use super::{verify, KillError, KillOutcome};
use crate::{
    model::ProcessIdentity,
    process::native::{bsd_info, identity as bsd_identity},
};
use std::{
    io, thread,
    time::{Duration, Instant},
};

pub struct Target {
    port: libc::mach_port_t,
    identity: ProcessIdentity,
}

// Stable Mach ABI declarations absent from, or deprecated by, libc.
unsafe extern "C" {
    static mach_task_self_: libc::mach_port_t;
    fn mach_port_deallocate(
        task: libc::mach_port_t,
        name: libc::mach_port_t,
    ) -> libc::kern_return_t;
}

impl Drop for Target {
    fn drop(&mut self) {
        // SAFETY: task_for_pid transferred a send right held uniquely by this target.
        unsafe {
            mach_port_deallocate(mach_task_self_, self.port);
        }
    }
}

impl Target {
    pub fn prepare(identity: ProcessIdentity) -> Result<Self, KillError> {
        let pid = i32::try_from(identity.pid)
            .map_err(|_| KillError::Refused("PID exceeds native range"))?;
        verify(identity)?;
        let mut port = 0;
        // SAFETY: port is a writable output; task_for_pid creates a stable task send right.
        let result = unsafe { libc::task_for_pid(mach_task_self_, pid, &mut port) };
        if result != libc::KERN_SUCCESS {
            verify(identity)?;
            return Err(KillError::PermissionDenied(format!("macOS task_for_pid denied a stable process handle (Mach error {result}); privileges or a task-port entitlement may be required")));
        }
        let target = Self { port, identity };
        // Verify after acquisition: a recycled PID must not authorize the new task port.
        verify(identity)?;
        if target.exited()? {
            return Err(KillError::AlreadyExited);
        }
        Ok(target)
    }

    fn exited(&self) -> Result<bool, KillError> {
        match bsd_info(self.identity.pid) {
            Ok(info) => Ok(bsd_identity(&info)? != self.identity || info.pbi_status == libc::SZOMB),
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH) =>
            {
                Ok(true)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn terminate(&mut self, force: bool, timeout: Duration) -> Result<KillOutcome, KillError> {
        if self.exited()? {
            return Ok(KillOutcome::AlreadyExited);
        }
        if !force {
            return Err(KillError::Unsupported("macOS cannot send SIGTERM through a stable public task handle; use --force for task_terminate"));
        }
        // SAFETY: the retained task port addresses only the validated process.
        let result = unsafe { libc::task_terminate(self.port) };
        if result != libc::KERN_SUCCESS {
            if self.exited()? {
                return Ok(KillOutcome::AlreadyExited);
            }
            return Err(KillError::PermissionDenied(format!(
                "macOS task_terminate failed (Mach error {result})"
            )));
        }
        let start = Instant::now();
        loop {
            if self.exited()? {
                return Ok(KillOutcome::Exited);
            }
            if start.elapsed() >= timeout {
                return Err(KillError::Timeout);
            }
            thread::sleep(
                timeout
                    .saturating_sub(start.elapsed())
                    .min(Duration::from_millis(10)),
            );
        }
    }
}
