use super::{KillError, KillOutcome};
use crate::{
    model::ProcessIdentity,
    process::native::{identity as handle_identity, open},
};
use std::{
    io,
    os::windows::io::{AsRawHandle, OwnedHandle},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{
        TerminateProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    },
};

pub struct Target {
    handle: OwnedHandle,
}

impl Target {
    pub fn prepare(identity: ProcessIdentity) -> Result<Self, KillError> {
        let handle = open(
            identity.pid,
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
        )?;
        if handle_identity(&handle, identity.pid)? != identity {
            return Err(KillError::IdentityChanged);
        }
        let target = Self { handle };
        if target.exited(0)? {
            return Err(KillError::AlreadyExited);
        }
        Ok(target)
    }

    fn exited(&self, timeout_ms: u32) -> Result<bool, KillError> {
        // SAFETY: this target keeps a valid waitable process handle open.
        match unsafe { WaitForSingleObject(self.handle.as_raw_handle(), timeout_ms) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            WAIT_FAILED => Err(io::Error::last_os_error().into()),
            _ => Err(KillError::Io(io::Error::other(
                "unexpected process wait result",
            ))),
        }
    }

    pub fn terminate(&mut self, _force: bool, timeout: Duration) -> Result<KillOutcome, KillError> {
        if self.exited(0)? {
            return Ok(KillOutcome::AlreadyExited);
        }
        // Windows has no generic SIGTERM equivalent. Both modes use TerminateProcess.
        // SAFETY: the retained process handle has PROCESS_TERMINATE access.
        if unsafe { TerminateProcess(self.handle.as_raw_handle(), 1) } == 0 {
            let error = io::Error::last_os_error();
            if self.exited(0)? {
                return Ok(KillOutcome::AlreadyExited);
            }
            return Err(error.into());
        }
        let start = Instant::now();
        loop {
            let remaining = timeout.saturating_sub(start.elapsed());
            let millis = remaining
                .as_millis()
                .saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0))
                .min(u128::from(u32::MAX - 1)) as u32;
            if self.exited(millis)? {
                return Ok(KillOutcome::Exited);
            }
            if start.elapsed() >= timeout {
                return Err(KillError::Timeout);
            }
        }
    }
}
