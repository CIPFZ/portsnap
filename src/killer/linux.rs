use super::{verify, KillError, KillOutcome};
use crate::model::ProcessIdentity;
use std::{
    fs, io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
    time::{Duration, Instant},
};

pub struct Target {
    pidfd: OwnedFd,
}

impl Target {
    pub fn prepare(identity: ProcessIdentity) -> Result<Self, KillError> {
        let pid = i32::try_from(identity.pid)
            .map_err(|_| KillError::Refused("PID exceeds native range"))?;
        // An inherited/bind-mounted procfs can use a different PID namespace
        // from pidfd_open. Reject that context before looking up a numeric PID.
        let proc_self = fs::read_link("/proc/self").map_err(KillError::Io)?;
        validate_procfs_self(&proc_self, std::process::id())?;
        // SAFETY: pidfd_open has scalar arguments and returns a new owned FD.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            return Err(if error.raw_os_error() == Some(libc::ENOSYS) {
                KillError::Unsupported("Linux pidfd support requires kernel 5.3 or newer")
            } else {
                error.into()
            });
        }
        // SAFETY: a nonnegative pidfd_open result is uniquely owned here.
        let target = Self {
            pidfd: unsafe { OwnedFd::from_raw_fd(fd as i32) },
        };
        // The kernel reports fdinfo's Pid relative to the *procfs mount's*
        // namespace. This binds the retained handle to the same PID lookup
        // used for metadata, even if namespace IDs happen to coincide above.
        let fdinfo =
            fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).map_err(KillError::Io)?;
        validate_pidfd_namespace(&fdinfo, identity.pid)?;
        verify(identity)?;
        if target.exited(0)? {
            return Err(KillError::AlreadyExited);
        }
        Ok(target)
    }

    fn exited(&self, timeout_ms: i32) -> Result<bool, KillError> {
        let mut descriptor = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll receives a valid pointer to exactly one initialized pollfd.
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if result < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if descriptor.revents & libc::POLLNVAL != 0 {
            return Err(KillError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid process handle",
            )));
        }
        Ok(descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0)
    }

    pub fn terminate(&mut self, force: bool, timeout: Duration) -> Result<KillOutcome, KillError> {
        if self.exited(0)? {
            return Ok(KillOutcome::AlreadyExited);
        }
        let signal = if force { libc::SIGKILL } else { libc::SIGTERM };
        // SAFETY: the pidfd targets the retained identity; null siginfo uses defaults.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(KillOutcome::AlreadyExited);
            }
            if error.raw_os_error() == Some(libc::ENOSYS) {
                return Err(KillError::Unsupported(
                    "kernel does not support pidfd_send_signal",
                ));
            }
            return Err(error.into());
        }
        let start = Instant::now();
        loop {
            let remaining = timeout.saturating_sub(start.elapsed());
            let millis = remaining
                .as_millis()
                .saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0))
                .min(i32::MAX as u128) as i32;
            match self.exited(millis) {
                Ok(true) => return Ok(KillOutcome::Exited),
                Ok(false) => {}
                Err(KillError::Io(error)) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
            if start.elapsed() >= timeout {
                return Err(KillError::Timeout);
            }
        }
    }
}

fn validate_procfs_self(observed: &Path, current_pid: u32) -> Result<(), KillError> {
    if observed
        .to_str()
        .and_then(|value| value.parse::<u32>().ok())
        != Some(current_pid)
    {
        return Err(KillError::Refused(
            "procfs does not match the caller PID namespace; mount procfs for this namespace",
        ));
    }
    Ok(())
}

fn validate_pidfd_namespace(fdinfo: &str, expected_pid: u32) -> Result<(), KillError> {
    let pid = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .and_then(|value| value.trim().parse::<i64>().ok());
    match pid {
        Some(-1) => Err(KillError::AlreadyExited),
        Some(pid) if pid == i64::from(expected_pid) => Ok(()),
        _ => Err(KillError::Refused(
            "cannot match the process handle to its procfs PID; check the procfs PID namespace",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreign_or_unknown_procfs_pid_namespace_is_refused() {
        assert!(validate_procfs_self(Path::new("123"), 123).is_ok());
        for observed in ["456", "", "self", "123/task/124"] {
            assert!(matches!(
                validate_procfs_self(Path::new(observed), 123),
                Err(KillError::Refused(_))
            ));
        }
    }

    #[test]
    fn pidfd_must_identify_expected_pid_in_procfs_namespace() {
        assert!(validate_pidfd_namespace("pos:\t0\nPid:\t123\nNSpid:\t123\n", 123).is_ok());
        for fdinfo in ["Pid:\t456\n", "Pid:\t0\n", "Pid:\tbroken\n", "pos:\t0\n"] {
            assert!(matches!(
                validate_pidfd_namespace(fdinfo, 123),
                Err(KillError::Refused(_))
            ));
        }
        assert!(matches!(
            validate_pidfd_namespace("Pid:\t-1\n", 123),
            Err(KillError::AlreadyExited)
        ));
    }
}
