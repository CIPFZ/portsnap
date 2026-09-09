//! Termination uses an OS handle acquired before confirmation.
use crate::model::{ProcessIdentity, ProcessInfo};
use std::{fmt, io, time::Duration};

#[cfg(target_os = "linux")]
#[path = "killer/linux.rs"]
mod native;
#[cfg(target_os = "macos")]
#[path = "killer/macos.rs"]
mod native;
#[cfg(windows)]
#[path = "killer/windows.rs"]
mod native;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillOutcome {
    Exited,
    AlreadyExited,
}

#[derive(Debug)]
pub enum KillError {
    Refused(&'static str),
    IdentityChanged,
    AlreadyExited,
    PermissionDenied(String),
    Unsupported(&'static str),
    Timeout,
    Io(io::Error),
}

impl fmt::Display for KillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(reason) => write!(f, "refusing termination: {reason}"),
            Self::IdentityChanged => {
                f.write_str("process identity changed since scanning; scan again")
            }
            Self::AlreadyExited => f.write_str("process has already exited"),
            Self::PermissionDenied(reason) => write!(f, "permission denied: {reason}"),
            Self::Unsupported(reason) => write!(f, "safe termination is unavailable: {reason}"),
            Self::Timeout => f.write_str("timed out waiting for the process to exit"),
            Self::Io(error) => write!(f, "process operation failed: {error}"),
        }
    }
}

impl std::error::Error for KillError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for KillError {
    fn from(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::PermissionDenied {
            Self::PermissionDenied(error.to_string())
        } else if error.kind() == io::ErrorKind::NotFound
            || cfg!(unix) && error.raw_os_error() == Some(3)
        {
            // ESRCH is 3 on supported Unix targets.
            Self::AlreadyExited
        } else {
            Self::Io(error)
        }
    }
}

pub struct PreparedTarget {
    native: native::Target,
}

impl PreparedTarget {
    pub fn prepare(process: &ProcessInfo) -> Result<Self, KillError> {
        Ok(Self {
            native: native::Target::prepare(validate(process)?)?,
        })
    }
    pub fn terminate(&mut self, force: bool, timeout: Duration) -> Result<KillOutcome, KillError> {
        self.native.terminate(force, timeout)
    }
}

fn validate(process: &ProcessInfo) -> Result<ProcessIdentity, KillError> {
    if process.pid <= 1 || process.pid == std::process::id() {
        return Err(KillError::Refused(
            "PID 0, PID 1, and this process are protected",
        ));
    }
    let identity = process
        .identity
        .ok_or(KillError::Refused("process identity is unknown"))?;
    if identity.pid != process.pid {
        return Err(KillError::IdentityChanged);
    }
    Ok(identity)
}

#[cfg(unix)]
pub(crate) fn verify(expected: ProcessIdentity) -> Result<(), KillError> {
    let current = crate::process::inspect(expected.pid)?;
    if current.identity != Some(expected) {
        return Err(KillError::IdentityChanged);
    }
    Ok(())
}
