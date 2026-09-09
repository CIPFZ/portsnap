//! Targeted metadata collection. Identities retain native timestamp precision.
use crate::model::ProcessInfo;
use std::io;

#[cfg(target_os = "linux")]
#[path = "process/linux.rs"]
mod native;
#[cfg(target_os = "macos")]
#[path = "process/macos.rs"]
pub(crate) mod native;
#[cfg(windows)]
#[path = "process/windows.rs"]
pub(crate) mod native;

pub fn inspect(pid: u32) -> io::Result<ProcessInfo> {
    native::inspect(pid)
}
