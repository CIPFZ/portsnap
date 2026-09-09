#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("portsnap supports Linux, macOS and Windows only");

pub mod killer;
pub mod model;
pub mod output;
pub mod process;
pub mod scanner;
