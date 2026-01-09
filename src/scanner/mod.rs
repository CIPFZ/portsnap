use crate::model::SocketInfo;
use anyhow::Result;

// 仅在 Windows 下编译 windows.rs
#[cfg(target_os = "windows")]
mod windows;

// 仅在非 Windows (Linux/macOS) 下编译 unix.rs
#[cfg(not(target_os = "windows"))]
mod unix;

pub struct Scanner;

impl Scanner {
    pub fn scan(ports_filter: Option<&[u16]>) -> Result<Vec<SocketInfo>> {
        // 编译期分发：调用对应平台的 scan 方法
        #[cfg(target_os = "windows")]
        return windows::Scanner::scan(ports_filter);

        #[cfg(not(target_os = "windows"))]
        return unix::Scanner::scan(ports_filter);
    }
}
