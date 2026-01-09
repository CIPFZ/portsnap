use sysinfo::{Pid, System};

pub struct Killer;

impl Killer {
    /// 根据 PID 终止进程
    pub fn kill(pid: u32) -> bool {
        let mut sys = System::new();
        // 必须刷新进程列表才能找到对应的进程对象
        sys.refresh_processes();

        // sysinfo 0.30+ 中 Pid 是一个封装类型，需要转换
        let pid = Pid::from_u32(pid);

        if let Some(process) = sys.process(pid) {
            // kill() 在 Windows 上对应 TerminateProcess，在 Linux 上对应 SIGKILL
            return process.kill();
        }

        // 如果找不到进程（可能已经退出了），返回 false
        false
    }
}
