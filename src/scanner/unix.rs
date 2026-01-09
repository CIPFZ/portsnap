use crate::model::{Protocol, SocketInfo};
use anyhow::Result;
use std::collections::HashMap;
use sysinfo::System;

pub(crate) struct Scanner;

impl Scanner {
    pub fn scan(ports_filter: Option<&[u16]>) -> Result<Vec<SocketInfo>> {
        // 1. 初始化进程名映射 (PID -> Name)
        // 这部分 Linux/macOS 通用
        let mut sys = System::new();
        sys.refresh_processes();

        let process_map: HashMap<u32, String> = sys
            .processes()
            .iter()
            .map(|(pid, process)| (pid.as_u32(), process.name().to_string()))
            .collect();

        // 2. 根据平台分发
        #[cfg(target_os = "linux")]
        return linux_impl::scan(ports_filter, &process_map);

        #[cfg(target_os = "macos")]
        return macos_impl::scan(ports_filter, &process_map);

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        Ok(vec![])
    }
}

// ==========================
// Linux 实现 (Based on procfs)
// ==========================
#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use procfs::net::{tcp, tcp6, udp, udp6, TcpState};

    pub fn scan(filter: Option<&[u16]>, p_map: &HashMap<u32, String>) -> Result<Vec<SocketInfo>> {
        let mut results = Vec::new();

        // 辅助闭包：处理 TCP/UDP 逻辑
        let mut add_entry = |local: std::net::SocketAddr, inode: u64, proto: Protocol| {
            let port = local.port();
            if let Some(ports) = filter {
                if !ports.contains(&port) {
                    return;
                }
            }

            // Linux procfs 需要通过 inode 反查 PID，这里简化处理：
            // procfs 库可以遍历 /proc/[pid]/fd 找到对应 inode，但这比较慢。
            // 为了 MVP，我们尝试通过 process_map 里的名字做个简单关联，或者
            // 在 procfs 高级用法中，需要遍历所有进程的 fd。
            //
            // 修正策略：为了让构建快速通过且逻辑可用，Linux 下暂时
            // 使用 procfs 的 process 查找功能。

            // 暂时先不填 PID，或者在此处做全进程扫描 (性能开销大)。
            // 为了 v0.1 构建通过，我们先填 0，后续优化。
            // *注意*：要在 Linux 上完美获取 PID，必须遍历 /proc/[pid]/fd/

            let pid = find_pid_by_inode(inode).unwrap_or(0);
            let name = p_map.get(&pid).cloned().unwrap_or_else(|| "-".to_string());

            results.push(SocketInfo {
                protocol: proto,
                local_addr: local.ip().to_string(),
                local_port: port,
                pid,
                process_name: name,
            });
        };

        // 扫描 TCP (IPv4 + IPv6)
        if let Ok(entries) = tcp() {
            for entry in entries {
                if entry.state == TcpState::Listen {
                    add_entry(entry.local_address, entry.inode, Protocol::TCP);
                }
            }
        }
        if let Ok(entries) = tcp6() {
            for entry in entries {
                if entry.state == TcpState::Listen {
                    add_entry(entry.local_address, entry.inode, Protocol::TCP);
                }
            }
        }

        // 扫描 UDP
        if let Ok(entries) = udp() {
            for entry in entries {
                add_entry(entry.local_address, entry.inode, Protocol::UDP);
            }
        }
        if let Ok(entries) = udp6() {
            for entry in entries {
                add_entry(entry.local_address, entry.inode, Protocol::UDP);
            }
        }

        results.sort_by_key(|k| k.local_port);
        Ok(results)
    }

    // 这是一个昂贵的操作，但在 Linux 不用 root 只能这么做
    fn find_pid_by_inode(target_inode: u64) -> Option<u32> {
        use procfs::process::all_processes;
        if let Ok(procs) = all_processes() {
            for p in procs {
                if let Ok(fds) = p.fd() {
                    for fd in fds {
                        if let procfs::process::FDTarget::Socket(inode) = fd.target {
                            if inode == target_inode {
                                return Some(p.pid as u32);
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

// ==========================
// macOS 实现 (Shell out to lsof)
// ==========================
#[cfg(target_os = "macos")]
mod macos_impl {
    use super::*;
    use regex::Regex;
    use std::process::Command;

    pub fn scan(filter: Option<&[u16]>, _p_map: &HashMap<u32, String>) -> Result<Vec<SocketInfo>> {
        let mut results = Vec::new();

        // 使用 lsof -i -P -n (不解析域名和端口名，速度快)
        let output = Command::new("lsof")
            .args(&["-iTCP", "-iUDP", "-sTCP:LISTEN", "-P", "-n"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // 解析输出: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        // node    12345 user ... TCP *:8080 (LISTEN)

        // 简单的正则匹配
        let re = Regex::new(r"(?m)^(\S+)\s+(\d+)\s+.*\s(TCP|UDP)\s+.*:(\d+)\s.*$").unwrap();

        for cap in re.captures_iter(&stdout) {
            let name = cap[1].to_string();
            let pid = cap[2].parse::<u32>().unwrap_or(0);
            let proto_str = &cap[3];
            let port = cap[4].parse::<u16>().unwrap_or(0);

            if let Some(ports) = filter {
                if !ports.contains(&port) {
                    continue;
                }
            }

            let protocol = if proto_str == "TCP" {
                Protocol::TCP
            } else {
                Protocol::UDP
            };

            results.push(SocketInfo {
                protocol,
                local_addr: "*".to_string(), // lsof 输出解析比较复杂，MVP 先用 *
                local_port: port,
                pid,
                process_name: name,
            });
        }

        results.sort_by_key(|k| k.local_port);
        Ok(results)
    }
}
