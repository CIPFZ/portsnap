use crate::model::{Protocol, SocketInfo};
use anyhow::Result;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use std::collections::HashMap;
use sysinfo::System;

pub(crate) struct Scanner;

impl Scanner {
    pub fn scan(ports_filter: Option<&[u16]>) -> Result<Vec<SocketInfo>> {
        // Linux/macOS 下的逻辑实现
        // 1. 初始化系统信息 (获取 PID -> Process Name)
        let mut sys = System::new();
        sys.refresh_processes();

        let process_map: HashMap<u32, String> = sys
            .processes()
            .iter()
            .map(|(pid, process)| (pid.as_u32(), process.name().to_string()))
            .collect();

        // 2. 配置扫描参数
        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

        // 3. 获取 Socket 信息
        let sockets = get_sockets_info(af_flags, proto_flags)?;
        let mut results = Vec::new();

        for si in sockets {
            let (protocol, local_addr, local_port) = match &si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp_info) => {
                    (Protocol::TCP, tcp_info.local_addr, tcp_info.local_port)
                }
                ProtocolSocketInfo::Udp(udp_info) => {
                    (Protocol::UDP, udp_info.local_addr, udp_info.local_port)
                }
            };

            if let Some(ports) = ports_filter {
                if !ports.contains(&local_port) {
                    continue;
                }
            }

            let pid = si.associated_pids.first().cloned().unwrap_or(0);

            // Unix 特异性处理：
            // 在 Linux/macOS 上，非 Root 用户无法获取 Root 进程的名称。
            // 这里我们做一个简单的 fallback 处理。
            let process_name = process_map.get(&pid).cloned().unwrap_or_else(|| {
                if pid == 0 {
                    "System".to_string()
                } else {
                    // 如果有 PID 但查不到名字，通常是权限不足
                    "-".to_string()
                }
            });

            results.push(SocketInfo {
                protocol,
                local_addr: local_addr.to_string(),
                local_port,
                pid,
                process_name,
            });
        }

        results.sort_by_key(|k| k.local_port);
        Ok(results)
    }
}
