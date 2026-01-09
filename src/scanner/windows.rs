use crate::model::{Protocol, SocketInfo};
use anyhow::Result;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use std::collections::HashMap;
use sysinfo::System; // 修正1: 移除了 ProcessExt, SystemExt

pub(crate) struct Scanner;

impl Scanner {
    /// 核心方法：扫描并返回结构化数据
    pub fn scan(ports_filter: Option<&[u16]>) -> Result<Vec<SocketInfo>> {
        // 1. 获取系统进程快照 (PID -> Name)
        let mut sys = System::new();
        sys.refresh_processes();

        // 修正1: sysinfo 0.30+ 不需要 trait，直接调用方法
        // 注意: sysinfo 的 pid 现在是 struct wrapper，需要转换为 u32
        let process_map: HashMap<u32, String> = sys
            .processes()
            .iter()
            .map(|(pid, process)| (pid.as_u32(), process.name().to_string()))
            .collect();

        // 2. 配置扫描参数
        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

        // 3. 调用底层 API 获取 Socket 信息
        let sockets = get_sockets_info(af_flags, proto_flags)?;
        let mut results = Vec::new();

        for si in sockets {
            // 修正2: 优化逻辑，一次性解构 Protocol, Addr, Port
            // 使用引用 &si.protocol_socket_info 避免所有权被 move
            let (protocol, local_addr, local_port) = match &si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp_info) => {
                    (Protocol::TCP, tcp_info.local_addr, tcp_info.local_port)
                }
                ProtocolSocketInfo::Udp(udp_info) => {
                    (Protocol::UDP, udp_info.local_addr, udp_info.local_port)
                }
            };

            // 过滤逻辑
            if let Some(ports) = ports_filter {
                if !ports.contains(&local_port) {
                    continue;
                }
            }

            // 获取 PID
            let pid = si.associated_pids.first().cloned().unwrap_or(0);

            // 查找进程名
            let process_name = process_map.get(&pid).cloned().unwrap_or_else(|| {
                if pid == 0 {
                    "System".to_string()
                } else {
                    "Unknown".to_string()
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

        // 排序
        results.sort_by_key(|k| k.local_port);

        Ok(results)
    }
}
