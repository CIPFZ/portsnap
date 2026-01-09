use serde::Serialize;
use std::fmt;

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub enum Protocol {
    TCP,
    UDP,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct SocketInfo {
    pub protocol: Protocol,
    pub local_addr: String,
    pub local_port: u16,
    pub pid: u32,
    pub process_name: String,
}

impl SocketInfo {
    pub fn to_text_row(&self) -> String {
        format!(
            "{:<6} {:<25} {:<10} {}", // 调整了列宽：5->6, 8->10，增加间距
            self.protocol,
            format!("{}:{}", self.local_addr, self.local_port),
            self.pid,
            self.process_name
        )
    }
}
