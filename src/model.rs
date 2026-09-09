use serde::Serialize;
use std::{fmt, net::IpAddr};

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        })
    }
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TcpState {
    Listen,
    Established,
    SynSent,
    SynReceived,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
    DeleteTcb,
    Unknown,
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Listen => "LISTEN",
            Self::Established => "ESTABLISHED",
            Self::SynSent => "SYN_SENT",
            Self::SynReceived => "SYN_RECEIVED",
            Self::FinWait1 => "FIN_WAIT1",
            Self::FinWait2 => "FIN_WAIT2",
            Self::CloseWait => "CLOSE_WAIT",
            Self::Closing => "CLOSING",
            Self::LastAck => "LAST_ACK",
            Self::TimeWait => "TIME_WAIT",
            Self::Closed => "CLOSED",
            Self::DeleteTcb => "DELETE_TCB",
            Self::Unknown => "UNKNOWN",
        })
    }
}

/// Native process start identifier; meaningful only on this host and boot.
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: Option<String>,
    pub identity: Option<ProcessIdentity>,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipStatus {
    Complete,
    Partial,
    Unavailable,
    NotApplicable,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct SocketInfo {
    pub protocol: Protocol,
    pub local_addr: IpAddr,
    pub local_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_scope: Option<String>,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_scope: Option<String>,
    pub state: Option<TcpState>,
    pub owners: Vec<ProcessInfo>,
    pub ownership: OwnershipStatus,
}

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub ports: Vec<u16>,
    pub listening_only: bool,
}

impl ScanOptions {
    pub fn matches(&self, socket: &SocketInfo) -> bool {
        (self.ports.is_empty() || self.ports.contains(&socket.local_port))
            && (!self.listening_only
                || socket.protocol == Protocol::Udp
                || socket.state == Some(TcpState::Listen))
    }
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct ScanWarning {
    pub source: String,
    pub message: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct ScanReport {
    pub schema_version: u32,
    pub sockets: Vec<SocketInfo>,
    pub complete: bool,
    pub warnings: Vec<ScanWarning>,
}

impl Default for ScanReport {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanReport {
    pub fn new() -> Self {
        Self {
            schema_version: 1,
            sockets: Vec::new(),
            complete: true,
            warnings: Vec::new(),
        }
    }
    pub fn warn(&mut self, source: impl Into<String>, message: impl Into<String>) {
        self.complete = false;
        self.warnings.push(ScanWarning {
            source: source.into(),
            message: message.into(),
        });
    }
}
