use crate::model::{OwnershipStatus, ScanReport, SocketInfo};
use std::{
    io::{self, Write},
    net::IpAddr,
};

pub fn endpoint(addr: IpAddr, port: u16, scope: Option<&str>) -> String {
    match addr {
        IpAddr::V4(_) => format!("{addr}:{port}"),
        IpAddr::V6(_) => match scope {
            Some(scope) => format!("[{addr}%{}]:{port}", visible(scope)),
            None => format!("[{addr}]:{port}"),
        },
    }
}

fn visible(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

fn addresses(socket: &SocketInfo) -> (String, String) {
    let local = endpoint(
        socket.local_addr,
        socket.local_port,
        socket.local_scope.as_deref(),
    );
    let remote = match (socket.remote_addr, socket.remote_port) {
        (Some(addr), Some(port)) => endpoint(addr, port, socket.remote_scope.as_deref()),
        _ => "-".to_owned(),
    };
    (local, remote)
}

pub fn write_text(mut out: impl Write, report: &ScanReport) -> io::Result<()> {
    if report.sockets.is_empty() {
        return writeln!(
            out,
            "{}",
            if report.complete {
                "No matching endpoints found."
            } else {
                "No matching endpoints observed; scan is incomplete."
            }
        );
    }
    let endpoints: Vec<_> = report.sockets.iter().map(addresses).collect();
    let local_width = endpoints
        .iter()
        .map(|(local, _)| local.chars().count())
        .max()
        .unwrap_or(0)
        .max(13);
    let remote_width = endpoints
        .iter()
        .map(|(_, remote)| remote.chars().count())
        .max()
        .unwrap_or(0)
        .max(14);
    writeln!(
        out,
        "{:<5} {:<local_width$} {:<remote_width$} {:<12} {:>8} PROCESS",
        "PROTO", "LOCAL ADDRESS", "REMOTE ADDRESS", "STATE", "PID"
    )?;
    for (socket, (local, remote)) in report.sockets.iter().zip(endpoints) {
        let state = socket
            .state
            .map(|state| state.to_string())
            .unwrap_or_else(|| "BOUND".to_owned());
        if socket.owners.is_empty() {
            let description = if socket.ownership == OwnershipStatus::NotApplicable {
                "(kernel-managed; no process)"
            } else {
                "(owner unavailable)"
            };
            writeln!(
                out,
                "{:<5} {:<local_width$} {:<remote_width$} {:<12} {:>8} {}",
                socket.protocol, local, remote, state, "-", description
            )?;
        } else {
            for owner in &socket.owners {
                let name = owner
                    .name
                    .as_deref()
                    .map(visible)
                    .unwrap_or_else(|| "(name unavailable)".to_owned());
                writeln!(
                    out,
                    "{:<5} {:<local_width$} {:<remote_width$} {:<12} {:>8} {}",
                    socket.protocol, local, remote, state, owner.pid, name
                )?;
            }
        }
    }
    Ok(())
}

pub fn write_warnings(mut out: impl Write, report: &ScanReport) -> io::Result<()> {
    for warning in &report.warnings {
        writeln!(
            out,
            "Warning [{}]: {}",
            visible(&warning.source),
            visible(&warning.message)
        )?;
    }
    if !report.complete && report.warnings.is_empty() {
        writeln!(out, "Warning: scan is incomplete.")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProcessInfo, Protocol, TcpState};
    #[test]
    fn ipv6_scope_and_port_are_unambiguous() {
        assert_eq!(
            endpoint("fe80::1".parse().unwrap(), 8080, Some("en0")),
            "[fe80::1%en0]:8080"
        );
    }
    #[test]
    fn table_lists_all_owners_aligns_columns_and_escapes_control_characters() {
        let mut report = ScanReport::new();
        report.sockets.push(SocketInfo {
            protocol: Protocol::Tcp,
            local_addr: "::1".parse().unwrap(),
            local_port: 8080,
            local_scope: None,
            remote_addr: None,
            remote_port: None,
            remote_scope: None,
            state: Some(TcpState::Listen),
            owners: vec![
                ProcessInfo {
                    pid: 123,
                    name: Some("one\x1b[31m".into()),
                    identity: None,
                },
                ProcessInfo {
                    pid: 456,
                    name: Some("two".into()),
                    identity: None,
                },
            ],
            ownership: OwnershipStatus::Complete,
        });
        let mut text = Vec::new();
        write_text(&mut text, &report).unwrap();
        let text = String::from_utf8(text).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].find("LOCAL ADDRESS"), lines[1].find("[::1]:8080"));
        assert!(text.contains("123"));
        assert!(text.contains("456"));
        assert!(!text.contains('\x1b'));
    }
    #[test]
    fn empty_incomplete_report_does_not_claim_no_occupancy() {
        let mut report = ScanReport::new();
        report.warn("tcp", "permission denied");
        let mut out = Vec::new();
        write_text(&mut out, &report).unwrap();
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("scan is incomplete"));
    }
}
