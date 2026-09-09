use crate::model::{OwnershipStatus, ScanReport, SocketInfo};
use std::{
    collections::BTreeMap,
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
    write_details(out, report)
}

fn write_details(mut out: impl Write, report: &ScanReport) -> io::Result<()> {
    let owners: BTreeMap<_, _> = report
        .sockets
        .iter()
        .flat_map(|socket| &socket.owners)
        .filter(|owner| owner.details.is_some())
        .map(|owner| ((owner.pid, owner.identity), owner))
        .collect();
    if owners.is_empty() {
        return Ok(());
    }
    writeln!(out, "\nPROCESS DETAILS")?;
    for owner in owners.into_values() {
        let Some(details) = &owner.details else {
            continue;
        };
        writeln!(
            out,
            "PID {} ({})",
            owner.pid,
            visible(owner.name.as_deref().unwrap_or("name unavailable"))
        )?;
        writeln!(
            out,
            "  Executable: {}",
            details
                .executable
                .as_deref()
                .map(visible)
                .unwrap_or_else(|| "unavailable".into())
        )?;
        // JSON argument arrays preserve empty arguments, quoting and platform-specific paths.
        let command = details
            .command
            .as_ref()
            .map(|args| serde_json::to_string(args).map(|text| visible(&text)))
            .transpose()
            .map_err(io::Error::other)?;
        writeln!(
            out,
            "  Arguments:  {}",
            command.as_deref().unwrap_or("unavailable")
        )?;
        let user = details.user.as_ref().map(|user| match &user.name {
            Some(name) => format!("{} ({})", visible(name), visible(&user.id)),
            None => visible(&user.id),
        });
        writeln!(
            out,
            "  User:       {}",
            user.as_deref().unwrap_or("unavailable")
        )?;
        writeln!(
            out,
            "  Parent PID: {}",
            details
                .parent_pid
                .map(|pid| pid.to_string())
                .as_deref()
                .unwrap_or("unavailable")
        )?;
        let started = details.start_time_unix_ms.map(|millis| {
            i64::try_from(millis)
                .ok()
                .and_then(chrono::DateTime::from_timestamp_millis)
                .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
                .unwrap_or_else(|| format!("{millis} ms since Unix epoch"))
        });
        writeln!(
            out,
            "  Started:    {}",
            started.as_deref().unwrap_or("unavailable")
        )?;
        for warning in &details.warnings {
            writeln!(
                out,
                "  Unavailable [{}; {}]: {}",
                warning.field,
                warning.code,
                visible(&warning.message)
            )?;
        }
    }
    Ok(())
}

pub fn write_warnings(mut out: impl Write, report: &ScanReport) -> io::Result<()> {
    for warning in &report.warnings {
        writeln!(
            out,
            "Warning [{}; {}]: {}",
            warning.code,
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
    use crate::model::{
        DetailField, DiagnosticCode, ProcessDetails, ProcessIdentity, ProcessInfo, ProcessUser,
        Protocol, TcpState,
    };
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
                    details: None,
                },
                ProcessInfo {
                    pid: 456,
                    name: Some("two".into()),
                    identity: None,
                    details: None,
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
        report.warn(
            crate::model::DiagnosticCode::PermissionDenied,
            "tcp",
            "permission denied",
        );
        let mut out = Vec::new();
        write_text(&mut out, &report).unwrap();
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("scan is incomplete"));
    }

    #[test]
    fn details_preserve_arguments_escape_external_text_and_deduplicate_shared_owners() {
        let mut details = ProcessDetails::empty();
        details.executable = Some("/tmp/a\x1b[31m\nprogram".into());
        details.command = Some(vec![
            "a program".into(),
            "".into(),
            "quoted \"word\"".into(),
            "line\nnext".into(),
        ]);
        details.user = Some(ProcessUser {
            id: "1000".into(),
            name: Some("dev\tuser".into()),
        });
        details.start_time_unix_ms = Some(1_700_000_000_123);
        details.warn(
            DetailField::ParentPid,
            DiagnosticCode::PermissionDenied,
            "access\nrefused",
        );
        let socket = SocketInfo {
            protocol: Protocol::Tcp,
            local_addr: "127.0.0.1".parse().unwrap(),
            local_port: 8080,
            local_scope: None,
            remote_addr: None,
            remote_port: None,
            remote_scope: None,
            state: Some(TcpState::Listen),
            owners: vec![ProcessInfo {
                pid: 123,
                name: Some("worker".into()),
                identity: Some(ProcessIdentity {
                    pid: 123,
                    start_time: 999,
                }),
                details: Some(details),
            }],
            ownership: OwnershipStatus::Complete,
        };
        let mut report = ScanReport::new();
        report.sockets = vec![
            socket.clone(),
            SocketInfo {
                local_port: 8081,
                ..socket
            },
        ];
        let mut text = Vec::new();
        write_text(&mut text, &report).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert_eq!(text.matches("PID 123 (worker)").count(), 1);
        assert!(text.contains(r#"["a program","","quoted \"word\"","line\nnext"]"#));
        assert!(text.contains("2023-11-14T22:13:20.123Z"));
        assert!(text.contains("Parent PID: unavailable"));
        assert!(text.contains(r"Unavailable [parent_pid; permission_denied]: access\nrefused"));
        assert!(text.contains(r"dev\tuser (1000)"));
        assert!(!text.contains('\x1b'));
        assert!(!text.contains("\nprogram"));
    }
}
