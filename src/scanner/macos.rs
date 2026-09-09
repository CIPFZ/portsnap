//! lsof's NUL-delimited field format is independent of column widths, command
//! whitespace and display-oriented connection arrows.
use crate::model::{
    AddressFamily, DiagnosticCode, OwnershipStatus, ProcessInfo, Protocol, ScanOptions, ScanReport,
    SocketInfo, TcpState,
};
use anyhow::{anyhow, bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(target_os = "macos")]
pub(super) fn scan(options: &crate::model::ScanOptions) -> Result<ScanReport> {
    super::scan_with_verified_owners(
        || {
            let output = std::process::Command::new("/usr/sbin/lsof")
                .args(lsof_args(options))
                .output()
                .context("cannot execute lsof; macOS scanning requires lsof")?;
            let mut report = parse_output(
                output.status.code(),
                &output.stdout,
                &output.stderr,
                options,
            )?;
            report.sockets.retain(|socket| options.matches(socket));
            // lsof can silently omit other users' descriptors without privilege.
            // SAFETY: geteuid has no arguments or preconditions.
            if unsafe { libc::geteuid() } != 0 {
                warn_incomplete_ownership(
                    &mut report,
                    DiagnosticCode::VisibilityLimited,
                    "lsof visibility",
                    "without root privileges, lsof may omit sockets owned by other users",
                );
            }
            Ok(report)
        },
        crate::process::inspect,
    )
}

fn lsof_args(options: &ScanOptions) -> Vec<&'static str> {
    let mut args = vec!["-n", "-P", "-F0pcftPnT"];
    // Some lsof dialects select IPv4-mapped IPv6 connections with -i4 even
    // though the descriptor type is IPv6. Include both for -6, then filter by
    // the descriptor's native family; otherwise mapped connections can vanish.
    for (protocol, ipv4, both) in [
        (Protocol::Tcp, "-i4TCP", "-iTCP"),
        (Protocol::Udp, "-i4UDP", "-iUDP"),
    ] {
        if options.protocol.is_none_or(|wanted| wanted == protocol) {
            args.push(if options.family == Some(AddressFamily::Ipv4) {
                ipv4
            } else {
                both
            });
        }
    }
    args
}

fn parse_output(
    status: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
    options: &ScanOptions,
) -> Result<ScanReport> {
    let diagnostic = String::from_utf8_lossy(stderr);
    let diagnostic = diagnostic.trim();
    match status {
        Some(1) if stdout.is_empty() && diagnostic.is_empty() => return Ok(ScanReport::new()),
        // lsof also uses exit 1 when one requested selector has no matches,
        // even if another selector produced valid rows (e.g. TCP but no UDP).
        Some(0) | Some(1) if !stdout.is_empty() || status == Some(0) => {}
        _ => bail!(
            "lsof failed (status {status:?}): {}",
            if diagnostic.is_empty() {
                "no diagnostic output"
            } else {
                diagnostic
            }
        ),
    }
    let mut report = parse_fields(stdout, options).context("invalid lsof field output")?;
    if !diagnostic.is_empty() {
        // lsof stderr is unstructured; do not infer a specific OS error from its text.
        warn_incomplete_ownership(
            &mut report,
            DiagnosticCode::SourceUnavailable,
            "lsof",
            diagnostic,
        );
    }
    Ok(report)
}

fn warn_incomplete_ownership(
    report: &mut ScanReport,
    code: DiagnosticCode,
    source: &str,
    message: &str,
) {
    report.warn(code, source, message);
    for socket in &mut report.sockets {
        socket.ownership = OwnershipStatus::Partial;
    }
}

#[derive(Default)]
struct FileFields {
    family: Option<String>,
    protocol: Option<String>,
    endpoint: Option<String>,
    state: Option<String>,
}

fn parse_fields(bytes: &[u8], options: &ScanOptions) -> Result<ScanReport> {
    let mut report = ScanReport::new();
    if bytes.is_empty() {
        return Ok(report);
    }
    if !bytes.strip_suffix(b"\n").unwrap_or(bytes).ends_with(b"\0") {
        bail!("truncated field (expected a NUL delimiter)");
    }
    let mut process = None;
    let mut file = None;
    let mut file_count = 0;
    let mut warnings = super::WarningSummary::default();
    for raw in bytes.split(|byte| *byte == 0) {
        let raw = raw.strip_prefix(b"\n").unwrap_or(raw);
        if raw.is_empty() {
            continue;
        }
        let field = raw[0];
        let value = std::str::from_utf8(&raw[1..]).context("non-UTF-8 field")?;
        match field {
            b'p' => {
                finish_file(
                    &mut report,
                    &process,
                    &mut file,
                    &mut file_count,
                    &mut warnings,
                    options,
                )?;
                let pid = value.parse::<u32>().context("invalid process ID")?;
                if pid == 0 {
                    bail!("invalid process ID 0");
                }
                process = Some(ProcessInfo {
                    pid,
                    name: None,
                    identity: None,
                    details: None,
                });
            }
            b'c' => {
                let owner = process
                    .as_mut()
                    .ok_or_else(|| anyhow!("command before process ID"))?;
                owner.name = Some(value.to_owned());
            }
            b'f' => {
                if process.is_none() {
                    bail!("file before process ID");
                }
                if value.is_empty() {
                    bail!("missing file descriptor");
                }
                finish_file(
                    &mut report,
                    &process,
                    &mut file,
                    &mut file_count,
                    &mut warnings,
                    options,
                )?;
                file = Some(FileFields::default());
            }
            b't' | b'P' | b'n' | b'T' => {
                let fields = file
                    .as_mut()
                    .ok_or_else(|| anyhow!("file field before descriptor"))?;
                match field {
                    b't' => set_once(&mut fields.family, value, "address family")?,
                    b'P' => set_once(&mut fields.protocol, value, "protocol")?,
                    b'n' => set_once(&mut fields.endpoint, value, "endpoint")?,
                    b'T' => {
                        if let Some(state) = value.strip_prefix("ST=") {
                            set_once(&mut fields.state, state, "TCP state")?;
                        }
                    }
                    _ => unreachable!(),
                }
            }
            _ => bail!("unexpected lsof field {:?}", char::from(field)),
        }
    }
    finish_file(
        &mut report,
        &process,
        &mut file,
        &mut file_count,
        &mut warnings,
        options,
    )?;
    warnings.append_to(&mut report);
    if file_count == 0 {
        bail!("nonempty output contains no socket records");
    }
    Ok(report)
}

fn set_once(slot: &mut Option<String>, value: &str, field: &str) -> Result<()> {
    if slot.replace(value.to_owned()).is_some() {
        bail!("duplicate {field} field");
    }
    Ok(())
}

fn finish_file(
    report: &mut ScanReport,
    process: &Option<ProcessInfo>,
    file: &mut Option<FileFields>,
    count: &mut usize,
    warnings: &mut super::WarningSummary,
    options: &ScanOptions,
) -> Result<()> {
    let Some(file) = file.take() else {
        return Ok(());
    };
    let owner = process
        .as_ref()
        .ok_or_else(|| anyhow!("socket without process"))?;
    let family = file
        .family
        .as_deref()
        .ok_or_else(|| anyhow!("socket missing address family"))?;
    if !matches!(family, "IPv4" | "IPv6") {
        bail!("unsupported address family {family}");
    }
    let protocol = match file.protocol.as_deref() {
        Some("TCP") => Protocol::Tcp,
        Some("UDP") => Protocol::Udp,
        other => bail!("unsupported or missing protocol: {other:?}"),
    };
    let endpoint = file
        .endpoint
        .ok_or_else(|| anyhow!("socket missing endpoint"))?;
    let (local, remote) = match endpoint.split_once("->") {
        Some((local, remote)) => (local, Some(remote)),
        None => (endpoint.as_str(), None),
    };
    let (local_addr, local_scope, local_port) = parse_endpoint(local, family)?;
    let (remote_addr, remote_scope, remote_port) = match remote {
        Some(remote) => {
            let (addr, scope, port) = parse_endpoint(remote, family)?;
            (Some(addr), scope, Some(port))
        }
        None => (None, None, None),
    };
    *count += 1;
    // lsof also reports unbound sockets (*:*), which occupy no local port.
    if local_port == 0 {
        return Ok(());
    }
    let state =
        (protocol == Protocol::Tcp).then(|| parse_state(file.state.as_deref().unwrap_or("")));
    let socket = SocketInfo {
        protocol,
        local_addr,
        local_scope,
        local_port,
        remote_addr,
        remote_scope,
        remote_port,
        state,
        owners: vec![owner.clone()],
        ownership: OwnershipStatus::Complete,
    };
    if options.matches(&socket) {
        if state == Some(TcpState::Unknown) {
            warnings.record(
                DiagnosticCode::UnknownState,
                "lsof TCP state",
                format!(
                    "PID {} port {local_port}: missing or unrecognized TCP state {:?}",
                    owner.pid, file.state
                ),
            );
        }
        report.sockets.push(socket);
    }
    Ok(())
}

fn parse_endpoint(value: &str, family: &str) -> Result<(IpAddr, Option<String>, u16)> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("endpoint lacks port: {value}"))?;
    let port = if port == "*" {
        0
    } else {
        port.parse::<u16>()
            .with_context(|| format!("invalid endpoint port: {value}"))?
    };
    let host = if host.starts_with('[') {
        host.strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .ok_or_else(|| anyhow!("invalid bracketed endpoint: {value}"))?
    } else {
        host
    };
    let (host, scope) = match host.split_once('%') {
        Some((host, scope)) if !scope.is_empty() && !scope.contains('%') => {
            (host, Some(scope.to_owned()))
        }
        Some(_) => bail!("invalid IPv6 scope: {value}"),
        None => (host, None),
    };
    let mut addr = if host == "*" {
        if family == "IPv6" {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        }
    } else {
        host.parse::<IpAddr>()
            .with_context(|| format!("invalid numeric endpoint: {value}"))?
    };
    if addr.is_ipv4() && scope.is_some() {
        bail!("IPv4 endpoint has a scope: {value}");
    }
    // lsof prints IPv4-mapped IPv6 peers in dotted notation, while retaining
    // the descriptor's IPv6 family. Preserve that family in the typed address.
    if let IpAddr::V4(ipv4) = addr {
        if family == "IPv6" {
            addr = IpAddr::V6(ipv4.to_ipv6_mapped());
        }
    }
    if addr.is_ipv6() != (family == "IPv6") {
        bail!("endpoint does not match {family}: {value}");
    }
    Ok((addr, scope, port))
}

fn parse_state(value: &str) -> TcpState {
    match value {
        "LISTEN" => TcpState::Listen,
        "ESTABLISHED" => TcpState::Established,
        "SYN_SENT" => TcpState::SynSent,
        "SYN_RCVD" | "SYN_RECEIVED" => TcpState::SynReceived,
        "FIN_WAIT_1" | "FIN_WAIT1" => TcpState::FinWait1,
        "FIN_WAIT_2" | "FIN_WAIT2" => TcpState::FinWait2,
        "CLOSE_WAIT" => TcpState::CloseWait,
        "CLOSING" => TcpState::Closing,
        "LAST_ACK" => TcpState::LastAck,
        "TIME_WAIT" => TcpState::TimeWait,
        "CLOSED" => TcpState::Closed,
        _ => TcpState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse_output(status: Option<i32>, stdout: &[u8], stderr: &[u8]) -> Result<ScanReport> {
        super::parse_output(status, stdout, stderr, &ScanOptions::default())
    }
    fn parse_fields(bytes: &[u8]) -> Result<ScanReport> {
        super::parse_fields(bytes, &ScanOptions::default())
    }
    const UDP: &[u8] =
        b"p123\0cspace name\0\nf3\0tIPv4\0PUDP\0n127.0.0.1:5353->8.8.8.8:53\0TQR=0\0TQS=0\0\n";

    #[test]
    fn parses_connected_udp_without_confusing_remote_port() {
        let report = parse_output(Some(0), UDP, b"").unwrap();
        let socket = &report.sockets[0];
        assert_eq!(socket.protocol, Protocol::Udp);
        assert_eq!(socket.local_port, 5353);
        assert_eq!(socket.remote_port, Some(53));
        assert_eq!(socket.remote_addr, Some("8.8.8.8".parse().unwrap()));
        assert_eq!(socket.state, None);
        assert_eq!(socket.owners[0].name.as_deref(), Some("space name"));
    }

    #[test]
    fn parses_tcp_ipv6_scopes_and_family_specific_wildcards() {
        let fixture = b"p12\0cx\0\nf3\0tIPv6\0PTCP\0n[fe80::1%en0]:8000->[fe80::2%en0]:9000\0TST=ESTABLISHED\0\nf4\0tIPv6\0PUDP\0n*:5353\0\nf5\0tIPv4\0PTCP\0n*:80\0TST=LISTEN\0\n";
        let report = parse_fields(fixture).unwrap();
        assert_eq!(report.sockets[0].local_scope.as_deref(), Some("en0"));
        assert_eq!(report.sockets[0].remote_scope.as_deref(), Some("en0"));
        assert_eq!(report.sockets[0].state, Some(TcpState::Established));
        assert_eq!(
            report.sockets[1].local_addr,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        );
        assert_eq!(
            report.sockets[2].local_addr,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn shared_socket_records_preserve_every_owner() {
        let report = parse_fields(b"p10\0ca\0\nf3\0tIPv4\0PTCP\0n*:80\0TST=LISTEN\0\nf4\0tIPv4\0PTCP\0n*:80\0TST=LISTEN\0\np20\0cb\0\nf5\0tIPv4\0PTCP\0n*:80\0TST=LISTEN\0\n").unwrap();
        let report = super::super::normalize(report, &crate::model::ScanOptions::default());
        assert_eq!(report.sockets.len(), 1);
        assert_eq!(
            report.sockets[0]
                .owners
                .iter()
                .map(|owner| owner.pid)
                .collect::<Vec<_>>(),
            [10, 20]
        );
    }

    #[test]
    fn ipv4_mapped_connections_keep_the_ipv6_socket_family() {
        let report = parse_fields(
            b"p12\0cx\0\nf5\0tIPv6\0PTCP\0n127.0.0.1:52001->127.0.0.1:59248\0TST=ESTABLISHED\0\n",
        )
        .unwrap();
        let socket = &report.sockets[0];
        assert_eq!(
            socket.local_addr,
            "::ffff:127.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            socket.remote_addr,
            Some("::ffff:127.0.0.1".parse::<IpAddr>().unwrap())
        );
        assert_eq!(socket.local_port, 52001);
        assert_eq!(socket.remote_port, Some(59248));
    }

    #[test]
    fn interprets_exit_status_and_diagnostics() {
        assert!(parse_output(Some(1), b"", b"").unwrap().sockets.is_empty());
        assert!(parse_output(Some(1), b"", b"permission denied").is_err());
        assert!(parse_output(Some(2), b"", b"").is_err());
        assert!(parse_output(None, UDP, b"").is_err());
        assert_eq!(parse_output(Some(1), UDP, b"").unwrap().sockets.len(), 1);
        let partial = parse_output(Some(1), UDP, b"WARNING: cannot inspect a process").unwrap();
        assert!(!partial.complete);
        assert_eq!(partial.sockets.len(), 1);
        assert_eq!(partial.sockets[0].ownership, OwnershipStatus::Partial);
        let partial = parse_output(Some(0), UDP, b"WARNING: cannot stat filesystem").unwrap();
        assert!(!partial.complete);
        assert_eq!(partial.sockets.len(), 1);
    }

    #[test]
    fn rejects_malformed_nonempty_output() {
        for malformed in [
            &b"not field output"[..],
            &b"p12\0cx\0\n"[..],
            &b"p12\0\nf3\0tIPv4\0PUDP\0\n"[..],
            &b"p12\0\nf3\0tIPv4\0PUDP\0nlocalhost:53\0\n"[..],
        ] {
            assert!(
                parse_output(Some(0), malformed, b"").is_err(),
                "accepted {malformed:?}"
            );
        }
    }

    #[test]
    fn unbound_sockets_are_not_port_occupants_and_unknown_states_warn() {
        assert!(parse_fields(b"p12\0\nf3\0tIPv4\0PUDP\0n*:*\0\n")
            .unwrap()
            .sockets
            .is_empty());
        let report = parse_fields(b"p12\0\nf3\0tIPv4\0PTCP\0n*:80\0TST=NEW_STATE\0\n").unwrap();
        assert!(!report.complete);
        assert_eq!(report.sockets[0].state, Some(TcpState::Unknown));
    }
    #[test]
    fn lsof_selectors_scope_protocol_and_preserve_mapped_ipv6_candidates() {
        for (protocol, family, expected) in [
            (Protocol::Tcp, AddressFamily::Ipv4, "-i4TCP"),
            (Protocol::Tcp, AddressFamily::Ipv6, "-iTCP"),
            (Protocol::Udp, AddressFamily::Ipv4, "-i4UDP"),
            (Protocol::Udp, AddressFamily::Ipv6, "-iUDP"),
        ] {
            let args = lsof_args(&ScanOptions {
                protocol: Some(protocol),
                family: Some(family),
                ..Default::default()
            });
            assert_eq!(
                args.iter()
                    .filter(|arg| arg.starts_with("-i"))
                    .copied()
                    .collect::<Vec<_>>(),
                [expected]
            );
        }
        assert_eq!(
            lsof_args(&ScanOptions {
                family: Some(AddressFamily::Ipv6),
                ..Default::default()
            }),
            ["-n", "-P", "-F0pcftPnT", "-iTCP", "-iUDP"]
        );
    }

    #[test]
    fn unknown_states_have_bounded_structured_warnings() {
        let mut fixture = String::from("p12\0cx\0\n");
        for port in 1000..1200 {
            fixture.push_str(&format!("f{port}\0tIPv4\0PTCP\0n*:{port}\0TST=NEW\0\n"));
        }
        let report = parse_fields(fixture.as_bytes()).unwrap();
        assert_eq!(report.sockets.len(), 200);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0].code, DiagnosticCode::UnknownState);
        assert!(report.warnings[0].message.len() < 1024);
        let partial = parse_output(Some(0), UDP, b"permission denied").unwrap();
        // Unstructured stderr cannot safely establish an OS error category.
        assert_eq!(partial.warnings[0].code, DiagnosticCode::SourceUnavailable);
    }
    #[test]
    fn native_family_filter_keeps_mapped_ipv6_and_ignores_unrelated_state_warnings() {
        let fixture = b"p12\0cx\0\nf3\0tIPv4\0PTCP\0n*:80\0TST=UNKNOWN_STATE\0\nf4\0tIPv6\0PTCP\0n127.0.0.1:52001->127.0.0.1:59248\0TST=ESTABLISHED\0\n";
        let options = ScanOptions {
            family: Some(AddressFamily::Ipv6),
            protocol: Some(Protocol::Tcp),
            ..Default::default()
        };
        let report = super::parse_output(Some(0), fixture, b"", &options).unwrap();
        assert_eq!(report.sockets.len(), 1);
        assert_eq!(
            report.sockets[0].local_addr,
            "::ffff:127.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert!(report.complete);
        assert!(report.warnings.is_empty());
        let report = super::parse_output(
            Some(0),
            fixture,
            b"",
            &ScanOptions {
                ports: vec![9999],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(report.sockets.is_empty());
        assert!(report.complete);
    }
}
