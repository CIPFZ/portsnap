use crate::model::{
    AddressFamily, DiagnosticCode, OwnershipStatus, ProcessInfo, Protocol, ScanOptions, ScanReport,
    SocketInfo, TcpState,
};
use anyhow::{bail, Result};
use std::{
    io,
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
};

pub(super) fn scan(options: &ScanOptions) -> Result<ScanReport> {
    super::scan_with_verified_owners(|| snapshot(options), crate::process::inspect)
}

fn snapshot(options: &ScanOptions) -> Result<ScanReport> {
    snapshot_with(options, table)
}

fn snapshot_with(
    options: &ScanOptions,
    mut query: impl FnMut(Protocol, u16) -> io::Result<Vec<SocketInfo>>,
) -> Result<ScanReport> {
    let mut report = ScanReport::new();
    let mut successful_tables = 0;
    let mut warnings = super::WarningSummary::default();
    for (protocol, family, source) in [
        (Protocol::Tcp, AF_INET, "TCP IPv4"),
        (Protocol::Tcp, AF_INET6, "TCP IPv6"),
        (Protocol::Udp, AF_INET, "UDP IPv4"),
        (Protocol::Udp, AF_INET6, "UDP IPv6"),
    ] {
        if !options.allows(
            protocol,
            if family == AF_INET {
                AddressFamily::Ipv4
            } else {
                AddressFamily::Ipv6
            },
        ) {
            continue;
        }
        match query(protocol, family) {
            Ok(sockets) => {
                successful_tables += 1;
                for socket in sockets.into_iter().filter(|socket| options.matches(socket)) {
                    if socket.ownership == OwnershipStatus::Unavailable {
                        warnings.record(
                            DiagnosticCode::OwnerUnavailable,
                            source,
                            format!("owner unavailable for local port {}", socket.local_port),
                        );
                    }
                    if socket.state == Some(TcpState::Unknown) {
                        warnings.record(
                            DiagnosticCode::UnknownState,
                            source,
                            format!(
                                "unrecognized TCP state for local port {}",
                                socket.local_port
                            ),
                        );
                    }
                    report.sockets.push(socket);
                }
            }
            Err(error) => report.warn(DiagnosticCode::from_io(&error), source, error.to_string()),
        }
    }
    warnings.append_to(&mut report);
    if successful_tables == 0 {
        bail!(
            "all requested Windows socket tables failed: {}",
            report
                .warnings
                .iter()
                .map(|warning| format!("{}: {}", warning.source, warning.message))
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    Ok(report)
}

fn table(protocol: Protocol, family: u16) -> io::Result<Vec<SocketInfo>> {
    let (buffer, byte_len) = read_table(|pointer, size| {
        // SAFETY: read_table supplies a null size-probe pointer or an aligned
        // writable allocation with at least *size bytes, alive for this call.
        unsafe {
            match protocol {
                Protocol::Tcp => GetExtendedTcpTable(
                    pointer,
                    size,
                    0,
                    u32::from(family),
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                ),
                Protocol::Udp => {
                    GetExtendedUdpTable(pointer, size, 0, u32::from(family), UDP_TABLE_OWNER_PID, 0)
                }
            }
        }
    })?;
    // SAFETY: each API/table class is paired with its Windows SDK row type.
    // These repr(C) rows contain only integer fields and byte arrays; every bit
    // pattern is valid. decode_rows validates every offset before reading.
    unsafe {
        match (protocol, family) {
            (Protocol::Tcp, AF_INET) => Ok(decode_rows::<MIB_TCPROW_OWNER_PID>(
                &buffer,
                byte_len,
                offset_of!(MIB_TCPTABLE_OWNER_PID, table),
            )?
            .into_iter()
            .map(tcp4)
            .collect()),
            (Protocol::Tcp, AF_INET6) => Ok(decode_rows::<MIB_TCP6ROW_OWNER_PID>(
                &buffer,
                byte_len,
                offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
            )?
            .into_iter()
            .map(tcp6)
            .collect()),
            (Protocol::Udp, AF_INET) => Ok(decode_rows::<MIB_UDPROW_OWNER_PID>(
                &buffer,
                byte_len,
                offset_of!(MIB_UDPTABLE_OWNER_PID, table),
            )?
            .into_iter()
            .map(udp4)
            .collect()),
            (Protocol::Udp, AF_INET6) => Ok(decode_rows::<MIB_UDP6ROW_OWNER_PID>(
                &buffer,
                byte_len,
                offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
            )?
            .into_iter()
            .map(udp6)
            .collect()),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported Windows address family {family}"),
            )),
        }
    }
}

fn read_table(
    mut query: impl FnMut(*mut std::ffi::c_void, &mut u32) -> u32,
) -> io::Result<(Vec<u64>, usize)> {
    let mut size = 0;
    let status = query(std::ptr::null_mut(), &mut size);
    if status != ERROR_INSUFFICIENT_BUFFER && status != NO_ERROR {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    for _ in 0..4 {
        if size < size_of::<u32>() as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Windows returned an invalid socket table size {size}"),
            ));
        }
        let capacity = (size as usize).div_ceil(size_of::<u64>());
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(capacity)
            .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
        buffer.resize(capacity, 0_u64);
        let status = query(buffer.as_mut_ptr().cast(), &mut size);
        if status == ERROR_INSUFFICIENT_BUFFER {
            continue;
        }
        if status != NO_ERROR {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if size as usize > buffer.len() * size_of::<u64>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned a table larger than its allocation",
            ));
        }
        return Ok((buffer, size as usize));
    }
    Err(io::Error::other(
        "Windows socket table kept growing during the scan; retry the query",
    ))
}

/// T must be the SDK integer-only row type associated with the requested table.
unsafe fn decode_rows<T: Copy>(
    buffer: &[u64],
    byte_len: usize,
    offset: usize,
) -> io::Result<Vec<T>> {
    if byte_len < size_of::<u32>() || byte_len > std::mem::size_of_val(buffer) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated Windows socket table header",
        ));
    }
    // SAFETY: the bounds above include a full u32, and unaligned reads do not
    // assume the alignment of the byte offset into the native table.
    let pointer = buffer.as_ptr().cast::<u8>();
    let count = unsafe { pointer.cast::<u32>().read_unaligned() } as usize;
    let rows_len = count
        .checked_mul(size_of::<T>())
        .and_then(|len| offset.checked_add(len))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows socket table row count overflow",
            )
        })?;
    if rows_len > byte_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated Windows socket table rows",
        ));
    }
    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: rows_len validates the entire range; the caller guarantees
        // the concrete row type's layout and that all bit patterns are valid.
        rows.push(unsafe {
            pointer
                .add(offset + index * size_of::<T>())
                .cast::<T>()
                .read_unaligned()
        });
    }
    Ok(rows)
}

fn owner_socket(
    protocol: Protocol,
    addr: IpAddr,
    scope: Option<String>,
    port: u32,
    pid: u32,
) -> SocketInfo {
    SocketInfo {
        protocol,
        local_addr: addr,
        local_scope: scope,
        local_port: u16::from_be(port as u16),
        remote_addr: None,
        remote_scope: None,
        remote_port: None,
        state: None,
        owners: if pid == 0 {
            Vec::new()
        } else {
            vec![ProcessInfo {
                pid,
                name: None,
                identity: None,
                details: None,
            }]
        },
        ownership: if pid == 0 {
            OwnershipStatus::Unavailable
        } else {
            OwnershipStatus::Complete
        },
    }
}

fn tcp4(row: MIB_TCPROW_OWNER_PID) -> SocketInfo {
    let mut socket = owner_socket(
        Protocol::Tcp,
        Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()).into(),
        None,
        row.dwLocalPort,
        row.dwOwningPid,
    );
    tcp_details(
        &mut socket,
        Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes()).into(),
        None,
        row.dwRemotePort,
        row.dwState,
    );
    socket
}

fn tcp6(row: MIB_TCP6ROW_OWNER_PID) -> SocketInfo {
    let mut socket = owner_socket(
        Protocol::Tcp,
        Ipv6Addr::from(row.ucLocalAddr).into(),
        scope(row.dwLocalScopeId),
        row.dwLocalPort,
        row.dwOwningPid,
    );
    tcp_details(
        &mut socket,
        Ipv6Addr::from(row.ucRemoteAddr).into(),
        scope(row.dwRemoteScopeId),
        row.dwRemotePort,
        row.dwState,
    );
    socket
}

fn udp4(row: MIB_UDPROW_OWNER_PID) -> SocketInfo {
    owner_socket(
        Protocol::Udp,
        Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()).into(),
        None,
        row.dwLocalPort,
        row.dwOwningPid,
    )
}

fn udp6(row: MIB_UDP6ROW_OWNER_PID) -> SocketInfo {
    owner_socket(
        Protocol::Udp,
        Ipv6Addr::from(row.ucLocalAddr).into(),
        scope(row.dwLocalScopeId),
        row.dwLocalPort,
        row.dwOwningPid,
    )
}

fn scope(value: u32) -> Option<String> {
    (value != 0).then(|| value.to_string())
}

fn tcp_details(
    socket: &mut SocketInfo,
    remote_addr: IpAddr,
    remote_scope: Option<String>,
    remote_port: u32,
    state: u32,
) {
    let state = match state {
        1 => TcpState::Closed,
        2 => TcpState::Listen,
        3 => TcpState::SynSent,
        4 => TcpState::SynReceived,
        5 => TcpState::Established,
        6 => TcpState::FinWait1,
        7 => TcpState::FinWait2,
        8 => TcpState::CloseWait,
        9 => TcpState::Closing,
        10 => TcpState::LastAck,
        11 => TcpState::TimeWait,
        12 => TcpState::DeleteTcb,
        _ => TcpState::Unknown,
    };
    socket.state = Some(state);
    // Remote fields in a LISTEN row are undefined in the Windows API.
    if state != TcpState::Listen {
        socket.remote_addr = Some(remote_addr);
        socket.remote_scope = remote_scope;
        socket.remote_port = Some(u16::from_be(remote_port as u16));
    }
    if socket.owners.is_empty() && state == TcpState::TimeWait {
        socket.ownership = OwnershipStatus::NotApplicable;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_native_addresses_ports_scopes_and_states() {
        let socket = tcp4(MIB_TCPROW_OWNER_PID {
            dwState: 2,
            dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwLocalPort: 8080_u16.to_be().into(),
            dwRemoteAddr: 99,
            dwRemotePort: 99,
            dwOwningPid: 12,
        });
        assert_eq!(socket.local_addr, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(socket.local_port, 8080);
        assert_eq!(socket.state, Some(TcpState::Listen));
        assert_eq!(socket.remote_addr, None);
        let socket = tcp6(MIB_TCP6ROW_OWNER_PID {
            ucLocalAddr: "fe80::1".parse::<Ipv6Addr>().unwrap().octets(),
            dwLocalScopeId: 7,
            dwLocalPort: 5353_u16.to_be().into(),
            ucRemoteAddr: "fe80::2".parse::<Ipv6Addr>().unwrap().octets(),
            dwRemoteScopeId: 8,
            dwRemotePort: 53_u16.to_be().into(),
            dwState: 5,
            dwOwningPid: 12,
        });
        assert_eq!(socket.local_scope.as_deref(), Some("7"));
        assert_eq!(socket.remote_scope.as_deref(), Some("8"));
        assert_eq!(socket.remote_port, Some(53));
        assert_eq!(socket.state, Some(TcpState::Established));
    }

    #[test]
    fn no_owner_in_time_wait_is_not_a_fake_pid() {
        let socket = tcp4(MIB_TCPROW_OWNER_PID {
            dwState: 11,
            dwLocalAddr: 0,
            dwLocalPort: 1,
            dwRemoteAddr: 0,
            dwRemotePort: 1,
            dwOwningPid: 0,
        });
        assert!(socket.owners.is_empty());
        assert_eq!(socket.ownership, OwnershipStatus::NotApplicable);
    }

    #[test]
    fn native_table_decoder_rejects_truncated_rows() {
        let buffer = [10_u64];
        // SAFETY: the row is an integer-only SDK type; deliberately short data
        // must fail bounds validation before any row is read.
        assert!(unsafe { decode_rows::<MIB_TCPROW_OWNER_PID>(&buffer, 8, 4) }.is_err());
        assert!(unsafe { decode_rows::<MIB_TCPROW_OWNER_PID>(&buffer, 3, 4) }.is_err());
    }

    #[test]
    fn retries_growing_tables_and_propagates_errors() {
        let mut calls = 0;
        let (buffer, len) = read_table(|pointer, size| {
            calls += 1;
            if calls <= 2 {
                *size = 8;
                return ERROR_INSUFFICIENT_BUFFER;
            }
            assert!(!pointer.is_null());
            *size = 8;
            NO_ERROR
        })
        .unwrap();
        assert_eq!(calls, 3);
        assert_eq!(len, 8);
        assert_eq!(buffer, [0]);
        assert!(read_table(|_, _| 5).is_err());
    }
    #[test]
    fn acquisition_skips_unrequested_tables_and_classifies_native_errors() {
        for (protocol, family, native_family) in [
            (Protocol::Tcp, AddressFamily::Ipv4, AF_INET),
            (Protocol::Tcp, AddressFamily::Ipv6, AF_INET6),
            (Protocol::Udp, AddressFamily::Ipv4, AF_INET),
            (Protocol::Udp, AddressFamily::Ipv6, AF_INET6),
        ] {
            let mut queried = Vec::new();
            let report = snapshot_with(
                &ScanOptions {
                    protocol: Some(protocol),
                    family: Some(family),
                    ..Default::default()
                },
                |p, f| {
                    queried.push((p, f));
                    if (p, f) == (protocol, native_family) {
                        Ok(Vec::new())
                    } else {
                        Err(io::Error::from_raw_os_error(5))
                    }
                },
            )
            .unwrap();
            assert_eq!(queried, [(protocol, native_family)]);
            assert!(report.complete);
        }
        let report = snapshot_with(
            &ScanOptions {
                family: Some(AddressFamily::Ipv4),
                ..Default::default()
            },
            |p, _| {
                if p == Protocol::Tcp {
                    Ok(Vec::new())
                } else {
                    Err(io::Error::from_raw_os_error(5))
                }
            },
        )
        .unwrap();
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0].code, DiagnosticCode::PermissionDenied);
        assert_eq!(report.warnings[0].source, "UDP IPv4");
    }

    #[test]
    fn malformed_tables_and_unknown_owner_warnings_are_structured_and_bounded() {
        let error = read_table(|_, size| {
            *size = 1;
            NO_ERROR
        })
        .unwrap_err();
        assert_eq!(DiagnosticCode::from_io(&error), DiagnosticCode::InvalidData);
        let report = snapshot_with(
            &ScanOptions {
                protocol: Some(Protocol::Tcp),
                family: Some(AddressFamily::Ipv4),
                ..Default::default()
            },
            |_, _| {
                Ok((1000_u16..1200)
                    .map(|port| {
                        owner_socket(
                            Protocol::Tcp,
                            IpAddr::V4(Ipv4Addr::LOCALHOST),
                            None,
                            port.to_be().into(),
                            0,
                        )
                    })
                    .collect())
            },
        )
        .unwrap();
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0].code, DiagnosticCode::OwnerUnavailable);
        assert!(report.warnings[0].message.len() < 1024);
    }
}
