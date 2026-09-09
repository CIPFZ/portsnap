use crate::model::{
    OwnershipStatus, ProcessInfo, Protocol, ScanOptions, ScanReport, SocketInfo, TcpState,
};
use anyhow::{bail, Context, Result};
use procfs::{net, FromReadSI};
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    net::SocketAddr,
    path::Path,
};

struct SocketRecord {
    socket: SocketInfo,
    inode: u64,
}

pub(super) fn scan(options: &ScanOptions) -> Result<ScanReport> {
    let mut report = ScanReport::new();
    // /proc/self/net is deliberately scoped to this process's network namespace.
    let records = read_tables(Path::new("/proc/self/net"), options, &mut report)?;
    let targets = records
        .iter()
        .map(|record| record.inode)
        .filter(|inode| *inode != 0)
        .collect::<HashSet<_>>();
    let mut index = OwnerIndex::default();
    if !targets.is_empty() {
        match collect_owners(Path::new("/proc"), &targets, crate::process::inspect) {
            Ok(found) => index = found,
            Err(error) => {
                report.warn("/proc", format!("Cannot enumerate process owners: {error}"));
                index.issues.record(&error);
            }
        }
        if index.issues.permission_denied != 0 || index.issues.other != 0 {
            report.warn(
                "/proc/*/fd",
                format!(
                    "Owner lookup was incomplete: {} permission denials and {} other read errors",
                    index.issues.permission_denied, index.issues.other
                ),
            );
        }
        if index.issues.changed_owners != 0 {
            report.warn(
                "/proc/*/fd",
                format!(
                    "{} process owner observation(s) changed during the scan",
                    index.issues.changed_owners
                ),
            );
        }
        // hidepid can omit whole processes without returning a permission error.
        if fs::read_to_string("/proc/self/mountinfo")
            .is_ok_and(|mounts| has_hidden_processes(&mounts))
        {
            index.issues.other += 1;
            report.warn(
                "/proc",
                "The procfs hidepid setting can hide additional socket owners",
            );
        }
    }
    let incomplete = index.issues.permission_denied != 0
        || index.issues.other != 0
        || index.issues.changed_owners != 0;
    let mut unknown = 0;
    for mut record in records {
        record.socket.owners = index.owners.get(&record.inode).cloned().unwrap_or_default();
        record.socket.ownership = if record.inode == 0 {
            // Kernel-owned TCP states, including TIME_WAIT, have no process FD.
            OwnershipStatus::NotApplicable
        } else if record.socket.owners.is_empty() {
            unknown += 1;
            OwnershipStatus::Unavailable
        } else if incomplete {
            OwnershipStatus::Partial
        } else {
            OwnershipStatus::Complete
        };
        report.sockets.push(record.socket);
    }
    if unknown != 0 {
        report.warn(
            "/proc/*/fd",
            format!(
                "Could not resolve owners for {unknown} socket(s); access restrictions or sockets changing during the scan can cause this"
            ),
        );
    }
    Ok(report)
}

fn read_tables(
    root: &Path,
    options: &ScanOptions,
    report: &mut ScanReport,
) -> Result<Vec<SocketRecord>> {
    let mut records = Vec::new();
    let mut readable = 0;
    for (name, protocol) in [
        ("tcp", Protocol::Tcp),
        ("tcp6", Protocol::Tcp),
        ("udp", Protocol::Udp),
        ("udp6", Protocol::Udp),
    ] {
        let path = root.join(name);
        match read_table(&path, protocol) {
            Ok(entries) => {
                readable += 1;
                records.extend(
                    entries
                        .into_iter()
                        .filter(|entry| options.matches(&entry.socket)),
                );
            }
            Err(error) => report.warn(path.display().to_string(), format!("{error:#}")),
        }
    }
    if readable == 0 {
        bail!(
            "Cannot read any TCP/UDP socket table: {}",
            report
                .warnings
                .iter()
                .map(|warning| format!("{}: {}", warning.source, warning.message))
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    Ok(records)
}

fn read_table(path: &Path, protocol: Protocol) -> Result<Vec<SocketRecord>> {
    let data = fs::read_to_string(path).context("Cannot read socket table")?;
    // procfs skips the first line unconditionally; reject empty/truncated input here.
    let header = data.lines().next().unwrap_or_default();
    if !header.contains("local_address") || !header.contains("inode") {
        bail!("Socket table has a missing or invalid header");
    }
    let system = procfs::current_system_info();
    match protocol {
        Protocol::Tcp => Ok(net::TcpNetEntries::from_read(data.as_bytes(), system)?
            .0
            .into_iter()
            .map(|entry| {
                record(
                    protocol,
                    entry.local_address,
                    entry.remote_address,
                    Some(tcp_state(entry.state)),
                    entry.inode,
                )
            })
            .collect()),
        Protocol::Udp => Ok(net::UdpNetEntries::from_read(data.as_bytes(), system)?
            .0
            .into_iter()
            .map(|entry| {
                record(
                    protocol,
                    entry.local_address,
                    entry.remote_address,
                    None,
                    entry.inode,
                )
            })
            .collect()),
    }
}

fn record(
    protocol: Protocol,
    local: SocketAddr,
    remote: SocketAddr,
    state: Option<TcpState>,
    inode: u64,
) -> SocketRecord {
    let has_remote = remote.port() != 0 || !remote.ip().is_unspecified();
    SocketRecord {
        socket: SocketInfo {
            protocol,
            local_addr: local.ip(),
            local_scope: None,
            local_port: local.port(),
            remote_addr: has_remote.then(|| remote.ip()),
            remote_scope: None,
            remote_port: has_remote.then(|| remote.port()),
            state,
            owners: Vec::new(),
            ownership: OwnershipStatus::Unavailable,
        },
        inode,
    }
}

fn tcp_state(state: net::TcpState) -> TcpState {
    match state {
        net::TcpState::Established => TcpState::Established,
        net::TcpState::SynSent => TcpState::SynSent,
        net::TcpState::SynRecv | net::TcpState::NewSynRecv => TcpState::SynReceived,
        net::TcpState::FinWait1 => TcpState::FinWait1,
        net::TcpState::FinWait2 => TcpState::FinWait2,
        net::TcpState::TimeWait => TcpState::TimeWait,
        net::TcpState::Close => TcpState::Closed,
        net::TcpState::CloseWait => TcpState::CloseWait,
        net::TcpState::LastAck => TcpState::LastAck,
        net::TcpState::Listen => TcpState::Listen,
        net::TcpState::Closing => TcpState::Closing,
    }
}

#[derive(Default)]
struct AccessIssues {
    permission_denied: usize,
    other: usize,
    changed_owners: usize,
}

impl AccessIssues {
    fn record(&mut self, error: &io::Error) {
        match error.kind() {
            io::ErrorKind::NotFound => {} // Processes and FDs routinely disappear.
            io::ErrorKind::PermissionDenied => self.permission_denied += 1,
            _ if error.raw_os_error() == Some(libc::ESRCH) => {}
            _ => self.other += 1,
        }
    }
}

#[derive(Default)]
struct OwnerIndex {
    owners: HashMap<u64, Vec<ProcessInfo>>,
    issues: AccessIssues,
}

fn collect_owners(
    root: &Path,
    targets: &HashSet<u64>,
    mut inspect: impl FnMut(u32) -> io::Result<ProcessInfo>,
) -> io::Result<OwnerIndex> {
    let mut index = OwnerIndex::default();
    // Exactly one process/FD traversal, regardless of the number of target sockets.
    for entry in fs::read_dir(root)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                index.issues.record(&error);
                continue;
            }
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let before = match inspect(pid) {
            Ok(process) => process,
            Err(error) => {
                index.issues.record(&error);
                continue;
            }
        };
        let fds = match fs::read_dir(entry.path().join("fd")) {
            Ok(fds) => fds,
            Err(error) => {
                index.issues.record(&error);
                continue;
            }
        };
        let mut held = HashSet::new();
        for fd in fds {
            let link = fd.and_then(|fd| fs::read_link(fd.path()));
            match link {
                Ok(link) => {
                    if let Some(inode) = link
                        .to_str()
                        .and_then(|link| link.strip_prefix("socket:["))
                        .and_then(|link| link.strip_suffix(']'))
                        .and_then(|inode| inode.parse::<u64>().ok())
                        .filter(|inode| targets.contains(inode))
                    {
                        held.insert(inode);
                    }
                }
                Err(error) => index.issues.record(&error),
            }
        }
        if held.is_empty() {
            continue;
        }
        let after = match inspect(pid) {
            Ok(process) => process,
            Err(error) => {
                index.issues.record(&error);
                index.issues.changed_owners += 1;
                continue;
            }
        };
        // Never attach FD observations to an identity read only after a PID reuse.
        if before.identity.is_none() || before.identity != after.identity {
            index.issues.changed_owners += 1;
            continue;
        }
        for inode in held {
            index.owners.entry(inode).or_default().push(after.clone());
        }
    }
    for owners in index.owners.values_mut() {
        owners.sort_by_key(|owner| owner.pid);
    }
    Ok(index)
}

fn has_hidden_processes(mountinfo: &str) -> bool {
    mountinfo.lines().any(|line| {
        let Some((mount, filesystem)) = line.split_once(" - ") else {
            return false;
        };
        let fields = mount.split_whitespace().collect::<Vec<_>>();
        fields.get(4) == Some(&"/proc")
            && filesystem.starts_with("proc ")
            && line
                .split(|c: char| c == ',' || c.is_whitespace())
                .any(|option| {
                    option
                        .strip_prefix("hidepid=")
                        .is_some_and(|value| value != "0" && value != "off")
                })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProcessIdentity;
    use std::{
        os::unix::fs::symlink,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "portsnap-proc-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }
        fn table(&self, name: &str, rows: &str) {
            fs::write(self.0.join(name), format!("{HEADER}{rows}")).unwrap();
        }
        fn fd(&self, pid: u32, fd: u32, inode: u64) {
            let directory = self.0.join(pid.to_string()).join("fd");
            fs::create_dir_all(&directory).unwrap();
            symlink(format!("socket:[{inode}]"), directory.join(fd.to_string())).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn process(pid: u32, start_time: u64) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: Some(format!("process-{pid}")),
            identity: Some(ProcessIdentity { pid, start_time }),
        }
    }

    #[test]
    fn all_unavailable_tables_fail_and_partial_tables_warn() {
        let fixture = Fixture::new();
        let options = ScanOptions::default();
        assert!(read_tables(&fixture.0, &options, &mut ScanReport::new()).is_err());
        fixture.table("tcp", "");
        let mut report = ScanReport::new();
        assert!(read_tables(&fixture.0, &options, &mut report)
            .unwrap()
            .is_empty());
        assert!(!report.complete);
        assert_eq!(report.warnings.len(), 3);
        fixture.table("tcp6", "");
        fixture.table("udp", "");
        fixture.table("udp6", "");
        let mut report = ScanReport::new();
        assert!(read_tables(&fixture.0, &options, &mut report)
            .unwrap()
            .is_empty());
        assert!(report.complete);
    }

    #[test]
    fn malformed_tables_are_not_empty_successes() {
        let fixture = Fixture::new();
        for data in ["", "garbage", HEADER, "bad header\ngarbage\n"] {
            fs::write(fixture.0.join("tcp"), data).unwrap();
            assert_eq!(
                read_table(&fixture.0.join("tcp"), Protocol::Tcp).is_ok(),
                data == HEADER
            );
        }
        fixture.table("tcp", "truncated row\n");
        assert!(read_table(&fixture.0.join("tcp"), Protocol::Tcp).is_err());
    }

    #[test]
    fn established_and_connected_udp_keep_local_and_remote_endpoints() {
        let fixture = Fixture::new();
        // procfs renders addresses using the native byte order.
        let local = format!("{:08X}", u32::from_ne_bytes([127, 0, 0, 1]));
        let remote = format!("{:08X}", u32::from_ne_bytes([8, 8, 8, 8]));
        let row = format!("0: {local}:14E9 {remote}:0035 01 00000000:00000000 00:00000000 00000000 1000 0 123 1\n");
        fixture.table("tcp", &row);
        fixture.table("udp", &row);
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            let name = if protocol == Protocol::Tcp {
                "tcp"
            } else {
                "udp"
            };
            let entry = read_table(&fixture.0.join(name), protocol)
                .unwrap()
                .remove(0)
                .socket;
            assert_eq!(entry.local_addr.to_string(), "127.0.0.1");
            assert_eq!(entry.local_port, 5353);
            assert_eq!(entry.remote_addr.unwrap().to_string(), "8.8.8.8");
            assert_eq!(entry.remote_port, Some(53));
            assert!(ScanOptions {
                ports: vec![5353],
                listening_only: false
            }
            .matches(&entry));
            assert_eq!(
                ScanOptions {
                    ports: vec![5353],
                    listening_only: true
                }
                .matches(&entry),
                protocol == Protocol::Udp
            );
        }
    }

    #[test]
    fn one_traversal_keeps_shared_owners_and_deduplicates_fds() {
        let fixture = Fixture::new();
        fixture.fd(10, 3, 123);
        fixture.fd(10, 4, 123);
        fixture.fd(10, 5, 456);
        fixture.fd(20, 3, 123);
        let mut reads = HashMap::<u32, u32>::new();
        let owners = collect_owners(&fixture.0, &HashSet::from([123, 456]), |pid| {
            *reads.entry(pid).or_default() += 1;
            Ok(process(pid, 100))
        })
        .unwrap();
        assert_eq!(
            owners.owners[&123]
                .iter()
                .map(|owner| owner.pid)
                .collect::<Vec<_>>(),
            vec![10, 20]
        );
        assert_eq!(owners.owners[&456].len(), 1);
        assert_eq!(reads, HashMap::from([(10, 2), (20, 2)]));
    }

    #[test]
    fn changed_process_identity_discards_stale_owner_observations() {
        let fixture = Fixture::new();
        fixture.fd(10, 3, 123);
        let mut start = 100;
        let index = collect_owners(&fixture.0, &HashSet::from([123]), |pid| {
            start += 1;
            Ok(process(pid, start))
        })
        .unwrap();
        assert!(index.owners.is_empty());
        assert_eq!(index.issues.changed_owners, 1);
    }

    #[test]
    fn missing_processes_are_expected_but_permissions_are_reported() {
        let fixture = Fixture::new();
        fixture.fd(10, 3, 123);
        for (kind, expected) in [
            (io::ErrorKind::NotFound, 0),
            (io::ErrorKind::PermissionDenied, 1),
        ] {
            let index = collect_owners(&fixture.0, &HashSet::from([123]), |_| {
                Err(io::Error::from(kind))
            })
            .unwrap();
            assert_eq!(index.issues.permission_denied, expected);
            assert_eq!(index.issues.other, 0);
        }
    }

    #[test]
    fn hidden_proc_mounts_are_detected() {
        assert!(has_hidden_processes(
            "22 1 0:20 / /proc rw - proc proc rw,hidepid=2\n"
        ));
        assert!(!has_hidden_processes(
            "22 1 0:20 / /proc rw - proc proc rw,hidepid=0\n"
        ));
        assert!(!has_hidden_processes(
            "22 1 0:20 / /elsewhere rw - proc proc rw,hidepid=2\n"
        ));
    }
}
