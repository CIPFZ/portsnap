use crate::model::{OwnershipStatus, ScanOptions, ScanReport, SocketInfo};
use anyhow::Result;
use std::collections::BTreeMap;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "macos", test))]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

pub struct Scanner;

#[cfg(any(target_os = "macos", target_os = "windows", test))]
#[derive(Default)]
struct MetadataWarnings(BTreeMap<&'static str, (usize, Vec<String>)>);

#[cfg(any(target_os = "macos", target_os = "windows", test))]
impl MetadataWarnings {
    fn record(&mut self, class: &'static str, pid: u32, detail: &str) {
        let (count, examples) = self.0.entry(class).or_default();
        *count += 1;
        if examples.len() < 3 {
            let example = if detail.is_empty() {
                format!("PID {pid}")
            } else {
                format!("PID {pid}: {detail}")
            };
            examples.push(example.chars().take(180).collect());
        }
    }

    fn append_to(self, report: &mut ScanReport) {
        for (class, (count, examples)) in self.0 {
            report.warn(
                "process metadata",
                format!(
                    "{count} process(es) {class}; examples: {}",
                    examples.join("; ")
                ),
            );
        }
    }
}

/// Socket APIs expose numeric PIDs, so take process identities before the
/// accepted socket snapshot and verify them again afterward. A PID first seen
/// in the second snapshot remains visible but is never eligible for killing.
#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn scan_with_verified_owners(
    mut snapshot: impl FnMut() -> Result<ScanReport>,
    inspect: impl Fn(u32) -> std::io::Result<crate::model::ProcessInfo>,
) -> Result<ScanReport> {
    use crate::model::ProcessInfo;
    let first = snapshot()?;
    let pids: std::collections::BTreeSet<_> = first
        .sockets
        .iter()
        .flat_map(|socket| socket.owners.iter().map(|owner| owner.pid))
        .collect();
    let before: BTreeMap<_, _> = pids.into_iter().map(|pid| (pid, inspect(pid))).collect();
    let mut report = snapshot()?;
    report.complete &= first.complete;
    report.warnings.extend(first.warnings);
    let pids: std::collections::BTreeSet<_> = report
        .sockets
        .iter()
        .flat_map(|socket| socket.owners.iter().map(|owner| owner.pid))
        .collect();
    let mut verified: BTreeMap<u32, ProcessInfo> = BTreeMap::new();
    let mut warnings = MetadataWarnings::default();
    for pid in pids {
        let (class, detail) = match before.get(&pid) {
            Some(Ok(previous)) => match inspect(pid) {
                Ok(current)
                    if current.identity.is_some() && current.identity == previous.identity =>
                {
                    if current.name.is_none() {
                        warnings.record("had no readable process name", pid, "");
                    }
                    verified.insert(pid, current);
                    continue;
                }
                Ok(_) => (
                    "changed identity or had no verifiable identity",
                    String::new(),
                ),
                Err(error) => (
                    "could not be verified after the socket snapshot",
                    error.to_string(),
                ),
            },
            Some(Err(error)) => (
                "had unreadable identities before the socket snapshot",
                error.to_string(),
            ),
            None => (
                "appeared during the scan and could not be verified",
                String::new(),
            ),
        };
        warnings.record(class, pid, &detail);
    }
    warnings.append_to(&mut report);
    for socket in &mut report.sockets {
        for owner in &mut socket.owners {
            if let Some(process) = verified.get(&owner.pid) {
                *owner = process.clone();
            } else {
                owner.identity = None;
                socket.ownership = OwnershipStatus::Partial;
            }
        }
    }
    Ok(report)
}

impl Scanner {
    pub fn scan(options: &ScanOptions) -> Result<ScanReport> {
        #[cfg(target_os = "linux")]
        let report = linux::scan(options)?;
        #[cfg(target_os = "macos")]
        let report = macos::scan(options)?;
        #[cfg(target_os = "windows")]
        let report = windows::scan(options)?;
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        return Err(anyhow::anyhow!(
            "unsupported operating system: {}",
            std::env::consts::OS
        ));

        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        Ok(normalize(report, options))
    }
}

/// Present one deterministic row per endpoint, collecting every known owner.
/// A conflicting identity is deliberately made unusable for termination.
fn normalize(mut report: ScanReport, options: &ScanOptions) -> ScanReport {
    let mut endpoints = BTreeMap::new();
    for mut socket in std::mem::take(&mut report.sockets) {
        if !options.matches(&socket) {
            continue;
        }
        let key = (
            socket.local_port,
            socket.protocol,
            socket.local_addr,
            socket.local_scope.clone(),
            socket.remote_addr,
            socket.remote_scope.clone(),
            socket.remote_port,
            socket.state,
        );
        if let Some(existing) = endpoints.get_mut(&key) {
            let existing: &mut SocketInfo = existing;
            existing.ownership = merge_ownership(existing.ownership, socket.ownership);
            existing.owners.append(&mut socket.owners);
        } else {
            endpoints.insert(key, socket);
        }
    }
    for mut socket in endpoints.into_values() {
        let mut owners = BTreeMap::new();
        for owner in std::mem::take(&mut socket.owners) {
            if let Some(existing) = owners.get_mut(&owner.pid) {
                let existing: &mut crate::model::ProcessInfo = existing;
                if existing.identity != owner.identity {
                    existing.identity = None;
                    socket.ownership = OwnershipStatus::Partial;
                    report.warn(
                        "process identity",
                        format!(
                            "PID {} changed or could not be verified during the scan",
                            owner.pid
                        ),
                    );
                }
                if existing.name.is_none() {
                    existing.name = owner.name;
                }
            } else {
                owners.insert(owner.pid, owner);
            }
        }
        socket.owners = owners.into_values().collect();
        report.sockets.push(socket);
    }
    report
        .warnings
        .sort_by(|a, b| (&a.source, &a.message).cmp(&(&b.source, &b.message)));
    report.warnings.dedup();
    report
}

fn merge_ownership(a: OwnershipStatus, b: OwnershipStatus) -> OwnershipStatus {
    use OwnershipStatus::*;
    match (a, b) {
        (Partial, _) | (_, Partial) => Partial,
        (Complete, Unavailable) | (Unavailable, Complete) => Partial,
        (Unavailable, _) | (_, Unavailable) => Unavailable,
        (Complete, _) | (_, Complete) => Complete,
        (NotApplicable, NotApplicable) => NotApplicable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProcessIdentity, ProcessInfo, Protocol, TcpState};

    fn socket(pid: u32) -> SocketInfo {
        SocketInfo {
            protocol: Protocol::Tcp,
            local_addr: "127.0.0.1".parse().unwrap(),
            local_port: 8080,
            local_scope: None,
            remote_addr: None,
            remote_port: None,
            remote_scope: None,
            state: Some(TcpState::Listen),
            ownership: OwnershipStatus::Complete,
            owners: vec![ProcessInfo {
                pid,
                name: Some("worker".into()),
                identity: Some(ProcessIdentity { pid, start_time: 7 }),
            }],
        }
    }

    #[test]
    fn coalesces_shared_sockets_and_sorts_unique_owners() {
        let mut report = ScanReport::new();
        report.sockets = vec![socket(20), socket(10), socket(20)];
        let result = normalize(report, &ScanOptions::default());
        assert_eq!(result.sockets.len(), 1);
        assert_eq!(
            result.sockets[0]
                .owners
                .iter()
                .map(|owner| owner.pid)
                .collect::<Vec<_>>(),
            [10, 20]
        );
        assert!(result.complete);
    }

    #[test]
    fn rejects_conflicting_pid_identity() {
        let mut changed = socket(20);
        changed.owners[0].identity.as_mut().unwrap().start_time = 8;
        let mut report = ScanReport::new();
        report.sockets = vec![socket(20), changed];
        let result = normalize(report, &ScanOptions::default());
        assert!(!result.complete);
        assert_eq!(result.sockets[0].owners[0].identity, None);
        assert_eq!(result.sockets[0].ownership, OwnershipStatus::Partial);
    }

    #[test]
    fn central_filter_enforces_listening_and_local_port() {
        let mut report = ScanReport::new();
        let mut connected = socket(20);
        connected.state = Some(TcpState::Established);
        report.sockets = vec![socket(10), connected];
        let result = normalize(
            report,
            &ScanOptions {
                ports: vec![8080],
                listening_only: true,
            },
        );
        assert_eq!(result.sockets.len(), 1);
        assert_eq!(result.sockets[0].state, Some(TcpState::Listen));
    }

    #[test]
    fn snapshot_verification_detects_pid_reuse() {
        let calls = std::cell::Cell::new(0);
        let report = scan_with_verified_owners(
            || {
                let mut report = ScanReport::new();
                report.sockets.push(socket(20));
                Ok(report)
            },
            |pid| {
                calls.set(calls.get() + 1);
                Ok(ProcessInfo {
                    pid,
                    name: Some("worker".into()),
                    identity: Some(ProcessIdentity {
                        pid,
                        start_time: calls.get(),
                    }),
                })
            },
        )
        .unwrap();
        assert!(!report.complete);
        assert_eq!(report.sockets[0].owners[0].identity, None);
        assert_eq!(report.sockets[0].ownership, OwnershipStatus::Partial);
    }

    #[test]
    fn newly_appearing_process_is_visible_but_not_killable() {
        let mut calls = 0;
        let report = scan_with_verified_owners(
            || {
                calls += 1;
                let mut report = ScanReport::new();
                report
                    .sockets
                    .push(socket(if calls == 1 { 20 } else { 30 }));
                Ok(report)
            },
            |pid| Ok(socket(pid).owners.remove(0)),
        )
        .unwrap();
        assert!(!report.complete);
        assert_eq!(report.sockets[0].owners[0].pid, 30);
        assert_eq!(report.sockets[0].owners[0].identity, None);
    }

    #[test]
    fn stable_process_metadata_remains_eligible() {
        let report = scan_with_verified_owners(
            || {
                let mut report = ScanReport::new();
                report.sockets.push(socket(20));
                Ok(report)
            },
            |pid| Ok(socket(pid).owners.remove(0)),
        )
        .unwrap();
        assert!(report.complete);
        assert!(report.sockets[0].owners[0].identity.is_some());
    }

    #[test]
    fn inaccessible_processes_have_counted_bounded_diagnostics() {
        let report = scan_with_verified_owners(
            || {
                let mut report = ScanReport::new();
                report.sockets = (10..210).map(socket).collect();
                Ok(report)
            },
            |_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "access denied",
                ))
            },
        )
        .unwrap();
        assert!(!report.complete);
        assert_eq!(report.warnings.len(), 1);
        let warning = &report.warnings[0];
        assert_eq!(warning.source, "process metadata");
        assert!(warning.message.contains("200 process(es)"));
        assert!(warning.message.contains("access denied"));
        assert_eq!(warning.message.matches("PID ").count(), 3);
        assert!(warning.message.len() < 1024);
        assert!(report
            .sockets
            .iter()
            .all(|socket| socket.ownership == OwnershipStatus::Partial
                && socket.owners[0].identity.is_none()));
    }
}
