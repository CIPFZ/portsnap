//! Targeted metadata collection. Identities retain native timestamp precision.
use crate::model::{
    DetailField, DiagnosticCode, ProcessDetails, ProcessIdentity, ProcessInfo, ScanReport,
};
use std::{collections::BTreeMap, io};

#[cfg(target_os = "linux")]
#[path = "process/linux.rs"]
mod native;
#[cfg(target_os = "macos")]
#[path = "process/macos.rs"]
pub(crate) mod native;
#[cfg(windows)]
#[path = "process/windows.rs"]
pub(crate) mod native;

pub fn inspect(pid: u32) -> io::Result<ProcessInfo> {
    native::inspect(pid)
}

/// Collect requested fields once per identity, then attach them to all socket owners.
/// Identity checks bracket native reads: a PID alone never authorizes enrichment.
pub fn enrich_details(report: &mut ScanReport) {
    enrich_with(report, inspect, native::read_details);
}

fn enrich_with(
    report: &mut ScanReport,
    mut inspect: impl FnMut(u32) -> io::Result<ProcessInfo>,
    mut read: impl FnMut(u32) -> ProcessDetails,
) {
    let mut cache = BTreeMap::<(u32, Option<ProcessIdentity>), ProcessDetails>::new();
    let mut failures = BTreeMap::<DiagnosticCode, usize>::new();
    for owner in report
        .sockets
        .iter_mut()
        .flat_map(|socket| &mut socket.owners)
    {
        let key = (owner.pid, owner.identity);
        let details = cache.entry(key).or_insert_with(|| {
            let result = match owner.identity.filter(|identity| identity.pid == owner.pid) {
                None => identity_failure(DiagnosticCode::ProcessUnverified),
                Some(expected) => match verify(expected, &mut inspect) {
                    Err(code) => identity_failure(code),
                    Ok(()) => {
                        let details = read(owner.pid);
                        match verify(expected, &mut inspect) {
                            Ok(()) => details,
                            Err(code) => identity_failure(code),
                        }
                    }
                },
            };
            // One aggregate per code, counting affected identities rather than fields/sockets.
            let codes = result
                .warnings
                .iter()
                .map(|warning| warning.code)
                .collect::<std::collections::BTreeSet<_>>();
            for code in codes {
                *failures.entry(code).or_default() += 1;
            }
            result
        });
        owner.details = Some(details.clone());
    }
    for (code, count) in failures {
        report.warn(code, "process_details", format!("Requested details are incomplete for {count} process(es); see owner details warnings"));
    }
}

fn verify(
    expected: ProcessIdentity,
    inspect: &mut impl FnMut(u32) -> io::Result<ProcessInfo>,
) -> Result<(), DiagnosticCode> {
    match inspect(expected.pid) {
        Ok(actual) if actual.pid != expected.pid => Err(DiagnosticCode::ProcessChanged),
        Ok(actual) => match actual.identity {
            Some(identity) if identity == expected => Ok(()),
            Some(_) => Err(DiagnosticCode::ProcessChanged),
            None => Err(DiagnosticCode::ProcessUnverified),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(DiagnosticCode::ProcessExited),
        #[cfg(unix)]
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
            Err(DiagnosticCode::ProcessExited)
        }
        Err(error) => Err(DiagnosticCode::from_io(&error)),
    }
}

fn identity_failure(code: DiagnosticCode) -> ProcessDetails {
    let mut details = ProcessDetails::empty();
    details.warn(
        DetailField::Identity,
        code,
        match code {
            DiagnosticCode::ProcessChanged => {
                "Process identity changed; requested details were discarded"
            }
            DiagnosticCode::ProcessExited => "Process exited before details could be verified",
            _ => "Process identity could not be verified; requested details are unavailable",
        },
    );
    details
}

pub(super) fn detail_error(details: &mut ProcessDetails, field: DetailField, error: io::Error) {
    let code = if error.kind() == io::ErrorKind::NotFound {
        DiagnosticCode::MetadataUnavailable
    } else {
        DiagnosticCode::from_io(&error)
    };
    details.warn(field, code, error.to_string());
}

#[cfg(unix)]
fn unix_user(uid: libc::uid_t, details: &mut ProcessDetails) -> crate::model::ProcessUser {
    let name = match user_name(uid) {
        Ok(name) => Some(name),
        Err(error) => {
            detail_error(details, DetailField::User, error);
            None
        }
    };
    crate::model::ProcessUser {
        id: uid.to_string(),
        name,
    }
}

#[cfg(unix)]
fn user_name(uid: libc::uid_t) -> io::Result<String> {
    use std::{ffi::CStr, mem::MaybeUninit, ptr};
    let mut capacity = 1024;
    loop {
        let mut buffer = vec![0u8; capacity];
        let mut entry = MaybeUninit::<libc::passwd>::zeroed();
        let mut result = ptr::null_mut();
        // SAFETY: buffers are writable for their declared lengths. The reentrant API
        // stores string pointers into buffer, which remains alive through conversion.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && capacity < 1024 * 1024 {
            capacity *= 2;
            continue;
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        if result.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No account name is mapped to the effective user ID",
            ));
        }
        // SAFETY: successful getpwuid_r initialized entry and a NUL-terminated name.
        let entry = unsafe { entry.assume_init() };
        if entry.pw_name.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Account name is missing",
            ));
        }
        // SAFETY: name points into the live buffer returned by getpwuid_r.
        return Ok(unsafe { CStr::from_ptr(entry.pw_name) }
            .to_string_lossy()
            .into_owned());
    }
}

/// Darwin returns argc, executable path, NUL padding, argc arguments, then environment.
/// Read exactly argc arguments; environment entries must never become command arguments.
#[cfg(any(target_os = "macos", test))]
fn parse_macos_command(bytes: &[u8], pointer_size: usize) -> io::Result<Vec<String>> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid KERN_PROCARGS2 command data",
        )
    };
    let count = i32::from_ne_bytes(
        bytes
            .get(..4)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    );
    let count = usize::try_from(count).map_err(|_| invalid())?;
    let payload = bytes.get(4..).ok_or_else(invalid)?;
    let path_end = payload
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(invalid)?;
    if count == 0 {
        return Ok(Vec::new());
    }
    // XNU aligns the saved executable path including its internal
    // "executable_path=" prefix, then removes that 15-byte prefix from sysctl
    // output. Skipping all NULs would lose an empty argv[0] and expose env entries.
    const EXECUTABLE_PREFIX: usize = b"executable_path=".len();
    if !matches!(pointer_size, 4 | 8) {
        return Err(invalid());
    }
    let start = (EXECUTABLE_PREFIX + path_end + 1).div_ceil(pointer_size) * pointer_size
        - EXECUTABLE_PREFIX;
    let padding = payload.get(path_end + 1..start).ok_or_else(invalid)?;
    if padding.iter().any(|&byte| byte != 0) {
        return Err(invalid());
    }
    let mut remaining = payload.get(start..).ok_or_else(invalid)?;
    if count > remaining.len() {
        return Err(invalid());
    }
    let mut command = Vec::with_capacity(count);
    for _ in 0..count {
        let end = remaining
            .iter()
            .position(|&byte| byte == 0)
            .ok_or_else(invalid)?;
        command.push(String::from_utf8_lossy(&remaining[..end]).into_owned());
        remaining = &remaining[end + 1..];
    }
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{OwnershipStatus, Protocol, SocketInfo};

    fn owner() -> ProcessInfo {
        ProcessInfo {
            pid: 42,
            name: Some("test".into()),
            identity: Some(ProcessIdentity {
                pid: 42,
                start_time: 123,
            }),
            details: None,
        }
    }
    fn report(owners: Vec<ProcessInfo>) -> ScanReport {
        ScanReport {
            sockets: vec![SocketInfo {
                protocol: Protocol::Tcp,
                local_addr: "127.0.0.1".parse().unwrap(),
                local_port: 8080,
                local_scope: None,
                remote_addr: None,
                remote_port: None,
                remote_scope: None,
                state: None,
                owners,
                ownership: OwnershipStatus::Complete,
            }],
            ..ScanReport::new()
        }
    }
    #[test]
    fn shared_owner_read_once_and_partial_fields_survive() {
        let mut report = report(vec![owner(), owner()]);
        let mut reads = 0;
        let mut inspections = 0;
        enrich_with(
            &mut report,
            |_| {
                inspections += 1;
                Ok(owner())
            },
            |_| {
                reads += 1;
                let mut details = ProcessDetails::empty();
                details.parent_pid = Some(7);
                detail_error(
                    &mut details,
                    DetailField::Executable,
                    io::Error::from(io::ErrorKind::PermissionDenied),
                );
                detail_error(
                    &mut details,
                    DetailField::Command,
                    io::Error::from(io::ErrorKind::PermissionDenied),
                );
                details
            },
        );
        assert_eq!((reads, inspections), (1, 2));
        assert!(!report.complete);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0].code, DiagnosticCode::PermissionDenied);
        for owner in &report.sockets[0].owners {
            assert_eq!(owner.details.as_ref().unwrap().parent_pid, Some(7));
        }
    }
    #[test]
    fn unknown_identity_never_reads_metadata() {
        let mut process = owner();
        process.identity = None;
        let mut report = report(vec![process]);
        enrich_with(
            &mut report,
            |_| panic!("must not inspect unverified PID"),
            |_| panic!("must not collect"),
        );
        assert_eq!(report.warnings[0].code, DiagnosticCode::ProcessUnverified);
    }
    #[test]
    fn replacement_during_reads_discards_every_field() {
        let mut report = report(vec![owner()]);
        let mut count = 0;
        enrich_with(
            &mut report,
            |_| {
                count += 1;
                let mut result = owner();
                if count == 2 {
                    result.identity.as_mut().unwrap().start_time += 1;
                }
                Ok(result)
            },
            |_| ProcessDetails {
                executable: Some("/wrong/process".into()),
                ..ProcessDetails::empty()
            },
        );
        let details = report.sockets[0].owners[0].details.as_ref().unwrap();
        assert!(details.executable.is_none());
        assert_eq!(details.warnings[0].code, DiagnosticCode::ProcessChanged);
    }
    #[test]
    fn identity_read_errors_keep_native_codes_before_and_after_collection() {
        for (kind, code) in [
            (io::ErrorKind::NotFound, DiagnosticCode::ProcessExited),
            (
                io::ErrorKind::PermissionDenied,
                DiagnosticCode::PermissionDenied,
            ),
            (io::ErrorKind::InvalidData, DiagnosticCode::InvalidData),
            (io::ErrorKind::Unsupported, DiagnosticCode::Unsupported),
            (io::ErrorKind::Other, DiagnosticCode::SourceUnavailable),
        ] {
            for fails_after_read in [false, true] {
                let mut report = report(vec![owner()]);
                let mut inspections = 0;
                let mut reads = 0;
                enrich_with(
                    &mut report,
                    |_| {
                        inspections += 1;
                        if fails_after_read && inspections == 1 {
                            Ok(owner())
                        } else {
                            // Identical messages demonstrate that classification uses the
                            // structured native error, not free-text matching.
                            Err(io::Error::new(kind, "same diagnostic text"))
                        }
                    },
                    |_| {
                        reads += 1;
                        ProcessDetails {
                            executable: Some("/unverified/program".into()),
                            command: Some(vec!["unverified argument".into()]),
                            ..ProcessDetails::empty()
                        }
                    },
                );
                assert_eq!(reads, usize::from(fails_after_read));
                assert!(!report.complete);
                assert_eq!(report.warnings.len(), 1);
                assert_eq!(report.warnings[0].code, code);
                let details = report.sockets[0].owners[0].details.as_ref().unwrap();
                assert!(details.executable.is_none());
                assert!(details.command.is_none());
                assert_eq!(details.warnings.len(), 1);
                assert_eq!(details.warnings[0].field, DetailField::Identity);
                assert_eq!(details.warnings[0].code, code);
            }
        }
    }
    #[test]
    fn missing_inspected_identity_remains_unverified() {
        let mut report = report(vec![owner()]);
        enrich_with(
            &mut report,
            |_| {
                let mut process = owner();
                process.identity = None;
                Ok(process)
            },
            |_| panic!("must not collect for missing identity"),
        );
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0].code, DiagnosticCode::ProcessUnverified);
    }
    #[cfg(unix)]
    #[test]
    fn native_esrch_identity_error_reports_process_exited() {
        let mut report = report(vec![owner()]);
        enrich_with(
            &mut report,
            |_| Err(io::Error::from_raw_os_error(libc::ESRCH)),
            |_| panic!("must not collect for exited process"),
        );
        assert_eq!(report.warnings[0].code, DiagnosticCode::ProcessExited);
    }
    fn macos_fixture(path: &[u8], args: &[&[u8]], pointer_size: usize) -> Vec<u8> {
        let mut bytes = (args.len() as i32).to_ne_bytes().to_vec();
        bytes.extend_from_slice(path);
        bytes.push(0);
        while (bytes.len() - 4 + b"executable_path=".len()) % pointer_size != 0 {
            bytes.push(0);
        }
        for arg in args {
            bytes.extend_from_slice(arg);
            bytes.push(0);
        }
        bytes.extend_from_slice(b"SECRET=hidden\0");
        bytes
    }
    #[test]
    fn macos_arguments_preserve_spaces_and_empty_args_and_exclude_environment() {
        for pointer_size in [4, 8] {
            let bytes = macos_fixture(
                b"/a path/program",
                &[b"program", b"two words", b"", b"last"],
                pointer_size,
            );
            assert_eq!(
                parse_macos_command(&bytes, pointer_size).unwrap(),
                ["program", "two words", "", "last"]
            );
            let bytes = macos_fixture(b"/bin/a", &[b"", b"arg1"], pointer_size);
            assert_eq!(
                parse_macos_command(&bytes, pointer_size).unwrap(),
                ["", "arg1"]
            );
        }
    }
    #[test]
    fn macos_arguments_reject_missing_header_padding_or_truncated_argv() {
        assert!(parse_macos_command(&[], 8).is_err());
        let mut bytes = macos_fixture(b"/bin/a", &[b"a", b"unfinished"], 8);
        bytes.truncate(bytes.len() - b"SECRET=hidden\0".len() - 1);
        assert!(parse_macos_command(&bytes, 8).is_err());
        let bytes = macos_fixture(b"/bin/a", &[], 8);
        assert!(parse_macos_command(&bytes, 8).unwrap().is_empty());
        let mut bytes = macos_fixture(b"/bin/a", &[b"a"], 8);
        bytes[4 + b"/bin/a\0".len()] = b'x';
        assert!(parse_macos_command(&bytes, 8).is_err());
    }
}
