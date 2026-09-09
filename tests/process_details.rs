#![cfg(unix)]

use portsnap::{
    model::{OwnershipStatus, Protocol, ScanReport, SocketInfo},
    process,
};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[test]
fn owned_process_details_keep_argv_user_parent_and_timestamp() {
    let before = now_ms();
    let script = "printf 'PORTSNAP_READY\\n'; read response";
    let mut child = ChildGuard(
        Command::new("/bin/sh")
            .args([
                "-c",
                script,
                "portsnap process details",
                "two words",
                "",
                "last",
            ])
            .env("PORTSNAP_DETAIL_SECRET", "not-part-of-command-5cac331d")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut line = String::new();
    BufReader::new(child.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "PORTSNAP_READY");
    let owner = process::inspect(child.0.id()).unwrap();
    assert!(
        owner.details.is_none(),
        "basic inspection must not read details"
    );
    let mut report = ScanReport {
        sockets: vec![SocketInfo {
            protocol: Protocol::Tcp,
            local_addr: "127.0.0.1".parse().unwrap(),
            local_port: 8080,
            local_scope: None,
            remote_addr: None,
            remote_port: None,
            remote_scope: None,
            state: None,
            owners: vec![owner],
            ownership: OwnershipStatus::Complete,
        }],
        ..ScanReport::new()
    };
    process::enrich_details(&mut report);
    let details = report.sockets[0].owners[0].details.as_ref().unwrap();
    assert!(report.complete, "{:?}", details.warnings);
    let executable = details.executable.as_ref().unwrap();
    assert_eq!(
        std::fs::canonicalize(executable).unwrap(),
        std::fs::canonicalize("/bin/sh").unwrap()
    );
    let command = details.command.as_ref().unwrap();
    assert_eq!(
        &command[1..],
        [
            "-c",
            script,
            "portsnap process details",
            "two words",
            "",
            "last"
        ]
    );
    assert!(!command
        .iter()
        .any(|value| value.contains("not-part-of-command-5cac331d")));
    assert_eq!(details.parent_pid, Some(std::process::id()));
    // SAFETY: geteuid takes no pointers and returns this test process's effective UID.
    assert_eq!(
        details.user.as_ref().unwrap().id,
        unsafe { libc::geteuid() }.to_string()
    );
    let started = details.start_time_unix_ms.unwrap();
    // Linux btime has whole-second precision; allow that source's rounding.
    assert!(
        started >= before.saturating_sub(2000) && started <= now_ms() + 1000,
        "unexpected process start timestamp: {started}"
    );
    child.0.stdin.take().unwrap().write_all(b"exit\n").unwrap();
    assert!(child.0.wait().unwrap().success());
}
