use portsnap::{
    killer::{KillError, KillOutcome, PreparedTarget},
    model::{ProcessIdentity, ProcessInfo},
    process,
};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, Command, Stdio},
    time::Duration,
};

const CHILD_ENV: &str = "PORTSNAP_TERMINATION_TEST_CHILD";

// Running our own test executable provides a portable child without shell descendants.
#[test]
fn owned_child_helper() {
    let Ok(mode) = std::env::var(CHILD_ENV) else {
        return;
    };
    #[cfg(unix)]
    if mode == "ignore-term" {
        // SAFETY: only this isolated test child changes its own signal disposition.
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
        }
    }
    #[cfg(not(unix))]
    let _ = mode;
    println!("PORTSNAP_CHILD_READY");
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_secs(60));
}

struct OwnedChild(Child);

impl OwnedChild {
    fn spawn(mode: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "owned_child_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, mode)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut child = Self(child);
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            assert_ne!(
                reader.read_line(&mut line).unwrap(),
                0,
                "child exited before readiness: {:?}",
                child.0.try_wait()
            );
            if line.contains("PORTSNAP_CHILD_READY") {
                break;
            }
            line.clear();
        }
        child
    }

    fn info(&self) -> ProcessInfo {
        process::inspect(self.0.id()).unwrap()
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        // These PIDs belong to Child handles created by this test and are never reaped
        // before cleanup, so child.kill cannot target a recycled unrelated Unix PID.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn prepare_or_explicit_macos_skip(info: &ProcessInfo) -> Option<PreparedTarget> {
    match PreparedTarget::prepare(info) {
        Ok(target) => Some(target),
        #[cfg(target_os = "macos")]
        Err(KillError::PermissionDenied(reason)) if reason.contains("task_for_pid denied") => {
            eprintln!("macOS capability unavailable: {reason}");
            None
        }
        Err(error) => panic!("prepare target: {error}"),
    }
}

#[test]
fn precise_metadata_is_stable_for_a_live_process() {
    let child = OwnedChild::spawn("normal");
    let first = child.info();
    let second = child.info();
    assert_eq!(first.identity, second.identity);
    assert_eq!(first.identity.unwrap().pid, child.0.id());
    assert!(!first.name.unwrap().is_empty());
}

#[test]
fn refuses_stale_identity_without_signalling_child() {
    let mut child = OwnedChild::spawn("normal");
    let mut stale = child.info();
    stale.identity.as_mut().unwrap().start_time ^= 1;
    assert!(matches!(
        PreparedTarget::prepare(&stale),
        Err(KillError::IdentityChanged)
    ));
    assert!(child.0.try_wait().unwrap().is_none());
}

#[test]
fn refuses_protected_missing_and_inconsistent_identity() {
    for pid in [0, 1, std::process::id()] {
        let info = ProcessInfo {
            pid,
            name: None,
            identity: Some(ProcessIdentity { pid, start_time: 1 }),
        };
        assert!(matches!(
            PreparedTarget::prepare(&info),
            Err(KillError::Refused(_))
        ));
    }
    let child = OwnedChild::spawn("normal");
    let mut info = child.info();
    info.identity = None;
    assert!(matches!(
        PreparedTarget::prepare(&info),
        Err(KillError::Refused(_))
    ));
    info.identity = Some(ProcessIdentity {
        pid: 0,
        start_time: 1,
    });
    assert!(matches!(
        PreparedTarget::prepare(&info),
        Err(KillError::IdentityChanged)
    ));
}

#[test]
fn detects_exit_during_confirmation() {
    let mut child = OwnedChild::spawn("normal");
    let info = child.info();
    let Some(mut target) = prepare_or_explicit_macos_skip(&info) else {
        return;
    };
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert_eq!(
        target.terminate(true, Duration::from_secs(2)).unwrap(),
        KillOutcome::AlreadyExited
    );
}

#[test]
fn detects_exit_before_preparation() {
    let mut child = OwnedChild::spawn("normal");
    let info = child.info();
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert!(matches!(
        PreparedTarget::prepare(&info),
        Err(KillError::AlreadyExited)
    ));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn normal_termination_waits_for_exit() {
    let mut child = OwnedChild::spawn("normal");
    let mut target = PreparedTarget::prepare(&child.info()).unwrap();
    assert_eq!(
        target.terminate(false, Duration::from_secs(3)).unwrap(),
        KillOutcome::Exited
    );
    let status = child.0.wait().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGTERM));
    }
    #[cfg(windows)]
    assert_eq!(status.code(), Some(1));
    assert_eq!(
        target.terminate(false, Duration::ZERO).unwrap(),
        KillOutcome::AlreadyExited
    );
}

#[cfg(target_os = "linux")]
#[test]
fn timeout_does_not_escalate_and_force_kills_same_target() {
    let mut child = OwnedChild::spawn("ignore-term");
    let mut target = PreparedTarget::prepare(&child.info()).unwrap();
    assert!(matches!(
        target.terminate(false, Duration::from_millis(30)),
        Err(KillError::Timeout)
    ));
    assert!(child.0.try_wait().unwrap().is_none());
    assert_eq!(
        target.terminate(true, Duration::from_secs(3)).unwrap(),
        KillOutcome::Exited
    );
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGKILL));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_stable_task_handle_requires_force() {
    let mut child = OwnedChild::spawn("normal");
    let Some(mut target) = prepare_or_explicit_macos_skip(&child.info()) else {
        return;
    };
    assert!(matches!(
        target.terminate(false, Duration::from_secs(3)),
        Err(KillError::Unsupported(_))
    ));
    assert!(child.0.try_wait().unwrap().is_none());
    assert_eq!(
        target.terminate(true, Duration::from_secs(3)).unwrap(),
        KillOutcome::Exited
    );
    child.0.wait().unwrap();
}
