use serde_json::Value;
use std::{
    net::{TcpListener, UdpSocket},
    process::Command,
};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_portsnap"))
}

#[test]
fn json_is_one_versioned_report_with_all_owners_and_typed_states() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let ports = [
        tcp.local_addr().unwrap().port(),
        udp.local_addr().unwrap().port(),
    ];
    let output = binary()
        .args([ports[0].to_string(), ports[1].to_string(), "--json".into()])
        .output()
        .unwrap();
    assert!(
        matches!(output.status.code(), Some(0 | 3)),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert!(report["complete"].is_boolean());
    assert!(report["warnings"].is_array());
    for warning in report["warnings"].as_array().unwrap() {
        assert!(warning["code"].is_string());
    }
    for row in report["sockets"].as_array().unwrap() {
        for owner in row["owners"].as_array().unwrap() {
            assert!(owner.get("details").is_none());
        }
    }
    for (port, protocol, state) in [(ports[0], "TCP", Some("LISTEN")), (ports[1], "UDP", None)] {
        let row = report["sockets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| {
                row["local_port"] == port
                    && row["protocol"] == protocol
                    && row["local_addr"] == "127.0.0.1"
            })
            .expect("owned socket missing");
        assert_eq!(row["local_addr"], "127.0.0.1");
        assert_eq!(row["state"].as_str(), state);
        assert!(row["owners"]
            .as_array()
            .unwrap()
            .iter()
            .any(|owner| owner["pid"] == std::process::id()));
    }
}

#[test]
fn invalid_json_kill_combination_fails_before_emitting_report() {
    let output = binary()
        .args(["8080", "--json", "--kill"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn conflicting_filters_fail_before_emitting_a_report() {
    for flags in [["--tcp", "--udp"], ["-4", "-6"], ["--ipv4", "--ipv6"]] {
        let output = binary()
            .args(["8080", "--json"])
            .args(flags)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn protocol_and_family_filters_constrain_json_results() {
    let tcp4 = TcpListener::bind("127.0.0.1:0").unwrap();
    let udp4 = UdpSocket::bind("127.0.0.1:0").unwrap();
    // IPv6 may be disabled on the host; IPv4 coverage still runs in that case.
    let tcp6 = TcpListener::bind("[::1]:0").ok();
    let udp6 = UdpSocket::bind("[::1]:0").ok();
    let mut fixtures = vec![
        (tcp4.local_addr().unwrap(), "TCP", "--tcp", "-4"),
        (udp4.local_addr().unwrap(), "UDP", "--udp", "-4"),
    ];
    if let Some(socket) = &tcp6 {
        fixtures.push((socket.local_addr().unwrap(), "TCP", "--tcp", "-6"));
    }
    if let Some(socket) = &udp6 {
        fixtures.push((socket.local_addr().unwrap(), "UDP", "--udp", "-6"));
    }
    let ports: Vec<_> = fixtures
        .iter()
        .map(|(addr, ..)| addr.port().to_string())
        .collect();
    for (addr, protocol, flag, family) in &fixtures {
        let output = binary()
            .args(&ports)
            .args(["--json", flag, family])
            .output()
            .unwrap();
        assert!(
            matches!(output.status.code(), Some(0 | 3)),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let rows = report["sockets"].as_array().unwrap();
        assert!(rows.iter().all(|row| {
            row["protocol"] == *protocol
                && row["local_addr"]
                    .as_str()
                    .unwrap()
                    .parse::<std::net::IpAddr>()
                    .unwrap()
                    .is_ipv4()
                    == addr.is_ipv4()
        }));
        assert!(
            rows.iter().any(|row| {
                row["local_port"] == addr.port()
                    && row["local_addr"] == addr.ip().to_string()
                    && row["owners"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|owner| owner["pid"] == std::process::id())
            }),
            "owned {protocol} endpoint {addr} missing: {report}"
        );
    }
}

#[test]
fn version_is_available_without_query_arguments() {
    let output = binary().arg("--version").output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains(env!("CARGO_PKG_VERSION")));
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
mod interactive {
    use super::*;
    use std::{
        fs,
        io::{Read, Write},
        path::PathBuf,
        process::{Child, Output, Stdio},
        sync::{
            atomic::{AtomicU64, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct OwnedListener {
        child: Child,
        path: PathBuf,
        port: u16,
    }
    impl OwnedListener {
        fn new() -> Self {
            Self::spawn("TCP", 0).expect("TCP listener helper failed to bind")
        }

        fn spawn(protocol: &str, port: u16) -> Option<Self> {
            let directory = loop {
                let path = std::env::temp_dir().join(format!(
                    "portsnap-cli-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                let builder = fs::DirBuilder::new();
                #[cfg(unix)]
                let builder = {
                    use std::os::unix::fs::DirBuilderExt;
                    let mut builder = builder;
                    builder.mode(0o700);
                    builder
                };
                match builder.create(&path) {
                    Ok(()) => break path,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("cannot reserve test directory: {error}"),
                }
            };
            let path = directory.join("ready");
            let child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "interactive::listener_helper",
                    "--ignored",
                    "--nocapture",
                ])
                .env("PORTSNAP_CLI_READY", &path)
                .env("PORTSNAP_CLI_PROTOCOL", protocol)
                .env("PORTSNAP_CLI_PORT", port.to_string())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut result = Self {
                child,
                path,
                port: 0,
            };
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Ok(text) = fs::read_to_string(&result.path) {
                    let fields: Vec<_> = text.split_whitespace().collect();
                    if fields.len() == 2 {
                        assert_eq!(
                            fields[0].parse::<u32>().unwrap(),
                            result.child.id(),
                            "readiness identity mismatch"
                        );
                        result.port = fields[1].parse().unwrap();
                        return Some(result);
                    }
                }
                assert!(Instant::now() < deadline, "listener helper failed to start");
                // An occupied UDP port is expected while finding a shared-number
                // TCP/UDP fixture. Dropping result cleans up this owned child.
                if result.child.try_wait().unwrap().is_some() {
                    return None;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }

        fn run(&mut self, answer: &[u8]) -> Output {
            self.run_with(answer, &[])
        }

        fn run_with(&mut self, answer: &[u8], options: &[&str]) -> Output {
            assert!(matches!(answer, b"y\n" | b"n\n" | b""));
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "owned listener must be alive before querying"
            );
            let child = binary()
                .args([
                    self.port.to_string(),
                    "--kill".into(),
                    "--force".into(),
                    "--timeout".into(),
                    "1".into(),
                ])
                .args(options)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut cli = CliGuard(child);
            let mut input = cli.0.stdin.take();
            let mut stdout = cli.0.stdout.take().unwrap();
            let stdout_reader = thread::spawn(move || {
                let mut bytes = Vec::new();
                stdout.read_to_end(&mut bytes).map(|_| bytes)
            });
            let mut stderr = cli.0.stderr.take().unwrap();
            let (sender, receiver) = mpsc::channel();
            let stderr_reader = thread::spawn(move || loop {
                let mut chunk = [0_u8; 4096];
                let read = stderr.read(&mut chunk);
                match read {
                    Ok(0) => break,
                    Ok(size) => {
                        if sender.send(Ok(chunk[..size].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        break;
                    }
                }
            });
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut diagnostic = Vec::new();
            let mut pending_line = Vec::new();
            let mut saw_owned_prompt = false;
            let mut stderr_closed = false;
            let status = loop {
                assert!(
                    Instant::now() < deadline,
                    "CLI timed out: {}",
                    String::from_utf8_lossy(&diagnostic)
                );
                match receiver.recv_timeout(Duration::from_millis(25)) {
                    Ok(chunk) => {
                        let chunk = chunk.unwrap();
                        diagnostic.extend_from_slice(&chunk);
                        pending_line.extend_from_slice(&chunk);
                        if let Some(newline) = pending_line.iter().rposition(|byte| *byte == b'\n')
                        {
                            pending_line.drain(..=newline);
                        }
                        if let Some(pid) = prompt_pid(&pending_line) {
                            let response = if pid == self.child.id() {
                                assert!(
                                    self.child.try_wait().unwrap().is_none(),
                                    "owned child exited before confirmation"
                                );
                                saw_owned_prompt = true;
                                answer
                            } else {
                                b"n\n"
                            };
                            if response.is_empty() {
                                // EOF applies only to the intended child's prompt.
                                drop(input.take());
                            } else {
                                input
                                    .as_mut()
                                    .expect("prompt after stdin closed")
                                    .write_all(response)
                                    .unwrap();
                            }
                            pending_line.clear();
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => stderr_closed = true,
                }
                if stderr_closed {
                    if let Some(status) = cli.0.try_wait().unwrap() {
                        break status;
                    }
                    // A disconnected receiver returns immediately; avoid spinning
                    // while waiting for the owned CLI child to finish exiting.
                    thread::sleep(Duration::from_millis(5));
                }
            };
            drop(input);
            stderr_reader.join().unwrap();
            let stdout = stdout_reader.join().unwrap().unwrap();
            assert!(
                saw_owned_prompt,
                "owned process never prompted: {}",
                String::from_utf8_lossy(&diagnostic)
            );
            Output {
                status,
                stdout,
                stderr: diagnostic,
            }
        }
    }

    /// Parse the whole prompt, including its quoted Debug-formatted name. A
    /// process name containing a fake `(PID ...)? [y/N]: ` must not authorize it.
    fn prompt_pid(line: &[u8]) -> Option<u32> {
        let quoted = line
            .strip_prefix(b"Force terminate process ")
            .or_else(|| line.strip_prefix(b"Terminate process "))?;
        if quoted.first() != Some(&b'"') {
            return None;
        }
        let mut escaped = false;
        for (index, byte) in quoted.iter().enumerate().skip(1) {
            if escaped {
                escaped = false;
                continue;
            }
            match byte {
                b'\\' => escaped = true,
                b'"' => {
                    let pid = quoted[index + 1..]
                        .strip_prefix(b" (PID ")?
                        .strip_suffix(b")? [y/N]: ")?;
                    if pid.is_empty() || !pid.iter().all(u8::is_ascii_digit) {
                        return None;
                    }
                    return std::str::from_utf8(pid).ok()?.parse().ok();
                }
                _ => {}
            }
        }
        None
    }

    struct CliGuard(Child);
    impl Drop for CliGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    impl Drop for OwnedListener {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = fs::remove_file(&self.path);
            let _ = fs::remove_dir(self.path.parent().unwrap());
        }
    }

    fn publish_and_hold<T>(socket: T, port: u16) {
        let path = std::env::var_os("PORTSNAP_CLI_READY").expect("only run through OwnedListener");
        fs::write(path, format!("{} {port}", std::process::id())).unwrap();
        // The parent owns cleanup. Never release this port on a timing deadline.
        loop {
            thread::park_timeout(Duration::from_secs(60));
            std::hint::black_box(&socket);
        }
    }

    #[test]
    #[ignore = "subprocess fixture; launched only by OwnedListener"]
    fn listener_helper() {
        let port: u16 = std::env::var("PORTSNAP_CLI_PORT").unwrap().parse().unwrap();
        match std::env::var("PORTSNAP_CLI_PROTOCOL").unwrap().as_str() {
            "TCP" => {
                if let Ok(socket) = TcpListener::bind(("127.0.0.1", port)) {
                    let port = socket.local_addr().unwrap().port();
                    publish_and_hold(socket, port);
                }
            }
            "UDP" => {
                if let Ok(socket) = UdpSocket::bind(("127.0.0.1", port)) {
                    let port = socket.local_addr().unwrap().port();
                    publish_and_hold(socket, port);
                }
            }
            _ => panic!("unknown fixture protocol"),
        }
    }

    #[test]
    fn prompt_parser_ignores_fake_pids_in_names_and_incomplete_prompts() {
        assert_eq!(
            prompt_pid(br#"Force terminate process "worker" (PID 123)? [y/N]: "#),
            Some(123)
        );
        assert_eq!(
            prompt_pid(br#"Force terminate process "evil (PID 123)? [y/N]: "#),
            None
        );
        assert_eq!(
            prompt_pid(
                br#"Force terminate process "evil \" (PID 123)? [y/N]: " (PID 456)? [y/N]: "#
            ),
            Some(456)
        );
        assert_eq!(
            prompt_pid(br#"Force terminate process "worker" (PID 123)? [y/N]:"#),
            None
        );
    }

    #[test]
    fn declining_never_terminates_the_child() {
        let mut target = OwnedListener::new();
        let output = target.run(b"n\n");
        assert!(
            matches!(output.status.code(), Some(0 | 3)),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(target.child.try_wait().unwrap().is_none());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Skipped PID"));
    }

    #[test]
    fn eof_returns_failure_without_terminating_the_child() {
        let mut target = OwnedListener::new();
        let output = target.run(b"");
        assert_eq!(output.status.code(), Some(1));
        assert!(target.child.try_wait().unwrap().is_none());
        assert!(String::from_utf8_lossy(&output.stderr).contains("confirmation input ended"));
    }

    #[test]
    fn confirmed_termination_verifies_exit_and_rescans_the_endpoint() {
        let mut target = OwnedListener::new();
        let output = target.run(b"y\n");
        // An unrelated protocol/interface may legitimately keep this numeric
        // port present after our process exits; it must be declined and survive.
        assert!(
            matches!(output.status.code(), Some(0 | 1 | 3)),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(target.child.try_wait().unwrap().is_some());
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(
            diagnostic.contains(&format!("PID {} exited (verified)", target.child.id())),
            "{diagnostic}"
        );
        assert!(
            diagnostic.contains("No matching endpoints")
                || diagnostic.contains("Matching endpoints remain"),
            "{diagnostic}"
        );
        assert!(TcpListener::bind(("127.0.0.1", target.port)).is_ok());
    }

    #[test]
    fn confirmation_declines_another_owner_at_the_same_numeric_port() {
        for _ in 0..10 {
            let mut target = OwnedListener::new();
            let Some(mut other) = OwnedListener::spawn("UDP", target.port) else {
                continue;
            };
            let output = target.run(b"y\n");
            assert_eq!(output.status.code(), Some(1));
            assert!(target.child.try_wait().unwrap().is_some());
            assert!(
                other.child.try_wait().unwrap().is_none(),
                "same-port UDP owner was terminated"
            );
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            assert!(
                diagnostic.contains(&format!("Skipped PID {}.", other.child.id())),
                "{diagnostic}"
            );
            assert!(
                diagnostic.contains("Matching endpoints remain"),
                "{diagnostic}"
            );
            return;
        }
        panic!("could not reserve TCP and UDP fixtures at the same port");
    }

    #[test]
    fn filtered_termination_preserves_same_port_udp_and_filters_the_final_scan() {
        for _ in 0..10 {
            let mut target = OwnedListener::new();
            let Some(mut other) = OwnedListener::spawn("UDP", target.port) else {
                continue;
            };
            let output = target.run_with(b"y\n", &["--tcp", "-4"]);
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            assert!(
                matches!(output.status.code(), Some(0 | 1 | 3)),
                "{diagnostic}"
            );
            assert!(target.child.try_wait().unwrap().is_some());
            assert!(
                other.child.try_wait().unwrap().is_none(),
                "excluded UDP owner was terminated"
            );
            assert!(
                !diagnostic.contains(&format!("(PID {})?", other.child.id())),
                "{diagnostic}"
            );
            assert!(
                diagnostic.contains(&format!("PID {} exited (verified)", target.child.id())),
                "{diagnostic}"
            );
            // Both the initial table and final result must respect the filter.
            assert!(!String::from_utf8_lossy(&output.stdout).contains("UDP"));
            assert!(TcpListener::bind(("127.0.0.1", target.port)).is_ok());
            return;
        }
        panic!("could not reserve TCP and UDP fixtures at the same port");
    }

    #[test]
    fn requested_details_describe_the_owned_child() {
        let target = OwnedListener::new();
        let output = binary()
            .arg(target.port.to_string())
            .args(["--tcp", "-4", "--details", "--json"])
            .output()
            .unwrap();
        assert!(
            matches!(output.status.code(), Some(0 | 3)),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let owner = report["sockets"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|row| row["owners"].as_array().unwrap())
            .find(|owner| owner["pid"] == target.child.id())
            .expect("owned child missing");
        let details = &owner["details"];
        assert_eq!(
            details["executable"],
            std::env::current_exe().unwrap().to_str().unwrap()
        );
        let args = details["command"].as_array().expect("command unavailable");
        assert_eq!(
            &args[1..],
            [
                "--exact",
                "interactive::listener_helper",
                "--ignored",
                "--nocapture"
            ]
        );
        assert_eq!(details["parent_pid"], std::process::id());
        assert!(!details["user"]["id"].as_str().unwrap().is_empty());
        let started = details["start_time_unix_ms"].as_u64().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        // Linux boot-time source has second precision; allow that rounding.
        assert!(u128::from(started) <= now && now - u128::from(started) < 60_000);
        assert_eq!(details["warnings"], serde_json::json!([]));
    }
}
