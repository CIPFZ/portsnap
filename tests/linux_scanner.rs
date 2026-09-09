#![cfg(target_os = "linux")]

use portsnap::{
    model::{AddressFamily, Protocol, ScanOptions, TcpState},
    scanner::Scanner,
};
use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    process::{Child, Command, Stdio},
};

#[test]
fn real_ipv4_tcp_udp_and_established_client_are_visible() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect(address).unwrap();
    let (_accepted, _) = listener.accept().unwrap();
    let client_address = client.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_address = udp.local_addr().unwrap();
    udp.connect(address).unwrap();

    let options = ScanOptions {
        ports: vec![address.port(), client_address.port(), udp_address.port()],
        listening_only: false,
        ..Default::default()
    };
    let report = Scanner::scan(&options).unwrap();
    let owned = |socket: &&portsnap::model::SocketInfo| {
        socket
            .owners
            .iter()
            .any(|owner| owner.pid == std::process::id() && owner.identity.is_some())
    };
    let listening = report
        .sockets
        .iter()
        .find(|socket| {
            socket.local_addr == address.ip()
                && socket.local_port == address.port()
                && socket.protocol == Protocol::Tcp
                && socket.state == Some(TcpState::Listen)
        })
        .unwrap();
    assert!(owned(&listening));
    assert_eq!(listening.remote_addr, None);
    let established = report
        .sockets
        .iter()
        .find(|socket| {
            socket.local_port == client_address.port()
                && socket.protocol == Protocol::Tcp
                && socket.state == Some(TcpState::Established)
        })
        .unwrap();
    assert_eq!(established.remote_addr, Some(address.ip()));
    assert_eq!(established.remote_port, Some(address.port()));
    assert!(owned(&established));
    let datagram = report
        .sockets
        .iter()
        .find(|socket| socket.local_port == udp_address.port() && socket.protocol == Protocol::Udp)
        .unwrap();
    assert_eq!(datagram.remote_port, Some(address.port()));
    assert!(owned(&datagram));

    let listeners = Scanner::scan(&ScanOptions {
        listening_only: true,
        ..options
    })
    .unwrap();
    assert!(!listeners
        .sockets
        .iter()
        .any(|socket| socket.protocol == Protocol::Tcp && socket.state != Some(TcpState::Listen)));
    assert!(listeners
        .sockets
        .iter()
        .any(|socket| socket.protocol == Protocol::Udp && socket.local_port == udp_address.port()));
}

#[test]
fn real_ipv6_tcp_and_udp_keep_the_bound_address() {
    let listener = match TcpListener::bind("[::1]:0") {
        Ok(listener) => listener,
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EAFNOSUPPORT | libc::EADDRNOTAVAIL)
            ) =>
        {
            return
        }
        Err(error) => panic!("IPv6 bind failed: {error}"),
    };
    let udp = UdpSocket::bind("[::1]:0").unwrap();
    let report = Scanner::scan(&ScanOptions {
        ports: vec![
            listener.local_addr().unwrap().port(),
            udp.local_addr().unwrap().port(),
        ],
        listening_only: true,
        ..Default::default()
    })
    .unwrap();
    for (protocol, address) in [
        (Protocol::Tcp, listener.local_addr().unwrap()),
        (Protocol::Udp, udp.local_addr().unwrap()),
    ] {
        let socket = report
            .sockets
            .iter()
            .find(|socket| {
                socket.protocol == protocol
                    && socket.local_port == address.port()
                    && socket.local_addr == address.ip()
            })
            .unwrap();
        assert!(socket
            .owners
            .iter()
            .any(|owner| owner.pid == std::process::id()));
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn inherited_socket_reports_both_process_owners() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let fd = listener.as_raw_fd();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "inherited_socket_helper", "--nocapture"])
        .env("PORTSNAP_TEST_FD", fd.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Only change the child's descriptor flags; the parent's listener remains CLOEXEC.
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags == -1 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = ChildGuard(command.spawn().unwrap());
    let child_pid = child.0.id();
    let mut output = BufReader::new(child.0.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(
            output.read_line(&mut line).unwrap(),
            0,
            "helper exited before becoming ready"
        );
        if line.contains("PORTSNAP_READY") {
            break;
        }
    }
    let report = Scanner::scan(&ScanOptions {
        ports: vec![port],
        listening_only: true,
        ..Default::default()
    })
    .unwrap();
    let socket = report
        .sockets
        .iter()
        .find(|socket| socket.protocol == Protocol::Tcp && socket.local_port == port)
        .unwrap();
    let owners = socket
        .owners
        .iter()
        .map(|owner| owner.pid)
        .collect::<Vec<_>>();
    assert!(
        owners.contains(&std::process::id()),
        "missing parent: {owners:?}"
    );
    assert!(owners.contains(&child_pid), "missing child: {owners:?}");
    child.0.stdin.take().unwrap().write_all(b"exit\n").unwrap();
    assert!(child.0.wait().unwrap().success());
}

#[test]
fn inherited_socket_helper() {
    let Ok(fd) = std::env::var("PORTSNAP_TEST_FD") else {
        return;
    };
    // The parent passes an exclusively inherited descriptor for this helper process.
    let listener = unsafe { TcpListener::from_raw_fd(fd.parse().unwrap()) };
    assert_ne!(listener.local_addr().unwrap().port(), 0);
    println!("PORTSNAP_READY");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
}

#[test]
fn protocol_and_family_filters_scope_real_bound_sockets() {
    let tcp4 = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp4.local_addr().unwrap().port();
    let udp4 = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port)).unwrap();
    for protocol in [Protocol::Tcp, Protocol::Udp] {
        let report = Scanner::scan(&ScanOptions {
            ports: vec![port],
            protocol: Some(protocol),
            family: Some(AddressFamily::Ipv4),
            ..Default::default()
        })
        .unwrap();
        assert!(!report.sockets.is_empty());
        assert!(report
            .sockets
            .iter()
            .all(|socket| socket.protocol == protocol
                && socket.local_addr.is_ipv4()
                && socket.local_port == port));
        assert!(report.sockets.iter().any(|socket| socket
            .owners
            .iter()
            .any(|owner| owner.pid == std::process::id())));
    }
    drop(udp4);
    let tcp6 = match TcpListener::bind("[::1]:0") {
        Ok(listener) => listener,
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EAFNOSUPPORT | libc::EADDRNOTAVAIL)
            ) =>
        {
            return
        }
        Err(error) => panic!("IPv6 bind failed: {error}"),
    };
    let udp6 = UdpSocket::bind(tcp6.local_addr().unwrap()).unwrap();
    for protocol in [Protocol::Tcp, Protocol::Udp] {
        let report = Scanner::scan(&ScanOptions {
            ports: vec![tcp6.local_addr().unwrap().port()],
            protocol: Some(protocol),
            family: Some(AddressFamily::Ipv6),
            ..Default::default()
        })
        .unwrap();
        assert!(!report.sockets.is_empty());
        assert!(report
            .sockets
            .iter()
            .all(|socket| socket.protocol == protocol && socket.local_addr.is_ipv6()));
    }
    drop(udp6);
}
