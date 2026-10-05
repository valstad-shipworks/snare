//! The base `Sim` (no `SimHost`) now services UDP from process memory on every platform, the way
//! it already did TCP. These drive ordinary `std::net::UdpSocket`, whose socket/bind/sendto/
//! recvfrom calls land in the fabric, or on Windows in the Winsock backend. Datagram semantics
//! follow udp(7) and socket(2)/bind(2)/connect(2)/sendto(2)/recvfrom(2), and Winsock's
//! ([Microsoft Learn: recvfrom](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom)).

use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use snare::Sim;

#[test]
fn sendto_and_recvfrom() {
    Sim::new().run(|| {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b_addr = b.local_addr().unwrap();

        a.send_to(b"ping", b_addr).unwrap();

        let mut buf = [0u8; 16];
        let (n, from) = b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from, a.local_addr().unwrap());
    });
}

#[cfg(unix)]
#[test]
fn delayed_duplicate_datagrams_own_the_sent_payload() {
    for deterministic in [false, true] {
        let builder = Sim::builder();
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        sim.run(|| {
            let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
            let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
            let destination = receiver.local_addr().unwrap();
            snare::set_udp_policy(destination, |p| {
                p.latency = Duration::from_millis(5);
                p.duplicate_rate = 1.0;
            });
            receiver
                .set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            for connected in [false, true] {
                let mut payload: Vec<_> = (0..512).map(|i| (i % 251) as u8).collect();
                let expected = payload.clone();
                let sent = if connected {
                    sender.connect(destination).unwrap();
                    sender.send(&payload).unwrap()
                } else {
                    sender.send_to(&payload, destination).unwrap()
                };
                assert_eq!(sent, payload.len());
                payload.fill(255);
                let mut buf = [0; 1024];
                receiver.set_nonblocking(true).unwrap();
                assert_eq!(
                    receiver.peek_from(&mut buf).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                receiver.set_nonblocking(false).unwrap();
                std::thread::sleep(Duration::from_millis(5));
                for _ in 0..2 {
                    let (n, source) = receiver.peek_from(&mut buf).unwrap();
                    assert_eq!(&buf[..n], expected);
                    assert_eq!(source, sender.local_addr().unwrap());
                }
                for _ in 0..2 {
                    let (n, source) = receiver.recv_from(&mut buf).unwrap();
                    assert_eq!(&buf[..n], expected);
                    assert_eq!(source, sender.local_addr().unwrap());
                }
                receiver.set_nonblocking(true).unwrap();
                assert_eq!(
                    receiver.recv_from(&mut buf).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                receiver.set_nonblocking(false).unwrap();
            }
        });
    }
}

#[test]
fn blocking_recv_wakes_on_cross_thread_send() {
    Sim::new().run(|| {
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b_addr = b.local_addr().unwrap();

        let sender = std::thread::spawn(move || {
            let a = UdpSocket::bind("127.0.0.1:0").unwrap();
            // A real pause so the receiver is parked in recvfrom before the datagram arrives,
            // exercising the readiness wakeup rather than finding the queue already non-empty.
            std::thread::sleep(Duration::from_millis(20));
            a.send_to(b"wake", b_addr).unwrap();
        });

        let mut buf = [0u8; 16];
        let (n, _) = b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"wake");
        sender.join().unwrap();
    });
}

#[test]
fn connect_fixes_peer_for_send_and_filters_recv() {
    Sim::new().run(|| {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let other = UdpSocket::bind("127.0.0.1:0").unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(server_addr).unwrap();
        // A plain send with no destination now works because connect fixed the peer.
        client.send(b"hello").unwrap();

        let mut buf = [0u8; 16];
        let (n, from) = server.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(from, client.local_addr().unwrap());

        // The connected client only accepts datagrams from its peer: one from `other` is ignored
        // while the server's reply is delivered.
        other
            .send_to(b"stranger", client.local_addr().unwrap())
            .unwrap();
        server
            .send_to(b"reply", client.local_addr().unwrap())
            .unwrap();
        let (n, from) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"reply");
        assert_eq!(from, server_addr);
    });
}

#[test]
fn several_addresses_on_one_port() {
    // snare 1.x's add_ip_addr: distinct IPs sharing a port are distinct endpoints.
    Sim::new().run(|| {
        let port = {
            let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        let one = UdpSocket::bind(("127.0.0.1", port)).unwrap();
        let two = UdpSocket::bind(("127.0.0.2", port)).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();

        sender.send_to(b"to-one", ("127.0.0.1", port)).unwrap();
        sender.send_to(b"to-two", ("127.0.0.2", port)).unwrap();

        let mut buf = [0u8; 16];
        let (n, _) = one.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"to-one");
        let (n, _) = two.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"to-two");
    });
}

#[test]
fn broadcast_reaches_every_bound_socket() {
    Sim::new().run(|| {
        let port = {
            let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        let one = UdpSocket::bind(("0.0.0.0", port)).unwrap();
        let two = UdpSocket::bind(("127.0.0.2", port)).unwrap();

        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        // Broadcasting without SO_BROADCAST is refused (man 7 socket).
        assert!(sender.send_to(b"x", ("255.255.255.255", port)).is_err());
        sender.set_broadcast(true).unwrap();
        sender.send_to(b"all", ("255.255.255.255", port)).unwrap();

        let mut buf = [0u8; 16];
        let (n, _) = one.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"all");
        let (n, _) = two.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"all");
    });
}

#[test]
fn multicast_group_membership() {
    Sim::new().run(|| {
        let group: std::net::Ipv4Addr = "239.1.2.3".parse().unwrap();
        let port = {
            let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        let member = UdpSocket::bind(("0.0.0.0", port)).unwrap();
        member
            .join_multicast_v4(&group, &std::net::Ipv4Addr::UNSPECIFIED)
            .unwrap();

        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"group", (group, port)).unwrap();

        let mut buf = [0u8; 16];
        let (n, _) = member.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"group");
    });
}

#[test]
fn nonblocking_recv_is_eagain_when_empty() {
    Sim::new().run(|| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 16];
        let err = s.recv_from(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    });
}

#[cfg(unix)]
#[test]
fn receive_timeout_is_ignored_by_nonblocking_calls() {
    use std::os::fd::AsRawFd;
    use std::time::Instant;

    for deterministic in [false, true] {
        let builder = Sim::builder();
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        sim.run(|| {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let timeout = Duration::from_millis(20);
            socket.set_read_timeout(Some(timeout)).unwrap();
            socket.set_nonblocking(true).unwrap();
            let mut buffer = [0; 8];
            let start = Instant::now();
            assert_eq!(
                socket.recv(&mut buffer).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert!(start.elapsed() < timeout);
            socket.set_nonblocking(false).unwrap();
            let start = Instant::now();
            let result = unsafe {
                libc::recv(
                    socket.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            assert_eq!(result, -1);
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert!(start.elapsed() < timeout);
            let start = Instant::now();
            assert_eq!(
                socket.recv(&mut buffer).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert!(start.elapsed() >= timeout);
        });
    }
}

#[test]
fn tcp_and_udp_coexist_in_one_sim() {
    // A plain Sim serves both planes at once: a TCP tester and UDP datagrams in the same run.
    use snare::{Line, TesterAction, connect_tester, run_testers};
    let sim = Sim::new();
    sim.run(|| {
        let server = connect_tester::<Line>("127.0.0.5:9700")
            .then_action(|msg, _| TesterAction::Send(Line(format!("echo:{}", msg.0))))
            .until_after(Duration::from_millis(300));

        let (tx, rx) = mpsc::channel();
        let udp_peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_addr = udp_peer.local_addr().unwrap();
        tx.send(udp_addr).unwrap();

        let client = std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            let udp_addr = rx.recv().unwrap();
            let u = UdpSocket::bind("127.0.0.1:0").unwrap();
            u.send_to(b"datagram", udp_addr).unwrap();

            let mut tcp = std::net::TcpStream::connect("127.0.0.5:9700").unwrap();
            tcp.write_all(b"hi\n").unwrap();
            let mut line = String::new();
            BufReader::new(tcp).read_line(&mut line).unwrap();
            line
        });

        let mut buf = [0u8; 16];
        let (n, _) = udp_peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"datagram");

        run_testers!(server);
        assert_eq!(client.join().unwrap(), "echo:hi\n");
    });
    let _ = Arc::new(());
}

/// Peeks twice, receives, then peeks at what follows, through both `recvfrom` (`peek_from`) and
/// `recvmsg` with `MSG_PEEK` (on Windows a third `peek_from`).
fn peek_sequence() -> Vec<Vec<u8>> {
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    a.send_to(b"one", b.local_addr().unwrap()).unwrap();
    a.send_to(b"two", b.local_addr().unwrap()).unwrap();
    let mut seen = Vec::new();
    let mut buf = [0u8; 16];
    for _ in 0..2 {
        let (n, _) = b.peek_from(&mut buf).unwrap();
        seen.push(buf[..n].to_vec());
    }
    #[cfg(unix)]
    {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        let n = unsafe {
            libc::recvmsg(
                std::os::fd::AsRawFd::as_raw_fd(&b),
                &mut msg,
                libc::MSG_PEEK,
            )
        };
        assert!(n >= 0, "recvmsg MSG_PEEK failed");
        seen.push(buf[..n as usize].to_vec());
    }
    #[cfg(windows)]
    {
        let (n, _) = b.peek_from(&mut buf).unwrap();
        seen.push(buf[..n].to_vec());
    }
    let (n, _) = b.recv_from(&mut buf).unwrap();
    seen.push(buf[..n].to_vec());
    let (n, _) = b.peek_from(&mut buf).unwrap();
    seen.push(buf[..n].to_vec());
    let (n, _) = b.recv_from(&mut buf).unwrap();
    seen.push(buf[..n].to_vec());
    seen
}

#[test]
fn msg_peek_leaves_the_datagram_queued_os_truth() {
    let real = snare::real(peek_sequence);
    let simmed = Sim::new().run(peek_sequence);
    assert_eq!(simmed, real);
    assert_eq!(
        simmed,
        [&b"one"[..], b"one", b"one", b"one", b"two", b"two"]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn msg_peek_leaves_the_datagram_queued_on_a_simhost() {
    let host = snare::HostProfile::new().build();
    let simmed = Sim::builder().host(host).build().run(peek_sequence);
    assert_eq!(
        simmed,
        [&b"one"[..], b"one", b"one", b"one", b"two", b"two"]
    );
}
