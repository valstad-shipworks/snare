#![cfg(unix)]

//! The base `Sim` (no `SimHost`) now services UDP from process memory on every platform, the way
//! it already did TCP. These drive ordinary `std::net::UdpSocket`, whose socket/bind/sendto/
//! recvfrom calls land in the fabric. Datagram semantics follow udp(7) and socket(2)/bind(2)/
//! connect(2)/sendto(2)/recvfrom(2).

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
        other.send_to(b"stranger", client.local_addr().unwrap()).unwrap();
        server.send_to(b"reply", client.local_addr().unwrap()).unwrap();
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
