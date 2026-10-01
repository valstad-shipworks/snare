#![cfg(target_os = "linux")]

//! Under a `SimHost`, UDP (host-modelled, with NIC/timestamping smarts) and TCP (fabric-modelled)
//! now serve one simulation together, and the host's datagram path gained blocking cross-thread
//! receive, `connect`, broadcast, multicast and per-address (multi-IP) binding. Semantics follow
//! udp(7) and connect(2)/sendto(2)/recvfrom(2); SO_BROADCAST and IP_ADD_MEMBERSHIP are from
//! man 7 ip / man 7 socket.

use std::net::UdpSocket;
use std::time::Duration;

use snare::{HostProfile, Line, Sim, TesterAction, connect_tester, run_testers};

fn host_sim() -> Sim {
    Sim::builder().host(HostProfile::new().build()).build()
}

#[test]
fn tcp_control_and_udp_data_together() {
    host_sim().run(|| {
        let server = connect_tester::<Line>("127.0.0.9:9800")
            .then_action(|msg, _| TesterAction::Send(Line(format!("ok:{}", msg.0))))
            .until_after(Duration::from_millis(300));

        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let client = std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            let u = UdpSocket::bind("127.0.0.1:0").unwrap();
            u.send_to(b"telemetry", peer_addr).unwrap();
            let mut tcp = std::net::TcpStream::connect("127.0.0.9:9800").unwrap();
            tcp.write_all(b"go\n").unwrap();
            let mut line = String::new();
            BufReader::new(tcp).read_line(&mut line).unwrap();
            line
        });

        let mut buf = [0u8; 32];
        let (n, _) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"telemetry");

        run_testers!(server);
        assert_eq!(client.join().unwrap(), "ok:go\n");
    });
}

#[test]
fn blocking_recv_wakes_cross_thread() {
    host_sim().run(|| {
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b_addr = b.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let a = UdpSocket::bind("127.0.0.1:0").unwrap();
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
fn connect_then_send_and_peer_filter() {
    host_sim().run(|| {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let other = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(server_addr).unwrap();
        client.send(b"hi").unwrap();

        let mut buf = [0u8; 16];
        let (n, from) = server.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hi");
        assert_eq!(from, client.local_addr().unwrap());

        other.send_to(b"stranger", client.local_addr().unwrap()).unwrap();
        server.send_to(b"reply", client.local_addr().unwrap()).unwrap();
        let (n, from) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"reply");
        assert_eq!(from, server_addr);
    });
}

#[test]
fn broadcast_and_multi_ip() {
    host_sim().run(|| {
        let port = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let a = UdpSocket::bind(("0.0.0.0", port)).unwrap();
        let b = UdpSocket::bind(("127.0.0.2", port)).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(sender.send_to(b"x", ("255.255.255.255", port)).is_err());
        sender.set_broadcast(true).unwrap();
        sender.send_to(b"all", ("255.255.255.255", port)).unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = a.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"all");
        let (n, _) = b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"all");
    });
}

#[test]
fn multicast_group() {
    host_sim().run(|| {
        let group: std::net::Ipv4Addr = "239.9.9.9".parse().unwrap();
        let port = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
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
fn a_udp_tester_talks_to_simhost_sockets() {
    // A SimHost models UDP itself; a tester's endpoint still reaches its sockets, both ways.
    host_sim().run(|| {
        let device = snare::udp_tester::<snare::Bytes>("127.0.0.9:3956")
            .then_action(|msg, _| {
                let mut reply = b"re:".to_vec();
                reply.extend(msg.0);
                TesterAction::Send(snare::Bytes(reply))
            })
            .until_after(Duration::from_millis(100));

        let client = std::thread::spawn(|| {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.send_to(b"ping", "127.0.0.9:3956").unwrap();
            let mut buf = [0u8; 16];
            let (n, from) = sock.recv_from(&mut buf).unwrap();
            (buf[..n].to_vec(), from)
        });

        run_testers!(device);
        let (reply, from) = client.join().unwrap();
        assert_eq!(reply, b"re:ping");
        assert_eq!(from, "127.0.0.9:3956".parse().unwrap());
    });
}

#[test]
fn simhost_sockets_honour_link_latency() {
    host_sim().run(|| {
        let rx = UdpSocket::bind("127.0.0.9:9900").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        snare::set_udp_policy("127.0.0.9:9900", |p| p.latency = Duration::from_millis(30));
        tx.send_to(b"x", "127.0.0.9:9900").unwrap();
        rx.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 4];
        assert!(rx.recv_from(&mut buf).is_err(), "still in flight");
        rx.set_nonblocking(false).unwrap();
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"x");
    });
}
