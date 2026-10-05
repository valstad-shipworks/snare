//! Interfaces, routing and the socket table of snare's in-process network.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use snare::net::{TcpListener, TcpStream, UdpSocket};
use snare::{
    DropAccounting, Errno, IpNet, NicPolicy, NicSpec, OsSemantics, Packetable, Route, SocketKind,
    SocketType, TesterAction, ThreadExt, TimerState, add_ip_addr, add_nic, add_route, advance_time,
    closed_sockets, connect_tester, inject_socket_drops, nic, nic_counters, nics, os_error_code,
    os_semantics, pause_time, register_test, remove_nic, route_lookup, routes, run_testers,
    set_default_route, set_link, set_nic, set_nic_counters, set_nic_policy, set_os_semantics,
    set_socket_device, set_sys_limits, socket_entry, socket_id, socket_table, sockets_bound,
};

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn code<T: std::fmt::Debug>(r: io::Result<T>) -> i32 {
    let e = r.expect_err("expected an error");
    os_error_code(&e).unwrap_or_else(|| panic!("no OS code on {e:?}"))
}

const ALL: [OsSemantics; 3] = [OsSemantics::Linux, OsSemantics::MacOs, OsSemantics::Windows];

/// `eth0` at 10.0.0.1/24 and `eth1` at 10.0.1.1/24.
fn two_nics() {
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/24"))).unwrap();
    add_nic(NicSpec::new("eth1").address(net("10.0.1.1/24"))).unwrap();
}

fn drain(s: &UdpSocket) -> usize {
    s.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 2048];
    let mut n = 0;
    while s.recv_from(&mut buf).is_ok() {
        n += 1;
    }
    n
}

#[test]
fn defaults() {
    register_test();
    let lo = nic(os_semantics().loopback_name()).expect("loopback");
    assert_eq!(lo.id.index(), 1);
    assert!(lo.spec.addresses.contains(&net("127.0.0.1/8")));
    assert!(lo.spec.addresses.contains(&net("::1/128")));
    let snare0 = nic("snare0").expect("snare0");
    assert_eq!(snare0.id.index(), 2);
    assert!(snare0.default_nic && !snare0.explicit);
    assert!(snare0.spec.addresses.is_empty());
    let all = routes();
    for dest in ["0.0.0.0/0", "::/0"] {
        assert!(
            all.iter()
                .any(|r| r.dest == net(dest) && r.nic == "snare0" && r.metric == 100),
            "{dest} in {all:?}"
        );
    }

    add_ip_addr(ip("10.1.1.1"));
    let snare0 = nic("snare0").unwrap();
    assert_eq!(snare0.spec.addresses, vec![net("10.1.1.1/32")]);
    let s = UdpSocket::bind("10.1.1.1:5000").unwrap();
    assert_eq!(
        socket_entry(socket_id(&s)).unwrap().nic.as_deref(),
        Some("snare0")
    );
    assert_eq!(nics().len(), 2);
}

#[test]
fn loopback_is_named_for_the_selected_os() {
    let names = ["lo", "lo0", "Loopback Pseudo-Interface 1"];
    for (os, name) in ALL.into_iter().zip(names) {
        register_test();
        set_os_semantics(os);
        assert_eq!(nic(name).unwrap().id.index(), 1, "{os}");
        for other in names.iter().filter(|o| **o != name) {
            assert!(nic(other).is_none(), "{os}: {other} must not resolve");
        }
    }
}

#[test]
fn add_nic_with_a_subnet() {
    register_test();
    let id = add_nic(NicSpec::new("eth0").address(net("192.168.10.5/24"))).unwrap();
    assert_eq!(id.index(), 3);
    let s = UdpSocket::bind("192.168.10.5:0").unwrap();
    let entry = socket_entry(socket_id(&s)).unwrap();
    assert_eq!(entry.nic.as_deref(), Some("eth0"));
    assert_eq!(entry.kind, SocketKind::Udp);
    assert!(UdpSocket::bind("192.168.10.6:0").is_err());
    let snap = nic("eth0").unwrap();
    assert!(snap.explicit && !snap.default_nic);
    assert_eq!(snap.sockets, vec![socket_id(&s)]);

    let dup = add_nic(NicSpec::new("eth0"));
    assert_eq!(dup.unwrap_err().kind(), ErrorKind::AlreadyExists);
    let taken = add_nic(NicSpec::new("eth9").address(net("192.168.10.5/24")));
    assert_eq!(taken.unwrap_err().kind(), ErrorKind::InvalidInput);
}

#[test]
fn add_nic_takes_over_a_legacy_address() {
    register_test();
    add_ip_addr(ip("10.7.0.1"));
    add_nic(NicSpec::new("eth0").address(net("10.7.0.1/16"))).unwrap();
    assert!(nic("snare0").unwrap().spec.addresses.is_empty());
    add_ip_addr(ip("10.7.0.1"));
    assert!(nic("snare0").unwrap().spec.addresses.is_empty());
}

#[test]
fn route_selection() {
    register_test();
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/8"))).unwrap();
    add_nic(NicSpec::new("eth1").address(net("10.1.0.1/16"))).unwrap();
    add_nic(NicSpec::new("eth2").address(net("192.168.5.1/24"))).unwrap();

    assert_eq!(
        route_lookup(None, ip("10.1.2.3")).unwrap(),
        ("eth1".into(), Some(ip("10.1.0.1")))
    );
    assert_eq!(route_lookup(None, ip("10.2.0.1")).unwrap().0, "eth0");
    assert_eq!(route_lookup(None, ip("8.8.8.8")).unwrap().0, "snare0");

    add_route(Route {
        metric: 10,
        ..Route::new(net("172.16.0.0/12"), "eth0")
    })
    .unwrap();
    add_route(Route {
        metric: 5,
        src: Some(ip("192.168.5.1")),
        ..Route::new(net("172.16.0.0/12"), "eth2")
    })
    .unwrap();
    assert_eq!(
        route_lookup(None, ip("172.16.4.4")).unwrap(),
        ("eth2".into(), Some(ip("192.168.5.1")))
    );
    add_route(Route::new(net("172.16.4.0/24"), "eth1")).unwrap();
    assert_eq!(route_lookup(None, ip("172.16.4.4")).unwrap().0, "eth1");
    assert!(add_route(Route::new(net("1.0.0.0/8"), "nope")).is_err());

    let s = UdpSocket::bind("0.0.0.0:0").unwrap();
    s.send_to(b"x", "8.8.8.8:53").unwrap();
    set_default_route(None).unwrap();
    let e = route_lookup(None, ip("8.8.8.8")).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NetworkUnreachable);
    let r = s.send_to(b"x", "8.8.8.8:53");
    assert_eq!(code(r), os_semantics().errno(Errno::NetUnreach));
    set_default_route(Some("eth2")).unwrap();
    assert_eq!(route_lookup(None, ip("8.8.8.8")).unwrap().0, "eth2");
}

#[test]
fn weak_and_strong_host() {
    for os in ALL {
        register_test();
        set_os_semantics(os);
        two_nics();
        let s = UdpSocket::bind("10.0.0.1:0").unwrap();
        let r = s.send_to(b"x", "10.0.1.50:9");
        if os == OsSemantics::Windows {
            assert_eq!(r.as_ref().unwrap_err().kind(), ErrorKind::HostUnreachable);
            assert_eq!(code(r), 10065);
        } else {
            r.unwrap();
            let entry = socket_entry(socket_id(&s)).unwrap();
            assert_eq!(entry.last_tx_nic.as_deref(), Some("eth1"), "{os}");
        }
        s.send_to(b"x", "10.0.0.9:9").unwrap();
        assert_eq!(
            socket_entry(socket_id(&s)).unwrap().last_tx_nic.as_deref(),
            Some("eth0")
        );
    }
}

#[test]
fn bound_device_and_link_down() {
    for os in ALL {
        register_test();
        set_os_semantics(os);
        two_nics();
        let s = UdpSocket::bind("0.0.0.0:0").unwrap();
        let id = socket_id(&s);
        set_socket_device(id, Some("eth0")).unwrap();
        assert_eq!(
            socket_entry(id).unwrap().bound_device.as_deref(),
            Some("eth0")
        );
        s.send_to(b"x", "10.0.0.9:9").unwrap();
        assert_eq!(
            socket_entry(id).unwrap().last_tx_nic.as_deref(),
            Some("eth0")
        );
        let r = s.send_to(b"x", "10.0.1.9:9");
        assert_eq!(code(r), os.errno(Errno::NetUnreach), "{os}");

        set_link("eth0", false).unwrap();
        let r = s.send_to(b"x", "10.0.0.9:9");
        assert_eq!(r.as_ref().unwrap_err().kind(), ErrorKind::NetworkDown);
        let expected = match os {
            OsSemantics::Linux => 100,
            OsSemantics::MacOs => 50,
            _ => 10050,
        };
        assert_eq!(code(r), expected);
        set_link("eth0", true).unwrap();
        s.send_to(b"x", "10.0.0.9:9").unwrap();

        assert!(set_socket_device(id, Some("nope")).is_err());
        set_socket_device(id, None).unwrap();
    }
}

#[test]
fn strong_host_egress_down() {
    register_test();
    set_os_semantics(OsSemantics::Windows);
    two_nics();
    let s = UdpSocket::bind("10.0.0.1:0").unwrap();
    set_link("eth0", false).unwrap();
    assert_eq!(code(s.send_to(b"x", "10.0.0.9:9")), 10050);
}

#[test]
fn ingress_link_down_loses_silently() {
    register_test();
    two_nics();
    let rx = UdpSocket::bind("10.0.1.1:7000").unwrap();
    let tx = UdpSocket::bind("10.0.0.1:7001").unwrap();
    set_link("eth1", false).unwrap();
    assert!(!nic("eth1").unwrap().spec.link_up);
    let before = nic_counters("eth1").unwrap();
    tx.send_to(b"lost", "10.0.1.1:7000").unwrap();
    assert_eq!(drain(&rx), 0);
    assert_eq!(nic_counters("eth1").unwrap(), before);
    let entry = socket_entry(socket_id(&rx)).unwrap();
    assert_eq!((entry.drops, entry.wire_lost, entry.delivered), (0, 0, 0));

    set_link("eth1", true).unwrap();
    tx.send_to(b"back", "10.0.1.1:7000").unwrap();
    assert_eq!(drain(&rx), 1);
}

#[test]
fn per_nic_latency() {
    register_test();
    pause_time();
    two_nics();
    set_nic_policy("eth1", |p| p.latency = Duration::from_millis(5)).unwrap();
    let rx = UdpSocket::bind("10.0.1.1:7000").unwrap();
    rx.set_nonblocking(true).unwrap();
    let tx = UdpSocket::bind("10.0.0.1:7001").unwrap();
    tx.send_to(b"late", "10.0.1.1:7000").unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(
        rx.recv_from(&mut buf).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    advance_time(Duration::from_millis(4));
    assert_eq!(
        rx.recv_from(&mut buf).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    advance_time(Duration::from_millis(1));
    let (n, from) = rx.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"late");
    assert_eq!(from, addr("10.0.0.1:7001"));
    assert_eq!(
        socket_entry(socket_id(&rx)).unwrap().last_rx_nic.as_deref(),
        Some("eth1")
    );
}

#[test]
fn earlier_deadline_overtakes_without_head_of_line_blocking() {
    register_test();
    pause_time();
    two_nics();
    let rx = UdpSocket::bind("10.0.1.1:7000").unwrap();
    rx.set_nonblocking(true).unwrap();
    let tx = UdpSocket::bind("10.0.0.1:7001").unwrap();
    set_nic_policy("eth1", |p| p.latency = Duration::from_millis(10)).unwrap();
    tx.send_to(b"first", "10.0.1.1:7000").unwrap();
    set_nic_policy("eth1", |p| p.latency = Duration::from_millis(2)).unwrap();
    tx.send_to(b"second", "10.0.1.1:7000").unwrap();

    let mut buf = [0u8; 16];
    advance_time(Duration::from_millis(2));
    let (n, _) = rx.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"second");
    assert!(rx.recv_from(&mut buf).is_err());
    advance_time(Duration::from_millis(8));
    let (n, _) = rx.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"first");
}

#[test]
fn jitter_reorders_datagrams() {
    register_test();
    pause_time();
    snare::seed_rng(7);
    two_nics();
    set_nic_policy("eth1", |p| p.jitter = Duration::from_millis(50)).unwrap();
    let rx = UdpSocket::bind("10.0.1.1:7000").unwrap();
    rx.set_nonblocking(true).unwrap();
    let tx = UdpSocket::bind("10.0.0.1:7001").unwrap();
    for i in 0u8..32 {
        tx.send_to(&[i], "10.0.1.1:7000").unwrap();
    }
    advance_time(Duration::from_millis(50));
    let mut got = Vec::new();
    let mut buf = [0u8; 4];
    while rx.recv_from(&mut buf).is_ok() {
        got.push(buf[0]);
    }
    assert_eq!(got.len(), 32);
    assert!(
        got.windows(2).any(|w| w[0] > w[1]),
        "no reordering: {got:?}"
    );
}

#[test]
fn loss_and_drop_accounting() {
    register_test();
    two_nics();
    let rx = UdpSocket::bind("10.0.1.1:7000").unwrap();
    let id = socket_id(&rx);
    let tx = UdpSocket::bind("10.0.0.1:7001").unwrap();
    set_nic_policy("eth1", |p: &mut NicPolicy| p.loss_rate = 1.0).unwrap();
    for _ in 0..3 {
        tx.send_to(b"x", "10.0.1.1:7000").unwrap();
    }
    assert_eq!(drain(&rx), 0);
    let e = socket_entry(id).unwrap();
    assert_eq!((e.drops, e.wire_lost, e.overflowed), (3, 3, 0));
    assert_eq!(nic_counters("eth1").unwrap().rx_dropped, 3);

    set_sys_limits(|l| l.drop_accounting = DropAccounting::OverflowOnly);
    for _ in 0..2 {
        tx.send_to(b"x", "10.0.1.1:7000").unwrap();
    }
    let e = socket_entry(id).unwrap();
    assert_eq!((e.drops, e.wire_lost), (3, 5));

    inject_socket_drops(id, 10).unwrap();
    assert_eq!(socket_entry(id).unwrap().drops, 13);
}

#[test]
fn per_nic_counters() {
    register_test();
    two_nics();
    let rx = UdpSocket::bind("10.0.1.1:7000").unwrap();
    let tx = UdpSocket::bind("10.0.0.1:7001").unwrap();
    for _ in 0..2 {
        tx.send_to(&[0u8; 10], "10.0.1.1:7000").unwrap();
    }
    assert_eq!(drain(&rx), 2);
    let eth1 = nic_counters("eth1").unwrap();
    assert_eq!((eth1.tx_packets, eth1.tx_bytes), (2, 20));
    assert_eq!((eth1.rx_packets, eth1.rx_bytes), (2, 20));
    assert_eq!(nic_counters("eth0").unwrap(), Default::default());
    let e = socket_entry(socket_id(&rx)).unwrap();
    assert_eq!((e.delivered, e.queued, e.queued_bytes), (2, 0, 0));

    let lo_name = os_semantics().loopback_name();
    let lo_before = nic_counters(lo_name).unwrap();
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    a.send_to(b"abc", b.local_addr().unwrap()).unwrap();
    let lo = nic_counters(lo_name).unwrap();
    assert_eq!(lo.tx_packets - lo_before.tx_packets, 1);
    assert_eq!(lo.rx_bytes - lo_before.rx_bytes, 3);
    set_nic_counters("eth0", |c| c.rx_crc_errors = 4).unwrap();
    assert_eq!(nic_counters("eth0").unwrap().rx_crc_errors, 4);
}

#[test]
fn socket_table_and_entries() {
    register_test();
    two_nics();
    let udp = UdpSocket::bind("10.0.0.1:7500").unwrap();
    let listener = TcpListener::bind("10.0.0.1:8000").unwrap();
    let lid = socket_id(&listener);
    let c1 = TcpStream::connect("10.0.0.1:8000").unwrap();
    let c2 = TcpStream::connect("10.0.0.1:8000").unwrap();
    let (s1, _) = listener.accept().unwrap();
    let (s2, _) = listener.accept().unwrap();

    let bound = sockets_bound(addr("10.0.0.1:8000"));
    assert_eq!(bound.len(), 3, "{bound:?}");
    assert!(
        bound
            .iter()
            .any(|e| e.id == lid && e.kind == SocketKind::TcpListener)
    );
    for s in [&s1, &s2] {
        let e = bound.iter().find(|e| e.id == socket_id(s)).unwrap();
        assert_eq!(e.kind, SocketKind::TcpStream);
        assert_eq!(e.listener, Some(lid));
        assert_eq!(e.nic.as_deref(), Some("eth0"));
    }
    let e = socket_entry(socket_id(&c1)).unwrap();
    assert_eq!(e.peer, Some(addr("10.0.0.1:8000")));
    assert_eq!(e.last_tx_nic.as_deref(), Some("eth0"));
    assert_eq!(socket_entry(socket_id(&udp)).unwrap().kind, SocketKind::Udp);

    let table = socket_table();
    let ids = [
        socket_id(&udp),
        lid,
        socket_id(&c1),
        socket_id(&c2),
        socket_id(&s1),
        socket_id(&s2),
    ];
    for id in ids {
        assert!(table.iter().any(|e| e.id == id));
    }
    assert!(table.windows(2).all(|w| w[0].id < w[1].id));

    let c1_id = socket_id(&c1);
    drop(c1);
    assert!(socket_table().iter().all(|e| e.id != c1_id));
    let closed = socket_entry(c1_id).unwrap();
    assert!(closed.closed && closed.closed_at.is_some());
}

#[derive(Clone, Debug)]
struct Bytes(Vec<u8>);

impl Packetable for Bytes {
    const CAN_BE_FLATTENED: bool = false;
    const SOCKET_TYPE: SocketType = SocketType::Udp;

    fn encode(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn decode(data: &[u8]) -> Option<(Self, usize)> {
        (!data.is_empty()).then(|| (Self(data.to_vec()), data.len()))
    }
}

#[derive(Default)]
struct Seen(Vec<SocketAddr>);

fn note_source(seen: &mut Seen, _: Bytes, src: SocketAddr) -> TesterAction<Bytes> {
    seen.0.push(src);
    TesterAction::Multiple(Vec::new())
}

#[test]
fn wildcard_delivery_on_an_explicit_nic() {
    register_test();
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/24"))).unwrap();
    let rx = UdpSocket::bind("0.0.0.0:7200").unwrap();
    rx.set_nonblocking(true).unwrap();
    let tx = UdpSocket::bind("0.0.0.0:0").unwrap();
    let tx_port = tx.local_addr().unwrap().port();

    tx.send_to(b"modern", "10.0.0.1:7200").unwrap();
    let mut buf = [0u8; 16];
    let (n, from) = rx.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"modern");
    assert_eq!(from, SocketAddr::new(ip("10.0.0.1"), tx_port));
    let e = socket_entry(socket_id(&rx)).unwrap();
    assert_eq!(e.nic, None);
    assert_eq!(e.last_rx_nic.as_deref(), Some("eth0"));

    if snare::os_semantics_explicit() {
        return;
    }
    add_ip_addr(ip("10.50.0.1"));
    tx.send_to(b"legacy", "10.50.0.1:7200").unwrap();
    assert!(
        rx.recv_from(&mut buf).is_err(),
        "legacy snare0 traffic is not wildcard-delivered"
    );

    let mut tester = connect_tester::<Bytes>(addr("10.50.0.1:7200"))
        .then_stateful_action::<Seen>(note_source)
        .until_stateful_condition::<Seen>(|s| !s.0.is_empty())
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_secs(2));
    run_testers!(tester);
    assert_eq!(
        tester.peek_state::<Seen>().0,
        vec![SocketAddr::new(ip("0.0.0.0"), tx_port)],
        "legacy datagrams reach virtual testers with the bound source"
    );
}

#[test]
fn tcp_stalls_while_the_link_is_down() {
    register_test();
    two_nics();
    let listener = TcpListener::bind("10.0.1.1:8100").unwrap();
    let mut client = TcpStream::connect("10.0.1.1:8100").unwrap();
    let (mut server, _) = listener.accept().unwrap();
    server.set_nonblocking(true).unwrap();
    assert_eq!(
        socket_entry(socket_id(&server))
            .unwrap()
            .last_rx_nic
            .as_deref(),
        Some("eth1")
    );

    set_link("eth1", false).unwrap();
    assert_eq!(client.write(b"hi").unwrap(), 2);
    let mut buf = [0u8; 8];
    assert_eq!(
        server.read(&mut buf).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    let e = socket_entry(socket_id(&server)).unwrap();
    assert_eq!((e.queued, e.queued_bytes), (1, 2));

    set_link("eth1", true).unwrap();
    assert_eq!(server.read(&mut buf).unwrap(), 2);
    assert_eq!(&buf[..2], b"hi");
}

#[test]
fn tcp_takes_the_nic_latency_in_order() {
    register_test();
    pause_time();
    two_nics();
    set_nic_policy("eth1", |p| p.latency = Duration::from_millis(3)).unwrap();
    let listener = TcpListener::bind("10.0.1.1:8200").unwrap();
    let mut client = TcpStream::connect("10.0.1.1:8200").unwrap();
    let (mut server, _) = listener.accept().unwrap();
    server.set_nonblocking(true).unwrap();
    client.write_all(b"a").unwrap();
    set_nic_policy("eth1", |p| p.latency = Duration::from_millis(1)).unwrap();
    client.write_all(b"b").unwrap();
    let mut buf = [0u8; 4];
    advance_time(Duration::from_millis(1));
    assert_eq!(
        server.read(&mut buf).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    advance_time(Duration::from_millis(2));
    let mut got = Vec::new();
    while let Ok(n) = server.read(&mut buf) {
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, b"ab");
}

#[test]
fn remove_a_nic() {
    register_test();
    add_nic(NicSpec::new("eth2").address(net("172.20.0.1/16"))).unwrap();
    add_route(Route::new(net("172.21.0.0/16"), "eth2")).unwrap();
    assert_eq!(route_lookup(None, ip("172.21.0.9")).unwrap().0, "eth2");
    assert!(remove_nic("eth2"));
    assert!(nic("eth2").is_none());
    assert!(!remove_nic("eth2"));
    assert!(routes().iter().all(|r| r.nic != "eth2"));
    assert_eq!(route_lookup(None, ip("172.21.0.9")).unwrap().0, "snare0");
    assert!(UdpSocket::bind("172.20.0.1:0").is_err());
    assert!(!remove_nic("snare0"));
    assert!(!remove_nic(os_semantics().loopback_name()));
}

#[test]
fn set_nic_changes_addresses_and_policy() {
    register_test();
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/24"))).unwrap();
    set_nic("eth0", |spec| {
        spec.addresses.push(net("10.0.0.2/24"));
        spec.mtu = 9000;
        spec.policy.latency = Duration::from_millis(1);
    })
    .unwrap();
    let snap = nic("eth0").unwrap();
    assert_eq!(snap.spec.mtu, 9000);
    assert_eq!(snap.spec.policy.latency, Duration::from_millis(1));
    assert!(UdpSocket::bind("10.0.0.2:0").is_ok());
    assert!(set_nic("nope", |_| {}).is_err());
}

#[test]
fn dropping_the_last_clone_frees_the_port() {
    register_test();
    let a = UdpSocket::bind("127.0.0.1:7300").unwrap();
    let id = socket_id(&a);
    let b = a.try_clone().unwrap();
    assert_eq!(socket_id(&b), id);
    drop(a);
    assert!(socket_table().iter().any(|e| e.id == id));
    assert!(UdpSocket::bind("127.0.0.1:7300").is_err());
    drop(b);
    assert!(socket_table().iter().all(|e| e.id != id));
    let closed = closed_sockets();
    let tomb = closed.iter().find(|e| e.id == id).expect("tombstone");
    assert!(tomb.closed && tomb.closed_at.is_some());
    assert_eq!(tomb.local, addr("127.0.0.1:7300"));
    let again = UdpSocket::bind("127.0.0.1:7300").unwrap();
    assert_ne!(socket_id(&again), id);
    assert!(socket_entry(id).unwrap().closed);
}

#[test]
fn tcp_order_survives_link_flaps_and_removal() {
    register_test();
    two_nics();
    let listener = TcpListener::bind("10.0.1.1:8300").unwrap();
    let mut client = TcpStream::connect("10.0.1.1:8300").unwrap();
    let (mut server, _) = listener.accept().unwrap();
    server.set_nonblocking(true).unwrap();

    set_link("eth1", false).unwrap();
    client.write_all(b"ab").unwrap();
    set_link("eth1", true).unwrap();
    client.write_all(b"cd").unwrap();
    set_link("eth1", false).unwrap();
    client.write_all(b"ef").unwrap();
    assert!(remove_nic("eth1"));
    client.write_all(b"gh").unwrap();

    let mut buf = [0u8; 16];
    let mut got = Vec::new();
    while let Ok(n) = server.read(&mut buf) {
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, b"abcdefgh");
}

#[test]
fn blocked_readers_wake_on_link_up_and_after_latency() {
    register_test();
    pause_time();
    two_nics();
    let listener = TcpListener::bind("10.0.1.1:8400").unwrap();
    let mut client = TcpStream::connect("10.0.1.1:8400").unwrap();
    let (mut server, _) = listener.accept().unwrap();
    set_link("eth1", false).unwrap();
    client.write_all(b"hi").unwrap();
    let reader = std::thread::spawn(move || {
        let mut buf = [0u8; 4];
        let n = server.read(&mut buf).unwrap();
        buf[..n].to_vec()
    })
    .register_as_child();
    std::thread::sleep(Duration::from_millis(20));
    set_link("eth1", true).unwrap();
    assert_eq!(reader.join().unwrap(), b"hi");

    set_nic_policy("eth1", |p| p.latency = Duration::from_millis(5)).unwrap();
    let rx = UdpSocket::bind("10.0.1.1:7400").unwrap();
    let tx = UdpSocket::bind("10.0.0.1:7401").unwrap();
    let reader = std::thread::spawn(move || {
        let mut buf = [0u8; 8];
        rx.recv_from(&mut buf).unwrap().0
    })
    .register_as_child();
    std::thread::sleep(Duration::from_millis(20));
    tx.send_to(b"x", "10.0.1.1:7400").unwrap();
    advance_time(Duration::from_millis(5));
    assert_eq!(reader.join().unwrap(), 1);
}

#[test]
fn a_socket_outliving_its_slot_leaves_the_next_slot_alone() {
    register_test();
    let old = UdpSocket::bind("127.0.0.1:7600").unwrap();
    register_test();
    let new = UdpSocket::bind("127.0.0.1:7600").unwrap();
    assert_ne!(socket_id(&old), socket_id(&new));
    drop(old);
    assert!(socket_table().iter().any(|e| e.id == socket_id(&new)));
    new.set_nonblocking(true).unwrap();
    assert_eq!(
        new.recv_from(&mut [0u8; 4]).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
}
