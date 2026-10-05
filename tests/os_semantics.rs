//! Each faithful row of snare's OS emulation, run under Linux, macOS and
//! Windows semantics, then once in legacy mode (no OS selected), where the
//! historical results must hold exactly.

use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::time::Duration;

use std::io::{Read, Write};

use snare::net::{TcpListener, TcpStream, UdpSocket};
use snare::sched::PState;
use snare::sched::testkit::{StrictClock, StrictConfig};
use snare::{
    Errno, IpNet, NicPolicy, NicSpec, OsSemantics, add_ip_addr, add_nic, advance_time,
    inject_icmp_port_unreachable, os_error_code, os_semantics, os_semantics_explicit, pause_time,
    register_test, reset_tcp, set_default_route, set_nic_policy, set_os_semantics, set_privileges,
    socket_entry, socket_id, time_value,
};

const ALL: [OsSemantics; 3] = [OsSemantics::Linux, OsSemantics::MacOs, OsSemantics::Windows];

fn for_each_os(f: impl Fn(OsSemantics)) {
    for os in ALL {
        register_test();
        set_os_semantics(os);
        assert_eq!(os_semantics(), os);
        assert!(os_semantics_explicit());
        f(os);
    }
}

/// Legacy scenarios only mean something when `SNARE_OS` leaves the slot in
/// legacy mode.
fn legacy() -> bool {
    register_test();
    !os_semantics_explicit()
}

fn code<T: std::fmt::Debug>(r: io::Result<T>) -> i32 {
    let e = r.expect_err("expected an error");
    os_error_code(&e).unwrap_or_else(|| panic!("no OS code on {e:?}"))
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn pick(os: OsSemantics, linux: i32, macos: i32, windows: i32) -> i32 {
    match os {
        OsSemantics::Linux => linux,
        OsSemantics::MacOs => macos,
        _ => windows,
    }
}

#[test]
fn ephemeral_ports_follow_the_os_range() {
    for_each_os(|os| {
        let range = os.ephemeral_ports();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        assert_eq!(port, *range.start(), "{os}");

        let listener = TcpListener::bind("127.0.0.1:5000").unwrap();
        let client = TcpStream::connect("127.0.0.1:5000").unwrap();
        let port = client.local_addr().unwrap().port();
        assert!(range.contains(&port), "{os}: {port}");
        drop(listener);
    });
}

#[test]
fn ephemeral_ports_legacy() {
    if !legacy() {
        return;
    }
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_eq!(udp.local_addr().unwrap().port(), 40_000);
    let _listener = TcpListener::bind("127.0.0.1:5000").unwrap();
    let client = TcpStream::connect("127.0.0.1:5000").unwrap();
    assert_eq!(client.local_addr().unwrap().port(), 40_001);
}

#[test]
fn bind_to_an_unknown_ip() {
    for_each_os(|os| {
        let r = UdpSocket::bind("10.9.9.9:5000");
        assert_eq!(r.as_ref().unwrap_err().kind(), ErrorKind::AddrNotAvailable);
        assert_eq!(code(r), pick(os, 99, 49, 10049));
        let r = TcpListener::bind("10.9.9.9:5000");
        assert_eq!(code(r), pick(os, 99, 49, 10049));
    });
}

#[test]
fn bind_to_an_unknown_ip_legacy() {
    if !legacy() {
        return;
    }
    let e = UdpSocket::bind("10.9.9.9:5000").unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
    assert_eq!(os_error_code(&e), None);
    let e = TcpListener::bind("10.9.9.9:5000").unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AddrNotAvailable);
    assert_eq!(os_error_code(&e), None);
}

#[test]
fn port_in_use() {
    for_each_os(|os| {
        let _a = UdpSocket::bind("127.0.0.1:6000").unwrap();
        let r = UdpSocket::bind("127.0.0.1:6000");
        assert_eq!(r.as_ref().unwrap_err().kind(), ErrorKind::AddrInUse);
        assert_eq!(code(r), pick(os, 98, 48, 10048));

        let _w = UdpSocket::bind("0.0.0.0:6001").unwrap();
        assert_eq!(
            code(UdpSocket::bind("0.0.0.0:6001")),
            pick(os, 98, 48, 10048)
        );

        let _l = TcpListener::bind("127.0.0.1:6000").unwrap();
        assert_eq!(
            code(TcpListener::bind("127.0.0.1:6000")),
            pick(os, 98, 48, 10048)
        );
    });
}

#[test]
fn port_in_use_legacy() {
    if !legacy() {
        return;
    }
    let _a = UdpSocket::bind("127.0.0.1:6000").unwrap();
    let e = UdpSocket::bind("127.0.0.1:6000").unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
    let _w = UdpSocket::bind("0.0.0.0:6001").unwrap();
    let moved = UdpSocket::bind("0.0.0.0:6001").unwrap();
    assert_eq!(moved.local_addr().unwrap().port(), 40_000);
    let e = TcpListener::bind("127.0.0.1:6000").unwrap_err();
    assert_eq!(
        e.kind(),
        ErrorKind::AddrNotAvailable,
        "legacy ports are shared across protocols"
    );
}

#[test]
fn specific_over_wildcard() {
    for_each_os(|os| {
        let _w = UdpSocket::bind("0.0.0.0:6002").unwrap();
        let r = UdpSocket::bind("127.0.0.1:6002");
        if os == OsSemantics::Windows {
            assert!(r.is_ok(), "{os}: {r:?}");
        } else {
            assert_eq!(code(r), pick(os, 98, 48, 10048));
        }
    });
}

#[test]
fn specific_over_wildcard_legacy() {
    if !legacy() {
        return;
    }
    let _w = UdpSocket::bind("0.0.0.0:6002").unwrap();
    assert!(UdpSocket::bind("127.0.0.1:6002").is_ok());
}

#[test]
fn privileged_port_without_net_bind_service() {
    for_each_os(|os| {
        set_privileges(|p| {
            p.root = false;
            p.net_bind_service = false;
        });
        let r = UdpSocket::bind("127.0.0.1:80");
        let t = TcpListener::bind("127.0.0.1:81");
        if os == OsSemantics::Linux {
            assert_eq!(r.as_ref().unwrap_err().kind(), ErrorKind::PermissionDenied);
            assert_eq!(code(r), 13);
            assert_eq!(code(t), 13);
        } else {
            assert!(r.is_ok() && t.is_ok(), "{os}");
        }
    });
}

#[test]
fn privileged_port_legacy_follows_the_host() {
    if !legacy() {
        return;
    }
    set_privileges(|p| {
        p.root = false;
        p.net_bind_service = false;
    });
    let r = UdpSocket::bind("127.0.0.1:80");
    if OsSemantics::host() == OsSemantics::Linux {
        assert_eq!(code(r), 13);
    } else {
        assert!(r.is_ok());
    }
}

#[test]
fn loopback_beyond_127_0_0_1() {
    for_each_os(|os| {
        let r = UdpSocket::bind("127.0.0.2:5000");
        if os == OsSemantics::MacOs {
            assert_eq!(code(r), 49);
        } else {
            assert_eq!(r.unwrap().local_addr().unwrap(), addr("127.0.0.2:5000"));
        }
    });
}

#[test]
fn loopback_beyond_127_0_0_1_legacy() {
    if !legacy() {
        return;
    }
    let e = UdpSocket::bind("127.0.0.2:5000").unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
}

#[test]
fn broadcast_needs_so_broadcast() {
    for_each_os(|os| {
        let s = UdpSocket::bind("0.0.0.0:0").unwrap();
        let r = s.send_to(b"hi", "255.255.255.255:9");
        assert_eq!(r.as_ref().unwrap_err().kind(), ErrorKind::PermissionDenied);
        assert_eq!(code(r), pick(os, 13, 13, 10013));
        s.set_broadcast(true).unwrap();
        assert_eq!(s.send_to(b"hi", "255.255.255.255:9").unwrap(), 2);
    });
}

#[test]
fn broadcast_legacy() {
    if !legacy() {
        return;
    }
    let s = UdpSocket::bind("0.0.0.0:0").unwrap();
    assert_eq!(s.send_to(b"hi", "255.255.255.255:9").unwrap(), 2);
}

#[test]
fn oversized_datagrams() {
    for_each_os(|os| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let r = s.send_to(&vec![0u8; 65_508], "127.0.0.1:9");
        assert_eq!(code(r), pick(os, 90, 40, 10040));
        if os != OsSemantics::MacOs {
            assert_eq!(
                s.send_to(&vec![0u8; 65_507], "127.0.0.1:9").unwrap(),
                65_507
            );
        }
        let r = s.send_to(&vec![0u8; 9_217], "127.0.0.1:9");
        if os == OsSemantics::MacOs {
            assert_eq!(code(r), 40);
        } else {
            assert_eq!(r.unwrap(), 9_217);
        }
        assert_eq!(s.send_to(&vec![0u8; 9_216], "127.0.0.1:9").unwrap(), 9_216);
    });
}

#[test]
fn oversized_datagrams_legacy() {
    if !legacy() {
        return;
    }
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_eq!(
        s.send_to(&vec![0u8; 65_508], "127.0.0.1:9").unwrap(),
        65_508
    );
    assert_eq!(s.send_to(&vec![0u8; 9_217], "127.0.0.1:9").unwrap(), 9_217);
}

#[test]
fn read_timeout() {
    for_each_os(|os| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
        let mut buf = [0u8; 8];
        let r = s.recv_from(&mut buf);
        let kind = r.as_ref().unwrap_err().kind();
        if os == OsSemantics::Windows {
            assert_eq!(kind, ErrorKind::TimedOut);
        } else {
            assert_eq!(kind, ErrorKind::WouldBlock);
        }
        assert_eq!(code(r), pick(os, 11, 35, 10060));

        let listener = TcpListener::bind("127.0.0.1:5100").unwrap();
        let client = TcpStream::connect("127.0.0.1:5100").unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let r = std::io::Read::read(&mut &client, &mut buf);
        assert_eq!(code(r), pick(os, 11, 35, 10060));
        drop(listener);
    });
}

#[test]
fn read_timeout_legacy() {
    if !legacy() {
        return;
    }
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
    let e = s.recv_from(&mut [0u8; 8]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::WouldBlock);
    assert_eq!(os_error_code(&e), None);
}

#[test]
fn nonblocking_errno() {
    for_each_os(|os| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_nonblocking(true).unwrap();
        let r = s.recv_from(&mut [0u8; 8]);
        assert_eq!(r.as_ref().unwrap_err().kind(), ErrorKind::WouldBlock);
        assert_eq!(code(r), pick(os, 11, 35, 10035));

        let listener = TcpListener::bind("127.0.0.1:5200").unwrap();
        listener.set_nonblocking(true).unwrap();
        assert_eq!(code(listener.accept()), pick(os, 11, 35, 10035));
    });
}

#[test]
fn nonblocking_errno_legacy() {
    if !legacy() {
        return;
    }
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_nonblocking(true).unwrap();
    let e = s.recv_from(&mut [0u8; 8]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::WouldBlock);
    assert_eq!(os_error_code(&e), None);
    assert_eq!(
        e.to_string(),
        io::Error::from(ErrorKind::WouldBlock).to_string()
    );
}

#[test]
fn recv_into_a_short_buffer() {
    for_each_os(|os| {
        let rx = UdpSocket::bind("127.0.0.1:7100").unwrap();
        rx.set_nonblocking(true).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(b"0123456789", "127.0.0.1:7100").unwrap();
        let mut buf = [0u8; 4];
        let r = rx.recv_from(&mut buf);
        if os == OsSemantics::Windows {
            assert_eq!(code(r), 10040);
        } else {
            assert_eq!(r.unwrap().0, 4);
        }
        assert_eq!(&buf, b"0123");
        assert!(
            rx.recv_from(&mut buf).is_err(),
            "{os}: the datagram is consumed"
        );
    });
}

#[test]
fn recv_into_a_short_buffer_legacy() {
    if !legacy() {
        return;
    }
    let rx = UdpSocket::bind("127.0.0.1:7100").unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    tx.send_to(b"0123456789", "127.0.0.1:7100").unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(rx.recv_from(&mut buf).unwrap().0, 4);
    assert_eq!(&buf, b"0123");
}

#[test]
fn selection_is_per_slot_and_affects_later_sockets() {
    register_test();
    let host = os_semantics();
    let before = UdpSocket::bind("127.0.0.1:0").unwrap();
    let other = if host == OsSemantics::Linux {
        OsSemantics::Windows
    } else {
        OsSemantics::Linux
    };
    set_os_semantics(other);
    let after = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_eq!(
        after.local_addr().unwrap().port(),
        *other.ephemeral_ports().start()
    );
    assert_ne!(before.local_addr().unwrap(), after.local_addr().unwrap());

    let child = std::thread::spawn(|| {
        register_test();
        os_semantics_explicit()
    });
    let explicit_elsewhere = child.join().unwrap();
    assert_eq!(explicit_elsewhere, snare_os_env().is_some());

    let unregistered = std::thread::spawn(os_semantics_explicit);
    assert_eq!(unregistered.join().unwrap(), snare_os_env().is_some());
}

fn snare_os_env() -> Option<String> {
    std::env::var("SNARE_OS")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

/// A fresh slot on `os` whose clock only moves by jumping to the next
/// deadline once every participant waits.
fn strict(os: OsSemantics) -> StrictClock {
    register_test();
    set_os_semantics(os);
    StrictClock::start(StrictConfig::default()).unwrap()
}

/// Run `f` on a snare thread, returning its result and the virtual time it
/// took.
fn timed<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> (T, Duration) {
    let start = time_value();
    let out = snare::thread::spawn(f).join().unwrap();
    (out, time_value() - start)
}

fn connect(target: &str) -> io::Result<()> {
    TcpStream::connect(target).map(drop)
}

fn connect_within(target: &str, timeout: Duration) -> io::Result<()> {
    TcpStream::connect_timeout(&addr(target), timeout).map(drop)
}

#[test]
fn connect_to_an_owned_address_with_no_listener() {
    for os in ALL {
        let _clock = strict(os);
        let (r, took) = timed(|| connect("127.0.0.1:7000"));
        assert_eq!(r.as_ref().unwrap_err().kind(), ErrorKind::ConnectionRefused);
        assert_eq!(code(r), pick(os, 111, 61, 10061), "{os}");
        let retry = if os == OsSemantics::Windows { 2 } else { 0 };
        assert_eq!(took, Duration::from_secs(retry), "{os}");

        let (r, took) = timed(|| connect_within("127.0.0.1:7000", Duration::from_millis(500)));
        if os == OsSemantics::Windows {
            let e = r.unwrap_err();
            assert_eq!(e.kind(), ErrorKind::TimedOut);
            assert_eq!(os_error_code(&e), None, "std's own connect_timeout error");
            assert_eq!(took, Duration::from_millis(500));
        } else {
            assert_eq!(code(r), pick(os, 111, 61, 0));
            assert_eq!(took, Duration::ZERO);
        }
    }
}

#[test]
fn connect_to_an_owned_address_with_no_listener_legacy() {
    if !legacy() {
        return;
    }
    let _clock = StrictClock::start(StrictConfig::default()).unwrap();
    let (r, took) = timed(|| connect("127.0.0.1:7000"));
    let e = r.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ConnectionRefused);
    assert_eq!(os_error_code(&e), None);
    assert_eq!(took, Duration::ZERO);
}

#[test]
fn connect_to_a_silent_address() {
    for os in ALL {
        let _clock = strict(os);
        let (r, took) = timed(|| connect("10.1.2.3:7000"));
        assert_eq!(r.as_ref().unwrap_err().kind(), ErrorKind::TimedOut);
        assert_eq!(code(r), pick(os, 110, 60, 10060), "{os}");
        assert_eq!(
            took,
            Duration::from_secs(pick(os, 127, 75, 21) as u64),
            "{os}"
        );

        let (r, took) = timed(|| connect_within("10.1.2.3:7000", Duration::from_secs(3)));
        let e = r.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::TimedOut);
        assert_eq!(os_error_code(&e), None);
        assert_eq!(took, Duration::from_secs(3), "{os}");

        let (r, took) = timed(|| connect_within("10.1.2.3:7000", Duration::from_secs(600)));
        assert_eq!(code(r), pick(os, 110, 60, 10060));
        assert_eq!(took, Duration::from_secs(pick(os, 127, 75, 21) as u64));

        set_default_route(None).unwrap();
        let (r, took) = timed(|| connect("10.1.2.3:7000"));
        assert_eq!(code(r), pick(os, 101, 51, 10051), "{os}: no route");
        assert_eq!(took, Duration::ZERO);
    }
}

#[test]
fn connect_to_a_silent_address_legacy() {
    if !legacy() {
        return;
    }
    let _clock = StrictClock::start(StrictConfig::default()).unwrap();
    let (r, took) = timed(|| connect("10.1.2.3:7000"));
    let e = r.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AddrNotAvailable);
    assert_eq!(os_error_code(&e), None);
    assert_eq!(took, Duration::ZERO);
}

/// Wait (in real time) until a participant is blocked in `wait`.
fn wait_blocked(clock: &StrictClock, wait: &str) {
    let start = std::time::Instant::now();
    while !clock
        .driver()
        .participants()
        .iter()
        .any(|p| p.state == PState::Blocked && p.wait == Some(wait))
    {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "nothing blocked in {wait}"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn connect_retry_takes_a_listener_that_appears() {
    let clock = strict(OsSemantics::Windows);
    let setup = snare::sched::setup_scope("bind-later");
    let (r, took) = {
        let start = time_value();
        let client = snare::thread::spawn(|| {
            TcpStream::connect("127.0.0.1:7010").map(|s| s.peer_addr().unwrap())
        });
        wait_blocked(&clock, "tcp connect");
        let listener = TcpListener::bind("127.0.0.1:7010").unwrap();
        drop(setup);
        let r = client.join().unwrap();
        drop(listener);
        (r, time_value() - start)
    };
    assert_eq!(r.unwrap(), addr("127.0.0.1:7010"));
    assert_eq!(took, Duration::ZERO);
}

fn icmp_host(os: OsSemantics, connected: bool) -> Option<i32> {
    match (os, connected) {
        (OsSemantics::Windows, _) => Some(10054),
        (_, true) => Some(pick(os, 111, 61, 0)),
        (_, false) => None,
    }
}

fn expect_icmp(os: OsSemantics, r: io::Result<usize>, connected: bool) {
    match icmp_host(os, connected) {
        Some(c) => assert_eq!(code(r), c, "{os}"),
        None => assert_eq!(r.unwrap_err().kind(), ErrorKind::WouldBlock, "{os}"),
    }
}

fn icmp_to_udp(os: OsSemantics) {
    let local = addr("127.0.0.1:7100");
    let far = addr("127.0.0.1:7200");
    let mut buf = [0u8; 8];

    let connected = UdpSocket::bind(local).unwrap();
    connected.connect(far).unwrap();
    connected.set_nonblocking(true).unwrap();
    inject_icmp_port_unreachable(local, far);
    let expected = if os == OsSemantics::Windows {
        Errno::ConnReset
    } else {
        Errno::ConnRefused
    };
    assert_eq!(
        socket_entry(socket_id(&connected)).unwrap().icmp_error,
        Some(expected)
    );
    expect_icmp(os, connected.recv(&mut buf), true);
    assert_eq!(
        connected.recv(&mut buf).unwrap_err().kind(),
        ErrorKind::WouldBlock,
        "{os}: reported once"
    );

    inject_icmp_port_unreachable(local, far);
    let sent = connected.send(b"x");
    if os == OsSemantics::Windows {
        assert_eq!(sent.unwrap(), 1, "Windows reports it only on receive");
        expect_icmp(os, connected.recv(&mut buf), true);
    } else {
        expect_icmp(os, sent, true);
    }

    inject_icmp_port_unreachable(local, addr("127.0.0.1:7300"));
    assert_eq!(
        socket_entry(socket_id(&connected)).unwrap().icmp_error,
        None,
        "{os}: an error about another peer never reaches a connected socket"
    );
    drop(connected);

    let open = UdpSocket::bind(local).unwrap();
    open.set_nonblocking(true).unwrap();
    inject_icmp_port_unreachable(local, far);
    expect_icmp(os, open.recv_from(&mut buf).map(|(n, _)| n), false);
    assert_eq!(
        open.recv_from(&mut buf).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
}

#[test]
fn icmp_port_unreachable_to_udp() {
    for_each_os(icmp_to_udp);
}

#[test]
fn icmp_port_unreachable_to_udp_legacy() {
    if !legacy() {
        return;
    }
    icmp_to_udp(OsSemantics::host());
}

#[test]
fn icmp_wakes_a_blocked_windows_receiver() {
    let clock = strict(OsSemantics::Windows);
    let rx = UdpSocket::bind("127.0.0.1:7400").unwrap();
    let reader = snare::thread::spawn(move || rx.recv_from(&mut [0u8; 8]).map(|(n, _)| n));
    wait_blocked(&clock, "udp read");
    inject_icmp_port_unreachable(addr("127.0.0.1:7400"), addr("127.0.0.1:7500"));
    assert_eq!(code(reader.join().unwrap()), 10054);
}

fn icmp_policy(os: OsSemantics) {
    let lab: IpNet = "10.20.0.1/24".parse().unwrap();
    let peer: IpNet = "10.20.0.2/24".parse().unwrap();
    add_nic(
        NicSpec::new("lab0")
            .address(lab)
            .address(peer)
            .policy(NicPolicy {
                icmp_port_unreachable: true,
                ..NicPolicy::default()
            }),
    )
    .unwrap();
    let mut buf = [0u8; 8];

    let sut = UdpSocket::bind("10.20.0.1:5000").unwrap();
    sut.set_nonblocking(true).unwrap();
    sut.connect("10.20.0.2:6000").unwrap();
    assert_eq!(sut.send(b"hello").unwrap(), 5);
    expect_icmp(os, sut.recv(&mut buf), true);

    let open = UdpSocket::bind("10.20.0.1:5001").unwrap();
    open.set_nonblocking(true).unwrap();
    open.send_to(b"hello", "10.20.0.2:6000").unwrap();
    expect_icmp(os, open.recv_from(&mut buf).map(|(n, _)| n), false);

    let listening = UdpSocket::bind("10.20.0.2:6001").unwrap();
    open.send_to(b"hi", "10.20.0.2:6001").unwrap();
    assert_eq!(listening.recv_from(&mut buf).unwrap().0, 2);
    assert_eq!(socket_entry(socket_id(&open)).unwrap().icmp_error, None);

    add_ip_addr("10.30.0.9".parse().unwrap());
    set_nic_policy("snare0", |p| p.icmp_port_unreachable = true).unwrap();
    let tester = UdpSocket::bind("0.0.0.0:0").unwrap();
    tester.set_nonblocking(true).unwrap();
    tester.connect("10.30.0.9:6000").unwrap();
    tester.send(b"to a virtual tester").unwrap();
    assert_eq!(
        socket_entry(socket_id(&tester)).unwrap().icmp_error,
        None,
        "{os}: add_ip_addr addresses never answer with ICMP"
    );
    assert_eq!(
        tester.recv(&mut buf).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
}

#[test]
fn icmp_port_unreachable_policy() {
    for_each_os(icmp_policy);
}

#[test]
fn icmp_port_unreachable_policy_legacy() {
    if !legacy() {
        return;
    }
    icmp_policy(OsSemantics::host());
}

#[test]
fn a_later_icmp_error_never_postpones_a_pending_one() {
    for_each_os(|os| {
        pause_time();
        add_nic(
            NicSpec::new("lab0")
                .address("10.20.0.1/24".parse::<IpNet>().unwrap())
                .address("10.20.0.2/24".parse::<IpNet>().unwrap())
                .policy(NicPolicy {
                    icmp_port_unreachable: true,
                    latency: Duration::from_millis(3),
                    ..NicPolicy::default()
                }),
        )
        .unwrap();
        let sut = UdpSocket::bind("10.20.0.1:5000").unwrap();
        sut.set_nonblocking(true).unwrap();
        sut.connect("10.20.0.2:6000").unwrap();
        let mut buf = [0u8; 8];
        sut.send(b"a").unwrap();
        advance_time(Duration::from_millis(4));
        sut.send(b"b").unwrap();
        advance_time(Duration::from_millis(2));
        expect_icmp(os, sut.recv(&mut buf), true);
    });
}

fn tcp_pair(port: u16) -> (TcpStream, TcpStream) {
    let target = SocketAddr::new([127, 0, 0, 1].into(), port);
    let listener = TcpListener::bind(target).unwrap();
    let client = TcpStream::connect(target).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

#[test]
fn write_after_the_peer_closed() {
    for_each_os(|os| {
        let (mut client, server) = tcp_pair(7600);
        drop(server);
        let mut buf = [0u8; 8];
        assert_eq!(client.write(b"first").unwrap(), 5, "{os}: FIN only");
        assert_eq!(code(client.write(b"second")), pick(os, 32, 32, 10054));
        assert_eq!(code(client.write(b"third")), pick(os, 32, 32, 10054));
        let r = client.read(&mut buf);
        if os == OsSemantics::Windows {
            assert_eq!(code(r), 10054);
        } else {
            assert_eq!(r.unwrap(), 0, "{os}: EOF after the FIN");
        }
        assert!(client.take_error().unwrap().is_none(), "{os}");

        let (mut client, _server) = tcp_pair(7601);
        reset_tcp(client.local_addr().unwrap());
        let r = client.write(b"x");
        assert_eq!(r.as_ref().unwrap_err().kind(), ErrorKind::ConnectionReset);
        assert_eq!(code(r), pick(os, 104, 54, 10054));
        assert_eq!(code(client.write(b"y")), pick(os, 32, 32, 10054));

        let (mut client, _server) = tcp_pair(7602);
        reset_tcp(client.local_addr().unwrap());
        assert_eq!(code(client.read(&mut buf)), pick(os, 104, 54, 10054));

        let (mut client, _server) = tcp_pair(7603);
        client.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(code(client.write(b"x")), pick(os, 32, 32, 10058));
    });
}

#[test]
fn write_after_the_peer_closed_legacy() {
    if !legacy() {
        return;
    }
    let (mut client, server) = tcp_pair(7600);
    drop(server);
    let e = client.write(b"first").unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotConnected);
    assert_eq!(os_error_code(&e), None);
    let taken = client.take_error().unwrap().unwrap();
    assert_eq!(taken.kind(), ErrorKind::ConnectionReset);

    let (mut client, _server) = tcp_pair(7601);
    reset_tcp(client.local_addr().unwrap());
    let e = client.write(b"x").unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ConnectionReset);
    assert_eq!(os_error_code(&e), None);
}

#[test]
fn zero_linger_resets_the_peer() {
    for_each_os(|os| {
        let (client, mut server) = tcp_pair(7700);
        client.set_linger(Some(Duration::ZERO)).unwrap();
        assert_eq!(client.linger().unwrap(), Some(Duration::ZERO));
        drop(client);
        let mut buf = [0u8; 8];
        let r = server.read(&mut buf);
        assert_eq!(r.as_ref().unwrap_err().kind(), ErrorKind::ConnectionReset);
        assert_eq!(code(r), pick(os, 104, 54, 10054));
        assert_eq!(code(server.write(b"x")), pick(os, 32, 32, 10054));

        let (client, mut server) = tcp_pair(7701);
        drop(client);
        assert_eq!(
            server.read(&mut buf).unwrap(),
            0,
            "{os}: a plain close is a FIN"
        );
    });
}

#[test]
fn zero_linger_legacy() {
    if !legacy() {
        return;
    }
    let (client, _server) = tcp_pair(7700);
    let e = client.set_linger(Some(Duration::ZERO)).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidInput);
}
