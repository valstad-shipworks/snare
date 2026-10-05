//! fast-talker's socket options, socket table and multicast under the shim,
//! and snare's own multicast, broadcast and dual-stack delivery, per
//! emulated OS.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use snare::fast_talker::multicast;
use snare::fast_talker::nic::Nic;
use snare::fast_talker::options::{Policy, Reason, Rules, SocketOption};
use snare::fast_talker::rt::Scheduler;
use snare::fast_talker::sim::{self, FtEvent};
use snare::fast_talker::sockets::{self, Protocol, SocketMemory, SocketOptions, State};
use snare::net::{TcpListener, TcpStream, UdpSocket};
use snare::{
    IpNet, Membership, NicSpec, OsSemantics, Route, add_nic, add_route, nic_counters,
    os_error_code, pause_time, register_test, set_os_semantics, set_privileges, socket_entry,
    socket_id,
};

const ALL: [OsSemantics; 3] = [OsSemantics::Linux, OsSemantics::MacOs, OsSemantics::Windows];

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

/// A fresh slot on `os` (legacy with `None`) with a paused clock, `eth0` at
/// 10.0.0.1/24 and `eth1` at 10.0.0.2/24.
fn setup(os: Option<OsSemantics>) {
    register_test();
    if let Some(os) = os {
        set_os_semantics(os);
    }
    pause_time();
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/24"))).unwrap();
    add_nic(NicSpec::new("eth1").address(net("10.0.0.2/24"))).unwrap();
}

fn bind(a: &str) -> UdpSocket {
    let s = UdpSocket::bind(a).unwrap();
    s.set_nonblocking(true).unwrap();
    s
}

fn code<T: std::fmt::Debug>(r: io::Result<T>) -> Option<i32> {
    os_error_code(&r.unwrap_err())
}

fn recv(s: &UdpSocket) -> Option<(Vec<u8>, SocketAddr)> {
    let mut buf = [0u8; 2048];
    match s.recv_from(&mut buf) {
        Ok((n, from)) => Some((buf[..n].to_vec(), from)),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => None,
        Err(e) => panic!("recv: {e}"),
    }
}

fn opts() -> SocketOptions {
    SocketOptions::default()
}

#[test]
fn recv_buffer_follows_each_os() {
    for (os, want) in ALL.into_iter().zip([200_000u32, 100_000, 100_000]) {
        setup(Some(os));
        let s = bind("10.0.0.1:7000");
        SocketOptions {
            recv_buffer: Some(100_000),
            ..opts()
        }
        .apply(&s)
        .unwrap();
        assert_eq!(SocketMemory::of(&s).unwrap().rcvbuf, want, "{os}");
        let id = socket_id(&s);
        assert_eq!(socket_entry(id).unwrap().rcvbuf, Some(want as usize));
        let snap = sim::socket(id).unwrap();
        assert_eq!(snap.options.recv_buffer, Some(100_000));
        assert_eq!(snap.sockopts.recv_buffer, Some(want as usize));
        assert_eq!(snap.sockopts.log.len(), 1);
        assert_eq!(snap.sockopts.log[0].what, "recv_buffer(100000)");
    }

    setup(Some(OsSemantics::MacOs));
    let s = bind("10.0.0.1:7000");
    let r = SocketOptions {
        recv_buffer: Some(20 << 20),
        ..opts()
    }
    .apply(&s);
    assert_eq!(code(r), Some(55), "ENOBUFS over kern.ipc.maxsockbuf");
    let log = sim::socket(socket_id(&s)).unwrap().sockopts.log;
    assert_eq!(log[0].os_error, Some(55));
    assert!(sim::events().iter().any(|e| matches!(
        &e.event,
        FtEvent::Socket { socket, result: Err(_), .. } if *socket == socket_id(&s)
    )));
}

#[test]
fn force_falls_back_to_the_capped_size_without_net_admin() {
    setup(Some(OsSemantics::Linux));
    let s = bind("10.0.0.1:7000");
    let big = SocketOptions {
        recv_buffer: Some(1_000_000),
        send_buffer: Some(1_000_000),
        ..opts()
    };
    big.apply(&s).unwrap();
    let m = SocketMemory::of(&s).unwrap();
    assert_eq!((m.rcvbuf, m.sndbuf), (2_000_000, 2_000_000), "FORCE");

    set_privileges(|p| {
        p.root = false;
        p.net_admin = false;
    });
    big.apply(&s).unwrap();
    let m = SocketMemory::of(&s).unwrap();
    assert_eq!(
        (m.rcvbuf, m.sndbuf),
        (212_992 * 2, 212_992 * 2),
        "capped at rmem_max/wmem_max, doubled"
    );
}

#[test]
fn bind_device_steers_sends() {
    for os in ALL {
        setup(Some(os));
        let s = bind("0.0.0.0:0");
        let id = socket_id(&s);
        s.send_to(b"a", addr("10.0.0.9:9")).unwrap();
        assert_eq!(
            socket_entry(id).unwrap().last_tx_nic.as_deref(),
            Some("eth0")
        );
        SocketOptions {
            bind_device: Some("eth1".into()),
            ..opts()
        }
        .apply(&s)
        .unwrap();
        s.send_to(b"b", addr("10.0.0.9:9")).unwrap();
        let entry = socket_entry(id).unwrap();
        assert_eq!(entry.last_tx_nic.as_deref(), Some("eth1"), "{os}");
        let snap = sim::socket(id).unwrap();
        assert_eq!(snap.sockopts.bind_device.as_deref(), Some("eth1"));
        if os == OsSemantics::Windows {
            assert_eq!(entry.bound_device, None, "IP_UNICAST_IF only steers sends");
            assert!(snap.sockopts.bind_device_send_only);
        } else {
            assert_eq!(entry.bound_device.as_deref(), Some("eth1"));
        }

        let unknown = SocketOptions {
            bind_device: Some("eth9".into()),
            ..opts()
        }
        .apply(&s)
        .unwrap_err();
        if os == OsSemantics::Linux {
            assert_eq!(os_error_code(&unknown), Some(19), "ENODEV");
        } else {
            assert_eq!(unknown.kind(), io::ErrorKind::NotFound);
        }
    }

    setup(Some(OsSemantics::Linux));
    set_privileges(|p| p.net_raw = false);
    let s = bind("0.0.0.0:0");
    let to = |dev: &str| SocketOptions {
        bind_device: Some(dev.into()),
        ..opts()
    };
    to("eth0")
        .apply(&s)
        .expect("Linux 5.7+ binds an unbound socket unprivileged");
    assert_eq!(
        code(to("eth1").apply(&s)),
        Some(1),
        "rebinding needs CAP_NET_RAW"
    );

    sim::set_sys_facts(|f| f.kernel = "5.4.0-150-generic #167-Ubuntu SMP".into());
    let s = bind("0.0.0.0:0");
    assert_eq!(
        code(to("eth0").apply(&s)),
        Some(1),
        "before 5.7 it always does"
    );
}

#[test]
fn priority_dscp_and_busy_poll() {
    setup(Some(OsSemantics::MacOs));
    let s = bind("10.0.0.1:7000");
    let busy = SocketOptions {
        busy_poll: Some(Duration::from_micros(50)),
        ..opts()
    };
    let e = busy.apply(&s).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    assert_eq!(e.to_string(), "busy polling not available on this platform");
    let e = SocketOptions {
        priority: Some(1),
        busy_poll_budget: Some(8),
        ..opts()
    }
    .apply(&s)
    .unwrap_err();
    assert_eq!(
        e.to_string(),
        "priority and busy polling not available on this platform"
    );

    setup(Some(OsSemantics::Windows));
    let s = bind("10.0.0.1:7000");
    let e = SocketOptions {
        dscp: Some(46),
        ..opts()
    }
    .apply(&s)
    .unwrap_err();
    assert_eq!(e.to_string(), "dscp not available on this platform");
    assert_eq!(
        code(
            SocketOptions {
                cpu_affinity: Some(1),
                ..opts()
            }
            .apply(&s)
        ),
        Some(10022),
        "SIO_CPU_AFFINITY needs an unbound socket"
    );

    setup(Some(OsSemantics::Linux));
    let s = bind("10.0.0.1:7000");
    let id = socket_id(&s);
    SocketOptions {
        dscp: Some(46),
        ..opts()
    }
    .apply(&s)
    .unwrap();
    let eff = sim::socket(id).unwrap().sockopts;
    assert_eq!(eff.tos, Some(184));
    assert_eq!(eff.priority, Some(4), "IP_TOS resets SO_PRIORITY");
    let bad = SocketOptions {
        dscp: Some(64),
        ..opts()
    }
    .apply(&s)
    .unwrap_err();
    assert_eq!(bad.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(bad.to_string(), "DSCP 64 is out of range 0-63");

    SocketOptions {
        priority: Some(6),
        busy_poll: Some(Duration::from_micros(50)),
        prefer_busy_poll: Some(true),
        busy_poll_budget: Some(64),
        dont_fragment: Some(true),
        ..opts()
    }
    .apply(&s)
    .unwrap();
    let eff = sim::socket(id).unwrap().sockopts;
    assert_eq!(eff.priority, Some(6));
    assert_eq!(eff.busy_poll, Duration::from_micros(50));
    assert!(eff.prefer_busy_poll && eff.dont_fragment);
    assert_eq!(eff.busy_poll_budget, 64);

    set_privileges(|p| {
        p.net_admin = false;
        p.net_raw = false;
    });
    let prio = |p| {
        SocketOptions {
            priority: Some(p),
            ..opts()
        }
        .apply(&s)
    };
    prio(3).unwrap();
    assert_eq!(code(prio(7)), Some(1), "SO_PRIORITY over 6");
    let poll = |us| {
        SocketOptions {
            busy_poll: Some(Duration::from_micros(us)),
            ..opts()
        }
        .apply(&s)
    };
    poll(20).expect("lowering needs nothing");
    assert_eq!(code(poll(100)), Some(1), "raising needs CAP_NET_ADMIN");
}

#[test]
fn dont_fragment_fails_sends_over_the_mtu() {
    for (os, want) in ALL.into_iter().zip([90, 40, 10040]) {
        setup(Some(os));
        let s = bind("10.0.0.1:7000");
        s.send_to(&[0u8; 1500], addr("10.0.0.9:9"))
            .expect("fragments without DF");
        SocketOptions {
            dont_fragment: Some(true),
            ..opts()
        }
        .apply(&s)
        .unwrap();
        s.send_to(&[0u8; 1472], addr("10.0.0.9:9")).unwrap();
        assert_eq!(
            code(s.send_to(&[0u8; 1473], addr("10.0.0.9:9"))),
            Some(want)
        );
    }
}

#[test]
fn apply_all_reports_skips_per_os() {
    let options = vec![
        SocketOption::RecvBuffer(65_536),
        SocketOption::LinuxPriority(3),
        SocketOption::WinCpuAffinity(0),
        SocketOption::Dscp(46),
        SocketOption::LinuxBusyPoll(50),
    ];
    #[cfg(feature = "fast-talker-pyo3")]
    let options = snare::fast_talker::py::SocketOptions(options).0;
    let rules = Rules {
        other_platform: Policy::Report,
        unsupported: Policy::Report,
        ..Rules::default()
    };

    setup(Some(OsSemantics::MacOs));
    let s = bind("10.0.0.1:7000");
    let report = SocketOption::apply_all(&s, &options, &rules).unwrap();
    assert_eq!(
        report.applied,
        [SocketOption::RecvBuffer(65_536), SocketOption::Dscp(46)]
    );
    let skipped: Vec<_> = report
        .skipped
        .iter()
        .map(|s| (s.option.clone(), s.reason.clone()))
        .collect();
    assert_eq!(
        skipped,
        [
            (
                SocketOption::LinuxPriority(3),
                Reason::OtherPlatform("Linux")
            ),
            (
                SocketOption::WinCpuAffinity(0),
                Reason::OtherPlatform("Windows")
            ),
            (
                SocketOption::LinuxBusyPoll(50),
                Reason::OtherPlatform("Linux")
            ),
        ]
    );
    let snap = sim::socket(socket_id(&s)).unwrap();
    assert_eq!(snap.options.recv_buffer, Some(65_536));
    assert_eq!(snap.sockopts.tos, Some(184));

    setup(Some(OsSemantics::Windows));
    let s = bind("10.0.0.1:7000");
    let report = SocketOption::apply_all(&s, &options[..1], &rules).unwrap();
    assert_eq!(report.applied, [SocketOption::RecvBuffer(65_536)]);
    let report = SocketOption::apply_all(&s, &options[3..4], &rules).unwrap();
    assert!(report.applied.is_empty());
    assert!(matches!(
        report.skipped[0].reason,
        Reason::Unsupported(ref why) if why == "dscp not available on this platform"
    ));

    setup(Some(OsSemantics::Linux));
    let s = bind("10.0.0.1:7000");
    let linux = [
        SocketOption::RecvBuffer(65_536),
        SocketOption::LinuxPriority(3),
        SocketOption::LinuxBusyPoll(50),
    ];
    let report = SocketOption::apply_all(&s, &linux, &Rules::default()).unwrap();
    assert_eq!(report.applied, linux);
    assert!(report.skipped.is_empty());
    let eff = sim::socket(socket_id(&s)).unwrap().sockopts;
    assert_eq!(eff.recv_buffer, Some(131_072));
    assert_eq!(eff.priority, Some(3));
}

#[test]
fn socket_table_lists_snare_sockets() {
    setup(Some(OsSemantics::Linux));
    let u = bind("10.0.0.1:7000");
    SocketOptions {
        bind_device: Some("eth0".into()),
        ..opts()
    }
    .apply(&u)
    .unwrap();
    let peer = bind("10.0.0.2:7001");
    peer.connect("10.0.0.1:7000").unwrap();
    peer.send(b"hello").unwrap();

    let udp = sockets::udp().unwrap();
    let find = |local: SocketAddr| {
        udp.iter()
            .find(|s| s.local == local)
            .copied()
            .unwrap_or_else(|| panic!("{local} listed"))
    };
    let s = find(addr("10.0.0.1:7000"));
    let id = socket_id(&u).get();
    assert_eq!(s.protocol, Protocol::Udp);
    assert_eq!(s.state, State::Close);
    assert_eq!(s.interface, Nic::open("eth0").unwrap().index());
    assert_eq!(s.cookie, Some(id));
    assert_eq!(s.inode, Some(id as u32));
    assert_eq!(s.uid, Some(0));
    assert_eq!(s.recv_queue, Some(5));
    assert_eq!(s.memory.unwrap().drops, Some(0));
    let p = find(addr("10.0.0.2:7001"));
    assert_eq!(p.state, State::Established);
    assert_eq!(p.remote, Some(addr("10.0.0.1:7000")));
    assert_eq!(p.interface, 0);

    let listener = TcpListener::bind("10.0.0.1:8000").unwrap();
    let client = TcpStream::connect("10.0.0.1:8000").unwrap();
    let tcp = sockets::tcp().unwrap();
    assert!(tcp.iter().all(|s| s.protocol == Protocol::Tcp));
    let l = tcp
        .iter()
        .find(|s| s.state == State::Listen)
        .expect("listener listed");
    assert_eq!(l.local, addr("10.0.0.1:8000"));
    assert_eq!(l.remote, None);
    assert_eq!(l.cookie, Some(socket_id(&listener).get()));
    let c = tcp
        .iter()
        .find(|s| s.cookie == Some(socket_id(&client).get()))
        .expect("client listed");
    assert_eq!(c.state, State::Established);
    assert_eq!(c.remote, Some(addr("10.0.0.1:8000")));

    setup(Some(OsSemantics::Windows));
    let u = bind("10.0.0.1:7000");
    u.connect("10.0.0.2:7001").unwrap();
    let s = sockets::udp().unwrap()[0];
    assert_eq!(s.pid, Some(std::process::id()));
    assert_eq!(
        (s.cookie, s.inode, s.memory, s.remote),
        (None, None, None, None)
    );
    assert_eq!(s.state, State::Close, "Windows can't tell connected UDP");

    setup(Some(OsSemantics::MacOs));
    set_privileges(|p| p.root = false);
    let u = bind("10.0.0.1:7000");
    let s = sockets::udp().unwrap()[0];
    assert_eq!(s.uid, Some(501));
    assert_eq!(s.cookie, Some(socket_id(&u).get()));
    assert_eq!(s.inode, None);
    assert_eq!(s.memory.unwrap().drops, None);
}

#[test]
fn multicast_memberships_and_delivery() {
    let group = ip("239.1.1.1");
    for os in [OsSemantics::Linux, OsSemantics::MacOs] {
        setup(Some(os));
        let tx = bind("10.0.0.1:4000");
        multicast::set_send_interface(&tx, "eth0").unwrap();
        let unjoined = bind("0.0.0.0:5000");
        let member = bind("0.0.0.0:6000");
        multicast::join(&member, group, "eth0").unwrap();

        tx.send_to(b"g", SocketAddr::new(group, 6000)).unwrap();
        let (data, from) = recv(&member).expect("member receives");
        assert_eq!((data.as_slice(), from), (&b"g"[..], addr("10.0.0.1:4000")));

        tx.send_to(b"all", SocketAddr::new(group, 5000)).unwrap();
        if os == OsSemantics::Linux {
            assert!(recv(&unjoined).is_some(), "IP_MULTICAST_ALL");
            multicast::only_joined(&unjoined, true).unwrap();
            tx.send_to(b"all", SocketAddr::new(group, 5000)).unwrap();
        }
        assert!(recv(&unjoined).is_none(), "{os}: joined-only");

        let entry = socket_entry(socket_id(&member)).unwrap();
        let want = Membership {
            group,
            source: None,
            nic: "eth0".into(),
        };
        assert_eq!(entry.memberships, std::slice::from_ref(&want));
        assert_eq!(sim::socket(socket_id(&member)).unwrap().memberships, [want]);
        assert!(nic_counters("eth0").unwrap().multicast >= 1);

        assert_eq!(
            code(multicast::join(&member, group, "eth0")),
            Some(if os == OsSemantics::Linux { 98 } else { 48 })
        );
        multicast::leave(&member, group, "eth0").unwrap();
        assert_eq!(
            code(multicast::leave(&member, group, "eth0")),
            Some(if os == OsSemantics::Linux { 99 } else { 49 })
        );
        tx.send_to(b"gone", SocketAddr::new(group, 6000)).unwrap();
        assert!(recv(&member).is_none(), "left");

        let e = multicast::join(&member, ip("10.0.0.5"), "").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let e = multicast::join(&member, group, "eth9").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }
}

#[test]
fn source_specific_membership_and_loopback() {
    setup(Some(OsSemantics::Linux));
    let ssm = ip("232.1.1.1");
    let from_eth0 = bind("10.0.0.1:4000");
    let from_eth1 = bind("10.0.0.2:4001");
    for tx in [&from_eth0, &from_eth1] {
        multicast::set_send_interface(tx, "eth0").unwrap();
    }
    let rx = bind("0.0.0.0:5003");
    multicast::join_source(&rx, ssm, ip("10.0.0.1"), "eth0").unwrap();
    from_eth1
        .send_to(b"other", SocketAddr::new(ssm, 5003))
        .unwrap();
    assert!(recv(&rx).is_none(), "another source is filtered");
    from_eth0
        .send_to(b"ok", SocketAddr::new(ssm, 5003))
        .unwrap();
    assert_eq!(recv(&rx).unwrap().0, b"ok");
    assert_eq!(
        socket_entry(socket_id(&rx)).unwrap().memberships[0].source,
        Some(ip("10.0.0.1"))
    );
    let e = multicast::join_source(&rx, ssm, ip("::1"), "eth0").unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    multicast::leave_source(&rx, ssm, ip("10.0.0.1"), "eth0").unwrap();
    assert!(socket_entry(socket_id(&rx)).unwrap().memberships.is_empty());

    let own = ip("239.1.1.2");
    let me = bind("0.0.0.0:5004");
    multicast::join(&me, own, "").unwrap();
    assert_eq!(
        socket_entry(socket_id(&me)).unwrap().memberships[0].nic,
        "snare0",
        "the default route's interface"
    );
    me.send_to(b"echo", SocketAddr::new(own, 5004)).unwrap();
    assert_eq!(recv(&me).unwrap().0, b"echo", "looped back");
    multicast::set_loopback(&me, false).unwrap();
    assert!(!me.multicast_loop_v4().unwrap());
    me.send_to(b"echo", SocketAddr::new(own, 5004)).unwrap();
    assert!(recv(&me).is_none());

    multicast::set_hops(&me, 8).unwrap();
    assert_eq!(me.multicast_ttl_v4().unwrap(), 8);
    assert_eq!(code(multicast::set_hops(&me, 256)), Some(22));
    let snap = sim::socket(socket_id(&me)).unwrap();
    assert_eq!(
        (snap.multicast_hops, snap.multicast_loop),
        (Some(8), Some(false))
    );

    let listener = TcpListener::bind("10.0.0.1:8000").unwrap();
    let stream = TcpStream::connect("10.0.0.1:8000").unwrap();
    assert_eq!(
        code(multicast::join(&stream, own, "")),
        Some(22),
        "a stream"
    );
    drop(listener);
}

#[test]
fn std_join_multicast_v4_shares_the_membership_table() {
    setup(Some(OsSemantics::Linux));
    add_route(Route::new(net("224.0.0.0/4"), "eth1")).unwrap();
    let group = Ipv4Addr::new(239, 2, 2, 2);
    let rx = bind("0.0.0.0:5000");
    assert!(rx.multicast_loop_v4().unwrap());
    assert_eq!(rx.multicast_ttl_v4().unwrap(), 1);
    rx.join_multicast_v4(&group, &Ipv4Addr::new(10, 0, 0, 2))
        .unwrap();
    assert_eq!(
        socket_entry(socket_id(&rx)).unwrap().memberships,
        [Membership {
            group: IpAddr::V4(group),
            source: None,
            nic: "eth1".into(),
        }]
    );
    let tx = bind("10.0.0.2:4000");
    tx.send_to(b"m", (group, 5000)).unwrap();
    assert_eq!(recv(&rx).unwrap().0, b"m");

    rx.leave_multicast_v4(&group, &Ipv4Addr::new(10, 0, 0, 2))
        .unwrap();
    tx.send_to(b"m", (group, 5000)).unwrap();
    assert!(recv(&rx).is_none());

    rx.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)
        .unwrap();
    assert_eq!(
        socket_entry(socket_id(&rx)).unwrap().memberships[0].nic,
        "eth1",
        "routing picks the interface for 0.0.0.0"
    );
    assert_eq!(
        code(rx.join_multicast_v4(&group, &Ipv4Addr::new(10, 9, 9, 9))),
        Some(19)
    );
    assert_eq!(
        code(rx.leave_multicast_v4(&Ipv4Addr::new(239, 9, 9, 9), &Ipv4Addr::UNSPECIFIED)),
        Some(99)
    );
    rx.join_multicast_v6(&"ff02::1".parse().unwrap(), 0)
        .unwrap();
}

#[test]
fn a_group_without_members_reaches_no_socket() {
    setup(Some(OsSemantics::Linux));
    let tx = bind("10.0.0.1:4000");
    let not_member = bind("0.0.0.0:5000");
    let before = nic_counters("eth0").unwrap().tx_packets;
    tx.send_to(b"x", "239.3.3.3:5000").unwrap();
    assert!(recv(&not_member).is_none());
    assert_eq!(
        nic_counters("eth0").unwrap().tx_packets,
        before + 1,
        "Linux sends out of the interface owning the bound address"
    );

    let wildcard = bind("0.0.0.0:0");
    let before = nic_counters("snare0").unwrap().tx_packets;
    wildcard.send_to(b"x", "239.3.3.3:5000").unwrap();
    assert_eq!(
        nic_counters("snare0").unwrap().tx_packets,
        before + 1,
        "an unbound sender follows the default route"
    );

    setup(Some(OsSemantics::MacOs));
    let tx = bind("10.0.0.1:4000");
    let before = nic_counters("snare0").unwrap().tx_packets;
    tx.send_to(b"x", "239.3.3.3:5000").unwrap();
    assert_eq!(
        nic_counters("snare0").unwrap().tx_packets,
        before + 1,
        "macOS routes multicast whatever the bound address"
    );
}

#[test]
fn only_joined_is_a_no_op_off_linux_and_on_streams() {
    let group = ip("239.4.4.4");
    for os in [OsSemantics::MacOs, OsSemantics::Windows] {
        setup(Some(os));
        let rx = bind("0.0.0.0:5000");
        multicast::only_joined(&rx, true).unwrap();
        let _listener = TcpListener::bind("10.0.0.1:8000").unwrap();
        let stream = TcpStream::connect("10.0.0.1:8000").unwrap();
        multicast::only_joined(&stream, true).unwrap();
    }

    setup(Some(OsSemantics::Linux));
    let _listener = TcpListener::bind("10.0.0.1:8000").unwrap();
    let stream = TcpStream::connect("10.0.0.1:8000").unwrap();
    multicast::only_joined(&stream, true).expect("IP_MULTICAST_ALL has no stream check");
    let member = bind("0.0.0.0:5001");
    multicast::join(&member, group, "eth0").unwrap();
    let rx = bind("0.0.0.0:5000");
    let tx = bind("10.0.0.1:4000");
    tx.send_to(b"a", SocketAddr::new(group, 5000)).unwrap();
    assert_eq!(recv(&rx).unwrap().0, b"a", "IP_MULTICAST_ALL");
    assert!(recv(&member).is_none(), "another port");
    multicast::only_joined(&rx, true).unwrap();
    tx.send_to(b"b", SocketAddr::new(group, 5000)).unwrap();
    assert!(recv(&rx).is_none());
}

#[test]
fn broadcast_needs_so_broadcast_and_reaches_the_segment() {
    for os in ALL {
        setup(Some(os));
        let tx = bind("10.0.0.1:4000");
        let rx = bind("0.0.0.0:6000");
        let unicast = bind("10.0.0.2:6001");
        let e = tx.send_to(b"b", "10.0.0.255:6000").unwrap_err();
        assert_eq!(
            os_error_code(&e),
            Some(if os == OsSemantics::Windows {
                10013
            } else {
                13
            })
        );
        tx.set_broadcast(true).unwrap();
        tx.send_to(b"b", "10.0.0.255:6000").unwrap();
        assert_eq!(recv(&rx).unwrap().0, b"b", "{os}");
        tx.send_to(b"b", "10.0.0.255:6001").unwrap();
        assert!(recv(&unicast).is_none(), "a unicast bind never sees it");
        tx.send_to(b"all", "255.255.255.255:6000").unwrap();
        assert_eq!(recv(&rx).unwrap().0, b"all");
    }

    setup(None);
    if snare::os_semantics_explicit() {
        return;
    }
    let tx = bind("10.0.0.1:4000");
    let rx = bind("0.0.0.0:6000");
    tx.send_to(b"legacy", "10.0.0.255:6000").unwrap();
    assert_eq!(recv(&rx).unwrap().0, b"legacy");
}

#[test]
fn v6_wildcard_takes_ipv4_per_os() {
    for os in ALL {
        setup(Some(os));
        let rx = bind("[::]:7000");
        let tx = bind("10.0.0.1:4000");
        tx.send_to(b"v4", "10.0.0.2:7000").unwrap();
        if os == OsSemantics::Windows {
            assert!(recv(&rx).is_none(), "IPV6_V6ONLY is on");
            continue;
        }
        let (data, from) = recv(&rx).expect("dual-stack");
        assert_eq!(data, b"v4");
        assert_eq!(from, addr("[::ffff:10.0.0.1]:4000"), "{os}");
        rx.send_to(b"back", from).unwrap();
        let (data, from) = recv(&tx).unwrap();
        assert_eq!(data, b"back");
        assert_eq!(from.port(), 7000);
        assert!(from.is_ipv4());
    }

    setup(None);
    if snare::os_semantics_explicit() {
        return;
    }
    let rx = bind("[::]:7000");
    let tx = bind("10.0.0.1:4000");
    tx.send_to(b"v4", "10.0.0.2:7000").unwrap();
    assert!(recv(&rx).is_none(), "legacy keeps families apart");
}

#[test]
fn binding_a_group_address() {
    setup(Some(OsSemantics::Windows));
    assert_eq!(code(UdpSocket::bind("239.1.1.1:5000")), Some(10049));
    for os in [OsSemantics::Linux, OsSemantics::MacOs] {
        setup(Some(os));
        let rx = bind("239.1.1.1:5000");
        multicast::join(&rx, ip("239.1.1.1"), "eth0").unwrap();
        let tx = bind("10.0.0.1:4000");
        multicast::set_send_interface(&tx, "eth0").unwrap();
        tx.send_to(b"g", "239.1.1.1:5000").unwrap();
        assert_eq!(recv(&rx).unwrap().0, b"g", "{os}");
    }
}

#[test]
fn incoming_cpu_follows_a_napi_pin() {
    setup(Some(OsSemantics::Linux));
    let rx = bind("10.0.0.1:7000");
    let tx = bind("10.0.0.2:4000");
    rx.connect("10.0.0.2:4000").unwrap();
    let id = socket_id(&rx);
    assert_eq!(sim::incoming_cpu(id).unwrap(), None, "nothing arrived yet");
    tx.send_to(b"x", "10.0.0.1:7000").unwrap();
    assert!(recv(&rx).is_some());
    let nic = Nic::open("eth0").unwrap();
    let napi = nic.napi_for_socket(&rx).unwrap().unwrap();
    napi.pin(&[3], Scheduler::Fifo(50)).unwrap();
    assert_eq!(sim::incoming_cpu(id).unwrap(), Some(3));
    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    assert_eq!(sockets::incoming_cpu(&rx).unwrap(), Some(3));

    setup(Some(OsSemantics::MacOs));
    let rx = bind("10.0.0.1:7000");
    let e = sim::incoming_cpu(socket_id(&rx)).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::Unsupported);
}

#[test]
fn a_raw_fd_style_buffer_setup_works_on_snare_sockets() {
    register_test();
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    let pkt = 9000usize;
    SocketOptions {
        recv_buffer: Some((256 * 1024).max(8 * pkt)),
        ..SocketOptions::default()
    }
    .apply(&sock)
    .expect("no EBADF: the option reaches snare, not setsockopt(-1)");
    let entry = socket_entry(socket_id(&sock)).unwrap();
    assert!(entry.rcvbuf.is_some_and(|n| n >= 256 * 1024));
    assert!(SocketMemory::of(&sock).unwrap().rcvbuf >= 256 * 1024);
}
