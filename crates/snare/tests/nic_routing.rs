//! The sim's interfaces and routes: the default topology, the open sim that claims whatever the
//! code under test binds, routed sims that only bind their own addresses, longest-prefix routing,
//! source selection, and which sockets a datagram or connection reaches.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};

use snare::{
    Fault, IpNet, NicSpec, RecordedEvent, Route, Sim, add_nic, remove_nic, route_lookup, routes,
    set_default_route,
};

#[cfg(unix)]
mod code {
    pub const EADDRNOTAVAIL: i32 = libc::EADDRNOTAVAIL;
    pub const ENETUNREACH: i32 = libc::ENETUNREACH;
    pub const EHOSTUNREACH: i32 = libc::EHOSTUNREACH;
    pub const EACCES: i32 = libc::EACCES;
    #[cfg(target_os = "linux")]
    pub const EINVAL: i32 = libc::EINVAL;
}

#[cfg(windows)]
mod code {
    pub const EADDRNOTAVAIL: i32 = 10049;
    pub const ENETUNREACH: i32 = 10051;
    pub const EHOSTUNREACH: i32 = 10065;
    pub const EACCES: i32 = 10013;
}

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn errno(e: std::io::Error) -> i32 {
    e.raw_os_error().expect("an OS error")
}

/// eth0 10.0.0.1/24 with stations .2 and .3, eth1 10.1.0.1/24 with station .2.
fn two_nics() -> Sim {
    Sim::builder()
        .nic(
            NicSpec::new("eth0")
                .index(4)
                .address(net("10.0.0.1/24"))
                .station(ip("10.0.0.2"))
                .station(ip("10.0.0.3")),
        )
        .nic(
            NicSpec::new("eth1")
                .index(5)
                .address(net("10.1.0.1/24"))
                .station(ip("10.1.0.2")),
        )
        .build()
}

fn try_recv(sock: &UdpSocket) -> Option<(Vec<u8>, SocketAddr)> {
    sock.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 64];
    match sock.recv_from(&mut buf) {
        Ok((n, from)) => Some((buf[..n].to_vec(), from)),
        Err(e) if e.kind() == ErrorKind::WouldBlock => None,
        Err(e) => panic!("recv failed: {e}"),
    }
}

#[test]
fn default_topology_has_lo_and_sim0() {
    let sim = Sim::new();
    let nics = sim.nics();
    assert_eq!(nics.len(), 2, "{nics:?}");
    let (lo, sim0) = (&nics[0], &nics[1]);
    let (name, mtu) = if cfg!(target_os = "linux") {
        ("lo", 65536)
    } else if cfg!(target_os = "macos") {
        ("lo0", 16384)
    } else {
        ("Loopback Pseudo-Interface 1", u32::MAX)
    };
    assert_eq!(
        (lo.index, lo.spec.name.as_str(), lo.spec.mtu),
        (1, name, mtu)
    );
    assert!(lo.loopback);
    assert_eq!(lo.spec.addresses, vec![net("127.0.0.1/8"), net("::1/128")]);
    assert_eq!((sim0.index, sim0.spec.name.as_str()), (2, "sim0"));
    assert!(sim0.spec.addresses.is_empty());
    assert!(sim0.spec.admin_up && sim0.spec.carrier);
    let defaults: Vec<_> = sim
        .routes()
        .into_iter()
        .filter(|r| r.dest.prefix == 0)
        .collect();
    assert_eq!(
        defaults,
        vec![
            Route::new(net("0.0.0.0/0"), "sim0").metric(100),
            Route::new(net("::/0"), "sim0").metric(100),
        ]
    );
}

#[test]
fn open_sim_auto_assigns_binds() {
    let sim = Sim::new();
    sim.run(|| {
        let sock = UdpSocket::bind("10.9.8.7:0").unwrap();
        assert_eq!(sock.local_addr().unwrap().ip(), ip("10.9.8.7"));
        let listener = TcpListener::bind("10.9.8.8:0").unwrap();
        assert_eq!(listener.local_addr().unwrap().ip(), ip("10.9.8.8"));
    });
    let sim0 = sim.nic("sim0").unwrap();
    assert!(sim0.spec.addresses.contains(&net("10.9.8.7/32")));
    assert!(sim0.spec.addresses.contains(&net("10.9.8.8/32")));
}

#[test]
fn flapping_sim0_keeps_the_sim_open() {
    let sim = Sim::new();
    sim.run(|| {
        UdpSocket::bind("10.9.8.7:0").unwrap();
        snare::set_link("sim0", false).unwrap();
        snare::set_link("sim0", true).unwrap();
        snare::set_nic("sim0", |spec| spec.mtu = 9000).unwrap();
        UdpSocket::bind("10.9.8.8:0").expect("still open after a flap");
    });
    assert!(
        sim.nic("sim0")
            .unwrap()
            .spec
            .addresses
            .contains(&net("10.9.8.8/32"))
    );
}

#[test]
fn routed_sim_rejects_unowned_bind() {
    two_nics().run(|| {
        UdpSocket::bind("10.0.0.1:0").unwrap();
        UdpSocket::bind("127.0.0.5:0").unwrap();
        UdpSocket::bind("10.0.0.2:0").expect("a station address binds");
        let err = UdpSocket::bind("10.0.0.9:0").unwrap_err();
        assert_eq!(errno(err), code::EADDRNOTAVAIL);
        let err = TcpListener::bind("192.168.7.1:0").unwrap_err();
        assert_eq!(errno(err), code::EADDRNOTAVAIL);
    });
}

#[test]
fn longest_prefix_then_owner_then_metric_then_order() {
    let sim = two_nics();
    sim.add_route(Route::new(net("10.1.0.128/25"), "eth0"))
        .unwrap();
    sim.add_route(Route::new(net("172.16.0.0/16"), "eth0").metric(10))
        .unwrap();
    sim.add_route(Route::new(net("172.16.0.0/16"), "eth1").metric(5))
        .unwrap();
    sim.add_route(Route::new(net("192.168.0.0/16"), "eth0").metric(1))
        .unwrap();
    sim.add_route(Route::new(net("192.168.0.0/16"), "eth1").metric(1))
        .unwrap();
    let lookup = |src: Option<&str>, dst: &str| {
        let choice = sim.route_lookup(src.map(ip), ip(dst)).unwrap();
        (choice.nic, choice.src.unwrap())
    };
    assert_eq!(lookup(None, "10.1.0.200"), ("eth0".into(), ip("10.0.0.1")));
    assert_eq!(lookup(None, "10.1.0.20"), ("eth1".into(), ip("10.1.0.1")));
    assert_eq!(lookup(None, "172.16.3.4"), ("eth1".into(), ip("10.1.0.1")));
    assert_eq!(lookup(None, "192.168.3.4"), ("eth0".into(), ip("10.0.0.1")));
    assert_eq!(
        lookup(Some("10.1.0.1"), "192.168.3.4"),
        ("eth1".into(), ip("10.1.0.1"))
    );
    assert_eq!(lookup(None, "8.8.8.8").0, "sim0");
    assert_eq!(lookup(None, "10.0.0.1").0, sim.nics()[0].spec.name);
}

#[test]
fn no_route_errno() {
    let sim = two_nics();
    sim.run(|| {
        set_default_route(None).unwrap();
        let wildcard = UdpSocket::bind("0.0.0.0:0").unwrap();
        let err = wildcard.send_to(b"x", "8.8.8.8:53").unwrap_err();
        assert_eq!(errno(err), code::ENETUNREACH);
        let bound = UdpSocket::bind("10.0.0.1:0").unwrap();
        let err = bound.send_to(b"x", "8.8.8.8:53").unwrap_err();
        let send = if cfg!(target_os = "macos") {
            code::EHOSTUNREACH
        } else {
            code::ENETUNREACH
        };
        assert_eq!(errno(err), send);
        let err = TcpStream::connect("8.8.8.8:53").unwrap_err();
        assert_eq!(errno(err), code::ENETUNREACH);
        assert_eq!(
            route_lookup(None, ip("8.8.8.8"))
                .unwrap_err()
                .raw_os_error(),
            Some(code::ENETUNREACH)
        );
    });
    let unreachable: Vec<_> = sim
        .recorded_events()
        .into_iter()
        .filter_map(|e| match e.event {
            RecordedEvent::Fault {
                fault: Fault::Unreachable { errno },
                ..
            } => Some(errno),
            _ => None,
        })
        .collect();
    assert_eq!(unreachable.len(), 3, "{unreachable:?}");
}

#[test]
fn wildcard_source_selection() {
    two_nics().run(|| {
        let station = UdpSocket::bind("10.1.0.2:7000").unwrap();
        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        let local = sock.local_addr().unwrap();
        assert!(local.ip().is_unspecified());
        sock.send_to(b"hi", "10.1.0.2:7000").unwrap();
        let (data, from) = try_recv(&station).expect("delivered");
        assert_eq!(data, b"hi");
        assert_eq!(from, SocketAddr::new(ip("10.1.0.1"), local.port()));
        assert!(sock.local_addr().unwrap().ip().is_unspecified());
    });
}

#[test]
fn tcp_client_source_is_route_src() {
    two_nics().run(|| {
        let listener = TcpListener::bind("10.0.0.2:9000").unwrap();
        let client = TcpStream::connect("10.0.0.2:9000").unwrap();
        let (_, peer) = listener.accept().unwrap();
        assert_eq!(client.local_addr().unwrap().ip(), ip("10.0.0.1"));
        assert_eq!(peer, client.local_addr().unwrap());
        let local = TcpStream::connect(listener.local_addr().unwrap());
        assert!(local.is_ok());
    });
}

#[cfg(unix)]
fn reuse_bind(ip: Ipv4Addr, port: u16) -> UdpSocket {
    use std::os::fd::FromRawFd;
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        assert!(fd >= 0);
        let one: libc::c_int = 1;
        let set = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&one as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        assert_eq!(set, 0);
        let mut sin: libc::sockaddr_in = std::mem::zeroed();
        #[cfg(target_os = "macos")]
        {
            sin.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_port = port.to_be();
        sin.sin_addr.s_addr = u32::from(ip).to_be();
        let bound = libc::bind(
            fd,
            (&sin as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        assert_eq!(bound, 0, "{}", std::io::Error::last_os_error());
        UdpSocket::from_raw_fd(fd)
    }
}

#[cfg(windows)]
fn reuse_bind(ip: Ipv4Addr, port: u16) -> UdpSocket {
    UdpSocket::bind((ip, port)).unwrap()
}

#[test]
fn exact_bind_beats_wildcard() {
    Sim::new().run(|| {
        let wildcard = reuse_bind(Ipv4Addr::UNSPECIFIED, 0);
        let port = wildcard.local_addr().unwrap().port();
        let exact = reuse_bind(Ipv4Addr::LOCALHOST, port);
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"one", ("127.0.0.1", port)).unwrap();
        assert_eq!(try_recv(&exact).unwrap().0, b"one");
        assert!(try_recv(&wildcard).is_none(), "only the exact bind gets it");
        sender.send_to(b"two", ("127.0.0.2", port)).unwrap();
        assert_eq!(try_recv(&wildcard).unwrap().0, b"two");
        assert!(try_recv(&exact).is_none());
    });
}

#[test]
fn station_traffic_never_hits_host_wildcard() {
    two_nics().run(|| {
        let host = UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = host.local_addr().unwrap().port();
        let station = UdpSocket::bind("10.0.0.2:0").unwrap();
        station.send_to(b"elsewhere", ("10.0.0.3", port)).unwrap();
        assert!(try_recv(&host).is_none());
        station.send_to(b"mine", ("10.0.0.1", port)).unwrap();
        let (data, from) = try_recv(&host).unwrap();
        assert_eq!(data, b"mine");
        assert_eq!(from, station.local_addr().unwrap());
    });
}

#[test]
fn loopback_source_off_host() {
    two_nics().run(|| {
        let _station = UdpSocket::bind("10.0.0.2:7100").unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let err = sock.send_to(b"x", "10.0.0.2:7100").unwrap_err();
        #[cfg(target_os = "linux")]
        assert_eq!(errno(err), code::EINVAL);
        #[cfg(target_os = "macos")]
        assert_eq!(errno(err), code::EADDRNOTAVAIL);
        #[cfg(windows)]
        assert_eq!(errno(err), code::ENETUNREACH);
    });
}

#[test]
fn windows_strong_host_send_and_receive() {
    two_nics().run(|| {
        let station = UdpSocket::bind("10.0.0.2:7200").unwrap();
        let sock = UdpSocket::bind("10.1.0.1:0").unwrap();
        let sent = sock.send_to(b"cross", "10.0.0.2:7200");
        if cfg!(windows) {
            assert_eq!(errno(sent.unwrap_err()), code::ENETUNREACH);
            assert!(try_recv(&station).is_none());
        } else {
            sent.unwrap();
            let (_, from) = try_recv(&station).unwrap();
            assert_eq!(from, sock.local_addr().unwrap());
        }
        station.send_to(b"in", sock.local_addr().unwrap()).unwrap();
        let got = try_recv(&sock);
        if cfg!(windows) {
            assert!(got.is_none(), "strong host drops it on the wrong interface");
        } else {
            assert_eq!(got.unwrap().0, b"in");
        }
    });
}

#[test]
fn directed_broadcast_reaches_segment() {
    two_nics().run(|| {
        let a = UdpSocket::bind("10.0.0.2:0").unwrap();
        let port = a.local_addr().unwrap().port();
        let b = UdpSocket::bind(("10.0.0.3", port)).unwrap();
        let other = UdpSocket::bind(("10.1.0.2", port)).unwrap();
        let host = UdpSocket::bind(("0.0.0.0", port)).unwrap();
        let sender = UdpSocket::bind("10.0.0.1:0").unwrap();
        let err = sender.send_to(b"x", ("10.0.0.255", port)).unwrap_err();
        assert_eq!(errno(err), code::EACCES);
        sender.set_broadcast(true).unwrap();
        sender.send_to(b"all", ("10.0.0.255", port)).unwrap();
        assert_eq!(try_recv(&a).unwrap().0, b"all");
        assert_eq!(try_recv(&b).unwrap().0, b"all");
        assert_eq!(try_recv(&host).unwrap().0, b"all");
        assert!(try_recv(&other).is_none(), "another segment");
    });
}

#[test]
fn wildcard_listener_accepts_host_addresses_only() {
    two_nics().run(|| {
        let listener = TcpListener::bind("0.0.0.0:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        TcpStream::connect(("10.0.0.1", port)).unwrap();
        TcpStream::connect(("127.0.0.1", port)).unwrap();
        let err = TcpStream::connect(("10.0.0.2", port)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
    });
}

#[test]
fn remove_nic_drops_routes_and_addresses() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("eth1").address(net("10.5.0.1/24"))).unwrap();
        assert_eq!(route_lookup(None, ip("10.5.0.9")).unwrap().nic, "eth1");
        UdpSocket::bind("10.5.0.1:0").unwrap();
        remove_nic("eth1").unwrap();
        assert!(routes().iter().all(|r| r.nic != "eth1"));
        assert_eq!(route_lookup(None, ip("10.5.0.9")).unwrap().nic, "sim0");
        let err = UdpSocket::bind("10.5.0.1:0").unwrap_err();
        assert_eq!(errno(err), code::EADDRNOTAVAIL);
        let lo = snare::nics()[0].spec.name.clone();
        assert!(remove_nic(&lo).is_err());
        assert!(remove_nic("eth1").is_err());
    });
}

#[test]
fn ipnet_parses_and_matches() {
    let n = net("10.0.0.77/24");
    assert_eq!(n.network(), ip("10.0.0.0"));
    assert_eq!(n.broadcast(), Some(ip("10.0.0.255")));
    assert!(n.contains(ip("10.0.0.200")) && !n.contains(ip("10.0.1.1")));
    assert_eq!(net("10.0.0.1"), IpNet::host(ip("10.0.0.1")));
    assert_eq!(net("fe80::1/64").network(), ip("fe80::"));
    assert!(net("0.0.0.0/0").contains(ip("8.8.8.8")));
    assert!("10.0.0.1/33".parse::<IpNet>().is_err());
    assert_eq!(n.to_string(), "10.0.0.77/24");
}
