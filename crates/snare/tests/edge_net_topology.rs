//! Topology edge cases pinned exactly: route ties (longest prefix, then the bound address's
//! interface, then the lowest metric, then the earliest route, connected subnets before explicit
//! routes, down interfaces skipped) agree between `route_lookup` and where a real send leaves;
//! carrier and admin flaps in the middle of a TCP stream and a datagram burst, with the interface
//! counters they leave; binding to a device from the test; the strong or weak host of the build
//! OS; don't-fragment `EMSGSIZE` at exactly payload + 28 (IPv4) / + 48 (IPv6) past the MTU, after
//! an MTU change too; raw L2 frames at exactly MTU + 14; and every counter of eth0 after a fixed
//! mixed scenario.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};

use snare::{
    IpNet, NicSpec, Route, Sim, nic_counters, remove_route, route_lookup, set_link, set_nic,
    set_socket_device, socket_entry, socket_id,
};

#[cfg(unix)]
mod code {
    pub const ENETUNREACH: i32 = libc::ENETUNREACH;
}

#[cfg(windows)]
mod code {
    pub const ENETUNREACH: i32 = 10051;
}

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// eth0 10.0.0.1/24 + fd00::1/64 (index 4), eth1 10.1.0.1/24 + fd01::1/64 (index 5), eth2
/// 10.2.0.1/24 (index 6), each with station .2 (and ::2).
fn three_nics() -> Sim {
    Sim::builder()
        .nic(
            NicSpec::new("eth0")
                .index(4)
                .address(net("10.0.0.1/24"))
                .address(net("fd00::1/64"))
                .station(ip("10.0.0.2"))
                .station(ip("fd00::2")),
        )
        .nic(
            NicSpec::new("eth1")
                .index(5)
                .address(net("10.1.0.1/24"))
                .address(net("fd01::1/64"))
                .station(ip("10.1.0.2"))
                .station(ip("fd01::2")),
        )
        .nic(
            NicSpec::new("eth2")
                .index(6)
                .address(net("10.2.0.1/24"))
                .station(ip("10.2.0.2")),
        )
        .build()
}

fn try_recv(sock: &UdpSocket) -> Option<Vec<u8>> {
    sock.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 64];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => Some(buf[..n].to_vec()),
        Err(e) if e.kind() == ErrorKind::WouldBlock => None,
        Err(e) => panic!("recv failed: {e}"),
    }
}

fn try_read(stream: &mut TcpStream) -> Option<Vec<u8>> {
    stream.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 4096];
    match stream.read(&mut buf) {
        Ok(n) => Some(buf[..n].to_vec()),
        Err(e) if e.kind() == ErrorKind::WouldBlock => None,
        Err(e) => panic!("read failed: {e}"),
    }
}

/// `route_lookup`'s answer as `nic src`, or the errno.
fn lookup(src: Option<&str>, dst: &str) -> String {
    match route_lookup(src.map(ip), ip(dst)) {
        Ok(c) => format!("{} {}", c.nic, c.src.unwrap()),
        Err(e) => format!("errno {}", e.raw_os_error().unwrap()),
    }
}

/// The interface a datagram from a socket bound at `from` to `dst` leaves through, or the errno.
fn sent_via(from: &str, dst: &str) -> String {
    let sock = UdpSocket::bind(from).unwrap();
    match sock.send_to(b"r", dst) {
        Ok(_) => socket_entry(socket_id(&sock).unwrap())
            .unwrap()
            .last_tx_nic
            .unwrap_or_default(),
        Err(e) => format!("errno {}", e.raw_os_error().unwrap()),
    }
}

#[test]
fn route_ties_resolve_exactly() {
    let sim = three_nics();
    for route in [
        Route::new(net("172.16.0.0/16"), "eth0").metric(5),
        Route::new(net("172.16.0.0/16"), "eth1").metric(5),
        Route::new(net("172.17.0.0/16"), "eth1").metric(7),
        Route::new(net("172.17.0.0/16"), "eth0").metric(3),
        Route::new(net("172.18.0.0/16"), "eth0").metric(1),
        Route::new(net("172.18.0.0/16"), "eth1").metric(9),
        Route::new(net("10.1.0.0/24"), "eth0"),
        Route::new(net("10.1.0.7/32"), "eth2"),
        Route::new(net("172.19.0.0/16"), "eth2").src(ip("10.0.0.1")),
        Route::new(net("fd10::/32"), "eth0").metric(5),
        Route::new(net("fd10::/32"), "eth1").metric(5),
        Route::new(net("fd10:1::/48"), "eth1").metric(50),
    ] {
        sim.add_route(route).unwrap();
    }
    sim.run(|| {
        let weak = !cfg!(windows);
        let table = [
            (None, "172.16.1.1", "eth0 10.0.0.1"),
            (None, "172.17.1.1", "eth0 10.0.0.1"),
            (None, "172.18.1.1", "eth0 10.0.0.1"),
            (Some("10.1.0.1"), "172.18.1.1", "eth1 10.1.0.1"),
            (Some("10.1.0.1"), "172.16.1.1", "eth1 10.1.0.1"),
            (
                Some("10.2.0.1"),
                "172.16.1.1",
                if weak { "eth0 10.2.0.1" } else { "errno 10051" },
            ),
            (None, "10.1.0.9", "eth1 10.1.0.1"),
            (None, "10.1.0.7", "eth2 10.2.0.1"),
            (None, "172.19.0.1", "eth2 10.0.0.1"),
            (None, "fd10::9", "eth0 fd00::1"),
            (None, "fd10:1::9", "eth1 fd01::1"),
            (Some("fd01::1"), "fd10::9", "eth1 fd01::1"),
            (None, "8.8.8.8", "sim0 10.0.0.1"),
        ];
        for (src, dst, want) in table {
            assert_eq!(lookup(src, dst), want, "lookup {src:?} -> {dst}");
            let from = match (src, dst.contains(':')) {
                (Some(s), true) => format!("[{s}]:0"),
                (Some(s), false) => format!("{s}:0"),
                (None, true) => "[::]:0".to_string(),
                (None, false) => "0.0.0.0:0".to_string(),
            };
            let dst = if dst.contains(':') {
                format!("[{dst}]:9")
            } else {
                format!("{dst}:9")
            };
            let nic = want.split(' ').next().unwrap();
            let want_send = if nic == "errno" {
                format!("errno {}", code::ENETUNREACH)
            } else {
                nic.to_string()
            };
            assert_eq!(sent_via(&from, &dst), want_send, "send {from} -> {dst}");
        }

        set_link("eth0", false).unwrap();
        let want = if weak {
            "eth0 10.0.0.1"
        } else {
            "eth1 10.1.0.1"
        };
        assert_eq!(
            lookup(None, "172.16.1.1"),
            want,
            "carrier down keeps routes on unix"
        );
        set_link("eth0", true).unwrap();
        set_nic("eth0", |s| s.admin_up = false).unwrap();
        assert_eq!(
            lookup(None, "172.16.1.1"),
            "eth1 10.1.0.1",
            "admin down withdraws them"
        );
        assert_eq!(lookup(None, "172.17.1.1"), "eth1 10.1.0.1");
        set_nic("eth0", |s| s.admin_up = true).unwrap();
        assert_eq!(lookup(None, "172.16.1.1"), "eth0 10.0.0.1");

        assert!(
            remove_route(net("172.16.0.0/16")),
            "removes every route to the prefix"
        );
        assert!(!remove_route(net("172.16.0.0/16")));
        assert_eq!(lookup(None, "172.16.1.1"), "sim0 10.0.0.1");
        assert!(remove_route(net("10.1.0.7/32")));
        assert_eq!(lookup(None, "10.1.0.7"), "eth1 10.1.0.1");
    });
}

/// A connection from the host to a station listener across eth0 (MTU 1500): what is written
/// while carrier is down waits and lands in order once it returns, across an admin flap too.
/// eth0 counts a write as segments of payload + 54 only if the link is up when it is written:
/// bytes that stalled and crossed later are never counted.
#[test]
fn tcp_across_flaps_keeps_order_and_counts() {
    three_nics().run(|| {
        let listener = TcpListener::bind("10.0.0.2:9400").unwrap();
        let mut client = TcpStream::connect("10.0.0.2:9400").unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let base = nic_counters("eth0").unwrap();
        client.write_all(b"one").unwrap();
        assert_eq!(try_read(&mut server).unwrap(), b"one");
        set_link("eth0", false).unwrap();
        client.write_all(b"two").unwrap();
        client.write_all(&[b'x'; 2000]).unwrap();
        assert_eq!(try_read(&mut server), None, "held on the link");
        set_link("eth0", true).unwrap();
        let mut got = Vec::new();
        while let Some(chunk) = try_read(&mut server) {
            got.extend(chunk);
        }
        assert_eq!(got.len(), 2003);
        assert_eq!(&got[..3], b"two");
        set_nic("eth0", |s| s.admin_up = false).unwrap();
        client.write_all(b"three").unwrap();
        assert_eq!(try_read(&mut server), None);
        set_nic("eth0", |s| s.admin_up = true).unwrap();
        assert_eq!(try_read(&mut server).unwrap(), b"three");
        server.write_all(b"back").unwrap();
        assert_eq!(try_read(&mut client).unwrap(), b"back");
        let c = nic_counters("eth0").unwrap();
        let tx = (c.tx_packets - base.tx_packets, c.tx_bytes - base.tx_bytes);
        let rx = (c.rx_packets - base.rx_packets, c.rx_bytes - base.rx_bytes);
        assert_eq!(tx, (1, 3 + 54));
        assert_eq!(rx, (1, 4 + 54));
        assert_eq!((c.tx_dropped, c.tx_carrier_errors, c.rx_dropped), (0, 0, 0));
    });
}

/// Ten datagrams each way while eth0 has no carrier: on Linux and macOS each send succeeds and is
/// counted dropped and a carrier error, each inbound one is an rx drop; Windows withdraws the route
/// and fails the sends. After the link returns one datagram each way lands and counts.
#[test]
fn udp_burst_across_a_carrier_flap_counts_exactly() {
    three_nics().run(|| {
        let host = UdpSocket::bind("10.0.0.1:7100").unwrap();
        let station = UdpSocket::bind("10.0.0.2:7100").unwrap();
        set_link("eth0", false).unwrap();
        let mut failed = 0;
        for i in 0..10u8 {
            if host.send_to(&[i; 20], "10.0.0.2:7100").is_err() {
                failed += 1;
            }
            station.send_to(&[i; 30], "10.0.0.1:7100").unwrap();
        }
        assert_eq!(try_recv(&station), None);
        assert_eq!(try_recv(&host), None);
        let c = nic_counters("eth0").unwrap();
        if cfg!(windows) {
            assert_eq!(failed, 10);
            assert_eq!((c.tx_dropped, c.tx_carrier_errors), (0, 0));
        } else {
            assert_eq!(failed, 0);
            assert_eq!((c.tx_dropped, c.tx_carrier_errors), (10, 10));
        }
        assert_eq!((c.tx_packets, c.rx_packets, c.rx_dropped), (0, 0, 10));
        set_link("eth0", true).unwrap();
        host.send_to(&[1; 20], "10.0.0.2:7100").unwrap();
        station.send_to(&[2; 30], "10.0.0.1:7100").unwrap();
        assert_eq!(try_recv(&station).unwrap(), [1; 20]);
        assert_eq!(try_recv(&host).unwrap(), [2; 30]);
        let c = nic_counters("eth0").unwrap();
        assert_eq!(
            (c.tx_packets, c.tx_bytes, c.rx_packets, c.rx_bytes),
            (1, 62, 1, 72)
        );
    });
}

/// A wildcard socket put on eth1 by the test sends there even toward eth0's subnet (Linux assumes
/// the destination on-link; macOS's scoped lookup misses with `ENETUNREACH`; Windows' unicast
/// interface follows its routes). Windows leaves reception on both interfaces enabled;
/// Unix filters to eth1. Unbinding restores routing and reception.
#[test]
fn bound_device_steers_and_filters() {
    three_nics().run(|| {
        let sock = UdpSocket::bind("0.0.0.0:7500").unwrap();
        let id = socket_id(&sock).unwrap();
        let s0 = UdpSocket::bind("10.0.0.2:7500").unwrap();
        let s1 = UdpSocket::bind("10.1.0.2:7500").unwrap();
        set_socket_device(id, Some("eth1")).unwrap();
        let sent = sock.send_to(b"a", "10.0.0.2:7500");
        if cfg!(target_os = "linux") {
            sent.unwrap();
            assert_eq!(
                socket_entry(id).unwrap().last_tx_nic.as_deref(),
                Some("eth1")
            );
        } else if cfg!(target_os = "macos") {
            assert_eq!(sent.unwrap_err().raw_os_error(), Some(code::ENETUNREACH));
        } else {
            sent.unwrap();
        }
        sock.send_to(b"b", "10.1.0.2:7500").unwrap();
        assert_eq!(try_recv(&s1).unwrap(), b"b");
        s0.send_to(b"via eth0", "10.0.0.1:7500").unwrap();
        s1.send_to(b"via eth1", "10.1.0.1:7500").unwrap();
        if cfg!(windows) {
            assert_eq!(try_recv(&sock).unwrap(), b"via eth0");
            assert_eq!(try_recv(&sock).unwrap(), b"via eth1");
            assert_eq!(try_recv(&sock), None);
        } else {
            assert_eq!(try_recv(&sock).unwrap(), b"via eth1");
            assert_eq!(
                try_recv(&sock),
                None,
                "eth0's datagram never reached the bound socket"
            );
        }
        set_socket_device(id, None).unwrap();
        s0.send_to(b"again", "10.0.0.1:7500").unwrap();
        assert_eq!(try_recv(&sock).unwrap(), b"again");
        sock.send_to(b"c", "10.0.0.2:7500").unwrap();
        assert_eq!(
            socket_entry(id).unwrap().last_tx_nic.as_deref(),
            Some("eth0")
        );
    });
}

/// eth1's station sends to eth0's address: Linux and macOS (weak host) take it, arriving on eth1;
/// Windows (strong host) does not. A socket bound to eth0's address sending to eth1's station
/// leaves through eth1 on the weak hosts and fails `WSAENETUNREACH` on Windows.
#[test]
fn strong_or_weak_host_exactly() {
    three_nics().run(|| {
        let host = UdpSocket::bind("10.0.0.1:7600").unwrap();
        let s1 = UdpSocket::bind("10.1.0.2:7600").unwrap();
        s1.send_to(b"cross", "10.0.0.1:7600").unwrap();
        let got = try_recv(&host);
        let sent = host.send_to(b"out", "10.1.0.2:7600");
        let entry = socket_entry(socket_id(&host).unwrap()).unwrap();
        if cfg!(windows) {
            assert_eq!(got, None);
            assert_eq!(sent.unwrap_err().raw_os_error(), Some(code::ENETUNREACH));
        } else {
            assert_eq!(got.unwrap(), b"cross");
            assert_eq!(entry.last_rx_nic.as_deref(), Some("eth1"));
            sent.unwrap();
            assert_eq!(
                socket_entry(entry.id).unwrap().last_tx_nic.as_deref(),
                Some("eth1")
            );
            assert_eq!(try_recv(&s1).unwrap(), b"out");
        }
    });
}

#[cfg(unix)]
mod df {
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    #[cfg(target_os = "linux")]
    const DF4: (i32, i32, i32) = (libc::IPPROTO_IP, 10, libc::IP_PMTUDISC_DO);
    #[cfg(target_os = "macos")]
    const DF4: (i32, i32, i32) = (libc::IPPROTO_IP, 28, 1);
    const DF6: (i32, i32, i32) = (libc::IPPROTO_IPV6, 62, 1);

    fn set(s: &UdpSocket, (level, name, value): (i32, i32, i32)) {
        let rc =
            unsafe { libc::setsockopt(s.as_raw_fd(), level, name, (&raw const value).cast(), 4) };
        assert_eq!(rc, 0, "setsockopt");
    }

    pub fn on(s: &UdpSocket, v6: bool) {
        set(s, if v6 { DF6 } else { DF4 });
        big_sndbuf(s);
    }

    pub fn big_sndbuf(s: &UdpSocket) {
        let big: i32 = 1 << 17;
        let rc = unsafe {
            libc::setsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const big).cast(),
                4,
            )
        };
        assert_eq!(rc, 0);
    }

    /// The errno of a `len`-byte send to `to`, or 0.
    pub fn send(s: &UdpSocket, len: usize, to: &str) -> i32 {
        match s.send_to(&vec![3u8; len], to) {
            Ok(n) => {
                assert_eq!(n, len);
                0
            }
            Err(e) => e.raw_os_error().unwrap(),
        }
    }
}

/// Don't-fragment boundaries at several MTUs on eth0, IPv4 (payload + 28) and IPv6 (payload +
/// 48), the limit following an MTU change at once, and a datagram past the MTU without
/// don't-fragment delivered whole.
#[cfg(unix)]
#[test]
fn dont_fragment_boundaries_are_exact() {
    three_nics().run(|| {
        let v4 = UdpSocket::bind("10.0.0.1:0").unwrap();
        let v6 = UdpSocket::bind("[fd00::1]:0").unwrap();
        let plain = UdpSocket::bind("10.0.0.1:0").unwrap();
        df::big_sndbuf(&plain);
        let rx4 = UdpSocket::bind("10.0.0.2:7700").unwrap();
        let rx6 = UdpSocket::bind("[fd00::2]:7700").unwrap();
        df::on(&v4, false);
        df::on(&v6, true);
        let emsgsize = libc::EMSGSIZE;
        for mtu in [576u32, 1280, 1500, 9000] {
            set_nic("eth0", |s| s.mtu = mtu).unwrap();
            let m = mtu as usize;
            assert_eq!(df::send(&v4, m - 28, "10.0.0.2:7700"), 0, "v4 at mtu {mtu}");
            assert_eq!(
                df::send(&v4, m - 27, "10.0.0.2:7700"),
                emsgsize,
                "v4 past mtu {mtu}"
            );
            assert_eq!(
                df::send(&v6, m - 48, "[fd00::2]:7700"),
                0,
                "v6 at mtu {mtu}"
            );
            assert_eq!(
                df::send(&v6, m - 47, "[fd00::2]:7700"),
                emsgsize,
                "v6 past mtu {mtu}"
            );
            assert_eq!(
                df::send(&plain, m + 100, "10.0.0.2:7700"),
                0,
                "no DF at mtu {mtu}"
            );
        }
        rx4.set_nonblocking(true).unwrap();
        rx6.set_nonblocking(true).unwrap();
        let mut buf = vec![0u8; 10_000];
        let mut sizes4 = Vec::new();
        while let Ok((n, _)) = rx4.recv_from(&mut buf) {
            sizes4.push(n);
        }
        let mut sizes6 = Vec::new();
        while let Ok((n, _)) = rx6.recv_from(&mut buf) {
            sizes6.push(n);
        }
        assert_eq!(sizes4, [548, 676, 1252, 1380, 1472, 1600, 8972, 9100]);
        assert_eq!(sizes6, [528, 1232, 1452, 8952]);
        let c = nic_counters("eth0").unwrap();
        assert_eq!(c.tx_packets, 12, "a refused send counts nowhere");
        assert_eq!((c.tx_dropped, c.tx_errors), (0, 0));
    });
}

#[cfg(target_os = "linux")]
mod raw {
    pub fn open_on(index: i32) -> i32 {
        unsafe {
            let fd = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                i32::from(0x88A4u16.to_be()),
            );
            assert!(fd >= 0);
            let mut sll: libc::sockaddr_ll = std::mem::zeroed();
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_ifindex = index;
            let rc = libc::bind(
                fd,
                (&sll as *const libc::sockaddr_ll).cast(),
                size_of::<libc::sockaddr_ll>() as u32,
            );
            assert_eq!(rc, 0);
            fd
        }
    }
}

#[cfg(target_os = "macos")]
mod raw {
    const BIOCSETIF: libc::c_ulong = 0x8020_426c;

    pub fn open_on(_index: i32) -> i32 {
        let path = std::ffi::CString::new("/dev/bpf0").unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
        assert!(fd >= 0);
        let mut ifr = [0u8; 32];
        ifr[..4].copy_from_slice(b"eth0");
        assert_eq!(unsafe { libc::ioctl(fd, BIOCSETIF, ifr.as_mut_ptr()) }, 0);
        fd
    }
}

/// A raw L2 frame of exactly MTU + 14 bytes goes and counts; one byte more is `EMSGSIZE` and
/// counts nowhere, at the default 1500 and after the MTU drops to 1000.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn raw_frame_mtu_boundary_is_exact() {
    three_nics().run(|| {
        let fd = raw::open_on(4);
        let frame = vec![0u8; 9100];
        let write = |len: usize| {
            let n = unsafe { libc::write(fd, frame.as_ptr().cast(), len) };
            if n < 0 {
                -std::io::Error::last_os_error().raw_os_error().unwrap() as isize
            } else {
                n
            }
        };
        let e = libc::EMSGSIZE as isize;
        assert_eq!(write(1514), 1514);
        assert_eq!(write(1515), -e);
        set_nic("eth0", |s| s.mtu = 1000).unwrap();
        assert_eq!(write(1014), 1014);
        assert_eq!(write(1015), -e);
        assert_eq!(write(60), 60);
        let c = nic_counters("eth0").unwrap();
        assert_eq!(
            (c.tx_packets, c.tx_bytes, c.tx_errors),
            (3, 1514 + 1014 + 60, 0)
        );
        unsafe { libc::close(fd) };
    });
}

/// Every counter of eth0 after a fixed mix: three host-to-station datagrams (10, 100, 1000
/// bytes), two back (5, 50), a multicast to a group a host socket joined, a TCP connection to a
/// station with a 3000-byte write (MTU 1500: segments of 1460, 1460 and 80) and a 7-byte reply,
/// and one datagram sent while eth0 had no carrier.
#[test]
fn eth0_counters_after_a_fixed_scenario() {
    let sim = three_nics();
    sim.run(|| {
        let host = UdpSocket::bind("10.0.0.1:7800").unwrap();
        let station = UdpSocket::bind("10.0.0.2:7800").unwrap();
        for len in [10, 100, 1000] {
            host.send_to(&vec![1u8; len], "10.0.0.2:7800").unwrap();
        }
        for len in [5, 50] {
            station.send_to(&vec![2u8; len], "10.0.0.1:7800").unwrap();
        }
        let group: std::net::Ipv4Addr = "239.9.9.9".parse().unwrap();
        let member = UdpSocket::bind("0.0.0.0:7801").unwrap();
        member
            .join_multicast_v4(&group, &"10.0.0.1".parse().unwrap())
            .unwrap();
        station.send_to(b"mcast", (group, 7801)).unwrap();
        let listener = TcpListener::bind("10.0.0.2:7802").unwrap();
        let mut client = TcpStream::connect("10.0.0.2:7802").unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(&[7u8; 3000]).unwrap();
        let mut buf = [0u8; 3000];
        server.read_exact(&mut buf).unwrap();
        server.write_all(b"thanks!").unwrap();
        client.read_exact(&mut buf[..7]).unwrap();
        set_link("eth0", false).unwrap();
        let _ = host.send_to(b"gone", "10.0.0.2:7800");
        set_link("eth0", true).unwrap();
    });
    let c = sim.nic_counters("eth0").unwrap();
    let tx_udp = (10 + 42) + (100 + 42) + (1000 + 42);
    let tx_tcp = (1460 + 54) * 2 + (80 + 54);
    let rx_udp = (5 + 42) + (50 + 42) + (5 + 42);
    let rx_tcp = 7 + 54;
    let carrier_lost = if cfg!(windows) { 0 } else { 1 };
    assert_eq!(
        c,
        snare::NicCounters {
            tx_packets: 6,
            tx_bytes: (tx_udp + tx_tcp) as u64,
            rx_packets: 4,
            rx_bytes: (rx_udp + rx_tcp) as u64,
            multicast: 1,
            tx_dropped: carrier_lost,
            tx_carrier_errors: carrier_lost,
            ..Default::default()
        }
    );
}
