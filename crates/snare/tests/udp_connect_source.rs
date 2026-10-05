//! A UDP socket bound to the wildcard address takes the route's source address when it connects,
//! as every host does (Linux `ip4_datagram_connect`/`ip6_datagram_dst_update`, macOS
//! `in_pcbconnect`, Winsock), and receives only there while connected. Dissolving the association
//! (`connect` to an `AF_UNSPEC` address) follows each host: Linux returns the address to the
//! wildcard unless `bind` named one and gives up a port `bind` did not name; macOS returns the
//! address to the wildcard, keeps the port and fails with `EAFNOSUPPORT`; Windows returns it to
//! what `bind` named and keeps the port. `connect_source_os_truth` compares the sim with the real
//! stack over loopback; the rest route through simulated interfaces.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use snare::{IpNet, NicSpec, Route, Sim};

#[cfg(unix)]
mod os {
    use std::net::UdpSocket;
    use std::os::fd::{AsRawFd, FromRawFd};

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    }

    /// A socket of `v6`'s family that was never bound.
    pub fn unbound(v6: bool) -> UdpSocket {
        let family = if v6 { libc::AF_INET6 } else { libc::AF_INET };
        let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
        assert!(fd >= 0);
        unsafe { UdpSocket::from_raw_fd(fd) }
    }

    /// `connect` to an `AF_UNSPEC` address.
    pub fn disconnect(s: &UdpSocket) -> Result<(), i32> {
        let mut addr: libc::sockaddr = unsafe { std::mem::zeroed() };
        addr.sa_family = libc::AF_UNSPEC as libc::sa_family_t;
        let len = size_of::<libc::sockaddr>() as libc::socklen_t;
        let rc = unsafe { libc::connect(s.as_raw_fd(), &addr, len) };
        if rc == 0 { Ok(()) } else { Err(errno()) }
    }
}

#[cfg(windows)]
mod os {
    use std::net::UdpSocket;
    use std::os::windows::io::{AsRawSocket, FromRawSocket};

    use windows_sys::Win32::Networking::WinSock as ws;

    pub fn unbound(v6: bool) -> UdpSocket {
        let _ = UdpSocket::bind("127.0.0.1:0");
        let family = if v6 { ws::AF_INET6 } else { ws::AF_INET };
        let s = unsafe { ws::socket(family.into(), ws::SOCK_DGRAM, 0) };
        assert_ne!(s, ws::INVALID_SOCKET);
        unsafe { UdpSocket::from_raw_socket(s as _) }
    }

    /// `connect` to an all-zero `SOCKADDR_IN`, whose family is `AF_UNSPEC`.
    pub fn disconnect(s: &UdpSocket) -> Result<(), i32> {
        let addr: ws::SOCKADDR_IN = unsafe { std::mem::zeroed() };
        let len = size_of::<ws::SOCKADDR_IN>() as i32;
        let rc = unsafe { ws::connect(s.as_raw_socket() as usize, (&raw const addr).cast(), len) };
        if rc == 0 {
            Ok(())
        } else {
            Err(unsafe { ws::WSAGetLastError() })
        }
    }
}

/// Names ports in order of appearance (`0` stays `0`), so runs that draw different ephemeral
/// ports compare equal.
#[derive(Default)]
struct Ports(Vec<u16>);

impl Ports {
    fn local(&mut self, s: &UdpSocket) -> String {
        match s.local_addr() {
            Ok(addr) if addr.port() == 0 => format!("{}:0", addr.ip()),
            Ok(addr) => {
                let index = match self.0.iter().position(|&p| p == addr.port()) {
                    Some(index) => index,
                    None => {
                        self.0.push(addr.port());
                        self.0.len() - 1
                    }
                };
                format!("{}:p{index}", addr.ip())
            }
            Err(e) => format!("error {}", e.raw_os_error().unwrap_or_default()),
        }
    }
}

fn code<T>(r: std::io::Result<T>) -> Result<(), i32> {
    r.map(|_| ()).map_err(|e| e.raw_os_error().unwrap())
}

/// Connects a socket bound at `bind` (or never bound) to `dst`, dissolves the association,
/// sends unconnected, and connects again, noting the local address at every step.
fn connect_cycle(bind: Option<&str>, dst: &str) -> Vec<String> {
    let dst: SocketAddr = dst.parse().unwrap();
    let s = match bind {
        Some(bind) => UdpSocket::bind(bind).unwrap(),
        None => os::unbound(dst.is_ipv6()),
    };
    let mut ports = Ports::default();
    let mut out = vec![format!("{bind:?} -> {dst}")];
    if bind.is_some() {
        out.push(format!("bound {}", ports.local(&s)));
    }
    out.push(format!("connect {:?}", code(s.connect(dst))));
    out.push(format!("connected {}", ports.local(&s)));
    out.push(format!("disconnect {:?}", os::disconnect(&s)));
    out.push(format!("disconnected {}", ports.local(&s)));
    out.push(format!("peer {:?}", code(s.peer_addr())));
    out.push(format!("send {:?}", code(s.send_to(b"x", dst))));
    out.push(format!("sent {}", ports.local(&s)));
    out.push(format!("reconnect {:?}", code(s.connect(dst))));
    out.push(format!("reconnected {}", ports.local(&s)));
    out
}

fn connect_probe() -> Vec<String> {
    [
        (Some("0.0.0.0:0"), "127.0.0.1:9"),
        (Some("0.0.0.0:0"), "127.0.0.5:9"),
        (Some("0.0.0.0:47613"), "127.0.0.1:9"),
        (Some("127.0.0.1:0"), "127.0.0.1:9"),
        (Some("127.0.0.1:47614"), "127.0.0.1:9"),
        (None, "127.0.0.1:9"),
        (Some("[::]:0"), "[::1]:9"),
        (Some("[::]:47615"), "[::1]:9"),
        (Some("[::1]:0"), "[::1]:9"),
        (None, "[::1]:9"),
    ]
    .into_iter()
    .flat_map(|(bind, dst)| connect_cycle(bind, dst))
    .collect()
}

#[test]
fn connect_source_os_truth() {
    let real = snare::real(connect_probe);
    let simulated = Sim::new().run(connect_probe);
    assert_eq!(simulated, real);
}

/// A connect moves where a wildcard-bound socket receives, not the port its bind claimed: binding
/// the wildcard at that port again is still `EADDRINUSE`.
fn rebind_probe() -> Vec<String> {
    let first = UdpSocket::bind("0.0.0.0:47616").unwrap();
    let mut out = vec![format!(
        "before {:?}",
        code(UdpSocket::bind("0.0.0.0:47616"))
    )];
    first.connect("127.0.0.1:9").unwrap();
    out.push(format!(
        "after {:?}",
        code(UdpSocket::bind("0.0.0.0:47616"))
    ));
    out
}

#[test]
fn connected_wildcard_keeps_its_port_os_truth() {
    let real = snare::real(rebind_probe);
    let simulated = Sim::new().run(rebind_probe);
    assert_eq!(simulated, real);
}

/// Through a simulated interface, where the connect rehashes the socket to the interface's
/// address, a second wildcard bind of the port still fails, so a probe for a free port moves on.
#[test]
fn connected_wildcard_keeps_its_port_on_an_interface() {
    nic_sim().run(|| {
        let first = UdpSocket::bind("0.0.0.0:47617").unwrap();
        first.connect("10.0.0.2:9").unwrap();
        assert_eq!(
            first.local_addr().unwrap().ip(),
            IpAddr::from([10, 0, 0, 1])
        );
        let again = UdpSocket::bind("0.0.0.0:47617").map(|_| ());
        assert_eq!(code(again), Err(libc::EADDRINUSE));
    });
}

/// Winsock also dissolves the association on a connect to the all-zero IPv4 address.
#[cfg(windows)]
#[test]
fn zero_address_disconnect_os_truth() {
    let probe = || {
        let s = UdpSocket::bind("0.0.0.0:0").unwrap();
        let mut ports = Ports::default();
        s.connect("127.0.0.1:9").unwrap();
        let connected = ports.local(&s);
        let zero = code(s.connect("0.0.0.0:0"));
        (connected, zero, ports.local(&s), code(s.peer_addr()))
    };
    let real = snare::real(probe);
    assert_eq!(Sim::new().run(probe), real);
}

/// While connected, a socket that took the route's source receives what is sent there and
/// nothing sent to its old wildcard's other addresses.
#[test]
fn connected_wildcard_receives_only_at_its_source() {
    Sim::new().run(|| {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let s = UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = s.local_addr().unwrap().port();
        s.connect("127.0.0.3:9").unwrap();
        assert_eq!(
            s.local_addr().unwrap(),
            SocketAddr::from(([127, 0, 0, 1], port))
        );
        s.connect(peer.local_addr().unwrap()).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        peer.send_to(b"to", SocketAddr::from(([127, 0, 0, 2], port)))
            .unwrap();
        peer.send_to(b"source", SocketAddr::from(([127, 0, 0, 1], port)))
            .unwrap();
        let mut buf = [0; 16];
        let n = s.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"source");
        assert!(s.recv(&mut buf).is_err(), "127.0.0.2 is not its address");
    });
}

fn nic_sim() -> Sim {
    Sim::builder()
        .nic(
            NicSpec::new("eth0")
                .address("10.0.0.1/24".parse::<IpNet>().unwrap())
                .address("fd00::1/64".parse::<IpNet>().unwrap())
                .station("10.0.0.2".parse::<IpAddr>().unwrap())
                .station("fd00::2".parse::<IpAddr>().unwrap()),
        )
        .nic(
            NicSpec::new("eth1")
                .address("10.1.0.1/24".parse::<IpNet>().unwrap())
                .station("10.1.0.2".parse::<IpAddr>().unwrap()),
        )
        .route(
            Route::new("192.168.0.0/16".parse::<IpNet>().unwrap(), "eth1").gateway([10, 1, 0, 254]),
        )
        .build()
}

/// Connects a wildcard-bound socket to `dst` and returns the address it took.
fn source_for(wildcard: &str, dst: SocketAddr) -> SocketAddr {
    let s = UdpSocket::bind(wildcard).unwrap();
    s.connect(dst).unwrap();
    s.local_addr().unwrap()
}

/// On a plain sim each interface's subnet and route gives its own source address, and the
/// station on the subnet reaches the connected socket there.
#[test]
fn wildcard_connect_takes_the_interface_source() {
    nic_sim().run(|| {
        assert_eq!(
            source_for("0.0.0.0:0", "10.0.0.2:9".parse().unwrap()).ip(),
            IpAddr::from([10, 0, 0, 1])
        );
        assert_eq!(
            source_for("0.0.0.0:0", "10.1.0.2:9".parse().unwrap()).ip(),
            IpAddr::from([10, 1, 0, 1])
        );
        assert_eq!(
            source_for("0.0.0.0:0", "192.168.7.7:9".parse().unwrap()).ip(),
            IpAddr::from([10, 1, 0, 1]),
            "through eth1's gateway"
        );
        assert_eq!(
            source_for("[::]:0", "[fd00::2]:9".parse().unwrap()).ip(),
            "fd00::1".parse::<IpAddr>().unwrap()
        );

        let station = UdpSocket::bind("10.0.0.2:7000").unwrap();
        let s = UdpSocket::bind("0.0.0.0:0").unwrap();
        s.connect("10.0.0.2:7000").unwrap();
        let local = s.local_addr().unwrap();
        assert_eq!(local.ip(), IpAddr::from([10, 0, 0, 1]));
        station.send_to(b"reply", local).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut buf = [0; 16];
        let n = s.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"reply");
        s.send(b"ping").unwrap();
        let (n, from) = station.recv_from(&mut buf).unwrap();
        assert_eq!((&buf[..n], from), (&b"ping"[..], local));
    });
}

/// Connecting a connected socket again: Linux keeps the source the first connect picked; macOS
/// (`soconnectlock` disconnects first) and Windows pick it anew, as measured on the real hosts.
#[test]
fn reconnect_source_follows_the_host() {
    nic_sim().run(|| {
        let s = UdpSocket::bind("0.0.0.0:0").unwrap();
        s.connect("10.0.0.2:9").unwrap();
        s.connect("10.1.0.2:9").unwrap();
        let expected = if cfg!(target_os = "linux") {
            [10, 0, 0, 1]
        } else {
            [10, 1, 0, 1]
        };
        assert_eq!(s.local_addr().unwrap().ip(), IpAddr::from(expected));
    });
}

/// A connect with no route fails and leaves the wildcard bind as it was.
#[test]
fn unrouted_connect_keeps_the_wildcard() {
    nic_sim().run(|| {
        snare::set_default_route(None).unwrap();
        let s = UdpSocket::bind("0.0.0.0:0").unwrap();
        let before = s.local_addr().unwrap();
        assert!(s.connect("172.16.0.1:9").is_err());
        assert_eq!(s.local_addr().unwrap(), before);
    });
}

/// The socket table follows the rebind.
#[test]
fn socket_table_shows_the_connected_source() {
    nic_sim().run(|| {
        let s = UdpSocket::bind("0.0.0.0:0").unwrap();
        s.connect("10.0.0.2:9").unwrap();
        let entry = snare::socket_entry(snare::socket_id(&s).unwrap()).unwrap();
        assert_eq!(entry.local, Some(s.local_addr().unwrap()));
        assert_eq!(entry.local.unwrap().ip(), IpAddr::from([10, 0, 0, 1]));
    });
}

#[cfg(target_os = "linux")]
mod simhost {
    use std::net::{IpAddr, SocketAddr, UdpSocket};
    use std::time::Duration;

    use snare::{HostProfile, IpNet, Nic, Sim};

    fn host_sim() -> Sim {
        let host = HostProfile::new()
            .nic(
                Nic::new("eth0", 2)
                    .network("10.0.0.1/24".parse::<IpNet>().unwrap())
                    .station("10.0.0.2".parse::<IpAddr>().unwrap()),
            )
            .nic(
                Nic::new("eth1", 3)
                    .network("10.1.0.1/24".parse::<IpNet>().unwrap())
                    .network("fd01::1/64".parse::<IpNet>().unwrap())
                    .station("10.1.0.2".parse::<IpAddr>().unwrap()),
            )
            .build();
        Sim::builder().host(host).build()
    }

    /// A `SimHost` socket bound to the wildcard takes the source of the interface its route
    /// leaves by, and the station there reaches it.
    #[test]
    fn simhost_wildcard_connect_takes_the_interface_source() {
        host_sim().run(|| {
            let s = UdpSocket::bind("0.0.0.0:0").unwrap();
            let port = s.local_addr().unwrap().port();
            s.connect("10.1.0.2:9").unwrap();
            assert_eq!(
                s.local_addr().unwrap(),
                SocketAddr::from(([10, 1, 0, 1], port))
            );

            let v6 = UdpSocket::bind("[::]:0").unwrap();
            v6.connect("[fd01::2]:9").unwrap();
            assert_eq!(
                v6.local_addr().unwrap().ip(),
                "fd01::1".parse::<IpAddr>().unwrap()
            );

            let station = UdpSocket::bind("10.0.0.2:7000").unwrap();
            let s = UdpSocket::bind("0.0.0.0:0").unwrap();
            s.connect("10.0.0.2:7000").unwrap();
            let local = s.local_addr().unwrap();
            assert_eq!(local.ip(), IpAddr::from([10, 0, 0, 1]));
            station.send_to(b"reply", local).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let mut buf = [0; 16];
            let n = s.recv(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"reply");
        });
    }

    /// The disconnect rules of `__udp_disconnect`, on a `SimHost`'s sockets.
    #[test]
    fn simhost_disconnect_follows_the_bind_locks() {
        host_sim().run(|| {
            let cycle = |bind: &str| {
                let s = UdpSocket::bind(bind).unwrap();
                s.connect("10.0.0.2:9").unwrap();
                let connected = s.local_addr().unwrap();
                super::os::disconnect(&s).unwrap();
                let disconnected = s.local_addr().unwrap();
                s.send_to(b"x", "10.0.0.2:9").unwrap();
                (connected, disconnected, s.local_addr().unwrap())
            };
            let (connected, disconnected, sent) = cycle("0.0.0.0:0");
            assert_eq!(connected.ip(), IpAddr::from([10, 0, 0, 1]));
            assert_eq!(disconnected, "0.0.0.0:0".parse().unwrap());
            assert!(sent.ip().is_unspecified() && sent.port() != 0);

            let (connected, disconnected, sent) = cycle("0.0.0.0:47620");
            assert_eq!(connected, "10.0.0.1:47620".parse().unwrap());
            assert_eq!(disconnected, "0.0.0.0:47620".parse().unwrap());
            assert_eq!(sent, disconnected);

            let (connected, disconnected, sent) = cycle("10.0.0.1:0");
            assert_eq!(disconnected, "10.0.0.1:0".parse().unwrap());
            assert_eq!(sent.ip(), connected.ip());
            assert_ne!(sent.port(), 0);
        });
    }
}
