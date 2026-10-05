//! The sim's socket table: one record per open socket of the code under test, with its identity,
//! addresses, memberships, traffic counters, pending `SO_ERROR` and open/close times.

use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::time::Duration;

use snare::{Sim, SocketEntry, SocketKind};

fn entry_of(id: snare::SocketId) -> SocketEntry {
    snare::socket_entry(id).unwrap()
}

#[test]
fn ids_are_unique_and_never_reused() {
    Sim::new().run(|| {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (ida, idb) = (snare::socket_id(&a).unwrap(), snare::socket_id(&b).unwrap());
        assert!(ida < idb);
        drop(a);
        let c = TcpListener::bind("127.0.0.1:0").unwrap();
        let idc = snare::socket_id(&c).unwrap();
        assert!(idc > idb);

        let live: Vec<_> = snare::socket_table().iter().map(|e| e.id).collect();
        assert_eq!(live, vec![idb, idc]);
        let closed: Vec<_> = snare::closed_sockets().iter().map(|e| e.id).collect();
        assert_eq!(closed, vec![ida]);
        assert!(entry_of(ida).closed_at.is_some());
    });
}

#[test]
fn socket_id_of_std_and_mio_sockets() {
    let sim = Sim::new();
    sim.run(|| {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(snare::socket_id(&udp).is_some());
        assert!(snare::socket_id(&listener).is_some());
        #[cfg(unix)]
        {
            let mio_udp = mio::net::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            assert!(snare::socket_id(&mio_udp).is_some());
        }
        let real = snare::real(|| UdpSocket::bind("127.0.0.1:0")).unwrap();
        assert_eq!(snare::socket_id(&real), None);
    });
    let outside = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_eq!(snare::socket_id(&outside), None);
    assert_eq!(sim.socket_table().len(), 0);
    assert_eq!(sim.closed_sockets().len(), if cfg!(unix) { 3 } else { 2 });
}

#[test]
fn dup_shares_identity() {
    Sim::new().run(|| {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = a.try_clone().unwrap();
        let id = snare::socket_id(&a).unwrap();
        assert_eq!(snare::socket_id(&b), Some(id));
        assert_eq!(snare::socket_table().len(), 1);
        drop(a);
        assert_eq!(entry_of(id).closed_at, None);
        drop(b);
        assert!(entry_of(id).closed_at.is_some());
    });
}

#[test]
fn entry_tracks_local_peer_memberships() {
    Sim::new().run(|| {
        let s = UdpSocket::bind("0.0.0.0:0").unwrap();
        let id = snare::socket_id(&s).unwrap();
        let port = s.local_addr().unwrap().port();
        let group = Ipv4Addr::new(239, 1, 2, 3);
        s.join_multicast_v4(&group, &Ipv4Addr::new(127, 0, 0, 1))
            .unwrap();
        s.connect("127.0.0.1:4000").unwrap();

        let e = entry_of(id);
        assert_eq!(e.kind, SocketKind::Udp);
        assert_eq!(e.local, Some(([127, 0, 0, 1], port).into()));
        assert_eq!(e.peer, Some("127.0.0.1:4000".parse().unwrap()));
        assert_eq!(e.memberships.len(), 1);
        assert_eq!(e.memberships[0].group, std::net::IpAddr::V4(group));
        assert_eq!(
            e.memberships[0].interface_addr,
            Some(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
    });
}

#[test]
fn sockets_bound_finds_every_socket_on_an_address() {
    Sim::new().run(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let _other = UdpSocket::bind("127.0.0.3:0").unwrap();

        let mut ids: Vec<_> = snare::sockets_bound(addr).iter().map(|e| e.id).collect();
        ids.sort();
        let mut want = vec![
            snare::socket_id(&listener).unwrap(),
            snare::socket_id(&accepted).unwrap(),
        ];
        want.sort();
        assert_eq!(ids, want);
    });
}

#[test]
fn created_and_closed_times_are_virtual() {
    let sim = Sim::new();
    let id = sim.run(|| {
        std::thread::sleep(Duration::from_secs(2));
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let id = snare::socket_id(&s).unwrap();
        std::thread::sleep(Duration::from_secs(5));
        drop(s);
        id
    });
    let e = sim.socket_entry(id).unwrap();
    assert!(e.created_at >= Duration::from_secs(2) && e.created_at < Duration::from_millis(2010));
    let open = e.closed_at.unwrap() - e.created_at;
    assert!(
        open >= Duration::from_secs(5) && open < Duration::from_millis(5010),
        "{open:?}"
    );
}

#[test]
fn delivered_and_sent_counts() {
    Sim::new().run(|| {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..3 {
            a.send_to(&[7u8; 10], b.local_addr().unwrap()).unwrap();
        }
        b.recv_from(&mut [0u8; 32]).unwrap();
        let (ea, eb) = (
            entry_of(snare::socket_id(&a).unwrap()),
            entry_of(snare::socket_id(&b).unwrap()),
        );
        assert_eq!((ea.sent, ea.delivered), (3, 0));
        assert_eq!((eb.delivered, eb.delivered_bytes), (3, 30));
        assert_eq!((eb.queued, eb.queued_bytes), (2, 20));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        use std::io::Write;
        client.write_all(b"abc").unwrap();
        client.write_all(b"de").unwrap();
        let es = entry_of(snare::socket_id(&server).unwrap());
        assert_eq!((es.delivered, es.delivered_bytes), (2, 5));
        assert_eq!((es.queued, es.queued_bytes), (2, 5));
        assert_eq!(entry_of(snare::socket_id(&client).unwrap()).sent, 2);
    });
}

#[test]
fn so_error_reads_and_clears() {
    Sim::new().run(|| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let id = snare::socket_id(&s).unwrap();
        assert!(s.take_error().unwrap().is_none());
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        let errno = connection_refused();
        snare::__set_pending_error(id, errno);
        assert_eq!(entry_of(id).pending_error, Some(errno));
        let err = s.take_error().unwrap().unwrap();
        assert_eq!(err.raw_os_error(), Some(errno));
        assert_eq!(err.kind(), refused.kind());
        assert!(s.take_error().unwrap().is_none());
        assert_eq!(entry_of(id).pending_error, None);
    });
}

#[cfg(unix)]
fn connection_refused() -> i32 {
    libc::ECONNREFUSED
}

#[cfg(windows)]
fn connection_refused() -> i32 {
    10061
}

#[cfg(target_os = "linux")]
#[test]
fn simhost_udp_sockets_are_in_the_same_table() {
    let host = snare::HostProfile::default().build();
    Sim::builder().host(host).build().run(|| {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let nl = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, 0) };
        assert!(nl >= 0);
        let kinds: Vec<_> = snare::socket_table().iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![
                SocketKind::Udp,
                SocketKind::TcpListener,
                SocketKind::Netlink
            ]
        );
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.send_to(b"hi", udp.local_addr().unwrap()).unwrap();
        let e = entry_of(snare::socket_id(&udp).unwrap());
        assert_eq!((e.delivered, e.queued), (1, 1));
        assert_eq!(entry_of(snare::socket_id(&peer).unwrap()).sent, 1);
        drop(listener);
        unsafe { libc::close(nl) };
        assert_eq!(snare::closed_sockets().len(), 2);
    });
}

fn table_run(seed: u64) -> (Vec<SocketEntry>, Vec<SocketEntry>) {
    let sim = Sim::builder().deterministic().seed(seed).build();
    sim.run(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            for _ in 0..3 {
                let (mut s, _) = listener.accept().unwrap();
                let mut buf = [0u8; 8];
                let n = s.read(&mut buf).unwrap();
                s.write_all(&buf[..n]).unwrap();
            }
        });
        let clients: Vec<_> = (0..3)
            .map(|i| {
                std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
                    std::thread::sleep(Duration::from_millis(i * 3));
                    let mut s = TcpStream::connect(addr).unwrap();
                    s.write_all(&[i as u8; 4]).unwrap();
                    let mut buf = [0u8; 4];
                    s.read_exact(&mut buf).unwrap();
                    drop(u);
                })
            })
            .collect();
        for c in clients {
            c.join().unwrap();
        }
        server.join().unwrap();
    });
    (sim.socket_table(), sim.closed_sockets())
}

#[test]
fn socket_table_replays_under_deterministic() {
    let first = table_run(11);
    assert_eq!(first.0.len() + first.1.len(), 1 + 3 * 3);
    assert_eq!(first, table_run(11));
}
