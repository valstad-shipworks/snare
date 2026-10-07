//! Behaviour pins for socket tables at scale, ahead of performance work on the fabric's
//! registries: ten thousand UDP sockets take socket ids 1, 2, 3, … in creation order, list in that
//! order and close in the order they are closed, each one's datagram reaches only it; ephemeral
//! UDP ports go lowest free first from 49152 and a freed port is the next one taken; thousands of
//! TCP connections to one listener with an explicit large backlog are accepted in connect
//! order, each from the next ephemeral port. The ephemeral range filling up is pinned too.
//!
//! The descriptors themselves are real ones `dup`ed from one placeholder, so their numbers belong
//! to the process (other tests in the binary hold some) and only their distinctness is pinned. Each
//! test raises the soft `RLIMIT_NOFILE` to the hard limit first, so the default macOS limit of 256
//! does not end a run early.

#![cfg(unix)]

use std::collections::HashSet;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;

use snare::{Sim, SocketKind};

const SOCKETS: usize = 10_000;

/// The first port of the IANA dynamic range the sim takes ephemeral ports from.
const EPHEMERAL_FIRST: u16 = 49152;

/// Raises the soft descriptor limit to the hard one, or to 100 000 when the hard one is higher
/// (macOS refuses a soft limit above `kern.maxfilesperproc`).
fn raise_nofile() {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a live rlimit.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) }, 0);
    let want = lim.rlim_max.min(100_000);
    if lim.rlim_cur < want {
        lim.rlim_cur = want;
        // SAFETY: as above.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) };
    }
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn id_of(sock: &UdpSocket) -> u64 {
    snare::socket_id(sock).unwrap().get()
}

#[test]
fn ten_thousand_udp_sockets_take_ids_in_creation_order() {
    raise_nofile();
    let sim = Sim::new();
    sim.run(|| {
        let socks: Vec<UdpSocket> = (0..SOCKETS)
            .map(|i| UdpSocket::bind(loopback(10_000 + i as u16)).unwrap())
            .collect();
        let ids: Vec<u64> = socks.iter().map(id_of).collect();
        assert_eq!(ids, (1..=SOCKETS as u64).collect::<Vec<_>>());

        let table = snare::socket_table();
        assert_eq!(table.len(), SOCKETS);
        assert!(
            table
                .iter()
                .enumerate()
                .all(|(i, e)| e.id.get() == i as u64 + 1
                    && e.kind == SocketKind::Udp
                    && e.local == Some(loopback(10_000 + i as u16))
                    && e.created_at.is_zero()),
            "the table lists sockets oldest first with their binds"
        );

        let fds: HashSet<i32> = socks.iter().map(AsRawFd::as_raw_fd).collect();
        assert_eq!(fds.len(), SOCKETS, "every socket has its own descriptor");

        let mut socks: Vec<Option<UdpSocket>> = socks.into_iter().map(Some).collect();
        let mut closed_order = Vec::new();
        for i in (0..SOCKETS).rev().filter(|i| i % 2 == 1) {
            closed_order.push(i as u64 + 1);
            socks[i] = None;
        }
        let closed: Vec<u64> = snare::closed_sockets().iter().map(|e| e.id.get()).collect();
        assert_eq!(closed, closed_order, "closed sockets list in closing order");
        let open: Vec<u64> = snare::socket_table().iter().map(|e| e.id.get()).collect();
        assert_eq!(open, (1..=SOCKETS as u64).step_by(2).collect::<Vec<_>>());

        let next = UdpSocket::bind(loopback(10_001)).unwrap();
        assert_eq!(id_of(&next), SOCKETS as u64 + 1, "ids are never reused");
        drop(socks);
    });
    assert_eq!(sim.socket_table().len(), 0);
    assert_eq!(sim.closed_sockets().len(), SOCKETS + 1);
}

#[test]
fn a_datagram_to_each_of_ten_thousand_sockets_reaches_only_it() {
    raise_nofile();
    let sim = Sim::new();
    sim.run(|| {
        let tx = UdpSocket::bind(loopback(9_000)).unwrap();
        let socks: Vec<UdpSocket> = (0..SOCKETS)
            .map(|i| UdpSocket::bind(loopback(10_000 + i as u16)).unwrap())
            .collect();
        for (i, sock) in socks.iter().enumerate().rev() {
            tx.send_to(&(i as u32).to_be_bytes(), sock.local_addr().unwrap())
                .unwrap();
        }
        let mut buf = [0u8; 8];
        for (i, sock) in socks.iter().enumerate() {
            sock.set_nonblocking(true).unwrap();
            let (n, from) = sock.recv_from(&mut buf).unwrap();
            assert_eq!(
                (&buf[..n], from),
                (&(i as u32).to_be_bytes()[..], loopback(9_000))
            );
            assert_eq!(
                sock.recv_from(&mut buf).unwrap_err().kind(),
                ErrorKind::WouldBlock,
                "socket {i} got exactly one"
            );
        }
        let sender = snare::socket_entry(snare::socket_id(&tx).unwrap()).unwrap();
        assert_eq!((sender.sent, sender.delivered), (SOCKETS as u64, 0));
        assert!(
            snare::socket_table()
                .iter()
                .skip(1)
                .all(|e| e.delivered == 1 && e.delivered_bytes == 4 && e.queued == 0)
        );
    });
    let udp = sim.proto_counters().udp4;
    assert_eq!(
        (udp.sent, udp.received, udp.no_ports),
        (SOCKETS as u64, SOCKETS as u64, 0)
    );
}

#[test]
fn ephemeral_udp_ports_go_lowest_free_first() {
    let sim = Sim::new();
    sim.run(|| {
        let mut socks: Vec<Option<UdpSocket>> = (0..500)
            .map(|_| Some(UdpSocket::bind("127.0.0.1:0").unwrap()))
            .collect();
        let ports: Vec<u16> = socks
            .iter()
            .map(|s| s.as_ref().unwrap().local_addr().unwrap().port())
            .collect();
        assert_eq!(
            ports,
            (EPHEMERAL_FIRST..EPHEMERAL_FIRST + 500).collect::<Vec<_>>()
        );

        socks[250] = None;
        socks[100] = None;
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let c = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(
            [a, b, c].map(|s| s.local_addr().unwrap().port()),
            [
                EPHEMERAL_FIRST + 100,
                EPHEMERAL_FIRST + 250,
                EPHEMERAL_FIRST + 500
            ]
        );
        let other = UdpSocket::bind("127.0.0.2:0").unwrap();
        assert_eq!(
            other.local_addr().unwrap().port(),
            EPHEMERAL_FIRST,
            "ports are taken per address"
        );
    });
}

#[test]
fn wildcard_ephemeral_ports_wait_for_the_last_address_and_alias() {
    Sim::new().run(|| {
        let first = UdpSocket::bind("127.0.0.1:49152").unwrap();
        let alias = first.try_clone().unwrap();
        let second = UdpSocket::bind("127.0.0.2:49152").unwrap();
        let wildcard = UdpSocket::bind("0.0.0.0:0").unwrap();
        assert_eq!(wildcard.local_addr().unwrap().port(), 49153);
        drop(wildcard);
        drop(first);
        drop(second);
        let wildcard = UdpSocket::bind("0.0.0.0:0").unwrap();
        assert_eq!(wildcard.local_addr().unwrap().port(), 49153);
        drop(wildcard);
        drop(alias);
        let wildcard = UdpSocket::bind("0.0.0.0:0").unwrap();
        assert_eq!(wildcard.local_addr().unwrap().port(), 49152);
        let specific = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(specific.local_addr().unwrap().port(), 49152);
        drop(specific);
        let specific = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(specific.local_addr().unwrap().port(), 49152);
    });
}

#[test]
fn wildcard_ephemeral_ports_are_independent_between_address_families() {
    Sim::new().run(|| {
        let v4 = UdpSocket::bind("127.0.0.1:49152").unwrap();
        let v6 = UdpSocket::bind("[::]:0").unwrap();
        assert_eq!(v6.local_addr().unwrap().port(), 49152);
        let v4_wildcard = UdpSocket::bind("0.0.0.0:0").unwrap();
        assert_eq!(v4_wildcard.local_addr().unwrap().port(), 49153);
        let v6_specific = UdpSocket::bind("[::1]:0").unwrap();
        assert_eq!(v6_specific.local_addr().unwrap().port(), 49152);
        drop(v4);
        let reused = UdpSocket::bind("0.0.0.0:0").unwrap();
        assert_eq!(reused.local_addr().unwrap().port(), 49152);
    });
}

/// Fills every port of the dynamic range on 127.0.0.1 with an explicit bind.
fn fill_ephemeral_range() -> Vec<UdpSocket> {
    (EPHEMERAL_FIRST..=u16::MAX)
        .map(|port| UdpSocket::bind(loopback(port)).unwrap())
        .collect()
}

#[test]
fn a_full_ephemeral_range_leaves_other_addresses_alone() {
    raise_nofile();
    Sim::new().run(|| {
        let _full = fill_ephemeral_range();
        let other = UdpSocket::bind("127.0.0.2:0").unwrap();
        assert_eq!(
            other.local_addr().unwrap(),
            "127.0.0.2:49152".parse().unwrap()
        );
    });
}

#[test]
fn a_full_ephemeral_range_refuses_port_zero() {
    raise_nofile();
    Sim::new().run(|| {
        let _full = fill_ephemeral_range();
        // Linux __inet_bind turns a failed get_port into EADDRINUSE; xnu in_pcbbind runs out of
        // ports with EADDRNOTAVAIL.
        let want = if cfg!(target_os = "linux") {
            libc::EADDRINUSE
        } else {
            libc::EADDRNOTAVAIL
        };
        let bound = UdpSocket::bind("127.0.0.1:0");
        assert_eq!(
            bound
                .as_ref()
                .map(|s| s.local_addr().unwrap())
                .map_err(|e| e.raw_os_error()),
            Err(Some(want))
        );
    });
}

#[test]
fn two_thousand_tcp_connects_queue_and_accept_in_connect_order() {
    raise_nofile();
    const CONNS: usize = 2_000;
    let sim = Sim::new();
    sim.set_sys_limits(|limits| limits.listen_backlog_max = CONNS);
    sim.run(|| {
        let listener = TcpListener::bind("127.0.0.1:7000").unwrap();
        assert_eq!(
            unsafe { libc::listen(listener.as_raw_fd(), CONNS as i32) },
            0
        );
        let clients: Vec<TcpStream> = (0..CONNS)
            .map(|_| TcpStream::connect("127.0.0.1:7000").unwrap())
            .collect();
        let locals: Vec<SocketAddr> = clients.iter().map(|c| c.local_addr().unwrap()).collect();
        assert_eq!(
            locals,
            (0..CONNS)
                .map(|i| loopback(EPHEMERAL_FIRST + i as u16))
                .collect::<Vec<_>>(),
            "each connect takes the next ephemeral port"
        );
        let accepted: Vec<(TcpStream, SocketAddr)> =
            (0..CONNS).map(|_| listener.accept().unwrap()).collect();
        let peers: Vec<SocketAddr> = accepted.iter().map(|(_, peer)| *peer).collect();
        assert_eq!(
            peers, locals,
            "the configured backlog is accepted first in, first out"
        );

        let listener_id = snare::socket_id(&listener).unwrap();
        let table = snare::socket_table();
        assert_eq!(table.len(), 1 + 2 * CONNS);
        let accepted_ids: Vec<u64> = table
            .iter()
            .filter(|e| e.listener == Some(listener_id))
            .map(|e| e.id.get())
            .collect();
        assert_eq!(
            accepted_ids,
            (CONNS as u64 + 2..=2 * CONNS as u64 + 1).collect::<Vec<_>>(),
            "accepted streams take ids after every client, in accept order"
        );
    });
    let tcp = sim.proto_counters().tcp4;
    assert_eq!(
        (tcp.active_opens, tcp.passive_opens, tcp.curr_estab),
        (CONNS as u64, CONNS as u64, 0)
    );
}

#[test]
fn tcp_ephemeral_ports_never_repeat_a_live_connection() {
    raise_nofile();
    const CONNS: usize = (u16::MAX - EPHEMERAL_FIRST) as usize + 2;
    let sim = Sim::new();
    sim.set_sys_limits(|limits| limits.listen_backlog_max = CONNS);
    sim.run(|| {
        let listener = TcpListener::bind("127.0.0.1:7000").unwrap();
        assert_eq!(
            unsafe { libc::listen(listener.as_raw_fd(), CONNS as i32) },
            0
        );
        let mut locals = HashSet::new();
        let mut clients = Vec::with_capacity(CONNS);
        for n in 0..CONNS {
            match TcpStream::connect("127.0.0.1:7000") {
                Ok(c) => {
                    let local = c.local_addr().unwrap();
                    assert!(locals.insert(local), "connect {n} reused live port {local}");
                    clients.push(c);
                }
                Err(e) => {
                    assert_eq!(n, CONNS - 1, "only the connect past the range fails");
                    assert_eq!(e.raw_os_error(), Some(libc::EADDRNOTAVAIL));
                }
            }
        }
    });
}
