//! Behaviour pins for readiness at scale, ahead of performance work on epoll and kqueue: two
//! thousand UDP sockets registered with one `mio::Poll` (epoll on Linux, kqueue on macOS), a
//! datagram sent to each in a scrambled order, are each reported exactly once (edge-triggered) by
//! one wait, or across exactly 32 waits of at most 64 events, and a second datagram to a socket
//! already reported is a new edge. On Linux a level-triggered epoll set of the same sockets
//! reports all of them on every wait.
//!
//! The kernels report ready descriptors in the order they became ready (Linux fs/eventpoll.c
//! appends to `rdllist`; XNU bsd/kern/kern_event.c queues an activated knote at the tail of its
//! kqueue), and a level-triggered descriptor a short wait reported goes to the back of the list,
//! so successive short waits move through all of them.

#![cfg(unix)]

use std::net::SocketAddr;
use std::time::Duration;

use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
use snare::Sim;

const SOCKETS: usize = 2_000;

/// The order the datagrams are sent in: a fixed permutation of `0..SOCKETS`.
fn send_order() -> Vec<usize> {
    (0..SOCKETS).map(|i| (i * 7 + 3) % SOCKETS).collect()
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Registers `SOCKETS` sockets on `poll`, token `i` for the one on port 20000 + i, then sends one
/// datagram to each in [`send_order`].
fn setup(poll: &Poll) -> (Vec<UdpSocket>, std::net::UdpSocket) {
    let mut socks: Vec<UdpSocket> = (0..SOCKETS)
        .map(|i| UdpSocket::bind(loopback(20_000 + i as u16)).unwrap())
        .collect();
    for (i, sock) in socks.iter_mut().enumerate() {
        poll.registry()
            .register(sock, Token(i), Interest::READABLE)
            .unwrap();
    }
    let tx = std::net::UdpSocket::bind("127.0.0.1:9000").unwrap();
    for i in send_order() {
        tx.send_to(&[1], loopback(20_000 + i as u16)).unwrap();
    }
    (socks, tx)
}

fn tokens(events: &Events) -> Vec<usize> {
    events.iter().map(|e| e.token().0).collect()
}

#[test]
fn one_wait_reports_every_ready_socket_exactly_once() {
    Sim::new().run(|| {
        let mut poll = Poll::new().unwrap();
        let (_socks, _tx) = setup(&poll);
        let mut events = Events::with_capacity(2 * SOCKETS);
        poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
        let mut got = tokens(&events);
        assert_eq!(got.len(), SOCKETS);
        got.sort_unstable();
        assert_eq!(got, (0..SOCKETS).collect::<Vec<_>>());
        poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert!(events.is_empty(), "each edge is reported once");
    });
}

#[test]
fn short_waits_report_every_ready_socket_in_full_batches() {
    Sim::new().run(|| {
        let mut poll = Poll::new().unwrap();
        let (_socks, tx) = setup(&poll);
        let mut events = Events::with_capacity(64);
        let mut batches = Vec::new();
        loop {
            poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
            if events.is_empty() {
                break;
            }
            batches.push(tokens(&events));
        }
        let sizes: Vec<usize> = batches.iter().map(Vec::len).collect();
        let mut want = vec![64; SOCKETS / 64];
        want.push(SOCKETS % 64);
        assert_eq!(sizes, want);
        let mut all: Vec<usize> = batches.concat();
        all.sort_unstable();
        assert_eq!(all, (0..SOCKETS).collect::<Vec<_>>());

        tx.send_to(&[2], loopback(20_000 + 1_234)).unwrap();
        tx.send_to(&[2], loopback(20_000 + 17)).unwrap();
        poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
        let mut again = tokens(&events);
        again.sort_unstable();
        assert_eq!(again, [17, 1_234], "a second datagram is a new edge");
    });
}

/// The tokens one wait reports after [`setup`], on a fresh sim built by `sim`.
fn reported_order(sim: Sim) -> Vec<usize> {
    sim.run(|| {
        let mut poll = Poll::new().unwrap();
        let (_socks, _tx) = setup(&poll);
        let mut events = Events::with_capacity(2 * SOCKETS);
        poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
        tokens(&events)
    })
}

#[test]
fn ready_sockets_are_reported_in_the_order_they_became_ready() {
    assert_eq!(reported_order(Sim::new()), send_order());
}

#[test]
fn deterministic_runs_report_ready_sockets_in_the_same_order() {
    let sim = || Sim::builder().deterministic().seed(1).build();
    assert_eq!(reported_order(sim()), reported_order(sim()));
}

#[cfg(target_os = "linux")]
mod level_triggered {
    use std::os::fd::AsRawFd;

    use super::*;

    fn epoll_wait(epfd: i32, max: usize) -> Vec<usize> {
        let mut evs = vec![libc::epoll_event { events: 0, u64: 0 }; max];
        // SAFETY: `evs` holds `max` events.
        let n = unsafe { libc::epoll_wait(epfd, evs.as_mut_ptr(), max as i32, 0) };
        assert!(n >= 0);
        evs[..n as usize].iter().map(|e| e.u64 as usize).collect()
    }

    /// A level-triggered epoll set over `SOCKETS` sockets, each sent one datagram in
    /// [`send_order`]; runs `check` with the epoll descriptor.
    fn with_ready_set(check: impl FnOnce(i32)) {
        Sim::new().run(|| {
            // SAFETY: plain syscalls on descriptors this test owns.
            let epfd = unsafe { libc::epoll_create1(0) };
            assert!(epfd >= 0);
            let socks: Vec<std::net::UdpSocket> = (0..SOCKETS)
                .map(|i| std::net::UdpSocket::bind(loopback(20_000 + i as u16)).unwrap())
                .collect();
            for (i, sock) in socks.iter().enumerate() {
                let mut ev = libc::epoll_event {
                    events: libc::EPOLLIN as u32,
                    u64: i as u64,
                };
                // SAFETY: as above.
                let rc = unsafe {
                    libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, sock.as_raw_fd(), &mut ev)
                };
                assert_eq!(rc, 0);
            }
            let tx = std::net::UdpSocket::bind("127.0.0.1:9000").unwrap();
            for i in send_order() {
                tx.send_to(&[1], loopback(20_000 + i as u16)).unwrap();
            }
            check(epfd);
            // SAFETY: as above.
            unsafe { libc::close(epfd) };
        });
    }

    #[test]
    fn level_triggered_waits_report_every_ready_socket_every_time() {
        with_ready_set(|epfd| {
            for _ in 0..3 {
                let mut got = epoll_wait(epfd, 2 * SOCKETS);
                got.sort_unstable();
                assert_eq!(got, (0..SOCKETS).collect::<Vec<_>>());
            }
        });
    }

    #[test]
    fn level_triggered_short_waits_rotate_through_the_ready_list() {
        with_ready_set(|epfd| {
            let mut seen = std::collections::HashSet::new();
            for _ in 0..SOCKETS.div_ceil(64) {
                seen.extend(epoll_wait(epfd, 64));
            }
            assert_eq!(
                seen.len(),
                SOCKETS,
                "32 waits of 64 reach every ready socket"
            );
        });
    }
}
