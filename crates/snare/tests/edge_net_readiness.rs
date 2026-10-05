#![cfg(unix)]

//! Readiness edge cases pinned ahead of the performance pass, each a step-by-step record of what
//! the readiness calls report. Linux: the masks `epoll_wait` reports for one stream registered
//! level-triggered, `EPOLLET` and `EPOLLONESHOT` in three epoll sets at once, `epoll_ctl`'s error
//! codes, a registered fd closed (its number reused, or a duplicate kept open), `maxevents`
//! rotation among ready registrations, eventfd counter, semaphore and argument rules, and the
//! hang-up bits of a half- and fully-shut stream. macOS: `EVFILT_READ` knotes added plain,
//! `EV_CLEAR`, `EV_ONESHOT` and `EV_DISPATCH` with `EV_DISABLE`/`EV_ENABLE`, `EVFILT_USER` in
//! every mode, and the per-change errors `EV_RECEIPT` and a plain change list return. Both:
//! `poll` over a closed or negative fd, after the peer closed, and on a refused nonblocking
//! connect; a `mio::Waker` woken many times before a poll; the exact virtual microsecond each
//! readiness call that returns without blocking is charged; and `select`, which is not modelled.
//!
//! Every `*_os_truth` test runs one function on the host's loopback and in a sim and asserts the
//! same record, so the model is held to the kernel's answer, and the record itself is pinned.
//! Where the model departs from the kernel the `*_os_truth` test is ignored as a bug and a sim-only
//! test pins what the model does now.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use snare::Sim;

/// Held by every test of this file: several of them close an fd and use its number afterwards,
/// which another test opening a socket meanwhile would take.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn on_host<R>(f: impl FnOnce() -> R) -> R {
    let _serial = serial();
    f()
}

fn in_sim<R>(f: impl FnOnce() -> R) -> R {
    let _serial = serial();
    Sim::new().run(f)
}

fn in_deterministic<R>(f: impl FnOnce() -> R) -> R {
    let _serial = serial();
    Sim::builder()
        .deterministic()
        .stuck_after(Duration::from_secs(5))
        .build()
        .run(f)
}

#[cfg(target_os = "linux")]
fn in_simhost<R>(f: impl FnOnce() -> R) -> R {
    let _serial = serial();
    Sim::builder()
        .host(snare::HostProfile::new().build())
        .build()
        .run(f)
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

/// Lets a real kernel finish what a loopback write started; virtual (free) in a sim.
fn settle() {
    std::thread::sleep(Duration::from_millis(5));
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    settle();
    (client, server)
}

/// One `poll` with `timeout_ms`: its return and every revents.
fn poll(fds: &[(i32, i16)], timeout_ms: i32) -> (i32, Vec<i16>) {
    let mut pfds: Vec<libc::pollfd> = fds
        .iter()
        .map(|&(fd, events)| libc::pollfd {
            fd,
            events,
            revents: 0,
        })
        .collect();
    let n = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as _, timeout_ms) };
    assert!(n >= 0, "poll: {}", std::io::Error::last_os_error());
    (n, pfds.iter().map(|p| p.revents).collect())
}

#[cfg(target_os = "linux")]
mod epoll {
    use super::*;

    const IN: u32 = libc::EPOLLIN as u32;
    const OUT: u32 = libc::EPOLLOUT as u32;
    const ET: u32 = libc::EPOLLET as u32;
    const ONESHOT: u32 = libc::EPOLLONESHOT as u32;
    const RDHUP: u32 = libc::EPOLLRDHUP as u32;
    const HUP: u32 = libc::EPOLLHUP as u32;

    fn create() -> i32 {
        let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        assert!(ep >= 0);
        ep
    }

    fn ctl(ep: i32, op: i32, fd: i32, events: u32, data: u64) -> Result<(), i32> {
        let mut ev = libc::epoll_event { events, u64: data };
        if unsafe { libc::epoll_ctl(ep, op, fd, &mut ev) } == 0 {
            Ok(())
        } else {
            Err(errno())
        }
    }

    /// `epoll_wait` with room for `max` events: each `(events, data)`, sorted by data.
    fn wait(ep: i32, max: usize, timeout_ms: i32) -> Vec<(u32, u64)> {
        let mut out = vec![libc::epoll_event { events: 0, u64: 0 }; max];
        let n = unsafe { libc::epoll_wait(ep, out.as_mut_ptr(), max as i32, timeout_ms) };
        assert!(n >= 0, "epoll_wait: {}", std::io::Error::last_os_error());
        let mut got: Vec<(u32, u64)> = out[..n as usize]
            .iter()
            .map(|e| (e.events, e.u64))
            .collect();
        got.sort_unstable_by_key(|e| e.1);
        got
    }

    fn close(fd: i32) {
        unsafe { libc::close(fd) };
    }

    type Snap = [Vec<(u32, u64)>; 3];

    /// One connected stream registered `IN | OUT` level-triggered (data 1), `EPOLLET` (2) and
    /// `EPOLLONESHOT` (3) in three epoll sets, through the peer's writes, partial and full reads,
    /// and a one-shot re-armed for input only.
    fn modes_sequence() -> Vec<Snap> {
        let (mut client, mut server) = tcp_pair();
        client.set_nonblocking(true).unwrap();
        let fd = client.as_raw_fd();
        let eps = [create(), create(), create()];
        for (i, mode) in [0, ET, ONESHOT].into_iter().enumerate() {
            ctl(
                eps[i],
                libc::EPOLL_CTL_ADD,
                fd,
                IN | OUT | mode,
                i as u64 + 1,
            )
            .unwrap();
        }
        let snap = || eps.map(|e| wait(e, 8, 0));
        let mut seen = vec![snap(), snap()];
        server.write_all(b"ab").unwrap();
        settle();
        seen.push(snap());
        seen.push(snap());
        assert_eq!(client.read(&mut [0u8; 1]).unwrap(), 1);
        seen.push(snap());
        server.write_all(b"c").unwrap();
        settle();
        seen.push(snap());
        assert_eq!(client.read(&mut [0u8; 8]).unwrap(), 2);
        seen.push(snap());
        ctl(eps[2], libc::EPOLL_CTL_MOD, fd, IN | ONESHOT, 3).unwrap();
        seen.push(snap());
        server.write_all(b"d").unwrap();
        settle();
        seen.push(snap());
        seen.push(snap());
        ctl(eps[1], libc::EPOLL_CTL_MOD, fd, IN | OUT | ET, 2).unwrap();
        seen.push(snap());
        for ep in eps {
            close(ep);
        }
        seen
    }

    fn modes_expected() -> Vec<Snap> {
        let lt = |m| vec![(m, 1)];
        let et = |m| vec![(m, 2)];
        let os = |m| vec![(m, 3)];
        vec![
            [lt(OUT), et(OUT), os(OUT)],
            [lt(OUT), vec![], vec![]],
            [lt(IN | OUT), et(IN | OUT), vec![]],
            [lt(IN | OUT), vec![], vec![]],
            [lt(IN | OUT), vec![], vec![]],
            [lt(IN | OUT), et(IN | OUT), vec![]],
            [lt(OUT), vec![], vec![]],
            [lt(OUT), vec![], vec![]],
            [lt(IN | OUT), et(IN | OUT), os(IN)],
            [lt(IN | OUT), vec![], vec![]],
            [lt(IN | OUT), et(IN | OUT), vec![]],
        ]
    }

    #[test]
    fn level_edge_and_oneshot_masks() {
        assert_eq!(in_sim(modes_sequence), modes_expected());
    }

    #[test]
    fn level_edge_and_oneshot_masks_deterministic() {
        assert_eq!(in_deterministic(modes_sequence), modes_expected());
    }

    #[test]
    fn level_edge_and_oneshot_masks_os_truth() {
        assert_eq!(on_host(modes_sequence), modes_expected());
    }

    fn terminal_edges() -> Vec<Vec<(u32, u64)>> {
        let (client, server) = tcp_pair();
        client.set_nonblocking(true).unwrap();
        let ep = create();
        ctl(
            ep,
            libc::EPOLL_CTL_ADD,
            client.as_raw_fd(),
            IN | OUT | RDHUP | ET,
            1,
        )
        .unwrap();
        let mut seen = vec![wait(ep, 1, 0), wait(ep, 1, 0)];
        server.shutdown(Shutdown::Write).unwrap();
        settle();
        seen.push(wait(ep, 1, 0));
        seen.extend((0..3).map(|_| wait(ep, 1, 0)));
        drop(server);
        client.shutdown(Shutdown::Write).unwrap();
        settle();
        seen.push(wait(ep, 1, 0));
        seen.extend((0..3).map(|_| wait(ep, 1, 0)));
        close(ep);
        seen
    }

    #[test]
    fn terminal_edge_events_are_delivered_once_os_truth() {
        let real = on_host(terminal_edges);
        assert_eq!(
            real,
            vec![
                vec![(OUT, 1)],
                vec![],
                vec![(IN | OUT | RDHUP, 1)],
                vec![],
                vec![],
                vec![],
                vec![(IN | OUT | RDHUP | HUP, 1)],
                vec![],
                vec![],
                vec![],
            ]
        );
        assert_eq!(in_sim(terminal_edges), real);
        assert_eq!(in_deterministic(terminal_edges), real);
    }

    fn error_edges() -> Vec<Vec<(u32, u64)>> {
        let unused = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = unused.local_addr().unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        drop(unused);
        socket.connect(port).unwrap();
        let ep = create();
        ctl(ep, libc::EPOLL_CTL_ADD, socket.as_raw_fd(), IN | ET, 1).unwrap();
        let mut seen = vec![wait(ep, 1, 0)];
        for _ in 0..2 {
            socket.send(b"x").unwrap();
            settle();
            seen.push(wait(ep, 1, 0));
            seen.extend((0..3).map(|_| wait(ep, 1, 0)));
            assert_eq!(
                socket.take_error().unwrap().unwrap().raw_os_error(),
                Some(libc::ECONNREFUSED)
            );
        }
        close(ep);
        seen
    }

    #[test]
    fn a_new_error_rearms_an_edge_without_an_intermediate_poll_os_truth() {
        let real = on_host(error_edges);
        assert_eq!(
            real,
            vec![
                vec![],
                vec![(libc::EPOLLERR as u32, 1)],
                vec![],
                vec![],
                vec![],
                vec![(libc::EPOLLERR as u32, 1)],
                vec![],
                vec![],
                vec![]
            ]
        );
        assert_eq!(in_sim(error_edges), real);
        assert_eq!(in_deterministic(error_edges), real);
        assert_eq!(in_simhost(error_edges), real);
    }

    fn refused_edges() -> Vec<Vec<(u32, u64)>> {
        let (fd, _) = refused_socket();
        settle();
        let ep = create();
        ctl(ep, libc::EPOLL_CTL_ADD, fd, IN | OUT | ET, 1).unwrap();
        let seen = (0..4).map(|_| wait(ep, 1, 0)).collect();
        close(ep);
        close(fd);
        seen
    }

    #[test]
    fn a_refused_connection_reports_one_terminal_edge_os_truth() {
        let real = on_host(refused_edges);
        assert_eq!(
            real,
            vec![
                vec![(IN | OUT | HUP | libc::EPOLLERR as u32, 1)],
                vec![],
                vec![],
                vec![]
            ]
        );
        assert_eq!(in_sim(refused_edges), real);
        assert_eq!(in_deterministic(refused_edges), real);
    }

    #[test]
    fn a_delayed_ack_rearms_an_undrained_timestamp_edge() {
        in_sim(|| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            snare::set_tcp_policy(addr, |p| p.latency = Duration::from_millis(20));
            let mut client = TcpStream::connect(addr).unwrap();
            let (_server, _) = listener.accept().unwrap();
            let flags: u32 = (1 << 1) | (1 << 4) | (1 << 9) | (1 << 11);
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        client.as_raw_fd(),
                        libc::SOL_SOCKET,
                        37,
                        (&raw const flags).cast(),
                        size_of::<u32>() as _,
                    )
                },
                0
            );
            let ep = create();
            ctl(ep, libc::EPOLL_CTL_ADD, client.as_raw_fd(), ET, 1).unwrap();
            client.write_all(b"x").unwrap();
            let error = vec![(libc::EPOLLERR as u32, 1)];
            assert_eq!(wait(ep, 1, 0), error);
            assert!(wait(ep, 1, 0).is_empty());
            std::thread::sleep(Duration::from_millis(30));
            assert!(wait(ep, 1, 0).is_empty());
            std::thread::sleep(Duration::from_millis(20));
            assert_eq!(wait(ep, 1, 0), error);
            assert!(wait(ep, 1, 0).is_empty());
            close(ep);
        });
    }

    fn timestamp_edges() -> Vec<Vec<(u32, u64)>> {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let flags: u32 = (1 << 1) | (1 << 4) | (1 << 11);
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    tx.as_raw_fd(),
                    libc::SOL_SOCKET,
                    37,
                    (&raw const flags).cast(),
                    size_of::<u32>() as _,
                )
            },
            0
        );
        let ep = create();
        ctl(ep, libc::EPOLL_CTL_ADD, tx.as_raw_fd(), ET, 1).unwrap();
        let mut seen = vec![wait(ep, 1, 0)];
        for _ in 0..2 {
            tx.send_to(b"x", rx.local_addr().unwrap()).unwrap();
            settle();
            seen.push(wait(ep, 1, 0));
            seen.push(wait(ep, 1, 0));
        }
        close(ep);
        seen
    }

    #[test]
    fn a_new_timestamp_rearms_an_undrained_error_queue_os_truth() {
        let real = on_host(timestamp_edges);
        assert_eq!(
            real,
            vec![
                vec![],
                vec![(libc::EPOLLERR as u32, 1)],
                vec![],
                vec![(libc::EPOLLERR as u32, 1)],
                vec![]
            ]
        );
        assert_eq!(in_sim(timestamp_edges), real);
        assert_eq!(in_deterministic(timestamp_edges), real);
        assert_eq!(in_simhost(timestamp_edges), real);
    }

    fn consumed_pending_error_edges() -> Vec<Vec<(u32, u64)>> {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let unused = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = unused.local_addr().unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let flags = (1u32 << 1) | (1 << 4) | (1 << 11);
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    tx.as_raw_fd(),
                    libc::SOL_SOCKET,
                    37,
                    (&raw const flags).cast(),
                    size_of::<u32>() as _,
                )
            },
            0
        );
        let ep = create();
        ctl(ep, libc::EPOLL_CTL_ADD, tx.as_raw_fd(), ET, 1).unwrap();
        tx.send_to(b"stamp", rx.local_addr().unwrap()).unwrap();
        settle();
        let mut seen = vec![wait(ep, 1, 0), wait(ep, 1, 0)];
        let disabled = 0u32;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    tx.as_raw_fd(),
                    libc::SOL_SOCKET,
                    37,
                    (&raw const disabled).cast(),
                    size_of::<u32>() as _,
                )
            },
            0
        );
        drop(unused);
        tx.connect(port).unwrap();
        tx.send(b"icmp").unwrap();
        settle();
        assert_eq!(
            tx.take_error().unwrap().unwrap().raw_os_error(),
            Some(libc::ECONNREFUSED)
        );
        seen.push(wait(ep, 1, 0));
        seen.push(wait(ep, 1, 0));
        close(ep);
        seen
    }

    #[test]
    fn taking_so_error_preserves_a_new_error_edge_os_truth() {
        let real = on_host(consumed_pending_error_edges);
        let error = vec![(libc::EPOLLERR as u32, 1)];
        assert_eq!(real, vec![error.clone(), vec![], error, vec![]]);
        assert_eq!(in_sim(consumed_pending_error_edges), real);
        assert_eq!(in_deterministic(consumed_pending_error_edges), real);
        assert_eq!(in_simhost(consumed_pending_error_edges), real);
    }

    fn queued_icmp_readiness() -> Vec<Vec<(u32, u64)>> {
        let unused = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = unused.local_addr().unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        drop(unused);
        socket.connect(port).unwrap();
        let enabled = 1i32;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_IP,
                    libc::IP_RECVERR,
                    (&raw const enabled).cast(),
                    size_of::<i32>() as _,
                )
            },
            0
        );
        let ep = create();
        ctl(ep, libc::EPOLL_CTL_ADD, socket.as_raw_fd(), IN | ET, 1).unwrap();
        socket.send(b"x").unwrap();
        settle();
        assert_eq!(
            socket.take_error().unwrap().unwrap().raw_os_error(),
            Some(libc::ECONNREFUSED)
        );
        let mut seen = vec![wait(ep, 1, 0), wait(ep, 1, 0)];
        ctl(ep, libc::EPOLL_CTL_MOD, socket.as_raw_fd(), IN, 1).unwrap();
        seen.push(wait(ep, 1, 0));
        seen.push(wait(ep, 1, 0));
        let mut payload = [0u8; 8];
        let mut control = [0usize; 64];
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of_val(&control);
        assert!(
            unsafe {
                libc::recvmsg(
                    socket.as_raw_fd(),
                    &raw mut msg,
                    libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT,
                )
            } >= 0
        );
        seen.push(wait(ep, 1, 0));
        close(ep);
        seen
    }

    #[test]
    fn clearing_so_error_preserves_queued_icmp_readiness_os_truth() {
        let real = on_host(queued_icmp_readiness);
        let error = vec![(libc::EPOLLERR as u32, 1)];
        assert_eq!(
            real,
            vec![error.clone(), vec![], error.clone(), error, vec![]]
        );
        assert_eq!(in_sim(queued_icmp_readiness), real);
        assert_eq!(in_deterministic(queued_icmp_readiness), real);
        assert_eq!(in_simhost(queued_icmp_readiness), real);
    }

    /// `epoll_ctl`'s answer to: ADD, ADD again, MOD and DEL of an unregistered fd, DEL, DEL
    /// again, an unknown op, a non-epoll `epfd`, the set added to itself, and a closed fd.
    fn ctl_codes() -> Vec<Result<(), i32>> {
        let ep = create();
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let closed = UdpSocket::bind("127.0.0.1:0").unwrap();
        let closed_fd = closed.as_raw_fd();
        drop(closed);
        let (a, b) = (a.as_raw_fd(), b.as_raw_fd());
        let codes = vec![
            ctl(ep, libc::EPOLL_CTL_ADD, a, IN, 1),
            ctl(ep, libc::EPOLL_CTL_ADD, a, IN, 1),
            ctl(ep, libc::EPOLL_CTL_MOD, b, IN, 2),
            ctl(ep, libc::EPOLL_CTL_DEL, b, 0, 0),
            ctl(ep, libc::EPOLL_CTL_DEL, a, 0, 0),
            ctl(ep, libc::EPOLL_CTL_DEL, a, 0, 0),
            ctl(ep, 99, a, IN, 1),
            ctl(a, libc::EPOLL_CTL_ADD, b, IN, 2),
            ctl(ep, libc::EPOLL_CTL_ADD, ep, IN, 3),
            ctl(ep, libc::EPOLL_CTL_ADD, closed_fd, IN, 4),
        ];
        close(ep);
        codes
    }

    #[test]

    fn ctl_codes_os_truth() {
        let real = on_host(ctl_codes);
        assert_eq!(
            real,
            [
                Ok(()),
                Err(libc::EEXIST),
                Err(libc::ENOENT),
                Err(libc::ENOENT),
                Ok(()),
                Err(libc::ENOENT),
                Err(libc::EINVAL),
                Err(libc::EINVAL),
                Err(libc::EINVAL),
                Err(libc::EBADF),
            ]
        );
        assert_eq!(in_sim(ctl_codes), real);
    }

    #[test]
    fn ctl_codes_real_os() {
        assert_eq!(
            on_host(ctl_codes),
            [
                Ok(()),
                Err(libc::EEXIST),
                Err(libc::ENOENT),
                Err(libc::ENOENT),
                Ok(()),
                Err(libc::ENOENT),
                Err(libc::EINVAL),
                Err(libc::EINVAL),
                Err(libc::EINVAL),
                Err(libc::EBADF),
            ]
        );
    }

    /// A registered socket closed and a new one opened on the same fd number, never registered,
    /// then sent a datagram: whether the number was reused, and what the set reports.
    fn closed_then_reused() -> (bool, Vec<(u32, u64)>) {
        let ep = create();
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = a.as_raw_fd();
        ctl(ep, libc::EPOLL_CTL_ADD, fd, IN, 1).unwrap();
        drop(a);
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let reused = b.as_raw_fd() == fd;
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(b"x", b.local_addr().unwrap()).unwrap();
        settle();
        let got = wait(ep, 8, 0);
        close(ep);
        (reused, got)
    }

    #[test]

    fn closed_fd_reused_os_truth() {
        let real = on_host(closed_then_reused);
        assert_eq!(real, (true, vec![]));
        assert_eq!(in_sim(closed_then_reused), real);
    }

    /// A registered socket duplicated (`try_clone`, `F_DUPFD_CLOEXEC`), the registered fd closed,
    /// then a datagram sent to it: what the set reports.
    fn dup_kept_open() -> Vec<(u32, u64)> {
        let ep = create();
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = a.local_addr().unwrap();
        let copy = a.try_clone().unwrap();
        ctl(ep, libc::EPOLL_CTL_ADD, a.as_raw_fd(), IN, 1).unwrap();
        drop(a);
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(b"x", addr).unwrap();
        settle();
        let got = wait(ep, 8, 0);
        drop(copy);
        assert!(wait(ep, 8, 0).is_empty());
        close(ep);
        got
    }

    #[test]

    fn dup_kept_open_os_truth() {
        let real = on_host(dup_kept_open);
        assert_eq!(real, vec![(IN, 1)]);
        assert_eq!(in_sim(dup_kept_open), real);
        assert_eq!(in_simhost(dup_kept_open), real);
    }

    fn efd(init: u32, flags: i32) -> i32 {
        let fd = unsafe { libc::eventfd(init, flags | libc::EFD_CLOEXEC) };
        assert!(fd >= 0);
        fd
    }

    fn efd_write(fd: i32, v: u64) -> Result<usize, i32> {
        let n = unsafe { libc::write(fd, v.to_ne_bytes().as_ptr().cast(), 8) };
        if n < 0 { Err(errno()) } else { Ok(n as usize) }
    }

    fn efd_read(fd: i32) -> Result<u64, i32> {
        let mut b = [0u8; 8];
        let n = unsafe { libc::read(fd, b.as_mut_ptr().cast(), 8) };
        if n < 0 {
            Err(errno())
        } else {
            assert_eq!(n, 8);
            Ok(u64::from_ne_bytes(b))
        }
    }

    /// Two eventfds, both ready, in one set with room for one event per wait: level-triggered
    /// (data 1, 2) four waits, then edge-triggered (3, 4) three waits.
    fn maxevents_one() -> Vec<Vec<u64>> {
        let ep = create();
        let fds = [efd(0, libc::EFD_NONBLOCK), efd(0, libc::EFD_NONBLOCK)];
        ctl(ep, libc::EPOLL_CTL_ADD, fds[0], IN, 1).unwrap();
        ctl(ep, libc::EPOLL_CTL_ADD, fds[1], IN, 2).unwrap();
        efd_write(fds[0], 1).unwrap();
        efd_write(fds[1], 1).unwrap();
        let datas = |ep| wait(ep, 1, 0).into_iter().map(|e| e.1).collect::<Vec<_>>();
        let mut seen: Vec<Vec<u64>> = (0..4).map(|_| datas(ep)).collect();
        let et = create();
        let efds = [efd(0, libc::EFD_NONBLOCK), efd(0, libc::EFD_NONBLOCK)];
        ctl(et, libc::EPOLL_CTL_ADD, efds[0], IN | ET, 3).unwrap();
        ctl(et, libc::EPOLL_CTL_ADD, efds[1], IN | ET, 4).unwrap();
        efd_write(efds[0], 1).unwrap();
        efd_write(efds[1], 1).unwrap();
        let mut et_seen: Vec<Vec<u64>> = (0..3).map(|_| datas(et)).collect();
        et_seen[..2].sort();
        seen.extend(et_seen);
        for fd in fds.into_iter().chain(efds).chain([ep, et]) {
            close(fd);
        }
        seen
    }

    #[test]

    fn maxevents_one_os_truth() {
        let real = on_host(maxevents_one);
        assert_eq!(
            real,
            [vec![1], vec![2], vec![1], vec![2], vec![3], vec![4], vec![]]
        );
        assert_eq!(in_sim(maxevents_one), real);
    }

    /// eventfd reads and writes: semaphore mode, the whole counter, a zero write, short buffers,
    /// the `u64::MAX` write, a long read buffer, and what poll says of an empty and a set
    /// counter.
    fn eventfd_rules() -> Vec<String> {
        let mut out = Vec::new();
        let sem = efd(3, libc::EFD_NONBLOCK | libc::EFD_SEMAPHORE);
        for _ in 0..4 {
            out.push(format!("sem {:?}", efd_read(sem)));
        }
        let fd = efd(0, libc::EFD_NONBLOCK);
        out.push(format!(
            "empty {:?} {:?}",
            efd_read(fd),
            poll(&[(fd, libc::POLLIN | libc::POLLOUT)], 0)
        ));
        out.push(format!(
            "w2 {:?} w5 {:?}",
            efd_write(fd, 2),
            efd_write(fd, 5)
        ));
        out.push(format!(
            "set {:?}",
            poll(&[(fd, libc::POLLIN | libc::POLLOUT)], 0)
        ));
        out.push(format!("all {:?} then {:?}", efd_read(fd), efd_read(fd)));
        out.push(format!("w0 {:?} then {:?}", efd_write(fd, 0), efd_read(fd)));
        let short_read = unsafe { libc::read(fd, [0u8; 4].as_mut_ptr().cast(), 4) };
        out.push(format!("short read {short_read} {}", errno()));
        let short_write = unsafe { libc::write(fd, 1u32.to_ne_bytes().as_ptr().cast(), 4) };
        out.push(format!("short write {short_write} {}", errno()));
        out.push(format!("max {:?}", efd_write(fd, u64::MAX)));
        efd_write(fd, 9).unwrap();
        let mut long = [0u8; 16];
        let n = unsafe { libc::read(fd, long.as_mut_ptr().cast(), 16) };
        out.push(format!("long {n} {:?}", &long[..8]));
        close(sem);
        close(fd);
        out
    }

    #[test]
    fn eventfd_rules_os_truth() {
        let real = on_host(eventfd_rules);
        assert_eq!(
            real,
            [
                "sem Ok(1)",
                "sem Ok(1)",
                "sem Ok(1)",
                "sem Err(11)",
                "empty Err(11) (1, [4])",
                "w2 Ok(8) w5 Ok(8)",
                "set (1, [5])",
                "all Ok(7) then Err(11)",
                "w0 Ok(8) then Err(11)",
                "short read -1 22",
                "short write -1 22",
                "max Err(22)",
                "long 8 [9, 0, 0, 0, 0, 0, 0, 0]",
            ]
        );
        assert_eq!(in_sim(eventfd_rules), real);
    }

    fn closed_eventfd_reused() -> (bool, Vec<(u32, u64)>) {
        let ep = create();
        let fd = efd(0, libc::EFD_NONBLOCK);
        ctl(ep, libc::EPOLL_CTL_ADD, fd, IN, 1).unwrap();
        close(fd);
        let replacement = efd(1, libc::EFD_NONBLOCK);
        let reused = replacement == fd;
        let got = wait(ep, 8, 0);
        close(replacement);
        close(ep);
        (reused, got)
    }

    #[test]
    fn closed_eventfd_reused_os_truth() {
        let real = on_host(closed_eventfd_reused);
        assert_eq!(real, (true, vec![]));
        assert_eq!(in_sim(closed_eventfd_reused), real);
        assert_eq!(in_deterministic(closed_eventfd_reused), real);
        assert_eq!(in_simhost(closed_eventfd_reused), real);
    }

    fn eventfd_aliases_and_reuse() -> Vec<Vec<(u32, u64)>> {
        let original_ep = create();
        let ep = unsafe { libc::dup(original_ep) };
        assert!(ep >= 0);
        assert_eq!(
            ctl(ep, libc::EPOLL_CTL_ADD, original_ep, IN, 0),
            Err(libc::EINVAL)
        );
        close(original_ep);
        let original = efd(0, libc::EFD_NONBLOCK);
        let copy = unsafe { libc::dup(original) };
        assert!(copy >= 0);
        ctl(ep, libc::EPOLL_CTL_ADD, original, IN, 1).unwrap();
        close(original);
        let replacement = efd(1, libc::EFD_NONBLOCK);
        assert_eq!(replacement, original);
        let mut seen = vec![wait(ep, 8, 0)];
        ctl(ep, libc::EPOLL_CTL_ADD, replacement, IN, 2).unwrap();
        efd_write(copy, 1).unwrap();
        seen.push(wait(ep, 8, 0));
        close(copy);
        seen.push(wait(ep, 8, 0));
        close(replacement);
        seen.push(wait(ep, 8, 0));
        close(ep);
        seen
    }

    #[test]
    fn eventfd_aliases_and_reuse_os_truth() {
        let real = on_host(eventfd_aliases_and_reuse);
        assert_eq!(
            real,
            vec![vec![], vec![(IN, 1), (IN, 2)], vec![(IN, 2)], vec![]]
        );
        assert_eq!(in_sim(eventfd_aliases_and_reuse), real);
        assert_eq!(in_deterministic(eventfd_aliases_and_reuse), real);
        assert_eq!(in_simhost(eventfd_aliases_and_reuse), real);
    }

    /// A nonblocking eventfd filled to the largest counter, then written once more.
    fn eventfd_full() -> (Result<usize, i32>, Result<usize, i32>) {
        let fd = efd(0, libc::EFD_NONBLOCK);
        let fill = efd_write(fd, u64::MAX - 1);
        let more = efd_write(fd, 1);
        close(fd);
        (fill, more)
    }

    #[test]

    fn eventfd_full_os_truth() {
        let real = on_host(eventfd_full);
        assert_eq!(real, (Ok(8), Err(libc::EAGAIN)));
        assert_eq!(in_sim(eventfd_full), real);
    }

    /// A stream registered `IN | OUT | RDHUP` level-triggered and polled for the same, as the
    /// peer shuts its sending side, then this end shuts its own.
    fn hangup_masks() -> Vec<(Vec<(u32, u64)>, i16)> {
        let (client, server) = tcp_pair();
        let fd = client.as_raw_fd();
        let ep = create();
        ctl(ep, libc::EPOLL_CTL_ADD, fd, IN | OUT | RDHUP, 1).unwrap();
        let snap = || {
            let (_, r) = poll(&[(fd, libc::POLLIN | libc::POLLOUT | libc::POLLRDHUP)], 0);
            (wait(ep, 8, 0), r[0])
        };
        let mut seen = vec![snap()];
        server.shutdown(Shutdown::Write).unwrap();
        settle();
        seen.push(snap());
        client.shutdown(Shutdown::Write).unwrap();
        settle();
        seen.push(snap());
        close(ep);
        seen
    }

    #[test]

    fn hangup_masks_os_truth() {
        let real = on_host(hangup_masks);
        let rd = libc::POLLIN | libc::POLLOUT | libc::POLLRDHUP;
        assert_eq!(
            real,
            [
                (vec![(OUT, 1)], libc::POLLOUT),
                (vec![(IN | OUT | RDHUP, 1)], rd),
                (vec![(IN | OUT | RDHUP | HUP, 1)], rd | libc::POLLHUP),
            ]
        );
        assert_eq!(in_sim(hangup_masks), real);
    }
}

#[cfg(target_os = "macos")]
mod kqueue {
    use super::*;

    fn kev(ident: usize, filter: i16, flags: u16, fflags: u32, udata: u64) -> libc::kevent {
        libc::kevent {
            ident,
            filter,
            flags,
            fflags,
            data: 0,
            udata: udata as *mut libc::c_void,
        }
    }

    fn create() -> i32 {
        let kq = unsafe { libc::kqueue() };
        assert!(kq >= 0);
        kq
    }

    /// Applies `changes` with no room for events: the return, or the errno.
    fn apply(kq: i32, changes: &[libc::kevent]) -> Result<i32, i32> {
        let n = unsafe {
            libc::kevent(
                kq,
                changes.as_ptr(),
                changes.len() as i32,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if n < 0 { Err(errno()) } else { Ok(n) }
    }

    /// A zero-timeout `kevent`: each event's `(udata, filter, flags, fflags, data)`, sorted.
    fn take(kq: i32) -> Vec<(u64, i16, u16, u32, i64)> {
        let mut out = [kev(0, 0, 0, 0, 0); 16];
        let ts0 = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, out.as_mut_ptr(), 16, &ts0) };
        assert!(n >= 0, "kevent: {}", std::io::Error::last_os_error());
        let mut got: Vec<_> = out[..n as usize]
            .iter()
            .map(|e| (e.udata as u64, e.filter, e.flags, e.fflags, e.data as i64))
            .collect();
        got.sort_unstable();
        got
    }

    /// The `udata`s of a [`take`].
    fn udatas(kq: i32) -> Vec<u64> {
        take(kq).into_iter().map(|e| e.0).collect()
    }

    type ErrorEvent = (u64, i16, u16, u32, i64);

    fn capped_datagram_edges() -> Vec<(u64, i64)> {
        let sockets: Vec<_> = (0..3)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let kq = create();
        let changes: Vec<_> = sockets
            .iter()
            .enumerate()
            .map(|(i, s)| {
                kev(
                    s.as_raw_fd() as _,
                    libc::EVFILT_READ,
                    libc::EV_ADD | libc::EV_CLEAR,
                    0,
                    i as _,
                )
            })
            .collect();
        apply(kq, &changes).unwrap();
        assert!(take(kq).is_empty());
        let lengths = [1, 9, 8192];
        for (s, &len) in sockets.iter().zip(&lengths) {
            tx.send_to(&vec![len as u8; len], s.local_addr().unwrap())
                .unwrap();
        }
        settle();
        let mut got = Vec::new();
        for _ in 0..sockets.len() {
            let mut ev = kev(0, 0, 0, 0, 0);
            let ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            assert_eq!(
                unsafe { libc::kevent(kq, std::ptr::null(), 0, &mut ev, 1, &ts) },
                1
            );
            got.push((ev.udata as u64, ev.data as i64));
        }
        assert!(take(kq).is_empty());
        let mut buf = vec![0; 8192];
        for (s, &len) in sockets.iter().zip(&lengths) {
            assert_eq!(s.recv(&mut buf).unwrap(), len);
            assert!(buf[..len].iter().all(|&b| b == len as u8));
        }
        tx.send_to(b"next", sockets[1].local_addr().unwrap())
            .unwrap();
        settle();
        let next = take(kq);
        assert_eq!(next.len(), 1);
        assert_eq!((next[0].0, next[0].4), (1, 4));
        assert!(take(kq).is_empty());
        unsafe { libc::close(kq) };
        got.sort_unstable();
        got
    }

    #[test]
    fn capped_zero_timeout_polls_preserve_datagram_edges_and_payloads_os_truth() {
        let real = on_host(capped_datagram_edges);
        assert_eq!(real, [(0, 1), (1, 9), (2, 8192)]);
        assert_eq!(in_sim(capped_datagram_edges), real);
        assert_eq!(in_deterministic(capped_datagram_edges), real);
    }

    fn capped_read_write_edges() -> Vec<u64> {
        let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        b.write_all(b"buffered").unwrap();
        let kq = create();
        apply(
            kq,
            &[
                kev(
                    a.as_raw_fd() as _,
                    libc::EVFILT_READ,
                    libc::EV_ADD | libc::EV_CLEAR,
                    0,
                    31,
                ),
                kev(
                    a.as_raw_fd() as _,
                    libc::EVFILT_WRITE,
                    libc::EV_ADD | libc::EV_CLEAR,
                    0,
                    42,
                ),
            ],
        )
        .unwrap();
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let got = (0..2)
            .map(|_| {
                let mut ev = kev(0, 0, 0, 0, 0);
                assert_eq!(
                    unsafe { libc::kevent(kq, std::ptr::null(), 0, &mut ev, 1, &ts) },
                    1
                );
                ev.udata as u64
            })
            .collect();
        assert!(take(kq).is_empty());
        let mut buf = [0; 8];
        (&a).read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"buffered");
        unsafe { libc::close(kq) };
        got
    }

    #[test]
    fn capped_zero_timeout_polls_report_read_before_write_os_truth() {
        let real = on_host(capped_read_write_edges);
        assert_eq!(real, [31, 42]);
        assert_eq!(in_sim(capped_read_write_edges), real);
        assert_eq!(in_deterministic(capped_read_write_edges), real);
    }

    fn settled_error_edges() -> Vec<Vec<ErrorEvent>> {
        let (fd, _) = refused_socket();
        settle();
        let kq = create();
        apply(
            kq,
            &[
                kev(
                    fd as _,
                    libc::EVFILT_READ,
                    libc::EV_ADD | libc::EV_CLEAR,
                    0,
                    1,
                ),
                kev(
                    fd as _,
                    libc::EVFILT_WRITE,
                    libc::EV_ADD | libc::EV_CLEAR,
                    0,
                    2,
                ),
            ],
        )
        .unwrap();
        let result = (0..4).map(|_| take(kq)).collect();
        unsafe {
            libc::close(kq);
            libc::close(fd);
        }
        result
    }

    #[test]
    fn a_settled_error_does_not_repeat_under_ev_clear_os_truth() {
        let real = on_host(settled_error_edges);
        assert_eq!(real[0].len(), 2);
        assert!(real[1..].iter().all(Vec::is_empty));
        assert_eq!(in_sim(settled_error_edges), real);
        assert_eq!(in_deterministic(settled_error_edges), real);
    }

    fn failed_write_buffer_metadata() -> Vec<(i32, i64)> {
        [None, Some(1024i32), Some(4096), Some(65536)]
            .into_iter()
            .map(|value| {
                let (fd, _) = refused_socket_with_buffer(value);
                settle();
                let mut sndbuf = 0i32;
                let mut len = size_of::<i32>() as libc::socklen_t;
                assert_eq!(
                    unsafe {
                        libc::getsockopt(
                            fd,
                            libc::SOL_SOCKET,
                            libc::SO_SNDBUF,
                            (&raw mut sndbuf).cast(),
                            &raw mut len,
                        )
                    },
                    0
                );
                let kq = create();
                apply(
                    kq,
                    &[kev(
                        fd as _,
                        libc::EVFILT_WRITE,
                        libc::EV_ADD | libc::EV_CLEAR,
                        0,
                        1,
                    )],
                )
                .unwrap();
                let event = take(kq).pop().unwrap();
                unsafe {
                    libc::close(kq);
                    libc::close(fd);
                }
                (sndbuf, event.4)
            })
            .collect()
    }

    #[test]
    fn failed_write_buffer_metadata_os_truth() {
        let real = on_host(failed_write_buffer_metadata);
        assert_eq!(in_sim(failed_write_buffer_metadata), real);
        assert_eq!(in_deterministic(failed_write_buffer_metadata), real);
    }

    /// Four socketpair ends registered `EVFILT_READ` plain (udata 1), `EV_CLEAR` (2),
    /// `EV_ONESHOT` (3) and `EV_DISPATCH` (4), through writes, a re-enable, disabling the plain
    /// one, partial and full reads.
    fn read_modes() -> Vec<Vec<u64>> {
        let kq = create();
        let pairs: Vec<_> = (0..4)
            .map(|_| std::os::unix::net::UnixStream::pair().unwrap())
            .collect();
        for (a, _) in &pairs {
            a.set_nonblocking(true).unwrap();
        }
        let modes = [0, libc::EV_CLEAR, libc::EV_ONESHOT, libc::EV_DISPATCH];
        let changes: Vec<_> = pairs
            .iter()
            .zip(modes)
            .enumerate()
            .map(|(i, ((a, _), mode))| {
                kev(
                    a.as_raw_fd() as usize,
                    libc::EVFILT_READ,
                    libc::EV_ADD | mode,
                    0,
                    i as u64 + 1,
                )
            })
            .collect();
        assert_eq!(apply(kq, &changes), Ok(0));
        let write_all = |pairs: &[(
            std::os::unix::net::UnixStream,
            std::os::unix::net::UnixStream,
        )]| {
            for (_, b) in pairs {
                (&*b).write_all(b"xy").unwrap();
            }
        };
        let mut seen = vec![udatas(kq)];
        write_all(&pairs);
        seen.push(udatas(kq));
        seen.push(udatas(kq));
        write_all(&pairs);
        seen.push(udatas(kq));
        let fd = |i: usize| pairs[i].0.as_raw_fd() as usize;
        assert_eq!(
            apply(kq, &[kev(fd(3), libc::EVFILT_READ, libc::EV_ENABLE, 0, 4)]),
            Ok(0)
        );
        seen.push(udatas(kq));
        assert_eq!(
            apply(kq, &[kev(fd(0), libc::EVFILT_READ, libc::EV_DISABLE, 0, 1)]),
            Ok(0)
        );
        seen.push(udatas(kq));
        for (a, _) in &pairs {
            assert_eq!((&*a).read(&mut [0u8; 1]).unwrap(), 1);
        }
        seen.push(udatas(kq));
        assert_eq!(
            apply(kq, &[kev(fd(0), libc::EVFILT_READ, libc::EV_ENABLE, 0, 1)]),
            Ok(0)
        );
        seen.push(udatas(kq));
        for (a, _) in &pairs {
            assert_eq!((&*a).read(&mut [0u8; 8]).unwrap(), 3);
        }
        seen.push(udatas(kq));
        assert_eq!(
            apply(kq, &[kev(fd(3), libc::EVFILT_READ, libc::EV_ENABLE, 0, 4)]),
            Ok(0)
        );
        write_all(&pairs);
        seen.push(udatas(kq));
        unsafe { libc::close(kq) };
        seen
    }

    fn read_modes_expected() -> Vec<Vec<u64>> {
        vec![
            vec![],
            vec![1, 2, 3, 4],
            vec![1],
            vec![1, 2],
            vec![1, 4],
            vec![],
            vec![],
            vec![1],
            vec![],
            vec![1, 2, 4],
        ]
    }

    #[test]
    fn read_modes_sequence() {
        assert_eq!(in_sim(read_modes), read_modes_expected());
    }

    #[test]
    fn read_modes_sequence_deterministic() {
        assert_eq!(in_deterministic(read_modes), read_modes_expected());
    }

    #[test]
    fn read_modes_sequence_os_truth() {
        assert_eq!(on_host(read_modes), read_modes_expected());
    }

    /// One socketpair end with three bytes waiting, registered plain for reading and writing:
    /// every field of the two events.
    fn event_fields() -> Vec<(u64, i16, u16, u32, i64)> {
        let kq = create();
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        (&b).write_all(b"abc").unwrap();
        let fd = a.as_raw_fd() as usize;
        assert_eq!(
            apply(
                kq,
                &[
                    kev(fd, libc::EVFILT_READ, libc::EV_ADD, 0, 1),
                    kev(fd, libc::EVFILT_WRITE, libc::EV_ADD, 0, 2),
                ]
            ),
            Ok(0)
        );
        let got = take(kq);
        unsafe { libc::close(kq) };
        got
    }

    #[test]

    fn event_fields_os_truth() {
        let real = on_host(event_fields);
        assert_eq!(
            real,
            [
                (1, libc::EVFILT_READ, libc::EV_ADD, 0, 3),
                (2, libc::EVFILT_WRITE, libc::EV_ADD, 0, 8192)
            ]
        );
        assert_eq!(in_sim(event_fields), real);
    }

    /// User events added plain (1), `EV_CLEAR` (2), `EV_ONESHOT` (3) and `EV_DISPATCH` (4): what
    /// each zero-timeout `kevent` reports as they are triggered, re-enabled and deleted, and what
    /// the second trigger of all four, after the one-shot was reported, returns.
    fn user_modes() -> (Vec<Vec<u64>>, Result<i32, i32>) {
        let kq = create();
        let modes = [0, libc::EV_CLEAR, libc::EV_ONESHOT, libc::EV_DISPATCH];
        let adds: Vec<_> = modes
            .iter()
            .enumerate()
            .map(|(i, m)| kev(i + 1, libc::EVFILT_USER, libc::EV_ADD | m, 0, i as u64 + 1))
            .collect();
        assert_eq!(apply(kq, &adds), Ok(0));
        let trigger_all = || {
            let t: Vec<_> = (1..=4)
                .map(|i| kev(i, libc::EVFILT_USER, 0, libc::NOTE_TRIGGER, i as u64))
                .collect();
            apply(kq, &t)
        };
        let mut seen = vec![udatas(kq)];
        assert_eq!(trigger_all(), Ok(0));
        seen.push(udatas(kq));
        seen.push(udatas(kq));
        let again = trigger_all();
        seen.push(udatas(kq));
        assert_eq!(
            apply(kq, &[kev(4, libc::EVFILT_USER, libc::EV_ENABLE, 0, 4)]),
            Ok(0)
        );
        seen.push(udatas(kq));
        assert_eq!(
            apply(kq, &[kev(1, libc::EVFILT_USER, libc::EV_DELETE, 0, 1)]),
            Ok(0)
        );
        seen.push(udatas(kq));
        unsafe { libc::close(kq) };
        (seen, again)
    }

    #[test]

    fn user_modes_os_truth() {
        let real = on_host(user_modes);
        assert_eq!(
            real,
            (
                vec![
                    vec![],
                    vec![1, 2, 3, 4],
                    vec![1],
                    vec![1, 2],
                    vec![1, 4],
                    vec![]
                ],
                Err(libc::ENOENT)
            )
        );
        assert_eq!(in_sim(user_modes), real);
    }

    /// Changes that fail, each alone with `EV_RECEIPT` (the receipt's `flags` and `data`), and a
    /// failing change in a plain list with no room for events (the call's return).
    fn change_errors() -> Vec<String> {
        let kq = create();
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let closed = std::os::unix::net::UnixStream::pair()
            .unwrap()
            .0
            .as_raw_fd() as usize;
        let fd = a.as_raw_fd() as usize;
        let changes = [
            kev(fd, libc::EVFILT_READ, libc::EV_ADD, 0, 1),
            kev(fd, libc::EVFILT_WRITE, libc::EV_DELETE, 0, 2),
            kev(9, libc::EVFILT_USER, libc::EV_DELETE, 0, 3),
            kev(9, libc::EVFILT_USER, 0, libc::NOTE_TRIGGER, 4),
            kev(closed, libc::EVFILT_READ, libc::EV_ADD, 0, 5),
        ];
        let mut out = Vec::new();
        for mut ch in changes {
            ch.flags |= libc::EV_RECEIPT;
            let mut r = [kev(0, 0, 0, 0, 0)];
            let n = unsafe { libc::kevent(kq, &ch, 1, r.as_mut_ptr(), 1, std::ptr::null()) };
            out.push(format!(
                "receipt {n} flags {:#x} data {}",
                { r[0].flags },
                { r[0].data }
            ));
        }
        for ch in &changes[1..] {
            out.push(format!("plain {:?}", apply(kq, std::slice::from_ref(ch))));
        }
        unsafe { libc::close(kq) };
        out
    }

    #[test]

    fn change_errors_os_truth() {
        let real = on_host(change_errors);
        assert_eq!(
            real,
            [
                "receipt 1 flags 0x4041 data 0",
                "receipt 1 flags 0x4042 data 2",
                "receipt 1 flags 0x4042 data 2",
                "receipt 1 flags 0x4040 data 2",
                "receipt 1 flags 0x4041 data 9",
                "plain Err(2)",
                "plain Err(2)",
                "plain Err(2)",
                "plain Err(9)",
            ]
        );
        assert_eq!(in_sim(change_errors), real);
    }
}

/// Polls of a live socket beside a closed fd, and beside a negative one.
fn poll_odd_fds() -> Vec<(i32, Vec<i16>)> {
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let gone = UdpSocket::bind("127.0.0.1:0").unwrap();
    let gone_fd = gone.as_raw_fd();
    drop(gone);
    let both = libc::POLLIN | libc::POLLOUT;
    let fd = a.as_raw_fd();
    vec![
        poll(&[(fd, both)], 0),
        poll(&[(fd, both), (gone_fd, libc::POLLIN)], 0),
        poll(&[(fd, both), (-1, libc::POLLIN)], 0),
        poll(&[(gone_fd, libc::POLLIN)], 0),
    ]
}

/// The real OS answers for the sim socket's `/dev/null` placeholder: readable and writable on
/// Linux, `POLLNVAL` on macOS, whose `poll` does not take devices.

#[test]

fn poll_odd_fds_os_truth() {
    let real = on_host(poll_odd_fds);
    assert_eq!(
        real,
        [
            (1, vec![libc::POLLOUT]),
            (2, vec![libc::POLLOUT, libc::POLLNVAL]),
            (1, vec![libc::POLLOUT, 0]),
            (1, vec![libc::POLLNVAL]),
        ]
    );
    assert_eq!(in_sim(poll_odd_fds), real);
}

/// A stream's poll (`POLLIN | POLLOUT`) before and after its peer closes, after it reads end of
/// stream, and after it shuts its own sending side.
fn poll_after_peer_close() -> Vec<i16> {
    let (mut client, server) = tcp_pair();
    let fd = client.as_raw_fd();
    let both = libc::POLLIN | libc::POLLOUT;
    let mut seen = vec![poll(&[(fd, both)], 0).1[0]];
    drop(server);
    settle();
    seen.push(poll(&[(fd, both)], 0).1[0]);
    assert_eq!(client.read(&mut [0u8; 4]).unwrap(), 0);
    seen.push(poll(&[(fd, both)], 0).1[0]);
    client.shutdown(Shutdown::Write).unwrap();
    settle();
    seen.push(poll(&[(fd, both)], 0).1[0]);
    seen
}

#[test]

fn poll_after_peer_close_os_truth() {
    let real = on_host(poll_after_peer_close);
    let hup = libc::POLLIN | libc::POLLHUP;
    let expected = if cfg!(target_os = "linux") {
        [
            libc::POLLOUT,
            libc::POLLIN | libc::POLLOUT,
            libc::POLLIN | libc::POLLOUT,
            hup | libc::POLLOUT,
        ]
    } else {
        [libc::POLLOUT, hup, hup, hup]
    };
    assert_eq!(real, expected);
    assert_eq!(in_sim(poll_after_peer_close), real);
}

/// A nonblocking connect to a closed loopback port: its errno, the poll after it settles,
/// `SO_ERROR`, and the poll after the error was read.
fn refused_socket() -> (i32, i32) {
    refused_socket_with_buffer(None)
}

fn refused_socket_with_buffer(sndbuf: Option<i32>) -> (i32, i32) {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0);
    if let Some(value) = sndbuf {
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&raw const value).cast(),
                    size_of::<i32>() as _,
                )
            },
            0
        );
    }
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sin.sin_family = libc::AF_INET as _;
    sin.sin_port = port.to_be();
    sin.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
    #[cfg(target_os = "macos")]
    {
        sin.sin_len = size_of::<libc::sockaddr_in>() as u8;
    }
    let rc = unsafe {
        libc::connect(
            fd,
            (&sin as *const libc::sockaddr_in).cast(),
            size_of::<libc::sockaddr_in>() as u32,
        )
    };
    let connect = if rc == 0 { 0 } else { errno() };
    (fd, connect)
}

fn refused_connect() -> (i32, i16, i32, i16) {
    let (fd, connect) = refused_socket();
    let both = libc::POLLIN | libc::POLLOUT;
    let first = poll(&[(fd, both)], 1000).1[0];
    let mut err: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut err as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    let after = poll(&[(fd, both)], 0).1[0];
    unsafe { libc::close(fd) };
    (connect, first, err, after)
}

#[test]
fn refused_connect_poll_as_modelled() {
    assert_eq!(in_sim(refused_connect), on_host(refused_connect));
}

#[test]
fn refused_connect_poll_os_truth() {
    let real = on_host(refused_connect);
    let hup = libc::POLLIN | libc::POLLHUP;
    let expected = if cfg!(target_os = "linux") {
        let after = hup | libc::POLLOUT;
        (
            libc::EINPROGRESS,
            after | libc::POLLERR,
            libc::ECONNREFUSED,
            after,
        )
    } else {
        (libc::EINPROGRESS, hup, libc::ECONNREFUSED, hup)
    };
    assert_eq!(real, expected);
    assert_eq!(in_sim(refused_connect), real);
}

/// A `mio::Waker` woken five times, from this thread and two others, before one poll: the
/// events of that poll and of the next zero-timeout one.
fn waker_many_wakes() -> (usize, usize) {
    use mio::{Events, Poll, Token, Waker};
    let mut poll = Poll::new().unwrap();
    let waker = std::sync::Arc::new(Waker::new(poll.registry(), Token(3)).unwrap());
    waker.wake().unwrap();
    let others: Vec<_> = (0..2)
        .map(|_| {
            let w = waker.clone();
            std::thread::spawn(move || {
                w.wake().unwrap();
                w.wake().unwrap();
            })
        })
        .collect();
    for t in others {
        t.join().unwrap();
    }
    let mut events = Events::with_capacity(8);
    poll.poll(&mut events, Some(Duration::from_millis(100)))
        .unwrap();
    let first = events.iter().filter(|e| e.token() == Token(3)).count();
    poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
    (first, events.iter().count())
}

#[test]
fn waker_many_wakes_one_event() {
    assert_eq!(in_sim(waker_many_wakes), (1, 0));
}

#[test]
fn waker_many_wakes_one_event_deterministic() {
    assert_eq!(in_deterministic(waker_many_wakes), (1, 0));
}

#[test]
fn waker_many_wakes_one_event_os_truth() {
    assert_eq!(on_host(waker_many_wakes), (1, 0));
}

/// The virtual time each readiness call costs: ten empty zero-timeout polls, a poll that finds
/// its fd ready with a zero and with an infinite timeout, a poll that waits out 7 ms, and the
/// same for `epoll_wait` (Linux) or `kevent` (macOS): three empty zero-timeout waits, a 7 ms
/// wait out, and a wait that finds an event at once.
fn charges() -> Vec<Duration> {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let fd = s.as_raw_fd();
    let now = || snare::time().value();
    let mut out = Vec::new();
    let mut step = |f: &mut dyn FnMut()| {
        let t0 = now();
        f();
        out.push(now() - t0);
    };
    step(&mut || {
        for _ in 0..10 {
            assert_eq!(poll(&[(fd, libc::POLLIN)], 0).0, 0);
        }
    });
    step(&mut || assert_eq!(poll(&[(fd, libc::POLLOUT)], 0).0, 1));
    step(&mut || assert_eq!(poll(&[(fd, libc::POLLOUT)], -1).0, 1));
    step(&mut || assert_eq!(poll(&[(fd, libc::POLLIN)], 7).0, 0));
    #[cfg(target_os = "linux")]
    {
        let ep = unsafe { libc::epoll_create1(0) };
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: 1,
        };
        assert_eq!(
            unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev) },
            0
        );
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
        let mut wait = |t| unsafe { libc::epoll_wait(ep, out.as_mut_ptr(), 4, t) };
        step(&mut || {
            for _ in 0..3 {
                assert_eq!(wait(0), 0);
            }
        });
        step(&mut || assert_eq!(wait(7), 0));
        ev.events = libc::EPOLLOUT as u32;
        assert_eq!(
            unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_MOD, fd, &mut ev) },
            0
        );
        step(&mut || assert_eq!(wait(-1), 1));
        unsafe { libc::close(ep) };
    }
    #[cfg(target_os = "macos")]
    {
        let kq = unsafe { libc::kqueue() };
        let ch = libc::kevent {
            ident: fd as usize,
            filter: libc::EVFILT_READ,
            flags: libc::EV_ADD,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        assert_eq!(
            unsafe { libc::kevent(kq, &ch, 1, std::ptr::null_mut(), 0, std::ptr::null()) },
            0
        );
        let mut evs = [ch; 4];
        let mut wait = |ms: i64| {
            let ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: ms * 1_000_000,
            };
            unsafe { libc::kevent(kq, std::ptr::null(), 0, evs.as_mut_ptr(), 4, &ts) }
        };
        step(&mut || {
            for _ in 0..3 {
                assert_eq!(wait(0), 0);
            }
        });
        step(&mut || assert_eq!(wait(7), 0));
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(b"x", s.local_addr().unwrap()).unwrap();
        step(&mut || assert_eq!(wait(0), 1));
        unsafe { libc::close(kq) };
    }
    out
}

/// A wait that times out lands 1 ns past its deadline, as every time skip does.
fn charges_expected() -> Vec<Duration> {
    let us = Duration::from_micros;
    let wait7 = Duration::from_millis(7) + Duration::from_nanos(1);
    vec![us(10), us(1), us(1), wait7, us(3), wait7, us(1)]
}

#[test]
fn zero_timeout_polls_charge_a_microsecond() {
    assert_eq!(in_sim(charges), charges_expected());
}

#[test]
fn zero_timeout_polls_charge_a_microsecond_deterministic() {
    assert_eq!(in_deterministic(charges), charges_expected());
}

/// A zero-timeout `select` on an empty sim UDP socket: the fds it reports readable, and how many
/// `select` calls the sim counted as unmodelled.
fn select_on_a_sim_socket() -> (bool, u64) {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let fd = s.as_raw_fd();
    let mut set: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe {
        libc::FD_ZERO(&mut set);
        libc::FD_SET(fd, &mut set);
    }
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let n = unsafe {
        libc::select(
            fd + 1,
            &mut set,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut tv,
        )
    };
    assert!(n >= 0);
    let readable = unsafe { libc::FD_ISSET(fd, &set) };
    let counted = snare_interpose::Domain::current().map_or(0, |d| {
        d.unmodelled()
            .iter()
            .filter(|(call, _)| call.function == "select")
            .map(|(_, n)| *n)
            .sum()
    });
    (readable, counted)
}

#[test]

fn select_os_truth() {
    assert_eq!(on_host(select_on_a_sim_socket), (false, 0));
    assert!(!in_sim(select_on_a_sim_socket).0);
}
