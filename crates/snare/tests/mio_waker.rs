//! Edge-triggered readiness, which `mio` builds on: its Linux `Waker` is an eventfd registered
//! `EPOLLIN | EPOLLET` that it never reads until the counter would overflow, and its macOS waker an
//! `EVFILT_USER` added with `EV_CLEAR`; every socket it registers is edge-triggered too
//! (`EPOLLET`, `EV_CLEAR`). A fired waker or a socket that stays readable or writable must be
//! reported once per event, not on every poll, or an event loop spins.
//!
//! The raw epoll sequences run against the host kernel as well (`*_os_truth`), so the model is
//! pinned to what Linux does: man 7 epoll, "Level-triggered and edge-triggered".
//!
//! On Windows mio waits on an I/O completion port fed by `\Device\Afd` poll requests
//! ([Microsoft Learn: I/O Completion Ports](https://learn.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports)),
//! whose socket readiness is supplied by the sim. Windows re-arms socket readiness when Mio observes
//! `WouldBlock`; partial reads need not produce another edge when more data arrives
//! ([Mio portability](https://docs.rs/mio/latest/mio/struct.Poll.html#portability)).

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mio::{Events, Interest, Poll, Token, Waker};
use snare::Sim;

fn deterministic() -> Sim {
    Sim::builder()
        .deterministic()
        .stuck_after(Duration::from_secs(5))
        .build()
}

/// How many polls of `poll` within `window` returned at least one event.
fn polls_with_events(poll: &mut Poll, window: Duration) -> usize {
    let mut events = Events::with_capacity(8);
    let start = Instant::now();
    let mut woken = 0;
    while start.elapsed() < window && woken < 1000 {
        poll.poll(&mut events, Some(Duration::from_millis(20)))
            .unwrap();
        if !events.is_empty() {
            woken += 1;
        }
    }
    woken
}

/// A waker woken once is reported by one poll; woken again, by one more.
fn waker_fires_once_per_wake() -> (usize, usize, usize) {
    let mut poll = Poll::new().unwrap();
    let waker = Waker::new(poll.registry(), Token(1)).unwrap();
    let idle = polls_with_events(&mut poll, Duration::from_millis(100));
    waker.wake().unwrap();
    let once = polls_with_events(&mut poll, Duration::from_millis(200));
    waker.wake().unwrap();
    waker.wake().unwrap();
    let again = polls_with_events(&mut poll, Duration::from_millis(200));
    (idle, once, again)
}

#[test]
fn mio_waker_fires_once_per_wake() {
    assert_eq!(Sim::new().run(waker_fires_once_per_wake), (0, 1, 1));
}

#[test]
fn mio_waker_fires_once_per_wake_deterministic() {
    assert_eq!(deterministic().run(waker_fires_once_per_wake), (0, 1, 1));
}

#[test]
fn mio_waker_fires_once_per_wake_os_truth() {
    assert_eq!(waker_fires_once_per_wake(), (0, 1, 1));
}

/// A waker woken from another thread while the poller blocks wakes it once, and the poller then
/// blocks again for its full timeout.
fn waker_from_another_thread() -> (bool, usize) {
    let mut poll = Poll::new().unwrap();
    let waker = Arc::new(Waker::new(poll.registry(), Token(7)).unwrap());
    let w = waker.clone();
    let waking = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        w.wake().unwrap();
    });
    let mut events = Events::with_capacity(4);
    poll.poll(&mut events, Some(Duration::from_secs(3)))
        .unwrap();
    let woke = events.iter().any(|e| e.token() == Token(7));
    waking.join().unwrap();
    (
        woke,
        polls_with_events(&mut poll, Duration::from_millis(100)),
    )
}

#[test]
fn mio_waker_from_another_thread() {
    assert_eq!(Sim::new().run(waker_from_another_thread), (true, 0));
}

#[test]
fn mio_waker_from_another_thread_deterministic() {
    assert_eq!(deterministic().run(waker_from_another_thread), (true, 0));
}

/// A connected stream registered readable and writable, as tokio registers every socket: the
/// writable edge after connecting and the readable edge of the peer's data each wake one poll,
/// and a stream that merely stays writable or readable does not wake any more. Also with a
/// fired waker on the same poll (the shape atlink's and telegenic's event loops have).
fn stream_edges(addr: &'static str, with_waker: bool) -> (usize, usize, usize) {
    let listener = std::net::TcpListener::bind(addr).unwrap();
    let mut poll = Poll::new().unwrap();
    let waker = with_waker.then(|| Waker::new(poll.registry(), Token(1)).unwrap());
    let client = std::net::TcpStream::connect(addr).unwrap();
    client.set_nonblocking(true).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    let mut stream = mio::net::TcpStream::from_std(client);
    poll.registry()
        .register(
            &mut stream,
            Token(0),
            Interest::READABLE | Interest::WRITABLE,
        )
        .unwrap();
    let writable = polls_with_events(&mut poll, Duration::from_millis(100));
    server.write_all(b"hello").unwrap();
    let mut buf = [0u8; 64];
    let mut events = Events::with_capacity(8);
    let mut readable = 0;
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(200) && readable < 1000 {
        poll.poll(&mut events, Some(Duration::from_millis(20)))
            .unwrap();
        if events
            .iter()
            .any(|event| event.token() == Token(0) && event.is_readable())
        {
            readable += 1;
            while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
        }
    }
    if let Some(waker) = &waker {
        waker.wake().unwrap();
    }
    let woken = polls_with_events(&mut poll, Duration::from_millis(100));
    (writable, readable, woken)
}

#[test]
fn mio_stream_edges() {
    let got = Sim::new().run(|| stream_edges("127.0.0.1:47301", false));
    assert_eq!(got, (1, 1, 0));
}

#[test]
fn mio_stream_edges_deterministic() {
    let got = deterministic().run(|| stream_edges("127.0.0.1:47302", true));
    assert_eq!(got, (1, 1, 1));
}

#[test]
fn mio_stream_edges_os_truth() {
    assert_eq!(stream_edges("127.0.0.1:47303", true), (1, 1, 1));
}

/// A datagram socket that stays readable (one datagram read of two) is not reported again; one
/// more datagram arriving is a new edge on Unix. Windows requires a read through `WouldBlock`
/// before re-arming. Both first datagrams are queued before the socket is
/// registered, which reports them as one edge (a real host could otherwise deliver them on
/// either side of a poll).
fn datagram_edges(port: u16) -> (usize, usize, usize, usize) {
    let mut poll = Poll::new().unwrap();
    let mut rx = mio::net::UdpSocket::bind(format!("127.0.0.1:{port}").parse().unwrap()).unwrap();
    let tx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    tx.send_to(b"a", rx.local_addr().unwrap()).unwrap();
    tx.send_to(b"b", rx.local_addr().unwrap()).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    poll.registry()
        .register(&mut rx, Token(0), Interest::READABLE)
        .unwrap();
    let first = polls_with_events(&mut poll, Duration::from_millis(100));
    rx.recv(&mut [0u8; 8]).unwrap();
    let left_unread = polls_with_events(&mut poll, Duration::from_millis(100));
    tx.send_to(b"c", rx.local_addr().unwrap()).unwrap();
    let more = polls_with_events(&mut poll, Duration::from_millis(100));
    let mut pending = Vec::new();
    loop {
        let mut bytes = [0u8; 8];
        match rx.recv(&mut bytes) {
            Ok(n) => pending.push(bytes[..n].to_vec()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("{error}"),
        }
    }
    assert_eq!(pending, [b"b".to_vec(), b"c".to_vec()]);
    tx.send_to(b"d", rx.local_addr().unwrap()).unwrap();
    let rearmed = polls_with_events(&mut poll, Duration::from_millis(100));
    assert_eq!(rx.recv(&mut [0u8; 8]).unwrap(), 1);
    (first, left_unread, more, rearmed)
}

#[test]
fn mio_datagram_edges() {
    assert_eq!(
        Sim::new().run(|| datagram_edges(47311)),
        (1, 0, usize::from(cfg!(unix)), 1)
    );
}

#[test]
fn mio_datagram_edges_os_truth() {
    assert_eq!(datagram_edges(47312), (1, 0, usize::from(cfg!(unix)), 1));
}

#[cfg(target_os = "linux")]
mod epoll {
    //! The same epoll sequence on an eventfd and a UDP socket, through raw libc, in the sim and on
    //! the host kernel.

    use std::os::fd::AsRawFd;

    use snare::Sim;

    /// `epoll_wait` with a 50 ms timeout: the `data` of each event reported.
    fn wait(ep: i32) -> Vec<u64> {
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 8];
        let n = unsafe { libc::epoll_wait(ep, out.as_mut_ptr(), 8, 50) };
        assert!(n >= 0, "epoll_wait: {}", std::io::Error::last_os_error());
        let mut got: Vec<u64> = out[..n as usize].iter().map(|e| e.u64).collect();
        got.sort_unstable();
        got
    }

    fn ctl(ep: i32, op: i32, fd: i32, events: i32, data: u64) {
        let mut ev = libc::epoll_event {
            events: events as u32,
            u64: data,
        };
        let rc = unsafe { libc::epoll_ctl(ep, op, fd, &mut ev) };
        assert_eq!(rc, 0, "epoll_ctl: {}", std::io::Error::last_os_error());
    }

    fn efd_write(fd: i32, v: u64) {
        let rc = unsafe { libc::write(fd, v.to_ne_bytes().as_ptr().cast(), 8) };
        assert_eq!(rc, 8);
    }

    fn efd_read(fd: i32) -> u64 {
        let mut b = [0u8; 8];
        let rc = unsafe { libc::read(fd, b.as_mut_ptr().cast(), 8) };
        assert_eq!(rc, 8);
        u64::from_ne_bytes(b)
    }

    /// Three eventfds — edge-triggered (data 1), level-triggered (data 2), one-shot (data 3) —
    /// driven through writes, reads and a re-arm, recording what each `epoll_wait` reports.
    fn eventfd_sequence() -> Vec<Vec<u64>> {
        let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        let flags = libc::EFD_NONBLOCK | libc::EFD_CLOEXEC;
        let (et, lt, os) = unsafe {
            (
                libc::eventfd(0, flags),
                libc::eventfd(0, flags),
                libc::eventfd(0, flags),
            )
        };
        ctl(
            ep,
            libc::EPOLL_CTL_ADD,
            et,
            libc::EPOLLIN | libc::EPOLLET,
            1,
        );
        ctl(ep, libc::EPOLL_CTL_ADD, lt, libc::EPOLLIN, 2);
        ctl(
            ep,
            libc::EPOLL_CTL_ADD,
            os,
            libc::EPOLLIN | libc::EPOLLONESHOT,
            3,
        );
        let mut seen = vec![wait(ep)];
        for fd in [et, lt, os] {
            efd_write(fd, 1);
        }
        seen.push(wait(ep));
        seen.push(wait(ep));
        for fd in [et, os] {
            efd_write(fd, 1);
        }
        seen.push(wait(ep));
        seen.push(wait(ep));
        assert_eq!(efd_read(et), 2);
        seen.push(wait(ep));
        efd_write(et, 5);
        ctl(
            ep,
            libc::EPOLL_CTL_MOD,
            os,
            libc::EPOLLIN | libc::EPOLLONESHOT,
            3,
        );
        seen.push(wait(ep));
        seen.push(wait(ep));
        ctl(
            ep,
            libc::EPOLL_CTL_MOD,
            et,
            libc::EPOLLIN | libc::EPOLLET,
            1,
        );
        seen.push(wait(ep));
        seen.push(wait(ep));
        seen
    }

    fn eventfd_expected() -> Vec<Vec<u64>> {
        vec![
            vec![],
            vec![1, 2, 3],
            vec![2],
            vec![1, 2],
            vec![2],
            vec![2],
            vec![1, 2, 3],
            vec![2],
            vec![1, 2],
            vec![2],
        ]
    }

    #[test]
    fn eventfd_edge_level_and_oneshot() {
        assert_eq!(Sim::new().run(eventfd_sequence), eventfd_expected());
    }

    #[test]
    fn eventfd_edge_level_and_oneshot_deterministic() {
        assert_eq!(
            super::deterministic().run(eventfd_sequence),
            eventfd_expected()
        );
    }

    #[test]
    fn eventfd_edge_level_and_oneshot_os_truth() {
        assert_eq!(eventfd_sequence(), eventfd_expected());
    }

    /// A UDP socket registered `EPOLLIN | EPOLLET`: each datagram arriving is an edge, even onto
    /// one still unread; a read that leaves one queued is not.
    fn udp_sequence(port: u16) -> Vec<Vec<u64>> {
        let rx = std::net::UdpSocket::bind(("127.0.0.1", port)).unwrap();
        rx.set_nonblocking(true).unwrap();
        let tx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        ctl(
            ep,
            libc::EPOLL_CTL_ADD,
            rx.as_raw_fd(),
            libc::EPOLLIN | libc::EPOLLET,
            9,
        );
        let mut seen = vec![wait(ep)];
        tx.send_to(b"a", rx.local_addr().unwrap()).unwrap();
        seen.push(wait(ep));
        seen.push(wait(ep));
        tx.send_to(b"b", rx.local_addr().unwrap()).unwrap();
        seen.push(wait(ep));
        rx.recv(&mut [0u8; 4]).unwrap();
        seen.push(wait(ep));
        rx.recv(&mut [0u8; 4]).unwrap();
        tx.send_to(b"c", rx.local_addr().unwrap()).unwrap();
        seen.push(wait(ep));
        seen.push(wait(ep));
        seen
    }

    fn udp_expected() -> Vec<Vec<u64>> {
        vec![vec![], vec![9], vec![], vec![9], vec![], vec![9], vec![]]
    }

    #[test]
    fn udp_edge_triggered() {
        assert_eq!(Sim::new().run(|| udp_sequence(47321)), udp_expected());
    }

    #[test]
    fn udp_edge_triggered_os_truth() {
        assert_eq!(udp_sequence(47322), udp_expected());
    }
}
