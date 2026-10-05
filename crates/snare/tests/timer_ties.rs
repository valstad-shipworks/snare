//! A timed wait that times out wakes at its own deadline (1 ns past it, as a time skip lands)
//! when another thread's timer falls due at the same instant, whatever kind either wait is: a
//! native one that notices its deadline between real-time slices (a park, a condition variable, a
//! channel built on them, an event listener) or one of the sim's own (a sleep, a socket timeout,
//! `poll` or `WSAPoll`, a mio poll over kqueue, epoll or IOCP). Each pairing runs on the plain clock and
//! under `deterministic()`, which also replays.
//!
//! On Windows mio waits in `GetQueuedCompletionStatusEx` on an I/O completion port fed by
//! `\Device\Afd` poll requests
//! ([Microsoft Learn: I/O Completion Ports](https://learn.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports)),
//! using simulated socket readiness and the same virtual timeout as the other waiters.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use event_listener::{Event, Listener};
use snare::Sim;

/// The timeout every wait in a pairing runs for, so the partner's waits fall due together with
/// the waiter's.
const TIMEOUT: Duration = Duration::from_millis(50);

/// How far past its deadline a wait may return: the 1 ns a time skip lands past it and the
/// microsecond charged for each call that returns without blocking around it.
const SLACK: Duration = Duration::from_micros(100);

/// How many timeouts the partner waits out in a row, the first of them tied with the waiter's.
const PARTNER_WAITS: u32 = 3;

#[derive(Clone, Copy, Debug)]
enum Wait {
    Sleep,
    Park,
    Condvar,
    Channel,
    EventListener,
    SocketTimeout,
    Poll,
    Mio,
}

const KINDS: [Wait; 8] = [
    Wait::Sleep,
    Wait::Park,
    Wait::Condvar,
    Wait::Channel,
    Wait::EventListener,
    Wait::SocketTimeout,
    Wait::Poll,
    Wait::Mio,
];

/// A fresh loopback address for a socket that nothing ever sends to.
fn quiet_addr() -> std::net::SocketAddr {
    static NEXT: AtomicU16 = AtomicU16::new(20_000);
    std::net::SocketAddr::from(([127, 0, 0, 1], NEXT.fetch_add(1, Ordering::Relaxed)))
}

/// Waits out `timeout` in a wait of `kind` that nothing ends early.
fn wait_out(kind: Wait, timeout: Duration) {
    match kind {
        Wait::Sleep => std::thread::sleep(timeout),
        Wait::Park => std::thread::park_timeout(timeout),
        Wait::Condvar => {
            let lock = Mutex::new(());
            let cv = Condvar::new();
            let (_guard, result) = cv
                .wait_timeout_while(lock.lock().unwrap(), timeout, |()| true)
                .unwrap();
            assert!(result.timed_out());
        }
        Wait::Channel => {
            let (_tx, rx) = mpsc::channel::<()>();
            assert_eq!(
                rx.recv_timeout(timeout),
                Err(mpsc::RecvTimeoutError::Timeout)
            );
        }
        Wait::EventListener => {
            let event = Event::new();
            let listener = event.listen();
            assert!(listener.wait_timeout(timeout).is_none());
        }
        Wait::SocketTimeout => {
            let sock = UdpSocket::bind(quiet_addr()).unwrap();
            sock.set_read_timeout(Some(timeout)).unwrap();
            let err = sock.recv(&mut [0u8; 8]).unwrap_err();
            assert!(matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ));
        }
        Wait::Poll => {
            let sock = UdpSocket::bind(quiet_addr()).unwrap();
            assert_eq!(poll_readable(&sock, timeout), 0);
        }
        Wait::Mio => {
            let mut poll = mio::Poll::new().unwrap();
            let mut sock = mio::net::UdpSocket::bind(quiet_addr()).unwrap();
            poll.registry()
                .register(&mut sock, mio::Token(0), mio::Interest::READABLE)
                .unwrap();
            let mut events = mio::Events::with_capacity(4);
            poll.poll(&mut events, Some(timeout)).unwrap();
            assert!(events.is_empty());
        }
    }
}

/// `poll(2)` for `sock` to turn readable, up to `timeout`: how many descriptors were ready.
#[cfg(unix)]
fn poll_readable(sock: &UdpSocket, timeout: Duration) -> i32 {
    use std::os::fd::AsRawFd;
    let mut fds = [libc::pollfd {
        fd: sock.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }];
    let ms = libc::c_int::try_from(timeout.as_millis()).unwrap();
    // SAFETY: `fds` is a live array of one pollfd.
    unsafe { libc::poll(fds.as_mut_ptr(), 1, ms) }
}

/// `WSAPoll` for `sock` to turn readable, up to `timeout`: how many sockets were ready
/// ([Microsoft Learn: WSAPoll](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsapoll)).
#[cfg(windows)]
fn poll_readable(sock: &UdpSocket, timeout: Duration) -> i32 {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{POLLRDNORM, WSAPOLLFD, WSAPoll};
    let mut fds = [WSAPOLLFD {
        fd: sock.as_raw_socket() as usize,
        events: POLLRDNORM,
        revents: 0,
    }];
    let ms = i32::try_from(timeout.as_millis()).unwrap();
    // SAFETY: `fds` is a live array of one WSAPOLLFD.
    unsafe { WSAPoll(fds.as_mut_ptr(), 1, ms) }
}

/// The waiter waits out one [`TIMEOUT`] of `waiter` while a partner thread waits out
/// [`PARTNER_WAITS`] of `partner` back to back, the first due at the same instant. Returns how
/// long each took on the sim's clock. The two meet at a barrier first, so the partner is running
/// its own code, past its thread's start-up, when the waiter begins.
fn tie(waiter: Wait, partner: Wait) -> (Duration, Duration) {
    let barrier = Arc::new(Barrier::new(2));
    let met = barrier.clone();
    let start = Instant::now();
    let other = std::thread::spawn(move || {
        met.wait();
        for _ in 0..PARTNER_WAITS {
            wait_out(partner, TIMEOUT);
        }
        start.elapsed()
    });
    barrier.wait();
    wait_out(waiter, TIMEOUT);
    let waited = start.elapsed();
    let partnered = other.join().unwrap();
    (waited, partnered)
}

#[track_caller]
fn assert_within(took: Duration, due: Duration, what: &str) {
    assert!(
        took >= due && took - due <= SLACK,
        "{what}: took {took:?}, due at {due:?}"
    );
}

/// Every waiter kind tied with `partner`, on the plain clock and deterministically, twice.
fn tied_with(partner: Wait) {
    for waiter in KINDS {
        let what = format!("{waiter:?} tied with {partner:?}");
        let (waited, partnered) = Sim::new().run(move || tie(waiter, partner));
        assert_within(waited, TIMEOUT, &format!("{what}, plain clock"));
        assert_within(
            partnered,
            TIMEOUT * PARTNER_WAITS,
            &format!("{what}'s partner, plain"),
        );
        let det = || Sim::builder().deterministic().seed(3).build();
        let first = det().run(move || tie(waiter, partner));
        assert_within(first.0, TIMEOUT, &format!("{what}, deterministic"));
        assert_within(
            first.1,
            TIMEOUT * PARTNER_WAITS,
            &format!("{what}'s partner, deterministic"),
        );
        assert_eq!(
            first,
            det().run(move || tie(waiter, partner)),
            "{what} replays"
        );
    }
}

#[test]
fn every_wait_tied_with_a_sleep() {
    tied_with(Wait::Sleep);
}

#[test]
fn every_wait_tied_with_a_park() {
    tied_with(Wait::Park);
}

#[test]
fn every_wait_tied_with_a_condvar() {
    tied_with(Wait::Condvar);
}

#[test]
fn every_wait_tied_with_a_channel() {
    tied_with(Wait::Channel);
}

#[test]
fn every_wait_tied_with_an_event_listener() {
    tied_with(Wait::EventListener);
}

#[test]
fn every_wait_tied_with_a_socket_timeout() {
    tied_with(Wait::SocketTimeout);
}

#[test]
fn every_wait_tied_with_poll() {
    tied_with(Wait::Poll);
}

#[test]
fn every_wait_tied_with_a_mio_poll() {
    tied_with(Wait::Mio);
}
