use std::cell::Cell;
use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use snare::mio::{Events, Interest, Poll, Token, Waker};
use snare::net::{TcpListener, TcpStream, UdpSocket};
use snare::sched::{self, Driver, DriverConfig, Grant, PState, attach_driver};
use snare::time::Instant;
use snare::{
    UdpPolicy, advance_time, inject_udp_from_test, pause_time, register_test, resume_time,
    seed_rng, set_time_rate, set_udp_policy, time_value,
};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn driven() -> Driver {
    sched::mark_driver_thread();
    attach_driver(DriverConfig {
        seed: 1,
        accounting: true,
        audit: false,
    })
    .unwrap()
}

fn wait_real(cond: impl Fn() -> bool, limit: Duration) -> bool {
    let start = std::time::Instant::now();
    while !cond() {
        if start.elapsed() > limit {
            return false;
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    true
}

fn blocked_in(driver: &Driver, name: &str, wait: &str) -> bool {
    driver
        .participants()
        .iter()
        .any(|p| &*p.name == name && p.state == PState::Blocked && p.wait == Some(wait))
}

fn spawn_named<T: Send + 'static>(
    name: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> std::thread::JoinHandle<T> {
    snare::thread::Builder::new()
        .name(name.to_string())
        .spawn(f)
        .unwrap()
}

/// Runs jobs for the thread under test, one at a time, and acknowledges each.
struct Helper {
    jobs: mpsc::Sender<Box<dyn FnOnce() + Send>>,
    done: mpsc::Receiver<()>,
}

impl Helper {
    fn new() -> Self {
        let (jobs, rx) = mpsc::channel::<Box<dyn FnOnce() + Send>>();
        let (ack, done) = mpsc::channel();
        snare::thread::spawn(move || {
            for job in rx {
                job();
                if ack.send(()).is_err() {
                    break;
                }
            }
        });
        Self { jobs, done }
    }

    fn run(&self, job: impl FnOnce() + Send + 'static) {
        self.jobs.send(Box::new(job)).unwrap();
        self.done.recv().unwrap();
    }
}

/// Run `body` on a registered thread and fail if it has not finished within
/// `limit` of wall time.
fn capped(limit: Duration, body: impl FnOnce() + Send + 'static) {
    let (tx, rx) = mpsc::channel();
    let h = snare::thread::spawn(move || {
        body();
        let _ = tx.send(());
    });
    match rx.recv_timeout(limit) {
        Ok(()) => h.join().unwrap(),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            if let Err(p) = h.join() {
                std::panic::resume_unwind(p);
            }
        }
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("lost wakeup: hung for {limit:?}"),
    }
}

const ROUNDS: usize = 10_000;
const CAP: Duration = Duration::from_secs(10);

/// Install a hook that, in the window between a wait's readiness check and
/// its park, has the helper thread run `inject` and counts the injections.
fn inject_in_window(
    expect: &'static str,
    helper: Rc<Helper>,
    inject: impl Fn() + Send + Sync + 'static,
) -> Rc<Cell<usize>> {
    let hits = Rc::new(Cell::new(0));
    let h = Rc::clone(&hits);
    let inject = Arc::new(inject);
    sched::set_wait_hook(Some(Box::new(move |wait| {
        assert_eq!(wait, expect);
        h.set(h.get() + 1);
        let inject = Arc::clone(&inject);
        helper.run(move || inject());
    })));
    hits
}

#[test]
fn a_notify_between_check_and_park_is_not_lost_in_accept() {
    let _s = serial();
    register_test();
    capped(CAP, || {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let clients = Arc::new(Mutex::new(Vec::new()));
        let c = Arc::clone(&clients);
        let hits = inject_in_window("tcp accept", Rc::new(Helper::new()), move || {
            c.lock().unwrap().push(TcpStream::connect(addr).unwrap());
        });
        for _ in 0..ROUNDS {
            listener.accept().unwrap();
        }
        sched::set_wait_hook(None);
        assert_eq!(hits.get(), ROUNDS);
    });
}

#[test]
fn a_notify_between_check_and_park_is_not_lost_in_tcp_read() {
    let _s = serial();
    register_test();
    capped(CAP, || {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let client = Arc::new(Mutex::new(client));
        let hits = inject_in_window("tcp read", Rc::new(Helper::new()), move || {
            client.lock().unwrap().write_all(&[7]).unwrap();
        });
        let mut byte = [0u8; 1];
        for _ in 0..ROUNDS {
            assert_eq!(server.read(&mut byte).unwrap(), 1);
        }
        sched::set_wait_hook(None);
        assert_eq!(hits.get(), ROUNDS);
    });
}

#[test]
fn a_notify_between_check_and_park_is_not_lost_in_udp_read() {
    let _s = serial();
    register_test();
    capped(CAP, || {
        let reader = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = reader.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let hits = inject_in_window("udp read", Rc::new(Helper::new()), move || {
            sender.send_to(b"x", to).unwrap();
        });
        let mut buf = [0u8; 4];
        for _ in 0..ROUNDS {
            assert_eq!(reader.recv_from(&mut buf).unwrap().0, 1);
        }
        sched::set_wait_hook(None);
        assert_eq!(hits.get(), ROUNDS);
    });
}

#[test]
fn a_notify_between_check_and_park_is_not_lost_in_mio_poll() {
    let _s = serial();
    register_test();
    capped(CAP, || {
        let mut poll = Poll::new().unwrap();
        let waker = Arc::new(Waker::new(poll.registry(), Token(0)).unwrap());
        let mut reader = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = reader.local_addr().unwrap();
        poll.registry()
            .register(&mut reader, Token(1), Interest::READABLE)
            .unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let round = Arc::new(Mutex::new(0usize));
        let r = Arc::clone(&round);
        let hits = inject_in_window("mio poll", Rc::new(Helper::new()), move || {
            if r.lock().unwrap().is_multiple_of(2) {
                waker.wake().unwrap();
            } else {
                sender.send_to(b"x", to).unwrap();
            }
        });
        let mut events = Events::with_capacity(8);
        let mut buf = [0u8; 4];
        for i in 0..ROUNDS {
            *round.lock().unwrap() = i;
            poll.poll(&mut events, None).unwrap();
            let token = events.iter().next().unwrap().token();
            assert_eq!(token, Token(i % 2));
            if token == Token(1) {
                reader.recv_from(&mut buf).unwrap();
            }
        }
        sched::set_wait_hook(None);
        assert_eq!(hits.get(), ROUNDS);
    });
}

fn udp_reader(name: &str) -> (SocketAddr, std::thread::JoinHandle<Duration>) {
    let (tx, rx) = mpsc::channel();
    let h = spawn_named(name, move || {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send(sock.local_addr().unwrap()).unwrap();
        let mut buf = [0u8; 16];
        sock.recv_from(&mut buf).unwrap();
        time_value()
    });
    (rx.recv().unwrap(), h)
}

fn delay_to(addr: SocketAddr, latency: Duration) {
    set_udp_policy(addr, |p| {
        *p = UdpPolicy {
            inbound_latency: latency,
            ..UdpPolicy::default()
        }
    });
}

const PEER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
    19_900,
);

#[test]
fn a_delayed_datagram_wakes_a_no_timeout_reader_at_its_release_on_a_jump() {
    let _s = serial();
    register_test();
    let driver = driven();
    let (addr, reader) = udp_reader("reader");
    assert!(wait_real(
        || blocked_in(&driver, "reader", "udp read"),
        Duration::from_secs(5)
    ));
    delay_to(addr, Duration::from_millis(5));
    let t0 = driver.now();
    inject_udp_from_test(PEER, addr, b"hi".to_vec());
    assert!(driver.quiescence().quiescent);
    assert_eq!(
        driver.quiescence().next_deadline,
        Some(t0 + Duration::from_millis(5))
    );
    driver.jump_to(t0 + Duration::from_secs(10)).unwrap();
    assert_eq!(reader.join().unwrap(), t0 + Duration::from_millis(5));
    assert_eq!(driver.now(), t0 + Duration::from_millis(5));
}

#[test]
fn a_delayed_datagram_wakes_a_no_timeout_reader_at_its_release_under_flow() {
    let _s = serial();
    register_test();
    let driver = driven();
    let (addr, reader) = udp_reader("reader");
    assert!(wait_real(
        || blocked_in(&driver, "reader", "udp read"),
        Duration::from_secs(5)
    ));
    delay_to(addr, Duration::from_millis(5));
    let t0 = driver.now();
    inject_udp_from_test(PEER, addr, b"hi".to_vec());
    driver.grant(Grant {
        anchor_v: t0,
        anchor_wall: std::time::Instant::now(),
        rate: 1.0,
        horizon: t0 + Duration::from_millis(5),
    });
    assert_eq!(reader.join().unwrap(), t0 + Duration::from_millis(5));
}

#[test]
fn virtual_latency_at_rate_ten_takes_a_tenth_of_the_wall_time() {
    let _s = serial();
    register_test();
    set_time_rate(10.0);
    let mut fastest = Duration::MAX;
    for _ in 0..10 {
        let (tx, rx) = mpsc::channel();
        let h = snare::thread::spawn(move || {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            tx.send(sock.local_addr().unwrap()).unwrap();
            let mut buf = [0u8; 16];
            sock.recv_from(&mut buf).unwrap();
        });
        let addr = rx.recv().unwrap();
        delay_to(addr, Duration::from_millis(10));
        std::thread::sleep(Duration::from_millis(20));
        let v0 = Instant::now();
        let w0 = std::time::Instant::now();
        inject_udp_from_test(PEER, addr, b"hi".to_vec());
        h.join().unwrap();
        let wall = w0.elapsed();
        assert!(v0.elapsed() >= Duration::from_millis(10));
        fastest = fastest.min(wall);
    }
    assert!(
        fastest >= Duration::from_micros(900) && fastest < Duration::from_millis(5),
        "10 ms virtual at rate 10 took {fastest:?} of wall time"
    );
}

fn tcp_pair() -> (TcpStream, TcpStream, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server, listener)
}

#[test]
fn a_read_timeout_does_not_fire_while_the_clock_is_paused() {
    let _s = serial();
    register_test();
    let (_client, mut server, _l) = tcp_pair();
    server
        .set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    pause_time();
    let t0 = time_value();
    let done = Arc::new(AtomicBool::new(false));
    let d = Arc::clone(&done);
    let reader = snare::thread::spawn(move || {
        let err = server.read(&mut [0u8; 4]).unwrap_err();
        d.store(true, Ordering::Release);
        (err.kind(), time_value())
    });
    std::thread::sleep(Duration::from_millis(200));
    assert!(!done.load(Ordering::Acquire), "timed out on a paused clock");
    advance_time(Duration::from_millis(20));
    let (kind, at) = reader.join().unwrap();
    resume_time();
    assert_eq!(kind, ErrorKind::WouldBlock);
    assert!(at >= t0 + Duration::from_millis(10));
}

#[test]
fn a_frozen_read_timeout_fires_exactly_on_a_jump() {
    let _s = serial();
    register_test();
    let (_client, mut server, _l) = tcp_pair();
    server
        .set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    let driver = driven();
    let t0 = driver.now();
    let reader = spawn_named("reader", move || {
        let err = server.read(&mut [0u8; 4]).unwrap_err();
        (err.kind(), time_value())
    });
    assert!(wait_real(
        || blocked_in(&driver, "reader", "tcp read"),
        Duration::from_secs(5)
    ));
    std::thread::sleep(Duration::from_millis(200));
    assert!(!reader.is_finished(), "timed out on a frozen clock");
    driver.jump_to(t0 + Duration::from_secs(10)).unwrap();
    let (kind, at) = reader.join().unwrap();
    assert_eq!(kind, ErrorKind::WouldBlock);
    assert_eq!(at, t0 + Duration::from_millis(10));
}

#[test]
fn a_thread_in_accept_is_blocked_in_tcp_accept() {
    let _s = serial();
    register_test();
    let driver = driven();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = spawn_named("acceptor", move || listener.accept().map(|(_, peer)| peer));
    assert!(wait_real(
        || blocked_in(&driver, "acceptor", "tcp accept"),
        Duration::from_secs(5)
    ));
    let q = driver.quiescence();
    assert!(q.quiescent, "{q:?}");
    let client = TcpStream::connect(addr).unwrap();
    assert_eq!(
        acceptor.join().unwrap().unwrap(),
        client.local_addr().unwrap()
    );
}

#[test]
fn connect_timeout_bounds_a_delaying_listener() {
    let _s = serial();
    register_test();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    set_time_rate(100.0);
    snare::set_listener_behavior(
        addr,
        snare::ListenerBehavior::DelayingUntil(Instant::now() + Duration::from_secs(60)),
    );
    let start = Instant::now();
    let err = TcpStream::connect_timeout(&addr, Duration::from_millis(200)).unwrap_err();
    let took = start.elapsed();
    assert_eq!(err.kind(), ErrorKind::TimedOut);
    assert!(took >= Duration::from_millis(200) && took < Duration::from_secs(60));
}

fn lossy_run(seed: Option<u64>) -> Vec<u8> {
    register_test();
    let _driver = seed.map(|seed| {
        sched::mark_driver_thread();
        attach_driver(DriverConfig {
            seed,
            accounting: false,
            audit: false,
        })
        .unwrap()
    });
    if seed.is_none() {
        seed_rng(42);
    }
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    sock.set_nonblocking(true).unwrap();
    set_udp_policy(addr, |p| {
        p.loss_rate = 0.3;
        p.duplicate_rate = 0.2;
    });
    for i in 0..200u8 {
        inject_udp_from_test(PEER, addr, vec![i]);
    }
    let mut got = Vec::new();
    let mut buf = [0u8; 4];
    while let Ok((n, _)) = sock.recv_from(&mut buf) {
        got.extend_from_slice(&buf[..n]);
    }
    got
}

#[test]
fn a_seeded_policy_run_is_repeatable() {
    let _s = serial();
    let a = lossy_run(None);
    let b = lossy_run(None);
    assert_eq!(a, b);
    assert!(a.len() > 100 && a.len() < 250, "{} delivered", a.len());
    let c = lossy_run(Some(9));
    let d = lossy_run(Some(9));
    assert_eq!(c, d);
    assert_ne!(a, c);
}
