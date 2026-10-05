//! Coarse real-time guards against pathological slowdowns. Each workload retains a generous
//! budget calibrated on macOS and Linux in Docker, including debug-build overhead.

#![cfg(unix)]

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use snare::Sim;

/// Runs `f` on a fresh sim and fails if it took longer than `bound` of real time.
#[track_caller]
fn guard(what: &str, bound: Duration, f: impl FnOnce()) {
    let sim = Sim::new();
    let took = sim.run(|| {
        let start = snare::real(Instant::now);
        f();
        snare::real(|| start.elapsed())
    });
    eprintln!("{what}: {took:?} (bound {bound:?})");
    assert!(
        took < bound,
        "{what} took {took:?}, past its bound of {bound:?}"
    );
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// 100 000 `sched_yield`s: measured 150 ms (macOS), 351 ms (Linux).
#[test]
fn a_hundred_thousand_yields() {
    guard("100k yields", Duration::from_millis(3500), || {
        for _ in 0..100_000 {
            std::thread::yield_now();
        }
    });
}

/// 100 000 empty nonblocking receives, each charged 1 µs of virtual time: measured 161 ms
/// (macOS), 541 ms (Linux).
#[test]
fn a_hundred_thousand_empty_receives() {
    guard("100k empty receives", Duration::from_millis(5400), || {
        let sock = UdpSocket::bind(loopback(9000)).unwrap();
        sock.set_nonblocking(true).unwrap();
        for _ in 0..100_000 {
            let _ = sock.recv(&mut [0u8; 4]);
        }
    });
}

/// 100 000 clock reads, a yield after every 32 so they never become a clock spin: measured
/// 242 ms (macOS), 378 ms (Linux).
#[test]
fn a_hundred_thousand_clock_reads() {
    guard("100k clock reads", Duration::from_millis(3800), || {
        for i in 0..100_000 {
            std::hint::black_box(Instant::now());
            if i % 32 == 31 {
                std::thread::yield_now();
            }
        }
    });
}

/// 20 000 UDP datagrams sent and received on loopback: measured 113 ms (macOS), 80 ms (Linux).
#[test]
fn twenty_thousand_udp_round_trips() {
    guard("20k udp send+recv", Duration::from_millis(1200), || {
        let a = UdpSocket::bind(loopback(9000)).unwrap();
        let b = UdpSocket::bind(loopback(9001)).unwrap();
        for _ in 0..20_000 {
            a.send_to(b"x", loopback(9001)).unwrap();
            b.recv(&mut [0u8; 4]).unwrap();
        }
    });
}

/// 10 000 one-millisecond sleeps, each a time skip: measured 31 ms (macOS), 24 ms (Linux).
#[test]
fn ten_thousand_time_skips() {
    guard("10k time skips", Duration::from_millis(320), || {
        for _ in 0..10_000 {
            std::thread::sleep(Duration::from_millis(1));
        }
    });
}

/// 1 000 threads spawned and joined one after another: measured 34 ms (macOS), 51 ms (Linux).
#[test]
fn a_thousand_thread_spawns() {
    guard("1k spawn+join", Duration::from_millis(520), || {
        for _ in 0..1_000 {
            std::thread::spawn(|| ()).join().unwrap();
        }
    });
}

/// 10 000 UDP sockets bound to explicit ports: measured 1.36 s (macOS), 1.27 s (Linux).
#[test]
fn ten_thousand_explicit_binds() {
    guard("10k explicit binds", Duration::from_secs(14), || {
        let socks: Vec<_> = (0..10_000)
            .map(|i| UdpSocket::bind(loopback(10_000 + i)).unwrap())
            .collect();
        drop(socks);
    });
}

#[test]
fn a_thousand_ephemeral_binds() {
    guard("1k ephemeral binds", Duration::from_secs(42), || {
        let socks: Vec<_> = (0..1_000)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        drop(socks);
    });
}

/// 100 sims built, entered and dropped: measured 8.5 ms (macOS), 24 ms (Linux).
#[test]
fn a_hundred_sims() {
    let start = Instant::now();
    for _ in 0..100 {
        Sim::new().run(|| ());
    }
    let took = start.elapsed();
    let bound = Duration::from_millis(250);
    eprintln!("100 sims: {took:?} (bound {bound:?})");
    assert!(
        took < bound,
        "100 sims took {took:?}, past its bound of {bound:?}"
    );
}
