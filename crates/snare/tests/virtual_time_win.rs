#![cfg(windows)]

//! The discrete-event virtual clock on Windows, the `Sim` default: time jumps to the next pending
//! sleep or timeout when every managed thread is blocked — for `Sleep`, Winsock waits, and std's
//! `WaitOnAddress`-based Condvar/park/channels alike — and costs a microsecond per call that
//! returns without blocking. The unix counterparts are `tests/virtual_time.rs` and
//! `tests/native_waits.rs`.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use snare::Sim;

fn vsim() -> Sim {
    Sim::builder().virtual_clock().build()
}

#[test]
fn reads_do_not_tick() {
    vsim().run(|| {
        let a = Instant::now();
        let b = Instant::now();
        assert_eq!(a, b);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(now.as_secs(), 1_700_000_000);
    });
}

#[test]
fn a_lone_sleep_skips_virtual_time() {
    let real = Instant::now();
    vsim().run(|| {
        let start = Instant::now();
        std::thread::sleep(Duration::from_secs(3600));
        assert!(start.elapsed() >= Duration::from_secs(3600), "a virtual hour elapsed");
    });
    assert!(real.elapsed() < Duration::from_secs(60), "ran as-fast-as-possible");
}

#[test]
fn advance_time_steps_the_clock() {
    let sim = vsim();
    sim.advance_time(Duration::from_secs(5));
    sim.run(|| {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(now.as_secs(), 1_700_000_005);
    });
}

#[test]
fn time_skips_across_threads_to_a_sleeper() {
    vsim().run(|| {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = receiver.local_addr().unwrap();
        let start = Instant::now();
        let sender = std::thread::spawn(move || {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            std::thread::sleep(Duration::from_secs(600));
            s.send_to(b"tick", addr).unwrap();
        });
        let mut buf = [0u8; 8];
        let (n, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"tick");
        sender.join().unwrap();
        assert!(start.elapsed() >= Duration::from_secs(600), "clock advanced to the sleeper");
    });
}

#[test]
fn a_condvar_timeout_runs_on_virtual_time() {
    let real = Instant::now();
    vsim().run(|| {
        let flag = Mutex::new(());
        let cv = Condvar::new();
        let start = Instant::now();
        let (_guard, result) = cv
            .wait_timeout_while(flag.lock().unwrap(), Duration::from_secs(30), |_| true)
            .unwrap();
        assert!(result.timed_out());
        assert!(start.elapsed() >= Duration::from_secs(30), "virtual time reached the timeout");
    });
    assert!(real.elapsed() < Duration::from_secs(30), "ran as-fast-as-possible");
}

#[test]
fn a_channel_recv_timeout_runs_on_virtual_time() {
    let real = Instant::now();
    vsim().run(|| {
        let (_tx, rx) = mpsc::channel::<u8>();
        let start = Instant::now();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        assert!(start.elapsed() >= Duration::from_secs(10), "virtual time reached the timeout");
    });
    assert!(real.elapsed() < Duration::from_secs(10), "ran as-fast-as-possible");
}

#[test]
fn a_busy_poll_lets_virtual_time_reach_a_sleeper() {
    let real = Instant::now();
    Sim::new().run(|| {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let addr = receiver.local_addr().unwrap();
        let start = Instant::now();
        let sender = std::thread::spawn(move || {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            std::thread::sleep(Duration::from_millis(10));
            s.send_to(b"late", addr).unwrap();
        });
        let mut buf = [0u8; 8];
        let n = loop {
            match receiver.recv_from(&mut buf) {
                Ok((n, _)) => break n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("{e}"),
            }
        };
        assert_eq!(&buf[..n], b"late");
        sender.join().unwrap();
        assert!(start.elapsed() >= Duration::from_millis(10), "the sender's sleep elapsed");
    });
    assert!(real.elapsed() < Duration::from_secs(30), "the spin did not stall the clock");
}

#[test]
fn spinning_on_yield_lets_virtual_time_advance() {
    let real = Instant::now();
    vsim().run(|| {
        let done = Arc::new(AtomicBool::new(false));
        let signal = done.clone();
        let start = Instant::now();
        let sleeper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(5));
            signal.store(true, Ordering::Release);
        });
        while !done.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        assert!(start.elapsed() >= Duration::from_secs(5), "the sleeper's virtual 5s passed");
        sleeper.join().unwrap();
    });
    assert!(real.elapsed() < Duration::from_secs(5), "ran as-fast-as-possible");
}
