//! async-io's reactor under a sim: one process-wide poller (an epoll set with an eventfd notifier
//! and a timerfd on Linux, a kqueue with an `EVFILT_USER` notifier on macOS) and one "async-io"
//! thread that waits on it, both created by whichever sim touches async-io first and kept for
//! the life of the process. Its timers must fire on the sim's clock, and every later sim of the
//! process, in this binary's other tests too, must be able to use the same reactor.
//!
//! The tests take turns: two sims running at once cannot share one reactor coherently (its timer
//! queue would hold instants of two clocks), and a sim that only touches the reactor's memory
//! (a timer queued while its notifier is already pending) gives snare no call to wait at.

#![cfg(unix)]

use std::net::{SocketAddr, UdpSocket};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_io::{Async, Timer};
use snare::Sim;

fn turn() -> MutexGuard<'static, ()> {
    static TURN: Mutex<()> = Mutex::new(());
    TURN.lock().unwrap_or_else(|e| e.into_inner())
}

fn sim(deterministic: bool) -> Sim {
    let builder = Sim::builder().stuck_after(Duration::from_secs(10));
    if deterministic {
        builder.deterministic().build()
    } else {
        builder.build()
    }
}

fn two_timers() -> Duration {
    let start = Instant::now();
    futures_lite::future::block_on(async {
        Timer::after(Duration::from_millis(50)).await;
        Timer::after(Duration::from_millis(50)).await;
    });
    start.elapsed()
}

fn udp_round_trip() -> usize {
    futures_lite::future::block_on(async {
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let a = Async::<UdpSocket>::bind(any).unwrap();
        let b = Async::<UdpSocket>::bind(any).unwrap();
        let to = b.get_ref().local_addr().unwrap();
        a.send_to(b"ping", to).await.unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = b.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from, a.get_ref().local_addr().unwrap());
        Timer::after(Duration::from_millis(20)).await;
        n
    })
}

fn assert_timers_took_virtual_time(elapsed: Duration) {
    assert!(
        elapsed >= Duration::from_millis(100) && elapsed < Duration::from_secs(1),
        "two 50 ms timers took {elapsed:?} of sim time"
    );
}

#[test]
fn timers_fire_on_the_virtual_clock() {
    let _turn = turn();
    let elapsed = sim(false).run(two_timers);
    assert_timers_took_virtual_time(elapsed);
}

#[test]
fn timers_fire_on_a_deterministic_clock() {
    let _turn = turn();
    let elapsed = sim(true).run(two_timers);
    assert_timers_took_virtual_time(elapsed);
}

#[test]
fn a_udp_round_trip_goes_through_the_reactor() {
    let _turn = turn();
    assert_eq!(sim(true).run(udp_round_trip), 4);
}

#[test]
fn sequential_sims_each_use_the_reactor() {
    let _turn = turn();
    for round in 0..3 {
        let deterministic = round % 2 == 0;
        let (n, elapsed) = sim(deterministic).run(|| (udp_round_trip(), two_timers()));
        assert_eq!(n, 4, "round {round}");
        assert_timers_took_virtual_time(elapsed);
    }
}
