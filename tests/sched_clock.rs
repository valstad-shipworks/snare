use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use snare::sched::{
    self, AttachError, DriverConfig, Grant, ParkResult, attach_driver, current_unparker,
    pending_timers, sleep_until,
};
use snare::time::{Instant, SystemTime};
use snare::{
    advance_time, pause_time, register_test, resume_time, set_time_rate, set_time_value, time_rate,
    time_value,
};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn far() -> Duration {
    Duration::from_secs(1 << 30)
}

struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

struct Record {
    id: usize,
    log: Arc<Mutex<Vec<usize>>>,
}

impl Wake for Record {
    fn wake(self: Arc<Self>) {
        self.log.lock().unwrap().push(self.id);
    }
}

fn poll_once<F: Future + Unpin>(f: &mut F, waker: &Waker) -> Poll<F::Output> {
    Pin::new(f).poll(&mut Context::from_waker(waker))
}

fn wait_real(cond: impl Fn() -> bool, limit: Duration) -> bool {
    let start = std::time::Instant::now();
    while !cond() {
        if start.elapsed() > limit {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    true
}

#[test]
fn now_is_monotone_and_never_passes_the_horizon() {
    let _s = serial();
    register_test();
    let driver = attach_driver(DriverConfig::default()).unwrap();

    let published = Arc::new(AtomicU64::new(driver.now().as_nanos() as u64));
    let stop = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..16)
        .map(|_| {
            let published = Arc::clone(&published);
            let stop = Arc::clone(&stop);
            snare::thread::spawn(move || {
                let mut last = 0u64;
                while !stop.load(Ordering::Acquire) {
                    let v = time_value().as_nanos() as u64;
                    let h = published.load(Ordering::Acquire);
                    assert!(v >= last, "time went backwards: {last} -> {v}");
                    assert!(v <= h, "time {v} passed the horizon {h}");
                    last = v;
                }
            })
        })
        .collect();

    let rates = [0.0, 0.5, 1.0, 10.0, 1_000.0, 1e6, 1e9];
    let mut rng = Xorshift(0x9e37_79b9_7f4a_7c15);
    let mut horizon = published.load(Ordering::Acquire);
    for _ in 0..10_000 {
        horizon += rng.next() % 2_000_000;
        published.store(horizon, Ordering::Release);
        if rng.next().is_multiple_of(50) {
            driver.freeze();
            continue;
        }
        let now = driver.now().as_nanos() as u64;
        let anchor = (now + rng.next() % 2_000_000).saturating_sub(1_000_000);
        driver.grant(Grant {
            anchor_v: Duration::from_nanos(anchor),
            anchor_wall: std::time::Instant::now(),
            rate: rates[(rng.next() % rates.len() as u64) as usize],
            horizon: Duration::from_nanos(horizon),
        });
    }
    stop.store(true, Ordering::Release);
    for r in readers {
        r.join().expect("reader saw a violation");
    }
}

#[test]
fn timers_fire_in_deadline_then_seq_order() {
    let _s = serial();
    register_test();
    pause_time();
    let base = Instant::now();

    let log = Arc::new(Mutex::new(Vec::new()));
    let mut sleeps = Vec::new();
    let mut expected = Vec::new();
    for id in 0..200usize {
        let offset = Duration::from_millis(1 + (id as u64 * 7_919) % 37);
        let mut s = sleep_until(base + offset);
        let waker = Waker::from(Arc::new(Record {
            id,
            log: Arc::clone(&log),
        }));
        assert!(poll_once(&mut s, &waker).is_pending());
        sleeps.push(s);
        expected.push((offset, id));
    }
    expected.sort();
    let expected: Vec<usize> = expected.into_iter().map(|(_, id)| id).collect();

    advance_time(Duration::from_secs(1));
    assert!(wait_real(
        || log.lock().unwrap().len() == 200,
        Duration::from_secs(5)
    ));
    assert_eq!(*log.lock().unwrap(), expected);
    assert_eq!(pending_timers(), 0);
}

#[test]
fn driven_sleeps_wake_on_the_wall_target() {
    let _s = serial();
    register_test();
    let driver = attach_driver(DriverConfig::default()).unwrap();

    let mut latencies = Vec::new();
    for period in [Duration::from_millis(5), Duration::from_millis(8)] {
        for _ in 0..20 {
            driver.freeze();
            let frozen = driver.now();
            let deadline = Instant::now() + period;
            let g = Grant {
                anchor_v: frozen,
                anchor_wall: std::time::Instant::now(),
                rate: 10.0,
                horizon: far(),
            };
            driver.grant(g);
            snare::thread::sleep_until(deadline);
            let woke = std::time::Instant::now();
            let target = g.anchor_wall + period / 10;
            assert!(Instant::now() >= deadline);
            latencies.push(woke.saturating_duration_since(target));
        }
    }
    latencies.sort();
    let median = latencies[latencies.len() / 2];
    assert!(
        median < Duration::from_micros(200),
        "median wake latency {median:?}, all {latencies:?}"
    );
}

#[test]
fn dropped_sleeps_leave_no_heap_entries() {
    let _s = serial();
    register_test();
    pause_time();
    let waker = Waker::noop();
    let base = Instant::now();
    let mut sleeps: Vec<_> = (0..1_000u64)
        .map(|i| sleep_until(base + Duration::from_millis(1 + i)))
        .collect();
    for s in &mut sleeps {
        assert!(poll_once(s, waker).is_pending());
    }
    assert_eq!(pending_timers(), 1_000);
    drop(sleeps);
    assert_eq!(pending_timers(), 0);

    let mut done = sleep_until(base + Duration::from_millis(5));
    assert!(poll_once(&mut done, waker).is_pending());
    advance_time(Duration::from_millis(5));
    assert!(poll_once(&mut done, waker).is_ready());
    assert_eq!(pending_timers(), 0);
}

#[test]
fn now_takes_no_locks() {
    let _s = serial();
    register_test();
    let _ = Instant::now();
    let _ = SystemTime::now();
    let Some(before) = sched::debug_lock_count() else {
        return;
    };
    for _ in 0..1_000 {
        let _ = Instant::now();
        let _ = SystemTime::now();
        let _ = time_value();
    }
    assert_eq!(sched::debug_lock_count(), Some(before));
}

#[test]
fn legacy_controls_are_ignored_while_driven() {
    let _s = serial();
    register_test();
    set_time_value(Duration::from_secs(10));
    let driver = attach_driver(DriverConfig::default()).unwrap();
    assert_eq!(
        attach_driver(DriverConfig::default()).unwrap_err(),
        AttachError::AlreadyAttached
    );
    let frozen = time_value();
    set_time_rate(5.0);
    advance_time(Duration::from_secs(60));
    set_time_value(Duration::ZERO);
    assert_eq!(time_rate(), 0.0);
    assert_eq!(time_value(), frozen);

    drop(driver);
    assert_eq!(time_rate(), 0.0);
    assert_eq!(time_value(), frozen);
    advance_time(Duration::from_secs(1));
    assert_eq!(time_value(), frozen + Duration::from_secs(1));
    assert!(attach_driver(DriverConfig::default()).is_ok());
}

#[test]
fn resume_restores_the_rate_before_the_pause() {
    let _s = serial();
    register_test();
    set_time_rate(3.0);
    pause_time();
    assert_eq!(time_rate(), 0.0);
    resume_time();
    assert_eq!(time_rate(), 3.0);
    set_time_rate(1e9);
    assert_eq!(time_rate(), 1e6);
}

#[cfg(not(snare_global))]
#[test]
fn attach_needs_a_state_slot() {
    let _s = serial();
    let err = std::thread::spawn(|| attach_driver(DriverConfig::default()).unwrap_err())
        .join()
        .unwrap();
    assert_eq!(err, AttachError::NotGlobal);
}

#[test]
fn the_horizon_holds_sleepers_until_the_next_grant() {
    let _s = serial();
    register_test();
    let driver = attach_driver(DriverConfig::default()).unwrap();
    let start = driver.now();
    driver.grant(Grant {
        anchor_v: start,
        anchor_wall: std::time::Instant::now(),
        rate: 1_000.0,
        horizon: start + Duration::from_millis(5),
    });

    let woke = Arc::new(AtomicBool::new(false));
    let sleeper = {
        let woke = Arc::clone(&woke);
        snare::thread::spawn(move || {
            snare::thread::sleep(Duration::from_millis(10));
            woke.store(true, Ordering::Release);
        })
    };
    std::thread::sleep(Duration::from_millis(50));
    assert!(!woke.load(Ordering::Acquire));
    assert_eq!(time_value(), start + Duration::from_millis(5));

    driver.grant(Grant {
        anchor_v: driver.now(),
        anchor_wall: std::time::Instant::now(),
        rate: 1_000.0,
        horizon: far(),
    });
    sleeper.join().unwrap();
    assert!(woke.load(Ordering::Acquire));
}

#[test]
fn park_times_out_on_virtual_time_and_consumes_early_unparks() {
    let _s = serial();
    register_test();
    pause_time();

    current_unparker().unpark();
    assert_eq!(sched::park(None), ParkResult::Unparked);

    let deadline = Instant::now() + Duration::from_secs(5);
    let advancer = snare::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(20));
        advance_time(Duration::from_secs(5));
    });
    let real = std::time::Instant::now();
    assert_eq!(sched::park(Some(deadline)), ParkResult::TimedOut);
    assert!(real.elapsed() < Duration::from_secs(2));
    advancer.join().unwrap();
    assert_eq!(pending_timers(), 0);

    let unparker = current_unparker();
    let waker = snare::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        unparker.unpark();
    });
    let far_deadline = Instant::now() + Duration::from_secs(3_600);
    assert_eq!(sched::park(Some(far_deadline)), ParkResult::Unparked);
    waker.join().unwrap();
    assert_eq!(pending_timers(), 0);
}

#[test]
fn block_on_a_sleep_follows_the_clock_rate() {
    let _s = serial();
    register_test();
    set_time_rate(1_000.0);
    let start = Instant::now();
    let real = std::time::Instant::now();
    sched::block_on(sleep_until(start + Duration::from_secs(2)));
    assert!(start.elapsed() >= Duration::from_secs(2));
    assert!(real.elapsed() < Duration::from_millis(500));
    resume_time();
}

#[test]
fn a_backwards_set_value_is_not_undone_by_racing_readers() {
    let _s = serial();
    register_test();
    let stop = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let stop = Arc::clone(&stop);
            snare::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let _ = Instant::now();
                }
            })
        })
        .collect();
    for _ in 0..5_000 {
        set_time_value(Duration::from_secs(100));
        set_time_value(Duration::ZERO);
        let v = time_value();
        assert!(v < Duration::from_secs(1), "clock stuck at {v:?}");
    }
    stop.store(true, Ordering::Release);
    for r in readers {
        r.join().unwrap();
    }
}

#[test]
fn a_sleep_outliving_its_slot_still_fires() {
    let _s = serial();
    register_test();
    set_time_rate(1_000.0);
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut s = sleep_until(Instant::now() + Duration::from_secs(2));
    let waker = Waker::from(Arc::new(Record {
        id: 7,
        log: Arc::clone(&log),
    }));
    assert!(poll_once(&mut s, &waker).is_pending());

    register_test();
    let _ = time_value();
    assert!(wait_real(
        || !log.lock().unwrap().is_empty(),
        Duration::from_secs(5)
    ));
    assert!(poll_once(&mut s, &waker).is_ready());
}
