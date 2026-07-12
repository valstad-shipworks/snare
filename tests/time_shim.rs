use std::sync::mpsc;
use std::time::Duration;

use snare::time::{Instant, SystemTime, UNIX_EPOCH};
use snare::{
    advance_time, pause_time, register_test, resume_time, set_time_rate, set_time_value, time_rate,
    time_value,
};

#[test]
fn default_rate_tracks_real_time() {
    register_test();
    assert_eq!(time_rate(), 1.0);

    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(20));
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(15),
        "virtual clock should advance with real time at rate 1.0, got {elapsed:?}"
    );
}

#[test]
fn pausing_freezes_now() {
    register_test();
    pause_time();
    assert_eq!(time_rate(), 0.0);

    let a = Instant::now();
    std::thread::sleep(Duration::from_millis(20));
    let b = Instant::now();
    assert_eq!(a, b, "a paused clock must not advance across real sleeps");
    assert_eq!(a.elapsed(), Duration::ZERO);
}

#[test]
fn advance_works_while_paused() {
    register_test();
    pause_time();

    let a = Instant::now();
    advance_time(Duration::from_secs(30));
    let b = Instant::now();
    assert_eq!(b.duration_since(a), Duration::from_secs(30));

    // Still paused: no further drift.
    std::thread::sleep(Duration::from_millis(10));
    assert_eq!(Instant::now(), b);
}

#[test]
fn set_value_jumps_the_clock() {
    register_test();
    pause_time();
    set_time_value(Duration::from_secs(1_000));
    assert_eq!(time_value(), Duration::from_secs(1_000));
    assert_eq!(Instant::now().elapsed(), Duration::ZERO);
}

#[test]
fn high_rate_runs_fast() {
    register_test();
    set_time_rate(1000.0);

    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(20));
    let elapsed = start.elapsed();
    // 20ms real * 1000 ~= 20s virtual; allow a wide margin for scheduling.
    assert!(
        elapsed >= Duration::from_secs(5),
        "rate 1000 should advance far faster than wall time, got {elapsed:?}"
    );
}

#[test]
fn rate_survives_reanchoring_without_going_backwards() {
    register_test();
    pause_time();
    set_time_value(Duration::from_secs(100));
    let before = Instant::now();

    resume_time();
    std::thread::sleep(Duration::from_millis(5));
    pause_time();

    let after = Instant::now();
    assert!(
        after >= before,
        "changing the rate must never move the clock backwards"
    );
    assert!(after.duration_since(before) < Duration::from_secs(1));
}

#[test]
#[should_panic(expected = "monotonicity")]
fn negative_rate_is_rejected() {
    register_test();
    set_time_rate(-1.0);
}

#[test]
fn system_time_tracks_the_same_clock() {
    register_test();
    pause_time();

    let wall = SystemTime::now();
    let since_epoch = wall.duration_since(UNIX_EPOCH).unwrap();
    assert!(
        since_epoch > Duration::from_secs(1_700_000_000),
        "wall base should be seeded from the real system clock, got {since_epoch:?}"
    );

    advance_time(Duration::from_secs(60));
    let later = SystemTime::now();
    assert_eq!(later.duration_since(wall).unwrap(), Duration::from_secs(60));
}

#[test]
fn sleep_blocks_on_the_virtual_clock_while_paused() {
    register_test();
    pause_time();
    set_time_value(Duration::from_secs(100));

    snare::thread::spawn(|| {
        // Real wait so the main thread is parked in the virtual sleep first,
        // then advance virtual time to its deadline to release it.
        snare::thread::real_sleep(Duration::from_millis(30));
        advance_time(Duration::from_secs(5));
    });

    let real_start = std::time::Instant::now();
    let virt_start = Instant::now();
    snare::thread::sleep(Duration::from_secs(5));
    let real_elapsed = real_start.elapsed();

    assert_eq!(virt_start.elapsed(), Duration::from_secs(5));
    assert!(
        real_elapsed < Duration::from_secs(2),
        "a virtual 5s sleep should be released by advancing the clock, not by \
         waiting 5 real seconds (took {real_elapsed:?})"
    );
}

#[test]
fn sleep_returns_fast_under_a_high_rate() {
    register_test();
    set_time_rate(1000.0);

    let real_start = std::time::Instant::now();
    let virt_start = Instant::now();
    snare::thread::sleep(Duration::from_secs(10));
    let real_elapsed = real_start.elapsed();

    assert!(virt_start.elapsed() >= Duration::from_secs(10));
    assert!(
        real_elapsed < Duration::from_secs(2),
        "10 virtual seconds at rate 1000 should take ~10ms of real time, took {real_elapsed:?}"
    );
}

#[test]
fn real_sleep_ignores_the_virtual_clock() {
    register_test();
    pause_time();

    let before = Instant::now();
    let real_start = std::time::Instant::now();
    snare::thread::real_sleep(Duration::from_millis(20));
    let real_elapsed = real_start.elapsed();

    assert!(
        real_elapsed >= Duration::from_millis(15),
        "real_sleep must block in real time even while the clock is paused, got {real_elapsed:?}"
    );
    assert_eq!(before.elapsed(), Duration::ZERO, "the clock stayed paused");
}

#[test]
fn clock_is_shared_across_the_thread_chain() {
    register_test();
    pause_time();
    set_time_value(Duration::from_secs(500));

    let (tx, rx) = mpsc::channel();
    snare::thread::spawn(move || {
        // Child thread resolves the same per-test slot, so it sees the paused
        // clock and the value the parent set.
        let seen = time_value();
        advance_time(Duration::from_secs(10));
        tx.send(seen).unwrap();
    });

    let seen = rx.recv().unwrap();
    assert_eq!(seen, Duration::from_secs(500));
    // The child's advance is visible back on the parent thread.
    assert_eq!(time_value(), Duration::from_secs(510));
}
