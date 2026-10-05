#![cfg(not(feature = "shim"))]

use std::time::{Duration, Instant};

use snare::sched::{
    self, AttachError, DriverConfig, ParkResult, attach_driver, current_unparker, pending_timers,
    sleep_until,
};

#[test]
fn block_on_a_sleep_waits_wall_time() {
    let start = Instant::now();
    sched::block_on(sleep_until(start + Duration::from_millis(20)));
    let took = start.elapsed();
    assert!(took >= Duration::from_millis(20), "{took:?}");
    assert!(took < Duration::from_secs(1), "{took:?}");
}

#[test]
fn attach_is_refused_without_the_shim() {
    assert_eq!(
        attach_driver(DriverConfig::default()).unwrap_err(),
        AttachError::ShimDisabled
    );
}

#[test]
fn park_times_out_and_unparks() {
    let start = Instant::now();
    let deadline = start + Duration::from_millis(10);
    assert_eq!(sched::park(Some(deadline)), ParkResult::TimedOut);
    assert!(Instant::now() >= deadline);

    let unparker = current_unparker();
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(10));
        unparker.unpark();
    });
    assert_eq!(
        sched::park(Some(Instant::now() + Duration::from_secs(60))),
        ParkResult::Unparked
    );
    t.join().unwrap();
}

#[test]
fn participation_calls_are_no_ops() {
    let _g = sched::participate("stub");
    let _b = sched::busy("stub");
    sched::hint_starving("stub", 1.0);
    assert!(!sched::is_participant());
}

#[test]
fn sleep_until_returns_after_the_deadline() {
    let deadline = Instant::now() + Duration::from_millis(5);
    snare::thread::sleep_until(deadline);
    assert!(Instant::now() >= deadline);
    let _ = pending_timers();
}

#[test]
fn driven_and_participant_are_false_without_the_shim() {
    assert!(!sched::is_driven());
    assert!(!sched::is_participant());
    sched::mark_background("stub-bg");
    sched::mark_helper();
    let _scope = sched::setup_scope("stub");
    assert!(!sched::is_driven());
    assert!(sched::held_leases().is_empty());
}

#[test]
fn block_on_timeout_runs_on_wall_time() {
    let start = Instant::now();
    let r = sched::block_on_timeout(std::future::pending::<()>(), Duration::from_millis(50));
    assert_eq!(r, None);
    let took = start.elapsed();
    assert!(took >= Duration::from_millis(50), "{took:?}");
    assert!(took < Duration::from_secs(5), "{took:?}");
    assert_eq!(
        sched::block_on_timeout(async { 7 }, Duration::from_millis(50)),
        Some(7)
    );
    assert_eq!(sched::block_on_until(async { 8 }, None), Some(8));
}

#[test]
fn a_waker_set_wakes_a_wall_waiter() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Poll;

    let set = Arc::new(sched::WakerSet::new());
    let flag = Arc::new(AtomicBool::new(false));
    let (s, f) = (Arc::clone(&set), Arc::clone(&flag));
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(10));
        f.store(true, Ordering::SeqCst);
        s.wake_all();
    });
    let r = sched::block_on_timeout(
        std::future::poll_fn(|cx| {
            set.register(cx.waker());
            if flag.load(Ordering::SeqCst) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
        Duration::from_secs(30),
    );
    assert_eq!(r, Some(()));
    t.join().unwrap();
}
