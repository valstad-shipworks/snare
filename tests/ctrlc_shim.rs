use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use snare::ctrlc::{self, Error};
use snare::sched::{self, BlockerKind, Driver, DriverConfig, PState, attach_driver};
use snare::{register_test, time_value};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn setup_driver(audit: bool) -> (MutexGuard<'static, ()>, Driver) {
    let guard = serial();
    register_test();
    sched::mark_driver_thread();
    let driver = attach_driver(DriverConfig {
        seed: 3,
        accounting: true,
        audit,
    })
    .unwrap();
    (guard, driver)
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

fn counting_handler() -> Arc<AtomicU64> {
    let count = Arc::new(AtomicU64::new(0));
    let c = Arc::clone(&count);
    ctrlc::set_handler(move || {
        c.fetch_add(1, Ordering::SeqCst);
    })
    .unwrap();
    count
}

fn state_of(driver: &Driver, name: &str) -> Option<PState> {
    driver
        .participants()
        .into_iter()
        .find(|p| &*p.name == name)
        .map(|p| p.state)
}

fn wait_idle(driver: &Driver) {
    assert!(
        wait_real(
            || state_of(driver, "ctrl-c") == Some(PState::Blocked) && driver.quiescence().quiescent,
            Duration::from_secs(5),
        ),
        "handler thread never went idle: {:?}",
        driver.participants()
    );
}

#[test]
fn the_handler_runs_once_per_raise_on_its_own_thread() {
    let _s = serial();
    register_test();
    let (tx, rx) = mpsc::channel();
    ctrlc::set_handler(move || {
        tx.send(std::thread::current().name().map(String::from))
            .unwrap();
    })
    .unwrap();

    for _ in 0..5 {
        assert!(ctrlc::raise());
        let name = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(name.as_deref(), Some("ctrl-c"));
    }
    assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());

    for _ in 0..3 {
        assert!(ctrlc::raise());
    }
    for _ in 0..3 {
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
}

#[test]
fn a_second_handler_is_refused() {
    let _s = serial();
    register_test();
    let count = counting_handler();
    assert!(matches!(
        ctrlc::set_handler(|| {}),
        Err(Error::MultipleHandlers)
    ));
    assert!(matches!(
        ctrlc::try_set_handler(|| {}),
        Err(Error::MultipleHandlers)
    ));
    assert!(ctrlc::raise());
    assert!(wait_real(
        || count.load(Ordering::SeqCst) == 1,
        Duration::from_secs(5)
    ));
}

#[test]
fn a_raise_without_a_handler_or_slot_is_dropped() {
    let _s = serial();
    register_test();
    assert!(!ctrlc::raise());
    let _count = counting_handler();
    let from_slotless = std::thread::spawn(ctrlc::raise).join().unwrap();
    assert!(!from_slotless);
}

#[test]
fn the_idle_handler_thread_is_blocked_and_a_raise_makes_it_runnable() {
    let (_s, driver) = setup_driver(false);
    let (gate_tx, gate_rx) = mpsc::channel::<()>();
    let count = Arc::new(AtomicU64::new(0));
    let c = Arc::clone(&count);
    ctrlc::set_handler(move || {
        gate_rx.recv().unwrap();
        c.fetch_add(1, Ordering::SeqCst);
    })
    .unwrap();
    wait_idle(&driver);
    let wait = driver
        .participants()
        .into_iter()
        .find(|p| &*p.name == "ctrl-c")
        .and_then(|p| p.wait);
    assert_eq!(wait, Some("ctrlc"));

    for round in 1..=3 {
        assert!(ctrlc::raise());
        let q = driver.quiescence();
        assert!(!q.quiescent);
        assert_eq!(q.blocker.map(|b| b.0), Some(BlockerKind::Runnable));
        assert_eq!(state_of(&driver, "ctrl-c"), Some(PState::Running));
        gate_tx.send(()).unwrap();
        wait_idle(&driver);
        assert_eq!(count.load(Ordering::SeqCst), round);
    }
}

#[test]
fn a_raise_inside_a_timestamp_is_deferred_until_it_ends() {
    let (_s, driver) = setup_driver(false);
    let count = counting_handler();
    wait_idle(&driver);

    let t = driver.now() + Duration::from_millis(10);
    driver.enter_timestamp(t);
    assert!(ctrlc::raise());
    let q = driver.quiescence();
    assert_eq!(q.blocker.map(|b| b.0), Some(BlockerKind::Deferred));
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert_eq!(state_of(&driver, "ctrl-c"), Some(PState::Blocked));

    driver.leave_timestamp(t);
    assert!(wait_real(
        || count.load(Ordering::SeqCst) == 1,
        Duration::from_secs(5)
    ));
    wait_idle(&driver);
}

#[test]
fn a_background_raise_is_no_stray_and_no_violation() {
    let (_s, driver) = setup_driver(true);
    let count = counting_handler();
    wait_idle(&driver);

    snare::thread::Builder::new()
        .name("telemetry".into())
        .spawn(|| {
            sched::mark_background("telemetry");
            assert!(ctrlc::raise());
        })
        .unwrap()
        .join()
        .unwrap();
    assert!(wait_real(
        || count.load(Ordering::SeqCst) == 1,
        Duration::from_secs(5)
    ));
    wait_idle(&driver);

    let audit = driver.audit();
    assert_eq!(audit.stray_wakes, 0);
    assert!(audit.strays.is_empty());
    assert_eq!(audit.total_violations, 0, "{:?}", audit.violations);
    assert!(
        audit
            .class_effects
            .iter()
            .any(|e| e.op == "unpark" && &*e.thread == "telemetry")
    );
    assert!(driver.participants().iter().all(|p| !p.stray));
}

#[test]
fn the_handler_reads_virtual_time() {
    let (_s, driver) = setup_driver(false);
    let (tx, rx) = mpsc::channel();
    ctrlc::set_handler(move || tx.send(time_value()).unwrap()).unwrap();
    wait_idle(&driver);

    let target = driver.now() + Duration::from_secs(3600);
    driver.jump_to(target).unwrap();
    assert!(ctrlc::raise());
    let seen = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(seen, time_value());
    assert!(seen >= Duration::from_secs(3600));
    assert_eq!(driver.now(), target);
}
