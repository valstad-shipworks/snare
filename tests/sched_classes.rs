use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use snare::register_test;
use snare::sched::{
    self, BlockerKind, Driver, DriverConfig, PState, ThreadClass, Unparker, attach_driver, busy,
    current_unparker, park,
    testkit::{StrictClock, StrictConfig},
};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn manual() -> (MutexGuard<'static, ()>, Driver) {
    let guard = serial();
    register_test();
    sched::mark_driver_thread();
    let driver = attach_driver(DriverConfig {
        seed: 5,
        accounting: true,
        audit: false,
    })
    .unwrap();
    (guard, driver)
}

fn wait_real(cond: impl Fn() -> bool) -> bool {
    let start = std::time::Instant::now();
    while !cond() {
        if start.elapsed() > Duration::from_secs(30) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    true
}

fn spawn_foreign<T: Send + 'static>(
    name: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> std::thread::JoinHandle<T> {
    let parent = std::thread::current().id();
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            snare::register_thread_child_of(parent);
            f()
        })
        .unwrap()
}

/// A participant that parks `rounds` times, reporting its unparker first.
fn parked(name: &str, rounds: usize) -> (Unparker, std::thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel();
    let h = snare::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            tx.send(current_unparker()).unwrap();
            for _ in 0..rounds {
                park(None);
            }
        })
        .unwrap();
    (rx.recv().unwrap(), h)
}

fn state_of(driver: &Driver, name: &str) -> Option<PState> {
    driver
        .participants()
        .into_iter()
        .find(|p| &*p.name == name)
        .map(|p| p.state)
}

#[test]
fn a_background_unpark_is_a_class_effect_not_a_stray() {
    let (_g, driver) = manual();
    let (unparker, target) = parked("bg-target", 1);
    assert!(wait_real(
        || state_of(&driver, "bg-target") == Some(PState::Blocked)
    ));

    spawn_foreign("bg-waker", move || {
        sched::mark_background("bg-waker");
        assert_eq!(sched::thread_class(), ThreadClass::Background);
        unparker.unpark();
    })
    .join()
    .unwrap();
    target.join().unwrap();

    let audit = driver.audit();
    assert_eq!(audit.stray_wakes, 0);
    assert!(audit.strays.is_empty());
    assert_eq!(audit.total_class_effects, 1);
    assert_eq!(audit.class_effects.len(), 1);
    let e = &audit.class_effects[0];
    assert_eq!(e.op, "unpark");
    assert_eq!(&*e.thread, "bg-waker");
    assert_eq!(e.class, ThreadClass::Background);
    assert!(state_of(&driver, "bg-waker").is_none());
}

#[test]
fn a_sleeping_helper_is_recorded_and_never_registered() {
    let _g = serial();
    register_test();
    let clock = StrictClock::start(StrictConfig::default()).unwrap();
    let t0 = clock.now();
    spawn_foreign("helper-sleeper", || {
        sched::mark_helper();
        snare::thread::sleep(Duration::from_millis(5));
        sched::thread_class()
    })
    .join()
    .map(|c| assert_eq!(c, ThreadClass::Helper))
    .unwrap();
    assert_eq!(clock.now() - t0, Duration::from_millis(5));
    let driver = clock.driver();
    assert!(
        driver
            .participants()
            .iter()
            .all(|p| &*p.name != "helper-sleeper")
    );
    let audit = driver.audit();
    assert!(audit.total_class_effects >= 1);
    assert!(
        audit
            .class_effects
            .iter()
            .any(|e| e.class == ThreadClass::Helper && e.op == "sleep")
    );
    assert_eq!(audit.stray_wakes, 0);
}

#[test]
fn setup_effects_are_counted_apart_and_the_scope_blocks_quiescence() {
    let (_g, driver) = manual();
    let (unparker, target) = parked("setup-target", 2);
    assert!(wait_real(
        || state_of(&driver, "setup-target") == Some(PState::Blocked)
    ));

    let (step_tx, step_rx) = mpsc::channel::<()>();
    let (ack_tx, ack_rx) = mpsc::channel::<()>();
    let setup = spawn_foreign("setup-main", move || {
        let scope = sched::setup_scope("rig");
        assert_eq!(sched::thread_class(), ThreadClass::Background);
        ack_tx.send(()).unwrap();
        step_rx.recv().unwrap();
        unparker.unpark();
        ack_tx.send(()).unwrap();
        step_rx.recv().unwrap();
        drop(scope);
        unparker.unpark();
    });

    ack_rx.recv().unwrap();
    let q = driver.quiescence();
    assert!(!q.quiescent);
    assert_eq!(q.blocker.as_ref().map(|b| b.0), Some(BlockerKind::Lease));
    assert_eq!(q.blocker.map(|b| b.1), Some(Arc::from("setup:rig")));
    assert_eq!(sched::held_leases(), vec![("setup:rig", None)]);

    step_tx.send(()).unwrap();
    ack_rx.recv().unwrap();
    assert!(wait_real(
        || state_of(&driver, "setup-target") == Some(PState::Blocked)
    ));
    let audit = driver.audit();
    assert!(audit.total_setup_effects >= 2, "{audit:?}");
    assert_eq!(audit.total_class_effects, 0);

    step_tx.send(()).unwrap();
    setup.join().unwrap();
    target.join().unwrap();
    let audit = driver.audit();
    assert_eq!(audit.total_class_effects, 1);
    assert_eq!(audit.class_effects[0].op, "unpark");
    assert_eq!(audit.stray_wakes, 0);
    assert!(driver.quiescence().quiescent);
}

#[test]
fn last_wait_and_leases_are_reported() {
    let (_g, driver) = manual();
    let (tx, rx) = mpsc::channel();
    let (hold_tx, hold_rx) = mpsc::channel::<()>();
    let h = snare::thread::Builder::new()
        .name("leaser".into())
        .spawn(move || {
            tx.send(current_unparker()).unwrap();
            park(None);
            let lease = busy("work");
            hold_rx.recv().unwrap();
            drop(lease);
        })
        .unwrap();
    let unparker = rx.recv().unwrap();
    assert!(wait_real(
        || state_of(&driver, "leaser") == Some(PState::Blocked)
    ));
    unparker.unpark();
    assert!(wait_real(|| {
        driver
            .participants()
            .iter()
            .any(|p| &*p.name == "leaser" && p.leases == ["work"])
    }));
    let info = driver
        .participants()
        .into_iter()
        .find(|p| &*p.name == "leaser")
        .unwrap();
    assert_eq!(info.state, PState::Running);
    assert_eq!(info.last_wait, Some("park"));
    assert_eq!(
        driver.held_leases(),
        vec![("work", Some(Arc::<str>::from("leaser")))]
    );
    hold_tx.send(()).unwrap();
    h.join().unwrap();
    assert!(driver.held_leases().is_empty());
}

#[test]
fn a_background_sleep_future_is_recorded() {
    let _g = serial();
    register_test();
    let clock = StrictClock::start(StrictConfig::default()).unwrap();
    let t0 = clock.now();
    spawn_foreign("bg-sleeper", || {
        sched::mark_background("bg-sleeper");
        sched::block_on(sched::sleep_until(
            snare::time::Instant::now() + Duration::from_millis(2),
        ));
    })
    .join()
    .unwrap();
    assert_eq!(clock.now() - t0, Duration::from_millis(2));
    let audit = clock.driver().audit();
    let ops: Vec<_> = audit
        .class_effects
        .iter()
        .filter(|e| &*e.thread == "bg-sleeper")
        .map(|e| e.op)
        .collect();
    assert!(
        ops.contains(&"sleep") && ops.contains(&"block_on"),
        "{ops:?}"
    );
    assert_eq!(audit.stray_wakes, 0);
}
