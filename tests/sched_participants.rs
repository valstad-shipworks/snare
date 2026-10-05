use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use snare::sched::{
    self, BlockerKind, Driver, DriverConfig, NotQuiescent, PState, ParkResult, Unparker,
    attach_driver, block_on, busy, current_unparker, park,
};
use snare::{register_test, time_value};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn setup(audit: bool) -> (MutexGuard<'static, ()>, Driver) {
    let guard = serial();
    register_test();
    sched::mark_driver_thread();
    let driver = attach_driver(DriverConfig {
        seed: 7,
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

fn spawn_named<T: Send + 'static>(
    name: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> std::thread::JoinHandle<T> {
    snare::thread::Builder::new()
        .name(name.to_string())
        .spawn(f)
        .unwrap()
}

/// A thread that is not spawned through snare and so is unknown to the
/// scheduler until it does something visible.
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

/// A participant that parks until unparked `rounds` times, reporting its
/// unparker first.
fn parked_participant(
    name: &str,
    rounds: usize,
) -> (Unparker, Arc<AtomicU64>, std::thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel();
    let woke = Arc::new(AtomicU64::new(0));
    let w = Arc::clone(&woke);
    let h = spawn_named(name, move || {
        tx.send(current_unparker()).unwrap();
        for _ in 0..rounds {
            park(None);
            w.fetch_add(1, Ordering::SeqCst);
        }
    });
    (rx.recv().unwrap(), woke, h)
}

fn state_of(driver: &Driver, name: &str) -> Option<PState> {
    driver
        .participants()
        .into_iter()
        .find(|p| &*p.name == name)
        .map(|p| p.state)
}

#[test]
fn a_wake_transfers_runnable_before_the_waker_parks() {
    const ROUNDS: usize = 100_000;
    let (_s, driver) = setup(false);

    let (a_tx, a_rx) = mpsc::channel::<Unparker>();
    let (b_tx, b_rx) = mpsc::channel::<Unparker>();
    let done = Arc::new(AtomicBool::new(false));

    let d = Arc::clone(&done);
    let a = spawn_named("ping", move || {
        a_tx.send(current_unparker()).unwrap();
        let b = b_rx.recv().unwrap();
        for _ in 0..ROUNDS {
            b.unpark();
            park(None);
        }
        d.store(true, Ordering::SeqCst);
    });
    let b = spawn_named("pong", move || {
        b_tx.send(current_unparker()).unwrap();
        let a = a_rx.recv().unwrap();
        for _ in 0..ROUNDS {
            park(None);
            a.unpark();
        }
    });

    let mut samples = 0u64;
    let mut last_epoch = 0;
    loop {
        let q = driver.quiescence();
        if q.runnable == 0 || q.quiescent {
            assert!(
                done.load(Ordering::SeqCst),
                "domain looked idle mid ping-pong: {q:?}"
            );
            break;
        }
        assert!(q.epoch >= last_epoch);
        last_epoch = q.epoch;
        samples += 1;
        std::hint::spin_loop();
        if a.is_finished() && b.is_finished() {
            break;
        }
    }
    a.join().unwrap();
    b.join().unwrap();
    assert!(samples > 0);
    let q = driver.quiescence();
    assert_eq!((q.runnable, q.blocked), (0, 0), "{q:?}");
}

#[test]
fn a_spawned_child_counts_before_it_first_runs() {
    let (_s, driver) = setup(false);

    for _ in 0..200 {
        let child_parking = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<Unparker>();
        let flag = Arc::clone(&child_parking);
        let parent = snare::thread::spawn(move || {
            tx.send(current_unparker()).unwrap();
            let child_tx = tx.clone();
            let child = snare::thread::spawn(move || {
                let spin = std::time::Instant::now();
                while spin.elapsed() < Duration::from_micros(300) {
                    std::hint::spin_loop();
                }
                child_tx.send(current_unparker()).unwrap();
                flag.store(true, Ordering::SeqCst);
                park(None);
            });
            park(None);
            child.join().unwrap();
        });

        loop {
            let q = driver.quiescence();
            if q.quiescent {
                assert!(
                    child_parking.load(Ordering::SeqCst),
                    "quiescent before the child parked: {q:?}"
                );
                if q.blocked == 2 {
                    break;
                }
            }
            std::hint::spin_loop();
        }

        let parent_u = rx.recv().unwrap();
        let child_u = rx.recv().unwrap();
        child_u.unpark();
        parent_u.unpark();
        parent.join().unwrap();
    }
}

#[test]
fn thread_exit_deregisters_the_participant() {
    let (_s, driver) = setup(false);
    let start = driver.now();

    let h = spawn_named("short-lived", || {
        snare::thread::sleep(Duration::from_millis(3));
    });
    assert!(wait_real(
        || state_of(&driver, "short-lived") == Some(PState::Blocked),
        Duration::from_secs(5)
    ));
    let info = driver
        .participants()
        .into_iter()
        .find(|p| &*p.name == "short-lived")
        .unwrap();
    assert_eq!(info.wait, Some("sleep"));
    assert_eq!(info.deadline, Some(start + Duration::from_millis(3)));

    assert!(wait_real(
        || driver.quiescence().quiescent,
        Duration::from_secs(5)
    ));
    assert_eq!(driver.jump_to(start + Duration::from_secs(1)), Ok(1));
    assert_eq!(driver.now(), start + Duration::from_millis(3));
    h.join().unwrap();

    assert!(driver.participants().is_empty());
    let q = driver.quiescence();
    assert_eq!((q.runnable, q.blocked), (0, 0));
    assert!(q.quiescent, "{q:?}");
}

#[test]
fn jump_refuses_when_a_wake_lands_after_the_quiescence_read() {
    let (_s, driver) = setup(false);
    let (tx, rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let h = spawn_named("sleeper", move || {
        tx.send(current_unparker()).unwrap();
        park(None);
        go_rx.recv().unwrap();
    });
    let u = rx.recv().unwrap();

    assert!(wait_real(
        || driver.quiescence().quiescent,
        Duration::from_secs(5)
    ));
    let q = driver.quiescence();
    assert!(q.quiescent);

    let stray = spawn_foreign("late-waker", move || u.unpark());
    stray.join().unwrap();

    let target = driver.now() + Duration::from_millis(10);
    assert_eq!(driver.jump_to(target), Err(NotQuiescent));
    assert!(driver.now() < target);
    let q = driver.quiescence();
    assert_eq!(
        q.blocker.as_ref().map(|b| b.0),
        Some(BlockerKind::Runnable),
        "{q:?}"
    );
    go_tx.send(()).unwrap();
    h.join().unwrap();
}

#[test]
fn jump_lands_on_the_earliest_timer_group() {
    let (_s, driver) = setup(false);
    let t0 = driver.now();

    let fired_at = Arc::new(Mutex::new(Vec::new()));
    let hs: Vec<_> = [5u64, 5, 9]
        .into_iter()
        .enumerate()
        .map(|(i, ms)| {
            let fired_at = Arc::clone(&fired_at);
            spawn_named(&format!("grid-{i}"), move || {
                snare::thread::sleep_until(snare::time::Instant::now() + Duration::from_millis(ms));
                fired_at.lock().unwrap().push(time_value());
            })
        })
        .collect();

    assert!(wait_real(
        || driver.quiescence().blocked == 3 && driver.quiescence().quiescent,
        Duration::from_secs(5)
    ));
    assert_eq!(
        driver.quiescence().next_deadline,
        Some(t0 + Duration::from_millis(5))
    );
    assert_eq!(driver.jump_to(t0 + Duration::from_secs(1)), Ok(2));
    assert_eq!(driver.now(), t0 + Duration::from_millis(5));
    assert!(wait_real(
        || fired_at.lock().unwrap().len() == 2 && driver.quiescence().quiescent,
        Duration::from_secs(5)
    ));
    assert_eq!(driver.jump_to(t0 + Duration::from_secs(1)), Ok(1));
    assert_eq!(driver.now(), t0 + Duration::from_millis(9));
    for h in hs {
        h.join().unwrap();
    }
    let mut got = fired_at.lock().unwrap().clone();
    got.sort();
    assert_eq!(
        got,
        [5, 5, 9].map(|ms| t0 + Duration::from_millis(ms)).to_vec()
    );
}

#[test]
fn wakes_inside_a_timestamp_wait_for_leave_timestamp() {
    let (_s, driver) = setup(false);
    let t = driver.now() + Duration::from_millis(8);

    let seen = Arc::new(Mutex::new(None));
    let s = Arc::clone(&seen);
    let (tx, rx) = mpsc::channel();
    let b = spawn_named("reader", move || {
        tx.send(current_unparker()).unwrap();
        park(None);
        *s.lock().unwrap() = Some(time_value());
    });
    let u = rx.recv().unwrap();
    assert!(wait_real(
        || driver.quiescence().quiescent,
        Duration::from_secs(5)
    ));

    driver.enter_timestamp(t);
    assert_eq!(time_value(), t);
    assert_eq!(snare::time::Instant::now(), snare::time::Instant::now());
    assert_eq!(driver.now(), t - Duration::from_nanos(1));

    u.unpark();
    let pool_wake = {
        let u = u.clone();
        let parent = std::thread::current().id();
        std::thread::spawn(move || {
            snare::register_thread_child_of(parent);
            sched::mark_driver_thread();
            sched::with_driver_time(t, || {
                u.unpark();
                time_value()
            })
        })
    };
    assert_eq!(pool_wake.join().unwrap(), t);

    std::thread::sleep(Duration::from_millis(30));
    assert!(
        seen.lock().unwrap().is_none(),
        "woke before leave_timestamp"
    );
    assert_eq!(state_of(&driver, "reader"), Some(PState::Blocked));
    let q = driver.quiescence();
    assert!(!q.quiescent);
    assert_eq!(q.blocker.map(|b| b.0), Some(BlockerKind::Deferred));

    assert_eq!(driver.leave_timestamp(t), 0);
    b.join().unwrap();
    assert_eq!(*seen.lock().unwrap(), Some(t));
    assert_eq!(driver.now(), t);
    assert!(driver.audit().strays.is_empty());
}

#[test]
fn an_unknown_waker_is_registered_as_a_running_stray() {
    let (_s, driver) = setup(false);
    let (u, woke, h) = parked_participant("target", 2);
    assert!(wait_real(
        || driver.quiescence().quiescent,
        Duration::from_secs(5)
    ));

    let (go_tx, go_rx) = mpsc::channel::<()>();
    let stray = spawn_foreign("stray-waker", move || {
        u.unpark();
        go_rx.recv().unwrap();
        u.unpark();
    });
    assert!(wait_real(
        || woke.load(Ordering::SeqCst) == 1,
        Duration::from_secs(5)
    ));
    let info = driver
        .participants()
        .into_iter()
        .find(|p| &*p.name == "stray-waker")
        .expect("stray registered");
    assert!(info.stray);
    assert_eq!(info.state, PState::Running);
    assert!(!driver.quiescence().quiescent);

    go_tx.send(()).unwrap();
    stray.join().unwrap();
    h.join().unwrap();
    let audit = driver.audit();
    assert_eq!(audit.stray_wakes, 1);
    assert_eq!(audit.strays, vec![Arc::<str>::from("stray-waker")]);
    assert!(audit.violations.is_empty());
    assert!(driver.participants().is_empty());
}

#[test]
fn audit_reports_a_wake_after_the_lease_was_dropped() {
    let (_s, driver) = setup(true);
    let (u, woke, h) = parked_participant("worker", 2);
    assert!(wait_real(
        || driver.quiescence().quiescent,
        Duration::from_secs(5)
    ));

    let u2 = u.clone();
    spawn_foreign("careful", move || {
        let lease = busy("careful-work");
        u2.unpark();
        drop(lease);
    })
    .join()
    .unwrap();
    assert!(wait_real(
        || woke.load(Ordering::SeqCst) == 1 && driver.quiescence().quiescent,
        Duration::from_secs(5)
    ));
    assert!(driver.audit().violations.is_empty());
    assert_eq!(driver.audit().stray_wakes, 0);

    spawn_foreign("leaky", move || {
        let lease = busy("leaky-work");
        drop(lease);
        u.unpark();
    })
    .join()
    .unwrap();
    h.join().unwrap();

    let audit = driver.audit();
    assert_eq!(audit.total_violations, 1, "{audit:?}");
    let v = &audit.violations[0];
    assert_eq!((&*v.thread, v.op, v.blocked), ("leaky", "unpark", false));
    assert_eq!(audit.stray_wakes, 1);
}

#[test]
fn block_on_a_flume_receive_is_blocked() {
    let (_s, driver) = setup(false);
    let (tx, rx) = flume::bounded::<u32>(1);
    let h = spawn_named("consumer", move || block_on(rx.recv_async()).unwrap());

    assert!(wait_real(
        || state_of(&driver, "consumer") == Some(PState::Blocked),
        Duration::from_secs(5)
    ));
    let info = driver
        .participants()
        .into_iter()
        .find(|p| &*p.name == "consumer")
        .unwrap();
    assert_eq!(info.wait, Some("block_on"));
    assert!(driver.quiescence().quiescent);

    tx.send(42).unwrap();
    assert_eq!(h.join().unwrap(), 42);
    assert!(driver.audit().strays.is_empty());
}

#[test]
fn a_lease_blocks_quiescence_and_its_release_notifies() {
    let (_s, driver) = setup(false);
    let lease = busy("render");
    let q = driver.quiescence();
    assert!(!q.quiescent);
    assert_eq!(q.busy, 1);
    assert_eq!(q.blocker, Some((BlockerKind::Lease, Arc::from("render"))));
    assert!(
        driver
            .participants()
            .iter()
            .any(|p| p.state == PState::Busy("render"))
    );

    let fired = Arc::new(AtomicBool::new(false));
    let f = Arc::clone(&fired);
    driver.arm_notify(q.epoch, Arc::new(move || f.store(true, Ordering::SeqCst)));
    assert!(!fired.load(Ordering::SeqCst));
    let moved = std::thread::spawn(move || drop(lease));
    moved.join().unwrap();
    assert!(fired.load(Ordering::SeqCst));
    assert!(driver.quiescence().quiescent);
}

#[test]
fn hints_are_drained_once() {
    let (_s, driver) = setup(false);
    sched::hint_starving("stmo-left", 1.0);
    sched::hint_starving("seam", 0.5);
    assert_eq!(
        driver.drain_hints(),
        vec![(Arc::from("stmo-left"), 1.0), (Arc::from("seam"), 0.5)]
    );
    assert!(driver.drain_hints().is_empty());
}

#[test]
fn explicit_participation_and_timers_listing() {
    let (_s, driver) = setup(false);
    let t0 = driver.now();
    let (tx, rx) = mpsc::channel::<()>();
    let h = std::thread::spawn({
        let parent = std::thread::current().id();
        move || {
            snare::register_thread_child_of(parent);
            let _g = sched::participate("arm-left");
            assert!(sched::is_participant());
            tx.send(()).unwrap();
            park(Some(
                snare::time::Instant::now() + Duration::from_millis(20),
            ))
        }
    });
    rx.recv().unwrap();
    assert!(wait_real(
        || state_of(&driver, "arm-left") == Some(PState::Blocked),
        Duration::from_secs(5)
    ));
    let timers = driver.timers(8);
    assert_eq!(timers.len(), 1);
    assert_eq!(timers[0].deadline, t0 + Duration::from_millis(20));
    assert_eq!(timers[0].owner.as_deref(), Some("arm-left"));

    assert_eq!(driver.jump_to(t0 + Duration::from_secs(1)), Ok(1));
    assert_eq!(h.join().unwrap(), ParkResult::TimedOut);
    assert!(driver.participants().is_empty());
}

#[test]
fn accounting_off_is_never_quiescent() {
    let _s = serial();
    register_test();
    let driver = attach_driver(DriverConfig::default()).unwrap();
    let q = driver.quiescence();
    assert!(!q.quiescent);
    assert_eq!(q.blocker.map(|b| b.0), Some(BlockerKind::Untracked));
    assert_eq!(
        driver.jump_to(driver.now() + Duration::from_secs(1)),
        Err(NotQuiescent)
    );
    let h = snare::thread::spawn(sched::is_participant);
    assert!(!h.join().unwrap());
}

#[test]
fn a_timer_in_flight_is_not_quiescent() {
    let (_s, driver) = setup(false);
    let done = Arc::new(AtomicBool::new(false));
    let worst = Arc::new(AtomicU64::new(0));
    let (d, w) = (Arc::clone(&done), Arc::clone(&worst));
    let h = spawn_named("ticker", move || {
        for _ in 0..3000 {
            let deadline = snare::time::Instant::now() + Duration::from_micros(50);
            snare::thread::sleep_until(deadline);
            let lag = snare::time::Instant::now().saturating_duration_since(deadline);
            w.fetch_max(lag.as_nanos() as u64, Ordering::SeqCst);
        }
        d.store(true, Ordering::SeqCst);
    });

    let regrant = |driver: &Driver| {
        driver.grant(sched::Grant {
            anchor_v: driver.now(),
            anchor_wall: std::time::Instant::now(),
            rate: 1.0,
            horizon: Duration::MAX,
        })
    };
    regrant(&driver);
    while !done.load(Ordering::SeqCst) {
        if driver.quiescence().quiescent
            && driver
                .jump_to(driver.now() + Duration::from_secs(1))
                .is_ok()
        {
            regrant(&driver);
        }
        std::hint::spin_loop();
    }
    h.join().unwrap();
    let worst = Duration::from_nanos(worst.load(Ordering::SeqCst));
    assert!(
        worst < Duration::from_millis(500),
        "a sleeper woke {worst:?} late"
    );
}

#[test]
fn firing_a_sleep_from_an_unmarked_driver_thread_is_not_a_stray() {
    let _s = serial();
    register_test();
    let driver = attach_driver(DriverConfig {
        seed: 1,
        accounting: true,
        audit: true,
    })
    .unwrap();
    let t0 = driver.now();
    let h = spawn_named("sleeper", move || {
        block_on(sched::sleep_until(
            snare::time::Instant::now() + Duration::from_millis(5),
        ));
        time_value()
    });
    assert!(wait_real(
        || state_of(&driver, "sleeper") == Some(PState::Blocked),
        Duration::from_secs(5)
    ));
    assert_eq!(driver.jump_to(t0 + Duration::from_secs(1)), Ok(1));
    assert_eq!(h.join().unwrap(), t0 + Duration::from_millis(5));
    let audit = driver.audit();
    assert!(audit.strays.is_empty(), "{audit:?}");
    assert_eq!(audit.total_violations, 0, "{audit:?}");
    assert!(!sched::is_participant());
    assert!(driver.quiescence().quiescent);
}
