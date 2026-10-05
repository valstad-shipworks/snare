use std::future::{Future, pending};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use snare::register_test;
use snare::sched::{
    self, Driver, DriverConfig, NotQuiescent, PState, WakerSet, attach_driver, block_on_timeout,
    block_on_until,
    testkit::{StrictClock, StrictConfig},
};
use snare::time::Instant;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn strict() -> (MutexGuard<'static, ()>, StrictClock) {
    let guard = serial();
    register_test();
    let clock = StrictClock::start(StrictConfig {
        seed: 3,
        ..StrictConfig::default()
    })
    .unwrap();
    (guard, clock)
}

fn manual() -> (MutexGuard<'static, ()>, Driver) {
    let guard = serial();
    register_test();
    sched::mark_driver_thread();
    let driver = attach_driver(DriverConfig {
        seed: 3,
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

fn spawn_named<T: Send + 'static>(
    name: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> std::thread::JoinHandle<T> {
    snare::thread::Builder::new()
        .name(name.to_string())
        .spawn(f)
        .unwrap()
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

#[derive(Default)]
struct Flag {
    set: AtomicBool,
    wakers: WakerSet,
}

impl Flag {
    fn raise(&self) {
        self.set.store(true, Ordering::SeqCst);
        self.wakers.wake_all();
    }

    fn wait(self: &Arc<Self>) -> FlagWait {
        FlagWait(Arc::clone(self))
    }
}

struct FlagWait(Arc<Flag>);

impl Future for FlagWait {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.0.wakers.register(cx.waker());
        if self.0.set.load(Ordering::SeqCst) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

fn state_of(driver: &Driver, name: &str) -> Option<PState> {
    driver
        .participants()
        .into_iter()
        .find(|p| &*p.name == name)
        .map(|p| p.state)
}

#[test]
fn is_driven_follows_the_driver_and_the_thread_class() {
    let _g = serial();
    register_test();
    assert!(!sched::is_driven());
    assert!(!sched::is_participant());
    sched::mark_driver_thread();
    let driver = attach_driver(DriverConfig {
        seed: 1,
        accounting: true,
        audit: false,
    })
    .unwrap();
    assert!(!sched::is_driven(), "a driver-class thread is never driven");

    let child = spawn_named("driven-child", || {
        (sched::is_driven(), sched::is_participant())
    });
    assert_eq!(child.join().unwrap(), (true, true));

    let foreign = spawn_foreign("driven-foreign", || {
        let before = sched::is_participant();
        let driven = sched::is_driven();
        let after = sched::is_participant();
        sched::mark_background("bg");
        (
            before,
            driven,
            after,
            sched::is_driven(),
            sched::thread_class(),
        )
    });
    let (before, driven, after, bg_driven, class) = foreign.join().unwrap();
    assert!(
        !before && !after,
        "is_participant and is_driven never register"
    );
    assert!(driven);
    assert!(!bg_driven);
    assert_eq!(class, sched::ThreadClass::Background);
    assert!(
        driver
            .participants()
            .iter()
            .all(|p| &*p.name != "driven-foreign")
    );
    drop(driver);
}

#[test]
fn block_on_timeout_expires_at_the_virtual_deadline() {
    let (_g, clock) = strict();
    let h = spawn_named("timeout-waiter", || {
        let t0 = Instant::now();
        let r = block_on_timeout(pending::<()>(), Duration::from_secs(2));
        (r, Instant::now().duration_since(t0))
    });
    let (r, took) = h.join().unwrap();
    assert_eq!(r, None);
    assert_eq!(took, Duration::from_secs(2));
    drop(clock);
}

#[test]
fn a_future_completed_after_a_virtual_sleep_returns_at_that_instant() {
    let (_g, clock) = strict();
    let setup = sched::setup_scope("spawn");
    let flag = Arc::new(Flag::default());
    let f = Arc::clone(&flag);
    let waiter = spawn_named("flag-waiter", move || {
        let t0 = Instant::now();
        let r = block_on_timeout(f.wait(), Duration::from_secs(1));
        (r, Instant::now().duration_since(t0))
    });
    let f = Arc::clone(&flag);
    let raiser = spawn_named("flag-raiser", move || {
        snare::thread::sleep(Duration::from_millis(8));
        f.raise();
    });
    drop(setup);
    raiser.join().unwrap();
    let (r, took) = waiter.join().unwrap();
    assert_eq!(r, Some(()));
    assert_eq!(took, Duration::from_millis(8));
    drop(clock);
}

#[test]
fn a_waker_set_wakes_every_waiter() {
    let (_g, clock) = strict();
    let t0 = clock.now();
    let setup = sched::setup_scope("spawn");
    let flag = Arc::new(Flag::default());
    let waiters: Vec<_> = (0..2)
        .map(|i| {
            let f = Arc::clone(&flag);
            spawn_named(&format!("set-waiter-{i}"), move || {
                block_on_timeout(f.wait(), Duration::from_secs(5))
            })
        })
        .collect();
    let f = Arc::clone(&flag);
    let raiser = spawn_named("set-raiser", move || {
        snare::thread::sleep(Duration::from_millis(3));
        f.raise();
    });
    drop(setup);
    raiser.join().unwrap();
    for w in waiters {
        assert_eq!(w.join().unwrap(), Some(()));
    }
    assert_eq!(clock.now() - t0, Duration::from_millis(3));
    drop(clock);
}

#[test]
fn a_block_on_until_wait_is_quiescent_and_gates_checked_entry() {
    let (_g, driver) = manual();
    let t0 = driver.now();
    let at = t0 + Duration::from_millis(1);
    let flag = Arc::new(Flag::default());
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let f = Arc::clone(&flag);
    let h = spawn_named("until-waiter", move || {
        go_rx.recv().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        block_on_until(f.wait(), Some(deadline))
    });

    assert!(wait_real(|| state_of(&driver, "until-waiter").is_some()));
    assert_eq!(
        driver.enter_timestamp_checked(at),
        Err(NotQuiescent),
        "a running participant blocks checked entry"
    );
    assert!(!driver.quiescence().quiescent);

    go_tx.send(()).unwrap();
    assert!(wait_real(|| driver.quiescence().quiescent));
    let info = driver
        .participants()
        .into_iter()
        .find(|p| &*p.name == "until-waiter")
        .unwrap();
    assert_eq!(info.state, PState::Blocked);
    assert_eq!(info.wait, Some("block_on"));
    assert_eq!(info.deadline, Some(t0 + Duration::from_secs(10)));

    assert_eq!(
        driver.enter_timestamp_checked(t0 + Duration::from_secs(11)),
        Err(NotQuiescent),
        "a timer due before the timestamp blocks checked entry"
    );
    driver.enter_timestamp_checked(at).unwrap();
    assert_eq!(snare::time_value(), at);
    flag.raise();
    assert_eq!(state_of(&driver, "until-waiter"), Some(PState::Blocked));
    driver.leave_timestamp(at);
    assert_eq!(h.join().unwrap(), Some(()));
    assert_eq!(driver.now(), at);
}
