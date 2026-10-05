//! Behaviour pins for the executive (`snare::sched::Executive`), ahead of performance work on the
//! clock and the quiescence census: the exact time each move lands on, what each move returns, and
//! what it leaves the sim's quiescence reading at.
//!
//! The rules pinned: `jump_to` lands exactly on the earliest participant timer at or before its
//! target (not 1 ns past it, as a time skip does), or exactly on the target with none, and never
//! back; a sleeper it releases reads exactly its deadline; `freeze` holds the clock where charges
//! left it until the next grant; a timestamp before the current time changes nothing the code
//! under test reads; a timestamp with nothing at it releases nothing, kicks no one and leaves the
//! quiescence epoch where it was; a busy or setup lease refuses every gated move until it is given
//! back; wakes between the sim's own threads are never counted as outside wakes; the quiescence
//! epoch never goes back; the thread census lists each of the sim's threads under its class; the
//! driver-time API refuses a thread that is not a driver.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use snare::Sim;
use snare::sched::{
    self, BlockerKind, Executive, ExecutiveConfig, Grant, NotQuiescent, Quiescence, ThreadClass,
    ThreadOwner,
};

const MS: Duration = Duration::from_millis(1);
const NS: Duration = Duration::from_nanos(1);

fn real_now() -> Instant {
    snare::real(Instant::now)
}

fn real_since(start: Instant) -> Duration {
    snare::real(|| start.elapsed())
}

fn real_sleep(d: Duration) {
    snare::real(|| thread::sleep(d));
}

/// A sim to build, with its name for messages.
type NamedSim = (&'static str, fn() -> Sim);

fn sims() -> [NamedSim; 2] {
    [
        ("discrete", Sim::new as fn() -> Sim),
        ("deterministic", || {
            Sim::builder().deterministic().seed(5).build()
        }),
    ]
}

/// Waits until the sim is quiescent with `blocked` participants blocked and `next` its next
/// participant deadline.
fn settle(exec: &Executive, blocked: u32, next: Option<Duration>) -> Quiescence {
    let start = real_now();
    loop {
        let q = exec.quiescence();
        if q.quiescent && q.blocked == blocked && q.next_deadline == next {
            return q;
        }
        assert!(
            real_since(start) < Duration::from_secs(20),
            "never settled at {blocked} blocked, next {next:?}: {q:?}"
        );
        real_sleep(Duration::from_micros(200));
    }
}

/// Jumps to `t` once the sim has settled into a quiescent state, retrying while a woken waiter
/// has yet to run.
fn jump(exec: &Executive, t: Duration) -> u32 {
    let start = real_now();
    loop {
        if let Ok(fired) = exec.jump_to(t) {
            return fired;
        }
        assert!(
            real_since(start) < Duration::from_secs(20),
            "never quiescent"
        );
        real_sleep(Duration::from_micros(200));
    }
}

fn frozen_grant(exec: &Executive, horizon: Duration) {
    exec.grant(Grant {
        anchor_v: exec.now(),
        anchor_wall: real_now(),
        rate: 0.0,
        horizon,
    });
}

/// Sleepers at 3, 3, 6 and 9 ms; each returns the sim time it woke at.
fn sleepers() -> Vec<Duration> {
    let handles: Vec<_> = [3, 3, 6, 9]
        .into_iter()
        .map(|ms| {
            thread::spawn(move || {
                thread::sleep(ms * MS);
                sched::now()
            })
        })
        .collect();
    handles.into_iter().map(|h| h.join().unwrap()).collect()
}

#[test]
fn jumps_land_exactly_on_timers_and_targets() {
    for (name, sim) in sims() {
        let sim = sim();
        thread::scope(|s| {
            let exec = sim.executive(ExecutiveConfig::default()).unwrap();
            let run = s.spawn(|| sim.run(sleepers));
            settle(&exec, 5, Some(3 * MS));
            assert_eq!(jump(&exec, 2 * MS), 0, "{name}: short of every timer");
            assert_eq!(exec.now(), 2 * MS, "{name}");
            settle(&exec, 5, Some(3 * MS));
            assert_eq!(jump(&exec, MS), 0, "{name}: a target behind");
            assert_eq!(exec.now(), 2 * MS, "{name}: never back");
            settle(&exec, 5, Some(3 * MS));
            assert_eq!(jump(&exec, 3 * MS), 2, "{name}: a target on a timer");
            assert_eq!(exec.now(), 3 * MS, "{name}");
            settle(&exec, 3, Some(6 * MS));
            assert_eq!(jump(&exec, 6 * MS - NS), 0, "{name}: 1 ns short");
            assert_eq!(exec.now(), 6 * MS - NS, "{name}");
            settle(&exec, 3, Some(6 * MS));
            assert_eq!(jump(&exec, Duration::from_secs(1)), 1, "{name}");
            assert_eq!(
                exec.now(),
                6 * MS,
                "{name}: lands on the timer, not past it"
            );
            settle(&exec, 2, Some(9 * MS));
            assert_eq!(jump(&exec, Duration::from_secs(1)), 1, "{name}");
            assert_eq!(exec.now(), 9 * MS, "{name}");
            assert_eq!(
                run.join().unwrap(),
                vec![3 * MS, 3 * MS, 6 * MS, 9 * MS],
                "{name}: each sleeper reads exactly its deadline"
            );
        });
    }
}

/// Charges crawl a frozen grant up to its horizon; `freeze` pins the horizon where the clock is,
/// so further charges are free until a new grant raises it.
#[test]
fn freeze_holds_the_clock_where_the_charges_left_it() {
    for (name, sim) in sims() {
        let sim = sim();
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        frozen_grant(&exec, MS);
        let charge = |n: usize| {
            sim.run(|| {
                let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
                sock.set_nonblocking(true).unwrap();
                let mut buf = [0u8; 4];
                for _ in 0..n {
                    assert!(sock.recv_from(&mut buf).is_err());
                }
                sched::now()
            })
        };
        assert_eq!(charge(3), Duration::from_micros(3), "{name}");
        exec.freeze();
        assert_eq!(charge(50), Duration::from_micros(3), "{name}: frozen");
        frozen_grant(&exec, Duration::from_micros(10));
        assert_eq!(
            charge(50),
            Duration::from_micros(10),
            "{name}: the new horizon"
        );
        assert_eq!(exec.now(), Duration::from_micros(10), "{name}");
    }
}

/// A timestamp entered and left with nothing at it releases nothing and leaves the blocked count
/// and the next deadline where they were, and on the plain clock the epoch too (under the
/// deterministic schedule it may move: see `edge_time_quiescence`'s ignored
/// `empty_timestamps_wake_no_one_under_deterministic`).
#[test]
fn an_empty_timestamp_leaves_the_sim_exactly_as_it_was() {
    for (name, sim) in sims() {
        let sim = sim();
        thread::scope(|s| {
            let exec = sim.executive(ExecutiveConfig::default()).unwrap();
            let run = s.spawn(|| {
                sim.run(|| {
                    thread::sleep(50 * MS);
                    sched::now()
                })
            });
            let before = settle(&exec, 1, Some(50 * MS));
            exec.enter_timestamp(20 * MS);
            assert_eq!(exec.now(), 20 * MS, "{name}");
            assert_eq!(exec.leave_timestamp(20 * MS), 0, "{name}");
            real_sleep(20 * MS);
            let after = exec.quiescence();
            if name == "discrete" {
                assert_eq!(after.epoch, before.epoch, "{name}: nobody was kicked");
            }
            assert_eq!(
                (after.quiescent, after.blocked, after.next_deadline),
                (true, 1, Some(50 * MS)),
                "{name}"
            );
            assert_eq!(exec.now(), 20 * MS, "{name}");
            assert_eq!(jump(&exec, Duration::from_secs(1)), 1, "{name}");
            assert_eq!(run.join().unwrap(), 50 * MS, "{name}");
        });
    }
}

/// A timestamp behind the current time: the driver reads it, the code under test never reads
/// less than it already did, and leaving it moves nothing.
#[test]
fn a_timestamp_behind_the_clock_changes_nothing_the_sim_reads() {
    for (name, sim) in sims() {
        let sim = sim();
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        assert_eq!(exec.jump_to(10 * MS), Ok(0), "{name}");
        let driver = sim.run(|| {
            sched::mark_driver_thread();
            exec.enter_timestamp(4 * MS);
            sched::now()
        });
        assert_eq!(driver, 4 * MS, "{name}: the driver reads its own time");
        assert_eq!(exec.now(), 10 * MS, "{name}: the sim never reads back");
        assert_eq!(sim.time_value(), 10 * MS, "{name}");
        assert_eq!(exec.leave_timestamp(4 * MS), 0, "{name}");
        assert_eq!(exec.now(), 10 * MS, "{name}");
        drop(exec);
        let after = thread::spawn(move || sim.run(sched::now)).join().unwrap();
        assert_eq!(after, 10 * MS, "{name}: handed back where it was");
    }
}

/// A timer exactly at the timestamp stays pending while it is open and fires on leaving; its
/// sleeper reads exactly the timestamp. A checked entry is refused for a timer 1 ns before it.
#[test]
fn a_timer_at_the_timestamp_fires_on_leaving_and_one_before_refuses_entry() {
    for (name, sim) in sims() {
        let sim = sim();
        thread::scope(|s| {
            let exec = sim.executive(ExecutiveConfig::default()).unwrap();
            let run = s.spawn(|| {
                sim.run(|| {
                    thread::sleep(8 * MS);
                    sched::now()
                })
            });
            settle(&exec, 1, Some(8 * MS));
            assert_eq!(
                exec.enter_timestamp_checked(8 * MS + NS),
                Err(NotQuiescent),
                "{name}"
            );
            assert_eq!(
                exec.now(),
                Duration::ZERO,
                "{name}: a refused entry changes nothing"
            );
            let start = real_now();
            while exec.enter_timestamp_checked(8 * MS).is_err() {
                assert!(real_since(start) < Duration::from_secs(20), "{name}");
                real_sleep(Duration::from_micros(200));
            }
            assert_eq!(exec.next_deadline(), Some(8 * MS), "{name}: still pending");
            assert_eq!(exec.leave_timestamp(8 * MS), 1, "{name}");
            assert_eq!(run.join().unwrap(), 8 * MS, "{name}");
        });
    }
}

/// While a busy or setup lease is held every gated move is refused and names it; the clock does
/// not move; once it is given back the same move goes through.
#[test]
fn leases_refuse_every_gated_move_until_given_back() {
    for (name, sim) in sims() {
        let sim = sim();
        thread::scope(|s| {
            let exec = sim.executive(ExecutiveConfig::default()).unwrap();
            let (taken, take) = std::sync::mpsc::channel();
            let (give_back, given) = std::sync::mpsc::channel::<()>();
            let run = s.spawn(|| {
                sim.run(|| {
                    let worker = thread::spawn(move || {
                        let setup = sched::setup_scope("boot");
                        taken.send(()).unwrap();
                        given.recv().unwrap();
                        drop(setup);
                        thread::sleep(4 * MS);
                        sched::now()
                    });
                    worker.join().unwrap()
                })
            });
            take.recv().unwrap();
            let busy = sim.busy("outside");
            let start = real_now();
            let q = loop {
                let q = exec.quiescence();
                if q.blocked == 2 {
                    break q;
                }
                assert!(real_since(start) < Duration::from_secs(20), "{name}: {q:?}");
                real_sleep(Duration::from_micros(200));
            };
            assert!(!q.quiescent, "{name}");
            assert_eq!(q.busy, 2, "{name}");
            assert_eq!(
                q.blocker.as_ref().map(|(kind, _)| *kind),
                Some(BlockerKind::Lease),
                "{name}"
            );
            assert_eq!(exec.jump_to(MS), Err(NotQuiescent), "{name}");
            assert_eq!(
                exec.enter_timestamp_checked(MS),
                Err(NotQuiescent),
                "{name}"
            );
            drop(busy);
            assert_eq!(
                exec.jump_to(MS),
                Err(NotQuiescent),
                "{name}: setup still held"
            );
            assert_eq!(exec.now(), Duration::ZERO, "{name}");
            give_back.send(()).unwrap();
            settle(&exec, 2, Some(4 * MS));
            assert_eq!(jump(&exec, MS), 0, "{name}");
            settle(&exec, 2, Some(4 * MS));
            assert_eq!(jump(&exec, MS * 10), 1, "{name}");
            assert_eq!(run.join().unwrap(), 4 * MS, "{name}");
        });
    }
}

/// A hundred condition-variable round trips between the sim's own threads, each round started by
/// a sleep the executive jumps to, checking that the quiescence epoch read between jumps never goes
/// back. Returns each sim's outside-wake count.
fn ping_pong_under_jumps() -> Vec<(&'static str, u64)> {
    let mut counts = Vec::new();
    const ROUNDS: u32 = 100;
    for (name, sim) in sims() {
        let sim = sim();
        let done = AtomicBool::new(false);
        thread::scope(|s| {
            let exec = sim.executive(ExecutiveConfig::default()).unwrap();
            let run = s.spawn(|| {
                sim.run(|| {
                    let pair = Arc::new((Mutex::new(0u32), Condvar::new()));
                    let ponger = {
                        let pair = pair.clone();
                        thread::spawn(move || {
                            for round in 1..=ROUNDS {
                                let mut turn = pair.0.lock().unwrap();
                                while *turn != 2 * round - 1 {
                                    turn = pair.1.wait(turn).unwrap();
                                }
                                *turn += 1;
                                pair.1.notify_all();
                            }
                        })
                    };
                    for round in 1..=ROUNDS {
                        thread::sleep(MS);
                        let mut turn = pair.0.lock().unwrap();
                        *turn += 1;
                        pair.1.notify_all();
                        while *turn != 2 * round {
                            turn = pair.1.wait(turn).unwrap();
                        }
                    }
                    ponger.join().unwrap();
                    done.store(true, Ordering::SeqCst);
                })
            });
            let mut last = exec.quiescence().epoch;
            let start = real_now();
            while !done.load(Ordering::SeqCst) {
                let q = exec.quiescence();
                assert!(q.epoch >= last, "{name}: epoch went back");
                last = q.epoch;
                if let Some(next) = q.next_deadline.filter(|_| q.quiescent) {
                    let _ = exec.jump_to(next);
                }
                assert!(
                    real_since(start) < Duration::from_secs(60),
                    "{name}: {q:?} {:?}",
                    exec.participants()
                );
                thread::yield_now();
            }
            run.join().unwrap();
            assert_eq!(
                exec.now(),
                MS * ROUNDS,
                "{name}: each jump lands on a sleep's deadline"
            );
            counts.push((name, exec.outside_wakes()));
            assert!(exec.quiescence().epoch >= last, "{name}");
        });
    }
    counts
}

#[test]
fn the_quiescence_epoch_only_rises() {
    assert_eq!(ping_pong_under_jumps().len(), 2);
}

#[test]
fn the_sims_own_wakes_are_never_outside_wakes() {
    for (name, outside) in ping_pong_under_jumps() {
        assert_eq!(outside, 0, "{name}");
    }
}

/// The census taken inside the run lists the run's threads under their classes, by name.
#[test]
fn the_census_lists_each_thread_under_its_class() {
    for (name, sim) in sims() {
        let sim = sim();
        let census = sim.run(|| {
            let (ready, wait) = std::sync::mpsc::channel();
            let spawn = |label: &'static str, class: Option<ThreadClass>| {
                let ready = ready.clone();
                let (release, stop) = std::sync::mpsc::channel::<()>();
                let handle = thread::Builder::new()
                    .name(label.into())
                    .spawn(move || {
                        match class {
                            Some(ThreadClass::Background) => sched::mark_background(label),
                            Some(ThreadClass::Helper) => sched::mark_helper(),
                            _ => {}
                        }
                        ready.send(()).unwrap();
                        stop.recv().ok();
                    })
                    .unwrap();
                (handle, release)
            };
            let threads = [
                spawn("edge-part", None),
                spawn("edge-bg", Some(ThreadClass::Background)),
                spawn("edge-helper", Some(ThreadClass::Helper)),
            ];
            for _ in 0..3 {
                wait.recv().unwrap();
            }
            let census = sched::thread_census();
            for (handle, release) in threads {
                release.send(()).unwrap();
                handle.join().unwrap();
            }
            census
        });
        let Some(census) = census else {
            continue;
        };
        let class_of = |label: &str| {
            census
                .this_sim()
                .find(|t| t.name.as_deref() == Some(label))
                .map(|t| t.owner)
        };
        assert_eq!(
            class_of("edge-part"),
            Some(ThreadOwner::ThisSim(ThreadClass::Participant)),
            "{name}: {census:?}"
        );
        assert_eq!(
            class_of("edge-bg"),
            Some(ThreadOwner::ThisSim(ThreadClass::Background)),
            "{name}"
        );
        assert_eq!(
            class_of("edge-helper"),
            Some(ThreadOwner::ThisSim(ThreadClass::Helper)),
            "{name}"
        );
        assert!(
            census.this_sim().count() >= 4,
            "{name}: the run's own thread and the three: {census:?}"
        );
    }
}

#[test]
fn driver_time_refuses_a_participant_and_a_thread_off_the_sim() {
    let panics = |f: fn()| std::panic::catch_unwind(f).is_err();
    assert!(panics(|| {
        Sim::new().run(|| sched::with_driver_time(MS, || ()));
    }));
    assert!(panics(|| sched::with_driver_time(MS, || ())));
    let read = Sim::new().run(|| {
        sched::mark_driver_thread();
        sched::with_driver_time(7 * MS, sched::now)
    });
    assert_eq!(read, 7 * MS);
}

#[cfg(unix)]
#[test]
fn quiescence_keeps_the_deadline_of_a_concurrently_released_timed_wait() {
    let sim = Sim::new();
    let exec = sim.executive(ExecutiveConfig::default()).unwrap();
    let state = Arc::new((Mutex::new(()), Condvar::new()));
    let done = AtomicBool::new(false);
    let stop = AtomicBool::new(false);
    let started = AtomicBool::new(false);
    let deadline_missing = thread::scope(|scope| {
        let run = scope.spawn(|| {
            sim.run(|| {
                let (lock, cv) = &*state;
                started.store(true, Ordering::Release);
                for _ in 0..10_000 {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let guard = lock.lock().unwrap();
                    drop(cv.wait_timeout(guard, Duration::from_secs(1)).unwrap());
                }
            });
            done.store(true, Ordering::Release);
        });
        let notify = scope.spawn(|| {
            while !stop.load(Ordering::Acquire) && !done.load(Ordering::Acquire) {
                state.1.notify_one();
                real_sleep(Duration::from_micros(10));
            }
        });
        let start = real_now();
        let mut missing = None;
        while !done.load(Ordering::Acquire) && real_since(start) < Duration::from_secs(3) {
            let q = exec.quiescence();
            if started.load(Ordering::Acquire)
                && q.quiescent
                && q.blocked == 1
                && q.next_deadline.is_none()
            {
                missing = Some(q);
                break;
            }
        }
        stop.store(true, Ordering::Release);
        exec.detach();
        state.1.notify_one();
        notify.join().unwrap();
        run.join().unwrap();
        missing
    });
    assert!(deadline_missing.is_none(), "{deadline_missing:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn a_futex_with_a_changed_value_never_makes_a_participant_quiescent() {
    let sim = Sim::new();
    let exec = sim.executive(ExecutiveConfig::default()).unwrap();
    let done = AtomicBool::new(false);
    let stop = AtomicBool::new(false);
    let observed = thread::scope(|scope| {
        let run = scope.spawn(|| {
            sim.run(|| {
                let word = std::sync::atomic::AtomicU32::new(0);
                while !stop.load(Ordering::Acquire) {
                    let result = unsafe {
                        libc::syscall(
                            libc::SYS_futex,
                            &word,
                            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                            1,
                            std::ptr::null::<libc::timespec>(),
                            0,
                            0,
                        )
                    };
                    assert_eq!(result, -1);
                    assert_eq!(
                        std::io::Error::last_os_error().raw_os_error(),
                        Some(libc::EAGAIN)
                    );
                }
            });
            done.store(true, Ordering::Release);
        });
        let start = real_now();
        let mut observed = None;
        while !done.load(Ordering::Acquire) && real_since(start) < Duration::from_millis(200) {
            let q = exec.quiescence();
            if q.quiescent && q.blocked == 1 {
                observed = Some(q);
                break;
            }
        }
        stop.store(true, Ordering::Release);
        exec.detach();
        run.join().unwrap();
        observed
    });
    assert!(observed.is_none(), "{observed:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn futex_wait_argument_errors_match_the_native_kernel() {
    Sim::new().run(|| {});
    let word = std::sync::atomic::AtomicU32::new(0);
    let negative = libc::timespec {
        tv_sec: -1,
        tv_nsec: 0,
    };
    let invalid_nanos = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000_000,
    };
    let expired = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED);
    let address = std::ptr::from_ref(&word) as usize;
    let wait = libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG;
    let bitset = libc::FUTEX_WAIT_BITSET | libc::FUTEX_PRIVATE_FLAG;
    let cases = [
        (address, wait, 1, 0, 0),
        (0, wait, 1, 0, 0),
        (address + 1, wait, 1, 0, 0),
        (page as usize, wait, 1, 0, 0),
        (address, wait, 1, std::ptr::from_ref(&negative) as usize, 0),
        (
            address,
            wait,
            1,
            std::ptr::from_ref(&invalid_nanos) as usize,
            0,
        ),
        (address, wait, 1, 1, 0),
        (address, bitset, 1, 0, 0),
        (
            address,
            bitset,
            1,
            std::ptr::from_ref(&negative) as usize,
            1,
        ),
        (address, wait | libc::FUTEX_CLOCK_REALTIME, 1, 0, 0),
        (address, bitset, 0, std::ptr::from_ref(&expired) as usize, 1),
    ];
    let call = |(word, operation, expected, timeout, mask): (usize, i32, i32, usize, u32)| {
        let result =
            unsafe { libc::syscall(libc::SYS_futex, word, operation, expected, timeout, 0, mask) };
        (result, std::io::Error::last_os_error().raw_os_error())
    };
    let native = snare::real(|| cases.map(call));
    let simulated = [Sim::new(), Sim::builder().deterministic().seed(31).build()]
        .map(|sim| sim.run(|| cases.map(call)));
    assert_eq!(unsafe { libc::munmap(page, 4096) }, 0);
    for result in simulated {
        assert_eq!(result, native);
    }
}
