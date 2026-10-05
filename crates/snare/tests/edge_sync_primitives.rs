//! std's synchronisation primitives under a sim, pinned for the performance pass. Under
//! `deterministic()` each scenario's trace — who acquired, woke or timed out, and at which virtual
//! instant to the nanosecond — replays exactly and matches its golden
//! (`golden/edge_sync_primitives.<os>.txt`): Mutex hand-offs, RwLock reader/writer order, Condvar
//! `notify_one` against `notify_all` with every wake counted, a Condvar timeout, OnceLock and Once
//! racing initialisers, Barrier leaders, rendezvous and timed channels, park/unpark, and try_lock
//! storms. On the plain clock the same primitives keep their ordering and virtual-time bounds.
//! Locks held across a run's end, taken outside and released inside, and held by a thread the run
//! left behind, are all eventually taken.
#![cfg(unix)]

#[path = "support/golden.rs"]
mod golden;

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex, Once, OnceLock, RwLock, mpsc};
use std::time::{Duration, Instant};

use snare::Sim;

/// One scenario's events, each stamped with the sim's time read without ticking it.
#[derive(Clone, Default)]
struct Trace(Arc<Mutex<Vec<(String, Duration)>>>);

impl Trace {
    fn note(&self, what: impl Into<String>) {
        let at = snare::sched::now();
        self.0.lock().unwrap().push((what.into(), at));
    }

    fn take(&self) -> Vec<(String, Duration)> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

/// Runs `scenario` on two fresh deterministic sims, checks they agree, and renders the trace with
/// times relative to the run's start.
fn replayed(name: &str, scenario: fn(&Trace)) -> String {
    let run = || {
        let sim = Sim::builder().deterministic().seed(1).build();
        let trace = Trace::default();
        let start = sim.time_value();
        sim.run(|| scenario(&trace));
        trace
            .take()
            .into_iter()
            .map(|(what, at)| (what, at.saturating_sub(start)))
            .collect::<Vec<_>>()
    };
    let first = run();
    let second = run();
    assert_eq!(first, second, "{name} replays");
    let mut out = format!("## {name}\n");
    for (what, at) in first {
        writeln!(out, "{:>12} ns  {what}", at.as_nanos()).unwrap();
    }
    out
}

fn mutex_handoff(trace: &Trace) {
    let lock = Arc::new(Mutex::new(()));
    let workers: Vec<_> = (0..4)
        .map(|w| {
            let (lock, trace) = (lock.clone(), trace.clone());
            std::thread::spawn(move || {
                for round in 0..2 {
                    let _held = lock.lock().unwrap();
                    trace.note(format!("w{w} r{round} acquired"));
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
}

fn rwlock_order(trace: &Trace) {
    let lock = Arc::new(RwLock::new(0u32));
    let writer = lock.write().unwrap();
    trace.note("main write");
    let readers: Vec<_> = (0..3)
        .map(|r| {
            let (lock, trace) = (lock.clone(), trace.clone());
            std::thread::spawn(move || {
                let value = *lock.read().unwrap();
                trace.note(format!("reader {r} saw {value}"));
                std::thread::sleep(Duration::from_millis(1));
            })
        })
        .collect();
    let second = {
        let (lock, trace) = (lock.clone(), trace.clone());
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_micros(500));
            let mut w = lock.write().unwrap();
            *w += 10;
            trace.note(format!("writer 2 wrote {}", *w));
        })
    };
    std::thread::sleep(Duration::from_millis(2));
    drop(writer);
    trace.note("main released");
    for r in readers {
        r.join().unwrap();
    }
    second.join().unwrap();
    trace.note(format!("final {}", *lock.read().unwrap()));
}

fn condvar_notify_counts(trace: &Trace) {
    let state = Arc::new((Mutex::new((0u32, 0u32)), Condvar::new()));
    let wakes = Arc::new(AtomicU32::new(0));
    let waiters: Vec<_> = (0..5)
        .map(|w| {
            let (state, trace, wakes) = (state.clone(), trace.clone(), wakes.clone());
            std::thread::spawn(move || {
                let (lock, cv) = &*state;
                let mut s = lock.lock().unwrap();
                s.0 += 1;
                let ticket = s.1;
                while s.1 == ticket {
                    s = cv.wait(s).unwrap();
                    wakes.fetch_add(1, Ordering::SeqCst);
                }
                trace.note(format!("waiter {w} through ticket {}", s.1));
            })
        })
        .collect();
    let (lock, cv) = &*state;
    while lock.lock().unwrap().0 < 5 {
        std::thread::sleep(Duration::from_micros(10));
    }
    trace.note("all waiting");
    lock.lock().unwrap().1 = 1;
    cv.notify_one();
    std::thread::sleep(Duration::from_millis(1));
    trace.note(format!(
        "after notify_one: {} wakes",
        wakes.load(Ordering::SeqCst)
    ));
    cv.notify_all();
    for w in waiters {
        w.join().unwrap();
    }
    trace.note(format!(
        "after notify_all: {} wakes",
        wakes.load(Ordering::SeqCst)
    ));
}

fn condvar_timeout(trace: &Trace) {
    let lock = Mutex::new(());
    let cv = Condvar::new();
    let (guard, result) = cv
        .wait_timeout(lock.lock().unwrap(), Duration::from_millis(7))
        .unwrap();
    drop(guard);
    trace.note(format!("wait_timeout timed_out={}", result.timed_out()));
    let (_guard, result) = cv
        .wait_timeout_while(lock.lock().unwrap(), Duration::from_millis(3), |_| true)
        .unwrap();
    trace.note(format!(
        "wait_timeout_while timed_out={}",
        result.timed_out()
    ));
}

fn once_races(trace: &Trace) {
    let cell = Arc::new(OnceLock::new());
    let once = Arc::new(Once::new());
    let runs = Arc::new(AtomicU32::new(0));
    let racers: Vec<_> = (0..4)
        .map(|r| {
            let (cell, once, runs, trace) =
                (cell.clone(), once.clone(), runs.clone(), trace.clone());
            std::thread::spawn(move || {
                let value = *cell.get_or_init(|| {
                    runs.fetch_add(1, Ordering::SeqCst);
                    trace.note(format!("racer {r} initialises the cell"));
                    std::thread::sleep(Duration::from_millis(2));
                    r * 100
                });
                trace.note(format!("racer {r} sees {value}"));
                once.call_once(|| {
                    runs.fetch_add(1, Ordering::SeqCst);
                    trace.note(format!("racer {r} runs the once"));
                    std::thread::sleep(Duration::from_millis(1));
                });
                trace.note(format!("racer {r} past the once"));
            })
        })
        .collect();
    for r in racers {
        r.join().unwrap();
    }
    trace.note(format!("initialisers run {}", runs.load(Ordering::SeqCst)));
}

fn barrier_leaders(trace: &Trace) {
    let barrier = Arc::new(Barrier::new(4));
    let threads: Vec<_> = (0..4u64)
        .map(|t| {
            let (barrier, trace) = (barrier.clone(), trace.clone());
            std::thread::spawn(move || {
                for round in 0..2 {
                    std::thread::sleep(Duration::from_millis(t + 1));
                    let leader = barrier.wait().is_leader();
                    trace.note(format!("t{t} round {round} through leader={leader}"));
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
}

fn channels(trace: &Trace) {
    let (tx, rx) = mpsc::sync_channel::<u32>(0);
    let sender = {
        let trace = trace.clone();
        std::thread::spawn(move || {
            for n in 0..3 {
                tx.send(n).unwrap();
                trace.note(format!("sent {n}"));
            }
        })
    };
    for _ in 0..3 {
        std::thread::sleep(Duration::from_millis(1));
        let n = rx.recv().unwrap();
        trace.note(format!("received {n}"));
    }
    sender.join().unwrap();
    let (_tx, rx) = mpsc::channel::<u32>();
    let r = rx.recv_timeout(Duration::from_millis(4));
    trace.note(format!("recv_timeout {r:?}"));
    let (tx, rx) = mpsc::channel::<u32>();
    let late = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(3));
        tx.send(5).unwrap();
    });
    let r = rx.recv_timeout(Duration::from_millis(10));
    trace.note(format!("recv_timeout {r:?}"));
    late.join().unwrap();
}

fn park_unpark(trace: &Trace) {
    std::thread::park_timeout(Duration::from_millis(2));
    trace.note("park_timeout returned");
    let main = std::thread::current();
    main.unpark();
    std::thread::park();
    trace.note("park after unpark returned");
    let unparker = {
        let main = main.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(3));
            main.unpark();
        })
    };
    std::thread::park_timeout(Duration::from_millis(50));
    trace.note("park_timeout unparked");
    unparker.join().unwrap();
}

fn trylock_storm(trace: &Trace) {
    let lock = Arc::new(Mutex::new(0u32));
    let threads: Vec<_> = (0..6)
        .map(|t| {
            let lock = lock.clone();
            std::thread::spawn(move || {
                let mut won = 0;
                for _ in 0..50 {
                    if let Ok(mut g) = lock.try_lock() {
                        *g += 1;
                        won += 1;
                        std::thread::yield_now();
                    }
                    std::thread::yield_now();
                }
                (t, won)
            })
        })
        .collect();
    let wins: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    for (t, won) in &wins {
        trace.note(format!("t{t} won {won}"));
    }
    let total: u32 = wins.iter().map(|(_, w)| w).sum();
    assert_eq!(*lock.lock().unwrap(), total);
    trace.note(format!("total {total}"));
}

/// Checks `scenario`'s replayed trace against `golden/edge_sync_primitives/<name>.<os>.txt`.
fn check(name: &str, scenario: fn(&Trace)) {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else {
        "macos"
    };
    golden::check_text(
        &format!("edge_sync_primitives/{name}.{os}.txt"),
        &replayed(name, scenario),
    );
}

#[test]
fn mutex_hand_off_trace() {
    check("mutex_hand_off", mutex_handoff);
}

#[test]
fn rwlock_order_trace() {
    check("rwlock_order", rwlock_order);
}

#[test]
fn condvar_notify_counts_trace() {
    check("condvar_notify_counts", condvar_notify_counts);
}

#[test]
fn condvar_timeout_trace() {
    check("condvar_timeout", condvar_timeout);
}

#[test]
fn once_races_trace() {
    check("once_races", once_races);
}

#[test]
fn barrier_leaders_trace() {
    check("barrier_leaders", barrier_leaders);
}

#[test]
fn channels_trace() {
    check("channels", channels);
}

#[test]
fn park_and_unpark_trace() {
    check("park_and_unpark", park_unpark);
}

#[test]
fn try_lock_storm_trace() {
    check("try_lock_storm", trylock_storm);
}

#[test]
fn notify_one_wakes_exactly_one_of_five_on_the_plain_clock() {
    Sim::new().run(|| {
        let trace = Trace::default();
        condvar_notify_counts(&trace);
        let lines: Vec<String> = trace.take().into_iter().map(|(w, _)| w).collect();
        let through = lines
            .iter()
            .position(|l| l.starts_with("after notify_one"))
            .unwrap();
        assert_eq!(
            lines[through - 1..=through]
                .iter()
                .filter(|l| l.contains("through"))
                .count(),
            1,
            "{lines:?}"
        );
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.contains("through ticket 1"))
                .count(),
            5
        );
    });
}

#[test]
fn timed_waits_end_at_their_virtual_deadlines_on_the_plain_clock() {
    Sim::new().run(|| {
        let lock = Mutex::new(());
        let cv = Condvar::new();
        let start = Instant::now();
        let (_g, r) = cv
            .wait_timeout(lock.lock().unwrap(), Duration::from_secs(3))
            .unwrap();
        let condvar = start.elapsed();
        assert!(r.timed_out());
        let start = Instant::now();
        std::thread::park_timeout(Duration::from_secs(2));
        let park = start.elapsed();
        let (_tx, rx) = mpsc::channel::<()>();
        let start = Instant::now();
        assert!(rx.recv_timeout(Duration::from_secs(1)).is_err());
        let channel = start.elapsed();
        for (what, took, want) in [
            ("condvar", condvar, 3),
            ("park", park, 2),
            ("channel", channel, 1),
        ] {
            let want = Duration::from_secs(want);
            assert!(
                took >= want && took < want + Duration::from_millis(5),
                "{what}: {took:?}"
            );
        }
    });
}

/// Runs `f` on its own thread and fails if it takes longer than `limit`, so a lost wakeup fails
/// the test instead of hanging it.
fn within<R: Send + 'static>(
    limit: Duration,
    what: &str,
    f: impl FnOnce() -> R + Send + 'static,
) -> R {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(limit) {
        Ok(r) => r,
        Err(_) => panic!("{what} did not finish within {limit:?}"),
    }
}

#[test]
fn a_once_initialised_by_a_managed_thread_releases_a_passthrough_waiter() {
    within(Duration::from_secs(60), "the passthrough waiter", || {
        for _ in 0..20 {
            let once = Arc::new(Once::new());
            let order = Arc::new(Mutex::new(Vec::new()));
            Sim::new().run(|| {
                let (started_tx, started) = mpsc::channel();
                let (past_tx, past) = mpsc::channel();
                let initialiser = {
                    let (once, order) = (once.clone(), order.clone());
                    std::thread::spawn(move || {
                        once.call_once(|| {
                            started_tx.send(()).unwrap();
                            std::thread::sleep(Duration::from_millis(20));
                            order.lock().unwrap().push("managed init");
                        });
                    })
                };
                started.recv().unwrap();
                let (once, order2) = (once.clone(), order.clone());
                snare::real(|| {
                    std::thread::spawn(move || {
                        once.call_once(|| order2.lock().unwrap().push("passthrough init"));
                        order2.lock().unwrap().push("passthrough past");
                        past_tx.send(()).unwrap();
                    })
                });
                past.recv().unwrap();
                initialiser.join().unwrap();
            });
            assert_eq!(*order.lock().unwrap(), ["managed init", "passthrough past"]);
        }
    });
}

#[test]
fn a_once_initialised_under_passthrough_releases_a_managed_waiter() {
    within(Duration::from_secs(60), "the managed waiter", || {
        for _ in 0..20 {
            let once = Arc::new(Once::new());
            let order = Arc::new(Mutex::new(Vec::new()));
            Sim::new().run(|| {
                let (started_tx, started) = mpsc::channel();
                let initialiser = {
                    let (once, order) = (once.clone(), order.clone());
                    snare::real(|| {
                        std::thread::spawn(move || {
                            once.call_once(|| {
                                started_tx.send(()).unwrap();
                                std::thread::sleep(Duration::from_millis(5));
                                order.lock().unwrap().push("passthrough init");
                            });
                        })
                    })
                };
                snare::real(|| started.recv().unwrap());
                once.call_once(|| order.lock().unwrap().push("managed init"));
                order.lock().unwrap().push("managed past");
                snare::real(|| initialiser.join().unwrap());
            });
            assert_eq!(*order.lock().unwrap(), ["passthrough init", "managed past"]);
        }
    });
}

#[test]
fn a_once_raced_by_managed_and_passthrough_threads_runs_once() {
    within(Duration::from_secs(60), "the racers", || {
        for round in 0..50 {
            let once = Arc::new(Once::new());
            let runs = Arc::new(AtomicU32::new(0));
            Sim::new().run(|| {
                let (done_tx, done) = mpsc::channel();
                for r in 0..4 {
                    let (once, runs, done_tx) = (once.clone(), runs.clone(), done_tx.clone());
                    let body = move || {
                        once.call_once(|| {
                            runs.fetch_add(1, Ordering::SeqCst);
                            std::thread::sleep(Duration::from_millis(1));
                        });
                        done_tx.send(()).unwrap();
                    };
                    if (r + round) % 2 == 0 {
                        std::thread::spawn(body);
                    } else {
                        snare::real(|| std::thread::spawn(body));
                    }
                }
                for _ in 0..4 {
                    done.recv().unwrap();
                }
            });
            assert_eq!(runs.load(Ordering::SeqCst), 1);
        }
    });
}

#[test]
fn a_guard_carried_across_run_boundaries_is_released_inside_the_next_run() {
    within(Duration::from_secs(30), "the next run's waiter", || {
        let sim = Sim::new();
        let lock = Arc::new(Mutex::new(Vec::new()));
        let guard = sim.run(|| lock.lock().unwrap());
        assert!(lock.try_lock().is_err(), "held between runs");
        let (waited, slept) = sim.run(|| {
            let waiter = {
                let lock = lock.clone();
                std::thread::spawn(move || {
                    let start = Instant::now();
                    lock.lock().unwrap().push("waiter");
                    start.elapsed()
                })
            };
            let start = Instant::now();
            std::thread::sleep(Duration::from_secs(1));
            let slept = start.elapsed();
            let mut guard = guard;
            guard.push("holder");
            drop(guard);
            (waiter.join().unwrap(), slept)
        });
        assert!(slept >= Duration::from_secs(1));
        assert!(waited >= Duration::from_secs(1), "{waited:?}");
        assert_eq!(*lock.lock().unwrap(), ["holder", "waiter"]);
    });
}

#[test]
fn a_guard_taken_outside_every_sim_is_released_inside_one() {
    within(Duration::from_secs(30), "the waiter", || {
        let lock = Arc::new(Mutex::new(0u32));
        let guard = lock.lock().unwrap();
        let sim = Sim::new();
        sim.run(|| {
            let waiter = {
                let lock = lock.clone();
                std::thread::spawn(move || *lock.lock().unwrap() += 1)
            };
            std::thread::sleep(Duration::from_millis(10));
            drop(guard);
            waiter.join().unwrap();
        });
        assert_eq!(*lock.lock().unwrap(), 1);
    });
}

#[test]
fn a_lock_held_by_a_thread_the_run_left_behind_is_taken_by_the_next_run() {
    within(Duration::from_secs(30), "the next run", || {
        let sim = Sim::new();
        let lock = Arc::new(Mutex::new(Vec::new()));
        let (held_tx, held) = mpsc::channel();
        let leftover = sim.run(|| {
            let lock = lock.clone();
            std::thread::spawn(move || {
                let mut guard = lock.lock().unwrap();
                held_tx.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(30));
                guard.push("leftover");
            })
        });
        held.recv().unwrap();
        let virtual_wait = sim.run(|| {
            let start = Instant::now();
            lock.lock().unwrap().push("next run");
            start.elapsed()
        });
        leftover.join().unwrap();
        assert_eq!(*lock.lock().unwrap(), ["leftover", "next run"]);
        assert!(virtual_wait < Duration::from_secs(1), "{virtual_wait:?}");
    });
}

#[test]
fn a_guard_taken_before_a_deterministic_sim_is_released_inside_it() {
    within(Duration::from_secs(30), "the deterministic waiter", || {
        let lock = Arc::new(Mutex::new(0u32));
        let guard = lock.lock().unwrap();
        Sim::builder().deterministic().build().run(|| {
            let waiter = {
                let lock = lock.clone();
                std::thread::spawn(move || *lock.lock().unwrap() += 1)
            };
            std::thread::sleep(Duration::from_millis(10));
            drop(guard);
            waiter.join().unwrap();
        });
        assert_eq!(*lock.lock().unwrap(), 1);
    });
}
