//! Behaviour pins for quiescence, give-ups and wake-ups, ahead of performance work on the census,
//! the readiness board and the clock: when a blocked wait may give up (exactly when every
//! participant is blocked with nothing left to move time, never before), what happens to threads
//! left over after a run, that sims side by side never share time, and how many times a blocked
//! thread is woken per event, counted rather than timed.
//!
//! The rules pinned: a wait does not give up while another participant is running, is starting
//! (spawned but not yet run) or has been woken and not yet run; a deadlock with no timer gives up
//! without moving the clock; a thread left sleeping after its run sleeps no faster than real time
//! but lands each wake exactly; concurrent sims keep exact, independent clocks; the stuck watchdog
//! stays quiet through long virtual sleeps, a held lease and a paused clock; a condition-variable
//! waiter, a parked thread and a sleep future each wake exactly once per event; an empty
//! executive timestamp wakes no one and leaves the epoch alone.

use std::future::Future;
use std::net::UdpSocket;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use snare::Sim;
use snare::sched::{self, ExecutiveConfig};

#[path = "support/landing.rs"]
mod landing;

const MS: Duration = Duration::from_millis(1);

fn ns() -> u64 {
    sched::now().as_nanos() as u64
}

/// A sim to build, with its name for messages.
type NamedSim = (&'static str, fn() -> Sim);

fn sims() -> [NamedSim; 2] {
    [
        ("discrete", Sim::new as fn() -> Sim),
        ("deterministic", || {
            Sim::builder().deterministic().seed(11).build()
        }),
    ]
}

fn real_now() -> Instant {
    snare::real(Instant::now)
}

/// Burns CPU with no hooked call for about `spins` iterations.
fn compute(spins: u64) -> u64 {
    let mut x = 0u64;
    for i in 0..spins {
        x = std::hint::black_box(x.wrapping_mul(6364136223846793005).wrapping_add(i));
    }
    x
}

/// A blocked receive whose only sender is a thread just spawned, or busy computing with no hooked
/// call, waits for it rather than give up, and time does not move.
#[test]
fn a_wait_never_gives_up_while_a_thread_is_starting_or_computing() {
    for (name, sim) in sims() {
        for round in 0..40u64 {
            let got = sim().run(move || {
                let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
                let to = rx.local_addr().unwrap();
                let sender = thread::spawn(move || {
                    compute(round * 20_000);
                    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
                    tx.send_to(b"x", to).unwrap();
                });
                let mut buf = [0u8; 1];
                let got = rx.recv_from(&mut buf).map(|(n, _)| n);
                sender.join().unwrap();
                (got.ok(), ns())
            });
            assert_eq!(got, (Some(1), 0), "{name}, round {round}");
        }
    }
}

/// A receive whose sender has been notified out of a condition variable, by a thread that then
/// exits, waits for the woken sender to run.
#[test]
fn a_wait_never_gives_up_while_a_woken_thread_has_yet_to_run() {
    for (name, sim) in sims() {
        for round in 0..40 {
            let got = sim().run(|| {
                let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
                let to = rx.local_addr().unwrap();
                let gate = Arc::new((Mutex::new(false), Condvar::new()));
                let sender = {
                    let gate = gate.clone();
                    thread::spawn(move || {
                        let mut open = gate.0.lock().unwrap();
                        while !*open {
                            open = gate.1.wait(open).unwrap();
                        }
                        drop(open);
                        UdpSocket::bind("127.0.0.1:0")
                            .unwrap()
                            .send_to(b"y", to)
                            .unwrap();
                    })
                };
                let opener = thread::spawn(move || {
                    *gate.0.lock().unwrap() = true;
                    gate.1.notify_all();
                });
                let mut buf = [0u8; 1];
                let got = rx.recv_from(&mut buf).map(|(n, _)| n);
                opener.join().unwrap();
                sender.join().unwrap();
                (got.ok(), ns())
            });
            assert_eq!(got, (Some(1), 0), "{name}, round {round}");
        }
    }
}

/// A true deadlock with no timer: the blocked receive gives up with `WouldBlock`, the clock does
/// not move, and a join on a thread that gave up the same way returns.
#[test]
fn a_deadlock_with_no_timer_gives_up_without_moving_the_clock() {
    for (name, sim) in sims() {
        let seen = sim().run(|| {
            let blocked = thread::spawn(|| {
                let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
                let mut buf = [0u8; 1];
                sock.recv_from(&mut buf).unwrap_err().kind()
            });
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut buf = [0u8; 1];
            let mine = sock.recv_from(&mut buf).unwrap_err().kind();
            (mine, blocked.join().unwrap(), ns())
        });
        assert_eq!(
            seen,
            (
                std::io::ErrorKind::WouldBlock,
                std::io::ErrorKind::WouldBlock,
                0
            ),
            "{name}"
        );
    }
}

/// A deadlock behind a timer gives up only after the skip to the timer, and exactly there.
#[test]
fn a_deadlock_behind_a_timer_gives_up_just_past_it() {
    for (name, sim) in sims() {
        let seen = sim().run(|| {
            let sleeper = thread::spawn(|| thread::sleep(7 * MS));
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut buf = [0u8; 1];
            let kind = sock.recv_from(&mut buf).unwrap_err().kind();
            sleeper.join().unwrap();
            (kind, ns())
        });
        assert_eq!(
            seen,
            (std::io::ErrorKind::WouldBlock, landing::past(7_000_000)),
            "{name}"
        );
    }
}

/// A thread left sleeping in a loop after its run returns keeps landing exactly just past each
/// deadline, but no further ahead of where the run left the clock than real time has moved.
#[test]
fn a_thread_left_over_after_its_run_sleeps_no_faster_than_real_time() {
    for (name, sim) in sims() {
        let sim = sim();
        let (tx, rx) = mpsc::channel();
        let real = real_now();
        sim.run(move || {
            thread::spawn(move || {
                let mut seen = Vec::new();
                for _ in 0..5 {
                    thread::sleep(10 * MS);
                    seen.push(ns());
                }
                tx.send(seen).unwrap();
            });
        });
        let seen = rx.recv_timeout(Duration::from_secs(30)).unwrap();
        let elapsed = snare::real(|| real.elapsed());
        assert_eq!(seen, landing::steps(0, 10_000_000, 5), "{name}");
        assert!(
            Duration::from_nanos(seen[4]) <= elapsed,
            "{name}: {:?} of sim time in {elapsed:?} of real time",
            Duration::from_nanos(seen[4])
        );
    }
}

/// Sims running side by side on their own threads keep their own exact clocks, and pausing one
/// holds only that one.
#[test]
fn concurrent_sims_keep_independent_exact_clocks() {
    let paused = Sim::new();
    paused.pause_time();
    let held = thread::scope(|s| {
        let held = s.spawn(|| {
            paused.run(|| {
                let start = Instant::now();
                sched::park(Some(start + MS));
                ns()
            })
        });
        let runs: Vec<_> = (1..=4u32)
            .map(|k| {
                s.spawn(move || {
                    let sim = if k % 2 == 0 {
                        Sim::builder().deterministic().seed(k as u64).build()
                    } else {
                        Sim::new()
                    };
                    let seen = sim.run(|| {
                        (0..50)
                            .map(|_| {
                                thread::sleep(MS * k);
                                ns()
                            })
                            .collect::<Vec<_>>()
                    });
                    (k, seen, sim.time_value())
                })
            })
            .collect();
        for run in runs {
            let (k, seen, end) = run.join().unwrap();
            let expected = landing::steps(0, u64::from(k) * 1_000_000, 50);
            assert_eq!(seen, expected, "sim {k}");
            assert_eq!(end, Duration::from_nanos(expected[49]), "sim {k}");
        }
        assert_eq!(
            paused.time_value(),
            Duration::ZERO,
            "the paused sim never moved"
        );
        paused.time().advance(MS);
        held.join().unwrap()
    });
    assert_eq!(held, 1_000_000);
}

/// The stuck watchdog stays quiet through an hour of virtual sleeps, a lease held across real
/// work, and a paused clock held for a while; if it fired, it would abort this test binary.
#[test]
fn the_stuck_watchdog_stays_quiet_through_legitimate_waits() {
    for deterministic in [false, true] {
        let builder = Sim::builder().stuck_after(Duration::from_millis(40));
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        let at = sim.run(|| {
            for _ in 0..60 {
                thread::sleep(Duration::from_secs(60));
            }
            {
                let _busy = sched::busy("real work");
                snare::real(|| thread::sleep(Duration::from_millis(150)));
            }
            ns()
        });
        assert_eq!(
            at,
            landing::steps(0, 60_000_000_000, 60)[59],
            "deterministic {deterministic}"
        );
        sim.pause_time();
        let time = sim.time();
        let resumer = thread::spawn(move || {
            snare::real(|| thread::sleep(Duration::from_millis(150)));
            time.resume();
        });
        let woke = sim.run(|| {
            thread::sleep(MS);
            ns()
        });
        resumer.join().unwrap();
        assert_eq!(
            woke,
            landing::past(at + 1_000_000),
            "deterministic {deterministic}"
        );
    }
}

/// A condition-variable waiter woken by one notify per event loops exactly once per event: no
/// spurious returns from time skips, other threads' timers or other waits.
#[test]
fn a_condvar_waiter_wakes_once_per_event() {
    const EVENTS: u64 = 40;
    for (name, sim) in sims() {
        let returns = sim().run(|| {
            let state = Arc::new((Mutex::new(0u64), Condvar::new()));
            let returns = Arc::new(AtomicU64::new(0));
            let noise: Vec<_> = (1..=6u32)
                .map(|k| {
                    thread::spawn(move || {
                        for _ in 0..30 {
                            thread::sleep(Duration::from_micros(700) * k);
                        }
                    })
                })
                .collect();
            let waiter = {
                let state = state.clone();
                let returns = returns.clone();
                thread::spawn(move || {
                    let mut seen = 0;
                    let mut count = state.0.lock().unwrap();
                    while seen < EVENTS {
                        count = state.1.wait(count).unwrap();
                        returns.fetch_add(1, Ordering::SeqCst);
                        seen = *count;
                    }
                })
            };
            for _ in 0..EVENTS {
                thread::sleep(MS);
                *state.0.lock().unwrap() += 1;
                state.1.notify_one();
            }
            waiter.join().unwrap();
            for t in noise {
                t.join().unwrap();
            }
            returns.load(Ordering::SeqCst)
        });
        assert_eq!(returns, EVENTS, "{name}");
    }
}

/// `sched::park` returns `Unparked` exactly once per unpark when each unpark follows the last park.
#[test]
fn a_parked_thread_wakes_once_per_unpark() {
    const EVENTS: usize = 40;
    for (name, sim) in sims() {
        let returns = sim().run(|| {
            let (tx, rx) = mpsc::channel();
            let returns = Arc::new(AtomicUsize::new(0));
            let parked = {
                let returns = returns.clone();
                thread::spawn(move || {
                    tx.send(sched::current_unparker()).unwrap();
                    let mut unparked = 0;
                    while unparked < EVENTS {
                        returns.fetch_add(1, Ordering::SeqCst);
                        if sched::park(None) == sched::ParkResult::Unparked {
                            unparked += 1;
                        }
                    }
                })
            };
            let unparker = rx.recv().unwrap();
            for _ in 0..EVENTS {
                thread::sleep(MS);
                unparker.unpark();
            }
            parked.join().unwrap();
            returns.load(Ordering::SeqCst)
        });
        assert_eq!(returns, EVENTS, "{name}");
    }
}

/// Counts its polls of a sleep future.
struct Counted {
    sleep: Pin<Box<sched::Sleep>>,
    polls: Arc<AtomicUsize>,
}

impl Future for Counted {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        self.sleep.as_mut().poll(cx)
    }
}

/// A sleep future among fifty threads sleeping to other instants is polled exactly twice: once to
/// register, once when its own deadline comes.
#[test]
fn a_sleep_future_is_polled_once_more_only_at_its_own_deadline() {
    for (name, sim) in sims() {
        let (polls, at) = sim().run(|| {
            let others: Vec<_> = (1..=50u32)
                .map(|k| thread::spawn(move || thread::sleep(Duration::from_micros(97) * k)))
                .collect();
            let polls = Arc::new(AtomicUsize::new(0));
            let deadline = Instant::now() + Duration::from_micros(2_501);
            sched::block_on(Counted {
                sleep: Box::pin(sched::sleep_until(deadline)),
                polls: polls.clone(),
            });
            let at = ns();
            for t in others {
                t.join().unwrap();
            }
            (polls.load(Ordering::SeqCst), at)
        });
        assert_eq!((polls, at), (2, landing::past(2_501_000)), "{name}");
    }
}

/// Fifty empty executive timestamps over twenty blocked condition-variable waiters: no waiter
/// returns from its wait, and the quiescence epoch does not move.
fn empty_timestamps(name: &str, sim: Sim) {
    let returns = Arc::new(AtomicU64::new(0));
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let (epochs, during, now, waits) = thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                let waiters: Vec<_> = (0..20)
                    .map(|_| {
                        let release = release.clone();
                        let returns = returns.clone();
                        thread::spawn(move || {
                            let mut open = release.0.lock().unwrap();
                            while !*open {
                                open = release.1.wait(open).unwrap();
                                returns.fetch_add(1, Ordering::SeqCst);
                            }
                        })
                    })
                    .collect();
                for w in waiters {
                    w.join().unwrap();
                }
            })
        });
        let start = real_now();
        let before = loop {
            let q = exec.quiescence();
            if q.quiescent && q.blocked == 21 {
                break q;
            }
            if snare::real(|| start.elapsed()) > Duration::from_secs(20) {
                break q;
            }
            snare::real(|| thread::sleep(Duration::from_micros(200)));
        };
        let initial_waits = exec.participants();
        let fired: Vec<u32> = (1..=50u32)
            .map(|i| {
                exec.enter_timestamp(MS * i);
                exec.leave_timestamp(MS * i)
            })
            .collect();
        snare::real(|| thread::sleep(20 * MS));
        let after = exec.quiescence();
        let final_waits = exec.participants();
        let during = (returns.load(Ordering::SeqCst), fired);
        let now = exec.now();
        *release.0.lock().unwrap() = true;
        release.1.notify_all();
        run.join().unwrap();
        ((before, after), during, now, (initial_waits, final_waits))
    });
    let (before, after) = epochs;
    assert!(
        before.quiescent && before.blocked == 21,
        "{name}: {before:?}"
    );
    assert_eq!(during, (0, vec![0; 50]), "{name}: no waiter returned");
    assert_eq!(now, 50 * MS, "{name}");
    assert_eq!(after.epoch, before.epoch, "{name}: {waits:?}");
    assert_eq!(
        returns.load(Ordering::SeqCst),
        20,
        "{name}: one return each"
    );
}

#[test]
fn empty_timestamps_wake_no_one() {
    empty_timestamps("discrete", Sim::new());
}

#[test]
fn empty_timestamps_wake_no_one_under_deterministic() {
    empty_timestamps(
        "deterministic",
        Sim::builder().deterministic().seed(11).build(),
    );
}
