//! Behaviour pins for the discrete virtual clock, ahead of performance work on it: the exact
//! nanosecond every sleep, timed wait and time skip lands on, asserted with `==`.
//!
//! The rules pinned: a time skip lands just past the earliest pending deadline (1 ns, or on Windows
//! the next `QueryPerformanceCounter` tick), so a wait for `d` from `t` wakes at `past(t + d)`; every wait whose deadline the landing reached wakes there with
//! it (adjacent deadlines coalesce, they are not visited one by one); a zero wait moves nothing;
//! a satisfied or dropped timed wait leaves no timer behind for a later skip to visit; deadlines
//! at the far end of the clock saturate instead of wrapping. Each holds on the plain discrete
//! clock and under `deterministic()`, where it also replays exactly. Readings come from
//! `snare::sched::now()`, which reads sim time without ticking and is not itself a hooked call.

use std::future::Future;
use std::net::UdpSocket;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use snare::sched;
use snare::{Sim, SimBuilder};

#[path = "support/landing.rs"]
mod landing;

use landing::{past, steps, wakes};

const MS: Duration = Duration::from_millis(1);
const US: Duration = Duration::from_micros(1);
const SLEEP_NS: u64 = if cfg!(windows) { 100 } else { 1 };

/// Sim time in nanoseconds, read without ticking the clock.
fn ns() -> u64 {
    sched::now().as_nanos() as u64
}

/// A sim builder, with its name for messages.
type NamedBuilder = (&'static str, fn() -> SimBuilder);

fn builders() -> [NamedBuilder; 2] {
    [
        ("discrete", || Sim::builder().fixed_epoch()),
        ("deterministic", || Sim::builder().deterministic().seed(7)),
    ]
}

/// Runs `scenario` on the plain discrete clock and under `deterministic()` (twice, which must
/// replay), and checks every run against `expected`.
fn pin<T: PartialEq + std::fmt::Debug + Clone>(expected: T, scenario: impl Fn() -> T + Sync) {
    pin_each(expected.clone(), expected, scenario);
}

/// [`pin`], where the plain discrete clock and the deterministic schedule differ on purpose or by
/// current design.
fn pin_each<T: PartialEq + std::fmt::Debug>(
    discrete: T,
    deterministic: T,
    scenario: impl Fn() -> T + Sync,
) {
    assert_eq!(
        Sim::builder().fixed_epoch().build().run(&scenario),
        discrete,
        "discrete"
    );
    let det = || {
        Sim::builder()
            .deterministic()
            .seed(7)
            .build()
            .run(&scenario)
    };
    assert_eq!(det(), deterministic, "deterministic");
    assert_eq!(det(), deterministic, "deterministic replay");
}

#[test]
fn chained_sleeps_land_just_past_each_deadline() {
    let second = past(past(10_000_000) + 10_000_000);
    let third = past(second + SLEEP_NS);
    let fifth = past(third + 1_000_000_000);
    pin(
        vec![
            past(10_000_000),
            second,
            third,
            third,
            fifth,
            past(fifth + 1_000),
        ],
        || {
            let mut seen = Vec::new();
            for d in [
                10 * MS,
                10 * MS,
                Duration::from_nanos(SLEEP_NS),
                Duration::ZERO,
                Duration::from_secs(1),
                US,
            ] {
                thread::sleep(d);
                seen.push(ns());
            }
            seen
        },
    );
}

#[test]
fn timed_waits_that_expire_land_just_past_their_deadline() {
    pin(steps(0, 5_000_000, 4), || {
        let mut seen = Vec::new();

        let pair = (Mutex::new(()), Condvar::new());
        let guard = pair.0.lock().unwrap();
        let (_guard, timeout) = pair.1.wait_timeout(guard, 5 * MS).unwrap();
        assert!(timeout.timed_out());
        seen.push(ns());

        let (_tx, rx) = mpsc::channel::<()>();
        assert!(rx.recv_timeout(5 * MS).is_err());
        seen.push(ns());

        thread::park_timeout(5 * MS);
        seen.push(ns());

        let start = Instant::now();
        assert_eq!(
            sched::park(Some(start + 5 * MS)),
            sched::ParkResult::TimedOut
        );
        seen.push(ns());
        seen
    });
}

#[test]
fn socket_read_timeouts_expire_on_the_virtual_clock() {
    let first = past(7_000_000);
    pin(vec![first, first, past(first + 7_000_000)], || {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(7 * MS)).unwrap();
        let mut buf = [0u8; 8];
        let err = sock.recv_from(&mut buf).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "{err:?}"
        );
        let first = ns();
        let after_err = ns();
        let _ = sock.recv_from(&mut buf).unwrap_err();
        vec![first, after_err, ns()]
    });
}

/// A zero timeout never blocks and moves no time by a skip. On the plain discrete clock the waits
/// that still reach the OS (a condition variable's, a thread park's) return without blocking and
/// are charged the 1 µs call latency; the deterministic schedule, which emulates those waits,
/// charges nothing. The ones std answers itself (`sleep(0)`, `recv_timeout(0)`) and `sched::park`
/// with a passed deadline cost nothing either way.
#[test]
fn zero_timeouts_never_skip_and_charge_only_native_waits_on_the_plain_clock() {
    pin_each(vec![0, 0, 1_000, 1_000, 2_000], vec![0; 5], || {
        let mut seen = Vec::new();
        thread::sleep(Duration::ZERO);
        seen.push(ns());
        let (_tx, rx) = mpsc::channel::<()>();
        assert!(rx.recv_timeout(Duration::ZERO).is_err());
        seen.push(ns());
        let pair = (Mutex::new(()), Condvar::new());
        let guard = pair.0.lock().unwrap();
        let (_guard, timeout) = pair.1.wait_timeout(guard, Duration::ZERO).unwrap();
        assert!(timeout.timed_out());
        seen.push(ns());
        assert_eq!(
            sched::park(Some(Instant::now())),
            sched::ParkResult::TimedOut
        );
        seen.push(ns());
        thread::park_timeout(Duration::ZERO);
        seen.push(ns());
        seen
    });
}

#[test]
fn smallest_common_wait_quantum_lands_just_past_each_deadline() {
    let wait = if cfg!(windows) { 1_000_000 } else { 1 };
    pin(steps(0, wait, 3), || {
        let mut seen = Vec::new();
        thread::sleep(Duration::from_nanos(wait));
        seen.push(ns());
        let (_tx, rx) = mpsc::channel::<()>();
        assert!(rx.recv_timeout(Duration::from_nanos(wait)).is_err());
        seen.push(ns());
        let pair = (Mutex::new(()), Condvar::new());
        let guard = pair.0.lock().unwrap();
        let _ = pair
            .1
            .wait_timeout(guard, Duration::from_nanos(wait))
            .unwrap();
        seen.push(ns());
        seen
    });
}

/// A wait with no practical deadline (`Duration::MAX`) that something ends early returns when it
/// is ended, and the far-off deadline it registered never pulls the clock along afterwards.
#[test]
fn duration_max_waits_end_on_their_event_and_leave_no_far_timer() {
    let notified = past(5_000_000);
    let sent = past(notified + 5_000_000);
    pin(vec![notified, sent, sent], || {
        let mut seen = Vec::new();

        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let notifier = {
            let pair = pair.clone();
            thread::spawn(move || {
                thread::sleep(5 * MS);
                *pair.0.lock().unwrap() = true;
                pair.1.notify_one();
            })
        };
        let mut ready = pair.0.lock().unwrap();
        while !*ready {
            let (next, timeout) = pair.1.wait_timeout(ready, Duration::MAX).unwrap();
            assert!(!timeout.timed_out());
            ready = next;
        }
        drop(ready);
        notifier.join().unwrap();
        seen.push(ns());

        let (tx, rx) = mpsc::channel();
        let sender = thread::spawn(move || {
            thread::sleep(5 * MS);
            tx.send(1).unwrap();
        });
        assert_eq!(rx.recv_timeout(Duration::MAX), Ok(1));
        sender.join().unwrap();
        seen.push(ns());

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut buf = [0u8; 4];
        let err = sock.recv_from(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock, "{err:?}");
        seen.push(ns());
        seen
    });
}

/// Sleeps reaching close to the far end of the clock land exactly as anywhere else.
#[test]
fn sleeps_near_the_end_of_the_clock_land_exactly() {
    let far = if cfg!(windows) {
        u64::MAX / 100 * 100 - 1000
    } else {
        u64::MAX - 10
    };
    let final_wait = 5 * SLEEP_NS;
    pin(vec![past(far), past(past(far) + final_wait)], move || {
        let mut seen = Vec::new();
        thread::sleep(Duration::from_nanos(far));
        seen.push(ns());
        thread::sleep(Duration::from_nanos(final_wait));
        seen.push(ns());
        seen
    });
}

#[test]
fn a_sleep_past_the_end_of_the_clock_saturates() {
    let far = u64::MAX - 10;
    pin(u64::MAX, move || {
        thread::sleep(Duration::from_nanos(far));
        thread::sleep(Duration::from_secs(1));
        ns()
    });
}

#[test]
fn a_lone_duration_max_sleep_saturates_at_the_end_of_the_clock() {
    pin(u64::MAX, || {
        thread::sleep(Duration::MAX);
        ns()
    });
}

/// Every thread sleeping to the same instant wakes at the same landing just past it, however many
/// there are, and the threads with deadlines the landing reached wake there with them.
#[test]
fn tied_and_adjacent_deadlines_share_one_landing() {
    let deadlines: Vec<u64> = (0..8)
        .map(|_| 10_000_000)
        .chain([10_000_000 + SLEEP_NS, 10_000_000 + 2 * SLEEP_NS])
        .collect();
    let expected: Vec<(u64, u64)> = (0..).zip(wakes(&deadlines)).collect();
    pin(expected, move || {
        let deadlines = deadlines.clone();
        let sleepers: Vec<_> = deadlines
            .into_iter()
            .enumerate()
            .map(|(i, d)| {
                thread::spawn(move || {
                    thread::sleep(Duration::from_nanos(d));
                    (i as u64, ns())
                })
            })
            .collect();
        sleepers.into_iter().map(|h| h.join().unwrap()).collect()
    });
}

/// The exact landing of every sleeper among many with spread, tied and adjacent deadlines: each
/// wakes at the first landing at or past its deadline, and a landing is the earliest deadline
/// still ahead plus one.
#[test]
fn many_sleepers_wake_at_the_first_landing_past_their_deadline() {
    let deadlines: Vec<u64> = (0..120u64)
        .map(|i| {
            let deadline = 1_000 + (i * 7_919) % 50_000 + (i % 3);
            deadline / SLEEP_NS * SLEEP_NS
        })
        .collect();
    let expected = wakes(&deadlines);
    let given = deadlines.clone();
    pin(expected, move || {
        let sleepers: Vec<_> = given
            .iter()
            .map(|&d| {
                thread::spawn(move || {
                    thread::sleep(Duration::from_nanos(d));
                    ns()
                })
            })
            .collect();
        sleepers
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
}

/// A thread woken by a skip that at once registers a new wait one sleep quantum out, beside a
/// sleeper whose deadline was registered from the start at the same instant: both land together.
/// A Windows sleep falls on a 100 ns grid while a landing need not, so there the sleeper takes the
/// grid instant at or before the new wait's deadline, and the new wait lands with it only if that
/// landing reaches it.
#[test]
fn a_timer_registered_right_after_a_skip_coalesces_with_one_already_there() {
    let woke = past(10_000_000);
    let early = woke + SLEEP_NS;
    let late = early / SLEEP_NS * SLEEP_NS;
    let late_landing = past(late);
    let again = if late_landing >= early {
        late_landing
    } else {
        past(early)
    };
    pin((woke, again, late_landing), move || {
        let early = thread::spawn(|| {
            thread::sleep(10 * MS);
            let woke = ns();
            thread::sleep(Duration::from_nanos(SLEEP_NS));
            (woke, ns())
        });
        let late = thread::spawn(move || {
            thread::sleep(Duration::from_nanos(late));
            ns()
        });
        let (woke, again) = early.join().unwrap();
        (woke, again, late.join().unwrap())
    });
}

/// A timed wait that its event ends early takes its deadline with it: a deadlocked wait after it
/// gives up at once, with no skip to the abandoned deadline, and a later sleep is measured from
/// the early wake.
#[test]
fn a_timed_wait_ended_early_leaves_no_ghost_deadline() {
    let woke = past(3_000_000);
    pin((woke, woke, past(woke + 10_000_000)), || {
        let (tx, rx) = mpsc::channel();
        let sender = thread::spawn(move || {
            thread::sleep(3 * MS);
            tx.send(()).unwrap();
        });
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        sender.join().unwrap();
        let woke = ns();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(
            sock.recv_from(&mut buf).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let gave_up = ns();
        thread::sleep(10 * MS);
        (woke, gave_up, ns())
    });
}

/// Polls a set of sleep futures, noting the reading at which each completes, and counts its own
/// polls.
struct AllSleeps {
    sleeps: Vec<Option<Pin<Box<sched::Sleep>>>>,
    done: Vec<u64>,
    polls: Arc<AtomicUsize>,
}

impl Future for AllSleeps {
    type Output = Vec<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Vec<u64>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        let now = ns();
        let this = &mut *self;
        for (slot, done) in this.sleeps.iter_mut().zip(this.done.iter_mut()) {
            if let Some(sleep) = slot
                && sleep.as_mut().poll(cx).is_ready()
            {
                *done = now;
                *slot = None;
            }
        }
        if this.sleeps.iter().all(Option::is_none) {
            Poll::Ready(std::mem::take(&mut this.done))
        } else {
            Poll::Pending
        }
    }
}

/// Three thousand timers on one thread, many sharing an instant: each completes just past its
/// deadline, and the waiting thread is polled no more than once per distinct deadline plus the
/// first poll, however many timers share one. A socket call between the sleeps keeps their
/// clock reads from adding up to a clock spin (see `building_many_sleeps_in_a_row_moves_no_time`).
#[test]
fn thousands_of_timers_each_complete_just_past_their_deadline() {
    const N: u64 = 3_000;
    const DISTINCT: u64 = 1_500;
    let expected: Vec<u64> = (0..N).map(|i| past((i % DISTINCT + 1) * 1_000)).collect();
    for (name, builder) in builders() {
        let polls = Arc::new(AtomicUsize::new(0));
        let done = builder().build().run({
            let polls = polls.clone();
            move || {
                let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
                let origin = Instant::now();
                let sleeps = (0..N)
                    .map(|i| {
                        sock.local_addr().unwrap();
                        Some(Box::pin(sched::sleep_until(
                            origin + US * (i % DISTINCT + 1) as u32,
                        )))
                    })
                    .collect();
                sched::block_on(AllSleeps {
                    sleeps,
                    done: vec![0; N as usize],
                    polls,
                })
            }
        });
        assert_eq!(done, expected, "{name}");
        let polls = polls.load(Ordering::SeqCst);
        assert!(
            polls <= DISTINCT as usize + 1,
            "{name}: {polls} polls for {DISTINCT} deadlines"
        );
    }
}

/// Building sleep futures reads the clock, as `sched::sleep_until` must, but building them is not
/// waiting on time.
#[test]
fn building_many_sleeps_in_a_row_moves_no_time() {
    pin(0, || {
        let origin = Instant::now();
        let sleeps: Vec<_> = (1..=100u32)
            .map(|i| Box::pin(sched::sleep_until(origin + US * i)))
            .collect();
        let at = ns();
        drop(sleeps);
        at
    });
}

#[test]
fn charged_calls_release_a_native_wait_at_its_deadline() {
    charged_native_wait(false);
}

#[test]
fn charged_calls_release_a_native_wait_after_a_runnable_sibling_exits() {
    charged_native_wait(true);
}

fn charged_native_wait(with_sibling: bool) {
    let sim = Sim::builder().deterministic().build();
    sim.run(|| {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let completed = Arc::new(AtomicUsize::new(0));
        let worker = {
            let completed = completed.clone();
            thread::spawn(move || {
                let mutex = Mutex::new(());
                let condvar = Condvar::new();
                let (_guard, timeout) =
                    condvar.wait_timeout(mutex.lock().unwrap(), 3 * MS).unwrap();
                completed.store(1, Ordering::Release);
                timeout.timed_out()
            })
        };
        let sibling = with_sibling.then(|| {
            thread::spawn(|| {
                while snare::time().value() < 4 * MS {
                    thread::yield_now();
                }
            })
        });
        for _ in 0..5000 {
            if completed.load(Ordering::Acquire) != 0 {
                break;
            }
            assert_eq!(
                socket.recv(&mut [0]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
        let released = completed.load(Ordering::Acquire) != 0;
        thread::sleep(US);
        assert!(worker.join().unwrap());
        if let Some(sibling) = sibling {
            sibling.join().unwrap();
        }
        assert!(
            released,
            "the native timeout waited for the poller to block"
        );
    });
}
