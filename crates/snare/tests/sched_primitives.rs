//! The cooperative primitives of `snare::sched` — park, block_on, Sleep, WakerSet — inside a sim,
//! where they run on its clock and its schedule, and off one, on real time.

use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use snare::Sim;
use snare::sched::{self, Executive, ExecutiveConfig, ParkResult, Quiescence, WakerSet};

const MS: Duration = Duration::from_millis(1);

fn real_now() -> Instant {
    snare::real(Instant::now)
}

fn real_since(start: Instant) -> Duration {
    snare::real(|| start.elapsed())
}

fn real_sleep(d: Duration) {
    snare::real(|| thread::sleep(d));
}

fn settle(exec: &Executive) -> Quiescence {
    let start = real_now();
    loop {
        let q = exec.quiescence();
        if q.quiescent && q.blocked > 0 {
            return q;
        }
        assert!(
            real_since(start) < Duration::from_secs(20),
            "the sim never went quiescent: {q:?}"
        );
        real_sleep(Duration::from_micros(200));
    }
}

fn settle_at(exec: &Executive, next: Duration) {
    while settle(exec).next_deadline != Some(next) {
        real_sleep(Duration::from_micros(200));
    }
}

fn settle_in(exec: &Executive, wait: &str) {
    loop {
        settle(exec);
        if exec.participants().iter().any(|p| p.wait == Some(wait)) {
            return;
        }
        real_sleep(Duration::from_micros(200));
    }
}

/// Asserts the calling thread's clock reads `deadline`, or the nanosecond past it a time skip
/// lands on, give or take how coarsely the platform's `Instant` rounds.
fn assert_at(deadline: Instant) {
    let now = Instant::now();
    assert!(now >= deadline, "woke {:?} early", deadline - now);
    assert!(
        now - deadline < Duration::from_micros(1),
        "woke {:?} late",
        now - deadline
    );
}

fn park_checks(slack: Duration) {
    let start = Instant::now();
    assert_eq!(sched::park(Some(start + 5 * MS)), ParkResult::TimedOut);
    let waited = start.elapsed();
    assert!(
        (5 * MS..5 * MS + slack).contains(&waited),
        "parked {waited:?}"
    );

    sched::current_unparker().unpark();
    let before = Instant::now();
    assert_eq!(
        sched::park(Some(before + Duration::from_secs(1))),
        ParkResult::Unparked
    );
    assert!(
        before.elapsed() < slack,
        "an early unpark is consumed at once"
    );
    assert_eq!(
        sched::park(Some(Instant::now() + MS)),
        ParkResult::TimedOut,
        "and only once"
    );

    let unparker = sched::current_unparker();
    let start = Instant::now();
    let peer = thread::spawn(move || {
        thread::sleep(2 * MS);
        unparker.unpark();
    });
    assert_eq!(sched::park(None), ParkResult::Unparked);
    assert!(start.elapsed() >= 2 * MS);
    peer.join().unwrap();
}

#[test]
fn park_times_out_on_virtual_time_and_consumes_early_unparks() {
    let real = real_now();
    Sim::new().run(|| {
        park_checks(MS);
        let start = Instant::now();
        assert_eq!(
            sched::park(Some(start + Duration::from_secs(3600))),
            ParkResult::TimedOut
        );
        assert_at(start + Duration::from_secs(3600));
    });
    assert!(
        real_since(real) < Duration::from_secs(10),
        "an hour of virtual time passes at once"
    );
    park_checks(Duration::from_secs(2));
}

/// Pending until the calling thread's clock reaches its deadline, without ever arranging a wake:
/// only the poll after the deadline sees it.
struct Until {
    deadline: Instant,
    polls: Arc<AtomicUsize>,
}

impl Future for Until {
    type Output = Instant;

    fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Instant> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        let now = Instant::now();
        if now >= self.deadline {
            Poll::Ready(now)
        } else {
            Poll::Pending
        }
    }
}

#[test]
fn block_on_timeout_expires_at_the_virtual_deadline_and_polls_once_more() {
    Sim::new().run(|| {
        let polls = Arc::new(AtomicUsize::new(0));
        let start = Instant::now();
        let deadline = start + 10 * MS;
        let at = sched::block_on_timeout(
            Until {
                deadline,
                polls: polls.clone(),
            },
            10 * MS,
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            2,
            "one poll, then one after the deadline"
        );
        assert_at(at.expect("ready at the deadline"));
        assert_at(deadline);

        let polls = Arc::new(AtomicUsize::new(0));
        let start = Instant::now();
        let never = Until {
            deadline: start + Duration::from_secs(1),
            polls: polls.clone(),
        };
        assert_eq!(sched::block_on_timeout(never, 4 * MS), None);
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_at(start + 4 * MS);

        let start = Instant::now();
        let ready = sched::block_on_timeout(async { 7 }, Duration::MAX);
        assert_eq!(
            ready,
            Some(7),
            "a timeout past the end of the clock is no deadline"
        );
        assert_eq!(Instant::now(), start);
        assert_eq!(sched::block_on(async { 8 }), 8);
    });
}

#[test]
fn a_runnable_participant_keeps_a_pending_sleep_timer_still() {
    Sim::new().run(|| {
        let start = Instant::now();
        let mut sleep = pin!(sched::sleep_until(start + MS));
        let mut context = Context::from_waker(Waker::noop());
        assert!(sleep.as_mut().poll(&mut context).is_pending());
        assert!(!snare_interpose::time_skip());
        assert_eq!(Instant::now(), start);
    });
}

#[test]
fn a_sleep_future_completes_at_exactly_its_instant() {
    Sim::new().run(|| {
        let start = Instant::now();
        let deadline = start + 7 * MS;
        let mut sleep = pin!(sched::sleep_until(deadline));
        assert!(!sleep.is_elapsed());
        sched::block_on(sleep.as_mut());
        assert!(sleep.is_elapsed());
        assert_at(deadline);

        let base = Instant::now();
        let woke: Vec<_> = [3, 1, 2]
            .map(|k| {
                thread::spawn(move || {
                    let deadline = base + k * MS;
                    sched::block_on(sched::sleep_until(deadline));
                    assert_at(deadline);
                    Instant::now() - base
                })
            })
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        for (k, at) in [3, 1, 2].into_iter().zip(woke) {
            assert!(
                at >= k * MS && at < k * MS + Duration::from_micros(1),
                "{k}: {at:?}"
            );
        }

        let past = Instant::now();
        sched::block_on(sched::sleep_until(past - MS));
        assert_eq!(
            Instant::now(),
            past,
            "a deadline already passed takes no time"
        );
    });
}

#[test]
fn a_sleep_future_completes_at_exactly_its_instant_under_an_executive_jump() {
    let sim = Sim::new();
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                let start = Instant::now();
                sched::block_on(sched::sleep_until(start + 7 * MS));
                (start.elapsed(), sched::now())
            })
        });
        settle_at(&exec, 7 * MS);
        loop {
            settle(&exec);
            if let Ok(fired) = exec.jump_to(Duration::from_secs(1)) {
                assert_eq!(fired, 1);
                break;
            }
        }
        assert_eq!(exec.now(), 7 * MS);
        let (elapsed, now) = run.join().unwrap();
        assert_eq!(now, 7 * MS);
        assert!(elapsed >= 7 * MS && elapsed < 7 * MS + Duration::from_micros(1));
    });
}

fn deterministic_sleeps(seed: u64) -> Vec<(usize, Duration)> {
    let sim = Sim::builder().deterministic().seed(seed).build();
    sim.run(|| {
        let order = Arc::new(Mutex::new(Vec::new()));
        let base = Instant::now();
        let workers: Vec<_> = (0..4)
            .map(|i| {
                let order = order.clone();
                thread::spawn(move || {
                    for round in 0..3u32 {
                        let deadline = base + MS * (round * 4 + 4 - i as u32);
                        sched::block_on(sched::sleep_until(deadline));
                        assert_at(deadline);
                        order.lock().unwrap().push((i, Instant::now() - base));
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        Arc::try_unwrap(order).unwrap().into_inner().unwrap()
    })
}

#[test]
fn a_sleep_future_completes_at_exactly_its_instant_under_deterministic() {
    for seed in 0..4 {
        let first = deterministic_sleeps(seed);
        assert_eq!(first.len(), 12);
        let mut sorted = first.clone();
        sorted.sort_by_key(|&(_, at)| at);
        assert_eq!(first, sorted, "each sleep wakes in deadline order");
        for &(i, at) in &first {
            let ms = at.as_millis() as u32;
            assert_eq!((ms - 1) % 4, (3 - i) as u32, "worker {i} woke at {at:?}");
        }
        assert_eq!(deterministic_sleeps(seed), first, "seed {seed} replays");
    }
}

#[test]
fn dropped_sleeps_leave_no_timer_entries() {
    let sim = Sim::new();
    let exec = sim.executive(ExecutiveConfig::default()).unwrap();
    sim.run(|| {
        let polled = |waker: &Waker| {
            let mut sleep = Box::pin(sched::sleep_until(Instant::now() + Duration::from_secs(1)));
            assert!(
                sleep
                    .as_mut()
                    .poll(&mut Context::from_waker(waker))
                    .is_pending()
            );
            sleep
        };
        let mut sleep = polled(Waker::noop());
        assert_eq!(exec.timers(8).len(), 1);
        let other = sched::current_unparker().waker();
        assert!(
            sleep
                .as_mut()
                .poll(&mut Context::from_waker(&other))
                .is_pending()
        );
        assert_eq!(exec.timers(8).len(), 1, "a new waker replaces the old one");
        drop(sleep);
        assert!(exec.timers(8).is_empty());

        let sleeps: Vec<_> = (0..3).map(|_| polled(Waker::noop())).collect();
        assert_eq!(exec.timers(8).len(), 3);
        drop(sleeps);
        assert!(exec.timers(8).is_empty());

        thread::spawn(move || {
            sched::mark_background("sampler");
            drop(polled(Waker::noop()));
        })
        .join()
        .unwrap();
        assert!(exec.timers(8).is_empty(), "a background thread's too");
    });
    drop(exec);
}

#[test]
fn dropping_a_fired_sleep_allows_the_next_sleep_to_finish() {
    let sim = Sim::new();
    sim.run(|| {
        let mut sleep = Box::pin(sched::sleep_until(Instant::now() + MS));
        assert!(
            sleep
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        sim.advance_time(MS);
        drop(sleep);
        let deadline = Instant::now() + MS;
        sched::block_on(sched::sleep_until(deadline));
        assert_at(deadline);
    });
}

fn waker_set_checks() {
    let set = Arc::new(WakerSet::new());
    let open = Arc::new(AtomicBool::new(false));
    let waiting = Arc::new(AtomicUsize::new(0));
    let waiters: Vec<_> = (0..3)
        .map(|_| {
            let (set, open, waiting) = (set.clone(), open.clone(), waiting.clone());
            thread::spawn(move || {
                let mut counted = false;
                sched::block_on(poll_fn(|cx| {
                    set.register(cx.waker());
                    set.register(cx.waker());
                    if !counted {
                        counted = true;
                        waiting.fetch_add(1, Ordering::SeqCst);
                    }
                    if open.load(Ordering::SeqCst) {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                }));
            })
        })
        .collect();
    while waiting.load(Ordering::SeqCst) < 3 {
        thread::sleep(MS);
    }
    open.store(true, Ordering::SeqCst);
    set.wake_all();
    for waiter in waiters {
        waiter.join().unwrap();
    }
}

#[test]
fn a_waker_set_wakes_every_waiter() {
    Sim::new().run(waker_set_checks);
    Sim::builder().deterministic().build().run(waker_set_checks);
    waker_set_checks();
}

#[test]
fn is_driven_and_is_participant_follow_class_and_clock() {
    assert!(!sched::is_driven());
    assert!(!sched::is_participant());
    Sim::new().run(|| {
        assert!(sched::is_driven());
        assert!(sched::is_participant());
        thread::spawn(|| {
            sched::mark_background("sampler");
            assert!(!sched::is_driven());
            assert!(!sched::is_participant());
        })
        .join()
        .unwrap();
        thread::spawn(|| {
            sched::mark_driver_thread();
            assert!(!sched::is_driven());
        })
        .join()
        .unwrap();
    });
    let sim = Sim::new();
    sim.pause_time();
    sim.run(|| assert!(sched::is_driven(), "a paused clock is still virtual"));
    Sim::builder()
        .time_rate(2.0)
        .build()
        .run(|| assert!(sched::is_driven()));
    Sim::builder().wall_clock().build().run(|| {
        assert!(sched::is_participant());
        assert!(!sched::is_driven());
    });
}

#[test]
fn park_wake_is_gated_during_a_timestamp() {
    let t = 7 * MS;
    Sim::new().run(|| {
        let exec = sched::attach(ExecutiveConfig::default()).unwrap();
        sched::mark_driver_thread();
        let done = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let parker = {
            let done = done.clone();
            thread::spawn(move || {
                tx.send(sched::current_unparker()).unwrap();
                let result = sched::park(None);
                done.store(true, Ordering::SeqCst);
                (result, sched::now())
            })
        };
        let unparker = rx.recv().unwrap();
        settle_in(&exec, "park");
        exec.enter_timestamp(t);
        unparker.unpark();
        real_sleep(50 * MS);
        assert!(
            !done.load(Ordering::SeqCst),
            "the parked thread waits for the timestamp to end"
        );
        assert_eq!(exec.leave_timestamp(t), 0);
        assert_eq!(parker.join().unwrap(), (ParkResult::Unparked, t));
    });
}

#[test]
fn a_sleep_future_completes_on_real_and_scaled_time() {
    let start = Instant::now();
    sched::block_on(sched::sleep_until(start + 20 * MS));
    assert!(start.elapsed() >= 20 * MS);
    let sleep = sched::sleep_until(Instant::now() + Duration::from_secs(3600));
    assert_eq!(
        sched::block_on_timeout(sleep, MS),
        None,
        "a dropped real-time sleep"
    );

    let real = real_now();
    Sim::builder().time_rate(100.0).build().run(|| {
        let start = Instant::now();
        sched::block_on(sched::sleep_until(start + Duration::from_secs(1)));
        assert!(start.elapsed() >= Duration::from_secs(1));
    });
    let took = real_since(real);
    assert!(
        (9 * MS..Duration::from_secs(5)).contains(&took),
        "a second at rate 100 takes about 10 ms: {took:?}"
    );
}

struct ChannelWaker(Mutex<mpsc::Sender<()>>);

impl std::task::Wake for ChannelWaker {
    fn wake(self: Arc<Self>) {
        let _ = self.0.lock().unwrap().send(());
    }
}

struct CondvarWaker(Mutex<bool>, std::sync::Condvar);

impl std::task::Wake for CondvarWaker {
    fn wake(self: Arc<Self>) {
        *self.0.lock().unwrap() = true;
        self.1.notify_all();
    }
}

/// Polls a sleep the way a hand-rolled executor does: with its own waker, blocking in a channel
/// receive between polls.
fn sleep_on_a_channel_waker() {
    let (tx, rx) = mpsc::channel();
    let waker = Waker::from(Arc::new(ChannelWaker(Mutex::new(tx))));
    let mut cx = Context::from_waker(&waker);
    let deadline = Instant::now() + 5 * MS;
    let mut sleep = pin!(sched::sleep_until(deadline));
    while sleep.as_mut().poll(&mut cx).is_pending() {
        rx.recv().unwrap();
    }
    assert_at(deadline);
}

fn sleep_on_a_condvar_waker() {
    let woken = Arc::new(CondvarWaker(Mutex::new(false), std::sync::Condvar::new()));
    let waker = Waker::from(woken.clone());
    let mut cx = Context::from_waker(&waker);
    let deadline = Instant::now() + 5 * MS;
    let mut sleep = pin!(sched::sleep_until(deadline));
    while sleep.as_mut().poll(&mut cx).is_pending() {
        let mut flag = woken.0.lock().unwrap();
        while !*flag {
            flag = woken.1.wait(flag).unwrap();
        }
        *flag = false;
    }
    assert_at(deadline);
}

fn twice(run: fn()) {
    let peer = thread::spawn(run);
    run();
    peer.join().unwrap();
}

#[test]
fn a_sleep_polled_with_any_waker_completes_at_its_instant() {
    for run in [sleep_on_a_channel_waker, sleep_on_a_condvar_waker] {
        Sim::new().run(run);
        Sim::new().run(|| twice(run));
    }
}

#[test]
fn a_sleep_polled_with_any_waker_completes_at_its_instant_under_deterministic() {
    for run in [sleep_on_a_channel_waker, sleep_on_a_condvar_waker] {
        Sim::builder().deterministic().build().run(run);
        Sim::builder().deterministic().build().run(|| twice(run));
    }
}

/// A waker that blocks until released, as the code under test's waker may on a lock of its own.
struct BlockedWaker {
    blocking: AtomicBool,
    release: AtomicBool,
    woken: Mutex<mpsc::Sender<()>>,
}

impl std::task::Wake for BlockedWaker {
    fn wake(self: Arc<Self>) {
        self.blocking.store(true, Ordering::SeqCst);
        while !self.release.load(Ordering::SeqCst) {
            real_sleep(Duration::from_micros(200));
        }
        let _ = self.woken.lock().unwrap().send(());
    }
}

/// Each sim's clock runs its wakers on a thread of its own: a waker of one sim blocked on a lock
/// whose holder waits for another sim to move on must not hold up the wakers of that other sim's
/// time skip.
#[test]
fn a_waker_blocked_in_one_sim_does_not_hold_up_another_sims_time_skips() {
    let (tx, rx) = mpsc::channel();
    let blocked = Arc::new(BlockedWaker {
        blocking: AtomicBool::new(false),
        release: AtomicBool::new(false),
        woken: Mutex::new(tx),
    });
    let other = {
        let blocked = blocked.clone();
        thread::spawn(move || {
            Sim::new().run(|| {
                let waker = Waker::from(blocked);
                let mut cx = Context::from_waker(&waker);
                let mut sleep = pin!(sched::sleep_until(Instant::now() + MS));
                while sleep.as_mut().poll(&mut cx).is_pending() {
                    rx.recv().unwrap();
                }
            });
        })
    };
    while !blocked.blocking.load(Ordering::SeqCst) {
        real_sleep(Duration::from_micros(200));
    }

    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        for deterministic in [false, true] {
            for run in [sleep_on_a_channel_waker, sleep_on_a_condvar_waker] {
                let builder = Sim::builder();
                let sim = if deterministic {
                    builder.deterministic().build()
                } else {
                    builder.build()
                };
                sim.run(run);
            }
        }
        done_tx.send(()).unwrap();
    });
    let done = done_rx.recv_timeout(Duration::from_secs(20));
    blocked.release.store(true, Ordering::SeqCst);
    other.join().unwrap();
    assert!(
        done.is_ok(),
        "a sim's time skip waited on a waker of another sim that was blocked"
    );
}

#[test]
fn a_background_sleep_completes_while_the_participant_joins_it() {
    let sims = [Sim::new(), Sim::builder().deterministic().build()];
    for sim in sims {
        sim.run(|| {
            let background = thread::spawn(|| {
                sched::mark_background("sampler");
                let deadline = Instant::now() + 3 * MS;
                sched::block_on(sched::sleep_until(deadline));
                let (tx, rx) = mpsc::channel();
                let waker = Waker::from(Arc::new(ChannelWaker(Mutex::new(tx))));
                let mut cx = Context::from_waker(&waker);
                let deadline = deadline + 3 * MS;
                let mut sleep = pin!(sched::sleep_until(deadline));
                while sleep.as_mut().poll(&mut cx).is_pending() {
                    rx.recv().unwrap();
                }
                Instant::now() >= deadline
            });
            assert!(background.join().unwrap());
        });
    }
}

#[test]
fn sleeps_and_is_driven_on_an_as_fast_as_possible_clock() {
    let check = || {
        assert!(sched::is_participant());
        assert!(!sched::is_driven());
        let start = Instant::now();
        sched::block_on(sched::sleep_until(start + Duration::from_secs(5)));
        assert!(start.elapsed() >= Duration::from_secs(5));
    };
    #[cfg(target_os = "linux")]
    Sim::builder()
        .host(snare::HostProfile::new().build())
        .wall_clock()
        .build()
        .run(check);
    #[cfg(windows)]
    Sim::builder().wall_clock().build().run(check);
    #[cfg(not(any(target_os = "linux", windows)))]
    let _ = check;
}

struct LockingWaker {
    lock: Arc<Mutex<()>>,
    release: mpsc::Sender<()>,
    parked: Waker,
}

impl std::task::Wake for LockingWaker {
    fn wake(self: Arc<Self>) {
        self.release.send(()).unwrap();
        let _held = self.lock.lock().unwrap();
        self.parked.wake_by_ref();
    }
}

#[test]
fn a_clock_waker_can_wait_for_a_thread_that_bumps_readiness() {
    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        Sim::new().run(|| {
            let lock = Arc::new(Mutex::new(()));
            let (release_tx, release_rx) = mpsc::channel();
            let (held_tx, held_rx) = mpsc::channel();
            let holder = {
                let lock = lock.clone();
                thread::spawn(move || {
                    sched::mark_background("lock holder");
                    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                    let held = lock.lock().unwrap();
                    held_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    drop(socket);
                    drop(held);
                })
            };
            held_rx.recv().unwrap();
            let waker = Waker::from(Arc::new(LockingWaker {
                lock,
                release: release_tx,
                parked: sched::current_unparker().waker(),
            }));
            let mut cx = Context::from_waker(&waker);
            let mut sleep = pin!(sched::sleep_until(Instant::now() + MS));
            while sleep.as_mut().poll(&mut cx).is_pending() {
                sched::park(None);
            }
            holder.join().unwrap();
        });
        done_tx.send(()).unwrap();
    });
    assert!(done_rx.recv_timeout(Duration::from_secs(20)).is_ok());
}

struct CancelSleepOnDrop {
    sleep: Mutex<Option<sched::Sleep>>,
    cancelled: mpsc::Sender<()>,
}

#[allow(clippy::manual_noop_waker)]
impl std::task::Wake for CancelSleepOnDrop {
    fn wake(self: Arc<Self>) {}
}

impl Drop for CancelSleepOnDrop {
    fn drop(&mut self) {
        self.sleep.get_mut().unwrap().take();
        self.cancelled.send(()).unwrap();
    }
}

#[test]
fn dropping_a_timer_waker_can_cancel_another_timer() {
    let (cancelled_tx, cancelled_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        Sim::new().run(|| {
            let deadline = Instant::now() + Duration::from_secs(60);
            let mut inner = sched::sleep_until(deadline);
            let mut cx = Context::from_waker(Waker::noop());
            assert!(std::pin::Pin::new(&mut inner).poll(&mut cx).is_pending());
            let waker = Waker::from(Arc::new(CancelSleepOnDrop {
                sleep: Mutex::new(Some(inner)),
                cancelled: cancelled_tx,
            }));
            let mut outer = sched::sleep_until(deadline);
            let mut cx = Context::from_waker(&waker);
            assert!(std::pin::Pin::new(&mut outer).poll(&mut cx).is_pending());
            drop(waker);
            drop(outer);
        });
    });
    assert!(cancelled_rx.recv_timeout(Duration::from_secs(20)).is_ok());
    worker.join().unwrap();
}

#[test]
fn dropping_a_fired_sleep_outside_its_sim_releases_later_timers() {
    let (sleep_tx, sleep_rx) = mpsc::channel();
    let (first_tx, first_rx) = mpsc::channel();
    let (second_tx, second_rx) = mpsc::channel();
    let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let participant_gate = gate.clone();
    let worker = thread::spawn(move || {
        Sim::new().run(|| {
            let start = Instant::now();
            let first_waker = Waker::from(Arc::new(ChannelWaker(Mutex::new(first_tx))));
            let second_waker = Waker::from(Arc::new(ChannelWaker(Mutex::new(second_tx))));
            let mut first = sched::sleep_until(start + MS);
            let mut second = sched::sleep_until(start + 2 * MS);
            assert!(
                std::pin::Pin::new(&mut first)
                    .poll(&mut Context::from_waker(&first_waker))
                    .is_pending()
            );
            assert!(
                std::pin::Pin::new(&mut second)
                    .poll(&mut Context::from_waker(&second_waker))
                    .is_pending()
            );
            sleep_tx.send(first).unwrap();
            let mut open = participant_gate.0.lock().unwrap();
            while !*open {
                open = participant_gate.1.wait(open).unwrap();
            }
            drop(second);
        });
    });
    let first = sleep_rx.recv_timeout(Duration::from_secs(20)).unwrap();
    first_rx.recv_timeout(Duration::from_secs(20)).unwrap();
    drop(first);
    let fired = second_rx.recv_timeout(Duration::from_secs(2));
    *gate.0.lock().unwrap() = true;
    gate.1.notify_one();
    worker.join().unwrap();
    assert!(
        fired.is_ok(),
        "later timer stayed blocked after cancellation"
    );
}
