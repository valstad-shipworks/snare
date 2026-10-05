//! Behaviour pins for timers at scale: exact deadlines, one polling-thread wake per instant,
//! and registration order for tied futures. Thread ordering under deterministic scheduling is
//! checked against a golden. Setup pauses the clock while installing future deadlines.

#![cfg(unix)]

#[path = "support/golden.rs"]
mod golden;

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Wake, Waker};
use std::time::{Duration, Instant};

use snare::Sim;
use snare::sched::{self, Unparker};

const NS: Duration = Duration::from_nanos(1);

/// Records its sleep's index when woken, then wakes the polling thread.
struct Slot {
    idx: usize,
    woken: Arc<Mutex<Vec<usize>>>,
    main: Unparker,
}

impl Wake for Slot {
    fn wake(self: Arc<Self>) {
        snare::real(|| self.woken.lock().unwrap().push(self.idx));
        self.main.unpark();
    }
}

/// When sleep `i` of a run spread over `spread` instants is due, from the run's start.
fn due(i: usize, spread: usize) -> Duration {
    Duration::from_millis(1 + ((i * 7919) % spread) as u64)
}

/// What a run of many sleeps saw: each completion as (sim time, index) in completion order, and
/// how often the polling thread parked.
struct TimerRun {
    done: Vec<(Duration, usize)>,
    parks: usize,
}

/// Registers `n` sleeps due over `spread` instants with the clock paused, then polls each as its
/// waker fires, until all are done.
fn many_sleeps(sim: &Sim, n: usize, spread: usize) -> TimerRun {
    sim.run(|| {
        let woken = Arc::new(Mutex::new(Vec::new()));
        let main = sched::current_unparker();
        let base = Instant::now();
        snare::time().pause();
        let mut sleeps: Vec<_> = (0..n)
            .map(|i| Some(Box::pin(sched::sleep_until(base + due(i, spread)))))
            .collect();
        let wakers: Vec<Waker> = (0..n)
            .map(|idx| {
                Waker::from(Arc::new(Slot {
                    idx,
                    woken: woken.clone(),
                    main: main.clone(),
                }))
            })
            .collect();
        let mut done = Vec::with_capacity(n);
        let mut parks = 0;
        let mut ready: Vec<usize> = (0..n).collect();
        let mut at = Duration::ZERO;
        let mut paused = true;
        while done.len() < n {
            for idx in std::mem::take(&mut ready) {
                let sleep = sleeps[idx].as_mut().unwrap();
                if sleep
                    .as_mut()
                    .poll(&mut Context::from_waker(&wakers[idx]))
                    .is_ready()
                {
                    done.push((at, idx));
                    sleeps[idx] = None;
                }
            }
            if done.len() == n {
                break;
            }
            if paused {
                paused = false;
                snare::time().resume();
            }
            loop {
                let batch: Vec<usize> = snare::real(|| std::mem::take(&mut *woken.lock().unwrap()));
                if !batch.is_empty() {
                    at = snare::time().value();
                    ready = batch;
                    break;
                }
                sched::park(None);
                parks += 1;
            }
        }
        TimerRun { done, parks }
    })
}

fn check_many_sleeps(sim: &Sim, n: usize, spread: usize) {
    let run = many_sleeps(sim, n, spread);
    assert_eq!(run.done.len(), n);
    assert!(
        run.done.iter().all(|&(at, i)| at == due(i, spread) + NS),
        "every sleep completes 1 ns past its deadline"
    );
    assert_eq!(run.parks, spread, "one wake of the poller per instant");
    for pair in run.done.windows(2) {
        let ((a, i), (b, j)) = (pair[0], pair[1]);
        assert!(
            a < b || (a == b && i < j),
            "ties wake in registration order: {pair:?}"
        );
    }
}

#[test]
fn twenty_thousand_timers_fire_at_their_deadlines_ties_in_registration_order() {
    check_many_sleeps(&Sim::new(), 20_000, 200);
}

#[test]
fn twenty_thousand_timers_under_deterministic() {
    check_many_sleeps(&Sim::builder().deterministic().seed(4).build(), 20_000, 200);
}

#[test]
fn a_hundred_thousand_timers_fire_at_their_deadlines_ties_in_registration_order() {
    check_many_sleeps(&Sim::new(), 100_000, 1_000);
}

/// A thousand threads, each sleeping to one of ten tied deadlines and recording when it woke, in
/// the order they woke.
fn thousand_sleepers(sim: &Sim) -> Vec<(usize, Duration)> {
    sim.run(|| {
        let log = Arc::new(Mutex::new(Vec::new()));
        let start = Instant::now();
        let threads: Vec<_> = (0..1_000)
            .map(|i| {
                let log = log.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(1 + (i % 10) as u64));
                    log.lock().unwrap().push((i, start.elapsed()));
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        Arc::try_unwrap(log).unwrap().into_inner().unwrap()
    })
}

#[test]
fn a_thousand_sleeping_threads_wake_at_their_deadlines() {
    let log = thousand_sleepers(&Sim::new());
    assert_eq!(log.len(), 1_000);
    for &(i, woke) in &log {
        assert_eq!(woke, due_of(i) + NS, "thread {i}");
    }
    let mut groups: Vec<Duration> = log.iter().map(|&(i, _)| due_of(i)).collect();
    groups.dedup();
    assert_eq!(
        groups.len(),
        10,
        "every thread of one deadline wakes before the next deadline's"
    );
}

fn due_of(i: usize) -> Duration {
    Duration::from_millis(1 + (i % 10) as u64)
}

#[test]
fn a_thousand_sleeping_threads_wake_in_a_golden_order_under_deterministic() {
    let sim = || Sim::builder().deterministic().seed(5).build();
    let first = thousand_sleepers(&sim());
    assert_eq!(first, thousand_sleepers(&sim()), "the same seed replays");
    let mut out = String::new();
    for (i, woke) in &first {
        out.push_str(&format!("{i} {}\n", woke.as_nanos()));
    }
    golden::check_text("edge_scale_sleepers.txt", &out);
}

#[test]
fn creating_a_thousand_sleeps_does_not_move_the_clock() {
    Sim::new().run(|| {
        let base = Instant::now();
        let sleeps: Vec<_> = (0..1_000)
            .map(|_| sched::sleep_until(base + Duration::from_secs(1)))
            .collect();
        assert_eq!(snare::time().value(), Duration::ZERO);
        assert!(sleeps.iter().all(|s| !s.is_elapsed()));
    });
}

#[test]
fn a_long_clock_spin_never_saturates_the_clock() {
    Sim::new().run(|| {
        for _ in 0..3_000 {
            std::hint::black_box(Instant::now());
        }
        let now = snare::time().value();
        assert!(
            now < Duration::from_secs(3_600),
            "3000 reads moved the clock {now:?}"
        );
        assert!(Instant::now().checked_add(Duration::from_secs(1)).is_some());
    });
}
