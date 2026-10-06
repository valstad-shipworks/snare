//! Behaviour pins for the clock controls (`pause`, `resume`, `advance`, `set_value`, `set_rate`),
//! ahead of performance work on the clock: every ordered pair of controls from a fresh sim, with
//! the exact reading, pause state and rate after each, and what a waiter sees when a control
//! releases it.
//!
//! The rules pinned: no control ever moves the reading back; `advance` and `set_value` move a
//! held or discrete clock by exactly what they say and keep it paused if it was; `advance(0)` and
//! setting the current value change nothing; setting a value behind the reading panics and leaves
//! the clock alone; `set_rate(0.0)` is `pause`, `set_rate(INFINITY)` returns to the discrete base
//! mode unpaused, and a deterministic sim refuses a finite rate without touching the clock; a
//! waiter released by `advance` or `set_value` wakes at exactly the reading the control left,
//! while one released by `resume` wakes by a time skip, 1 ns past its deadline.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::thread;
use std::time::{Duration, Instant};

use snare::{Sim, TimeHandle, sched};

#[path = "support/landing.rs"]
mod landing;

/// Where a time skip to `deadline` lands.
fn past(deadline: Duration) -> Duration {
    Duration::from_nanos(landing::past(deadline.as_nanos() as u64))
}

const MS: Duration = Duration::from_millis(1);

#[derive(Clone, Copy, Debug, PartialEq)]
enum Op {
    Pause,
    Resume,
    Advance,
    AdvanceZero,
    SetForward,
    SetSame,
    SetBack,
    RateZero,
    RateInfinity,
    RateScaled,
}

const OPS: [Op; 10] = [
    Op::Pause,
    Op::Resume,
    Op::Advance,
    Op::AdvanceZero,
    Op::SetForward,
    Op::SetSame,
    Op::SetBack,
    Op::RateZero,
    Op::RateInfinity,
    Op::RateScaled,
];

/// What the clock should be after a control, for a clock that is not scaled to real time.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Model {
    value: Duration,
    paused: bool,
    scaled: bool,
}

impl Model {
    fn rate(&self) -> f64 {
        if self.paused {
            0.0
        } else if self.scaled {
            SCALED
        } else {
            f64::INFINITY
        }
    }
}

const SCALED: f64 = 1_000.0;

/// Applies `op`, returning whether it panicked.
fn apply(time: &TimeHandle, op: Op) -> bool {
    let now = time.value();
    catch_unwind(AssertUnwindSafe(|| match op {
        Op::Pause => time.pause(),
        Op::Resume => time.resume(),
        Op::Advance => time.advance(MS),
        Op::AdvanceZero => time.advance(Duration::ZERO),
        Op::SetForward => time.set_value(now + MS),
        Op::SetSame => time.set_value(now),
        Op::SetBack => time.set_value(now.saturating_sub(Duration::from_nanos(1))),
        Op::RateZero => time.set_rate(0.0),
        Op::RateInfinity => time.set_rate(f64::INFINITY),
        Op::RateScaled => time.set_rate(SCALED),
    }))
    .is_err()
}

/// The model's next state and whether `op` should panic.
fn step(m: Model, op: Op, deterministic: bool) -> (Model, bool) {
    let mut next = m;
    match op {
        Op::Pause | Op::RateZero => next.paused = true,
        Op::Resume => next.paused = false,
        Op::Advance | Op::SetForward => next.value += MS,
        Op::AdvanceZero | Op::SetSame => {}
        Op::SetBack => return (m, !m.value.is_zero()),
        Op::RateInfinity => {
            next.paused = false;
            next.scaled = false;
        }
        Op::RateScaled if deterministic => return (m, true),
        Op::RateScaled => {
            next.paused = false;
            next.scaled = true;
        }
    }
    (next, false)
}

/// Every ordered pair of controls, applied to a fresh sim that first moved to 5 ms: the reading
/// never goes back, and while the clock is not scaled every reading, pause state and rate is
/// exactly the model's. A set on a running scaled clock races real time (the value it is measured
/// from moves on before it lands), so only its effect on the state is checked.
fn every_pair(deterministic: bool) {
    for a in OPS {
        for b in OPS {
            let sim = if deterministic {
                Sim::builder().deterministic().build()
            } else {
                Sim::new()
            };
            let time = sim.time();
            time.advance(5 * MS);
            let mut model = Model {
                value: 5 * MS,
                paused: false,
                scaled: false,
            };
            let mut last = time.value();
            for op in [a, b] {
                let before = time.value();
                let panicked = apply(&time, op);
                let (next, should_panic) = step(model, op, deterministic);
                let what = format!("{a:?} then {b:?}, at {op:?}");
                let races_real_time = model.scaled
                    && !model.paused
                    && matches!(op, Op::SetForward | Op::SetSame | Op::SetBack);
                if !races_real_time {
                    assert_eq!(panicked, should_panic, "{what}");
                }
                let now = time.value();
                assert!(now >= last, "{what}: went back from {last:?} to {now:?}");
                if panicked {
                    assert!(
                        model.scaled || now == before,
                        "{what}: a refused control moved the clock"
                    );
                }
                last = now;
                let ran = model.scaled && !model.paused;
                model = next;
                assert_eq!(time.is_paused(), model.paused, "{what}");
                assert_eq!(time.rate(), model.rate(), "{what}");
                if !ran && !(model.scaled && !model.paused) {
                    assert_eq!(now, model.value, "{what}");
                } else {
                    assert!(now >= model.value, "{what}: {now:?} < {:?}", model.value);
                    model.value = now;
                }
            }
        }
    }
}

#[test]
fn every_pair_of_controls_on_the_discrete_clock() {
    every_pair(false);
}

#[test]
fn every_pair_of_controls_under_deterministic() {
    every_pair(true);
}

/// A paused clock with a waiter on an absolute deadline: the waiter wakes at exactly the reading
/// of the control that reached its deadline, not 1 ns past it.
#[test]
fn waiters_released_by_advance_and_set_value_wake_at_the_reading_they_left() {
    for deterministic in [false, true] {
        for set in [false, true] {
            let sim = if deterministic {
                Sim::builder().deterministic().build()
            } else {
                Sim::new()
            };
            sim.pause_time();
            let time = sim.time();
            let (started, start) = std::sync::mpsc::channel();
            let driver = thread::spawn(move || {
                start.recv().unwrap();
                for step in 1..=4u32 {
                    snare::real(|| thread::sleep(20 * MS));
                    if set {
                        time.set_value(3 * MS * step);
                    } else {
                        time.advance(3 * MS);
                    }
                }
            });
            let woke = sim.run(|| {
                let origin = Instant::now();
                started.send(()).unwrap();
                let parked = thread::spawn(move || {
                    assert_eq!(
                        sched::park(Some(origin + 10 * MS)),
                        sched::ParkResult::TimedOut
                    );
                    sched::now()
                });
                sched::block_on(sched::sleep_until(origin + 10 * MS));
                (sched::now(), parked.join().unwrap())
            });
            driver.join().unwrap();
            assert_eq!(
                woke,
                (12 * MS, 12 * MS),
                "deterministic {deterministic}, set_value {set}"
            );
        }
    }
}

/// A paused clock resumed with a sleeper pending moves on by a time skip, landing 1 ns past the
/// sleeper's deadline.
#[test]
fn a_waiter_released_by_resume_wakes_just_past_its_deadline() {
    for deterministic in [false, true] {
        let sim = if deterministic {
            Sim::builder().deterministic().build()
        } else {
            Sim::new()
        };
        sim.pause_time();
        let time = sim.time();
        let driver = thread::spawn(move || {
            snare::real(|| thread::sleep(50 * MS));
            assert_eq!(time.value(), Duration::ZERO, "nothing moved a paused clock");
            time.resume();
        });
        let woke = sim.run(|| {
            let origin = Instant::now();
            sched::block_on(sched::sleep_until(origin + 10 * MS));
            sched::now()
        });
        driver.join().unwrap();
        assert_eq!(woke, past(10 * MS), "deterministic {deterministic}");
    }
}

/// Controls made from inside the run, by the thread the clock is waiting on, read back exactly.
#[test]
fn controls_from_inside_the_run_read_back_exactly() {
    for deterministic in [false, true] {
        let sim = if deterministic {
            Sim::builder().deterministic().build()
        } else {
            Sim::new()
        };
        let seen = sim.run(|| {
            let time = snare::time();
            let mut seen = Vec::new();
            time.advance(2 * MS);
            seen.push(sched::now());
            time.pause();
            time.advance(3 * MS);
            seen.push(sched::now());
            time.set_value(9 * MS);
            seen.push(sched::now());
            time.resume();
            thread::sleep(MS);
            seen.push(sched::now());
            time.set_rate(f64::INFINITY);
            thread::sleep(MS);
            seen.push(sched::now());
            seen
        });
        assert_eq!(
            seen,
            vec![
                2 * MS,
                5 * MS,
                9 * MS,
                past(10 * MS),
                past(past(10 * MS) + MS),
            ],
            "deterministic {deterministic}"
        );
    }
}
