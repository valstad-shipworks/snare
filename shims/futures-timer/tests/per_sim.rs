//! `Delay` inside snare sims: each sim has its own "futures-timer" thread, so a sim's delays time
//! on its own clock however many sims run at once.

#![cfg(snare)]

use std::time::{Duration, Instant};

use futures_timer::Delay;
use snare::sched::{Executive, ExecutiveConfig};
use snare::Sim;

const DELAY: Duration = Duration::from_millis(50);

fn sim(deterministic: bool) -> Sim {
    let builder = Sim::builder().stuck_after(Duration::from_secs(10));
    if deterministic {
        builder.deterministic().build()
    } else {
        builder.build()
    }
}

fn delays() -> Duration {
    let start = Instant::now();
    futures_lite::future::block_on(async {
        Delay::new(DELAY).await;
        let _cancelled = Delay::new(Duration::from_secs(30));
        Delay::new(DELAY).await;
    });
    start.elapsed()
}

fn assert_virtual(elapsed: Duration) {
    assert!(
        (2 * DELAY..2 * DELAY + Duration::from_millis(1)).contains(&elapsed),
        "two {:?} delays took {:?} of sim time",
        DELAY,
        elapsed
    );
}

#[test]
fn sequential_sims_each_get_a_timer_thread() {
    for deterministic in [false, true, false, true] {
        assert_virtual(sim(deterministic).run(delays));
    }
}

#[test]
fn concurrent_sims_each_get_a_timer_thread() {
    let workers: Vec<_> = (0..4)
        .map(|i| {
            std::thread::spawn(move || {
                for _ in 0..5 {
                    assert_virtual(sim(i % 2 == 0).run(delays));
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

/// Jumps to each next deadline until `run` finishes, failing after ten seconds of real time.
fn drive<T>(exec: &Executive, run: &std::thread::JoinHandle<T>) {
    let start = snare::real(Instant::now);
    while !run.is_finished() {
        assert!(
            snare::real(|| start.elapsed()) < Duration::from_secs(10),
            "the sim never finished, at {:?}: {:?}",
            exec.now(),
            exec.quiescence()
        );
        let q = exec.quiescence();
        match q.next_deadline {
            Some(next) if q.quiescent => drop(exec.jump_to(next)),
            _ => snare::real(|| std::thread::sleep(Duration::from_micros(50))),
        }
    }
}

/// The harness shape of an executive-driven simulator: the sim is entered only to spawn its
/// threads, and an executive outside it moves its clock.
#[test]
fn concurrent_executive_driven_sims_each_get_a_timer_thread() {
    let workers: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(|| {
                for _ in 0..5 {
                    let sim = Sim::new();
                    let exec = sim.executive(ExecutiveConfig::default()).unwrap();
                    let run = sim.run(|| std::thread::spawn(delays));
                    drive(&exec, &run);
                    assert_virtual(run.join().unwrap());
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}
