//! quanta's clocks inside snare sims: they read the sim's clock, never calibrate against it, and
//! replay under a deterministic schedule.

#![cfg(snare)]

use std::time::{Duration, Instant};

use snare::Sim;

fn sim(deterministic: bool) -> Sim {
    let builder = Sim::builder().stuck_after(Duration::from_secs(10));
    if deterministic {
        builder.deterministic().seed(5).build()
    } else {
        builder.build()
    }
}

fn assert_virtual(elapsed: Duration, what: &str) {
    assert!(
        (Duration::from_millis(50)..Duration::from_millis(60)).contains(&elapsed),
        "{what}: a 50 ms sleep took {elapsed:?} of sim time"
    );
}

fn clock_and_global() -> (Duration, Duration) {
    let clock = quanta::Clock::new();
    let start = clock.now();
    let global = quanta::Instant::now();
    std::thread::sleep(Duration::from_millis(50));
    (clock.now() - start, global.elapsed())
}

#[test]
fn a_new_clock_does_not_spend_sim_time() {
    let spent = sim(false).run(|| {
        let start = Instant::now();
        let clock = quanta::Clock::new();
        let _ = clock.now();
        start.elapsed()
    });
    assert!(
        spent < Duration::from_millis(5),
        "making a clock took {spent:?} of sim time"
    );
}

#[test]
fn clocks_read_sim_time() {
    let (clock, global) = sim(false).run(clock_and_global);
    assert_virtual(clock, "Clock::now");
    assert_virtual(global, "Instant::now");
}

#[test]
fn the_global_clock_made_outside_reads_sim_time_inside() {
    let _ = quanta::Instant::now();
    let elapsed = sim(false).run(|| {
        let start = quanta::Instant::now();
        std::thread::sleep(Duration::from_millis(50));
        start.elapsed()
    });
    assert_virtual(elapsed, "Instant::now");
}

#[test]
fn sequential_sims() {
    for deterministic in [false, true, false, true] {
        let (clock, global) = sim(deterministic).run(clock_and_global);
        assert_virtual(clock, "Clock::now");
        assert_virtual(global, "Instant::now");
    }
}

#[test]
fn concurrent_sims() {
    let workers: Vec<_> = (0..4)
        .map(|i| {
            std::thread::spawn(move || {
                for _ in 0..3 {
                    let (clock, global) = sim(i % 2 == 0).run(clock_and_global);
                    assert_virtual(clock, "Clock::now");
                    assert_virtual(global, "Instant::now");
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn deterministic_sims_replay() {
    let trace = || {
        sim(true).run(|| {
            let clock = quanta::Clock::new();
            let start = clock.now();
            let workers: Vec<_> = (0..3u64)
                .map(|i| {
                    let clock = clock.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(7 * i + 1));
                        clock.now()
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|w| w.join().unwrap() - start)
                .collect::<Vec<_>>()
        })
    };
    let first = trace();
    for _ in 0..3 {
        assert_eq!(trace(), first);
    }
}

#[test]
fn recent_follows_an_upkeep_thread_in_the_sim() {
    let delta = sim(false).run(|| {
        let _upkeep = quanta::Upkeep::new(Duration::from_millis(1))
            .start()
            .unwrap();
        let before = quanta::Instant::recent();
        std::thread::sleep(Duration::from_millis(50));
        quanta::Instant::recent() - before
    });
    assert!(
        (Duration::from_millis(45)..Duration::from_millis(60)).contains(&delta),
        "Instant::recent moved {delta:?} across a 50 ms sleep"
    );
}

#[test]
fn outside_a_sim_the_clock_is_real() {
    let clock = quanta::Clock::new();
    let start = clock.now();
    let real = Instant::now();
    std::thread::sleep(Duration::from_millis(10));
    assert!(clock.now() - start >= Duration::from_millis(10));
    assert!(real.elapsed() >= Duration::from_millis(10));
}
