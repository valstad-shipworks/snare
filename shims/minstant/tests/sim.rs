//! minstant inside snare sims: never the TSC, so its instants and its anchor's Unix time are the
//! sim's.

#![cfg(snare)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use snare::Sim;

fn sim(deterministic: bool) -> Sim {
    let builder = Sim::builder().stuck_after(Duration::from_secs(10));
    if deterministic {
        builder.deterministic().seed(5).build()
    } else {
        builder.build()
    }
}

fn sleep_50ms() -> Duration {
    let start = minstant::Instant::now();
    std::thread::sleep(Duration::from_millis(50));
    start.elapsed()
}

fn assert_virtual(elapsed: Duration) {
    assert!(
        (Duration::from_millis(50)..Duration::from_millis(60)).contains(&elapsed),
        "a 50 ms sleep took {elapsed:?} of sim time"
    );
}

#[test]
fn the_tsc_is_never_used() {
    assert!(!minstant::is_tsc_available());
}

#[test]
fn instants_read_sim_time() {
    assert_virtual(sim(false).run(sleep_50ms));
}

#[test]
fn the_anchor_gives_the_sims_unix_time() {
    let (unix_nanos, sim_unix) = sim(false).run(|| {
        let anchor = minstant::Anchor::new();
        let nanos = minstant::Instant::now().as_unix_nanos(&anchor);
        let sim_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        (nanos, sim_unix)
    });
    let diff = (unix_nanos as i128 - sim_unix.as_nanos() as i128).abs();
    assert!(
        diff < Duration::from_millis(5).as_nanos() as i128,
        "anchor Unix time {unix_nanos} is not the sim's {sim_unix:?}"
    );
}

#[test]
fn sequential_and_concurrent_sims() {
    for deterministic in [false, true, false, true] {
        assert_virtual(sim(deterministic).run(sleep_50ms));
    }
    let workers: Vec<_> = (0..4)
        .map(|i| std::thread::spawn(move || assert_virtual(sim(i % 2 == 0).run(sleep_50ms))))
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn deterministic_sims_replay() {
    let trace = || {
        sim(true).run(|| {
            let start = minstant::Instant::now();
            let workers: Vec<_> = (0..3u64)
                .map(|i| {
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(7 * i + 1));
                        minstant::Instant::now()
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|w| w.join().unwrap().duration_since(start))
                .collect::<Vec<_>>()
        })
    };
    let first = trace();
    for _ in 0..3 {
        assert_eq!(trace(), first);
    }
}

#[test]
fn outside_a_sim_instants_are_real() {
    let start = minstant::Instant::now();
    std::thread::sleep(Duration::from_millis(10));
    assert!(start.elapsed() >= Duration::from_millis(9));
}
