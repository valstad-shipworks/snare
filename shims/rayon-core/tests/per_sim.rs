//! With `cfg(snare_parallel_rayon)`, each snare sim gets its own global pool: concurrent sims
//! never run each other's jobs, and the pool's workers exit with their sim.

#![cfg(all(snare, snare_parallel_rayon))]

use std::sync::mpsc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use snare::sched::SimId;
use snare::Sim;

fn sim(deterministic: bool) -> Sim {
    let builder = Sim::builder().stuck_after(Duration::from_secs(10));
    if deterministic {
        builder.deterministic().seed(3).build()
    } else {
        builder.build()
    }
}

fn in_range(elapsed: Duration, lo: u64, hi: u64, what: &str) {
    assert!(
        (Duration::from_millis(lo)..Duration::from_millis(hi)).contains(&elapsed),
        "{what} took {elapsed:?} of sim time, expected {lo}..{hi} ms"
    );
}

/// join, scope and spawn on the global pool; every job must run in the calling sim.
fn exercise(deterministic: bool) {
    sim(deterministic).run(|| {
        let me = snare::sched::current_sim();
        let jobs: Mutex<Vec<Option<SimId>>> = Mutex::default();
        let job = |ms: u64| {
            std::thread::sleep(Duration::from_millis(ms));
            jobs.lock().unwrap().push(snare::sched::current_sim());
        };

        let start = Instant::now();
        rayon_core::join(|| job(50), || job(30));
        in_range(start.elapsed(), 50, 60, "join");

        let start = Instant::now();
        rayon_core::scope(|s| {
            for _ in 0..rayon_core::current_num_threads() {
                s.spawn(|_| job(10));
            }
        });
        in_range(start.elapsed(), 10, 20, "scope");

        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        rayon_core::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            tx.send(snare::sched::current_sim()).unwrap();
        });
        assert_eq!(rx.recv().unwrap(), me);
        in_range(start.elapsed(), 20, 30, "spawn");

        let jobs = jobs.into_inner().unwrap();
        assert!(
            jobs.iter().all(|sim| *sim == me),
            "jobs ran in {jobs:?}, not {me:?}"
        );
    });
}

#[test]
fn sequential_sims() {
    for deterministic in [false, true, false, true] {
        exercise(deterministic);
    }
}

#[test]
fn concurrent_sims() {
    let workers: Vec<_> = (0..4)
        .map(|i| std::thread::spawn(move || (0..3).for_each(|_| exercise(i % 2 == 0))))
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn the_global_pool_replays() {
    let trace = || {
        sim(true).run(|| {
            let log = Mutex::new(Vec::new());
            let start = Instant::now();
            rayon_core::scope(|s| {
                for i in 0..12u64 {
                    let log = &log;
                    s.spawn(move |_| {
                        std::thread::sleep(Duration::from_millis(i % 4));
                        let at = start.elapsed().as_micros();
                        log.lock()
                            .unwrap()
                            .push((i, rayon_core::current_thread_index(), at));
                    });
                }
            });
            log.into_inner().unwrap()
        })
    };
    let first = trace();
    exercise(false);
    for _ in 0..3 {
        assert_eq!(trace(), first);
    }
}

#[test]
fn build_global_configures_the_sims_pool() {
    for threads in [2, 3] {
        sim(false).run(|| {
            rayon_core::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build_global()
                .unwrap();
            assert_eq!(rayon_core::current_num_threads(), threads);
            assert!(rayon_core::ThreadPoolBuilder::new().build_global().is_err());
        });
    }
}

#[test]
fn the_workers_exit_with_their_sim() {
    let sim = sim(false);
    let workers = sim.run(|| {
        rayon_core::ThreadPoolBuilder::new()
            .num_threads(2)
            .thread_name(|i| format!("per-sim-rayon-{i}"))
            .build_global()
            .unwrap();
        rayon_core::join(|| (), || ());
        let census = snare::sched::thread_census().unwrap();
        let workers: Vec<u64> = census
            .threads
            .iter()
            .filter(|t| {
                t.name
                    .as_deref()
                    .is_some_and(|n| n.starts_with("per-sim-rayon-"))
            })
            .map(|t| t.os_id)
            .collect();
        assert_eq!(workers.len(), 2, "{census:?}");
        workers
    });
    drop(sim);
    let gone = (0..100).any(|_| {
        let census = snare_interpose::census(None).unwrap();
        if census.threads.iter().all(|t| !workers.contains(&t.os_id)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
        false
    });
    assert!(gone, "the sim's rayon workers outlived it");
}

#[test]
fn outside_a_sim_the_pool_is_the_process_one() {
    let (a, b) = rayon_core::join(|| 1, || 2);
    assert_eq!(a + b, 3);
    let outside = rayon_core::current_num_threads();
    sim(false).run(|| {
        rayon_core::ThreadPoolBuilder::new()
            .num_threads(outside + 1)
            .build_global()
            .unwrap();
    });
    assert_eq!(rayon_core::current_num_threads(), outside);
}
