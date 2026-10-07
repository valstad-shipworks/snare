//! rayon-core pools made inside deterministic snare sims steal in the same order on every run,
//! whatever pools the process made before.

#![cfg(snare)]

use std::sync::Mutex;
use std::time::{Duration, Instant};

use snare::Sim;

type Log = Mutex<Vec<(u64, Option<usize>, u128)>>;

fn tree(depth: u32, id: u64, log: &Log, start: Instant) {
    if depth == 0 {
        std::thread::sleep(Duration::from_millis(id % 3 + 1));
        let entry = (
            id,
            rayon_core::current_thread_index(),
            start.elapsed().as_micros(),
        );
        log.lock().unwrap().push(entry);
        return;
    }
    rayon_core::join(
        || tree(depth - 1, id * 2, log, start),
        || tree(depth - 1, id * 2 + 1, log, start),
    );
}

fn local_pool_trace() -> Vec<(u64, Option<usize>, u128)> {
    Sim::builder()
        .deterministic()
        .seed(11)
        .stuck_after(Duration::from_secs(10))
        .build()
        .run(|| {
            let pool = rayon_core::ThreadPoolBuilder::new()
                .num_threads(3)
                .build()
                .unwrap();
            let log = Log::default();
            let start = Instant::now();
            pool.install(|| tree(4, 1, &log, start));
            log.into_inner().unwrap()
        })
}

#[test]
fn a_local_pool_replays_whatever_pools_came_before() {
    let first = local_pool_trace();
    assert_eq!(first.len(), 16);
    for extra in [1, 2, 5] {
        drop(
            rayon_core::ThreadPoolBuilder::new()
                .num_threads(extra)
                .build()
                .unwrap(),
        );
        assert_eq!(local_pool_trace(), first, "after a pool of {extra}");
    }
}

#[test]
fn a_local_pool_runs_on_sim_time() {
    let elapsed = Sim::builder()
        .stuck_after(Duration::from_secs(10))
        .build()
        .run(|| {
            let pool = rayon_core::ThreadPoolBuilder::new()
                .num_threads(2)
                .build()
                .unwrap();
            let start = Instant::now();
            pool.join(
                || std::thread::sleep(Duration::from_millis(50)),
                || std::thread::sleep(Duration::from_millis(30)),
            );
            start.elapsed()
        });
    assert!(
        (Duration::from_millis(50)..Duration::from_millis(90)).contains(&elapsed),
        "a join of 50 ms and 30 ms sleeps took {elapsed:?} of sim time"
    );
}
