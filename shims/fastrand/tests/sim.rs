//! fastrand's thread-local generators inside snare sims: seeded from the sim, so a deterministic
//! sim draws the same numbers whatever the process ran before it.

#![cfg(snare)]

use std::time::Duration;

use snare::Sim;

fn det_sim() -> Sim {
    Sim::builder()
        .deterministic()
        .seed(9)
        .stuck_after(Duration::from_secs(10))
        .build()
}

fn draws() -> Vec<u64> {
    (0..4).map(|_| fastrand::u64(..)).collect()
}

fn threads_draw() -> Vec<Vec<u64>> {
    det_sim().run(|| {
        let workers: Vec<_> = (0..3)
            .map(|i| {
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(i));
                    let mut forked = fastrand::Rng::new();
                    let mut v = draws();
                    v.push(forked.u64(..));
                    v
                })
            })
            .collect();
        workers.into_iter().map(|w| w.join().unwrap()).collect()
    })
}

#[test]
fn replay_does_not_depend_on_threads_made_before() {
    let first = threads_draw();
    for extra in [1, 7, 30] {
        for _ in 0..extra {
            std::thread::spawn(|| fastrand::u64(..)).join().unwrap();
        }
        assert_eq!(threads_draw(), first, "after {extra} more threads");
    }
}

#[test]
fn a_thread_entering_another_sim_is_reseeded() {
    let first = det_sim().run(draws);
    let _ = draws();
    let second = det_sim().run(draws);
    assert_eq!(first, second);
}

#[test]
fn a_seed_the_caller_set_is_kept() {
    fastrand::seed(7);
    let drawn = det_sim().run(|| fastrand::u64(..));
    assert_eq!(drawn, fastrand::Rng::with_seed(7).u64(..));
}

#[test]
fn concurrent_sims_replay() {
    let reference = threads_draw();
    let workers: Vec<_> = (0..4).map(|_| std::thread::spawn(threads_draw)).collect();
    for worker in workers {
        assert_eq!(worker.join().unwrap(), reference);
    }
}

#[test]
fn outside_a_sim_threads_get_distinct_seeds() {
    let a = std::thread::spawn(fastrand::get_seed).join().unwrap();
    let b = std::thread::spawn(fastrand::get_seed).join().unwrap();
    assert_ne!(a, b);
}
