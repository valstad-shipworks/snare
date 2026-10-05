//! Behaviour pins for many threads, ahead of performance work on the scheduler and accounting:
//!
//! - A thousand threads parked on one condition variable all wake from one `notify_all`, each
//!   exactly once, without virtual time moving; under `deterministic()` they wake in an order
//!   pinned to a golden that replays.
//! - Thread lineage ids at depth and breadth — a chain of 300 threads each spawning the next, and
//!   a tree of 10 × 10 × 10 — are all distinct, independent of scheduling (the same on the
//!   free-running clock and under `deterministic()`, run after run), and pinned to a golden.
//! - The executive lists every one of a thousand blocked participants.

#![cfg(unix)]

#[path = "support/golden.rs"]
mod golden;

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use snare::Sim;
use snare::sched::ExecutiveConfig;

const WAITERS: usize = 1_000;

#[derive(Default)]
struct Gate {
    open: bool,
    parked: usize,
    woke: Vec<usize>,
}

/// Parks `WAITERS` threads on one condvar, opens it with one `notify_all` once every one is
/// waiting, and returns the order they woke in and how far virtual time moved from the notify to
/// the last join.
fn notify_all_run(sim: &Sim) -> (Vec<usize>, Duration) {
    sim.run(|| {
        let state = Arc::new((Mutex::new(Gate::default()), Condvar::new()));
        let waiters: Vec<_> = (0..WAITERS)
            .map(|i| {
                let state = state.clone();
                std::thread::spawn(move || {
                    let (lock, cv) = &*state;
                    let mut g = lock.lock().unwrap();
                    g.parked += 1;
                    while !g.open {
                        g = cv.wait(g).unwrap();
                    }
                    g.woke.push(i);
                })
            })
            .collect();
        while state.0.lock().unwrap().parked < WAITERS {
            std::thread::sleep(Duration::from_millis(1));
        }
        let notified = snare::time().value();
        state.0.lock().unwrap().open = true;
        state.1.notify_all();
        for w in waiters {
            w.join().unwrap();
        }
        let woke = std::mem::take(&mut state.0.lock().unwrap().woke);
        (woke, snare::time().value() - notified)
    })
}

#[test]
fn a_thousand_condvar_waiters_all_wake_from_one_notify_all() {
    let (mut woke, took) = notify_all_run(&Sim::new());
    assert_eq!(took, Duration::ZERO, "waking is not a timed wait");
    woke.sort_unstable();
    assert_eq!(
        woke,
        (0..WAITERS).collect::<Vec<_>>(),
        "each wakes exactly once"
    );
}

#[test]
fn a_thousand_condvar_waiters_wake_in_a_golden_order_under_deterministic() {
    let sim = || Sim::builder().deterministic().seed(1).build();
    let (woke, took) = notify_all_run(&sim());
    assert_eq!(took, Duration::ZERO);
    assert_eq!(notify_all_run(&sim()).0, woke, "the same seed replays");
    let out: String = woke.iter().map(|i| format!("{i}\n")).collect();
    golden::check_text("edge_scale_condvar_wake_order.txt", &out);
}

/// Spawns a chain of `depth` threads, each spawning the next, and returns each one's lineage.
fn chain(depth: usize) -> Vec<u64> {
    let mut ids = vec![snare_interpose::thread_lineage()];
    if depth > 0 {
        ids.extend(std::thread::spawn(move || chain(depth - 1)).join().unwrap());
    }
    ids
}

/// Spawns `fanout` children per thread down `levels` levels and returns every lineage, depth
/// first, children in spawn order.
fn tree(fanout: usize, levels: usize) -> Vec<u64> {
    let mut ids = vec![snare_interpose::thread_lineage()];
    if levels > 0 {
        let children: Vec<_> = (0..fanout)
            .map(|_| std::thread::spawn(move || tree(fanout, levels - 1)))
            .collect();
        for c in children {
            ids.extend(c.join().unwrap());
        }
    }
    ids
}

fn lineages(sim: &Sim) -> (Vec<u64>, Vec<u64>) {
    sim.run(|| (chain(300), tree(10, 3)))
}

#[test]
fn lineage_ids_of_deep_and_wide_trees_are_distinct_stable_and_golden() {
    let (chain_ids, tree_ids) = lineages(&Sim::new());
    assert_eq!((chain_ids.len(), tree_ids.len()), (301, 1_111));
    let mut all: Vec<u64> = chain_ids[1..]
        .iter()
        .chain(&tree_ids[1..])
        .copied()
        .collect();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), 300 + 1_110, "no two threads share a lineage id");
    assert_eq!(
        (chain_ids[0], tree_ids[0]),
        (0, 0),
        "the entering thread is lineage 0"
    );

    assert_eq!(lineages(&Sim::new()), (chain_ids.clone(), tree_ids.clone()));
    let det = Sim::builder().deterministic().seed(9).build();
    assert_eq!(
        lineages(&det),
        (chain_ids.clone(), tree_ids.clone()),
        "lineage does not depend on the schedule"
    );

    let mut out = String::from("chain\n");
    for id in &chain_ids {
        out.push_str(&format!("{id:016x}\n"));
    }
    out.push_str("tree\n");
    for id in &tree_ids {
        out.push_str(&format!("{id:016x}\n"));
    }
    golden::check_text("edge_scale_lineage.txt", &out);
}

#[test]
fn the_executive_lists_a_thousand_blocked_participants() {
    let sim = Sim::new();
    let exec = sim.executive(ExecutiveConfig::default()).unwrap();
    std::thread::scope(|s| {
        let run = s.spawn(|| {
            sim.run(|| {
                let threads: Vec<_> = (0..WAITERS)
                    .map(|i| {
                        std::thread::Builder::new()
                            .name(format!("sleeper-{i}"))
                            .spawn(|| std::thread::sleep(Duration::from_millis(5)))
                            .unwrap()
                    })
                    .collect();
                for t in threads {
                    t.join().unwrap();
                }
            })
        });
        let start = snare::real(std::time::Instant::now);
        let q = loop {
            let q = exec.quiescence();
            if q.quiescent && q.blocked as usize == WAITERS + 1 {
                break q;
            }
            assert!(
                snare::real(|| start.elapsed()) < Duration::from_secs(60),
                "never settled: {q:?}"
            );
            snare::real(|| std::thread::sleep(Duration::from_millis(1)));
        };
        assert_eq!((q.runnable, q.busy), (0, 0));
        assert_eq!(q.next_deadline, Some(Duration::from_millis(5)));
        let participants = exec.participants();
        let sleepers = participants
            .iter()
            .filter(|p| {
                p.name.starts_with("sleeper-") && p.deadline == Some(Duration::from_millis(5))
            })
            .count();
        assert_eq!((participants.len(), sleepers), (WAITERS + 1, WAITERS));
        assert_eq!(exec.jump_to(Duration::from_millis(5)), Ok(WAITERS as u32));
        drop(exec);
        run.join().unwrap();
    });
}
