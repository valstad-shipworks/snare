//! A workload for a test binary that installs a C allocator as its `#[global_allocator]`
//! (`alloc_jemalloc.rs`, `alloc_mimalloc.rs`). Such an allocator calls the hooked pthread and
//! clock functions from inside its own critical sections: jemalloc sets up the mutexes of each new
//! arena while it holds the lock over all arenas, the first time a new thread allocates, and reads
//! the clock for its decay bookkeeping. A hook that allocates there deadlocks the allocator on its
//! own lock, and every thread allocating after it hangs too. A thread no sim manages (a stuck
//! watchdog, a test's own thread) records what a managed one does under the sim's own code, so
//! enough of those alive at once to need new arenas reach it, as do fresh threads allocating in
//! sims, one sim after another and several at once. The clock the allocator reads every so many
//! allocations must cost the run no more time than a hooked call would.

#![allow(dead_code)]

use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use snare::{Sim, SimBuilder};

/// Allocations of up to 70 KB, a few hundred live at a time, on threads made inside the sim, then
/// sleeps: 8 threads that sleep 200 ms each after their churn, joined, then a 2 s sleep.
fn workload() -> Duration {
    let start = Instant::now();
    let threads: Vec<_> = (0..8u8)
        .map(|n| {
            thread::spawn(move || {
                let mut keep = Vec::new();
                for i in 0..2_000usize {
                    keep.push(vec![n; (i * 37) % 70_000]);
                    if keep.len() > 50 {
                        keep.drain(..25);
                    }
                }
                thread::sleep(Duration::from_millis(200));
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    thread::sleep(Duration::from_secs(2));
    start.elapsed()
}

/// Runs `f` on a thread of its own and fails the test if it has not finished within `limit` of
/// real time, rather than hang with it.
fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || tx.send(f()).unwrap());
    rx.recv_timeout(limit)
        .unwrap_or_else(|_| panic!("still running after {limit:?}: a hook deadlocked"))
}

fn assert_costs_only_its_sleeps(elapsed: Duration, what: &str) {
    assert!(
        elapsed >= Duration::from_millis(2_200) && elapsed < Duration::from_millis(2_300),
        "{what}: the workload took {elapsed:?} of sim time"
    );
}

/// Threads outside any sim, more alive at once than an allocator keeps arenas for by default
/// (jemalloc: four per CPU), each allocating as it starts.
fn unmanaged_threads() {
    let n = 4 * thread::available_parallelism().map_or(4, |n| n.get()) + 8;
    let all = Arc::new(Barrier::new(n));
    let threads: Vec<_> = (0..n)
        .map(|i| {
            let all = all.clone();
            thread::spawn(move || {
                let kept: Vec<Vec<u8>> = (0..64).map(|j| vec![1; 64 + (i + j) * 97]).collect();
                all.wait();
                drop(kept);
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
}

/// A sim to build, with its name for messages.
type NamedSim = (&'static str, fn() -> SimBuilder);

fn watched() -> SimBuilder {
    Sim::builder().stuck_after(Duration::from_secs(60))
}

/// The workload in a free-running sim, which installs the hooks, then unmanaged threads, then the
/// workload in a deterministic sim and a free-running one again, then in four sims at once, three
/// rounds each, all with a stuck watchdog, a thread of its own.
pub fn under_sims() {
    within(Duration::from_secs(120), || {
        let sims: [NamedSim; 3] = [
            ("free-running", watched),
            ("deterministic", || watched().deterministic()),
            ("free-running again", watched),
        ];
        for (n, (name, sim)) in sims.into_iter().enumerate() {
            if n == 1 {
                unmanaged_threads();
            }
            assert_costs_only_its_sleeps(sim().build().run(workload), name);
        }
        let parallel: Vec<_> = (0..4)
            .map(|_| {
                thread::spawn(|| {
                    for _ in 0..3 {
                        assert_costs_only_its_sleeps(watched().build().run(workload), "parallel");
                    }
                })
            })
            .collect();
        for sims in parallel {
            sims.join().unwrap();
        }
    });
}
