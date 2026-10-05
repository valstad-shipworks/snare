//! std mutexes contended across many sims at once, while sims end around them: a thread of one
//! sim waits on a lock a thread of another holds, a run's root leaves its sim still holding a lock
//! its own threads wait on, and those waiters outlive the run. Every lock is eventually taken and
//! every thread finishes; none is left blocked on a mutex no thread holds.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use snare::Sim;

/// A lock in static data (on Linux, futex waits on it take the static-image path).
static STATIC_LOCK: Mutex<u64> = Mutex::new(0);

/// Runs `f` on its own thread and fails the test if it takes longer than `limit`: a lost wakeup
/// would otherwise hang the test.
fn within<R: Send + 'static>(
    limit: Duration,
    what: &str,
    f: impl FnOnce() -> R + Send + 'static,
) -> R {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(limit) {
        Ok(r) => r,
        Err(_) => panic!("{what} did not finish within {limit:?}"),
    }
}

/// Takes `lock` `n` times, sometimes yielding while holding it. No sim wait while holding a lock
/// shared with other sims: virtual time in one sim waits on every lock its threads wait for, so
/// a sleep under a lock another sim also takes would tie the two sims' clocks together.
fn contend(lock: &Mutex<u64>, n: u64) {
    for i in 0..n {
        let mut held = lock.lock().unwrap();
        *held += 1;
        if i % 3 == 0 {
            std::thread::yield_now();
        }
        drop(held);
        if i % 5 == 0 {
            std::thread::yield_now();
        }
    }
}

/// Takes the sim's own `lock` `n` times, sleeping in virtual time while holding it.
fn contend_sleeping(lock: &Mutex<u64>, n: u64) {
    for _ in 0..n {
        let mut held = lock.lock().unwrap();
        *held += 1;
        std::thread::sleep(Duration::from_micros(100));
        drop(held);
    }
}

/// How many times each worker takes each lock.
const ROUNDS: u64 = 40;

/// One sim: three workers contend the static lock, the shared heap lock and a lock of the sim's
/// own; the root takes the static lock and leaves the run still holding it, so the workers that
/// wait for it outlive the run, and the heap lock is held by the calling thread from before the
/// run until after it. Returns once every worker has finished.
fn one_sim(heap: &Arc<Mutex<u64>>, deterministic: bool, total: &AtomicU64) {
    let sim = if deterministic {
        Sim::builder().deterministic().build()
    } else {
        Sim::new()
    };
    let heap_held = heap.lock().unwrap();
    let local = Arc::new(Mutex::new(0u64));
    let (workers, static_held) = sim.run(|| {
        let workers: Vec<_> = (0..3)
            .map(|_| {
                let (heap, local) = (heap.clone(), local.clone());
                std::thread::spawn(move || {
                    contend_sleeping(&local, ROUNDS / 4);
                    contend(&STATIC_LOCK, ROUNDS);
                    contend(&heap, ROUNDS);
                })
            })
            .collect::<Vec<_>>();
        std::thread::yield_now();
        (workers, STATIC_LOCK.lock().unwrap())
    });
    std::thread::sleep(Duration::from_millis(1));
    drop(static_held);
    drop(heap_held);
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(*local.lock().unwrap(), 3 * (ROUNDS / 4));
    total.fetch_add(3 * ROUNDS, Ordering::Relaxed);
}

#[test]
fn mutexes_contended_across_ending_sims_are_always_taken() {
    let heap = Arc::new(Mutex::new(0u64));
    let total = Arc::new(AtomicU64::new(0));
    let (h, t) = (heap.clone(), total.clone());
    within(Duration::from_secs(240), "200 contending sims", move || {
        let lanes: Vec<_> = (0..8)
            .map(|lane| {
                let (heap, total) = (h.clone(), t.clone());
                std::thread::spawn(move || {
                    for round in 0..25 {
                        one_sim(&heap, (lane + round) % 4 == 0, &total);
                    }
                })
            })
            .collect();
        for lane in lanes {
            lane.join().unwrap();
        }
    });
    assert_eq!(*heap.lock().unwrap(), total.load(Ordering::Relaxed));
    assert!(*STATIC_LOCK.lock().unwrap() >= total.load(Ordering::Relaxed));
}

/// A participant waits on a lock a thread outside the sim holds while its run ends and the sim is
/// dropped; once the lock is let go it takes it and finishes.
#[test]
fn a_waiter_whose_sim_ends_takes_the_lock_once_it_is_free() {
    within(Duration::from_secs(60), "the orphaned waiters", || {
        for _ in 0..50 {
            let lock = Arc::new(Mutex::new(0u64));
            let held = lock.lock().unwrap();
            let sim = Sim::new();
            let waiter = sim.run(|| {
                let lock = lock.clone();
                std::thread::spawn(move || *lock.lock().unwrap() += 1)
            });
            drop(sim);
            std::thread::sleep(Duration::from_millis(1));
            drop(held);
            waiter.join().unwrap();
            assert_eq!(*lock.lock().unwrap(), 1);
        }
    });
}

/// Under a deterministic schedule a participant takes a lock, another waits for it in the
/// schedule, and the holder leaves the schedule (marking itself background) before it lets go,
/// while the root keeps yielding so the schedule never goes idle: the waiter still gets the lock.
#[test]
fn a_holder_leaving_the_schedule_still_releases_its_waiters() {
    within(Duration::from_secs(60), "the waiter", || {
        for _ in 0..20 {
            Sim::builder().deterministic().build().run(|| {
                let lock = Arc::new(Mutex::new(0u64));
                let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let (taken_tx, taken) = mpsc::channel();
                let holder = {
                    let lock = lock.clone();
                    std::thread::spawn(move || {
                        let held = lock.lock().unwrap();
                        taken_tx.send(()).unwrap();
                        for _ in 0..4 {
                            std::thread::yield_now();
                        }
                        snare::sched::mark_background("holder");
                        drop(held);
                    })
                };
                taken.recv().unwrap();
                let waiter = {
                    let (lock, done) = (lock.clone(), done.clone());
                    std::thread::spawn(move || {
                        *lock.lock().unwrap() += 1;
                        done.store(true, Ordering::SeqCst);
                    })
                };
                while !done.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
                holder.join().unwrap();
                waiter.join().unwrap();
                assert_eq!(*lock.lock().unwrap(), 1);
            });
        }
    });
}
