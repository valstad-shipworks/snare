//! Threads left over from one sim's run, woken by a later sim. A process-wide pool (rayon's global
//! registry, a `static` executor, a blocking pool in a `LazyLock`) starts its workers under the
//! first sim that touches it, and they park between jobs. The next sim to hand them a job wakes
//! them through a condition variable, a futex or a parker, and the job is that sim's: its clock,
//! its quiescence and its schedule. A wait in a deterministic sim that a thread outside its
//! schedule ends (another sim's, or one no sim manages) must end there too, however busy the
//! schedule keeps itself.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use snare::Sim;
use snare::sched::{SimId, current_sim};

type Job = Box<dyn FnOnce() + Send>;

fn sim(deterministic: bool) -> Sim {
    let builder = Sim::builder().stuck_after(Duration::from_secs(10));
    if deterministic {
        builder.deterministic().build()
    } else {
        builder.build()
    }
}

/// A worker started in a sim of its own, taking jobs from a channel.
fn leftover_worker() -> Sender<Job> {
    sim(false).run(|| {
        let (jobs, queue) = mpsc::channel::<Job>();
        std::thread::spawn(move || {
            for job in queue {
                job();
            }
        });
        jobs
    })
}

/// Runs `job` on the worker behind `jobs` and waits for what it sends back.
fn on_worker<T: Send + 'static>(jobs: &Sender<Job>, job: impl FnOnce() -> T + Send + 'static) -> T {
    let (done, result) = mpsc::channel();
    jobs.send(Box::new(move || done.send(job()).unwrap()))
        .unwrap();
    result.recv().unwrap()
}

/// `elapsed` is the `ms` milliseconds a sleep took on the sim's clock, landing just past them as a
/// time skip does.
fn assert_just_past(elapsed: Duration, ms: u64) {
    let at = Duration::from_millis(ms);
    assert!(
        elapsed > at && elapsed < at + Duration::from_millis(1),
        "{elapsed:?} for a {ms} ms sleep"
    );
}

fn sleep_and_name() -> Option<SimId> {
    std::thread::sleep(Duration::from_millis(50));
    current_sim()
}

/// Spins on the CPU for `real` of real time, making no hooked call but the clock reads.
fn compute(real: Duration) {
    let start = snare::real(Instant::now);
    let mut x = 0u64;
    while snare::real(|| start.elapsed()) < real {
        for i in 0..10_000u64 {
            x = std::hint::black_box(x.wrapping_mul(31).wrapping_add(i));
        }
    }
}

#[test]
fn a_leftover_worker_runs_a_later_sims_job_on_its_clock() {
    for deterministic in [false, true] {
        let jobs = leftover_worker();
        let later = sim(deterministic);
        let (elapsed, ran_in) = later.run(|| {
            let start = Instant::now();
            let ran_in = on_worker(&jobs, sleep_and_name);
            (start.elapsed(), ran_in)
        });
        assert_eq!(ran_in, Some(later.id()), "deterministic: {deterministic}");
        assert_just_past(elapsed, 50);
    }
}

#[test]
fn a_leftover_worker_signalling_a_condvar_is_waited_for() {
    for deterministic in [false, true] {
        let jobs = leftover_worker();
        let later = sim(deterministic);
        let (elapsed, ran_in) = later.run(|| {
            let start = Instant::now();
            let slot = Arc::new((Mutex::new(None), Condvar::new()));
            let filled = slot.clone();
            jobs.send(Box::new(move || {
                let ran_in = sleep_and_name();
                *filled.0.lock().unwrap() = Some(ran_in);
                filled.1.notify_one();
            }))
            .unwrap();
            let mut ran_in = slot.0.lock().unwrap();
            while ran_in.is_none() {
                ran_in = slot.1.wait(ran_in).unwrap();
            }
            (start.elapsed(), ran_in.unwrap())
        });
        assert_eq!(ran_in, Some(later.id()), "deterministic: {deterministic}");
        assert_just_past(elapsed, 50);
    }
}

#[test]
fn time_waits_while_a_leftover_worker_computes_for_the_sim() {
    for deterministic in [false, true] {
        let jobs = leftover_worker();
        let answer = sim(deterministic).run(|| {
            let (done, result) = mpsc::channel();
            jobs.send(Box::new(move || {
                compute(Duration::from_millis(200));
                let _ = done.send(());
            }))
            .unwrap();
            result.recv_timeout(Duration::from_secs(5))
        });
        assert_eq!(answer, Ok(()), "deterministic: {deterministic}");
    }
}

/// A pool whose workers share one queue under one lock and one condition variable, so a job
/// wakes one of several waiters, and spin a while before they park, as rayon's do.
struct Pool {
    queue: Mutex<VecDeque<Job>>,
    ready: Condvar,
}

impl Pool {
    fn start(workers: usize) -> Arc<Pool> {
        let pool = Arc::new(Pool {
            queue: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
        });
        for _ in 0..workers {
            let pool = pool.clone();
            std::thread::spawn(move || pool.work());
        }
        pool
    }

    fn work(&self) {
        loop {
            let mut spins = 0;
            let job = loop {
                if let Some(job) = self.queue.lock().unwrap().pop_front() {
                    break job;
                }
                if spins < 32 {
                    spins += 1;
                    std::thread::yield_now();
                    continue;
                }
                let mut queue = self.queue.lock().unwrap();
                while queue.is_empty() {
                    queue = self.ready.wait(queue).unwrap();
                }
                break queue.pop_front().unwrap();
            };
            job();
        }
    }

    fn run<T: Send + 'static>(&self, job: impl FnOnce() -> T + Send + 'static) -> Receiver<T> {
        let (done, result) = mpsc::channel();
        self.queue
            .lock()
            .unwrap()
            .push_back(Box::new(move || done.send(job()).unwrap()));
        self.ready.notify_one();
        result
    }
}

#[test]
fn a_pool_started_by_one_sim_serves_each_later_one_in_its_world() {
    let pool = sim(false).run(|| Pool::start(3));
    for deterministic in [false, true, false, true] {
        let later = sim(deterministic);
        let (elapsed, ran_in) = later.run(|| {
            let start = Instant::now();
            let ran_in = pool.run(sleep_and_name).recv().unwrap();
            (start.elapsed(), ran_in)
        });
        assert_eq!(ran_in, Some(later.id()), "deterministic: {deterministic}");
        assert_just_past(elapsed, 50);
    }
}

#[test]
fn workers_sharing_a_locked_receiver_serve_each_later_sim() {
    let queue = sim(false).run(|| {
        let (jobs, queue) = mpsc::channel::<Job>();
        let queue = Arc::new(Mutex::new(queue));
        for _ in 0..2 {
            let queue = queue.clone();
            std::thread::spawn(move || {
                loop {
                    let job = queue.lock().unwrap().recv();
                    match job {
                        Ok(job) => job(),
                        Err(_) => return,
                    }
                }
            });
        }
        jobs
    });
    for deterministic in [false, true, false, true] {
        let later = sim(deterministic);
        let (elapsed, ran_in) = later.run(|| {
            let start = Instant::now();
            let ran_in = on_worker(&queue, sleep_and_name);
            (start.elapsed(), ran_in)
        });
        assert_eq!(ran_in, Some(later.id()), "deterministic: {deterministic}");
        assert_just_past(elapsed, 50);
    }
}

#[test]
fn leftover_workers_follow_a_deterministic_sim_the_same_way_each_run() {
    let trace = || {
        let pool = sim(false).run(|| Pool::start(2));
        let jobs = leftover_worker();
        sim(true).run(|| {
            let start = Instant::now();
            let from_pool = pool.run(move || {
                std::thread::sleep(Duration::from_millis(30));
                start.elapsed()
            });
            let from_worker = on_worker(&jobs, move || {
                std::thread::sleep(Duration::from_millis(20));
                start.elapsed()
            });
            (from_worker, from_pool.recv().unwrap(), start.elapsed())
        })
    };
    let first = trace();
    assert_just_past(first.0, 20);
    assert_just_past(first.1, 30);
    assert_just_past(first.2, 30);
    assert_eq!(trace(), first);
}

/// A thread no sim manages, waking a deterministic sim's waiter after `after` of real time
/// through `wake`.
fn wake_from_outside(after: Duration, wake: impl FnOnce() + Send + 'static) {
    snare::real(|| {
        std::thread::spawn(move || {
            std::thread::sleep(after);
            wake();
        })
    });
}

/// A deterministic sim whose ticker sleeps 1 ms at a time, so the schedule never idles, while
/// its main thread waits on `wait`; returns how many ticks the ticker made before it was stopped.
fn waited_beside_a_ticker(wait: impl FnOnce()) -> usize {
    const MOST: usize = 1_000_000;
    sim(true).run(|| {
        let stop = Arc::new(AtomicBool::new(false));
        let ticks = Arc::new(AtomicUsize::new(0));
        let ticker = {
            let (stop, ticks) = (stop.clone(), ticks.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) && ticks.load(Ordering::SeqCst) < MOST {
                    std::thread::sleep(Duration::from_millis(1));
                    ticks.fetch_add(1, Ordering::SeqCst);
                }
            })
        };
        wait();
        stop.store(true, Ordering::SeqCst);
        ticker.join().unwrap();
        let ticks = ticks.load(Ordering::SeqCst);
        assert!(ticks < MOST, "the wait ended only once the ticker stopped");
        ticks
    })
}

#[test]
fn a_condvar_signal_from_outside_reaches_a_busy_deterministic_schedule() {
    let slot = Arc::new((Mutex::new(false), Condvar::new()));
    let signal = slot.clone();
    let ticks = waited_beside_a_ticker(move || {
        wake_from_outside(Duration::from_millis(50), move || {
            *signal.0.lock().unwrap() = true;
            signal.1.notify_one();
        });
        let mut set = slot.0.lock().unwrap();
        while !*set {
            set = slot.1.wait(set).unwrap();
        }
    });
    assert!(ticks > 0);
}

#[test]
fn an_unpark_from_outside_reaches_a_busy_deterministic_schedule() {
    let woken = Arc::new(AtomicBool::new(false));
    let set = woken.clone();
    let ticks = waited_beside_a_ticker(move || {
        let main = std::thread::current();
        wake_from_outside(Duration::from_millis(50), move || {
            set.store(true, Ordering::SeqCst);
            main.unpark();
        });
        while !woken.load(Ordering::SeqCst) {
            std::thread::park();
        }
    });
    assert!(ticks > 0);
}
