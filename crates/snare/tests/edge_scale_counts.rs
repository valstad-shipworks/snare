//! Performance invariants measured by counts rather than wall time, so they hold on a loaded
//! machine: how many time skips a run takes and how many timers each fires, how much virtual time
//! each kind of call is charged at a hundred thousand calls, how many wakes the executive counts
//! as coming from outside the sim, and how often a waiter that has nothing to do is woken.
//! Counted through public API only: an `Executive` (its `jump_to`s and `outside_wakes`), the sim's
//! clock, and on Linux the kernel's per-thread context-switch count.
//!
//! The executive's quiescence epoch is not used: it also moves with the real time a step takes
//! (waits that re-check on real-time slices), so between two jumps it varies run to run (3 to 67
//! for one sleep, measured on macOS) and is no count to budget.
//!
//! Tests named `perf_budget_*` pin today's cost as an upper bound with a little slack, documented
//! at each constant, so the performance pass can lower them as it improves things; the others are
//! exact semantics a faster implementation must keep. A target the pass should reach but today's
//! code misses is ignored with a `perf target:` reason.

#![cfg(unix)]

use std::net::UdpSocket;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use snare::Sim;
use snare::sched::{Executive, ExecutiveConfig, Quiescence};

const MS: Duration = Duration::from_millis(1);
const US: Duration = Duration::from_micros(1);
const NS: Duration = Duration::from_nanos(1);

fn real_now() -> Instant {
    snare::real(Instant::now)
}

/// Waits until every participant of the executive's sim is blocked, or the run has ended.
fn settle(exec: &Executive, done: &std::sync::atomic::AtomicBool) -> Option<Quiescence> {
    let start = real_now();
    loop {
        let q = exec.quiescence();
        if q.quiescent && q.blocked > 0 {
            return Some(q);
        }
        if done.load(std::sync::atomic::Ordering::SeqCst) {
            return None;
        }
        let elapsed = snare::real(|| start.elapsed());
        if elapsed >= Duration::from_secs(60) {
            report_stall(exec, &q);
        }
        assert!(
            elapsed < Duration::from_secs(60),
            "the sim never settled: {q:?}"
        );
        snare::real(|| std::thread::sleep(Duration::from_micros(100)));
    }
}

fn report_stall(exec: &Executive, quiescence: &Quiescence) {
    snare::real(|| {
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr(),
            "executive stalled: {quiescence:?}; {:?}",
            exec.participants()
        );
    });
}

/// What an executive saw driving a run to its end, one time skip at a time.
#[derive(Debug, Default)]
struct Driven {
    /// The deadline of each `jump_to`, in order.
    jumps: Vec<Duration>,
    /// Timers each jump fired.
    fired: Vec<u32>,
    outside_wakes: u64,
}

/// Runs `body` in `sim` while an executive jumps the clock to each next deadline once the sim is
/// quiescent.
fn drive(sim: &Sim, body: impl FnOnce() + Send) -> Driven {
    let exec = sim.executive(ExecutiveConfig::default()).unwrap();
    let done = std::sync::atomic::AtomicBool::new(false);
    let mut driven = Driven::default();
    std::thread::scope(|s| {
        let run = s.spawn(|| {
            sim.run(body);
            done.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            while let Some(q) = settle(&exec, &done) {
                let Some(next) = q.next_deadline else {
                    report_stall(&exec, &q);
                    panic!("blocked with no deadline: {q:?}; {:?}", exec.participants());
                };
                match exec.jump_to(next) {
                    Ok(fired) => {
                        driven.jumps.push(next);
                        driven.fired.push(fired);
                    }
                    Err(_) => continue,
                }
            }
        }));
        if let Err(panic) = result {
            exec.detach();
            let _ = run.join();
            std::panic::resume_unwind(panic);
        }
        run.join().unwrap();
        driven.outside_wakes = exec.outside_wakes();
    });
    driven
}

#[test]
fn n_sequential_sleeps_take_exactly_n_time_skips() {
    const N: u32 = 1_000;
    let sim = Sim::new();
    let driven = drive(&sim, || {
        for _ in 0..N {
            std::thread::sleep(MS);
        }
    });
    assert_eq!(driven.jumps.len(), N as usize, "one skip per sleep");
    assert!(driven.fired.iter().all(|&f| f == 1), "{:?}", driven.fired);
    assert!(
        driven
            .jumps
            .iter()
            .enumerate()
            .all(|(k, &at)| at == (k as u32 + 1) * MS),
        "each skip lands on the next sleep's deadline: {:?}",
        &driven.jumps[..5]
    );
    assert_eq!(driven.outside_wakes, 0);
}

#[test]
fn n_sequential_sleeps_move_the_free_clock_by_exactly_n_deadlines() {
    for sim in [Sim::new(), Sim::builder().deterministic().seed(1).build()] {
        let took = sim.run(|| {
            let start = snare::time().value();
            for _ in 0..10_000 {
                std::thread::sleep(MS);
            }
            snare::time().value() - start
        });
        assert_eq!(
            took,
            10_000 * (MS + NS),
            "each skip lands 1 ns past its deadline"
        );
    }
}

/// What `n` calls of one kind cost in virtual time, run on a fresh sim built by `sim`.
fn charged(sim: Sim, n: u32, call: impl Fn(&UdpSocket, &UdpSocket)) -> Duration {
    sim.run(|| {
        let a = UdpSocket::bind("127.0.0.1:9100").unwrap();
        let b = UdpSocket::bind("127.0.0.1:9101").unwrap();
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();
        let start = snare::time().value();
        for _ in 0..n {
            call(&a, &b);
        }
        snare::time().value() - start
    })
}

fn poll_zero(sock: &UdpSocket) {
    use std::os::fd::AsRawFd;
    let mut fds = [libc::pollfd {
        fd: sock.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }];
    // SAFETY: `fds` is a live array of one pollfd.
    unsafe { libc::poll(fds.as_mut_ptr(), 1, 0) };
}

#[test]
fn each_call_is_charged_exactly_at_scale() {
    const N: u32 = 100_000;
    let sims = || [Sim::new(), Sim::builder().deterministic().seed(2).build()];
    for sim in sims() {
        let empty = charged(sim, N, |a, _| {
            let _ = a.recv(&mut [0u8; 4]);
        });
        assert_eq!(empty, N * US, "an empty nonblocking receive costs 1 µs");
    }
    for sim in sims() {
        assert_eq!(
            charged(sim, N, |a, _| poll_zero(a)),
            N * US,
            "poll(0) costs 1 µs"
        );
    }
    for sim in sims() {
        let pair = charged(sim, N, |a, b| {
            a.send_to(b"x", "127.0.0.1:9101").unwrap();
            b.recv(&mut [0u8; 4]).unwrap();
        });
        assert_eq!(
            pair,
            Duration::ZERO,
            "a send and a receive that finds data cost nothing"
        );
    }
    for sim in sims() {
        let m = Mutex::new(0u32);
        let locks = charged(sim, N, |_, _| *m.lock().unwrap() += 1);
        assert_eq!(locks, Duration::ZERO, "an uncontended lock costs nothing");
    }
    let yields = charged(Sim::new(), N, |_, _| std::thread::yield_now());
    assert_eq!(yields, Duration::ZERO, "a yield costs nothing");
}

#[test]
fn a_condvar_ping_pong_sees_no_outside_wakes() {
    const ROUNDS: u32 = 500;
    let driven = drive(&Sim::new(), || {
        let state = Arc::new((Mutex::new(0u32), Condvar::new()));
        let other = state.clone();
        let pong = std::thread::spawn(move || {
            let (lock, cv) = &*other;
            for _ in 0..ROUNDS {
                let mut g = lock.lock().unwrap();
                while *g % 2 == 0 {
                    g = cv.wait(g).unwrap();
                }
                *g += 1;
                cv.notify_one();
            }
        });
        let (lock, cv) = &*state;
        for _ in 0..ROUNDS {
            std::thread::sleep(MS);
            let mut g = lock.lock().unwrap();
            *g += 1;
            cv.notify_one();
            while *g % 2 == 1 {
                g = cv.wait(g).unwrap();
            }
        }
        pong.join().unwrap();
    });
    assert_eq!(driven.jumps.len(), ROUNDS as usize);
    assert_eq!(driven.outside_wakes, 0);
}

#[cfg(target_os = "linux")]
mod idle_wakes {
    use super::*;

    /// The kernel's count of voluntary context switches of thread `tid` of this process.
    fn voluntary_switches(tid: i32) -> u64 {
        let status =
            snare::real(|| std::fs::read_to_string(format!("/proc/self/task/{tid}/status")))
                .unwrap();
        status
            .lines()
            .find_map(|l| l.strip_prefix("voluntary_ctxt_switches:"))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn settled_switches(tid: i32) -> u64 {
        snare::real(|| {
            let started = Instant::now();
            let mut stable = started;
            let mut previous = voluntary_switches(tid);
            loop {
                let status =
                    std::fs::read_to_string(format!("/proc/self/task/{tid}/status")).unwrap();
                let sleeping = status.lines().any(|line| {
                    line.strip_prefix("State:")
                        .is_some_and(|state| state.split_whitespace().next() == Some("S"))
                });
                let current = voluntary_switches(tid);
                if !sleeping || current != previous {
                    stable = Instant::now();
                    previous = current;
                } else if stable.elapsed() >= Duration::from_millis(5) {
                    return current;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "idle waiter did not settle"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        })
    }

    /// How many times a thread blocked in a receive on a quiet socket went to sleep again while
    /// `n` datagrams were exchanged between two other threads, with the real time the exchange
    /// took.
    fn idle_switches(n: u32) -> (u64, Duration) {
        Sim::new().run(|| {
            let quiet = UdpSocket::bind("127.0.0.1:9002").unwrap();
            let (tid_tx, tid_rx) = std::sync::mpsc::channel();
            let idler = std::thread::spawn(move || {
                // SAFETY: gettid has no preconditions.
                tid_tx.send(unsafe { libc::gettid() }).unwrap();
                quiet.recv(&mut [0u8; 4]).is_err()
            });
            let tid = tid_rx.recv().unwrap();
            let rx = UdpSocket::bind("127.0.0.1:9000").unwrap();
            let tx = UdpSocket::bind("127.0.0.1:9001").unwrap();
            let reader = std::thread::spawn(move || {
                for _ in 0..n {
                    rx.recv(&mut [0u8; 4]).unwrap();
                }
            });
            let before = settled_switches(tid);
            let start = real_now();
            for i in 0..n {
                std::thread::sleep(MS);
                tx.send_to(&i.to_be_bytes(), "127.0.0.1:9000").unwrap();
            }
            reader.join().unwrap();
            let took = snare::real(|| start.elapsed());
            let after = voluntary_switches(tid);
            snare::raise_socket_error(
                "127.0.0.1:9002",
                std::io::Error::from_raw_os_error(libc::ECONNREFUSED),
            );
            assert!(idler.join().unwrap());
            (after - before, took)
        })
    }

    /// Upper bound retained alongside the stricter isolation assertion below.
    const IDLE_WAKES_PER_DELIVERY_BUDGET: u64 = 3;

    #[test]
    fn perf_budget_idle_waiter_wakes_per_delivery() {
        const N: u32 = 500;
        let (switches, took) = idle_switches(N);
        eprintln!("idle waiter: {switches} wakes over {N} deliveries in {took:?}");
        assert!(
            switches <= IDLE_WAKES_PER_DELIVERY_BUDGET * u64::from(N),
            "{switches} wakes over {N} deliveries"
        );
    }

    #[test]
    fn an_idle_waiter_is_not_woken_by_unrelated_traffic() {
        let (switches, took) = idle_switches(500);
        eprintln!("idle waiter: {switches} wakes over 500 deliveries in {took:?}");
        // A waiter with no deadline still re-checks for quiescence every 200 ms of real time.
        let polls = (took.as_millis() / 200) as u64 + 2;
        assert!(switches <= polls, "{switches} wakes in {took:?}");
    }
}
