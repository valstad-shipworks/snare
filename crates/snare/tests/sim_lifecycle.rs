//! Threads a run leaves behind: a thread spawned inside `Sim::run` that is still alive when the
//! run returns keeps running in the sim, but nothing waits on it any more. Its sleeps and timed
//! waits pass in real time instead of racing the clock ahead, a wait with nothing left to wait for
//! blocks instead of giving up, the next run takes it back into virtual time, and the stuck-run
//! watchdog leaves it alone — whether the `Sim` is still alive or already dropped.
#![cfg(unix)]

use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use snare::{EasyBuilder, Sim};

/// The calling thread's CPU time, from the OS even inside a sim.
fn thread_cpu() -> Duration {
    snare::real(|| {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid out-pointer for the call.
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
        Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
    })
}

/// Real time, also inside a sim.
fn real_now() -> Instant {
    snare::real(Instant::now)
}

/// A thread sleeping on a fixed grid until told to stop, publishing its laps and its own CPU time.
struct Sleeper {
    stop: Arc<AtomicBool>,
    laps: Arc<AtomicU64>,
    cpu_ns: Arc<AtomicU64>,
    handle: JoinHandle<()>,
}

impl Sleeper {
    /// Starts the sleeper on the calling thread's sim, sleeping to each multiple of `period`.
    fn spawn(period: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let laps = Arc::new(AtomicU64::new(0));
        let cpu_ns = Arc::new(AtomicU64::new(0));
        let (s, l, c) = (stop.clone(), laps.clone(), cpu_ns.clone());
        let handle = std::thread::spawn(move || {
            let mut next = Instant::now();
            while !s.load(Ordering::Relaxed) {
                next += period;
                std::thread::sleep(next.saturating_duration_since(Instant::now()));
                l.fetch_add(1, Ordering::Relaxed);
                c.store(thread_cpu().as_nanos() as u64, Ordering::Relaxed);
            }
        });
        Sleeper {
            stop,
            laps,
            cpu_ns,
            handle,
        }
    }

    /// Its laps and CPU time so far.
    fn sample(&self) -> (u64, Duration) {
        (
            self.laps.load(Ordering::Relaxed),
            Duration::from_nanos(self.cpu_ns.load(Ordering::Relaxed)),
        )
    }

    /// Asks it to stop and joins it, from any thread.
    fn finish(self) {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.join().unwrap();
    }
}

/// Watches a left-over 5 ms sleeper for 400 ms of real time: it keeps lapping at about real time's
/// pace, using a small share of a CPU.
fn assert_sleeps_in_real_time(sleeper: &Sleeper, what: &str) {
    std::thread::sleep(Duration::from_millis(50));
    let (laps0, cpu0) = sleeper.sample();
    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(400));
    let (laps1, cpu1) = sleeper.sample();
    let wall = start.elapsed();
    let laps = laps1 - laps0;
    let cpu = cpu1.saturating_sub(cpu0);
    assert!(
        cpu < wall / 4,
        "{what}: the left-over sleeper used {cpu:?} of CPU in {wall:?}"
    );
    let most = wall.as_millis() as u64 / 5 + 20;
    assert!(
        (5..=most).contains(&laps),
        "{what}: {laps} laps of 5 ms in {wall:?}"
    );
}

/// The sims the lifecycle is checked on: the default discrete clock, a deterministic schedule,
/// and an as-fast-as-possible host clock.
fn sims() -> Vec<(&'static str, Sim)> {
    vec![
        ("discrete", Sim::new()),
        ("deterministic", Sim::builder().deterministic().build()),
        (
            "as-fast-as-possible",
            Sim::builder()
                .host(EasyBuilder::minimal().build())
                .wall_clock()
                .build(),
        ),
    ]
}

#[test]
fn a_thread_left_over_from_a_run_sleeps_in_real_time() {
    for (what, sim) in sims() {
        let sleeper = sim.run(|| Sleeper::spawn(Duration::from_millis(5)));
        let before = sim.time_value();
        let start = Instant::now();
        assert_sleeps_in_real_time(&sleeper, what);
        let moved = sim.time_value().saturating_sub(before);
        assert!(
            moved <= start.elapsed() + Duration::from_millis(20),
            "{what}: the clock moved {moved:?} in {:?}",
            start.elapsed()
        );
        sleeper.finish();
    }
}

#[test]
fn threads_outliving_a_dropped_sim_still_sleep_in_real_time() {
    for (what, sim) in sims() {
        let sleeper = sim.run(|| Sleeper::spawn(Duration::from_millis(5)));
        drop(sim);
        assert_sleeps_in_real_time(&sleeper, what);
        sleeper.finish();
    }
}

#[test]
fn the_next_run_takes_its_leftovers_back_into_virtual_time() {
    let sim = Sim::new();
    let sleeper = sim.run(|| Sleeper::spawn(Duration::from_millis(5)));
    std::thread::sleep(Duration::from_millis(30));
    let between = sim.time_value();
    let (virtual_elapsed, real_elapsed) = sim.run(|| {
        let (t0, r0) = (Instant::now(), real_now());
        std::thread::sleep(Duration::from_secs(10));
        (t0.elapsed(), real_now() - r0)
    });
    assert!(virtual_elapsed >= Duration::from_secs(10));
    assert!(
        real_elapsed < Duration::from_secs(2),
        "10 s of virtual sleep took {real_elapsed:?} beside a left-over sleeper"
    );
    assert!(sim.time_value() >= between + Duration::from_secs(10));
    let (laps, _) = sleeper.sample();
    assert!(laps >= 2000, "the left-over sleeper ran {laps} laps");
    assert_sleeps_in_real_time(&sleeper, "after the second run");
    sleeper.finish();
}

#[test]
fn a_left_over_wait_with_nothing_to_wait_for_blocks_until_the_next_run() {
    let sim = Sim::new();
    let (tx, rx) = mpsc::channel();
    let addr = sim.run(|| {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 16];
            let got = socket.recv_from(&mut buf).map(|(n, _)| buf[..n].to_vec());
            tx.send(got.map_err(|e| e.kind())).unwrap();
        });
        addr
    });
    assert_eq!(
        rx.recv_timeout(Duration::from_millis(500)),
        Err(mpsc::RecvTimeoutError::Timeout),
        "a left-over receive with no sender gave up"
    );
    sim.run(|| {
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .send_to(b"late", addr)
            .unwrap();
    });
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        Ok(b"late".to_vec())
    );
}

#[test]
fn stuck_after_leaves_threads_left_over_from_a_run_alone() {
    let sim = Sim::builder()
        .stuck_after(Duration::from_millis(50))
        .build();
    let stop = Arc::new(AtomicBool::new(false));
    let spinner = sim.run(|| {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                std::hint::spin_loop();
            }
        })
    });
    std::thread::sleep(Duration::from_millis(400));
    stop.store(true, Ordering::Relaxed);
    spinner.join().unwrap();
}
