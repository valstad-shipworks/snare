//! Where a sim's virtual clock starts. A plain sim continues the process's time: its monotonic
//! and realtime clocks start where the furthest clock of every sim built before it had got to,
//! whether that sim still runs or not, so an `Instant` or `SystemTime` a library kept in a static
//! is never ahead of a later sim's clocks. A deterministic sim, or one built with
//! `fixed_epoch()`, starts at the fixed epoch, so its absolute readings replay. Sim time
//! (`time_value`) counts from the clock's start either way.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use snare::Sim;

/// 2023-11-14T22:13:20Z, `CLOCK_REALTIME` at monotonic zero on the fixed epoch.
const FIXED_EPOCH: Duration = Duration::from_secs(1_700_000_000);

fn now() -> (Instant, SystemTime) {
    (Instant::now(), SystemTime::now())
}

fn since_unix_epoch(t: SystemTime) -> Duration {
    t.duration_since(UNIX_EPOCH)
        .expect("virtual realtime is after the Unix epoch")
}

/// `CLOCK_MONOTONIC` and `CLOCK_REALTIME`, read back to back on a clock that holds still between
/// reads.
#[cfg(unix)]
fn raw_clocks() -> (Duration, Duration) {
    let read = |id| {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid timespec to fill.
        assert_eq!(unsafe { libc::clock_gettime(id, &mut ts) }, 0);
        Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
    };
    (read(libc::CLOCK_MONOTONIC), read(libc::CLOCK_REALTIME))
}

#[test]
fn sequential_plain_sims_never_go_back() {
    let mut last: Option<(Instant, SystemTime)> = None;
    for _ in 0..3 {
        Sim::new().run(|| {
            let (instant, system) = now();
            if let Some((was_instant, was_system)) = last {
                assert!(instant >= was_instant, "Instant went back between sims");
                assert!(system >= was_system, "SystemTime went back between sims");
            }
            std::thread::sleep(Duration::from_secs(3600));
            last = Some(now());
        });
    }
}

#[test]
fn a_sim_starts_past_one_still_running() {
    let reached = Mutex::new(None);
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            Sim::new().run(|| {
                std::thread::sleep(Duration::from_secs(7200));
                *reached.lock().unwrap() = Some(now());
                while !done.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(100));
                }
            });
        });
        let (instant, system) = loop {
            if let Some(seen) = *reached.lock().unwrap() {
                break seen;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        let (later_instant, later_system) = Sim::new().run(now);
        done.store(true, Ordering::Release);
        assert!(
            later_instant >= instant,
            "a new sim's Instant is behind one a running sim handed out"
        );
        assert!(
            later_system >= system,
            "a new sim's SystemTime is behind one a running sim handed out"
        );
    });
}

#[test]
fn deterministic_and_fixed_epoch_sims_start_at_the_epoch() {
    Sim::new().run(|| std::thread::sleep(Duration::from_secs(86_400)));
    for builder in [Sim::builder().deterministic(), Sim::builder().fixed_epoch()] {
        let sim = builder.build();
        assert_eq!(sim.time_value(), Duration::ZERO);
        sim.run(|| {
            assert_eq!(since_unix_epoch(SystemTime::now()), FIXED_EPOCH);
            #[cfg(unix)]
            assert_eq!(raw_clocks(), (Duration::ZERO, FIXED_EPOCH));
            std::thread::sleep(Duration::from_secs(5));
            let after = since_unix_epoch(SystemTime::now()) - FIXED_EPOCH;
            assert!(after >= Duration::from_secs(5) && after < Duration::from_secs(6));
        });
        let value = sim.time_value();
        assert!(value >= Duration::from_secs(5) && value < Duration::from_secs(6));
    }
}

#[test]
fn sim_time_counts_from_a_continuing_clock_start() {
    let earlier = Sim::new();
    earlier.run(|| std::thread::sleep(Duration::from_millis(1500)));
    let sim = Sim::new();
    assert_eq!(sim.time_value(), Duration::ZERO);
    let start = sim.run(SystemTime::now);
    assert!(since_unix_epoch(start) >= FIXED_EPOCH + Duration::from_millis(1500));
    assert_eq!(
        since_unix_epoch(start).subsec_nanos(),
        0,
        "a continuing clock starts on a whole second"
    );
    sim.set_time_value(Duration::from_secs(10));
    assert_eq!(sim.time_value(), Duration::from_secs(10));
    assert_eq!(
        sim.run(SystemTime::now).duration_since(start).unwrap(),
        Duration::from_secs(10)
    );
}

#[cfg(unix)]
#[test]
fn boot_time_holds_within_a_continuing_sim() {
    Sim::new().run(|| std::thread::sleep(Duration::from_secs(42)));
    let sim = Sim::new();
    let boot = sim.run(|| {
        let (monotonic, realtime) = raw_clocks();
        assert!(monotonic >= Duration::from_secs(42));
        let boot = realtime - monotonic;
        assert!(boot >= FIXED_EPOCH);
        std::thread::sleep(Duration::from_secs(3));
        let (monotonic, realtime) = raw_clocks();
        assert_eq!(realtime - monotonic, boot, "boot time moved within the sim");
        boot
    });
    sim.advance_time(Duration::from_secs(60));
    let (monotonic, realtime) = sim.run(raw_clocks);
    assert_eq!(realtime - monotonic, boot);
}

/// A runtime made in one sim and reused in the next keeps its timer wheel's elapsed time in the
/// static: a later sim's clock must not start behind it, or a short sleep there reads as already
/// past due and returns at once.
#[test]
fn a_static_tokio_runtime_sleeps_in_a_later_sim() {
    static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    });
    let sleep = |d| {
        Sim::new().run(|| {
            let start = Instant::now();
            RT.block_on(async move { tokio::time::sleep(d).await });
            start.elapsed()
        })
    };
    assert!(sleep(Duration::from_secs(3600)) >= Duration::from_secs(3600));
    let short = sleep(Duration::from_millis(10));
    assert!(
        short >= Duration::from_millis(10),
        "the second sim's 10 ms sleep returned after {short:?}"
    );
}

#[test]
fn an_executive_works_in_sim_time_on_a_continuing_clock() {
    use snare::sched::{self, ExecutiveConfig};
    Sim::new().run(|| std::thread::sleep(Duration::from_secs(1000)));
    let sim = Sim::new();
    sim.run(|| {
        let start = SystemTime::now();
        let exec = sched::attach(ExecutiveConfig::default()).unwrap();
        assert_eq!(exec.now(), Duration::ZERO);
        exec.enter_timestamp(Duration::from_secs(3));
        assert_eq!(
            SystemTime::now().duration_since(start).unwrap(),
            Duration::from_secs(3)
        );
        assert_eq!(sched::now(), Duration::from_secs(3));
        assert_eq!(exec.leave_timestamp(Duration::from_secs(3)), 0);
        assert_eq!(exec.now(), Duration::from_secs(3));
    });
    assert_eq!(sim.time_value(), Duration::from_secs(3));
}
