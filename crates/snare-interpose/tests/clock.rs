use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use snare_interpose::{ClockKind, Domain, Flow, Layer, SleepRequest};

const MONOTONIC_ORIGIN: Duration = Duration::from_secs(1_000);
const REALTIME_ORIGIN: Duration = Duration::from_secs(1_893_456_000);

/// A clock that only moves when a managed thread sleeps.
#[derive(Default)]
struct SteppedClock {
    elapsed: Mutex<Duration>,
}

impl SteppedClock {
    fn elapsed(&self) -> Duration {
        *self.elapsed.lock().unwrap()
    }
}

impl Layer for SteppedClock {
    fn now(&self, clock: ClockKind) -> Flow<Duration> {
        let origin = match clock {
            ClockKind::Monotonic => MONOTONIC_ORIGIN,
            ClockKind::Realtime | ClockKind::Tai => REALTIME_ORIGIN,
        };
        Flow::Done(origin + self.elapsed())
    }

    fn sleep(&self, request: SleepRequest) -> Flow<()> {
        let mut elapsed = self.elapsed.lock().unwrap();
        match request {
            SleepRequest::For(d) => *elapsed += d,
            SleepRequest::Until(ClockKind::Monotonic, t) => {
                *elapsed = (*elapsed).max(t - MONOTONIC_ORIGIN)
            }
            SleepRequest::Until(ClockKind::Realtime, t)
            | SleepRequest::Until(ClockKind::Tai, t) => {
                *elapsed = (*elapsed).max(t - REALTIME_ORIGIN)
            }
        }
        Flow::Done(())
    }
}

fn stepped() -> (Arc<SteppedClock>, Domain) {
    let clock = Arc::new(SteppedClock::default());
    let domain = Domain::new([clock.clone() as Arc<dyn Layer>]);
    (clock, domain)
}

#[test]
fn install_patches_the_test_binary() {
    let report = snare_interpose::install();
    let expected = if cfg!(windows) {
        ["QueryPerformanceCounter", "Sleep", "CreateThread"]
    } else if cfg!(target_os = "linux") {
        ["clock_gettime", "clock_nanosleep", "pthread_create"]
    } else {
        ["clock_gettime", "nanosleep", "pthread_create"]
    };
    for symbol in expected {
        assert!(report.patched(symbol), "{symbol} not patched: {report:#?}");
    }
}

#[test]
fn std_sleep_and_instant_follow_the_layer() {
    let (clock, domain) = stepped();
    let wall = Instant::now();
    domain.run(|| {
        let start = Instant::now();
        std::thread::sleep(Duration::from_secs(3_600));
        assert_eq!(start.elapsed(), Duration::from_secs(3_600));
    });
    assert_eq!(clock.elapsed(), Duration::from_secs(3_600));
    assert!(wall.elapsed() < Duration::from_secs(5));
}

#[test]
fn system_time_follows_the_layer() {
    let (_clock, domain) = stepped();
    let now = domain.run(SystemTime::now);
    assert_eq!(now.duration_since(UNIX_EPOCH).unwrap(), REALTIME_ORIGIN);
}

#[test]
fn threads_outside_a_domain_see_the_os() {
    let (_clock, _domain) = stepped();
    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    assert!(since_epoch < REALTIME_ORIGIN);
    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(20));
    assert!(start.elapsed() >= Duration::from_millis(20));
}

#[test]
fn spawned_threads_inherit_the_domain() {
    let (clock, domain) = stepped();
    let child_elapsed = domain.run(|| {
        std::thread::spawn(|| {
            let start = Instant::now();
            std::thread::sleep(Duration::from_secs(60));
            (start.elapsed(), Domain::current().is_some())
        })
        .join()
        .unwrap()
    });
    assert_eq!(child_elapsed, (Duration::from_secs(60), true));
    assert_eq!(clock.elapsed(), Duration::from_secs(60));
}

#[test]
fn real_escapes_the_domain() {
    let (_clock, domain) = stepped();
    domain.run(|| {
        let since_epoch = snare_interpose::real(SystemTime::now)
            .duration_since(UNIX_EPOCH)
            .unwrap();
        assert!(since_epoch < REALTIME_ORIGIN);
    });
}

/// Observes calls and passes them on, reading the clock itself from inside the layer.
#[derive(Default)]
struct Counting {
    calls: AtomicUsize,
}

impl Layer for Counting {
    fn now(&self, _clock: ClockKind) -> Flow<Duration> {
        let _ = Instant::now();
        self.calls.fetch_add(1, Ordering::Relaxed);
        Flow::Pass
    }
}

#[test]
fn passing_layers_see_calls_without_reentry() {
    let counting = Arc::new(Counting::default());
    let domain = Domain::new([counting.clone() as Arc<dyn Layer>]);
    let before = SystemTime::now();
    let during = domain.run(SystemTime::now);
    assert!(during >= before);
    assert_eq!(counting.calls.load(Ordering::Relaxed), 1);
}

#[cfg(target_os = "macos")]
#[test]
fn direct_libsystem_calls_are_redirected() {
    unsafe extern "C" {
        fn mach_absolute_time() -> u64;
        fn clock_gettime_nsec_np(clock: libc::clockid_t) -> u64;
    }
    let (_clock, domain) = stepped();
    let (ticks, nanos) = domain.run(|| {
        // SAFETY: plain libSystem clock reads.
        unsafe {
            (
                mach_absolute_time(),
                clock_gettime_nsec_np(libc::CLOCK_UPTIME_RAW),
            )
        }
    });
    assert_eq!(nanos, MONOTONIC_ORIGIN.as_nanos() as u64);
    // SAFETY: as above, outside the domain.
    let real_ticks = unsafe { mach_absolute_time() };
    assert!(ticks > 0 && ticks != real_ticks);
}

#[test]
fn public_now_reads_the_virtual_clock() {
    let (_clock, domain) = stepped();
    assert_eq!(snare_interpose::now(ClockKind::Monotonic), None); // off a domain
    let (mono, real) = domain.run(|| {
        // Works even under passthrough, as a backend would call it.
        snare_interpose::real(|| {
            (
                snare_interpose::now(ClockKind::Monotonic),
                snare_interpose::now(ClockKind::Realtime),
            )
        })
    });
    assert_eq!(mono, Some(MONOTONIC_ORIGIN));
    assert_eq!(real, Some(REALTIME_ORIGIN));
}
