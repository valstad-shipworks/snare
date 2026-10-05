//! The virtual clock as std sees it. `std::time::Instant` and `std::time::SystemTime` read the
//! kernel through the same `clock_gettime`/`gettimeofday` (and, on Darwin, `mach_absolute_time`)
//! symbols the sim interposes, so safe Rust time code observes the deterministic virtual clock
//! with no `libc` in the test. man 2 clock_gettime: CLOCK_REALTIME counts from the Unix epoch,
//! CLOCK_MONOTONIC from an unspecified origin that never goes backwards.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use snare::Sim;

const VIRTUAL_EPOCH_SECS: u64 = 1_700_000_000;

/// A sim with a `SimHost` where there is one; on Windows, whose `SystemTime` and `Instant` read
/// `GetSystemTimePreciseAsFileTime` and `QueryPerformanceCounter`
/// ([Microsoft Learn: Acquiring high-resolution time stamps](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps)),
/// the plain sim on the same virtual clock.
fn sim() -> Sim {
    #[cfg(unix)]
    return Sim::builder()
        .host(snare::HostProfile::new().build())
        .build();
    #[cfg(windows)]
    return Sim::new();
}

#[test]
fn system_time_sits_at_the_fixed_virtual_epoch() {
    sim().run(|| {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("virtual realtime is after the Unix epoch");
        assert_eq!(
            since_epoch.as_secs(),
            VIRTUAL_EPOCH_SECS,
            "SystemTime reads the fixed virtual realtime epoch, not the wall clock"
        );
    });
}

#[test]
fn system_time_never_moves_backwards() {
    sim().run(|| {
        let a = SystemTime::now();
        let b = SystemTime::now();
        assert!(
            b >= a,
            "each realtime read advances the shared virtual clock"
        );
    });
}

#[test]
fn instant_elapsed_reflects_a_virtual_sleep() {
    sim().run(|| {
        let start = Instant::now();
        // A two-second sleep returns immediately: the clock layer carries it virtually. Were it a
        // real sleep the test would still pass but cost two wall-clock seconds.
        std::thread::sleep(Duration::from_secs(2));
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_secs(2),
            "virtual monotonic time advanced by at least the slept duration, got {elapsed:?}"
        );
    });
}

#[test]
fn instant_is_monotonic_across_reads() {
    sim().run(|| {
        let first = Instant::now();
        let second = Instant::now();
        assert!(second >= first, "Instant never regresses");
        std::thread::sleep(Duration::from_millis(1));
        assert!(
            first.elapsed() >= Duration::from_millis(1),
            "a sleep advances the clock"
        );
    });
}

#[test]
fn many_short_sleeps_accumulate_virtually() {
    sim().run(|| {
        let start = Instant::now();
        for _ in 0..1000 {
            std::thread::sleep(Duration::from_millis(10));
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_secs(10),
            "1000 x 10ms virtual sleeps sum to >= 10s, got {elapsed:?}"
        );
    });
}

#[test]
fn a_run_completes_despite_an_enormous_sleep() {
    sim().run(|| {
        // A full day. AFAP means this returns at once instead of blocking the test harness.
        std::thread::sleep(Duration::from_secs(86_400));
    });
}
