#![cfg(unix)]

//! The virtual clock as std sees it. `std::time::Instant` and `std::time::SystemTime` read the
//! kernel through the same `clock_gettime`/`gettimeofday` (and, on Darwin, `mach_absolute_time`)
//! symbols the sim interposes, so safe Rust time code observes the deterministic virtual clock
//! with no `libc` in the test. man 2 clock_gettime: CLOCK_REALTIME counts from the Unix epoch,
//! CLOCK_MONOTONIC from an unspecified origin that never goes backwards.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use snare::{HostProfile, Sim};

const VIRTUAL_EPOCH_SECS: u64 = 1_700_000_000;

#[test]
fn system_time_sits_at_the_fixed_virtual_epoch() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
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
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let a = SystemTime::now();
        let b = SystemTime::now();
        assert!(b >= a, "each realtime read advances the shared virtual clock");
    });
}

#[test]
fn instant_elapsed_reflects_a_virtual_sleep() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
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
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let first = Instant::now();
        let second = Instant::now();
        assert!(second >= first, "Instant never regresses");
        // Each clock read ticks the virtual clock forward, so two back-to-back reads differ: the
        // caveat is that virtual time passes per read, it does not track wall time.
        assert!(second.duration_since(first) > Duration::ZERO, "reads advance the clock");
    });
}

#[test]
fn many_short_sleeps_accumulate_virtually() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
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
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        // A full day. AFAP means this returns at once instead of blocking the test harness.
        std::thread::sleep(Duration::from_secs(86_400));
    });
}
