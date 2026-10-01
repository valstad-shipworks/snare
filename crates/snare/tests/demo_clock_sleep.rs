#![cfg(target_os = "linux")]

//! As-fast-as-possible sleeping. Every blocking wait a program makes — `nanosleep(2)`,
//! `clock_nanosleep(2)` (relative and TIMER_ABSTIME), `usleep(3)` — returns immediately while the
//! virtual clock jumps forward by the requested interval, so a program that paces itself with
//! sleeps runs at full speed yet still observes the time it meant to wait.

use snare::{HostProfile, Sim};

fn mono() -> i128 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

fn ts(secs: i64, nanos: i64) -> libc::timespec {
    libc::timespec { tv_sec: secs, tv_nsec: nanos }
}

#[test]
fn nanosleep_advances_monotonic_by_the_request() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let before = mono();
        let req = ts(5, 0);
        let rc = unsafe { libc::nanosleep(&req, std::ptr::null_mut()) };
        assert_eq!(rc, 0, "nanosleep returns success");
        let delta = mono() - before;
        assert!(delta >= 5_000_000_000, "virtual monotonic advanced >= 5s, got {delta}ns");
    });
}

#[test]
fn nanosleep_reports_zero_remaining() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        // man 2 nanosleep: on early return the unslept remainder is written back. The sim never
        // interrupts a sleep, so the remainder is always zero.
        let req = ts(0, 250_000_000);
        let mut remaining = ts(9, 9);
        let rc = unsafe { libc::nanosleep(&req, &mut remaining) };
        assert_eq!(rc, 0);
        assert_eq!(remaining.tv_sec, 0, "no seconds remain");
        assert_eq!(remaining.tv_nsec, 0, "no nanoseconds remain");
    });
}

#[test]
fn usleep_advances_by_the_microsecond_interval() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let before = mono();
        let rc = unsafe { libc::usleep(750_000) };
        assert_eq!(rc, 0, "usleep returns success");
        let delta = mono() - before;
        assert!(delta >= 750_000_000, "virtual monotonic advanced >= 750ms, got {delta}ns");
    });
}

#[test]
fn clock_nanosleep_relative_advances_monotonic() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let before = mono();
        let req = ts(3, 0);
        let mut remaining = ts(0, 0);
        let rc = unsafe {
            libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &req, &mut remaining)
        };
        assert_eq!(rc, 0, "relative clock_nanosleep returns success");
        let delta = mono() - before;
        assert!(delta >= 3_000_000_000, "advanced >= 3s, got {delta}ns");
    });
}

#[test]
fn clock_nanosleep_absolute_jumps_to_the_deadline() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        // TIMER_ABSTIME names an absolute deadline on the chosen clock; the virtual clock is
        // pushed forward to meet it (man 2 clock_nanosleep).
        let now = mono();
        let deadline_ns = now + 10_000_000_000; // 10s in the future
        let deadline = ts((deadline_ns / 1_000_000_000) as i64, (deadline_ns % 1_000_000_000) as i64);
        let rc = unsafe {
            libc::clock_nanosleep(libc::CLOCK_MONOTONIC, libc::TIMER_ABSTIME, &deadline, std::ptr::null_mut())
        };
        assert_eq!(rc, 0, "absolute clock_nanosleep returns success");
        assert!(mono() >= deadline_ns, "clock reached the absolute deadline");
    });
}

#[test]
fn an_absolute_deadline_in_the_past_returns_at_once() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        // A deadline already behind the clock is a no-op: fetch_max never regresses the counter.
        let now = mono();
        let past = ts(0, 0);
        let rc = unsafe {
            libc::clock_nanosleep(libc::CLOCK_MONOTONIC, libc::TIMER_ABSTIME, &past, std::ptr::null_mut())
        };
        assert_eq!(rc, 0);
        let after = mono();
        assert!(after >= now, "the clock did not go backwards for a stale deadline");
    });
}

#[test]
fn absolute_realtime_deadline_is_honored() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        // Pace against CLOCK_REALTIME: a deadline one second past the fixed epoch.
        let deadline = ts(1_700_000_001, 0);
        let rc = unsafe {
            libc::clock_nanosleep(libc::CLOCK_REALTIME, libc::TIMER_ABSTIME, &deadline, std::ptr::null_mut())
        };
        assert_eq!(rc, 0, "absolute realtime deadline accepted");
        let mut ts_now: libc::timespec = unsafe { std::mem::zeroed() };
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts_now) };
        assert!(ts_now.tv_sec >= 1_700_000_001, "realtime reached the deadline");
    });
}

#[test]
fn clock_nanosleep_leaves_remaining_untouched_for_absolute() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        // man 2 clock_nanosleep: with TIMER_ABSTIME the remain argument is not used.
        let now = mono();
        let deadline_ns = now + 1_000_000_000;
        let deadline = ts((deadline_ns / 1_000_000_000) as i64, (deadline_ns % 1_000_000_000) as i64);
        let mut remaining = ts(7, 7);
        let rc = unsafe {
            libc::clock_nanosleep(libc::CLOCK_MONOTONIC, libc::TIMER_ABSTIME, &deadline, &mut remaining)
        };
        assert_eq!(rc, 0);
        assert_eq!(remaining.tv_sec, 7, "remaining is untouched for an absolute sleep");
        assert_eq!(remaining.tv_nsec, 7, "remaining is untouched for an absolute sleep");
    });
}

#[test]
fn sleep_ordering_is_preserved_across_calls() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let t0 = mono();
        std::thread::sleep(std::time::Duration::from_secs(1));
        let t1 = mono();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let t2 = mono();
        assert!(t1 - t0 >= 1_000_000_000, "first second elapsed");
        assert!(t2 - t1 >= 2_000_000_000, "next two seconds elapsed");
    });
}
