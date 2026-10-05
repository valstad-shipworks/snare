#![cfg(target_os = "macos")]

//! The Darwin clock surface over the virtual clock: `clock_gettime(2)`, the flat-nanosecond
//! `clock_gettime_nsec_np(3)`, and `mach_absolute_time(3)` (which `std::time::Instant` reads on
//! macOS). Darwin's clock ids live in <sys/_types/_clockid_t.h>; CLOCK_UPTIME_RAW and the
//! *_APPROX variants all map onto the monotonic virtual clock since the sim has no real uptime or
//! coarse tick to distinguish them.

use std::time::{Duration, Instant};

use snare::{HostProfile, Sim};

unsafe extern "C" {
    fn clock_gettime_nsec_np(clk: libc::clockid_t) -> u64;
}

fn get(clk: libc::clockid_t) -> libc::timespec {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::clock_gettime(clk, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime succeeds");
    ts
}

#[test]
fn realtime_sits_at_the_fixed_epoch() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let r = get(libc::CLOCK_REALTIME);
        assert_eq!(r.tv_sec, 1_700_000_000, "virtual realtime epoch");
    });
}

fn nanos(ts: libc::timespec) -> u64 {
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

#[test]
fn monotonic_and_uptime_raw_start_near_zero() {
    let host = HostProfile::new().build();
    let sim = Sim::builder().host(host).build();
    sim.run(|| {
        let mono = nanos(get(libc::CLOCK_MONOTONIC));
        assert!(mono < 1_000_000_000, "monotonic starts at zero ({mono})");
        assert_eq!(
            nanos(get(libc::CLOCK_UPTIME_RAW)),
            mono,
            "uptime-raw shares the reading"
        );
        assert_eq!(
            nanos(get(libc::CLOCK_MONOTONIC_RAW)),
            mono,
            "monotonic-raw shares it"
        );
    });
    assert_eq!(sim.time_value(), Duration::ZERO, "sim time starts at zero");
}

#[test]
fn clock_gettime_nsec_np_reports_realtime_in_nanoseconds() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let nsec = unsafe { clock_gettime_nsec_np(libc::CLOCK_REALTIME) };
        assert_eq!(
            nsec / 1_000_000_000,
            1_700_000_000,
            "flat-nanosecond realtime at the epoch"
        );
    });
}

#[test]
fn clock_gettime_nsec_np_monotonic_follows_sleeps() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let a = unsafe { clock_gettime_nsec_np(libc::CLOCK_MONOTONIC) };
        std::thread::sleep(std::time::Duration::from_millis(1));
        let b = unsafe { clock_gettime_nsec_np(libc::CLOCK_MONOTONIC) };
        assert!(
            b >= a + 1_000_000,
            "a sleep advances the monotonic virtual clock ({a} -> {b})"
        );
    });
}

#[test]
fn instant_elapsed_reflects_a_virtual_sleep() {
    // std::time::Instant on macOS reads mach_absolute_time, which the sim serves from the virtual
    // monotonic clock, so a virtual sleep shows up in elapsed().
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let start = Instant::now();
        std::thread::sleep(Duration::from_secs(4));
        assert!(
            start.elapsed() >= Duration::from_secs(4),
            "virtual monotonic advanced by 4s"
        );
    });
}

#[test]
fn tai_offset_does_not_perturb_realtime_on_darwin() {
    // Darwin has no CLOCK_TAI; the TAI offset only affects CLOCK_TAI on Linux, so realtime here is
    // unchanged whatever offset the profile carries.
    let host = HostProfile::new().tai_offset(37).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(
            get(libc::CLOCK_REALTIME).tv_sec,
            1_700_000_000,
            "realtime untouched by the offset"
        );
    });
}
