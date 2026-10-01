#![cfg(target_os = "linux")]

//! `clock_gettime(2)` across every clock id the sim virtualizes. man 2 clock_gettime defines the
//! ids and their relationships; CLOCK_TAI (value 11, <linux/time.h>) leads CLOCK_REALTIME by the
//! kernel's TAI-UTC offset. The COARSE and RAW variants share the base clock's reading because the
//! virtual clock has no tick granularity or NTP slewing to distinguish them.

use snare::{HostProfile, Sim};

fn get(clk: libc::clockid_t) -> libc::timespec {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::clock_gettime(clk, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime({clk}) succeeds");
    ts
}

fn nanos(ts: libc::timespec) -> i128 {
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

const VIRTUAL_EPOCH_NANOS: i128 = 1_700_000_000i128 * 1_000_000_000;

#[test]
fn monotonic_starts_near_its_origin() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let m = get(libc::CLOCK_MONOTONIC);
        // The origin is zero; a handful of reads have advanced it by microseconds at most.
        assert!(m.tv_sec == 0, "monotonic origin is near zero, got {}s", m.tv_sec);
    });
}

#[test]
fn realtime_starts_at_the_fixed_epoch() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let r = get(libc::CLOCK_REALTIME);
        assert_eq!(r.tv_sec, 1_700_000_000, "realtime sits at the fixed virtual epoch");
    });
}

#[test]
fn coarse_variants_track_their_base_clock() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        // No tick granularity in the sim, so *_COARSE reads the same virtual clock as its base and
        // only ever differs by the per-read 1µs advance.
        let rt = get(libc::CLOCK_REALTIME);
        let rt_coarse = get(libc::CLOCK_REALTIME_COARSE);
        assert_eq!(rt.tv_sec, rt_coarse.tv_sec, "REALTIME_COARSE shares the realtime epoch");

        let mono = get(libc::CLOCK_MONOTONIC);
        let mono_coarse = get(libc::CLOCK_MONOTONIC_COARSE);
        assert_eq!(mono.tv_sec, mono_coarse.tv_sec, "MONOTONIC_COARSE shares the origin");
    });
}

#[test]
fn raw_and_boottime_are_monotonic_too() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        // CLOCK_MONOTONIC_RAW skips NTP slewing and CLOCK_BOOTTIME includes suspend time on a real
        // kernel; the sim has neither, so both map onto the monotonic virtual clock.
        let raw = get(libc::CLOCK_MONOTONIC_RAW);
        let boot = get(libc::CLOCK_BOOTTIME);
        assert_eq!(raw.tv_sec, 0, "MONOTONIC_RAW near the origin");
        assert_eq!(boot.tv_sec, 0, "BOOTTIME near the origin");
    });
}

#[test]
fn every_read_advances_the_shared_clock() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let a = nanos(get(libc::CLOCK_MONOTONIC));
        let b = nanos(get(libc::CLOCK_MONOTONIC));
        let c = nanos(get(libc::CLOCK_MONOTONIC));
        assert!(a < b && b < c, "monotonic strictly increases per read ({a} < {b} < {c})");
    });
}

#[test]
fn realtime_and_monotonic_share_one_counter() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        // Realtime is the monotonic counter plus the epoch offset; a realtime read taken after a
        // monotonic read exceeds it by exactly the epoch (within the per-read tick).
        let mono = nanos(get(libc::CLOCK_MONOTONIC));
        let rt = nanos(get(libc::CLOCK_REALTIME));
        assert!(rt - mono >= VIRTUAL_EPOCH_NANOS, "realtime = monotonic + fixed epoch");
    });
}

#[test]
fn tai_leads_realtime_by_the_default_offset() {
    // HostProfile::new() carries the present-day 37s TAI-UTC offset.
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let rt = get(libc::CLOCK_REALTIME);
        let tai = get(libc::CLOCK_TAI);
        assert_eq!(tai.tv_sec - rt.tv_sec, 37, "CLOCK_TAI leads CLOCK_REALTIME by 37s");
    });
}

#[test]
fn tai_offset_is_configurable() {
    let host = HostProfile::new().tai_offset(10).build();
    Sim::builder().host(host).build().run(|| {
        let rt = get(libc::CLOCK_REALTIME);
        let tai = get(libc::CLOCK_TAI);
        assert_eq!(tai.tv_sec - rt.tv_sec, 10, "a custom offset is honored");
    });
}

#[test]
fn a_zero_tai_offset_tracks_realtime() {
    let host = HostProfile::new().tai_offset(0).build();
    Sim::builder().host(host).build().run(|| {
        let rt = get(libc::CLOCK_REALTIME);
        let tai = get(libc::CLOCK_TAI);
        assert_eq!(tai.tv_sec, rt.tv_sec, "offset 0 makes TAI and realtime coincide");
    });
}
