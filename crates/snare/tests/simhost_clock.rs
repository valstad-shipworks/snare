#![cfg(unix)]
use snare::{HostProfile, Sim};

fn clock_gettime(clk: libc::clockid_t) -> libc::timespec {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::clock_gettime(clk, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime failed");
    ts
}

fn secs(ts: libc::timespec) -> libc::time_t {
    ts.tv_sec
}

#[test]
fn realtime_is_virtual_and_deterministic() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        // The fixed virtual epoch, not the real wall clock.
        let t = clock_gettime(libc::CLOCK_REALTIME);
        assert_eq!(secs(t), 1_700_000_000, "virtual realtime epoch");
    });
}

#[test]
fn monotonic_advances_each_read() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let a = clock_gettime(libc::CLOCK_MONOTONIC);
        let b = clock_gettime(libc::CLOCK_MONOTONIC);
        let an = a.tv_sec as i128 * 1_000_000_000 + a.tv_nsec as i128;
        let bn = b.tv_sec as i128 * 1_000_000_000 + b.tv_nsec as i128;
        assert!(bn > an, "virtual monotonic clock advances ({an} -> {bn})");
    });
}

#[test]
fn sleep_advances_the_virtual_clock_without_blocking() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let before = clock_gettime(libc::CLOCK_MONOTONIC);
        // A full hour of sleep: if it actually blocked, the test would hang (caught by the
        // harness). It returns at once because the clock layer carries the sleep virtually, and
        // virtual monotonic time still moves forward by the hour.
        std::thread::sleep(std::time::Duration::from_secs(3600));
        let after = clock_gettime(libc::CLOCK_MONOTONIC);
        let delta = after.tv_sec - before.tv_sec;
        assert!(delta >= 3600, "virtual monotonic advanced by >= 1h, got {delta}s");
    });
}

#[cfg(target_os = "linux")]
#[test]
fn clock_tai_leads_realtime_by_the_offset() {
    let host = HostProfile::new().tai_offset(37).build();
    Sim::builder().host(host).build().run(|| {
        const CLOCK_TAI: libc::clockid_t = 11;
        // Read realtime then TAI; both advance the shared clock by 1µs per read, so TAI's second
        // count is realtime's + 37 regardless of the sub-second drift.
        let rt = clock_gettime(libc::CLOCK_REALTIME);
        let tai = clock_gettime(CLOCK_TAI);
        assert_eq!(secs(tai) - secs(rt), 37, "CLOCK_TAI leads by the TAI-UTC offset");
    });
}
