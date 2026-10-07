#![cfg(unix)]

//! `gettimeofday(2)` reads the same virtual realtime clock as `clock_gettime(CLOCK_REALTIME)`,
//! reported as a `struct timeval` (seconds + microseconds). The obsolete timezone argument is
//! ignored (man 2 gettimeofday).

use snare::{HostProfile, Sim};

const VIRTUAL_EPOCH_SECS: libc::time_t = 1_700_000_000;

fn gettimeofday() -> libc::timeval {
    let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "gettimeofday succeeds");
    tv
}

#[test]
fn reports_the_virtual_realtime_epoch() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).fixed_epoch().build().run(|| {
        let tv = gettimeofday();
        assert_eq!(
            tv.tv_sec, VIRTUAL_EPOCH_SECS,
            "seconds sit at the fixed epoch"
        );
        assert!(
            (0..1_000_000).contains(&i128::from(tv.tv_usec)),
            "microseconds in range"
        );
    });
}

#[test]
fn a_null_timezone_pointer_is_accepted() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).fixed_epoch().build().run(|| {
        // The tz argument has been obsolete since 4.3BSD; passing NULL is the normal call.
        let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
        assert_eq!(rc, 0);
    });
}

#[test]
fn successive_reads_do_not_regress() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).fixed_epoch().build().run(|| {
        let a = gettimeofday();
        let b = gettimeofday();
        let an = a.tv_sec as i128 * 1_000_000 + a.tv_usec as i128;
        let bn = b.tv_sec as i128 * 1_000_000 + b.tv_usec as i128;
        assert!(bn >= an, "realtime, in microseconds, does not go backwards");
    });
}

#[test]
fn agrees_with_clock_gettime_realtime_to_the_second() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).fixed_epoch().build().run(|| {
        let tv = gettimeofday();
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
        assert_eq!(rc, 0);
        assert_eq!(
            tv.tv_sec, ts.tv_sec,
            "gettimeofday and clock_gettime(CLOCK_REALTIME) share the realtime clock"
        );
    });
}
