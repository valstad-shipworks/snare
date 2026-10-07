//! Local time follows the sim's own time zone when the sim decides one: `TZ` in an isolated
//! environment, or an `/etc/localtime` its file plane serves. `localtime_r`, `localtime`,
//! `mktime`, `ctime_r` and `time` read it (man 3 tzset, localtime, mktime; man 2 time), and on
//! macOS so does CoreFoundation's system zone. A sim that decides neither leaves local time to
//! the C library.
#![cfg(unix)]

use std::ffi::CStr;

use snare::{FsBuilder, HostProfile, Sim};

/// 2023-11-14 22:13:20 UTC, the sim's realtime epoch.
const EPOCH: libc::time_t = 1_700_000_000;

fn with_env(vars: &[(&str, &str)]) -> Sim {
    let mut profile = HostProfile::new().isolate_env();
    for (k, v) in vars {
        profile = profile.env(*k, *v);
    }
    Sim::builder().host(profile.build()).build()
}

fn with_localtime(fs: FsBuilder) -> Sim {
    Sim::builder()
        .fs(fs.build())
        .host(HostProfile::new().isolate_env().build())
        .build()
}

fn zone_file(name: &str) -> Vec<u8> {
    std::fs::read(format!("/usr/share/zoneinfo/{name}")).unwrap()
}

/// `t` broken down in the local zone: the offset, the abbreviation, and the fields.
fn local(t: libc::time_t) -> (i64, String, [i32; 9]) {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    assert!(!unsafe { libc::localtime_r(&t, &mut tm) }.is_null());
    let zone = unsafe { CStr::from_ptr(tm.tm_zone) }
        .to_string_lossy()
        .into_owned();
    (
        tm.tm_gmtoff as i64,
        zone,
        [
            tm.tm_year,
            tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            tm.tm_wday,
            tm.tm_yday,
            tm.tm_isdst,
        ],
    )
}

#[test]
fn tz_in_an_isolated_environment_sets_the_local_zone() {
    let (off, zone, fields) = with_env(&[("TZ", "Asia/Tokyo")]).run(|| local(EPOCH));
    assert_eq!((off, zone.as_str()), (9 * 3600, "JST"));
    // 2023-11-15 07:13:20, a Wednesday, day 318 of the year.
    assert_eq!(fields, [123, 10, 15, 7, 13, 20, 3, 318, 0]);
}

#[test]
fn each_sim_has_its_own_zone_on_one_thread() {
    let tokyo = with_env(&[("TZ", "Asia/Tokyo")]).run(|| local(EPOCH).0);
    let sao_paulo = with_env(&[("TZ", "America/Sao_Paulo")]).run(|| local(EPOCH).0);
    let tokyo_again = with_env(&[("TZ", "Asia/Tokyo")]).run(|| local(EPOCH).0);
    assert_eq!((tokyo, sao_paulo, tokyo_again), (32_400, -10_800, 32_400));
}

#[test]
fn spawned_threads_see_the_sims_zone() {
    let off = with_env(&[("TZ", "Europe/Oslo")])
        .run(|| std::thread::spawn(|| local(EPOCH).0).join().unwrap());
    assert_eq!(off, 3600);
}

#[test]
fn a_tz_set_in_the_sim_is_seen_after_tzset() {
    unsafe extern "C" {
        fn tzset();
    }
    let (before, after) = with_env(&[("TZ", "UTC")]).run(|| {
        let before = local(EPOCH).0;
        unsafe { std::env::set_var("TZ", "Asia/Kolkata") };
        unsafe { tzset() };
        (before, local(EPOCH).0)
    });
    assert_eq!((before, after), (0, 5 * 3600 + 1800));
}

#[test]
fn posix_tz_strings_and_empty_tz() {
    let r = with_env(&[("TZ", "<+0330>-3:30")]).run(|| local(EPOCH));
    assert_eq!((r.0, r.1.as_str()), (12_600, "+0330"));
    // 2023-07-01 12:00 UTC falls in daylight time under the US rules.
    let summer = 1_688_212_800;
    let r = with_env(&[("TZ", "EST5EDT,M3.2.0,M11.1.0")]).run(|| (local(summer), local(EPOCH)));
    assert_eq!((r.0.0, r.0.1.as_str(), r.0.2[8]), (-4 * 3600, "EDT", 1));
    assert_eq!((r.1.0, r.1.1.as_str(), r.1.2[8]), (-5 * 3600, "EST", 0));
    let r = with_env(&[("TZ", "")]).run(|| local(EPOCH));
    assert_eq!((r.0, r.2[3]), (0, 22));
}

#[test]
fn etc_localtime_in_the_sims_file_system_sets_the_zone() {
    let fs = FsBuilder::new().file("/etc/localtime", zone_file("America/Sao_Paulo"));
    let off = with_localtime(fs).run(|| local(EPOCH).0);
    assert_eq!(off, -3 * 3600);
}

#[test]
fn etc_localtime_linked_into_the_real_zoneinfo_sets_the_zone() {
    let fs = FsBuilder::new().symlink("/etc/localtime", "/usr/share/zoneinfo/Europe/Oslo");
    let (off, zone, _) = with_localtime(fs).run(|| local(EPOCH));
    assert_eq!((off, zone.as_str()), (3600, "CET"));
}

#[test]
fn no_etc_localtime_and_no_tz_is_utc() {
    let fs = FsBuilder::new().own_prefix("/etc");
    let (off, zone, _) = with_localtime(fs).run(|| local(EPOCH));
    assert_eq!((off, zone.as_str()), (0, "UTC"));
}

#[test]
fn tz_names_a_zone_in_the_sims_tzdir() {
    let fs = FsBuilder::new().file("/zones/Lab/Here", zone_file("Asia/Kathmandu"));
    let sim = Sim::builder()
        .fs(fs.build())
        .host(
            HostProfile::new()
                .env("TZ", "Lab/Here")
                .env("TZDIR", "/zones")
                .build(),
        )
        .build();
    assert_eq!(sim.run(|| local(EPOCH).0), 5 * 3600 + 2700);
}

#[test]
fn mktime_inverts_localtime_and_normalizes() {
    let r = with_env(&[("TZ", "America/New_York")]).run(|| {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_year = 123;
        tm.tm_mon = 10;
        tm.tm_mday = 14;
        tm.tm_hour = 17;
        tm.tm_min = 13;
        tm.tm_sec = 20;
        tm.tm_isdst = -1;
        let t = unsafe { libc::mktime(&mut tm) };
        let mut overflow: libc::tm = unsafe { std::mem::zeroed() };
        overflow.tm_year = 123;
        overflow.tm_mon = 13;
        overflow.tm_mday = 0;
        overflow.tm_isdst = -1;
        unsafe { libc::mktime(&mut overflow) };
        (
            t,
            tm.tm_isdst,
            tm.tm_gmtoff,
            overflow.tm_year,
            overflow.tm_mon,
            overflow.tm_mday,
        )
    });
    assert_eq!(r, (EPOCH, 0, -5 * 3600, 124, 0, 31));
}

#[test]
fn localtime_and_ctime_r_use_the_sims_zone() {
    let (hour, text) = with_env(&[("TZ", "Asia/Tokyo")]).run(|| {
        let tm = unsafe { libc::localtime(&EPOCH) };
        let hour = unsafe { (*tm).tm_hour };
        let mut buf = [0 as libc::c_char; 26];
        assert!(!unsafe { libc::ctime_r(&EPOCH, buf.as_mut_ptr()) }.is_null());
        let text = unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        (hour, text)
    });
    assert_eq!(hour, 7);
    assert_eq!(text, "Wed Nov 15 07:13:20 2023\n");
}

#[test]
fn a_sim_that_decides_no_zone_leaves_it_to_libc() {
    let outside = local(EPOCH);
    let inside = Sim::builder().build().run(|| local(EPOCH));
    assert_eq!(inside, outside);
}

#[test]
fn deterministic_runs_read_the_zone_alike() {
    let run = || {
        Sim::builder()
            .deterministic()
            .seed(4)
            .host(HostProfile::new().env("TZ", "Australia/Lord_Howe").build())
            .build()
            .run(|| std::thread::spawn(|| local(EPOCH)).join().unwrap())
    };
    let (a, b) = (run(), run());
    assert_eq!(a, b);
    assert_eq!(a.0, 11 * 3600);
}

#[test]
fn time_reads_the_virtual_realtime_clock() {
    let (t, stored, now) = Sim::builder().fixed_epoch().build().run(|| {
        let mut stored: libc::time_t = 0;
        let t = unsafe { libc::time(&mut stored) };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (t, stored, now)
    });
    assert_eq!(t, EPOCH);
    assert_eq!(stored, EPOCH);
    assert_eq!(now, EPOCH as u64);
}

#[cfg(target_os = "macos")]
mod core_foundation {
    use super::*;
    use std::ffi::c_void;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFTimeZoneResetSystem();
        fn CFTimeZoneCopySystem() -> *const c_void;
        fn CFTimeZoneCopyDefault() -> *const c_void;
        fn CFTimeZoneGetName(zone: *const c_void) -> *const c_void;
        fn CFTimeZoneGetSecondsFromGMT(zone: *const c_void, at: f64) -> f64;
        fn CFStringGetCString(s: *const c_void, buf: *mut u8, len: isize, encoding: u32) -> u8;
        fn CFRelease(object: *const c_void);
    }

    /// Seconds from 2001-01-01, CoreFoundation's reference date, to the sim's epoch.
    const AT: f64 = (EPOCH - 978_307_200) as f64;

    fn describe(zone: *const c_void) -> (String, f64) {
        assert!(!zone.is_null());
        let mut buf = [0u8; 128];
        let ok = unsafe {
            CFStringGetCString(CFTimeZoneGetName(zone), buf.as_mut_ptr(), 128, 0x0800_0100)
        };
        assert_ne!(ok, 0);
        let name = CStr::from_bytes_until_nul(&buf)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let off = unsafe { CFTimeZoneGetSecondsFromGMT(zone, AT) };
        unsafe { CFRelease(zone) };
        (name, off)
    }

    fn system_zone() -> (String, f64) {
        unsafe { CFTimeZoneResetSystem() };
        describe(unsafe { CFTimeZoneCopySystem() })
    }

    #[test]
    fn the_system_zone_follows_tz() {
        let a = with_env(&[("TZ", "Asia/Tokyo")]).run(system_zone);
        let b = with_env(&[("TZ", "America/Sao_Paulo")]).run(system_zone);
        assert_eq!(a, ("Asia/Tokyo".into(), 32_400.0));
        assert_eq!(b, ("America/Sao_Paulo".into(), -10_800.0));
        let default =
            with_env(&[("TZ", "Europe/Oslo")]).run(|| describe(unsafe { CFTimeZoneCopyDefault() }));
        assert_eq!(default, ("Europe/Oslo".into(), 3600.0));
    }

    #[test]
    fn the_system_zone_follows_the_sims_etc_localtime() {
        let fs = FsBuilder::new().symlink("/etc/localtime", "/usr/share/zoneinfo/Europe/Oslo");
        let linked = with_localtime(fs).run(system_zone);
        assert_eq!(linked, ("Europe/Oslo".into(), 3600.0));
        let fs = FsBuilder::new().file("/etc/localtime", zone_file("Asia/Kathmandu"));
        let copied = with_localtime(fs).run(system_zone);
        assert_eq!(copied.1, 20_700.0);
    }

    #[test]
    fn a_sim_that_decides_no_zone_keeps_the_real_system_zone() {
        let outside = system_zone();
        assert_eq!(Sim::builder().build().run(system_zone), outside);
    }
}
