//! The sim's own time-zone resolution against the C library's: the same zones, set through `TZ`
//! in the real process environment outside the sim and in an isolated environment inside it,
//! give the same `localtime_r` and `mktime` results. One test, since `TZ` is process-wide.
#![cfg(unix)]

use std::ffi::CStr;

use snare::{HostProfile, Sim};

unsafe extern "C" {
    fn tzset();
}

/// Zone files with northern and southern daylight time, a half-hour daylight shift, a
/// 45-minute offset, abolished daylight time, a skipped day and negative daylight time; and TZ
/// strings, which the C library parses itself.
/// TZ values at the edges of the syntax: empty, a missing file, a bare abbreviation, a leading
/// `:`, an absolute path.
const EDGES: &[&str] = &[
    "",
    "Foo/Bar",
    "XYZ",
    ":Asia/Tokyo",
    "/usr/share/zoneinfo/Asia/Tokyo",
];

const ZONES: &[&str] = &[
    "America/New_York",
    "Europe/London",
    "Europe/Dublin",
    "Australia/Lord_Howe",
    "Asia/Kathmandu",
    "America/Sao_Paulo",
    "Pacific/Apia",
    "America/Santiago",
    "EST5EDT,M3.2.0,M11.1.0",
    "<+0330>-3:30",
    "NZST-12NZDT,M9.5.0,M4.1.0/3",
    "UTC0",
];

/// Every half hour of 2024, plus instants long before and after it, and before the first
/// transition of most zone files.
fn instants() -> Vec<libc::time_t> {
    let mut v: Vec<libc::time_t> = (1_704_067_200..1_735_689_600).step_by(1800).collect();
    v.extend([
        -5_000_000_000,
        -2_208_988_800,
        0,
        1_700_000_000,
        2_000_000_000,
        4_102_444_800,
        4_118_000_000,
        13_000_000_000,
    ]);
    v
}

type Broken = (i64, String, [i32; 9]);
type Made = (libc::time_t, [i32; 9]);

fn localtime(t: libc::time_t) -> Option<Broken> {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return None;
    }
    let zone = unsafe { CStr::from_ptr(tm.tm_zone) }
        .to_string_lossy()
        .into_owned();
    Some((
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
    ))
}

/// `mktime` of each whole hour of 2024 in local time, with `tm_isdst` -1, 0 and 1: the result,
/// and the normalized fields it wrote back.
fn mktimes() -> Vec<Made> {
    let mut out = Vec::new();
    for yday in 0..366 {
        for hour in 0..24 {
            for isdst in [-1, 0, 1] {
                let mut tm: libc::tm = unsafe { std::mem::zeroed() };
                tm.tm_year = 124;
                tm.tm_mday = 1 + yday;
                tm.tm_hour = hour;
                tm.tm_min = 30;
                tm.tm_isdst = isdst;
                let t = unsafe { libc::mktime(&mut tm) };
                out.push((
                    t,
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
                ));
            }
        }
    }
    out
}

fn compute() -> (Vec<Option<Broken>>, Vec<Made>) {
    (instants().into_iter().map(localtime).collect(), mktimes())
}

#[test]
fn local_time_matches_the_c_library() {
    if !std::path::Path::new("/usr/share/zoneinfo/America/New_York").exists() {
        eprintln!("skipped: no zoneinfo database on this host");
        return;
    }
    let saved = std::env::var_os("TZ");
    let mut mismatches = Vec::new();
    for zone in ZONES {
        unsafe {
            std::env::set_var("TZ", zone);
            tzset();
        }
        let real = compute();
        let sim = Sim::builder()
            .host(HostProfile::new().env("TZ", *zone).build())
            .build()
            .run(compute);
        let at = instants();
        for (i, (r, s)) in real.0.iter().zip(&sim.0).enumerate() {
            if r != s {
                mismatches.push(format!(
                    "{zone} localtime_r({}): real {r:?} sim {s:?}",
                    at[i]
                ));
            }
        }
        for (i, (r, s)) in real.1.iter().zip(&sim.1).enumerate() {
            if r == s {
                continue;
            }
            // Each local time is tried with tm_isdst -1, 0 and 1 in turn. Where 0 and 1 both
            // find an instant of their own kind, the time is ambiguous, and with -1 the choice
            // is open: the sim's must be one of the two.
            let base = i - i % 3;
            let (std, dst) = (real.1[base + 1], real.1[base + 2]);
            let ambiguous = std.0 != dst.0 && std.1[8] == 0 && dst.1[8] == 1;
            if i % 3 == 0 && ambiguous && (s == &std || s == &dst) {
                continue;
            }
            mismatches.push(format!("{zone} mktime: real {r:?} sim {s:?}"));
        }
    }
    for tz in EDGES {
        unsafe {
            std::env::set_var("TZ", tz);
            tzset();
        }
        let real = localtime(1_700_000_000);
        let sim = Sim::builder()
            .host(HostProfile::new().env("TZ", *tz).build())
            .build()
            .run(|| localtime(1_700_000_000));
        if real != sim {
            mismatches.push(format!("TZ={tz:?}: real {real:?} sim {sim:?}"));
        }
    }
    unsafe {
        match saved {
            Some(v) => std::env::set_var("TZ", v),
            None => std::env::remove_var("TZ"),
        }
        tzset();
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches, first: {:#?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(20)]
    );
}
