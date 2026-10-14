//! The sim's own time-zone resolution against the C library's: the same zones, set through `TZ`
//! in the real process environment outside the sim and in an isolated environment inside it,
//! give the same `localtime_r` and `mktime` results. One test, since `TZ` is process-wide.
#![cfg(unix)]

use std::ffi::CStr;

use snare::{HostProfile, Sim};

unsafe extern "C" {
    fn tzset();
}

/// TZ values at the edges of the syntax: empty, a missing file, a bare abbreviation, a leading
/// `:`, an absolute path.
const EDGES: &[&str] = &[
    "",
    "Foo/Bar",
    "XYZ",
    ":Asia/Tokyo",
    "/usr/share/zoneinfo/Asia/Tokyo",
];

/// Zone files with northern and southern daylight time, a half-hour daylight shift, a
/// 45-minute offset, abolished daylight time, a skipped day, negative daylight time, a two-hour
/// daylight shift and daylight time suspended each Ramadan; and TZ strings, which the C library
/// parses itself.
const ZONES: &[&str] = &[
    "America/New_York",
    "Europe/London",
    "Europe/Dublin",
    "Australia/Lord_Howe",
    "Asia/Kathmandu",
    "America/Sao_Paulo",
    "Pacific/Apia",
    "America/Santiago",
    "Africa/Casablanca",
    "Antarctica/Troll",
    "Europe/Moscow",
    "America/St_Johns",
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

/// The local times `mktimes` tries, as (year since 1900, day of the year from 0, seconds into
/// the day): half past each hour of 2024, and around every change of offset from 1900 to 2100
/// the current zone has, found by `localtime_r` a day at a time and bisected: four times inside
/// each overlap or gap and a minute either side. Computed with the C library outside the sim.
fn mktime_inputs() -> Vec<(i32, i32, i64)> {
    let mut v: Vec<(i32, i32, i64)> = (0..366)
        .flat_map(|yday| (0..24).map(move |hour| (124, yday, hour * 3600 + 1800)))
        .collect();
    let offset = |t: libc::time_t| localtime(t).map_or(0, |b| b.0);
    let mut day: libc::time_t = -2_208_988_800;
    while day < 4_102_444_800 {
        let (before, after) = (offset(day), offset(day + 86_400));
        if before != after {
            let (mut lo, mut hi) = (day, day + 86_400);
            while hi - lo > 1 {
                let mid = lo + (hi - lo) / 2;
                if offset(mid) == before {
                    lo = mid;
                } else {
                    hi = mid;
                }
            }
            let (from, to) = (hi + before, hi + after);
            let (start, end) = (from.min(to), from.max(to));
            let mut locals = vec![start - 60, end + 60];
            locals.extend((0..4).map(|k| start + (end - start) * k / 4));
            for local in locals {
                let mut tm: libc::tm = unsafe { std::mem::zeroed() };
                assert!(!unsafe { libc::gmtime_r(&local, &mut tm) }.is_null());
                v.push((tm.tm_year, tm.tm_yday, local.rem_euclid(86_400)));
            }
        }
        day += 86_400;
    }
    v
}

/// `mktime` of each of `inputs`, with `tm_isdst` -1, 0 and 1: the result, and the normalized
/// fields it wrote back. glibc starts its search from the offset its previous call found, so a
/// first call puts the C library and the sim at the same offset.
fn mktimes(inputs: &[(i32, i32, i64)]) -> Vec<Made> {
    let mut first: libc::tm = unsafe { std::mem::zeroed() };
    first.tm_year = 124;
    first.tm_mday = 15;
    first.tm_hour = 12;
    first.tm_isdst = -1;
    unsafe { libc::mktime(&mut first) };
    let mut out = Vec::new();
    for &(year, yday, seconds) in inputs {
        for isdst in [-1, 0, 1] {
            let mut tm: libc::tm = unsafe { std::mem::zeroed() };
            tm.tm_year = year;
            tm.tm_mday = 1 + yday;
            tm.tm_hour = (seconds / 3600) as i32;
            tm.tm_min = (seconds / 60 % 60) as i32;
            tm.tm_sec = (seconds % 60) as i32;
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
    out
}

fn compute(inputs: &[(i32, i32, i64)]) -> (Vec<Option<Broken>>, Vec<Made>) {
    (
        instants().into_iter().map(localtime).collect(),
        mktimes(inputs),
    )
}

/// strftime(3) of `struct tm`s built by hand, without a zone name (or with an empty one) and
/// with an offset that is not the zone's, in winter and summer, for each `tm_isdst`: the
/// conversions that read the C library's own zone, `%Z`, `%s` and, on macOS, `%z`. Called right
/// after tzset(3), before any conversion moves `tzname`.
fn texts() -> Vec<String> {
    let mut out = Vec::new();
    for (mon, isdst, zone) in [
        (0, 0, None),
        (0, 1, None),
        (0, -1, None),
        (6, 0, None),
        (6, 1, None),
        (6, 2, None),
        (6, 0, Some(c"")),
        (6, 0, Some(c"ABC")),
    ] {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_year = 124;
        tm.tm_mon = mon;
        tm.tm_mday = 3;
        tm.tm_hour = 12;
        tm.tm_isdst = isdst;
        tm.tm_gmtoff = 3600 * 5 + 60 * 7;
        if let Some(zone) = zone {
            tm.tm_zone = zone.as_ptr() as _;
        }
        for format in [c"%Z|%z|%c|%+|%s", c"%-z|%_z|%0z|%#Z|%^Z|%_10s"] {
            let mut buf = [0 as libc::c_char; 256];
            let n = unsafe { libc::strftime(buf.as_mut_ptr(), buf.len(), format.as_ptr(), &tm) };
            let text = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy();
            out.push(format!("{n} {text}"));
        }
    }
    out
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
        if cfg!(target_os = "macos") && *zone == "Africa/Casablanca" {
            continue;
        }
        unsafe {
            std::env::set_var("TZ", zone);
            tzset();
        }
        let real_texts = texts();
        let inputs = mktime_inputs();
        let real = compute(&inputs);
        let (sim, sim_texts) = Sim::builder()
            .host(HostProfile::new().env("TZ", *zone).build())
            .build()
            .run(|| {
                let texts = texts();
                (compute(&inputs), texts)
            });
        for (r, s) in real_texts.iter().zip(&sim_texts) {
            if r != s {
                mismatches.push(format!("{zone} strftime: real {r:?} sim {s:?}"));
            }
        }
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
            if r != s {
                let (input, isdst) = (inputs[i / 3], i as i32 % 3 - 1);
                mismatches.push(format!(
                    "{zone} mktime({input:?}, isdst {isdst}): real {r:?} sim {s:?}"
                ));
            }
        }
    }
    for tz in EDGES {
        unsafe {
            std::env::set_var("TZ", tz);
            tzset();
        }
        let real_texts = texts();
        let real = localtime(1_700_000_000);
        let (sim, sim_texts) = Sim::builder()
            .host(HostProfile::new().env("TZ", *tz).build())
            .build()
            .run(|| {
                let texts = texts();
                (localtime(1_700_000_000), texts)
            });
        if real != sim {
            mismatches.push(format!("TZ={tz:?}: real {real:?} sim {sim:?}"));
        }
        if real_texts != sim_texts {
            mismatches.push(format!(
                "TZ={tz:?} strftime: real {real_texts:?} sim {sim_texts:?}"
            ));
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
