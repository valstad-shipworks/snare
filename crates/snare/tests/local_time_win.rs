//! Local time on Windows follows the sim's own time zone when it has one
//! ([`SimBuilder::time_zone`]): the Win32 zone and conversion calls, the UCRT's local time and
//! zone state, and chrono, time and jiff, which read them. The `_os_truth` tests run the same
//! calls on the real OS outside the sim, with the sim given the machine's zone; the others pin
//! values measured on Windows 11 26300 with the machine set to the zone in question.
#![cfg(windows)]

use std::ffi::{CStr, c_char, c_int};

use snare::Sim;
use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::System::SystemInformation::{GetLocalTime, GetSystemTime};
use windows_sys::Win32::System::Time::{
    DYNAMIC_TIME_ZONE_INFORMATION, FileTimeToSystemTime, GetDynamicTimeZoneInformation,
    GetTimeZoneInformation, GetTimeZoneInformationForYear, SystemTimeToFileTime,
    SystemTimeToTzSpecificLocalTime, SystemTimeToTzSpecificLocalTimeEx, TIME_ZONE_INFORMATION,
    TzSpecificLocalTimeToSystemTime, TzSpecificLocalTimeToSystemTimeEx,
};

/// 2023-11-14 22:13:20 UTC, the sim's fixed epoch.
const EPOCH: i64 = 1_700_000_000;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Tm {
    sec: c_int,
    min: c_int,
    hour: c_int,
    mday: c_int,
    mon: c_int,
    year: c_int,
    wday: c_int,
    yday: c_int,
    isdst: c_int,
}

unsafe extern "C" {
    fn _localtime64_s(tm: *mut Tm, t: *const i64) -> c_int;
    fn _localtime64(t: *const i64) -> *mut Tm;
    fn _mktime64(tm: *mut Tm) -> i64;
    fn _tzset();
    fn _get_timezone(v: *mut i32) -> c_int;
    fn _get_daylight(v: *mut c_int) -> c_int;
    fn _get_dstbias(v: *mut i32) -> c_int;
    fn _get_tzname(len: *mut usize, buf: *mut c_char, size: usize, index: c_int) -> c_int;
    fn __tzname() -> *mut *mut c_char;
    fn __timezone() -> *mut i32;
    fn _ctime64_s(buf: *mut c_char, size: usize, t: *const i64) -> c_int;
    fn strftime(out: *mut c_char, size: usize, format: *const c_char, tm: *const Tm) -> usize;
    fn wcsftime(out: *mut u16, size: usize, format: *const u16, tm: *const Tm) -> usize;
    fn _errno() -> *mut c_int;
    fn _ftime64_s(tp: *mut Timeb) -> c_int;
    fn _strtime_s(buf: *mut c_char, size: usize) -> c_int;
    fn _wstrdate(buf: *mut u16) -> *mut u16;
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Timeb {
    time: i64,
    millitm: u16,
    timezone: i16,
    dstflag: i16,
}

fn ftime() -> Timeb {
    let mut tb = Timeb::default();
    assert_eq!(unsafe { _ftime64_s(&mut tb) }, 0);
    tb
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn FileTimeToLocalFileTime(ft: *const FILETIME, local: *mut FILETIME) -> i32;
    fn LocalFileTimeToFileTime(local: *const FILETIME, ft: *mut FILETIME) -> i32;
}

fn zoned(name: &str) -> Sim {
    Sim::builder().fixed_epoch().time_zone(name).build()
}

fn wide(s: &[u16]) -> String {
    let n = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..n])
}

fn filetime(t: i64) -> FILETIME {
    let v = (t * 10_000_000 + 116_444_736_000_000_000) as u64;
    FILETIME {
        dwLowDateTime: v as u32,
        dwHighDateTime: (v >> 32) as u32,
    }
}

fn ticks(ft: FILETIME) -> i64 {
    ((u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)) as i64
}

fn systemtime(t: i64) -> SYSTEMTIME {
    let mut st: SYSTEMTIME = unsafe { std::mem::zeroed() };
    assert_ne!(unsafe { FileTimeToSystemTime(&filetime(t), &mut st) }, 0);
    st
}

fn seconds(st: &SYSTEMTIME) -> i64 {
    let mut ft = filetime(0);
    assert_ne!(unsafe { SystemTimeToFileTime(st, &mut ft) }, 0);
    (ticks(ft) - 116_444_736_000_000_000) / 10_000_000
}

fn local_st(year: u16, month: u16, day: u16, hour: u16, minute: u16) -> SYSTEMTIME {
    SYSTEMTIME {
        wYear: year,
        wMonth: month,
        wDayOfWeek: 0,
        wDay: day,
        wHour: hour,
        wMinute: minute,
        wSecond: 0,
        wMilliseconds: 0,
    }
}

type Fields = (u16, u16, u16, u16, u16, u16, u16);

fn fields(st: &SYSTEMTIME) -> Fields {
    (
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wDayOfWeek,
        st.wHour,
        st.wMinute,
        st.wSecond,
    )
}

/// `SystemTimeToTzSpecificLocalTime` by `rule` (null for none): the local time of `t` as
/// seconds, or `None`.
fn to_local_by(rule: *const TIME_ZONE_INFORMATION, t: i64) -> Option<i64> {
    let mut local: SYSTEMTIME = unsafe { std::mem::zeroed() };
    (unsafe { SystemTimeToTzSpecificLocalTime(rule, &systemtime(t), &mut local) } != 0)
        .then(|| seconds(&local))
}

fn to_local(t: i64) -> Option<i64> {
    to_local_by(std::ptr::null(), t)
}

/// `TzSpecificLocalTimeToSystemTime` by `rule` (null for none).
fn to_utc_by(rule: *const TIME_ZONE_INFORMATION, local: &SYSTEMTIME) -> Option<i64> {
    let mut utc: SYSTEMTIME = unsafe { std::mem::zeroed() };
    (unsafe { TzSpecificLocalTimeToSystemTime(rule, local, &mut utc) } != 0).then(|| seconds(&utc))
}

fn to_utc(local: &SYSTEMTIME) -> Option<i64> {
    to_utc_by(std::ptr::null(), local)
}

fn to_utc_ex(local: &SYSTEMTIME) -> Option<i64> {
    let mut utc: SYSTEMTIME = unsafe { std::mem::zeroed() };
    (unsafe { TzSpecificLocalTimeToSystemTimeEx(std::ptr::null(), local, &mut utc) } != 0)
        .then(|| seconds(&utc))
}

fn to_local_ex(t: i64) -> Option<i64> {
    let mut local: SYSTEMTIME = unsafe { std::mem::zeroed() };
    (unsafe { SystemTimeToTzSpecificLocalTimeEx(std::ptr::null(), &systemtime(t), &mut local) }
        != 0)
        .then(|| seconds(&local))
}

type Rule = (i32, String, Fields, i32, String, Fields, i32);

fn rule(r: &TIME_ZONE_INFORMATION) -> Rule {
    (
        r.Bias,
        wide(&r.StandardName),
        fields(&r.StandardDate),
        r.StandardBias,
        wide(&r.DaylightName),
        fields(&r.DaylightDate),
        r.DaylightBias,
    )
}

fn zone_information() -> (u32, Rule) {
    let mut r: TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
    let id = unsafe { GetTimeZoneInformation(&mut r) };
    (id, rule(&r))
}

fn dynamic_information() -> (u32, Rule, String, bool) {
    let mut d: DYNAMIC_TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
    let id = unsafe { GetDynamicTimeZoneInformation(&mut d) };
    let r = TIME_ZONE_INFORMATION {
        Bias: d.Bias,
        StandardName: d.StandardName,
        StandardDate: d.StandardDate,
        StandardBias: d.StandardBias,
        DaylightName: d.DaylightName,
        DaylightDate: d.DaylightDate,
        DaylightBias: d.DaylightBias,
    };
    (
        id,
        rule(&r),
        wide(&d.TimeZoneKeyName),
        d.DynamicDaylightTimeDisabled,
    )
}

fn year_rule(year: u16) -> Option<Rule> {
    let mut r: TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
    (unsafe { GetTimeZoneInformationForYear(year, std::ptr::null(), &mut r) } != 0)
        .then(|| rule(&r))
}

fn machine_key() -> String {
    dynamic_information().2
}

fn crt_local(t: i64) -> (c_int, Tm) {
    let mut tm = Tm::default();
    let r = unsafe { _localtime64_s(&mut tm, &t) };
    (r, tm)
}

fn crt_mktime(
    year: c_int,
    mon: c_int,
    mday: c_int,
    hour: c_int,
    min: c_int,
    isdst: c_int,
) -> (i64, Tm) {
    let mut tm = Tm {
        year,
        mon,
        mday,
        hour,
        min,
        isdst,
        ..Tm::default()
    };
    let t = unsafe { _mktime64(&mut tm) };
    (t, tm)
}

fn crt_strftime(format: &CStr, tm: &Tm) -> String {
    let mut out = [0 as c_char; 128];
    let n = unsafe { strftime(out.as_mut_ptr(), out.len(), format.as_ptr(), tm) };
    unsafe { CStr::from_ptr(out.as_ptr()) }.to_string_lossy()[..n].to_string()
}

fn crt_zone_state() -> (i32, c_int, i32, String, String) {
    let (mut timezone, mut daylight, mut dstbias) = (0, 0, 0);
    unsafe {
        _get_timezone(&mut timezone);
        _get_daylight(&mut daylight);
        _get_dstbias(&mut dstbias);
    }
    let name = |i: c_int| {
        let mut buf = [0 as c_char; 64];
        let mut len = 0;
        assert_eq!(unsafe { _get_tzname(&mut len, buf.as_mut_ptr(), 64, i) }, 0);
        unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    };
    (timezone, daylight, dstbias, name(0), name(1))
}

#[test]
fn the_win32_zone_is_the_sims() {
    let (dynamic, info, offset) = zoned("Europe/Oslo").run(|| {
        let offset = to_local(EPOCH).unwrap() - EPOCH;
        (dynamic_information(), zone_information(), offset)
    });
    assert_eq!(dynamic.2, "W. Europe Standard Time");
    assert!(!dynamic.3);
    assert_eq!(dynamic.0, 1);
    assert_eq!(info, (dynamic.0, dynamic.1.clone()));
    let (bias, standard, standard_date, _, daylight, daylight_date, daylight_bias) = info.1;
    assert_eq!(
        (bias, standard.as_str(), daylight.as_str(), daylight_bias),
        (
            -60,
            "W. Europe Standard Time",
            "W. Europe Daylight Time",
            -60
        )
    );
    // Standard time from the last Sunday of October at 03:00, daylight time from the last
    // Sunday of March at 02:00.
    assert_eq!(
        (standard_date.1, standard_date.2, standard_date.4),
        (10, 5, 3)
    );
    assert_eq!(
        (daylight_date.1, daylight_date.2, daylight_date.4),
        (3, 5, 2)
    );
    assert_eq!(offset, 3600);
}

#[test]
fn iana_names_and_aliases_map_to_windows_zones() {
    for (name, key) in [
        ("Asia/Kolkata", "India Standard Time"),
        ("Asia/Calcutta", "India Standard Time"),
        ("Europe/Kyiv", "FLE Standard Time"),
        ("America/Sao_Paulo", "E. South America Standard Time"),
        ("UTC", "UTC"),
        ("Etc/GMT-14", "Line Islands Standard Time"),
        ("Tokyo Standard Time", "Tokyo Standard Time"),
    ] {
        assert_eq!(zoned(name).run(machine_key), key, "{name}");
    }
}

#[test]
#[should_panic(expected = "no Windows time zone for \"Mars/Olympus_Mons\"")]
fn an_unknown_zone_panics_at_build() {
    zoned("Mars/Olympus_Mons");
}

#[test]
fn each_sim_has_its_own_zone_on_one_thread() {
    let offset = |name: &str| zoned(name).run(|| to_local(EPOCH).unwrap() - EPOCH);
    assert_eq!(
        (
            offset("Asia/Tokyo"),
            offset("America/Sao_Paulo"),
            offset("Asia/Tokyo")
        ),
        (9 * 3600, -3 * 3600, 9 * 3600)
    );
}

#[test]
fn spawned_threads_see_the_sims_zone() {
    let key = zoned("Asia/Kathmandu").run(|| std::thread::spawn(machine_key).join().unwrap());
    assert_eq!(key, "Nepal Standard Time");
}

/// Pacific time: Windows applies each year's rule (2006's April to October, 2007's March to
/// November); a local time in the spring gap reads as daylight time without `Ex` and as
/// standard time with it, and the autumn overlap as daylight time with both. Measured with the
/// machine in Pacific Standard Time.
#[test]
fn pacific_conversions_follow_each_years_rule() {
    let r = zoned("America/Los_Angeles").run(|| {
        (
            to_local(1_143_966_600),
            to_local(1_678_613_400),
            to_local(1_678_617_000),
            to_utc(&local_st(2023, 3, 12, 2, 30)),
            to_utc_ex(&local_st(2023, 3, 12, 2, 30)),
            to_utc(&local_st(2023, 11, 5, 1, 30)),
            to_utc_ex(&local_st(2006, 4, 2, 2, 30)),
            to_utc(&local_st(2006, 3, 12, 2, 30)),
            to_local_ex(1_162_114_200),
        )
    });
    // 2006-04-02 08:30Z is 00:30 PST, before 2006's start; 2023-03-12 09:30Z 01:30 PST, 10:30Z
    // 03:30 PDT.
    assert_eq!(r.0, Some(1_143_966_600 - 8 * 3600));
    assert_eq!(r.1, Some(1_678_613_400 - 8 * 3600));
    assert_eq!(r.2, Some(1_678_617_000 - 7 * 3600));
    // 2023-03-12 02:30 local: 09:30Z, and 10:30Z with Ex.
    assert_eq!(r.3, Some(1_678_613_400));
    assert_eq!(r.4, Some(1_678_617_000));
    // 2023-11-05 01:30 local: 08:30Z, the daylight one.
    assert_eq!(r.5, Some(1_699_173_000));
    // 2006-04-02 02:30, in 2006's gap: 10:30Z with Ex; 2006-03-12 02:30 is no gap in 2006.
    assert_eq!(r.6, Some(1_143_973_800));
    assert_eq!(r.7, Some(1_142_159_400));
    // 2006-10-29 09:30Z is 01:30 PST, after 2006's end.
    assert_eq!(r.8, Some(1_162_114_200 - 8 * 3600));
}

#[test]
fn year_rules_come_from_the_sims_zone() {
    let (y2006, y2023) = zoned("America/Los_Angeles").run(|| (year_rule(2006), year_rule(2023)));
    let (y2006, y2023) = (y2006.unwrap(), y2023.unwrap());
    // 2006: first Sunday of April to last Sunday of October; 2023: second Sunday of March to
    // first Sunday of November.
    assert_eq!((y2006.5.1, y2006.5.2, y2006.2.1, y2006.2.2), (4, 1, 10, 5));
    assert_eq!((y2023.5.1, y2023.5.2, y2023.2.1, y2023.2.2), (3, 2, 11, 1));
}

#[test]
fn now_is_the_sims_time_in_the_sims_zone() {
    let (system, local, shifted, back, id) = zoned("Asia/Kolkata").run(|| {
        let mut system: SYSTEMTIME = unsafe { std::mem::zeroed() };
        let mut local: SYSTEMTIME = unsafe { std::mem::zeroed() };
        unsafe {
            GetSystemTime(&mut system);
            GetLocalTime(&mut local);
        }
        let mut shifted = filetime(0);
        let mut back = filetime(0);
        unsafe {
            FileTimeToLocalFileTime(&filetime(1_688_212_800), &mut shifted);
            LocalFileTimeToFileTime(&shifted, &mut back);
        }
        (system, local, shifted, back, zone_information().0)
    });
    assert_eq!(seconds(&system), EPOCH);
    assert_eq!(seconds(&local), EPOCH + 5 * 3600 + 1800);
    assert_eq!(
        (ticks(shifted) - ticks(filetime(1_688_212_800))) / 10_000_000,
        5 * 3600 + 1800
    );
    assert_eq!(ticks(back), ticks(filetime(1_688_212_800)));
    assert_eq!(id, 0);
}

/// `FileTimeToLocalFileTime` moves any time by the offset in effect now: in Oslo at the
/// November epoch, a July time moves an hour, not two.
#[test]
fn file_times_move_by_the_offset_now() {
    let (july, daylight_now) = zoned("Europe/Oslo").run(|| {
        let mut shifted = filetime(0);
        unsafe { FileTimeToLocalFileTime(&filetime(1_688_212_800), &mut shifted) };
        (
            (ticks(shifted) - ticks(filetime(1_688_212_800))) / 10_000_000,
            zone_information().0,
        )
    });
    assert_eq!((july, daylight_now), (3600, 1));
}

#[test]
fn a_sim_that_decides_no_zone_reads_the_machines_zone_at_the_sims_time() {
    let machine_offset = to_local(EPOCH).unwrap() - EPOCH;
    let (system, local) = Sim::builder().fixed_epoch().build().run(|| {
        let mut system: SYSTEMTIME = unsafe { std::mem::zeroed() };
        let mut local: SYSTEMTIME = unsafe { std::mem::zeroed() };
        unsafe {
            GetSystemTime(&mut system);
            GetLocalTime(&mut local);
        }
        (seconds(&system), seconds(&local))
    });
    assert_eq!(system, EPOCH);
    assert_eq!(local, EPOCH + machine_offset);
}

/// The UCRT's state starts as Pacific time in a fresh process, whatever the machine's zone, and
/// takes the zone's on the first call that needs it; Lord Howe's daylight time is half an hour.
#[test]
fn the_ucrt_zone_state_starts_as_pacific_time_and_takes_the_sims() {
    let (before, after, names) = zoned("Australia/Lord_Howe").run(|| {
        let before = crt_zone_state();
        unsafe { _tzset() };
        let names = unsafe {
            let names = __tzname();
            (
                CStr::from_ptr(*names).to_string_lossy().into_owned(),
                *__timezone(),
            )
        };
        (before, crt_zone_state(), names)
    });
    assert_eq!(before, (28_800, 1, -3600, "PST".into(), "PDT".into()));
    assert_eq!(
        after,
        (
            -37_800,
            1,
            -1800,
            "Lord Howe Standard Time".into(),
            "Lord Howe Daylight Time".into()
        )
    );
    assert_eq!(names, ("Lord Howe Standard Time".into(), -37_800));
}

/// The UCRT applies the current year's rule to every year (2006-04-02 08:30Z reads as 01:30 PDT,
/// where Windows says 00:30 PST), and `_mktime64` of a time in the spring gap with
/// `tm_isdst` -1 lands an hour back, in standard time. Measured with the machine in Pacific
/// Standard Time.
#[test]
fn pacific_ucrt_conversions() {
    let r = zoned("America/Los_Angeles").run(|| {
        (
            crt_local(1_143_966_600),
            crt_local(EPOCH),
            crt_mktime(123, 2, 12, 2, 30, -1),
            crt_mktime(123, 2, 12, 2, 30, 0),
            crt_mktime(123, 10, 5, 1, 30, -1),
            crt_mktime(123, 10, 5, 1, 30, 1),
            crt_mktime(106, 3, 2, 2, 30, -1),
            crt_mktime(69, 11, 31, 23, 0, 0),
            crt_local(100),
        )
    });
    assert_eq!(r.0.0, 0);
    assert_eq!((r.0.1.hour, r.0.1.min, r.0.1.isdst), (1, 30, 1));
    assert_eq!(
        r.1.1,
        Tm {
            sec: 20,
            min: 13,
            hour: 14,
            mday: 14,
            mon: 10,
            year: 123,
            wday: 2,
            yday: 317,
            isdst: 0
        }
    );
    assert_eq!((r.2.0, r.2.1.hour, r.2.1.isdst), (1_678_613_400, 1, 0));
    assert_eq!((r.3.0, r.3.1.hour, r.3.1.isdst), (1_678_617_000, 3, 1));
    assert_eq!((r.4.0, r.4.1.isdst), (1_699_176_600, 0));
    assert_eq!((r.5.0, r.5.1.isdst), (1_699_173_000, 1));
    assert_eq!((r.6.0, r.6.1.hour, r.6.1.isdst), (1_143_970_200, 2, 1));
    assert_eq!(r.7.0, 25_200);
    assert_eq!((r.8.1.year, r.8.1.mday, r.8.1.hour), (69, 31, 16));
}

#[test]
fn ucrt_text_uses_the_sims_zone() {
    let (zone, ctime, narrow, wide_text) = zoned("Europe/Oslo").run(|| {
        let (_, mut tm) = crt_local(EPOCH);
        let standard = crt_strftime(c"%H:%M %z %Z|%%z|%#z", &tm);
        tm.isdst = 1;
        let daylight = crt_strftime(c"%z %Z", &tm);
        let mut buf = [0 as c_char; 32];
        assert_eq!(unsafe { _ctime64_s(buf.as_mut_ptr(), 32, &EPOCH) }, 0);
        let ctime = unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let format: Vec<u16> = "%z %Z\0".encode_utf16().collect();
        let mut out = [0u16; 64];
        let n = unsafe { wcsftime(out.as_mut_ptr(), 64, format.as_ptr(), &tm) };
        let local = unsafe { *_localtime64(&EPOCH) };
        (
            (standard, daylight),
            ctime,
            local,
            String::from_utf16_lossy(&out[..n]),
        )
    });
    assert_eq!(zone.0, "23:13 +0100 W. Europe Standard Time|%z|+0100");
    assert_eq!(zone.1, "+0200 W. Europe Daylight Time");
    assert_eq!(ctime, "Tue Nov 14 23:13:20 2023\n");
    assert_eq!((narrow.hour, narrow.isdst), (23, 0));
    assert_eq!(wide_text, "+0200 W. Europe Daylight Time");
}

#[test]
fn ucrt_range_errors_are_the_ucrts() {
    let (negative, errno, too_late, mktime_early) = zoned("Asia/Tokyo").run(|| {
        unsafe { *_errno() = 0 };
        let negative = crt_local(-1);
        let errno = unsafe { *_errno() };
        let too_late = crt_local(32_536_800_000).0;
        let early = crt_mktime(69, 11, 31, 23, 0, -1).0;
        (negative, errno, too_late, early)
    });
    assert_eq!(negative.0, 22);
    assert_eq!(negative.1.hour, -1);
    assert_eq!((errno, too_late, mktime_early), (22, 22, -1));
}

fn clock_texts() -> (String, String) {
    let mut time = [0 as c_char; 9];
    assert_eq!(unsafe { _strtime_s(time.as_mut_ptr(), 9) }, 0);
    let mut date = [0u16; 9];
    assert!(!unsafe { _wstrdate(date.as_mut_ptr()) }.is_null());
    (
        unsafe { CStr::from_ptr(time.as_ptr()) }
            .to_string_lossy()
            .into_owned(),
        wide(&date),
    )
}

#[test]
fn strtime_and_strdate_read_the_sims_clock_and_zone() {
    assert_eq!(
        zoned("Asia/Tokyo").run(clock_texts),
        ("07:13:20".into(), "11/15/23".into())
    );
}

#[test]
fn ftime_reads_the_sims_clock_and_zone() {
    let zoned = zoned("Europe/Oslo").run(ftime);
    assert_eq!(
        zoned,
        Timeb {
            time: EPOCH,
            millitm: 0,
            timezone: -60,
            dstflag: 0
        }
    );
    let summer = Sim::builder()
        .fixed_epoch()
        .time_zone("Europe/Oslo")
        .build();
    summer.advance_time(std::time::Duration::from_secs(1_719_835_200 - EPOCH as u64));
    assert_eq!(summer.run(ftime).dstflag, 1);
    let plain = Sim::builder().fixed_epoch().build().run(ftime);
    assert_eq!((plain.time, plain.millitm), (EPOCH, 0));
}

#[test]
fn chrono_time_and_jiff_read_the_sims_zone() {
    use chrono::{Offset, TimeZone};
    let (chrono_offset, time_offset, jiff_zone) = zoned("Europe/Oslo").run(|| {
        let summer = chrono::Utc.with_ymd_and_hms(2023, 7, 1, 12, 0, 0).unwrap();
        let chrono_offset = chrono::Local
            .offset_from_utc_datetime(&summer.naive_utc())
            .fix()
            .local_minus_utc();
        let at = time::OffsetDateTime::from_unix_timestamp(1_688_212_800).unwrap();
        let time_offset = time::UtcOffset::local_offset_at(at)
            .unwrap()
            .whole_seconds();
        let system = jiff::tz::TimeZone::try_system().unwrap();
        let jiff_offset = system
            .to_offset(jiff::Timestamp::from_second(1_688_212_800).unwrap())
            .seconds();
        (
            chrono_offset,
            time_offset,
            (system.iana_name().map(str::to_owned), jiff_offset),
        )
    });
    assert_eq!((chrono_offset, time_offset), (7200, 7200));
    assert_eq!(jiff_zone, (Some("Europe/Berlin".into()), 7200));
}

#[test]
fn deterministic_runs_read_the_zone_alike() {
    let run = || {
        Sim::builder()
            .deterministic()
            .time_zone("Australia/Lord_Howe")
            .build()
            .run(|| {
                std::thread::spawn(|| (to_local(EPOCH), crt_local(EPOCH)))
                    .join()
                    .unwrap()
            })
    };
    let (a, b) = (run(), run());
    assert_eq!(a, b);
    assert_eq!(a.0, Some(EPOCH + 11 * 3600));
}

/// Asserts `real` and `sim` agree, naming the first input they differ on.
fn same<I: std::fmt::Debug, T: PartialEq + std::fmt::Debug>(
    what: &str,
    inputs: &[I],
    real: &[T],
    sim: &[T],
) {
    assert_eq!(real.len(), sim.len(), "{what}");
    let differ = real.iter().zip(sim).position(|(r, s)| r != s);
    if let Some(i) = differ {
        let count = real.iter().zip(sim).filter(|(r, s)| r != s).count();
        panic!(
            "{what}: {count} differ, first {:?}: real {:?} sim {:?}",
            inputs[i], real[i], sim[i]
        );
    }
}

/// Every hour of 1999 to 2001 and 2023 to 2025, and every week from 1980 to 2040.
fn instants() -> Vec<i64> {
    let mut v: Vec<i64> = (915_148_800..1_009_843_200).step_by(3600).collect();
    v.extend((1_672_531_200..1_767_225_600).step_by(3600));
    v.extend((315_532_800..2_208_988_800).step_by(7 * 86_400 + 5 * 3600 + 1800));
    v
}

/// With no zone, and with the current rule passed explicitly, which Windows takes for no zone;
/// and with that rule renamed, which it applies as given. The sim runs on the wall clock, so its
/// current rule is the real year's.
#[test]
fn win32_conversions_match_the_os_truth() {
    let key = machine_key();
    let compute = || {
        let mut current: TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
        unsafe { GetTimeZoneInformation(&mut current) };
        let mut renamed = current;
        renamed.StandardName[0] = u16::from(b'#');
        let by = |rule: &TIME_ZONE_INFORMATION| -> Vec<_> {
            instants()
                .iter()
                .map(|&t| (to_local_by(rule, t), to_utc_by(rule, &systemtime(t))))
                .collect()
        };
        let explicit = (by(&current), by(&renamed));
        let instants = instants();
        let locals: Vec<_> = instants.iter().map(|&t| to_local(t)).collect();
        let locals_ex: Vec<_> = instants.iter().map(|&t| to_local_ex(t)).collect();
        let utcs: Vec<_> = instants.iter().map(|&t| to_utc(&systemtime(t))).collect();
        let utcs_ex: Vec<_> = instants
            .iter()
            .map(|&t| to_utc_ex(&systemtime(t)))
            .collect();
        let years: Vec<_> = (1970..2050).map(year_rule).collect();
        (locals, locals_ex, utcs, utcs_ex, years, explicit)
    };
    let real = compute();
    let sim = Sim::builder()
        .wall_clock()
        .time_zone(&key)
        .build()
        .run(compute);
    let at = instants();
    let years: Vec<u16> = (1970..2050).collect();
    same(
        &format!("SystemTimeToTzSpecificLocalTime in {key}"),
        &at,
        &real.0,
        &sim.0,
    );
    same(
        &format!("SystemTimeToTzSpecificLocalTimeEx in {key}"),
        &at,
        &real.1,
        &sim.1,
    );
    same(
        &format!("TzSpecificLocalTimeToSystemTime in {key}"),
        &at,
        &real.2,
        &sim.2,
    );
    same(
        &format!("TzSpecificLocalTimeToSystemTimeEx in {key}"),
        &at,
        &real.3,
        &sim.3,
    );
    same(
        &format!("GetTimeZoneInformationForYear in {key}"),
        &years,
        &real.4,
        &sim.4,
    );
    same(
        &format!("the current rule in {key}"),
        &at,
        &real.5.0,
        &sim.5.0,
    );
    same(
        &format!("a renamed rule in {key}"),
        &at,
        &real.5.1,
        &sim.5.1,
    );
}

#[test]
fn the_current_zone_matches_the_os_truth() {
    let key = machine_key();
    let compute = || {
        let mut local: SYSTEMTIME = unsafe { std::mem::zeroed() };
        let mut system: SYSTEMTIME = unsafe { std::mem::zeroed() };
        unsafe {
            GetSystemTime(&mut system);
            GetLocalTime(&mut local);
        }
        let mut shifted = filetime(0);
        unsafe { FileTimeToLocalFileTime(&filetime(EPOCH), &mut shifted) };
        let tb = ftime();
        (
            (tb.timezone, tb.dstflag),
            zone_information(),
            dynamic_information(),
            (seconds(&local) - seconds(&system) + 30).div_euclid(60),
            ticks(shifted) - ticks(filetime(EPOCH)),
        )
    };
    let real = compute();
    let sim = Sim::builder()
        .wall_clock()
        .time_zone(&key)
        .build()
        .run(compute);
    assert_eq!(real, sim);
}

fn crt_instants() -> Vec<i64> {
    let mut v = instants();
    v.extend([0, 1, 100, 259_200, 32_536_799_999, -1, 32_536_800_000]);
    v
}

type MktimeInput = (c_int, c_int, c_int, c_int, c_int, c_int);

fn mktime_inputs() -> Vec<MktimeInput> {
    let mut v = Vec::new();
    for yday in (0..366).step_by(3) {
        for hour in 0..24 {
            for isdst in [-1, 0, 1] {
                v.push((124, 0, 1 + yday, hour, 30, isdst));
            }
        }
    }
    for year in [69, 70, 1100, 1101, 1102] {
        v.push((year, 0, 1, 0, 0, -1));
        v.push((year, 11, 31, 23, 0, -1));
    }
    v
}

/// The UCRT converts every year by the rule of the year it set the zone in, so the sim runs on
/// the wall clock, in the real year.
#[test]
fn ucrt_local_time_matches_the_os_truth() {
    let key = machine_key();
    unsafe { _tzset() };
    let compute = || {
        unsafe { _tzset() };
        let state = crt_zone_state();
        let locals: Vec<_> = crt_instants().iter().map(|&t| crt_local(t)).collect();
        let made: Vec<_> = mktime_inputs()
            .into_iter()
            .map(|(y, m, d, h, mi, dst)| crt_mktime(y, m, d, h, mi, dst))
            .collect();
        let text: Vec<_> = [0, 1]
            .into_iter()
            .map(|isdst| {
                let tm = Tm {
                    isdst,
                    ..crt_local(EPOCH).1
                };
                crt_strftime(c"%c %z %Z %#z %Ez", &tm)
            })
            .collect();
        (state, locals, made, text)
    };
    let real = compute();
    let sim = Sim::builder()
        .wall_clock()
        .time_zone(&key)
        .build()
        .run(compute);
    assert_eq!(real.0, sim.0, "zone state in {key}");
    same(
        &format!("_localtime64_s in {key}"),
        &crt_instants(),
        &real.1,
        &sim.1,
    );
    same(
        &format!("_mktime64 in {key}"),
        &mktime_inputs(),
        &real.2,
        &sim.2,
    );
    assert_eq!(real.3, sim.3, "strftime in {key}");
}
