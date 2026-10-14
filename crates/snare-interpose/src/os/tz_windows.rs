//! Local time on Windows for a sim that decides its own time zone, and for a sim on a virtual
//! clock.
//!
//! A sim built with a time zone ([`crate::DomainBuilder::time_zone`]) has a Windows zone of its
//! own: the registry's dynamic time zone of that name, or of the Windows zone CLDR maps an IANA
//! name to. Windows converts with that zone's rules for each year (dynamic daylight saving time),
//! so the sim hands every conversion to the OS with the zone named explicitly, in the form that
//! measured identical to the implicit one with the machine set to that zone (Windows 11 26300,
//! Pacific, AUS Eastern, Morocco, Egypt, Lord Howe, Pacific SA and W. Europe, every hour of
//! twelve years and every week of 1980 to 2040):
//!
//! - `SystemTimeToTzSpecificLocalTime` and `TzSpecificLocalTimeToSystemTime` with no zone give
//!   what the same calls give with `GetTimeZoneInformationForYear`'s rule for the given time's
//!   year, which is how the sim makes them; the `Ex` forms with no zone are the `Ex` forms with
//!   the zone's dynamic information. A rule equal to the current zone's is taken by Windows as
//!   "no zone"; any other is applied as given, which the sim keeps by renaming such a rule
//!   before handing it on, so the machine's own zone never matches it.
//! - `GetTimeZoneInformation` and `GetDynamicTimeZoneInformation` report the rule of the current
//!   year, and whether daylight saving time is in effect now; `FileTimeToLocalFileTime`,
//!   `LocalFileTimeToFileTime` and `GetLocalTime` use the offset in effect now.
//!
//! "Now" is the sim's clock. A sim on a virtual clock that decides no zone gets the machine's
//! zone at the sim's time for the calls that depend on now, and everything else from the OS.
//!
//! The UCRT keeps its own copy of the zone (`_tzset`, `_timezone`, `_daylight`, `_dstbias`,
//! `_tzname`) and converts inside itself, where no hook sees it. A sim with a zone of its own
//! gets a C runtime state of its own, as a process starting on a machine in that zone would:
//! the UCRT's initial values (Pacific time) until the first call that sets the zone, then the
//! values `_tzset` derives from `GetTimeZoneInformation`, which the sim's local-time calls
//! convert with by the UCRT's rules (its current-year rule for every year). With `TZ` in the C
//! runtime's environment the UCRT ignores the machine's zone, and the sim leaves it alone.

use std::cell::UnsafeCell;
use std::ffi::{c_char, c_int};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::System::Time::{
    DYNAMIC_TIME_ZONE_INFORMATION, EnumDynamicTimeZoneInformation, FileTimeToSystemTime,
    GetDynamicTimeZoneInformation, GetTimeZoneInformationForYear, SystemTimeToFileTime,
    SystemTimeToTzSpecificLocalTime, SystemTimeToTzSpecificLocalTimeEx, TIME_ZONE_INFORMATION,
    TzSpecificLocalTimeToSystemTime, TzSpecificLocalTimeToSystemTimeEx,
};

use crate::hooks::{Hook, hook, original};
use crate::layer::ClockKind;
use crate::state::Passthrough;

#[path = "windows_zones.rs"]
mod table;

type Tzi = TIME_ZONE_INFORMATION;
type Dtzi = DYNAMIC_TIME_ZONE_INFORMATION;

/// `TIME_ZONE_ID_UNKNOWN`, `TIME_ZONE_ID_STANDARD`, `TIME_ZONE_ID_DAYLIGHT` (timezoneapi.h;
/// [Microsoft Learn: GetTimeZoneInformation](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-gettimezoneinformation)).
const ZONE_UNKNOWN: u32 = 0;
const ZONE_STANDARD: u32 = 1;
const ZONE_DAYLIGHT: u32 = 2;

/// 100 ns intervals from 1601-01-01 to 1970-01-01.
const FILETIME_UNIX_OFFSET: u64 = 116_444_736_000_000_000;

/// corecrt.h `struct tm`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
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
    fn _errno() -> *mut c_int;
    fn _gmtime64_s(tm: *mut Tm, t: *const i64) -> c_int;
    fn _gmtime64(t: *const i64) -> *mut Tm;
    fn asctime(tm: *const Tm) -> *mut c_char;
    fn _wasctime(tm: *const Tm) -> *mut u16;
    fn asctime_s(buf: *mut c_char, size: usize, tm: *const Tm) -> c_int;
    fn _wasctime_s(buf: *mut u16, size: usize, tm: *const Tm) -> c_int;
    fn _wgetenv_s(len: *mut usize, buf: *mut u16, size: usize, name: *const u16) -> c_int;
    fn ___lc_codepage_func() -> u32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn WideCharToMultiByte(
        code_page: u32,
        flags: u32,
        wide: *const u16,
        wide_len: c_int,
        narrow: *mut u8,
        narrow_len: c_int,
        default: *const u8,
        used_default: *mut i32,
    ) -> c_int;
}

const EINVAL: c_int = 22;
const ERANGE: c_int = 34;

/// A sim's time zone: the registry's dynamic time zone information for it, and the sim's
/// C runtime copy of it.
pub(crate) struct Zone {
    dtzi: Dtzi,
    crt: Box<Crt>,
}

impl Zone {
    /// The zone `name` stands for: a Windows zone's registry key name (`"W. Europe Standard
    /// Time"`), or an IANA name CLDR maps to one (`"Europe/Oslo"`); `None` when it names neither
    /// or the registry lacks the zone.
    pub(crate) fn find(name: &str) -> Option<Self> {
        let _passthrough = Passthrough::enter();
        let zones = registry();
        let key = if zones.iter().any(|z| key_of(z) == name) {
            name
        } else {
            table::WINDOWS_ZONES
                .iter()
                .find(|(_, names)| names.split(' ').any(|n| n == name))?
                .0
        };
        let dtzi = zones.into_iter().find(|z| key_of(z) == key)?;
        Some(Zone {
            dtzi,
            crt: Crt::new(),
        })
    }
}

/// Every dynamic time zone in the registry, by `EnumDynamicTimeZoneInformation`, which returns
/// `ERROR_NO_MORE_ITEMS` past the last
/// ([Microsoft Learn: EnumDynamicTimeZoneInformation](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-enumdynamictimezoneinformation)).
fn registry() -> Vec<Dtzi> {
    let mut zones = Vec::new();
    for index in 0.. {
        // SAFETY: an all-zero DYNAMIC_TIME_ZONE_INFORMATION is a valid buffer to fill.
        let mut zone: Dtzi = unsafe { std::mem::zeroed() };
        // SAFETY: a writable DYNAMIC_TIME_ZONE_INFORMATION.
        if unsafe { EnumDynamicTimeZoneInformation(index, &mut zone) } != 0 {
            break;
        }
        zones.push(zone);
    }
    zones
}

fn key_of(zone: &Dtzi) -> String {
    let key = &zone.TimeZoneKeyName;
    let len = key.iter().position(|&c| c == 0).unwrap_or(key.len());
    String::from_utf16_lossy(&key[..len])
}

/// The calling thread's sim zone, `None` in passthrough or when its domain decides none.
fn sim_zone() -> Option<Arc<Zone>> {
    crate::domain::time_zone()
}

/// The zone and the time the calls that depend on now use: the sim's zone at the sim's time
/// (the real time on a wall clock), or, on a virtual clock in a sim that decides no zone, the
/// machine's zone at the sim's time. `None` leaves the call to the OS, as for a machine whose
/// zone does not follow its dynamic rules.
fn now_zone() -> Option<(Dtzi, u64)> {
    if let Some(zone) = sim_zone() {
        return Some((zone.dtzi, sim_now()));
    }
    let now = crate::domain::read_clock(ClockKind::Realtime)
        .map(|now| (now.as_nanos() / 100) as u64 + FILETIME_UNIX_OFFSET)?;
    let _passthrough = Passthrough::enter();
    // SAFETY: an all-zero DYNAMIC_TIME_ZONE_INFORMATION is a valid buffer to fill.
    let mut machine: Dtzi = unsafe { std::mem::zeroed() };
    // SAFETY: a writable DYNAMIC_TIME_ZONE_INFORMATION.
    let id = unsafe { GetDynamicTimeZoneInformation(&mut machine) };
    (id != u32::MAX && !machine.DynamicDaylightTimeDisabled).then_some((machine, now))
}

/// Now as a `FILETIME`: the sim's realtime clock, or the real one on a wall clock. Read outside
/// passthrough, where the sim's clock answers.
fn sim_now() -> u64 {
    crate::domain::read_clock(ClockKind::Realtime)
        .map(|now| (now.as_nanos() / 100) as u64 + FILETIME_UNIX_OFFSET)
        .unwrap_or_else(real_now)
}

fn real_now() -> u64 {
    let _passthrough = Passthrough::enter();
    let mut now = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: a writable FILETIME.
    unsafe { windows_sys::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime(&mut now) };
    to_u64(now)
}

fn to_u64(ft: FILETIME) -> u64 {
    u64::from(ft.dwHighDateTime) << 32 | u64::from(ft.dwLowDateTime)
}

fn to_filetime(v: u64) -> FILETIME {
    FILETIME {
        dwLowDateTime: v as u32,
        dwHighDateTime: (v >> 32) as u32,
    }
}

fn system_time(ft: u64) -> Option<SYSTEMTIME> {
    // SAFETY: an all-zero SYSTEMTIME is a valid buffer to fill.
    let mut st: SYSTEMTIME = unsafe { std::mem::zeroed() };
    // SAFETY: a readable FILETIME and a writable SYSTEMTIME.
    (unsafe { FileTimeToSystemTime(&to_filetime(ft), &mut st) } != 0).then_some(st)
}

fn file_time(st: &SYSTEMTIME) -> Option<u64> {
    let mut ft = to_filetime(0);
    // SAFETY: a readable SYSTEMTIME and a writable FILETIME.
    (unsafe { SystemTimeToFileTime(st, &mut ft) } != 0).then(|| to_u64(ft))
}

/// `zone`'s rule for `year`, by `GetTimeZoneInformationForYear`. Called under passthrough.
fn year_rule(zone: &Dtzi, year: u16) -> Option<Tzi> {
    // SAFETY: an all-zero TIME_ZONE_INFORMATION is a valid buffer to fill.
    let mut rule: Tzi = unsafe { std::mem::zeroed() };
    // SAFETY: a readable DYNAMIC_TIME_ZONE_INFORMATION and a writable TIME_ZONE_INFORMATION.
    (unsafe { GetTimeZoneInformationForYear(year, zone, &mut rule) } != 0).then_some(rule)
}

/// `rule` under a standard name no zone has, so Windows applies it as given rather than taking
/// it for the machine's current zone and applying that zone's dynamic rules.
fn renamed(rule: &Tzi) -> Tzi {
    let mut renamed = *rule;
    renamed.StandardName = [0; 32];
    for (slot, unit) in renamed.StandardName.iter_mut().zip("snare zone".encode_utf16()) {
        *slot = unit;
    }
    renamed
}

fn same_rule(a: &Tzi, b: &Tzi) -> bool {
    a.Bias == b.Bias
        && a.StandardName == b.StandardName
        && same_date(&a.StandardDate, &b.StandardDate)
        && a.StandardBias == b.StandardBias
        && a.DaylightName == b.DaylightName
        && same_date(&a.DaylightDate, &b.DaylightDate)
        && a.DaylightBias == b.DaylightBias
}

fn same_date(a: &SYSTEMTIME, b: &SYSTEMTIME) -> bool {
    (
        a.wYear,
        a.wMonth,
        a.wDayOfWeek,
        a.wDay,
        a.wHour,
        a.wMinute,
        a.wSecond,
        a.wMilliseconds,
    ) == (
        b.wYear,
        b.wMonth,
        b.wDayOfWeek,
        b.wDay,
        b.wHour,
        b.wMinute,
        b.wSecond,
        b.wMilliseconds,
    )
}

/// `zone`'s rule for the year of `now` and its `TIME_ZONE_ID_*`: unknown for a rule without
/// daylight saving time, else daylight or standard as the offset at `now` is.
fn current(zone: &Dtzi, now: u64) -> Option<(Tzi, u32)> {
    let _passthrough = Passthrough::enter();
    let rule = year_rule(zone, system_time(now)?.wYear)?;
    if rule.DaylightDate.wMonth == 0 {
        return Some((rule, ZONE_UNKNOWN));
    }
    let daylight = -i64::from(rule.Bias + rule.DaylightBias) * 600_000_000;
    let standard = -i64::from(rule.Bias + rule.StandardBias) * 600_000_000;
    let offset = offset_at(zone, now)?;
    let id = if offset == daylight && offset != standard {
        ZONE_DAYLIGHT
    } else {
        ZONE_STANDARD
    };
    Some((rule, id))
}

/// The offset of local time in `zone` from UTC at `ft`, in 100 ns units. Called under
/// passthrough.
fn offset_at(zone: &Dtzi, ft: u64) -> Option<i64> {
    let whole = ft - ft % 10_000;
    let utc = system_time(whole)?;
    let rule = renamed(&year_rule(zone, utc.wYear)?);
    // SAFETY: an all-zero SYSTEMTIME is a valid buffer to fill.
    let mut local: SYSTEMTIME = unsafe { std::mem::zeroed() };
    // SAFETY: readable rule and time, a writable SYSTEMTIME.
    if unsafe { SystemTimeToTzSpecificLocalTime(&rule, &utc, &mut local) } == 0 {
        return None;
    }
    Some(file_time(&local)? as i64 - whole as i64)
}

/// The rule a conversion with `given` (null for none) applies in `zone` to a time of `year`:
/// the year's rule when none is given or the given one is the zone's current rule, which
/// Windows takes for no rule; otherwise the given one, renamed. A year with no rule gets the
/// current one, so the OS rejects the time itself.
fn conversion_rule(zone: &Zone, given: *const Tzi, year: u16) -> Option<Tzi> {
    let now = sim_now();
    let _passthrough = Passthrough::enter();
    let current = year_rule(&zone.dtzi, system_time(now)?.wYear)?;
    // SAFETY: a non-null rule is the caller's readable TIME_ZONE_INFORMATION.
    if let Some(given) = unsafe { given.as_ref() }
        && !same_rule(given, &current)
    {
        return Some(renamed(given));
    }
    Some(renamed(&year_rule(&zone.dtzi, year).unwrap_or(current)))
}

static GET_TIME_ZONE_INFORMATION: AtomicUsize = AtomicUsize::new(0);
static GET_DYNAMIC_TIME_ZONE_INFORMATION: AtomicUsize = AtomicUsize::new(0);
static GET_TIME_ZONE_INFORMATION_FOR_YEAR: AtomicUsize = AtomicUsize::new(0);
static SYSTEM_TIME_TO_TZ_SPECIFIC_LOCAL_TIME: AtomicUsize = AtomicUsize::new(0);
static SYSTEM_TIME_TO_TZ_SPECIFIC_LOCAL_TIME_EX: AtomicUsize = AtomicUsize::new(0);
static TZ_SPECIFIC_LOCAL_TIME_TO_SYSTEM_TIME: AtomicUsize = AtomicUsize::new(0);
static TZ_SPECIFIC_LOCAL_TIME_TO_SYSTEM_TIME_EX: AtomicUsize = AtomicUsize::new(0);
static FILE_TIME_TO_LOCAL_FILE_TIME: AtomicUsize = AtomicUsize::new(0);
static LOCAL_FILE_TIME_TO_FILE_TIME: AtomicUsize = AtomicUsize::new(0);
static GET_LOCAL_TIME: AtomicUsize = AtomicUsize::new(0);
static GET_SYSTEM_TIME: AtomicUsize = AtomicUsize::new(0);
static CRT_TZSET: AtomicUsize = AtomicUsize::new(0);
static CRT_TIMEZONE: AtomicUsize = AtomicUsize::new(0);
static CRT_DAYLIGHT: AtomicUsize = AtomicUsize::new(0);
static CRT_DSTBIAS: AtomicUsize = AtomicUsize::new(0);
static CRT_TZNAME: AtomicUsize = AtomicUsize::new(0);
static CRT_GET_TIMEZONE: AtomicUsize = AtomicUsize::new(0);
static CRT_GET_DAYLIGHT: AtomicUsize = AtomicUsize::new(0);
static CRT_GET_DSTBIAS: AtomicUsize = AtomicUsize::new(0);
static CRT_GET_TZNAME: AtomicUsize = AtomicUsize::new(0);
static CRT_LOCALTIME64_S: AtomicUsize = AtomicUsize::new(0);
static CRT_LOCALTIME32_S: AtomicUsize = AtomicUsize::new(0);
static CRT_LOCALTIME64: AtomicUsize = AtomicUsize::new(0);
static CRT_LOCALTIME32: AtomicUsize = AtomicUsize::new(0);
static CRT_MKTIME64: AtomicUsize = AtomicUsize::new(0);
static CRT_MKTIME32: AtomicUsize = AtomicUsize::new(0);
static CRT_CTIME64: AtomicUsize = AtomicUsize::new(0);
static CRT_CTIME32: AtomicUsize = AtomicUsize::new(0);
static CRT_WCTIME64: AtomicUsize = AtomicUsize::new(0);
static CRT_WCTIME32: AtomicUsize = AtomicUsize::new(0);
static CRT_CTIME64_S: AtomicUsize = AtomicUsize::new(0);
static CRT_CTIME32_S: AtomicUsize = AtomicUsize::new(0);
static CRT_WCTIME64_S: AtomicUsize = AtomicUsize::new(0);
static CRT_WCTIME32_S: AtomicUsize = AtomicUsize::new(0);
static CRT_STRFTIME: AtomicUsize = AtomicUsize::new(0);
static CRT_STRFTIME_L: AtomicUsize = AtomicUsize::new(0);
static CRT_STRFTIME_INTERNAL: AtomicUsize = AtomicUsize::new(0);
static CRT_WCSFTIME: AtomicUsize = AtomicUsize::new(0);
static CRT_WCSFTIME_L: AtomicUsize = AtomicUsize::new(0);
static CRT_WCSFTIME_INTERNAL: AtomicUsize = AtomicUsize::new(0);
static CRT_FTIME64_S: AtomicUsize = AtomicUsize::new(0);
static CRT_FTIME32_S: AtomicUsize = AtomicUsize::new(0);
static CRT_FTIME64: AtomicUsize = AtomicUsize::new(0);
static CRT_FTIME32: AtomicUsize = AtomicUsize::new(0);
static CRT_STRTIME_S: AtomicUsize = AtomicUsize::new(0);
static CRT_WSTRTIME_S: AtomicUsize = AtomicUsize::new(0);
static CRT_STRTIME: AtomicUsize = AtomicUsize::new(0);
static CRT_WSTRTIME: AtomicUsize = AtomicUsize::new(0);
static CRT_STRDATE_S: AtomicUsize = AtomicUsize::new(0);
static CRT_WSTRDATE_S: AtomicUsize = AtomicUsize::new(0);
static CRT_STRDATE: AtomicUsize = AtomicUsize::new(0);
static CRT_WSTRDATE: AtomicUsize = AtomicUsize::new(0);

/// The local-time hooks: kernel32's zone and conversion calls, and the UCRT's time zone state
/// and conversions as binaries linked against the UCRT import them.
pub(super) fn hooks() -> Vec<Hook> {
    vec![
        hook!(
            "GetTimeZoneInformation",
            "kernel32.dll",
            get_time_zone_information,
            GET_TIME_ZONE_INFORMATION
        ),
        hook!(
            "GetDynamicTimeZoneInformation",
            "kernel32.dll",
            get_dynamic_time_zone_information,
            GET_DYNAMIC_TIME_ZONE_INFORMATION
        ),
        hook!(
            "GetTimeZoneInformationForYear",
            "kernel32.dll",
            get_time_zone_information_for_year,
            GET_TIME_ZONE_INFORMATION_FOR_YEAR
        ),
        hook!(
            "SystemTimeToTzSpecificLocalTime",
            "kernel32.dll",
            system_time_to_tz_specific_local_time,
            SYSTEM_TIME_TO_TZ_SPECIFIC_LOCAL_TIME
        ),
        hook!(
            "SystemTimeToTzSpecificLocalTimeEx",
            "kernel32.dll",
            system_time_to_tz_specific_local_time_ex,
            SYSTEM_TIME_TO_TZ_SPECIFIC_LOCAL_TIME_EX
        ),
        hook!(
            "TzSpecificLocalTimeToSystemTime",
            "kernel32.dll",
            tz_specific_local_time_to_system_time,
            TZ_SPECIFIC_LOCAL_TIME_TO_SYSTEM_TIME
        ),
        hook!(
            "TzSpecificLocalTimeToSystemTimeEx",
            "kernel32.dll",
            tz_specific_local_time_to_system_time_ex,
            TZ_SPECIFIC_LOCAL_TIME_TO_SYSTEM_TIME_EX
        ),
        hook!(
            "FileTimeToLocalFileTime",
            "kernel32.dll",
            file_time_to_local_file_time,
            FILE_TIME_TO_LOCAL_FILE_TIME
        ),
        hook!(
            "LocalFileTimeToFileTime",
            "kernel32.dll",
            local_file_time_to_file_time,
            LOCAL_FILE_TIME_TO_FILE_TIME
        ),
        hook!("GetLocalTime", "kernel32.dll", get_local_time, GET_LOCAL_TIME),
        hook!(
            "GetSystemTime",
            "kernel32.dll",
            get_system_time,
            GET_SYSTEM_TIME
        ),
        Hook {
            module: CRT_TIME,
            ..hook!("_tzset", crt_tzset, CRT_TZSET)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("__timezone", crt_timezone, CRT_TIMEZONE)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("__daylight", crt_daylight, CRT_DAYLIGHT)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("__dstbias", crt_dstbias, CRT_DSTBIAS)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("__tzname", crt_tzname, CRT_TZNAME)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_get_timezone", crt_get_timezone, CRT_GET_TIMEZONE)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_get_daylight", crt_get_daylight, CRT_GET_DAYLIGHT)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_get_dstbias", crt_get_dstbias, CRT_GET_DSTBIAS)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_get_tzname", crt_get_tzname, CRT_GET_TZNAME)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_localtime64_s", crt_localtime64_s, CRT_LOCALTIME64_S)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_localtime32_s", crt_localtime32_s, CRT_LOCALTIME32_S)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_localtime64", crt_localtime64, CRT_LOCALTIME64)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_localtime32", crt_localtime32, CRT_LOCALTIME32)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_mktime64", crt_mktime64, CRT_MKTIME64)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_mktime32", crt_mktime32, CRT_MKTIME32)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_ctime64", crt_ctime64, CRT_CTIME64)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_ctime32", crt_ctime32, CRT_CTIME32)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_wctime64", crt_wctime64, CRT_WCTIME64)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_wctime32", crt_wctime32, CRT_WCTIME32)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_ctime64_s", crt_ctime64_s, CRT_CTIME64_S)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_ctime32_s", crt_ctime32_s, CRT_CTIME32_S)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_wctime64_s", crt_wctime64_s, CRT_WCTIME64_S)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_wctime32_s", crt_wctime32_s, CRT_WCTIME32_S)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("strftime", crt_strftime, CRT_STRFTIME)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_strftime_l", crt_strftime_l, CRT_STRFTIME_L)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_Strftime", crt_strftime_internal, CRT_STRFTIME_INTERNAL)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("wcsftime", crt_wcsftime, CRT_WCSFTIME)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_wcsftime_l", crt_wcsftime_l, CRT_WCSFTIME_L)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_Wcsftime", crt_wcsftime_internal, CRT_WCSFTIME_INTERNAL)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_ftime64_s", crt_ftime64_s, CRT_FTIME64_S)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_ftime32_s", crt_ftime32_s, CRT_FTIME32_S)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_ftime64", crt_ftime64, CRT_FTIME64)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_ftime32", crt_ftime32, CRT_FTIME32)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_strtime_s", crt_strtime_s, CRT_STRTIME_S)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_wstrtime_s", crt_wstrtime_s, CRT_WSTRTIME_S)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_strtime", crt_strtime, CRT_STRTIME)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_wstrtime", crt_wstrtime, CRT_WSTRTIME)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_strdate_s", crt_strdate_s, CRT_STRDATE_S)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_wstrdate_s", crt_wstrdate_s, CRT_WSTRDATE_S)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_strdate", crt_strdate, CRT_STRDATE)
        },
        Hook {
            module: CRT_TIME,
            ..hook!("_wstrdate", crt_wstrdate, CRT_WSTRDATE)
        },
    ]
}

/// The API set the UCRT's time functions are imported through (the import name binaries linked
/// against the UCRT carry).
const CRT_TIME: &str = "api-ms-win-crt-time-l1-1-0.dll";

/// `GetTimeZoneInformation`: the current year's rule and whether daylight saving time is in
/// effect now
/// ([Microsoft Learn: GetTimeZoneInformation](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-gettimezoneinformation)).
unsafe extern "system" fn get_time_zone_information(out: *mut Tzi) -> u32 {
    if !out.is_null()
        && let Some((zone, now)) = now_zone()
        && let Some((rule, id)) = current(&zone, now)
    {
        // SAFETY: the caller passed a writable TIME_ZONE_INFORMATION.
        unsafe { out.write(rule) };
        return id;
    }
    // SAFETY: GET_TIME_ZONE_INFORMATION holds kernel32's GetTimeZoneInformation.
    unsafe { original::<unsafe extern "system" fn(*mut Tzi) -> u32>(&GET_TIME_ZONE_INFORMATION)(out) }
}

/// `GetDynamicTimeZoneInformation`: as [`get_time_zone_information`], with the zone's registry
/// key name
/// ([Microsoft Learn: GetDynamicTimeZoneInformation](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-getdynamictimezoneinformation)).
/// jiff names the system zone from the key.
unsafe extern "system" fn get_dynamic_time_zone_information(out: *mut Dtzi) -> u32 {
    if !out.is_null()
        && let Some((zone, now)) = now_zone()
        && let Some((rule, id)) = current(&zone, now)
    {
        let info = Dtzi {
            Bias: rule.Bias,
            StandardName: rule.StandardName,
            StandardDate: rule.StandardDate,
            StandardBias: rule.StandardBias,
            DaylightName: rule.DaylightName,
            DaylightDate: rule.DaylightDate,
            DaylightBias: rule.DaylightBias,
            TimeZoneKeyName: zone.TimeZoneKeyName,
            DynamicDaylightTimeDisabled: zone.DynamicDaylightTimeDisabled,
        };
        // SAFETY: the caller passed a writable DYNAMIC_TIME_ZONE_INFORMATION.
        unsafe { out.write(info) };
        return id;
    }
    // SAFETY: GET_DYNAMIC_TIME_ZONE_INFORMATION holds kernel32's GetDynamicTimeZoneInformation.
    unsafe {
        original::<unsafe extern "system" fn(*mut Dtzi) -> u32>(&GET_DYNAMIC_TIME_ZONE_INFORMATION)(
            out,
        )
    }
}

/// `GetTimeZoneInformationForYear`: with no zone given, the sim's
/// ([Microsoft Learn: GetTimeZoneInformationForYear](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-gettimezoneinformationforyear)).
/// chrono's `Local` reads its offsets from it.
unsafe extern "system" fn get_time_zone_information_for_year(
    year: u16,
    zone: *const Dtzi,
    out: *mut Tzi,
) -> i32 {
    let sim = zone.is_null().then(sim_zone).flatten();
    let zone = sim.as_ref().map_or(zone, |sim| &sim.dtzi as *const Dtzi);
    // SAFETY: GET_TIME_ZONE_INFORMATION_FOR_YEAR holds kernel32's GetTimeZoneInformationForYear;
    // `zone` is the caller's or the sim's.
    unsafe {
        original::<unsafe extern "system" fn(u16, *const Dtzi, *mut Tzi) -> i32>(
            &GET_TIME_ZONE_INFORMATION_FOR_YEAR,
        )(year, zone, out)
    }
}

/// `SystemTimeToTzSpecificLocalTime`: UTC to local time with `rule`, or the sim's zone for none
/// or its current rule; see the module documentation
/// ([Microsoft Learn: SystemTimeToTzSpecificLocalTime](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-systemtimetotzspecificlocaltime)).
/// The `time` crate's local offset comes from it.
unsafe extern "system" fn system_time_to_tz_specific_local_time(
    rule: *const Tzi,
    utc: *const SYSTEMTIME,
    local: *mut SYSTEMTIME,
) -> i32 {
    // SAFETY: a non-null time is the caller's readable SYSTEMTIME.
    if let Some(year) = unsafe { utc.as_ref() }.map(|t| t.wYear)
        && !local.is_null()
        && let Some(zone) = sim_zone()
        && let Some(applied) = conversion_rule(&zone, rule, year)
    {
        let _passthrough = Passthrough::enter();
        // SAFETY: the rule above and the caller's times.
        return unsafe { SystemTimeToTzSpecificLocalTime(&applied, utc, local) };
    }
    // SAFETY: SYSTEM_TIME_TO_TZ_SPECIFIC_LOCAL_TIME holds the kernel32 function.
    unsafe {
        original::<
            unsafe extern "system" fn(*const Tzi, *const SYSTEMTIME, *mut SYSTEMTIME) -> i32,
        >(&SYSTEM_TIME_TO_TZ_SPECIFIC_LOCAL_TIME)(rule, utc, local)
    }
}

/// `TzSpecificLocalTimeToSystemTime`: the inverse, by the same rule
/// ([Microsoft Learn: TzSpecificLocalTimeToSystemTime](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-tzspecificlocaltimetosystemtime)).
unsafe extern "system" fn tz_specific_local_time_to_system_time(
    rule: *const Tzi,
    local: *const SYSTEMTIME,
    utc: *mut SYSTEMTIME,
) -> i32 {
    // SAFETY: a non-null time is the caller's readable SYSTEMTIME.
    if let Some(year) = unsafe { local.as_ref() }.map(|t| t.wYear)
        && !utc.is_null()
        && let Some(zone) = sim_zone()
        && let Some(applied) = conversion_rule(&zone, rule, year)
    {
        let _passthrough = Passthrough::enter();
        // SAFETY: the rule above and the caller's times.
        return unsafe { TzSpecificLocalTimeToSystemTime(&applied, local, utc) };
    }
    // SAFETY: TZ_SPECIFIC_LOCAL_TIME_TO_SYSTEM_TIME holds the kernel32 function.
    unsafe {
        original::<
            unsafe extern "system" fn(*const Tzi, *const SYSTEMTIME, *mut SYSTEMTIME) -> i32,
        >(&TZ_SPECIFIC_LOCAL_TIME_TO_SYSTEM_TIME)(rule, local, utc)
    }
}

/// `SystemTimeToTzSpecificLocalTimeEx`: with no zone given, the sim's
/// ([Microsoft Learn: SystemTimeToTzSpecificLocalTimeEx](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-systemtimetotzspecificlocaltimeex)).
unsafe extern "system" fn system_time_to_tz_specific_local_time_ex(
    zone: *const Dtzi,
    utc: *const SYSTEMTIME,
    local: *mut SYSTEMTIME,
) -> i32 {
    if zone.is_null()
        && let Some(sim) = sim_zone()
    {
        let _passthrough = Passthrough::enter();
        // SAFETY: the sim's zone and the caller's times.
        return unsafe { SystemTimeToTzSpecificLocalTimeEx(&sim.dtzi, utc, local) };
    }
    // SAFETY: SYSTEM_TIME_TO_TZ_SPECIFIC_LOCAL_TIME_EX holds the kernel32 function.
    unsafe {
        original::<
            unsafe extern "system" fn(*const Dtzi, *const SYSTEMTIME, *mut SYSTEMTIME) -> i32,
        >(&SYSTEM_TIME_TO_TZ_SPECIFIC_LOCAL_TIME_EX)(zone, utc, local)
    }
}

/// `TzSpecificLocalTimeToSystemTimeEx`: with no zone given, the sim's
/// ([Microsoft Learn: TzSpecificLocalTimeToSystemTimeEx](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-tzspecificlocaltimetosystemtimeex)).
unsafe extern "system" fn tz_specific_local_time_to_system_time_ex(
    zone: *const Dtzi,
    local: *const SYSTEMTIME,
    utc: *mut SYSTEMTIME,
) -> i32 {
    if zone.is_null()
        && let Some(sim) = sim_zone()
    {
        let _passthrough = Passthrough::enter();
        // SAFETY: the sim's zone and the caller's times.
        return unsafe { TzSpecificLocalTimeToSystemTimeEx(&sim.dtzi, local, utc) };
    }
    // SAFETY: TZ_SPECIFIC_LOCAL_TIME_TO_SYSTEM_TIME_EX holds the kernel32 function.
    unsafe {
        original::<
            unsafe extern "system" fn(*const Dtzi, *const SYSTEMTIME, *mut SYSTEMTIME) -> i32,
        >(&TZ_SPECIFIC_LOCAL_TIME_TO_SYSTEM_TIME_EX)(zone, local, utc)
    }
}

/// The offset in effect now, for the calls that convert by it.
fn offset_now() -> Option<i64> {
    let (zone, now) = now_zone()?;
    let _passthrough = Passthrough::enter();
    offset_at(&zone, now)
}

/// `FileTimeToLocalFileTime`: `ft` moved by the offset in effect now, whatever time `ft` is
/// ([Microsoft Learn: FileTimeToLocalFileTime](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-filetimetolocalfiletime)).
unsafe extern "system" fn file_time_to_local_file_time(
    ft: *const FILETIME,
    local: *mut FILETIME,
) -> i32 {
    if !ft.is_null()
        && !local.is_null()
        && let Some(offset) = offset_now()
    {
        // SAFETY: the caller's readable and writable FILETIMEs.
        unsafe { local.write(to_filetime(to_u64(*ft).wrapping_add_signed(offset))) };
        return 1;
    }
    // SAFETY: FILE_TIME_TO_LOCAL_FILE_TIME holds the kernel32 function.
    unsafe {
        original::<unsafe extern "system" fn(*const FILETIME, *mut FILETIME) -> i32>(
            &FILE_TIME_TO_LOCAL_FILE_TIME,
        )(ft, local)
    }
}

/// `LocalFileTimeToFileTime`: the inverse, by the offset in effect now
/// ([Microsoft Learn: LocalFileTimeToFileTime](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-localfiletimetofiletime)).
unsafe extern "system" fn local_file_time_to_file_time(
    local: *const FILETIME,
    ft: *mut FILETIME,
) -> i32 {
    if !local.is_null()
        && !ft.is_null()
        && let Some(offset) = offset_now()
    {
        // SAFETY: the caller's readable and writable FILETIMEs.
        unsafe { ft.write(to_filetime(to_u64(*local).wrapping_add_signed(-offset))) };
        return 1;
    }
    // SAFETY: LOCAL_FILE_TIME_TO_FILE_TIME holds the kernel32 function.
    unsafe {
        original::<unsafe extern "system" fn(*const FILETIME, *mut FILETIME) -> i32>(
            &LOCAL_FILE_TIME_TO_FILE_TIME,
        )(local, ft)
    }
}

/// Now in local time, by the offset in effect now; `None` leaves it to the OS.
fn local_now() -> Option<SYSTEMTIME> {
    let (zone, now) = now_zone()?;
    let _passthrough = Passthrough::enter();
    offset_at(&zone, now).and_then(|offset| system_time(now.wrapping_add_signed(offset)))
}

/// `GetLocalTime`: now in local time
/// ([Microsoft Learn: GetLocalTime](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlocaltime)).
unsafe extern "system" fn get_local_time(out: *mut SYSTEMTIME) {
    if !out.is_null()
        && let Some(local) = local_now()
    {
        // SAFETY: the caller passed a writable SYSTEMTIME.
        unsafe { out.write(local) };
        return;
    }
    // SAFETY: GET_LOCAL_TIME holds kernel32's GetLocalTime.
    unsafe { original::<unsafe extern "system" fn(*mut SYSTEMTIME)>(&GET_LOCAL_TIME)(out) }
}

/// `GetSystemTime`: now in UTC, on the sim's realtime clock
/// ([Microsoft Learn: GetSystemTime](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtime)).
/// Like `GetLocalTime` it reads the clock inside kernel32, where no hook sees it.
unsafe extern "system" fn get_system_time(out: *mut SYSTEMTIME) {
    if !out.is_null()
        && let Some(now) = crate::domain::read_clock(ClockKind::Realtime)
    {
        let _passthrough = Passthrough::enter();
        if let Some(utc) = system_time((now.as_nanos() / 100) as u64 + FILETIME_UNIX_OFFSET) {
            // SAFETY: the caller passed a writable SYSTEMTIME.
            unsafe { out.write(utc) };
            return;
        }
    }
    // SAFETY: GET_SYSTEM_TIME holds kernel32's GetSystemTime.
    unsafe { original::<unsafe extern "system" fn(*mut SYSTEMTIME)>(&GET_SYSTEM_TIME)(out) }
}

/// The UCRT's zone state as a sim holds it: `_timezone`, `_daylight`, `_dstbias` and the
/// `_tzname` strings at stable addresses, since `__timezone()` and the rest hand out pointers to
/// them, and the rule `_tzset` read from `GetTimeZoneInformation`.
struct Crt {
    /// Whether the zone has been set once, as the UCRT's `__tzset` does on the first call that
    /// needs it (tzset.cpp `tzset_init_state`).
    set: AtomicBool,
    timezone: AtomicI32,
    daylight: AtomicI32,
    dstbias: AtomicI32,
    names: UnsafeCell<Names>,
    state: Mutex<CrtState>,
}

// SAFETY: `names` is written only under `state`'s lock, by `_tzset`; the code under test reads
// and may write it through the pointers `__tzname()` returns, as it would the UCRT's own.
unsafe impl Sync for Crt {}
// SAFETY: the pointers in `names` point into the same box, which moves with it.
unsafe impl Send for Crt {}

/// `_tzname`: the two pointers `__tzname()` returns, the narrow strings they point to, and the
/// wide ones `wcsftime`'s `%Z` reads (timeset.cpp `tzname_states`, `_TZ_STRINGS_SIZE` 64).
struct Names {
    pointers: [*mut c_char; 2],
    narrow: [[c_char; 64]; 2],
    wide: [[u16; 64]; 2],
}

struct CrtState {
    /// The rule `_tzset` read (tzset.cpp `tz_info`).
    rule: Tzi,
}

impl Crt {
    /// The UCRT's state before anything sets the zone: Pacific time (timeset.cpp
    /// `__acrt_initialize_timeset`; measured on Windows 11 26300 in every zone).
    fn new() -> Box<Self> {
        let mut names = Names {
            pointers: [std::ptr::null_mut(); 2],
            narrow: [[0; 64]; 2],
            wide: [[0; 64]; 2],
        };
        for (i, name) in ["PST", "PDT"].into_iter().enumerate() {
            for (j, b) in name.bytes().enumerate() {
                names.narrow[i][j] = b as c_char;
                names.wide[i][j] = u16::from(b);
            }
        }
        let crt = Box::new(Crt {
            set: AtomicBool::new(false),
            timezone: AtomicI32::new(8 * 3600),
            daylight: AtomicI32::new(1),
            dstbias: AtomicI32::new(-3600),
            names: UnsafeCell::new(names),
            state: Mutex::new(CrtState {
                // SAFETY: all-zero is a valid TIME_ZONE_INFORMATION.
                rule: unsafe { std::mem::zeroed() },
            }),
        });
        let names = crt.names.get();
        // SAFETY: nothing else has seen `names` yet; the box keeps the strings where they are.
        unsafe {
            (*names).pointers = [
                (*names).narrow[0].as_mut_ptr(),
                (*names).narrow[1].as_mut_ptr(),
            ];
        }
        crt
    }

    /// `__tzset`: sets the zone the first time it is needed. Called outside passthrough.
    fn ensure(&self, zone: &Dtzi) {
        if self.set.load(Ordering::Acquire) {
            return;
        }
        let now = sim_now();
        let _passthrough = Passthrough::enter();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !self.set.load(Ordering::Relaxed) {
            self.tzset(zone, now, &mut state);
            self.set.store(true, Ordering::Release);
        }
    }

    /// tzset.cpp `tzset_from_system_nolock`: `_timezone` is the standard offset west in seconds,
    /// `_daylight` whether the rule has daylight saving time with a bias, `_dstbias` the
    /// daylight bias beyond the standard one, and `_tzname` the rule's names, the narrow ones
    /// in the current code page.
    fn tzset(&self, zone: &Dtzi, now: u64, state: &mut CrtState) {
        let Some((rule, _)) = current(zone, now) else {
            return;
        };
        let mut timezone = rule.Bias * 60;
        if rule.StandardDate.wMonth != 0 {
            timezone += rule.StandardBias * 60;
        }
        let (daylight, dstbias) = if rule.DaylightDate.wMonth != 0 && rule.DaylightBias != 0 {
            (1, (rule.DaylightBias - rule.StandardBias) * 60)
        } else {
            (0, 0)
        };
        self.timezone.store(timezone, Ordering::Relaxed);
        self.daylight.store(daylight, Ordering::Relaxed);
        self.dstbias.store(dstbias, Ordering::Relaxed);
        // SAFETY: a valid call with no arguments.
        let code_page = unsafe { ___lc_codepage_func() };
        let names = self.names.get();
        for (i, name) in [rule.StandardName, rule.DaylightName].iter().enumerate() {
            let mut wide = [0u16; 64];
            let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
            wide[..len].copy_from_slice(&name[..len]);
            let mut narrow = [0 as c_char; 64];
            // SAFETY: a NUL-terminated wide string and a 64-byte buffer.
            unsafe {
                WideCharToMultiByte(
                    code_page,
                    0,
                    wide.as_ptr(),
                    -1,
                    narrow.as_mut_ptr().cast(),
                    64,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                )
            };
            // SAFETY: `names` lives in the box; writers hold `state`'s lock.
            unsafe {
                (*names).wide[i] = wide;
                (*names).narrow[i] = narrow;
            }
        }
        state.rule = rule;
    }

    fn values(&self) -> (i64, bool, i64) {
        (
            i64::from(self.timezone.load(Ordering::Relaxed)),
            self.daylight.load(Ordering::Relaxed) != 0,
            i64::from(self.dstbias.load(Ordering::Relaxed)),
        )
    }

    fn rule(&self) -> Tzi {
        let _passthrough = Passthrough::enter();
        self.state.lock().unwrap_or_else(|e| e.into_inner()).rule
    }
}

/// The calling thread's sim zone for the UCRT's calls: `None` without one, or when `TZ` is set
/// in the C runtime's environment, which the UCRT then reads instead of the machine's zone
/// (tzset.cpp `tzset_nolock`).
fn crt_zone() -> Option<Arc<Zone>> {
    let zone = sim_zone()?;
    let _passthrough = Passthrough::enter();
    let mut len = 0;
    let mut value = [0u16; 2];
    let name = [u16::from(b'T'), u16::from(b'Z'), 0];
    // SAFETY: a two-unit buffer and a NUL-terminated name.
    let status = unsafe { _wgetenv_s(&mut len, value.as_mut_ptr(), 2, name.as_ptr()) };
    (status != ERANGE && (status != 0 || value[0] == 0)).then_some(zone)
}

fn set_errno(errno: c_int) {
    // SAFETY: the calling thread's errno.
    unsafe { *_errno() = errno };
}

/// The largest `__time64_t` and `__time32_t` the UCRT's `_localtime64_s` and `_localtime32_s`
/// accept, 3001-01-19 07:59:59 and 2038-01-18 23:59:59 UTC (measured on Windows 11 26300 in
/// three zones; corecrt.h's `_MAX__TIME32_T`).
const MAX_TIME64: i64 = 32_536_799_999;
const MAX_TIME32: i64 = 0x7fff_d27f;

/// localtime.cpp `common_localtime_s` for a time it accepts, `max` being the type's largest:
/// the time moved west by `_timezone` and broken down, and by `_dstbias` more when `_isindst`
/// finds the result in daylight saving time. Within three days of either end of the range the
/// UTC time is broken down and its fields moved instead, `_isindst` judging the UTC time. `0`,
/// or the errno `_gmtime64_s` failed with.
fn crt_local(zone: &Zone, t: i64, tm: &mut Tm, max: i64) -> c_int {
    const DAY: i64 = 86_400;
    zone.crt.ensure(&zone.dtzi);
    let (timezone, daylight, dstbias) = zone.crt.values();
    if t > 3 * DAY && t < max - 3 * DAY {
        let mut local = t - timezone;
        // SAFETY: a writable struct tm and a readable time.
        let status = unsafe { _gmtime64_s(tm, &local) };
        if status != 0 {
            return status;
        }
        if daylight && in_daylight_time(&zone.crt.rule(), dstbias, tm) {
            local -= dstbias;
            // SAFETY: as above.
            let status = unsafe { _gmtime64_s(tm, &local) };
            if status != 0 {
                return status;
            }
            tm.isdst = 1;
        }
        return 0;
    }
    // SAFETY: a writable struct tm and a readable time.
    let status = unsafe { _gmtime64_s(tm, &t) };
    if status != 0 {
        return status;
    }
    let mut carry = i64::from(tm.sec);
    if daylight && in_daylight_time(&zone.crt.rule(), dstbias, tm) {
        carry -= timezone + dstbias;
        tm.isdst = 1;
    } else {
        carry -= timezone;
    }
    carry = settle(&mut tm.sec, carry, 60);
    let minutes = i64::from(tm.min) + carry / 60;
    carry = settle(&mut tm.min, minutes, 60);
    let hours = i64::from(tm.hour) + carry / 60;
    carry = settle(&mut tm.hour, hours, 24);
    let days = carry / 24;
    if days > 0 {
        tm.wday = ((i64::from(tm.wday) + days) % 7) as c_int;
        tm.mday += days as c_int;
        tm.yday += days as c_int;
    } else if days < 0 {
        tm.wday = ((i64::from(tm.wday) + 7 + days) % 7) as c_int;
        tm.mday += days as c_int;
        if tm.mday <= 0 {
            tm.mday += 31;
            tm.yday += days as c_int + 365;
            tm.mon = 11;
            tm.year -= 1;
        } else {
            tm.yday += days as c_int;
        }
    }
    0
}

/// Sets `field` to `carry` modulo `unit`, borrowing a unit when that is negative, and returns
/// what is left to carry, as localtime.cpp's field-by-field adjustment does.
fn settle(field: &mut c_int, mut carry: i64, unit: i64) -> i64 {
    *field = (carry % unit) as c_int;
    if *field < 0 {
        *field += unit as c_int;
        carry -= unit;
    }
    carry
}

/// The days before each month, less one, of a common and a leap year (corecrt_internal_time.h
/// `_days`, `_lpdays`).
const DAYS: [i64; 13] = [-1, 30, 58, 89, 119, 150, 180, 211, 242, 272, 303, 333, 364];
const LEAP_DAYS: [i64; 13] = [-1, 30, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365];

/// corecrt_internal_time.h `__crt_time_is_leap_year`, for years since 1900.
fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year + 1900) % 400 == 0
}

/// corecrt_internal_time.h `__crt_time_elapsed_leap_years`: leap years from 1970 to `year`.
fn elapsed_leap_years(year: i64) -> i64 {
    (year - 1) / 4 - (year - 1) / 100 + (year + 299) / 400 - 17
}

/// tzset.cpp `cvtdate`: the day of the year and millisecond of the day, in local standard time,
/// a rule date falls on in `year` (years since 1900). A date with no year is the `wDay`th
/// (5: last) `wDayOfWeek` of `wMonth`; with one, that month's `wDay`. The end of daylight
/// saving time is given in daylight time, so `end_bias` (`_dstbias`) moves it to standard time.
fn rule_day(year: i64, date: &SYSTEMTIME, end_bias: Option<i64>) -> Option<(i64, i64)> {
    let days = if is_leap(year) { &LEAP_DAYS } else { &DAYS };
    let month = usize::from(date.wMonth);
    if !(1..=12).contains(&month) {
        return None;
    }
    let mut yday = if date.wYear == 0 {
        let mut yday = 1 + days[month - 1];
        let first = (yday + (year - 70) * 365 + elapsed_leap_years(year) + 4) % 7;
        let (week, weekday) = (i64::from(date.wDay), i64::from(date.wDayOfWeek));
        yday += if first <= weekday {
            weekday - first + (week - 1) * 7
        } else {
            weekday - first + week * 7
        };
        if week == 5 && yday > days[month] {
            yday -= 7;
        }
        yday
    } else {
        days[month - 1] + i64::from(date.wDay)
    };
    let mut ms = i64::from(date.wMilliseconds)
        + 1000
            * (i64::from(date.wSecond)
                + 60 * (i64::from(date.wMinute) + 60 * i64::from(date.wHour)));
    if let Some(bias) = end_bias {
        ms += bias * 1000;
        if ms < 0 {
            ms += 86_400_000;
            yday -= 1;
        } else if ms >= 86_400_000 {
            ms -= 86_400_000;
            yday += 1;
        }
    }
    Some((yday, ms))
}

/// tzset.cpp `_isindst_nolock`: whether the local standard time `tm` falls in daylight saving
/// time by `rule`'s dates in `tm`'s year.
fn in_daylight_time(rule: &Tzi, dstbias: i64, tm: &Tm) -> bool {
    let year = i64::from(tm.year);
    let (Some((start, start_ms)), Some((end, end_ms))) = (
        rule_day(year, &rule.DaylightDate, None),
        rule_day(year, &rule.StandardDate, Some(dstbias)),
    ) else {
        return false;
    };
    let yday = i64::from(tm.yday);
    if start < end {
        if yday < start || yday > end {
            return false;
        }
        if yday > start && yday < end {
            return true;
        }
    } else {
        if yday < end || yday > start {
            return true;
        }
        if yday > end && yday < start {
            return false;
        }
    }
    let ms = 1000 * (i64::from(tm.sec) + 60 * i64::from(tm.min) + 3600 * i64::from(tm.hour));
    if yday == start {
        ms >= start_ms
    } else {
        ms < end_ms
    }
}

/// localtime.cpp `common_localtime_s` for a `__time64_t` (`wide`) or `__time32_t`: `None` when the
/// UCRT's own checks reject the arguments, which it does before reading the zone.
fn sim_localtime(tm: *mut Tm, t: Option<i64>, wide: bool) -> Option<c_int> {
    let max = if wide { MAX_TIME64 } else { MAX_TIME32 };
    let t = t.filter(|t| (0..=max).contains(t))?;
    if tm.is_null() {
        return None;
    }
    let zone = crt_zone()?;
    // SAFETY: the caller's writable struct tm, filled with 0xff first as the UCRT does.
    let tm = unsafe {
        tm.write_bytes(0xff, 1);
        &mut *tm
    };
    Some(crt_local(&zone, t, tm, max))
}

/// `_localtime64_s` ([Microsoft Learn: localtime_s, _localtime32_s, _localtime64_s](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/localtime-s-localtime32-s-localtime64-s)).
unsafe extern "C" fn crt_localtime64_s(tm: *mut Tm, t: *const i64) -> c_int {
    // SAFETY: a non-null time is the caller's readable __time64_t.
    if let Some(r) = sim_localtime(tm, unsafe { t.as_ref() }.copied(), true) {
        return r;
    }
    // SAFETY: CRT_LOCALTIME64_S holds the UCRT's _localtime64_s.
    unsafe {
        original::<unsafe extern "C" fn(*mut Tm, *const i64) -> c_int>(&CRT_LOCALTIME64_S)(tm, t)
    }
}

/// `_localtime32_s`.
unsafe extern "C" fn crt_localtime32_s(tm: *mut Tm, t: *const i32) -> c_int {
    // SAFETY: a non-null time is the caller's readable __time32_t.
    if let Some(r) = sim_localtime(tm, unsafe { t.as_ref() }.map(|&t| i64::from(t)), false) {
        return r;
    }
    // SAFETY: CRT_LOCALTIME32_S holds the UCRT's _localtime32_s.
    unsafe {
        original::<unsafe extern "C" fn(*mut Tm, *const i32) -> c_int>(&CRT_LOCALTIME32_S)(tm, t)
    }
}

/// `_localtime64` and `_localtime32` (C's `localtime`): into the thread's buffer, the one
/// `gmtime` also fills (localtime.cpp `common_localtime`, `__getgmtimebuf`), or null.
fn sim_localtime_buffer(t: Option<i64>, wide: bool) -> Option<*mut Tm> {
    crt_zone()?;
    // SAFETY: `_gmtime64` of the epoch returns the thread's buffer.
    let buffer = unsafe { _gmtime64(&0) };
    if buffer.is_null() {
        return None;
    }
    let r = sim_localtime(buffer, t, wide)?;
    Some(if r == 0 { buffer } else { std::ptr::null_mut() })
}

/// `_localtime64` ([Microsoft Learn: localtime, _localtime32, _localtime64](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/localtime-localtime32-localtime64)).
unsafe extern "C" fn crt_localtime64(t: *const i64) -> *mut Tm {
    // SAFETY: a non-null time is the caller's readable __time64_t.
    if let Some(r) = sim_localtime_buffer(unsafe { t.as_ref() }.copied(), true) {
        return r;
    }
    // SAFETY: CRT_LOCALTIME64 holds the UCRT's _localtime64.
    unsafe { original::<unsafe extern "C" fn(*const i64) -> *mut Tm>(&CRT_LOCALTIME64)(t) }
}

/// `_localtime32`.
unsafe extern "C" fn crt_localtime32(t: *const i32) -> *mut Tm {
    // SAFETY: a non-null time is the caller's readable __time32_t.
    if let Some(r) = sim_localtime_buffer(unsafe { t.as_ref() }.map(|&t| i64::from(t)), false) {
        return r;
    }
    // SAFETY: CRT_LOCALTIME32 holds the UCRT's _localtime32.
    unsafe { original::<unsafe extern "C" fn(*const i32) -> *mut Tm>(&CRT_LOCALTIME32)(t) }
}

/// mktime.cpp `common_mktime` with local time, for a `__time64_t` (`wide`) or `__time32_t`: the
/// fields counted up as UTC in the type's arithmetic, with overflow, a year outside 1969 to the
/// type's last year plus one, or a month carrying the year out of it failing with `EINVAL`
/// before the zone is read; then moved by `_timezone` and broken down, and by `_dstbias` more
/// when `tm_isdst` is positive, or negative and that time is in daylight saving time.
fn crt_mktime(zone: &Zone, tb: &mut Tm, wide: bool) -> i64 {
    let max_year = if wide { 1100 } else { 138 };
    let fit = |v: i64| if wide { v } else { i64::from(v as i32) };
    let fail = || {
        set_errno(EINVAL);
        -1
    };
    let mut years = i64::from(tb.year);
    if years < 69 || years > max_year + 1 {
        return fail();
    }
    if !(0..=11).contains(&tb.mon) {
        years += i64::from(tb.mon / 12);
        tb.mon %= 12;
        if tb.mon < 0 {
            tb.mon += 12;
            years -= 1;
        }
        if years < 69 || years > max_year + 1 {
            return fail();
        }
    }
    let mut month_days = DAYS[tb.mon as usize];
    if is_leap(years) && tb.mon > 1 {
        month_days += 1;
    }
    let days = (years - 70) * 365 + elapsed_leap_years(years) + month_days;
    let add = |a: i64, b: i64| {
        let sum = fit(a.wrapping_add(b));
        let overflow = (a >= 0 && b >= 0 && sum < 0) || (a < 0 && b < 0 && sum >= 0);
        (!overflow).then_some(sum)
    };
    let mul = |a: i64, b: i64| {
        let product = fit(a.wrapping_mul(b));
        (a == 0 || product / a == b).then_some(product)
    };
    let seconds = (|| {
        let days = add(days, i64::from(tb.mday))?;
        let hours = add(mul(days, 24)?, i64::from(tb.hour))?;
        let minutes = add(mul(hours, 60)?, i64::from(tb.min))?;
        add(mul(minutes, 60)?, i64::from(tb.sec))
    })();
    let Some(seconds) = seconds else {
        return fail();
    };
    zone.crt.ensure(&zone.dtzi);
    let (timezone, _, dstbias) = zone.crt.values();
    let max = if wide { MAX_TIME64 } else { MAX_TIME32 };
    let local = |t: i64, out: &mut Tm| (0..=max).contains(&t) && crt_local(zone, t, out, max) == 0;
    let mut t = fit(seconds + timezone);
    let mut out = Tm::default();
    if !local(t, &mut out) {
        return fail();
    }
    if tb.isdst > 0 || (tb.isdst < 0 && out.isdst > 0) {
        t = fit(t + dstbias);
        if !local(t, &mut out) {
            return fail();
        }
    }
    *tb = out;
    t
}

/// `_mktime64` ([Microsoft Learn: mktime, _mktime32, _mktime64](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/mktime-mktime32-mktime64)).
unsafe extern "C" fn crt_mktime64(tb: *mut Tm) -> i64 {
    if !tb.is_null()
        && let Some(zone) = crt_zone()
    {
        // SAFETY: the caller's readable and writable struct tm.
        return crt_mktime(&zone, unsafe { &mut *tb }, true);
    }
    // SAFETY: CRT_MKTIME64 holds the UCRT's _mktime64.
    unsafe { original::<unsafe extern "C" fn(*mut Tm) -> i64>(&CRT_MKTIME64)(tb) }
}

/// `_mktime32`.
unsafe extern "C" fn crt_mktime32(tb: *mut Tm) -> i32 {
    if !tb.is_null()
        && let Some(zone) = crt_zone()
    {
        // SAFETY: the caller's readable and writable struct tm.
        return crt_mktime(&zone, unsafe { &mut *tb }, false) as i32;
    }
    // SAFETY: CRT_MKTIME32 holds the UCRT's _mktime32.
    unsafe { original::<unsafe extern "C" fn(*mut Tm) -> i32>(&CRT_MKTIME32)(tb) }
}

/// ctime.cpp `common_ctime`: the local time of a non-negative time as `asctime` writes it, into
/// the thread's buffer, or null.
fn sim_ctime<C>(t: Option<i64>, wide: bool, text: unsafe extern "C" fn(*const Tm) -> *mut C) -> Option<*mut C> {
    let t = t.filter(|&t| t >= 0)?;
    let zone = crt_zone()?;
    let max = if wide { MAX_TIME64 } else { MAX_TIME32 };
    if t > max {
        return None;
    }
    let mut tm = Tm::default();
    if crt_local(&zone, t, &mut tm, max) != 0 {
        return Some(std::ptr::null_mut());
    }
    // SAFETY: a broken-down time.
    Some(unsafe { text(&tm) })
}

/// `_ctime64` ([Microsoft Learn: ctime, _ctime32, _ctime64, _wctime, _wctime32, _wctime64](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/ctime-ctime32-ctime64-wctime-wctime32-wctime64)).
unsafe extern "C" fn crt_ctime64(t: *const i64) -> *mut c_char {
    // SAFETY: a non-null time is the caller's readable __time64_t.
    if let Some(r) = sim_ctime(unsafe { t.as_ref() }.copied(), true, asctime) {
        return r;
    }
    // SAFETY: CRT_CTIME64 holds the UCRT's _ctime64.
    unsafe { original::<unsafe extern "C" fn(*const i64) -> *mut c_char>(&CRT_CTIME64)(t) }
}

/// `_ctime32`.
unsafe extern "C" fn crt_ctime32(t: *const i32) -> *mut c_char {
    // SAFETY: a non-null time is the caller's readable __time32_t.
    if let Some(r) = sim_ctime(unsafe { t.as_ref() }.map(|&t| i64::from(t)), false, asctime) {
        return r;
    }
    // SAFETY: CRT_CTIME32 holds the UCRT's _ctime32.
    unsafe { original::<unsafe extern "C" fn(*const i32) -> *mut c_char>(&CRT_CTIME32)(t) }
}

/// `_wctime64`.
unsafe extern "C" fn crt_wctime64(t: *const i64) -> *mut u16 {
    // SAFETY: a non-null time is the caller's readable __time64_t.
    if let Some(r) = sim_ctime(unsafe { t.as_ref() }.copied(), true, _wasctime) {
        return r;
    }
    // SAFETY: CRT_WCTIME64 holds the UCRT's _wctime64.
    unsafe { original::<unsafe extern "C" fn(*const i64) -> *mut u16>(&CRT_WCTIME64)(t) }
}

/// `_wctime32`.
unsafe extern "C" fn crt_wctime32(t: *const i32) -> *mut u16 {
    // SAFETY: a non-null time is the caller's readable __time32_t.
    if let Some(r) = sim_ctime(unsafe { t.as_ref() }.map(|&t| i64::from(t)), false, _wasctime) {
        return r;
    }
    // SAFETY: CRT_WCTIME32 holds the UCRT's _wctime32.
    unsafe { original::<unsafe extern "C" fn(*const i32) -> *mut u16>(&CRT_WCTIME32)(t) }
}

/// ctime.cpp `common_ctime_s`: as [`sim_ctime`] into the caller's buffer of `size` characters,
/// which the UCRT's checks (a buffer of at least 26, a non-negative time) have passed. The
/// buffer is emptied first.
fn sim_ctime_s<C: Default>(
    buffer: *mut C,
    size: usize,
    t: Option<i64>,
    wide: bool,
    text: unsafe extern "C" fn(*mut C, usize, *const Tm) -> c_int,
) -> Option<c_int> {
    let t = t.filter(|&t| t >= 0)?;
    if buffer.is_null() || size < 26 {
        return None;
    }
    let zone = crt_zone()?;
    let max = if wide { MAX_TIME64 } else { MAX_TIME32 };
    if t > max {
        return None;
    }
    // SAFETY: the caller's buffer of `size` characters.
    unsafe { buffer.write(C::default()) };
    let mut tm = Tm::default();
    let status = crt_local(&zone, t, &mut tm, max);
    if status != 0 {
        return Some(status);
    }
    // SAFETY: as above, and a broken-down time.
    Some(unsafe { text(buffer, size, &tm) })
}

/// `_ctime64_s` ([Microsoft Learn: ctime_s, _ctime32_s, _ctime64_s, _wctime_s, _wctime32_s, _wctime64_s](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/ctime-s-ctime32-s-ctime64-s-wctime-s-wctime32-s-wctime64-s)).
unsafe extern "C" fn crt_ctime64_s(buffer: *mut c_char, size: usize, t: *const i64) -> c_int {
    // SAFETY: a non-null time is the caller's readable __time64_t.
    if let Some(r) = sim_ctime_s(buffer, size, unsafe { t.as_ref() }.copied(), true, asctime_s) {
        return r;
    }
    // SAFETY: CRT_CTIME64_S holds the UCRT's _ctime64_s.
    unsafe {
        original::<unsafe extern "C" fn(*mut c_char, usize, *const i64) -> c_int>(&CRT_CTIME64_S)(
            buffer, size, t,
        )
    }
}

/// `_ctime32_s`.
unsafe extern "C" fn crt_ctime32_s(buffer: *mut c_char, size: usize, t: *const i32) -> c_int {
    // SAFETY: a non-null time is the caller's readable __time32_t.
    let t64 = unsafe { t.as_ref() }.map(|&t| i64::from(t));
    if let Some(r) = sim_ctime_s(buffer, size, t64, false, asctime_s) {
        return r;
    }
    // SAFETY: CRT_CTIME32_S holds the UCRT's _ctime32_s.
    unsafe {
        original::<unsafe extern "C" fn(*mut c_char, usize, *const i32) -> c_int>(&CRT_CTIME32_S)(
            buffer, size, t,
        )
    }
}

/// `_wctime64_s`.
unsafe extern "C" fn crt_wctime64_s(buffer: *mut u16, size: usize, t: *const i64) -> c_int {
    // SAFETY: a non-null time is the caller's readable __time64_t.
    if let Some(r) = sim_ctime_s(buffer, size, unsafe { t.as_ref() }.copied(), true, _wasctime_s) {
        return r;
    }
    // SAFETY: CRT_WCTIME64_S holds the UCRT's _wctime64_s.
    unsafe {
        original::<unsafe extern "C" fn(*mut u16, usize, *const i64) -> c_int>(&CRT_WCTIME64_S)(
            buffer, size, t,
        )
    }
}

/// `_wctime32_s`.
unsafe extern "C" fn crt_wctime32_s(buffer: *mut u16, size: usize, t: *const i32) -> c_int {
    // SAFETY: a non-null time is the caller's readable __time32_t.
    let t64 = unsafe { t.as_ref() }.map(|&t| i64::from(t));
    if let Some(r) = sim_ctime_s(buffer, size, t64, false, _wasctime_s) {
        return r;
    }
    // SAFETY: CRT_WCTIME32_S holds the UCRT's _wctime32_s.
    unsafe {
        original::<unsafe extern "C" fn(*mut u16, usize, *const i32) -> c_int>(&CRT_WCTIME32_S)(
            buffer, size, t,
        )
    }
}

/// `_tzset` ([Microsoft Learn: _tzset](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/tzset)):
/// sets the zone again. It leaves the first-call flag alone, as the UCRT's does.
unsafe extern "C" fn crt_tzset() {
    if let Some(zone) = crt_zone() {
        let now = sim_now();
        let _passthrough = Passthrough::enter();
        let mut state = zone.crt.state.lock().unwrap_or_else(|e| e.into_inner());
        zone.crt.tzset(&zone.dtzi, now, &mut state);
        return;
    }
    // SAFETY: CRT_TZSET holds the UCRT's _tzset.
    unsafe { original::<unsafe extern "C" fn()>(&CRT_TZSET)() }
}

/// `__timezone`, behind the `_timezone` macro (timeset.cpp).
unsafe extern "C" fn crt_timezone() -> *mut i32 {
    match crt_zone() {
        Some(zone) => zone.crt.timezone.as_ptr(),
        // SAFETY: CRT_TIMEZONE holds the UCRT's __timezone.
        None => unsafe { original::<unsafe extern "C" fn() -> *mut i32>(&CRT_TIMEZONE)() },
    }
}

/// `__daylight`, behind `_daylight`.
unsafe extern "C" fn crt_daylight() -> *mut c_int {
    match crt_zone() {
        Some(zone) => zone.crt.daylight.as_ptr(),
        // SAFETY: CRT_DAYLIGHT holds the UCRT's __daylight.
        None => unsafe { original::<unsafe extern "C" fn() -> *mut c_int>(&CRT_DAYLIGHT)() },
    }
}

/// `__dstbias`, behind `_dstbias`.
unsafe extern "C" fn crt_dstbias() -> *mut i32 {
    match crt_zone() {
        Some(zone) => zone.crt.dstbias.as_ptr(),
        // SAFETY: CRT_DSTBIAS holds the UCRT's __dstbias.
        None => unsafe { original::<unsafe extern "C" fn() -> *mut i32>(&CRT_DSTBIAS)() },
    }
}

/// `__tzname`, behind `_tzname`.
unsafe extern "C" fn crt_tzname() -> *mut *mut c_char {
    match crt_zone() {
        // SAFETY: the pointers live in the zone's box.
        Some(zone) => unsafe { (*zone.crt.names.get()).pointers.as_mut_ptr() },
        // SAFETY: CRT_TZNAME holds the UCRT's __tzname.
        None => unsafe { original::<unsafe extern "C" fn() -> *mut *mut c_char>(&CRT_TZNAME)() },
    }
}

/// `_get_timezone` ([Microsoft Learn: _get_timezone](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/get-timezone)):
/// the value as it stands, without setting the zone.
unsafe extern "C" fn crt_get_timezone(out: *mut i32) -> c_int {
    if !out.is_null()
        && let Some(zone) = crt_zone()
    {
        // SAFETY: the caller's writable long.
        unsafe { out.write(zone.crt.timezone.load(Ordering::Relaxed)) };
        return 0;
    }
    // SAFETY: CRT_GET_TIMEZONE holds the UCRT's _get_timezone.
    unsafe { original::<unsafe extern "C" fn(*mut i32) -> c_int>(&CRT_GET_TIMEZONE)(out) }
}

/// `_get_daylight`.
unsafe extern "C" fn crt_get_daylight(out: *mut c_int) -> c_int {
    if !out.is_null()
        && let Some(zone) = crt_zone()
    {
        // SAFETY: the caller's writable int.
        unsafe { out.write(zone.crt.daylight.load(Ordering::Relaxed)) };
        return 0;
    }
    // SAFETY: CRT_GET_DAYLIGHT holds the UCRT's _get_daylight.
    unsafe { original::<unsafe extern "C" fn(*mut c_int) -> c_int>(&CRT_GET_DAYLIGHT)(out) }
}

/// `_get_dstbias`.
unsafe extern "C" fn crt_get_dstbias(out: *mut i32) -> c_int {
    if !out.is_null()
        && let Some(zone) = crt_zone()
    {
        // SAFETY: the caller's writable long.
        unsafe { out.write(zone.crt.dstbias.load(Ordering::Relaxed)) };
        return 0;
    }
    // SAFETY: CRT_GET_DSTBIAS holds the UCRT's _get_dstbias.
    unsafe { original::<unsafe extern "C" fn(*mut i32) -> c_int>(&CRT_GET_DSTBIAS)(out) }
}

/// `_get_tzname` ([Microsoft Learn: _get_tzname](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/get-tzname)):
/// the length of name `index` with its NUL, and the name when `buffer` holds it; `ERANGE` when
/// it does not. Arguments the UCRT rejects go to it.
unsafe extern "C" fn crt_get_tzname(
    len: *mut usize,
    buffer: *mut c_char,
    size: usize,
    index: c_int,
) -> c_int {
    let valid = buffer.is_null() == (size == 0) && !len.is_null() && (index == 0 || index == 1);
    if valid && let Some(zone) = crt_zone() {
        // SAFETY: the strings live in the zone's box.
        let name = unsafe { (*zone.crt.names.get()).narrow[index as usize] };
        let n = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        // SAFETY: the caller's writable size_t, and `buffer` of `size` bytes when non-null.
        unsafe {
            len.write(n + 1);
            if buffer.is_null() {
                return 0;
            }
            buffer.write(0);
            if n + 1 > size {
                return ERANGE;
            }
            std::ptr::copy_nonoverlapping(name.as_ptr(), buffer, n);
            buffer.add(n).write(0);
        }
        return 0;
    }
    // SAFETY: CRT_GET_TZNAME holds the UCRT's _get_tzname.
    unsafe {
        original::<unsafe extern "C" fn(*mut usize, *mut c_char, usize, c_int) -> c_int>(
            &CRT_GET_TZNAME,
        )(len, buffer, size, index)
    }
}

/// sys/timeb.h `struct __timeb64` and `struct __timeb32`.
#[repr(C)]
struct Timeb<T> {
    time: T,
    millitm: u16,
    timezone: i16,
    dstflag: i16,
}

/// ftime.cpp `common_ftime_s`: now in seconds and milliseconds, `_timezone` in minutes after
/// setting the zone, and whether `GetTimeZoneInformation` reports daylight saving time with a
/// rule that has it (`-1` when it fails). A sim with its own zone fills it all; one on a virtual
/// clock without a zone has the UCRT fill it and replaces the time and the daylight flag with
/// the sim's. `false` leaves the call to the UCRT.
fn sim_ftime<T>(tp: *mut Timeb<T>, original: impl FnOnce(*mut Timeb<T>), time: impl Fn(i64) -> T) -> bool {
    if tp.is_null() {
        return false;
    }
    let (now, timezone) = match crt_zone() {
        Some(zone) => {
            zone.crt.ensure(&zone.dtzi);
            (sim_now(), Some(zone.crt.values().0))
        }
        None => match crate::domain::read_clock(ClockKind::Realtime) {
            Some(now) => ((now.as_nanos() / 100) as u64 + FILETIME_UNIX_OFFSET, None),
            None => return false,
        },
    };
    let dstflag = now_zone().map(|(zone, _)| match current(&zone, now) {
        Some((rule, id)) => {
            i16::from(id == ZONE_DAYLIGHT && rule.DaylightDate.wMonth != 0 && rule.DaylightBias != 0)
        }
        None => -1,
    });
    if timezone.is_none() {
        original(tp);
    }
    // SAFETY: the caller's writable struct, filled in by the UCRT above when it has no zone.
    let tp = unsafe { &mut *tp };
    if let Some(timezone) = timezone {
        tp.timezone = (timezone / 60) as i16;
    }
    if let Some(dstflag) = dstflag {
        tp.dstflag = dstflag;
    }
    tp.millitm = (now / 10_000 % 1000) as u16;
    tp.time = time(((now - FILETIME_UNIX_OFFSET) / 10_000_000) as i64);
    true
}

/// `_ftime64_s` ([Microsoft Learn: _ftime_s, _ftime32_s, _ftime64_s](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/ftime-s-ftime32-s-ftime64-s)).
unsafe extern "C" fn crt_ftime64_s(tp: *mut Timeb<i64>) -> c_int {
    // SAFETY: CRT_FTIME64_S holds the UCRT's _ftime64_s.
    let ucrt = |tp| unsafe {
        original::<unsafe extern "C" fn(*mut Timeb<i64>) -> c_int>(&CRT_FTIME64_S)(tp);
    };
    if sim_ftime(tp, ucrt, |t| t) {
        return 0;
    }
    // SAFETY: as above.
    unsafe { original::<unsafe extern "C" fn(*mut Timeb<i64>) -> c_int>(&CRT_FTIME64_S)(tp) }
}

/// `_ftime32_s`.
unsafe extern "C" fn crt_ftime32_s(tp: *mut Timeb<i32>) -> c_int {
    // SAFETY: CRT_FTIME32_S holds the UCRT's _ftime32_s.
    let ucrt = |tp| unsafe {
        original::<unsafe extern "C" fn(*mut Timeb<i32>) -> c_int>(&CRT_FTIME32_S)(tp);
    };
    if sim_ftime(tp, ucrt, |t| t as i32) {
        return 0;
    }
    // SAFETY: as above.
    unsafe { original::<unsafe extern "C" fn(*mut Timeb<i32>) -> c_int>(&CRT_FTIME32_S)(tp) }
}

/// `_ftime64` ([Microsoft Learn: _ftime, _ftime32, _ftime64](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/ftime-ftime32-ftime64)).
unsafe extern "C" fn crt_ftime64(tp: *mut Timeb<i64>) {
    // SAFETY: CRT_FTIME64 holds the UCRT's _ftime64.
    let ucrt = |tp| unsafe { original::<unsafe extern "C" fn(*mut Timeb<i64>)>(&CRT_FTIME64)(tp) };
    if !sim_ftime(tp, ucrt, |t| t) {
        ucrt(tp);
    }
}

/// `_ftime32`.
unsafe extern "C" fn crt_ftime32(tp: *mut Timeb<i32>) {
    // SAFETY: CRT_FTIME32 holds the UCRT's _ftime32.
    let ucrt = |tp| unsafe { original::<unsafe extern "C" fn(*mut Timeb<i32>)>(&CRT_FTIME32)(tp) };
    if !sim_ftime(tp, ucrt, |t| t as i32) {
        ucrt(tp);
    }
}

/// strtime.cpp and strdate.cpp: now in local time as `HH:MM:SS` (`time`) or `MM/DD/YY`, written
/// with its NUL to `buffer`, which the UCRT's checks (non-null, nine characters) have passed.
/// `false` leaves the call to the UCRT.
fn clock_text<C: Unit>(buffer: *mut C, size: usize, time: bool) -> bool {
    if buffer.is_null() || size < 9 {
        return false;
    }
    let Some(now) = local_now() else {
        return false;
    };
    let fields = if time {
        [now.wHour, now.wMinute, now.wSecond]
    } else {
        [now.wMonth, now.wDay, now.wYear % 100]
    };
    let separator = if time { b':' } else { b'/' };
    let text = format!(
        "{:02}{}{:02}{}{:02}",
        fields[0], separator as char, fields[1], separator as char, fields[2]
    );
    for (i, b) in text.bytes().chain([0]).enumerate() {
        // SAFETY: the caller's buffer of at least nine characters.
        unsafe { buffer.add(i).write(C::of(b)) };
    }
    true
}

/// `_strtime_s` ([Microsoft Learn: _strtime_s, _wstrtime_s](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtime-s-wstrtime-s)).
unsafe extern "C" fn crt_strtime_s(buffer: *mut c_char, size: usize) -> c_int {
    if clock_text(buffer, size, true) {
        return 0;
    }
    // SAFETY: CRT_STRTIME_S holds the UCRT's _strtime_s.
    unsafe { original::<unsafe extern "C" fn(*mut c_char, usize) -> c_int>(&CRT_STRTIME_S)(buffer, size) }
}

/// `_wstrtime_s`.
unsafe extern "C" fn crt_wstrtime_s(buffer: *mut u16, size: usize) -> c_int {
    if clock_text(buffer, size, true) {
        return 0;
    }
    // SAFETY: CRT_WSTRTIME_S holds the UCRT's _wstrtime_s.
    unsafe { original::<unsafe extern "C" fn(*mut u16, usize) -> c_int>(&CRT_WSTRTIME_S)(buffer, size) }
}

/// `_strtime` ([Microsoft Learn: _strtime, _wstrtime](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtime-wstrtime)).
unsafe extern "C" fn crt_strtime(buffer: *mut c_char) -> *mut c_char {
    if clock_text(buffer, 9, true) {
        return buffer;
    }
    // SAFETY: CRT_STRTIME holds the UCRT's _strtime.
    unsafe { original::<unsafe extern "C" fn(*mut c_char) -> *mut c_char>(&CRT_STRTIME)(buffer) }
}

/// `_wstrtime`.
unsafe extern "C" fn crt_wstrtime(buffer: *mut u16) -> *mut u16 {
    if clock_text(buffer, 9, true) {
        return buffer;
    }
    // SAFETY: CRT_WSTRTIME holds the UCRT's _wstrtime.
    unsafe { original::<unsafe extern "C" fn(*mut u16) -> *mut u16>(&CRT_WSTRTIME)(buffer) }
}

/// `_strdate_s` ([Microsoft Learn: _strdate_s, _wstrdate_s](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strdate-s-wstrdate-s)).
unsafe extern "C" fn crt_strdate_s(buffer: *mut c_char, size: usize) -> c_int {
    if clock_text(buffer, size, false) {
        return 0;
    }
    // SAFETY: CRT_STRDATE_S holds the UCRT's _strdate_s.
    unsafe { original::<unsafe extern "C" fn(*mut c_char, usize) -> c_int>(&CRT_STRDATE_S)(buffer, size) }
}

/// `_wstrdate_s`.
unsafe extern "C" fn crt_wstrdate_s(buffer: *mut u16, size: usize) -> c_int {
    if clock_text(buffer, size, false) {
        return 0;
    }
    // SAFETY: CRT_WSTRDATE_S holds the UCRT's _wstrdate_s.
    unsafe { original::<unsafe extern "C" fn(*mut u16, usize) -> c_int>(&CRT_WSTRDATE_S)(buffer, size) }
}

/// `_strdate` ([Microsoft Learn: _strdate, _wstrdate](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strdate-wstrdate)).
unsafe extern "C" fn crt_strdate(buffer: *mut c_char) -> *mut c_char {
    if clock_text(buffer, 9, false) {
        return buffer;
    }
    // SAFETY: CRT_STRDATE holds the UCRT's _strdate.
    unsafe { original::<unsafe extern "C" fn(*mut c_char) -> *mut c_char>(&CRT_STRDATE)(buffer) }
}

/// `_wstrdate`.
unsafe extern "C" fn crt_wstrdate(buffer: *mut u16) -> *mut u16 {
    if clock_text(buffer, 9, false) {
        return buffer;
    }
    // SAFETY: CRT_WSTRDATE holds the UCRT's _wstrdate.
    unsafe { original::<unsafe extern "C" fn(*mut u16) -> *mut u16>(&CRT_WSTRDATE)(buffer) }
}

/// A character of a format string, narrow or wide.
trait Unit: Copy + Eq + Default {
    fn of(b: u8) -> Self;
}

impl Unit for c_char {
    fn of(b: u8) -> Self {
        b as c_char
    }
}

impl Unit for u16 {
    fn of(b: u8) -> Self {
        u16::from(b)
    }
}

/// `format` with each `%z` and `%Z` (with the `#` flag or the `E`/`O` modifiers the UCRT skips)
/// replaced by the text the UCRT would produce for `tm` from the sim's zone state
/// (wcsftime.cpp `expand_time`): the offset as `±hhmm`, east positive, from `_timezone` plus
/// `_dstbias` when `tm_isdst` is nonzero, and `_tzname` by `tm_isdst`. `None` when there is none.
/// Only these read the zone, so the rest is left to the UCRT.
fn rewrite<C: Unit>(zone: &Zone, format: *const C, tm: &Tm, name: impl Fn(usize) -> Vec<C>) -> Option<Vec<C>> {
    let percent = C::of(b'%');
    let mut units = Vec::new();
    let mut i = 0;
    // SAFETY: the caller's NUL-terminated format string.
    loop {
        let c = unsafe { *format.add(i) };
        if c == C::default() {
            break;
        }
        units.push(c);
        i += 1;
    }
    let mut out = Vec::with_capacity(units.len() + 1);
    let mut changed = false;
    let mut at = 0;
    while at < units.len() {
        if units[at] != percent {
            out.push(units[at]);
            at += 1;
            continue;
        }
        let mut end = at + 1;
        if units.get(end) == Some(&C::of(b'#')) {
            end += 1;
        }
        if units.get(end).is_some_and(|&c| c == C::of(b'E') || c == C::of(b'O')) {
            end += 1;
        }
        let Some(&directive) = units.get(end) else {
            out.extend_from_slice(&units[at..]);
            break;
        };
        if directive != C::of(b'z') && directive != C::of(b'Z') {
            out.extend_from_slice(&units[at..=end]);
            at = end + 1;
            continue;
        }
        if !changed {
            zone.crt.ensure(&zone.dtzi);
            changed = true;
        }
        let text: Vec<C> = if directive == C::of(b'z') {
            let (timezone, _, dstbias) = zone.crt.values();
            let offset = timezone + if tm.isdst != 0 { dstbias } else { 0 };
            let sign = if offset <= 0 { '+' } else { '-' };
            let offset = offset.abs();
            format!("{sign}{:02}{:02}", offset / 3600, offset / 60 % 60)
                .bytes()
                .map(C::of)
                .collect()
        } else {
            name(usize::from(tm.isdst != 0))
        };
        for c in text {
            if c == percent {
                out.push(percent);
            }
            out.push(c);
        }
        at = end + 1;
    }
    out.push(C::default());
    changed.then_some(out)
}

fn narrow_name(zone: &Zone, index: usize) -> Vec<c_char> {
    // SAFETY: the strings live in the zone's box.
    let name = unsafe { (*zone.crt.names.get()).narrow[index] };
    name.iter().copied().take_while(|&c| c != 0).collect()
}

fn wide_name(zone: &Zone, index: usize) -> Vec<u16> {
    // SAFETY: the strings live in the zone's box.
    let name = unsafe { (*zone.crt.names.get()).wide[index] };
    name.iter().copied().take_while(|&c| c != 0).collect()
}

/// The format a sim's `strftime` hands the UCRT, when it differs from the caller's.
fn narrow_format(format: *const c_char, tm: *const Tm) -> Option<Vec<c_char>> {
    if format.is_null() || tm.is_null() {
        return None;
    }
    let zone = crt_zone()?;
    // SAFETY: the caller's struct tm.
    let tm = unsafe { &*tm };
    rewrite(&zone, format, tm, |i| narrow_name(&zone, i))
}

fn wide_format(format: *const u16, tm: *const Tm) -> Option<Vec<u16>> {
    if format.is_null() || tm.is_null() {
        return None;
    }
    let zone = crt_zone()?;
    // SAFETY: the caller's struct tm.
    let tm = unsafe { &*tm };
    rewrite(&zone, format, tm, |i| wide_name(&zone, i))
}

/// `strftime` ([Microsoft Learn: strftime, wcsftime, _strftime_l, _wcsftime_l](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strftime-wcsftime-strftime-l-wcsftime-l)).
unsafe extern "C" fn crt_strftime(
    out: *mut c_char,
    size: usize,
    format: *const c_char,
    tm: *const Tm,
) -> usize {
    let rewritten = narrow_format(format, tm);
    let format = rewritten.as_ref().map_or(format, |f| f.as_ptr());
    // SAFETY: CRT_STRFTIME holds the UCRT's strftime.
    unsafe {
        original::<unsafe extern "C" fn(*mut c_char, usize, *const c_char, *const Tm) -> usize>(
            &CRT_STRFTIME,
        )(out, size, format, tm)
    }
}

/// `_strftime_l`.
unsafe extern "C" fn crt_strftime_l(
    out: *mut c_char,
    size: usize,
    format: *const c_char,
    tm: *const Tm,
    locale: *mut std::ffi::c_void,
) -> usize {
    let rewritten = narrow_format(format, tm);
    let format = rewritten.as_ref().map_or(format, |f| f.as_ptr());
    // SAFETY: CRT_STRFTIME_L holds the UCRT's _strftime_l.
    unsafe {
        original::<
            unsafe extern "C" fn(
                *mut c_char,
                usize,
                *const c_char,
                *const Tm,
                *mut std::ffi::c_void,
            ) -> usize,
        >(&CRT_STRFTIME_L)(out, size, format, tm, locale)
    }
}

/// `_Strftime`, with the locale's time data.
unsafe extern "C" fn crt_strftime_internal(
    out: *mut c_char,
    size: usize,
    format: *const c_char,
    tm: *const Tm,
    time_data: *mut std::ffi::c_void,
) -> usize {
    let rewritten = narrow_format(format, tm);
    let format = rewritten.as_ref().map_or(format, |f| f.as_ptr());
    // SAFETY: CRT_STRFTIME_INTERNAL holds the UCRT's _Strftime.
    unsafe {
        original::<
            unsafe extern "C" fn(
                *mut c_char,
                usize,
                *const c_char,
                *const Tm,
                *mut std::ffi::c_void,
            ) -> usize,
        >(&CRT_STRFTIME_INTERNAL)(out, size, format, tm, time_data)
    }
}

/// `wcsftime`.
unsafe extern "C" fn crt_wcsftime(
    out: *mut u16,
    size: usize,
    format: *const u16,
    tm: *const Tm,
) -> usize {
    let rewritten = wide_format(format, tm);
    let format = rewritten.as_ref().map_or(format, |f| f.as_ptr());
    // SAFETY: CRT_WCSFTIME holds the UCRT's wcsftime.
    unsafe {
        original::<unsafe extern "C" fn(*mut u16, usize, *const u16, *const Tm) -> usize>(
            &CRT_WCSFTIME,
        )(out, size, format, tm)
    }
}

/// `_wcsftime_l`.
unsafe extern "C" fn crt_wcsftime_l(
    out: *mut u16,
    size: usize,
    format: *const u16,
    tm: *const Tm,
    locale: *mut std::ffi::c_void,
) -> usize {
    let rewritten = wide_format(format, tm);
    let format = rewritten.as_ref().map_or(format, |f| f.as_ptr());
    // SAFETY: CRT_WCSFTIME_L holds the UCRT's _wcsftime_l.
    unsafe {
        original::<
            unsafe extern "C" fn(*mut u16, usize, *const u16, *const Tm, *mut std::ffi::c_void) -> usize,
        >(&CRT_WCSFTIME_L)(out, size, format, tm, locale)
    }
}

/// `_Wcsftime`, with the locale's time data.
unsafe extern "C" fn crt_wcsftime_internal(
    out: *mut u16,
    size: usize,
    format: *const u16,
    tm: *const Tm,
    time_data: *mut std::ffi::c_void,
) -> usize {
    let rewritten = wide_format(format, tm);
    let format = rewritten.as_ref().map_or(format, |f| f.as_ptr());
    // SAFETY: CRT_WCSFTIME_INTERNAL holds the UCRT's _Wcsftime.
    unsafe {
        original::<
            unsafe extern "C" fn(*mut u16, usize, *const u16, *const Tm, *mut std::ffi::c_void) -> usize,
        >(&CRT_WCSFTIME_INTERNAL)(out, size, format, tm, time_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_cldr_name_is_listed_once() {
        let mut seen = crate::HashSet::default();
        for (_, names) in table::WINDOWS_ZONES {
            for name in names.split(' ') {
                assert!(seen.insert(name), "{name} listed twice");
            }
        }
        assert!(seen.contains("Europe/Kyiv") && seen.contains("Asia/Calcutta"));
    }

    #[test]
    fn ucrt_rule_days() {
        // 2023 (123): second Sunday of March is day 70, first Sunday of November day 308;
        // the end moves back an hour into standard time.
        let start = SYSTEMTIME {
            wYear: 0,
            wMonth: 3,
            wDayOfWeek: 0,
            wDay: 2,
            wHour: 2,
            wMinute: 0,
            wSecond: 0,
            wMilliseconds: 0,
        };
        let end = SYSTEMTIME {
            wMonth: 11,
            wDay: 1,
            ..start
        };
        assert_eq!(rule_day(123, &start, None), Some((70, 7_200_000)));
        assert_eq!(rule_day(123, &end, Some(-3600)), Some((308, 3_600_000)));
        let last = SYSTEMTIME {
            wMonth: 10,
            wDay: 5,
            ..start
        };
        // The last Sunday of October 2023 is the 29th, day 301.
        assert_eq!(rule_day(123, &last, None).map(|d| d.0), Some(301));
    }
}
