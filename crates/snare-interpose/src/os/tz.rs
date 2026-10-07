//! Local time for a sim that decides its own time zone.
//!
//! The C library resolves the local zone from inside itself: glibc reads `TZ` through its internal
//! `getenv` and opens the zone file with its internal `open`, and macOS's libc and CoreFoundation
//! live in the shared cache, whose calls the patcher leaves alone. None of that reaches a sim's
//! environment or file plane, so a sim with `TZ` in an isolated environment, or with its own
//! `/etc/localtime`, would still see the machine's zone. When the domain decides
//! ([`crate::domain::time_zone_setting`]), the local-time hooks resolve the zone here instead, the
//! way tzset(3) describes, and read the files through the hooked file calls, so the sim's file
//! plane serves them and paths it declines reach the real files:
//!
//! - `TZ` unset: `/etc/localtime` (following it by `readlink` when the plane serves it as a link
//!   into the real zoneinfo directory), or UTC when there is none.
//! - `TZ` empty: UTC.
//! - Otherwise, after an optional leading `:`, an absolute path or a name under `TZDIR`
//!   (`/usr/share/zoneinfo` by default) naming a TZif file (RFC 8536), else a POSIX TZ string
//!   (IEEE Std 1003.1-2024, 8.3 Other Environment Variables, `TZ`), else UTC: under glibc's
//!   names on Linux, which keeps the abbreviation a malformed TZ starts with.
//!
//! A TZif file's leap-second records are not applied, so the `right/` zones read as their
//! `posix/` twins. The `tzname`, `timezone` and `daylight` globals stay the process's: they are
//! shared by every thread, so no sim can own them.

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

/// What decides a domain's local zone: the domain's serial, and its `TZ` and `TZDIR` variables.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Setting {
    pub(crate) serial: u64,
    pub(crate) tz: Option<Vec<u8>>,
    pub(crate) tzdir: Option<Vec<u8>>,
}

/// One local time type: its offset east of UTC in seconds, whether it is daylight saving time,
/// and its abbreviation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct LocalType {
    pub(crate) utoff: i32,
    pub(crate) isdst: bool,
    pub(crate) abbr: &'static CStr,
}

/// The day of the year a POSIX TZ rule changes on (IEEE Std 1003.1-2024, 8.3, `TZ` *rule*).
#[derive(Clone, Copy, Debug)]
enum Day {
    /// `Jn`: day 1..=365, February 29 never counted.
    Julian(u16),
    /// `n`: zero-based day 0..=365, February 29 counted.
    Ordinal(u16),
    /// `Mm.w.d`: weekday `d` (0 = Sunday) of week `w` (5 = the last) of month `m`.
    Month { month: u8, week: u8, weekday: u8 },
}

/// When a rule changes: a day and a local time in seconds.
type Change = (Day, i32);

/// A POSIX TZ string: a standard type and optionally a daylight type with the changes that start
/// and end it.
#[derive(Clone, Debug)]
struct Rule {
    std: LocalType,
    dst: Option<(LocalType, Change, Change)>,
}

/// A resolved zone: TZif transitions and types, and the rule for times after the last
/// transition (or for every time, from a TZ string alone).
#[derive(Debug)]
pub(crate) struct Zone {
    transitions: Vec<i64>,
    indices: Vec<u8>,
    types: Vec<LocalType>,
    rule: Option<Rule>,
}

/// A zone with where it came from: its IANA name when one is known, and its TZif bytes when it
/// came from a file. CoreFoundation's zone is built from the name and bytes.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) struct Resolved {
    pub(crate) zone: Zone,
    pub(crate) name: Option<String>,
    pub(crate) data: Option<Vec<u8>>,
}

/// Bumped by `tzset`, which makes every thread resolve its zone again.
static GENERATION: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static CACHE: RefCell<Vec<(Setting, u64, Rc<Resolved>)>> = const { RefCell::new(Vec::new()) };
}

/// The calling thread's sim zone, or `None` when the C library decides. `fresh` resolves it again,
/// as `localtime` and `mktime` do (they behave as if they called tzset(3)); otherwise a zone
/// resolved since the last `tzset` is reused, as `localtime_r` may.
pub(crate) fn current(fresh: bool) -> Option<Rc<Resolved>> {
    let setting = crate::domain::time_zone_setting()?;
    let generation = GENERATION.load(Ordering::Relaxed);
    if !fresh
        && let Ok(Some(hit)) = CACHE.try_with(|c| {
            c.borrow()
                .iter()
                .find(|(s, g, _)| *s == setting && *g == generation)
                .map(|(_, _, r)| r.clone())
        })
    {
        return Some(hit);
    }
    let resolved = Rc::new(resolve(&setting));
    let _ = CACHE.try_with(|c| {
        let mut c = c.borrow_mut();
        c.retain(|(s, g, _)| *g == generation && s.serial != setting.serial);
        c.truncate(7);
        c.push((setting, generation, resolved.clone()));
    });
    Some(resolved)
}

/// Forgets every thread's resolved zone; see [`current`].
pub(crate) fn invalidate() {
    GENERATION.fetch_add(1, Ordering::Relaxed);
}

/// Resolves `setting` as described in the module documentation.
fn resolve(setting: &Setting) -> Resolved {
    let dir = setting
        .tzdir
        .clone()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| b"/usr/share/zoneinfo".to_vec());
    let Some(tz) = &setting.tz else {
        return local_file().unwrap_or_else(utc);
    };
    let tz = tz.strip_prefix(b":").unwrap_or(tz);
    // An empty TZ is UTC; glibc spells it "Universal" (time/tzset.c `tzset_internal`), which is
    // the name of a zone file and otherwise a zone of that abbreviation.
    let tz: &[u8] = match tz {
        [] if cfg!(target_os = "linux") => b"Universal",
        [] => return utc(),
        tz => tz,
    };
    let path = if tz.starts_with(b"/") {
        tz.to_vec()
    } else {
        [&dir[..], b"/", tz].concat()
    };
    if let Some(data) = read(&path)
        && let Some(zone) = parse_tzif(&data)
    {
        let name = if tz.starts_with(b"/") {
            zone_name(tz)
        } else {
            String::from_utf8(tz.to_vec()).ok()
        };
        return Resolved {
            zone,
            name,
            data: Some(data),
        };
    }
    match parse_posix(tz) {
        Some(rule) => Resolved {
            zone: Zone::from_rule(rule),
            name: None,
            data: None,
        },
        None if cfg!(target_os = "linux") => unparsed(tz),
        None => utc(),
    }
}

/// glibc's zone for a TZ that is neither a file nor a whole TZ string: whatever abbreviation
/// leads it, at offset 0 (`__tzset_parse_tz` keeps the name it parsed before the offset failed).
/// tzcode falls back to UTC instead.
fn unparsed(tz: &[u8]) -> Resolved {
    let mut p = Parser { s: tz, at: 0 };
    let abbr = p.name().unwrap_or_default();
    Resolved {
        zone: Zone::from_rule(Rule {
            std: LocalType {
                utoff: 0,
                isdst: false,
                abbr: intern(abbr),
            },
            dst: None,
        }),
        name: None,
        data: None,
    }
}

/// `/etc/localtime`, read through the sim's file plane. A plane may serve it as a link into the
/// real zoneinfo directory that it will not open itself, so a failed read follows the link.
fn local_file() -> Option<Resolved> {
    const LOCALTIME: &str = "/etc/localtime";
    let link = std::fs::read_link(LOCALTIME).ok().map(|target| {
        if target.is_absolute() {
            target
        } else {
            std::path::Path::new("/etc").join(target)
        }
    });
    let data = std::fs::read(LOCALTIME)
        .ok()
        .or_else(|| std::fs::read(link.as_ref()?).ok())?;
    let zone = parse_tzif(&data)?;
    use std::os::unix::ffi::OsStrExt;
    let name = link.and_then(|l| zone_name(l.as_os_str().as_bytes()));
    Some(Resolved {
        zone,
        name,
        data: Some(data),
    })
}

/// The IANA name in a zone file's path: what follows its last `zoneinfo/` component, as
/// systemd's `get_timezone` and iana-time-zone take it.
fn zone_name(path: &[u8]) -> Option<String> {
    const MARK: &[u8] = b"zoneinfo/";
    let at = path.windows(MARK.len()).rposition(|w| w == MARK)?;
    let name = &path[at + MARK.len()..];
    (!name.is_empty())
        .then(|| String::from_utf8(name.to_vec()).ok())
        .flatten()
}

fn read(path: &[u8]) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    std::fs::read(std::ffi::OsStr::from_bytes(path)).ok()
}

/// UTC, what tzset(3) falls back to for a zone it cannot load.
fn utc() -> Resolved {
    Resolved {
        zone: Zone::from_rule(Rule {
            std: LocalType {
                utoff: 0,
                isdst: false,
                abbr: intern(b"UTC"),
            },
            dst: None,
        }),
        name: Some("UTC".into()),
        data: None,
    }
}

/// A process-lifetime C string for `bytes`: `tm_zone` points at the abbreviation, and a caller
/// may keep the `struct tm` as long as it likes.
fn intern(bytes: &[u8]) -> &'static CStr {
    static TABLE: std::sync::Mutex<Vec<&'static CStr>> = std::sync::Mutex::new(Vec::new());
    let _passthrough = crate::state::Passthrough::enter();
    let mut table = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(found) = table.iter().find(|s| s.to_bytes() == bytes) {
        return found;
    }
    let owned: &'static CStr = Box::leak(
        CString::new(bytes.to_vec())
            .unwrap_or_default()
            .into_boxed_c_str(),
    );
    table.push(owned);
    owned
}

impl Zone {
    fn from_rule(rule: Rule) -> Self {
        Self {
            transitions: Vec::new(),
            indices: Vec::new(),
            types: vec![rule.std],
            rule: Some(rule),
        }
    }

    /// The local time type in effect at `t` seconds since the epoch. RFC 8536 §3.2: before the
    /// first transition type 0 applies; after the last, the footer's TZ string when there is one.
    pub(crate) fn at(&self, t: i64) -> LocalType {
        #[cfg(target_os = "macos")]
        if self.transitions.is_empty()
            && let Some(rule) = &self.rule
            && rule.first_change().is_some_and(|first| t < first)
        {
            return rule.std;
        }
        let after = self.transitions.partition_point(|&x| x <= t);
        if after == self.transitions.len()
            && let Some(rule) = &self.rule
        {
            return rule.at(t);
        }
        match after.checked_sub(1) {
            Some(i) => self.types[usize::from(self.indices[i])],
            None => self.types[0],
        }
    }

    /// The standard type of the zone's rule, or its first type.
    #[cfg(target_os = "macos")]
    pub(crate) fn standard(&self) -> LocalType {
        self.rule.as_ref().map_or(self.types[0], |r| r.std)
    }

    /// The zone's types, most recently in effect first: the rule's, then each transition's from
    /// the last back, as tzcode's `time1` orders them.
    #[cfg(target_os = "macos")]
    fn recent_types(&self) -> Vec<LocalType> {
        let rule = self
            .rule
            .iter()
            .flat_map(|r| r.dst.map(|d| d.0).into_iter().chain(std::iter::once(r.std)));
        let mut out: Vec<LocalType> = Vec::new();
        for ty in rule.chain(self.indices.iter().rev().map(|&i| self.types[usize::from(i)])) {
            if !out.contains(&ty) {
                out.push(ty);
            }
        }
        out
    }
}

impl Rule {
    /// The type in effect at `t`. The year is `t`'s UTC year, and each change is that year's
    /// rule day at the rule time in the local time then in effect: standard time for the start,
    /// daylight time for the end (IEEE Std 1003.1-2024, 8.3, `TZ` *rule*). A start after the end
    /// in the year is a southern-hemisphere rule, daylight time spanning the new year.
    fn at(&self, t: i64) -> LocalType {
        let Some((dst, start, end)) = self.dst else {
            return self.std;
        };
        let year = civil_from_days(t.div_euclid(86_400)).0;
        let start = change(year, start, self.std.utoff);
        let end = change(year, end, dst.utoff);
        let in_dst = if start < end {
            start <= t && t < end
        } else {
            !(end <= t && t < start)
        };
        if in_dst { dst } else { self.std }
    }

    /// The first change of 1970, before which tzcode's `tzparse` has no transitions and
    /// standard time applies.
    #[cfg(target_os = "macos")]
    fn first_change(&self) -> Option<i64> {
        let (dst, start, end) = self.dst?;
        Some(change(1970, start, self.std.utoff).min(change(1970, end, dst.utoff)))
    }
}

/// When a rule's `(day, time)` falls in `year`, for a rule time in local time of offset `utoff`.
/// glibc's `compute_change` (time/tzset.c) counts the days from January 1 of `year` only after
/// 1970, and from 1970-01-01 for 1970 and earlier, though it finds the rule day in `year`'s own
/// calendar; the sim's C library sees the same change times.
fn change(year: i64, (day, time): Change, utoff: i32) -> i64 {
    let jan1 = days_from_civil(year, 1, 1);
    let base = if cfg!(target_os = "linux") && year <= 1970 {
        0
    } else {
        jan1
    };
    (base + day_of(year, day) - jan1)
        .saturating_mul(86_400)
        .saturating_add(i64::from(time) - i64::from(utoff))
}

/// Days since 1970-01-01 of the day `day` names in `year`.
fn day_of(year: i64, day: Day) -> i64 {
    let jan1 = days_from_civil(year, 1, 1);
    match day {
        Day::Julian(n) => {
            let n = i64::from(n) - 1;
            jan1 + n + i64::from(is_leap(year) && n >= 59)
        }
        Day::Ordinal(n) => jan1 + i64::from(n),
        Day::Month {
            month,
            week,
            weekday,
        } => {
            let first = days_from_civil(year, month.into(), 1);
            let first_weekday = (first + 4).rem_euclid(7);
            let mut day = (i64::from(weekday) - first_weekday).rem_euclid(7) + 7 * (i64::from(week) - 1);
            let length = month_length(year, month.into());
            while day >= length {
                day -= 7;
            }
            first + day
        }
    }
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn month_length(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant, "chrono-Compatible Low-Level
/// Date Algorithms", `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The proleptic Gregorian date of a day count since 1970-01-01 (Hinnant, `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// Parses a TZif file (RFC 8536): the version 1 block, or for version 2 and later the 64-bit block
/// and the footer's TZ string. `None` for anything malformed.
pub(crate) fn parse_tzif(data: &[u8]) -> Option<Zone> {
    let header = |at: usize| -> Option<(u8, [usize; 6])> {
        let h = data.get(at..at + 44)?;
        if &h[..4] != b"TZif" {
            return None;
        }
        let mut counts = [0usize; 6];
        for (i, c) in counts.iter_mut().enumerate() {
            let w = &h[20 + 4 * i..24 + 4 * i];
            *c = u32::from_be_bytes(w.try_into().ok()?) as usize;
        }
        Some((h[4], counts))
    };
    // Counts are isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt (RFC 8536 §3.1).
    let block_len = |c: [usize; 6], time: usize| {
        c[3] * time + c[3] + c[4] * 6 + c[5] + c[2] * (time + 4) + c[1] + c[0]
    };
    let (version, v1) = header(0)?;
    let (at, counts, time) = if version >= b'2' {
        let second = 44 + block_len(v1, 4);
        (second + 44, header(second)?.1, 8)
    } else {
        (44, v1, 4)
    };
    let [_, _, _, timecnt, typecnt, charcnt] = counts;
    if typecnt == 0 {
        return None;
    }
    let body = data.get(at..at + block_len(counts, time))?;
    let (times, rest) = body.split_at(timecnt * time);
    let (indices, rest) = rest.split_at(timecnt);
    let (infos, rest) = rest.split_at(typecnt * 6);
    let chars = &rest[..charcnt];
    let transitions = times
        .chunks(time)
        .map(|c| match time {
            8 => i64::from_be_bytes(c.try_into().unwrap()),
            _ => i64::from(i32::from_be_bytes(c.try_into().unwrap())),
        })
        .collect::<Vec<_>>();
    if indices.iter().any(|&i| usize::from(i) >= typecnt) {
        return None;
    }
    let types = infos
        .chunks(6)
        .map(|c| {
            let utoff = i32::from_be_bytes(c[..4].try_into().unwrap());
            let start = usize::from(c[5]);
            let abbr = chars.get(start..)?;
            let end = abbr.iter().position(|&b| b == 0)?;
            Some(LocalType {
                utoff,
                isdst: c[4] != 0,
                abbr: intern(&abbr[..end]),
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let rule = if version >= b'2' {
        let footer = data.get(at + body.len()..)?;
        let footer = footer.strip_prefix(b"\n")?;
        let end = footer.iter().position(|&b| b == b'\n')?;
        match &footer[..end] {
            [] => None,
            tz => Some(parse_posix(tz)?),
        }
    } else {
        None
    };
    Some(Zone {
        transitions,
        indices: indices.to_vec(),
        types,
        rule,
    })
}

/// Parses a POSIX TZ string, `std offset [dst [offset] [,start[/time],end[/time]]]` (IEEE Std
/// 1003.1-2024, 8.3), with RFC 8536 §3.3.1's extension of rule times to -167..=167 hours. A
/// daylight zone without rules changes on glibc's and tzcode's default, the second Sunday of
/// March and the first of November at 02:00.
fn parse_posix(s: &[u8]) -> Option<Rule> {
    let mut p = Parser { s, at: 0 };
    let std_name = p.name()?;
    let std_utoff = -p.offset(24)?;
    let std = LocalType {
        utoff: std_utoff,
        isdst: false,
        abbr: intern(std_name),
    };
    if p.done() {
        return Some(Rule { std, dst: None });
    }
    let dst_name = p.name()?;
    let dst_utoff = match p.peek() {
        Some(b',') | None => std_utoff + 3600,
        _ => -p.offset(24)?,
    };
    let dst = LocalType {
        utoff: dst_utoff,
        isdst: true,
        abbr: intern(dst_name),
    };
    let (start, end) = if p.done() {
        (
            (
                Day::Month {
                    month: 3,
                    week: 2,
                    weekday: 0,
                },
                7200,
            ),
            (
                Day::Month {
                    month: 11,
                    week: 1,
                    weekday: 0,
                },
                7200,
            ),
        )
    } else {
        p.eat(b',')?;
        let start = p.change()?;
        p.eat(b',')?;
        let end = p.change()?;
        (start, end)
    };
    p.done().then_some(Rule {
        std,
        dst: Some((dst, start, end)),
    })
}

struct Parser<'a> {
    s: &'a [u8],
    at: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.at).copied()
    }

    fn done(&self) -> bool {
        self.at == self.s.len()
    }

    fn eat(&mut self, c: u8) -> Option<()> {
        (self.peek() == Some(c)).then(|| self.at += 1)
    }

    /// A zone abbreviation: three or more letters, or `<...>` of letters, digits, `+` and `-`.
    fn name(&mut self) -> Option<&'a [u8]> {
        if self.eat(b'<').is_some() {
            let start = self.at;
            while self
                .peek()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'-')
            {
                self.at += 1;
            }
            let name = &self.s[start..self.at];
            self.eat(b'>')?;
            return (name.len() >= 3).then_some(name);
        }
        let start = self.at;
        while self.peek().is_some_and(|c| c.is_ascii_alphabetic()) {
            self.at += 1;
        }
        let name = &self.s[start..self.at];
        (name.len() >= 3).then_some(name)
    }

    fn number(&mut self, max: u32) -> Option<u32> {
        let start = self.at;
        let mut n: u32 = 0;
        while let Some(c) = self.peek().filter(u8::is_ascii_digit) {
            n = n.checked_mul(10)?.checked_add(u32::from(c - b'0'))?;
            self.at += 1;
        }
        (self.at > start && n <= max).then_some(n)
    }

    /// `[+|-]hh[:mm[:ss]]` in seconds, with hours up to `max_hours`.
    fn offset(&mut self, max_hours: u32) -> Option<i32> {
        let sign = match self.peek() {
            Some(b'-') => {
                self.at += 1;
                -1
            }
            Some(b'+') => {
                self.at += 1;
                1
            }
            _ => 1,
        };
        let mut secs = self.number(max_hours)? * 3600;
        if self.eat(b':').is_some() {
            secs += self.number(59)? * 60;
            if self.eat(b':').is_some() {
                secs += self.number(59)?;
            }
        }
        Some(sign * secs as i32)
    }

    /// `date[/time]`, the time defaulting to 02:00:00.
    fn change(&mut self) -> Option<Change> {
        let day = match self.peek()? {
            b'J' => {
                self.at += 1;
                Day::Julian(self.number(365).filter(|&n| n >= 1)? as u16)
            }
            b'M' => {
                self.at += 1;
                let month = self.number(12).filter(|&n| n >= 1)? as u8;
                self.eat(b'.')?;
                let week = self.number(5).filter(|&n| n >= 1)? as u8;
                self.eat(b'.')?;
                let weekday = self.number(6)? as u8;
                Day::Month {
                    month,
                    week,
                    weekday,
                }
            }
            _ => Day::Ordinal(self.number(365)? as u16),
        };
        let time = match self.eat(b'/') {
            Some(()) => self.offset(167)?,
            None => 7200,
        };
        Some((day, time))
    }
}

/// Fills `tm` with `t` in `zone`, as localtime_r(3) does; `false` when the year does not fit
/// `tm_year` (`EOVERFLOW`).
pub(crate) fn break_down(zone: &Zone, t: i64, tm: &mut libc::tm) -> bool {
    // Every year `tm_year` holds lies within 2^56 seconds of the epoch.
    if t.unsigned_abs() >= 1 << 56 {
        return false;
    }
    let ty = zone.at(t);
    let Some(local) = t.checked_add(i64::from(ty.utoff)) else {
        return false;
    };
    let days = local.div_euclid(86_400);
    let secs = local.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let Ok(tm_year) = i32::try_from(year - 1900) else {
        return false;
    };
    tm.tm_sec = (secs % 60) as i32;
    tm.tm_min = (secs / 60 % 60) as i32;
    tm.tm_hour = (secs / 3600) as i32;
    tm.tm_mday = day as i32;
    tm.tm_mon = month as i32 - 1;
    tm.tm_year = tm_year;
    tm.tm_wday = (days + 4).rem_euclid(7) as i32;
    tm.tm_yday = (days - days_from_civil(year, 1, 1)) as i32;
    tm.tm_isdst = i32::from(ty.isdst);
    tm.tm_gmtoff = ty.utoff.into();
    tm.tm_zone = ty.abbr.as_ptr() as _;
    true
}

/// mktime(3): the time `tm` names as local time in `zone`, with `tm` normalized and completed.
/// Out-of-range fields carry into the next larger ones. `Err` leaves `tm` alone and carries the
/// errno to set, if any.
///
/// A local time can name one instant, two (a fall-back overlap) or none (a spring-forward gap):
///
/// - In an overlap a non-negative `tm_isdst` picks the instant of that kind; with `tm_isdst`
///   negative POSIX leaves the choice open, glibc's choice depends on the offset its previous
///   `mktime` call in the process found, and tzcode's on its binary search, so the sim takes the
///   earlier.
/// - In a gap both libraries move the time by the gap's size, preferring the result whose kind
///   differs from a non-negative `tm_isdst`; for a negative one glibc prefers daylight time and
///   tzcode the later side.
/// - A `tm_isdst` that no instant of the local time has is [`mismatched`].
pub(crate) fn make_time(zone: &Zone, tm: &mut libc::tm) -> Result<i64, Option<libc::c_int>> {
    let month = i64::from(tm.tm_mon);
    let year = i64::from(tm.tm_year) + 1900 + month.div_euclid(12);
    let days = days_from_civil(year, month.rem_euclid(12) + 1, 1) + i64::from(tm.tm_mday) - 1;
    let local = days * 86_400
        + i64::from(tm.tm_hour) * 3600
        + i64::from(tm.tm_min) * 60
        + i64::from(tm.tm_sec);
    let found = instants(zone, local);
    let wanted = (tm.tm_isdst >= 0).then_some(tm.tm_isdst > 0);
    let t = match (found.first(), wanted) {
        (None, _) => {
            let probe = local - i64::from(zone.at(local).utoff);
            let before = zone.at(probe - 86_400);
            let after = zone.at(probe + 86_400);
            // `local` in `before`'s offset lands after the gap, in `after`; in `after`'s, before
            // it. With a negative `tm_isdst` glibc prefers the side in daylight time, tzcode the
            // later one.
            let prefer_before = match wanted {
                Some(dst) => before.isdst != dst && after.isdst == dst,
                None => cfg!(target_os = "linux") && before.isdst && !after.isdst,
            };
            let ty = if prefer_before { after } else { before };
            local - i64::from(ty.utoff)
        }
        (Some(&(t, _)), None) => t,
        (Some(&first), Some(dst)) => match found.iter().find(|f| f.1.isdst == dst) {
            Some(f) => f.0,
            None => mismatched(zone, local, first, dst)?,
        },
    };
    let mut out = *tm;
    if !break_down(zone, t, &mut out) {
        return Err(Some(libc::EOVERFLOW));
    }
    *tm = out;
    Ok(t)
}

/// Every instant whose local time in `zone` is `local`, earliest first, with its type.
fn instants(zone: &Zone, local: i64) -> Vec<(i64, LocalType)> {
    let mut found: Vec<(i64, LocalType)> = Vec::new();
    for d in -2..=2 {
        let t = local - i64::from(zone.at(local + d * 86_400).utoff);
        let ty = zone.at(t);
        if t + i64::from(ty.utoff) == local && !found.iter().any(|f| f.0 == t) {
            found.push((t, ty));
        }
    }
    found.sort_by_key(|f| f.0);
    found
}

/// The time for a local time whose only instants, `found` among them, are not of the kind
/// `dst` asks for. glibc's `__mktime_internal` (time/mktime.c) looks a week at a time up to
/// about seven years either side of `found` for a type of that kind and takes the local time in
/// its offset, and failing that moves the time an hour.
#[cfg(target_os = "linux")]
fn mismatched(
    zone: &Zone,
    local: i64,
    (t, ty): (i64, LocalType),
    dst: bool,
) -> Result<i64, Option<libc::c_int>> {
    const STRIDE: i64 = 601_200;
    const BOUND: i64 = 457_243_200 / 2 + STRIDE;
    let mut delta = STRIDE;
    while delta < BOUND {
        for other in [t - delta, t + delta] {
            let o = zone.at(other);
            if o.isdst == dst {
                return Ok(local - i64::from(o.utoff));
            }
        }
        delta += STRIDE;
    }
    Ok(t + 3600 * (i64::from(!dst) - i64::from(!ty.isdst)))
}

/// The time for a local time whose only instants, `found` among them, are not of the kind
/// `dst` asks for. tzcode's `time1` (Apple Libc stdtime/FreeBSD/localtime.c) assumes the time
/// was computed in the most recent type of that kind, converts it into the most recent type of
/// the other kind and looks that up; a zone with no type of that kind fails without setting
/// errno. A TZ string without daylight time has no kinds to tell apart, and its one type
/// serves either.
#[cfg(target_os = "macos")]
fn mismatched(
    zone: &Zone,
    local: i64,
    (t, _): (i64, LocalType),
    dst: bool,
) -> Result<i64, Option<libc::c_int>> {
    if zone.transitions.is_empty() && zone.rule.as_ref().is_some_and(|r| r.dst.is_none()) {
        return Ok(t);
    }
    let recent = zone.recent_types();
    for same in recent.iter().filter(|ty| ty.isdst == dst) {
        for other in recent.iter().filter(|ty| ty.isdst != dst) {
            let moved = local + i64::from(other.utoff) - i64::from(same.utoff);
            if let Some(f) = instants(zone, moved).iter().find(|f| f.1.isdst != dst) {
                return Ok(f.0);
            }
        }
    }
    Err(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(s: &str) -> Zone {
        Zone::from_rule(parse_posix(s.as_bytes()).unwrap())
    }

    #[test]
    fn calendar_round_trips() {
        for days in [-800_000, -1, 0, 59, 365, 11_016, 19_000, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
    }

    #[test]
    fn posix_rules() {
        let z = rule("CST6CDT,M3.2.0,M11.1.0");
        // 2023-03-12 07:59:59 UTC is 01:59:59 CST; one second later is 03:00 CDT.
        assert_eq!(z.at(1_678_607_999).utoff, -6 * 3600);
        assert_eq!(z.at(1_678_608_000).utoff, -5 * 3600);
        // 2023-11-05 06:59:59 UTC is 01:59:59 CDT; one second later 01:00 CST.
        assert_eq!(z.at(1_699_167_599).utoff, -5 * 3600);
        assert_eq!(z.at(1_699_167_600).utoff, -6 * 3600);
        let z = rule("<+1030>-10:30<+11>-11,M10.1.0,M4.1.0");
        assert_eq!(z.at(1_700_000_000).utoff, 11 * 3600);
        assert_eq!(z.at(1_690_000_000).utoff, 10 * 3600 + 1800);
        assert_eq!(rule("JST-9").at(0).utoff, 9 * 3600);
        assert_eq!(rule("JST-9").at(0).abbr, c"JST");
        assert!(parse_posix(b"Asia/Tokyo").is_none());
        assert!(parse_posix(b"JS-9").is_none());
        assert!(parse_posix(b"EST5EDT,M3.2.0").is_none());
    }

    #[test]
    fn mktime_gaps_and_overlaps() {
        let z = rule("CST6CDT,M3.2.0,M11.1.0");
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_year = 123;
        tm.tm_mon = 2;
        tm.tm_mday = 12;
        tm.tm_hour = 2;
        tm.tm_min = 30;
        tm.tm_isdst = -1;
        // 02:30 does not exist; CST applies, giving 03:30 CDT.
        assert_eq!(make_time(&z, &mut tm), Ok(1_678_609_800));
        assert_eq!((tm.tm_hour, tm.tm_isdst), (3, 1));
        tm.tm_mon = 10;
        tm.tm_mday = 5;
        tm.tm_hour = 1;
        tm.tm_min = 30;
        tm.tm_isdst = 0;
        assert_eq!(make_time(&z, &mut tm), Ok(1_699_169_400));
        tm.tm_hour = 1;
        tm.tm_isdst = 1;
        assert_eq!(make_time(&z, &mut tm), Ok(1_699_165_800));
        tm.tm_mon = 0;
        tm.tm_mday = 32;
        tm.tm_hour = 0;
        tm.tm_min = 0;
        tm.tm_isdst = -1;
        make_time(&z, &mut tm).unwrap();
        assert_eq!((tm.tm_mon, tm.tm_mday, tm.tm_yday), (1, 1, 31));
    }
}
