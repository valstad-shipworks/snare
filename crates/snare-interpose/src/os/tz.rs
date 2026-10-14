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
//! data shared by every thread, so no sim can own them, and writing a sim's values into them
//! would show them to every other sim and to code outside. What the C library reads from them
//! inside itself — strftime(3)'s `%Z` of a `struct tm` without a zone name, and on macOS its
//! `%z` — the sim answers from a copy of its own ([`strftime_inputs`], [`note_conversion`]).

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

#[path = "tz_mktime.rs"]
mod mktime;

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
    /// Whether it comes from a TZ string alone, without a file.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    posix: bool,
    quirk: Quirk,
}

/// How a zone from an unusual `TZ` differs from the zone of its type alone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Quirk {
    None,
    /// tzcode's zone for an empty `TZ`, UTC with no local time types at all ("user wants it
    /// fast rather than right"): tzset leaves no names, and mktime fails for daylight time.
    Untyped,
    /// glibc's zone for a `TZ` whose offset does not parse: tzset leaves the daylight name
    /// empty (`__tzset_parse_tz` sets both names to "" before parsing).
    Unparsed,
}

/// A zone with where it came from: its IANA name when one is known, and its TZif bytes when it
/// came from a file. CoreFoundation's zone is built from the name and bytes.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) struct Resolved {
    pub(crate) zone: Zone,
    pub(crate) name: Option<String>,
    pub(crate) data: Option<Vec<u8>>,
    /// The `TZ` and `TZDIR` it was resolved from, which name the zone a sim's `tzname` follows.
    key: (Option<Vec<u8>>, Option<Vec<u8>>),
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
    let mut resolved = resolve(&setting);
    resolved.key = (setting.tz.clone(), setting.tzdir.clone());
    let resolved = Rc::new(resolved);
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
        [] => {
            let mut fast = utc();
            fast.zone.quirk = Quirk::Untyped;
            return fast;
        }
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
            key: Default::default(),
        };
    }
    match parse_posix(tz) {
        Some(rule) => Resolved {
            zone: Zone::from_rule(rule),
            name: None,
            data: None,
            key: Default::default(),
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
    let mut zone = Zone::from_rule(Rule {
        std: LocalType {
            utoff: 0,
            isdst: false,
            abbr: intern(abbr),
        },
        dst: None,
    });
    zone.quirk = Quirk::Unparsed;
    Resolved {
        zone,
        name: None,
        data: None,
        key: Default::default(),
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
        key: Default::default(),
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
        key: Default::default(),
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
            posix: true,
            quirk: Quirk::None,
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
        posix: false,
        quirk: Quirk::None,
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

/// The standard and daylight types tzset(3) leaves in `tzname` (and, on macOS, `timezone` and
/// `altzone`) for `zone`: those of the latest transitions of each kind, as glibc's
/// `__tzfile_read` and tzcode's `settzname` scan them from the end, or a TZ string's own. A
/// zone without daylight time gets its standard type twice from glibc, and from tzcode a type
/// of three spaces (`WILDABBR`) at the offset of the first transition's type.
pub(crate) fn tzset_types(zone: &Zone) -> (LocalType, LocalType) {
    let (mut std, mut dst) = (None, None);
    for &i in zone.indices.iter().rev() {
        let ty = zone.types[usize::from(i)];
        let slot = if ty.isdst { &mut dst } else { &mut std };
        slot.get_or_insert(ty);
        if std.is_some() && dst.is_some() {
            break;
        }
    }
    if zone.transitions.is_empty()
        && let Some(rule) = &zone.rule
    {
        std = Some(rule.std);
        dst = rule.dst.map(|d| d.0);
    }
    let first = zone
        .indices
        .first()
        .map_or(zone.types[0], |&i| zone.types[usize::from(i)]);
    if cfg!(target_os = "macos") {
        let wild = LocalType {
            abbr: intern(b"   "),
            ..first
        };
        if zone.quirk == Quirk::Untyped {
            return (wild, wild);
        }
        (std.unwrap_or(wild), dst.unwrap_or(wild))
    } else {
        let std = std.unwrap_or(zone.types[0]);
        if zone.quirk == Quirk::Unparsed {
            return (std, LocalType { abbr: c"", ..std });
        }
        (std, dst.unwrap_or(std))
    }
}

/// What the C library's `tzname` holds in a sim: the names tzset(3) left for the zone named by
/// `key`, as the sim's conversions have moved them since.
struct TzNames {
    key: (Option<Vec<u8>>, Option<Vec<u8>>),
    names: [&'static CStr; 2],
}

/// The calling thread's sim's `tzname` state, `None` off a sim.
fn sim_names() -> Option<std::sync::Arc<std::sync::Mutex<Option<TzNames>>>> {
    crate::domain::sim_local(|| std::sync::Mutex::new(None))
}

/// Runs `op` on the calling sim's `tzname` for `resolved`'s zone, starting from the names tzset(3)
/// leaves ([`tzset_types`]) when the sim has none yet or had them for another zone. `None` off a
/// sim.
fn with_names<R>(resolved: &Resolved, op: impl FnOnce(&mut [&'static CStr; 2]) -> R) -> Option<R> {
    let state = sim_names()?;
    let _passthrough = crate::state::Passthrough::enter();
    let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
    let current = match &mut *state {
        Some(n) if n.key == resolved.key => n,
        slot => {
            let (std, dst) = tzset_types(&resolved.zone);
            slot.insert(TzNames {
                key: resolved.key.clone(),
                names: [std.abbr, dst.abbr],
            })
        }
    };
    Some(op(&mut current.names))
}

/// The calling sim's `tzname` for `resolved`'s zone.
fn tzname(resolved: &Resolved) -> [&'static CStr; 2] {
    with_names(resolved, |names| *names).unwrap_or_else(|| {
        let (std, dst) = tzset_types(&resolved.zone);
        [std.abbr, dst.abbr]
    })
}

/// Moves the calling sim's `tzname` as the C library does when it converts `t` to local time:
/// tzcode names the type of `t` (`localsub`), glibc the types around it (`__tzfile_compute`),
/// leaving a TZ string's names alone.
pub(crate) fn note_conversion(resolved: &Resolved, t: i64) {
    let zone = &resolved.zone;
    let ty = zone.at(t);
    with_names(resolved, |names| {
        if cfg!(target_os = "macos") {
            names[usize::from(ty.isdst)] = ty.abbr;
        } else if !zone.transitions.is_empty() {
            let (std, dst) = glibc_names_at(zone, t);
            *names = [std.abbr, dst.abbr];
        }
    });
}

/// glibc's `__tzfile_compute` names for `t` in a zone with transitions: before the first, the
/// first standard type and the first daylight type of the file; after the last, the TZ string's
/// (`__tzset_parse_tz`, its standard name twice without daylight time); otherwise the type of
/// the transition before `t` and, for the other kind, the first after it, a missing standard
/// name taking the daylight one and a missing daylight name the standard one.
fn glibc_names_at(zone: &Zone, t: i64) -> (LocalType, LocalType) {
    let count = zone.transitions.len();
    let ty = |i: usize| zone.types[usize::from(zone.indices[i])];
    let mut names: [Option<LocalType>; 2] = [None, None];
    if t < zone.transitions[0] {
        let mut i = 0;
        while i < zone.types.len() && zone.types[i].isdst {
            names[1].get_or_insert(zone.types[i]);
            i += 1;
        }
        if i == zone.types.len() {
            i = 0;
        }
        names[0] = Some(zone.types[i]);
        if names[1].is_none() {
            names[1] = zone.types[i..].iter().copied().find(|t| t.isdst);
        }
    } else {
        if t >= zone.transitions[count - 1]
            && let Some(rule) = &zone.rule
        {
            return (rule.std, rule.dst.map_or(rule.std, |d| d.0));
        }
        let i = zone.transitions.partition_point(|&x| x <= t);
        let before = ty(i - 1);
        names[usize::from(before.isdst)] = Some(before);
        for j in i..count {
            let next = ty(j);
            let slot = &mut names[usize::from(next.isdst)];
            if slot.is_none() {
                *slot = Some(next);
                if names[0].is_some() && names[1].is_some() {
                    break;
                }
            }
        }
        if names[0].is_none() {
            names[0] = names[1];
        }
    }
    let std = names[0].unwrap_or(zone.types[0]);
    (std, names[1].unwrap_or(std))
}

/// A character of a strftime(3) format, narrow or wide.
pub(crate) trait FormatUnit: Copy + Eq {
    fn of(byte: u8) -> Self;
    fn digit(self) -> Option<u32>;
}

impl FormatUnit for std::ffi::c_char {
    fn of(byte: u8) -> Self {
        byte as Self
    }

    #[allow(clippy::unnecessary_cast)]
    fn digit(self) -> Option<u32> {
        (self as u8 as char).to_digit(10)
    }
}

impl FormatUnit for libc::wchar_t {
    fn of(byte: u8) -> Self {
        Self::from(byte)
    }

    #[allow(clippy::unnecessary_cast)]
    fn digit(self) -> Option<u32> {
        char::from_u32(self as u32)?.to_digit(10)
    }
}

/// What strftime(3) should be handed for `format` and `tm` in `zone`, when it differs from what
/// the caller passed. The C library reads its own zone for three conversions, which the sim
/// answers from `zone` instead:
///
/// - `%Z` of a `struct tm` without a zone name prints `tzname[tm_isdst]` (glibc: an empty name
///   too, and `"?"` past 1; tzcode: `tm_isdst != 0`), which the sim keeps per sim
///   ([`note_conversion`]); the copy of `tm` handed on carries that name, so the formats `%c`
///   and `%+` expand to are covered too. The library's `tzname` moves with the conversion a
///   `%s` makes, so a `%Z` after a `%s` in the same format can print a name the sim's does not.
/// - `%s` is mktime(3) of a copy of `tm`; it is replaced by the sim's, padded to the GNU field
///   width with zeros for the `0` flag and spaces otherwise.
/// - On macOS `%z` is `timezone` for `tm_isdst` 0 and `altzone` above, not `tm_gmtoff`
///   (UNIX03), and nothing below; padded by the `-`, `_` and `0` flags as tzcode pads years.
pub(crate) fn strftime_inputs<C: FormatUnit>(
    resolved: &Resolved,
    format: *const C,
    tm: &libc::tm,
) -> Option<(Option<Vec<C>>, libc::tm)> {
    let (std, dst) = tzset_types(&resolved.zone);
    let [std_name, dst_name] = tzname(resolved);
    let mut named = *tm;
    // SAFETY: a non-null `tm_zone` is the caller's C string.
    let unnamed = tm.tm_zone.is_null()
        || (cfg!(target_os = "linux") && unsafe { *tm.tm_zone } == 0);
    if unnamed && tm.tm_isdst >= 0 {
        let name = match tm.tm_isdst {
            0 => std_name,
            1 => dst_name,
            _ if cfg!(target_os = "linux") => c"?",
            _ => dst_name,
        };
        named.tm_zone = name.as_ptr() as _;
    }
    let mut units = Vec::new();
    // SAFETY: the caller's NUL-terminated format.
    unsafe {
        let mut at = format;
        while *at != C::of(0) {
            units.push(*at);
            at = at.add(1);
        }
    }
    let rewritten = rewrite_format(resolved, &units, tm, (std, dst));
    let changed = unnamed && tm.tm_isdst >= 0;
    (changed || rewritten.is_some()).then(|| {
        (
            rewritten.map(|mut f| {
                f.push(C::of(0));
                f
            }),
            named,
        )
    })
}

/// `units` with each `%s`, and on macOS each `%z`, replaced by its text; `None` when it has none.
fn rewrite_format<C: FormatUnit>(
    resolved: &Resolved,
    units: &[C],
    tm: &libc::tm,
    (std, dst): (LocalType, LocalType),
) -> Option<Vec<C>> {
    let percent = C::of(b'%');
    let mut out = Vec::with_capacity(units.len());
    let mut changed = false;
    let mut at = 0;
    while at < units.len() {
        if units[at] != percent {
            out.push(units[at]);
            at += 1;
            continue;
        }
        let Some(spec) = directive(units, at) else {
            out.extend_from_slice(&units[at..]);
            break;
        };
        let end = spec.end;
        let text = if units[end] == C::of(b's') {
            let mut copy = *tm;
            let t = match make_time(&resolved.zone, &mut copy) {
                Ok(t) => {
                    note_conversion(resolved, t);
                    t
                }
                Err(_) => -1,
            };
            let digits = t.to_string();
            let width = spec.width.max(digits.len());
            let fill = if spec.pad == Some(b'0') { '0' } else { ' ' };
            Some(format!("{}{digits}", fill.to_string().repeat(width - digits.len())))
        } else if cfg!(target_os = "macos") && units[end] == C::of(b'z') {
            Some(match tm.tm_isdst {
                ..0 => String::new(),
                isdst => {
                    let east = if isdst == 0 { std.utoff } else { dst.utoff };
                    let minutes = east.abs() / 60;
                    let value = minutes / 60 * 100 + minutes % 60;
                    let sign = if east < 0 { '-' } else { '+' };
                    match spec.pad {
                        Some(b'-') => format!("{sign}{value}"),
                        Some(b'_') => format!("{sign}{value:4}"),
                        _ => format!("{sign}{value:04}"),
                    }
                }
            })
        } else {
            None
        };
        match text {
            Some(text) => {
                changed = true;
                for b in text.bytes() {
                    if b == b'%' {
                        out.push(percent);
                    }
                    out.push(C::of(b));
                }
            }
            None => out.extend_from_slice(&units[at..=end]),
        }
        at = end + 1;
    }
    changed.then_some(out)
}

/// A strftime(3) conversion: where its conversion character is, its padding flag and its field
/// width.
struct Directive {
    end: usize,
    pad: Option<u8>,
    width: usize,
}

/// The conversion starting with the `%` at `at`, as the C library reads it: glibc takes flags
/// (`_`, `-`, `0`, `^`, `#`), a field width, then an `E` or `O` modifier; tzcode takes at most
/// one `E` or `O` and one of `-`, `_`, `0`, in any order, and no width. `None` when the format
/// ends first.
fn directive<C: FormatUnit>(units: &[C], at: usize) -> Option<Directive> {
    let mut i = at + 1;
    let mut pad = None;
    let mut width = 0usize;
    let is = |i: usize, b: u8| units.get(i) == Some(&C::of(b));
    if cfg!(target_os = "linux") {
        while let Some(&c) = units.get(i) {
            match b"_-0^#".iter().copied().find(|&b| c == C::of(b)) {
                Some(b) => {
                    if b != b'^' && b != b'#' {
                        pad = Some(b);
                    }
                    i += 1;
                }
                None => break,
            }
        }
        while let Some(d) = units.get(i).and_then(|c| c.digit()) {
            width = width.saturating_mul(10).saturating_add(d as usize);
            i += 1;
        }
        if is(i, b'E') || is(i, b'O') {
            i += 1;
        }
    } else {
        let mut modifier = false;
        loop {
            if !modifier && (is(i, b'E') || is(i, b'O')) {
                modifier = true;
            } else if let Some(b) = b"-_0"
                .iter()
                .copied()
                .find(|&b| pad.is_none() && is(i, b))
            {
                pad = Some(b);
            } else {
                break;
            }
            i += 1;
        }
    }
    (i < units.len()).then_some(Directive {
        end: i,
        pad,
        width,
    })
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
/// Out-of-range fields carry into the next larger ones. `Err` carries the errno to set, if any.
///
/// On Linux, glibc's search, step for step (`mktime::glibc`), from the offset the sim's previous
/// call found, as glibc keeps it for the process; it fails with `EOVERFLOW`, leaving `tm` alone.
///
/// On macOS, tzcode's, step for step (`mktime::tzcode`). It keeps `errno`; it makes a
/// `tm_isdst` above 1 into 1 first, and a negative one into 0 where it finds no instant, even
/// when it fails.
pub(crate) fn make_time(zone: &Zone, tm: &mut libc::tm) -> Result<i64, Option<libc::c_int>> {
    #[cfg(target_os = "linux")]
    {
        with_mktime_offset(|offset| mktime::glibc::mktime(zone, tm, offset))
            .ok_or(Some(libc::EOVERFLOW))
    }
    #[cfg(target_os = "macos")]
    {
        mktime::tzcode::mktime(zone, tm).ok_or(None)
    }
}

/// glibc's `localtime_offset`, the offset its previous mktime(3) found: one per sim, as glibc
/// has one per process.
#[cfg(target_os = "linux")]
struct MktimeOffset(std::sync::Mutex<i64>);

/// Runs `op` on the calling sim's [`MktimeOffset`], or on a fresh one off a sim.
#[cfg(target_os = "linux")]
fn with_mktime_offset<R>(op: impl FnOnce(&mut i64) -> R) -> R {
    match crate::domain::sim_local(|| MktimeOffset(std::sync::Mutex::new(0))) {
        Some(state) => {
            let _passthrough = crate::state::Passthrough::enter();
            let mut offset = state.0.lock().unwrap_or_else(|e| e.into_inner());
            op(&mut offset)
        }
        None => op(&mut 0),
    }
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
