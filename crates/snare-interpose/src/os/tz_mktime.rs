//! mktime(3) as each C library computes it, over a sim's zone. Both search for the instant whose
//! local time is the one asked for, and where a local time names two instants or none, the one
//! found depends on how they search: glibc's from the offset its previous call found
//! (time/mktime.c `__mktime_internal`, which the sim keeps per sim), tzcode's by bisecting the
//! whole range of `time_t` (Apple Libc stdtime/FreeBSD/localtime.c `time1`, `time2sub`). These
//! follow them step for step, converting with the sim's zone where they call localtime.

use super::{Zone, break_down};

/// The local time of `t` in `zone` as the C library's localtime_r(3) gives it, `None` where the
/// year overflows (`EOVERFLOW`).
fn convert(zone: &Zone, t: i64) -> Option<libc::tm> {
    // SAFETY: all-zero is a valid struct tm.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    break_down(zone, t, &mut tm).then_some(tm)
}

/// glibc 2.41 time/mktime.c.
#[cfg(target_os = "linux")]
pub(super) mod glibc {
    use super::convert;
    use crate::os::tz::Zone;

    /// `leapyear`, for years since 1900.
    fn leapyear(year: i64) -> bool {
        (year & 3) == 0 && (year % 100 != 0 || ((year / 100) & 3) == (-(1900 / 100) & 3))
    }

    const MON_YDAY: [[i64; 13]; 2] = [
        [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365],
        [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366],
    ];

    /// `isdst_differ`: whether `a` and `b` disagree as `tm_isdst` values, both being set.
    fn isdst_differ(a: i32, b: i32) -> bool {
        ((a == 0) != (b == 0)) && a >= 0 && b >= 0
    }

    /// `shr`: `a` shifted right by `b`, rounding toward minus infinity.
    fn shr(a: i64, b: u32) -> i64 {
        a >> b
    }

    /// `ydhms_diff`: (year1-yday1 hour1:min1:sec1) less (year0-yday0 hour0:min0:sec0) in
    /// seconds, years counted from 1900, without leap seconds.
    #[allow(clippy::too_many_arguments)]
    fn ydhms_diff(
        year1: i64,
        yday1: i64,
        hour1: i32,
        min1: i32,
        sec1: i32,
        year0: i32,
        yday0: i32,
        hour0: i32,
        min0: i32,
        sec0: i32,
    ) -> i64 {
        let year0 = i64::from(year0);
        let a4 = shr(year1, 2) + shr(1900, 2) - i64::from(year1 & 3 == 0);
        let b4 = shr(year0, 2) + shr(1900, 2) - i64::from(year0 & 3 == 0);
        let a100 = (a4 + i64::from(a4 < 0)) / 25 - i64::from(a4 < 0);
        let b100 = (b4 + i64::from(b4 < 0)) / 25 - i64::from(b4 < 0);
        let a400 = shr(a100, 2);
        let b400 = shr(b100, 2);
        let leap_days = (a4 - b4) - (a100 - b100) + (a400 - b400);
        let years = year1 - year0;
        let days = 365 * years + yday1 - i64::from(yday0) + leap_days;
        let hours = 24 * days + i64::from(hour1) - i64::from(hour0);
        let minutes = 60 * hours + i64::from(min1) - i64::from(min0);
        60 * minutes + i64::from(sec1) - i64::from(sec0)
    }

    /// `tm_diff`: the requested time less `tm`.
    fn tm_diff(year: i64, yday: i64, hour: i32, min: i32, sec: i32, tm: &libc::tm) -> i64 {
        ydhms_diff(
            year, yday, hour, min, sec, tm.tm_year, tm.tm_yday, tm.tm_hour, tm.tm_min, tm.tm_sec,
        )
    }

    /// `long_int_avg`, rounding toward plus infinity.
    fn avg(a: i64, b: i64) -> i64 {
        shr(a, 1) + shr(b, 1) + ((a | b) & 1)
    }

    /// `ranged_convert`: `t` converted, or, when it overflows, the nearest time that does not,
    /// found by bisecting toward 0.
    fn ranged_convert(zone: &Zone, t: &mut i64) -> Option<libc::tm> {
        if let Some(tm) = convert(zone, *t) {
            return Some(tm);
        }
        let (mut ok, mut bad) = (0, *t);
        let mut found = None;
        loop {
            let mid = avg(ok, bad);
            if mid == ok || mid == bad {
                break;
            }
            match convert(zone, mid) {
                Some(tm) => {
                    ok = mid;
                    found = Some(tm);
                }
                None => bad = mid,
            }
        }
        let tm = found?;
        *t = ok;
        Some(tm)
    }

    /// `__mktime_internal` with localtime: `tm` normalized and its time, `offset` being the
    /// offset the previous call found and becoming this one's; `None` leaves `tm` alone, for
    /// `EOVERFLOW`.
    pub(crate) fn mktime(zone: &Zone, tp: &mut libc::tm, offset: &mut i64) -> Option<i64> {
        let mut remaining_probes = 6;
        let mut sec = tp.tm_sec;
        let min = tp.tm_min;
        let hour = tp.tm_hour;
        let mday = tp.tm_mday;
        let mon = tp.tm_mon;
        let isdst = tp.tm_isdst;
        let mut dst2 = false;
        let mon_remainder = mon % 12;
        let negative_mon_remainder = i32::from(mon_remainder < 0);
        let mon_years = mon / 12 - negative_mon_remainder;
        let year = i64::from(tp.tm_year) + i64::from(mon_years);
        let mon_yday = MON_YDAY[usize::from(leapyear(year))]
            [(mon_remainder + 12 * negative_mon_remainder) as usize]
            - 1;
        let yday = mon_yday + i64::from(mday);
        let sec_requested = sec;
        sec = sec.clamp(0, 59);
        let negative_offset_guess = 0i32.wrapping_sub(*offset as i32);
        let t0 = ydhms_diff(year, yday, hour, min, sec, 70, 0, 0, 0, negative_offset_guess);
        let (mut t, mut t1, mut t2) = (t0, t0, t0);
        let mut tm;
        'search: {
            loop {
                tm = ranged_convert(zone, &mut t)?;
                let dt = tm_diff(year, yday, hour, min, sec, &tm);
                if dt == 0 {
                    break;
                }
                if t == t1
                    && t != t2
                    && (tm.tm_isdst < 0
                        || if isdst < 0 {
                            dst2 <= (tm.tm_isdst != 0)
                        } else {
                            (isdst != 0) != (tm.tm_isdst != 0)
                        })
                {
                    break 'search;
                }
                remaining_probes -= 1;
                if remaining_probes == 0 {
                    return None;
                }
                (t1, t2) = (t2, t);
                t += dt;
                dst2 = tm.tm_isdst != 0;
            }
            if isdst_differ(isdst, tm.tm_isdst) {
                let dst_difference = i64::from(isdst == 0) - i64::from(tm.tm_isdst == 0);
                const STRIDE: i64 = 601_200;
                const DURATION_MAX: i64 = 457_243_209;
                let delta_bound = DURATION_MAX / 2 + STRIDE;
                let mut delta = STRIDE;
                while delta < delta_bound {
                    for direction in [-1, 1] {
                        let Some(mut ot) = t.checked_add(delta * direction) else {
                            continue;
                        };
                        let otm = ranged_convert(zone, &mut ot)?;
                        if !isdst_differ(isdst, otm.tm_isdst) {
                            let gt = ot + tm_diff(year, yday, hour, min, sec, &otm);
                            if let Some(gtm) = convert(zone, gt) {
                                t = gt;
                                tm = gtm;
                                break 'search;
                            }
                        }
                    }
                    delta += STRIDE;
                }
                t += 3600 * dst_difference;
                tm = convert(zone, t)?;
            }
        }
        *offset = t.wrapping_sub(t0).wrapping_sub(i64::from(negative_offset_guess));
        if sec_requested != tm.tm_sec {
            let adjustment = i64::from(sec == 0 && tm.tm_sec == 60) - i64::from(sec)
                + i64::from(sec_requested);
            t = t.checked_add(adjustment)?;
            tm = convert(zone, t)?;
        }
        *tp = tm;
        Some(t)
    }
}

/// tzcode as Apple Libc ships it (stdtime/FreeBSD/localtime.c), built with `PCTS` and
/// `__DARWIN_UNIX03`: a time with no instant of its own is taken as standard time and moved into
/// each other type, as a gap with a negative `tm_isdst` measured on macOS shows.
#[cfg(target_os = "macos")]
pub(super) mod tzcode {
    use super::convert;
    use crate::os::tz::{LocalType, Quirk, Zone};

    const YEAR_LENGTHS: [i32; 2] = [365, 366];
    const MON_LENGTHS: [[i32; 12]; 2] = [
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31],
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31],
    ];

    fn isleap(y: i64) -> bool {
        y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
    }

    /// `increment_overflow`: adds `delta`, reporting whether the `int` overflowed.
    fn increment_overflow(number: &mut i32, delta: i32) -> bool {
        let (sum, overflow) = number.overflowing_add(delta);
        *number = sum;
        overflow
    }

    /// `long_increment_overflow`.
    fn long_increment_overflow(number: &mut i64, delta: i32) -> bool {
        let (sum, overflow) = number.overflowing_add(i64::from(delta));
        *number = sum;
        overflow
    }

    /// The whole `base`s of `units`, flooring, which `normalize_overflow` carries.
    fn tens(units: i32, base: i32) -> i32 {
        if units >= 0 {
            units / base
        } else {
            -1 - (-1 - units) / base
        }
    }

    /// `normalize_overflow`: carries whole `base`s of `units` into `tens`.
    fn normalize_overflow(tens_slot: &mut i32, units: &mut i32, base: i32) -> bool {
        let delta = tens(*units, base);
        *units -= delta * base;
        increment_overflow(tens_slot, delta)
    }

    /// `long_normalize_overflow`.
    fn long_normalize_overflow(tens_slot: &mut i64, units: &mut i32, base: i32) -> bool {
        let delta = tens(*units, base);
        *units -= delta * base;
        long_increment_overflow(tens_slot, delta)
    }

    /// `tmcomp`: the order of two normalized times.
    fn tmcomp(a: &libc::tm, b: &libc::tm) -> i32 {
        if a.tm_year != b.tm_year {
            return if a.tm_year > b.tm_year { 1 } else { -1 };
        }
        [
            a.tm_mon - b.tm_mon,
            a.tm_mday - b.tm_mday,
            a.tm_hour - b.tm_hour,
            a.tm_min - b.tm_min,
            a.tm_sec - b.tm_sec,
        ]
        .into_iter()
        .find(|&d| d != 0)
        .unwrap_or(0)
    }

    /// The local time types tzcode holds for `zone` (`ttis`): none for an empty `TZ`; a TZ
    /// string's daylight type then standard type (`tzparse`); a file's own, followed by its TZ
    /// string's two when that has daylight time (`tzload`).
    fn ttis(zone: &Zone) -> Vec<LocalType> {
        if zone.quirk == Quirk::Untyped {
            return Vec::new();
        }
        let footer = zone.rule.as_ref().and_then(|r| r.dst.map(|d| [d.0, r.std]));
        match (zone.posix, footer) {
            (true, Some(pair)) => pair.to_vec(),
            (true, None) => zone.types.clone(),
            (false, footer) => zone.types.iter().copied().chain(footer.into_iter().flatten()).collect(),
        }
    }

    /// `time2sub` with `localsub`: `None` for `WRONG`.
    fn time2sub(zone: &Zone, tmp: &mut libc::tm, do_norm_secs: bool) -> Option<i64> {
        let mut yourtm = *tmp;
        if do_norm_secs && normalize_overflow(&mut yourtm.tm_min, &mut yourtm.tm_sec, 60) {
            return None;
        }
        if normalize_overflow(&mut yourtm.tm_hour, &mut yourtm.tm_min, 60)
            || normalize_overflow(&mut yourtm.tm_mday, &mut yourtm.tm_hour, 24)
        {
            return None;
        }
        let mut y = i64::from(yourtm.tm_year);
        if long_normalize_overflow(&mut y, &mut yourtm.tm_mon, 12)
            || long_increment_overflow(&mut y, 1900)
        {
            return None;
        }
        while yourtm.tm_mday <= 0 {
            if long_increment_overflow(&mut y, -1) {
                return None;
            }
            let li = y + i64::from(1 < yourtm.tm_mon);
            yourtm.tm_mday += YEAR_LENGTHS[usize::from(isleap(li))];
        }
        while yourtm.tm_mday > 366 {
            let li = y + i64::from(1 < yourtm.tm_mon);
            yourtm.tm_mday -= YEAR_LENGTHS[usize::from(isleap(li))];
            if long_increment_overflow(&mut y, 1) {
                return None;
            }
        }
        loop {
            let i = MON_LENGTHS[usize::from(isleap(y))][yourtm.tm_mon as usize];
            if yourtm.tm_mday <= i {
                break;
            }
            yourtm.tm_mday -= i;
            yourtm.tm_mon += 1;
            if yourtm.tm_mon >= 12 {
                yourtm.tm_mon = 0;
                if long_increment_overflow(&mut y, 1) {
                    return None;
                }
            }
        }
        if long_increment_overflow(&mut y, -1900) {
            return None;
        }
        yourtm.tm_year = y as i32;
        if i64::from(yourtm.tm_year) != y || yourtm.tm_year < 0 {
            return None;
        }
        let saved_seconds;
        if (0..60).contains(&yourtm.tm_sec) {
            saved_seconds = 0;
        } else if y + 1900 < 1970 {
            if increment_overflow(&mut yourtm.tm_sec, 1 - 60) {
                return None;
            }
            saved_seconds = yourtm.tm_sec;
            yourtm.tm_sec = 59;
        } else {
            saved_seconds = yourtm.tm_sec;
            yourtm.tm_sec = 0;
        }
        let ttis = ttis(zone);
        let (mut lo, mut hi) = (i64::MIN, i64::MAX);
        let mut t;
        loop {
            t = (lo / 2 + hi / 2).clamp(lo, hi);
            let mytm = convert(zone, t);
            let dir = match &mytm {
                None if t > 0 => 1,
                None => -1,
                Some(mine) => tmcomp(mine, &yourtm),
            };
            if dir != 0 {
                if t == lo {
                    t = t.checked_add(1)?;
                    lo += 1;
                } else if t == hi {
                    t = t.checked_sub(1)?;
                    hi -= 1;
                }
                if lo > hi {
                    return None;
                }
                if dir > 0 {
                    hi = t;
                } else {
                    lo = t;
                }
                continue;
            }
            if ttis.len() == 1 && yourtm.tm_isdst > 0 {
                yourtm.tm_isdst = 0;
            }
            let mine = mytm?;
            if yourtm.tm_isdst < 0 || mine.tm_isdst == yourtm.tm_isdst {
                break;
            }
            let wanted = yourtm.tm_isdst != 0;
            let mut matched = None;
            'hunt: for i in (0..ttis.len()).rev() {
                if ttis[i].isdst != wanted {
                    continue;
                }
                for j in (0..ttis.len()).rev() {
                    if ttis[j].isdst == wanted {
                        continue;
                    }
                    let newt = t + i64::from(ttis[j].utoff) - i64::from(ttis[i].utoff);
                    let Some(other) = convert(zone, newt) else {
                        continue;
                    };
                    if tmcomp(&other, &yourtm) == 0 && other.tm_isdst == yourtm.tm_isdst {
                        matched = Some(newt);
                        break 'hunt;
                    }
                }
            }
            t = matched?;
            break;
        }
        let newt = t.checked_add(i64::from(saved_seconds))?;
        *tmp = convert(zone, newt)?;
        Some(newt)
    }

    /// `time2`: without normalizing seconds first, in case `tm_sec` is a leap second, then with.
    fn time2(zone: &Zone, tmp: &mut libc::tm) -> Option<i64> {
        time2sub(zone, tmp, false).or_else(|| time2sub(zone, tmp, true))
    }

    /// `time1` with `localsub`: a `tm_isdst` above 1 taken as 1; a time with no instant of its
    /// own taken as standard time (`PCTS`), then as computed in each recent type of its kind and
    /// moved into each recent type of the other. `None` for `WRONG`, `tm` keeping the `tm_isdst`
    /// it got.
    pub(crate) fn mktime(zone: &Zone, tmp: &mut libc::tm) -> Option<i64> {
        if tmp.tm_isdst > 1 {
            tmp.tm_isdst = 1;
        }
        if let Some(t) = time2(zone, tmp) {
            return Some(t);
        }
        if tmp.tm_isdst < 0 {
            tmp.tm_isdst = 0;
        }
        if zone.quirk == Quirk::Untyped {
            return None;
        }
        let recent = zone.recent_types();
        let dst = tmp.tm_isdst != 0;
        for same in recent.iter().filter(|ty| ty.isdst == dst) {
            for other in recent.iter().filter(|ty| ty.isdst != dst) {
                let shift = other.utoff - same.utoff;
                tmp.tm_sec += shift;
                tmp.tm_isdst = i32::from(tmp.tm_isdst == 0);
                if let Some(t) = time2(zone, tmp) {
                    return Some(t);
                }
                tmp.tm_sec -= shift;
                tmp.tm_isdst = i32::from(tmp.tm_isdst == 0);
            }
        }
        None
    }
}
