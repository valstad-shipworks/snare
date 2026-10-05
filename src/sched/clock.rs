use std::sync::atomic::{AtomicBool, AtomicU64, Ordering, fence};

use parking_lot::{Mutex, MutexGuard};

use super::timer::{TimeSource, wall_now_ns};

const Q32: f64 = 4_294_967_296.0;
pub(crate) const MAX_RATE: f64 = 1e6;

/// `v(wall) = min(horizon, anchor_v + (wall - anchor_wall) * rate)`, with the
/// rate in 32.32 fixed point so large rates never saturate a float cast.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Line {
    pub anchor_v: u64,
    pub anchor_wall: u64,
    pub rate_q32: u64,
    pub horizon: u64,
}

impl Line {
    pub(crate) fn value_at(&self, wall: u64) -> u64 {
        let dw = wall.saturating_sub(self.anchor_wall) as u128;
        let dv = (dw * self.rate_q32 as u128) >> 32;
        let v = (self.anchor_v as u128 + dv).min(u64::MAX as u128) as u64;
        v.min(self.horizon)
    }

    pub(crate) fn wall_at(&self, v: u64) -> Option<u64> {
        if v > self.horizon {
            return None;
        }
        if v <= self.anchor_v {
            return Some(self.anchor_wall);
        }
        if self.rate_q32 == 0 {
            return None;
        }
        let dw = (((v - self.anchor_v) as u128) << 32).div_ceil(self.rate_q32 as u128);
        Some((self.anchor_wall as u128 + dw).min(u64::MAX as u128) as u64)
    }
}

fn sanitize(rate: f64) -> f64 {
    if rate.is_nan() {
        0.0
    } else {
        rate.clamp(0.0, MAX_RATE)
    }
}

pub(crate) fn rate_to_q32(rate: f64) -> u64 {
    (sanitize(rate) * Q32).round() as u64
}

struct Writer {
    resume_rate: f64,
}

/// Lock-free virtual clock. Readers go through a seqlock over the [`Line`];
/// writers serialise on `writer`. `last` makes `now()` monotone across
/// re-anchors and concurrent readers.
pub(crate) struct Clock {
    seq: AtomicU64,
    anchor_v: AtomicU64,
    anchor_wall: AtomicU64,
    rate_q32: AtomicU64,
    horizon: AtomicU64,
    rate_bits: AtomicU64,
    driven: AtomicBool,
    last: AtomicU64,
    resets: AtomicU64,
    writer: Mutex<Writer>,
}

impl Clock {
    pub(crate) fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            anchor_v: AtomicU64::new(0),
            anchor_wall: AtomicU64::new(wall_now_ns()),
            rate_q32: AtomicU64::new(rate_to_q32(1.0)),
            horizon: AtomicU64::new(u64::MAX),
            rate_bits: AtomicU64::new(1.0f64.to_bits()),
            driven: AtomicBool::new(false),
            last: AtomicU64::new(0),
            resets: AtomicU64::new(0),
            writer: Mutex::new(Writer { resume_rate: 1.0 }),
        }
    }

    pub(crate) fn line(&self) -> Line {
        loop {
            let s1 = self.seq.load(Ordering::Acquire);
            if s1 & 1 == 1 {
                std::hint::spin_loop();
                continue;
            }
            let line = Line {
                anchor_v: self.anchor_v.load(Ordering::Relaxed),
                anchor_wall: self.anchor_wall.load(Ordering::Relaxed),
                rate_q32: self.rate_q32.load(Ordering::Relaxed),
                horizon: self.horizon.load(Ordering::Relaxed),
            };
            fence(Ordering::Acquire);
            if self.seq.load(Ordering::Relaxed) == s1 {
                return line;
            }
        }
    }

    pub(crate) fn now(&self) -> u64 {
        'read: loop {
            let resets = self.resets.load(Ordering::SeqCst);
            let v = self.line().value_at(wall_now_ns());
            let mut cur = self.last.load(Ordering::SeqCst);
            loop {
                // A value computed from the line before a backwards
                // `set_value` must not be published over the reset floor.
                if self.resets.load(Ordering::SeqCst) != resets {
                    continue 'read;
                }
                if v <= cur {
                    return cur;
                }
                match self
                    .last
                    .compare_exchange_weak(cur, v, Ordering::SeqCst, Ordering::SeqCst)
                {
                    Ok(_) => return v,
                    Err(c) => cur = c,
                }
            }
        }
    }

    pub(crate) fn rate(&self) -> f64 {
        f64::from_bits(self.rate_bits.load(Ordering::Acquire))
    }

    pub(crate) fn is_driven(&self) -> bool {
        self.driven.load(Ordering::Acquire)
    }

    fn write(&self) -> MutexGuard<'_, Writer> {
        super::note_lock();
        self.writer.lock()
    }

    /// Current value at wall time `w`, never below anything already returned.
    fn current(&self, w: u64) -> u64 {
        self.line()
            .value_at(w)
            .max(self.last.load(Ordering::Acquire))
    }

    fn publish(&self, line: Line, rate: f64) {
        let s = self.seq.load(Ordering::Relaxed);
        self.seq.store(s.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        self.anchor_v.store(line.anchor_v, Ordering::Relaxed);
        self.anchor_wall.store(line.anchor_wall, Ordering::Relaxed);
        self.rate_q32.store(line.rate_q32, Ordering::Relaxed);
        self.horizon.store(line.horizon, Ordering::Relaxed);
        self.seq.store(s.wrapping_add(2), Ordering::Release);
        self.rate_bits.store(rate.to_bits(), Ordering::Release);
    }

    fn reanchor(&self, value: u64, rate: f64, horizon: u64) {
        let rate = sanitize(rate);
        self.publish(
            Line {
                anchor_v: value,
                anchor_wall: wall_now_ns(),
                rate_q32: rate_to_q32(rate),
                horizon,
            },
            rate,
        );
    }

    /// Scaled-mode rate change. Returns `false` (and changes nothing) while
    /// driven.
    pub(crate) fn set_rate(&self, rate: f64) -> bool {
        let mut w = self.write();
        if self.is_driven() {
            return false;
        }
        let old = self.rate();
        if rate == 0.0 && old > 0.0 {
            w.resume_rate = old;
        }
        self.reanchor(self.current(wall_now_ns()), rate, u64::MAX);
        true
    }

    pub(crate) fn resume(&self) -> bool {
        let w = self.write();
        if self.is_driven() {
            return false;
        }
        if self.rate() == 0.0 {
            let rate = w.resume_rate;
            self.reanchor(self.current(wall_now_ns()), rate, u64::MAX);
        }
        true
    }

    pub(crate) fn set_value(&self, value: u64) -> bool {
        let _w = self.write();
        if self.is_driven() {
            return false;
        }
        self.reanchor(value, self.rate(), u64::MAX);
        self.resets.fetch_add(1, Ordering::SeqCst);
        self.last.store(value, Ordering::SeqCst);
        true
    }

    pub(crate) fn advance(&self, by: u64) -> bool {
        let _w = self.write();
        if self.is_driven() {
            return false;
        }
        let value = self.current(wall_now_ns()).saturating_add(by);
        self.reanchor(value, self.rate(), u64::MAX);
        self.last.fetch_max(value, Ordering::AcqRel);
        true
    }

    pub(crate) fn set_driven(&self) {
        let _w = self.write();
        let now = self.current(wall_now_ns());
        self.driven.store(true, Ordering::Release);
        self.reanchor(now, 0.0, now);
    }

    pub(crate) fn set_scaled(&self) {
        let _w = self.write();
        let now = self.current(wall_now_ns());
        self.driven.store(false, Ordering::Release);
        self.reanchor(now, 0.0, u64::MAX);
    }

    /// Driven-mode grant. The line is anchored at `(anchor_v, anchor_wall)`
    /// unless that would move time backwards, in which case it is anchored at
    /// the current value and wall time.
    pub(crate) fn grant(&self, anchor_v: u64, anchor_wall: u64, rate: f64, horizon: u64) {
        let _w = self.write();
        let w = wall_now_ns();
        let now = self.current(w);
        let (anchor_v, anchor_wall) = if anchor_v >= now {
            (anchor_v, anchor_wall)
        } else {
            (now, w)
        };
        let rate = sanitize(rate);
        self.publish(
            Line {
                anchor_v,
                anchor_wall,
                rate_q32: rate_to_q32(rate),
                horizon,
            },
            rate,
        );
    }

    /// Hold the clock at `max(now, value)`: rate 0, horizon at the landing
    /// value. Returns where it landed.
    pub(crate) fn jump(&self, value: u64) -> u64 {
        let _w = self.write();
        let landing = self.current(wall_now_ns()).max(value);
        self.reanchor(landing, 0.0, landing);
        landing
    }

    pub(crate) fn freeze(&self) {
        let _w = self.write();
        let now = self.current(wall_now_ns());
        self.reanchor(now, 0.0, now);
    }
}

impl TimeSource for Clock {
    fn now_ns(&self) -> u64 {
        self.now()
    }

    fn wall_at(&self, v: u64) -> Option<u64> {
        self.line().wall_at(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_round_trips_through_wall_at() {
        let line = Line {
            anchor_v: 1_000,
            anchor_wall: 50,
            rate_q32: rate_to_q32(10.0),
            horizon: u64::MAX,
        };
        let w = line.wall_at(1_000 + 5_000_000).unwrap();
        assert_eq!(w, 50 + 500_000);
        assert!(line.value_at(w) >= 1_000 + 5_000_000);
        assert!(line.value_at(w - 1) < 1_000 + 5_000_000);
    }

    #[test]
    fn horizon_clamps_and_blocks_wall_at() {
        let line = Line {
            anchor_v: 0,
            anchor_wall: 0,
            rate_q32: rate_to_q32(1.0),
            horizon: 7,
        };
        assert_eq!(line.value_at(1_000), 7);
        assert_eq!(line.wall_at(8), None);
        assert_eq!(line.wall_at(7), Some(7));
    }

    #[test]
    fn huge_rate_does_not_saturate() {
        let line = Line {
            anchor_v: 0,
            anchor_wall: 0,
            rate_q32: rate_to_q32(1e9),
            horizon: u64::MAX,
        };
        assert_eq!(line.value_at(1_000), 1_000_000_000);
    }
}
