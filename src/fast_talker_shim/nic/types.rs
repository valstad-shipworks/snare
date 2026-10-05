//! fast-talker's NIC data types for hosts whose fast-talker build lacks
//! them, so the simulated OS can report them anywhere. Same fields,
//! methods and derives as fast-talker's.

#[cfg(not(any(target_os = "linux", target_os = "android")))]
use std::time::Duration;

/// Energy Efficient Ethernet state from [`Nic::eee`](super::Nic). EEE lets
/// the link sleep between frames, and waking it adds tens of microseconds
/// to the first frame after an idle gap. Windows only reports `enabled`.
#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Eee {
    /// Whether EEE is enabled on this side.
    pub enabled: bool,
    /// Whether the link negotiated EEE and is using it.
    pub active: bool,
    /// Whether the transmitter may enter low-power idle.
    pub tx_lpi_enabled: bool,
    /// How long the transmitter waits idle before entering low-power idle.
    pub tx_lpi_timer: std::time::Duration,
}

/// Receive-side scaling placement: which CPUs run the adapter's receive
/// DPCs, the Windows counterpart of NAPI placement. `None` means unset, so
/// the driver default applies.
#[cfg(not(windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rss {
    /// Whether receive-side scaling is on (`*RSS`). Off, all receive
    /// processing runs on one CPU.
    pub enabled: bool,
    /// The first CPU receive processing may use (`*RssBaseProcNumber`).
    pub base_cpu: Option<u32>,
    /// The last CPU receive processing may use (`*RssMaxProcNumber`).
    pub max_cpu: Option<u32>,
    /// How many CPUs receive processing may spread over
    /// (`*MaxRssProcessors`).
    pub max_processors: Option<u32>,
}

/// Settings for an ETF (earliest txtime first) qdisc, which holds each
/// datagram sent with `Timestamped::send_at` until its time.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "fast-talker-serde",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Etf {
    /// How long before its time a datagram is handed on, to cover the
    /// driver (and, without offload, timer wake-up) latency. 300 µs by
    /// default.
    pub delta: Duration,
    /// Have the NIC hold each frame until its time (launch-time offload).
    pub offload: bool,
    /// Treat times as deadlines, for sockets using
    /// [`TxTime::Deadline`](::fast_talker::TxTime::Deadline).
    pub deadline: bool,
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl Default for Etf {
    fn default() -> Self {
        Self {
            delta: Duration::from_micros(300),
            offload: false,
            deadline: false,
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
const TC_H_ROOT: u32 = 0xffff_ffff;

/// A queueing discipline attached to an interface.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Qdisc {
    /// Its kind (`mq`, `fq_codel`, `etf`, ...).
    pub kind: String,
    /// Its handle, major number in the top 16 bits.
    pub handle: u32,
    /// Where it hangs: `0xffff_ffff` for the root, otherwise the parent
    /// class.
    pub parent: u32,
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl Qdisc {
    /// Whether it is the interface's root qdisc.
    pub fn is_root(&self) -> bool {
        self.parent == TC_H_ROOT
    }
}

/// How a clock offset was measured.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OffsetMethod {
    /// The NIC captured its clock and the system clock at the same instant.
    Precise,
    /// The NIC clock was read between two system clock reads taken by the
    /// driver.
    Extended,
    /// The kernel bracketed the whole clock read with system clock reads.
    Basic,
}

/// The offset between a NIC's PTP hardware clock and the system clock.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClockOffset {
    /// The PTP clock's device number (`/dev/ptp<n>`).
    pub clock: u32,
    /// NIC clock minus `CLOCK_REALTIME`, in nanoseconds.
    pub offset_nanos: i64,
    /// How far `offset_nanos` may be off.
    pub uncertainty: Duration,
    /// How the offset was measured.
    pub method: OffsetMethod,
    /// How far `CLOCK_TAI` leads `CLOCK_REALTIME`.
    pub tai_offset: Duration,
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl ClockOffset {
    /// Offset from the system clock once a TAI time base is allowed for:
    /// whichever of `offset_nanos` and `offset_nanos - tai_offset` is
    /// smaller in magnitude.
    pub fn effective_offset_nanos(&self) -> i64 {
        let tai = self.tai_offset.as_nanos() as i64;
        [self.offset_nanos, self.offset_nanos - tai]
            .into_iter()
            .min_by_key(|o| o.unsigned_abs())
            .unwrap()
    }

    /// Whether the NIC clock is within `tolerance` of the system clock, in
    /// UTC or TAI.
    pub fn is_disciplined(&self, tolerance: Duration) -> bool {
        u128::from(self.effective_offset_nanos().unsigned_abs()) + self.uncertainty.as_nanos()
            <= tolerance.as_nanos()
    }
}

/// Direction of a hardware queue.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum QueueKind {
    /// A receive queue.
    Rx,
    /// A transmit queue.
    Tx,
}

/// The kernel's standard statistics for one hardware queue. Counters the
/// hardware lacks are `None`.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct QueueStats {
    /// Queue direction.
    pub kind: QueueKind,
    /// Queue index.
    pub queue: u32,
    /// Packets through the queue.
    pub packets: Option<u64>,
    /// Bytes through the queue.
    pub bytes: Option<u64>,
    /// Receive: packets dropped because no buffer could be allocated.
    pub alloc_fail: Option<u64>,
    /// Packets the hardware dropped on this queue, for any reason.
    pub hw_drops: Option<u64>,
    /// Receive: of `hw_drops`, those lost because the ring was full.
    pub hw_drop_overruns: Option<u64>,
    /// Of `hw_drops`, those dropped by a rate limit.
    pub hw_drop_ratelimits: Option<u64>,
    /// Transmit: of `hw_drops`, those dropped for an error.
    pub hw_drop_errors: Option<u64>,
    /// Receive: packets with a bad checksum.
    pub csum_bad: Option<u64>,
    /// Transmit: times the driver stopped the queue.
    pub stop: Option<u64>,
    /// Transmit: times the driver restarted a stopped queue.
    pub wake: Option<u64>,
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl QueueStats {
    /// The change in every counter since `earlier` for the same queue. A
    /// counter reported in only one of the two reads is `None`.
    pub fn since(&self, earlier: &QueueStats) -> QueueStats {
        let d = |now: Option<u64>, then: Option<u64>| Some(delta(then?, now?));
        QueueStats {
            kind: self.kind,
            queue: self.queue,
            packets: d(self.packets, earlier.packets),
            bytes: d(self.bytes, earlier.bytes),
            alloc_fail: d(self.alloc_fail, earlier.alloc_fail),
            hw_drops: d(self.hw_drops, earlier.hw_drops),
            hw_drop_overruns: d(self.hw_drop_overruns, earlier.hw_drop_overruns),
            hw_drop_ratelimits: d(self.hw_drop_ratelimits, earlier.hw_drop_ratelimits),
            hw_drop_errors: d(self.hw_drop_errors, earlier.hw_drop_errors),
            csum_bad: d(self.csum_bad, earlier.csum_bad),
            stop: d(self.stop, earlier.stop),
            wake: d(self.wake, earlier.wake),
        }
    }

    /// Whether any hardware drop or allocation failure counter is non-zero.
    pub fn has_loss(&self) -> bool {
        [self.hw_drops, self.hw_drop_overruns, self.alloc_fail]
            .into_iter()
            .flatten()
            .any(|v| v > 0)
    }
}

/// The change in a counter from `before` to `after`: a drop from a 32-bit
/// value is a wrap at 2^32, a drop from anything larger is a reset.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn delta(before: u64, after: u64) -> u64 {
    if after >= before {
        after - before
    } else if before <= u64::from(u32::MAX) {
        after + (1 << 32) - before
    } else {
        after
    }
}

#[cfg(all(test, not(any(target_os = "linux", target_os = "android"))))]
mod tests {
    use super::*;

    #[test]
    fn copies_behave_like_fast_talkers() {
        let q = Qdisc {
            kind: "etf".into(),
            handle: 0x10000,
            parent: TC_H_ROOT,
        };
        assert!(q.is_root());
        let c = ClockOffset {
            clock: 0,
            offset_nanos: 37_000_000_050,
            uncertainty: Duration::ZERO,
            method: OffsetMethod::Precise,
            tai_offset: Duration::from_secs(37),
        };
        assert_eq!(c.effective_offset_nanos(), 50);
        assert!(c.is_disciplined(Duration::from_nanos(50)));
        let before = QueueStats {
            kind: QueueKind::Rx,
            queue: 0,
            packets: Some(u64::from(u32::MAX) - 1),
            bytes: None,
            alloc_fail: None,
            hw_drops: Some(1),
            hw_drop_overruns: None,
            hw_drop_ratelimits: None,
            hw_drop_errors: None,
            csum_bad: None,
            stop: None,
            wake: None,
        };
        let after = QueueStats {
            packets: Some(3),
            hw_drops: Some(1),
            ..before
        };
        let d = after.since(&before);
        assert_eq!(d.packets, Some(5));
        assert!(!d.has_loss());
        assert_eq!(Etf::default().delta, Duration::from_micros(300));
    }
}
