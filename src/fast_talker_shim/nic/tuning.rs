//! Linux interface tuning: EEE, threaded NAPI and its threads, interrupt
//! placement, per-queue steering and queue limits, busy-poll deferral,
//! hardware timestamping, queue statistics and the PTP clock. EEE, receive
//! timestamping and interrupt affinity also exist on Windows, as the
//! adapter properties fast-talker's Windows backend uses.

use std::io;
use std::time::Duration;

use ::fast_talker::rt::Scheduler;

use super::{
    ClockOffset, Eee, Need, Nic, OffsetMethod, QueueKind, QueueStats, done, ensure, invalid,
    mk_clock_offset, mk_queue_stats, not_supported, physical, sync_napi_threads,
};
use crate::fast_talker_shim::irq::Irq;
use crate::fast_talker_shim::platform::{Item, require};
use crate::fast_talker_shim::rt::Thread;
use crate::fast_talker_shim::sim::QueueStatsRec;
use crate::netif::{NicRec, SimSocket};
use crate::os::{OsSemantics, SysErrno, code_err, sys_err};

/// The kernel's `DQL_MAX_LIMIT`, the default and the ceiling of a byte
/// queue limit.
const DQL_MAX_LIMIT: u64 = 1_879_048_192;
const ENOENT: i32 = 2;

/// One NAPI instance of an interface: the polling context that moves
/// received frames from a hardware queue into sockets, with the interrupt
/// that kicks it and, when NAPI is threaded, the kernel thread it runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Napi {
    /// NAPI id, as reported by `SO_INCOMING_NAPI_ID`.
    pub id: u32,
    /// The interrupt that schedules this NAPI.
    pub irq: Option<Irq>,
    /// The kernel thread polling this NAPI, when NAPI is threaded.
    pub thread: Option<Thread>,
}

impl Napi {
    /// Runs this NAPI's receive path on `cpus` at `scheduler`: its
    /// interrupt's affinity, the interrupt's handler threads' priority, and
    /// the NAPI thread's affinity and priority.
    pub fn pin(&self, cpus: &[usize], scheduler: Scheduler) -> io::Result<()> {
        if let Some(irq) = self.irq {
            irq.pin(cpus, scheduler)?;
        }
        if let Some(thread) = self.thread {
            thread.pin_scheduler(cpus, scheduler)?;
        }
        Ok(())
    }
}

fn no_file(os: OsSemantics) -> io::Error {
    code_err(os, ENOENT, "ENOENT", io::ErrorKind::NotFound)
}

fn queues(n: &NicRec, rx: bool) -> usize {
    if n.is_loopback() {
        return 1;
    }
    let c = n.ft.channels;
    (c.combined + if rx { c.rx } else { c.tx }).max(1) as usize
}

fn cpu_count() -> usize {
    crate::state::ft_slot().inner.lock().cpus.count
}

fn check_cpus(cpus: &[usize], count: usize, os: OsSemantics) -> io::Result<()> {
    if cpus.iter().any(|&c| c >= count) {
        return Err(invalid(os));
    }
    Ok(())
}

fn sorted(cpus: &[usize]) -> Vec<usize> {
    let mut v = cpus.to_vec();
    v.sort_unstable();
    v.dedup();
    v
}

/// The queue statistics `n` reports: the test's seed, else zeroed receive
/// and transmit entries per queue carrying the interface's packet and byte
/// counts on queue 0.
pub(crate) fn queue_stats_of(n: &NicRec) -> Vec<QueueStatsRec> {
    if let Some(seeded) = &n.ft.queue_stats {
        return seeded.clone();
    }
    let mut out = Vec::new();
    for (kind, rx) in [(QueueKind::Rx, true), (QueueKind::Tx, false)] {
        for q in 0..queues(n, rx) as u32 {
            let mut rec = QueueStatsRec::new(kind, q);
            let (packets, bytes) = match (rx, q) {
                (true, 0) => (n.counters.rx_packets, n.counters.rx_bytes),
                (false, 0) => (n.counters.tx_packets, n.counters.tx_bytes),
                _ => (0, 0),
            };
            rec.packets = Some(packets);
            rec.bytes = Some(bytes);
            if rx {
                rec.hw_drops = Some(0);
                rec.alloc_fail = Some(0);
            } else {
                rec.stop = Some(0);
                rec.wake = Some(0);
            }
            out.push(rec);
        }
    }
    out
}

impl Nic {
    /// Energy Efficient Ethernet state. `EOPNOTSUPP` on Linux, and no EEE
    /// property on Windows, for an interface without
    /// [`NicCaps::eee`](crate::NicCaps). Windows only reports `enabled`.
    pub fn eee(&self) -> io::Result<Eee> {
        self.get(Item::NicEee, |n, os| {
            physical(n, os)?;
            match os {
                OsSemantics::Windows if !n.spec.caps.eee => Err(no_eee()),
                OsSemantics::Windows => {
                    let mut e = n.ft.eee;
                    e.active = false;
                    e.tx_lpi_enabled = false;
                    e.tx_lpi_timer = Duration::ZERO;
                    Ok(e)
                }
                _ if !n.spec.caps.eee => Err(not_supported(os)),
                _ => Ok(n.ft.eee),
            }
        })
    }

    /// Turns Energy Efficient Ethernet on or off.
    pub fn set_eee(&self, enabled: bool) -> io::Result<()> {
        self.set(
            Item::NicEee,
            Need::NetAdmin,
            format!("set_eee({enabled})"),
            |n, os| {
                physical(n, os)?;
                if !n.spec.caps.eee {
                    return Err(match os {
                        OsSemantics::Windows => no_eee(),
                        _ => not_supported(os),
                    });
                }
                let changed = n.ft.eee.enabled != enabled;
                n.ft.eee.enabled = enabled;
                n.ft.eee.active = enabled;
                n.ft.eee.tx_lpi_enabled = enabled;
                Ok(((), os == OsSemantics::Windows && changed))
            },
        )
    }

    /// Whether NAPI polling runs in dedicated kernel threads.
    pub fn threaded_napi(&self) -> io::Result<bool> {
        self.get(Item::LinuxNicTuning, |n, _| Ok(n.ft.threaded_napi))
    }

    /// Moves NAPI polling into one `napi/<nic>-<id>` kernel thread per
    /// NAPI, which [`Nic::napis`] can then pin, or back into softirq.
    /// `EOPNOTSUPP` for an interface without
    /// [`NicCaps::threaded_napi`](crate::NicCaps).
    pub fn set_threaded_napi(&self, on: bool) -> io::Result<()> {
        ensure(self.id);
        self.set(
            Item::LinuxNicTuning,
            Need::Sysfs,
            format!("set_threaded_napi({on})"),
            |n, os| {
                if !n.spec.caps.threaded_napi || n.is_loopback() {
                    return Err(not_supported(os));
                }
                n.ft.threaded_napi = on;
                done(())
            },
        )?;
        sync_napi_threads(self.id);
        Ok(())
    }

    /// The interface's NAPI instances with their interrupts and threads.
    pub fn napis(&self) -> io::Result<Vec<Napi>> {
        require(Item::LinuxNicTuning)?;
        ensure(self.id);
        self.get(Item::LinuxNicTuning, |n, _| {
            Ok(n.ft
                .napis
                .iter()
                .map(|r| Napi {
                    id: r.id,
                    irq: r.irq.map(Irq::new),
                    thread: r.thread.map(Thread::from_snare_tid),
                })
                .collect())
        })
    }

    /// The interrupts that serve receive queues, in queue order.
    pub fn queue_irqs(&self) -> io::Result<Vec<Irq>> {
        let irqs = self.irqs()?;
        let slot = crate::state::ft_slot();
        let g = slot.inner.lock();
        let mut queued: Vec<(u32, Irq)> = irqs
            .into_iter()
            .filter_map(|irq| {
                let name = &g.irqs.get(&irq.number())?.name;
                let (_, q) = name.rsplit_once("-TxRx-").or(name.rsplit_once("-rx-"))?;
                Some((q.parse().ok()?, irq))
            })
            .collect();
        queued.sort();
        Ok(queued.into_iter().map(|(_, irq)| irq).collect())
    }

    /// The NAPI that delivered the last packet `socket` received on this
    /// interface: its receive queue is the one a flow rule steers the flow
    /// to, else the one the flow hashes to. `None` until the socket has
    /// received through this interface. Linux records every packet for TCP
    /// and connected UDP, but only the first for an unconnected UDP socket.
    pub fn napi_for_socket(&self, socket: &impl SimSocket) -> io::Result<Option<Napi>> {
        require(Item::LinuxNicTuning)?;
        let Some(steer) = super::flow::steer(socket.socket_id()) else {
            return Ok(None);
        };
        if steer.nic != self.id {
            return Ok(None);
        }
        Ok(self.napis()?.get(steer.queue as usize).copied())
    }

    /// The interrupts the interface's device raises. Empty for the
    /// loopback.
    pub fn irqs(&self) -> io::Result<Vec<Irq>> {
        require(Item::LinuxNicTuning)?;
        ensure(self.id);
        self.get(Item::LinuxNicTuning, |n, _| {
            let mut v: Vec<Irq> = n.ft.irqs.iter().copied().map(Irq::new).collect();
            v.sort();
            Ok(v)
        })
    }

    /// Delivers every interrupt the interface raises to `cpus`. On Windows
    /// this is the adapter's interrupt affinity policy: an empty `cpus`
    /// hands the choice back to Windows, and a change restarts the adapter.
    pub fn set_irq_affinity(&self, cpus: &[usize]) -> io::Result<()> {
        if crate::os_semantics() == OsSemantics::Windows {
            return self.set_windows_irq_affinity(cpus);
        }
        for irq in self.irqs()? {
            irq.set_affinity(cpus)?;
        }
        Ok(())
    }

    /// Number of receive queues.
    pub fn rx_queues(&self) -> io::Result<usize> {
        self.get(Item::LinuxNicTuning, |n, _| Ok(queues(n, true)))
    }

    /// Number of transmit queues.
    pub fn tx_queues(&self) -> io::Result<usize> {
        self.get(Item::LinuxNicTuning, |n, _| Ok(queues(n, false)))
    }

    /// The CPUs whose sends use transmit queue `queue` (XPS).
    pub fn xps_cpus(&self, queue: usize) -> io::Result<Vec<usize>> {
        self.get(Item::LinuxNicTuning, |n, os| {
            if queue >= queues(n, false) {
                return Err(no_file(os));
            }
            Ok(n.ft.xps.get(&queue).cloned().unwrap_or_default())
        })
    }

    /// Makes sends from `cpus` use transmit queue `queue` (XPS).
    pub fn set_xps_cpus(&self, queue: usize, cpus: &[usize]) -> io::Result<()> {
        let count = cpu_count();
        self.set(
            Item::LinuxNicTuning,
            Need::Sysfs,
            format!("set_xps_cpus({queue}, {cpus:?})"),
            |n, os| {
                if queue >= queues(n, false) {
                    return Err(no_file(os));
                }
                check_cpus(cpus, count, os)?;
                n.ft.xps.insert(queue, sorted(cpus));
                done(())
            },
        )
    }

    /// The CPUs receive queue `queue` hands packets to (RPS). Empty keeps
    /// processing on the polling CPU.
    pub fn rps_cpus(&self, queue: usize) -> io::Result<Vec<usize>> {
        self.get(Item::LinuxNicTuning, |n, os| {
            if queue >= queues(n, true) {
                return Err(no_file(os));
            }
            Ok(n.ft.rps.get(&queue).cloned().unwrap_or_default())
        })
    }

    /// Sets RPS for receive queue `queue`.
    pub fn set_rps_cpus(&self, queue: usize, cpus: &[usize]) -> io::Result<()> {
        let count = cpu_count();
        self.set(
            Item::LinuxNicTuning,
            Need::Sysfs,
            format!("set_rps_cpus({queue}, {cpus:?})"),
            |n, os| {
                if queue >= queues(n, true) {
                    return Err(no_file(os));
                }
                check_cpus(cpus, count, os)?;
                n.ft.rps.insert(queue, sorted(cpus));
                done(())
            },
        )
    }

    /// Upper bound, in bytes, of the byte queue limit on transmit queue
    /// `queue`.
    pub fn bql_limit_max(&self, queue: usize) -> io::Result<u64> {
        self.get(Item::LinuxNicTuning, |n, os| {
            if queue >= queues(n, false) {
                return Err(no_file(os));
            }
            Ok(n.ft.bql.get(&queue).copied().unwrap_or(DQL_MAX_LIMIT))
        })
    }

    /// Caps the bytes queued in the hardware ring for transmit queue
    /// `queue`. Over the kernel's maximum is `EINVAL`.
    pub fn set_bql_limit_max(&self, queue: usize, bytes: u64) -> io::Result<()> {
        self.set(
            Item::LinuxNicTuning,
            Need::Sysfs,
            format!("set_bql_limit_max({queue}, {bytes})"),
            |n, os| {
                if queue >= queues(n, false) {
                    return Err(no_file(os));
                }
                if bytes > DQL_MAX_LIMIT {
                    return Err(invalid(os));
                }
                n.ft.bql.insert(queue, bytes);
                done(())
            },
        )
    }

    /// How many NAPI polls may find no work before interrupts are
    /// re-enabled.
    pub fn napi_defer_hard_irqs(&self) -> io::Result<u32> {
        self.get(Item::LinuxNicTuning, |n, _| Ok(n.ft.napi_defer_hard_irqs))
    }

    /// Keeps interrupts masked for `n` empty polls.
    pub fn set_napi_defer_hard_irqs(&self, n: u32) -> io::Result<()> {
        self.set(
            Item::LinuxNicTuning,
            Need::Sysfs,
            format!("set_napi_defer_hard_irqs({n})"),
            |rec, os| {
                if i32::try_from(n).is_err() {
                    return Err(invalid(os));
                }
                rec.ft.napi_defer_hard_irqs = n;
                done(())
            },
        )
    }

    /// The GRO flush timeout.
    pub fn gro_flush_timeout(&self) -> io::Result<Duration> {
        self.get(Item::LinuxNicTuning, |n, _| Ok(n.ft.gro_flush_timeout))
    }

    /// Sets the GRO flush timeout.
    pub fn set_gro_flush_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.set(
            Item::LinuxNicTuning,
            Need::Sysfs,
            format!("set_gro_flush_timeout({timeout:?})"),
            |n, _| {
                n.ft.gro_flush_timeout = timeout;
                done(())
            },
        )
    }

    /// Whether the NIC stamps received frames: in hardware on Linux
    /// (`EOPNOTSUPP` without
    /// [`NicCaps::hw_rx_timestamp`](crate::NicCaps)), in the driver on
    /// Windows. It is the same switch a hardware-stamping
    /// [`Timestamped`](crate::fast_talker::Timestamped) turns on.
    pub fn rx_timestamping(&self) -> io::Result<bool> {
        self.get(Item::RxTimestamping, |n, os| match os {
            OsSemantics::Windows => {
                physical(n, os)?;
                Ok(n.ft.win_timestamping.rx)
            }
            _ if !n.spec.caps.hw_rx_timestamp => Err(not_supported(os)),
            _ => Ok(n.ft.hwtstamp.rx),
        })
    }

    /// Turns receive timestamping on or off.
    pub fn set_rx_timestamping(&self, on: bool) -> io::Result<()> {
        self.set(
            Item::RxTimestamping,
            Need::NetAdmin,
            format!("set_rx_timestamping({on})"),
            |n, os| match os {
                OsSemantics::Windows => {
                    physical(n, os)?;
                    let changed = n.ft.win_timestamping.rx != on;
                    n.ft.win_timestamping.rx = on;
                    Ok(((), changed))
                }
                _ if !n.spec.caps.hw_rx_timestamp => Err(not_supported(os)),
                _ => {
                    n.ft.hwtstamp.rx = on;
                    done(())
                }
            },
        )
    }

    /// The kernel's per-queue statistics, from
    /// [`sim::set_queue_stats`](crate::fast_talker::sim::set_queue_stats)
    /// or else the interface's counters on queue 0. `EOPNOTSUPP` without
    /// [`NicCaps::queue_stats`](crate::NicCaps).
    pub fn queue_stats(&self) -> io::Result<Vec<QueueStats>> {
        self.get(Item::LinuxNicTuning, |n, os| {
            if !n.spec.caps.queue_stats {
                return Err(not_supported(os));
            }
            let mut v: Vec<QueueStats> = queue_stats_of(n).iter().map(mk_queue_stats).collect();
            v.sort_by_key(|s| (s.kind, s.queue));
            Ok(v)
        })
    }

    /// The interface's PTP hardware clock: `Some(n)` for `/dev/ptp<n>`.
    pub fn ptp_clock(&self) -> io::Result<Option<u32>> {
        self.get(Item::LinuxNicTuning, |n, _| Ok(n.ft.ptp.map(|p| p.clock)))
    }

    /// Offset of the NIC's PTP hardware clock from the system clock, as
    /// [`sim::set_ptp`](crate::fast_talker::sim::set_ptp) seeds it: a TAI
    /// clock reads the TAI offset ahead. `Precise` when the seed has no
    /// uncertainty, else `Extended`. Reading the clock needs `root`.
    pub fn clock_offset(&self) -> io::Result<ClockOffset> {
        require(Item::LinuxNicTuning)?;
        let root = crate::privileges().root;
        let tai_offset = crate::state::ft_slot().inner.lock().tai_offset;
        let (name, ptp) = self.get(Item::LinuxNicTuning, |n, _| {
            Ok((n.spec.name.clone(), n.ft.ptp))
        })?;
        let ptp = ptp.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("{name} has no PTP hardware clock"),
            )
        })?;
        if !root {
            return Err(sys_err(SysErrno::Access));
        }
        let tai = if ptp.tai {
            tai_offset.as_nanos() as i64
        } else {
            0
        };
        let method = if ptp.uncertainty.is_zero() {
            OffsetMethod::Precise
        } else {
            OffsetMethod::Extended
        };
        Ok(mk_clock_offset(
            ptp.clock,
            ptp.offset_nanos + tai,
            ptp.uncertainty,
            method,
            tai_offset,
        ))
    }
}

fn no_eee() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "the adapter's driver has no Energy Efficient Ethernet property",
    )
}
