//! fast-talker's `nic` over snare's NICs ([`add_nic`](crate::add_nic)): one
//! interface model shared with routing and delivery.
//!
//! Every method exists on every host. Which ones work, and the errors they
//! give, follow [`os_semantics`](crate::os_semantics): rings, coalescing,
//! flow control and channels on Linux and Windows, the Linux tuning
//! (NAPI, queues, flow steering, qdiscs, PTP) on Linux only, and adapter
//! timestamping, interrupt policy and RSS on Windows only. Linux setters
//! need `net_admin` (sysfs ones `root` too); Windows setters need an
//! elevated process (`root`) and restart the adapter, which holds its link
//! down for [`NicCaps::win_restart_flap`](crate::NicCaps::win_restart_flap)
//! of virtual time. Tests read back what was applied with
//! [`sim::interface`](super::sim::interface).

use std::fmt;
use std::io;
use std::net::IpAddr;

#[cfg(any(target_os = "linux", target_os = "android", windows))]
pub use ::fast_talker::nic::Eee;
#[cfg(windows)]
pub use ::fast_talker::nic::Rss;
pub use ::fast_talker::nic::{
    Channels, Coalesce, DriverInfo, FlowAction, FlowMatch, FlowProtocol, FlowRule, LinkStats,
    Pause, Rings,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use ::fast_talker::nic::{ClockOffset, Etf, OffsetMethod, Qdisc, QueueKind, QueueStats};

mod flow;
mod kernel;
mod qdisc;
mod tuning;
mod types;
mod windows;

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
pub use types::Eee;
#[cfg(not(windows))]
pub use types::Rss;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub use types::{ClockOffset, Etf, OffsetMethod, Qdisc, QueueKind, QueueStats};

pub(crate) use flow::{incoming_cpu, udp_flow_dropped};
pub(crate) use kernel::{
    ensure, ensure_all, rebuild, retire_locked as kernel_retire, retire_removed, sync_napi_threads,
};
pub(crate) use qdisc::qdisc_tree;
pub use tuning::Napi;
pub(crate) use tuning::queue_stats_of;

use super::platform::{Item, require};
use super::sim::{FtEvent, NicApply};
use crate::netif::{NicCounters, NicId, NicRec, Privileges};
use crate::os::{Errno, OsSemantics, SysErrno, os_err_for, os_error_code, sys_err_for};
use crate::time::Instant;

/// A snare NIC, addressed by name. Methods act on the interface with the
/// index it had when opened, so a renamed interface keeps working.
#[derive(Clone)]
pub struct Nic {
    name: String,
    id: NicId,
}

impl fmt::Debug for Nic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nic")
            .field("name", &self.name)
            .field("index", &self.id.index())
            .finish_non_exhaustive()
    }
}

/// What a setter needs on the emulated OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Need {
    /// An ethtool or netlink change: `CAP_NET_ADMIN`.
    NetAdmin,
    /// A sysfs write: root to open the file, then `CAP_NET_ADMIN`.
    Sysfs,
    /// An elevated process, as every Windows adapter change needs.
    Elevated,
}

impl Need {
    fn check(self, os: OsSemantics, p: &Privileges) -> io::Result<()> {
        let need = if os == OsSemantics::Windows {
            Need::Elevated
        } else {
            self
        };
        let denied = match need {
            Need::NetAdmin => (!p.net_admin).then_some(SysErrno::Perm),
            Need::Sysfs if !p.root => Some(SysErrno::Access),
            Need::Sysfs => (!p.net_admin).then_some(SysErrno::Perm),
            Need::Elevated => (!p.root).then_some(SysErrno::Access),
        };
        denied.map_or(Ok(()), |e| Err(sys_err_for(os, e)))
    }
}

/// A setter's value, and whether it restarted a Windows adapter.
type Applied<R> = io::Result<(R, bool)>;

fn done<R>(r: R) -> Applied<R> {
    Ok((r, false))
}

pub(super) fn gone() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "interface removed")
}

fn not_supported(os: OsSemantics) -> io::Error {
    os_err_for(os, Errno::OpNotSupp)
}

fn invalid(os: OsSemantics) -> io::Error {
    sys_err_for(os, SysErrno::Inval)
}

/// The adapter's registry key is missing a standardized keyword.
fn no_keyword(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("the adapter's driver has no {name} property"),
    )
}

/// Loopback has no ethtool device on Linux and no adapter on Windows.
fn physical(n: &NicRec, os: OsSemantics) -> io::Result<()> {
    if !n.is_loopback() {
        return Ok(());
    }
    Err(match os {
        OsSemantics::Windows => io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} has no adapter device", n.spec.name),
        ),
        _ => not_supported(os),
    })
}

impl Nic {
    fn of(n: &crate::NicSnapshot) -> Self {
        Self {
            name: n.spec.name.clone(),
            id: n.id,
        }
    }

    /// Opens the snare NIC called `name`: only the emulated OS's loopback
    /// name resolves for the loopback. Fails with `NotFound` when there is
    /// none.
    pub fn open(name: &str) -> io::Result<Self> {
        crate::nic(name).map(|n| Self::of(&n)).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no interface named {name:?}"),
            )
        })
    }

    /// Opens the NIC `ip` is assigned to, or `None` when no NIC has that
    /// address. Addresses [`add_ip_addr`](crate::add_ip_addr) assigns are on
    /// the default interface.
    pub fn with_address(ip: IpAddr) -> io::Result<Option<Self>> {
        Ok(crate::nics()
            .into_iter()
            .find(|n| n.spec.addresses.iter().any(|a| a.addr == ip))
            .map(|n| Self::of(&n)))
    }

    /// Interface name, as passed to [`Nic::open`].
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Interface index.
    pub fn index(&self) -> u32 {
        self.id.index()
    }

    fn get<R>(
        &self,
        item: Item,
        f: impl FnOnce(&NicRec, OsSemantics) -> io::Result<R>,
    ) -> io::Result<R> {
        require(item)?;
        crate::netif::with_nic_rec(self.id, |n, os| f(n, os)).unwrap_or_else(|| Err(gone()))
    }

    /// Apply a setting: `item` must exist on the emulated OS, the caller
    /// must hold `need`, and then `f` validates and applies it. Applied or
    /// refused, it goes into the interface's apply log and the shim's
    /// events.
    fn set<R>(
        &self,
        item: Item,
        need: Need,
        what: String,
        f: impl FnOnce(&mut NicRec, OsSemantics) -> Applied<R>,
    ) -> io::Result<R> {
        require(item)?;
        let privs = crate::privileges();
        let now = Instant::now();
        let tid = crate::threads::current_tid();
        let outcome = crate::state::with_net(|ctx| {
            let os = ctx.net.os;
            let nic = ctx.net.nic_by_id_mut(self.id)?;
            let result = need.check(os, &privs).and_then(|()| f(nic, os));
            let mut restarted = None;
            let result = result.map(|(r, restart)| {
                if restart {
                    let until = now + nic.spec.caps.win_restart_flap;
                    nic.ft.flap_until = Some(until);
                    restarted = Some(until);
                }
                r
            });
            let status = result.as_ref().map(|_| ()).map_err(io::Error::kind);
            nic.ft.apply_log.push(NicApply {
                at: now,
                tid,
                what: what.clone(),
                result: status,
                os_error: result.as_ref().err().and_then(os_error_code),
            });
            let id = nic.id;
            let name = nic.spec.name.clone();
            let wakes: Vec<(usize, Instant)> = restarted
                .map(|until| {
                    ctx.tcp
                        .values()
                        .filter(|c| c.nic == Some(id))
                        .map(|c| (c.stream_id, until))
                        .collect()
                })
                .unwrap_or_default();
            Some((result, status, name, wakes))
        });
        let Some((result, status, name, wakes)) = outcome else {
            return Err(gone());
        };
        super::sim::log(FtEvent::Nic {
            nic: name,
            what,
            result: status,
        });
        crate::state::wake_stalled(wakes);
        result
    }

    /// Whether the NIC's link is up: down while its link is set down with
    /// [`set_link`](crate::set_link), and while a Windows adapter restart
    /// is under way.
    pub fn link_up(&self) -> io::Result<bool> {
        require(Item::NicLinkStats)?;
        let now = Instant::now();
        crate::netif::with_nic_rec(self.id, |n, _| {
            n.spec.link_up && n.ft.flap_until.is_none_or(|until| now >= until)
        })
        .ok_or_else(gone)
    }

    /// What the driver reports about itself, from the NIC's
    /// [`DriverSeed`](crate::DriverSeed). Windows reports only the
    /// adapter description (`driver`) and its version.
    pub fn driver(&self) -> io::Result<DriverInfo> {
        self.get(Item::NicDriver, |n, os| {
            physical(n, os)?;
            let mut info = n.ft.driver.clone();
            if os == OsSemantics::Windows {
                info.firmware.clear();
                info.bus.clear();
                info.expansion_rom.clear();
            }
            Ok(info)
        })
    }

    /// Every counter the driver exposes, named as the emulated OS names
    /// them. Values follow the interface's
    /// [`NicCounters`](crate::NicCounters), with the test's
    /// [`sim::set_driver_stats`](super::sim::set_driver_stats) on top.
    pub fn driver_stats(&self) -> io::Result<DriverStats> {
        let mut stats = DriverStats::default();
        stats.refresh(self)?;
        Ok(stats)
    }

    /// The standard interface counters, from the interface's
    /// [`NicCounters`](crate::NicCounters). Fields the emulated OS does not
    /// report read as zero.
    pub fn link_stats(&self) -> io::Result<LinkStats> {
        self.get(Item::NicLinkStats, |n, os| Ok(link_stats(&n.counters, os)))
    }

    /// RX/TX descriptor ring sizes.
    pub fn rings(&self) -> io::Result<Rings> {
        self.get(Item::NicRingsCoalescePauseChannels, |n, os| {
            has_rings(n, os)?;
            Ok(n.ft.rings)
        })
    }

    /// Resizes the descriptor rings. The `*_max` fields are ignored. Sizes
    /// of zero or over the maxima are `EINVAL`.
    pub fn set_rings(&self, r: &Rings) -> io::Result<()> {
        let r = *r;
        self.set(
            Item::NicRingsCoalescePauseChannels,
            Need::NetAdmin,
            format!("set_rings({r:?})"),
            |n, os| {
                has_rings(n, os)?;
                let cur = n.ft.rings;
                if os == OsSemantics::Windows {
                    if r.rx == 0 || r.rx > cur.rx_max || (cur.tx_max != 0 && r.tx > cur.tx_max) {
                        return Err(invalid(os));
                    }
                    let tx = if cur.tx_max != 0 { r.tx } else { cur.tx };
                    let changed = r.rx != cur.rx || tx != cur.tx;
                    n.ft.rings.rx = r.rx;
                    n.ft.rings.tx = tx;
                    return Ok(((), changed));
                }
                let over = r.rx > cur.rx_max
                    || r.tx > cur.tx_max
                    || r.rx_mini > cur.rx_mini_max
                    || r.rx_jumbo > cur.rx_jumbo_max;
                if over || r.rx == 0 || r.tx == 0 {
                    return Err(invalid(os));
                }
                n.ft.rings.rx = r.rx;
                n.ft.rings.tx = r.tx;
                n.ft.rings.rx_mini = r.rx_mini;
                n.ft.rings.rx_jumbo = r.rx_jumbo;
                done(())
            },
        )
    }

    /// Interrupt coalescing. On Windows only the on/off interrupt
    /// moderation, as `adaptive_rx` and `adaptive_tx`.
    pub fn coalesce(&self) -> io::Result<Coalesce> {
        self.get(Item::NicRingsCoalescePauseChannels, |n, os| {
            has_coalesce(n, os)?;
            Ok(if os == OsSemantics::Windows {
                let on = n.ft.coalesce.adaptive_rx;
                Coalesce {
                    adaptive_rx: on,
                    adaptive_tx: on,
                    ..Coalesce::default()
                }
            } else {
                n.ft.coalesce
            })
        })
    }

    /// Sets interrupt coalescing. On Linux a non-zero field the driver does
    /// not support ([`NicCaps::coalesce_supported`](crate::NicCaps)) is
    /// `EOPNOTSUPP`, and a time or frame count over the driver's limits
    /// `EINVAL`. Windows turns moderation off when `adaptive_rx` is false
    /// and `rx_usecs` and `rx_usecs_irq` are zero, on otherwise.
    pub fn set_coalesce(&self, c: &Coalesce) -> io::Result<()> {
        let c = *c;
        self.set(
            Item::NicRingsCoalescePauseChannels,
            Need::NetAdmin,
            format!("set_coalesce({c:?})"),
            |n, os| {
                has_coalesce(n, os)?;
                if os == OsSemantics::Windows {
                    let on = c.adaptive_rx || c.rx_usecs != 0 || c.rx_usecs_irq != 0;
                    let changed = on != n.ft.coalesce.adaptive_rx;
                    n.ft.coalesce = Coalesce {
                        adaptive_rx: on,
                        adaptive_tx: on,
                        ..Coalesce::default()
                    };
                    return Ok(((), changed));
                }
                check_coalesce(&c, &n.spec.caps, os)?;
                n.ft.coalesce = c;
                done(())
            },
        )
    }

    /// Ethernet flow control. Windows has no autonegotiation switch.
    pub fn pause(&self) -> io::Result<Pause> {
        self.get(Item::NicRingsCoalescePauseChannels, |n, os| {
            has_pause(n, os)?;
            let mut p = n.ft.pause;
            if os == OsSemantics::Windows {
                p.autoneg = false;
            }
            Ok(p)
        })
    }

    /// Sets Ethernet flow control.
    pub fn set_pause(&self, p: &Pause) -> io::Result<()> {
        let p = *p;
        self.set(
            Item::NicRingsCoalescePauseChannels,
            Need::NetAdmin,
            format!("set_pause({p:?})"),
            |n, os| {
                has_pause(n, os)?;
                if os == OsSemantics::Windows {
                    let changed = (p.rx, p.tx) != (n.ft.pause.rx, n.ft.pause.tx);
                    n.ft.pause = Pause {
                        autoneg: false,
                        ..p
                    };
                    return Ok(((), changed));
                }
                n.ft.pause = p;
                done(())
            },
        )
    }

    /// Queue counts. Windows reports its RSS queues as `combined`.
    pub fn channels(&self) -> io::Result<Channels> {
        self.get(Item::NicRingsCoalescePauseChannels, |n, os| {
            has_channels(n, os)?;
            Ok(n.ft.channels)
        })
    }

    /// Sets queue counts. The `*_max` fields are ignored. A count of zero or
    /// over its maximum is `EINVAL`, as is dropping a queue a flow rule
    /// steers to. A new `combined` count recreates the interface's
    /// interrupts, NAPIs and their kernel threads with new numbers, as
    /// drivers do.
    pub fn set_channels(&self, c: &Channels) -> io::Result<()> {
        let c = *c;
        ensure(self.id);
        let retired = self.set(
            Item::NicRingsCoalescePauseChannels,
            Need::NetAdmin,
            format!("set_channels({c:?})"),
            |n, os| {
                has_channels(n, os)?;
                let cur = n.ft.channels;
                if os == OsSemantics::Windows {
                    if c.combined == 0 || c.combined > cur.combined_max {
                        return Err(invalid(os));
                    }
                    if c.combined == cur.combined {
                        return done(None);
                    }
                    n.ft.channels.combined = c.combined;
                    return Ok((Some(kernel::retire_locked(n)), true));
                }
                let over = c.combined > cur.combined_max
                    || c.rx > cur.rx_max
                    || c.tx > cur.tx_max
                    || c.other > cur.other_max;
                if over || c.combined + c.rx == 0 || c.combined + c.tx == 0 {
                    return Err(invalid(os));
                }
                let rx_queues = c.combined + c.rx;
                let steered_away =
                    n.ft.flow_rules
                        .iter()
                        .any(|r| matches!(r.action, FlowAction::Queue(q) if q >= rx_queues));
                if steered_away {
                    return Err(invalid(os));
                }
                let rebuild = c.combined != cur.combined;
                n.ft.channels = Channels {
                    rx_max: cur.rx_max,
                    tx_max: cur.tx_max,
                    other_max: cur.other_max,
                    combined_max: cur.combined_max,
                    ..c
                };
                let tx_queues = (c.combined + c.tx) as usize;
                n.ft.xps.retain(|&q, _| q < tx_queues);
                n.ft.bql.retain(|&q, _| q < tx_queues);
                n.ft.rps.retain(|&q, _| q < rx_queues as usize);
                n.ft.etf
                    .retain(|q, _| q.is_none_or(|q| usize::from(q) < tx_queues));
                n.ft.queue_qdisc.retain(|&q, _| usize::from(q) < tx_queues);
                done(rebuild.then(|| kernel::retire_locked(n)))
            },
        )?;
        if let Some(retired) = retired {
            rebuild(self.id, retired);
        }
        Ok(())
    }
}

fn has_rings(n: &NicRec, os: OsSemantics) -> io::Result<()> {
    physical(n, os)?;
    let caps = &n.spec.caps;
    match os {
        OsSemantics::Windows if caps.rx_ring_max == 0 => Err(no_keyword("*ReceiveBuffers")),
        _ if caps.rx_ring_max == 0 && caps.tx_ring_max == 0 => Err(not_supported(os)),
        _ => Ok(()),
    }
}

fn has_coalesce(n: &NicRec, os: OsSemantics) -> io::Result<()> {
    physical(n, os)?;
    let none = n.spec.caps.coalesce_supported == crate::CoalesceSupport::NONE;
    match os {
        OsSemantics::Windows if none => Err(no_keyword("*InterruptModeration")),
        _ if none => Err(not_supported(os)),
        _ => Ok(()),
    }
}

fn has_pause(n: &NicRec, os: OsSemantics) -> io::Result<()> {
    physical(n, os)?;
    match os {
        OsSemantics::Windows if !n.spec.caps.pause => Err(no_keyword("*FlowControl")),
        _ if !n.spec.caps.pause => Err(not_supported(os)),
        _ => Ok(()),
    }
}

fn has_channels(n: &NicRec, os: OsSemantics) -> io::Result<()> {
    physical(n, os)?;
    let none = n.spec.caps.combined_channels_max == 0;
    match os {
        OsSemantics::Windows if none => Err(no_keyword("*NumRssQueues")),
        _ if none => Err(not_supported(os)),
        _ => Ok(()),
    }
}

#[derive(Clone, Copy)]
enum Limit {
    Usecs,
    Frames,
    Unlimited,
}

fn check_coalesce(c: &Coalesce, caps: &crate::NicCaps, os: OsSemantics) -> io::Result<()> {
    use crate::CoalesceSupport as S;
    use Limit::{Frames, Unlimited, Usecs};
    let fields = [
        (c.rx_usecs, S::RX_USECS, Usecs),
        (c.rx_frames, S::RX_MAX_FRAMES, Frames),
        (c.rx_usecs_irq, S::RX_USECS_IRQ, Usecs),
        (c.rx_frames_irq, S::RX_MAX_FRAMES_IRQ, Frames),
        (c.tx_usecs, S::TX_USECS, Usecs),
        (c.tx_frames, S::TX_MAX_FRAMES, Frames),
        (c.tx_usecs_irq, S::TX_USECS_IRQ, Usecs),
        (c.tx_frames_irq, S::TX_MAX_FRAMES_IRQ, Frames),
        (c.stats_block_usecs, S::STATS_BLOCK_USECS, Unlimited),
        (u32::from(c.adaptive_rx), S::USE_ADAPTIVE_RX, Unlimited),
        (u32::from(c.adaptive_tx), S::USE_ADAPTIVE_TX, Unlimited),
        (c.pkt_rate_low, S::PKT_RATE_LOW, Unlimited),
        (c.rx_usecs_low, S::RX_USECS_LOW, Usecs),
        (c.rx_frames_low, S::RX_MAX_FRAMES_LOW, Frames),
        (c.tx_usecs_low, S::TX_USECS_LOW, Usecs),
        (c.tx_frames_low, S::TX_MAX_FRAMES_LOW, Frames),
        (c.pkt_rate_high, S::PKT_RATE_HIGH, Unlimited),
        (c.rx_usecs_high, S::RX_USECS_HIGH, Usecs),
        (c.rx_frames_high, S::RX_MAX_FRAMES_HIGH, Frames),
        (c.tx_usecs_high, S::TX_USECS_HIGH, Usecs),
        (c.tx_frames_high, S::TX_MAX_FRAMES_HIGH, Frames),
        (c.sample_interval, S::RATE_SAMPLE_INTERVAL, Unlimited),
    ];
    if fields
        .iter()
        .any(|&(v, bit, _)| v != 0 && !caps.coalesce_supported.contains(bit))
    {
        return Err(not_supported(os));
    }
    let over = fields.iter().any(|&(v, _, limit)| match limit {
        Usecs => v > caps.coalesce_usecs_max,
        Frames => v > caps.coalesce_frames_max,
        Unlimited => false,
    });
    if over {
        return Err(invalid(os));
    }
    Ok(())
}

/// `counters` as the emulated OS reports them: every field on Linux; on
/// macOS packets, bytes, errors, drops, multicast, collisions and
/// `rx_nohandler`; on Windows those plus the missed, FIFO, CRC and frame
/// errors.
pub(crate) fn link_stats(c: &NicCounters, os: OsSemantics) -> LinkStats {
    let mut s = LinkStats::default();
    s.rx_packets = c.rx_packets;
    s.tx_packets = c.tx_packets;
    s.rx_bytes = c.rx_bytes;
    s.tx_bytes = c.tx_bytes;
    s.rx_errors = c.rx_errors;
    s.tx_errors = c.tx_errors;
    s.rx_dropped = c.rx_dropped;
    s.tx_dropped = c.tx_dropped;
    s.multicast = c.multicast;
    s.collisions = c.collisions;
    s.rx_nohandler = c.rx_nohandler;
    if os == OsSemantics::MacOs {
        return s;
    }
    s.rx_missed_errors = c.rx_missed_errors;
    s.rx_fifo_errors = c.rx_fifo_errors;
    s.rx_crc_errors = c.rx_crc_errors;
    s.rx_frame_errors = c.rx_frame_errors;
    s.tx_fifo_errors = c.tx_fifo_errors;
    if os == OsSemantics::Windows {
        return s;
    }
    s.rx_length_errors = c.rx_length_errors;
    s.rx_over_errors = c.rx_over_errors;
    s.tx_aborted_errors = c.tx_aborted_errors;
    s.tx_carrier_errors = c.tx_carrier_errors;
    s.tx_heartbeat_errors = c.tx_heartbeat_errors;
    s.tx_window_errors = c.tx_window_errors;
    s.rx_compressed = c.rx_compressed;
    s.tx_compressed = c.tx_compressed;
    s.rx_otherhost_dropped = c.rx_otherhost_dropped;
    s
}

const LINUX_STATS: [&str; 11] = [
    "rx_packets",
    "tx_packets",
    "rx_bytes",
    "tx_bytes",
    "rx_errors",
    "tx_errors",
    "rx_dropped",
    "tx_dropped",
    "multicast",
    "rx_missed_errors",
    "rx_fifo_errors",
];

const MACOS_STATS: [&str; 14] = [
    "rx_packets",
    "rx_errors",
    "tx_packets",
    "tx_errors",
    "collisions",
    "rx_bytes",
    "tx_bytes",
    "rx_multicast",
    "tx_multicast",
    "rx_queue_drops",
    "rx_no_protocol",
    "tx_queue_len",
    "tx_queue_max",
    "tx_queue_drops",
];

const WINDOWS_ROW_STATS: [&str; 12] = [
    "rx_bytes",
    "rx_unicast",
    "rx_non_unicast",
    "rx_discards",
    "rx_errors",
    "rx_unknown_protocol",
    "tx_bytes",
    "tx_unicast",
    "tx_non_unicast",
    "tx_discards",
    "tx_errors",
    "tx_queue_len",
];

const WINDOWS_OID_STATS: [&str; 7] = [
    "rx_no_buffer",
    "rx_fifo_overrun",
    "rx_crc_errors",
    "rx_alignment_errors",
    "tx_fifo_underrun",
    "tx_one_collision",
    "tx_more_collisions",
];

/// The value of the standard driver counter `name` on `os`.
fn derived_stat(c: &NicCounters, name: &str, os: OsSemantics) -> u64 {
    match (os, name) {
        (_, "rx_packets") => c.rx_packets,
        (_, "tx_packets") => c.tx_packets,
        (_, "rx_bytes") => c.rx_bytes,
        (_, "tx_bytes") => c.tx_bytes,
        (_, "rx_errors") => c.rx_errors,
        (_, "tx_errors") => c.tx_errors,
        (_, "rx_dropped" | "rx_queue_drops" | "rx_discards") => c.rx_dropped,
        (_, "tx_dropped" | "tx_queue_drops" | "tx_discards") => c.tx_dropped,
        (_, "multicast" | "rx_multicast" | "rx_non_unicast") => c.multicast,
        (_, "collisions" | "tx_one_collision") => c.collisions,
        (_, "rx_missed_errors" | "rx_no_buffer") => c.rx_missed_errors,
        (_, "rx_fifo_errors" | "rx_fifo_overrun") => c.rx_fifo_errors,
        (_, "rx_no_protocol" | "rx_unknown_protocol") => c.rx_nohandler,
        (_, "rx_crc_errors") => c.rx_crc_errors,
        (_, "rx_alignment_errors") => c.rx_frame_errors,
        (_, "tx_fifo_underrun") => c.tx_fifo_errors,
        (OsSemantics::Windows, "rx_unicast") => c.rx_packets.saturating_sub(c.multicast),
        (OsSemantics::Windows, "tx_unicast") => c.tx_packets,
        (OsSemantics::MacOs, "tx_queue_max") => 128,
        _ => 0,
    }
}

/// The driver counters of `n` on `os`, in driver order: the standard set
/// for the OS (or the interface's own
/// [`NicCaps::driver_stats`](crate::NicCaps) on Linux), then any the test
/// seeded that the driver does not name.
pub(crate) fn driver_stats_of(n: &NicRec, os: OsSemantics) -> Vec<(String, u64)> {
    let names: Vec<&str> = match os {
        OsSemantics::Linux if !n.spec.caps.driver_stats.is_empty() => n
            .spec
            .caps
            .driver_stats
            .iter()
            .map(String::as_str)
            .collect(),
        OsSemantics::Linux if n.is_loopback() => Vec::new(),
        OsSemantics::Linux => LINUX_STATS.to_vec(),
        OsSemantics::MacOs => MACOS_STATS.to_vec(),
        _ if n.is_loopback() => WINDOWS_ROW_STATS.to_vec(),
        _ => WINDOWS_ROW_STATS
            .iter()
            .chain(&WINDOWS_OID_STATS)
            .copied()
            .collect(),
    };
    let seeded = |name: &str| {
        n.ft.driver_stats
            .iter()
            .find(|(s, _)| s == name)
            .map(|&(_, v)| v)
    };
    let mut out: Vec<(String, u64)> = names
        .iter()
        .map(|&name| {
            let v = seeded(name).unwrap_or_else(|| derived_stat(&n.counters, name, os));
            (name.to_string(), v)
        })
        .collect();
    for (name, v) in &n.ft.driver_stats {
        if !names.contains(&name.as_str()) {
            out.push((name.clone(), *v));
        }
    }
    out
}

/// Driver-specific counters (`ethtool -S`).
#[derive(Clone, Default)]
pub struct DriverStats {
    names: Vec<String>,
    values: Vec<u64>,
}

impl fmt::Debug for DriverStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl DriverStats {
    /// Re-reads the values, and the names when the driver's counter set
    /// changed.
    pub fn refresh(&mut self, nic: &Nic) -> io::Result<()> {
        let stats = nic.get(Item::NicLinkStats, |n, os| Ok(driver_stats_of(n, os)))?;
        let (names, values): (Vec<String>, Vec<u64>) = stats.into_iter().unzip();
        if names != self.names {
            self.names = names;
        }
        self.values = values;
        Ok(())
    }

    /// `(name, value)` pairs in driver order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, u64)> {
        self.names
            .iter()
            .map(String::as_str)
            .zip(self.values.iter().copied())
    }

    /// The counter called exactly `name`.
    pub fn get(&self, name: &str) -> Option<u64> {
        self.iter().find(|&(n, _)| n == name).map(|(_, v)| v)
    }

    /// Counter names, parallel to [`DriverStats::values`].
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Counter values, parallel to [`DriverStats::names`].
    pub fn values(&self) -> &[u64] {
        &self.values
    }

    /// Number of counters.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether the driver exposes no counters.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn mk_qdisc(kind: String, handle: u32, parent: u32) -> Qdisc {
    ::fast_talker::__sim::ctor::qdisc(kind, handle, parent)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn mk_qdisc(kind: String, handle: u32, parent: u32) -> Qdisc {
    Qdisc {
        kind,
        handle,
        parent,
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn mk_clock_offset(
    clock: u32,
    offset_nanos: i64,
    uncertainty: std::time::Duration,
    method: OffsetMethod,
    tai_offset: std::time::Duration,
) -> ClockOffset {
    ::fast_talker::__sim::ctor::clock_offset(clock, offset_nanos, uncertainty, method, tai_offset)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn mk_clock_offset(
    clock: u32,
    offset_nanos: i64,
    uncertainty: std::time::Duration,
    method: OffsetMethod,
    tai_offset: std::time::Duration,
) -> ClockOffset {
    ClockOffset {
        clock,
        offset_nanos,
        uncertainty,
        method,
        tai_offset,
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn mk_queue_stats(r: &super::sim::QueueStatsRec) -> QueueStats {
    ::fast_talker::__sim::ctor::queue_stats(
        r.kind,
        r.queue,
        r.packets,
        r.bytes,
        r.alloc_fail,
        r.hw_drops,
        r.hw_drop_overruns,
        r.hw_drop_ratelimits,
        r.hw_drop_errors,
        r.csum_bad,
        r.stop,
        r.wake,
    )
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn mk_queue_stats(r: &super::sim::QueueStatsRec) -> QueueStats {
    QueueStats {
        kind: r.kind,
        queue: r.queue,
        packets: r.packets,
        bytes: r.bytes,
        alloc_fail: r.alloc_fail,
        hw_drops: r.hw_drops,
        hw_drop_overruns: r.hw_drop_overruns,
        hw_drop_ratelimits: r.hw_drop_ratelimits,
        hw_drop_errors: r.hw_drop_errors,
        csum_bad: r.csum_bad,
        stop: r.stop,
        wake: r.wake,
    }
}
