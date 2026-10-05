//! Per-state-slot fast-talker state: what the code under test configured on
//! its threads and process, the simulated host's facts, and the records
//! tests query. NIC and socket settings live on snare's own NIC and socket
//! records ([`NicFt`], [`UdpFt`], [`TcpFt`]).

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use ::fast_talker::nic::{Channels, Coalesce, DriverInfo, FlowRule, Pause, Rings};
use ::fast_talker::rt::{QosClass, Scheduler, ThreadPriority};
use ::fast_talker::sockets::SocketOptions;
use ::fast_talker::tcp::Stage;
use ::fast_talker::{Config, Source, TxTime, TxTimeError};
use parking_lot::Mutex;

use super::nic::{Eee, Etf, Rss};
use super::sim::{
    CpuTopology, DmaLatencyRequest, FtEntry, MonitorRecord, NicApply, PlanRecord, QueueStatsRec,
    SockOptsSnapshot, StackDelay, SysCheckRecord, SysFacts, ThreadApply, TimeConstraint,
};
use crate::netif::{CoalesceSupport, NicId, NicSpec};
use crate::time::Instant;

#[derive(Default)]
pub(crate) struct FtSlot {
    pub(crate) inner: Mutex<FtState>,
    /// Held while interfaces' interrupts, NAPIs and kernel threads are
    /// built or torn down, so concurrent first uses build them once.
    pub(crate) kernel: Mutex<()>,
}

#[allow(dead_code)]
pub(crate) struct FtState {
    pub rt: BTreeMap<u64, ThreadRt>,
    pub process: ProcessRec,
    pub cpus: CpuTopology,
    pub sys_facts: SysFacts,
    pub plans: Vec<PlanRecord>,
    pub sys_checks: Vec<SysCheckRecord>,
    pub monitors: Vec<MonitorRecord>,
    pub events: Vec<FtEntry>,
    pub stack_delay: StackDelay,
    pub tai_offset: Duration,
    pub irq_default_affinity: Vec<usize>,
    pub next_irq: u32,
    pub next_napi: u32,
    pub protocol_counter_injections: BTreeMap<String, u64>,
    /// Every interrupt line of the simulated host, by number.
    pub irqs: BTreeMap<u32, IrqRec>,
    /// Whether the per-CPU kernel threads (`ksoftirqd/N`) exist yet.
    pub kernel_seeded: bool,
}

/// One interrupt line of the simulated host.
#[derive(Debug, Clone)]
pub(crate) struct IrqRec {
    /// Its handler names, as `/proc/interrupts` shows them.
    pub name: String,
    pub nic: Option<NicId>,
    pub affinity: Vec<usize>,
    /// Its handler threads (`irq/N-name`), by snare tid.
    pub threads: Vec<u64>,
    pub log: Vec<NicApply>,
}

impl Default for FtState {
    fn default() -> Self {
        let cpus = CpuTopology::default();
        Self {
            rt: BTreeMap::new(),
            process: ProcessRec::default(),
            irq_default_affinity: (0..cpus.count).collect(),
            cpus,
            sys_facts: SysFacts::default(),
            plans: Vec::new(),
            sys_checks: Vec::new(),
            monitors: Vec::new(),
            events: Vec::new(),
            stack_delay: StackDelay::default(),
            tai_offset: Duration::from_secs(37),
            next_irq: 120,
            next_napi: 8193,
            protocol_counter_injections: BTreeMap::new(),
            irqs: BTreeMap::new(),
            kernel_seeded: false,
        }
    }
}

/// The real-time settings applied to one thread, keyed in [`FtState::rt`]
/// by its snare tid.
#[derive(Debug, Clone, Default)]
pub(crate) struct ThreadRt {
    pub scheduler: Option<Scheduler>,
    pub nice: Option<i8>,
    pub affinity: Option<Vec<usize>>,
    pub qos: Option<QosClass>,
    pub time_constraint: Option<TimeConstraint>,
    pub win_priority: Option<ThreadPriority>,
    pub power_throttling_disabled: bool,
    /// The MMCSS task joined, with the id of its guard.
    pub mmcss: Option<(u64, String)>,
    pub prefault_bytes: usize,
    pub log: Vec<ThreadApply>,
}

/// Process-wide real-time settings.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProcessRec {
    pub memory_locked: bool,
    pub dma_latency: Vec<DmaLatencyRequest>,
    pub win_priority: Option<::fast_talker::rt::ProcessPriority>,
    pub timer_resolution: Vec<(u64, Duration)>,
    pub power_throttling_disabled: bool,
    pub process_cpus: Option<Vec<usize>>,
    pub working_set: Option<(usize, usize)>,
    /// The id of the next guard handed out (a DMA latency request, a timer
    /// resolution, an MMCSS registration).
    pub next_guard: u64,
    pub log: Vec<ThreadApply>,
}

/// fast-talker's view of one snare NIC, kept on the NIC's own record.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct NicFt {
    pub driver: DriverInfo,
    pub rings: Rings,
    pub coalesce: Coalesce,
    pub pause: Pause,
    pub channels: Channels,
    pub eee: Eee,
    pub threaded_napi: bool,
    pub napis: Vec<NapiRec>,
    pub irqs: Vec<u32>,
    /// Whether the interface's interrupts, NAPIs and kernel threads exist
    /// yet. They are made on first use.
    pub objects_built: bool,
    pub rps: BTreeMap<usize, Vec<usize>>,
    pub xps: BTreeMap<usize, Vec<usize>>,
    pub bql: BTreeMap<usize, u64>,
    pub napi_defer_hard_irqs: u32,
    pub gro_flush_timeout: Duration,
    pub ntuple: bool,
    pub flow_rules: Vec<FlowRule>,
    /// The root `mq` was recreated with a handle, as a per-queue qdisc
    /// needs.
    pub root_mq_named: bool,
    /// Transmit queues whose qdisc was restored to the system default.
    pub queue_qdisc: BTreeMap<u16, String>,
    pub etf: BTreeMap<Option<u16>, Etf>,
    pub hwtstamp: HwTstamp,
    /// Windows' `*SoftwareTimestamp`: the driver stamps received and sent
    /// packets.
    pub win_timestamping: HwTstamp,
    pub win_irq_affinity: Option<Vec<usize>>,
    pub rss: Rss,
    pub ptp: Option<PtpState>,
    /// Driver counters seeded or bumped by the test, which override the
    /// ones derived from the interface's counters.
    pub driver_stats: Vec<(String, u64)>,
    pub queue_stats: Option<Vec<QueueStatsRec>>,
    pub apply_log: Vec<NicApply>,
    /// A Windows adapter restart holds the link down until then.
    pub flap_until: Option<Instant>,
}

impl NicFt {
    pub(crate) fn new(spec: &NicSpec) -> Self {
        let caps = &spec.caps;
        let mut driver = DriverInfo::default();
        driver.driver = spec.driver.driver.clone();
        driver.version = spec.driver.version.clone();
        driver.firmware = spec.driver.firmware.clone();
        driver.bus = spec.driver.bus.clone();
        driver.expansion_rom = spec.driver.expansion_rom.clone();
        let rings = Rings {
            rx_max: caps.rx_ring_max,
            tx_max: caps.tx_ring_max,
            rx: caps.rx_ring,
            tx: caps.tx_ring,
            ..Rings::default()
        };
        let supports = |bit| caps.coalesce_supported.contains(bit);
        let coalesce = Coalesce {
            rx_usecs: if supports(CoalesceSupport::RX_USECS) {
                3
            } else {
                0
            },
            tx_usecs: if supports(CoalesceSupport::TX_USECS) {
                3
            } else {
                0
            },
            adaptive_rx: supports(CoalesceSupport::USE_ADAPTIVE_RX),
            adaptive_tx: supports(CoalesceSupport::USE_ADAPTIVE_TX),
            ..Coalesce::default()
        };
        let pause = Pause {
            autoneg: caps.pause,
            rx: caps.pause,
            tx: caps.pause,
        };
        let channels = Channels {
            combined_max: caps.combined_channels_max,
            combined: caps.combined_channels,
            ..Channels::default()
        };
        let mut eee = Eee::default();
        eee.enabled = caps.eee;
        eee.active = caps.eee;
        eee.tx_lpi_enabled = caps.eee;
        Self {
            driver,
            rings,
            coalesce,
            pause,
            channels,
            eee,
            threaded_napi: false,
            napis: Vec::new(),
            irqs: Vec::new(),
            objects_built: false,
            rps: BTreeMap::new(),
            xps: BTreeMap::new(),
            bql: BTreeMap::new(),
            napi_defer_hard_irqs: 0,
            gro_flush_timeout: Duration::ZERO,
            ntuple: false,
            flow_rules: Vec::new(),
            root_mq_named: false,
            queue_qdisc: BTreeMap::new(),
            etf: BTreeMap::new(),
            hwtstamp: HwTstamp::default(),
            win_timestamping: HwTstamp {
                rx: caps.sw_timestamp,
                tx: caps.sw_timestamp,
            },
            win_irq_affinity: None,
            rss: Rss {
                enabled: true,
                ..Rss::default()
            },
            ptp: caps.phc_index.map(|clock| PtpState {
                clock,
                offset_nanos: 0,
                uncertainty: Duration::ZERO,
                tai: true,
            }),
            driver_stats: Vec::new(),
            queue_stats: None,
            apply_log: Vec::new(),
            flap_until: None,
        }
    }
}

/// One NAPI instance of a simulated NIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct NapiRec {
    pub id: u32,
    pub irq: Option<u32>,
    pub thread: Option<u64>,
}

/// The NIC's hardware timestamping state (`SIOCSHWTSTAMP`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct HwTstamp {
    pub rx: bool,
    pub tx: bool,
}

/// A NIC's PTP hardware clock: its index and how far it is from the
/// system clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct PtpState {
    pub clock: u32,
    pub offset_nanos: i64,
    pub uncertainty: Duration,
    /// The clock runs in TAI, as PTP clocks usually do.
    pub tai: bool,
}

/// fast-talker's view of one snare UDP socket, kept on its record.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) struct UdpFt {
    pub timestamping: Option<Config>,
    pub source: Option<Source>,
    pub interface: Option<String>,
    pub tx: TxStamping,
    /// The interface stamping this socket's sends in hardware.
    pub tx_hw: Option<NicId>,
    pub txtime: Option<TxTime>,
    pub next_tx_id: u32,
    pub errq: VecDeque<TxRecord>,
    pub txtime_errors: VecDeque<(Instant, TxTimeError)>,
    /// Timed sends still to be reported missed instead of sent.
    pub missed_budget: u32,
    pub sockopts: SocketOptions,
    pub effective: SockOptsSnapshot,
    /// The source, destination and interface of the datagram Linux
    /// records as the socket's last: every datagram once connected, else
    /// only the first.
    pub rx_flow: Option<(std::net::SocketAddr, std::net::SocketAddr, NicId)>,
}

impl UdpFt {
    /// Whether an error-queue entry is ready: a transmit stamp the kernel
    /// signals as an error condition, or a dropped timed send.
    pub(crate) fn error_ready(&self, now: Instant) -> bool {
        let stamp =
            self.tx == TxStamping::Kernel && self.errq.front().is_some_and(|r| r.visible_at <= now);
        stamp || self.txtime_errors.front().is_some_and(|(at, _)| *at <= now)
    }
}

/// Who stamps a UDP socket's sends.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum TxStamping {
    #[default]
    Off,
    /// The kernel stamps every send on the socket and signals the stamps
    /// as an error condition (Linux).
    Kernel,
    /// fast-talker stamps the sends made through `Timestamped` (macOS,
    /// Windows).
    Library,
}

/// One sent datagram whose transmit stamp is waiting to be read.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TxRecord {
    pub id: u32,
    /// When the datagram left: the send, or the launch of a timed send.
    pub at: Instant,
    pub visible_at: Instant,
    pub source: Source,
    pub egress: Option<NicId>,
}

/// fast-talker's view of one snare TCP stream, kept on its record.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) struct TcpFt {
    pub timestamping: Option<Config>,
    pub source: Option<Source>,
    pub interface: Option<String>,
    pub tx: TxStamping,
    /// The interface stamping this stream's sends in hardware.
    pub tx_hw: Option<NicId>,
    /// Bytes written since transmit stamping started: the next send's
    /// first byte has this offset.
    pub tx_offset: u64,
    /// Sends stamped so far.
    pub stamped_sends: u32,
    /// Send stages not read yet, in the order they become visible.
    pub tx_events: VecDeque<TcpTxRecord>,
    /// Stamped sends held on a downed interface, with the return latency of
    /// their acknowledgement, acknowledged once they reach the peer.
    pub held_acks: Vec<(u32, Duration)>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub sockopts: SocketOptions,
    pub effective: SockOptsSnapshot,
}

impl TcpFt {
    /// Whether a send stage the kernel signals as an error condition is
    /// ready to read.
    pub(crate) fn error_ready(&self, now: Instant) -> bool {
        self.tx == TxStamping::Kernel && self.tx_events.front().is_some_and(|r| r.visible_at <= now)
    }
}

/// fast-talker's view of one snare TCP listener, kept on its record.
#[derive(Debug, Default)]
pub(crate) struct ListenerFt {
    pub sockopts: SocketOptions,
    pub effective: SockOptsSnapshot,
}

/// One stage of one TCP send, waiting to be read.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TcpTxRecord {
    pub id: u32,
    pub stage: Stage,
    pub at: Instant,
    pub visible_at: Instant,
    pub source: Source,
    pub egress: Option<NicId>,
}
