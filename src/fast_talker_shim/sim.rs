//! The test side of the fast-talker shim: seed the simulated host and query
//! what the code under test configured. Everything here is per state slot,
//! like the rest of snare. NICs, routes, privileges, limits, socket drops
//! and the emulated OS are seeded through snare's own functions
//! ([`add_nic`](crate::add_nic), [`set_privileges`](crate::set_privileges),
//! [`set_os_semantics`](crate::set_os_semantics), ...).

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
use std::thread::ThreadId;
use std::time::Duration;

use ::fast_talker::monitor::{Sample, SourceError};
use ::fast_talker::options::ThreadOption;
use ::fast_talker::plan::{Drift, Plan};
use ::fast_talker::rt::{ProcessPriority, QosClass, Scheduler, ThreadPriority};
use ::fast_talker::sockets::SocketOptions;
use ::fast_talker::sys_check::{Check, Finding};
use ::fast_talker::{Config, Source, TxTime};

use super::nic::{
    Channels, Coalesce, DriverInfo, Eee, Etf, FlowRule, Pause, QueueKind, Rings, Rss,
};
use super::slot::{FtSlot, IrqRec, NicFt, PtpState};
use crate::netif::{NicId, SocketEntry, SocketId, SocketKind, socket_table_locked, with_nic_rec};
use crate::os::OsSemantics;
use crate::sched::ThreadClass;
use crate::time::Instant;

/// Install snare's fast-talker backend. snare does this itself when a test
/// registers, a state slot is created or a socket is opened; call it when a
/// harness calls a hooked fast-talker function before any of those.
pub fn install() {
    super::hooks::install();
}

/// The simulated host's CPUs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuTopology {
    pub count: usize,
    /// `isolcpus=`.
    pub isolated: Vec<usize>,
    /// `nohz_full=`.
    pub nohz_full: Vec<usize>,
    /// `rcu_nocbs=`.
    pub rcu_nocbs: Vec<usize>,
}

impl Default for CpuTopology {
    fn default() -> Self {
        Self {
            count: 8,
            isolated: Vec::new(),
            nohz_full: Vec::new(),
            rcu_nocbs: Vec::new(),
        }
    }
}

/// Where the simulated network stack takes its timestamps, relative to a
/// datagram's virtual delivery instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackDelay {
    /// How long before the kernel stamp the NIC stamped a received frame.
    pub hw_rx_before_kernel: Duration,
    /// How long after the kernel stamp the NIC stamped a sent frame.
    pub hw_tx_after_kernel: Duration,
}

impl Default for StackDelay {
    fn default() -> Self {
        Self {
            hw_rx_before_kernel: Duration::from_micros(2),
            hw_tx_after_kernel: Duration::from_micros(2),
        }
    }
}

/// What the simulated host's system checks read. CPU isolation comes from
/// [`CpuTopology`], privileges from [`set_privileges`](crate::set_privileges)
/// and socket limits from [`set_sys_limits`](crate::set_sys_limits).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysFacts {
    pub preempt_rt: bool,
    /// `uname -rv`, as a failed `PreemptRt` check reports it.
    pub kernel: String,
    pub irqbalance_running: bool,
    /// `kernel.sched_rt_runtime_us`.
    pub rt_runtime_us: i64,
    /// cpufreq governor of every CPU; empty for no cpufreq driver.
    pub governor: String,
    /// The idle states of every CPU; empty for no cpuidle driver.
    pub idle_states: Vec<IdleState>,
    /// `transparent_hugepage/enabled`; empty for a kernel without them.
    pub transparent_hugepages: String,
    pub smt_enabled: bool,
    /// sysctls by dotted name. Unset ones read snare's own values where it
    /// has them (`net.core.rmem_max`, `kern.ipc.maxsockbuf`,
    /// `kernel.sched_rt_runtime_us`, ...).
    pub sysctls: BTreeMap<String, String>,
    /// The kernel command line. `isolcpus=`, `nohz_full=` and `rcu_nocbs=`
    /// are added from [`CpuTopology`].
    pub kernel_args: Vec<String>,
    pub macos_low_power_mode: bool,
    /// The active power plan's name.
    pub win_power_plan: String,
    /// The share of cores the active power plan keeps unparked, in percent.
    pub win_unparked_percent: u32,
}

/// One CPU idle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdleState {
    pub name: String,
    pub latency_us: u32,
    pub disabled: bool,
}

impl IdleState {
    pub fn new(name: &str, latency_us: u32) -> Self {
        Self {
            name: name.into(),
            latency_us,
            disabled: false,
        }
    }

    pub fn disabled(mut self) -> Self {
        self.disabled = true;
        self
    }
}

/// The Windows power plans a real-time host runs.
pub(crate) const WIN_FAST_PLANS: [&str; 2] = ["High performance", "Ultimate Performance"];

impl SysFacts {
    /// A host set up for real-time work: every check in
    /// `Check::recommended` passes for any CPU list the topology isolates.
    pub fn tuned() -> Self {
        Self {
            preempt_rt: true,
            kernel: "6.6.44-rt39 #1 SMP PREEMPT_RT".into(),
            irqbalance_running: false,
            rt_runtime_us: -1,
            governor: "performance".into(),
            idle_states: vec![
                IdleState::new("POLL", 0),
                IdleState::new("C1", 2),
                IdleState::new("C1E", 10).disabled(),
                IdleState::new("C6", 133).disabled(),
            ],
            transparent_hugepages: "never".into(),
            smt_enabled: false,
            sysctls: BTreeMap::new(),
            kernel_args: Vec::new(),
            macos_low_power_mode: false,
            win_power_plan: "High performance".into(),
            win_unparked_percent: 100,
        }
    }

    /// A distribution's defaults.
    pub fn stock() -> Self {
        Self {
            preempt_rt: false,
            kernel: "6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC".into(),
            irqbalance_running: true,
            rt_runtime_us: 950_000,
            governor: "schedutil".into(),
            idle_states: vec![
                IdleState::new("POLL", 0),
                IdleState::new("C1", 2),
                IdleState::new("C1E", 10),
                IdleState::new("C6", 133),
            ],
            transparent_hugepages: "madvise".into(),
            smt_enabled: true,
            sysctls: BTreeMap::new(),
            kernel_args: vec!["quiet".into(), "splash".into()],
            macos_low_power_mode: false,
            win_power_plan: "Balanced".into(),
            win_unparked_percent: 10,
        }
    }
}

impl Default for SysFacts {
    fn default() -> Self {
        Self::tuned()
    }
}

/// Mach time-constraint scheduling applied to a thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeConstraint {
    pub period: Duration,
    pub computation: Duration,
    pub constraint: Duration,
}

/// One real-time setting applied to a thread, or skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadApply {
    pub at: Instant,
    /// What was applied, e.g. `format!("{option:?}")`. Skipped options are
    /// prefixed `skipped:`.
    pub what: String,
    pub result: Result<(), std::io::ErrorKind>,
    pub os_error: Option<i32>,
}

/// One thread the state slot knows about, with the real-time settings the
/// code under test gave it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ThreadSnapshot {
    /// snare's id for the thread: what `rt::Thread::id` returns under the
    /// shim.
    pub tid: u64,
    /// The host thread id, where it was recorded.
    pub host_tid: Option<u64>,
    pub std_id: Option<ThreadId>,
    pub name: Option<String>,
    /// A synthetic kernel thread (an IRQ or NAPI thread).
    pub kernel: bool,
    /// The thread's scheduler class now, or when it exited.
    pub class: ThreadClass,
    pub exited: bool,
    pub scheduler: Option<Scheduler>,
    pub nice: Option<i8>,
    pub affinity: Option<Vec<usize>>,
    pub qos: Option<QosClass>,
    pub time_constraint: Option<TimeConstraint>,
    pub win_priority: Option<ThreadPriority>,
    pub power_throttling_disabled: bool,
    /// The MMCSS task the thread joined.
    pub mmcss: Option<String>,
    pub prefault_bytes: usize,
    pub log: Vec<ThreadApply>,
}

/// One `CpuDmaLatency` request still held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaLatencyRequest {
    pub id: u64,
    pub max: Duration,
    pub at: Instant,
    pub tid: Option<u64>,
}

/// The process-wide real-time settings the code under test made.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProcessSnapshot {
    /// `lock_memory` succeeded.
    pub memory_locked: bool,
    /// `CpuDmaLatency` requests still held.
    pub dma_latency: Vec<DmaLatencyRequest>,
    /// The latency limit in force: the smallest request held.
    pub dma_latency_effective: Option<Duration>,
    /// The Windows priority class, where it was set.
    pub priority: Option<ProcessPriority>,
    /// `TimerResolution` requests still held.
    pub timer_resolution: Vec<Duration>,
    /// The timer resolution in force: the finest request held.
    pub timer_resolution_effective: Option<Duration>,
    pub power_throttling_disabled: bool,
    /// The CPUs `set_process_cpus` keeps the process on.
    pub process_cpus: Option<Vec<usize>>,
    /// The working set `reserve_working_set` reserved: minimum and maximum.
    pub working_set: Option<(usize, usize)>,
    /// Every process-wide setting applied or refused, in order.
    pub log: Vec<ThreadApply>,
}

pub use crate::mcast::Membership;

/// The socket options in force on a socket, as the kernel reports them
/// back, and every `SocketOptions` field applied or refused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SockOptsSnapshot {
    /// The effective receive buffer: doubled on Linux.
    pub recv_buffer: Option<usize>,
    pub send_buffer: Option<usize>,
    /// The `IP_TOS` or `IPV6_TCLASS` byte: the DSCP shifted left by two.
    pub tos: Option<u8>,
    /// `SO_PRIORITY`. Setting the IPv4 TOS on Linux resets it to the TOS's
    /// default priority.
    pub priority: Option<u32>,
    pub bind_device: Option<String>,
    /// Windows' `IP_UNICAST_IF` steers only sends.
    pub bind_device_send_only: bool,
    pub dont_fragment: bool,
    pub busy_poll: Duration,
    pub prefer_busy_poll: bool,
    pub busy_poll_budget: u16,
    pub cpu_affinity: Option<usize>,
    pub log: Vec<SocketApply>,
}

/// One socket option the code under test applied, or had refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketApply {
    pub at: Instant,
    pub tid: Option<u64>,
    /// What was applied, e.g. `recv_buffer(100000)`.
    pub what: String,
    pub result: Result<(), io::ErrorKind>,
    pub os_error: Option<i32>,
}

/// One `Plan::apply` or `Plan::check`.
#[derive(Debug, Clone)]
pub struct PlanRecord {
    pub at: Instant,
    pub tid: Option<u64>,
    pub plan: Plan,
    /// A `check` rather than an `apply`.
    pub check: bool,
    pub error: Option<String>,
    pub drift: Vec<Drift>,
}

/// One `sys_check` call and the findings it was served.
#[derive(Debug, Clone)]
pub struct SysCheckRecord {
    pub at: Instant,
    pub tid: Option<u64>,
    pub checks: Vec<Check>,
    pub findings: Vec<Finding>,
}

/// One monitor the code under test started, with its whole config.
#[derive(Debug, Clone)]
pub struct MonitorRecord {
    pub id: u64,
    pub thread_tid: Option<u64>,
    pub started_at: Instant,
    pub stopped_at: Option<Instant>,
    pub interval: Duration,
    pub interfaces: Vec<String>,
    /// Label, socket, and whether it is a stream.
    pub sockets: Vec<(String, SocketId, bool)>,
    pub protocol_counters: bool,
    pub driver_stats: bool,
    pub queue_stats: bool,
    pub clock_every: Option<u32>,
    pub plan: Option<Plan>,
    pub plan_every: u32,
    pub thread: Vec<ThreadOption>,
    pub samples: u64,
    pub last_sample: Option<Sample>,
    pub last_errors: Vec<SourceError>,
}

/// Something the fast-talker shim did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FtEvent {
    /// The code under test used an item the emulated OS lacks.
    Unsupported { item: &'static str, os: OsSemantics },
    /// A timed send left at once: its interface has no ETF qdisc.
    TxTimeWithoutEtf { socket: SocketId },
    /// A real-time setting applied to a thread, or to the process when
    /// `thread` is `None`, or refused.
    Rt {
        thread: Option<u64>,
        what: String,
        result: Result<(), std::io::ErrorKind>,
    },
    /// A `sys_check` call and how many of its checks passed.
    SysCheck { checks: usize, passed: usize },
    /// An interface setting applied, or refused.
    Nic {
        nic: String,
        what: String,
        result: Result<(), std::io::ErrorKind>,
    },
    /// An interrupt affinity change, of one interrupt or of all of them
    /// when `irq` is `None`, applied or refused.
    Irq {
        irq: Option<u32>,
        what: String,
        result: Result<(), std::io::ErrorKind>,
    },
    /// A socket option or multicast setting applied, or refused.
    Socket {
        socket: SocketId,
        what: String,
        result: Result<(), std::io::ErrorKind>,
    },
    /// A thread or process option this snare does not know, refused as
    /// unsupported.
    UnknownOption { what: String },
    /// A `Plan::apply`, and why it stopped, if it did.
    PlanApplied {
        interfaces: Vec<String>,
        error: Option<String>,
    },
    /// A `Plan::check` and how many settings drifted.
    PlanChecked { drift: usize },
    /// A monitor started, by its [`MonitorRecord::id`].
    MonitorStarted { id: u64 },
    /// A monitor stopped.
    MonitorStopped { id: u64 },
}

/// An [`FtEvent`], when and on which thread it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtEntry {
    pub at: Instant,
    pub tid: Option<u64>,
    pub event: FtEvent,
}

fn slot() -> Arc<FtSlot> {
    crate::state::ft_slot()
}

pub(crate) fn log(event: FtEvent) {
    let tid = crate::threads::current_tid();
    let at = Instant::now();
    slot().inner.lock().events.push(FtEntry { at, tid, event });
}

/// Set the simulated host's CPUs. Also resets the default IRQ affinity to
/// every CPU.
pub fn set_cpus(t: CpuTopology) {
    let s = slot();
    let mut g = s.inner.lock();
    g.irq_default_affinity = (0..t.count).collect();
    g.cpus = t;
}

/// How far `CLOCK_TAI` leads `CLOCK_REALTIME` on the simulated host.
/// 37 s by default.
pub fn set_tai_offset(d: Duration) {
    slot().inner.lock().tai_offset = d;
}

pub fn set_stack_delay(d: StackDelay) {
    slot().inner.lock().stack_delay = d;
}

/// Change what system checks read. [`SysFacts::tuned`] by default.
pub fn set_sys_facts(f: impl FnOnce(&mut SysFacts)) {
    let s = slot();
    let mut facts = s.inner.lock().sys_facts.clone();
    f(&mut facts);
    s.inner.lock().sys_facts = facts;
}

/// Add to the protocol counters `Counters::read` reports, by `nstat`
/// name. The traffic snare carries is counted on top.
pub fn set_protocol_counters(f: impl FnOnce(&mut BTreeMap<String, u64>)) {
    let s = slot();
    let mut counters = s.inner.lock().protocol_counter_injections.clone();
    f(&mut counters);
    s.inner.lock().protocol_counter_injections = counters;
}

/// Every thread the state slot knows about, oldest first.
pub fn threads() -> Vec<ThreadSnapshot> {
    let infos = crate::threads::all();
    let s = slot();
    let g = s.inner.lock();
    infos
        .into_iter()
        .map(|t| {
            let rt = g.rt.get(&t.tid).cloned().unwrap_or_default();
            ThreadSnapshot {
                tid: t.tid,
                host_tid: t.host_tid,
                std_id: t.std_id,
                name: t.name,
                kernel: t.kernel,
                class: t.class,
                exited: t.exited,
                scheduler: rt.scheduler,
                nice: rt.nice,
                affinity: rt.affinity,
                qos: rt.qos,
                time_constraint: rt.time_constraint,
                win_priority: rt.win_priority,
                power_throttling_disabled: rt.power_throttling_disabled,
                mmcss: rt.mmcss.map(|(_, task)| task),
                prefault_bytes: rt.prefault_bytes,
                log: rt.log,
            }
        })
        .collect()
}

/// The newest thread named `name`.
pub fn thread_named(name: &str) -> Option<ThreadSnapshot> {
    threads()
        .into_iter()
        .rev()
        .find(|t| t.name.as_deref() == Some(name))
}

/// The thread with std id `id`.
pub fn thread_of(id: ThreadId) -> Option<ThreadSnapshot> {
    threads().into_iter().find(|t| t.std_id == Some(id))
}

/// The thread with snare tid `tid`, kernel threads included.
pub fn thread_by_tid(tid: u64) -> Option<ThreadSnapshot> {
    threads().into_iter().find(|t| t.tid == tid)
}

/// The process-wide real-time settings.
pub fn process() -> ProcessSnapshot {
    let s = slot();
    let g = s.inner.lock();
    let p = &g.process;
    ProcessSnapshot {
        memory_locked: p.memory_locked,
        dma_latency: p.dma_latency.clone(),
        dma_latency_effective: p.dma_latency.iter().map(|r| r.max).min(),
        priority: p.win_priority,
        timer_resolution: p.timer_resolution.iter().map(|(_, d)| *d).collect(),
        timer_resolution_effective: p.timer_resolution.iter().map(|(_, d)| *d).min(),
        power_throttling_disabled: p.power_throttling_disabled,
        process_cpus: p.process_cpus.clone(),
        working_set: p.working_set,
        log: p.log.clone(),
    }
}

/// Every plan applied or checked, in order.
pub fn plans_applied() -> Vec<PlanRecord> {
    slot().inner.lock().plans.clone()
}

/// Every `sys_check` call, in order.
pub fn sys_checks() -> Vec<SysCheckRecord> {
    slot().inner.lock().sys_checks.clone()
}

/// Every monitor started, in order.
pub fn monitors() -> Vec<MonitorRecord> {
    slot().inner.lock().monitors.clone()
}

/// Everything the shim logged, in order.
pub fn events() -> Vec<FtEntry> {
    slot().inner.lock().events.clone()
}

pub fn clear_events() {
    slot().inner.lock().events.clear();
}

/// An interface's PTP hardware clock, as [`set_ptp`] seeds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtpSeed {
    /// Its index (`/dev/ptpN`).
    pub clock: u32,
    /// How far it is ahead of the system clock (behind when negative),
    /// beyond the TAI offset. Hardware stamps further off than a socket's
    /// `Config::tolerance` fall back to kernel stamps.
    pub offset_nanos: i64,
    pub uncertainty: Duration,
    /// It runs in TAI, [`set_tai_offset`] ahead of the system clock, as
    /// PTP clocks usually do.
    pub tai: bool,
}

impl Default for PtpSeed {
    fn default() -> Self {
        Self {
            clock: 0,
            offset_nanos: 0,
            uncertainty: Duration::ZERO,
            tai: true,
        }
    }
}

/// Give the interface `nic` a PTP hardware clock, or change how far it is
/// from the system clock. An interface with hardware timestamping and no
/// PTP clock stamps on a free-running clock whose readings fail every
/// tolerance check.
pub fn set_ptp(nic: &str, ptp: PtpSeed) -> io::Result<()> {
    crate::netif::with_nic_ft(nic, |ft| {
        ft.ptp = Some(PtpState {
            clock: ptp.clock,
            offset_nanos: ptp.offset_nanos,
            uncertainty: ptp.uncertainty,
            tai: ptp.tai,
        });
    })
    .ok_or_else(|| no_interface(nic))
}

/// Put an ETF qdisc on transmit queue `queue` of the interface `nic`
/// (`None` for the root), or take it off with `None`. Timed sends through
/// the interface are held until their launch time only with one in place.
pub fn set_etf(nic: &str, queue: Option<u16>, etf: Option<Etf>) -> io::Result<()> {
    crate::netif::set_etf_internal(nic, queue, etf)
}

/// Report the next `n` timed sends the socket `id` makes through an ETF
/// qdisc as missed at their launch time, instead of sending them.
pub fn inject_txtime_missed(id: SocketId, n: u32) -> io::Result<()> {
    crate::state::with_net(|ctx| {
        let c = ctx
            .udp
            .iter_mut()
            .find(|c| c.id == id && !c.dropped)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no live UDP socket with id {}", id.get()),
                )
            })?;
        c.ft.missed_budget = c.ft.missed_budget.saturating_add(n);
        Ok(())
    })
}

fn no_interface(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("no interface named {name:?}"),
    )
}

/// One socket as fast-talker sees it: its snare entry, plus what the code
/// under test configured through fast-talker.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FtSocketSnapshot {
    pub entry: SocketEntry,
    /// A TCP stream rather than a datagram socket.
    pub stream: bool,
    /// The `Config` a `Timestamped` was built with, if any.
    pub timestamping: Option<Config>,
    /// The best timestamp source it got.
    pub source: Option<Source>,
    /// The interface hardware stamping was enabled on.
    pub hardware_interface: Option<String>,
    /// The timed-send mode enabled on the socket.
    pub txtime: Option<TxTime>,
    /// Every `SocketOptions` field applied, merged: what was asked for.
    pub options: SocketOptions,
    /// What is in force.
    pub sockopts: SockOptsSnapshot,
    pub memberships: Vec<Membership>,
    /// The multicast TTL or hop limit of the socket's family.
    pub multicast_hops: Option<u32>,
    /// Multicast loopback for the socket's family.
    pub multicast_loop: Option<bool>,
    pub only_joined: bool,
    /// Transmit stamp ids handed out so far: one per stamped send.
    pub tx_ids_issued: u32,
    /// Transmit stamps (a stream's send stages) not read yet, ready or not.
    pub pending_tx_stamps: usize,
    /// Dropped timed sends not read yet, ready or not.
    pub pending_txtime_errors: usize,
    /// Timed sends still to be reported missed ([`inject_txtime_missed`]).
    pub txtime_missed_pending: u32,
    /// Bytes a stream has written and received.
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl FtSocketSnapshot {
    fn bare(entry: SocketEntry) -> Self {
        Self {
            stream: entry.kind == SocketKind::TcpStream,
            memberships: entry.memberships.clone(),
            entry,
            timestamping: None,
            source: None,
            hardware_interface: None,
            txtime: None,
            options: SocketOptions::default(),
            sockopts: SockOptsSnapshot::default(),
            multicast_hops: None,
            multicast_loop: None,
            only_joined: false,
            tx_ids_issued: 0,
            pending_tx_stamps: 0,
            pending_txtime_errors: 0,
            txtime_missed_pending: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

fn snapshots(ctx: &crate::state::NetCtx<'_>) -> Vec<FtSocketSnapshot> {
    socket_table_locked(ctx)
        .into_iter()
        .map(|entry| {
            let id = entry.id;
            let mut snap = FtSocketSnapshot::bare(entry);
            if let Some(c) = ctx.udp.iter().find(|c| c.id == id && !c.dropped) {
                let ft = &c.ft;
                snap.timestamping = ft.timestamping.clone();
                snap.source = ft.source;
                snap.hardware_interface = ft.interface.clone();
                snap.txtime = ft.txtime;
                snap.options = ft.sockopts.clone();
                snap.sockopts = ft.effective.clone();
                let v4 = c.bound_addr.is_ipv4();
                snap.multicast_hops = Some(if v4 { c.mcast.ttl_v4 } else { c.mcast.hops_v6 });
                snap.multicast_loop = Some(if v4 { c.mcast.loop_v4 } else { c.mcast.loop_v6 });
                snap.only_joined = c.mcast.only_joined;
                snap.tx_ids_issued = ft.next_tx_id;
                snap.pending_tx_stamps = ft.errq.len();
                snap.pending_txtime_errors = ft.txtime_errors.len();
                snap.txtime_missed_pending = ft.missed_budget;
            } else if let Some(c) = ctx.tcp.values().find(|c| c.id == id) {
                let ft = &c.ft;
                snap.timestamping = ft.timestamping.clone();
                snap.source = ft.source;
                snap.hardware_interface = ft.interface.clone();
                snap.options = ft.sockopts.clone();
                snap.sockopts = ft.effective.clone();
                snap.tx_ids_issued = ft.stamped_sends;
                snap.pending_tx_stamps = ft.tx_events.len();
                snap.bytes_sent = ft.bytes_sent;
                snap.bytes_received = ft.bytes_received;
            }
            snap
        })
        .collect()
}

/// The socket `id` as fast-talker sees it. A closed socket has only its
/// entry.
pub fn socket(id: SocketId) -> Option<FtSocketSnapshot> {
    crate::state::with_net(|ctx| {
        snapshots(&ctx)
            .into_iter()
            .find(|s| s.entry.id == id)
            .or_else(|| {
                ctx.net
                    .history
                    .iter()
                    .rev()
                    .find(|e| e.id == id)
                    .cloned()
                    .map(FtSocketSnapshot::bare)
            })
    })
}

/// Every live socket as fast-talker sees it, by id.
pub fn sockets() -> Vec<FtSocketSnapshot> {
    crate::state::with_net(|ctx| snapshots(&ctx))
}

/// What fast-talker's `sockets::incoming_cpu` reports for the socket `id`:
/// the CPU that processed its last received packet. The function itself
/// exists only on Linux and Windows hosts.
pub fn incoming_cpu(id: SocketId) -> io::Result<Option<usize>> {
    super::nic::incoming_cpu(id)
}

/// One interface or interrupt setting the code under test applied, or had
/// refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicApply {
    pub at: Instant,
    pub tid: Option<u64>,
    /// What was applied, e.g. `set_rings(Rings { .. })`.
    pub what: String,
    pub result: Result<(), io::ErrorKind>,
    pub os_error: Option<i32>,
}

/// One queue's statistics, as [`set_queue_stats`] seeds them and
/// `Nic::queue_stats` reports them. `None` is a statistic the driver does
/// not keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueStatsRec {
    pub kind: QueueKind,
    pub queue: u32,
    pub packets: Option<u64>,
    pub bytes: Option<u64>,
    pub alloc_fail: Option<u64>,
    pub hw_drops: Option<u64>,
    pub hw_drop_overruns: Option<u64>,
    pub hw_drop_ratelimits: Option<u64>,
    pub hw_drop_errors: Option<u64>,
    pub csum_bad: Option<u64>,
    pub stop: Option<u64>,
    pub wake: Option<u64>,
}

impl QueueStatsRec {
    /// Queue `queue` of `kind`, keeping no statistics.
    pub fn new(kind: QueueKind, queue: u32) -> Self {
        Self {
            kind,
            queue,
            packets: None,
            bytes: None,
            alloc_fail: None,
            hw_drops: None,
            hw_drop_overruns: None,
            hw_drop_ratelimits: None,
            hw_drop_errors: None,
            csum_bad: None,
            stop: None,
            wake: None,
        }
    }
}

/// One qdisc of an interface, root first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QdiscSnapshot {
    pub kind: String,
    pub handle: u32,
    pub parent: u32,
    /// The transmit queue it serves; `None` for the root.
    pub queue: Option<u16>,
    /// Its settings, for an ETF qdisc.
    pub etf: Option<Etf>,
}

/// One NAPI of an interface, with where its interrupt and thread run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NapiSnapshot {
    pub id: u32,
    /// The receive queue it polls.
    pub queue: u32,
    pub irq: Option<u32>,
    pub irq_affinity: Option<Vec<usize>>,
    /// Its `napi/<nic>-<id>` thread while NAPI is threaded, by snare tid.
    pub thread: Option<u64>,
    pub thread_name: Option<String>,
    pub thread_scheduler: Option<Scheduler>,
    pub thread_affinity: Option<Vec<usize>>,
}

/// One interrupt of the simulated host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrqSnapshot {
    pub number: u32,
    pub name: String,
    pub nic: Option<String>,
    pub affinity: Vec<usize>,
    pub effective_affinity: Vec<usize>,
    /// Its handler threads, by snare tid.
    pub threads: Vec<u64>,
    /// Every affinity change applied to it or refused, in order.
    pub log: Vec<NicApply>,
}

/// The settings of an interface the code under test can change, as
/// [`interface`] reports them and [`mutate_interface`] edits them.
#[derive(Debug, Clone, PartialEq)]
pub struct InterfaceSettings {
    pub rings: Rings,
    pub coalesce: Coalesce,
    pub pause: Pause,
    pub channels: Channels,
    pub eee: Eee,
    pub threaded_napi: bool,
    /// RPS CPUs by receive queue.
    pub rps: BTreeMap<usize, Vec<usize>>,
    /// XPS CPUs by transmit queue.
    pub xps: BTreeMap<usize, Vec<usize>>,
    /// Byte queue limits by transmit queue.
    pub bql: BTreeMap<usize, u64>,
    pub napi_defer_hard_irqs: u32,
    pub gro_flush_timeout: Duration,
    pub ntuple: bool,
    pub flow_rules: Vec<FlowRule>,
    /// Linux hardware timestamping (`SIOCSHWTSTAMP`).
    pub hw_rx_timestamping: bool,
    pub hw_tx_timestamping: bool,
    /// Windows driver timestamping (`*SoftwareTimestamp`).
    pub win_rx_timestamping: bool,
    pub win_tx_timestamping: bool,
    /// The Windows interrupt affinity policy.
    pub win_irq_affinity: Option<Vec<usize>>,
    pub rss: Rss,
}

/// One interface as fast-talker sees it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct InterfaceSnapshot {
    pub name: String,
    pub index: u32,
    /// The link as the interface reports it: down while set down or while
    /// a Windows adapter restart is under way.
    pub link_up: bool,
    /// When the last Windows adapter restart ended or ends.
    pub restart_until: Option<Instant>,
    pub settings: InterfaceSettings,
    pub driver: DriverInfo,
    pub napis: Vec<NapiSnapshot>,
    pub irqs: Vec<u32>,
    pub qdiscs: Vec<QdiscSnapshot>,
    pub ptp: Option<PtpSeed>,
    /// Its driver counters, as the emulated OS names them.
    pub driver_stats: Vec<(String, u64)>,
    pub queue_stats: Vec<QueueStatsRec>,
    /// Every setting applied or refused, in order.
    pub apply_log: Vec<NicApply>,
}

fn settings_of(ft: &NicFt) -> InterfaceSettings {
    InterfaceSettings {
        rings: ft.rings,
        coalesce: ft.coalesce,
        pause: ft.pause,
        channels: ft.channels,
        eee: ft.eee,
        threaded_napi: ft.threaded_napi,
        rps: ft.rps.clone(),
        xps: ft.xps.clone(),
        bql: ft.bql.clone(),
        napi_defer_hard_irqs: ft.napi_defer_hard_irqs,
        gro_flush_timeout: ft.gro_flush_timeout,
        ntuple: ft.ntuple,
        flow_rules: ft.flow_rules.clone(),
        hw_rx_timestamping: ft.hwtstamp.rx,
        hw_tx_timestamping: ft.hwtstamp.tx,
        win_rx_timestamping: ft.win_timestamping.rx,
        win_tx_timestamping: ft.win_timestamping.tx,
        win_irq_affinity: ft.win_irq_affinity.clone(),
        rss: ft.rss,
    }
}

fn apply_settings(ft: &mut NicFt, s: InterfaceSettings) {
    ft.rings = s.rings;
    ft.coalesce = s.coalesce;
    ft.pause = s.pause;
    ft.channels = s.channels;
    ft.eee = s.eee;
    ft.threaded_napi = s.threaded_napi;
    ft.rps = s.rps;
    ft.xps = s.xps;
    ft.bql = s.bql;
    ft.napi_defer_hard_irqs = s.napi_defer_hard_irqs;
    ft.gro_flush_timeout = s.gro_flush_timeout;
    ft.ntuple = s.ntuple;
    ft.flow_rules = s.flow_rules;
    ft.hwtstamp.rx = s.hw_rx_timestamping;
    ft.hwtstamp.tx = s.hw_tx_timestamping;
    ft.win_timestamping.rx = s.win_rx_timestamping;
    ft.win_timestamping.tx = s.win_tx_timestamping;
    ft.win_irq_affinity = s.win_irq_affinity;
    ft.rss = s.rss;
}

fn nic_id(name: &str) -> io::Result<NicId> {
    crate::nic(name)
        .map(|n| n.id)
        .ok_or_else(|| no_interface(name))
}

/// The interface `nic` as fast-talker sees it: what the code under test
/// configured on it, its kernel objects, and what it reports.
pub fn interface(nic: &str) -> Option<InterfaceSnapshot> {
    let id = crate::nic(nic)?.id;
    super::nic::ensure(id);
    let now = Instant::now();
    let (mut snap, napis) = with_nic_rec(id, |n, os| {
        let snap = InterfaceSnapshot {
            name: n.spec.name.clone(),
            index: n.id.index(),
            link_up: n.spec.link_up && n.ft.flap_until.is_none_or(|until| now >= until),
            restart_until: n.ft.flap_until,
            settings: settings_of(&n.ft),
            driver: n.ft.driver.clone(),
            napis: Vec::new(),
            irqs: n.ft.irqs.clone(),
            qdiscs: super::nic::qdisc_tree(n),
            ptp: n.ft.ptp.map(|p| PtpSeed {
                clock: p.clock,
                offset_nanos: p.offset_nanos,
                uncertainty: p.uncertainty,
                tai: p.tai,
            }),
            driver_stats: super::nic::driver_stats_of(n, os),
            queue_stats: super::nic::queue_stats_of(n),
            apply_log: n.ft.apply_log.clone(),
        };
        (snap, n.ft.napis.clone())
    })?;
    let infos = crate::threads::all();
    let s = slot();
    let g = s.inner.lock();
    snap.napis = napis
        .iter()
        .enumerate()
        .map(|(q, r)| {
            let rt = r.thread.and_then(|t| g.rt.get(&t));
            NapiSnapshot {
                id: r.id,
                queue: q as u32,
                irq: r.irq,
                irq_affinity: r
                    .irq
                    .and_then(|i| g.irqs.get(&i))
                    .map(|i| i.affinity.clone()),
                thread: r.thread,
                thread_name: r
                    .thread
                    .and_then(|t| infos.iter().find(|i| i.tid == t))
                    .and_then(|i| i.name.clone()),
                thread_scheduler: rt.and_then(|rt| rt.scheduler),
                thread_affinity: rt.and_then(|rt| rt.affinity.clone()),
            }
        })
        .collect();
    Some(snap)
}

/// Every interface, in index order.
pub fn interfaces() -> Vec<InterfaceSnapshot> {
    crate::nics()
        .into_iter()
        .filter_map(|n| interface(&n.spec.name))
        .collect()
}

fn irq_snapshots(only: Option<u32>) -> Vec<IrqSnapshot> {
    super::nic::ensure_all();
    let names: BTreeMap<NicId, String> = crate::nics()
        .into_iter()
        .map(|n| (n.id, n.spec.name))
        .collect();
    let s = slot();
    let g = s.inner.lock();
    g.irqs
        .iter()
        .filter(|(n, _)| only.is_none_or(|o| o == **n))
        .map(|(&number, r)| IrqSnapshot {
            number,
            name: r.name.clone(),
            nic: r.nic.and_then(|id| names.get(&id).cloned()),
            affinity: r.affinity.clone(),
            effective_affinity: r.affinity.first().copied().into_iter().collect(),
            threads: r.threads.clone(),
            log: r.log.clone(),
        })
        .collect()
}

/// The interrupt numbered `n`.
pub fn irq(n: u32) -> Option<IrqSnapshot> {
    irq_snapshots(Some(n)).pop()
}

/// Every interrupt of the simulated host, in number order.
pub fn irqs() -> Vec<IrqSnapshot> {
    irq_snapshots(None)
}

/// Set driver counters of the interface `nic`, by name. They override the
/// ones derived from its [`NicCounters`](crate::NicCounters); names the
/// driver does not report are added after its own, which changes its
/// counter set.
pub fn set_driver_stats(nic: &str, stats: Vec<(String, u64)>) -> io::Result<()> {
    let id = nic_id(nic)?;
    with_nic_rec(id, |n, _| {
        for (name, v) in stats {
            match n.ft.driver_stats.iter_mut().find(|(s, _)| *s == name) {
                Some(slot) => slot.1 = v,
                None => n.ft.driver_stats.push((name, v)),
            }
        }
    })
    .ok_or_else(|| no_interface(nic))
}

/// Add `d` to the driver counter `name` of the interface `nic`, from the
/// value it reports now.
pub fn bump_driver_stat(nic: &str, name: &str, d: u64) -> io::Result<()> {
    let id = nic_id(nic)?;
    with_nic_rec(id, |n, os| {
        let now = super::nic::driver_stats_of(n, os)
            .into_iter()
            .find(|(s, _)| s == name)
            .map_or(0, |(_, v)| v);
        match n.ft.driver_stats.iter_mut().find(|(s, _)| s == name) {
            Some(slot) => slot.1 = now.wrapping_add(d),
            None => {
                n.ft.driver_stats
                    .push((name.to_string(), now.wrapping_add(d)))
            }
        }
    })
    .ok_or_else(|| no_interface(nic))
}

/// Change the per-queue statistics the interface `nic` reports, starting
/// from what it reports now. `f` runs under snare's state lock and must
/// not call into snare.
pub fn set_queue_stats(nic: &str, f: impl FnOnce(&mut Vec<QueueStatsRec>)) -> io::Result<()> {
    let id = nic_id(nic)?;
    with_nic_rec(id, |n, _| {
        let mut v = super::nic::queue_stats_of(n);
        f(&mut v);
        n.ft.queue_stats = Some(v);
    })
    .ok_or_else(|| no_interface(nic))
}

/// Add interrupt `n` named `name`, with an `irq/<n>-<name>` handler thread,
/// raised by the interface `nic` if given. An interrupt already numbered
/// `n` is replaced.
pub fn set_irq(n: u32, name: &str, nic: Option<&str>) -> io::Result<()> {
    let id = nic.map(nic_id).transpose()?;
    if let Some(id) = id {
        super::nic::ensure(id);
    }
    let tid = crate::threads::add_kernel_thread(&format!("irq/{n}-{name}"));
    let old = {
        let s = slot();
        let mut g = s.inner.lock();
        let affinity = g.irq_default_affinity.clone();
        g.rt.entry(tid).or_default().affinity = Some(affinity.clone());
        g.next_irq = g.next_irq.max(n + 1);
        g.irqs.insert(
            n,
            IrqRec {
                name: name.to_string(),
                nic: id,
                affinity,
                threads: vec![tid],
                log: Vec::new(),
            },
        )
    };
    if let Some(prev) = old.as_ref().and_then(|r| r.nic).filter(|&p| Some(p) != id) {
        with_nic_rec(prev, |rec, _| rec.ft.irqs.retain(|&i| i != n));
    }
    for t in old.into_iter().flat_map(|r| r.threads) {
        crate::threads::exit_kernel_thread(t);
    }
    if let Some(id) = id {
        with_nic_rec(id, |rec, _| {
            if !rec.ft.irqs.contains(&n) {
                rec.ft.irqs.push(n);
            }
        });
    }
    Ok(())
}

/// Change the interface `nic`'s settings behind the code under test's
/// back, as another tool or a driver reset would: nothing is logged, and a
/// read shows the change. A new `combined` channel count recreates its
/// interrupts and NAPIs. `f` runs under snare's state lock and must not
/// call into snare.
pub fn mutate_interface(nic: &str, f: impl FnOnce(&mut InterfaceSettings)) -> io::Result<()> {
    let id = nic_id(nic)?;
    super::nic::ensure(id);
    let retired = with_nic_rec(id, |n, _| {
        let mut s = settings_of(&n.ft);
        f(&mut s);
        let rebuild = s.channels.combined != n.ft.channels.combined;
        apply_settings(&mut n.ft, s);
        rebuild.then(|| super::nic::kernel_retire(n))
    })
    .ok_or_else(|| no_interface(nic))?;
    match retired {
        Some(r) => super::nic::rebuild(id, r),
        None => super::nic::sync_napi_threads(id),
    }
    Ok(())
}
