//! A simulated host behind [`snare_interpose::Host`], [`snare_interpose::Fs`] and
//! [`snare_interpose::Net`]. It answers the scheduling, CPU-topology, NIC and socket-tuning calls a
//! real-time program (such as `fast-talker`) makes — against a test-configurable profile — without
//! ever touching the real scheduler or NIC.
//!
//! The OS *personality* (which symbols exist, errno values, path layout) is fixed by `cfg!` at
//! compile time. What a test configures here are host *facts*: CPU count, isolated/nohz CPUs,
//! governor, granted capabilities, rlimits, and (later) NIC and IRQ profiles. Reading them back
//! from `/sys`, `/proc` and `ethtool` is what the code under test does; serving them is this type.

use std::collections::HashMap;
use std::ffi::{c_char, c_int};
use std::path::Path;
use std::sync::{Arc, Mutex};

use snare_interpose::NetResult as HostResult;
use snare_interpose::{Env, Fs, Host, Layer, Net, NetResult, NetResult as FsResult};

use crate::fs_sim::{err, fill_stat, ino_of, ok, path_of};
#[cfg(target_os = "linux")]
use crate::fs_sim::{DirEntry, DirStream, fill_statx};

use crate::clock::{Clock, ClockLayer};

/// Capability numbers (`<linux/capability.h>`) the setters gate on. Exposed so tests can grant
/// them by name.
pub const CAP_NET_ADMIN: c_int = 12;
pub const CAP_IPC_LOCK: c_int = 14;
pub const CAP_SYS_NICE: c_int = 23;

/// Interface statistics reported through rtnetlink `IFLA_STATS64` (a subset of the kernel's
/// `rtnl_link_stats64`). Build with `LinkStats { rx_packets: .., ..Default::default() }`.
#[derive(Clone, Copy, Default)]
pub struct LinkStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

/// A simulated network interface. Attach it to a [`HostProfile`] with [`HostProfile::nic`]; the
/// code under test then resolves it by name (`if_nametoindex`) and queries it over `ethtool`.
pub struct Nic {
    name: String,
    ifindex: u32,
    mtu: i32,
    driver: String,
    driver_version: String,
    bus_info: String,
    hwtstamp_supported: bool,
    operstate: String,
    subsystem: String,
    address: Option<std::net::IpAddr>,
    rx_queues: usize,
    tx_queues: usize,
    msi_irqs: Vec<u32>,
    link_stats: LinkStats,
    ptp_index: Option<u32>,
}

impl Nic {
    /// A new interface with the given name and index (both must be unique on the host).
    pub fn new(name: impl Into<String>, ifindex: u32) -> Self {
        Nic {
            name: name.into(),
            ifindex,
            mtu: 1500,
            driver: "sim".to_string(),
            driver_version: "0".to_string(),
            bus_info: String::new(),
            hwtstamp_supported: false,
            operstate: "up".to_string(),
            subsystem: "pci".to_string(),
            address: None,
            rx_queues: 1,
            tx_queues: 1,
            msi_irqs: Vec::new(),
            link_stats: LinkStats::default(),
            ptp_index: None,
        }
    }

    /// The PTP hardware clock index this NIC's PHC is exposed at — i.e. `ETHTOOL_GET_TS_INFO`'s
    /// `phc_index`, backing an open of `/dev/ptp<N>`.
    pub fn ptp_index(mut self, index: u32) -> Self {
        self.ptp_index = Some(index);
        self
    }

    /// The interface statistics reported through rtnetlink `RTM_GETLINK` / `IFLA_STATS64`.
    pub fn link_stats(mut self, stats: LinkStats) -> Self {
        self.link_stats = stats;
        self
    }

    /// The number of RX and TX queues (listed under `/sys/class/net/<name>/queues` as `rx-N`/`tx-N`).
    pub fn queues(mut self, rx: usize, tx: usize) -> Self {
        self.rx_queues = rx;
        self.tx_queues = tx;
        self
    }

    /// The MSI IRQ numbers listed under `/sys/class/net/<name>/device/msi_irqs`.
    pub fn msi_irqs<I: IntoIterator<Item = u32>>(mut self, irqs: I) -> Self {
        self.msi_irqs = irqs.into_iter().collect();
        self
    }

    /// The IP address reported for this interface by `getifaddrs` (fast-talker's
    /// `Nic::with_address` and hardware-timestamp auto-selection look it up here).
    pub fn address(mut self, ip: impl Into<std::net::IpAddr>) -> Self {
        self.address = Some(ip.into());
        self
    }

    pub fn mtu(mut self, mtu: i32) -> Self {
        self.mtu = mtu;
        self
    }

    /// The link state reported at `/sys/class/net/<name>/operstate` (e.g. `"up"`, `"down"`).
    pub fn operstate(mut self, state: impl Into<String>) -> Self {
        self.operstate = state.into();
        self
    }

    /// The bus the `device/subsystem` symlink points at (e.g. `"pci"`, `"virtio"`). fast-talker
    /// reads this to detect a virtio NIC.
    pub fn subsystem(mut self, bus: impl Into<String>) -> Self {
        self.subsystem = bus.into();
        self
    }

    /// The `ethtool` driver name and version (`ETHTOOL_GDRVINFO`).
    pub fn driver(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.driver = name.into();
        self.driver_version = version.into();
        self
    }

    /// The PCI/USB bus address reported in `ethtool` drvinfo.
    pub fn bus_info(mut self, bus: impl Into<String>) -> Self {
        self.bus_info = bus.into();
        self
    }

    /// Whether the NIC advertises hardware timestamping (so `SIOCSHWTSTAMP` is accepted).
    pub fn hardware_timestamping(mut self, on: bool) -> Self {
        self.hwtstamp_supported = on;
        self
    }
}

struct NicState {
    ifindex: u32,
    // Everything below is read only through the Linux NIC ioctls.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    mtu: i32,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    driver: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    driver_version: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    bus_info: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    hwtstamp_supported: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    hwtstamp_tx: i32,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    hwtstamp_rx: i32,
    operstate: String,
    subsystem: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    address: Option<std::net::IpAddr>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    rx_queues: usize,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    tx_queues: usize,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    msi_irqs: Vec<u32>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    link_stats: LinkStats,
}

/// A test-configurable description of the simulated host. Build one, then attach it to a
/// [`Sim`](crate::Sim) with [`SimBuilder::host`](crate::SimBuilder::host).
pub struct HostProfile {
    cpu_count: usize,
    online: Option<Vec<usize>>,
    isolated: Vec<usize>,
    nohz_full: Vec<usize>,
    governor: String,
    preempt_rt: bool,
    caps: u64,
    nics: Vec<Nic>,
    default_qdisc: String,
    tai_offset_secs: u64,
    /// PTP hardware clocks exposed as `/dev/ptp<N>`, mapping the clock index to the nanosecond
    /// offset its PHC leads `CLOCK_REALTIME` by (0 = tracks realtime exactly).
    ptp_clocks: std::collections::BTreeMap<u32, i64>,
    /// ETF root-qdisc parameters `(delta, clockid, flags)` reported through rtnetlink
    /// `RTM_GETQDISC`; `Some` also makes the reported root-qdisc kind `"etf"`.
    etf: Option<(i32, i32, u32)>,
    /// When set, the process environment is isolated: `getenv`/`setenv`/`unsetenv` are served from
    /// `env` alone, and the real environment is invisible to the code under test.
    isolate_env: bool,
    env: Vec<(String, String)>,
}

impl Default for HostProfile {
    fn default() -> Self {
        Self::new()
    }
}

impl HostProfile {
    /// A single-CPU, non-real-time host with no isolated CPUs and no elevated capabilities.
    pub fn new() -> Self {
        HostProfile {
            cpu_count: 1,
            online: None,
            isolated: Vec::new(),
            nohz_full: Vec::new(),
            governor: "powersave".to_string(),
            preempt_rt: false,
            caps: 0,
            nics: Vec::new(),
            default_qdisc: "fq_codel".to_string(),
            tai_offset_secs: 37,
            ptp_clocks: std::collections::BTreeMap::new(),
            etf: None,
            isolate_env: false,
            env: Vec::new(),
        }
    }

    /// Report an `etf` root qdisc through rtnetlink `RTM_GETQDISC`, carrying the given `TCA_ETF_PARMS`
    /// (`delta` ns, `clockid`, `flags`). Sets the reported root-qdisc kind to `"etf"`.
    pub fn etf_qdisc(mut self, delta: i32, clockid: i32, flags: u32) -> Self {
        self.default_qdisc = "etf".to_string();
        self.etf = Some((delta, clockid, flags));
        self
    }

    /// The TAI–UTC offset in seconds that `CLOCK_TAI` leads `CLOCK_REALTIME` by (37 today).
    pub fn tai_offset(mut self, secs: u64) -> Self {
        self.tai_offset_secs = secs;
        self
    }

    /// Set an environment variable the code under test reads with `std::env::var`/`getenv`. Using
    /// this isolates the environment: the code sees only the variables set here, not the real
    /// process environment. Tester code can still reach the real environment via
    /// [`snare::real_env`](crate::real_env).
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.isolate_env = true;
        self.env.push((key.into(), value.into()));
        self
    }

    /// Isolate the environment with no variables set — every `std::env::var` the code under test
    /// makes returns `None`. Equivalent to [`env`](Self::env) but starting empty.
    pub fn isolate_env(mut self) -> Self {
        self.isolate_env = true;
        self
    }

    /// Expose a PTP hardware clock at `/dev/ptp<index>` whose PHC tracks `CLOCK_REALTIME` exactly.
    pub fn ptp_clock(mut self, index: u32) -> Self {
        self.ptp_clocks.entry(index).or_insert(0);
        self
    }

    /// Expose a PTP hardware clock at `/dev/ptp<index>` whose PHC leads `CLOCK_REALTIME` by
    /// `offset_nanos` (may be negative), so a consumer reads a deterministic non-zero PHC offset.
    pub fn ptp_clock_offset(mut self, index: u32, offset_nanos: i64) -> Self {
        self.ptp_clocks.insert(index, offset_nanos);
        self
    }

    /// Attach a simulated [`Nic`].
    pub fn nic(mut self, nic: Nic) -> Self {
        self.nics.push(nic);
        self
    }

    /// The value at `/proc/sys/net/core/default_qdisc`.
    pub fn default_qdisc(mut self, qdisc: impl Into<String>) -> Self {
        self.default_qdisc = qdisc.into();
        self
    }

    /// Number of logical CPUs (`/sys/devices/system/cpu/online` spans `0..count`).
    pub fn cpus(mut self, count: usize) -> Self {
        self.cpu_count = count.max(1);
        self
    }

    /// Override the online CPU set (defaults to every CPU in `0..cpus`).
    pub fn online<I: IntoIterator<Item = usize>>(mut self, cpus: I) -> Self {
        self.online = Some(cpus.into_iter().collect());
        self
    }

    /// CPUs carved out with `isolcpus=` (`/sys/devices/system/cpu/isolated`).
    pub fn isolated<I: IntoIterator<Item = usize>>(mut self, cpus: I) -> Self {
        self.isolated = cpus.into_iter().collect();
        self
    }

    /// CPUs in `nohz_full=` (`/sys/devices/system/cpu/nohz_full`).
    pub fn nohz_full<I: IntoIterator<Item = usize>>(mut self, cpus: I) -> Self {
        self.nohz_full = cpus.into_iter().collect();
        self
    }

    /// The `scaling_governor` reported for every CPU.
    pub fn governor(mut self, governor: impl Into<String>) -> Self {
        self.governor = governor.into();
        self
    }

    /// Whether the kernel reports `PREEMPT_RT` (`/sys/kernel/realtime` is `1`).
    pub fn preempt_rt(mut self, on: bool) -> Self {
        self.preempt_rt = on;
        self
    }

    /// Grant a capability (see [`CAP_SYS_NICE`] and friends). Setters gated on a capability the
    /// host lacks fail with `EPERM`, exactly as the kernel would.
    pub fn cap(mut self, cap: c_int) -> Self {
        if (0..64).contains(&cap) {
            self.caps |= 1u64 << cap;
        }
        self
    }

    /// Finalize into a [`SimHost`] ready to attach to a [`Sim`](crate::Sim).
    pub fn build(self) -> Arc<SimHost> {
        Arc::new(SimHost::new(self))
    }
}

/// A fully-featured interface: up, hardware timestamping, an `igb`-style driver and the given
/// address — what most tests want without spelling out every field.
fn rich_nic(name: &str, ifindex: u32, ip: std::net::IpAddr) -> Nic {
    Nic::new(name, ifindex)
        .mtu(1500)
        .driver("igb", "5.6.0")
        .bus_info(format!("0000:{ifindex:02x}:00.0"))
        .hardware_timestamping(true)
        .operstate("up")
        .address(ip)
}

/// A batteries-included [`HostProfile`] builder. Start from a preset that matches the kind of
/// machine your code expects, tweak if needed, then [`build`](EasyBuilder::build). Every preset
/// ships a working NIC, so `if_nametoindex`, `ethtool`, `getifaddrs` and the `/sys/class/net`
/// reads all succeed out of the box.
///
/// ```no_run
/// use snare::{EasyBuilder, Sim};
/// let host = EasyBuilder::realtime().build(); // privileged 8-CPU PREEMPT_RT host + hw-ts NIC
/// Sim::builder().host(host).build().run(|| {
///     // scheduling, mlock, hardware-timestamp configuration all succeed here
/// });
/// ```
pub struct EasyBuilder {
    profile: HostProfile,
}

impl Default for EasyBuilder {
    fn default() -> Self {
        Self::realtime()
    }
}

impl EasyBuilder {
    /// The default preset: a privileged 8-CPU real-time host — `performance` governor, `PREEMPT_RT`,
    /// CPUs 2–7 isolated and `nohz_full`, `CAP_SYS_NICE` + `CAP_IPC_LOCK` + `CAP_NET_ADMIN`, the `fq`
    /// qdisc, and a hardware-timestamping NIC `eth0` at 10.0.0.10. Suits most fast-talker real-time
    /// and timestamping tests: every tuning call the code makes succeeds.
    pub fn realtime() -> Self {
        let profile = HostProfile::new()
            .cpus(8)
            .isolated(2..8)
            .nohz_full(2..8)
            .governor("performance")
            .preempt_rt(true)
            .default_qdisc("fq")
            .cap(CAP_SYS_NICE)
            .cap(CAP_IPC_LOCK)
            .cap(CAP_NET_ADMIN)
            .nic(rich_nic("eth0", 2, std::net::Ipv4Addr::new(10, 0, 0, 10).into()));
        EasyBuilder { profile }
    }

    /// A large privileged server: 16 CPUs, `performance` governor, CPUs 4–15 isolated, all tuning
    /// capabilities, a 9000-MTU hardware-timestamping NIC `eth0` at 10.0.0.20. Not a real-time
    /// kernel (`preempt_rt` off), which is typical of production servers.
    pub fn server() -> Self {
        let profile = HostProfile::new()
            .cpus(16)
            .isolated(4..16)
            .governor("performance")
            .default_qdisc("fq")
            .cap(CAP_SYS_NICE)
            .cap(CAP_IPC_LOCK)
            .cap(CAP_NET_ADMIN)
            .nic(rich_nic("eth0", 2, std::net::Ipv4Addr::new(10, 0, 0, 20).into()).mtu(9000));
        EasyBuilder { profile }
    }

    /// A developer laptop: 4 CPUs, `powersave` governor, no real-time kernel, and — crucially — no
    /// elevated capabilities, so real-time scheduling, `mlockall` and hardware timestamping fail
    /// with `EPERM` just as they would for an unprivileged user. Its NIC `wlan0` (192.168.1.50)
    /// has no hardware timestamping. Use it to test the graceful-degradation paths.
    pub fn laptop() -> Self {
        let profile = HostProfile::new()
            .cpus(4)
            .governor("powersave")
            .default_qdisc("fq_codel")
            .nic(
                Nic::new("wlan0", 2)
                    .driver("iwlwifi", "1")
                    .operstate("up")
                    .address(std::net::Ipv4Addr::new(192, 168, 1, 50)),
            );
        EasyBuilder { profile }
    }

    /// The [`realtime`](Self::realtime) host with every capability revoked — the same hardware, but
    /// the process cannot actually apply the tuning. For asserting that a program reports or
    /// tolerates `EPERM` from scheduling / `mlockall` / `SIOCSHWTSTAMP`.
    pub fn unprivileged() -> Self {
        let mut easy = Self::realtime();
        easy.profile.caps = 0;
        easy
    }

    /// A bare single-CPU host with no capabilities, no NIC and no real-time features — a blank
    /// slate to build on with [`add_nic`](Self::add_nic) and the tweak methods.
    pub fn minimal() -> Self {
        EasyBuilder {
            profile: HostProfile::new(),
        }
    }

    /// Set the CPU count (online CPUs follow).
    pub fn cpus(mut self, n: usize) -> Self {
        self.profile = self.profile.cpus(n);
        self
    }

    /// Replace the isolated-CPU set.
    pub fn isolate<I: IntoIterator<Item = usize>>(mut self, cpus: I) -> Self {
        self.profile = self.profile.isolated(cpus);
        self
    }

    /// Set the `scaling_governor` reported for every CPU.
    pub fn governor(mut self, governor: impl Into<String>) -> Self {
        self.profile = self.profile.governor(governor);
        self
    }

    /// Grant all tuning capabilities (`true`) or revoke them (`false`).
    pub fn privileged(mut self, on: bool) -> Self {
        self.profile.caps = 0;
        if on {
            self.profile = self
                .profile
                .cap(CAP_SYS_NICE)
                .cap(CAP_IPC_LOCK)
                .cap(CAP_NET_ADMIN);
        }
        self
    }

    /// Whether the kernel reports `PREEMPT_RT`.
    pub fn realtime_kernel(mut self, on: bool) -> Self {
        self.profile = self.profile.preempt_rt(on);
        self
    }

    /// Add a fully specified [`Nic`] (e.g. a custom driver or no timestamping).
    pub fn add_nic(mut self, nic: Nic) -> Self {
        self.profile = self.profile.nic(nic);
        self
    }

    /// Add a ready-to-use hardware-timestamping interface with the given name, index and address.
    pub fn nic(self, name: &str, ifindex: u32, ip: impl Into<std::net::IpAddr>) -> Self {
        self.add_nic(rich_nic(name, ifindex, ip.into()))
    }

    /// Drop all interfaces added so far (including a preset's default NIC).
    pub fn without_nics(mut self) -> Self {
        self.profile.nics.clear();
        self
    }

    /// Drop to the underlying [`HostProfile`] for full control.
    pub fn profile(self) -> HostProfile {
        self.profile
    }

    /// Finalize into a [`SimHost`].
    pub fn build(self) -> Arc<SimHost> {
        self.profile.build()
    }
}

struct OpenFile {
    data: Vec<u8>,
    cursor: usize,
    writable: bool,
    path: std::path::PathBuf,
}

/// Per-(virtual)-thread scheduling state. `policy`/`rt_priority` are the `sched_setscheduler`
/// view; `nice` the `setpriority` view; `affinity` the CPU mask (empty means "every online CPU").
/// Fields default to `SCHED_OTHER` (policy 0), priority 0, nice 0, and an empty affinity mask
/// (meaning "every online CPU").
#[derive(Clone, Default)]
struct ThreadState {
    policy: c_int,
    rt_priority: c_int,
    nice: c_int,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    affinity: Vec<usize>,
}

const TID_BASE: i32 = 4000;

/// A datagram queued for delivery, with the virtual-clock timestamp stamped when it was sent.
#[cfg(target_os = "linux")]
struct Datagram {
    data: Vec<u8>,
    src: std::net::SocketAddr,
    timestamp: std::time::Duration,
    /// Still in flight until then (link latency); `None` arrived on sending.
    arrives: Option<crate::readiness::Deadline>,
}

#[cfg(target_os = "linux")]
impl Datagram {
    fn arrived(&self) -> bool {
        self.arrives.is_none_or(|d| d.passed())
    }
}

/// Takes the earliest-arrived datagram from `queue` whose source passes `accept`: one that
/// overtook another in flight is read first; ones that arrived on sending keep their order.
#[cfg(target_os = "linux")]
fn take_arrived(
    queue: &mut std::collections::VecDeque<Datagram>,
    accept: impl Fn(std::net::SocketAddr) -> bool,
) -> Option<Datagram> {
    let idx = queue
        .iter()
        .enumerate()
        .filter(|(_, dg)| accept(dg.src) && dg.arrived())
        .min_by_key(|(i, dg)| (dg.arrives.map(|d| d.instant()), *i))?
        .0;
    queue.remove(idx)
}

/// A datagram for a receive queue that becomes receivable `delay` from now, its timestamp the
/// arrival time.
#[cfg(target_os = "linux")]
fn in_flight(
    data: Vec<u8>,
    src: std::net::SocketAddr,
    sent: std::time::Duration,
    delay: std::time::Duration,
) -> Datagram {
    let arrives = (!delay.is_zero()).then(|| crate::readiness::Deadline::after(delay));
    if let Some(arrives) = arrives {
        arrives.wake_waiters_then();
    }
    Datagram {
        data,
        src,
        timestamp: sent + delay,
        arrives,
    }
}

/// A simulated `SOCK_DGRAM` socket: its bound address, receive and error queues, recorded socket
/// options, and whether `SO_TIMESTAMPING` software stamping is enabled.
#[cfg(target_os = "linux")]
struct UdpSocket {
    domain: c_int,
    local: Option<std::net::SocketAddr>,
    /// The connected peer, set by `connect` (man 2 connect): it fixes the default `send`
    /// destination and filters received datagrams to that source.
    peer: Option<std::net::SocketAddr>,
    rx: std::collections::VecDeque<Datagram>,
    errq: std::collections::VecDeque<Datagram>,
    nonblocking: bool,
    /// SO_BROADCAST (man 7 socket): broadcasting to `255.255.255.255` is refused without it.
    broadcast: bool,
    /// Multicast groups joined via `IP_ADD_MEMBERSHIP`/`IPV6_JOIN_GROUP` (man 7 ip / ipv6).
    groups: Vec<std::net::IpAddr>,
    timestamping: u32,
    sockopts: HashMap<(c_int, c_int), Vec<u8>>,
    /// The transmit deadline (nanoseconds, in the `SO_TXTIME` clock) carried by the most recent
    /// `sendmsg` `SCM_TXTIME` control message — what an ETF-paced sender asked to send this at.
    tx_deadline: Option<u64>,
}

// SO_TIMESTAMPING / SCM_TIMESTAMPING, the SOF_TIMESTAMPING_* flag bits and SO_TXTIME / SCM_TXTIME
// are defined in <linux/net_tstamp.h> and documented in Documentation/networking/timestamping.rst;
// SO_TXTIME pacing is also covered by man 8 tc-etf.
#[cfg(target_os = "linux")]
const SO_TIMESTAMPING: c_int = 37;
/// `SCM_TXTIME` == `SO_TXTIME` (61): the per-packet transmit-deadline control message.
#[cfg(target_os = "linux")]
const SCM_TXTIME: c_int = 61;
#[cfg(target_os = "linux")]
const SOF_TIMESTAMPING_SOFTWARE: u32 = 1 << 4;
#[cfg(target_os = "linux")]
const SCM_TIMESTAMPING: c_int = SO_TIMESTAMPING;

/// `PRIO_PROCESS` is `c_int` on macOS but `c_uint` on Linux; normalise once.
#[allow(clippy::unnecessary_cast)]
const PRIO_PROCESS: c_int = libc::PRIO_PROCESS as c_int;

pub(crate) struct HostState {
    cpu_count: usize,
    online: Vec<usize>,
    isolated: Vec<usize>,
    nohz_full: Vec<usize>,
    governor: String,
    preempt_rt: bool,
    caps: u64,
    /// The latency cap currently requested through `/dev/cpu_dma_latency`, in microseconds, if the
    /// guard fd is held open.
    cpu_dma_latency: Option<i32>,
    open: HashMap<c_int, OpenFile>,
    #[cfg(target_os = "linux")]
    dirs: HashMap<c_int, DirStream>,
    threads: std::collections::BTreeMap<i32, ThreadState>,
    thread_ids: HashMap<std::thread::ThreadId, i32>,
    next_tid: i32,
    mem_locked: bool,
    nics: HashMap<String, NicState>,
    default_qdisc: String,
    #[cfg(target_os = "linux")]
    ptp_clocks: std::collections::BTreeMap<u32, i64>,
    #[cfg(target_os = "linux")]
    etf: Option<(i32, i32, u32)>,
    /// macOS thread scheduling, keyed by `pthread_t`: (policy, priority).
    #[cfg(target_os = "macos")]
    mac_threads: HashMap<u64, (c_int, c_int)>,
    #[cfg(target_os = "linux")]
    udp: HashMap<c_int, UdpSocket>,
    #[cfg(target_os = "linux")]
    netlinks: HashMap<c_int, std::collections::VecDeque<Vec<u8>>>,
    /// Bound datagram sockets keyed by full address, so several IPs can share a port (snare 1.x's
    /// `add_ip_addr`) and a wildcard `0.0.0.0`/`::` bind coexists with specific ones.
    #[cfg(target_os = "linux")]
    bound: HashMap<std::net::SocketAddr, c_int>,
    #[cfg(target_os = "linux")]
    next_ephemeral: u16,
    env: HashMap<std::ffi::CString, std::ffi::CString>,
}

impl HostState {
    fn render(&self, path: &Path) -> Option<Vec<u8>> {
        let p = path.to_str()?;
        // CPU-list sysfs files, rendered in the comma/range cpumask syntax the kernel uses.
        // Documentation/ABI/testing/sysfs-devices-system-cpu; the isolated/nohz_full sets come from
        // the isolcpus= / nohz_full= boot args in Documentation/admin-guide/kernel-parameters.txt.
        let text = match p {
            "/sys/devices/system/cpu/online" => format_cpu_list(&self.online),
            "/sys/devices/system/cpu/isolated" => format_cpu_list(&self.isolated),
            "/sys/devices/system/cpu/nohz_full" => {
                if self.nohz_full.is_empty() {
                    String::new()
                } else {
                    format_cpu_list(&self.nohz_full)
                }
            }
            // PREEMPT_RT exports /sys/kernel/realtime = 1 (kernel/ksysfs.c under CONFIG_PREEMPT_RT).
            "/sys/kernel/realtime" => {
                if self.preempt_rt {
                    "1".to_string()
                } else {
                    return None;
                }
            }
            _ => return self.render_dynamic(p),
        };
        Some(with_newline(text))
    }

    fn render_dynamic(&self, p: &str) -> Option<Vec<u8>> {
        if p == "/proc/sys/net/core/default_qdisc" {
            return Some(with_newline(self.default_qdisc.clone()));
        }
        if let Some(rest) = p.strip_prefix("/sys/class/net/")
            && let Some((name, attr)) = rest.split_once('/')
        {
            let nic = self.nics.get(name)?;
            // Documentation/ABI/testing/sysfs-class-net (mtu, ifindex, operstate; carrier tracks
            // operstate == "up").
            let text = match attr {
                "mtu" => nic.mtu.to_string(),
                "ifindex" => nic.ifindex.to_string(),
                "operstate" => nic.operstate.clone(),
                "carrier" => {
                    if nic.operstate == "up" { "1".to_string() } else { "0".to_string() }
                }
                _ => return None,
            };
            return Some(with_newline(text));
        }
        if let Some(rest) = p.strip_prefix("/sys/devices/system/cpu/cpu")
            && let Some((n, tail)) = rest.split_once('/')
        {
            let cpu: usize = n.parse().ok()?;
            if cpu >= self.cpu_count {
                return None;
            }
            // Documentation/admin-guide/pm/cpufreq.rst (per-policy cpufreq sysfs attributes).
            if tail == "cpufreq/scaling_governor" {
                return Some(with_newline(self.governor.clone()));
            }
            if tail == "online" {
                let v = if self.online.contains(&cpu) { "1" } else { "0" };
                return Some(with_newline(v.to_string()));
            }
        }
        None
    }

    fn known_file(&self, path: &Path) -> bool {
        self.render(path).is_some() || path == Path::new("/dev/cpu_dma_latency")
    }

    /// The directory listing for a synthetic `/sys/class/net/<if>/{queues,device/msi_irqs}` path,
    /// or `None` if the path is not a modelled directory. See
    /// Documentation/ABI/testing/sysfs-class-net-queues (rx-N/tx-N) and, for `device/msi_irqs`,
    /// Documentation/ABI/testing/sysfs-pci-devices.
    #[cfg(target_os = "linux")]
    fn dir_entries(&self, path: &Path) -> Option<Vec<DirEntry>> {
        fn entry(name: &str) -> DirEntry {
            DirEntry {
                name: name.as_bytes().to_vec(),
                ino: 1,
                dtype: libc::DT_DIR,
            }
        }
        let rest = path.to_str()?.strip_prefix("/sys/class/net/")?.to_string();
        let mut entries = vec![entry("."), entry("..")];
        if let Some(name) = rest.strip_suffix("/queues") {
            let nic = self.nics.get(name)?;
            for i in 0..nic.rx_queues {
                entries.push(entry(&format!("rx-{i}")));
            }
            for i in 0..nic.tx_queues {
                entries.push(entry(&format!("tx-{i}")));
            }
            Some(entries)
        } else if let Some(name) = rest.strip_suffix("/device/msi_irqs") {
            let nic = self.nics.get(name)?;
            for irq in &nic.msi_irqs {
                entries.push(entry(&irq.to_string()));
            }
            Some(entries)
        } else {
            None
        }
    }

    /// Whether `path` falls in a subtree this host fully models. A path here that `render` does not
    /// produce is reported as `ENOENT` rather than leaking to the real `/sys` or `/proc`.
    fn owns_path(&self, path: &Path) -> bool {
        const PREFIXES: &[&str] = &[
            "/sys/devices/system/cpu",
            "/sys/kernel",
            "/sys/class/net",
            "/proc/sys/net",
        ];
        let Some(p) = path.to_str() else {
            return false;
        };
        PREFIXES.iter().any(|pre| p == *pre || p.starts_with(&format!("{pre}/")))
    }

    /// The calling OS thread's simulated tid, minted on first use.
    fn current_tid(&mut self) -> i32 {
        let id = std::thread::current().id();
        if let Some(&tid) = self.thread_ids.get(&id) {
            return tid;
        }
        let tid = self.next_tid;
        self.next_tid += 1;
        self.thread_ids.insert(id, tid);
        self.threads.entry(tid).or_default();
        tid
    }

    /// Resolve a scheduling `pid` argument (`0` = the caller) to a tid with a state entry.
    fn resolve(&mut self, pid: i32) -> i32 {
        let tid = if pid == 0 { self.current_tid() } else { pid };
        self.threads.entry(tid).or_default();
        tid
    }

    fn has_cap(&self, cap: c_int) -> bool {
        (0..64).contains(&cap) && self.caps & (1u64 << cap) != 0
    }

    /// Build the reply to a netlink request. `RTM_GETLINK` yields a link dump, `RTM_GETQDISC` the
    /// root qdisc, `GENL_ID_CTRL` a genetlink family lookup; any other type yields a bare
    /// `NLMSG_DONE` (harmless for the requests this models). Protocol: man 7 netlink / man 7
    /// rtnetlink; message and attribute types in `<linux/rtnetlink.h>`.
    #[cfg(target_os = "linux")]
    fn netlink_reply(&self, req: &[u8]) -> Vec<u8> {
        const RTM_GETLINK: u16 = 18;
        const RTM_GETQDISC: u16 = 38;
        const GENL_ID_CTRL: u16 = 16;
        let (ty, seq) = if req.len() >= 12 {
            (
                u16::from_ne_bytes([req[4], req[5]]),
                u32::from_ne_bytes([req[8], req[9], req[10], req[11]]),
            )
        } else {
            (0, 0)
        };
        let mut nics: Vec<(&String, &NicState)> = self.nics.iter().collect();
        nics.sort_by(|a, b| a.0.cmp(b.0));
        match ty {
            RTM_GETLINK => build_getlink_dump(&nics, seq),
            RTM_GETQDISC => {
                let ifindex = nics.first().map(|(_, n)| n.ifindex as i32).unwrap_or(0);
                build_getqdisc_dump(&self.default_qdisc, self.etf, ifindex, seq)
            }
            GENL_ID_CTRL => build_genl_ctrl_reply(req, seq),
            _ => build_getlink_dump(&[], seq),
        }
    }

    /// Pick a free ephemeral port (49152..=65535), or `None` if the whole range is bound.
    #[cfg(target_os = "linux")]
    fn alloc_ephemeral(&mut self, ip: std::net::IpAddr) -> Option<u16> {
        for _ in 49152..=65535u32 {
            let p = self.next_ephemeral;
            self.next_ephemeral = if p == u16::MAX { 49152 } else { p + 1 };
            if !self.bound.contains_key(&std::net::SocketAddr::new(ip, p)) {
                return Some(p);
            }
        }
        None
    }

    /// The datagram sockets a message to `dest` should reach: the exact unicast bind plus any
    /// wildcard bind on the port, every socket on the port for a broadcast, or every socket that
    /// joined the group for a multicast. Mirrors the fabric's `UdpRegistry::recipients`.
    #[cfg(target_os = "linux")]
    fn udp_recipients(&self, dest: std::net::SocketAddr) -> Vec<c_int> {
        let port = dest.port();
        let on_port = |s: &UdpSocket| s.local.is_some_and(|l| l.port() == port);
        if udp_is_broadcast(dest.ip()) {
            return self
                .udp
                .iter()
                .filter(|(_, s)| on_port(s))
                .map(|(fd, _)| *fd)
                .collect();
        }
        if dest.ip().is_multicast() {
            return self
                .udp
                .iter()
                .filter(|(_, s)| on_port(s) && s.groups.contains(&dest.ip()))
                .map(|(fd, _)| *fd)
                .collect();
        }
        self.udp
            .iter()
            .filter(|(_, s)| {
                s.local
                    .is_some_and(|l| l == dest || (l.ip().is_unspecified() && l.port() == port))
            })
            .map(|(fd, _)| *fd)
            .collect()
    }

    /// Delivers one datagram from `fd` to `dest`, stamping it with `now` from the virtual clock.
    /// Resolves (lazily assigning) the sender's local address, fans out to every recipient, and
    /// records a TX-timestamp completion on the error queue when SO_TIMESTAMPING asked for one.
    #[cfg(target_os = "linux")]
    fn udp_deliver(
        &mut self,
        fd: c_int,
        data: Vec<u8>,
        dest: std::net::SocketAddr,
        now: std::time::Duration,
        policies: Option<&crate::netpolicy::Policies>,
    ) -> Option<NetResult> {
        let src = match self.udp[&fd].local {
            Some(sa) => sa,
            None => {
                let ip = udp_loopback_for(self.udp[&fd].domain);
                let p = self.alloc_ephemeral(ip).unwrap_or(0);
                let sa = std::net::SocketAddr::new(ip, p);
                if p != 0 {
                    self.bound.insert(sa, fd);
                }
                self.udp.get_mut(&fd).unwrap().local = Some(sa);
                sa
            }
        };
        // man 7 socket: broadcasting to 255.255.255.255 needs SO_BROADCAST, else EACCES.
        if udp_is_broadcast(dest.ip()) && !self.udp[&fd].broadcast {
            return err(libc::EACCES);
        }
        let tx_flags = self.udp[&fd].timestamping;
        let len = data.len();
        for rfd in self.udp_recipients(dest) {
            if let Some(s) = self.udp.get_mut(&rfd) {
                let delays = match (&policies, s.local) {
                    (Some(p), Some(at)) => p.deliveries(at, len),
                    _ => vec![std::time::Duration::ZERO],
                };
                for delay in delays {
                    s.rx.push_back(in_flight(data.clone(), src, now, delay));
                }
            }
        }
        if tx_flags & SOF_TIMESTAMPING_TX_SOFTWARE != 0 {
            self.udp.get_mut(&fd).unwrap().errq.push_back(Datagram {
                data: Vec::new(),
                src,
                timestamp: now,
                arrives: None,
            });
        }
        ok(len as i64)
    }
}

/// A simulated host serving `fast-talker`'s tuning calls from an in-memory [`HostProfile`].
pub struct SimHost {
    state: Mutex<HostState>,
    devnull: c_int,
    clock: Arc<Clock>,
    isolate_env: bool,
    /// The registries of the `Sim` this host serves, so its datagram sockets and that sim's
    /// tester endpoints reach each other.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    registries: Mutex<Option<Arc<crate::fabric::Registries>>>,
}

impl SimHost {
    /// Joins this host's datagram sockets to the tester endpoints of the `Sim` it serves, both
    /// ways: what its sockets send reaches the testers, and what testers send reaches its sockets.
    pub(crate) fn attach_fabric(self: &Arc<Self>, regs: Arc<crate::fabric::Registries>) {
        let backend: std::sync::Weak<dyn crate::fabric::ForeignUdp> = Arc::downgrade(self) as _;
        crate::fabric::attach_foreign_udp(&regs, backend);
        *self.registries.lock().unwrap() = Some(regs);
    }

    /// Hands a datagram one of this host's sockets sent on to the sim's tester endpoints, once the
    /// host lock is released (delivery wakes waiters, whose checks take that lock).
    #[cfg(target_os = "linux")]
    fn deliver_to_testers(
        &self,
        result: &Option<NetResult>,
        src: Option<std::net::SocketAddr>,
        dest: std::net::SocketAddr,
        data: &[u8],
    ) {
        if !matches!(result, Some(NetResult::Ok(_))) {
            return;
        }
        let regs = self.registries.lock().unwrap().clone();
        if let (Some(regs), Some(src)) = (regs, src) {
            crate::fabric::deliver_to_endpoints(&regs, src, dest, data);
        }
    }

    fn new(p: HostProfile) -> Self {
        let online = p.online.unwrap_or_else(|| (0..p.cpu_count).collect());
        #[cfg(target_os = "linux")]
        let ptp_clocks = {
            let mut clocks = p.ptp_clocks.clone();
            for nic in &p.nics {
                if let Some(index) = nic.ptp_index {
                    clocks.entry(index).or_insert(0);
                }
            }
            clocks
        };
        let nics = p
            .nics
            .into_iter()
            .map(|n| {
                (
                    n.name,
                    NicState {
                        ifindex: n.ifindex,
                        mtu: n.mtu,
                        driver: n.driver,
                        driver_version: n.driver_version,
                        bus_info: n.bus_info,
                        hwtstamp_supported: n.hwtstamp_supported,
                        hwtstamp_tx: 0,
                        hwtstamp_rx: 0,
                        operstate: n.operstate,
                        subsystem: n.subsystem,
                        address: n.address,
                        rx_queues: n.rx_queues,
                        tx_queues: n.tx_queues,
                        msi_irqs: n.msi_irqs,
                        link_stats: n.link_stats,
                    },
                )
            })
            .collect();
        let devnull = snare_interpose::real(|| unsafe {
            libc::open(c"/dev/null".as_ptr(), libc::O_RDWR)
        });
        SimHost {
            state: Mutex::new(HostState {
                cpu_count: p.cpu_count,
                online,
                isolated: p.isolated,
                nohz_full: p.nohz_full,
                governor: p.governor,
                preempt_rt: p.preempt_rt,
                caps: p.caps,
                cpu_dma_latency: None,
                open: HashMap::new(),
                #[cfg(target_os = "linux")]
                dirs: HashMap::new(),
                threads: std::collections::BTreeMap::new(),
                thread_ids: HashMap::new(),
                next_tid: TID_BASE,
                mem_locked: false,
                nics,
                default_qdisc: p.default_qdisc,
                #[cfg(target_os = "linux")]
                ptp_clocks,
                #[cfg(target_os = "linux")]
                etf: p.etf,
                #[cfg(target_os = "macos")]
                mac_threads: HashMap::new(),
                #[cfg(target_os = "linux")]
                udp: HashMap::new(),
                #[cfg(target_os = "linux")]
                netlinks: HashMap::new(),
                #[cfg(target_os = "linux")]
                bound: HashMap::new(),
                #[cfg(target_os = "linux")]
                next_ephemeral: 49152,
                env: p
                    .env
                    .into_iter()
                    .filter_map(|(k, v)| {
                        Some((std::ffi::CString::new(k).ok()?, std::ffi::CString::new(v).ok()?))
                    })
                    .collect(),
            }),
            devnull,
            clock: Arc::new(Clock::new(p.tai_offset_secs)),
            isolate_env: p.isolate_env,
            registries: Mutex::new(None),
        }
    }

    /// Whether this host isolates the process environment (see [`HostProfile::env`]).
    pub(crate) fn isolate_env(&self) -> bool {
        self.isolate_env
    }

    pub(crate) fn clock_layer(self: &Arc<Self>) -> Arc<dyn Layer> {
        Arc::new(ClockLayer(self.clock.clone()))
    }

    pub(crate) fn clock(&self) -> Arc<Clock> {
        self.clock.clone()
    }

    /// The transmit deadline (nanoseconds, in the socket's `SO_TXTIME` clock) carried by the most
    /// recent `SCM_TXTIME` `sendmsg` on `fd`, or `None` if none was seen. Lets a test assert the
    /// pacing deadline the code under test requested.
    #[cfg(target_os = "linux")]
    pub fn last_tx_deadline(&self, fd: c_int) -> Option<u64> {
        self.state.lock().unwrap().udp.get(&fd).and_then(|s| s.tx_deadline)
    }

    fn reserve_fd(&self) -> std::io::Result<c_int> {
        if self.devnull < 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EMFILE));
        }
        let fd = unsafe { libc::dup(self.devnull) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if fd < 3 {
            unsafe { libc::close(fd) };
            return Err(std::io::Error::from_raw_os_error(libc::EMFILE));
        }
        Ok(fd)
    }
}

impl Drop for SimHost {
    fn drop(&mut self) {
        // Close every fd still reserved in the tables (each is a live dup of /dev/null), then the
        // devnull template itself, so a dropped sim leaks no descriptors.
        if let Ok(state) = self.state.lock() {
            for &fd in state.open.keys() {
                unsafe { libc::close(fd) };
            }
            #[cfg(target_os = "linux")]
            for &fd in state.udp.keys() {
                unsafe { libc::close(fd) };
            }
            #[cfg(target_os = "linux")]
            for &fd in state.netlinks.keys() {
                unsafe { libc::close(fd) };
            }
        }
        if self.devnull >= 0 {
            unsafe { libc::close(self.devnull) };
        }
    }
}

impl Fs for SimHost {
    fn owns(&self, fd: c_int) -> bool {
        let state = self.state.lock().unwrap();
        if state.open.contains_key(&fd) {
            return true;
        }
        #[cfg(target_os = "linux")]
        if state.dirs.contains_key(&fd) {
            return true;
        }
        false
    }

    unsafe fn open(&self, path: *const c_char, flags: c_int, _mode: u32) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        let mut state = self.state.lock().unwrap();

        if path == Path::new("/dev/cpu_dma_latency") {
            let fd = match self.reserve_fd() {
                Ok(fd) => fd,
                Err(e) => return err(e.raw_os_error().unwrap_or(libc::EMFILE)),
            };
            // Default PM QoS cap in µs while no writer holds the fd open (kernel resets to
            // PM_QOS_CPU_DMA_LAT_DEFAULT_VALUE on release). /dev/cpu_dma_latency in
            // Documentation/admin-guide/pm/cpuidle.rst, Documentation/power/pm_qos_interface.rst.
            state.cpu_dma_latency = Some(2_000_000_000);
            state.open.insert(
                fd,
                OpenFile { data: Vec::new(), cursor: 0, writable: true, path },
            );
            return ok(fd as i64);
        }

        #[cfg(target_os = "linux")]
        if let Some(index) = parse_ptp_index(&path) {
            if !state.ptp_clocks.contains_key(&index) {
                return err(libc::ENOENT);
            }
            let fd = match self.reserve_fd() {
                Ok(fd) => fd,
                Err(e) => return err(e.raw_os_error().unwrap_or(libc::EMFILE)),
            };
            state.open.insert(
                fd,
                OpenFile { data: Vec::new(), cursor: 0, writable: false, path },
            );
            return ok(fd as i64);
        }

        let Some(data) = state.render(&path) else {
            return if state.owns_path(&path) { err(libc::ENOENT) } else { None };
        };
        if flags & libc::O_WRONLY != 0 || flags & libc::O_RDWR != 0 {
            return err(libc::EACCES);
        }
        let fd = match self.reserve_fd() {
            Ok(fd) => fd,
            Err(e) => return err(e.raw_os_error().unwrap_or(libc::EMFILE)),
        };
        state
            .open
            .insert(fd, OpenFile { data, cursor: 0, writable: false, path });
        ok(fd as i64)
    }

    unsafe fn openat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        flags: c_int,
        mode: u32,
    ) -> Option<FsResult> {
        if dirfd != libc::AT_FDCWD {
            let absolute = unsafe { path.as_ref() }.is_some_and(|p| *p == b'/' as c_char);
            if !absolute {
                return None;
            }
        }
        unsafe { self.open(path, flags, mode) }
    }

    unsafe fn read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<FsResult> {
        let mut state = self.state.lock().unwrap();
        let file = state.open.get_mut(&fd)?;
        let start = file.cursor.min(file.data.len());
        let n = len.min(file.data.len() - start);
        unsafe { std::ptr::copy_nonoverlapping(file.data[start..].as_ptr(), buf, n) };
        file.cursor = start + n;
        ok(n as i64)
    }

    unsafe fn write(&self, fd: c_int, buf: *const u8, len: usize) -> Option<FsResult> {
        let mut state = self.state.lock().unwrap();
        let is_latency = state
            .open
            .get(&fd)
            .is_some_and(|f| f.writable && f.path == Path::new("/dev/cpu_dma_latency"));
        if is_latency {
            if len >= 4 {
                let mut micros = [0u8; 4];
                unsafe { std::ptr::copy_nonoverlapping(buf, micros.as_mut_ptr(), 4) };
                state.cpu_dma_latency = Some(i32::from_ne_bytes(micros));
            }
            return ok(len as i64);
        }
        if state.open.contains_key(&fd) {
            return err(libc::EACCES);
        }
        None
    }

    unsafe fn lseek(&self, fd: c_int, offset: i64, whence: c_int) -> Option<FsResult> {
        let mut state = self.state.lock().unwrap();
        let file = state.open.get_mut(&fd)?;
        let base = match whence {
            libc::SEEK_SET => 0i64,
            libc::SEEK_CUR => file.cursor as i64,
            libc::SEEK_END => file.data.len() as i64,
            _ => return err(libc::EINVAL),
        };
        let target = base.saturating_add(offset);
        if target < 0 {
            return err(libc::EINVAL);
        }
        file.cursor = target as usize;
        ok(target)
    }

    unsafe fn fstat(&self, fd: c_int, buf: *mut u8) -> Option<FsResult> {
        let state = self.state.lock().unwrap();
        #[cfg(target_os = "linux")]
        if state.dirs.contains_key(&fd) {
            return fill_stat(buf, 0o040555, 0, fd as u64 | 1, 2);
        }
        let file = state.open.get(&fd)?;
        fill_stat(buf, 0o100444, file.data.len() as u64, fd as u64 | 1, 1)
    }

    unsafe fn stat(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        let state = self.state.lock().unwrap();
        let Some(data) = state.render(&path) else {
            return if state.owns_path(&path) { err(libc::ENOENT) } else { None };
        };
        fill_stat(buf, 0o100444, data.len() as u64, ino_of(&path), 1)
    }

    unsafe fn lstat(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        unsafe { self.stat(path, buf) }
    }

    unsafe fn readlink(&self, path: *const c_char, buf: *mut u8, len: usize) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        let p = path.to_str()?;
        let state = self.state.lock().unwrap();
        let subsystem = p
            .strip_prefix("/sys/class/net/")
            .and_then(|r| r.strip_suffix("/device/subsystem"))
            .and_then(|name| state.nics.get(name));
        let Some(nic) = subsystem else {
            // A path inside a modelled subtree that is not this symlink is ENOENT, not a leak.
            return if state.owns_path(&path) { err(libc::ENOENT) } else { None };
        };
        // /sys/class/net/<if>/device/subsystem is a symlink into /sys/bus/<type> (sysfs device
        // model; Documentation/ABI/testing/sysfs-class-net).
        let target = format!("../../../../bus/{}", nic.subsystem);
        let bytes = target.as_bytes();
        let n = bytes.len().min(len);
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n) };
        ok(n as i64)
    }

    unsafe fn readlinkat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        buf: *mut u8,
        len: usize,
    ) -> Option<FsResult> {
        if dirfd != libc::AT_FDCWD {
            let absolute = unsafe { path.as_ref() }.is_some_and(|p| *p == b'/' as c_char);
            if !absolute {
                return None;
            }
        }
        unsafe { self.readlink(path, buf, len) }
    }

    #[cfg(target_os = "linux")]
    unsafe fn statx(
        &self,
        dirfd: c_int,
        path: *const c_char,
        _flags: c_int,
        _mask: u32,
        buf: *mut u8,
    ) -> Option<FsResult> {
        if let Some(p) = unsafe { path.as_ref() }
            && *p == 0
        {
            let state = self.state.lock().unwrap();
            let file = state.open.get(&dirfd)?;
            return fill_statx(buf, 0o100444, file.data.len() as u64, dirfd as u64 | 1, 1);
        }
        let path = unsafe { path_of(path) }?;
        let state = self.state.lock().unwrap();
        let Some(data) = state.render(&path) else {
            return if state.owns_path(&path) { err(libc::ENOENT) } else { None };
        };
        fill_statx(buf, 0o100444, data.len() as u64, ino_of(&path), 1)
    }

    unsafe fn access(&self, path: *const c_char, _mode: c_int) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        let state = self.state.lock().unwrap();
        if state.known_file(&path) {
            ok(0)
        } else if state.owns_path(&path) {
            err(libc::ENOENT)
        } else {
            None
        }
    }

    unsafe fn faccessat(
        &self,
        _dirfd: c_int,
        path: *const c_char,
        mode: c_int,
        _flags: c_int,
    ) -> Option<FsResult> {
        unsafe { self.access(path, mode) }
    }

    unsafe fn close(&self, fd: c_int) -> Option<FsResult> {
        let mut state = self.state.lock().unwrap();
        let file = state.open.remove(&fd)?;
        if file.path == Path::new("/dev/cpu_dma_latency") {
            state.cpu_dma_latency = None;
        }
        unsafe { libc::close(fd) };
        ok(0)
    }

    #[cfg(target_os = "linux")]
    unsafe fn ioctl(&self, fd: c_int, request: u64, arg: i64) -> Option<FsResult> {
        if (request >> 8) & 0xff != PTP_IOCTL_MAGIC {
            return None;
        }
        let state = self.state.lock().unwrap();
        let file = state.open.get(&fd)?;
        let index = parse_ptp_index(&file.path)?;
        let offset = *state.ptp_clocks.get(&index)?;
        let sample = self.clock.ptp_sample(offset);
        unsafe { fill_ptp_offset(request & 0xff, arg, sample) }
    }

    #[cfg(target_os = "linux")]
    unsafe fn opendir(&self, path: *const c_char) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        let mut state = self.state.lock().unwrap();
        let Some(entries) = state.dir_entries(&path) else {
            return if state.owns_path(&path) {
                err(libc::ENOENT)
            } else {
                None
            };
        };
        let fd = match self.reserve_fd() {
            Ok(fd) => fd,
            Err(e) => return err(e.raw_os_error().unwrap_or(libc::EMFILE)),
        };
        state.dirs.insert(fd, DirStream::new(entries));
        ok(fd as i64)
    }

    #[cfg(target_os = "linux")]
    unsafe fn readdir(&self, fd: c_int) -> Option<FsResult> {
        let mut state = self.state.lock().unwrap();
        let d = state.dirs.get_mut(&fd)?;
        let Some(e) = d.entries.get(d.cursor) else {
            return ok(0); // end of stream: readdir returns NULL
        };
        let (name, ino, dtype) = (e.name.clone(), e.ino, e.dtype);
        d.cursor += 1;
        crate::fs_sim::fill_dirent(&mut d.scratch, &name, ino, dtype);
        ok((&*d.scratch as *const _) as i64)
    }

    #[cfg(target_os = "linux")]
    unsafe fn closedir(&self, fd: c_int) -> Option<FsResult> {
        self.state.lock().unwrap().dirs.remove(&fd)?;
        let ret = unsafe { libc::close(fd) };
        ok(ret as i64)
    }
}

// man 2 sched_setscheduler: SCHED_FIFO and SCHED_RR are the real-time policies, and
// SCHED_RESET_ON_FORK may be OR'd into the policy word, so it is masked off before comparing.
fn is_realtime(policy: c_int) -> bool {
    #[cfg(target_os = "linux")]
    let p = policy & !libc::SCHED_RESET_ON_FORK;
    #[cfg(not(target_os = "linux"))]
    let p = policy;
    p == libc::SCHED_FIFO || p == libc::SCHED_RR
}

impl Env for SimHost {
    unsafe fn getenv(&self, name: *const c_char) -> *mut c_char {
        if name.is_null() {
            return std::ptr::null_mut();
        }
        let name = unsafe { std::ffi::CStr::from_ptr(name) };
        let state = self.state.lock().unwrap();
        match state.env.get(name) {
            // man 3 getenv: the value lives in the map (a stable heap `CString`), valid until it is
            // replaced or removed — the same pointer-lifetime contract as the real `getenv`.
            Some(value) => value.as_ptr() as *mut c_char,
            None => std::ptr::null_mut(),
        }
    }

    unsafe fn setenv(&self, name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int {
        if name.is_null() || value.is_null() {
            return -1;
        }
        let key = unsafe { std::ffi::CStr::from_ptr(name) }.to_owned();
        let val = unsafe { std::ffi::CStr::from_ptr(value) }.to_owned();
        let mut state = self.state.lock().unwrap();
        // man 3 setenv: with overwrite == 0 an existing variable is left unchanged (and success).
        if overwrite == 0 && state.env.contains_key(&key) {
            return 0;
        }
        state.env.insert(key, val);
        0
    }

    unsafe fn unsetenv(&self, name: *const c_char) -> c_int {
        if name.is_null() {
            return -1;
        }
        let key = unsafe { std::ffi::CStr::from_ptr(name) }.to_owned();
        self.state.lock().unwrap().env.remove(&key);
        0
    }
}

impl Host for SimHost {
    fn has_cap(&self, cap: c_int) -> bool {
        self.state.lock().unwrap().has_cap(cap)
    }

    fn gettid(&self) -> Option<HostResult> {
        let mut state = self.state.lock().unwrap();
        ok(state.current_tid() as i64)
    }

    unsafe fn sched_setscheduler(
        &self,
        pid: i32,
        policy: c_int,
        param: *const u8,
    ) -> Option<HostResult> {
        let priority = if param.is_null() {
            0
        } else {
            unsafe { (param as *const c_int).read_unaligned() }
        };
        let mut state = self.state.lock().unwrap();
        // man 2 sched_setscheduler: switching to a real-time policy requires CAP_SYS_NICE, else EPERM.
        if is_realtime(policy) && !state.has_cap(CAP_SYS_NICE) {
            return err(libc::EPERM);
        }
        let tid = state.resolve(pid);
        let t = state.threads.get_mut(&tid).unwrap();
        t.policy = policy;
        t.rt_priority = priority;
        ok(0)
    }

    unsafe fn sched_getscheduler(&self, pid: i32) -> Option<HostResult> {
        let mut state = self.state.lock().unwrap();
        let tid = state.resolve(pid);
        ok(state.threads[&tid].policy as i64)
    }

    unsafe fn sched_setparam(&self, pid: i32, param: *const u8) -> Option<HostResult> {
        let priority = if param.is_null() {
            0
        } else {
            unsafe { (param as *const c_int).read_unaligned() }
        };
        let mut state = self.state.lock().unwrap();
        let tid = state.resolve(pid);
        state.threads.get_mut(&tid).unwrap().rt_priority = priority;
        ok(0)
    }

    unsafe fn sched_getparam(&self, pid: i32, param: *mut u8) -> Option<HostResult> {
        let mut state = self.state.lock().unwrap();
        let tid = state.resolve(pid);
        let priority = state.threads[&tid].rt_priority;
        if !param.is_null() {
            unsafe { (param as *mut c_int).write_unaligned(priority) };
        }
        ok(0)
    }

    #[cfg(target_os = "linux")]
    unsafe fn sched_setaffinity(
        &self,
        pid: i32,
        len: usize,
        set: *const u8,
    ) -> Option<HostResult> {
        if set.is_null() || len < std::mem::size_of::<libc::cpu_set_t>() {
            return err(libc::EINVAL);
        }
        let set = unsafe { &*(set as *const libc::cpu_set_t) };
        let mut state = self.state.lock().unwrap();
        // man 2 sched_setaffinity; the cpu_set_t bit macros are CPU_SET(3).
        // CPU_ISSET/CPU_SET are UB past the bit capacity of a `cpu_set_t` (1024 on glibc).
        let cap = std::mem::size_of::<libc::cpu_set_t>() * 8;
        let count = state.cpu_count.min(cap);
        let wanted: Vec<usize> = (0..count).filter(|&c| unsafe { libc::CPU_ISSET(c, set) }).collect();
        // A mask selecting no in-range CPU is EINVAL, exactly as the kernel reports.
        if wanted.is_empty() {
            return err(libc::EINVAL);
        }
        let tid = state.resolve(pid);
        state.threads.get_mut(&tid).unwrap().affinity = wanted;
        ok(0)
    }

    #[cfg(target_os = "linux")]
    unsafe fn sched_getaffinity(&self, pid: i32, len: usize, set: *mut u8) -> Option<HostResult> {
        if set.is_null() || len < std::mem::size_of::<libc::cpu_set_t>() {
            return err(libc::EINVAL);
        }
        let mut state = self.state.lock().unwrap();
        let cap = std::mem::size_of::<libc::cpu_set_t>() * 8;
        let count = state.cpu_count.min(cap);
        let tid = state.resolve(pid);
        let affinity = state.threads[&tid].affinity.clone();
        let set = set as *mut libc::cpu_set_t;
        unsafe {
            libc::CPU_ZERO(&mut *set);
            if affinity.is_empty() {
                for cpu in state.online.iter().copied().filter(|&c| c < count) {
                    libc::CPU_SET(cpu, &mut *set);
                }
            } else {
                for cpu in affinity.into_iter().filter(|&c| c < cap) {
                    libc::CPU_SET(cpu, &mut *set);
                }
            }
        }
        ok(0)
    }

    unsafe fn setpriority(&self, which: c_int, who: u32, prio: c_int) -> Option<HostResult> {
        if which != PRIO_PROCESS {
            return None;
        }
        let mut state = self.state.lock().unwrap();
        // man 2 setpriority: lowering the nice value (raising priority) needs CAP_SYS_NICE, else EACCES.
        if prio < 0 && !state.has_cap(CAP_SYS_NICE) {
            return err(libc::EACCES);
        }
        let tid = state.resolve(who as i32);
        state.threads.get_mut(&tid).unwrap().nice = prio;
        ok(0)
    }

    unsafe fn getpriority(&self, which: c_int, who: u32) -> Option<HostResult> {
        if which != PRIO_PROCESS {
            return None;
        }
        let mut state = self.state.lock().unwrap();
        let tid = state.resolve(who as i32);
        ok(state.threads[&tid].nice as i64)
    }

    fn mlockall(&self, _flags: c_int) -> Option<HostResult> {
        let mut state = self.state.lock().unwrap();
        // man 2 mlockall: locking beyond RLIMIT_MEMLOCK requires CAP_IPC_LOCK, else EPERM.
        if !state.has_cap(CAP_IPC_LOCK) {
            return err(libc::EPERM);
        }
        state.mem_locked = true;
        ok(0)
    }

    fn munlockall(&self) -> Option<HostResult> {
        self.state.lock().unwrap().mem_locked = false;
        ok(0)
    }

    // man 3 pthread_setschedparam: SCHED_FIFO/RR/OTHER with a struct sched_param priority.
    #[cfg(target_os = "macos")]
    unsafe fn pthread_setschedparam(
        &self,
        thread: u64,
        policy: c_int,
        param: *const u8,
    ) -> Option<HostResult> {
        let priority = if param.is_null() {
            0
        } else {
            unsafe { (param as *const c_int).read_unaligned() }
        };
        self.state
            .lock()
            .unwrap()
            .mac_threads
            .insert(thread, (policy, priority));
        ok(0)
    }

    #[cfg(target_os = "macos")]
    unsafe fn pthread_getschedparam(
        &self,
        thread: u64,
        policy: *mut c_int,
        param: *mut u8,
    ) -> Option<HostResult> {
        let (pol, prio) = self
            .state
            .lock()
            .unwrap()
            .mac_threads
            .get(&thread)
            .copied()
            .unwrap_or((0, 0)); // SCHED_OTHER, priority 0
        if !policy.is_null() {
            unsafe { policy.write_unaligned(pol) };
        }
        if !param.is_null() {
            unsafe { (param as *mut c_int).write_unaligned(prio) };
        }
        ok(0)
    }

    #[cfg(target_os = "macos")]
    unsafe fn thread_policy_set(
        &self,
        _thread: u32,
        _flavor: c_int,
        _info: *const u8,
        _count: u32,
    ) -> Option<HostResult> {
        // Accept any Mach thread policy (e.g. THREAD_TIME_CONSTRAINT_POLICY, <mach/thread_policy.h>)
        // deterministically, without touching the real scheduler. KERN_SUCCESS.
        ok(0)
    }

    // pthread_set_qos_class_self_np with a QOS_CLASS_* from <pthread/qos.h>.
    #[cfg(target_os = "macos")]
    fn set_qos(&self, _qos_class: c_int, _relative_priority: c_int) -> Option<HostResult> {
        ok(0)
    }

    #[cfg(target_os = "macos")]
    unsafe fn sysctl(
        &self,
        name: *const c_int,
        namelen: u32,
        oldp: *mut u8,
        oldlenp: *mut usize,
        _newp: *const u8,
        _newlen: usize,
    ) -> Option<HostResult> {
        if name.is_null() || namelen < 5 {
            return None;
        }
        let mib = unsafe { std::slice::from_raw_parts(name, namelen as usize) };
        if mib[0] != CTL_NET || mib[1] != PF_ROUTE || mib[4] != NET_RT_IFLIST2 {
            return None;
        }
        if oldlenp.is_null() {
            return err(libc::EINVAL);
        }
        let state = self.state.lock().unwrap();
        let mut nics: Vec<(&String, &NicState)> = state.nics.iter().collect();
        nics.sort_by(|a, b| a.0.cmp(b.0));
        let blob = build_iflist2(&nics);
        if oldp.is_null() {
            unsafe { *oldlenp = blob.len() };
            return ok(0);
        }
        if unsafe { *oldlenp } < blob.len() {
            return err(libc::ENOMEM);
        }
        unsafe {
            std::ptr::copy_nonoverlapping(blob.as_ptr(), oldp, blob.len());
            *oldlenp = blob.len();
        }
        ok(0)
    }

    #[cfg(target_os = "linux")]
    unsafe fn syscall(&self, number: i64, args: [i64; 6]) -> Option<HostResult> {
        match number {
            n if n == libc::SYS_sched_setscheduler => unsafe {
                self.sched_setscheduler(args[0] as i32, args[1] as c_int, args[2] as *const u8)
            },
            n if n == libc::SYS_sched_getscheduler => unsafe {
                self.sched_getscheduler(args[0] as i32)
            },
            n if n == libc::SYS_sched_setparam => unsafe {
                self.sched_setparam(args[0] as i32, args[1] as *const u8)
            },
            n if n == libc::SYS_sched_getparam => unsafe {
                self.sched_getparam(args[0] as i32, args[1] as *mut u8)
            },
            n if n == libc::SYS_sched_setaffinity => unsafe {
                self.sched_setaffinity(args[0] as i32, args[1] as usize, args[2] as *const u8)
            },
            n if n == libc::SYS_sched_getaffinity => unsafe {
                self.sched_getaffinity(args[0] as i32, args[1] as usize, args[2] as *mut u8)
            },
            n if n == libc::SYS_setpriority => unsafe {
                self.setpriority(args[0] as c_int, args[1] as u32, args[2] as c_int)
            },
            // man 2 getpriority (NOTES): the raw syscall returns 20 - nice (always positive, so it
            // never collides with an errno), unlike the libc wrapper which returns nice directly.
            n if n == libc::SYS_getpriority => {
                if args[0] as c_int != PRIO_PROCESS {
                    return None;
                }
                let mut state = self.state.lock().unwrap();
                let tid = state.resolve(args[1] as i32);
                ok((20 - state.threads[&tid].nice) as i64)
            }
            _ => None,
        }
    }
}

// Socket ioctl request numbers from <linux/sockios.h>, driven with an `ifreq` per man 7 netdevice.
// SIOCETHTOOL nests an ethtool command struct (<linux/ethtool.h>); SIOC[GS]HWTSTAMP nest a
// `struct hwtstamp_config` (<linux/net_tstamp.h>, Documentation/networking/timestamping.rst).
#[cfg(target_os = "linux")]
const SIOCETHTOOL: u64 = 0x8946;
#[cfg(target_os = "linux")]
const SIOCGIFINDEX: u64 = 0x8933;
#[cfg(target_os = "linux")]
const SIOCGIFMTU: u64 = 0x8921;
#[cfg(target_os = "linux")]
const SIOCSHWTSTAMP: u64 = 0x89b0;
#[cfg(target_os = "linux")]
const SIOCGHWTSTAMP: u64 = 0x89b1;
#[cfg(target_os = "linux")]
const SIOCGIFFLAGS: u64 = 0x8913;
#[cfg(target_os = "linux")]
const ETHTOOL_GDRVINFO: u32 = 0x3;

/// Read the NUL-terminated `ifr_name` (the first 16 bytes of an `ifreq`).
///
/// # Safety
/// `arg` is the ioctl's `*ifreq`.
#[cfg(target_os = "linux")]
unsafe fn read_ifname(arg: i64) -> Option<String> {
    let p = arg as *const u8;
    if p.is_null() {
        return None;
    }
    let mut name = Vec::new();
    for i in 0..16 {
        let b = unsafe { *p.add(i) };
        if b == 0 {
            break;
        }
        name.push(b);
    }
    String::from_utf8(name).ok()
}

/// Write a NUL-terminated string into a fixed-width C `char` field.
#[cfg(target_os = "linux")]
unsafe fn write_cstr_field(base: *mut u8, offset: usize, width: usize, s: &str) {
    let bytes = s.as_bytes();
    let n = bytes.len().min(width - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(offset), n);
        *base.add(offset + n) = 0;
    }
}

// SOF_TIMESTAMPING_TX_SOFTWARE from <linux/net_tstamp.h>: request a software TX timestamp,
// delivered on the socket error queue (Documentation/networking/timestamping.rst).
#[cfg(target_os = "linux")]
const SOF_TIMESTAMPING_TX_SOFTWARE: u32 = 1 << 1;

/// Parse a `sockaddr_in`/`sockaddr_in6` into a [`std::net::SocketAddr`].
/// The limited broadcast address `255.255.255.255` (man 7 ip); subnet-directed broadcasts need a
/// netmask the host does not model, so tests use this form.
#[cfg(target_os = "linux")]
fn udp_is_broadcast(ip: std::net::IpAddr) -> bool {
    matches!(ip, std::net::IpAddr::V4(v4) if v4 == std::net::Ipv4Addr::BROADCAST)
}

#[cfg(target_os = "linux")]
fn udp_loopback_for(domain: c_int) -> std::net::IpAddr {
    if domain == libc::AF_INET6 {
        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    }
}

/// If `(level, name)` is an `IP_ADD_MEMBERSHIP`/`IPV6_JOIN_GROUP`, reads the group address from the
/// leading `in_addr`/`in6_addr` of the `ip_mreq`/`ipv6_mreq` option value (man 7 ip / ipv6).
#[cfg(target_os = "linux")]
fn udp_parse_group(level: c_int, name: c_int, bytes: &[u8]) -> Option<std::net::IpAddr> {
    if level == libc::IPPROTO_IP && name == libc::IP_ADD_MEMBERSHIP && bytes.len() >= 4 {
        return Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        )));
    }
    if level == libc::IPPROTO_IPV6 && name == libc::IPV6_ADD_MEMBERSHIP && bytes.len() >= 16 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&bytes[..16]);
        return Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)));
    }
    None
}

///
/// # Safety
/// `ptr` points to at least `len` bytes of a `sockaddr`.
#[cfg(target_os = "linux")]
unsafe fn read_sockaddr(ptr: *const u8, len: u32) -> Option<std::net::SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    if ptr.is_null() || len < 8 {
        return None;
    }
    let family = unsafe { (ptr as *const u16).read_unaligned() } as c_int;
    let port = u16::from_be(unsafe { (ptr.add(2) as *const u16).read_unaligned() });
    match family {
        libc::AF_INET => {
            let mut a = [0u8; 4];
            unsafe { std::ptr::copy_nonoverlapping(ptr.add(4), a.as_mut_ptr(), 4) };
            Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(a), port)))
        }
        libc::AF_INET6 if len >= 28 => {
            let mut a = [0u8; 16];
            unsafe { std::ptr::copy_nonoverlapping(ptr.add(8), a.as_mut_ptr(), 16) };
            Some(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(a), port, 0, 0)))
        }
        _ => None,
    }
}

/// Write `addr` into a caller's `sockaddr` buffer and update `*addrlen` to the full size.
///
/// # Safety
/// `buf` has capacity `*addrlen`; `addrlen` is writable.
#[cfg(target_os = "linux")]
unsafe fn write_sockaddr(addr: std::net::SocketAddr, buf: *mut u8, addrlen: *mut u32) {
    if buf.is_null() || addrlen.is_null() {
        return;
    }
    let cap = unsafe { *addrlen } as usize;
    let bytes = sockaddr_bytes(addr);
    let n = bytes.len().min(cap);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n);
        *addrlen = bytes.len() as u32;
    }
}

/// Serialise a [`std::net::SocketAddr`] into `sockaddr_in`/`sockaddr_in6` bytes.
#[cfg(target_os = "linux")]
fn sockaddr_bytes(addr: std::net::SocketAddr) -> Vec<u8> {
    use std::net::SocketAddr;
    let mut bytes = Vec::new();
    match addr {
        SocketAddr::V4(v4) => {
            bytes.extend_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            bytes.extend_from_slice(&v4.port().to_be_bytes());
            bytes.extend_from_slice(&v4.ip().octets());
            bytes.resize(16, 0);
        }
        SocketAddr::V6(v6) => {
            bytes.extend_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            bytes.extend_from_slice(&v6.port().to_be_bytes());
            bytes.extend_from_slice(&0u32.to_ne_bytes());
            bytes.extend_from_slice(&v6.ip().octets());
            bytes.extend_from_slice(&0u32.to_ne_bytes());
        }
    }
    bytes
}

/// Write the datagram's source address into a `recvmsg` `msghdr`'s name buffer, if present.
///
/// # Safety
/// `hdr` is the caller's `msghdr`.
#[cfg(target_os = "linux")]
unsafe fn addr_write_from_msg(hdr: *mut libc::msghdr, src: std::net::SocketAddr) -> bool {
    let name = unsafe { (*hdr).msg_name } as *mut u8;
    if name.is_null() {
        return false;
    }
    let mut caplen = unsafe { (*hdr).msg_namelen };
    unsafe {
        write_sockaddr(src, name, &mut caplen);
        (*hdr).msg_namelen = caplen;
    }
    true
}

/// Append a `SOL_SOCKET`/`SCM_TIMESTAMPING` control message carrying `struct scm_timestamping`
/// (three `timespec`s; only the software slot is filled) from the virtual clock.
///
/// # Safety
/// `hdr.msg_control` has capacity `hdr.msg_controllen`.
#[cfg(target_os = "linux")]
unsafe fn write_timestamping_cmsg(
    hdr: *mut libc::msghdr,
    ts: std::time::Duration,
    _errqueue: bool,
) {
    let payload = std::mem::size_of::<[libc::timespec; 3]>();
    let space = unsafe { libc::CMSG_SPACE(payload as u32) } as usize;
    let control = unsafe { (*hdr).msg_control } as *mut u8;
    if control.is_null() || unsafe { (*hdr).msg_controllen } < space {
        unsafe { (*hdr).msg_controllen = 0 };
        return;
    }
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(hdr) };
    if cmsg.is_null() {
        unsafe { (*hdr).msg_controllen = 0 };
        return;
    }
    let mut tsarr: [libc::timespec; 3] = unsafe { std::mem::zeroed() };
    tsarr[0].tv_sec = ts.as_secs() as libc::time_t;
    tsarr[0].tv_nsec = ts.subsec_nanos() as _;
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = SCM_TIMESTAMPING;
        (*cmsg).cmsg_len = libc::CMSG_LEN(payload as u32) as _;
        let data = libc::CMSG_DATA(cmsg);
        std::ptr::copy_nonoverlapping(tsarr.as_ptr() as *const u8, data, payload);
        (*hdr).msg_controllen = space as _;
    }
}

/// Scan a `sendmsg` control buffer for a `SOL_SOCKET`/`SCM_TXTIME` message and return its
/// transmit deadline (`u64` nanoseconds). Walks with `CMSG_*`, so a truncated or absent control
/// buffer yields `None` without reading past `msg_controllen`.
///
/// # Safety
/// `hdr.msg_control` has capacity `hdr.msg_controllen`.
#[cfg(target_os = "linux")]
unsafe fn read_txtime_cmsg(hdr: *const libc::msghdr) -> Option<u64> {
    if unsafe { (*hdr).msg_control }.is_null() || unsafe { (*hdr).msg_controllen } == 0 {
        return None;
    }
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(hdr) };
    while !cmsg.is_null() {
        let (level, ty, len) =
            unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type, (*cmsg).cmsg_len as usize) };
        if level == libc::SOL_SOCKET
            && ty == SCM_TXTIME
            && len >= unsafe { libc::CMSG_LEN(8) as usize }
        {
            let data = unsafe { libc::CMSG_DATA(cmsg) };
            return Some(unsafe { (data as *const u64).read_unaligned() });
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(hdr, cmsg) };
    }
    None
}

/// The clock index `N` if `path` is `/dev/ptp<N>`, else `None`.
#[cfg(target_os = "linux")]
fn parse_ptp_index(path: &Path) -> Option<u32> {
    path.to_str()?.strip_prefix("/dev/ptp")?.parse().ok()
}

/// The PTP ioctl magic byte (`'='`) and the request numbers this models. The `_IO*('=', ..)`
/// request codes and struct layouts are in `<linux/ptp_clock.h>`; overview in
/// Documentation/driver-api/ptp.rst.
#[cfg(target_os = "linux")]
const PTP_IOCTL_MAGIC: u64 = b'=' as u64;
#[cfg(target_os = "linux")]
const PTP_MAX_SAMPLES: usize = 25;

/// Write a `struct ptp_clock_time { __s64 sec; __u32 nsec; __u32 reserved; }` (16 bytes) at
/// `base + offset`.
///
/// # Safety
/// `base + offset .. + 16` is writable.
#[cfg(target_os = "linux")]
unsafe fn write_ptp_clock_time(base: *mut u8, offset: usize, sec: i64, nsec: u32) {
    unsafe {
        (base.add(offset) as *mut i64).write_unaligned(sec);
        (base.add(offset + 8) as *mut u32).write_unaligned(nsec);
        (base.add(offset + 12) as *mut u32).write_unaligned(0);
    }
}

/// Answer the `PTP_SYS_OFFSET` family from `sample` (`[device, realtime, monoraw]`). `arg` is the
/// caller's ioctl struct pointer, `nr` the request's command number.
///
/// # Safety
/// `arg` points to the fixed-size ABI struct the command names (bounds honoured below).
#[cfg(target_os = "linux")]
unsafe fn fill_ptp_offset(nr: u64, arg: i64, sample: [(i64, u32); 3]) -> Option<FsResult> {
    let base = arg as *mut u8;
    if base.is_null() {
        return err(libc::EFAULT);
    }
    let [device, realtime, monoraw] = sample;
    match nr {
        // PTP_SYS_OFFSET_PRECISE = _IOWR('=', 8, struct ptp_sys_offset_precise) — 64 bytes:
        // device, sys_realtime, sys_monoraw (16 each), then reserved.
        8 => {
            unsafe {
                write_ptp_clock_time(base, 0, device.0, device.1);
                write_ptp_clock_time(base, 16, realtime.0, realtime.1);
                write_ptp_clock_time(base, 32, monoraw.0, monoraw.1);
            }
            ok(0)
        }
        // PTP_SYS_OFFSET = _IOW('=', 5, struct ptp_sys_offset): n_samples (u32) + rsv[3] (12),
        // then ts[2*n_samples+1] interleaving system (even) and PHC (odd) reads.
        5 => {
            let n = (unsafe { (base as *const u32).read_unaligned() } as usize).min(PTP_MAX_SAMPLES);
            for i in 0..n {
                let sys = 16 + i * 32;
                let phc = sys + 16;
                unsafe {
                    write_ptp_clock_time(base, sys, realtime.0, realtime.1);
                    write_ptp_clock_time(base, phc, device.0, device.1);
                }
            }
            unsafe { write_ptp_clock_time(base, 16 + n * 32, realtime.0, realtime.1) };
            ok(0)
        }
        _ => err(libc::ENOTTY),
    }
}

/// Append an rtnetlink attribute (`rta_len`, `rta_type`, payload), padded to a 4-byte boundary.
#[cfg(target_os = "linux")]
fn push_rtattr(out: &mut Vec<u8>, ty: u16, payload: &[u8], nul_terminate: bool) {
    let mut data = payload.to_vec();
    if nul_terminate {
        data.push(0);
    }
    let len = (4 + data.len()) as u16;
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(&data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// Build an `RTM_GETLINK` dump reply: one `RTM_NEWLINK` message per interface (carrying
/// `IFLA_IFNAME` and `IFLA_STATS64`), terminated by `NLMSG_DONE`. Native byte order, as the kernel.
#[cfg(target_os = "linux")]
fn build_getlink_dump(nics: &[(&String, &NicState)], seq: u32) -> Vec<u8> {
    const RTM_NEWLINK: u16 = 16;
    const NLMSG_DONE: u16 = 3;
    const NLM_F_MULTI: u16 = 2;
    const IFLA_IFNAME: u16 = 3;
    const IFLA_STATS64: u16 = 23;
    const ARPHRD_ETHER: u16 = 1; // <linux/if_arp.h>

    let mut out = Vec::new();
    let push_nlmsghdr = |out: &mut Vec<u8>, ty: u16| {
        out.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len — patched below
        out.extend_from_slice(&ty.to_ne_bytes());
        out.extend_from_slice(&NLM_F_MULTI.to_ne_bytes());
        out.extend_from_slice(&seq.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid = 0 (from the kernel)
    };

    for (name, nic) in nics {
        let start = out.len();
        push_nlmsghdr(&mut out, RTM_NEWLINK);
        // ifinfomsg
        out.push(0); // ifi_family = AF_UNSPEC
        out.push(0); // padding
        out.extend_from_slice(&ARPHRD_ETHER.to_ne_bytes());
        out.extend_from_slice(&(nic.ifindex as i32).to_ne_bytes());
        let flags = libc::IFF_UP as u32
            | if nic.operstate == "up" { libc::IFF_RUNNING as u32 } else { 0 };
        out.extend_from_slice(&flags.to_ne_bytes()); // ifi_flags
        out.extend_from_slice(&0xffff_ffffu32.to_ne_bytes()); // ifi_change
        push_rtattr(&mut out, IFLA_IFNAME, name.as_bytes(), true);
        // IFLA_STATS64 carries struct rtnl_link_stats64 (<linux/if_link.h>): 24 u64 fields, of
        // which only the first eight are modelled.
        let mut stats = [0u8; 192];
        let s = &nic.link_stats;
        for (i, v) in [
            s.rx_packets, s.tx_packets, s.rx_bytes, s.tx_bytes,
            s.rx_errors, s.tx_errors, s.rx_dropped, s.tx_dropped,
        ]
        .iter()
        .enumerate()
        {
            stats[i * 8..i * 8 + 8].copy_from_slice(&v.to_ne_bytes());
        }
        push_rtattr(&mut out, IFLA_STATS64, &stats, false);
        let len = (out.len() - start) as u32;
        out[start..start + 4].copy_from_slice(&len.to_ne_bytes());
    }

    let start = out.len();
    push_nlmsghdr(&mut out, NLMSG_DONE);
    out.extend_from_slice(&0i32.to_ne_bytes()); // done payload: error code 0
    let len = (out.len() - start) as u32;
    out[start..start + 4].copy_from_slice(&len.to_ne_bytes());
    out
}

/// Prepend a 16-byte `nlmsghdr` (length patched to the whole message, `nlmsg_pid = 0`) to `body`
/// and pad the result to a 4-byte boundary.
#[cfg(target_os = "linux")]
fn nl_message(ty: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let len = (16 + body.len()) as u32;
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(body);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out
}

/// Find a netlink attribute's payload by type within `attrs` (a run of `nlattr`s).
#[cfg(target_os = "linux")]
fn find_nlattr(attrs: &[u8], want: u16) -> Option<&[u8]> {
    let mut pos = 0;
    while pos + 4 <= attrs.len() {
        let len = u16::from_ne_bytes([attrs[pos], attrs[pos + 1]]) as usize;
        let ty = u16::from_ne_bytes([attrs[pos + 2], attrs[pos + 3]]);
        if len < 4 || pos + len > attrs.len() {
            break;
        }
        if ty == want {
            return Some(&attrs[pos + 4..pos + len]);
        }
        pos += len.next_multiple_of(4);
    }
    None
}

/// Answer a genetlink controller `CTRL_CMD_GETFAMILY`: resolve the `"netdev"` family to a fixed
/// id. An unknown family (or a non-`GETFAMILY` command) yields `NLMSG_ERROR(-ENODEV)`. The
/// controller commands and `CTRL_ATTR_*` are in `<linux/genetlink.h>`; see also
/// Documentation/userspace-api/netlink/intro.rst.
#[cfg(target_os = "linux")]
fn build_genl_ctrl_reply(req: &[u8], seq: u32) -> Vec<u8> {
    const CTRL_CMD_NEWFAMILY: u8 = 1;
    const CTRL_CMD_GETFAMILY: u8 = 3;
    const CTRL_ATTR_FAMILY_ID: u16 = 1;
    const CTRL_ATTR_FAMILY_NAME: u16 = 2;
    const GENL_ID_CTRL: u16 = 16;
    const NLMSG_ERROR: u16 = 2;
    const NETDEV_FAMILY_ID: u16 = 24;

    let cmd = req.get(16).copied().unwrap_or(0);
    let name = req
        .get(20..)
        .and_then(|attrs| find_nlattr(attrs, CTRL_ATTR_FAMILY_NAME))
        .map(|p| {
            let end = p.iter().position(|&b| b == 0).unwrap_or(p.len());
            &p[..end]
        });
    if cmd != CTRL_CMD_GETFAMILY || name != Some(b"netdev".as_slice()) {
        // NLMSG_ERROR payload: the errno (negated) followed by the offending header.
        let mut body = Vec::new();
        body.extend_from_slice(&(-libc::ENODEV).to_ne_bytes());
        body.extend_from_slice(&req[..req.len().min(16)]);
        return nl_message(NLMSG_ERROR, 0, seq, &body);
    }
    let mut body = vec![CTRL_CMD_NEWFAMILY, 2, 0, 0]; // genlmsghdr: cmd, version, reserved
    push_rtattr(&mut body, CTRL_ATTR_FAMILY_ID, &NETDEV_FAMILY_ID.to_ne_bytes(), false);
    push_rtattr(&mut body, CTRL_ATTR_FAMILY_NAME, b"netdev", true);
    nl_message(GENL_ID_CTRL, 0, seq, &body)
}

/// Build an `RTM_GETQDISC` reply: one `RTM_NEWQDISC` for the root qdisc (carrying `TCA_KIND`, and
/// for `etf` a nested `TCA_OPTIONS`/`TCA_ETF_PARMS`), terminated by `NLMSG_DONE`. `struct
/// tc_etf_qopt` is in `<linux/pkt_sched.h>` and the etf qdisc in man 8 tc-etf.
#[cfg(target_os = "linux")]
fn build_getqdisc_dump(
    kind: &str,
    etf: Option<(i32, i32, u32)>,
    ifindex: i32,
    seq: u32,
) -> Vec<u8> {
    const RTM_NEWQDISC: u16 = 36;
    const NLMSG_DONE: u16 = 3;
    const NLM_F_MULTI: u16 = 2;
    const TCA_KIND: u16 = 1;
    const TCA_OPTIONS: u16 = 2;
    const TCA_ETF_PARMS: u16 = 1;
    const TC_H_ROOT: u32 = 0xFFFF_FFFF;

    let mut body = Vec::new();
    body.push(0); // tcm_family = AF_UNSPEC
    body.push(0); // tcm__pad1
    body.extend_from_slice(&0u16.to_ne_bytes()); // tcm__pad2
    body.extend_from_slice(&ifindex.to_ne_bytes()); // tcm_ifindex
    body.extend_from_slice(&0u32.to_ne_bytes()); // tcm_handle
    body.extend_from_slice(&TC_H_ROOT.to_ne_bytes()); // tcm_parent
    body.extend_from_slice(&0u32.to_ne_bytes()); // tcm_info
    push_rtattr(&mut body, TCA_KIND, kind.as_bytes(), true);
    if let Some((delta, clockid, flags)) = etf.filter(|_| kind == "etf") {
        let mut parms = Vec::new();
        parms.extend_from_slice(&delta.to_ne_bytes());
        parms.extend_from_slice(&clockid.to_ne_bytes());
        parms.extend_from_slice(&flags.to_ne_bytes());
        let mut opts = Vec::new();
        push_rtattr(&mut opts, TCA_ETF_PARMS, &parms, false);
        push_rtattr(&mut body, TCA_OPTIONS, &opts, false);
    }

    let mut out = nl_message(RTM_NEWQDISC, NLM_F_MULTI, seq, &body);
    out.extend_from_slice(&nl_message(NLMSG_DONE, NLM_F_MULTI, seq, &0i32.to_ne_bytes()));
    out
}

impl Net for SimHost {
    unsafe fn if_nametoindex(&self, name: *const c_char) -> Option<NetResult> {
        if name.is_null() {
            return None;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(name) }.to_str().ok()?;
        let state = self.state.lock().unwrap();
        match state.nics.get(name) {
            Some(nic) => ok(nic.ifindex as i64),
            None => err(libc::ENODEV),
        }
    }

    #[cfg(target_os = "linux")]
    unsafe fn ioctl(&self, fd: c_int, request: u64, arg: i64) -> Option<NetResult> {
        // man 2 ioctl_list / man 7 socket: FIONBIO sets non-blocking mode from a pointed-to int —
        // what std's `set_nonblocking` uses on Linux, so a host-modelled UDP socket must honour it.
        if request == libc::FIONBIO {
            let mut state = self.state.lock().unwrap();
            let sock = state.udp.get_mut(&fd)?;
            if arg == 0 {
                return err(libc::EFAULT);
            }
            sock.nonblocking = unsafe { (arg as *const c_int).read_unaligned() } != 0;
            return ok(0);
        }
        // Only the NIC ioctls carry an `ifreq`; reading `ifr_name` off any other request (e.g.
        // FIONREAD, whose arg is a 4-byte `int`) would read out of bounds.
        if !matches!(
            request,
            SIOCGIFINDEX
                | SIOCGIFMTU
                | SIOCGIFFLAGS
                | SIOCETHTOOL
                | SIOCSHWTSTAMP
                | SIOCGHWTSTAMP
        ) {
            return None;
        }
        let name = unsafe { read_ifname(arg) }?;
        let base = arg as *mut u8;
        let mut state = self.state.lock().unwrap();
        let has_net_admin = state.has_cap(CAP_NET_ADMIN);
        let nic = state.nics.get_mut(&name)?;
        match request {
            SIOCGIFINDEX => {
                unsafe { (base.add(16) as *mut c_int).write_unaligned(nic.ifindex as c_int) };
                ok(0)
            }
            SIOCGIFMTU => {
                unsafe { (base.add(16) as *mut c_int).write_unaligned(nic.mtu) };
                ok(0)
            }
            SIOCETHTOOL => {
                let data = unsafe { (base.add(16) as *const *mut u8).read_unaligned() };
                if data.is_null() {
                    return err(libc::EFAULT);
                }
                let cmd = unsafe { (data as *const u32).read_unaligned() };
                match cmd {
                    ETHTOOL_GDRVINFO => {
                        // struct ethtool_drvinfo (<linux/ethtool.h>): cmd @0, then fixed-width char
                        // fields driver @4, version @36, ..., bus_info @100 (each 32 bytes).
                        unsafe {
                            write_cstr_field(data, 4, 32, &nic.driver);
                            write_cstr_field(data, 36, 32, &nic.driver_version);
                            write_cstr_field(data, 100, 32, &nic.bus_info);
                        }
                        ok(0)
                    }
                    _ => err(libc::EOPNOTSUPP),
                }
            }
            SIOCSHWTSTAMP => {
                // The kernel checks the privilege before the device capability.
                if !has_net_admin {
                    return err(libc::EPERM);
                }
                if !nic.hwtstamp_supported {
                    return err(libc::ERANGE);
                }
                let data = unsafe { (base.add(16) as *const *mut u8).read_unaligned() };
                if data.is_null() {
                    return err(libc::EFAULT);
                }
                // struct hwtstamp_config { int flags; int tx_type; int rx_filter; } (<linux/net_tstamp.h>)
                let tx = unsafe { (data.add(4) as *const c_int).read_unaligned() };
                let rx = unsafe { (data.add(8) as *const c_int).read_unaligned() };
                nic.hwtstamp_tx = tx;
                nic.hwtstamp_rx = rx;
                ok(0)
            }
            SIOCGHWTSTAMP => {
                let data = unsafe { (base.add(16) as *const *mut u8).read_unaligned() };
                if data.is_null() {
                    return err(libc::EFAULT);
                }
                unsafe {
                    (data.add(4) as *mut c_int).write_unaligned(nic.hwtstamp_tx);
                    (data.add(8) as *mut c_int).write_unaligned(nic.hwtstamp_rx);
                }
                ok(0)
            }
            SIOCGIFFLAGS => {
                let flags: libc::c_short = (libc::IFF_UP
                    | if nic.operstate == "up" { libc::IFF_RUNNING } else { 0 })
                    as libc::c_short;
                // ifr_flags is a `short` in the ifreq union at offset 16.
                unsafe { (base.add(16) as *mut libc::c_short).write_unaligned(flags) };
                ok(0)
            }
            _ => None,
        }
    }

    #[cfg(target_os = "linux")]
    fn owns(&self, fd: c_int) -> bool {
        let state = self.state.lock().unwrap();
        state.udp.contains_key(&fd) || state.netlinks.contains_key(&fd)
    }

    #[cfg(target_os = "linux")]
    unsafe fn socket(&self, domain: c_int, ty: c_int, _protocol: c_int) -> Option<NetResult> {
        if domain == libc::AF_NETLINK {
            let fd = match self.reserve_fd() {
                Ok(fd) => fd,
                Err(e) => return err(e.raw_os_error().unwrap_or(libc::EMFILE)),
            };
            self.state
                .lock()
                .unwrap()
                .netlinks
                .insert(fd, std::collections::VecDeque::new());
            return ok(fd as i64);
        }
        if domain != libc::AF_INET && domain != libc::AF_INET6 {
            return None;
        }
        if ty & 0xFF != libc::SOCK_DGRAM {
            return None; // only datagram sockets are modelled; TCP falls through to the OS
        }
        let fd = match self.reserve_fd() {
            Ok(fd) => fd,
            Err(e) => return err(e.raw_os_error().unwrap_or(libc::EMFILE)),
        };
        let nonblocking = ty & libc::SOCK_NONBLOCK != 0;
        self.state.lock().unwrap().udp.insert(
            fd,
            UdpSocket {
                domain,
                local: None,
                peer: None,
                rx: std::collections::VecDeque::new(),
                errq: std::collections::VecDeque::new(),
                nonblocking,
                broadcast: false,
                groups: Vec::new(),
                timestamping: 0,
                sockopts: HashMap::new(),
                tx_deadline: None,
            },
        );
        ok(fd as i64)
    }

    #[cfg(target_os = "linux")]
    unsafe fn bind(&self, fd: c_int, addr: *const u8, len: u32) -> Option<NetResult> {
        let mut state = self.state.lock().unwrap();
        if !state.udp.contains_key(&fd) {
            return None;
        }
        let Some(mut sa) = (unsafe { read_sockaddr(addr, len) }) else {
            return err(libc::EINVAL);
        };
        if sa.port() == 0 {
            let Some(p) = state.alloc_ephemeral(sa.ip()) else {
                return err(libc::EADDRINUSE);
            };
            sa.set_port(p);
        } else if state.bound.contains_key(&sa) {
            return err(libc::EADDRINUSE);
        }
        state.bound.insert(sa, fd);
        state.udp.get_mut(&fd).unwrap().local = Some(sa);
        ok(0)
    }

    #[cfg(target_os = "linux")]
    unsafe fn connect(&self, fd: c_int, addr: *const u8, len: u32) -> Option<NetResult> {
        let Some(dest) = (unsafe { read_sockaddr(addr, len) }) else {
            return err(libc::EINVAL);
        };
        let mut state = self.state.lock().unwrap();
        if !state.udp.contains_key(&fd) {
            return None;
        }
        // man 2 connect on a datagram socket: fix the default peer, assigning an ephemeral local
        // address first if unbound so the peer can address a reply.
        if state.udp[&fd].local.is_none() {
            let ip = udp_loopback_for(state.udp[&fd].domain);
            if let Some(p) = state.alloc_ephemeral(ip) {
                let sa = std::net::SocketAddr::new(ip, p);
                state.bound.insert(sa, fd);
                state.udp.get_mut(&fd).unwrap().local = Some(sa);
            }
        }
        state.udp.get_mut(&fd).unwrap().peer = Some(dest);
        ok(0)
    }

    #[cfg(target_os = "linux")]
    unsafe fn sendto(
        &self,
        fd: c_int,
        buf: *const u8,
        len: usize,
        _flags: c_int,
        addr: *const u8,
        addr_len: u32,
    ) -> Option<NetResult> {
        {
            let mut state = self.state.lock().unwrap();
            if state.netlinks.contains_key(&fd) {
                let req = if buf.is_null() || len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(buf, len) }.to_vec()
                };
                let reply = state.netlink_reply(&req);
                state.netlinks.get_mut(&fd).unwrap().push_back(reply);
                return ok(len as i64);
            }
        }
        let Some(dest) = (unsafe { read_sockaddr(addr, addr_len) }) else {
            return err(libc::EINVAL);
        };
        let now = self.clock.tick_realtime();
        let data = if buf.is_null() || len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(buf, len) }.to_vec()
        };
        let mut state = self.state.lock().unwrap();
        if !state.udp.contains_key(&fd) {
            return None;
        }
        let payload = data.clone();
        let regs = self.registries.lock().unwrap().clone();
        if let (Some(regs), Some(src)) = (&regs, state.udp[&fd].local)
            && regs.policies.send_stalled(src)
        {
            // A stalled link (`UdpPolicy::send_queue_depth == Some(0)`): the send cannot go out.
            return err(libc::EAGAIN);
        }
        let result = state.udp_deliver(fd, data, dest, now, regs.as_ref().map(|r| &r.policies));
        let src = state.udp[&fd].local;
        drop(state);
        self.deliver_to_testers(&result, src, dest, &payload);
        // Wake any thread blocked in recvfrom waiting on a datagram.
        crate::fabric::readiness().bump();
        result
    }

    #[cfg(target_os = "linux")]
    unsafe fn sendmsg(&self, fd: c_int, msg: *const u8, flags: c_int) -> Option<NetResult> {
        if msg.is_null() {
            return err(libc::EFAULT);
        }
        let hdr = msg as *const libc::msghdr;
        // Gather the scattered payload into one datagram.
        let mut data = Vec::new();
        let iov = unsafe { (*hdr).msg_iov };
        let iovlen = unsafe { (*hdr).msg_iovlen };
        if !iov.is_null() {
            for i in 0..iovlen {
                let v = unsafe { &*iov.add(i) };
                if v.iov_base.is_null() || v.iov_len == 0 {
                    continue;
                }
                data.extend_from_slice(unsafe {
                    std::slice::from_raw_parts(v.iov_base as *const u8, v.iov_len)
                });
            }
        }
        // A netlink destination is a `sockaddr_nl`, not an INET address, so handle it before
        // `read_sockaddr` (which only understands AF_INET/AF_INET6) would reject the message.
        {
            let mut state = self.state.lock().unwrap();
            if state.netlinks.contains_key(&fd) {
                let reply = state.netlink_reply(&data);
                state.netlinks.get_mut(&fd).unwrap().push_back(reply);
                return ok(data.len() as i64);
            }
        }
        // An ETF/SO_TXTIME sender passes its per-packet transmit deadline here; record the most
        // recent one so a test can assert what pacing deadline the code under test requested.
        if let Some(deadline) = unsafe { read_txtime_cmsg(hdr) } {
            let mut state = self.state.lock().unwrap();
            if let Some(sock) = state.udp.get_mut(&fd) {
                sock.tx_deadline = Some(deadline);
            }
        }
        let Some(dest) = (unsafe { read_sockaddr((*hdr).msg_name as *const u8, (*hdr).msg_namelen) })
        else {
            return err(libc::EINVAL);
        };
        let len = data.len();
        let ptr = data.as_ptr();
        let dest_bytes = sockaddr_bytes(dest);
        unsafe { self.sendto(fd, ptr, len, flags, dest_bytes.as_ptr(), dest_bytes.len() as u32) }
    }

    #[cfg(target_os = "linux")]
    unsafe fn send(&self, fd: c_int, buf: *const u8, len: usize, _flags: c_int) -> Option<NetResult> {
        {
            let mut state = self.state.lock().unwrap();
            if state.netlinks.contains_key(&fd) {
                let req = if buf.is_null() || len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(buf, len) }.to_vec()
                };
                let reply = state.netlink_reply(&req);
                state.netlinks.get_mut(&fd).unwrap().push_back(reply);
                return ok(len as i64);
            }
            match state.udp.get(&fd) {
                // man 2 send: a datagram socket with no connected peer has nowhere to send.
                Some(sock) if sock.peer.is_none() => return err(libc::EDESTADDRREQ),
                Some(_) => {}
                None => return None,
            }
        }
        let now = self.clock.tick_realtime();
        let data = if buf.is_null() || len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(buf, len) }.to_vec()
        };
        let mut state = self.state.lock().unwrap();
        let dest = state.udp.get(&fd).and_then(|s| s.peer)?;
        let payload = data.clone();
        let regs = self.registries.lock().unwrap().clone();
        if let (Some(regs), Some(src)) = (&regs, state.udp[&fd].local)
            && regs.policies.send_stalled(src)
        {
            // A stalled link (`UdpPolicy::send_queue_depth == Some(0)`): the send cannot go out.
            return err(libc::EAGAIN);
        }
        let result = state.udp_deliver(fd, data, dest, now, regs.as_ref().map(|r| &r.policies));
        let src = state.udp[&fd].local;
        drop(state);
        self.deliver_to_testers(&result, src, dest, &payload);
        crate::fabric::readiness().bump();
        result
    }

    #[cfg(target_os = "linux")]
    unsafe fn recvfrom(
        &self,
        fd: c_int,
        buf: *mut u8,
        len: usize,
        flags: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        {
            let mut state = self.state.lock().unwrap();
            if let Some(q) = state.netlinks.get_mut(&fd) {
                let Some(blob) = q.pop_front() else {
                    return err(libc::EAGAIN);
                };
                let n = len.min(blob.len());
                unsafe { std::ptr::copy_nonoverlapping(blob.as_ptr(), buf, n) };
                // Keep the unread tail (including the trailing NLMSG_DONE) for the next recv.
                if n < blob.len() {
                    q.push_front(blob[n..].to_vec());
                }
                return ok(n as i64);
            }
            if !state.udp.contains_key(&fd) {
                return None;
            }
        }
        let (peer, nonblocking) = {
            let state = self.state.lock().unwrap();
            let sock = &state.udp[&fd];
            (sock.peer, sock.nonblocking)
        };
        // A connected socket only accepts datagrams from its peer; an unconnected one from anyone.
        let pop = || {
            let mut state = self.state.lock().unwrap();
            let sock = state.udp.get_mut(&fd)?;
            take_arrived(&mut sock.rx, |src| peer.is_none_or(|p| p == src))
        };
        let dg = if let Some(dg) = pop() {
            dg
        } else if nonblocking || flags & libc::MSG_DONTWAIT != 0 {
            snare_interpose::charge_latency();
            return err(libc::EAGAIN);
        } else if crate::fabric::readiness().wait_until(None, || {
            let state = self.state.lock().unwrap();
            state
                .udp
                .get(&fd)
                .is_some_and(|s| {
                    s.rx
                        .iter()
                        .any(|dg| dg.arrived() && peer.is_none_or(|p| p == dg.src))
                })
        }) {
            match pop() {
                Some(dg) => dg,
                None => return err(libc::EAGAIN),
            }
        } else {
            return err(libc::EAGAIN); // quiescent: no peer will ever send
        };
        let n = len.min(dg.data.len());
        unsafe { std::ptr::copy_nonoverlapping(dg.data.as_ptr(), buf, n) };
        if !addr.is_null() && !addr_len.is_null() {
            unsafe { write_sockaddr(dg.src, addr, addr_len) };
        }
        ok(n as i64)
    }

    #[cfg(target_os = "linux")]
    unsafe fn recvmsg(&self, fd: c_int, msg: *mut u8, flags: c_int) -> Option<NetResult> {
        if msg.is_null() {
            return err(libc::EFAULT);
        }
        let hdr = msg as *mut libc::msghdr;
        let mut state = self.state.lock().unwrap();
        if let Some(q) = state.netlinks.get_mut(&fd) {
            let Some(blob) = q.pop_front() else {
                return err(libc::EAGAIN);
            };
            let iov = unsafe { (*hdr).msg_iov };
            let iovlen = unsafe { (*hdr).msg_iovlen };
            let mut remaining = &blob[..];
            let mut copied = 0usize;
            if !iov.is_null() {
                for i in 0..iovlen {
                    if remaining.is_empty() {
                        break;
                    }
                    let v = unsafe { &*iov.add(i) };
                    if v.iov_base.is_null() || v.iov_len == 0 {
                        continue;
                    }
                    let take = remaining.len().min(v.iov_len);
                    unsafe {
                        std::ptr::copy_nonoverlapping(remaining.as_ptr(), v.iov_base as *mut u8, take)
                    };
                    remaining = &remaining[take..];
                    copied += take;
                }
            }
            // A too-small buffer keeps the unread tail for the next recv rather than losing it
            // (and with it the NLMSG_DONE that ends the dump).
            if !remaining.is_empty() {
                q.push_front(remaining.to_vec());
            }
            unsafe { (*hdr).msg_controllen = 0 };
            return ok(copied as i64);
        }
        let sock = state.udp.get_mut(&fd)?;
        let errqueue = flags & libc::MSG_ERRQUEUE != 0;
        let queue = if errqueue { &mut sock.errq } else { &mut sock.rx };
        let Some(dg) = take_arrived(queue, |_| true) else {
            // Drivers poll the error queue for TX timestamps in a loop: charge the miss so the
            // poll lets a discrete clock move. Released first, since charging can wake waiters.
            drop(state);
            snare_interpose::charge_latency();
            return err(libc::EAGAIN);
        };
        let ts_enabled = sock.timestamping & SOF_TIMESTAMPING_SOFTWARE != 0
            || (errqueue && sock.timestamping & SOF_TIMESTAMPING_TX_SOFTWARE != 0);

        // Scatter the payload across the caller's iovecs.
        let mut remaining = &dg.data[..];
        let iov = unsafe { (*hdr).msg_iov };
        let iovlen = unsafe { (*hdr).msg_iovlen };
        let mut copied = 0usize;
        if !iov.is_null() {
            for i in 0..iovlen {
                if remaining.is_empty() {
                    break;
                }
                let v = unsafe { &*iov.add(i) };
                if v.iov_base.is_null() || v.iov_len == 0 {
                    continue;
                }
                let take = remaining.len().min(v.iov_len);
                unsafe {
                    std::ptr::copy_nonoverlapping(remaining.as_ptr(), v.iov_base as *mut u8, take)
                };
                remaining = &remaining[take..];
                copied += take;
            }
        }
        // Write the source address into the name buffer, if the caller supplied one.
        unsafe { addr_write_from_msg(hdr, dg.src) };

        // Attach an SCM_TIMESTAMPING control message from the virtual clock.
        if ts_enabled {
            unsafe { write_timestamping_cmsg(hdr, dg.timestamp, errqueue) };
        } else {
            unsafe { (*hdr).msg_controllen = 0 };
        }
        ok(copied as i64)
    }

    #[cfg(target_os = "linux")]
    unsafe fn setsockopt(
        &self,
        fd: c_int,
        level: c_int,
        name: c_int,
        val: *const u8,
        len: u32,
    ) -> Option<NetResult> {
        let mut state = self.state.lock().unwrap();
        let sock = state.udp.get_mut(&fd)?;
        let bytes = if val.is_null() {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(val, len as usize) }.to_vec()
        };
        if level == libc::SOL_SOCKET && name == SO_TIMESTAMPING && bytes.len() >= 4 {
            sock.timestamping =
                u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        // man 7 socket: SO_BROADCAST permits sending to a broadcast address.
        if level == libc::SOL_SOCKET && name == libc::SO_BROADCAST {
            sock.broadcast = bytes.first().is_some_and(|&b| b != 0);
        }
        // man 7 ip / ipv6: join a multicast group so datagrams to it are delivered here.
        if let Some(group) = udp_parse_group(level, name, &bytes)
            && !sock.groups.contains(&group)
        {
            sock.groups.push(group);
        }
        sock.sockopts.insert((level, name), bytes);
        ok(0)
    }

    #[cfg(target_os = "linux")]
    unsafe fn getsockopt(
        &self,
        fd: c_int,
        level: c_int,
        name: c_int,
        val: *mut u8,
        len: *mut u32,
    ) -> Option<NetResult> {
        let state = self.state.lock().unwrap();
        let sock = state.udp.get(&fd)?;
        if val.is_null() || len.is_null() {
            return err(libc::EFAULT);
        }
        let cap = unsafe { *len } as usize;
        // For an owned socket, an option never set reads back as zero (a modelled default) rather
        // than declining — declining would forward to the dup'd /dev/null fd and return ENOTSOCK.
        let empty = Vec::new();
        let stored = sock.sockopts.get(&(level, name)).unwrap_or(&empty);
        let n = if stored.is_empty() {
            cap.min(4)
        } else {
            stored.len().min(cap)
        };
        unsafe {
            std::ptr::write_bytes(val, 0, n);
            if !stored.is_empty() {
                std::ptr::copy_nonoverlapping(stored.as_ptr(), val, n);
            }
            *len = n as u32;
        }
        ok(0)
    }

    #[cfg(target_os = "linux")]
    unsafe fn recv(&self, fd: c_int, buf: *mut u8, len: usize, flags: c_int) -> Option<NetResult> {
        unsafe { self.recvfrom(fd, buf, len, flags, std::ptr::null_mut(), std::ptr::null_mut()) }
    }

    #[cfg(target_os = "linux")]
    unsafe fn getsockname(
        &self,
        fd: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        let state = self.state.lock().unwrap();
        let sock = state.udp.get(&fd)?;
        // man 2 getsockname: an unbound socket reports the wildcard address on its family.
        let local = sock.local.unwrap_or_else(|| {
            std::net::SocketAddr::new(
                if sock.domain == libc::AF_INET6 {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                } else {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                },
                0,
            )
        });
        drop(state);
        unsafe { write_sockaddr(local, addr, addr_len) };
        ok(0)
    }

    #[cfg(target_os = "linux")]
    unsafe fn getpeername(
        &self,
        fd: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        let state = self.state.lock().unwrap();
        let sock = state.udp.get(&fd)?;
        // man 2 getpeername: ENOTCONN until the datagram socket has been connected.
        let Some(peer) = sock.peer else {
            return err(libc::ENOTCONN);
        };
        drop(state);
        unsafe { write_sockaddr(peer, addr, addr_len) };
        ok(0)
    }

    #[cfg(target_os = "linux")]
    unsafe fn getifaddrs(&self, ifap: *mut *mut u8) -> Option<NetResult> {
        use std::net::IpAddr;
        // man 3 getifaddrs: build a linked list of `struct ifaddrs` the caller releases with
        // freeifaddrs(3); ifa_addr points at a sockaddr_in here.
        if ifap.is_null() {
            return err(libc::EFAULT);
        }
        let state = self.state.lock().unwrap();
        // Only IPv4 addresses are presented for now; sorted by name for a deterministic list.
        let mut entries: Vec<(String, std::net::Ipv4Addr, bool)> = state
            .nics
            .iter()
            .filter_map(|(name, nic)| match nic.address {
                Some(IpAddr::V4(ip)) => Some((name.clone(), ip, nic.operstate == "up")),
                _ => None,
            })
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        if entries.is_empty() {
            unsafe { *ifap = std::ptr::null_mut() };
            return ok(0);
        }

        let n = entries.len();
        let ifsz = std::mem::size_of::<libc::ifaddrs>();
        let sasz = std::mem::size_of::<libc::sockaddr_in>();
        let names_len: usize = entries.iter().map(|(name, ..)| name.len() + 1).sum();
        let total = n * ifsz + n * sasz + names_len;
        let block = unsafe { libc::malloc(total) } as *mut u8;
        if block.is_null() {
            return err(libc::ENOMEM);
        }
        unsafe { std::ptr::write_bytes(block, 0, total) };

        let ifs = block as *mut libc::ifaddrs;
        let sas = unsafe { block.add(n * ifsz) } as *mut libc::sockaddr_in;
        let names = unsafe { block.add(n * ifsz + n * sasz) };
        let mut name_off = 0usize;
        for (i, (name, ip, up)) in entries.iter().enumerate() {
            let ifa = unsafe { ifs.add(i) };
            let sa = unsafe { sas.add(i) };
            let nptr = unsafe { names.add(name_off) };
            unsafe {
                std::ptr::copy_nonoverlapping(name.as_ptr(), nptr, name.len());
                *nptr.add(name.len()) = 0;
                (*sa).sin_family = libc::AF_INET as u16;
                (*sa).sin_addr.s_addr = u32::from(*ip).to_be();
                (*ifa).ifa_next = if i + 1 < n {
                    ifs.add(i + 1)
                } else {
                    std::ptr::null_mut()
                };
                (*ifa).ifa_name = nptr as *mut c_char;
                (*ifa).ifa_flags = libc::IFF_UP as u32
                    | if *up { libc::IFF_RUNNING as u32 } else { 0 };
                (*ifa).ifa_addr = sa as *mut libc::sockaddr;
            }
            name_off += name.len() + 1;
        }
        unsafe { *ifap = block };
        ok(0)
    }

    #[cfg(target_os = "linux")]
    unsafe fn freeifaddrs(&self, ifa: *mut u8) -> Option<NetResult> {
        // The list is one allocation (glibc-style), so freeing the head frees all of it.
        if !ifa.is_null() {
            unsafe { libc::free(ifa as *mut libc::c_void) };
        }
        ok(0)
    }

    #[cfg(target_os = "linux")]
    unsafe fn close(&self, fd: c_int) -> Option<NetResult> {
        let mut state = self.state.lock().unwrap();
        if state.netlinks.remove(&fd).is_some() {
            unsafe { libc::close(fd) };
            return ok(0);
        }
        let sock = state.udp.remove(&fd)?;
        if let Some(local) = sock.local {
            state.bound.remove(&local);
        }
        unsafe { libc::close(fd) };
        ok(0)
    }

    #[cfg(target_os = "linux")]
    unsafe fn fcntl(&self, fd: c_int, cmd: c_int, arg: i64) -> Option<NetResult> {
        let mut state = self.state.lock().unwrap();
        let sock = state.udp.get_mut(&fd)?;
        match cmd {
            libc::F_SETFL => {
                sock.nonblocking = arg as c_int & libc::O_NONBLOCK != 0;
                ok(0)
            }
            libc::F_GETFL => {
                ok(if sock.nonblocking { libc::O_NONBLOCK as i64 } else { 0 })
            }
            _ => ok(0),
        }
    }
}

/// macOS `sysctl` `CTL_NET.PF_ROUTE...NET_RT_IFLIST2` MIB words (man 3 sysctl; PF_ROUTE in
/// `<sys/socket.h>`, NET_RT_IFLIST2 in `<sys/sysctl.h>`).
#[cfg(target_os = "macos")]
const CTL_NET: c_int = 4;
#[cfg(target_os = "macos")]
const PF_ROUTE: c_int = 17;
#[cfg(target_os = "macos")]
const NET_RT_IFLIST2: c_int = 6;

/// Size of a `struct if_msghdr2` on macOS/LP64: a 32-byte header plus a 136-byte `if_data64`.
#[cfg(target_os = "macos")]
const IF_MSGHDR2_LEN: usize = 168;

/// Build a `NET_RT_IFLIST2` routing blob: one header-only `struct if_msghdr2` (`ifm_addrs = 0`)
/// per interface, in the given order, carrying the link index, flags and `if_data64` counters.
/// Fixed ABI offsets are written directly, so a libc struct-layout skew cannot shift them.
/// Layouts: XNU `struct if_msghdr2` (`<net/if_var.h>`) and `struct if_data64` (`<net/if.h>`).
#[cfg(target_os = "macos")]
fn build_iflist2(nics: &[(&String, &NicState)]) -> Vec<u8> {
    const RTM_VERSION: u8 = 5;
    const RTM_IFINFO2: u8 = 0x12;
    const IFT_ETHER: u8 = 6;

    let mut out = vec![0u8; nics.len() * IF_MSGHDR2_LEN];
    for (i, (_, nic)) in nics.iter().enumerate() {
        let msg = &mut out[i * IF_MSGHDR2_LEN..(i + 1) * IF_MSGHDR2_LEN];
        msg[0..2].copy_from_slice(&(IF_MSGHDR2_LEN as u16).to_ne_bytes()); // ifm_msglen
        msg[2] = RTM_VERSION; // ifm_version
        msg[3] = RTM_IFINFO2; // ifm_type
        // ifm_addrs @4 = 0 (no trailing sockaddrs)
        let flags: i32 =
            libc::IFF_UP | if nic.operstate == "up" { libc::IFF_RUNNING } else { 0 };
        msg[8..12].copy_from_slice(&flags.to_ne_bytes()); // ifm_flags
        msg[12..14].copy_from_slice(&(nic.ifindex as u16).to_ne_bytes()); // ifm_index
        // ifm_snd_* / ifm_timer @16..32 = 0

        let d = 32; // struct if_data64
        msg[d] = IFT_ETHER; // ifi_type
        msg[d + 8..d + 12].copy_from_slice(&(nic.mtu as u32).to_ne_bytes()); // ifi_mtu
        let s = &nic.link_stats;
        let put = |msg: &mut [u8], off: usize, v: u64| {
            msg[d + off..d + off + 8].copy_from_slice(&v.to_ne_bytes());
        };
        put(msg, 24, s.rx_packets); // ifi_ipackets
        put(msg, 32, s.rx_errors); // ifi_ierrors
        put(msg, 40, s.tx_packets); // ifi_opackets
        put(msg, 48, s.tx_errors); // ifi_oerrors
        put(msg, 64, s.rx_bytes); // ifi_ibytes
        put(msg, 72, s.tx_bytes); // ifi_obytes
        put(msg, 96, s.rx_dropped); // ifi_iqdrops
    }
    out
}

fn format_cpu_list(cpus: &[usize]) -> String {
    if cpus.is_empty() {
        return String::new();
    }
    let mut sorted = cpus.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut parts = Vec::new();
    let mut start = sorted[0];
    let mut prev = sorted[0];
    for &c in &sorted[1..] {
        if c == prev + 1 {
            prev = c;
            continue;
        }
        parts.push(range(start, prev));
        start = c;
        prev = c;
    }
    parts.push(range(start, prev));
    parts.join(",")
}

fn range(start: usize, end: usize) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

fn with_newline(mut s: String) -> Vec<u8> {
    s.push('\n');
    s.into_bytes()
}

#[cfg(target_os = "linux")]
impl crate::fabric::ForeignUdp for SimHost {
    fn deliver_from_peer(&self, src: std::net::SocketAddr, dest: std::net::SocketAddr, data: &[u8]) {
        let now = self.clock.tick_realtime();
        let regs = self.registries.lock().unwrap().clone();
        let mut state = self.state.lock().unwrap();
        for fd in state.udp_recipients(dest) {
            if let Some(s) = state.udp.get_mut(&fd) {
                let delays = match (&regs, s.local) {
                    (Some(r), Some(at)) => r.policies.deliveries(at, data.len()),
                    _ => vec![std::time::Duration::ZERO],
                };
                for delay in delays {
                    s.rx.push_back(in_flight(data.to_vec(), src, now, delay));
                }
            }
        }
        drop(state);
        crate::fabric::readiness().bump();
    }
}

#[cfg(not(target_os = "linux"))]
impl crate::fabric::ForeignUdp for SimHost {
    fn deliver_from_peer(&self, _: std::net::SocketAddr, _: std::net::SocketAddr, _: &[u8]) {}
}
