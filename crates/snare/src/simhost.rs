//! A simulated host behind [`snare_interpose::Host`], [`snare_interpose::Fs`] and
//! [`snare_interpose::Net`]. It answers the scheduling, CPU-topology, NIC and socket-tuning calls a
//! real-time program (such as `fast-talker`) makes — against a test-configurable profile — without
//! ever touching the real scheduler or NIC.
//!
//! The OS *personality* (which symbols exist, errno values, path layout) is fixed by `cfg!` at
//! compile time. What a test configures here are host *facts*: CPU count, isolated/nohz CPUs,
//! governor, granted capabilities, rlimits, and (later) NIC and IRQ profiles. Reading them back
//! from `/sys`, `/proc` and `ethtool` is what the code under test does; serving them is this type.
//!
//! Every hook returns `None` to decline (the call falls through to the next layer or the real
//! OS) and `Some` to answer. A path or fd the host does not model is declined; a path inside a
//! subtree it fully models (see [`HostState::owns_path`]) but does not render is answered with
//! `ENOENT`, so nothing leaks from the real `/sys` or `/proc`. Datagram and netlink sockets are
//! modelled on Linux only; on macOS the socket calls are served by the fabric. The module is
//! Unix-only; Windows has its own host in `win_host`.
//!
//! Locking: all mutable host state sits behind the one [`SimHost::state`] mutex. A socket's
//! `SockRec` has its own lock, which may be taken while `state` is held (never the reverse).
//! `SockRec` methods that consult the receive probe (`land`, `fionread`, the entry listing)
//! call back into `HostRx`, which locks `state`, so they must run with `state` released.
//! `SimHost::registries` is held only long enough to clone the `Arc`, never across a `state`
//! lock. `snare_interpose::charge_latency` can wake waiters that re-enter the host, so it is
//! called with `state` released.

use std::collections::HashMap;
use std::ffi::{c_char, c_int};
use std::path::Path;
use std::sync::{Arc, Mutex};

use snare_interpose::NetResult as HostResult;
#[cfg(target_os = "linux")]
use snare_interpose::NetResult;
use snare_interpose::{Env, Fs, Host, Layer, Net, NetResult as FsResult};

#[cfg(target_os = "linux")]
use crate::fs_sim::{DirEntry, DirStream, fill_statx};
use crate::fs_sim::{
    OpenFiles, descriptor_fcntl, err, fill_stat, ino_of, ok, path_of, set_cloexec, status_flags,
};

use crate::clock::{Clock, ClockLayer};
use crate::netif::{IpNet, NicCounters, NicPolicy, NicSnapshot, NicSpec, Route};
#[cfg(target_os = "linux")]
use crate::sockets::{Membership, RxProbe, SockRec, SocketKind};

/// Capability numbers (`<linux/capability.h>`) the setters gate on. Exposed so tests can grant
/// them by name. `CAP_NET_BIND_SERVICE` (10) permits binding a port below 1024 (man 7
/// capabilities; include/uapi/linux/capability.h).
pub const CAP_NET_BIND_SERVICE: c_int = crate::limits::CAP_NET_BIND_SERVICE;
/// `CAP_NET_ADMIN` (12): interface configuration, including `SIOCSHWTSTAMP` (man 7
/// capabilities; include/uapi/linux/capability.h).
pub const CAP_NET_ADMIN: c_int = crate::limits::CAP_NET_ADMIN;
/// `CAP_NET_RAW` (13): raw and packet sockets (man 7 capabilities;
/// include/uapi/linux/capability.h).
pub const CAP_NET_RAW: c_int = crate::limits::CAP_NET_RAW;
/// `CAP_IPC_LOCK` (14): `mlock`/`mlockall` beyond `RLIMIT_MEMLOCK` (man 7 capabilities, man 2
/// mlockall; include/uapi/linux/capability.h).
pub const CAP_IPC_LOCK: c_int = crate::limits::CAP_IPC_LOCK;
/// `CAP_SYS_NICE` (23): real-time scheduling policies and lowering the nice value (man 7
/// capabilities, man 7 sched; include/uapi/linux/capability.h).
pub const CAP_SYS_NICE: c_int = crate::limits::CAP_SYS_NICE;

/// Interface statistics reported through rtnetlink `IFLA_STATS64` (a subset of the kernel's
/// `rtnl_link_stats64`). Build with `LinkStats { rx_packets: .., ..Default::default() }`. They
/// seed the topology's live [`NicCounters`], which the sim then advances as traffic crosses the
/// interface; sysfs `statistics/*` and macOS `NET_RT_IFLIST2` report the same counters.
#[derive(Clone, Copy, Debug, Default)]
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
    /// Whether `SIOCSHWTSTAMP` is accepted on this interface.
    hwtstamp_supported: bool,
    /// The starting `struct hwtstamp_config` `(flags, tx_type, rx_filter)`.
    hwtstamp: [i32; 3],
    hwtstamp_rx_mapping: [Option<Result<i32, i32>>; 16],
    /// `num_tx_queues`, the transmit queues allocated when the device was created; `None` takes
    /// the channel maxima.
    tx_queues_allocated: Option<usize>,
    /// `IFF_NO_QUEUE`: the device starts with `noqueue` (veth, bridges, VLANs).
    no_queue: bool,
    /// The sysfs `operstate` string reported while the link has no carrier but is admin-up; see
    /// [`HostState::operstate`].
    operstate: String,
    carrier: Option<bool>,
    /// The bus name the `device/subsystem` symlink resolves to.
    subsystem: String,
    /// A host address (a /32 or /128) on the interface; merged with `networks`.
    address: Option<std::net::IpAddr>,
    rx_queues: usize,
    tx_queues: usize,
    msi_irqs: Vec<u32>,
    /// Starting values of the interface counters.
    link_stats: LinkStats,
    /// The PHC index, which also exposes `/dev/ptp<N>`.
    ptp_index: Option<u32>,
    /// Addresses with their prefix; each yields a connected route through this interface.
    networks: Vec<IpNet>,
    /// Other addresses on the segment that in-process sockets may bind as stations.
    stations: Vec<std::net::IpAddr>,
    /// The link's latency, loss and stall behaviour.
    policy: NicPolicy,
    /// The driver's `ethtool` capabilities and settings.
    ethtool: crate::ethtool::NicEthtool,
}

impl Nic {
    /// A new interface with the given name and index (both must be unique on the host). Defaults:
    /// MTU 1500 (the Ethernet payload maximum, RFC 894), link up, driver `"sim"` version `"0"`,
    /// `pci` subsystem, one RX and one TX queue, no hardware timestamping, no address. The
    /// driver name and version are snare placeholders.
    pub fn new(name: impl Into<String>, ifindex: u32) -> Self {
        Nic {
            name: name.into(),
            ifindex,
            mtu: 1500,
            driver: "sim".to_string(),
            driver_version: "0".to_string(),
            bus_info: String::new(),
            hwtstamp_supported: false,
            hwtstamp: [0; 3],
            hwtstamp_rx_mapping: [None; 16],
            tx_queues_allocated: None,
            no_queue: false,
            operstate: "up".to_string(),
            carrier: None,
            subsystem: "pci".to_string(),
            address: None,
            rx_queues: 1,
            tx_queues: 1,
            msi_irqs: Vec::new(),
            link_stats: LinkStats::default(),
            ptp_index: None,
            networks: Vec::new(),
            stations: Vec::new(),
            policy: NicPolicy::default(),
            ethtool: crate::ethtool::NicEthtool::new(),
        }
    }

    /// An address of the host on this interface with its subnet, whose connected route the sim
    /// routes through it.
    pub fn network(mut self, net: impl Into<IpNet>) -> Self {
        self.networks.push(net.into());
        self
    }

    /// An address on this interface's segment that in-process sockets may bind as a station; see
    /// [`NicSpec::stations`].
    pub fn station(mut self, ip: impl Into<std::net::IpAddr>) -> Self {
        self.stations.push(ip.into());
        self
    }

    /// How the link behind this interface treats the traffic that crosses it.
    pub fn policy(mut self, policy: NicPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// The interface as the sim's topology holds it, with its statistics as the counters' start.
    /// `address` becomes a host-prefix entry and `networks` follow; a later entry with the same
    /// address replaces an earlier one, so a network overrides a bare address. A negative MTU
    /// clamps to 0. Carrier follows `operstate == "up"` unless explicitly configured.
    fn topology_fact(&self) -> (NicSpec, NicCounters) {
        let mut spec = NicSpec::new(self.name.clone())
            .index(self.ifindex)
            .mtu(self.mtu.max(0) as u32)
            .link(self.carrier.unwrap_or(self.operstate == "up"))
            .policy(self.policy.clone());
        for net in self
            .address
            .map(IpNet::host)
            .into_iter()
            .chain(self.networks.iter().copied())
        {
            spec.addresses.retain(|n| n.addr != net.addr);
            spec.addresses.push(net);
        }
        spec.stations = self.stations.clone();
        let stats = self.link_stats;
        let counters = NicCounters {
            rx_packets: stats.rx_packets,
            tx_packets: stats.tx_packets,
            rx_bytes: stats.rx_bytes,
            tx_bytes: stats.tx_bytes,
            rx_errors: stats.rx_errors,
            tx_errors: stats.tx_errors,
            rx_dropped: stats.rx_dropped,
            tx_dropped: stats.tx_dropped,
            ..NicCounters::default()
        };
        (spec, counters)
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

    /// The interface MTU in bytes, reported by sysfs `mtu`, rtnetlink `IFLA_MTU`, `SIOCGIFMTU`
    /// and macOS `ifi_mtu`.
    pub fn mtu(mut self, mtu: i32) -> Self {
        self.mtu = mtu;
        self
    }

    /// The link state reported at `/sys/class/net/<name>/operstate` (e.g. `"up"`, `"down"`).
    pub fn operstate(mut self, state: impl Into<String>) -> Self {
        self.operstate = state.into();
        self
    }

    /// The initial carrier state, independently of the operational-state string. Without this
    /// override, carrier is present only when `operstate` is `"up"`.
    pub fn carrier(mut self, present: bool) -> Self {
        self.carrier = Some(present);
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

    /// The hardware timestamping configuration the device starts with, `struct hwtstamp_config`'s
    /// `flags`, `tx_type` (`HWTSTAMP_TX_*`) and `rx_filter` (`HWTSTAMP_FILTER_*`) as
    /// `SIOCGHWTSTAMP` reads them: what another program (ptp4l) left set. Off and no filter by
    /// default, as a driver starts.
    pub fn hwtstamp_config(mut self, flags: i32, tx_type: i32, rx_filter: i32) -> Self {
        self.hwtstamp = [flags, tx_type, rx_filter];
        self
    }

    /// The driver's result for a requested Linux `HWTSTAMP_FILTER_*` receive filter: the applied
    /// filter or a positive errno. Populate this from observed `SIOCSHWTSTAMP` results; explicit
    /// entries supersede inference from advertised capabilities. Requests without an entry use
    /// the default widening rule. Unknown filter values or a nonpositive errno return `EINVAL`.
    pub fn hwtstamp_rx_mapping(
        mut self,
        requested: i32,
        applied: Result<i32, i32>,
    ) -> std::io::Result<Self> {
        if !(0..HWTSTAMP_FILTER_CNT).contains(&requested)
            || match applied {
                Ok(filter) => !(0..HWTSTAMP_FILTER_CNT).contains(&filter),
                Err(error) => error <= 0,
            }
        {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        self.hwtstamp_rx_mapping[requested as usize] = Some(applied);
        Ok(self)
    }

    /// The transmit queues the driver allocated when it created the device (`num_tx_queues`,
    /// fixed for the device's life), as opposed to the ones in use (`real_num_tx_queues`, what
    /// [`queues`](Self::queues) and a channel change set, listed under `queues/`). Whether `mq`
    /// may be the root and how many classes it has go by this count (include/linux/netdevice.h
    /// `netif_is_multiqueue`, net/sched/sch_mq.c `mq_init_common`). Without it a driver with
    /// [`channels`](Self::channels) allocated `combined_max + tx_max` queues (veth's
    /// `veth_get_channels` reports `num_tx_queues` as `max_tx`), one without as many as are in
    /// use; drivers that allocate more than their channel maximum (igb: `IGB_MAX_TX_QUEUES`) need
    /// it set.
    pub fn tx_queues_allocated(mut self, n: usize) -> Self {
        self.tx_queues_allocated = Some(n);
        self
    }

    /// Marks the device `IFF_NO_QUEUE` (include/linux/netdevice.h), as virtual drivers such as
    /// veth, bridge and VLAN do: it starts with a `noqueue` root qdisc whatever its queue count
    /// (net/sched/sch_generic.c `attach_default_qdiscs`, `attach_one_default_qdisc`), and gets
    /// that back when its root qdisc is deleted.
    pub fn no_queue(mut self) -> Self {
        self.no_queue = true;
        self
    }

    /// The firmware version `ETHTOOL_GDRVINFO` reports (`fw_version`, `ethtool -i`'s
    /// `firmware-version`).
    pub fn firmware(mut self, version: impl Into<String>) -> Self {
        self.ethtool.firmware = version.into();
        self
    }

    /// The expansion (option) ROM version `ETHTOOL_GDRVINFO` reports (`erom_version`,
    /// `ethtool -i`'s `expansion-rom-version`).
    pub fn expansion_rom(mut self, version: impl Into<String>) -> Self {
        self.ethtool.expansion_rom = version.into();
        self
    }

    /// The register-dump size reported by `ETHTOOL_GDRVINFO`, in bytes.
    pub fn register_dump_len(mut self, bytes: u32) -> Self {
        self.ethtool.register_dump_len = bytes;
        self
    }

    /// The EEPROM size reported by `ETHTOOL_GDRVINFO`, in bytes.
    pub fn eeprom_len(mut self, bytes: u32) -> Self {
        self.ethtool.eeprom_len = bytes;
        self
    }

    /// The private-flag count reported by `ETHTOOL_GDRVINFO` and `ETHTOOL_GSSET_INFO`.
    pub fn private_flags_count(mut self, count: u32) -> Self {
        self.ethtool.private_flags_count = count;
        self
    }

    /// Gives the driver resizable descriptor rings (`ETHTOOL_[GS]RINGPARAM`): the maxima and the
    /// starting sizes. Without it both commands are `EOPNOTSUPP`.
    pub fn rings(mut self, rings: crate::ethtool::Rings) -> Self {
        self.ethtool.rings = Some(rings);
        self
    }

    /// Gives the driver interrupt coalescing (`ETHTOOL_[GS]COALESCE`): the fields it accepts
    /// (its `supported_coalesce_params`) and their starting values. Setting a non-zero value in
    /// any other field is `EOPNOTSUPP`, as net/ethtool/ioctl.c `ethtool_set_coalesce_supported`
    /// rules. Without it both commands are `EOPNOTSUPP`.
    pub fn coalesce(
        mut self,
        supported: crate::ethtool::CoalesceParams,
        values: crate::ethtool::Coalesce,
    ) -> Self {
        self.ethtool.coalesce = Some((supported, values));
        self
    }

    /// The largest `*usecs*` and `*frames*` coalescing values the driver accepts; above them
    /// `ETHTOOL_SCOALESCE` is `EINVAL`. Unlimited by default.
    pub fn coalesce_limits(mut self, usecs_max: u32, frames_max: u32) -> Self {
        self.ethtool.coalesce_usecs_max = usecs_max;
        self.ethtool.coalesce_frames_max = frames_max;
        self
    }

    /// Gives the driver settable queue counts (`ETHTOOL_[GS]CHANNELS`). The interface's RX and
    /// TX queues (see [`queues`](Self::queues)) become `combined + rx` and `combined + tx`, now
    /// and after every change.
    pub fn channels(mut self, channels: crate::ethtool::Channels) -> Self {
        self.ethtool.channels = Some(channels);
        self
    }

    /// Gives the driver flow control (`ETHTOOL_[GS]PAUSEPARAM`) with these starting settings.
    pub fn pause(mut self, pause: crate::ethtool::Pause) -> Self {
        self.ethtool.pause = Some(pause);
        self
    }

    /// Gives the driver Energy Efficient Ethernet (`ETHTOOL_[GS]EEE`) with these starting
    /// settings.
    pub fn eee(mut self, eee: crate::ethtool::Eee) -> Self {
        self.ethtool.eee = Some(eee);
        self
    }

    /// Gives the driver n-tuple flow steering with a rule table of `slots` entries: the
    /// `ETH_FLAG_NTUPLE` feature becomes settable (off to start) and the `ETHTOOL_*RXCLS*`
    /// commands work. Without it they are `EOPNOTSUPP`.
    pub fn ntuple(mut self, slots: u32) -> Self {
        self.ethtool.flow_slots = Some(slots);
        self.ethtool.hw_features |= crate::ethtool::ETH_FLAG_NTUPLE;
        self
    }

    /// The driver's statistics (`ethtool -S`: `ETHTOOL_GSSET_INFO`, `ETHTOOL_GSTRINGS`,
    /// `ETHTOOL_GSTATS`), names and starting values in report order; change them later with
    /// [`SimHost::set_driver_stat`]. Without any, the statistics commands are `EOPNOTSUPP` and
    /// `ETHTOOL_GDRVINFO` reports `n_stats` 0, as for a driver with no `get_ethtool_stats`.
    pub fn driver_stats<I, S>(mut self, stats: I) -> Self
    where
        I: IntoIterator<Item = (S, u64)>,
        S: Into<String>,
    {
        self.ethtool.stats = stats.into_iter().map(|(n, v)| (n.into(), v)).collect();
        self
    }

    /// The transmit queues whose hardware launches frames at their time: an `etf` qdisc with
    /// `TC_ETF_OFFLOAD_ON` is accepted on these and refused (`EINVAL`) on others; without this
    /// the driver has no ETF offload and such a qdisc is `EOPNOTSUPP` (net/sched/sch_etf.c
    /// `etf_enable_offload`).
    pub fn etf_offload<I: IntoIterator<Item = u16>>(mut self, queues: I) -> Self {
        self.ethtool.etf_offload = Some(queues.into_iter().collect());
        self
    }

    /// Whether NAPI starts out threaded (`/sys/class/net/<if>/threaded` reads 1). Off by default,
    /// as the kernel starts every device.
    pub fn threaded_napi(mut self, on: bool) -> Self {
        self.ethtool.threaded_napi = on;
        self
    }

    /// What `ETHTOOL_GET_TS_INFO` reports, verbatim: the `SOF_TIMESTAMPING_*` capabilities
    /// (`so_timestamping`), and bit masks of the `HWTSTAMP_TX_*` types and `HWTSTAMP_FILTER_*`
    /// filters (include/uapi/linux/net_tstamp.h). A real driver's `get_ts_info` decides these
    /// (e.g. igb_get_ts_info offers the 82576 the PTP filters but not `HWTSTAMP_FILTER_ALL`), so
    /// a profile copied from one reports them as it does; without this a NIC reports the I210's
    /// set when [`hardware_timestamping`](Self::hardware_timestamping) is on and software
    /// stamping alone when it is off. The PHC index stays [`ptp_index`](Self::ptp_index)'s.
    pub fn timestamping_caps(
        mut self,
        so_timestamping: u32,
        tx_types: u32,
        rx_filters: u32,
    ) -> Self {
        self.ethtool.ts_info = Some((so_timestamping, tx_types, rx_filters));
        self
    }

    /// The legacy `ETH_FLAG_*` features (`enum ethtool_flags`, include/uapi/linux/ethtool.h):
    /// those on now, which `ETHTOOL_GFLAGS` reads, and those `ETHTOOL_SFLAGS` may change (the
    /// driver's `hw_features`). Replaces what [`ntuple`](Self::ntuple) made settable, so call
    /// that after this one.
    pub fn flags(mut self, on: u32, settable: u32) -> Self {
        self.ethtool.features = on;
        self.ethtool.hw_features = settable;
        self
    }
}

/// The per-interface facts the host serves itself (driver info, timestamping config, queue and
/// IRQ listings), keyed by name in [`HostState::nics`]. Addresses, link state and counters live in
/// the sim's topology instead, read back as a [`NicSnapshot`].
struct NicState {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    ifindex: u32,
    // Everything below is read only through the Linux NIC ioctls.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    driver: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    driver_version: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    bus_info: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    hwtstamp_supported: bool,
    /// The `struct hwtstamp_config` the driver applied, `(flags, tx_type, rx_filter)`
    /// (include/uapi/linux/net_tstamp.h), read back by `SIOCGHWTSTAMP`: the profile's
    /// [`Nic::hwtstamp_config`], then what `SIOCSHWTSTAMP` set.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    hwtstamp: [i32; 3],
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    hwtstamp_rx_mapping: [Option<Result<i32, i32>>; 16],
    /// The profile's operational state.
    operstate: String,
    carrier: Option<bool>,
    subsystem: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    rx_queues: usize,
    /// `real_num_tx_queues`: the transmit queues in use, which `queues/` lists and a channel
    /// change sets.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    tx_queues: usize,
    /// `num_tx_queues`: the transmit queues allocated, fixed for the device's life (see
    /// [`Nic::tx_queues_allocated`]).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    num_tx_queues: usize,
    /// `IFF_NO_QUEUE` ([`Nic::no_queue`]).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    no_queue: bool,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    msi_irqs: Vec<u32>,
    /// The driver's `ethtool` capabilities and what has been set through them.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    ethtool: crate::ethtool::NicEthtool,
    /// The interface's qdiscs.
    #[cfg(target_os = "linux")]
    qdiscs: crate::qdisc::NicQdiscs,
}

/// What a PTP hardware clock's driver offers (its `struct ptp_clock_info`), which decides what
/// `PTP_CLOCK_GETCAPS` reports and which of the clock's ioctls work (drivers/ptp/ptp_chardev.c
/// `ptp_ioctl`, Linux 7.0). The default is a bare clock: nothing to adjust (the sim's PHC follows
/// the virtual clock), no alarms, external timestamp channels, periodic outputs, PPS or pins, no
/// cross-timestamping (`getcrosststamp`, as on igb's I210), and `gettimex64`, so
/// `PTP_SYS_OFFSET_EXTENDED` works. A profile copied from a real clock takes its
/// `PTP_CLOCK_GETCAPS` words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtpCaps {
    /// `max_adj`: the largest frequency adjustment, in parts per billion.
    pub max_adj: i32,
    /// `n_alarm`: programmable alarms.
    pub n_alarm: i32,
    /// `n_ext_ts`: external timestamp channels (`PTP_EXTTS_REQUEST`'s indices).
    pub n_ext_ts: i32,
    /// `n_per_out`: periodic outputs (`PTP_PEROUT_REQUEST`'s indices).
    pub n_per_out: i32,
    /// `pps`: whether `PTP_ENABLE_PPS` turns on a PPS event.
    pub pps: bool,
    /// `n_pins`: programmable pins (`PTP_PIN_GETFUNC`/`PTP_PIN_SETFUNC` indices).
    pub n_pins: i32,
    /// `cross_timestamping`: the driver has `getcrosststamp`, so `PTP_SYS_OFFSET_PRECISE` works.
    pub cross_timestamping: bool,
    /// `adjust_phase`: the driver has `adjphase` and `getmaxphase`.
    pub adjust_phase: bool,
    /// `max_phase_adj`: the largest phase adjustment, in nanoseconds (0 without
    /// `adjust_phase`).
    pub max_phase_adj: i32,
    /// The driver has `gettimex64`, so `PTP_SYS_OFFSET_EXTENDED` works (not reported by
    /// `PTP_CLOCK_GETCAPS`; nearly every current driver has it).
    pub extended: bool,
}

impl Default for PtpCaps {
    fn default() -> Self {
        PtpCaps {
            max_adj: 0,
            n_alarm: 0,
            n_ext_ts: 0,
            n_per_out: 0,
            pps: false,
            n_pins: 0,
            cross_timestamping: false,
            adjust_phase: false,
            max_phase_adj: 0,
            extended: true,
        }
    }
}

impl PtpCaps {
    /// The capabilities of a clock whose `PTP_CLOCK_GETCAPS` reported these first nine words
    /// (`max_adj` through `max_phase_adj`), with `gettimex64`.
    pub fn from_words(w: [i32; 9]) -> Self {
        PtpCaps {
            max_adj: w[0],
            n_alarm: w[1],
            n_ext_ts: w[2],
            n_per_out: w[3],
            pps: w[4] != 0,
            n_pins: w[5],
            cross_timestamping: w[6] != 0,
            adjust_phase: w[7] != 0,
            max_phase_adj: w[8],
            extended: true,
        }
    }
}

/// A test-configurable description of the simulated host. Build one, then attach it to a
/// [`Sim`](crate::Sim) with [`SimBuilder::host`](crate::SimBuilder::host).
pub struct HostProfile {
    /// Logical CPUs, numbered `0..cpu_count`; at least 1.
    cpu_count: usize,
    /// The online set; `None` means every CPU.
    online: Option<Vec<usize>>,
    isolated: Vec<usize>,
    nohz_full: Vec<usize>,
    governor: String,
    preempt_rt: bool,
    /// Granted capabilities, bit `n` for capability number `n`.
    caps: u64,
    root: bool,
    nics: Vec<Nic>,
    /// The root qdisc kind reported by sysctl and `RTM_GETQDISC`.
    default_qdisc: String,
    /// Seconds `CLOCK_TAI` leads `CLOCK_REALTIME`.
    tai_offset_secs: u64,
    /// PTP hardware clocks exposed as `/dev/ptp<N>`, mapping the clock index to the nanosecond
    /// offset its PHC leads `CLOCK_REALTIME` by (0 = tracks realtime exactly).
    ptp_clocks: std::collections::BTreeMap<u32, i64>,
    /// The driver capabilities of the PTP clocks that have their own; the rest get
    /// [`PtpCaps::default`].
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    ptp_caps: std::collections::BTreeMap<u32, PtpCaps>,
    /// ETF root-qdisc parameters `(delta, clockid, flags)` reported through rtnetlink
    /// `RTM_GETQDISC`; `Some` also makes the reported root-qdisc kind `"etf"`.
    etf: Option<(i32, i32, u32)>,
    /// When set, `getenv`/`setenv`/`unsetenv` are served from `env` alone. Linux enumeration reads
    /// the real process-global `environ` directly.
    isolate_env: bool,
    /// The isolated environment's variables, in insertion order (a later duplicate wins).
    env: Vec<(String, String)>,
    /// Routes declared on top of the connected routes the interfaces imply.
    routes: Vec<Route>,
    /// What `uname` reports; a `None` version follows [`preempt_rt`](Self::preempt_rt) on Linux.
    sysname: String,
    nodename: String,
    kernel_release: String,
    kernel_version: Option<String>,
    machine: String,
}

#[cfg(target_os = "linux")]
const DEFAULT_SYSNAME: &str = "Linux";
#[cfg(target_os = "macos")]
const DEFAULT_SYSNAME: &str = "Darwin";
#[cfg(target_os = "linux")]
const DEFAULT_KERNEL_RELEASE: &str = "6.12.0";
#[cfg(target_os = "macos")]
const DEFAULT_KERNEL_RELEASE: &str = "25.0.0";
#[cfg(target_os = "linux")]
const DEFAULT_KERNEL_VERSION: &str = "#1 SMP PREEMPT_DYNAMIC";
#[cfg(target_os = "macos")]
const DEFAULT_KERNEL_VERSION: &str = "Darwin Kernel Version 25.0.0";
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const DEFAULT_MACHINE: &str = "arm64";
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
const DEFAULT_MACHINE: &str = std::env::consts::ARCH;

/// The kernel identity a [`SimHost`] reports through `uname`.
#[derive(Clone, Debug)]
struct Uname {
    sysname: String,
    nodename: String,
    release: String,
    version: String,
    machine: String,
}

impl Default for HostProfile {
    fn default() -> Self {
        Self::new()
    }
}

impl HostProfile {
    /// A single-CPU, non-real-time host with no isolated CPUs and no elevated capabilities.
    ///
    /// The `powersave` governor is a snare default: it is the algorithm `intel_pstate` selects
    /// unless the kernel is built with `CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE`
    /// (Documentation/admin-guide/pm/intel_pstate.rst, "Active Mode"). `fq_codel` is the qdisc most
    /// distributions set through systemd's `sysctl.d/50-default.conf`; the kernel's own default
    /// is `pfifo_fast` (Documentation/admin-guide/sysctl/net.rst, `default_qdisc`). The TAI offset
    /// is 37 s, TAI−UTC since 2017-01-01 (IERS Bulletin C).
    ///
    /// `uname` reports a host named `snare`: on Linux release `6.12.0`, version `#1 SMP
    /// PREEMPT_DYNAMIC` (`#1 SMP PREEMPT_RT` with [`preempt_rt`](Self::preempt_rt)), the forms
    /// `scripts/mkcompile_h` builds; on macOS `Darwin` release `25.0.0`. The machine is the build
    /// target's (`x86_64`, `aarch64`, or `arm64` on macOS).
    pub fn new() -> Self {
        HostProfile {
            cpu_count: 1,
            online: None,
            isolated: Vec::new(),
            nohz_full: Vec::new(),
            governor: "powersave".to_string(),
            preempt_rt: false,
            caps: 0,
            root: false,
            nics: Vec::new(),
            default_qdisc: "fq_codel".to_string(),
            tai_offset_secs: 37,
            ptp_clocks: std::collections::BTreeMap::new(),
            ptp_caps: std::collections::BTreeMap::new(),
            etf: None,
            isolate_env: false,
            env: Vec::new(),
            routes: Vec::new(),
            sysname: DEFAULT_SYSNAME.to_string(),
            nodename: "snare".to_string(),
            kernel_release: DEFAULT_KERNEL_RELEASE.to_string(),
            kernel_version: None,
            machine: DEFAULT_MACHINE.to_string(),
        }
    }

    /// The operating system name `uname` reports (`Linux`, `Darwin`).
    pub fn sysname(mut self, name: impl Into<String>) -> Self {
        self.sysname = name.into();
        self
    }

    /// The host name `uname` reports. `gethostname` is not modelled and still reads the real one.
    pub fn nodename(mut self, name: impl Into<String>) -> Self {
        self.nodename = name.into();
        self
    }

    /// The kernel release `uname` reports, such as `6.12.0-rt5`.
    pub fn kernel_release(mut self, release: impl Into<String>) -> Self {
        self.kernel_release = release.into();
        self
    }

    /// The kernel version string `uname` reports, such as `#1 SMP PREEMPT_RT Mon Jan 6 12:00:00
    /// UTC 2025`. Setting it stops it following [`preempt_rt`](Self::preempt_rt).
    pub fn kernel_version(mut self, version: impl Into<String>) -> Self {
        self.kernel_version = Some(version.into());
        self
    }

    /// The hardware name `uname` reports (`x86_64`, `aarch64`, `arm64`).
    pub fn machine(mut self, machine: impl Into<String>) -> Self {
        self.machine = machine.into();
        self
    }

    /// Copies every `uname` field from the machine running the test. The call bypasses the sim, so
    /// it works inside one.
    pub fn real_uname(mut self) -> std::io::Result<Self> {
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        if snare_interpose::real(|| unsafe { libc::uname(&mut uts) }) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let field = |f: &[c_char]| {
            unsafe { std::ffi::CStr::from_ptr(f.as_ptr()) }
                .to_string_lossy()
                .into_owned()
        };
        self.sysname = field(&uts.sysname);
        self.nodename = field(&uts.nodename);
        self.kernel_release = field(&uts.release);
        self.kernel_version = Some(field(&uts.version));
        self.machine = field(&uts.machine);
        Ok(self)
    }

    fn uname(&self) -> Uname {
        let version = self.kernel_version.clone().unwrap_or_else(|| {
            if cfg!(target_os = "linux") && self.preempt_rt {
                "#1 SMP PREEMPT_RT".to_string()
            } else {
                DEFAULT_KERNEL_VERSION.to_string()
            }
        });
        Uname {
            sysname: self.sysname.clone(),
            nodename: self.nodename.clone(),
            release: self.kernel_release.clone(),
            version,
            machine: self.machine.clone(),
        }
    }

    /// A route of the host. Declaring a default route (`0.0.0.0/0` or `::/0`) replaces the ones
    /// through the lowest interface the host otherwise gets.
    pub fn route(mut self, route: Route) -> Self {
        self.routes.push(route);
        self
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
    /// this isolates those lookups to the variables set here. On Linux, `std::env::vars` and
    /// `vars_os` still enumerate the real process environment. Tester code can reach it inside
    /// [`snare::real`](crate::real), which sends the calling thread's OS calls to the OS.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.isolate_env = true;
        self.env.push((key.into(), value.into()));
        self
    }

    /// Isolate environment lookups with no variables set: `std::env::var` returns `Err(NotPresent)`.
    /// Enumeration has the platform limits described in [`env`](Self::env).
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

    /// Gives the PTP hardware clock `/dev/ptp<index>` (exposing it if no clock or NIC did yet)
    /// its driver's capabilities, in place of [`PtpCaps::default`].
    pub fn ptp_clock_caps(mut self, index: u32, caps: PtpCaps) -> Self {
        self.ptp_clocks.entry(index).or_insert(0);
        self.ptp_caps.insert(index, caps);
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
    /// host lacks fail with `EPERM`, exactly as the kernel would. Numbers outside `0..64` are
    /// ignored: the kernel's capability sets are two 32-bit words (`_LINUX_CAPABILITY_U32S_3`,
    /// include/uapi/linux/capability.h; man 7 capabilities).
    pub fn cap(mut self, cap: c_int) -> Self {
        if (0..64).contains(&cap) {
            self.caps |= 1u64 << cap;
        }
        self
    }

    /// Whether the code under test runs as root: `geteuid` reads 0, and macOS's root-only calls
    /// (binding a reserved port on a specific address, opening `/dev/bpf*`) succeed. Capabilities
    /// stay as granted with [`cap`](Self::cap).
    pub fn root(mut self, on: bool) -> Self {
        self.root = on;
        self
    }

    /// Finalize into a [`SimHost`] ready to attach to a [`Sim`](crate::Sim).
    pub fn build(self) -> Arc<SimHost> {
        Arc::new(SimHost::new(self))
    }
}

/// A fully-featured interface: up, hardware timestamping, an `igb`-style driver and the given
/// address — what most tests want without spelling out every field. The driver name and version
/// are illustrative snare choices (`igb` is the Intel I210/I350 driver, a common PTP-capable
/// NIC); `bus_info` follows the PCI `domain:bus:device.function` form `ethtool -i` prints, with
/// the bus number taken from `ifindex` so each NIC gets a distinct address.
///
/// Its `ethtool` driver is an I210 as igb drives it (drivers/net/ethernet/intel/igb, Linux
/// 6.12): rings 256 of at most 4096 (`IGB_DEFAULT_RXD`/`IGB_MAX_RXD`, `*_TXD`), coalescing in
/// `rx-usecs`/`tx-usecs` only (`supported_coalesce_params = ETHTOOL_COALESCE_USECS`) up to
/// `IGB_MAX_ITR_USECS` 10000, starting at 3 (`IGB_DEFAULT_ITR`, the dynamic setting;
/// `tx-usecs` reads 0 with queue pairs), up to 4 queue pairs plus the `NON_Q_VECTORS` other
/// vector (one pair in use, matching the interface's single queue), flow control on, EEE on for
/// 100 and 1000 Mb/s (`ADVERTISED_100baseT_Full | ADVERTISED_1000baseT_Full`), a 16-rule flow
/// table (`IGB_MAX_RXNFC_FILTERS`) and launch-time (ETF) offload on queues 0 and 1
/// (`igb_offload_txtime`). The firmware version is illustrative.
fn rich_nic(name: &str, ifindex: u32, ip: std::net::IpAddr) -> Nic {
    use crate::ethtool::{Channels, Coalesce, CoalesceParams, Eee, Pause, Rings};
    Nic::new(name, ifindex)
        .mtu(1500)
        .driver("igb", "5.6.0")
        .bus_info(format!("0000:{ifindex:02x}:00.0"))
        .firmware("3.25, 0x800005d0")
        .hardware_timestamping(true)
        .operstate("up")
        .address(ip)
        .rings(Rings {
            rx_max: 4096,
            tx_max: 4096,
            rx: 256,
            tx: 256,
            ..Rings::default()
        })
        .coalesce(
            CoalesceParams::USECS,
            Coalesce {
                rx_usecs: 3,
                ..Coalesce::default()
            },
        )
        .coalesce_limits(10_000, u32::MAX)
        .channels(Channels {
            combined_max: 4,
            other_max: 1,
            combined: 1,
            other: 1,
            ..Channels::default()
        })
        .pause(Pause {
            autoneg: true,
            rx: true,
            tx: true,
        })
        .eee(Eee {
            supported: 0x28,
            advertised: 0x28,
            lp_advertised: 0x28,
            enabled: true,
            tx_lpi_enabled: true,
            ..Eee::default()
        })
        .ntuple(16)
        .etf_offload([0, 1])
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
            .cap(CAP_NET_RAW)
            .cap(CAP_NET_BIND_SERVICE)
            .nic(rich_nic(
                "eth0",
                2,
                std::net::Ipv4Addr::new(10, 0, 0, 10).into(),
            ));
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
            .cap(CAP_NET_RAW)
            .cap(CAP_NET_BIND_SERVICE)
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
                .cap(CAP_NET_ADMIN)
                .cap(CAP_NET_RAW)
                .cap(CAP_NET_BIND_SERVICE);
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

/// A file the host opened: a snapshot of its rendered contents taken at `open`, as sysfs and
/// procfs render an attribute once per open file. The fd is a real `dup` of `/dev/null` (see
/// [`SimHost::reserve_fd`]), closed when the file is.
struct OpenFile {
    data: Vec<u8>,
    /// An errno every `read` fails with (see [`HostState::read_error`]).
    read_error: Option<c_int>,
    /// Byte offset of the next `read`; may exceed `data.len()` after an `lseek`.
    cursor: usize,
    /// Opened for writing. Only `/dev/cpu_dma_latency` and the `threaded` attributes take
    /// writes; a `/dev/ptp<N>` opened for writing may make the clock's changing ioctls.
    writable: bool,
    flags: c_int,
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

/// The first simulated tid minted. A snare choice: any positive base works; 4000 keeps simulated
/// tids clear of `0` (the "calling thread" argument of the `sched_*` calls) and of the small pids
/// a test might pass deliberately.
const TID_BASE: i32 = 4000;

/// The uid of the first user a stock install creates: 1000 on Linux (`UID_MIN` in man 5
/// login.defs), 501 on macOS (the uid the first account gets, as observed with `id -u` on
/// macOS 26; Apple documents no source for it).
const UNPRIVILEGED_UID: u32 = if cfg!(target_os = "macos") { 501 } else { 1000 };

/// A datagram queued for delivery, with the virtual-clock timestamp stamped when it was sent.
/// Also used for the error-queue entries that carry a TX software timestamp, with empty `data`.
#[cfg(target_os = "linux")]
#[derive(Clone)]
struct Datagram {
    data: Vec<u8>,
    src: std::net::SocketAddr,
    /// Virtual `CLOCK_REALTIME` when it became receivable (send time plus link delay); reported
    /// in `SCM_TIMESTAMPING` and used to move the clock forward when it is read.
    timestamp: std::time::Duration,
    rx_fallback: Arc<std::sync::OnceLock<std::time::Duration>>,
    /// Still in flight until then (link latency); `None` arrived on sending.
    arrives: Option<crate::readiness::Deadline>,
    /// The link it crosses and that link's down epoch when it was sent.
    via: Option<(Arc<crate::netif::LinkState>, u64)>,
    /// The hardware stamp the receiving NIC took, on its clock ([`HostState::nic_hw_stamp`]).
    hw: Option<std::time::Duration>,
    /// The smallest MTU on its path, which decides whether it crossed as fragments
    /// ([`crate::netif::Copy::mtu`]).
    mtu: Option<u32>,
}

#[cfg(target_os = "linux")]
impl Datagram {
    /// Whether the link it crossed went down while it was in flight.
    fn lost(&self) -> bool {
        match (&self.via, self.arrives) {
            (Some((link, epoch)), Some(at)) => link.lost_in_flight(*epoch, at.instant()),
            _ => false,
        }
    }
}

/// Lets the receive buffer ([`crate::limits::RxQueue`]) order, admit and account the datagram.
#[cfg(target_os = "linux")]
impl crate::limits::Arrival for Datagram {
    fn src(&self) -> std::net::SocketAddr {
        self.src
    }

    fn payload(&self) -> usize {
        self.data.len()
    }

    fn arrives(&self) -> Option<crate::readiness::Deadline> {
        self.arrives
    }

    fn lost(&self) -> bool {
        Datagram::lost(self)
    }

    fn path_mtu(&self) -> Option<u32> {
        self.mtu
    }
}

/// A datagram for a receive queue that becomes receivable `delay` from now, its timestamp the
/// arrival time. A non-zero delay registers the deadline with the readiness waiters so a blocked
/// receiver wakes when it passes.
#[cfg(target_os = "linux")]
fn in_flight(
    data: Vec<u8>,
    src: std::net::SocketAddr,
    sent: std::time::Duration,
    delay: std::time::Duration,
    via: Option<(Arc<crate::netif::LinkState>, u64)>,
) -> Datagram {
    let arrives = (!delay.is_zero()).then(|| crate::readiness::Deadline::after(delay));
    if let Some(arrives) = arrives {
        arrives.wake_waiters_then();
    }
    Datagram {
        data,
        src,
        timestamp: sent + delay,
        rx_fallback: Arc::default(),
        arrives,
        via,
        hw: None,
        mtu: None,
    }
}

/// A simulated `SOCK_DGRAM` socket: its bound address, receive queue and recorded socket options.
/// Its timestamping state and transmit stamps live in its record (`crate::tstamp`).
#[cfg(target_os = "linux")]
struct UdpSocket {
    fd: c_int,
    descriptors: std::collections::BTreeSet<c_int>,
    /// `AF_INET` or `AF_INET6`, as passed to `socket`.
    domain: c_int,
    /// The bound address; set by `bind`, or implicitly by the first `connect`/send.
    local: Option<std::net::SocketAddr>,
    /// The address `bind` was given (port 0 for any): what a disconnect falls back to.
    requested: Option<std::net::SocketAddr>,
    /// The connected peer, set by `connect` (man 2 connect): it fixes the default `send`
    /// destination and filters received datagrams to that source.
    peer: Option<std::net::SocketAddr>,
    /// The receive buffer, bounded by `SO_RCVBUF` accounting in [`crate::limits`].
    rx: crate::limits::RxQueue<Datagram>,
    /// `O_NONBLOCK`, from `SOCK_NONBLOCK`, `FIONBIO` or `F_SETFL`.
    nonblocking: bool,
    /// SO_BROADCAST (man 7 socket): broadcasting to `255.255.255.255` is refused without it.
    broadcast: bool,
    /// Raw values of every option set that no modelled handler consumed, keyed by
    /// `(level, name)`, so `getsockopt` reads back what was set.
    sockopts: HashMap<(c_int, c_int), Vec<u8>>,
    /// The transmit deadline (nanoseconds, in the `SO_TXTIME` clock) carried by the most recent
    /// `sendmsg` `SCM_TXTIME` control message — what an ETF-paced sender asked to send this at.
    tx_deadline: Option<u64>,
    /// The sim-wide socket record: options, pending error, counters, and the receive probe.
    rec: Arc<SockRec>,
    /// Owns what the record's receive probe points at.
    _probe: Arc<HostRx>,
}

#[cfg(target_os = "linux")]
impl UdpSocket {
    /// Lands each datagram that has arrived since the last look in the receive buffer.
    fn land(&mut self) {
        self.rx.land(Some(&self.rec));
    }
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct UdpSockets {
    sockets: HashMap<u64, UdpSocket>,
    descriptors: HashMap<c_int, u64>,
}

#[cfg(target_os = "linux")]
impl UdpSockets {
    fn get(&self, fd: &c_int) -> Option<&UdpSocket> {
        self.sockets.get(self.descriptors.get(fd)?)
    }

    fn get_mut(&mut self, fd: &c_int) -> Option<&mut UdpSocket> {
        let id = *self.descriptors.get(fd)?;
        self.sockets.get_mut(&id)
    }

    fn contains_key(&self, fd: &c_int) -> bool {
        self.descriptors.contains_key(fd)
    }

    fn insert(&mut self, fd: c_int, socket: UdpSocket) {
        let id = socket.rec.id.get();
        self.descriptors.insert(fd, id);
        self.sockets.insert(id, socket);
    }

    fn keys(&self) -> impl Iterator<Item = &c_int> {
        self.descriptors.keys()
    }

    fn iter(&self) -> impl Iterator<Item = (c_int, &UdpSocket)> {
        self.sockets.values().map(|socket| (socket.fd, socket))
    }

    fn alias(&mut self, oldfd: c_int, newfd: c_int) {
        let id = self.descriptors[&oldfd];
        self.descriptors.insert(newfd, id);
        self.sockets.get_mut(&id).unwrap().descriptors.insert(newfd);
    }

    fn close(&mut self, fd: c_int) -> Option<Option<UdpSocket>> {
        let id = self.descriptors.remove(&fd)?;
        let socket = self.sockets.get_mut(&id)?;
        socket.descriptors.remove(&fd);
        if let Some(&remaining) = socket.descriptors.first() {
            socket.fd = remaining;
            Some(None)
        } else {
            Some(self.sockets.remove(&id))
        }
    }
}

/// A simulated `AF_NETLINK` socket. Each request sent on it is answered at once, and the reply
/// queued here for the next receive (see [`HostState::netlink_reply`]).
#[cfg(target_os = "linux")]
struct NetlinkSocket {
    /// Whole reply messages, one per request; a partly read reply keeps its unread tail at the
    /// front.
    replies: std::collections::VecDeque<Vec<u8>>,
    responses: u64,
    rec: Arc<SockRec>,
    _probe: Arc<NetlinkRx>,
    nonblocking: bool,
    descriptors: std::collections::BTreeSet<c_int>,
    sockopts: HashMap<(c_int, c_int), Vec<u8>>,
}

#[cfg(target_os = "linux")]
struct NetlinkRx {
    host: std::sync::Weak<SimHost>,
    id: u64,
}

#[cfg(target_os = "linux")]
impl RxProbe for NetlinkRx {
    fn land(&self) {}

    fn queued(&self) -> (usize, usize) {
        let Some(host) = self.host.upgrade() else {
            return (0, 0);
        };
        let state = host.state.lock().unwrap();
        state
            .netlinks
            .sockets
            .get(&self.id)
            .map_or((0, 0), |socket| {
                (
                    socket.replies.len(),
                    socket.replies.iter().map(Vec::len).sum(),
                )
            })
    }

    fn next_len(&self) -> Option<usize> {
        let host = self.host.upgrade()?;
        host.state
            .lock()
            .unwrap()
            .netlinks
            .sockets
            .get(&self.id)?
            .replies
            .front()
            .map(Vec::len)
    }

    fn landed(&self) -> u64 {
        let Some(host) = self.host.upgrade() else {
            return 0;
        };
        host.state
            .lock()
            .unwrap()
            .netlinks
            .sockets
            .get(&self.id)
            .map_or(0, |socket| socket.responses)
    }
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct NetlinkSockets {
    sockets: HashMap<u64, NetlinkSocket>,
    descriptors: HashMap<c_int, u64>,
}

#[cfg(target_os = "linux")]
impl NetlinkSockets {
    fn get(&self, fd: &c_int) -> Option<&NetlinkSocket> {
        self.sockets.get(self.descriptors.get(fd)?)
    }

    fn get_mut(&mut self, fd: &c_int) -> Option<&mut NetlinkSocket> {
        self.sockets.get_mut(self.descriptors.get(fd)?)
    }

    fn contains_key(&self, fd: &c_int) -> bool {
        self.descriptors.contains_key(fd)
    }

    fn keys(&self) -> impl Iterator<Item = &c_int> {
        self.descriptors.keys()
    }

    fn insert(&mut self, fd: c_int, socket: NetlinkSocket) {
        let id = socket.rec.id.get();
        self.descriptors.insert(fd, id);
        self.sockets.insert(id, socket);
    }

    fn alias(&mut self, oldfd: c_int, newfd: c_int) {
        let id = self.descriptors[&oldfd];
        self.descriptors.insert(newfd, id);
        self.sockets.get_mut(&id).unwrap().descriptors.insert(newfd);
    }

    fn remove(&mut self, fd: &c_int) -> Option<Option<NetlinkSocket>> {
        let id = self.descriptors.remove(fd)?;
        let socket = self.sockets.get_mut(&id)?;
        socket.descriptors.remove(fd);
        Some(if socket.descriptors.is_empty() {
            self.sockets.remove(&id)
        } else {
            None
        })
    }
}

/// The receive queue of one of a host's datagram sockets, as its record's probe sees it. Every
/// method locks [`SimHost::state`], so the record must not call the probe while that lock is held.
/// The host is held weakly: the socket record can outlive it.
#[cfg(target_os = "linux")]
struct HostRx {
    host: std::sync::Weak<SimHost>,
    id: u64,
}

#[cfg(target_os = "linux")]
impl RxProbe for HostRx {
    fn pending_time(&self) -> bool {
        self.host.upgrade().is_some_and(|host| {
            host.state
                .lock()
                .unwrap()
                .udp
                .sockets
                .get(&self.id)
                .is_some_and(|sock| sock.rx.pending_time())
        })
    }

    fn land(&self) {
        if let Some(host) = self.host.upgrade()
            && let Some(sock) = host.state.lock().unwrap().udp.sockets.get_mut(&self.id)
        {
            sock.land();
        }
    }

    fn queued(&self) -> (usize, usize) {
        let Some(host) = self.host.upgrade() else {
            return (0, 0);
        };
        let state = host.state.lock().unwrap();
        state
            .udp
            .sockets
            .get(&self.id)
            .map_or((0, 0), |sock| sock.rx.queued())
    }

    fn next_len(&self) -> Option<usize> {
        let host = self.host.upgrade()?;
        let mut state = host.state.lock().unwrap();
        let sock = state.udp.sockets.get_mut(&self.id)?;
        sock.rx.next_len(Some(&sock.rec))
    }

    fn landed(&self) -> u64 {
        let Some(host) = self.host.upgrade() else {
            return 0;
        };
        let mut state = host.state.lock().unwrap();
        state
            .udp
            .sockets
            .get_mut(&self.id)
            .map_or(0, |sock| sock.rx.landed(Some(&sock.rec)))
    }
}

/// `PRIO_PROCESS` is `c_int` on macOS but `c_uint` on Linux; normalise once.
#[allow(clippy::unnecessary_cast)]
const PRIO_PROCESS: c_int = libc::PRIO_PROCESS as c_int;

/// The host's mutable state, all behind [`SimHost::state`]. Built from a [`HostProfile`] by
/// [`SimHost::new`]; once attached to a sim, privileges and NIC facts are read from the sim's
/// shared state (`shared`) so privilege and topology changes made through the sim are seen here.
pub(crate) struct HostState {
    cpu_count: usize,
    /// The online CPUs; the profile's override or every CPU.
    online: Vec<usize>,
    isolated: Vec<usize>,
    nohz_full: Vec<usize>,
    governor: String,
    preempt_rt: bool,
    /// The profile's capability mask, used only until the host is attached to a sim.
    caps: u64,
    /// The profile's root flag, likewise superseded by the sim's privileges once attached.
    root: bool,
    /// The latency cap currently requested through `/dev/cpu_dma_latency`, in microseconds, if the
    /// guard fd is held open.
    cpu_dma_latency: Option<i32>,
    /// Files opened through [`Fs::open`], by fd.
    open: OpenFiles<OpenFile>,
    /// Directory streams opened through [`Fs::opendir`], by fd.
    #[cfg(target_os = "linux")]
    dirs: OpenFiles<DirStream>,
    /// Scheduling state per simulated tid, created on first reference.
    threads: std::collections::BTreeMap<i32, ThreadState>,
    /// The simulated tid minted for each OS thread that has asked.
    thread_ids: HashMap<std::thread::ThreadId, i32>,
    /// The next tid to mint, starting at [`TID_BASE`].
    next_tid: i32,
    /// The simulated tid of each `pthread_t` a `pthread_setschedparam` named or whose thread asked
    /// for its tid, so the POSIX thread calls and the tid-based ones see one state.
    #[cfg(target_os = "linux")]
    pthreads: HashMap<u64, i32>,
    nics: HashMap<String, NicState>,
    default_qdisc: String,
    /// PHC index to its offset from `CLOCK_REALTIME` in ns: the profile's clocks plus each NIC's
    /// `ptp_index`.
    #[cfg(target_os = "linux")]
    ptp_clocks: std::collections::BTreeMap<u32, i64>,
    /// The profile's PTP clock capabilities, by index.
    #[cfg(target_os = "linux")]
    ptp_caps: std::collections::BTreeMap<u32, PtpCaps>,
    /// The last automatic qdisc handle handed out (`qdisc_alloc_handle` in
    /// net/sched/sch_api.c starts from `8000:` and steps by one major number).
    #[cfg(target_os = "linux")]
    qdisc_auto: u32,
    /// macOS thread scheduling, keyed by [`mac_thread_id`]: (policy, priority).
    #[cfg(target_os = "macos")]
    mac_threads: HashMap<u64, (c_int, c_int)>,
    /// Datagram sockets the host serves, by fd.
    #[cfg(target_os = "linux")]
    udp: UdpSockets,
    /// Netlink sockets the host serves, by fd.
    #[cfg(target_os = "linux")]
    netlinks: NetlinkSockets,
    /// Bound datagram sockets keyed by full address, so several IPs can share a port (snare 1.x's
    /// `add_ip_addr`) and a wildcard `0.0.0.0`/`::` bind coexists with specific ones.
    #[cfg(target_os = "linux")]
    bound: HashMap<std::net::SocketAddr, c_int>,
    /// Where the round-robin search for a free ephemeral port resumes.
    #[cfg(target_os = "linux")]
    next_ephemeral: u16,
    /// The isolated environment. Values are heap `CString`s whose pointers `getenv` hands out.
    env: HashMap<std::ffi::CString, std::ffi::CString>,
    #[cfg(target_os = "linux")]
    inherited_threads: HashMap<u64, ThreadState>,
    /// The sim this host serves; empty until [`SimHost::attach_fabric`].
    shared: std::sync::Weak<crate::scope::SimShared>,
}

impl HostState {
    #[cfg(target_os = "linux")]
    fn socket_rec(&self, fd: c_int) -> Option<Arc<SockRec>> {
        self.udp
            .get(&fd)
            .map(|socket| socket.rec.clone())
            .or_else(|| self.netlinks.get(&fd).map(|socket| socket.rec.clone()))
    }

    #[cfg(target_os = "linux")]
    fn remove_socket(&mut self, fd: c_int) {
        if self.netlinks.remove(&fd).is_none()
            && let Some(socket) = self.udp.close(fd).flatten()
            && let Some(local) = socket.local
        {
            self.bound.remove(&local);
        }
    }

    /// Moves bound datagram socket `fd` from `from` to `to` in `bound`, as the kernel rehashes a
    /// socket whose local address a connect or disconnect changed; an address another socket
    /// holds leaves it where it is.
    #[cfg(target_os = "linux")]
    fn rehash(&mut self, fd: c_int, from: std::net::SocketAddr, to: std::net::SocketAddr) {
        if from == to || self.bound.contains_key(&to) {
            return;
        }
        self.bound.remove(&from);
        self.bound.insert(to, fd);
        if let Some(sock) = self.udp.get_mut(&fd) {
            sock.local = Some(to);
            sock.rec.set_local(to);
        }
    }

    /// Dissolves datagram socket `fd`'s association; see [`Net::connect`].
    #[cfg(target_os = "linux")]
    fn udp_disconnect(&mut self, fd: c_int) {
        let Some(sock) = self.udp.get_mut(&fd) else {
            return;
        };
        sock.peer = None;
        sock.rec.set_peer(None);
        let Some(bound) = sock.local else {
            return;
        };
        let requested = sock.requested;
        let ip = requested
            .map(|r| r.ip())
            .filter(|ip| !ip.is_unspecified())
            .unwrap_or(match bound {
                std::net::SocketAddr::V4(_) => std::net::Ipv4Addr::UNSPECIFIED.into(),
                std::net::SocketAddr::V6(_) => std::net::Ipv6Addr::UNSPECIFIED.into(),
            });
        if requested.is_some_and(|r| r.port() != 0) {
            self.rehash(fd, bound, std::net::SocketAddr::new(ip, bound.port()));
            return;
        }
        sock.local = None;
        sock.rec.state().local =
            Some(std::net::SocketAddr::new(ip, 0)).filter(|a| !a.ip().is_unspecified());
        self.bound.remove(&bound);
    }

    #[cfg(target_os = "linux")]
    fn alias_socket(&mut self, oldfd: c_int, newfd: c_int) {
        if self.udp.contains_key(&oldfd) {
            self.udp.alias(oldfd, newfd);
        } else {
            self.netlinks.alias(oldfd, newfd);
        }
    }

    /// The topology's current view of interface `name`, or `None` if it has no such interface
    /// or the host is not attached.
    fn topo_nic(&self, name: &str) -> Option<NicSnapshot> {
        self.shared.upgrade()?.nic(name)
    }

    /// Every interface in the topology, in ifindex order (the order rtnetlink dumps and
    /// `NET_RT_IFLIST2` list them).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn topo_nics(&self) -> Vec<NicSnapshot> {
        let mut nics = self.shared.upgrade().map(|s| s.nics()).unwrap_or_default();
        nics.sort_by_key(|n| n.index);
        nics
    }

    /// The RFC 2863 operational state sysfs and rtnetlink report: down while administratively
    /// down, up with carrier (loopback reports unknown, as the kernel's does: its driver never
    /// sets an operstate, leaving `IF_OPER_UNKNOWN`; Documentation/networking/operstates.rst), and
    /// otherwise the state the host profile gave the interface when it is not "up".
    fn operstate(&self, nic: &NicSnapshot) -> String {
        if !nic.spec.admin_up {
            return "down".to_string();
        }
        if nic.spec.carrier {
            let unknown = nic.loopback
                || self
                    .nics
                    .get(&nic.spec.name)
                    .is_some_and(|n| n.carrier == Some(true) && n.operstate == "unknown");
            return if unknown { "unknown" } else { "up" }.to_string();
        }
        self.nics
            .get(&nic.spec.name)
            .filter(|n| {
                n.operstate != "up" && !(n.carrier == Some(true) && n.operstate == "unknown")
            })
            .map(|n| n.operstate.clone())
            .unwrap_or_else(|| "down".to_string())
    }

    /// The error a read of a sysfs attribute fails with, as net-sysfs's `carrier_show` returns
    /// EINVAL for an interface that is not running (net/core/net-sysfs.c, `carrier_show`).
    fn read_error(&self, path: &Path) -> Option<c_int> {
        let name = path
            .to_str()?
            .strip_prefix("/sys/class/net/")?
            .strip_suffix("/carrier")?;
        let nic = self.topo_nic(name)?;
        (!nic.spec.admin_up).then_some(libc::EINVAL)
    }

    /// The contents of the sysfs or procfs file at `path` as the kernel would render it (one
    /// value and a trailing newline), or `None` if the host does not model that file. Computed
    /// from current state on each call; [`Fs::open`] snapshots it.
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
            // The PREEMPT_RT patch set exports /sys/kernel/realtime = 1 (kernel/ksysfs.c under
            // CONFIG_PREEMPT_RT in linux-stable-rt, e.g. v6.6-rt); mainline ksysfs.c has no such
            // attribute, so a mainline PREEMPT_RT kernel does not show it.
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

    /// The files [`render`](Self::render) does not match by exact path: sysctls, `/proc/self/status`,
    /// per-interface `/sys/class/net/<if>/*` attributes and per-CPU `/sys/devices/system/cpu/cpuN/*`.
    fn render_dynamic(&self, p: &str) -> Option<Vec<u8>> {
        // Documentation/admin-guide/sysctl/net.rst, default_qdisc.
        if p == "/proc/sys/net/core/default_qdisc" {
            return Some(with_newline(self.default_qdisc.clone()));
        }
        // Documentation/networking/ip-sysctl.rst, tcp_syn_retries; the value is the sim's limit.
        if p == "/proc/sys/net/ipv4/tcp_syn_retries" {
            let retries = self.shared.upgrade()?.sys.limits().tcp_syn_retries;
            return Some(with_newline(retries.to_string()));
        }
        if p == "/proc/sys/net/ipv4/tcp_syn_linear_timeouts" {
            let linear = self.shared.upgrade()?.sys.limits().tcp_syn_linear_timeouts;
            return Some(with_newline(linear.to_string()));
        }
        if cfg!(target_os = "linux")
            && (p == "/proc/self/status" || p == "/proc/thread-self/status")
        {
            return Some(self.status().into_bytes());
        }
        if let Some(rest) = p.strip_prefix("/sys/class/net/")
            && let Some((name, attr)) = rest.split_once('/')
        {
            let nic = self.topo_nic(name)?;
            // Documentation/ABI/testing/sysfs-class-net; `flags` is dev->flags
            // (net/core/net-sysfs.c), which never holds the operational IFF_RUNNING /
            // IFF_LOWER_UP bits: netif_get_flags (net/core/dev.c) derives those on read, and
            // sysfs does not call it.
            let c = &nic.counters;
            let text = match attr {
                "mtu" => nic.spec.mtu.to_string(),
                "ifindex" => nic.index.to_string(),
                "operstate" => self.operstate(&nic),
                "carrier" => u8::from(nic.spec.carrier).to_string(),
                "flags" => {
                    // 0x10000 is IFF_LOWER_UP (include/uapi/linux/if.h), absent from libc.
                    let operational = (libc::IFF_RUNNING | 0x10000) as u32;
                    format!("{:#x}", crate::ifaddrs::flags(&nic) & !operational)
                }
                "address" => {
                    let m = nic.hw_addr();
                    format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        m[0], m[1], m[2], m[3], m[4], m[5]
                    )
                }
                "statistics/rx_packets" => c.rx_packets.to_string(),
                "statistics/tx_packets" => c.tx_packets.to_string(),
                "statistics/rx_bytes" => c.rx_bytes.to_string(),
                "statistics/tx_bytes" => c.tx_bytes.to_string(),
                "statistics/rx_errors" => c.rx_errors.to_string(),
                "statistics/tx_errors" => c.tx_errors.to_string(),
                "statistics/rx_dropped" => c.rx_dropped.to_string(),
                "statistics/tx_dropped" => c.tx_dropped.to_string(),
                "statistics/multicast" => c.multicast.to_string(),
                "statistics/tx_carrier_errors" => c.tx_carrier_errors.to_string(),
                "statistics/rx_nohandler" => c.rx_nohandler.to_string(),
                // net/core/net-sysfs.c threaded_show: dev->threaded in decimal.
                "threaded" => {
                    u8::from(self.nics.get(name).is_some_and(|n| n.ethtool.threaded_napi))
                        .to_string()
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

    /// The profile interface whose `threaded` attribute `path` is, if it is one.
    fn threaded_attr(&self, path: &Path) -> Option<String> {
        let name = path
            .to_str()?
            .strip_prefix("/sys/class/net/")?
            .strip_suffix("/threaded")?;
        self.nics.contains_key(name).then(|| name.to_string())
    }

    /// A write to `/sys/class/net/<nic>/threaded`, as net/core/net-sysfs.c `netdev_store` and
    /// `modify_napi_threaded` (Linux 6.12) take it: `EPERM` without `CAP_NET_ADMIN`, `EINVAL`
    /// for text `kstrtoul` (base 0, one trailing newline) does not parse, `EOPNOTSUPP` for a
    /// value other than 0 or 1.
    fn store_threaded(&mut self, nic: &str, text: &[u8]) -> Result<(), c_int> {
        if !self.has_cap(CAP_NET_ADMIN) {
            return Err(libc::EPERM);
        }
        let text = std::str::from_utf8(text).map_err(|_| libc::EINVAL)?;
        let text = text.strip_suffix('\n').unwrap_or(text);
        let value =
            if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16)
            } else if text.len() > 1 && text.starts_with('0') {
                u64::from_str_radix(&text[1..], 8)
            } else {
                text.strip_prefix('+').unwrap_or(text).parse()
            }
            .map_err(|_| libc::EINVAL)?;
        if value > 1 {
            return Err(libc::EOPNOTSUPP);
        }
        self.nics.get_mut(nic).unwrap().ethtool.threaded_napi = value == 1;
        Ok(())
    }

    /// The credential and capability lines of proc(5)'s `/proc/<pid>/status` (man 5
    /// proc_pid_status): real/effective/saved/filesystem uid and gid all equal, and the
    /// permitted, effective and bounding sets equal to the granted capabilities, as 16 hex digits.
    /// The gid mirrors the uid, a snare simplification.
    fn status(&self) -> String {
        let privileges = self.privileges();
        let uid = if privileges.root { 0 } else { UNPRIVILEGED_UID };
        let caps = privileges.cap_mask();
        format!(
            "Name:\tsnare\nState:\tR (running)\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n\
             Gid:\t{uid}\t{uid}\t{uid}\t{uid}\nCapInh:\t{:016x}\nCapPrm:\t{caps:016x}\n\
             CapEff:\t{caps:016x}\nCapBnd:\t{caps:016x}\nCapAmb:\t{:016x}\n",
            0, 0
        )
    }

    /// Whether `access` finds `path`: a rendered file or `/dev/cpu_dma_latency`. `/dev/ptp<N>` is
    /// not listed, so its `access` falls through to the real OS.
    fn known_file(&self, path: &Path) -> bool {
        self.render(path).is_some() || path == Path::new("/dev/cpu_dma_latency")
    }

    /// The directory listing for a synthetic `/sys/class/net/<if>/{queues,device/msi_irqs}` path,
    /// or `None` if the path is not a modelled directory. See
    /// Documentation/ABI/testing/sysfs-class-net-queues (rx-N/tx-N) and, for `device/msi_irqs`,
    /// Documentation/ABI/testing/sysfs-bus-pci.
    #[cfg(target_os = "linux")]
    fn dir_entries(&self, path: &Path) -> Option<Vec<DirEntry>> {
        let entry = |name: &str| {
            let node = match name {
                "." => path.to_owned(),
                ".." => path.parent().unwrap_or(path).to_owned(),
                _ => path.join(name),
            };
            DirEntry {
                name: name.as_bytes().to_vec(),
                ino: ino_of(&node),
                dtype: libc::DT_DIR,
            }
        };
        let mut entries = vec![entry("."), entry("..")];
        if path == Path::new("/sys/class/net") {
            let mut names: Vec<_> = self.nics.keys().collect();
            names.sort();
            entries.extend(names.into_iter().map(|name| DirEntry {
                name: name.as_bytes().to_vec(),
                ino: ino_of(&path.join(name)),
                dtype: libc::DT_LNK,
            }));
            return Some(entries);
        }
        let rest = path.to_str()?.strip_prefix("/sys/class/net/")?.to_string();
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
                entries.push(DirEntry {
                    name: irq.to_string().into_bytes(),
                    ino: ino_of(&path.join(irq.to_string())),
                    dtype: libc::DT_REG,
                });
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
            "/proc/self/status",
            "/proc/thread-self/status",
        ];
        let Some(p) = path.to_str() else {
            return false;
        };
        PREFIXES
            .iter()
            .any(|pre| p == *pre || p.starts_with(&format!("{pre}/")))
    }

    /// The calling OS thread's simulated tid, minted on first use. Tids are never reused, so a
    /// thread that exits leaves its scheduling state behind.
    fn current_tid(&mut self) -> i32 {
        let id = std::thread::current().id();
        if let Some(&tid) = self.thread_ids.get(&id) {
            return tid;
        }
        #[cfg(target_os = "linux")]
        let tid = {
            let me = unsafe { libc::pthread_self() } as u64;
            match self.pthreads.get(&me) {
                Some(&tid) => tid,
                None => {
                    let tid = self.mint_tid();
                    self.pthreads.insert(me, tid);
                    tid
                }
            }
        };
        #[cfg(not(target_os = "linux"))]
        let tid = self.mint_tid();
        self.thread_ids.insert(id, tid);
        self.threads.entry(tid).or_default();
        tid
    }

    /// A fresh simulated tid.
    fn mint_tid(&mut self) -> i32 {
        let tid = self.next_tid;
        self.next_tid += 1;
        tid
    }

    /// The simulated tid of POSIX thread `thread`: the caller's own, or one minted for a thread
    /// that has not asked yet and adopted by it when it does.
    #[cfg(target_os = "linux")]
    fn pthread_tid(&mut self, thread: u64) -> i32 {
        if thread == unsafe { libc::pthread_self() } as u64 {
            return self.current_tid();
        }
        if let Some(&tid) = self.pthreads.get(&thread) {
            return tid;
        }
        let tid = self.mint_tid();
        self.pthreads.insert(thread, tid);
        self.threads.entry(tid).or_default();
        tid
    }

    /// The scheduling state of `tid` as the permission rules read it.
    #[cfg(target_os = "linux")]
    fn sched_state(&self, tid: i32) -> crate::proclimits::SchedState {
        let t = &self.threads[&tid];
        crate::proclimits::SchedState {
            policy: t.policy & !libc::SCHED_RESET_ON_FORK,
            rt_priority: t.rt_priority,
            nice: t.nice,
            reset_on_fork: t.policy & libc::SCHED_RESET_ON_FORK != 0,
        }
    }

    /// Applies `sched_setscheduler(policy, {priority})` (or `sched_setparam` with
    /// `SETPARAM_POLICY`) to `tid` under the sim's privileges (see
    /// [`crate::proclimits::sched_setscheduler`]).
    #[cfg(target_os = "linux")]
    fn set_sched(&mut self, tid: i32, policy: c_int, priority: c_int) -> Option<HostResult> {
        let cur = self.sched_state(tid);
        match crate::proclimits::sched_setscheduler(&self.privileges(), cur, policy, priority) {
            Ok(new) => {
                let t = self.threads.get_mut(&tid).unwrap();
                t.policy = new.policy
                    | if new.reset_on_fork {
                        libc::SCHED_RESET_ON_FORK
                    } else {
                        0
                    };
                t.rt_priority = new.rt_priority;
                ok(0)
            }
            Err(e) => err(e),
        }
    }

    /// Resolve a scheduling `pid` argument (`0` = the caller, man 2 sched_setscheduler) to a tid
    /// with a state entry. Any other value is accepted as a tid and given a default entry; the
    /// host never reports `ESRCH`.
    fn resolve(&mut self, pid: i32) -> i32 {
        let tid = if pid == 0 { self.current_tid() } else { pid };
        self.threads.entry(tid).or_default();
        tid
    }

    /// Whether the code under test holds `cap`: the sim's privileges once the host serves one,
    /// so `set_privileges` and the host's gates agree.
    fn has_cap(&self, cap: c_int) -> bool {
        match self.shared.upgrade() {
            Some(shared) => shared.sys.has_cap(cap),
            None => (0..64).contains(&cap) && self.caps & (1u64 << cap) != 0,
        }
    }

    /// The process's privileges: the sim's once attached, else the profile's.
    fn privileges(&self) -> crate::Privileges {
        match self.shared.upgrade() {
            Some(shared) => shared.sys.privileges(),
            None => crate::Privileges::from_caps(self.caps, self.root),
        }
    }

    /// Build the reply to a netlink request. `RTM_GETLINK` yields a link dump, or with no
    /// `NLM_F_DUMP` bit the one link [`getlink_one`](Self::getlink_one) picks, `RTM_GETQDISC`
    /// every interface's qdiscs, `RTM_NEWQDISC`/`RTM_DELQDISC` change them (see
    /// [`change_qdisc`](Self::change_qdisc)) and answer with an `NLMSG_ERROR` carrying the error,
    /// or 0 when `NLM_F_ACK` asked for an ack, or nothing; `GENL_ID_CTRL` a genetlink family
    /// lookup; any other type yields a bare `NLMSG_DONE` (harmless for the requests this models).
    /// Protocol: man 7 netlink / man 7 rtnetlink; message and attribute types in
    /// `<linux/rtnetlink.h>`. `RTM_GETADDR` and `RTM_GETROUTE` dump the topology's addresses and
    /// routes. Only the first message of `req` is read, and `NLM_F_DUMP` is inspected for
    /// `RTM_GETLINK` alone: every other `GET` is answered as a dump.
    ///
    /// The header fields are read at their `struct nlmsghdr` offsets (include/uapi/linux/netlink.h):
    /// `nlmsg_type` at 4, `nlmsg_seq` at 8; the byte at 16 is the first byte of the payload, the
    /// family of an `rtgenmsg`/`ifinfomsg`/`ifaddrmsg`/`rtmsg`.
    #[cfg(target_os = "linux")]
    fn netlink_reply(&mut self, req: &[u8]) -> Vec<u8> {
        // include/uapi/linux/rtnetlink.h; GENL_ID_CTRL = NLMSG_MIN_TYPE in
        // include/uapi/linux/genetlink.h.
        const RTM_GETLINK: u16 = 18;
        const RTM_GETADDR: u16 = 22;
        const RTM_GETROUTE: u16 = 26;
        const RTM_NEWQDISC: u16 = 36;
        const RTM_DELQDISC: u16 = 37;
        const RTM_GETQDISC: u16 = 38;
        const GENL_ID_CTRL: u16 = 16;
        const NLMSG_ERROR: u16 = 2;
        const NLM_F_ACK: u16 = 4;
        const NLM_F_DUMP: u16 = 0x300;
        let (ty, seq) = if req.len() >= 12 {
            (
                u16::from_ne_bytes([req[4], req[5]]),
                u32::from_ne_bytes([req[8], req[9], req[10], req[11]]),
            )
        } else {
            (0, 0)
        };
        let family = req.get(16).copied().unwrap_or(0);
        match ty {
            RTM_GETLINK if u16::from_ne_bytes([req[6], req[7]]) & NLM_F_DUMP == 0 => {
                match self.getlink_one(req) {
                    Ok(reply) => reply,
                    Err(errno) => {
                        let mut body = Vec::new();
                        body.extend_from_slice(&(-errno).to_ne_bytes());
                        body.extend_from_slice(&req[..req.len().min(16)]);
                        nl_message(NLMSG_ERROR, 0, seq, &body)
                    }
                }
            }
            RTM_GETLINK => {
                let nics = self.topo_nics();
                let links: Vec<(&NicSnapshot, String)> =
                    nics.iter().map(|n| (n, self.operstate(n))).collect();
                build_getlink_dump(&links, seq)
            }
            RTM_GETADDR => build_getaddr_dump(&self.topo_nics(), family, seq),
            RTM_GETROUTE => {
                let routes = self
                    .shared
                    .upgrade()
                    .map(|s| s.live_routes())
                    .unwrap_or_default();
                build_getroute_dump(&routes, family, seq)
            }
            RTM_GETQDISC => {
                let mut nics: Vec<&NicState> = self.nics.values().collect();
                nics.sort_by_key(|n| n.ifindex);
                build_getqdisc_dump(&nics, seq)
            }
            RTM_NEWQDISC | RTM_DELQDISC => {
                let flags = u16::from_ne_bytes([req[6], req[7]]);
                let result = self.change_qdisc(ty == RTM_NEWQDISC, flags, req);
                if result.is_ok() && flags & NLM_F_ACK == 0 {
                    return Vec::new();
                }
                // NLMSG_ERROR (include/uapi/linux/netlink.h): the negated errno, 0 for an ack,
                // then the request's header (netlink_ack in net/netlink/af_netlink.c).
                let mut body = Vec::new();
                body.extend_from_slice(&(-result.err().unwrap_or(0)).to_ne_bytes());
                body.extend_from_slice(&req[..req.len().min(16)]);
                nl_message(NLMSG_ERROR, 0, seq, &body)
            }
            GENL_ID_CTRL => build_genl_ctrl_reply(req, seq),
            _ => build_getlink_dump(&[], seq),
        }
    }

    /// The reply to an `RTM_GETLINK` without `NLM_F_DUMP`: the one `RTM_NEWLINK` of the interface
    /// named by the `ifinfomsg`'s `ifi_index` (offset 20), or when that is 0 by an `IFLA_IFNAME`
    /// attribute, with no `NLM_F_MULTI` and no `NLMSG_DONE`. `ENODEV` names no interface, and a
    /// request naming none at all, or too short for an `ifinfomsg`, is `EINVAL` (`rtnl_getlink`
    /// and `rtnl_valid_getlink_req` in net/core/rtnetlink.c).
    #[cfg(target_os = "linux")]
    fn getlink_one(&self, req: &[u8]) -> Result<Vec<u8>, c_int> {
        const IFLA_IFNAME: u16 = 3;
        if req.len() < 32 {
            return Err(libc::EINVAL);
        }
        let seq = u32::from_ne_bytes(req[8..12].try_into().unwrap());
        let index = i32::from_ne_bytes(req[20..24].try_into().unwrap());
        let len = (u32::from_ne_bytes(req[0..4].try_into().unwrap()) as usize).clamp(32, req.len());
        let name = find_nlattr(&req[32..len], IFLA_IFNAME)
            .map(|data| data.split(|&b| b == 0).next().unwrap_or_default());
        let nics = self.topo_nics();
        let nic = if index > 0 {
            nics.iter().find(|n| n.index as i32 == index)
        } else if let Some(name) = name {
            nics.iter().find(|n| n.spec.name.as_bytes() == name)
        } else {
            return Err(libc::EINVAL);
        }
        .ok_or(libc::ENODEV)?;
        Ok(getlink_message(nic, &self.operstate(nic), 0, seq))
    }

    /// Queues the reply to netlink request `req` on socket `fd`, if the kernel would send one.
    #[cfg(target_os = "linux")]
    fn queue_netlink_reply(&mut self, fd: c_int, req: &[u8]) -> Option<Arc<SockRec>> {
        let reply = self.netlink_reply(req);
        if reply.is_empty() {
            return None;
        }
        let socket = self.netlinks.get_mut(&fd).unwrap();
        socket.replies.push_back(reply);
        socket.responses += 1;
        Some(socket.rec.clone())
    }

    /// Applies an `RTM_NEWQDISC` (`new`) or `RTM_DELQDISC` (see [`crate::qdisc`]): `EPERM` without
    /// `CAP_NET_ADMIN` (net/core/rtnetlink.c `rtnetlink_rcv_msg`), `ENODEV` for an index no
    /// profile interface has, then the qdisc rules. The `struct tcmsg` after the 16-byte header
    /// holds `tcm_ifindex` at 20, `tcm_handle` at 24 and `tcm_parent` at 28; attributes start at
    /// 36.
    #[cfg(target_os = "linux")]
    fn change_qdisc(&mut self, new: bool, flags: u16, req: &[u8]) -> Result<(), c_int> {
        if !self.has_cap(CAP_NET_ADMIN) {
            return Err(libc::EPERM);
        }
        if req.len() < 36 {
            return Err(libc::EINVAL);
        }
        let word = |at: usize| u32::from_ne_bytes(req[at..at + 4].try_into().unwrap());
        let (ifindex, handle, parent) = (word(20), word(24), word(28));
        let len = (word(0) as usize).clamp(36, req.len());
        let attrs = &req[36..len];
        let default_qdisc = self.default_qdisc.clone();
        let mut auto = self.qdisc_auto;
        let nic = self
            .nics
            .values_mut()
            .find(|n| n.ifindex == ifindex)
            .ok_or(libc::ENODEV)?;
        let dev = crate::qdisc::Device {
            num_tx_queues: nic.num_tx_queues,
            real_tx_queues: nic.tx_queues,
            no_queue: nic.no_queue,
            default_qdisc: &default_qdisc,
            etf_offload: nic.ethtool.etf_offload.as_deref(),
        };
        let result = if new {
            nic.qdiscs
                .modify(&dev, &mut auto, flags, handle, parent, attrs)
        } else {
            nic.qdiscs.delete(&dev, handle, parent)
        };
        self.qdisc_auto = auto;
        result
    }

    /// Pick a free ephemeral port (49152..=65535), or `None` if the whole range is bound.
    ///
    /// The range is IANA's dynamic/private range (RFC 6335 §6), a snare choice; Linux's default
    /// `ip_local_port_range` is 32768–60999 (Documentation/networking/ip-sysctl.rst). Ports are
    /// handed out round-robin from `next_ephemeral` rather than hashed as the kernel does, which
    /// keeps them deterministic. A port counts as taken when bound on the same family at the same
    /// address, or at any address when `ip` is the wildcard.
    #[cfg(target_os = "linux")]
    fn alloc_ephemeral(&mut self, ip: std::net::IpAddr) -> Option<u16> {
        for _ in 49152..=65535u32 {
            let p = self.next_ephemeral;
            self.next_ephemeral = if p == u16::MAX { 49152 } else { p + 1 };
            let taken = self.bound.keys().any(|a| {
                a.port() == p
                    && a.is_ipv4() == ip.is_ipv4()
                    && (a.ip() == ip || ip.is_unspecified())
            });
            if !taken {
                return Some(p);
            }
        }
        None
    }

    /// The datagram sockets a message to `dest` could reach: for a multicast group the sockets
    /// on the port that take it (`SockRec::takes_group`, given whether the host `joined` the
    /// group), else every socket bound on the port. The topology picks among them. Sorted by fd
    /// so fan-out is deterministic.
    #[cfg(target_os = "linux")]
    fn udp_cands(
        &self,
        dest: std::net::SocketAddr,
        joined: bool,
    ) -> Vec<crate::netif::Cand<c_int>> {
        let mut out: Vec<crate::netif::Cand<c_int>> = self
            .udp
            .iter()
            .filter_map(|(fd, s)| {
                let local = s.local.filter(|l| l.port() == dest.port())?;
                if dest.ip().is_multicast() && !s.rec.takes_group(local, dest.ip(), joined) {
                    return None;
                }
                Some(crate::netif::Cand {
                    addr: local,
                    endpoint: false,
                    device: s.rec.state().device.as_ref().map(|d| d.0),
                    q: fd,
                })
            })
            .collect();
        out.sort_by_key(|c| c.q);
        out
    }

    /// Queues each copy fan-out decided on for the host's sockets. A copy with no delays was lost
    /// on the wire and is only counted; one with several delays was duplicated by the link
    /// policy. `now` is the virtual send time each arrival is stamped from.
    #[cfg(target_os = "linux")]
    fn udp_land(
        &mut self,
        copies: Vec<crate::netif::Copy<c_int>>,
        data: &[u8],
        src: std::net::SocketAddr,
        now: std::time::Duration,
    ) {
        for copy in copies {
            if let Some(s) = self.udp.get_mut(&copy.q) {
                if copy.delays.is_empty() {
                    s.rec.count_wire_lost();
                } else {
                    s.rec.note_rx_nic(copy.nic.as_deref());
                }
                let port = s.local.map_or(0, |l| l.port());
                for delay in copy.delays {
                    let mut dg = in_flight(data.to_vec(), src, now, delay, copy.via.clone());
                    dg.mtu = copy.mtu;
                    dg.hw = copy.nic.as_deref().and_then(|nic| {
                        nic_hw_stamp(
                            &self.nics,
                            &self.ptp_clocks,
                            nic,
                            dg.timestamp,
                            Some((port, data)),
                        )
                    });
                    s.rx.push(dg, Some(&s.rec));
                }
            }
        }
    }
}

/// `HWTSTAMP_FILTER_*` values that stamp every received packet: `ALL`, `SOME` (the driver's
/// choice; the sim's NICs stamp all).
#[cfg(target_os = "linux")]
const STAMP_ALL_FILTERS: [c_int; 2] = [1, 2];
/// UDP port 319, where PTP event messages go (IEEE 1588 annex D).
#[cfg(target_os = "linux")]
const PTP_EVENT_PORT: u16 = 319;

#[cfg(target_os = "linux")]
fn udp_hw_filter(filter: c_int, port: u16, data: &[u8]) -> bool {
    if STAMP_ALL_FILTERS.contains(&filter) {
        return true;
    }
    if filter == 15 {
        return port == 123;
    }
    if port != PTP_EVENT_PORT || data.len() < 34 {
        return false;
    }
    let version = data[1] & 0x0f;
    let message = if version == 1 {
        data[32]
    } else {
        data[0] & 0x0f
    };
    match (filter, version) {
        (3, 1) => message <= 1,
        (4, 1) => message == 0,
        (5, 1) => message == 1,
        (6 | 12, 2) => message <= 3,
        (7 | 13, 2) => message == 0,
        (8 | 14, 2) => message == 1,
        _ => false,
    }
}

/// The hardware stamp NIC `name` takes of a packet passing it at `real` (`CLOCK_REALTIME`), read
/// on its PTP clock (`phc_index`'s offset from realtime; realtime itself without one): a sent
/// packet (`rx_port` `None`) when the driver's `tx_type` is on, a received one to UDP port
/// `rx_port` when its `rx_filter` covers it. `None`
/// for a NIC without hardware timestamping. The configuration consulted is what `SIOCSHWTSTAMP`
/// applied (`apply_hwtstamp`), as a driver's transmit and receive paths consult theirs.
#[cfg(target_os = "linux")]
fn nic_hw_stamp(
    nics: &HashMap<String, NicState>,
    ptp_clocks: &std::collections::BTreeMap<u32, i64>,
    name: &str,
    real: std::time::Duration,
    rx_port: Option<(u16, &[u8])>,
) -> Option<std::time::Duration> {
    let nic = nics.get(name).filter(|n| n.hwtstamp_supported)?;
    let [_, tx_type, rx_filter] = nic.hwtstamp;
    let stamps = match rx_port {
        None => tx_type != 0,
        Some((port, data)) => udp_hw_filter(rx_filter, port, data),
    };
    if !stamps {
        return None;
    }
    let offset = nic
        .ethtool
        .phc_index
        .and_then(|i| ptp_clocks.get(&i))
        .copied()
        .unwrap_or(0);
    let nanos = (real.as_nanos() as i128 + i128::from(offset)).max(0);
    Some(std::time::Duration::from_nanos(nanos as u64))
}

#[cfg(target_os = "linux")]
fn udp_onestep_stamp(tx_type: c_int, port: u16, data: &[u8]) -> bool {
    if port != 319 || data.len() < 44 || data[1] & 0xf != 2 || data[6] & 2 != 0 {
        return false;
    }
    let message = data[0] & 0xf;
    message == 0 && matches!(tx_type, 2 | 3) || message == 3 && tx_type == 3 && data.len() >= 54
}

/// A simulated host serving `fast-talker`'s tuning calls from an in-memory [`HostProfile`].
pub struct SimHost {
    /// All mutable host state; see the module docs for the lock-ordering rules.
    state: Mutex<HostState>,
    /// A real fd on `/dev/null`, opened outside interposition, that [`reserve_fd`](Self::reserve_fd)
    /// duplicates to mint fds; negative if the open failed.
    devnull: c_int,
    /// The host's virtual clock, also installed as a layer by [`clock_layer`](Self::clock_layer).
    clock: Arc<Clock>,
    isolate_env: bool,
    /// The registries of the `Sim` this host serves, so its datagram sockets and that sim's
    /// tester endpoints reach each other.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    registries: Mutex<Option<Arc<crate::fabric::Registries>>>,
    /// A weak handle to this host, set by `attach_fabric`, for the receive probes of its sockets.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    me: std::sync::OnceLock<std::sync::Weak<SimHost>>,
    /// The interfaces and routes the profile declared, handed to the sim to build its topology.
    topology: (Vec<(NicSpec, NicCounters)>, Vec<Route>),
    uname: Uname,
}

impl SimHost {
    /// Joins this host's datagram sockets to the tester endpoints of the `Sim` it serves, both
    /// ways: what its sockets send reaches the testers, and what testers send reaches its sockets.
    /// Also seeds the sim's privileges from the profile, after which the sim's are authoritative.
    /// Until it runs, the host serves no sockets (`socket` fails with `EAFNOSUPPORT`).
    pub(crate) fn attach_fabric(self: &Arc<Self>, regs: Arc<crate::fabric::Registries>) {
        let backend: std::sync::Weak<dyn crate::fabric::ForeignUdp> = Arc::downgrade(self) as _;
        crate::fabric::attach_foreign_udp(&regs, backend);
        let mut state = self.state.lock().unwrap();
        let privileges = crate::Privileges::from_caps(state.caps, state.root);
        regs.shared.sys.set_privileges(|p| *p = privileges);
        state.shared = Arc::downgrade(&regs.shared);
        drop(state);
        *self.registries.lock().unwrap() = Some(regs);
        let _ = self.me.set(Arc::downgrade(self));
    }

    /// The attached sim's shared state, or `None` before [`attach_fabric`](Self::attach_fabric).
    #[cfg(target_os = "linux")]
    fn shared(&self) -> Option<Arc<crate::scope::SimShared>> {
        let regs = self.registries.lock().unwrap();
        regs.as_ref().map(|regs| regs.shared.clone())
    }

    /// The record of the host's datagram or netlink socket on `fd`, and whether it is a netlink
    /// one. A netlink socket answers the socket-level options of [`crate::limits::sockopt`] and
    /// `SO_ERROR`, and stores any other option as it is set.
    #[cfg(target_os = "linux")]
    fn sockopt_rec(&self, fd: c_int) -> Option<(Arc<SockRec>, bool)> {
        let state = self.state.lock().unwrap();
        if let Some(netlink) = state.netlinks.get(&fd) {
            return Some((netlink.rec.clone(), true));
        }
        Some((state.udp.get(&fd)?.rec.clone(), false))
    }

    /// Mints a socket fd served by the host, with its record. Without an attached sim there is
    /// nothing to route through, so the socket is refused with `EAFNOSUPPORT` (a snare choice).
    #[cfg(target_os = "linux")]
    fn open_socket(&self, kind: SocketKind) -> Result<(c_int, Arc<SockRec>), c_int> {
        let shared = self.shared().ok_or(libc::EAFNOSUPPORT)?;
        let fd = self
            .reserve_fd()
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EMFILE))?;
        Ok((fd, shared.new_socket(kind, fd)))
    }

    #[cfg(target_os = "linux")]
    fn detach_socket(&self, fd: c_int, replaced: bool) -> Option<()> {
        let rec = {
            let mut state = self.state.lock().unwrap();
            let rec = state.socket_rec(fd)?;
            state.remove_socket(fd);
            rec
        };
        if replaced {
            if let Some(shared) = self.shared() {
                shared.sockets.fd_replaced(fd, &rec, shared.stamp());
            }
        } else {
            self.socket_closed(fd);
        }
        if let Some(shared) = self.shared() {
            shared.bump_keys(&[rec.wake_key()]);
        }
        Some(())
    }

    /// Drops `fd`'s socket record from the sim's socket table.
    #[cfg(target_os = "linux")]
    fn socket_closed(&self, fd: c_int) {
        if let Some(shared) = self.shared() {
            shared.socket_closed(fd);
        }
    }

    /// Sends one datagram from `fd` to `dest`, stamped `now`, along the route the host picks:
    /// binding an unbound socket to the wildcard address first, fanning out to the host's own
    /// sockets and then to the sim's tester endpoints, and queueing the transmit stamps
    /// `SO_TIMESTAMPING` asked for (`tstamp::udp_sent`).
    ///
    /// Error order follows Linux: a pending socket error is reported first (and cleared), then a
    /// routing failure, then a don't-fragment datagram too large for the egress interface
    /// (`netif::frag`), then a stalled send queue. A send no socket or endpoint accepts raises the
    /// ICMP port-unreachable path. Takes `registries` and `state` one after the other, never both,
    /// and releases `state` before the capture and endpoint delivery, which can re-enter the host.
    #[cfg(target_os = "linux")]
    fn udp_send(
        &self,
        fd: c_int,
        data: Vec<u8>,
        dest: std::net::SocketAddr,
        now: std::time::Duration,
    ) -> Option<NetResult> {
        if data.len() > if dest.is_ipv4() { 65507 } else { 65527 } {
            return err(libc::EMSGSIZE);
        }
        let regs = self.registries.lock().unwrap().clone()?;
        let shared = regs.shared.clone();
        let station = regs.station_at(dest.ip());
        let (local, requested, domain, broadcast, rec) = {
            let state = self.state.lock().unwrap();
            let sock = state.udp.get(&fd)?;
            (
                sock.local,
                sock.requested,
                sock.domain,
                sock.broadcast,
                sock.rec.clone(),
            )
        };
        rec.land();
        if let Some(errno) = rec.take_error_as(&shared, crate::sockets::Taker::Send) {
            return err(errno);
        }
        let unhashed = requested.map(|r| std::net::SocketAddr::new(r.ip(), 0));
        let view = rec.view(local.or(unhashed));
        let sender =
            match shared.route_send(&view, dest, crate::netif::Op::Send, station, broadcast) {
                Ok(sender) => sender,
                Err(errno) => return err(errno),
            };
        if let Err(errno) = crate::netif::frag::check_send(
            &shared,
            &rec,
            domain == libc::AF_INET6,
            &sender,
            dest,
            data.len(),
        ) {
            return err(errno);
        }
        if let Some(local) = local
            && shared.policies.send_stalled(local)
        {
            // A stalled link (`UdpPolicy::send_queue_depth == Some(0)`): the send cannot go out.
            return err(libc::EAGAIN);
        }
        let joined = dest.ip().is_multicast() && shared.host_joined(dest.ip());
        let mut state = self.state.lock().unwrap();
        let local = match local {
            Some(local) => local,
            None => {
                let ip = unhashed.map_or(
                    if domain == libc::AF_INET6 {
                        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                    } else {
                        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                    },
                    |a| a.ip(),
                );
                let Some(port) = state.alloc_ephemeral(ip) else {
                    return err(libc::EAGAIN);
                };
                let sa = std::net::SocketAddr::new(ip, port);
                if sa.port() != 0 {
                    state.bound.insert(sa, fd);
                }
                state.udp.get_mut(&fd)?.local = Some(sa);
                rec.set_local(sa);
                sa
            }
        };
        let src = sender.source(local);
        let len = data.len();
        let cands = state.udp_cands(dest, joined);
        let copies = shared.fan_out(
            &sender,
            crate::netif::Wire { src, dest, len },
            station,
            cands,
            true,
        );
        let mut keys = crate::readiness::WakeKeys::default();
        keys.push(rec.wake_key());
        for copy in &copies {
            if let Some(socket) = state.udp.get(&copy.q) {
                keys.push(socket.rec.wake_key());
            }
        }
        let mut reached = copies.len();
        state.udp_land(copies, &data, src, now);
        let hw = sender
            .egress_name()
            .filter(|name| {
                state
                    .nics
                    .get(*name)
                    .is_none_or(|nic| !udp_onestep_stamp(nic.hwtstamp[1], dest.port(), &data))
            })
            .and_then(|nic| nic_hw_stamp(&state.nics, &state.ptp_clocks, nic, now, None));
        crate::tstamp::udp_sent(&rec, crate::tstamp::Stamp::from_real(now), hw, || {
            crate::tstamp::looped_frame(src, dest, false, &data)
        });
        rec.note_tx_nic(sender.egress_name());
        rec.count_udp_sent(dest, &sender);
        drop(state);
        shared.capture_udp(
            &sender,
            src,
            dest,
            crate::pcapng::Dir::Out,
            &data,
            Some(now),
        );
        reached += crate::fabric::deliver_to_endpoints(&regs, &sender, src, dest, &data);
        if reached == 0 {
            shared.unreachable_port(&rec, &sender, src, dest, &data, station);
        }
        shared.bump_keys(keys.as_slice());
        ok(len as i64)
    }

    /// Builds the host from `p`. Opens the `/dev/null` template fd with interposition bypassed
    /// (`snare_interpose::real`), so the open is never served by a sim.
    fn new(p: HostProfile) -> Self {
        let uname = p.uname();
        let online = p.online.unwrap_or_else(|| (0..p.cpu_count).collect());
        let topology = (
            p.nics.iter().map(Nic::topology_fact).collect(),
            p.routes.clone(),
        );
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
        #[cfg(target_os = "linux")]
        let default_qdisc = p.default_qdisc.clone();
        let nics = p
            .nics
            .into_iter()
            .map(|n| {
                let mut ethtool = n.ethtool;
                ethtool.phc_index = n.ptp_index;
                let (rx_queues, tx_queues) = match ethtool.channels {
                    Some(c) => ((c.combined + c.rx) as usize, (c.combined + c.tx) as usize),
                    None => (n.rx_queues, n.tx_queues),
                };
                let num_tx_queues = n
                    .tx_queues_allocated
                    .or(ethtool
                        .channels
                        .map(|c| (c.combined_max + c.tx_max) as usize))
                    .unwrap_or(tx_queues)
                    .max(tx_queues);
                #[cfg(target_os = "linux")]
                let qdiscs = crate::qdisc::NicQdiscs::initial(
                    &crate::qdisc::Device {
                        num_tx_queues,
                        real_tx_queues: tx_queues,
                        no_queue: n.no_queue,
                        default_qdisc: &default_qdisc,
                        etf_offload: ethtool.etf_offload.as_deref(),
                    },
                    p.etf,
                );
                (
                    n.name,
                    NicState {
                        ifindex: n.ifindex,
                        driver: n.driver,
                        driver_version: n.driver_version,
                        bus_info: n.bus_info,
                        hwtstamp_supported: n.hwtstamp_supported,
                        hwtstamp: n.hwtstamp,
                        hwtstamp_rx_mapping: n.hwtstamp_rx_mapping,
                        operstate: n.operstate,
                        carrier: n.carrier,
                        subsystem: n.subsystem,
                        rx_queues,
                        tx_queues,
                        num_tx_queues,
                        no_queue: n.no_queue,
                        msi_irqs: n.msi_irqs,
                        ethtool,
                        #[cfg(target_os = "linux")]
                        qdiscs,
                    },
                )
            })
            .collect();
        let devnull =
            snare_interpose::real(|| unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) });
        SimHost {
            state: Mutex::new(HostState {
                cpu_count: p.cpu_count,
                online,
                isolated: p.isolated,
                nohz_full: p.nohz_full,
                governor: p.governor,
                preempt_rt: p.preempt_rt,
                caps: p.caps,
                root: p.root,
                cpu_dma_latency: None,
                open: OpenFiles::default(),
                #[cfg(target_os = "linux")]
                dirs: OpenFiles::default(),
                threads: std::collections::BTreeMap::new(),
                thread_ids: HashMap::new(),
                next_tid: TID_BASE,
                #[cfg(target_os = "linux")]
                pthreads: HashMap::new(),
                nics,
                default_qdisc: p.default_qdisc,
                #[cfg(target_os = "linux")]
                ptp_clocks,
                #[cfg(target_os = "linux")]
                ptp_caps: p.ptp_caps,
                #[cfg(target_os = "linux")]
                qdisc_auto: 0x8000_0000,
                #[cfg(target_os = "macos")]
                mac_threads: HashMap::new(),
                #[cfg(target_os = "linux")]
                udp: UdpSockets::default(),
                #[cfg(target_os = "linux")]
                netlinks: NetlinkSockets::default(),
                #[cfg(target_os = "linux")]
                bound: HashMap::new(),
                #[cfg(target_os = "linux")]
                next_ephemeral: 49152,
                #[cfg(target_os = "linux")]
                inherited_threads: HashMap::new(),
                env: p
                    .env
                    .into_iter()
                    .filter_map(|(k, v)| {
                        Some((
                            std::ffi::CString::new(k).ok()?,
                            std::ffi::CString::new(v).ok()?,
                        ))
                    })
                    .collect(),
                shared: std::sync::Weak::new(),
            }),
            devnull,
            clock: Arc::new(Clock::new(p.tai_offset_secs)),
            isolate_env: p.isolate_env,
            registries: Mutex::new(None),
            me: std::sync::OnceLock::new(),
            topology,
            uname,
        }
    }

    /// The interfaces and routes the host declares, for the sim's topology.
    pub(crate) fn topology_facts(&self) -> (Vec<(NicSpec, NicCounters)>, Vec<Route>) {
        self.topology.clone()
    }

    /// Whether this host isolates the process environment (see [`HostProfile::env`]).
    pub(crate) fn isolate_env(&self) -> bool {
        self.isolate_env
    }

    /// A layer serving the clock calls (`clock_gettime` and friends) from this host's clock.
    pub(crate) fn clock_layer(self: &Arc<Self>) -> Arc<dyn Layer> {
        Arc::new(ClockLayer(self.clock.clone()))
    }

    /// The host's virtual clock.
    pub(crate) fn clock(&self) -> Arc<Clock> {
        self.clock.clone()
    }

    /// The CPU latency cap, in microseconds, the code under test currently requests through
    /// `/dev/cpu_dma_latency`, or `None` while no descriptor on it is open. Opening the file starts
    /// the request at the kernel's no-constraint default of 2000 s (`PM_QOS_CPU_LATENCY_DEFAULT_VALUE`),
    /// each write of a native-endian `s32` replaces it, and closing the last descriptor withdraws
    /// it (Documentation/power/pm_qos_interface.rst).
    pub fn cpu_dma_latency(&self) -> Option<i32> {
        self.state.lock().unwrap().cpu_dma_latency
    }

    /// Interface `nic`'s driver as `ethtool` sees it now: its capabilities and every ring,
    /// coalescing, channel, flow-control, EEE, feature and flow-rule setting the code under test
    /// has made, or `None` for an interface the profile did not declare.
    pub fn ethtool(&self, nic: &str) -> Option<crate::ethtool::NicEthtool> {
        self.state
            .lock()
            .unwrap()
            .nics
            .get(nic)
            .map(|n| n.ethtool.clone())
    }

    /// Sets driver statistic `name` of interface `nic` to `value` (see [`Nic::driver_stats`]),
    /// adding it at the end if the driver did not report it yet. `false` for an unknown
    /// interface.
    pub fn set_driver_stat(&self, nic: &str, name: &str, value: u64) -> bool {
        let mut state = self.state.lock().unwrap();
        let Some(n) = state.nics.get_mut(nic) else {
            return false;
        };
        match n.ethtool.stats.iter_mut().find(|(s, _)| s == name) {
            Some((_, v)) => *v = value,
            None => n.ethtool.stats.push((name.to_string(), value)),
        }
        true
    }

    /// The transmit deadline (nanoseconds, in the socket's `SO_TXTIME` clock) carried by the most
    /// recent `SCM_TXTIME` `sendmsg` on `fd`, or `None` if none was seen. Lets a test assert the
    /// pacing deadline the code under test requested.
    #[cfg(target_os = "linux")]
    pub fn last_tx_deadline(&self, fd: c_int) -> Option<u64> {
        self.state
            .lock()
            .unwrap()
            .udp
            .get(&fd)
            .and_then(|s| s.tx_deadline)
    }

    /// Mints an fd for a simulated file or socket by `dup`ing the `/dev/null` template, so the
    /// number is genuinely allocated in the process and cannot collide with a real fd; the
    /// kernel's lowest-free-fd rule picks it (man 2 dup).
    fn reserve_fd(&self) -> std::io::Result<c_int> {
        if self.devnull < 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EMFILE));
        }
        let fd = unsafe { libc::dup(self.devnull) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
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
            for &fd in state.dirs.keys() {
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

#[cfg(target_os = "linux")]
fn directory_links(entries: &[DirEntry]) -> u64 {
    2 + entries
        .iter()
        .skip(2)
        .filter(|entry| entry.dtype == libc::DT_DIR)
        .count() as u64
}

fn host_file_metadata(path: &Path, length: usize) -> (u32, u64) {
    #[cfg(target_os = "linux")]
    {
        if path.starts_with("/proc") {
            return (
                if path.starts_with("/proc/sys") {
                    0o100644
                } else {
                    0o100444
                },
                0,
            );
        }
        if path.starts_with("/sys") {
            let writable = matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some(
                    "mtu"
                        | "flags"
                        | "threaded"
                        | "tx_queue_len"
                        | "gro_flush_timeout"
                        | "napi_defer_hard_irqs"
                )
            );
            return (if writable { 0o100644 } else { 0o100444 }, unsafe {
                libc::sysconf(libc::_SC_PAGESIZE)
            }
                as u64);
        }
    }
    let _ = path;
    (0o100444, length as u64)
}

pub(crate) fn host_stat(
    buf: *mut u8,
    path: &Path,
    mode: u32,
    size: u64,
    links: u64,
) -> Option<FsResult> {
    let result = fill_stat(buf, mode, size, ino_of(path), links);
    #[cfg(target_os = "linux")]
    if matches!(result, Some(FsResult::Ok(_))) {
        unsafe {
            (*buf.cast::<libc::stat>()).st_blocks = 0;
            if path.starts_with("/proc") {
                (*buf.cast::<libc::stat>()).st_blksize = 1024;
            }
            if path.starts_with("/sys")
                || path.starts_with("/proc/sys")
                || path.starts_with("/proc/net")
            {
                (*buf.cast::<libc::stat>()).st_uid = 0;
                (*buf.cast::<libc::stat>()).st_gid = 0;
            }
        }
    }
    result
}

#[cfg(target_os = "linux")]
pub(crate) fn host_statx(
    buf: *mut u8,
    path: &Path,
    mode: u32,
    size: u64,
    links: u64,
) -> Option<FsResult> {
    let result = fill_statx(buf, mode, size, ino_of(path), links);
    if matches!(result, Some(FsResult::Ok(_))) {
        unsafe {
            buf.add(48).cast::<u64>().write_unaligned(0);
            if path.starts_with("/proc") {
                buf.add(4).cast::<u32>().write_unaligned(1024);
            }
            if path.starts_with("/sys")
                || path.starts_with("/proc/sys")
                || path.starts_with("/proc/net")
            {
                buf.add(20).cast::<u32>().write_unaligned(0);
                buf.add(24).cast::<u32>().write_unaligned(0);
            }
        }
    }
    result
}

impl Fs for SimHost {
    /// Whether `fd` is one of the host's open files or directory streams.
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

    /// Opens a host file. `/dev/cpu_dma_latency` opens writable and starts the PM QoS request at
    /// the default; `/dev/ptp<N>` opens if the clock exists (else `ENOENT`); any other rendered
    /// file opens read-only with its contents snapshotted, and a write-mode open fails with
    /// `EACCES` as sysfs's 0444 attributes do. Mode bits are ignored.
    unsafe fn open(&self, path: *const c_char, flags: c_int, _mode: u32) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        let mut state = self.state.lock().unwrap();

        if path == Path::new("/dev/cpu_dma_latency") {
            let fd = match self.reserve_fd() {
                Ok(fd) => fd,
                Err(e) => return err(e.raw_os_error().unwrap_or(libc::EMFILE)),
            };
            // Default PM QoS cap in µs while no writer holds the fd open (kernel resets to
            // PM_QOS_CPU_LATENCY_DEFAULT_VALUE = 2000 * USEC_PER_SEC on release, include/linux/
            // pm_qos.h; named PM_QOS_CPU_DMA_LAT_DEFAULT_VALUE before Linux 5.7). /dev/cpu_dma_latency
            // in Documentation/admin-guide/pm/cpuidle.rst, Documentation/power/pm_qos_interface.rst.
            state.cpu_dma_latency = Some(2_000_000_000);
            state.open.insert(
                fd,
                OpenFile {
                    data: Vec::new(),
                    read_error: None,
                    cursor: 0,
                    writable: true,
                    flags: status_flags(flags),
                    path,
                },
            );
            set_cloexec(fd, flags);
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
                OpenFile {
                    data: Vec::new(),
                    read_error: None,
                    cursor: 0,
                    writable: flags & (libc::O_WRONLY | libc::O_RDWR) != 0,
                    flags: status_flags(flags),
                    path,
                },
            );
            set_cloexec(fd, flags);
            return ok(fd as i64);
        }

        #[cfg(target_os = "linux")]
        if state.dir_entries(&path).is_some() {
            if flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC) != 0 {
                return err(libc::EISDIR);
            }
            drop(state);
            let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            let result = unsafe { self.opendir(path.as_ptr()) };
            if let Some(FsResult::Ok(fd)) = result
                && flags & libc::O_CLOEXEC == 0
            {
                descriptor_fcntl(fd as c_int, libc::F_SETFD, 0);
            }
            return result;
        }
        let Some(data) = state.render(&path) else {
            return if state.owns_path(&path) {
                err(libc::ENOENT)
            } else {
                None
            };
        };
        let write = flags & libc::O_WRONLY != 0 || flags & libc::O_RDWR != 0;
        // Sysfs attributes are root-owned; the writable ones are mode 0644
        // (Documentation/ABI/testing/sysfs-class-net), so only root may open them for writing.
        if write && !(state.threaded_attr(&path).is_some() && state.privileges().root) {
            return err(libc::EACCES);
        }
        let fd = match self.reserve_fd() {
            Ok(fd) => fd,
            Err(e) => return err(e.raw_os_error().unwrap_or(libc::EMFILE)),
        };
        let read_error = state.read_error(&path);
        state.open.insert(
            fd,
            OpenFile {
                data,
                read_error,
                cursor: 0,
                writable: write,
                flags: status_flags(flags),
                path,
            },
        );
        set_cloexec(fd, flags);
        ok(fd as i64)
    }

    /// `open` for an absolute path or one relative to `AT_FDCWD`; a path relative to another
    /// directory fd is declined, since the host keeps no directory fds for `open` to resolve
    /// against (man 2 openat: an absolute path ignores `dirfd`).
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

    /// Reads from the open snapshot at the cursor; 0 at or past the end. A file with a
    /// `read_error` fails every read with it.
    unsafe fn read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<FsResult> {
        let mut state = self.state.lock().unwrap();
        #[cfg(target_os = "linux")]
        if state.dirs.contains_key(&fd) {
            return err(libc::EISDIR);
        }
        let file = state.open.get_mut(&fd)?;
        if file.flags & libc::O_ACCMODE == libc::O_WRONLY {
            return err(libc::EBADF);
        }
        if let Some(errno) = file.read_error {
            return err(errno);
        }
        let start = file.cursor.min(file.data.len());
        let n = len.min(file.data.len() - start);
        if n != 0 {
            unsafe { std::ptr::copy_nonoverlapping(file.data[start..].as_ptr(), buf, n) };
        }
        file.cursor += n;
        ok(n as i64)
    }

    unsafe fn pread(&self, fd: c_int, buf: *mut u8, len: usize, offset: i64) -> Option<FsResult> {
        let state = self.state.lock().unwrap();
        #[cfg(target_os = "linux")]
        if state.dirs.contains_key(&fd) {
            return err(if offset < 0 {
                libc::EINVAL
            } else {
                libc::EISDIR
            });
        }
        let file = state.open.get(&fd)?;
        if offset < 0 {
            return err(libc::EINVAL);
        }
        if file.flags & libc::O_ACCMODE == libc::O_WRONLY {
            return err(libc::EBADF);
        }
        if let Some(errno) = file.read_error {
            return err(errno);
        }
        let start = (offset as usize).min(file.data.len());
        let n = len.min(file.data.len() - start);
        if n != 0 {
            unsafe { std::ptr::copy_nonoverlapping(file.data[start..].as_ptr(), buf, n) };
        }
        ok(n as i64)
    }

    /// A write to `/dev/cpu_dma_latency` takes its first four bytes as the native-endian `s32`
    /// latency cap in µs (Documentation/power/pm_qos_interface.rst; the ASCII hex form the kernel
    /// also accepts is not modelled) and reports the whole buffer written. An fd opened read-only
    /// rejects writes with `EBADF`.
    unsafe fn write(&self, fd: c_int, buf: *const u8, len: usize) -> Option<FsResult> {
        let mut state = self.state.lock().unwrap();
        #[cfg(target_os = "linux")]
        if state.dirs.contains_key(&fd) {
            return err(libc::EBADF);
        }
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
        let threaded = state
            .open
            .get(&fd)
            .filter(|f| f.writable)
            .and_then(|f| state.threaded_attr(&f.path));
        if let Some(nic) = threaded {
            let text = unsafe { std::slice::from_raw_parts(buf, len) };
            return match state.store_threaded(&nic, text) {
                Ok(()) => ok(len as i64),
                Err(e) => err(e),
            };
        }
        if let Some(file) = state.open.get(&fd) {
            return err(if file.writable {
                libc::EACCES
            } else {
                libc::EBADF
            });
        }
        None
    }

    unsafe fn pwrite(
        &self,
        fd: c_int,
        _buf: *const u8,
        _len: usize,
        _offset: i64,
    ) -> Option<FsResult> {
        let state = self.state.lock().unwrap();
        let file = state.open.get(&fd)?;
        err(if file.path.starts_with("/dev") {
            libc::EOPNOTSUPP
        } else {
            libc::ESPIPE
        })
    }

    unsafe fn ftruncate(&self, fd: c_int, _len: i64) -> Option<FsResult> {
        let state = self.state.lock().unwrap();
        state.open.get(&fd)?;
        err(libc::EINVAL)
    }

    unsafe fn fsync(&self, fd: c_int) -> Option<FsResult> {
        let state = self.state.lock().unwrap();
        let file = state.open.get(&fd)?;
        if file.path.starts_with("/sys") {
            ok(0)
        } else {
            err(libc::EINVAL)
        }
    }

    /// Moves the cursor (man 2 lseek): `EINVAL` for an unknown `whence` or a negative result;
    /// seeking past the end is allowed.
    unsafe fn lseek(&self, fd: c_int, offset: i64, whence: c_int) -> Option<FsResult> {
        let mut state = self.state.lock().unwrap();
        #[cfg(target_os = "linux")]
        if let Some(stream) = state.dirs.get_mut(&fd) {
            let base = match whence {
                libc::SEEK_SET => 0,
                libc::SEEK_CUR => stream.cursor as i64,
                _ => return err(libc::EINVAL),
            };
            let Some(target) = base.checked_add(offset).filter(|target| *target >= 0) else {
                return err(libc::EINVAL);
            };
            stream.cursor = target as usize;
            return ok(target);
        }
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
        if let Some(stream) = state.dirs.get(&fd) {
            let path = stream.path.as_ref()?;
            let links = directory_links(&stream.entries);
            return host_stat(buf, path, 0o040755, 0, links);
        }
        let file = state.open.get(&fd)?;
        let (mode, size) = host_file_metadata(&file.path, file.data.len());
        host_stat(buf, &file.path, mode, size, 1)
    }

    unsafe fn stat(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        let state = self.state.lock().unwrap();
        #[cfg(target_os = "linux")]
        if let Some(entries) = state.dir_entries(&path) {
            let links = directory_links(&entries);
            return host_stat(buf, &path, 0o040755, 0, links);
        }
        let Some(data) = state.render(&path) else {
            return if state.owns_path(&path) {
                err(libc::ENOENT)
            } else {
                None
            };
        };
        let (mode, size) = host_file_metadata(&path, data.len());
        host_stat(buf, &path, mode, size, 1)
    }

    /// The same as `stat`: no rendered file is a symlink.
    unsafe fn lstat(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        unsafe { self.stat(path, buf) }
    }

    /// Resolves the one modelled symlink, `/sys/class/net/<if>/device/subsystem`. Like readlink(2)
    /// it truncates silently to `len` and writes no NUL.
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
            return if state.owns_path(&path) {
                err(libc::ENOENT)
            } else {
                None
            };
        };
        // /sys/class/net/<if>/device/subsystem is a symlink into /sys/bus/<type>, whose last path
        // element names the subsystem (Documentation/admin-guide/sysfs-rules.rst).
        let target = format!("../../../../bus/{}", nic.subsystem);
        let bytes = target.as_bytes();
        let n = bytes.len().min(len);
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n) };
        ok(n as i64)
    }

    /// `readlink` for an absolute path or one relative to `AT_FDCWD`; see [`Fs::openat`].
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

    /// `statx` by path, or of `dirfd` itself when the path is empty (the `AT_EMPTY_PATH` form;
    /// man 2 statx). The flags and mask are ignored and every basic field filled.
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
            if let Some(stream) = state.dirs.get(&dirfd) {
                let path = stream.path.as_ref()?;
                let links = directory_links(&stream.entries);
                return host_statx(buf, path, 0o040755, 0, links);
            }
            let file = state.open.get(&dirfd)?;
            let (mode, size) = host_file_metadata(&file.path, file.data.len());
            return host_statx(buf, &file.path, mode, size, 1);
        }
        let path = unsafe { path_of(path) }?;
        let state = self.state.lock().unwrap();
        if let Some(entries) = state.dir_entries(&path) {
            let links = directory_links(&entries);
            return host_statx(buf, &path, 0o040755, 0, links);
        }
        let Some(data) = state.render(&path) else {
            return if state.owns_path(&path) {
                err(libc::ENOENT)
            } else {
                None
            };
        };
        let (mode, size) = host_file_metadata(&path, data.len());
        host_statx(buf, &path, mode, size, 1)
    }

    /// Succeeds for any known file whatever `mode` asks (including `W_OK` on a read-only
    /// attribute, which the real kernel would refuse for a non-root caller), `ENOENT` inside a
    /// modelled subtree.
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

    /// `access`, ignoring `dirfd` and the flags; a relative path never names a modelled file, so
    /// it falls through.
    unsafe fn faccessat(
        &self,
        _dirfd: c_int,
        path: *const c_char,
        mode: c_int,
        _flags: c_int,
    ) -> Option<FsResult> {
        unsafe { self.access(path, mode) }
    }

    /// Closes a host file and its reserved fd. Closing `/dev/cpu_dma_latency` withdraws the
    /// latency request, as releasing the kernel's PM QoS request does.
    unsafe fn close(&self, fd: c_int) -> Option<FsResult> {
        let mut state = self.state.lock().unwrap();
        #[cfg(target_os = "linux")]
        if state.dirs.remove(&fd).is_some() {
            unsafe { libc::close(fd) };
            return ok(0);
        }
        let file = state.open.remove(&fd)?;
        if file.is_some_and(|file| file.path == Path::new("/dev/cpu_dma_latency")) {
            state.cpu_dma_latency = None;
        }
        unsafe { libc::close(fd) };
        ok(0)
    }

    unsafe fn fd_replaced(&self, fd: c_int) -> Option<FsResult> {
        let mut state = self.state.lock().unwrap();
        #[cfg(target_os = "linux")]
        if state.dirs.remove(&fd).is_some() {
            return ok(0);
        }
        let file = state.open.remove(&fd)?;
        if file.is_some_and(|file| file.path == Path::new("/dev/cpu_dma_latency")) {
            state.cpu_dma_latency = None;
        }
        ok(0)
    }

    unsafe fn dup(&self, oldfd: c_int, newfd: c_int) -> Option<FsResult> {
        let mut state = self.state.lock().unwrap();
        let released = if state.open.contains_key(&oldfd) {
            #[cfg(target_os = "linux")]
            state.dirs.remove(&newfd);
            state.open.alias(oldfd, newfd)?
        } else {
            #[cfg(target_os = "linux")]
            {
                if !state.dirs.contains_key(&oldfd) {
                    return None;
                }
                let released = state.open.remove(&newfd).flatten();
                state.dirs.alias(oldfd, newfd)?;
                released
            }
            #[cfg(not(target_os = "linux"))]
            return None;
        };
        if released.is_some_and(|file| file.path == Path::new("/dev/cpu_dma_latency")) {
            state.cpu_dma_latency = None;
        }
        ok(newfd as i64)
    }

    unsafe fn dup_to(&self, oldfd: c_int, newfd: c_int, flags: Option<c_int>) -> Option<FsResult> {
        let mut state = self.state.lock().unwrap();
        let is_file = state.open.contains_key(&oldfd);
        let is_dir = {
            #[cfg(target_os = "linux")]
            {
                state.dirs.contains_key(&oldfd)
            }
            #[cfg(not(target_os = "linux"))]
            {
                false
            }
        };
        if !is_file && !is_dir {
            return None;
        }
        let result = crate::fabric::duplicate_to(oldfd, newfd, flags);
        if result < 0 {
            return err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EBADF));
        }
        let released = if is_file {
            #[cfg(target_os = "linux")]
            state.dirs.remove(&newfd);
            state.open.alias(oldfd, newfd).flatten()
        } else {
            let released = state.open.remove(&newfd).flatten();
            #[cfg(target_os = "linux")]
            state.dirs.alias(oldfd, newfd);
            released
        };
        if released.is_some_and(|file| file.path == Path::new("/dev/cpu_dma_latency")) {
            state.cpu_dma_latency = None;
        }
        ok(result as i64)
    }

    unsafe fn fcntl(&self, fd: c_int, cmd: c_int, arg: i64) -> Option<FsResult> {
        let mut state = self.state.lock().unwrap();
        let is_file = state.open.contains_key(&fd);
        let is_dir = {
            #[cfg(target_os = "linux")]
            {
                state.dirs.contains_key(&fd)
            }
            #[cfg(not(target_os = "linux"))]
            {
                false
            }
        };
        if !is_file && !is_dir {
            return None;
        }
        match cmd {
            libc::F_DUPFD | libc::F_DUPFD_CLOEXEC => {
                let result = descriptor_fcntl(fd, cmd, arg)?;
                if let FsResult::Ok(newfd) = result {
                    if is_file {
                        state.open.alias(fd, newfd as c_int);
                    }
                    #[cfg(target_os = "linux")]
                    if is_dir {
                        state.dirs.alias(fd, newfd as c_int);
                    }
                }
                Some(result)
            }
            libc::F_GETFD | libc::F_SETFD => descriptor_fcntl(fd, cmd, arg),
            libc::F_GETFL => ok(state
                .open
                .get(&fd)
                .map_or(libc::O_RDONLY, |file| file.flags) as i64),
            libc::F_SETFL => {
                if let Some(file) = state.open.get_mut(&fd) {
                    let mask = libc::O_APPEND | libc::O_NONBLOCK;
                    file.flags = (file.flags & !mask) | (arg as c_int & mask);
                }
                ok(0)
            }
            _ => err(libc::EINVAL),
        }
    }

    /// The PTP clock ioctls on a `/dev/ptp<N>` fd ([`ptp_ioctl`]), against the clock's
    /// [`PtpCaps`]. One sample of the virtual clock answers every timestamp slot, so the PHC
    /// offset reads back exactly. Charges one call latency first so a polling loop advances a
    /// discrete clock.
    #[cfg(target_os = "linux")]
    unsafe fn ioctl(&self, fd: c_int, request: u64, arg: i64) -> Option<FsResult> {
        if (request >> 8) & 0xff != PTP_IOCTL_MAGIC {
            return None;
        }
        let (offset, caps, writable, root) = {
            let state = self.state.lock().unwrap();
            let file = state.open.get(&fd)?;
            let index = parse_ptp_index(&file.path)?;
            let offset = *state.ptp_clocks.get(&index)?;
            let caps = state.ptp_caps.get(&index).copied().unwrap_or_default();
            (offset, caps, file.writable, state.privileges().root)
        };
        snare_interpose::charge_latency();
        let clock = PtpFile {
            caps,
            writable,
            root,
        };
        unsafe { ptp_ioctl(&clock, request, arg, || self.clock.ptp_sample(offset)) }
    }

    /// Opens a modelled `/sys/class/net` directory. The returned value is a reserved fd that stands
    /// in for the `DIR *` handle the interposer hands back.
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
        let mut stream = DirStream::new(entries);
        stream.path = Some(path);
        state.dirs.insert(fd, stream);
        set_cloexec(fd, libc::O_CLOEXEC);
        ok(fd as i64)
    }

    /// The next entry as a pointer to a `struct dirent` in the stream's scratch buffer, valid
    /// until the next `readdir` on the stream (the same lifetime man 3 readdir gives), or 0 (a
    /// NULL `dirent *`) at the end.
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
    unsafe fn fdopendir(&self, fd: c_int) -> Option<FsResult> {
        if self.state.lock().unwrap().dirs.contains_key(&fd) {
            set_cloexec(fd, libc::O_CLOEXEC);
            ok(fd as i64)
        } else {
            None
        }
    }

    #[cfg(target_os = "linux")]
    unsafe fn statfs(&self, raw: *const c_char, buf: *mut u8) -> Option<FsResult> {
        let path = unsafe { path_of(raw) }?;
        let state = self.state.lock().unwrap();
        if !state.owns_path(&path) {
            return None;
        }
        if state.render(&path).is_none() && state.dir_entries(&path).is_none() {
            return err(libc::ENOENT);
        }
        let root = if path.starts_with("/sys") {
            c"/sys"
        } else if path.starts_with("/proc") {
            c"/proc"
        } else {
            c"/dev"
        };
        let result = unsafe { libc::statfs(root.as_ptr(), buf.cast()) };
        if result == 0 {
            ok(0)
        } else {
            err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO))
        }
    }

    #[cfg(target_os = "linux")]
    unsafe fn fstatfs(&self, fd: c_int, buf: *mut u8) -> Option<FsResult> {
        let state = self.state.lock().unwrap();
        let path = if let Some(file) = state.open.get(&fd) {
            file.path.clone()
        } else {
            state.dirs.get(&fd)?.path.as_ref()?.clone()
        };
        let root = if path.starts_with("/sys") {
            c"/sys"
        } else if path.starts_with("/proc") {
            c"/proc"
        } else {
            c"/dev"
        };
        let result = unsafe { libc::statfs(root.as_ptr(), buf.cast()) };
        if result == 0 {
            ok(0)
        } else {
            err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO))
        }
    }

    #[cfg(target_os = "linux")]
    unsafe fn getdents64(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<FsResult> {
        let mut state = self.state.lock().unwrap();
        if let Some(stream) = state.dirs.get_mut(&fd) {
            crate::fs_sim::pack_directory(stream, buf, len)
        } else if state.open.contains_key(&fd) {
            err(libc::ENOTDIR)
        } else {
            None
        }
    }

    /// Drops the stream and closes its reserved fd.
    #[cfg(target_os = "linux")]
    unsafe fn closedir(&self, fd: c_int) -> Option<FsResult> {
        self.state.lock().unwrap().dirs.remove(&fd)?;
        let ret = unsafe { libc::close(fd) };
        ok(ret as i64)
    }
}

/// The isolated environment, consulted only when the profile isolates it (see
/// [`HostProfile::env`]).
#[cfg(target_os = "linux")]
unsafe fn errno_ptr() -> *mut c_int {
    unsafe { libc::__errno_location() }
}
#[cfg(target_os = "macos")]
unsafe fn errno_ptr() -> *mut c_int {
    unsafe { libc::__error() }
}

#[cfg(test)]
#[test]
fn cpu_latency_request_survives_closing_one_descriptor_alias() {
    let host = HostProfile::new().build();
    let Some(FsResult::Ok(fd)) =
        (unsafe { Fs::open(&*host, c"/dev/cpu_dma_latency".as_ptr(), libc::O_RDWR, 0) })
    else {
        panic!("opening cpu latency request failed");
    };
    let fd = fd as c_int;
    let alias = snare_interpose::real(|| unsafe { libc::dup(fd) });
    assert!(alias >= 0);
    assert!(matches!(
        unsafe { Fs::dup(&*host, fd, alias) },
        Some(FsResult::Ok(_))
    ));
    let latency = 37i32.to_ne_bytes();
    assert!(matches!(
        unsafe { Fs::write(&*host, fd, latency.as_ptr(), latency.len()) },
        Some(FsResult::Ok(4))
    ));
    assert!(matches!(
        unsafe { Fs::close(&*host, fd) },
        Some(FsResult::Ok(0))
    ));
    assert_eq!(host.state.lock().unwrap().cpu_dma_latency, Some(37));
    assert!(matches!(
        unsafe { Fs::close(&*host, alias) },
        Some(FsResult::Ok(0))
    ));
    assert_eq!(host.state.lock().unwrap().cpu_dma_latency, None);
}

impl Env for SimHost {
    fn snapshot(&self) -> Option<Vec<std::ffi::CString>> {
        let state = self.state.lock().unwrap();
        let mut vars: Vec<_> = state
            .env
            .iter()
            .map(|(key, value)| {
                let mut bytes = key.as_bytes().to_vec();
                bytes.push(b'=');
                bytes.extend_from_slice(value.as_bytes());
                std::ffi::CString::new(bytes).unwrap()
            })
            .collect();
        vars.sort();
        Some(vars)
    }

    /// The variable's value, or NULL if unset or `name` is NULL.
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

    /// Sets a variable, validating its name before changing the environment.
    unsafe fn setenv(&self, name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int {
        if name.is_null() || value.is_null() {
            unsafe { *errno_ptr() = libc::EINVAL };
            return -1;
        }
        let key = unsafe { std::ffi::CStr::from_ptr(name) }.to_owned();
        if key.to_bytes().is_empty() || key.to_bytes().contains(&b'=') {
            unsafe { *errno_ptr() = libc::EINVAL };
            return -1;
        }
        let val = unsafe { std::ffi::CStr::from_ptr(value) }.to_owned();
        let mut state = self.state.lock().unwrap();
        // man 3 setenv: with overwrite == 0 an existing variable is left unchanged (and success).
        if overwrite == 0 && state.env.contains_key(&key) {
            return 0;
        }
        state.env.insert(key, val);
        0
    }

    /// Removes a variable (success if it was not set, man 3 unsetenv); -1 for NULL. A pointer
    /// `getenv` returned for it dangles afterwards, as with the real `unsetenv`.
    unsafe fn unsetenv(&self, name: *const c_char) -> c_int {
        if name.is_null() {
            unsafe { *errno_ptr() = libc::EINVAL };
            return -1;
        }
        let key = unsafe { std::ffi::CStr::from_ptr(name) }.to_owned();
        if key.to_bytes().is_empty() || key.to_bytes().contains(&b'=') {
            unsafe { *errno_ptr() = libc::EINVAL };
            return -1;
        }
        self.state.lock().unwrap().env.remove(&key);
        0
    }
}

/// Process identity, scheduling, memory locking and (on macOS) Mach thread policy and the
/// routing sysctl. Scheduling state is recorded per simulated tid and never reaches the real
/// scheduler.
impl Host for SimHost {
    #[cfg(target_os = "linux")]
    fn thread_inherit(&self, lineage: u64) {
        let mut state = self.state.lock().unwrap();
        let tid = state.current_tid();
        let sched = state.threads[&tid].clone();
        state.inherited_threads.insert(lineage, sched);
    }
    #[cfg(target_os = "linux")]
    fn thread_adopt(&self, lineage: u64) {
        let mut state = self.state.lock().unwrap();
        if let Some(sched) = state.inherited_threads.remove(&lineage) {
            let tid = state.mint_tid();
            state
                .pthreads
                .insert(unsafe { libc::pthread_self() } as u64, tid);
            state.threads.insert(tid, sched);
        }
    }
    #[cfg(target_os = "linux")]
    fn thread_cancel(&self, lineage: u64) {
        self.state
            .lock()
            .unwrap()
            .inherited_threads
            .remove(&lineage);
    }
    #[cfg(target_os = "linux")]
    unsafe fn clock_gettime(&self, id: i32, buf: *mut u8) -> Option<HostResult> {
        if id & 7 != 3 {
            return None;
        }
        let fd = !(id >> 3);
        let offset = {
            let state = self.state.lock().unwrap();
            let file = state.open.get(&fd)?;
            let index = parse_ptp_index(&file.path)?;
            *state.ptp_clocks.get(&index)?
        };
        if buf.is_null() {
            return err(libc::EFAULT);
        }
        let (tv_sec, tv_nsec) = self.clock.ptp_sample(offset)[0];
        unsafe {
            buf.cast::<libc::timespec>().write(libc::timespec {
                tv_sec,
                tv_nsec: tv_nsec as _,
            })
        };
        ok(0)
    }
    #[cfg(target_os = "linux")]
    unsafe fn clock_getres(&self, id: i32, buf: *mut u8) -> Option<HostResult> {
        if id & 7 != 3 {
            return None;
        }
        let state = self.state.lock().unwrap();
        let file = state.open.get(&!(id >> 3))?;
        parse_ptp_index(&file.path)?;
        if !buf.is_null() {
            unsafe {
                buf.cast::<libc::timespec>().write(libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 1,
                })
            };
        }
        ok(0)
    }

    fn has_cap(&self, cap: c_int) -> bool {
        self.state.lock().unwrap().has_cap(cap)
    }

    /// 0 when running as root, else `UNPRIVILEGED_UID` (1000 on Linux, 501 on macOS).
    fn geteuid(&self) -> Option<u32> {
        let root = self.state.lock().unwrap().privileges().root;
        Some(if root { 0 } else { UNPRIVILEGED_UID })
    }

    /// The same as `geteuid`: the sim models no setuid split.
    fn getuid(&self) -> Option<u32> {
        self.geteuid()
    }

    /// Fills the `struct utsname` from the profile, each field cut to fit with its NUL. Linux's
    /// `domainname` reads `(none)`, the kernel's `UTS_DOMAINNAME` default
    /// (include/linux/uts.h).
    unsafe fn uname(&self, buf: *mut u8) -> Option<HostResult> {
        if buf.is_null() {
            return err(libc::EFAULT);
        }
        let uts = unsafe { &mut *(buf as *mut libc::utsname) };
        let u = &self.uname;
        put_c_field(&mut uts.sysname, &u.sysname);
        put_c_field(&mut uts.nodename, &u.nodename);
        put_c_field(&mut uts.release, &u.release);
        put_c_field(&mut uts.version, &u.version);
        put_c_field(&mut uts.machine, &u.machine);
        #[cfg(target_os = "linux")]
        put_c_field(&mut uts.domainname, "(none)");
        ok(0)
    }

    /// The calling thread's simulated tid.
    fn gettid(&self) -> Option<HostResult> {
        let mut state = self.state.lock().unwrap();
        ok(state.current_tid() as i64)
    }

    /// Records the policy and `sched_priority` (the first `int` of `struct sched_param`) under
    /// the kernel's validity and permission rules, `RLIMIT_RTPRIO` included (see
    /// [`crate::proclimits::sched_setscheduler`]). A NULL param or negative pid is `EINVAL`
    /// (kernel/sched/syscalls.c `do_sched_setscheduler`); any other pid names a thread, so the host
    /// never reports `ESRCH`.
    #[cfg(target_os = "linux")]
    unsafe fn sched_setscheduler(
        &self,
        pid: i32,
        policy: c_int,
        param: *const u8,
    ) -> Option<HostResult> {
        if param.is_null() || pid < 0 || policy < 0 {
            return err(libc::EINVAL);
        }
        let priority = unsafe { (param as *const c_int).read_unaligned() };
        let mut state = self.state.lock().unwrap();
        let tid = state.resolve(pid);
        state.set_sched(tid, policy, priority)
    }

    /// The recorded policy word, including `SCHED_RESET_ON_FORK` if it was set.
    unsafe fn sched_getscheduler(&self, pid: i32) -> Option<HostResult> {
        if pid < 0 {
            return err(libc::EINVAL);
        }
        let mut state = self.state.lock().unwrap();
        let tid = state.resolve(pid);
        ok(state.threads[&tid].policy as i64)
    }

    /// Records `sched_priority` within the thread's current policy, under the same rules as
    /// `sched_setscheduler` (the kernel passes `SETPARAM_POLICY` down the same path).
    #[cfg(target_os = "linux")]
    unsafe fn sched_setparam(&self, pid: i32, param: *const u8) -> Option<HostResult> {
        if param.is_null() || pid < 0 {
            return err(libc::EINVAL);
        }
        let priority = unsafe { (param as *const c_int).read_unaligned() };
        let mut state = self.state.lock().unwrap();
        let tid = state.resolve(pid);
        state.set_sched(tid, crate::proclimits::SETPARAM_POLICY, priority)
    }

    /// Writes the recorded `sched_priority` into the first `int` of `*param`.
    unsafe fn sched_getparam(&self, pid: i32, param: *mut u8) -> Option<HostResult> {
        if pid < 0 || param.is_null() {
            return err(libc::EINVAL);
        }
        let mut state = self.state.lock().unwrap();
        let tid = state.resolve(pid);
        let priority = state.threads[&tid].rt_priority;
        if !param.is_null() {
            unsafe { (param as *mut c_int).write_unaligned(priority) };
        }
        ok(0)
    }

    /// Records the CPUs of the mask below the host's CPU count. A mask shorter than a glibc
    /// `cpu_set_t` (128 bytes) is `EINVAL`, a snare simplification: the kernel accepts any length
    /// and only requires `cpusetsize` to cover `nr_cpu_ids` for `sched_getaffinity` (man 2
    /// sched_setaffinity, ERRORS). Offline CPUs in the mask are kept, not rejected.
    #[cfg(target_os = "linux")]
    unsafe fn sched_setaffinity(&self, pid: i32, len: usize, set: *const u8) -> Option<HostResult> {
        if set.is_null() || len < std::mem::size_of::<libc::cpu_set_t>() {
            return err(libc::EINVAL);
        }
        let set = unsafe { &*(set as *const libc::cpu_set_t) };
        let mut state = self.state.lock().unwrap();
        // man 2 sched_setaffinity; the cpu_set_t bit macros are CPU_SET(3).
        // CPU_ISSET/CPU_SET are UB past the bit capacity of a `cpu_set_t` (1024 on glibc).
        let cap = std::mem::size_of::<libc::cpu_set_t>() * 8;
        let count = state.cpu_count.min(cap);
        let wanted: Vec<usize> = (0..count)
            .filter(|&c| unsafe { libc::CPU_ISSET(c, set) })
            .collect();
        // A mask selecting no in-range CPU is EINVAL, exactly as the kernel reports.
        if wanted.is_empty() {
            return err(libc::EINVAL);
        }
        let tid = state.resolve(pid);
        state.threads.get_mut(&tid).unwrap().affinity = wanted;
        ok(0)
    }

    /// Writes the recorded mask, or every online CPU when none was set. A buffer shorter than a
    /// glibc `cpu_set_t` (128 bytes) is `EINVAL`, as for `sched_setaffinity`. Returns 0 like the
    /// glibc wrapper; the raw syscall's return of the mask size in bytes is not modelled (man 2
    /// sched_setaffinity, "C library/kernel differences").
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

    /// Records the nice value for `PRIO_PROCESS` (on Linux a tid, man 2 setpriority BUGS),
    /// clamped to -20..=19, with lowering it gated on `CAP_SYS_NICE` or `RLIMIT_NICE` (see
    /// [`crate::proclimits::setpriority`]). `PRIO_PGRP`/`PRIO_USER` are declined.
    #[cfg(target_os = "linux")]
    unsafe fn setpriority(&self, which: c_int, who: u32, prio: c_int) -> Option<HostResult> {
        if which != PRIO_PROCESS {
            return None;
        }
        let mut state = self.state.lock().unwrap();
        if who != 0 && !state.threads.contains_key(&(who as i32)) {
            return err(libc::ESRCH);
        }
        let tid = state.resolve(who as i32);
        let current = state.threads[&tid].nice;
        match crate::proclimits::setpriority(&state.privileges(), current, prio) {
            Ok(nice) => {
                state.threads.get_mut(&tid).unwrap().nice = nice;
                ok(0)
            }
            Err(e) => err(e),
        }
    }

    /// The recorded nice value for `PRIO_PROCESS`, as the libc wrapper returns it.
    unsafe fn getpriority(&self, which: c_int, who: u32) -> Option<HostResult> {
        if which != PRIO_PROCESS {
            return None;
        }
        let mut state = self.state.lock().unwrap();
        let tid = state.resolve(who as i32);
        ok(state.threads[&tid].nice as i64)
    }

    /// Locks the whole address space in the sim's accounting under `RLIMIT_MEMLOCK` and
    /// `CAP_IPC_LOCK` (see `proclimits`); real memory is never locked.
    #[cfg(target_os = "linux")]
    fn mlockall(&self, flags: c_int) -> Option<HostResult> {
        let shared = self.state.lock().unwrap().shared.upgrade()?;
        crate::proclimits::mlockall(&shared.sys, flags)
    }

    /// Unlocks everything; never fails.
    #[cfg(target_os = "linux")]
    fn munlockall(&self) -> Option<HostResult> {
        let shared = self.state.lock().unwrap().shared.upgrade()?;
        crate::proclimits::munlockall(&shared.sys)
    }

    /// Locks (Linux) or wires (macOS) the pages in the sim's accounting under `RLIMIT_MEMLOCK`;
    /// real memory is never locked.
    fn mlock(&self, addr: u64, len: u64) -> Option<HostResult> {
        let shared = self.state.lock().unwrap().shared.upgrade()?;
        crate::proclimits::mlock(&shared.sys, addr, len)
    }

    /// Unlocks the pages in the sim's accounting.
    fn munlock(&self, addr: u64, len: u64) -> Option<HostResult> {
        let shared = self.state.lock().unwrap().shared.upgrade()?;
        crate::proclimits::munlock(&shared.sys, addr, len)
    }

    /// The sim's `RLIMIT_MEMLOCK` (and on Linux `RLIMIT_RTPRIO`, `RLIMIT_NICE`); other resources
    /// are the real process's.
    unsafe fn getrlimit(&self, resource: c_int, rlim: *mut u8) -> Option<HostResult> {
        let shared = self.state.lock().unwrap().shared.upgrade()?;
        unsafe { crate::proclimits::getrlimit(&shared.sys, resource, rlim) }
    }

    /// Changes a modelled limit of the sim, never the real process's.
    unsafe fn setrlimit(&self, resource: c_int, rlim: *const u8) -> Option<HostResult> {
        let shared = self.state.lock().unwrap().shared.upgrade()?;
        unsafe { crate::proclimits::setrlimit(&shared.sys, resource, rlim) }
    }

    /// `prlimit` on the sim's own process; see [`getrlimit`](Self::getrlimit).
    #[cfg(target_os = "linux")]
    unsafe fn prlimit(
        &self,
        pid: i32,
        resource: c_int,
        new: *const u8,
        old: *mut u8,
    ) -> Option<HostResult> {
        let shared = self.state.lock().unwrap().shared.upgrade()?;
        unsafe { crate::proclimits::prlimit(&shared.sys, pid, resource, new, old) }
    }

    /// `pthread_setschedparam` on Linux: `sched_setscheduler` on the thread's simulated tid, the
    /// error returned rather than put in errno (the hook does that).
    #[cfg(target_os = "linux")]
    unsafe fn pthread_setschedparam(
        &self,
        thread: u64,
        policy: c_int,
        param: *const u8,
    ) -> Option<HostResult> {
        if param.is_null() {
            return err(libc::EINVAL);
        }
        let priority = unsafe { (param as *const c_int).read_unaligned() };
        let mut state = self.state.lock().unwrap();
        let tid = state.pthread_tid(thread);
        if policy < 0 {
            return err(libc::EINVAL);
        }
        state.set_sched(tid, policy, priority)
    }

    /// `pthread_getschedparam` on Linux: the simulated thread's policy word and priority, as
    /// `sched_getscheduler`/`sched_getparam` report them.
    #[cfg(target_os = "linux")]
    unsafe fn pthread_getschedparam(
        &self,
        thread: u64,
        policy: *mut c_int,
        param: *mut u8,
    ) -> Option<HostResult> {
        let mut state = self.state.lock().unwrap();
        let tid = state.pthread_tid(thread);
        let t = state.threads[&tid].clone();
        if !policy.is_null() {
            unsafe { policy.write_unaligned(t.policy) };
        }
        if !param.is_null() {
            unsafe { (param as *mut c_int).write_unaligned(t.rt_priority) };
        }
        ok(0)
    }

    /// Records the policy and priority for `thread` (`SCHED_FIFO`, `SCHED_RR` or `SCHED_OTHER` with
    /// a `struct sched_param` priority). There is no capability gate: macOS's
    /// pthread_setschedparam(3) lists no privilege error, only `EINVAL`, `ENOTSUP` and `ESRCH`.
    /// A policy other than those three is `EINVAL`; the priority is not validated. Setting any policy, even `SCHED_OTHER` at the default
    /// priority, opts the thread out of QoS for good, as on macOS (see [`set_qos`](Self::set_qos)).
    #[cfg(target_os = "macos")]
    unsafe fn pthread_setschedparam(
        &self,
        thread: u64,
        policy: c_int,
        param: *const u8,
    ) -> Option<HostResult> {
        if ![libc::SCHED_OTHER, libc::SCHED_FIFO, libc::SCHED_RR].contains(&policy) {
            return err(libc::EINVAL);
        }
        let priority = if param.is_null() {
            0
        } else {
            unsafe { (param as *const c_int).read_unaligned() }
        };
        self.state
            .lock()
            .unwrap()
            .mac_threads
            .insert(mac_thread_id(thread), (policy, priority));
        ok(0)
    }

    /// The recorded policy and priority for `thread`, or `SCHED_OTHER` priority 0 if never set.
    /// That default is a snare simplification, not the priority a fresh macOS thread reports.
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
            .get(&mac_thread_id(thread))
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

    /// Accepts any Mach thread policy and returns `KERN_SUCCESS` (0).
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

    /// `pthread_set_qos_class_self_np` with a `QOS_CLASS_*` from `<pthread/qos.h>`: accepted and
    /// not recorded. A class outside `QOS_CLASS_*` or a relative priority outside
    /// `QOS_MIN_RELATIVE_PRIORITY..=0` is `EINVAL`. A thread whose scheduling policy has been set
    /// is "permanently opted-out of the QOS class system" (`<pthread/qos.h>`) and gets `EPERM`;
    /// macOS opts out on any successful `pthread_setschedparam`, `SCHED_OTHER` at the default
    /// priority included, and setting the policy back does not opt the thread in again.
    #[cfg(target_os = "macos")]
    fn set_qos(&self, qos_class: c_int, relative_priority: c_int) -> Option<HostResult> {
        const QOS_CLASSES: [c_int; 5] = [0x21, 0x19, 0x15, 0x11, 0x09];
        const QOS_MIN_RELATIVE_PRIORITY: c_int = -15;
        if !QOS_CLASSES.contains(&qos_class)
            || !(QOS_MIN_RELATIVE_PRIORITY..=0).contains(&relative_priority)
        {
            return err(libc::EINVAL);
        }
        let me = mac_thread_id(unsafe { libc::pthread_self() } as u64);
        if self.state.lock().unwrap().mac_threads.contains_key(&me) {
            return err(libc::EPERM);
        }
        ok(0)
    }

    /// Serves `{CTL_NET, PF_ROUTE, 0, family, NET_RT_IFLIST2, ...}` from the topology and the
    /// protocol-counter nodes from the sim's counters (`netstats::macos`); every other
    /// MIB is declined. The usual two-step protocol (man 3 sysctl): a NULL `oldp` reports the
    /// size needed, a short buffer fails with `ENOMEM`. The address family and interface index
    /// words (`mib[3]`, `mib[5]`) are not used to filter.
    #[cfg(target_os = "macos")]
    unsafe fn sysctl(
        &self,
        name: *const c_int,
        namelen: u32,
        oldp: *mut u8,
        oldlenp: *mut usize,
        newp: *const u8,
        _newlen: usize,
    ) -> Option<HostResult> {
        if name.is_null() {
            return None;
        }
        let mib = unsafe { std::slice::from_raw_parts(name, namelen as usize) };
        use crate::netstats::macos;
        let shared = self.state.lock().unwrap().shared.upgrade();
        if let Some(shared) = shared
            && let Some(r) = unsafe { macos::read(&shared, mib, oldp, oldlenp, newp) }
        {
            return Some(r);
        }
        if namelen < 5 {
            return None;
        }
        if mib[0] != CTL_NET || mib[1] != PF_ROUTE || mib[4] != NET_RT_IFLIST2 {
            return None;
        }
        if oldlenp.is_null() {
            return err(libc::EINVAL);
        }
        let nics = self.state.lock().unwrap().topo_nics();
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

    /// `sysctlbyname` for the protocol-counter nodes (see [`sysctl`](Self::sysctl)); every
    /// other name is declined.
    #[cfg(target_os = "macos")]
    unsafe fn sysctlbyname(
        &self,
        name: *const c_char,
        oldp: *mut u8,
        oldlenp: *mut usize,
        newp: *const u8,
        _newlen: usize,
    ) -> Option<HostResult> {
        use crate::netstats::macos;
        let mib = macos::mib_of(unsafe { macos::name_str(name) }?)?;
        let shared = self.state.lock().unwrap().shared.upgrade()?;
        unsafe { macos::read(&shared, &mib, oldp, oldlenp, newp) }
    }

    /// `sysctlnametomib` for the protocol-counter nodes; every other name is declined.
    #[cfg(target_os = "macos")]
    unsafe fn sysctlnametomib(
        &self,
        name: *const c_char,
        mib: *mut c_int,
        sizep: *mut usize,
    ) -> Option<HostResult> {
        unsafe {
            crate::netstats::macos::name_to_mib(crate::netstats::macos::name_str(name)?, mib, sizep)
        }
    }

    /// Routes raw `syscall(2)` scheduling calls to the same handlers as their wrappers; every
    /// other number is declined.
    #[cfg(target_os = "linux")]
    unsafe fn syscall(&self, number: i64, args: [i64; 6]) -> Option<HostResult> {
        match number {
            n if n == libc::SYS_sched_setscheduler => unsafe {
                self.sched_setscheduler(args[0] as i32, args[1] as c_int, args[2] as *const u8)
            },
            n if n == libc::SYS_uname => unsafe { self.uname(args[0] as *mut u8) },
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
            _ => unsafe { crate::proclimits::route_syscall(self, number, args) },
        }
    }
}

// Socket ioctl request numbers from <linux/sockios.h>, driven with an `ifreq` per man 7 netdevice.
// SIOCETHTOOL nests an ethtool command struct (<linux/ethtool.h>); SIOC[GS]HWTSTAMP nest a
// `struct hwtstamp_config` (<linux/net_tstamp.h>, Documentation/networking/timestamping.rst).
/// `SIOCETHTOOL` (include/uapi/linux/sockios.h): `ifr_data` points at an ethtool command struct.
#[cfg(target_os = "linux")]
const SIOCETHTOOL: u64 = 0x8946;
/// `SIOCSHWTSTAMP` (include/uapi/linux/sockios.h): set a device's hardware timestamping config.
#[cfg(target_os = "linux")]
const SIOCSHWTSTAMP: u64 = 0x89b0;
/// `SIOCGHWTSTAMP` (include/uapi/linux/sockios.h): read it back.
#[cfg(target_os = "linux")]
const SIOCGHWTSTAMP: u64 = 0x89b1;

/// Read the NUL-terminated `ifr_name` (the first `IFNAMSIZ` = 16 bytes of an `ifreq`;
/// include/uapi/linux/if.h, man 7 netdevice).
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

/// Writes `text` into the C string field `field`, truncated to leave room for its NUL, and zeroes
/// the rest.
fn put_c_field(field: &mut [c_char], text: &str) {
    field.fill(0);
    let n = text.len().min(field.len() - 1);
    for (dst, &b) in field.iter_mut().zip(&text.as_bytes()[..n]) {
        *dst = b as c_char;
    }
}

/// The never-reused 64-bit id of the thread behind `pthread_t` `thread` (man 3
/// pthread_threadid_np); a `pthread_t` is a structure address that a later thread can reuse.
#[cfg(target_os = "macos")]
fn mac_thread_id(thread: u64) -> u64 {
    let mut id = 0;
    if unsafe { libc::pthread_threadid_np(thread as libc::pthread_t, &mut id) } == 0 {
        id
    } else {
        thread
    }
}

/// The options a host datagram socket models itself, beyond the sim-wide handlers: `SO_BROADCAST`,
/// the timeouts, `IP_RECVERR`/`IPV6_RECVERR`, and `SO_ERROR`. Multicast joins are matched by
/// `udp_parse_group`.
#[cfg(target_os = "linux")]
fn host_modelled(level: c_int, name: c_int) -> bool {
    matches!(
        (level, name),
        (libc::SOL_SOCKET, libc::SO_BROADCAST)
            | (libc::SOL_SOCKET, libc::SO_RCVTIMEO)
            | (libc::SOL_SOCKET, libc::SO_SNDTIMEO)
            | (libc::SOL_SOCKET, libc::SO_ERROR)
            | (libc::IPPROTO_IP, libc::IP_RECVERR)
            | (libc::IPPROTO_IPV6, libc::IPV6_RECVERR)
            | (libc::IPPROTO_IP, libc::IP_DROP_MEMBERSHIP)
            | (libc::IPPROTO_IPV6, libc::IPV6_DROP_MEMBERSHIP)
    )
}

/// If `(level, name)` is an `IP_ADD_MEMBERSHIP`/`IPV6_ADD_MEMBERSHIP` (`IPV6_JOIN_GROUP` on Linux),
/// reads the group address from the leading `in_addr`/`in6_addr` of the `ip_mreq`/`ipv6_mreq`
/// option value (include/uapi/linux/in.h, in6.h; IP_ADD_MEMBERSHIP(2const)).
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

/// The membership a join request for `group` asks for: `ip_mreq`/`ip_mreqn` (interface address at
/// 4, `ip_mreqn` index at 8; include/uapi/linux/in.h) or `ipv6_mreq` (interface index at 16;
/// include/uapi/linux/in6.h).
#[cfg(target_os = "linux")]
fn udp_membership(group: std::net::IpAddr, bytes: &[u8]) -> Membership {
    let word = |at: usize| {
        bytes
            .get(at..at + 4)
            .map_or(0, |b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
    };
    match group {
        std::net::IpAddr::V4(_) => {
            let interface = bytes
                .get(4..8)
                .map(|b| std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))
                .filter(|a| !a.is_unspecified());
            Membership {
                group,
                interface_addr: interface.map(std::net::IpAddr::V4),
                ifindex: word(8),
            }
        }
        std::net::IpAddr::V6(_) => Membership {
            group,
            interface_addr: None,
            ifindex: word(16),
        },
    }
}

/// Parse a `sockaddr_in`/`sockaddr_in6` into a [`std::net::SocketAddr`]: family at 0, port
/// (network order) at 2, IPv4 address at 4, IPv6 address at 8 (man 7 ip, man 7 ipv6;
/// include/uapi/linux/in.h, in6.h). The IPv6
/// flow info and scope id are dropped. `None` for any other family or a length too short for
/// the family (8 bytes for IPv4 here rather than the full 16, 28 for IPv6).
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
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(a),
                port,
                0,
                0,
            )))
        }
        _ => None,
    }
}

/// Write `addr` into a caller's `sockaddr` buffer and update `*addrlen` to the full size. A short
/// buffer is truncated and `*addrlen` still reports the full size, as man 2 getsockname
/// specifies.
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

/// Serialise a [`std::net::SocketAddr`] into `sockaddr_in` (16 bytes, zero-padded `sin_zero`) or
/// `sockaddr_in6` (28 bytes, zero flow info and scope id) bytes (man 7 ip, man 7 ipv6).
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

/// Write the datagram's source address into a `recvmsg` `msghdr`'s name buffer, if present, and
/// set `msg_namelen` to the full address size. Returns whether a name buffer was there.
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

/// `HWTSTAMP_FLAG_MASK` (include/uapi/linux/net_tstamp.h): `HWTSTAMP_FLAG_BONDED_PHC_INDEX`.
#[cfg(target_os = "linux")]
const HWTSTAMP_FLAG_MASK: c_int = 1;
/// `__HWTSTAMP_TX_CNT` and `__HWTSTAMP_FILTER_CNT`: the `tx_type` and `rx_filter` values the core
/// knows are below these.
#[cfg(target_os = "linux")]
const HWTSTAMP_TX_CNT: c_int = 4;
const HWTSTAMP_FILTER_CNT: c_int = 16;

/// The `HWTSTAMP_FILTER_*` filters a driver may apply for a request of `filter`: `filter`
/// itself, then the wider ones, narrowest first. A PTP message filter widens to its version's
/// (and transport's) event filter, a v2 one then to all PTP v2 events, and every one at last to
/// every packet (`HWTSTAMP_FILTER_ALL`), as do `HWTSTAMP_FILTER_SOME` and
/// `HWTSTAMP_FILTER_NTP_ALL` (include/uapi/linux/net_tstamp.h, `enum hwtstamp_rx_filters`).
#[cfg(target_os = "linux")]
fn hwtstamp_widenings(filter: c_int) -> Vec<c_int> {
    let wider: &[c_int] = match filter {
        0 | 1 => &[],
        3 => &[1],
        4 | 5 => &[3, 1],
        6 => &[12, 1],
        7 | 8 => &[6, 12, 1],
        9 => &[12, 1],
        10 | 11 => &[9, 12, 1],
        12 => &[1],
        13 | 14 => &[12, 1],
        _ => &[1],
    };
    std::iter::once(filter)
        .chain(wider.iter().copied())
        .collect()
}

/// The `struct hwtstamp_config` `(flags, tx_type, rx_filter)` a driver applies for `SIOCSHWTSTAMP`
/// `cfg`, which the kernel copies back to the caller, or the errno. The core first, as
/// net/core/dev_ioctl.c `dev_set_hwtstamp` (Linux 7.0) runs it: `net_hwtstamp_validate` refuses
/// an unknown flag (`EINVAL`) and a `tx_type` or `rx_filter` the kernel does not know (`ERANGE`),
/// then a device without `ndo_hwtstamp_set` (no hardware timestamping) is `EOPNOTSUPP`. Then
/// an unsupported transmit type is `ERANGE`. Explicit receive-filter mappings describe the
/// driver's captured result; absent entries use the narrowest advertised covering filter.
/// The flags are kept as given, as igb stores the whole config.
#[cfg(target_os = "linux")]
fn apply_hwtstamp(
    cfg: [c_int; 3],
    hardware: bool,
    tx_types: u32,
    rx_filters: u32,
    mappings: &[Option<Result<c_int, c_int>>; 16],
) -> Result<[c_int; 3], c_int> {
    let [flags, tx, rx] = cfg;
    if flags & !HWTSTAMP_FLAG_MASK != 0 {
        return Err(libc::EINVAL);
    }
    if !(0..HWTSTAMP_TX_CNT).contains(&tx) || !(0..HWTSTAMP_FILTER_CNT).contains(&rx) {
        return Err(libc::ERANGE);
    }
    if !hardware {
        return Err(libc::EOPNOTSUPP);
    }
    if tx_types & (1 << tx) == 0 {
        return Err(libc::ERANGE);
    }
    let applied = match mappings[rx as usize] {
        Some(outcome) => outcome?,
        None => hwtstamp_widenings(rx)
            .into_iter()
            .find(|&f| f == 0 || rx_filters & (1 << f) != 0)
            .ok_or(libc::ERANGE)?,
    };
    Ok([flags, tx, applied])
}

/// The clock index `N` if `path` is `/dev/ptp<N>`, else `None`.
#[cfg(target_os = "linux")]
fn parse_ptp_index(path: &Path) -> Option<u32> {
    path.to_str()?.strip_prefix("/dev/ptp")?.parse().ok()
}

/// The PTP ioctl magic byte (`'='`, `PTP_CLK_MAGIC` in include/uapi/linux/ptp_clock.h); the
/// request codes and struct layouts are there too, overview in Documentation/driver-api/ptp.rst.
#[cfg(target_os = "linux")]
const PTP_IOCTL_MAGIC: u64 = b'=' as u64;
/// `PTP_MAX_SAMPLES` (include/uapi/linux/ptp_clock.h): the most samples one `PTP_SYS_OFFSET` or
/// `PTP_SYS_OFFSET_EXTENDED` may ask for; more is `EINVAL`.
#[cfg(target_os = "linux")]
const PTP_MAX_SAMPLES: usize = 25;
/// `PTP_MAX_CHANNELS` (drivers/ptp/ptp_private.h): the highest channel `PTP_MASK_EN_SINGLE`
/// takes.
#[cfg(target_os = "linux")]
const PTP_MAX_CHANNELS: u32 = 2048;

/// `_IOC(dir, '=', nr, size)` (include/uapi/asm-generic/ioctl.h): `dir` 1 write, 2 read, 3 both.
#[cfg(target_os = "linux")]
const fn ptp_ioc(dir: u64, nr: u64, size: u64) -> u64 {
    (dir << 30) | (size << 16) | (PTP_IOCTL_MAGIC << 8) | nr
}

/// The PTP clock requests of include/uapi/linux/ptp_clock.h, each also numbered again (`*2`) with
/// the same layout; `ptp_ioctl` matches the whole request code.
#[cfg(target_os = "linux")]
mod ptp_req {
    use super::ptp_ioc;
    /// `struct ptp_clock_caps`: 20 ints.
    pub(super) const GETCAPS: [u64; 2] = [ptp_ioc(2, 1, 80), ptp_ioc(2, 10, 80)];
    /// `struct ptp_extts_request`: index, flags, `rsv[2]`.
    pub(super) const EXTTS: [u64; 2] = [ptp_ioc(1, 2, 16), ptp_ioc(1, 11, 16)];
    /// `struct ptp_perout_request`: start (or phase), period, index, flags, on (or `rsv[4]`).
    pub(super) const PEROUT: [u64; 2] = [ptp_ioc(1, 3, 56), ptp_ioc(1, 12, 56)];
    /// An `int`, passed by value.
    pub(super) const ENABLE_PPS: [u64; 2] = [ptp_ioc(1, 4, 4), ptp_ioc(1, 13, 4)];
    /// `struct ptp_sys_offset`: `n_samples`, `rsv[3]`, `ts[2 * PTP_MAX_SAMPLES + 1]`.
    pub(super) const SYS_OFFSET: [u64; 2] = [ptp_ioc(1, 5, 832), ptp_ioc(1, 14, 832)];
    /// `struct ptp_pin_desc`: `name[64]`, index, func, chan, `rsv[5]`.
    pub(super) const PIN_GETFUNC: [u64; 2] = [ptp_ioc(3, 6, 96), ptp_ioc(3, 15, 96)];
    pub(super) const PIN_SETFUNC: [u64; 2] = [ptp_ioc(1, 7, 96), ptp_ioc(1, 16, 96)];
    /// `struct ptp_sys_offset_precise`: device, `sys_realtime`, `sys_monoraw`, `rsv[4]`.
    pub(super) const PRECISE: [u64; 2] = [ptp_ioc(3, 8, 64), ptp_ioc(3, 17, 64)];
    /// `struct ptp_sys_offset_extended`: `n_samples`, `clockid`, `rsv[2]`,
    /// `ts[PTP_MAX_SAMPLES][3]`.
    pub(super) const EXTENDED: [u64; 2] = [ptp_ioc(3, 9, 1216), ptp_ioc(3, 18, 1216)];
    pub(super) const MASK_CLEAR_ALL: u64 = ptp_ioc(0, 19, 0);
    pub(super) const MASK_EN_SINGLE: u64 = ptp_ioc(1, 20, 4);
    pub(super) const PRECISE_CYCLES: u64 = ptp_ioc(3, 21, 64);
    pub(super) const EXTENDED_CYCLES: u64 = ptp_ioc(3, 22, 1216);
}

/// What a PTP request runs against: the clock's capabilities, whether the fd was opened for
/// writing (`FMODE_WRITE`), and whether the caller is root, standing in for `CAP_SYS_TIME`,
/// which [`crate::Privileges`] does not model.
#[cfg(target_os = "linux")]
struct PtpFile {
    caps: PtpCaps,
    writable: bool,
    root: bool,
}

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

/// A PTP clock request as drivers/ptp/ptp_chardev.c `ptp_ioctl` (Linux 7.0) answers it, the
/// readings taken from `sample` (`[device, realtime, monotonic]` at one instant; the sim's
/// `CLOCK_MONOTONIC` and `CLOCK_MONOTONIC_RAW` agree). `arg` is the caller's struct pointer
/// (`EFAULT` when null).
///
/// - `PTP_CLOCK_GETCAPS`: the [`PtpCaps`] words (`ptp_clock_getcaps`), the rest zero.
/// - `PTP_SYS_OFFSET`: `n_samples` above `PTP_MAX_SAMPLES` is `EINVAL`; otherwise `ts[]`
///   alternates system and device readings and ends on a system one (`ptp_sys_offset`).
/// - `PTP_SYS_OFFSET_PRECISE`: `EOPNOTSUPP` without `cross_timestamping`
///   (`ptp_sys_offset_precise`), else device, `CLOCK_REALTIME` and `CLOCK_MONOTONIC_RAW`.
/// - `PTP_SYS_OFFSET_EXTENDED`: `EOPNOTSUPP` without `gettimex64`; `EINVAL` past
///   `PTP_MAX_SAMPLES`, with `rsv[0]`/`rsv[1]` set, or for a `clockid` other than
///   `CLOCK_REALTIME`, `CLOCK_MONOTONIC` and `CLOCK_MONOTONIC_RAW` (`CLOCK_AUX` clocks are not
///   modelled); else each sample is the system clock, the device and the system clock again
///   (`ptp_sys_offset_extended`).
/// - The `_CYCLES` variants: `EOPNOTSUPP`, as for a clock without `has_cycles`.
/// - `PTP_EXTTS_REQUEST`, `PTP_PEROUT_REQUEST`, `PTP_PIN_SETFUNC`, `PTP_ENABLE_PPS`: `EACCES`
///   on an fd not open for writing. Then: the `*2` requests' reserved bits and flags are checked
///   (`EINVAL`), and a channel or pin past the clock's count is `EINVAL`; one within is accepted
///   (the driver's own flag checks are not modelled). `PTP_ENABLE_PPS` needs `CAP_SYS_TIME`
///   (`EPERM`) and is accepted where the clock has `pps`, else `EOPNOTSUPP` (what drivers'
///   `enable` returns for a request they lack).
/// - `PTP_PIN_GETFUNC`: `EINVAL` past `n_pins`, else the pin's index with function
///   `PTP_PF_NONE` and channel 0 (the sim's pins have no names).
/// - `PTP_MASK_CLEAR_ALL` succeeds; `PTP_MASK_EN_SINGLE` takes a channel up to
///   `PTP_MAX_CHANNELS` (`EFAULT` above, as the kernel reports it).
/// - Any other request is `ENOTTY`.
///
/// # Safety
/// `arg` points to the struct the request names, or is the value for `PTP_ENABLE_PPS`.
#[cfg(target_os = "linux")]
unsafe fn ptp_ioctl(
    clock: &PtpFile,
    request: u64,
    arg: i64,
    sample: impl FnOnce() -> [(i64, u32); 3],
) -> Option<FsResult> {
    use ptp_req::*;
    let base = arg as *mut u8;
    let word = |at: usize| unsafe { (base.add(at) as *const u32).read_unaligned() };
    let caps = clock.caps;
    let changes = EXTTS.contains(&request)
        || PEROUT.contains(&request)
        || PIN_SETFUNC.contains(&request)
        || ENABLE_PPS.contains(&request);
    if changes && !clock.writable {
        return err(libc::EACCES);
    }
    if ENABLE_PPS.contains(&request) {
        if !clock.root {
            return err(libc::EPERM);
        }
        return if caps.pps {
            ok(0)
        } else {
            err(libc::EOPNOTSUPP)
        };
    }
    if request == MASK_CLEAR_ALL {
        return ok(0);
    }
    if request == PRECISE_CYCLES || request == EXTENDED_CYCLES {
        return err(libc::EOPNOTSUPP);
    }
    let known = GETCAPS.contains(&request)
        || EXTTS.contains(&request)
        || PEROUT.contains(&request)
        || SYS_OFFSET.contains(&request)
        || PIN_GETFUNC.contains(&request)
        || PIN_SETFUNC.contains(&request)
        || PRECISE.contains(&request)
        || EXTENDED.contains(&request)
        || request == MASK_EN_SINGLE;
    if !known {
        return err(libc::ENOTTY);
    }
    if PRECISE.contains(&request) && !caps.cross_timestamping
        || EXTENDED.contains(&request) && !caps.extended
    {
        return err(libc::EOPNOTSUPP);
    }
    if base.is_null() {
        return err(libc::EFAULT);
    }
    let within = |index: u32, count: i32| i64::from(index) < i64::from(count);
    if GETCAPS.contains(&request) {
        let words = [
            caps.max_adj,
            caps.n_alarm,
            caps.n_ext_ts,
            caps.n_per_out,
            i32::from(caps.pps),
            caps.n_pins,
            i32::from(caps.cross_timestamping),
            i32::from(caps.adjust_phase),
            if caps.adjust_phase {
                caps.max_phase_adj
            } else {
                0
            },
        ];
        unsafe {
            std::ptr::write_bytes(base, 0, 80);
            for (i, w) in words.iter().enumerate() {
                (base.add(4 * i) as *mut i32).write_unaligned(*w);
            }
        }
        return ok(0);
    }
    if EXTTS.contains(&request) {
        // PTP_EXTTS_VALID_FLAGS: ENABLE_FEATURE, RISING_EDGE, FALLING_EDGE, STRICT_FLAGS,
        // EXT_OFFSET (bits 0..=4); PTP_EXTTS_EDGES the two edge bits.
        let (index, flags) = (word(0), word(4));
        if request == EXTTS[1]
            && (flags & !0x1f != 0
                || word(8) != 0
                || word(12) != 0
                || flags & 1 != 0 && flags & 0b110 == 0)
        {
            return err(libc::EINVAL);
        }
        return if within(index, caps.n_ext_ts) {
            ok(0)
        } else {
            err(libc::EINVAL)
        };
    }
    if PEROUT.contains(&request) {
        // PTP_PEROUT_VALID_FLAGS: ONE_SHOT, DUTY_CYCLE, PHASE (bits 0..=2); without DUTY_CYCLE
        // the trailing `rsv[4]` must be zero.
        let (index, flags) = (word(32), word(36));
        if request == PEROUT[1]
            && (flags & !0b111 != 0
                || flags & 0b10 == 0 && (40..56).step_by(4).any(|at| word(at) != 0))
        {
            return err(libc::EINVAL);
        }
        return if within(index, caps.n_per_out) {
            ok(0)
        } else {
            err(libc::EINVAL)
        };
    }
    if PIN_GETFUNC.contains(&request) || PIN_SETFUNC.contains(&request) {
        let index = word(64);
        let v2 = request == PIN_GETFUNC[1] || request == PIN_SETFUNC[1];
        if v2 && (76..96).step_by(4).any(|at| word(at) != 0) || !within(index, caps.n_pins) {
            return err(libc::EINVAL);
        }
        if PIN_GETFUNC.contains(&request) {
            unsafe {
                std::ptr::write_bytes(base, 0, 96);
                (base.add(64) as *mut u32).write_unaligned(index);
            }
        }
        return ok(0);
    }
    if request == MASK_EN_SINGLE {
        return if word(0) > PTP_MAX_CHANNELS {
            err(libc::EFAULT)
        } else {
            ok(0)
        };
    }
    let [device, realtime, monoraw] = sample();
    if PRECISE.contains(&request) {
        unsafe {
            std::ptr::write_bytes(base, 0, 64);
            write_ptp_clock_time(base, 0, device.0, device.1);
            write_ptp_clock_time(base, 16, realtime.0, realtime.1);
            write_ptp_clock_time(base, 32, monoraw.0, monoraw.1);
        }
        return ok(0);
    }
    if SYS_OFFSET.contains(&request) {
        let n = word(0) as usize;
        if n > PTP_MAX_SAMPLES {
            return err(libc::EINVAL);
        }
        for i in 0..n {
            let sys = 16 + i * 32;
            unsafe {
                write_ptp_clock_time(base, sys, realtime.0, realtime.1);
                write_ptp_clock_time(base, sys + 16, device.0, device.1);
            }
        }
        unsafe { write_ptp_clock_time(base, 16 + n * 32, realtime.0, realtime.1) };
        return ok(0);
    }
    let (n, clockid) = (word(0) as usize, word(4) as c_int);
    if n > PTP_MAX_SAMPLES || word(8) != 0 || word(12) != 0 {
        return err(libc::EINVAL);
    }
    let system = match clockid {
        libc::CLOCK_REALTIME => realtime,
        libc::CLOCK_MONOTONIC | libc::CLOCK_MONOTONIC_RAW => monoraw,
        _ => return err(libc::EINVAL),
    };
    for i in 0..n {
        let at = 16 + i * 48;
        unsafe {
            write_ptp_clock_time(base, at, system.0, system.1);
            write_ptp_clock_time(base, at + 16, device.0, device.1);
            write_ptp_clock_time(base, at + 32, system.0, system.1);
        }
    }
    ok(0)
}

/// Append an rtnetlink attribute (`rta_len`, `rta_type`, payload), padded to a 4-byte boundary
/// (`RTA_ALIGNTO` = 4, include/uapi/linux/rtnetlink.h; man 3 rtnetlink). `rta_len` covers the
/// header and payload but not the padding. `nul_terminate` appends the NUL a string attribute
/// carries.
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

/// `NLM_F_MULTI` (include/uapi/linux/netlink.h): marks each message of a multipart dump reply,
/// which `NLMSG_DONE` ends (man 7 netlink).
#[cfg(target_os = "linux")]
const NLM_F_MULTI: u16 = 2;

/// Appends the `NLMSG_DONE` (3, include/uapi/linux/netlink.h) that ends a dump: its payload is
/// the error code 0.
#[cfg(target_os = "linux")]
fn nl_done(out: &mut Vec<u8>, seq: u32) {
    const NLMSG_DONE: u16 = 3;
    out.extend_from_slice(&nl_message(
        NLMSG_DONE,
        NLM_F_MULTI,
        seq,
        &0i32.to_ne_bytes(),
    ));
}

/// The `IF_OPER_*` value of an operstate (`<linux/if.h>`, RFC 2863;
/// Documentation/networking/operstates.rst). Anything unrecognised is `IF_OPER_UNKNOWN` (0).
#[cfg(target_os = "linux")]
fn oper_code(state: &str) -> u8 {
    match state {
        "notpresent" => 1,
        "down" => 2,
        "lowerlayerdown" => 3,
        "testing" => 4,
        "dormant" => 5,
        "up" => 6,
        _ => 0,
    }
}

/// Build an `RTM_GETLINK` dump reply (man 7 rtnetlink): one `RTM_NEWLINK` per interface in index
/// order, carrying `IFLA_IFNAME`, `IFLA_MTU`, `IFLA_OPERSTATE`, `IFLA_CARRIER`, `IFLA_ADDRESS`,
/// `IFLA_BROADCAST` (all-ones, or zeros on loopback) and `IFLA_STATS64`, then `NLMSG_DONE`.
/// Native byte order, as the kernel.
///
/// The body starts with a 16-byte `struct ifinfomsg` (family, pad, `ifi_type`, `ifi_index`,
/// `ifi_flags`, `ifi_change`; include/uapi/linux/rtnetlink.h). `IFLA_*` numbers are from
/// include/uapi/linux/if_link.h, `ARPHRD_*` from include/uapi/linux/if_arp.h. Each NIC is paired
/// with the operstate string [`HostState::operstate`] computed for it.
#[cfg(target_os = "linux")]
fn build_getlink_dump(nics: &[(&NicSnapshot, String)], seq: u32) -> Vec<u8> {
    let mut out = Vec::new();
    for (nic, operstate) in nics {
        out.extend_from_slice(&getlink_message(nic, operstate, NLM_F_MULTI, seq));
    }
    nl_done(&mut out, seq);
    out
}

/// One `RTM_NEWLINK` of an [`RTM_GETLINK`](build_getlink_dump) reply, with header `flags`.
#[cfg(target_os = "linux")]
fn getlink_message(nic: &NicSnapshot, operstate: &str, flags: u16, seq: u32) -> Vec<u8> {
    const RTM_NEWLINK: u16 = 16;
    const IFLA_ADDRESS: u16 = 1;
    const IFLA_BROADCAST: u16 = 2;
    const IFLA_IFNAME: u16 = 3;
    const IFLA_MTU: u16 = 4;
    const IFLA_OPERSTATE: u16 = 16;
    const IFLA_STATS64: u16 = 23;
    const IFLA_CARRIER: u16 = 33;
    const ARPHRD_ETHER: u16 = 1;
    const ARPHRD_LOOPBACK: u16 = 772;

    let mut body = Vec::new();
    body.push(0); // ifi_family = AF_UNSPEC
    body.push(0);
    let hatype = if nic.loopback {
        ARPHRD_LOOPBACK
    } else {
        ARPHRD_ETHER
    };
    body.extend_from_slice(&hatype.to_ne_bytes());
    body.extend_from_slice(&(nic.index as i32).to_ne_bytes());
    body.extend_from_slice(&crate::ifaddrs::flags(nic).to_ne_bytes()); // ifi_flags
    body.extend_from_slice(&0u32.to_ne_bytes()); // ifi_change
    push_rtattr(&mut body, IFLA_IFNAME, nic.spec.name.as_bytes(), true);
    push_rtattr(&mut body, IFLA_MTU, &nic.spec.mtu.to_ne_bytes(), false);
    push_rtattr(&mut body, IFLA_OPERSTATE, &[oper_code(operstate)], false);
    push_rtattr(
        &mut body,
        IFLA_CARRIER,
        &[u8::from(nic.spec.carrier)],
        false,
    );
    push_rtattr(&mut body, IFLA_ADDRESS, &nic.hw_addr(), false);
    let broadcast = if nic.loopback { [0; 6] } else { [0xff; 6] };
    push_rtattr(&mut body, IFLA_BROADCAST, &broadcast, false);
    // struct rtnl_link_stats64 (<linux/if_link.h>) up to rx_nohandler: 24 __u64 counters,
    // tx_carrier_errors at index 17, rx_nohandler at 23. Newer kernels append
    // rx_otherhost_dropped; readers take the attribute length as given.
    let c = &nic.counters;
    let mut stats = [0u64; 24];
    for (i, v) in [
        (0, c.rx_packets),
        (1, c.tx_packets),
        (2, c.rx_bytes),
        (3, c.tx_bytes),
        (4, c.rx_errors),
        (5, c.tx_errors),
        (6, c.rx_dropped),
        (7, c.tx_dropped),
        (8, c.multicast),
        (17, c.tx_carrier_errors),
        (23, c.rx_nohandler),
    ] {
        stats[i] = v;
    }
    let stats: Vec<u8> = stats.iter().flat_map(|v| v.to_ne_bytes()).collect();
    push_rtattr(&mut body, IFLA_STATS64, &stats, false);
    nl_message(RTM_NEWLINK, flags, seq, &body)
}

/// The `rtm_scope` / `ifa_scope` of an address (`<linux/rtnetlink.h>`): host for loopback, link
/// for IPv6 link-local (`fe80::/10`, RFC 4291 §2.5.6), universe otherwise. IPv4 link-local
/// (169.254/16) is reported as universe: the kernel stores the scope the configuring request
/// carries (net/ipv4/devinet.c, `inet_rtm_to_ifa`), and iproute2 defaults it to universe for
/// every IPv4 address outside 127/8 (ip/ipaddress.c, `default_scope`).
#[cfg(target_os = "linux")]
fn addr_scope(ip: std::net::IpAddr) -> u8 {
    const RT_SCOPE_UNIVERSE: u8 = 0;
    const RT_SCOPE_LINK: u8 = 253;
    const RT_SCOPE_HOST: u8 = 254;
    match ip {
        ip if ip.is_loopback() => RT_SCOPE_HOST,
        std::net::IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80 => RT_SCOPE_LINK,
        _ => RT_SCOPE_UNIVERSE,
    }
}

/// The address in network byte order, as an `IFA_*`/`RTA_*` payload carries it.
#[cfg(target_os = "linux")]
fn ip_bytes(ip: std::net::IpAddr) -> Vec<u8> {
    match ip {
        std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
        std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// `AF_INET` or `AF_INET6` as the one-byte family field of `ifaddrmsg`/`rtmsg`.
#[cfg(target_os = "linux")]
fn family_of(ip: std::net::IpAddr) -> u8 {
    if ip.is_ipv4() {
        libc::AF_INET as u8
    } else {
        libc::AF_INET6 as u8
    }
}

/// Build an `RTM_GETADDR` dump reply (man 7 rtnetlink): one `RTM_NEWADDR` (`struct ifaddrmsg`
/// with `IFA_ADDRESS`, and for IPv4 `IFA_LOCAL`, `IFA_LABEL` and `IFA_BROADCAST`) per host address,
/// IPv4 before IPv6, limited to `family` unless it is `AF_UNSPEC`. The 8-byte `ifaddrmsg` is
/// family, prefix length, flags (`IFA_F_PERMANENT`, a statically configured address), scope and
/// ifindex; `IFA_*` numbers and flags are in include/uapi/linux/if_addr.h. IPv4 carries
/// `IFA_LOCAL` equal to `IFA_ADDRESS` as on a non-point-to-point link, and loopback gets no
/// broadcast.
#[cfg(target_os = "linux")]
fn build_getaddr_dump(nics: &[NicSnapshot], family: u8, seq: u32) -> Vec<u8> {
    const RTM_NEWADDR: u16 = 20;
    const IFA_ADDRESS: u16 = 1;
    const IFA_LOCAL: u16 = 2;
    const IFA_LABEL: u16 = 3;
    const IFA_BROADCAST: u16 = 4;
    const IFA_F_PERMANENT: u8 = 0x80;

    let mut out = Vec::new();
    for v4 in [true, false] {
        let fam = if v4 { libc::AF_INET } else { libc::AF_INET6 } as u8;
        if family != 0 && family != fam {
            continue;
        }
        for nic in nics {
            for net in nic.spec.addresses.iter().filter(|n| n.addr.is_ipv4() == v4) {
                let mut body = vec![fam, net.prefix, IFA_F_PERMANENT, addr_scope(net.addr)];
                body.extend_from_slice(&nic.index.to_ne_bytes());
                push_rtattr(&mut body, IFA_ADDRESS, &ip_bytes(net.addr), false);
                if v4 {
                    push_rtattr(&mut body, IFA_LOCAL, &ip_bytes(net.addr), false);
                    if let Some(b) = net.broadcast().filter(|_| !nic.loopback) {
                        push_rtattr(&mut body, IFA_BROADCAST, &ip_bytes(b), false);
                    }
                    push_rtattr(&mut body, IFA_LABEL, nic.spec.name.as_bytes(), true);
                }
                out.extend_from_slice(&nl_message(RTM_NEWADDR, NLM_F_MULTI, seq, &body));
            }
        }
    }
    nl_done(&mut out, seq);
    out
}

/// Build an `RTM_GETROUTE` dump reply (man 7 rtnetlink): one `RTM_NEWROUTE` (`struct rtmsg` in
/// the main table with `RTA_TABLE`, `RTA_DST`, `RTA_GATEWAY`, `RTA_PREFSRC`, `RTA_PRIORITY` and
/// `RTA_OIF`) per route in the table, limited to `family` unless it is `AF_UNSPEC`. Connected
/// routes are the kernel's (link scope), the rest boot-protocol routes.
///
/// A route counts as connected when it has no gateway, metric 0 and a non-default prefix. The
/// 12-byte `rtmsg` is family, dst/src prefix lengths, TOS, table, protocol, scope, type and flags;
/// `RT_TABLE_*`, `RTPROT_*`, `RT_SCOPE_*`, `RTN_*` and `RTA_*` are in
/// include/uapi/linux/rtnetlink.h. Each route is paired with its outgoing ifindex.
#[cfg(target_os = "linux")]
fn build_getroute_dump(routes: &[(Route, u32)], family: u8, seq: u32) -> Vec<u8> {
    const RTM_NEWROUTE: u16 = 24;
    const RT_TABLE_MAIN: u8 = 254;
    const RTPROT_KERNEL: u8 = 2;
    const RTPROT_BOOT: u8 = 3;
    const RT_SCOPE_UNIVERSE: u8 = 0;
    const RT_SCOPE_LINK: u8 = 253;
    const RTN_UNICAST: u8 = 1;
    const RTA_DST: u16 = 1;
    const RTA_OIF: u16 = 4;
    const RTA_GATEWAY: u16 = 5;
    const RTA_PRIORITY: u16 = 6;
    const RTA_PREFSRC: u16 = 7;
    const RTA_TABLE: u16 = 15;

    let mut out = Vec::new();
    for (route, index) in routes {
        let fam = family_of(route.dest.addr);
        if family != 0 && family != fam {
            continue;
        }
        let connected = route.gateway.is_none() && route.metric == 0 && route.dest.prefix > 0;
        let (protocol, scope) = if connected {
            (RTPROT_KERNEL, RT_SCOPE_LINK)
        } else {
            (RTPROT_BOOT, RT_SCOPE_UNIVERSE)
        };
        let mut body = vec![
            fam,
            route.dest.prefix,
            0,
            0,
            RT_TABLE_MAIN,
            protocol,
            scope,
            RTN_UNICAST,
        ];
        body.extend_from_slice(&0u32.to_ne_bytes()); // rtm_flags
        push_rtattr(
            &mut body,
            RTA_TABLE,
            &(RT_TABLE_MAIN as u32).to_ne_bytes(),
            false,
        );
        if route.dest.prefix > 0 {
            push_rtattr(&mut body, RTA_DST, &ip_bytes(route.dest.network()), false);
        }
        if let Some(gw) = route.gateway {
            push_rtattr(&mut body, RTA_GATEWAY, &ip_bytes(gw), false);
        }
        if let Some(src) = route.src {
            push_rtattr(&mut body, RTA_PREFSRC, &ip_bytes(src), false);
        }
        if route.metric > 0 {
            push_rtattr(&mut body, RTA_PRIORITY, &route.metric.to_ne_bytes(), false);
        }
        push_rtattr(&mut body, RTA_OIF, &index.to_ne_bytes(), false);
        out.extend_from_slice(&nl_message(RTM_NEWROUTE, NLM_F_MULTI, seq, &body));
    }
    nl_done(&mut out, seq);
    out
}

/// Prepend a 16-byte `nlmsghdr` (length patched to the whole message, `nlmsg_pid = 0`) to `body`
/// and pad the result to a 4-byte boundary (`NLMSG_ALIGNTO`, include/uapi/linux/netlink.h).
/// `nlmsg_pid` 0 marks a message from the kernel (man 7 netlink).
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

/// Find a netlink attribute's payload by type within `attrs` (a run of `nlattr`s, each 4-byte
/// aligned; include/uapi/linux/netlink.h). Stops at the first malformed length. The type is
/// compared whole, so an attribute with `NLA_F_NESTED`/`NLA_F_NET_BYTEORDER` set does not match.
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
///
/// The kernel answers an unknown family with `-ENOENT` (net/netlink/genetlink.c,
/// `ctrl_getfamily`); the sim's `-ENODEV` differs, and a caller only sees that the lookup failed.
/// The request's `genlmsghdr.cmd` is the byte at 16, its attributes start at 20 (after the
/// 4-byte `genlmsghdr`). The reply's version 2 is the controller family's `.version`
/// (net/netlink/genetlink.c, `genl_ctrl`).
#[cfg(target_os = "linux")]
fn build_genl_ctrl_reply(req: &[u8], seq: u32) -> Vec<u8> {
    const CTRL_CMD_NEWFAMILY: u8 = 1;
    const CTRL_CMD_GETFAMILY: u8 = 3;
    const CTRL_ATTR_FAMILY_ID: u16 = 1;
    const CTRL_ATTR_FAMILY_NAME: u16 = 2;
    const GENL_ID_CTRL: u16 = 16;
    const NLMSG_ERROR: u16 = 2;
    // A snare choice: the kernel allocates generic-netlink family ids dynamically
    // (`idr_alloc_cyclic` from GENL_START_ALLOC, net/netlink/genetlink.c), so any id works.
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
    push_rtattr(
        &mut body,
        CTRL_ATTR_FAMILY_ID,
        &NETDEV_FAMILY_ID.to_ne_bytes(),
        false,
    );
    push_rtattr(&mut body, CTRL_ATTR_FAMILY_NAME, b"netdev", true);
    nl_message(GENL_ID_CTRL, 0, seq, &body)
}

/// Build an `RTM_GETQDISC` reply: one `RTM_NEWQDISC` per qdisc of each interface in index order
/// (`tc_dump_qdisc` walks every device, root first), each carrying `TCA_KIND` and, for `etf`, a
/// nested `TCA_OPTIONS`/`TCA_ETF_PARMS` (`struct tc_etf_qopt` in <linux/pkt_sched.h>, man 8
/// tc-etf), terminated by `NLMSG_DONE`.
///
/// Each message is a 20-byte `struct tcmsg` (include/uapi/linux/rtnetlink.h: family, two pad
/// fields, `tcm_ifindex`, `tcm_handle`, `tcm_parent`, `tcm_info`) and its attributes; a root's
/// parent is `TC_H_ROOT`. `TCA_KIND`/`TCA_OPTIONS` are from include/uapi/linux/rtnetlink.h,
/// `TCA_ETF_PARMS` from include/uapi/linux/pkt_sched.h.
#[cfg(target_os = "linux")]
fn build_getqdisc_dump(nics: &[&NicState], seq: u32) -> Vec<u8> {
    const RTM_NEWQDISC: u16 = 36;
    const NLMSG_DONE: u16 = 3;
    const NLM_F_MULTI: u16 = 2;
    const TCA_KIND: u16 = 1;
    const TCA_OPTIONS: u16 = 2;
    const TCA_ETF_PARMS: u16 = 1;

    let mut out = Vec::new();
    for nic in nics {
        for (handle, parent, q) in nic.qdiscs.listing(nic.tx_queues) {
            let mut body = vec![0u8, 0, 0, 0];
            body.extend_from_slice(&(nic.ifindex as i32).to_ne_bytes());
            body.extend_from_slice(&handle.to_ne_bytes());
            body.extend_from_slice(&parent.to_ne_bytes());
            body.extend_from_slice(&0u32.to_ne_bytes());
            push_rtattr(&mut body, TCA_KIND, q.kind.as_bytes(), true);
            if let Some((delta, clockid, flags)) = q.etf {
                let mut parms = Vec::new();
                parms.extend_from_slice(&delta.to_ne_bytes());
                parms.extend_from_slice(&clockid.to_ne_bytes());
                parms.extend_from_slice(&flags.to_ne_bytes());
                let mut opts = Vec::new();
                push_rtattr(&mut opts, TCA_ETF_PARMS, &parms, false);
                push_rtattr(&mut body, TCA_OPTIONS, &opts, false);
            }
            out.extend_from_slice(&nl_message(RTM_NEWQDISC, NLM_F_MULTI, seq, &body));
        }
    }
    out.extend_from_slice(&nl_message(
        NLMSG_DONE,
        NLM_F_MULTI,
        seq,
        &0i32.to_ne_bytes(),
    ));
    out
}

/// The host's datagram (`AF_INET`/`AF_INET6` `SOCK_DGRAM`) and `AF_NETLINK` sockets, and the NIC
/// ioctls. Linux only; on other targets every hook keeps the trait's declining default. Stream
/// sockets and any fd the host did not mint are declined.
impl Net for SimHost {
    /// `FIONREAD`/`SIOCOUTQ` and `FIONBIO` on a host datagram socket; `SIOCETHTOOL` (the
    /// NIC's driver, see [`crate::ethtool`]), `SIOCSHWTSTAMP` and `SIOCGHWTSTAMP` on any fd
    /// naming a profile NIC. `SIOCOUTQ` always reads 0: a sent datagram leaves at once.
    #[cfg(target_os = "linux")]
    unsafe fn ioctl(&self, fd: c_int, request: u64, arg: i64) -> Option<NetResult> {
        // fs/ioctl.c ioctl_fionbio: FIONBIO sets O_NONBLOCK from a pointed-to int —
        // what std's `set_nonblocking` uses on Linux, so a host-modelled UDP socket must honour it.
        // man 7 udp: SIOCINQ (FIONREAD) is the next datagram's size, SIOCOUTQ the unsent bytes.
        if request == libc::FIONREAD || request == libc::TIOCOUTQ {
            let rec = self.state.lock().unwrap().udp.get(&fd)?.rec.clone();
            if arg == 0 {
                return err(libc::EFAULT);
            }
            let value = if request == libc::FIONREAD {
                rec.fionread()
            } else {
                0
            };
            unsafe { (arg as *mut c_int).write_unaligned(value) };
            return ok(0);
        }
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
        // FIONREAD, whose arg is a 4-byte `int`) would read out of bounds. The interface queries
        // (SIOCGIF*) are the topology's, which the fabric behind this host answers.
        if !matches!(request, SIOCETHTOOL | SIOCSHWTSTAMP | SIOCGHWTSTAMP) {
            return None;
        }
        let name = unsafe { read_ifname(arg) }?;
        let base = arg as *mut u8;
        let mut state = self.state.lock().unwrap();
        let has_net_admin = state.has_cap(CAP_NET_ADMIN);
        let link_up = state
            .topo_nic(&name)
            .is_some_and(|n| n.spec.admin_up && n.spec.carrier);
        let nic = state.nics.get_mut(&name)?;
        match request {
            SIOCETHTOOL => {
                // ifr_data: the union after the 16-byte ifr_name (include/uapi/linux/if.h).
                let data = unsafe { (base.add(16) as *const *mut u8).read_unaligned() };
                if data.is_null() {
                    return err(libc::EFAULT);
                }
                let ctx = crate::ethtool::Ctx {
                    net_admin: has_net_admin,
                    link_up,
                    hw_timestamping: nic.hwtstamp_supported,
                    driver: &nic.driver,
                    version: &nic.driver_version,
                    bus_info: &nic.bus_info,
                    queues: (&mut nic.rx_queues, &mut nic.tx_queues),
                };
                match unsafe { nic.ethtool.ioctl(ctx, data) } {
                    Ok(()) => ok(0),
                    Err(e) => err(e),
                }
            }
            SIOCSHWTSTAMP => {
                if !has_net_admin {
                    return err(libc::EPERM);
                }
                let data = unsafe { (base.add(16) as *const *mut c_int).read_unaligned() };
                if data.is_null() {
                    return err(libc::EFAULT);
                }
                let cfg: [c_int; 3] =
                    std::array::from_fn(|i| unsafe { data.add(i).read_unaligned() });
                let (_, tx_types, rx_filters) = nic.ethtool.timestamping(nic.hwtstamp_supported);
                match apply_hwtstamp(
                    cfg,
                    nic.hwtstamp_supported,
                    tx_types,
                    rx_filters,
                    &nic.hwtstamp_rx_mapping,
                ) {
                    Ok(applied) => {
                        nic.hwtstamp = applied;
                        for (i, v) in applied.iter().enumerate() {
                            unsafe { data.add(i).write_unaligned(*v) };
                        }
                        ok(0)
                    }
                    Err(e) => err(e),
                }
            }
            SIOCGHWTSTAMP => {
                // net/core/dev_ioctl.c `dev_get_hwtstamp`: a driver without `ndo_hwtstamp_get`
                // is EOPNOTSUPP before anything is copied.
                if !nic.hwtstamp_supported {
                    return err(libc::EOPNOTSUPP);
                }
                let data = unsafe { (base.add(16) as *const *mut c_int).read_unaligned() };
                if data.is_null() {
                    return err(libc::EFAULT);
                }
                for (i, v) in nic.hwtstamp.iter().enumerate() {
                    unsafe { data.add(i).write_unaligned(*v) };
                }
                ok(0)
            }
            _ => None,
        }
    }

    /// Whether `fd` is one of the host's datagram or netlink sockets.
    #[cfg(target_os = "linux")]
    fn owns(&self, fd: c_int) -> bool {
        let state = self.state.lock().unwrap();
        state.udp.contains_key(&fd) || state.netlinks.contains_key(&fd)
    }

    /// Creates a netlink socket (any protocol) or an IPv4/IPv6 datagram socket. The socket type is
    /// taken from the type's low byte (the kernel masks with `SOCK_TYPE_MASK` = 0xf,
    /// include/linux/net.h); `SOCK_NONBLOCK`/`SOCK_CLOEXEC` are flags OR'd above it.
    #[cfg(target_os = "linux")]
    unsafe fn socket(&self, domain: c_int, ty: c_int, protocol: c_int) -> Option<NetResult> {
        if domain == libc::AF_NETLINK {
            // netlink_create (net/netlink/af_netlink.c) takes only raw and datagram sockets.
            let base = ty & 0xf;
            if base != libc::SOCK_RAW && base != libc::SOCK_DGRAM {
                return err(libc::ESOCKTNOSUPPORT);
            }
            let (fd, rec) = match self.open_socket(SocketKind::Netlink) {
                Ok(opened) => opened,
                Err(errno) => return err(errno),
            };
            rec.set_family(domain, protocol);
            rec.set_type(base);
            let probe = Arc::new(NetlinkRx {
                host: self.me.get().cloned().unwrap_or_default(),
                id: rec.id.get(),
            });
            rec.set_probe(Arc::downgrade(&probe) as std::sync::Weak<dyn RxProbe>);
            self.state.lock().unwrap().netlinks.insert(
                fd,
                NetlinkSocket {
                    replies: std::collections::VecDeque::new(),
                    responses: 0,
                    rec,
                    _probe: probe,
                    nonblocking: ty & libc::SOCK_NONBLOCK != 0,
                    descriptors: std::collections::BTreeSet::from([fd]),
                    sockopts: HashMap::new(),
                },
            );
            if ty & libc::SOCK_CLOEXEC != 0 {
                snare_interpose::real(|| unsafe {
                    libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC)
                });
            }
            return ok(fd as i64);
        }
        if domain != libc::AF_INET && domain != libc::AF_INET6 {
            return None;
        }
        if ty & 0xFF != libc::SOCK_DGRAM {
            return None; // only datagram sockets are modelled; TCP falls through to the OS
        }
        let (fd, rec) = match self.open_socket(SocketKind::Udp) {
            Ok(opened) => opened,
            Err(errno) => return err(errno),
        };
        rec.set_family(
            domain,
            if protocol == 0 {
                libc::IPPROTO_UDP
            } else {
                protocol
            },
        );
        rec.set_type(libc::SOCK_DGRAM);
        let probe = Arc::new(HostRx {
            host: self.me.get().cloned().unwrap_or_default(),
            id: rec.id.get(),
        });
        rec.set_probe(Arc::downgrade(&probe) as std::sync::Weak<dyn RxProbe>);
        let nonblocking = ty & libc::SOCK_NONBLOCK != 0;
        self.state.lock().unwrap().udp.insert(
            fd,
            UdpSocket {
                fd,
                descriptors: std::collections::BTreeSet::from([fd]),
                domain,
                local: None,
                requested: None,
                peer: None,
                rx: crate::limits::RxQueue::default(),
                nonblocking,
                broadcast: false,
                sockopts: HashMap::new(),
                tx_deadline: None,
                rec,
                _probe: probe,
            },
        );
        if ty & libc::SOCK_CLOEXEC != 0 {
            let result = snare_interpose::real(|| unsafe {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC)
            });
            if result < 0 {
                let errno = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EMFILE);
                unsafe { Net::close(self, fd) };
                return err(errno);
            }
        }
        ok(fd as i64)
    }

    /// Binds a datagram socket (man 2 bind). The address must be one the topology lets the host
    /// claim, and a port below `ip_unprivileged_port_start` needs `CAP_NET_BIND_SERVICE` (`EACCES`;
    /// man 7 ip; Documentation/networking/ip-sysctl.rst, default 1024); both checks are the sim's.
    /// Port 0 picks an ephemeral port.
    /// An exact address already bound is `EADDRINUSE`; `SO_REUSEADDR`/`SO_REUSEPORT` sharing is
    /// not modelled here. A wildcard and a specific address on the same port coexist. Rebinding a
    /// bound socket, which Linux refuses with `EINVAL`, is not checked.
    #[cfg(target_os = "linux")]
    unsafe fn bind(&self, fd: c_int, addr: *const u8, len: u32) -> Option<NetResult> {
        if !self.state.lock().unwrap().udp.contains_key(&fd) {
            return None;
        }
        let Some(mut sa) = (unsafe { read_sockaddr(addr, len) }) else {
            return err(libc::EINVAL);
        };
        if let Some(shared) = self.shared() {
            if let Err(errno) = shared.claim_address(sa.ip()) {
                return err(errno);
            }
            if let Some(errno) = shared.sys.bind_denied(sa) {
                return err(errno);
            }
        }
        let asked = sa;
        let mut state = self.state.lock().unwrap();
        if sa.port() == 0 {
            let Some(p) = state.alloc_ephemeral(sa.ip()) else {
                return err(libc::EADDRINUSE);
            };
            sa.set_port(p);
        } else if state.bound.contains_key(&sa) {
            return err(libc::EADDRINUSE);
        }
        state.bound.insert(sa, fd);
        let sock = state.udp.get_mut(&fd).unwrap();
        sock.local = Some(sa);
        sock.requested = Some(asked);
        sock.rec.set_local(sa);
        ok(0)
    }

    /// Sets a datagram socket's default peer after checking the route; a socket bound to the
    /// wildcard takes the route's source address (see [`crate::netif::Sender::connected_local`]).
    /// An `AF_UNSPEC` address dissolves the association as `__udp_disconnect` (net/ipv4/udp.c)
    /// does: the local address returns to the wildcard unless `bind` named one, and the port is
    /// given up unless `bind` named one. Any other address is parsed before the fd's ownership is
    /// checked, so a non-INET address on an fd the host does not own is answered `EINVAL` rather
    /// than declined.
    #[cfg(target_os = "linux")]
    unsafe fn connect(&self, fd: c_int, addr: *const u8, len: u32) -> Option<NetResult> {
        if !self.state.lock().unwrap().udp.contains_key(&fd) {
            return None;
        }
        if !addr.is_null()
            && len as usize >= size_of::<libc::sa_family_t>()
            && unsafe { (*addr.cast::<libc::sockaddr>()).sa_family } as c_int == libc::AF_UNSPEC
        {
            self.state.lock().unwrap().udp_disconnect(fd);
            return ok(0);
        }
        let Some(dest) = (unsafe { read_sockaddr(addr, len) }) else {
            return err(libc::EINVAL);
        };
        let (local, requested, broadcast, rec) = {
            let state = self.state.lock().unwrap();
            let sock = state.udp.get(&fd)?;
            (sock.local, sock.requested, sock.broadcast, sock.rec.clone())
        };
        let unhashed = requested.map(|r| std::net::SocketAddr::new(r.ip(), 0));
        // man 2 connect on a datagram socket: fix the default peer, taking the route's source
        // address at an ephemeral port first if unbound so the peer can address a reply.
        let regs = self.registries.lock().unwrap().clone()?;
        let station = regs.station_at(dest.ip());
        let sender = match regs.shared.route_send(
            &rec.view(local.or(unhashed)),
            dest,
            crate::netif::Op::Connect,
            station,
            broadcast,
        ) {
            Ok(sender) => sender,
            Err(errno) => return err(errno),
        };
        let mut state = self.state.lock().unwrap();
        match state.udp.get(&fd)?.local {
            None => {
                let unspecified = if dest.is_ipv4() {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                } else {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                };
                let unbound = unhashed.unwrap_or(std::net::SocketAddr::new(unspecified, 0));
                let ip = sender.connected_local(unbound).ip();
                let Some(p) = state.alloc_ephemeral(ip) else {
                    return err(libc::EAGAIN);
                };
                let sa = std::net::SocketAddr::new(ip, p);
                state.bound.insert(sa, fd);
                state.udp.get_mut(&fd).unwrap().local = Some(sa);
            }
            Some(bound) => state.rehash(fd, bound, sender.connected_local(bound)),
        }
        let sock = state.udp.get_mut(&fd).unwrap();
        sock.peer = Some(dest);
        if let Some(local) = sock.local {
            sock.rec.set_local(local);
        }
        sock.rec.set_peer(Some(dest));
        ok(0)
    }

    /// On a netlink socket the buffer is a request: its reply is queued at once and the whole
    /// length reported sent. On a datagram socket, sends one datagram to `addr`; a NULL `addr`
    /// is `EINVAL` even when connected (the kernel would use the peer). The address is parsed
    /// before the fd's ownership is checked, so a NULL or non-INET address on an fd the host does
    /// not own is also answered `EINVAL` rather than declined. Charges one call latency
    /// and ticks the virtual realtime clock to stamp the send.
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
                let reply = state.queue_netlink_reply(fd, &req);
                drop(state);
                if let Some(reply) = reply
                    && let Some(shared) = self.shared()
                {
                    shared.bump_keys(&[reply.wake_key()]);
                }
                return ok(len as i64);
            }
        }
        let Some(dest) = (unsafe { read_sockaddr(addr, addr_len) }) else {
            return err(libc::EINVAL);
        };
        snare_interpose::charge_latency();
        let now = self.clock.tick_realtime();
        let data = if buf.is_null() || len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(buf, len) }.to_vec()
        };
        if !self.state.lock().unwrap().udp.contains_key(&fd) {
            return None;
        }
        self.udp_send(fd, data, dest, now)
    }

    /// Gathers the iovecs into one datagram (or netlink request), checks and records an
    /// `SCM_TXTIME` deadline ([`crate::tstamp::txtime_cmsg`]: `EINVAL` without `SO_TXTIME` or
    /// for a malformed message, as udp_sendmsg's `ip_cmsg_send` reports), then sends as `sendto`.
    /// Like `sendto`, a message without an INET `msg_name` is `EINVAL`, on any fd that is not a
    /// host netlink socket, owned or not.
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
                let reply = state.queue_netlink_reply(fd, &data);
                drop(state);
                if let Some(reply) = reply
                    && let Some(shared) = self.shared()
                {
                    shared.bump_keys(&[reply.wake_key()]);
                }
                return ok(data.len() as i64);
            }
        }
        let Some(dest) =
            (unsafe { read_sockaddr((*hdr).msg_name as *const u8, (*hdr).msg_namelen) })
        else {
            return err(libc::EINVAL);
        };
        let rec = self.state.lock().unwrap().udp.get(&fd)?.rec.clone();
        match unsafe { crate::tstamp::txtime_cmsg(&rec, hdr) } {
            Ok(Some(deadline)) => {
                if let Some(sock) = self.state.lock().unwrap().udp.get_mut(&fd) {
                    sock.tx_deadline = Some(deadline);
                }
            }
            Ok(None) => {}
            Err(errno) => return err(errno),
        }
        let len = data.len();
        let ptr = data.as_ptr();
        let dest_bytes = sockaddr_bytes(dest);
        unsafe {
            self.sendto(
                fd,
                ptr,
                len,
                flags,
                dest_bytes.as_ptr(),
                dest_bytes.len() as u32,
            )
        }
    }

    /// A netlink request, or a datagram to the connected peer.
    #[cfg(target_os = "linux")]
    unsafe fn send(
        &self,
        fd: c_int,
        buf: *const u8,
        len: usize,
        _flags: c_int,
    ) -> Option<NetResult> {
        {
            let mut state = self.state.lock().unwrap();
            if state.netlinks.contains_key(&fd) {
                let req = if buf.is_null() || len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(buf, len) }.to_vec()
                };
                let reply = state.queue_netlink_reply(fd, &req);
                drop(state);
                if let Some(reply) = reply
                    && let Some(shared) = self.shared()
                {
                    shared.bump_keys(&[reply.wake_key()]);
                }
                return ok(len as i64);
            }
            match state.udp.get(&fd) {
                // man 2 send: a datagram socket with no connected peer has nowhere to send.
                Some(sock) if sock.peer.is_none() => return err(libc::EDESTADDRREQ),
                Some(_) => {}
                None => return None,
            }
        }
        snare_interpose::charge_latency();
        let now = self.clock.tick_realtime();
        let data = if buf.is_null() || len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(buf, len) }.to_vec()
        };
        let dest = self
            .state
            .lock()
            .unwrap()
            .udp
            .get(&fd)
            .and_then(|s| s.peer)?;
        self.udp_send(fd, data, dest, now)
    }

    /// Receives a netlink reply or a datagram (man 2 recv). A netlink socket with nothing queued
    /// returns `EAGAIN` rather than blocking, since nothing will ever arrive unrequested. A
    /// datagram larger than `len` is truncated and the rest discarded (man 7 udp). `MSG_PEEK`
    /// returns the next datagram and leaves it queued, and reads a pending error without
    /// clearing it on macOS (see [`crate::sockets::Taker::Peek`]). A blocking receive waits on the sim's
    /// readiness until a datagram lands, an error is pending, `SO_RCVTIMEO` expires or the sim
    /// is quiescent (both `EAGAIN`). Reading a datagram moves the virtual clock to its arrival.
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
            if let Some(q) = state.netlinks.get_mut(&fd).map(|n| &mut n.replies) {
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
        let (_peer, nonblocking, rec) = {
            let state = self.state.lock().unwrap();
            let sock = state.udp.get(&fd)?;
            (sock.peer, sock.nonblocking, sock.rec.clone())
        };
        let shared = self.shared()?;
        rec.land();
        let deadline = rec.opts().rcvtimeo.map(crate::readiness::Deadline::timeout);
        // A connected socket only accepts datagrams from its peer; an unconnected one from anyone.
        let pop = || {
            let mut state = self.state.lock().unwrap();
            let sock = state.udp.get_mut(&fd)?;
            let accept = |_| true;
            if flags & libc::MSG_PEEK != 0 {
                sock.rx.peek(accept, Some(&sock.rec)).map(|(dg, _)| dg)
            } else {
                sock.rx.pop(accept, Some(&sock.rec)).map(|(dg, _)| dg)
            }
        };
        let taker = if flags & libc::MSG_PEEK != 0 {
            crate::sockets::Taker::Peek
        } else {
            crate::sockets::Taker::Recv
        };
        // Linux reports a pending error before the datagrams already queued (net/ipv4/udp.c,
        // __skb_recv_udp checks sock_error before dequeuing).
        let dg = loop {
            rec.land();
            if let Some(errno) = rec.take_error_as(&shared, taker) {
                return err(errno);
            }
            if let Some(dg) = pop() {
                break dg;
            }
            if nonblocking || flags & libc::MSG_DONTWAIT != 0 {
                snare_interpose::charge_latency();
                return err(libc::EAGAIN);
            }
            if !crate::fabric::readiness().wait_until_on(
                "udp recv",
                deadline,
                &[rec.wake_key()],
                || rec.pending_time(),
                || {
                    let mut state = self.state.lock().unwrap();
                    rec.peek_error().is_some()
                        || state
                            .udp
                            .get_mut(&fd)
                            .is_some_and(|s| s.rx.has(|_| true, Some(&s.rec)))
                },
            ) {
                return err(libc::EAGAIN); // SO_RCVTIMEO, or quiescent: no peer will ever send
            }
        };
        self.clock.reach_realtime(dg.timestamp);
        let n = len.min(dg.data.len());
        crate::tstamp::note_datagram_read(
            &shared,
            &rec,
            crate::tstamp::Stamp::from_real(dg.timestamp),
            &dg.rx_fallback,
        );
        unsafe { std::ptr::copy_nonoverlapping(dg.data.as_ptr(), buf, n) };
        if !addr.is_null() && !addr_len.is_null() {
            unsafe { write_sockaddr(dg.src, addr, addr_len) };
        }
        ok(if flags & libc::MSG_TRUNC != 0 {
            dg.data.len()
        } else {
            n
        } as i64)
    }

    #[cfg(target_os = "linux")]
    fn keep_error(&self, fd: c_int, errno: c_int) {
        let rec = self.state.lock().unwrap().socket_rec(fd);
        if let Some(rec) = rec {
            rec.raise_error(errno, crate::sockets::ErrorOrigin::Raised, None);
        }
    }

    /// Scatters a netlink reply or a datagram into the iovecs and fills name, control messages
    /// and flags (man 2 recvmsg). A blocking datagram receive waits as [`recvfrom`](Self::recvfrom)
    /// does; a nonblocking one, a netlink socket and `MSG_ERRQUEUE` never wait, and are `EAGAIN`
    /// with nothing queued. `MSG_ERRQUEUE` returns the oldest arrived ICMP report or transmit
    /// stamp.
    /// Control messages: the receive timestamps the socket asked for (`tstamp::rx_cmsgs`), then
    /// the `SO_RXQ_OVFL` drop count when enabled and non-zero (man 7 socket).
    /// `MSG_TRUNC`/`MSG_CTRUNC` flag a short data or control buffer.
    ///
    /// Netlink deviates from the kernel on a short buffer: `netlink_recvmsg`
    /// (net/netlink/af_netlink.c) sets `MSG_TRUNC` and drops the rest, while the sim keeps the
    /// tail for the next receive so a dump is never lost.
    #[cfg(target_os = "linux")]
    unsafe fn recvmsg(&self, fd: c_int, msg: *mut u8, flags: c_int) -> Option<NetResult> {
        if msg.is_null() {
            return err(libc::EFAULT);
        }
        let hdr = msg as *mut libc::msghdr;
        let mut state = self.state.lock().unwrap();
        if let Some(q) = state.netlinks.get_mut(&fd).map(|n| &mut n.replies) {
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
                        std::ptr::copy_nonoverlapping(
                            remaining.as_ptr(),
                            v.iov_base as *mut u8,
                            take,
                        )
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
        let rec = sock.rec.clone();
        if errqueue {
            let v6 = sock.domain == libc::AF_INET6;
            drop(state);
            if let Some(read) =
                unsafe { read_error_report(&rec, hdr, v6, self.shared()?.tstamp_now().real) }
            {
                return Some(read);
            }
            snare_interpose::charge_latency();
            return err(libc::EAGAIN);
        }
        let wait = !sock.nonblocking && flags & libc::MSG_DONTWAIT == 0;
        let shared = self.shared()?;
        drop(state);
        let deadline = rec.opts().rcvtimeo.map(crate::readiness::Deadline::timeout);
        let (dg, drops) = loop {
            rec.land();
            if let Some(errno) = rec.take_error_as(&shared, crate::sockets::Taker::Recv) {
                return err(errno);
            }
            let got = {
                let mut state = self.state.lock().unwrap();
                let sock = state.udp.get_mut(&fd)?;
                if flags & libc::MSG_PEEK != 0 {
                    sock.rx.peek(|_| true, Some(&sock.rec))
                } else {
                    sock.rx.pop(|_| true, Some(&sock.rec))
                }
            };
            if let Some(got) = got {
                break got;
            }
            if !wait {
                // Drivers poll for datagrams in a loop: charge the miss so the poll lets a
                // discrete clock move.
                snare_interpose::charge_latency();
                return err(libc::EAGAIN);
            }
            if !crate::fabric::readiness().wait_until_on(
                "udp recvmsg",
                deadline,
                &[rec.wake_key()],
                || rec.pending_time(),
                || {
                    let mut state = self.state.lock().unwrap();
                    rec.peek_error().is_some()
                        || state
                            .udp
                            .get_mut(&fd)
                            .is_some_and(|s| s.rx.has(|_| true, Some(&s.rec)))
                },
            ) {
                return err(libc::EAGAIN);
            }
        };
        self.clock.reach_realtime(dg.timestamp);
        let rxq_ovfl = rec.state().buf.rxq_ovfl;

        let copied = unsafe { crate::fabric::scatter(hdr, &dg.data) };
        // Write the source address into the name buffer, if the caller supplied one.
        unsafe { addr_write_from_msg(hdr, dg.src) };

        let stamp = crate::tstamp::Stamp {
            hw: dg.hw,
            ..crate::tstamp::Stamp::from_real(dg.timestamp)
        };
        let mut cmsgs = crate::tstamp::rx_cmsgs(
            self.shared().as_deref(),
            &rec,
            stamp,
            crate::tstamp::Rx::Datagram,
            Some(dg.rx_fallback.as_ref()),
        );
        if rxq_ovfl && drops > 0 {
            cmsgs.push((
                libc::SOL_SOCKET,
                crate::limits::SO_RXQ_OVFL,
                drops.to_ne_bytes().to_vec(),
            ));
        }
        let mut msg_flags = 0;
        if copied < dg.data.len() {
            msg_flags |= libc::MSG_TRUNC;
        }
        if unsafe { crate::fabric::write_cmsg_list(hdr, &cmsgs) } {
            msg_flags |= libc::MSG_CTRUNC;
        }
        unsafe { (*hdr).msg_flags = msg_flags };
        ok(copied as i64)
    }

    /// Sets an option on a host datagram socket. The sim-wide handlers (`netif::sockopt` for
    /// device and routing options, `limits::sockopt` for buffer sizes and the like, `netif::frag`
    /// for the don't-fragment options, `tstamp` for the timestamp options and `SO_TXTIME`) go
    /// first and may refuse with an errno; otherwise the option is
    /// interpreted here where modelled and its raw bytes stored for `getsockopt`. An option
    /// neither modelled here (`SO_BROADCAST`, `IP_RECVERR`/`IPV6_RECVERR`, the timeouts,
    /// multicast joins) nor [`harmless`](crate::fabric::harmless) is recorded as
    /// unmodelled (`SimShared::unmodelled_option`) and stored, or refused with `ENOPROTOOPT`
    /// under `strict_sockopts`.
    #[cfg(target_os = "linux")]
    unsafe fn setsockopt(
        &self,
        fd: c_int,
        level: c_int,
        name: c_int,
        val: *const u8,
        len: u32,
    ) -> Option<NetResult> {
        let (rec, netlink) = self.sockopt_rec(fd)?;
        if netlink {
            let shared = self.shared()?;
            if let Some(result) =
                unsafe { crate::limits::sockopt::set(&shared, &rec, level, name, val, len) }
            {
                return match result {
                    Ok(()) => ok(0),
                    Err(errno) => err(errno),
                };
            }
            if shared.unmodelled_option(&rec, crate::sockets::UnmodelledOption::Set { level, name })
            {
                return err(libc::ENOPROTOOPT);
            }
            let bytes = if val.is_null() {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(val, len as usize) }.to_vec()
            };
            let mut state = self.state.lock().unwrap();
            state
                .netlinks
                .get_mut(&fd)?
                .sockopts
                .insert((level, name), bytes);
            return ok(0);
        }
        if let Some(shared) = self.shared()
            && let Some(result) = unsafe {
                crate::netif::sockopt::set(&shared, &rec, level, name, val, len)
                    .or_else(|| crate::limits::sockopt::set(&shared, &rec, level, name, val, len))
            }
        {
            return match result {
                Ok(()) => ok(0),
                Err(errno) => err(errno),
            };
        }
        let v6 = self.state.lock().unwrap().udp.get(&fd)?.domain == libc::AF_INET6;
        if let Some(result) = unsafe { crate::netif::frag::set(&rec, v6, level, name, val, len) } {
            return match result {
                Ok(()) => ok(0),
                Err(errno) => err(errno),
            };
        }
        if let Some(result) = unsafe {
            crate::tstamp::set(
                self.shared().as_deref(),
                &rec,
                crate::tstamp::Kind::Datagram,
                level,
                name,
                val,
                len,
            )
        } {
            return match result {
                Ok(()) => ok(0),
                Err(errno) => err(errno),
            };
        }
        let net_admin = self
            .shared()
            .is_some_and(|shared| shared.sys.has_cap(crate::limits::CAP_NET_ADMIN));
        if let Some(result) =
            unsafe { crate::tstamp::set_txtime(&rec, net_admin, level, name, val, len) }
        {
            return match result {
                Ok(()) => ok(0),
                Err(errno) => err(errno),
            };
        }
        if !host_modelled(level, name)
            && !crate::fabric::harmless(level, name)
            && udp_parse_group(level, name, &[0; 16]).is_none()
            && let Some(shared) = self.shared()
            && shared.unmodelled_option(&rec, crate::sockets::UnmodelledOption::Set { level, name })
        {
            return err(libc::ENOPROTOOPT);
        }
        let mut state = self.state.lock().unwrap();
        let sock = state.udp.get_mut(&fd)?;
        let bytes = if val.is_null() {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(val, len as usize) }.to_vec()
        };
        // man 7 socket: SO_BROADCAST permits sending to a broadcast address.
        if level == libc::SOL_SOCKET && name == libc::SO_BROADCAST {
            sock.broadcast = bytes.first().is_some_and(|&b| b != 0);
        }
        // IP_RECVERR(2const): queue ICMP errors for MSG_ERRQUEUE, which also reports them on an
        // unconnected socket.
        if (level, name) == (libc::IPPROTO_IP, libc::IP_RECVERR)
            || (level, name) == (libc::IPPROTO_IPV6, libc::IPV6_RECVERR)
        {
            sock.rec.state().dgram.recverr = bytes.iter().any(|&b| b != 0);
        }
        // man 7 socket: SO_RCVTIMEO/SO_SNDTIMEO bound blocking receives/sends; zero means none.
        if level == libc::SOL_SOCKET && (name == libc::SO_RCVTIMEO || name == libc::SO_SNDTIMEO) {
            let timeout =
                unsafe { crate::fabric::parse_timeval(val, len) }.filter(|d| !d.is_zero());
            let mut rec = sock.rec.state();
            if name == libc::SO_RCVTIMEO {
                rec.opts.rcvtimeo = timeout;
            } else {
                rec.opts.sndtimeo = timeout;
            }
            return ok(0);
        }
        // IP_ADD_MEMBERSHIP(2const), IPV6_ADD_MEMBERSHIP(2const): join a multicast group so
        // datagrams to it are delivered here.
        let drop_group = (level == libc::IPPROTO_IP && name == libc::IP_DROP_MEMBERSHIP)
            || (level == libc::IPPROTO_IPV6 && name == libc::IPV6_DROP_MEMBERSHIP);
        let membership_name = if drop_group {
            if level == libc::IPPROTO_IP {
                libc::IP_ADD_MEMBERSHIP
            } else {
                libc::IPV6_ADD_MEMBERSHIP
            }
        } else {
            name
        };
        if let Some(group) = udp_parse_group(level, membership_name, &bytes)
            && let Err(errno) = sock
                .rec
                .change_membership(udp_membership(group, &bytes), !drop_group)
        {
            return err(errno);
        }
        sock.sockopts.insert((level, name), bytes);
        ok(0)
    }

    /// Reads an option: the sim-wide handlers first, then the timestamp options, the timeouts,
    /// `SO_ERROR`, and finally the stored bytes of whatever was set. An option never set reads as
    /// zeros; one neither modelled nor [`harmless`](crate::fabric::harmless) is then recorded as
    /// unmodelled, or refused with `ENOPROTOOPT` under `strict_sockopts`. `*len` is updated to
    /// the bytes written.
    #[cfg(target_os = "linux")]
    unsafe fn getsockopt(
        &self,
        fd: c_int,
        level: c_int,
        name: c_int,
        val: *mut u8,
        len: *mut u32,
    ) -> Option<NetResult> {
        let (rec, netlink) = self.sockopt_rec(fd)?;
        if netlink {
            if let Some(result) =
                unsafe { crate::limits::sockopt::get(&rec, level, name, val, len) }
            {
                return match result {
                    Ok(()) => ok(0),
                    Err(errno) => err(errno),
                };
            }
            if val.is_null() || len.is_null() {
                return err(libc::EFAULT);
            }
            if level == libc::SOL_SOCKET && name == libc::SO_ERROR {
                let errno = self
                    .shared()
                    .and_then(|shared| rec.take_error_as(&shared, crate::sockets::Taker::SoError))
                    .unwrap_or(0);
                unsafe { crate::fabric::write_opt(errno, val, len) };
                return ok(0);
            }
            let stored = self
                .state
                .lock()
                .unwrap()
                .netlinks
                .get(&fd)?
                .sockopts
                .get(&(level, name))
                .cloned()
                .unwrap_or_default();
            if stored.is_empty()
                && let Some(shared) = self.shared()
                && shared
                    .unmodelled_option(&rec, crate::sockets::UnmodelledOption::Get { level, name })
            {
                return err(libc::ENOPROTOOPT);
            }
            let cap = unsafe { *len } as usize;
            let n = if stored.is_empty() {
                cap.min(4)
            } else {
                stored.len().min(cap)
            };
            unsafe {
                std::ptr::write_bytes(val, 0, n);
                std::ptr::copy_nonoverlapping(stored.as_ptr(), val, n.min(stored.len()));
                *len = n as u32;
            }
            return ok(0);
        }
        rec.land();
        if val.is_null() || len.is_null() {
            return err(libc::EFAULT);
        }
        if unsafe { crate::netif::sockopt::get(&rec, level, name, val, len) }.is_some() {
            return ok(0);
        }
        let v6 = self.state.lock().unwrap().udp.get(&fd)?.domain == libc::AF_INET6;
        if let Some(result) = unsafe { crate::netif::frag::get(&rec, v6, level, name, val, len) } {
            return match result {
                Ok(()) => ok(0),
                Err(errno) => err(errno),
            };
        }
        if let Some(result) = unsafe { crate::limits::sockopt::get(&rec, level, name, val, len) } {
            return match result {
                Ok(()) => ok(0),
                Err(errno) => err(errno),
            };
        }
        if unsafe { crate::tstamp::get(&rec, level, name, val, len) }.is_some() {
            return ok(0);
        }
        let state = self.state.lock().unwrap();
        let sock = state.udp.get(&fd)?;
        if level == libc::SOL_SOCKET && (name == libc::SO_RCVTIMEO || name == libc::SO_SNDTIMEO) {
            let opts = sock.rec.opts();
            let d = if name == libc::SO_RCVTIMEO {
                opts.rcvtimeo
            } else {
                opts.sndtimeo
            };
            unsafe { crate::fabric::write_timeval(d.unwrap_or_default(), val, len) };
            return ok(0);
        }
        // man 7 socket: SO_ERROR reads and clears the pending error.
        if level == libc::SOL_SOCKET && name == libc::SO_ERROR {
            let rec = sock.rec.clone();
            drop(state);
            let errno = self
                .shared()
                .and_then(|shared| rec.take_error_as(&shared, crate::sockets::Taker::SoError))
                .unwrap_or(0);
            unsafe { crate::fabric::write_opt(errno, val, len) };
            return ok(0);
        }
        let cap = unsafe { *len } as usize;
        // For an owned socket, an option never set reads back as zero (a modelled default) rather
        // than declining — declining would forward to the dup'd /dev/null fd and return ENOTSOCK.
        let empty = Vec::new();
        let stored = sock.sockopts.get(&(level, name)).unwrap_or(&empty);
        if stored.is_empty()
            && !host_modelled(level, name)
            && !crate::fabric::harmless(level, name)
            && let Some(shared) = self.shared()
            && shared.unmodelled_option(&rec, crate::sockets::UnmodelledOption::Get { level, name })
        {
            return err(libc::ENOPROTOOPT);
        }
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

    /// `recvfrom` without a source address.
    #[cfg(target_os = "linux")]
    unsafe fn recv(&self, fd: c_int, buf: *mut u8, len: usize, flags: c_int) -> Option<NetResult> {
        unsafe {
            self.recvfrom(
                fd,
                buf,
                len,
                flags,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }
    }

    /// The bound address, or the family's wildcard with port 0 while unbound.
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
        let unhashed = sock.requested.map(|r| std::net::SocketAddr::new(r.ip(), 0));
        let local = sock.local.or(unhashed).unwrap_or_else(|| {
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

    /// The connected peer, or `ENOTCONN`.
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

    /// Closes a host socket: releases its bound address, drops its sim record (with `state`
    /// released, since that can reach the probe) and closes the reserved fd. Queued datagrams are
    /// discarded.
    #[cfg(target_os = "linux")]
    unsafe fn close(&self, fd: c_int) -> Option<NetResult> {
        self.detach_socket(fd, false)?;
        unsafe { libc::close(fd) };
        ok(0)
    }

    #[cfg(target_os = "linux")]
    unsafe fn fd_replaced(&self, fd: c_int) -> Option<NetResult> {
        self.detach_socket(fd, true)?;
        ok(0)
    }

    #[cfg(target_os = "linux")]
    unsafe fn dup_to(&self, fd: c_int, newfd: c_int, flags: Option<c_int>) -> Option<NetResult> {
        let shared = self.shared()?;
        let mut state = self.state.lock().unwrap();
        let rec = state.socket_rec(fd)?;
        let result = crate::fabric::duplicate_to(fd, newfd, flags);
        if result < 0 {
            return err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EBADF));
        }
        if fd == newfd
            || state
                .socket_rec(newfd)
                .is_some_and(|previous| Arc::ptr_eq(&previous, &rec))
        {
            return ok(result as i64);
        }
        let previous = state.socket_rec(newfd);
        state.remove_socket(newfd);
        state.alias_socket(fd, newfd);
        shared.sockets.alias(newfd, &rec);
        drop(state);
        if let Some(previous) = previous {
            shared.sockets.fd_replaced(newfd, &previous, shared.stamp());
            shared.bump_keys(&[previous.wake_key()]);
        }
        ok(result as i64)
    }

    /// `F_SETFL`/`F_GETFL` share `O_NONBLOCK` across descriptors. Descriptor flags and duplicate
    /// allocation use the reserved kernel fd.
    /// Netlink descriptors share their reply queue and status flags.
    #[cfg(target_os = "linux")]
    unsafe fn fcntl(&self, fd: c_int, cmd: c_int, arg: i64) -> Option<NetResult> {
        let shared = self.shared();
        let mut state = self.state.lock().unwrap();
        let rec = state.socket_rec(fd)?;
        if matches!(cmd, libc::F_DUPFD | libc::F_DUPFD_CLOEXEC) {
            let newfd = snare_interpose::real(|| unsafe { libc::fcntl(fd, cmd, arg as c_int) });
            if newfd < 0 {
                return err(std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EMFILE));
            }
            state.alias_socket(fd, newfd);
            shared?.sockets.alias(newfd, &rec);
            return ok(newfd as i64);
        }
        if matches!(cmd, libc::F_GETFD | libc::F_SETFD) {
            let result = snare_interpose::real(|| unsafe { libc::fcntl(fd, cmd, arg as c_int) });
            return if result < 0 {
                err(std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EINVAL))
            } else {
                ok(result as i64)
            };
        }
        let nonblocking = if let Some(socket) = state.udp.get_mut(&fd) {
            &mut socket.nonblocking
        } else {
            &mut state.netlinks.get_mut(&fd)?.nonblocking
        };
        match cmd {
            libc::F_SETFL => {
                *nonblocking = arg as c_int & libc::O_NONBLOCK != 0;
                ok(0)
            }
            libc::F_GETFL => {
                ok((libc::O_RDWR | if *nonblocking { libc::O_NONBLOCK } else { 0 }) as i64)
            }
            _ => err(libc::EINVAL),
        }
    }

    #[cfg(target_os = "linux")]
    unsafe fn dup(&self, fd: c_int) -> Option<NetResult> {
        unsafe { Net::fcntl(self, fd, libc::F_DUPFD, 0) }
    }
}

/// `CTL_NET` (4, `<sys/sysctl.h>`): the network top-level MIB (man 3 sysctl).
#[cfg(target_os = "macos")]
const CTL_NET: c_int = 4;
/// `PF_ROUTE` (= `AF_ROUTE` = 17, `<sys/socket.h>`): the routing-socket subtree under `CTL_NET`.
#[cfg(target_os = "macos")]
const PF_ROUTE: c_int = 17;
/// `NET_RT_IFLIST2` (6, `<sys/socket.h>`): the interface list as `RTM_IFINFO2` messages with
/// 64-bit counters.
#[cfg(target_os = "macos")]
const NET_RT_IFLIST2: c_int = 6;

/// The record length the sim emits per interface: a 32-byte `if_msghdr2` header plus a 136-byte
/// `if_data64` area. The SDK's `sizeof(struct if_msghdr2)` is 160 (`if_data64` is 128 bytes under
/// `#pragma pack(4)` in `<net/if_var.h>`, checked against the macOS SDK on arm64 and x86_64), so
/// each record carries 8 trailing zero bytes. Consumers step by `ifm_msglen`, as the routing
/// message format requires (man 4 route), so the padding is harmless; the
/// `simhost_macos_sysctl` and `simhost_nic_topology` tests pin 168.
#[cfg(target_os = "macos")]
const IF_MSGHDR2_LEN: usize = 168;

/// Build a `NET_RT_IFLIST2` routing blob: one header-only `struct if_msghdr2` (`ifm_addrs = 0`)
/// per interface, in the given order, carrying the link index, flags and `if_data64` counters.
/// Fixed ABI offsets are written directly, so a libc struct-layout skew cannot shift them.
/// Layouts: XNU `struct if_msghdr2` (`<net/if.h>`) and `struct if_data64` (`<net/if_var.h>`).
/// A real kernel record also carries the interface's link-layer `sockaddr_dl` (`RTA_IFP`); the
/// sim's carries none.
#[cfg(target_os = "macos")]
fn build_iflist2(nics: &[NicSnapshot]) -> Vec<u8> {
    // RTM_VERSION and RTM_IFINFO2 from <net/route.h>; IFT_ETHER (0x6) and IFT_LOOP (0x18) from
    // <net/if_types.h>.
    const RTM_VERSION: u8 = 5;
    const RTM_IFINFO2: u8 = 0x12;
    const IFT_ETHER: u8 = 6;
    const IFT_LOOP: u8 = 24;

    let mut out = vec![0u8; nics.len() * IF_MSGHDR2_LEN];
    for (i, nic) in nics.iter().enumerate() {
        let msg = &mut out[i * IF_MSGHDR2_LEN..(i + 1) * IF_MSGHDR2_LEN];
        msg[0..2].copy_from_slice(&(IF_MSGHDR2_LEN as u16).to_ne_bytes()); // ifm_msglen
        msg[2] = RTM_VERSION; // ifm_version
        msg[3] = RTM_IFINFO2; // ifm_type
        // ifm_addrs @4 = 0 (no trailing sockaddrs)
        let flags = crate::ifaddrs::flags(nic);
        msg[8..12].copy_from_slice(&flags.to_ne_bytes()); // ifm_flags
        msg[12..14].copy_from_slice(&(nic.index as u16).to_ne_bytes()); // ifm_index
        // ifm_snd_* / ifm_timer @16..32 = 0

        let d = 32; // struct if_data64
        msg[d] = if nic.loopback { IFT_LOOP } else { IFT_ETHER }; // ifi_type
        msg[d + 8..d + 12].copy_from_slice(&nic.spec.mtu.to_ne_bytes()); // ifi_mtu
        let c = &nic.counters;
        let put = |msg: &mut [u8], off: usize, v: u64| {
            msg[d + off..d + off + 8].copy_from_slice(&v.to_ne_bytes());
        };
        put(msg, 24, c.rx_packets); // ifi_ipackets
        put(msg, 32, c.rx_errors); // ifi_ierrors
        put(msg, 40, c.tx_packets); // ifi_opackets
        put(msg, 48, c.tx_errors); // ifi_oerrors
        put(msg, 64, c.rx_bytes); // ifi_ibytes
        put(msg, 72, c.tx_bytes); // ifi_obytes
        put(msg, 80, c.multicast); // ifi_imcasts
        put(msg, 96, c.rx_dropped); // ifi_iqdrops
    }
    out
}

/// Render a CPU set in the kernel's cpulist format: sorted, deduplicated, consecutive runs
/// collapsed to `a-b`, comma-separated (e.g. `0,2-5`; Documentation/admin-guide/cputopology.rst).
/// An empty set renders as the empty string.
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

/// One cpulist run: `n` for a single CPU, `a-b` otherwise.
fn range(start: usize, end: usize) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

/// Fills `hdr` with an ICMP error from the error queue, as Linux's `ip_recv_error`
/// (net/ipv4/ip_sockglue.c) does: the original destination as the name, and an
/// `IP_RECVERR`/`IPV6_RECVERR` control message holding a `struct sock_extended_err`
/// (`<linux/errqueue.h>`) followed by the offender's address, and the original datagram payload.
///
/// `sock_extended_err` is `ee_errno` (u32), `ee_origin`, `ee_type`, `ee_code`, `ee_pad`, then
/// `ee_info` and `ee_data` (u32 each), 16 bytes; `SO_EE_ORIGIN_ICMP`/`ICMP6` are 2 and 3
/// (include/uapi/linux/errqueue.h; IP_RECVERR(2const)). The ICMP type/code pairs are
/// destination/port unreachable: 3/3 for ICMPv4 (RFC 792) and 1/4 for ICMPv6 (RFC 4443 §3.1).
/// The offender is reported with port 0.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn write_icmp_report(
    hdr: *mut libc::msghdr,
    report: &crate::sockets::IcmpReport,
) -> Option<NetResult> {
    const SO_EE_ORIGIN_ICMP: u8 = 2;
    const SO_EE_ORIGIN_ICMP6: u8 = 3;
    let copied = unsafe { crate::fabric::scatter(hdr, &report.payload) };
    let offender = report.offender;
    let (level, ty, origin, icmp_type, icmp_code) = if offender.is_ipv4() {
        // ICMP_DEST_UNREACH / ICMP_PORT_UNREACH.
        (libc::SOL_IP, libc::IP_RECVERR, SO_EE_ORIGIN_ICMP, 3u8, 3u8)
    } else {
        // ICMPV6_DEST_UNREACH / ICMPV6_PORT_UNREACH.
        (libc::SOL_IPV6, libc::IPV6_RECVERR, SO_EE_ORIGIN_ICMP6, 1, 4)
    };
    let mut data = Vec::with_capacity(16 + 28);
    data.extend_from_slice(&(report.errno as u32).to_ne_bytes());
    data.extend_from_slice(&[origin, icmp_type, icmp_code, 0]);
    data.extend_from_slice(&0u32.to_ne_bytes());
    data.extend_from_slice(&0u32.to_ne_bytes());
    data.extend_from_slice(&sockaddr_bytes(std::net::SocketAddr::new(offender.ip(), 0)));
    unsafe {
        addr_write_from_msg(hdr, offender);
        let mut msg_flags = libc::MSG_ERRQUEUE;
        if copied < report.payload.len() {
            msg_flags |= libc::MSG_TRUNC;
        }
        if !crate::fabric::write_cmsgs_at(hdr, &[(level, ty, &data)]) {
            msg_flags |= libc::MSG_CTRUNC;
        }
        (*hdr).msg_flags = msg_flags;
    }
    ok(copied as i64)
}

#[cfg(target_os = "linux")]
pub(crate) unsafe fn read_error_report(
    rec: &SockRec,
    hdr: *mut libc::msghdr,
    v6: bool,
    now: std::time::Duration,
) -> Option<NetResult> {
    rec.land();
    match rec.pop_error_report()? {
        crate::sockets::ErrorReport::Icmp(report) => unsafe { write_icmp_report(hdr, &report) },
        crate::sockets::ErrorReport::Tx(report) => unsafe {
            crate::tstamp::write_tx_report(rec, report, hdr, v6, now)
        },
    }
}

/// A sysfs/procfs value as read: the text plus the trailing newline the kernel's `show`
/// functions emit.
fn with_newline(mut s: String) -> Vec<u8> {
    s.push('\n');
    s.into_bytes()
}

/// The fabric's way into the host's datagram sockets: what a tester endpoint sends lands here.
#[cfg(target_os = "linux")]
impl crate::fabric::ForeignUdp for SimHost {
    /// Delivers a datagram a tester sent from `src` to `dest`, fanned out over the host's sockets
    /// by the topology as if it came from a station at `src`, then wakes waiting receivers.
    /// Ticks the virtual realtime clock to stamp the arrival. Takes `registries` and then `state`,
    /// never both at once.
    fn deliver_from_peer(
        &self,
        src: std::net::SocketAddr,
        dest: std::net::SocketAddr,
        data: &[u8],
    ) -> usize {
        let now = self.clock.tick_realtime();
        let Some(regs) = self.registries.lock().unwrap().clone() else {
            return 0;
        };
        let station = regs.station_at(dest.ip());
        let sender = crate::netif::Sender::Station(src.ip());
        let joined = dest.ip().is_multicast() && regs.shared.host_joined(dest.ip());
        let mut state = self.state.lock().unwrap();
        let cands = state.udp_cands(dest, joined);
        let copies = regs.shared.fan_out(
            &sender,
            crate::netif::Wire {
                src,
                dest,
                len: data.len(),
            },
            station,
            cands,
            true,
        );
        let mut keys = crate::readiness::WakeKeys::default();
        for copy in &copies {
            if let Some(socket) = state.udp.get(&copy.q) {
                keys.push(socket.rec.wake_key());
            }
        }
        let reached = copies.len();
        state.udp_land(copies, data, src, now);
        drop(state);
        regs.shared.bump_keys(keys.as_slice());
        reached
    }
}

/// Off Linux the host models no datagram sockets, so a tester's datagram has nowhere to land
/// here and is dropped; the fabric serves those platforms' sockets itself.
#[cfg(not(target_os = "linux"))]
impl crate::fabric::ForeignUdp for SimHost {
    fn deliver_from_peer(
        &self,
        _: std::net::SocketAddr,
        _: std::net::SocketAddr,
        _: &[u8],
    ) -> usize {
        0
    }
}
