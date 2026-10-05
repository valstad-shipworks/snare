//! First-class network interfaces, routing and the socket table of snare's
//! in-process network.
//!
//! Every state slot starts with two interfaces: the loopback (named after the
//! selected [`OsSemantics`], index 1, `127.0.0.1/8` and `::1/128`) and
//! `snare0` (index 2), the default interface that carries the default routes
//! and every address added with [`add_ip_addr`](crate::add_ip_addr).
//! Tests add more with [`add_nic`], route between them with [`add_route`] and
//! [`set_default_route`], take links down with [`set_link`], and give each
//! interface its own latency, jitter and loss with [`set_nic_policy`].
//!
//! Interfaces are shared L2 segments: two sockets whose addresses sit on the
//! same interface talk through it, not through the loopback, so its policy
//! applies to driver↔device traffic.
//!
//! Sockets have identity: every UDP socket, TCP stream and TCP listener gets
//! a [`SocketId`] when it is created, readable with [`socket_id`]. Use it with
//! [`socket_entry`], [`set_socket_device`] and [`inject_socket_drops`];
//! [`socket_table`] lists the live sockets and [`closed_sockets`] the closed
//! ones.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::os::{Errno, OsSemantics, os_err_for, sys_err_for};
use crate::state::{NetCtx, TcpConnection, UdpConnection, with_net};
use crate::time::Instant;

/// An interface address with its prefix length, e.g. `10.0.0.2/24`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl IpNet {
    /// `addr/prefix`. Panics if `prefix` is longer than the address.
    pub fn new(addr: IpAddr, prefix: u8) -> Self {
        assert!(
            prefix <= max_prefix(addr),
            "prefix /{prefix} is too long for {addr}"
        );
        Self { addr, prefix }
    }

    /// `addr/32` or `addr/128`.
    pub fn host(addr: IpAddr) -> Self {
        Self {
            addr,
            prefix: max_prefix(addr),
        }
    }

    /// The network address: `addr` with its host bits cleared.
    pub fn network(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) & v4_mask(self.prefix))),
            IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) & v6_mask(self.prefix))),
        }
    }

    /// Whether `ip` lies in this network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let m = v4_mask(self.prefix);
                u32::from(a) & m == u32::from(b) & m
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let m = v6_mask(self.prefix);
                u128::from(a) & m == u128::from(b) & m
            }
            _ => false,
        }
    }

    /// The directed broadcast address of an IPv4 network of `/30` or wider.
    pub fn broadcast(&self) -> Option<Ipv4Addr> {
        match self.addr {
            IpAddr::V4(a) if self.prefix <= 30 => {
                Some(Ipv4Addr::from(u32::from(a) | !v4_mask(self.prefix)))
            }
            _ => None,
        }
    }
}

fn max_prefix(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

impl From<IpAddr> for IpNet {
    fn from(addr: IpAddr) -> Self {
        Self::host(addr)
    }
}

impl FromStr for IpNet {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr.parse().map_err(|e| format!("{s:?}: {e}"))?;
        let prefix = match prefix {
            Some(p) => p.parse::<u8>().map_err(|e| format!("{s:?}: {e}"))?,
            None => max_prefix(addr),
        };
        if prefix > max_prefix(addr) {
            return Err(format!("{s:?}: prefix too long"));
        }
        Ok(Self { addr, prefix })
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// An interface's index (the OS `ifindex`). The loopback is 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NicId(pub(crate) u32);

impl NicId {
    pub fn index(self) -> u32 {
        self.0
    }
}

/// The kind of an interface.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NicKind {
    Loopback,
    Ethernet,
}

/// Everything a test says about an interface. Build with [`NicSpec::new`].
#[derive(Debug, Clone, PartialEq)]
pub struct NicSpec {
    pub name: String,
    pub kind: NicKind,
    /// The interface index; `None` picks the next free one.
    pub index: Option<u32>,
    pub addresses: Vec<IpNet>,
    /// `None` derives a locally administered address from the index.
    pub mac: Option<[u8; 6]>,
    pub mtu: u32,
    pub link_up: bool,
    pub speed_mbps: Option<u32>,
    pub driver: DriverSeed,
    pub caps: NicCaps,
    pub policy: NicPolicy,
}

impl NicSpec {
    /// An Ethernet interface named `name`: link up, MTU 1500, 1 Gb/s, no
    /// addresses, default capabilities and a perfect link.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: NicKind::Ethernet,
            index: None,
            addresses: Vec::new(),
            mac: None,
            mtu: 1500,
            link_up: true,
            speed_mbps: Some(1000),
            driver: DriverSeed::default(),
            caps: NicCaps::default(),
            policy: NicPolicy::default(),
        }
    }

    /// Add an address.
    pub fn address(mut self, net: impl Into<IpNet>) -> Self {
        self.addresses.push(net.into());
        self
    }

    pub fn caps(mut self, caps: NicCaps) -> Self {
        self.caps = caps;
        self
    }

    pub fn policy(mut self, policy: NicPolicy) -> Self {
        self.policy = policy;
        self
    }

    fn loopback(name: &str) -> Self {
        Self {
            name: name.to_string(),
            kind: NicKind::Loopback,
            index: Some(LOOPBACK_INDEX),
            addresses: vec![
                IpNet::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8),
                IpNet::host(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ],
            mac: Some([0; 6]),
            mtu: 65536,
            link_up: true,
            speed_mbps: None,
            driver: DriverSeed {
                driver: String::new(),
                ..DriverSeed::default()
            },
            caps: NicCaps {
                rx_ring_max: 0,
                tx_ring_max: 0,
                rx_ring: 0,
                tx_ring: 0,
                combined_channels_max: 1,
                combined_channels: 1,
                coalesce_supported: CoalesceSupport::NONE,
                pause: false,
                threaded_napi: false,
                ..NicCaps::default()
            },
            policy: NicPolicy::default(),
        }
    }
}

/// What the driver reports about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverSeed {
    pub driver: String,
    pub version: String,
    pub firmware: String,
    pub bus: String,
    pub expansion_rom: String,
}

impl Default for DriverSeed {
    fn default() -> Self {
        Self {
            driver: "snare".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            firmware: String::new(),
            bus: String::new(),
            expansion_rom: String::new(),
        }
    }
}

/// What an interface can do, and its current ring and channel sizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicCaps {
    pub hw_rx_timestamp: bool,
    pub hw_tx_timestamp: bool,
    pub sw_timestamp: bool,
    /// The PTP hardware clock index (`/dev/ptpN`).
    pub phc_index: Option<u32>,
    pub rx_ring_max: u32,
    pub tx_ring_max: u32,
    pub rx_ring: u32,
    pub tx_ring: u32,
    pub combined_channels_max: u32,
    pub combined_channels: u32,
    pub coalesce_supported: CoalesceSupport,
    pub coalesce_usecs_max: u32,
    pub coalesce_frames_max: u32,
    pub pause: bool,
    pub eee: bool,
    pub ntuple: bool,
    pub flow_rule_slots: u32,
    pub etf_offload: bool,
    pub threaded_napi: bool,
    pub queue_stats: bool,
    /// Names of the driver-specific statistics the interface reports.
    pub driver_stats: Vec<String>,
    /// How long the link drops when a Windows adapter restarts to apply a
    /// ring, coalescing, pause or channel change.
    pub win_restart_flap: Duration,
}

impl Default for NicCaps {
    fn default() -> Self {
        Self {
            hw_rx_timestamp: false,
            hw_tx_timestamp: false,
            sw_timestamp: true,
            phc_index: None,
            rx_ring_max: 4096,
            tx_ring_max: 4096,
            rx_ring: 256,
            tx_ring: 256,
            combined_channels_max: 8,
            combined_channels: 4,
            coalesce_supported: CoalesceSupport::ALL,
            coalesce_usecs_max: 8191,
            coalesce_frames_max: 1024,
            pause: true,
            eee: false,
            ntuple: false,
            flow_rule_slots: 0,
            etf_offload: false,
            threaded_napi: true,
            queue_stats: false,
            driver_stats: Vec::new(),
            win_restart_flap: Duration::from_secs(2),
        }
    }
}

/// The coalescing parameters a driver accepts, as Linux's
/// `ETHTOOL_COALESCE_*` bit set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoalesceSupport(pub u32);

impl CoalesceSupport {
    pub const NONE: Self = Self(0);
    pub const ALL: Self = Self((1 << 27) - 1);
    pub const RX_USECS: Self = Self(1 << 0);
    pub const RX_MAX_FRAMES: Self = Self(1 << 1);
    pub const RX_USECS_IRQ: Self = Self(1 << 2);
    pub const RX_MAX_FRAMES_IRQ: Self = Self(1 << 3);
    pub const TX_USECS: Self = Self(1 << 4);
    pub const TX_MAX_FRAMES: Self = Self(1 << 5);
    pub const TX_USECS_IRQ: Self = Self(1 << 6);
    pub const TX_MAX_FRAMES_IRQ: Self = Self(1 << 7);
    pub const STATS_BLOCK_USECS: Self = Self(1 << 8);
    pub const USE_ADAPTIVE_RX: Self = Self(1 << 9);
    pub const USE_ADAPTIVE_TX: Self = Self(1 << 10);
    pub const PKT_RATE_LOW: Self = Self(1 << 11);
    pub const RX_USECS_LOW: Self = Self(1 << 12);
    pub const RX_MAX_FRAMES_LOW: Self = Self(1 << 13);
    pub const TX_USECS_LOW: Self = Self(1 << 14);
    pub const TX_MAX_FRAMES_LOW: Self = Self(1 << 15);
    pub const PKT_RATE_HIGH: Self = Self(1 << 16);
    pub const RX_USECS_HIGH: Self = Self(1 << 17);
    pub const RX_MAX_FRAMES_HIGH: Self = Self(1 << 18);
    pub const TX_USECS_HIGH: Self = Self(1 << 19);
    pub const TX_MAX_FRAMES_HIGH: Self = Self(1 << 20);
    pub const RATE_SAMPLE_INTERVAL: Self = Self(1 << 21);
    pub const USE_CQE_RX: Self = Self(1 << 22);
    pub const USE_CQE_TX: Self = Self(1 << 23);
    pub const TX_AGGR_MAX_BYTES: Self = Self(1 << 24);
    pub const TX_AGGR_MAX_FRAMES: Self = Self(1 << 25);
    pub const TX_AGGR_TIME_USECS: Self = Self(1 << 26);

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for CoalesceSupport {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Link effects for traffic arriving on an interface.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct NicPolicy {
    /// Added to every datagram and TCP chunk.
    pub latency: Duration,
    /// Extra per-packet delay, uniform in `[0, jitter]`. Datagrams can
    /// overtake each other; TCP bytes never do.
    pub jitter: Duration,
    /// Per-datagram loss probability in `[0, 1]`. Not applied to TCP.
    pub loss_rate: f32,
    /// Per-datagram duplication probability in `[0, 1]`.
    pub duplicate_rate: f32,
    /// Answer datagrams to closed ports on this interface's addresses with
    /// ICMP port unreachable (see
    /// [`inject_icmp_port_unreachable`](crate::inject_icmp_port_unreachable)
    /// for what the sender sees). Addresses assigned through
    /// [`add_ip_addr`](crate::add_ip_addr) never answer, so virtual testers
    /// behind them keep receiving.
    pub icmp_port_unreachable: bool,
}

/// A configured route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub dest: IpNet,
    /// The interface the route sends through.
    pub nic: String,
    pub gateway: Option<IpAddr>,
    /// The preferred source address for traffic on this route.
    pub src: Option<IpAddr>,
    /// Lower wins between routes of the same prefix length.
    pub metric: u32,
}

impl Route {
    /// A route to `dest` through `nic` with metric 0.
    pub fn new(dest: IpNet, nic: impl Into<String>) -> Self {
        Self {
            dest,
            nic: nic.into(),
            gateway: None,
            src: None,
            metric: 0,
        }
    }
}

/// Per-interface counters, named after Linux's `rtnl_link_stats64`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NicCounters {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub multicast: u64,
    pub collisions: u64,
    pub rx_length_errors: u64,
    pub rx_over_errors: u64,
    pub rx_crc_errors: u64,
    pub rx_frame_errors: u64,
    pub rx_fifo_errors: u64,
    pub rx_missed_errors: u64,
    pub tx_aborted_errors: u64,
    pub tx_carrier_errors: u64,
    pub tx_fifo_errors: u64,
    pub tx_heartbeat_errors: u64,
    pub tx_window_errors: u64,
    pub rx_compressed: u64,
    pub tx_compressed: u64,
    pub rx_nohandler: u64,
    pub rx_otherhost_dropped: u64,
}

/// A copy of one interface's state, from [`nic`] or [`nics`].
#[derive(Debug, Clone)]
pub struct NicSnapshot {
    pub id: NicId,
    pub spec: NicSpec,
    pub counters: NicCounters,
    /// Live sockets bound to one of its addresses or to the device.
    pub sockets: Vec<SocketId>,
    /// This is the interface [`add_ip_addr`](crate::add_ip_addr) assigns to.
    pub default_nic: bool,
    /// Created with [`add_nic`].
    pub explicit: bool,
}

/// A socket's identity. Ids are never reused, not even across state slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketId(pub(crate) u64);

impl SocketId {
    pub fn get(self) -> u64 {
        self.0
    }
}

mod sealed {
    pub trait Sealed {}
}

/// A snare socket: [`crate::net::UdpSocket`], [`crate::net::TcpStream`] or
/// [`crate::net::TcpListener`]. Sealed.
///
/// None of them has an OS handle: they implement neither `AsFd` nor
/// fast-talker's own `Socket` and `tcp::Stream`, so no real syscall can be
/// made on them. fast-talker's shim takes them through this trait instead.
#[cfg_attr(
    all(feature = "shim", feature = "fast-talker-core", unix),
    doc = "```compile_fail\nfn needs<T: std::os::fd::AsFd>() {}\nneeds::<snare::net::UdpSocket>();\n```"
)]
#[cfg_attr(
    all(feature = "shim", feature = "fast-talker-core", unix),
    doc = "```compile_fail\nfn needs<T: std::os::fd::AsFd>() {}\nneeds::<snare::net::TcpStream>();\n```"
)]
#[cfg_attr(
    all(feature = "shim", feature = "fast-talker-core", unix),
    doc = "```compile_fail\nfn needs<T: std::os::fd::AsFd>() {}\nneeds::<snare::net::TcpListener>();\n```"
)]
#[cfg_attr(
    all(feature = "shim", feature = "fast-talker-core", unix),
    doc = "```compile_fail\nfn needs<T: fast_talker::Socket>() {}\nneeds::<snare::net::UdpSocket>();\n```"
)]
#[cfg_attr(
    all(feature = "shim", feature = "fast-talker-core", unix),
    doc = "```compile_fail\nfn needs<T: fast_talker::tcp::Stream>() {}\nneeds::<snare::net::TcpStream>();\n```"
)]
pub trait SimSocket: sealed::Sealed {
    fn socket_id(&self) -> SocketId;
}

impl sealed::Sealed for crate::net::UdpSocket {}
impl sealed::Sealed for crate::net::TcpStream {}
impl sealed::Sealed for crate::net::TcpListener {}

impl SimSocket for crate::net::UdpSocket {
    fn socket_id(&self) -> SocketId {
        self.id()
    }
}

impl SimSocket for crate::net::TcpStream {
    fn socket_id(&self) -> SocketId {
        self.id()
    }
}

impl SimSocket for crate::net::TcpListener {
    fn socket_id(&self) -> SocketId {
        self.id()
    }
}

#[cfg(feature = "mio-compat")]
macro_rules! mio_sim_socket {
    ($($ty:ident),*) => {$(
        impl sealed::Sealed for crate::mio_shim::net::$ty {}

        impl SimSocket for crate::mio_shim::net::$ty {
            fn socket_id(&self) -> SocketId {
                self.id()
            }
        }
    )*};
}

#[cfg(feature = "mio-compat")]
mio_sim_socket!(UdpSocket, TcpStream, TcpListener);

/// The [`SocketId`] of `s`.
pub fn socket_id(s: &impl SimSocket) -> SocketId {
    s.socket_id()
}

/// What kind of socket a [`SocketEntry`] describes.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketKind {
    Udp,
    TcpStream,
    TcpListener,
}

/// One socket as the network sees it.
#[derive(Debug, Clone)]
pub struct SocketEntry {
    pub id: SocketId,
    pub kind: SocketKind,
    pub local: SocketAddr,
    pub peer: Option<SocketAddr>,
    /// The listener an accepted stream came from.
    pub listener: Option<SocketId>,
    /// The interface owning the bound address; `None` for a wildcard bind.
    pub nic: Option<String>,
    pub bound_device: Option<String>,
    pub multicast_if: Option<String>,
    /// The multicast groups a UDP socket joined.
    pub memberships: Vec<crate::Membership>,
    pub last_tx_nic: Option<String>,
    pub last_rx_nic: Option<String>,
    pub rcvbuf: Option<usize>,
    pub sndbuf: Option<usize>,
    /// Datagrams (UDP) or chunks (TCP) waiting to be read or delivered.
    pub queued: usize,
    pub queued_bytes: usize,
    /// Datagrams (UDP) or chunks (TCP) delivered to the socket.
    pub delivered: u64,
    /// Datagrams dropped because the receive buffer was full.
    pub overflowed: u64,
    /// Datagrams lost on the wire before reaching the socket.
    pub wire_lost: u64,
    /// The socket's drop counter, as a kernel would report it.
    pub drops: u32,
    /// An ICMP-induced error waiting for the socket's next call.
    pub icmp_error: Option<Errno>,
    pub closed: bool,
    pub created_at: Instant,
    pub closed_at: Option<Instant>,
}

/// What the process is allowed to do. Everything is granted by default;
/// revoke to make privilege checks fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Privileges {
    pub root: bool,
    pub net_admin: bool,
    pub net_raw: bool,
    pub net_bind_service: bool,
    pub sys_nice: bool,
    pub ipc_lock: bool,
    pub rtprio_limit: u8,
    pub nice_limit: i8,
    /// `RLIMIT_MEMLOCK` in bytes; `None` is unlimited.
    pub memlock_limit: Option<u64>,
}

impl Default for Privileges {
    fn default() -> Self {
        Self {
            root: true,
            net_admin: true,
            net_raw: true,
            net_bind_service: true,
            sys_nice: true,
            ipc_lock: true,
            rtprio_limit: 99,
            nice_limit: -20,
            memlock_limit: None,
        }
    }
}

/// How a lost datagram is counted against its destination socket.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DropAccounting {
    /// Wire loss and buffer overflow both count as socket drops.
    #[default]
    PolicyAndOverflow,
    /// Only buffer overflow counts, as on a real kernel.
    OverflowOnly,
}

/// System-wide socket limits. Defaults follow the selected OS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysLimits {
    pub rmem_default: usize,
    pub rmem_max: usize,
    pub wmem_default: usize,
    pub wmem_max: usize,
    /// macOS `kern.ipc.maxsockbuf`.
    pub max_sockbuf: usize,
    /// macOS `net.inet.udp.maxdgram`.
    pub udp_max_dgram: Option<usize>,
    /// Enforce `rmem_default` on sockets that never set `SO_RCVBUF`.
    pub enforce_default_rcvbuf: bool,
    /// Bytes charged per queued datagram on top of its payload (Linux).
    pub per_datagram_overhead: usize,
    pub drop_accounting: DropAccounting,
}

impl SysLimits {
    /// The defaults of `os`.
    pub fn for_os(os: OsSemantics) -> Self {
        let (rmem_default, rmem_max, wmem_default, wmem_max, max_sockbuf, udp_max_dgram) = match os
        {
            OsSemantics::Linux => (212_992, 212_992, 212_992, 212_992, 212_992, None),
            OsSemantics::MacOs => (786_896, 8_388_608, 9_216, 8_388_608, 8_388_608, Some(9_216)),
            OsSemantics::Windows => (65_536, usize::MAX, 65_536, usize::MAX, usize::MAX, None),
        };
        Self {
            rmem_default,
            rmem_max,
            wmem_default,
            wmem_max,
            max_sockbuf,
            udp_max_dgram,
            enforce_default_rcvbuf: false,
            per_datagram_overhead: 768,
            drop_accounting: DropAccounting::PolicyAndOverflow,
        }
    }
}

impl Default for SysLimits {
    fn default() -> Self {
        Self::for_os(OsSemantics::host())
    }
}

/// Which socket buffer [`set_socket_buffer`] sets.
#[cfg_attr(not(any(test, feature = "fast-talker-core")), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BufDir {
    Recv,
    Send,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddrOrigin {
    Default,
    Legacy,
    Explicit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Proto {
    Udp,
    Tcp,
}

static NEXT_SOCKET: AtomicU64 = AtomicU64::new(1);

const LOOPBACK_INDEX: u32 = 1;
const DEFAULT_NIC_INDEX: u32 = 2;
const DEFAULT_NIC_NAME: &str = "snare0";
const DEFAULT_ROUTE_METRIC: u32 = 100;

#[derive(Debug)]
pub(crate) struct NicRec {
    pub id: NicId,
    pub spec: NicSpec,
    pub counters: NicCounters,
    pub default_nic: bool,
    pub explicit: bool,
    origins: HashMap<IpAddr, AddrOrigin>,
    #[cfg(feature = "fast-talker-core")]
    pub ft: crate::fast_talker_shim::slot::NicFt,
}

impl NicRec {
    fn new(id: NicId, mut spec: NicSpec, default_nic: bool, explicit: bool) -> Self {
        spec.index = Some(id.0);
        if spec.mac.is_none() {
            let [a, b, c, d] = id.0.to_be_bytes();
            spec.mac = Some([0x02, 0x00, a, b, c, d]);
        }
        let origin = if explicit {
            AddrOrigin::Explicit
        } else {
            AddrOrigin::Default
        };
        let origins = spec.addresses.iter().map(|n| (n.addr, origin)).collect();
        Self {
            id,
            #[cfg(feature = "fast-talker-core")]
            ft: crate::fast_talker_shim::slot::NicFt::new(&spec),
            spec,
            counters: NicCounters::default(),
            default_nic,
            explicit,
            origins,
        }
    }

    pub(crate) fn up(&self) -> bool {
        self.spec.link_up && !self.flapping()
    }

    /// Whether a Windows adapter restart holds the link down. Read without
    /// resolving the state slot, so it is safe under the state lock; a
    /// thread that has not read its clock yet sees the restart as still
    /// going on.
    #[cfg(feature = "fast-talker-core")]
    fn flapping(&self) -> bool {
        self.ft.flap_until.is_some_and(|until| {
            crate::sched::cached_mono_now().is_none_or(|now| now < until.as_virtual())
        })
    }

    #[cfg(not(feature = "fast-talker-core"))]
    fn flapping(&self) -> bool {
        false
    }

    /// When the last Windows adapter restart of this interface ended, or
    /// ends.
    pub(crate) fn flap_end(&self) -> Option<Instant> {
        #[cfg(feature = "fast-talker-core")]
        return self.ft.flap_until;
        #[cfg(not(feature = "fast-talker-core"))]
        None
    }

    pub(crate) fn is_loopback(&self) -> bool {
        self.spec.kind == NicKind::Loopback
    }

    fn origin(&self, ip: IpAddr) -> AddrOrigin {
        self.origins
            .get(&ip)
            .copied()
            .unwrap_or(AddrOrigin::Explicit)
    }

    fn first_addr(&self, v4: bool) -> Option<IpAddr> {
        self.spec
            .addresses
            .iter()
            .map(|n| n.addr)
            .find(|a| a.is_ipv4() == v4 && !a.is_unspecified())
    }
}

/// Host-wide UDP counters for one IP version, as the kernel keeps them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(not(feature = "fast-talker-core"), allow(dead_code))]
pub(crate) struct UdpStats {
    /// Datagrams put on a socket's receive queue.
    pub queued: u64,
    /// Datagrams an application read.
    pub read: u64,
    /// Datagrams to a port no socket was bound to, answered with ICMP.
    pub no_ports: u64,
    /// Datagrams sent.
    pub out: u64,
    /// Datagrams dropped because the receive buffer was full.
    pub rcvbuf_errors: u64,
    /// Datagrams dropped on receive for any reason.
    pub in_errors: u64,
}

/// UDP counters of the calling thread's state slot: IPv4, then IPv6.
#[cfg(feature = "fast-talker-core")]
pub(crate) fn udp_stats() -> [UdpStats; 2] {
    with_net(|ctx| ctx.net.udp_stats)
}

/// The per-slot network: interfaces, routes, OS selection, privileges,
/// limits and the closed-socket history.
#[derive(Debug)]
pub(crate) struct NetModel {
    pub os: OsSemantics,
    pub os_explicit: bool,
    pub nics: Vec<NicRec>,
    pub routes: Vec<Route>,
    pub privileges: Privileges,
    pub limits: SysLimits,
    pub limits_explicit: bool,
    pub history: Vec<SocketEntry>,
    /// Host-wide UDP counters: IPv4, then IPv6.
    pub udp_stats: [UdpStats; 2],
    next_index: u32,
    next_seq: u64,
    ephemeral_next: [Option<u16>; 2],
}

impl Default for NetModel {
    fn default() -> Self {
        Self::new(crate::os::env_os())
    }
}

impl NetModel {
    pub(crate) fn new(env: Option<OsSemantics>) -> Self {
        let os = env.unwrap_or_default();
        let lo = NicRec::new(
            NicId(LOOPBACK_INDEX),
            NicSpec::loopback(os.loopback_name()),
            false,
            false,
        );
        let snare0 = NicRec::new(
            NicId(DEFAULT_NIC_INDEX),
            NicSpec::new(DEFAULT_NIC_NAME),
            true,
            false,
        );
        Self {
            os,
            os_explicit: env.is_some(),
            nics: vec![lo, snare0],
            routes: default_routes(DEFAULT_NIC_NAME),
            privileges: Privileges::default(),
            limits: SysLimits::for_os(os),
            limits_explicit: false,
            history: Vec::new(),
            udp_stats: [UdpStats::default(); 2],
            next_index: DEFAULT_NIC_INDEX + 1,
            next_seq: 0,
            ephemeral_next: [None; 2],
        }
    }

    pub(crate) fn set_os(&mut self, os: OsSemantics) {
        self.os = os;
        self.os_explicit = true;
        self.ephemeral_next = [None; 2];
        if let Some(lo) = self.nics.iter_mut().find(|n| n.is_loopback()) {
            lo.spec.name = os.loopback_name().to_string();
        }
        if !self.limits_explicit {
            self.limits = SysLimits::for_os(os);
        }
    }

    pub(crate) fn faithful(&self) -> bool {
        self.os_explicit
    }

    /// The UDP counters of the IP version of `addr`.
    pub(crate) fn udp_stats_mut(&mut self, addr: &SocketAddr) -> &mut UdpStats {
        &mut self.udp_stats[usize::from(!addr.is_ipv4())]
    }

    /// A fresh id, unique across every state slot, so a socket that
    /// outlives its slot never aliases one created after `register_test`.
    pub(crate) fn next_socket_id(&mut self) -> SocketId {
        SocketId(NEXT_SOCKET.fetch_add(1, Ordering::Relaxed))
    }

    pub(crate) fn next_seq(&mut self) -> u64 {
        self.next_seq += 1;
        self.next_seq
    }

    pub(crate) fn nic_by_id(&self, id: NicId) -> Option<&NicRec> {
        self.nics.iter().find(|n| n.id == id)
    }

    pub(crate) fn nic_by_id_mut(&mut self, id: NicId) -> Option<&mut NicRec> {
        self.nics.iter_mut().find(|n| n.id == id)
    }

    pub(crate) fn nic_by_name(&self, name: &str) -> Option<&NicRec> {
        self.nics.iter().find(|n| n.spec.name == name)
    }

    fn nic_by_name_mut(&mut self, name: &str) -> Option<&mut NicRec> {
        self.nics.iter_mut().find(|n| n.spec.name == name)
    }

    pub(crate) fn nic_name(&self, id: Option<NicId>) -> Option<String> {
        id.and_then(|id| self.nic_by_id(id))
            .map(|n| n.spec.name.clone())
    }

    fn loopback(&self) -> Option<&NicRec> {
        self.nics.iter().find(|n| n.is_loopback())
    }

    pub(crate) fn default_nic(&self) -> Option<&NicRec> {
        self.nics.iter().find(|n| n.default_nic)
    }

    /// The interface that owns `ip` as one of its addresses. On the loopback
    /// the whole `127.0.0.0/8` counts on faithful Linux and Windows.
    pub(crate) fn owner_of(&self, ip: IpAddr) -> Option<&NicRec> {
        if ip.is_unspecified() {
            return None;
        }
        if let Some(n) = self
            .nics
            .iter()
            .find(|n| n.spec.addresses.iter().any(|a| a.addr == ip))
        {
            return Some(n);
        }
        if self.faithful() && self.os != OsSemantics::MacOs && ip.is_loopback() && ip.is_ipv4() {
            return self
                .loopback()
                .filter(|lo| lo.spec.addresses.iter().any(|a| a.contains(ip)));
        }
        None
    }

    pub(crate) fn owner_id(&self, ip: IpAddr) -> Option<NicId> {
        self.owner_of(ip).map(|n| n.id)
    }

    /// Whether a socket may bind `ip`.
    pub(crate) fn is_ip_valid(&self, ip: IpAddr) -> bool {
        ip.is_unspecified() || self.owner_of(ip).is_some()
    }

    /// Whether `ip` is an address a test assigned explicitly, through
    /// [`add_nic`] or [`set_nic`]. Traffic to such addresses follows the
    /// modern delivery and source-selection rules even in legacy mode.
    pub(crate) fn ip_is_explicit(&self, ip: IpAddr) -> bool {
        self.owner_of(ip)
            .is_some_and(|n| n.explicit || n.origin(ip) == AddrOrigin::Explicit)
    }

    /// Whether a datagram to `ip` that finds no socket is answered with ICMP
    /// port unreachable: the owning interface's policy asks for it and the
    /// address was not assigned through [`add_ip_addr`](crate::add_ip_addr).
    pub(crate) fn icmp_answers(&self, ip: IpAddr) -> bool {
        self.owner_of(ip).is_some_and(|n| {
            n.spec.policy.icmp_port_unreachable && n.origin(ip) != AddrOrigin::Legacy
        })
    }

    /// Modern delivery and source selection apply to `ip`.
    pub(crate) fn modern(&self, ip: IpAddr) -> bool {
        self.faithful() || self.ip_is_explicit(ip)
    }

    pub(crate) fn is_broadcast(&self, ip: IpAddr) -> bool {
        let IpAddr::V4(v4) = ip else {
            return false;
        };
        v4 == Ipv4Addr::BROADCAST
            || self
                .nics
                .iter()
                .flat_map(|n| n.spec.addresses.iter())
                .any(|a| a.broadcast() == Some(v4))
    }

    pub(crate) fn add_ip_addr(&mut self, ip: IpAddr) {
        if ip.is_unspecified() || self.owner_of(ip).is_some() {
            return;
        }
        let target = if ip.is_loopback() {
            self.nics.iter_mut().find(|n| n.is_loopback())
        } else {
            self.nics.iter_mut().find(|n| n.default_nic)
        };
        if let Some(nic) = target {
            nic.spec.addresses.push(IpNet::host(ip));
            nic.origins.insert(ip, AddrOrigin::Legacy);
        }
    }

    /// Every route as (destination, interface, preferred source, metric):
    /// the configured ones in insertion order, then the connected routes
    /// derived from the interfaces' addresses.
    fn route_views(&self) -> impl Iterator<Item = (IpNet, &str, Option<IpAddr>, u32)> {
        let configured = self
            .routes
            .iter()
            .map(|r| (r.dest, r.nic.as_str(), r.src, r.metric));
        let connected = self.nics.iter().flat_map(|n| {
            n.spec.addresses.iter().map(move |a| {
                let dest = IpNet {
                    addr: a.network(),
                    prefix: a.prefix,
                };
                (dest, n.spec.name.as_str(), Some(a.addr), 0)
            })
        });
        configured.chain(connected)
    }

    fn all_routes(&self) -> Vec<Route> {
        let connected = self.nics.iter().flat_map(|n| {
            n.spec.addresses.iter().map(|a| Route {
                dest: IpNet {
                    addr: a.network(),
                    prefix: a.prefix,
                },
                nic: n.spec.name.clone(),
                gateway: None,
                src: Some(a.addr),
                metric: 0,
            })
        });
        self.routes.iter().cloned().chain(connected).collect()
    }

    fn nic_reaches(&self, nic: &NicRec, dst: IpAddr) -> bool {
        if nic.is_loopback() && dst.is_loopback() {
            return true;
        }
        nic.spec.addresses.iter().any(|a| a.contains(dst))
            || self
                .routes
                .iter()
                .any(|r| r.nic == nic.spec.name && r.dest.contains(dst) && r.dest.prefix > 0)
    }

    /// Pick the egress interface for a send from `sock` to `dst`, and the
    /// source address its route prefers.
    pub(crate) fn select_egress(
        &self,
        sock: &SockView,
        dst: IpAddr,
    ) -> Result<(NicId, Option<IpAddr>), Errno> {
        if let Some(dev) = sock.bound_device {
            let nic = self.nic_by_id(dev).ok_or(Errno::NoDev)?;
            if !nic.up() {
                return Err(Errno::NetDown);
            }
            if !self.nic_reaches(nic, dst) && !self.default_route_via(nic) {
                return Err(Errno::NetUnreach);
            }
            return Ok((nic.id, None));
        }
        if dst.is_multicast()
            && let Some(dev) = sock.multicast_if
        {
            let nic = self.nic_by_id(dev).ok_or(Errno::NoDev)?;
            if !nic.up() {
                return Err(Errno::NetDown);
            }
            return Ok((nic.id, None));
        }
        // A limited broadcast, and on Linux any IPv4 multicast, leaves
        // through the interface owning the bound source address, not through
        // a route.
        let by_source = dst == IpAddr::V4(Ipv4Addr::BROADCAST)
            || (self.os == OsSemantics::Linux
                && self.faithful()
                && dst.is_ipv4()
                && dst.is_multicast());
        if by_source && let Some(nic) = self.owner_of(sock.local_ip) {
            return if nic.up() {
                Ok((nic.id, None))
            } else {
                Err(Errno::NetDown)
            };
        }
        if dst.is_loopback() {
            let lo = self.loopback().ok_or(Errno::NetUnreach)?;
            if !lo.up() {
                return Err(Errno::NetDown);
            }
            return Ok((lo.id, None));
        }
        let local_nic = (!sock.local_ip.is_unspecified())
            .then(|| self.owner_of(sock.local_ip))
            .flatten();
        let candidates = self
            .route_views()
            .enumerate()
            .filter(|(_, (dest, ..))| dest.contains(dst))
            .filter_map(|(seq, (dest, nic, src, metric))| {
                let nic = self.nic_by_name(nic)?;
                nic.up().then_some((dest.prefix, metric, src, seq, nic))
            });
        let rank = |(prefix, metric, _, seq, nic): &(u8, u32, Option<IpAddr>, usize, &NicRec)| {
            (
                std::cmp::Reverse(*prefix),
                local_nic.is_none_or(|l| l.id != nic.id),
                *metric,
                *seq,
            )
        };
        let strong =
            self.os == OsSemantics::Windows && sock.strong_host && !sock.local_ip.is_unspecified();
        if strong {
            let Some(local) = local_nic else {
                return Err(Errno::HostUnreach);
            };
            if !local.up() {
                return Err(Errno::NetDown);
            }
            return candidates
                .filter(|(.., nic)| nic.id == local.id)
                .min_by_key(rank)
                .map(|(_, _, src, _, nic)| (nic.id, src))
                .ok_or(Errno::HostUnreach);
        }
        match candidates.min_by_key(rank) {
            Some((_, _, src, _, nic)) => Ok((nic.id, src)),
            None => {
                if self.os == OsSemantics::MacOs && local_nic.is_some_and(|l| !l.up()) {
                    Err(Errno::NetDown)
                } else {
                    Err(Errno::NetUnreach)
                }
            }
        }
    }

    fn default_route_via(&self, nic: &NicRec) -> bool {
        self.routes
            .iter()
            .any(|r| r.dest.prefix == 0 && r.nic == nic.spec.name)
    }

    /// The source IP of a datagram or connection from a socket bound to
    /// `local_ip` towards `dst` through `egress`. `None` keeps the bound
    /// (possibly wildcard) address.
    pub(crate) fn select_source(
        &self,
        local_ip: IpAddr,
        dst: IpAddr,
        egress: NicId,
        route_src: Option<IpAddr>,
    ) -> Option<IpAddr> {
        if !local_ip.is_unspecified() {
            return Some(local_ip);
        }
        if self.owner_of(dst).is_some() {
            return Some(dst);
        }
        if let Some(src) = route_src.filter(|s| s.is_ipv4() == dst.is_ipv4()) {
            return Some(src);
        }
        self.nic_by_id(egress)?.first_addr(dst.is_ipv4())
    }

    /// Whether the modern source-selection rule applies to a send through
    /// `egress`.
    pub(crate) fn modern_source(&self, egress: NicId) -> bool {
        self.faithful() || self.nic_by_id(egress).is_some_and(|n| n.explicit)
    }

    /// Whether strong-host routing applies to a socket bound to `local_ip`
    /// sending to `dst`.
    pub(crate) fn strong_host_applies(&self, local_ip: IpAddr, dst: IpAddr) -> bool {
        self.faithful() || self.ip_is_explicit(local_ip) || self.ip_is_explicit(dst)
    }

    pub(crate) fn ingress_for(&self, dst: IpAddr, egress: Option<NicId>) -> Option<NicId> {
        self.owner_id(dst).or(egress)
    }

    pub(crate) fn nic_up(&self, id: Option<NicId>) -> bool {
        id.and_then(|id| self.nic_by_id(id)).is_none_or(|n| n.up())
    }

    pub(crate) fn policy_of(&self, id: Option<NicId>) -> NicPolicy {
        id.and_then(|id| self.nic_by_id(id))
            .map(|n| n.spec.policy)
            .unwrap_or_default()
    }

    /// Whether a flow rule on the interface `ingress` drops a UDP datagram
    /// from `src` to `dst` in hardware. A dropped datagram counts in the
    /// interface's `rx_dropped`.
    pub(crate) fn flow_drops(
        &mut self,
        ingress: Option<NicId>,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> bool {
        #[cfg(feature = "fast-talker-core")]
        if let Some(nic) = ingress.and_then(|id| self.nic_by_id_mut(id))
            && crate::fast_talker_shim::nic::udp_flow_dropped(nic, src, dst)
        {
            nic.counters.rx_dropped += 1;
            return true;
        }
        let _ = (ingress, src, dst);
        false
    }

    pub(crate) fn counters_mut(&mut self, id: Option<NicId>) -> Option<&mut NicCounters> {
        id.and_then(|id| self.nic_by_id_mut(id))
            .map(|n| &mut n.counters)
    }

    /// Pick an ephemeral port in the selected OS's range that `taken` does
    /// not reject.
    pub(crate) fn faithful_ephemeral(
        &mut self,
        proto: Proto,
        mut taken: impl FnMut(u16) -> bool,
    ) -> Option<u16> {
        let range = self.os.ephemeral_ports();
        let (start, end) = (*range.start(), *range.end());
        let slot = &mut self.ephemeral_next[proto as usize];
        let mut port = slot.filter(|p| range.contains(p)).unwrap_or(start);
        for _ in 0..=(end - start) {
            let candidate = port;
            port = if port == end { start } else { port + 1 };
            if !taken(candidate) {
                *slot = Some(port);
                return Some(candidate);
            }
        }
        None
    }
}

fn default_routes(nic: &str) -> Vec<Route> {
    vec![
        Route {
            metric: DEFAULT_ROUTE_METRIC,
            ..Route::new(IpNet::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0), nic)
        },
        Route {
            metric: DEFAULT_ROUTE_METRIC,
            ..Route::new(IpNet::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0), nic)
        },
    ]
}

/// The routing-relevant view of a socket.
pub(crate) struct SockView {
    pub local_ip: IpAddr,
    pub bound_device: Option<NicId>,
    pub multicast_if: Option<NicId>,
    pub strong_host: bool,
}

/// Whether binding `new` conflicts with an existing bind at `old` of the
/// same protocol, under `os`'s rules.
pub(crate) fn bind_conflicts(os: OsSemantics, old: SocketAddr, new: SocketAddr) -> bool {
    if old.port() != new.port() || old.is_ipv4() != new.is_ipv4() {
        return false;
    }
    let (o, n) = (old.ip().is_unspecified(), new.ip().is_unspecified());
    if os == OsSemantics::Windows && o && !n {
        return false;
    }
    o || n || old.ip() == new.ip()
}

fn not_found(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("no interface named {what:?}"),
    )
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

fn check_addresses(net: &NetModel, spec: &NicSpec, except: Option<NicId>) -> io::Result<()> {
    for a in &spec.addresses {
        if a.addr.is_unspecified() || a.addr.is_multicast() {
            return Err(invalid(format!("{a} cannot be an interface address")));
        }
        if spec.kind != NicKind::Loopback && a.addr.is_loopback() {
            return Err(invalid(format!("{a} is a loopback address")));
        }
        if let Some(owner) = net.nics.iter().find(|n| {
            Some(n.id) != except
                && n.spec
                    .addresses
                    .iter()
                    .any(|b| b.addr == a.addr && n.origin(b.addr) != AddrOrigin::Legacy)
        }) {
            return Err(invalid(format!(
                "{} is already assigned to {}",
                a.addr, owner.spec.name
            )));
        }
    }
    Ok(())
}

fn take_legacy(net: &mut NetModel, spec: &NicSpec, except: Option<NicId>) {
    for n in net.nics.iter_mut().filter(|n| Some(n.id) != except) {
        n.spec.addresses.retain(|b| {
            !(spec.addresses.iter().any(|a| a.addr == b.addr)
                && n.origins.get(&b.addr) == Some(&AddrOrigin::Legacy))
        });
    }
}

/// Add an interface. Its addresses must not belong to another interface,
/// except addresses [`add_ip_addr`](crate::add_ip_addr) put on the default
/// interface, which move to the new one.
pub fn add_nic(spec: NicSpec) -> io::Result<NicId> {
    with_net(|ctx| {
        let net = ctx.net;
        if net.nic_by_name(&spec.name).is_some() || spec.name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("an interface named {:?} already exists", spec.name),
            ));
        }
        if spec.kind == NicKind::Loopback {
            return Err(invalid("a state slot has exactly one loopback".into()));
        }
        check_addresses(net, &spec, None)?;
        let index = match spec.index {
            Some(i) if net.nics.iter().any(|n| n.id.0 == i) || i == 0 => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("interface index {i} is taken"),
                ));
            }
            Some(i) => i,
            None => {
                while net.nics.iter().any(|n| n.id.0 == net.next_index) {
                    net.next_index += 1;
                }
                net.next_index
            }
        };
        net.next_index = net.next_index.max(index + 1);
        take_legacy(net, &spec, None);
        let id = NicId(index);
        net.nics.push(NicRec::new(id, spec, false, true));
        Ok(id)
    })
}

/// Remove the interface `name`. The loopback and the default interface
/// cannot be removed. Routes through it go with it; sockets bound to its
/// addresses stay open but can no longer route. TCP bytes stalled on its
/// link are released, and its connections no longer run over an interface.
pub fn remove_nic(name: &str) -> bool {
    let now = Instant::now();
    let resumed = with_net(|ctx| {
        let net = &mut *ctx.net;
        let idx = net
            .nics
            .iter()
            .position(|n| n.spec.name == name && !n.is_loopback() && !n.default_nic)?;
        let id = net.nics[idx].id;
        let wakes = crate::state::resume_stalled_locked(ctx.tcp, net, id, now);
        for c in ctx.tcp.values_mut().filter(|c| c.nic == Some(id)) {
            c.nic = None;
        }
        let removed = net.nics.remove(idx);
        net.routes.retain(|r| r.nic != name);
        Some((wakes, removed))
    });
    match resumed {
        Some((wakes, _removed)) => {
            crate::state::wake_stalled(wakes);
            #[cfg(feature = "fast-talker-core")]
            crate::fast_talker_shim::nic::retire_removed(_removed);
            true
        }
        None => false,
    }
}

/// Change an interface. Addresses it gains count as explicitly assigned. A
/// link that comes up resumes stalled TCP traffic.
pub fn set_nic(name: &str, f: impl FnOnce(&mut NicSpec)) -> io::Result<()> {
    let now = Instant::now();
    let resumed = with_net(|ctx| {
        let net = &mut *ctx.net;
        let nic = net.nic_by_name(name).ok_or_else(|| not_found(name))?;
        let id = nic.id;
        let was_up = nic.up();
        let mut spec = nic.spec.clone();
        f(&mut spec);
        spec.index = Some(id.0);
        if spec.name != name && net.nic_by_name(&spec.name).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("an interface named {:?} already exists", spec.name),
            ));
        }
        if spec.name.is_empty() {
            return Err(invalid("an interface needs a name".into()));
        }
        let kind = net.nic_by_id(id).map(|n| n.spec.kind);
        if kind != Some(spec.kind) {
            return Err(invalid("an interface's kind cannot change".into()));
        }
        check_addresses(net, &spec, Some(id))?;
        take_legacy(net, &spec, Some(id));
        if spec.name != name {
            for r in net.routes.iter_mut().filter(|r| r.nic == name) {
                r.nic = spec.name.clone();
            }
        }
        let nic = net.nic_by_id_mut(id).expect("interface vanished");
        for a in &spec.addresses {
            nic.origins.entry(a.addr).or_insert(AddrOrigin::Explicit);
        }
        let up = spec.link_up;
        nic.spec = spec;
        Ok((!was_up && up).then(|| crate::state::resume_stalled_locked(ctx.tcp, net, id, now)))
    })?;
    if let Some(wakes) = resumed {
        crate::state::wake_stalled(wakes);
    }
    Ok(())
}

/// Bring an interface's link up or down. Down, datagrams to its addresses
/// are lost silently, sends that must use it fail with `ENETDOWN`, and TCP
/// bytes over it stall until the link returns.
pub fn set_link(name: &str, up: bool) -> io::Result<()> {
    set_nic(name, |spec| spec.link_up = up)
}

/// Change an interface's link policy.
pub fn set_nic_policy(name: &str, f: impl FnOnce(&mut NicPolicy)) -> io::Result<()> {
    with_net(|ctx| {
        let nic = ctx
            .net
            .nic_by_name_mut(name)
            .ok_or_else(|| not_found(name))?;
        f(&mut nic.spec.policy);
        Ok(())
    })
}

/// Change an interface's counters.
pub fn set_nic_counters(name: &str, f: impl FnOnce(&mut NicCounters)) -> io::Result<()> {
    with_net(|ctx| {
        let nic = ctx
            .net
            .nic_by_name_mut(name)
            .ok_or_else(|| not_found(name))?;
        f(&mut nic.counters);
        Ok(())
    })
}

/// A snapshot of the interface `name`.
pub fn nic(name: &str) -> Option<NicSnapshot> {
    with_net(|ctx| {
        let table = socket_table_locked(&ctx);
        let nic = ctx.net.nic_by_name(name)?;
        Some(snapshot(nic, &table))
    })
}

/// Run `f` on the fast-talker state of the interface `name`, under the
/// state lock: `f` must not call back into snare.
#[cfg(feature = "fast-talker-core")]
pub(crate) fn with_nic_ft<R>(
    name: &str,
    f: impl FnOnce(&mut crate::fast_talker_shim::slot::NicFt) -> R,
) -> Option<R> {
    with_net(|ctx| ctx.net.nic_by_name_mut(name).map(|n| f(&mut n.ft)))
}

/// Run `f` on the interface with index `id`, under the state lock: `f`
/// must not call back into snare.
#[cfg(feature = "fast-talker-core")]
pub(crate) fn with_nic_rec<R>(
    id: NicId,
    f: impl FnOnce(&mut NicRec, OsSemantics) -> R,
) -> Option<R> {
    with_net(|ctx| {
        let os = ctx.net.os;
        ctx.net.nic_by_id_mut(id).map(|n| f(n, os))
    })
}

/// Put an ETF qdisc on the interface `name`, on transmit queue `queue`
/// (`None` for the root), or take it off with `None`.
#[cfg(feature = "fast-talker-core")]
pub(crate) fn set_etf_internal(
    name: &str,
    queue: Option<u16>,
    etf: Option<crate::fast_talker_shim::nic::Etf>,
) -> io::Result<()> {
    with_nic_ft(name, |ft| match etf {
        Some(etf) => {
            ft.etf.insert(queue, etf);
        }
        None => {
            ft.etf.remove(&queue);
        }
    })
    .ok_or_else(|| not_found(name))
}

/// Snapshots of every interface, in index order.
pub fn nics() -> Vec<NicSnapshot> {
    with_net(|ctx| {
        let table = socket_table_locked(&ctx);
        let mut out: Vec<NicSnapshot> = ctx.net.nics.iter().map(|n| snapshot(n, &table)).collect();
        out.sort_by_key(|n| n.id);
        out
    })
}

fn snapshot(nic: &NicRec, table: &[SocketEntry]) -> NicSnapshot {
    let name = Some(nic.spec.name.clone());
    NicSnapshot {
        id: nic.id,
        spec: nic.spec.clone(),
        counters: nic.counters.clone(),
        sockets: table
            .iter()
            .filter(|e| e.nic == name || e.bound_device == name)
            .map(|e| e.id)
            .collect(),
        default_nic: nic.default_nic,
        explicit: nic.explicit,
    }
}

/// The counters of the interface `name`.
pub fn nic_counters(name: &str) -> Option<NicCounters> {
    with_net(|ctx| ctx.net.nic_by_name(name).map(|n| n.counters.clone()))
}

/// Add a route. Its interface must exist.
pub fn add_route(route: Route) -> io::Result<()> {
    with_net(|ctx| {
        if ctx.net.nic_by_name(&route.nic).is_none() {
            return Err(not_found(&route.nic));
        }
        ctx.net.routes.push(route);
        Ok(())
    })
}

/// Remove every configured route to `dest`. Connected routes, which follow
/// the interfaces' addresses, cannot be removed.
pub fn remove_route(dest: IpNet) -> bool {
    with_net(|ctx| {
        let before = ctx.net.routes.len();
        ctx.net.routes.retain(|r| r.dest != dest);
        ctx.net.routes.len() != before
    })
}

/// Point the IPv4 and IPv6 default routes at `nic`, or remove them.
pub fn set_default_route(nic: Option<&str>) -> io::Result<()> {
    with_net(|ctx| {
        if let Some(name) = nic
            && ctx.net.nic_by_name(name).is_none()
        {
            return Err(not_found(name));
        }
        ctx.net.routes.retain(|r| r.dest.prefix != 0);
        if let Some(name) = nic {
            ctx.net.routes.extend(default_routes(name));
        }
        Ok(())
    })
}

/// Every route: the configured ones in insertion order, then the connected
/// routes derived from the interfaces' addresses.
pub fn routes() -> Vec<Route> {
    with_net(|ctx| ctx.net.all_routes())
}

/// The interface a packet from `src` to `dst` leaves through, and the
/// source address that would be chosen for it.
pub fn route_lookup(src: Option<IpAddr>, dst: IpAddr) -> io::Result<(String, Option<IpAddr>)> {
    with_net(|ctx| {
        let net = &*ctx.net;
        let local_ip = src.unwrap_or(if dst.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        });
        let view = SockView {
            local_ip,
            bound_device: None,
            multicast_if: None,
            strong_host: net.strong_host_applies(local_ip, dst),
        };
        let (egress, route_src) = net
            .select_egress(&view, dst)
            .map_err(|e| os_err_for(net.os, e))?;
        let source = net.select_source(local_ip, dst, egress, route_src);
        Ok((net.nic_name(Some(egress)).unwrap_or_default(), source))
    })
}

pub(crate) fn udp_entry(net: &NetModel, c: &UdpConnection) -> SocketEntry {
    SocketEntry {
        id: c.id,
        kind: SocketKind::Udp,
        local: c.bound_addr,
        peer: c.connected,
        listener: None,
        nic: net.nic_name(net.owner_id(c.bound_addr.ip())),
        bound_device: net.nic_name(c.bound_device),
        multicast_if: net.nic_name(c.multicast_if),
        memberships: crate::mcast::memberships(net, &c.mcast),
        last_tx_nic: net.nic_name(c.last_tx_nic),
        last_rx_nic: net.nic_name(c.last_rx_nic),
        rcvbuf: c.rcvbuf,
        sndbuf: c.sndbuf,
        queued: c.to_local.len(),
        queued_bytes: c.queued_bytes,
        delivered: c.delivered,
        overflowed: c.overflowed,
        wire_lost: c.wire_lost,
        drops: c.drops,
        icmp_error: c.icmp_error.map(|(_, e)| e),
        closed: c.is_destroyed || c.dropped,
        created_at: c.created_at,
        closed_at: c.closed_at,
    }
}

pub(crate) fn tcp_entry(net: &NetModel, c: &TcpConnection) -> SocketEntry {
    let pending: usize = c.pending_inbound.iter().map(|(_, b)| b.len()).sum();
    let stalled: usize = c.stalled.iter().map(Vec::len).sum();
    SocketEntry {
        id: c.id,
        kind: SocketKind::TcpStream,
        local: c.local_addr,
        peer: Some(c.peer_addr),
        listener: c.listener,
        nic: net.nic_name(net.owner_id(c.local_addr.ip())),
        bound_device: net.nic_name(c.bound_device),
        multicast_if: None,
        memberships: Vec::new(),
        last_tx_nic: net.nic_name(c.nic),
        last_rx_nic: net.nic_name(c.nic),
        rcvbuf: c.rcvbuf,
        sndbuf: c.sndbuf,
        queued: c.pending_inbound.len() + c.stalled.len(),
        queued_bytes: c.incoming.len() + pending + stalled,
        delivered: c.delivered,
        overflowed: 0,
        wire_lost: 0,
        drops: 0,
        icmp_error: None,
        closed: c.is_destroyed,
        created_at: c.created_at,
        closed_at: None,
    }
}

pub(crate) fn listener_entry(net: &NetModel, l: &crate::state::TcpListenerState) -> SocketEntry {
    SocketEntry {
        id: l.id,
        kind: SocketKind::TcpListener,
        local: l.bound_addr,
        peer: None,
        listener: None,
        nic: net.nic_name(net.owner_id(l.bound_addr.ip())),
        bound_device: net.nic_name(l.bound_device),
        multicast_if: None,
        memberships: Vec::new(),
        last_tx_nic: None,
        last_rx_nic: None,
        rcvbuf: None,
        sndbuf: None,
        queued: l.pending_streams.len(),
        queued_bytes: 0,
        delivered: 0,
        overflowed: 0,
        wire_lost: 0,
        drops: 0,
        icmp_error: None,
        closed: l.is_closed,
        created_at: l.created_at,
        closed_at: None,
    }
}

pub(crate) fn socket_table_locked(ctx: &NetCtx<'_>) -> Vec<SocketEntry> {
    let net = &*ctx.net;
    let mut out: Vec<SocketEntry> = ctx
        .udp
        .iter()
        .filter(|c| !c.dropped)
        .map(|c| udp_entry(net, c))
        .collect();
    out.extend(ctx.tcp.values().map(|c| tcp_entry(net, c)));
    out.extend(ctx.listeners.values().map(|l| listener_entry(net, l)));
    out.sort_by_key(|e| e.id);
    out
}

/// The socket `id`, live or closed.
pub fn socket_entry(id: SocketId) -> Option<SocketEntry> {
    with_net(|ctx| {
        socket_table_locked(&ctx)
            .into_iter()
            .find(|e| e.id == id)
            .or_else(|| ctx.net.history.iter().rev().find(|e| e.id == id).cloned())
    })
}

/// Every live socket bound to `local`: a listener and the streams accepted
/// from it share one.
pub fn sockets_bound(local: SocketAddr) -> Vec<SocketEntry> {
    with_net(|ctx| {
        socket_table_locked(&ctx)
            .into_iter()
            .filter(|e| e.local == local)
            .collect()
    })
}

/// Every live socket, by id.
pub fn socket_table() -> Vec<SocketEntry> {
    with_net(|ctx| socket_table_locked(&ctx))
}

/// Every socket that has been closed, oldest first.
pub fn closed_sockets() -> Vec<SocketEntry> {
    with_net(|ctx| ctx.net.history.clone())
}

/// Bind the socket `id` to the interface `nic` (`SO_BINDTODEVICE`), or
/// unbind it. It then sends only through that interface and receives only
/// what arrives on it.
pub fn set_socket_device(id: SocketId, nic: Option<&str>) -> io::Result<()> {
    with_net(|ctx| {
        let os = ctx.net.os;
        let dev = match nic {
            Some(name) => Some(
                ctx.net
                    .nic_by_name(name)
                    .map(|n| n.id)
                    .ok_or_else(|| os_err_for(os, Errno::NoDev))?,
            ),
            None => None,
        };
        if let Some(c) = ctx.udp.iter_mut().find(|c| c.id == id && !c.dropped) {
            c.bound_device = dev;
        } else if let Some(c) = ctx.tcp.values_mut().find(|c| c.id == id) {
            c.bound_device = dev;
        } else if let Some(l) = ctx.listeners.values_mut().find(|l| l.id == id) {
            l.bound_device = dev;
        } else {
            return Err(no_socket(id));
        }
        Ok(())
    })
}

/// Add `n` to the drop counter of the UDP socket `id`.
pub fn inject_socket_drops(id: SocketId, n: u32) -> io::Result<()> {
    with_net(|ctx| {
        let c = ctx
            .udp
            .iter_mut()
            .find(|c| c.id == id && !c.dropped)
            .ok_or_else(|| no_socket(id))?;
        c.drops = c.drops.wrapping_add(n);
        Ok(())
    })
}

fn no_socket(id: SocketId) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("no live socket with id {}", id.0),
    )
}

/// Change the process's privileges.
pub fn set_privileges(f: impl FnOnce(&mut Privileges)) {
    with_net(|ctx| f(&mut ctx.net.privileges));
}

/// The process's privileges.
pub fn privileges() -> Privileges {
    with_net(|ctx| ctx.net.privileges.clone())
}

/// Change the system's socket limits. From then on
/// [`set_os_semantics`](crate::set_os_semantics) no longer resets them.
pub fn set_sys_limits(f: impl FnOnce(&mut SysLimits)) {
    with_net(|ctx| {
        f(&mut ctx.net.limits);
        ctx.net.limits_explicit = true;
    });
}

/// The system's socket limits.
pub fn sys_limits() -> SysLimits {
    with_net(|ctx| ctx.net.limits.clone())
}

/// Set `SO_RCVBUF` or `SO_SNDBUF` on the socket `id` as the selected OS
/// would, returning the effective size. `force` is `SO_RCVBUFFORCE`. A
/// listener's buffers are checked but not kept: nothing is queued on it.
#[cfg_attr(not(any(test, feature = "fast-talker-core")), allow(dead_code))]
pub(crate) fn set_socket_buffer(
    id: SocketId,
    dir: BufDir,
    requested: usize,
    force: bool,
) -> io::Result<usize> {
    with_net(|ctx| {
        let net = &*ctx.net;
        let os = net.os;
        let limits = &net.limits;
        let effective = match os {
            OsSemantics::Linux => {
                if force && !(net.privileges.net_admin || net.privileges.root) {
                    return Err(sys_err_for(os, crate::os::SysErrno::Perm));
                }
                let (cap, min) = match dir {
                    BufDir::Recv => (limits.rmem_max, 2304),
                    BufDir::Send => (limits.wmem_max, 4608),
                };
                let capped = if force { requested } else { requested.min(cap) };
                capped.saturating_mul(2).max(min)
            }
            OsSemantics::MacOs => {
                if requested > limits.max_sockbuf {
                    return Err(os_err_for(os, Errno::NoBufs));
                }
                requested
            }
            OsSemantics::Windows => requested,
        };
        let slot = if let Some(c) = ctx.udp.iter_mut().find(|c| c.id == id && !c.dropped) {
            match dir {
                BufDir::Recv => &mut c.rcvbuf,
                BufDir::Send => &mut c.sndbuf,
            }
        } else if let Some(c) = ctx.tcp.values_mut().find(|c| c.id == id) {
            match dir {
                BufDir::Recv => &mut c.rcvbuf,
                BufDir::Send => &mut c.sndbuf,
            }
        } else if ctx.listeners.values().any(|l| l.id == id && !l.is_closed) {
            return Ok(effective);
        } else {
            return Err(no_socket(id));
        };
        *slot = Some(effective);
        Ok(effective)
    })
}

/// The receive-buffer cap enforced on a UDP socket, if any.
pub(crate) fn rcvbuf_cap(net: &NetModel, rcvbuf: Option<usize>) -> Option<usize> {
    rcvbuf.or_else(|| {
        net.limits.enforce_default_rcvbuf.then(|| {
            if net.os == OsSemantics::Linux {
                net.limits.rmem_default.saturating_mul(2)
            } else {
                net.limits.rmem_default
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::UdpSocket;

    #[test]
    fn ipnet_math() {
        let n: IpNet = "10.1.2.3/24".parse().unwrap();
        assert_eq!(n.network(), "10.1.2.0".parse::<IpAddr>().unwrap());
        assert!(n.contains("10.1.2.200".parse().unwrap()));
        assert!(!n.contains("10.1.3.1".parse().unwrap()));
        assert_eq!(n.broadcast(), Some(Ipv4Addr::new(10, 1, 2, 255)));
        let h: IpNet = "fe80::1".parse().unwrap();
        assert_eq!(h.prefix, 128);
        assert!(
            IpNet::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).contains("1.2.3.4".parse().unwrap())
        );
    }

    fn setup(os: OsSemantics) -> (UdpSocket, UdpSocket) {
        crate::register_test();
        crate::set_os_semantics(os);
        crate::pause_time();
        add_nic(NicSpec::new("eth0").address("10.0.0.1/24".parse::<IpNet>().unwrap())).unwrap();
        add_nic(NicSpec::new("eth1").address("10.0.0.2/24".parse::<IpNet>().unwrap())).unwrap();
        let rx = UdpSocket::bind("10.0.0.2:7000").unwrap();
        rx.set_nonblocking(true).unwrap();
        let tx = UdpSocket::bind("10.0.0.1:7001").unwrap();
        (rx, tx)
    }

    fn fill(os: OsSemantics, cap: usize) -> usize {
        let (rx, tx) = setup(os);
        let id = socket_id(&rx);
        let eff = set_socket_buffer(id, BufDir::Recv, cap, false).unwrap();
        for _ in 0..20 {
            tx.send_to(&[0u8; 100], "10.0.0.2:7000").unwrap();
        }
        let mut n = 0;
        let mut buf = [0u8; 200];
        while rx.recv_from(&mut buf).is_ok() {
            n += 1;
        }
        assert_eq!(socket_entry(id).unwrap().overflowed as usize, 20 - n);
        let _ = eff;
        n
    }

    #[test]
    fn rcvbuf_linux_overshoots_by_one_datagram() {
        let n = fill(OsSemantics::Linux, 1000);
        assert_eq!(n, 3);
    }

    #[test]
    fn rcvbuf_macos_is_exact() {
        let n = fill(OsSemantics::MacOs, 1000);
        assert_eq!(n, 10);
    }

    #[test]
    fn linux_buffer_sizes_are_doubled_and_capped() {
        let (rx, _tx) = setup(OsSemantics::Linux);
        let id = socket_id(&rx);
        assert_eq!(
            set_socket_buffer(id, BufDir::Recv, 1000, false).unwrap(),
            2304
        );
        assert_eq!(
            set_socket_buffer(id, BufDir::Recv, 4096, false).unwrap(),
            8192
        );
        assert_eq!(
            set_socket_buffer(id, BufDir::Recv, 1 << 30, false).unwrap(),
            212_992 * 2
        );
        set_privileges(|p| {
            p.root = false;
            p.net_admin = false;
        });
        let err = set_socket_buffer(id, BufDir::Recv, 1 << 20, true).unwrap_err();
        assert_eq!(crate::os_error_code(&err), Some(1));
    }

    #[test]
    fn macos_rejects_buffers_over_max_sockbuf() {
        let (rx, _tx) = setup(OsSemantics::MacOs);
        let err = set_socket_buffer(socket_id(&rx), BufDir::Send, 9_000_000, false).unwrap_err();
        assert_eq!(crate::os_error_code(&err), Some(55));
    }

    #[test]
    fn drops_at_enqueue_is_read_at_release() {
        let (rx, tx) = setup(OsSemantics::Linux);
        let id = socket_id(&rx);
        set_nic_policy("eth1", |p| p.latency = Duration::from_millis(5)).unwrap();
        tx.send_to(b"a", "10.0.0.2:7000").unwrap();
        inject_socket_drops(id, 7).unwrap();
        crate::advance_time(Duration::from_millis(5));
        crate::state::release_pending_for_udp("10.0.0.2:7000".parse().unwrap());
        let seen = crate::state::with_net(|ctx| {
            let c = ctx.udp.iter().find(|c| c.id == id).unwrap();
            c.to_local.front().map(|p| (p.drops_at_enqueue, p.at))
        });
        let (drops, _) = seen.expect("datagram released");
        assert_eq!(drops, 7);
    }
}
