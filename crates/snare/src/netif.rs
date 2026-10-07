//! The sim's interfaces, addresses, routes and link state: the host facts every backend routes the
//! code under test's traffic through. Behaviour is the host OS's; only the facts are configured.
//!
//! [`Topology`] lives in `SimShared::topology`, one mutex per sim, reached through
//! `SimShared::topo`, which ignores poisoning. Every `SimShared` method here that the test calls
//! directly runs its lock inside `snare_interpose::real`, so the lock and its allocations never
//! re-enter the hooks; the ones the hooks call (`route_send`, `fan_out`, `claim_address`,
//! `raw_send`, …) are already in passthrough. Events and the wake-up `kick` that a change implies
//! are collected in an [`After`] and issued once the topology lock is released.
//!
//! Each interface's live link is a separate [`LinkState`] behind an `Arc`, so a datagram in flight
//! or a TCP connection can watch it without the topology lock. Its own two mutexes (`downs`,
//! `schedule`) are leaves taken under or outside the topology lock, never the other way round.
//! `LinkState::apply_due` records events through `SimShared::record_ago` and may run with the
//! topology lock held, so the event log must never take the topology lock. The `Policies` locks
//! (in `netpolicy`) are likewise taken under the topology lock in [`SimShared::fan_out`].

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use crate::events::{Fault, LinkFault, RecordedEvent};
use crate::readiness::Deadline;
use crate::scope::{self, SimShared};

/// An address with a prefix length: an interface address with its subnet, or a route's
/// destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    /// The address itself; host bits are kept, so an interface address keeps its own address.
    pub addr: IpAddr,
    /// Prefix length in bits: at most 32 for IPv4, 128 for IPv6.
    pub prefix: u8,
}

/// The full prefix length of `ip`'s family: 32 or 128.
fn max_prefix(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 32 } else { 128 }
}

/// The netmask of a `prefix`-bit prefix in `ip`'s family, right-aligned in a `u128` (the low 32
/// bits for IPv4).
fn mask_bits(ip: IpAddr, prefix: u8) -> u128 {
    let width = max_prefix(ip) as u32;
    let full: u128 = if width == 32 {
        u32::MAX as u128
    } else {
        u128::MAX
    };
    if prefix == 0 {
        0
    } else {
        full & !(full.checked_shr(prefix as u32).unwrap_or(0))
    }
}

/// `ip` as an integer, right-aligned like [`mask_bits`].
fn bits(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u32::from(v4) as u128,
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// The address `value` in `like`'s family; the inverse of [`bits`].
fn from_bits(like: IpAddr, value: u128) -> IpAddr {
    match like {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(value as u32)),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(value)),
    }
}

impl IpNet {
    /// Panics when `prefix` is longer than the address.
    #[track_caller]
    pub fn new(addr: IpAddr, prefix: u8) -> Self {
        assert!(
            prefix <= max_prefix(addr),
            "prefix /{prefix} is too long for {addr}"
        );
        IpNet { addr, prefix }
    }

    /// The single address `addr` (/32 or /128).
    pub fn host(addr: IpAddr) -> Self {
        IpNet {
            addr,
            prefix: max_prefix(addr),
        }
    }

    /// The network address: `addr` with the host bits cleared.
    pub fn network(&self) -> IpAddr {
        from_bits(
            self.addr,
            bits(self.addr) & mask_bits(self.addr, self.prefix),
        )
    }

    /// Whether `ip` lies in this prefix. An address of the other family never does.
    pub fn contains(&self, ip: IpAddr) -> bool {
        if ip.is_ipv4() != self.addr.is_ipv4() {
            return false;
        }
        let mask = mask_bits(ip, self.prefix);
        bits(ip) & mask == bits(self.addr) & mask
    }

    /// The directed broadcast address of an IPv4 subnet of /30 or wider (all host bits set,
    /// RFC 919 §7, RFC 922 §7); `None` otherwise: a /31 point-to-point link has none (RFC 3021
    /// §2.2), a /32 is a single host, and IPv6 has no broadcast (RFC 4291 §2).
    pub fn broadcast(&self) -> Option<IpAddr> {
        if !self.addr.is_ipv4() || self.prefix > 30 {
            return None;
        }
        let host = !mask_bits(self.addr, self.prefix) & u32::MAX as u128;
        Some(from_bits(self.addr, bits(self.addr) | host))
    }
}

impl From<IpAddr> for IpNet {
    /// `addr` as a single-host prefix.
    fn from(addr: IpAddr) -> Self {
        IpNet::host(addr)
    }
}

impl From<Ipv4Addr> for IpNet {
    /// `addr` as a single-host prefix.
    fn from(addr: Ipv4Addr) -> Self {
        IpNet::host(addr.into())
    }
}

impl From<Ipv6Addr> for IpNet {
    /// `addr` as a single-host prefix.
    fn from(addr: Ipv6Addr) -> Self {
        IpNet::host(addr.into())
    }
}

impl fmt::Display for IpNet {
    /// `addr/prefix`, the form [`FromStr`] reads.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Why a string is not an [`IpNet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseIpNetError(String);

impl fmt::Display for ParseIpNetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid address/prefix {:?}", self.0)
    }
}

impl std::error::Error for ParseIpNetError {}

impl FromStr for IpNet {
    type Err = ParseIpNetError;

    /// `10.0.0.1/24`, `fe80::1/64`, or a bare address for a single host.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || ParseIpNetError(s.to_string());
        let (addr, prefix) = match s.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (s, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| bad())?;
        let prefix = match prefix {
            Some(p) => p.parse::<u8>().map_err(|_| bad())?,
            None => max_prefix(addr),
        };
        if prefix > max_prefix(addr) {
            return Err(bad());
        }
        Ok(IpNet { addr, prefix })
    }
}

/// How the link behind one interface treats the traffic that crosses it (host to station and
/// station to station; never host-local traffic). Delays add to and losses compound with the
/// address's [`UdpPolicy`](crate::UdpPolicy); TCP takes the latency and jitter, in order, and
/// never loses bytes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NicPolicy {
    /// How long a datagram or TCP write spends crossing the link.
    pub latency: Duration,
    /// A further delay drawn uniformly from `0..jitter` per datagram or TCP write.
    pub jitter: Duration,
    /// Probability, 0.0–1.0, that a datagram crossing the link is lost.
    pub loss_rate: f64,
    /// Probability, 0.0–1.0, that a datagram crossing the link arrives twice.
    pub duplicate_rate: f64,
}

/// One interface of the simulated host: its name, addresses, the station addresses on its
/// segment, and its link. Build with [`NicSpec::new`] and add it with
/// [`SimBuilder::nic`](crate::SimBuilder::nic) or [`add_nic`].
#[derive(Debug, Clone, PartialEq)]
pub struct NicSpec {
    /// The interface name, unique in the sim (`eth0`, `en0`, …).
    pub name: String,
    /// `None` takes the next free index.
    pub index: Option<u32>,
    /// The host's own addresses on this interface, with their subnets.
    pub addresses: Vec<IpNet>,
    /// Addresses on this interface's segment that in-process sockets may bind as stations: not
    /// the host's, never reached through a host wildcard bind, and across the link from it.
    pub stations: Vec<IpAddr>,
    /// The hardware address; `None` derives one from the index (see `NicSnapshot::hw_addr`).
    pub mac: Option<[u8; 6]>,
    /// The largest IP packet the link carries, in bytes, link header excluded.
    pub mtu: u32,
    /// Administratively up: `IFF_UP`, "interface is admin up" (Linux
    /// `Documentation/networking/operstates.rst`), what `ip link set … up/down` changes.
    pub admin_up: bool,
    /// The link has carrier: Linux's `IFF_LOWER_UP`, "driver has signaled netif_carrier_on()",
    /// and with `admin_up` also `IFF_RUNNING` (`Documentation/networking/operstates.rst`).
    pub carrier: bool,
    /// The link speed reported by the speed queries (`ethtool`, macOS `ifi_baudrate`); `None`
    /// for an interface with no fixed speed, such as loopback.
    pub speed_mbps: Option<u32>,
    /// Windows NDIS physical-medium metadata; `None` reports 802.3 (14), or unspecified (0)
    /// for loopback. This is independent of the interface's Ethernet media type.
    pub physical_medium: Option<i32>,
    /// How the link delays, loses and duplicates what crosses it.
    pub policy: NicPolicy,
}

impl NicSpec {
    /// An Ethernet interface that is up with carrier, MTU 1500 (the Ethernet MTU, RFC 894),
    /// 1000 Mb/s (a snare default: a common gigabit NIC), no addresses.
    pub fn new(name: impl Into<String>) -> Self {
        NicSpec {
            name: name.into(),
            index: None,
            addresses: Vec::new(),
            stations: Vec::new(),
            mac: None,
            mtu: 1500,
            admin_up: true,
            carrier: true,
            speed_mbps: Some(1000),
            physical_medium: None,
            policy: NicPolicy::default(),
        }
    }

    /// Adds a host address with its subnet; a bare address is a /32 or /128.
    pub fn address(mut self, net: impl Into<IpNet>) -> Self {
        self.addresses.push(net.into());
        self
    }

    /// Adds a station address on this interface's segment (see [`NicSpec::stations`]).
    pub fn station(mut self, ip: impl Into<IpAddr>) -> Self {
        self.stations.push(ip.into());
        self
    }

    /// Asks for interface index `index` (1 or more; 0 is never an interface, RFC 3493 §4).
    pub fn index(mut self, index: u32) -> Self {
        self.index = Some(index);
        self
    }

    /// Sets the MTU in bytes.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }

    /// Sets the hardware address.
    pub fn mac(mut self, mac: [u8; 6]) -> Self {
        self.mac = Some(mac);
        self
    }

    /// Whether the link has carrier.
    pub fn link(mut self, carrier: bool) -> Self {
        self.carrier = carrier;
        self
    }

    /// Sets the Windows NDIS physical-medium value reported by IP Helper.
    pub fn physical_medium(mut self, physical_medium: i32) -> Self {
        self.physical_medium = Some(physical_medium);
        self
    }

    /// Sets the link policy.
    pub fn policy(mut self, policy: NicPolicy) -> Self {
        self.policy = policy;
        self
    }
}

/// A route: traffic to `dest` leaves through `nic`, to `gateway` when it is off-link, from `src`
/// when the socket did not choose one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The destination prefix; `/0` is a default route.
    pub dest: IpNet,
    /// The egress interface's name.
    pub nic: String,
    /// The next hop; `None` for an on-link destination.
    pub gateway: Option<IpAddr>,
    /// The preferred source address, like `ip route … src` (man 8 ip-route, `src`).
    pub src: Option<IpAddr>,
    /// Among routes of equal prefix length, the lower metric wins.
    pub metric: u32,
}

impl Route {
    /// An on-link route to `dest` through `nic`, metric 0, no preferred source.
    pub fn new(dest: impl Into<IpNet>, nic: impl Into<String>) -> Self {
        Route {
            dest: dest.into(),
            nic: nic.into(),
            gateway: None,
            src: None,
            metric: 0,
        }
    }

    /// Sends through next hop `gateway`.
    pub fn gateway(mut self, gateway: impl Into<IpAddr>) -> Self {
        self.gateway = Some(gateway.into());
        self
    }

    /// Prefers source address `src` for sockets that did not bind one.
    pub fn src(mut self, src: impl Into<IpAddr>) -> Self {
        self.src = Some(src.into());
        self
    }

    /// Sets the metric.
    pub fn metric(mut self, metric: u32) -> Self {
        self.metric = metric;
        self
    }
}

/// Where [`route_lookup`] sends traffic: the interface, the source address it would carry and
/// the next hop when it is not on-link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteChoice {
    /// The egress interface's name.
    pub nic: String,
    /// The egress interface's index.
    pub index: u32,
    /// The source address the traffic would carry.
    pub src: Option<IpAddr>,
    /// The next hop; `None` when the destination is on-link.
    pub gateway: Option<IpAddr>,
}

/// An interface's traffic counters. Frames count their Ethernet, IP and transport headers. The
/// fields are those of Linux's `struct rtnl_link_stats` (`include/uapi/linux/if_link.h`), which
/// `getifaddrs`, netlink and sysfs report; macOS's `struct if_data` (`<net/if_var.h>`) shows the
/// subset it has. The sim bumps `tx_carrier_errors` (if_link.h: "frame transmission errors due
/// to loss of carrier") for each frame sent while the link had no carrier, alongside
/// `tx_dropped`. It never sets `rx_errors`, `tx_errors` or `rx_nohandler` (if_link.h: received
/// "but dropped by the networking stack because the device is not designated to receive
/// packets"); only [`set_nic_counters`] does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
    pub tx_carrier_errors: u64,
    pub rx_nohandler: u64,
}

/// One interface as it is now.
#[derive(Debug, Clone)]
pub struct NicSnapshot {
    /// The interface index.
    pub index: u32,
    /// The interface as configured, with `index` filled in and `admin_up`/`carrier` showing the
    /// live link (scheduled transitions applied).
    pub spec: NicSpec,
    /// The counters now.
    pub counters: NicCounters,
    /// Whether this is the loopback interface.
    pub loopback: bool,
}

impl NicSnapshot {
    /// The configured Windows NDIS physical medium, or the interface's default.
    pub fn physical_medium(&self) -> i32 {
        self.spec
            .physical_medium
            .unwrap_or(if self.loopback { 0 } else { 14 })
    }

    /// The hardware address: the configured one, `02:00:<index, big-endian>` otherwise, and all
    /// zeros on loopback. `0x02` in the first octet is the Local bit with the Group bit clear: a
    /// locally administered unicast address that cannot collide with a vendor-assigned one
    /// (RFC 7042 §2.1).
    pub(crate) fn hw_addr(&self) -> [u8; 6] {
        if self.loopback {
            return [0; 6];
        }
        self.spec.mac.unwrap_or_else(|| {
            let i = self.index.to_be_bytes();
            [0x02, 0x00, i[0], i[1], i[2], i[3]]
        })
    }

    /// Administratively up with carrier.
    pub(crate) fn running(&self) -> bool {
        self.spec.admin_up && self.spec.carrier
    }
}

/// The host's error codes for routing decisions: the platform's `errno` values (`<errno.h>`).
#[cfg(unix)]
pub(crate) mod code {
    pub(crate) const ENETUNREACH: i32 = libc::ENETUNREACH;
    pub(crate) const EHOSTUNREACH: i32 = libc::EHOSTUNREACH;
    pub(crate) const EADDRNOTAVAIL: i32 = libc::EADDRNOTAVAIL;
    pub(crate) const ENETDOWN: i32 = libc::ENETDOWN;
    pub(crate) const EACCES: i32 = libc::EACCES;
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) const EINVAL: i32 = libc::EINVAL;
}

/// Winsock codes (`<winerror.h>`) under their errno names, so the routing code reads the same on
/// every platform
/// ([Microsoft Learn: Windows Sockets Error Codes](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2)).
#[cfg(windows)]
pub(crate) mod code {
    /// `WSAENETUNREACH`.
    pub(crate) const ENETUNREACH: i32 = 10051;
    /// `WSAEHOSTUNREACH`.
    pub(crate) const EHOSTUNREACH: i32 = 10065;
    /// `WSAEADDRNOTAVAIL`.
    pub(crate) const EADDRNOTAVAIL: i32 = 10049;
    /// `WSAENETDOWN`.
    pub(crate) const ENETDOWN: i32 = 10050;
    /// `WSAEACCES`.
    pub(crate) const EACCES: i32 = 10013;
    /// `WSAEINVAL`.
    #[allow(dead_code)]
    pub(crate) const EINVAL: i32 = 10022;
}

/// The name, MTU and index of the loopback interface on the build host. Linux: `lo`, MTU 65536
/// (`drivers/net/loopback.c`, `loopback_setup` passes `64 * 1024`), index 1 (`LOOPBACK_IFINDEX`,
/// `include/net/flow.h`). macOS: `lo0`, MTU 16384 (`LOMTU`, `bsd/net/if_loop.c`). Windows: the
/// name and the `u32::MAX` MTU that Windows reports for its loopback interface; pinned only
/// against the sim by `nic_routing.rs` `default_topology_has_lo_and_sim0`. snare puts it at index
/// 1 on every platform (a host snapshot may move it, see `Topology::make_room`). It holds
/// 127.0.0.1/8 (127/8 is loopback, RFC 1122 §3.2.1.3) and ::1 (RFC 4291 §2.5.3).
fn loopback_spec() -> NicSpec {
    let (name, mtu) = if cfg!(target_os = "linux") {
        ("lo", 65536)
    } else if cfg!(target_os = "macos") {
        ("lo0", 16384)
    } else {
        ("Loopback Pseudo-Interface 1", u32::MAX)
    };
    let mut spec = NicSpec::new(name).index(1).mtu(mtu);
    spec.addresses = vec![
        IpNet::new(Ipv4Addr::LOCALHOST.into(), 8),
        IpNet::host(Ipv6Addr::LOCALHOST.into()),
    ];
    spec.speed_mbps = None;
    spec
}

struct LinkTransition {
    at: Deadline,
    carrier: bool,
    #[cfg(windows)]
    restart: Option<RestartTransition>,
}

#[cfg(windows)]
struct RestartTransition {
    generation: Arc<Mutex<u64>>,
    epoch: u64,
    timer: Option<u64>,
}

/// The live link of one interface, shared with what crosses it (a datagram in flight, a TCP
/// connection) so they see flaps without reaching back into the topology.
///
/// The flags are atomics read with `Acquire` and written with `Release`/`AcqRel`; a reader may see
/// `admin_up` and `carrier` from two different moments, which only matters to a racing reader and
/// matches a real interface changing under it. Every reader that cares about scheduled changes
/// calls [`apply_due`](Self::apply_due) first.
pub(crate) struct LinkState {
    /// The interface name, for the events this records.
    name: String,
    admin_up: AtomicBool,
    carrier: AtomicBool,
    /// The interface has been removed. Terminal: never cleared.
    removed: AtomicBool,
    /// When each loss of the link happened, on the deadline clock; its length is the link's
    /// down epoch.
    downs: Mutex<Vec<Duration>>,
    #[cfg(target_os = "macos")]
    delivery_holds: Mutex<Vec<(Duration, Option<Duration>)>>,
    /// Carrier transitions still to come, `(when, carrier)`, kept sorted by deadline with equal
    /// deadlines in the order they were scheduled.
    schedule: Mutex<VecDeque<LinkTransition>>,
    /// The sim, for recording transitions. Weak because the sim owns the topology that owns this.
    shared: Weak<SimShared>,
}

impl LinkState {
    /// The link of `spec` as configured, with nothing scheduled.
    fn new(spec: &NicSpec, shared: Weak<SimShared>) -> Self {
        LinkState {
            name: spec.name.clone(),
            admin_up: AtomicBool::new(spec.admin_up),
            carrier: AtomicBool::new(spec.carrier),
            removed: AtomicBool::new(false),
            downs: Mutex::default(),
            #[cfg(target_os = "macos")]
            delivery_holds: Mutex::new(if spec.admin_up && spec.carrier {
                Vec::new()
            } else {
                vec![(Duration::ZERO, None)]
            }),
            schedule: Mutex::default(),
            shared,
        }
    }

    /// Up with carrier, without applying due transitions.
    fn up(&self) -> bool {
        self.admin_up.load(Ordering::Acquire) && self.carrier.load(Ordering::Acquire)
    }

    /// Changes admin state and carrier, noting when the link goes down at `at` (a time on the
    /// deadline clock). Returns whether anything changed. Only an up-to-down edge starts a new
    /// down epoch; going from admin-down to carrier-less does not.
    fn set(&self, admin: Option<bool>, carrier: Option<bool>, at: Duration) -> bool {
        #[cfg(target_os = "macos")]
        let mut holds = self.delivery_holds.lock().unwrap();
        let was = self.up();
        let mut changed = false;
        if let Some(admin) = admin {
            changed |= self.admin_up.swap(admin, Ordering::AcqRel) != admin;
        }
        if let Some(carrier) = carrier {
            changed |= self.carrier.swap(carrier, Ordering::AcqRel) != carrier;
        }
        if was && !self.up() {
            self.downs.lock().unwrap().push(at);
            #[cfg(target_os = "macos")]
            holds.push((at, None));
        }
        #[cfg(target_os = "macos")]
        if !was
            && self.up()
            && let Some((_, until)) = holds.last_mut()
        {
            *until = Some(at);
        }
        changed
    }

    /// Applies every scheduled transition whose time has come, each at its own deadline (so a
    /// late check still dates the loss of the link correctly) and records the ones that changed
    /// something, dated back by how overdue they are. Never wakes anything: the transition's own
    /// deadline already did. Takes `schedule`, releases it, then `downs`; may run under the
    /// topology lock.
    fn apply_due(&self) {
        #[cfg(target_os = "macos")]
        let shared = self.shared.upgrade();
        #[cfg(target_os = "macos")]
        let clock = shared.as_ref().and_then(|shared| shared.clock.as_deref());
        let due: Vec<LinkTransition> = {
            let mut schedule = self.schedule.lock().unwrap();
            let mut due = Vec::new();
            while schedule.front().is_some_and(|change| {
                #[cfg(target_os = "macos")]
                {
                    change.at.passed_on(clock)
                }
                #[cfg(not(target_os = "macos"))]
                {
                    change.at.passed()
                }
            }) {
                due.push(schedule.pop_front().expect("transition"));
            }
            due
        };
        for change in due {
            #[cfg(windows)]
            let generation = change
                .restart
                .as_ref()
                .map(|restart| restart.generation.lock().unwrap_or_else(|e| e.into_inner()));
            #[cfg(windows)]
            if change
                .restart
                .as_ref()
                .zip(generation.as_ref())
                .is_some_and(|(restart, generation)| restart.epoch != **generation)
            {
                continue;
            }
            let (at, carrier) = (change.at, change.carrier);
            let changed = self.set(None, Some(carrier), at.instant());
            #[cfg(windows)]
            drop(generation);
            if changed && let Some(shared) = self.shared.upgrade() {
                #[cfg(target_os = "macos")]
                let ago = shared
                    .stamp()
                    .saturating_sub(at.timeline_at(shared.real_origin(), shared.clock.as_deref()));
                #[cfg(not(target_os = "macos"))]
                let ago = at.overdue();
                shared.record_ago(
                    ago,
                    RecordedEvent::NicChanged {
                        nic: self.name.clone(),
                        admin_up: self.admin_up.load(Ordering::Acquire),
                        carrier,
                    },
                );
            }
        }
    }

    /// Whether frames cross the link now: administratively up with carrier.
    pub(crate) fn usable(&self) -> bool {
        self.apply_due();
        self.up()
    }

    /// Administratively up, due transitions applied.
    fn admin(&self) -> bool {
        self.apply_due();
        self.admin_up.load(Ordering::Acquire)
    }

    /// Whether stalled TCP bytes may move: the link is usable, or its interface is gone.
    pub(crate) fn releases(&self) -> bool {
        self.removed.load(Ordering::Acquire) || self.usable()
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn effective_arrival(&self, mut at: Deadline) -> Deadline {
        self.apply_due();
        for &(since, until) in self.delivery_holds.lock().unwrap().iter() {
            if since > at.instant() {
                break;
            }
            if let Some(until) = until
                && until > at.instant()
            {
                at = at.later(until.saturating_sub(at.instant()));
            }
        }
        at
    }

    #[cfg(target_os = "macos")]
    fn remove(&self, at: Duration) {
        self.set(Some(false), Some(false), at);
        let mut holds = self.delivery_holds.lock().unwrap();
        if let Some((_, until)) = holds.last_mut() {
            *until = Some(at);
        }
        self.removed.store(true, Ordering::Release);
    }

    /// How many times the link has gone down: a datagram stamps the epoch at send and compares
    /// it in [`lost_in_flight`](Self::lost_in_flight).
    pub(crate) fn epoch(&self) -> u64 {
        self.apply_due();
        self.downs.lock().unwrap().len() as u64
    }

    /// Whether a datagram sent at `epoch` and due to arrive at `arrival` (deadline clock) was in
    /// flight when the link went down: a loss after that epoch and before its arrival. A frame on
    /// a wire that loses carrier is gone; the sim does not requeue it.
    pub(crate) fn lost_in_flight(&self, epoch: u64, arrival: Duration) -> bool {
        self.apply_due();
        let downs = self.downs.lock().unwrap();
        downs
            .iter()
            .skip(epoch as usize)
            .any(|&down| down < arrival)
    }
}

/// How an interface address came to be there.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Origin {
    /// Configured by the test.
    Explicit,
    /// Claimed by a bind while the sim was open.
    Auto,
}

/// One interface in the topology.
struct NicRec {
    index: u32,
    name: Arc<str>,
    /// The configuration. `admin_up` and `carrier` here are stale: `link` is the truth.
    spec: NicSpec,
    loopback: bool,
    link: Arc<LinkState>,
    counters: NicCounters,
    /// Where each of `spec.addresses` came from. Auto-claimed addresses do not close an open sim
    /// when `set_nic` keeps them.
    origins: HashMap<IpAddr, Origin>,
}

impl NicRec {
    /// The interface as the test sees it, with its live link state.
    fn snapshot(&self) -> NicSnapshot {
        let mut spec = self.spec.clone();
        spec.index = Some(self.index);
        spec.admin_up = self.link.admin();
        spec.carrier = self.link.carrier.load(Ordering::Acquire);
        NicSnapshot {
            index: self.index,
            spec,
            counters: self.counters,
            loopback: self.loopback,
        }
    }

    /// Whether `ip` is one of the interface's addresses. Loopback owns every loopback address
    /// (all of 127/8 and ::1), not only the configured ones, as Linux's local route for 127/8 on
    /// `lo` makes the whole block local.
    fn has_address(&self, ip: IpAddr) -> bool {
        if self.loopback && ip.is_loopback() {
            return true;
        }
        self.spec.addresses.iter().any(|net| net.addr == ip)
    }

    /// Whether the host may use the interface's addresses as its own: Windows withdraws them with
    /// carrier (media sense: "whenever Windows detects a 'down' state, it removes the bound
    /// protocols from that adapter", [Microsoft Learn: Disable Media Sensing feature for TCP/IP,
    /// KB 239924](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-media-sensing-feature-for-tcpip));
    /// the resulting `WSAEADDRNOTAVAIL` bind is pinned only against the sim, by `nic_os_truth.rs`
    /// `windows_strong_host_and_media_sense`. Linux and macOS keep them while the interface is
    /// down (measured on Linux by `nic_os_truth.rs` `linux_netns_ground_truth`: a bind there still
    /// succeeds; macOS follows the same rule, pinned only by `nic_link.rs` `admin_down_errnos`
    /// against the sim).
    fn addresses_live(&self) -> bool {
        !cfg!(windows) || self.link.usable()
    }

    /// Whether the interface's routes are in the table: Linux and macOS keep them until the
    /// interface goes down, Windows withdraws them with carrier. Linux removes them on
    /// `NETDEV_DOWN` (`net/ipv4/fib_frontend.c`, `fib_netdev_event` → `fib_disable_ip`; measured
    /// by `linux_netns_ground_truth`) and keeps using them without carrier
    /// (`ignore_routes_with_linkdown` defaults to 0, Documentation/networking/ip-sysctl.rst).
    /// Windows invalidates them on a media disconnect (KB 239924, as for
    /// [`addresses_live`](Self::addresses_live)); the `WSAENETUNREACH` that follows is pinned only
    /// against the sim by `windows_strong_host_and_media_sense`. macOS is assumed to follow Linux,
    /// unmeasured. A removed interface has none.
    fn routes_live(&self) -> bool {
        if self.link.removed.load(Ordering::Acquire) {
            return false;
        }
        if cfg!(windows) {
            self.link.usable()
        } else {
            self.link.admin()
        }
    }

    /// The interface's address in `dst`'s family to send from, preferring one on `dst`'s
    /// subnet, else its first. A simplification of RFC 6724 §5 source selection (rule 8, longest
    /// matching prefix, reduced to "on the subnet").
    fn source_for(&self, dst: IpAddr) -> Option<IpAddr> {
        let family = self
            .spec
            .addresses
            .iter()
            .filter(|net| net.addr.is_ipv4() == dst.is_ipv4());
        let mut first = None;
        for net in family {
            if net.contains(dst) {
                return Some(net.addr);
            }
            first.get_or_insert(net.addr);
        }
        first
    }
}

/// Which way a frame crossed an interface.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dir {
    /// Sent by the host.
    Tx,
    /// Received by the host.
    Rx,
}

/// Whether a route lookup is for a datagram send or a connect: macOS answers a missing route
/// differently for each.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    /// A datagram `sendto`/`send`.
    Send,
    /// A `connect`, or a route query that stands for one.
    Connect,
}

/// What a socket contributes to its route lookup.
#[derive(Clone, Copy, Default)]
pub(crate) struct SockView {
    /// The bound address, if bound (possibly the wildcard).
    pub(crate) local: Option<SocketAddr>,
    /// The interface index the socket is bound to: Linux `SO_BINDTODEVICE`/`SO_BINDTOIFINDEX`,
    /// macOS `IP_BOUND_IF`/`IPV6_BOUND_IF`, Windows `IP_UNICAST_IF`/`IPV6_UNICAST_IF`.
    pub(crate) device: Option<u32>,
    /// The interface index of `IP_MULTICAST_IF`/`IPV6_MULTICAST_IF`.
    pub(crate) mcast_if: Option<u32>,
}

/// The way out for one send.
#[derive(Clone)]
pub(crate) struct Path {
    /// The egress interface's index (loopback's for `local`).
    pub(crate) egress: u32,
    /// The egress interface's name.
    pub(crate) name: Arc<str>,
    /// The source address a wildcard-bound socket's traffic carries.
    pub(crate) src: IpAddr,
    /// The next hop, when the route has one.
    pub(crate) gateway: Option<IpAddr>,
    /// The egress interface's link.
    pub(crate) link: Arc<LinkState>,
    /// Delivered to the host itself, through the loopback interface.
    pub(crate) local: bool,
}

/// Who sent a datagram: the host, through the path its route lookup chose, or a station on a
/// segment (a tester, or a socket bound at a station address).
#[derive(Clone)]
pub(crate) enum Sender {
    /// A socket of the host, leaving along the path its route lookup chose.
    Host(Path),
    /// A socket bound at this station address.
    Station(IpAddr),
}

impl Sender {
    /// The source address the datagram carries from a socket bound at `local`.
    pub(crate) fn source(&self, local: SocketAddr) -> SocketAddr {
        match self {
            Sender::Host(path) if local.ip().is_unspecified() => {
                SocketAddr::new(path.src, local.port())
            }
            _ => local,
        }
    }

    /// Where a datagram socket bound at `local` stands once it connects along this route: a
    /// wildcard bind takes the route's source address, v4-mapped on an IPv6 socket (Linux
    /// `ip4_datagram_connect`, net/ipv4/datagram.c, and `ip6_datagram_dst_update`,
    /// net/ipv6/datagram.c; macOS `in_pcbconnect`, bsd/netinet/in_pcb.c; and Winsock alike, as
    /// measured by tests/udp_connect_source.rs).
    pub(crate) fn connected_local(&self, local: SocketAddr) -> SocketAddr {
        let src = self.source(local);
        match (src.ip(), local) {
            (IpAddr::V4(v4), SocketAddr::V6(_)) => {
                SocketAddr::new(v4.to_ipv6_mapped().into(), local.port())
            }
            (IpAddr::V6(_), SocketAddr::V4(_)) => local,
            _ => src,
        }
    }

    /// The interface a host datagram leaves through; `None` for a station.
    pub(crate) fn egress_name(&self) -> Option<&str> {
        match self {
            Sender::Host(path) => Some(&path.name),
            Sender::Station(_) => None,
        }
    }
}

/// A socket a datagram could be delivered to.
pub(crate) struct Cand<Q> {
    /// The address the socket is bound at.
    pub(crate) addr: SocketAddr,
    /// A tester's endpoint: a station of its own unless it sits at a host address.
    pub(crate) endpoint: bool,
    /// The interface the socket is bound to (see [`SockView::device`]).
    pub(crate) device: Option<u32>,
    /// The backend's handle on the socket's receive queue, passed through untouched.
    pub(crate) q: Q,
}

/// One recipient's copies of a datagram; none when the link lost it on the way.
pub(crate) struct Copy<Q> {
    /// The recipient's queue handle, from its [`Cand`].
    pub(crate) q: Q,
    /// One delay per copy that arrives: empty when lost, two when duplicated.
    pub(crate) delays: crate::netpolicy::Delays,
    /// The link the datagram crosses and its down epoch at send, for
    /// [`LinkState::lost_in_flight`] at arrival; `None` when it crosses no interface.
    pub(crate) via: Option<(Arc<LinkState>, u64)>,
    /// The interface it arrived on, for a socket of the host.
    pub(crate) nic: Option<Arc<str>>,
    /// The smallest MTU of the interfaces it crosses (the sender's egress, the link, the
    /// recipient's ingress), `None` when it crosses none: a datagram longer than its packets may
    /// be crossed as IP fragments, which the receiver charges one buffer each
    /// ([`crate::limits::linux_truesize_fragmented`]).
    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) mtu: Option<u32>,
}

/// One datagram on the wire: from, to and payload length.
#[derive(Clone, Copy)]
pub(crate) struct Wire {
    pub(crate) src: SocketAddr,
    pub(crate) dest: SocketAddr,
    pub(crate) len: usize,
}

/// A TCP connection's crossing of an interface.
#[derive(Clone)]
pub(crate) struct Hop {
    /// The interface's index.
    pub(crate) index: u32,
    /// The interface's link: bytes stall while it is down.
    pub(crate) link: Arc<LinkState>,
}

/// What kind of address a datagram is sent to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DestKind {
    Unicast,
    /// 255.255.255.255, the limited broadcast (RFC 919 §7; RFC 1122 §3.2.1.3).
    Limited,
    /// The directed broadcast address of this host subnet.
    Directed(IpNet),
    Multicast,
}

/// How well a route matches: prefix length, then the preferred interface, then a low metric.
type Rank = (u8, bool, std::cmp::Reverse<u32>);

/// The interfaces and routes of one sim.
pub(crate) struct Topology {
    /// Every interface, loopback included, kept sorted by index.
    nics: Vec<NicRec>,
    /// The configured routes, in the order added. The connected routes are derived on demand
    /// ([`all_routes`](Self::all_routes)).
    routes: Vec<Route>,
    /// No interface has been given an address yet: binding any address claims it for the host.
    open: bool,
    /// The index of the default `sim0` interface while it exists, where an open sim's claimed
    /// addresses go.
    sim0: Option<u32>,
    /// The sim, handed to each new [`LinkState`].
    shared: Weak<SimShared>,
}

impl Topology {
    /// A topology holding only the loopback interface at index 1, open.
    pub(crate) fn new(shared: Weak<SimShared>) -> Self {
        let lo = loopback_spec();
        let link = Arc::new(LinkState::new(&lo, shared.clone()));
        Topology {
            nics: vec![NicRec {
                index: 1,
                name: Arc::from(lo.name.as_str()),
                origins: lo
                    .addresses
                    .iter()
                    .map(|n| (n.addr, Origin::Explicit))
                    .collect(),
                spec: lo,
                loopback: true,
                link,
                counters: NicCounters::default(),
            }],
            routes: Vec::new(),
            open: true,
            sim0: None,
            shared,
        }
    }

    /// The loopback interface, which always exists.
    fn lo(&self) -> &NicRec {
        self.nics
            .iter()
            .find(|n| n.loopback)
            .expect("loopback interface")
    }

    /// The interface at `index`.
    fn nic(&self, index: u32) -> Option<&NicRec> {
        self.nics.iter().find(|n| n.index == index)
    }

    /// The interface at `index`, mutably.
    fn nic_mut(&mut self, index: u32) -> Option<&mut NicRec> {
        self.nics.iter_mut().find(|n| n.index == index)
    }

    /// The interface named `name`.
    fn by_name(&self, name: &str) -> Option<&NicRec> {
        self.nics.iter().find(|n| n.spec.name == name)
    }

    /// The lowest unused index from `from` on.
    fn free_index(&self, from: u32) -> u32 {
        (from..)
            .find(|i| self.nic(*i).is_none())
            .expect("a free interface index")
    }

    /// The name of interface `index`, as `if_indextoname` reports it.
    pub(crate) fn name_of(&self, index: u32) -> Option<String> {
        self.nic(index).map(|n| n.spec.name.clone())
    }

    /// The index of interface `name`, as `if_nametoindex` reports it.
    pub(crate) fn index_of(&self, name: &str) -> Option<u32> {
        self.by_name(name).map(|n| n.index)
    }

    /// The index of the interface that holds `ip`, configured or claimed, live or not.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn index_of_address(&self, ip: IpAddr) -> Option<u32> {
        self.owner(ip).map(|n| n.index)
    }

    /// The loopback interface's index: 1 unless a host interface took it.
    pub(crate) fn loopback_index(&self) -> u32 {
        self.lo().index
    }

    /// The interface whose segment `ip` sits on; see [`segment`](Self::segment).
    pub(crate) fn segment_of(&self, ip: IpAddr) -> Option<u32> {
        self.segment(ip)
    }

    /// Interface `index`'s name and MTU, and whether it is loopback.
    pub(crate) fn wire_of(&self, index: u32) -> Option<(String, u32, bool)> {
        self.nic(index)
            .map(|n| (n.spec.name.clone(), n.spec.mtu, n.loopback))
    }

    /// The hardware address of the interface that owns `ip`, a host address; loopback has none.
    /// Derived as [`NicSnapshot::hw_addr`] derives it.
    pub(crate) fn mac_of(&self, ip: IpAddr) -> Option<[u8; 6]> {
        let nic = self
            .nics
            .iter()
            .find(|n| !n.loopback && n.has_address(ip))?;
        Some(nic.spec.mac.unwrap_or_else(|| {
            let i = nic.index.to_be_bytes();
            [0x02, 0x00, i[0], i[1], i[2], i[3]]
        }))
    }

    /// Interface `index`'s MTU.
    pub(crate) fn mtu_of(&self, index: u32) -> Option<u32> {
        self.nic(index).map(|n| n.spec.mtu)
    }

    /// Interface `index`'s live link.
    pub(crate) fn link_of(&self, index: u32) -> Option<Arc<LinkState>> {
        self.nic(index).map(|n| n.link.clone())
    }

    /// Adds a non-loopback interface. Refuses a taken name or index and index 0, which is never
    /// an interface (RFC 3493 §4: indexes start at 1); with no index asked for, takes the lowest
    /// free one from 2, since 1 is loopback's. An interface with addresses closes the open sim.
    fn insert(&mut self, mut spec: NicSpec, counters: NicCounters) -> io::Result<u32> {
        if self.by_name(&spec.name).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("an interface named {} exists", spec.name),
            ));
        }
        let index = match spec.index {
            Some(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "interface index 0 is reserved",
                ));
            }
            Some(index) if self.nic(index).is_some() => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("interface index {index} is taken"),
                ));
            }
            Some(index) => index,
            None => self.free_index(2),
        };
        spec.index = Some(index);
        if !spec.addresses.is_empty() {
            self.open = false;
        }
        let link = Arc::new(LinkState::new(&spec, self.shared.clone()));
        self.nics.push(NicRec {
            index,
            name: Arc::from(spec.name.as_str()),
            origins: spec
                .addresses
                .iter()
                .map(|n| (n.addr, Origin::Explicit))
                .collect(),
            spec,
            loopback: false,
            link,
            counters,
        });
        self.nics.sort_by_key(|n| n.index);
        Ok(index)
    }

    /// Moves the loopback interface off `index`, for a host that declares an interface there (a
    /// host snapshot whose loopback is not at 1, such as Windows, where it often is not). Loopback
    /// takes the lowest free index above `index`.
    fn make_room(&mut self, index: u32) {
        if self.lo().index == index {
            let free = self.free_index(2).max(index + 1);
            let free = (free..)
                .find(|i| self.nic(*i).is_none())
                .expect("free index");
            if let Some(lo) = self.nics.iter_mut().find(|n| n.loopback) {
                lo.index = free;
                lo.spec.index = Some(free);
            }
            self.nics.sort_by_key(|n| n.index);
        }
    }

    /// Every route: the connected subnet of each interface address, then the configured ones. The
    /// connected routes stand for the prefix route the kernel adds with an address (Linux
    /// `fib_add_ifaddr`, `net/ipv4/fib_frontend.c`); a /32 or /128 address adds none, and
    /// loopback's are left out since local delivery never consults the table here.
    fn all_routes(&self) -> Vec<Route> {
        let mut out = Vec::new();
        for nic in self.nics.iter().filter(|n| !n.loopback) {
            for net in &nic.spec.addresses {
                if net.prefix < max_prefix(net.addr) {
                    out.push(Route {
                        dest: IpNet::new(net.network(), net.prefix),
                        nic: nic.spec.name.clone(),
                        gateway: None,
                        src: Some(net.addr),
                        metric: 0,
                    });
                }
            }
        }
        out.extend(self.routes.iter().cloned());
        out
    }

    /// The longest-prefix route to `dst` through an interface `usable` accepts, preferring the
    /// interface `prefer`, then the lowest metric, then the earliest route (connected routes come
    /// before configured ones). Preferring the interface that holds the socket's bound address is
    /// a snare tie-break, not an OS rule, pinned by `nic_routing.rs`
    /// `longest_prefix_then_owner_then_metric_then_order`; Windows narrows further in
    /// [`egress`](Self::egress).
    fn lpm(
        &self,
        dst: IpAddr,
        usable: impl Fn(&NicRec) -> bool,
        prefer: Option<u32>,
    ) -> Option<(Route, u32)> {
        let mut best: Option<(Route, u32, Rank)> = None;
        for route in self.all_routes() {
            if !route.dest.contains(dst) {
                continue;
            }
            let Some(nic) = self.by_name(&route.nic) else {
                continue;
            };
            if !usable(nic) {
                continue;
            }
            let key = (
                route.dest.prefix,
                prefer == Some(nic.index),
                std::cmp::Reverse(route.metric),
            );
            if best.as_ref().is_none_or(|(_, _, k)| key > *k) {
                best = Some((route, nic.index, key));
            }
        }
        best.map(|(route, index, _)| (route, index))
    }

    /// The interface holding `ip` (loopback for any loopback address), live or not.
    fn owner(&self, ip: IpAddr) -> Option<&NicRec> {
        self.nics.iter().find(|n| n.has_address(ip))
    }

    /// Whether `ip` is one of the host's own addresses now.
    pub(crate) fn is_host(&self, ip: IpAddr) -> bool {
        if ip.is_loopback() {
            return true;
        }
        self.owner(ip).is_some_and(NicRec::addresses_live)
    }

    /// Whether `ip` is a configured station address on some segment.
    pub(crate) fn is_station_ip(&self, ip: IpAddr) -> bool {
        self.nics.iter().any(|n| n.spec.stations.contains(&ip))
    }

    /// The interface whose segment `ip` sits on: the one listing it as a station, else the one
    /// the longest-prefix route to it leaves through (down interfaces included, removed ones not).
    fn segment(&self, ip: IpAddr) -> Option<u32> {
        if let Some(nic) = self.nics.iter().find(|n| n.spec.stations.contains(&ip)) {
            return Some(nic.index);
        }
        self.lpm(ip, |n| !n.link.removed.load(Ordering::Acquire), None)
            .map(|(_, index)| index)
    }

    /// Classifies `ip` as a destination. A directed broadcast is recognised only for the host's
    /// own subnets.
    fn dest_kind(&self, ip: IpAddr) -> DestKind {
        if ip.is_multicast() {
            return DestKind::Multicast;
        }
        if ip == IpAddr::V4(Ipv4Addr::BROADCAST) {
            return DestKind::Limited;
        }
        for nic in &self.nics {
            for net in &nic.spec.addresses {
                if net.broadcast() == Some(ip) {
                    return DestKind::Directed(*net);
                }
            }
        }
        DestKind::Unicast
    }

    /// Whether `ip` is the limited broadcast or a directed broadcast of a host subnet.
    pub(crate) fn is_broadcast(&self, ip: IpAddr) -> bool {
        matches!(
            self.dest_kind(ip),
            DestKind::Limited | DestKind::Directed(_)
        )
    }

    /// The host's own address of `dst`'s family to send from when the egress interface has
    /// none: any other interface's, else loopback.
    fn fallback_source(&self, dst: IpAddr) -> IpAddr {
        self.nics
            .iter()
            .filter(|n| !n.loopback && n.addresses_live())
            .find_map(|n| n.source_for(dst))
            .unwrap_or(match dst {
                IpAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
                IpAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
            })
    }

    /// The [`Path`] out through `nic`.
    fn path(&self, nic: &NicRec, src: IpAddr, gateway: Option<IpAddr>, local: bool) -> Path {
        Path {
            egress: nic.index,
            name: nic.name.clone(),
            src,
            gateway,
            link: nic.link.clone(),
            local,
        }
    }

    /// The errno for a destination no route covers. macOS: a send from a specific address fails
    /// in `ip_output` with `EHOSTUNREACH` (`bsd/netinet/ip_output.c`, the `ro->ro_rt == NULL`
    /// case), one from the wildcard with `ENETUNREACH` while `in_pcbladdr` picks its source
    /// (`bsd/netinet/in_pcb.c`). Linux and Windows answer `ENETUNREACH`/`WSAENETUNREACH` for both
    /// (Linux: `fib_lookup` fails with `-ENETUNREACH`, `net/ipv4/fib_rules.c` `__fib_lookup`, and
    /// `ip_route_output_key_hash_rcu` passes it on, `net/ipv4/route.c`). Pinned by
    /// `nic_routing.rs` `no_route_errno` against the sim.
    fn no_route(op: Op, bound: bool) -> i32 {
        if cfg!(target_os = "macos") && op == Op::Send && bound {
            code::EHOSTUNREACH
        } else {
            code::ENETUNREACH
        }
    }

    /// The way out for traffic from a socket seen as `view` to `dst`, the host's own address
    /// when `dst_host`, or the errno the send or connect fails with. In order:
    ///
    /// - traffic to the host itself goes over loopback, from the bound address or `dst` itself
    ///   (127.0.0.1 for any 127/8 destination);
    /// - multicast and limited broadcast leave through the socket's chosen interface, else its
    ///   source address's (no route lookup);
    /// - a loopback source may not leave the host (Linux, macOS);
    /// - a socket bound to an interface uses only that interface's routes (macOS scoped routing)
    ///   or assumes the destination is on-link there (Linux);
    /// - otherwise longest-prefix match, which Windows' strong host send narrows to the source
    ///   address's own interface.
    fn egress(&self, view: &SockView, dst: IpAddr, op: Op, dst_host: bool) -> Result<Path, i32> {
        let bound = view
            .local
            .map(|l| l.ip())
            .filter(|ip| !ip.is_unspecified() && !ip.is_multicast());
        if dst_host {
            let src = bound.unwrap_or(match dst {
                IpAddr::V4(v4) if v4.is_loopback() => Ipv4Addr::LOCALHOST.into(),
                other => other,
            });
            return Ok(self.path(self.lo(), src, None, true));
        }
        let owner = bound.and_then(|ip| self.owner(ip));
        let src_from = |nic: &NicRec, route_src: Option<IpAddr>| {
            bound
                .or(route_src.filter(|s| s.is_ipv4() == dst.is_ipv4()))
                .or_else(|| nic.source_for(dst))
                .unwrap_or_else(|| self.fallback_source(dst))
        };
        // A multicast or limited broadcast leaves through the interface the socket chose, else the
        // one its source address belongs to, loopback included.
        let group = dst.is_multicast() || dst == IpAddr::V4(Ipv4Addr::BROADCAST);
        if group
            && let Some(index) = view
                .mcast_if
                .filter(|_| dst.is_multicast())
                .or(view.device)
                .or_else(|| owner.map(|n| n.index))
        {
            let nic = self.nic(index).ok_or(code::ENETUNREACH)?;
            return Ok(self.path(nic, src_from(nic, None), None, false));
        }
        if let Some(ip) = bound
            && ip.is_loopback()
            && !cfg!(windows)
        {
            // Measured (nic_os_truth.rs loopback_source_off_host_matches_real_os): Linux refuses a
            // loopback source leaving the host with EINVAL (net/ipv4/route.c __mkroute_output),
            // macOS with EADDRNOTAVAIL.
            return Err(if cfg!(target_os = "linux") {
                code::EINVAL
            } else {
                code::EADDRNOTAVAIL
            });
        }
        // snare's model of macOS for a source on an administratively down interface, unsourced
        // in XNU; pinned only against the sim (nic_link.rs admin_down_errnos).
        if cfg!(target_os = "macos") && owner.is_some_and(|n| !n.link.admin()) {
            return Err(code::ENETDOWN);
        }
        // The Windows multicast exclusion below is never hit: a multicast destination with a
        // device set already left through that device in the group branch above, so on Windows
        // IP_UNICAST_IF does steer multicast when IP_MULTICAST_IF is unset. Microsoft Learn
        // (IPPROTO_IP socket options) describes IP_UNICAST_IF as the interface "for sending IPv4
        // traffic" and IP_MULTICAST_IF as the one "for sending IPv4 multicast traffic"; which of
        // them the real stack applies to multicast when only IP_UNICAST_IF is set is unmeasured.
        // A device index that no longer exists is ENETUNREACH here; Linux answers ENODEV
        // (net/ipv4/route.c ip_route_output_key_hash_rcu, dev_get_by_index_rcu failing).
        if let Some(dev) = view
            .device
            .filter(|_| !(cfg!(windows) && dst.is_multicast()))
        {
            let nic = self.nic(dev).ok_or(code::ENETUNREACH)?;
            let scoped = self.lpm(dst, |n| n.index == dev && n.routes_live(), None);
            if cfg!(target_os = "macos") {
                // The same unsourced ENETDOWN model as for a source on a down interface.
                if !nic.link.admin() {
                    return Err(code::ENETDOWN);
                }
                // Measured (nic_os_truth.rs bound_if_scope_miss_matches_real_os): a scoped lookup
                // that misses is ENETUNREACH.
                let (route, _) = scoped.ok_or(code::ENETUNREACH)?;
                return Ok(self.path(nic, src_from(nic, route.src), route.gateway, false));
            }
            if cfg!(windows) && !nic.routes_live() {
                return Err(code::ENETUNREACH);
            }
            // Linux: an oif that is not IFF_UP is ENETUNREACH (net/ipv4/route.c
            // ip_route_output_key_hash_rcu); a lookup that misses on it assumes the destination is
            // on-link ("Apparently, routing tables are wrong", same function).
            if !nic.link.admin() {
                return Err(code::ENETUNREACH);
            }
            let (src, gateway) = match scoped {
                Some((route, _)) => (src_from(nic, route.src), route.gateway),
                None => (src_from(nic, None), None),
            };
            return Ok(self.path(nic, src, gateway, false));
        }
        let prefer = owner.map(|n| n.index);
        let (mut route, mut index) = self
            .lpm(dst, NicRec::routes_live, prefer)
            .ok_or_else(|| Self::no_route(op, bound.is_some()))?;
        // Windows strong host send: a bound source leaves only through its own interface, by a
        // lookup constrained to it (Microsoft Learn: "The Cable Guy: Strong and Weak Host Models",
        // https://learn.microsoft.com/en-us/previous-versions/technet-magazine/cc137807(v=msdn.10);
        // measured by nic_os_truth.rs windows_strong_host_and_media_sense).
        if cfg!(windows) && bound.is_some() && prefer != Some(index) {
            (route, index) = self
                .lpm(dst, |n| n.routes_live() && Some(n.index) == prefer, None)
                .ok_or(code::ENETUNREACH)?;
        }
        let nic = self.nic(index).expect("routed interface");
        Ok(self.path(nic, src_from(nic, route.src), route.gateway, false))
    }

    /// Counts one `frame`-byte frame on interface `index`; `multicast` also counts a received
    /// multicast frame, as Linux's `multicast` counter is "multicast packets received"
    /// (`include/uapi/linux/if_link.h`, `struct rtnl_link_stats64` field docs).
    pub(crate) fn account(&mut self, index: u32, dir: Dir, frame: usize, multicast: bool) {
        let Some(nic) = self.nic_mut(index) else {
            return;
        };
        let c = &mut nic.counters;
        match dir {
            Dir::Tx => {
                c.tx_packets += 1;
                c.tx_bytes += frame as u64;
            }
            Dir::Rx => {
                c.rx_packets += 1;
                c.rx_bytes += frame as u64;
                if multicast {
                    c.multicast += 1;
                }
            }
        }
    }

    /// Counts a frame sent while the link had no carrier: dropped, and a carrier error.
    fn count_carrier_drop(&mut self, index: u32) {
        if let Some(nic) = self.nic_mut(index) {
            nic.counters.tx_dropped += 1;
            nic.counters.tx_carrier_errors += 1;
        }
    }

    /// Counts a frame that could not be received because the link was down.
    fn count_rx_drop(&mut self, index: u32) {
        if let Some(nic) = self.nic_mut(index) {
            nic.counters.rx_dropped += 1;
        }
    }

    /// Interface `index`'s link policy, `None` when it is the perfect default, so the caller draws
    /// nothing for it.
    fn policy_of(&self, index: u32) -> Option<NicPolicy> {
        self.nic(index)
            .map(|n| n.spec.policy.clone())
            .filter(|p| *p != NicPolicy::default())
    }

    /// Claims `ip` for the host if it may bind it: one of its addresses, a station address, a
    /// broadcast or multicast address, or — while the sim is open — any address, which becomes
    /// the host's on `sim0` (127/8 is always on loopback). Otherwise `EADDRNOTAVAIL`, bind's
    /// "nonexistent interface or not local" error (man 7 ip, `EADDRNOTAVAIL`;
    /// `WSAEADDRNOTAVAIL` on Windows). With `sim0` gone, the claim goes to the first non-loopback
    /// interface, else to loopback.
    fn claim(&mut self, ip: IpAddr) -> Result<(), i32> {
        if ip.is_unspecified() || ip.is_multicast() || self.is_broadcast(ip) || self.is_host(ip) {
            return Ok(());
        }
        if self.is_station_ip(ip) {
            return Ok(());
        }
        if !self.open || self.owner(ip).is_some() {
            return Err(code::EADDRNOTAVAIL);
        }
        let index = self
            .sim0
            .filter(|i| self.nic(*i).is_some())
            .or_else(|| self.nics.iter().find(|n| !n.loopback).map(|n| n.index))
            .unwrap_or(self.lo().index);
        let nic = self.nic_mut(index).expect("interface");
        nic.spec.addresses.push(IpNet::host(ip));
        nic.origins.insert(ip, Origin::Auto);
        Ok(())
    }

    /// Whether `ip` is the host's, a station's, or nobody's, given whether a tester or station
    /// socket is bound there. In an open sim any other address counts as the host's, since a bind
    /// would claim it.
    pub(crate) fn presence(&self, ip: IpAddr, station: bool) -> Presence {
        if self.is_host(ip) {
            Presence::Host
        } else if station || self.is_station_ip(ip) {
            Presence::Station
        } else if self.open {
            Presence::Host
        } else {
            Presence::Absent
        }
    }
}

impl Topology {
    /// Who answers a SYN to `ip`: as [`presence`](Self::presence), except that an open sim's
    /// addresses nobody has claimed are nobody's.
    fn syn_presence(&self, ip: IpAddr, station: bool) -> Presence {
        if self.is_host(ip) {
            Presence::Host
        } else if station || self.is_station_ip(ip) {
            Presence::Station
        } else {
            Presence::Absent
        }
    }

    /// Whether `ip` sits on a segment the host is attached to: a route without a gateway, other
    /// than a default route, covers it.
    fn on_link(&self, ip: IpAddr) -> bool {
        self.lpm(ip, NicRec::routes_live, None)
            .is_some_and(|(route, _)| route.gateway.is_none() && route.dest.prefix > 0)
    }
}

/// Who answers at an address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Presence {
    /// One of the host's addresses: delivered locally.
    Host,
    /// A station across a link.
    Station,
    /// Nothing: a connect times out, a datagram vanishes.
    Absent,
}

/// The on-wire length of a UDP datagram of `payload` bytes, as the interface counters count it:
/// Ethernet header 14 (IEEE 802.3; the FCS is excluded, as `rx_bytes`/`tx_bytes` exclude it,
/// `include/uapi/linux/if_link.h`) + IPv4 header 20
/// (RFC 791) or IPv6 header 40 (RFC 8200) + UDP header 8 (RFC 768). No IP options or extension
/// headers.
fn frame_len(ip: IpAddr, payload: usize) -> usize {
    payload + if ip.is_ipv4() { 42 } else { 62 }
}

/// The error for an interface name the sim does not have.
fn not_found(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("no interface named {name}"),
    )
}

/// What a topology change leaves to do once its lock is released.
#[derive(Default)]
struct After {
    /// Events to record, in order.
    events: Vec<RecordedEvent>,
    /// Whether to wake waiters, because something they wait on may have changed.
    kick: bool,
}

impl SimShared {
    /// Applies every scheduled link transition that has come due, so the event log holds them.
    /// Collects the links under the topology lock and applies them after releasing it.
    pub(crate) fn settle_links(&self) {
        let links: Vec<Arc<LinkState>> =
            snare_interpose::real(|| self.topo().nics.iter().map(|n| n.link.clone()).collect());
        for link in links {
            link.apply_due();
        }
    }

    /// Who answers a SYN to `ip`, and whether it is on-link; see `Topology::syn_presence`. The
    /// caller (`syn_plan` in `faults`) uses on-link to cut an absent address's connect short
    /// where neighbour resolution would fail, rather than letting it time out.
    pub(crate) fn syn_target(&self, ip: IpAddr, station: bool) -> (Presence, bool) {
        snare_interpose::real(|| {
            let topo = self.topo();
            (topo.syn_presence(ip, station), topo.on_link(ip))
        })
    }

    /// Whether a connect to `ip` is delivered to the host itself.
    pub(crate) fn dest_is_host(&self, ip: IpAddr, station: bool) -> bool {
        snare_interpose::real(|| {
            let topo = self.topo();
            topo.dest_kind(ip) == DestKind::Unicast && topo.presence(ip, station) == Presence::Host
        })
    }

    /// The interface latency an ICMP error for a datagram to `dest` along `sender` crosses each
    /// way, or `None` when nothing at `dest` would answer: it is not a unicast address the host or
    /// a station holds.
    pub(crate) fn icmp_one_way(
        &self,
        sender: &Sender,
        dest: IpAddr,
        station: bool,
    ) -> Option<Duration> {
        snare_interpose::real(|| {
            let topo = self.topo();
            if topo.dest_kind(dest) != DestKind::Unicast
                || topo.presence(dest, station) == Presence::Absent
            {
                return None;
            }
            if let Sender::Host(path) = sender
                && !path.local
                && path.gateway.is_none()
                && topo.segment(dest).is_some_and(|seg| seg != path.egress)
            {
                return None;
            }
            Some(match sender {
                Sender::Host(path) if !path.local => topo
                    .policy_of(path.egress)
                    .map_or(Duration::ZERO, |p| p.latency),
                _ => Duration::ZERO,
            })
        })
    }

    /// Counts a datagram to `dest` that no socket took, if it was the host's to take: a unicast
    /// one to the host's address as `NoPorts`, a broadcast one, or a multicast one for a group a
    /// socket of the host joined, as `IgnoredMulti` (see [`crate::netstats`] for each OS's
    /// names). A multicast group the host never joined is dropped below UDP and counts nowhere
    /// (Linux `ip_check_mc_rcu`, net/ipv4/igmp.c; xnu `ip_input` drops a datagram for a group
    /// the interface has not joined). `station` says whether a tester or station socket is
    /// bound at `dest`'s address.
    pub(crate) fn count_unreceived(&self, dest: SocketAddr, station: bool) {
        let ip = dest.ip();
        let (kind, host) = snare_interpose::real(|| {
            let topo = self.topo();
            (
                topo.dest_kind(ip),
                topo.presence(ip, station) == Presence::Host,
            )
        });
        let udp = self.stats.udp(ip);
        match kind {
            DestKind::Unicast if host => crate::netstats::bump(&udp.no_ports),
            DestKind::Unicast => {}
            DestKind::Multicast if !self.host_joined(ip) => {}
            _ => crate::netstats::bump(&udp.ignored_multi),
        }
    }

    /// Whether an open socket of the code under test is a member of multicast `group`.
    pub(crate) fn host_joined(&self, group: IpAddr) -> bool {
        snare_interpose::real(|| self.sockets.live_recs().iter().any(|rec| rec.joined(group)))
    }

    /// Locks the topology. Poisoning is ignored: a panicking test thread must not wedge the
    /// sim's other threads, and every mutation leaves the topology consistent at each step.
    pub(crate) fn topo(&self) -> MutexGuard<'_, Topology> {
        self.topology.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Records `after`'s events and kicks the sim; called with the topology lock released.
    fn finish(&self, after: After) {
        for event in after.events {
            self.record(event);
        }
        if after.kick {
            self.kick();
        }
    }

    /// Builds the starting topology: the declared interfaces (a host's first, moving loopback off
    /// an index one claims), `sim0` with the default routes unless a host declared interfaces, in
    /// which case the default routes leave through its lowest one, then the declared routes.
    /// The implicit default routes (`0.0.0.0/0`, `::/0`) carry metric 100, a snare choice that
    /// lets a test's own metric-0 route win a tie; they are left out when a host route is already
    /// a default. Panics on a clash or a route through an unknown interface: a broken sim
    /// definition.
    pub(crate) fn init_topology(
        &self,
        host_nics: Vec<(NicSpec, NicCounters)>,
        host_routes: Vec<Route>,
        nics: Vec<NicSpec>,
        routes: Vec<Route>,
    ) {
        snare_interpose::real(|| {
            let mut topo = self.topo();
            let host_declared = !host_nics.is_empty();
            for (spec, counters) in host_nics {
                if let Some(index) = spec.index {
                    topo.make_room(index);
                }
                let name = spec.name.clone();
                if let Err(e) = topo.insert(spec, counters) {
                    panic!("host interface {name}: {e}");
                }
            }
            for spec in nics {
                let name = spec.name.clone();
                if let Err(e) = topo.insert(spec, NicCounters::default()) {
                    panic!("interface {name}: {e}");
                }
            }
            let default_nic = if host_declared {
                topo.nics
                    .iter()
                    .find(|n| !n.loopback)
                    .map(|n| n.spec.name.clone())
            } else {
                let index = topo.free_index(2);
                topo.insert(NicSpec::new("sim0").index(index), NicCounters::default())
                    .expect("sim0");
                topo.sim0 = Some(index);
                Some("sim0".to_string())
            };
            let explicit_default = host_routes.iter().any(|r| r.dest.prefix == 0);
            if let Some(name) = default_nic.filter(|_| !explicit_default) {
                topo.routes.push(
                    Route::new(IpNet::new(Ipv4Addr::UNSPECIFIED.into(), 0), name.clone())
                        .metric(100),
                );
                topo.routes.push(
                    Route::new(IpNet::new(Ipv6Addr::UNSPECIFIED.into(), 0), name).metric(100),
                );
            }
            for route in host_routes.into_iter().chain(routes) {
                assert!(
                    topo.by_name(&route.nic).is_some(),
                    "route to {} via unknown interface {}",
                    route.dest,
                    route.nic
                );
                topo.routes.push(route);
            }
        });
    }

    /// Adds an interface, records a `NicChanged` event with its initial link state, and kicks.
    pub(crate) fn add_nic(&self, spec: NicSpec) -> io::Result<u32> {
        let (index, after) = snare_interpose::real(|| {
            let mut topo = self.topo();
            let name = spec.name.clone();
            let (admin_up, carrier) = (spec.admin_up, spec.carrier);
            let index = topo.insert(spec, NicCounters::default())?;
            let after = After {
                events: vec![RecordedEvent::NicChanged {
                    nic: name,
                    admin_up,
                    carrier,
                }],
                kick: true,
            };
            io::Result::Ok((index, after))
        })?;
        self.finish(after);
        Ok(index)
    }

    /// Removes an interface and its routes. Its link is brought down (a new down epoch, so
    /// datagrams in flight across it are lost), any schedule is dropped, and it is marked removed,
    /// which releases stalled TCP bytes. Loopback cannot be removed.
    pub(crate) fn remove_nic(&self, name: &str) -> io::Result<()> {
        let after = snare_interpose::real(|| {
            let mut topo = self.topo();
            let nic = topo.by_name(name).ok_or_else(|| not_found(name))?;
            if nic.loopback {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the loopback interface cannot be removed",
                ));
            }
            let index = nic.index;
            let pos = topo
                .nics
                .iter()
                .position(|n| n.index == index)
                .expect("nic");
            let rec = topo.nics.remove(pos);
            topo.routes.retain(|r| r.nic != name);
            if topo.sim0 == Some(index) {
                topo.sim0 = None;
            }
            rec.link.apply_due();
            rec.link.schedule.lock().unwrap().clear();
            let now = Deadline::after(Duration::ZERO).instant();
            #[cfg(target_os = "macos")]
            rec.link.remove(now);
            #[cfg(not(target_os = "macos"))]
            {
                rec.link.set(Some(false), Some(false), now);
                rec.link.removed.store(true, Ordering::Release);
            }
            Ok(After {
                events: vec![RecordedEvent::NicChanged {
                    nic: name.to_string(),
                    admin_up: false,
                    carrier: false,
                }],
                kick: true,
            })
        })?;
        self.finish(after);
        Ok(())
    }

    /// Edits an interface through `change` on a snapshot of it. A new non-auto address closes an
    /// open sim. Admin state and carrier go to the live link; a `NicChanged` event is recorded
    /// only if they changed. Address origins carry over for addresses kept.
    pub(crate) fn set_nic(&self, name: &str, change: impl FnOnce(&mut NicSpec)) -> io::Result<()> {
        let after = snare_interpose::real(|| {
            let mut topo = self.topo();
            let index = topo.index_of(name).ok_or_else(|| not_found(name))?;
            let mut spec = topo.nic(index).expect("nic").snapshot().spec;
            change(&mut spec);
            if spec.name != name || spec.index != Some(index) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "an interface's name and index cannot change",
                ));
            }
            let current = topo.nic(index).expect("nic");
            if !current.loopback
                && spec
                    .addresses
                    .iter()
                    .any(|n| current.origins.get(&n.addr) != Some(&Origin::Auto))
            {
                topo.open = false;
            }
            let now = Deadline::after(Duration::ZERO).instant();
            let nic = topo.nic_mut(index).expect("nic");
            let changed = nic.link.set(Some(spec.admin_up), Some(spec.carrier), now);
            let origins = std::mem::take(&mut nic.origins);
            nic.origins = spec
                .addresses
                .iter()
                .map(|n| {
                    (
                        n.addr,
                        origins.get(&n.addr).copied().unwrap_or(Origin::Explicit),
                    )
                })
                .collect();
            let event = RecordedEvent::NicChanged {
                nic: name.to_string(),
                admin_up: spec.admin_up,
                carrier: spec.carrier,
            };
            nic.spec = spec;
            Ok(After {
                events: changed.then_some(event).into_iter().collect(),
                kick: true,
            })
        })?;
        self.finish(after);
        Ok(())
    }

    /// Sets the interface's carrier now.
    pub(crate) fn set_link(&self, name: &str, carrier: bool) -> io::Result<()> {
        self.set_nic(name, |spec| spec.carrier = carrier)
    }

    /// Queues a carrier change `after` from now on the deadline clock, in deadline order, and
    /// registers the deadline so the clock (virtual or real) wakes waiters when it falls.
    pub(crate) fn schedule_link(
        &self,
        name: &str,
        after: Duration,
        carrier: bool,
    ) -> io::Result<()> {
        let at = snare_interpose::real(|| {
            let topo = self.topo();
            let nic = topo.by_name(name).ok_or_else(|| not_found(name))?;
            let at = Deadline::after(after);
            let mut schedule = nic.link.schedule.lock().unwrap();
            let pos = schedule
                .iter()
                .position(|change| change.at.instant() > at.instant())
                .unwrap_or(schedule.len());
            schedule.insert(
                pos,
                LinkTransition {
                    at,
                    carrier,
                    #[cfg(windows)]
                    restart: None,
                },
            );
            io::Result::Ok(at)
        })?;
        snare_interpose::real(|| at.wake_waiters_then());
        self.kick();
        Ok(())
    }

    #[cfg(windows)]
    pub(crate) fn adapter_link(
        &self,
        name: &str,
        generation: &Arc<Mutex<u64>>,
        epoch: u64,
        restore: Option<Deadline>,
    ) -> io::Result<()> {
        let timer = restore.and_then(|at| snare_interpose::real(|| at.arm()));
        let result = snare_interpose::real(|| {
            let topo = self.topo();
            let nic = topo.by_name(name).ok_or_else(|| not_found(name))?;
            nic.link.apply_due();
            let current = generation.lock().unwrap_or_else(|e| e.into_inner());
            if *current != epoch {
                return Ok((
                    After {
                        events: Vec::new(),
                        kick: false,
                    },
                    Vec::new(),
                    false,
                ));
            }
            let mut schedule = nic.link.schedule.lock().unwrap();
            let mut cancelled = Vec::new();
            schedule.retain(|change| {
                if let Some(restart) = &change.restart
                    && Arc::ptr_eq(&restart.generation, generation)
                {
                    cancelled.extend(restart.timer);
                    false
                } else {
                    true
                }
            });
            let pending = restore.filter(|at| !at.passed());
            let carrier = restore.is_some() && pending.is_none();
            let changed = nic.link.set(
                None,
                Some(carrier),
                Deadline::after(Duration::ZERO).instant(),
            );
            if let Some(at) = pending {
                let pos = schedule
                    .iter()
                    .position(|change| change.at.instant() > at.instant())
                    .unwrap_or(schedule.len());
                schedule.insert(
                    pos,
                    LinkTransition {
                        at,
                        carrier: true,
                        restart: Some(RestartTransition {
                            generation: generation.clone(),
                            epoch,
                            timer,
                        }),
                    },
                );
            }
            Ok((
                After {
                    events: changed
                        .then(|| RecordedEvent::NicChanged {
                            nic: name.to_owned(),
                            admin_up: nic.link.admin_up.load(Ordering::Acquire),
                            carrier,
                        })
                        .into_iter()
                        .collect(),
                    kick: true,
                },
                cancelled,
                pending.is_some(),
            ))
        });
        match result {
            Ok((after, cancelled, armed)) => {
                if let Some(clock) = &self.clock {
                    for timer in cancelled {
                        clock.unregister_event(timer);
                    }
                    if !armed && let Some(timer) = timer {
                        clock.unregister_event(timer);
                    }
                }
                self.finish(after);
                Ok(())
            }
            Err(error) => {
                if let Some(clock) = &self.clock
                    && let Some(timer) = timer
                {
                    clock.unregister_event(timer);
                }
                Err(error)
            }
        }
    }

    #[cfg(windows)]
    pub(crate) fn cancel_adapter_link(&self, name: &str, generation: &Arc<Mutex<u64>>) {
        let cancelled = snare_interpose::real(|| {
            let topo = self.topo();
            let Some(nic) = topo.by_name(name) else {
                return Vec::new();
            };
            let mut schedule = nic.link.schedule.lock().unwrap();
            let mut cancelled = Vec::new();
            schedule.retain(|change| {
                if let Some(restart) = &change.restart
                    && Arc::ptr_eq(&restart.generation, generation)
                {
                    cancelled.extend(restart.timer);
                    false
                } else {
                    true
                }
            });
            cancelled
        });
        if let Some(clock) = &self.clock {
            for timer in cancelled {
                clock.unregister_event(timer);
            }
        }
        self.kick();
    }

    /// Edits an interface's link policy and kicks, so waiters re-check delays.
    pub(crate) fn set_nic_policy(
        &self,
        name: &str,
        change: impl FnOnce(&mut NicPolicy),
    ) -> io::Result<()> {
        snare_interpose::real(|| {
            let mut topo = self.topo();
            let index = topo.index_of(name).ok_or_else(|| not_found(name))?;
            change(&mut topo.nic_mut(index).expect("nic").spec.policy);
            io::Result::Ok(())
        })?;
        self.kick();
        Ok(())
    }

    /// Edits an interface's counters. Nothing waits on counters, so nothing is woken.
    pub(crate) fn set_nic_counters(
        &self,
        name: &str,
        change: impl FnOnce(&mut NicCounters),
    ) -> io::Result<()> {
        snare_interpose::real(|| {
            let mut topo = self.topo();
            let index = topo.index_of(name).ok_or_else(|| not_found(name))?;
            change(&mut topo.nic_mut(index).expect("nic").counters);
            Ok(())
        })
    }

    /// A snapshot of interface `name`.
    pub(crate) fn nic(&self, name: &str) -> Option<NicSnapshot> {
        snare_interpose::real(|| self.topo().by_name(name).map(NicRec::snapshot))
    }

    /// Snapshots of every interface, by index.
    pub(crate) fn nics(&self) -> Vec<NicSnapshot> {
        snare_interpose::real(|| self.topo().nics.iter().map(NicRec::snapshot).collect())
    }

    /// Interface `name`'s counters.
    pub(crate) fn nic_counters(&self, name: &str) -> Option<NicCounters> {
        snare_interpose::real(|| self.topo().by_name(name).map(|n| n.counters))
    }

    /// Appends a configured route; its interface must exist.
    pub(crate) fn add_route(&self, route: Route) -> io::Result<()> {
        snare_interpose::real(|| {
            let mut topo = self.topo();
            if topo.by_name(&route.nic).is_none() {
                return Err(not_found(&route.nic));
            }
            topo.routes.push(route);
            Ok(())
        })?;
        self.kick();
        Ok(())
    }

    /// Removes every configured route to exactly `dest`; whether any went. Connected routes are
    /// not configured and stay.
    pub(crate) fn remove_route(&self, dest: IpNet) -> bool {
        let removed = snare_interpose::real(|| {
            let mut topo = self.topo();
            let before = topo.routes.len();
            topo.routes.retain(|r| r.dest != dest);
            topo.routes.len() != before
        });
        if removed {
            self.kick();
        }
        removed
    }

    /// Replaces every default route with a metric-100 pair through `nic`, or removes them.
    pub(crate) fn set_default_route(&self, nic: Option<&str>) -> io::Result<()> {
        snare_interpose::real(|| {
            let mut topo = self.topo();
            if let Some(name) = nic
                && topo.by_name(name).is_none()
            {
                return Err(not_found(name));
            }
            topo.routes.retain(|r| r.dest.prefix != 0);
            if let Some(name) = nic {
                topo.routes.push(
                    Route::new(IpNet::new(Ipv4Addr::UNSPECIFIED.into(), 0), name).metric(100),
                );
                topo.routes.push(
                    Route::new(IpNet::new(Ipv6Addr::UNSPECIFIED.into(), 0), name).metric(100),
                );
            }
            Ok(())
        })?;
        self.kick();
        Ok(())
    }

    /// Every route, live or withdrawn; see `Topology::all_routes`.
    pub(crate) fn routes(&self) -> Vec<Route> {
        snare_interpose::real(|| self.topo().all_routes())
    }

    /// The routes in the table now, each with its interface's index: those of an interface that
    /// is gone or (on Windows, without carrier; elsewhere, administratively) down are withdrawn.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub(crate) fn live_routes(&self) -> Vec<(Route, u32)> {
        snare_interpose::real(|| {
            let topo = self.topo();
            topo.all_routes()
                .into_iter()
                .filter_map(|route| {
                    let nic = topo.by_name(&route.nic)?;
                    nic.routes_live().then_some((route, nic.index))
                })
                .collect()
        })
    }

    /// The route a connect from `src` to `dst` would take, as [`route_lookup`] reports it.
    pub(crate) fn route_lookup(&self, src: Option<IpAddr>, dst: IpAddr) -> io::Result<RouteChoice> {
        snare_interpose::real(|| {
            let topo = self.topo();
            let view = SockView {
                local: src.map(|ip| SocketAddr::new(ip, 0)),
                ..SockView::default()
            };
            let path = topo
                .egress(&view, dst, Op::Connect, topo.is_host(dst))
                .map_err(io::Error::from_raw_os_error)?;
            Ok(RouteChoice {
                nic: path.name.to_string(),
                index: path.egress,
                src: Some(path.src),
                gateway: path.gateway,
            })
        })
    }

    /// Whether the code under test may bind `ip`, claiming it for the host while the sim is open.
    /// Called from the bind hook, already in passthrough.
    pub(crate) fn claim_address(&self, ip: IpAddr) -> Result<(), i32> {
        self.topo().claim(ip)
    }

    /// How a send or connect from a socket seen as `view` reaches `dest`: from a station socket
    /// as that station, otherwise along the host's route. `station` says whether a tester or
    /// station socket is bound at `dest`'s address. Refuses a broadcast without `broadcast_ok`
    /// (`SO_BROADCAST`): `EACCES` on Linux (man 7 ip, ERRORS, EACCES) and macOS (man 2 send,
    /// EACCES), `WSAEACCES` on Windows
    /// ([Microsoft Learn: Windows Sockets Error Codes](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2)).
    /// Records an unreachable or down network as a `Fault::Unreachable` as it fails the call.
    pub(crate) fn route_send(
        &self,
        view: &SockView,
        dest: SocketAddr,
        op: Op,
        station: bool,
        broadcast_ok: bool,
    ) -> Result<Sender, i32> {
        let result = {
            let topo = self.topo();
            if let Some(local) = view.local.filter(|l| topo.is_station_ip(l.ip())) {
                return Ok(Sender::Station(local.ip()));
            }
            let kind = topo.dest_kind(dest.ip());
            if matches!(kind, DestKind::Limited | DestKind::Directed(_)) && !broadcast_ok {
                return Err(code::EACCES);
            }
            let dst_host =
                kind == DestKind::Unicast && topo.presence(dest.ip(), station) == Presence::Host;
            topo.egress(view, dest.ip(), op, dst_host)
        };
        result.map(Sender::Host).inspect_err(|&errno| {
            if [code::ENETUNREACH, code::EHOSTUNREACH, code::ENETDOWN].contains(&errno) {
                self.record(RecordedEvent::Fault {
                    addr: Some(dest),
                    fault: Fault::Unreachable { errno },
                });
            }
        })
    }

    /// The interface a TCP connection along `sender` crosses, if it leaves the host: the egress
    /// for the host, the segment of `dest` for a station.
    pub(crate) fn tcp_hop(&self, sender: &Sender, dest: IpAddr) -> Option<Hop> {
        match sender {
            Sender::Host(path) if path.local => None,
            Sender::Host(path) => Some(Hop {
                index: path.egress,
                link: path.link.clone(),
            }),
            Sender::Station(_) => {
                let topo = self.topo();
                let index = topo.segment(dest)?;
                Some(Hop {
                    index,
                    link: topo.link_of(index)?,
                })
            }
        }
    }

    /// The name of the interface a TCP connection crosses: its hop's, or loopback's when it
    /// stays on the host.
    pub(crate) fn hop_name(&self, hop: Option<&Hop>) -> Option<String> {
        let topo = self.topo();
        topo.name_of(hop.map_or(topo.loopback_index(), |h| h.index))
    }

    /// The extra delay the crossed interface's policy adds to one TCP write: its latency plus one
    /// jitter draw. The topology lock is released before the draw.
    pub(crate) fn hop_delay(&self, hop: Option<&Hop>) -> Duration {
        let Some(policy) = hop.and_then(|hop| self.topo().policy_of(hop.index)) else {
            return Duration::ZERO;
        };
        policy.latency + self.policies.jitter(policy.jitter)
    }

    /// Counts one TCP write of `len` bytes, as segments of at most MTU-40 bytes, on the crossed
    /// interface (outbound from the host for the connecting end) or twice on loopback (once each
    /// way, as Linux's loopback reports every frame as both sent and received,
    /// `drivers/net/loopback.c` `loopback_get_stats64`). MTU-40 is the IPv4 MSS (MTU minus the
    /// 20-byte IPv4 and 20-byte TCP fixed headers; RFC 9293 §3.7.1 derives its default MSS the same
    /// way, 536 = 576 - 40 for IPv4 and 1220 = 1280 - 60 for IPv6); snare uses MTU-40 for IPv6 too,
    /// where the real MSS is MTU-60. Each segment counts its headers: Ethernet 14 + IPv4 20
    /// or IPv6 40 + TCP 20, so 54 or 74. Nothing is counted while the link is down, since the
    /// bytes stall rather than cross. ACKs are not counted.
    ///
    /// The same segments count in the host's TCP counters (`OutSegs` when `cut.0`, the code
    /// under test, wrote them; `InSegs` when `cut.1`, the code under test, reads them), stalled
    /// or not, in `dest`'s family.
    #[cfg(windows)]
    pub(crate) fn account_tcp(
        &self,
        hop: Option<&Hop>,
        from_client: bool,
        len: usize,
        dest: IpAddr,
        cut: (bool, bool),
    ) {
        self.account_tcp_mss(hop, from_client, len, dest, cut, None);
    }

    pub(crate) fn account_tcp_mss(
        &self,
        hop: Option<&Hop>,
        from_client: bool,
        len: usize,
        dest: IpAddr,
        cut: (bool, bool),
        mss: Option<usize>,
    ) {
        if len == 0 {
            return;
        }
        let v6 = dest.is_ipv6();
        let mut topo = self.topo();
        let mss_of =
            |index: u32| topo.mtu_of(index).unwrap_or(1500).saturating_sub(40).max(1) as usize;
        let segs = len
            .div_ceil(mss.unwrap_or_else(|| mss_of(hop.map_or(topo.lo().index, |h| h.index))))
            as u64;
        let tcp = self.stats.tcp(dest);
        if cut.0 {
            tcp.out_segs
                .fetch_add(segs, std::sync::atomic::Ordering::Relaxed);
        }
        if cut.1 {
            tcp.in_segs
                .fetch_add(segs, std::sync::atomic::Ordering::Relaxed);
        }
        let (index, dirs): (u32, &[Dir]) = match hop {
            Some(hop) if !hop.link.usable() => return,
            Some(hop) if from_client => (hop.index, &[Dir::Tx]),
            Some(hop) => (hop.index, &[Dir::Rx]),
            None => (topo.lo().index, &[Dir::Tx, Dir::Rx]),
        };
        let mss = mss.unwrap_or_else(|| mss_of(index));
        let header = if v6 { 74 } else { 54 };
        let mut left = len;
        while left > 0 {
            let seg = left.min(mss);
            for dir in dirs {
                topo.account(index, *dir, seg + header, false);
            }
            left -= seg;
        }
    }

    /// The copies of a datagram on `wire` each candidate gets: the exact
    /// bind, else a wildcard bind when `dest` is the host's; every socket on the port for a
    /// broadcast; every member for a multicast group. Applies each crossed interface's link state,
    /// policy and counters, then the receiving address's link policy, in (port, address) order.
    /// `tx` counts the send itself, once per datagram however many backends fan it out.
    ///
    /// Who receives, for a recipient of the host: its exact bind, or a wildcard bind when the
    /// destination is the host's. A socket bound to an interface receives only what arrived there
    /// (Linux `SO_BINDTODEVICE`, man 7 socket). snare applies the same filter to macOS
    /// `IP_BOUND_IF`, which XNU does not: its receive check skips a bound socket only on an
    /// interface marked `IFEF_RESTRICTED_RECV` (`bsd/netinet/in_pcb.c` `_inp_restricted_recv`), so
    /// a real macOS socket bound to one interface still receives unicast arriving on another (read
    /// from the source, not measured). Nor
    /// does the filter apply on Windows, where
    /// `IP_UNICAST_IF` "does not change the default interface for receiving"
    /// ([Microsoft Learn: IPPROTO_IP socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options)).
    /// Windows instead applies strong host receive: a datagram for a specific address is taken only
    /// on that address's own interface ("The Cable Guy: Strong and Weak Host Models",
    /// [Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/technet-magazine/cc137807(v=msdn.10))).
    /// A host datagram for a station on another segment never arrives. Holds the topology lock
    /// throughout and takes the `Policies` locks under it.
    pub(crate) fn fan_out<Q>(
        &self,
        sender: &Sender,
        wire: Wire,
        station: bool,
        cands: Vec<Cand<Q>>,
        tx: bool,
    ) -> Vec<Copy<Q>> {
        let dest = wire.dest;
        let mut topo = self.topo();
        let dip = dest.ip();
        let kind = topo.dest_kind(dip);
        let mut cands: Vec<Cand<Q>> = cands
            .into_iter()
            .filter(|c| c.addr.port() == dest.port() && c.addr.is_ipv4() == dest.is_ipv4())
            .collect();
        let mut chosen: Vec<Cand<Q>> = match kind {
            DestKind::Unicast => match cands.iter().position(|c| c.addr == dest) {
                Some(i) => {
                    cands.swap(0, i);
                    cands.truncate(1);
                    cands
                }
                None if topo.presence(dip, station) == Presence::Host => cands
                    .into_iter()
                    .filter(|c| c.addr.ip().is_unspecified())
                    .collect(),
                None => Vec::new(),
            },
            DestKind::Limited | DestKind::Multicast => cands,
            DestKind::Directed(net) => cands
                .into_iter()
                .filter(|c| {
                    let ip = c.addr.ip();
                    let station = c.endpoint || topo.is_station_ip(ip);
                    ip.is_unspecified() || ip == dip || (station && net.contains(ip))
                })
                .collect(),
        };
        chosen.sort_by_key(|c| (c.addr.port(), c.addr.ip()));
        let mut out = Vec::new();
        self.fan_out_selected(&mut topo, sender, wire, kind, chosen, tx, |copy| {
            out.push(copy)
        });
        out
    }

    #[cfg(unix)]
    pub(crate) fn fan_out_one<Q>(
        &self,
        sender: &Sender,
        wire: Wire,
        station: bool,
        cand: Option<Cand<Q>>,
        tx: bool,
    ) -> Option<Copy<Q>> {
        let mut topo = self.topo();
        let dest = wire.dest;
        let dip = dest.ip();
        let kind = topo.dest_kind(dip);
        let chosen = cand.filter(|c| {
            if c.addr.port() != dest.port() || c.addr.is_ipv4() != dest.is_ipv4() {
                return false;
            }
            match kind {
                DestKind::Unicast => {
                    c.addr == dest
                        || (c.addr.ip().is_unspecified()
                            && topo.presence(dip, station) == Presence::Host)
                }
                DestKind::Limited | DestKind::Multicast => true,
                DestKind::Directed(net) => {
                    let ip = c.addr.ip();
                    let station = c.endpoint || topo.is_station_ip(ip);
                    ip.is_unspecified() || ip == dip || (station && net.contains(ip))
                }
            }
        });
        let mut out = None;
        self.fan_out_selected(&mut topo, sender, wire, kind, chosen, tx, |copy| {
            out = Some(copy)
        });
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn fan_out_selected<Q>(
        &self,
        topo: &mut Topology,
        sender: &Sender,
        wire: Wire,
        kind: DestKind,
        chosen: impl IntoIterator<Item = Cand<Q>>,
        tx: bool,
        mut emit: impl FnMut(Copy<Q>),
    ) {
        let Wire { src, dest, len } = wire;
        let dip = dest.ip();
        let multicast = kind == DestKind::Multicast;
        let lo = topo.lo().index;
        let frame = frame_len(dip, len);
        let sender_up = match sender {
            Sender::Host(path) if path.local => {
                if tx {
                    topo.account(lo, Dir::Tx, frame, false);
                }
                true
            }
            Sender::Host(path) => {
                let up = path.link.usable();
                if tx && up {
                    topo.account(path.egress, Dir::Tx, frame, false);
                } else if tx {
                    topo.count_carrier_drop(path.egress);
                    self.record(RecordedEvent::Fault {
                        addr: Some(dest),
                        fault: Fault::LinkDown {
                            nic: path.name.to_string(),
                        },
                    });
                }
                up
            }
            Sender::Station(_) => true,
        };
        for c in chosen {
            let ip = c.addr.ip();
            let rcpt_host = if c.endpoint {
                topo.is_host(ip)
            } else {
                !topo.is_station_ip(ip)
            };
            let (crossing, ingress) = match sender {
                Sender::Host(path) if rcpt_host => {
                    (None, Some(if path.local { lo } else { path.egress }))
                }
                Sender::Host(path) if path.local => (None, None),
                Sender::Host(path) => {
                    let elsewhere = topo.segment(ip).is_some_and(|seg| seg != path.egress);
                    if !sender_up || elsewhere {
                        continue;
                    }
                    (Some(path.egress), None)
                }
                Sender::Station(sip) => {
                    let sender_host = topo.is_host(*sip);
                    match (sender_host, rcpt_host) {
                        (true, true) => (None, Some(lo)),
                        (true, false) => (topo.segment(ip), None),
                        (false, true) => {
                            let seg = topo.segment(*sip);
                            (seg, seg)
                        }
                        (false, false) => (topo.segment(*sip), None),
                    }
                }
            };
            let egress = match sender {
                Sender::Host(path) if path.local => Some(lo),
                Sender::Host(path) => Some(path.egress),
                Sender::Station(_) => None,
            };
            let mtu = [egress, crossing, ingress]
                .into_iter()
                .flatten()
                .filter_map(|index| topo.mtu_of(index))
                .min();
            let mut via = None;
            let mut policy = None;
            if let Some(index) = crossing {
                let Some(link) = topo.link_of(index) else {
                    continue;
                };
                if !link.usable() {
                    if rcpt_host {
                        topo.count_rx_drop(index);
                    }
                    continue;
                }
                via = Some((link.clone(), link.epoch()));
                policy = topo.policy_of(index);
            }
            if rcpt_host && !cfg!(windows) && c.device.is_some() && c.device != ingress {
                continue;
            }
            if rcpt_host
                && cfg!(windows)
                && !ip.is_unspecified()
                && let Some(ingress) = ingress.filter(|i| *i != lo)
                && topo.owner(ip).map(|n| n.index) != Some(ingress)
            {
                continue;
            }
            let (mut delays, faults) = self.policies.link_deliveries(policy.as_ref(), c.addr, len);
            let held = self
                .policies
                .held_until_pair(src, dest, c.addr)
                .map(|until| until.remaining());
            if let Some(held) = held {
                for delay in &mut delays {
                    *delay = (*delay).max(held);
                }
            }
            for fault in faults {
                self.record(RecordedEvent::Link {
                    from: src,
                    to: c.addr,
                    len,
                    fault,
                });
            }
            let nic = match ingress.filter(|_| rcpt_host) {
                Some(index) => {
                    for _ in &delays {
                        topo.account(index, Dir::Rx, frame, multicast);
                    }
                    topo.nic(index).map(|nic| nic.name.clone())
                }
                None => None,
            };
            emit(Copy {
                q: c.q,
                delays,
                via,
                nic,
                mtu,
            });
        }
    }

    /// A raw frame sent on interface `index`: `Err` with the errno the send fails with, else
    /// whether the frame reaches the medium. An unknown index is let through (the raw backend
    /// validated it). Linux refuses a frame on an interface that is not up with `ENETDOWN`
    /// (`net/packet/af_packet.c`, `packet_snd`); a frame without carrier is accepted and lost,
    /// counted as a carrier error.
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    pub(crate) fn raw_send(&self, index: u32, len: usize) -> Result<bool, i32> {
        let mut topo = self.topo();
        let Some(nic) = topo.nic(index) else {
            return Ok(true);
        };
        if cfg!(target_os = "linux") && !nic.link.admin() {
            return Err(code::ENETDOWN);
        }
        // Linux packet_snd refuses a frame longer than mtu + hard_header_len (ETH_HLEN, 14, for
        // Ethernet: net/ethernet/eth.c ether_setup) with
        // EMSGSIZE (net/packet/af_packet.c; a further 4-byte VLAN_HLEN is allowed only for a tagged
        // frame, not modelled). XNU's bpf_movein is looser: it allows mtu + BPF_WRITE_LEEWAY (18)
        // after the 14-byte header (bsd/net/bpf.c); snare applies the Linux bound on both.
        // 10040 is WSAEMSGSIZE.
        if len > nic.spec.mtu as usize + 14 {
            #[cfg(unix)]
            return Err(libc::EMSGSIZE);
            #[cfg(windows)]
            return Err(10040);
        }
        if !nic.link.usable() {
            topo.count_carrier_drop(index);
            return Ok(false);
        }
        topo.account(index, Dir::Tx, len, false);
        Ok(true)
    }
}

impl crate::netpolicy::Policies {
    /// The copies of a `len`-byte datagram crossing an interface with `nic` policy to `to`, each
    /// as the delay before it can be received. Draws in a fixed order: the interface's loss,
    /// duplication and one jitter per copy, then the address policy per copy; with no interface
    /// policy it draws exactly as the address policy alone does.
    pub(crate) fn link_deliveries(
        &self,
        nic: Option<&NicPolicy>,
        to: SocketAddr,
        len: usize,
    ) -> (crate::netpolicy::Delays, Vec<LinkFault>) {
        let Some(nic) = nic else {
            let (delays, fault) = self.deliveries(to, len);
            return (delays, fault.into_iter().collect());
        };
        if nic.loss_rate > 0.0 && self.unit() < nic.loss_rate {
            return (crate::netpolicy::Delays::default(), vec![LinkFault::Lost]);
        }
        let mut faults = Vec::new();
        let copies = if nic.duplicate_rate > 0.0 && self.unit() < nic.duplicate_rate {
            faults.push(LinkFault::Duplicated);
            2
        } else {
            1
        };
        let base: crate::netpolicy::Delays = (0..copies)
            .map(|_| nic.latency + self.jitter(nic.jitter))
            .collect();
        let mut delays = crate::netpolicy::Delays::default();
        for first in base {
            let (more, fault) = self.deliveries(to, len);
            faults.extend(fault);
            delays.extend(more.into_iter().map(|d| first + d));
        }
        (delays, faults)
    }
}

/// Adds an interface to the calling thread's sim and returns its index. Fails if the name or
/// index is taken. The first interface with an address ends the open sim: from then on the code
/// under test can only bind the host's addresses and its interfaces' station addresses.
#[track_caller]
pub fn add_nic(spec: NicSpec) -> io::Result<u32> {
    scope::here().add_nic(spec)
}

/// Removes an interface, its addresses and its routes; TCP bytes stalled on its link move again.
#[track_caller]
pub fn remove_nic(name: &str) -> io::Result<()> {
    scope::here().remove_nic(name)
}

/// Edits an interface in place (not its name or index): addresses, stations, MTU, admin state,
/// carrier, policy.
#[track_caller]
pub fn set_nic(name: &str, change: impl FnOnce(&mut NicSpec)) -> io::Result<()> {
    scope::here().set_nic(name, change)
}

/// Gives or takes an interface's carrier now.
#[track_caller]
pub fn set_link(name: &str, carrier: bool) -> io::Result<()> {
    scope::here().set_link(name, carrier)
}

/// Gives or takes an interface's carrier `after` from now on the sim's clock. A thread blocked on
/// traffic over the link wakes when it changes.
#[track_caller]
pub fn schedule_link(name: &str, after: Duration, carrier: bool) -> io::Result<()> {
    scope::here().schedule_link(name, after, carrier)
}

/// Edits an interface's link policy; see [`NicPolicy`].
#[track_caller]
pub fn set_nic_policy(name: &str, change: impl FnOnce(&mut NicPolicy)) -> io::Result<()> {
    scope::here().set_nic_policy(name, change)
}

/// Edits an interface's live counters.
#[track_caller]
pub fn set_nic_counters(name: &str, change: impl FnOnce(&mut NicCounters)) -> io::Result<()> {
    scope::here().set_nic_counters(name, change)
}

/// Interface `name` as it is now.
#[track_caller]
pub fn nic(name: &str) -> Option<NicSnapshot> {
    scope::here().nic(name)
}

/// Every interface, by index.
#[track_caller]
pub fn nics() -> Vec<NicSnapshot> {
    scope::here().nics()
}

/// Interface `name`'s counters now.
#[track_caller]
pub fn nic_counters(name: &str) -> Option<NicCounters> {
    scope::here().nic_counters(name)
}

/// Adds a route through an existing interface.
#[track_caller]
pub fn add_route(route: Route) -> io::Result<()> {
    scope::here().add_route(route)
}

/// Removes the configured routes to `dest`; whether there were any.
#[track_caller]
pub fn remove_route(dest: IpNet) -> bool {
    scope::here().remove_route(dest)
}

/// Points the default routes (`0.0.0.0/0`, `::/0`) at `nic`, or removes them.
#[track_caller]
pub fn set_default_route(nic: Option<&str>) -> io::Result<()> {
    scope::here().set_default_route(nic)
}

/// Every route, the connected subnets of the interfaces' addresses first.
#[track_caller]
pub fn routes() -> Vec<Route> {
    scope::here().routes()
}

/// Where the host would send traffic to `dst` from `src` (or a source it picks), or the error a
/// connect there fails with.
#[track_caller]
pub fn route_lookup(src: Option<IpAddr>, dst: IpAddr) -> io::Result<RouteChoice> {
    scope::here().route_lookup(src, dst)
}

/// The interface option a socket holds: what `SO_BINDTODEVICE`/`IP_BOUND_IF`/`IP_UNICAST_IF` or
/// `IP_MULTICAST_IF` set. This is the unix half; Windows' `IP_UNICAST_IF` lives with its backend.
///
/// Where snare's answer differs from the kernel's, the item says so.
#[cfg(unix)]
pub(crate) mod sockopt {
    use std::ffi::c_int;
    use std::net::Ipv4Addr;

    use crate::scope::SimShared;
    use crate::sockets::SockRec;

    // include/uapi/asm-generic/socket.h.
    #[cfg(target_os = "linux")]
    const SO_BINDTODEVICE: c_int = 25;
    #[cfg(target_os = "linux")]
    const SO_BINDTOIFINDEX: c_int = 62;
    // bsd/netinet/in.h and bsd/netinet6/in6.h.
    #[cfg(target_os = "macos")]
    const IP_BOUND_IF: c_int = 25;
    #[cfg(target_os = "macos")]
    const IPV6_BOUND_IF: c_int = 125;
    // include/uapi/linux/in.h and include/uapi/linux/in6.h.
    #[cfg(target_os = "linux")]
    const IP_MULTICAST_ALL: c_int = 49;
    #[cfg(target_os = "linux")]
    const IPV6_MULTICAST_ALL: c_int = 29;

    /// The `int` an option value holds; `None` for a null or short buffer.
    fn read_int(val: *const u8, len: u32) -> Option<c_int> {
        if val.is_null() || (len as usize) < size_of::<c_int>() {
            return None;
        }
        Some(unsafe { val.cast::<c_int>().read_unaligned() })
    }

    /// Handles an interface-binding option; `None` when `(level, name)` is not one.
    ///
    /// - `SO_BINDTODEVICE` (Linux): a name, NUL-terminated or not; empty unbinds (man 7 socket);
    ///   an unknown name is `ENODEV` (`net/core/sock.c`, `sock_setbindtodevice`). Linux truncates
    ///   the name to 15 bytes and looks it up before the `CAP_NET_RAW` check, so an unknown name
    ///   on an already bound socket is `ENODEV` there and `EPERM` here; snare refuses a name that
    ///   is not UTF-8 with `EINVAL`.
    /// - `SO_BINDTOIFINDEX` (Linux): an index, 0 unbinds. snare refuses an index it does not have
    ///   with `ENODEV`; Linux's `sock_bindtoindex_locked` (`net/core/sock.c`) checks only for a
    ///   negative index (`EINVAL`) and stores any other without looking it up.
    /// - `IP_BOUND_IF`/`IPV6_BOUND_IF` (macOS): an index, 0 unbinds; unknown is `ENXIO`
    ///   (`bsd/netinet/in_pcb.c`, `inp_bindif`).
    /// - `IP_MULTICAST_IF`: an `in_addr`, or on Linux an `ip_mreqn` whose index wins
    ///   (`IP_MULTICAST_IF(2const)`); 0.0.0.0 clears it; an address or index no interface has is
    ///   `EADDRNOTAVAIL`, as Linux answers (`net/ipv4/ip_sockglue.c`, `do_ip_setsockopt`).
    /// - `IPV6_MULTICAST_IF`: an index (`IPV6_MULTICAST_IF(2const)`), 0 clears it
    ///   (`net/ipv6/ipv6_sockglue.c`, `do_ipv6_setsockopt`).
    /// - `IP_MULTICAST_ALL` (Linux): an `int`, or a single byte, that must be 0 or 1, else
    ///   `EINVAL` (`net/ipv4/ip_sockglue.c`, `do_ip_setsockopt`); `IPV6_MULTICAST_ALL` an `int`
    ///   of any value, `EINVAL` when shorter (`do_ipv6_setsockopt`). See
    ///   [`SockRec::takes_group`] for what they change.
    ///
    /// # Safety
    /// `val` points to `len` readable bytes.
    pub(crate) unsafe fn set(
        shared: &SimShared,
        rec: &SockRec,
        level: c_int,
        name: c_int,
        val: *const u8,
        len: u32,
    ) -> Option<Result<(), c_int>> {
        // Changing the device of an already bound socket needs CAP_NET_RAW, else EPERM (net/core/
        // sock.c sock_bindtoindex_locked; man 7 socket).
        #[cfg(target_os = "linux")]
        if level == libc::SOL_SOCKET
            && (name == SO_BINDTODEVICE || name == SO_BINDTOIFINDEX)
            && rec.state().device.is_some()
            && !shared.sys.has_cap(crate::limits::CAP_NET_RAW)
        {
            return Some(Err(libc::EPERM));
        }
        #[cfg(target_os = "linux")]
        if level == libc::SOL_SOCKET && name == SO_BINDTODEVICE {
            let bytes = if val.is_null() {
                &[][..]
            } else {
                unsafe { std::slice::from_raw_parts(val, len as usize) }
            };
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            let Ok(dev) = std::str::from_utf8(&bytes[..end]) else {
                return Some(Err(libc::EINVAL));
            };
            if dev.is_empty() {
                rec.state().device = None;
                return Some(Ok(()));
            }
            let Some(index) = shared.topo().index_of(dev) else {
                return Some(Err(libc::ENODEV));
            };
            rec.state().device = Some((index, dev.to_string()));
            return Some(Ok(()));
        }
        #[cfg(target_os = "linux")]
        if level == libc::SOL_SOCKET && name == SO_BINDTOIFINDEX {
            let Some(index) = read_int(val, len) else {
                return Some(Err(libc::EINVAL));
            };
            return Some(bind_index(shared, rec, index, libc::ENODEV));
        }
        #[cfg(target_os = "macos")]
        if (level == libc::IPPROTO_IP && name == IP_BOUND_IF)
            || (level == libc::IPPROTO_IPV6 && name == IPV6_BOUND_IF)
        {
            let Some(index) = read_int(val, len) else {
                return Some(Err(libc::EINVAL));
            };
            return Some(bind_index(shared, rec, index, libc::ENXIO));
        }
        if level == libc::IPPROTO_IP && name == libc::IP_MULTICAST_IF {
            if val.is_null() || len < 4 {
                return Some(Err(libc::EINVAL));
            }
            let bytes = unsafe { std::slice::from_raw_parts(val, len as usize) };
            // IP_MULTICAST_IF(2const): an in_addr, or on Linux an ip_mreqn whose imr_ifindex (at
            // 8) wins. Linux
            // also takes an 8-byte ip_mreq, whose imr_interface is at 4 (do_ip_setsockopt copies
            // it over ip_mreqn's first 8 bytes); snare reads offset 0 for anything under 12 bytes,
            // so it treats an ip_mreq's group address as the interface.
            let by_index = (cfg!(target_os = "linux") && bytes.len() >= 12)
                .then(|| c_int::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]))
                .filter(|i| *i > 0);
            let addr_at = if cfg!(target_os = "linux") && bytes.len() >= 12 {
                4
            } else {
                0
            };
            let addr = Ipv4Addr::new(
                bytes[addr_at],
                bytes[addr_at + 1],
                bytes[addr_at + 2],
                bytes[addr_at + 3],
            );
            let topo = shared.topo();
            let nic = match by_index {
                Some(index) => topo.name_of(index as u32).map(|n| (index as u32, n)),
                None if addr.is_unspecified() => {
                    drop(topo);
                    rec.state().mcast_if = None;
                    return Some(Ok(()));
                }
                None => topo
                    .owner(addr.into())
                    .map(|n| (n.index, n.spec.name.clone())),
            };
            drop(topo);
            let Some(nic) = nic else {
                return Some(Err(libc::EADDRNOTAVAIL));
            };
            rec.state().mcast_if = Some(nic);
            return Some(Ok(()));
        }
        if level == libc::IPPROTO_IPV6 && name == libc::IPV6_MULTICAST_IF {
            let Some(index) = read_int(val, len) else {
                return Some(Err(libc::EINVAL));
            };
            if index == 0 {
                rec.state().mcast_if = None;
                return Some(Ok(()));
            }
            // snare answers ENXIO for an unknown index. Linux answers ENODEV
            // (net/ipv6/ipv6_sockglue.c do_ipv6_setsockopt); XNU EINVAL out of range, else
            // EADDRNOTAVAIL (bsd/netinet6/in6_mcast.c in6p_set_multicast_if).
            let Some(nic) = shared.topo().name_of(index as u32) else {
                return Some(Err(libc::ENXIO));
            };
            rec.state().mcast_if = Some((index as u32, nic));
            return Some(Ok(()));
        }
        #[cfg(target_os = "linux")]
        if level == libc::IPPROTO_IP && name == IP_MULTICAST_ALL {
            let v = match len {
                _ if val.is_null() || len == 0 => return Some(Err(libc::EINVAL)),
                1..4 => c_int::from(unsafe { *val }),
                _ => read_int(val, len).unwrap_or_default(),
            };
            if v != 0 && v != 1 {
                return Some(Err(libc::EINVAL));
            }
            rec.state().dgram.mc_all = v == 1;
            return Some(Ok(()));
        }
        #[cfg(target_os = "linux")]
        if level == libc::IPPROTO_IPV6 && name == IPV6_MULTICAST_ALL {
            let Some(v) = read_int(val, len) else {
                return Some(Err(libc::EINVAL));
            };
            rec.state().dgram.mc6_all = v != 0;
            return Some(Ok(()));
        }
        let _ = (shared, rec, val, len);
        None
    }

    /// Binds `rec` to interface `index` (0 unbinds), failing with `unknown` for an index the sim
    /// does not have: `ENODEV` on Linux, `ENXIO` on macOS.
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    fn bind_index(
        shared: &SimShared,
        rec: &SockRec,
        index: c_int,
        unknown: c_int,
    ) -> Result<(), c_int> {
        if index == 0 {
            rec.state().device = None;
            return Ok(());
        }
        let Some(name) = u32::try_from(index)
            .ok()
            .and_then(|i| shared.topo().name_of(i))
        else {
            return Err(unknown);
        };
        rec.state().device = Some((index as u32, name));
        Ok(())
    }

    /// Reads an interface-binding option back; `None` when `(level, name)` is not one. The index
    /// options read back as an `int`, 0 when unset, and Linux `IP_MULTICAST_ALL`/
    /// `IPV6_MULTICAST_ALL` as an `int` 0 or 1. `IP_MULTICAST_IF` is not read here.
    ///
    /// # Safety
    /// `val`/`len` are the caller's getsockopt buffer.
    pub(crate) unsafe fn get(
        rec: &SockRec,
        level: c_int,
        name: c_int,
        val: *mut u8,
        len: *mut u32,
    ) -> Option<()> {
        #[cfg(target_os = "linux")]
        if level == libc::SOL_SOCKET && name == SO_BINDTODEVICE {
            // man 7 socket: the bound name, NUL-terminated; length 0 when unbound
            // (net/core/sock.c sock_getbindtodevice). Linux fails a buffer shorter than IFNAMSIZ
            // (16) with EINVAL; snare instead truncates the name to the buffer.
            let dev = rec.state().device.clone();
            if !val.is_null() && !len.is_null() {
                let cap = unsafe { *len } as usize;
                let bytes = dev.map(|(_, n)| n.into_bytes()).unwrap_or_default();
                let n = if bytes.is_empty() {
                    0
                } else {
                    (bytes.len() + 1).min(cap)
                };
                unsafe {
                    std::ptr::write_bytes(val, 0, n);
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        val,
                        n.saturating_sub(1).min(bytes.len()),
                    );
                    *len = n as u32;
                }
            }
            return Some(());
        }
        let index = |dev: Option<(u32, String)>| dev.map_or(0, |(i, _)| i as c_int);
        #[cfg(target_os = "linux")]
        let value = (level == libc::SOL_SOCKET && name == SO_BINDTOIFINDEX)
            .then(|| index(rec.state().device.clone()));
        #[cfg(target_os = "macos")]
        let value = ((level == libc::IPPROTO_IP && name == IP_BOUND_IF)
            || (level == libc::IPPROTO_IPV6 && name == IPV6_BOUND_IF))
            .then(|| index(rec.state().device.clone()));
        #[cfg(target_os = "linux")]
        let value = value.or_else(|| {
            let dgram = rec.state().dgram;
            match (level, name) {
                (libc::IPPROTO_IP, IP_MULTICAST_ALL) => Some(dgram.mc_all as c_int),
                (libc::IPPROTO_IPV6, IPV6_MULTICAST_ALL) => Some(dgram.mc6_all as c_int),
                _ => None,
            }
        });
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let value: Option<c_int> = None;
        let value = value.or_else(|| {
            (level == libc::IPPROTO_IPV6 && name == libc::IPV6_MULTICAST_IF)
                .then(|| index(rec.state().mcast_if.clone()))
        })?;
        unsafe { crate::fabric::write_opt(value, val, len) };
        Some(())
    }
}

/// The don't-fragment socket options and what they do to a datagram larger than its egress
/// interface's MTU. The sim never fragments on the wire: without don't-fragment such a datagram is
/// delivered whole, as reassembly would leave it; with it, the send fails `EMSGSIZE` as the host's
/// stack fails it before anything leaves.
///
/// - Linux: `IP_MTU_DISCOVER` and `IPV6_MTU_DISCOVER` take an `IP_PMTUDISC_*` mode, 0 to 5, else
///   `EINVAL` (net/ipv4/ip_sockglue.c `do_ip_setsockopt`, net/ipv6/ipv6_sockglue.c
///   `do_ipv6_setsockopt`). A datagram may not be fragmented under `DO`, `PROBE` and `INTERFACE`;
///   `DONT`, `WANT` and `OMIT` let it be (include/net/ip.h `ip_sk_ignore_df`, include/net/ipv6.h
///   `ip6_sk_ignore_df`), and then `__ip_append_data` / `__ip6_append_data` fail it with
///   `EMSGSIZE` once payload and headers pass the MTU. `IPV6_DONTFRAG` refuses fragmentation of
///   IPv6 datagrams whatever the mode (`__ip6_append_data`; RFC 3542 §11.2). An IPv4 datagram,
///   from an IPv4 socket or an IPv6 one sending to a v4-mapped address, follows
///   `IP_MTU_DISCOVER`; an IPv6 one follows the IPv6 options.
/// - macOS: `IP_DONTFRAG` (IPv4 sockets only, else `EINVAL`: XNU bsd/netinet/ip_output.c
///   `ip_ctloutput`, "This option is settable only for IPv4") and `IPV6_DONTFRAG` (IPv6 sockets
///   only, `EINVAL` on an IPv4 one) are flags; `ip_output` / `ip6_output` fail a don't-fragment
///   packet larger than the interface MTU with `EMSGSIZE`. `IPV6_DONTFRAG` covers an IPv6
///   socket's v4-mapped sends too.
///
/// The bounds are the payload plus 8 bytes of UDP header plus 20 of IPv4 or 40 of IPv6 header (no
/// IP options or extension headers are modelled), against the egress interface's configured MTU:
/// the sim learns no smaller path MTU. Linux's `IP_RECVERR` report of a local `EMSGSIZE`
/// (`ip_local_error`) is not modelled. Everything here was measured on loopback by
/// tests/dontfrag.rs `dontfrag_os_truth`, including the option values, the optlen rules and the
/// wrong-family errors.
#[cfg(unix)]
pub(crate) mod frag {
    use std::ffi::c_int;
    use std::net::{IpAddr, SocketAddr};

    use crate::scope::SimShared;
    use crate::sockets::SockRec;

    use super::Sender;

    /// Linux `IP_MTU_DISCOVER` (10, include/uapi/linux/in.h).
    #[cfg(target_os = "linux")]
    const IP_MTU_DISCOVER: c_int = 10;
    /// Linux `IPV6_MTU_DISCOVER` (23, include/uapi/linux/in6.h).
    #[cfg(target_os = "linux")]
    const IPV6_MTU_DISCOVER: c_int = 23;
    /// macOS `IP_DONTFRAG` (28, XNU bsd/netinet/in.h).
    #[cfg(target_os = "macos")]
    const IP_DONTFRAG: c_int = 28;
    /// `IPV6_DONTFRAG`: 62 on Linux (include/uapi/linux/in6.h) and macOS (XNU
    /// bsd/netinet6/in6.h).
    const IPV6_DONTFRAG: c_int = 62;
    /// The highest `IP_PMTUDISC_*`/`IPV6_PMTUDISC_*` mode, `IP_PMTUDISC_OMIT` (5,
    /// include/uapi/linux/in.h and in6.h).
    #[cfg(target_os = "linux")]
    const PMTUDISC_OMIT: c_int = 5;
    /// `IP_PMTUDISC_DO` (2), `IP_PMTUDISC_PROBE` (3) and `IP_PMTUDISC_INTERFACE` (4): the modes
    /// that keep a datagram whole (include/net/ip.h `ip_sk_ignore_df`).
    const PMTUDISC_NO_FRAG: std::ops::RangeInclusive<u8> = 2..=4;
    /// The UDP header (RFC 768).
    const UDP_HEADER: usize = 8;
    /// The IPv4 header without options (RFC 791 §3.1).
    const IPV4_HEADER: usize = 20;
    /// The IPv6 header (RFC 8200 §3).
    const IPV6_HEADER: usize = 40;

    /// What `setsockopt` or `getsockopt` of a don't-fragment option fails with on a socket of the
    /// other family: on Linux an IPv6 option on an IPv4 socket is `ENOPROTOOPT` to set and
    /// `EOPNOTSUPP` to read (net/ipv4/udp.c hands `SOL_IPV6` to `ip_setsockopt`, which knows no
    /// such level), on macOS either family's option on the other is `EINVAL`.
    #[cfg(target_os = "linux")]
    fn wrong_family(set: bool) -> c_int {
        if set {
            libc::ENOPROTOOPT
        } else {
            libc::EOPNOTSUPP
        }
    }

    /// The `int` an option value holds, read as Linux's `do_ip_setsockopt` reads it: a full `int`,
    /// else a single byte, else 0.
    #[cfg(target_os = "linux")]
    fn read_ip_int(val: *const u8, len: u32) -> c_int {
        if val.is_null() || len == 0 {
            return 0;
        }
        if (len as usize) < size_of::<c_int>() {
            return c_int::from(unsafe { *val });
        }
        unsafe { val.cast::<c_int>().read_unaligned() }
    }

    /// The `int` of a value at least an `int` long, `None` for a null or shorter one.
    fn read_full_int(val: *const u8, len: u32) -> Option<c_int> {
        if val.is_null() || (len as usize) < size_of::<c_int>() {
            return None;
        }
        Some(unsafe { val.cast::<c_int>().read_unaligned() })
    }

    /// Sets a don't-fragment option on `rec`, an IPv6 socket if `v6`; `None` when `(level, name)`
    /// is not one. See the module for the rules.
    ///
    /// # Safety
    /// `val` points to `len` readable bytes.
    #[cfg(target_os = "linux")]
    pub(crate) unsafe fn set(
        rec: &SockRec,
        v6: bool,
        level: c_int,
        name: c_int,
        val: *const u8,
        len: u32,
    ) -> Option<Result<(), c_int>> {
        match (level, name) {
            (libc::IPPROTO_IP, IP_MTU_DISCOVER) => {
                let mode = read_ip_int(val, len);
                if !(0..=PMTUDISC_OMIT).contains(&mode) {
                    return Some(Err(libc::EINVAL));
                }
                rec.state().frag.pmtudisc = mode as u8;
                Some(Ok(()))
            }
            (libc::IPPROTO_IPV6, IPV6_MTU_DISCOVER | IPV6_DONTFRAG) if !v6 => {
                Some(Err(wrong_family(true)))
            }
            (libc::IPPROTO_IPV6, IPV6_MTU_DISCOVER) => match read_full_int(val, len) {
                Some(mode) if (0..=PMTUDISC_OMIT).contains(&mode) => {
                    rec.state().frag.pmtudisc6 = mode as u8;
                    Some(Ok(()))
                }
                _ => Some(Err(libc::EINVAL)),
            },
            (libc::IPPROTO_IPV6, IPV6_DONTFRAG) => {
                // do_ipv6_setsockopt reads a value shorter than an int as 0.
                rec.state().frag.dontfrag6 = read_full_int(val, len).unwrap_or(0) != 0;
                Some(Ok(()))
            }
            _ => None,
        }
    }

    /// Sets a don't-fragment option on `rec`, an IPv6 socket if `v6`; `None` when `(level, name)`
    /// is not one. See the module for the rules.
    ///
    /// # Safety
    /// `val` points to `len` readable bytes.
    #[cfg(target_os = "macos")]
    pub(crate) unsafe fn set(
        rec: &SockRec,
        v6: bool,
        level: c_int,
        name: c_int,
        val: *const u8,
        len: u32,
    ) -> Option<Result<(), c_int>> {
        let ipv6 = match (level, name) {
            (libc::IPPROTO_IP, IP_DONTFRAG) if !v6 => false,
            (libc::IPPROTO_IPV6, IPV6_DONTFRAG) if v6 => true,
            (libc::IPPROTO_IP, IP_DONTFRAG) | (libc::IPPROTO_IPV6, IPV6_DONTFRAG) => {
                return Some(Err(libc::EINVAL));
            }
            _ => return None,
        };
        // sooptcopyin refuses a value shorter than the int it copies with EINVAL.
        let Some(on) = read_full_int(val, len) else {
            return Some(Err(libc::EINVAL));
        };
        let mut state = rec.state();
        if ipv6 {
            state.frag.dontfrag6 = on != 0;
        } else {
            state.frag.dontfrag = on != 0;
        }
        Some(Ok(()))
    }

    /// Reads a don't-fragment option of `rec` back as an `int` (the mode, or 0/1 for a flag);
    /// `None` when `(level, name)` is not one.
    ///
    /// # Safety
    /// `val`/`len` are the caller's getsockopt buffer.
    pub(crate) unsafe fn get(
        rec: &SockRec,
        v6: bool,
        level: c_int,
        name: c_int,
        val: *mut u8,
        len: *mut u32,
    ) -> Option<Result<(), c_int>> {
        let frag = rec.state().frag;
        #[cfg(target_os = "linux")]
        let value = match (level, name) {
            (libc::IPPROTO_IP, IP_MTU_DISCOVER) => c_int::from(frag.pmtudisc),
            (libc::IPPROTO_IPV6, IPV6_MTU_DISCOVER | IPV6_DONTFRAG) if !v6 => {
                return Some(Err(wrong_family(false)));
            }
            (libc::IPPROTO_IPV6, IPV6_MTU_DISCOVER) => c_int::from(frag.pmtudisc6),
            (libc::IPPROTO_IPV6, IPV6_DONTFRAG) => c_int::from(frag.dontfrag6),
            _ => return None,
        };
        #[cfg(target_os = "macos")]
        let value = match (level, name) {
            (libc::IPPROTO_IP, IP_DONTFRAG) if !v6 => c_int::from(frag.dontfrag),
            (libc::IPPROTO_IPV6, IPV6_DONTFRAG) if v6 => c_int::from(frag.dontfrag6),
            (libc::IPPROTO_IP, IP_DONTFRAG) | (libc::IPPROTO_IPV6, IPV6_DONTFRAG) => {
                return Some(Err(libc::EINVAL));
            }
            _ => return None,
        };
        unsafe { write_int(value, val, len) };
        Some(Ok(()))
    }

    /// Writes an `int` option value into a buffer of `*len` bytes and sets `*len` to what was
    /// written. A buffer shorter than an `int` gets one byte on Linux, the value as an `unsigned
    /// char` (`do_ip_getsockopt`, and `do_ipv6_getsockopt` alike for these options), and the
    /// leading bytes of the `int` on macOS (`sooptcopyout` copies `min(valsize, sizeof(int))`).
    ///
    /// # Safety
    /// `val` and `len` are each null or valid, `val` writable for `*len` bytes.
    unsafe fn write_int(value: c_int, val: *mut u8, len: *mut u32) {
        if val.is_null() || len.is_null() {
            return;
        }
        let cap = unsafe { *len } as usize;
        let n = size_of::<c_int>().min(cap);
        let n = if cfg!(target_os = "linux") && n < size_of::<c_int>() {
            n.min(1)
        } else {
            n
        };
        let bytes = if cfg!(target_os = "linux") && n == 1 {
            [value as u8, 0, 0, 0]
        } else {
            value.to_ne_bytes()
        };
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), val, n);
            *len = n as u32;
        }
    }

    /// Whether a datagram from `rec` (an IPv6 socket if `v6`) to `dest` may not be fragmented, and
    /// the IP and UDP headers it carries.
    fn no_frag(rec: &SockRec, v6: bool, dest: SocketAddr) -> (bool, usize) {
        let frag = rec.state().frag;
        let v4_dest = match dest.ip() {
            IpAddr::V4(_) => true,
            IpAddr::V6(ip) => ip.to_ipv4_mapped().is_some(),
        };
        let headers = UDP_HEADER + if v4_dest { IPV4_HEADER } else { IPV6_HEADER };
        let keep_whole = if cfg!(target_os = "linux") {
            if v4_dest {
                PMTUDISC_NO_FRAG.contains(&frag.pmtudisc)
            } else {
                PMTUDISC_NO_FRAG.contains(&frag.pmtudisc6) || frag.dontfrag6
            }
        } else if v6 {
            frag.dontfrag6
        } else {
            frag.dontfrag
        };
        (keep_whole, headers)
    }

    /// Refuses with `EMSGSIZE` a datagram of `len` payload bytes from `rec` (an IPv6 socket if
    /// `v6`) to `dest` that may not be fragmented and is larger, with its headers, than the MTU
    /// of the interface `sender` leaves through. A station's datagram crosses no interface of the
    /// host and is never refused.
    pub(crate) fn check_send(
        shared: &SimShared,
        rec: &SockRec,
        v6: bool,
        sender: &Sender,
        dest: SocketAddr,
        len: usize,
    ) -> Result<(), c_int> {
        let Sender::Host(path) = sender else {
            return Ok(());
        };
        let (keep_whole, headers) = no_frag(rec, v6, dest);
        if !keep_whole {
            return Ok(());
        }
        let Some(mtu) = shared.nic(&path.name).map(|nic| nic.spec.mtu as usize) else {
            return Ok(());
        };
        if len.saturating_add(headers) > mtu {
            return Err(libc::EMSGSIZE);
        }
        Ok(())
    }
}
