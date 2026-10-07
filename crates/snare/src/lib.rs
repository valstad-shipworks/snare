//! Ergonomic in-process network testing, built on [`snare_interpose`].
//!
//! Write the code under test against plain `std::net`. In a test, create a [`Sim`], run the code
//! inside it, and describe the peer it talks to with a [`Tester`] — the same shape as the original
//! snare's `connect_tester` / `then_action` / `with_cyclic_action` / `run_testers!`.
//!
//! ```no_run
//! use std::io::{BufRead, BufReader, Write};
//! use std::net::TcpStream;
//! use std::time::Duration;
//! use snare::{connect_tester, run_testers, Line, Sim, TesterAction};
//!
//! let sim = Sim::new();
//! sim.run(|| {
//!     let server = connect_tester::<Line>("127.0.0.2:9000")
//!         .then_action(|msg, _from| TesterAction::Send(Line(format!("echo:{}", msg.0))))
//!         .until_after(Duration::from_millis(200));
//!
//!     let client = std::thread::spawn(|| {
//!         let mut stream = TcpStream::connect("127.0.0.2:9000").unwrap();
//!         stream.write_all(b"hello\n").unwrap();
//!         let mut line = String::new();
//!         BufReader::new(stream).read_line(&mut line).unwrap();
//!         line
//!     });
//!
//!     run_testers!(server);
//!     assert_eq!(client.join().unwrap(), "echo:hello\n");
//! });
//! ```
//!
//! The code under test uses real `TcpStream`; its socket calls are serviced from process memory,
//! and the tester is the other end of the wire. Threads spawned inside [`Sim::run`] join the
//! simulation automatically.
//!
//! Every resource or object used by the code under test must be created under its active
//! simulation, including dependency and worker initialization. [`real`] is reserved for the
//! harness and other-side emulation; it must not wrap the code under test or its constructors.
//!
//! TCP (`SOCK_STREAM`) and UDP (`SOCK_DGRAM`) over IPv4/IPv6 are both serviced from memory, with
//! blocking or non-blocking sockets, `poll`, and readiness via `epoll` (Linux) or `kqueue` (macOS)
//! — so `mio`-based code runs on both. UDP covers `bind`/`connect`/`sendto`/`recvfrom`, blocking
//! cross-thread receive, broadcast, multicast and several addresses sharing a port.
//!
//! This file holds only the public front: the unix [`Sim`] / [`SimBuilder`] (the Windows ones live
//! in `win_host`), the [`TimeHandle`] onto a sim's clock, and the re-exports. Everything a sim
//! owns sits in one `scope::SimShared`, which every backend reaches either through the `Sim`
//! (from any thread) or through the calling thread's scope (from inside [`Sim::run`]); the free
//! functions such as [`add_nic`] and [`add_host`] take the second route and panic off a sim.

#[cfg(not(any(
    all(
        target_os = "linux",
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    all(windows, any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
compile_error!(
    "snare supports only x86_64/aarch64 Linux (glibc), macOS, and x86_64/aarch64 Windows; \
     gate the dependency on `cfg(any(all(target_os = \"linux\", target_env = \"gnu\", \
     any(target_arch = \"x86_64\", target_arch = \"aarch64\")), target_os = \"macos\", windows))`"
);

mod clock;
mod dns;
#[cfg(unix)]
mod ethtool;
mod events;
mod executive;
#[cfg(unix)]
mod fabric;
mod faults;
#[cfg(unix)]
mod fs_sim;
#[cfg(unix)]
mod ifaddrs;
#[cfg(windows)]
mod iphlp;
mod limits;
mod netif;
mod netpolicy;
mod netstats;
mod packet;
mod pcapng;
#[cfg(unix)]
mod proclimits;
#[cfg(target_os = "linux")]
mod procnet;
#[cfg(target_os = "linux")]
mod qdisc;
mod random;
mod readiness;
pub mod sched;
mod scope;
mod signals;
#[cfg(unix)]
mod simhost;
mod sockets;
mod stream;
#[cfg(target_os = "linux")]
mod tcp_transport;
mod tester;
#[cfg(unix)]
mod tstamp;

#[cfg(windows)]
mod win_adapter;
#[cfg(windows)]
mod win_host;
#[cfg(windows)]
mod win_net;
#[cfg(windows)]
mod win_sockopt;

use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use snare_interpose::Domain;

use crate::clock::Clock;
#[cfg(unix)]
use crate::clock::ClockLayer;
use crate::scope::SimShared;

pub use dns::{
    DnsFailure, DnsPolicy, add_host, remove_host, set_default_dns_policy, set_dns_policy,
};
#[cfg(unix)]
pub use ethtool::{Channels, Coalesce, CoalesceParams, Eee, FlowRule, NicEthtool, Pause, Rings};
pub use events::{
    Direction, Fault, LinkFault, RecordedEntry, RecordedEvent, Toward, Transport,
    clear_recorded_events, recorded_events,
};
#[cfg(unix)]
pub use fabric::Fabric;
pub use faults::{
    ListenerBehavior, inject_icmp_port_unreachable, quiesce, raise_socket_error,
    set_listener_behavior,
};
#[cfg(unix)]
pub use fs_sim::{FsBuilder, VirtualFs};
pub use limits::{
    Privileges, Rlimit, SysLimits, privileges, set_privileges, set_sys_limits, sys_limits,
};
pub use netif::{
    IpNet, NicCounters, NicPolicy, NicSnapshot, NicSpec, ParseIpNetError, Route, RouteChoice,
    add_nic, add_route, nic, nic_counters, nics, remove_nic, remove_route, route_lookup, routes,
    schedule_link, set_default_route, set_link, set_nic, set_nic_counters, set_nic_policy,
};
pub use netpolicy::{TcpPolicy, UdpPolicy, set_tcp_policy, set_udp_policy};
pub use netstats::{ProtoCounters, TcpCounters, UdpCounters, proto_counters};
pub use packet::{
    Bytes, Cr, CrLf, Delimited, Delimiter, Endian, FrameLength, LengthField, LengthPrefixed, Lf,
    Line, Packet,
};
pub use signals::{PendingSignal, Signal, SignalDelivery, SignalHandle, SignalOrigin};
#[cfg(unix)]
pub use simhost::{
    CAP_IPC_LOCK, CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_SYS_NICE, EasyBuilder,
    HostProfile, LinkStats, Nic, PtpCaps, SimHost,
};
#[doc(hidden)]
pub use sockets::__set_pending_error;
pub use sockets::{
    Membership, SocketEntry, SocketId, SocketKind, UnmodelledOption, closed_sockets,
    inject_socket_drops, set_socket_device, socket_entry, socket_id, socket_table, sockets_bound,
};
pub use tester::{Recorder, Tester, TesterAction, connect_tester, udp_tester};
#[doc(hidden)]
pub use tester::{RunTester as __RunTester, run_testers as __run_testers};

#[cfg(windows)]
pub use win_adapter::{Adapter, AdapterKey, AdvancedProperty, RegValue};
#[cfg(windows)]
pub use win_host::{MmcssTask, PowerThrottling, Sim, SimBuilder, WinHost, WorkingSet};

/// The file plane `fs` with, on Linux, the sim's `/proc/net/snmp` and `/proc/net/snmp6` in front
/// of it ([`procnet`]).
#[cfg(unix)]
fn with_proc_net(
    shared: &Arc<SimShared>,
    fs: Arc<dyn snare_interpose::Fs>,
) -> Arc<dyn snare_interpose::Fs> {
    #[cfg(target_os = "linux")]
    return Arc::new(fs_sim::FsChain(vec![
        Arc::new(procnet::ProcNetFs::new(shared)),
        fs,
    ]));
    #[cfg(not(target_os = "linux"))]
    {
        let _ = shared;
        fs
    }
}

/// The file plane of a sim with a `SimHost`: the host's synthetic `/sys`, `/proc` and `/dev`
/// first, then `fs` for every path the host declines.
#[cfg(unix)]
fn host_files(host: &Arc<SimHost>, fs: Option<&Arc<VirtualFs>>) -> Arc<dyn snare_interpose::Fs> {
    match fs {
        Some(fs) => Arc::new(fs_sim::FsChain(vec![host.clone(), fs.clone()])),
        None => host.clone(),
    }
}

/// Runs `f` with the calling thread's OS calls going to the real OS, even inside a [`Sim::run`].
/// Reserved for the test harness and other-side emulation that need real files, the real
/// environment or real sockets. The code under test and all its resource construction must stay
/// under the active simulation, outside this closure. Wrap an
/// ordinary std call in it, e.g. `snare::real(|| std::fs::read(path))` or
/// `snare::real(|| std::env::var("KEY"))`.
pub use snare_interpose::real;

#[cfg(not(snare))]
compile_error!(
    "snare must be built with `--cfg snare`. Run the tests with `cargo snare test`, which sets it \
     and routes rustix and the raw-syscall crates through libc where snare can see them. \
     `cargo snare --init` moves snare under `[target.'cfg(snare)'.dev-dependencies]` so plain \
     `cargo test` leaves it out."
);

/// The items most tests use: `use snare::prelude::*;`.
pub mod prelude {
    pub use crate::{
        Bytes, Delimited, Direction, FrameLength, IpNet, LengthPrefixed, Line, ListenerBehavior,
        NicPolicy, NicSpec, Packet, Privileges, Recorder, Rlimit, Sim, SimBuilder, SocketKind,
        SysLimits, TcpPolicy, Tester, TesterAction, UdpPolicy, connect_tester,
        inject_icmp_port_unreachable, raise_socket_error, real, run_testers, set_listener_behavior,
        set_tcp_policy, set_udp_policy, udp_tester,
    };
    #[cfg(unix)]
    pub use crate::{HostProfile, Nic, SimHost};
}

/// A running simulation: a [`Domain`] whose managed threads' sockets are
/// serviced by an in-memory [`Fabric`], and whose file operations may be served by a
/// [`VirtualFs`]. One per test.
#[cfg(unix)]
pub struct Sim {
    /// The interposer domain the run's threads join; dropping it uninstalls the sim's backends.
    domain: Domain,
    /// Everything the sim owns: clock, sockets, topology, DNS, events, capture.
    shared: Arc<SimShared>,
    /// The network backend; also the net plane behind a [`SimHost`], and the file plane when no
    /// [`VirtualFs`] is given. Held so it lives exactly as long as the sim.
    _fabric: Arc<Fabric>,
    /// The file backend, if one was given; held for the sim's lifetime.
    _fs: Option<Arc<VirtualFs>>,
    /// The host backend, if one was given; held for the sim's lifetime.
    _host: Option<Arc<SimHost>>,
    /// This sim's place among the real-signal forwarders; dropping it unregisters, and the last
    /// one to go restores the process's own handlers.
    _forward: Option<signals::forward::Registration>,
}

#[cfg(unix)]
impl std::fmt::Debug for Sim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sim")
            .field("id", &self.domain.id())
            .finish_non_exhaustive()
    }
}

/// Drops the sim's [`snare_interpose::sim_local`] values inside a last run, so a shim's per-sim
/// reactor shuts down in the sim that made it. Then writes out the frames still due and closes
/// the capture file: threads that outlive the sim may still hold its registries.
#[cfg(unix)]
impl Drop for Sim {
    fn drop(&mut self) {
        let locals = self.domain.take_locals();
        if !locals.is_empty() {
            self.run(move || drop(locals));
        }
        if let Some(capture) = self.shared.capture() {
            capture.finish();
        }
    }
}

#[cfg(unix)]
impl Default for Sim {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
impl Sim {
    /// Starts a fresh simulation with just the network fabric.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Composes a simulation with an optional [`VirtualFs`].
    pub fn builder() -> SimBuilder {
        SimBuilder::default()
    }

    /// Runs `f` with the calling thread — and every thread it spawns — inside the simulation.
    pub fn run<R>(&self, f: impl FnOnce() -> R) -> R {
        // Scope this sim's registries to the run so `connect_tester` / `add_nic` (called on this
        // thread) reach exactly this sim, never another test's.
        let _registries = fabric::enter(self._fabric.registries());
        self.domain.run(f)
    }

    /// Holds virtual time: reads return the same instant, and every sleep and timed wait blocks
    /// until time is moved — by [`advance_time`](Self::advance_time),
    /// [`set_time_value`](Self::set_time_value) or [`resume_time`](Self::resume_time) — from a
    /// thread that is not itself waiting on the clock.
    #[track_caller]
    pub fn pause_time(&self) {
        self.time().pause();
    }

    /// Restarts a paused clock in the mode and at the rate it had before the pause.
    #[track_caller]
    pub fn resume_time(&self) {
        self.time().resume();
    }

    /// Moves virtual time forward by `by`, whether or not it is paused, waking the sleepers and
    /// timeouts it reaches.
    #[track_caller]
    pub fn advance_time(&self, by: Duration) {
        self.time().advance(by);
    }

    /// Runs the clock scaled to real time at `rate` virtual seconds per real second (capped at
    /// 1e6), pauses it at 0.0, or returns it at `f64::INFINITY` to virtual time — discrete-event,
    /// or as-fast-as-possible for a sim built with `wall_clock` — keeping the current reading.
    /// Panics on a negative or NaN rate, and on a finite rate above zero in a
    /// [`deterministic`](SimBuilder::deterministic) sim.
    #[track_caller]
    pub fn set_time_rate(&self, rate: f64) {
        self.time().set_rate(rate);
    }

    /// 0.0 while paused, the rate while scaled to real time, `f64::INFINITY` on virtual time.
    #[track_caller]
    pub fn time_rate(&self) -> f64 {
        self.time().rate()
    }

    /// Sets sim time to `value`, moving `CLOCK_MONOTONIC` and the realtime clocks by the same step.
    /// Forward only: panics, leaving the clock alone, if `value` is before
    /// [`time_value`](Self::time_value).
    #[track_caller]
    pub fn set_time_value(&self, value: Duration) {
        self.time().set_value(value);
    }

    /// Sim time, without ticking the clock: how far the sim's clock has moved since it was built,
    /// which is also how far `CLOCK_REALTIME` is past its fixed epoch (2023-11-14T22:13:20Z, Unix
    /// time 1 700 000 000 s: a snare choice, a round recent instant so timestamps look plausible).
    /// `CLOCK_MONOTONIC` reads the same value, so every sim's monotonic clock starts at zero and a
    /// replay reads identical absolute instants. An `Instant` from outside the sim, or from an
    /// earlier sim, belongs to another timeline and may look ahead of one taken in it.
    #[track_caller]
    pub fn time_value(&self) -> Duration {
        self.time().value()
    }

    /// A cloneable, `Send`-able handle to this sim's clock, usable from any thread, inside the
    /// run or outside it. Panics on a sim built with
    /// [`wall_clock`](SimBuilder::wall_clock) alone, which runs on the real clock.
    #[track_caller]
    pub fn time(&self) -> TimeHandle {
        self.shared.time()
    }

    /// Everything this sim has recorded so far, oldest first: what crossed its testers'
    /// boundaries, what its link policies did and which faults took effect. Readable from any
    /// thread, during the run or after it.
    pub fn recorded_events(&self) -> Vec<RecordedEntry> {
        self.shared.events.snapshot()
    }

    /// Empties this sim's log, so what follows can be read on its own.
    pub fn clear_recorded_events(&self) {
        self.shared.events.clear();
    }

    /// The pcapng file this sim captures to, if it captures; see [`SimBuilder::pcapng`].
    pub fn pcapng_path(&self) -> Option<&std::path::Path> {
        self.shared.capture().map(|c| c.path())
    }

    /// Socket `id` of this sim, open or closed; see [`socket_entry`].
    pub fn socket_entry(&self, id: SocketId) -> Option<SocketEntry> {
        self.shared.socket_entry(id)
    }

    /// This sim's open sockets, oldest first; see [`socket_table`].
    pub fn socket_table(&self) -> Vec<SocketEntry> {
        self.shared.socket_table()
    }

    /// This sim's closed sockets, in the order they closed; see [`closed_sockets`].
    pub fn closed_sockets(&self) -> Vec<SocketEntry> {
        self.shared.closed_sockets()
    }

    /// See [`inject_socket_drops`].
    pub fn inject_socket_drops(&self, id: SocketId, n: u32) -> std::io::Result<()> {
        self.shared.inject_socket_drops(id, n)
    }

    /// See [`set_socket_device`].
    pub fn set_socket_device(&self, id: SocketId, nic: Option<&str>) -> std::io::Result<()> {
        self.shared.set_socket_device(id, nic)
    }

    /// This sim's protocol counters; see [`proto_counters`].
    pub fn proto_counters(&self) -> ProtoCounters {
        self.shared.proto_counters()
    }

    /// What the code under test may do in this sim; see [`set_privileges`].
    pub fn privileges(&self) -> Privileges {
        self.shared.sys.privileges()
    }

    /// Changes this sim's privileges from then on, from any thread.
    pub fn set_privileges(&self, change: impl FnOnce(&mut Privileges)) {
        self.shared.sys.set_privileges(change);
    }

    /// This sim's socket limits; see [`set_sys_limits`].
    pub fn sys_limits(&self) -> SysLimits {
        self.shared.sys.limits()
    }

    /// Changes this sim's socket limits for sockets created from then on, from any thread.
    pub fn set_sys_limits(&self, change: impl FnOnce(&mut SysLimits)) {
        self.shared.sys.set_limits(change);
    }

    /// Adds an interface to this sim; see [`add_nic`].
    pub fn add_nic(&self, spec: NicSpec) -> std::io::Result<u32> {
        self.shared.add_nic(spec)
    }

    /// See [`remove_nic`].
    pub fn remove_nic(&self, name: &str) -> std::io::Result<()> {
        self.shared.remove_nic(name)
    }

    /// See [`set_nic`].
    pub fn set_nic(&self, name: &str, change: impl FnOnce(&mut NicSpec)) -> std::io::Result<()> {
        self.shared.set_nic(name, change)
    }

    /// See [`set_link`].
    pub fn set_link(&self, name: &str, carrier: bool) -> std::io::Result<()> {
        self.shared.set_link(name, carrier)
    }

    /// See [`schedule_link`].
    pub fn schedule_link(&self, name: &str, after: Duration, carrier: bool) -> std::io::Result<()> {
        self.shared.schedule_link(name, after, carrier)
    }

    /// See [`set_nic_policy`].
    pub fn set_nic_policy(
        &self,
        name: &str,
        change: impl FnOnce(&mut NicPolicy),
    ) -> std::io::Result<()> {
        self.shared.set_nic_policy(name, change)
    }

    /// See [`set_nic_counters`].
    pub fn set_nic_counters(
        &self,
        name: &str,
        change: impl FnOnce(&mut NicCounters),
    ) -> std::io::Result<()> {
        self.shared.set_nic_counters(name, change)
    }

    /// This sim's interface `name`, if it has one; see [`nic`].
    pub fn nic(&self, name: &str) -> Option<NicSnapshot> {
        self.shared.nic(name)
    }

    /// This sim's interfaces; see [`nics`].
    pub fn nics(&self) -> Vec<NicSnapshot> {
        self.shared.nics()
    }

    /// The counters of this sim's interface `name`; see [`nic_counters`].
    pub fn nic_counters(&self, name: &str) -> Option<NicCounters> {
        self.shared.nic_counters(name)
    }

    /// Adds a route to this sim; see [`add_route`].
    pub fn add_route(&self, route: Route) -> std::io::Result<()> {
        self.shared.add_route(route)
    }

    /// Removes this sim's route to `dest`, returning whether there was one; see
    /// [`remove_route`].
    pub fn remove_route(&self, dest: IpNet) -> bool {
        self.shared.remove_route(dest)
    }

    /// See [`set_default_route`].
    pub fn set_default_route(&self, nic: Option<&str>) -> std::io::Result<()> {
        self.shared.set_default_route(nic)
    }

    /// This sim's routing table; see [`routes`].
    pub fn routes(&self) -> Vec<Route> {
        self.shared.routes()
    }

    /// See [`route_lookup`].
    pub fn route_lookup(
        &self,
        src: Option<std::net::IpAddr>,
        dst: std::net::IpAddr,
    ) -> std::io::Result<RouteChoice> {
        self.shared.route_lookup(src, dst)
    }

    /// Holds this sim busy until the lease drops, from any thread, inside the run or outside it;
    /// see [`sched::busy`].
    pub fn busy(&self, label: &'static str) -> sched::BusyLease {
        sched::BusyLease::take(self.domain.clone(), label)
    }

    /// The leases holding this sim busy; see [`sched::held_leases`].
    pub fn held_leases(&self) -> Vec<sched::LeaseInfo> {
        self.domain.leases()
    }

    /// This sim's id: what [`sched::current_sim`] returns on its threads.
    pub fn id(&self) -> sched::SimId {
        self.domain.id()
    }

    /// Every OS thread of the process, this sim's told apart from other sims' and from unmanaged
    /// ones, from any thread; see [`sched::thread_census`].
    pub fn thread_census(&self) -> Option<sched::ThreadCensus> {
        snare_interpose::census(Some(&self.domain))
    }

    /// Resolves `name` to `addrs` in this sim, from any thread; see [`add_host`].
    pub fn add_host(&self, name: &str, addrs: impl IntoIterator<Item = std::net::IpAddr>) {
        self.shared.dns.add(name, addrs);
    }

    /// Forgets `name` in this sim, from any thread; see [`remove_host`].
    pub fn remove_host(&self, name: &str) {
        self.shared.dns.remove(name);
    }

    /// Changes how this sim answers lookups of `name`, from any thread; see [`set_dns_policy`].
    pub fn set_dns_policy(&self, name: &str, change: impl FnOnce(&mut DnsPolicy)) {
        self.shared.dns.update_policy(name, change);
    }

    /// Changes how this sim answers names without a policy of their own, from any thread; see
    /// [`set_default_dns_policy`].
    pub fn set_default_dns_policy(&self, change: impl FnOnce(&mut DnsPolicy)) {
        self.shared.dns.update_default_policy(change);
    }

    /// Delivers `signal` to the code under test as the host OS would and returns what it did; see
    /// [`SignalHandle::raise`].
    pub fn raise_signal(&self, signal: Signal) -> SignalDelivery {
        self.signals().raise(signal)
    }

    /// Delivers `signal` after `delay` of sim time; see [`SignalHandle::raise_after`].
    pub fn raise_signal_after(&self, signal: Signal, delay: Duration) -> PendingSignal {
        self.signals().raise_after(signal, delay)
    }

    /// A cloneable handle that sends signals into this sim from any thread.
    pub fn signals(&self) -> SignalHandle {
        SignalHandle::new(self.shared.clone())
    }

    /// Makes `addr` answer connects as `behavior` says, from any thread, inside the run or outside
    /// it; see [`set_listener_behavior`]. A `DelayingUntil` instant read on a thread outside the
    /// sim is taken as that far ahead of the sim's clock.
    pub fn set_listener_behavior(
        &self,
        addr: impl std::net::ToSocketAddrs,
        behavior: ListenerBehavior,
    ) {
        faults::set_listener_behavior_on(&self.shared, addr, behavior);
    }

    /// Raises `error` on the sockets at `addr`, from any thread, inside the run or outside it; see
    /// [`raise_socket_error`].
    pub fn raise_socket_error(&self, addr: impl std::net::ToSocketAddrs, error: std::io::Error) {
        crate::faults::raise_socket_error_on(&self.shared, addr, error);
    }

    /// Delivers an ICMP port unreachable from `from` to the datagram sockets at `to`, from any
    /// thread; see [`inject_icmp_port_unreachable`].
    pub fn inject_icmp_port_unreachable(
        &self,
        to: impl std::net::ToSocketAddrs,
        from: impl std::net::ToSocketAddrs,
    ) {
        crate::faults::inject_icmp_on(&self.shared, to, from);
    }

    /// Holds the traffic at `addr` for `span` in `direction`, from any thread; see
    /// [`quiesce`].
    pub fn quiesce(
        &self,
        addr: impl std::net::ToSocketAddrs,
        span: Duration,
        direction: crate::Direction,
    ) {
        crate::faults::quiesce_on(&self.shared, addr, span, direction);
    }

    /// Changes the TCP link policy at `addr`, from any thread; see
    /// [`set_tcp_policy`].
    pub fn set_tcp_policy(
        &self,
        addr: impl std::net::ToSocketAddrs,
        change: impl FnOnce(&mut crate::TcpPolicy),
    ) {
        crate::netpolicy::set_tcp_policy_on(&self.shared, addr, change);
    }

    /// Changes the datagram link policy at `addr`, from any thread; see
    /// [`set_udp_policy`].
    pub fn set_udp_policy(
        &self,
        addr: impl std::net::ToSocketAddrs,
        change: impl FnOnce(&mut crate::UdpPolicy),
    ) {
        crate::netpolicy::set_udp_policy_on(&self.shared, addr, change);
    }

    /// Hands this sim's clock to an [`Executive`](sched::Executive) until it drops, from any
    /// thread, inside the run or outside it.
    pub fn executive(
        &self,
        cfg: sched::ExecutiveConfig,
    ) -> Result<sched::Executive, sched::AttachError> {
        executive::attach_to(self.shared.clone(), self.domain.clone(), cfg)
    }
}

/// A handle to a [`Sim`]'s virtual clock, usable from any thread — one running inside the sim, or
/// one outside it driving time while every simulated thread waits. See the `Sim` methods of the
/// same names.
#[derive(Clone)]
pub struct TimeHandle {
    clock: Arc<Clock>,
    /// The sim the clock belongs to: consulted for executive ownership and kicked after a write.
    shared: Arc<SimShared>,
}

impl std::fmt::Debug for TimeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimeHandle")
            .field("now", &self.clock.value())
            .finish_non_exhaustive()
    }
}

impl TimeHandle {
    /// Applies one change to the clock. Panics first if an [`Executive`](sched::Executive) owns
    /// the clock. The change runs under [`real`] so the clock's own locks and condition variables
    /// are the real OS ones even when the caller is a simulated thread; afterwards every waiter is
    /// kicked to re-check its deadline. No sim lock is held across the kick.
    #[track_caller]
    fn write(&self, op: impl FnOnce(&Clock)) {
        self.shared.assert_clock_free();
        snare_interpose::real(|| op(&self.clock));
        self.shared.kick();
    }

    /// See [`Sim::pause_time`].
    #[track_caller]
    pub fn pause(&self) {
        self.write(Clock::pause);
    }

    /// See [`Sim::resume_time`].
    #[track_caller]
    pub fn resume(&self) {
        self.write(Clock::resume);
    }

    /// See [`Sim::advance_time`].
    #[track_caller]
    pub fn advance(&self, by: Duration) {
        self.write(|clock| clock.advance_by(by));
    }

    /// See [`Sim::set_time_rate`].
    #[track_caller]
    pub fn set_rate(&self, rate: f64) {
        self.shared.assert_clock_free();
        self.clock.check_rate(rate);
        self.write(|clock| clock.set_rate(rate));
    }

    /// See [`Sim::time_rate`].
    pub fn rate(&self) -> f64 {
        self.clock.rate()
    }

    /// See [`Sim::set_time_value`].
    #[track_caller]
    pub fn set_value(&self, value: Duration) {
        self.shared.assert_clock_free();
        if let Err(now) = snare_interpose::real(|| self.clock.set_value(value)) {
            panic!("time is monotonic: cannot set the clock back from {now:?} to {value:?}");
        }
        self.shared.kick();
    }

    /// See [`Sim::time_value`].
    pub fn value(&self) -> Duration {
        self.clock.value()
    }

    /// Whether the clock is paused.
    pub fn is_paused(&self) -> bool {
        self.clock.is_paused()
    }
}

/// The clock of the [`Sim`] the calling thread runs in — the test body or any thread it spawned.
/// Panics off a sim, and on a sim with no controllable clock (see [`Sim::time`]).
#[track_caller]
pub fn time() -> TimeHandle {
    scope::here().time()
}

/// Composes a [`Sim`] from a fabric plus optional backends.
#[cfg(unix)]
#[derive(Default)]
pub struct SimBuilder {
    fs: Option<Arc<VirtualFs>>,
    host: Option<Arc<SimHost>>,
    /// Set by [`wall_clock`](Self::wall_clock); overridden by `time_rate` and cleared by
    /// `deterministic`.
    wall_clock: bool,
    time_rate: Option<f64>,
    seed: u64,
    deterministic: bool,
    /// The inverse of [`record_events`](Self::record_events), so `Default` records.
    quiet: bool,
    /// Interfaces added on top of a [`SimHost`]'s own, in the order given.
    nics: Vec<NicSpec>,
    routes: Vec<Route>,
    /// Names, real-resolver snapshots and the real-DNS fallback, applied at `build`.
    dns: dns::DnsSetup,
    forward_signals: bool,
    /// See [`process_signal_handlers`](Self::process_signal_handlers).
    process_signal_handlers: bool,
    /// `None` keeps the default (or the host profile's), `Some` overrides it at `build`.
    privileges: Option<Privileges>,
    sys_limits: Option<SysLimits>,
    pcapng: Option<std::path::PathBuf>,
    /// See [`pcapng_wall_comment`](Self::pcapng_wall_comment).
    pcapng_wall_comment: bool,
    /// See [`stuck_after`](Self::stuck_after).
    stuck_after: Option<Duration>,
    /// See [`strict_sockopts`](Self::strict_sockopts).
    strict_sockopts: bool,
    #[cfg(target_os = "linux")]
    rx_timestamp_startup_delay: Duration,
}

#[cfg(unix)]
impl SimBuilder {
    /// What the code under test may do (default [`Privileges::all`], or what a [`SimHost`]'s
    /// profile grants); see [`set_privileges`].
    pub fn privileges(mut self, privileges: Privileges) -> Self {
        self.privileges = Some(privileges);
        self
    }

    /// The socket limits the sim starts with (default [`SysLimits::host`]).
    pub fn sys_limits(mut self, limits: SysLimits) -> Self {
        self.sys_limits = Some(limits);
        self
    }

    /// Sets the one-time startup delay for software receive timestamp generation.
    ///
    /// The default is zero: generation is already active. A nonzero delay starts on the first
    /// successful request to enable software receive timestamp generation anywhere in the sim,
    /// and runs on the sim's clock. Toggling timestamp options or enabling them on another socket
    /// does not restart the sim-wide startup window.
    #[cfg(target_os = "linux")]
    pub fn rx_timestamp_startup_delay(mut self, delay: Duration) -> Self {
        self.rx_timestamp_startup_delay = delay;
        self
    }

    /// Gives the sim an interface; see [`add_nic`].
    pub fn nic(mut self, spec: NicSpec) -> Self {
        self.nics.push(spec);
        self
    }

    /// Gives the sim a route; see [`add_route`].
    pub fn route(mut self, route: Route) -> Self {
        self.routes.push(route);
        self
    }

    /// Serves the code under test's file operations from `fs`.
    pub fn fs(mut self, fs: Arc<VirtualFs>) -> Self {
        self.fs = Some(fs);
        self
    }

    /// Runs the sim on the discrete-event virtual clock — the default, so this only states
    /// it. Time is deterministic and moves in two ways: when every managed thread is blocked it
    /// jumps to the next pending sleep or timeout (so a multi-second sleep finishes in
    /// microseconds of real time), and each call that returns without blocking costs a microsecond
    /// (so a thread busy-polling a ready socket still lets the timers it waits on fire). With a
    /// [`SimHost`] this is the host's clock, so its timestamps and PHC follow the same time.
    pub fn virtual_clock(mut self) -> Self {
        self.wall_clock = false;
        self
    }

    /// Runs the sim's threads deterministically: one at a time, switching only where a thread
    /// waits — a socket, sleep, mutex, condition variable, channel, park, join or yield — and
    /// always to the next runnable thread in a fixed order, so with the same [`seed`](Self::seed)
    /// a run replays exactly, interleavings included. It covers every participant of the run: the
    /// code under test, its testers and the test body, but not threads marked with
    /// [`sched::mark_background`] and the like, which run beside it. Implies the virtual clock,
    /// which may be paused, advanced and set but not scaled to real time.
    ///
    /// What it cannot see it cannot order: a thread spinning on an atomic without ever yielding
    /// keeps running, and a call that blocks in the OS outside snare's hooks blocks everyone.
    pub fn deterministic(mut self) -> Self {
        self.deterministic = true;
        self.wall_clock = false;
        self
    }

    /// Runs a plain `Sim` on the real wall clock instead of the virtual one, for a test that needs
    /// real elapsed time; such a sim has no clock to control. A [`SimHost`]'s clock stays virtual
    /// but runs as-fast-as-possible instead: each read ticks it a microsecond and a sleep jumps it
    /// forward at once.
    pub fn wall_clock(mut self) -> Self {
        self.wall_clock = true;
        self
    }

    /// Starts the virtual clock scaled to real time at `rate`; see [`Sim::set_time_rate`]. Takes
    /// precedence over [`wall_clock`](Self::wall_clock): `time_rate(1.0)` is a clock that tracks
    /// real time and can still be paused, advanced and set.
    #[track_caller]
    pub fn time_rate(mut self, rate: f64) -> Self {
        clock::validate_rate(rate, false);
        self.time_rate = Some(rate);
        self
    }

    /// Seeds the sim's randomness (default 0): the random bytes the code under test reads, and
    /// the link faults of [`set_udp_policy`]. The same seed replays the same
    /// values — each thread draws its own stream, so scheduling cannot reorder them — and a
    /// different seed explores a different run.
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Serves scheduling, CPU-topology, NIC and socket-tuning calls from a [`SimHost`]. The host
    /// also serves its own synthetic `/sys`, `/proc` and `/dev` reads, ahead of any
    /// [`fs`](Self::fs) set alongside it: a path the host does not model goes on to that
    /// [`VirtualFs`], and one neither serves reaches the real OS.
    pub fn host(mut self, host: Arc<SimHost>) -> Self {
        self.host = Some(host);
        self
    }

    /// Whether the sim keeps its [recorded events](Sim::recorded_events) (default on). Off, the
    /// log stays empty, for a long chatty run that does not read it.
    pub fn record_events(mut self, on: bool) -> Self {
        self.quiet = !on;
        self
    }

    /// Fails every socket option and ioctl the sim does not model, rather than accepting it
    /// without effect: `setsockopt`/`getsockopt` with `ENOPROTOOPT` (`WSAENOPROTOOPT` on
    /// Windows, `WSAEINVAL` at `SOL_SOCKET`), what the host answers for an option it does not know
    /// (man 2 setsockopt; [Microsoft Learn:
    /// setsockopt](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-setsockopt)),
    /// and an `ioctl` with the host's code for a request a socket does not know: `ENOTTY` on
    /// Linux, `ENXIO` on macOS, `WSAEOPNOTSUPP` on Windows (measured by tests/strict_sockopts.rs).
    /// The first refusal is also written to stderr. Either way each such call is listed in the
    /// socket's [`SocketEntry::unmodelled_options`](crate::SocketEntry::unmodelled_options) and
    /// logged as [`RecordedEvent::UnmodelledOption`](crate::RecordedEvent::UnmodelledOption).
    /// The options the sim ignores on purpose, as harmless to what a test can observe, are not
    /// refused; the README lists them.
    pub fn strict_sockopts(mut self) -> Self {
        self.strict_sockopts = true;
        self
    }

    /// Resolves `name` to `addrs` from the start; see [`add_host`].
    pub fn add_host(
        mut self,
        name: &str,
        addrs: impl IntoIterator<Item = std::net::IpAddr>,
    ) -> Self {
        self.dns.add_host(name, addrs);
        self
    }

    /// Forwards the real `SIGINT`, `SIGTERM` and `SIGHUP` the process receives into this sim while
    /// it lives, as [`SignalOrigin::Real`]. While any sim forwards, the process's own handlers are
    /// replaced by a forwarder; a signal no forwarding sim handled or ignored is then raised for
    /// real against the process's own disposition. The last sim to drop puts them back.
    pub fn forward_real_signals(mut self) -> Self {
        self.forward_signals = true;
        self
    }

    /// Lets a signal this sim's code never set an action for (`sigaction`, `signal`) reach the
    /// handler the code under test last installed for it in any sim of the process. A library
    /// that installs its dispatcher once per process and remembers that in a static
    /// (signal-hook-registry, and so `tokio::signal`, `signal-hook` and `async-signal`) never
    /// calls `sigaction` again in a later sim, or in one running alongside the sim whose code
    /// first registered, so without this only that sim's signals reach it. The dispatcher runs
    /// whatever every sim registered with it, as one process's would.
    pub fn process_signal_handlers(mut self) -> Self {
        self.process_signal_handlers = true;
        self
    }

    /// Looks `name` up on the real resolver when the sim is built and keeps what it found, so the
    /// run itself never leaves the process. Panics in [`build`](Self::build) if the lookup fails.
    pub fn resolve_real(mut self, name: &str) -> Self {
        self.dns.resolve_real(name);
        self
    }

    /// Sends names the sim does not know to the real resolver instead of failing them, recorded
    /// as unmodelled calls. Cannot be combined with [`deterministic`](Self::deterministic): `build`
    /// panics.
    pub fn real_dns(mut self) -> Self {
        self.dns.real_dns();
        self
    }

    /// Writes every frame that crosses the sim's network to a pcapng file at `path`, created (or
    /// truncated) at [`build`](Self::build), which panics if it cannot be. Frames are fabricated
    /// at their sender — Ethernet, IP and TCP/UDP/ICMP headers around what was sent, a TCP
    /// connection with its handshake, ACKs, FINs and resets — and stamped on the sim's clock
    /// (`CLOCK_REALTIME`), one interface block per interface crossed. Capture never changes the
    /// run; under [`deterministic`](Self::deterministic) the same seed writes the same bytes. Keep
    /// `path` on a local disk: a slow write holds up the thread that sent the frame.
    ///
    /// With no path given, setting `SNARE_PCAPNG_DIR` captures every sim to
    /// `<dir>/<building thread's name>.pcapng` (`-2`, `-3`… for further sims built by a thread of
    /// the same name); a file that cannot be created there only warns.
    pub fn pcapng(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.pcapng = Some(path.into());
        self
    }

    /// Whether each captured frame also carries the real wall time its sender sent it at (default
    /// off), as a pcapng comment (draft-ietf-opsawg-pcapng §3.5, opt_comment) of the form
    /// `wall 2026-10-02T09:15:42.123456789Z`, for lining a capture up with logs written on real
    /// time. The frames' stamps stay on the sim's clock. A frame due after it was sent (an ACK
    /// after the link's latency, a planned SYN retransmission) carries the real time it was
    /// written, the first moment the capture saw the sim's clock reach it. Setting
    /// `SNARE_PCAPNG_WALL_COMMENT` to anything but empty or `0` turns it on for every sim. The
    /// comments make the file differ from run to run, even under
    /// [`deterministic`](Self::deterministic).
    pub fn pcapng_wall_comment(mut self, on: bool) -> Self {
        self.pcapng_wall_comment = on;
        self
    }

    /// Fails the run when the sim makes no progress for `after` of real time while a participant
    /// keeps it busy (default off): the classic case is a thread spinning on an atomic with no
    /// hooked call, which keeps the discrete clock from moving, so every sleeper it waits on
    /// waits for good. Progress is a participant blocking or waking, a lease taken or given back,
    /// virtual time moving (a time skip, a clock write, a scaled or granted clock flowing, the
    /// latency each non-blocking call is charged) or, under [`deterministic`](Self::deterministic),
    /// a participant beginning a wait in the schedule. It never fires while every participant is
    /// blocked — on a paused clock, on an [`Executive`](crate::sched::Executive), on locks only a
    /// thread outside the sim can release — nor while a lease ([`Sim::busy`],
    /// [`sched::setup_scope`]) is held or an executive's timestamp is open, nor on a sim built
    /// [`wall_clock`](Self::wall_clock), whose time moves on its own. So a participant that
    /// legitimately runs longer than `after` without a hooked call — a long computation, a
    /// blocking call snare does not hook, work under [`real`] — must hold `busy` across it.
    ///
    /// On firing, a report naming each participant (running, or what it waits in and until when,
    /// what it last waited in, the leases it holds) is attempted on the process's stderr, past
    /// the test harness's capture. Reporting has a 100 ms budget before the process aborts, so
    /// locked or blocked stderr may leave the report incomplete. A stuck thread cannot be made
    /// to panic from outside. Samples are scheduled every eighth of `after` (between 1 ms and
    /// 250 ms); OS scheduling can delay detection and termination. Panics if `after` is zero.
    #[track_caller]
    pub fn stuck_after(mut self, after: Duration) -> Self {
        assert!(!after.is_zero(), "stuck_after must be longer than zero");
        self.stuck_after = Some(after);
        self
    }

    /// Builds the sim and installs its domain. The order matters: the clock is configured before
    /// `SimShared` captures it; the topology and host table are loaded before any backend can
    /// serve a call; the domain is installed last, and only then is its weak handle stored in
    /// `SimShared` (so a kick before that point wakes the clock and readiness board but skips the
    /// domain rather than reaching a half-built one).
    ///
    /// The domain offers each call to its layers first to last, in the order added: the registry
    /// scope, the seeded random layer, then the clock layer (the sim's own, or the host's). Net
    /// backends are likewise consulted in the order added and the first `Some` wins, so with a
    /// [`SimHost`] the fabric sees only what the host declines.
    ///
    /// Panics if [`real_dns`](Self::real_dns) is combined with
    /// [`deterministic`](Self::deterministic), if a [`resolve_real`](Self::resolve_real) lookup
    /// fails, or if the [`pcapng`](Self::pcapng) file cannot be created.
    #[track_caller]
    pub fn build(self) -> Sim {
        self.dns.check(self.deterministic);
        // A `SimHost` owns the virtual clock that answers `clock_gettime` and stamps timestamps. A
        // plain `Sim` has one of its own unless it runs on the real clock.
        let virtual_base = !self.wall_clock || self.time_rate.is_some();
        let clock = match &self.host {
            Some(host) => {
                let clock = host.clock();
                clock.set_discrete(virtual_base);
                Some(clock)
            }
            // 37 s is TAI−UTC since 2017-01-01 (IERS Bulletin C,
            // https://hpiers.obspm.fr/iers/bul/bulc/bulletinc.dat), the offset a synchronised Linux
            // host's CLOCK_TAI carries (man 2 clock_gettime, CLOCK_TAI; man 2 adjtimex, ADJ_TAI).
            None => virtual_base.then(|| Arc::new(Clock::new(37))),
        };
        if let Some(clock) = &clock {
            clock.set_deterministic(self.deterministic);
            if let Some(rate) = self.time_rate {
                clock.check_rate(rate);
                clock.set_rate(rate);
            }
        }
        let shared = SimShared::new(self.seed, clock.clone());
        #[cfg(target_os = "linux")]
        shared
            .rx_timestamp_startup
            .set_delay(self.rx_timestamp_startup_delay);
        shared.events.set_enabled(!self.quiet);
        shared
            .strict_sockopts
            .store(self.strict_sockopts, std::sync::atomic::Ordering::Relaxed);
        shared
            .signals
            .reach_process_handlers(self.process_signal_handlers);
        crate::pcapng::attach(&shared, self.pcapng, self.pcapng_wall_comment);
        let (host_nics, host_routes) = match &self.host {
            Some(host) => host.topology_facts(),
            None => (Vec::new(), Vec::new()),
        };
        shared.init_topology(host_nics, host_routes, self.nics, self.routes);
        self.dns.apply(&shared);
        let fabric = Arc::new(Fabric::new(shared.clone()));
        let mut builder = Domain::builder()
            .resolver(dns::DnsSetup::resolver(&shared))
            .signals(Arc::new(signals::SimSignals(shared.clone())))
            .layers([
                Arc::new(fabric::ScopeLayer(fabric.registries()))
                    as Arc<dyn snare_interpose::Layer>,
                Arc::new(random::RandomLayer::new(shared.seed)),
            ]);
        if self.deterministic {
            builder = builder.deterministic();
        }
        if let Some(after) = self.stuck_after {
            builder = builder.stuck_after(after);
        }
        if let (None, Some(clock)) = (&self.host, &clock) {
            builder = builder
                .layers([Arc::new(ClockLayer(clock.clone())) as Arc<dyn snare_interpose::Layer>]);
        }
        if let Some(host) = &self.host {
            host.attach_fabric(fabric.registries());
        }
        if let Some(privileges) = self.privileges {
            shared.sys.set_privileges(|p| *p = privileges);
        }
        if let Some(limits) = self.sys_limits {
            shared.sys.set_limits(|l| *l = limits);
        }
        if let Some(host) = &self.host {
            // The host owns the NIC/scheduling/synthetic-fs planes: its `Net` handles the
            // ethtool and timestamping ioctls, netlink and UDP; its `Fs` the synthetic
            // `/sys`·`/proc`, in front of a `VirtualFs` if one is set; its `Host` the scheduling
            // calls; and its clock layer makes `clock_gettime` (incl. `CLOCK_TAI`) deterministic.
            // The fabric sits behind it on the net plane so the socket families the host declines
            // — TCP streams, raw L2 — are still simulated, and the interface queries it declines
            // are answered from the topology: a test gets host-modelled UDP and fabric-modelled
            // TCP at once.
            builder = builder
                .layers([host.clock_layer()])
                .net(host.clone())
                .net(fabric.clone())
                .fs(with_proc_net(&shared, host_files(host, self.fs.as_ref())))
                .host(host.clone());
            // Only isolate the environment when the test asked to (see `HostProfile::env`), so
            // hosts that do not configure env keep reading the real one.
            if host.isolate_env() {
                builder = builder.env(host.clone());
            }
        } else {
            builder = builder
                .net(fabric.clone())
                .host(Arc::new(proclimits::ProcHost {
                    shared: shared.clone(),
                }));
            builder = match &self.fs {
                Some(fs) => builder.fs(with_proc_net(&shared, fs.clone())),
                // With no explicit VirtualFs, the fabric serves the file plane: on macOS it owns
                // `/dev/bpf*` for raw L2; on Linux it declines every path.
                None => builder.fs(with_proc_net(&shared, fabric.clone())),
            };
        }
        let domain = builder.install();
        let _ = shared.domain.set(domain.downgrade());
        if let Some(clock) = &shared.clock {
            clock.set_domain(&domain);
        }
        let forward = self
            .forward_signals
            .then(|| signals::forward::register(shared.clone()));
        Sim {
            domain,
            shared,
            _fabric: fabric,
            _fs: self.fs,
            _host: self.host,
            _forward: forward,
        }
    }
}
