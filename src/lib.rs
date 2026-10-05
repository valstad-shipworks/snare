#![doc = include_str!("../README.md")]

#[cfg(feature = "ctrlc-compat")]
pub mod ctrlc;
#[cfg(feature = "fast-talker-core")]
pub mod fast_talker;
#[cfg(feature = "mio-compat")]
pub mod mio;
pub mod net;
pub mod os;
pub mod sched;
pub mod thread;
pub mod time;

#[cfg(feature = "shim")]
mod census;
#[cfg(all(feature = "shim", feature = "ctrlc-compat"))]
mod ctrlc_shim;
#[cfg(all(feature = "shim", feature = "fast-talker-core"))]
mod fast_talker_shim;
#[cfg(feature = "shim")]
mod framework;
#[cfg(feature = "shim")]
mod host_threads;
#[cfg(feature = "shim")]
mod mcast;
#[cfg(all(feature = "shim", feature = "mio-compat"))]
mod mio_shim;
#[cfg(feature = "shim")]
pub mod netif;
#[cfg(feature = "shim")]
pub(crate) mod pcapng;
#[cfg(feature = "shim")]
mod resolve;
#[cfg(feature = "shim")]
mod shim_std_tcp;
#[cfg(feature = "shim")]
mod shim_std_udp;
#[cfg(feature = "shim")]
pub(crate) mod state;
#[cfg(feature = "shim")]
mod threads;

// Top-level type aliases — kept for back-compat with the original snare API.
// New code should prefer `snare::net::TcpStream` etc. for parity with `std::net`.
pub use net::{TcpListener, TcpStream, UdpSocket};

#[cfg(feature = "shim")]
pub use state::{
    ListenerBehavior, QuiesceMode, RecordedEntry, RecordedEvent, UdpPolicy, add_host, add_ip_addr,
    advance_time, clear_recorded_events, enable_pcapng, inject_icmp_port_unreachable,
    inject_tcp_from_test, inject_udp_from_test, pause_time, peek_local_addr_for_peer, quiesce,
    quiesce_with_mode, recorded_events, register_child_thread, register_test,
    register_thread_child_of, reset_tcp, resume_time, seed_rng, set_listener_behavior,
    set_tcp_inbound_latency, set_tcp_recv_window, set_time_rate, set_time_value, set_udp_policy,
    time_rate, time_value,
};

pub use os::{Errno, OsSemantics, SimOsError, SysErrno, os_error_code, os_semantics};
#[cfg(feature = "shim")]
pub use os::{os_semantics_explicit, set_os_semantics};

#[cfg(feature = "shim")]
pub use mcast::Membership;
#[cfg(feature = "shim")]
pub use netif::{
    CoalesceSupport, DriverSeed, DropAccounting, IpNet, NicCaps, NicCounters, NicId, NicKind,
    NicPolicy, NicSnapshot, NicSpec, Privileges, Route, SimSocket, SocketEntry, SocketId,
    SocketKind, SysLimits, add_nic, add_route, closed_sockets, inject_socket_drops, nic,
    nic_counters, nics, privileges, remove_nic, remove_route, route_lookup, routes,
    set_default_route, set_link, set_nic, set_nic_counters, set_nic_policy, set_privileges,
    set_socket_device, set_sys_limits, socket_entry, socket_id, socket_table, sockets_bound,
    sys_limits,
};

/// No-op when the `shim` feature is disabled — kept for API parity so call
/// sites don't need `#[cfg(feature = "shim")]`.
#[cfg(not(feature = "shim"))]
#[inline(always)]
pub fn enable_pcapng() {}
#[cfg(feature = "shim")]
pub use framework::*;

#[cfg(not(feature = "shim"))]
#[inline(always)]
pub fn register_child_thread(_child_thread_id: std::thread::ThreadId) {}

#[cfg(not(feature = "shim"))]
#[inline(always)]
pub fn register_thread_child_of(_parent_thread_id: std::thread::ThreadId) {}

/// Convenience trait for `let h = thread::spawn(...).register_as_child();`
/// — chains [`register_child_thread`] onto a `JoinHandle`, `Thread`, or `ThreadId`.
pub trait ThreadExt {
    /// Attach to the current test's state slot, returning `self` for chaining.
    fn register_as_child(self) -> Self;
}

impl ThreadExt for std::thread::ThreadId {
    #[inline(always)]
    fn register_as_child(self) -> std::thread::ThreadId {
        register_child_thread(self);
        self
    }
}

impl<T> ThreadExt for std::thread::JoinHandle<T> {
    #[inline(always)]
    fn register_as_child(self) -> std::thread::JoinHandle<T> {
        register_child_thread(self.thread().id());
        self
    }
}

impl ThreadExt for std::thread::Thread {
    #[inline(always)]
    fn register_as_child(self) -> std::thread::Thread {
        register_child_thread(self.id());
        self
    }
}

#[cfg(feature = "shim")]
impl ThreadExt for thread::Thread {
    #[inline(always)]
    fn register_as_child(self) -> thread::Thread {
        register_child_thread(self.id());
        self
    }
}

/// Transport selector used by [`Packetable::SOCKET_TYPE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketType {
    Udp,
    Tcp,
}
