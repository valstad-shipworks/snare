#![doc = include_str!("../README.md")]

#[cfg(feature = "mio-compat")]
pub mod mio;
pub mod net;
pub mod thread;
pub mod time;

#[cfg(feature = "shim")]
mod framework;
#[cfg(all(feature = "shim", feature = "mio-compat"))]
mod mio_shim;
#[cfg(feature = "shim")]
pub(crate) mod pcapng;
#[cfg(feature = "shim")]
mod shim_std_tcp;
#[cfg(feature = "shim")]
mod shim_std_udp;
#[cfg(feature = "shim")]
pub(crate) mod state;

// Top-level type aliases — kept for back-compat with the original snare API.
// New code should prefer `snare::net::TcpStream` etc. for parity with `std::net`.
pub use net::{TcpListener, TcpStream, UdpSocket};

#[cfg(feature = "shim")]
pub use state::{
    ListenerBehavior, QuiesceMode, RecordedEntry, RecordedEvent, UdpPolicy, add_ip_addr,
    advance_time, clear_recorded_events, enable_pcapng, inject_tcp_from_test, pause_time,
    peek_local_addr_for_peer, quiesce, quiesce_with_mode, recorded_events, register_child_thread,
    register_test, register_thread_child_of, reset_tcp, resume_time, seed_rng,
    set_listener_behavior, set_tcp_inbound_latency, set_tcp_recv_window, set_time_rate,
    set_time_value, set_udp_policy, time_rate, time_value,
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

/// Transport selector used by [`Packetable::SOCKET_TYPE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketType {
    Udp,
    Tcp,
}
