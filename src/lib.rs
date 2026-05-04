//! # snare
//!
//! Network mocking for Rust tests. Provides drop-in replacement modules for
//! [`std::net`], [`std::thread`], and [`mio`] — under the `shim` feature the
//! traffic is intercepted by the per-test framework, otherwise the modules are
//! transparent re-exports of their standard counterparts.
//!
//! ## Drop-in modules
//!
//! Replace these imports project-wide and the same code path runs against
//! either the real network or the test harness depending on how the crate is
//! built:
//!
//! | Replace | With |
//! |---|---|
//! | `std::net::{TcpListener, TcpStream, UdpSocket}` | [`crate::net`] |
//! | `std::thread::*` | [`crate::thread`] |
//! | `mio::{Poll, Waker, Token, Interest, event, net}` | `crate::mio` *(requires `mio-compat` feature)* |
//!
//! Example:
//! ```ignore
//! use snare::net::{TcpListener, TcpStream};
//! use snare::thread;            // spawn auto-registers as a child of `current()`
//! use snare::mio::{Poll, Waker};
//! ```
//!
//! Each module is also a drop-in replacement when the `shim` feature is OFF —
//! it transparently re-exports the underlying standard library / `::mio` types,
//! so production builds pay zero overhead.
//!
//! ## Enabling the shim for tests only
//!
//! The intended pattern is to depend on snare without `shim` as a regular dep
//! (so production code re-exports `std`/`mio`) and add the same version as a
//! `dev-dependencies` entry with `shim` enabled. Cargo unifies the two and
//! turns the feature on ONLY when building the test profile:
//!
//! ```toml
//! [dependencies]
//! snare = "1"
//!
//! [dev-dependencies]
//! snare = { version = "1", features = ["shim", "mio-compat"] }
//! ```
//!
//! Then `use snare::net::TcpStream;` resolves to the shim under tests and to
//! `std::net::TcpStream` in production — no `#[cfg(test)]` toggling needed at
//! the call site.
//!
//! ## Features
//!
//! - `shim` — replace [`net`] / [`mio`] / [`thread`] internals with snare's
//!   in-process mock. Without this feature the modules transparently re-export
//!   the underlying standard or `::mio` types and snare is essentially a no-op.
//! - `mio-compat` — expose the [`mio`] module (transparent re-export of
//!   `::mio` when `shim` is off, snare's mio shim when `shim` is on). Required
//!   if your SUT drives I/O with `mio`.
//!
//! ## Test-thread setup
//!
//! Every `#[test]` that touches the shim must call [`register_test`] first.
//! For threads spawned by the test (or its SUT), the simplest path is to
//! `use snare::thread;` instead of `std::thread`: [`thread::spawn`] /
//! [`thread::Builder::spawn`] register each spawned thread as a child of the
//! spawning thread before running its body, so no manual
//! `.register_as_child()` is needed.
//!
//! If you must use `std::thread::spawn`, attach each child to the test slot
//! manually via [`ThreadExt::register_as_child`] on the parent or
//! [`register_thread_child_of`] from inside the spawned closure. See `tests/`
//! for end-to-end examples.

pub mod net;
pub mod thread;
#[cfg(feature = "mio-compat")]
pub mod mio;

#[cfg(feature = "shim")]
pub(crate) mod state;
#[cfg(feature = "shim")]
mod shim_std_tcp;
#[cfg(feature = "shim")]
mod shim_std_udp;
#[cfg(feature = "shim")]
mod framework;
#[cfg(all(feature = "shim", feature = "mio-compat"))]
mod mio_shim;

// Top-level type aliases — kept for back-compat with the original snare API.
// New code should prefer `snare::net::TcpStream` etc. for parity with `std::net`.
pub use net::{TcpListener, TcpStream, UdpSocket};

#[cfg(feature = "shim")]
pub use state::{
    ListenerBehavior, QuiesceMode, RecordedEntry, RecordedEvent, UdpPolicy, add_ip_addr,
    clear_recorded_events, inject_tcp_from_test, peek_local_addr_for_peer, quiesce,
    quiesce_with_mode, recorded_events, register_child_thread, register_thread_child_of,
    register_test, reset_tcp, seed_rng, set_listener_behavior,
    set_tcp_inbound_latency, set_tcp_recv_window, set_udp_policy,
};
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

impl <T> ThreadExt for std::thread::JoinHandle<T> {
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
