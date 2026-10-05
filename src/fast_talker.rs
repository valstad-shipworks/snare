//! Drop-in shim for [`fast_talker`].
//!
//! Use `snare::fast_talker::` in place of `fast_talker::`. Without the
//! `shim` feature this module is a transparent re-export of `::fast_talker`
//! and nothing extra runs, so real hardware behaves exactly as before.
//!
//! With `shim`, everything that touches the OS (sockets, timestamps, NIC
//! settings, IRQs, real-time thread and process settings, system checks,
//! counters, the monitor thread, multicast) works against snare's in-process
//! network and virtual clock instead. Configuration, option, plan, check and
//! result types stay fast-talker's own, so a `fast_talker::options::ThreadOption`
//! or `fast_talker::Config` read from a config file is the same type under
//! both.
//!
//! fast-talker functions that take an OS socket (`SocketOptions::apply`,
//! `SocketOption::apply_all`, `SocketMemory::of`, `sockets::incoming_cpu`,
//! `WatchedSocket::new`) also accept snare's sockets under the shim and hand
//! them to snare; they never reach a real syscall. Replace raw-fd code such as
//! `libc::setsockopt(sock.as_raw_fd(), ..)` with those functions: the same
//! line then works on real hardware and in simulation.
//!
//! Code that passes its own wall-clock time, such as
//! `Timestamped::send_at(at)` or `RoundTrips::poll(now, ..)`, must take it
//! from [`compat::now`] (or `snare::time::SystemTime::now().into()`), not
//! `std::time::SystemTime::now()`, which does not follow snare's clock.
//!
//! Under the shim, `monitor::Monitor` samples on a background snare thread
//! on virtual time. Its callback runs while the monitor holds a
//! [`busy`](crate::sched::busy) lease, so it must not block on a snare wait
//! (a blocking snare read, a snare sleep): under a driver that deadlocks.
//!
//! fast-talker's own entry points (`sys_check`, `Check::recommended`,
//! `Counters::read`, plans, options, the monitor) reach snare through a hook
//! installed by the first snare call in the process. Under
//! `--cfg snare_global`, make one (such as `snare::os_semantics()`) before
//! the code under test starts, or those calls read the real host.
//!
//! Needs the `fast-talker-core` feature; `fast-talker-compat` matches a plain
//! `fast-talker` dependency with its default features.

#[cfg(not(feature = "shim"))]
pub use ::fast_talker::*;

#[cfg(feature = "shim")]
pub use crate::fast_talker_shim::*;

#[path = "fast_talker_compat.rs"]
pub mod compat;
