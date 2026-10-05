//! Helpers whose one spelling works with and without snare's `shim`.

use std::io;
use std::time::SystemTime;

#[cfg(any(feature = "shim", feature = "fast-talker-options"))]
use ::fast_talker::options::{ApplyError, Report, Rules, ThreadOption};
use ::fast_talker::tcp::TcpInfo;

/// The wall clock fast-talker's stamps are read against: snare's virtual
/// clock under the shim, [`SystemTime::now`] otherwise. Use it for
/// `Timestamped::send_at` and `RoundTrips::poll`.
#[cfg(feature = "shim")]
pub fn now() -> SystemTime {
    crate::time::SystemTime::now().into()
}

/// The wall clock fast-talker's stamps are read against: snare's virtual
/// clock under the shim, [`SystemTime::now`] otherwise. Use it for
/// `Timestamped::send_at` and `RoundTrips::poll`.
#[cfg(not(feature = "shim"))]
pub fn now() -> SystemTime {
    SystemTime::now()
}

/// The health of a TCP stream: `TcpInfo::of`, which cannot take a snare
/// stream. Under the shim it is what `TimestampedStream::info` reports.
#[cfg(feature = "shim")]
pub fn tcp_info(stream: &crate::net::TcpStream) -> io::Result<TcpInfo> {
    crate::fast_talker_shim::tcp::tcp_info(crate::netif::socket_id(stream))
}

/// The health of a TCP stream: `TcpInfo::of`, which cannot take a snare
/// stream.
#[cfg(all(not(feature = "shim"), unix))]
pub fn tcp_info(stream: &impl std::os::fd::AsRawFd) -> io::Result<TcpInfo> {
    TcpInfo::of(stream)
}

/// The health of a TCP stream: `TcpInfo::of`, which cannot take a snare
/// stream.
#[cfg(all(not(feature = "shim"), windows))]
pub fn tcp_info(stream: &impl std::os::windows::io::AsRawSocket) -> io::Result<TcpInfo> {
    TcpInfo::of(stream)
}

/// `ThreadOption::apply_all_to` for a [`rt::Thread`](crate::fast_talker::rt::Thread),
/// which is snare's own type under the shim.
#[cfg(feature = "shim")]
pub fn apply_thread_options_to(
    thread: crate::fast_talker::rt::Thread,
    options: &[ThreadOption],
    rules: &Rules<'_, ThreadOption>,
) -> Result<Report<ThreadOption>, ApplyError<ThreadOption>> {
    crate::fast_talker_shim::rt_options::apply_to(thread, options, rules)
}

/// `ThreadOption::apply_all_to` for a [`rt::Thread`](crate::fast_talker::rt::Thread),
/// which is snare's own type under the shim.
#[cfg(all(not(feature = "shim"), feature = "fast-talker-options"))]
pub fn apply_thread_options_to(
    thread: ::fast_talker::rt::Thread,
    options: &[ThreadOption],
    rules: &Rules<'_, ThreadOption>,
) -> Result<Report<ThreadOption>, ApplyError<ThreadOption>> {
    ThreadOption::apply_all_to(thread, options, rules)
}
