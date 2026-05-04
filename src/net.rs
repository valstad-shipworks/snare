//! Drop-in shim for [`std::net`].
//!
//! Re-exports `TcpListener` / `TcpStream` / `UdpSocket` from snare's in-process
//! shim when the `shim` feature is on, and from `std::net` otherwise. Use
//! `snare::net::TcpStream` instead of `std::net::TcpStream` and the same code
//! path runs against either the real network or the test harness depending on
//! how the crate is built.
//!
//! When the `shim` feature is off this module is a transparent re-export of
//! `std::net` — nothing extra runs.

#[cfg(feature = "shim")]
pub use crate::shim_std_tcp::{
    Incoming, ShimStdTcpListener as TcpListener, ShimStdTcpStream as TcpStream,
};
#[cfg(feature = "shim")]
pub use crate::shim_std_udp::ShimStdUdpSocket as UdpSocket;

#[cfg(not(feature = "shim"))]
pub use std::net::{Incoming, TcpListener, TcpStream, UdpSocket};
