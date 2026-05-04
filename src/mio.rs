//! Drop-in shim for [`mio`].
//!
//! Re-exports `Poll` / `Waker` / `Token` / `Interest` / `event::*` /
//! `net::{TcpStream, UdpSocket}` from snare's in-process shim when the `shim`
//! feature is on, and from real `mio` otherwise. Use `snare::mio::Poll`
//! instead of `mio::Poll` and the same `Poll`-driven event loop runs against
//! either the real kernel or the test harness depending on how the crate is
//! built.
//!
//! When the `shim` feature is off this module is a transparent re-export of
//! `::mio` — nothing extra runs.
//!
//! Requires the `mio-compat` cargo feature (which itself pulls in `mio` as a
//! dependency).

#[cfg(feature = "shim")]
pub use crate::mio_shim::{Events, Interest, Poll, Registry, Token, Waker, event, features, guide, net};

#[cfg(not(feature = "shim"))]
pub use ::mio::{Events, Interest, Poll, Registry, Token, Waker, event, features, guide, net};
