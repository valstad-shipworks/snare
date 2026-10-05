//! fast-talker's API over snare's network, virtual clock and simulated host.

pub use ::fast_talker::{
    Config, Hardware, Received, Sent, Source, Timestamp, TxTime, TxTimeError, TxTimeErrorKind,
    TxTimestamp, counters, latency, monitor, options, plan, sockets, sys_check,
};

#[cfg(feature = "fast-talker-pyo3")]
pub use ::fast_talker::py;

pub use socket::{Socket, Timestamped};

mod handle;
pub(crate) mod hooks;
mod host_checks;
pub mod irq;
mod monitoring;
pub mod multicast;
pub mod nic;
mod plans;
pub(crate) mod platform;
mod proto_counters;
pub mod rt;
pub(crate) mod rt_options;
pub mod sim;
pub(crate) mod slot;
pub(crate) mod socket;
mod sockopts;
pub mod tcp;
