//! Drop-in shim for [`ctrlc`].
//!
//! Use `snare::ctrlc::set_handler` instead of `ctrlc::set_handler`. When the
//! `shim` feature is off this module is a transparent re-export of `::ctrlc`
//! — nothing extra runs.
//!
//! With `shim` on, each state slot holds at most one virtual handler. It runs
//! on a dedicated `ctrl-c` thread spawned through [`crate::thread`], so it is
//! a scheduler participant that is blocked while idle and reads snare's
//! virtual clock. `raise` delivers a virtual Ctrl-C to the calling thread's
//! slot. The first virtual handler also installs the real `ctrlc` handler,
//! and a real Ctrl-C is forwarded to every slot's virtual handler from
//! `ctrlc`'s own thread, which is marked background.
//!
//! `raise_signal` delivers other signals and console events, following the
//! selected [`OsSemantics`](crate::OsSemantics): which ones exist, which ones
//! `ctrlc` catches, and whether the OS would end the process afterwards.
//!
//! Requires the `ctrlc-compat` cargo feature. `ctrlc-termination` enables
//! `ctrlc`'s `termination` feature as well.

#[cfg(feature = "shim")]
pub use crate::ctrlc_shim::{
    Error, Signal, SignalDelivery, SignalType, VirtualSignal, raise, raise_signal, set_handler,
    try_set_handler,
};

#[cfg(not(feature = "shim"))]
pub use ::ctrlc::{Error, Signal, SignalType, set_handler, try_set_handler};
