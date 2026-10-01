//! Drop-in replacement for the `xsk-rs` AF_XDP crate, for use under snare2's in-process harness.
//!
//! The real crate drives AF_XDP sockets: a UMEM is an `mmap`'d region shared with the kernel, and
//! frames move across the TX/RX/fill/completion rings with no per-frame syscall. That is exactly
//! what makes it un-interposable — an import-table interposer never sees the frames.
//!
//! This shim keeps the public API the real crate exposes to a consumer (see [`Umem`], [`Socket`],
//! [`TxQueue`], [`RxQueue`], [`FillQueue`], [`CompQueue`], [`FrameDesc`] and the [`config`] types)
//! but replaces the kernel entirely. The UMEM is a plain heap buffer, the four rings are in-process
//! `VecDeque`s, and every frame crosses a real fd via libc: TX frames are written with `send`, RX
//! frames are read with `recv`. An interposer that hooks those libc symbols therefore observes and
//! can redirect the same frames it already handles for `AF_PACKET`.
//!
//! What is faithful: the frame-descriptor lifecycle (write to UMEM, produce to TX, reclaim from the
//! completion queue; offer to the fill queue, consume from RX), the `needs_wakeup`/`wakeup` flush
//! contract, and the byte contents of every frame.
//!
//! What is not: there is no kernel, no XDP program, and no zero-copy. The backing fd is a
//! `socketpair`, so absent an interposer, TX frames loop straight back to RX in-process (which is
//! what the round-trip test relies on). `queue_id`, the interface name, and every flag other than
//! `XDP_USE_NEED_WAKEUP`'s wakeup behaviour are accepted and ignored. Shared-UMEM binds are not
//! modelled: [`Socket::new`] always returns the fill/completion pair as `Some`.

pub mod config;

mod emu;
mod frame;
mod socket;
mod umem;

pub use frame::FrameDesc;
pub use socket::{RxQueue, Socket, TxQueue};
pub use umem::{CompQueue, FillQueue, Umem};
