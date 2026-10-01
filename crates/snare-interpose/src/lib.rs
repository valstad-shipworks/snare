//! Redirects a program's calls into the operating system to pluggable layers, per thread.
//!
//! [`install`] rewrites the import tables of the running executable (ELF GOT, Mach-O
//! `__got`/lazy pointers, PE IAT) so that selected OS functions land in this crate first. Every
//! thread starts *real*: its calls go straight to the OS. A thread becomes *managed* by entering
//! a [`Domain`], and from then on those calls are translated into [`Layer`] operations and offered
//! to the domain's layers in order. Threads a managed thread creates inherit its domain.
//!
//! ```no_run
//! use std::sync::Arc;
//! use std::time::{Duration, Instant};
//! use snare_interpose::{ClockKind, Domain, Flow, Layer, SleepRequest};
//!
//! struct Frozen(Duration);
//!
//! impl Layer for Frozen {
//!     fn now(&self, clock: ClockKind) -> Flow<Duration> {
//!         match clock {
//!             ClockKind::Monotonic => Flow::Done(self.0),
//!             _ => Flow::Pass,
//!         }
//!     }
//! }
//!
//! let domain = Domain::new([Arc::new(Frozen(Duration::from_secs(5))) as Arc<dyn Layer>]);
//! domain.run(|| {
//!     let a = Instant::now();
//!     assert_eq!(a.elapsed(), Duration::ZERO);
//! });
//! ```
//!
//! Code running inside a layer is never redirected, so a layer may freely use std, sockets or
//! the clock to do real work.
//!
//! # Finding what is not simulated
//!
//! Besides the functions layers model, the crate hooks the OS functions they do not model yet
//! (sockets, readiness, blocking waits, signals, raw `syscall` and `ioctl` on Linux). Those pass
//! straight to the OS, but a managed thread's call is counted in [`Domain::unmodelled`] and
//! offered to [`Layer::unmodelled`]. Every other function an image imports is listed in
//! [`ImagePatches::other_imports`] for review. On Windows and macOS there is no stable raw-syscall
//! ABI, so every OS call goes through an import and is seen. Linux is the exception: code can issue
//! a `syscall` instruction inline, with nothing to hook.
//!
//! Two Linux bypasses matter in practice, both from `rustix`'s default `linux_raw` backend and
//! from io_uring:
//!
//! - Build the code under test with `--cfg rustix_use_libc` so `rustix` routes through `libc`,
//!   where its socket, clock and thread calls meet the hooks. A harness sets this; this crate
//!   cannot set it for its dependents.
//! - io_uring submits its I/O without a syscall per operation, so those never appear. The ring is
//!   created with `io_uring_setup`, which the common path issues through `libc`'s `syscall` and so
//!   is recorded; a [`Layer::unmodelled`] that rejects it turns any io_uring use into a failure
//!   rather than a silent gap.

mod domain;
mod env;
mod fs;
mod hooks;
mod host;
mod layer;
mod net;
mod os;
mod patch;
mod state;

pub use domain::{
    Domain, DomainBuilder, Managed, charge_latency, discrete_now, in_passthrough, managed_live, managed_parked,
    mark_waiting, now, real, register_timer, thread_lineage, time_skip, unregister_timer,
};
pub use env::Env;
pub use fs::Fs;
pub use host::Host;
pub use layer::{ClockKind, Flow, Layer, SleepRequest, Unmodelled};
pub use net::{Net, NetResult};
pub use patch::{ImagePatches, InstallReport, install};
