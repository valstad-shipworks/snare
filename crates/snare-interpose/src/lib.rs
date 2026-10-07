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
//! Sources: Apple makes no guarantees at the kernel system call interface and strives for binary
//! compatibility only in its dynamically linked libraries and frameworks
//! ([Apple Technical Q&A QA1118: Statically linked binaries on Mac OS X](https://developer.apple.com/library/archive/qa/qa1118/_index.html));
//! Windows publishes no system-call numbers, and calls even `ntdll.dll`'s native entry points
//! "internal to the operating system and subject to change from one release of Windows to another"
//! ([Microsoft Learn: NtQuerySystemInformation function](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation));
//! Linux keeps its system-call interface stable for userspace
//! (`Documentation/process/stable-api-nonsense.rst`).
//!
//! Two Linux bypasses matter in practice, both from `rustix`'s default `linux_raw` backend and
//! from io_uring:
//!
//! - Build the code under test with `--cfg rustix_use_libc` so `rustix` routes through `libc`,
//!   where its socket, clock and thread calls meet the hooks. A harness sets this; this crate
//!   cannot set it for its dependents.
//! - io_uring submits its I/O without a syscall per operation (shared submission and completion
//!   rings, man 7 io_uring), so those never appear. The ring is created with `io_uring_setup(2)`.
//!   The `io-uring` crate issues it through `libc::syscall` unless its `direct-syscall` feature is
//!   on (`src/sys/mod.rs`), so it is recorded, and a [`Layer::unmodelled`] that rejects it turns
//!   io_uring use into a failure rather than a silent gap. liburing issues it inline on x86_64
//!   and aarch64 (`src/syscall.h`, `src/arch/*/syscall.h`), so that use goes unseen.

#[cfg(not(any(
    all(
        target_os = "linux",
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    target_os = "macos",
    all(windows, any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
compile_error!(
    "snare-interpose supports only x86_64/aarch64 Linux (glibc), macOS, and x86_64/aarch64 Windows; \
     gate the dependency on `cfg(any(all(target_os = \"linux\", target_env = \"gnu\", \
     any(target_arch = \"x86_64\", target_arch = \"aarch64\")), target_os = \"macos\", windows))`"
);

macro_rules! on_supported_targets {
    ($($item:item)*) => {
        $(
            #[cfg(any(
                all(
                    target_os = "linux",
                    target_env = "gnu",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                ),
                target_os = "macos",
                all(windows, any(target_arch = "x86_64", target_arch = "aarch64"))
            ))]
            $item
        )*
    };
}

on_supported_targets! {
    mod accounting;
    mod census;
    #[cfg(windows)]
    mod detour;
    mod domain;
    mod env;
    mod fs;
    mod hooks;
    mod host;
    mod layer;
    mod net;
    mod os;
    #[cfg(unix)]
    mod owners;
    mod patch;
    mod race;
    mod resolve;
    mod sched;
    mod signals;
    mod stall;
    mod state;

    pub use accounting::{
        AuditReport, BlockerKind, ClassEffect, EpochBump, LeaseId, LeaseInfo, LeaseKind, PState,
        ParticipantInfo, Quiescence, QuiescenceViolation, ThreadClass, WaitLabel, current_wait_label,
        note_wait_deadline, set_child_class, set_in_setup, wait_label,
    };
    pub use census::{
        CensusThread, ServiceThread, SimId, ThreadCensus, ThreadOwner, census, current_os_thread_id,
        service_thread,
    };
    pub use domain::{
        Domain, DomainBuilder, FdWait, Managed, WeakDomain, bump_epoch, cancel_wake, charge_latency,
        current_sim,
        det_active, det_block, det_block_readiness, det_wake, det_wake_readiness, domain_key, dormant,
        end_spin, executive_attached, expire_timer, fd_wait, foreign_time_skip, idle_wait,
        in_passthrough,
        mark_sim_waiting, mark_waiting, note_effect, now, parked_on_shared_word, pass_gate, quiescent,
        real, real_span,
        recorded_thread_class, register_event_timer, register_timer, register_wake, set_thread_class,
        set_thread_name, SimLocals, sim_local, stalled, thread_class, thread_lineage, thread_name, time_skip,
        try_leave_sim_wait, unregister_event_timer, unregister_timer, virtual_now,
    };
    #[cfg(unix)]
    pub use domain::{defer_descriptor_cleanup, descriptor_transaction};
    pub use env::Env;
    pub use fs::Fs;
    #[cfg(windows)]
    pub use host::DevCall;
    pub use host::Host;
    pub use layer::{ClockKind, Flow, Layer, SleepRequest, SpinStep, Unmodelled};
    #[cfg(windows)]
    pub use net::IpHlpCall;
    #[cfg(windows)]
    pub use net::{CompletionCall, CompletionPost, CompletionQuery};
    pub use net::{HandOver, Net, NetResult};
    #[cfg(unix)]
    pub use owners::{bury_fd, claim_fd, minted, orphan, release_fd};
    #[doc(hidden)]
    pub use os::joined_lists;
    #[cfg(windows)]
    pub use os::{next_performance_count, performance_count};
    pub use patch::{ImagePatches, InstallReport, install};
    #[doc(hidden)]
    pub use race::RaceCell;
    pub use resolve::{Lookup, Resolver, Reverse};
    pub use sched::{DetKey, DetWake, ReadinessKey, ReadinessWake};
    #[cfg(unix)]
    pub use signals::{Disposition, deliver_here, is_virtual};
    pub use signals::{SignalOutcome, SignalSource, Signals, simulated};
}
