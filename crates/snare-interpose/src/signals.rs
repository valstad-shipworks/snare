//! Per-domain signal dispositions. A domain built with a [`Signals`] table keeps its own idea of
//! how each virtual signal is handled: the code under test installs handlers with the OS's own
//! calls (`sigaction`, `signal`, `SetConsoleCtrlHandler`), the real process's dispositions stay
//! untouched, and a signal raised inside the domain is delivered from the table as the host OS
//! would deliver it.
//!
//! The table itself lives in the sim (`snare::signals`), behind the [`Signals`] trait; this module
//! holds the delivery side that has to run on the calling thread: which signals are virtual, the
//! per-thread blocked/pending bits that model the OS's "a signal is blocked while its own handler
//! runs" rule, and calling a handler with the arguments the kernel would pass. The hooks that feed
//! it are in `os::signal_hooks` (unix) and `os::windows` (console control and the CRT).
//!
//! Every [`Signals`] method is called with the thread in passthrough, so the table may lock and
//! allocate without re-entering the hooks; a handler of the code under test is called through
//! [`simulated`], so its own OS calls reach the domain again.

#[cfg(unix)]
use std::cell::Cell;
use std::ffi::c_int;

use crate::state::Passthrough;

/// Who sent a signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignalSource {
    /// The sim, on the test's behalf.
    Sim,
    /// The code under test itself: `raise`, `kill` of its own process, `pthread_kill`,
    /// `GenerateConsoleCtrlEvent`.
    Process,
    /// A real signal the process received, forwarded into the domain.
    Real,
}

/// What delivering a signal did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignalOutcome {
    /// A handler of the code under test ran.
    Handled,
    /// A handler ran, after which the OS would end the process (a Windows close, logoff or
    /// shutdown event).
    HandledThenExit,
    /// The OS default action applies; the domain never carries it out.
    DefaultAction,
    /// The signal is ignored.
    Ignored,
}

/// How a unix signal is handled, taken from the table at the moment of delivery.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// `SIG_DFL`: the OS default action, which for the virtual signals is to end the process
    /// (man 7 signal, "Standard signals" table). The domain reports it and never carries it out.
    Default,
    /// `SIG_IGN`: the signal is discarded.
    Ignore,
    /// A handler at `address`: `fn(c_int)`, or with `siginfo` `fn(c_int, *mut siginfo_t, *mut
    /// c_void)`. `nodefer` lets the signal interrupt its own handler.
    Handler {
        /// The `sa_handler`/`sa_sigaction` word the code under test installed.
        address: usize,
        /// `SA_SIGINFO` was set: call the three-argument form (man 2 sigaction, `SA_SIGINFO`).
        siginfo: bool,
        /// The signal is not blocked while its handler runs (man 2 sigaction, `SA_NODEFER`).
        nodefer: bool,
    },
}

/// A domain's signal table. Its methods run with the calling thread in passthrough.
///
/// Implementations must not call a handler of the code under test while holding a lock of their
/// own: a handler may call back into the table (`sigaction`, `signal`, `SetConsoleCtrlHandler`)
/// on the same thread.
pub trait Signals: Send + Sync + 'static {
    /// Installs `act` for the virtual signal `sig` if given, returning the action it replaces
    /// (man 2 sigaction: `act` and `oldact` are each optional).
    #[cfg(unix)]
    fn sigaction(&self, sig: c_int, act: Option<&libc::sigaction>) -> libc::sigaction;

    /// How `sig` is handled now, applying `SA_RESETHAND` as the delivery takes it: a handler
    /// installed with it is returned once and the table falls back to `SIG_DFL` (man 2 sigaction,
    /// `SA_RESETHAND`).
    #[cfg(unix)]
    fn take_disposition(&self, sig: c_int) -> Disposition;

    /// `SetConsoleCtrlHandler(handler, add)`; `handler` 0 is the ignore-CTRL+C flag. `Err` is the
    /// Win32 error to fail with
    /// ([Microsoft Learn: SetConsoleCtrlHandler](https://learn.microsoft.com/en-us/windows/console/setconsolectrlhandler)).
    #[cfg(windows)]
    fn set_console_ctrl_handler(&self, handler: usize, add: bool) -> Result<(), u32>;

    /// `GenerateConsoleCtrlEvent` for this process: delivers `event` to the handlers on a new
    /// thread and returns without waiting, as the OS does
    /// ([Microsoft Learn: HandlerRoutine](https://learn.microsoft.com/en-us/windows/console/handlerroutine):
    /// "the system creates a new thread in the process to execute the function").
    #[cfg(windows)]
    fn console_event(&self, event: u32);

    /// The CRT's `signal(sig, handler)`, returning the previous handler
    /// ([Microsoft Learn: signal](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/signal)).
    #[cfg(windows)]
    fn crt_signal(&self, sig: c_int, handler: usize) -> usize;

    /// The CRT's `raise(sig)`: runs the CRT handler synchronously
    /// ([Microsoft Learn: raise](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/raise)).
    /// Returns what `raise` returns, 0 on success.
    #[cfg(windows)]
    fn crt_raise(&self, sig: c_int) -> c_int;

    /// Notes a delivery, as it takes effect. `raw` is the host's number: a signal number on unix,
    /// a `CTRL_*_EVENT` on Windows.
    fn record(&self, raw: i32, source: SignalSource, outcome: SignalOutcome);
}

/// Runs `f` with the calling thread's OS calls offered to its domain again: how the sim runs a
/// handler of the code under test from inside its own code.
///
/// The passthrough flag is restored when `f` returns or unwinds, so the caller's own code after
/// it is back in passthrough.
pub fn simulated<R>(f: impl FnOnce() -> R) -> R {
    let _simulated = Passthrough::leave();
    f()
}

/// The signals a domain keeps its own dispositions for; every other signal is the OS's.
///
/// These are the asynchronous "please stop" signals a program handles for a clean shutdown
/// (the set `ctrlc` handles with its `termination` feature). Fault signals (`SIGSEGV`, `SIGBUS`, ...)
/// must stay real, and `SIGKILL`/`SIGSTOP` cannot be caught at all (man 7 signal), so the OS keeps
/// rejecting them itself.
#[cfg(unix)]
pub fn is_virtual(sig: c_int) -> bool {
    matches!(sig, libc::SIGINT | libc::SIGTERM | libc::SIGHUP)
}

// One bit per signal number, `1 << sig`; the virtual signals are all below 64 (SIGHUP 1, SIGINT 2,
// SIGTERM 15 on both Linux and Darwin: <asm-generic/signal.h>, <sys/signal.h>).
#[cfg(unix)]
thread_local! {
    /// The virtual signals whose handler is running on this thread and which that handler blocks:
    /// the per-thread signal mask the kernel extends on handler entry unless `SA_NODEFER` is set
    /// (kernel/signal.c `signal_delivered`; XNU bsd/kern/kern_sig.c `postsig_locked`; man 2
    /// sigaction, `SA_NODEFER`). Only the signal itself is tracked: the kernel also adds the
    /// handler's `sa_mask`, which the sim does not apply.
    static HANDLING: Cell<u64> = const { Cell::new(0) };
    /// The virtual signals raised on this thread while blocked. A standard signal does not queue:
    /// however often it is raised while blocked, it is delivered once when unblocked (man 7
    /// signal, "Queueing and delivery semantics for standard signals"), so one bit is enough.
    static DEFERRED: Cell<u64> = const { Cell::new(0) };
}

/// Delivers the virtual signal `sig` on the calling managed thread as `kill` to its own process
/// would: its handler runs here and now. `None` off a domain, on a domain without a signal table,
/// or for a signal the domain leaves to the OS.
///
/// POSIX requires a signal a process sends itself, if unblocked, to be delivered before `kill`
/// returns (IEEE Std 1003.1, kill); delivering on the calling thread meets that.
#[cfg(unix)]
pub fn deliver_here(sig: c_int, source: SignalSource) -> Option<SignalOutcome> {
    deliver(sig, source, false)
}

/// [`deliver_here`], with `tkill` for a signal aimed at the calling thread itself (`raise`,
/// `pthread_kill`), which Linux reports as `SI_TKILL`: glibc sends both with tgkill(2), and the
/// kernel fills a thread-directed kill's `si_code` with `SI_TKILL` (kernel/signal.c
/// `prepare_kill_siginfo`, `do_tkill`).
#[cfg(unix)]
pub(crate) fn deliver(sig: c_int, source: SignalSource, tkill: bool) -> Option<SignalOutcome> {
    if !is_virtual(sig) {
        return None;
    }
    let signals = crate::domain::signals_here()?;
    Some(deliver_with(&*signals, sig, source, tkill))
}

/// Delivers `sig` from `signals` on this thread, modelling the kernel's mask handling.
///
/// - If `sig` is blocked here (its own handler is running without `SA_NODEFER`), it is left
///   pending in `DEFERRED` and reported as handled; the outer delivery picks it up.
/// - Otherwise the disposition is taken (applying `SA_RESETHAND`) and recorded, and a handler is
///   called with `sig` added to `HANDLING` unless `nodefer`.
/// - When the outermost handler for `sig` returns and `sig` became pending meanwhile, it is
///   delivered again by whatever disposition is in force then, as the kernel does on sigreturn
///   when the mask drops (man 7 signal, "Signal mask and pending signals").
///
/// Returns the outcome of the first delivery. The table is only read and recorded through
/// [`crate::real`], never while a handler runs, so a handler may call `sigaction` freely.
#[cfg(unix)]
fn deliver_with(
    signals: &dyn Signals,
    sig: c_int,
    source: SignalSource,
    tkill: bool,
) -> SignalOutcome {
    let bit = 1u64 << sig;
    let mut first = None;
    loop {
        if HANDLING.try_with(Cell::get).unwrap_or(0) & bit != 0 {
            // Blocked while its own handler runs: pending until that handler returns, and then
            // delivered by the disposition in force at that moment.
            let _ = DEFERRED.try_with(|d| d.set(d.get() | bit));
            return first.unwrap_or(SignalOutcome::Handled);
        }
        let disposition = crate::real(|| signals.take_disposition(sig));
        let outcome = match disposition {
            Disposition::Default => SignalOutcome::DefaultAction,
            Disposition::Ignore => SignalOutcome::Ignored,
            Disposition::Handler { .. } => SignalOutcome::Handled,
        };
        first.get_or_insert(outcome);
        crate::real(|| signals.record(sig, source, outcome));
        let Disposition::Handler {
            address,
            siginfo,
            nodefer,
        } = disposition
        else {
            break;
        };
        let previous = HANDLING.try_with(Cell::get).unwrap_or(0);
        if !nodefer {
            let _ = HANDLING.try_with(|h| h.set(previous | bit));
        }
        // SAFETY: the code under test installed `address` as a handler of this shape.
        simulated(|| unsafe { call_handler(address, siginfo, sig, source, tkill) });
        let _ = HANDLING.try_with(|h| h.set(previous));
        let redeliver = previous & bit == 0
            && DEFERRED
                .try_with(|d| {
                    let pending = d.get() & bit != 0;
                    d.set(d.get() & !bit);
                    pending
                })
                .unwrap_or(false);
        if !redeliver {
            break;
        }
    }
    first.unwrap_or(SignalOutcome::Handled)
}

/// The `si_code` of a signal sent with kill(2), or with `tkill` aimed at one thread: `SI_USER`
/// (0) or `SI_TKILL` (-6), per include/uapi/asm-generic/siginfo.h and kernel/signal.c
/// `prepare_kill_siginfo` (man 2 sigaction, "The si_code field").
#[cfg(target_os = "linux")]
fn si_code(tkill: bool) -> c_int {
    if tkill { libc::SI_TKILL } else { libc::SI_USER }
}

/// The `si_code` handed to a Darwin handler: `SI_USER`, 0x10001 in XNU bsd/sys/signal.h, for
/// process- and thread-directed signals alike.
///
/// Note that the real kernel does not use this value for `kill`: XNU bsd/kern/kern_sig.c
/// `psignal_internal` stores `si_code = 0` ("an ordinary signal"), and on macOS 26 (arm64) a
/// `SA_SIGINFO` handler sees `si_code == 0` after `kill`, `raise` and `pthread_kill` alike. The
/// sim's value is pinned by `crates/snare/tests/signals.rs`, which asserts `0x10001`.
#[cfg(target_os = "macos")]
fn si_code(_tkill: bool) -> c_int {
    0x10001
}

/// Calls a handler as the kernel would for a signal sent with `kill` (or `tgkill`, `tkill`): a
/// `siginfo_t` naming the sender, and a zeroed context.
///
/// The kernel fills `si_pid`/`si_uid` with the sender's (man 2 sigaction: "Signals sent with
/// kill(2) and sigqueue(3) fill in si_pid and si_uid"). For [`SignalSource::Process`] that is this
/// process; a signal from the sim or forwarded from outside names the parent process instead, a
/// snare choice standing in for the shell or supervisor that would have sent it. The context
/// (`ucontext_t`) is all zeros: handlers that inspect it are fault handlers, and the virtual
/// signals are never faults.
///
/// # Safety
/// `address` is a handler of the shape `siginfo` says.
#[cfg(unix)]
unsafe fn call_handler(
    address: usize,
    siginfo: bool,
    sig: c_int,
    source: SignalSource,
    tkill: bool,
) {
    if !siginfo {
        // SAFETY: the caller's handler.
        let handler: extern "C" fn(c_int) = unsafe { std::mem::transmute(address) };
        handler(sig);
        return;
    }
    // SAFETY: as above.
    let handler: extern "C" fn(c_int, *mut libc::siginfo_t, *mut libc::c_void) =
        unsafe { std::mem::transmute(address) };
    // SAFETY: both are plain C structs for which all-zero is a valid value.
    let (mut info, mut context): (libc::siginfo_t, libc::ucontext_t) =
        unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
    // SAFETY: getpid, getppid and getuid have no preconditions.
    let (pid, uid) = unsafe {
        let pid = if source == SignalSource::Process {
            libc::getpid()
        } else {
            libc::getppid()
        };
        (pid, libc::getuid())
    };
    fill_siginfo(&mut info, sig, si_code(tkill), pid, uid);
    handler(sig, &mut info, (&raw mut context).cast());
}

/// Writes the fields a kill(2)-sent signal carries into a zeroed `siginfo_t`.
///
/// The `libc` crate exposes the Linux `siginfo_t` union only through accessor methods, so the
/// fields are written at their offsets. include/uapi/asm-generic/siginfo.h `__SIGINFO`:
/// `si_signo` (0), `si_errno` (4), `si_code` (8), then `union __sifields`, which holds pointers
/// and so is 8-byte aligned at 16 on LP64; its `_kill` member is `si_pid` (16) then `si_uid`
/// (20). The whole struct is padded to `SI_MAX_SIZE`, 128 bytes. These offsets hold for the LP64
/// targets snare supports, not for 32-bit ones, where the union starts at 12, nor for MIPS
/// (`__ARCH_HAS_SWAPPED_SIGINFO`, `si_code` before `si_errno`).
#[cfg(target_os = "linux")]
fn fill_siginfo(
    info: &mut libc::siginfo_t,
    sig: c_int,
    code: c_int,
    pid: libc::pid_t,
    uid: libc::uid_t,
) {
    let base = (info as *mut libc::siginfo_t).cast::<u8>();
    // SAFETY: offsets inside the 128-byte siginfo_t, per the layout above.
    unsafe {
        base.cast::<c_int>().write(sig);
        base.add(8).cast::<c_int>().write(code);
        base.add(16).cast::<libc::pid_t>().write(pid);
        base.add(20).cast::<libc::uid_t>().write(uid);
    }
}

/// Writes the fields a kill(2)-sent signal carries; Darwin's `siginfo_t` has plain named fields
/// (XNU bsd/sys/signal.h, `struct __siginfo`).
#[cfg(target_os = "macos")]
fn fill_siginfo(
    info: &mut libc::siginfo_t,
    sig: c_int,
    code: c_int,
    pid: libc::pid_t,
    uid: libc::uid_t,
) {
    info.si_signo = sig;
    info.si_code = code;
    info.si_pid = pid;
    info.si_uid = uid;
}
