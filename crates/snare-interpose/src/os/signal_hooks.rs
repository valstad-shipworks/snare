//! The unix signal calls. For the virtual signals (see [`crate::is_virtual`]) a managed thread of a
//! domain with a [`Signals`](crate::Signals) table reads and changes the table instead of the
//! process's dispositions. A signal it sends to its own process or to itself is delivered from
//! the table on the spot, and one aimed at another thread of the domain is left pending for that
//! thread; everything else goes to the OS.
//!
//! Each hook either answers from the table and returns, or calls [`domain::observe`] (so an
//! executive's audit sees an OS signal call it did not model) and forwards to libc unchanged. The
//! table is reached through [`domain::dispatch_signals`], which declines in passthrough and off a
//! domain without a table, so the sim's own `sigaction` calls (real-signal forwarding) go to the
//! OS.

use std::ffi::c_int;
use std::sync::atomic::AtomicUsize;

use libc::{pid_t, pthread_t, sighandler_t};

use crate::domain;
use crate::hooks::{Hook, hook, original};
use crate::signals::{self, SignalSource, is_virtual};
use crate::state;

// The libc function each hook replaced, filled in by the patcher and read with `original`.
static SIGACTION: AtomicUsize = AtomicUsize::new(0);
static SIGNAL: AtomicUsize = AtomicUsize::new(0);
static RAISE: AtomicUsize = AtomicUsize::new(0);
static KILL: AtomicUsize = AtomicUsize::new(0);
static PTHREAD_KILL: AtomicUsize = AtomicUsize::new(0);

/// The unix signal hooks, for the platform hook table in `os`.
pub(crate) fn hooks() -> Vec<Hook> {
    vec![
        hook!("sigaction", sigaction, SIGACTION),
        hook!("signal", signal, SIGNAL),
        hook!("raise", raise, RAISE),
        hook!("kill", kill, KILL),
        hook!("pthread_kill", pthread_kill, PTHREAD_KILL),
    ]
}

/// libc's `sigaction` (man 2 sigaction).
type SigactionFn =
    unsafe extern "C" fn(c_int, *const libc::sigaction, *mut libc::sigaction) -> c_int;

/// `sigaction(sig, act, old)` (man 2 sigaction; IEEE Std 1003.1, sigaction): installs `act` (if
/// non-null) and reports the previous action in `old` (if non-null), returning 0. Invalid signals
/// and `SIGKILL`/`SIGSTOP` are never virtual, so the OS rejects them itself with `EINVAL`.
unsafe extern "C" fn sigaction(
    sig: c_int,
    act: *const libc::sigaction,
    old: *mut libc::sigaction,
) -> c_int {
    if is_virtual(sig) {
        // SAFETY: a non-null `act` points at the caller's sigaction.
        let act = unsafe { act.as_ref() };
        if let Some(previous) = domain::dispatch_signals(|table| table.sigaction(sig, act)) {
            if !old.is_null() {
                // SAFETY: a non-null `old` points at the caller's writable sigaction.
                unsafe { old.write(previous) };
            }
            return 0;
        }
    }
    domain::observe("sigaction", None);
    // SAFETY: SIGACTION holds libc's sigaction; arguments forwarded unchanged.
    unsafe { original::<SigactionFn>(&SIGACTION)(sig, act, old) }
}

/// `signal(sig, handler)` (man 2 signal; Darwin man 3 signal): glibc and Darwin both give BSD
/// semantics — the handler stays installed, the signal is blocked while it runs, and interrupted
/// calls restart — and return the previous handler, or `SIG_ERR` with `EINVAL`.
///
/// The virtual case builds the same `sigaction` glibc's `signal` does: `sa_mask` holding only
/// `sig`, `sa_flags = SA_RESTART` (glibc sysdeps/posix/signal.c `__bsd_signal`; man 2 signal,
/// "Portability"). Passing `SIG_ERR` as the handler is rejected with `EINVAL`, as glibc's
/// `__bsd_signal` does. Darwin's `signal` differs only in leaving `sa_mask` empty (Apple Libc
/// gen/FreeBSD/signal.c `signal__`), which a later `sigaction` query would show; the sim uses
/// glibc's mask on both.
unsafe extern "C" fn signal(sig: c_int, handler: sighandler_t) -> sighandler_t {
    if is_virtual(sig) {
        let previous = domain::dispatch_signals(|table| {
            if handler == libc::SIG_ERR {
                return None;
            }
            // SAFETY: an all-zero sigaction is valid; the set calls only write its mask.
            let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
            act.sa_sigaction = handler;
            // SAFETY: as above.
            unsafe {
                libc::sigemptyset(&mut act.sa_mask);
                libc::sigaddset(&mut act.sa_mask, sig);
            }
            act.sa_flags = libc::SA_RESTART;
            Some(table.sigaction(sig, Some(&act)).sa_sigaction)
        });
        match previous {
            Some(Some(previous)) => return previous,
            Some(None) => {
                // SAFETY: setting the calling thread's errno.
                unsafe { crate::os::sockets::set_errno(libc::EINVAL) };
                return libc::SIG_ERR;
            }
            None => {}
        }
    }
    domain::observe("signal", None);
    // SAFETY: SIGNAL holds libc's signal; arguments forwarded unchanged.
    unsafe {
        original::<unsafe extern "C" fn(c_int, sighandler_t) -> sighandler_t>(&SIGNAL)(sig, handler)
    }
}

/// Delivers `sig` to the calling thread from its domain's table, as a call aimed at itself.
///
/// `false` when the call is the OS's: in passthrough, off a domain with a table, or for a signal
/// that is not virtual. A delivery charges the per-call latency ([`domain::charge_latency`]) so
/// that a loop raising signals still advances a discrete clock.
fn deliver_self(sig: c_int, tkill: bool) -> bool {
    if state::passthrough() || signals::deliver(sig, SignalSource::Process, tkill).is_none() {
        return false;
    }
    domain::charge_latency();
    true
}

/// `raise(sig)` (man 3 raise; IEEE Std 1003.1, raise): the signal is delivered to the calling
/// thread, and "if a signal handler is called, the raise() function shall not return until after
/// the signal handler does". glibc implements it with tgkill(2), hence `tkill` for `si_code`.
unsafe extern "C" fn raise(sig: c_int) -> c_int {
    if deliver_self(sig, true) {
        return 0;
    }
    domain::observe("raise", None);
    // SAFETY: RAISE holds libc's raise.
    unsafe { original::<unsafe extern "C" fn(c_int) -> c_int>(&RAISE)(sig) }
}

/// `kill(pid, sig)` (man 2 kill; IEEE Std 1003.1, kill): `pid > 0` names a process, 0 the
/// caller's process group, -1 every process it may signal except itself, `< -1` the group `-pid`;
/// `sig` 0 only checks the target exists.
///
/// `kill(-1, sig)` skips the caller on both hosts: Linux man 2 kill NOTES ("on Linux the call
/// kill(-1,sig) does not signal the calling process"; kernel/signal.c `kill_something_info`
/// skips `same_thread_group(p, current)`), and Darwin man 2 kill ("excluding the process sending
/// the signal"). So only `getpid()`, 0 and `-getpgrp()` reach the caller. A virtual signal reaching
/// the caller's own process is delivered from the table, synchronously as POSIX requires of a
/// signal a process sends itself; the rest of the process group is not simulated.
unsafe extern "C" fn kill(pid: pid_t, sig: c_int) -> c_int {
    // SAFETY: getpid and getpgrp have no preconditions.
    let own = unsafe { pid == libc::getpid() || pid == 0 || pid == -libc::getpgrp() };
    if sig != 0 && own && deliver_self(sig, false) {
        return 0;
    }
    domain::observe("kill", None);
    // SAFETY: KILL holds libc's kill.
    unsafe { original::<unsafe extern "C" fn(pid_t, c_int) -> c_int>(&KILL)(pid, sig) }
}

/// `pthread_kill(thread, sig)` (man 3 pthread_kill; IEEE Std 1003.1, pthread_kill): a signal aimed
/// at one thread. To the caller itself it is delivered at once; to another thread of the domain it
/// is left pending ([`domain::post_signal`]) and delivered at that thread's next hooked call, the
/// sim's stand-in for the kernel interrupting it. A thread outside the domain gets the real
/// signal.
unsafe extern "C" fn pthread_kill(thread: pthread_t, sig: c_int) -> c_int {
    if is_virtual(sig) && !state::passthrough() && domain::signals_here().is_some() {
        // SAFETY: pthread_self has no preconditions.
        if thread == unsafe { libc::pthread_self() } {
            if deliver_self(sig, true) {
                return 0;
            }
        } else if domain::post_signal(crate::os::unix::handle_key(thread), sig) {
            domain::charge_latency();
            return 0;
        }
    }
    domain::observe("pthread_kill", None);
    // SAFETY: PTHREAD_KILL holds libc's pthread_kill.
    unsafe {
        original::<unsafe extern "C" fn(pthread_t, c_int) -> c_int>(&PTHREAD_KILL)(thread, sig)
    }
}
