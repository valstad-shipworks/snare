//! The unix signal calls. For the virtual signals (see [`crate::is_virtual`]) a managed thread of a
//! domain with a [`Signals`](crate::Signals) table reads and changes the table instead of the
//! process's dispositions, and its own mask of them (`pthread_sigmask`, `sigprocmask`) instead of
//! its real one. A signal it sends to itself is delivered from the table on the spot unless it
//! blocks it, one it sends to its own process goes to the thread the kernel would pick (see
//! `signals::target`), and one aimed at another thread of the domain is left pending for that
//! thread; `pause` and `sigsuspend` wait for a handler to run, and `sigwait`, `sigwaitinfo` and
//! `sigtimedwait` for a signal to take. Everything else goes to the OS, but for a `SIGCHLD` action
//! set outside every domain once the domains' children have it stood in for (see
//! [`crate::children`]), and the waits that reap a domain's child, which note how it ended.
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
use crate::children;
use crate::signals::{self, Cause, SignalSource, is_virtual};
use crate::state;

// The libc function each hook replaced, filled in by the patcher and read with `original`.
static SIGACTION: AtomicUsize = AtomicUsize::new(0);
static SIGNAL: AtomicUsize = AtomicUsize::new(0);
static RAISE: AtomicUsize = AtomicUsize::new(0);
static KILL: AtomicUsize = AtomicUsize::new(0);
static PTHREAD_KILL: AtomicUsize = AtomicUsize::new(0);
static PAUSE: AtomicUsize = AtomicUsize::new(0);
static SIGSUSPEND: AtomicUsize = AtomicUsize::new(0);
static WAITPID: AtomicUsize = AtomicUsize::new(0);
static WAIT4: AtomicUsize = AtomicUsize::new(0);
static WAITID: AtomicUsize = AtomicUsize::new(0);
static WAIT: AtomicUsize = AtomicUsize::new(0);
static PTHREAD_SIGMASK: AtomicUsize = AtomicUsize::new(0);
static SIGPROCMASK: AtomicUsize = AtomicUsize::new(0);
static SIGPENDING: AtomicUsize = AtomicUsize::new(0);
static SIGWAIT: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static SIGWAITINFO: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static SIGTIMEDWAIT: AtomicUsize = AtomicUsize::new(0);

/// The unix signal hooks, for the platform hook table in `os`.
pub(crate) fn hooks() -> Vec<Hook> {
    vec![
        hook!("sigaction", sigaction, SIGACTION),
        hook!("signal", signal, SIGNAL),
        hook!("raise", raise, RAISE),
        hook!("kill", kill, KILL),
        hook!("pthread_kill", pthread_kill, PTHREAD_KILL),
        hook!("pause", pause, PAUSE),
        hook!("sigsuspend", sigsuspend, SIGSUSPEND),
        hook!("waitpid", waitpid, WAITPID),
        hook!("wait4", wait4, WAIT4),
        hook!("waitid", waitid, WAITID),
        hook!("wait", wait, WAIT),
        hook!("pthread_sigmask", pthread_sigmask, PTHREAD_SIGMASK),
        hook!("sigprocmask", sigprocmask, SIGPROCMASK),
        hook!("sigpending", sigpending, SIGPENDING),
        hook!("sigwait", sigwait, SIGWAIT),
        #[cfg(target_os = "linux")]
        hook!("sigwaitinfo", sigwaitinfo, SIGWAITINFO),
        #[cfg(target_os = "linux")]
        hook!("sigtimedwait", sigtimedwait, SIGTIMEDWAIT),
    ]
}

/// libc's `sigaction` (man 2 sigaction).
type SigactionFn =
    unsafe extern "C" fn(c_int, *const libc::sigaction, *mut libc::sigaction) -> c_int;

/// `sigaction(sig, act, old)` (man 2 sigaction; IEEE Std 1003.1, sigaction): installs `act` (if
/// non-null) and reports the previous action in `old` (if non-null), returning 0. Invalid signals
/// and `SIGKILL`/`SIGSTOP` are never virtual, so the OS rejects them itself with `EINVAL`. A
/// `SIGCHLD` action set outside every domain becomes the process's own (see
/// [`children::outside_sigaction`]).
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
            if act.is_some() {
                signals::discard_if_ignored(sig);
            }
            return 0;
        }
        if sig == libc::SIGCHLD
            && !state::passthrough()
            // SAFETY: a non-null `old` points at the caller's writable sigaction.
            && children::outside_sigaction(act, unsafe { old.as_mut() }).is_some()
        {
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
            Some(table.sigaction(sig, Some(&bsd_action(sig, handler))).sa_sigaction)
        });
        match previous {
            Some(Some(previous)) => {
                signals::discard_if_ignored(sig);
                return previous;
            }
            Some(None) => {
                // SAFETY: setting the calling thread's errno.
                unsafe { crate::os::sockets::set_errno(libc::EINVAL) };
                return libc::SIG_ERR;
            }
            None => {}
        }
        if sig == libc::SIGCHLD && handler != libc::SIG_ERR && !state::passthrough() {
            let act = bsd_action(sig, handler);
            // SAFETY: an all-zero sigaction is valid.
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            if children::outside_sigaction(Some(&act), Some(&mut old)).is_some() {
                return old.sa_sigaction;
            }
        }
    }
    domain::observe("signal", None);
    // SAFETY: SIGNAL holds libc's signal; arguments forwarded unchanged.
    unsafe {
        original::<unsafe extern "C" fn(c_int, sighandler_t) -> sighandler_t>(&SIGNAL)(sig, handler)
    }
}

/// The action `signal(sig, handler)` installs (see [`signal`]).
fn bsd_action(sig: c_int, handler: sighandler_t) -> libc::sigaction {
    // SAFETY: an all-zero sigaction is valid; the set calls only write its mask.
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = handler;
    // SAFETY: as above.
    unsafe {
        libc::sigemptyset(&mut act.sa_mask);
        libc::sigaddset(&mut act.sa_mask, sig);
    }
    act.sa_flags = libc::SA_RESTART;
    act
}

/// Delivers `sig` from the calling thread's domain's table: with `tkill` to the calling thread, as
/// a call aimed at itself, else to its process (see [`signals::deliver_here`]).
///
/// `false` when the call is the OS's: in passthrough, off a domain with a table, or for a signal
/// that is not virtual. A delivery charges the per-call latency ([`domain::charge_latency`]) so
/// that a loop raising signals still advances a discrete clock.
fn deliver_self(sig: c_int, tkill: bool) -> bool {
    if state::passthrough() {
        return false;
    }
    let cause = Cause::Kill { tkill };
    let delivered = if tkill {
        signals::deliver(sig, SignalSource::Process, cause)
    } else {
        signals::deliver_to_process(sig, SignalSource::Process, cause)
    };
    if delivered.is_none() {
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

/// `pause()` (man 2 pause): waits until a signal handler has run on the calling thread, then
/// fails with `EINTR`; it is never restarted (man 7 signal, "Interruption of system calls and
/// library functions by signal handlers"). On a thread of a domain with a signal table the wait
/// is the domain's ([`Signals::suspend`](crate::Signals::suspend)).
unsafe extern "C" fn pause() -> c_int {
    if domain::dispatch_signals(|table| table.suspend()).is_some() {
        // SAFETY: setting the calling thread's errno.
        unsafe { crate::os::sockets::set_errno(libc::EINTR) };
        return -1;
    }
    domain::observe("pause", None);
    // SAFETY: PAUSE holds libc's pause.
    unsafe { original::<unsafe extern "C" fn() -> c_int>(&PAUSE)() }
}

/// `sigsuspend(mask)` (man 2 sigsuspend): as [`pause`] with the thread's mask replaced by `mask`
/// meanwhile, and put back once a handler has returned. On a thread of a domain with a signal
/// table it waits for a handler of the domain's that `mask` lets through to run, as `pause` does;
/// a real signal the mask lets in does not end it.
unsafe extern "C" fn sigsuspend(mask: *const libc::sigset_t) -> c_int {
    if !state::passthrough() && !mask.is_null() && domain::signal_domain().is_some() {
        let before = signals::mask();
        // SAFETY: a non-null `mask` points at the caller's signal set.
        signals::replace_mask(signals::virtual_bits(unsafe { &*mask }));
        let suspended = domain::dispatch_signals(|table| table.suspend());
        signals::change_mask(before);
        if suspended.is_some() {
            // SAFETY: setting the calling thread's errno.
            unsafe { crate::os::sockets::set_errno(libc::EINTR) };
            return -1;
        }
    }
    domain::observe("sigsuspend", None);
    // SAFETY: SIGSUSPEND holds libc's sigsuspend; the caller's mask.
    unsafe {
        original::<unsafe extern "C" fn(*const libc::sigset_t) -> c_int>(&SIGSUSPEND)(mask)
    }
}

/// Waits in the calling thread's domain for a child a wait with `options` is for to end, before
/// the wait blocks in the OS, so a signal handler of the domain's interrupts it as the host's
/// interrupts the wait (see [`crate::Net::await_child`] and [`crate::Net::await_children`]).
/// `pid` is `waitpid`'s: a child of a domain's is waited for through its own probe; any other
/// child, any child (-1) or a process group's (0, or below -1) through probes of the process's
/// children of that kind as they are found. `true` when a handler interrupted it, with `errno` set
/// to `EINTR`. One that returns at once (`WNOHANG`), or one for a stop or a continue as well, is
/// left to the OS.
fn interrupted_awaiting(pid: libc::pid_t, options: c_int) -> bool {
    if options & (libc::WNOHANG | libc::WUNTRACED | libc::WCONTINUED) != 0 || state::passthrough()
    {
        return false;
    }
    if pid > 0 && children::followed(pid) {
        return interrupted(domain::dispatch_net(|net| net.await_child(pid)));
    }
    let (idtype, id) = match pid {
        -1 => (libc::P_ALL, 0),
        // SAFETY: getpgrp has no preconditions.
        0 => (libc::P_PGID, (unsafe { libc::getpgrp() }) as libc::id_t),
        group if group < 0 => (libc::P_PGID, group.unsigned_abs() as libc::id_t),
        child => (libc::P_PID, child as libc::id_t),
    };
    interrupted_awaiting_any(idtype, id)
}

/// As [`interrupted_awaiting`], for a wait for the children `idtype` and `id` name, as `waitid`
/// names them, that blocks until one of them exits.
fn interrupted_awaiting_any(idtype: libc::idtype_t, id: libc::id_t) -> bool {
    if state::passthrough()
        || domain::signal_domain().is_none()
        || crate::real(|| children::reapable(idtype, id))
        || crate::real(|| children::of_process(idtype, id)).is_empty()
    {
        return false;
    }
    let mut listed = || crate::real(|| children::of_process(idtype, id));
    let mut ready = || crate::real(|| children::reapable(idtype, id));
    interrupted(domain::dispatch_net(|net| {
        net.await_children(&mut listed, &mut ready)
    }))
}

/// Whether a backend's wait for a child failed, with `EINTR` from a handler, which it sets as
/// `errno`.
fn interrupted(waited: Option<i64>) -> bool {
    match waited {
        Some(r) if r < 0 => {
            // SAFETY: setting the calling thread's errno.
            unsafe { crate::os::sockets::set_errno((-r) as c_int) };
            true
        }
        _ => false,
    }
}

/// `waitpid(pid, status, options)` (man 2 waitpid), noting how a reaped child of a domain ended.
unsafe extern "C" fn waitpid(pid: libc::pid_t, status: *mut c_int, options: c_int) -> libc::pid_t {
    if interrupted_awaiting(pid, options) {
        return -1;
    }
    type WaitpidFn = unsafe extern "C" fn(libc::pid_t, *mut c_int, c_int) -> libc::pid_t;
    let mut seen = 0;
    let out = if status.is_null() { &raw mut seen } else { status };
    // SAFETY: WAITPID holds libc's waitpid; `out` is the caller's status or a local.
    let reaped = unsafe { original::<WaitpidFn>(&WAITPID)(pid, out, options) };
    if reaped > 0 {
        // SAFETY: waitpid wrote the status.
        children::reaped(reaped, unsafe { *out });
    }
    reaped
}

/// `wait4(pid, status, options, usage)` (man 2 wait4), as [`waitpid`].
unsafe extern "C" fn wait4(
    pid: libc::pid_t,
    status: *mut c_int,
    options: c_int,
    usage: *mut libc::rusage,
) -> libc::pid_t {
    if interrupted_awaiting(pid, options) {
        return -1;
    }
    type Wait4Fn =
        unsafe extern "C" fn(libc::pid_t, *mut c_int, c_int, *mut libc::rusage) -> libc::pid_t;
    let mut seen = 0;
    let out = if status.is_null() { &raw mut seen } else { status };
    // SAFETY: WAIT4 holds libc's wait4; the caller's arguments, `out` for its status.
    let reaped = unsafe { original::<Wait4Fn>(&WAIT4)(pid, out, options, usage) };
    if reaped > 0 {
        // SAFETY: wait4 wrote the status.
        children::reaped(reaped, unsafe { *out });
    }
    reaped
}

/// `wait(status)` (man 2 wait), as [`waitpid`] of any child.
unsafe extern "C" fn wait(status: *mut c_int) -> libc::pid_t {
    if interrupted_awaiting(-1, 0) {
        return -1;
    }
    let mut seen = 0;
    let out = if status.is_null() { &raw mut seen } else { status };
    // SAFETY: WAIT holds libc's wait; `out` is the caller's status or a local.
    let reaped = unsafe { original::<unsafe extern "C" fn(*mut c_int) -> libc::pid_t>(&WAIT)(out) };
    if reaped > 0 {
        // SAFETY: wait wrote the status.
        children::reaped(reaped, unsafe { *out });
    }
    reaped
}

/// `waitid(idtype, id, info, options)` (man 2 waitid), noting how a reaped child of a domain ended;
/// with `WNOWAIT` the child is left to be reaped and nothing is noted. One that blocks until a
/// child exits is one a signal handler of the domain's interrupts, as [`waitpid`].
unsafe extern "C" fn waitid(
    idtype: libc::idtype_t,
    id: libc::id_t,
    info: *mut libc::siginfo_t,
    options: c_int,
) -> c_int {
    let exits = options & libc::WEXITED != 0
        && options & (libc::WNOHANG | libc::WSTOPPED | libc::WCONTINUED) == 0
        && matches!(idtype, libc::P_ALL | libc::P_PID | libc::P_PGID);
    if exits && interrupted_awaiting_any(idtype, id) {
        return -1;
    }
    type WaitidFn =
        unsafe extern "C" fn(libc::idtype_t, libc::id_t, *mut libc::siginfo_t, c_int) -> c_int;
    // SAFETY: WAITID holds libc's waitid; the caller's arguments.
    let r = unsafe { original::<WaitidFn>(&WAITID)(idtype, id, info, options) };
    if r == 0 && !info.is_null() && options & libc::WNOWAIT == 0 {
        // SAFETY: waitid filled `info`.
        let (pid, code, status) =
            unsafe { ((*info).si_pid(), (*info).si_code, (*info).si_status()) };
        children::reaped_info(pid, code, status);
    }
    r
}

/// libc's `pthread_sigmask` and `sigprocmask` (man 2 sigprocmask, man 3 pthread_sigmask).
type SigmaskFn = unsafe extern "C" fn(c_int, *const libc::sigset_t, *mut libc::sigset_t) -> c_int;

/// The mask change of `pthread_sigmask` and `sigprocmask` on a thread of a domain with a signal
/// table: the virtual signals in `set` change the thread's mask in the domain, the rest its real
/// one through `real`, and `old` reports both. The real mask keeps its virtual signals as they
/// were, so a signal the kernel sends the process still reaches the sim's own handlers (see
/// [`crate::children`] and `snare::signals::forward`). `None` when the call is the OS's alone;
/// otherwise what `real` returned, which also rejects an unknown `how` (`EINVAL`, only with a set
/// given: man 2 sigprocmask; on both hosts a null `set` with any `how` only reads the mask).
///
/// # Safety
/// `set` and `old` are null or point at signal sets, as the caller's call takes them.
unsafe fn change_mask(
    how: c_int,
    set: *const libc::sigset_t,
    old: *mut libc::sigset_t,
    real: impl Fn(c_int, *const libc::sigset_t, *mut libc::sigset_t) -> c_int,
) -> Option<c_int> {
    if state::passthrough() {
        return None;
    }
    domain::signal_domain()?;
    let before = signals::mask();
    // SAFETY: a non-null `set` points at the caller's signal set.
    let wanted = unsafe { set.as_ref() };
    let mut outside = wanted.copied();
    if let Some(outside) = outside.as_mut() {
        let keep = if how == libc::SIG_SETMASK {
            // SAFETY: an all-zero sigset_t is valid; a null new set only reads the mask.
            let mut current: libc::sigset_t = unsafe { std::mem::zeroed() };
            crate::real(|| real(libc::SIG_BLOCK, std::ptr::null(), &mut current));
            signals::virtual_bits(&current)
        } else {
            0
        };
        signals::set_virtual_bits(outside, keep);
    }
    let r = crate::real(|| {
        real(
            how,
            outside.as_ref().map_or(std::ptr::null(), std::ptr::from_ref),
            old,
        )
    });
    if r != 0 {
        return Some(r);
    }
    if !old.is_null() {
        // SAFETY: the caller's writable signal set, just filled by the OS.
        signals::set_virtual_bits(unsafe { &mut *old }, before);
    }
    if let Some(wanted) = wanted {
        let bits = signals::virtual_bits(wanted);
        let next = match how {
            libc::SIG_BLOCK => before | bits,
            libc::SIG_UNBLOCK => before & !bits,
            _ => bits,
        };
        signals::change_mask(next);
    }
    domain::charge_latency();
    Some(0)
}

/// `pthread_sigmask(how, set, old)` (man 3 pthread_sigmask; IEEE Std 1003.1, pthread_sigmask): see
/// [`change_mask`]. Returns an error number. A pending signal the new mask lets through is
/// delivered before it returns.
unsafe extern "C" fn pthread_sigmask(
    how: c_int,
    set: *const libc::sigset_t,
    old: *mut libc::sigset_t,
) -> c_int {
    // SAFETY: PTHREAD_SIGMASK holds libc's pthread_sigmask; the caller's arguments.
    let real = |how, set, old| unsafe { original::<SigmaskFn>(&PTHREAD_SIGMASK)(how, set, old) };
    // SAFETY: the caller's arguments.
    if let Some(r) = unsafe { change_mask(how, set, old, real) } {
        return r;
    }
    domain::observe("pthread_sigmask", None);
    real(how, set, old)
}

/// `sigprocmask(how, set, old)` (man 2 sigprocmask): the calling thread's mask, as
/// [`pthread_sigmask`], failing with -1 and `errno`. On both Linux and Darwin it changes only the
/// calling thread's mask (Linux kernel/signal.c `sigprocmask` sets `current->blocked`; XNU
/// bsd/kern/kern_sig.c `sigprocmask` the calling uthread's `uu_sigmask`).
unsafe extern "C" fn sigprocmask(
    how: c_int,
    set: *const libc::sigset_t,
    old: *mut libc::sigset_t,
) -> c_int {
    // SAFETY: SIGPROCMASK holds libc's sigprocmask; the caller's arguments.
    let real = |how, set, old| {
        // SAFETY: as above.
        let r = unsafe { original::<SigmaskFn>(&SIGPROCMASK)(how, set, old) };
        if r == 0 { 0 } else { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) }
    };
    // SAFETY: the caller's arguments.
    match unsafe { change_mask(how, set, old, real) } {
        Some(0) => 0,
        Some(e) => {
            // SAFETY: setting the calling thread's errno.
            unsafe { crate::os::sockets::set_errno(e) };
            -1
        }
        None => {
            domain::observe("sigprocmask", None);
            // SAFETY: as above.
            unsafe { original::<SigmaskFn>(&SIGPROCMASK)(how, set, old) }
        }
    }
}

/// `sigpending(set)` (man 2 sigpending): the signals pending for the calling thread or its
/// process; the virtual ones are the domain's.
unsafe extern "C" fn sigpending(set: *mut libc::sigset_t) -> c_int {
    // SAFETY: SIGPENDING holds libc's sigpending; the caller's set.
    let r = unsafe {
        original::<unsafe extern "C" fn(*mut libc::sigset_t) -> c_int>(&SIGPENDING)(set)
    };
    if r == 0
        && !set.is_null()
        && !state::passthrough()
        && let Some(pending) = signals::pending()
    {
        // SAFETY: the caller's writable signal set, just filled by the OS.
        signals::set_virtual_bits(unsafe { &mut *set }, pending);
    }
    r
}

/// The virtual signals of `set` a `sigwait`-family call of the calling thread waits for in its
/// domain: `None` when the call is the OS's, for a set of none of them or off a domain with a
/// signal table. A set that also names signals the domain leaves to the OS waits for the domain's
/// alone.
fn waited(set: *const libc::sigset_t) -> Option<(domain::SignalDomain, u64)> {
    if state::passthrough() || set.is_null() {
        return None;
    }
    // SAFETY: a non-null `set` points at the caller's signal set.
    let wanted = signals::virtual_bits(unsafe { &*set });
    if wanted == 0 {
        return None;
    }
    Some((domain::signal_domain()?, wanted))
}

/// `sigwait(set, sig)` (man 3 sigwait; IEEE Std 1003.1, sigwait): takes a pending signal of
/// `set`, waiting for one, and stores its number in `sig`; returns 0. A handler of another signal
/// that runs meanwhile does not end it, on either host: glibc's retries `sigtimedwait` on `EINTR`
/// (sysdeps/unix/sysv/linux/sigwait.c `do_sigwait`), and POSIX lets it fail with nothing else
/// than `EINVAL`.
unsafe extern "C" fn sigwait(set: *const libc::sigset_t, sig: *mut c_int) -> c_int {
    if let Some((domain, wanted)) = waited(set) {
        loop {
            if let signals::Waited::Took(posted) = signals::wait_for(domain, wanted, None, "sigwait")
            {
                if !sig.is_null() {
                    // SAFETY: a non-null `sig` points at the caller's int.
                    unsafe { sig.write(posted.sig) };
                }
                return 0;
            }
        }
    }
    domain::observe("sigwait", None);
    // SAFETY: SIGWAIT holds libc's sigwait; the caller's arguments.
    unsafe {
        original::<unsafe extern "C" fn(*const libc::sigset_t, *mut c_int) -> c_int>(&SIGWAIT)(
            set, sig,
        )
    }
}

/// `sigtimedwait` and `sigwaitinfo` on a domain's signals (man 2 sigwaitinfo): the number of the
/// signal taken, `info` filled as a handler's would be; -1 with `EAGAIN` once `timeout` has passed,
/// or `EINTR` when a handler of another signal ran. A thread-directed signal's `si_code` reads
/// `SI_USER`, as glibc folds the kernel's `SI_TKILL` into it (sysdeps/unix/sysv/linux/
/// sigtimedwait.c); pinned against the host by crates/snare/tests/signal_masks.rs.
#[cfg(target_os = "linux")]
fn wait_info(
    domain: domain::SignalDomain,
    wanted: u64,
    info: *mut libc::siginfo_t,
    timeout: Option<std::time::Duration>,
    label: &'static str,
) -> c_int {
    let e = match signals::wait_for(domain, wanted, timeout, label) {
        signals::Waited::Took(posted) => {
            if !info.is_null() {
                let signals::SignalInfo {
                    signo,
                    code,
                    pid,
                    uid,
                    status,
                } = signals::info(posted);
                let code = if code == libc::SI_TKILL { libc::SI_USER } else { code };
                // SAFETY: an all-zero siginfo_t is valid; the caller's writable one.
                unsafe {
                    info.write(std::mem::zeroed());
                    signals::fill_siginfo(&mut *info, signo, code, pid, uid, status);
                }
            }
            return posted.sig;
        }
        signals::Waited::Interrupted => libc::EINTR,
        signals::Waited::TimedOut => libc::EAGAIN,
    };
    // SAFETY: setting the calling thread's errno.
    unsafe { crate::os::sockets::set_errno(e) };
    -1
}

/// `sigwaitinfo(set, info)` (man 2 sigwaitinfo): [`wait_info`] with no timeout.
#[cfg(target_os = "linux")]
unsafe extern "C" fn sigwaitinfo(set: *const libc::sigset_t, info: *mut libc::siginfo_t) -> c_int {
    if let Some((domain, wanted)) = waited(set) {
        return wait_info(domain, wanted, info, None, "sigwaitinfo");
    }
    domain::observe("sigwaitinfo", None);
    type SigwaitinfoFn = unsafe extern "C" fn(*const libc::sigset_t, *mut libc::siginfo_t) -> c_int;
    // SAFETY: SIGWAITINFO holds libc's sigwaitinfo; the caller's arguments.
    unsafe { original::<SigwaitinfoFn>(&SIGWAITINFO)(set, info) }
}

/// `sigtimedwait(set, info, timeout)` (man 2 sigtimedwait): [`wait_info`] for at most `timeout`
/// of the domain's time; a null `timeout` waits for good, and one out of range fails with `EINVAL`
/// (kernel/signal.c `do_sigtimedwait`: `timespec64_valid`).
#[cfg(target_os = "linux")]
unsafe extern "C" fn sigtimedwait(
    set: *const libc::sigset_t,
    info: *mut libc::siginfo_t,
    timeout: *const libc::timespec,
) -> c_int {
    if let Some((domain, wanted)) = waited(set) {
        // SAFETY: a non-null `timeout` points at the caller's timespec.
        let span = match unsafe { timeout.as_ref() } {
            None => None,
            Some(ts) if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) => {
                // SAFETY: setting the calling thread's errno.
                unsafe { crate::os::sockets::set_errno(libc::EINVAL) };
                return -1;
            }
            Some(ts) => Some(std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)),
        };
        return wait_info(domain, wanted, info, span, "sigtimedwait");
    }
    domain::observe("sigtimedwait", None);
    type SigtimedwaitFn = unsafe extern "C" fn(
        *const libc::sigset_t,
        *mut libc::siginfo_t,
        *const libc::timespec,
    ) -> c_int;
    // SAFETY: SIGTIMEDWAIT holds libc's sigtimedwait; the caller's arguments.
    unsafe { original::<SigtimedwaitFn>(&SIGTIMEDWAIT)(set, info, timeout) }
}
