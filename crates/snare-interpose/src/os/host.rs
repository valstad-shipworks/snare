//! Scheduling, affinity, priority, resource-limit and memory-locking hooks that consult the calling thread's
//! [`Host`](crate::Host) before the OS. These are the *named* libc symbols; the raw-syscall forms
//! (`syscall(SYS_sched_setscheduler, …)`, which musl-linked programs use) are caught by the
//! `syscall` hook in `unix.rs`, which also consults the host. A `None` host declines, and the call
//! reaches the real kernel unchanged.
//!
//! Every hook here follows one shape: offer the call to [`dispatch_host`] (which declines under
//! passthrough and outside a domain), and on `Some` turn the host's result into the C return
//! convention; on `None` call the original. Linux-only (`gettid` is glibc 2.30+; man 2 gettid).

use std::ffi::c_int;
use std::sync::atomic::AtomicUsize;

use crate::domain::dispatch_host;
use crate::hooks::{Hook, hook, original};
use crate::os::sockets::finish;

/// Declares the `AtomicUsize` that holds one hook's original, filled by [`crate::patch::install`].
macro_rules! slot {
    ($name:ident) => {
        static $name: AtomicUsize = AtomicUsize::new(0);
    };
}

slot!(GETTID);
slot!(SCHED_SETSCHEDULER);
slot!(SCHED_GETSCHEDULER);
slot!(SCHED_SETPARAM);
slot!(SCHED_GETPARAM);
slot!(SCHED_SETAFFINITY);
slot!(SCHED_GETAFFINITY);
slot!(SETPRIORITY);
slot!(GETPRIORITY);
slot!(MLOCKALL);
slot!(MUNLOCKALL);
slot!(MLOCK);
slot!(MUNLOCK);
slot!(GETRLIMIT);
slot!(GETRLIMIT64);
slot!(SETRLIMIT);
slot!(SETRLIMIT64);
slot!(PRLIMIT);
slot!(PRLIMIT64);
slot!(PTHREAD_SETSCHEDPARAM);
slot!(PTHREAD_GETSCHEDPARAM);

/// The hooks this module contributes to the Linux hook table; all are modelled.
pub(crate) fn hooks() -> Vec<Hook> {
    vec![
        hook!("gettid", gettid, GETTID),
        hook!("sched_setscheduler", sched_setscheduler, SCHED_SETSCHEDULER),
        hook!("sched_getscheduler", sched_getscheduler, SCHED_GETSCHEDULER),
        hook!("sched_setparam", sched_setparam, SCHED_SETPARAM),
        hook!("sched_getparam", sched_getparam, SCHED_GETPARAM),
        hook!("sched_setaffinity", sched_setaffinity, SCHED_SETAFFINITY),
        hook!("sched_getaffinity", sched_getaffinity, SCHED_GETAFFINITY),
        hook!("setpriority", setpriority, SETPRIORITY),
        hook!("getpriority", getpriority, GETPRIORITY),
        hook!("mlockall", mlockall, MLOCKALL),
        hook!("munlockall", munlockall, MUNLOCKALL),
        hook!("mlock", mlock, MLOCK),
        hook!("munlock", munlock, MUNLOCK),
        hook!("getrlimit", getrlimit, GETRLIMIT),
        hook!("getrlimit64", getrlimit64, GETRLIMIT64),
        hook!("setrlimit", setrlimit, SETRLIMIT),
        hook!("setrlimit64", setrlimit64, SETRLIMIT64),
        hook!("prlimit", prlimit, PRLIMIT),
        hook!("prlimit64", prlimit64, PRLIMIT64),
        hook!(
            "pthread_setschedparam",
            pthread_setschedparam,
            PTHREAD_SETSCHEDPARAM
        ),
        hook!(
            "pthread_getschedparam",
            pthread_getschedparam,
            PTHREAD_GETSCHEDPARAM
        ),
    ]
}

/// `gettid`: the host's simulated thread id, or the real one.
unsafe extern "C" fn gettid() -> libc::pid_t {
    // man 2 gettid: the kernel thread id (a TID), which for sched_* is the per-thread `pid`.
    if let Some(r) = dispatch_host(|h| h.gettid()) {
        return finish(r) as libc::pid_t;
    }
    // SAFETY: GETTID holds libc's gettid.
    unsafe { original::<unsafe extern "C" fn() -> libc::pid_t>(&GETTID)() }
}

/// `sched_setscheduler`: `0` or `-1` with errno from the host, or the real call.
unsafe extern "C" fn sched_setscheduler(
    pid: libc::pid_t,
    policy: c_int,
    param: *const libc::sched_param,
) -> c_int {
    // man 2 sched_setscheduler: policy SCHED_OTHER/FIFO/RR/BATCH/IDLE; sched_param.sched_priority
    // is in 1..=99 for the realtime policies and must be 0 otherwise (man 7 sched).
    // SAFETY: `param` points to a `sched_param`.
    if let Some(r) = dispatch_host(|h| unsafe { h.sched_setscheduler(pid, policy, param.cast()) }) {
        return finish(r) as c_int;
    }
    // SAFETY: SCHED_SETSCHEDULER holds libc's sched_setscheduler.
    unsafe {
        original::<unsafe extern "C" fn(libc::pid_t, c_int, *const libc::sched_param) -> c_int>(
            &SCHED_SETSCHEDULER,
        )(pid, policy, param)
    }
}

/// `sched_getscheduler`: the policy, or `-1` with errno, from the host or the real call.
unsafe extern "C" fn sched_getscheduler(pid: libc::pid_t) -> c_int {
    // man 2 sched_getscheduler: returns the policy (a SCHED_* constant) for the thread.
    if let Some(r) = dispatch_host(|h| unsafe { h.sched_getscheduler(pid) }) {
        return finish(r) as c_int;
    }
    // SAFETY: SCHED_GETSCHEDULER holds libc's sched_getscheduler.
    unsafe { original::<unsafe extern "C" fn(libc::pid_t) -> c_int>(&SCHED_GETSCHEDULER)(pid) }
}

/// `sched_setparam`: `0` or `-1` with errno from the host, or the real call.
unsafe extern "C" fn sched_setparam(pid: libc::pid_t, param: *const libc::sched_param) -> c_int {
    // man 2 sched_setparam: sets sched_priority within the thread's current policy.
    // SAFETY: `param` points to a `sched_param`.
    if let Some(r) = dispatch_host(|h| unsafe { h.sched_setparam(pid, param.cast()) }) {
        return finish(r) as c_int;
    }
    // SAFETY: SCHED_SETPARAM holds libc's sched_setparam.
    unsafe {
        original::<unsafe extern "C" fn(libc::pid_t, *const libc::sched_param) -> c_int>(
            &SCHED_SETPARAM,
        )(pid, param)
    }
}

/// `sched_getparam`: fills `param` and returns `0`, or `-1` with errno.
unsafe extern "C" fn sched_getparam(pid: libc::pid_t, param: *mut libc::sched_param) -> c_int {
    // man 2 sched_getparam: reports sched_priority (0 for the non-realtime policies).
    // SAFETY: `param` receives a `sched_param`.
    if let Some(r) = dispatch_host(|h| unsafe { h.sched_getparam(pid, param.cast()) }) {
        return finish(r) as c_int;
    }
    // SAFETY: SCHED_GETPARAM holds libc's sched_getparam.
    unsafe {
        original::<unsafe extern "C" fn(libc::pid_t, *mut libc::sched_param) -> c_int>(
            &SCHED_GETPARAM,
        )(pid, param)
    }
}

/// `sched_setaffinity`: `0` or `-1` with errno from the host, or the real call.
unsafe extern "C" fn sched_setaffinity(
    pid: libc::pid_t,
    cpusetsize: usize,
    set: *const libc::cpu_set_t,
) -> c_int {
    // man 2 sched_setaffinity: cpu_set_t is a fixed-size bitmask (CPU_SETSIZE bits, built with
    // the CPU_SET(3) macros); `cpusetsize` is sizeof(cpu_set_t) in bytes.
    // SAFETY: `set` points to `cpusetsize` bytes of mask.
    if let Some(r) = dispatch_host(|h| unsafe { h.sched_setaffinity(pid, cpusetsize, set.cast()) })
    {
        return finish(r) as c_int;
    }
    // SAFETY: SCHED_SETAFFINITY holds libc's sched_setaffinity.
    unsafe {
        original::<unsafe extern "C" fn(libc::pid_t, usize, *const libc::cpu_set_t) -> c_int>(
            &SCHED_SETAFFINITY,
        )(pid, cpusetsize, set)
    }
}

/// `sched_getaffinity`: the glibc wrapper returns `0` on success, though the raw syscall returns
/// the mask size it copied (man 2 sched_getaffinity, C library/kernel differences). This hook
/// stands in for the wrapper, so a host should return `Ok(0)` here.
unsafe extern "C" fn sched_getaffinity(
    pid: libc::pid_t,
    cpusetsize: usize,
    set: *mut libc::cpu_set_t,
) -> c_int {
    // man 2 sched_getaffinity: writes the thread's CPU-affinity bitmask into `set`.
    // SAFETY: `set` receives `cpusetsize` bytes of mask.
    if let Some(r) = dispatch_host(|h| unsafe { h.sched_getaffinity(pid, cpusetsize, set.cast()) })
    {
        return finish(r) as c_int;
    }
    // SAFETY: SCHED_GETAFFINITY holds libc's sched_getaffinity.
    unsafe {
        original::<unsafe extern "C" fn(libc::pid_t, usize, *mut libc::cpu_set_t) -> c_int>(
            &SCHED_GETAFFINITY,
        )(pid, cpusetsize, set)
    }
}

/// `setpriority`: `0` or `-1` with errno from the host, or the real call.
unsafe extern "C" fn setpriority(which: c_int, who: libc::id_t, prio: c_int) -> c_int {
    // man 2 setpriority: `which` is PRIO_PROCESS/PGRP/USER; nice `prio` ranges -20..=19.
    // SAFETY: no pointers.
    if let Some(r) = dispatch_host(|h| unsafe { h.setpriority(which, who, prio) }) {
        return finish(r) as c_int;
    }
    // SAFETY: SETPRIORITY holds libc's setpriority.
    unsafe {
        original::<unsafe extern "C" fn(c_int, libc::id_t, c_int) -> c_int>(&SETPRIORITY)(
            which, who, prio,
        )
    }
}

/// `getpriority`: the host's nice value, returned as-is (see the note in the body), or the real
/// call.
unsafe extern "C" fn getpriority(which: c_int, who: libc::id_t) -> c_int {
    // man 2 getpriority: returns the nice value, which may legitimately be negative — so it cannot
    // use the `finish` "negative means errno" convention. (The raw syscall returns 20 - nice, i.e.
    // 40..=1, so its own return value is never negative and cannot be mistaken for an error; libc
    // maps it back and, per the man page's RETURN VALUE, a caller clears errno before the call to
    // tell a true -1 error from nice == -1.)
    // A host models it as always succeeding and returns the value directly.
    // SAFETY: no pointers.
    if let Some(r) = dispatch_host(|h| unsafe { h.getpriority(which, who) }) {
        return r as c_int;
    }
    // SAFETY: GETPRIORITY holds libc's getpriority.
    unsafe {
        original::<unsafe extern "C" fn(c_int, libc::id_t) -> c_int>(&GETPRIORITY)(which, who)
    }
}

/// `mlockall`: `0` or `-1` with errno from the host, or the real call.
unsafe extern "C" fn mlockall(flags: c_int) -> c_int {
    // man 2 mlockall: flags MCL_CURRENT/MCL_FUTURE(/MCL_ONFAULT) lock the process's pages resident.
    if let Some(r) = dispatch_host(|h| h.mlockall(flags)) {
        return finish(r) as c_int;
    }
    // SAFETY: MLOCKALL holds libc's mlockall.
    unsafe { original::<unsafe extern "C" fn(c_int) -> c_int>(&MLOCKALL)(flags) }
}

/// `munlockall`: `0` or `-1` with errno from the host, or the real call.
unsafe extern "C" fn munlockall() -> c_int {
    // man 2 munlockall: undoes mlockall, unlocking all of the process's mapped pages.
    if let Some(r) = dispatch_host(|h| h.munlockall()) {
        return finish(r) as c_int;
    }
    // SAFETY: MUNLOCKALL holds libc's munlockall.
    unsafe { original::<unsafe extern "C" fn() -> c_int>(&MUNLOCKALL)() }
}

/// `mlock`: `0` or `-1` with errno from the host, or the real call.
unsafe extern "C" fn mlock(addr: *const libc::c_void, len: usize) -> c_int {
    // man 2 mlock: locks the pages of [addr, addr + len) resident, charged to RLIMIT_MEMLOCK.
    if let Some(r) = dispatch_host(|h| h.mlock(addr as u64, len as u64)) {
        return finish(r) as c_int;
    }
    // SAFETY: MLOCK holds libc's mlock.
    unsafe {
        original::<unsafe extern "C" fn(*const libc::c_void, usize) -> c_int>(&MLOCK)(addr, len)
    }
}

/// `munlock`: `0` or `-1` with errno from the host, or the real call.
unsafe extern "C" fn munlock(addr: *const libc::c_void, len: usize) -> c_int {
    // man 2 munlock: unlocks the pages of [addr, addr + len).
    if let Some(r) = dispatch_host(|h| h.munlock(addr as u64, len as u64)) {
        return finish(r) as c_int;
    }
    // SAFETY: MUNLOCK holds libc's munlock.
    unsafe {
        original::<unsafe extern "C" fn(*const libc::c_void, usize) -> c_int>(&MUNLOCK)(addr, len)
    }
}

/// The C signature of `getrlimit`/`getrlimit64` (identical on 64-bit glibc, which aliases them).
type GetrlimitFn = unsafe extern "C" fn(c_int, *mut libc::rlimit) -> c_int;
/// The C signature of `setrlimit`/`setrlimit64`.
type SetrlimitFn = unsafe extern "C" fn(c_int, *const libc::rlimit) -> c_int;
/// The C signature of `prlimit`/`prlimit64`.
type PrlimitFn =
    unsafe extern "C" fn(libc::pid_t, c_int, *const libc::rlimit, *mut libc::rlimit) -> c_int;

/// `getrlimit` and `getrlimit64` through `slot`: `0` or `-1` with errno from the host, or the
/// real call.
fn getrlimit_via(slot: &AtomicUsize, resource: c_int, rlim: *mut libc::rlimit) -> c_int {
    // man 2 getrlimit: writes the soft and hard limit of `resource` to *rlim.
    // SAFETY: `rlim` is the caller's `struct rlimit`.
    if let Some(r) = dispatch_host(|h| unsafe { h.getrlimit(resource, rlim.cast()) }) {
        return finish(r) as c_int;
    }
    // SAFETY: `slot` holds libc's getrlimit or getrlimit64.
    unsafe { original::<GetrlimitFn>(slot)(resource, rlim) }
}

/// `setrlimit` and `setrlimit64` through `slot`.
fn setrlimit_via(slot: &AtomicUsize, resource: c_int, rlim: *const libc::rlimit) -> c_int {
    // man 2 setrlimit: installs *rlim as `resource`'s soft and hard limit.
    // SAFETY: `rlim` is the caller's `struct rlimit`.
    if let Some(r) = dispatch_host(|h| unsafe { h.setrlimit(resource, rlim.cast()) }) {
        return finish(r) as c_int;
    }
    // SAFETY: `slot` holds libc's setrlimit or setrlimit64.
    unsafe { original::<SetrlimitFn>(slot)(resource, rlim) }
}

/// `prlimit` and `prlimit64` through `slot`.
fn prlimit_via(
    slot: &AtomicUsize,
    pid: libc::pid_t,
    resource: c_int,
    new: *const libc::rlimit,
    old: *mut libc::rlimit,
) -> c_int {
    // man 2 prlimit: reads `pid`'s old limit into *old and installs *new; either may be NULL.
    // SAFETY: `new`/`old` are the caller's.
    if let Some(r) = dispatch_host(|h| unsafe { h.prlimit(pid, resource, new.cast(), old.cast()) })
    {
        return finish(r) as c_int;
    }
    // SAFETY: `slot` holds libc's prlimit or prlimit64.
    unsafe { original::<PrlimitFn>(slot)(pid, resource, new, old) }
}

/// `getrlimit`.
unsafe extern "C" fn getrlimit(resource: c_int, rlim: *mut libc::rlimit) -> c_int {
    getrlimit_via(&GETRLIMIT, resource, rlim)
}

/// `getrlimit64`.
unsafe extern "C" fn getrlimit64(resource: c_int, rlim: *mut libc::rlimit) -> c_int {
    getrlimit_via(&GETRLIMIT64, resource, rlim)
}

/// `setrlimit`.
unsafe extern "C" fn setrlimit(resource: c_int, rlim: *const libc::rlimit) -> c_int {
    setrlimit_via(&SETRLIMIT, resource, rlim)
}

/// `setrlimit64`.
unsafe extern "C" fn setrlimit64(resource: c_int, rlim: *const libc::rlimit) -> c_int {
    setrlimit_via(&SETRLIMIT64, resource, rlim)
}

/// `prlimit`.
unsafe extern "C" fn prlimit(
    pid: libc::pid_t,
    resource: c_int,
    new: *const libc::rlimit,
    old: *mut libc::rlimit,
) -> c_int {
    prlimit_via(&PRLIMIT, pid, resource, new, old)
}

/// `prlimit64`.
unsafe extern "C" fn prlimit64(
    pid: libc::pid_t,
    resource: c_int,
    new: *const libc::rlimit,
    old: *mut libc::rlimit,
) -> c_int {
    prlimit_via(&PRLIMIT64, pid, resource, new, old)
}

/// `pthread_setschedparam`: returns the error number itself (IEEE Std 1003.1,
/// pthread_setschedparam, RETURN VALUE), so a host error is returned, not put in errno. glibc
/// makes the `sched_setscheduler` syscall inside libc, past the import table, so only this hook
/// sees it.
unsafe extern "C" fn pthread_setschedparam(
    thread: libc::pthread_t,
    policy: c_int,
    param: *const libc::sched_param,
) -> c_int {
    // SAFETY: `param` is the caller's `sched_param`.
    if let Some(r) =
        dispatch_host(|h| unsafe { h.pthread_setschedparam(thread, policy, param.cast()) })
    {
        return if r < 0 { -r as c_int } else { 0 };
    }
    // SAFETY: PTHREAD_SETSCHEDPARAM holds libc's pthread_setschedparam.
    unsafe {
        original::<unsafe extern "C" fn(libc::pthread_t, c_int, *const libc::sched_param) -> c_int>(
            &PTHREAD_SETSCHEDPARAM,
        )(thread, policy, param)
    }
}

/// `pthread_getschedparam`: returns the error number itself, like `pthread_setschedparam`.
unsafe extern "C" fn pthread_getschedparam(
    thread: libc::pthread_t,
    policy: *mut c_int,
    param: *mut libc::sched_param,
) -> c_int {
    // SAFETY: `policy`/`param` are the caller's.
    if let Some(r) =
        dispatch_host(|h| unsafe { h.pthread_getschedparam(thread, policy, param.cast()) })
    {
        return if r < 0 { -r as c_int } else { 0 };
    }
    // SAFETY: PTHREAD_GETSCHEDPARAM holds libc's pthread_getschedparam.
    unsafe {
        original::<unsafe extern "C" fn(libc::pthread_t, *mut c_int, *mut libc::sched_param) -> c_int>(
            &PTHREAD_GETSCHEDPARAM,
        )(thread, policy, param)
    }
}
