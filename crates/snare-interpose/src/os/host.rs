//! Scheduling, affinity, priority and memory-locking hooks that consult the calling thread's
//! [`Host`](crate::Host) before the OS. These are the *named* libc symbols; the raw-syscall forms
//! (`syscall(SYS_sched_setscheduler, …)`, which musl-linked programs use) are caught by the
//! `syscall` hook in `unix.rs`, which also consults the host. A `None` host declines, and the call
//! reaches the real kernel unchanged.

use std::ffi::c_int;
use std::sync::atomic::AtomicUsize;

use crate::domain::dispatch_host;
use crate::hooks::{Hook, hook, original};
use crate::os::sockets::finish;

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
    ]
}

unsafe extern "C" fn gettid() -> libc::pid_t {
    // man 2 gettid: the kernel thread id (a TID), which for sched_* is the per-thread `pid`.
    if let Some(r) = dispatch_host(|h| h.gettid()) {
        return finish(r) as libc::pid_t;
    }
    // SAFETY: GETTID holds libc's gettid.
    unsafe { original::<unsafe extern "C" fn() -> libc::pid_t>(&GETTID)() }
}

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

unsafe extern "C" fn sched_getscheduler(pid: libc::pid_t) -> c_int {
    // man 2 sched_getscheduler: returns the policy (a SCHED_* constant) for the thread.
    if let Some(r) = dispatch_host(|h| unsafe { h.sched_getscheduler(pid) }) {
        return finish(r) as c_int;
    }
    // SAFETY: SCHED_GETSCHEDULER holds libc's sched_getscheduler.
    unsafe { original::<unsafe extern "C" fn(libc::pid_t) -> c_int>(&SCHED_GETSCHEDULER)(pid) }
}

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

unsafe extern "C" fn sched_setaffinity(
    pid: libc::pid_t,
    cpusetsize: usize,
    set: *const libc::cpu_set_t,
) -> c_int {
    // man 2 sched_setaffinity: cpu_set_t is a fixed-size bitmask (CPU_SETSIZE bits, built with
    // the CPU_SET(3) macros); `cpusetsize` is sizeof(cpu_set_t) in bytes.
    // SAFETY: `set` points to `cpusetsize` bytes of mask.
    if let Some(r) =
        dispatch_host(|h| unsafe { h.sched_setaffinity(pid, cpusetsize, set.cast()) })
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

unsafe extern "C" fn getpriority(which: c_int, who: libc::id_t) -> c_int {
    // man 2 getpriority: returns the nice value, which may legitimately be negative — so it cannot
    // use the `finish` "negative means errno" convention. (The kernel stores nice as 20-nice, i.e.
    // 1..=40, precisely so its own return value is never -1; libc maps it back and, per the man
    // page, a caller clears errno before the call to disambiguate a true -1 error from nice == -1.)
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

unsafe extern "C" fn mlockall(flags: c_int) -> c_int {
    // man 2 mlockall: flags MCL_CURRENT/MCL_FUTURE(/MCL_ONFAULT) lock the process's pages resident.
    if let Some(r) = dispatch_host(|h| h.mlockall(flags)) {
        return finish(r) as c_int;
    }
    // SAFETY: MLOCKALL holds libc's mlockall.
    unsafe { original::<unsafe extern "C" fn(c_int) -> c_int>(&MLOCKALL)(flags) }
}

unsafe extern "C" fn munlockall() -> c_int {
    // man 2 munlockall: undoes mlockall, unlocking all of the process's mapped pages.
    if let Some(r) = dispatch_host(|h| h.munlockall()) {
        return finish(r) as c_int;
    }
    // SAFETY: MUNLOCKALL holds libc's munlockall.
    unsafe { original::<unsafe extern "C" fn() -> c_int>(&MUNLOCKALL)() }
}
