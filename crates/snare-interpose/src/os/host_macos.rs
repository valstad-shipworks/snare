//! macOS scheduling hooks. Unlike Linux (POSIX `sched_*` via the `syscall` symbol), macOS programs
//! set thread scheduling through `pthread_setschedparam` and the Mach `thread_policy_set`. These
//! consult the calling thread's [`Host`](crate::Host) before the OS; a `None` host declines.

use std::ffi::{c_char, c_int, c_uint, c_void};
use std::sync::atomic::AtomicUsize;

use crate::domain::dispatch_host;
use crate::hooks::{Hook, hook, original};
use crate::os::sockets::finish;

macro_rules! slot {
    ($name:ident) => {
        static $name: AtomicUsize = AtomicUsize::new(0);
    };
}

slot!(PTHREAD_SETSCHEDPARAM);
slot!(PTHREAD_GETSCHEDPARAM);
slot!(THREAD_POLICY_SET);
slot!(PTHREAD_SET_QOS_CLASS_SELF_NP);
slot!(SYSCTL);
slot!(SYSCTLNAMETOMIB);

pub(crate) fn hooks() -> Vec<Hook> {
    vec![
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
        hook!("thread_policy_set", thread_policy_set, THREAD_POLICY_SET),
        hook!(
            "pthread_set_qos_class_self_np",
            pthread_set_qos_class_self_np,
            PTHREAD_SET_QOS_CLASS_SELF_NP
        ),
        hook!("sysctl", sysctl, SYSCTL),
        hook!("sysctlnametomib", sysctlnametomib, SYSCTLNAMETOMIB),
    ]
}

type SysctlFn =
    unsafe extern "C" fn(*mut c_int, c_uint, *mut c_void, *mut usize, *mut c_void, usize) -> c_int;

unsafe extern "C" fn sysctl(
    name: *mut c_int,
    namelen: c_uint,
    oldp: *mut c_void,
    oldlenp: *mut usize,
    newp: *mut c_void,
    newlen: usize,
) -> c_int {
    // man 3 sysctl: `name` is a MIB integer array of length `namelen`; `oldp`/`oldlenp` read the
    // value (oldlenp in/out), `newp`/`newlen` write it. Scheduling info comes via CTL_KERN/CTL_HW.
    // SAFETY: `name` points to `namelen` MIB words; `oldp`/`oldlenp`/`newp` are the caller's.
    if let Some(r) = dispatch_host(|h| unsafe {
        h.sysctl(name, namelen, oldp.cast(), oldlenp, newp.cast(), newlen)
    }) {
        return finish(r) as c_int;
    }
    // SAFETY: SYSCTL holds libc's sysctl.
    unsafe { original::<SysctlFn>(&SYSCTL)(name, namelen, oldp, oldlenp, newp, newlen) }
}

unsafe extern "C" fn sysctlnametomib(
    name: *const c_char,
    mibp: *mut c_int,
    sizep: *mut usize,
) -> c_int {
    // man 3 sysctlnametomib: resolves a dotted name (e.g. "hw.ncpu") to its MIB array; `sizep` is
    // in/out (mibp capacity in, resolved length out).
    // SAFETY: `name` is a C string; `mibp`/`sizep` receive the resolved MIB.
    if let Some(r) = dispatch_host(|h| unsafe { h.sysctlnametomib(name, mibp, sizep) }) {
        return finish(r) as c_int;
    }
    // SAFETY: SYSCTLNAMETOMIB holds libc's sysctlnametomib.
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, *mut c_int, *mut usize) -> c_int>(
            &SYSCTLNAMETOMIB,
        )(name, mibp, sizep)
    }
}

unsafe extern "C" fn thread_policy_set(
    thread: u32,
    flavor: c_int,
    info: *mut u32,
    count: u32,
) -> c_int {
    // <mach/thread_policy.h> thread_policy_set: `flavor` selects the policy struct and `count`
    // is its length in natural_t words (e.g. THREAD_TIME_CONSTRAINT_POLICY ->
    // thread_time_constraint_policy_data_t {period, computation, constraint, preemptible},
    // THREAD_TIME_CONSTRAINT_POLICY_COUNT words). This is Darwin's realtime knob in place of
    // SCHED_FIFO; see Apple's "Using the RT Threads" / xnu osfmk/kern/thread_policy.c.
    // SAFETY: `info` points to `count` policy words.
    if let Some(r) =
        dispatch_host(|h| unsafe { h.thread_policy_set(thread, flavor, info.cast(), count) })
    {
        // Returns a kern_return_t: 0 = KERN_SUCCESS.
        return r as c_int;
    }
    // SAFETY: THREAD_POLICY_SET holds the Mach thread_policy_set.
    unsafe {
        original::<unsafe extern "C" fn(u32, c_int, *mut u32, u32) -> c_int>(&THREAD_POLICY_SET)(
            thread, flavor, info, count,
        )
    }
}

unsafe extern "C" fn pthread_set_qos_class_self_np(qos_class: c_int, relative_priority: c_int) -> c_int {
    // <pthread/qos.h> pthread_set_qos_class_self_np: `qos_class` is a qos_class_t
    // (QOS_CLASS_USER_INTERACTIVE/USER_INITIATED/DEFAULT/UTILITY/BACKGROUND);
    // `relative_priority` is a non-positive offset within the class (0 down to QOS_MIN_RELATIVE_PRIORITY).
    if let Some(r) = dispatch_host(|h| h.set_qos(qos_class, relative_priority)) {
        // Returns 0 on success, an errno on failure.
        return if r < 0 { -r as c_int } else { 0 };
    }
    // SAFETY: PTHREAD_SET_QOS_CLASS_SELF_NP holds libc's pthread_set_qos_class_self_np.
    unsafe {
        original::<unsafe extern "C" fn(c_int, c_int) -> c_int>(&PTHREAD_SET_QOS_CLASS_SELF_NP)(
            qos_class,
            relative_priority,
        )
    }
}

unsafe extern "C" fn pthread_setschedparam(
    thread: libc::pthread_t,
    policy: c_int,
    param: *const libc::sched_param,
) -> c_int {
    // man 3 pthread_setschedparam: `policy` is SCHED_OTHER/FIFO/RR and sched_param.sched_priority
    // lies within sched_get_priority_min(policy)..=sched_get_priority_max(policy).
    // SAFETY: `param` is the caller's sched_param.
    if let Some(r) =
        dispatch_host(|h| unsafe { h.pthread_setschedparam(thread as u64, policy, param.cast()) })
    {
        // pthread_* return the errno directly (0 on success, a positive errno on failure).
        return if r < 0 { -r as c_int } else { 0 };
    }
    // SAFETY: PTHREAD_SETSCHEDPARAM holds libc's pthread_setschedparam.
    unsafe {
        original::<unsafe extern "C" fn(libc::pthread_t, c_int, *const libc::sched_param) -> c_int>(
            &PTHREAD_SETSCHEDPARAM,
        )(thread, policy, param)
    }
}

unsafe extern "C" fn pthread_getschedparam(
    thread: libc::pthread_t,
    policy: *mut c_int,
    param: *mut libc::sched_param,
) -> c_int {
    // man 3 pthread_getschedparam: reports the thread's current policy and sched_param.
    // SAFETY: `policy`/`param` receive the current values.
    if let Some(r) = dispatch_host(|h| unsafe {
        h.pthread_getschedparam(thread as u64, policy, param.cast())
    }) {
        return if r < 0 { -r as c_int } else { 0 };
    }
    // SAFETY: PTHREAD_GETSCHEDPARAM holds libc's pthread_getschedparam.
    unsafe {
        original::<unsafe extern "C" fn(libc::pthread_t, *mut c_int, *mut libc::sched_param) -> c_int>(
            &PTHREAD_GETSCHEDPARAM,
        )(thread, policy, param)
    }
}
