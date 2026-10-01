//! A per-domain process/scheduler tuning backend, sibling to [`Net`](crate::Net) and
//! [`Fs`](crate::Fs). It has no file descriptors of its own: it services the scheduling, affinity,
//! priority, memory-locking and rlimit calls a real-time program makes, recording them against a
//! simulated host and gating the setters on configured capabilities and rlimits — it never touches
//! the real scheduler. A `None` host leaves those calls to observe-and-forward, as today.
//!
//! On Linux several of these arrive only through the `syscall` symbol (glibc has no wrapper for
//! `sched_setscheduler` on every version); [`Host::syscall`] is the backstop the `syscall` hook
//! consults, in addition to the named wrapper symbols.

use core::ffi::{c_char, c_int};

pub use crate::net::NetResult as HostResult;

type Pid = i32; // libc::pid_t
type Id = u32; // libc::id_t

#[allow(unused_variables, clippy::missing_safety_doc)]
pub trait Host: Send + Sync + 'static {
    /// Whether the simulated host grants `cap` (e.g. `CAP_SYS_NICE`). Not a libc symbol — the
    /// setters consult it to decide between success and `EPERM`. `CAP_*` values and their effects
    /// are in `capabilities(7)` (`<linux/capability.h>`).
    fn has_cap(&self, cap: c_int) -> bool {
        false
    }

    /// Models `sched_setscheduler(2)`; `policy` is `SCHED_OTHER`/`SCHED_FIFO`/`SCHED_RR`/… and
    /// `param` a `struct sched_param` carrying `sched_priority` (`<sched.h>`).
    unsafe fn sched_setscheduler(
        &self,
        pid: Pid,
        policy: c_int,
        param: *const u8,
    ) -> Option<HostResult> {
        None
    }
    /// Models `sched_getscheduler(2)` — the current policy for `pid`.
    unsafe fn sched_getscheduler(&self, pid: Pid) -> Option<HostResult> {
        None
    }
    /// Models `sched_setparam(2)`; `param` is a `struct sched_param`.
    unsafe fn sched_setparam(&self, pid: Pid, param: *const u8) -> Option<HostResult> {
        None
    }
    /// Models `sched_getparam(2)`.
    unsafe fn sched_getparam(&self, pid: Pid, param: *mut u8) -> Option<HostResult> {
        None
    }
    /// Models `sched_setaffinity(2)`; `set` is a `cpu_set_t` of `len` bytes (`CPU_SET(3)`,
    /// `<sched.h>`).
    unsafe fn sched_setaffinity(&self, pid: Pid, len: usize, set: *const u8) -> Option<HostResult> {
        None
    }
    /// Models `sched_getaffinity(2)`.
    unsafe fn sched_getaffinity(&self, pid: Pid, len: usize, set: *mut u8) -> Option<HostResult> {
        None
    }
    /// Models `sched_get_priority_max(2)` — the top `sched_priority` valid for `policy`.
    fn sched_get_priority_max(&self, policy: c_int) -> Option<HostResult> {
        None
    }
    /// Models `sched_get_priority_min(2)`.
    fn sched_get_priority_min(&self, policy: c_int) -> Option<HostResult> {
        None
    }
    /// Models `setpriority(2)`; `which` is `PRIO_PROCESS`/`PRIO_PGRP`/`PRIO_USER` and `prio` the
    /// nice value in `[-20, 19]` (`<sys/resource.h>`).
    unsafe fn setpriority(&self, which: c_int, who: Id, prio: c_int) -> Option<HostResult> {
        None
    }
    /// Models `getpriority(2)`. The nice value can be negative, so it is returned directly, never
    /// via the `-errno` convention (`getpriority(2)` BUGS notes the same ambiguity in C).
    unsafe fn getpriority(&self, which: c_int, who: Id) -> Option<HostResult> {
        None
    }
    /// Models `setrlimit(2)`; `resource` is `RLIMIT_*` and `rlim` a `struct rlimit`
    /// (`rlim_cur`/`rlim_max`, `<sys/resource.h>`).
    unsafe fn setrlimit(&self, resource: c_int, rlim: *const u8) -> Option<HostResult> {
        None
    }
    /// Models `getrlimit(2)`.
    unsafe fn getrlimit(&self, resource: c_int, rlim: *mut u8) -> Option<HostResult> {
        None
    }
    /// Models `mlockall(2)`; `flags` are `MCL_CURRENT`/`MCL_FUTURE`/`MCL_ONFAULT` (`<sys/mman.h>`).
    fn mlockall(&self, flags: c_int) -> Option<HostResult> {
        None
    }
    /// Models `munlockall(2)`.
    fn munlockall(&self) -> Option<HostResult> {
        None
    }

    /// The Linux `syscall`-symbol backstop for numbers with no (or an inlined) libc wrapper, such
    /// as `SYS_sched_setscheduler`. Returns `Some` if this host handled the numbered call.
    ///
    /// Models `syscall(2)`; `number` is a `SYS_*`/`__NR_*` constant (`<sys/syscall.h>`,
    /// `<asm/unistd.h>`) and the ABI passes up to six register arguments.
    unsafe fn syscall(&self, number: i64, args: [i64; 6]) -> Option<HostResult> {
        None
    }

    /// The caller's simulated kernel thread id. Backs Linux `gettid` and macOS `pthread_threadid_np`,
    /// and is the `pid` argument every scheduling/affinity/priority call on "this thread" carries.
    ///
    /// Models `gettid(2)` (Linux) and `pthread_threadid_np(3)` (macOS).
    fn gettid(&self) -> Option<HostResult> {
        None
    }

    /// macOS `pthread_getschedparam(thread, *policy, *param)`.
    ///
    /// Models `pthread_getschedparam(3)`; `param` is a `struct sched_param`.
    ///
    /// # Safety
    /// `policy`/`param` receive the current policy and `sched_param`.
    unsafe fn pthread_getschedparam(
        &self,
        thread: u64,
        policy: *mut c_int,
        param: *mut u8,
    ) -> Option<HostResult> {
        None
    }

    /// macOS `pthread_setschedparam(thread, policy, *param)`.
    ///
    /// Models `pthread_setschedparam(3)`.
    ///
    /// # Safety
    /// `param` points to a `sched_param`.
    unsafe fn pthread_setschedparam(
        &self,
        thread: u64,
        policy: c_int,
        param: *const u8,
    ) -> Option<HostResult> {
        None
    }

    /// macOS `thread_policy_set(thread, flavor, info, count)` — e.g. `THREAD_TIME_CONSTRAINT_POLICY`.
    ///
    /// Mach thread-policy call; `flavor` and the `info` struct layout are in
    /// `<mach/thread_policy.h>`, `count` given in `natural_t` words.
    ///
    /// # Safety
    /// `info` points to `count` words of policy data.
    unsafe fn thread_policy_set(
        &self,
        thread: u32,
        flavor: c_int,
        info: *const u8,
        count: u32,
    ) -> Option<HostResult> {
        None
    }

    /// macOS `pthread_set_qos_class_self_np(qos_class, relative_priority)`.
    ///
    /// `qos_class` is a `qos_class_t` (`QOS_CLASS_USER_INTERACTIVE`, …) from `<pthread/qos.h>`.
    fn set_qos(&self, qos_class: c_int, relative_priority: c_int) -> Option<HostResult> {
        None
    }

    /// macOS `sysctl(name, namelen, oldp, oldlenp, newp, newlen)` for host facts (NIC stats,
    /// CPU topology, `sys_check`).
    ///
    /// Models `sysctl(3)`; `name` is a MIB array of `CTL_*`/`HW_*`/`KERN_*` integers
    /// (`<sys/sysctl.h>`).
    ///
    /// # Safety
    /// `name` points to `namelen` MIB words; `oldp`/`oldlenp`/`newp` are the caller's buffers.
    unsafe fn sysctl(
        &self,
        name: *const c_int,
        namelen: u32,
        oldp: *mut u8,
        oldlenp: *mut usize,
        newp: *const u8,
        newlen: usize,
    ) -> Option<HostResult> {
        None
    }

    /// macOS `sysctlnametomib(name, mib, sizep)`.
    ///
    /// Models `sysctlnametomib(3)` — resolve a dotted name (e.g. `"hw.ncpu"`) to its MIB.
    ///
    /// # Safety
    /// `mib`/`sizep` receive the resolved MIB and its length.
    unsafe fn sysctlnametomib(
        &self,
        name: *const c_char,
        mib: *mut c_int,
        sizep: *mut usize,
    ) -> Option<HostResult> {
        None
    }

    // --- Windows scheduling (the `SetThreadPriority` family, not POSIX `sched_*`). Handles are
    // passed as `u64`; priorities and classes keep their Win32 encodings. `Ok(1)` is a successful
    // `BOOL`, `Err(e)` fails with `SetLastError(e)`. ---

    /// Windows `SetThreadPriority(thread, priority)` — returns a `BOOL`.
    ///
    /// MSDN `SetThreadPriority`; `priority` is `THREAD_PRIORITY_*` (`-15..=15`,
    /// `THREAD_PRIORITY_TIME_CRITICAL`/`_IDLE` for the realtime extremes).
    fn set_thread_priority(&self, thread: u64, priority: c_int) -> Option<HostResult> {
        None
    }
    /// Windows `GetThreadPriority(thread)` — returns the priority, which may be negative.
    ///
    /// MSDN `GetThreadPriority`; fails with `THREAD_PRIORITY_ERROR_RETURN`.
    fn get_thread_priority(&self, thread: u64) -> Option<HostResult> {
        None
    }
    /// Windows `SetThreadAffinityMask(thread, mask)` — returns the previous mask in `Ok`, or
    /// `Ok(0)` for failure (as Win32 does). It must not use `Err`, since a valid mask can set bit
    /// 63 and the hook preserves all 64 bits rather than treating a high bit as `-errno`.
    ///
    /// MSDN `SetThreadAffinityMask`; each bit is a logical processor within the caller's group.
    fn set_thread_affinity_mask(&self, thread: u64, mask: u64) -> Option<HostResult> {
        None
    }
    /// Windows `SetPriorityClass(process, class)` — returns a `BOOL`.
    ///
    /// MSDN `SetPriorityClass`; `class` is `REALTIME_PRIORITY_CLASS`/`HIGH_PRIORITY_CLASS`/…
    fn set_priority_class(&self, process: u64, class: u32) -> Option<HostResult> {
        None
    }
    /// Windows `GetPriorityClass(process)` — returns the class, `0` on failure.
    ///
    /// MSDN `GetPriorityClass`.
    fn get_priority_class(&self, process: u64) -> Option<HostResult> {
        None
    }
    /// Windows `timeBeginPeriod(period)` / `timeEndPeriod(period)` — `TIMERR_NOERROR` (0) on success.
    ///
    /// MSDN `timeBeginPeriod`/`timeEndPeriod` (winmm); `period` is the requested minimum timer
    /// resolution in milliseconds.
    fn time_period(&self, begin: bool, period: u32) -> Option<HostResult> {
        None
    }
}
