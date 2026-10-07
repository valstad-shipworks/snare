//! A per-domain process/scheduler tuning backend, sibling to [`Net`](crate::Net) and
//! [`Fs`](crate::Fs). It has no file descriptors of its own: it services the scheduling, affinity,
//! priority, memory-locking and rlimit calls a real-time program makes, recording them against a
//! simulated host and gating the setters on configured capabilities and rlimits — it never touches
//! the real scheduler. Without a host those calls reach the real OS.
//!
//! On Linux several of these arrive only through the `syscall` symbol: musl's
//! `sched_setscheduler`, `sched_setparam`, `sched_getscheduler` and `sched_getparam` wrappers
//! deliberately fail with `ENOSYS` (musl `src/sched/sched_setscheduler.c` and its siblings), so
//! musl-linked programs issue the syscall directly.
//! [`Host::syscall`] is the backstop the `syscall` hook consults, in addition to the named
//! wrapper symbols.
//!
//! Every method defaults to `None` ("not modelled, let the real OS answer"), so a host overrides
//! only what it simulates. A method returns [`HostResult`]: `Ok(n)` is the call's success value
//! and `Err(errno)` its failure, which each hook converts to the function's own C convention
//! (`-1` and errno, a returned errno, a `BOOL` with `SetLastError`). Methods are called on the
//! calling thread, under passthrough, with no snare lock held, from whichever thread of the
//! domain made the call, hence `Send + Sync`.

use core::ffi::{c_char, c_int};

pub use crate::net::NetResult as HostResult;

/// `pid_t`; on Linux a thread id is also a valid `pid` for the `sched_*` calls, and 0 means the
/// caller (man 2 sched_setscheduler).
type Pid = i32; // libc::pid_t
/// `id_t`, the `who` of `setpriority`/`getpriority`, interpreted per `which` (man 2 setpriority).
type Id = u32; // libc::id_t

/// A simulated host's scheduling and process-limit state, installed per domain.
///
/// The pointer arguments are the caller's, passed through untranslated and typed as bytes so
/// the trait does not depend on `libc`'s per-OS struct definitions. For the `unsafe` methods
/// they are valid for the C function's documented sizes, as the C caller guaranteed.
#[allow(unused_variables, clippy::missing_safety_doc)]
pub trait Host: Send + Sync + 'static {
    fn thread_inherit(&self, lineage: u64) {}
    fn thread_adopt(&self, lineage: u64) {}
    fn thread_cancel(&self, lineage: u64) {}
    unsafe fn clock_gettime(&self, id: i32, buf: *mut u8) -> Option<HostResult> {
        None
    }
    unsafe fn clock_getres(&self, id: i32, buf: *mut u8) -> Option<HostResult> {
        None
    }

    /// Whether the simulated host grants `cap` (e.g. `CAP_SYS_NICE`). Not a libc symbol — the
    /// setters consult it to decide between success and `EPERM`. `CAP_*` values and their effects
    /// are in `capabilities(7)` (`<linux/capability.h>`). No hook calls it; it is for the host's
    /// own setters and its [`syscall`](Host::syscall) backstop.
    fn has_cap(&self, cap: c_int) -> bool {
        false
    }

    /// The effective and real user id the code under test runs as. Models `geteuid(2)` and
    /// `getuid(2)`. Consulted by the Unix `geteuid` hook; `None` reports the real id.
    fn geteuid(&self) -> Option<u32> {
        None
    }
    /// The real user id; see [`geteuid`](Host::geteuid). Consulted by the Unix `getuid` hook.
    fn getuid(&self) -> Option<u32> {
        None
    }

    /// Models `sysconf(3)` for `_SC_NPROCESSORS_CONF` and `_SC_NPROCESSORS_ONLN`, the processors
    /// configured and online; the Unix `sysconf` hook offers no other name.
    fn sysconf(&self, name: c_int) -> Option<HostResult> {
        None
    }

    /// Models `uname(2)`; `buf` is a `struct utsname` (`<sys/utsname.h>`). Consulted by the Unix
    /// `uname` hook and, on Linux, reachable as `SYS_uname` through [`syscall`](Host::syscall).
    unsafe fn uname(&self, buf: *mut u8) -> Option<HostResult> {
        None
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
    /// Models `sched_get_priority_max(2)` — the top `sched_priority` valid for `policy`. No hook in
    /// this crate calls it; a host may route `SYS_sched_get_priority_max` to it from its
    /// [`syscall`](Host::syscall) backstop.
    fn sched_get_priority_max(&self, policy: c_int) -> Option<HostResult> {
        None
    }
    /// Models `sched_get_priority_min(2)`; not called by any hook, like
    /// [`sched_get_priority_max`](Host::sched_get_priority_max).
    fn sched_get_priority_min(&self, policy: c_int) -> Option<HostResult> {
        None
    }
    /// Models `setpriority(2)`; `which` is `PRIO_PROCESS`/`PRIO_PGRP`/`PRIO_USER` and `prio` the
    /// nice value in `[-20, 19]` (`<sys/resource.h>`).
    unsafe fn setpriority(&self, which: c_int, who: Id, prio: c_int) -> Option<HostResult> {
        None
    }
    /// Models `getpriority(2)`. The nice value can be negative, so it is returned directly, never
    /// via the `-errno` convention (`getpriority(2)` RETURN VALUE notes the same ambiguity in C).
    unsafe fn getpriority(&self, which: c_int, who: Id) -> Option<HostResult> {
        None
    }
    /// Models `setrlimit(2)`; `resource` is `RLIMIT_*` and `rlim` a `struct rlimit`
    /// (`rlim_cur`/`rlim_max`, `<sys/resource.h>`). Backs the `setrlimit` (and glibc
    /// `setrlimit64`) hook on Linux and macOS.
    unsafe fn setrlimit(&self, resource: c_int, rlim: *const u8) -> Option<HostResult> {
        None
    }
    /// Models `getrlimit(2)`, writing a `struct rlimit` to `rlim`. Backs the `getrlimit` (and
    /// glibc `getrlimit64`) hook on Linux and macOS.
    unsafe fn getrlimit(&self, resource: c_int, rlim: *mut u8) -> Option<HostResult> {
        None
    }
    /// Models Linux `prlimit(2)`: for process `pid` (0 is the caller), report the old limit into
    /// `old` and install `new`, either of which may be NULL. Backs the `prlimit`/`prlimit64`
    /// hooks; a host may route `SYS_prlimit64` to it from [`syscall`](Host::syscall).
    unsafe fn prlimit(
        &self,
        pid: Pid,
        resource: c_int,
        new: *const u8,
        old: *mut u8,
    ) -> Option<HostResult> {
        None
    }
    /// Models `mlock(2)` of `len` bytes at `addr` (Linux and macOS).
    fn mlock(&self, addr: u64, len: u64) -> Option<HostResult> {
        None
    }
    /// Models `munlock(2)` of `len` bytes at `addr` (Linux and macOS).
    fn munlock(&self, addr: u64, len: u64) -> Option<HostResult> {
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

    /// The caller's simulated kernel thread id: the `pid` argument every scheduling, affinity or
    /// priority call on "this thread" carries.
    ///
    /// Models `gettid(2)` and backs the Linux `gettid` hook. macOS `pthread_threadid_np` is not
    /// hooked.
    fn gettid(&self) -> Option<HostResult> {
        None
    }

    /// `pthread_getschedparam(thread, *policy, *param)` (macOS; on Linux glibc issues the
    /// syscall internally, so this hook is the only way to see it).
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

    /// `pthread_setschedparam(thread, policy, *param)` (macOS and Linux, as above).
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

    /// macOS `sysctlbyname(name, oldp, oldlenp, newp, newlen)`: the same read or write as
    /// [`sysctl`](Self::sysctl), naming the node by its dotted name (man 3 sysctlbyname). libc
    /// resolves it with its own `__sysctlbyname` system call rather than through `sysctl`, so it
    /// needs a hook of its own.
    ///
    /// # Safety
    /// `name` is a C string; `oldp`/`oldlenp`/`newp` are the caller's buffers.
    unsafe fn sysctlbyname(
        &self,
        name: *const c_char,
        oldp: *mut u8,
        oldlenp: *mut usize,
        newp: *const u8,
        newlen: usize,
    ) -> Option<HostResult> {
        None
    }

    /// Windows `SetThreadPriority(thread, priority)` — returns a `BOOL`.
    ///
    /// The Windows methods model the `SetThreadPriority` family, not POSIX `sched_*`. Handles are
    /// passed as `u64`; priorities and classes keep their Win32 encodings. For the `BOOL`
    /// functions `Ok(1)` is success and `Err(e)` fails with `SetLastError(e)`.
    ///
    /// `priority` is `THREAD_PRIORITY_*`: `-2..=2`, `THREAD_PRIORITY_IDLE` (-15) and
    /// `THREAD_PRIORITY_TIME_CRITICAL` (15), plus `-7..=-3` and `3..=6` in a
    /// `REALTIME_PRIORITY_CLASS` process
    /// ([Microsoft Learn: SetThreadPriority](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadpriority)).
    fn set_thread_priority(&self, thread: u64, priority: c_int) -> Option<HostResult> {
        None
    }
    /// Windows `GetThreadPriority(thread)` — returns the priority, which may be negative.
    ///
    /// Failure is the value `THREAD_PRIORITY_ERROR_RETURN` (`0x7FFFFFFF` in `windows-sys`), not an
    /// error code, so a host reports it as `Ok(THREAD_PRIORITY_ERROR_RETURN)`; the hook returns
    /// `Ok`'s value as-is
    /// ([Microsoft Learn: GetThreadPriority](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadpriority)).
    fn get_thread_priority(&self, thread: u64) -> Option<HostResult> {
        None
    }
    /// Windows `SetThreadAffinityMask(thread, mask)` — returns the previous mask in `Ok`, or
    /// `Ok(0)` for failure (as Win32 does). It must not use `Err`, since a valid mask can set bit
    /// 63 and the hook preserves all 64 bits rather than treating a high bit as `-errno`.
    ///
    /// Each bit is a logical processor within the thread's processor group
    /// ([Microsoft Learn: SetThreadAffinityMask](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadaffinitymask)).
    fn set_thread_affinity_mask(&self, thread: u64, mask: u64) -> Option<HostResult> {
        None
    }
    /// Windows `SetPriorityClass(process, class)` — returns a `BOOL`.
    ///
    /// `class` is `REALTIME_PRIORITY_CLASS`/`HIGH_PRIORITY_CLASS`/…
    /// ([Microsoft Learn: SetPriorityClass](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setpriorityclass)).
    fn set_priority_class(&self, process: u64, class: u32) -> Option<HostResult> {
        None
    }
    /// Windows `GetPriorityClass(process)` — returns the class, `0` on failure.
    ///
    /// `Err(e)` returns 0 with `SetLastError(e)`
    /// ([Microsoft Learn: GetPriorityClass](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getpriorityclass)).
    fn get_priority_class(&self, process: u64) -> Option<HostResult> {
        None
    }
    /// Windows `timeBeginPeriod(period)` / `timeEndPeriod(period)` — `TIMERR_NOERROR` (0) on success.
    ///
    /// `period` is the requested minimum timer resolution in milliseconds
    /// ([Microsoft Learn: timeBeginPeriod](https://learn.microsoft.com/en-us/windows/win32/api/timeapi/nf-timeapi-timebeginperiod)).
    /// The result is an `MMRESULT`, so a host reports a refusal as `Ok(TIMERR_NOCANDO)` (97 in
    /// `windows-sys`; the name is from the same Learn page); the hook reports an `Err` as
    /// `TIMERR_NOCANDO` too.
    fn time_period(&self, begin: bool, period: u32) -> Option<HostResult> {
        None
    }

    /// Windows `SetProcessWorkingSetSizeEx(process, min, max, flags)` — returns a `BOOL`; `Err(e)`
    /// fails with `SetLastError(e)`.
    ///
    /// `min`/`max` are byte counts and `flags` the `QUOTA_LIMITS_HARDWS_*` bits
    /// ([Microsoft Learn: SetProcessWorkingSetSizeEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessworkingsetsizeex)).
    fn set_working_set(
        &self,
        process: u64,
        min: usize,
        max: usize,
        flags: u32,
    ) -> Option<HostResult> {
        None
    }

    /// Windows `GetProcessWorkingSetSizeEx(process, *min, *max, *flags)` — returns a `BOOL`.
    ///
    /// ([Microsoft Learn: GetProcessWorkingSetSizeEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-getprocessworkingsetsizeex)).
    ///
    /// # Safety
    /// `min`, `max` and `flags` are writable.
    unsafe fn get_working_set(
        &self,
        process: u64,
        min: *mut usize,
        max: *mut usize,
        flags: *mut u32,
    ) -> Option<HostResult> {
        None
    }

    /// avrt `AvSetMmThreadCharacteristicsW(task, task_index)`: registers the calling thread with
    /// the MMCSS task named `task` (UTF-16, without its terminator). `Ok` is the task handle the
    /// hook returns; `Err(e)` returns NULL with `SetLastError(e)`
    /// ([Microsoft Learn: AvSetMmThreadCharacteristicsW](https://learn.microsoft.com/en-us/windows/win32/api/avrt/nf-avrt-avsetmmthreadcharacteristicsw)).
    ///
    /// # Safety
    /// `task_index` is null or a readable and writable `DWORD`.
    unsafe fn av_set_mm_thread_characteristics(
        &self,
        task: &[u16],
        task_index: *mut u32,
    ) -> Option<HostResult> {
        None
    }
    /// avrt `AvSetMmThreadPriority(task, priority)`, an `AVRT_PRIORITY`; returns a `BOOL`
    /// ([Microsoft Learn: AvSetMmThreadPriority](https://learn.microsoft.com/en-us/windows/win32/api/avrt/nf-avrt-avsetmmthreadpriority)).
    fn av_set_mm_thread_priority(&self, task: u64, priority: c_int) -> Option<HostResult> {
        None
    }
    /// avrt `AvRevertMmThreadCharacteristics(task)`; returns a `BOOL`
    /// ([Microsoft Learn: AvRevertMmThreadCharacteristics](https://learn.microsoft.com/en-us/windows/win32/api/avrt/nf-avrt-avrevertmmthreadcharacteristics)).
    fn av_revert_mm_thread_characteristics(&self, task: u64) -> Option<HostResult> {
        None
    }

    /// Windows `SetProcessInformation(process, class, info, size)`, a `PROCESS_INFORMATION_CLASS`;
    /// returns a `BOOL`. A host declines the classes it does not model
    /// ([Microsoft Learn: SetProcessInformation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessinformation)).
    ///
    /// # Safety
    /// `info` is valid for `size` bytes.
    unsafe fn set_process_information(
        &self,
        process: u64,
        class: c_int,
        info: *const u8,
        size: u32,
    ) -> Option<HostResult> {
        None
    }
    /// Windows `GetProcessInformation(process, class, info, size)`; returns a `BOOL`.
    ///
    /// # Safety
    /// `info` is valid for `size` bytes.
    unsafe fn get_process_information(
        &self,
        process: u64,
        class: c_int,
        info: *mut u8,
        size: u32,
    ) -> Option<HostResult> {
        None
    }
    /// Windows `SetThreadInformation(thread, class, info, size)`, a `THREAD_INFORMATION_CLASS`;
    /// returns a `BOOL`. A host declines the classes it does not model
    /// ([Microsoft Learn: SetThreadInformation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadinformation)).
    ///
    /// # Safety
    /// `info` is valid for `size` bytes.
    unsafe fn set_thread_information(
        &self,
        thread: u64,
        class: c_int,
        info: *const u8,
        size: u32,
    ) -> Option<HostResult> {
        None
    }
    /// Windows `GetThreadInformation(thread, class, info, size)`; returns a `BOOL`.
    ///
    /// # Safety
    /// `info` is valid for `size` bytes.
    unsafe fn get_thread_information(
        &self,
        thread: u64,
        class: c_int,
        info: *mut u8,
        size: u32,
    ) -> Option<HostResult> {
        None
    }

    /// Windows `GetSystemCpuSetInformation(info, len, returned, process, flags)`: the
    /// `SYSTEM_CPU_SET_INFORMATION` records of the machine's CPU sets; returns a `BOOL`
    /// ([Microsoft Learn: GetSystemCpuSetInformation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getsystemcpusetinformation)).
    ///
    /// # Safety
    /// `info` is null or valid for `len` bytes; `returned` is null or writable.
    unsafe fn system_cpu_set_information(
        &self,
        info: *mut u8,
        len: u32,
        returned: *mut u32,
        process: u64,
        flags: u32,
    ) -> Option<HostResult> {
        None
    }
    /// Windows `SetProcessDefaultCpuSets(process, ids, count)` (`thread` false) or
    /// `SetThreadSelectedCpuSets(thread, ids, count)` (`thread` true); returns a `BOOL`
    /// ([Microsoft Learn: SetProcessDefaultCpuSets](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessdefaultcpusets)).
    ///
    /// # Safety
    /// `ids` is null or holds `count` ids.
    unsafe fn set_cpu_sets(
        &self,
        thread: bool,
        handle: u64,
        ids: *const u32,
        count: u32,
    ) -> Option<HostResult> {
        None
    }
    /// Windows `GetProcessDefaultCpuSets` (`thread` false) or `GetThreadSelectedCpuSets`
    /// (`thread` true) `(handle, ids, count, required)`; returns a `BOOL`
    /// ([Microsoft Learn: GetProcessDefaultCpuSets](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessdefaultcpusets)).
    ///
    /// # Safety
    /// `ids` is null or has room for `count` ids; `required` is writable.
    unsafe fn get_cpu_sets(
        &self,
        thread: bool,
        handle: u64,
        ids: *mut u32,
        count: u32,
        required: *mut u32,
    ) -> Option<HostResult> {
        None
    }

    /// A device-installation or registry call on a handle, device instance or device class the
    /// host may own (see [`DevCall`] for each call's return convention). `None` passes the call
    /// to the real `setupapi`, `cfgmgr32` or `advapi32` export.
    ///
    /// # Safety
    /// The pointers in `call` are the caller's, valid as the C function documents them.
    #[cfg(windows)]
    unsafe fn device(&self, call: DevCall<'_>) -> Option<HostResult> {
        None
    }
}

/// The SetupAPI, Configuration Manager and registry calls a program makes to find a network
/// adapter's device node, change its advanced properties in the registry and restart it, offered
/// to [`Host::device`]. Handles travel as `u64` and pointers as bytes, so the trait does not
/// depend on `windows-sys`'s per-feature types; string arguments are UTF-16 without their
/// terminator, `None` for a null pointer.
///
/// Return conventions: the `SetupDi*` calls return `Ok(value)` (a handle or `TRUE`) or `Err(code)`
/// for the hook to put in the thread's last error and return `FALSE` / `INVALID_HANDLE_VALUE`, as
/// SetupAPI does
/// ([Microsoft Learn: SetupDiGetClassDevsW](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetclassdevsw));
/// the `Reg*` calls return `Ok(status)`, the `LSTATUS` the function itself returns
/// ([Microsoft Learn: RegQueryValueExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw));
/// the `CM_*` calls return `Ok(configret)`, the `CONFIGRET` code
/// ([Microsoft Learn: CM_Disable_DevNode](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_disable_devnode)).
#[cfg(windows)]
pub enum DevCall<'a> {
    /// `SetupDiGetClassDevsW(class, enumerator, parent, flags)`; `class` is the `GUID`'s 16 bytes.
    GetClassDevs {
        class: Option<&'a [u8; 16]>,
        enumerator: Option<&'a [u16]>,
        flags: u32,
    },
    /// `SetupDiEnumDeviceInfo(set, index, data)`; `data` is an `SP_DEVINFO_DATA`.
    EnumDeviceInfo { set: u64, index: u32, data: *mut u8 },
    /// `SetupDiDestroyDeviceInfoList(set)`.
    DestroyDeviceInfoList { set: u64 },
    /// `SetupDiOpenDevRegKey(set, data, scope, profile, key_type, access)`; `data` is an
    /// `SP_DEVINFO_DATA`.
    OpenDevRegKey {
        set: u64,
        data: *const u8,
        scope: u32,
        profile: u32,
        key_type: u32,
        access: u32,
    },
    /// `CM_Disable_DevNode(devinst, flags)`.
    DisableDevNode { devinst: u32, flags: u32 },
    /// `CM_Enable_DevNode(devinst, flags)`.
    EnableDevNode { devinst: u32, flags: u32 },
    /// `RegOpenKeyExW(key, subkey, options, access, result)`.
    OpenKey {
        key: u64,
        subkey: Option<&'a [u16]>,
        access: u32,
        result: *mut u64,
    },
    /// `RegCreateKeyExW(key, subkey, 0, class, options, access, security, result, disposition)`;
    /// `disposition` may be null.
    CreateKey {
        key: u64,
        subkey: Option<&'a [u16]>,
        access: u32,
        result: *mut u64,
        disposition: *mut u32,
    },
    /// `RegQueryValueExW(key, name, NULL, ty, data, len)`; `ty`, `data` and `len` may be null.
    QueryValue {
        key: u64,
        name: Option<&'a [u16]>,
        ty: *mut u32,
        data: *mut u8,
        len: *mut u32,
    },
    /// `RegSetValueExW(key, name, 0, ty, data, len)`.
    SetValue {
        key: u64,
        name: Option<&'a [u16]>,
        ty: u32,
        data: *const u8,
        len: u32,
    },
    /// `RegDeleteValueW(key, name)`.
    DeleteValue { key: u64, name: Option<&'a [u16]> },
    /// `RegCloseKey(key)`.
    CloseKey { key: u64 },
}
