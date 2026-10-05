//! Process resource limits and the privilege rules of the calls they gate: `getrlimit`,
//! `setrlimit` and `prlimit` on the limits a sim models ([`Privileges::rtprio_limit`],
//! [`Privileges::nice_limit`], [`Privileges::memlock_limit`]), the `RLIMIT_RTPRIO`/`RLIMIT_NICE`
//! allowance of `sched_setscheduler` and `setpriority`, and the `RLIMIT_MEMLOCK` accounting of
//! `mlock`/`mlockall`. Each rule follows the build host's kernel, cited where it is applied.
//!
//! [`SimHost`](crate::SimHost) applies these to its own scheduling state. A plain sim has no
//! scheduling state of its own, so [`ProcHost`] gates the same calls on the sim's privileges and
//! hands an allowed one to the real kernel (which may still refuse it); its limits, though, are
//! wholly the sim's, and `setrlimit` never reaches the real process.
//!
//! Locking: the privileges and the [`Wired`] page table each sit behind their own mutex in
//! [`SysConfig`]; the wired table is taken with no other snare lock held and the privileges are
//! only copied out under theirs, so neither nests inside the other.

use std::ffi::c_int;
use std::io;

use snare_interpose::{Host, NetResult as HostResult};

use crate::limits::{Privileges, Rlimit, SysConfig};

/// `RLIMIT_MEMLOCK` on the build host (<sys/resource.h>).
const RLIMIT_MEMLOCK: c_int = libc::RLIMIT_MEMLOCK as c_int;
/// `RLIMIT_RTPRIO` (include/uapi/asm-generic/resource.h). Linux only.
#[cfg(target_os = "linux")]
const RLIMIT_RTPRIO: c_int = libc::RLIMIT_RTPRIO as c_int;
/// `RLIMIT_NICE` (include/uapi/asm-generic/resource.h). Linux only.
#[cfg(target_os = "linux")]
const RLIMIT_NICE: c_int = libc::RLIMIT_NICE as c_int;

/// A handled call returning `n`.
fn ok(n: i64) -> Option<HostResult> {
    Some(HostResult::Ok(n))
}

/// A handled call failing with `errno`.
fn err(errno: c_int) -> Option<HostResult> {
    Some(HostResult::Err(errno))
}

/// The host's `RLIM_INFINITY` as snare's [`Rlimit::INFINITY`]: macOS uses `(1 << 63) - 1` and
/// treats anything above it as infinite too (xnu bsd/kern/kern_resource.c `dosetrlimit` clamps
/// to it).
fn from_os(v: libc::rlim_t) -> u64 {
    #[cfg(target_os = "macos")]
    let infinite = v >= libc::RLIM_INFINITY;
    #[cfg(not(target_os = "macos"))]
    let infinite = v == libc::RLIM_INFINITY;
    if infinite { Rlimit::INFINITY } else { v }
}

/// [`Rlimit::INFINITY`] as the host's `RLIM_INFINITY`.
fn to_os(v: u64) -> libc::rlim_t {
    if v == Rlimit::INFINITY {
        libc::RLIM_INFINITY
    } else {
        v
    }
}

/// The real process's limit for `resource`, read with `getrlimit(2)`. Call under
/// [`snare_interpose::real`].
pub(crate) fn real_rlimit(resource: c_int) -> io::Result<Rlimit> {
    let mut r = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    #[cfg(target_os = "linux")]
    let rc = unsafe { libc::getrlimit(resource as libc::__rlimit_resource_t, &mut r) };
    #[cfg(not(target_os = "linux"))]
    let rc = unsafe { libc::getrlimit(resource, &mut r) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Rlimit {
        cur: from_os(r.rlim_cur),
        max: from_os(r.rlim_max),
    })
}

/// The [`Privileges`] field that holds `resource`, or `None` for a resource the sim leaves to
/// the real process.
fn slot(p: &mut Privileges, resource: c_int) -> Option<&mut Rlimit> {
    match resource {
        RLIMIT_MEMLOCK => Some(&mut p.memlock_limit),
        #[cfg(target_os = "linux")]
        RLIMIT_RTPRIO => Some(&mut p.rtprio_limit),
        #[cfg(target_os = "linux")]
        RLIMIT_NICE => Some(&mut p.nice_limit),
        _ => None,
    }
}

/// Whether the sim models `resource`.
fn modelled(resource: c_int) -> bool {
    slot(&mut Privileges::none(), resource).is_some()
}

/// Reads a `struct rlimit` (two `rlim_t`, <sys/resource.h>).
///
/// # Safety
/// `ptr` points to a `struct rlimit`.
unsafe fn read_rlimit(ptr: *const u8) -> Rlimit {
    let r = unsafe { (ptr as *const libc::rlimit).read_unaligned() };
    Rlimit {
        cur: from_os(r.rlim_cur),
        max: from_os(r.rlim_max),
    }
}

/// Writes a `struct rlimit`.
///
/// # Safety
/// `ptr` points to a writable `struct rlimit`.
unsafe fn write_rlimit(ptr: *mut u8, r: Rlimit) {
    let out = libc::rlimit {
        rlim_cur: to_os(r.cur),
        rlim_max: to_os(r.max),
    };
    unsafe { (ptr as *mut libc::rlimit).write_unaligned(out) };
}

/// Replaces `resource`'s limit, or says why not: `EINVAL` for a soft limit above the hard one,
/// `EPERM` for raising the hard limit without `CAP_SYS_RESOURCE` (Linux kernel/sys.c
/// `do_prlimit`) or, on macOS, for raising either above the current hard limit without root
/// (xnu bsd/kern/kern_resource.c `dosetrlimit`, which calls `suser`). Measured on macOS 26 by
/// tests/rlimits.rs `memlock_os_truth`.
fn check_set(p: &Privileges, old: Rlimit, new: Rlimit) -> Result<(), c_int> {
    if new.cur > new.max {
        return Err(libc::EINVAL);
    }
    let raises = if cfg!(target_os = "macos") {
        (new.cur > old.max || new.max > old.max) && !p.root
    } else {
        new.max > old.max && !p.sys_resource
    };
    if raises { Err(libc::EPERM) } else { Ok(()) }
}

/// `prlimit(2)` on the sim's own process (`pid` 0, or the caller's real pid): reads the old limit
/// into `old` and installs `new`, either of which may be NULL. Declined for a resource the sim
/// does not model and for another process.
///
/// # Safety
/// `new`/`old` are NULL or point to a `struct rlimit`.
pub(crate) unsafe fn prlimit(
    sys: &SysConfig,
    pid: i32,
    resource: c_int,
    new: *const u8,
    old: *mut u8,
) -> Option<HostResult> {
    if !modelled(resource) || (pid != 0 && pid != std::process::id() as i32) {
        return None;
    }
    let new = (!new.is_null()).then(|| unsafe { read_rlimit(new) });
    let mut result = Ok(());
    let mut before = Rlimit::new(0);
    sys.set_privileges(|p| {
        let current = *slot(p, resource).unwrap();
        before = current;
        if let Some(new) = new {
            result = check_set(p, current, new);
            if result.is_ok() {
                *slot(p, resource).unwrap() = new;
            }
        }
    });
    if let Err(e) = result {
        return err(e);
    }
    if !old.is_null() {
        unsafe { write_rlimit(old, before) };
    }
    ok(0)
}

/// `getrlimit(2)` for a modelled resource.
///
/// # Safety
/// `out` is NULL or points to a `struct rlimit`.
pub(crate) unsafe fn getrlimit(
    sys: &SysConfig,
    resource: c_int,
    out: *mut u8,
) -> Option<HostResult> {
    if !modelled(resource) {
        return None;
    }
    #[cfg(not(target_os = "linux"))]
    if out.is_null() {
        return err(libc::EFAULT);
    }
    unsafe { prlimit(sys, 0, resource, std::ptr::null(), out) }
}

/// `setrlimit(2)` for a modelled resource.
///
/// # Safety
/// `new` is NULL or points to a `struct rlimit`.
pub(crate) unsafe fn setrlimit(
    sys: &SysConfig,
    resource: c_int,
    new: *const u8,
) -> Option<HostResult> {
    if !modelled(resource) {
        return None;
    }
    if new.is_null() {
        return err(libc::EFAULT);
    }
    unsafe { prlimit(sys, 0, resource, new, std::ptr::null_mut()) }
}

/// A thread's scheduling state as the permission rules read it (kernel/sched/syscalls.c).
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub(crate) struct SchedState {
    /// The policy, without `SCHED_RESET_ON_FORK`.
    pub(crate) policy: c_int,
    /// `sched_priority`: 1..=99 under a real-time policy, else 0.
    pub(crate) rt_priority: c_int,
    /// The nice value, -20..=19.
    pub(crate) nice: c_int,
    /// Whether `SCHED_RESET_ON_FORK` is set.
    pub(crate) reset_on_fork: bool,
}

/// `SETPARAM_POLICY` (kernel/sched/syscalls.c): the policy `sched_setparam` passes on, meaning
/// "keep the current one".
#[cfg(target_os = "linux")]
pub(crate) const SETPARAM_POLICY: c_int = -1;

/// `SCHED_DEADLINE` (include/uapi/linux/sched.h).
#[cfg(target_os = "linux")]
const SCHED_DEADLINE: c_int = 6;

/// `can_nice` (kernel/sched/syscalls.c): lowering the nice value to `nice` is allowed with
/// `CAP_SYS_NICE`, or when `20 - nice` (`nice_to_rlimit`, include/linux/sched/prio.h) is within
/// the soft `RLIMIT_NICE`.
#[cfg(target_os = "linux")]
fn is_nice_reduction(p: &Privileges, nice: c_int) -> bool {
    (20 - nice) as u64 <= p.nice_limit.cur
}

/// The new state of a `sched_setscheduler(policy, {priority})` (or `sched_setparam` with
/// [`SETPARAM_POLICY`]) on a thread in state `cur`, or the errno the kernel refuses it with, in
/// the kernel's order (kernel/sched/syscalls.c, Linux 6.12):
///
/// - `__sched_setscheduler`: `EINVAL` for an unknown policy, a priority above 99, a real-time
///   policy with priority 0 or another policy with a non-zero one (`SCHED_DEADLINE` always fails
///   here, as its parameters cannot be given through `struct sched_param`);
/// - `user_check_sched_setscheduler`, skipped with `CAP_SYS_NICE`: `EPERM` to switch to a
///   real-time policy when `RLIMIT_RTPRIO` is 0, to raise the real-time priority above both the
///   current one and `RLIMIT_RTPRIO`, to leave `SCHED_IDLE` when `RLIMIT_NICE` does not cover the
///   current nice value, or to clear `SCHED_RESET_ON_FORK`.
///
/// `priority` is the `int` of `struct sched_param`; the kernel copies it into an unsigned field,
/// so a negative one is `EINVAL`.
#[cfg(target_os = "linux")]
pub(crate) fn sched_setscheduler(
    p: &Privileges,
    cur: SchedState,
    policy: c_int,
    priority: c_int,
) -> Result<SchedState, c_int> {
    let (policy, reset_on_fork) = if policy == SETPARAM_POLICY {
        (cur.policy, cur.reset_on_fork)
    } else {
        let reset = policy & libc::SCHED_RESET_ON_FORK != 0;
        let policy = policy & !libc::SCHED_RESET_ON_FORK;
        let valid = matches!(
            policy,
            libc::SCHED_OTHER | libc::SCHED_FIFO | libc::SCHED_RR | libc::SCHED_BATCH
        ) || policy == libc::SCHED_IDLE
            || policy == SCHED_DEADLINE;
        if !valid {
            return Err(libc::EINVAL);
        }
        (policy, reset)
    };
    let priority = priority as u32;
    let rt = policy == libc::SCHED_FIFO || policy == libc::SCHED_RR;
    if priority > 99 || policy == SCHED_DEADLINE || rt != (priority != 0) {
        return Err(libc::EINVAL);
    }
    if !p.sys_nice {
        let rtprio = p.rtprio_limit.cur;
        let denied = (rt && policy != cur.policy && rtprio == 0)
            || (rt && priority > cur.rt_priority as u32 && u64::from(priority) > rtprio)
            || (cur.policy == libc::SCHED_IDLE
                && policy != libc::SCHED_IDLE
                && !is_nice_reduction(p, cur.nice))
            || (cur.reset_on_fork && !reset_on_fork);
        if denied {
            return Err(libc::EPERM);
        }
    }
    Ok(SchedState {
        policy,
        rt_priority: priority as c_int,
        nice: cur.nice,
        reset_on_fork,
    })
}

/// The nice value a `setpriority(PRIO_PROCESS, …, nice)` leaves, or its errno (kernel/sys.c,
/// Linux 6.12): the value is clamped to -20..=19 first, and lowering it below the current one
/// needs `can_nice`, else `EACCES` (`set_one_prio`).
#[cfg(target_os = "linux")]
pub(crate) fn setpriority(p: &Privileges, current: c_int, nice: c_int) -> Result<c_int, c_int> {
    let nice = nice.clamp(-20, 19);
    if nice < current && !p.sys_nice && !is_nice_reduction(p, nice) {
        return Err(libc::EACCES);
    }
    Ok(nice)
}

/// The pages the code under test has locked (`mlock`) or wired (macOS), as runs of pages with a
/// lock count each: Linux locks are not nested, so a count is 0 or 1 (a second `mlock` of a page
/// changes nothing and one `munlock` unlocks it, man 2 mlock); macOS wiring nests per page, so a
/// page stays wired until unwired as often as it was wired (xnu osfmk/vm/vm_map.c
/// `user_wired_count`; measured by tests/rlimits.rs `memlock_os_truth`).
#[derive(Default)]
pub(crate) struct Wired {
    /// Disjoint `(first page, end page, count)` runs, sorted, every count non-zero.
    runs: Vec<(u64, u64, u32)>,
    /// Whether `mlockall(MCL_CURRENT)` locked the whole address space.
    all: bool,
}

impl Wired {
    /// Pages with a non-zero count.
    fn pages(&self) -> u64 {
        self.runs.iter().map(|&(s, e, _)| e - s).sum()
    }

    /// Pages in `[start, end)` with a count of 0.
    fn unwired_in(&self, start: u64, end: u64) -> u64 {
        let covered: u64 = self
            .runs
            .iter()
            .map(|&(s, e, _)| e.min(end).saturating_sub(s.max(start)))
            .sum();
        (end - start) - covered
    }

    /// Applies `f` to the count of every page in `[start, end)`.
    fn update(&mut self, start: u64, end: u64, f: impl Fn(u32) -> u32) {
        let mut out = Vec::with_capacity(self.runs.len() + 2);
        let mut at = start;
        for &(s, e, c) in &self.runs {
            if e <= start || s >= end {
                out.push((s, e, c));
                continue;
            }
            if s < start {
                out.push((s, start, c));
            }
            if at < s {
                out.push((at, s, f(0)));
            }
            out.push((s.max(start), e.min(end), f(c)));
            if e > end {
                out.push((end, e, c));
            }
            at = e.min(end);
        }
        if at < end {
            out.push((at, end, f(0)));
        }
        out.retain(|&(s, e, c)| c != 0 && s < e);
        out.sort_unstable_by_key(|&(s, _, _)| s);
        self.runs = out;
    }
}

/// The real page size (`sysconf(_SC_PAGESIZE)`).
fn page_size() -> u64 {
    snare_interpose::real(|| unsafe { libc::sysconf(libc::_SC_PAGESIZE) }) as u64
}

/// The pages `[addr, addr + len)` touches, or `None` if it wraps the address space (Linux
/// mm/mlock.c `apply_vma_lock_flags`: `EINVAL`).
fn page_range(addr: u64, len: u64) -> Option<(u64, u64)> {
    let ps = page_size();
    let end = addr.checked_add(len)?;
    Some((addr / ps, end.div_ceil(ps)))
}

/// The real process's total mapped pages (`mm->total_vm`): the first field of
/// `/proc/self/statm` (man 5 proc_pid_statm).
#[cfg(target_os = "linux")]
fn total_vm_pages() -> u64 {
    snare_interpose::real(|| std::fs::read_to_string("/proc/self/statm"))
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
        .unwrap_or(u64::MAX)
}

/// The errno `mlock(addr, len)` fails with, given the sim's privileges and what is already
/// locked, or `Ok(pages)` with the page range it locks.
///
/// - Linux (mm/mlock.c `do_mlock`, Linux 6.12): `EPERM` when `RLIMIT_MEMLOCK` is 0 without
///   `CAP_IPC_LOCK` (`can_do_mlock`); `ENOMEM` when the locked pages, those newly locked included,
///   would exceed the soft `RLIMIT_MEMLOCK` without `CAP_IPC_LOCK`.
/// - macOS (xnu bsd/kern/kern_mman.c `mlock`, osfmk/vm/vm_map.c `add_wire_counts`): a zero
///   length is a no-op; `EAGAIN` (`KERN_RESOURCE_SHORTAGE`) when the newly wired bytes would take
///   the wired total past `RLIMIT_MEMLOCK`, whatever the privileges. Measured by tests/rlimits.rs
///   `memlock_os_truth`.
///
/// Whether the range is mapped is not checked, so the kernel's `ENOMEM` for an unmapped range is
/// not reproduced.
fn mlock_check(
    p: &Privileges,
    w: &Wired,
    addr: u64,
    len: u64,
) -> Result<Option<(u64, u64)>, c_int> {
    if cfg!(target_os = "macos") && len == 0 {
        return Ok(None);
    }
    let limit = p.memlock_limit.cur;
    if cfg!(target_os = "linux") && limit == 0 && !p.ipc_lock {
        return Err(libc::EPERM);
    }
    let (start, end) = page_range(addr, len).ok_or(libc::EINVAL)?;
    if start == end {
        return Ok(None);
    }
    let ps = page_size();
    let limit_pages = if limit == Rlimit::INFINITY {
        u64::MAX
    } else {
        limit / ps
    };
    let locked = w.pages() + w.unwired_in(start, end);
    if cfg!(target_os = "macos") {
        if locked > limit_pages {
            return Err(libc::EAGAIN);
        }
    } else if !w.all && locked > limit_pages && !p.ipc_lock {
        return Err(libc::ENOMEM);
    }
    Ok(Some((start, end)))
}

/// Records a successful `mlock` of `range`.
fn wire(w: &mut Wired, range: Option<(u64, u64)>) {
    if let Some((start, end)) = range {
        if cfg!(target_os = "macos") {
            w.update(start, end, |c| c.saturating_add(1));
        } else {
            w.update(start, end, |_| 1);
        }
    }
}

/// Records a `munlock` of `[addr, addr + len)`: Linux unlocks the pages, macOS unwires each once.
fn unwire(w: &mut Wired, addr: u64, len: u64) -> Result<(), c_int> {
    let (start, end) = page_range(addr, len).ok_or(libc::EINVAL)?;
    if start < end {
        if cfg!(target_os = "macos") {
            w.update(start, end, |c| c.saturating_sub(1));
        } else {
            w.update(start, end, |_| 0);
        }
    }
    Ok(())
}

/// The errno `mlockall(flags)` fails with, from mm/mlock.c (Linux 6.12): `EINVAL` for no flags,
/// unknown flags or `MCL_ONFAULT` alone; `EPERM` per `can_do_mlock`; with `MCL_CURRENT`,
/// `ENOMEM` when the whole address space (`total_vm`) exceeds the soft `RLIMIT_MEMLOCK` without
/// `CAP_IPC_LOCK`.
#[cfg(target_os = "linux")]
fn mlockall_check(p: &Privileges, flags: c_int) -> Result<(), c_int> {
    let known = libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT;
    if flags == 0 || flags & !known != 0 || flags == libc::MCL_ONFAULT {
        return Err(libc::EINVAL);
    }
    let limit = p.memlock_limit.cur;
    if limit == 0 && !p.ipc_lock {
        return Err(libc::EPERM);
    }
    let limit_pages = if limit == Rlimit::INFINITY {
        u64::MAX
    } else {
        limit / page_size()
    };
    if flags & libc::MCL_CURRENT != 0 && !p.ipc_lock && total_vm_pages() > limit_pages {
        return Err(libc::ENOMEM);
    }
    Ok(())
}

/// `mlock(2)` modelled in full: checks and records, never locking real memory.
pub(crate) fn mlock(sys: &SysConfig, addr: u64, len: u64) -> Option<HostResult> {
    let p = sys.privileges();
    let mut w = sys.wired();
    match mlock_check(&p, &w, addr, len) {
        Ok(range) => {
            wire(&mut w, range);
            ok(0)
        }
        Err(e) => err(e),
    }
}

/// `munlock(2)` modelled in full; never fails for a valid range.
pub(crate) fn munlock(sys: &SysConfig, addr: u64, len: u64) -> Option<HostResult> {
    match unwire(&mut sys.wired(), addr, len) {
        Ok(()) => ok(0),
        Err(e) => err(e),
    }
}

/// `mlockall(2)` modelled in full.
#[cfg(target_os = "linux")]
pub(crate) fn mlockall(sys: &SysConfig, flags: c_int) -> Option<HostResult> {
    let p = sys.privileges();
    if let Err(e) = mlockall_check(&p, flags) {
        return err(e);
    }
    if flags & libc::MCL_CURRENT != 0 {
        sys.wired().all = true;
    }
    ok(0)
}

/// `munlockall(2)`: unlocks everything, `mlock`ed ranges included (mm/mlock.c
/// `apply_mlockall_flags(0)` clears `VM_LOCKED` on every mapping).
#[cfg(target_os = "linux")]
pub(crate) fn munlockall(sys: &SysConfig) -> Option<HostResult> {
    *sys.wired() = Wired::default();
    ok(0)
}

/// Routes the raw `syscall(2)` forms of the limit and memory-locking calls to `host`'s handlers:
/// `prlimit64` (the only rlimit syscall on arm64, include/uapi/asm-generic/unistd.h) and, on
/// x86_64, `getrlimit`/`setrlimit` (arch/x86/entry/syscalls/syscall_64.tbl); `mlock`, `munlock`,
/// `mlockall`, `munlockall`.
///
/// # Safety
/// The arguments are the caller's syscall arguments.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn route_syscall(
    host: &dyn Host,
    number: i64,
    args: [i64; 6],
) -> Option<HostResult> {
    match number {
        n if n == libc::SYS_prlimit64 => unsafe {
            host.prlimit(
                args[0] as i32,
                args[1] as c_int,
                args[2] as *const u8,
                args[3] as *mut u8,
            )
        },
        #[cfg(target_arch = "x86_64")]
        n if n == libc::SYS_getrlimit => unsafe {
            host.getrlimit(args[0] as c_int, args[1] as *mut u8)
        },
        #[cfg(target_arch = "x86_64")]
        n if n == libc::SYS_setrlimit => unsafe {
            host.setrlimit(args[0] as c_int, args[1] as *const u8)
        },
        n if n == libc::SYS_mlock => host.mlock(args[0] as u64, args[1] as u64),
        n if n == libc::SYS_munlock => host.munlock(args[0] as u64, args[1] as u64),
        n if n == libc::SYS_mlockall => host.mlockall(args[0] as c_int),
        n if n == libc::SYS_munlockall => host.munlockall(),
        _ => None,
    }
}

/// The process host of a sim without a [`SimHost`](crate::SimHost): the sim's resource limits
/// in full, and its privileges and limits as a gate in front of the real scheduling and
/// memory-locking calls. On macOS it also serves the protocol-counter sysctls.
pub(crate) struct ProcHost {
    pub(crate) shared: std::sync::Arc<crate::scope::SimShared>,
}

impl ProcHost {
    fn sys(&self) -> &SysConfig {
        &self.shared.sys
    }

    /// The calling thread's real scheduling state, read under passthrough (the host runs there).
    #[cfg(target_os = "linux")]
    fn real_sched(tid: i32) -> Option<SchedState> {
        let policy = unsafe { libc::sched_getscheduler(tid) };
        if policy < 0 {
            return None;
        }
        let mut param = libc::sched_param { sched_priority: 0 };
        if unsafe { libc::sched_getparam(tid, &mut param) } != 0 {
            return None;
        }
        Some(SchedState {
            policy: policy & !libc::SCHED_RESET_ON_FORK,
            rt_priority: param.sched_priority,
            nice: Self::real_nice(tid)?,
            reset_on_fork: policy & libc::SCHED_RESET_ON_FORK != 0,
        })
    }

    /// The real nice value of `tid`, via the raw syscall (which returns `20 - nice`, man 2
    /// getpriority NOTES) so a nice of -1 is not mistaken for an error.
    #[cfg(target_os = "linux")]
    fn real_nice(tid: i32) -> Option<c_int> {
        let raw = unsafe { libc::syscall(libc::SYS_getpriority, libc::PRIO_PROCESS, tid) };
        (raw >= 0).then(|| 20 - raw as c_int)
    }

    /// Gates a scheduler change on the sim's privileges, then lets the real call through.
    #[cfg(target_os = "linux")]
    fn gate_sched(&self, pid: i32, policy: c_int, param: *const u8) -> Option<HostResult> {
        if param.is_null() || pid < 0 {
            return None;
        }
        let priority = unsafe { (param as *const c_int).read_unaligned() };
        let cur = Self::real_sched(pid)?;
        match sched_setscheduler(&self.sys().privileges(), cur, policy, priority) {
            Err(libc::EPERM) => err(libc::EPERM),
            _ => None,
        }
    }
}

impl Host for ProcHost {
    unsafe fn getrlimit(&self, resource: c_int, rlim: *mut u8) -> Option<HostResult> {
        unsafe { getrlimit(self.sys(), resource, rlim) }
    }

    unsafe fn setrlimit(&self, resource: c_int, rlim: *const u8) -> Option<HostResult> {
        unsafe { setrlimit(self.sys(), resource, rlim) }
    }

    unsafe fn prlimit(
        &self,
        pid: i32,
        resource: c_int,
        new: *const u8,
        old: *mut u8,
    ) -> Option<HostResult> {
        unsafe { prlimit(self.sys(), pid, resource, new, old) }
    }

    /// Gated on the sim's privileges and limits (see [`mlock_check`]); an allowed call is made
    /// for real and recorded only if it succeeds.
    fn mlock(&self, addr: u64, len: u64) -> Option<HostResult> {
        let p = self.sys().privileges();
        let mut w = self.sys().wired();
        match mlock_check(&p, &w, addr, len) {
            Err(e) => err(e),
            Ok(range) => {
                if unsafe { libc::mlock(addr as *const libc::c_void, len as usize) } != 0 {
                    return err(io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::ENOMEM));
                }
                wire(&mut w, range);
                ok(0)
            }
        }
    }

    /// Unlocks for real, then forgets the range.
    fn munlock(&self, addr: u64, len: u64) -> Option<HostResult> {
        if unsafe { libc::munlock(addr as *const libc::c_void, len as usize) } != 0 {
            return err(io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::ENOMEM));
        }
        let _ = unwire(&mut self.sys().wired(), addr, len);
        ok(0)
    }

    /// Gated on the sim's privileges and limits (see [`mlockall_check`]), then made for real.
    #[cfg(target_os = "linux")]
    fn mlockall(&self, flags: c_int) -> Option<HostResult> {
        if let Err(e) = mlockall_check(&self.sys().privileges(), flags) {
            return err(e);
        }
        if unsafe { libc::mlockall(flags) } != 0 {
            return err(io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::ENOMEM));
        }
        if flags & libc::MCL_CURRENT != 0 {
            self.sys().wired().all = true;
        }
        ok(0)
    }

    #[cfg(target_os = "linux")]
    fn munlockall(&self) -> Option<HostResult> {
        unsafe { libc::munlockall() };
        munlockall(self.sys())
    }

    /// `EPERM` where the sim's privileges and `RLIMIT_RTPRIO` forbid the change (see
    /// [`sched_setscheduler`]); otherwise the real call.
    #[cfg(target_os = "linux")]
    unsafe fn sched_setscheduler(
        &self,
        pid: i32,
        policy: c_int,
        param: *const u8,
    ) -> Option<HostResult> {
        if policy < 0 {
            return None;
        }
        self.gate_sched(pid, policy, param)
    }

    #[cfg(target_os = "linux")]
    unsafe fn sched_setparam(&self, pid: i32, param: *const u8) -> Option<HostResult> {
        self.gate_sched(pid, SETPARAM_POLICY, param)
    }

    /// `EACCES` where the sim's privileges and `RLIMIT_NICE` forbid lowering the nice value of
    /// a thread (`PRIO_PROCESS`); otherwise the real call.
    #[cfg(target_os = "linux")]
    unsafe fn setpriority(&self, which: c_int, who: u32, prio: c_int) -> Option<HostResult> {
        if which != libc::PRIO_PROCESS as c_int {
            return None;
        }
        let current = Self::real_nice(who as i32)?;
        match setpriority(&self.sys().privileges(), current, prio) {
            Err(e) => err(e),
            Ok(_) => None,
        }
    }

    /// `pthread_setschedparam` on the calling thread, gated like `sched_setscheduler`; another
    /// thread's is left to the real call.
    #[cfg(target_os = "linux")]
    unsafe fn pthread_setschedparam(
        &self,
        thread: u64,
        policy: c_int,
        param: *const u8,
    ) -> Option<HostResult> {
        if thread != unsafe { libc::pthread_self() } as u64 {
            return None;
        }
        match self.gate_sched(0, policy, param) {
            Some(HostResult::Err(e)) => err(e),
            _ => None,
        }
    }

    #[cfg(target_os = "linux")]
    unsafe fn syscall(&self, number: i64, args: [i64; 6]) -> Option<HostResult> {
        match number {
            n if n == libc::SYS_sched_setscheduler => unsafe {
                self.sched_setscheduler(args[0] as i32, args[1] as c_int, args[2] as *const u8)
            },
            n if n == libc::SYS_sched_setparam => unsafe {
                self.sched_setparam(args[0] as i32, args[1] as *const u8)
            },
            n if n == libc::SYS_setpriority => unsafe {
                self.setpriority(args[0] as c_int, args[1] as u32, args[2] as c_int)
            },
            _ => unsafe { route_syscall(self, number, args) },
        }
    }

    #[cfg(target_os = "macos")]
    unsafe fn sysctl(
        &self,
        name: *const c_int,
        namelen: u32,
        oldp: *mut u8,
        oldlenp: *mut usize,
        newp: *const u8,
        newlen: usize,
    ) -> Option<HostResult> {
        let stats = crate::netstats::macos::StatsHost(self.shared.clone());
        unsafe { stats.sysctl(name, namelen, oldp, oldlenp, newp, newlen) }
    }

    #[cfg(target_os = "macos")]
    unsafe fn sysctlbyname(
        &self,
        name: *const std::ffi::c_char,
        oldp: *mut u8,
        oldlenp: *mut usize,
        newp: *const u8,
        newlen: usize,
    ) -> Option<HostResult> {
        let stats = crate::netstats::macos::StatsHost(self.shared.clone());
        unsafe { stats.sysctlbyname(name, oldp, oldlenp, newp, newlen) }
    }

    #[cfg(target_os = "macos")]
    unsafe fn sysctlnametomib(
        &self,
        name: *const std::ffi::c_char,
        mib: *mut c_int,
        sizep: *mut usize,
    ) -> Option<HostResult> {
        let stats = crate::netstats::macos::StatsHost(self.shared.clone());
        unsafe { stats.sysctlnametomib(name, mib, sizep) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wired_runs_split_and_merge() {
        let mut w = Wired::default();
        w.update(10, 20, |c| c + 1);
        w.update(15, 25, |c| c + 1);
        assert_eq!(w.runs, vec![(10, 15, 1), (15, 20, 2), (20, 25, 1)]);
        assert_eq!(w.pages(), 15);
        assert_eq!(w.unwired_in(0, 30), 15);
        w.update(12, 22, |c| c.saturating_sub(1));
        assert_eq!(w.runs, vec![(10, 12, 1), (15, 20, 1), (22, 25, 1)]);
        w.update(0, 100, |_| 0);
        assert!(w.runs.is_empty());
    }
}
