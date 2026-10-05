//! fast-talker's `rt` over snare's thread registry. Settings are recorded
//! for tests to query ([`sim::threads`](super::sim::threads),
//! [`sim::process`](super::sim::process)); they never reach the host's
//! scheduler and never change how snare schedules a thread.
//!
//! Every item exists on every host. Which ones work, and the errors they
//! give, follow [`os_semantics`](crate::os_semantics). Privileges come from
//! [`set_privileges`](crate::set_privileges): on Windows,
//! `SeIncreaseBasePriorityPrivilege` is `sys_nice`,
//! `SeIncreaseWorkingSetPrivilege` is `ipc_lock` and an elevated process is
//! `root`.

use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;

pub use ::fast_talker::rt::{ProcessPriority, QosClass, Scheduler, ThreadPriority};

use super::platform::{Item, require};
use super::sim::{DmaLatencyRequest, FtEntry, FtEvent, ThreadApply, TimeConstraint};
use super::slot::{FtSlot, FtState, ThreadRt};
use crate::os::{OsSemantics, SysErrno, sys_err};
use crate::threads::ThreadInfo;
use crate::time::Instant;

const UNKNOWN_THREAD: u64 = 1 << 63;
const CPU_SETSIZE: usize = 1024;
const WINDOWS_GROUP_SIZE: usize = 64;
const MACOS_RT_PRIORITIES: (u8, u8) = (15, 47);
const MACH_MAX_RT_QUANTUM: Duration = Duration::from_millis(50);
const KERN_INVALID_ARGUMENT: i32 = 4;
const TIMER_RESOLUTION_MAX_MS: u32 = 1_000_000;
const ERROR_INVALID_TASK_NAME: i32 = 1550;
const ERROR_THREAD_ALREADY_IN_TASK: i32 = 1552;
const MMCSS_TASKS: [&str; 8] = [
    "Audio",
    "Capture",
    "DisplayPostProcessing",
    "Distribution",
    "Games",
    "Playback",
    "Pro Audio",
    "Window Manager",
];

/// A thread of the simulated host, by snare's thread id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Thread {
    tid: u64,
}

enum On {
    Thread(u64),
    Process,
}

/// Record one setting: applied through `result`'s closure when it is `Ok`,
/// which gives the call's value,
/// logged either way on the thread (or the process) and as an
/// [`FtEvent::Rt`].
fn record<R, F: FnOnce(&mut FtState) -> R>(
    on: On,
    what: String,
    result: io::Result<F>,
) -> io::Result<R> {
    let at = Instant::now();
    let caller = crate::threads::current_tid();
    let thread = match on {
        On::Thread(t) => Some(t),
        On::Process => None,
    };
    let known = thread.is_none_or(|t| crate::threads::by_tid(t).is_some());
    let outcome = result.as_ref().map(|_| ()).map_err(io::Error::kind);
    let os_error = result.as_ref().err().and_then(crate::os_error_code);
    let slot = crate::state::ft_slot();
    let mut g = slot.inner.lock();
    let result = result.map(|apply| apply(&mut g));
    g.events.push(FtEntry {
        at,
        tid: caller,
        event: FtEvent::Rt {
            thread,
            what: what.clone(),
            result: outcome,
        },
    });
    if known {
        let entry = ThreadApply {
            at,
            what,
            result: outcome,
            os_error,
        };
        match thread {
            Some(t) => g.rt.entry(t).or_default().log.push(entry),
            None => g.process.log.push(entry),
        }
    }
    result
}

fn refuse(on: On, what: String, e: io::Error) -> io::Result<()> {
    record(on, what, Err::<fn(&mut FtState), _>(e))
}

fn cpu_count() -> usize {
    crate::state::ft_slot().inner.lock().cpus.count
}

fn read_rt<R>(tid: u64, f: impl FnOnce(Option<&ThreadRt>) -> R) -> R {
    let slot = crate::state::ft_slot();
    let g = slot.inner.lock();
    f(g.rt.get(&tid))
}

/// `name` as the OS reports it: Linux keeps 15 bytes, macOS 63.
fn os_name(name: &str, os: OsSemantics) -> &str {
    let max = match os {
        OsSemantics::Linux => 15,
        OsSemantics::MacOs => 63,
        OsSemantics::Windows => usize::MAX,
    };
    if name.len() <= max {
        return name;
    }
    let mut end = max;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    &name[..end]
}

/// Linux kernel threads bound to one CPU, which refuse other affinities.
fn per_cpu_kernel_thread(info: &ThreadInfo) -> bool {
    info.kernel
        && info.name.as_deref().is_some_and(|n| {
            ["ksoftirqd/", "migration/", "cpuhp/"]
                .iter()
                .any(|p| n.starts_with(p))
        })
}

fn sorted(cpus: &[usize]) -> Vec<usize> {
    let mut v = cpus.to_vec();
    v.sort_unstable();
    v.dedup();
    v
}

fn invalid_input(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

fn windows_cpus(cpus: &[usize], count: usize) -> io::Result<()> {
    if let Some(c) = cpus.iter().find(|&&c| c >= count) {
        return Err(invalid_input(format!("no CPU {c}")));
    }
    Ok(())
}

impl Thread {
    /// The calling thread, registered with snare on first use. Panics on a
    /// thread with no snare state slot.
    pub fn current() -> Self {
        let tid = crate::threads::current_tid()
            .expect("snare::fast_talker::rt::Thread::current needs a snare state slot");
        Self { tid }
    }

    /// The thread with snare tid `tid`, else the one with that host thread
    /// id. Synthetic kernel threads have tids beyond `i32`; find them with
    /// [`find`](Self::find). An unknown id gives a thread whose calls fail
    /// with `ESRCH`.
    pub fn from_tid(tid: i32) -> Self {
        u64::try_from(tid).map_or(
            Self {
                tid: UNKNOWN_THREAD,
            },
            Self::resolve,
        )
    }

    /// The thread with snare tid `id`, else the one with that host thread
    /// id, as [`from_tid`](Self::from_tid).
    pub fn from_id(id: u32) -> Self {
        Self::resolve(id.into())
    }

    fn resolve(id: u64) -> Self {
        if crate::threads::by_tid(id).is_some() {
            return Self { tid: id };
        }
        match crate::threads::by_host_tid(id) {
            Some(info) => Self { tid: info.tid },
            None => Self {
                tid: id | UNKNOWN_THREAD,
            },
        }
    }

    /// Every live thread, kernel threads included, whose name as Linux
    /// keeps it (15 bytes) starts with `prefix`, by tid.
    pub fn find(prefix: &str) -> io::Result<Vec<Thread>> {
        require(Item::LinuxRt)?;
        let mut out: Vec<Thread> = crate::threads::all()
            .into_iter()
            .filter(|t| !t.exited)
            .filter(|t| {
                os_name(t.name.as_deref().unwrap_or(""), OsSemantics::Linux).starts_with(prefix)
            })
            .map(|t| Thread { tid: t.tid })
            .collect();
        out.sort_by_key(|t| t.tid);
        Ok(out)
    }

    pub(crate) fn from_snare_tid(tid: u64) -> Self {
        Self { tid }
    }

    /// snare's id for the thread: unique within its state slot, and the key
    /// [`sim::threads`](super::sim::threads) reports it under.
    pub fn id(&self) -> u64 {
        self.tid
    }

    fn info(&self) -> io::Result<ThreadInfo> {
        crate::threads::by_tid(self.tid)
            .filter(|t| !t.exited)
            .ok_or_else(|| sys_err(SysErrno::Srch))
    }

    /// The thread's name, cut to what the OS keeps: 15 bytes on Linux, 63
    /// on macOS.
    pub fn name(&self) -> io::Result<String> {
        require(Item::ThreadIdentity)?;
        let info = self.info()?;
        let os = crate::os_semantics();
        Ok(os_name(info.name.as_deref().unwrap_or(""), os).to_string())
    }

    /// Current scheduling policy and priority; `Other` until set.
    pub fn scheduler(&self) -> io::Result<Scheduler> {
        require(Item::ThreadScheduler)?;
        self.info()?;
        Ok(read_rt(self.tid, |rt| rt.and_then(|r| r.scheduler)).unwrap_or(Scheduler::Other))
    }

    /// Sets the scheduling policy and priority. Linux takes real-time
    /// priorities 1-99 and needs `sys_nice` or an `rtprio_limit` at least
    /// that high; macOS clamps them to 15-47 and has no `Batch` or `Idle`.
    pub fn set_scheduler(&self, scheduler: Scheduler) -> io::Result<()> {
        let tid = self.tid;
        let result = self
            .scheduler_for(scheduler)
            .map(|eff| move |g: &mut FtState| g.rt.entry(tid).or_default().scheduler = Some(eff));
        record(
            On::Thread(tid),
            format!("set_scheduler({scheduler:?})"),
            result,
        )
    }

    fn scheduler_for(&self, scheduler: Scheduler) -> io::Result<Scheduler> {
        require(Item::ThreadScheduler)?;
        self.info()?;
        if crate::os_semantics() == OsSemantics::MacOs {
            let (lo, hi) = MACOS_RT_PRIORITIES;
            return match scheduler {
                Scheduler::Batch | Scheduler::Idle => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "macOS has no SCHED_BATCH or SCHED_IDLE",
                )),
                Scheduler::Fifo(p) => Ok(Scheduler::Fifo(p.clamp(lo, hi))),
                Scheduler::RoundRobin(p) => Ok(Scheduler::RoundRobin(p.clamp(lo, hi))),
                Scheduler::Other => Ok(Scheduler::Other),
            };
        }
        if let Scheduler::Fifo(p) | Scheduler::RoundRobin(p) = scheduler {
            if !(1..=99).contains(&p) {
                return Err(sys_err(SysErrno::Inval));
            }
            let privs = crate::privileges();
            if !privs.sys_nice && p > privs.rtprio_limit {
                return Err(sys_err(SysErrno::Perm));
            }
        }
        Ok(scheduler)
    }

    /// The CPUs the thread may run on: every CPU until set.
    pub fn affinity(&self) -> io::Result<Vec<usize>> {
        require(Item::ThreadAffinity)?;
        self.info()?;
        let slot = crate::state::ft_slot();
        let g = slot.inner.lock();
        Ok(g.rt
            .get(&self.tid)
            .and_then(|r| r.affinity.clone())
            .unwrap_or_else(|| (0..g.cpus.count).collect()))
    }

    /// Restricts the thread to `cpus`. A CPU the simulated host lacks is
    /// `EINVAL` on Linux and `InvalidInput` on Windows, as are Linux's
    /// per-CPU kernel threads (`ksoftirqd/N`) and, on Windows, CPUs in more
    /// than one processor group.
    pub fn set_affinity(&self, cpus: &[usize]) -> io::Result<()> {
        let tid = self.tid;
        let result = self
            .affinity_for(cpus)
            .map(|cpus| move |g: &mut FtState| g.rt.entry(tid).or_default().affinity = Some(cpus));
        record(On::Thread(tid), format!("set_affinity({cpus:?})"), result)
    }

    fn affinity_for(&self, cpus: &[usize]) -> io::Result<Vec<usize>> {
        require(Item::ThreadAffinity)?;
        let info = self.info()?;
        let count = cpu_count();
        if crate::os_semantics() == OsSemantics::Windows {
            windows_cpus(cpus, count)?;
            let Some(first) = cpus.first() else {
                return Err(invalid_input("no CPUs given"));
            };
            if cpus
                .iter()
                .any(|c| c / WINDOWS_GROUP_SIZE != first / WINDOWS_GROUP_SIZE)
            {
                return Err(invalid_input(
                    "a thread's CPUs must all be in one processor group",
                ));
            }
        } else {
            if let Some(c) = cpus.iter().find(|&&c| c >= CPU_SETSIZE) {
                return Err(invalid_input(format!("CPU {c} is beyond CPU_SETSIZE")));
            }
            if cpus.is_empty() || cpus.iter().any(|&c| c >= count) || per_cpu_kernel_thread(&info) {
                return Err(sys_err(SysErrno::Inval));
            }
        }
        Ok(sorted(cpus))
    }

    /// Nice value; 0 until set.
    pub fn nice(&self) -> io::Result<i8> {
        require(Item::LinuxRt)?;
        self.info()?;
        Ok(read_rt(self.tid, |rt| rt.and_then(|r| r.nice)).unwrap_or(0))
    }

    /// Sets the nice value, clamped to -20..=19. Going below `nice_limit`
    /// needs `sys_nice`, else `EACCES` as `setpriority` gives.
    pub fn set_nice(&self, nice: i8) -> io::Result<()> {
        let tid = self.tid;
        let result = (|| {
            require(Item::LinuxRt)?;
            self.info()?;
            let n = nice.clamp(-20, 19);
            let privs = crate::privileges();
            if n < privs.nice_limit && !privs.sys_nice {
                return Err(sys_err(SysErrno::Access));
            }
            Ok(move |g: &mut FtState| g.rt.entry(tid).or_default().nice = Some(n))
        })();
        record(On::Thread(tid), format!("set_nice({nice})"), result)
    }

    /// Sets affinity, then scheduling, as fast-talker's `pin` does off
    /// Windows.
    #[cfg(not(windows))]
    pub fn pin(&self, cpus: &[usize], scheduler: Scheduler) -> io::Result<()> {
        self.pin_scheduler(cpus, scheduler)
    }

    /// Sets affinity, then priority, as fast-talker's `pin` does on
    /// Windows.
    #[cfg(windows)]
    pub fn pin(&self, cpus: &[usize], priority: ThreadPriority) -> io::Result<()> {
        self.pin_priority(cpus, priority)
    }

    /// [`set_affinity`](Self::set_affinity), then
    /// [`set_scheduler`](Self::set_scheduler), on every host.
    pub fn pin_scheduler(&self, cpus: &[usize], scheduler: Scheduler) -> io::Result<()> {
        self.set_affinity(cpus)?;
        self.set_scheduler(scheduler)
    }

    /// [`set_affinity`](Self::set_affinity), then
    /// [`set_priority`](Self::set_priority), on every host.
    pub fn pin_priority(&self, cpus: &[usize], priority: ThreadPriority) -> io::Result<()> {
        self.set_affinity(cpus)?;
        self.set_priority(priority)
    }

    /// Makes this a Mach time-constraint thread. Fails as
    /// `thread_policy_set` does when `constraint` is shorter than
    /// `computation` or `computation` is over 50 ms. macOS.
    pub fn set_time_constraint(
        &self,
        period: Duration,
        computation: Duration,
        constraint: Duration,
    ) -> io::Result<()> {
        let tid = self.tid;
        let result = (|| {
            require(Item::MacOsRt)?;
            self.info()?;
            if constraint < computation || computation > MACH_MAX_RT_QUANTUM {
                return Err(io::Error::other(format!(
                    "thread_policy_set failed with kern_return_t {KERN_INVALID_ARGUMENT}"
                )));
            }
            let tc = TimeConstraint {
                period,
                computation,
                constraint,
            };
            Ok(move |g: &mut FtState| g.rt.entry(tid).or_default().time_constraint = Some(tc))
        })();
        let what = format!("set_time_constraint({period:?}, {computation:?}, {constraint:?})");
        record(On::Thread(tid), what, result)
    }

    /// Sets the QoS class. Must be the calling thread, or fails with
    /// `InvalidInput`. macOS.
    pub fn set_qos(&self, class: QosClass) -> io::Result<()> {
        let tid = self.tid;
        let result = (|| {
            require(Item::MacOsRt)?;
            self.info()?;
            if crate::threads::current_tid() != Some(tid) {
                return Err(invalid_input(
                    "macOS only sets the QoS class of the calling thread",
                ));
            }
            Ok(move |g: &mut FtState| g.rt.entry(tid).or_default().qos = Some(class))
        })();
        record(On::Thread(tid), format!("set_qos({class:?})"), result)
    }

    /// The thread's priority within its process's class; `Normal` until
    /// set. Windows.
    pub fn priority(&self) -> io::Result<ThreadPriority> {
        require(Item::WindowsRt)?;
        self.info()?;
        Ok(read_rt(self.tid, |rt| rt.and_then(|r| r.win_priority))
            .unwrap_or(ThreadPriority::Normal))
    }

    /// Sets the thread's priority within its process's class. Windows.
    pub fn set_priority(&self, priority: ThreadPriority) -> io::Result<()> {
        let tid = self.tid;
        let result = (|| {
            require(Item::WindowsRt)?;
            self.info()?;
            Ok(move |g: &mut FtState| g.rt.entry(tid).or_default().win_priority = Some(priority))
        })();
        record(
            On::Thread(tid),
            format!("set_priority({priority:?})"),
            result,
        )
    }

    /// Opts the thread out of EcoQoS. Windows.
    pub fn disable_power_throttling(&self) -> io::Result<()> {
        let tid = self.tid;
        let result =
            (|| {
                require(Item::WindowsRt)?;
                self.info()?;
                Ok(move |g: &mut FtState| {
                    g.rt.entry(tid).or_default().power_throttling_disabled = true
                })
            })();
        record(On::Thread(tid), "disable_power_throttling".into(), result)
    }
}

/// Maps a host thread to its snare thread through the host thread id snare
/// recorded. A host thread snare never saw maps to a thread whose calls
/// fail with `ESRCH`.
impl From<::fast_talker::rt::Thread> for Thread {
    fn from(t: ::fast_talker::rt::Thread) -> Self {
        Self::from_host_id(t.id())
    }
}

impl Thread {
    /// The snare thread behind host thread id `host`, as fast-talker's
    /// `rt::Thread::id` reports it.
    pub(crate) fn from_host_id(host: u64) -> Self {
        if host == ::fast_talker::rt::Thread::current().id()
            && let Some(tid) = crate::threads::current_tid()
        {
            return Self { tid };
        }
        match crate::threads::by_host_tid(host) {
            Some(info) => Self { tid: info.tid },
            None => Self {
                tid: host | UNKNOWN_THREAD,
            },
        }
    }
}

/// Log one option of an options list on `thread`'s record, or the
/// process's when `thread` is `None`. Threads snare does not know are not
/// logged.
pub(crate) fn log_option(thread: Option<Thread>, what: String, result: Result<(), &io::Error>) {
    if thread.is_some_and(|t| crate::threads::by_tid(t.tid).is_none()) {
        return;
    }
    let entry = ThreadApply {
        at: Instant::now(),
        what,
        result: result.map_err(io::Error::kind),
        os_error: result.err().and_then(crate::os_error_code),
    };
    let slot = crate::state::ft_slot();
    let mut g = slot.inner.lock();
    match thread {
        Some(t) => g.rt.entry(t.tid).or_default().log.push(entry),
        None => g.process.log.push(entry),
    }
}

/// Touches `bytes` of the calling thread's stack, as fast-talker's does,
/// and records the amount on the thread.
pub fn prefault_stack(bytes: usize) {
    if let Some(tid) = crate::threads::current_tid() {
        let slot = crate::state::ft_slot();
        let mut g = slot.inner.lock();
        let rt = g.rt.entry(tid).or_default();
        rt.prefault_bytes = rt.prefault_bytes.max(bytes);
    }
    ::fast_talker::rt::prefault_stack(bytes);
}

/// Locks the process's memory. Needs `ipc_lock` or an unlimited
/// `memlock_limit`; otherwise `EPERM` with a zero limit and `ENOMEM` with
/// any other. Linux.
pub fn lock_memory() -> io::Result<()> {
    let result = (|| {
        require(Item::LinuxRt)?;
        let privs = crate::privileges();
        if !privs.ipc_lock {
            match privs.memlock_limit {
                None => {}
                Some(0) => return Err(sys_err(SysErrno::Perm)),
                Some(_) => return Err(sys_err(SysErrno::NoMem)),
            }
        }
        Ok(|g: &mut FtState| g.process.memory_locked = true)
    })();
    record(On::Process, "lock_memory".into(), result)
}

/// CPUs isolated with `isolcpus=`, from
/// [`CpuTopology`](super::sim::CpuTopology). Linux.
pub fn isolated_cpus() -> io::Result<Vec<usize>> {
    require(Item::LinuxRt)?;
    Ok(crate::state::ft_slot().inner.lock().cpus.isolated.clone())
}

/// CPUs running tickless (`nohz_full=`), from
/// [`CpuTopology`](super::sim::CpuTopology). Linux.
pub fn nohz_full_cpus() -> io::Result<Vec<usize>> {
    require(Item::LinuxRt)?;
    Ok(crate::state::ft_slot().inner.lock().cpus.nohz_full.clone())
}

/// A guard's hold on its state slot, released on drop.
struct Held {
    slot: Arc<FtSlot>,
    id: u64,
}

impl fmt::Debug for Held {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Held").field("id", &self.id).finish()
    }
}

fn next_guard(g: &mut FtState) -> u64 {
    let id = g.process.next_guard;
    g.process.next_guard += 1;
    id
}

/// A held CPU wake-up latency limit, released on drop. The limit in force
/// is the smallest one held ([`sim::process`](super::sim::process)).
#[derive(Debug)]
pub struct CpuDmaLatency {
    held: Held,
}

impl CpuDmaLatency {
    /// Requests that no CPU take longer than `max` to wake. Opening
    /// `/dev/cpu_dma_latency` needs `root`, else `EACCES`. Linux.
    pub fn request(max: Duration) -> io::Result<Self> {
        let slot = crate::state::ft_slot();
        let at = Instant::now();
        let tid = crate::threads::current_tid();
        let micros = u32::try_from(max.as_micros())
            .map_or(i32::MAX.unsigned_abs(), |m| m.min(i32::MAX.unsigned_abs()));
        let held_max = Duration::from_micros(micros.into());
        let result = (|| {
            require(Item::LinuxRt)?;
            if !crate::privileges().root {
                return Err(sys_err(SysErrno::Access));
            }
            Ok(move |g: &mut FtState| {
                let id = next_guard(g);
                g.process.dma_latency.push(DmaLatencyRequest {
                    id,
                    max: held_max,
                    at,
                    tid,
                });
                id
            })
        })();
        let id = record(
            On::Process,
            format!("CpuDmaLatency::request({max:?})"),
            result,
        )?;
        Ok(Self {
            held: Held { slot, id },
        })
    }
}

impl Drop for CpuDmaLatency {
    fn drop(&mut self) {
        let id = self.held.id;
        self.held
            .slot
            .inner
            .lock()
            .process
            .dma_latency
            .retain(|r| r.id != id);
    }
}

/// The process's priority class; `Normal` until set. Windows.
pub fn process_priority() -> io::Result<ProcessPriority> {
    require(Item::WindowsRt)?;
    Ok(crate::state::ft_slot()
        .inner
        .lock()
        .process
        .win_priority
        .unwrap_or(ProcessPriority::Normal))
}

/// Sets the process's priority class. Without `sys_nice`
/// (`SeIncreaseBasePriorityPrivilege`), Windows grants `High` instead of
/// `Realtime`, and this fails with `PermissionDenied`. Windows.
pub fn set_process_priority(priority: ProcessPriority) -> io::Result<()> {
    let what = format!("set_process_priority({priority:?})");
    if let Err(e) = require(Item::WindowsRt) {
        return refuse(On::Process, what, e);
    }
    if priority == ProcessPriority::Realtime && !crate::privileges().sys_nice {
        let granted = ProcessPriority::High;
        crate::state::ft_slot().inner.lock().process.win_priority = Some(granted);
        let e = io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "asked for {priority:?} priority but Windows granted {granted:?}; run elevated"
            ),
        );
        return refuse(On::Process, what, e);
    }
    record(
        On::Process,
        what,
        Ok(move |g: &mut FtState| g.process.win_priority = Some(priority)),
    )
}

/// Opts the whole process out of EcoQoS and timer-resolution throttling.
/// Windows.
pub fn disable_power_throttling() -> io::Result<()> {
    let result = require(Item::WindowsRt)
        .map(|()| |g: &mut FtState| g.process.power_throttling_disabled = true);
    record(On::Process, "disable_power_throttling".into(), result)
}

/// Keeps the process's threads on `cpus`; an empty slice clears it.
/// Windows.
pub fn set_process_cpus(cpus: &[usize]) -> io::Result<()> {
    let result = (|| {
        require(Item::WindowsRt)?;
        windows_cpus(cpus, cpu_count())?;
        let set = (!cpus.is_empty()).then(|| sorted(cpus));
        Ok(move |g: &mut FtState| g.process.process_cpus = set)
    })();
    record(On::Process, format!("set_process_cpus({cpus:?})"), result)
}

/// Reserves a working set of at least `min` bytes. Needs `ipc_lock`
/// (`SeIncreaseWorkingSetPrivilege`), else `ERROR_PRIVILEGE_NOT_HELD`.
/// Windows.
pub fn reserve_working_set(min: usize, max: usize) -> io::Result<()> {
    let result = (|| {
        require(Item::WindowsRt)?;
        if !crate::privileges().ipc_lock {
            return Err(sys_err(SysErrno::Perm));
        }
        Ok(move |g: &mut FtState| g.process.working_set = Some((min, max.max(min))))
    })();
    record(
        On::Process,
        format!("reserve_working_set({min}, {max})"),
        result,
    )
}

/// A held system timer resolution request, released on drop. Windows.
#[derive(Debug)]
pub struct TimerResolution {
    held: Held,
}

impl TimerResolution {
    /// Requests `resolution` in whole milliseconds, 1 ms at finest.
    pub fn request(resolution: Duration) -> io::Result<Self> {
        let slot = crate::state::ft_slot();
        let millis = u32::try_from(resolution.as_millis().max(1)).unwrap_or(u32::MAX);
        let result = (|| {
            require(Item::WindowsRt)?;
            if millis > TIMER_RESOLUTION_MAX_MS {
                return Err(invalid_input(format!(
                    "timer resolution {millis} ms is out of range"
                )));
            }
            Ok(move |g: &mut FtState| {
                let id = next_guard(g);
                g.process
                    .timer_resolution
                    .push((id, Duration::from_millis(millis.into())));
                id
            })
        })();
        let id = record(
            On::Process,
            format!("TimerResolution::request({resolution:?})"),
            result,
        )?;
        Ok(Self {
            held: Held { slot, id },
        })
    }
}

impl Drop for TimerResolution {
    fn drop(&mut self) {
        let id = self.held.id;
        self.held
            .slot
            .inner
            .lock()
            .process
            .timer_resolution
            .retain(|(i, _)| *i != id);
    }
}

/// The calling thread's MMCSS registration, reverted on drop. Windows.
#[derive(Debug)]
pub struct Mmcss {
    held: Held,
    tid: u64,
}

impl Mmcss {
    /// Joins MMCSS task `task` (a key under `...\SystemProfile\Tasks`, such
    /// as `"Pro Audio"`). Another name fails with
    /// `ERROR_INVALID_TASK_NAME`, and a thread already in a task with
    /// `ERROR_THREAD_ALREADY_IN_TASK`.
    pub fn join(task: &str) -> io::Result<Self> {
        let slot = crate::state::ft_slot();
        let tid = Thread::current().tid;
        let result = (|| {
            require(Item::WindowsRt)?;
            let os = crate::os_semantics();
            let win32 = |code, name| crate::os::code_err(os, code, name, io::ErrorKind::Other);
            let Some(known) = MMCSS_TASKS.iter().find(|t| t.eq_ignore_ascii_case(task)) else {
                return Err(win32(ERROR_INVALID_TASK_NAME, "ERROR_INVALID_TASK_NAME"));
            };
            if read_rt(tid, |rt| rt.is_some_and(|r| r.mmcss.is_some())) {
                return Err(win32(
                    ERROR_THREAD_ALREADY_IN_TASK,
                    "ERROR_THREAD_ALREADY_IN_TASK",
                ));
            }
            Ok(move |g: &mut FtState| {
                let id = next_guard(g);
                g.rt.entry(tid).or_default().mmcss = Some((id, known.to_string()));
                id
            })
        })();
        let id = record(On::Thread(tid), format!("Mmcss::join({task:?})"), result)?;
        Ok(Self {
            held: Held { slot, id },
            tid,
        })
    }
}

impl Drop for Mmcss {
    fn drop(&mut self) {
        let id = self.held.id;
        let mut g = self.held.slot.inner.lock();
        if let Some(rt) = g.rt.get_mut(&self.tid)
            && rt.mmcss.as_ref().is_some_and(|(i, _)| *i == id)
        {
            rt.mmcss = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_cut_where_each_os_cuts_them() {
        let long = "telegenic-gvsp-stream-0123456789-0123456789-0123456789-0123456789";
        assert_eq!(os_name(long, OsSemantics::Linux), "telegenic-gvsp-");
        assert_eq!(os_name(long, OsSemantics::MacOs).len(), 63);
        assert_eq!(os_name(long, OsSemantics::Windows), long);
        assert_eq!(
            os_name("héllo-wörld-ünï", OsSemantics::Linux),
            "héllo-wörld-"
        );
    }
}
