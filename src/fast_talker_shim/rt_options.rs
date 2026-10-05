//! fast-talker's thread and process options on snare's simulated host.
//! fast-talker's own `run` applies the rules and builds the report; each
//! option it attempts comes here, one at a time, and is carried out by the
//! shim's [`rt`](super::rt) as fast-talker's per-OS code would.

use std::cell::Cell;
use std::io;
use std::time::Duration;

use ::fast_talker::__sim::{Guard, ThreadTarget};
use ::fast_talker::options::{ApplyError, ProcessOption, Report, Rules, ThreadOption};

use super::rt::{self, CpuDmaLatency, Mmcss, Thread, TimerResolution, log_option};
use super::sim::FtEvent;
use crate::os::OsSemantics;

thread_local! {
    static TARGET: Cell<Option<Thread>> = const { Cell::new(None) };
}

/// Whether the calling thread is inside [`apply_to`], which answers its
/// options even off a snare thread.
pub(crate) fn redirected() -> bool {
    TARGET.with(Cell::get).is_some()
}

/// `ThreadOption::apply_all_to` for a snare thread, through fast-talker's
/// own `run`: the options land on `thread` in place of the calling one.
pub(crate) fn apply_to(
    thread: Thread,
    options: &[ThreadOption],
    rules: &Rules<'_, ThreadOption>,
) -> Result<Report<ThreadOption>, ApplyError<ThreadOption>> {
    struct Restore(Option<Thread>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TARGET.with(|t| t.set(self.0));
        }
    }
    let _restore = Restore(TARGET.with(|t| t.replace(Some(thread))));
    ThreadOption::apply_all(options, rules)
}

fn unsupported(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, why.to_owned())
}

fn only_own() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "this option only applies to the calling thread",
    )
}

fn unknown(what: String) -> io::Error {
    let e = unsupported(&format!("{what} is not simulated by snare"));
    super::sim::log(FtEvent::UnknownOption { what });
    e
}

fn none(r: io::Result<()>) -> io::Result<Guard> {
    r.map(|()| None)
}

fn log(thread: Option<Thread>, option: &impl std::fmt::Debug, result: &io::Result<Guard>) {
    let what = format!("{option:?}");
    match result {
        Ok(_) => log_option(thread, what, Ok(())),
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {
            log_option(thread, format!("skipped:{what}"), Err(e));
        }
        Err(e) => log_option(thread, what, Err(e)),
    }
}

/// One thread option, as `Backend::thread_option`.
pub(crate) fn thread_option(target: ThreadTarget, option: &ThreadOption) -> io::Result<Guard> {
    let no_slot = || {
        io::Error::new(
            io::ErrorKind::NotFound,
            "thread options on a thread with no snare state slot",
        )
    };
    if crate::sched::try_slot().is_none() {
        return Err(no_slot());
    }
    let current = crate::threads::current_tid().map(Thread::from_snare_tid);
    let thread = match target {
        ThreadTarget::Current => TARGET.with(Cell::get).or(current),
        ThreadTarget::Id(host) => Some(Thread::from_host_id(host)),
    };
    let Some(thread) = thread else {
        return Err(no_slot());
    };
    let result = apply_thread(option, thread, current == Some(thread));
    log(Some(thread), option, &result);
    result
}

fn apply_thread(option: &ThreadOption, thread: Thread, own: bool) -> io::Result<Guard> {
    let os = crate::os_semantics();
    match option {
        ThreadOption::PrefaultStack(bytes) => {
            if !own {
                return Err(only_own());
            }
            rt::prefault_stack(*bytes);
            Ok(None)
        }
        ThreadOption::CpuAffinity(cpus) => {
            if os == OsSemantics::MacOs {
                return Err(unsupported(
                    "macOS has no CPU affinity; MacOsQos(UserInteractive) keeps a thread on performance cores",
                ));
            }
            none(thread.set_affinity(cpus))
        }
        ThreadOption::RtPriority(p) => {
            if os == OsSemantics::Windows {
                return Err(unsupported(
                    "Windows has no numeric real-time priority; use WinPriority or WinMmcss",
                ));
            }
            none(thread.set_scheduler(::fast_talker::rt::Scheduler::Fifo(*p)))
        }
        ThreadOption::UnixScheduler(s) => none(thread.set_scheduler(*s)),
        ThreadOption::LinuxNice(n) => none(thread.set_nice(*n)),
        ThreadOption::WinPriority(p) => none(thread.set_priority(*p)),
        ThreadOption::WinDisablePowerThrottling => none(thread.disable_power_throttling()),
        ThreadOption::WinMmcss(task) => {
            if !own {
                return Err(only_own());
            }
            Ok(Some(Box::new(Mmcss::join(task)?)))
        }
        ThreadOption::MacOsQos(q) => none(thread.set_qos(*q)),
        ThreadOption::MacOsTimeConstraint {
            period_us,
            computation_us,
            constraint_us,
        } => none(thread.set_time_constraint(
            Duration::from_micros(*period_us),
            Duration::from_micros(*computation_us),
            Duration::from_micros(*constraint_us),
        )),
        other => Err(unknown(format!("{other:?}"))),
    }
}

/// One process option, as `Backend::process_option`.
pub(crate) fn process_option(option: &ProcessOption) -> io::Result<Guard> {
    let result = apply_process(option);
    log(None, option, &result);
    result
}

fn apply_process(option: &ProcessOption) -> io::Result<Guard> {
    match option {
        ProcessOption::LockMemory => match crate::os_semantics() {
            OsSemantics::Windows => Err(unsupported(
                "Windows cannot lock all memory; use WinReserveWorkingSet",
            )),
            OsSemantics::MacOs => Err(unsupported("macOS does not implement mlockall")),
            _ => none(rt::lock_memory()),
        },
        ProcessOption::LinuxCpuDmaLatency(us) => {
            let guard = CpuDmaLatency::request(Duration::from_micros((*us).into()))?;
            Ok(Some(Box::new(guard)))
        }
        ProcessOption::WinPriority(p) => none(rt::set_process_priority(*p)),
        ProcessOption::WinTimerResolution(ms) => {
            let guard = TimerResolution::request(Duration::from_millis((*ms).into()))?;
            Ok(Some(Box::new(guard)))
        }
        ProcessOption::WinDisablePowerThrottling => none(rt::disable_power_throttling()),
        ProcessOption::WinProcessCpus(cpus) => none(rt::set_process_cpus(cpus)),
        ProcessOption::WinReserveWorkingSet {
            min_bytes,
            max_bytes,
        } => none(rt::reserve_working_set(*min_bytes, *max_bytes)),
        other => Err(unknown(format!("{other:?}"))),
    }
}
