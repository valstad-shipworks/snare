//! Telling a stuck domain from a waiting one, in real time.
//!
//! A domain makes progress when a participant parks or wakes, when its epoch moves (a lease is
//! taken or given back, a class changes), when its virtual clock moves (a time skip, a write from outside,
//! a scaled or granted clock flowing, the latency a hooked call is charged, a clock spin's step),
//! or, under a deterministic schedule, when a participant begins a wait there. What a thread does between
//! hooked calls is invisible to it: a participant spinning on an atomic, or computing, keeps the
//! domain busy — it is not blocked, so time does not skip — while nothing the domain can see
//! changes, and under the discrete clock every sleeper waiting on that time waits for good.
//!
//! Two kinds of stall are told apart here, both measured in real time from the last progress:
//!
//! - *Idle*: a deterministic schedule waits in real time with every participant blocked — on a held
//!   clock, on a lease, or on locks only something outside the simulation can release. Each is
//!   something the design waits for rather than a fault, so [`warn`] says so once on stderr after
//!   [`STALL_WARN`] and the schedule carries on.
//! - *Busy*: with [`DomainBuilder::stuck_after`](crate::DomainBuilder::stuck_after) set, a
//!   [`Watchdog`] thread fails the run once a participant has been running for that long with no
//!   progress, no lease held and no executive's timestamp open, on a virtual clock, and the
//!   participants outside any wait have used that much CPU time meanwhile: one the OS has not let
//!   run (a loaded machine) is not stuck yet. One blocked in a call snare does not see uses no
//!   CPU time either, so it is failed only after [`off_cpu_limit`] of real time without progress.
//!   A lease is how a thread declares work the simulation cannot see; an open timestamp is the
//!   executive's own business; a blocked participant is waiting, not stuck; and a clock that is
//!   not virtual (the real one, or one that ticks as it is read) moves on its own, so nothing
//!   waits on a spinner to move it. Nor does it watch a dormant domain (every run ended): what
//!   the threads left over from a run do is no longer the test's.
//!
//! A busy stall cannot be unwound into the test: the stuck thread never reaches a hook, and one
//! thread cannot make another panic. The watchdog attempts its report on the process's standard
//! error, past the test harness's output capture. Reporting gets 2 s before the process aborts,
//! even if stderr is locked or blocked.

use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::accounting::{LeaseKind, PState, ParticipantInfo};
use crate::domain::{Domain, WeakDomain};

/// How long a deterministic schedule idles in real time with nothing able to move before
/// [`warn`] reports it. A snare choice: long enough that an outside release or clock write
/// normally lands first, short enough to explain a hang while the test still runs.
pub(crate) const STALL_WARN: Duration = Duration::from_secs(1);

/// Why a deterministic schedule is waiting in real time.
#[derive(Clone, Copy)]
pub(crate) enum Idle {
    /// The clock is held.
    Held,
    /// The clock moves with real time while the sim waits on a child process.
    Process,
    /// A lease holds the domain busy.
    Leased,
    /// Only lock and address waits remain, which only something outside the simulation can release.
    Outside,
    /// A time skip waits on threads of other sims that share the process's statics with it.
    HeldOff,
}

/// How long a busy domain may go without progress while its running participants use no CPU time
/// before [`Watchdog`] fails it: ten times `after`, and at least 5 s. A snare choice: a loaded
/// machine leaves a thread unscheduled for far less, while a participant blocked in a call snare
/// does not hook (a real pipe nobody writes, `waitpid`, `sigwait`) waits for good.
fn off_cpu_limit(after: Duration) -> Duration {
    after.saturating_mul(10).max(Duration::from_secs(5))
}

/// What [`Watchdog`] compares from one sample to the next: the epoch, the virtual monotonic time
/// (`None` on a clock that is not virtual), and the waits begun in a deterministic schedule.
pub(crate) type Progress = (u64, Option<Duration>, u64);

/// Prints, once per idle stretch, why the calling thread's deterministic schedule has made no
/// progress for [`STALL_WARN`] and what each participant waits in. Silent for a held clock while
/// an executive is attached, since it moves time from outside and a long hold is its business.
/// Called with none of the domain's locks held: the listing takes the census lock.
pub(crate) fn warn(why: Idle) {
    if matches!(why, Idle::Held) && crate::domain::executive_attached() {
        return;
    }
    let listing = Domain::current()
        .map(|domain| listing(&domain.participants()))
        .unwrap_or_default();
    let what = match why {
        Idle::Held => {
            "every participant is blocked on a held clock; advance or resume it, or have its \
             executive move it, from outside the simulation"
        }
        Idle::Process => {
            "every participant is blocked, waiting on a child process or on what one may write; \
             the clock moves with real time until it is done"
        }
        Idle::Leased => {
            "every participant is blocked while a lease holds the simulation busy; drop the busy \
             lease or setup scope"
        }
        Idle::Outside => {
            "every participant is blocked and nothing in the simulation can wake them. Still \
             polling in case something outside the simulation does"
        }
        Idle::HeldOff => {
            "every participant is blocked while threads of another sim that shares the \
             process's statics with this one run, and may yet wake one; time moves once they \
             park"
        }
    };
    eprintln!(
        "snare: deterministic scheduler has made no progress for {STALL_WARN:?}: {what}.\n{listing}"
    );
}

/// One line per participant and lease: its name and lineage, whether it runs or what it waits in
/// (with its deadline on the sim's clock), what it last waited in, and the leases it holds.
pub(crate) fn listing(rows: &[ParticipantInfo]) -> String {
    let mut out = String::new();
    for row in rows {
        let _ = match &row.state {
            PState::Running => write!(out, "  running  {} (thread {:#x})", row.name, row.id),
            PState::Blocked => write!(
                out,
                "  blocked  {} (thread {:#x}) in {}",
                row.name,
                row.id,
                row.wait.unwrap_or("an unlabelled wait")
            ),
            PState::Busy(label) if row.lease_kind == Some(LeaseKind::Setup) => {
                write!(out, "  setup    {label:?} held by {}", row.name)
            }
            PState::Busy(label) => write!(out, "  lease    {label:?} held by {}", row.name),
        };
        if let Some(deadline) = row.deadline {
            let _ = write!(out, " until {deadline:?}");
        }
        if !matches!(row.state, PState::Busy(_)) {
            if let Some(last) = row.last_wait {
                let _ = write!(out, ", last waited in {last}");
            }
            if !row.leases.is_empty() {
                let _ = write!(out, ", holding {:?}", row.leases);
            }
        }
        out.push('\n');
    }
    out
}

/// The thread that watches a domain for a busy stall, stopped when the domain drops.
#[derive(Default)]
pub(crate) struct Watchdog {
    /// Set when the domain drops; the thread returns at its next sample.
    stop: Mutex<bool>,
    /// Signalled with `stop`.
    stopped: Condvar,
}

impl Watchdog {
    /// Starts the watchdog for `domain`, failing the run once a participant has kept it busy for
    /// `after` of real time, and of the busy participants' CPU time, with no progress. The thread
    /// is spawned under passthrough, so the domain never adopts it, and holds only a weak
    /// reference between samples.
    pub(crate) fn start(domain: WeakDomain, after: Duration) -> Arc<Watchdog> {
        let watchdog = Arc::new(Watchdog::default());
        let watch = watchdog.clone();
        crate::domain::real(|| {
            std::thread::Builder::new()
                .name("snare-stuck-watchdog".into())
                .spawn(move || {
                    let _service = crate::census::service_thread();
                    watch.run(&domain, after);
                })
                .expect("start the stuck watchdog")
        });
        watchdog
    }

    /// Ends the thread.
    pub(crate) fn stop(&self) {
        *self.stop.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.stopped.notify_all();
    }

    /// Samples the domain every eighth of `after` (at least 1 ms, at most 250 ms, a snare choice
    /// that bounds both the overshoot past `after` and the cost of watching), keeping the real
    /// instant progress was last seen while the domain stays busy.
    fn run(&self, domain: &WeakDomain, after: Duration) {
        let tick = (after / 8).clamp(Duration::from_millis(1), Duration::from_millis(250));
        let mut last: Option<(Progress, Instant, Option<Duration>)> = None;
        loop {
            {
                let stop = self.stop.lock().unwrap_or_else(|e| e.into_inner());
                let stop = self
                    .stopped
                    .wait_timeout_while(stop, tick, |stop| !*stop)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
                if *stop {
                    return;
                }
            }
            let Some(domain) = domain.upgrade() else {
                return;
            };
            let progress = domain.progress();
            if progress.1.is_none() || domain.is_dormant() || !domain.busy_unleased() {
                last = None;
                continue;
            }
            let now = Instant::now();
            let cpu = domain.running_cpu_time();
            match last {
                Some((seen, since, cpu_since)) if seen == progress => {
                    let stalled = now - since;
                    let busy = match (cpu_since, cpu) {
                        (Some(from), Some(to)) => to.saturating_sub(from) >= after,
                        _ => true,
                    };
                    if stalled >= after && busy {
                        fail(&domain, stalled, after, Stall::Spinning);
                    }
                    if stalled >= off_cpu_limit(after) {
                        fail(&domain, stalled, after, Stall::OffCpu);
                    }
                }
                _ => last = Some((progress, now, cpu)),
            }
        }
    }
}

/// What a busy stall looks like from outside.
enum Stall {
    /// The running participants use CPU time.
    Spinning,
    /// They use none: blocked in calls snare does not hook.
    OffCpu,
}

/// Writes the busy-stall report to the process's standard error and aborts.
fn fail(domain: &Domain, stalled: Duration, after: Duration, stall: Stall) -> ! {
    let at = domain.progress().1.unwrap_or_default();
    let why = match stall {
        Stall::Spinning => {
            "A participant that makes no hooked call — spinning on an atomic, or computing — keeps \
             the simulation from going quiescent, so the discrete clock cannot move and nothing \
             waiting on it wakes. Make it block, sleep or yield, or hold `busy()` across work the \
             simulation cannot see."
        }
        Stall::OffCpu => {
            "The running participants used no CPU time meanwhile: one is blocked in a call snare \
             does not hook (a real pipe or file, `waitpid`, `sigwait`), which keeps the simulation \
             from going quiescent as a spin does. Make what it waits on happen, or hold `busy()` \
             across the call."
        }
    };
    let report = format!(
        "snare: stuck: the simulation made no progress for {stalled:?} of real time (stuck_after \
         {after:?}) while a participant kept it busy: virtual time stood at {at:?}, no participant \
         blocked or woke, and no lease was held. {why} Aborting: a stuck thread cannot be unwound \
         from outside.\n{}{}",
        domain
            .baton_holder()
            .map(|name| format!("  {name} holds the deterministic schedule's baton\n"))
            .unwrap_or_default(),
        listing(&domain.participants())
    );
    let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
    let reporter = crate::domain::real(|| {
        std::thread::Builder::new()
            .name("snare-stuck-report".into())
            .spawn(move || {
                let _service = crate::census::service_thread();
                let mut stderr = std::io::stderr().lock();
                let _ = stderr.write_all(report.as_bytes());
                let _ = stderr.flush();
                let _ = finished_tx.send(());
            })
    });
    if reporter.is_ok() {
        let _ = finished_rx.recv_timeout(Duration::from_secs(2));
    }
    std::process::abort();
}
