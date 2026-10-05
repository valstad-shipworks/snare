//! [`Executive`]: handing a sim's virtual clock to a simulation outside it in the same process.
//!
//! While attached, the clock is *driven* ([`Clock::attach_driven`]): it moves only along the
//! executive's [`Grant`]s, by its [`jump_to`](Executive::jump_to)s and timestamps, and by charged
//! call latency inside a granted horizon. Quiescence checks that gate a move are made under the
//! readiness lock ([`Readiness::locked`](crate::readiness::Readiness::locked)) and the domain's
//! accounting together, so no participant starts running between the check and the move.
//!
//! The executive's thread may itself be a sim thread, and its own clock reads must not be the
//! sim's: most clock calls here run under passthrough (`snare_interpose::real`), and the clock's
//! own real-time samples ([`real_now`](crate::readiness::real_now)) always do.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use snare_interpose::{Domain, ThreadClass};

use crate::clock::{self, Clock, nanos};
use crate::readiness::readiness;
use crate::scope::SimShared;

pub use snare_interpose::{
    AuditReport, BlockerKind, ClassEffect, PState, ParticipantInfo, Quiescence, QuiescenceViolation,
};

/// How an [`Executive`] runs.
#[derive(Clone, Debug, Default)]
pub struct ExecutiveConfig {
    /// Log the effects of background and helper threads, wakes from outside the sim and calls it
    /// cannot model, for [`Executive::audit`]. Also on when `SNARE_SCHED_AUDIT` is set to anything
    /// but empty or `0`.
    pub audit: bool,
}

/// A stretch of time an [`Executive`] lets the sim's clock run through on its own: from `anchor_v`
/// at the real instant `anchor_wall`, at `rate` virtual seconds per real second, never past
/// `horizon`.
#[derive(Copy, Clone, Debug)]
pub struct Grant {
    /// Sim time at `anchor_wall`; one behind the current time anchors at the current time.
    pub anchor_v: Duration,
    /// A real instant, read outside the sim (`snare::real(Instant::now)`).
    pub anchor_wall: Instant,
    /// In `[0, 1e6]`; NaN counts as 0. Under [`deterministic`](crate::SimBuilder::deterministic)
    /// a rate above 0 runs as 0, since nothing there may depend on real time.
    pub rate: f64,
    /// Sim time the clock holds at once it gets there; raised to `anchor_v` if below it.
    pub horizon: Duration,
}

/// Why an [`Executive`] could not attach.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AttachError {
    /// The sim already has one.
    AlreadyAttached,
    /// [`attach`] was called off a sim's thread.
    NotInSim,
    /// The sim runs on the real clock and has no clock to own.
    WallClock,
}

impl fmt::Display for AttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AttachError::AlreadyAttached => "this Sim's clock is already owned by an Executive",
            AttachError::NotInSim => "must be called from a thread running inside Sim::run",
            AttachError::WallClock => {
                "this Sim runs on the real clock (SimBuilder::wall_clock) and has no clock to own"
            }
        })
    }
}

impl std::error::Error for AttachError {}

/// A participant was running, a woken waiter or a timer due had yet to be taken, a lease was held
/// or a timestamp's wake was still deferred, so time did not move.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NotQuiescent;

impl fmt::Display for NotQuiescent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the simulation is not quiescent")
    }
}

impl std::error::Error for NotQuiescent {}

/// One pending timer: when, on the sim's clock, and the name of the thread waiting for it (`None`
/// for an event, such as a datagram arriving).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimerInfo {
    /// Sim time the timer falls due.
    pub deadline: Duration,
    /// The waiting thread's display name; `None` for an event or an anonymous waker.
    pub owner: Option<Arc<str>>,
}

/// Wakes a sim whose clock flows under a grant as its timers come due in real time. Its thread,
/// `snare-executive-flow`, starts with the first flowing grant and stops when the executive drops.
struct Flow {
    state: Mutex<FlowState>,
    /// Signalled when the grant changes or the flow stops, so the thread re-reads the line.
    changed: Condvar,
}

#[derive(Default)]
struct FlowState {
    /// The thread has been spawned.
    started: bool,
    /// The executive dropped: the thread returns, and none is started after.
    stop: bool,
}

/// How long the flow thread sleeps when no timer is ahead on the line, or at most before
/// re-reading it. A snare choice: a grant change signals the thread at once, so this only bounds
/// how late a timer registered meanwhile is noticed.
const FLOW_IDLE: Duration = Duration::from_millis(200);

impl Flow {
    /// Locks the flow's state, ignoring poison.
    fn lock(&self) -> std::sync::MutexGuard<'_, FlowState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Re-reads the line; starts the waker thread the first time a grant flows.
    fn changed(self: &Arc<Self>, flowing: bool, clock: &Arc<Clock>, shared: &Arc<SimShared>) {
        let start = {
            let mut st = self.lock();
            let start = flowing && !st.started && !st.stop;
            st.started |= start;
            start
        };
        self.changed.notify_all();
        if start {
            let (flow, clock, shared) = (self.clone(), clock.clone(), shared.clone());
            // Spawned under passthrough, so the sim does not adopt it as a managed thread.
            snare_interpose::real(|| {
                std::thread::Builder::new()
                    .name("snare-executive-flow".into())
                    .spawn(move || {
                        let _service = snare_interpose::service_thread();
                        flow.run(&clock, &shared);
                    })
                    .expect("start the executive's flow waker")
            });
        }
    }

    /// The flow thread's loop: sleeps until real time carries the line to its next timer, then
    /// delivers what is due and kicks the sim.
    fn run(&self, clock: &Clock, shared: &SimShared) {
        let mut st = self.lock();
        loop {
            if st.stop {
                return;
            }
            let wait = match clock.next_flow_wake() {
                None => FLOW_IDLE,
                Some(at) => {
                    let now = nanos(crate::readiness::real_now());
                    if at > now {
                        Duration::from_nanos(at - now).min(FLOW_IDLE)
                    } else {
                        drop(st);
                        let now = clock.peek();
                        let (_, wakers) = clock.fire_upto(now, now);
                        wakers.into_iter().for_each(std::task::Waker::wake);
                        shared.kick();
                        st = self.lock();
                        continue;
                    }
                }
            };
            st = self
                .changed
                .wait_timeout(st, wait)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// Ends the flow thread.
    fn stop(&self) {
        self.lock().stop = true;
        self.changed.notify_all();
    }
}

/// The owner of a [`Sim`](crate::Sim)'s virtual clock while it lives: an outside simulation that
/// moves the sim's time itself, in the same process. While it is attached nothing else moves time
/// — no time skip on quiescence, no deadlock give-up, and every clock control of the sim panics.
/// It lets time flow in [`grant`](Self::grant)s, [`jump_to`](Self::jump_to)s the clock between
/// timers once the sim is quiescent, and acts inside the sim at a time of its own with
/// [`enter_timestamp`](Self::enter_timestamp): what it does there reaches no participant until
/// [`leave_timestamp`](Self::leave_timestamp). Dropping it hands the clock back, at its current
/// reading.
pub struct Executive {
    shared: Arc<SimShared>,
    clock: Arc<Clock>,
    domain: Domain,
    cfg: ExecutiveConfig,
    flow: Arc<Flow>,
    /// The deterministic-sim rate warning has been printed once.
    warned_rate: AtomicBool,
}

/// Whether `SNARE_SCHED_AUDIT` asks for an audit: set, and neither empty nor `0`.
fn audit_env() -> bool {
    snare_interpose::real(|| std::env::var("SNARE_SCHED_AUDIT"))
        .is_ok_and(|v| !v.is_empty() && v != "0")
}

/// Attaches an executive to `shared`'s clock and `domain`. Claims `shared.executive` first, then
/// the domain, undoing the claim if the domain already has one; then takes the clock over and
/// delivers whatever was already due, so the first move starts from a clean table.
pub(crate) fn attach_to(
    shared: Arc<SimShared>,
    domain: Domain,
    cfg: ExecutiveConfig,
) -> Result<Executive, AttachError> {
    let Some(clock) = shared.clock.clone() else {
        return Err(AttachError::WallClock);
    };
    if shared.executive.swap(true, Ordering::AcqRel) {
        return Err(AttachError::AlreadyAttached);
    }
    if !domain.attach_executive(cfg.audit || audit_env()) {
        shared.executive.store(false, Ordering::Release);
        return Err(AttachError::AlreadyAttached);
    }
    let wakers = snare_interpose::real(|| {
        clock.attach_driven();
        let now = clock.peek();
        clock.fire_upto(now, now).1
    });
    wake(wakers);
    shared.kick();
    Ok(Executive {
        shared,
        clock,
        domain,
        cfg,
        flow: Arc::new(Flow {
            state: Mutex::default(),
            changed: Condvar::new(),
        }),
        warned_rate: AtomicBool::new(false),
    })
}

/// Attaches an [`Executive`] to the sim the calling thread runs in; see
/// [`Sim::executive`](crate::Sim::executive).
pub fn attach(cfg: ExecutiveConfig) -> Result<Executive, AttachError> {
    let shared = crate::scope::try_here().ok_or(AttachError::NotInSim)?;
    let domain = Domain::current().ok_or(AttachError::NotInSim)?;
    attach_to(shared, domain, cfg)
}

/// Wakes `wakers` the clock handed out, under passthrough and with no clock lock held.
fn wake(wakers: Vec<std::task::Waker>) {
    if !wakers.is_empty() {
        snare_interpose::real(|| wakers.into_iter().for_each(std::task::Waker::wake));
    }
}

/// Runs `f` with the calling driver thread reading `t` as the sim's time, through every clock it
/// reads — for a pool worker doing an executive's work at its current timestamp. Panics unless the
/// thread is its sim's driver ([`mark_driver_thread`](crate::sched::mark_driver_thread)).
#[track_caller]
pub fn with_driver_time<R>(t: Duration, f: impl FnOnce() -> R) -> R {
    assert_eq!(
        snare_interpose::thread_class(),
        Some(ThreadClass::Driver),
        "with_driver_time runs on a driver thread of a sim (sched::mark_driver_thread)"
    );
    let shared = crate::scope::here();
    let Some(sim_clock) = &shared.clock else {
        panic!("this Sim runs on the real clock (SimBuilder::wall_clock) and has no sim time");
    };
    struct Restore(Option<clock::DriverTime>);
    impl Drop for Restore {
        fn drop(&mut self) {
            clock::set_driver_time(self.0);
        }
    }
    let _restore = Restore(clock::set_driver_time(Some(
        sim_clock.driver_time_at(nanos(t)),
    )));
    f()
}

impl Executive {
    /// Sim time `t` as monotonic nanos on the clock; sim time is the monotonic reading.
    fn at(&self, t: Duration) -> u64 {
        nanos(t)
    }

    /// A monotonic reading as sim time: the inverse of [`at`](Self::at).
    fn sim_time(&self, monotonic: Duration) -> Duration {
        monotonic
    }

    /// The display name of the thread with lineage `owner`, or `"event"`.
    fn name(&self, owner: Option<u64>) -> Arc<str> {
        match owner {
            Some(lineage) => self.domain.display_name(lineage),
            None => snare_interpose::real(|| Arc::from("event")),
        }
    }

    /// The owner of a participant timer due and not yet taken, or of one before `before`.
    fn timer_blocker(&self, before: Option<u64>) -> Option<Arc<str>> {
        let due = self.clock.due().or_else(|| {
            let before = before?;
            let next = self.clock.next_deadline_after(self.clock.peek())?;
            (next < before).then(|| self.clock.owner_at(next))
        })?;
        Some(self.name(due))
    }

    /// Current sim time: what [`Sim::time_value`](crate::Sim::time_value) reads.
    pub fn now(&self) -> Duration {
        self.clock.value()
    }

    /// The configuration it was attached with.
    pub fn config(&self) -> &ExecutiveConfig {
        &self.cfg
    }

    /// Lets the clock run along the grant's line. An anchor behind the current time anchors the
    /// line at the current time and real instant instead, so time never goes back; timers the new
    /// line has already passed come due at once.
    pub fn grant(&self, g: Grant) {
        let mut rate = if g.rate.is_nan() {
            0.0
        } else {
            g.rate.clamp(0.0, clock::MAX_RATE)
        };
        if rate > 0.0 && self.clock.is_deterministic() {
            if !self.warned_rate.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "snare: a deterministic Sim cannot let its clock flow with real time; the \
                     executive's grant at rate {rate} runs at rate 0"
                );
            }
            rate = 0.0;
        }
        let anchor_real = nanos(snare_interpose::real(|| {
            g.anchor_wall
                .saturating_duration_since(crate::readiness::real_origin())
        }));
        let (before, after) = snare_interpose::real(|| {
            let before = self.clock.peek();
            self.clock
                .grant(self.at(g.anchor_v), anchor_real, rate, self.at(g.horizon));
            (before, self.clock.peek())
        });
        self.flow.changed(rate > 0.0, &self.clock, &self.shared);
        self.release_passed(before, after);
    }

    /// Delivers what the clock moved past from `before` to `after`, and wakes the sim to see it.
    /// Returns how many participant waits, events and wakers fell in `(before, after]`.
    fn release_passed(&self, before: u64, after: u64) -> u32 {
        if after <= before && self.clock.due().is_none() {
            return 0;
        }
        let (fired, wakers) = snare_interpose::real(|| self.clock.fire_upto(before, after));
        wake(wakers);
        self.shared.kick();
        fired
    }

    /// Holds the clock where it is: the horizon at the current time, rate 0.
    pub fn freeze(&self) {
        snare_interpose::real(|| self.clock.freeze());
        self.flow.changed(false, &self.clock, &self.shared);
    }

    /// The earliest participant timer after the current time, on the sim's clock.
    pub fn next_deadline(&self) -> Option<Duration> {
        let next = snare_interpose::real(|| self.clock.next_deadline_after(self.clock.peek()))?;
        Some(self.sim_time(Duration::from_nanos(next)))
    }

    /// Moves the clock to `t`, or to the earliest participant timer before it, if the sim is
    /// quiescent — checked in the same step as the move, so no participant starts running in
    /// between. It lands exactly on that timer, so one jump releases one timer group; returns how
    /// many participant waits, events and wakers were due there. The line re-anchors there at the
    /// grant's rate, its horizon raised to reach 1 ns past it if need be, so the clock holds there
    /// — but for that nanosecond, which only a charged call can cross — unless the grant flows on
    /// beyond. On `Err` nothing changed.
    ///
    /// Landing exactly on a deadline leaves a loop such as std's `Condvar::wait_timeout_while`
    /// re-waiting a zero timeout; that call's charged latency carries it past, so the horizon
    /// reaches 1 ns beyond the landing for such code.
    pub fn jump_to(&self, t: Duration) -> Result<u32, NotQuiescent> {
        let target = self.at(t);
        let (fired, wakers) = readiness()
            .locked(self.domain.key(), |settling| {
                self.domain.if_quiescent(
                    settling,
                    || self.timer_blocker(None),
                    false,
                    || {
                        let (before, landing) = self.clock.jump_driven(target, true, true);
                        self.clock.fire_upto(before, landing)
                    },
                )
            })
            .map_err(|_| NotQuiescent)?;
        wake(wakers);
        self.shared.kick();
        Ok(fired)
    }

    /// Starts acting inside the sim at time `t` on the calling thread, which becomes the sim's
    /// driver: it reads exactly `t` from every clock, and the code under test reads at least `t`.
    /// The clock itself moves to just before `t`, so timers at `t` are still pending. Participants
    /// woken from here on — by data the caller sends, or timers before `t` — wait until
    /// [`leave_timestamp`](Self::leave_timestamp). Under
    /// [`deterministic`](crate::SimBuilder::deterministic) it first waits for the schedule to go
    /// idle and then holds it. A participant still running when this is called can see what the
    /// caller does at `t` before the timestamp ends; [`enter_timestamp_checked`](Self::enter_timestamp_checked)
    /// rules that out.
    pub fn enter_timestamp(&self, t: Duration) {
        crate::sched::mark_driver_thread();
        self.domain.begin_timestamp();
        let target = self.at(t);
        snare_interpose::real(|| {
            self.clock.jump_driven(target.saturating_sub(1), false, false);
            self.clock.set_stamp(Some(target));
        });
        clock::set_driver_time(Some(self.clock.driver_time_at(target)));
    }

    /// [`enter_timestamp`](Self::enter_timestamp), only if the sim is quiescent and no participant
    /// timer falls before `t`, checked in the same step as the entry. On `Err` nothing changed but
    /// the calling thread becoming the driver.
    pub fn enter_timestamp_checked(&self, t: Duration) -> Result<(), NotQuiescent> {
        crate::sched::mark_driver_thread();
        let target = self.at(t);
        readiness()
            .locked(self.domain.key(), |settling| {
                self.domain.if_quiescent(
                    settling,
                    || self.timer_blocker(Some(target)),
                    true,
                    || {
                        self.clock.jump_driven(target.saturating_sub(1), false, false);
                        self.clock.set_stamp(Some(target));
                    },
                )
            })
            .map_err(|_| NotQuiescent)?;
        clock::set_driver_time(Some(self.clock.driver_time_at(target)));
        Ok(())
    }

    /// Ends the timestamp at `t`: the clock moves to `t` (and holds there, but for the nanosecond a
    /// zero-timeout wait can creep past it, unless a flowing grant reaches further), every timer due at `t` comes due, and the participants held since the
    /// timestamp began run — under
    /// [`deterministic`](crate::SimBuilder::deterministic) in the schedule's order, with what came
    /// due at `t` released before the schedule moves on. Returns how many participant waits,
    /// events and wakers fell between the clock's reading before the move (just before `t`, after
    /// [`enter_timestamp`](Self::enter_timestamp)) and `t`.
    ///
    /// Only waiters something reached are woken: with no timer, event or wait due and nothing done
    /// at the timestamp, a sim that was quiescent before it is quiescent right after.
    pub fn leave_timestamp(&self, t: Duration) -> u32 {
        clock::set_driver_time(None);
        let target = self.at(t);
        let (fired, wakers, reached) = snare_interpose::real(|| {
            let (before, _) = self.clock.jump_driven(target, false, true);
            let (fired, wakers) = self.clock.fire_upto(before, target);
            self.clock.set_stamp(None);
            (fired, wakers, self.clock.wait_reached())
        });
        let woke = !wakers.is_empty();
        wake(wakers);
        if fired > 0 || woke || reached {
            self.shared.kick();
        } else {
            self.domain.kick_due();
        }
        self.domain.end_timestamp();
        fired
    }

    /// Whether the sim is quiescent, and what holds it up if not, read under the same locks as
    /// [`jump_to`](Self::jump_to).
    pub fn quiescence(&self) -> Quiescence {
        let mut next = None;
        let mut q = readiness().locked(self.domain.key(), |settling| {
            self.domain.quiescence(settling, || {
                next = self.next_deadline();
                self.timer_blocker(None)
            })
        });
        q.next_deadline = if q.quiescent {
            next
        } else {
            self.next_deadline()
        };
        q
    }

    /// Calls `f` once the quiescence epoch moves past `seen_epoch` (at once if it already has):
    /// on the thread that moved it, with no lock of the sim held. Replaces an earlier arming.
    pub fn arm_notify(&self, seen_epoch: u64, f: Arc<dyn Fn() + Send + Sync>) {
        self.domain.arm(seen_epoch, f);
    }

    /// Every participant, then one row per lease.
    pub fn participants(&self) -> Vec<ParticipantInfo> {
        let mut rows = self.domain.participants();
        for row in &mut rows {
            row.deadline = row.deadline.map(|d| self.sim_time(d));
        }
        rows
    }

    /// The first `n` pending timers: the participants' in time order, then the other threads' in
    /// time order.
    pub fn timers(&self, n: usize) -> Vec<TimerInfo> {
        let pending = snare_interpose::real(|| self.clock.pending_timers(n));
        pending
            .into_iter()
            .map(|timer| TimerInfo {
                deadline: self.sim_time(Duration::from_nanos(timer.at)),
                owner: timer.owner.map(|lineage| self.domain.display_name(lineage)),
            })
            .collect()
    }

    /// The starvation hints raised since the last call (see
    /// [`hint_starving`](crate::sched::hint_starving)).
    pub fn drain_hints(&self) -> Vec<(Arc<str>, f32)> {
        self.domain.take_hints()
    }

    /// The leases holding the sim busy, oldest first, each with its kind and the name of the
    /// thread that took it.
    pub fn held_leases(&self) -> Vec<crate::sched::LeaseInfo> {
        self.domain.leases()
    }

    /// How many times a participant was woken from a native wait (a futex, a condition variable,
    /// a semaphore) by something outside the sim since this executive attached: every
    /// participant was blocked and nothing the sim sees happened before the wake. Counted with or
    /// without [`audit`](ExecutiveConfig::audit), which adds the details; a run whose reactions
    /// must all come from the sim asserts it stays zero.
    pub fn outside_wakes(&self) -> u64 {
        self.domain.outside_wakes()
    }

    /// The id of the sim this executive owns.
    pub fn sim_id(&self) -> crate::sched::SimId {
        self.domain.id()
    }

    /// Every OS thread of the process, this sim's told apart from other sims' and from unmanaged
    /// ones; see [`thread_census`](crate::sched::thread_census).
    pub fn thread_census(&self) -> Option<crate::sched::ThreadCensus> {
        snare_interpose::census(Some(&self.domain))
    }

    /// What the audit has seen since this executive attached; empty without audit.
    pub fn audit(&self) -> AuditReport {
        let mut report = self.domain.audit();
        for effect in &mut report.class_effects {
            effect.at = self.sim_time(effect.at);
        }
        for violation in &mut report.violations {
            violation.at = self.sim_time(violation.at);
        }
        report
    }

    /// Hands the clock back; the same as dropping the executive.
    pub fn detach(self) {}
}

impl Drop for Executive {
    /// Stops the flow thread, hands the clock back at its reading (or an open timestamp's, if
    /// later), releases the domain and kicks the sim so its waits re-check on the base clock.
    fn drop(&mut self) {
        self.flow.stop();
        snare_interpose::real(|| self.clock.detach_driven());
        self.domain.detach_executive();
        self.shared.executive.store(false, Ordering::Release);
        self.shared.kick();
    }
}

impl fmt::Debug for Executive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Executive")
            .field("now", &self.now())
            .field("cfg", &self.cfg)
            .finish()
    }
}
