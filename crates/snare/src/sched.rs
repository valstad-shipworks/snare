//! What each thread of a [`Sim`](crate::Sim) is to the simulation, and what holds it busy.
//!
//! Every thread created inside [`Sim::run`](crate::Sim::run) is simulated: its sockets, clock,
//! files and environment are the sim's. By default it is also a *participant*: virtual time skips
//! only once every participant is blocked, a blocked wait gives up only when they all are, and a
//! [`deterministic`](crate::SimBuilder::deterministic) sim runs participants one at a time.
//!
//! A thread the test does not wait on — a sampler, a log pump, a server left running, a UI — can
//! step out of that with [`mark_background`] or [`mark_helper`]: it stays simulated but never holds
//! up quiescence, never runs in the deterministic schedule, and its sleeps and timeouts are satisfied
//! as the clock passes them rather than steering where it skips, unless every participant waits on
//! what only such a thread can do (a join on a sampler told to stop). [`mark_driver_thread`] goes
//! further for the thread that drives the sim: its clock reads and sleeps are real.
//!
//! [`busy`] and [`setup_scope`] hold time still explicitly, for work the sim cannot see.
//!
//! An [`Executive`] hands the sim's clock to a simulation outside it, in the same process: it
//! grants time, jumps between timers once the sim is quiescent and acts at timestamps of its own.

use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use snare_interpose::{ClockKind, Domain, LeaseId};

use crate::clock::Clock;
use crate::readiness::Deadline;
use crate::scope::SimShared;

pub use snare_interpose::{
    CensusThread, LeaseInfo, LeaseKind, SimId, ThreadCensus, ThreadClass, ThreadOwner,
};

pub use crate::executive::{
    AttachError, AuditReport, BlockerKind, ClassEffect, Executive, ExecutiveConfig, Grant,
    NotQuiescent, PState, ParticipantInfo, Quiescence, QuiescenceViolation, TimerInfo, attach,
    with_driver_time,
};

/// The calling thread's class: [`ThreadClass::Participant`] unless something re-classed it, on any
/// thread. [`is_participant`] also checks that the thread runs in a sim.
pub fn thread_class() -> ThreadClass {
    snare_interpose::recorded_thread_class().0
}

/// Whether the calling thread runs in a sim, in any class: it was created inside
/// [`Sim::run`](crate::Sim::run) or entered one, and has not left. Code that may run either way —
/// a library shared between a sim and a real deployment — can ask this before reaching for the
/// sim's controls; [`busy`] and [`setup_scope`] need not ask, since they do nothing off a sim.
pub fn in_sim() -> bool {
    Domain::current().is_some()
}

/// The sim the calling thread runs in, `None` off a sim. Two threads with the same id run in the
/// same sim; a [`thread_census`] names other sims' threads by it.
pub fn current_sim() -> Option<SimId> {
    Domain::current().map(|domain| domain.id())
}

/// Lists every OS thread of the process with whose it is: the calling thread's sim's (with its
/// class), another sim's, one of snare's own service threads, or no sim's at all. Off a sim every
/// managed thread is another sim's. `None` where the OS's threads cannot be listed.
///
/// A thread counts as a sim's from the moment it is managed — created inside the run, or entering
/// it — until it leaves; one just being created, or exiting, may read as unmanaged for that moment,
/// and on Linux a thread just joined can still be listed, unmanaged, until the kernel has released
/// it (`pthread_join` returns once the kernel clears the thread's id, man 2 set_tid_address).
/// Threads are listed from `/proc/self/task` on Linux (man 5 proc_pid_task), `task_threads` on
/// macOS (XNU osfmk mach/task.defs) and a Toolhelp thread snapshot on Windows
/// ([Microsoft Learn: Traversing the thread list](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)).
pub fn thread_census() -> Option<ThreadCensus> {
    snare_interpose::census(Domain::current().as_ref())
}

/// Whether the calling thread runs in a sim as a participant.
pub fn is_participant() -> bool {
    snare_interpose::thread_class() == Some(ThreadClass::Participant)
}

/// Whether the calling thread's waits are driven by its sim: it is a participant and the sim's
/// clock is virtual — discrete, paused, scaled to real time or owned by an [`Executive`] — so its
/// sleeps and timeouts pass as the sim moves time. `false` off a sim, on a thread of another
/// class, and on a clock that runs on real time or as fast as possible.
pub fn is_driven() -> bool {
    is_participant() && snare_interpose::virtual_now().is_some()
}

/// Makes the calling thread a background thread of its sim: simulated, but never holding up
/// quiescence or the deterministic schedule, its timers steering a time skip only once every
/// participant waits on what only such a thread can do. `label` says what it is. Does nothing off a sim.
pub fn mark_background(label: &'static str) {
    snare_interpose::set_thread_class(ThreadClass::Background, Some(label));
}

/// Makes the calling thread a helper of its sim: treated as a background thread, for one that
/// serves the simulation's machinery rather than the code under test. Does nothing off a sim.
pub fn mark_helper() {
    snare_interpose::set_thread_class(ThreadClass::Helper, None);
}

/// Makes the calling thread its sim's driver: treated as a background thread, except that its clock
/// reads and sleeps are real. Its sockets, files and environment stay simulated. Does nothing off a
/// sim.
pub fn mark_driver_thread() {
    snare_interpose::set_thread_class(ThreadClass::Driver, None);
}

/// Returned by [`participate`]: the thread is a participant until it drops.
#[must_use]
pub struct ParticipantGuard {
    /// The class and label to restore; `None` off a sim, where the guard does nothing.
    previous: Option<(ThreadClass, Option<&'static str>)>,
    /// The thread's name before [`participate`] renamed it.
    name: Option<Arc<str>>,
    _not_send: PhantomData<*const ()>,
}

/// Makes the calling thread a participant of its sim, listed as `name`, until the guard drops; it
/// then returns to its previous class and name. Under a deterministic schedule it waits here for its
/// turn; called from a thread of another class, that turn comes at a point that depends on real
/// time, so the run replays only if the participants wait for this thread. Does nothing off a sim.
pub fn participate(name: &str) -> ParticipantGuard {
    let previous = snare_interpose::set_thread_class(ThreadClass::Participant, None);
    let name = previous
        .is_some()
        .then(|| snare_interpose::set_thread_name(Some(name)))
        .flatten();
    ParticipantGuard {
        previous,
        name,
        _not_send: PhantomData,
    }
}

impl Drop for ParticipantGuard {
    fn drop(&mut self) {
        if let Some((class, label)) = self.previous {
            snare_interpose::set_thread_name(self.name.as_deref());
            snare_interpose::set_thread_class(class, label);
        }
    }
}

impl fmt::Debug for ParticipantGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParticipantGuard")
            .field("previous", &self.previous)
            .field("name", &self.name)
            .finish()
    }
}

/// Returned by [`spawn_as`]: threads the caller creates start in its class until it drops.
#[must_use]
pub struct SpawnClassGuard {
    /// The child class in force before, restored on drop so guards nest.
    previous: Option<(ThreadClass, &'static str)>,
    _not_send: PhantomData<*const ()>,
}

/// Every thread the caller creates while the guard lives starts in `class`, labelled `label`;
/// threads created after it drops are participants again. For a thread pool or library that spawns
/// its own threads, which cannot mark themselves.
pub fn spawn_as(class: ThreadClass, label: &'static str) -> SpawnClassGuard {
    SpawnClassGuard {
        previous: snare_interpose::set_child_class(Some((class, label))),
        _not_send: PhantomData,
    }
}

impl Drop for SpawnClassGuard {
    fn drop(&mut self) {
        snare_interpose::set_child_class(self.previous);
    }
}

impl fmt::Debug for SpawnClassGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpawnClassGuard")
            .field("previous", &self.previous)
            .finish()
    }
}

/// Holds its sim busy until dropped: virtual time does not skip and no blocked wait gives up, as if
/// a participant were running. `Send`, so work done elsewhere can carry it and drop it when done.
/// One taken off a sim is inert: it holds nothing.
#[must_use]
pub struct BusyLease {
    /// The sim held busy, with the lease's label and kind; `None` for an inert lease.
    held: Option<(Domain, &'static str, LeaseKind)>,
    /// Taken on drop, so the lease is released exactly once.
    lease: Option<LeaseId>,
}

impl BusyLease {
    /// Takes a [`LeaseKind::Busy`] lease labelled `label` on `domain`.
    pub(crate) fn take(domain: Domain, label: &'static str) -> Self {
        Self::take_of(Some(domain), label, LeaseKind::Busy)
    }

    /// Takes a lease of `kind` labelled `label` on `domain`; inert with no domain.
    fn take_of(domain: Option<Domain>, label: &'static str, kind: LeaseKind) -> Self {
        let lease = domain
            .as_ref()
            .map(|domain| domain.take_lease_of(label, kind));
        BusyLease {
            held: domain.map(|domain| (domain, label, kind)),
            lease,
        }
    }

    /// Whether the lease holds a sim busy: `false` for one taken off a sim.
    pub fn is_held(&self) -> bool {
        self.lease.is_some()
    }

    /// The lease's label.
    pub fn label(&self) -> Option<&'static str> {
        self.held.as_ref().map(|&(_, label, _)| label)
    }

    /// What kind of lease it is; `None` for an inert one.
    pub fn kind(&self) -> Option<LeaseKind> {
        self.held.as_ref().map(|&(_, _, kind)| kind)
    }
}

impl Drop for BusyLease {
    fn drop(&mut self) {
        if let (Some(lease), Some((domain, _, _))) = (self.lease.take(), &self.held) {
            domain.release_lease(lease);
        }
    }
}

impl fmt::Debug for BusyLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BusyLease")
            .field("label", &self.label())
            .field("kind", &self.kind())
            .field("sim", &self.held.as_ref().map(|(domain, _, _)| domain.id()))
            .finish()
    }
}

/// Holds the calling thread's sim busy until the lease drops; see [`BusyLease`]. Off a sim it
/// returns an inert lease, so code shared with a real deployment can call it unconditionally.
pub fn busy(label: &'static str) -> BusyLease {
    snare_interpose::note_effect("busy");
    BusyLease::take_of(Domain::current(), label, LeaseKind::Busy)
}

/// Returned by [`setup_scope`]: the sim is held busy until it drops.
#[must_use]
pub struct SetupScope {
    lease: BusyLease,
    _not_send: PhantomData<*const ()>,
}

impl Drop for SetupScope {
    fn drop(&mut self) {
        snare_interpose::set_in_setup(false);
    }
}

impl fmt::Debug for SetupScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetupScope")
            .field("lease", &self.lease)
            .finish()
    }
}

/// Holds time still while the calling thread sets the sim up — starting servers, spawning workers
/// that have yet to reach their first wait — so no time passes before the run proper begins. A
/// [`LeaseKind::Setup`] lease, like [`busy`] otherwise, tied to the calling thread: listed as
/// setup, so whatever watches the sim can tell a long setup from a stuck run. Off a sim it holds
/// nothing.
pub fn setup_scope(label: &'static str) -> SetupScope {
    snare_interpose::set_in_setup(true);
    snare_interpose::note_effect("busy");
    SetupScope {
        lease: BusyLease::take_of(Domain::current(), label, LeaseKind::Setup),
        _not_send: PhantomData,
    }
}

/// Notes that `source` is starved — of time, of input — with `severity`, for whatever drives the
/// sim to act on. Does nothing off a sim.
pub fn hint_starving(source: &str, severity: f32) {
    if let Some(domain) = Domain::current() {
        domain.push_hint(source, severity);
    }
}

/// The leases holding the calling thread's sim busy, oldest first, each with its kind and the name
/// of the thread that took it (`None` for one taken from outside the sim). Empty off a sim.
pub fn held_leases() -> Vec<LeaseInfo> {
    Domain::current().map_or_else(Vec::new, |domain| domain.leases())
}

/// The calling thread's name in its sim: the name it gave itself (std's `Builder::name`,
/// `pthread_setname_np` (man 3 pthread_setname_np), or
/// [`SetThreadDescription`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreaddescription))
/// or [`participate`] gave it. `None` off a sim and for a thread never named.
pub fn thread_name() -> Option<Arc<str>> {
    snare_interpose::thread_name()
}

/// The calling thread's sim's time (see [`Sim::time_value`](crate::Sim::time_value)), read without
/// ticking it, whatever the thread's class: the time a driver thread sees the simulation at, or
/// its driver time inside [`with_driver_time`]. Off a sim, and on a sim with no virtual clock,
/// real monotonic time since snare's process-wide origin, fixed the first time anything asks.
pub fn now() -> Duration {
    crate::scope::try_here()
        .and_then(|shared| {
            let clock = shared.clock.as_ref()?;
            Some(clock.driver_value().unwrap_or_else(|| clock.value()))
        })
        .unwrap_or_else(crate::readiness::real_now)
}

/// How [`park`] returned.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ParkResult {
    /// The thread's [`Unparker`] fired (now or before the call).
    Unparked,
    /// The deadline passed first.
    TimedOut,
}

/// A thread's park token, and the sim it last parked in, so a wake from any thread reaches that
/// sim's waits.
struct ParkCell {
    /// Set by an unpark, consumed by the park that sees it.
    token: AtomicBool,
    /// The owning thread, for a real `unpark` when it parks off a sim or past a sim give-up.
    thread: std::thread::Thread,
    /// Weak, so a parked thread's cell never keeps a finished sim alive.
    sim: Mutex<Weak<SimShared>>,
}

impl ParkCell {
    /// Sets the token and wakes the thread, both its real park and its sim wait. On the clock's
    /// waker thread ([`in_clock_wake`](crate::clock::in_clock_wake)) the kick is left to the
    /// clock's caller, which wakes the sim's waiters once the wakers have run and may meanwhile
    /// hold locks a kick would take.
    fn unpark(&self) {
        self.token.store(true, Ordering::Release);
        self.thread.unpark();
        if crate::clock::in_clock_wake() {
            return;
        }
        let sim =
            snare_interpose::real(|| self.sim.lock().unwrap_or_else(|e| e.into_inner()).upgrade());
        if let Some(sim) = sim {
            sim.kick();
        }
    }
}

impl Wake for ParkCell {
    fn wake(self: Arc<Self>) {
        self.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.unpark();
    }
}

thread_local! {
    static PARK_CELL: Arc<ParkCell> = Arc::new(ParkCell {
        token: AtomicBool::new(false),
        thread: std::thread::current(),
        sim: Mutex::new(Weak::new()),
    });
}

/// The calling thread's park cell, noting the sim it runs in.
fn park_cell() -> Arc<ParkCell> {
    let cell = PARK_CELL.with(Arc::clone);
    if let Some(sim) = crate::scope::try_here() {
        snare_interpose::real(|| {
            *cell.sim.lock().unwrap_or_else(|e| e.into_inner()) = Arc::downgrade(&sim);
        });
    }
    cell
}

/// Wakes a thread blocked in [`park`] or [`block_on`], from any thread, inside or outside its sim.
/// A wake before the thread parks is kept, and ends its next park at once.
#[derive(Clone)]
pub struct Unparker(Arc<ParkCell>);

impl Unparker {
    /// Wakes the thread, or makes its next park return at once.
    pub fn unpark(&self) {
        self.0.unpark();
    }

    /// A waker that unparks the thread.
    pub fn waker(&self) -> Waker {
        Waker::from(self.0.clone())
    }
}

impl fmt::Debug for Unparker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unparker").finish_non_exhaustive()
    }
}

/// The calling thread's [`Unparker`].
pub fn current_unparker() -> Unparker {
    Unparker(park_cell())
}

/// Blocks the calling thread until its [`Unparker`] fires or `deadline` passes. An unpark that
/// came before the call is consumed and returns at once.
///
/// In a sim the deadline is on the sim's clock, as the thread reads `Instant`s, and the park is a
/// sim wait: it counts toward quiescence, a virtual deadline is a timer a time skip lands on, and
/// a wake during an [`Executive`]'s timestamp lets the thread go only once the timestamp ends. A
/// participant parked with no deadline while nothing in the sim can move it keeps waiting, as a
/// join does, for a thread of another class to unpark it. Off a sim it is real time.
pub fn park(deadline: Option<Instant>) -> ParkResult {
    park_as("park", deadline)
}

/// [`park`], with the wait labelled `label` for diagnostics. In a sim a wait that gives up with
/// no deadline (every participant blocked) falls back to a real `std::thread::park`, so only an
/// unpark ends it, as a join's would.
fn park_as(label: &'static str, deadline: Option<Instant>) -> ParkResult {
    let cell = park_cell();
    let in_sim = snare_interpose::thread_class().is_some();
    loop {
        if cell.token.swap(false, Ordering::AcqRel) {
            return ParkResult::Unparked;
        }
        let left = match deadline {
            Some(deadline) => match deadline.checked_duration_since(Instant::now()) {
                Some(left) if !left.is_zero() => Some(left),
                _ => return ParkResult::TimedOut,
            },
            None => None,
        };
        if !in_sim {
            match left {
                Some(left) => std::thread::park_timeout(left),
                None => std::thread::park(),
            }
            continue;
        }
        let woken = snare_interpose::real(|| {
            crate::readiness::readiness().wait_until(label, left.map(Deadline::timeout), || {
                cell.token.load(Ordering::Acquire)
            })
        });
        if !woken && left.is_none() {
            let _label = snare_interpose::wait_label(label);
            std::thread::park();
        }
    }
}

/// Runs `f` to completion on the calling thread, [`park`]ing between polls; the waker is the
/// thread's [`Unparker`].
pub fn block_on<F: Future>(f: F) -> F::Output {
    match block_on_until(f, None) {
        Some(output) => output,
        None => unreachable!("a block_on with no deadline ends only when its future does"),
    }
}

/// [`block_on`], giving up at `deadline` (`None` for none), read as the calling thread reads
/// `Instant`s: on the sim's clock in a sim. Once the deadline passes `f` is polled once more, so
/// an output ready at the deadline is not lost.
pub fn block_on_until<F: Future>(f: F, deadline: Option<Instant>) -> Option<F::Output> {
    let waker = Waker::from(park_cell());
    let mut cx = Context::from_waker(&waker);
    let mut f = pin!(f);
    loop {
        if let Poll::Ready(output) = f.as_mut().poll(&mut cx) {
            return Some(output);
        }
        if park_as("block_on", deadline) == ParkResult::TimedOut {
            return match f.as_mut().poll(&mut cx) {
                Poll::Ready(output) => Some(output),
                Poll::Pending => None,
            };
        }
    }
}

/// [`block_on_until`] `timeout` from now; a timeout past the end of the clock means no deadline.
pub fn block_on_timeout<F: Future>(f: F, timeout: Duration) -> Option<F::Output> {
    block_on_until(f, Instant::now().checked_add(timeout))
}

/// The clock the calling thread's `Instant`s read: its sim's, with the reading now, or `None` for
/// real time — off a sim, on a sim with no virtual clock, and on a driver thread outside an
/// executive's timestamp.
fn instant_clock() -> Option<(Arc<Clock>, u64)> {
    let clock = crate::scope::try_here()?.clock.clone()?;
    if snare_interpose::thread_class() == Some(ThreadClass::Driver)
        && snare_interpose::real(|| clock.driver_time()).is_none()
    {
        return None;
    }
    let now = snare_interpose::now(ClockKind::Monotonic)?;
    Some((clock, crate::clock::nanos(now)))
}

/// A future that completes once the clock reaches its deadline; see [`sleep_until`]. Dropping it
/// drops its timer.
pub struct Sleep {
    /// The deadline as the creating thread's `Instant`s read it.
    deadline: Instant,
    /// The deadline on `clock`'s monotonic nanos, or on [`real_now`](crate::readiness::real_now).
    at: u64,
    /// The sim clock `at` is on; `None` for real time.
    clock: Option<Arc<Clock>>,
    /// The registered wake's key and waker, while one is registered.
    wake: Option<(u64, Waker)>,
}

/// A [`Sleep`] that completes at `deadline`, read as the calling thread reads `Instant`s: in a sim,
/// on its clock, so it completes as a time skip, an executive's jump or grant, or a scaled clock
/// reaches the deadline. On real time otherwise — which a driver thread outside an executive's
/// timestamp is on: it should time its waits with real-time timers, or under
/// [`with_driver_time`].
pub fn sleep_until(deadline: Instant) -> Sleep {
    snare_interpose::end_spin();
    let (clock, now) = match instant_clock() {
        Some((clock, now)) => (Some(clock), now),
        None => (None, crate::clock::nanos(crate::readiness::real_now())),
    };
    let now_instant = Instant::now();
    let at = match deadline.checked_duration_since(now_instant) {
        Some(ahead) => now.saturating_add(crate::clock::nanos(ahead)),
        None => now.saturating_sub(crate::clock::nanos(now_instant - deadline)),
    };
    Sleep {
        deadline,
        at,
        clock,
        wake: None,
    }
}

impl Sleep {
    /// Whether its clock has reached the deadline.
    pub fn is_elapsed(&self) -> bool {
        self.reading() >= self.at
    }

    /// Its clock's reading now, as `at` is measured: a driver's timestamp time if it has one, else
    /// the code under test's monotonic reading; real time with no clock.
    fn reading(&self) -> u64 {
        match &self.clock {
            Some(clock) => {
                snare_interpose::real(|| clock.driver_time().unwrap_or_else(|| clock.monotonic()))
            }
            None => crate::clock::nanos(crate::readiness::real_now()),
        }
    }

    /// Whether the calling thread reads `Instant`s on this sleep's clock.
    fn on_my_clock(&self) -> bool {
        match (instant_clock(), &self.clock) {
            (Some((here, _)), Some(clock)) => Arc::ptr_eq(&here, clock),
            (None, None) => true,
            _ => false,
        }
    }

    /// Whether the sleep is over. A clock that reached `at` while the calling thread's `Instant`
    /// still reads short of the deadline (the two round differently) moves `at` on by the rest.
    fn finished(&mut self) -> bool {
        if !self.is_elapsed() {
            return false;
        }
        if self.on_my_clock()
            && let Some(rest) = self.deadline.checked_duration_since(Instant::now())
            && !rest.is_zero()
        {
            self.at = self.reading().saturating_add(crate::clock::nanos(rest));
            self.cancel();
            return false;
        }
        self.cancel();
        true
    }

    /// Registers `waker` for `at`: on the real-time waker with no clock; through the calling
    /// thread's layer when the clock is its own sim's, so the timer is filed as its class says;
    /// directly as a foreign timer from another sim's thread or from outside. A clock that will
    /// not hold a wake (running as fast as possible) is jumped to `at` instead.
    fn register(&mut self, waker: &Waker) {
        let Some(clock) = &self.clock else {
            let id = crate::clock::wake_id();
            crate::readiness::schedule_wake(Duration::from_nanos(self.at), id, waker.clone());
            self.wake = Some((id, waker.clone()));
            return;
        };
        let at = Duration::from_nanos(self.at);
        let here = crate::scope::try_here()
            .and_then(|shared| shared.clock.clone())
            .is_some_and(|c| Arc::ptr_eq(&c, clock));
        let id = if here {
            snare_interpose::register_wake(at, waker.clone())
        } else {
            snare_interpose::real(|| clock.register_wake(self.at, waker.clone(), true))
        };
        match id {
            Some(id) => self.wake = Some((id, waker.clone())),
            None => snare_interpose::real(|| clock.expire(at)),
        }
    }

    /// Drops the registered wake, if any.
    fn cancel(&mut self) {
        let Some((id, _)) = self.wake.take() else {
            return;
        };
        match &self.clock {
            Some(clock) => snare_interpose::real(|| clock.cancel_wake(id)),
            None => crate::readiness::cancel_wake(id),
        }
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.finished() {
            return Poll::Ready(());
        }
        if !this
            .wake
            .as_ref()
            .is_some_and(|(_, waker)| waker.will_wake(cx.waker()))
        {
            this.cancel();
            snare_interpose::note_effect("sleep");
            this.register(cx.waker());
        }
        if this.finished() {
            return Poll::Ready(());
        }
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl fmt::Debug for Sleep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sleep")
            .field("deadline", &self.deadline)
            .field("registered", &self.wake.is_some())
            .finish()
    }
}

/// The wakers of every task waiting on one piece of state, for futures that wait on it from
/// several places at once.
///
/// A waiting `poll` [`register`](Self::register)s its waker before it checks the state, and returns
/// `Pending` only if the check still fails; the side that changes the state does so first, then
/// calls [`wake_all`](Self::wake_all). Either the check sees the change or the waker is in place
/// when `wake_all` runs, so no wake is lost.
#[derive(Default)]
pub struct WakerSet {
    wakers: Mutex<Vec<Waker>>,
}

impl WakerSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `waker`, replacing one that wakes the same task.
    pub fn register(&self, waker: &Waker) {
        snare_interpose::real(|| {
            let mut wakers = self.wakers.lock().unwrap_or_else(|e| e.into_inner());
            match wakers.iter_mut().find(|w| w.will_wake(waker)) {
                Some(w) => w.clone_from(waker),
                None => wakers.push(waker.clone()),
            }
        });
    }

    /// Takes every registered waker and wakes it.
    pub fn wake_all(&self) {
        let wakers = snare_interpose::real(|| {
            std::mem::take(&mut *self.wakers.lock().unwrap_or_else(|e| e.into_inner()))
        });
        wakers.into_iter().for_each(Waker::wake);
    }
}

impl fmt::Debug for WakerSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let waiting =
            snare_interpose::real(|| self.wakers.lock().unwrap_or_else(|e| e.into_inner()).len());
        f.debug_struct("WakerSet")
            .field("waiting", &waiting)
            .finish()
    }
}
