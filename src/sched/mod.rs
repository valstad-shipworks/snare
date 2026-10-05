//! Scheduler hooks for driving snare's virtual clock from an outside
//! simulation executive.
//!
//! With the `shim` feature on, every state slot owns one lock-free virtual
//! clock and one timer heap. The clock runs in one of two modes:
//!
//! - **Scaled** (the default): virtual time follows wall time times a rate,
//!   controlled with the legacy [`set_time_rate`](crate::set_time_rate) family.
//! - **Driven**: a [`Driver`] (from [`attach_driver`]) owns the clock and hands
//!   it [`Grant`]s — a flow line plus a horizon the clock never passes. The
//!   legacy controls are ignored with a warning while a driver is attached.
//!
//! Timers ([`Sleep`], [`park`] with a deadline, [`crate::thread::sleep`]) live
//! in a per-slot heap fired by one `snare-sched-timer` thread in
//! `(deadline, seq)` order as the clock reaches them.
//!
//! Under an accounting driver, snare also tracks *participants*: the threads
//! whose progress matters to the simulation. A participant is running unless
//! it is blocked in a snare wait ([`park`], [`block_on`], [`Sleep`],
//! [`crate::thread::sleep`]). The domain is *quiescent* when no participant
//! is running, no [`BusyLease`] is held, no wake is deferred and no timer is
//! due; only then can the driver jump the clock ([`Driver::jump_to`]).
//! Threads join by spawn handoff ([`crate::thread::spawn`] registers the
//! child before it starts), by their first blocking snare call, by waking a
//! participant, or explicitly with [`participate`]. Threads marked
//! [`mark_background`] or [`mark_helper`] never join; their snare effects
//! are recorded as [`ClassEffect`]s instead. Code that must choose between a
//! snare wait and a wall wait asks [`is_driven`].
//!
//! Without `shim` every item still exists: [`park`], [`block_on`] and [`Sleep`]
//! run on wall time, the participation calls are no-ops, and
//! [`attach_driver`] returns [`AttachError::ShimDisabled`].

#[cfg(feature = "shim")]
mod audit;
mod block_on;
#[cfg(feature = "shim")]
pub(crate) mod clock;
#[cfg(feature = "shim")]
mod driver;
mod lease;
mod park;
#[cfg(feature = "shim")]
pub(crate) mod participant;
#[cfg(feature = "shim")]
mod slot;
#[cfg(not(feature = "shim"))]
mod stub;
#[doc(hidden)]
#[cfg(feature = "shim")]
pub mod testkit;
pub(crate) mod timer;
#[cfg(feature = "shim")]
pub(crate) mod waitset;
mod wakerset;

use std::cell::Cell;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use timer::ParkCell;

pub use block_on::{Sleep, block_on, block_on_timeout, block_on_until, sleep_until};
pub use lease::{BusyLease, busy, hint_starving};
pub use park::{Unparker, current_unparker, park};
pub use wakerset::WakerSet;

#[cfg(not(feature = "shim"))]
pub use stub::{Driver, attach_driver};
#[cfg(not(feature = "shim"))]
use stub::{Source, timers};

#[cfg(feature = "shim")]
pub(crate) use audit::{audit_env, fatal_violation, note_effect, strict};
#[cfg(feature = "shim")]
pub use driver::{Driver, attach_driver};
#[cfg(all(feature = "shim", feature = "ctrlc-compat"))]
pub(crate) use park::park_as;
#[cfg(all(feature = "shim", feature = "fast-talker-core"))]
pub(crate) use park::{own_unparker, park_background_leased};
#[cfg(feature = "shim")]
pub(crate) use park::{park_thread, thread_token};
#[cfg(feature = "shim")]
pub(crate) use participant::class_effect;
#[cfg(feature = "shim")]
pub(crate) use participant::handoff;
#[cfg(feature = "shim")]
use slot::timers;
#[cfg(feature = "shim")]
pub(crate) use slot::{
    SchedSlot, instant_ns, invalidate_slot_cache, mono_now, sleep_for, sleep_until_virtual, slot,
    try_slot, wall_now, wall_of, warn_driven, with_slot,
};
#[cfg(all(feature = "shim", feature = "fast-talker-core"))]
pub(crate) use slot::{cached_mono_now, driver_time, instant_of_wall};

#[cfg(feature = "shim")]
#[doc(hidden)]
pub use waitset::set_wait_hook;

#[cfg(feature = "shim")]
pub(crate) type Source = clock::Clock;

/// Wall-clock time of virtual [`DRIVEN_ORIGIN`] under a driver, as time
/// since the Unix epoch: 2026-01-01T00:00:00Z. Attaching a driver pins the
/// virtual `SystemTime` here so driven runs never inherit the host's clock.
pub const DRIVEN_WALL_EPOCH: Duration = Duration::from_secs(1_767_225_600);

/// Where [`attach_driver`] puts the virtual clock when it attaches before
/// this value. A clock already past it moves forward to the next whole
/// second instead, since virtual time never goes backwards.
pub const DRIVEN_ORIGIN: Duration = Duration::from_secs(1);

/// Configuration for [`attach_driver`].
#[derive(Clone, Debug, Default)]
pub struct DriverConfig {
    /// Seed for snare's network RNG (loss, jitter, reorder).
    pub seed: u64,
    /// Track participants for quiescence detection.
    pub accounting: bool,
    /// Record snare-visible effects by blocked or unknown threads.
    pub audit: bool,
}

/// A flow line for a driven clock: virtual time starts at `anchor_v` at wall
/// time `anchor_wall` and advances at `rate`, but never past `horizon`.
#[derive(Copy, Clone, Debug)]
pub struct Grant {
    pub anchor_v: Duration,
    pub anchor_wall: std::time::Instant,
    pub rate: f64,
    pub horizon: Duration,
}

/// Why [`attach_driver`] refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AttachError {
    /// This state slot already has a driver.
    AlreadyAttached,
    /// The calling thread has no state slot: build with `--cfg snare_global`
    /// or call [`register_test`](crate::register_test) first.
    NotGlobal,
    /// snare was built without the `shim` feature.
    ShimDisabled,
}

impl fmt::Display for AttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AttachError::AlreadyAttached => "a snare sched driver is already attached",
            AttachError::NotGlobal => {
                "no snare state slot for this thread (needs --cfg snare_global or register_test)"
            }
            AttachError::ShimDisabled => "snare was built without the `shim` feature",
        })
    }
}

impl std::error::Error for AttachError {}

/// Returned by a jump that found the domain no longer quiescent.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NotQuiescent;

/// How [`park`] returned.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ParkResult {
    Unparked,
    TimedOut,
}

/// A participant's state as the driver sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PState {
    /// Running or runnable: blocks quiescence.
    Running,
    /// Parked in a snare wait.
    Blocked,
    /// A busy lease with this label.
    Busy(&'static str),
}

/// What keeps the domain from being quiescent.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum BlockerKind {
    /// A participant is running.
    Runnable,
    /// A thread registered by waking a participant is running.
    Stray,
    /// A busy lease is held.
    Lease,
    /// Wakes from the current timestamp have not been delivered yet.
    Deferred,
    /// A timer is due and has not fired yet.
    TimerDue,
    /// The driver was attached without accounting.
    Untracked,
}

/// The quiescence predicate and its inputs, read atomically.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Quiescence {
    pub quiescent: bool,
    /// Bumped on every change to participant, lease or deferred-wake state.
    pub epoch: u64,
    pub runnable: u32,
    pub busy: u32,
    pub blocked: u32,
    pub next_deadline: Option<Duration>,
    /// Why the domain is not quiescent, with a name for display.
    pub blocker: Option<(BlockerKind, Arc<str>)>,
}

/// One row of [`Driver::participants`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParticipantInfo {
    pub id: u64,
    pub name: Arc<str>,
    pub state: PState,
    /// Registered because it woke a participant without being one.
    pub stray: bool,
    /// Virtual time spent in the current state.
    pub since_virtual: Duration,
    /// Wall time spent in the current state.
    pub since_wall: Duration,
    /// Virtual deadline of the current wait, if any.
    pub deadline: Option<Duration>,
    /// What the participant is blocked in, e.g. `"park"`, `"sleep"`, `"block_on"`.
    pub wait: Option<&'static str>,
    /// The wait it most recently woke from.
    pub last_wait: Option<&'static str>,
    /// Labels of the busy leases taken on this participant's thread and
    /// still held.
    pub leases: Vec<&'static str>,
}

/// One row of [`Driver::timers`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimerInfo {
    pub deadline: Duration,
    /// The participant the timer wakes, if it wakes a parked participant.
    pub owner: Option<Arc<str>>,
}

/// A snare-visible effect by a thread that should not have been able to
/// cause one: a blocked participant, or an unknown thread with no lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuiescenceViolation {
    pub thread: Arc<str>,
    pub op: &'static str,
    /// The thread was a participant marked blocked (otherwise unknown).
    pub blocked: bool,
    /// The operation was refused because it would escape the sim, such as
    /// a hostname lookup through the host's resolver; the caller got an
    /// error instead.
    pub fatal: bool,
    /// Virtual time of the effect.
    pub at: Duration,
}

/// Returned by [`Driver::audit`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditReport {
    /// Unknown threads registered because they woke a participant.
    pub stray_wakes: u64,
    /// Names of those threads, each once.
    pub strays: Vec<Arc<str>>,
    /// The most recent violations (audit mode only).
    pub violations: Vec<QuiescenceViolation>,
    /// Violations recorded in total, including ones no longer kept.
    pub total_violations: u64,
    /// The most recent snare effects made by background and helper threads
    /// outside a [`setup_scope`].
    pub class_effects: Vec<ClassEffect>,
    /// Class effects recorded in total, including ones no longer kept.
    pub total_class_effects: u64,
    /// Effects made by classified threads inside a [`setup_scope`].
    pub total_setup_effects: u64,
    /// Every thread a [`thread_census`] found unaccounted for, in host id
    /// order.
    pub unknown_threads: Vec<UnknownThread>,
}

/// An OS thread of the process that snare could not account for: not
/// registered, not matched by a [`classify_background_by_name`] rule, and
/// not a system thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownThread {
    /// The host's id for the thread (`pthread_threadid_np`, `gettid`,
    /// `GetCurrentThreadId`).
    pub host_tid: u64,
    pub name: Option<Arc<str>>,
    /// The thread had exited by the last census.
    pub exited: bool,
}

/// How a [`thread_census`] accounted for one OS thread.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HostThreadKind {
    /// In snare's thread registry, with its class. `Unclassified` is a
    /// thread snare spawned or saw that is neither marked nor a participant
    /// right now.
    Known(ThreadClass),
    /// Created by the OS for its own use rather than by the process. On
    /// macOS these are libdispatch's workqueue threads: the kernel creates
    /// them (they announce their own creation to the pthread introspection
    /// hook, where a `pthread_create` thread is announced by its creator,
    /// and until the kernel first sends one to user space it has no pthread
    /// at all) and they run only dispatch blocks, such as a Metal completion
    /// handler. Nothing else counts as system.
    System,
    /// Not accounted for. Two censuses in a row make it an
    /// [`UnknownThread`].
    Unregistered,
}

/// One OS thread as a [`thread_census`] saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CensusThread {
    pub host_tid: u64,
    pub name: Option<Arc<str>>,
    pub kind: HostThreadKind,
}

/// Returned by [`thread_census`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadCensus {
    /// Every live OS thread of the process.
    pub threads: Vec<CensusThread>,
    /// Every unknown thread found by this and earlier censuses of the state
    /// slot, in host id order.
    pub unknown: Vec<UnknownThread>,
    /// Every thread start since the process loaded was observed, so threads
    /// that lived and died between censuses are covered too. Only macOS
    /// tracks starts.
    pub creation_tracked: bool,
}

/// Hold every OS thread of the process against the calling thread's state
/// slot's thread registry. Meaningful when one state slot covers the process
/// (`--cfg snare_global`); under [`register_test`](crate::register_test)
/// the other tests' threads are unknown to this slot.
///
/// Threads register by being spawned through [`crate::thread`], by marking
/// their class ([`mark_background`], [`mark_helper`],
/// [`mark_driver_thread`]) or by becoming participants. A live thread that
/// two consecutive censuses find unregistered is recorded as unknown, as is
/// a thread that started and exited unregistered (where starts are
/// tracked); the record is kept for the slot's life and read by
/// [`unknown_threads`] and [`Driver::audit`]. Space censuses apart (a
/// sampler period): two back to back can catch a thread in the moment
/// between its start and its registration. `None` without a state slot, without `shim`, or where
/// the platform cannot list threads (it can on macOS, Linux and Windows).
pub fn thread_census() -> Option<ThreadCensus> {
    #[cfg(feature = "shim")]
    return crate::census::run();
    #[cfg(not(feature = "shim"))]
    None
}

/// Every thread the censuses of the calling thread's state slot have found
/// unaccounted for, without running a new census. Empty without `shim`.
pub fn unknown_threads() -> Vec<UnknownThread> {
    #[cfg(feature = "shim")]
    return crate::sched::try_slot()
        .map(|_| crate::census::unknown())
        .unwrap_or_default();
    #[cfg(not(feature = "shim"))]
    Vec::new()
}

/// Account for threads the process cannot run code on (a third-party
/// runtime's workers with no start hook) as background, by name: from now
/// on a census adopts every unregistered live thread whose name `matches`
/// into the registry as background. A last resort; a thread that can call
/// [`mark_background`] should.
pub fn classify_background_by_name(matches: fn(&str) -> bool) {
    #[cfg(feature = "shim")]
    crate::census::add_name_rule(matches);
    #[cfg(not(feature = "shim"))]
    let _ = matches;
}

/// How snare treats a thread under an accounting [`Driver`].
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ThreadClass {
    /// A registered participant: counts toward quiescence.
    Participant,
    /// Telemetry, logging and other work outside the simulation (see
    /// [`mark_background`]). Never registered; its snare effects are
    /// recorded as [`ClassEffect`]s.
    Background,
    /// A compute-pool worker that only runs while a participant waits on it
    /// (see [`mark_helper`]). Never registered; its snare effects are
    /// recorded as [`ClassEffect`]s.
    Helper,
    /// The executive and its pools (see [`mark_driver_thread`]).
    Driver,
    /// Not registered and not classified: its first blocking snare call
    /// registers it.
    Unclassified,
}

/// A snare-visible effect by a background or helper thread: waking a
/// participant, entering a snare wait, a socket send or receive, or taking a
/// [`BusyLease`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassEffect {
    pub thread: Arc<str>,
    pub class: ThreadClass,
    pub op: &'static str,
    /// Virtual time of the effect.
    pub at: Duration,
}

/// Held while the current thread counts as a scheduler participant. Not
/// `Send`: participation belongs to the thread that asked for it.
#[must_use = "the thread stops participating when the guard is dropped"]
pub struct ParticipantGuard {
    #[cfg(feature = "shim")]
    pid: u64,
    _thread: PhantomData<*const ()>,
}

impl fmt::Debug for ParticipantGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParticipantGuard").finish_non_exhaustive()
    }
}

impl Drop for ParticipantGuard {
    fn drop(&mut self) {
        #[cfg(feature = "shim")]
        if self.pid != 0 {
            participant::leave(self.pid);
        }
    }
}

/// Register the current thread as a scheduler participant named `name`
/// (renaming it if it already is one). A no-op unless an accounting
/// [`Driver`] owns the thread's clock.
pub fn participate(name: &str) -> ParticipantGuard {
    #[cfg(feature = "shim")]
    let pid = participant::participate(name);
    #[cfg(not(feature = "shim"))]
    let _ = name;
    ParticipantGuard {
        #[cfg(feature = "shim")]
        pid,
        _thread: PhantomData,
    }
}

/// Whether the calling thread is currently a registered scheduler
/// participant. Never registers it. Always `false` without `shim`.
pub fn is_participant() -> bool {
    #[cfg(feature = "shim")]
    return participant::is_participant();
    #[cfg(not(feature = "shim"))]
    false
}

/// Whether a wait on the calling thread should be snare-visible, with its
/// deadline on the virtual clock: `shim` is on, an accounting [`Driver`] owns
/// the thread's clock, and the thread is not background, helper or
/// driver-class. Unlike [`is_participant`], an unclassified thread that has
/// not blocked yet counts, since its first snare wait registers it.
pub fn is_driven() -> bool {
    #[cfg(feature = "shim")]
    {
        if is_driver_thread() || classified().is_some() {
            return false;
        }
        participant::accounting_here()
    }
    #[cfg(not(feature = "shim"))]
    false
}

/// Mark the calling thread as background (telemetry, logging, reporting):
/// it is never a participant, so it never holds up quiescence, and each
/// snare effect it makes is recorded as a [`ClassEffect`]. `label` names it
/// in those records. Ends any current participation.
pub fn mark_background(label: &'static str) {
    set_class(CLASS_BACKGROUND, Some(label));
}

/// Mark the calling thread as a helper: a compute-pool worker that runs only
/// while a participant waits on it synchronously. Never a participant; its
/// snare effects are recorded as [`ClassEffect`]s.
pub fn mark_helper() {
    set_class(CLASS_HELPER, None);
}

/// The calling thread's class.
pub fn thread_class() -> ThreadClass {
    if is_driver_thread() {
        return ThreadClass::Driver;
    }
    match classified() {
        Some(c) => c,
        None if is_participant() => ThreadClass::Participant,
        None => ThreadClass::Unclassified,
    }
}

fn set_class(class: u8, label: Option<&'static str>) {
    let _ = CLASS.try_with(|c| c.set(class));
    let _ = CLASS_LABEL.try_with(|c| c.set(label));
    #[cfg(feature = "shim")]
    {
        participant::leave_current();
        if let Some(c) = classified() {
            crate::threads::note_class(c);
        }
    }
}

/// `Background` or `Helper` if the calling thread was marked as one.
pub(crate) fn classified() -> Option<ThreadClass> {
    match CLASS.try_with(Cell::get).unwrap_or(0) {
        CLASS_BACKGROUND => Some(ThreadClass::Background),
        CLASS_HELPER => Some(ThreadClass::Helper),
        _ => None,
    }
}

#[cfg_attr(not(feature = "shim"), allow(dead_code))]
pub(crate) fn class_label() -> Option<&'static str> {
    CLASS_LABEL.try_with(Cell::get).ok().flatten()
}

#[cfg_attr(not(feature = "shim"), allow(dead_code))]
pub(crate) fn in_setup() -> bool {
    SETUP_DEPTH.try_with(Cell::get).unwrap_or(0) > 0
}

/// Held while the calling thread wires up the simulation: time cannot move
/// (it holds a busy lease labelled `setup:<label>`), and the snare effects
/// the thread makes are counted as setup effects rather than class effects.
/// Not `Send`.
#[must_use = "setup ends when the guard is dropped"]
pub struct SetupScope {
    lease: Option<BusyLease>,
    _thread: PhantomData<*const ()>,
}

impl fmt::Debug for SetupScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetupScope")
            .field("lease", &self.lease)
            .finish()
    }
}

impl Drop for SetupScope {
    fn drop(&mut self) {
        if self.lease.take().is_some() {
            let _ = SETUP_DEPTH.try_with(|c| c.set(c.get().saturating_sub(1)));
        }
    }
}

/// Start the calling thread's setup phase. An unclassified thread is marked
/// background (see [`mark_background`]) with `label`; then a busy lease
/// labelled `setup:<label>` is taken and held until the guard drops, so the
/// driver cannot move time while the simulation is being wired up. Effects
/// the thread makes meanwhile count into
/// [`AuditReport::total_setup_effects`]. A no-op guard without `shim`.
pub fn setup_scope(label: &'static str) -> SetupScope {
    #[cfg(feature = "shim")]
    {
        if thread_class() == ThreadClass::Unclassified {
            mark_background(label);
        }
        let _ = SETUP_DEPTH.try_with(|c| c.set(c.get() + 1));
        SetupScope {
            lease: Some(busy(setup_label(label))),
            _thread: PhantomData,
        }
    }
    #[cfg(not(feature = "shim"))]
    {
        let _ = label;
        SetupScope {
            lease: None,
            _thread: PhantomData,
        }
    }
}

#[cfg(feature = "shim")]
fn setup_label(label: &'static str) -> &'static str {
    use std::collections::HashMap;
    use std::sync::LazyLock;
    static LABELS: LazyLock<parking_lot::Mutex<HashMap<&'static str, &'static str>>> =
        LazyLock::new(Default::default);
    LABELS
        .lock()
        .entry(label)
        .or_insert_with(|| Box::leak(format!("setup:{label}").into_boxed_str()))
}

/// Every busy lease held in the calling thread's state slot: its label, and
/// the name of the participant whose thread took it (`None` when the holder
/// is not a participant, e.g. a background thread or one that has exited).
pub fn held_leases() -> Vec<(&'static str, Option<Arc<str>>)> {
    #[cfg(feature = "shim")]
    return slot::try_slot()
        .map(|s| s.reg().held_leases())
        .unwrap_or_default();
    #[cfg(not(feature = "shim"))]
    Vec::new()
}

/// Mark the calling thread as a driver-class thread (the executive, its
/// worker pool): it is never a participant, and it may wake participants
/// without being counted as a stray.
pub fn mark_driver_thread() {
    set_driver_thread();
    #[cfg(feature = "shim")]
    participant::leave_current();
}

/// Run `f` with the calling thread reading exactly `t` from every snare
/// clock and its wakes deferred until the driver's next
/// [`Driver::leave_timestamp`]. For executive worker threads running part of
/// a timestamp the driver thread entered. Without `shim`, just runs `f`.
pub fn with_driver_time<R>(t: Duration, f: impl FnOnce() -> R) -> R {
    #[cfg(feature = "shim")]
    {
        struct Restore(Option<u64>, Option<Arc<participant::Registry>>);
        impl Drop for Restore {
            fn drop(&mut self) {
                slot::set_driver_time(self.0.take());
                participant::set_defer(self.1.take());
            }
        }
        let reg = slot::try_slot().map(|s| Arc::clone(s.reg()));
        let _restore = Restore(
            slot::set_driver_time(Some(slot::duration_ns(t))),
            participant::set_defer(reg),
        );
        f()
    }
    #[cfg(not(feature = "shim"))]
    {
        let _ = t;
        f()
    }
}

thread_local! {
    static PARK_CELL: Arc<ParkCell> = Arc::new(ParkCell::default());
    static LOCKS: Cell<u64> = const { Cell::new(0) };
    static DRIVER_THREAD: Cell<bool> = const { Cell::new(false) };
    static CLASS: Cell<u8> = const { Cell::new(0) };
    static CLASS_LABEL: Cell<Option<&'static str>> = const { Cell::new(None) };
    static SETUP_DEPTH: Cell<u32> = const { Cell::new(0) };
}

const CLASS_BACKGROUND: u8 = 1;
const CLASS_HELPER: u8 = 2;

fn park_cell() -> Arc<ParkCell> {
    PARK_CELL
        .try_with(Arc::clone)
        .unwrap_or_else(|_| Arc::new(ParkCell::default()))
}

pub(crate) fn set_driver_thread() {
    let _ = DRIVER_THREAD.try_with(|c| c.set(true));
    #[cfg(feature = "shim")]
    crate::threads::note_class(ThreadClass::Driver);
}

/// Run `f` with the calling thread counted as a driver-class thread.
#[cfg(feature = "shim")]
pub(crate) fn as_driver<R>(f: impl FnOnce() -> R) -> R {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = DRIVER_THREAD.try_with(|c| c.set(self.0));
        }
    }
    let _restore = Restore(DRIVER_THREAD.try_with(|c| c.replace(true)).unwrap_or(false));
    f()
}

#[cfg_attr(not(feature = "shim"), allow(dead_code))]
pub(crate) fn is_driver_thread() -> bool {
    DRIVER_THREAD.try_with(Cell::get).unwrap_or(false)
}

#[inline]
pub(crate) fn note_lock() {
    #[cfg(debug_assertions)]
    let _ = LOCKS.try_with(|c| c.set(c.get() + 1));
}

/// Number of snare-internal lock acquisitions made by the calling thread.
/// `None` in release builds, where the counter is compiled out.
#[doc(hidden)]
pub fn debug_lock_count() -> Option<u64> {
    if cfg!(debug_assertions) {
        LOCKS.try_with(Cell::get).ok()
    } else {
        None
    }
}

/// Number of pending entries in the current slot's timer heap.
pub fn pending_timers() -> usize {
    timers().pending()
}
