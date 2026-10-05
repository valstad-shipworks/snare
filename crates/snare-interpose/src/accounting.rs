//! Who counts toward a domain's quiescence, and what holds it busy.
//!
//! Every managed thread has a [`ThreadClass`]. Only participants count toward quiescence and run in
//! a deterministic schedule; the other classes are still simulated but never hold up the domain.
//! Leases hold a domain non-quiescent explicitly, and the epoch lets an observer learn, without
//! polling, that any of this changed.
//!
//! Per-thread facts (class, wait label, setup depth) live in const-initialized thread-locals with
//! no destructor, which a hook can read without allocating and which stay readable during thread
//! teardown; should one be unreachable, it reads as its default. Per-domain facts live in [`Accounting`], whose locks are taken in this order: the
//! skip gate, then the census ([`Core`]) or the lease table; the census before a deterministic
//! schedule's own lock. The remaining mutexes (the armed callback, hints, names, handles) are leaves
//! never held while another is taken. Every lock is taken under passthrough, so blocking on one is
//! never itself counted as a wait, and an [`EpochBump`] runs its callback only after its creator
//! has let go of its locks. Windows timer publication takes the census before the timer-signal
//! leaf during native admission; that leaf is released before scheduler or timestamp-gate waits.

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::state::Passthrough;

/// How a managed thread takes part in its domain.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ThreadClass {
    /// Runs the code under test: it counts toward quiescence, so time skips only once it blocks,
    /// and it runs in a deterministic schedule.
    Participant,
    /// Simulated like a participant, but never holds up quiescence or the deterministic schedule,
    /// and its timers steer a time skip only once every participant waits on what only such a
    /// thread can do: a sampler, a log pump, a server the test leaves running.
    Background,
    /// As [`Background`](ThreadClass::Background), for a thread that serves the sim's machinery
    /// rather than the code under test.
    Helper,
    /// As [`Background`](ThreadClass::Background), and its clock reads and sleeps are real: the
    /// thread that drives the simulation from inside it.
    Driver,
}

thread_local! {
    /// The calling thread's class; a thread no domain ever classed is a participant.
    static CLASS: Cell<ThreadClass> = const { Cell::new(ThreadClass::Participant) };
    /// The name the class was given with, for an executive's listing.
    static LABEL: Cell<Option<&'static str>> = const { Cell::new(None) };
    /// The class and label this thread's next children start in; `None` makes them participants.
    static CHILD_CLASS: Cell<Option<(ThreadClass, &'static str)>> = const { Cell::new(None) };
    /// What the thread is blocked in, set by the innermost live [`WaitLabel`].
    static WAIT_LABEL: Cell<Option<&'static str>> = const { Cell::new(None) };
    /// The address of the native wait object the thread is blocked on, if any.
    static WAIT_KEY: Cell<Option<usize>> = const { Cell::new(None) };
    #[cfg(windows)]
    static TIMER_ADMISSION: Cell<bool> = const { Cell::new(false) };
    #[cfg(windows)]
    static TIMER_CONSUMED: Cell<Option<usize>> = const { Cell::new(None) };
    #[cfg(target_os = "linux")]
    static WAIT_MASK: Cell<u32> = const { Cell::new(u32::MAX) };
    #[cfg(target_os = "linux")]
    static WAIT_EXPECTED: Cell<Option<u32>> = const { Cell::new(None) };
    #[cfg(target_os = "linux")]
    static WAIT_FUTEX_PRIVATE: Cell<Option<bool>> = const { Cell::new(None) };
    /// The pthread mutex the thread's wait returns holding, if any.
    static WAIT_MUTEX: Cell<Option<usize>> = const { Cell::new(None) };
    /// The deadline [`note_wait_deadline`] left for the next wait to take.
    static WAIT_DEADLINE: Cell<Option<Duration>> = const { Cell::new(None) };
    /// How many [`set_in_setup`] scopes the thread is inside.
    static SETUP_DEPTH: Cell<u32> = const { Cell::new(0) };
    /// The lineage of the thread this one is about to join, for its wait's row.
    static JOIN_TARGET: Cell<Option<u64>> = const { Cell::new(None) };
    /// Whether the thread is counted in its domain's `Core::gated`.
    static GATED: Cell<bool> = const { Cell::new(false) };
}

#[cfg(windows)]
pub(crate) struct TimerAdmission {
    previous: (bool, Option<usize>),
}

#[cfg(windows)]
impl TimerAdmission {
    pub(crate) fn enter() -> Self {
        Self {
            previous: (
                TIMER_ADMISSION.with(|value| value.replace(true)),
                TIMER_CONSUMED.with(Cell::take),
            ),
        }
    }

    pub(crate) fn consumed(&self) -> Option<usize> {
        TIMER_CONSUMED.with(Cell::take)
    }
}

#[cfg(windows)]
impl Drop for TimerAdmission {
    fn drop(&mut self) {
        TIMER_ADMISSION.with(|value| value.set(self.previous.0));
        TIMER_CONSUMED.with(|value| value.set(self.previous.1));
    }
}

#[cfg(windows)]
pub(crate) fn timer_admitting() -> bool {
    TIMER_ADMISSION.with(Cell::get)
}

#[cfg(windows)]
pub(crate) fn timer_consumed(key: usize) {
    TIMER_CONSUMED.with(|value| value.set(Some(key)));
}

/// Records whether the calling thread is counted in its domain's `Core::gated`, returning whether
/// it was.
pub(crate) fn swap_gated(gated: bool) -> bool {
    GATED.try_with(|g| g.replace(gated)).unwrap_or(false)
}

/// Notes which thread (by lineage) the calling thread is about to join; the next wait takes it.
pub(crate) fn set_join_target(target: Option<u64>) {
    let _ = JOIN_TARGET.try_with(|t| t.set(target));
}

/// Takes the join target [`set_join_target`] left, clearing it.
pub(crate) fn take_join_target() -> Option<u64> {
    JOIN_TARGET.try_with(Cell::take).unwrap_or(None)
}

/// Notes the deadline, on the domain's monotonic clock, of the wait the calling thread is about to
/// block in, for its row in an executive's listing. The next wait to begin takes it.
pub fn note_wait_deadline(deadline: Option<Duration>) {
    let _ = WAIT_DEADLINE.try_with(|d| d.set(deadline));
}

/// Takes the deadline [`note_wait_deadline`] left, clearing it.
pub(crate) fn take_wait_deadline() -> Option<Duration> {
    WAIT_DEADLINE.try_with(Cell::take).unwrap_or(None)
}

/// Counts the calling thread into (`true`) or out of a setup phase, whose effects an executive's
/// audit counts apart from the run proper.
pub fn set_in_setup(entering: bool) {
    let _ = SETUP_DEPTH.try_with(|d| {
        d.set(if entering {
            d.get().saturating_add(1)
        } else {
            d.get().saturating_sub(1)
        })
    });
}

/// Whether the calling thread is inside at least one setup scope.
fn in_setup() -> bool {
    SETUP_DEPTH.try_with(Cell::get).unwrap_or(0) > 0
}

/// The calling thread's class as recorded, managed or not.
pub(crate) fn class() -> ThreadClass {
    CLASS
        .try_with(Cell::get)
        .unwrap_or(ThreadClass::Participant)
}

/// The label the calling thread's class was given with, if any.
pub(crate) fn label() -> Option<&'static str> {
    LABEL.try_with(Cell::get).unwrap_or(None)
}

/// Records the calling thread's class, returning what it was.
pub(crate) fn swap_class(
    class: ThreadClass,
    label: Option<&'static str>,
) -> (ThreadClass, Option<&'static str>) {
    let class = CLASS
        .try_with(|c| c.replace(class))
        .unwrap_or(ThreadClass::Participant);
    let label = LABEL.try_with(|l| l.replace(label)).unwrap_or(None);
    (class, label)
}

/// Whether the calling thread is a participant, the default.
pub(crate) fn participant() -> bool {
    class() == ThreadClass::Participant
}

/// The class the calling thread's next children start in, `None` for participants; returns the
/// previous setting.
pub fn set_child_class(
    class: Option<(ThreadClass, &'static str)>,
) -> Option<(ThreadClass, &'static str)> {
    CHILD_CLASS.try_with(|c| c.replace(class)).unwrap_or(None)
}

/// The class and label a thread the calling thread creates starts in.
pub(crate) fn child_class() -> (ThreadClass, Option<&'static str>) {
    match CHILD_CLASS.try_with(Cell::get).unwrap_or(None) {
        Some((class, label)) => (class, Some(label)),
        None => (ThreadClass::Participant, None),
    }
}

/// Names what the calling thread is about to block in until the guard drops.
#[must_use]
///
/// Guards nest: each restores on drop what it replaced, so they must drop in reverse order.
pub struct WaitLabel {
    /// The label in force before this guard.
    previous: Option<&'static str>,
    /// The wait-object address in force before this guard.
    previous_key: Option<usize>,
    /// The awaited mutex in force before this guard.
    previous_mutex: Option<usize>,
}

/// Labels the calling thread's wait (`"tcp recv"`, `"futex"`) for diagnostics until the guard
/// drops. Never allocates, so it is safe inside a hook.
pub fn wait_label(label: &'static str) -> WaitLabel {
    wait_label_keyed(label, None, None)
}

/// As [`wait_label`], for a native wait on the object at address `key` (a futex word, a
/// semaphore), so a wake there counts the waiter as released before it runs again.
pub(crate) fn wait_label_on(label: &'static str, key: usize) -> WaitLabel {
    wait_label_keyed(label, Some(key), None)
}

/// As [`wait_label`], for a native wait that returns holding the pthread mutex at `mutex`: a
/// contended lock (`key` `None`), or a condition variable's wait on `key`. Such a waiter can only
/// run once that mutex is free, however the OS woke it.
#[cfg(any(unix, windows))]
pub(crate) fn wait_label_mutex(label: &'static str, key: Option<usize>, mutex: usize) -> WaitLabel {
    wait_label_keyed(label, key, Some(mutex))
}

/// Installs all three wait facts at once, returning the guard that restores the old ones.
fn wait_label_keyed(label: &'static str, key: Option<usize>, mutex: Option<usize>) -> WaitLabel {
    let previous = WAIT_LABEL
        .try_with(|l| l.replace(Some(label)))
        .unwrap_or(None);
    let previous_key = WAIT_KEY.try_with(|k| k.replace(key)).unwrap_or(None);
    let previous_mutex = WAIT_MUTEX.try_with(|m| m.replace(mutex)).unwrap_or(None);
    WaitLabel {
        previous,
        previous_key,
        previous_mutex,
    }
}

impl std::fmt::Debug for WaitLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WaitLabel")
            .field("previous", &self.previous)
            .finish_non_exhaustive()
    }
}

impl Drop for WaitLabel {
    fn drop(&mut self) {
        let _ = WAIT_LABEL.try_with(|l| l.set(self.previous));
        let _ = WAIT_KEY.try_with(|k| k.set(self.previous_key));
        let _ = WAIT_MUTEX.try_with(|m| m.set(self.previous_mutex));
    }
}

/// The address of the native wait object the calling thread is about to block on, if labelled.
pub(crate) fn current_wait_key() -> Option<usize> {
    WAIT_KEY.try_with(Cell::get).unwrap_or(None)
}

#[cfg(target_os = "linux")]
pub(crate) struct WaitMask(u32, Option<u32>, Option<bool>);

#[cfg(target_os = "linux")]
pub(crate) fn wait_mask(mask: u32, expected: u32, private: bool) -> WaitMask {
    WaitMask(
        WAIT_MASK
            .try_with(|current| current.replace(mask))
            .unwrap_or(u32::MAX),
        WAIT_EXPECTED
            .try_with(|current| current.replace(Some(expected)))
            .unwrap_or(None),
        WAIT_FUTEX_PRIVATE
            .try_with(|current| current.replace(Some(private)))
            .unwrap_or(None),
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn wait_mask_value() -> u32 {
    WAIT_MASK.try_with(Cell::get).unwrap_or(u32::MAX)
}

#[cfg(target_os = "linux")]
pub(crate) fn wait_expected_value() -> Option<u32> {
    WAIT_EXPECTED.try_with(Cell::get).unwrap_or(None)
}

pub(crate) fn wait_futex_private() -> Option<bool> {
    #[cfg(target_os = "linux")]
    return WAIT_FUTEX_PRIVATE.try_with(Cell::get).unwrap_or(None);
    #[cfg(not(target_os = "linux"))]
    None
}

#[cfg(target_os = "linux")]
impl Drop for WaitMask {
    fn drop(&mut self) {
        let _ = WAIT_MASK.try_with(|mask| mask.set(self.0));
        let _ = WAIT_EXPECTED.try_with(|expected| expected.set(self.1));
        let _ = WAIT_FUTEX_PRIVATE.try_with(|private| private.set(self.2));
    }
}

/// The pthread mutex the calling thread's labelled wait returns holding, if any.
pub(crate) fn current_wait_mutex() -> Option<usize> {
    WAIT_MUTEX.try_with(Cell::get).unwrap_or(None)
}

/// What the calling thread is blocked in, as its innermost [`wait_label`] names it.
pub fn current_wait_label() -> Option<&'static str> {
    WAIT_LABEL.try_with(Cell::get).unwrap_or(None)
}

/// A lease taken with [`Domain::take_lease`](crate::Domain::take_lease), to give back once.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct LeaseId(pub(crate) u64);

/// What a lease holds its domain busy for.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum LeaseKind {
    /// Work the sim cannot see, such as a computation another thread runs for a participant: held
    /// for as long as one reaction takes.
    Busy,
    /// Setting the sim up: servers starting, workers that have yet to reach their first wait. Held
    /// for as long as setup takes, which may be far longer than a reaction without anything being
    /// stuck.
    Setup,
}

/// A held lease, as a domain lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseInfo {
    /// Why it is held.
    pub label: &'static str,
    /// What it holds the domain busy for.
    pub kind: LeaseKind,
    /// The name of the thread that took it; `None` for one taken from outside the domain.
    pub holder: Option<Arc<str>>,
}

/// One held lease.
struct Lease {
    /// Why it is held, for diagnostics.
    label: &'static str,
    kind: LeaseKind,
    /// The lineage of the domain thread that took it; `None` when taken from outside the domain.
    holder: Option<u64>,
}

/// A callback armed on the epoch, run once on whichever thread next moves it.
type Callback = Arc<dyn Fn() + Send + Sync>;

/// A callback an epoch change released, run when this drops: on the thread that changed the
/// epoch, under passthrough, after that thread has let go of its locks.
#[must_use]
pub struct EpochBump(Option<Callback>);

impl EpochBump {
    /// A bump that released no callback.
    pub(crate) const NONE: EpochBump = EpochBump(None);

    /// Whether dropping this runs a callback.
    pub fn is_armed(&self) -> bool {
        self.0.is_some()
    }
}

impl std::fmt::Debug for EpochBump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochBump")
            .field("armed", &self.is_armed())
            .finish()
    }
}

impl Drop for EpochBump {
    fn drop(&mut self) {
        if let Some(callback) = self.0.take() {
            let _passthrough = Passthrough::enter();
            callback();
        }
    }
}

/// What keeps a domain from being quiescent, most pressing first.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum BlockerKind {
    /// A participant is running.
    Runnable,
    /// A waiter has been woken and has yet to run.
    Settling,
    /// A [`LeaseKind::Busy`] lease holds the domain busy.
    Lease,
    /// Only [`LeaseKind::Setup`] leases hold the domain busy: it is being set up.
    Setup,
    /// A participant woken during an executive's timestamp waits for the timestamp to end.
    Deferred,
    /// A timer is due and its waiter has yet to take it.
    TimerDue,
}

/// A domain's quiescence as an executive reads it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Quiescence {
    /// No participant can make progress until time moves.
    pub quiescent: bool,
    /// The domain's epoch when this was read.
    pub epoch: u64,
    /// Participants not blocked.
    pub runnable: u32,
    /// Leases held.
    pub busy: u32,
    /// Participants blocked.
    pub blocked: u32,
    /// The earliest pending timer of a participant after the current time, on the sim's clock.
    pub next_deadline: Option<Duration>,
    /// What holds the domain up, with the thread, lease or timer owner it names.
    pub blocker: Option<(BlockerKind, Arc<str>)>,
}

/// What a participant is doing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PState {
    /// Not counted as blocked.
    Running,
    /// Parked in a wait the domain counts toward quiescence.
    Blocked,
    /// A lease, listed as its own row with its label; its kind is the row's
    /// [`lease_kind`](ParticipantInfo::lease_kind).
    Busy(&'static str),
}

/// One participant (or lease) of a domain, as an executive lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParticipantInfo {
    /// The thread's lineage id.
    pub id: u64,
    /// The thread's name (see [`thread_name`](crate::thread_name)), or the lease's label.
    pub name: Arc<str>,
    /// Whether it runs, waits or is a lease.
    pub state: PState,
    /// How long it has been in `state`, on the sim's clock.
    pub since_virtual: Duration,
    /// How long it has been in `state`, in real time.
    pub since_wall: Duration,
    /// When its current wait times out, on the sim's clock.
    pub deadline: Option<Duration>,
    /// What it is blocked in.
    pub wait: Option<&'static str>,
    /// What it last blocked in.
    pub last_wait: Option<&'static str>,
    /// The leases it holds.
    pub leases: Vec<&'static str>,
    /// For a lease's row ([`PState::Busy`]), what kind of lease it is; `None` for a thread's row.
    pub lease_kind: Option<LeaseKind>,
}

/// A background or helper thread doing something the sim sees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassEffect {
    /// The thread's name.
    pub thread: Arc<str>,
    /// The thread's class, background or helper.
    pub class: ThreadClass,
    /// The call that had the effect, such as `"sem_post"` or `"FUTEX_WAKE"`.
    pub op: &'static str,
    /// When, on the sim's clock.
    pub at: Duration,
}

/// A call the sim could not account for, made while an executive owned the clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuiescenceViolation {
    /// The thread's name.
    pub thread: Arc<str>,
    /// The call it made.
    pub op: &'static str,
    /// Whether the thread was counted as blocked when it made the call.
    pub blocked: bool,
    /// Whether the executive treats this violation as ending the run.
    pub fatal: bool,
    /// When, on the sim's clock.
    pub at: Duration,
}

/// What an executive's audit has seen since it attached.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditReport {
    /// Participants released from a native wait by something the sim did not see.
    pub outside_wakes: u64,
    /// The last 256 violations.
    pub violations: Vec<QuiescenceViolation>,
    /// Every violation seen, including those no longer kept.
    pub total_violations: u64,
    /// The last 256 effects of background and helper threads outside a setup scope.
    pub class_effects: Vec<ClassEffect>,
    /// Every such effect seen, including those no longer kept.
    pub total_class_effects: u64,
    /// Effects of background and helper threads inside a setup scope.
    pub total_setup_effects: u64,
}

// A snare choice: enough recent entries to diagnose a run, bounded so a long run's audit cannot
// grow without limit.
const AUDIT_KEEP: usize = 256;

/// Appends `item`, dropping the oldest entry once [`AUDIT_KEEP`] are kept.
fn keep<T>(log: &mut VecDeque<T>, item: T) {
    if log.len() == AUDIT_KEEP {
        log.pop_front();
    }
    log.push_back(item);
}

/// The audit's running record while an executive with auditing is attached; the private twin
/// of [`AuditReport`], with bounded queues in place of vectors.
#[derive(Default)]
struct AuditLog {
    violations: VecDeque<QuiescenceViolation>,
    total_violations: u64,
    class_effects: VecDeque<ClassEffect>,
    total_class_effects: u64,
    total_setup_effects: u64,
}

/// A thread's place in its domain's census.
#[derive(Clone, Copy)]
pub(crate) struct Row {
    pub(crate) class: ThreadClass,
    /// The wait it is blocked in; `None` while it runs.
    pub(crate) wait: Option<RowWait>,
    /// When it entered its current state: (sim's monotonic clock, [`real_elapsed`]).
    pub(crate) since: (Duration, Duration),
    /// The label of the last wait it blocked in, kept after the wait ends.
    pub(crate) last_wait: Option<&'static str>,
}

/// The wait a [`Row`]'s thread is blocked in.
#[derive(Clone, Copy)]
pub(crate) struct RowWait {
    /// What the wait is, as its [`WaitLabel`] named it.
    pub(crate) label: Option<&'static str>,
    /// When it times out, on the sim's monotonic clock; `None` for an untimed wait.
    pub(crate) deadline: Option<Duration>,
    /// The address a native wait blocks on, which a wake names.
    pub(crate) key: Option<usize>,
    /// The pthread mutex the wait returns holding.
    pub(crate) mutex: Option<usize>,
    #[cfg(target_os = "linux")]
    pub(crate) mask: u32,
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) token: u64,
    #[cfg(target_os = "linux")]
    pub(crate) expected: Option<u32>,
    #[cfg(target_os = "linux")]
    pub(crate) futex_private: Option<bool>,
    #[cfg(target_os = "linux")]
    pub(crate) pre_released: bool,
    #[cfg(target_os = "linux")]
    pub(crate) claimed: bool,
    /// A wake on `key` that reached every waiter parked there when it was made reached this one.
    /// Its own, unlike the per-address count, so another waiter on the same address leaving its
    /// wait (a spurious return, a timeout) cannot take it.
    #[cfg(windows)]
    pub(crate) woken: bool,
}

#[cfg(windows)]
struct TimerRelease {
    key: usize,
    cutoff: u64,
    remaining: usize,
    _lifetime: Arc<dyn Send + Sync>,
}

#[cfg(windows)]
#[derive(Default)]
pub(crate) struct TimerSignals {
    generation: u64,
    pending: Vec<TimerRelease>,
}

#[cfg(windows)]
impl TimerSignals {
    pub(crate) fn admit(&mut self) -> u64 {
        self.generation = self
            .generation
            .checked_add(1)
            .expect("native wait generation exhausted");
        self.generation
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct Release {
    mask: u32,
    futex_private: Option<bool>,
    cutoff: u64,
    remaining: usize,
}

#[cfg(target_os = "linux")]
impl Release {
    fn includes(self, token: u64, mask: u32, private: Option<bool>) -> bool {
        token <= self.cutoff
            && self.mask & mask != 0
            && self
                .futex_private
                .is_none_or(|scope| private == Some(scope))
    }
}

#[cfg(target_os = "linux")]
struct Releases {
    first: Release,
    rest: Vec<Release>,
    // Kernel wake counts omit waiter identities, so overlapping masks can leave returns ambiguous.
    claims: Vec<(u64, u64, u32, Option<bool>)>,
}

#[cfg(target_os = "linux")]
impl Releases {
    fn records(&self) -> impl Iterator<Item = &Release> {
        std::iter::once(&self.first).chain(&self.rest)
    }

    fn records_mut(&mut self) -> impl Iterator<Item = &mut Release> {
        std::iter::once(&mut self.first).chain(&mut self.rest)
    }

    fn retain(&mut self) -> bool {
        self.rest.retain(|record| record.remaining > 0);
        if self.first.remaining == 0 {
            if self.rest.is_empty() {
                return false;
            }
            self.first = self.rest.remove(0);
        }
        true
    }

    fn includes(release: Release, candidate: (u64, u64, u32, Option<bool>)) -> bool {
        release.includes(candidate.0, candidate.2, candidate.3) && release.cutoff < candidate.1
    }

    fn augment(
        candidate: usize,
        slots: &[Release],
        candidates: &[(u64, u64, u32, Option<bool>)],
        seen: &mut [bool],
        assigned: &mut [Option<usize>],
    ) -> bool {
        let mut parents = vec![None; candidates.len()];
        let mut pending = vec![candidate];
        while let Some(current) = pending.pop() {
            for (slot, &release) in slots.iter().enumerate() {
                if seen[slot] || !Self::includes(release, candidates[current]) {
                    continue;
                }
                seen[slot] = true;
                match assigned[slot] {
                    None => {
                        assigned[slot] = Some(current);
                        let mut current = current;
                        while let Some((previous, slot)) = parents[current] {
                            assigned[slot] = Some(previous);
                            current = previous;
                        }
                        return true;
                    }
                    Some(previous) if previous != candidate && parents[previous].is_none() => {
                        parents[previous] = Some((current, slot));
                        pending.push(previous);
                    }
                    Some(_) => {}
                }
            }
        }
        false
    }

    fn can_escape(
        candidate: usize,
        required: usize,
        slots: &[Release],
        candidates: &[(u64, u64, u32, Option<bool>)],
        assigned: &[Option<usize>],
        seen: &mut [bool],
    ) -> bool {
        let mut pending = vec![candidate];
        while let Some(candidate) = pending.pop() {
            for (slot, &release) in slots.iter().enumerate() {
                if seen[slot] || !Self::includes(release, candidates[candidate]) {
                    continue;
                }
                seen[slot] = true;
                match assigned[slot] {
                    None => return true,
                    Some(next) if next >= required => return true,
                    Some(next) => pending.push(next),
                }
            }
        }
        false
    }

    fn can_claim(&self, candidate: (u64, u64, u32, Option<bool>)) -> bool {
        if self.claims.is_empty() && self.rest.is_empty() {
            return self.first.remaining > 0 && Self::includes(self.first, candidate);
        }
        let slots: Vec<_> = self
            .records()
            .flat_map(|record| std::iter::repeat_n(*record, record.remaining))
            .collect();
        let mut candidates = self.claims.clone();
        candidates.push(candidate);
        let mut assigned = vec![None; slots.len()];
        let mut seen = vec![false; slots.len()];
        for candidate in 0..candidates.len() {
            seen.fill(false);
            if !Self::augment(candidate, &slots, &candidates, &mut seen, &mut assigned) {
                return false;
            }
        }
        true
    }

    fn match_candidates(&mut self, live: &[(u64, u64, u32, Option<bool>)], claim: bool) -> bool {
        let records: Vec<_> = self.records().copied().collect();
        let indices: Vec<_> = records
            .iter()
            .enumerate()
            .flat_map(|(index, record)| std::iter::repeat_n(index, record.remaining))
            .collect();
        let slots: Vec<_> = indices.iter().map(|&record| records[record]).collect();
        let mut candidates = self.claims.clone();
        candidates.extend_from_slice(live);
        let mut assigned = vec![None; slots.len()];
        let mut seen = vec![false; slots.len()];
        let mut claimed = false;
        for candidate in 0..candidates.len() {
            seen.fill(false);
            let matched = Self::augment(candidate, &slots, &candidates, &mut seen, &mut assigned);
            if candidate < self.claims.len() {
                assert!(matched, "native release attribution lost");
            }
            if claim && candidate == self.claims.len() {
                claimed = matched;
            }
        }
        let required = self.claims.len() + usize::from(claimed);
        // A fulfilled slot can retire once no alternating path can move its receipt to a free slot.
        let mut forced = vec![false; required];
        for (candidate, forced) in forced.iter_mut().enumerate() {
            seen.fill(false);
            *forced = !Self::can_escape(
                candidate,
                required,
                &slots,
                &candidates,
                &assigned,
                &mut seen,
            );
        }
        for record in self.records_mut() {
            record.remaining = 0;
        }
        for (slot, candidate) in assigned.iter().enumerate() {
            if candidate.is_none_or(|candidate| candidate < required && forced[candidate]) {
                continue;
            }
            let record = indices[slot];
            if record == 0 {
                self.first.remaining += 1;
            } else {
                self.rest[record - 1].remaining += 1;
            }
        }
        let pending = assigned
            .iter()
            .flatten()
            .filter(|&&candidate| candidate >= required)
            .count();
        self.claims = candidates
            .into_iter()
            .take(required)
            .enumerate()
            .filter_map(|(index, candidate)| (!forced[index]).then_some(candidate))
            .collect();
        if pending == 0 {
            for record in self.records_mut() {
                record.remaining = 0;
            }
            self.claims.clear();
        }
        claimed
    }
}

/// Who holds a pthread mutex that a participant's wait needs, as the lock hooks saw it.
#[cfg_attr(windows, allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Owner {
    /// Unlocked, as far as the hooks have seen.
    Free,
    /// Held by a thread none of whose holds the domain could rule out: one holding more mutexes
    /// than [`Held`] records.
    Unknown,
    /// Held by a thread the domain never saw take it: one outside the domain (another test's, an
    /// unmanaged one) or the sim's own, under passthrough. Nothing the domain does releases it.
    Outside,
    /// Held by the thread with this lineage.
    Thread(u64),
}

/// How many pthread mutexes [`Held`] records per thread. A snare choice: code rarely nests more
/// locks than this; a thread holding more counts as possibly holding any mutex (`Owner::Unknown`).
const HELD_SLOTS: usize = 8;

/// The pthread mutexes a managed thread holds, as its lock hooks saw it take and let go of them,
/// readable from the thread that waits for one of them. Only the owning thread writes it, with
/// sequentially consistent stores, so a waiter that publishes its watch (`Accounting::watching`)
/// before reading these either sees a hold or is seen by the holder (see `domain::note_mutex`).
#[cfg_attr(windows, allow(dead_code))]
#[derive(Default)]
pub(crate) struct Held {
    /// The held mutexes' addresses; 0 marks a free slot.
    slots: [AtomicUsize; HELD_SLOTS],
    /// Holds that found no free slot.
    spilled: AtomicUsize,
}

#[cfg_attr(windows, allow(dead_code))]
impl Held {
    /// The thread took `mutex`.
    pub(crate) fn take(&self, mutex: usize) {
        match self
            .slots
            .iter()
            .find(|slot| slot.load(Ordering::Relaxed) == 0)
        {
            Some(slot) => slot.store(mutex, Ordering::SeqCst),
            None => {
                self.spilled.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    /// The thread let go of `mutex`. A mutex it took unseen (before it was managed, or under
    /// passthrough) is in no slot, and leaves the spill count alone unless one is pending.
    pub(crate) fn free(&self, mutex: usize) {
        match self
            .slots
            .iter()
            .find(|slot| slot.load(Ordering::Relaxed) == mutex)
        {
            Some(slot) => slot.store(0, Ordering::SeqCst),
            None => {
                #[allow(deprecated)]
                let _ = self
                    .spilled
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
            }
        }
    }

    /// Whether the thread is seen holding `mutex`.
    pub(crate) fn holds(&self, mutex: usize) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.load(Ordering::SeqCst) == mutex)
    }

    /// Whether some of the thread's holds went unrecorded.
    fn spilled(&self) -> bool {
        self.spilled.load(Ordering::SeqCst) > 0
    }
}

thread_local! {
    /// The calling thread's [`Held`] in the domain managing it, null while unmanaged. Owned by
    /// that domain's census (`Core::held`), which outlives the pointer: [`swap_held`] puts the
    /// previous one back before the thread's row goes.
    static HELD: Cell<*const Held> = const { Cell::new(std::ptr::null()) };
    static OUTSIDE_HELD: Held = const { Held { slots: [const { AtomicUsize::new(0) }; HELD_SLOTS], spilled: AtomicUsize::new(0) } };
}

/// Installs `held` as the calling thread's [`Held`] and returns the one it replaced.
pub(crate) fn swap_held(held: *const Held) -> *const Held {
    let previous = HELD.try_with(Cell::get).unwrap_or(std::ptr::null());
    let outside = OUTSIDE_HELD
        .try_with(|h| h as *const Held)
        .unwrap_or(std::ptr::null());
    let from = if previous.is_null() {
        outside
    } else {
        previous
    };
    let to = if held.is_null() { outside } else { held };
    if let (Some(from), Some(to)) = (unsafe { from.as_ref() }, unsafe { to.as_ref() }) {
        for (from, to) in from.slots.iter().zip(&to.slots) {
            to.store(from.load(Ordering::SeqCst), Ordering::SeqCst);
        }
        to.spilled
            .store(from.spilled.load(Ordering::SeqCst), Ordering::SeqCst);
    }
    let _ = HELD.try_with(|h| h.set(held));
    previous
}

/// The calling thread's [`Held`], if it is managed.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn held() -> Option<&'static Held> {
    let held = HELD.try_with(Cell::get).unwrap_or(std::ptr::null());
    // SAFETY: a non-null pointer is installed only while the census that owns it keeps it alive
    // (see `HELD`); the reference is not kept past the hook that reads it.
    unsafe { held.as_ref() }.or_else(|| {
        let outside = OUTSIDE_HELD.try_with(|h| h as *const Held).ok()?;
        unsafe { outside.as_ref() }
    })
}

/// A pthread mutex the census tracks because a participant's wait needs it.
#[cfg_attr(windows, allow(dead_code))]
struct Watched {
    owner: Owner,
    /// Participant waits that need it; the entry goes when this reaches zero.
    watchers: u32,
}

/// The state an executive's checks must see consistent, under one lock: the census, the timestamp
/// gate and the audit log.
#[derive(Default)]
pub(crate) struct Core {
    /// Every managed thread of the domain, by lineage.
    pub(crate) rows: BTreeMap<u64, Row>,
    /// Whether an executive's timestamp is open: participants woken meanwhile wait at the gate.
    pub(crate) gate_closed: bool,
    /// How many participants a timestamp held at the gate have yet to count themselves running:
    /// those still waiting there, and those the gate has let go that have yet to leave their wait.
    pub(crate) gated: u32,
    /// The audit, present only while an executive that asked for one is attached.
    audit: Option<AuditLog>,
    /// The epoch and effect count when the domain last became quiescent, to tell an outside wake.
    quiet: Option<(u64, u64)>,
    /// Participants parked joining a thread, by the joined thread's lineage.
    pub(crate) joining: HashMap<u64, u32>,
    /// Joiners whose thread has exited but who have yet to count themselves running: the OS has
    /// released them, so the domain only looks quiescent.
    pub(crate) released: u32,
    /// Participants a wake on each address released from a native wait, who have yet to count
    /// themselves running.
    #[cfg(not(target_os = "linux"))]
    signalled: HashMap<usize, u32>,
    #[cfg(target_os = "linux")]
    signalled: HashMap<usize, Releases>,
    #[cfg(target_os = "linux")]
    wait_token: u64,
    #[cfg(target_os = "linux")]
    ready_rows: usize,
    /// The pthread mutexes participants' waits need, with their holders.
    mutexes: HashMap<usize, Watched>,
    #[cfg(windows)]
    shared_mutexes: HashMap<usize, std::collections::BTreeSet<u64>>,
    #[cfg(windows)]
    timer_releases: Vec<TimerRelease>,
    /// Every managed thread's [`Held`], by lineage; the census owns them so a thread that never
    /// leaves its domain cleanly leaves nothing dangling.
    held: HashMap<u64, Arc<Held>>,
}

impl Core {
    pub(crate) fn clear_quiet(&mut self) {
        self.quiet = None;
    }

    /// A thread left: its joiners are released.
    pub(crate) fn exited(&mut self, lineage: u64) {
        if let Some(n) = self.joining.remove(&lineage) {
            self.released += n;
        }
    }

    /// A joiner counts itself running again.
    pub(crate) fn joined(&mut self, target: u64) {
        match self.joining.get_mut(&target) {
            Some(n) if *n > 1 => *n -= 1,
            Some(_) => {
                self.joining.remove(&target);
            }
            None => self.released = self.released.saturating_sub(1),
        }
    }

    /// A wake on `key` for up to `n` waiters: that many participants parked there, less those
    /// already released, count as released until they run.
    ///
    /// The pending count never exceeds the participants parked on `key`, since the OS wakes at
    /// most those: a `FUTEX_WAKE` of `n` wakes at most `n` waiters (man 2const FUTEX_WAKE), a
    /// condition variable's broadcast every waiter and its signal at least one (POSIX
    /// pthread_cond_broadcast), a semaphore post one waiter (POSIX sem_post).
    pub(crate) fn signal(&mut self, key: usize, n: usize) {
        #[cfg(target_os = "linux")]
        self.signal_masked(key, n, u32::MAX);
        #[cfg(not(target_os = "linux"))]
        self.signal_matching(key, n, |_| true);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn signal_masked(&mut self, key: usize, n: usize, mask: u32) {
        self.signal_masked_in_space(key, n, mask, None);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn signal_masked_in_space(
        &mut self,
        key: usize,
        n: usize,
        mask: u32,
        private: Option<bool>,
    ) {
        let cutoff = self
            .rows
            .values()
            .filter_map(|row| {
                row.wait
                    .filter(|wait| {
                        row.class == ThreadClass::Participant
                            && wait.key == Some(key)
                            && !wait.claimed
                            && wait.mask & mask != 0
                            && private.is_none_or(|scope| wait.futex_private == Some(scope))
                    })
                    .map(|wait| wait.token)
            })
            .max();
        let Some(_) = cutoff.filter(|_| n > 0) else {
            return;
        };
        self.wait_token = self
            .wait_token
            .checked_add(1)
            .expect("native wait generation exhausted");
        let eligible = self
            .rows
            .values()
            .filter(|row| {
                row.class == ThreadClass::Participant
                    && row.wait.is_some_and(|wait| {
                        wait.key == Some(key)
                            && !wait.claimed
                            && wait.mask & mask != 0
                            && private.is_none_or(|scope| wait.futex_private == Some(scope))
                    })
            })
            .count();
        let record = Release {
            mask,
            futex_private: private,
            cutoff: self.wait_token,
            remaining: n.min(eligible),
        };
        match self.signalled.entry(key) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Releases {
                    first: record,
                    rest: Vec::new(),
                    claims: Vec::new(),
                });
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let releases = entry.get_mut();
                if releases.claims.is_empty()
                    && releases.rest.is_empty()
                    && releases.first.mask == mask
                    && releases.first.futex_private == private
                    && self.rows.values().all(|row| {
                        row.class != ThreadClass::Participant
                            || row.wait.is_none_or(|wait| {
                                wait.key != Some(key)
                                    || wait.claimed
                                    || wait.mask & mask == 0
                                    || wait.token <= releases.first.cutoff
                            })
                    })
                {
                    releases.first.remaining =
                        releases.first.remaining.saturating_add(record.remaining);
                    releases.first.cutoff = record.cutoff;
                } else if let Some(previous) = releases.records_mut().find(|previous| {
                    previous.mask == mask
                        && previous.cutoff == record.cutoff
                        && previous.futex_private == private
                }) {
                    previous.remaining = previous.remaining.saturating_add(record.remaining);
                } else {
                    releases.rest.push(record);
                }
            }
        }
        self.prune_releases(key);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn signal_futex(
        &mut self,
        key: usize,
        count: i64,
        mask: u32,
        private: bool,
        word: impl FnOnce() -> Option<u32>,
    ) {
        if count > 0 {
            self.signal_masked_in_space(key, count as usize, mask, Some(private));
        }
        if count == 0
            && self.rows.values().any(|row| {
                row.class == ThreadClass::Participant
                    && row.wait.is_some_and(|wait| {
                        wait.key == Some(key)
                            && wait.mask & mask != 0
                            && wait.expected.is_some()
                            && wait.futex_private == Some(private)
                    })
            })
            && let Some(word) = word()
        {
            for row in self.rows.values_mut() {
                if row.class == ThreadClass::Participant
                    && let Some(wait) = row.wait.as_mut()
                    && wait.key == Some(key)
                    && wait.mask & mask != 0
                    && wait.futex_private == Some(private)
                    && wait.expected.is_some_and(|expected| expected != word)
                {
                    if !wait.pre_released && !wait.claimed {
                        self.ready_rows += 1;
                    }
                    wait.pre_released = true;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn note_futex_pre_enrollment_return(&mut self, lineage: u64) {
        if let Some(row) = self.rows.get_mut(&lineage)
            && row.class == ThreadClass::Participant
            && let Some(wait) = row.wait.as_mut()
            && wait.expected.is_some()
            && !wait.pre_released
        {
            if !wait.claimed {
                self.ready_rows += 1;
            }
            wait.pre_released = true;
        }
    }

    #[cfg(target_os = "linux")]
    fn prune_releases(&mut self, key: usize) {
        let Some(releases) = self.signalled.get_mut(&key) else {
            return;
        };
        if releases.rest.is_empty() && releases.claims.is_empty() {
            let count = self
                .rows
                .values()
                .filter(|row| {
                    row.class == ThreadClass::Participant
                        && row.wait.is_some_and(|wait| {
                            wait.key == Some(key)
                                && !wait.claimed
                                && releases.first.includes(
                                    wait.token,
                                    wait.mask,
                                    wait.futex_private,
                                )
                        })
                })
                .count();
            releases.first.remaining = releases.first.remaining.min(count);
        } else {
            let candidates: Vec<_> = self
                .rows
                .values()
                .filter_map(|row| {
                    row.wait
                        .filter(|wait| {
                            row.class == ThreadClass::Participant
                                && wait.key == Some(key)
                                && !wait.claimed
                        })
                        .map(|wait| (wait.token, u64::MAX, wait.mask, wait.futex_private))
                })
                .collect();
            releases.match_candidates(&candidates, false);
        }
        if !releases.retain() {
            self.signalled.remove(&key);
        }
    }

    #[cfg(target_os = "linux")]
    fn claim_release(&mut self, lineage: u64) -> bool {
        let Some(wait) = self.rows.get(&lineage).and_then(|row| row.wait) else {
            return false;
        };
        if wait.claimed {
            return true;
        }
        if wait.pre_released {
            return true;
        }
        let Some(key) = wait.key else {
            return false;
        };
        self.wait_token = self
            .wait_token
            .checked_add(1)
            .expect("native wait generation exhausted");
        let retired = self.wait_token;
        let credited = self.signalled.get_mut(&key).is_some_and(|releases| {
            if releases.rest.is_empty() && releases.claims.is_empty() {
                if releases
                    .first
                    .includes(wait.token, wait.mask, wait.futex_private)
                    && releases.first.remaining > 0
                {
                    releases.first.remaining -= 1;
                    true
                } else {
                    false
                }
            } else {
                let mut candidates = vec![(wait.token, retired, wait.mask, wait.futex_private)];
                candidates.extend(self.rows.iter().filter_map(|(&other, row)| {
                    row.wait
                        .filter(|wait| {
                            other != lineage
                                && row.class == ThreadClass::Participant
                                && wait.key == Some(key)
                                && !wait.claimed
                        })
                        .map(|wait| (wait.token, u64::MAX, wait.mask, wait.futex_private))
                }));
                releases.match_candidates(&candidates, true)
            }
        });
        let owned = credited || wait.pre_released;
        if owned
            && let Some(wait) = self
                .rows
                .get_mut(&lineage)
                .and_then(|row| row.wait.as_mut())
        {
            if !wait.pre_released && !wait.claimed {
                self.ready_rows += 1;
            }
            wait.claimed = true;
        }
        self.prune_releases(key);
        owned
    }

    #[cfg(windows)]
    fn timer_released(&self, wait: RowWait) -> bool {
        wait.key.is_some_and(|key| {
            self.timer_releases.iter().any(|release| {
                release.key == key && wait.token <= release.cutoff && release.remaining > 0
            })
        })
    }

    #[cfg(windows)]
    pub(crate) fn consume_timer_event(&mut self, key: usize) {
        if let Some(release) = self
            .timer_releases
            .iter_mut()
            .find(|release| release.key == key && release.remaining > 0)
        {
            release.remaining -= 1;
        }
        self.prune_timer_releases();
    }

    #[cfg(windows)]
    fn consume_timer_release(&mut self, wait: RowWait) -> bool {
        let Some(release) = self.timer_releases.iter_mut().find(|release| {
            wait.key == Some(release.key) && wait.token <= release.cutoff && release.remaining > 0
        }) else {
            return false;
        };
        release.remaining -= 1;
        true
    }

    #[cfg(windows)]
    fn prune_timer_releases(&mut self) {
        let rows = &self.rows;
        self.timer_releases.retain_mut(|release| {
            let eligible = rows
                .values()
                .filter(|row| row.class == ThreadClass::Participant)
                .filter_map(|row| row.wait)
                .filter(|wait| wait.key == Some(release.key) && wait.token <= release.cutoff)
                .count();
            release.remaining = release.remaining.min(eligible);
            release.remaining != 0
        });
    }

    pub(crate) fn has_pending_releases(&self) -> bool {
        #[cfg(windows)]
        if !self.timer_releases.is_empty() {
            return true;
        }
        #[cfg(target_os = "linux")]
        if self.ready_rows > 0 {
            return true;
        }
        !self.signalled.is_empty()
    }

    #[cfg(not(target_os = "linux"))]
    fn signal_matching(&mut self, key: usize, n: usize, matches: impl Fn(RowWait) -> bool) {
        let (parked, eligible) = self
            .rows
            .values()
            .filter_map(|row| {
                (row.class == ThreadClass::Participant)
                    .then_some(row.wait)
                    .flatten()
                    .filter(|wait| wait.key == Some(key))
            })
            .fold((0, 0), |(parked, eligible), wait| {
                (parked + 1, eligible + usize::from(matches(wait)))
            });
        if eligible == 0 || n == 0 {
            return;
        }
        #[cfg(windows)]
        if n >= eligible {
            for row in self.rows.values_mut() {
                if row.class == ThreadClass::Participant
                    && let Some(wait) = row.wait.as_mut()
                    && wait.key == Some(key)
                    && matches(*wait)
                {
                    wait.woken = true;
                }
            }
        }
        let pending = self.signalled.entry(key).or_default();
        let target = u32::try_from(n.min(eligible)).unwrap_or(u32::MAX);
        *pending = pending
            .saturating_add(target)
            .min(u32::try_from(parked).unwrap_or(u32::MAX));
        if *pending == 0 {
            self.signalled.remove(&key);
        }
    }

    /// The first participant parked in a native wait that is free to return: woken on its
    /// address, and holding or able to take the mutex it returns holding; or in a contended lock
    /// no other thread of the domain holds.
    pub(crate) fn first_released(&self) -> Option<u64> {
        self.rows.iter().find_map(|(&lineage, row)| {
            if row.class != ThreadClass::Participant {
                return None;
            }
            let wait = row.wait?;
            let released = match (wait.key, wait.mutex) {
                (Some(key), mutex) => {
                    #[cfg(target_os = "linux")]
                    let released = wait.pre_released
                        || wait.claimed
                        || self.signalled.get(&key).is_some_and(|releases| {
                            releases.can_claim((
                                wait.token,
                                u64::MAX,
                                wait.mask,
                                wait.futex_private,
                            ))
                        });
                    #[cfg(not(target_os = "linux"))]
                    let released = self.signalled.contains_key(&key);
                    #[cfg(windows)]
                    let released = released || wait.woken || self.timer_released(wait);
                    released && !mutex.is_some_and(|m| self.held_by_other(m, lineage))
                }
                (None, Some(mutex)) => self.lock_unheld(mutex, lineage),
                (None, None) => false,
            };
            released.then_some(lineage)
        })
    }

    /// The first participant in a contended lock that no other thread of the domain holds: the
    /// mutex is free, already its own, or held where nothing the domain does can release it. Such
    /// a waiter is about to run, or waits on the world outside, so the domain is not quiescent.
    pub(crate) fn first_unheld_lock(&self) -> Option<u64> {
        if self.mutexes.is_empty() {
            return None;
        }
        self.rows.iter().find_map(|(&lineage, row)| {
            let wait = row.wait.filter(|w| w.key.is_none())?;
            let mutex = wait.mutex?;
            (row.class == ThreadClass::Participant && self.lock_unheld(mutex, lineage))
                .then_some(lineage)
        })
    }

    /// Whether `lineage`'s contended lock on `mutex` is not held by another thread of the domain.
    /// An unwatched mutex counts as held.
    fn lock_unheld(&self, mutex: usize, lineage: u64) -> bool {
        self.mutexes.get(&mutex).is_some_and(|w| match w.owner {
            Owner::Free | Owner::Outside => true,
            Owner::Unknown => false,
            Owner::Thread(owner) => owner == lineage,
        })
    }

    /// Whether `mutex` is watched and held by someone other than `lineage`; an owner the domain
    /// cannot name counts as someone else.
    fn held_by_other(&self, mutex: usize, lineage: u64) -> bool {
        self.mutexes.get(&mutex).is_some_and(|w| match w.owner {
            Owner::Free => false,
            Owner::Unknown | Owner::Outside => true,
            Owner::Thread(owner) => owner != lineage,
        })
    }

    /// Who holds `mutex`, which the caller just failed to take, as the domain's threads' [`Held`]
    /// records show: one of them, possibly one whose holds overflowed, or none.
    #[cfg(any(unix, windows))]
    pub(crate) fn holder_of(&self, mutex: usize) -> Owner {
        let mut spilled = false;
        for (&lineage, held) in &self.held {
            if held.holds(mutex) {
                return Owner::Thread(lineage);
            }
            spilled |= held.spilled();
        }
        if spilled {
            Owner::Unknown
        } else {
            Owner::Outside
        }
    }

    /// A participant is about to wait for `mutex`: in a contended lock, whose holder is found
    /// unless an earlier watch already tracks it, or, `releasing`, in a condition variable's wait,
    /// which lets go of it, so it is free whatever was recorded.
    #[cfg(any(unix, windows))]
    pub(crate) fn watch_mutex(&mut self, mutex: usize, releasing: bool) {
        let owner = if releasing {
            #[cfg(windows)]
            if let Some(owner) = self
                .shared_mutexes
                .get(&mutex)
                .and_then(|owners| owners.first())
            {
                return self.watch_owned_mutex(mutex, Owner::Thread(*owner));
            }
            Owner::Free
        } else {
            match self.mutexes.get(&mutex) {
                Some(watched) => watched.owner,
                None => self.holder_of(mutex),
            }
        };
        self.watch_owned_mutex(mutex, owner);
    }

    #[cfg(any(unix, windows))]
    fn watch_owned_mutex(&mut self, mutex: usize, owner: Owner) {
        let watched = self
            .mutexes
            .entry(mutex)
            .or_insert(Watched { owner, watchers: 0 });
        watched.watchers += 1;
        watched.owner = owner;
    }

    #[cfg(windows)]
    pub(crate) fn shared_mutex_taken(&mut self, mutex: usize, lineage: u64) {
        let owners = self.shared_mutexes.entry(mutex).or_default();
        owners.insert(lineage);
        if let Some(watched) = self.mutexes.get_mut(&mutex) {
            watched.owner = Owner::Thread(*owners.first().unwrap());
        }
    }

    #[cfg(windows)]
    pub(crate) fn shared_mutex_freed(&mut self, mutex: usize, lineage: u64) {
        let Some(owners) = self.shared_mutexes.get_mut(&mutex) else {
            self.mutex_freed(mutex, lineage);
            return;
        };
        owners.remove(&lineage);
        let owner = owners.first().copied().map_or(Owner::Free, Owner::Thread);
        let update = self
            .mutexes
            .get(&mutex)
            .is_some_and(|watched| match watched.owner {
                Owner::Thread(current) => current == lineage || owners.contains(&current),
                _ => true,
            });
        if owners.is_empty() {
            self.shared_mutexes.remove(&mutex);
        }
        if update && let Some(watched) = self.mutexes.get_mut(&mutex) {
            watched.owner = owner;
        }
    }

    /// A participant's wait that needed `mutex` ended; the entry goes with its last watcher.
    #[cfg(any(unix, windows))]
    pub(crate) fn unwatch_mutex(&mut self, mutex: usize) {
        if let Some(watched) = self.mutexes.get_mut(&mutex) {
            watched.watchers -= 1;
            if watched.watchers == 0 {
                self.mutexes.remove(&mutex);
            }
        }
    }

    /// How many mutexes are watched, mirrored into [`Accounting::watching`] for the lock-free check.
    #[cfg(any(unix, windows))]
    pub(crate) fn watching(&self) -> usize {
        self.mutexes.len()
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn mutex_held_outside(&self, mutex: usize) -> bool {
        self.mutexes
            .get(&mutex)
            .is_some_and(|watched| watched.owner == Owner::Outside)
    }

    /// `lineage` took `mutex`.
    #[cfg(any(unix, windows))]
    pub(crate) fn mutex_taken(&mut self, mutex: usize, lineage: u64) {
        if let Some(watched) = self.mutexes.get_mut(&mutex) {
            watched.owner = Owner::Thread(lineage);
        }
    }

    /// `lineage` let go of `mutex`, unless another thread has taken it since.
    #[cfg(any(unix, windows))]
    pub(crate) fn mutex_freed(&mut self, mutex: usize, lineage: u64) {
        if let Some(watched) = self.mutexes.get_mut(&mutex)
            && (matches!(watched.owner, Owner::Unknown | Owner::Outside)
                || watched.owner == Owner::Thread(lineage))
        {
            watched.owner = Owner::Free;
        }
    }

    /// A participant woken from a native wait on an address has left it for the timestamp gate:
    /// it takes one release there, if any is pending, and no longer waits on the address. `true`
    /// if it did.
    pub(crate) fn take_release(&mut self, lineage: u64) -> bool {
        let Some(wait) = self
            .rows
            .get_mut(&lineage)
            .and_then(|row| row.wait.as_mut())
        else {
            return false;
        };
        #[cfg(windows)]
        let previous = *wait;
        wait.mutex = None;
        let Some(key) = wait.key.take() else {
            return false;
        };
        #[cfg(windows)]
        if !self.consume_timer_release(previous) {
            self.consume_release(key);
        }
        #[cfg(windows)]
        self.prune_timer_releases();
        #[cfg(not(any(target_os = "linux", windows)))]
        self.consume_release(key);
        #[cfg(target_os = "linux")]
        self.prune_releases(key);
        true
    }

    /// One released waiter on `key` has run: the pending count there drops by one.
    #[cfg(not(target_os = "linux"))]
    fn consume_release(&mut self, key: usize) {
        if let Some(pending) = self.signalled.get_mut(&key) {
            *pending -= 1;
            if *pending == 0 {
                self.signalled.remove(&key);
            }
        }
    }

    /// Clears generic wake attribution when an executive attaches or detaches; live timer
    /// receipts remain paired with the native waits their physical signals released.
    pub(crate) fn clear_signalled(&mut self) {
        self.signalled.clear();
        #[cfg(target_os = "linux")]
        {
            self.ready_rows = 0;
        }
        #[cfg(target_os = "linux")]
        for row in self.rows.values_mut() {
            if let Some(wait) = row.wait.as_mut() {
                wait.pre_released = false;
                wait.claimed = false;
            }
        }
    }

    /// Sets a thread's wait, returning the wait it replaced and retiring its release attribution.
    pub(crate) fn set_waiting(
        &mut self,
        lineage: u64,
        wait: Option<RowWait>,
        since: Option<(Duration, Duration)>,
    ) -> Option<RowWait> {
        #[cfg(target_os = "linux")]
        let mut wait = wait;
        #[cfg(target_os = "linux")]
        if let Some(wait) = wait.as_mut() {
            self.wait_token = self
                .wait_token
                .checked_add(1)
                .expect("native wait generation exhausted");
            wait.token = self.wait_token;
        }
        let row = self.rows.get_mut(&lineage)?;
        if let Some(w) = wait {
            row.last_wait = w.label.or(row.last_wait);
        }
        let previous = std::mem::replace(&mut row.wait, wait);
        #[cfg(target_os = "linux")]
        if previous.is_some_and(|wait| wait.pre_released || wait.claimed) {
            self.ready_rows -= 1;
        }
        row.since = since.unwrap_or_default();
        #[cfg(not(target_os = "linux"))]
        if wait.is_none()
            && let Some(key) = previous.and_then(|w| w.key)
        {
            #[cfg(windows)]
            if !self.consume_timer_release(previous.unwrap()) {
                self.consume_release(key);
            }
            #[cfg(not(windows))]
            self.consume_release(key);
        }
        #[cfg(windows)]
        self.prune_timer_releases();
        #[cfg(target_os = "linux")]
        if let Some(key) = previous.and_then(|wait| wait.key) {
            self.prune_releases(key);
        }
        previous
    }
}

/// Real time since the first call, for how long a thread has been in its state. Read under
/// passthrough, so it is the OS's monotonic clock, not the domain's.
pub(crate) fn real_elapsed() -> Duration {
    static ORIGIN: crate::race::RaceCell<Instant> = crate::race::RaceCell::new();
    let _passthrough = Passthrough::enter();
    ORIGIN.get_or_init(Instant::now).0.elapsed()
}

/// A domain's accounting: its leases, epoch, starvation hints and thread names.
#[derive(Default)]
pub(crate) struct Accounting {
    /// The census, gate and audit; see [`Core`].
    core: Mutex<Core>,
    #[cfg(windows)]
    timer_signals: Mutex<TimerSignals>,
    /// Where participants woken during a timestamp wait for it to end.
    gate: Condvar,
    /// Whether an executive is attached; written under `core`.
    attached: AtomicBool,
    /// Whether the attached executive asked for an audit.
    auditing: AtomicBool,
    /// Participants parked in a native wait on an address, so a wake elsewhere skips the census.
    pub(crate) keyed: std::sync::atomic::AtomicU32,
    /// How many pthread mutexes the census watches, so a lock elsewhere skips it. Read and written
    /// sequentially consistent, as [`Held`] relies on.
    pub(crate) watching: AtomicUsize,
    /// Effects of non-participant threads, to tell their wakes from outside ones.
    effects: AtomicU64,
    /// Participants woken from a native wait by something outside the domain (see
    /// [`note_wake`](Self::note_wake)), counted whether or not an audit is kept.
    outside_wakes: AtomicU64,
    /// Held leases, by [`LeaseId`].
    leases: Mutex<BTreeMap<u64, Lease>>,
    /// Held across a time skip and across taking a lease, so a skip either lands before a lease
    /// is taken or sees it.
    skip_gate: Mutex<()>,
    next_lease: AtomicU64,
    /// `leases.len()`, readable without the lock; a time skip checks it under `skip_gate`.
    lease_count: AtomicUsize,
    /// Moves on with every change an observer of quiescence may care about.
    epoch: AtomicU64,
    /// The callback waiting for the epoch to move; see [`arm`](Self::arm).
    armed: Mutex<Option<Callback>>,
    /// Whether `armed` holds a callback, so [`bump`](Self::bump) skips the lock when it does not.
    is_armed: AtomicBool,
    /// Starvation hints (source, severity) pushed since the driver last took them.
    hints: Mutex<Vec<(Arc<str>, f32)>>,
    /// Thread names by lineage, as the threads named themselves.
    names: Mutex<HashMap<u64, Arc<str>>>,
    /// The OS handle (`pthread_t`, Windows thread handle) of each live thread, to its lineage.
    handles: Mutex<HashMap<usize, u64>>,
    /// The OS thread id ([`crate::census::current_os_thread_id`]) of each live thread, to its
    /// lineage, for a thread census.
    os_ids: Mutex<HashMap<u64, u64>>,
    /// The domain's id among every domain the process makes.
    pub(crate) serial: Serial,
}

/// A number no other domain of the process has: each one made takes the next.
pub(crate) struct Serial(pub(crate) u64);

impl Default for Serial {
    fn default() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Serial(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// Locks `mutex`, carrying on through poisoning: a panic on one thread must not turn every later
/// hook on every thread into a panic.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Accounting {
    /// Locks the census. Callers hold passthrough, so blocking here is not itself counted.
    pub(crate) fn core(&self) -> MutexGuard<'_, Core> {
        let core = lock(&self.core);
        #[cfg(windows)]
        let mut core = core;
        #[cfg(windows)]
        self.flush_timer_signals(&mut core);
        #[cfg(not(windows))]
        let core = core;
        core
    }

    #[cfg(windows)]
    pub(crate) fn timer_signals(&self) -> MutexGuard<'_, TimerSignals> {
        lock(&self.timer_signals)
    }

    #[cfg(windows)]
    pub(crate) fn defer_timer_signal(
        &self,
        key: usize,
        lifetime: Arc<dyn Send + Sync>,
        signal: impl FnOnce() -> usize,
    ) {
        let mut signals = self.timer_signals();
        let count = signal();
        if count != 0 && self.keyed.load(Ordering::SeqCst) != 0 {
            let cutoff = signals.generation;
            if let Some(release) = signals
                .pending
                .iter_mut()
                .find(|release| release.key == key && release.cutoff == cutoff)
            {
                release.remaining = release.remaining.saturating_add(count);
            } else {
                signals.pending.push(TimerRelease {
                    key,
                    cutoff,
                    remaining: count,
                    _lifetime: lifetime,
                });
            }
        }
    }

    #[cfg(windows)]
    pub(crate) fn flush_timer_signals(&self, core: &mut Core) {
        self.drain_timer_signals(core, &mut self.timer_signals());
    }

    #[cfg(windows)]
    pub(crate) fn drain_timer_signals(&self, core: &mut Core, signals: &mut TimerSignals) {
        for release in signals.pending.drain(..) {
            if let Some(existing) = core
                .timer_releases
                .iter_mut()
                .find(|existing| existing.key == release.key && existing.cutoff == release.cutoff)
            {
                existing.remaining = existing.remaining.saturating_add(release.remaining);
            } else {
                core.timer_releases.push(release);
            }
        }
        core.prune_timer_releases();
    }

    /// Waits on the timestamp gate, releasing the census meanwhile. A condition variable may wake
    /// spuriously, so callers re-check `gate_closed` in a loop.
    pub(crate) fn wait_at_gate<'a>(&self, core: MutexGuard<'a, Core>) -> MutexGuard<'a, Core> {
        let core = self.gate.wait(core).unwrap_or_else(|e| e.into_inner());
        #[cfg(windows)]
        let mut core = core;
        #[cfg(windows)]
        self.flush_timer_signals(&mut core);
        core
    }

    /// Ends a timestamp and wakes every participant waiting at the gate.
    pub(crate) fn open_gate(&self, core: &mut Core) {
        core.gate_closed = false;
        self.gate.notify_all();
    }

    /// Whether an executive is attached.
    pub(crate) fn attached(&self) -> bool {
        self.attached.load(Ordering::Relaxed)
    }

    /// Whether the attached executive keeps an audit.
    pub(crate) fn auditing(&self) -> bool {
        self.auditing.load(Ordering::Relaxed)
    }

    /// Marks an executive attached, `false` if one already is. Starts from a clean slate: a fresh
    /// audit if asked for and no pending releases.
    pub(crate) fn attach(&self, audit: bool) -> bool {
        let _passthrough = Passthrough::enter();
        let mut core = self.core();
        if self.attached.swap(true, Ordering::AcqRel) {
            return false;
        }
        core.audit = audit.then(AuditLog::default);
        core.quiet = None;
        core.clear_signalled();
        self.outside_wakes.store(0, Ordering::Relaxed);
        self.auditing.store(audit, Ordering::Release);
        true
    }

    /// Marks the executive gone, drops its audit and bookkeeping, and opens the gate so no
    /// participant stays parked at a timestamp nobody will end.
    pub(crate) fn detach(&self) {
        let _passthrough = Passthrough::enter();
        let mut core = self.core();
        self.attached.store(false, Ordering::Release);
        self.auditing.store(false, Ordering::Release);
        core.audit = None;
        core.clear_signalled();
        self.open_gate(&mut core);
    }

    /// How many leases are held.
    pub(crate) fn lease_count(&self) -> usize {
        self.lease_count.load(Ordering::SeqCst)
    }

    /// Notes that the domain just became quiescent at the current epoch, to tell an outside wake.
    pub(crate) fn note_quiet(&self, core: &mut Core) {
        core.quiet = Some((self.epoch(), self.effects.load(Ordering::SeqCst)));
    }

    /// A participant left a native wait woken: an outside wake if nothing the sim sees happened
    /// since the domain became quiescent.
    pub(crate) fn note_wake(&self, core: &mut Core) {
        #[cfg(target_os = "linux")]
        let owned = core.claim_release(crate::thread_lineage());
        #[cfg(not(target_os = "linux"))]
        let owned = current_wait_key().is_some_and(|key| core.signalled.contains_key(&key));
        #[cfg(windows)]
        let owned = owned
            || core
                .rows
                .get(&crate::thread_lineage())
                .and_then(|row| row.wait)
                .is_some_and(|wait| wait.woken || core.timer_released(wait));
        if owned
            || current_wait_label() == Some("mutex")
            || JOIN_TARGET.try_with(Cell::get).ok().flatten().is_some()
        {
            return;
        }
        let now = (self.epoch(), self.effects.load(Ordering::SeqCst));
        if core.quiet == Some(now) {
            self.count_outside_wake();
            core.quiet = None;
        }
    }

    /// Counts an outside wake, such as one a deterministic schedule found, without taking the
    /// census lock.
    pub(crate) fn count_outside_wake(&self) {
        self.outside_wakes.fetch_add(1, Ordering::Relaxed);
    }

    /// The outside wakes counted since the domain was made or an executive last attached.
    pub(crate) fn outside_wakes(&self) -> u64 {
        self.outside_wakes.load(Ordering::Relaxed)
    }

    /// Counts an effect of a non-participant thread, and logs it for a background or helper one.
    pub(crate) fn note_effect(&self, effect: impl FnOnce() -> Option<ClassEffect>) {
        self.effects.fetch_add(1, Ordering::SeqCst);
        let Some(effect) = effect() else {
            return;
        };
        let setup = in_setup();
        let _passthrough = Passthrough::enter();
        if let Some(audit) = &mut self.core().audit {
            if setup {
                audit.total_setup_effects += 1;
            } else {
                audit.total_class_effects += 1;
                keep(&mut audit.class_effects, effect);
            }
        }
    }

    /// Records a call the sim could not account for, if an audit is kept.
    pub(crate) fn note_violation(&self, violation: QuiescenceViolation) {
        let _passthrough = Passthrough::enter();
        if let Some(audit) = &mut self.core().audit {
            audit.total_violations += 1;
            keep(&mut audit.violations, violation);
        }
    }

    /// What the audit has seen so far; empty when none is kept.
    pub(crate) fn audit_report(&self) -> AuditReport {
        let _passthrough = Passthrough::enter();
        let core = self.core();
        let Some(audit) = &core.audit else {
            return AuditReport::default();
        };
        AuditReport {
            outside_wakes: self.outside_wakes(),
            violations: audit.violations.iter().cloned().collect(),
            total_violations: audit.total_violations,
            class_effects: audit.class_effects.iter().cloned().collect(),
            total_class_effects: audit.total_class_effects,
            total_setup_effects: audit.total_setup_effects,
        }
    }

    /// Adds a thread to the census, running, and returns its [`Held`] for the thread to install
    /// with [`swap_held`]; the census keeps it until [`remove_row`](Self::remove_row).
    pub(crate) fn add_row(&self, lineage: u64, class: ThreadClass) -> *const Held {
        let _passthrough = Passthrough::enter();
        let held = Arc::new(Held::default());
        let ptr = Arc::as_ptr(&held);
        let mut core = self.core();
        core.rows.insert(
            lineage,
            Row {
                class,
                wait: None,
                since: (Duration::ZERO, Duration::ZERO),
                last_wait: None,
            },
        );
        core.held.insert(lineage, held);
        ptr
    }

    /// Drops a thread from the census as it leaves its domain.
    pub(crate) fn remove_row(&self, lineage: u64) {
        let _passthrough = Passthrough::enter();
        let mut core = self.core();
        let previous = core.rows.remove(&lineage);
        #[cfg(target_os = "linux")]
        if previous
            .and_then(|row| row.wait)
            .is_some_and(|wait| wait.pre_released || wait.claimed)
        {
            core.ready_rows -= 1;
        }
        #[cfg(target_os = "linux")]
        if let Some(key) = previous.and_then(|row| row.wait).and_then(|wait| wait.key) {
            core.prune_releases(key);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = previous;
        #[cfg(windows)]
        core.prune_timer_releases();
        core.held.remove(&lineage);
    }

    /// Reclasses a thread, clearing its wait: a thread changes class only while running.
    pub(crate) fn set_row_class(&self, lineage: u64, class: ThreadClass) {
        let _passthrough = Passthrough::enter();
        let mut core = self.core();
        if let Some(row) = core.rows.get_mut(&lineage) {
            row.class = class;
            let previous = row.wait.take();
            #[cfg(target_os = "linux")]
            if previous.is_some_and(|wait| wait.pre_released || wait.claimed) {
                core.ready_rows -= 1;
            }
            #[cfg(target_os = "linux")]
            if let Some(key) = previous.and_then(|wait| wait.key) {
                core.prune_releases(key);
            }
            #[cfg(not(target_os = "linux"))]
            let _ = previous;
        }
        #[cfg(windows)]
        core.prune_timer_releases();
    }

    /// Whether any lease is held.
    pub(crate) fn leases_held(&self) -> bool {
        self.lease_count.load(Ordering::SeqCst) > 0
    }

    /// Admits a time skip unless a lease is held; the lease cannot be taken until the guard drops.
    pub(crate) fn skip_gate(&self) -> Option<MutexGuard<'_, ()>> {
        let gate = lock(&self.skip_gate);
        (!self.leases_held()).then_some(gate)
    }

    /// The current epoch.
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Moves the epoch on and releases the armed callback, if any, to the caller. `is_armed` is
    /// read after the increment, and [`arm`](Self::arm) sets it before re-reading the epoch, so an
    /// arm racing a bump either sees the new epoch or is seen by it.
    pub(crate) fn bump(&self) -> EpochBump {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        if !self.is_armed.load(Ordering::SeqCst) {
            return EpochBump::NONE;
        }
        let _passthrough = Passthrough::enter();
        let mut armed = lock(&self.armed);
        self.is_armed.store(false, Ordering::SeqCst);
        EpochBump(armed.take())
    }

    /// Runs `callback` once the epoch moves past `seen`: now if it already has, else on the
    /// thread that next moves it. A later arm replaces an earlier one still waiting.
    pub(crate) fn arm(&self, seen: u64, callback: Callback) {
        let fire = {
            let _passthrough = Passthrough::enter();
            let mut armed = lock(&self.armed);
            *armed = Some(callback);
            self.is_armed.store(true, Ordering::SeqCst);
            if self.epoch.load(Ordering::SeqCst) == seen {
                return;
            }
            self.is_armed.store(false, Ordering::SeqCst);
            armed.take()
        };
        drop(EpochBump(fire));
    }

    /// Takes a lease labelled `label` for `holder`, and bumps the epoch. The insertion happens under
    /// the skip gate, so a time skip in flight finishes first and none starts until the lease shows.
    pub(crate) fn take_lease(
        &self,
        label: &'static str,
        kind: LeaseKind,
        holder: Option<u64>,
    ) -> (LeaseId, EpochBump) {
        let id = self.next_lease.fetch_add(1, Ordering::Relaxed);
        {
            let _passthrough = Passthrough::enter();
            let _gate = lock(&self.skip_gate);
            lock(&self.leases).insert(
                id,
                Lease {
                    label,
                    kind,
                    holder,
                },
            );
            self.lease_count.fetch_add(1, Ordering::SeqCst);
        }
        (LeaseId(id), self.bump())
    }

    /// Gives a lease back; `None` if it was not held.
    pub(crate) fn release_lease(&self, id: LeaseId) -> Option<EpochBump> {
        let removed = {
            let _passthrough = Passthrough::enter();
            lock(&self.leases).remove(&id.0)
        };
        removed?;
        self.lease_count.fetch_sub(1, Ordering::SeqCst);
        Some(self.bump())
    }

    /// The oldest held [`LeaseKind::Busy`] lease, else the oldest lease, as its label and kind, to
    /// name it as the blocker.
    pub(crate) fn first_lease(&self) -> Option<(&'static str, LeaseKind)> {
        let _passthrough = Passthrough::enter();
        let leases = lock(&self.leases);
        leases
            .values()
            .find(|lease| lease.kind == LeaseKind::Busy)
            .or_else(|| leases.values().next())
            .map(|lease| (lease.label, lease.kind))
    }

    /// Every held lease, oldest first, as (label, kind, holder).
    pub(crate) fn leases(&self) -> Vec<(&'static str, LeaseKind, Option<u64>)> {
        let _passthrough = Passthrough::enter();
        lock(&self.leases)
            .values()
            .map(|lease| (lease.label, lease.kind, lease.holder))
            .collect()
    }

    /// Notes that `source` is starved with `severity`, for the driver.
    pub(crate) fn push_hint(&self, source: &str, severity: f32) {
        let _passthrough = Passthrough::enter();
        lock(&self.hints).push((Arc::from(source), severity));
    }

    /// The hints pushed since the last call, oldest first.
    pub(crate) fn take_hints(&self) -> Vec<(Arc<str>, f32)> {
        let _passthrough = Passthrough::enter();
        std::mem::take(&mut *lock(&self.hints))
    }

    /// The name recorded for a thread.
    pub(crate) fn name(&self, lineage: u64) -> Option<Arc<str>> {
        let _passthrough = Passthrough::enter();
        lock(&self.names).get(&lineage).cloned()
    }

    /// Sets or clears a thread's name, returning the one it replaced.
    pub(crate) fn set_name(&self, lineage: u64, name: Option<Arc<str>>) -> Option<Arc<str>> {
        let _passthrough = Passthrough::enter();
        let mut names = lock(&self.names);
        match name {
            Some(name) => names.insert(lineage, name),
            None => names.remove(&lineage),
        }
    }

    /// Maps a new thread's OS handle to its lineage, and, made on that thread, its OS thread id.
    pub(crate) fn record_handle(&self, handle: usize, lineage: u64) {
        let _passthrough = Passthrough::enter();
        lock(&self.handles).insert(handle, lineage);
        if handle == crate::os::current_thread_handle()
            && let Some(id) = crate::census::current_os_thread_id()
        {
            lock(&self.os_ids).insert(id, lineage);
        }
    }

    /// Forgets a thread's handle as it leaves, keeping the name the OS held for it if it recorded
    /// none, so the handle is never used once the OS may have reused it.
    pub(crate) fn forget_handle(&self, handle: usize, lineage: u64) {
        let _passthrough = Passthrough::enter();
        if let Some(id) = crate::census::current_os_thread_id() {
            let mut os_ids = lock(&self.os_ids);
            if os_ids.get(&id) == Some(&lineage) {
                os_ids.remove(&id);
            }
        }
        let removed = lock(&self.handles).remove_entry(&handle);
        if removed.is_some_and(|(_, l)| l == lineage)
            && let Some(name) = crate::os::thread_name(None)
        {
            lock(&self.names)
                .entry(lineage)
                .or_insert_with(|| Arc::from(name));
        }
    }

    /// The OS handle of the live thread with `lineage`.
    pub(crate) fn handle_of(&self, lineage: u64) -> Option<usize> {
        let _passthrough = Passthrough::enter();
        lock(&self.handles)
            .iter()
            .find_map(|(&handle, &l)| (l == lineage).then_some(handle))
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn native_mutex_lineage(&self, mutex: usize) -> Option<u64> {
        let _passthrough = Passthrough::enter();
        let owner = unsafe { crate::os::sync::native_mutex_owner(mutex) }?;
        match owner {
            crate::os::sync::NativeMutexOwner::ThreadId(id) => lock(&self.os_ids).get(&id).copied(),
            crate::os::sync::NativeMutexOwner::MachPort(port) => {
                lock(&self.handles).iter().find_map(|(&handle, &lineage)| {
                    let own = unsafe { libc::pthread_mach_thread_np(handle as libc::pthread_t) };
                    (own & 0xffff_fffc == port).then_some(lineage)
                })
            }
        }
    }

    /// Every live thread's OS thread id with its lineage and class.
    pub(crate) fn os_threads(&self) -> Vec<(u64, u64, ThreadClass)> {
        let _passthrough = Passthrough::enter();
        let ids: Vec<(u64, u64)> = lock(&self.os_ids).iter().map(|(&id, &l)| (id, l)).collect();
        let core = self.core();
        ids.into_iter()
            .filter_map(|(id, lineage)| Some((id, lineage, core.rows.get(&lineage)?.class)))
            .collect()
    }

    /// The lineage of the live thread with OS handle `handle`.
    pub(crate) fn lineage_of(&self, handle: usize) -> Option<u64> {
        let _passthrough = Passthrough::enter();
        lock(&self.handles).get(&handle).copied()
    }
}

/// The name a thread is listed under when it never named itself.
pub(crate) fn fallback_name(lineage: u64) -> Arc<str> {
    let _passthrough = Passthrough::enter();
    Arc::from(format!("thread-{lineage:x}"))
}

#[cfg(all(test, target_os = "linux"))]
mod release_tests {
    use super::*;

    fn park(core: &mut Core, lineage: u64, mask: u32) {
        core.rows.entry(lineage).or_insert(Row {
            class: ThreadClass::Participant,
            wait: None,
            since: (Duration::ZERO, Duration::ZERO),
            last_wait: None,
        });
        core.set_waiting(
            lineage,
            Some(RowWait {
                label: Some("futex"),
                deadline: None,
                key: Some(1),
                mutex: None,
                mask,
                token: 0,
                expected: Some(0),
                futex_private: Some(true),
                pre_released: false,
                claimed: false,
            }),
            None,
        );
    }

    #[test]
    fn overlapping_masks_allow_either_compatible_return_order() {
        for (first, second) in [(1, 2), (1, 3), (2, 1), (2, 3), (3, 1), (3, 2)] {
            let mut core = Core::default();
            park(&mut core, 1, 3);
            park(&mut core, 2, 1);
            park(&mut core, 3, 2);
            core.signal_futex(1, 1, 1, true, || None);
            core.signal_futex(1, 1, 2, true, || None);
            assert!(core.claim_release(first));
            core.set_waiting(first, None, None);
            assert!(core.claim_release(second));
            core.set_waiting(second, None, None);
            assert!(!core.has_pending_releases());
            assert!(!core.claim_release(6 - first - second));
        }
    }

    #[test]
    fn completed_wait_generations_do_not_leave_receipts_on_later_wakes() {
        let mut core = Core::default();
        park(&mut core, 1, 3);
        park(&mut core, 2, 1);
        park(&mut core, 3, 2);
        core.signal_futex(1, 1, 1, true, || None);
        core.signal_futex(1, 1, 2, true, || None);
        assert!(core.claim_release(1));
        core.set_waiting(1, None, None);
        for _ in 0..1000 {
            park(&mut core, 4, 3);
            core.signal_futex(1, 1, 3, true, || None);
            assert!(core.claim_release(4));
            core.set_waiting(4, None, None);
            let pending = &core.signalled[&1];
            assert_eq!(pending.claims.len(), 1);
            assert_eq!(
                pending
                    .records()
                    .map(|record| record.remaining)
                    .sum::<usize>(),
                2
            );
        }
        assert!(core.claim_release(2));
        core.set_waiting(2, None, None);
        assert!(!core.has_pending_releases());
        assert!(!core.claim_release(3));
    }

    #[test]
    fn timed_out_generation_cannot_spend_a_compatible_remaining_credit() {
        let mut core = Core::default();
        park(&mut core, 1, 3);
        park(&mut core, 2, 1);
        park(&mut core, 3, 2);
        core.signal_futex(1, 1, 1, true, || None);
        core.signal_futex(1, 1, 2, true, || None);
        assert!(core.claim_release(1));
        core.set_waiting(1, None, None);
        core.set_waiting(2, None, None);
        park(&mut core, 2, 1);
        assert!(!core.claim_release(2));
        assert!(core.claim_release(3));
        core.set_waiting(3, None, None);
        assert!(!core.has_pending_releases());
    }

    #[test]
    fn unsuccessful_wakes_only_release_changed_expected_values_once() {
        let mut core = Core::default();
        park(&mut core, 1, 1);
        park(&mut core, 2, 2);
        for _ in 0..1000 {
            core.signal_futex(1, 0, 1, true, || Some(1));
        }
        assert!(core.claim_release(1));
        core.set_waiting(1, None, None);
        assert!(!core.has_pending_releases());
        assert!(!core.claim_release(2));
        core.signal_futex(1, 0, 2, true, || Some(0));
        assert!(!core.has_pending_releases());
    }

    #[test]
    fn a_kernel_wake_and_a_pre_enrollment_return_keep_separate_receipts() {
        for (first, second) in [(1, 2), (2, 1)] {
            let mut core = Core::default();
            park(&mut core, 1, 1);
            park(&mut core, 2, 1);
            core.signal_futex(1, 1, 1, true, || Some(1));
            core.note_futex_pre_enrollment_return(2);
            assert!(core.claim_release(first));
            core.set_waiting(first, None, None);
            assert!(core.has_pending_releases());
            assert!(core.claim_release(second));
            core.set_waiting(second, None, None);
            assert!(!core.has_pending_releases());
        }
    }

    #[test]
    fn a_changed_condvar_word_does_not_release_unwoken_kernel_waiters() {
        let mut core = Core::default();
        for lineage in 1..=5 {
            park(&mut core, lineage, u32::MAX);
        }
        core.signal_futex(1, 1, u32::MAX, true, || Some(1));
        assert!(core.claim_release(1));
        core.set_waiting(1, None, None);
        assert!(!core.has_pending_releases());
        for lineage in 2..=5 {
            assert!(!core.claim_release(lineage));
        }
    }

    #[test]
    fn private_and_shared_keys_keep_separate_release_receipts() {
        let mut core = Core::default();
        park(&mut core, 1, 3);
        park(&mut core, 2, 3);
        core.rows
            .get_mut(&2)
            .unwrap()
            .wait
            .as_mut()
            .unwrap()
            .futex_private = Some(false);
        core.signal_futex(1, 0, 1, true, || Some(1));
        assert!(!core.claim_release(2));
        assert!(core.claim_release(1));
        core.set_waiting(1, None, None);
        assert!(!core.has_pending_releases());
        park(&mut core, 1, 3);
        core.signal_futex(1, 1, 2, true, || Some(0));
        assert!(!core.claim_release(2));
        assert!(core.claim_release(1));
        core.set_waiting(1, None, None);
        assert!(!core.has_pending_releases());
        core.signal_futex(1, 1, 2, false, || Some(0));
        assert!(core.claim_release(2));
        core.set_waiting(2, None, None);
        assert!(!core.has_pending_releases());
    }
}

#[cfg(all(test, windows))]
mod timer_release_tests {
    use super::*;

    fn park(accounting: &Accounting, core: &mut Core, lineage: u64, key: usize) {
        let mut signals = accounting.timer_signals();
        accounting.drain_timer_signals(core, &mut signals);
        let wait = RowWait {
            label: Some("sleep"),
            deadline: None,
            key: Some(key),
            mutex: None,
            token: signals.admit(),
            woken: false,
        };
        core.rows.entry(lineage).or_insert(Row {
            class: ThreadClass::Participant,
            wait: None,
            since: (Duration::ZERO, Duration::ZERO),
            last_wait: None,
        });
        core.set_waiting(lineage, Some(wait), None);
        accounting.keyed.fetch_add(1, Ordering::SeqCst);
    }

    fn auto_event() -> windows_sys::Win32::Foundation::HANDLE {
        unsafe {
            windows_sys::Win32::System::Threading::CreateEventExW(
                std::ptr::null(),
                std::ptr::null(),
                0,
                windows_sys::Win32::System::Threading::EVENT_ALL_ACCESS,
            )
        }
    }

    fn signal_auto_event(handle: windows_sys::Win32::Foundation::HANDLE) -> usize {
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtSetEvent(
                handle: windows_sys::Win32::Foundation::HANDLE,
                previous: *mut i32,
            ) -> i32;
        }
        let mut previous = 0;
        assert!(unsafe { NtSetEvent(handle, &mut previous) } >= 0);
        usize::from(previous == 0)
    }

    #[test]
    fn coalesced_auto_event_signals_offer_only_one_native_release() {
        let _passthrough = Passthrough::enter();
        let handle = auto_event();
        assert!(!handle.is_null());
        let accounting = Accounting::default();
        let mut core = accounting.core();
        park(&accounting, &mut core, 1, 7);
        park(&accounting, &mut core, 2, 7);
        for _ in 0..2 {
            accounting.defer_timer_signal(7, Arc::new(()), || signal_auto_event(handle));
        }
        accounting.flush_timer_signals(&mut core);
        assert_eq!(
            unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(handle, 0) },
            0
        );
        core.set_waiting(2, None, None);
        assert_eq!(
            unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(handle, 0) },
            258
        );
        assert!(!core.has_pending_releases());
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(handle);
        }
    }

    #[test]
    fn native_auto_event_poll_consumption_retires_the_latched_receipt() {
        let _passthrough = Passthrough::enter();
        let handle = auto_event();
        let accounting = Accounting::default();
        let mut core = accounting.core();
        park(&accounting, &mut core, 1, 7);
        accounting.defer_timer_signal(7, Arc::new(()), || signal_auto_event(handle));
        let mut signals = accounting.timer_signals();
        accounting.drain_timer_signals(&mut core, &mut signals);
        assert_eq!(
            unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(handle, 0) },
            0
        );
        core.consume_timer_event(7);
        assert!(!core.has_pending_releases());
        assert_eq!(
            unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(handle, 0) },
            258
        );
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(handle);
        }
    }

    #[test]
    fn audit_reset_keeps_a_live_physical_timer_release() {
        let accounting = Accounting::default();
        let mut core = accounting.core();
        park(&accounting, &mut core, 1, 7);
        accounting.defer_timer_signal(7, Arc::new(()), || 1);
        accounting.flush_timer_signals(&mut core);
        core.clear_signalled();
        assert_eq!(core.first_released(), Some(1));
        core.take_release(1);
        assert!(!core.has_pending_releases());
    }

    #[test]
    fn deferred_timer_release_excludes_a_later_wait_on_the_same_key() {
        let accounting = Accounting::default();
        let lifetime = Arc::new(());
        let weak = Arc::downgrade(&lifetime);
        let mut core = accounting.core();
        park(&accounting, &mut core, 1, 7);
        accounting.defer_timer_signal(7, lifetime, || 1);
        accounting.flush_timer_signals(&mut core);
        assert_eq!(core.first_released(), Some(1));
        assert!(weak.upgrade().is_some());
        park(&accounting, &mut core, 2, 7);
        core.set_waiting(1, None, None);
        assert_eq!(core.first_released(), None);
        assert!(!core.has_pending_releases());
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn deferred_auto_reset_release_is_claimed_by_the_returning_waiter() {
        for returning in [1, 2] {
            let accounting = Accounting::default();
            let mut core = accounting.core();
            park(&accounting, &mut core, 1, 7);
            park(&accounting, &mut core, 2, 7);
            accounting.defer_timer_signal(7, Arc::new(()), || 1);
            accounting.flush_timer_signals(&mut core);
            assert!(core.timer_released(core.rows[&returning].wait.unwrap()));
            assert!(core.take_release(returning));
            assert_eq!(core.first_released(), None);
            assert!(!core.has_pending_releases());
        }
    }

    #[test]
    fn deferred_manual_reset_release_keeps_the_remaining_waiters_settling() {
        let accounting = Accounting::default();
        let mut core = accounting.core();
        park(&accounting, &mut core, 1, 7);
        park(&accounting, &mut core, 2, 7);
        accounting.defer_timer_signal(7, Arc::new(()), || usize::MAX);
        accounting.flush_timer_signals(&mut core);
        core.take_release(2);
        assert_eq!(core.first_released(), Some(1));
        core.take_release(1);
        assert!(!core.has_pending_releases());
    }

    #[test]
    fn repeated_unclaimed_signals_coalesce_and_retire_with_their_waiters() {
        let accounting = Accounting::default();
        let mut core = accounting.core();
        park(&accounting, &mut core, 1, 7);
        for _ in 0..1000 {
            accounting.defer_timer_signal(7, Arc::new(()), || 1);
        }
        assert_eq!(accounting.timer_signals().pending.len(), 1);
        accounting.flush_timer_signals(&mut core);
        assert_eq!(core.timer_releases.len(), 1);
        assert_eq!(core.timer_releases[0].remaining, 1);
        core.set_waiting(1, None, None);
        assert!(!core.has_pending_releases());
    }
}
