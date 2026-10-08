//! Deterministic scheduling for one domain: exactly one managed thread runs at a time, and control
//! passes only where a thread waits — a sim wait, a mutex, condition variable, futex, semaphore or
//! address wait, a join, a yield — to the next runnable thread in a fixed order. The order follows
//! the threads' lineage ids, which come from what the code does rather than how the OS schedules
//! it, so a run replays exactly.
//!
//! The waits are emulated rather than handed to the kernel: a waiter parks here, and the thread
//! that would have woken it through the kernel — necessarily the one running — moves it to the run
//! queue directly. Nothing is woken behind the scheduler's back, so who runs next never depends on
//! timing. When nothing can run, virtual time moves to the next deadline; with none left, sim waits
//! give up as a deadlock would make them — unless the clock is held (paused) or a lease holds the
//! domain busy, when the schedule idles until something outside the simulation moves time or gives
//! the lease back and [`Scheduler::kick`]s it. Once no sim wait is left to give up, the timers of
//! threads outside the schedule move time, since only those threads can release the rest.
//!
//! Only participants run in the schedule. A thread of another class runs freely beside it; what it
//! wakes still reaches the schedule, and while no thread holds the baton its wake hands it on.
//!
//! Invariants, all under the [`State`] lock: at most one thread holds the baton (`holder`); a
//! thread is at most one of runnable and blocked, and the holder is neither; a key's waiters wake
//! in the order they began to wait. The thread that lets go of the baton with nothing runnable runs
//! [`Scheduler::dispatch`] itself, or delegates it to a parked thread ([`Grant::Dispatch`]) when it
//! is leaving the schedule, so exactly one thread drives the schedule while it is idle.
//!
//! Lock order: the [`State`] lock may be held while taking a [`Parker`]'s lock (to delegate), but a
//! parker's lock is never held while taking the state lock — a parked thread lets go of its parker
//! before re-locking the state. Every entry point that
//! locks runs under [`Passthrough`] (callers of [`Scheduler::lock`] enter it themselves), so the
//! scheduler's own mutexes and condition variables are not hooked back into it. The domain's
//! census lock, when both are needed, is taken first (see `Domain::if_quiescent`).

#[cfg(windows)]
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

#[cfg(any(unix, windows))]
use crate::pending::MutexRecord;
use crate::pending::Pending;
use crate::stall::{Idle, STALL_WARN};
use crate::state::Passthrough;

/// What a deterministic wait waits for.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DetKey {
    /// A change in the simulation's sockets or clock (the sim's readiness signal).
    Readiness,
    /// A wake on a memory address: a futex word, a mutex, a condition variable, a semaphore.
    Addr(usize),
    /// The exit of the thread with this lineage id (a join).
    Exit(u64),
}

/// A stable source of simulated descriptor readiness.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ReadinessKey {
    /// A simulated socket's open description.
    Socket(u64),
    /// A simulated non-socket open description.
    #[cfg(unix)]
    Descriptor(u64),
    #[cfg(windows)]
    CompletionPort(u64),
}

/// Which subscriptions a readiness notification reaches.
#[derive(Clone, Copy)]
pub enum ReadinessWake<'a> {
    /// Every subscription.
    All,
    /// Subscriptions with deadlines or pending delayed arrivals.
    Timer,
    /// Subscriptions to any named open description.
    Keys(&'a [ReadinessKey]),
}

pub(crate) struct ReadinessInterest {
    inline: [ReadinessKey; 8],
    len: usize,
    overflow: Vec<ReadinessKey>,
    broad: bool,
    timed: bool,
}

impl ReadinessInterest {
    pub(crate) fn new(keys: Option<&[ReadinessKey]>, timed: bool) -> Self {
        let mut interest = Self {
            inline: [ReadinessKey::Socket(0); 8],
            len: 0,
            overflow: Vec::new(),
            broad: keys.is_none(),
            timed,
        };
        if let Some(keys) = keys {
            interest.len = keys.len();
            if keys.len() <= interest.inline.len() {
                interest.inline[..keys.len()].copy_from_slice(keys);
            } else {
                interest.overflow.extend_from_slice(keys);
            }
        }
        interest
    }

    fn matches(&self, event: ReadinessWake<'_>) -> bool {
        self.broad
            || match event {
                ReadinessWake::All => true,
                ReadinessWake::Timer => self.timed,
                ReadinessWake::Keys(keys) => {
                    let interests = if self.overflow.is_empty() {
                        &self.inline[..self.len]
                    } else {
                        &self.overflow
                    };
                    keys.iter().any(|key| interests.contains(key))
                }
            }
    }
}

/// Why a deterministic wait ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DetWake {
    /// Woken by the key's waker (or re-polled; waits re-check their condition either way).
    Woken,
    /// Its deadline passed.
    TimedOut,
    /// Nothing could ever wake it: every thread was blocked with no time left to pass.
    Deadlock,
}

thread_local! {
    /// Set when a wait nested in a dispatch this thread runs while blocked spoiled the wait it is
    /// blocked in (see `os::nested`), so it re-polls once the dispatch is over.
    static REPOLL_SELF: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

thread_local! {
    /// Set while the calling thread waits in the schedule for a lock a thread outside it holds
    /// (see [`outside_holder`]).
    static OUTSIDE_HOLDER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Returned by [`outside_holder`]; restores the flag when dropped.
pub(crate) struct OutsideHolder(bool);

impl Drop for OutsideHolder {
    fn drop(&mut self) {
        let _ = OUTSIDE_HOLDER.try_with(|o| o.set(self.0));
    }
}

/// Marks the calling thread's waits in the schedule, until the guard drops, as waits for a lock
/// held by a thread outside it: something only that thread does ends them, so they no more make the
/// schedule deadlocked than a wait on a word in static data does (see
/// [`Scheduler::blocked_on_shared_word`]).
pub(crate) fn outside_holder() -> OutsideHolder {
    OutsideHolder(
        OUTSIDE_HOLDER
            .try_with(|o| o.replace(true))
            .unwrap_or(false),
    )
}

/// Asks for the calling thread's wait in the schedule to be re-polled once the dispatch it is
/// running is over (see [`Scheduler::repoll_if_spoiled`]).
pub(crate) fn repoll_self() {
    let _ = REPOLL_SELF.try_with(|r| r.set(true));
}

/// Clears a [`repoll_self`] no dispatch took.
pub(crate) fn clear_repoll_self() {
    let _ = REPOLL_SELF.try_with(|r| r.set(false));
}

/// What a parked thread is handed.
#[derive(Clone, Copy)]
enum Grant {
    /// The baton, with why the thread was made ready.
    Run(DetWake),
    /// The duty of moving the schedule on (time skips, deadlock resolution, real-time idling) while
    /// it stays blocked, for a thread that left the schedule and must not wait on its behalf.
    Dispatch,
}

/// Where a parked thread waits to be handed the baton. One per thread, kept in its [`Slot`] and
/// shared by `Arc` so a grant can be made after the state lock is released.
#[derive(Default)]
struct Parker {
    /// The pending grant, taken by the parked thread. A one-slot latch: a grant made before the
    /// thread parks is kept, so none is lost to the race between granting and waiting.
    grant: Mutex<Option<Grant>>,
    /// Signalled when `grant` is filled.
    granted: Condvar,
}

impl Parker {
    /// Hands the thread the baton, overwriting a pending [`Grant::Dispatch`]: running supersedes
    /// the duty to move the schedule on.
    fn grant(&self, why: DetWake) {
        *self.grant.lock().unwrap() = Some(Grant::Run(why));
        self.granted.notify_one();
    }

    /// Hands the thread the duty of dispatching, unless a grant is already pending (a pending run
    /// grant must not be replaced, and a pending dispatch need not be repeated).
    fn delegate(&self) {
        let mut grant = self.grant.lock().unwrap();
        if grant.is_none() {
            *grant = Some(Grant::Dispatch);
            self.granted.notify_one();
        }
    }

    /// Drops a pending grant, as the thread leaves the schedule: one made meanwhile went to a
    /// thread no longer waiting for it.
    fn forget(&self) {
        *self.grant.lock().unwrap() = None;
    }

    /// Blocks until a grant is pending and takes it, looping over the condition variable's
    /// spurious wakeups (POSIX `pthread_cond_wait`; std's `Condvar::wait` documents the same).
    fn wait(&self) -> Grant {
        let mut grant = self.grant.lock().unwrap();
        loop {
            if let Some(grant) = grant.take() {
                return grant;
            }
            grant = self.granted.wait(grant).unwrap();
        }
    }
}

/// A thread parked in the schedule.
struct Blocked {
    /// What wakes it.
    key: DetKey,
    mask: u32,
    futex_private: Option<bool>,
    readiness: Option<ReadinessInterest>,
    /// The virtual monotonic time it times out at, if any.
    deadline: Option<Duration>,
    signal_version: Option<u64>,
    futex_value: Option<u32>,
    #[cfg(windows)]
    address_value: Option<(usize, u64)>,
    #[cfg(windows)]
    timer_waker: bool,
    /// Waiting for a lock a thread outside the schedule holds (see [`outside_holder`]).
    outside_holder: bool,
}

impl Blocked {
    /// Whether only the wake of a timer the waiter registered itself ends the wait, as for a
    /// Windows waitable timer, rather than a re-poll.
    fn woken_by_timer(&self) -> bool {
        #[cfg(windows)]
        return self.timer_waker;
        #[cfg(not(windows))]
        false
    }

    fn should_repoll(&self) -> bool {
        let DetKey::Addr(addr) = self.key else {
            return false;
        };
        #[cfg(windows)]
        if self.timer_waker {
            return false;
        }
        #[cfg(windows)]
        if let Some((size, value)) = self.address_value {
            return unsafe { crate::os::windows::address_value(addr, size) } != value;
        }
        #[cfg(target_os = "linux")]
        let current_signal =
            crate::os::sync::signal_version_masked(addr, self.mask, self.futex_private);
        #[cfg(not(target_os = "linux"))]
        let current_signal = signal_version(addr);
        let signalled = self
            .signal_version
            .is_some_and(|version| current_signal != Some(version));
        match self.futex_value {
            Some(value) => signalled || futex_value(addr) != value,
            None => self.signal_version.is_none() || signalled,
        }
    }

    /// Whether what the wait is for changed since it began, for a wait that records how to tell
    /// (a condition variable's signal count, a futex word, a Windows address): a thread outside
    /// the schedule acted between the waiter's last look and its listing (see
    /// `domain::det_foreign`).
    fn changed_outside(&self) -> bool {
        #[cfg(windows)]
        let recorded = self.address_value.is_some();
        #[cfg(not(windows))]
        let recorded = false;
        (recorded || self.signal_version.is_some() || self.futex_value.is_some())
            && self.should_repoll()
    }
}

/// The holder of the baton while an executive runs a timestamp: no lineage, since lineages are
/// SplitMix64 outputs over a parent and a birth order and never reach this value in practice
/// (a snare choice of sentinel; `hold_external` debug-asserts no thread has a parker under it).
pub(crate) const EXTERNAL: u64 = u64::MAX;

/// A deterministic schedule's state, behind [`Scheduler::lock`]. Threads are named by lineage id.
///
/// What a lock, unlock, wait or wake does under the lock neither allocates nor frees: a thread
/// inside a C allocator, holding one of its locks, may be waiting for this one, and the allocation
/// could need that lock. Each thread's share lives in its [`Slot`], made before the lock is taken
/// ([`Scheduler::lock_with_room`]), and the tables only ever grow with the lock let go.
#[derive(Default)]
pub(crate) struct State {
    /// The lineage id of the thread allowed to run.
    holder: Option<u64>,
    /// Every thread the schedule has met and that has not left the domain, by lineage.
    threads: Threads,
    /// How many threads are ready to run (`Slot::runnable`).
    runnable: usize,
    /// How many threads are waiting (`Slot::blocked`).
    blocked: usize,
    /// The order threads began to wait in, for each key's waiters to wake oldest first.
    next_wait: u64,
    /// The last thread handed the baton: the round-robin cursor.
    last: u64,
    /// Threads that have left the domain, in order, so a late join on one returns at once and
    /// [`Scheduler::lineage_of`] no longer names a handle the OS may have reused: a `pthread_t`'s
    /// lifetime ends once the thread has terminated and been joined or detached, after which it
    /// may be reused (POSIX XSH 2.9.2 "Thread IDs"), and a Windows thread id is unique only "until
    /// the thread terminates" ([Microsoft Learn: GetCurrentThreadId function](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadid)).
    exited: Vec<u64>,
    /// OS thread handles of this domain's threads, for joins, in order: the `pthread_t` from
    /// `pthread_self` on unix, the thread id from `GetCurrentThreadId` on Windows (see
    /// `os::current_thread_handle`).
    handles: Vec<(usize, u64)>,
    /// When, in real time (`accounting::real_elapsed`), the current stretch of real-time waits
    /// with nothing else able to move began, for the stall warning; `None` once the baton is
    /// granted.
    idle_since: Option<Duration>,
    /// Whether the current idle stretch has been warned about.
    warned: bool,
    /// How many waits participants have begun in the schedule: the deterministic counterpart of a
    /// census park moving the epoch, which the stall watchdog counts as progress. A yield is not a
    /// wait, so threads yielding to each other make none.
    pub(crate) waits: u64,
    /// Threads inside [`Scheduler::enter_root`] that have not yet left.
    roots: usize,
    /// Keys a wake from outside the schedule reached while none of their waiters was blocked: the
    /// next wait on one returns at once (see `domain::det_foreign`).
    foreign: ForeignKeys,
    /// Which of this domain's threads holds each pthread mutex, by address. A mutex held by none
    /// of them is held outside the domain — by another test's simulation or an unmanaged thread.
    #[cfg(any(unix, windows))]
    owners: MutexOwners,
    #[cfg(windows)]
    shared_owners: HashMap<usize, std::collections::BTreeSet<u64>>,
}

/// One thread's share of the schedule.
struct Slot {
    /// Where it waits for the baton, shared by `Arc` so a grant can be made after the state lock
    /// is released.
    parker: Arc<Parker>,
    /// Ready to run, with why it was made ready.
    runnable: Option<DetWake>,
    /// Waiting, with what for and when it began (`State::next_wait`).
    blocked: Option<(Blocked, u64)>,
    /// Re-polled for something outside the sim while waiting, with the key it waited on, to tell
    /// whether the re-poll found progress.
    repolled: Option<DetKey>,
    /// Let go when the schedule detached, and not yet waiting in it again.
    let_go: bool,
    /// Let go and now in a native wait, with the key a wake in the schedule releases it with.
    outside: Option<DetKey>,
    /// Caught in a spin (see `domain::clock_spin`), with whether its last step polled the clock. A
    /// runnable thread spinning waits on time rather than having work to do.
    spinner: Option<bool>,
}

impl Slot {
    fn new(parker: Arc<Parker>) -> Self {
        Self {
            parker,
            runnable: None,
            blocked: None,
            repolled: None,
            let_go: false,
            outside: None,
            spinner: None,
        }
    }
}

/// The schedule's threads, ordered by lineage. Room for more is made only with the state lock let
/// go (see [`Scheduler::lock_with_room`]).
#[derive(Default)]
struct Threads(Vec<(u64, Slot)>);

impl Threads {
    fn get(&self, t: u64) -> Option<&Slot> {
        let i = self.0.binary_search_by_key(&t, |&(t, _)| t).ok()?;
        Some(&self.0[i].1)
    }

    fn get_mut(&mut self, t: u64) -> Option<&mut Slot> {
        let i = self.0.binary_search_by_key(&t, |&(t, _)| t).ok()?;
        Some(&mut self.0[i].1)
    }

    /// `t`'s slot, made with the parker taken out of `parker` if it has none; `None` if it has
    /// none and there is no room or no parker for one.
    fn get_or_insert(
        &mut self,
        t: u64,
        parker: &mut Option<Arc<Parker>>,
    ) -> Option<&mut Slot> {
        let i = match self.0.binary_search_by_key(&t, |&(t, _)| t) {
            Ok(i) => i,
            Err(i) => {
                if self.0.len() == self.0.capacity() {
                    return None;
                }
                self.0.insert(i, (t, Slot::new(parker.take()?)));
                i
            }
        };
        Some(&mut self.0[i].1)
    }

    fn remove(&mut self, t: u64) -> Option<Slot> {
        let i = self.0.binary_search_by_key(&t, |&(t, _)| t).ok()?;
        Some(self.0.remove(i).1)
    }

    fn iter(&self) -> impl Iterator<Item = (u64, &Slot)> {
        self.0.iter().map(|(t, slot)| (*t, slot))
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = (u64, &mut Slot)> {
        self.0.iter_mut().map(|(t, slot)| (*t, slot))
    }
}

/// How many keys [`ForeignKeys`] keeps. A snare choice, far past the waits that race a wake from
/// outside at once; past it one is forgotten, and its waiter is left to the re-poll that catches
/// what changed outside the schedule.
const FOREIGN_KEYS: usize = 64;

/// [`State::foreign`]: a fixed set, as an outside wake may come from a thread inside an allocator.
struct ForeignKeys {
    keys: [Option<DetKey>; FOREIGN_KEYS],
    /// The slot the next key takes when none is free.
    next: usize,
}

impl Default for ForeignKeys {
    fn default() -> Self {
        Self {
            keys: [None; FOREIGN_KEYS],
            next: 0,
        }
    }
}

impl ForeignKeys {
    fn insert(&mut self, key: DetKey) {
        if self.keys.contains(&Some(key)) {
            return;
        }
        let slot = match self.keys.iter().position(Option::is_none) {
            Some(free) => free,
            None => {
                self.next = (self.next + 1) % FOREIGN_KEYS;
                self.next
            }
        };
        self.keys[slot] = Some(key);
    }

    fn remove(&mut self, key: DetKey) -> bool {
        match self.keys.iter().position(|&k| k == Some(key)) {
            Some(i) => {
                self.keys[i] = None;
                true
            }
            None => false,
        }
    }

    fn clear(&mut self) {
        self.keys = [None; FOREIGN_KEYS];
    }
}

impl State {
    /// The thread that holds the baton or is next to, if any: the schedule is not idle.
    pub(crate) fn running(&self) -> Option<u64> {
        self.holder.filter(|&t| t != EXTERNAL).or_else(|| {
            self.threads
                .iter()
                .find(|(_, slot)| slot.runnable.is_some())
                .map(|(t, _)| t)
        })
    }

    /// How many threads are running or ready, and how many are blocked.
    pub(crate) fn counts(&self) -> (usize, usize) {
        let holding = usize::from(self.holder.is_some_and(|t| t != EXTERNAL));
        (self.runnable + holding, self.blocked)
    }

    /// Takes the baton for an executive; called only on an idle schedule.
    pub(crate) fn hold_external(&mut self) {
        debug_assert!(
            self.threads.get(EXTERNAL).is_none(),
            "a thread has the executive's lineage"
        );
        self.holder = Some(EXTERNAL);
    }

    fn idle(&self) -> bool {
        self.holder.is_none() && self.runnable == 0
    }

    /// The participant holding the baton, if any (an executive's hold is not a participant's).
    pub(crate) fn holder(&self) -> Option<u64> {
        self.holder.filter(|&t| t != EXTERNAL)
    }

    /// Whether an executive holds the baton for a timestamp.
    pub(crate) fn held_externally(&self) -> bool {
        self.holder == Some(EXTERNAL)
    }

    /// Notes one more real-time wait of an idle stretch: `true` once, the first time the stretch
    /// has lasted [`STALL_WARN`].
    fn note_idle(&mut self) -> bool {
        let now = crate::accounting::real_elapsed();
        let since = *self.idle_since.get_or_insert(now);
        if self.warned || now.saturating_sub(since) < STALL_WARN {
            return false;
        }
        self.warned = true;
        true
    }

    /// Ends an idle stretch: something moved.
    fn end_idle(&mut self) {
        self.idle_since = None;
        self.warned = false;
    }

    /// A re-polled waiter did something: progress, unless it only blocked again on the same key.
    fn settle_repoll(&mut self, t: u64, blocked_on: Option<DetKey>) {
        if let Some(key) = self.threads.get_mut(t).and_then(|slot| slot.repolled.take())
            && blocked_on != Some(key)
        {
            crate::domain::count_outside_wake();
        }
    }

    /// Makes `t` ready to run with `why`, replacing why it was made ready if it already was.
    fn set_runnable(&mut self, t: u64, why: DetWake) {
        if let Some(slot) = self.threads.get_mut(t)
            && slot.runnable.replace(why).is_none()
        {
            self.runnable += 1;
        }
    }

    /// Makes `t` ready to run with `why` unless it already is.
    fn set_runnable_if_not(&mut self, t: u64, why: DetWake) {
        if let Some(slot) = self.threads.get_mut(t)
            && slot.runnable.is_none()
        {
            slot.runnable = Some(why);
            self.runnable += 1;
        }
    }

    fn take_runnable(&mut self, t: u64) -> Option<DetWake> {
        let why = self.threads.get_mut(t)?.runnable.take()?;
        self.runnable -= 1;
        Some(why)
    }

    fn is_runnable(&self, t: u64) -> bool {
        self.threads.get(t).is_some_and(|slot| slot.runnable.is_some())
    }

    /// Records `t` waiting in `blocked`, after every wait begun before it.
    fn set_blocked(&mut self, t: u64, blocked: Blocked) {
        let order = self.next_wait;
        if let Some(slot) = self.threads.get_mut(t) {
            if slot.blocked.replace((blocked, order)).is_none() {
                self.blocked += 1;
            }
            self.next_wait += 1;
        }
    }

    fn take_blocked(&mut self, t: u64) -> Option<Blocked> {
        let (blocked, _) = self.threads.get_mut(t)?.blocked.take()?;
        self.blocked -= 1;
        Some(blocked)
    }

    fn blocked(&self) -> impl Iterator<Item = (u64, &Blocked)> {
        self.threads
            .iter()
            .filter_map(|(t, slot)| slot.blocked.as_ref().map(|(b, _)| (t, b)))
    }

    /// The first blocked thread's parker, which takes over moving the schedule on.
    fn first_blocked_parker(&self) -> Option<&Arc<Parker>> {
        self.threads
            .iter()
            .find(|(_, slot)| slot.blocked.is_some())
            .map(|(_, slot)| &slot.parker)
    }
}

/// Room [`Scheduler::lock_with_room`] makes in the state's tables before handing it out.
#[derive(Clone, Copy, Default)]
struct Room {
    /// New threads, each with room to leave the domain later.
    threads: usize,
    /// New thread handles.
    handles: usize,
}

/// A wake from outside a schedule, queued for it: (key, count, futex mask, futex scope).
type ForeignWake = (DetKey, usize, u32, Option<bool>);

/// A domain's deterministic scheduler.
#[derive(Default)]
pub(crate) struct Scheduler {
    /// Everything the schedule decides on; see [`Scheduler::lock`].
    state: Mutex<State>,
    /// Signalled whenever the schedule goes idle, for an executive waiting to take the baton.
    went_idle: Condvar,
    /// Every root has left and nothing could run: the threads still alive (daemons the code under
    /// test left behind) run outside the schedule until a thread enters the domain again.
    detached: AtomicBool,
    /// Wakes from outside the schedule made while [`state`](Self::state) was held, as (key, count,
    /// futex mask, futex scope), for its holder to deliver: it may be waiting, holding it, on the
    /// very thread that made them (a layer's time skip runs the code under test's wakers).
    foreign_queue: Pending<ForeignWake>,
    /// How many threads are let go (`Slot::let_go`), so a hook on any other thread skips the
    /// state lock in [`rejoin`](Self::rejoin).
    let_go: AtomicUsize,
    /// Mutexes taken and let go while [`state`](Self::state) was held, for its next holder to
    /// record in `owners` (see `crate::pending`).
    #[cfg(any(unix, windows))]
    owner_records: Pending<MutexRecord>,
}

/// How many mutexes [`MutexOwners`] tracks at once. A snare choice, far past the mutexes a
/// domain's threads hold at once; one taken while it is full goes unrecorded, and so counts as
/// held outside the domain.
#[cfg(any(unix, windows))]
const OWNED_MUTEXES: usize = 1024;

/// Which thread holds each mutex, by address, in a table made with the schedule, so recording a
/// hold never allocates: the thread recording it may be inside a C allocator, holding the lock an
/// allocation would need. Open addressing with linear probing; address 0 marks a free slot.
#[cfg(any(unix, windows))]
struct MutexOwners(Box<[(usize, u64)]>);

#[cfg(any(unix, windows))]
impl Default for MutexOwners {
    fn default() -> Self {
        Self(vec![(0, 0); OWNED_MUTEXES].into_boxed_slice())
    }
}

#[cfg(any(unix, windows))]
impl MutexOwners {
    const MASK: usize = OWNED_MUTEXES - 1;

    fn home(addr: usize) -> usize {
        let hash = ((addr >> 3) as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        (hash >> (64 - OWNED_MUTEXES.trailing_zeros())) as usize
    }

    /// The slot holding `addr`, or the free slot where it would go; `None` if neither is found.
    fn find(&self, addr: usize) -> Option<usize> {
        let mut i = Self::home(addr);
        for _ in 0..OWNED_MUTEXES {
            let slot = self.0[i].0;
            if slot == addr || slot == 0 {
                return Some(i);
            }
            i = (i + 1) & Self::MASK;
        }
        None
    }

    fn insert(&mut self, addr: usize, owner: u64) {
        if let Some(i) = self.find(addr) {
            self.0[i] = (addr, owner);
        }
    }

    fn contains(&self, addr: usize) -> bool {
        self.find(addr).is_some_and(|i| self.0[i].0 == addr)
    }

    /// Frees `addr`'s slot, moving back each later entry of its probe run that may fill it.
    fn remove(&mut self, addr: usize) {
        let Some(mut hole) = self.find(addr).filter(|&i| self.0[i].0 == addr) else {
            return;
        };
        let mut j = hole;
        loop {
            j = (j + 1) & Self::MASK;
            let entry = self.0[j];
            if entry.0 == 0 {
                break;
            }
            let home = Self::home(entry.0);
            if (j.wrapping_sub(home) & Self::MASK) >= (j.wrapping_sub(hole) & Self::MASK) {
                self.0[hole] = entry;
                hole = j;
            }
        }
        self.0[hole] = (0, 0);
    }

    /// One of the mutexes `owner` holds.
    fn held_by(&self, owner: u64) -> Option<usize> {
        self.0
            .iter()
            .find(|&&(addr, o)| addr != 0 && o == owner)
            .map(|&(addr, _)| addr)
    }

    #[cfg(test)]
    fn owner(&self, addr: usize) -> Option<u64> {
        let i = self.find(addr)?;
        (self.0[i].0 == addr).then_some(self.0[i].1)
    }

    fn apply(&mut self, record: MutexRecord) {
        if record.taken {
            self.insert(record.mutex, record.lineage);
        } else {
            self.remove(record.mutex);
        }
    }
}

/// How long the scheduler waits in real time, when every thread is blocked on a lock or address
/// with nothing in the sim able to release it, before re-polling those waiters: something outside
/// the sim (an unmanaged thread holding the lock) may have changed what they wait on. Also the
/// longest real-time step of an idling dispatch and of an executive waiting for an idle schedule.
/// A snare choice, not an OS value: short enough that an outside release is noticed promptly,
/// long enough that a stuck schedule costs little CPU.
const OUTSIDE_POLL: Duration = Duration::from_millis(1);

impl Scheduler {
    /// Locks the schedule's state, recovering it from a poisoned lock: a panic on a thread that
    /// held it must not wedge every other thread of the domain. The caller enters passthrough
    /// first.
    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.take_owner_records(&mut st);
        st
    }

    /// The state if no other thread holds it, its queued owner records taken.
    fn try_lock(&self) -> Option<MutexGuard<'_, State>> {
        let mut st = match self.state.try_lock() {
            Ok(st) => st,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return None,
        };
        self.take_owner_records(&mut st);
        Some(st)
    }

    /// [`lock`](Self::lock), once the state's tables have `room`: they grow with the lock let go,
    /// the old ones are freed with it let go too, and the lock is taken again until the room is
    /// there.
    fn lock_with_room(&self, room: Room) -> MutexGuard<'_, State> {
        loop {
            let st = self.lock();
            let threads = st.threads.0.len() + room.threads;
            let exits = st.exited.len() + threads + 1;
            let handles = st.handles.len() + room.handles;
            let short = |len: usize, capacity: usize| (len > capacity).then(|| len.max(2 * capacity));
            let grow = (
                short(threads, st.threads.0.capacity()),
                short(exits, st.exited.capacity()),
                short(handles, st.handles.capacity()),
            );
            if grow == (None, None, None) {
                return st;
            }
            drop(st);
            let mut threads = grow.0.map(Vec::with_capacity);
            let mut exited = grow.1.map(Vec::with_capacity);
            let mut handles = grow.2.map(Vec::with_capacity);
            let mut st = self.lock();
            fn adopt<T>(table: &mut Vec<T>, grown: &mut Option<Vec<T>>) {
                if let Some(grown) = grown
                    && grown.capacity() > table.capacity()
                {
                    grown.append(table);
                    std::mem::swap(table, grown);
                }
            }
            adopt(&mut st.threads.0, &mut threads);
            adopt(&mut st.exited, &mut exited);
            adopt(&mut st.handles, &mut handles);
            drop(st);
        }
    }

    #[cfg(any(unix, windows))]
    fn take_owner_records(&self, st: &mut State) {
        self.owner_records.drain(|record| st.owners.apply(record));
    }

    #[cfg(not(any(unix, windows)))]
    fn take_owner_records(&self, _st: &mut State) {}

    /// Records `record` in `owners` without waiting for the state: queued for its holder if
    /// another thread has it, as a lock or unlock hook may be running inside an allocator that
    /// holder's next allocation needs.
    #[cfg(any(unix, windows))]
    fn record_owner(&self, record: MutexRecord) {
        let _passthrough = Passthrough::enter();
        let mut st = match self.try_lock() {
            Some(st) => st,
            None if self.owner_records.push(record) => return,
            None => self.lock(),
        };
        st.owners.apply(record);
    }

    /// Takes the baton for an executive once the schedule is idle: no thread holds it and none is
    /// ready to.
    pub(crate) fn acquire_external(&self) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        while !st.idle() {
            st = self
                .went_idle
                .wait_timeout(st, OUTSIDE_POLL)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        st.hold_external();
    }

    /// Gives back the baton an executive holds, handing it to the next runnable thread, or the
    /// duty of moving the schedule on to the first blocked one.
    pub(crate) fn release_external(&self) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        if st.holder != Some(EXTERNAL) {
            return;
        }
        st.holder = None;
        let Some(st) = Self::grant_next(st) else {
            return;
        };
        if let Some(parker) = st.first_blocked_parker() {
            parker.delegate();
        }
    }

    /// The state locked with a slot for `t`, made if it has none, and the slot's parker. `None` if
    /// `skip` says, under the lock, not to make one. A parker for a new slot is made, and one left
    /// unused freed, with the lock let go.
    fn lock_slot(
        &self,
        t: u64,
        skip: impl Fn(&State) -> bool,
    ) -> Option<(MutexGuard<'_, State>, Arc<Parker>)> {
        let mut spare = None;
        loop {
            let mut st = self.lock_with_room(Room {
                threads: 1,
                handles: 0,
            });
            if skip(&st) {
                drop(st);
                return None;
            }
            let parker = st
                .threads
                .get_or_insert(t, &mut spare)
                .map(|slot| slot.parker.clone());
            match parker {
                Some(parker) if spare.is_none() => return Some((st, parker)),
                Some(_) => {
                    drop(st);
                    spare = None;
                }
                None => {
                    drop(st);
                    spare = Some(Arc::new(Parker::default()));
                }
            }
        }
    }

    /// The thread that entered the domain (`Domain::enter`) takes the baton, or queues for it if
    /// another thread of the domain holds it.
    pub(crate) fn enter_root(&self, me: u64) {
        let _passthrough = Passthrough::enter();
        let Some((mut st, parker)) = self.lock_slot(me, |_| false) else {
            return;
        };
        st.roots += 1;
        self.detached.store(false, Ordering::SeqCst);
        if st.holder.is_none() {
            st.holder = Some(me);
            st.last = me;
            return;
        }
        st.set_runnable(me, DetWake::Woken);
        drop(st);
        self.park(&parker);
    }

    /// A managed thread is being created: queue it now, so the scheduler never mistakes the gap
    /// before the OS starts it for every thread being blocked.
    pub(crate) fn spawned(&self, child: u64) {
        let _passthrough = Passthrough::enter();
        let Some((mut st, _)) = self.lock_slot(child, |_| self.detached()) else {
            return;
        };
        st.set_runnable(child, DetWake::Woken);
        Self::grant_if_idle(st);
    }

    /// A participant joins the schedule from outside it: queue it and wait for its turn.
    pub(crate) fn attach_thread(&self, me: u64) {
        let _passthrough = Passthrough::enter();
        let Some((mut st, parker)) = self.lock_slot(me, |_| false) else {
            return;
        };
        if st.holder == Some(me) {
            return;
        }
        st.set_runnable(me, DetWake::Woken);
        Self::grant_if_idle(st);
        self.park(&parker);
    }

    /// The running thread leaves the schedule without leaving the domain: it runs on beside the
    /// schedule, which hands the baton on if it held it. With no thread to hand it to, the first
    /// blocked thread takes over moving the schedule on, since the leaving thread cannot wait for
    /// time or a deadlock on its behalf.
    pub(crate) fn detach_thread(&self, me: u64) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        st.take_runnable(me);
        st.take_blocked(me);
        if let Some(slot) = st.threads.get(me) {
            slot.parker.forget();
        }
        let disowned = Self::disown(&mut st, me);
        if st.holder != Some(me) {
            if disowned {
                Self::grant_if_idle(st);
            }
            return;
        }
        st.holder = None;
        let Some(st) = Self::grant_next(st) else {
            return;
        };
        if let Some(parker) = st.first_blocked_parker() {
            parker.delegate();
        }
    }

    /// The OS failed to create a thread queued by [`spawned`](Scheduler::spawned).
    pub(crate) fn unspawned(&self, child: u64) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        st.take_runnable(child);
        let slot = st.threads.remove(child);
        drop(st);
        drop(slot);
    }

    /// Records the OS handle of a thread this domain created, for [`lineage_of`](Scheduler::lineage_of).
    pub(crate) fn record_handle(&self, handle: usize, child: u64) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock_with_room(Room {
            threads: 0,
            handles: 1,
        });
        match st.handles.binary_search_by_key(&handle, |&(h, _)| h) {
            Ok(i) => st.handles[i].1 = child,
            Err(i) => st.handles.insert(i, (handle, child)),
        }
    }

    /// The lineage id of the thread with this OS handle, if this domain created it and it has not
    /// yet exited.
    pub(crate) fn lineage_of(&self, handle: usize) -> Option<u64> {
        let _passthrough = Passthrough::enter();
        let st = self.lock();
        let i = st.handles.binary_search_by_key(&handle, |&(h, _)| h).ok()?;
        let lineage = st.handles[i].1;
        st.exited.binary_search(&lineage).is_err().then_some(lineage)
    }

    /// A new managed thread's first act: wait for the baton.
    pub(crate) fn started(&self, me: u64) {
        let _passthrough = Passthrough::enter();
        let Some((st, parker)) = self.lock_slot(me, |st| {
            self.detached() && !st.is_runnable(me) && st.holder != Some(me)
        }) else {
            return;
        };
        drop(st);
        self.park(&parker);
    }

    /// Whether the schedule has let its threads go; see [`Scheduler::detached`].
    pub(crate) fn detached(&self) -> bool {
        self.detached.load(Ordering::SeqCst)
    }

    /// The running thread leaves the domain (`root`: through the guard of
    /// [`enter_root`](Self::enter_root)): wake its joiners and pass the baton on.
    pub(crate) fn exit(&self, me: u64, root: bool) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock_with_room(Room::default());
        if root {
            st.roots = st.roots.saturating_sub(1);
        }
        st.settle_repoll(me, None);
        if let Err(i) = st.exited.binary_search(&me) {
            st.exited.insert(i, me);
        }
        st.take_runnable(me);
        st.take_blocked(me);
        let slot = st.threads.remove(me);
        if slot.as_ref().is_some_and(|slot| slot.let_go) {
            self.let_go.fetch_sub(1, Ordering::SeqCst);
        }
        Self::disown(&mut st, me);
        Self::wake_key(&mut st, DetKey::Exit(me), usize::MAX, DetWake::Woken);
        if st.holder == Some(me) {
            st.holder = None;
            if let Some(st) = Self::grant_next(st)
                && let Some(parker) = st.first_blocked_parker()
            {
                parker.delegate();
            }
        } else {
            Self::grant_if_idle(st);
        }
        drop(slot);
    }

    /// Parks the running thread on `key` until it is woken or virtual time reaches `deadline`.
    pub(crate) fn block(
        &self,
        me: u64,
        key: DetKey,
        deadline: Option<Duration>,
        register_timer: bool,
        mask: u32,
        readiness: Option<ReadinessInterest>,
    ) -> DetWake {
        let _passthrough = Passthrough::enter();
        let now = crate::domain::virtual_now();
        if let (Some(at), Some(now)) = (deadline, now)
            && now >= at
        {
            return DetWake::TimedOut;
        }
        // Make the deadline a pending timer, so the time skip lands on it.
        let timer = match (register_timer, deadline, now) {
            (true, Some(at), Some(now)) => crate::domain::register_timer(at - now),
            _ => None,
        };
        let blocked = Blocked {
            key,
            mask,
            futex_private: crate::accounting::wait_futex_private(),
            readiness,
            deadline,
            signal_version: wait_signal_version(key),
            futex_value: futex_wait_value(key),
            #[cfg(windows)]
            address_value: address_wait_value(key),
            #[cfg(windows)]
            timer_waker: !register_timer,
            outside_holder: OUTSIDE_HOLDER
                .try_with(std::cell::Cell::get)
                .unwrap_or(false),
        };
        let mut st = self.lock();
        if st.holder != Some(me) && self.take_let_go(&mut st, me) && !self.detached() {
            // A thread let go when the schedule detached waits in it again, without the baton.
            st.waits += 1;
            st.set_blocked(me, blocked);
            let parker = st.threads.get(me).map(|slot| slot.parker.clone());
            drop(st);
            let why = parker.map_or(DetWake::Woken, |parker| self.park(&parker));
            if let Some(key) = timer {
                crate::domain::unregister_timer(key);
            }
            return why;
        }
        // Not this domain's running thread (it raced in from outside the schedule), or a join on a
        // thread outside the schedule that exited since the caller looked: let it go.
        let parker = st.threads.get(me).map(|slot| slot.parker.clone());
        let joined_gone =
            matches!(key, DetKey::Exit(t) if st.exited.binary_search(&t).is_ok());
        let Some(parker) = parker.filter(|_| st.holder == Some(me) && !joined_gone) else {
            drop(st);
            drop(blocked);
            if let Some(key) = timer {
                crate::domain::unregister_timer(key);
            }
            return DetWake::Woken;
        };
        self.take_foreign(&mut st);
        if st.foreign.remove(key) || blocked.changed_outside() {
            drop(st);
            drop(blocked);
            if let Some(key) = timer {
                crate::domain::unregister_timer(key);
            }
            return DetWake::Woken;
        }
        st.settle_repoll(me, Some(key));
        st.waits += 1;
        st.set_blocked(me, blocked);
        st.holder = None;
        self.dispatch(st);
        self.repoll_if_spoiled(me);
        let why = self.park(&parker);
        if let Some(key) = timer {
            crate::domain::unregister_timer(key);
        }
        why
    }

    /// Clears `t`'s let-go mark; `true` if it had one.
    fn take_let_go(&self, st: &mut State, t: u64) -> bool {
        let Some(slot) = st.threads.get_mut(t) else {
            return false;
        };
        if !std::mem::take(&mut slot.let_go) {
            return false;
        }
        self.let_go.fetch_sub(1, Ordering::SeqCst);
        true
    }

    /// Records that `me` now holds the mutex at `addr`.
    #[cfg(any(unix, windows))]
    pub(crate) fn took(&self, addr: usize, me: u64) {
        self.record_owner(MutexRecord {
            mutex: addr,
            lineage: me,
            taken: true,
        });
    }

    /// Records that the mutex at `addr` was released.
    #[cfg(any(unix, windows))]
    pub(crate) fn released(&self, addr: usize) {
        self.record_owner(MutexRecord {
            mutex: addr,
            lineage: 0,
            taken: false,
        });
    }

    /// Whether one of this domain's threads holds the mutex at `addr`.
    #[cfg(any(unix, windows))]
    pub(crate) fn held_inside(&self, addr: usize) -> bool {
        let _passthrough = Passthrough::enter();
        let state = self.lock();
        #[cfg(windows)]
        if state
            .shared_owners
            .get(&addr)
            .is_some_and(|owners| !owners.is_empty())
        {
            return true;
        }
        state.owners.contains(addr)
    }

    #[cfg(windows)]
    pub(crate) fn took_shared(&self, addr: usize, me: u64) {
        let _pass = Passthrough::enter();
        self.lock()
            .shared_owners
            .entry(addr)
            .or_default()
            .insert(me);
    }

    #[cfg(windows)]
    pub(crate) fn released_shared(&self, addr: usize, me: u64) {
        let _pass = Passthrough::enter();
        let mut state = self.lock();
        if let Some(owners) = state.shared_owners.get_mut(&addr) {
            owners.remove(&me);
            if owners.is_empty() {
                state.shared_owners.remove(&addr);
            }
        }
    }

    /// Moves up to `n` of `key`'s waiters, oldest first, to the run queue. Returns how many. A
    /// thread outside the schedule waking one while no thread holds the baton hands it on.
    pub(crate) fn wake(&self, key: DetKey, n: usize) -> usize {
        self.wake_masked(key, n, u32::MAX, None)
    }

    pub(crate) fn wake_masked(
        &self,
        key: DetKey,
        n: usize,
        mask: u32,
        private: Option<bool>,
    ) -> usize {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        let mut woken = Self::wake_key_matching(&mut st, key, n, DetWake::Woken, |wait| {
            wait.mask & mask != 0 && private.is_none_or(|scope| wait.futex_private == Some(scope))
        });
        if woken < n && !self.detached() {
            woken += Self::wake_outside(&mut st, key, n - woken);
        }
        if woken > 0 {
            Self::grant_if_idle(st);
        }
        woken
    }

    /// As [`wake_masked`](Self::wake_masked), for a wake made by a thread outside the schedule (of
    /// another domain, or of none) on an address one of its threads waits on. A wake that finds
    /// no waiter blocked there is kept for the next wait on the key (see `domain::det_foreign`).
    pub(crate) fn wake_foreign(
        &self,
        key: DetKey,
        n: usize,
        mask: u32,
        private: Option<bool>,
    ) -> usize {
        let _passthrough = Passthrough::enter();
        let mut st = match self.try_lock() {
            Some(st) => st,
            None if self.foreign_queue.push((key, n, mask, private)) => return 0,
            None => self.lock(),
        };
        let woken = Self::wake_foreign_locked(&mut st, key, n, mask, private);
        if woken > 0 {
            Self::grant_if_idle(st);
        }
        woken
    }

    fn wake_foreign_locked(
        st: &mut State,
        key: DetKey,
        n: usize,
        mask: u32,
        private: Option<bool>,
    ) -> usize {
        let woken = Self::wake_key_matching(st, key, n, DetWake::Woken, |wait| {
            wait.mask & mask != 0 && private.is_none_or(|scope| wait.futex_private == Some(scope))
        });
        if woken == 0 {
            st.foreign.insert(key);
        }
        woken
    }

    /// Delivers the wakes [`wake_foreign`](Self::wake_foreign) queued while the state was held.
    fn take_foreign(&self, st: &mut State) {
        self.foreign_queue
            .drain(|(key, n, mask, private)| {
                Self::wake_foreign_locked(st, key, n, mask, private);
            });
    }

    pub(crate) fn wake_readiness(&self, event: ReadinessWake<'_>) -> usize {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        let mut woken = Self::wake_readiness_key(&mut st, event);
        if !self.detached() {
            woken += Self::wake_outside(&mut st, DetKey::Readiness, usize::MAX);
        }
        if woken > 0 {
            Self::grant_if_idle(st);
        }
        woken
    }

    /// Queues up to `n` let-go threads in a native wait on `key`, lowest lineage first, to take the
    /// baton when their wait returns: a wake from inside the schedule orders them as it would a
    /// waiter in it.
    fn wake_outside(st: &mut State, key: DetKey, n: usize) -> usize {
        let mut woken = 0;
        let mut newly_runnable = 0;
        for (_, slot) in st.threads.iter_mut() {
            if woken == n {
                break;
            }
            if slot.outside != Some(key) {
                continue;
            }
            slot.outside = None;
            if slot.runnable.replace(DetWake::Woken).is_none() {
                newly_runnable += 1;
            }
            woken += 1;
        }
        st.runnable += newly_runnable;
        woken
    }

    /// A let-go thread enters a native wait on `key`; see [`wake_outside`](Self::wake_outside).
    pub(crate) fn wait_outside(&self, me: u64, key: DetKey) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        if let Some(slot) = st.threads.get_mut(me)
            && slot.let_go
        {
            slot.outside = Some(key);
        }
    }

    /// A native wait returned. A thread let go when the schedule detached, while a run is active
    /// again, waits for the baton before going back to the code under test, so it never runs
    /// beside the thread holding it.
    pub(crate) fn rejoin(&self, me: u64) {
        if self.let_go.load(Ordering::SeqCst) == 0 {
            return;
        }
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        if let Some(slot) = st.threads.get_mut(me) {
            slot.outside = None;
        }
        if self.detached() || !self.take_let_go(&mut st, me) {
            return;
        }
        let Some(parker) = st.threads.get(me).map(|slot| slot.parker.clone()) else {
            return;
        };
        if st.holder != Some(me) {
            st.set_runnable_if_not(me, DetWake::Woken);
            Self::grant_if_idle(st);
        } else {
            drop(st);
        }
        self.park(&parker);
    }

    /// Hands the baton to the next runnable thread if no thread holds it. A thread idling in
    /// [`dispatch`](Self::dispatch) finds the baton taken when it next looks, and stops.
    /// Forgets the mutexes `me` holds as it leaves the schedule (still holding them: a root
    /// returning from its run with a guard, a thread marking itself background), and makes their
    /// waiters runnable to try again. Its unlock will no longer reach the schedule, so they now
    /// wait for a holder outside it, in real time. Returns whether it held any.
    #[cfg(any(unix, windows))]
    fn disown(st: &mut State, me: u64) -> bool {
        let mut held = false;
        while let Some(addr) = st.owners.held_by(me) {
            st.owners.remove(addr);
            Self::wake_key(st, DetKey::Addr(addr), usize::MAX, DetWake::Woken);
            held = true;
        }
        #[cfg(windows)]
        {
            let shared: Vec<usize> = st
                .shared_owners
                .iter_mut()
                .filter_map(|(&addr, owners)| owners.remove(&me).then_some(addr))
                .collect();
            st.shared_owners.retain(|_, owners| !owners.is_empty());
            for &addr in &shared {
                Self::wake_key(st, DetKey::Addr(addr), usize::MAX, DetWake::Woken);
            }
            held |= !shared.is_empty();
        }
        held
    }

    /// No mutex owners are kept off unix.
    #[cfg(not(any(unix, windows)))]
    fn disown(_st: &mut State, _me: u64) -> bool {
        false
    }

    fn grant_if_idle(st: MutexGuard<'_, State>) {
        if st.holder.is_none() {
            let _ = Self::grant_next(st);
        }
    }

    /// The running thread steps aside for every other runnable thread, then runs again.
    pub(crate) fn yield_now(&self, me: u64) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        if st.holder != Some(me) {
            return;
        }
        st.settle_repoll(me, None);
        self.take_foreign(&mut st);
        if st.runnable == 0 {
            // Nobody else can run: yielding changes nothing, so keep the baton.
            return;
        }
        let Some(parker) = st.threads.get(me).map(|slot| slot.parker.clone()) else {
            return;
        };
        st.set_runnable(me, DetWake::Woken);
        st.holder = None;
        self.dispatch(st);
        self.park(&parker);
    }

    /// One step of the running thread's spin (see `domain::clock_spin`), `clock` when the spin reads
    /// the clock. While another runnable thread is not spinning itself, it has work to do at the
    /// current instant, so the spinner only yields to it. Otherwise `advance` moves time (a step of
    /// a clock spin, or a time skip for a yield-only one, which waits while a clock spinner is
    /// about, since a skip could jump past that spinner's deadline); the threads whose deadlines
    /// it reached time out, sim waits re-check, and the spinner yields so they run before its next
    /// step.
    pub(crate) fn spin(&self, me: u64, clock: bool, advance: impl FnOnce() -> bool) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        if st.holder != Some(me) {
            return;
        }
        if let Some(slot) = st.threads.get_mut(me) {
            slot.spinner = Some(clock);
        }
        let others_work = st
            .threads
            .iter()
            .any(|(_, slot)| slot.runnable.is_some() && slot.spinner.is_none());
        let clock_elsewhere = st
            .threads
            .iter()
            .any(|(t, slot)| slot.spinner == Some(true) && t != me);
        if others_work || (!clock && clock_elsewhere) {
            drop(st);
            self.yield_now(me);
            return;
        }
        drop(st);
        if advance() {
            let timer_wakes = crate::domain::took_timer_wakes();
            let mut st = self.lock();
            Self::release_due(&mut st, crate::domain::virtual_now());
            Self::wake_readiness_key(&mut st, ReadinessWake::Timer);
            if timer_wakes {
                Self::repoll_addr_waiters(&mut st);
            }
            drop(st);
            crate::domain::wake_unscheduled();
        }
        self.yield_now(me);
    }

    /// `me`'s spin ended: it made another hooked call.
    pub(crate) fn unspin(&self, me: u64) {
        let _passthrough = Passthrough::enter();
        if let Some(slot) = self.lock().threads.get_mut(me) {
            slot.spinner = None;
        }
    }

    /// Waits on `parker` until the thread is handed the baton, moving the schedule on meanwhile
    /// whenever it is delegated that duty.
    fn park(&self, parker: &Parker) -> DetWake {
        loop {
            match parker.wait() {
                Grant::Run(why) => return why,
                Grant::Dispatch => {
                    let st = self.lock();
                    if st.holder.is_none() {
                        self.dispatch(st);
                    }
                    self.repoll_if_spoiled(crate::domain::thread_lineage());
                }
            }
        }
    }

    /// Re-polls `me`, the calling thread, if a wait nested in the dispatch it just ran spoiled the
    /// wait it is blocked in (see [`repoll_self`]): no wake in the schedule will come for that wait,
    /// since the `unpark` meant for it no longer wakes the OS wait (see `os::nested`).
    fn repoll_if_spoiled(&self, me: u64) {
        if !REPOLL_SELF.try_with(|r| r.replace(false)).unwrap_or(false) {
            return;
        }
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        let Some(key) = st
            .threads
            .get(me)
            .and_then(|slot| slot.blocked.as_ref())
            .map(|(b, _)| b.key)
        else {
            return;
        };
        Self::unblock(&mut st, me, DetWake::Woken);
        if let Some(slot) = st.threads.get_mut(me) {
            slot.repolled = Some(key);
        }
        Self::grant_if_idle(st);
    }

    /// Moves up to `n` of `key`'s waiters, oldest first, from blocked to runnable with `why`.
    /// Returns how many moved; grants nothing.
    fn wake_key(st: &mut State, key: DetKey, n: usize, why: DetWake) -> usize {
        Self::wake_key_masked(st, key, n, u32::MAX, why)
    }

    fn wake_key_masked(st: &mut State, key: DetKey, n: usize, mask: u32, why: DetWake) -> usize {
        Self::wake_key_matching(st, key, n, why, |wait| wait.mask & mask != 0)
    }

    fn wake_readiness_key(st: &mut State, event: ReadinessWake<'_>) -> usize {
        Self::wake_key_matching(st, DetKey::Readiness, usize::MAX, DetWake::Woken, |wait| {
            wait.readiness
                .as_ref()
                .is_none_or(|interest| interest.matches(event))
        })
    }

    /// Wakes the waiters on `key` that `matches` accepts, oldest first, up to `n` of them: all in
    /// one pass when `n` reaches them all, else the oldest left, one pass each.
    fn wake_key_matching(
        st: &mut State,
        key: DetKey,
        n: usize,
        why: DetWake,
        matches: impl Fn(&Blocked) -> bool,
    ) -> usize {
        let waiting = |slot: &Slot| {
            slot.blocked
                .as_ref()
                .filter(|(wait, _)| wait.key == key && matches(wait))
                .map(|&(_, order)| order)
        };
        let all = st
            .threads
            .iter()
            .filter(|(_, slot)| waiting(slot).is_some())
            .count();
        if n >= all {
            let mut i = 0;
            while let Some((t, hit)) = st.threads.0.get(i).map(|(t, slot)| (*t, waiting(slot).is_some())) {
                if hit {
                    Self::unblock(st, t, why);
                }
                i += 1;
            }
            return all;
        }
        for _ in 0..n {
            let oldest = st
                .threads
                .iter()
                .filter_map(|(t, slot)| waiting(slot).map(|order| (order, t)))
                .min();
            let Some((_, t)) = oldest else {
                break;
            };
            Self::unblock(st, t, why);
        }
        n
    }

    /// Moves `t`, if blocked, to runnable with `why`.
    fn unblock(st: &mut State, t: u64, why: DetWake) {
        if st.take_blocked(t).is_some() {
            st.set_runnable(t, why);
        }
    }

    /// Times out every blocked thread whose deadline `now` has reached.
    fn release_due(st: &mut State, now: Option<Duration>) {
        Self::release_due_matching(st, now, |_| true);
    }

    fn release_due_matching(
        st: &mut State,
        now: Option<Duration>,
        matches: impl Fn(&Blocked) -> bool,
    ) {
        let Some(now) = now else {
            return;
        };
        let mut i = 0;
        while let Some((t, due)) = st.threads.0.get(i).map(|(t, slot)| {
            let due = slot
                .blocked
                .as_ref()
                .is_some_and(|(b, _)| b.deadline.is_some_and(|at| now >= at) && matches(b));
            (*t, due)
        }) {
            if due {
                Self::unblock(st, t, DetWake::TimedOut);
            }
            i += 1;
        }
    }

    /// Something outside the schedule moved the clock (see `Domain::kick`): release what is now
    /// due, let sim waits re-check, and if no thread holds the baton hand it on. Callable from any
    /// thread, managed or not, since it only grants parked threads.
    /// `timer_wakes` says wakers fired from inside the sim (see `Layer::take_timer_wakes`), so the
    /// threads held on native wait objects re-poll too.
    pub(crate) fn kick(&self, now: Option<Duration>, timer_wakes: bool) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        Self::release_due(&mut st, now);
        Self::wake_readiness_key(&mut st, ReadinessWake::Timer);
        if timer_wakes {
            Self::repoll_addr_waiters(&mut st);
        }
        // Grant only: when nothing is runnable the thread that last let go of the baton is already
        // idling in `dispatch`.
        Self::grant_if_idle(st);
    }

    /// As [`kick`](Self::kick) for a clock that moved without anything of the sim's coming due but
    /// the schedule's own timed waits: those `now` reached are released, and no other wait is
    /// woken to re-check.
    pub(crate) fn release_due_at(&self, now: Option<Duration>) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        Self::release_due(&mut st, now);
        Self::grant_if_idle(st);
    }

    /// Times out the native waits `now` reached when a call's latency moved the clock. While other
    /// threads wait for their turn only waits on a timer's own wake are released: nothing re-polls
    /// them for that wake, and a time skip taken once those threads have run would carry the clock
    /// on to the next deadline first.
    pub(crate) fn release_due_native_at(&self, now: Option<Duration>) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        let others_run = st.runnable > 0;
        Self::release_due_matching(&mut st, now, |wait| {
            matches!(wait.key, DetKey::Addr(_)) && (!others_run || wait.woken_by_timer())
        });
        Self::grant_if_idle(st);
    }

    /// Hands the baton to the next runnable thread after the cursor, or gives the lock back if no
    /// thread is runnable.
    fn grant_next(mut st: MutexGuard<'_, State>) -> Option<MutexGuard<'_, State>> {
        let last = st.last;
        let next = st
            .threads
            .iter()
            .find(|&(t, slot)| t > last && slot.runnable.is_some())
            .or_else(|| st.threads.iter().find(|(_, slot)| slot.runnable.is_some()))
            .map(|(t, slot)| (t, slot.parker.clone()));
        let Some((t, parker)) = next else {
            return Some(st);
        };
        let why = st.take_runnable(t).unwrap_or(DetWake::Woken);
        st.holder = Some(t);
        st.last = t;
        st.end_idle();
        drop(st);
        parker.grant(why);
        None
    }

    /// Hands the baton to the next runnable thread after the cursor, moving virtual time when
    /// nothing can run. Called with no holder.
    fn dispatch<'a>(&'a self, st: MutexGuard<'a, State>) {
        if self.dispatch_inner(st) {
            // Threads outside the schedule wait on the clock too; let them see the new time.
            crate::domain::wake_unscheduled();
        }
    }

    /// [`dispatch`](Self::dispatch), reporting whether it moved virtual time.
    fn dispatch_inner<'a>(&'a self, mut st: MutexGuard<'a, State>) -> bool {
        let mut skipped = false;
        loop {
            self.take_foreign(&mut st);
            st = match Self::grant_next(st) {
                Some(st) => st,
                None => return skipped,
            };
            self.went_idle.notify_all();
            if st.blocked == 0 {
                return skipped;
            }
            if st.roots == 0 && !crate::domain::leases_held() {
                self.detach(st);
                return skipped;
            }
            if crate::domain::leases_held() {
                // A lease holds the domain busy: time may not skip and no wait may give up until
                // it is given back.
                match self.idle(st, OUTSIDE_POLL, Idle::Leased) {
                    Some(next) => st = next,
                    None => return skipped,
                }
                continue;
            }
            if crate::domain::took_timer_wakes() {
                // Those wakes reached the OS unhooked; the threads they released re-poll.
                Self::repoll_addr_waiters(&mut st);
                continue;
            }
            if crate::domain::time_skip() {
                skipped = true;
                Self::release_due(&mut st, crate::domain::virtual_now());
                // Sleepers and timed sim waits re-check against the new time.
                Self::wake_readiness_key(&mut st, ReadinessWake::Timer);
                continue;
            }
            if crate::domain::leases_held() {
                continue;
            }
            if let Some(span) = crate::domain::idle_wait() {
                // The clock is held: every thread waits on time that only something outside the
                // simulation can move, which is not a deadlock. Idle until it moves.
                match self.idle(st, span, Idle::Held) {
                    Some(next) => st = next,
                    None => return skipped,
                }
                continue;
            }
            // No time left to pass. Sim waits give up, as a deadlock makes them — unless a thread
            // waits on a word in static data, which a thread outside the sim may hold: then the
            // wait for it to let go below is no deadlock.
            if !Self::blocked_on_shared_word(&st)
                && Self::wake_key(&mut st, DetKey::Readiness, usize::MAX, DetWake::Deadlock) > 0
            {
                continue;
            }
            // Every participant waits on something only a thread outside the schedule can do (a
            // join on a sampler told to stop): that thread's timers are what moves time now.
            if crate::domain::foreign_time_skip() {
                skipped = true;
                drop(st);
                crate::domain::wake_unscheduled();
                st = self.lock();
                if st.holder.is_some() {
                    return skipped;
                }
                Self::release_due(&mut st, crate::domain::virtual_now());
                continue;
            }
            // Only lock and address waits remain, and nothing in the sim can release them; a
            // thread outside it might. Wait a moment of real time, then let them re-check.
            let warn = st.note_idle();
            drop(st);
            if warn {
                crate::stall::warn(Idle::Outside);
            }
            std::thread::sleep(OUTSIDE_POLL);
            st = self.lock();
            if st.holder.is_some() {
                return skipped;
            }
            Self::repoll_addr_waiters(&mut st);
        }
    }

    /// Whether a blocked thread waits on a word in a loaded image: a lock in static data (std's
    /// stdout and stderr locks, a `static` mutex) that a thread of another sim or of none may hold,
    /// and which carries no owner to tell; or on a lock it knows such a thread holds.
    fn blocked_on_shared_word(st: &State) -> bool {
        #[cfg(any(target_os = "linux", windows))]
        return st.blocked().any(|(_, b)| {
            b.outside_holder
                || matches!(b.key, DetKey::Addr(addr) if crate::domain::in_static_image(addr))
        });
        #[cfg(not(any(target_os = "linux", windows)))]
        st.blocked().any(|(_, b)| b.outside_holder)
    }

    /// Every root has left and nothing can run: lets every blocked thread go, to wait outside the
    /// schedule from now on. Called with no holder.
    fn detach(&self, mut st: MutexGuard<'_, State>) {
        self.detached.store(true, Ordering::SeqCst);
        st.foreign.clear();
        st.end_idle();
        st.blocked = 0;
        let mut let_go = 0;
        for (_, slot) in st.threads.iter_mut() {
            slot.repolled = None;
            if slot.blocked.take().is_some() {
                if !std::mem::replace(&mut slot.let_go, true) {
                    let_go += 1;
                }
                slot.parker.grant(DetWake::Woken);
            }
        }
        self.let_go.fetch_add(let_go, Ordering::SeqCst);
    }

    /// One real-time wait of a dispatch on a held clock or a leased domain. `None` when another
    /// thread took the baton meanwhile (a kick granted it), so this dispatch is over.
    ///
    /// The first wait of an idle stretch moves the domain's epoch on, so an executive watching it
    /// ([`Domain::arm`](crate::Domain::arm)) learns the schedule has gone idle. The sleep is the
    /// shorter of `span` and [`OUTSIDE_POLL`]; afterwards, unless a thread became runnable
    /// meanwhile, due deadlines time out, sim waits re-check if virtual time moved, and address
    /// waiters re-poll.
    fn idle<'a>(
        &'a self,
        mut st: MutexGuard<'a, State>,
        span: Duration,
        why: Idle,
    ) -> Option<MutexGuard<'a, State>> {
        let first = st.idle_since.is_none();
        let warn = st.note_idle();
        let before = crate::domain::virtual_now();
        let bump = first.then(crate::domain::bump_epoch);
        drop(st);
        if warn {
            crate::stall::warn(why);
        }
        drop(bump);
        std::thread::sleep(span.min(OUTSIDE_POLL));
        st = self.lock();
        if st.holder.is_some() {
            return None;
        }
        if st.runnable > 0 {
            return Some(st);
        }
        let now = crate::domain::virtual_now();
        if !crate::domain::executive_attached() {
            Self::release_due(&mut st, now);
            if now != before {
                Self::wake_readiness_key(&mut st, ReadinessWake::Timer);
            }
        }
        Self::repoll_addr_waiters(&mut st);
        Some(st)
    }

    /// Lets every lock and address waiter re-check, in case something outside the simulation
    /// changed what it waits on.
    fn repoll_addr_waiters(st: &mut State) {
        #[cfg(windows)]
        for (key, count, _lifetime) in crate::domain::take_timer_word_wakes() {
            Self::wake_key(st, DetKey::Addr(key), count, DetWake::Woken);
        }
        let mut i = 0;
        while let Some((t, key)) = st.threads.0.get(i).map(|(t, slot)| {
            let key = slot
                .blocked
                .as_ref()
                .filter(|(b, _)| b.should_repoll())
                .map(|(b, _)| b.key);
            (*t, key)
        }) {
            if let Some(key) = key {
                Self::unblock(st, t, DetWake::Woken);
                if let Some(slot) = st.threads.get_mut(t) {
                    slot.repolled = Some(key);
                }
            }
            i += 1;
        }
    }
}

#[cfg(windows)]
fn address_wait_value(key: DetKey) -> Option<(usize, u64)> {
    if let DetKey::Addr(addr) = key {
        return crate::os::windows::address_wait_value(addr);
    }
    None
}

fn wait_signal_version(key: DetKey) -> Option<u64> {
    #[cfg(unix)]
    if let DetKey::Addr(addr) = key {
        return crate::os::sync::wait_signal_version(addr);
    }
    let _ = key;
    None
}

#[cfg(not(target_os = "linux"))]
fn signal_version(addr: usize) -> Option<u64> {
    #[cfg(unix)]
    return crate::os::sync::signal_version(addr);
    #[cfg(windows)]
    {
        let _ = addr;
        None
    }
}

fn futex_wait_value(key: DetKey) -> Option<u32> {
    #[cfg(target_os = "linux")]
    if let DetKey::Addr(addr) = key {
        return crate::os::sync::futex_wait_value(addr);
    }
    let _ = key;
    None
}

fn futex_value(addr: usize) -> u32 {
    #[cfg(target_os = "linux")]
    return unsafe { &*(addr as *const std::sync::atomic::AtomicU32) }
        .load(std::sync::atomic::Ordering::Acquire);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = addr;
        0
    }
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::{MutexOwners, OWNED_MUTEXES};
    use std::collections::HashMap;

    #[test]
    fn mutex_owners_agree_with_a_map_through_collisions_and_removals() {
        let mut owners = MutexOwners::default();
        let mut model = HashMap::new();
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for step in 0..200_000u64 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let addr = 8 * (1 + seed % (3 * OWNED_MUTEXES as u64 / 4)) as usize;
            if seed >> 40 & 1 == 0 && model.len() < OWNED_MUTEXES - 1 {
                owners.insert(addr, step);
                model.insert(addr, step);
            } else {
                owners.remove(addr);
                model.remove(&addr);
            }
            assert_eq!(owners.contains(addr), model.contains_key(&addr));
        }
        for (&addr, &owner) in &model {
            assert_eq!(owners.owner(addr), Some(owner));
        }
        assert_eq!(owners.0.iter().filter(|e| e.0 != 0).count(), model.len());
    }
}
