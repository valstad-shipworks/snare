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
//! thread is in at most one of `runnable` and `blocked`, and the holder is in neither; every
//! `blocked` thread is queued under its key in `queues` (the queues may hold stale entries, which
//! [`Scheduler::wake_key`] skips). The thread that lets go of the baton with nothing runnable runs
//! [`Scheduler::dispatch`] itself, or delegates it to a parked thread ([`Grant::Dispatch`]) when it
//! is leaving the schedule, so exactly one thread drives the schedule while it is idle.
//!
//! Lock order: the [`State`] lock may be held while taking a [`Parker`]'s lock (to delegate), but a
//! parker's lock is never held while taking the state lock — a grant drops the state lock first,
//! and a parked thread lets go of its parker before re-locking the state. Every entry point that
//! locks runs under [`Passthrough`] (callers of [`Scheduler::lock`] enter it themselves), so the
//! scheduler's own mutexes and condition variables are not hooked back into it. The domain's
//! census lock, when both are needed, is taken first (see `Domain::if_quiescent`).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

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

/// Where a parked thread waits to be handed the baton. One per thread, kept in
/// [`State::parkers`] and shared by `Arc` so a grant can be made after the state lock is released.
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
#[derive(Default)]
pub(crate) struct State {
    /// The lineage id of the thread allowed to run.
    holder: Option<u64>,
    /// Address waiters re-polled for something outside the sim, with the key they waited on, to
    /// tell whether the re-poll found progress.
    repolled: HashMap<u64, DetKey>,
    /// Threads ready to run, with why they were made ready.
    runnable: BTreeMap<u64, DetWake>,
    /// Threads waiting, ordered by lineage id so timeouts wake in a fixed order. Boxed: a debug
    /// build gives each move of an entry inside the map's insert its own stack slot, on the stack
    /// of a thread that may have only 16 KiB.
    blocked: BTreeMap<u64, Box<Blocked>>,
    /// Each key's waiters, in the order they began to wait.
    queues: HashMap<DetKey, VecDeque<u64>>,
    /// Each thread's parker, created on first use and dropped when it leaves the schedule.
    parkers: HashMap<u64, Arc<Parker>>,
    /// The last thread handed the baton: the round-robin cursor.
    last: u64,
    /// Threads that have left the domain, so a late join on one returns at once and
    /// [`Scheduler::lineage_of`] no longer names a handle the OS may have reused: a `pthread_t`'s
    /// lifetime ends once the thread has terminated and been joined or detached, after which it
    /// may be reused (POSIX XSH 2.9.2 "Thread IDs"), and a Windows thread id is unique only "until
    /// the thread terminates" ([Microsoft Learn: GetCurrentThreadId function](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadid)).
    exited: std::collections::HashSet<u64>,
    /// OS thread handles of this domain's threads, for joins: the `pthread_t` from `pthread_self`
    /// on unix, the thread id from `GetCurrentThreadId` on Windows (see
    /// `os::current_thread_handle`).
    handles: HashMap<usize, u64>,
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
    /// Threads the schedule let go when it detached, which have not yet waited in it again.
    let_go: HashSet<u64>,
    /// Let-go threads now in a native wait, by the key a wake in the schedule releases them with.
    outside: HashMap<u64, DetKey>,
    /// Keys a wake from outside the schedule reached while none of their waiters was blocked: the
    /// next wait on one returns at once (see `domain::det_foreign`).
    foreign: HashSet<DetKey>,
    /// Threads caught in a spin (see `domain::clock_spin`), with whether its last step polled the clock.
    /// A runnable thread in here waits on time rather than having work to do.
    spinners: BTreeMap<u64, bool>,
    /// Which of this domain's threads holds each pthread mutex, by address. A mutex held by none
    /// of them is held outside the domain — by another test's simulation or an unmanaged thread.
    #[cfg(any(unix, windows))]
    owners: HashMap<usize, u64>,
    #[cfg(windows)]
    shared_owners: HashMap<usize, std::collections::BTreeSet<u64>>,
}

impl State {
    /// The thread that holds the baton or is next to, if any: the schedule is not idle.
    pub(crate) fn running(&self) -> Option<u64> {
        self.holder
            .filter(|&t| t != EXTERNAL)
            .or_else(|| self.runnable.keys().next().copied())
    }

    /// How many threads are running or ready, and how many are blocked.
    pub(crate) fn counts(&self) -> (usize, usize) {
        let holding = usize::from(self.holder.is_some_and(|t| t != EXTERNAL));
        (self.runnable.len() + holding, self.blocked.len())
    }

    /// Takes the baton for an executive; called only on an idle schedule.
    pub(crate) fn hold_external(&mut self) {
        debug_assert!(
            !self.parkers.contains_key(&EXTERNAL),
            "a thread has the executive's lineage"
        );
        self.holder = Some(EXTERNAL);
    }

    fn idle(&self) -> bool {
        self.holder.is_none() && self.runnable.is_empty()
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
        if let Some(key) = self.repolled.remove(&t)
            && blocked_on != Some(key)
        {
            crate::domain::count_outside_wake();
        }
    }
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
    foreign_queue: Mutex<Vec<ForeignWake>>,
    /// Whether `foreign_queue` may hold any, so delivering them skips its lock when not.
    foreign_queued: AtomicBool,
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
        self.state.lock().unwrap_or_else(|e| e.into_inner())
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
        if let Some(parker) = st.blocked.keys().next().and_then(|t| st.parkers.get(t)) {
            parker.delegate();
        }
    }

    /// The thread that entered the domain (`Domain::enter`) takes the baton, or queues for it if
    /// another thread of the domain holds it.
    pub(crate) fn enter_root(&self, me: u64) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        st.roots += 1;
        self.detached.store(false, Ordering::SeqCst);
        let parker = st.parkers.entry(me).or_default().clone();
        if st.holder.is_none() {
            st.holder = Some(me);
            st.last = me;
            return;
        }
        st.runnable.insert(me, DetWake::Woken);
        drop(st);
        self.park(&parker);
    }

    /// A managed thread is being created: queue it now, so the scheduler never mistakes the gap
    /// before the OS starts it for every thread being blocked.
    pub(crate) fn spawned(&self, child: u64) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        if self.detached() {
            return;
        }
        st.parkers.entry(child).or_default();
        st.runnable.insert(child, DetWake::Woken);
        Self::grant_if_idle(st);
    }

    /// A participant joins the schedule from outside it: queue it and wait for its turn.
    pub(crate) fn attach_thread(&self, me: u64) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        let parker = st.parkers.entry(me).or_default().clone();
        if st.holder == Some(me) {
            return;
        }
        st.runnable.insert(me, DetWake::Woken);
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
        st.parkers.remove(&me);
        st.runnable.remove(&me);
        st.blocked.remove(&me);
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
        if let Some(parker) = st.blocked.keys().next().and_then(|t| st.parkers.get(t)) {
            parker.delegate();
        }
    }

    /// The OS failed to create a thread queued by [`spawned`](Scheduler::spawned).
    pub(crate) fn unspawned(&self, child: u64) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        st.runnable.remove(&child);
        st.parkers.remove(&child);
    }

    /// Records the OS handle of a thread this domain created, for [`lineage_of`](Scheduler::lineage_of).
    pub(crate) fn record_handle(&self, handle: usize, child: u64) {
        let _passthrough = Passthrough::enter();
        self.lock().handles.insert(handle, child);
    }

    /// The lineage id of the thread with this OS handle, if this domain created it and it has not
    /// yet exited.
    pub(crate) fn lineage_of(&self, handle: usize) -> Option<u64> {
        let _passthrough = Passthrough::enter();
        let st = self.lock();
        let lineage = *st.handles.get(&handle)?;
        (!st.exited.contains(&lineage)).then_some(lineage)
    }

    /// A new managed thread's first act: wait for the baton.
    pub(crate) fn started(&self, me: u64) {
        let _passthrough = Passthrough::enter();
        let parker = {
            let mut st = self.lock();
            if self.detached() && !st.runnable.contains_key(&me) && st.holder != Some(me) {
                return;
            }
            st.parkers.entry(me).or_default().clone()
        };
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
        let mut st = self.lock();
        if root {
            st.roots = st.roots.saturating_sub(1);
        }
        st.let_go.remove(&me);
        st.outside.remove(&me);
        st.settle_repoll(me, None);
        st.exited.insert(me);
        st.parkers.remove(&me);
        st.runnable.remove(&me);
        st.blocked.remove(&me);
        st.spinners.remove(&me);
        Self::disown(&mut st, me);
        Self::wake_key(&mut st, DetKey::Exit(me), usize::MAX, DetWake::Woken);
        if st.holder == Some(me) {
            st.holder = None;
            let Some(st) = Self::grant_next(st) else {
                return;
            };
            if let Some(parker) = st.blocked.keys().next().and_then(|t| st.parkers.get(t)) {
                parker.delegate();
            }
        } else {
            Self::grant_if_idle(st);
        }
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
        let mut st = self.lock();
        if st.holder != Some(me) && st.let_go.remove(&me) && !self.detached() {
            // A thread let go when the schedule detached waits in it again, without the baton.
            st.waits += 1;
            st.blocked.insert(
                me,
                Box::new(Blocked {
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
                }),
            );
            st.queues.entry(key).or_default().push_back(me);
            let parker = st.parkers.entry(me).or_default().clone();
            drop(st);
            let why = self.park(&parker);
            if let Some(key) = timer {
                crate::domain::unregister_timer(key);
            }
            return why;
        }
        // Not this domain's running thread (it raced in from outside the schedule), or a join on a
        // thread outside the schedule that exited since the caller looked: let it go.
        if st.holder != Some(me) || matches!(key, DetKey::Exit(t) if st.exited.contains(&t)) {
            drop(st);
            if let Some(key) = timer {
                crate::domain::unregister_timer(key);
            }
            return DetWake::Woken;
        }
        let blocked = Box::new(Blocked {
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
        });
        self.take_foreign(&mut st);
        if st.foreign.remove(&key) || blocked.changed_outside() {
            drop(st);
            if let Some(key) = timer {
                crate::domain::unregister_timer(key);
            }
            return DetWake::Woken;
        }
        st.settle_repoll(me, Some(key));
        st.waits += 1;
        st.blocked.insert(me, blocked);
        st.queues.entry(key).or_default().push_back(me);
        let parker = st.parkers.entry(me).or_default().clone();
        st.holder = None;
        self.dispatch(st);
        self.repoll_if_spoiled(me);
        let why = self.park(&parker);
        if let Some(key) = timer {
            crate::domain::unregister_timer(key);
        }
        why
    }

    /// Records that `me` now holds the mutex at `addr`.
    #[cfg(any(unix, windows))]
    pub(crate) fn took(&self, addr: usize, me: u64) {
        let _passthrough = Passthrough::enter();
        self.lock().owners.insert(addr, me);
    }

    /// Records that the mutex at `addr` was released.
    #[cfg(any(unix, windows))]
    pub(crate) fn released(&self, addr: usize) {
        let _passthrough = Passthrough::enter();
        self.lock().owners.remove(&addr);
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
        state.owners.contains_key(&addr)
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
        let mut st = match self.state.try_lock() {
            Ok(st) => st,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                self.foreign_queue
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((key, n, mask, private));
                self.foreign_queued.store(true, Ordering::SeqCst);
                return 0;
            }
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
        if !self.foreign_queued.swap(false, Ordering::SeqCst) {
            return;
        }
        let queued =
            std::mem::take(&mut *self.foreign_queue.lock().unwrap_or_else(|e| e.into_inner()));
        for (key, n, mask, private) in queued {
            Self::wake_foreign_locked(st, key, n, mask, private);
        }
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
        let mut waiters: Vec<u64> = st
            .outside
            .iter()
            .filter(|&(_, &k)| k == key)
            .map(|(&t, _)| t)
            .collect();
        waiters.sort_unstable();
        waiters.truncate(n);
        for &t in &waiters {
            st.outside.remove(&t);
            st.parkers.entry(t).or_default();
            st.runnable.insert(t, DetWake::Woken);
        }
        waiters.len()
    }

    /// A let-go thread enters a native wait on `key`; see [`wake_outside`](Self::wake_outside).
    pub(crate) fn wait_outside(&self, me: u64, key: DetKey) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        if st.let_go.contains(&me) {
            st.outside.insert(me, key);
        }
    }

    /// A native wait returned. A thread let go when the schedule detached, while a run is active
    /// again, waits for the baton before going back to the code under test, so it never runs
    /// beside the thread holding it.
    pub(crate) fn rejoin(&self, me: u64) {
        let _passthrough = Passthrough::enter();
        let mut st = self.lock();
        st.outside.remove(&me);
        if self.detached() || !st.let_go.remove(&me) {
            return;
        }
        let parker = st.parkers.entry(me).or_default().clone();
        if st.holder != Some(me) {
            st.runnable.entry(me).or_insert(DetWake::Woken);
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
        let held: Vec<usize> = st
            .owners
            .iter()
            .filter(|&(_, &owner)| owner == me)
            .map(|(&addr, _)| addr)
            .collect();
        #[cfg(windows)]
        let held = {
            let mut held = held;
            for (&addr, owners) in &mut st.shared_owners {
                if owners.remove(&me) {
                    held.push(addr);
                }
            }
            st.shared_owners.retain(|_, owners| !owners.is_empty());
            held
        };
        for &addr in &held {
            st.owners.remove(&addr);
            Self::wake_key(st, DetKey::Addr(addr), usize::MAX, DetWake::Woken);
        }
        !held.is_empty()
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
        if st.runnable.is_empty() {
            // Nobody else can run: yielding changes nothing, so keep the baton.
            return;
        }
        st.runnable.insert(me, DetWake::Woken);
        let parker = st.parkers.entry(me).or_default().clone();
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
        st.spinners.insert(me, clock);
        let others_work = st.runnable.keys().any(|t| !st.spinners.contains_key(t));
        let clock_elsewhere = st.spinners.iter().any(|(&t, &c)| c && t != me);
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
        self.lock().spinners.remove(&me);
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
        let Some(key) = st.blocked.get(&me).map(|b| b.key) else {
            return;
        };
        Self::unblock(&mut st, me, DetWake::Woken);
        st.repolled.insert(me, key);
        Self::grant_if_idle(st);
    }

    /// Moves up to `n` of `key`'s waiters, oldest first, from `blocked` to `runnable` with `why`.
    /// Queue entries for threads no longer blocked (timed out, re-polled, gone) are dropped
    /// without counting. Returns how many moved; grants nothing.
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

    fn wake_key_matching(
        st: &mut State,
        key: DetKey,
        n: usize,
        why: DetWake,
        matches: impl Fn(&Blocked) -> bool,
    ) -> usize {
        let State {
            blocked,
            queues,
            runnable,
            ..
        } = st;
        let Some(queue) = queues.get_mut(&key) else {
            return 0;
        };
        let mut woken = 0;
        let mut index = 0;
        while woken < n && index < queue.len() {
            let t = queue[index];
            let Some(wait) = blocked.get(&t).filter(|wait| wait.key == key) else {
                queue.remove(index);
                continue;
            };
            if matches(wait) {
                queue.remove(index);
                blocked.remove(&t);
                runnable.insert(t, why);
                woken += 1;
            } else {
                index += 1;
            }
        }
        woken
    }

    /// Moves `t`, if blocked, to `runnable` with `why`, removing it from its key's queue.
    fn unblock(st: &mut State, t: u64, why: DetWake) {
        if let Some(b) = st.blocked.remove(&t) {
            if let Some(q) = st.queues.get_mut(&b.key) {
                q.retain(|&w| w != t);
            }
            st.runnable.insert(t, why);
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
        let due: Vec<u64> = st
            .blocked
            .iter()
            .filter(|(_, b)| b.deadline.is_some_and(|at| now >= at) && matches(b))
            .map(|(&t, _)| t)
            .collect();
        for t in due {
            Self::unblock(st, t, DetWake::TimedOut);
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
        let others_run = !st.runnable.is_empty();
        Self::release_due_matching(&mut st, now, |wait| {
            matches!(wait.key, DetKey::Addr(_)) && (!others_run || wait.woken_by_timer())
        });
        Self::grant_if_idle(st);
    }

    /// Hands the baton to the next runnable thread after the cursor, or gives the lock back if no
    /// thread is runnable.
    fn grant_next(mut st: MutexGuard<'_, State>) -> Option<MutexGuard<'_, State>> {
        let next = st
            .runnable
            .range(st.last.saturating_add(1)..)
            .next()
            .or_else(|| st.runnable.iter().next())
            .map(|(&t, &why)| (t, why));
        let Some((t, why)) = next else {
            return Some(st);
        };
        st.runnable.remove(&t);
        st.holder = Some(t);
        st.last = t;
        st.end_idle();
        let parker = st.parkers.entry(t).or_default().clone();
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
            if st.blocked.is_empty() {
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
        return st.blocked.values().any(|b| {
            b.outside_holder
                || matches!(b.key, DetKey::Addr(addr) if crate::domain::in_static_image(addr))
        });
        #[cfg(not(any(target_os = "linux", windows)))]
        st.blocked.values().any(|b| b.outside_holder)
    }

    /// Every root has left and nothing can run: lets every blocked thread go, to wait outside the
    /// schedule from now on. Called with no holder.
    fn detach(&self, mut st: MutexGuard<'_, State>) {
        self.detached.store(true, Ordering::SeqCst);
        let blocked: Vec<u64> = std::mem::take(&mut st.blocked).into_keys().collect();
        st.queues.clear();
        st.repolled.clear();
        st.foreign.clear();
        st.end_idle();
        let parkers: Vec<Arc<Parker>> = blocked
            .iter()
            .filter_map(|t| st.parkers.get(t).cloned())
            .collect();
        st.let_go.extend(blocked);
        drop(st);
        for parker in parkers {
            parker.grant(DetWake::Woken);
        }
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
        if !st.runnable.is_empty() {
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
        let addr_waiters: Vec<(u64, DetKey)> = st
            .blocked
            .iter()
            .filter(|(_, b)| b.should_repoll())
            .map(|(&t, b)| (t, b.key))
            .collect();
        for (t, key) in addr_waiters {
            Self::unblock(st, t, DetWake::Woken);
            st.repolled.insert(t, key);
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
