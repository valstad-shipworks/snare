//! The virtual clock a [`Sim`](crate::Sim) runs on, and the [`Layer`] that answers the code under
//! test's clock reads, sleeps and timed waits from it.
//!
//! The clock is a [`Line`] through real time published under a seqlock (`Clock::seq`), plus two
//! timer tables (participants' and foreign threads') that the quiescence time skip and an
//! [`Executive`](crate::sched::Executive) jump between. Readings are monotonic: every value handed
//! out raises `Clock::floor`, and no write ever moves `monotonic_nanos` back.
//!
//! Lock order: `Clock::control` before either timer table; the participants' table (`pending`)
//! before the foreign one when both are held in turn, never both at once. No timer table is held
//! while a waker runs: wakers taken under one are woken by [`wake_all`] after it is let go, on the
//! clock's `snare-timer-wakes` thread. `control` may still be held then (a charge, or a time skip that
//! only prunes), so a waker must not move the clock itself.

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering, fence};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError, Weak};
use std::task::Waker;
use std::time::Duration;

use snare_interpose::{ClockKind, Flow, Layer, RaceCell, SleepRequest, SpinStep, ThreadClass};

/// 2^32, the scale of the 32.32 fixed-point rate in [`Line::rate_q32`].
const Q32: f64 = 4_294_967_296.0;

/// The fastest a scaled clock runs: a million virtual seconds per real second. A snare choice: at
/// this rate `rate_q32` is below 2^52, so the `f64` → fixed-point conversion stays exact to the
/// unit, and an hour of real time still fits a `u64` of virtual nanoseconds.
pub(crate) const MAX_RATE: f64 = 1e6;

/// How long a wait on a paused or driven clock sleeps in real time between checks; a clock
/// writer's kick cuts it short. A snare choice: long enough to cost nothing while held, short
/// enough that a missed kick shows only as latency.
const HELD_POLL: Duration = Duration::from_millis(200);

/// How long, in real time, a clock spin waits for a waiter the clock already reached to run
/// before it moves time on regardless (see [`Clock::spin_step`]). A snare choice, the same 5 ms a
/// sim wait settles for after a time skip on another thread's behalf: long enough for the woken
/// thread to run, and a bound on how long a wait that never takes its deadline can hold a spin.
const SPIN_SETTLE: Duration = Duration::from_millis(5);

/// `CLOCK_REALTIME` at monotonic zero on a clock that keeps the fixed epoch: Unix time
/// 1_700_000_000 s = 2023-11-14T22:13:20Z (`date -u -r 1700000000`), a round recent instant so
/// timestamps look plausible; a snare choice.
const FIXED_EPOCH_NANOS: u64 = 1_700_000_000 * 1_000_000_000;

/// What a continuing clock's start is rounded to, and the least it starts past the process's
/// highest reading: a whole second, which every timer unit a hooked clock API converts to (Mach
/// ticks, `QueryPerformanceCounter` ticks at any whole-hertz frequency, 100 ns intervals) divides,
/// so sim time converts the same in every sim. The gap outlasts caches that trust a timestamp for
/// under a second of `SystemTime` (chrono's thread-local `Local` zone); it costs no real time.
const START_GRAIN: u64 = 1_000_000_000;

/// Every begun clock of the process, and the highest readings of those already dropped: where a
/// continuing clock starts (see [`Clock::begin`]).
struct Timelines {
    live: Vec<Weak<Clock>>,
    /// The highest monotonic reading a dropped clock reached.
    past_monotonic: u64,
    /// The highest `CLOCK_REALTIME` reading a dropped clock reached.
    past_realtime: u64,
}

static TIMELINES: Mutex<Timelines> = Mutex::new(Timelines {
    live: Vec::new(),
    past_monotonic: 0,
    past_realtime: 0,
});

/// Locks [`TIMELINES`], ignoring poison: every update leaves it consistent.
fn lock_timelines() -> MutexGuard<'static, Timelines> {
    TIMELINES.lock().unwrap_or_else(|e| e.into_inner())
}

/// Virtual time as a line through real time: `v(real) = min(horizon, anchor_v + (real -
/// anchor_real) * rate)`, the rate in 32.32 fixed point so a large rate never saturates a float
/// cast.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Line {
    /// Virtual monotonic nanoseconds at the anchor.
    pub(crate) anchor_v: u64,
    /// Real nanoseconds since [`real_origin`](crate::readiness::real_origin) at the anchor.
    pub(crate) anchor_real: u64,
    /// Virtual nanoseconds per real nanosecond, times 2^32; 0 holds the line at `anchor_v`.
    pub(crate) rate_q32: u64,
    /// The virtual time the line never passes: `u64::MAX` in a base or scaled mode, an
    /// executive's grant limit while driven.
    pub(crate) horizon: u64,
}

impl Line {
    /// The virtual reading at real time `real`; a `real` before the anchor reads `anchor_v`.
    /// Computed in `u128` so `dr * rate_q32` never overflows, then saturated to `u64`.
    pub(crate) fn value_at(&self, real: u64) -> u64 {
        let dr = real.saturating_sub(self.anchor_real) as u128;
        let dv = (dr * self.rate_q32 as u128) >> 32;
        let v = (self.anchor_v as u128 + dv).min(u64::MAX as u128) as u64;
        v.min(self.horizon)
    }

    /// The earliest real time at which the line reaches `v`, or `None` if it never does. Rounds
    /// up, so `value_at(real_at(v)) >= v` always holds.
    pub(crate) fn real_at(&self, v: u64) -> Option<u64> {
        if v > self.horizon {
            return None;
        }
        if v <= self.anchor_v {
            return Some(self.anchor_real);
        }
        if self.rate_q32 == 0 {
            return None;
        }
        let dr = (((v - self.anchor_v) as u128) << 32).div_ceil(self.rate_q32 as u128);
        Some((self.anchor_real as u128 + dr).min(u64::MAX as u128) as u64)
    }
}

/// `rate` virtual seconds per real second as 32.32 fixed point, clamped to `[0, MAX_RATE]`. An
/// infinite rate clamps to [`MAX_RATE`]; callers map infinity to a base mode before getting here.
pub(crate) fn rate_to_q32(rate: f64) -> u64 {
    (rate.clamp(0.0, MAX_RATE) * Q32).round() as u64
}

/// Panics unless `rate` is a clock rate: in (0, 1e6] scaled to real time (larger values clamp),
/// 0.0 for paused, or infinity for virtual time. A deterministic sim refuses real-time rates.
#[track_caller]
pub(crate) fn validate_rate(rate: f64, deterministic: bool) {
    assert!(
        rate >= 0.0,
        "time rate {rate} would run the monotonic clock backwards or undefined; use a rate in \
         (0, 1e6], 0.0 to pause or f64::INFINITY for virtual time"
    );
    assert!(
        !(deterministic && rate.is_finite() && rate > 0.0),
        "a deterministic Sim cannot run its clock at a real-time rate ({rate}): nothing in it may \
         depend on real time; pause, advance or set the clock instead"
    );
}

/// A driver thread's time: the monotonic reading, and the executive generation it was set under.
pub(crate) type DriverTime = (u64, u64);

thread_local! {
    /// The monotonic reading a driver thread sees while it acts at an executive's timestamp.
    static DRIVER_TIME: Cell<Option<DriverTime>> = const { Cell::new(None) };
    /// Set for good on a `snare-timer-wakes` thread, which wakes the wakers its clock took while
    /// their poster may hold locks of its own.
    static CLOCK_WAKE: Cell<bool> = const { Cell::new(false) };
}

/// Whether the calling thread is waking wakers the clock took. The clock's caller wakes the
/// sim's waiters afterwards, so a waker run now only marks its task woken.
pub(crate) fn in_clock_wake() -> bool {
    CLOCK_WAKE.try_with(Cell::get).unwrap_or(false)
}

/// A key for a waker registered on a clock or on the real-time waker, unique in the process.
pub(crate) fn wake_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Sets the calling thread's driver time, returning the previous one.
pub(crate) fn set_driver_time(t: Option<DriverTime>) -> Option<DriverTime> {
    DRIVER_TIME.try_with(|d| d.replace(t)).unwrap_or(None)
}

/// The waits, one-shot events and wakers due at one instant, and the lineages of the threads
/// waiting.
#[derive(Default)]
pub(crate) struct Entry {
    /// Blocked sleeps and timed waits due here; each is dropped by its own waiter
    /// ([`Clock::unregister_timer`]) or pruned with its entry once the clock is past it
    /// ([`take_upto`]), never by firing.
    waits: u32,
    /// One-shot events (a datagram arriving, say), dropped when time reaches them.
    events: u32,
    /// Wakers from [`Clock::register_wake`], keyed by [`wake_id`], taken when time reaches them.
    wakers: Vec<(u64, Option<u64>, Waker)>,
    /// A delivered wake holds its deadline until the task polls or cancels its timer.
    awaiting: Vec<u64>,
    /// The thread lineage of each of `waits`, for an executive's listing; at most `waits` long.
    owners: TimerOwners,
}

#[derive(Default)]
struct TimerOwners {
    inline: [u64; 4],
    len: usize,
    overflow: Vec<u64>,
}

impl TimerOwners {
    fn len(&self) -> usize {
        self.len
    }

    fn first(&self) -> Option<&u64> {
        self.iter().next()
    }

    fn iter(&self) -> impl Iterator<Item = &u64> {
        self.inline[..self.len.min(self.inline.len())]
            .iter()
            .chain(self.overflow.iter())
    }

    fn push(&mut self, owner: u64) {
        if self.len < self.inline.len() {
            self.inline[self.len] = owner;
        } else {
            self.overflow.push(owner);
        }
        self.len += 1;
    }

    fn pop(&mut self) -> Option<u64> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        if self.len >= self.inline.len() {
            self.overflow.pop()
        } else {
            Some(self.inline[self.len])
        }
    }

    fn swap_remove(&mut self, i: usize) {
        if i >= self.inline.len() {
            self.overflow.swap_remove(i - self.inline.len());
            self.len -= 1;
        } else if let Some(last) = self.pop()
            && i < self.len
        {
            self.inline[i] = last;
        }
    }
}

impl Entry {
    /// Whether nothing is due here any more, so the entry can leave its table.
    fn is_empty(&self) -> bool {
        self.waits == 0 && self.events == 0 && self.wakers.is_empty() && self.awaiting.is_empty()
    }

    /// Everything due here, for an executive's count of what a move released.
    fn count(&self) -> u32 {
        self.waits + self.events + u32::try_from(self.wakers.len()).unwrap_or(u32::MAX)
    }
}

/// A timer table: monotonic nanos → what is due then, ordered so the earliest is first.
#[derive(Default)]
struct Timers {
    entries: BTreeMap<u64, Entry>,
    wake_deadlines: HashMap<u64, u64>,
}

impl Deref for Timers {
    type Target = BTreeMap<u64, Entry>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl DerefMut for Timers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.entries
    }
}

impl Timers {
    fn register_wake(&mut self, at: u64, id: u64, owner: Option<u64>, waker: Waker) {
        self.entries
            .entry(at)
            .or_default()
            .wakers
            .push((id, owner, waker));
        self.wake_deadlines.insert(id, at);
    }

    fn take_wakers_at(&mut self, at: u64, hold: bool, out: &mut Vec<Waker>) -> bool {
        let entry = self.entries.get_mut(&at).unwrap();
        let any = !entry.wakers.is_empty();
        for (id, _, waker) in entry.wakers.drain(..) {
            if hold {
                entry.awaiting.push(id);
            } else {
                self.wake_deadlines.remove(&id);
            }
            out.push(waker);
        }
        any
    }

    fn cancel_wake(&mut self, id: u64) -> Option<Option<Waker>> {
        let at = self.wake_deadlines.remove(&id)?;
        let entry = self.entries.get_mut(&at).unwrap();
        let waker = if let Some(i) = entry.wakers.iter().position(|&(key, _, _)| key == id) {
            Some(entry.wakers.swap_remove(i).2)
        } else {
            let i = entry.awaiting.iter().position(|&key| key == id).unwrap();
            entry.awaiting.swap_remove(i);
            None
        };
        if entry.is_empty() {
            self.entries.remove(&at);
        }
        Some(waker)
    }
}

/// One pending timer, for an executive's listing: when, and the lineage of the thread waiting
/// (`None` for an event).
pub(crate) struct PendingTimer {
    pub(crate) at: u64,
    pub(crate) owner: Option<u64>,
}

/// `d` in nanoseconds, saturating at `u64::MAX` (about 584 years).
pub(crate) fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// The 100 ns interval Windows timer APIs count in.
#[cfg(windows)]
const WINDOWS_TIMER_UNIT: u64 = 100;

/// The earliest monotonic time past `t` at which the code under test sees the clock move: 1 ns
/// later; on Windows 100 ns, the unit of its timer APIs, or the next `QueryPerformanceCounter` tick
/// should that be later, since std's `Instant` cannot see inside a tick. 100 ns covers a tick at
/// every counter frequency from 10 MHz up (the frequency under a hypervisor and on recent
/// Windows), so the landing does not depend on the host. Saturates at the end of the clock.
fn creep_past(t: u64) -> u64 {
    #[cfg(windows)]
    {
        let tick = u128::from(nanos(snare_interpose::next_performance_count(
            Duration::from_nanos(t),
        )));
        let tick = if tick > u128::from(t) {
            tick as u64
        } else {
            t.saturating_add(1)
        };
        tick.max(t.saturating_add(WINDOWS_TIMER_UNIT))
    }
    #[cfg(not(windows))]
    {
        t.saturating_add(1)
    }
}

/// Real nanoseconds since the process origin, the time base of [`Line::anchor_real`].
fn real_nanos() -> u64 {
    nanos(crate::readiness::real_now())
}

/// The virtual clock every [`Sim`](crate::Sim) runs on — on its own in a plain sim, or driving a
/// `SimHost`'s timestamps as well.
///
/// Its base mode is discrete-event (the default: reads hold still, and time moves by time skips
/// and charged call latency) or as-fast-as-possible (each read ticks it a microsecond and a sleep
/// jumps it forward). On top of either it can run scaled to real time at a rate, or be paused,
/// which holds every sleeper and timed wait until something moves time.
pub(crate) struct Clock {
    /// The reading in a base mode, and the line's anchor while scaled.
    monotonic_nanos: AtomicU64,
    /// `CLOCK_REALTIME` at monotonic zero, in nanoseconds since the Unix epoch: the sim's boot
    /// time. Set once, by [`begin`](Clock::begin).
    base_realtime_nanos: AtomicU64,
    /// The monotonic reading sim time counts from: zero on the fixed epoch, else where
    /// [`begin`](Clock::begin) started the clock.
    origin: AtomicU64,
    /// [`begin`](Clock::begin) has placed the clock and listed it in [`TIMELINES`].
    begun: AtomicBool,
    /// `CLOCK_TAI` minus `CLOCK_REALTIME`, from the sim's builder.
    tai_offset_nanos: u64,
    /// Discrete-event base mode: a sleep registers its wake deadline and blocks; virtual time jumps
    /// to the earliest deadline only when the whole sim is quiescent. Off = as-fast-as-possible.
    discrete: AtomicBool,
    /// Held: reads return the held value and nothing moves time but a writer. Kept under the
    /// seqlock with the line, which keeps its rate so [`resume`](Clock::resume) restores it.
    paused: AtomicBool,
    /// Seqlock over the line (`monotonic_nanos`, `anchor_real`, `rate_q32`, `horizon`): odd while
    /// a writer (always under `control`) is mid-update, bumped by 2 per write.
    seq: AtomicU64,
    /// [`Line::anchor_real`].
    anchor_real: AtomicU64,
    /// Non-zero while scaled to real time (kept through a pause, so a resume restores it), or
    /// while an executive's grant flows.
    rate_q32: AtomicU64,
    /// [`Line::horizon`].
    horizon: AtomicU64,
    /// The scaled rate as `f64` bits, or the grant's rate while driven; 0.0 in a base mode.
    scaled_rate: AtomicU64,
    /// The highest reading handed out, which keeps reads monotonic across re-anchors.
    floor: AtomicU64,
    /// Refuses real-time rates: set for a deterministic sim, where nothing may depend on real time.
    deterministic: AtomicBool,
    /// Owned by an executive: the line is a grant, clamped to its horizon, and only the executive
    /// moves time.
    driven: AtomicBool,
    /// While an executive's timestamp is open, the monotonic time it runs at: what the code under
    /// test reads, though the clock itself stays just short of it until the timestamp ends.
    stamp: AtomicU64,
    /// Moves on each time an executive lets go, so a driver time set under it lapses on every
    /// thread.
    driver_gen: AtomicU64,
    /// Held by every write that re-anchors the clock or moves it in a base mode, so a mode change
    /// never interleaves with a time skip, a charge or a jump.
    control: Mutex<()>,
    /// Scaled timers pruned on registration after real time reached them, whose waiters may not
    /// have woken yet; the next time skip reports them as fired.
    fired: AtomicBool,
    /// Wakers from [`register_wake`](Clock::register_wake) were woken since the domain last asked
    /// (see `Layer::take_timer_wakes`).
    woke_timers: AtomicBool,
    /// Real nanoseconds since the process origin at which a clock spin first found a participant
    /// wait the clock had reached but its waiter had not yet taken; 0 while there is none. See
    /// [`spin_step`](Clock::spin_step).
    spin_due_since: AtomicU64,
    /// A time skip or a quiescence check held off for a wait the clock had reached but its waiter
    /// had not yet taken (see [`wait_due`](Clock::wait_due)); the waiter that takes the last such
    /// wait wakes the sim's waiters to try again.
    held: AtomicBool,
    /// Pending sleep/timeout wake deadlines and one-shot events (monotonic nanos → what is due
    /// then), for the quiescence time-skip and an executive's jumps. Waits are refcounted so a timed
    /// socket wait that returns early can drop its deadline without disturbing another wait that
    /// happens to share the same instant; an entry at or before the current time is due and not
    /// yet taken.
    pending: Mutex<Timers>,
    /// The timed waits of threads that are not participants, kept as `pending` is. A time skip
    /// lands on one only once every participant waits on something only such a thread can do;
    /// otherwise they are satisfied as the clock passes them.
    foreign: Mutex<Timers>,
    /// Every run of the sim has ended (see [`set_dormant`](Clock::set_dormant)).
    dormant: AtomicBool,
    /// The reading when the dormant spell began.
    dormant_v: AtomicU64,
    /// Real nanoseconds since the process origin when the dormant spell began.
    dormant_real: AtomicU64,
    /// The thread this clock's wakers run on, once one has run (see [`wake_all`]).
    runner: RaceCell<Arc<WakeRunner>>,
    /// The [`Domain::key`](snare_interpose::Domain::key) of the sim the clock serves, whose
    /// waiters its own bumps wake; 0 until the sim is installed.
    domain: AtomicUsize,
    owner: Mutex<Option<snare_interpose::WeakDomain>>,
}

impl Drop for Clock {
    /// Folds the readings the clock reached into [`TIMELINES`] and stops the thread the clock's
    /// wakers ran on, if one was started.
    fn drop(&mut self) {
        if self.begun.load(Ordering::Acquire) {
            let (monotonic, realtime) = self.high_water();
            let this: *const Clock = self;
            snare_interpose::real(|| {
                let mut timelines = lock_timelines();
                timelines.past_monotonic = timelines.past_monotonic.max(monotonic);
                timelines.past_realtime = timelines.past_realtime.max(realtime);
                timelines.live.retain(|clock| clock.as_ptr() != this);
            });
        }
        if let Some(runner) = self.runner.get() {
            snare_interpose::real(|| runner.close());
        }
    }
}

/// Whether the calling thread's timers are foreign: it runs in a sim but is not a participant.
fn foreign_caller() -> bool {
    snare_interpose::thread_class().is_some_and(|class| class != ThreadClass::Participant)
}

/// Whether the calling thread is its sim's driver, whose clock reads and sleeps are real.
fn driver_caller() -> bool {
    snare_interpose::thread_class() == Some(ThreadClass::Driver)
}

impl Clock {
    /// A discrete-event clock, the default base mode, at monotonic zero on the fixed epoch, with
    /// `CLOCK_TAI` leading `CLOCK_REALTIME` by `tai_offset_secs`. A sim's clock is then placed on
    /// the process's timeline by [`begin`](Self::begin).
    pub(crate) fn new(tai_offset_secs: u64) -> Self {
        Clock {
            monotonic_nanos: AtomicU64::new(0),
            base_realtime_nanos: AtomicU64::new(FIXED_EPOCH_NANOS),
            origin: AtomicU64::new(0),
            begun: AtomicBool::new(false),
            tai_offset_nanos: tai_offset_secs * 1_000_000_000,
            discrete: AtomicBool::new(true),
            paused: AtomicBool::new(false),
            seq: AtomicU64::new(0),
            anchor_real: AtomicU64::new(0),
            rate_q32: AtomicU64::new(0),
            horizon: AtomicU64::new(u64::MAX),
            scaled_rate: AtomicU64::new(0f64.to_bits()),
            floor: AtomicU64::new(0),
            deterministic: AtomicBool::new(false),
            driven: AtomicBool::new(false),
            stamp: AtomicU64::new(0),
            driver_gen: AtomicU64::new(0),
            control: Mutex::new(()),
            fired: AtomicBool::new(false),
            woke_timers: AtomicBool::new(false),
            spin_due_since: AtomicU64::new(0),
            held: AtomicBool::new(false),
            pending: Mutex::new(Timers::default()),
            foreign: Mutex::new(Timers::default()),
            dormant: AtomicBool::new(false),
            dormant_v: AtomicU64::new(0),
            dormant_real: AtomicU64::new(0),
            runner: RaceCell::new(),
            domain: AtomicUsize::new(0),
            owner: Mutex::new(None),
        }
    }

    /// The [`Domain::key`](snare_interpose::Domain::key) of the sim the clock serves; 0 before
    /// [`set_domain`](Self::set_domain), which a bump reads as every domain.
    pub(crate) fn domain(&self) -> usize {
        self.domain.load(Ordering::Acquire)
    }

    /// Records the domain of the sim the clock now serves (a `SimHost`'s clock serves each sim
    /// built on the host in turn).
    pub(crate) fn set_domain(&self, domain: &snare_interpose::Domain) {
        *self.owner.lock().unwrap_or_else(|e| e.into_inner()) = Some(domain.downgrade());
        self.domain.store(domain.key(), Ordering::Release);
    }

    /// Begins (`true`) or ends a dormant spell: every run of the sim has ended, and whatever still
    /// waits on the clock is a thread left over from one, which nothing in the test waits on.
    /// While dormant a time skip lands no further past the reading the spell began at than real
    /// time has moved since, so a leftover thread sleeping in a loop sleeps in real time rather
    /// than racing the clock ahead at full speed, and an as-fast-as-possible clock holds still
    /// between skips instead of jumping each sleep. The reading is kept when the spell ends.
    pub(crate) fn set_dormant(&self, on: bool) {
        self.controlled(|| {
            if on {
                self.dormant_v.store(self.peek(), Ordering::Release);
                self.dormant_real.store(real_nanos(), Ordering::Release);
            }
            self.dormant.store(on, Ordering::Release);
        });
    }

    /// Whether a dormant spell is on (see [`set_dormant`](Self::set_dormant)).
    fn is_dormant(&self) -> bool {
        self.dormant.load(Ordering::Acquire)
    }

    /// While dormant, the furthest a time skip may land: the reading the spell began at plus the
    /// real time since. `None` otherwise.
    fn dormant_limit(&self) -> Option<u64> {
        self.is_dormant().then(|| {
            let real = real_nanos().saturating_sub(self.dormant_real.load(Ordering::Acquire));
            self.dormant_v.load(Ordering::Acquire).saturating_add(real)
        })
    }

    /// Places the clock on the process's timeline, once, before the first sim built on it runs;
    /// later calls do nothing. On the `fixed` epoch it stays at monotonic zero and realtime
    /// 2023-11-14T22:13:20Z, so absolute readings replay. Otherwise it continues: monotonic time
    /// starts at least [`START_GRAIN`] past the highest reading any clock of the process has handed
    /// out, on a whole [`START_GRAIN`], and realtime no earlier than the highest realtime reading, so a value a
    /// library kept in a static from an earlier sim, or from one still running, is never ahead of
    /// this sim's clocks. Realtime minus monotonic, the boot time, is fixed from here on.
    pub(crate) fn begin(self: &Arc<Self>, fixed: bool) {
        snare_interpose::real(|| {
            let mut timelines = lock_timelines();
            if self.begun.load(Ordering::Acquire) {
                return;
            }
            // A clock whose last `Arc` is gone but whose drop has not yet folded its readings in
            // is unreadable; its drop is under way and takes the lock next.
            while timelines.live.iter().any(|clock| clock.strong_count() == 0) {
                drop(timelines);
                std::thread::yield_now();
                timelines = lock_timelines();
            }
            // Dropped only once the lock is let go: the last `Arc` of a clock may be among them,
            // and its drop takes the lock.
            let live: Vec<Arc<Clock>> = timelines.live.iter().filter_map(Weak::upgrade).collect();
            if !fixed {
                let (mut monotonic, mut realtime) =
                    (timelines.past_monotonic, timelines.past_realtime);
                for (m, r) in live.iter().map(|clock| clock.high_water()) {
                    monotonic = monotonic.max(m);
                    realtime = realtime.max(r);
                }
                self.start_at(monotonic, realtime);
            }
            self.begun.store(true, Ordering::Release);
            timelines.live.push(Arc::downgrade(self));
            drop(timelines);
            drop(live);
        });
    }

    /// Moves a fresh clock's start to the first [`START_GRAIN`] a whole grain past `monotonic`
    /// (zero for the first clock of the process), with
    /// `CLOCK_REALTIME` there no earlier than `realtime` and sim time counted from there.
    fn start_at(&self, monotonic: u64, realtime: u64) {
        let base = realtime.saturating_sub(monotonic).max(FIXED_EPOCH_NANOS);
        let start = if monotonic == 0 && realtime == 0 {
            0
        } else {
            monotonic
                .saturating_add(START_GRAIN)
                .div_ceil(START_GRAIN)
                .saturating_mul(START_GRAIN)
        };
        self.controlled(|| {
            self.base_realtime_nanos.store(base, Ordering::Release);
            self.origin.store(start, Ordering::Release);
            self.publish_line(
                start,
                self.anchor_real.load(Ordering::Relaxed),
                self.rate_q32.load(Ordering::Relaxed),
                self.horizon.load(Ordering::Relaxed),
            );
            self.floor.fetch_max(start, Ordering::AcqRel);
        });
    }

    /// The highest monotonic and realtime readings handed out so far, an open executive
    /// timestamp's included.
    fn high_water(&self) -> (u64, u64) {
        let monotonic = self.peek().max(self.stamp.load(Ordering::Acquire));
        (monotonic, self.realtime_at(monotonic))
    }

    /// `CLOCK_REALTIME` at monotonic zero: the sim's boot time.
    #[cfg(unix)]
    pub(crate) fn base_realtime(&self) -> Duration {
        Duration::from_nanos(self.base_realtime_nanos.load(Ordering::Acquire))
    }

    /// `CLOCK_REALTIME` at sim time zero, where the sim's timeline (see `scope::timeline`) starts.
    pub(crate) fn timeline_realtime(&self) -> Duration {
        Duration::from_nanos(self.realtime_at(self.origin()))
    }

    /// The monotonic reading sim time counts from.
    pub(crate) fn origin(&self) -> u64 {
        self.origin.load(Ordering::Acquire)
    }

    /// `CLOCK_REALTIME` now, without ticking an as-fast-as-possible clock: the instant a file
    /// operation stamps on what it touches.
    #[cfg(unix)]
    pub(crate) fn realtime_peek(&self) -> Duration {
        Duration::from_nanos(self.realtime_at(self.peek()))
    }

    /// `CLOCK_REALTIME` nanoseconds at monotonic reading `monotonic`: the two never drift apart,
    /// since nothing in a sim steps or slews its realtime clock.
    fn realtime_at(&self, monotonic: u64) -> u64 {
        self.base_realtime_nanos
            .load(Ordering::Acquire)
            .saturating_add(monotonic)
    }

    /// Picks the base mode, discrete-event or as-fast-as-possible; set once, before the sim's
    /// threads run.
    pub(crate) fn set_discrete(&self, on: bool) {
        self.discrete.store(on, Ordering::Relaxed);
    }

    /// Marks the clock as a deterministic sim's, which refuses real-time rates; set once, before
    /// the sim's threads run.
    pub(crate) fn set_deterministic(&self, on: bool) {
        self.deterministic.store(on, Ordering::Relaxed);
    }

    /// Whether the clock refuses real-time rates (see [`set_deterministic`](Self::set_deterministic)).
    pub(crate) fn is_deterministic(&self) -> bool {
        self.deterministic.load(Ordering::Relaxed)
    }

    /// Whether an executive owns the clock.
    pub(crate) fn is_driven(&self) -> bool {
        self.driven.load(Ordering::Acquire)
    }

    /// Whether the base mode is discrete-event rather than as-fast-as-possible.
    fn is_discrete(&self) -> bool {
        self.discrete.load(Ordering::Relaxed)
    }

    /// Whether the clock is held by [`pause`](Self::pause).
    pub(crate) fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    /// Whether the line runs at a rate: scaled to real time, or under a flowing grant.
    fn is_scaled(&self) -> bool {
        self.rate_q32.load(Ordering::Acquire) != 0
    }

    /// As-fast-as-possible and running: reads tick and sleeps jump.
    fn jumps(&self) -> bool {
        !self.is_discrete()
            && !self.is_paused()
            && !self.is_scaled()
            && !self.is_driven()
            && !self.is_dormant()
    }

    /// The line, whether it is paused, and a real-time sample taken inside the same seqlock read,
    /// so the sample never postdates a re-anchor the line misses.
    fn line(&self) -> (Line, u64, bool) {
        loop {
            let s1 = self.seq.load(Ordering::Acquire);
            if s1 & 1 == 1 {
                std::hint::spin_loop();
                continue;
            }
            let line = Line {
                anchor_v: self.monotonic_nanos.load(Ordering::Relaxed),
                anchor_real: self.anchor_real.load(Ordering::Relaxed),
                rate_q32: self.rate_q32.load(Ordering::Relaxed),
                horizon: self.horizon.load(Ordering::Relaxed),
            };
            let paused = self.paused.load(Ordering::Relaxed);
            let real = real_nanos();
            fence(Ordering::Acquire);
            if self.seq.load(Ordering::Relaxed) == s1 {
                return (line, real, paused);
            }
        }
    }

    /// The reading of a clock that is not running along a line: the anchor, or a higher value
    /// already handed out.
    fn held_value(&self) -> u64 {
        self.monotonic_nanos
            .load(Ordering::Acquire)
            .max(self.floor.load(Ordering::Acquire))
    }

    /// The current monotonic reading in nanoseconds, without ticking. Ignores an open timestamp:
    /// this is the clock's own position, which stays short of the stamp until it closes. A line
    /// reading raises `floor`, so no later read returns less.
    pub(crate) fn peek(&self) -> u64 {
        if self.is_driven() {
            return self.line_value();
        }
        if self.is_paused() || !self.is_scaled() {
            return self.held_value();
        }
        let (line, real, paused) = self.line();
        if paused || line.rate_q32 == 0 {
            return self.held_value();
        }
        let v = line.value_at(real);
        self.floor.fetch_max(v, Ordering::AcqRel).max(v)
    }

    /// The line's reading now, clamped to its horizon, never below a reading already handed out.
    fn line_value(&self) -> u64 {
        let (line, real, _) = self.line();
        let v = line.value_at(real);
        self.floor.fetch_max(v, Ordering::AcqRel).max(v)
    }

    /// Re-anchors a base or scaled line at `to(reading)` now, running at `rate_q32` or held if
    /// `paused`. The reading is taken inside the write, so a reader still on the old line never
    /// samples real time past it. Called under `control`.
    fn publish(&self, rate_q32: u64, paused: bool, to: impl FnOnce(u64) -> u64) {
        let s = self.seq.load(Ordering::Relaxed);
        self.seq.store(s.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        let real = real_nanos();
        let held = self.held_value();
        let line = Line {
            anchor_v: self.monotonic_nanos.load(Ordering::Relaxed),
            anchor_real: self.anchor_real.load(Ordering::Relaxed),
            rate_q32: self.rate_q32.load(Ordering::Relaxed),
            horizon: self.horizon.load(Ordering::Relaxed),
        };
        let now = if self.is_paused() || line.rate_q32 == 0 {
            held
        } else {
            line.value_at(real).max(held)
        };
        self.monotonic_nanos.fetch_max(to(now), Ordering::Relaxed);
        self.anchor_real.store(real, Ordering::Relaxed);
        self.rate_q32.store(rate_q32, Ordering::Relaxed);
        self.horizon.store(u64::MAX, Ordering::Relaxed);
        self.paused.store(paused, Ordering::Release);
        self.seq.store(s.wrapping_add(2), Ordering::Release);
    }

    /// Publishes a whole line. `monotonic_nanos` only rises: an `anchor_v` below it leaves the
    /// anchor where it was. Called under `control`.
    fn publish_line(&self, anchor_v: u64, anchor_real: u64, rate_q32: u64, horizon: u64) {
        let s = self.seq.load(Ordering::Relaxed);
        self.seq.store(s.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        self.monotonic_nanos.fetch_max(anchor_v, Ordering::Relaxed);
        self.anchor_real.store(anchor_real, Ordering::Relaxed);
        self.rate_q32.store(rate_q32, Ordering::Relaxed);
        self.horizon.store(horizon, Ordering::Relaxed);
        self.seq.store(s.wrapping_add(2), Ordering::Release);
    }

    /// Takes `control`, ignoring poison: the guarded state is the atomics, which a panic leaves
    /// consistent outside a seqlock write.
    fn control(&self) -> MutexGuard<'_, ()> {
        self.control.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs `f` under `control`.
    fn controlled<R>(&self, f: impl FnOnce() -> R) -> R {
        let _control = self.control();
        f()
    }

    /// `control`, unless a writer holds it right now. Used on the hot read and charge paths, which
    /// skip their tick rather than queue behind a writer; the writer moves time anyway.
    fn try_control(&self) -> Option<MutexGuard<'_, ()>> {
        match self.control.try_lock() {
            Ok(guard) => Some(guard),
            Err(TryLockError::Poisoned(e)) => Some(e.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        }
    }

    /// The reading the code under test gets: ticking an as-fast-as-possible clock, and at an open
    /// timestamp's time while one is open.
    fn advance(&self) -> u64 {
        if !self.jumps() {
            // The stamp first: a timestamp closes only once the clock has reached it, so a read
            // that finds it closed then finds the clock there.
            let stamp = self.stamp.load(Ordering::Acquire);
            return self.peek().max(stamp);
        }
        let Some(_control) = self.try_control() else {
            return self.peek();
        };
        if !self.jumps() {
            return self.peek();
        }
        // A snare choice: each read of an as-fast-as-possible clock moves it 1 µs, so successive
        // reads differ and a busy-wait on elapsed time terminates.
        self.step_base(1_000).1
    }

    /// Moves a base-mode reading `by` on from the highest value handed out, returning the readings
    /// before and after. Called under `control`.
    fn step_base(&self, by: u64) -> (u64, u64) {
        let floor = self.floor.load(Ordering::Acquire);
        #[allow(deprecated)]
        let before = self
            .monotonic_nanos
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |m| {
                Some(m.max(floor).saturating_add(by))
            })
            .unwrap_or_else(|m| m)
            .max(floor);
        let after = before.saturating_add(by);
        self.floor.fetch_max(after, Ordering::AcqRel);
        (before, after)
    }

    /// Jumps an as-fast-as-possible clock forward to `wake`, as its sleeps do. `false` if the clock
    /// is not jumping (any more).
    fn jump_to(&self, wake: u64) -> bool {
        let _control = self.control();
        if !self.jumps() {
            return false;
        }
        self.monotonic_nanos.fetch_max(wake, Ordering::Relaxed);
        true
    }

    /// The code under test's reading of clock `kind`, ticking an as-fast-as-possible clock.
    pub(crate) fn now(&self, kind: ClockKind) -> Duration {
        self.reading(kind, self.advance())
    }

    /// The reading of `kind` at monotonic time `m`.
    fn reading(&self, kind: ClockKind, m: u64) -> Duration {
        // man 2 clock_gettime: CLOCK_TAI is "derived from wall-clock time but counting leap
        // seconds", i.e. CLOCK_REALTIME plus the kernel's TAI-UTC offset (set through adjtimex
        // ADJ_TAI; man 2 adjtimex). Linux-only; macOS and Windows have no TAI clock to hook.
        let nanos = match kind {
            ClockKind::Monotonic => m,
            ClockKind::Realtime => self.realtime_at(m),
            ClockKind::Tai => self.realtime_at(m) + self.tai_offset_nanos,
        };
        Duration::from_nanos(nanos)
    }

    /// `CLOCK_REALTIME` as the code under test would read it now, ticking an as-fast-as-possible
    /// clock: the send time `SimHost` takes for a datagram. A `SOF_TIMESTAMPING_TX_SOFTWARE` sender
    /// gets it as is on its error queue, and the receiver gets it plus the link delay, both in
    /// `ts[0]` of `SCM_TIMESTAMPING`, the software slot (Documentation/networking/timestamping.rst,
    /// "Most timestamps are passed in `ts[0]`").
    #[cfg(target_os = "linux")]
    pub(crate) fn tick_realtime(&self) -> Duration {
        Duration::from_nanos(self.realtime_at(self.advance()))
    }

    /// One PTP cross-timestamp sample taken at a single virtual instant: the PHC (`device`) time,
    /// `CLOCK_REALTIME` and `CLOCK_MONOTONIC_RAW`, each as `(seconds, nanoseconds)`. The PHC leads
    /// realtime by `phc_offset_nanos`. All three come from one clock tick, so a consumer reads a
    /// consistent, deterministic offset. The order is that of `struct ptp_sys_offset_precise`
    /// (`device`, `sys_realtime`, `sys_monoraw`), answered for `PTP_SYS_OFFSET_PRECISE` and its
    /// relatives (include/uapi/linux/ptp_clock.h); the sim's `CLOCK_MONOTONIC_RAW` is its monotonic
    /// clock, which no one slews.
    #[cfg(target_os = "linux")]
    pub(crate) fn ptp_sample(&self, phc_offset_nanos: i64) -> [(i64, u32); 3] {
        let m = self.advance();
        let realtime = self.realtime_at(m);
        let device = realtime.saturating_add_signed(phc_offset_nanos);
        let split = |nanos: u64| {
            (
                (nanos / 1_000_000_000) as i64,
                (nanos % 1_000_000_000) as u32,
            )
        };
        [split(device), split(realtime), split(m)]
    }

    /// Carries out a sleep on virtual time. As-fast-as-possible, the clock jumps to the wake time
    /// and the sleep returns at once. Otherwise the wake time is a pending timer and the sleep
    /// blocks until the clock reaches it — by a time skip, scaled real time passing, or a writer
    /// moving a paused clock.
    pub(crate) fn sleep(&self, request: SleepRequest) {
        let wake = match request {
            SleepRequest::For(d) => self.peek().saturating_add(nanos(d)),
            SleepRequest::Until(ClockKind::Monotonic, t) => nanos(t),
            SleepRequest::Until(kind, t) => {
                let epoch = match kind {
                    ClockKind::Tai => self.realtime_at(self.tai_offset_nanos),
                    _ => self.realtime_at(0),
                };
                nanos(t).saturating_sub(epoch)
            }
        };
        let done = || self.peek() >= wake || self.jumps() && self.jump_to(wake);
        if done() {
            return;
        }
        let readiness = crate::readiness::readiness();
        if foreign_caller() {
            // Not a participant: the sleep waits as its own timed wait, a foreign timer the clock
            // passes rather than one it skips to.
            snare_interpose::note_effect("sleep");
            loop {
                let left = Duration::from_nanos(wake.saturating_sub(self.peek()));
                let deadline = crate::readiness::Deadline::after(left);
                readiness.wait_until("sleep", Some(deadline), || {
                    self.peek() >= wake || self.jumps()
                });
                if done() {
                    return;
                }
            }
        }
        self.add_pending(wake, false, false);
        loop {
            snare_interpose::note_wait_deadline(Some(Duration::from_nanos(wake)));
            readiness.wait_until("sleep", None, || self.peek() >= wake || self.jumps());
            if done() {
                break;
            }
        }
        self.unregister_timer(wake, false);
    }

    /// Locks the foreign or the participants' timer table, ignoring poison. Callers hold at most
    /// one table at a time, taking `control` first when they need both.
    fn timers(&self, foreign: bool) -> MutexGuard<'_, Timers> {
        let timers = if foreign {
            &self.foreign
        } else {
            &self.pending
        };
        timers.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Adds one wait (owned by the calling thread's lineage) or one `event` at `wake`.
    fn add_pending(&self, wake: u64, foreign: bool, event: bool) {
        let mut timers = self.timers(foreign);
        let entry = timers.entry(wake).or_default();
        if event {
            entry.events += 1;
        } else {
            entry.waits += 1;
            entry.owners.push(snare_interpose::thread_lineage());
        }
    }

    /// Transport predicates may hold readiness, so inserting their events must not run wakers.
    #[cfg(target_os = "macos")]
    pub(crate) fn register_event_quiet(&self, after: Duration) -> Option<Duration> {
        if self.jumps() || after.is_zero() {
            return None;
        }
        self.add_pending(self.peek().saturating_add(nanos(after)), false, true);
        self.real_span(after)
    }

    /// Registers a timed wait of `after` from now as a pending deadline, returning its absolute
    /// monotonic-nanos key (for [`unregister_timer`](Clock::unregister_timer)), as a foreign timer
    /// for a thread that is not a participant; an `event` is one-shot, taken when time reaches it.
    /// `None` on a running as-fast-as-possible clock, where sleeps and timeouts advance time
    /// directly, and for an event already due.
    ///
    /// On a scaled clock this also prunes participant timers real time has already carried the
    /// clock past, setting `fired` so the next time skip reports progress, and wakes their wakers
    /// once the table is let go.
    pub(crate) fn register_timer(
        &self,
        after: Duration,
        foreign: bool,
        event: bool,
    ) -> Option<u64> {
        if self.jumps() || event && after.is_zero() {
            return None;
        }
        let now = self.peek();
        let wake = now.saturating_add(nanos(after));
        if foreign {
            self.add_pending(wake, true, event);
            return Some(wake);
        }
        let pruned = {
            let mut pending = self.timers(false);
            let pruned = if self.is_scaled()
                && !self.is_driven()
                && pending
                    .first_key_value()
                    .is_some_and(|(&first, _)| first <= now)
            {
                self.fired.store(true, Ordering::Release);
                take_upto(&mut pending, now).1
            } else {
                Vec::new()
            };
            let entry = pending.entry(wake).or_default();
            if event {
                entry.events += 1;
            } else {
                entry.waits += 1;
                entry.owners.push(snare_interpose::thread_lineage());
            }
            pruned
        };
        self.wake_taken(pruned);
        Some(wake)
    }

    /// Something stamped `realtime` was taken in: an as-fast-as-possible clock, on which link
    /// delays pass in real time, jumps to the stamp so no read after it is earlier.
    #[cfg(unix)]
    pub(crate) fn reach_realtime(&self, realtime: Duration) {
        if self.jumps() {
            let at = nanos(realtime).saturating_sub(self.realtime_at(0));
            self.jump_to(at);
        }
    }

    /// A timed wait timed out at `deadline` on a running as-fast-as-possible clock: it jumps the
    /// clock there, as a sleep does.
    pub(crate) fn expire(&self, deadline: Duration) {
        if self.jumps() {
            self.jump_to(nanos(deadline));
        }
    }

    /// Advances a running discrete clock by `latency` (see `Layer::charge_latency`), reporting
    /// whether it reached a pending deadline. A driven clock crawls the same way, but never past
    /// the horizon of its grant.
    fn charge(&self, latency: Duration) -> bool {
        if self.is_driven() {
            return self.charge_driven(latency);
        }
        let running_discrete = || self.is_discrete() && !self.is_paused() && !self.is_scaled();
        if !running_discrete() {
            return false;
        }
        let (reached, wakers) = {
            let Some(_control) = self.try_control() else {
                return false;
            };
            if !running_discrete() {
                return false;
            }
            let (before, after) = self.step_base(nanos(latency));
            let reached = self.reached(before, after);
            (reached, self.fire_upto(before, after).1)
        };
        self.wake_taken(wakers);
        reached
    }

    /// One step of a participant's clock spin (see `Layer::spin_step`): moves a running discrete
    /// clock `step` on (at least 1 ns), but never past a participant timer in one step. A step that
    /// would reach the earliest timer ahead lands 1 ns short of it first, so a spinner whose own
    /// deadline comes no later sees it before the timer's waiter runs; the next step lands just
    /// past it, as a time skip does, and fires it. Timers of any thread that the step passes fire
    /// as a charge fires them.
    ///
    /// Outside a deterministic schedule, a participant wait the clock has reached but whose waiter
    /// has not yet taken it holds the spin ([`SpinStep::Waking`]) until the waiter runs or
    /// [`SPIN_SETTLE`] of real time passes: a timed native wait notices its deadline only between
    /// real-time slices, and moving on before it does would run time ahead of its work. A
    /// deterministic schedule runs the woken threads itself before the spinner's next step.
    ///
    /// A paused clock, or one an executive drives, is [`SpinStep::Held`]: spinning never moves
    /// it. A scaled or as-fast-as-possible clock moves on its own ([`SpinStep::Runs`]).
    fn spin_step(&self, step: Duration) -> SpinStep {
        let held = || self.is_paused() || self.is_driven();
        let runs = || !self.is_discrete() || self.is_scaled();
        if held() {
            return SpinStep::Held;
        }
        if runs() {
            return SpinStep::Runs;
        }
        let spin = || {
            let _control = self.control();
            if held() {
                return (SpinStep::Held, Vec::new());
            }
            if runs() {
                return (SpinStep::Runs, Vec::new());
            }
            let now = self.peek();
            if !self.is_deterministic() && self.due().is_some() {
                let real = real_nanos().max(1);
                let since = match self.spin_due_since.compare_exchange(
                    0,
                    real,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => real,
                    Err(since) => since,
                };
                if real.saturating_sub(since) < nanos(SPIN_SETTLE) {
                    return (SpinStep::Waking, Vec::new());
                }
            }
            self.spin_due_since.store(0, Ordering::Release);
            let target = now.saturating_add(nanos(step).max(1));
            let landing = match self.next_deadline_after(now) {
                Some(at) if target >= at && now < at - 1 => at - 1,
                Some(at) if target >= at => creep_past(at),
                _ => target,
            };
            let (before, after) = self.step_base(landing - now);
            let fired = self.reached(before, after);
            (SpinStep::Moved { fired }, self.fire_upto(before, after).1)
        };
        #[cfg(windows)]
        let owner = (!self.is_deterministic() && !self.is_dormant())
            .then(|| {
                self.owner
                    .lock()
                    .unwrap()
                    .as_ref()
                    .and_then(|owner| owner.upgrade())
            })
            .flatten();
        #[cfg(windows)]
        let (step, wakers) = if let Some(owner) = owner {
            crate::readiness::readiness()
                .spin_clock(&owner, spin)
                .unwrap_or((SpinStep::Waking, Vec::new()))
        } else {
            spin()
        };
        #[cfg(not(windows))]
        let (step, wakers) = spin();
        self.wake_taken(wakers);
        step
    }

    /// [`charge`](Self::charge) on a driven clock: moves `floor` (not the line) up to `latency` on,
    /// clamped to the grant's horizon, so the crawl never outruns what the executive allowed.
    fn charge_driven(&self, latency: Duration) -> bool {
        let fired = {
            let Some(_control) = self.try_control() else {
                return false;
            };
            if !self.is_driven() {
                return false;
            }
            let before = self.peek();
            let horizon = self.horizon.load(Ordering::Acquire);
            let after = before.saturating_add(nanos(latency)).min(horizon);
            if after <= before {
                return false;
            }
            self.floor.fetch_max(after, Ordering::AcqRel);
            let reached = self.reached(before, after);
            let (_, wakers) = self.fire_upto(before, after);
            (reached, wakers)
        };
        self.wake_taken(fired.1);
        fired.0
    }

    /// Whether any timer, foreign or not, falls in `(before, after]`.
    fn reached(&self, before: u64, after: u64) -> bool {
        [false, true].into_iter().any(|foreign| {
            self.timers(foreign)
                .range(before.saturating_add(1)..=after)
                .next()
                .is_some()
        })
    }

    /// Delivers what is due by `t`: drops its one-shot events and takes its wakers, which the
    /// caller wakes once it has let go of its locks, and counts what the participants' table held
    /// in `(from, t]` (waits, events and wakers). Waits stay registered until their waiters take
    /// them.
    pub(crate) fn fire_upto(&self, from: u64, t: u64) -> (u32, Vec<Waker>) {
        let mut count = 0u32;
        let mut wakers = Vec::new();
        for foreign in [false, true] {
            let mut timers = self.timers(foreign);
            let due: Vec<u64> = timers.range(..=t).map(|(&at, _)| at).collect();
            for at in due {
                let Some(entry) = timers.get_mut(&at) else {
                    continue;
                };
                if !foreign && at > from {
                    count = count.saturating_add(entry.count());
                }
                entry.events = 0;
                let hold = !foreign && !self.is_deterministic();
                let taken = timers.take_wakers_at(at, hold, &mut wakers);
                if hold && taken {
                    self.held.store(true, Ordering::Release);
                }
                if timers.get(&at).unwrap().is_empty() {
                    timers.remove(&at);
                }
            }
        }
        if !wakers.is_empty() {
            self.woke_timers.store(true, Ordering::Release);
        }
        (count, wakers)
    }

    /// Drops one reference to a pending deadline from [`register_timer`](Clock::register_timer),
    /// looking first among the foreign timers if `foreign`, then in the other table, since a
    /// thread may have changed class between registering and dropping. Removes the caller's own
    /// lineage from the owners when it is there, else any one.
    pub(crate) fn unregister_timer(&self, wake: u64, foreign: bool) {
        let me = snare_interpose::thread_lineage();
        for foreign in [foreign, !foreign] {
            let mut timers = self.timers(foreign);
            let Some(entry) = timers.get_mut(&wake).filter(|e| e.waits > 0) else {
                continue;
            };
            entry.waits -= 1;
            let owner = entry.owners.iter().position(|&o| o == me);
            match owner {
                Some(i) => {
                    entry.owners.swap_remove(i);
                }
                None => {
                    entry.owners.pop();
                }
            }
            if entry.is_empty() {
                timers.remove(&wake);
            }
            break;
        }
        self.release_held();
    }

    /// Once no reached wait is left untaken, wakes the waiters a time skip held off for one (see
    /// `held`), so they re-check quiescence and skip now rather than at their next poll; and, with
    /// wakers pending that a skip could land on, runs an idle skip for participants all blocked in
    /// native waits, which run no skip of their own. Called with no timer table held.
    fn release_held(&self) {
        if !self.held.load(Ordering::Acquire) {
            return;
        }
        let now = self.peek();
        if [false, true]
            .into_iter()
            .any(|foreign| reached_wait(&self.timers(foreign), now))
        {
            return;
        }
        if !self.held.swap(false, Ordering::AcqRel) {
            return;
        }
        crate::readiness::readiness().bump_time_unscheduled(self.domain());
        let owner = self.owner.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if self.holds_wakers()
            && let Some(domain) = owner.and_then(|owner| owner.upgrade())
        {
            crate::readiness::skip_idle_later(&domain);
        }
    }

    /// Drops one event from [`register_timer`](Clock::register_timer) at `wake` that has not
    /// happened yet.
    pub(crate) fn unregister_event(&self, wake: u64) {
        let mut timers = self.timers(false);
        let Some(entry) = timers.get_mut(&wake).filter(|e| e.events > 0) else {
            return;
        };
        entry.events -= 1;
        if entry.is_empty() {
            timers.remove(&wake);
        }
    }

    /// Wakes `waker` once the clock reaches `at` (monotonic nanos), as a foreign timer for a thread
    /// that is not a participant. On a scaled clock the real-time waker also wakes it when real
    /// time carries the clock there. `None` on a running as-fast-as-possible clock, which moves
    /// only when read or slept on.
    pub(crate) fn register_wake(&self, at: u64, waker: Waker, foreign: bool) -> Option<u64> {
        if self.jumps() {
            return None;
        }
        let id = wake_id();
        let owner = snare_interpose::Domain::current().map(|_| snare_interpose::thread_lineage());
        let real_at = (self.is_scaled() && !self.is_driven() && !self.is_paused())
            .then(|| self.line().0.real_at(at))
            .flatten();
        if let Some(real_at) = real_at {
            crate::readiness::schedule_wake(Duration::from_nanos(real_at), id, waker.clone());
        }
        self.timers(foreign).register_wake(at, id, owner, waker);
        Some(id)
    }

    /// Cancels a registration from [`register_wake`](Clock::register_wake), releasing its
    /// deadline if the wake has already been delivered.
    pub(crate) fn cancel_wake(&self, id: u64) {
        crate::readiness::cancel_wake(id);
        for foreign in [false, true] {
            let cancelled = {
                let mut timers = self.timers(foreign);
                timers.cancel_wake(id)
            };
            if let Some(cancelled) = cancelled {
                drop(cancelled);
                self.release_held();
                return;
            }
        }
    }

    /// Takes the wakers due by `t`, foreign or not, leaving waits and events registered.
    fn take_wakers(&self, t: u64) -> Vec<Waker> {
        let mut wakers = Vec::new();
        for foreign in [false, true] {
            let mut timers = self.timers(foreign);
            let due: Vec<u64> = timers
                .range(..=t)
                .filter(|(_, entry)| !entry.wakers.is_empty())
                .map(|(&at, _)| at)
                .collect();
            for at in due {
                let hold = !foreign && !self.is_deterministic();
                let taken = timers.take_wakers_at(at, hold, &mut wakers);
                if hold && taken {
                    self.held.store(true, Ordering::Release);
                }
                if timers.get(&at).unwrap().is_empty() {
                    timers.remove(&at);
                }
            }
        }
        wakers
    }

    /// Wakes `wakers` the clock took, noting it for the domain.
    fn wake_taken(&self, wakers: Vec<Waker>) {
        if wakers.is_empty() {
            return;
        }
        self.woke_timers.store(true, Ordering::Release);
        wake_all(&self.runner, wakers);
    }

    /// Whether any waker from [`register_wake`](Clock::register_wake) is pending.
    fn holds_wakers(&self) -> bool {
        [false, true].into_iter().any(|foreign| {
            self.timers(foreign)
                .values()
                .any(|entry| !entry.wakers.is_empty())
        })
    }

    /// Whether a running discrete clock outside a deterministic sim has reached a participant's
    /// wait that its waiter has yet to take (see `Layer::wait_due`). Only such a clock time-skips
    /// past waiters on its own; a deterministic schedule runs the threads a skip released before
    /// it skips again.
    fn wait_due(&self) -> bool {
        if !self.is_discrete()
            || self.is_scaled()
            || self.is_paused()
            || self.is_driven()
            || self.is_deterministic()
        {
            return false;
        }
        let due = reached_wait(&self.timers(false), self.peek());
        if due {
            self.held.store(true, Ordering::Release);
        }
        due
    }

    /// Whether a wait of any thread at or before the reading is still registered: one its waiter
    /// has yet to take, which only a wake of the waiters lets it see.
    pub(crate) fn wait_reached(&self) -> bool {
        let now = self.peek();
        [false, true]
            .into_iter()
            .any(|foreign| reached_wait(&self.timers(foreign), now))
    }

    /// Wakes the wakers the clock has reached, after a writer moved it.
    pub(crate) fn wake_due(&self) {
        let wakers = self.take_wakers(self.peek());
        self.wake_taken(wakers);
    }

    /// The monotonic reading the code under test gets, without ticking: at an open timestamp's
    /// time while one is open.
    pub(crate) fn monotonic(&self) -> u64 {
        self.peek().max(self.stamp.load(Ordering::Acquire))
    }

    /// Panics unless `rate` is one [`set_rate`](Clock::set_rate) accepts.
    #[track_caller]
    pub(crate) fn check_rate(&self, rate: f64) {
        validate_rate(rate, self.deterministic.load(Ordering::Relaxed));
    }

    /// Runs the clock at `rate` virtual seconds per real second (clamped to 1e6), pauses it at
    /// 0.0, or returns it to its base mode at infinity. Keeps the current reading.
    pub(crate) fn set_rate(&self, rate: f64) {
        self.controlled(|| {
            if self.is_driven() {
                return;
            }
            if rate == 0.0 {
                if !self.is_paused() {
                    self.publish(self.rate_q32.load(Ordering::Relaxed), true, |now| now);
                }
                return;
            }
            let (q32, scaled) = if rate.is_finite() {
                let rate = rate.min(MAX_RATE);
                (rate_to_q32(rate), rate)
            } else {
                (0, 0.0)
            };
            self.publish(q32, false, |now| now);
            self.scaled_rate.store(scaled.to_bits(), Ordering::Release);
        });
    }

    /// 0.0 while paused, the rate while scaled, infinity in a base mode; while driven, the
    /// current grant's rate.
    pub(crate) fn rate(&self) -> f64 {
        if self.is_driven() {
            return f64::from_bits(self.scaled_rate.load(Ordering::Acquire));
        }
        if self.is_paused() {
            return 0.0;
        }
        let rate = f64::from_bits(self.scaled_rate.load(Ordering::Acquire));
        if rate == 0.0 { f64::INFINITY } else { rate }
    }

    /// Holds the clock: reads return the current time, and sleepers and timed waits block until
    /// it is moved or resumed.
    pub(crate) fn pause(&self) {
        self.set_rate(0.0);
    }

    /// Restarts a paused clock in the mode and at the rate it had before the pause.
    pub(crate) fn resume(&self) {
        self.controlled(|| {
            if !self.is_paused() || self.is_driven() {
                return;
            }
            self.publish(self.rate_q32.load(Ordering::Relaxed), false, |now| now);
        });
    }

    /// Moves the clock forward by `d`, whether or not it is paused.
    pub(crate) fn advance_by(&self, d: Duration) {
        if d.is_zero() {
            return;
        }
        self.controlled(|| {
            if self.is_driven() {
                return;
            }
            let paused = self.is_paused();
            self.publish(self.rate_q32.load(Ordering::Relaxed), paused, |now| {
                now.saturating_add(nanos(d))
            });
        });
    }

    /// Sets sim time to `value`. Forward only: `Err` with the current sim time if `value` lies
    /// before it.
    pub(crate) fn set_value(&self, value: Duration) -> Result<(), Duration> {
        let origin = self.origin();
        let value = origin.saturating_add(nanos(value));
        self.controlled(|| {
            let now = self.peek();
            if self.is_driven() {
                return Ok(());
            }
            if value < now {
                return Err(self.sim_time(now));
            }
            if value > now {
                let paused = self.is_paused();
                self.publish(self.rate_q32.load(Ordering::Relaxed), paused, |now| {
                    now.max(value)
                });
            }
            Ok(())
        })
    }

    /// Sim time: how far the monotonic reading, without ticking, is past the
    /// [`origin`](Self::origin), at an open timestamp's time while one is open, as the code under
    /// test reads it.
    pub(crate) fn value(&self) -> Duration {
        let stamp = self.stamp.load(Ordering::Acquire);
        self.sim_time(self.peek().max(stamp))
    }

    /// Monotonic reading `monotonic` as sim time.
    pub(crate) fn sim_time(&self, monotonic: u64) -> Duration {
        Duration::from_nanos(monotonic.saturating_sub(self.origin()))
    }

    /// Sim time `t` as a monotonic reading.
    pub(crate) fn at_sim_time(&self, t: Duration) -> u64 {
        self.origin().saturating_add(nanos(t))
    }

    /// The driver time for monotonic reading `t` under the current executive.
    pub(crate) fn driver_time_at(&self, t: u64) -> DriverTime {
        (t, self.driver_gen.load(Ordering::Acquire))
    }

    /// The calling thread's driver time, unless the executive it was set under has let go.
    pub(crate) fn driver_time(&self) -> Option<u64> {
        let (t, generation) = DRIVER_TIME.try_with(Cell::get).ok()??;
        (generation == self.driver_gen.load(Ordering::Acquire)).then_some(t)
    }

    /// Hands the clock to an executive: it holds at the current reading until the first grant.
    pub(crate) fn attach_driven(&self) {
        self.controlled(|| {
            let now = self.peek();
            self.publish_line(now, real_nanos(), 0, now);
            self.scaled_rate.store(0f64.to_bits(), Ordering::Release);
            self.driven.store(true, Ordering::Release);
            self.paused.store(false, Ordering::Release);
        });
    }

    /// Takes the clock back from an executive: it returns to its base mode at its current reading,
    /// or at an open timestamp's time if that is later.
    pub(crate) fn detach_driven(&self) {
        self.controlled(|| {
            if !self.is_driven() {
                return;
            }
            let now = self.peek().max(self.stamp.load(Ordering::Acquire));
            self.publish_line(now, real_nanos(), 0, u64::MAX);
            self.floor.fetch_max(now, Ordering::AcqRel);
            self.stamp.store(0, Ordering::Release);
            self.driver_gen.fetch_add(1, Ordering::AcqRel);
            self.driven.store(false, Ordering::Release);
            self.scaled_rate.store(0f64.to_bits(), Ordering::Release);
        });
    }

    /// Runs a driven clock along a new line through `(anchor_v, anchor_real)` at `rate` up to
    /// `horizon`. An anchor behind the current reading moves to the reading, now, so time never
    /// goes back.
    pub(crate) fn grant(&self, anchor_v: u64, anchor_real: u64, rate: f64, horizon: u64) {
        self.controlled(|| {
            if !self.is_driven() {
                return;
            }
            let now = self.peek();
            let (anchor_v, anchor_real) = if anchor_v >= now {
                (anchor_v, anchor_real)
            } else {
                (now, real_nanos())
            };
            self.publish_line(
                anchor_v,
                anchor_real,
                rate_to_q32(rate),
                horizon.max(anchor_v),
            );
            self.scaled_rate.store(rate.to_bits(), Ordering::Release);
        });
    }

    /// Holds a driven clock where it is: horizon at the reading, rate 0.
    pub(crate) fn freeze(&self) {
        self.controlled(|| {
            if !self.is_driven() {
                return;
            }
            let now = self.peek();
            self.publish_line(now, real_nanos(), 0, now);
            self.scaled_rate.store(0f64.to_bits(), Ordering::Release);
        });
    }

    /// Moves a driven clock forward to `t`, or with `to_next` to the earliest participant timer
    /// after the reading if that comes first, raising the horizon to reach it and keeping the
    /// grant's rate. Returns the reading before and after.
    ///
    /// With `past`, the horizon reaches [`creep_past`] the landing. A landing stops the clock exactly
    /// on a deadline, where a wait that recomputes `deadline - now` (flume's `recv_timeout`,
    /// std's `Condvar::wait_timeout_while`) comes back with a zero timeout; the latency charged to
    /// that call is what carries the clock past it, and only inside the horizon. Without the
    /// creep such a thread spins at its deadline as a running participant, and time never
    /// moves again.
    pub(crate) fn jump_driven(&self, t: u64, to_next: bool, past: bool) -> (u64, u64) {
        self.controlled(|| {
            let now = self.peek();
            if !self.is_driven() {
                return (now, now);
            }
            let landing = match self.next_deadline_after(now).filter(|_| to_next) {
                Some(next) => next.min(t),
                None => t,
            };
            let to = now.max(landing);
            let reach = if past { creep_past(to) } else { to };
            let horizon = self.horizon.load(Ordering::Acquire).max(reach);
            self.publish_line(
                to,
                real_nanos(),
                self.rate_q32.load(Ordering::Acquire),
                horizon,
            );
            (now, to)
        })
    }

    /// Opens (`Some`) or closes a timestamp at monotonic time `t`: while open, the code under test
    /// reads at least `t`.
    pub(crate) fn set_stamp(&self, t: Option<u64>) {
        self.stamp.store(t.unwrap_or(0), Ordering::Release);
    }

    /// The earliest participant timer after `now`.
    pub(crate) fn next_deadline_after(&self, now: u64) -> Option<u64> {
        self.timers(false)
            .range(now.saturating_add(1)..)
            .next()
            .map(|(&at, _)| at)
    }

    /// The earliest timer of any thread after `now`.
    fn next_any_after(&self, now: u64) -> Option<u64> {
        [false, true]
            .into_iter()
            .filter_map(|foreign| {
                self.timers(foreign)
                    .range(now.saturating_add(1)..)
                    .next()
                    .map(|(&at, _)| at)
            })
            .min()
    }

    /// The owner of a participant timer that is due and not yet taken: `Some(None)` for an event
    /// or a waker.
    pub(crate) fn due(&self) -> Option<Option<u64>> {
        let now = self.peek();
        self.timers(false)
            .range(..=now)
            .next()
            .map(|(_, entry)| entry.owners.first().copied())
    }

    /// The first owner of the participant timer at `at`: `None` for an event or a waker.
    pub(crate) fn owner_at(&self, at: u64) -> Option<u64> {
        self.timers(false)
            .get(&at)
            .and_then(|entry| entry.owners.first().copied())
    }

    /// The calling thread's driver time as sim time, while it has one.
    pub(crate) fn driver_value(&self) -> Option<Duration> {
        self.driver_time().map(|t| self.sim_time(t))
    }

    /// The first `n` pending timers: the participants' in time order, then the other threads' in
    /// time order.
    pub(crate) fn pending_timers(&self, n: usize) -> Vec<PendingTimer> {
        let mut out = Vec::new();
        for foreign in [false, true] {
            for (&at, entry) in self.timers(foreign).iter() {
                let owners = entry.owners.iter().map(|&o| Some(o));
                let anonymous = (entry.owners.len()..(entry.waits as usize))
                    .chain(0..entry.events as usize)
                    .map(|_| None);
                let wakers = entry.wakers.iter().map(|(_, owner, _)| *owner);
                out.extend(
                    owners
                        .chain(anonymous)
                        .chain(wakers)
                        .map(|owner| PendingTimer { at, owner }),
                );
                if out.len() >= n {
                    out.truncate(n);
                    return out;
                }
            }
        }
        out
    }

    /// When, in real time since the process origin, a driven clock running at a rate above zero
    /// next reaches a pending timer of any thread. `None` when it never does on its own (rate 0,
    /// nothing pending, or the timer is past the grant's horizon).
    pub(crate) fn next_flow_wake(&self) -> Option<u64> {
        if !self.is_driven() {
            return None;
        }
        let (line, ..) = self.line();
        if line.rate_q32 == 0 {
            return None;
        }
        let next = self.next_any_after(self.peek())?;
        line.real_at(next)
    }

    /// The quiescence time-skip: jump to the earliest pending sleep/timeout deadline still in the
    /// future. `true` if time moved (a blocked sleeper can now wake), `false` if nothing is pending
    /// or the clock does not skip (paused, driven or as-fast-as-possible). A scaled clock moves on
    /// its own, so instead it fires the timers real time has already carried it past: their
    /// waiters may not have woken yet, and until they do the sim only looks stuck.
    fn advance_to_next_deadline(&self) -> bool {
        let (moved, pruned) = self.collect_skip(false, || {
            let _control = self.control();
            if self.is_paused() || self.is_driven() {
                return (false, Vec::new());
            }
            if self.is_scaled() {
                let now = self.peek();
                let mut pending = self.timers(false);
                let (any, pruned) = take_upto(&mut pending, now);
                let fired = self.fired.swap(false, Ordering::AcqRel) || any;
                (fired, pruned)
            } else if !self.is_discrete() && !self.is_dormant() {
                (false, Vec::new())
            } else {
                self.skip_to_next_deadline()
            }
        });
        self.wake_taken(pruned);
        moved
    }

    /// The discrete half of [`advance_to_next_deadline`](Self::advance_to_next_deadline), run
    /// under `control`: prunes reached deadlines and jumps just past the earliest pending one,
    /// returning whether time moved and the wakers to run once `control` is released.
    ///
    /// Outside a deterministic sim it refuses while a participant's wait it has reached is still
    /// registered (see [`wait_due`](Self::wait_due)), so two deadlines at one instant both wake
    /// there: a skip on to the next would leave the slower waiter to notice its own deadline late.
    fn skip_to_next_deadline(&self) -> (bool, Vec<Waker>) {
        let now = self.peek();
        let mut pending = self.timers(false);
        if !self.is_deterministic() && reached_wait(&pending, now) {
            self.held.store(true, Ordering::Release);
            return (false, Vec::new());
        }
        // Drop deadlines already reached (their waits have woken), then jump to the earliest
        // still in the future so the thread waiting on it can run.
        let pruned = take_upto(&mut pending, now).1;
        let Some((&next, _)) = pending.iter().next() else {
            return (false, pruned);
        };
        if self.dormant_limit().is_some_and(|limit| next >= limit) {
            return (false, pruned);
        }
        // Land just past the deadline as the code under test reads the clock, as a real timer
        // fires: discrete time never ticks on its own, so landing exactly on it would leave
        // `elapsed == timeout` and a caller's "re-wait while elapsed < timeout" loop (std's
        // `Condvar::wait_timeout_while`) re-waiting with a zero timeout forever.
        let landing = creep_past(next);
        self.monotonic_nanos.fetch_max(landing, Ordering::Relaxed);
        drop(pending);
        let mut pruned = pruned;
        pruned.extend(self.take_wakers(landing));
        (true, pruned)
    }

    /// Jumps a running discrete clock just past its earliest pending deadline, foreign or not (see
    /// `Layer::try_foreign_time_skip`). `false` if none is pending, the clock does not skip, or,
    /// outside a deterministic sim, a wait of any thread it has reached is still registered.
    fn advance_to_next_any_deadline(&self) -> bool {
        let (moved, pruned) = self.collect_skip(true, || {
            let mut pruned = Vec::new();
            let _control = self.control();
            if self.is_paused()
                || self.is_scaled()
                || (!self.is_discrete() && !self.is_dormant())
                || self.is_driven()
            {
                return (false, pruned);
            }
            let now = self.peek();
            if !self.is_deterministic()
                && [false, true]
                    .into_iter()
                    .any(|foreign| reached_wait(&self.timers(foreign), now))
            {
                self.held.store(true, Ordering::Release);
                return (false, pruned);
            }
            let next = [false, true]
                .into_iter()
                .filter_map(|foreign| {
                    let mut timers = self.timers(foreign);
                    pruned.extend(take_upto(&mut timers, now).1);
                    timers.first_key_value().map(|(&wake, _)| wake)
                })
                .min()
                .filter(|&next| self.dormant_limit().is_none_or(|limit| next < limit));
            if let Some(next) = next {
                let landing = creep_past(next);
                self.monotonic_nanos.fetch_max(landing, Ordering::Relaxed);
                pruned.extend(self.take_wakers(landing));
            }
            (next.is_some(), pruned)
        });
        self.wake_taken(pruned);
        moved
    }

    fn collect_skip(
        &self,
        _foreign: bool,
        skip: impl FnOnce() -> (bool, Vec<Waker>),
    ) -> (bool, Vec<Waker>) {
        #[cfg(windows)]
        if !self.is_deterministic() && !self.is_dormant() {
            let owner = self
                .owner
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|owner| owner.upgrade());
            if let Some(owner) = owner {
                return crate::readiness::readiness()
                    .skip_clock(&owner, _foreign, skip)
                    .unwrap_or_default();
            }
        }
        let result = skip();
        #[cfg(windows)]
        if result.0 && !self.is_deterministic() {
            crate::readiness::readiness().bump_time_unscheduled(self.domain());
        }
        result
    }

    /// The reading timed waits measure their deadlines on, without ticking; `None` on a running
    /// as-fast-as-possible clock, whose waits run on real time and jump the clock as they expire.
    pub(crate) fn virtual_now(&self) -> Option<Duration> {
        (!self.jumps()).then(|| Duration::from_nanos(self.peek()))
    }

    /// How much real time `span` of virtual time takes at the line's current rate; `None` when the
    /// clock does not run on its own (paused, frozen by an executive, or in either base mode).
    fn real_span(&self, span: Duration) -> Option<Duration> {
        if self.is_paused() && !self.is_driven() {
            return None;
        }
        let rate_q32 = self.rate_q32.load(Ordering::Acquire);
        if rate_q32 == 0 {
            return None;
        }
        let from_zero = Line {
            anchor_v: 0,
            anchor_real: 0,
            rate_q32,
            horizon: u64::MAX,
        };
        from_zero.real_at(nanos(span)).map(Duration::from_nanos)
    }

    /// How long a quiescent wait should sleep in real time before time will have moved on its own:
    /// [`HELD_POLL`] on a paused or driven clock (only a writer moves it, and its kick wakes the
    /// waiter sooner), the real span to the next participant timer on a scaled clock (at least
    /// 1 µs, a snare floor so a span of a few nanoseconds never busy-spins), and `None` when time
    /// moves only by a time skip or a scaled clock has no participant timer ahead, so quiescence
    /// there is a deadlock. While dormant and not scaled, the real time until a time skip may
    /// reach the next timer of any thread (see [`set_dormant`](Self::set_dormant)), or
    /// [`HELD_POLL`] with none: a thread left over from a run blocks rather than giving up.
    fn idle_wait(&self) -> Option<Duration> {
        if self.is_paused() || self.is_driven() {
            return Some(HELD_POLL);
        }
        if let Some(limit) = self.dormant_limit().filter(|_| !self.is_scaled()) {
            let now = self.peek();
            let earliest = [false, true]
                .into_iter()
                .filter_map(|foreign| {
                    let timers = self.timers(foreign);
                    timers
                        .range(now.saturating_add(1)..)
                        .next()
                        .map(|(&at, _)| at)
                })
                .min();
            let Some(earliest) = earliest else {
                return Some(HELD_POLL);
            };
            let span = earliest.saturating_add(1).saturating_sub(limit);
            return Some(Duration::from_nanos(span).max(Duration::from_micros(1)));
        }
        if !self.is_scaled() {
            return None;
        }
        let now = self.peek();
        let earliest = *self.timers(false).range(now.saturating_add(1)..).next()?.0;
        let span = self.real_span(Duration::from_nanos(earliest - now))?;
        Some(span.max(Duration::from_micros(1)))
    }
}

/// Whether a wait at or before `now` is still registered: the clock reached it and its waiter has
/// yet to take it.
fn reached_wait(timers: &Timers, now: u64) -> bool {
    timers
        .range(..=now)
        .any(|(_, entry)| entry.waits > 0 || !entry.awaiting.is_empty())
}

/// Removes every entry at or before `upto`, returning whether there was one and their wakers.
fn take_upto(timers: &mut Timers, upto: u64) -> (bool, Vec<Waker>) {
    let later = timers.entries.split_off(&upto.saturating_add(1));
    let due = std::mem::replace(&mut timers.entries, later);
    let any = !due.is_empty();
    let wakers = due
        .into_values()
        .flat_map(|entry| {
            for id in entry
                .awaiting
                .iter()
                .chain(entry.wakers.iter().map(|(id, _, _)| id))
            {
                timers.wake_deadlines.remove(id);
            }
            entry.wakers.into_iter().map(|(_, _, waker)| waker)
        })
        .collect();
    (any, wakers)
}

/// Wakes `wakers` from the sim's own code on `runner`, with neither a timer table nor `control`
/// held, and returns once they have run. The caller wakes the sim's waiters afterwards; see
/// [`in_clock_wake`].
///
/// They run on a thread of their own, outside the sim: the thread moving the clock may be the
/// one a waker wakes, midway into its own blocking call, and a channel or a parker does not wake
/// the thread that signals it.
fn wake_all(runner: &RaceCell<Arc<WakeRunner>>, wakers: Vec<Waker>) {
    if wakers.is_empty() {
        return;
    }
    if in_clock_wake() {
        wakers.into_iter().for_each(Waker::wake);
        return;
    }
    snare_interpose::real(|| WakeRunner::started(runner).run(wakers));
}

/// The thread a [`Clock`] runs its wakers on (see [`wake_all`]), started unmanaged on first use
/// and stopped when the clock is dropped.
///
/// One per clock rather than one per process: a poster blocks until its wakers have run, maybe
/// holding a lock of the sim's (a time skip runs under the process-wide readiness lock), and a
/// waker is the code under test's and may block on a lock of its own. Shared, a waker of one sim
/// blocked on a lock whose holder waits for that readiness lock would hold up a time skip of
/// another sim that holds it, and neither would ever move.
struct WakeRunner {
    state: Mutex<RunnerState>,
    changed: std::sync::Condvar,
}

/// One job at a time, handed over through `WakeRunner::changed`.
#[derive(Default)]
struct RunnerState {
    /// The wakers posted and not yet taken by the runner; a poster waits for it to be free.
    job: Option<Vec<Waker>>,
    /// Jobs posted so far: a poster's ticket.
    posted: u64,
    /// Jobs the runner has finished; a poster returns once this reaches its ticket.
    done: u64,
    /// The clock is gone: the runner thread exits once no job is left.
    closed: bool,
}

impl WakeRunner {
    /// The runner in `cell`, spawning its thread the first time it is asked for. Callers are under
    /// passthrough ([`wake_all`] runs it in `snare_interpose::real`), so the sim never adopts the
    /// thread.
    ///
    /// A [`RaceCell`], not a `OnceLock`: the first caller is often a participant moving the clock
    /// from inside its own hooked wait (a time skip in the deterministic schedule's dispatch, an
    /// idle skip as it enters a native wait), already parked on std's thread parker, and a second
    /// caller waiting there for another thread's initialisation would park it again (see
    /// `RaceCell`).
    fn started(cell: &RaceCell<Arc<WakeRunner>>) -> &Arc<WakeRunner> {
        let (runner, won) = cell.get_or_init(|| {
            Arc::new(WakeRunner {
                state: Mutex::default(),
                changed: std::sync::Condvar::new(),
            })
        });
        if won {
            let serving = runner.clone();
            std::thread::Builder::new()
                .name("snare-timer-wakes".into())
                .spawn(move || {
                    let _service = snare_interpose::service_thread();
                    serving.serve();
                })
                .expect("start the timer waker thread");
        }
        runner
    }

    /// Locks the runner's state, ignoring poison.
    fn lock(&self) -> MutexGuard<'_, RunnerState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Posts `wakers` as the next job and blocks until the runner has woken them all.
    fn run(&self, wakers: Vec<Waker>) {
        let mut state = self.lock();
        while state.job.is_some() {
            state = self.changed.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        state.job = Some(wakers);
        state.posted += 1;
        let ticket = state.posted;
        self.changed.notify_all();
        while state.done < ticket {
            state = self.changed.wait(state).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Lets the runner thread exit once it has finished any job posted.
    fn close(&self) {
        self.lock().closed = true;
        self.changed.notify_all();
    }

    /// The runner thread's loop: takes each job, wakes it with the state unlocked and
    /// [`in_clock_wake`] set, and counts it done even if a waker panics, so its poster never hangs.
    fn serve(&self) {
        CLOCK_WAKE.set(true);
        let mut state = self.lock();
        loop {
            let Some(wakers) = state.job.take() else {
                if state.closed {
                    return;
                }
                state = self.changed.wait(state).unwrap_or_else(|e| e.into_inner());
                continue;
            };
            drop(state);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                wakers.into_iter().for_each(Waker::wake);
            }));
            state = self.lock();
            state.done += 1;
            self.changed.notify_all();
            drop(outcome);
        }
    }
}

/// The [`Layer`] that puts a sim's threads on its [`Clock`]. A driver thread passes through to the
/// real clock, except while it acts at an executive's timestamp
/// ([`with_driver_time`](crate::sched::with_driver_time)), when it reads exactly that time.
pub(crate) struct ClockLayer(pub(crate) Arc<Clock>);

impl Layer for ClockLayer {
    /// A clock read (`clock_gettime`, `mach_absolute_time`, `QueryPerformanceCounter` and the
    /// like, as `snare_interpose` maps them to a [`ClockKind`]).
    fn now(&self, clock: ClockKind) -> Flow<Duration> {
        if let Some(t) = self.0.driver_time() {
            return Flow::Done(self.0.reading(clock, t));
        }
        if driver_caller() {
            return Flow::Pass;
        }
        Flow::Done(self.0.now(clock))
    }

    fn sleep(&self, request: SleepRequest) -> Flow<()> {
        if driver_caller() {
            return Flow::Pass;
        }
        self.0.sleep(request);
        Flow::Done(())
    }

    fn try_time_skip(&self) -> bool {
        self.0.advance_to_next_deadline()
    }

    fn try_foreign_time_skip(&self) -> bool {
        self.0.advance_to_next_any_deadline()
    }

    fn register_timer(&self, after: Duration) -> Option<u64> {
        self.0.register_timer(after, foreign_caller(), false)
    }

    fn register_event_timer(&self, after: Duration) -> Option<u64> {
        self.0.register_timer(after, false, true)
    }

    fn unregister_timer(&self, key: u64) {
        self.0.unregister_timer(key, foreign_caller());
    }

    fn unregister_event_timer(&self, key: u64) {
        self.0.unregister_event(key);
    }

    fn supports_timer_wakes(&self) -> bool {
        true
    }

    fn register_wake(&self, at: Duration, waker: Waker) -> Option<u64> {
        let foreign = foreign_caller();
        let key = self.0.register_wake(nanos(at), waker, foreign)?;
        // Participants already blocked for good run no skip of their own to land on it.
        if foreign && let Some(domain) = snare_interpose::Domain::current() {
            crate::readiness::skip_idle_later(&domain);
        }
        Some(key)
    }

    fn register_owned_wake(&self, at: Duration, waker: Waker, foreign: bool) -> Option<u64> {
        self.0.register_wake(nanos(at), waker, foreign)
    }

    fn take_timer_wakes(&self) -> bool {
        self.0.woke_timers.swap(false, Ordering::AcqRel)
    }

    fn native_quiescence(&self, domain: &snare_interpose::Domain) {
        if self.0.holds_wakers() {
            crate::readiness::skip_idle_later(domain);
        }
    }

    fn cancel_wake(&self, key: u64) {
        self.0.cancel_wake(key);
    }

    fn charge_latency(&self, latency: Duration) -> bool {
        self.0.charge(latency)
    }

    fn spin_step(&self, step: Duration) -> SpinStep {
        if driver_caller() {
            return SpinStep::Runs;
        }
        self.0.spin_step(step)
    }

    fn expire_timer(&self, deadline: Duration) {
        self.0.expire(deadline);
    }

    fn virtual_now(&self) -> Option<Duration> {
        if let Some(t) = self.0.driver_time() {
            return Some(Duration::from_nanos(t));
        }
        self.0.virtual_now()
    }

    fn real_span(&self, span: Duration) -> Option<Duration> {
        self.0.real_span(span)
    }

    fn idle_wait(&self) -> Option<Duration> {
        self.0.idle_wait()
    }

    fn wake_waiters(&self, domain: usize) {
        crate::readiness::readiness().bump_time(domain);
    }

    fn wake_waiters_after_readiness(&self, _domain: usize) {}

    fn wake_unscheduled(&self, domain: usize) {
        crate::readiness::readiness().bump_time_unscheduled(domain);
    }

    fn settling(&self, domain: usize) -> bool {
        crate::readiness::readiness().settling(domain)
    }

    fn dormant(&self, dormant: bool) {
        self.0.set_dormant(dormant);
    }

    fn wait_due(&self) -> bool {
        self.0.wait_due()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Wake;

    struct RecordedWake {
        id: usize,
        fired: Arc<Mutex<Vec<usize>>>,
    }

    impl Wake for RecordedWake {
        fn wake(self: Arc<Self>) {
            self.fired.lock().unwrap().push(self.id);
        }
    }

    #[test]
    fn cancelling_distinct_deadlines_preserves_remaining_wakes() {
        crate::Sim::new().run(|| {
            let clock = Clock::new(0);
            clock.set_discrete(true);
            let fired = Arc::new(Mutex::new(Vec::new()));
            let ids: Vec<_> = (0..256)
                .map(|i| {
                    clock
                        .register_wake(
                            i as u64 + 1,
                            Waker::from(Arc::new(RecordedWake {
                                id: i,
                                fired: fired.clone(),
                            })),
                            i % 3 == 0,
                        )
                        .unwrap()
                })
                .collect();
            for i in (0..256).rev().filter(|i| i % 2 == 0) {
                clock.cancel_wake(ids[i]);
            }
            let (_, wakers) = clock.fire_upto(0, 256);
            wakers.into_iter().for_each(Waker::wake);
            let expected: Vec<_> = [false, true]
                .into_iter()
                .flat_map(|foreign| (0..256).filter(move |i| i % 2 == 1 && (i % 3 == 0) == foreign))
                .collect();
            assert_eq!(*fired.lock().unwrap(), expected);
            for id in ids {
                clock.cancel_wake(id);
            }
            for foreign in [false, true] {
                let timers = clock.timers(foreign);
                assert!(timers.is_empty());
                assert!(timers.wake_deadlines.is_empty());
            }
        });
    }

    #[test]
    fn cancelling_a_tied_wake_preserves_swap_removal_order() {
        crate::Sim::new().run(|| {
            let clock = Clock::new(0);
            clock.set_discrete(true);
            let fired = Arc::new(Mutex::new(Vec::new()));
            let ids: Vec<_> = (0..4)
                .map(|id| {
                    clock
                        .register_wake(
                            10,
                            Waker::from(Arc::new(RecordedWake {
                                id,
                                fired: fired.clone(),
                            })),
                            false,
                        )
                        .unwrap()
                })
                .collect();
            clock.cancel_wake(ids[1]);
            clock.fire_upto(0, 10).1.into_iter().for_each(Waker::wake);
            assert_eq!(*fired.lock().unwrap(), [0, 3, 2]);
            for id in ids {
                clock.cancel_wake(id);
            }
            assert!(clock.timers(false).is_empty());
        });
    }

    #[test]
    fn delivered_native_wakes_hold_the_deadline_until_cancelled() {
        crate::Sim::new().run(|| {
            let clock = Clock::new(0);
            clock.set_discrete(true);
            let first = clock
                .register_wake(10, Waker::noop().clone(), false)
                .unwrap();
            let second = clock
                .register_wake(10, Waker::noop().clone(), false)
                .unwrap();
            let wakers = clock.fire_upto(0, 10).1;
            assert_eq!(wakers.len(), 2);
            assert!(reached_wait(&clock.timers(false), 10));
            clock.cancel_wake(first);
            assert!(reached_wait(&clock.timers(false), 10));
            clock.cancel_wake(second);
            assert!(!reached_wait(&clock.timers(false), 10));
            assert!(clock.timers(false).wake_deadlines.is_empty());
        });
    }

    #[test]
    fn firing_or_pruning_wakes_cleans_unheld_reverse_entries() {
        crate::Sim::new().run(|| {
            for (deterministic, foreign) in [(false, true), (true, false), (true, true)] {
                let clock = Clock::new(0);
                clock.set_discrete(true);
                clock.set_deterministic(deterministic);
                let id = clock
                    .register_wake(10, Waker::noop().clone(), foreign)
                    .unwrap();
                assert_eq!(clock.take_wakers(10).len(), 1);
                assert!(clock.timers(foreign).is_empty());
                assert!(clock.timers(foreign).wake_deadlines.is_empty());
                clock.cancel_wake(id);
            }
            let clock = Clock::new(0);
            clock.set_discrete(true);
            clock
                .register_wake(10, Waker::noop().clone(), false)
                .unwrap();
            clock
                .register_wake(20, Waker::noop().clone(), false)
                .unwrap();
            clock.fire_upto(0, 10);
            let pruned = {
                let mut timers = clock.timers(false);
                let (any, wakers) = take_upto(&mut timers, 20);
                assert!(any);
                assert!(timers.is_empty());
                assert!(timers.wake_deadlines.is_empty());
                wakers
            };
            assert_eq!(pruned.len(), 1);
        });
    }

    struct CancelWakeOnDrop {
        clock: std::sync::Weak<Clock>,
        sibling: u64,
        dropped: Arc<AtomicBool>,
    }

    #[allow(
        clippy::manual_noop_waker,
        reason = "the destructor cancels another timer"
    )]
    impl Wake for CancelWakeOnDrop {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for CancelWakeOnDrop {
        fn drop(&mut self) {
            self.clock.upgrade().unwrap().cancel_wake(self.sibling);
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn cancellation_drops_a_waker_after_unlocking_its_table() {
        crate::Sim::new().run(|| {
            let clock = Arc::new(Clock::new(0));
            clock.set_discrete(true);
            let sibling = clock
                .register_wake(20, Waker::noop().clone(), false)
                .unwrap();
            let dropped = Arc::new(AtomicBool::new(false));
            let id = clock
                .register_wake(
                    10,
                    Waker::from(Arc::new(CancelWakeOnDrop {
                        clock: Arc::downgrade(&clock),
                        sibling,
                        dropped: dropped.clone(),
                    })),
                    false,
                )
                .unwrap();
            clock.cancel_wake(id);
            assert!(dropped.load(Ordering::SeqCst));
            assert!(clock.timers(false).is_empty());
            assert!(clock.timers(false).wake_deadlines.is_empty());
        });
    }

    #[test]
    fn deterministic_spin_steps_do_not_wait_for_native_timer_settling() {
        let clock = Clock::new(0);
        clock.set_discrete(true);
        clock.set_deterministic(true);
        let timer = clock.register_timer(Duration::ZERO, false, false).unwrap();
        assert!(matches!(
            clock.spin_step(Duration::from_nanos(1)),
            SpinStep::Moved { .. }
        ));
        clock.unregister_timer(timer, false);
    }

    #[test]
    fn line_round_trips_through_real_at() {
        let line = Line {
            anchor_v: 1_000,
            anchor_real: 50,
            rate_q32: rate_to_q32(10.0),
            horizon: u64::MAX,
        };
        let r = line.real_at(1_000 + 5_000_000).unwrap();
        assert_eq!(r, 50 + 500_000);
        assert!(line.value_at(r) >= 1_000 + 5_000_000);
        assert!(line.value_at(r - 1) < 1_000 + 5_000_000);
    }

    #[test]
    fn max_rate_does_not_saturate() {
        let line = Line {
            anchor_v: 0,
            anchor_real: 0,
            rate_q32: rate_to_q32(MAX_RATE),
            horizon: u64::MAX,
        };
        assert_eq!(line.value_at(1_000), 1_000_000_000);
        assert_eq!(line.value_at(3_600_000_000_000), 3_600_000_000_000_000_000);
        assert_eq!(line.real_at(1_000_000_000), Some(1_000));
    }

    #[test]
    fn real_at_is_none_at_rate_zero() {
        let line = Line {
            anchor_v: 10,
            anchor_real: 0,
            rate_q32: 0,
            horizon: u64::MAX,
        };
        assert_eq!(line.real_at(11), None);
        assert_eq!(line.real_at(10), Some(0));
        assert_eq!(line.value_at(1_000_000), 10);
    }

    #[test]
    fn horizon_clamps_value_at() {
        let line = Line {
            anchor_v: 0,
            anchor_real: 0,
            rate_q32: rate_to_q32(1.0),
            horizon: 7,
        };
        assert_eq!(line.value_at(1_000), 7);
        assert_eq!(line.real_at(8), None);
        assert_eq!(line.real_at(7), Some(7));
    }

    #[test]
    fn rates_clamp_to_the_maximum() {
        assert_eq!(rate_to_q32(1e9), rate_to_q32(MAX_RATE));
    }
}
