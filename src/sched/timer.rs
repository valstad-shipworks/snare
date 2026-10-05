use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, OnceLock};
use std::task::{Wake, Waker};
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex, MutexGuard};

/// Below this much remaining wall time the timer thread stops trusting the OS
/// timed wait and spins, so wakes land within tens of microseconds.
const SPIN_NS: u64 = 400_000;

static WALL_EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Timer ids are unique across every heap, so a [`ParkCell`] that is reused
/// with a different heap can never mistake a stale fire for its own.
static NEXT_TIMER_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn wall_now_ns() -> u64 {
    WALL_EPOCH.elapsed().as_nanos() as u64
}

pub(crate) fn wall_ns_of(t: Instant) -> u64 {
    t.saturating_duration_since(*WALL_EPOCH).as_nanos() as u64
}

pub(crate) fn wall_instant(ns: u64) -> Instant {
    *WALL_EPOCH + Duration::from_nanos(ns)
}

/// Where a timer heap reads time from: `now_ns` in the heap's own time domain,
/// and `wall_at` maps a point in that domain to the wall time (ns since
/// [`WALL_EPOCH`]) it will be reached, or `None` if the current line never
/// reaches it.
pub(crate) trait TimeSource: Send + Sync + 'static {
    fn now_ns(&self) -> u64;
    fn wall_at(&self, v: u64) -> Option<u64>;
}

#[derive(Default)]
pub(crate) struct ParkState {
    pub(crate) woken: bool,
    fired: u64,
    #[cfg(feature = "shim")]
    pub(crate) link: Option<super::participant::Link>,
    /// The registry moved the participant parked here back to running
    /// during its current wait.
    #[cfg(feature = "shim")]
    pub(crate) running: bool,
}

/// Per-waiter parking cell. Deliberately not the std thread park token, so
/// snare waits never consume an unpark meant for user code.
#[derive(Default)]
pub(crate) struct ParkCell {
    state: Mutex<ParkState>,
    cv: Condvar,
}

pub(crate) enum ParkWake {
    Unparked,
    Fired,
}

impl ParkCell {
    /// Wake the owner. Under `shim` this defers the wake while the caller is
    /// inside a driver timestamp and moves a blocked participant back to
    /// runnable before the OS wake.
    pub(crate) fn unpark(self: &Arc<Self>) {
        #[cfg(feature = "shim")]
        {
            if super::participant::defer_wake(self) {
                return;
            }
            self.unpark_undeferred();
        }
        #[cfg(not(feature = "shim"))]
        self.raw_unpark();
    }

    /// [`unpark`](Self::unpark) without deferring inside a driver timestamp.
    #[cfg(feature = "shim")]
    pub(crate) fn unpark_undeferred(self: &Arc<Self>) {
        let mut s = lock(&self.state);
        if let Some(link) = s.link.clone() {
            drop(s);
            link.reg
                .wake(&link, self, super::participant::WakeKind::Unpark);
            return;
        }
        s.woken = true;
        self.cv.notify_all();
    }

    fn fire(&self, token: u64) {
        #[cfg(feature = "shim")]
        {
            let link = lock(&self.state).link.clone();
            if let Some(link) = link {
                link.reg
                    .wake(&link, self, super::participant::WakeKind::Fire(token));
                return;
            }
        }
        self.raw_fire(token);
    }

    #[cfg_attr(not(feature = "shim"), allow(dead_code))]
    pub(crate) fn raw_unpark(&self) {
        let mut s = lock(&self.state);
        s.woken = true;
        self.cv.notify_all();
    }

    pub(crate) fn raw_fire(&self, token: u64) {
        let mut s = lock(&self.state);
        s.fired = token;
        self.cv.notify_all();
    }

    /// Record an unpark without waking the waiter; `running` says the
    /// registry moved its participant to running. Follow with
    /// [`notify`](Self::notify).
    #[cfg(feature = "shim")]
    pub(crate) fn mark_unparked(&self, running: bool) {
        let mut s = lock(&self.state);
        s.woken = true;
        s.running |= running;
    }

    /// [`mark_unparked`](Self::mark_unparked) for the firing of timer `token`.
    #[cfg(feature = "shim")]
    pub(crate) fn mark_fired(&self, token: u64, running: bool) {
        let mut s = lock(&self.state);
        s.fired = token;
        s.running |= running;
    }

    /// Wake the waiter to re-check what was marked. Needs no lock: a waiter
    /// checks its flags under the cell lock before it sleeps.
    #[cfg(feature = "shim")]
    pub(crate) fn notify(&self) {
        self.cv.notify_all();
    }

    #[cfg_attr(not(feature = "shim"), allow(dead_code))]
    pub(crate) fn lock_state(&self) -> MutexGuard<'_, ParkState> {
        lock(&self.state)
    }

    /// Consume a pending unpark, if any.
    pub(crate) fn take_woken(&self) -> bool {
        std::mem::take(&mut lock(&self.state).woken)
    }

    /// [`wait`](Self::wait) with no wall bound for a participant, also
    /// returning (and clearing) whether the registry moved it to running.
    #[cfg(feature = "shim")]
    pub(crate) fn wait_participant(&self, token: u64) -> (ParkWake, bool) {
        let mut s = lock(&self.state);
        loop {
            let wake = if std::mem::take(&mut s.woken) {
                ParkWake::Unparked
            } else if token != 0 && s.fired == token {
                ParkWake::Fired
            } else {
                self.cv.wait(&mut s);
                continue;
            };
            return (wake, std::mem::take(&mut s.running));
        }
    }

    /// Block until unparked or until timer `token` fires. `token == 0` waits
    /// only for an unpark. `until` bounds the wait in wall time.
    pub(crate) fn wait(&self, token: u64, until: Option<Instant>) -> Option<ParkWake> {
        let mut s = lock(&self.state);
        loop {
            if std::mem::take(&mut s.woken) {
                return Some(ParkWake::Unparked);
            }
            if token != 0 && s.fired == token {
                return Some(ParkWake::Fired);
            }
            match until {
                Some(t) => {
                    if self.cv.wait_until(&mut s, t).timed_out() {
                        return std::mem::take(&mut s.woken).then_some(ParkWake::Unparked);
                    }
                }
                None => self.cv.wait(&mut s),
            }
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

pub(crate) enum TimerTarget {
    #[cfg_attr(not(feature = "shim"), allow(dead_code))]
    Park(Arc<ParkCell>),
    Waker(Waker),
    /// Runs on the firing thread with no snare lock held. Used to wake the
    /// readers of a resource whose delayed data becomes visible at the
    /// deadline; it must not resolve a state slot.
    #[cfg_attr(not(feature = "shim"), allow(dead_code))]
    Release(Box<dyn FnOnce() + Send>),
}

type Entries = BinaryHeap<Reverse<(u64, u64)>>;

/// Two heaps over one set of live entries. `heap` holds the domain's timers:
/// its head is the next deadline a driver may jump to. `foreign` holds the
/// deadlines of threads outside the simulation; they fire once time passes
/// them but never decide where time goes.
struct Heap {
    heap: Entries,
    foreign: Entries,
    live: HashMap<u64, TimerTarget>,
    spawned: bool,
    shutdown: bool,
    armed: bool,
}

impl Heap {
    fn take_due(&mut self, now: u64, firing: &AtomicU64, due: &mut Vec<(u64, TimerTarget)>) {
        let mut taken = take_due_from(&mut self.heap, &mut self.live, now);
        let foreign = take_due_from(&mut self.foreign, &mut self.live, now);
        if !foreign.is_empty() {
            taken.extend(foreign);
            taken.sort_unstable_by_key(|&(deadline, seq, _)| (deadline, seq));
        }
        firing.fetch_add(taken.len() as u64, Ordering::AcqRel);
        due.extend(taken.into_iter().map(|(_, seq, target)| (seq, target)));
    }

    fn drop_stale_head(&mut self) {
        drop_stale(&mut self.heap, &self.live);
        drop_stale(&mut self.foreign, &self.live);
    }

    /// The earliest live deadline in either heap.
    fn earliest(&self) -> Option<u64> {
        let head = |h: &Entries| h.peek().map(|r| r.0.0);
        match (head(&self.heap), head(&self.foreign)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    fn compact(&mut self) {
        if self.heap.len() + self.foreign.len() > 64
            && self.heap.len() + self.foreign.len() > 2 * self.live.len()
        {
            let Heap {
                heap,
                foreign,
                live,
                ..
            } = self;
            heap.retain(|Reverse((_, seq))| live.contains_key(seq));
            foreign.retain(|Reverse((_, seq))| live.contains_key(seq));
        }
    }
}

fn take_due_from(
    heap: &mut Entries,
    live: &mut HashMap<u64, TimerTarget>,
    now: u64,
) -> Vec<(u64, u64, TimerTarget)> {
    let mut due = Vec::new();
    while let Some(&Reverse((deadline, seq))) = heap.peek() {
        if deadline > now && live.contains_key(&seq) {
            break;
        }
        heap.pop();
        if let Some(target) = live.remove(&seq) {
            due.push((deadline, seq, target));
        }
    }
    due
}

fn drop_stale(heap: &mut Entries, live: &HashMap<u64, TimerTarget>) {
    while let Some(&Reverse((_, seq))) = heap.peek() {
        if live.contains_key(&seq) {
            break;
        }
        heap.pop();
    }
}

/// A virtual-time timer heap plus the `snare-sched-timer` thread that fires it.
/// Entries fire in `(deadline, seq)` order once `now_ns() >= deadline`.
pub(crate) struct Timers<S: TimeSource> {
    src: S,
    heap: Mutex<Heap>,
    cv: Condvar,
    kick: AtomicU64,
    /// Entries taken off the heap whose targets have not been woken yet.
    firing: AtomicU64,
    settled: OnceLock<Box<dyn Fn() + Send + Sync>>,
}

impl<S: TimeSource> Timers<S> {
    pub(crate) fn new(src: S) -> Arc<Self> {
        Arc::new(Self {
            src,
            heap: Mutex::new(Heap {
                heap: BinaryHeap::new(),
                foreign: BinaryHeap::new(),
                live: HashMap::new(),
                spawned: false,
                shutdown: false,
                armed: false,
            }),
            cv: Condvar::new(),
            kick: AtomicU64::new(0),
            firing: AtomicU64::new(0),
            settled: OnceLock::new(),
        })
    }

    /// Run `f` each time the last in-flight fire completes.
    #[cfg_attr(not(feature = "shim"), allow(dead_code))]
    pub(crate) fn on_settled(&self, f: Box<dyn Fn() + Send + Sync>) {
        let _ = self.settled.set(f);
    }

    pub(crate) fn source(&self) -> &S {
        &self.src
    }

    #[cfg_attr(not(feature = "shim"), allow(dead_code))]
    pub(crate) fn insert(self: &Arc<Self>, deadline: u64, target: TimerTarget) -> u64 {
        self.insert_as(deadline, target, false)
    }

    /// [`insert`](Self::insert) into the domain heap, or with `foreign` into
    /// the heap that never sets [`next_deadline`](Self::next_deadline).
    pub(crate) fn insert_as(
        self: &Arc<Self>,
        deadline: u64,
        target: TimerTarget,
        foreign: bool,
    ) -> u64 {
        let mut h = lock(&self.heap);
        let seq = NEXT_TIMER_ID.fetch_add(1, Ordering::Relaxed);
        if foreign {
            h.foreign.push(Reverse((deadline, seq)));
        } else {
            h.heap.push(Reverse((deadline, seq)));
        }
        h.live.insert(seq, target);
        let head = h.earliest() == Some(deadline);
        if !h.spawned {
            h.spawned = true;
            let me = Arc::clone(self);
            let parent = std::thread::current().id();
            std::thread::Builder::new()
                .name("snare-sched-timer".into())
                .spawn(move || {
                    crate::register_thread_child_of(parent);
                    me.run()
                })
                .expect("failed to spawn snare-sched-timer thread");
        } else if head {
            self.kick.fetch_add(1, Ordering::AcqRel);
            self.cv.notify_all();
        }
        seq
    }

    /// Remove a pending entry. Returns `false` if it already fired or was
    /// cancelled.
    pub(crate) fn cancel(&self, id: u64) -> bool {
        let mut h = lock(&self.heap);
        let was_live = h.live.remove(&id).is_some();
        h.drop_stale_head();
        if h.shutdown && h.live.is_empty() {
            self.cv.notify_all();
        }
        h.compact();
        was_live
    }

    /// Replace the waker of a pending entry. Returns `false` if it is no
    /// longer pending.
    pub(crate) fn set_waker(&self, id: u64, waker: &Waker) -> bool {
        let mut h = lock(&self.heap);
        match h.live.get_mut(&id) {
            Some(TimerTarget::Waker(w)) => {
                if !w.will_wake(waker) {
                    *w = waker.clone();
                }
                true
            }
            Some(TimerTarget::Park(_) | TimerTarget::Release(_)) => true,
            None => false,
        }
    }

    pub(crate) fn pending(&self) -> usize {
        lock(&self.heap).live.len()
    }

    #[cfg_attr(not(feature = "shim"), allow(dead_code))]
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        let h = lock(&self.heap);
        h.heap.peek().map(|r| r.0.0)
    }

    /// The earliest pending deadline, and whether any entry has been taken
    /// off the heap but not yet delivered to its target.
    #[cfg_attr(not(feature = "shim"), allow(dead_code))]
    pub(crate) fn next_deadline_and_firing(&self) -> (Option<u64>, bool) {
        let h = lock(&self.heap);
        (
            h.heap.peek().map(|r| r.0.0),
            self.firing.load(Ordering::Acquire) != 0,
        )
    }

    /// Re-arm the timer thread after the time line changed.
    #[cfg_attr(not(feature = "shim"), allow(dead_code))]
    pub(crate) fn notify(&self) {
        let _h = lock(&self.heap);
        self.kick.fetch_add(1, Ordering::AcqRel);
        self.cv.notify_all();
    }

    /// [`notify`](Self::notify), skipped when the timer thread has nothing
    /// to do: it holds no wall deadline and the earliest entry is still
    /// unreachable on the current line. Call it after the clock change.
    #[cfg_attr(not(feature = "shim"), allow(dead_code))]
    pub(crate) fn notify_if_reachable(&self) {
        let h = lock(&self.heap);
        let reachable = h
            .earliest()
            .is_some_and(|deadline| self.src.wall_at(deadline).is_some());
        if h.armed || h.shutdown || reachable {
            self.kick.fetch_add(1, Ordering::AcqRel);
            self.cv.notify_all();
        }
    }

    /// Let the timer thread exit once no entries are pending. Entries that
    /// are still pending (a [`Sleep`](super::Sleep) can outlive its slot)
    /// keep firing until they are gone.
    #[cfg_attr(not(feature = "shim"), allow(dead_code))]
    pub(crate) fn shutdown(&self) {
        let mut h = lock(&self.heap);
        h.shutdown = true;
        self.kick.fetch_add(1, Ordering::AcqRel);
        self.cv.notify_all();
    }

    /// Fire every entry that is due now on the calling thread. Returns how
    /// many fired.
    #[cfg_attr(not(feature = "shim"), allow(dead_code))]
    pub(crate) fn fire_due(&self) -> u32 {
        let mut due = Vec::new();
        {
            let mut h = lock(&self.heap);
            h.take_due(self.src.now_ns(), &self.firing, &mut due);
        }
        let n = due.len() as u32;
        self.fire_all(&mut due);
        n
    }

    /// Run `advance` (a clock move) and take every entry due afterwards in
    /// one step under the heap lock, so the timer thread cannot fire them in
    /// between. Deliver the result with [`fire_taken`](Self::fire_taken).
    #[cfg_attr(not(feature = "shim"), allow(dead_code))]
    pub(crate) fn advance_and_take<R>(
        &self,
        advance: impl FnOnce() -> R,
    ) -> (R, Vec<(u64, TimerTarget)>) {
        let mut due = Vec::new();
        let mut h = lock(&self.heap);
        let r = advance();
        h.take_due(self.src.now_ns(), &self.firing, &mut due);
        (r, due)
    }

    /// Fire entries taken by [`advance_and_take`](Self::advance_and_take).
    /// Returns how many fired.
    #[cfg_attr(not(feature = "shim"), allow(dead_code))]
    pub(crate) fn fire_taken(&self, mut due: Vec<(u64, TimerTarget)>) -> u32 {
        let n = due.len() as u32;
        self.fire_all(&mut due);
        n
    }

    /// The `n` earliest pending entries: deadline, plus the park cell for
    /// entries that wake a parked thread.
    #[cfg_attr(not(feature = "shim"), allow(dead_code))]
    pub(crate) fn snapshot(&self, n: usize) -> Vec<(u64, Option<Arc<ParkCell>>)> {
        let h = lock(&self.heap);
        let mut entries: Vec<(u64, u64)> = h
            .heap
            .iter()
            .map(|r| r.0)
            .filter(|(_, seq)| h.live.contains_key(seq))
            .collect();
        entries.sort_unstable();
        entries.truncate(n);
        entries
            .into_iter()
            .map(|(deadline, seq)| {
                let cell = match h.live.get(&seq) {
                    Some(TimerTarget::Park(cell)) => Some(Arc::clone(cell)),
                    _ => None,
                };
                (deadline, cell)
            })
            .collect()
    }

    fn run(self: Arc<Self>) {
        super::set_driver_thread();
        let mut h = lock(&self.heap);
        let mut due = Vec::new();
        loop {
            if h.shutdown && h.live.is_empty() {
                h.spawned = false;
                return;
            }
            h.take_due(self.src.now_ns(), &self.firing, &mut due);
            if !due.is_empty() {
                MutexGuard::unlocked(&mut h, || self.fire_all(&mut due));
                continue;
            }
            let kick = self.kick.load(Ordering::Acquire);
            let wake_wall = h.earliest().and_then(|deadline| self.src.wall_at(deadline));
            h.armed = wake_wall.is_some();
            match wake_wall {
                None => self.cv.wait(&mut h),
                Some(w) => {
                    let now_w = wall_now_ns();
                    if w > now_w.saturating_add(SPIN_NS) {
                        self.cv.wait_until(&mut h, wall_instant(w - SPIN_NS));
                    } else if w > now_w {
                        MutexGuard::unlocked(&mut h, || {
                            while wall_now_ns() < w && self.kick.load(Ordering::Acquire) == kick {
                                std::hint::spin_loop();
                                std::thread::yield_now();
                            }
                        });
                    }
                }
            }
        }
    }

    fn fire_all(&self, due: &mut Vec<(u64, TimerTarget)>) {
        for (seq, target) in due.drain(..) {
            match target {
                TimerTarget::Park(cell) => cell.fire(seq),
                TimerTarget::Waker(w) => w.wake(),
                TimerTarget::Release(f) => f(),
            }
            if self.firing.fetch_sub(1, Ordering::AcqRel) == 1
                && let Some(f) = self.settled.get()
            {
                f();
            }
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    super::note_lock();
    m.lock()
}
