use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::panic::Location;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use parking_lot::Mutex;

use super::clock::Clock;
use super::participant::Registry;
use super::timer::Timers;
use super::waitset::WaitSets;

/// Per-state-slot scheduler state: the clock, its timer heap, the
/// participant registry and the network wait sets.
pub(crate) struct SchedSlot {
    timers: Arc<Timers<Clock>>,
    reg: Arc<Registry>,
    waits: Arc<WaitSets>,
    wall_base_ns: AtomicU64,
    os_ctx: AtomicU8,
    pub(super) driver: AtomicBool,
}

impl SchedSlot {
    pub(crate) fn new() -> Self {
        let wall_base_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let timers = Timers::new(Clock::new());
        let reg = Registry::new(Arc::clone(&timers));
        let weak = Arc::downgrade(&reg);
        timers.on_settled(Box::new(move || {
            if let Some(reg) = weak.upgrade() {
                reg.timers_settled();
            }
        }));
        Self {
            reg,
            timers,
            waits: Arc::default(),
            wall_base_ns: AtomicU64::new(wall_base_ns),
            os_ctx: AtomicU8::new(0),
            driver: AtomicBool::new(false),
        }
    }

    /// Wall-clock time of virtual instant zero, in ns since the Unix epoch.
    pub(crate) fn wall_base_ns(&self) -> u64 {
        self.wall_base_ns.load(Ordering::Acquire)
    }

    pub(crate) fn set_wall_base_ns(&self, ns: u64) {
        self.wall_base_ns.store(ns, Ordering::Release);
    }

    /// The slot's OS selection as encoded by the network state, 0 until it
    /// is first read there.
    pub(crate) fn os_ctx(&self) -> u8 {
        self.os_ctx.load(Ordering::Acquire)
    }

    /// Store the OS selection. Only under the state lock, so the last store
    /// is the current selection.
    pub(crate) fn set_os_ctx(&self, v: u8) {
        self.os_ctx.store(v, Ordering::Release);
    }

    pub(crate) fn clock(&self) -> &Clock {
        self.timers.source()
    }

    pub(crate) fn timers(&self) -> &Arc<Timers<Clock>> {
        &self.timers
    }

    pub(crate) fn reg(&self) -> &Arc<Registry> {
        &self.reg
    }

    pub(crate) fn waits(&self) -> &Arc<WaitSets> {
        &self.waits
    }
}

impl Drop for SchedSlot {
    fn drop(&mut self) {
        self.timers.shutdown();
    }
}

thread_local! {
    static SLOT_CACHE: RefCell<Option<(u64, Arc<SchedSlot>)>> = const { RefCell::new(None) };
    static DRIVER_TIME: Cell<Option<u64>> = const { Cell::new(None) };
}

static SLOT_GEN: AtomicU64 = AtomicU64::new(1);

/// Force every thread to re-resolve its state slot on its next clock read.
pub(crate) fn invalidate_slot_cache() {
    SLOT_GEN.fetch_add(1, Ordering::AcqRel);
}

/// Run `f` on the calling thread's cached state slot without touching its
/// reference count; `Err(f)` hands `f` back on a cache miss.
fn cached_or<R, F: FnOnce(&SchedSlot) -> R>(f: F) -> Result<R, F> {
    let generation = SLOT_GEN.load(Ordering::Acquire);
    let mut f = Some(f);
    let hit = SLOT_CACHE
        .try_with(|c| {
            let c = c.try_borrow().ok()?;
            match &*c {
                Some((g, s)) if *g == generation => f.take().map(|f| f(s)),
                _ => None,
            }
        })
        .ok()
        .flatten();
    match (hit, f) {
        (Some(r), _) => Ok(r),
        (None, Some(f)) => Err(f),
        (None, None) => unreachable!("slot closure consumed without a result"),
    }
}

fn cached<R>(f: impl FnOnce(&SchedSlot) -> R) -> Option<R> {
    cached_or(f).ok()
}

/// Run `f` on the calling thread's state slot, resolving it as [`slot`] does
/// on a cache miss.
pub(crate) fn with_slot<R>(f: impl FnOnce(&SchedSlot) -> R) -> R {
    match cached_or(f) {
        Ok(r) => r,
        Err(f) => f(&slot()),
    }
}

/// [`with_slot`], but `None` for a thread with no state slot, as
/// [`try_slot`].
pub(crate) fn try_with_slot<R>(f: impl FnOnce(&SchedSlot) -> R) -> Option<R> {
    match cached_or(f) {
        Ok(r) => Some(r),
        Err(f) => try_slot().map(|s| f(&s)),
    }
}

/// Cache `s` for the calling thread. Skipped while a [`with_slot`] closure
/// up the stack borrows the cache.
fn store(s: &Arc<SchedSlot>) {
    let generation = SLOT_GEN.load(Ordering::Acquire);
    let old = SLOT_CACHE
        .try_with(|c| {
            c.try_borrow_mut()
                .ok()
                .and_then(|mut c| c.replace((generation, Arc::clone(s))))
        })
        .ok()
        .flatten();
    drop(old);
}

pub(crate) fn slot() -> Arc<SchedSlot> {
    if let Some(s) = cached_arc() {
        return s;
    }
    let s = crate::state::sched_slot();
    #[cfg(feature = "fast-talker-core")]
    crate::fast_talker_shim::hooks::install();
    store(&s);
    s
}

fn cached_arc() -> Option<Arc<SchedSlot>> {
    let generation = SLOT_GEN.load(Ordering::Acquire);
    SLOT_CACHE
        .try_with(|c| match &*c.try_borrow().ok()? {
            Some((g, s)) if *g == generation => Some(Arc::clone(s)),
            _ => None,
        })
        .ok()
        .flatten()
}

/// Like [`slot`], but `None` for a thread with no state slot instead of a
/// grace-period wait and a panic.
pub(crate) fn try_slot() -> Option<Arc<SchedSlot>> {
    if let Some(s) = cached_arc() {
        return Some(s);
    }
    let s = crate::state::try_sched_slot()?;
    store(&s);
    Some(s)
}

/// The calling thread's driver-time override, if it is inside
/// `enter_timestamp` or `with_driver_time`.
pub(crate) fn driver_time() -> Option<u64> {
    DRIVER_TIME.try_with(Cell::get).ok().flatten()
}

pub(crate) fn set_driver_time(t: Option<u64>) -> Option<u64> {
    DRIVER_TIME.try_with(|c| c.replace(t)).ok().flatten()
}

fn now_ns() -> u64 {
    if let Some(t) = driver_time() {
        return t;
    }
    match cached(|s| s.clock().now()) {
        Some(v) => v,
        None => slot().clock().now(),
    }
}

pub(crate) fn mono_now() -> Duration {
    Duration::from_nanos(now_ns())
}

/// The virtual time now, without resolving the state slot: `None` when the
/// calling thread has never read its clock. Safe under snare's state lock.
/// Reads the slot the thread last resolved even when another test has
/// since registered, which only moves other threads' slots.
#[cfg(feature = "fast-talker-core")]
pub(crate) fn cached_mono_now() -> Option<Duration> {
    driver_time()
        .or_else(|| {
            SLOT_CACHE
                .try_with(|c| c.try_borrow().ok()?.as_ref().map(|(_, s)| s.clock().now()))
                .ok()
                .flatten()
        })
        .map(Duration::from_nanos)
}

pub(crate) fn wall_now() -> Duration {
    let (base, now) = match cached(|s| (s.wall_base_ns(), s.clock().now())) {
        Some(v) => v,
        None => {
            let s = slot();
            (s.wall_base_ns(), s.clock().now())
        }
    };
    let now = driver_time().unwrap_or(now);
    Duration::from_nanos(base) + Duration::from_nanos(now)
}

/// The wall-clock time of the virtual instant `at`.
pub(crate) fn wall_of(at: crate::time::Instant) -> std::time::SystemTime {
    let base = match cached(|s| s.wall_base_ns()) {
        Some(b) => b,
        None => slot().wall_base_ns(),
    };
    std::time::UNIX_EPOCH + Duration::from_nanos(base) + at.as_virtual()
}

/// The virtual instant of the wall-clock time `t`, or `None` when `t` is
/// before the clock's virtual epoch.
#[cfg_attr(not(feature = "fast-talker-core"), allow(dead_code))]
pub(crate) fn instant_of_wall(t: std::time::SystemTime) -> Option<crate::time::Instant> {
    let base = match cached(|s| s.wall_base_ns()) {
        Some(b) => b,
        None => slot().wall_base_ns(),
    };
    let since = t.duration_since(std::time::UNIX_EPOCH).ok()?;
    since
        .checked_sub(Duration::from_nanos(base))
        .map(crate::time::Instant::from_virtual)
}

pub(crate) fn timers() -> Arc<Timers<Clock>> {
    Arc::clone(slot().timers())
}

pub(crate) fn instant_ns(t: crate::time::Instant) -> u64 {
    duration_ns(t.as_virtual())
}

pub(crate) fn duration_ns(d: Duration) -> u64 {
    d.as_nanos().min(u64::MAX as u128) as u64
}

/// Block the calling thread until the virtual clock reaches `deadline_ns`.
/// Uses its own park cell, so a pending [`super::Unparker`] wake is left for
/// the next [`super::park`].
pub(crate) fn sleep_until_ns(deadline_ns: u64) {
    let cell = Arc::new(super::timer::ParkCell::default());
    super::park::wait_on(&cell, Some(deadline_ns), "sleep", false);
}

pub(crate) fn sleep_for(dur: Duration) {
    if dur.is_zero() {
        return;
    }
    sleep_until_ns(now_ns().saturating_add(duration_ns(dur)));
}

pub(crate) fn sleep_until_virtual(deadline: crate::time::Instant) {
    sleep_until_ns(instant_ns(deadline));
}

#[track_caller]
pub(crate) fn warn_driven(op: &str) {
    type Seen = HashSet<&'static Location<'static>>;
    static SEEN: LazyLock<Mutex<Seen>> = LazyLock::new(|| Mutex::new(HashSet::new()));
    let loc = Location::caller();
    if SEEN.lock().insert(loc) {
        eprintln!("snare: {op} at {loc} ignored: the clock is owned by a snare::sched::Driver");
    }
}
