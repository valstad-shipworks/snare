//! The blocking edge of synchronization: the contended path of mutexes, condition variables, thread
//! parking and every channel built on them. Uncontended, all of these are userspace atomics and
//! never reach here; when they must block they bottom out in a few OS calls:
//!
//! - Linux: `syscall(SYS_futex, FUTEX_WAIT[_BITSET])` — std's Mutex/RwLock/Condvar/park/Once and
//!   parking_lot all issue it through libc's generic `syscall`, which the `syscall` hook routes here.
//! - macOS: `pthread_mutex_lock` and `pthread_cond_*` (std Mutex/Condvar, parking_lot), and
//!   `dispatch_semaphore_wait` (std's thread parker, hence RwLock/Once and the channels that park).
//!
//! A managed thread blocked in one of these is counted toward its domain's quiescence, and its
//! timeout — computed by the caller from the (virtual) clock — is honoured in the domain's time.
//! A lock whose holder is outside the domain is the exception: nothing in the domain will release
//! it, so its waiter must not let the domain look quiescent. The pthread mutex hooks record each
//! managed thread's holds (`accounting::Held`), which tells a contended lock's holder apart; a
//! futex word carries no owner, so a Linux wait on one in static data, where std's process-wide
//! locks live, first waits out a short real-time grace uncounted (`outside_grace`). So does a wait
//! a lock's back-off spin leads into (`domain::backing_off`), which may be on a lock the domain
//! shares with other threads wherever it lives: parking_lot's process-wide bucket locks are on
//! the heap, and parked behind with a futex on Linux or a condition variable on macOS.
//!
//! Each hook takes one of three paths. Under a deterministic schedule (`det_*`) the wait parks in
//! the schedule on the object's address, and the matching wake moves waiters there to the run
//! queue. Otherwise a managed thread makes the real call, bracketed so the domain counts it as
//! parked, and a timed wait is cut into real-time slices checked against the virtual deadline
//! (`domain::timed_native_wait`). Off a domain, or under passthrough, the call is forwarded as is.
//! Wakes (`pthread_cond_signal`, `sem_post`, `FUTEX_WAKE`, ...) are always forwarded too, after
//! noting the release so an attached executive does not mistake the woken waiters' domain for
//! quiescent before they run.
//!
//! Each `static` below holds the original of the function of the same name, filled in by
//! `crate::patch` before any import is redirected.

use std::ffi::{c_int, c_long};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use libc::{pthread_cond_t, pthread_mutex_t, timespec};

use crate::domain::{self, TimedWait};
use crate::hooks::{Hook, hook, original};
use crate::layer::ClockKind;
use crate::os::nested;

unsafe extern "C" {
    fn pthread_mutexattr_gettype(attr: *const libc::pthread_mutexattr_t, kind: *mut c_int)
    -> c_int;
}

static PTHREAD_MUTEX_INIT: AtomicUsize = AtomicUsize::new(0);
static PTHREAD_MUTEX_DESTROY: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static PTHREAD_COND_INIT: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static PTHREAD_COND_DESTROY: AtomicUsize = AtomicUsize::new(0);

type WaitSignalMasks =
    std::collections::HashMap<(u32, Option<bool>), std::sync::Weak<std::sync::atomic::AtomicU64>>;
type WaitSignals = std::collections::HashMap<usize, WaitSignalMasks>;
static WAIT_SIGNALS: std::sync::OnceLock<std::sync::Mutex<WaitSignals>> =
    std::sync::OnceLock::new();

thread_local! {
    static WAIT_SIGNAL_VERSION: std::cell::Cell<Option<(usize, u64)>> = const { std::cell::Cell::new(None) };
    #[cfg(target_os = "linux")]
    static FUTEX_WAIT_VALUE: std::cell::Cell<Option<(usize, u32)>> = const { std::cell::Cell::new(None) };
}

pub(crate) fn wait_signal_version(addr: usize) -> Option<u64> {
    WAIT_SIGNAL_VERSION
        .try_with(|value| value.get())
        .ok()
        .flatten()
        .and_then(|(cond, version)| (cond == addr).then_some(version))
}

#[cfg(target_os = "linux")]
pub(crate) fn futex_wait_value(addr: usize) -> Option<u32> {
    FUTEX_WAIT_VALUE
        .try_with(|value| value.get())
        .ok()
        .flatten()
        .and_then(|(word, value)| (word == addr).then_some(value))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn signal_version(addr: usize) -> Option<u64> {
    signal_version_masked(addr, u32::MAX, None)
}

pub(crate) fn signal_version_masked(addr: usize, mask: u32, private: Option<bool>) -> Option<u64> {
    let signals = WAIT_SIGNALS.get()?;
    crate::real(|| {
        signals
            .lock()
            .unwrap()
            .get(&addr)?
            .get(&(mask, private))?
            .upgrade()
            .map(|signal| signal.load(std::sync::atomic::Ordering::Acquire))
    })
}

fn track_signal(addr: usize) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
    track_signal_masked(addr, u32::MAX, None)
}

fn track_signal_masked(
    addr: usize,
    mask: u32,
    private: Option<bool>,
) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
    crate::real(|| {
        let signals = WAIT_SIGNALS.get_or_init(Default::default);
        let mut signals = signals.lock().unwrap();
        signals.retain(|_, masks| {
            masks.retain(|_, signal| signal.strong_count() > 0);
            !masks.is_empty()
        });
        let masks = signals.entry(addr).or_default();
        match masks
            .get(&(mask, private))
            .and_then(std::sync::Weak::upgrade)
        {
            Some(signal) => signal,
            None => {
                let signal = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                masks.insert((mask, private), std::sync::Arc::downgrade(&signal));
                signal
            }
        }
    })
}

fn note_wait_signal(addr: usize) {
    note_wait_signal_masked(addr, u32::MAX, None);
}

fn note_wait_signal_masked(addr: usize, mask: u32, private: Option<bool>) {
    if let Some(signals) = WAIT_SIGNALS.get() {
        crate::real(|| {
            if let Some(masks) = signals.lock().unwrap().get(&addr) {
                for (&(wait_mask, wait_private), signal) in masks {
                    if wait_mask & mask != 0
                        && private.is_none_or(|scope| wait_private == Some(scope))
                        && let Some(signal) = signal.upgrade()
                    {
                        signal.fetch_add(1, std::sync::atomic::Ordering::Release);
                    }
                }
            }
        });
    }
}

/// Mutexes or condition variables, by address, that were set up other than the default way: the
/// few a hook must treat differently (an error-checking mutex, a condition variable on another
/// clock). Default ones are never recorded, so an allocator that sets up its own locks while it
/// holds others reaches no allocation and no lock here; while nothing is recorded a lookup or a
/// removal takes no lock either.
struct Unusual<V> {
    /// How many entries `map` holds, read without its lock.
    len: AtomicUsize,
    map: std::sync::Mutex<Option<std::collections::HashMap<usize, V>>>,
}

impl<V: Copy> Unusual<V> {
    const fn new() -> Self {
        Self {
            len: AtomicUsize::new(0),
            map: std::sync::Mutex::new(None),
        }
    }

    /// Records `addr` as set up with `value`, or forgets it when `value` is `None`, the default.
    fn set(&self, addr: usize, value: Option<V>) {
        if value.is_none() && self.len.load(Ordering::Acquire) == 0 {
            return;
        }
        crate::real(|| {
            let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
            let map = map.get_or_insert_with(Default::default);
            match value {
                Some(value) => map.insert(addr, value),
                None => map.remove(&addr),
            };
            self.len.store(map.len(), Ordering::Release);
        });
    }

    fn get(&self, addr: usize) -> Option<V> {
        if self.len.load(Ordering::Acquire) == 0 {
            return None;
        }
        crate::real(|| {
            let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
            map.as_ref()?.get(&addr).copied()
        })
    }
}

/// The error-checking mutexes, whose relock by their holder must fail rather than deadlock.
static ERRORCHECK_MUTEXES: Unusual<()> = Unusual::new();

unsafe extern "C" fn pthread_mutex_init(
    mutex: *mut pthread_mutex_t,
    attr: *const libc::pthread_mutexattr_t,
) -> c_int {
    type Init =
        unsafe extern "C" fn(*mut pthread_mutex_t, *const libc::pthread_mutexattr_t) -> c_int;
    let r = unsafe { original::<Init>(&PTHREAD_MUTEX_INIT)(mutex, attr) };
    if r == 0 && !crate::state::passthrough() {
        let mut kind = libc::PTHREAD_MUTEX_DEFAULT;
        if !attr.is_null() {
            unsafe { pthread_mutexattr_gettype(attr, &mut kind) };
        }
        ERRORCHECK_MUTEXES.set(
            mutex as usize,
            (kind == libc::PTHREAD_MUTEX_ERRORCHECK).then_some(()),
        );
    }
    r
}

unsafe extern "C" fn pthread_mutex_destroy(mutex: *mut pthread_mutex_t) -> c_int {
    let r = unsafe { original::<MutexFn>(&PTHREAD_MUTEX_DESTROY)(mutex) };
    if r == 0 && !crate::state::passthrough() {
        ERRORCHECK_MUTEXES.set(mutex as usize, None);
    }
    r
}

/// The condition variables on a clock other than `CLOCK_REALTIME`, with that clock.
#[cfg(target_os = "linux")]
static COND_CLOCKS: Unusual<libc::clockid_t> = Unusual::new();

#[cfg(target_os = "linux")]
unsafe extern "C" fn pthread_cond_init(
    cond: *mut pthread_cond_t,
    attr: *const libc::pthread_condattr_t,
) -> c_int {
    type Init = unsafe extern "C" fn(*mut pthread_cond_t, *const libc::pthread_condattr_t) -> c_int;
    let r = unsafe { original::<Init>(&PTHREAD_COND_INIT)(cond, attr) };
    if r == 0 && !crate::state::passthrough() {
        let mut clock = libc::CLOCK_REALTIME;
        if !attr.is_null() {
            unsafe { libc::pthread_condattr_getclock(attr, &mut clock) };
        }
        COND_CLOCKS.set(cond as usize, (clock != libc::CLOCK_REALTIME).then_some(clock));
    }
    r
}

#[cfg(target_os = "linux")]
unsafe extern "C" fn pthread_cond_destroy(cond: *mut pthread_cond_t) -> c_int {
    let r = unsafe { original::<CondSignalFn>(&PTHREAD_COND_DESTROY)(cond) };
    if r == 0 && !crate::state::passthrough() {
        COND_CLOCKS.set(cond as usize, None);
    }
    r
}

fn cond_clock(cond: *mut pthread_cond_t) -> ClockKind {
    #[cfg(target_os = "linux")]
    if COND_CLOCKS.get(cond as usize) == Some(libc::CLOCK_MONOTONIC) {
        return ClockKind::Monotonic;
    }
    let _ = cond;
    ClockKind::Realtime
}

static PTHREAD_MUTEX_LOCK: AtomicUsize = AtomicUsize::new(0);
static PTHREAD_MUTEX_TRYLOCK: AtomicUsize = AtomicUsize::new(0);
static PTHREAD_MUTEX_UNLOCK: AtomicUsize = AtomicUsize::new(0);
static PTHREAD_COND_SIGNAL: AtomicUsize = AtomicUsize::new(0);
static PTHREAD_COND_BROADCAST: AtomicUsize = AtomicUsize::new(0);
static PTHREAD_COND_WAIT: AtomicUsize = AtomicUsize::new(0);
static PTHREAD_COND_TIMEDWAIT: AtomicUsize = AtomicUsize::new(0);
static SCHED_YIELD: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "macos")]
static PTHREAD_COND_TIMEDWAIT_RELATIVE_NP: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "macos")]
static DISPATCH_SEMAPHORE_WAIT: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "macos")]
static DISPATCH_TIME: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "macos")]
static DISPATCH_SEMAPHORE_SIGNAL: AtomicUsize = AtomicUsize::new(0);
static SEM_WAIT: AtomicUsize = AtomicUsize::new(0);
static SEM_TRYWAIT: AtomicUsize = AtomicUsize::new(0);
static SEM_POST: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static SEM_TIMEDWAIT: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static SEM_CLOCKWAIT: AtomicUsize = AtomicUsize::new(0);

/// The synchronization hooks for this target.
pub(crate) fn hooks() -> Vec<Hook> {
    vec![
        hook!("pthread_mutex_init", pthread_mutex_init, PTHREAD_MUTEX_INIT),
        hook!(
            "pthread_mutex_destroy",
            pthread_mutex_destroy,
            PTHREAD_MUTEX_DESTROY
        ),
        #[cfg(target_os = "linux")]
        hook!("pthread_cond_init", pthread_cond_init, PTHREAD_COND_INIT),
        #[cfg(target_os = "linux")]
        hook!(
            "pthread_cond_destroy",
            pthread_cond_destroy,
            PTHREAD_COND_DESTROY
        ),
        hook!("pthread_mutex_lock", pthread_mutex_lock, PTHREAD_MUTEX_LOCK),
        hook!(
            "pthread_mutex_trylock",
            pthread_mutex_trylock,
            PTHREAD_MUTEX_TRYLOCK
        ),
        hook!(
            "pthread_mutex_unlock",
            pthread_mutex_unlock,
            PTHREAD_MUTEX_UNLOCK
        ),
        hook!(
            "pthread_cond_signal",
            pthread_cond_signal,
            PTHREAD_COND_SIGNAL
        ),
        hook!(
            "pthread_cond_broadcast",
            pthread_cond_broadcast,
            PTHREAD_COND_BROADCAST
        ),
        hook!("pthread_cond_wait", pthread_cond_wait, PTHREAD_COND_WAIT),
        hook!(
            "pthread_cond_timedwait",
            pthread_cond_timedwait,
            PTHREAD_COND_TIMEDWAIT
        ),
        hook!("sched_yield", sched_yield, SCHED_YIELD),
        hook!("sem_wait", sem_wait, SEM_WAIT),
        hook!("sem_trywait", sem_trywait, SEM_TRYWAIT),
        hook!("sem_post", sem_post, SEM_POST),
        #[cfg(target_os = "linux")]
        hook!("sem_timedwait", sem_timedwait, SEM_TIMEDWAIT),
        #[cfg(target_os = "linux")]
        hook!("sem_clockwait", sem_clockwait, SEM_CLOCKWAIT),
        #[cfg(target_os = "macos")]
        hook!(
            "pthread_cond_timedwait_relative_np",
            pthread_cond_timedwait_relative_np,
            PTHREAD_COND_TIMEDWAIT_RELATIVE_NP
        ),
        #[cfg(target_os = "macos")]
        hook!(
            "dispatch_semaphore_wait",
            dispatch_semaphore_wait,
            DISPATCH_SEMAPHORE_WAIT
        ),
        #[cfg(target_os = "macos")]
        hook!("dispatch_time", dispatch_time, DISPATCH_TIME),
        #[cfg(target_os = "macos")]
        hook!(
            "dispatch_semaphore_signal",
            dispatch_semaphore_signal,
            DISPATCH_SEMAPHORE_SIGNAL
        ),
    ]
}

/// Whether this call should run under the domain's deterministic schedule: a managed thread of the
/// code under test (not the sim's own internals) in a deterministic domain.
fn deterministic() -> bool {
    domain::counts_native_waits() && domain::det_active()
}

/// The virtual-clock instant `after` from now, for a deterministic wait's deadline.
fn virtual_deadline(after: Duration) -> Option<Duration> {
    domain::virtual_now().map(|now| now.saturating_add(after))
}

/// Takes `mutex` under the deterministic schedule: a contended lock waits in the schedule on the
/// mutex's address until an unlock there wakes it. A mutex held by a thread outside the schedule
/// (another test's, a thread no sim manages, a pool's worker left over from an earlier sim) is
/// first waited for in real time, keeping the baton, for [`DET_OUTSIDE_HOLDER_GRACE`], so a short
/// hold cannot reorder this simulation's threads; a holder that keeps it longer (blocked itself,
/// as a pool's worker waiting for its next job while holding the queue's lock) is then waited for
/// in the schedule, where its unlock reaches the waiter wherever it is made
/// (`domain::det_wake_addr`). Any other error from `pthread_mutex_trylock` (`EINVAL`, or `EAGAIN`
/// once a recursive mutex's count is exhausted; POSIX pthread_mutex_lock, which also specifies
/// trylock) is returned as is.
///
/// # Safety
/// As for `pthread_mutex_lock`.
unsafe fn det_mutex_lock(mutex: *mut pthread_mutex_t) -> c_int {
    let addr = mutex as usize;
    let mut grace = DET_OUTSIDE_HOLDER_GRACE;
    loop {
        if !deterministic() {
            // The schedule let this thread go while it waited.
            // SAFETY: the caller's mutex.
            return unsafe { pthread_mutex_lock(mutex) };
        }
        // SAFETY: the caller's mutex.
        match unsafe { trylock(mutex) } {
            0 => {
                domain::det_took(addr);
                domain::note_mutex_taken(addr);
                return 0;
            }
            libc::EBUSY
                if crate::accounting::held().is_some_and(|held| held.holds(addr))
                    && ERRORCHECK_MUTEXES.get(addr).is_some() =>
            {
                return unsafe { original::<MutexFn>(&PTHREAD_MUTEX_LOCK)(mutex) };
            }
            libc::EBUSY if domain::det_held_inside(addr) => {
                let _label = crate::wait_label("mutex");
                domain::det_block(crate::DetKey::Addr(addr), None);
            }
            libc::EBUSY => {
                domain::end_spin();
                let _listed = domain::det_listen(addr);
                // SAFETY: the caller's mutex.
                match unsafe { trylock_within(mutex, grace) } {
                    Some(0) => {
                        domain::det_took(addr);
                        domain::note_mutex_taken(addr);
                        return 0;
                    }
                    Some(r) => return r,
                    None => {
                        grace = Duration::ZERO;
                        let _label = crate::wait_label("mutex");
                        let _outside = crate::sched::outside_holder();
                        domain::det_block(crate::DetKey::Addr(addr), None);
                    }
                }
            }
            r => return r,
        }
    }
}

/// Retries `pthread_mutex_trylock` on `mutex` for up to `grace` of real time while it reports
/// `EBUSY`: `None` if it still does, else what it last returned.
///
/// # Safety
/// As for `pthread_mutex_trylock`.
unsafe fn trylock_within(mutex: *mut pthread_mutex_t, grace: Duration) -> Option<c_int> {
    // How often the mutex is tried meanwhile. A snare choice.
    const POLL: Duration = Duration::from_micros(50);
    let start = crate::real(std::time::Instant::now);
    loop {
        // SAFETY: as for this function.
        match unsafe { trylock(mutex) } {
            libc::EBUSY => {}
            r => return Some(r),
        }
        if crate::real(|| start.elapsed()) >= grace {
            return None;
        }
        crate::real(|| std::thread::sleep(POLL));
    }
}

/// Releases `mutex` and wakes one deterministic waiter on it.
///
/// # Safety
/// As for `pthread_mutex_unlock`.
unsafe fn det_mutex_unlock(mutex: *mut pthread_mutex_t) -> c_int {
    domain::det_released(mutex as usize);
    domain::note_mutex_freed(mutex as usize);
    // SAFETY: PTHREAD_MUTEX_UNLOCK holds libc's pthread_mutex_unlock; the caller's mutex.
    let r = unsafe { original::<MutexFn>(&PTHREAD_MUTEX_UNLOCK)(mutex) };
    domain::det_wake_addr(mutex as usize, 1);
    r
}

/// A condition-variable wait under the deterministic schedule: release the mutex, wait on the
/// condvar's address until signalled or `deadline`, take the mutex back.
///
/// # Safety
/// As for `pthread_cond_wait`, with `mutex` held.
unsafe fn det_cond_wait(
    cond: *mut pthread_cond_t,
    mutex: *mut pthread_mutex_t,
    deadline: Option<Duration>,
) -> c_int {
    let signal = track_signal(cond as usize);
    let previous = WAIT_SIGNAL_VERSION.with(|version| {
        version.replace(Some((
            cond as usize,
            signal.load(std::sync::atomic::Ordering::Acquire),
        )))
    });
    unsafe { det_mutex_unlock(mutex) };
    let why = {
        let _label = crate::accounting::wait_label_on("cond", cond as usize);
        domain::det_block(crate::DetKey::Addr(cond as usize), deadline)
    };
    WAIT_SIGNAL_VERSION.with(|version| version.set(previous));
    unsafe { det_mutex_lock(mutex) };
    if why == crate::DetWake::TimedOut {
        libc::ETIMEDOUT
    } else {
        0
    }
}

/// A `timespec` as a span, clamping a negative or out-of-range field into range rather than
/// failing: the real call has already accepted or will reject the value itself.
fn span(ts: &timespec) -> Duration {
    Duration::new(
        ts.tv_sec.max(0) as u64,
        ts.tv_nsec.clamp(0, 999_999_999) as u32,
    )
}

/// A span as a `timespec`, for a real wait's relative or absolute deadline.
fn to_timespec(d: Duration) -> timespec {
    timespec {
        tv_sec: d.as_secs() as libc::time_t,
        tv_nsec: d.subsec_nanos() as _,
    }
}

/// `pthread_mutex_lock`, `_trylock` and `_unlock`.
type MutexFn = unsafe extern "C" fn(*mut pthread_mutex_t) -> c_int;
/// `pthread_cond_wait`.
type CondWaitFn = unsafe extern "C" fn(*mut pthread_cond_t, *mut pthread_mutex_t) -> c_int;
/// `pthread_cond_timedwait` and, on macOS, `pthread_cond_timedwait_relative_np`.
type CondTimedWaitFn =
    unsafe extern "C" fn(*mut pthread_cond_t, *mut pthread_mutex_t, *const timespec) -> c_int;

/// libc's `pthread_mutex_trylock`, past the hook.
///
/// # Safety
/// As for `pthread_mutex_trylock`.
unsafe fn trylock(mutex: *mut pthread_mutex_t) -> c_int {
    // SAFETY: PTHREAD_MUTEX_TRYLOCK holds libc's pthread_mutex_trylock; argument forwarded.
    unsafe { original::<MutexFn>(&PTHREAD_MUTEX_TRYLOCK)(mutex) }
}

#[cfg(target_os = "macos")]
pub(crate) enum NativeMutexOwner {
    ThreadId(u64),
    MachPort(u32),
}

#[cfg(target_os = "macos")]
pub(crate) unsafe fn native_mutex_owner(mutex: usize) -> Option<NativeMutexOwner> {
    use std::sync::atomic::Ordering;
    if !mutex.is_multiple_of(8) || std::mem::size_of::<pthread_mutex_t>() != 64 {
        return None;
    }
    let bytes = mutex as *const u8;
    let signature =
        unsafe { bytes.cast::<std::sync::atomic::AtomicU32>().as_ref()? }.load(Ordering::Acquire);
    if !matches!(signature, 0x4d55_5458 | 0x4d55_545a) {
        return None;
    }
    // Darwin libpthread src/types_internal.h fixes mtxopts at 12 and the owner union at 24.
    let options =
        unsafe { &*bytes.add(12).cast::<std::sync::atomic::AtomicU32>() }.load(Ordering::Relaxed);
    if options & (1 << 14) != 0 {
        let owner = unsafe { &*bytes.add(24).cast::<std::sync::atomic::AtomicU32>() }
            .load(Ordering::Acquire)
            & 0xffff_fffc;
        (owner != 0 && owner != 0xffff_fffc).then_some(NativeMutexOwner::MachPort(owner))
    } else {
        let owner = unsafe { &*bytes.add(24).cast::<std::sync::atomic::AtomicU64>() }
            .load(Ordering::Acquire);
        (owner != 0 && owner != u64::MAX).then_some(NativeMutexOwner::ThreadId(owner))
    }
}

/// Notes the calling thread took `mutex` if `r` says it did.
fn taken(mutex: *mut pthread_mutex_t, r: c_int) -> c_int {
    if r == 0 {
        domain::note_mutex_taken(mutex as usize);
    }
    r
}

/// `pthread_mutex_lock` (POSIX pthread_mutex_lock): a contended lock is a wait that only another
/// thread's unlock ends, so it is counted toward quiescence (or, deterministic, parks in the
/// schedule), though while no other thread of the domain holds the mutex it keeps the domain from
/// being quiescent (see `domain::watch_mutex`). Every successful lock is recorded so a participant
/// waiting for this mutex can tell who holds it, if anyone.
unsafe extern "C" fn pthread_mutex_lock(mutex: *mut pthread_mutex_t) -> c_int {
    // SAFETY: PTHREAD_MUTEX_LOCK holds libc's pthread_mutex_lock.
    let lock = unsafe { original::<MutexFn>(&PTHREAD_MUTEX_LOCK) };
    if !domain::counts_native_waits() {
        // SAFETY: forwarding the caller's argument unchanged.
        return taken(mutex, unsafe { lock(mutex) });
    }
    if domain::det_active() {
        // SAFETY: the caller's mutex.
        return unsafe { det_mutex_lock(mutex) };
    }
    // Only a contended lock blocks. Counting every lock would show a running thread as parked for
    // a moment, long enough for a peer to mistake the domain for deadlocked. trylock's EBUSY means
    // the mutex is already locked (POSIX pthread_mutex_lock).
    // SAFETY: the caller's mutex, as pthread_mutex_lock would receive it.
    match unsafe { trylock(mutex) } {
        0 => taken(mutex, 0),
        libc::EBUSY => {
            // Once watched, every later unlock is seen; trying again catches one that came before.
            let watch = domain::watch_mutex(mutex as usize, false);
            // SAFETY: as above.
            if watch.is_some() && unsafe { trylock(mutex) } == 0 {
                return taken(mutex, 0);
            }
            let _label = crate::accounting::wait_label_mutex("mutex", None, mutex as usize);
            // SAFETY: forwarding the caller's argument unchanged.
            domain::native_wait(|| taken(mutex, unsafe { lock(mutex) }))
        }
        // SAFETY: as above; let the real call report whatever trylock objected to.
        _ => taken(mutex, unsafe { lock(mutex) }),
    }
}

/// `pthread_mutex_trylock`: never blocks, so it is forwarded and only a success recorded.
unsafe extern "C" fn pthread_mutex_trylock(mutex: *mut pthread_mutex_t) -> c_int {
    // SAFETY: forwarding the caller's argument unchanged.
    taken(mutex, unsafe { trylock(mutex) })
}

/// `pthread_mutex_unlock`: forwarded and recorded, and it wakes one waiter parked on the mutex in
/// a deterministic schedule: its own thread's, or another's waiting on a holder outside it.
unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut pthread_mutex_t) -> c_int {
    if deterministic() {
        // SAFETY: the caller's mutex.
        return unsafe { det_mutex_unlock(mutex) };
    }
    // SAFETY: PTHREAD_MUTEX_UNLOCK holds libc's pthread_mutex_unlock; argument forwarded.
    let r = unsafe { original::<MutexFn>(&PTHREAD_MUTEX_UNLOCK)(mutex) };
    if r == 0 {
        domain::note_mutex_freed(mutex as usize);
        domain::det_wake_addr(mutex as usize, 1);
    }
    r
}

/// `pthread_cond_signal` and `pthread_cond_broadcast`.
type CondSignalFn = unsafe extern "C" fn(*mut pthread_cond_t) -> c_int;

/// `pthread_cond_signal`: unblocks at least one waiter (POSIX pthread_cond_broadcast), counted
/// here as one.
unsafe extern "C" fn pthread_cond_signal(cond: *mut pthread_cond_t) -> c_int {
    note_wait_signal(cond as usize);
    domain::note_hook_effect("pthread_cond_signal");
    domain::note_release(cond as usize, 1);
    domain::det_wake_addr(cond as usize, 1);
    // SAFETY: PTHREAD_COND_SIGNAL holds libc's pthread_cond_signal; argument forwarded.
    unsafe { original::<CondSignalFn>(&PTHREAD_COND_SIGNAL)(cond) }
}

/// `pthread_cond_broadcast`: unblocks every waiter (POSIX pthread_cond_broadcast).
unsafe extern "C" fn pthread_cond_broadcast(cond: *mut pthread_cond_t) -> c_int {
    note_wait_signal(cond as usize);
    domain::note_hook_effect("pthread_cond_broadcast");
    domain::note_release(cond as usize, usize::MAX);
    domain::det_wake_addr(cond as usize, usize::MAX);
    // SAFETY: PTHREAD_COND_BROADCAST holds libc's pthread_cond_broadcast; argument forwarded.
    unsafe { original::<CondSignalFn>(&PTHREAD_COND_BROADCAST)(cond) }
}

/// `pthread_cond_wait`: atomically releases `mutex`, blocks until signalled (or spuriously), and
/// returns holding `mutex` again (POSIX pthread_cond_wait). Counted as a wait on the condvar's
/// address that needs `mutex` to return.
unsafe extern "C" fn pthread_cond_wait(
    cond: *mut pthread_cond_t,
    mutex: *mut pthread_mutex_t,
) -> c_int {
    if domain::backing_off() {
        let grace = if deterministic() {
            DET_OUTSIDE_HOLDER_GRACE
        } else {
            OUTSIDE_HOLDER_GRACE
        };
        // SAFETY: the caller's condvar and held mutex.
        return unsafe { cond_outside_grace(cond, mutex, grace) };
    }
    if deterministic() {
        // SAFETY: the caller's condvar and held mutex.
        return unsafe { det_cond_wait(cond, mutex, None) };
    }
    // SAFETY: PTHREAD_COND_WAIT holds libc's pthread_cond_wait.
    let wait = unsafe { original::<CondWaitFn>(&PTHREAD_COND_WAIT) };
    let _watch = cond_watch(mutex);
    let _label = crate::accounting::wait_label_mutex("cond", Some(cond as usize), mutex as usize);
    // SAFETY: the caller's mutex, which the wait returns holding.
    let relock = |lock: bool| unsafe { relock_mutex(mutex, lock) };
    // SAFETY: forwarding the caller's arguments unchanged.
    let r = domain::native_cond_wait(&relock, || unsafe { wait(cond, mutex) });
    domain::note_mutex_taken(mutex as usize);
    r
}

/// A condition-variable wait that a back-off spin leads into (see [`domain::backing_off`]), for
/// its first `grace` ([`OUTSIDE_HOLDER_GRACE`], or [`DET_OUTSIDE_HOLDER_GRACE`] under a
/// deterministic schedule, which keeps the baton meanwhile) as a real wait the domain does not
/// count, as [`outside_grace`] waits on a futex word in static data: a lock's slow path parks on
/// it, and the lock's holder, which will wake it, may be outside the domain. Ends the spin, so the
/// caller's next wait counts, and returns the wait's result, or zero once the grace ran out: a
/// spurious wakeup, which every condvar caller must tolerate (POSIX pthread_cond_wait).
///
/// # Safety
/// `cond` and `mutex` are as for `pthread_cond_wait`, with `mutex` held by the caller.
unsafe fn cond_outside_grace(
    cond: *mut pthread_cond_t,
    mutex: *mut pthread_mutex_t,
    grace: Duration,
) -> c_int {
    domain::end_spin();
    // SAFETY: PTHREAD_COND_TIMEDWAIT_RELATIVE_NP holds libc's function.
    #[cfg(target_os = "macos")]
    let (wait, timeout) = unsafe {
        (
            original::<CondTimedWaitFn>(&PTHREAD_COND_TIMEDWAIT_RELATIVE_NP),
            to_timespec(grace),
        )
    };
    // SAFETY: PTHREAD_COND_TIMEDWAIT holds libc's function.
    #[cfg(target_os = "linux")]
    let (wait, timeout) = unsafe {
        (
            original::<CondTimedWaitFn>(&PTHREAD_COND_TIMEDWAIT),
            to_timespec(crate::real(|| {
                let mut ts = timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                let clock = match cond_clock(cond) {
                    ClockKind::Monotonic => libc::CLOCK_MONOTONIC,
                    _ => libc::CLOCK_REALTIME,
                };
                libc::clock_gettime(clock, &mut ts);
                span(&ts) + grace
            })),
        )
    };
    domain::note_mutex_freed(mutex as usize);
    // SAFETY: the caller's condvar and held mutex, with the grace as the timeout.
    let r = unsafe { wait(cond, mutex, &timeout) };
    domain::note_mutex_taken(mutex as usize);
    if r == libc::ETIMEDOUT { 0 } else { r }
}

/// A condition-variable wait is about to let go of `mutex` inside libc, where no hook sees it.
fn cond_watch(mutex: *mut pthread_mutex_t) -> Option<domain::MutexWatch> {
    let watch = domain::watch_mutex(mutex as usize, true);
    domain::note_mutex_freed(mutex as usize);
    watch
}

/// Takes (`true`) or lets go of the mutex a condition-variable wait returned holding, with the
/// real calls: the thread is still counted in its wait. A thread that followed a wake into a
/// deterministic sim meanwhile takes it back in that sim's schedule.
///
/// # Safety
/// `mutex` is the caller's, held by it to let go.
unsafe fn relock_mutex(mutex: *mut pthread_mutex_t, lock: bool) {
    // SAFETY: PTHREAD_MUTEX_LOCK and PTHREAD_MUTEX_UNLOCK hold libc's functions; the caller's mutex.
    unsafe {
        if lock && deterministic() {
            det_mutex_lock(mutex);
        } else if lock {
            taken(mutex, original::<MutexFn>(&PTHREAD_MUTEX_LOCK)(mutex));
        } else {
            original::<MutexFn>(&PTHREAD_MUTEX_UNLOCK)(mutex);
            domain::note_mutex_freed(mutex as usize);
        }
    }
}

/// `pthread_cond_timedwait`: as `pthread_cond_wait`, giving up with `ETIMEDOUT` once the absolute
/// `deadline` passes on the condvar's clock — `CLOCK_REALTIME` unless set otherwise with
/// `pthread_condattr_setclock` (POSIX pthread_cond_timedwait, pthread_condattr_setclock).
unsafe extern "C" fn pthread_cond_timedwait(
    cond: *mut pthread_cond_t,
    mutex: *mut pthread_mutex_t,
    deadline: *const timespec,
) -> c_int {
    // SAFETY: PTHREAD_COND_TIMEDWAIT holds libc's pthread_cond_timedwait.
    let wait = unsafe { original::<CondTimedWaitFn>(&PTHREAD_COND_TIMEDWAIT) };
    if deterministic() && !deadline.is_null() {
        // Taken to be on CLOCK_REALTIME, the virtual clock the caller read: macOS has no other,
        // and it is the Linux default. A Linux condvar set to another clock is not detected here.
        let now = domain::now(cond_clock(cond)).unwrap_or_default();
        // SAFETY: a non-null deadline points at the caller's timespec.
        let after = span(unsafe { &*deadline }).saturating_sub(now);
        // SAFETY: the caller's condvar and held mutex.
        return unsafe { det_cond_wait(cond, mutex, virtual_deadline(after)) };
    }
    if !deadline.is_null()
        && domain::virtual_waits()
        && let Some(now) = domain::now(cond_clock(cond))
    {
        // macOS has no pthread_condattr_setclock (absent from the SDK's <pthread.h>), so the
        // deadline is always on CLOCK_REALTIME —
        // here the virtual one the caller read. Wait out the remainder in the domain's time.
        // SAFETY: a non-null deadline points at the caller's timespec.
        let after = span(unsafe { &*deadline }).saturating_sub(now);
        // SAFETY: the caller's condition variable and the mutex it holds.
        return unsafe { cond_wait_for(cond, mutex, after) };
    }
    // Elsewhere the deadline's clock is whatever the condvar was created with, which this hook
    // cannot see, so the wait keeps its own deadline and is only counted.
    let _watch = cond_watch(mutex);
    let _label = crate::accounting::wait_label_mutex("cond", Some(cond as usize), mutex as usize);
    // SAFETY: the caller's mutex, which the wait returns holding.
    let relock = |lock: bool| unsafe { relock_mutex(mutex, lock) };
    // SAFETY: forwarding the caller's arguments unchanged.
    let r = domain::native_cond_wait(&relock, || unsafe { wait(cond, mutex, deadline) });
    domain::note_mutex_taken(mutex as usize);
    r
}

/// Darwin's `pthread_cond_timedwait_relative_np`: as `pthread_cond_timedwait` with a timeout
/// relative to now (macOS SDK `<pthread.h>`).
#[cfg(target_os = "macos")]
unsafe extern "C" fn pthread_cond_timedwait_relative_np(
    cond: *mut pthread_cond_t,
    mutex: *mut pthread_mutex_t,
    timeout: *const timespec,
) -> c_int {
    if deterministic() && !timeout.is_null() {
        // SAFETY: a non-null timeout points at the caller's timespec; condvar and mutex theirs.
        return unsafe { det_cond_wait(cond, mutex, virtual_deadline(span(&*timeout))) };
    }
    if timeout.is_null() || !domain::virtual_waits() {
        domain::note_mutex_freed(mutex as usize);
        // SAFETY: PTHREAD_COND_TIMEDWAIT_RELATIVE_NP holds libc's function; arguments forwarded.
        let r = unsafe {
            original::<CondTimedWaitFn>(&PTHREAD_COND_TIMEDWAIT_RELATIVE_NP)(cond, mutex, timeout)
        };
        domain::note_mutex_taken(mutex as usize);
        return r;
    }
    // SAFETY: a non-null timeout points at the caller's timespec; the condvar and mutex are theirs.
    unsafe { cond_wait_for(cond, mutex, span(&*timeout)) }
}

/// Waits on `cond` for at most `after` of the domain's time. Condition-variable signals are not
/// latched, so a slice that times out short of the deadline returns a spurious wakeup (which every
/// condvar caller must already tolerate; POSIX pthread_cond_wait, "Condition Wait Semantics")
/// rather than waiting again and risking a lost signal.
///
/// # Safety
/// `cond` and `mutex` are as for `pthread_cond_timedwait`, with `mutex` held by the caller.
unsafe fn cond_wait_for(
    cond: *mut pthread_cond_t,
    mutex: *mut pthread_mutex_t,
    after: Duration,
) -> c_int {
    // SAFETY: PTHREAD_COND_TIMEDWAIT_RELATIVE_NP holds libc's function.
    #[cfg(target_os = "macos")]
    let wait = unsafe { original::<CondTimedWaitFn>(&PTHREAD_COND_TIMEDWAIT_RELATIVE_NP) };
    #[cfg(target_os = "linux")]
    let wait = unsafe { original::<CondTimedWaitFn>(&PTHREAD_COND_TIMEDWAIT) };
    let _watch = cond_watch(mutex);
    let _label = crate::accounting::wait_label_mutex("cond", Some(cond as usize), mutex as usize);
    // SAFETY: the caller's mutex, which the wait returns holding.
    let relock = |lock: bool| unsafe { relock_mutex(mutex, lock) };
    let outcome = domain::timed_native_wait(after, Some(0), Some(&relock), |slice| {
        #[cfg(target_os = "macos")]
        let timeout = to_timespec(slice);
        #[cfg(target_os = "linux")]
        let timeout = to_timespec(crate::real(|| {
            let mut ts = timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let clock = match cond_clock(cond) {
                ClockKind::Monotonic => libc::CLOCK_MONOTONIC,
                _ => libc::CLOCK_REALTIME,
            };
            unsafe { libc::clock_gettime(clock, &mut ts) };
            span(&ts) + slice
        }));
        // SAFETY: the caller's condvar and held mutex, with a relative timeout of `slice`.
        let r = unsafe { wait(cond, mutex, &timeout) };
        (r != libc::ETIMEDOUT).then_some(r)
    });
    domain::note_mutex_taken(mutex as usize);
    match outcome {
        TimedWait::Woken(r) => r,
        TimedWait::TimedOut => libc::ETIMEDOUT,
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> c_int;
}

/// `struct mach_timebase_info` (macOS SDK `<mach/mach_time.h>`): Mach absolute-time ticks convert
/// to nanoseconds as `ticks * numer / denom`
/// ([Apple Technical Q&A QA1398: Mach Absolute Time Units](https://developer.apple.com/library/archive/qa/qa1398/_index.html)).
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Default)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}

// dispatch/time.h: DISPATCH_TIME_NOW is 0 and DISPATCH_TIME_FOREVER is all ones. libdispatch's
// src/shims/time.h encodes the clock in the top two bits: both clear for the default
// (mach_absolute_time) clock, bit 63 alone for continuous time (mach_continuous_time, its
// DISPATCH_CLOCK_MONOTONIC), both set for wall time (stored negated), so every deadline not on
// the default clock has the sign bit set.
#[cfg(target_os = "macos")]
const DISPATCH_TIME_NOW: u64 = 0;
#[cfg(target_os = "macos")]
const DISPATCH_TIME_FOREVER: u64 = !0;

/// `dispatch_time(when, delta)`.
#[cfg(target_os = "macos")]
type DispatchTimeFn = unsafe extern "C" fn(u64, i64) -> u64;

#[cfg(target_os = "macos")]
thread_local! {
    /// The last `dispatch_time(DISPATCH_TIME_NOW, delta)` this thread built, as (deadline, delta).
    /// A timed dispatch wait almost always passes a deadline built this way an instant earlier
    /// (std's parker does), so this recovers the span the caller asked for exactly — reading it
    /// back off the real Mach clock would come up short by however long has passed since, and
    /// leave the caller re-waiting for a remainder that rounds to nothing.
    static LAST_DISPATCH_TIME: std::cell::Cell<(u64, i64)> = const { std::cell::Cell::new((0, 0)) };
}

/// `dispatch_time` (dispatch/time.h): forwarded, remembering a deadline built from
/// `DISPATCH_TIME_NOW` so [`dispatch_semaphore_wait`] can recover its exact span.
#[cfg(target_os = "macos")]
unsafe extern "C" fn dispatch_time(when: u64, delta: i64) -> u64 {
    // SAFETY: DISPATCH_TIME holds libdispatch's dispatch_time.
    let deadline = unsafe { original::<DispatchTimeFn>(&DISPATCH_TIME)(when, delta) };
    if when == DISPATCH_TIME_NOW && domain::virtual_waits() {
        let _ = LAST_DISPATCH_TIME.try_with(|last| last.set((deadline, delta)));
    }
    deadline
}

/// `dispatch_semaphore_wait` (dispatch/semaphore.h): a counting semaphore, so a signal sent
/// between two slices is kept, not lost, and the wait can be sliced safely. Returns zero once
/// signalled and non-zero on timeout (dispatch/semaphore.h), which libdispatch reports as
/// `KERN_OPERATION_TIMED_OUT` (`_DSEMA4_TIMEOUT` in libdispatch src/shims/lock.h). A deadline on
/// the default clock is waited out in the domain's time; one on the wall or continuous clock goes
/// to libdispatch unchanged, only counted.
///
/// A wait on the semaphore the thread already waits on further up its stack is nested in that wait
/// (see `os::nested`): std's thread parker, parked again by sim code run inside the outer park. It
/// waits for real for at most `NESTED_WAIT_SLICE`, or to the caller's own deadline if sooner, and
/// then returns zero, signalled or not. A spoiled outer wait returns zero rather than a timeout,
/// which would send std's `park_timeout` to wait, unbounded, for the signal of an `unpark` it saw
/// arrive (library/std/src/sys/sync/thread_parking/darwin.rs), a signal no spoiled park gets.
#[cfg(target_os = "macos")]
unsafe extern "C" fn dispatch_semaphore_wait(semaphore: *mut libc::c_void, timeout: u64) -> c_long {
    let Some(outer) = nested::begin(semaphore as usize) else {
        // SAFETY: the caller's arguments.
        return unsafe { nested_semaphore_wait(semaphore, timeout) };
    };
    // SAFETY: the caller's arguments.
    let r = unsafe { semaphore_wait(semaphore, timeout) };
    if outer.spoiled() { 0 } else { r }
}

/// The nested `dispatch_semaphore_wait` of [`dispatch_semaphore_wait`].
///
/// # Safety
/// As for `dispatch_semaphore_wait`.
#[cfg(target_os = "macos")]
unsafe fn nested_semaphore_wait(semaphore: *mut libc::c_void, timeout: u64) -> c_long {
    type WaitFn = unsafe extern "C" fn(*mut libc::c_void, u64) -> c_long;
    // SAFETY: DISPATCH_SEMAPHORE_WAIT and DISPATCH_TIME hold libdispatch's functions.
    let (wait, deadline_in) = unsafe {
        (
            original::<WaitFn>(&DISPATCH_SEMAPHORE_WAIT),
            original::<DispatchTimeFn>(&DISPATCH_TIME),
        )
    };
    let span = i64::try_from(nested::NESTED_WAIT_SLICE.as_nanos()).unwrap_or(i64::MAX);
    // SAFETY: dispatch_time only reads the clock.
    let slice = unsafe { deadline_in(DISPATCH_TIME_NOW, span) };
    // A deadline on the default clock compares with `slice` directly; one on another clock has the
    // sign bit set (see DISPATCH_TIME_FOREVER) and is left to the caller's next wait.
    let own = (timeout as i64) >= 0 && timeout <= slice;
    // SAFETY: the caller's semaphore, with a deadline on the default clock.
    let r = unsafe { wait(semaphore, if own { timeout } else { slice }) };
    if own { r } else { 0 }
}

/// The body of [`dispatch_semaphore_wait`] for a wait not nested in another on the same semaphore.
///
/// # Safety
/// As for `dispatch_semaphore_wait`.
#[cfg(target_os = "macos")]
unsafe fn semaphore_wait(semaphore: *mut libc::c_void, timeout: u64) -> c_long {
    // macOS SDK <mach/kern_return.h> KERN_OPERATION_TIMED_OUT: what a timed-out dispatch wait
    // returns.
    const KERN_OPERATION_TIMED_OUT: c_long = 49;
    type WaitFn = unsafe extern "C" fn(*mut libc::c_void, u64) -> c_long;
    // SAFETY: DISPATCH_SEMAPHORE_WAIT and DISPATCH_TIME hold libdispatch's functions.
    let (wait, deadline_in) = unsafe {
        (
            original::<WaitFn>(&DISPATCH_SEMAPHORE_WAIT),
            original::<DispatchTimeFn>(&DISPATCH_TIME),
        )
    };
    if !domain::virtual_waits() || timeout == DISPATCH_TIME_NOW {
        // SAFETY: forwarding the caller's arguments unchanged.
        return unsafe { wait(semaphore, timeout) };
    }
    let _label = crate::accounting::wait_label_on("semaphore", semaphore as usize);
    if timeout == DISPATCH_TIME_FOREVER
        // SAFETY: the caller's semaphore.
        && let Some(r) = unsafe { det_semaphore_wait(semaphore, wait, None) }
    {
        return r;
    }
    if timeout == DISPATCH_TIME_FOREVER || (timeout as i64) < 0 {
        return domain::native_wait_on(crate::DetKey::Addr(semaphore as usize), || {
            if nested::spoiled(semaphore as usize) {
                return 0;
            }
            // SAFETY: forwarding the caller's arguments unchanged.
            unsafe { wait(semaphore, timeout) }
        });
    }
    let after = match LAST_DISPATCH_TIME.try_with(|last| last.get()) {
        Ok((deadline, delta)) if deadline == timeout => Duration::from_nanos(delta.max(0) as u64),
        // A deadline built some other way: read the span back off the Mach clock, rounding up a
        // tick (a snare choice) so the wait overshoots the caller's deadline rather than stopping
        // short of it.
        _ => {
            let mut timebase = MachTimebaseInfo::default();
            // SAFETY: mach_timebase_info fills the struct; dispatch_time only reads the clock.
            let ticks = unsafe {
                mach_timebase_info(&mut timebase);
                timeout.saturating_sub(deadline_in(DISPATCH_TIME_NOW, 0)) + 1
            };
            let nanos =
                u128::from(ticks) * u128::from(timebase.numer) / u128::from(timebase.denom.max(1));
            Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
        }
    };
    // SAFETY: the caller's semaphore.
    if let Some(r) = unsafe { det_semaphore_wait(semaphore, wait, virtual_deadline(after)) } {
        return r;
    }
    let outcome = domain::timed_native_wait(after, None, None, |slice| {
        if nested::spoiled(semaphore as usize) {
            return Some(0);
        }
        let span = i64::try_from(slice.as_nanos()).unwrap_or(i64::MAX);
        // SAFETY: the caller's semaphore, with a deadline `slice` from now on the real clock.
        let r = unsafe { wait(semaphore, deadline_in(DISPATCH_TIME_NOW, span)) };
        (r == 0).then_some(r)
    });
    match outcome {
        TimedWait::Woken(r) => r,
        TimedWait::TimedOut => KERN_OPERATION_TIMED_OUT,
    }
}

/// A semaphore wait under the deterministic schedule: take a signal if one is there, else wait on
/// the semaphore's address until a signal there wakes it or `deadline` passes. `None` when the
/// calling thread is not (or no longer) in the schedule, and waits natively instead.
///
/// # Safety
/// `semaphore` is the caller's; `wait` is libdispatch's `dispatch_semaphore_wait`.
#[cfg(target_os = "macos")]
unsafe fn det_semaphore_wait(
    semaphore: *mut libc::c_void,
    wait: unsafe extern "C" fn(*mut libc::c_void, u64) -> c_long,
    deadline: Option<Duration>,
) -> Option<c_long> {
    // macOS SDK <mach/kern_return.h>, as in `dispatch_semaphore_wait`.
    const KERN_OPERATION_TIMED_OUT: c_long = 49;
    while domain::det_active() {
        let _listed = domain::det_listen(semaphore as usize);
        // SAFETY: a non-blocking take on the caller's semaphore.
        if unsafe { wait(semaphore, DISPATCH_TIME_NOW) } == 0 {
            domain::det_wait_begins(deadline);
            return Some(0);
        }
        let why = domain::det_block(crate::DetKey::Addr(semaphore as usize), deadline);
        if nested::spoiled(semaphore as usize) {
            return Some(0);
        }
        if why == crate::DetWake::TimedOut {
            return Some(KERN_OPERATION_TIMED_OUT);
        }
    }
    None
}

/// `dispatch_semaphore_signal` (dispatch/semaphore.h): increments the semaphore, waking one
/// waiter; forwarded, and under the schedule it also wakes one waiter parked there.
#[cfg(target_os = "macos")]
unsafe extern "C" fn dispatch_semaphore_signal(semaphore: *mut libc::c_void) -> c_long {
    domain::note_hook_effect("dispatch_semaphore_signal");
    domain::note_release(semaphore as usize, 1);
    // SAFETY: DISPATCH_SEMAPHORE_SIGNAL holds libdispatch's function; argument forwarded.
    let r = unsafe {
        original::<unsafe extern "C" fn(*mut libc::c_void) -> c_long>(&DISPATCH_SEMAPHORE_SIGNAL)(
            semaphore,
        )
    };
    if domain::det_wake_addr(semaphore as usize, 1) > 0 {
        return 1;
    }
    r
}

/// `sched_yield` (man 2 sched_yield): a spinner's way of waiting. Under the schedule it hands the
/// other runnable threads a turn; otherwise, once the yields make a caught spin and every other
/// participant is parked, it offers the domain a time skip. The real yield follows either way.
unsafe extern "C" fn sched_yield() -> c_int {
    domain::yield_point();
    // SAFETY: SCHED_YIELD holds libc's sched_yield.
    unsafe { original::<unsafe extern "C" fn() -> c_int>(&SCHED_YIELD)() }
}

/// The Linux futex wait and wake, reached through libc's `syscall` (std and parking_lot issue them
/// there). Returns `None` for every other futex operation, and whenever there is nothing to model
/// (off a managed thread, no virtual waits, a wake with no deterministic waiter to reach), so the
/// caller forwards it untouched; `real` performs one raw `syscall(SYS_futex, …)` with the given
/// arguments. A wake is always noted as a release first.
///
/// `args` are `uaddr, futex_op, val, timeout, uaddr2, val3` (man 2 futex). The operation is
/// `futex_op` without its option bits `FUTEX_PRIVATE_FLAG` and `FUTEX_CLOCK_REALTIME`
/// (`include/uapi/linux/futex.h`). A wake's `val` is an `int` count of waiters to wake, usually 1
/// or `INT_MAX` (man 2const FUTEX_WAKE); it returns how many it woke. A result of -1 leaves errno
/// as the kernel set it, the `syscall(2)` wrapper's convention.
///
/// A wait on the word the thread already waits on further up its stack is nested in that wait (see
/// `os::nested`): std's thread parker, parked again by sim code run inside the outer park. It waits
/// for real for at most `NESTED_WAIT_SLICE` for the word to change from what it holds now, which no
/// longer matches what the caller expects, and then returns 0. An outer wait a nested one spoiled,
/// or whose std parker a nested park took the notification of, returns 0 with that notification
/// put back ([`nested::settle_parker`]).
///
/// # Safety
/// `args` are the caller's futex arguments, as `syscall(SYS_futex, …)` would receive them.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn futex(
    args: [usize; 6],
    real: impl Fn([usize; 6]) -> c_long,
) -> Option<c_long> {
    let [word, op, value, ..] = args;
    let command = op as c_int & !(libc::FUTEX_PRIVATE_FLAG | libc::FUTEX_CLOCK_REALTIME);
    if command != libc::FUTEX_WAIT && command != libc::FUTEX_WAIT_BITSET {
        // SAFETY: as for this function.
        return unsafe { futex_call(args, real) };
    }
    if !domain::virtual_waits() && !nested::waiting(word) {
        return None;
    }
    let mut timeout = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if (command == libc::FUTEX_WAIT_BITSET && args[5] as u32 == 0)
        || (command == libc::FUTEX_WAIT && op as c_int & libc::FUTEX_CLOCK_REALTIME != 0)
        || (args[3] != 0
            && (!unsafe { read_futex_argument(args[3], &mut timeout) }
                || timeout.tv_sec < 0
                || !(0..1_000_000_000).contains(&timeout.tv_nsec)))
    {
        return Some(real(args));
    }
    let _mask = crate::accounting::wait_mask(
        if command == libc::FUTEX_WAIT_BITSET {
            args[5] as u32
        } else {
            u32::MAX
        },
        value as u32,
        op as c_int & libc::FUTEX_PRIVATE_FLAG != 0,
    );
    if word == 0 || !word.is_multiple_of(std::mem::align_of::<u32>()) {
        return Some(real(args));
    }
    if futex_word(word).is_none() {
        return Some(real(args));
    }
    let Some(outer) = nested::begin(word) else {
        return Some(nested_futex_wait(args, &real));
    };
    let before = unsafe { nested::load(word, 4) };
    // SAFETY: as for this function.
    let r = unsafe { futex_call(args, |args| if outer.spoiled() { 0 } else { real(args) }) };
    if !unsafe { nested::settle_parker(&outer, word, 4, u64::from(value as u32), before) } {
        return r;
    }
    Some(0)
}

#[cfg(target_os = "linux")]
unsafe fn read_futex_argument<T: Copy>(address: usize, output: &mut T) -> bool {
    let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let size = std::mem::size_of::<T>();
    let local = libc::iovec {
        iov_base: std::ptr::from_mut(output).cast(),
        iov_len: size,
    };
    let remote = libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: size,
    };
    let result = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
    let copied = result == size as isize
        || (result == -1
            && matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM | libc::EACCES | libc::ENOSYS)
            )
            && unsafe { read_process_memory(address, output) });
    unsafe { *libc::__errno_location() = error };
    copied
}

#[cfg(target_os = "linux")]
unsafe fn read_process_memory<T: Copy>(address: usize, output: &mut T) -> bool {
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::FileExt;

    let _passthrough = crate::state::Passthrough::enter();
    let Some(end) = address.checked_add(std::mem::size_of::<T>()) else {
        return false;
    };
    let Ok(maps) = std::fs::File::open("/proc/self/maps") else {
        return false;
    };
    let mut maps = BufReader::new(maps);
    let mut line = Vec::new();
    let mut covered = address;
    while covered < end {
        line.clear();
        if !matches!(maps.read_until(b'\n', &mut line), Ok(1..)) {
            return false;
        }
        let mut fields = line.split(|byte| byte.is_ascii_whitespace());
        let (Some(range), Some(permissions)) = (fields.next(), fields.next()) else {
            return false;
        };
        let Some((start, stop)) = std::str::from_utf8(range)
            .ok()
            .and_then(|range| range.split_once('-'))
            .and_then(|(start, stop)| {
                Some((
                    usize::from_str_radix(start, 16).ok()?,
                    usize::from_str_radix(stop, 16).ok()?,
                ))
            })
        else {
            return false;
        };
        if stop <= covered {
            continue;
        }
        // /proc/self/mem can force reads through a mapping's current protections.
        if start > covered || permissions.first() != Some(&b'r') {
            return false;
        }
        covered = stop.min(end);
    }
    drop(maps);
    let Ok(memory) = std::fs::File::open("/proc/self/mem") else {
        return false;
    };
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            std::ptr::from_mut(output).cast::<u8>(),
            std::mem::size_of::<T>(),
        )
    };
    memory.read_at(bytes, address as u64).ok() == Some(bytes.len())
}

#[cfg(target_os = "linux")]
fn futex_word(address: usize) -> Option<u32> {
    let mut word = 0;
    unsafe { read_futex_argument(address, &mut word) }.then_some(word)
}

#[cfg(target_os = "linux")]
fn shared_futex_preflight(
    args: [usize; 6],
    real: &impl Fn([usize; 6]) -> c_long,
) -> Option<(c_long, c_int)> {
    let saved_error = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let [word, operation, value, _, word2, bitset] = args;
    let operation = operation as c_int;
    let command = operation & !(libc::FUTEX_PRIVATE_FLAG | libc::FUTEX_CLOCK_REALTIME);
    let mask = if command == libc::FUTEX_WAIT_BITSET {
        bitset
    } else {
        MATCH_ANY
    };
    let deadline = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let operation = (libc::FUTEX_WAIT_BITSET | (operation & libc::FUTEX_CLOCK_REALTIME)) as usize;
    let result = real([
        word,
        operation,
        value,
        &deadline as *const timespec as usize,
        word2,
        mask,
    ]);
    let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    unsafe { *libc::__errno_location() = saved_error };
    (result != -1 || error != libc::ETIMEDOUT).then_some((result, error))
}

/// The nested futex wait of [`futex`]: one real `FUTEX_WAIT_BITSET` on the word's current value,
/// until `NESTED_WAIT_SLICE` from now on `CLOCK_MONOTONIC` (man 2 futex).
#[cfg(target_os = "linux")]
fn nested_futex_wait(args: [usize; 6], real: &impl Fn([usize; 6]) -> c_long) -> c_long {
    let [word, op, ..] = args;
    // SAFETY: the caller's futex word, read atomically as the kernel would.
    let current = unsafe {
        (*(word as *const std::sync::atomic::AtomicU32)).load(std::sync::atomic::Ordering::SeqCst)
    };
    let deadline = to_timespec(crate::real(real_monotonic) + nested::NESTED_WAIT_SLICE);
    let attempt_op = ((op as c_int & libc::FUTEX_PRIVATE_FLAG) | libc::FUTEX_WAIT_BITSET) as usize;
    let deadline_ptr = &deadline as *const timespec as usize;
    real([
        word,
        attempt_op,
        current as usize,
        deadline_ptr,
        0,
        MATCH_ANY,
    ]);
    0
}

/// The body of [`futex`] for every operation but a nested wait.
///
/// # Safety
/// As for [`futex`].
#[cfg(target_os = "linux")]
unsafe fn futex_call(args: [usize; 6], real: impl Fn([usize; 6]) -> c_long) -> Option<c_long> {
    let [word, op, value, timeout, word2, bitset] = args;
    let op = op as c_int;
    let command = op & !(libc::FUTEX_PRIVATE_FLAG | libc::FUTEX_CLOCK_REALTIME);
    if command == libc::FUTEX_WAKE || command == libc::FUTEX_WAKE_BITSET {
        if op & libc::FUTEX_CLOCK_REALTIME != 0
            || (command == libc::FUTEX_WAKE_BITSET && bitset as u32 == 0)
            || !word.is_multiple_of(std::mem::align_of::<u32>())
        {
            return Some(real(args));
        }
        let mask = if command == libc::FUTEX_WAKE_BITSET {
            bitset as u32
        } else {
            u32::MAX
        };
        domain::note_hook_effect("FUTEX_WAKE");
        let n = (value as c_int).max(1) as usize;
        if !deterministic() {
            let native = domain::release_native_futex(
                word,
                n,
                mask,
                op & libc::FUTEX_PRIVATE_FLAG != 0,
                || {
                    let result = real(args);
                    if result >= 0 {
                        note_wait_signal_masked(
                            word,
                            mask,
                            Some(op & libc::FUTEX_PRIVATE_FLAG != 0),
                        );
                    }
                    result
                },
                || futex_word(word),
            );
            if native < 0 {
                return Some(native);
            }
            let woken =
                domain::det_wake_futex_addr(word, n, mask, op & libc::FUTEX_PRIVATE_FLAG != 0)
                    as c_long;
            return Some(native + woken);
        }
    }
    let mut timeout_value = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if domain::virtual_waits()
        && (command == libc::FUTEX_WAIT || command == libc::FUTEX_WAIT_BITSET)
        && ((command == libc::FUTEX_WAIT_BITSET && bitset as u32 == 0)
            || (command == libc::FUTEX_WAIT && op & libc::FUTEX_CLOCK_REALTIME != 0)
            || (timeout != 0
                && (!unsafe { read_futex_argument(timeout, &mut timeout_value) }
                    || timeout_value.tv_sec < 0
                    || !(0..1_000_000_000).contains(&timeout_value.tv_nsec))))
    {
        return Some(real(args));
    }
    if domain::virtual_waits()
        && (command == libc::FUTEX_WAIT || command == libc::FUTEX_WAIT_BITSET)
        && op & libc::FUTEX_PRIVATE_FLAG == 0
        && let Some((result, error)) = shared_futex_preflight(args, &real)
    {
        unsafe { *libc::__errno_location() = error };
        return Some(result);
    }
    if deterministic() {
        // SAFETY: as for this function.
        return unsafe { det_futex(op, command, word, value, timeout, &real, args) };
    }
    if !domain::virtual_waits()
        || (command != libc::FUTEX_WAIT && command != libc::FUTEX_WAIT_BITSET)
    {
        return None;
    }
    let _label = crate::accounting::wait_label_on("futex", word);
    let errno = || std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let preflight = || {
        if op & libc::FUTEX_PRIVATE_FLAG == 0 {
            return shared_futex_preflight(args, &real).map(Some);
        }
        match futex_word(word) {
            Some(current) if current != value as u32 => Some(Some((-1, libc::EAGAIN))),
            Some(_) => None,
            None => Some(None),
        }
    };
    if timeout == 0 {
        if domain::counts_native_waits()
            && (domain::in_static_image(word) || domain::backing_off())
            && let Some(r) = outside_grace(OUTSIDE_HOLDER_GRACE, op, command, args, &real)
        {
            return Some(r);
        }
        let result = domain::native_wait_at_checked(
            None,
            preflight,
            || {
                let result = real(args);
                let error = errno();
                if result == -1 && error == libc::EAGAIN {
                    domain::note_futex_pre_enrollment_return();
                }
                Some((result, error))
            },
            |result| result.is_some_and(|(result, _)| result == 0),
        );
        let Some((result, error)) = result else {
            return Some(real(args));
        };
        unsafe { *libc::__errno_location() = error };
        return Some(result);
    }
    let given = span(&timeout_value);
    // FUTEX_WAIT's timeout is relative (man 2const FUTEX_WAIT); FUTEX_WAIT_BITSET's is absolute
    // (man 2const FUTEX_WAIT_BITSET), on CLOCK_MONOTONIC or, with FUTEX_CLOCK_REALTIME,
    // CLOCK_REALTIME (man 2 futex) — the virtual clock the caller read, under a clock layer.
    let after = if command == libc::FUTEX_WAIT {
        given
    } else {
        let clock = if op & libc::FUTEX_CLOCK_REALTIME != 0 {
            crate::layer::ClockKind::Realtime
        } else {
            crate::layer::ClockKind::Monotonic
        };
        match domain::now(clock) {
            Some(now) => given.saturating_sub(now),
            // No clock layer: the deadline is already on the kernel's clock.
            None => return Some(domain::native_wait(|| real(args))),
        }
    };
    // Each attempt waits on the caller's word, value and bitset until a real-clock deadline, so a
    // wake landing between attempts is never lost: the kernel re-checks the word every time.
    let attempt_op = ((op & libc::FUTEX_PRIVATE_FLAG) | libc::FUTEX_WAIT_BITSET) as usize;
    let bitset = if command == libc::FUTEX_WAIT_BITSET {
        bitset
    } else {
        MATCH_ANY
    };
    let outcome = domain::timed_native_wait_checked(
        after,
        preflight,
        |slice| {
            let deadline = to_timespec(crate::real(real_monotonic) + slice);
            let deadline_ptr = &deadline as *const timespec as usize;
            let r = real([word, attempt_op, value, deadline_ptr, word2, bitset]);
            let e = errno();
            if r == -1 && e == libc::EAGAIN {
                domain::note_futex_pre_enrollment_return();
            }
            (r != -1 || e != libc::ETIMEDOUT).then_some(Some((r, e)))
        },
        |result| result.is_some_and(|(result, _)| result == 0),
    );
    let (r, e) = match outcome {
        TimedWait::Woken(Some(woken)) => woken,
        TimedWait::Woken(None) => return Some(real(args)),
        TimedWait::TimedOut => (-1, libc::ETIMEDOUT),
    };
    // SAFETY: errno is this thread's; restore what the futex call reported.
    unsafe { *libc::__errno_location() = e };
    Some(r)
}

/// The kernel's `CLOCK_MONOTONIC`, the clock a `FUTEX_WAIT_BITSET` deadline without
/// `FUTEX_CLOCK_REALTIME` is measured on (man 2 futex).
#[cfg(target_os = "linux")]
fn real_monotonic() -> Duration {
    let mut ts = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime fills `ts`; under passthrough this is the kernel's monotonic clock.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    span(&ts)
}

/// `FUTEX_BITSET_MATCH_ANY`, all 32 bits set (`include/uapi/linux/futex.h`; man 2const
/// FUTEX_WAIT_BITSET): a `FUTEX_WAIT_BITSET` with this mask is `FUTEX_WAIT` with an absolute timeout.
#[cfg(target_os = "linux")]
const MATCH_ANY: usize = 0xffff_ffff;

/// How long a wait on a futex word or semaphore in static data, or one a lock's back-off spin leads
/// into, first waits in real time, for a holder or poster outside the simulation, before it counts
/// as a wait in the domain: keeping the baton under a deterministic schedule, or counted running
/// otherwise. A snare choice: long enough for an outside holder in a short critical section to let
/// go, short enough not to slow a run that waits on an inside one.
const OUTSIDE_HOLDER_GRACE: Duration = Duration::from_millis(1);

/// [`OUTSIDE_HOLDER_GRACE`] for a wait under a deterministic schedule, which keeps the baton
/// meanwhile. Once a wait passes the baton on, which thread runs next depends on how long the outside
/// holder took, so the run no longer replays; std's thread-start lock, which another test's spawning
/// threads hold, stays held for a few milliseconds on a loaded machine. A snare choice: long enough
/// to outlast such a holder, at the cost of that much real time per wait on a word a parked thread
/// of the domain holds.
const DET_OUTSIDE_HOLDER_GRACE: Duration = Duration::from_millis(50);

/// The first [`OUTSIDE_HOLDER_GRACE`] of a futex wait on a word in static data, which may be a lock
/// shared with threads outside the simulation (std's own statics: the stack-overflow handler's
/// thread-info lock every thread start and exit takes, stdout's lock), or of one a lock's back-off
/// spin leads into (see [`domain::backing_off`]), as a real wait the domain does not count. A futex
/// word carries no owner, so whether a thread of the domain holds it cannot be told; a holder
/// outside lets go in that time, and a holder inside merely delays the wait's counting by it.
/// Returns the futex call's result, with errno as the kernel left it, when it ended other than by
/// timing out (woken, or the word no longer held `value`); `None` once the grace ran out.
///
/// `args` are as for [`futex`]: the wait uses the caller's word, value and, for
/// `FUTEX_WAIT_BITSET`, bitset, with an absolute deadline on `CLOCK_MONOTONIC` (man 2 futex).
#[cfg(target_os = "linux")]
fn outside_grace(
    grace: Duration,
    op: c_int,
    command: c_int,
    args: [usize; 6],
    real: &impl Fn([usize; 6]) -> c_long,
) -> Option<c_long> {
    let [word, _, value, _, word2, bitset] = args;
    let deadline = to_timespec(crate::real(real_monotonic) + grace);
    let attempt_op = ((op & libc::FUTEX_PRIVATE_FLAG) | libc::FUTEX_WAIT_BITSET) as usize;
    let bits = if command == libc::FUTEX_WAIT_BITSET {
        bitset
    } else {
        MATCH_ANY
    };
    let deadline_ptr = &deadline as *const timespec as usize;
    let r = real([word, attempt_op, value, deadline_ptr, word2, bits]);
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if r == -1 && e == libc::ETIMEDOUT {
        return None;
    }
    // SAFETY: errno is this thread's; restore what the futex call reported.
    unsafe { *libc::__errno_location() = e };
    Some(r)
}

/// A futex wait or wake under the deterministic schedule (man 2 futex): a wait whose word still
/// holds the expected value parks on the word's address in the schedule, and a wake moves that
/// many of its waiters to the run queue (and wakes any real waiter outside the sim too). Other
/// operations go to the kernel.
///
/// As the kernel does, a wait whose word no longer holds `value` fails at once with `EAGAIN`, and
/// one that times out fails with `ETIMEDOUT` (man 2const FUTEX_WAIT). A wake returns the waiters
/// woken in the schedule plus those the real call woke.
///
/// # Safety
/// As for [`futex`].
#[cfg(target_os = "linux")]
unsafe fn det_futex(
    op: c_int,
    command: c_int,
    word: usize,
    value: usize,
    timeout: usize,
    real: &impl Fn([usize; 6]) -> c_long,
    args: [usize; 6],
) -> Option<c_long> {
    let set_errno = |e: c_int| {
        // SAFETY: errno is this thread's.
        unsafe { *libc::__errno_location() = e };
    };
    match command {
        libc::FUTEX_WAIT | libc::FUTEX_WAIT_BITSET => {
            let timeout = timeout as *const timespec;
            let deadline = if timeout.is_null() {
                None
            } else {
                // SAFETY: a non-null futex timeout points at the caller's timespec.
                let given = span(unsafe { &*timeout });
                if command == libc::FUTEX_WAIT {
                    virtual_deadline(given)
                } else {
                    // FUTEX_WAIT_BITSET: an absolute time on the clock the caller read.
                    let clock = if op & libc::FUTEX_CLOCK_REALTIME != 0 {
                        crate::layer::ClockKind::Realtime
                    } else {
                        crate::layer::ClockKind::Monotonic
                    };
                    let now = domain::now(clock).unwrap_or_default();
                    virtual_deadline(given.saturating_sub(now))
                }
            };
            domain::det_wait_begins(deadline);
            // SAFETY: the caller's futex word, read atomically as the kernel would.
            let current = unsafe {
                (*(word as *const std::sync::atomic::AtomicU32))
                    .load(std::sync::atomic::Ordering::SeqCst)
            };
            if current != value as u32 {
                set_errno(libc::EAGAIN);
                return Some(-1);
            }
            // A holder inside the simulation is parked while this thread keeps the baton and
            // cannot release the word meanwhile, so whether this wait yields never depends on
            // outside timing.
            if (domain::in_static_image(word) || domain::backing_off())
                && let Some(r) = outside_grace(DET_OUTSIDE_HOLDER_GRACE, op, command, args, real)
            {
                return Some(r);
            }
            let _label = crate::wait_label("futex");
            let signal = track_signal_masked(
                word,
                crate::accounting::wait_mask_value(),
                crate::accounting::wait_futex_private(),
            );
            let signal_previous = WAIT_SIGNAL_VERSION.with(|cell| {
                cell.replace(Some((
                    word,
                    signal.load(std::sync::atomic::Ordering::Acquire),
                )))
            });
            let previous = FUTEX_WAIT_VALUE.with(|cell| cell.replace(Some((word, value as u32))));
            let result = match domain::det_block(crate::DetKey::Addr(word), deadline) {
                crate::DetWake::TimedOut => {
                    set_errno(libc::ETIMEDOUT);
                    Some(-1)
                }
                _ => Some(0),
            };
            FUTEX_WAIT_VALUE.with(|cell| cell.set(previous));
            WAIT_SIGNAL_VERSION.with(|cell| cell.set(signal_previous));
            result
        }
        libc::FUTEX_WAKE | libc::FUTEX_WAKE_BITSET => {
            let n = (value as c_int).max(1) as usize;
            domain::place_woken(word, n);
            let outside = real(args);
            if outside < 0 {
                return Some(outside);
            }
            let mask = if command == libc::FUTEX_WAKE_BITSET {
                args[5] as u32
            } else {
                u32::MAX
            };
            note_wait_signal_masked(word, mask, Some(op & libc::FUTEX_PRIVATE_FLAG != 0));
            domain::note_futex_release(
                word,
                n,
                mask,
                op & libc::FUTEX_PRIVATE_FLAG != 0,
                || futex_word(word),
            );
            let woken =
                domain::det_wake_futex_addr(word, n, mask, op & libc::FUTEX_PRIVATE_FLAG != 0);
            Some(woken as c_long + outside)
        }
        _ => None,
    }
}

/// `sem_wait`, `sem_trywait` and `sem_post`.
type SemFn = unsafe extern "C" fn(*mut libc::sem_t) -> c_int;

/// The calling thread's errno.
fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Fails a semaphore call the POSIX way: errno set to `e`, -1 returned (man 3 sem_wait).
fn fail(e: c_int) -> c_int {
    // SAFETY: setting the calling thread's errno.
    unsafe { crate::os::sockets::set_errno(e) };
    -1
}

/// One round of a semaphore wait under the deterministic schedule: take a post if one is there,
/// else wait in the schedule on the semaphore's address until a post there or `deadline`.
/// `Some` is the wait's result; `None` means look again.
///
/// # Safety
/// `sem` is the caller's semaphore.
unsafe fn det_sem_round(sem: *mut libc::sem_t, deadline: Option<Duration>) -> Option<c_int> {
    let _listed = domain::det_listen(sem as usize);
    // SAFETY: SEM_TRYWAIT holds libc's sem_trywait; the caller's semaphore.
    if unsafe { original::<SemFn>(&SEM_TRYWAIT)(sem) } == 0 {
        domain::det_wait_begins(deadline);
        return Some(0);
    }
    #[cfg(target_os = "linux")]
    if domain::in_static_image(sem as usize) {
        // A semaphore in static data may be posted from outside the simulation (a real signal
        // handler): give that a moment in real time, keeping the baton, before waiting in the
        // schedule, so whether this wait yields never depends on outside timing.
        let until = to_timespec(crate::real(real_realtime) + OUTSIDE_HOLDER_GRACE);
        // SAFETY: SEM_TIMEDWAIT holds libc's sem_timedwait; the caller's semaphore.
        if unsafe { original::<SemTimedFn>(&SEM_TIMEDWAIT)(sem, &until) } == 0 {
            domain::det_wait_begins(deadline);
            return Some(0);
        }
    }
    match domain::det_block(crate::DetKey::Addr(sem as usize), deadline) {
        crate::DetWake::TimedOut => Some(fail(libc::ETIMEDOUT)),
        _ => None,
    }
}

/// `sem_wait`: decrements the semaphore, blocking while it is zero (man 3 sem_wait).
unsafe extern "C" fn sem_wait(sem: *mut libc::sem_t) -> c_int {
    // SAFETY: SEM_WAIT holds libc's sem_wait.
    let wait = unsafe { original::<SemFn>(&SEM_WAIT) };
    if !domain::virtual_waits() {
        // SAFETY: forwarding the caller's argument unchanged.
        return unsafe { wait(sem) };
    }
    let _label = crate::accounting::wait_label_on("semaphore", sem as usize);
    while deterministic() {
        // SAFETY: the caller's semaphore.
        if let Some(r) = unsafe { det_sem_round(sem, None) } {
            return r;
        }
    }
    // SAFETY: forwarding the caller's argument unchanged.
    domain::native_wait_on(crate::DetKey::Addr(sem as usize), || unsafe { wait(sem) })
}

/// `sem_trywait`: fails with `EAGAIN` when the semaphore is zero (man 3 sem_wait). A caller
/// looping on it is busy-polling, so each such failure charges the per-call latency that lets a
/// discrete virtual clock move under a spinner.
unsafe extern "C" fn sem_trywait(sem: *mut libc::sem_t) -> c_int {
    // SAFETY: SEM_TRYWAIT holds libc's sem_trywait; argument forwarded unchanged.
    let r = unsafe { original::<SemFn>(&SEM_TRYWAIT)(sem) };
    if r == -1 && domain::counts_native_waits() {
        let e = errno();
        if e == libc::EAGAIN {
            domain::charge_latency();
        }
        return fail(e);
    }
    r
}

/// `sem_post`: increments the semaphore, waking one waiter if any (man 3 sem_post). The wake in
/// the schedule must not disturb the errno the real call left.
unsafe extern "C" fn sem_post(sem: *mut libc::sem_t) -> c_int {
    domain::note_hook_effect("sem_post");
    domain::note_release(sem as usize, 1);
    // SAFETY: SEM_POST holds libc's sem_post; argument forwarded unchanged.
    let r = unsafe { original::<SemFn>(&SEM_POST)(sem) };
    if r == 0 {
        let e = errno();
        domain::det_wake_addr(sem as usize, 1);
        // SAFETY: setting the calling thread's errno back.
        unsafe { crate::os::sockets::set_errno(e) };
    }
    r
}

/// `sem_timedwait`.
#[cfg(target_os = "linux")]
type SemTimedFn = unsafe extern "C" fn(*mut libc::sem_t, *const timespec) -> c_int;

/// The kernel's `CLOCK_REALTIME`, the clock a `sem_timedwait` deadline is on: an absolute time
/// "since the Epoch" (man 3 sem_wait).
#[cfg(target_os = "linux")]
fn real_realtime() -> Duration {
    let mut ts = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime fills `ts`; under passthrough this is the kernel's realtime clock.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    span(&ts)
}

/// A semaphore wait until `deadline` on the clock `kind` reads, in the domain's time: the
/// deterministic schedule's, or real waits sliced against the virtual clock. `None` when the domain
/// has no virtual reading of `kind`, so the caller makes the real call with the caller's deadline.
///
/// # Safety
/// `sem` is the caller's semaphore; `real` is one real wait on it until an absolute
/// `CLOCK_REALTIME` time.
#[cfg(target_os = "linux")]
unsafe fn sem_wait_until(
    sem: *mut libc::sem_t,
    kind: crate::layer::ClockKind,
    deadline: Duration,
    real: impl Fn(&timespec) -> c_int,
) -> Option<c_int> {
    let now = domain::now(kind)?;
    let after = deadline.saturating_sub(now);
    let _label = crate::accounting::wait_label_on("semaphore", sem as usize);
    while deterministic() {
        // SAFETY: the caller's semaphore.
        if let Some(r) = unsafe { det_sem_round(sem, virtual_deadline(after)) } {
            return Some(r);
        }
    }
    let outcome = domain::timed_native_wait(after, None, None, |slice| {
        let until = to_timespec(crate::real(real_realtime) + slice);
        let r = real(&until);
        let e = errno();
        (r == 0 || e != libc::ETIMEDOUT).then_some((r, e))
    });
    Some(match outcome {
        TimedWait::Woken((0, _)) => 0,
        TimedWait::Woken((_, e)) => fail(e),
        TimedWait::TimedOut => fail(libc::ETIMEDOUT),
    })
}

/// A `timespec` this hook can model, as a span. glibc rejects a `tv_nsec` outside
/// `0..1_000_000_000` with `EINVAL` before even trying the semaphore (glibc nptl/sem_clockwait.c,
/// `valid_nanoseconds`; man 3 sem_wait), and a negative `tv_sec` is a deadline already past, so
/// anything this refuses goes to libc to report or time out.
#[cfg(target_os = "linux")]
fn valid(ts: *const timespec) -> Option<Duration> {
    // SAFETY: a non-null timespec is the caller's.
    let ts = unsafe { ts.as_ref() }?;
    (ts.tv_sec >= 0 && (0..1_000_000_000).contains(&ts.tv_nsec)).then(|| span(ts))
}

/// `sem_timedwait`: as `sem_wait`, failing with `ETIMEDOUT` once `abs_timeout`, an absolute
/// `CLOCK_REALTIME` time, passes (man 3 sem_wait).
#[cfg(target_os = "linux")]
unsafe extern "C" fn sem_timedwait(sem: *mut libc::sem_t, abs_timeout: *const timespec) -> c_int {
    // SAFETY: SEM_TIMEDWAIT holds libc's sem_timedwait.
    let timed = unsafe { original::<SemTimedFn>(&SEM_TIMEDWAIT) };
    if domain::virtual_waits()
        && let Some(deadline) = valid(abs_timeout)
        // SAFETY: the caller's semaphore, waited on with real realtime deadlines.
        && let Some(r) = unsafe {
            sem_wait_until(sem, crate::layer::ClockKind::Realtime, deadline, |until| {
                timed(sem, until)
            })
        }
    {
        return r;
    }
    // SAFETY: forwarding the caller's arguments unchanged.
    domain::native_wait(|| unsafe { timed(sem, abs_timeout) })
}

/// `sem_clockwait`: as `sem_timedwait`, with the deadline on `clock`, `CLOCK_MONOTONIC` or
/// `CLOCK_REALTIME` (glibc 2.30 NEWS; POSIX.1-2024 sem_clockwait). Other clocks go to libc, which
/// rejects them with `EINVAL` (glibc nptl/sem_clockwait.c, `futex_abstimed_supported_clockid`).
#[cfg(target_os = "linux")]
unsafe extern "C" fn sem_clockwait(
    sem: *mut libc::sem_t,
    clock: libc::clockid_t,
    abs_timeout: *const timespec,
) -> c_int {
    type ClockWaitFn =
        unsafe extern "C" fn(*mut libc::sem_t, libc::clockid_t, *const timespec) -> c_int;
    // SAFETY: SEM_CLOCKWAIT holds libc's sem_clockwait; SEM_TIMEDWAIT its sem_timedwait.
    let (clockwait, timed) = unsafe {
        (
            original::<ClockWaitFn>(&SEM_CLOCKWAIT),
            original::<SemTimedFn>(&SEM_TIMEDWAIT),
        )
    };
    let kind = match clock {
        libc::CLOCK_MONOTONIC => Some(crate::layer::ClockKind::Monotonic),
        libc::CLOCK_REALTIME => Some(crate::layer::ClockKind::Realtime),
        _ => None,
    };
    if domain::virtual_waits()
        && let (Some(kind), Some(deadline)) = (kind, valid(abs_timeout))
        // SAFETY: the caller's semaphore, waited on with real realtime deadlines.
        && let Some(r) = unsafe { sem_wait_until(sem, kind, deadline, |until| timed(sem, until)) }
    {
        return r;
    }
    // SAFETY: forwarding the caller's arguments unchanged.
    domain::native_wait(|| unsafe { clockwait(sem, clock, abs_timeout) })
}
