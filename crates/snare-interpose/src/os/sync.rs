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

use std::ffi::{c_int, c_long};
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use libc::{pthread_cond_t, pthread_mutex_t, timespec};

use crate::domain::{self, TimedWait};
use crate::hooks::{Hook, hook, original};
#[cfg(target_os = "macos")]
use crate::layer::ClockKind;

static PTHREAD_MUTEX_LOCK: AtomicUsize = AtomicUsize::new(0);
static PTHREAD_COND_WAIT: AtomicUsize = AtomicUsize::new(0);
static PTHREAD_COND_TIMEDWAIT: AtomicUsize = AtomicUsize::new(0);
static SCHED_YIELD: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "macos")]
static PTHREAD_COND_TIMEDWAIT_RELATIVE_NP: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "macos")]
static DISPATCH_SEMAPHORE_WAIT: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "macos")]
static DISPATCH_TIME: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn hooks() -> Vec<Hook> {
    vec![
        hook!("pthread_mutex_lock", pthread_mutex_lock, PTHREAD_MUTEX_LOCK),
        hook!("pthread_cond_wait", pthread_cond_wait, PTHREAD_COND_WAIT),
        hook!(
            "pthread_cond_timedwait",
            pthread_cond_timedwait,
            PTHREAD_COND_TIMEDWAIT
        ),
        hook!("sched_yield", sched_yield, SCHED_YIELD),
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
    ]
}

fn span(ts: &timespec) -> Duration {
    Duration::new(
        ts.tv_sec.max(0) as u64,
        ts.tv_nsec.clamp(0, 999_999_999) as u32,
    )
}

fn to_timespec(d: Duration) -> timespec {
    timespec {
        tv_sec: d.as_secs() as libc::time_t,
        tv_nsec: d.subsec_nanos() as _,
    }
}

type MutexFn = unsafe extern "C" fn(*mut pthread_mutex_t) -> c_int;
type CondWaitFn = unsafe extern "C" fn(*mut pthread_cond_t, *mut pthread_mutex_t) -> c_int;
type CondTimedWaitFn =
    unsafe extern "C" fn(*mut pthread_cond_t, *mut pthread_mutex_t, *const timespec) -> c_int;

unsafe extern "C" fn pthread_mutex_lock(mutex: *mut pthread_mutex_t) -> c_int {
    // SAFETY: PTHREAD_MUTEX_LOCK holds libc's pthread_mutex_lock.
    let lock = unsafe { original::<MutexFn>(&PTHREAD_MUTEX_LOCK) };
    if !domain::counts_native_waits() {
        // SAFETY: forwarding the caller's argument unchanged.
        return unsafe { lock(mutex) };
    }
    // Only a contended lock blocks. Counting every lock would show a running thread as parked for
    // a moment, long enough for a peer to mistake the domain for deadlocked. man 3
    // pthread_mutex_trylock: EBUSY means another thread holds it.
    // SAFETY: the caller's mutex, as pthread_mutex_lock would receive it.
    match unsafe { libc::pthread_mutex_trylock(mutex) } {
        0 => 0,
        // SAFETY: forwarding the caller's argument unchanged.
        libc::EBUSY => domain::native_wait(|| unsafe { lock(mutex) }),
        // SAFETY: as above; let the real call report whatever trylock objected to.
        _ => unsafe { lock(mutex) },
    }
}

unsafe extern "C" fn pthread_cond_wait(
    cond: *mut pthread_cond_t,
    mutex: *mut pthread_mutex_t,
) -> c_int {
    // SAFETY: PTHREAD_COND_WAIT holds libc's pthread_cond_wait.
    let wait = unsafe { original::<CondWaitFn>(&PTHREAD_COND_WAIT) };
    // SAFETY: forwarding the caller's arguments unchanged.
    domain::native_wait(|| unsafe { wait(cond, mutex) })
}

unsafe extern "C" fn pthread_cond_timedwait(
    cond: *mut pthread_cond_t,
    mutex: *mut pthread_mutex_t,
    deadline: *const timespec,
) -> c_int {
    // SAFETY: PTHREAD_COND_TIMEDWAIT holds libc's pthread_cond_timedwait.
    let wait = unsafe { original::<CondTimedWaitFn>(&PTHREAD_COND_TIMEDWAIT) };
    #[cfg(target_os = "macos")]
    if !deadline.is_null()
        && domain::counts_native_waits()
        && let Some(now) = domain::now(ClockKind::Realtime)
    {
        // macOS has no pthread_condattr_setclock, so the deadline is always on CLOCK_REALTIME —
        // here the virtual one the caller read. Wait out the remainder in the domain's time.
        // SAFETY: a non-null deadline points at the caller's timespec.
        let after = span(unsafe { &*deadline }).saturating_sub(now);
        // SAFETY: the caller's condition variable and the mutex it holds.
        return unsafe { cond_wait_for(cond, mutex, after) };
    }
    // Elsewhere the deadline's clock is whatever the condvar was created with, which this hook
    // cannot see, so the wait keeps its own deadline and is only counted.
    // SAFETY: forwarding the caller's arguments unchanged.
    domain::native_wait(|| unsafe { wait(cond, mutex, deadline) })
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn pthread_cond_timedwait_relative_np(
    cond: *mut pthread_cond_t,
    mutex: *mut pthread_mutex_t,
    timeout: *const timespec,
) -> c_int {
    if timeout.is_null() || !domain::counts_native_waits() {
        // SAFETY: PTHREAD_COND_TIMEDWAIT_RELATIVE_NP holds libc's function; arguments forwarded.
        return unsafe {
            original::<CondTimedWaitFn>(&PTHREAD_COND_TIMEDWAIT_RELATIVE_NP)(cond, mutex, timeout)
        };
    }
    // SAFETY: a non-null timeout points at the caller's timespec; the condvar and mutex are theirs.
    unsafe { cond_wait_for(cond, mutex, span(&*timeout)) }
}

/// Waits on `cond` for at most `after` of the domain's time. Condition-variable signals are not
/// latched, so a slice that times out short of the deadline returns a spurious wakeup (which every
/// condvar caller must already tolerate) rather than waiting again and risking a lost signal.
///
/// # Safety
/// `cond` and `mutex` are as for `pthread_cond_timedwait`, with `mutex` held by the caller.
#[cfg(target_os = "macos")]
unsafe fn cond_wait_for(
    cond: *mut pthread_cond_t,
    mutex: *mut pthread_mutex_t,
    after: Duration,
) -> c_int {
    // SAFETY: PTHREAD_COND_TIMEDWAIT_RELATIVE_NP holds libc's function.
    let wait = unsafe { original::<CondTimedWaitFn>(&PTHREAD_COND_TIMEDWAIT_RELATIVE_NP) };
    let outcome = domain::timed_native_wait(after, Some(0), |slice| {
        let timeout = to_timespec(slice);
        // SAFETY: the caller's condvar and held mutex, with a relative timeout of `slice`.
        let r = unsafe { wait(cond, mutex, &timeout) };
        (r != libc::ETIMEDOUT).then_some(r)
    });
    match outcome {
        TimedWait::Woken(r) => r,
        TimedWait::TimedOut => libc::ETIMEDOUT,
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> c_int;
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Default)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}

// dispatch/time.h: DISPATCH_TIME_NOW is 0 and DISPATCH_TIME_FOREVER is all ones; a wall-clock
// dispatch_time (from dispatch_walltime) has the sign bit set.
#[cfg(target_os = "macos")]
const DISPATCH_TIME_NOW: u64 = 0;
#[cfg(target_os = "macos")]
const DISPATCH_TIME_FOREVER: u64 = !0;

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

#[cfg(target_os = "macos")]
unsafe extern "C" fn dispatch_time(when: u64, delta: i64) -> u64 {
    // SAFETY: DISPATCH_TIME holds libdispatch's dispatch_time.
    let deadline = unsafe { original::<DispatchTimeFn>(&DISPATCH_TIME)(when, delta) };
    if when == DISPATCH_TIME_NOW && domain::counts_native_waits() {
        let _ = LAST_DISPATCH_TIME.try_with(|last| last.set((deadline, delta)));
    }
    deadline
}

/// `dispatch_semaphore_wait` (dispatch/semaphore.h): a counting semaphore, so a signal sent
/// between two slices is kept, not lost, and the wait can be sliced safely.
#[cfg(target_os = "macos")]
unsafe extern "C" fn dispatch_semaphore_wait(semaphore: *mut libc::c_void, timeout: u64) -> c_long {
    // mach/kern_return.h: what a timed-out dispatch wait returns.
    const KERN_OPERATION_TIMED_OUT: c_long = 49;
    type WaitFn = unsafe extern "C" fn(*mut libc::c_void, u64) -> c_long;
    // SAFETY: DISPATCH_SEMAPHORE_WAIT and DISPATCH_TIME hold libdispatch's functions.
    let (wait, deadline_in) = unsafe {
        (
            original::<WaitFn>(&DISPATCH_SEMAPHORE_WAIT),
            original::<DispatchTimeFn>(&DISPATCH_TIME),
        )
    };
    if !domain::counts_native_waits() || timeout == DISPATCH_TIME_NOW {
        // SAFETY: forwarding the caller's arguments unchanged.
        return unsafe { wait(semaphore, timeout) };
    }
    if timeout == DISPATCH_TIME_FOREVER || (timeout as i64) < 0 {
        // SAFETY: forwarding the caller's arguments unchanged.
        return domain::native_wait(|| unsafe { wait(semaphore, timeout) });
    }
    let after = match LAST_DISPATCH_TIME.try_with(|last| last.get()) {
        Ok((deadline, delta)) if deadline == timeout => Duration::from_nanos(delta.max(0) as u64),
        // A deadline built some other way: read the span back off the Mach clock, rounding up a
        // tick so the wait overshoots the caller's deadline rather than stopping short of it.
        _ => {
            let mut timebase = MachTimebaseInfo::default();
            // SAFETY: mach_timebase_info fills the struct; dispatch_time only reads the clock.
            let ticks = unsafe {
                mach_timebase_info(&mut timebase);
                timeout.saturating_sub(deadline_in(DISPATCH_TIME_NOW, 0)) + 1
            };
            let nanos = u128::from(ticks) * u128::from(timebase.numer)
                / u128::from(timebase.denom.max(1));
            Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
        }
    };
    let outcome = domain::timed_native_wait(after, None, |slice| {
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

unsafe extern "C" fn sched_yield() -> c_int {
    domain::yield_point();
    // SAFETY: SCHED_YIELD holds libc's sched_yield.
    unsafe { original::<unsafe extern "C" fn() -> c_int>(&SCHED_YIELD)() }
}

/// The Linux futex wait, reached through libc's `syscall` (std and parking_lot issue it there).
/// Returns `None` for every other futex operation, and off a managed thread, so the caller forwards
/// it untouched; `real` performs one raw `syscall(SYS_futex, …)` with the given arguments.
///
/// # Safety
/// `args` are the caller's futex arguments, as `syscall(SYS_futex, …)` would receive them.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn futex(args: [usize; 6], real: impl Fn([usize; 6]) -> c_long) -> Option<c_long> {
    // man 2 futex: FUTEX_BITSET_MATCH_ANY.
    const MATCH_ANY: usize = 0xffff_ffff;
    let [word, op, value, timeout, word2, bitset] = args;
    let op = op as c_int;
    let command = op & !(libc::FUTEX_PRIVATE_FLAG | libc::FUTEX_CLOCK_REALTIME);
    if !domain::counts_native_waits()
        || (command != libc::FUTEX_WAIT && command != libc::FUTEX_WAIT_BITSET)
    {
        return None;
    }
    let timeout = timeout as *const timespec;
    if timeout.is_null() {
        return Some(domain::native_wait(|| real(args)));
    }
    // SAFETY: a non-null futex timeout points at the caller's timespec.
    let given = span(unsafe { &*timeout });
    // man 2 futex: FUTEX_WAIT's timeout is relative; FUTEX_WAIT_BITSET's is absolute, on
    // CLOCK_MONOTONIC or (with FUTEX_CLOCK_REALTIME) CLOCK_REALTIME — the virtual clock the caller
    // read, under a clock layer.
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
    let errno = || std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let outcome = domain::timed_native_wait(after, None, |slice| {
        let deadline = to_timespec(crate::real(real_monotonic) + slice);
        let deadline_ptr = &deadline as *const timespec as usize;
        let r = real([word, attempt_op, value, deadline_ptr, word2, bitset]);
        let e = errno();
        (r != -1 || e != libc::ETIMEDOUT).then_some((r, e))
    });
    let (r, e) = match outcome {
        TimedWait::Woken(woken) => woken,
        TimedWait::TimedOut => (-1, libc::ETIMEDOUT),
    };
    // SAFETY: errno is this thread's; restore what the futex call reported.
    unsafe { *libc::__errno_location() = e };
    Some(r)
}

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
