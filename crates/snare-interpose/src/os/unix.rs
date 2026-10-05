//! The Unix hooks for clocks, sleeps, threads, randomness, the environment, user ids and symbol
//! lookup, plus the table of every Unix hook (see [`hooks()`]).
//!
//! Each replacement offers its call to the managed thread's layers through `domain::dispatch` and
//! its relatives, and makes the real call through the saved original when no layer handles it, or
//! when the thread is not managed. Each `static` below holds the original of the function of the
//! same name, filled in by `crate::patch` before any import is redirected.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use libc::{clockid_t, pthread_attr_t, pthread_t, timespec, timeval};

use crate::domain::{self, dispatch, dispatch_env};
use crate::hooks::{self, Hook, hook, observed, original};
use crate::layer::{ClockKind, SleepRequest};
use crate::state;

static CLOCK_GETTIME: AtomicUsize = AtomicUsize::new(0);
static GETTIMEOFDAY: AtomicUsize = AtomicUsize::new(0);
static NANOSLEEP: AtomicUsize = AtomicUsize::new(0);
static USLEEP: AtomicUsize = AtomicUsize::new(0);
static PTHREAD_CREATE: AtomicUsize = AtomicUsize::new(0);
static PTHREAD_JOIN: AtomicUsize = AtomicUsize::new(0);
static PTHREAD_SETNAME_NP: AtomicUsize = AtomicUsize::new(0);
static DLSYM: AtomicUsize = AtomicUsize::new(0);
static GETENTROPY: AtomicUsize = AtomicUsize::new(0);
static GETENV: AtomicUsize = AtomicUsize::new(0);
static SETENV: AtomicUsize = AtomicUsize::new(0);
static UNSETENV: AtomicUsize = AtomicUsize::new(0);
static GETEUID: AtomicUsize = AtomicUsize::new(0);
static GETUID: AtomicUsize = AtomicUsize::new(0);
static UNAME: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_os = "linux")]
static CLOCK_NANOSLEEP: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static DLOPEN: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static GETRANDOM: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
static SYSCALL: AtomicUsize = AtomicUsize::new(0);
#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
static IOCTL: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_os = "macos")]
static CLOCK_GETTIME_NSEC_NP: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "macos")]
static MACH_ABSOLUTE_TIME: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "macos")]
static MACH_CONTINUOUS_TIME: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "macos")]
static CC_RANDOM_GENERATE_BYTES: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "macos")]
static ARC4RANDOM_BUF: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "macos")]
static ARC4RANDOM: AtomicUsize = AtomicUsize::new(0);

/// Every hook on this Unix target: those defined here, then the observed ones, DNS, sockets,
/// synchronization, signals, files and host queries.
static CLOCK_GETRES: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "macos")]
static NS_GET_ENVIRON: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn hooks() -> Vec<Hook> {
    let mut hooks = vec![
        hook!("clock_gettime", clock_gettime, CLOCK_GETTIME),
        hook!("clock_getres", clock_getres, CLOCK_GETRES),
        hook!("gettimeofday", gettimeofday, GETTIMEOFDAY),
        hook!("nanosleep", nanosleep, NANOSLEEP),
        hook!("usleep", usleep, USLEEP),
        hook!("pthread_create", pthread_create, PTHREAD_CREATE),
        hook!("pthread_join", pthread_join, PTHREAD_JOIN),
        hook!("pthread_setname_np", pthread_setname_np, PTHREAD_SETNAME_NP),
        hook!("dlsym", dlsym, DLSYM),
        hook!("getentropy", getentropy, GETENTROPY),
        hook!("getenv", getenv, GETENV),
        hook!("setenv", setenv, SETENV),
        hook!("unsetenv", unsetenv, UNSETENV),
        #[cfg(target_os = "macos")]
        hook!("_NSGetEnviron", ns_get_environ, NS_GET_ENVIRON),
        hook!("geteuid", geteuid, GETEUID),
        hook!("getuid", getuid, GETUID),
        hook!("uname", uname, UNAME),
        #[cfg(target_os = "linux")]
        hook!("clock_nanosleep", clock_nanosleep, CLOCK_NANOSLEEP),
        #[cfg(target_os = "linux")]
        hook!("dlopen", dlopen, DLOPEN),
        #[cfg(target_os = "linux")]
        hook!("getrandom", getrandom, GETRANDOM),
        #[cfg(target_os = "macos")]
        hook!(
            "clock_gettime_nsec_np",
            clock_gettime_nsec_np,
            CLOCK_GETTIME_NSEC_NP
        ),
        #[cfg(target_os = "macos")]
        hook!("mach_absolute_time", mach_absolute_time, MACH_ABSOLUTE_TIME),
        #[cfg(target_os = "macos")]
        hook!(
            "mach_continuous_time",
            mach_continuous_time,
            MACH_CONTINUOUS_TIME
        ),
        #[cfg(target_os = "macos")]
        hook!(
            "CCRandomGenerateBytes",
            cc_random_generate_bytes,
            CC_RANDOM_GENERATE_BYTES
        ),
        #[cfg(target_os = "macos")]
        hook!("arc4random_buf", arc4random_buf, ARC4RANDOM_BUF),
        #[cfg(target_os = "macos")]
        hook!("arc4random", arc4random, ARC4RANDOM),
    ];
    hooks.extend(observed_hooks());
    hooks.extend(crate::os::dns::hooks());
    hooks.extend(crate::os::sockets::hooks());
    hooks.extend(crate::os::sync::hooks());
    hooks.extend(crate::os::signal_hooks::hooks());
    hooks.extend(crate::os::files::hooks());
    #[cfg(target_os = "linux")]
    hooks.extend(crate::os::host::hooks());
    #[cfg(target_os = "macos")]
    hooks.extend(crate::os::host_macos::hooks());
    hooks
}

/// OS calls no layer models yet; see [`crate::Unmodelled`].
///
/// Generic file-descriptor calls (`read`, `write`, `close`, `fcntl`) are left out: most of them
/// are file I/O, and a socket reaching them was already reported when it was created.
fn observed_hooks() -> Vec<Hook> {
    vec![
        observed!("fork", []),
        observed!("execve", [path, arguments, environment]),
        observed!(
            "posix_spawn",
            [pid, path, actions, attributes, arguments, environment]
        ),
        #[cfg(target_os = "linux")]
        observed!("sendmmsg", [fd, messages, count, flags]),
        #[cfg(target_os = "linux")]
        observed!("recvmmsg", [fd, messages, count, flags, timeout]),
        #[cfg(target_os = "linux")]
        observed!("ppoll", [fds, count, timeout, mask]),
        #[cfg(target_os = "linux")]
        hook!("syscall", syscall, SYSCALL).observed(),
        #[cfg(target_os = "linux")]
        hook!("ioctl", ioctl, IOCTL).observed(),
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        hook!("ioctl", crate::os::variadic::ioctl, IOCTL).observed(),
        #[cfg(target_os = "macos")]
        observed!(
            "kevent64",
            [
                queue,
                changes,
                change_count,
                events,
                event_count,
                flags,
                timeout
            ]
        ),
        #[cfg(target_os = "macos")]
        observed!("__ulock_wait", [operation, address, value, timeout]),
        #[cfg(target_os = "macos")]
        observed!("os_sync_wait_on_address", [address, value, size, flags]),
    ]
}

/// The virtual clock a Linux clock id reads, `None` for one left to the kernel (the CPU-time
/// clocks, alarm clocks and dynamic POSIX clocks).
///
/// man 2 clock_gettime for the clock ids and their semantics; `CLOCK_TAI` is 11 in
/// `include/uapi/linux/time.h`. COARSE variants read the same virtual clock as their base since the
/// sim has no tick granularity, and `CLOCK_BOOTTIME`, which unlike `CLOCK_MONOTONIC` counts time
/// suspended, reads the monotonic one since the sim never suspends.
#[cfg(target_os = "linux")]
fn clock_kind(id: clockid_t) -> Option<ClockKind> {
    match id {
        libc::CLOCK_REALTIME | libc::CLOCK_REALTIME_COARSE => Some(ClockKind::Realtime),
        libc::CLOCK_TAI => Some(ClockKind::Tai),
        libc::CLOCK_MONOTONIC
        | libc::CLOCK_MONOTONIC_RAW
        | libc::CLOCK_MONOTONIC_COARSE
        | libc::CLOCK_BOOTTIME => Some(ClockKind::Monotonic),
        _ => None,
    }
}

/// The virtual clock a Darwin clock id reads, `None` for the CPU-time clocks.
///
/// The `clockid_t` enum in the macOS SDK's `<_time.h>` (included by `<time.h>`):
/// `_CLOCK_REALTIME`=0, `_CLOCK_MONOTONIC_RAW`=4, `_CLOCK_MONOTONIC_RAW_APPROX`=5,
/// `_CLOCK_MONOTONIC`=6, `_CLOCK_UPTIME_RAW`=8, `_CLOCK_UPTIME_RAW_APPROX`=9. `CLOCK_MONOTONIC`
/// keeps counting while the system sleeps and the uptime clocks stop (Darwin man 3
/// clock_gettime); the sim never sleeps, so all of them read the monotonic one.
#[cfg(target_os = "macos")]
fn clock_kind(id: clockid_t) -> Option<ClockKind> {
    const REALTIME: clockid_t = 0;
    const MONOTONIC_RAW: clockid_t = 4;
    const MONOTONIC_RAW_APPROX: clockid_t = 5;
    const MONOTONIC: clockid_t = 6;
    const UPTIME_RAW: clockid_t = 8;
    const UPTIME_RAW_APPROX: clockid_t = 9;
    match id {
        REALTIME => Some(ClockKind::Realtime),
        MONOTONIC_RAW | MONOTONIC_RAW_APPROX | MONOTONIC | UPTIME_RAW | UPTIME_RAW_APPROX => {
            Some(ClockKind::Monotonic)
        }
        _ => None,
    }
}

/// The managed thread's reading of `kind`, `None` when no layer models it; see
/// `domain::read_clock`.
fn virtual_now(kind: ClockKind) -> Option<Duration> {
    domain::read_clock(kind)
}

/// A span as a `timespec`.
fn to_timespec(d: Duration) -> timespec {
    timespec {
        tv_sec: d.as_secs() as _,
        tv_nsec: d.subsec_nanos() as _,
    }
}

/// A `timespec` as a span, `None` for one the OS rejects with `EINVAL`: a negative `tv_sec` or a
/// `tv_nsec` outside `0..1_000_000_000` (Linux man 2 nanosleep; Darwin's man 2 nanosleep lists
/// only the `tv_nsec` range). Such a request is passed to the OS to report.
fn from_timespec(t: &timespec) -> Option<Duration> {
    if t.tv_sec < 0 || !(0..1_000_000_000).contains(&t.tv_nsec) {
        return None;
    }
    Some(Duration::new(t.tv_sec as u64, t.tv_nsec as u32))
}

/// `clock_gettime` (man 2 clock_gettime): the virtual reading of a clock [`clock_kind`] maps.
unsafe extern "C" fn clock_gettime(id: clockid_t, tp: *mut timespec) -> c_int {
    #[cfg(target_os = "linux")]
    if id < 0
        && let Some(r) = domain::dispatch_host(|host| unsafe { host.clock_gettime(id, tp.cast()) })
    {
        return crate::os::sockets::finish(r) as c_int;
    }
    if !tp.is_null()
        && let Some(now) = clock_kind(id).and_then(virtual_now)
    {
        // SAFETY: the caller passed a writable timespec.
        unsafe { tp.write(to_timespec(now)) };
        return 0;
    }
    // SAFETY: CLOCK_GETTIME holds libc's clock_gettime.
    unsafe {
        original::<unsafe extern "C" fn(clockid_t, *mut timespec) -> c_int>(&CLOCK_GETTIME)(id, tp)
    }
}

unsafe extern "C" fn clock_getres(id: clockid_t, tp: *mut timespec) -> c_int {
    #[cfg(target_os = "linux")]
    if id < 0
        && let Some(r) = domain::dispatch_host(|host| unsafe { host.clock_getres(id, tp.cast()) })
    {
        return crate::os::sockets::finish(r) as c_int;
    }
    unsafe {
        original::<unsafe extern "C" fn(clockid_t, *mut timespec) -> c_int>(&CLOCK_GETRES)(id, tp)
    }
}

/// `gettimeofday` (man 2 gettimeofday): fills a `struct timeval` (seconds + microseconds) from the
/// realtime clock; the `tz` argument is obsolete and ignored.
unsafe extern "C" fn gettimeofday(tv: *mut timeval, tz: *mut c_void) -> c_int {
    if !tv.is_null()
        && let Some(now) = virtual_now(ClockKind::Realtime)
    {
        // SAFETY: the caller passed a writable timeval.
        unsafe {
            tv.write(timeval {
                tv_sec: now.as_secs() as _,
                tv_usec: now.subsec_micros() as _,
            })
        };
        return 0;
    }
    // SAFETY: GETTIMEOFDAY holds libc's gettimeofday.
    unsafe {
        original::<unsafe extern "C" fn(*mut timeval, *mut c_void) -> c_int>(&GETTIMEOFDAY)(tv, tz)
    }
}

/// `nanosleep` (man 2 nanosleep): relative sleep; on early return (`EINTR`) the unslept time is
/// written to `remaining`. The sim never interrupts a sleep, so `remaining` is always zero.
unsafe extern "C" fn nanosleep(request: *const timespec, remaining: *mut timespec) -> c_int {
    // SAFETY: a non-null request points to a readable timespec.
    let duration = unsafe { request.as_ref() }.and_then(from_timespec);
    if let Some(duration) = duration
        && dispatch(|layer| layer.sleep(SleepRequest::For(duration))).is_some()
    {
        if !remaining.is_null() {
            // SAFETY: the caller passed a writable timespec.
            unsafe { remaining.write(to_timespec(Duration::ZERO)) };
        }
        return 0;
    }
    // SAFETY: NANOSLEEP holds libc's nanosleep.
    unsafe {
        original::<unsafe extern "C" fn(*const timespec, *mut timespec) -> c_int>(&NANOSLEEP)(
            request, remaining,
        )
    }
}

/// `usleep` (man 3 usleep): suspend for a microsecond interval (removed from POSIX.1-2008, still
/// widely linked).
unsafe extern "C" fn usleep(micros: libc::useconds_t) -> c_int {
    if dispatch(|layer| layer.sleep(SleepRequest::For(Duration::from_micros(micros.into()))))
        .is_some()
    {
        return 0;
    }
    // SAFETY: USLEEP holds libc's usleep.
    unsafe { original::<unsafe extern "C" fn(libc::useconds_t) -> c_int>(&USLEEP)(micros) }
}

/// `clock_nanosleep` (man 2 clock_nanosleep): sleep against a named clock. `TIMER_ABSTIME` (1 in
/// `include/uapi/linux/time.h`) selects an absolute deadline, for which no remaining time is
/// reported; otherwise the request is relative.
#[cfg(target_os = "linux")]
unsafe extern "C" fn clock_nanosleep(
    id: clockid_t,
    flags: c_int,
    request: *const timespec,
    remaining: *mut timespec,
) -> c_int {
    // SAFETY: a non-null request points to a readable timespec.
    let time = unsafe { request.as_ref() }.and_then(from_timespec);
    if let (Some(kind), Some(time)) = (clock_kind(id), time) {
        let sleep = if flags & libc::TIMER_ABSTIME != 0 {
            SleepRequest::Until(kind, time)
        } else {
            SleepRequest::For(time)
        };
        if dispatch(|layer| layer.sleep(sleep)).is_some() {
            if !remaining.is_null() && flags & libc::TIMER_ABSTIME == 0 {
                // SAFETY: the caller passed a writable timespec.
                unsafe { remaining.write(to_timespec(Duration::ZERO)) };
            }
            return 0;
        }
    }
    // SAFETY: CLOCK_NANOSLEEP holds libc's clock_nanosleep.
    unsafe {
        original::<unsafe extern "C" fn(clockid_t, c_int, *const timespec, *mut timespec) -> c_int>(
            &CLOCK_NANOSLEEP,
        )(id, flags, request, remaining)
    }
}

/// `clock_gettime_nsec_np` (Darwin man 3 clock_gettime): returns the named clock as a flat
/// nanosecond count.
#[cfg(target_os = "macos")]
unsafe extern "C" fn clock_gettime_nsec_np(id: clockid_t) -> u64 {
    if let Some(now) = clock_kind(id).and_then(virtual_now) {
        return now.as_nanos() as u64;
    }
    // SAFETY: CLOCK_GETTIME_NSEC_NP holds libc's clock_gettime_nsec_np.
    unsafe { original::<unsafe extern "C" fn(clockid_t) -> u64>(&CLOCK_GETTIME_NSEC_NP)(id) }
}

/// Nanoseconds as Mach absolute-time ticks. `mach_absolute_time` is in `mach_timebase_info` units,
/// not nanoseconds; ticks = nanos * denom / numer inverts the nanos = ticks * numer / denom
/// conversion Apple documents ([Apple Technical Q&A QA1398: Mach Absolute Time Units](https://developer.apple.com/library/archive/qa/qa1398/_index.html)).
/// The timebase is fixed for the life of the process, so it is read once.
#[cfg(target_os = "macos")]
fn nanos_to_mach_ticks(nanos: u128) -> u64 {
    // <mach/mach_time.h> struct mach_timebase_info: { numer: u32, denom: u32 }.
    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }
    unsafe extern "C" {
        fn mach_timebase_info(info: *mut Timebase) -> c_int;
    }
    static TIMEBASE: crate::race::RaceCell<(u32, u32)> = crate::race::RaceCell::new();
    let (numer, denom) = *TIMEBASE
        .get_or_init(|| {
            let mut info = Timebase { numer: 1, denom: 1 };
            // SAFETY: fills `info`; mach_timebase_info is not hooked.
            unsafe { mach_timebase_info(&mut info) };
            (info.numer, info.denom)
        })
        .0;
    (nanos * u128::from(denom) / u128::from(numer)) as u64
}

/// `mach_absolute_time` (macOS SDK `<mach/mach_time.h>`): the monotonic virtual clock in Mach ticks.
#[cfg(target_os = "macos")]
unsafe extern "C" fn mach_absolute_time() -> u64 {
    if let Some(now) = virtual_now(ClockKind::Monotonic) {
        return nanos_to_mach_ticks(now.as_nanos());
    }
    // SAFETY: MACH_ABSOLUTE_TIME holds libSystem's mach_absolute_time.
    unsafe { original::<unsafe extern "C" fn() -> u64>(&MACH_ABSOLUTE_TIME)() }
}

/// `mach_continuous_time`: "like mach_absolute_time, but advances during sleep" (macOS SDK
/// `<mach/mach_time.h>`); the sim has no sleep state, so both map to the monotonic virtual clock.
#[cfg(target_os = "macos")]
unsafe extern "C" fn mach_continuous_time() -> u64 {
    if let Some(now) = virtual_now(ClockKind::Monotonic) {
        return nanos_to_mach_ticks(now.as_nanos());
    }
    // SAFETY: MACH_CONTINUOUS_TIME holds libSystem's mach_continuous_time.
    unsafe { original::<unsafe extern "C" fn() -> u64>(&MACH_CONTINUOUS_TIME)() }
}

/// A pthread start routine (POSIX pthread_create).
type StartRoutine = extern "C" fn(*mut c_void) -> *mut c_void;

/// What a managed thread's child needs to start: the caller's routine and argument, and the domain
/// membership it inherits. Boxed by [`pthread_create`] and owned by the child once it runs.
struct Start {
    routine: StartRoutine,
    argument: *mut c_void,
    inherited: domain::Inherited,
}

/// The start routine a managed thread's children actually run: joins the inherited domain, runs
/// the caller's routine, and leaves the domain before the thread exits.
extern "C" fn managed_start(start: *mut c_void) -> *mut c_void {
    // SAFETY: `pthread_create` below boxed this `Start` and handed ownership to this thread.
    let Start {
        routine,
        argument,
        inherited,
    } = *unsafe { Box::from_raw(start.cast::<Start>()) };
    // SAFETY: `inherit` made this for this thread alone.
    let lineage = inherited.lineage;
    let child = unsafe { domain::adopt(inherited) };
    domain::dispatch_host(|host| {
        host.thread_adopt(lineage);
        Some(crate::host::HostResult::Ok(0))
    });
    let result = routine(argument);
    drop(child);
    result
}

/// `pthread_join` (man 3 pthread_join): blocks until `thread` terminates. A managed thread joining another is an
/// in-memory wait that only another managed thread can satisfy, so it counts toward quiescence:
/// without it, a thread that gives up on a deadlocked wait and then joins a still-parked peer would
/// leave that peer short of the quiescence count forever, and under a virtual clock the joined
/// thread's timers could never be time-skipped. The real join still wakes when the thread exits;
/// bracketing it only makes the wait visible to the scheduler. Off a domain the join just runs.
unsafe extern "C" fn pthread_join(thread: pthread_t, retval: *mut *mut c_void) -> c_int {
    domain::end_spin();
    // SAFETY: PTHREAD_JOIN holds libc's pthread_join.
    let join = unsafe {
        original::<unsafe extern "C" fn(pthread_t, *mut *mut c_void) -> c_int>(&PTHREAD_JOIN)
    };
    if domain::counts_native_waits()
        && domain::det_active()
        && let Some(target) = domain::det_lineage_of(handle_key(thread))
    {
        let _label = crate::wait_label("join");
        // Deterministic: wait for the thread's exit in the schedule; the real join then only
        // collects a thread that is already leaving.
        domain::det_block(crate::DetKey::Exit(target), None);
        // SAFETY: forwarding the caller's arguments unchanged.
        return unsafe { join(thread, retval) };
    }
    let _label = crate::wait_label("join");
    if !domain::begin_join(handle_key(thread)) {
        return unsafe { join(thread, retval) };
    }
    // SAFETY: forwarding the caller's arguments unchanged.
    domain::native_wait(|| unsafe { join(thread, retval) })
}

/// `pthread_setname_np` (Linux man 3 pthread_setname_np): names `thread`, failing with `ERANGE`
/// beyond 16 bytes including the NUL. The call goes to the OS unchanged; a name it accepts is also
/// recorded for the thread's row in its domain.
#[cfg(target_os = "linux")]
unsafe extern "C" fn pthread_setname_np(thread: pthread_t, name: *const c_char) -> c_int {
    // SAFETY: PTHREAD_SETNAME_NP holds libc's pthread_setname_np; arguments forwarded unchanged.
    let r = unsafe {
        original::<unsafe extern "C" fn(pthread_t, *const c_char) -> c_int>(&PTHREAD_SETNAME_NP)(
            thread, name,
        )
    };
    if r == 0 && !name.is_null() {
        // SAFETY: pthread_self has no preconditions.
        let handle = (thread != unsafe { libc::pthread_self() }).then(|| handle_key(thread));
        // SAFETY: the OS accepted `name`, so it is a C string.
        domain::record_thread_name(handle, unsafe { CStr::from_ptr(name) }.to_bytes());
    }
    r
}

/// `pthread_setname_np` on macOS takes only a name and names the calling thread (macOS SDK
/// `<pthread.h>`). A name the OS accepts is also recorded for the thread's row in its domain.
#[cfg(target_os = "macos")]
unsafe extern "C" fn pthread_setname_np(name: *const c_char) -> c_int {
    // SAFETY: PTHREAD_SETNAME_NP holds libc's pthread_setname_np; argument forwarded unchanged.
    let r = unsafe {
        original::<unsafe extern "C" fn(*const c_char) -> c_int>(&PTHREAD_SETNAME_NP)(name)
    };
    if r == 0 && !name.is_null() {
        // SAFETY: the OS accepted `name`, so it is a C string.
        domain::record_thread_name(None, unsafe { CStr::from_ptr(name) }.to_bytes());
    }
    r
}

/// A `pthread_t` as a map key. Its integer width is the platform's (`usize` on Apple, `c_ulong`
/// on Linux), so the cast is a no-op on some targets.
#[allow(clippy::unnecessary_cast)]
pub(crate) fn handle_key(thread: pthread_t) -> usize {
    thread as usize
}

/// `pthread_create` (man 3 pthread_create): a managed thread's child starts through
/// [`managed_start`] so it joins its parent's domain before any of its own code runs, and its
/// handle is recorded against its lineage for joins and naming. Off a domain the call is forwarded.
/// If creation fails the inherited membership is released, since no child will adopt it.
unsafe extern "C" fn pthread_create(
    thread: *mut pthread_t,
    attr: *const pthread_attr_t,
    routine: StartRoutine,
    argument: *mut c_void,
) -> c_int {
    // SAFETY: PTHREAD_CREATE holds libc's pthread_create.
    let create = unsafe {
        original::<
            unsafe extern "C" fn(
                *mut pthread_t,
                *const pthread_attr_t,
                StartRoutine,
                *mut c_void,
            ) -> c_int,
        >(&PTHREAD_CREATE)
    };
    let Some(inherited) = domain::inherit() else {
        // SAFETY: forwarding the caller's arguments unchanged.
        return unsafe { create(thread, attr, routine, argument) };
    };
    let lineage = inherited.lineage;
    domain::dispatch_host(|host| {
        host.thread_inherit(lineage);
        Some(crate::host::HostResult::Ok(0))
    });
    let start = Box::into_raw(Box::new(Start {
        routine,
        argument,
        inherited,
    }));
    // SAFETY: `managed_start` takes ownership of `start` once the thread runs.
    let result = unsafe { create(thread, attr, managed_start, start.cast()) };
    if result != 0 {
        domain::dispatch_host(|host| {
            host.thread_cancel(lineage);
            Some(crate::host::HostResult::Ok(0))
        });
        // SAFETY: the thread was not created, so `start` is still ours.
        let start = unsafe { Box::from_raw(start) };
        // SAFETY: nothing adopted it.
        unsafe { domain::release(start.inherited) };
    } else if !thread.is_null() {
        // SAFETY: on success pthread_create wrote the new thread's handle here.
        domain::record_handle(handle_key(unsafe { *thread }), lineage);
    }
    result
}

/// `dlsym` (man 3 dlsym): hands out hooks instead of the real functions, so code that looks
/// functions up at run time (std's weak symbols, for one) is redirected like code that links them.
/// Under passthrough the real address is returned, so the sim's own lookups reach the OS.
unsafe extern "C" fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void {
    // SAFETY: DLSYM holds libc's dlsym; arguments are forwarded unchanged.
    let found = unsafe {
        original::<unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void>(&DLSYM)(
            handle, name,
        )
    };
    if found.is_null() || name.is_null() || state::passthrough() {
        return found;
    }
    // SAFETY: dlsym succeeded, so `name` is a C string.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    match hooks::find(name) {
        Some(hook) if hook.resolved() => hook.replacement as *mut c_void,
        _ => found,
    }
}

/// `dlopen` (man 3 dlopen): patches the import tables of any object it loaded. macOS learns of new
/// images from dyld's add-image callback instead.
#[cfg(target_os = "linux")]
unsafe extern "C" fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void {
    // SAFETY: DLOPEN holds libc's dlopen; arguments are forwarded unchanged.
    let handle = unsafe {
        original::<unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void>(&DLOPEN)(
            filename, flags,
        )
    };
    if !handle.is_null() {
        crate::patch::patch_new_objects();
    }
    handle
}

/// Offers `length` bytes at `buffer` to the layers to fill; `true` if one did. A null buffer
/// counts as filled only for an empty request, so the real call reports any other.
fn virtual_random(buffer: *mut c_void, length: usize) -> bool {
    if buffer.is_null() {
        return length == 0;
    }
    // SAFETY: the caller of the hooked function passed `length` writable bytes at `buffer`.
    let buffer = unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), length) };
    dispatch(|layer| layer.random(buffer)).is_some()
}

/// `getentropy`: fills up to 256 bytes; a longer request fails with `EIO` (Linux man 3
/// getentropy; macOS man 2 getentropy).
unsafe extern "C" fn getentropy(buffer: *mut c_void, length: usize) -> c_int {
    // Longer requests fail with EIO; let the OS report that.
    if length <= 256 && virtual_random(buffer, length) {
        return 0;
    }
    // SAFETY: GETENTROPY holds libc's getentropy.
    unsafe {
        original::<unsafe extern "C" fn(*mut c_void, usize) -> c_int>(&GETENTROPY)(buffer, length)
    }
}

/// Which user the code under test runs as, when the domain's host models it (man 2 geteuid).
fn host_uid(op: impl FnOnce(&dyn crate::Host) -> Option<u32>) -> Option<libc::uid_t> {
    domain::dispatch_host(|h| op(h).map(|uid| crate::host::HostResult::Ok(uid.into())))
        .map(|uid| uid as libc::uid_t)
}

/// `geteuid` (man 2 geteuid): the effective user id, as the domain's host models it.
unsafe extern "C" fn geteuid() -> libc::uid_t {
    if let Some(uid) = host_uid(|h| h.geteuid()) {
        return uid;
    }
    // SAFETY: GETEUID holds libc's geteuid.
    unsafe { original::<unsafe extern "C" fn() -> libc::uid_t>(&GETEUID)() }
}

/// `getuid` (man 2 getuid): the real user id, as the domain's host models it.
unsafe extern "C" fn getuid() -> libc::uid_t {
    if let Some(uid) = host_uid(|h| h.getuid()) {
        return uid;
    }
    // SAFETY: GETUID holds libc's getuid.
    unsafe { original::<unsafe extern "C" fn() -> libc::uid_t>(&GETUID)() }
}

/// `uname` (man 2 uname): the kernel identity, as the domain's host models it.
unsafe extern "C" fn uname(buf: *mut libc::utsname) -> c_int {
    // SAFETY: `buf` is the caller's `struct utsname`.
    if let Some(r) = domain::dispatch_host(|h| unsafe { h.uname(buf.cast()) }) {
        return crate::os::sockets::finish(r) as c_int;
    }
    // SAFETY: UNAME holds libc's uname.
    unsafe { original::<unsafe extern "C" fn(*mut libc::utsname) -> c_int>(&UNAME)(buf) }
}

/// `getenv` (man 3 getenv): returns a pointer into the environment (not a copy); a later
/// setenv/unsetenv may invalidate it, so callers must not hold it across those calls.
unsafe extern "C" fn getenv(name: *const c_char) -> *mut c_char {
    // Rust's `std::env::var` reads through this symbol, so a simulated environment captures it.
    // SAFETY: `name` is the caller's C string.
    if let Some(value) = dispatch_env(|env| unsafe { env.getenv(name) }) {
        return value;
    }
    // SAFETY: GETENV holds libc's getenv.
    unsafe { original::<unsafe extern "C" fn(*const c_char) -> *mut c_char>(&GETENV)(name) }
}

/// `setenv` (man 3 setenv): a zero `overwrite` leaves an existing name unchanged and still returns
/// success.
unsafe extern "C" fn setenv(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int {
    // SAFETY: `name`/`value` are the caller's C strings.
    if let Some(r) = dispatch_env(|env| unsafe { env.setenv(name, value, overwrite) }) {
        return r;
    }
    // SAFETY: SETENV holds libc's setenv.
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, *const c_char, c_int) -> c_int>(&SETENV)(
            name, value, overwrite,
        )
    }
}

/// `unsetenv` (man 3 unsetenv): removing an absent name is not an error.
unsafe extern "C" fn unsetenv(name: *const c_char) -> c_int {
    // SAFETY: `name` is the caller's C string.
    if let Some(r) = dispatch_env(|env| unsafe { env.unsetenv(name) }) {
        return r;
    }
    // SAFETY: UNSETENV holds libc's unsetenv.
    unsafe { original::<unsafe extern "C" fn(*const c_char) -> c_int>(&UNSETENV)(name) }
}

/// `getrandom` (man 2 getrandom): returns the number of bytes written. Unlike getentropy there is no
/// 256-byte limit, though the kernel returns at most 32Mi-1 bytes per call from the urandom source
/// and only reads of up to 256 bytes are guaranteed whole. The sim fills the whole request,
/// however long, so `GRND_NONBLOCK`/`GRND_RANDOM` never short-read here.
#[cfg(target_os = "linux")]
unsafe extern "C" fn getrandom(buffer: *mut c_void, length: usize, flags: libc::c_uint) -> isize {
    if virtual_random(buffer, length) {
        return length as isize;
    }
    // SAFETY: GETRANDOM holds libc's getrandom.
    unsafe {
        original::<unsafe extern "C" fn(*mut c_void, usize, libc::c_uint) -> isize>(&GETRANDOM)(
            buffer, length, flags,
        )
    }
}

/// Records the syscall number, then forwards. Declared with six word-sized arguments after the
/// number: on x86_64 and AArch64 Linux, variadic integer arguments are passed exactly like named
/// ones (System V AMD64 psABI §3.2.3; AAPCS64 §6.8, see `crate::hooks`'s `observed!`), so this
/// hands the original what its caller passed.
///
/// man 2 syscall for the wrapper contract; its calling-convention table passes at most six
/// arguments (arg1–arg6) on x86-64 and arm64, hence the six words. Numbers are the arch's `SYS_*`
/// from `<sys/syscall.h>`.
#[cfg(target_os = "linux")]
unsafe extern "C" fn syscall(
    number: libc::c_long,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
) -> libc::c_long {
    type SyscallFn = unsafe extern "C" fn(
        libc::c_long,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
    ) -> libc::c_long;
    // std's and parking_lot's blocking edge on Linux: a futex wait counted toward quiescence and
    // timed in the domain's clock (see `os::sync`).
    if number == libc::SYS_getdents64
        && domain::fs_owns(a as c_int)
        && let Some(result) = domain::dispatch_fs(|fs| unsafe {
            fs.getdents64(a as c_int, b as *mut u8, c as u32 as usize)
        })
    {
        return crate::os::sockets::finish(result);
    }
    if number == libc::SYS_statfs
        && let Some(result) =
            domain::dispatch_fs(|fs| unsafe { fs.statfs(a as *const c_char, b as *mut u8) })
    {
        return crate::os::sockets::finish(result);
    }
    if number == libc::SYS_fstatfs
        && domain::fs_owns(a as c_int)
        && let Some(result) =
            domain::dispatch_fs(|fs| unsafe { fs.fstatfs(a as c_int, b as *mut u8) })
    {
        return crate::os::sockets::finish(result);
    }
    if number == libc::SYS_futex {
        // SAFETY: SYSCALL holds libc's syscall; the arguments are the caller's futex arguments.
        let real = |[a, b, c, d, e, f]: [usize; 6]| unsafe {
            original::<SyscallFn>(&SYSCALL)(number, a, b, c, d, e, f)
        };
        // SAFETY: as above.
        if let Some(r) = unsafe { crate::os::sync::futex([a, b, c, d, e, f], real) } {
            return r;
        }
    }
    // A managed host may model this number (fast-talker reaches the sched policy family only here,
    // since musl stubs the named wrappers). It diverts only numbers it recognises; the rest forward.
    // SYS_sched_setscheduler / SYS_sched_getscheduler etc.: man 2 sched_setscheduler.
    if let Some(r) = domain::dispatch_host(|h| unsafe {
        h.syscall(
            number,
            [a as i64, b as i64, c as i64, d as i64, e as i64, f as i64],
        )
    }) {
        // The C wrapper reports errors as -1 with errno set (man 2 syscall), not the negated errno
        // the kernel returns (man 2 intro).
        return crate::os::sockets::finish(r);
    }
    domain::observe("syscall", Some(number));
    // SAFETY: SYSCALL holds libc's syscall; see above for the argument passing.
    unsafe {
        original::<
            unsafe extern "C" fn(
                libc::c_long,
                usize,
                usize,
                usize,
                usize,
                usize,
                usize,
            ) -> libc::c_long,
        >(&SYSCALL)(number, a, b, c, d, e, f)
    }
}

/// Interface-name-keyed NIC ioctls that a simulated NIC answers on any socket fd (see [`ioctl`]).
#[cfg(target_os = "linux")]
fn is_nic_ioctl(request: libc::c_ulong) -> bool {
    // include/uapi/linux/sockios.h: SIOCSHWTSTAMP=0x89b0, SIOCGHWTSTAMP=0x89b1 (the
    // hardware-timestamp config ioctls of Documentation/networking/timestamping.rst). SIOCETHTOOL=0x8946 drives the
    // <linux/ethtool.h> command block; SIOCGIF* are the interface queries of man 7 netdevice.
    const SIOCSHWTSTAMP: libc::c_ulong = 0x89b0;
    const SIOCGHWTSTAMP: libc::c_ulong = 0x89b1;
    let r = request;
    r == libc::SIOCETHTOOL as libc::c_ulong
        || r == libc::SIOCGIFINDEX as libc::c_ulong
        || r == libc::SIOCGIFMTU as libc::c_ulong
        || r == libc::SIOCGIFFLAGS as libc::c_ulong
        || r == libc::SIOCGIFHWADDR as libc::c_ulong
        || r == SIOCSHWTSTAMP
        || r == SIOCGHWTSTAMP
}

/// The interface queries a simulated NIC answers on macOS. macOS SDK `<sys/sockio.h>`:
/// SIOCGIFFLAGS = _IOWR('i', 17, struct ifreq), SIOCGIFMTU = _IOWR('i', 51, struct ifreq). With
/// `<sys/ioccom.h>`'s encoding (`IOC_INOUT` 0xc0000000, length << 16, group << 8, number) and a
/// 32-byte `struct ifreq` (`<net/if.h>`: a 16-byte name and a 16-byte union) these are 0xc0206911
/// and 0xc0206933.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn is_nic_ioctl(request: libc::c_ulong) -> bool {
    request == 0xc020_6911 || request == 0xc020_6933
}

/// On macOS aarch64 `ioctl`'s third word arrives on the stack, so the real libc must be reached
/// through a variadic pointer that puts it back there; on Linux it travels in a register like a
/// named argument, so the fixed-arity pointer already matches.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type IoctlFn = unsafe extern "C" fn(c_int, libc::c_ulong, ...) -> c_int;
/// `ioctl` with its third word passed like a named argument.
#[cfg(target_os = "linux")]
type IoctlFn = unsafe extern "C" fn(c_int, libc::c_ulong, usize) -> c_int;

/// Records the request, then forwards. On macOS aarch64 the third word reaches here via the naked
/// trampoline in `crate::os::variadic`; on Linux it is passed like a named argument (see
/// `syscall`).
// The macOS-aarch64 trampoline tail-branches here from another codegen unit, so the symbol must
// have external linkage to be resolvable; `sym` still emits the right (mangled) reference.
#[cfg_attr(
    all(target_os = "macos", target_arch = "aarch64"),
    unsafe(export_name = "__snare_interpose_ioctl")
)]
#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
pub(crate) unsafe extern "C" fn ioctl(fd: c_int, request: libc::c_ulong, argument: usize) -> c_int {
    // man 2 ioctl: variadic in C (`ioctl(fd, request, ...)`), but every request we model takes a
    // single third word. For SIOC* that word is a `struct ifreq *` (man 7 netdevice).
    // SAFETY: `argument` is the ioctl's third word (a pointer for FIONBIO/FIONREAD/SIOC*).
    if domain::fs_owns(fd)
        && let Some(r) = domain::dispatch_fs(|fs| unsafe { fs.ioctl(fd, request, argument as i64) })
    {
        return crate::os::sockets::finish(r) as c_int;
    }
    // SAFETY: as above.
    if domain::net_owns(fd)
        && let Some(r) =
            domain::dispatch_net(|net| unsafe { net.ioctl(fd, request, argument as i64) })
    {
        return crate::os::sockets::finish(r) as c_int;
    }
    // NIC-configuration ioctls are keyed by the interface name inside the `ifreq`, not by the fd,
    // so a simulated NIC answers them on any socket — including a real `AF_INET` control socket it
    // does not own. The backend decodes `ifr_name` and declines interfaces it does not model.
    if is_nic_ioctl(request)
        && let Some(r) =
            domain::dispatch_net(|net| unsafe { net.ioctl(fd, request, argument as i64) })
    {
        return crate::os::sockets::finish(r) as c_int;
    }
    domain::observe("ioctl", Some(request as i64));
    // SAFETY: IOCTL holds libc's ioctl.
    unsafe { original::<IoctlFn>(&IOCTL)(fd, request, argument) }
}

/// `CCRandomGenerateBytes` (macOS SDK `<CommonCrypto/CommonRandom.h>`): returns `kCCSuccess` (0,
/// `<CommonCrypto/CommonCryptoError.h>`) once filled.
#[cfg(target_os = "macos")]
unsafe extern "C" fn cc_random_generate_bytes(buffer: *mut c_void, length: usize) -> i32 {
    if virtual_random(buffer, length) {
        return 0;
    }
    // SAFETY: CC_RANDOM_GENERATE_BYTES holds CommonCrypto's CCRandomGenerateBytes.
    unsafe {
        original::<unsafe extern "C" fn(*mut c_void, usize) -> i32>(&CC_RANDOM_GENERATE_BYTES)(
            buffer, length,
        )
    }
}

/// `arc4random_buf` (man 3 arc4random): fills the buffer; "always successful", so it returns no
/// status.
#[cfg(target_os = "macos")]
unsafe extern "C" fn arc4random_buf(buffer: *mut c_void, length: usize) {
    if !virtual_random(buffer, length) {
        // SAFETY: ARC4RANDOM_BUF holds libc's arc4random_buf.
        unsafe {
            original::<unsafe extern "C" fn(*mut c_void, usize)>(&ARC4RANDOM_BUF)(buffer, length)
        }
    }
}

/// `arc4random` (man 3 arc4random): a single 32-bit random value.
#[cfg(target_os = "macos")]
unsafe extern "C" fn arc4random() -> u32 {
    let mut value = 0u32;
    if virtual_random((&raw mut value).cast(), size_of::<u32>()) {
        return value;
    }
    // SAFETY: ARC4RANDOM holds libc's arc4random.
    unsafe { original::<unsafe extern "C" fn() -> u32>(&ARC4RANDOM)() }
}

#[cfg(target_os = "macos")]
struct EnvSnapshot {
    values: Vec<std::ffi::CString>,
    pointers: Vec<*mut c_char>,
    head: *mut *mut c_char,
}

#[cfg(target_os = "macos")]
thread_local! {
    static ENV_SNAPSHOT: std::cell::RefCell<EnvSnapshot> = const { std::cell::RefCell::new(EnvSnapshot {
        values: Vec::new(), pointers: Vec::new(), head: std::ptr::null_mut(),
    }) };
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn ns_get_environ() -> *mut *mut *mut c_char {
    if let Some(Some(values)) = dispatch_env(|env| env.snapshot())
        && let Ok(ptr) = ENV_SNAPSHOT.try_with(|snapshot| {
            let mut snapshot = snapshot.borrow_mut();
            snapshot.values = values;
            snapshot.pointers = snapshot
                .values
                .iter()
                .map(|s| s.as_ptr() as *mut c_char)
                .collect();
            snapshot.pointers.push(std::ptr::null_mut());
            snapshot.head = snapshot.pointers.as_mut_ptr();
            &raw mut snapshot.head
        })
    {
        return ptr;
    }
    unsafe { original::<unsafe extern "C" fn() -> *mut *mut *mut c_char>(&NS_GET_ENVIRON)() }
}
