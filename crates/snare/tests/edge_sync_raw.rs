//! The raw OS synchronisation calls a sim hooks, pinned for the performance pass: pthread mutex
//! return codes (`EBUSY`, error-checking `EDEADLK`/`EPERM`) as the host gives them, condition
//! variable timed waits ending at their absolute virtual deadline, `sched_yield`, threads made with
//! a bare `pthread_create` joining the sim with the next lineage, and per OS the futex (Linux),
//! POSIX semaphore (Linux) and dispatch semaphore (macOS) answers and wake counts.
#![cfg(unix)]

use std::mem::MaybeUninit;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use snare::Sim;

/// A heap pthread mutex of `kind`, initialised and destroyed with the value.
struct RawMutex(Box<libc::pthread_mutex_t>);

impl RawMutex {
    fn new(kind: libc::c_int) -> Self {
        let mut attr = MaybeUninit::<libc::pthread_mutexattr_t>::uninit();
        let mut mutex = Box::new(unsafe { std::mem::zeroed::<libc::pthread_mutex_t>() });
        // SAFETY: attr and mutex are valid storage, initialised before use and destroyed after.
        unsafe {
            assert_eq!(libc::pthread_mutexattr_init(attr.as_mut_ptr()), 0);
            assert_eq!(libc::pthread_mutexattr_settype(attr.as_mut_ptr(), kind), 0);
            assert_eq!(libc::pthread_mutex_init(&mut *mutex, attr.as_ptr()), 0);
            libc::pthread_mutexattr_destroy(attr.as_mut_ptr());
        }
        Self(mutex)
    }

    fn ptr(&self) -> *mut libc::pthread_mutex_t {
        ptr::from_ref(&*self.0).cast_mut()
    }

    fn lock(&self) -> libc::c_int {
        // SAFETY: an initialised mutex.
        unsafe { libc::pthread_mutex_lock(self.ptr()) }
    }

    fn trylock(&self) -> libc::c_int {
        // SAFETY: an initialised mutex.
        unsafe { libc::pthread_mutex_trylock(self.ptr()) }
    }

    fn unlock(&self) -> libc::c_int {
        // SAFETY: an initialised mutex.
        unsafe { libc::pthread_mutex_unlock(self.ptr()) }
    }
}

impl Drop for RawMutex {
    fn drop(&mut self) {
        // SAFETY: initialised in `new`, unlocked by every user before the drop.
        unsafe { libc::pthread_mutex_destroy(self.ptr()) };
    }
}

// SAFETY: pthread mutexes are made to be shared between threads.
unsafe impl Send for RawMutex {}
// SAFETY: as above.
unsafe impl Sync for RawMutex {}

/// The return codes of a fixed sequence of calls on a default and an error-checking mutex, one
/// call of it made on another thread.
fn mutex_codes(relock: bool) -> Vec<(&'static str, libc::c_int)> {
    let normal = Arc::new(RawMutex::new(libc::PTHREAD_MUTEX_NORMAL));
    let checked = Arc::new(RawMutex::new(libc::PTHREAD_MUTEX_ERRORCHECK));
    let mut codes = vec![
        ("normal lock", normal.lock()),
        ("normal trylock while held", normal.trylock()),
    ];
    let other = normal.clone();
    codes.push((
        "normal trylock from another thread",
        std::thread::spawn(move || other.trylock()).join().unwrap(),
    ));
    codes.push(("normal unlock", normal.unlock()));
    codes.push(("normal trylock free", normal.trylock()));
    codes.push(("normal unlock", normal.unlock()));
    codes.push(("checked lock", checked.lock()));
    if relock {
        codes.push(("checked relock", checked.lock()));
    }
    codes.push(("checked trylock while held", checked.trylock()));
    let other = checked.clone();
    codes.push((
        "checked unlock from another thread",
        std::thread::spawn(move || other.unlock()).join().unwrap(),
    ));
    codes.push(("checked unlock", checked.unlock()));
    codes.push(("checked unlock again", checked.unlock()));
    codes
}

#[test]
fn mutex_return_codes_os_truth() {
    let real = snare::real(|| mutex_codes(true));
    let sim = Sim::new().run(|| mutex_codes(true));
    assert_eq!(sim, real);
    assert_eq!(
        real.iter().map(|(_, c)| *c).collect::<Vec<_>>(),
        [
            0,
            libc::EBUSY,
            libc::EBUSY,
            0,
            0,
            0,
            0,
            libc::EDEADLK,
            libc::EBUSY,
            libc::EPERM,
            0,
            libc::EPERM
        ]
    );
    let real = snare::real(|| mutex_codes(false));
    let det = Sim::builder()
        .deterministic()
        .build()
        .run(|| mutex_codes(false));
    assert_eq!(det, real);
}

/// Runs `f` on its own thread and fails if it takes longer than `limit`, so a hang fails the test.
fn within<R: Send + 'static>(
    limit: Duration,
    what: &str,
    f: impl FnOnce() -> R + Send + 'static,
) -> R {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(limit) {
        Ok(r) => r,
        Err(_) => panic!("{what} did not finish within {limit:?}"),
    }
}

#[test]
fn an_error_checking_relock_is_edeadlk_under_the_schedule_os_truth() {
    let real = snare::real(|| mutex_codes(true));
    let det = within(Duration::from_secs(10), "the relock", || {
        Sim::builder()
            .deterministic()
            .build()
            .run(|| mutex_codes(true))
    });
    assert_eq!(det, real);
}

#[test]
fn a_trylock_storm_keeps_the_lock_consistent() {
    let wins = Sim::builder().deterministic().seed(3).build().run(|| {
        let mutex = Arc::new(RawMutex::new(libc::PTHREAD_MUTEX_NORMAL));
        let inside = Arc::new(AtomicU32::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (mutex, inside) = (mutex.clone(), inside.clone());
                std::thread::spawn(move || {
                    let mut won = 0u32;
                    for _ in 0..200 {
                        match mutex.trylock() {
                            0 => {
                                assert_eq!(inside.fetch_add(1, Ordering::SeqCst), 0);
                                // SAFETY: sched_yield has no preconditions.
                                unsafe { libc::sched_yield() };
                                inside.fetch_sub(1, Ordering::SeqCst);
                                assert_eq!(mutex.unlock(), 0);
                                won += 1;
                            }
                            code => assert_eq!(code, libc::EBUSY),
                        }
                        // SAFETY: as above.
                        unsafe { libc::sched_yield() };
                    }
                    won
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(wins.len(), 8);
    assert!(wins.iter().sum::<u32>() > 0);
}

/// `CLOCK_REALTIME` now plus `after`, as a timespec.
fn realtime_after(after: Duration) -> libc::timespec {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a valid out-pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
    let total = Duration::new(now.tv_sec as u64, now.tv_nsec as u32) + after;
    libc::timespec {
        tv_sec: total.as_secs() as libc::time_t,
        tv_nsec: total.subsec_nanos() as libc::c_long,
    }
}

/// A `pthread_cond_timedwait` with no signaller, `after` from now: its code and how long it took
/// on the sim's clock.
fn timed_cond_wait(after: Duration) -> (libc::c_int, Duration) {
    let mutex = RawMutex::new(libc::PTHREAD_MUTEX_NORMAL);
    let mut cond = Box::new(unsafe { std::mem::zeroed::<libc::pthread_cond_t>() });
    // SAFETY: valid storage; default attributes.
    assert_eq!(
        unsafe { libc::pthread_cond_init(&mut *cond, ptr::null()) },
        0
    );
    assert_eq!(mutex.lock(), 0);
    let deadline = realtime_after(after);
    let start = snare::sched::now();
    // SAFETY: an initialised condvar and the mutex this thread holds.
    let code = unsafe { libc::pthread_cond_timedwait(&mut *cond, mutex.ptr(), &deadline) };
    let took = snare::sched::now() - start;
    assert_eq!(mutex.unlock(), 0);
    // SAFETY: no thread waits on it any more.
    unsafe { libc::pthread_cond_destroy(&mut *cond) };
    (code, took)
}

#[test]
fn a_cond_timedwait_ends_at_its_absolute_virtual_deadline() {
    let det = Sim::builder().deterministic().build().run(|| {
        (
            timed_cond_wait(Duration::from_millis(250)),
            timed_cond_wait(Duration::ZERO),
            // SAFETY: sched_yield has no preconditions.
            unsafe { libc::sched_yield() },
        )
    });
    assert_eq!(det.0.0, libc::ETIMEDOUT);
    assert_eq!(
        det.0.1,
        Duration::from_millis(250) + Duration::from_nanos(1)
    );
    assert_eq!(det.1.0, libc::ETIMEDOUT);
    assert!(det.1.1 < Duration::from_micros(10), "{:?}", det.1.1);
    assert_eq!(det.2, 0);
}

#[test]
fn a_cond_timedwait_on_the_plain_clock_waits_out_its_virtual_deadline() {
    let real = Instant::now();
    let plain = Sim::new().run(|| timed_cond_wait(Duration::from_secs(30)));
    assert_eq!(plain.0, libc::ETIMEDOUT);
    assert!(
        plain.1 >= Duration::from_secs(30)
            && plain.1 < Duration::from_secs(30) + Duration::from_millis(5),
        "{:?}",
        plain.1
    );
    assert!(real.elapsed() < Duration::from_secs(20));
}

#[test]
fn a_signal_with_no_waiter_is_lost_and_a_waiter_is_woken_by_the_next() {
    let codes = Sim::builder().deterministic().build().run(|| {
        let state = Arc::new((
            RawMutex::new(libc::PTHREAD_MUTEX_NORMAL),
            CondCell::new(),
            AtomicU32::new(0),
        ));
        let lost = state.1.signal();
        let waiter = {
            let state = state.clone();
            std::thread::spawn(move || {
                let (mutex, cond, flag) = &*state;
                assert_eq!(mutex.lock(), 0);
                let mut waits = 0;
                while flag.load(Ordering::SeqCst) == 0 {
                    waits += 1;
                    assert_eq!(cond.wait(mutex), 0);
                }
                assert_eq!(mutex.unlock(), 0);
                waits
            })
        };
        std::thread::sleep(Duration::from_millis(1));
        let (mutex, cond, flag) = &*state;
        assert_eq!(mutex.lock(), 0);
        flag.store(1, Ordering::SeqCst);
        let signalled = cond.signal();
        assert_eq!(mutex.unlock(), 0);
        (lost, signalled, waiter.join().unwrap())
    });
    assert_eq!(codes, (0, 0, 1), "one wait, no spurious wakes");
}

/// A heap pthread condition variable.
struct CondCell(Box<libc::pthread_cond_t>);

impl CondCell {
    fn new() -> Self {
        let mut cond = Box::new(unsafe { std::mem::zeroed::<libc::pthread_cond_t>() });
        // SAFETY: valid storage; default attributes.
        assert_eq!(
            unsafe { libc::pthread_cond_init(&mut *cond, ptr::null()) },
            0
        );
        Self(cond)
    }

    fn ptr(&self) -> *mut libc::pthread_cond_t {
        ptr::from_ref(&*self.0).cast_mut()
    }

    fn signal(&self) -> libc::c_int {
        // SAFETY: an initialised condvar.
        unsafe { libc::pthread_cond_signal(self.ptr()) }
    }

    fn wait(&self, mutex: &RawMutex) -> libc::c_int {
        // SAFETY: an initialised condvar and a mutex the caller holds.
        unsafe { libc::pthread_cond_wait(self.ptr(), mutex.ptr()) }
    }
}

impl Drop for CondCell {
    fn drop(&mut self) {
        // SAFETY: no waiter is left.
        unsafe { libc::pthread_cond_destroy(self.ptr()) };
    }
}

// SAFETY: pthread condition variables are made to be shared between threads.
unsafe impl Send for CondCell {}
// SAFETY: as above.
unsafe impl Sync for CondCell {}

extern "C" fn raw_child(argument: *mut libc::c_void) -> *mut libc::c_void {
    let out = argument.cast::<(bool, u64)>();
    // SAFETY: the creator passes a live, exclusive (bool, u64) and joins before reading it.
    unsafe { *out = (snare::sched::in_sim(), snare_interpose::thread_lineage()) };
    0x5a as *mut libc::c_void
}

/// Creates a thread with a bare `pthread_create`, joins it, and returns what it saw and what the
/// join returned.
fn raw_thread() -> ((bool, u64), usize, libc::c_int) {
    let mut seen = (false, u64::MAX);
    let mut thread = MaybeUninit::<libc::pthread_t>::uninit();
    // SAFETY: `raw_child` writes `seen`, which outlives the join below.
    let created = unsafe {
        libc::pthread_create(
            thread.as_mut_ptr(),
            ptr::null(),
            raw_child,
            ptr::from_mut(&mut seen).cast(),
        )
    };
    assert_eq!(created, 0);
    let mut result = ptr::null_mut();
    // SAFETY: a joinable thread created above.
    let joined = unsafe { libc::pthread_join(thread.assume_init(), &mut result) };
    (seen, result as usize, joined)
}

#[test]
fn a_bare_pthread_create_joins_the_sim_with_the_next_lineage() {
    let seen = Sim::new().run(|| {
        let first = raw_thread();
        let spawned = std::thread::spawn(snare_interpose::thread_lineage)
            .join()
            .unwrap();
        let second = raw_thread();
        // SAFETY: joining oneself is reported, not carried out.
        let self_join = unsafe { libc::pthread_join(libc::pthread_self(), ptr::null_mut()) };
        (first, spawned, second, self_join)
    });
    let mix = |parent: u64, order: u64| {
        let mut z = parent ^ order.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    assert_eq!(seen.0, ((true, mix(0, 1)), 0x5a, 0));
    assert_eq!(seen.1, mix(0, 2));
    assert_eq!(seen.2, ((true, mix(0, 3)), 0x5a, 0));
    assert_eq!(seen.3, libc::EDEADLK);
    let off = raw_thread();
    assert_eq!(off, ((false, 0), 0x5a, 0));
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    fn futex(
        word: &AtomicU32,
        op: libc::c_int,
        value: u32,
        timeout: Option<&libc::timespec>,
    ) -> (libc::c_long, i32) {
        // SAFETY: a valid futex word; the timeout, if any, outlives the call.
        let r = unsafe {
            libc::syscall(
                libc::SYS_futex,
                word.as_ptr(),
                op | libc::FUTEX_PRIVATE_FLAG,
                value,
                timeout.map_or(ptr::null(), ptr::from_ref),
                ptr::null::<u32>(),
                0u32,
            )
        };
        let errno = if r == -1 {
            std::io::Error::last_os_error().raw_os_error().unwrap()
        } else {
            0
        };
        (r, errno)
    }

    fn futex_codes() -> Vec<(libc::c_long, i32)> {
        let word = AtomicU32::new(1);
        let short = libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        };
        vec![
            futex(&word, libc::FUTEX_WAIT, 0, None),
            futex(&word, libc::FUTEX_WAIT, 1, Some(&short)),
            futex(&word, libc::FUTEX_WAKE, 1, None),
            futex(&word, libc::FUTEX_WAKE, i32::MAX as u32, None),
        ]
    }

    fn futex_masked(
        word: &AtomicU32,
        op: libc::c_int,
        count: u32,
        mask: u32,
    ) -> (libc::c_long, i32) {
        let result = unsafe {
            libc::syscall(
                libc::SYS_futex,
                word.as_ptr(),
                op | libc::FUTEX_PRIVATE_FLAG,
                count,
                ptr::null::<libc::timespec>(),
                ptr::null::<u32>(),
                mask,
            )
        };
        (
            result,
            if result < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap()
            } else {
                0
            },
        )
    }

    fn subset_wake() -> ((libc::c_long, i32), bool, (libc::c_long, i32)) {
        let word = Arc::new(AtomicU32::new(0));
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let child = {
            let word = word.clone();
            let done = done.clone();
            std::thread::spawn(move || {
                ready_tx.send(()).unwrap();
                let result = futex_masked(&word, libc::FUTEX_WAIT_BITSET, 0, 1);
                done.store(true, Ordering::SeqCst);
                result
            })
        };
        ready_rx.recv().unwrap();
        snare::real(|| std::thread::sleep(Duration::from_millis(10)));
        let mismatch = futex_masked(&word, libc::FUTEX_WAKE_BITSET, 1, 2);
        std::thread::yield_now();
        let early = done.load(Ordering::SeqCst);
        futex_masked(&word, libc::FUTEX_WAKE_BITSET, 1, 1);
        (mismatch, early, child.join().unwrap())
    }

    #[test]
    fn futex_subset_masks_os_truth() {
        let native = snare::real(subset_wake);
        assert_eq!(native, ((0, 0), false, (0, 0)));
        for sim in [Sim::new(), Sim::builder().deterministic().build()] {
            assert_eq!(sim.run(subset_wake), native);
        }
    }

    fn futex_key_spaces() -> ((libc::c_long, i32), usize, (libc::c_long, i32), usize) {
        let word = Arc::new(AtomicU32::new(0));
        let call = |word: &AtomicU32, operation: i32, private: bool, value: u32| {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    word.as_ptr(),
                    operation | if private { libc::FUTEX_PRIVATE_FLAG } else { 0 },
                    value,
                    ptr::null::<libc::timespec>(),
                    ptr::null::<u32>(),
                    u32::MAX,
                )
            };
            (
                result,
                if result < 0 {
                    std::io::Error::last_os_error().raw_os_error().unwrap()
                } else {
                    0
                },
            )
        };
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let mut children = Vec::new();
        for (id, private) in [(0, false), (1, true)] {
            let word = word.clone();
            let ready_tx = ready_tx.clone();
            let done_tx = done_tx.clone();
            children.push(std::thread::spawn(move || {
                ready_tx.send(()).unwrap();
                let result = call(&word, libc::FUTEX_WAIT_BITSET, private, 0u32);
                done_tx.send(id).unwrap();
                result
            }));
            ready_rx.recv().unwrap();
            snare::real(|| std::thread::sleep(Duration::from_millis(5)));
        }
        let private = call(&word, libc::FUTEX_WAKE_BITSET, true, 1u32);
        let first = done_rx.recv().unwrap();
        let shared = call(&word, libc::FUTEX_WAKE_BITSET, false, 1u32);
        let second = done_rx.recv().unwrap();
        for child in children {
            assert_eq!(child.join().unwrap(), (0, 0));
        }
        (private, first, shared, second)
    }

    #[test]
    fn private_and_shared_futex_keys_wake_separate_cohorts_os_truth() {
        within(Duration::from_secs(5), "futex key spaces", || {
            let native = snare::real(futex_key_spaces);
            assert_eq!(native, ((1, 0), 1, (1, 0), 0));
            for sim in [Sim::new(), Sim::builder().deterministic().build()] {
                assert_eq!(sim.run(futex_key_spaces), native);
            }
        });
    }

    fn rejected_futex_wake(
        operation: i32,
        mode: u32,
    ) -> ((libc::c_long, i32), bool, (libc::c_long, i32)) {
        let word = Arc::new(AtomicU32::new(0));
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let child = {
            let word = word.clone();
            let done = done.clone();
            std::thread::spawn(move || {
                ready_tx.send(()).unwrap();
                let result = futex_masked(&word, libc::FUTEX_WAIT_BITSET, 0, 1);
                done.store(true, Ordering::SeqCst);
                result
            })
        };
        ready_rx.recv().unwrap();
        snare::real(|| std::thread::sleep(Duration::from_millis(10)));
        let call = || futex_masked(&word, operation | libc::FUTEX_CLOCK_REALTIME, 1, 1);
        let rejected = if mode == 0 {
            call()
        } else {
            let _class =
                snare::sched::spawn_as(snare::sched::ThreadClass::Background, "rejected-wake");
            std::thread::scope(|scope| {
                scope
                    .spawn(|| if mode == 1 { call() } else { snare::real(call) })
                    .join()
                    .unwrap()
            })
        };
        snare::real(|| std::thread::sleep(Duration::from_millis(10)));
        std::thread::yield_now();
        let early = done.load(Ordering::SeqCst);
        futex_masked(&word, libc::FUTEX_WAKE_BITSET, 1, 1);
        (rejected, early, child.join().unwrap())
    }

    #[test]
    fn rejected_futex_wakes_do_not_release_waiters_os_truth() {
        for operation in [libc::FUTEX_WAKE, libc::FUTEX_WAKE_BITSET] {
            for mode in 0..3 {
                let native = snare::real(|| rejected_futex_wake(operation, mode));
                assert_eq!(native, ((-1, libc::ENOSYS), false, (0, 0)));
                for sim in [Sim::new(), Sim::builder().deterministic().build()] {
                    assert_eq!(
                        sim.run(|| rejected_futex_wake(operation, mode)),
                        native,
                        "op={operation} mode={mode}"
                    );
                }
            }
        }
    }

    fn nonpositive_wake_count(count: u32) -> (libc::c_long, i32) {
        let word = Arc::new(AtomicU32::new(0));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let child = {
            let word = word.clone();
            std::thread::spawn(move || {
                ready_tx.send(()).unwrap();
                futex_masked(&word, libc::FUTEX_WAIT_BITSET, 0, 1)
            })
        };
        ready_rx.recv().unwrap();
        snare::real(|| std::thread::sleep(Duration::from_millis(10)));
        let woke = futex_masked(&word, libc::FUTEX_WAKE_BITSET, count, 1);
        futex_masked(&word, libc::FUTEX_WAKE_BITSET, 1, 1);
        assert_eq!(child.join().unwrap(), (0, 0));
        woke
    }

    #[test]
    fn nonpositive_legacy_futex_wake_counts_os_truth() {
        for count in [0, u32::MAX] {
            let native = snare::real(|| nonpositive_wake_count(count));
            assert_eq!(native, (1, 0));
            for sim in [Sim::new(), Sim::builder().deterministic().build()] {
                assert_eq!(sim.run(|| nonpositive_wake_count(count)), native);
            }
        }
    }

    fn repeated_masked_wake(
        stage: &std::sync::atomic::AtomicBool,
    ) -> (i64, [(libc::c_long, i32); 2]) {
        let word = Arc::new(AtomicU32::new(0));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let children = [1, 2].map(|mask| {
            let word = word.clone();
            let ready_tx = ready_tx.clone();
            std::thread::spawn(move || {
                ready_tx.send(()).unwrap();
                futex_masked(&word, libc::FUTEX_WAIT_BITSET, 0, mask)
            })
        });
        ready_rx.recv().unwrap();
        ready_rx.recv().unwrap();
        snare::real(|| std::thread::sleep(Duration::from_millis(10)));
        let mut wakes = 0;
        for _ in 0..1_000 {
            let (count, error) = futex_masked(&word, libc::FUTEX_WAKE_BITSET, 1, 1);
            assert_eq!(error, 0);
            wakes += count;
        }
        let [first, second] = children;
        let first = first.join().unwrap();
        stage.store(true, Ordering::Release);
        std::thread::sleep(Duration::from_millis(1));
        futex_masked(&word, libc::FUTEX_WAKE_BITSET, 1, 2);
        (wakes, [first, second.join().unwrap()])
    }

    #[test]
    fn repeated_masked_wakes_leave_no_credit_for_an_untouched_waiter_os_truth() {
        use snare::sched::{ExecutiveConfig, Quiescence};
        let native =
            snare::real(|| repeated_masked_wake(&std::sync::atomic::AtomicBool::new(false)));
        assert_eq!(native, (1, [(0, 0), (0, 0)]));
        for _ in 0..16 {
            let sim = Sim::new();
            let executive = sim.executive(ExecutiveConfig::default()).unwrap();
            let stage = std::sync::atomic::AtomicBool::new(false);
            let (result, settled) = std::thread::scope(|scope| {
                let run = scope.spawn(|| sim.run(|| repeated_masked_wake(&stage)));
                let start = snare::real(Instant::now);
                let mut settled = false;
                let mut last: Option<Quiescence> = None;
                while snare::real(|| start.elapsed()) < Duration::from_secs(2) {
                    let q = executive.quiescence();
                    if stage.load(Ordering::Acquire)
                        && q.quiescent
                        && q.blocked == 2
                        && let Some(deadline) = q.next_deadline
                        && executive.jump_to(deadline).is_ok()
                    {
                        settled = true;
                        break;
                    }
                    last = Some(q);
                    snare::real(|| std::thread::sleep(Duration::from_micros(50)));
                }
                executive.detach();
                (run.join().unwrap(), (settled, last))
            });
            assert_eq!(result, native);
            assert!(settled.0, "{settled:?}");
        }
    }

    fn readonly_shared_futex() -> (libc::c_long, i32) {
        unsafe {
            let memory = libc::mmap(
                ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(memory, libc::MAP_FAILED);
            memory.cast::<u32>().write(1);
            assert_eq!(libc::mprotect(memory, 4096, libc::PROT_READ), 0);
            let result = libc::syscall(
                libc::SYS_futex,
                memory,
                libc::FUTEX_WAIT,
                0u32,
                ptr::null::<libc::timespec>(),
                ptr::null::<u32>(),
                u32::MAX,
            );
            let error = if result < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap()
            } else {
                0
            };
            assert_eq!(libc::munmap(memory, 4096), 0);
            (result, error)
        }
    }

    #[test]
    fn shared_futex_key_validation_precedes_comparand_mismatch_os_truth() {
        let native = snare::real(readonly_shared_futex);
        assert_eq!(native, (-1, libc::EFAULT));
        for sim in [Sim::new(), Sim::builder().deterministic().build()] {
            assert_eq!(sim.run(readonly_shared_futex), native);
        }
    }

    #[test]
    fn masked_futex_wakes_preserve_the_order_of_skipped_waiters() {
        let got = Sim::builder().deterministic().build().run(|| {
            let word = Arc::new(AtomicU32::new(0));
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let mut children = Vec::new();
            for (id, mask) in [1, 2, 1].into_iter().enumerate() {
                let word = word.clone();
                let ready_tx = ready_tx.clone();
                let done_tx = done_tx.clone();
                children.push(std::thread::spawn(move || {
                    ready_tx.send(()).unwrap();
                    let result = futex_masked(&word, libc::FUTEX_WAIT_BITSET, 0, mask);
                    done_tx.send((id, result)).unwrap();
                }));
                ready_rx.recv().unwrap();
                std::thread::yield_now();
            }
            let mut got = Vec::new();
            for mask in [2, 1, 1] {
                let count = futex_masked(&word, libc::FUTEX_WAKE_BITSET, 1, mask);
                got.push((count, done_rx.recv().unwrap()));
            }
            for child in children {
                child.join().unwrap();
            }
            got
        });
        assert_eq!(
            got,
            [
                ((1, 0), (1, (0, 0))),
                ((1, 0), (0, (0, 0))),
                ((1, 0), (2, (0, 0)))
            ]
        );
    }

    #[test]
    fn futex_codes_os_truth() {
        let real = snare::real(futex_codes);
        let sim = Sim::new().run(futex_codes);
        assert_eq!(sim, real);
        assert_eq!(
            real,
            [(-1, libc::EAGAIN), (-1, libc::ETIMEDOUT), (0, 0), (0, 0)]
        );
    }

    #[test]
    fn waking_an_all_ones_futex_preserves_the_callers_word() {
        within(Duration::from_secs(5), "all-ones futex", || {
            for deterministic in [false, true] {
                let builder = Sim::builder();
                let sim = if deterministic {
                    builder.deterministic().build()
                } else {
                    builder.build()
                };
                sim.run(|| {
                    for _ in 0..32 {
                        let word = Arc::new(AtomicU32::new(u32::MAX));
                        let child_word = word.clone();
                        let (tx, rx) = std::sync::mpsc::channel();
                        let child = std::thread::spawn(move || {
                            tx.send(()).unwrap();
                            futex(&child_word, libc::FUTEX_WAIT, u32::MAX, None)
                        });
                        rx.recv().unwrap();
                        if deterministic {
                            std::thread::sleep(Duration::from_millis(1));
                        } else {
                            snare::real(|| std::thread::sleep(Duration::from_millis(2)));
                        }
                        word.store(0, Ordering::Release);
                        futex(&word, libc::FUTEX_WAKE, 1, None);
                        let result = child.join().unwrap();
                        assert!(result == (0, 0) || result == (-1, libc::EAGAIN));
                        assert_eq!(word.load(Ordering::Acquire), 0);
                    }
                });
            }
        });
    }

    #[test]
    fn contended_readers_and_writers_release_the_rwlock() {
        within(Duration::from_secs(5), "contended RwLock", || {
            Sim::new().run(|| {
                for _ in 0..32 {
                    let lock = Arc::new(std::sync::RwLock::new(0u32));
                    let held = lock.write().unwrap();
                    let (tx, rx) = std::sync::mpsc::channel();
                    let reader_lock = lock.clone();
                    let reader_tx = tx.clone();
                    let reader = std::thread::spawn(move || {
                        reader_tx.send(()).unwrap();
                        *reader_lock.read().unwrap()
                    });
                    let writer_lock = lock.clone();
                    let writer = std::thread::spawn(move || {
                        tx.send(()).unwrap();
                        *writer_lock.write().unwrap() = 1;
                    });
                    rx.recv().unwrap();
                    rx.recv().unwrap();
                    snare::real(|| std::thread::sleep(Duration::from_millis(2)));
                    drop(held);
                    assert!(reader.join().unwrap() <= 1);
                    writer.join().unwrap();
                    assert_eq!(*lock.read().unwrap(), 1);
                    *lock.write().unwrap() = 2;
                }
            });
        });
    }

    #[test]
    fn futex_wake_counts_the_waiters_it_woke() {
        let counts = Sim::builder().deterministic().build().run(|| {
            let word = Arc::new(AtomicU32::new(0));
            let waiters: Vec<_> = (0..3)
                .map(|_| {
                    let word = word.clone();
                    std::thread::spawn(move || {
                        while word.load(Ordering::SeqCst) == 0 {
                            futex(&word, libc::FUTEX_WAIT, 0, None);
                        }
                    })
                })
                .collect();
            std::thread::sleep(Duration::from_millis(1));
            word.store(1, Ordering::SeqCst);
            let one = futex(&word, libc::FUTEX_WAKE, 1, None);
            let rest = futex(&word, libc::FUTEX_WAKE, i32::MAX as u32, None);
            for w in waiters {
                w.join().unwrap();
            }
            (one, rest)
        });
        assert_eq!(counts, ((1, 0), (2, 0)));
    }

    #[test]
    fn a_futex_wait_times_out_on_virtual_time() {
        let took = Sim::builder().deterministic().build().run(|| {
            let word = AtomicU32::new(0);
            let timeout = libc::timespec {
                tv_sec: 3,
                tv_nsec: 0,
            };
            let start = snare::sched::now();
            let r = futex(&word, libc::FUTEX_WAIT, 0, Some(&timeout));
            (r, snare::sched::now() - start)
        });
        assert_eq!(took.0, (-1, libc::ETIMEDOUT));
        assert_eq!(took.1, Duration::from_secs(3) + Duration::from_nanos(1));
    }

    fn sem_codes() -> Vec<(libc::c_int, i32)> {
        let mut sem = Box::new(MaybeUninit::<libc::sem_t>::uninit());
        let sem = sem.as_mut_ptr();
        let errno = |r: libc::c_int| {
            (
                r,
                if r == -1 {
                    std::io::Error::last_os_error().raw_os_error().unwrap()
                } else {
                    0
                },
            )
        };
        // SAFETY: `sem` is valid storage, initialised first and destroyed last.
        unsafe {
            let mut codes = vec![errno(libc::sem_init(sem, 0, 0))];
            codes.push(errno(libc::sem_trywait(sem)));
            codes.push(errno(libc::sem_post(sem)));
            codes.push(errno(libc::sem_post(sem)));
            codes.push(errno(libc::sem_trywait(sem)));
            codes.push(errno(libc::sem_wait(sem)));
            codes.push(errno(libc::sem_trywait(sem)));
            let past = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            codes.push(errno(libc::sem_timedwait(sem, &past)));
            let bad = libc::timespec {
                tv_sec: 0,
                tv_nsec: 2_000_000_000,
            };
            codes.push(errno(libc::sem_timedwait(sem, &bad)));
            codes.push(errno(libc::sem_destroy(sem)));
            codes
        }
    }

    #[test]
    fn semaphore_codes_os_truth() {
        let real = snare::real(sem_codes);
        let sim = Sim::new().run(sem_codes);
        assert_eq!(sim, real);
        assert_eq!(
            real,
            [
                (0, 0),
                (-1, libc::EAGAIN),
                (0, 0),
                (0, 0),
                (0, 0),
                (0, 0),
                (-1, libc::EAGAIN),
                (-1, libc::ETIMEDOUT),
                (-1, libc::EINVAL),
                (0, 0)
            ]
        );
    }

    #[test]
    fn a_sem_timedwait_ends_at_its_absolute_virtual_deadline() {
        let took = Sim::builder().deterministic().build().run(|| {
            let mut sem = Box::new(MaybeUninit::<libc::sem_t>::uninit());
            let sem = sem.as_mut_ptr();
            // SAFETY: valid storage.
            assert_eq!(unsafe { libc::sem_init(sem, 0, 0) }, 0);
            let deadline = realtime_after(Duration::from_millis(40));
            let start = snare::sched::now();
            // SAFETY: an initialised semaphore and a valid deadline.
            let r = unsafe { libc::sem_timedwait(sem, &deadline) };
            let errno = std::io::Error::last_os_error().raw_os_error();
            let took = snare::sched::now() - start;
            // SAFETY: no waiter is left.
            unsafe { libc::sem_destroy(sem) };
            (r, errno, took)
        });
        assert_eq!((took.0, took.1), (-1, Some(libc::ETIMEDOUT)));
        assert_eq!(took.2, Duration::from_millis(40) + Duration::from_nanos(1));
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    #[allow(non_camel_case_types)]
    type dispatch_semaphore_t = *mut std::ffi::c_void;

    unsafe extern "C" {
        fn dispatch_semaphore_create(value: isize) -> dispatch_semaphore_t;
        fn dispatch_semaphore_wait(sema: dispatch_semaphore_t, timeout: u64) -> isize;
        fn dispatch_semaphore_signal(sema: dispatch_semaphore_t) -> isize;
        fn dispatch_time(when: u64, delta: i64) -> u64;
        fn dispatch_release(object: *mut std::ffi::c_void);
    }

    const DISPATCH_TIME_NOW: u64 = 0;
    const DISPATCH_TIME_FOREVER: u64 = !0;

    struct Sema(dispatch_semaphore_t);

    // SAFETY: dispatch semaphores are made to be shared between threads.
    unsafe impl Send for Sema {}
    // SAFETY: as above.
    unsafe impl Sync for Sema {}

    impl Drop for Sema {
        fn drop(&mut self) {
            // SAFETY: created by dispatch_semaphore_create, released once.
            unsafe { dispatch_release(self.0) };
        }
    }

    fn sema_codes() -> Vec<isize> {
        // SAFETY: plain libdispatch calls on a semaphore this function owns.
        unsafe {
            let sema = Sema(dispatch_semaphore_create(0));
            vec![
                dispatch_semaphore_wait(sema.0, DISPATCH_TIME_NOW),
                dispatch_semaphore_signal(sema.0),
                dispatch_semaphore_wait(sema.0, DISPATCH_TIME_NOW),
                dispatch_semaphore_wait(sema.0, dispatch_time(DISPATCH_TIME_NOW, 1_000_000)),
            ]
        }
    }

    #[test]
    fn dispatch_semaphore_codes_os_truth() {
        let real = snare::real(sema_codes);
        let sim = Sim::new().run(sema_codes);
        assert_eq!(sim, real);
        assert_eq!(real[1..3], [0, 0]);
        assert!(real[0] != 0 && real[3] != 0, "{real:?}");
    }

    #[test]
    fn a_dispatch_wait_times_out_on_virtual_time() {
        let seen = Sim::builder().deterministic().build().run(|| {
            // SAFETY: as above.
            let sema = Sema(unsafe { dispatch_semaphore_create(0) });
            let start = snare::sched::now();
            // SAFETY: as above.
            let timed_out = unsafe {
                dispatch_semaphore_wait(sema.0, dispatch_time(DISPATCH_TIME_NOW, 2_000_000_000))
            };
            (timed_out != 0, snare::sched::now() - start)
        });
        assert_eq!(
            seen,
            (true, Duration::from_secs(2) + Duration::from_nanos(1))
        );
    }

    /// A waiter blocks forever on a fresh semaphore, `settle` gives it time to block, and the
    /// signal that wakes it reports what it returned.
    fn signal_a_blocked_waiter(settle: Duration) -> (isize, isize) {
        // SAFETY: as above.
        let sema = Arc::new(Sema(unsafe { dispatch_semaphore_create(0) }));
        let waiter = {
            let sema = sema.clone();
            // SAFETY: as above.
            std::thread::spawn(move || unsafe {
                dispatch_semaphore_wait(sema.0, DISPATCH_TIME_FOREVER)
            })
        };
        std::thread::sleep(settle);
        // SAFETY: as above.
        let woke = unsafe { dispatch_semaphore_signal(sema.0) };
        (woke, waiter.join().unwrap())
    }

    #[test]
    fn a_signal_that_wakes_a_waiter_returns_nonzero_on_the_host() {
        assert_eq!(
            snare::real(|| signal_a_blocked_waiter(Duration::from_millis(50))),
            (1, 0)
        );
    }

    #[test]
    fn a_signal_that_wakes_a_waiter_returns_nonzero_in_the_sim() {
        let det = Sim::builder()
            .deterministic()
            .build()
            .run(|| signal_a_blocked_waiter(Duration::from_millis(1)));
        assert_eq!(det, (1, 0));
    }

    #[test]
    fn a_signal_that_wakes_a_waiter_os_truth() {
        let real = snare::real(|| signal_a_blocked_waiter(Duration::from_millis(50)));
        let det = Sim::builder()
            .deterministic()
            .build()
            .run(|| signal_a_blocked_waiter(Duration::from_millis(1)));
        assert_eq!(det, real);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn a_monotonic_condvar_times_out_on_its_virtual_clock() {
    for sim in [Sim::new(), Sim::builder().deterministic().build()] {
        sim.run(|| unsafe {
            let mutex = RawMutex::new(libc::PTHREAD_MUTEX_NORMAL);
            let mut attr = MaybeUninit::<libc::pthread_condattr_t>::uninit();
            let mut cond = MaybeUninit::<libc::pthread_cond_t>::uninit();
            assert_eq!(libc::pthread_condattr_init(attr.as_mut_ptr()), 0);
            assert_eq!(
                libc::pthread_condattr_setclock(attr.as_mut_ptr(), libc::CLOCK_MONOTONIC),
                0
            );
            assert_eq!(libc::pthread_cond_init(cond.as_mut_ptr(), attr.as_ptr()), 0);
            assert_eq!(libc::pthread_condattr_destroy(attr.as_mut_ptr()), 0);
            let mut deadline = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            assert_eq!(libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut deadline), 0);
            deadline.tv_sec += 30;
            assert_eq!(mutex.lock(), 0);
            let start = snare::sched::now();
            assert_eq!(
                libc::pthread_cond_timedwait(cond.as_mut_ptr(), mutex.ptr(), &deadline),
                libc::ETIMEDOUT
            );
            assert_eq!(
                snare::sched::now() - start,
                Duration::from_secs(30) + Duration::from_nanos(1)
            );
            assert_eq!(mutex.unlock(), 0);
            assert_eq!(libc::pthread_cond_destroy(cond.as_mut_ptr()), 0);
        });
    }
}
