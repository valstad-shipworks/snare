//! A participant blocked on a pthread mutex that a thread outside the simulation holds is waiting
//! on the world, not on the domain: nothing a participant does will make that holder let go, so
//! the domain is not quiescent and time does not skip past a sleeper's deadline while it waits. A
//! mutex a participant holds still leaves the waiter parked, so a holder sleeping on virtual time
//! with the lock held is time-skipped as before.
//!
//! std's `Mutex` is a pthread mutex on macOS but a futex on Linux, whose word names no holder, so
//! the raw pthread mutex below is what both platforms share.
//!
//! On Windows the raw lock is an SRW lock, taken exclusively; the hooks track its holder like
//! a pthread mutex. std's `Mutex` uses `WaitOnAddress`, whose word names no holder.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use snare::{Sim, SimBuilder};

/// The sleeper's deadline, in virtual time.
const DEADLINE: Duration = Duration::from_millis(100);

/// How long, in real time, the outside holder keeps the lock once the waiter is about to take it:
/// long enough for the waiter to block on it and for a time skip to land if one could.
const OUTSIDE_HOLD: Duration = Duration::from_millis(30);

/// A pthread mutex shared between threads.
#[cfg(unix)]
struct RawMutex(UnsafeCell<libc::pthread_mutex_t>);

/// An SRW lock shared between threads, taken exclusively.
#[cfg(windows)]
struct RawMutex(UnsafeCell<windows_sys::Win32::System::Threading::SRWLOCK>);

// SAFETY: a pthread mutex or SRW lock is made to be locked and unlocked from any thread.
unsafe impl Sync for RawMutex {}
// SAFETY: as above; it is never moved while locked.
unsafe impl Send for RawMutex {}

#[cfg(unix)]
impl RawMutex {
    fn new() -> Arc<Self> {
        Arc::new(Self(UnsafeCell::new(libc::PTHREAD_MUTEX_INITIALIZER)))
    }

    fn lock(&self) {
        // SAFETY: an initialized mutex, never moved.
        assert_eq!(unsafe { libc::pthread_mutex_lock(self.0.get()) }, 0);
    }

    fn unlock(&self) {
        // SAFETY: as above, held by the calling thread.
        assert_eq!(unsafe { libc::pthread_mutex_unlock(self.0.get()) }, 0);
    }
}

#[cfg(windows)]
impl RawMutex {
    fn new() -> Arc<Self> {
        Arc::new(Self(UnsafeCell::new(
            windows_sys::Win32::System::Threading::SRWLOCK_INIT,
        )))
    }

    fn lock(&self) {
        // SAFETY: an initialized SRW lock, never moved.
        unsafe { windows_sys::Win32::System::Threading::AcquireSRWLockExclusive(self.0.get()) };
    }

    fn unlock(&self) {
        // SAFETY: as above, held exclusively by the calling thread.
        unsafe { windows_sys::Win32::System::Threading::ReleaseSRWLockExclusive(self.0.get()) };
    }
}

/// A clocking mode's name and how to build a sim in it.
type Mode = (&'static str, fn() -> SimBuilder);

fn builders() -> [Mode; 2] {
    [
        ("free-running", Sim::builder),
        ("deterministic", || Sim::builder().deterministic().seed(3)),
    ]
}

/// Inside a sim: a thread outside it holds a mutex until a participant is about to lock it and
/// [`OUTSIDE_HOLD`] after, while the root sleeps to [`DEADLINE`]. Returns the virtual time at
/// which the participant took the lock.
fn lock_held_outside() -> Duration {
    let mutex = RawMutex::new();
    let about_to_lock = Arc::new(AtomicBool::new(false));
    let (locked_tx, locked_rx) = mpsc::channel();
    let outsider = {
        let mutex = mutex.clone();
        let about_to_lock = about_to_lock.clone();
        snare::real(|| {
            std::thread::spawn(move || {
                mutex.lock();
                locked_tx.send(()).unwrap();
                while !about_to_lock.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                std::thread::sleep(OUTSIDE_HOLD);
                mutex.unlock();
            })
        })
    };
    locked_rx.recv().unwrap();
    let start = Instant::now();
    let waiter = {
        let mutex = mutex.clone();
        std::thread::spawn(move || {
            about_to_lock.store(true, Ordering::SeqCst);
            mutex.lock();
            let at = start.elapsed();
            mutex.unlock();
            at
        })
    };
    std::thread::sleep(DEADLINE);
    let locked_at = waiter.join().unwrap();
    snare::real(|| outsider.join().unwrap());
    locked_at
}

#[test]
fn a_lock_held_outside_the_sim_holds_time_still() {
    for (mode, builder) in builders() {
        let locked_at = builder().build().run(lock_held_outside);
        assert!(
            locked_at < DEADLINE,
            "{mode}: the waiter took the lock at {locked_at:?}, after the sleeper's deadline"
        );
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "not modelled: std's Mutex is a futex (Linux) or WaitOnAddress (Windows) word that names no holder, so a waiter on one held outside counts as parked"
)]
fn a_std_mutex_held_outside_the_sim_holds_time_still() {
    // std's Mutex is a pthread mutex on macOS (std's sys::sync::mutex::pthread).
    for (mode, builder) in builders() {
        let locked_at = builder().build().run(|| {
            let mutex = Arc::new(std::sync::Mutex::new(()));
            let about_to_lock = Arc::new(AtomicBool::new(false));
            let (locked_tx, locked_rx) = mpsc::channel();
            let outsider = {
                let mutex = mutex.clone();
                let about_to_lock = about_to_lock.clone();
                snare::real(|| {
                    std::thread::spawn(move || {
                        let guard = mutex.lock().unwrap();
                        locked_tx.send(()).unwrap();
                        while !about_to_lock.load(Ordering::SeqCst) {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        std::thread::sleep(OUTSIDE_HOLD);
                        drop(guard);
                    })
                })
            };
            locked_rx.recv().unwrap();
            let start = Instant::now();
            let waiter = std::thread::spawn(move || {
                about_to_lock.store(true, Ordering::SeqCst);
                let _guard = mutex.lock().unwrap();
                start.elapsed()
            });
            std::thread::sleep(DEADLINE);
            let locked_at = waiter.join().unwrap();
            snare::real(|| outsider.join().unwrap());
            locked_at
        });
        assert!(
            locked_at < DEADLINE,
            "{mode}: the waiter took the lock at {locked_at:?}, after the sleeper's deadline"
        );
    }
}

#[test]
fn a_lock_held_inside_while_its_holder_sleeps_still_lets_time_skip() {
    let real = Instant::now();
    for (mode, builder) in builders() {
        let (locked_at, slept) = builder().build().run(|| {
            let mutex = RawMutex::new();
            let (locked_tx, locked_rx) = mpsc::channel();
            let start = Instant::now();
            let holder = {
                let mutex = mutex.clone();
                std::thread::spawn(move || {
                    mutex.lock();
                    locked_tx.send(()).unwrap();
                    std::thread::sleep(Duration::from_secs(60));
                    mutex.unlock();
                })
            };
            locked_rx.recv().unwrap();
            mutex.lock();
            let locked_at = start.elapsed();
            mutex.unlock();
            holder.join().unwrap();
            (locked_at, start.elapsed())
        });
        assert!(
            locked_at >= Duration::from_secs(60),
            "{mode}: took the lock at {locked_at:?}, before its holder let go"
        );
        assert!(slept >= Duration::from_secs(60), "{mode}: {slept:?}");
    }
    assert!(
        real.elapsed() < Duration::from_secs(30),
        "ran as-fast-as-possible"
    );
}
