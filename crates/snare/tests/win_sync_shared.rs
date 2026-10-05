#![cfg(windows)]

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use snare::Sim;
use windows_sys::Win32::Foundation::{ERROR_TIMEOUT, GetLastError};
use windows_sys::Win32::System::Threading::*;

struct Locks {
    srw: UnsafeCell<SRWLOCK>,
    cs: UnsafeCell<CRITICAL_SECTION>,
    condition: UnsafeCell<CONDITION_VARIABLE>,
    ready: AtomicUsize,
}

unsafe impl Send for Locks {}
unsafe impl Sync for Locks {}

impl Locks {
    fn new() -> Arc<Self> {
        let locks = Arc::new(Self {
            srw: UnsafeCell::new(SRWLOCK::default()),
            cs: UnsafeCell::new(CRITICAL_SECTION::default()),
            condition: UnsafeCell::new(CONDITION_VARIABLE::default()),
            ready: AtomicUsize::new(0),
        });
        unsafe { InitializeCriticalSection(locks.cs.get()) };
        locks
    }

    fn take(&self, mode: u32) {
        unsafe {
            match mode {
                0 => EnterCriticalSection(self.cs.get()),
                1 => AcquireSRWLockExclusive(self.srw.get()),
                2 => AcquireSRWLockShared(self.srw.get()),
                _ => unreachable!(),
            }
        }
    }

    fn release(&self, mode: u32) {
        unsafe {
            match mode {
                0 => LeaveCriticalSection(self.cs.get()),
                1 => ReleaseSRWLockExclusive(self.srw.get()),
                2 => ReleaseSRWLockShared(self.srw.get()),
                _ => unreachable!(),
            }
        }
    }

    fn wait(&self, mode: u32, timeout: u32) -> i32 {
        unsafe {
            match mode {
                0 => SleepConditionVariableCS(self.condition.get(), self.cs.get(), timeout),
                1 => SleepConditionVariableSRW(self.condition.get(), self.srw.get(), timeout, 0),
                2 => SleepConditionVariableSRW(self.condition.get(), self.srw.get(), timeout, 1),
                _ => unreachable!(),
            }
        }
    }
}

impl Drop for Locks {
    fn drop(&mut self) {
        unsafe { DeleteCriticalSection(self.cs.get()) };
    }
}

fn shared_holders() {
    let locks = Locks::new();
    let (ready, ready_rx) = mpsc::channel();
    let mut readers = Vec::new();
    let mut starts = Vec::new();
    for delay in [10, 20] {
        let locks = locks.clone();
        let ready = ready.clone();
        let (start, start_rx) = mpsc::channel();
        starts.push(start);
        readers.push(std::thread::spawn(move || {
            locks.take(2);
            ready.send(()).unwrap();
            start_rx.recv().unwrap();
            std::thread::sleep(Duration::from_millis(delay));
            locks.release(2);
        }));
    }
    ready_rx.recv().unwrap();
    ready_rx.recv().unwrap();
    assert!(!unsafe { TryAcquireSRWLockExclusive(locks.srw.get()) });
    for start in starts {
        start.send(()).unwrap();
    }
    locks.take(1);
    locks.release(1);
    for reader in readers {
        reader.join().unwrap();
    }
    assert!(unsafe { TryAcquireSRWLockExclusive(locks.srw.get()) });
    locks.release(1);
}

#[test]
fn multiple_shared_holders_block_a_writer_until_the_last_release() {
    shared_holders();
    for deterministic in [false, true] {
        let builder = Sim::builder();
        let sim = if deterministic {
            builder.deterministic()
        } else {
            builder
        }
        .build();
        sim.run(shared_holders);
        assert!(sim.time_value() >= Duration::from_millis(20));
    }
}

fn condition_probe(mode: u32, all: bool) -> (i32, u32, usize) {
    let locks = Locks::new();
    locks.take(mode);
    let timeout = locks.wait(mode, 0);
    let error = unsafe { GetLastError() };
    locks.release(mode);
    let (ready, ready_rx) = mpsc::channel();
    let count = if all { 3 } else { 1 };
    let mut waiters = Vec::new();
    for _ in 0..count {
        let locks = locks.clone();
        let ready = ready.clone();
        waiters.push(std::thread::spawn(move || {
            locks.take(mode);
            ready.send(()).unwrap();
            while locks.ready.load(Ordering::Acquire) == 0 {
                assert_ne!(locks.wait(mode, u32::MAX), 0);
            }
            locks.release(mode);
            1
        }));
    }
    for _ in 0..count {
        ready_rx.recv().unwrap();
    }
    let notify_mode = if mode == 0 { 0 } else { 1 };
    locks.take(notify_mode);
    locks.ready.store(1, Ordering::Release);
    unsafe {
        if all {
            WakeAllConditionVariable(locks.condition.get());
        } else {
            WakeConditionVariable(locks.condition.get());
        }
    }
    locks.release(notify_mode);
    (
        timeout,
        error,
        waiters
            .into_iter()
            .map(|waiter| waiter.join().unwrap())
            .sum(),
    )
}

#[test]
fn raw_condition_waits_atomically_unlock_and_reacquire_each_lock_mode() {
    for mode in 0..3 {
        for all in [false, true] {
            let native = condition_probe(mode, all);
            assert_eq!(native, (0, ERROR_TIMEOUT, if all { 3 } else { 1 }));
            for deterministic in [false, true] {
                let builder = Sim::builder();
                let sim = if deterministic {
                    builder.deterministic()
                } else {
                    builder
                }
                .build();
                let (model, domain) = sim.run(|| {
                    (
                        condition_probe(mode, all),
                        snare_interpose::Domain::current().unwrap(),
                    )
                });
                assert_eq!(model, native);
                assert_eq!(
                    domain.outside_wakes(),
                    0,
                    "mode={mode} all={all} deterministic={deterministic}"
                );
            }
        }
    }
}

#[test]
fn condition_timeouts_return_with_the_lock_reacquired() {
    for deterministic in [false, true] {
        let builder = Sim::builder();
        let sim = if deterministic {
            builder.deterministic()
        } else {
            builder
        }
        .build();
        sim.run(|| {
            for mode in 0..3 {
                let locks = Locks::new();
                locks.take(mode);
                let before = snare::sched::now();
                assert_eq!(locks.wait(mode, 25), 0);
                assert_eq!(unsafe { GetLastError() }, ERROR_TIMEOUT);
                assert!(snare::sched::now() - before >= Duration::from_millis(25));
                if mode != 0 {
                    assert!(!unsafe { TryAcquireSRWLockExclusive(locks.srw.get()) });
                } else {
                    assert!(unsafe { TryEnterCriticalSection(locks.cs.get()) } != 0);
                    locks.release(0);
                }
                locks.release(mode);
            }
        });
    }
}
