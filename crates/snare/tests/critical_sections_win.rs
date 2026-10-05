#![cfg(windows)]

use std::cell::UnsafeCell;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use snare::Sim;
use windows_sys::Win32::System::Threading::{
    AcquireSRWLockExclusive, CRITICAL_SECTION, DeleteCriticalSection, EnterCriticalSection,
    InitializeCriticalSection, LeaveCriticalSection, ReleaseSRWLockExclusive, SRWLOCK,
    TryAcquireSRWLockExclusive, TryEnterCriticalSection,
};

struct Section(UnsafeCell<CRITICAL_SECTION>);

// SAFETY: critical sections synchronize access between threads; the Arc keeps the address fixed.
unsafe impl Send for Section {}
// SAFETY: the Windows calls serialize ownership of the initialized critical section.
unsafe impl Sync for Section {}

impl Section {
    fn new() -> Arc<Self> {
        let section = Arc::new(Self(UnsafeCell::new(CRITICAL_SECTION::default())));
        unsafe { InitializeCriticalSection(section.0.get()) };
        section
    }

    fn enter(&self) {
        unsafe { EnterCriticalSection(self.0.get()) };
    }

    fn try_enter(&self) -> bool {
        unsafe { TryEnterCriticalSection(self.0.get()) != 0 }
    }

    fn leave(&self) {
        unsafe { LeaveCriticalSection(self.0.get()) };
    }
}

impl Drop for Section {
    fn drop(&mut self) {
        unsafe { DeleteCriticalSection(self.0.get()) };
    }
}

struct Exclusive(UnsafeCell<SRWLOCK>);

// SAFETY: SRW locks synchronize ownership, and the Arc keeps their address fixed.
unsafe impl Send for Exclusive {}
// SAFETY: only the Windows lock APIs access this initialized lock.
unsafe impl Sync for Exclusive {}

impl Exclusive {
    fn new() -> Arc<Self> {
        Arc::new(Self(UnsafeCell::new(SRWLOCK::default())))
    }

    fn enter(&self) {
        unsafe { AcquireSRWLockExclusive(self.0.get()) };
    }

    fn try_enter(&self) -> bool {
        unsafe { TryAcquireSRWLockExclusive(self.0.get()) }
    }

    fn leave(&self) {
        unsafe { ReleaseSRWLockExclusive(self.0.get()) };
    }
}

fn builders() -> [fn() -> snare::SimBuilder; 2] {
    [Sim::builder, || Sim::builder().deterministic()]
}

#[test]
fn recursive_sections_release_only_after_the_outermost_leave() {
    for builder in builders() {
        let real = Instant::now();
        let sim = builder().build();
        sim.run(|| {
            let section = Section::new();
            let held = section.clone();
            let (ready, acquired) = mpsc::channel();
            let holder = std::thread::spawn(move || {
                held.enter();
                assert!(held.try_enter());
                ready.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(10));
                held.leave();
                std::thread::sleep(Duration::from_millis(10));
                held.leave();
            });
            acquired.recv().unwrap();
            assert!(!section.try_enter());
            section.enter();
            section.leave();
            holder.join().unwrap();
        });
        assert!(sim.time_value() >= Duration::from_millis(20));
        assert!(real.elapsed() < Duration::from_secs(2));
    }
}

#[test]
fn a_section_owned_outside_keeps_virtual_time_still() {
    for builder in builders() {
        let section = Section::new();
        let held = section.clone();
        let (ready, acquired) = mpsc::channel();
        let (release, waiting) = mpsc::channel();
        let outsider = std::thread::spawn(move || {
            held.enter();
            ready.send(()).unwrap();
            waiting.recv().unwrap();
            std::thread::sleep(Duration::from_millis(30));
            held.leave();
        });
        acquired.recv().unwrap();
        let sim = builder().build();
        let locked_at = sim.run(|| {
            let start = Instant::now();
            let waiter = std::thread::spawn(move || {
                release.send(()).unwrap();
                section.enter();
                let at = start.elapsed();
                section.leave();
                at
            });
            std::thread::sleep(Duration::from_millis(100));
            waiter.join().unwrap()
        });
        outsider.join().unwrap();
        assert!(locked_at < Duration::from_millis(100), "{locked_at:?}");
    }
}

#[test]
fn try_enter_is_recursive_and_never_blocks() {
    for builder in builders() {
        builder().build().run(|| {
            let section = Section::new();
            assert!(section.try_enter());
            assert!(section.try_enter());
            section.leave();
            section.leave();
            let competitor = section.clone();
            std::thread::spawn(move || {
                assert!(competitor.try_enter());
                competitor.leave();
            })
            .join()
            .unwrap();
        });
    }
}

#[test]
fn exclusive_srw_holders_can_sleep_while_another_thread_waits() {
    for builder in builders() {
        let real = Instant::now();
        let sim = builder().build();
        sim.run(|| {
            let lock = Exclusive::new();
            let held = lock.clone();
            let (ready, acquired) = mpsc::channel();
            let holder = std::thread::spawn(move || {
                held.enter();
                assert!(!held.try_enter());
                ready.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(20));
                held.leave();
            });
            acquired.recv().unwrap();
            assert!(!lock.try_enter());
            lock.enter();
            lock.leave();
            holder.join().unwrap();
        });
        assert!(sim.time_value() >= Duration::from_millis(20));
        assert!(real.elapsed() < Duration::from_secs(2));
    }
}

#[test]
fn an_exclusive_srw_owned_outside_keeps_virtual_time_still() {
    for builder in builders() {
        let lock = Exclusive::new();
        let held = lock.clone();
        let (ready, acquired) = mpsc::channel();
        let (release, waiting) = mpsc::channel();
        let outsider = std::thread::spawn(move || {
            held.enter();
            ready.send(()).unwrap();
            waiting.recv().unwrap();
            std::thread::sleep(Duration::from_millis(30));
            held.leave();
        });
        acquired.recv().unwrap();
        let sim = builder().build();
        let locked_at = sim.run(|| {
            let start = Instant::now();
            let waiter = std::thread::spawn(move || {
                release.send(()).unwrap();
                lock.enter();
                let at = start.elapsed();
                lock.leave();
                at
            });
            std::thread::sleep(Duration::from_millis(100));
            waiter.join().unwrap()
        });
        outsider.join().unwrap();
        assert!(locked_at < Duration::from_millis(100), "{locked_at:?}");
    }
}

#[test]
fn a_child_left_after_the_run_can_finish_its_sleeps() {
    for builder in builders() {
        let sim = builder().build();
        let (done, finished) = mpsc::channel();
        sim.run(move || {
            std::thread::spawn(move || {
                for _ in 0..5 {
                    std::thread::sleep(Duration::from_millis(10));
                }
                done.send(()).unwrap();
            });
        });
        finished.recv_timeout(Duration::from_secs(2)).unwrap();
    }
}
