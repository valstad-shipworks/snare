//! POSIX unnamed semaphores (Linux) and Windows semaphore handles: a thread blocked on one counts
//! toward quiescence and waits out its timeout in sim time.

#[cfg(target_os = "linux")]
mod linux {
    use std::sync::atomic::{AtomicPtr, Ordering};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use snare::Sim;

    fn new_sem() -> &'static AtomicPtr<libc::sem_t> {
        // SAFETY: an all-zero sem_t is storage for sem_init.
        let sem = Box::leak(Box::new(unsafe { std::mem::zeroed::<libc::sem_t>() }));
        // SAFETY: initialises a process-private semaphore at 0.
        assert_eq!(unsafe { libc::sem_init(sem, 0, 0) }, 0);
        Box::leak(Box::new(AtomicPtr::new(sem)))
    }

    fn quiescence(sim: Sim) {
        let sem = new_sem();
        let real = snare::real(Instant::now);
        let (woke_at, elapsed) = sim.run(|| {
            let start = Instant::now();
            let waiter = thread::spawn(move || {
                // SAFETY: the semaphore lives for the whole process.
                assert_eq!(unsafe { libc::sem_wait(sem.load(Ordering::SeqCst)) }, 0);
                start.elapsed()
            });
            thread::sleep(Duration::from_secs(10));
            // SAFETY: as above.
            assert_eq!(unsafe { libc::sem_post(sem.load(Ordering::SeqCst)) }, 0);
            let woke_at = waiter.join().unwrap();
            let timed = thread::spawn(move || {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                let until = now + Duration::from_secs(3);
                let ts = libc::timespec {
                    tv_sec: until.as_secs() as _,
                    tv_nsec: until.subsec_nanos() as _,
                };
                let begin = Instant::now();
                // SAFETY: as above.
                let r = unsafe { libc::sem_timedwait(sem.load(Ordering::SeqCst), &ts) };
                let e = std::io::Error::last_os_error().raw_os_error();
                (r, e, begin.elapsed())
            });
            let (r, e, waited) = timed.join().unwrap();
            assert_eq!((r, e), (-1, Some(libc::ETIMEDOUT)));
            assert!(
                waited >= Duration::from_secs(3) && waited < Duration::from_secs(4),
                "{waited:?}"
            );
            // SAFETY: as above.
            assert_eq!(unsafe { libc::sem_trywait(sem.load(Ordering::SeqCst)) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EAGAIN)
            );
            (woke_at, start.elapsed())
        });
        assert!(
            woke_at >= Duration::from_secs(10) && woke_at < Duration::from_secs(11),
            "{woke_at:?}"
        );
        assert!(elapsed >= Duration::from_secs(13), "{elapsed:?}");
        assert!(
            snare::real(|| real.elapsed()) < Duration::from_secs(5),
            "sim time, not real"
        );
    }

    #[test]
    fn sem_wait_quiescence() {
        quiescence(Sim::new());
    }

    #[test]
    fn sem_wait_quiescence_deterministic() {
        quiescence(Sim::builder().deterministic().build());
    }
}

#[cfg(windows)]
mod windows {
    use std::thread;
    use std::time::{Duration, Instant};

    use snare::Sim;

    type Handle = *mut std::ffi::c_void;
    unsafe extern "system" {
        fn CreateSemaphoreA(attrs: *mut u8, initial: i32, max: i32, name: *const u8) -> Handle;
        fn ReleaseSemaphore(handle: Handle, count: i32, previous: *mut i32) -> i32;
        fn WaitForSingleObject(handle: Handle, millis: u32) -> u32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    struct Sem(Handle);
    // SAFETY: a kernel handle may be used from any thread.
    unsafe impl Send for Sem {}
    unsafe impl Sync for Sem {}

    fn waits(sim: Sim) {
        let real = snare::real(Instant::now);
        let (woke_at, timed) = sim.run(|| {
            // SAFETY: creates an anonymous semaphore at 0.
            let sem = std::sync::Arc::new(Sem(unsafe {
                CreateSemaphoreA(std::ptr::null_mut(), 0, 16, std::ptr::null())
            }));
            let start = Instant::now();
            let waiter = {
                let sem = sem.clone();
                thread::spawn(move || {
                    // SAFETY: the semaphore outlives the waiter.
                    assert_eq!(unsafe { WaitForSingleObject(sem.0, u32::MAX) }, 0);
                    start.elapsed()
                })
            };
            thread::sleep(Duration::from_secs(10));
            // SAFETY: as above.
            assert_ne!(
                unsafe { ReleaseSemaphore(sem.0, 1, std::ptr::null_mut()) },
                0
            );
            let woke_at = waiter.join().unwrap();
            let begin = Instant::now();
            // SAFETY: as above.
            assert_eq!(unsafe { WaitForSingleObject(sem.0, 3000) }, 258);
            let timed = begin.elapsed();
            // SAFETY: closes the semaphore made above.
            unsafe { CloseHandle(sem.0) };
            (woke_at, timed)
        });
        assert!(
            woke_at >= Duration::from_secs(10) && woke_at < Duration::from_secs(11),
            "{woke_at:?}"
        );
        assert!(
            timed >= Duration::from_secs(3) && timed < Duration::from_secs(4),
            "{timed:?}"
        );
        assert!(
            snare::real(|| real.elapsed()) < Duration::from_secs(5),
            "sim time, not real"
        );
    }

    #[test]
    fn semaphore_waits() {
        waits(Sim::new());
    }

    #[test]
    fn semaphore_waits_deterministic() {
        waits(Sim::builder().deterministic().build());
    }
}
