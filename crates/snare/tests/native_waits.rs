//! Native blocking waits — the contended path of std's Mutex/Condvar/park and the channels built on
//! them (a futex on Linux; `pthread_*` and `dispatch_semaphore_wait` on macOS; `WaitOnAddress` on
//! Windows, [Microsoft Learn: WaitOnAddress](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitonaddress))
//! — take part in the
//! simulation: a thread blocked in one counts toward quiescence, its timeout runs on the virtual
//! clock, and a thread spinning on `yield_now` lets virtual time advance instead of stalling it.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use snare::Sim;

fn vsim() -> Sim {
    Sim::builder().virtual_clock().build()
}

#[test]
fn a_condvar_wait_counts_toward_quiescence() {
    // The waiter is parked on a condvar only main can satisfy; main is parked on a socket nothing
    // will ever send to. Both are blocked, so main's receive must see the domain as deadlocked and
    // give up — which it can only do if the condvar wait counts as parked.
    Sim::new().run(|| {
        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let theirs = pair.clone();
        let waiter = std::thread::spawn(move || {
            let (flag, cv) = &*theirs;
            let mut set = flag.lock().unwrap();
            while !*set {
                set = cv.wait(set).unwrap();
            }
        });

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut buf = [0u8; 8];
        assert!(
            sock.recv_from(&mut buf).is_err(),
            "the deadlocked receive gave up"
        );

        let (flag, cv) = &*pair;
        *flag.lock().unwrap() = true;
        cv.notify_one();
        waiter.join().unwrap();
    });
}

#[test]
fn a_contended_mutex_waits_out_a_virtual_sleep() {
    // The holder sleeps for a virtual minute with the lock held while main blocks on it. Only once
    // main's contended lock counts as parked is the domain quiescent, so the holder's sleep can be
    // time-skipped rather than stalling forever.
    let real = Instant::now();
    vsim().run(|| {
        let lock = Arc::new(Mutex::new(0u32));
        let held = lock.clone();
        let (locked_tx, locked_rx) = mpsc::channel();
        let start = Instant::now();
        let holder = std::thread::spawn(move || {
            let mut guard = held.lock().unwrap();
            locked_tx.send(()).unwrap();
            std::thread::sleep(Duration::from_secs(60));
            *guard += 1;
        });
        locked_rx.recv().unwrap();
        assert_eq!(
            *lock.lock().unwrap(),
            1,
            "main got the lock after the holder released it"
        );
        assert!(
            start.elapsed() >= Duration::from_secs(60),
            "the holder's virtual minute passed"
        );
        holder.join().unwrap();
    });
    assert!(
        real.elapsed() < Duration::from_secs(30),
        "ran as-fast-as-possible"
    );
}

#[test]
fn a_condvar_timeout_runs_on_virtual_time() {
    let real = Instant::now();
    vsim().run(|| {
        let flag = Mutex::new(());
        let cv = Condvar::new();
        let start = Instant::now();
        // Nothing ever notifies, so the wait must run its whole (virtual) timeout. The `_while`
        // form re-waits across spurious wakeups, as condvar callers must.
        let (_guard, result) = cv
            .wait_timeout_while(flag.lock().unwrap(), Duration::from_secs(30), |_| true)
            .unwrap();
        assert!(result.timed_out());
        let waited = start.elapsed();
        assert!(
            (Duration::from_millis(29_900)..=Duration::from_secs(31)).contains(&waited),
            "virtual time reached the timeout, got {waited:?}"
        );
    });
    assert!(
        real.elapsed() < Duration::from_secs(30),
        "ran as-fast-as-possible"
    );
}

#[test]
fn a_channel_recv_timeout_runs_on_virtual_time() {
    // std's mpsc parks the receiver (`thread::park_timeout`: a futex on Linux, a dispatch
    // semaphore on macOS, `WaitOnAddress` on Windows) until the deadline.
    let real = Instant::now();
    vsim().run(|| {
        let (_tx, rx) = mpsc::channel::<u8>();
        let start = Instant::now();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        assert!(
            start.elapsed() >= Duration::from_millis(9_900),
            "virtual time reached the timeout"
        );
    });
    assert!(
        real.elapsed() < Duration::from_secs(10),
        "ran as-fast-as-possible"
    );
}

#[test]
fn spinning_on_yield_lets_virtual_time_advance() {
    // A busy-wait that only yields never parks. With every other thread asleep, its yields let the
    // clock jump to the sleeper's wake-up instead of spinning against frozen time forever.
    let real = Instant::now();
    vsim().run(|| {
        let done = Arc::new(AtomicBool::new(false));
        let signal = done.clone();
        let start = Instant::now();
        let sleeper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(5));
            signal.store(true, Ordering::Release);
        });
        while !done.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        assert!(
            start.elapsed() >= Duration::from_secs(5),
            "the sleeper's virtual 5s passed"
        );
        sleeper.join().unwrap();
    });
    assert!(
        real.elapsed() < Duration::from_secs(5),
        "ran as-fast-as-possible"
    );
}

/// Real time `f` takes inside a sim whose clock runs at ten times real time.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn real_time_at_10x(f: impl FnOnce()) -> Duration {
    Sim::builder().time_rate(10.0).build().run(|| {
        let real = snare::real(Instant::now);
        f();
        snare::real(|| real.elapsed())
    })
}

#[cfg(target_os = "linux")]
#[test]
fn a_scaled_futex_wait_bitset_times_out_on_scaled_time() {
    use std::sync::atomic::AtomicU32;
    let took = real_time_at_10x(|| {
        let word = AtomicU32::new(0);
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
        // man 2 futex: FUTEX_WAIT_BITSET's timeout is absolute on CLOCK_MONOTONIC.
        let deadline = libc::timespec {
            tv_sec: now.tv_sec + 1,
            tv_nsec: now.tv_nsec,
        };
        let start = Instant::now();
        let r = unsafe {
            libc::syscall(
                libc::SYS_futex,
                word.as_ptr(),
                libc::FUTEX_WAIT_BITSET | libc::FUTEX_PRIVATE_FLAG,
                0u32,
                &deadline as *const libc::timespec,
                std::ptr::null::<u32>(),
                u32::MAX,
            )
        };
        assert_eq!(r, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ETIMEDOUT)
        );
        assert!(start.elapsed() >= Duration::from_secs(1));
    });
    assert!(
        (Duration::from_millis(80)..Duration::from_secs(1)).contains(&took),
        "1 virtual s at 10x: {took:?}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn a_scaled_dispatch_semaphore_wait_times_out_on_scaled_time() {
    #[allow(non_camel_case_types)]
    type dispatch_semaphore_t = *mut std::ffi::c_void;
    unsafe extern "C" {
        fn dispatch_semaphore_create(value: isize) -> dispatch_semaphore_t;
        fn dispatch_semaphore_wait(sema: dispatch_semaphore_t, timeout: u64) -> isize;
        fn dispatch_time(when: u64, delta: i64) -> u64;
        fn dispatch_release(object: *mut std::ffi::c_void);
    }
    // <dispatch/time.h>: DISPATCH_TIME_NOW is 0.
    const DISPATCH_TIME_NOW: u64 = 0;
    let took = real_time_at_10x(|| {
        let sema = unsafe { dispatch_semaphore_create(0) };
        let start = Instant::now();
        let when = unsafe { dispatch_time(DISPATCH_TIME_NOW, 1_000_000_000) };
        assert_ne!(
            unsafe { dispatch_semaphore_wait(sema, when) },
            0,
            "timed out"
        );
        assert!(start.elapsed() >= Duration::from_secs(1));
        unsafe { dispatch_release(sema) };
    });
    assert!(
        (Duration::from_millis(80)..Duration::from_secs(1)).contains(&took),
        "1 virtual s at 10x: {took:?}"
    );
}
