#![cfg(windows)]

//! The discrete-event virtual clock on Windows, the `Sim` default: time jumps to the next pending
//! sleep or timeout when every managed thread is blocked — for `Sleep`, Winsock waits, and std's
//! `WaitOnAddress`-based Condvar/park/channels alike — and costs a microsecond per call that
//! returns without blocking. The unix counterparts are `tests/virtual_time.rs` and
//! `tests/native_waits.rs`.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use snare::Sim;

fn vsim() -> Sim {
    Sim::builder().virtual_clock().build()
}

unsafe extern "C" {
    /// The UCRT's `time` (Microsoft Learn: time, _time32, _time64).
    fn _time64(out: *mut i64) -> i64;
}

#[test]
fn crt_time_reads_the_virtual_clock() {
    let (t, stored) = Sim::builder().fixed_epoch().build().run(|| {
        let mut stored = 0i64;
        (unsafe { _time64(&mut stored) }, stored)
    });
    assert_eq!((t, stored), (1_700_000_000, 1_700_000_000));
}

#[test]
fn reads_do_not_tick() {
    Sim::builder().fixed_epoch().build().run(|| {
        let a = Instant::now();
        let b = Instant::now();
        assert_eq!(a, b);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(now.as_secs(), 1_700_000_000);
    });
}

#[test]
fn wall_clock_reads_and_sleeps_use_real_time() {
    let sim = Sim::builder().wall_clock().build();
    sim.run(|| {
        let real_start = snare::real(Instant::now);
        let start = Instant::now();
        let system = SystemTime::now();
        let real_system = snare::real(SystemTime::now);
        assert!(real_system.duration_since(system).unwrap() < Duration::from_secs(1));
        std::thread::sleep(Duration::from_millis(20));
        assert!(start.elapsed() >= Duration::from_millis(20));
        assert!(snare::real(|| real_start.elapsed()) >= Duration::from_millis(20));
    });
}

#[test]
#[should_panic(expected = "this Sim runs on the real clock")]
fn wall_clock_has_no_virtual_time_handle() {
    let _ = Sim::builder().wall_clock().build().time();
}

#[test]
fn explicit_rate_overrides_wall_clock() {
    let sim = Sim::builder().wall_clock().time_rate(0.0).build();
    sim.run(|| {
        let start = Instant::now();
        sim.advance_time(Duration::from_secs(1));
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    });
}

#[test]
fn a_lone_sleep_skips_virtual_time() {
    let real = Instant::now();
    vsim().run(|| {
        let start = Instant::now();
        std::thread::sleep(Duration::from_secs(3600));
        assert!(
            start.elapsed() >= Duration::from_secs(3600),
            "a virtual hour elapsed"
        );
    });
    assert!(
        real.elapsed() < Duration::from_secs(60),
        "ran as-fast-as-possible"
    );
}

#[test]
fn advance_time_steps_the_clock() {
    let sim = Sim::builder().fixed_epoch().build();
    sim.advance_time(Duration::from_secs(5));
    sim.run(|| {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(now.as_secs(), 1_700_000_005);
    });
}

#[test]
fn time_skips_across_threads_to_a_sleeper() {
    vsim().run(|| {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = receiver.local_addr().unwrap();
        let start = Instant::now();
        let sender = std::thread::spawn(move || {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            std::thread::sleep(Duration::from_secs(600));
            s.send_to(b"tick", addr).unwrap();
        });
        let mut buf = [0u8; 8];
        let (n, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"tick");
        sender.join().unwrap();
        assert!(
            start.elapsed() >= Duration::from_secs(600),
            "clock advanced to the sleeper"
        );
    });
}

#[test]
fn a_condvar_timeout_runs_on_virtual_time() {
    let real = Instant::now();
    vsim().run(|| {
        let flag = Mutex::new(());
        let cv = Condvar::new();
        let start = Instant::now();
        let (_guard, result) = cv
            .wait_timeout_while(flag.lock().unwrap(), Duration::from_secs(30), |_| true)
            .unwrap();
        assert!(result.timed_out());
        assert!(
            start.elapsed() >= Duration::from_secs(30),
            "virtual time reached the timeout"
        );
    });
    assert!(
        real.elapsed() < Duration::from_secs(30),
        "ran as-fast-as-possible"
    );
}

#[test]
fn a_channel_recv_timeout_runs_on_virtual_time() {
    let real = Instant::now();
    vsim().run(|| {
        let (_tx, rx) = mpsc::channel::<u8>();
        let start = Instant::now();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        assert!(
            start.elapsed() >= Duration::from_secs(10),
            "virtual time reached the timeout"
        );
    });
    assert!(
        real.elapsed() < Duration::from_secs(10),
        "ran as-fast-as-possible"
    );
}

#[test]
fn a_busy_poll_lets_virtual_time_reach_a_sleeper() {
    let real = Instant::now();
    Sim::new().run(|| {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let addr = receiver.local_addr().unwrap();
        let start = Instant::now();
        let sender = std::thread::spawn(move || {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            std::thread::sleep(Duration::from_millis(10));
            s.send_to(b"late", addr).unwrap();
        });
        let mut buf = [0u8; 8];
        let n = loop {
            match receiver.recv_from(&mut buf) {
                Ok((n, _)) => break n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("{e}"),
            }
        };
        assert_eq!(&buf[..n], b"late");
        sender.join().unwrap();
        assert!(
            start.elapsed() >= Duration::from_millis(10),
            "the sender's sleep elapsed"
        );
    });
    assert!(
        real.elapsed() < Duration::from_secs(30),
        "the spin did not stall the clock"
    );
}

#[test]
fn spinning_on_yield_lets_virtual_time_advance() {
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

fn after_real(delay: Duration, f: impl FnOnce() + Send + 'static) -> std::thread::JoinHandle<()> {
    snare::real(|| {
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            f();
        })
    })
}

#[test]
fn paused_sleep_and_sleep_ex_park() {
    use windows_sys::Win32::System::Threading::SleepEx;
    let sim = vsim();
    sim.pause_time();
    let time = sim.time();
    sim.run(|| {
        let real = snare::real(Instant::now);
        let start = Instant::now();
        let advancer = time.clone();
        let first = after_real(Duration::from_millis(200), move || {
            advancer.advance(Duration::from_secs(2));
        });
        std::thread::sleep(Duration::from_secs(2));
        assert!(
            snare::real(|| real.elapsed()) >= Duration::from_millis(150),
            "Sleep parked"
        );
        assert!(start.elapsed() >= Duration::from_secs(2));
        snare::real(|| first.join().unwrap());

        let real = snare::real(Instant::now);
        let second = after_real(Duration::from_millis(200), move || {
            time.advance(Duration::from_secs(3));
        });
        unsafe { SleepEx(3000, 0) };
        assert!(
            snare::real(|| real.elapsed()) >= Duration::from_millis(150),
            "SleepEx parked"
        );
        assert!(start.elapsed() >= Duration::from_secs(5));
        snare::real(|| second.join().unwrap());
    });
}

#[test]
fn scaled_qpc_and_precise_system_time_agree() {
    Sim::builder().time_rate(10.0).build().run(|| {
        let (i0, s0) = (Instant::now(), SystemTime::now());
        snare::real(|| std::thread::sleep(Duration::from_millis(100)));
        let (i1, s1) = (Instant::now(), SystemTime::now());
        let by_qpc = i1 - i0;
        let by_filetime = s1.duration_since(s0).unwrap();
        assert!(
            (Duration::from_millis(900)..Duration::from_secs(5)).contains(&by_qpc),
            "100 real ms at 10x: {by_qpc:?}"
        );
        let gap = by_qpc.abs_diff(by_filetime);
        assert!(
            gap < Duration::from_millis(50),
            "{by_qpc:?} vs {by_filetime:?}"
        );
    });
}

#[test]
fn scaled_wait_on_address_times_out_on_scaled_time() {
    use windows_sys::Win32::System::Threading::WaitOnAddress;
    Sim::builder().time_rate(10.0).build().run(|| {
        let word = 0u32;
        let compare = 0u32;
        let real = snare::real(Instant::now);
        let start = Instant::now();
        let timeout = Duration::from_secs(1);
        // WaitOnAddress may also return TRUE spuriously; a caller re-waits for what is left.
        let error = loop {
            let left = timeout.saturating_sub(start.elapsed());
            let woke = unsafe {
                WaitOnAddress(
                    (&word as *const u32).cast(),
                    (&compare as *const u32).cast(),
                    4,
                    u32::try_from(left.as_millis()).unwrap(),
                )
            };
            if woke == 0 {
                break unsafe { windows_sys::Win32::Foundation::GetLastError() };
            }
        };
        let took = snare::real(|| real.elapsed());
        assert_eq!(error, windows_sys::Win32::Foundation::ERROR_TIMEOUT);
        assert!(start.elapsed() >= Duration::from_secs(1));
        assert!(
            (Duration::from_millis(80)..Duration::from_secs(1)).contains(&took),
            "1 virtual s at 10x: {took:?}"
        );
    });
}
