#![cfg(unix)]
use snare::{HostProfile, Sim};

fn clock_gettime(clk: libc::clockid_t) -> libc::timespec {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::clock_gettime(clk, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime failed");
    ts
}

fn secs(ts: libc::timespec) -> libc::time_t {
    ts.tv_sec
}

#[test]
fn realtime_is_virtual_and_deterministic() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).fixed_epoch().build().run(|| {
        // The fixed virtual epoch, not the real wall clock.
        let t = clock_gettime(libc::CLOCK_REALTIME);
        assert_eq!(secs(t), 1_700_000_000, "virtual realtime epoch");
    });
}

#[test]
fn monotonic_advances_with_sleeps_not_reads() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let a = clock_gettime(libc::CLOCK_MONOTONIC);
        let b = clock_gettime(libc::CLOCK_MONOTONIC);
        std::thread::sleep(std::time::Duration::from_micros(10));
        let c = clock_gettime(libc::CLOCK_MONOTONIC);
        let nanos = |t: libc::timespec| t.tv_sec as i128 * 1_000_000_000 + t.tv_nsec as i128;
        assert_eq!(nanos(a), nanos(b), "reads alone leave discrete time still");
        assert!(
            nanos(c) > nanos(b),
            "a sleep advances it ({} -> {})",
            nanos(b),
            nanos(c)
        );
    });
}

#[test]
fn sleep_advances_the_virtual_clock_without_blocking() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let before = clock_gettime(libc::CLOCK_MONOTONIC);
        // A full hour of sleep: if it actually blocked, the test would hang (caught by the
        // harness). It returns at once because the clock layer carries the sleep virtually, and
        // virtual monotonic time still moves forward by the hour.
        std::thread::sleep(std::time::Duration::from_secs(3600));
        let after = clock_gettime(libc::CLOCK_MONOTONIC);
        let delta = after.tv_sec - before.tv_sec;
        assert!(
            delta >= 3600,
            "virtual monotonic advanced by >= 1h, got {delta}s"
        );
    });
}

#[cfg(target_os = "linux")]
#[test]
fn clock_tai_leads_realtime_by_the_offset() {
    let host = HostProfile::new().tai_offset(37).build();
    Sim::builder().host(host).build().run(|| {
        const CLOCK_TAI: libc::clockid_t = 11;
        // Read realtime then TAI; both advance the shared clock by 1µs per read, so TAI's second
        // count is realtime's + 37 regardless of the sub-second drift.
        let rt = clock_gettime(libc::CLOCK_REALTIME);
        let tai = clock_gettime(CLOCK_TAI);
        assert_eq!(
            secs(tai) - secs(rt),
            37,
            "CLOCK_TAI leads by the TAI-UTC offset"
        );
    });
}

fn after_real(
    delay: std::time::Duration,
    f: impl FnOnce() + Send + 'static,
) -> std::thread::JoinHandle<()> {
    snare::real(|| {
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            f();
        })
    })
}

#[test]
fn simhost_pause_parks_sleeper() {
    use std::time::{Duration, Instant};
    let sim = Sim::builder().host(HostProfile::new().build()).build();
    sim.pause_time();
    let time = sim.time();
    sim.run(|| {
        let real = snare::real(Instant::now);
        let start = Instant::now();
        let controller = after_real(Duration::from_millis(200), move || {
            time.advance(Duration::from_secs(1));
        });
        std::thread::sleep(Duration::from_secs(1));
        assert!(
            snare::real(|| real.elapsed()) >= Duration::from_millis(150),
            "the sleep parked"
        );
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        snare::real(|| controller.join().unwrap());
    });
}

#[test]
fn simhost_afap_pause_parks_then_resume_jumps() {
    use std::time::{Duration, Instant};
    let sim = Sim::builder()
        .host(HostProfile::new().build())
        .wall_clock()
        .build();
    sim.pause_time();
    let time = sim.time();
    sim.run(|| {
        let real = snare::real(Instant::now);
        let start = Instant::now();
        let controller = after_real(Duration::from_millis(200), move || time.resume());
        std::thread::sleep(Duration::from_secs(3600));
        assert!(
            snare::real(|| real.elapsed()) >= Duration::from_millis(150),
            "the sleep parked"
        );
        assert!(
            start.elapsed() >= Duration::from_secs(3600),
            "and jumped once resumed"
        );
        snare::real(|| controller.join().unwrap());
    });
}

fn paused_afap_sim() -> Sim {
    let sim = Sim::builder()
        .host(HostProfile::new().build())
        .wall_clock()
        .build();
    sim.pause_time();
    sim
}

#[test]
fn simhost_afap_paused_rcvtimeo_holds_until_advance() {
    use std::time::{Duration, Instant};
    let sim = paused_afap_sim();
    let time = sim.time();
    sim.run(|| {
        let sock = std::net::UdpSocket::bind("127.0.0.1:9871").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let real = snare::real(Instant::now);
        let start = Instant::now();
        let controller = after_real(Duration::from_millis(1500), move || {
            time.advance(Duration::from_secs(2));
        });
        let err = sock.recv_from(&mut [0u8; 8]).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "{err:?}"
        );
        let waited = snare::real(|| real.elapsed());
        assert!(
            waited >= Duration::from_millis(1400),
            "held until the advance: {waited:?}"
        );
        assert!(
            start.elapsed() >= Duration::from_secs(1),
            "the timeout elapsed on the clock"
        );
        snare::real(|| controller.join().unwrap());
    });
}

#[test]
fn simhost_afap_paused_rcvtimeo_expires_on_resume() {
    use std::time::{Duration, Instant};
    let sim = paused_afap_sim();
    let time = sim.time();
    sim.run(|| {
        let sock = std::net::UdpSocket::bind("127.0.0.1:9872").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3600)))
            .unwrap();
        let real = snare::real(Instant::now);
        let start = Instant::now();
        let controller = after_real(Duration::from_millis(200), move || time.resume());
        assert!(sock.recv_from(&mut [0u8; 8]).is_err());
        assert!(
            snare::real(|| real.elapsed()) >= Duration::from_millis(150),
            "held while paused"
        );
        assert!(
            start.elapsed() >= Duration::from_secs(3600),
            "jumped to the deadline on resume"
        );
        snare::real(|| controller.join().unwrap());
    });
}

#[test]
fn simhost_afap_paused_condvar_wait_timeout_holds() {
    use std::sync::{Condvar, Mutex};
    use std::time::{Duration, Instant};
    let sim = paused_afap_sim();
    let time = sim.time();
    sim.run(|| {
        let pair = (Mutex::new(()), Condvar::new());
        let real = snare::real(Instant::now);
        let start = Instant::now();
        let controller = after_real(Duration::from_millis(1500), move || {
            time.advance(Duration::from_secs(2));
        });
        let guard = pair.0.lock().unwrap();
        let (_guard, result) = pair
            .1
            .wait_timeout_while(guard, Duration::from_secs(1), |_| true)
            .unwrap();
        assert!(result.timed_out());
        let waited = snare::real(|| real.elapsed());
        assert!(
            waited >= Duration::from_millis(1400),
            "held until the advance: {waited:?}"
        );
        assert!(
            start.elapsed() >= Duration::from_secs(1),
            "the timeout elapsed on the clock"
        );
        snare::real(|| controller.join().unwrap());
    });
}

#[test]
fn simhost_afap_paused_condvar_wait_timeout_expires_on_resume() {
    use std::sync::{Condvar, Mutex};
    use std::time::{Duration, Instant};
    let sim = paused_afap_sim();
    let time = sim.time();
    sim.run(|| {
        let pair = (Mutex::new(()), Condvar::new());
        let real = snare::real(Instant::now);
        let start = Instant::now();
        let controller = after_real(Duration::from_millis(200), move || time.resume());
        let guard = pair.0.lock().unwrap();
        let (_guard, result) = pair
            .1
            .wait_timeout_while(guard, Duration::from_secs(1), |_| true)
            .unwrap();
        assert!(result.timed_out());
        assert!(
            snare::real(|| real.elapsed()) >= Duration::from_millis(150),
            "held while paused"
        );
        assert!(
            start.elapsed() >= Duration::from_secs(1),
            "jumped to the deadline on resume"
        );
        snare::real(|| controller.join().unwrap());
    });
}

#[cfg(target_os = "linux")]
#[test]
fn simhost_scaled_timestamps() {
    use std::time::Duration;
    const SO_TIMESTAMPING: i32 = 37;
    const SOF_TIMESTAMPING_RX_SOFTWARE: u32 = 1 << 3;
    const SOF_TIMESTAMPING_SOFTWARE: u32 = 1 << 4;
    let sim = Sim::builder()
        .host(HostProfile::new().build())
        .time_rate(10.0)
        .build();
    sim.run(|| {
        let rx = std::net::UdpSocket::bind("127.0.0.1:9870").unwrap();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&rx);
        let flags = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_TIMESTAMPING,
                &flags as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as u32,
            )
        };
        assert_eq!(rc, 0);
        let tx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let stamp = || {
            let mut buf = [0u8; 16];
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            };
            let mut control = [0u8; 128];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = control.len();
            assert!(unsafe { libc::recvmsg(fd, &mut msg, 0) } > 0);
            let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
            assert!(!cmsg.is_null(), "a timestamp was attached");
            let ts = unsafe {
                libc::CMSG_DATA(cmsg)
                    .cast::<libc::timespec>()
                    .read_unaligned()
            };
            Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
        };
        tx.send_to(b"a", "127.0.0.1:9870").unwrap();
        let first = stamp();
        snare::real(|| std::thread::sleep(Duration::from_millis(100)));
        tx.send_to(b"b", "127.0.0.1:9870").unwrap();
        let second = stamp();
        let apart = second - first;
        assert!(
            (Duration::from_millis(900)..Duration::from_secs(5)).contains(&apart),
            "100 real ms at 10x stamps about a virtual second apart: {apart:?}"
        );
    });
}

#[test]
fn simhost_afap_rate_changes_never_go_backwards() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;
    let sim = Sim::builder()
        .host(HostProfile::new().build())
        .wall_clock()
        .build();
    let time = sim.time();
    sim.run(|| {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let toggler = snare::real(|| {
            std::thread::spawn(move || {
                let mut i = 0u64;
                while !flag.load(Ordering::Relaxed) {
                    match i % 6 {
                        0 => time.set_rate(10.0),
                        1 | 4 => time.pause(),
                        2 => time.resume(),
                        3 => time.set_rate(1e6),
                        _ => time.set_rate(f64::INFINITY),
                    }
                    i += 1;
                    std::thread::yield_now();
                }
            })
        });
        let readers: Vec<_> = (0..3)
            .map(|_| {
                std::thread::spawn(|| {
                    let mut last = Instant::now();
                    for _ in 0..200_000 {
                        let now = Instant::now();
                        assert!(now >= last, "time went backwards: {last:?} -> {now:?}");
                        last = now;
                    }
                })
            })
            .collect();
        for reader in readers {
            reader.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        snare::real(|| toggler.join().unwrap());
    });
}

#[test]
fn simhost_afap_pause_holds_a_running_rcvtimeo() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    let sim = Sim::builder()
        .host(HostProfile::new().build())
        .wall_clock()
        .build();
    let time = sim.time();
    let advanced = Arc::new(AtomicBool::new(false));
    let seen = advanced.clone();
    sim.run(|| {
        let sock = std::net::UdpSocket::bind("127.0.0.1:9873").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let start = Instant::now();
        let controller = snare::real(|| {
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                time.pause();
                std::thread::sleep(Duration::from_millis(1000));
                advanced.store(true, Ordering::SeqCst);
                time.advance(Duration::from_secs(1));
            })
        });
        assert!(sock.recv_from(&mut [0u8; 8]).is_err());
        assert!(
            seen.load(Ordering::SeqCst),
            "the pause held the wait past its real-time deadline"
        );
        assert!(start.elapsed() >= Duration::from_millis(500));
        snare::real(|| controller.join().unwrap());
    });
}
