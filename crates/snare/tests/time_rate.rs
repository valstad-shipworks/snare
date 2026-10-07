//! Controlling the virtual clock: scaling it to real time at a rate, setting its monotonic value,
//! and pausing it so sleepers and timed waits hold until something outside the simulation moves
//! time — the way `nanosleep(2)` and `Sleep` wait out their whole interval.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use snare::{Sim, TesterAction, udp_tester};

const EPOCH_SECS: u64 = 1_700_000_000;

/// Runs `f` on an unmanaged thread after `delay` of real time: a controller outside the sim.
fn after_real(delay: Duration, f: impl FnOnce() + Send + 'static) -> JoinHandle<()> {
    snare::real(|| {
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            f();
        })
    })
}

fn real_now() -> Instant {
    snare::real(Instant::now)
}

fn real_since(start: Instant) -> Duration {
    snare::real(|| start.elapsed())
}

fn paused_sim() -> Sim {
    let sim = Sim::new();
    sim.pause_time();
    sim
}

#[test]
fn default_is_discrete() {
    let sim = Sim::new();
    assert_eq!(sim.time_rate(), f64::INFINITY);
    sim.run(|| {
        let a = Instant::now();
        let b = Instant::now();
        assert_eq!(a, b, "discrete reads hold still");
    });
}

#[test]
fn rate_one_tracks_real_time() {
    let sim = Sim::builder().time_rate(1.0).build();
    assert_eq!(sim.time_rate(), 1.0);
    let before = sim.time_value();
    std::thread::sleep(Duration::from_millis(100));
    let moved = sim.time_value() - before;
    assert!(
        (Duration::from_millis(90)..Duration::from_secs(2)).contains(&moved),
        "virtual time followed real time: {moved:?}"
    );
}

#[test]
fn high_rate_sleep_is_fast() {
    let sim = Sim::builder().time_rate(1000.0).build();
    sim.run(|| {
        let real = real_now();
        let start = Instant::now();
        std::thread::sleep(Duration::from_secs(10));
        assert!(start.elapsed() >= Duration::from_secs(10));
        let took = real_since(real);
        assert!(
            took < Duration::from_secs(2),
            "10 virtual s at 1000x took {took:?}"
        );
        assert!(
            took >= Duration::from_millis(5),
            "a scaled sleep waits real time: {took:?}"
        );
    });
}

#[test]
fn rate_is_capped() {
    let sim = Sim::new();
    sim.set_time_rate(1e9);
    assert_eq!(sim.time_rate(), 1e6);
}

#[test]
#[should_panic(expected = "monoton")]
fn negative_rate_panics() {
    Sim::new().set_time_rate(-1.0);
}

#[test]
#[should_panic(expected = "monoton")]
fn nan_rate_panics() {
    Sim::new().set_time_rate(f64::NAN);
}

#[test]
#[should_panic(expected = "monoton")]
fn builder_negative_rate_panics() {
    let _ = Sim::builder().time_rate(-2.0);
}

#[test]
fn infinity_returns_to_discrete() {
    let sim = Sim::new();
    sim.set_time_rate(10.0);
    std::thread::sleep(Duration::from_millis(20));
    sim.set_time_rate(f64::INFINITY);
    assert_eq!(sim.time_rate(), f64::INFINITY);
    let kept = sim.time_value();
    assert!(
        kept >= Duration::from_millis(100),
        "kept the scaled reading: {kept:?}"
    );
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(sim.time_value(), kept, "discrete time holds still again");
    sim.run(|| {
        let a = Instant::now();
        std::thread::sleep(Duration::from_secs(60));
        assert!(a.elapsed() >= Duration::from_secs(60));
    });
}

#[test]
fn resume_restores_rate() {
    let sim = Sim::new();
    sim.set_time_rate(3.0);
    sim.pause_time();
    assert_eq!(sim.time_rate(), 0.0);
    assert!(sim.time().is_paused());
    sim.resume_time();
    assert_eq!(sim.time_rate(), 3.0);

    let discrete = Sim::new();
    discrete.pause_time();
    discrete.resume_time();
    assert_eq!(discrete.time_rate(), f64::INFINITY);

    let zero = Sim::new();
    zero.set_time_rate(5.0);
    zero.set_time_rate(0.0);
    assert_eq!(zero.time_rate(), 0.0);
    zero.resume_time();
    assert_eq!(zero.time_rate(), 5.0);
}

#[test]
fn rate_change_never_goes_backwards() {
    let sim = Sim::new();
    let time = sim.time();
    sim.run(|| {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let toggler = snare::real(|| {
            std::thread::spawn(move || {
                let mut i = 0u64;
                while !flag.load(Ordering::Relaxed) {
                    match i % 5 {
                        0 => time.set_rate(1000.0),
                        1 => time.pause(),
                        2 => time.resume(),
                        3 => time.set_rate(f64::INFINITY),
                        _ => time.advance(Duration::from_micros(3)),
                    }
                    i += 1;
                    std::thread::yield_now();
                }
            })
        });
        let mut last = Instant::now();
        for _ in 0..10_000 {
            let now = Instant::now();
            assert!(now >= last, "time went backwards: {last:?} -> {now:?}");
            last = now;
        }
        stop.store(true, Ordering::Relaxed);
        snare::real(|| toggler.join().unwrap());
    });
}

#[test]
fn set_time_value_jumps_forward() {
    let sim = Sim::builder().fixed_epoch().build();
    let v = Duration::from_millis(1_234_500);
    sim.set_time_value(v);
    assert_eq!(sim.time_value(), v);
    sim.set_time_value(v);
    assert_eq!(sim.time_value(), v, "setting the current value is a no-op");
    sim.run(|| {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(
            now,
            Duration::from_secs(EPOCH_SECS) + v,
            "realtime moved with monotonic"
        );
    });
}

#[test]
#[should_panic(expected = "monoton")]
fn set_time_value_backwards_panics() {
    let sim = Sim::new();
    sim.set_time_value(Duration::from_secs(10));
    sim.set_time_value(Duration::from_secs(5));
}

#[test]
fn set_time_value_wakes_sleeper() {
    let sim = paused_sim();
    let time = sim.time();
    sim.run(|| {
        let start = Instant::now();
        let controller = after_real(Duration::from_millis(100), move || {
            time.set_value(time.value() + Duration::from_secs(20));
        });
        std::thread::sleep(Duration::from_secs(10));
        assert!(start.elapsed() >= Duration::from_secs(20));
        snare::real(|| controller.join().unwrap());
    });
}

#[test]
fn paused_sleep_parks_until_advance() {
    let sim = paused_sim();
    let time = sim.time();
    sim.run(|| {
        let real = real_now();
        let start = Instant::now();
        let controller = after_real(Duration::from_millis(200), move || {
            time.advance(Duration::from_secs(5));
        });
        std::thread::sleep(Duration::from_secs(5));
        assert!(
            real_since(real) >= Duration::from_millis(150),
            "the sleep parked"
        );
        assert_eq!(
            start.elapsed(),
            Duration::from_secs(5),
            "and woke on the advance"
        );
        snare::real(|| controller.join().unwrap());
    });
}

#[test]
fn paused_sleep_parks_until_resume() {
    let sim = paused_sim();
    let time = sim.time();
    sim.run(|| {
        let real = real_now();
        let start = Instant::now();
        let controller = after_real(Duration::from_millis(200), move || time.resume());
        std::thread::sleep(Duration::from_secs(1));
        assert!(
            real_since(real) >= Duration::from_millis(150),
            "the sleep parked"
        );
        assert!(
            start.elapsed() >= Duration::from_secs(1),
            "and finished once resumed"
        );
        snare::real(|| controller.join().unwrap());
    });
}

#[test]
fn paused_rcvtimeo_holds() {
    let sim = paused_sim();
    let time = sim.time();
    sim.run(|| {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let real = real_now();
        let start = Instant::now();
        let controller = after_real(Duration::from_millis(200), move || {
            time.advance(Duration::from_secs(2));
        });
        let mut buf = [0u8; 8];
        let err = sock.recv_from(&mut buf).unwrap_err();
        assert!(
            start.elapsed() >= Duration::from_secs(1),
            "the whole timeout elapsed on the clock"
        );
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "{err:?}"
        );
        assert!(
            real_since(real) >= Duration::from_millis(150),
            "the timeout held while paused"
        );
        snare::real(|| controller.join().unwrap());
    });
}

#[test]
fn paused_quiescence_is_not_deadlock() {
    let sim = paused_sim();
    let time = sim.time();
    sim.run(|| {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let real = real_now();
        let controller = after_real(Duration::from_millis(500), move || time.resume());
        let mut buf = [0u8; 8];
        assert!(
            sock.recv_from(&mut buf).is_err(),
            "gave up once resumed, as a deadlock does"
        );
        assert!(
            real_since(real) >= Duration::from_millis(450),
            "held while paused rather than declaring a deadlock"
        );
        snare::real(|| controller.join().unwrap());
    });
}

#[test]
fn paused_condvar_wait_timeout_holds() {
    let sim = paused_sim();
    let time = sim.time();
    sim.run(|| {
        let pair = Arc::new((Mutex::new(()), Condvar::new()));
        let real = real_now();
        let controller = after_real(Duration::from_millis(200), move || {
            time.advance(Duration::from_secs(2));
        });
        let (lock, cv) = &*pair;
        let guard = lock.lock().unwrap();
        let (_guard, result) = cv
            .wait_timeout_while(guard, Duration::from_secs(1), |_| true)
            .unwrap();
        assert!(result.timed_out());
        assert!(
            real_since(real) >= Duration::from_millis(150),
            "the timeout held while paused"
        );
        snare::real(|| controller.join().unwrap());
    });
}

#[test]
fn advance_expires_long_native_wait() {
    let sim = paused_sim();
    let time = sim.time();
    sim.run(|| {
        let pair = Arc::new((Mutex::new(()), Condvar::new()));
        let real = real_now();
        let controller = after_real(Duration::from_millis(100), move || {
            time.advance(Duration::from_secs(7200));
        });
        let (lock, cv) = &*pair;
        let guard = lock.lock().unwrap();
        let (_guard, result) = cv
            .wait_timeout_while(guard, Duration::from_secs(3600), |_| true)
            .unwrap();
        assert!(result.timed_out());
        assert!(real_since(real) < Duration::from_secs(30));
        snare::real(|| controller.join().unwrap());
    });
}

/// Real time taken by `f`, inside a sim scaled to `rate`.
fn real_time_of(rate: f64, f: impl FnOnce()) -> Duration {
    let sim = Sim::builder().time_rate(rate).build();
    sim.run(|| {
        let real = real_now();
        f();
        real_since(real)
    })
}

#[test]
fn scaled_rcvtimeo() {
    let took = real_time_of(10.0, || {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let start = Instant::now();
        let mut buf = [0u8; 8];
        assert!(sock.recv_from(&mut buf).is_err());
        assert!(start.elapsed() >= Duration::from_secs(2));
    });
    assert!(
        (Duration::from_millis(150)..Duration::from_secs(2)).contains(&took),
        "2 virtual s at 10x: {took:?}"
    );
}

#[test]
fn scaled_udp_latency() {
    let best = (0..10)
        .map(|i| {
            real_time_of(10.0, move || {
                let port = 47_100 + i;
                let rx = UdpSocket::bind(("127.0.0.1", port)).unwrap();
                snare::set_udp_policy(("127.0.0.1", port), |p| {
                    p.latency = Duration::from_millis(500)
                });
                let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
                let start = Instant::now();
                tx.send_to(b"x", ("127.0.0.1", port)).unwrap();
                let mut buf = [0u8; 8];
                rx.recv_from(&mut buf).unwrap();
                assert!(start.elapsed() >= Duration::from_millis(500));
            })
        })
        .min()
        .unwrap();
    assert!(
        (Duration::from_millis(40)..Duration::from_millis(600)).contains(&best),
        "500 virtual ms of latency at 10x: best {best:?}"
    );
}

#[test]
fn scaled_native_wait() {
    let took = real_time_of(10.0, || {
        let pair = (Mutex::new(()), Condvar::new());
        let guard = pair.0.lock().unwrap();
        let start = Instant::now();
        let (_guard, result) = pair
            .1
            .wait_timeout_while(guard, Duration::from_secs(1), |_| true)
            .unwrap();
        assert!(result.timed_out());
        assert!(start.elapsed() >= Duration::from_secs(1));
    });
    assert!(
        (Duration::from_millis(80)..Duration::from_secs(1)).contains(&took),
        "1 virtual s at 10x: {took:?}"
    );
}

#[cfg(unix)]
#[test]
fn scaled_poll_timeout() {
    let took = real_time_of(10.0, || {
        let mut poll = mio::Poll::new().unwrap();
        let mut sock = mio::net::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        poll.registry()
            .register(&mut sock, mio::Token(0), mio::Interest::READABLE)
            .unwrap();
        let mut events = mio::Events::with_capacity(4);
        let start = Instant::now();
        poll.poll(&mut events, Some(Duration::from_secs(1)))
            .unwrap();
        assert!(events.is_empty());
        assert!(start.elapsed() >= Duration::from_secs(1));
    });
    assert!(
        (Duration::from_millis(80)..Duration::from_secs(1)).contains(&took),
        "1 virtual s at 10x: {took:?}"
    );
}

#[cfg(windows)]
#[test]
fn scaled_poll_timeout() {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{POLLRDNORM, WSAPOLLFD, WSAPoll};
    let took = real_time_of(10.0, || {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut pfd = WSAPOLLFD {
            fd: sock.as_raw_socket() as usize,
            events: POLLRDNORM,
            revents: 0,
        };
        let start = Instant::now();
        assert_eq!(unsafe { WSAPoll(&mut pfd, 1, 1000) }, 0);
        assert!(start.elapsed() >= Duration::from_secs(1));
    });
    assert!(
        (Duration::from_millis(80)..Duration::from_secs(1)).contains(&took),
        "1 virtual s at 10x: {took:?}"
    );
}

#[test]
fn scaled_tester_cyclic() {
    let took = real_time_of(4.0, || {
        let rx = UdpSocket::bind("127.0.0.1:47201").unwrap();
        let ticker = udp_tester::<snare::Bytes>("127.0.0.1:47200")
            .with_cyclic_action(Duration::from_millis(200), || {
                TesterAction::SendTo(
                    "127.0.0.1:47201".parse().unwrap(),
                    snare::Bytes(b"tick".to_vec()),
                )
            })
            .until_after(Duration::from_millis(1050));
        let start = Instant::now();
        let runner = std::thread::spawn(move || snare::run_testers!(ticker));
        let mut buf = [0u8; 8];
        for i in 0..5 {
            if let Err(e) = rx.recv_from(&mut buf) {
                panic!("tick {i} at {:?}: {e}", start.elapsed());
            }
        }
        assert!(
            start.elapsed() >= Duration::from_secs(1),
            "five 200 ms ticks"
        );
        runner.join().unwrap();
    });
    assert!(
        (Duration::from_millis(200)..Duration::from_secs(2)).contains(&took),
        "a virtual second of ticks at 4x: {took:?}"
    );
}

#[test]
fn time_free_function_reaches_the_running_sim() {
    let sim = Sim::new();
    sim.run(|| {
        snare::time().advance(Duration::from_secs(5));
        let spawned = std::thread::spawn(|| snare::time().value()).join().unwrap();
        assert_eq!(spawned, Duration::from_secs(5));
    });
    assert_eq!(sim.time_value(), Duration::from_secs(5));
}

#[test]
#[should_panic(expected = "inside Sim::run")]
fn time_free_function_panics_outside_a_sim() {
    let _ = snare::time();
}

#[test]
#[should_panic(expected = "runs on the real clock")]
fn wall_clock_controls_panic() {
    Sim::builder().wall_clock().build().pause_time();
}

#[test]
#[should_panic(expected = "runs on the real clock")]
fn wall_clock_time_free_function_panics() {
    Sim::builder().wall_clock().build().run(|| {
        let _ = snare::time();
    });
}

#[test]
fn wall_clock_with_a_rate_is_controllable() {
    let sim = Sim::builder().wall_clock().time_rate(1.0).build();
    assert_eq!(sim.time_rate(), 1.0);
    sim.pause_time();
    assert_eq!(sim.time_rate(), 0.0);
}

#[cfg(windows)]
#[test]
fn scaled_wall_clock_pause_parks_a_sleeper() {
    let sim = Sim::builder().wall_clock().time_rate(1.0).build();
    sim.pause_time();
    let time = sim.time();
    sim.run(|| {
        let real = real_now();
        let start = Instant::now();
        let controller = after_real(Duration::from_millis(200), move || time.resume());
        std::thread::sleep(Duration::from_secs(3));
        assert!(
            real_since(real) >= Duration::from_millis(150),
            "the sleep parked"
        );
        assert!(
            start.elapsed() >= Duration::from_secs(3),
            "and jumped once resumed"
        );
        snare::real(|| controller.join().unwrap());
    });
}

#[cfg(windows)]
#[test]
fn scaled_wall_clock_paused_recv_timeout_holds() {
    let sim = Sim::builder().wall_clock().time_rate(1.0).build();
    sim.pause_time();
    let time = sim.time();
    sim.run(|| {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let real = real_now();
        let start = Instant::now();
        let controller = after_real(Duration::from_millis(1500), move || {
            time.advance(Duration::from_secs(2));
        });
        assert!(sock.recv_from(&mut [0u8; 8]).is_err());
        let waited = real_since(real);
        assert!(
            waited >= Duration::from_millis(1400),
            "held until the advance: {waited:?}"
        );
        assert!(start.elapsed() >= Duration::from_secs(1));
        snare::real(|| controller.join().unwrap());
    });
}

#[cfg(windows)]
#[test]
fn scaled_wall_clock_paused_recv_timeout_expires_on_resume() {
    let sim = Sim::builder().wall_clock().time_rate(1.0).build();
    sim.pause_time();
    let time = sim.time();
    sim.run(|| {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let real = real_now();
        let start = Instant::now();
        let controller = after_real(Duration::from_millis(200), move || time.resume());
        assert!(sock.recv_from(&mut [0u8; 8]).is_err());
        assert!(
            real_since(real) >= Duration::from_millis(450),
            "held while paused, then expired at the resumed rate"
        );
        assert!(
            start.elapsed() >= Duration::from_millis(300),
            "reached the deadline on resume"
        );
        snare::real(|| controller.join().unwrap());
    });
}

#[cfg(windows)]
#[test]
fn scaled_wall_clock_paused_condvar_wait_timeout_holds() {
    let sim = Sim::builder().wall_clock().time_rate(1.0).build();
    sim.pause_time();
    let time = sim.time();
    sim.run(|| {
        let pair = (Mutex::new(()), Condvar::new());
        let real = real_now();
        let controller = after_real(Duration::from_millis(1500), move || {
            time.advance(Duration::from_secs(2));
        });
        let guard = pair.0.lock().unwrap();
        let (_guard, result) = pair
            .1
            .wait_timeout_while(guard, Duration::from_secs(1), |_| true)
            .unwrap();
        assert!(result.timed_out());
        let waited = real_since(real);
        assert!(
            waited >= Duration::from_millis(1400),
            "held until the advance: {waited:?}"
        );
        snare::real(|| controller.join().unwrap());
    });
}

#[test]
fn ephemeral_ports_are_per_sim() {
    let ports: Vec<u16> = (0..2)
        .map(|i| {
            std::thread::spawn(move || {
                Sim::new().run(|| {
                    let addr = format!("127.0.0.{}:9{}50", 20 + i, i);
                    let server = snare::connect_tester::<snare::Line>(addr.as_str())
                        .until_after(Duration::from_millis(50));
                    let client = std::thread::spawn(move || {
                        let stream = std::net::TcpStream::connect(addr.as_str()).unwrap();
                        stream.local_addr().unwrap().port()
                    });
                    snare::run_testers!(server);
                    client.join().unwrap()
                })
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    assert_eq!(
        ports,
        [49152, 49152],
        "each sim numbers its client ports from 49152"
    );
}

#[cfg(windows)]
#[test]
fn scaled_wall_clock_rate_changes_never_go_backwards() {
    let sim = Sim::builder().wall_clock().time_rate(1.0).build();
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

#[cfg(windows)]
#[test]
fn scaled_wall_clock_pause_holds_a_running_recv_timeout() {
    let sim = Sim::builder().wall_clock().time_rate(1.0).build();
    let time = sim.time();
    let advanced = Arc::new(AtomicBool::new(false));
    let seen = advanced.clone();
    sim.run(|| {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
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
