//! Deterministic scheduling (`Sim::builder().deterministic()`): one thread runs at a time and
//! control passes only where a thread waits, always to the next thread in a fixed order — so every
//! interleaving below comes out the same on every run, however the OS would have scheduled it.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use snare::{Line, Sim, TesterAction, connect_tester, run_testers};

fn dsim(seed: u64) -> Sim {
    Sim::builder().deterministic().seed(seed).build()
}

/// Runs `scenario` twice on fresh deterministic sims and checks both runs saw the same thing.
fn replays<T: PartialEq + std::fmt::Debug>(scenario: impl Fn() -> T) -> T {
    let first = dsim(1).run(&scenario);
    let second = dsim(1).run(&scenario);
    assert_eq!(first, second, "the same seed must replay the same run");
    first
}

#[test]
fn yields_interleave_threads_in_a_fixed_order() {
    let log = replays(|| {
        let log = Arc::new(Mutex::new(Vec::new()));
        let workers: Vec<_> = (0..4)
            .map(|w| {
                let log = log.clone();
                std::thread::spawn(move || {
                    for step in 0..5 {
                        log.lock().unwrap().push((w, step));
                        std::thread::yield_now();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        Arc::try_unwrap(log).unwrap().into_inner().unwrap()
    });
    assert_eq!(log.len(), 20);
    let first_five: Vec<_> = log.iter().take(5).map(|(w, _)| *w).collect();
    assert!(
        first_five.windows(2).any(|w| w[0] != w[1]),
        "yields hand the baton around rather than running each thread to completion: {log:?}"
    );
}

#[test]
fn mutex_contention_resolves_the_same_way_every_run() {
    let order = replays(|| {
        let lock = Arc::new(Mutex::new(Vec::new()));
        let workers: Vec<_> = (0..5)
            .map(|w| {
                let lock = lock.clone();
                std::thread::spawn(move || {
                    for _ in 0..3 {
                        let mut held = lock.lock().unwrap();
                        held.push(w);
                        // Hold the lock across a wait, so the others pile up behind it.
                        std::thread::sleep(Duration::from_millis(1));
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        Arc::try_unwrap(lock).unwrap().into_inner().unwrap()
    });
    assert_eq!(order.len(), 15);
}

#[test]
fn channel_messages_from_many_producers_arrive_in_a_fixed_order() {
    let received = replays(|| {
        let (tx, rx) = mpsc::channel();
        let producers: Vec<_> = (0..4)
            .map(|p| {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    for n in 0..5 {
                        tx.send((p, n)).unwrap();
                        std::thread::sleep(Duration::from_micros(500 * (p + 1)));
                    }
                })
            })
            .collect();
        drop(tx);
        let received: Vec<_> = rx.iter().collect();
        for producer in producers {
            producer.join().unwrap();
        }
        received
    });
    assert_eq!(received.len(), 20);
}

#[test]
fn a_condvar_ping_pong_completes_and_replays() {
    let trace = replays(|| {
        let state = Arc::new((Mutex::new((0u32, Vec::new())), Condvar::new()));
        let other = state.clone();
        let pong = std::thread::spawn(move || {
            let (lock, cv) = &*other;
            for _ in 0..5 {
                let mut s = lock.lock().unwrap();
                while s.0 % 2 == 0 {
                    s = cv.wait(s).unwrap();
                }
                s.0 += 1;
                s.1.push("pong");
                cv.notify_one();
            }
        });
        let (lock, cv) = &*state;
        for _ in 0..5 {
            let mut s = lock.lock().unwrap();
            while s.0 % 2 == 1 {
                s = cv.wait(s).unwrap();
            }
            s.0 += 1;
            s.1.push("ping");
            cv.notify_one();
        }
        pong.join().unwrap();
        let s = lock.lock().unwrap();
        s.1.clone()
    });
    assert_eq!(trace, ["ping", "pong"].repeat(5));
}

#[test]
fn sleepers_wake_in_time_order_with_ties_in_a_fixed_order() {
    let wakes = replays(|| {
        let log = Arc::new(Mutex::new(Vec::new()));
        let sleepers: Vec<_> = [30u64, 10, 20, 10, 30]
            .into_iter()
            .enumerate()
            .map(|(i, ms)| {
                let log = log.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(ms));
                    log.lock().unwrap().push((ms, i));
                })
            })
            .collect();
        for sleeper in sleepers {
            sleeper.join().unwrap();
        }
        Arc::try_unwrap(log).unwrap().into_inner().unwrap()
    });
    let times: Vec<u64> = wakes.iter().map(|(ms, _)| *ms).collect();
    assert_eq!(times, [10, 10, 20, 30, 30], "woken in virtual-time order");
}

#[test]
fn scoped_threads_and_joins_work() {
    let total = replays(|| {
        let mut parts = [0u64; 4];
        std::thread::scope(|scope| {
            for (i, part) in parts.iter_mut().enumerate() {
                scope.spawn(move || {
                    std::thread::sleep(Duration::from_millis(i as u64));
                    *part = (i as u64 + 1) * 10;
                });
            }
        });
        parts.iter().sum::<u64>()
    });
    assert_eq!(total, 100);
}

#[test]
fn randomness_across_threads_replays() {
    let hashes = replays(|| {
        let workers: Vec<_> = (0..3)
            .map(|_| std::thread::spawn(|| RandomState::new().hash_one(7u64)))
            .collect();
        workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(hashes.len(), 3);
}

/// A lock in static data, held most of the time by a thread outside every sim.
#[cfg(target_os = "macos")]
static HELD_OUTSIDE: Mutex<()> = Mutex::new(());

/// Scheduled threads take a lock a thread outside the sim keeps busy, while the threads they spawn
/// start and exit beside the baton: each contended take waits for the outside holder in real time
/// without letting another scheduled thread run, so the order replays however long those waits
/// and the children's startups take. macOS only: there a pthread mutex names its owner, while a
/// Linux futex word or Windows address word does not and gets only a short grace for an outside
/// holder (OPEN_BUGS.md, "Locks held outside the sim").
#[cfg(target_os = "macos")]
#[test]
fn a_lock_held_outside_the_sim_does_not_reorder_threads_starting_beside_it() {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let holder = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let spin = |span| {
                let until = Instant::now() + span;
                while Instant::now() < until {}
            };
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let held = HELD_OUTSIDE.lock().unwrap();
                spin(Duration::from_micros(50));
                drop(held);
                // macOS mutexes are not fair: a holder that relocks at once starves the waiters.
                std::thread::sleep(Duration::from_micros(50));
            }
        })
    };
    let scenario = || {
        let log = Arc::new(Mutex::new(Vec::new()));
        let workers: Vec<_> = (0..8)
            .map(|w| {
                let log = log.clone();
                std::thread::spawn(move || {
                    for step in 0..20 {
                        let children: Vec<_> = (0..4)
                            .map(|_| {
                                let child = std::thread::spawn(|| {});
                                drop(HELD_OUTSIDE.lock().unwrap());
                                child
                            })
                            .collect();
                        log.lock().unwrap().push((w, step));
                        for child in children {
                            child.join().unwrap();
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        Arc::try_unwrap(log).unwrap().into_inner().unwrap()
    };
    let first = dsim(1).run(scenario);
    for _ in 0..30 {
        assert_eq!(
            dsim(1).run(scenario),
            first,
            "the same seed must replay the same run"
        );
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    holder.join().unwrap();
    assert_eq!(first.len(), 160);
}

#[test]
fn testers_run_under_the_schedule() {
    let line = replays(|| {
        let server = connect_tester::<Line>("127.0.0.8:9500")
            .then_action(|msg, _| TesterAction::Send(Line(format!("echo:{}", msg.0))))
            .until_after(Duration::from_millis(100));
        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.8:9500").unwrap();
            (&stream).write_all(b"hi\n").unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            line
        });
        run_testers!(server);
        client.join().unwrap()
    });
    assert_eq!(line, "echo:hi\n");
}

#[test]
fn a_deadlocked_receive_still_gives_up() {
    dsim(0).run(|| {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut buf = [0u8; 4];
        assert!(sock.recv_from(&mut buf).is_err());
    });
}

#[test]
fn timeouts_run_on_virtual_time() {
    let real = snare::real(Instant::now);
    dsim(0).run(|| {
        let (_tx, rx) = mpsc::channel::<u8>();
        let start = Instant::now();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        assert!(start.elapsed() >= Duration::from_secs(30));
    });
    assert!(snare::real(|| real.elapsed()) < Duration::from_secs(30));
}

#[cfg(target_os = "linux")]
#[test]
fn a_simhost_run_replays_under_the_schedule() {
    let run = || {
        let host = snare::HostProfile::new().build();
        Sim::builder()
            .host(host)
            .deterministic()
            .seed(3)
            .build()
            .run(|| {
                let rx = UdpSocket::bind("127.0.0.1:9600").unwrap();
                let senders: Vec<_> = (0..3u8)
                    .map(|s| {
                        std::thread::spawn(move || {
                            let tx = UdpSocket::bind(("127.0.0.1", 9610 + u16::from(s))).unwrap();
                            for n in 0..4u8 {
                                tx.send_to(&[s, n], "127.0.0.1:9600").unwrap();
                                std::thread::sleep(Duration::from_micros(300 * (u64::from(s) + 1)));
                            }
                        })
                    })
                    .collect();
                let start = Instant::now();
                let mut got = Vec::new();
                let mut buf = [0u8; 2];
                for _ in 0..12 {
                    rx.recv_from(&mut buf).unwrap();
                    got.push((buf, start.elapsed()));
                }
                for sender in senders {
                    sender.join().unwrap();
                }
                got
            })
    };
    let first = run();
    assert_eq!(first.len(), 12);
    assert_eq!(first, run(), "the same seed must replay the same run");
}

#[test]
#[should_panic(expected = "deterministic Sim cannot run its clock at a real-time rate")]
fn finite_rate_rejected() {
    let _ = Sim::builder().deterministic().time_rate(2.0).build();
}

#[test]
#[should_panic(expected = "deterministic Sim cannot run its clock at a real-time rate")]
fn finite_rate_rejected_after_build() {
    dsim(0).set_time_rate(1.0);
}

#[test]
fn clock_controls_work_under_the_schedule() {
    let sim = dsim(0);
    sim.pause_time();
    sim.advance_time(Duration::from_secs(1));
    sim.set_time_value(Duration::from_secs(2));
    sim.set_time_rate(f64::INFINITY);
    assert_eq!(sim.time_rate(), f64::INFINITY);
    assert_eq!(sim.time_value(), Duration::from_secs(2));
}

#[test]
fn paused_det_parks_and_unmanaged_advance_releases_in_lineage_order() {
    let run = || {
        let sim = dsim(5);
        sim.pause_time();
        let time = sim.time();
        sim.run(|| {
            let real = snare::real(Instant::now);
            let controller = snare::real(|| {
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(100));
                    time.advance(Duration::from_secs(1));
                })
            });
            let log = Arc::new(Mutex::new(Vec::new()));
            let sleepers: Vec<_> = (0..4u64)
                .map(|i| {
                    let log = log.clone();
                    std::thread::spawn(move || {
                        let start = Instant::now();
                        std::thread::sleep(Duration::from_millis(10 * (4 - i)));
                        log.lock().unwrap().push((i, start.elapsed()));
                    })
                })
                .collect();
            for sleeper in sleepers {
                sleeper.join().unwrap();
            }
            snare::real(|| controller.join().unwrap());
            assert!(
                snare::real(|| real.elapsed()) >= Duration::from_millis(80),
                "the sleepers parked until the outside advance"
            );
            Arc::try_unwrap(log).unwrap().into_inner().unwrap()
        })
    };
    let first = run();
    assert_eq!(first.len(), 4);
    assert!(
        first
            .iter()
            .all(|(_, slept)| *slept == Duration::from_secs(1)),
        "{first:?}"
    );
    assert_eq!(first, run(), "released in the same order on every run");
}

#[test]
fn exiting_thread_releases_a_native_join_with_a_paused_sibling() {
    let sim = dsim(7);
    sim.pause_time();
    sim.run(|| {
        snare::sched::mark_driver_thread();
        let exec = snare::sched::attach(Default::default()).unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = receiver.local_addr().unwrap();
        let idle = std::thread::spawn(move || {
            receiver.recv_from(&mut [0; 4]).unwrap();
        });
        let sleeper = std::thread::spawn(|| std::thread::sleep(Duration::from_secs(10)));
        let start = snare::real(Instant::now);
        loop {
            let state = exec.quiescence();
            if state.quiescent && state.blocked == 2 {
                break;
            }
            assert!(snare::real(|| start.elapsed()) < Duration::from_secs(2));
            snare::real(std::thread::yield_now);
        }
        let (joined, completed) = mpsc::channel();
        let observer = snare::real(|| {
            std::thread::spawn(move || {
                idle.join().unwrap();
                joined.send(()).unwrap();
            })
        });
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .send_to(b"stop", address)
            .unwrap();
        let joined_before_advance =
            snare::real(|| completed.recv_timeout(Duration::from_secs(1))).is_ok();
        exec.enter_timestamp(Duration::from_secs(10));
        exec.leave_timestamp(Duration::from_secs(10));
        sleeper.join().unwrap();
        snare::real(|| observer.join().unwrap());
        assert!(
            joined_before_advance,
            "native join waited for a sibling's clock"
        );
    });
}

#[test]
fn set_value_under_det_from_managed_thread() {
    let run = || {
        let sim = dsim(2);
        sim.pause_time();
        sim.run(|| {
            let log = Arc::new(Mutex::new(Vec::new()));
            let theirs = log.clone();
            let sleeper = std::thread::spawn(move || {
                let start = Instant::now();
                std::thread::sleep(Duration::from_secs(5));
                theirs.lock().unwrap().push(("woke", start.elapsed()));
            });
            std::thread::yield_now();
            let time = snare::time();
            log.lock().unwrap().push(("set", time.value()));
            time.set_value(time.value() + Duration::from_secs(5));
            sleeper.join().unwrap();
            Arc::try_unwrap(log).unwrap().into_inner().unwrap()
        })
    };
    let first = run();
    assert_eq!(
        first,
        [("set", Duration::ZERO), ("woke", Duration::from_secs(5))]
    );
    assert_eq!(first, run());
}

/// Three TCP clients and two UDP senders on a lossy, jittery, duplicating link, all racing one
/// another; returns the order the threads did their work in.
fn busy_edge() -> Vec<String> {
    let trace = Arc::new(Mutex::new(Vec::new()));
    snare::set_udp_policy("127.0.0.8:9611", |p| {
        p.loss_rate = 0.3;
        p.duplicate_rate = 0.3;
        p.jitter = Duration::from_millis(5);
    });
    let server = connect_tester::<Line>("127.0.0.8:9610")
        .then_test(|msg, _| (msg.0 != "skip").then_some(msg))
        .then_action(|msg, _| TesterAction::Send(Line(format!("echo:{}", msg.0))))
        .until_after(Duration::from_millis(100));
    let device = snare::udp_tester::<snare::Bytes>("127.0.0.8:9611")
        .then_action(|msg, _| TesterAction::Send(msg))
        .until_after(Duration::from_millis(100));
    let tcp = (0..3).map(|c| {
        let trace = trace.clone();
        std::thread::spawn(move || {
            let stream = TcpStream::connect("127.0.0.8:9610").unwrap();
            let mut reader = BufReader::new(&stream);
            for n in 0..3 {
                (&stream)
                    .write_all(format!("skip\n{c}.{n}\n").as_bytes())
                    .unwrap();
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                trace.lock().unwrap().push(line);
            }
        })
    });
    let udp = (0..2).map(|c| {
        let trace = trace.clone();
        std::thread::spawn(move || {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            for n in 0..10u8 {
                sock.send_to(&[c, n], "127.0.0.8:9611").unwrap();
                trace.lock().unwrap().push(format!("udp {c}.{n}"));
                std::thread::sleep(Duration::from_millis(1));
            }
        })
    });
    let workers: Vec<_> = tcp.chain(udp).collect();
    run_testers!(server, device);
    for worker in workers {
        worker.join().unwrap();
    }
    Arc::try_unwrap(trace).unwrap().into_inner().unwrap()
}

#[test]
fn the_event_log_replays_under_the_schedule() {
    let log = replays(|| {
        busy_edge();
        snare::recorded_events()
    });
    assert!(
        log.iter()
            .any(|e| matches!(e.event, snare::RecordedEvent::Link { .. })),
        "the lossy link logged faults: {log:?}"
    );
    assert!(
        log.windows(2)
            .all(|w| w[0].seq < w[1].seq && w[0].at <= w[1].at)
    );
}

#[test]
fn recording_does_not_perturb_the_schedule() {
    let run = |record| {
        let sim = Sim::builder()
            .deterministic()
            .seed(7)
            .record_events(record)
            .build();
        let trace = sim.run(busy_edge);
        (trace, sim.recorded_events().len())
    };
    let (recorded, logged) = run(true);
    let (unrecorded, nothing) = run(false);
    assert!(logged > 0);
    assert_eq!(nothing, 0);
    assert_eq!(recorded, unrecorded, "recording must not change the run");
}

fn flapping_link() -> Sim {
    let policy = snare::NicPolicy {
        latency: Duration::from_millis(2),
        jitter: Duration::from_millis(3),
        loss_rate: 0.2,
        duplicate_rate: 0.1,
    };
    Sim::builder()
        .deterministic()
        .seed(3)
        .nic(
            snare::NicSpec::new("eth0")
                .index(4)
                .address("10.0.0.1/24".parse::<snare::IpNet>().unwrap())
                .station("10.0.0.2".parse::<std::net::IpAddr>().unwrap())
                .policy(policy),
        )
        .build()
}

fn flap_run() -> (Vec<(u8, Duration)>, Vec<snare::RecordedEvent>) {
    let sim = flapping_link();
    let got = sim.run(|| {
        let rx = UdpSocket::bind("10.0.0.2:7000").unwrap();
        rx.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let start = Instant::now();
        let sender = std::thread::spawn(|| {
            let tx = UdpSocket::bind("10.0.0.1:0").unwrap();
            for i in 0..30u8 {
                let sent = tx.send_to(&[i], "10.0.0.2:7000");
                // Windows media sense withdraws the interface's routes with its carrier.
                if !cfg!(windows) {
                    sent.unwrap();
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let flapper = std::thread::spawn(|| {
            for _ in 0..3 {
                std::thread::sleep(Duration::from_millis(5));
                snare::set_link("eth0", false).unwrap();
                std::thread::sleep(Duration::from_millis(2));
                snare::set_link("eth0", true).unwrap();
            }
            snare::schedule_link("eth0", Duration::from_millis(3), false).unwrap();
            snare::schedule_link("eth0", Duration::from_millis(6), true).unwrap();
        });
        let mut got = Vec::new();
        let mut buf = [0u8; 4];
        while let Ok((n, _)) = rx.recv_from(&mut buf) {
            assert_eq!(n, 1);
            got.push((buf[0], start.elapsed()));
        }
        sender.join().unwrap();
        flapper.join().unwrap();
        got
    });
    let events = sim.recorded_events().into_iter().map(|e| e.event).collect();
    (got, events)
}

#[test]
fn link_flap_replays() {
    let (got, events) = flap_run();
    assert_eq!((got.clone(), events.clone()), flap_run());
    assert!(got.len() > 5 && got.len() < 30, "{got:?}");
    let flaps = events
        .iter()
        .filter(|e| matches!(e, snare::RecordedEvent::NicChanged { carrier: false, .. }))
        .count();
    assert_eq!(flaps, 4, "{events:?}");
}

#[test]
fn scheduled_link_up_time_skips_under_baton() {
    let real = Instant::now();
    let waited = replays(|| {
        let sim_nic = snare::NicSpec::new("eth9")
            .address("10.9.0.1/24".parse::<snare::IpNet>().unwrap())
            .station("10.9.0.2".parse::<std::net::IpAddr>().unwrap());
        snare::add_nic(sim_nic).unwrap();
        let listener = std::net::TcpListener::bind("10.9.0.2:9500").unwrap();
        let mut client = TcpStream::connect("10.9.0.2:9500").unwrap();
        let (mut server, _) = listener.accept().unwrap();
        snare::set_link("eth9", false).unwrap();
        client.write_all(b"later").unwrap();
        snare::schedule_link("eth9", Duration::from_secs(10), true).unwrap();
        let t0 = Instant::now();
        let mut buf = [0u8; 8];
        let n = std::io::Read::read(&mut server, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"later");
        t0.elapsed()
    });
    assert!(waited >= Duration::from_secs(10), "{waited:?}");
    assert!(
        real.elapsed() < Duration::from_secs(2),
        "{:?}",
        real.elapsed()
    );
}

#[test]
fn det_connect_timeout_replays() {
    let log = replays(|| {
        let delayed: std::net::SocketAddr = "127.0.0.7:7400".parse().unwrap();
        let listener = std::net::TcpListener::bind(delayed).unwrap();
        let until = Instant::now() + Duration::from_millis(1500);
        snare::set_listener_behavior(delayed, snare::ListenerBehavior::DelayingUntil(until));
        let start = Instant::now();
        let log = Arc::new(Mutex::new(Vec::new()));
        let workers: Vec<_> = [
            (0, "10.255.0.1:80", 5000),
            (1, "127.0.0.7:7400", 5000),
            (2, "10.255.0.2:80", 2500),
        ]
        .into_iter()
        .map(|(w, dest, ms)| {
            let log = log.clone();
            std::thread::spawn(move || {
                let dest = dest.parse().unwrap();
                let result = TcpStream::connect_timeout(&dest, Duration::from_millis(ms))
                    .map(drop)
                    .map_err(|e| e.kind());
                log.lock().unwrap().push((w, result, start.elapsed()));
            })
        })
        .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        listener.accept().unwrap();
        Arc::try_unwrap(log).unwrap().into_inner().unwrap()
    });
    assert_eq!(log.len(), 3);
    let outcome = |w| log.iter().find(|e| e.0 == w).unwrap().1;
    assert_eq!(outcome(0), Err(std::io::ErrorKind::TimedOut));
    assert_eq!(outcome(1), Ok(()));
    assert_eq!(outcome(2), Err(std::io::ErrorKind::TimedOut));
}

#[test]
fn det_backpressure_replays() {
    use std::io::Read;
    let log = replays(|| {
        let listener = std::net::TcpListener::bind("127.0.0.1:9300").unwrap();
        snare::set_tcp_policy("127.0.0.1:9300", |p| {
            p.recv_window = Some(16 * 1024);
            p.latency = Duration::from_millis(5);
            p.jitter = Duration::from_millis(3);
        });
        let mut client = TcpStream::connect("127.0.0.1:9300").unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let start = Instant::now();
        let writer = std::thread::spawn(move || {
            let data: Vec<u8> = (0..2048 * 1024).map(|i| (i % 251) as u8).collect();
            let mut writes = Vec::new();
            let mut sent = 0;
            while sent < data.len() {
                let end = data.len().min(sent + 8192);
                let n = client.write(&data[sent..end]).unwrap();
                writes.push((n, start.elapsed()));
                sent += n;
            }
            writes
        });
        let mut reads = Vec::new();
        let mut got = 0;
        let mut buf = [0u8; 5000];
        while got < 2048 * 1024 {
            let n = server.read(&mut buf).unwrap();
            reads.push((n, start.elapsed()));
            got += n;
        }
        (writer.join().unwrap(), reads)
    });
    let (writes, _) = log;
    assert!(
        writes.last().unwrap().1 >= Duration::from_millis(5 * 8),
        "the window held the writer back for round trips: {writes:?}"
    );
}

#[test]
fn det_icmp_and_stall_replays() {
    let log = replays(|| {
        let start = Instant::now();
        let mut log = Vec::new();
        snare::set_udp_policy("127.0.0.1:9", |p| p.latency = Duration::from_millis(7));
        let a = UdpSocket::bind("127.0.0.1:9400").unwrap();
        let b = UdpSocket::bind("127.0.0.1:9401").unwrap();
        a.connect("127.0.0.1:9").unwrap();
        a.send(b"x").unwrap();
        let mut buf = [0u8; 4];
        log.push(format!(
            "{:?} {:?}",
            a.recv(&mut buf).map_err(|e| e.kind()),
            start.elapsed()
        ));
        snare::quiesce(
            "127.0.0.1:9401",
            Duration::from_millis(30),
            snare::Direction::Receive,
        );
        let sender = std::thread::spawn(|| {
            let c = UdpSocket::bind("127.0.0.1:9402").unwrap();
            for i in 0..3u8 {
                c.send_to(&[i], "127.0.0.1:9401").unwrap();
                std::thread::sleep(Duration::from_millis(4));
            }
        });
        for _ in 0..3 {
            let (n, from) = b.recv_from(&mut buf).unwrap();
            log.push(format!("{} {:?} {from} {:?}", n, buf[0], start.elapsed()));
        }
        sender.join().unwrap();
        log
    });
    assert_eq!(log.len(), 4);
}
