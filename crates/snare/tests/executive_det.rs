//! An executive driving a deterministic sim: the schedule idles while it owns time, its timestamps
//! hold the baton, and a run it drives replays exactly.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use snare::Sim;
use snare::sched::{self, Executive, ExecutiveConfig, Grant, Quiescence};

const MS: Duration = Duration::from_millis(1);

fn dsim(seed: u64) -> Sim {
    Sim::builder().deterministic().seed(seed).build()
}

fn real_now() -> Instant {
    snare::real(Instant::now)
}

fn real_since(start: Instant) -> Duration {
    snare::real(|| start.elapsed())
}

fn real_sleep(d: Duration) {
    snare::real(|| thread::sleep(d));
}

fn settle(exec: &Executive) -> Quiescence {
    let start = real_now();
    loop {
        let q = exec.quiescence();
        if q.quiescent && q.blocked > 0 {
            return q;
        }
        assert!(
            real_since(start) < Duration::from_secs(20),
            "the sim never went quiescent: {q:?}"
        );
        real_sleep(Duration::from_micros(200));
    }
}

/// Jumps from timer to timer until `done`.
fn drive(exec: &Executive, done: impl Fn() -> bool) {
    let start = real_now();
    while !done() {
        assert!(
            real_since(start) < Duration::from_secs(30),
            "the run never finished"
        );
        let q = exec.quiescence();
        if !q.quiescent || q.blocked == 0 {
            real_sleep(Duration::from_micros(200));
            continue;
        }
        let to = q.next_deadline.unwrap_or(exec.now() + MS);
        let _ = exec.jump_to(to);
    }
}

type Trace = Vec<(usize, Duration, String, u64, Vec<u8>)>;

fn traced_run(seed: u64) -> Trace {
    let sim = dsim(seed);
    let trace = Arc::new(Mutex::new(Trace::new()));
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                let socks: Vec<UdpSocket> = (0..3)
                    .map(|i| UdpSocket::bind(("127.0.0.1", 47500 + i)).unwrap())
                    .collect();
                let workers: Vec<_> = socks
                    .into_iter()
                    .enumerate()
                    .map(|(id, sock)| {
                        let trace = trace.clone();
                        thread::spawn(move || {
                            sock.set_read_timeout(Some(2 * MS)).unwrap();
                            let hasher = RandomState::new();
                            let mut buf = [0u8; 8];
                            for round in 0..4u64 {
                                thread::sleep((id as u32 + round as u32 % 3 + 1) * MS);
                                let next = 47500 + ((id + 1) % 3) as u16;
                                sock.send_to(&[id as u8, round as u8], ("127.0.0.1", next))
                                    .unwrap();
                                let got = sock
                                    .recv_from(&mut buf)
                                    .map(|(n, _)| buf[..n].to_vec())
                                    .unwrap_or_default();
                                trace.lock().unwrap().push((
                                    id,
                                    sched::now(),
                                    format!("{:?}", Instant::now()),
                                    hasher.hash_one(round),
                                    got,
                                ));
                            }
                        })
                    })
                    .collect();
                for worker in workers {
                    worker.join().unwrap();
                }
            })
        });
        drive(&exec, || run.is_finished());
        run.join().unwrap();
    });
    Arc::try_unwrap(trace).unwrap().into_inner().unwrap()
}

#[test]
fn a_deterministic_run_with_an_executive_replays() {
    let first = traced_run(7);
    assert_eq!(first.len(), 12);
    assert_eq!(
        traced_run(7),
        first,
        "the same seed replays the same run, absolute instants too"
    );
    assert!(first.iter().any(|(_, at, ..)| *at > Duration::ZERO));
}

#[cfg(unix)]
#[test]
fn a_jump_releases_sleep_and_receive_deadlines_as_one_group() {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Wake, Waker};

    struct ObserveWake {
        returned: Arc<AtomicBool>,
        early: Arc<AtomicBool>,
    }

    impl Wake for ObserveWake {
        fn wake(self: Arc<Self>) {
            real_sleep(50 * MS);
            self.early
                .store(self.returned.load(Ordering::Acquire), Ordering::Release);
        }
    }

    let sim = dsim(7);
    let returned = Arc::new(AtomicBool::new(false));
    let early = Arc::new(AtomicBool::new(false));
    thread::scope(|scope| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = scope.spawn(|| {
            sim.run(|| {
                let waker = Waker::from(Arc::new(ObserveWake {
                    returned: returned.clone(),
                    early: early.clone(),
                }));
                let mut wake = sched::sleep_until(Instant::now() + 2 * MS);
                assert!(
                    Pin::new(&mut wake)
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
                let receiver_returned = returned.clone();
                let receiver = thread::spawn(move || {
                    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
                    sock.set_read_timeout(Some(2 * MS)).unwrap();
                    assert!(sock.recv_from(&mut [0; 1]).is_err());
                    receiver_returned.store(true, Ordering::Release);
                });
                let sleeper = thread::spawn(|| thread::sleep(2 * MS));
                receiver.join().unwrap();
                sleeper.join().unwrap();
                drop(wake);
            });
        });
        settle(&exec);
        exec.jump_to(2 * MS).unwrap();
        run.join().unwrap();
    });
    assert!(returned.load(Ordering::Acquire));
    assert!(!early.load(Ordering::Acquire));
}

fn timestamp_wake_order(reverse: bool) -> Vec<(usize, Duration)> {
    let t = 6 * MS;
    let sim = dsim(1);
    sim.run(|| {
        let exec = sched::attach(ExecutiveConfig::default()).unwrap();
        let woke = Arc::new(Mutex::new(Vec::new()));
        let readers: Vec<_> = (0..3)
            .map(|i| {
                let rx = UdpSocket::bind(("127.0.0.1", 47520 + i)).unwrap();
                let woke = woke.clone();
                thread::spawn(move || {
                    let mut buf = [0u8; 4];
                    rx.recv_from(&mut buf).unwrap();
                    woke.lock().unwrap().push((i as usize, sched::now()));
                })
            })
            .collect();
        sched::mark_driver_thread();
        settle(&exec);
        exec.enter_timestamp_checked(t).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut order: Vec<u16> = (0..3).collect();
        if reverse {
            order.reverse();
        }
        for i in order {
            tx.send_to(b"go", ("127.0.0.1", 47520 + i)).unwrap();
        }
        real_sleep(50 * MS);
        assert!(
            woke.lock().unwrap().is_empty(),
            "the executive holds the baton through the timestamp"
        );
        exec.leave_timestamp(t);
        for reader in readers {
            reader.join().unwrap();
        }
        Arc::try_unwrap(woke).unwrap().into_inner().unwrap()
    })
}

#[test]
fn checked_entry_takes_the_baton_and_leave_dispatches_in_lineage_order() {
    let forward = timestamp_wake_order(false);
    assert_eq!(forward.len(), 3);
    assert!(forward.iter().all(|(_, at)| *at == 6 * MS), "{forward:?}");
    assert_eq!(
        timestamp_wake_order(true),
        forward,
        "the readers run in the schedule's order, not the order the data arrived in"
    );
}

#[test]
fn the_scheduler_idles_instead_of_deadlocking_while_owned() {
    let sim = dsim(3);
    let returned = AtomicBool::new(false);
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
                let mut buf = [0u8; 4];
                let r = sock.recv_from(&mut buf);
                returned.store(true, Ordering::SeqCst);
                r.map(|(n, _)| n)
            })
        });
        settle(&exec);
        real_sleep(500 * MS);
        assert!(
            !returned.load(Ordering::SeqCst),
            "no deadlock give-up while owned"
        );
        let q = exec.quiescence();
        assert!(q.quiescent);
        assert_eq!((q.runnable, q.blocked), (0, 1));
        drop(exec);
        let err = run.join().unwrap().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    });
}

#[test]
fn a_rate_above_zero_is_treated_as_zero_under_deterministic() {
    let sim = dsim(4);
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                thread::sleep(10 * MS);
                sched::now()
            })
        });
        while exec.next_deadline() != Some(10 * MS) {
            real_sleep(Duration::from_micros(200));
        }
        settle(&exec);
        exec.grant(Grant {
            anchor_v: Duration::ZERO,
            anchor_wall: real_now(),
            rate: 1.0,
            horizon: Duration::from_secs(1),
        });
        real_sleep(100 * MS);
        assert_eq!(exec.now(), Duration::ZERO, "the grant does not flow");
        assert!(!run.is_finished());
        settle(&exec);
        assert_eq!(exec.jump_to(Duration::from_secs(1)), Ok(1));
        assert_eq!(run.join().unwrap(), 10 * MS);
    });
}
