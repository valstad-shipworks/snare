//! Sims running on parallel threads of one process stay isolated: one sim's sleepers, woken
//! waiters and left-over threads never hold another sim's quiescence up, so an executive's jumps
//! and plain time skips go through however many sims run beside it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use snare::Sim;
use snare::sched::{self, ExecutiveConfig, Grant};

/// Real time, also inside a sim.
fn real_now() -> Instant {
    snare::real(Instant::now)
}

/// Runs `f` on its own thread and fails the test if it takes longer than `limit`: a stalled sim
/// would otherwise hang the test.
fn within<R: Send + 'static>(
    limit: Duration,
    what: &str,
    f: impl FnOnce() -> R + Send + 'static,
) -> R {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(limit) {
        Ok(r) => r,
        Err(_) => panic!("{what} did not finish within {limit:?}"),
    }
}

/// A sim whose driver attaches an executive while a participant it spawned sleeps past the end
/// of the run, and one beside it that reads its own quiescence after a lease comes and goes: the
/// first sim's sleeper must never show up in the second's.
#[test]
fn a_neighbours_sleepers_never_leave_a_sim_settling() {
    within(Duration::from_secs(120), "200 sim pairs", || {
        let mut unsettled = Vec::new();
        for _ in 0..200 {
            let a = std::thread::spawn(|| {
                Sim::new().run(|| {
                    sched::mark_driver_thread();
                    let _exec = sched::attach(ExecutiveConfig::default()).unwrap();
                    let (tx, rx) = mpsc::channel();
                    std::thread::spawn(move || {
                        tx.send(()).unwrap();
                        std::thread::sleep(Duration::from_millis(20));
                    });
                    rx.recv().unwrap();
                    std::thread::sleep(Duration::from_millis(5));
                })
            });
            let b = std::thread::spawn(|| {
                Sim::new().run(|| {
                    sched::mark_driver_thread();
                    let exec = sched::attach(ExecutiveConfig::default()).unwrap();
                    drop(sched::busy("blip"));
                    std::thread::sleep(Duration::from_millis(5));
                    exec.quiescence()
                })
            });
            a.join().unwrap();
            let q = b.join().unwrap();
            if !q.quiescent {
                unsettled.push(q);
            }
        }
        assert!(
            unsettled.is_empty(),
            "{} unsettled: {:?}",
            unsettled.len(),
            unsettled.first()
        );
    });
}

/// One sim driven by an executive through `until` in jumps, with three participants sleeping on
/// grids of their own; each jump is retried for up to five seconds of real time while the sim is
/// not yet quiescent. Returns the participants' laps.
fn driven_grids(until: Duration) -> u64 {
    Sim::new().run(|| {
        sched::mark_driver_thread();
        let exec = sched::attach(ExecutiveConfig::default()).unwrap();
        exec.grant(Grant {
            anchor_v: exec.now(),
            anchor_wall: real_now(),
            rate: 0.0,
            horizon: exec.now(),
        });
        let laps = Arc::new(AtomicU64::new(0));
        let start = exec.now();
        let workers: Vec<_> = [3u64, 5, 7]
            .into_iter()
            .map(|ms| {
                let laps = laps.clone();
                std::thread::spawn(move || {
                    let period = Duration::from_millis(ms);
                    for _ in 0..until.as_millis() as u64 / ms {
                        std::thread::sleep(period);
                        laps.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        let end = start + until + Duration::from_millis(1);
        let mut stalled_since = None;
        while exec.now() < end {
            match exec.jump_to(end) {
                Ok(_) => stalled_since = None,
                Err(_) => {
                    let since = *stalled_since.get_or_insert_with(real_now);
                    assert!(
                        real_now() - since < Duration::from_secs(5),
                        "stalled at {:?}: {:?}",
                        exec.now(),
                        exec.quiescence()
                    );
                    std::thread::yield_now();
                }
            }
        }
        for worker in workers {
            worker.join().unwrap();
        }
        laps.load(Ordering::Relaxed)
    })
}

/// A sim on the plain discrete clock whose root and three participants sleep through `until`:
/// time skips alone carry it there. Returns the participants' laps.
fn skipped_grids(until: Duration) -> u64 {
    Sim::new().run(|| {
        let laps = Arc::new(AtomicU64::new(0));
        let workers: Vec<_> = [2u64, 3, 11]
            .into_iter()
            .map(|ms| {
                let laps = laps.clone();
                std::thread::spawn(move || {
                    let period = Duration::from_millis(ms);
                    for _ in 0..until.as_millis() as u64 / ms {
                        std::thread::sleep(period);
                        laps.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        std::thread::sleep(until);
        for worker in workers {
            worker.join().unwrap();
        }
        laps.load(Ordering::Relaxed)
    })
}

/// Expected laps of grids of `periods` ms through `until`.
fn laps(periods: &[u64], until: Duration) -> u64 {
    let ms = until.as_millis() as u64;
    periods.iter().map(|p| ms / p).sum()
}

#[test]
fn parallel_sims_with_sleepers_and_executives_never_stall() {
    within(Duration::from_secs(300), "240 parallel sims", || {
        let until = Duration::from_millis(60);
        let threads: Vec<_> = (0..6)
            .map(|lane| {
                std::thread::spawn(move || {
                    for round in 0..40 {
                        if (lane + round) % 2 == 0 {
                            assert_eq!(driven_grids(until), laps(&[3, 5, 7], until));
                        } else {
                            assert_eq!(skipped_grids(until), laps(&[2, 3, 11], until));
                        }
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    });
}

/// A running sim — one thread parked inside `Sim::run` for the whole drive, a participant sleeping
/// on a `period` grid — driven by an executive from outside through `steps` grid points: before
/// each jump it waits for the sim to read quiescent, so the jump can only be refused if something
/// wakes one of the sim's waiters in between. Alone nothing does. Returns how many jumps were
/// refused, with the quiescence read after the first refusal.
fn refused_jumps(period: Duration, steps: u32) -> (u32, Option<String>) {
    let sim = Arc::new(Sim::new());
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let resident = {
        let (sim, stop) = (sim.clone(), stop.clone());
        std::thread::spawn(move || {
            sim.run(|| {
                tx.send(sched::current_unparker()).unwrap();
                while !stop.load(Ordering::Acquire) {
                    sched::park(None);
                }
            })
        })
    };
    let unparker = rx.recv().unwrap();
    let exec = sim.executive(ExecutiveConfig::default()).unwrap();
    {
        let stop = stop.clone();
        sim.run(|| {
            std::thread::spawn(move || {
                let mut next = Instant::now();
                while !stop.load(Ordering::Acquire) {
                    next += period;
                    std::thread::sleep(next.saturating_duration_since(Instant::now()));
                }
            })
        });
    }
    let (mut refused, mut seen) = (0, None);
    for step in 1..=steps {
        let t = period * step;
        loop {
            while !exec.quiescence().quiescent {
                std::thread::yield_now();
            }
            match exec.jump_to(t) {
                Ok(_) => break,
                Err(_) => {
                    refused += 1;
                    seen.get_or_insert_with(|| format!("{:?}", exec.quiescence()));
                }
            }
        }
    }
    stop.store(true, Ordering::Release);
    unparker.unpark();
    drop(exec);
    resident.join().unwrap();
    (refused, seen)
}

/// Drives `periods.len()` running sims side by side, one executive each, and returns each one's
/// [`refused_jumps`].
fn side_by_side(periods: &[u64], steps: u32) -> Vec<(u32, Option<String>)> {
    let drives: Vec<_> = periods
        .iter()
        .map(|&ms| std::thread::spawn(move || refused_jumps(Duration::from_millis(ms), steps)))
        .collect();
    drives.into_iter().map(|d| d.join().unwrap()).collect()
}

/// A sim's waiters are woken only by changes to that sim: the bumps of the sims beside it — their
/// executives' jumps, their sleepers' wakes — never mark its waiters woken, so a jump made right
/// after it read quiescent goes through. One sim alone sets the baseline of no refused jump; two
/// and four together must each match it.
#[test]
fn side_by_side_executives_never_refuse_a_jump_for_a_neighbours_wake() {
    within(Duration::from_secs(240), "side-by-side executives", || {
        for periods in [&[1u64][..], &[1, 3], &[1, 2, 3, 5]] {
            for _ in 0..3 {
                let refusals = side_by_side(periods, 300);
                assert!(
                    refusals.iter().all(|(refused, _)| *refused == 0),
                    "{} sims side by side refused jumps: {refusals:?}",
                    periods.len()
                );
            }
        }
    });
}

/// A sim whose two participants bounce a datagram between their sockets until `stop` is set.
fn udp_ping_pong(stop: Arc<AtomicBool>) {
    Sim::new().run(|| {
        let a = UdpSocket::bind("127.0.0.1:7000").unwrap();
        let b = UdpSocket::bind("127.0.0.1:7001").unwrap();
        let echo = std::thread::spawn(move || {
            let mut buf = [0u8; 16];
            loop {
                let (n, from) = b.recv_from(&mut buf).unwrap();
                b.send_to(&buf[..n], from).unwrap();
                if buf[0] == 1 {
                    return;
                }
            }
        });
        let mut buf = [0u8; 16];
        loop {
            let last = stop.load(Ordering::Acquire);
            a.send_to(&[u8::from(last)], "127.0.0.1:7001").unwrap();
            a.recv_from(&mut buf).unwrap();
            if last {
                break;
            }
        }
        echo.join().unwrap();
    });
}

/// A sim whose participant streams bytes over a TCP connection to another, which reads them,
/// until `stop` is set.
fn tcp_stream(stop: Arc<AtomicBool>) {
    Sim::new().run(|| {
        let listener = TcpListener::bind("127.0.0.1:7100").unwrap();
        let reader = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            while conn.read(&mut buf).unwrap() > 0 {}
        });
        let mut conn = TcpStream::connect("127.0.0.1:7100").unwrap();
        while !stop.load(Ordering::Acquire) {
            conn.write_all(&[7u8; 1024]).unwrap();
        }
        drop(conn);
        reader.join().unwrap();
    });
}

/// A sim on the plain discrete clock whose participants sleep on short grids until `stop` is set,
/// moved on by time skips alone.
fn skipping_sleepers(stop: Arc<AtomicBool>) {
    Sim::new().run(|| {
        let sleepers: Vec<_> = [1u64, 2]
            .into_iter()
            .map(|ms| {
                let stop = stop.clone();
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(ms));
                    }
                })
            })
            .collect();
        for sleeper in sleepers {
            sleeper.join().unwrap();
        }
    });
}

/// The wakes of busy neighbours — datagrams landing, stream bytes arriving, time skips — reach
/// only their own sims' waiters, so an executive driving a sim beside them is never refused a
/// jump it made right after reading quiescent.
#[test]
fn busy_neighbours_never_refuse_a_driven_sims_jump() {
    within(
        Duration::from_secs(240),
        "a sim driven beside busy neighbours",
        || {
            for _ in 0..3 {
                let stop = Arc::new(AtomicBool::new(false));
                let neighbours: Vec<_> = [udp_ping_pong, tcp_stream, skipping_sleepers]
                    .into_iter()
                    .map(|neighbour| {
                        let stop = stop.clone();
                        std::thread::spawn(move || neighbour(stop))
                    })
                    .collect();
                let refusals = side_by_side(&[1, 2], 300);
                stop.store(true, Ordering::Release);
                for neighbour in neighbours {
                    neighbour.join().unwrap();
                }
                assert!(
                    refusals.iter().all(|(refused, _)| *refused == 0),
                    "driven beside busy neighbours, jumps were refused: {refusals:?}"
                );
            }
        },
    );
}
