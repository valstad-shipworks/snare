//! An executive's timestamps and quiescence checks against the sim's reactions: whatever an
//! executive does at a timestamp, and any wake from outside, keeps the sim from being quiescent
//! until the participant it woke has run, and a timestamp at which nothing happened leaves a
//! quiescent sim quiescent.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use snare::Sim;
use snare::sched::{self, Executive, ExecutiveConfig, Grant, Quiescence};

const MS: Duration = Duration::from_millis(1);

/// Runs these tests one at a time: each checks that nothing wakes its sim's waiters, which another
/// sim's activity in the same process may.
fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn real_now() -> Instant {
    snare::real(Instant::now)
}

fn real_since(start: Instant) -> Duration {
    snare::real(|| start.elapsed())
}

/// Busy-waits `d` of real time, as a participant doing work the sim cannot see.
fn real_work(d: Duration) {
    let end = real_now() + d;
    while real_now() < end {
        std::hint::spin_loop();
    }
}

fn sims() -> [(&'static str, Sim); 2] {
    [
        ("plain", Sim::new()),
        (
            "deterministic",
            Sim::builder().deterministic().seed(7).build(),
        ),
    ]
}

fn attach_frozen() -> Executive {
    sched::mark_driver_thread();
    let exec = sched::attach(ExecutiveConfig::default()).unwrap();
    exec.grant(Grant {
        anchor_v: Duration::ZERO,
        anchor_wall: real_now(),
        rate: 0.0,
        horizon: Duration::ZERO,
    });
    exec
}

/// Waits until the sim is quiescent with a participant blocked.
fn settle(exec: &Executive) -> Quiescence {
    settle_n(exec, 1)
}

/// Waits until the sim is quiescent with at least `n` participants blocked.
fn settle_n(exec: &Executive, n: u32) -> Quiescence {
    let start = real_now();
    loop {
        let q = exec.quiescence();
        if q.quiescent && q.blocked >= n {
            return q;
        }
        assert!(
            real_since(start) < Duration::from_secs(20),
            "the sim never went quiescent: {q:?}"
        );
        thread::yield_now();
    }
}

/// Enters the timestamp at `t` as soon as a checked entry succeeds, jumping to timers before it.
fn enter_checked(exec: &Executive, t: Duration) {
    let start = real_now();
    loop {
        let q = exec.quiescence();
        if q.quiescent {
            if exec.enter_timestamp_checked(t).is_ok() {
                return;
            }
        } else if let Some(d) = q.next_deadline.filter(|d| *d < t) {
            let _ = exec.jump_to(d);
        }
        assert!(
            real_since(start) < Duration::from_secs(20),
            "never entered {t:?}: {q:?}"
        );
        thread::yield_now();
    }
}

/// A participant echoes every datagram after some real work; the executive sends one at each
/// 8 ms timestamp and expects the echo back by the next.
fn echo_by_the_next_timestamp(sim: &Sim) -> u64 {
    sim.run(|| {
        let exec = attach_frozen();
        let lp = UdpSocket::bind("127.0.0.1:0").unwrap();
        lp.set_nonblocking(true).unwrap();
        let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (echo_addr, lp_addr) = (echo.local_addr().unwrap(), lp.local_addr().unwrap());
        thread::Builder::new()
            .name("echo".into())
            .spawn(move || {
                let mut buf = [0u8; 8];
                while let Ok((n, _)) = echo.recv_from(&mut buf) {
                    real_work(Duration::from_micros(500));
                    let _ = echo.send_to(&buf[..n], lp_addr);
                    if n == 8 && u64::from_le_bytes(buf) == 0 {
                        return;
                    }
                }
            })
            .unwrap();
        let (mut misses, mut answered) = (0u64, 0u64);
        for cycle in 1..=600u64 {
            let t = 8 * MS * u32::try_from(cycle).unwrap();
            enter_checked(&exec, t);
            let mut buf = [0u8; 8];
            while let Ok((8, _)) = lp.recv_from(&mut buf) {
                answered = answered.max(u64::from_le_bytes(buf));
            }
            if answered < cycle - 1 {
                misses += 1;
            }
            let payload = if cycle == 600 { 0 } else { cycle };
            lp.send_to(&payload.to_le_bytes(), echo_addr).unwrap();
            exec.leave_timestamp(t);
        }
        misses
    })
}

#[test]
fn a_datagram_sent_at_a_timestamp_is_answered_before_the_next_checked_entry() {
    let _serial = serial();
    for (kind, sim) in sims() {
        assert_eq!(
            echo_by_the_next_timestamp(&sim),
            0,
            "{kind}: an echo came back after the next timestamp was entered"
        );
    }
}

#[test]
fn leaving_a_timestamp_where_nothing_happened_leaves_the_sim_quiescent() {
    let _serial = serial();
    for (kind, sim) in sims() {
        sim.run(|| {
            let exec = attach_frozen();
            let stop = UdpSocket::bind("127.0.0.1:0").unwrap();
            let stop_addr = stop.local_addr().unwrap();
            let idle = thread::Builder::new()
                .name("idle".into())
                .spawn(move || {
                    let _ = stop.recv_from(&mut [0u8; 4]);
                })
                .unwrap();
            let sleeper = thread::Builder::new()
                .name("sleeper".into())
                .spawn(|| thread::sleep(Duration::from_secs(3600)))
                .unwrap();
            settle_n(&exec, 2);
            let mut busy = Vec::new();
            for i in 1..=100u32 {
                let t = 8 * MS * i;
                exec.enter_timestamp_checked(t)
                    .unwrap_or_else(|_| panic!("{kind}: not quiescent before {t:?}"));
                exec.leave_timestamp(t);
                let q = exec.quiescence();
                if !q.quiescent {
                    busy.push(q);
                }
                settle_n(&exec, 2);
            }
            assert!(
                busy.is_empty(),
                "{kind}: not quiescent right after {} of 100 timestamps, first {:?}",
                busy.len(),
                busy.first()
            );
            enter_checked(&exec, Duration::from_secs(1));
            UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .send_to(b"stop", stop_addr)
                .unwrap();
            exec.leave_timestamp(Duration::from_secs(1));
            idle.join().unwrap();
            enter_checked(&exec, Duration::from_secs(3600));
            exec.leave_timestamp(Duration::from_secs(3600));
            sleeper.join().unwrap();
        });
    }
}

#[test]
fn leaving_a_timestamp_still_releases_a_timer_due_at_it() {
    let _serial = serial();
    for (kind, sim) in sims() {
        sim.run(|| {
            let exec = attach_frozen();
            let woke = Arc::new(AtomicBool::new(false));
            let sleeper = {
                let woke = woke.clone();
                thread::spawn(move || {
                    thread::sleep(5 * MS);
                    woke.store(true, Ordering::SeqCst);
                })
            };
            settle(&exec);
            exec.enter_timestamp_checked(5 * MS).unwrap();
            assert_eq!(exec.leave_timestamp(5 * MS), 1, "{kind}");
            sleeper.join().unwrap();
            assert!(woke.load(Ordering::SeqCst), "{kind}");
        });
    }
}

#[test]
fn a_foreign_timer_kick_releases_its_udp_reaction_without_waking_a_neighbour() {
    let _serial = serial();
    for deterministic in [false, true] {
        let build = || {
            let builder = Sim::builder().seed(7);
            if deterministic {
                builder.deterministic().build()
            } else {
                builder.build()
            }
        };
        let a = build();
        let b = build();
        thread::scope(|scope| {
            let a_exec = a.executive(ExecutiveConfig::default()).unwrap();
            let b_exec = b.executive(ExecutiveConfig::default()).unwrap();
            let a_run = scope.spawn(|| {
                a.run(|| {
                    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
                    receiver.set_read_timeout(Some(20 * MS)).unwrap();
                    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
                    let destination = receiver.local_addr().unwrap();
                    let send = thread::spawn(move || {
                        thread::sleep(5 * MS);
                        sender.send_to(b"due", destination).unwrap();
                        sched::now()
                    });
                    let mut bytes = [0u8; 3];
                    let received = receiver.recv_from(&mut bytes).unwrap();
                    let at = sched::now();
                    let sent_at = send.join().unwrap();
                    (
                        received.0,
                        bytes,
                        sent_at,
                        at,
                        snare_interpose::Domain::current().unwrap().outside_wakes(),
                    )
                })
            });
            let b_run = scope.spawn(|| {
                b.run(|| {
                    thread::sleep(11 * MS);
                    sched::now()
                })
            });

            let before = settle_n(&b_exec, 1);
            assert_eq!(before.next_deadline, Some(11 * MS));
            let ready = settle_n(&a_exec, 2);
            assert_eq!(ready.next_deadline, Some(5 * MS));
            assert!(a_exec.jump_to(5 * MS).is_ok());
            assert_eq!(
                a_run.join().unwrap(),
                (3, *b"due", 5 * MS, 5 * MS, 0),
                "deterministic={deterministic}"
            );
            let after = b_exec.quiescence();
            assert_eq!(
                (
                    after.quiescent,
                    after.epoch,
                    after.blocked,
                    after.next_deadline
                ),
                (true, before.epoch, 1, Some(11 * MS)),
                "deterministic={deterministic}"
            );
            assert_eq!(b_exec.now(), Duration::ZERO);
            assert!(b_exec.jump_to(11 * MS).is_ok());
            assert_eq!(b_run.join().unwrap(), 11 * MS);
        });
    }
}

/// A participant parks; the executive unparks it and at once tries a checked entry, which must
/// not succeed before the participant has done its work. Before each unpark the driver bumps the
/// sim with a datagram nobody waits for, so the participant re-checks its park and parks again
/// just as the unpark comes.
fn unpark_then_enter(sim: &Sim, rounds: u64) -> (u64, u64) {
    sim.run(|| {
        let exec = attach_frozen();
        let reacted = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = {
            let (reacted, stop) = (reacted.clone(), stop.clone());
            thread::Builder::new()
                .name("parker".into())
                .spawn(move || {
                    tx.send(sched::current_unparker()).unwrap();
                    while !stop.load(Ordering::SeqCst) {
                        sched::park(None);
                        real_work(Duration::from_micros(50));
                        reacted.fetch_add(1, Ordering::SeqCst);
                    }
                })
                .unwrap()
        };
        let unparker = rx.recv().unwrap();
        let noise = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sink_addr = sink.local_addr().unwrap();
        let (mut missed, mut entered) = (0, 0);
        for i in 1..=2 * rounds {
            settle(&exec);
            let inject = i % 2 == 0;
            if inject {
                noise.send_to(b"x", sink_addr).unwrap();
                settle(&exec);
            }
            let before = reacted.load(Ordering::SeqCst);
            if inject {
                unparker.unpark();
            }
            let t = MS * u32::try_from(i).unwrap();
            if exec.enter_timestamp_checked(t).is_ok() {
                if inject {
                    entered += 1;
                    if reacted.load(Ordering::SeqCst) == before {
                        missed += 1;
                    }
                }
                exec.leave_timestamp(t);
            }
        }
        stop.store(true, Ordering::SeqCst);
        unparker.unpark();
        worker.join().unwrap();
        (missed, entered)
    })
}

#[test]
fn an_unpark_keeps_the_sim_busy_until_the_woken_participant_runs() {
    let _serial = serial();
    for (kind, sim) in sims() {
        let (missed, entered) = unpark_then_enter(&sim, 300);
        assert_eq!(
            missed, 0,
            "{kind}: {missed} of {entered} checked entries after an unpark came before the \
             participant ran"
        );
    }
}
