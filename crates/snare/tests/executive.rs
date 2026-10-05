//! The in-process executive (`snare::sched::Executive`): an outside simulation that owns a sim's
//! clock, jumps it between timers once the sim is quiescent and acts inside it at timestamps of
//! its own.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use snare::Sim;
use snare::sched::{
    self, AttachError, BlockerKind, Executive, ExecutiveConfig, Grant, NotQuiescent, PState,
    Quiescence, ThreadClass,
};

const MS: Duration = Duration::from_millis(1);

fn real_now() -> Instant {
    snare::real(Instant::now)
}

fn real_since(start: Instant) -> Duration {
    snare::real(|| start.elapsed())
}

fn real_sleep(d: Duration) {
    snare::real(|| thread::sleep(d));
}

/// The sim's fixed realtime epoch (2023-11-14T22:13:20Z), where sim time zero reads.
fn epoch() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

/// Waits until the sim is quiescent with a participant blocked: before the run starts there is
/// none, which is quiescent too.
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

/// Waits until the sim is quiescent with `next` its next deadline: a participant blocked for a
/// moment on its way to its timed wait leaves the sim briefly quiescent before that.
fn settle_at(exec: &Executive, next: Duration) -> Quiescence {
    loop {
        let q = settle(exec);
        if q.next_deadline == Some(next) {
            return q;
        }
        real_sleep(Duration::from_micros(200));
    }
}

/// Waits until a participant is blocked in `wait` and the sim is quiescent.
fn settle_in(exec: &Executive, wait: &str) {
    loop {
        settle(exec);
        if exec.participants().iter().any(|p| p.wait == Some(wait)) {
            return;
        }
        real_sleep(Duration::from_micros(200));
    }
}

fn jump(exec: &Executive, t: Duration) -> u32 {
    loop {
        settle(exec);
        if let Ok(fired) = exec.jump_to(t) {
            return fired;
        }
    }
}

fn enter_checked(exec: &Executive, t: Duration) {
    loop {
        settle(exec);
        if exec.enter_timestamp_checked(t).is_ok() {
            return;
        }
    }
}

fn frozen_grant(exec: &Executive, horizon: Duration) {
    exec.grant(Grant {
        anchor_v: exec.now(),
        anchor_wall: real_now(),
        rate: 0.0,
        horizon,
    });
}

/// Sets a flag when dropped, so a participant spinning on it is let go even when an assertion
/// fails first.
struct SetOnDrop<'a>(&'a AtomicBool);

impl Drop for SetOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn would_block(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    let code = libc::EAGAIN;
    #[cfg(windows)]
    let code = 10035;
    e.raw_os_error() == Some(code)
}

#[test]
fn attach_freezes_the_clock_until_the_first_grant() {
    let sim = Sim::new();
    let woke = AtomicBool::new(false);
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                let start = Instant::now();
                thread::sleep(10 * MS);
                woke.store(true, Ordering::SeqCst);
                start.elapsed()
            })
        });
        let q = settle_at(&exec, 10 * MS);
        assert_eq!((q.runnable, q.blocked), (0, 1));
        real_sleep(200 * MS);
        assert_eq!(exec.now(), Duration::ZERO, "nothing moved the clock");
        assert_eq!(sim.time_value(), Duration::ZERO);
        assert!(!woke.load(Ordering::SeqCst), "no time skip while owned");
        exec.grant(Grant {
            anchor_v: Duration::ZERO,
            anchor_wall: real_now(),
            rate: 1.0,
            horizon: Duration::from_secs(10),
        });
        assert!(run.join().unwrap() >= 10 * MS);
    });
}

#[test]
fn attach_errors() {
    fn send<T: Send>() {}
    send::<Executive>();
    let sim = Sim::new();
    let exec = sim.executive(ExecutiveConfig::default()).unwrap();
    assert_eq!(
        sim.executive(ExecutiveConfig::default()).unwrap_err(),
        AttachError::AlreadyAttached
    );
    assert_eq!(
        sim.run(|| sched::attach(ExecutiveConfig::default()).unwrap_err()),
        AttachError::AlreadyAttached
    );
    drop(exec);
    assert!(
        sim.run(|| sched::attach(ExecutiveConfig::default()))
            .is_ok()
    );
    assert_eq!(
        sched::attach(ExecutiveConfig::default()).unwrap_err(),
        AttachError::NotInSim
    );
    #[cfg(unix)]
    assert_eq!(
        Sim::builder()
            .wall_clock()
            .build()
            .executive(ExecutiveConfig::default())
            .unwrap_err(),
        AttachError::WallClock
    );
    assert!(!AttachError::NotInSim.to_string().is_empty());
}

#[test]
fn jump_lands_on_the_earliest_timer_group() {
    let sim = Sim::new();
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                let sleepers: Vec<_> = [5, 5, 9]
                    .into_iter()
                    .map(|ms| {
                        thread::spawn(move || {
                            let start = Instant::now();
                            thread::sleep(ms * MS);
                            (start.elapsed(), sched::now())
                        })
                    })
                    .collect();
                let woke = sleepers
                    .into_iter()
                    .map(|h| h.join().unwrap())
                    .collect::<Vec<_>>();
                thread::sleep((109 * MS).saturating_sub(sched::now()));
                woke
            })
        });
        settle_at(&exec, 5 * MS);
        while exec.timers(8).len() < 3 {
            real_sleep(Duration::from_micros(200));
        }
        assert_eq!(jump(&exec, 20 * MS), 2);
        assert_eq!(exec.now(), 5 * MS);
        assert_eq!(jump(&exec, 20 * MS), 1);
        assert_eq!(exec.now(), 9 * MS);
        assert_eq!(jump(&exec, 20 * MS), 0);
        assert_eq!(exec.now(), 20 * MS);
        settle_at(&exec, 109 * MS);
        assert_eq!(jump(&exec, Duration::from_secs(1)), 1);
        assert_eq!(exec.now(), 109 * MS);
        let woke = run.join().unwrap();
        assert_eq!(
            woke,
            vec![(5 * MS, 5 * MS), (5 * MS, 5 * MS), (9 * MS, 9 * MS)],
            "each sleeper wakes exactly on its deadline"
        );
    });
}

#[test]
fn jump_refused_while_a_participant_runs() {
    let sim = Sim::new();
    let stop = AtomicBool::new(false);
    let spinning = AtomicBool::new(false);
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                thread::scope(|inner| {
                    let spinner = thread::Builder::new()
                        .name("spinner".into())
                        .spawn_scoped(inner, || {
                            spinning.store(true, Ordering::SeqCst);
                            while !stop.load(Ordering::SeqCst) {
                                std::hint::spin_loop();
                            }
                        })
                        .unwrap();
                    spinner.join().unwrap();
                });
            })
        });
        let _stop = SetOnDrop(&stop);
        while !spinning.load(Ordering::SeqCst) {
            real_sleep(MS);
        }
        let started = real_now();
        loop {
            let participants = exec.participants();
            if participants.iter().any(|participant| {
                participant.state == PState::Blocked && participant.wait == Some("join")
            }) && participants
                .iter()
                .filter(|participant| participant.state == PState::Running)
                .count()
                == 1
            {
                break;
            }
            assert!(
                real_since(started) < Duration::from_secs(20),
                "the enclosing participant never joined the spinner: {participants:?}"
            );
            real_sleep(Duration::from_micros(200));
        }
        let before = exec.now();
        assert_eq!(exec.jump_to(Duration::from_secs(1)), Err(NotQuiescent));
        assert_eq!(exec.now(), before, "a refused jump changes nothing");
        let q = exec.quiescence();
        assert!(!q.quiescent);
        let (kind, name) = q.blocker.unwrap();
        assert_eq!(kind, BlockerKind::Runnable);
        assert_eq!(&*name, "spinner");
        stop.store(true, Ordering::SeqCst);
        run.join().unwrap();
    });
}

#[test]
fn jump_refused_when_a_wake_lands_after_the_quiescence_read() {
    let sim = Sim::new();
    let (go, wait_go) = mpsc::channel::<()>();
    let (sent, wait_sent) = mpsc::channel::<()>();
    let release = AtomicBool::new(false);
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                let rx = UdpSocket::bind("127.0.0.1:47310").unwrap();
                let sender = thread::spawn(move || {
                    sched::mark_background("sender");
                    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
                    wait_go.recv().unwrap();
                    tx.send_to(b"x", "127.0.0.1:47310").unwrap();
                    sent.send(()).unwrap();
                });
                let mut buf = [0u8; 4];
                rx.recv_from(&mut buf).unwrap();
                while !release.load(Ordering::SeqCst) {
                    std::hint::spin_loop();
                }
                sender.join().unwrap();
            })
        });
        let _release = SetOnDrop(&release);
        settle_in(&exec, "udp recv");
        go.send(()).unwrap();
        wait_sent.recv().unwrap();
        assert_eq!(exec.jump_to(Duration::from_secs(1)), Err(NotQuiescent));
        assert_eq!(exec.now(), Duration::ZERO);
        let after = exec.quiescence();
        assert!(!after.quiescent);
        assert!(matches!(
            after.blocker,
            Some((BlockerKind::Runnable | BlockerKind::Settling, _))
        ));
        release.store(true, Ordering::SeqCst);
        run.join().unwrap();
    });
}

#[test]
fn the_horizon_holds_sleepers_until_the_next_grant() {
    let sim = Sim::new();
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                let start = Instant::now();
                thread::sleep(50 * MS);
                start.elapsed()
            })
        });
        settle_at(&exec, 50 * MS);
        exec.grant(Grant {
            anchor_v: Duration::ZERO,
            anchor_wall: real_now(),
            rate: 1000.0,
            horizon: 20 * MS,
        });
        real_sleep(100 * MS);
        assert_eq!(exec.now(), 20 * MS, "the clock stops at the horizon");
        let rows = exec.participants();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, PState::Blocked);
        assert_eq!(rows[0].deadline, Some(50 * MS));
        exec.grant(Grant {
            anchor_v: exec.now(),
            anchor_wall: real_now(),
            rate: 1000.0,
            horizon: Duration::from_secs(1),
        });
        assert!(run.join().unwrap() >= 50 * MS);
    });
}

#[test]
fn charged_latency_never_crosses_the_horizon() {
    let sim = Sim::new();
    let exec = sim.executive(ExecutiveConfig::default()).unwrap();
    frozen_grant(&exec, MS);
    let (crawled, polls) = sim.run(|| {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        let start = Instant::now();
        let mut buf = [0u8; 4];
        for _ in 0..20_000 {
            assert!(sock.recv_from(&mut buf).is_err());
        }
        (start.elapsed(), sched::now())
    });
    assert_eq!(crawled, MS, "the busy poll crawled exactly to the horizon");
    assert_eq!(polls, MS);
    assert_eq!(exec.now(), MS);
}

#[test]
fn timestamp_defers_wakes_until_leave() {
    let t = 7 * MS;
    let sim = Sim::new();
    sim.run(|| {
        let exec = sched::attach(ExecutiveConfig::default()).unwrap();
        sched::mark_driver_thread();
        let done = Arc::new(AtomicBool::new(false));
        let reader = {
            let done = done.clone();
            let rx = UdpSocket::bind("127.0.0.1:47320").unwrap();
            thread::Builder::new()
                .name("reader".into())
                .spawn(move || {
                    let mut buf = [0u8; 4];
                    let (n, _) = rx.recv_from(&mut buf).unwrap();
                    done.store(true, Ordering::SeqCst);
                    (n, sched::now(), SystemTime::now())
                })
                .unwrap()
        };
        settle_in(&exec, "udp recv");
        exec.enter_timestamp(t);
        assert_eq!(sched::now(), t, "the driver reads the timestamp");
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(b"abc", "127.0.0.1:47320").unwrap();
        let start = real_now();
        let q = loop {
            let q = exec.quiescence();
            if q.blocker
                .as_ref()
                .is_some_and(|(k, _)| *k == BlockerKind::Deferred)
            {
                break q;
            }
            assert!(
                real_since(start) < Duration::from_secs(10),
                "never deferred: {q:?}"
            );
            real_sleep(MS);
        };
        assert_eq!(q.blocked, 1);
        real_sleep(50 * MS);
        assert!(
            !done.load(Ordering::SeqCst),
            "the reader waits for the timestamp to end"
        );
        assert_eq!(exec.leave_timestamp(t), 0);
        let (n, at, wall) = reader.join().unwrap();
        assert_eq!(n, 3);
        assert_eq!(at, t, "the reader reads the timestamp");
        assert_eq!(wall, epoch() + t);
    });
}

#[test]
fn checked_entry_refuses_with_a_timer_before_t_and_changes_nothing() {
    let sim = Sim::new();
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                thread::sleep(5 * MS);
                sched::now()
            })
        });
        settle_at(&exec, 5 * MS);
        assert_eq!(exec.enter_timestamp_checked(10 * MS), Err(NotQuiescent));
        assert_eq!(exec.now(), Duration::ZERO, "nothing moved");
        settle_at(&exec, 5 * MS);
        enter_checked(&exec, 5 * MS);
        assert_eq!(
            exec.now(),
            5 * MS,
            "inside the timestamp the sim reads its time"
        );
        assert_eq!(exec.leave_timestamp(5 * MS), 1);
        assert_eq!(run.join().unwrap(), 5 * MS);
    });
}

#[test]
fn leave_timestamp_fires_timers_due_at_t_and_returns_the_count() {
    let sim = Sim::new();
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                let sleepers: Vec<_> = (0..2)
                    .map(|_| {
                        thread::spawn(|| {
                            let start = Instant::now();
                            thread::sleep(4 * MS);
                            start.elapsed()
                        })
                    })
                    .collect();
                let later = thread::spawn(|| thread::sleep(8 * MS));
                let woke: Vec<_> = sleepers.into_iter().map(|h| h.join().unwrap()).collect();
                later.join().unwrap();
                woke
            })
        });
        settle_at(&exec, 4 * MS);
        while exec.timers(8).len() < 3 {
            real_sleep(Duration::from_micros(200));
        }
        enter_checked(&exec, 4 * MS);
        assert_eq!(exec.leave_timestamp(4 * MS), 2);
        assert_eq!(exec.now(), 4 * MS);
        assert_eq!(jump(&exec, Duration::from_secs(1)), 1);
        assert_eq!(exec.now(), 8 * MS);
        assert_eq!(run.join().unwrap(), vec![4 * MS, 4 * MS]);
    });
}

#[test]
fn waits_never_give_up_while_owned() {
    let sim = Sim::new();
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
        settle_in(&exec, "udp recv");
        real_sleep(600 * MS);
        assert!(
            !returned.load(Ordering::SeqCst),
            "a wait nothing can satisfy holds while the executive owns time"
        );
        drop(exec);
        let err = run.join().unwrap().unwrap_err();
        assert!(
            would_block(&err),
            "gives up as the OS reports a deadlock: {err:?}"
        );
    });
}

#[test]
fn time_controls_panic_while_owned() {
    let sim = Sim::new();
    let exec = sim.executive(ExecutiveConfig::default()).unwrap();
    let panics = |f: &dyn Fn()| {
        let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_err();
        let msg = err
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        assert!(msg.contains("owned by an Executive"), "{msg}");
    };
    panics(&|| sim.pause_time());
    panics(&|| sim.resume_time());
    panics(&|| sim.advance_time(MS));
    panics(&|| sim.set_time_rate(2.0));
    panics(&|| sim.set_time_value(Duration::from_secs(1)));
    panics(&|| sim.run(|| snare::time().advance(MS)));
    assert_eq!(sim.time_value(), Duration::ZERO);
    drop(exec);
    sim.advance_time(MS);
    assert_eq!(sim.time_value(), MS);
}

#[test]
fn driver_thread_reads_t_inside_a_timestamp_and_real_time_outside() {
    Sim::new().run(|| {
        let exec = sched::attach(ExecutiveConfig::default()).unwrap();
        exec.enter_timestamp(Duration::from_secs(3));
        assert_eq!(sched::thread_class(), ThreadClass::Driver);
        assert_eq!(SystemTime::now(), epoch() + Duration::from_secs(3));
        assert_eq!(sched::now(), Duration::from_secs(3));
        let a = Instant::now();
        assert_eq!(Instant::now(), a, "time holds at the timestamp");
        assert_eq!(exec.leave_timestamp(Duration::from_secs(3)), 0);
        assert_eq!(exec.now(), Duration::from_secs(3));
        let real = SystemTime::now();
        assert!(
            real > epoch() + Duration::from_secs(365 * 24 * 3600),
            "outside a timestamp the driver reads real time: {real:?}"
        );
        let start = Instant::now();
        thread::sleep(20 * MS);
        assert!(start.elapsed() >= 20 * MS);
        assert_eq!(
            exec.now(),
            Duration::from_secs(3),
            "a driver's sleep is real"
        );
    });
}

#[test]
fn with_driver_time_pool_worker_reads_t_and_its_wakes_are_gated() {
    let t = 4 * MS;
    Sim::new().run(|| {
        let exec = sched::attach(ExecutiveConfig::default()).unwrap();
        sched::mark_driver_thread();
        let done = Arc::new(AtomicBool::new(false));
        let reader = {
            let done = done.clone();
            let rx = UdpSocket::bind("127.0.0.1:47330").unwrap();
            thread::spawn(move || {
                let mut buf = [0u8; 4];
                rx.recv_from(&mut buf).unwrap();
                done.store(true, Ordering::SeqCst);
                sched::now()
            })
        };
        let (work, jobs) = mpsc::channel::<Duration>();
        let (ack, acks) = mpsc::channel::<SystemTime>();
        let worker = {
            let _pool = sched::spawn_as(ThreadClass::Driver, "pool");
            thread::spawn(move || {
                let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
                for t in jobs {
                    let wall = sched::with_driver_time(t, || {
                        tx.send_to(b"job", "127.0.0.1:47330").unwrap();
                        SystemTime::now()
                    });
                    ack.send(wall).unwrap();
                }
            })
        };
        settle_in(&exec, "udp recv");
        exec.enter_timestamp(t);
        work.send(t).unwrap();
        assert_eq!(
            acks.recv().unwrap(),
            epoch() + t,
            "the worker reads the timestamp"
        );
        real_sleep(50 * MS);
        assert!(
            !done.load(Ordering::SeqCst),
            "the worker's send is held back too"
        );
        exec.leave_timestamp(t);
        assert_eq!(reader.join().unwrap(), t);
        drop(work);
        worker.join().unwrap();
    });
}

#[test]
fn flowing_grant_advances_with_wall_time_and_fires_sleepers() {
    let sim = Sim::new();
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                let start = Instant::now();
                thread::sleep(30 * MS);
                start.elapsed()
            })
        });
        settle_at(&exec, 30 * MS);
        let start = real_now();
        exec.grant(Grant {
            anchor_v: Duration::ZERO,
            anchor_wall: start,
            rate: 1.0,
            horizon: Duration::from_secs(60),
        });
        assert!(run.join().unwrap() >= 30 * MS);
        let took = real_since(start);
        assert!(
            (25 * MS..Duration::from_secs(10)).contains(&took),
            "30 ms of sim time at rate 1: {took:?}"
        );
        assert!(exec.now() >= 30 * MS);
    });
}

#[test]
fn drop_restores_the_auto_time_skip_and_opens_the_gate() {
    Sim::new().run(|| {
        let exec = sched::attach(ExecutiveConfig::default()).unwrap();
        sched::mark_driver_thread();
        let reader = {
            let rx = UdpSocket::bind("127.0.0.1:47340").unwrap();
            thread::spawn(move || {
                let mut buf = [0u8; 4];
                rx.recv_from(&mut buf).unwrap();
                let real = real_now();
                let start = Instant::now();
                thread::sleep(Duration::from_secs(10));
                (start.elapsed(), real_since(real))
            })
        };
        settle_in(&exec, "udp recv");
        exec.enter_timestamp(MS);
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .send_to(b"x", "127.0.0.1:47340")
            .unwrap();
        drop(exec);
        let (slept, took) = reader.join().unwrap();
        assert!(slept >= Duration::from_secs(10));
        assert!(
            took < Duration::from_secs(5),
            "time skipped again: {took:?}"
        );
        assert!(sched::now() >= MS);
    });
}

#[test]
fn poll_timeouts_are_jump_targets() {
    let sim = Sim::new();
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| sim.run(|| poll_for(25 * MS)));
        settle_at(&exec, 25 * MS);
        assert_eq!(jump(&exec, Duration::from_secs(1)), 1);
        assert_eq!(exec.now(), 25 * MS);
        let (ready, took) = run.join().unwrap();
        assert_eq!(ready, 0);
        assert_eq!(took, 25 * MS);
    });
}

/// Polls an idle UDP socket for `timeout` through the OS's readiness API, returning how many
/// events were ready and how long the call took.
#[cfg(target_os = "linux")]
fn poll_for(timeout: Duration) -> (usize, Duration) {
    use std::os::fd::AsRawFd;
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    // SAFETY: plain epoll calls on a fresh descriptor and a local event buffer.
    unsafe {
        let ep = libc::epoll_create1(0);
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: 1,
        };
        assert_eq!(
            libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, sock.as_raw_fd(), &mut ev),
            0
        );
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
        let start = Instant::now();
        let n = libc::epoll_wait(ep, out.as_mut_ptr(), 4, timeout.as_millis() as i32);
        let took = start.elapsed();
        libc::close(ep);
        (n as usize, took)
    }
}

#[cfg(target_os = "macos")]
fn poll_for(timeout: Duration) -> (usize, Duration) {
    use mio::net::UdpSocket as MioUdp;
    use mio::{Events, Interest, Poll, Token};
    let mut poll = Poll::new().unwrap();
    let mut sock = MioUdp::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut sock, Token(1), Interest::READABLE)
        .unwrap();
    let mut events = Events::with_capacity(4);
    let start = Instant::now();
    poll.poll(&mut events, Some(timeout)).unwrap();
    (events.iter().count(), start.elapsed())
}

#[cfg(windows)]
fn poll_for(timeout: Duration) -> (usize, Duration) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{POLLRDNORM, WSAPOLLFD, WSAPoll};
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut pfd = WSAPOLLFD {
        fd: sock.as_raw_socket() as usize,
        events: POLLRDNORM,
        revents: 0,
    };
    let start = Instant::now();
    // SAFETY: one pollfd for a live socket.
    let n = unsafe { WSAPoll(&mut pfd, 1, timeout.as_millis() as i32) };
    (n as usize, start.elapsed())
}

#[test]
fn condvar_wait_timeout_while_finishes_after_a_jump_onto_its_deadline() {
    let sim = Sim::new();
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        frozen_grant(&exec, 50 * MS);
        let run = s.spawn(|| {
            sim.run(|| {
                let pair = (Mutex::new(()), Condvar::new());
                let start = Instant::now();
                let (_guard, result) = pair
                    .1
                    .wait_timeout_while(pair.0.lock().unwrap(), 10 * MS, |_| true)
                    .unwrap();
                (result.timed_out(), start.elapsed())
            })
        });
        settle_at(&exec, 10 * MS);
        assert_eq!(jump(&exec, 10 * MS), 1);
        let (timed_out, took) = run.join().unwrap();
        assert!(timed_out);
        assert!((10 * MS..11 * MS).contains(&took), "{took:?}");
    });
}

#[test]
fn a_notified_waiter_holds_off_a_jump_until_it_runs() {
    for round in 0..40 {
        let sim = Sim::new();
        thread::scope(|s| {
            let exec = sim.executive(ExecutiveConfig::default()).unwrap();
            let run = s.spawn(|| {
                sim.run(|| {
                    let pair = Arc::new((Mutex::new(false), Condvar::new()));
                    let waiter = {
                        let pair = pair.clone();
                        thread::spawn(move || {
                            let mut ready = pair.0.lock().unwrap();
                            while !*ready {
                                ready = pair.1.wait(ready).unwrap();
                            }
                            sched::now()
                        })
                    };
                    thread::sleep(MS);
                    *pair.0.lock().unwrap() = true;
                    pair.1.notify_one();
                    thread::sleep(5 * MS);
                    waiter.join().unwrap()
                })
            });
            let start = real_now();
            loop {
                let q = exec.quiescence();
                if q.quiescent && q.blocked == 2 && q.next_deadline == Some(MS) {
                    break;
                }
                assert!(real_since(start) < Duration::from_secs(20), "{q:?}");
                real_sleep(Duration::from_micros(100));
            }
            assert_eq!(jump(&exec, MS), 1);
            while exec.jump_to(6 * MS).is_err() {
                std::hint::spin_loop();
            }
            assert_eq!(exec.now(), 6 * MS);
            assert_eq!(
                run.join().unwrap(),
                MS,
                "round {round}: the notified waiter runs before time moves on"
            );
        });
    }
}

#[test]
fn a_waiter_on_a_mutex_relocked_before_it_runs_lets_the_holder_sleep() {
    for round in 0..20 {
        let sim = Sim::new();
        thread::scope(|s| {
            let exec = sim.executive(ExecutiveConfig::default()).unwrap();
            let run = s.spawn(|| {
                sim.run(|| {
                    let count = Arc::new(Mutex::new(0u32));
                    let held = count.lock().unwrap();
                    let waiter = {
                        let count = count.clone();
                        thread::spawn(move || *count.lock().unwrap() += 1)
                    };
                    thread::sleep(MS);
                    drop(held);
                    let held = count.lock().unwrap();
                    thread::sleep(5 * MS);
                    drop(held);
                    waiter.join().unwrap();
                    *count.lock().unwrap()
                })
            });
            settle_at(&exec, MS);
            assert_eq!(jump(&exec, MS), 1, "round {round}");
            settle_at(&exec, 6 * MS);
            assert_eq!(jump(&exec, 6 * MS), 1, "round {round}");
            assert_eq!(run.join().unwrap(), 1, "round {round}");
        });
    }
}

#[test]
fn a_waiter_notified_by_a_holder_that_then_sleeps_lets_time_move() {
    for round in 0..20 {
        let sim = Sim::new();
        thread::scope(|s| {
            let exec = sim.executive(ExecutiveConfig::default()).unwrap();
            let run = s.spawn(|| {
                sim.run(|| {
                    let pair = Arc::new((Mutex::new(false), Condvar::new()));
                    let waiter = {
                        let pair = pair.clone();
                        thread::spawn(move || {
                            let mut ready = pair.0.lock().unwrap();
                            while !*ready {
                                ready = pair.1.wait(ready).unwrap();
                            }
                            sched::now()
                        })
                    };
                    thread::sleep(MS);
                    let mut ready = pair.0.lock().unwrap();
                    *ready = true;
                    pair.1.notify_one();
                    thread::sleep(5 * MS);
                    drop(ready);
                    waiter.join().unwrap()
                })
            });
            settle_at(&exec, MS);
            assert_eq!(jump(&exec, MS), 1, "round {round}");
            settle_at(&exec, 6 * MS);
            assert_eq!(jump(&exec, 6 * MS), 1, "round {round}");
            assert_eq!(run.join().unwrap(), 6 * MS, "round {round}");
        });
    }
}

#[test]
fn a_condvar_waiter_notified_inside_a_timestamp_waits_for_leave() {
    let t = 7 * MS;
    let sim = Sim::new();
    sim.run(|| {
        let exec = sched::attach(ExecutiveConfig::default()).unwrap();
        sched::mark_driver_thread();
        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let done = Arc::new(AtomicBool::new(false));
        let waiter = {
            let (pair, done) = (pair.clone(), done.clone());
            thread::Builder::new()
                .name("cond waiter".into())
                .spawn(move || {
                    let mut ready = pair.0.lock().unwrap();
                    while !*ready {
                        ready = pair.1.wait(ready).unwrap();
                    }
                    done.store(true, Ordering::SeqCst);
                    sched::now()
                })
                .unwrap()
        };
        let start = real_now();
        while !exec
            .participants()
            .iter()
            .any(|p| p.state == PState::Blocked)
        {
            assert!(real_since(start) < Duration::from_secs(20));
            real_sleep(Duration::from_micros(200));
        }
        settle(&exec);
        exec.enter_timestamp(t);
        *pair.0.lock().unwrap() = true;
        pair.1.notify_one();
        let start = real_now();
        let q = loop {
            let q = exec.quiescence();
            if q.blocker
                .as_ref()
                .is_some_and(|(k, _)| *k == BlockerKind::Deferred)
            {
                break q;
            }
            assert!(
                real_since(start) < Duration::from_secs(10),
                "never deferred: {q:?}"
            );
            real_sleep(MS);
        };
        assert_eq!(q.blocked, 1);
        real_sleep(50 * MS);
        assert!(
            !done.load(Ordering::SeqCst),
            "the waiter waits for the timestamp to end"
        );
        assert!(
            *pair.0.lock().unwrap(),
            "the gate holds the waiter without its mutex"
        );
        exec.leave_timestamp(t);
        assert_eq!(waiter.join().unwrap(), t, "the waiter reads the timestamp");
    });
}

#[test]
fn dropping_the_executive_inside_a_timestamp_lapses_the_driver_time() {
    Sim::new().run(|| {
        let exec = sched::attach(ExecutiveConfig::default()).unwrap();
        exec.enter_timestamp(7 * MS);
        assert_eq!(SystemTime::now(), epoch() + 7 * MS);
        drop(exec);
        let real = SystemTime::now();
        assert!(
            real > epoch() + Duration::from_secs(365 * 24 * 3600),
            "the driver reads real time once the executive is gone: {real:?}"
        );
        let start = Instant::now();
        thread::sleep(3 * MS);
        assert!(start.elapsed() >= 3 * MS);
    });
}

#[test]
fn sim_time_agrees_with_the_monotonic_clock_inside_a_timestamp() {
    let t = 7 * MS;
    let sim = Sim::new();
    let go = AtomicBool::new(false);
    let spinning = AtomicBool::new(false);
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                let start = Instant::now();
                let v0 = sched::now();
                spinning.store(true, Ordering::SeqCst);
                while !go.load(Ordering::SeqCst) {
                    std::hint::spin_loop();
                }
                let elapsed = start.elapsed();
                (sched::now() - v0, elapsed)
            })
        });
        let _go = SetOnDrop(&go);
        while !spinning.load(Ordering::SeqCst) {
            real_sleep(MS);
        }
        exec.enter_timestamp(t);
        assert_eq!(exec.now(), t);
        go.store(true, Ordering::SeqCst);
        let (sim_elapsed, instant_elapsed) = run.join().unwrap();
        assert_eq!(sim_elapsed, instant_elapsed);
        assert_eq!(sim_elapsed, t);
        exec.leave_timestamp(t);
    });
}

/// A wait that recomputes `deadline - now` and waits again (std's `Condvar::wait_timeout_while`,
/// flume's `recv_timeout`) gets a zero timeout once the clock stops exactly on its deadline; the
/// clock reaching a nanosecond past the landing is what lets it see the deadline pass.
fn deadline_loop(timeout: Duration) -> Duration {
    let pair = (Mutex::new(()), Condvar::new());
    let start = Instant::now();
    let (_guard, result) = pair
        .1
        .wait_timeout_while(pair.0.lock().unwrap(), timeout, |()| true)
        .unwrap();
    assert!(result.timed_out());
    start.elapsed()
}

/// Joins `run`, failing the test if it has not finished within ten seconds of real time.
fn join_soon<T>(run: thread::ScopedJoinHandle<'_, T>) -> T {
    let start = real_now();
    while !run.is_finished() {
        assert!(
            real_since(start) < Duration::from_secs(10),
            "the wait is spinning at its deadline"
        );
        real_sleep(MS);
    }
    run.join().unwrap()
}

#[test]
fn a_wait_landed_on_by_a_jump_times_out() {
    let sim = Sim::new();
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| sim.run(|| deadline_loop(30 * MS)));
        settle_at(&exec, 30 * MS);
        assert_eq!(jump(&exec, Duration::from_secs(1)), 1);
        let waited = join_soon(run);
        assert!(
            waited >= 30 * MS && waited <= 30 * MS + Duration::from_nanos(1),
            "the wait timed out {waited:?} in"
        );
    });
}

#[test]
fn a_wait_landed_on_by_a_timestamp_times_out() {
    let sim = Sim::new();
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| sim.run(|| deadline_loop(30 * MS)));
        settle_at(&exec, 30 * MS);
        enter_checked(&exec, 30 * MS);
        exec.leave_timestamp(30 * MS);
        let waited = join_soon(run);
        assert!(
            waited >= 30 * MS && waited <= 30 * MS + Duration::from_nanos(1),
            "the wait timed out {waited:?} in"
        );
    });
}
