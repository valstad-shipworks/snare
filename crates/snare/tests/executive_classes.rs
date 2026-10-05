//! What an executive sees of a sim's threads: leases and the epoch, background threads' timers and
//! effects, the participant listing, the timer listing, hints and the audit.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use snare::Sim;
use snare::sched::{
    self, BlockerKind, Executive, ExecutiveConfig, NotQuiescent, PState, Quiescence, ThreadClass,
    TimerInfo,
};

const MS: Duration = Duration::from_millis(1);

fn audited() -> ExecutiveConfig {
    ExecutiveConfig { audit: true }
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

fn until(what: &str, mut f: impl FnMut() -> bool) {
    let start = real_now();
    while !f() {
        assert!(
            real_since(start) < Duration::from_secs(20),
            "timed out waiting: {what}"
        );
        real_sleep(Duration::from_micros(200));
    }
}

fn settle(exec: &Executive) -> Quiescence {
    let mut last = None;
    until("quiescence", || {
        let q = exec.quiescence();
        let done = q.quiescent && q.blocked > 0;
        last = Some(q);
        done
    });
    last.unwrap()
}

fn jump(exec: &Executive, t: Duration) -> u32 {
    loop {
        settle(exec);
        if let Ok(fired) = exec.jump_to(t) {
            return fired;
        }
    }
}

#[test]
fn a_lease_blocks_quiescence_and_its_release_fires_arm_notify() {
    let sim = Sim::new();
    let fired = Arc::new(AtomicBool::new(false));
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| sim.run(|| thread::sleep(5 * MS)));
        until("the sleeper's timer", || {
            exec.next_deadline() == Some(5 * MS)
        });
        settle(&exec);
        let lease = sim.busy("warmup");
        let mut q = exec.quiescence();
        until("the lease to be what blocks", || {
            q = exec.quiescence();
            q.blocker
                .as_ref()
                .is_some_and(|(k, _)| *k == BlockerKind::Lease)
        });
        assert!(!q.quiescent);
        assert_eq!(q.busy, 1);
        let (kind, label) = q.blocker.clone().unwrap();
        assert_eq!(kind, BlockerKind::Lease);
        assert_eq!(&*label, "warmup");
        assert_eq!(
            exec.held_leases(),
            vec![sched::LeaseInfo {
                label: "warmup",
                kind: sched::LeaseKind::Busy,
                holder: None,
            }]
        );
        assert_eq!(exec.jump_to(Duration::from_secs(1)), Err(NotQuiescent));
        assert_eq!(exec.now(), Duration::ZERO);
        let flag = fired.clone();
        exec.arm_notify(
            exec.quiescence().epoch,
            Arc::new(move || flag.store(true, Ordering::SeqCst)),
        );
        drop(lease);
        assert!(
            fired.load(Ordering::SeqCst),
            "giving the lease back moves the epoch"
        );
        assert_eq!(jump(&exec, Duration::from_secs(1)), 1);
        run.join().unwrap();
    });
}

#[test]
fn setup_effects_are_counted() {
    let sim = Sim::new();
    let exec = sim.executive(audited()).unwrap();
    sim.run(|| {
        thread::Builder::new()
            .name("bg".into())
            .spawn(|| {
                sched::mark_background("bg");
                let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
                {
                    let _setup = sched::setup_scope("boot");
                    tx.send_to(b"a", "127.0.0.1:47400").unwrap();
                    tx.send_to(b"b", "127.0.0.1:47400").unwrap();
                }
                tx.send_to(b"c", "127.0.0.1:47400").unwrap();
            })
            .unwrap()
            .join()
            .unwrap();
    });
    let report = exec.audit();
    assert!(report.total_setup_effects >= 2, "{report:?}");
    let sends: Vec<_> = report
        .class_effects
        .iter()
        .filter(|e| e.op == "sendto")
        .collect();
    assert_eq!(sends.len(), 1, "{report:?}");
    assert_eq!(&*sends[0].thread, "bg");
    assert_eq!(sends[0].class, ThreadClass::Background);
    assert_eq!(
        report.total_class_effects,
        report.class_effects.len() as u64
    );
}

#[test]
fn background_timers_never_steer_jumps_but_fire() {
    let sim = Sim::new();
    let woke = Arc::new(AtomicBool::new(false));
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                let background = {
                    let _bg = sched::spawn_as(ThreadClass::Background, "ticker");
                    let woke = woke.clone();
                    thread::spawn(move || {
                        let start = Instant::now();
                        thread::sleep(3 * MS);
                        woke.store(true, Ordering::SeqCst);
                        start.elapsed()
                    })
                };
                thread::sleep(10 * MS);
                background.join().unwrap()
            })
        });
        until("both sleepers waiting", || exec.timers(8).len() == 2);
        let q = settle(&exec);
        assert_eq!(
            q.next_deadline,
            Some(10 * MS),
            "a background timer is no jump target"
        );
        assert_eq!(jump(&exec, Duration::from_secs(1)), 1);
        assert_eq!(exec.now(), 10 * MS);
        assert!(run.join().unwrap() >= 3 * MS);
        assert!(
            woke.load(Ordering::SeqCst),
            "the background sleep passed and fired"
        );
    });
}

#[test]
fn a_background_udp_send_and_unpark_are_class_effects() {
    let sim = Sim::new();
    thread::scope(|s| {
        let exec = sim.executive(audited()).unwrap();
        let (go, wait_go) = mpsc::channel::<()>();
        let run = s.spawn(|| {
            sim.run(|| {
                let parker = thread::Builder::new()
                    .name("parker".into())
                    .spawn(thread::park)
                    .unwrap();
                let waker = parker.thread().clone();
                let background = thread::Builder::new()
                    .name("helper".into())
                    .spawn(move || {
                        sched::mark_background("helper");
                        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
                        wait_go.recv().unwrap();
                        tx.send_to(b"x", "127.0.0.1:47410").unwrap();
                        waker.unpark();
                    })
                    .unwrap();
                parker.join().unwrap();
                background.join().unwrap();
            })
        });
        until("the parker parks", || {
            exec.participants()
                .iter()
                .any(|p| &*p.name == "parker" && p.state == PState::Blocked)
        });
        go.send(()).unwrap();
        run.join().unwrap();
        let report = exec.audit();
        let ops: Vec<&str> = report
            .class_effects
            .iter()
            .filter(|e| &*e.thread == "helper")
            .map(|e| e.op)
            .collect();
        assert!(ops.contains(&"sendto"), "{ops:?}");
        #[cfg(target_os = "linux")]
        let unpark = "FUTEX_WAKE";
        #[cfg(target_os = "macos")]
        let unpark = "dispatch_semaphore_signal";
        #[cfg(windows)]
        let unpark = "WakeByAddressSingle";
        assert!(ops.contains(&unpark), "{ops:?}");
    });
}

#[test]
fn participants_report_names_waits_deadlines_last_wait_and_leases() {
    #[cfg(target_os = "linux")]
    const NATIVE: &str = "futex";
    #[cfg(target_os = "macos")]
    const NATIVE: &str = "cond";
    #[cfg(windows)]
    const NATIVE: &str = "WaitOnAddress";
    let sim = Sim::new();
    sim.run(|| {
        let exec = sched::attach(ExecutiveConfig::default()).unwrap();
        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let rx = UdpSocket::bind("127.0.0.1:47420").unwrap();
        let own = UdpSocket::bind("127.0.0.1:47421").unwrap();
        let sleeper = thread::Builder::new()
            .name("sleeper".into())
            .spawn(|| thread::sleep(50 * MS))
            .unwrap();
        let joiner = thread::Builder::new()
            .name("joiner".into())
            .spawn(move || sleeper.join().unwrap())
            .unwrap();
        let receiver = thread::Builder::new()
            .name("receiver".into())
            .spawn(move || {
                let mut buf = [0u8; 4];
                rx.recv_from(&mut buf).unwrap();
            })
            .unwrap();
        let waiter = {
            let pair = pair.clone();
            thread::Builder::new()
                .name("waiter".into())
                .spawn(move || {
                    let _lease = sched::busy("hold");
                    let mut ready = pair.0.lock().unwrap();
                    while !*ready {
                        ready = pair.1.wait(ready).unwrap();
                    }
                })
                .unwrap()
        };
        let mut buf = [0u8; 4];
        let rows = thread::scope(|scope| {
            scope.spawn(|| {
                sched::mark_background("poke");
                until("the caller blocks", || {
                    exec.participants()
                        .iter()
                        .any(|r| r.id == 0 && r.wait == Some("udp recv"))
                });
                UdpSocket::bind("127.0.0.1:0")
                    .unwrap()
                    .send_to(b"me", "127.0.0.1:47421")
                    .unwrap();
            });
            own.recv_from(&mut buf).unwrap();
            loop {
                let rows = exec.participants();
                let settled = [
                    ("sleeper", "sleep"),
                    ("joiner", "join"),
                    ("receiver", "udp recv"),
                    ("waiter", NATIVE),
                ]
                .iter()
                .all(|&(name, wait)| {
                    rows.iter()
                        .any(|r| &*r.name == name && r.wait == Some(wait))
                });
                if settled {
                    break rows;
                }
                real_sleep(MS);
            }
        });
        let row = |name: &str| {
            rows.iter()
                .find(|r| &*r.name == name && r.state != PState::Busy("hold"))
                .unwrap_or_else(|| panic!("no row {name}: {rows:?}"))
        };
        assert_eq!(row("sleeper").wait, Some("sleep"));
        assert_eq!(row("sleeper").deadline, Some(50 * MS));
        assert_eq!(row("joiner").wait, Some("join"));
        assert_eq!(row("receiver").wait, Some("udp recv"));
        assert_eq!(row("receiver").deadline, None);
        assert_eq!(row("waiter").wait, Some(NATIVE));
        assert_eq!(row("waiter").leases, vec!["hold"]);
        let me = rows
            .iter()
            .find(|r| r.state == PState::Running)
            .expect("the calling thread runs");
        assert_eq!(me.last_wait, Some("udp recv"));
        assert_eq!(me.wait, None);
        let lease = rows
            .iter()
            .find(|r| r.state == PState::Busy("hold"))
            .expect("a row for the lease");
        assert_eq!(&*lease.name, "waiter");
        for blocked in rows.iter().filter(|r| r.state == PState::Blocked) {
            assert_eq!(blocked.wait, blocked.last_wait);
        }
        drop(exec);
        *pair.0.lock().unwrap() = true;
        pair.1.notify_all();
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .send_to(b"go", "127.0.0.1:47420")
            .unwrap();
        receiver.join().unwrap();
        waiter.join().unwrap();
        joiner.join().unwrap();
    });
}

#[test]
fn joining_an_unmanaged_thread_never_makes_the_sim_quiescent() {
    let sim = Sim::new();
    let exec = sim.executive(ExecutiveConfig::default()).unwrap();
    let (release, released) = std::sync::mpsc::channel();
    let unmanaged = snare::real(|| thread::spawn(move || released.recv().unwrap()));
    let joining = AtomicBool::new(false);
    let mut observed_quiescent = false;
    thread::scope(|scope| {
        let run = scope.spawn(|| {
            sim.run(|| {
                joining.store(true, Ordering::Release);
                unmanaged.join().unwrap();
            });
        });
        until("the unmanaged join", || joining.load(Ordering::Acquire));
        for _ in 0..100 {
            observed_quiescent |= exec.quiescence().quiescent;
            real_sleep(Duration::from_micros(200));
        }
        release.send(()).unwrap();
        run.join().unwrap();
    });
    assert!(!observed_quiescent);
    assert_eq!(exec.outside_wakes(), 0);
}

#[test]
fn timers_listing_names_owners_and_hints_drain_once() {
    let sim = Sim::new();
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                let sampler = thread::Builder::new()
                    .name("sampler".into())
                    .spawn(|| {
                        sched::mark_background("sampler");
                        thread::sleep(3 * MS);
                    })
                    .unwrap();
                thread::Builder::new()
                    .name("sleeper".into())
                    .spawn(|| {
                        sched::hint_starving("rx", 0.5);
                        thread::sleep(5 * MS);
                    })
                    .unwrap()
                    .join()
                    .unwrap();
                sampler.join().unwrap();
            })
        });
        until("both timers", || exec.timers(8).len() == 2);
        settle(&exec);
        assert_eq!(
            exec.timers(8),
            vec![
                TimerInfo {
                    deadline: 5 * MS,
                    owner: Some(Arc::from("sleeper")),
                },
                TimerInfo {
                    deadline: 3 * MS,
                    owner: Some(Arc::from("sampler")),
                },
            ]
        );
        assert_eq!(exec.timers(1).len(), 1);
        assert_eq!(exec.drain_hints(), vec![(Arc::from("rx"), 0.5)]);
        assert!(exec.drain_hints().is_empty(), "hints drain once");
        assert_eq!(jump(&exec, Duration::from_secs(1)), 1);
        run.join().unwrap();
    });
}

#[test]
fn an_unmanaged_thread_waking_a_participant_is_an_outside_wake() {
    let sim = Sim::new();
    thread::scope(|s| {
        let exec = sim.executive(audited()).unwrap();
        let (tx, rx) = mpsc::channel::<u32>();
        let sim = &sim;
        let run = s.spawn(move || sim.run(move || rx.recv().unwrap()));
        settle(&exec);
        assert_eq!(exec.audit().outside_wakes, 0);
        tx.send(7).unwrap();
        assert_eq!(run.join().unwrap(), 7);
        assert_eq!(exec.audit().outside_wakes, 1);
    });
}

#[test]
fn an_unmodelled_call_is_a_violation_in_audit_mode() {
    let sim = Sim::new();
    let exec = sim.executive(audited()).unwrap();
    let op = sim.run(|| {
        thread::Builder::new()
            .name("caller".into())
            .spawn(unmodelled_call)
            .unwrap()
            .join()
            .unwrap()
    });
    let report = exec.audit();
    let violation = report
        .violations
        .iter()
        .find(|v| v.op == op && &*v.thread == "caller")
        .unwrap_or_else(|| panic!("no violation for {op}: {report:?}"));
    assert!(!violation.fatal);
    assert!(report.total_violations >= 1);
    drop(exec);
    let quiet = sim.executive(ExecutiveConfig::default()).unwrap();
    sim.run(unmodelled_call);
    assert!(quiet.audit().violations.is_empty(), "no audit, no log");
}

#[cfg(target_os = "linux")]
fn unmodelled_call() -> &'static str {
    // SAFETY: getppid takes no arguments.
    unsafe { libc::syscall(libc::SYS_getppid) };
    "syscall"
}

#[cfg(target_os = "macos")]
fn unmodelled_call() -> &'static str {
    let mut n: libc::c_int = 0;
    // SAFETY: FIONREAD writes one int; on a descriptor that is no socket it fails harmlessly.
    unsafe { libc::ioctl(0, libc::FIONREAD, &mut n) };
    "ioctl"
}

#[cfg(windows)]
fn unmodelled_call() -> &'static str {
    use windows_sys::Win32::Networking::WinSock::{INVALID_SOCKET, SOCKADDR, getsockname};
    let mut addr: SOCKADDR = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<SOCKADDR>() as i32;
    // SAFETY: a socket the sim does not own goes to Winsock, which rejects it.
    unsafe { getsockname(INVALID_SOCKET, &mut addr, &mut len) };
    "getsockname"
}
