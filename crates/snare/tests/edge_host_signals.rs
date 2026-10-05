#![cfg(unix)]
//! Edge cases of the per-sim signal table, pinned exactly ahead of a performance pass: the order
//! handlers run and the log records a mix of `raise`, `kill`, `pthread_kill` and the test's own
//! raises, with their virtual timestamps; `raise_after` timers firing in time order with ties in
//! a fixed order; what `SA_RESETHAND` leaves behind; the chain of previous
//! dispositions `sigaction` and `signal` return; a process-wide `SIG_IGN` read back as a sim's
//! starting disposition, snapshotted when the sim is built; isolation between sims and from
//! the real process, threads outside the sim and `snare::real`; signals outside the modelled three
//! going to the OS; and the `ctrlc` crate seeing each raise once, in order.

use std::ffi::c_int;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use snare::{RecordedEvent, Signal, SignalDelivery, SignalOrigin, Sim};

fn handler_action(handler: usize, flags: c_int) -> libc::sigaction {
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = handler;
        act.sa_flags = flags;
        libc::sigemptyset(&mut act.sa_mask);
        act
    }
}

fn install(sig: c_int, handler: usize, flags: c_int) -> libc::sigaction {
    let act = handler_action(handler, flags);
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        assert_eq!(libc::sigaction(sig, &act, &mut old), 0);
        old
    }
}

fn query(sig: c_int) -> libc::sigaction {
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        assert_eq!(libc::sigaction(sig, std::ptr::null(), &mut old), 0);
        old
    }
}

fn real_query(sig: c_int) -> (usize, c_int) {
    let act = snare::real(|| query(sig));
    (act.sa_sigaction, act.sa_flags)
}

fn signal_log(sim: &Sim) -> Vec<(Duration, Signal, SignalOrigin, SignalDelivery)> {
    sim.recorded_events()
        .into_iter()
        .filter_map(|entry| match entry.event {
            RecordedEvent::Signal {
                signal,
                origin,
                delivery,
            } => Some((entry.at, signal, origin, delivery)),
            _ => None,
        })
        .collect()
}

static ORDER: Mutex<Vec<c_int>> = Mutex::new(Vec::new());
extern "C" fn order_handler(sig: c_int) {
    ORDER.lock().unwrap().push(sig);
}

#[test]
fn mixed_raises_run_and_log_in_call_order() {
    let sim = Sim::builder().deterministic().build();
    let handle = sim.signals();
    sim.run(|| {
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            install(sig, order_handler as *const () as usize, 0);
        }
        let start = Instant::now();
        unsafe {
            assert_eq!(libc::raise(libc::SIGHUP), 0);
            assert_eq!(libc::kill(libc::getpid(), libc::SIGINT), 0);
        }
        assert_eq!(handle.raise(Signal::Terminate), SignalDelivery::Handled);
        std::thread::sleep(Duration::from_millis(5));
        unsafe {
            assert_eq!(libc::pthread_kill(libc::pthread_self(), libc::SIGINT), 0);
            assert_eq!(libc::kill(0, libc::SIGTERM), 0);
            assert_eq!(libc::kill(libc::getpid(), 0), 0);
            assert_eq!(libc::pthread_kill(libc::pthread_self(), 0), 0);
        }
        assert_eq!(handle.raise(Signal::Hangup), SignalDelivery::Handled);
        assert!(start.elapsed() >= Duration::from_millis(5));
    });
    assert_eq!(
        *ORDER.lock().unwrap(),
        [
            libc::SIGHUP,
            libc::SIGINT,
            libc::SIGTERM,
            libc::SIGINT,
            libc::SIGTERM,
            libc::SIGHUP
        ]
    );
    let log = signal_log(&sim);
    let what: Vec<_> = log.iter().map(|(_, s, o, d)| (*s, *o, *d)).collect();
    use SignalDelivery::Handled;
    use SignalOrigin::{Process, Sim as Test};
    assert_eq!(
        what,
        [
            (Signal::Hangup, Process, Handled),
            (Signal::Interrupt, Process, Handled),
            (Signal::Terminate, Test, Handled),
            (Signal::Interrupt, Process, Handled),
            (Signal::Terminate, Process, Handled),
            (Signal::Hangup, Test, Handled),
        ]
    );
    let at: Vec<Duration> = log.iter().map(|(at, ..)| *at).collect();
    assert!(at.windows(2).all(|w| w[0] <= w[1]), "{at:?}");
    assert!(
        at[2] < Duration::from_millis(5) && at[3] >= Duration::from_millis(5),
        "{at:?}"
    );
}

static TIMED: Mutex<Vec<(c_int, Duration)>> = Mutex::new(Vec::new());
extern "C" fn timed_handler(sig: c_int) {
    TIMED.lock().unwrap().push((sig, snare::sched::now()));
}

#[test]
fn raise_after_fires_in_time_order_with_ties_in_a_fixed_order() {
    let sim = Sim::builder().deterministic().build();
    let handle = sim.signals();
    let base = sim.run(|| {
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            install(sig, timed_handler as *const () as usize, 0);
        }
        let base = snare::sched::now();
        let pending = [
            handle.raise_after(Signal::Interrupt, Duration::from_millis(30)),
            handle.raise_after(Signal::Terminate, Duration::from_millis(10)),
            handle.raise_after(Signal::Hangup, Duration::from_millis(20)),
            handle.raise_after(Signal::Interrupt, Duration::from_millis(10)),
            handle.raise_after(Signal::Hangup, Duration::from_millis(10)),
        ];
        for p in pending {
            assert_eq!(p.wait(), SignalDelivery::Handled);
        }
        base
    });
    let got: Vec<(c_int, u128)> = TIMED
        .lock()
        .unwrap()
        .iter()
        .map(|(s, t)| (*s, (*t - base).as_millis()))
        .collect();
    assert_eq!(
        got,
        [
            (libc::SIGHUP, 10),
            (libc::SIGTERM, 10),
            (libc::SIGINT, 10),
            (libc::SIGHUP, 20),
            (libc::SIGINT, 30)
        ]
    );
}

static RESET: Mutex<u32> = Mutex::new(0);
extern "C" fn reset_handler(_: c_int) {
    *RESET.lock().unwrap() += 1;
}

#[test]
fn sa_resethand_leaves_the_default_behind() {
    let sim = Sim::new();
    sim.run(|| {
        let flags = libc::SA_RESETHAND | libc::SA_RESTART | libc::SA_SIGINFO;
        install(libc::SIGTERM, reset_handler as *const () as usize, flags);
        assert_eq!(sim.raise_signal(Signal::Terminate), SignalDelivery::Handled);
        let after = query(libc::SIGTERM);
        assert_eq!(after.sa_sigaction, libc::SIG_DFL);
        assert_eq!(after.sa_flags, flags, "the flags stay as they were");
        assert_eq!(
            sim.raise_signal(Signal::Terminate),
            SignalDelivery::DefaultAction
        );
        assert_eq!(
            unsafe { libc::raise(libc::SIGTERM) },
            0,
            "the default action is never carried out"
        );
    });
    assert_eq!(*RESET.lock().unwrap(), 1);
}

extern "C" fn chain_a(_: c_int) {}
extern "C" fn chain_b(_: c_int) {}

#[test]
fn previous_dispositions_chain() {
    let sim = Sim::new();
    sim.run(|| {
        let (a, b) = (chain_a as *const () as usize, chain_b as *const () as usize);
        let first = install(libc::SIGHUP, a, libc::SA_NODEFER);
        assert_eq!(install(libc::SIGHUP, b, 0).sa_sigaction, a);
        let old_b = install(libc::SIGHUP, libc::SIG_IGN, 0);
        assert_eq!((old_b.sa_sigaction, old_b.sa_flags), (b, 0));
        assert_eq!(unsafe { libc::signal(libc::SIGHUP, a) }, libc::SIG_IGN);
        assert_eq!(unsafe { libc::signal(libc::SIGHUP, libc::SIG_DFL) }, a);
        assert_eq!(query(libc::SIGHUP).sa_sigaction, libc::SIG_DFL);
        assert_eq!(
            sim.raise_signal(Signal::Hangup),
            SignalDelivery::DefaultAction
        );
        install(libc::SIGHUP, first.sa_sigaction, first.sa_flags);
    });
}

#[test]
fn a_process_sig_ign_is_the_starting_disposition() {
    let before = real_query(libc::SIGHUP);
    let early = Sim::new();
    snare::real(|| unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) });
    let late = Sim::new();
    let early_start = early.run(|| query(libc::SIGHUP).sa_sigaction);
    let late_start = late.run(|| query(libc::SIGHUP).sa_sigaction);
    assert_eq!(late.raise_signal(Signal::Hangup), SignalDelivery::Ignored);
    late.run(|| install(libc::SIGHUP, chain_a as *const () as usize, 0));
    assert_eq!(
        real_query(libc::SIGHUP).0,
        libc::SIG_IGN,
        "the process keeps its own"
    );
    snare::real(|| unsafe { libc::signal(libc::SIGHUP, before.0) });
    let again = late.run(|| query(libc::SIGHUP).sa_sigaction);
    assert_eq!(late_start, libc::SIG_IGN);
    assert_eq!(
        early_start, before.0,
        "the table is read from the process when the sim is built"
    );
    assert_eq!(again, chain_a as *const () as usize);
}

static PER_SIM: Mutex<Vec<&str>> = Mutex::new(Vec::new());
extern "C" fn sim_a_handler(_: c_int) {
    PER_SIM.lock().unwrap().push("a");
}

#[test]
fn tables_are_per_sim_and_never_the_process() {
    let real_term = real_query(libc::SIGTERM);
    let a = Sim::new();
    let b = Sim::new();
    a.run(|| {
        install(libc::SIGTERM, sim_a_handler as *const () as usize, 0);
        assert_eq!(
            real_query(libc::SIGTERM),
            real_term,
            "snare::real sees the process"
        );
        let unmanaged = snare::real(|| std::thread::spawn(|| query(libc::SIGTERM).sa_sigaction))
            .join()
            .unwrap();
        assert_eq!(unmanaged, real_term.0);
        let spawned = std::thread::spawn(|| query(libc::SIGTERM).sa_sigaction)
            .join()
            .unwrap();
        assert_eq!(
            spawned, sim_a_handler as *const () as usize,
            "the sim's threads share its table"
        );
    });
    assert_eq!(b.run(|| query(libc::SIGTERM).sa_sigaction), real_term.0);
    assert_eq!(
        b.raise_signal(Signal::Terminate),
        SignalDelivery::DefaultAction
    );
    assert_eq!(
        a.raise_signal(Signal::Terminate),
        SignalDelivery::Handled,
        "after the run, from outside"
    );
    assert_eq!(
        a.run(|| query(libc::SIGTERM).sa_sigaction),
        sim_a_handler as *const () as usize
    );
    assert_eq!(real_query(libc::SIGTERM), real_term);
    assert_eq!(*PER_SIM.lock().unwrap(), ["a"]);
    drop(a);
    assert_eq!(
        Sim::new().run(|| query(libc::SIGTERM).sa_sigaction),
        real_term.0
    );
}

static USR2: Mutex<u32> = Mutex::new(0);
extern "C" fn usr2_handler(_: c_int) {
    *USR2.lock().unwrap() += 1;
}

#[test]
fn other_signals_go_to_the_os() {
    let before = real_query(libc::SIGUSR2);
    let sim = Sim::new();
    sim.run(|| {
        install(libc::SIGUSR2, usr2_handler as *const () as usize, 0);
        assert_eq!(
            real_query(libc::SIGUSR2).0,
            usr2_handler as *const () as usize,
            "set on the process"
        );
        assert_eq!(unsafe { libc::raise(libc::SIGUSR2) }, 0);
    });
    assert_eq!(
        *USR2.lock().unwrap(),
        1,
        "the real signal ran the real handler"
    );
    assert!(signal_log(&sim).is_empty(), "and the sim recorded nothing");
    snare::real(|| unsafe { libc::signal(libc::SIGUSR2, before.0) });
}

#[test]
fn ctrlc_sees_each_raise_once_in_order() {
    let sim = Sim::new();
    let handle = sim.signals();
    let seen = sim.run(|| {
        let (tx, rx) = std::sync::mpsc::channel();
        let count = std::sync::atomic::AtomicU32::new(0);
        ctrlc::set_handler(move || {
            tx.send(count.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
                .unwrap();
        })
        .unwrap();
        let mut seen = Vec::new();
        for _ in 0..3 {
            assert_eq!(handle.raise(Signal::Interrupt), SignalDelivery::Handled);
            seen.push(rx.recv_timeout(Duration::from_secs(5)).unwrap());
        }
        assert_eq!(
            handle.raise(Signal::Terminate),
            SignalDelivery::DefaultAction,
            "ctrlc takes SIGINT only"
        );
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        seen
    });
    assert_eq!(seen, [0, 1, 2]);
}
