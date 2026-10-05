//! Signals per sim: the code under test's own `sigaction`/`signal`/`raise`/`kill`/`pthread_kill`
//! (console control handlers on Windows) against a table the sim keeps, and `Sim::raise_signal`
//! delivering into it as the host OS would.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use snare::{RecordedEvent, Signal, SignalDelivery, SignalOrigin, Sim};

fn signal_events(sim: &Sim) -> Vec<(Signal, SignalOrigin, SignalDelivery)> {
    sim.recorded_events()
        .into_iter()
        .filter_map(|entry| match entry.event {
            RecordedEvent::Signal {
                signal,
                origin,
                delivery,
            } => Some((signal, origin, delivery)),
            _ => None,
        })
        .collect()
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::ffi::c_int;

    pub(super) fn handler_action(handler: usize, flags: c_int) -> libc::sigaction {
        // SAFETY: an all-zero sigaction is valid; the set calls only write its mask.
        unsafe {
            let mut act: libc::sigaction = std::mem::zeroed();
            act.sa_sigaction = handler;
            act.sa_flags = flags;
            libc::sigemptyset(&mut act.sa_mask);
            act
        }
    }

    pub(super) fn install(sig: c_int, handler: usize, flags: c_int) -> libc::sigaction {
        let act = handler_action(handler, flags);
        // SAFETY: valid pointers to a sigaction and a place for the old one.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(sig, &act, &mut old), 0);
            old
        }
    }

    pub(super) fn query(sig: c_int) -> libc::sigaction {
        // SAFETY: a query only fills `old`.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(sig, std::ptr::null(), &mut old), 0);
            old
        }
    }

    fn errno() -> c_int {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    }

    static ROUNDTRIP: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn roundtrip_handler(_: c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {
        ROUNDTRIP.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn sigaction_roundtrip() {
        let real_before = snare::real(|| query(libc::SIGINT));
        let sim = Sim::new();
        sim.run(|| {
            let initial = query(libc::SIGINT);
            assert_eq!(
                initial.sa_sigaction, real_before.sa_sigaction,
                "starts as the process"
            );
            let mut act = handler_action(
                roundtrip_handler as *const () as usize,
                libc::SA_SIGINFO | libc::SA_RESTART,
            );
            // SAFETY: adds a signal to the mask of a local sigaction.
            unsafe { libc::sigaddset(&mut act.sa_mask, libc::SIGUSR1) };
            // SAFETY: valid pointers.
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::sigaction(libc::SIGINT, &act, &mut old) }, 0);
            assert_eq!(old.sa_sigaction, initial.sa_sigaction);
            let back = query(libc::SIGINT);
            assert_eq!(back.sa_sigaction, act.sa_sigaction);
            assert_eq!(back.sa_flags, act.sa_flags);
            // SAFETY: reads the mask of a local sigaction.
            assert_eq!(
                unsafe { libc::sigismember(&back.sa_mask, libc::SIGUSR1) },
                1
            );
            assert_eq!(sim.raise_signal(Signal::Interrupt), SignalDelivery::Handled);
        });
        assert_eq!(ROUNDTRIP.load(Ordering::SeqCst), 1);
        let real_after = snare::real(|| query(libc::SIGINT));
        assert_eq!(
            real_after.sa_sigaction, real_before.sa_sigaction,
            "the process is untouched"
        );
        assert_eq!(real_after.sa_flags, real_before.sa_flags);
    }

    #[test]
    fn sigaction_einval() {
        let sim = Sim::new();
        sim.run(|| {
            let act = handler_action(libc::SIG_IGN, 0);
            for sig in [0, -1, 1000, libc::SIGKILL, libc::SIGSTOP] {
                // SAFETY: valid pointer; the OS rejects every one of these signals.
                let r = unsafe { libc::sigaction(sig, &act, std::ptr::null_mut()) };
                assert_eq!((r, errno()), (-1, libc::EINVAL), "sigaction({sig})");
            }
        });
    }

    static BSD: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn bsd_handler(_: c_int) {
        BSD.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn signal_bsd_semantics() {
        let sim = Sim::new();
        sim.run(|| {
            let h = bsd_handler as *const () as libc::sighandler_t;
            // SAFETY: installs a handler that only counts.
            assert_eq!(unsafe { libc::signal(libc::SIGTERM, h) }, libc::SIG_DFL);
            let act = query(libc::SIGTERM);
            assert_eq!(act.sa_sigaction, h);
            assert_eq!(act.sa_flags & libc::SA_RESTART, libc::SA_RESTART);
            assert_eq!(act.sa_flags & libc::SA_RESETHAND, 0);
            // SAFETY: reads the mask of a local sigaction.
            assert_eq!(unsafe { libc::sigismember(&act.sa_mask, libc::SIGTERM) }, 1);
            // SAFETY: the handler only counts.
            unsafe {
                assert_eq!(libc::raise(libc::SIGTERM), 0);
                assert_eq!(libc::raise(libc::SIGTERM), 0);
            }
            assert_eq!(BSD.load(Ordering::SeqCst), 2, "the handler stays installed");
            // SAFETY: SIG_ERR is rejected without effect.
            assert_eq!(
                unsafe { libc::signal(libc::SIGTERM, libc::SIG_ERR) },
                libc::SIG_ERR
            );
            assert_eq!(errno(), libc::EINVAL);
            // SAFETY: restores the default.
            assert_eq!(unsafe { libc::signal(libc::SIGTERM, libc::SIG_DFL) }, h);
        });
    }

    static INLINE: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn inline_handler(_: c_int) {
        INLINE.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn raise_signal_inline() {
        let sim = Sim::new();
        sim.run(|| {
            install(libc::SIGINT, inline_handler as *const () as usize, 0);
            assert_eq!(sim.raise_signal(Signal::Interrupt), SignalDelivery::Handled);
            assert_eq!(
                INLINE.load(Ordering::SeqCst),
                1,
                "handled before raise returns"
            );
        });
        assert_eq!(
            signal_events(&sim),
            [(
                Signal::Interrupt,
                SignalOrigin::Sim,
                SignalDelivery::Handled
            )]
        );
    }

    static INFO: Mutex<Vec<(c_int, c_int, libc::pid_t)>> = Mutex::new(Vec::new());
    extern "C" fn info_handler(sig: c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
        assert!(!ctx.is_null());
        // SAFETY: the sim passes a valid siginfo.
        let info = unsafe { &*info };
        #[cfg(target_os = "linux")]
        // SAFETY: a kill-style siginfo carries the sender's pid.
        let pid = unsafe { info.si_pid() };
        #[cfg(target_os = "macos")]
        let pid = info.si_pid;
        assert_eq!(info.si_signo, sig);
        INFO.lock().unwrap().push((sig, info.si_code, pid));
    }

    #[test]
    fn siginfo_handler() {
        let sim = Sim::new();
        sim.run(|| {
            install(
                libc::SIGHUP,
                info_handler as *const () as usize,
                libc::SA_SIGINFO,
            );
            assert_eq!(sim.raise_signal(Signal::Hangup), SignalDelivery::Handled);
            // SAFETY: the handler only records.
            assert_eq!(unsafe { libc::raise(libc::SIGHUP) }, 0);
            // SAFETY: as above.
            assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGHUP) }, 0);
        });
        // SAFETY: no preconditions.
        let (pid, ppid) = unsafe { (libc::getpid(), libc::getppid()) };
        #[cfg(target_os = "linux")]
        let (user, tkill) = (libc::SI_USER, libc::SI_TKILL);
        // <sys/signal.h> (Darwin): SI_USER, for thread-directed signals too.
        #[cfg(target_os = "macos")]
        let (user, tkill) = (0x10001, 0x10001);
        assert_eq!(
            *INFO.lock().unwrap(),
            [
                (libc::SIGHUP, user, ppid),
                (libc::SIGHUP, tkill, pid),
                (libc::SIGHUP, user, pid)
            ]
        );
    }

    #[test]
    fn dispositions() {
        let sim = Sim::new();
        sim.run(|| {
            for signal in [
                Signal::Break,
                Signal::Close,
                Signal::Logoff,
                Signal::Shutdown,
            ] {
                assert_eq!(sim.raise_signal(signal), SignalDelivery::Unavailable);
            }
            install(libc::SIGTERM, libc::SIG_DFL, 0);
            assert_eq!(
                sim.raise_signal(Signal::Terminate),
                SignalDelivery::DefaultAction
            );
            install(libc::SIGTERM, libc::SIG_IGN, 0);
            assert_eq!(sim.raise_signal(Signal::Terminate), SignalDelivery::Ignored);
            assert_eq!(query(libc::SIGTERM).sa_sigaction, libc::SIG_IGN);
        });
        assert_eq!(
            signal_events(&sim),
            [
                (
                    Signal::Terminate,
                    SignalOrigin::Sim,
                    SignalDelivery::DefaultAction
                ),
                (
                    Signal::Terminate,
                    SignalOrigin::Sim,
                    SignalDelivery::Ignored
                )
            ]
        );
        assert_eq!(Signal::from_raw(libc::SIGINT), Some(Signal::Interrupt));
        assert_eq!(Signal::Hangup.raw(), Some(libc::SIGHUP));
        assert_eq!(Signal::from_raw(libc::SIGUSR1), None);
    }

    static DEPTH: AtomicUsize = AtomicUsize::new(0);
    static MAX_DEPTH: AtomicUsize = AtomicUsize::new(0);
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn reraising_handler(sig: c_int) {
        let depth = DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
        MAX_DEPTH.fetch_max(depth, Ordering::SeqCst);
        if CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
            // SAFETY: re-raises the signal being handled.
            unsafe { libc::raise(sig) };
        }
        DEPTH.fetch_sub(1, Ordering::SeqCst);
    }

    #[test]
    fn nodefer() {
        let sim = Sim::new();
        sim.run(|| {
            install(libc::SIGINT, reraising_handler as *const () as usize, 0);
            assert_eq!(sim.raise_signal(Signal::Interrupt), SignalDelivery::Handled);
            assert_eq!(CALLS.load(Ordering::SeqCst), 2);
            assert_eq!(
                MAX_DEPTH.load(Ordering::SeqCst),
                1,
                "deferred until the handler returns"
            );
            CALLS.store(0, Ordering::SeqCst);
            MAX_DEPTH.store(0, Ordering::SeqCst);
            install(
                libc::SIGINT,
                reraising_handler as *const () as usize,
                libc::SA_NODEFER,
            );
            assert_eq!(sim.raise_signal(Signal::Interrupt), SignalDelivery::Handled);
            assert_eq!(CALLS.load(Ordering::SeqCst), 2);
            assert_eq!(MAX_DEPTH.load(Ordering::SeqCst), 2, "SA_NODEFER nests");
            CALLS.store(0, Ordering::SeqCst);
            MAX_DEPTH.store(0, Ordering::SeqCst);
            install(
                libc::SIGINT,
                reraising_handler as *const () as usize,
                libc::SA_RESETHAND,
            );
            assert_eq!(sim.raise_signal(Signal::Interrupt), SignalDelivery::Handled);
            assert_eq!(
                CALLS.load(Ordering::SeqCst),
                1,
                "the re-raise meets SIG_DFL"
            );
            assert_eq!(query(libc::SIGINT).sa_sigaction, libc::SIG_DFL);
        });
    }

    #[test]
    fn process_raise_and_kill_self() {
        let sim = Sim::new();
        sim.run(|| {
            for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                install(sig, libc::SIG_DFL, 0);
            }
            // SAFETY: with the sim's default actions nothing ends the process.
            unsafe {
                assert_eq!(libc::raise(libc::SIGINT), 0);
                assert_eq!(libc::kill(libc::getpid(), libc::SIGTERM), 0);
                assert_eq!(libc::kill(0, libc::SIGHUP), 0);
                assert_eq!(libc::kill(libc::getpid(), 0), 0);
            }
        });
        assert_eq!(
            signal_events(&sim),
            [
                (
                    Signal::Interrupt,
                    SignalOrigin::Process,
                    SignalDelivery::DefaultAction
                ),
                (
                    Signal::Terminate,
                    SignalOrigin::Process,
                    SignalDelivery::DefaultAction
                ),
                (
                    Signal::Hangup,
                    SignalOrigin::Process,
                    SignalDelivery::DefaultAction
                )
            ]
        );
    }

    static HANDLED_ON: Mutex<Option<libc::pthread_t>> = Mutex::new(None);
    static TARGET_DONE: AtomicBool = AtomicBool::new(false);
    extern "C" fn thread_handler(_: c_int) {
        // SAFETY: no preconditions.
        *HANDLED_ON.lock().unwrap() = Some(unsafe { libc::pthread_self() });
        TARGET_DONE.store(true, Ordering::SeqCst);
    }

    #[test]
    fn pthread_kill_other_thread() {
        use std::os::unix::thread::JoinHandleExt;
        let sim = Sim::new();
        sim.run(|| {
            install(libc::SIGINT, thread_handler as *const () as usize, 0);
            let target = thread::spawn(|| {
                while !TARGET_DONE.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(1));
                }
            });
            let id = target.as_pthread_t();
            // SAFETY: the target thread is alive until the handler ran on it.
            assert_eq!(unsafe { libc::pthread_kill(id, libc::SIGINT) }, 0);
            target.join().unwrap();
            assert_eq!(
                *HANDLED_ON.lock().unwrap(),
                Some(id),
                "handled on the target thread"
            );
        });
        assert_eq!(
            signal_events(&sim),
            [(
                Signal::Interrupt,
                SignalOrigin::Process,
                SignalDelivery::Handled
            )]
        );
    }

    static A: AtomicUsize = AtomicUsize::new(0);
    static B: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn a_handler(_: c_int) {
        A.fetch_add(1, Ordering::SeqCst);
    }
    extern "C" fn b_handler(_: c_int) {
        B.fetch_add(1, Ordering::SeqCst);
    }

    pub(super) fn install_counter(which: usize) {
        let handler = if which == 0 {
            a_handler as *const () as usize
        } else {
            b_handler as *const () as usize
        };
        install(libc::SIGINT, handler, 0);
    }

    pub(super) fn counts() -> (usize, usize) {
        (A.load(Ordering::SeqCst), B.load(Ordering::SeqCst))
    }

    static UNMANAGED: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn unmanaged_handler(_: c_int) {
        UNMANAGED.fetch_add(1, Ordering::SeqCst);
    }

    pub(super) fn install_unmanaged_counter() {
        install(libc::SIGINT, unmanaged_handler as *const () as usize, 0);
    }

    pub(super) fn unmanaged_count() -> usize {
        UNMANAGED.load(Ordering::SeqCst)
    }

    static TIMED: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn timed_handler(_: c_int) {
        TIMED.fetch_add(1, Ordering::SeqCst);
    }

    pub(super) fn install_timed_counter() {
        install(libc::SIGINT, timed_handler as *const () as usize, 0);
    }

    pub(super) fn timed_count() -> usize {
        TIMED.load(Ordering::SeqCst)
    }

    pub(super) static GATED: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
    extern "C" fn gated_handler(_: c_int) {
        *GATED.0.lock().unwrap() = true;
        GATED.1.notify_all();
    }

    pub(super) fn install_gated() {
        install(libc::SIGINT, gated_handler as *const () as usize, 0);
    }
}

#[cfg(windows)]
mod win {
    use super::*;

    type Handler = unsafe extern "system" fn(u32) -> i32;

    unsafe extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<Handler>, add: i32) -> i32;
    }

    pub(super) fn add(handler: Handler) {
        // SAFETY: registers a handler with the sim's console table.
        assert_eq!(unsafe { SetConsoleCtrlHandler(Some(handler), 1) }, 1);
    }

    static A: AtomicUsize = AtomicUsize::new(0);
    static B: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "system" fn a_handler(_: u32) -> i32 {
        A.fetch_add(1, Ordering::SeqCst);
        1
    }
    unsafe extern "system" fn b_handler(_: u32) -> i32 {
        B.fetch_add(1, Ordering::SeqCst);
        1
    }

    pub(super) fn install_counter(which: usize) {
        add(if which == 0 { a_handler } else { b_handler });
    }

    pub(super) fn counts() -> (usize, usize) {
        (A.load(Ordering::SeqCst), B.load(Ordering::SeqCst))
    }

    static UNMANAGED: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "system" fn unmanaged_handler(_: u32) -> i32 {
        UNMANAGED.fetch_add(1, Ordering::SeqCst);
        1
    }

    pub(super) fn install_unmanaged_counter() {
        add(unmanaged_handler);
    }

    pub(super) fn unmanaged_count() -> usize {
        UNMANAGED.load(Ordering::SeqCst)
    }

    static TIMED: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "system" fn timed_handler(_: u32) -> i32 {
        TIMED.fetch_add(1, Ordering::SeqCst);
        1
    }

    pub(super) fn install_timed_counter() {
        add(timed_handler);
    }

    pub(super) fn timed_count() -> usize {
        TIMED.load(Ordering::SeqCst)
    }

    pub(super) static GATED: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());
    unsafe extern "system" fn gated_handler(_: u32) -> i32 {
        *GATED.0.lock().unwrap() = true;
        GATED.1.notify_all();
        1
    }

    pub(super) fn install_gated() {
        add(gated_handler);
    }
}

#[cfg(unix)]
use unix as os;
#[cfg(windows)]
use win as os;

#[test]
fn parallel_isolation() {
    let sims: Vec<Sim> = (0..2).map(|_| Sim::new()).collect();
    thread::scope(|scope| {
        for (which, sim) in sims.iter().enumerate() {
            scope.spawn(move || sim.run(|| os::install_counter(which)));
        }
    });
    let before = os::counts();
    assert_eq!(
        sims[0].raise_signal(Signal::Interrupt),
        SignalDelivery::Handled
    );
    let after = os::counts();
    assert_eq!(
        (after.0 - before.0, after.1 - before.1),
        (1, 0),
        "only the first sim's handler"
    );
    assert_eq!(
        sims[1].raise_signal(Signal::Interrupt),
        SignalDelivery::Handled
    );
    let last = os::counts();
    assert_eq!(
        (last.0 - after.0, last.1 - after.1),
        (0, 1),
        "only the second sim's handler"
    );
}

#[test]
fn raise_from_unmanaged_thread() {
    let sim = Sim::new();
    sim.run(os::install_unmanaged_counter);
    assert_eq!(
        sim.raise_signal(Signal::Interrupt),
        SignalDelivery::Handled,
        "after the run"
    );
    assert_eq!(os::unmanaged_count(), 1);
    let signals = sim.signals();
    sim.run(|| {
        let raiser = snare::real(|| thread::spawn(move || signals.raise(Signal::Interrupt)));
        while os::unmanaged_count() < 2 {
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            snare::real(|| raiser.join().unwrap()),
            SignalDelivery::Handled
        );
    });
    assert_eq!(
        signal_events(&sim),
        [
            (
                Signal::Interrupt,
                SignalOrigin::Sim,
                SignalDelivery::Handled
            ),
            (
                Signal::Interrupt,
                SignalOrigin::Sim,
                SignalDelivery::Handled
            )
        ]
    );
}

#[test]
fn raise_signal_after_virtual() {
    let sim = Sim::builder().deterministic().build();
    let signals = sim.signals();
    let (delivery, elapsed, real) = sim.run(|| {
        os::install_timed_counter();
        let real = snare::real(Instant::now);
        let start = Instant::now();
        let pending = signals.raise_after(Signal::Interrupt, Duration::from_secs(30));
        let delivery = pending.wait();
        (delivery, start.elapsed(), snare::real(|| real.elapsed()))
    });
    assert_eq!(delivery, SignalDelivery::Handled);
    assert!(os::timed_count() >= 1);
    assert!(
        elapsed >= Duration::from_secs(30) && elapsed < Duration::from_secs(31),
        "{elapsed:?}"
    );
    assert!(
        real < Duration::from_secs(10),
        "virtual, not real: {real:?}"
    );
    let at: Vec<Duration> = sim
        .recorded_events()
        .into_iter()
        .filter(|e| matches!(e.event, RecordedEvent::Signal { .. }))
        .map(|e| e.at)
        .collect();
    assert_eq!(at.len(), 1);
    assert!(at[0] >= Duration::from_secs(30), "{at:?}");
}

#[test]
fn signal_delivered_during_timestamp_is_gated() {
    use snare::sched::{self, BlockerKind, ExecutiveConfig};
    let t = Duration::from_millis(7);
    let sim = Sim::new();
    let signals = sim.signals();
    sim.run(|| {
        os::install_gated();
        let exec = sched::attach(ExecutiveConfig::default()).unwrap();
        sched::mark_driver_thread();
        let done = std::sync::Arc::new(AtomicBool::new(false));
        let waiter = {
            let done = done.clone();
            thread::spawn(move || {
                let mut raised = os::GATED.0.lock().unwrap();
                while !*raised {
                    raised = os::GATED.1.wait(raised).unwrap();
                }
                done.store(true, Ordering::SeqCst);
                sched::now()
            })
        };
        let in_cond_wait = |exec: &sched::Executive| {
            exec.participants()
                .iter()
                .any(|p| matches!(p.wait, Some("cond" | "futex" | "WaitOnAddress")))
        };
        let start = snare::real(Instant::now);
        loop {
            let q = exec.quiescence();
            if q.quiescent && q.blocked > 0 && in_cond_wait(&exec) {
                break;
            }
            assert!(snare::real(|| start.elapsed()) < Duration::from_secs(20));
            snare::real(|| thread::sleep(Duration::from_micros(200)));
        }
        exec.enter_timestamp(t);
        assert_eq!(signals.raise(Signal::Interrupt), SignalDelivery::Handled);
        let start = snare::real(Instant::now);
        loop {
            let q = exec.quiescence();
            if q.blocker
                .as_ref()
                .is_some_and(|(k, _)| *k == BlockerKind::Deferred)
            {
                break;
            }
            assert!(
                snare::real(|| start.elapsed()) < Duration::from_secs(10),
                "{q:?}"
            );
            snare::real(|| thread::sleep(Duration::from_millis(1)));
        }
        snare::real(|| thread::sleep(Duration::from_millis(50)));
        assert!(
            !done.load(Ordering::SeqCst),
            "the waiter waits for the timestamp to end"
        );
        exec.leave_timestamp(t);
        assert_eq!(waiter.join().unwrap(), t);
    });
}
