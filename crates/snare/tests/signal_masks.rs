//! Signal masks, pending signals and the calls that take them (`pthread_sigmask`, `sigprocmask`,
//! `sigpending`, `sigsuspend`, `sigwait`, and on Linux `sigwaitinfo`, `sigtimedwait` and
//! `signalfd`), against the host: each scenario runs on the real OS and then in a sim, plain and
//! deterministic, and must see the same.
//!
//! A signal sent to the process goes to whichever of its threads does not block it, so this test
//! has no harness (`harness = false`): its own main thread blocks the simulated signals before
//! anything else runs, every thread started after inherits that, and a signal sent to the process
//! reaches only a thread a scenario unblocks it on. A sim's first thread starts with the same mask,
//! as a program starts with the mask it was executed with. The main thread is also the one macOS
//! leaves a signal every thread blocks pending for, and the sim's root thread stands in for it.

fn main() {
    #[cfg(unix)]
    unix::main();
}

#[cfg(unix)]
mod unix {
    use std::ffi::c_int;
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use std::time::Duration;
    #[cfg(target_os = "linux")]
    use std::time::Instant;

    use snare::Sim;

    const SIMULATED: [c_int; 4] = [libc::SIGHUP, libc::SIGINT, libc::SIGTERM, libc::SIGCHLD];

    type Trace = Vec<String>;

    type Scenario = (&'static str, fn() -> Trace);

    pub(super) fn main() {
        block(&SIMULATED);
        let filters = filters();
        let scenarios: Vec<Scenario> = vec![
            ("unblock_order", unblock_order),
            ("ignored_while_blocked", ignored_while_blocked),
            ("masks", masks),
            ("sigsuspend", sigsuspend),
            ("to_the_unblocking_thread", to_the_unblocking_thread),
            ("pending_then_unblocked", pending_then_unblocked),
            ("sigwait", sigwait),
            ("child_sigwait", child_sigwait),
            #[cfg(target_os = "linux")]
            ("sigtimedwait", sigtimedwait),
            #[cfg(target_os = "linux")]
            ("signalfd", signalfd),
            #[cfg(target_os = "linux")]
            ("signalfd_waits", signalfd_waits),
        ];
        let mut ran = 0;
        for (name, scenario) in scenarios {
            if !filters.is_empty() && !filters.iter().any(|f| name.contains(f.as_str())) {
                continue;
            }
            take_real_sigchld();
            let host = scenario();
            assert_eq!(pending(), Vec::<c_int>::new(), "{name}: left pending");
            let sim = Sim::new().run(scenario);
            assert_eq!(sim, host, "{name}: sim against the host");
            let det = Sim::builder().deterministic().build().run(scenario);
            assert_eq!(det, host, "{name}: deterministic sim against the host");
            println!("test {name} ... ok");
            ran += 1;
        }
        println!("\ntest result: ok. {ran} passed; 0 failed");
    }

    /// Takes a real `SIGCHLD` left pending for the process: the kernel's for a child a sim made,
    /// which every thread here blocks, so the sim's stand-in for it never sees it.
    fn take_real_sigchld() {
        if pending().contains(&libc::SIGCHLD) {
            let set = set_of(&[libc::SIGCHLD]);
            let mut sig = 0;
            // SAFETY: a valid set and an int to fill; the signal is pending, so it returns at once.
            assert_eq!(unsafe { libc::sigwait(&set, &mut sig) }, 0);
        }
    }

    /// The names to run, from the command line, leaving out libtest's flags and their values.
    fn filters() -> Vec<String> {
        let mut args = std::env::args().skip(1);
        let mut names = Vec::new();
        while let Some(arg) = args.next() {
            if arg == "--skip" || arg == "--test-threads" {
                args.next();
            } else if !arg.starts_with('-') {
                names.push(arg);
            }
        }
        names
    }

    fn errno() -> c_int {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    }

    fn set_of(sigs: &[c_int]) -> libc::sigset_t {
        // SAFETY: an all-zero sigset_t is valid; the calls only fill it.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for &sig in sigs {
                libc::sigaddset(&mut set, sig);
            }
            set
        }
    }

    fn change(how: c_int, sigs: &[c_int]) {
        let set = set_of(sigs);
        // SAFETY: a valid set; no old set wanted.
        assert_eq!(
            unsafe { libc::pthread_sigmask(how, &set, std::ptr::null_mut()) },
            0
        );
    }

    fn block(sigs: &[c_int]) {
        change(libc::SIG_BLOCK, sigs);
    }

    fn unblock(sigs: &[c_int]) {
        change(libc::SIG_UNBLOCK, sigs);
    }

    fn members(set: &libc::sigset_t, sigs: &[c_int]) -> Vec<c_int> {
        sigs.iter()
            .copied()
            // SAFETY: a valid set and signal.
            .filter(|&sig| unsafe { libc::sigismember(set, sig) } == 1)
            .collect()
    }

    fn blocked() -> Vec<c_int> {
        // SAFETY: an all-zero sigset_t is valid; a null new set only reads.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut set) },
            0
        );
        members(
            &set,
            &[
                libc::SIGHUP,
                libc::SIGINT,
                libc::SIGTERM,
                libc::SIGCHLD,
                libc::SIGUSR1,
            ],
        )
    }

    fn pending() -> Vec<c_int> {
        // SAFETY: an all-zero sigset_t is valid; sigpending fills it.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::sigpending(&mut set) }, 0);
        members(&set, &SIMULATED)
    }

    fn name(sig: c_int) -> &'static str {
        match sig {
            libc::SIGHUP => "HUP",
            libc::SIGINT => "INT",
            libc::SIGTERM => "TERM",
            libc::SIGCHLD => "CHLD",
            _ => "?",
        }
    }

    static NOTES: [AtomicI32; 16] = [const { AtomicI32::new(0) }; 16];
    static NOTED: AtomicUsize = AtomicUsize::new(0);
    static WHO: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn note(sig: c_int) {
        let at = NOTED.fetch_add(1, Ordering::SeqCst);
        if let Some(slot) = NOTES.get(at) {
            slot.store(sig, Ordering::SeqCst);
        }
        // SAFETY: pthread_self has no preconditions.
        WHO.store(unsafe { libc::pthread_self() } as usize, Ordering::SeqCst);
    }

    /// The signals handled since the last call, in the order their handlers ran.
    fn notes() -> String {
        let n = NOTED.swap(0, Ordering::SeqCst).min(NOTES.len());
        NOTES[..n]
            .iter()
            .map(|s| name(s.load(Ordering::SeqCst)))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn me() -> usize {
        // SAFETY: pthread_self has no preconditions.
        unsafe { libc::pthread_self() as usize }
    }

    /// Installs `handler` (an address, `SIG_DFL` or `SIG_IGN`) for `sig`, returning the action
    /// it replaces.
    fn install(sig: c_int, handler: usize, flags: c_int) -> libc::sigaction {
        // SAFETY: an all-zero sigaction is valid; the calls fill the mask and read the old one.
        unsafe {
            let mut act: libc::sigaction = std::mem::zeroed();
            act.sa_sigaction = handler;
            act.sa_flags = flags;
            libc::sigemptyset(&mut act.sa_mask);
            let mut old: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(sig, &act, &mut old), 0);
            old
        }
    }

    fn noting(sig: c_int, flags: c_int) -> libc::sigaction {
        install(sig, note as *const () as usize, flags)
    }

    fn restore(sig: c_int, old: &libc::sigaction) {
        // SAFETY: an action `install` read.
        assert_eq!(
            unsafe { libc::sigaction(sig, old, std::ptr::null_mut()) },
            0
        );
    }

    fn raise(sig: c_int) {
        // SAFETY: a valid signal.
        assert_eq!(unsafe { libc::raise(sig) }, 0);
    }

    fn kill(sig: c_int) {
        // SAFETY: a valid signal to this process.
        assert_eq!(unsafe { libc::kill(libc::getpid(), sig) }, 0);
    }

    fn pthread_kill(thread: usize, sig: c_int) {
        // SAFETY: a thread of this process that is still running.
        assert_eq!(
            unsafe { libc::pthread_kill(thread as libc::pthread_t, sig) },
            0
        );
    }

    fn sleep_ms(ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }

    /// Pending signals a mask change lets through run highest number first, each handler's frame
    /// set up over the last, the thread's own taken before the process's on Linux.
    fn unblock_order() -> Trace {
        let mut trace = Trace::new();
        let three = [libc::SIGHUP, libc::SIGINT, libc::SIGTERM];
        let olds = three.map(|sig| noting(sig, 0));
        raise(libc::SIGTERM);
        raise(libc::SIGHUP);
        raise(libc::SIGINT);
        trace.push(format!("pending {:?}", pending()));
        unblock(&three);
        trace.push(format!("raised {}", notes()));
        block(&three);
        kill(libc::SIGTERM);
        kill(libc::SIGHUP);
        raise(libc::SIGINT);
        trace.push(format!("pending {:?}", pending()));
        unblock(&three);
        trace.push(format!("raised and sent {}", notes()));
        block(&three);
        for (sig, old) in three.iter().zip(&olds) {
            restore(*sig, old);
        }
        trace
    }

    /// An ignored signal sent while blocked: Linux keeps it pending, macOS discards it; making it
    /// ignored discards one pending.
    fn ignored_while_blocked() -> Trace {
        let mut trace = Trace::new();
        let old = install(libc::SIGINT, libc::SIG_IGN, 0);
        raise(libc::SIGINT);
        trace.push(format!("raised {:?}", pending()));
        kill(libc::SIGINT);
        trace.push(format!("sent {:?}", pending()));
        install(libc::SIGINT, libc::SIG_DFL, 0);
        trace.push(format!("default {:?}", pending()));
        install(libc::SIGINT, libc::SIG_IGN, 0);
        trace.push(format!("ignored again {:?}", pending()));
        restore(libc::SIGINT, &old);
        let old = install(libc::SIGCHLD, libc::SIG_DFL, 0);
        kill(libc::SIGCHLD);
        trace.push(format!("child default {:?}", pending()));
        noting(libc::SIGCHLD, 0);
        kill(libc::SIGCHLD);
        trace.push(format!("child handled {:?}", pending()));
        install(libc::SIGCHLD, libc::SIG_DFL, 0);
        trace.push(format!("child back to default {:?}", pending()));
        restore(libc::SIGCHLD, &old);
        trace.push(format!("handled {}", notes()));
        trace
    }

    /// What the mask calls report and reject, and what a new thread inherits.
    fn masks() -> Trace {
        let mut trace = Trace::new();
        trace.push(format!("start {:?}", blocked()));
        unblock(&[libc::SIGINT]);
        trace.push(format!("unblocked {:?}", blocked()));
        let inherited = std::thread::spawn(blocked).join().unwrap();
        trace.push(format!("a new thread {inherited:?}"));
        let set = set_of(&[libc::SIGINT, libc::SIGUSR1]);
        // SAFETY: an all-zero sigset_t is valid; plain mask calls.
        let mut old: libc::sigset_t = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::sigprocmask(libc::SIG_BLOCK, &set, &mut old) };
        trace.push(format!(
            "sigprocmask {r} old {:?}",
            members(&old, &[libc::SIGHUP, libc::SIGINT, libc::SIGUSR1])
        ));
        trace.push(format!("now {:?}", blocked()));
        let r = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &set_of(&SIMULATED), &mut old) };
        trace.push(format!(
            "setmask {r} old {:?} now {:?}",
            members(&old, &[libc::SIGINT, libc::SIGUSR1]),
            blocked()
        ));
        let r = unsafe { libc::pthread_sigmask(99, &set, std::ptr::null_mut()) };
        trace.push(format!("bad how {r}"));
        let r = unsafe { libc::pthread_sigmask(99, std::ptr::null(), &mut old) };
        trace.push(format!("bad how, no set {r}"));
        let r = unsafe { libc::sigprocmask(99, &set, std::ptr::null_mut()) };
        trace.push(format!("sigprocmask bad how {r} {}", errno()));
        trace.push(format!("end {:?}", blocked()));
        trace
    }

    /// `sigsuspend` takes a pending signal its mask lets through, or waits for one sent to the
    /// process, and puts the mask back.
    fn sigsuspend() -> Trace {
        let mut trace = Trace::new();
        let int = noting(libc::SIGINT, 0);
        let hup = noting(libc::SIGHUP, 0);
        raise(libc::SIGINT);
        let empty = set_of(&[]);
        // SAFETY: a valid set.
        let r = unsafe { libc::sigsuspend(&empty) };
        trace.push(format!("pending {r} {} {}", errno(), notes()));
        trace.push(format!("mask {:?}", blocked()));
        raise(libc::SIGINT);
        let sender = std::thread::spawn(|| {
            sleep_ms(50);
            kill(libc::SIGHUP);
        });
        let only_int = set_of(&[libc::SIGINT]);
        // SAFETY: a valid set.
        let r = unsafe { libc::sigsuspend(&only_int) };
        trace.push(format!("sent {r} {} {}", errno(), notes()));
        sender.join().unwrap();
        trace.push(format!("still pending {:?}", pending()));
        unblock(&[libc::SIGINT]);
        trace.push(format!("unblocked {}", notes()));
        block(&[libc::SIGINT]);
        restore(libc::SIGINT, &int);
        restore(libc::SIGHUP, &hup);
        trace
    }

    /// A signal sent to the process while every thread but one blocks it runs on that one,
    /// interrupting its `pause`.
    fn to_the_unblocking_thread() -> Trace {
        let mut trace = Trace::new();
        let old = noting(libc::SIGHUP, 0);
        let worker = std::thread::spawn(|| {
            unblock(&[libc::SIGHUP]);
            // SAFETY: no arguments.
            let r = unsafe { libc::pause() };
            (r, errno(), me())
        });
        sleep_ms(50);
        kill(libc::SIGHUP);
        let (r, e, worker) = worker.join().unwrap();
        trace.push(format!(
            "pause {r} {e}, ran {} on the worker {}",
            notes(),
            WHO.load(Ordering::SeqCst) == worker
        ));
        restore(libc::SIGHUP, &old);
        trace
    }

    /// A signal sent to the process while every thread blocks it, then unblocked by another
    /// thread: Linux runs it there, macOS keeps it for the main thread.
    fn pending_then_unblocked() -> Trace {
        let mut trace = Trace::new();
        let old = noting(libc::SIGHUP, 0);
        WHO.store(0, Ordering::SeqCst);
        kill(libc::SIGHUP);
        trace.push(format!("pending {:?}", pending()));
        let worker = std::thread::spawn(|| {
            unblock(&[libc::SIGHUP]);
            sleep_ms(20);
            me()
        })
        .join()
        .unwrap();
        trace.push(format!(
            "after the worker {} on it {}",
            notes(),
            WHO.load(Ordering::SeqCst) == worker
        ));
        unblock(&[libc::SIGHUP]);
        trace.push(format!(
            "after the main thread {} on it {}",
            notes(),
            WHO.load(Ordering::SeqCst) == me()
        ));
        block(&[libc::SIGHUP]);
        restore(libc::SIGHUP, &old);
        trace
    }

    fn wait_one(sigs: &[c_int]) -> (c_int, c_int) {
        let set = set_of(sigs);
        let mut sig = 0;
        // SAFETY: a valid set and an int to fill.
        let r = unsafe { libc::sigwait(&set, &mut sig) };
        (r, sig)
    }

    /// `sigwait` takes a pending signal at once, waits for one sent to the process, and goes on
    /// waiting through a handler of another signal.
    fn sigwait() -> Trace {
        let mut trace = Trace::new();
        let int = noting(libc::SIGINT, 0);
        let term = noting(libc::SIGTERM, 0);
        raise(libc::SIGTERM);
        trace.push(format!(
            "pending {:?}",
            wait_one(&[libc::SIGTERM, libc::SIGHUP])
        ));
        let sender = std::thread::spawn(|| {
            sleep_ms(50);
            kill(libc::SIGTERM);
        });
        trace.push(format!("sent {:?}", wait_one(&[libc::SIGTERM])));
        sender.join().unwrap();
        unblock(&[libc::SIGINT]);
        let main = me();
        let sender = std::thread::spawn(move || {
            sleep_ms(50);
            pthread_kill(main, libc::SIGINT);
            sleep_ms(50);
            kill(libc::SIGTERM);
        });
        trace.push(format!(
            "through a handler {:?}",
            wait_one(&[libc::SIGTERM])
        ));
        sender.join().unwrap();
        block(&[libc::SIGINT]);
        trace.push(format!("handled {}", notes()));
        restore(libc::SIGINT, &int);
        restore(libc::SIGTERM, &term);
        trace
    }

    /// A child's `SIGCHLD`, blocked and handled, goes to `sigwait` rather than the handler.
    fn child_sigwait() -> Trace {
        let mut trace = Trace::new();
        let old = noting(libc::SIGCHLD, 0);
        let mut child = std::process::Command::new("true").spawn().unwrap();
        trace.push(format!("waited {:?}", wait_one(&[libc::SIGCHLD])));
        trace.push(format!("exited {}", child.wait().unwrap().success()));
        trace.push(format!("handled {:?}", notes()));
        restore(libc::SIGCHLD, &old);
        trace
    }

    #[cfg(target_os = "linux")]
    fn timed(
        sigs: &[c_int],
        timeout: Option<Duration>,
    ) -> (c_int, c_int, Option<(c_int, bool, c_int)>) {
        let set = set_of(sigs);
        let ts = timeout.map(|t| libc::timespec {
            tv_sec: t.as_secs() as _,
            tv_nsec: t.subsec_nanos() as _,
        });
        // SAFETY: an all-zero siginfo_t is valid; the call fills it.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::sigtimedwait(
                &set,
                &mut info,
                ts.as_ref().map_or(std::ptr::null(), std::ptr::from_ref),
            )
        };
        if r < 0 {
            return (r, errno(), None);
        }
        // SAFETY: filled for a signal sent with kill or for a child, both with a pid.
        let pid = unsafe { info.si_pid() };
        (
            r,
            0,
            Some((
                info.si_code,
                pid == std::process::id() as c_int,
                info.si_signo,
            )),
        )
    }

    /// `sigtimedwait` and `sigwaitinfo`: timeouts on the sim's clock, interruption whatever the
    /// handler's flags, and the `siginfo_t` they fill.
    #[cfg(target_os = "linux")]
    fn sigtimedwait() -> Trace {
        let mut trace = Trace::new();
        let int = noting(libc::SIGINT, 0);
        trace.push(format!(
            "zero {:?}",
            timed(&[libc::SIGTERM], Some(Duration::ZERO))
        ));
        let start = Instant::now();
        trace.push(format!(
            "timeout {:?}",
            timed(&[libc::SIGTERM], Some(Duration::from_millis(200)))
        ));
        trace.push(format!(
            "waited it out {}",
            start.elapsed() >= Duration::from_millis(200)
        ));
        let bad = libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000_000,
        };
        let set = set_of(&[libc::SIGTERM]);
        // SAFETY: a valid set and timespec.
        let r = unsafe { libc::sigtimedwait(&set, std::ptr::null_mut(), &bad) };
        trace.push(format!("bad timeout {r} {}", errno()));
        raise(libc::SIGTERM);
        trace.push(format!("raised {:?}", timed(&[libc::SIGTERM], None)));
        kill(libc::SIGTERM);
        trace.push(format!(
            "sent {:?}",
            timed(&[libc::SIGTERM], Some(Duration::from_secs(5)))
        ));
        unblock(&[libc::SIGINT]);
        for restart in [false, true] {
            noting(libc::SIGINT, if restart { libc::SA_RESTART } else { 0 });
            let main = me();
            let sender = std::thread::spawn(move || {
                sleep_ms(50);
                pthread_kill(main, libc::SIGINT);
            });
            trace.push(format!(
                "interrupted, SA_RESTART {restart}: {:?} {}",
                timed(&[libc::SIGTERM], Some(Duration::from_secs(5))),
                notes()
            ));
            sender.join().unwrap();
        }
        block(&[libc::SIGINT]);
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id() as c_int;
        let set = set_of(&[libc::SIGCHLD]);
        // SAFETY: as above.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::sigwaitinfo(&set, &mut info) };
        // SAFETY: filled for a child's end.
        let (from, status) = unsafe { (info.si_pid(), info.si_status()) };
        trace.push(format!(
            "child by default {r} code {} from it {} status {status}",
            info.si_code,
            from == pid
        ));
        child.wait().unwrap();
        restore(libc::SIGINT, &int);
        trace
    }

    #[cfg(target_os = "linux")]
    fn read_info(fd: c_int, room: usize) -> (isize, c_int, Vec<(u32, i32, bool)>) {
        // SAFETY: all-zero is a valid signalfd_siginfo.
        let mut infos: [libc::signalfd_siginfo; 4] = unsafe { std::mem::zeroed() };
        let len = room.min(size_of_val(&infos));
        // SAFETY: `len` bytes of `infos`.
        let r = unsafe { libc::read(fd, infos.as_mut_ptr().cast(), len) };
        if r < 0 {
            return (r, errno(), Vec::new());
        }
        let n = r as usize / size_of::<libc::signalfd_siginfo>();
        let own = std::process::id();
        (
            r,
            0,
            infos[..n]
                .iter()
                .map(|i| (i.ssi_signo, i.ssi_code, i.ssi_pid == own))
                .collect(),
        )
    }

    #[cfg(target_os = "linux")]
    fn readable(fd: c_int) -> (c_int, i16) {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one pollfd.
        let r = unsafe { libc::poll(&mut pfd, 1, 0) };
        (r, pfd.revents)
    }

    /// A `signalfd`: what a read takes and rejects, its readiness, and changing its set.
    #[cfg(target_os = "linux")]
    fn signalfd() -> Trace {
        let mut trace = Trace::new();
        let term = set_of(&[libc::SIGTERM]);
        // SAFETY: a valid set.
        let fd = unsafe { libc::signalfd(-1, &term, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
        assert!(fd >= 0, "{}", errno());
        trace.push(format!("flags {:#x}", unsafe {
            libc::fcntl(fd, libc::F_GETFL)
        }));
        trace.push(format!("cloexec {}", unsafe {
            libc::fcntl(fd, libc::F_GETFD)
        }));
        trace.push(format!("empty {:?} {:?}", read_info(fd, 128), readable(fd)));
        trace.push(format!("short {:?}", read_info(fd, 10)));
        raise(libc::SIGTERM);
        trace.push(format!(
            "raised {:?} short {:?}",
            readable(fd),
            read_info(fd, 10)
        ));
        trace.push(format!("read {:?}", read_info(fd, 128)));
        let three = set_of(&[libc::SIGHUP, libc::SIGINT, libc::SIGTERM]);
        // SAFETY: a valid set; a signalfd of this process.
        let r = unsafe { libc::signalfd(fd, &three, 0) };
        trace.push(format!("changed {}", r == fd));
        let r = unsafe { libc::signalfd(fd, &three, 0x4000_0000) };
        trace.push(format!("bad flags on it {r} {}", errno()));
        let r = unsafe { libc::signalfd(-1, &three, 0x4000_0000) };
        trace.push(format!("bad flags {r} {}", errno()));
        let r = unsafe { libc::signalfd(0, &three, 0) };
        trace.push(format!("not one {r} {}", errno()));
        let r = unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
        trace.push(format!("write {r} {}", errno()));
        kill(libc::SIGINT);
        raise(libc::SIGHUP);
        trace.push(format!("pending {:?}", pending()));
        trace.push(format!("read two {:?}", read_info(fd, 512)));
        trace.push(format!("pending {:?}", pending()));
        // SAFETY: closing the descriptor made above.
        unsafe { libc::close(fd) };
        trace
    }

    /// A `signalfd` in `epoll`, a blocking read a signal sent from another thread ends, and one
    /// a handler of another signal interrupts.
    #[cfg(target_os = "linux")]
    fn signalfd_waits() -> Trace {
        let mut trace = Trace::new();
        let int = noting(libc::SIGINT, 0);
        let term = set_of(&[libc::SIGTERM]);
        // SAFETY: plain descriptor calls.
        let fd = unsafe { libc::signalfd(-1, &term, libc::SFD_CLOEXEC) };
        assert!(fd >= 0, "{}", errno());
        let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        let mut event = libc::epoll_event {
            events: (libc::EPOLLIN | libc::EPOLLET) as u32,
            u64: 7,
        };
        assert_eq!(
            unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut event) },
            0
        );
        let wait = |ms| {
            let mut events = [libc::epoll_event { events: 0, u64: 0 }; 2];
            // SAFETY: room for two events.
            let r = unsafe { libc::epoll_wait(ep, events.as_mut_ptr(), 2, ms) };
            let first = events[0];
            (
                r,
                if r > 0 {
                    (first.events, first.u64)
                } else {
                    (0, 0)
                },
            )
        };
        trace.push(format!("idle {:?}", wait(0)));
        let sender = std::thread::spawn(|| {
            sleep_ms(50);
            kill(libc::SIGTERM);
        });
        trace.push(format!("sent {:?}", wait(5_000)));
        trace.push(format!("edge spent {:?}", wait(0)));
        trace.push(format!("read {:?}", read_info(fd, 128)));
        sender.join().unwrap();
        let sender = std::thread::spawn(|| {
            sleep_ms(50);
            kill(libc::SIGTERM);
        });
        trace.push(format!("blocking read {:?}", read_info(fd, 128)));
        sender.join().unwrap();
        unblock(&[libc::SIGINT]);
        for restart in [false, true] {
            noting(libc::SIGINT, if restart { libc::SA_RESTART } else { 0 });
            let main = me();
            let sender = std::thread::spawn(move || {
                sleep_ms(50);
                pthread_kill(main, libc::SIGINT);
                sleep_ms(50);
                kill(libc::SIGTERM);
            });
            trace.push(format!(
                "interrupted, SA_RESTART {restart}: {:?} {}",
                read_info(fd, 128),
                notes()
            ));
            sender.join().unwrap();
            if !restart {
                trace.push(format!("then {:?}", read_info(fd, 128)));
            }
        }
        block(&[libc::SIGINT]);
        // SAFETY: closing the descriptors made above.
        unsafe {
            libc::close(ep);
            libc::close(fd);
        }
        restore(libc::SIGINT, &int);
        trace
    }
}
