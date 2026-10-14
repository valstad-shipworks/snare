//! `SIGCHLD` for the children a sim's threads make, against the host: the same program run on the
//! real OS and in a sim must see one `SIGCHLD` per child, with the `siginfo_t` the kernel fills
//! (`si_pid`, `si_code`, `si_status`), and the child's end must interrupt a `sigsuspend` alike.
#![cfg(unix)]

use std::ffi::c_int;
use std::process::Command;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use snare::{RecordedEvent, Signal, SignalDelivery, SignalOrigin, Sim};

fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

static CALLS: AtomicUsize = AtomicUsize::new(0);
static PID: AtomicI32 = AtomicI32::new(0);
static CODE: AtomicI32 = AtomicI32::new(0);
static STATUS: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_child(_: c_int, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    CALLS.fetch_add(1, Ordering::SeqCst);
    // SAFETY: the siginfo the kernel, or the sim, passed.
    unsafe {
        PID.store((*info).si_pid(), Ordering::SeqCst);
        CODE.store((*info).si_code, Ordering::SeqCst);
        STATUS.store((*info).si_status(), Ordering::SeqCst);
    }
}

fn install(handler: libc::sighandler_t, flags: c_int) -> libc::sigaction {
    // SAFETY: an all-zero sigaction is valid; the calls fill the mask and read the old action.
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = handler;
        act.sa_flags = flags;
        libc::sigemptyset(&mut act.sa_mask);
        let mut old: libc::sigaction = std::mem::zeroed();
        assert_eq!(libc::sigaction(libc::SIGCHLD, &act, &mut old), 0);
        old
    }
}

fn restore(old: &libc::sigaction) {
    // SAFETY: putting back an action `install` read.
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGCHLD, old, std::ptr::null_mut()) },
        0
    );
}

/// What one child's end showed the handler: how often it ran, and whether the `siginfo_t` named
/// the child, with its `si_code` and `si_status`.
type Seen = (usize, bool, c_int, c_int);

/// Runs `script` in `sh` as a child, waits for it, then gives a second `SIGCHLD` time to arrive.
fn child_end(script: &str, flags: c_int) -> Seen {
    let before = CALLS.load(Ordering::SeqCst);
    let old = install(on_child as *const () as libc::sighandler_t, flags);
    let mut child = Command::new("sh").arg("-c").arg(script).spawn().unwrap();
    let pid = child.id() as i32;
    child.wait().unwrap();
    for _ in 0..100 {
        if CALLS.load(Ordering::SeqCst) > before {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    snare::real(|| std::thread::sleep(Duration::from_millis(200)));
    std::thread::sleep(Duration::from_millis(200));
    restore(&old);
    (
        CALLS.load(Ordering::SeqCst) - before,
        PID.load(Ordering::SeqCst) == pid,
        CODE.load(Ordering::SeqCst),
        STATUS.load(Ordering::SeqCst),
    )
}

fn ends() -> Vec<Seen> {
    vec![
        child_end("exit 3", libc::SA_SIGINFO | libc::SA_RESTART),
        child_end("kill -TERM $$", libc::SA_SIGINFO),
        child_end("sleep 0.1; exit 0", libc::SA_SIGINFO | libc::SA_RESTART),
    ]
}

#[test]
fn one_sigchld_per_child_as_on_the_host() {
    let _serial = serial();
    let host = ends();
    assert_eq!(
        host,
        [
            (1, true, libc::CLD_EXITED, 3),
            (1, true, libc::CLD_KILLED, libc::SIGTERM),
            (1, true, libc::CLD_EXITED, 0),
        ]
    );
    for sim in [Sim::new(), Sim::builder().deterministic().build()] {
        assert_eq!(sim.run(ends), host);
        let children: Vec<_> = sim
            .recorded_events()
            .into_iter()
            .filter_map(|entry| match entry.event {
                RecordedEvent::Signal {
                    signal: Signal::Child,
                    origin,
                    delivery,
                } => Some((origin, delivery)),
                _ => None,
            })
            .collect();
        assert_eq!(
            children,
            [(SignalOrigin::Child, SignalDelivery::Handled); 3],
            "one recorded delivery per child"
        );
    }
}

static SUSPENDED: AtomicUsize = AtomicUsize::new(0);

extern "C" fn count_suspended(_: c_int) {
    SUSPENDED.fetch_add(1, Ordering::SeqCst);
}

/// `sigsuspend` until a child ends, as a shell waits for its jobs: `(return, errno, handler
/// runs)`.
fn suspend_for_child() -> (c_int, c_int, usize) {
    let before = SUSPENDED.load(Ordering::SeqCst);
    let old = install(count_suspended as *const () as libc::sighandler_t, 0);
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("sleep 0.1")
        .spawn()
        .unwrap();
    // SAFETY: an empty mask.
    let (r, e) = unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        let r = libc::sigsuspend(&mask);
        (r, std::io::Error::last_os_error().raw_os_error().unwrap())
    };
    child.wait().unwrap();
    restore(&old);
    (r, e, SUSPENDED.load(Ordering::SeqCst) - before)
}

/// The kernel gives a process its `SIGCHLD` on the main thread, which the test harness keeps
/// apart, so the host's answer is the one man 2 sigsuspend gives for the thread that gets it; in
/// the sim the root thread stands for the main thread.
#[test]
fn a_child_ending_ends_sigsuspend_on_the_root_thread() {
    let _serial = serial();
    for sim in [Sim::new(), Sim::builder().deterministic().build()] {
        assert_eq!(sim.run(suspend_for_child), (-1, libc::EINTR, 1));
    }
}

/// Spawns `sh -c true` with `posix_spawn`, which std's `Child` would otherwise reap itself, and
/// returns what `waitpid` on it says once it has had time to end: `(return, errno)`, the return
/// normalised to 1 for the child's pid.
fn spawn_and_reap(ignore: bool) -> (c_int, c_int) {
    let old = install(if ignore { libc::SIG_IGN } else { libc::SIG_DFL }, 0);
    let mut pid = 0;
    let argv = [
        c"sh".as_ptr(),
        c"-c".as_ptr(),
        c"true".as_ptr(),
        std::ptr::null(),
    ];
    // SAFETY: a NUL-terminated argv and the process's environment.
    let made = unsafe {
        unsafe extern "C" {
            static environ: *const *const libc::c_char;
        }
        libc::posix_spawnp(
            &mut pid,
            c"sh".as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr().cast(),
            environ.cast(),
        )
    };
    assert_eq!(made, 0);
    snare::real(|| std::thread::sleep(Duration::from_millis(300)));
    std::thread::sleep(Duration::from_millis(300));
    let mut status = 0;
    // SAFETY: a place for the status.
    let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    let e = if r < 0 {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    } else {
        0
    };
    restore(&old);
    (if r == pid { 1 } else { r }, e)
}

#[test]
fn an_ignored_sigchld_reaps_children_as_on_the_host() {
    let _serial = serial();
    let host = (spawn_and_reap(true), spawn_and_reap(false));
    assert_eq!(host, ((-1, libc::ECHILD), (1, 0)));
    for sim in [Sim::new(), Sim::builder().deterministic().build()] {
        let seen = sim.run(|| (spawn_and_reap(true), spawn_and_reap(false)));
        assert_eq!(seen, host);
    }
}
