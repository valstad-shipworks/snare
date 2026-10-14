//! Per-domain signal dispositions, masks and pending signals. A domain built with a [`Signals`]
//! table keeps its own idea of how each virtual signal is handled: the code under test installs
//! handlers with the OS's own calls (`sigaction`, `signal`, `SetConsoleCtrlHandler`), blocks them
//! with `pthread_sigmask` and `sigprocmask`, and takes them with `sigwait` and `signalfd`; the real
//! process's dispositions and masks stay untouched, and a signal raised inside the domain is
//! delivered from the table as the host OS would deliver it.
//!
//! The table itself lives in the sim (`snare::signals`), behind the [`Signals`] trait; this module
//! holds the delivery side that has to run on the calling thread: which signals are virtual, each
//! thread's mask and the signals pending for it or its process ([`State`]), which thread a signal
//! sent to the process goes to, and calling a handler with the arguments the kernel would pass.
//! The hooks that feed it are in `os::signal_hooks` (unix) and `os::windows` (console control and
//! the CRT).
//!
//! Every [`Signals`] method is called with the thread in passthrough, so the table may lock and
//! allocate without re-entering the hooks; a handler of the code under test is called through
//! [`simulated`], so its own OS calls reach the domain again.

#[cfg(unix)]
use std::cell::Cell;
use std::ffi::c_int;
#[cfg(unix)]
use std::sync::Mutex;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::state::Passthrough;

/// Who sent a signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignalSource {
    /// The sim, on the test's behalf.
    Sim,
    /// The code under test itself: `raise`, `kill` of its own process, `pthread_kill`,
    /// `GenerateConsoleCtrlEvent`.
    Process,
    /// A real signal the process received, forwarded into the domain.
    Real,
    /// A child process a thread of the domain made has ended.
    Child,
}

/// What delivering a signal did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignalOutcome {
    /// A handler of the code under test ran.
    Handled,
    /// A handler ran, after which the OS would end the process (a Windows close, logoff or
    /// shutdown event).
    HandledThenExit,
    /// The OS default action applies; the domain never carries it out.
    DefaultAction,
    /// The signal is ignored.
    Ignored,
    /// Every thread it could go to blocks it: it stays pending until one unblocks it or takes it
    /// with `sigwait` or a `signalfd`.
    Pending,
    /// A `sigwait`, `sigwaitinfo`, `sigtimedwait` or `signalfd` read took it; no handler runs.
    Accepted,
}

/// How a unix signal is handled, taken from the table at the moment of delivery.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// `SIG_DFL`: the OS default action, which for the virtual signals is to end the process
    /// (man 7 signal, "Standard signals" table). The domain reports it and never carries it out.
    Default,
    /// `SIG_IGN`: the signal is discarded.
    Ignore,
    /// A handler at `address`: `fn(c_int)`, or with `siginfo` `fn(c_int, *mut siginfo_t, *mut
    /// c_void)`. `nodefer` lets the signal interrupt its own handler.
    Handler {
        /// The `sa_handler`/`sa_sigaction` word the code under test installed.
        address: usize,
        /// `SA_SIGINFO` was set: call the three-argument form (man 2 sigaction, `SA_SIGINFO`).
        siginfo: bool,
        /// The signal is not blocked while its handler runs (man 2 sigaction, `SA_NODEFER`).
        nodefer: bool,
        /// Installed with `SA_RESTART`: a call the handler interrupts goes on if `SA_RESTART`
        /// restarts it (man 7 signal, "Interruption of system calls and library functions by
        /// signal handlers").
        restart: bool,
        /// The virtual signals its `sa_mask` blocks while it runs (see [`virtual_bits`]).
        blocks: u64,
    },
}

/// A domain's signal table. Its methods run with the calling thread in passthrough.
///
/// Implementations must not call a handler of the code under test while holding a lock of their
/// own: a handler may call back into the table (`sigaction`, `signal`, `SetConsoleCtrlHandler`)
/// on the same thread.
pub trait Signals: Send + Sync + 'static {
    /// Installs `act` for the virtual signal `sig` if given, returning the action it replaces
    /// (man 2 sigaction: `act` and `oldact` are each optional).
    #[cfg(unix)]
    fn sigaction(&self, sig: c_int, act: Option<&libc::sigaction>) -> libc::sigaction;

    /// How `sig` is handled now, applying `SA_RESETHAND` as the delivery takes it: a handler
    /// installed with it is returned once and the table falls back to `SIG_DFL` (man 2 sigaction,
    /// `SA_RESETHAND`).
    #[cfg(unix)]
    fn take_disposition(&self, sig: c_int) -> Disposition;

    /// How `sig` would be handled now, leaving `SA_RESETHAND` for the delivery to apply.
    #[cfg(unix)]
    fn disposition(&self, sig: c_int) -> Disposition;

    /// A signal was left pending for a thread of the domain: wakes its blocked calls to look.
    #[cfg(unix)]
    fn wake_waiters(&self) {}

    /// Blocks the calling thread until a signal handler has run on it, or until no handler ever
    /// can: `pause` and `sigsuspend` (man 2 pause).
    #[cfg(unix)]
    fn suspend(&self);

    /// Blocks the calling thread until `ready` holds, returning `true`, or until `timeout` of the
    /// domain's time has passed or the wait is interrupted (see [`interruptible`]), returning
    /// `false`: the wait of `sigwait`, `sigwaitinfo` and `sigtimedwait`. `ready` is asked again
    /// whenever a signal is left pending in the domain.
    #[cfg(unix)]
    fn wait(
        &self,
        label: &'static str,
        timeout: Option<std::time::Duration>,
        ready: &mut dyn FnMut() -> bool,
    ) -> bool;

    /// `SetConsoleCtrlHandler(handler, add)`; `handler` 0 is the ignore-CTRL+C flag. `Err` is the
    /// Win32 error to fail with
    /// ([Microsoft Learn: SetConsoleCtrlHandler](https://learn.microsoft.com/en-us/windows/console/setconsolectrlhandler)).
    #[cfg(windows)]
    fn set_console_ctrl_handler(&self, handler: usize, add: bool) -> Result<(), u32>;

    /// `GenerateConsoleCtrlEvent` for this process: delivers `event` to the handlers on a new
    /// thread and returns without waiting, as the OS does
    /// ([Microsoft Learn: HandlerRoutine](https://learn.microsoft.com/en-us/windows/console/handlerroutine):
    /// "the system creates a new thread in the process to execute the function").
    #[cfg(windows)]
    fn console_event(&self, event: u32);

    /// The CRT's `signal(sig, handler)`, returning the previous handler
    /// ([Microsoft Learn: signal](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/signal)).
    #[cfg(windows)]
    fn crt_signal(&self, sig: c_int, handler: usize) -> usize;

    /// The CRT's `raise(sig)`: runs the CRT handler synchronously
    /// ([Microsoft Learn: raise](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/raise)).
    /// Returns what `raise` returns, 0 on success.
    #[cfg(windows)]
    fn crt_raise(&self, sig: c_int) -> c_int;

    /// Notes a delivery, as it takes effect. `raw` is the host's number: a signal number on unix,
    /// a `CTRL_*_EVENT` on Windows.
    fn record(&self, raw: i32, source: SignalSource, outcome: SignalOutcome);
}

/// Runs `f` with the calling thread's OS calls offered to its domain again: how the sim runs a
/// handler of the code under test from inside its own code.
///
/// The passthrough flag is restored when `f` returns or unwinds, so the caller's own code after
/// it is back in passthrough.
pub fn simulated<R>(f: impl FnOnce() -> R) -> R {
    let _simulated = Passthrough::leave();
    f()
}

/// The signals a domain keeps its own dispositions for; every other signal is the OS's.
///
/// `SIGINT`, `SIGTERM` and `SIGHUP` are the asynchronous "please stop" signals a program handles
/// for a clean shutdown (the set `ctrlc` handles with its `termination` feature). `SIGCHLD`
/// reports the end of a child process, which the domain delivers itself for the children its
/// threads make ([`deliver_child_exit`]). Fault signals (`SIGSEGV`, `SIGBUS`, ...) must stay real,
/// and `SIGKILL`/`SIGSTOP` cannot be caught at all (man 7 signal), so the OS keeps rejecting them
/// itself.
#[cfg(unix)]
pub fn is_virtual(sig: c_int) -> bool {
    matches!(
        sig,
        libc::SIGINT | libc::SIGTERM | libc::SIGHUP | libc::SIGCHLD
    )
}

/// How a blocked call goes on once a signal handler has run on its thread (man 7 signal,
/// "Interruption of system calls and library functions by signal handlers").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restart {
    /// The call fails with `EINTR` whatever the handler's flags.
    Never,
    /// The call goes on when the handler was installed with `SA_RESTART`, and fails with `EINTR`
    /// otherwise.
    WithSaRestart,
}

/// What the end of a child process tells its parent's `SIGCHLD` handler: the `siginfo_t` fields
/// the kernel fills for it (man 2 sigaction, "The si_code field", `SIGCHLD`).
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildExit {
    /// The child's process id.
    pub pid: libc::pid_t,
    /// The child's real user id.
    pub uid: libc::uid_t,
    /// `CLD_EXITED`, `CLD_KILLED` or `CLD_DUMPED`.
    pub code: c_int,
    /// The exit status for `CLD_EXITED`, else the number of the signal that ended the child.
    pub status: c_int,
}

#[cfg(unix)]
impl ChildExit {
    /// The exit of child `pid` of user `uid` that wait(2) reports as `status`; `None` for a
    /// status that reports no end (a stop or a continue).
    pub fn from_wait_status(pid: libc::pid_t, uid: libc::uid_t, status: c_int) -> Option<Self> {
        let (code, status) = if libc::WIFEXITED(status) {
            (libc::CLD_EXITED, libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            let code = if libc::WCOREDUMP(status) {
                libc::CLD_DUMPED
            } else {
                libc::CLD_KILLED
            };
            (code, libc::WTERMSIG(status))
        } else {
            return None;
        };
        Some(ChildExit {
            pid,
            uid,
            code,
            status,
        })
    }
}

/// What sent a signal, for the `siginfo_t` its handler gets.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cause {
    /// kill(2), or with `tkill` a call aimed at one thread (`raise`, `pthread_kill`).
    Kill { tkill: bool },
    /// A child process ended.
    Child(ChildExit),
}

/// A handler installed with `SA_RESTART` ran (see `RAN`).
#[cfg(unix)]
const RAN_RESTART: u8 = 1;
/// A handler installed without `SA_RESTART` ran (see `RAN`).
#[cfg(unix)]
const RAN_NO_RESTART: u8 = 2;

/// The virtual signals; see [`is_virtual`].
#[cfg(unix)]
const VIRTUAL: [c_int; 4] = [libc::SIGHUP, libc::SIGINT, libc::SIGTERM, libc::SIGCHLD];

/// `sig`'s bit in a set of signals, `1 << sig`. The virtual signals are all below 64 (SIGHUP 1,
/// SIGINT 2, SIGTERM 15 on both Linux and Darwin, SIGCHLD 17 on Linux and 20 on Darwin:
/// <asm-generic/signal.h>, <sys/signal.h>).
#[cfg(unix)]
fn bit(sig: c_int) -> u64 {
    1u64 << sig
}

/// The virtual signals in `set`, one bit each (see [`bit`]).
#[cfg(unix)]
pub fn virtual_bits(set: &libc::sigset_t) -> u64 {
    VIRTUAL
        .iter()
        // SAFETY: `set` is a valid signal set and each number a valid signal.
        .filter(|&&sig| unsafe { libc::sigismember(set, sig) } == 1)
        .fold(0, |bits, &sig| bits | bit(sig))
}

/// Makes the virtual signals in `set` exactly those in `bits`, leaving the others as they are.
#[cfg(unix)]
pub(crate) fn set_virtual_bits(set: &mut libc::sigset_t, bits: u64) {
    for sig in VIRTUAL {
        // SAFETY: `set` is a valid signal set and `sig` a valid signal.
        unsafe {
            if bits & bit(sig) != 0 {
                libc::sigaddset(set, sig);
            } else {
                libc::sigdelset(set, sig);
            }
        }
    }
}

/// The lowest-numbered signal of `bits`.
#[cfg(unix)]
fn lowest(bits: u64) -> Option<c_int> {
    (bits != 0).then(|| bits.trailing_zeros() as c_int)
}

#[cfg(unix)]
thread_local! {
    /// The virtual signals this thread blocks: its signal mask as far as the domain models it
    /// (man 7 signal, "Signal mask and pending signals"), kept in step with its row in the
    /// domain's [`State`] so other threads can see whom a signal may go to.
    static MASK: Cell<u64> = const { Cell::new(0) };
    /// This thread was started by the domain to deliver a signal from outside it
    /// ([`mark_injected`]): no signal sent to the process is ever meant for it.
    static INJECTED: Cell<bool> = const { Cell::new(false) };
    /// The domain state and the generation of its pending signals this thread last looked at
    /// (see [`drain`]).
    static SEEN: Cell<(usize, u64)> = const { Cell::new((0, 0)) };
    /// How the [`interruptible`] call this thread is blocked in goes on after a handler.
    static SCOPE: Cell<Option<Restart>> = const { Cell::new(None) };
    /// A handler has interrupted the [`interruptible`] call this thread is blocked in.
    static INTERRUPTED: Cell<bool> = const { Cell::new(false) };
    /// The handlers that ran on this thread, as [`RAN_RESTART`] and [`RAN_NO_RESTART`] bits.
    static RAN: Cell<u8> = const { Cell::new(0) };
    /// Every handler of the last delivery that interrupted a call of this thread's was installed
    /// with `SA_RESTART`.
    static RESTARTING: Cell<bool> = const { Cell::new(false) };
    /// A handler cut short the `close` this thread makes (see [`close_interrupted`]), and
    /// whether every one that did was installed with `SA_RESTART`.
    static CLOSING: Cell<Option<bool>> = const { Cell::new(None) };
}

/// The calling thread's mask of virtual signals.
#[cfg(unix)]
pub(crate) fn mask() -> u64 {
    MASK.try_with(Cell::get).unwrap_or(0)
}

/// A signal left pending, with what its handler, `sigwaitinfo` or `signalfd` is told of it.
#[cfg(unix)]
#[derive(Clone, Copy)]
pub(crate) struct Posted {
    pub(crate) sig: c_int,
    pub(crate) source: SignalSource,
    pub(crate) cause: Cause,
}

/// What a domain knows of one of its threads' signals.
#[cfg(unix)]
struct Thread {
    /// When it joined the domain's threads, for the order a signal sent to the process tries them.
    order: u64,
    /// It entered the domain itself: the domain's stand-in for a main thread.
    root: bool,
    /// See `INJECTED`.
    injected: bool,
    /// See `MASK`.
    mask: u64,
    /// The signals pending for it alone, each at most once.
    pending: Vec<Posted>,
    /// How deep it is in [`interruptible`] calls.
    blocked: u32,
    /// The signals a `sigwait`, `sigwaitinfo` or `sigtimedwait` of its waits for.
    waits: u64,
    /// What ends the native wait it blocks in early, while it does (see [`kickable`]).
    kick: Option<Kick>,
    /// How many times a signal left pending for it has kicked its native waits.
    kicks: u64,
}

#[cfg(unix)]
impl Thread {
    fn new(order: u64, root: bool, mask: u64) -> Self {
        Thread {
            order,
            root,
            injected: false,
            mask,
            pending: Vec::new(),
            blocked: 0,
            waits: 0,
            kick: None,
            kicks: 0,
        }
    }

    /// Whether `sig`, sent to the process, may go to this thread: one the code under test runs on
    /// that does not block it.
    fn accepts(&self, sig: c_int) -> bool {
        !self.injected && self.mask & bit(sig) == 0
    }

    /// The order threads are tried in for a signal sent to the process: roots first.
    fn rank(&self) -> (bool, u64) {
        (!self.root, self.order)
    }
}

#[cfg(unix)]
#[derive(Default)]
struct Table {
    threads: crate::HashMap<u64, Thread>,
    /// Signals sent to the process that every thread blocked, each at most once.
    process: Vec<Posted>,
    /// The next thread's `order`.
    next: u64,
    /// How many signals are pending, for the thread and the process together.
    count: usize,
}

#[cfg(unix)]
impl Table {
    fn thread(&mut self, lineage: u64) -> &mut Thread {
        let next = &mut self.next;
        self.threads.entry(lineage).or_insert_with(|| {
            *next += 1;
            Thread::new(*next, false, 0)
        })
    }

    /// The thread a signal sent to the process and blocked by every thread waits on under macOS:
    /// the first root, standing in for the main thread.
    fn main(&self) -> Option<u64> {
        self.threads
            .iter()
            .filter(|(_, t)| t.root && !t.injected)
            .min_by_key(|(_, t)| t.order)
            .map(|(&lineage, _)| lineage)
    }

    /// Whether the calling thread, `lineage`, may take a signal left pending for the process. On
    /// Linux any thread that unblocks it does (kernel/signal.c `dequeue_signal` reads the shared
    /// queue after the thread's own); XNU posts a signal every thread blocks to the main thread's
    /// list instead (bsd/kern/kern_sig.c `psignal_internal`), so only it gets it once it unblocks.
    fn takes_process(&self, lineage: u64) -> bool {
        !INJECTED.try_with(Cell::get).unwrap_or(false)
            && (cfg!(target_os = "linux") || self.main() == Some(lineage))
    }

    /// The first thread, by [`Thread::rank`], that `filter` picks.
    fn first(&self, filter: impl Fn(&u64, &Thread) -> bool) -> Option<u64> {
        self.threads
            .iter()
            .filter(|(lineage, t)| filter(lineage, t))
            .min_by_key(|(_, t)| t.rank())
            .map(|(&lineage, _)| lineage)
    }

    /// The signals pending for `lineage`, its own and the process's.
    fn pending_for(&self, lineage: u64) -> u64 {
        let own = self
            .threads
            .get(&lineage)
            .map_or(0, |t| t.pending.iter().fold(0, |b, p| b | bit(p.sig)));
        self.process.iter().fold(own, |b, p| b | bit(p.sig))
    }

    /// Takes the lowest-numbered signal of `wanted` pending for `lineage`, its own before the
    /// process's on Linux (kernel/signal.c `dequeue_signal`); the process's only if `process`.
    /// XNU keeps one list for the thread a signal went to (see `takes_process`), from which it
    /// takes the lowest number (bsd/kern/kern_sig.c `issignal_locked`).
    fn take(&mut self, lineage: u64, wanted: u64, process: bool) -> Option<Posted> {
        let wanted = if cfg!(target_os = "linux") || !process {
            wanted
        } else {
            let all = self.pending_for(lineage) & wanted;
            lowest(all).map_or(0, bit)
        };
        let own = self.threads.get_mut(&lineage).and_then(|t| take_lowest(&mut t.pending, wanted));
        let taken = own.or_else(|| {
            process
                .then(|| take_lowest(&mut self.process, wanted))
                .flatten()
        });
        if taken.is_some() {
            self.count -= 1;
        }
        taken
    }

    /// Leaves `posted` pending for thread `lineage`, or for the process with `None`, unless that
    /// signal already is: a standard signal does not queue, so one raised again before delivery
    /// is delivered once, with what its first raising said (man 7 signal, "Queueing and delivery
    /// semantics for standard signals"; Linux drops it in kernel/signal.c `legacy_queue`).
    fn push(&mut self, lineage: Option<u64>, posted: Posted) {
        let list = match lineage {
            Some(lineage) => &mut self.thread(lineage).pending,
            None => &mut self.process,
        };
        if !list.iter().any(|p| p.sig == posted.sig) {
            list.push(posted);
            self.count += 1;
        }
    }

    /// Drops every pending `sig`, as setting its action to be ignored does (IEEE Std 1003.1,
    /// sigaction: "Setting a signal action to SIG_IGN for a signal that is pending shall cause the
    /// pending signal to be discarded").
    fn discard(&mut self, sig: c_int) {
        let mut dropped = 0;
        for list in self
            .threads
            .values_mut()
            .map(|t| &mut t.pending)
            .chain(std::iter::once(&mut self.process))
        {
            let before = list.len();
            list.retain(|p| p.sig != sig);
            dropped += before - list.len();
        }
        self.count -= dropped;
    }
}

#[cfg(unix)]
fn take_lowest(list: &mut Vec<Posted>, wanted: u64) -> Option<Posted> {
    let sig = lowest(list.iter().fold(0, |b, p| b | bit(p.sig)) & wanted)?;
    let at = list.iter().position(|p| p.sig == sig)?;
    Some(list.remove(at))
}

/// A domain's signal masks and pending signals, by thread lineage.
#[cfg(unix)]
#[derive(Default)]
pub(crate) struct State {
    table: Mutex<Table>,
    /// Bumped each time a signal is left pending, after it is: a thread's hooked calls look for one
    /// only when it has moved since they last did (see [`drain`]).
    generation: AtomicU64,
    /// Whether any signal may be pending: a lock-free check for the waits that ask often.
    any: AtomicBool,
}

#[cfg(unix)]
impl State {
    /// Runs `f` on the table, in passthrough so the lock's own calls reach the OS.
    fn with<R>(&self, f: impl FnOnce(&mut Table) -> R) -> R {
        let _passthrough = Passthrough::enter();
        let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
        let r = f(&mut table);
        self.any.store(table.count > 0, Ordering::SeqCst);
        r
    }

    /// Counts thread `lineage` in, blocking `mask`.
    pub(crate) fn join(&self, lineage: u64, root: bool, mask: u64) {
        self.with(|t| {
            t.next += 1;
            let order = t.next;
            let thread = t
                .threads
                .entry(lineage)
                .or_insert_with(|| Thread::new(order, root, mask));
            thread.root |= root;
            thread.mask = mask;
        });
    }

    /// Counts thread `lineage` out; the signals pending for it alone go with it.
    pub(crate) fn leave(&self, lineage: u64) {
        self.with(|t| {
            if let Some(thread) = t.threads.remove(&lineage) {
                t.count -= thread.pending.len();
            }
        });
    }

    /// Whether a signal `sig` sent to the process now would stay pending, or go to a `sigwait`:
    /// whether some thread waits for it, or every thread blocks it.
    pub(crate) fn holds(&self, sig: c_int) -> bool {
        self.with(|t| {
            t.threads.values().any(|th| th.waits & bit(sig) != 0)
                || (t.threads.values().any(|th| !th.injected)
                    && !t.threads.values().any(|th| th.accepts(sig)))
        })
    }

    fn bump(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }
}

/// Counts the calling thread, `lineage`, into `state` as it starts in a domain, blocking `mask`,
/// and returns the mask it had before, for [`left`].
#[cfg(unix)]
pub(crate) fn joined(state: &State, lineage: u64, root: bool, mask: u64) -> u64 {
    state.join(lineage, root, mask);
    let _ = INJECTED.try_with(|i| i.set(false));
    MASK.try_with(|m| m.replace(mask)).unwrap_or(0)
}

/// Counts the calling thread, `lineage`, out of `state` as it leaves a domain, putting back the
/// mask [`joined`] returned.
#[cfg(unix)]
pub(crate) fn left(state: &State, lineage: u64, previous: u64) {
    state.leave(lineage);
    let _ = MASK.try_with(|m| m.set(previous));
    let _ = INJECTED.try_with(|i| i.set(false));
}

/// Moves the calling thread from `from`, where it was `was`, to `to` as `now`, as it follows into
/// another domain: the signals left pending for it alone stay behind, its mask goes with it.
/// `None` for a domain without a signal table.
#[cfg(unix)]
pub(crate) fn moved(from: Option<&State>, was: u64, to: Option<&State>, now: u64) {
    if let Some(from) = from {
        from.leave(was);
    }
    if let Some(to) = to {
        let injected = INJECTED.try_with(Cell::get).unwrap_or(false);
        to.join(now, false, mask());
        if injected {
            to.with(|t| t.thread(now).injected = true);
        }
    }
}

/// Marks the calling thread as one a domain started only to deliver a signal from outside it.
#[cfg(unix)]
pub(crate) fn mark_injected(state: &State, lineage: u64) {
    let _ = INJECTED.try_with(|i| i.set(true));
    state.with(|t| t.thread(lineage).injected = true);
}

/// The calling thread's real signal mask's virtual signals: what a thread entering a domain
/// starts blocking, as a program's first thread starts with the mask it was executed with (man 7
/// signal: "the signal mask is preserved across execve(2)").
#[cfg(unix)]
pub(crate) fn real_mask() -> u64 {
    // SAFETY: an all-zero sigset_t is valid; a query only fills `current`.
    let mut current: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: a null new set only reads the mask.
    let r = crate::real(|| unsafe {
        libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut current)
    });
    if r == 0 { virtual_bits(&current) } else { 0 }
}

/// Where a signal sent to the process goes.
#[cfg(unix)]
enum Target {
    /// A thread waiting for it in `sigwait`, `sigwaitinfo` or `sigtimedwait`.
    Waiter(u64),
    /// Another thread, to run its handler there.
    Thread(u64),
    /// The calling thread.
    Here,
    /// Every thread blocks it: it stays pending for the process.
    Pending,
    /// No handler runs for it: its default action or its being ignored is logged as it is sent.
    Record,
}

/// Picks the thread a signal `sig` sent to the process goes to, as the kernel picks one.
///
/// A thread waiting for it in `sigwait` takes it first: Linux unblocks the waited signals for the
/// wait (kernel/signal.c `do_sigtimedwait` sets `real_blocked`), so `wants_signal` picks it, and
/// XNU's `get_signalthread` takes a thread whose `uu_sigwait` holds it. Otherwise Linux tries the
/// main thread, then the others from the last one picked (`complete_signal`), and XNU the
/// process's threads in order (`get_signalthread`), skipping any that block it. The domain's roots
/// stand in for the main thread: a root blocked in an [`interruptible`] call that does not block
/// it gets it, which interrupts the call; with none, the sending thread runs the handler itself
/// if it does not block it, standing in for a main thread running at that moment, which also meets
/// POSIX's demand that a signal a process sends itself, if unblocked, be delivered before `kill`
/// returns (IEEE Std 1003.1, kill). A thread the domain started to send a signal from outside it
/// stands in that way for whichever thread would take it, and for the main thread of a domain none
/// of whose own threads is running. Only when no root may take it does another blocked thread, then
/// any other, get it.
///
/// A signal every thread blocks stays pending for the process; one that is ignored is discarded
/// as it is sent instead, unless, on Linux, every thread blocks it (kernel/signal.c `sig_ignored`:
/// "Blocked signals are never ignored"); XNU discards it even then (`psignal_internal` checks
/// `p_sigignore` before any mask).
#[cfg(unix)]
fn target(
    state: &State,
    me: u64,
    sig: c_int,
    disposition: Disposition,
    injected: bool,
) -> Target {
    let mine = mask();
    state.with(|t| {
        if let Some(waiter) = t.first(|_, th| th.waits & bit(sig) != 0 && !th.injected) {
            return Target::Waiter(waiter);
        }
        let i_accept = !injected && mine & bit(sig) == 0;
        let others = |lineage: &u64, th: &Thread| *lineage != me && th.accepts(sig);
        let idle = !t.threads.values().any(|th| !th.injected);
        if !i_accept && !idle && t.first(others).is_none() {
            return if matches!(disposition, Disposition::Ignore) && !cfg!(target_os = "linux") {
                Target::Record
            } else {
                Target::Pending
            };
        }
        if !matches!(disposition, Disposition::Handler { .. }) {
            return Target::Record;
        }
        let i_am_root = t.threads.get(&me).is_some_and(|th| th.root);
        let a_root = (i_accept && i_am_root) || t.first(|l, th| th.root && others(l, th)).is_some();
        let blocked = |root: bool| {
            t.first(|l, th| th.blocked > 0 && (th.root || !root) && others(l, th))
        };
        if let Some(thread) = blocked(a_root) {
            return Target::Thread(thread);
        }
        if i_accept || injected {
            return Target::Here;
        }
        t.first(|l, th| (th.root || !a_root) && others(l, th))
            .map_or(Target::Pending, Target::Thread)
    })
}

/// Delivers the virtual signal `sig`, sent to the calling thread's process as `kill` sends it, in
/// the thread's domain, to the thread [`target`] picks. `None` off a domain, on a domain without
/// a signal table, or for a signal the domain leaves to the OS.
///
/// A handler that runs on another thread, one that interrupts a call, is reported handled before
/// it runs; one that goes to a thread's `sigwait` is reported accepted, and one every thread
/// blocks pending.
#[cfg(unix)]
pub fn deliver_here(sig: c_int, source: SignalSource) -> Option<SignalOutcome> {
    deliver_to_process(sig, source, Cause::Kill { tkill: false })
}

/// Delivers `SIGCHLD` for `exit` into the calling thread's domain, as [`deliver_here`] delivers a
/// signal sent to the process, with the `siginfo_t` the kernel fills for a child's end.
#[cfg(unix)]
pub fn deliver_child_exit(exit: ChildExit) -> Option<SignalOutcome> {
    deliver_to_process(libc::SIGCHLD, SignalSource::Child, Cause::Child(exit))
}

/// See [`deliver_here`].
#[cfg(unix)]
pub(crate) fn deliver_to_process(
    sig: c_int,
    source: SignalSource,
    cause: Cause,
) -> Option<SignalOutcome> {
    if !is_virtual(sig) {
        return None;
    }
    let domain = crate::domain::signal_domain()?;
    let disposition = crate::real(|| domain.table().disposition(sig));
    let me = crate::domain::thread_lineage();
    let injected = INJECTED.try_with(Cell::get).unwrap_or(false);
    let posted = Posted { sig, source, cause };
    Some(match target(domain.state(), me, sig, disposition, injected) {
        Target::Waiter(thread) => {
            post(domain, Some(thread), posted);
            SignalOutcome::Accepted
        }
        Target::Thread(thread) => {
            post(domain, Some(thread), posted);
            SignalOutcome::Handled
        }
        Target::Here => {
            domain
                .state()
                .with(|t| t.push(Some(me), posted));
            deliver_ready(domain, Some(sig)).unwrap_or(SignalOutcome::Handled)
        }
        Target::Pending => {
            post(domain, None, posted);
            SignalOutcome::Pending
        }
        Target::Record => {
            let outcome = match crate::real(|| domain.table().take_disposition(sig)) {
                Disposition::Ignore => SignalOutcome::Ignored,
                _ => SignalOutcome::DefaultAction,
            };
            record(domain, posted, outcome);
            outcome
        }
    })
}

/// Delivers the virtual signal `sig` aimed at the calling thread (`raise`, `pthread_kill`, which
/// Linux reports as `SI_TKILL`: glibc sends both with tgkill(2), and the kernel fills a
/// thread-directed kill's `si_code` with `SI_TKILL`, kernel/signal.c `prepare_kill_siginfo`,
/// `do_tkill`). One the thread blocks stays pending for it, unless it is ignored on macOS (see
/// [`target`]).
#[cfg(unix)]
pub(crate) fn deliver(sig: c_int, source: SignalSource, cause: Cause) -> Option<SignalOutcome> {
    if !is_virtual(sig) {
        return None;
    }
    let domain = crate::domain::signal_domain()?;
    let posted = Posted { sig, source, cause };
    if mask() & bit(sig) != 0 {
        let ignored = matches!(
            crate::real(|| domain.table().disposition(sig)),
            Disposition::Ignore
        );
        if ignored && !cfg!(target_os = "linux") {
            record(domain, posted, SignalOutcome::Ignored);
            return Some(SignalOutcome::Ignored);
        }
        post(domain, Some(crate::domain::thread_lineage()), posted);
        return Some(SignalOutcome::Pending);
    }
    let me = crate::domain::thread_lineage();
    domain
        .state()
        .with(|t| t.push(Some(me), posted));
    Some(deliver_ready(domain, Some(sig)).unwrap_or(SignalOutcome::Handled))
}

/// Sends `sig` to thread `lineage` of `domain` as `pthread_kill` from another thread does: left
/// pending for it, to be delivered once its mask lets it through. On macOS an ignored signal is
/// discarded as it is sent instead, whatever the thread's mask (see [`target`]).
#[cfg(unix)]
pub(crate) fn send_to_thread(domain: crate::domain::SignalDomain, lineage: u64, sig: c_int) {
    let posted = Posted {
        sig,
        source: SignalSource::Process,
        cause: Cause::Kill { tkill: true },
    };
    if !cfg!(target_os = "linux")
        && matches!(
            crate::real(|| domain.table().disposition(sig)),
            Disposition::Ignore
        )
    {
        record(domain, posted, SignalOutcome::Ignored);
        return;
    }
    post(domain, Some(lineage), posted);
}

/// Leaves `posted` pending for thread `lineage` of `domain`, or for its process with `None`, and
/// wakes the blocked calls that may want it: the domain's readiness waits, and the thread's
/// wait in a deterministic schedule.
#[cfg(unix)]
pub(crate) fn post(domain: crate::domain::SignalDomain, lineage: Option<u64>, posted: Posted) {
    domain.state().with(|t| t.push(lineage, posted));
    domain.state().bump();
    domain.wake(lineage);
    if let Some(lineage) = lineage {
        kick(domain, lineage, posted.sig);
    }
}

/// How a native wait is ended early for a signal left pending for the thread blocked in it (see
/// [`kickable`]).
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kick {
    /// A `FUTEX_WAKE` of every waiter on the futex word at `word`, the one the thread waits on,
    /// whose wait then returns 0 (man 2 futex); `private` adds `FUTEX_PRIVATE_FLAG`, which must
    /// match the wait's.
    #[cfg(target_os = "linux")]
    Futex { word: usize, private: bool },
    /// `thread_abort_safely` of the thread's Mach port: an abort-safe kernel wait of the thread
    /// (a semaphore's, a BSD sleep that catches signals) ends at once, and a BSD call blocked in
    /// one fails with `EINTR`, with no signal sent (XNU osfmk/kern/thread_act.c
    /// `thread_abort_safely`; measured on macOS 26 for `sem_wait`). Made while the thread runs
    /// in user space, the abort is dropped as it next returns there (`thread_apc_ast` clears it),
    /// so [`kick`] repeats it until the wait ends.
    #[cfg(target_os = "macos")]
    Abort(libc::mach_port_t),
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    /// `<mach/thread_act.h>`.
    fn thread_abort_safely(target: libc::mach_port_t) -> libc::kern_return_t;
}

#[cfg(unix)]
impl Kick {
    /// A kick of the calling thread's own abort-safe waits.
    #[cfg(target_os = "macos")]
    pub(crate) fn this_thread() -> Kick {
        // SAFETY: pthread_self has no preconditions; its port lives as long as the thread.
        Kick::Abort(unsafe { libc::pthread_mach_thread_np(libc::pthread_self()) })
    }

    /// Sends it. Called holding the domain's signal table, which the kicked thread takes to end
    /// its window ([`kickable`]), so the thread is still in it.
    fn send(self) {
        match self {
            #[cfg(target_os = "linux")]
            Kick::Futex { word, private } => {
                let op = libc::FUTEX_WAKE | if private { libc::FUTEX_PRIVATE_FLAG } else { 0 };
                // SAFETY: `word` is the futex word of the kicked thread's wait, alive while it
                // waits; a wake reads nothing else.
                unsafe { libc::syscall(libc::SYS_futex, word, op, c_int::MAX) };
            }
            #[cfg(target_os = "macos")]
            Kick::Abort(port) => {
                // SAFETY: the kicked thread's own port, alive while it waits.
                unsafe { thread_abort_safely(port) };
            }
        }
    }
}

/// How many times [`kick`] kicks a thread before giving up on its wait ending: some 50 ms of real
/// time once the first few have only yielded. A snare choice; a wait the kick reaches ends after
/// the first.
#[cfg(unix)]
const KICK_ROUNDS: u32 = 1_000;

/// Kicks the native wait thread `lineage` blocks in, if it blocks in one, for `sig` just left
/// pending for it, and goes on kicking until the wait ends or the signal is no longer pending for
/// it unblocked: a kick that lands as the thread is about to block, between its last look for a
/// signal and the wait itself, is lost.
#[cfg(unix)]
fn kick(domain: crate::domain::SignalDomain, lineage: u64, sig: c_int) {
    for round in 0..KICK_ROUNDS {
        let kicked = domain.state().with(|t| {
            let pending = t.pending_for(lineage) & bit(sig) != 0;
            let Some(thread) = t.threads.get_mut(&lineage) else {
                return false;
            };
            let Some(kick) = thread.kick.filter(|_| pending && thread.mask & bit(sig) == 0) else {
                return false;
            };
            thread.kicks += 1;
            kick.send();
            true
        });
        if !kicked {
            return;
        }
        crate::real(|| {
            if round < 8 {
                std::thread::yield_now();
            } else {
                std::thread::sleep(std::time::Duration::from_micros(50));
            }
        });
    }
}

/// How a [`kickable`] wait ended.
#[cfg(unix)]
pub(crate) enum KickWait<R> {
    /// `wait` returned this, and no kick reached it.
    Ran(R),
    /// `wait` returned this after a kick: it may have ended for the kick alone.
    Kicked(R),
    /// A signal was already pending for the thread unblocked: `wait` did not run.
    Pending,
}

/// Runs `wait`, a native wait that `kick` ends early, so that a signal left pending for the
/// calling thread while it waits sends the kick ([`post`]); one already pending skips the wait.
/// The thread's window opens before it looks for a pending signal and closes, under the signal
/// table's lock, as soon as `wait` returns, so a kick only ever reaches this wait. Off a domain
/// with a signal table `wait` just runs.
#[cfg(unix)]
pub(crate) fn kickable<R>(kick: Kick, wait: impl FnOnce() -> R) -> KickWait<R> {
    let Some(domain) = crate::domain::signal_domain() else {
        return KickWait::Ran(wait());
    };
    let me = crate::domain::thread_lineage();
    let before = domain.state().with(|t| {
        let thread = t.thread(me);
        thread.kick = Some(kick);
        thread.kicks
    });
    let result = (!interrupt_pending()).then(wait);
    let after = domain.state().with(|t| {
        let thread = t.thread(me);
        thread.kick = None;
        thread.kicks
    });
    match result {
        None => KickWait::Pending,
        Some(r) if after != before => KickWait::Kicked(r),
        Some(r) => KickWait::Ran(r),
    }
}

/// Whether the calling thread waits in an [`interruptible`] call: a native wait it makes there
/// leaves the signals pending meanwhile to the call, which delivers them as it decides how it goes
/// on.
#[cfg(unix)]
pub(crate) fn in_interruptible() -> bool {
    SCOPE.try_with(Cell::get).ok().flatten().is_some()
}

/// Logs a delivery to the domain's table. A child's `SIGCHLD` the domain ignores is not logged:
/// the kernel sends none to a parent that ignores it (kernel/signal.c `do_notify_parent`).
#[cfg(unix)]
fn record(domain: crate::domain::SignalDomain, posted: Posted, outcome: SignalOutcome) {
    if outcome == SignalOutcome::Ignored && matches!(posted.cause, Cause::Child(_)) {
        return;
    }
    crate::real(|| domain.table().record(posted.sig, posted.source, outcome));
}

/// A handler about to run: the frame the kernel sets up for it.
#[cfg(unix)]
#[derive(Clone, Copy)]
struct Frame {
    posted: Posted,
    address: usize,
    siginfo: bool,
    restart: bool,
    /// The mask while it runs: the mask before, its action's `sa_mask`, and its own signal unless
    /// `SA_NODEFER`.
    mask: u64,
}

/// Delivers every signal pending for the calling thread that its mask lets through, as the kernel
/// does on the way back to user space, and returns how `watch` was delivered, if it was.
///
/// The kernel takes one signal at a time, lowest number first, the thread's own before the
/// process's, and for each one handled sets up a frame and extends the mask by the handler's
/// `sa_mask` and the signal itself (kernel/signal.c `get_signal`, `signal_setup_done`; XNU
/// bsd/kern/kern_sig.c `postsig_locked`), then looks again before running anything, so the frame
/// set up last runs first and the handlers run highest number first, each returning into the one
/// below it; on return each frame puts back the mask from before it (man 2 sigreturn), and any
/// signal that lets through is delivered in turn. Pinned against both hosts by
/// crates/snare/tests/signal_masks.rs.
///
/// Each disposition is taken (applying `SA_RESETHAND`) and logged as its signal is taken. The
/// table is only read and logged through [`crate::real`], never while a handler runs, so a handler
/// may call `sigaction` freely.
#[cfg(unix)]
fn deliver_ready(
    domain: crate::domain::SignalDomain,
    watch: Option<c_int>,
) -> Option<SignalOutcome> {
    let me = crate::domain::thread_lineage();
    let mut seen = None;
    loop {
        let base = mask();
        let mut frames: Vec<Frame> = Vec::new();
        let mut blocked = base;
        while let Some(posted) = domain
            .state()
            .with(|t| {
                let process = t.takes_process(me);
                t.take(me, !blocked, process)
            })
        {
            let disposition = crate::real(|| domain.table().take_disposition(posted.sig));
            let outcome = match disposition {
                Disposition::Default => SignalOutcome::DefaultAction,
                Disposition::Ignore => SignalOutcome::Ignored,
                Disposition::Handler { .. } => SignalOutcome::Handled,
            };
            if watch == Some(posted.sig) {
                seen.get_or_insert(outcome);
            }
            record(domain, posted, outcome);
            if let Disposition::Handler {
                address,
                siginfo,
                nodefer,
                restart,
                blocks,
            } = disposition
            {
                blocked |= blocks | if nodefer { 0 } else { bit(posted.sig) };
                frames.push(Frame {
                    posted,
                    address,
                    siginfo,
                    restart,
                    mask: blocked,
                });
            }
        }
        if frames.is_empty() {
            return seen;
        }
        for at in (0..frames.len()).rev() {
            let frame = frames[at];
            set_mask(domain, frame.mask);
            let scope = SCOPE.try_with(|s| s.replace(None)).unwrap_or(None);
            let interrupted = INTERRUPTED.try_with(|i| i.replace(false)).unwrap_or(false);
            // SAFETY: the code under test installed `address` as a handler of this shape.
            simulated(|| unsafe {
                call_handler(frame.address, frame.siginfo, frame.posted)
            });
            let _ = SCOPE.try_with(|s| s.set(scope));
            let _ = INTERRUPTED.try_with(|i| i.set(interrupted));
            let ran = if frame.restart {
                RAN_RESTART
            } else {
                RAN_NO_RESTART
            };
            let _ = RAN.try_with(|r| r.set(r.get() | ran));
            set_mask(domain, at.checked_sub(1).map_or(base, |below| frames[below].mask));
            deliver_ready(domain, None);
        }
    }
}

/// Sets the calling thread's mask of virtual signals, here and in its domain's table.
#[cfg(unix)]
fn set_mask(domain: crate::domain::SignalDomain, next: u64) {
    let _ = MASK.try_with(|m| m.set(next));
    let me = crate::domain::thread_lineage();
    domain.state().with(|t| t.thread(me).mask = next);
}

/// Changes the calling thread's mask of virtual signals to `next`, as `pthread_sigmask` and
/// `sigprocmask` do, and delivers the pending signals it lets through before returning (IEEE Std
/// 1003.1, pthread_sigmask: "If there are any pending unblocked signals after the call to
/// pthread_sigmask(), at least one of those signals shall be delivered before the call to
/// pthread_sigmask() returns"). `false` off a domain with a signal table.
#[cfg(unix)]
pub(crate) fn change_mask(next: u64) -> bool {
    let Some(domain) = crate::domain::signal_domain() else {
        return false;
    };
    let unblocked = mask() & !next != 0;
    set_mask(domain, next);
    if unblocked {
        deliver_ready(domain, None);
    }
    true
}

/// Sets the calling thread's mask of virtual signals to `next` without delivering anything it lets
/// through: `sigsuspend`, whose wait delivers them.
#[cfg(unix)]
pub(crate) fn replace_mask(next: u64) {
    if let Some(domain) = crate::domain::signal_domain() {
        set_mask(domain, next);
    }
}

/// The virtual signals pending for the calling thread, its own and its process's (man 2
/// sigpending); `None` off a domain with a signal table.
#[cfg(unix)]
pub(crate) fn pending() -> Option<u64> {
    let domain = crate::domain::signal_domain()?;
    let me = crate::domain::thread_lineage();
    Some(domain.state().with(|t| t.pending_for(me)))
}

/// Discards every pending `sig` of the calling thread's domain if its action now ignores it (see
/// `Table::discard`).
#[cfg(unix)]
pub(crate) fn discard_if_ignored(sig: c_int) {
    let Some(domain) = crate::domain::signal_domain() else {
        return;
    };
    if matches!(
        crate::real(|| domain.table().disposition(sig)),
        Disposition::Ignore
    ) {
        domain.state().with(|t| t.discard(sig));
    }
}

/// Delivers the signals pending for the calling thread that its mask lets through, if any have
/// been left pending in its domain since it last looked: the check every hooked call makes.
#[cfg(unix)]
pub(crate) fn drain(domain: crate::domain::SignalDomain) {
    let state = domain.state();
    let generation = state.generation.load(Ordering::SeqCst);
    let key = (std::ptr::from_ref(state) as usize, generation);
    if SEEN.try_with(|s| s.replace(key)).unwrap_or(key) == key {
        return;
    }
    deliver_ready(domain, None);
}

/// Delivers the signals pending for the calling thread that its mask lets through.
#[cfg(unix)]
pub(crate) fn drain_here() {
    if let Some(domain) = crate::domain::signal_domain() {
        deliver_ready(domain, None);
    }
}

/// Whether a signal its mask lets through is pending for the calling thread.
#[cfg(unix)]
fn deliverable_here() -> bool {
    let Some(domain) = crate::domain::signal_domain() else {
        return false;
    };
    if !domain.state().any.load(Ordering::SeqCst) {
        return false;
    }
    let me = crate::domain::thread_lineage();
    let open = !mask();
    domain.state().with(|t| {
        let own = t
            .threads
            .get(&me)
            .is_some_and(|th| th.pending.iter().any(|p| open & bit(p.sig) != 0));
        own || (t.takes_process(me) && t.process.iter().any(|p| open & bit(p.sig) != 0))
    })
}

/// Takes the lowest-numbered signal of `wanted` pending for the calling thread, its own before
/// its process's, for `sigwait` or a `signalfd` read, and logs it as accepted.
#[cfg(unix)]
pub(crate) fn accept(domain: crate::domain::SignalDomain, wanted: u64) -> Option<Posted> {
    let me = crate::domain::thread_lineage();
    let posted = domain.state().with(|t| t.take(me, wanted, true))?;
    record(domain, posted, SignalOutcome::Accepted);
    Some(posted)
}

/// Whether a signal of `wanted` is pending for the calling thread, its own or its process's.
#[cfg(target_os = "linux")]
fn has_pending(domain: crate::domain::SignalDomain, wanted: u64) -> bool {
    if !domain.state().any.load(Ordering::SeqCst) {
        return false;
    }
    let me = crate::domain::thread_lineage();
    domain.state().with(|t| t.pending_for(me) & wanted != 0)
}

/// How a wait for a signal ended (see [`wait_for`]).
#[cfg(unix)]
pub(crate) enum Waited {
    /// It took this signal.
    Took(Posted),
    /// A handler of another signal ran and interrupted it.
    Interrupted,
    /// `timeout` passed first.
    TimedOut,
}

/// Waits for a signal of `wanted` and takes it: `sigwait`, `sigwaitinfo` and `sigtimedwait`
/// (man 2 sigwaitinfo). One already pending is taken at once; otherwise the thread waits, as one
/// signals sent to the process go to first (see [`target`]), until one is left pending for it,
/// `timeout` of the domain's time has passed, or a handler of another signal its mask lets through
/// runs, which interrupts the wait whatever the handler's flags (man 7 signal: `sigtimedwait` and
/// `sigwaitinfo` are never restarted).
#[cfg(unix)]
pub(crate) fn wait_for(
    domain: crate::domain::SignalDomain,
    wanted: u64,
    timeout: Option<std::time::Duration>,
    label: &'static str,
) -> Waited {
    if let Some(posted) = accept(domain, wanted) {
        return Waited::Took(posted);
    }
    if timeout.is_some_and(|t| t.is_zero()) {
        return Waited::TimedOut;
    }
    let me = crate::domain::thread_lineage();
    domain.state().with(|t| t.thread(me).waits |= wanted);
    struct Waiting(crate::domain::SignalDomain, u64, u64);
    impl Drop for Waiting {
        fn drop(&mut self) {
            let Waiting(domain, me, wanted) = *self;
            domain.state().with(|t| t.thread(me).waits &= !wanted);
        }
    }
    let waiting = Waiting(domain, me, wanted);
    let mut took = None;
    let (_, interrupted) = interruptible(Restart::Never, || {
        crate::real(|| {
            domain.table().wait(label, timeout, &mut || {
                if took.is_none() {
                    took = accept(domain, wanted);
                }
                took.is_some()
            })
        })
    });
    drop(waiting);
    match took {
        Some(posted) => Waited::Took(posted),
        None if interrupted => Waited::Interrupted,
        None => Waited::TimedOut,
    }
}

/// What a thread's [`State`] row says while it is blocked in an [`interruptible`] call.
#[cfg(unix)]
struct Blocked(crate::domain::SignalDomain, u64);

#[cfg(unix)]
impl Blocked {
    fn enter() -> Option<Self> {
        let domain = crate::domain::signal_domain()?;
        let me = crate::domain::thread_lineage();
        domain.state().with(|t| t.thread(me).blocked += 1);
        Some(Blocked(domain, me))
    }
}

#[cfg(unix)]
impl Drop for Blocked {
    fn drop(&mut self) {
        let me = self.1;
        self.0.state().with(|t| {
            let thread = t.thread(me);
            thread.blocked = thread.blocked.saturating_sub(1);
        });
    }
}

/// Runs `wait`, the wait of a blocking call, as one a signal handler can interrupt, and returns
/// its result and whether a handler interrupted it, for the call to fail with `EINTR`.
///
/// While `wait` runs, a signal its mask lets through pending for the calling thread (`pthread_kill`
/// from another thread, or one sent to the process that [`deliver_here`] picks this thread for)
/// ends it once the wait looks ([`interrupt_pending`]); the wait delivers it
/// ([`deliver_interrupting`]) and goes on or ends as `restart` and the handler's `SA_RESTART` say.
/// Off a domain with a signal table nothing is ever left pending, so `wait` just runs.
pub fn interruptible<R>(restart: Restart, wait: impl FnOnce() -> R) -> (R, bool) {
    #[cfg(unix)]
    {
        let scope = SCOPE.try_with(|s| s.replace(Some(restart))).unwrap_or(None);
        let interrupted = INTERRUPTED.try_with(|i| i.replace(false)).unwrap_or(false);
        let blocked = Blocked::enter();
        let result = wait();
        drop(blocked);
        let _ = SCOPE.try_with(|s| s.set(scope));
        let now = INTERRUPTED
            .try_with(|i| i.replace(interrupted))
            .unwrap_or(false);
        (result, now)
    }
    #[cfg(not(unix))]
    {
        let _ = restart;
        (wait(), false)
    }
}

/// Whether the calling thread waits in an [`interruptible`] call, not yet interrupted, with a
/// signal its mask lets through pending for it: the check a blocking wait adds to its readiness
/// test. Cheap while no signal is pending in the thread's domain.
pub fn interrupt_pending() -> bool {
    #[cfg(unix)]
    {
        SCOPE.try_with(Cell::get).ok().flatten().is_some()
            && !INTERRUPTED.try_with(Cell::get).unwrap_or(true)
            && deliverable_here()
    }
    #[cfg(not(unix))]
    false
}

/// Whether a handler has interrupted the [`interruptible`] call the calling thread is in: a wait
/// that loops on its own checks this to stop.
pub fn interrupted() -> bool {
    #[cfg(unix)]
    {
        INTERRUPTED.try_with(Cell::get).unwrap_or(false)
    }
    #[cfg(not(unix))]
    false
}

/// Delivers the signals pending for the calling thread, blocked in an [`interruptible`] call
/// whose wait [`interrupt_pending`] ended, and returns whether the call goes on: when no handler
/// ran (the signals were ignored), or every handler that ran was installed with `SA_RESTART` and
/// the call restarts under it. Otherwise the call is interrupted.
pub fn deliver_interrupting() -> bool {
    #[cfg(unix)]
    {
        let Some(restart) = SCOPE.try_with(Cell::get).ok().flatten() else {
            return true;
        };
        let outer = RAN.try_with(|r| r.replace(0)).unwrap_or(0);
        drain_here();
        let ran = RAN.try_with(|r| r.replace(outer)).unwrap_or(0);
        let interrupted = ran & RAN_NO_RESTART != 0
            || (ran & RAN_RESTART != 0 && restart == Restart::Never);
        if interrupted {
            let _ = INTERRUPTED.try_with(|i| i.set(true));
            let _ = RESTARTING.try_with(|r| r.set(ran & RAN_NO_RESTART == 0));
        }
        !interrupted
    }
    #[cfg(not(unix))]
    true
}

/// Notes that a signal handler cut short the linger of a socket the calling thread is closing
/// (`SO_LINGER`), in an [`interruptible`] wait that has just returned interrupted, for the `close`
/// to report as the host's does (see `os::sockets::close`).
#[cfg(unix)]
pub fn close_interrupted() {
    let restarting = RESTARTING.try_with(Cell::get).unwrap_or(false);
    let _ = CLOSING.try_with(|c| c.set(Some(restarting)));
}

/// Whether a signal handler cut short the calling thread's `close` since it last asked, and if so
/// whether every handler that did was installed with `SA_RESTART`.
#[cfg(unix)]
pub(crate) fn take_close_interrupted() -> Option<bool> {
    CLOSING.try_with(|c| c.take()).ok().flatten()
}

/// What a signal handler, `sigwaitinfo` or `signalfd` is told of a signal: the `siginfo_t` fields
/// the kernel fills for one sent with kill(2) or for a child's end (man 2 sigaction, "The siginfo_t
/// argument to a SA_SIGINFO handler").
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalInfo {
    /// `si_signo`.
    pub signo: c_int,
    /// `si_code`: `SI_USER`, `SI_TKILL`, or a child's `CLD_*`.
    pub code: c_int,
    /// `si_pid`: the sender's, or the child's.
    pub pid: libc::pid_t,
    /// `si_uid`: the sender's real user id, or the child's.
    pub uid: libc::uid_t,
    /// `si_status`: a child's exit status or the signal that ended it; 0 otherwise.
    pub status: c_int,
}

/// What a handler is told of `posted`. The kernel fills `si_pid`/`si_uid` with the sender's (man 2
/// sigaction: "Signals sent with kill(2) and sigqueue(3) fill in si_pid and si_uid"). For
/// [`SignalSource::Process`] that is this process; a signal from the sim or forwarded from outside
/// names the parent process instead, a snare choice standing in for the shell or supervisor that
/// would have sent it. Called with the thread simulated, so `getuid` is the domain's.
#[cfg(unix)]
fn info_of(posted: Posted) -> SignalInfo {
    match posted.cause {
        Cause::Kill { tkill } => {
            // SAFETY: getpid, getppid and getuid have no preconditions.
            let (pid, uid) = unsafe {
                let pid = if posted.source == SignalSource::Process {
                    libc::getpid()
                } else {
                    libc::getppid()
                };
                (pid, libc::getuid())
            };
            SignalInfo {
                signo: posted.sig,
                code: si_code(tkill),
                pid,
                uid,
                status: 0,
            }
        }
        Cause::Child(exit) => SignalInfo {
            signo: posted.sig,
            code: exit.code,
            pid: exit.pid,
            uid: exit.uid,
            status: exit.status,
        },
    }
}

/// What a `signalfd` read or `sigwaitinfo` is told of `posted`, worked out with the thread
/// simulated (see [`info_of`]).
#[cfg(target_os = "linux")]
pub(crate) fn info(posted: Posted) -> SignalInfo {
    simulated(|| info_of(posted))
}

/// The `si_code` of a signal sent with kill(2), or with `tkill` aimed at one thread: `SI_USER`
/// (0) or `SI_TKILL` (-6), per include/uapi/asm-generic/siginfo.h and kernel/signal.c
/// `prepare_kill_siginfo` (man 2 sigaction, "The si_code field").
#[cfg(target_os = "linux")]
fn si_code(tkill: bool) -> c_int {
    if tkill { libc::SI_TKILL } else { libc::SI_USER }
}

/// The `si_code` handed to a Darwin handler: `SI_USER`, 0x10001 in XNU bsd/sys/signal.h, for
/// process- and thread-directed signals alike.
///
/// Note that the real kernel does not use this value for `kill`: XNU bsd/kern/kern_sig.c
/// `psignal_internal` stores `si_code = 0` ("an ordinary signal"), and on macOS 26 (arm64) a
/// `SA_SIGINFO` handler sees `si_code == 0` after `kill`, `raise` and `pthread_kill` alike. The
/// sim's value is pinned by `crates/snare/tests/signals.rs`, which asserts `0x10001`.
#[cfg(target_os = "macos")]
fn si_code(_tkill: bool) -> c_int {
    0x10001
}

/// Calls a handler as the kernel would for `posted`: with `siginfo` a `siginfo_t` naming the sender
/// or the child (see [`info_of`]), and a zeroed context. The context (`ucontext_t`) is all zeros:
/// handlers that inspect it are fault handlers, and the virtual signals are never faults.
///
/// # Safety
/// `address` is a handler of the shape `siginfo` says.
#[cfg(unix)]
unsafe fn call_handler(address: usize, siginfo: bool, posted: Posted) {
    if !siginfo {
        // SAFETY: the caller's handler.
        let handler: extern "C" fn(c_int) = unsafe { std::mem::transmute(address) };
        handler(posted.sig);
        return;
    }
    // SAFETY: as above.
    let handler: extern "C" fn(c_int, *mut libc::siginfo_t, *mut libc::c_void) =
        unsafe { std::mem::transmute(address) };
    // SAFETY: both are plain C structs for which all-zero is a valid value.
    let (mut info, mut context): (libc::siginfo_t, libc::ucontext_t) =
        unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
    let SignalInfo {
        signo,
        code,
        pid,
        uid,
        status,
    } = info_of(posted);
    fill_siginfo(&mut info, signo, code, pid, uid, status);
    handler(posted.sig, &mut info, (&raw mut context).cast());
}

/// Writes the fields a kill(2)-sent signal, or a child's `SIGCHLD`, carries into a zeroed
/// `siginfo_t`; `status` is the child's.
///
/// The `libc` crate exposes the Linux `siginfo_t` union only through accessor methods, so the
/// fields are written at their offsets. include/uapi/asm-generic/siginfo.h `__SIGINFO`:
/// `si_signo` (0), `si_errno` (4), `si_code` (8), then `union __sifields`, which holds pointers
/// and so is 8-byte aligned at 16 on LP64; its `_kill` member is `si_pid` (16) then `si_uid`
/// (20), and its `_sigchld` member the same two then `si_status` (24) and the child's
/// `si_utime`/`si_stime`, which stay zero. The whole struct is padded to `SI_MAX_SIZE`, 128 bytes. These offsets hold for the LP64
/// targets snare supports, not for 32-bit ones, where the union starts at 12, nor for MIPS
/// (`__ARCH_HAS_SWAPPED_SIGINFO`, `si_code` before `si_errno`).
#[cfg(target_os = "linux")]
pub(crate) fn fill_siginfo(
    info: &mut libc::siginfo_t,
    sig: c_int,
    code: c_int,
    pid: libc::pid_t,
    uid: libc::uid_t,
    status: c_int,
) {
    let base = (info as *mut libc::siginfo_t).cast::<u8>();
    // SAFETY: offsets inside the 128-byte siginfo_t, per the layout above.
    unsafe {
        base.cast::<c_int>().write(sig);
        base.add(8).cast::<c_int>().write(code);
        base.add(16).cast::<libc::pid_t>().write(pid);
        base.add(20).cast::<libc::uid_t>().write(uid);
        base.add(24).cast::<c_int>().write(status);
    }
}

/// Writes the fields a kill(2)-sent signal, or a child's `SIGCHLD`, carries; Darwin's
/// `siginfo_t` has plain named fields (XNU bsd/sys/signal.h, `struct __siginfo`).
#[cfg(target_os = "macos")]
pub(crate) fn fill_siginfo(
    info: &mut libc::siginfo_t,
    sig: c_int,
    code: c_int,
    pid: libc::pid_t,
    uid: libc::uid_t,
    status: c_int,
) {
    info.si_signo = sig;
    info.si_code = code;
    info.si_pid = pid;
    info.si_uid = uid;
    info.si_status = status;
}

/// Takes up to `max` signals of `wanted` pending for the calling thread, its own before its
/// process's, lowest number first, for a `signalfd` read (man 2 signalfd: "the read(2) returns
/// information for as many signals as are pending and will fit in the supplied buffer"), and logs
/// each as accepted. Empty off a domain with a signal table. Call it holding no lock of the
/// caller's: working out what the reader is told runs the thread's hooked calls (see
/// [`SignalInfo`]).
#[cfg(target_os = "linux")]
pub fn take_signals(wanted: u64, max: usize) -> Vec<SignalInfo> {
    let Some(domain) = crate::domain::signal_domain() else {
        return Vec::new();
    };
    let taken: Vec<Posted> = std::iter::from_fn(|| accept(domain, wanted))
        .take(max)
        .collect();
    taken.into_iter().map(info).collect()
}

/// Whether a signal of `wanted` is pending for the calling thread, its own or its process's: a
/// `signalfd`'s readiness, which Linux reads for the thread that polls it (fs/signalfd.c
/// `signalfd_poll` looks at `current`).
#[cfg(target_os = "linux")]
pub fn signals_pending(wanted: u64) -> bool {
    crate::domain::signal_domain().is_some_and(|domain| has_pending(domain, wanted))
}

/// How many signals have been left pending in the calling thread's domain so far: a `signalfd`'s
/// read wakes, for an edge-triggered wait to see a new one.
#[cfg(target_os = "linux")]
pub fn signal_generation() -> u64 {
    crate::domain::signal_domain()
        .map_or(0, |domain| domain.state().generation.load(Ordering::SeqCst))
}
