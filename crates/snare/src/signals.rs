//! Signals and console control events, per sim. The code under test installs its handlers with
//! the OS's own calls — `sigaction`/`signal` on unix, `SetConsoleCtrlHandler` and the CRT's `signal`
//! on Windows — so `ctrlc` and `signal-hook` run unchanged; the dispositions live
//! in the sim and the real process's are never touched. [`Sim::raise_signal`](crate::Sim) delivers
//! a signal as the host OS would: on unix the handler runs synchronously, as for a signal a process
//! sends itself; on Windows the handlers run on a new thread, last registered first.
//!
//! [`SignalTable`] is a sim's dispositions; [`SimSignals`] exposes it to `snare_interpose` as the
//! domain's [`Signals`], which the interposed `sigaction`/`signal`/`raise`/`kill`/`pthread_kill`
//! (unix) and `SetConsoleCtrlHandler`/`GenerateConsoleCtrlEvent`/CRT `signal`/`raise` (Windows)
//! consult. [`forward`] optionally routes real signals the process receives into the sims that
//! asked for them. Every table lock is taken inside [`snare_interpose::real`] or from a
//! [`Signals`] method (already in passthrough), and never held while a handler of the code under
//! test runs, since a handler may reinstall itself.

use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use snare_interpose::{SignalOutcome, SignalSource, Signals};

use crate::events::RecordedEvent;
use crate::scope::SimShared;

/// A signal or console control event the code under test can be sent.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Signal {
    /// `SIGINT`; `CTRL_C_EVENT` (0) on Windows.
    Interrupt,
    /// `SIGTERM` (unix only).
    Terminate,
    /// `SIGHUP` (unix only).
    Hangup,
    /// `CTRL_BREAK_EVENT` (1, Windows only).
    Break,
    /// `CTRL_CLOSE_EVENT` (2, Windows only).
    Close,
    /// `CTRL_LOGOFF_EVENT` (5, Windows only).
    Logoff,
    /// `CTRL_SHUTDOWN_EVENT` (6, Windows only).
    ///
    /// The event numbers are wincon.h's
    /// ([Microsoft Learn: HandlerRoutine](https://learn.microsoft.com/en-us/windows/console/handlerroutine)).
    Shutdown,
}

impl Signal {
    /// The host OS's number for this signal — a signal number on unix, a console control event on
    /// Windows — or `None` where the OS has no such signal.
    pub fn raw(self) -> Option<i32> {
        #[cfg(unix)]
        {
            match self {
                Signal::Interrupt => Some(libc::SIGINT),
                Signal::Terminate => Some(libc::SIGTERM),
                Signal::Hangup => Some(libc::SIGHUP),
                _ => None,
            }
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Console::{
                CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT,
                CTRL_SHUTDOWN_EVENT,
            };
            let event = match self {
                Signal::Interrupt => CTRL_C_EVENT,
                Signal::Break => CTRL_BREAK_EVENT,
                Signal::Close => CTRL_CLOSE_EVENT,
                Signal::Logoff => CTRL_LOGOFF_EVENT,
                Signal::Shutdown => CTRL_SHUTDOWN_EVENT,
                _ => return None,
            };
            Some(event as i32)
        }
    }

    /// The signal the host OS numbers `raw`, if it is one the sim models. The inverse of
    /// [`Signal::raw`].
    pub fn from_raw(raw: i32) -> Option<Signal> {
        [
            Signal::Interrupt,
            Signal::Terminate,
            Signal::Hangup,
            Signal::Break,
            Signal::Close,
            Signal::Logoff,
            Signal::Shutdown,
        ]
        .into_iter()
        .find(|signal| signal.raw() == Some(raw))
    }
}

/// What delivering a signal did.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignalDelivery {
    /// A handler of the code under test ran (on Windows: one returned `TRUE`).
    Handled,
    /// Handlers ran, after which Windows would end the process: a close, logoff or shutdown event.
    HandledThenExit,
    /// The OS default action applies — usually ending the process, which the sim never does.
    DefaultAction,
    /// The signal is ignored.
    Ignored,
    /// The host OS has no such signal.
    Unavailable,
}

/// Who sent a recorded signal.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalOrigin {
    /// The test, through [`SignalHandle`] or the `Sim` methods.
    Sim,
    /// The code under test: `raise`, `kill` of its own process, `pthread_kill`,
    /// `GenerateConsoleCtrlEvent`.
    Process,
    /// A real signal forwarded into the sim (see `SimBuilder::forward_real_signals`).
    Real,
}

impl From<SignalOutcome> for SignalDelivery {
    fn from(outcome: SignalOutcome) -> Self {
        match outcome {
            SignalOutcome::Handled => SignalDelivery::Handled,
            SignalOutcome::HandledThenExit => SignalDelivery::HandledThenExit,
            SignalOutcome::DefaultAction => SignalDelivery::DefaultAction,
            SignalOutcome::Ignored => SignalDelivery::Ignored,
        }
    }
}

impl From<SignalSource> for SignalOrigin {
    fn from(source: SignalSource) -> Self {
        match source {
            SignalSource::Sim => SignalOrigin::Sim,
            SignalSource::Process => SignalOrigin::Process,
            SignalSource::Real => SignalOrigin::Real,
        }
    }
}

/// Sends signals into one sim, from any thread: one of the sim's own, or one outside it.
#[derive(Clone)]
pub struct SignalHandle {
    /// The sim's shared state: its table, its log, and (weakly) its domain.
    shared: Arc<SimShared>,
}

impl std::fmt::Debug for SignalHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalHandle").finish_non_exhaustive()
    }
}

impl SignalHandle {
    /// A handle on the sim behind `shared`.
    pub(crate) fn new(shared: Arc<SimShared>) -> Self {
        SignalHandle { shared }
    }

    /// Delivers `signal` and returns what it did. From a thread of the sim it is delivered there,
    /// as a signal the process sent itself; from any other thread, on a new thread of the sim,
    /// joined before this returns.
    ///
    /// [`SignalDelivery::Unavailable`] when the host has no such signal, the sim's domain is gone,
    /// or the delivery thread could not be started. The result slot is written and read inside
    /// [`snare_interpose::real`] so the hand-off itself never counts as a simulated wait.
    pub fn raise(&self, signal: Signal) -> SignalDelivery {
        let Some(raw) = signal.raw() else {
            return SignalDelivery::Unavailable;
        };
        let Some(domain) = self.shared.domain.get().and_then(|d| d.upgrade()) else {
            return SignalDelivery::Unavailable;
        };
        if domain.is_current() {
            return deliver(&self.shared, raw, SignalSource::Sim);
        }
        let slot = Arc::new(Mutex::new(SignalDelivery::Unavailable));
        let shared = self.shared.clone();
        let out = slot.clone();
        let thread = domain.spawn_injected("snare-signal", move || {
            let delivery = deliver(&shared, raw, SignalSource::Sim);
            snare_interpose::real(|| *out.lock().unwrap() = delivery);
        });
        match thread {
            Ok(thread) => {
                let _ = thread.join();
                snare_interpose::real(|| *slot.lock().unwrap())
            }
            Err(_) => SignalDelivery::Unavailable,
        }
    }

    /// Delivers `signal` once `delay` of sim time has passed, on a thread of the sim that sleeps
    /// it out like any other — a virtual timer the sim can skip to.
    ///
    /// From a thread of the sim the timer thread is spawned with `std::thread` inside
    /// [`snare_interpose::simulated`], so the interposed thread creation adopts it into the
    /// domain; from outside, the domain injects it. With the domain gone the returned
    /// [`PendingSignal`] reports [`SignalDelivery::Unavailable`].
    pub fn raise_after(&self, signal: Signal, delay: Duration) -> PendingSignal {
        let slot = Arc::new(Mutex::new(None));
        let out = slot.clone();
        let handle = self.clone();
        let body = move || {
            std::thread::sleep(delay);
            let delivery = handle.raise(signal);
            snare_interpose::real(|| *out.lock().unwrap() = Some(delivery));
        };
        let domain = self.shared.domain.get().and_then(|d| d.upgrade());
        let thread = match domain {
            Some(domain) if domain.is_current() => snare_interpose::simulated(|| {
                std::thread::Builder::new()
                    .name("snare-signal-timer".into())
                    .spawn(body)
                    .ok()
            }),
            Some(domain) => domain.spawn_injected("snare-signal-timer", body).ok(),
            None => None,
        };
        PendingSignal { thread, slot }
    }
}

/// A signal [`SignalHandle::raise_after`] will deliver.
pub struct PendingSignal {
    /// The timer thread; `None` when it could not be started.
    thread: Option<JoinHandle<()>>,
    /// Where the timer thread leaves the delivery's outcome.
    slot: Arc<Mutex<Option<SignalDelivery>>>,
}

impl std::fmt::Debug for PendingSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingSignal")
            .field("started", &self.thread.is_some())
            .finish_non_exhaustive()
    }
}

impl PendingSignal {
    /// Waits for the delivery and returns what it did: [`SignalDelivery::Unavailable`] if the
    /// timer thread never ran or died before delivering.
    pub fn wait(self) -> SignalDelivery {
        if let Some(thread) = self.thread {
            let _ = thread.join();
        }
        snare_interpose::real(|| {
            self.slot
                .lock()
                .unwrap()
                .unwrap_or(SignalDelivery::Unavailable)
        })
    }
}

/// Delivers the host-numbered `raw` on the calling thread of the sim: synchronously, its handler
/// run before this returns (see [`snare_interpose::deliver_here`]).
#[cfg(unix)]
fn deliver(_shared: &Arc<SimShared>, raw: i32, source: SignalSource) -> SignalDelivery {
    snare_interpose::deliver_here(raw, source).map_or(SignalDelivery::Unavailable, Into::into)
}

/// Delivers the console event `raw` on a new thread of the sim, as Windows does, and waits for
/// the outcome within the OS's time limit for that event (see [`console::deliver_and_wait`]).
#[cfg(windows)]
fn deliver(shared: &Arc<SimShared>, raw: i32, source: SignalSource) -> SignalDelivery {
    console::deliver_and_wait(shared, raw as u32, source)
}

/// One sim's dispositions.
pub(crate) struct SignalTable {
    /// The `sigaction` installed for each virtual signal, seeded from the process's own (see
    /// [`forward::inherited`]) so an inherited `SIG_IGN` survives, as across exec(2) (man 7
    /// signal, "Signal dispositions": ignored signals stay ignored across execve).
    #[cfg(unix)]
    actions: Mutex<Actions>,
    /// See `SimBuilder::process_signal_handlers`.
    #[cfg(unix)]
    process_handlers: std::sync::atomic::AtomicBool,
    /// Console control handlers, the ignore-CTRL+C flag and the CRT's signal table.
    #[cfg(windows)]
    console: Mutex<console::Console>,
}

impl SignalTable {
    /// A fresh table: on unix the process's dispositions for `SIGINT`, `SIGTERM` and `SIGHUP` as
    /// they were before any sim forwarded them; on Windows no handlers, as a new console process
    /// starts with only the default handler
    /// ([Microsoft Learn: SetConsoleCtrlHandler](https://learn.microsoft.com/en-us/windows/console/setconsolectrlhandler)).
    pub(crate) fn new() -> Self {
        SignalTable {
            #[cfg(unix)]
            actions: Mutex::new(Actions {
                by_signal: [libc::SIGINT, libc::SIGTERM, libc::SIGHUP]
                    .into_iter()
                    .map(|sig| (sig, forward::inherited(sig)))
                    .collect(),
                set: std::collections::HashSet::new(),
            }),
            #[cfg(unix)]
            process_handlers: std::sync::atomic::AtomicBool::new(false),
            #[cfg(windows)]
            console: Mutex::default(),
        }
    }
}

/// A sim's `sigaction` table.
#[cfg(unix)]
struct Actions {
    by_signal: std::collections::HashMap<i32, libc::sigaction>,
    /// The signals the sim's own code has set an action for.
    set: std::collections::HashSet<i32>,
}

#[cfg(unix)]
type Handlers = std::collections::BTreeMap<i32, libc::sigaction>;

/// The handler the code under test last installed for each signal, in whichever sim: what a sim
/// built with `SimBuilder::process_signal_handlers` falls back to for a signal its own code never
/// set an action for.
#[cfg(unix)]
static PROCESS_HANDLERS: Mutex<Handlers> = Mutex::new(std::collections::BTreeMap::new());

#[cfg(unix)]
fn process_handlers() -> std::sync::MutexGuard<'static, Handlers> {
    PROCESS_HANDLERS.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(unix)]
fn is_handler(action: &libc::sigaction) -> bool {
    action.sa_sigaction != libc::SIG_DFL && action.sa_sigaction != libc::SIG_IGN
}

#[cfg(unix)]
impl SignalTable {
    /// Whether a signal the sim's code never set an action for reaches the process's handler.
    pub(crate) fn reach_process_handlers(&self, on: bool) {
        self.process_handlers
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The [`Signals`] a sim's domain is built with: its table, and its log for the deliveries.
pub(crate) struct SimSignals(pub(crate) Arc<SimShared>);

impl SimSignals {
    /// The sim's dispositions.
    fn table(&self) -> &SignalTable {
        &self.0.signals
    }
}

impl Signals for SimSignals {
    /// Swaps the stored action; a signal never set reads back as the process's inherited one.
    #[cfg(unix)]
    fn sigaction(&self, sig: i32, act: Option<&libc::sigaction>) -> libc::sigaction {
        let mut actions = self.table().actions.lock().unwrap();
        let previous = actions
            .by_signal
            .get(&sig)
            .copied()
            .unwrap_or_else(|| forward::inherited(sig));
        if let Some(act) = act {
            actions.by_signal.insert(sig, *act);
            actions.set.insert(sig);
            let mut process = process_handlers();
            if is_handler(act) {
                process.insert(sig, *act);
            } else if process
                .get(&sig)
                .is_some_and(|installed| installed.sa_sigaction == previous.sa_sigaction)
            {
                process.remove(&sig);
            }
        }
        previous
    }

    /// Reads the action for delivery. With `SA_RESETHAND` the stored handler is reset to
    /// `SIG_DFL` as it is taken (man 2 sigaction, `SA_RESETHAND`: "Restore the signal action to
    /// the default upon entry to the signal handler").
    #[cfg(unix)]
    fn take_disposition(&self, sig: i32) -> snare_interpose::Disposition {
        use snare_interpose::Disposition;
        let mut actions = self.table().actions.lock().unwrap();
        if !actions.set.contains(&sig)
            && self
                .table()
                .process_handlers
                .load(std::sync::atomic::Ordering::Relaxed)
            && let Some(installed) = process_handlers().get(&sig).copied()
        {
            actions.by_signal.insert(sig, installed);
            actions.set.insert(sig);
        }
        let Some(action) = actions.by_signal.get_mut(&sig) else {
            return Disposition::Default;
        };
        match action.sa_sigaction {
            libc::SIG_DFL => return Disposition::Default,
            libc::SIG_IGN => return Disposition::Ignore,
            _ => {}
        }
        let address = action.sa_sigaction;
        let resethand = action.sa_flags & libc::SA_RESETHAND != 0;
        let disposition = Disposition::Handler {
            address,
            siginfo: action.sa_flags & libc::SA_SIGINFO != 0,
            // POSIX lets SA_RESETHAND act as if SA_NODEFER were set (IEEE Std 1003.1-2024,
            // sigaction: "sigaction() may behave as if the SA_NODEFER flag were also set"); the sim
            // takes that option on Linux only. Linux itself does not (kernel/signal.c
            // signal_delivered blocks the signal unless SA_NODEFER), nor does XNU
            // (bsd/kern/kern_sig.c postsig_locked checks ps_signodefer only).
            nodefer: action.sa_flags & libc::SA_NODEFER != 0
                || (resethand && cfg!(target_os = "linux")),
        };
        if resethand {
            action.sa_sigaction = libc::SIG_DFL;
        }
        disposition
    }

    /// See [`console::Console::set_handler`].
    #[cfg(windows)]
    fn set_console_ctrl_handler(&self, handler: usize, add: bool) -> Result<(), u32> {
        self.table()
            .console
            .lock()
            .unwrap()
            .set_handler(handler, add)
    }

    /// Starts the handlers on a new thread of the sim and returns at once:
    /// `GenerateConsoleCtrlEvent` does not wait for them.
    #[cfg(windows)]
    fn console_event(&self, event: u32) {
        console::deliver_async(&self.0, event, SignalSource::Process);
    }

    /// See [`console::Console::crt_signal`].
    #[cfg(windows)]
    fn crt_signal(&self, sig: i32, handler: usize) -> usize {
        self.table()
            .console
            .lock()
            .unwrap()
            .crt_signal(sig, handler)
    }

    /// Runs the CRT handler on the calling thread and returns 0, as UCRT `raise` does after a
    /// handler or `SIG_IGN` (ucrt/misc/signal.cpp `raise`); where the real CRT would `_exit(3)`
    /// for `SIG_DFL`, the sim records the default action and also returns 0.
    #[cfg(windows)]
    fn crt_raise(&self, sig: i32) -> i32 {
        console::crt_raise(&self.0, sig);
        0
    }

    /// Logs the delivery to the sim's event record.
    fn record(&self, raw: i32, source: SignalSource, outcome: SignalOutcome) {
        record(&self.0, raw, source, outcome.into());
    }
}

/// Logs a delivery of the host-numbered `raw` as a [`RecordedEvent::Signal`]; numbers the sim
/// does not model are dropped. Callers hold no table lock.
fn record(shared: &SimShared, raw: i32, source: SignalSource, delivery: SignalDelivery) {
    if let Some(signal) = Signal::from_raw(raw) {
        shared.record(RecordedEvent::Signal {
            signal,
            origin: source.into(),
            delivery,
        });
    }
}

/// Process-wide forwarding of real signals into the sims that opted in.
///
/// While at least one sim is registered, the process's own actions for `SIGINT`, `SIGTERM` and
/// `SIGHUP` are replaced by `on_signal`, which only writes the signal number to a pipe (the
/// self-pipe trick: write(2) is async-signal-safe, man 7 signal-safety). A reader thread turns
/// each byte into a delivery into every registered sim, outside signal context. The last
/// [`Registration`](forward::Registration) dropped puts the original actions back.
///
/// Lock order: a sim's table lock, then `FORWARDER` (`SimSignals::sigaction` reads
/// `inherited` while holding its table). `FORWARDER` is never held while a table lock is taken
/// or a handler runs: `forward` copies the sims out and releases it first.
#[cfg(unix)]
pub(crate) mod forward {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::{Arc, Mutex};

    use snare_interpose::{SignalOutcome, SignalSource};

    use crate::scope::SimShared;

    /// The signals forwarded: the virtual ones (see `snare_interpose::is_virtual`).
    const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

    /// The forwarding state while any sim is registered.
    #[derive(Default)]
    struct Forwarder {
        /// The id the last [`Registration`] got; ids are never reused.
        next_id: u64,
        /// The registered sims, in registration order.
        sims: Vec<(u64, Arc<SimShared>)>,
        /// The process's actions displaced by [`on_signal`], restored by the last registration out
        /// and borrowed for one delivery when no sim takes a signal.
        originals: HashMap<libc::c_int, libc::sigaction>,
    }

    /// `Some` exactly while a sim is registered and [`on_signal`] is installed.
    static FORWARDER: Mutex<Option<Forwarder>> = Mutex::new(None);
    /// The write end of the pipe the real handlers write to. Opened once and never closed, so a
    /// signal landing while the last sim stops forwarding never writes to a reused descriptor.
    static PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);
    /// Opens the pipe and starts the reader thread, once per process.
    static PIPE: std::sync::OnceLock<()> = std::sync::OnceLock::new();

    /// A sim's place among the forwarding targets; dropping it takes the sim out, and the last one
    /// out puts the process's own dispositions back.
    pub(crate) struct Registration(u64);

    impl Drop for Registration {
        /// Removes the sim; the last one out restores the process's original actions.
        fn drop(&mut self) {
            snare_interpose::real(|| {
                let mut slot = FORWARDER.lock().unwrap();
                let Some(forwarder) = slot.as_mut() else {
                    return;
                };
                forwarder.sims.retain(|(id, _)| *id != self.0);
                if !forwarder.sims.is_empty() {
                    return;
                }
                let forwarder = slot.take().expect("forwarder");
                for (sig, original) in &forwarder.originals {
                    // SAFETY: putting back the action read when forwarding began.
                    unsafe { libc::sigaction(*sig, original, std::ptr::null_mut()) };
                }
            });
        }
    }

    /// The disposition the process had for `sig` before any sim forwarded it: what a new sim's
    /// table starts from, so an inherited `SIG_IGN` reads back. While forwarding, the saved
    /// original; otherwise a query of the live action (man 2 sigaction: a null `act` only reads).
    pub(crate) fn inherited(sig: libc::c_int) -> libc::sigaction {
        snare_interpose::real(|| {
            if let Some(original) = FORWARDER
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|f| f.originals.get(&sig).copied())
            {
                return original;
            }
            // SAFETY: a query only fills `old`.
            unsafe {
                let mut old: libc::sigaction = std::mem::zeroed();
                libc::sigaction(sig, std::ptr::null(), &mut old);
                old
            }
        })
    }

    /// The real handler while forwarding: writes the signal number as one byte to the pipe.
    ///
    /// Only async-signal-safe work is allowed here (man 7 signal-safety): a single write(2) to a
    /// descriptor that is never closed, with `errno` saved and restored so the interrupted code
    /// does not see it change (man 7 signal-safety, "errno"). Signal numbers fit a byte (all
    /// below 32 for the forwarded set).
    extern "C" fn on_signal(sig: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {
        let byte = sig as u8;
        // SAFETY: errno is the interrupted code's and goes back as it was; write(2) is
        // async-signal-safe, and a full pipe only loses this signal.
        unsafe {
            let errno = errno_location();
            let saved = *errno;
            libc::write(
                PIPE_WRITE.load(Ordering::SeqCst),
                (&raw const byte).cast(),
                1,
            );
            *errno = saved;
        }
    }

    /// The calling thread's `errno` (glibc `__errno_location`, csu/errno-loc.c).
    #[cfg(target_os = "linux")]
    unsafe fn errno_location() -> *mut libc::c_int {
        // SAFETY: the calling thread's errno.
        unsafe { libc::__errno_location() }
    }

    /// The calling thread's `errno` (Darwin libc `__error`, <sys/errno.h>).
    #[cfg(not(target_os = "linux"))]
    unsafe fn errno_location() -> *mut libc::c_int {
        // SAFETY: the calling thread's errno.
        unsafe { libc::__error() }
    }

    /// Adds `shared` to the sims real signals are forwarded to, installing the forwarder first if
    /// it is the first.
    pub(crate) fn register(shared: Arc<SimShared>) -> Registration {
        snare_interpose::real(|| {
            let mut slot = FORWARDER.lock().unwrap();
            let forwarder = slot.get_or_insert_with(install);
            forwarder.next_id += 1;
            let id = forwarder.next_id;
            forwarder.sims.push((id, shared));
            Registration(id)
        })
    }

    /// Installs [`on_signal`] for every forwarded signal, saving the actions it displaces, and on
    /// first use opens the pipe and starts the reader thread.
    ///
    /// `SA_RESTART` keeps a real signal from failing the process's blocking calls with `EINTR`
    /// (man 7 signal, "Interruption of system calls and library functions by signal handlers");
    /// an empty `sa_mask` blocks nothing extra while the one-byte write runs. Called with
    /// [`FORWARDER`] held.
    fn install() -> Forwarder {
        PIPE.get_or_init(|| {
            let mut fds = [0; 2];
            // SAFETY: pipe fills `fds`.
            assert_eq!(
                unsafe { libc::pipe(fds.as_mut_ptr()) },
                0,
                "pipe for signal forwarding"
            );
            PIPE_WRITE.store(fds[1], Ordering::SeqCst);
            let read = fds[0];
            let _ = std::thread::Builder::new()
                .name("snare-signal-forwarder".into())
                .spawn(move || {
                    let _service = snare_interpose::service_thread();
                    read_forwarded(read);
                });
        });
        let mut originals = HashMap::new();
        for sig in SIGNALS {
            // SAFETY: installs a handler that only writes to the pipe; reads back the old action.
            unsafe {
                let mut act: libc::sigaction = std::mem::zeroed();
                act.sa_sigaction = on_signal as *const () as libc::sighandler_t;
                act.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
                libc::sigemptyset(&mut act.sa_mask);
                let mut old: libc::sigaction = std::mem::zeroed();
                libc::sigaction(sig, &act, &mut old);
                originals.insert(sig, old);
            }
        }
        Forwarder {
            next_id: 0,
            sims: Vec::new(),
            originals,
        }
    }

    /// The reader thread: one byte per real signal, forwarded until the pipe closes or fails.
    /// `EINTR` (a signal landing on this thread mid-read) is retried.
    fn read_forwarded(read: libc::c_int) {
        loop {
            let mut byte = 0u8;
            // SAFETY: reads one byte into `byte`.
            let n = unsafe { libc::read(read, (&raw mut byte).cast(), 1) };
            if n == 0 {
                break;
            }
            if n < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            forward(libc::c_int::from(byte));
        }
        // SAFETY: the pipe's read end, owned by this reader.
        unsafe { libc::close(read) };
    }

    /// Delivers a real `sig` into every forwarding sim; if none handled or ignored it, the process
    /// gets it as it would have without the sims.
    ///
    /// Each sim gets it on a thread its domain injects, joined before the next sim, so the
    /// handlers run as managed code. Falling back puts the original action back, re-raises
    /// (raise(3), delivered before it returns), then reinstalls [`on_signal`]; with the original
    /// `SIG_DFL` that ends the process as the signal would have.
    fn forward(sig: libc::c_int) {
        let (sims, original) = {
            let slot = FORWARDER.lock().unwrap();
            let Some(forwarder) = slot.as_ref() else {
                return;
            };
            let sims: Vec<Arc<SimShared>> = forwarder.sims.iter().map(|(_, s)| s.clone()).collect();
            (sims, forwarder.originals.get(&sig).copied())
        };
        let mut taken = false;
        for shared in sims {
            let Some(domain) = shared.domain.get().and_then(|d| d.upgrade()) else {
                continue;
            };
            let outcome = Arc::new(Mutex::new(None));
            let out = outcome.clone();
            let thread = domain.spawn_injected("snare-signal-forward", move || {
                let r = snare_interpose::deliver_here(sig, SignalSource::Real);
                snare_interpose::real(|| *out.lock().unwrap() = r);
            });
            if let Ok(thread) = thread {
                let _ = thread.join();
            }
            taken |= matches!(
                *outcome.lock().unwrap(),
                Some(
                    SignalOutcome::Handled
                        | SignalOutcome::HandledThenExit
                        | SignalOutcome::Ignored
                )
            );
        }
        if taken {
            return;
        }
        let Some(original) = original else {
            return;
        };
        // SAFETY: the process's own action goes back for one real delivery, then the forwarder's.
        unsafe {
            let mut ours: libc::sigaction = std::mem::zeroed();
            libc::sigaction(sig, &original, &mut ours);
            libc::raise(sig);
            libc::sigaction(sig, &ours, std::ptr::null_mut());
        }
    }
}

/// Process-wide forwarding of real console control events into the sims that opted in.
///
/// While any sim is registered, `on_event` sits in the process's real console handler list.
/// Windows calls it on a thread of its own for each event; it delivers into every registered sim
/// and returns `TRUE` if any of them took the event, `FALSE` to let the next handler (finally the
/// default `ExitProcess`) run
/// ([Microsoft Learn: HandlerRoutine](https://learn.microsoft.com/en-us/windows/console/handlerroutine)).
#[cfg(windows)]
pub(crate) mod forward {
    use std::sync::{Arc, Mutex};

    use snare_interpose::SignalSource;

    use crate::scope::SimShared;

    /// The registered sims.
    #[derive(Default)]
    struct Forwarder {
        /// The id the last [`Registration`] got; ids are never reused.
        next_id: u64,
        /// The registered sims, in registration order.
        sims: Vec<(u64, Arc<SimShared>)>,
    }

    /// `Some` exactly while a sim is registered and [`on_event`] is installed.
    static FORWARDER: Mutex<Option<Forwarder>> = Mutex::new(None);

    /// A sim's place among the forwarding targets; dropping it takes the sim out, and the last one
    /// out removes [`on_event`] from the process's handler list.
    pub(crate) struct Registration(u64);

    impl Drop for Registration {
        /// Removes the sim; the last one out unregisters [`on_event`].
        fn drop(&mut self) {
            snare_interpose::real(|| {
                let mut slot = FORWARDER.lock().unwrap();
                let Some(forwarder) = slot.as_mut() else {
                    return;
                };
                forwarder.sims.retain(|(id, _)| *id != self.0);
                if forwarder.sims.is_empty() {
                    *slot = None;
                    // SAFETY: removes the handler `register` added.
                    unsafe {
                        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(
                            Some(on_event),
                            0,
                        )
                    };
                }
            });
        }
    }

    /// The real console control handler while forwarding. Delivers `event` into each sim in turn,
    /// on a thread its domain injects, waiting for each within the OS's time limit
    /// ([`super::console::deliver_and_wait`]). The sims are copied out before any is delivered
    /// to, so [`FORWARDER`] is not held while handlers run.
    unsafe extern "system" fn on_event(event: u32) -> windows_sys::core::BOOL {
        let sims: Vec<Arc<SimShared>> = snare_interpose::real(|| {
            FORWARDER
                .lock()
                .unwrap()
                .as_ref()
                .map(|f| f.sims.iter().map(|(_, s)| s.clone()).collect())
                .unwrap_or_default()
        });
        let mut taken = false;
        for shared in sims {
            let Some(domain) = shared.domain.get().and_then(|d| d.upgrade()) else {
                continue;
            };
            let out = Arc::new(Mutex::new(None));
            let slot = out.clone();
            let thread = domain.spawn_injected("snare-signal-forward", move || {
                let delivery = super::console::deliver_and_wait(&shared, event, SignalSource::Real);
                snare_interpose::real(|| *slot.lock().unwrap() = Some(delivery));
            });
            if let Ok(thread) = thread {
                let _ = thread.join();
            }
            taken |= matches!(
                *out.lock().unwrap(),
                Some(
                    super::SignalDelivery::Handled
                        | super::SignalDelivery::HandledThenExit
                        | super::SignalDelivery::Ignored
                )
            );
        }
        taken.into()
    }

    /// Adds `shared` to the sims real console events are forwarded to, adding [`on_event`] to
    /// the process's handler list if it is the first.
    pub(crate) fn register(shared: Arc<SimShared>) -> Registration {
        snare_interpose::real(|| {
            let mut slot = FORWARDER.lock().unwrap();
            let forwarder = slot.get_or_insert_with(|| {
                // SAFETY: adds a handler that forwards into the registered sims.
                unsafe {
                    windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_event), 1)
                };
                Forwarder::default()
            });
            forwarder.next_id += 1;
            let id = forwarder.next_id;
            forwarder.sims.push((id, shared));
            Registration(id)
        })
    }
}

/// Console control handlers and the CRT's signal table, as Windows keeps them.
///
/// The handler list follows SetConsoleCtrlHandler and HandlerRoutine on Microsoft Learn: handlers
/// are called last-registered first until one returns `TRUE`, each event on a new thread, with a
/// time limit for close/logoff/shutdown. The CRT part follows the UCRT's `signal`/`raise`
/// (ucrt/misc/signal.cpp in the Windows SDK sources): the first `signal(SIGINT | SIGBREAK, ..)`
/// registers the CRT's own console handler (`ctrlevent_capture`), which maps `CTRL_C_EVENT` to
/// `SIGINT` and every other event to `SIGBREAK`, resets a function handler to `SIG_DFL` before
/// calling it, and returns `FALSE` for `SIG_DFL` so the next handler runs. The sim passes only
/// `CTRL_BREAK_EVENT` to the `SIGBREAK` handler (see `console::run_handlers`).
///
/// Lock rule: the [`Console`](console::Console) mutex is taken only inside [`snare_interpose::real`] or a
/// [`Signals`] method, and is released before any handler is called.
#[cfg(windows)]
mod console {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::time::Duration;

    use snare_interpose::SignalSource;
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };

    use super::SignalDelivery;
    use crate::readiness::{Deadline, readiness};
    use crate::scope::SimShared;

    // winerror.h: ERROR_INVALID_PARAMETER (87). Microsoft Learn's SetConsoleCtrlHandler page gives
    // no error code for removing a handler never added; 87 is snare's choice, pinned by
    // crates/snare/tests/signals_win.rs `remove_unregistered`.
    const ERROR_INVALID_PARAMETER: u32 = 87;
    // signal.h (UCRT): SIGINT 2, SIGBREAK 21, SIG_DFL ((void (*)(int))0), SIG_IGN ((void (*)(int))1).
    const SIGINT: i32 = 2;
    const SIGBREAK: i32 = 21;
    const SIG_DFL: usize = 0;
    const SIG_IGN: usize = 1;
    /// Where the CRT's own console handler sits in the list once `signal(SIGINT | SIGBREAK, ..)`
    /// installed it. A snare sentinel: no function lives at `usize::MAX`.
    const CRT_HANDLER: usize = usize::MAX;

    /// One sim's console state.
    #[derive(Default)]
    pub(super) struct Console {
        /// Registered `HandlerRoutine` addresses in registration order (called from the back),
        /// with [`CRT_HANDLER`] standing for the CRT's own. A handler added twice appears twice,
        /// as in Windows' list.
        handlers: Vec<usize>,
        /// `SetConsoleCtrlHandler(NULL, TRUE)` is in force: `CTRL_C_EVENT` reaches no handler.
        /// `CTRL_BREAK_EVENT` is unaffected
        /// ([Microsoft Learn: GenerateConsoleCtrlEvent](https://learn.microsoft.com/en-us/windows/console/generateconsolectrlevent):
        /// "CTRL+BREAK signals always cause the handler functions to be called").
        ignore_ctrl_c: bool,
        /// The CRT `signal` table: handler (or `SIG_DFL`/`SIG_IGN`) per signal number; absent is
        /// `SIG_DFL`.
        crt: HashMap<i32, usize>,
    }

    impl Console {
        /// `SetConsoleCtrlHandler(handler, add)`: a null `handler` sets or clears the ignore-CTRL+C
        /// flag; otherwise `add` appends it and removal drops its most recent registration
        /// (Microsoft Learn does not say which of two registrations goes; newest is snare's
        /// choice). Removing one that is not registered fails with `ERROR_INVALID_PARAMETER`.
        pub(super) fn set_handler(&mut self, handler: usize, add: bool) -> Result<(), u32> {
            if handler == 0 {
                self.ignore_ctrl_c = add;
                return Ok(());
            }
            if add {
                self.handlers.push(handler);
                return Ok(());
            }
            match self.handlers.iter().rposition(|&h| h == handler) {
                Some(i) => {
                    self.handlers.remove(i);
                    Ok(())
                }
                None => Err(ERROR_INVALID_PARAMETER),
            }
        }

        /// The CRT's `signal(sig, handler)`: stores `handler`, returning the previous one
        /// (`SIG_DFL` if none), and for `SIGINT`/`SIGBREAK` registers the CRT's console handler
        /// the first time, as UCRT `signal` does with `SetConsoleCtrlHandler(ctrlevent_capture,
        /// TRUE)`. The CRT handler is never unregistered afterwards.
        pub(super) fn crt_signal(&mut self, sig: i32, handler: usize) -> usize {
            if matches!(sig, SIGINT | SIGBREAK) && !self.handlers.contains(&CRT_HANDLER) {
                self.handlers.push(CRT_HANDLER);
            }
            self.crt.insert(sig, handler).unwrap_or(SIG_DFL)
        }

        /// Takes the CRT handler for `sig`, resetting a function to `SIG_DFL` as the CRT does
        /// before calling it ([Microsoft Learn: signal](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/signal):
        /// "Before the specified function is executed, the value of func is set to SIG_DFL").
        fn take_crt(&mut self, sig: i32) -> usize {
            let handler = self.crt.get(&sig).copied().unwrap_or(SIG_DFL);
            if handler != SIG_DFL && handler != SIG_IGN {
                self.crt.insert(sig, SIG_DFL);
            }
            handler
        }
    }

    /// Locks `shared`'s console state. Callers must be in passthrough and must drop the guard
    /// before calling any handler.
    fn table(shared: &SimShared) -> std::sync::MutexGuard<'_, Console> {
        shared.signals.console.lock().unwrap()
    }

    /// The console event the CRT's `sig` stands for, for the log: `SIGINT` is `CTRL_C_EVENT`,
    /// `SIGBREAK` is `CTRL_BREAK_EVENT`. Other CRT signals (`SIGTERM`) are not logged.
    fn event_of(sig: i32) -> Option<i32> {
        match sig {
            SIGINT => Some(CTRL_C_EVENT as i32),
            SIGBREAK => Some(CTRL_BREAK_EVENT as i32),
            _ => None,
        }
    }

    /// Calls CRT handler `handler` for `sig`, returning whether it counts as handled, as
    /// `ctrlevent_capture` returns it: `SIG_DFL` is not (`FALSE`, the next console handler
    /// runs), `SIG_IGN` and a function are (`TRUE`). The function runs as simulated code.
    fn call_crt(handler: usize, sig: i32) -> bool {
        match handler {
            SIG_DFL => false,
            SIG_IGN => true,
            f => {
                // SAFETY: the code under test registered `f` as a CRT signal handler.
                let f: extern "C" fn(i32) = unsafe { std::mem::transmute(f) };
                snare_interpose::simulated(|| f(sig));
                true
            }
        }
    }

    /// The CRT's `raise(sig)`: synchronous, on the calling thread
    /// ([Microsoft Learn: raise](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/raise)).
    /// A `SIG_DFL` would make the real CRT end the process with exit code 3 (Microsoft Learn:
    /// signal, "By default, signal terminates the calling program with exit code 3"; UCRT `raise`
    /// calls `_exit(3)` for every signal, although the raise page lists `SIGTERM` as ignored); the
    /// sim only records [`SignalDelivery::DefaultAction`].
    pub(super) fn crt_raise(shared: &SimShared, sig: i32) {
        let handler = snare_interpose::real(|| table(shared).take_crt(sig));
        let delivery = match handler {
            SIG_DFL => SignalDelivery::DefaultAction,
            SIG_IGN => SignalDelivery::Ignored,
            _ => SignalDelivery::Handled,
        };
        if let Some(event) = event_of(sig) {
            snare_interpose::real(|| super::record(shared, event, SignalSource::Process, delivery));
        }
        call_crt(handler, sig);
    }

    /// Whether this process counts as a Windows (GUI) application, to which the system does not
    /// deliver `CTRL_LOGOFF_EVENT` or `CTRL_SHUTDOWN_EVENT`: "If a console application loads the
    /// gdi32.dll or user32.dll library, the HandlerRoutine function ... does not get called for
    /// the CTRL_LOGOFF_EVENT and CTRL_SHUTDOWN_EVENT events"
    /// ([Microsoft Learn: SetConsoleCtrlHandler](https://learn.microsoft.com/en-us/windows/console/setconsolectrlhandler)).
    /// Asked of the real process with `GetModuleHandleW`, which does not load anything.
    fn user_session_ignored() -> bool {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        let loaded = |name: &str| {
            let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            // SAFETY: a NUL-terminated module name; the refcount is untouched.
            !unsafe { GetModuleHandleW(wide.as_ptr()) }.is_null()
        };
        loaded("user32.dll") || loaded("gdi32.dll")
    }

    /// The outcome slot's value while the handlers are still running.
    const PENDING: u8 = 0;

    /// A [`SignalDelivery`] as a nonzero byte, so the outcome can be handed over in an atomic
    /// that [`deliver_and_wait`] polls from its readiness wait.
    fn encode(delivery: SignalDelivery) -> u8 {
        match delivery {
            SignalDelivery::Handled => 1,
            SignalDelivery::HandledThenExit => 2,
            SignalDelivery::DefaultAction => 3,
            SignalDelivery::Ignored => 4,
            _ => 5,
        }
    }

    /// The inverse of [`encode`]; `None` for [`PENDING`].
    fn decode(code: u8) -> Option<SignalDelivery> {
        Some(match code {
            1 => SignalDelivery::Handled,
            2 => SignalDelivery::HandledThenExit,
            3 => SignalDelivery::DefaultAction,
            4 => SignalDelivery::Ignored,
            5 => SignalDelivery::Unavailable,
            _ => return None,
        })
    }

    /// Runs the handlers for `event`, last registered first, until one returns `TRUE`, as the
    /// thread Windows creates for a console event does
    /// ([Microsoft Learn: HandlerRoutine](https://learn.microsoft.com/en-us/windows/console/handlerroutine)).
    ///
    /// The outcome is decided, and recorded, before any handler runs when it does not depend on
    /// them: `CTRL_C_EVENT` under the ignore flag and logoff/shutdown in a GUI process are
    /// [`Ignored`](SignalDelivery::Ignored) and run nothing; a close, logoff or shutdown ends the
    /// process whatever the handlers return (returning `TRUE` only stops the remaining handlers,
    /// "the system terminates the process"), so it is
    /// [`HandledThenExit`](SignalDelivery::HandledThenExit) with handlers registered and
    /// [`DefaultAction`](SignalDelivery::DefaultAction) without. Otherwise the outcome is
    /// recorded after the handlers: `Handled` if one returned `TRUE`, else `DefaultAction` (the
    /// default handler's `ExitProcess`, which the sim does not carry out). The CRT's handler only
    /// takes `CTRL_C_EVENT` and `CTRL_BREAK_EVENT` here and is skipped for close, logoff and
    /// shutdown, where the real `ctrlevent_capture` would run the `SIGBREAK` handler.
    fn run_handlers(shared: &SimShared, event: u32, source: SignalSource) -> SignalDelivery {
        let closing = matches!(
            event,
            CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT
        );
        let (handlers, ignore) = snare_interpose::real(|| {
            let console = table(shared);
            (console.handlers.clone(), console.ignore_ctrl_c)
        });
        let early = if (event == CTRL_C_EVENT && ignore)
            || (matches!(event, CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT) && user_session_ignored())
        {
            Some(SignalDelivery::Ignored)
        } else if closing {
            Some(if handlers.is_empty() {
                SignalDelivery::DefaultAction
            } else {
                SignalDelivery::HandledThenExit
            })
        } else {
            None
        };
        if let Some(delivery) = early {
            snare_interpose::real(|| super::record(shared, event as i32, source, delivery));
            if delivery != SignalDelivery::HandledThenExit {
                return delivery;
            }
        }
        let mut handled = false;
        for &handler in handlers.iter().rev() {
            let taken = if handler == CRT_HANDLER {
                let sig = match event {
                    CTRL_C_EVENT => SIGINT,
                    CTRL_BREAK_EVENT => SIGBREAK,
                    _ => continue,
                };
                let crt = snare_interpose::real(|| table(shared).take_crt(sig));
                call_crt(crt, sig)
            } else {
                // SAFETY: the code under test registered `handler` as a console control handler.
                let f: unsafe extern "system" fn(u32) -> i32 =
                    unsafe { std::mem::transmute(handler) };
                snare_interpose::simulated(|| unsafe { f(event) }) != 0
            };
            if taken {
                handled = true;
                break;
            }
        }
        if let Some(delivery) = early {
            return delivery;
        }
        let delivery = if handled {
            SignalDelivery::Handled
        } else {
            SignalDelivery::DefaultAction
        };
        snare_interpose::real(|| super::record(shared, event as i32, source, delivery));
        delivery
    }

    /// Starts the handlers for `event` on a new thread of the sim, as Windows does, and returns
    /// the slot the outcome lands in.
    ///
    /// From a thread of the sim the thread is spawned inside [`snare_interpose::simulated`] so
    /// the interposed thread creation adopts it; from outside, the domain injects it. The thread
    /// bumps the readiness counter after storing the outcome so a waiter in
    /// [`deliver_and_wait`] re-checks. If no thread could be started the slot holds
    /// [`SignalDelivery::Unavailable`]; with the domain gone it stays [`PENDING`].
    fn spawn_delivery(shared: &Arc<SimShared>, event: u32, source: SignalSource) -> Arc<AtomicU8> {
        let slot = Arc::new(AtomicU8::new(PENDING));
        let out = slot.clone();
        let target = shared.clone();
        let body = move || {
            let delivery = run_handlers(&target, event, source);
            out.store(encode(delivery), Ordering::SeqCst);
            snare_interpose::real(|| target.bump());
        };
        let domain = shared.domain.get().and_then(|d| d.upgrade());
        let spawned = match domain {
            Some(domain) if domain.is_current() => snare_interpose::simulated(|| {
                std::thread::Builder::new()
                    .name("snare-console-event".into())
                    .spawn(body)
                    .map(drop)
            }),
            Some(domain) => domain.spawn_injected("snare-console-event", body).map(drop),
            None => Ok(()),
        };
        if spawned.is_err() {
            slot.store(encode(SignalDelivery::Unavailable), Ordering::SeqCst);
        }
        slot
    }

    /// `GenerateConsoleCtrlEvent`'s delivery: starts the handlers and does not wait.
    pub(super) fn deliver_async(shared: &Arc<SimShared>, event: u32, source: SignalSource) {
        spawn_delivery(shared, event, source);
    }

    /// Delivers `event` and waits for its outcome as long as Windows would let the handlers run
    /// before ending the process: without limit for CTRL+C and CTRL+BREAK, 5 s for a close and
    /// 20 s for a logoff or shutdown, in sim time. A wait that runs out reports
    /// [`SignalDelivery::HandledThenExit`]: Windows would end the process with the handler still
    /// running.
    ///
    /// The limits follow the "Timeouts" table of
    /// [Microsoft Learn: HandlerRoutine](https://learn.microsoft.com/en-us/windows/console/handlerroutine):
    /// `CTRL_CLOSE_EVENT` `SPI_GETHUNGAPPTIMEOUT`, 5000 ms; `CTRL_C`/`CTRL_BREAK` no timeout. For
    /// logoff and shutdown that table gives `SPI_GETWAITTOKILLTIMEOUT`, 5000 ms, for an ordinary
    /// process and `SPI_GETWAITTOKILLSERVICETIMEOUT`, 20000 ms, for a service at shutdown; the sim
    /// uses the 20 s service figure for both.
    pub(super) fn deliver_and_wait(
        shared: &Arc<SimShared>,
        event: u32,
        source: SignalSource,
    ) -> SignalDelivery {
        let slot = spawn_delivery(shared, event, source);
        let limit = match event {
            CTRL_CLOSE_EVENT => Some(Duration::from_secs(5)),
            CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => Some(Duration::from_secs(20)),
            _ => None,
        };
        let deadline = snare_interpose::real(|| limit.map(Deadline::timeout));
        snare_interpose::real(|| {
            readiness().wait_until("signal", deadline, || {
                slot.load(Ordering::SeqCst) != PENDING
            })
        });
        match decode(slot.load(Ordering::SeqCst)) {
            Some(delivery) => delivery,
            None if limit.is_some() => SignalDelivery::HandledThenExit,
            None => SignalDelivery::Handled,
        }
    }
}
