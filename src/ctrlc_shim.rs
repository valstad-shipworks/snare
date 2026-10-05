use std::sync::{Arc, Once, Weak};

use parking_lot::Mutex;

pub use ::ctrlc::{Error, Signal, SignalType};

use crate::OsSemantics;
use crate::sched::{Unparker, current_unparker, mark_background, park_as};

#[derive(Default)]
pub(crate) struct CtrlcSlot {
    state: Mutex<SlotState>,
}

#[derive(Default)]
struct SlotState {
    installed: bool,
    pending: u64,
    unparker: Option<Unparker>,
}

static SLOTS: Mutex<Vec<Weak<CtrlcSlot>>> = Mutex::new(Vec::new());
static OS_HANDLER: Once = Once::new();

/// Register the Ctrl-C handler for the calling thread's state slot. On a
/// thread with no state slot this is [`::ctrlc::set_handler`].
///
/// Starts a dedicated `ctrl-c` thread (through [`crate::thread`]) that runs
/// `user_handler` once for every Ctrl-C delivered to the slot, whether by
/// [`raise`] or by a real Ctrl-C. Returns [`Error::MultipleHandlers`] if the
/// slot already has a handler.
///
/// # Errors
/// [`Error::MultipleHandlers`] if a handler is set, [`Error::System`] if the
/// handler thread could not be spawned.
pub fn set_handler<F>(user_handler: F) -> Result<(), Error>
where
    F: FnMut() + 'static + Send,
{
    if crate::state::try_sched_slot().is_none() {
        return ::ctrlc::set_handler(user_handler);
    }
    init_and_set_handler(user_handler)
}

/// The same as [`set_handler`]: a virtual handler never overwrites another.
/// On a thread with no state slot this is [`::ctrlc::try_set_handler`].
///
/// # Errors
/// As [`set_handler`].
pub fn try_set_handler<F>(user_handler: F) -> Result<(), Error>
where
    F: FnMut() + 'static + Send,
{
    if crate::state::try_sched_slot().is_none() {
        return ::ctrlc::try_set_handler(user_handler);
    }
    init_and_set_handler(user_handler)
}

/// A signal or console event a test can deliver with [`raise_signal`].
/// Which ones exist follows the selected [`OsSemantics`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VirtualSignal {
    /// `SIGINT`, or `CTRL_C_EVENT` on Windows.
    Interrupt,
    /// `SIGTERM`. Unix only.
    Terminate,
    /// `SIGHUP`. Unix only.
    Hangup,
    /// `CTRL_BREAK_EVENT`. Windows only.
    Break,
    /// `CTRL_CLOSE_EVENT`. Windows only.
    Close,
    /// `CTRL_LOGOFF_EVENT`. Windows only.
    Logoff,
    /// `CTRL_SHUTDOWN_EVENT`. Windows only.
    Shutdown,
}

/// What a [`raise_signal`] did.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignalDelivery {
    /// The slot's handler runs.
    Handled,
    /// The handler runs, and once it returns the real OS would end the
    /// process (Windows close, logoff and shutdown events). snare leaves the
    /// process running; the harness decides what an exit means.
    HandledThenExit,
    /// No handler catches it, so the OS default action (ending the process)
    /// applies. snare does not end the process.
    DefaultAction,
    /// The signal does not exist under the selected OS semantics.
    Unavailable,
}

/// Deliver a virtual Ctrl-C to the calling thread's state slot. Returns
/// whether a handler was set to receive it; without one, or on a thread with
/// no state slot, the Ctrl-C is dropped. The same as
/// `raise_signal(VirtualSignal::Interrupt) == SignalDelivery::Handled`.
///
/// The handler thread is woken like any participant: it becomes runnable
/// before the wake, the wake is deferred while the caller is inside
/// [`Driver::enter_timestamp`](crate::sched::Driver::enter_timestamp), and a
/// caller that is not a participant, driver or background thread is counted
/// as a stray.
pub fn raise() -> bool {
    raise_signal(VirtualSignal::Interrupt) == SignalDelivery::Handled
}

/// Deliver `sig` to the calling thread's state slot as the selected
/// [`OsSemantics`] and `ctrlc` would.
///
/// On Unix `Interrupt`, `Terminate` and `Hangup` exist; `ctrlc` catches
/// `SIGINT` always and `SIGTERM` and `SIGHUP` only with its `termination`
/// feature (snare's `ctrlc-termination`), so without it those two take the
/// default action. On Windows `Interrupt`, `Break`, `Close`, `Logoff` and
/// `Shutdown` exist, and `ctrlc`'s console handler catches every one of
/// them whatever its features; after `Close`, `Logoff` and `Shutdown` the
/// OS ends the process once the handler returns. Without a handler, or on a
/// thread with no state slot, an existing signal takes the default action.
pub fn raise_signal(sig: VirtualSignal) -> SignalDelivery {
    let os = crate::os::os_semantics();
    let windows = os == OsSemantics::Windows;
    let exists = match sig {
        VirtualSignal::Interrupt => true,
        VirtualSignal::Terminate | VirtualSignal::Hangup => !windows,
        VirtualSignal::Break
        | VirtualSignal::Close
        | VirtualSignal::Logoff
        | VirtualSignal::Shutdown => windows,
    };
    if !exists {
        return SignalDelivery::Unavailable;
    }
    let caught = windows
        || !matches!(sig, VirtualSignal::Terminate | VirtualSignal::Hangup)
        || cfg!(feature = "ctrlc-termination");
    if !caught || crate::state::try_sched_slot().is_none() || !deliver(&crate::state::ctrlc_slot())
    {
        return SignalDelivery::DefaultAction;
    }
    match sig {
        VirtualSignal::Close | VirtualSignal::Logoff | VirtualSignal::Shutdown => {
            SignalDelivery::HandledThenExit
        }
        _ => SignalDelivery::Handled,
    }
}

fn init_and_set_handler<F>(user_handler: F) -> Result<(), Error>
where
    F: FnMut() + 'static + Send,
{
    let slot = crate::state::ctrlc_slot();
    {
        let mut s = slot.state.lock();
        if s.installed {
            return Err(Error::MultipleHandlers);
        }
        s.installed = true;
    }
    let runner = Arc::clone(&slot);
    let spawned = crate::thread::Builder::new()
        .name("ctrl-c".into())
        .spawn(move || run(&runner, user_handler));
    if let Err(e) = spawned {
        slot.state.lock().installed = false;
        return Err(Error::System(e));
    }
    SLOTS.lock().push(Arc::downgrade(&slot));
    OS_HANDLER.call_once(|| {
        if let Err(e) = ::ctrlc::set_handler(forward_os_signal) {
            eprintln!("snare: real Ctrl-C will not reach virtual handlers: {e}");
        }
    });
    Ok(())
}

fn run<F: FnMut()>(slot: &CtrlcSlot, mut user_handler: F) {
    slot.state.lock().unparker = Some(current_unparker());
    loop {
        let pending = std::mem::take(&mut slot.state.lock().pending);
        if pending == 0 {
            park_as(None, "ctrlc");
            continue;
        }
        for _ in 0..pending {
            user_handler();
        }
    }
}

fn deliver(slot: &CtrlcSlot) -> bool {
    let unparker = {
        let mut s = slot.state.lock();
        if !s.installed {
            return false;
        }
        s.pending += 1;
        s.unparker.clone()
    };
    if let Some(u) = unparker {
        u.unpark();
    }
    true
}

fn forward_os_signal() {
    mark_background("ctrlc-os");
    let slots: Vec<Arc<CtrlcSlot>> = SLOTS.lock().iter().filter_map(Weak::upgrade).collect();
    for slot in slots {
        deliver(&slot);
    }
}
