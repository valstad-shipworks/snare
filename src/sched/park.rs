use std::fmt;
use std::sync::Arc;

use super::timer::{ParkCell, ParkWake};
use super::{ParkResult, park_cell};

/// Wakes a thread blocked in [`park`] (or in [`block_on`](super::block_on)).
#[derive(Clone)]
pub struct Unparker(pub(super) Arc<ParkCell>);

impl Unparker {
    pub fn unpark(&self) {
        self.0.unpark();
    }

    /// Wake now, even inside a driver timestamp where
    /// [`unpark`](Self::unpark) defers the wake. Only for threads that are
    /// never participants, whose wake cannot move the domain.
    #[cfg(all(feature = "shim", feature = "fast-talker-core"))]
    pub(crate) fn unpark_now(&self) {
        self.0.unpark_undeferred();
    }
}

impl fmt::Debug for Unparker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unparker").finish_non_exhaustive()
    }
}

/// The [`Unparker`] for the calling thread. Under an accounting driver this
/// registers the caller as a participant if it is not one yet.
pub fn current_unparker() -> Unparker {
    #[cfg(feature = "shim")]
    let _ = super::participant::member_link();
    Unparker(park_cell())
}

/// The calling thread's [`Unparker`], without registering it as a
/// participant: for background threads.
#[cfg(all(feature = "shim", feature = "fast-talker-core"))]
pub(crate) fn own_unparker() -> Unparker {
    Unparker(park_cell())
}

/// Block until this thread's [`Unparker`] fires or `deadline` passes. An
/// unpark that arrived before the call is consumed and returns immediately.
/// The deadline is virtual time under `shim`, wall time otherwise.
///
/// Under an accounting [`Driver`](super::Driver) the caller counts as
/// blocked while parked, so the domain can be quiescent.
pub fn park(deadline: Option<crate::time::Instant>) -> ParkResult {
    park_as(deadline, "park")
}

pub(crate) fn park_as(deadline: Option<crate::time::Instant>, wait: &'static str) -> ParkResult {
    let cell = park_cell();
    #[cfg(feature = "shim")]
    {
        wait_on(&cell, deadline.map(super::slot::instant_ns), wait, true)
    }
    #[cfg(not(feature = "shim"))]
    {
        let _ = wait;
        if cell.take_woken() {
            return ParkResult::Unparked;
        }
        match cell.wait(0, deadline) {
            Some(ParkWake::Unparked) => ParkResult::Unparked,
            _ if deadline.is_none() => ParkResult::Unparked,
            _ => ParkResult::TimedOut,
        }
    }
}

/// [`park`] until `deadline` for a thread that is never a participant.
/// Under an attached driver the timer takes a busy lease labelled `label`
/// as it fires, before the domain can count as quiescent again, and hands
/// it to the caller: virtual time stays at the deadline until the caller
/// drops it. The lease is `None` with no driver, or when unparked first.
#[cfg(all(feature = "shim", feature = "fast-talker-core"))]
pub(crate) fn park_background_leased(
    deadline: crate::time::Instant,
    label: &'static str,
) -> (ParkResult, Option<super::BusyLease>) {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::timer::{TimeSource, TimerTarget};

    let reg = super::participant::any_attached()
        .then(super::slot::try_slot)
        .flatten()
        .map(|s| Arc::clone(s.reg()));
    let Some(reg) = reg else {
        return (park(Some(deadline)), None);
    };
    super::participant::class_effect("park");
    let cell = park_cell();
    if cell.take_woken() {
        return (ParkResult::Unparked, None);
    }
    let deadline = super::slot::instant_ns(deadline);
    let timers = super::slot::timers();
    if timers.source().now_ns() >= deadline {
        return (ParkResult::TimedOut, None);
    }
    let handoff: Arc<parking_lot::Mutex<Option<super::BusyLease>>> = Arc::default();
    let fired = Arc::new(AtomicBool::new(false));
    let id = {
        let handoff = Arc::clone(&handoff);
        let fired = Arc::clone(&fired);
        let cell = Arc::clone(&cell);
        timers.insert(
            deadline,
            TimerTarget::Release(Box::new(move || {
                *handoff.lock() = super::BusyLease::taken(&reg, label);
                fired.store(true, Ordering::Release);
                cell.unpark_undeferred();
            })),
        )
    };
    super::participant::foreign_timer_added();
    cell.wait(0, None);
    if !fired.load(Ordering::Acquire) {
        timers.cancel(id);
    }
    let lease = handoff.lock().take();
    let result = if fired.load(Ordering::Acquire) {
        ParkResult::TimedOut
    } else {
        ParkResult::Unparked
    };
    (result, lease)
}

/// Wait on `cell` until it is unparked or the virtual `deadline` passes,
/// with participant accounting when a driver tracks this thread.
#[cfg(feature = "shim")]
pub(crate) fn wait_on(
    cell: &Arc<ParkCell>,
    deadline: Option<u64>,
    wait: &'static str,
    consume_woken: bool,
) -> ParkResult {
    super::participant::class_effect(wait);
    if let Some(link) = super::participant::member_link() {
        return link.reg.park(&link, cell, deadline, wait, consume_woken);
    }
    wait_plain(cell, deadline, consume_woken)
}

#[cfg(feature = "shim")]
pub(crate) fn wait_plain(
    cell: &Arc<ParkCell>,
    deadline: Option<u64>,
    consume_woken: bool,
) -> ParkResult {
    use super::timer::{TimeSource, TimerTarget};

    if consume_woken && cell.take_woken() {
        return ParkResult::Unparked;
    }
    let Some(deadline) = deadline else {
        cell.wait(0, None);
        return ParkResult::Unparked;
    };
    let timers = super::slot::timers();
    if timers.source().now_ns() >= deadline {
        return ParkResult::TimedOut;
    }
    let foreign = super::participant::foreign_here();
    let id = timers.insert_as(deadline, TimerTarget::Park(Arc::clone(cell)), foreign);
    if !foreign {
        super::participant::foreign_timer_added();
    }
    match cell.wait(id, None) {
        Some(ParkWake::Fired) => ParkResult::TimedOut,
        _ => {
            timers.cancel(id);
            ParkResult::Unparked
        }
    }
}

/// The token [`crate::thread::park`] waits on for the thread `id`, apart
/// from the cell snare's own waits use, so an unpark never cuts a snare
/// sleep short. An unpark before the thread first parks is kept.
#[cfg(feature = "shim")]
pub(crate) fn thread_token(id: std::thread::ThreadId) -> Arc<ParkCell> {
    use std::collections::HashMap;
    use std::sync::LazyLock;

    static TOKENS: LazyLock<parking_lot::Mutex<HashMap<std::thread::ThreadId, Arc<ParkCell>>>> =
        LazyLock::new(Default::default);

    struct Forget(std::thread::ThreadId);
    impl Drop for Forget {
        fn drop(&mut self) {
            TOKENS.lock().remove(&self.0);
        }
    }
    thread_local! {
        static FORGET: std::cell::OnceCell<Forget> = const { std::cell::OnceCell::new() };
    }

    if id == std::thread::current().id() {
        let _ = FORGET.try_with(|f| {
            f.get_or_init(|| Forget(id));
        });
    }
    Arc::clone(TOKENS.lock().entry(id).or_default())
}

/// Block the calling thread on its [`thread_token`] until it is unparked
/// or the virtual `deadline` passes.
#[cfg(feature = "shim")]
pub(crate) fn park_thread(deadline: Option<crate::time::Instant>, wait: &'static str) {
    let cell = thread_token(std::thread::current().id());
    wait_on(&cell, deadline.map(super::slot::instant_ns), wait, true);
}
