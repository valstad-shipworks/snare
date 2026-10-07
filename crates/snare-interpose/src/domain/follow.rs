//! Process-local descriptors that outlive the sim that made them, and the threads that follow
//! them into the next sim.
//!
//! An epoll set, a kqueue, an eventfd or a timerfd belongs to the process, not to a network: a
//! library may create one once per process (async-io's reactor keeps its poller and the thread
//! that waits on it in statics) under whichever sim touches it first. A test binary builds a new
//! world around the same process for each test, so a later sim must be able to use that object,
//! and the thread blocked on it must then run in the later sim's world, on its clock.
//!
//! Every virtual descriptor is recorded with the sim that minted it (`crate::owners`). A hook
//! whose own sim does not own an fd consults [`elsewhere`] before going to the OS:
//!
//! * A descriptor of a sim with no run in progress, reached from a sim with one, is handed over:
//!   that sim's backends give every process-local descriptor they hold to this sim's
//!   ([`Net::hand_over`](crate::Net::hand_over)). Its threads blocked on one of them get a place
//!   in this sim made ready first, counted live as a spawned thread is, so this sim cannot read
//!   as quiescent before they arrive.
//! * A thread left over from a run that has ended, reaching a descriptor that moved, follows it:
//!   it leaves its sim as an exiting thread does and joins the descriptor's sim as an adopted one.
//!   So does one reaching a socket of a sim whose run is in progress ([`follow_owner`]): a
//!   process-wide thread pool (an executor's workers) started under an earlier sim picks up work
//!   the running sim handed it, and that work belongs to the running sim's world.
//! * A descriptor of a sim whose run is in progress, reached from another running sim, is shared
//!   by two live worlds at once, which no model of one process can serve: the caller waits, busy
//!   in its own sim, until that run ends.
//! * Anything else of another sim (a socket reached from a running sim, or of a sim with no run in
//!   progress, a descriptor of a sim that is gone) fails with `EBADF`, as an fd this world never
//!   opened would, rather than reaching the OS's placeholder.

use std::cell::Cell;
use std::ffi::c_int;
use std::sync::{Condvar, Mutex, MutexGuard};
#[cfg(unix)]
use std::time::Duration;

use super::{
    Arc, Inherited, Inner, SendInherited, ThreadClass, accounting, offer_idle_skip, release, state,
    thread_lineage, wake_if_quiescent,
};
#[cfg(unix)]
use super::{Domain, Flow, Lineage, Ordering, dispatch, end_spin, mix_lineage, swap_lineage};
#[cfg(unix)]
use crate::owners::{self, Owner};
use crate::state::Passthrough;

thread_local! {
    /// Whether the calling thread may follow a descriptor to another domain: a thread its domain's
    /// code created, outside any nested [`Domain::enter`].
    static FOLLOWABLE: Cell<bool> = const { Cell::new(false) };
}

/// Mixed with a following thread's lineage in the domain it leaves to give its lineage in the one
/// it joins. A snare choice: the ASCII bytes of `"FOLLOWER"`.
#[cfg(unix)]
const FOLLOW_SALT: u64 = 0x464f_4c4c_4f57_4552;

/// How long a thread waiting for another sim's run to end sleeps between checks; an ending run
/// wakes it sooner.
#[cfg(unix)]
const IDLE_POLL: Duration = Duration::from_millis(100);

/// How long, in real time, a hand-over waits for the giving sim's threads to come to rest in a
/// wait, and how often it looks. A thread left over from an ended run soon blocks again; one
/// caught running would go on in the old world with no place made ready for it, and could act
/// there on what the new one just did (a timer it queued, read on the old clock). A snare choice:
/// long past any such thread's step, short against a test.
#[cfg(unix)]
const SETTLE: Duration = Duration::from_millis(200);
#[cfg(unix)]
const SETTLE_POLL: Duration = Duration::from_micros(200);

static IDLE_LOCK: Mutex<()> = Mutex::new(());
static IDLE: Condvar = Condvar::new();

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// Sets whether the calling thread may follow a descriptor, returning what it was.
pub(super) fn set_followable(on: bool) -> bool {
    FOLLOWABLE.try_with(|f| f.replace(on)).unwrap_or(false)
}

/// A domain's last run ended: wake the threads of other sims waiting for that.
pub(super) fn run_ended() {
    let _passthrough = Passthrough::enter();
    let _idle = lock(&IDLE_LOCK);
    IDLE.notify_all();
}

/// A thread of a domain blocked on one of its descriptors (see [`fd_wait`]).
#[derive(Clone, Copy)]
pub(crate) struct FdWaiter {
    lineage: u64,
    fd: c_int,
    class: ThreadClass,
    label: Option<&'static str>,
}

/// Returned by [`fd_wait`]; ends the record when dropped.
#[must_use]
pub struct FdWait {
    /// The domain the wait was recorded in; null when nothing was recorded.
    domain: *const Inner,
    lineage: u64,
    fd: c_int,
}

impl std::fmt::Debug for FdWait {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FdWait").field("fd", &self.fd).finish_non_exhaustive()
    }
}

/// Records that the calling thread is about to block on descriptor `fd` of its domain, until the
/// guard drops: should the descriptor be handed to another sim meanwhile, the thread gets a
/// place there before it is woken to follow it. A backend calls this around a wait on a
/// process-local descriptor (an epoll set, a kqueue, an eventfd, a timerfd).
pub fn fd_wait(fd: c_int) -> FdWait {
    let domain = state::domain();
    if domain.is_null() || !FOLLOWABLE.try_with(Cell::get).unwrap_or(false) {
        return FdWait {
            domain: std::ptr::null(),
            lineage: 0,
            fd,
        };
    }
    let lineage = thread_lineage();
    let (class, label) = (accounting::class(), accounting::label());
    let _passthrough = Passthrough::enter();
    // SAFETY: the calling thread's domain is live while it is installed.
    lock(&unsafe { &*domain }.fd_waits).push(FdWaiter {
        lineage,
        fd,
        class,
        label,
    });
    FdWait {
        domain,
        lineage,
        fd,
    }
}

impl Drop for FdWait {
    fn drop(&mut self) {
        if self.domain.is_null() {
            return;
        }
        let _passthrough = Passthrough::enter();
        // SAFETY: a wait is recorded and dropped on the same thread, inside one hooked call, so
        // the domain it was recorded in is still the thread's and still live.
        let mut waits = lock(&unsafe { &*self.domain }.fd_waits);
        if let Some(i) = waits
            .iter()
            .position(|w| w.lineage == self.lineage && w.fd == self.fd)
        {
            waits.swap_remove(i);
        }
    }
}

/// Drops thread `lineage` from `domain`'s census as it leaves it, giving back any place another
/// sim made ready for it there that it never took.
pub(super) fn forget(domain: &Inner, lineage: u64) {
    let _passthrough = Passthrough::enter();
    let place = {
        let mut followers = lock(&domain.followers);
        let place = followers.remove(&lineage);
        domain.accounting.remove_row(lineage);
        place
    };
    if let Some(SendInherited(place)) = place {
        // SAFETY: the place was made by `place_in` and never adopted.
        unsafe { give_back(place) };
    }
}

/// Gives back a place made ready in another domain for a thread that never took it, from any
/// thread: the domain may read as quiescent once it is gone, so it is told to look again, as it is
/// when one of its own threads exits.
///
/// # Safety
/// `place` was made by `place_in` and never adopted.
pub(super) unsafe fn give_back(place: Inherited) {
    let participant = place.class == ThreadClass::Participant;
    let domain = place.domain;
    // SAFETY: the place holds a strong count on its domain; this one outlives `release`.
    unsafe { Arc::increment_strong_count(domain) };
    // SAFETY: as the caller promises.
    unsafe { release(place) };
    // SAFETY: the count taken above.
    let held = unsafe { Arc::from_raw(domain) };
    if participant {
        drop(held.accounting.bump());
        wake_if_quiescent(&held);
        offer_idle_skip(domain);
    }
}

/// What a hook does with an fd no backend of its own sim serves.
#[cfg(unix)]
pub(crate) enum Elsewhere {
    /// Go to the OS: a real descriptor, or one of this sim's its backends declined.
    Real,
    /// The descriptor now belongs to the calling thread's sim (or the thread to the descriptor's):
    /// offer the call again.
    Retry,
    /// Fail with this errno.
    Fail(c_int),
}

/// Decides, and arranges, what becomes of a call on `fd` that no backend of the calling thread's
/// sim took (see the module documentation).
#[cfg(unix)]
pub(crate) fn elsewhere(fd: c_int) -> Elsewhere {
    let owner = owners::owner(fd);
    if owner == Owner::None || state::passthrough() {
        return Elsewhere::Real;
    }
    let here = state::domain();
    if here.is_null() {
        return Elsewhere::Real;
    }
    // SAFETY: the calling thread's domain is live while it is installed.
    let me = unsafe { &*here };
    let (serial, local) = match owner {
        Owner::Sim { serial, local } => (serial, local),
        Owner::Orphan => {
            end_spin();
            let _passthrough = Passthrough::enter();
            let taken = crate::domain::descriptor_transaction(|| {
                owners::adopt_orphan(fd, |mut state, fds| {
                    for net in &me.net {
                        // SAFETY: the descriptor transaction is held.
                        match unsafe { net.take_over(state, fds) } {
                            Ok(()) => return Ok(()),
                            Err(back) => state = back,
                        }
                    }
                    Err(state)
                })
            });
            // Another thread may have taken it over, or closed it, first.
            return if (taken && mine(fd)) || owners::owner(fd) != Owner::Orphan {
                Elsewhere::Retry
            } else {
                Elsewhere::Fail(libc::EBADF)
            };
        }
        _ => {
            end_spin();
            return mirrored(me, fd);
        }
    };
    if serial == me.accounting.serial.0 {
        return Elsewhere::Real;
    }
    end_spin();
    let _passthrough = Passthrough::enter();
    if !local {
        if follow_running(me, serial) && mine(fd) {
            return Elsewhere::Retry;
        }
        return mirrored(me, fd);
    }
    let Some(theirs) = crate::census::find(serial) else {
        return if owner_moves_on(fd, owner) {
            Elsewhere::Retry
        } else {
            Elsewhere::Fail(libc::EBADF)
        };
    };
    if me.dormant.load(Ordering::SeqCst) {
        if !follow(&theirs) {
            return Elsewhere::Fail(libc::EBADF);
        }
    } else if !theirs.0.dormant.load(Ordering::SeqCst) {
        wait_until_idle(&theirs);
        return Elsewhere::Retry;
    } else {
        hand_over(&theirs.0, me);
    }
    // Another sim may have taken it first; the call then looks again at where it went.
    if mine(fd) || owners::owner(fd) != owner {
        Elsewhere::Retry
    } else {
        Elsewhere::Fail(libc::EBADF)
    }
}

/// Moves the calling thread, left over from a run of its domain that has ended, into the sim that
/// minted `fd` if that sim has a run in progress. `true` when the thread now belongs to the sim
/// that owns `fd`, so a call on it should be offered again. Anything else is left to the call's
/// own handling.
#[cfg(unix)]
pub(crate) fn follow_owner(fd: c_int) -> bool {
    let Owner::Sim { serial, .. } = owners::owner(fd) else {
        return false;
    };
    if state::passthrough() {
        return false;
    }
    let here = state::domain();
    if here.is_null() {
        return false;
    }
    // SAFETY: the calling thread's domain is live while it is installed.
    let me = unsafe { &*here };
    if serial == me.accounting.serial.0 {
        return false;
    }
    end_spin();
    let _passthrough = Passthrough::enter();
    follow_running(me, serial) && mine(fd)
}

/// Moves the calling thread into sim `serial` if the thread is left over from an ended run of its
/// own sim `me` and `serial` has a run in progress.
#[cfg(unix)]
fn follow_running(me: &Inner, serial: u64) -> bool {
    if !me.dormant.load(Ordering::SeqCst) {
        return false;
    }
    match crate::census::find(serial) {
        Some(theirs) if !theirs.0.dormant.load(Ordering::SeqCst) => follow(&theirs),
        _ => false,
    }
}

/// A descriptor of another sim (or of one that is gone) that is not process-local: served by
/// this sim's own instance of it if a backend has one to give (see
/// [`Net::mirror`](crate::Net::mirror)), and otherwise `EBADF`, as an fd this world never opened.
#[cfg(unix)]
fn mirrored(me: &Inner, fd: c_int) -> Elsewhere {
    let _passthrough = Passthrough::enter();
    // SAFETY: no pointers are involved.
    if me.net.iter().any(|net| unsafe { net.mirror(fd) }) {
        Elsewhere::Retry
    } else {
        Elsewhere::Fail(libc::EBADF)
    }
}

/// The sim holding `fd`, a process-local descriptor, when that is another sim than the calling
/// thread's and its run is in progress.
#[cfg(unix)]
pub(crate) fn running_elsewhere(fd: c_int) -> Option<Domain> {
    let Owner::Sim {
        serial,
        local: true,
    } = owners::owner(fd)
    else {
        return None;
    };
    if state::passthrough() {
        return None;
    }
    let here = state::domain();
    // SAFETY: the calling thread's domain is live while it is installed.
    if here.is_null() || serial == unsafe { &*here }.accounting.serial.0 {
        return None;
    }
    let _passthrough = Passthrough::enter();
    let theirs = crate::census::find(serial)?;
    (!theirs.0.dormant.load(Ordering::SeqCst)).then_some(theirs)
}

/// Whether the calling thread's sim owns `fd`.
#[cfg(unix)]
fn mine(fd: c_int) -> bool {
    let here = state::domain();
    // SAFETY: the calling thread's domain is live while it is installed.
    !here.is_null()
        && matches!(owners::owner(fd), Owner::Sim { serial, .. }
            if serial == unsafe { &*here }.accounting.serial.0)
}

/// Whether `fd`, recorded against a sim that is going away, soon leaves `was`: that sim's
/// backends orphan or bury what they minted as they drop, just after the sim stops being found.
/// Waits a bounded real time, in case something else keeps a backend alive.
#[cfg(unix)]
fn owner_moves_on(fd: c_int, was: Owner) -> bool {
    let by = std::time::Instant::now() + SETTLE;
    loop {
        if owners::owner(fd) != was {
            return true;
        }
        if std::time::Instant::now() >= by {
            return false;
        }
        std::thread::sleep(SETTLE_POLL);
    }
}

/// Blocks until `theirs` has no run in progress. The calling thread stays busy, not blocked, in
/// its own sim meanwhile, so that sim's stuck watchdog still reports a wait that never ends (two
/// runs at once each waiting on the other through a lock of the code under test).
#[cfg(unix)]
fn wait_until_idle(theirs: &Domain) {
    let mut idle = lock(&IDLE_LOCK);
    while !theirs.0.dormant.load(Ordering::SeqCst) {
        idle = IDLE
            .wait_timeout(idle, IDLE_POLL)
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
}

/// Moves every process-local descriptor of `from`'s backends to `to`'s (the calling thread's
/// domain), first making a place in `to` for each of `from`'s threads blocked on one, then waking
/// them to follow.
#[cfg(unix)]
fn hand_over(from: &Inner, to: &Inner) {
    let settle_by = std::time::Instant::now() + SETTLE;
    while from
        .accounting
        .core()
        .rows
        .values()
        .any(|row| row.class == ThreadClass::Participant && row.wait.is_none())
        && std::time::Instant::now() < settle_by
    {
        std::thread::sleep(SETTLE_POLL);
    }
    crate::domain::descriptor_transaction(|| {
        let mut moved = Vec::new();
        let mut wakes = Vec::new();
        for net in &from.net {
            // SAFETY: the descriptor transaction is held.
            let Some(handed) = (unsafe { net.hand_over() }) else {
                continue;
            };
            let live: Vec<c_int> = handed
                .fds
                .iter()
                .copied()
                .filter(|&fd| {
                    owners::owner(fd)
                        == Owner::Sim {
                            serial: from.accounting.serial.0,
                            local: true,
                        }
                })
                .collect();
            let mut state = Some(handed.state);
            for taker in &to.net {
                // SAFETY: as above.
                match unsafe { taker.take_over(state.take().unwrap(), &live) } {
                    Ok(()) => break,
                    Err(back) => state = Some(back),
                }
            }
            if let Some(state) = state {
                // SAFETY: as above; no backend of `to` took it, so it goes back.
                let _ = unsafe { net.take_over(state, &handed.fds) };
                continue;
            }
            moved.extend(live);
            wakes.push(handed.wake);
        }
        let mut waiters: Vec<FdWaiter> = lock(&from.fd_waits)
            .iter()
            .filter(|w| moved.contains(&w.fd))
            .copied()
            .collect();
        waiters.sort_by_key(|w| w.lineage);
        waiters.dedup_by_key(|w| w.lineage);
        {
            let mut followers = lock(&from.followers);
            for waiter in waiters {
                if followers.contains_key(&waiter.lineage)
                    || !from
                        .accounting
                        .core()
                        .rows
                        .contains_key(&waiter.lineage)
                {
                    continue;
                }
                let place = place_in(to, waiter.class, waiter.label, waiter.lineage);
                followers.insert(waiter.lineage, SendInherited(place));
            }
        }
        debug_assert!(state::domain() == std::ptr::from_ref(to));
        for wake in wakes {
            wake();
        }
    });
}

/// A place in `to` (a live domain held in an `Arc`) for a thread of class `class`, lineage `from`
/// in the domain it leaves, that follows a descriptor there: counted live and queued in a
/// deterministic schedule as a spawned thread is. Its lineage there is mixed from its old one, so
/// it is the same whether the place was made ready at a hand-over or as the thread arrived.
#[cfg(unix)]
fn place_in(to: &Inner, class: ThreadClass, label: Option<&'static str>, from: u64) -> Inherited {
    let mut lineage = mix_lineage(FOLLOW_SALT, from);
    while to.accounting.core().rows.contains_key(&lineage) {
        lineage = mix_lineage(FOLLOW_SALT, lineage);
    }
    let domain = std::ptr::from_ref(to);
    // SAFETY: `to` is live and held in an `Arc`; the place takes a count of its own.
    unsafe { Arc::increment_strong_count(domain) };
    if class == ThreadClass::Participant {
        to.participants.fetch_add(1, Ordering::SeqCst);
    }
    let held = to.accounting.add_row(lineage, class);
    if class == ThreadClass::Participant
        && let Some(sched) = to.sched.as_ref().filter(|sched| !sched.detached())
    {
        sched.spawned(lineage);
    }
    Inherited {
        domain,
        class,
        label,
        lineage,
        held,
    }
}

/// Moves the calling thread, left over from a run of its domain that has ended, into `to`: it
/// leaves its domain as an exiting thread does and joins `to` as an adopted one, taking the place
/// `to` made ready for it if there is one. `false`, changing nothing, for a thread that cannot
/// move (one that entered its domain itself, or is inside a nested entry).
#[cfg(unix)]
fn follow(to: &Domain) -> bool {
    if !FOLLOWABLE.try_with(Cell::get).unwrap_or(false) {
        return false;
    }
    let from_ptr = state::domain();
    if from_ptr.is_null() {
        return false;
    }
    let to_ptr = Arc::as_ptr(&to.0);
    if from_ptr == to_ptr {
        return true;
    }
    // SAFETY: the calling thread's domain is live while it is installed, and the thread holds a
    // strong count on it (released at the end of this function).
    let from = unsafe { &*from_ptr };
    let lineage = thread_lineage();
    let (class, label) = (accounting::class(), accounting::label());
    let ready = lock(&from.followers).remove(&lineage);
    let place = match ready {
        Some(SendInherited(place)) if place.domain == to_ptr => place,
        other => {
            if let Some(SendInherited(place)) = other {
                // SAFETY: made by `place_in`, never adopted.
                unsafe { give_back(place) };
            }
            place_in(&to.0, class, label, lineage)
        }
    };
    dispatch(|layer| {
        layer.thread_exiting();
        Flow::<()>::Pass
    });
    if let Some(sched) = &from.sched {
        sched.exit(lineage, false);
    }
    let handle = crate::os::current_thread_handle();
    let name = from.thread_name(lineage);
    accounting::swap_held(place.held);
    from.accounting.forget_handle(handle, lineage);
    forget(from, lineage);
    from.accounting.core().exited(lineage);
    if class == ThreadClass::Participant {
        from.participants.fetch_sub(1, Ordering::SeqCst);
        drop(from.accounting.bump());
        wake_if_quiescent(from);
        offer_idle_skip(from_ptr);
    }
    state::replace_domain(place.domain);
    swap_lineage(Lineage {
        id: place.lineage,
        children: 0,
    });
    accounting::swap_class(place.class, place.label);
    // SAFETY: the place holds a strong count on its domain, now the thread's.
    let joined = unsafe { &*place.domain };
    joined.accounting.record_handle(handle, place.lineage);
    if name.is_some() {
        joined.accounting.set_name(place.lineage, name);
    }
    if place.class == ThreadClass::Participant
        && let Some(sched) = &joined.sched
    {
        sched.started(place.lineage);
    }
    dispatch(|layer| {
        layer.thread_started();
        Flow::<()>::Pass
    });
    // SAFETY: the count `adopt` (or an earlier `follow`) took on the domain the thread left,
    // which its guard no longer releases.
    unsafe { drop(Arc::from_raw(from_ptr)) };
    true
}
