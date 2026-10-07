//! Threads left over from a run that has ended, woken by a running sim: they follow the waker into
//! its world.
//!
//! A process-wide pool (rayon's global registry, a `static` executor's workers, a blocking pool
//! kept in a `LazyLock`) starts its threads under whichever sim first touches it, and they park on
//! condition variables, futexes and semaphores between jobs. Once that sim's run ends they are its
//! leftovers. A later sim handing them work wakes them through the same primitive, and the work
//! they then do is the later sim's: its clock, its quiescence, its schedule. So a wake made by a
//! thread of a sim whose run is in progress, on a word a participant of a dormant sim is parked
//! on, makes that waiter a place in the waker's sim first, as a spawn does for a child, and the
//! waiter takes it as its wait returns ([`follow_woken`]), leaving its own sim as a thread
//! following a descriptor does (`follow::follow`).
//!
//! Which of several waiters a partial wake reaches is the OS's choice. Each waiter a wake for at
//! least every listed waiter reaches gets a place of its own; a partial wake makes as many places
//! as it may wake waiters of dormant sims, each claimable by any of them (of whichever dormant sim)
//! returning from a wait on that word. A place nobody takes within [`SETTLE`] is given back by a service thread, as the
//! kernel may have woken a waiter the census never listed (one outside every sim, or still in an
//! uncounted grace period) instead: the waker's sim stops waiting for it. A waiter that still
//! arrives later follows all the same, onto a place made as it arrives.
//!
//! Threads of a sim whose run is in progress never move, nor do threads of other classes than
//! participants, which are not listed.

use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use super::{
    Arc, Domain, Inner, KEYED_WAITER_COUNT, Ordering, SendInherited, ThreadClass, accounting,
    follow, keyed_waiters, state, thread_lineage,
};
use crate::state::Passthrough;

/// How long, in real time, a place made at a wake waits for its waiter. A snare choice: a woken
/// waiter normally returns within microseconds, and one held up past this has lost the race with
/// whatever its sim's peers waited on meanwhile.
const SETTLE: Duration = Duration::from_millis(200);

/// How long, in real time, a waiter whose place was given back may still follow the wake that
/// made it. A snare choice, long past any OS scheduling delay.
const LATE: Duration = Duration::from_secs(5);

/// A wake that reached a waiter of a dormant sim.
struct Woken {
    /// The waiter's sim, or, for a place any waiter may take, the sim of the one its lineage is
    /// mixed from.
    from: Domain,
    /// The waker's sim.
    to: Domain,
    /// The word the waiter is parked on.
    key: usize,
    /// The waiter's lineage in `from`: the one thread that may take the place when `exact`, or
    /// the waiter the place's lineage is mixed from when any waiter on `key` may.
    lineage: u64,
    exact: bool,
    /// The place in `to`, until taken or given back.
    place: Option<SendInherited>,
    /// When the place is given back, or once it has been, when the record is dropped.
    by: Instant,
}

static WOKEN: Mutex<Vec<Woken>> = Mutex::new(Vec::new());

/// How many records [`WOKEN`] holds, so a wait returning with none anywhere skips its lock.
static WOKEN_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Signalled when a record is added, for the service thread giving back places.
static REAPER: Condvar = Condvar::new();
static REAPER_STARTED: AtomicBool = AtomicBool::new(false);

fn woken() -> MutexGuard<'static, Vec<Woken>> {
    WOKEN.lock().unwrap_or_else(|e| e.into_inner())
}

/// A handle on the domain at `domain`, which the caller knows to be live.
///
/// # Safety
/// `domain` points at an `Inner` held in an `Arc` with a strong count that outlives this call.
unsafe fn domain_at(domain: *const Inner) -> Domain {
    // SAFETY: as the caller promises.
    unsafe {
        Arc::increment_strong_count(domain);
        Domain(Arc::from_raw(domain))
    }
}

/// A wake on `key` for up to `n` waiters, about to be made by the calling thread: when its sim
/// has a run in progress, each participant of a dormant sim parked there that the wake may reach
/// gets a place in the calling thread's sim (see the module documentation). Called before the
/// OS wake, so the place is there by the time the waiter returns.
pub(crate) fn place_woken(key: usize, n: usize) {
    if KEYED_WAITER_COUNT.load(Ordering::SeqCst) == 0 || state::passthrough() {
        return;
    }
    let here = state::domain();
    if here.is_null() {
        return;
    }
    // SAFETY: the calling thread's domain is live while it is installed.
    let to = unsafe { &*here };
    if to.dormant.load(Ordering::SeqCst) {
        return;
    }
    let _passthrough = Passthrough::enter();
    let own = to.key();
    let (parked, mut dormant) = {
        let waiters = keyed_waiters();
        let mut parked = 0;
        let mut dormant: Vec<(Domain, u64)> = Vec::new();
        for &(_, domain, lineage) in waiters.iter().filter(|w| w.0 == key) {
            parked += 1;
            if domain == own {
                continue;
            }
            let domain = domain as *const Inner;
            // SAFETY: a listed participant keeps its domain alive: it is delisted, under this
            // lock, as it leaves its wait, before its guard lets the domain go.
            if unsafe { &*domain }.dormant.load(Ordering::SeqCst) {
                // SAFETY: as above.
                dormant.push((unsafe { domain_at(domain) }, lineage));
            }
        }
        (parked, dormant)
    };
    if dormant.is_empty() {
        return;
    }
    dormant.sort_by_key(|(domain, lineage)| (domain.0.accounting.serial.0, *lineage));
    let exact = n >= parked;
    let listed = dormant.len();
    if !exact {
        dormant.truncate(n);
    }
    // SAFETY: the calling thread holds a count on its domain.
    let to_handle = unsafe { domain_at(here) };
    let by = Instant::now() + SETTLE;
    let mut pending = woken();
    for (from, lineage) in dormant {
        let waiting = if exact {
            pending
                .iter()
                .any(|w| w.from.0.key() == from.0.key() && w.exact && w.lineage == lineage)
                || from
                    .0
                    .followers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains_key(&lineage)
        } else {
            pending.iter().filter(|w| !w.exact && w.key == key).count() >= listed
        };
        if waiting {
            continue;
        }
        let place = follow::place_in(to, ThreadClass::Participant, None, lineage);
        pending.push(Woken {
            from,
            to: to_handle.clone(),
            key,
            lineage,
            exact,
            place: Some(SendInherited(place)),
            by,
        });
    }
    WOKEN_COUNT.store(pending.len(), Ordering::SeqCst);
    drop(pending);
    start_reaper();
    REAPER.notify_all();
}

/// The calling thread, back from a native wait on the word it is labelled with, takes a place a
/// running sim's wake made ready for it, if there is one, and follows that sim (see the module
/// documentation). A condition variable's wait passes `relock`, which lets go of its mutex
/// (`false`) for the move and takes it back (`true`) in the new sim, so the thread never waits
/// for that sim's turn holding a lock of the code under test.
pub(super) fn follow_woken(relock: Option<&dyn Fn(bool)>) {
    if WOKEN_COUNT.load(Ordering::SeqCst) == 0 || state::passthrough() {
        return;
    }
    let Some(key) = accounting::current_wait_key() else {
        return;
    };
    let here = state::domain();
    if here.is_null() {
        return;
    }
    // SAFETY: the calling thread's domain is live while it is installed.
    let me = unsafe { &*here };
    let lineage = thread_lineage();
    let record = {
        let _passthrough = Passthrough::enter();
        let mut pending = woken();
        let found = pending
            .iter()
            .position(|w| {
                w.exact && w.key == key && w.lineage == lineage && w.from.0.key() == me.key()
            })
            .or_else(|| pending.iter().position(|w| !w.exact && w.key == key));
        let record = found.map(|i| pending.swap_remove(i));
        WOKEN_COUNT.store(pending.len(), Ordering::SeqCst);
        record
    };
    let Some(mut record) = record else {
        return;
    };
    let moves = follow::followable()
        && me.dormant.load(Ordering::SeqCst)
        && !record.to.0.dormant.load(Ordering::SeqCst);
    let place = record.place.take();
    if !moves {
        if let Some(place) = place {
            give_back(&record.to, place);
        }
        let _passthrough = Passthrough::enter();
        drop(record);
        return;
    }
    if let Some(relock) = relock {
        relock(false);
    }
    {
        let _passthrough = Passthrough::enter();
        if let Some(place) = place {
            let old = me
                .followers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(lineage, place);
            if let Some(SendInherited(old)) = old {
                // SAFETY: made by `place_in` and never adopted.
                unsafe { follow::give_back(old) };
            }
        }
        follow::follow(&record.to);
        drop(record);
    }
    if let Some(relock) = relock {
        relock(true);
    }
}

/// The longest [`settle`] waits for a sim's leftover threads in all. A snare choice.
const SETTLE_CAP: Duration = Duration::from_secs(5);

/// How often [`settle`] looks at a sim's leftover threads. A snare choice.
const SETTLE_POLL: Duration = Duration::from_micros(200);

/// Waits, a bounded real time, for the participants left over from `domain`'s run that just ended
/// to come to rest in a wait, and, under a deterministic schedule, for the schedule to let them go.
/// A pool's worker that has just run out of work spins a while before it parks (rayon yields 32
/// times), and one still spinning when a later sim posts work picks it up without any wake to
/// follow, doing that sim's work in this one's world. The wait goes on while threads keep coming to
/// rest, each within [`SETTLE`] of the last (a deterministic schedule hands the spinners its baton
/// one at a time), up to [`SETTLE_CAP`]; a thread that never rests (computing, or blocked in a call
/// snare does not see) holds it up [`SETTLE`] at most. A rest must hold across two looks, since a
/// thread a deterministic schedule lets go returns from its wait there before it waits natively.
pub(super) fn settle(domain: &Inner) {
    let _passthrough = Passthrough::enter();
    let start = Instant::now();
    let mut by = start + SETTLE;
    let mut rested = false;
    let mut fewest = usize::MAX;
    while Instant::now() < by.min(start + SETTLE_CAP) {
        if !domain.dormant.load(Ordering::SeqCst) {
            return;
        }
        let (any, running) = {
            let core = domain.accounting.core();
            let participants = core
                .rows
                .values()
                .filter(|row| row.class == ThreadClass::Participant);
            let mut any = false;
            let mut running = 0;
            for row in participants {
                any = true;
                running += usize::from(row.wait.is_none());
            }
            (any, running)
        };
        let at_rest =
            !any || (running == 0 && domain.sched.as_ref().is_none_or(|sched| sched.detached()));
        if at_rest && rested {
            return;
        }
        rested = at_rest;
        if running < fewest {
            fewest = running;
            by = Instant::now() + SETTLE;
        }
        std::thread::sleep(SETTLE_POLL);
    }
}

/// Gives back a place made at a wake that nobody took, from any thread. Under a deterministic
/// schedule the place may already hold the baton, which goes on to the next thread.
fn give_back(to: &Domain, SendInherited(place): SendInherited) {
    let _passthrough = Passthrough::enter();
    if let Some(sched) = &to.0.sched {
        sched.exit(place.lineage, false);
    }
    // SAFETY: made by `place_in` and never adopted.
    unsafe { follow::give_back(place) };
}

/// Starts the service thread giving back places nobody took, once per process.
fn start_reaper() {
    if REAPER_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let started = std::thread::Builder::new()
        .name("snare-wake-reaper".into())
        .spawn(|| {
            let _service = crate::census::service_thread();
            let _passthrough = Passthrough::enter();
            reap();
        });
    if started.is_err() {
        REAPER_STARTED.store(false, Ordering::SeqCst);
    }
}

/// Gives back each place nobody took within [`SETTLE`], and forgets each given-back record
/// [`LATE`] later.
fn reap() {
    let mut pending = woken();
    loop {
        let now = Instant::now();
        let mut expired = Vec::new();
        let mut gone = Vec::new();
        let mut i = 0;
        while i < pending.len() {
            let record = &mut pending[i];
            if record.by > now {
                i += 1;
                continue;
            }
            match record.place.take() {
                Some(place) => {
                    expired.push((record.to.clone(), place));
                    record.by = now + LATE;
                    i += 1;
                }
                None => gone.push(pending.swap_remove(i)),
            }
        }
        WOKEN_COUNT.store(pending.len(), Ordering::SeqCst);
        if !expired.is_empty() || !gone.is_empty() {
            drop(pending);
            for (to, place) in expired {
                give_back(&to, place);
            }
            drop(gone);
            pending = woken();
            continue;
        }
        pending = match pending.iter().map(|w| w.by).min() {
            Some(at) => {
                REAPER
                    .wait_timeout(pending, at.saturating_duration_since(now))
                    .unwrap_or_else(|e| e.into_inner())
                    .0
            }
            None => REAPER.wait(pending).unwrap_or_else(|e| e.into_inner()),
        };
    }
}
