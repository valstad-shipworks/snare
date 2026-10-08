//! Wakes reaching a deterministic schedule's address waiters from threads outside it.
//!
//! A participant of a deterministic domain waits on a condition variable, futex word or semaphore
//! in its schedule, not in the kernel, so only a wake that reaches the schedule ends the wait. A
//! thread of the same domain wakes it there itself. A thread of another sim, or of none (an
//! executor's worker shared across sims, a harness thread), only reaches the real object. So every
//! such wait is listed here by address while it lasts, and a wake from anywhere else on a listed
//! address is passed to the waiter's schedule. A wake that finds no waiter blocked there yet (it
//! raced the waiter's way into the schedule) is kept, and the wait it was meant for returns at
//! once.

use std::sync::atomic::AtomicUsize;
use std::sync::{Mutex, MutexGuard};

use super::{Arc, Domain, Inner, Ordering, det_wakes, state};
use crate::room::RoomVec;
use crate::sched::DetKey;
use crate::state::Passthrough;

/// How many locks the listing is split over, by address, so parallel deterministic sims seldom
/// share one. A snare choice.
const SHARDS: usize = 64;

/// How many waits a shard of [`WAITING`] lists before it allocates. A snare choice, past the
/// distinct addresses the deterministic sims hashed to one shard wait on at once: a waiter may be
/// inside a C allocator, waiting for one of its locks.
const SHARD_ROOM: usize = 16;

/// A deterministic wait on an address: (address, domain, how many of the domain's threads wait
/// there).
type Listing = (usize, usize, usize);

type Shard = RoomVec<Listing, SHARD_ROOM>;

/// Every deterministic waiter on an address, process-wide, split by address over [`SHARDS`]
/// locks.
static WAITING: [Mutex<Shard>; SHARDS] = [const { Mutex::new(RoomVec::new()) }; SHARDS];

/// How many entries [`WAITING`] holds, so a wake with no deterministic waiter anywhere skips the
/// lookup.
static WAITING_COUNT: AtomicUsize = AtomicUsize::new(0);

fn shard(addr: usize) -> MutexGuard<'static, Shard> {
    let index = (addr >> 3 ^ addr >> 12) % SHARDS;
    WAITING[index].lock().unwrap_or_else(|e| e.into_inner())
}

/// How many domains a wake gathers before it allocates: a snare choice, past the deterministic
/// sims that wait on one address at once.
pub(super) const WAKE_ROOM: usize = 8;

/// A deterministic wait on an address, listed until dropped.
pub(crate) struct DetAddrWait {
    addr: usize,
    domain: usize,
}

/// Lists a wait of a thread of `domain`'s schedule on `addr`.
pub(super) fn listen(addr: usize, domain: &Inner) -> DetAddrWait {
    let domain = domain.key();
    let _passthrough = Passthrough::enter();
    let mut waiting = shard(addr);
    match waiting.find_mut(|(a, d, _)| (*a, *d) == (addr, domain)) {
        Some(entry) => entry.2 += 1,
        None => {
            waiting.push((addr, domain, 1));
            WAITING_COUNT.fetch_add(1, Ordering::SeqCst);
        }
    }
    DetAddrWait { addr, domain }
}

impl Drop for DetAddrWait {
    fn drop(&mut self) {
        let _passthrough = Passthrough::enter();
        let mut waiting = shard(self.addr);
        let listed = (self.addr, self.domain);
        if let Some(entry) = waiting.find_mut(|(a, d, _)| (*a, *d) == listed) {
            entry.2 -= 1;
            if entry.2 == 0 {
                waiting.retain(|&(a, d, _)| (a, d) != listed);
                WAITING_COUNT.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
}

/// A wake on `addr` for up to `n` waiters whose futex mask meets `mask` (and, when given, of that
/// futex scope): passed to the schedule of every deterministic domain other than the calling
/// thread's own (whose wakes reach its schedule directly) with a thread waiting there. Returns
/// how many waiters it made runnable. snare's own service threads are left out: a clock's waker
/// thread runs while the schedule it wakes for holds its lock, waiting for it, and the schedule
/// re-polls its waiters once it is done.
pub(crate) fn wake_foreign(addr: usize, n: usize, mask: u32, private: Option<bool>) -> usize {
    if WAITING_COUNT.load(Ordering::SeqCst) == 0 || state::passthrough() || crate::census::serving()
    {
        return 0;
    }
    let own = if det_wakes() {
        state::domain() as usize
    } else {
        0
    };
    let _passthrough = Passthrough::enter();
    let mut domains = RoomVec::<Domain, WAKE_ROOM>::new();
    for &(_, d, _) in shard(addr)
        .iter()
        .filter(|&&(a, d, _)| a == addr && d != own)
    {
        let domain = d as *const Inner;
        // SAFETY: a listed waiter keeps its domain alive: its listing drops, under this lock,
        // before it leaves the domain.
        domains.push(unsafe {
            Arc::increment_strong_count(domain);
            Domain(Arc::from_raw(domain))
        });
    }
    let mut woken = 0;
    for domain in domains.iter() {
        let Some(sched) = domain.0.sched.as_ref() else {
            continue;
        };
        let reached = sched.wake_foreign(DetKey::Addr(addr), n, mask, private);
        if reached > 0 {
            domain.0.accounting.count_outside_wake();
        }
        woken += reached;
    }
    woken
}
