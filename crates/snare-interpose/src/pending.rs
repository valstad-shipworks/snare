//! Changes a hook makes to state behind a lock it must not wait for, kept for that lock's next
//! holder.
//!
//! A C allocator installed as the global allocator calls the lock, unlock and wake hooks from
//! inside its own critical sections, so the thread making a change may hold a lock the allocator
//! needs: waiting there for a lock whose holder is allocating, or allocating itself, deadlocks the
//! allocator. Such a change is applied at once when its lock is free, and otherwise queued in a
//! [`Pending`], which never allocates, for whoever takes the lock next. Every taker applies the
//! queue before it reads anything, so a reader sees each change whose hook returned before it took
//! the lock, just as it would have had the hook waited for the lock instead.

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};

/// How many changes a [`Pending`] queues at most. A snare choice, far past the hooks that run while
/// one critical section lasts; a change that finds the queue full waits for the lock.
const CAPACITY: usize = 1024;

/// A pthread mutex taken or let go by a thread of the domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MutexRecord {
    pub(crate) mutex: usize,
    pub(crate) lineage: u64,
    pub(crate) taken: bool,
}

struct Slot<T> {
    /// The ticket of the change this slot holds once filled (one past it), or of the next one it
    /// may take (the ticket itself): Dmitry Vyukov's bounded queue.
    seq: AtomicUsize,
    value: UnsafeCell<MaybeUninit<T>>,
}

/// Changes queued for the holder of the lock they are for, oldest first, in a ring made once. Any
/// thread pushes; only the lock's holder [`drain`](Self::drain)s.
pub(crate) struct Pending<T> {
    slots: Box<[Slot<T>]>,
    /// The next ticket a push claims.
    tail: AtomicUsize,
    /// The next ticket a drain applies.
    head: AtomicUsize,
}

// SAFETY: a slot's value is written only by the push that claimed its ticket and read only by the
// drain, each ordered against the other by the slot's `seq`.
unsafe impl<T: Send> Sync for Pending<T> {}

impl<T> Default for Pending<T> {
    fn default() -> Self {
        Self {
            slots: (0..CAPACITY)
                .map(|i| Slot {
                    seq: AtomicUsize::new(i),
                    value: UnsafeCell::new(MaybeUninit::uninit()),
                })
                .collect(),
            tail: AtomicUsize::new(0),
            head: AtomicUsize::new(0),
        }
    }
}

impl<T: Copy> Pending<T> {
    /// Queues `value` for the lock's next holder, or returns `false` if the queue is full.
    pub(crate) fn push(&self, value: T) -> bool {
        let mut pos = self.tail.load(Ordering::SeqCst);
        loop {
            let slot = &self.slots[pos % CAPACITY];
            let seq = slot.seq.load(Ordering::Acquire);
            match (seq.wrapping_sub(pos) as isize).signum() {
                0 => match self.tail.compare_exchange_weak(
                    pos,
                    pos.wrapping_add(1),
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => {
                        // SAFETY: the ticket is this push's alone until `seq` publishes it.
                        unsafe { (*slot.value.get()).write(value) };
                        slot.seq.store(pos.wrapping_add(1), Ordering::Release);
                        return true;
                    }
                    Err(current) => pos = current,
                },
                -1 => return false,
                _ => pos = self.tail.load(Ordering::SeqCst),
            }
        }
    }

    /// Hands `apply` every change pushed before the call, oldest first. Only the lock's holder
    /// calls it. A push that has claimed its ticket but not yet filled the slot is waited for: it
    /// has only a copy and a store left to make, neither of which can block.
    pub(crate) fn drain(&self, mut apply: impl FnMut(T)) {
        let end = self.tail.load(Ordering::SeqCst);
        let mut pos = self.head.load(Ordering::Relaxed);
        while pos != end {
            let slot = &self.slots[pos % CAPACITY];
            let mut spins = 0u32;
            while slot.seq.load(Ordering::Acquire) != pos.wrapping_add(1) {
                spins += 1;
                if spins.is_multiple_of(64) {
                    std::thread::yield_now();
                } else {
                    std::hint::spin_loop();
                }
            }
            // SAFETY: `seq` says the push that claimed this ticket has written its value.
            let value = unsafe { (*slot.value.get()).assume_init() };
            slot.seq
                .store(pos.wrapping_add(CAPACITY), Ordering::Release);
            pos = pos.wrapping_add(1);
            self.head.store(pos, Ordering::SeqCst);
            apply(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(n: usize) -> MutexRecord {
        MutexRecord {
            mutex: n,
            lineage: n as u64 * 3,
            taken: n.is_multiple_of(2),
        }
    }

    #[test]
    fn drains_in_push_order_and_refuses_past_capacity() {
        let records = Pending::default();
        for round in 0..3 {
            for n in 0..CAPACITY {
                assert!(records.push(record(round * CAPACITY + n)));
            }
            assert!(!records.push(record(0)));
            let mut seen = Vec::new();
            records.drain(|r| seen.push(r));
            let expected: Vec<_> = (0..CAPACITY).map(|n| record(round * CAPACITY + n)).collect();
            assert_eq!(seen, expected);
        }
    }

    #[test]
    fn concurrent_pushes_each_drain_once_in_each_threads_order() {
        let records = std::sync::Arc::new(Pending::default());
        let threads: Vec<_> = (0..4usize)
            .map(|t| {
                let records = records.clone();
                std::thread::spawn(move || {
                    for i in 0..10_000usize {
                        while !records.push(MutexRecord {
                            mutex: t,
                            lineage: i as u64,
                            taken: true,
                        }) {
                            std::thread::yield_now();
                        }
                    }
                })
            })
            .collect();
        let drainer = std::sync::Mutex::new(());
        let mut next = [0u64; 4];
        let mut drained = 0;
        while drained < 40_000 {
            let _held = drainer.lock().unwrap();
            records.drain(|r: MutexRecord| {
                assert_eq!(r.lineage, next[r.mutex]);
                next[r.mutex] += 1;
                drained += 1;
            });
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(next, [10_000; 4]);
    }
}
