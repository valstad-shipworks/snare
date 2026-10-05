//! A value made on first use that no caller ever waits for: callers that race to make it each make
//! one, the first to publish wins and the rest drop theirs.
//!
//! The sim's process-wide singletons use it in place of `OnceLock` because they are reached from
//! inside hooked waits, on a thread std has already parked on its own parker. A `OnceLock` caller
//! that arrives while another thread is initialising it waits for that thread; on macOS that wait
//! parks with `thread::park` (library/std/src/sys/sync/once/queue.rs, `wait`), on the very parker
//! the thread is parked on already, and the parker cannot track two parks at once
//! (library/std/src/sys/sync/thread_parking/darwin.rs: the second `fetch_sub` takes `state` below
//! `PARKED`, so `unpark` sees no parked thread and signals nothing). See `os::sync` for how a nested
//! wait like that is still woken; this cell avoids making one at all.

use std::marker::PhantomData;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

/// A value made on first use without blocking (see the module docs). Its value is boxed once and
/// freed with the cell.
pub struct RaceCell<T> {
    /// The published value, null until one is.
    value: AtomicPtr<T>,
    /// Owns a `T`, for drop check and auto traits.
    _owns: PhantomData<Box<T>>,
}

// SAFETY: the cell shares its `T` across threads by reference once published and drops it on the
// thread that drops the cell, as `OnceLock<T>` does.
unsafe impl<T: Send + Sync> Sync for RaceCell<T> {}
// SAFETY: as above; moving the cell moves ownership of the boxed `T`.
unsafe impl<T: Send> Send for RaceCell<T> {}

impl<T> RaceCell<T> {
    /// An empty cell.
    pub const fn new() -> Self {
        Self {
            value: AtomicPtr::new(ptr::null_mut()),
            _owns: PhantomData,
        }
    }

    /// The value, if one has been published.
    pub fn get(&self) -> Option<&T> {
        // SAFETY: a non-null pointer was published by `get_or_init` from `Box::into_raw` with
        // release ordering, read here with acquire, and lives until the cell drops.
        unsafe { self.value.load(Ordering::Acquire).as_ref() }
    }

    /// The value, making it with `make` if none is published yet, and whether this call's value
    /// is the one published. Callers racing here may each run `make`; exactly one of them is told
    /// it won, and the others' values are dropped unused, so `make` must have no effect beyond
    /// building the value: a winner starts whatever goes with it.
    pub fn get_or_init(&self, make: impl FnOnce() -> T) -> (&T, bool) {
        if let Some(value) = self.get() {
            return (value, false);
        }
        let mine = Box::into_raw(Box::new(make()));
        match self.value.compare_exchange(
            ptr::null_mut(),
            mine,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            // SAFETY: `mine` is now published, for the cell's life.
            Ok(_) => (unsafe { &*mine }, true),
            Err(theirs) => {
                // SAFETY: `mine` was never published, so this is its only owner; `theirs` is the
                // non-null value another caller published.
                unsafe {
                    drop(Box::from_raw(mine));
                    (&*theirs, false)
                }
            }
        }
    }
}

impl<T> Default for RaceCell<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for RaceCell<T> {
    fn drop(&mut self) {
        let value = *self.value.get_mut();
        if !value.is_null() {
            // SAFETY: published from `Box::into_raw` and owned by the cell alone.
            unsafe { drop(Box::from_raw(value)) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RaceCell;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn racing_callers_share_one_value_and_exactly_one_wins() {
        let cell = RaceCell::new();
        let made = AtomicUsize::new(0);
        let start = Barrier::new(8);
        let results: Vec<(usize, bool)> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|i| {
                    let (cell, made, start) = (&cell, &made, &start);
                    s.spawn(move || {
                        start.wait();
                        let (value, won) = cell.get_or_init(|| {
                            made.fetch_add(1, Ordering::SeqCst);
                            i
                        });
                        (*value, won)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let published = *cell.get().unwrap();
        assert!(results.iter().all(|&(value, _)| value == published));
        assert_eq!(results.iter().filter(|&&(_, won)| won).count(), 1);
        assert!(
            results
                .iter()
                .any(|&(value, won)| won && value == published)
        );
        assert!(made.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn a_published_value_is_kept() {
        let cell = RaceCell::new();
        assert_eq!(cell.get_or_init(|| 1), (&1, true));
        assert_eq!(cell.get_or_init(|| 2), (&1, false));
        assert_eq!(cell.get(), Some(&1));
    }
}
