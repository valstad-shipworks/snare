use std::fmt;
use std::task::Waker;

use parking_lot::Mutex;

/// The wakers of every task waiting on one piece of state, for futures whose
/// state can be awaited from several places at once (clones of a handle).
///
/// A waiting `poll` must [`register`](Self::register) its waker *before* it
/// checks the state, and return `Pending` only if the check still fails
/// afterwards. The side that changes the state does so first and then calls
/// [`wake_all`](Self::wake_all). Either the check sees the change or the
/// registration is in place when `wake_all` runs, so no wake is lost.
#[derive(Default)]
pub struct WakerSet {
    wakers: Mutex<Vec<Waker>>,
}

impl WakerSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `waker`, replacing an entry that would wake the same task.
    pub fn register(&self, waker: &Waker) {
        let mut wakers = self.wakers.lock();
        match wakers.iter_mut().find(|w| w.will_wake(waker)) {
            Some(w) => w.clone_from(waker),
            None => wakers.push(waker.clone()),
        }
    }

    /// Remove every registered waker and wake it.
    pub fn wake_all(&self) {
        let wakers = std::mem::take(&mut *self.wakers.lock());
        for w in wakers {
            w.wake();
        }
    }
}

impl fmt::Debug for WakerSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WakerSet")
            .field("waiting", &self.wakers.lock().len())
            .finish()
    }
}
