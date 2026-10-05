//! Per-resource wait sets for the network shim.
//!
//! A blocking socket call registers a [`WaitTicket`] on the resources it
//! depends on *before* checking readiness, then parks on the ticket. A
//! mutation notifies only its own resource's set, and a notify that lands
//! between the check and the park marks the ticket's cell woken, so the park
//! returns at once instead of missing the wake.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use super::ParkResult;
use super::timer::ParkCell;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum WaitKey {
    /// A TCP connection end, by stream id.
    Stream(usize),
    /// A TCP listener's accept queue.
    Listener(SocketAddr),
    /// A UDP socket's inbound queue.
    Udp(SocketAddr),
    /// Policy or quiesce changes on a local address.
    Addr(SocketAddr),
    /// A mio `Poll`'s waker.
    #[cfg_attr(not(feature = "mio-compat"), allow(dead_code))]
    Poll(u64),
    /// Every notification in the slot.
    Any,
}

type Waiters = Vec<(u64, Arc<ParkCell>)>;

#[derive(Default)]
pub(crate) struct WaitSets {
    sets: Mutex<HashMap<WaitKey, Waiters>>,
    next: AtomicU64,
}

impl WaitSets {
    fn add(&self, keys: &[WaitKey], cell: &Arc<ParkCell>) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        super::note_lock();
        let mut sets = self.sets.lock();
        for key in keys {
            sets.entry(*key).or_default().push((id, Arc::clone(cell)));
        }
        id
    }

    fn remove(&self, id: u64, keys: &[WaitKey]) {
        super::note_lock();
        let mut sets = self.sets.lock();
        for key in keys {
            if let Some(waiters) = sets.get_mut(key) {
                waiters.retain(|(w, _)| *w != id);
                if waiters.is_empty() {
                    sets.remove(key);
                }
            }
        }
    }

    /// Wake every waiter registered on `key`, and every waiter on
    /// [`WaitKey::Any`], each set in registration order.
    pub(crate) fn notify(&self, key: WaitKey) {
        let cells: Vec<Arc<ParkCell>> = {
            super::note_lock();
            let sets = self.sets.lock();
            let own = sets.get(&key).into_iter().flatten();
            let any = (key != WaitKey::Any)
                .then(|| sets.get(&WaitKey::Any))
                .flatten()
                .into_iter()
                .flatten();
            own.chain(any).map(|(_, c)| Arc::clone(c)).collect()
        };
        for cell in cells {
            cell.unpark();
        }
    }

    #[cfg(test)]
    fn waiters(&self, key: WaitKey) -> usize {
        self.sets.lock().get(&key).map_or(0, Vec::len)
    }
}

/// A registration on one or more wait sets, taken before a readiness check.
pub(crate) struct WaitTicket {
    sets: Arc<WaitSets>,
    id: u64,
    keys: Vec<WaitKey>,
    cell: Arc<ParkCell>,
}

impl WaitTicket {
    /// Register the calling thread on `keys`. Must not be called while the
    /// shim's state lock is held.
    pub(crate) fn register(keys: impl IntoIterator<Item = WaitKey>) -> Self {
        let sets = super::slot::with_slot(|s| Arc::clone(s.waits()));
        let keys: Vec<WaitKey> = keys.into_iter().collect();
        let cell = Arc::new(ParkCell::default());
        let id = sets.add(&keys, &cell);
        Self {
            sets,
            id,
            keys,
            cell,
        }
    }

    /// Park until a registered resource is notified or the virtual
    /// `deadline` passes. `wait` names the wait for the driver's participant
    /// table.
    pub(crate) fn wait(
        self,
        deadline: Option<crate::time::Instant>,
        wait: &'static str,
    ) -> ParkResult {
        run_hook(wait);
        super::park::wait_on(
            &self.cell,
            deadline.map(super::slot::instant_ns),
            wait,
            true,
        )
    }
}

impl Drop for WaitTicket {
    fn drop(&mut self) {
        self.sets.remove(self.id, &self.keys);
    }
}

type Hook = Box<dyn FnMut(&'static str)>;

thread_local! {
    static WAIT_HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
}

fn run_hook(wait: &'static str) {
    let hook = WAIT_HOOK.try_with(|h| h.borrow_mut().take()).ok().flatten();
    if let Some(mut hook) = hook {
        hook(wait);
        let _ = WAIT_HOOK.try_with(|h| {
            let mut slot = h.borrow_mut();
            if slot.is_none() {
                *slot = Some(hook);
            }
        });
    }
}

/// Install a hook that runs on the calling thread between a socket wait's
/// readiness check and its park, with the wait's name. For tests that
/// inject a notification into that window.
#[doc(hidden)]
pub fn set_wait_hook(hook: Option<Box<dyn FnMut(&'static str)>>) {
    let _ = WAIT_HOOK.try_with(|h| *h.borrow_mut() = hook);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_reaches_own_set_and_any_only() {
        let sets = WaitSets::default();
        let a = Arc::new(ParkCell::default());
        let b = Arc::new(ParkCell::default());
        let any = Arc::new(ParkCell::default());
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let ia = sets.add(&[WaitKey::Stream(1)], &a);
        let _ib = sets.add(&[WaitKey::Udp(addr)], &b);
        let _iany = sets.add(&[WaitKey::Any], &any);
        sets.notify(WaitKey::Stream(1));
        assert!(a.take_woken());
        assert!(!b.take_woken());
        assert!(any.take_woken());
        sets.remove(ia, &[WaitKey::Stream(1)]);
        assert_eq!(sets.waiters(WaitKey::Stream(1)), 0);
        assert_eq!(sets.waiters(WaitKey::Udp(addr)), 1);
    }
}
