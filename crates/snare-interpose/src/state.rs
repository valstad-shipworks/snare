use std::cell::Cell;
use std::ptr;

use crate::domain::Inner;

// Both slots are const-initialized with no destructor, so reading them from inside a hook never
// allocates, never registers a TLS destructor and keeps working while the thread is torn down.
thread_local! {
    static DOMAIN: Cell<*const Inner> = const { Cell::new(ptr::null()) };
    static PASSTHROUGH: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn domain() -> *const Inner {
    DOMAIN.try_with(Cell::get).unwrap_or(ptr::null())
}

pub(crate) fn replace_domain(domain: *const Inner) -> *const Inner {
    DOMAIN
        .try_with(|d| d.replace(domain))
        .unwrap_or(ptr::null())
}

pub(crate) fn passthrough() -> bool {
    PASSTHROUGH.try_with(Cell::get).unwrap_or(true)
}

/// While alive, the calling thread's hooked calls go to the OS.
pub(crate) struct Passthrough {
    previous: bool,
}

impl Passthrough {
    pub(crate) fn enter() -> Self {
        let previous = PASSTHROUGH.try_with(|p| p.replace(true)).unwrap_or(true);
        Self { previous }
    }
}

impl Drop for Passthrough {
    fn drop(&mut self) {
        let _ = PASSTHROUGH.try_with(|p| p.set(self.previous));
    }
}
