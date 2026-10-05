//! The two per-thread switches every hook reads first: which domain the thread belongs to, and
//! whether its hooked calls are currently going straight to the OS.
//!
//! A thread is managed exactly when [`domain`] is non-null and [`passthrough`] is `false`. Code
//! that runs on behalf of the sim (a layer, the domain's own bookkeeping) holds a [`Passthrough`]
//! guard, so its own clock reads, locks and sockets are never redirected back into the sim.

use std::cell::Cell;
use std::ptr;

use crate::domain::Inner;

// Both slots are const-initialized with no destructor, so reading them from inside a hook never
// allocates, never registers a TLS destructor and keeps working while the thread is torn down.
// The `try_with` fallbacks below cover a slot that cannot be reached all the same.
thread_local! {
    /// The calling thread's domain, borrowed: the [`Managed`](crate::Managed) guard that installed
    /// it owns a strong reference to the `Inner` and restores the previous pointer on drop, so the
    /// pointer stays valid while it is installed.
    static DOMAIN: Cell<*const Inner> = const { Cell::new(ptr::null()) };
    /// `true` while the thread is running sim code whose OS calls must not be redirected.
    static PASSTHROUGH: Cell<bool> = const { Cell::new(false) };
}

/// The calling thread's domain, null when it has none or the slot cannot be reached.
pub(crate) fn domain() -> *const Inner {
    DOMAIN.try_with(Cell::get).unwrap_or(ptr::null())
}

/// Installs `domain` as the calling thread's domain and returns the previous one, for the caller
/// to restore; null, with nothing installed, if the slot cannot be reached.
pub(crate) fn replace_domain(domain: *const Inner) -> *const Inner {
    DOMAIN
        .try_with(|d| d.replace(domain))
        .unwrap_or(ptr::null())
}

/// Whether the calling thread's hooked calls go straight to the OS. A slot that cannot be reached
/// reads as passthrough, so a hook never touches a domain it cannot track.
pub(crate) fn passthrough() -> bool {
    PASSTHROUGH.try_with(Cell::get).unwrap_or(true)
}

/// While alive, the calling thread's hooked calls go to the OS.
///
/// Guards nest: each restores the value it found on drop, so they must be dropped in reverse order
/// of creation, as scoped guards are.
pub(crate) struct Passthrough {
    /// The switch's value before this guard set it.
    previous: bool,
}

impl Passthrough {
    /// Switches redirection off for the calling thread until the guard drops.
    pub(crate) fn enter() -> Self {
        Self::set(true)
    }

    /// While alive, the calling thread's hooked calls are offered to its domain again, even inside
    /// a passthrough scope.
    pub(crate) fn leave() -> Self {
        Self::set(false)
    }

    /// Sets the switch to `value`, remembering the old one; `true` if the slot cannot be reached.
    fn set(value: bool) -> Self {
        let previous = PASSTHROUGH.try_with(|p| p.replace(value)).unwrap_or(true);
        Self { previous }
    }
}

impl Drop for Passthrough {
    fn drop(&mut self) {
        let _ = PASSTHROUGH.try_with(|p| p.set(self.previous));
    }
}
