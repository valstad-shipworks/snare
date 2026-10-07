//! A hooked wait made while the calling thread already waits on the same object further up its own
//! stack. Sim code runs inside a participant's hooked wait — the deterministic schedule's dispatch,
//! and a layer's time skip in it, inside `det_block`; an idle skip as a native wait begins — and
//! when that wait is std's thread parker, a std wait in the sim code that parks (a channel, and on
//! macOS a contended `Once`/`OnceLock` or `RwLock`, library/std/src/sys/sync/once/queue.rs and
//! rwlock/queue.rs) parks the same parker again.
//!
//! std's parker tracks one park at a time. `park` takes its `state` from `EMPTY` to `PARKED` with a
//! `fetch_sub` and `unpark` wakes the OS wait only if its swap to `NOTIFIED` finds `PARKED`
//! (library/std/src/sys/sync/thread_parking/darwin.rs, futex.rs). A second park takes `state` past
//! `PARKED`, so the `unpark` meant for it wakes nothing; and the two parks share the one
//! notification, so whichever returns first consumes the `unpark` the other waits for.
//!
//! So a nested wait waits for real only for a short slice ([`NESTED_WAIT_SLICE`]) and then returns
//! as woken, as std's parker allows (`thread::park` "may also return *spuriously*",
//! library/std/src/thread/functions.rs): its caller re-checks what it waits for and waits again,
//! until whatever it waits for has happened. The outer wait is marked spoiled and returns as woken
//! at its next chance, never timed out, so its caller re-checks too rather than wait for an
//! `unpark` that has been and gone; a deterministic schedule re-polls it once the dispatch the
//! nested wait ran in is over (`sched::repoll_self`). Where std's parker loops until `state` reads
//! `NOTIFIED` (futex.rs, on Linux and Windows) the outer wait first puts the notification back
//! ([`settle_parker`]), which also covers a nested park that found the notification waiting and
//! took it without ever reaching the OS.

use std::cell::{Cell, RefCell};
use std::time::Duration;

/// How many hooked waits one thread can have in progress at once and still tell a nested one: one
/// for each wait the sim's own code runs inside another. A snare choice, well past the two or
/// three a dispatch inside a parked wait reaches; a wait beyond it goes untracked.
const MAX_WAITS: usize = 8;

/// The hooked waits in progress on a thread, outermost first: each object waited on, and whether
/// a wait nested in it spoiled it. Fixed-size, so the futex and semaphore hooks that keep it never
/// allocate, nor register a destructor on a thread's first wait, either of which could reenter an
/// allocator that waits on a lock of its own.
struct Waits {
    waits: [(usize, bool); MAX_WAITS],
    len: usize,
}

impl Waits {
    fn active(&self) -> &[(usize, bool)] {
        &self.waits[..self.len]
    }

    fn active_mut(&mut self) -> &mut [(usize, bool)] {
        &mut self.waits[..self.len]
    }
}

thread_local! {
    static WAITS: RefCell<Waits> = const {
        RefCell::new(Waits {
            waits: [(0, false); MAX_WAITS],
            len: 0,
        })
    };
    static STARTING: Cell<bool> = const { Cell::new(false) };
}

/// Adoption precedes Rust's ThreadInit, which requires an uninitialized current-thread handle.
pub(crate) struct Startup {
    previous: bool,
}

pub(crate) fn startup() -> Startup {
    Startup {
        previous: STARTING.with(|starting| starting.replace(true)),
    }
}

impl Drop for Startup {
    fn drop(&mut self) {
        let _ = STARTING.try_with(|starting| starting.set(self.previous));
    }
}

/// How long one real wait nested in another on the same object lasts before it returns to its
/// caller to re-check: a snare choice, short enough that the caller sees its condition met
/// promptly, long enough not to spin.
pub(crate) const NESTED_WAIT_SLICE: Duration = Duration::from_millis(1);

/// A hooked wait on the object at `addr` in progress on the calling thread, from [`begin`]. Dropping
/// it ends the wait.
pub(crate) struct Outer {
    /// The object waited on.
    addr: usize,
}

/// Begins a hooked wait on the object at `addr`, or returns `None` if the calling thread already
/// waits on it further up its stack: the wait is nested, the enclosing one is now spoiled, and the
/// caller makes a [`NESTED_WAIT_SLICE`] wait instead.
pub(crate) fn begin(addr: usize) -> Option<Outer> {
    let nested = WAITS
        .try_with(|waits| {
            let mut waits = waits.borrow_mut();
            if let Some(wait) = waits.active_mut().iter_mut().find(|wait| wait.0 == addr) {
                wait.1 = true;
                true
            } else {
                if waits.len < MAX_WAITS {
                    let len = waits.len;
                    waits.waits[len] = (addr, false);
                    waits.len += 1;
                }
                false
            }
        })
        .unwrap_or(false);
    if nested {
        crate::sched::repoll_self();
        None
    } else {
        Some(Outer { addr })
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn waiting(addr: usize) -> bool {
    WAITS
        .try_with(|waits| waits.borrow().active().iter().any(|wait| wait.0 == addr))
        .unwrap_or(false)
}

/// Whether a nested wait spoiled the calling thread's wait on `addr`.
pub(crate) fn spoiled(addr: usize) -> bool {
    WAITS
        .try_with(|waits| {
            waits
                .borrow()
                .active()
                .iter()
                .any(|wait| wait.0 == addr && wait.1)
        })
        .unwrap_or(false)
}

impl Outer {
    /// Whether a wait nested in this one spoiled it: it then returns as woken.
    pub(crate) fn spoiled(&self) -> bool {
        spoiled(self.addr)
    }
}

impl Drop for Outer {
    fn drop(&mut self) {
        let clear = WAITS
            .try_with(|waits| {
                let mut waits = waits.borrow_mut();
                let active = waits.active_mut();
                if let Some(index) = active.iter().rposition(|wait| wait.0 == self.addr) {
                    active.copy_within(index + 1.., index);
                    waits.len -= 1;
                }
                !waits.active().iter().any(|wait| wait.1)
            })
            .unwrap_or(true);
        if clear {
            crate::sched::clear_repoll_self();
        }
    }
}

/// Whether a nested wait spoiled the outer wait, restoring the current thread's park
/// notification without changing the caller's synchronization word.
#[cfg(any(target_os = "linux", windows))]
pub(crate) unsafe fn settle_parker(
    outer: &Outer,
    addr: usize,
    size: usize,
    expected: u64,
    before: u64,
) -> bool {
    let spoiled = outer.spoiled();
    let parked = match size {
        1 => expected == u64::from(u8::MAX),
        4 => expected == u64::from(u32::MAX),
        _ => false,
    } && before == expected;
    if !STARTING.try_with(Cell::get).unwrap_or(true)
        && (spoiled || (parked && unsafe { load(addr, size) } == 0))
    {
        // An all-ones wait can also belong to an RwLock, whose word must remain untouched.
        crate::real(|| std::thread::current().unpark());
    }
    spoiled
}

#[cfg(any(target_os = "linux", windows))]
pub(crate) unsafe fn load(addr: usize, size: usize) -> u64 {
    use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};
    match size {
        1 => u64::from(unsafe { &*(addr as *const AtomicU8) }.load(Ordering::Acquire)),
        4 => u64::from(unsafe { &*(addr as *const AtomicU32) }.load(Ordering::Acquire)),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::begin;

    #[test]
    fn nested_startup_scopes_preserve_the_outer_scope() {
        assert!(!super::STARTING.with(std::cell::Cell::get));
        let outer = super::startup();
        assert!(super::STARTING.with(std::cell::Cell::get));
        let inner = super::startup();
        drop(inner);
        assert!(super::STARTING.with(std::cell::Cell::get));
        drop(outer);
        assert!(!super::STARTING.with(std::cell::Cell::get));
    }

    #[test]
    fn detects_a_wait_beneath_a_different_wait() {
        let first = begin(1).unwrap();
        let second = begin(2).unwrap();
        assert!(begin(1).is_none());
        assert!(first.spoiled());
        assert!(!second.spoiled());
        drop(second);
        assert!(first.spoiled());
        drop(first);
        assert!(!begin(1).unwrap().spoiled());
    }

    #[test]
    fn preserves_multiple_spoiled_waits() {
        let first = begin(1).unwrap();
        let second = begin(2).unwrap();
        assert!(begin(1).is_none());
        assert!(begin(2).is_none());
        drop(second);
        assert!(first.spoiled());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_nested_all_ones_wait_does_not_modify_the_callers_word() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let word = AtomicU32::new(0);
        let addr = std::ptr::from_ref(&word) as usize;
        let outer = begin(addr).unwrap();
        assert!(begin(addr).is_none());
        assert!(unsafe {
            super::settle_parker(&outer, addr, 4, u64::from(u32::MAX), u64::from(u32::MAX))
        });
        assert_eq!(word.load(Ordering::Acquire), 0);
        std::thread::park_timeout(std::time::Duration::ZERO);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn an_all_ones_wait_does_not_identify_a_thread_parker() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let word = AtomicU32::new(0);
        let addr = std::ptr::from_ref(&word) as usize;
        let outer = begin(addr).unwrap();
        assert!(!unsafe {
            super::settle_parker(&outer, addr, 4, u64::from(u32::MAX), u64::from(u32::MAX))
        });
        assert_eq!(word.load(Ordering::Acquire), 0);
    }
}
