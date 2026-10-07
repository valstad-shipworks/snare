//! Which sim minted each virtual descriptor, for the whole process.
//!
//! A backend's descriptors are real fd numbers (a placeholder the OS will not hand out again), so
//! a thread of another sim that reaches one would otherwise go to the OS with the placeholder.
//! Backends record what they mint here; a hook that finds no backend of its own sim owning an fd
//! consults it before going to the OS (see `domain::elsewhere`). Lookups are a lock-free load per
//! fd, from a table grown in fixed chunks that are never freed.

use std::any::Any;
use std::ffi::c_int;
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use crate::census::SimId;
use crate::state::Passthrough;

/// Descriptors per chunk.
const CHUNK: usize = 4096;
/// Chunks in the table: room for fds below `CHUNK * CHUNKS` (4Mi), past Linux's default
/// `fs.nr_open` of 1Mi (Documentation/admin-guide/sysctl/fs.rst) and macOS's
/// `kern.maxfilesperproc`.
const CHUNKS: usize = 1024;

type Chunk = [AtomicU64; CHUNK];

type Table = [AtomicPtr<Chunk>; CHUNKS];

static TABLE: Table = [const { AtomicPtr::new(ptr::null_mut()) }; CHUNKS];

/// The serial of the sim whose file plane ([`Fs`](crate::Fs)) minted each descriptor, kept apart
/// from [`TABLE`]: an open file description is the process's, so a file is served by the plane
/// that opened it whichever thread reaches it, and never moves.
static FILES: Table = [const { AtomicPtr::new(ptr::null_mut()) }; CHUNKS];

/// The entry of a descriptor whose sim is gone: its placeholder stays open, but it names nothing.
const GONE: u64 = u64::MAX;
/// The entry of a process-local descriptor whose sim is gone, kept for the next sim to reach it.
const ORPHAN: u64 = u64::MAX - 1;

/// Who a descriptor belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Owner {
    /// No sim: a real descriptor, or none.
    None,
    /// The sim with this serial minted it. `local` marks a kernel object that belongs to the
    /// process rather than to a network (an epoll set, a kqueue, an eventfd, a timerfd), which
    /// may move to another sim of the process.
    Sim { serial: u64, local: bool },
    /// Its sim is gone, and it with it.
    Gone,
    /// Its sim is gone, but it belongs to the process: held for whichever sim reaches it next
    /// (see [`orphan`]).
    Orphan,
}

fn slot(fd: c_int, grow: bool) -> Option<&'static AtomicU64> {
    slot_in(&TABLE, fd, grow)
}

fn slot_in(table: &'static Table, fd: c_int, grow: bool) -> Option<&'static AtomicU64> {
    let fd = usize::try_from(fd).ok()?;
    let (chunk, index) = (fd / CHUNK, fd % CHUNK);
    let cell = table.get(chunk)?;
    let mut table = cell.load(Ordering::Acquire);
    if table.is_null() {
        if !grow {
            return None;
        }
        let fresh = Box::into_raw(Box::new([const { AtomicU64::new(0) }; CHUNK]));
        table = match cell.compare_exchange(
            ptr::null_mut(),
            fresh,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => fresh,
            Err(installed) => {
                // SAFETY: `fresh` came from `Box::into_raw` above and was never shared.
                drop(unsafe { Box::from_raw(fresh) });
                installed
            }
        };
    }
    // SAFETY: an installed chunk is never freed.
    Some(unsafe { &(*table)[index] })
}

/// Who owns `fd`.
pub(crate) fn owner(fd: c_int) -> Owner {
    match slot(fd, false).map_or(0, |entry| entry.load(Ordering::Acquire)) {
        0 => Owner::None,
        GONE => Owner::Gone,
        ORPHAN => Owner::Orphan,
        value => Owner::Sim {
            serial: value >> 1,
            local: value & 1 != 0,
        },
    }
}

/// Whether a sim minted `fd`, live or not: a placeholder, not a descriptor of the OS's own.
pub fn minted(fd: c_int) -> bool {
    owner(fd) != Owner::None
}

/// Records that `sim` minted `fd` (see [`Owner::Sim`] for `local`).
pub fn claim_fd(fd: c_int, sim: SimId, local: bool) {
    if let Some(entry) = slot(fd, true) {
        entry.store(sim.0 << 1 | u64::from(local), Ordering::Release);
    }
}

/// Forgets `fd`, if `sim` still owns it: closed, or replaced by another descriptor.
pub fn release_fd(fd: c_int, sim: SimId) {
    replace(fd, sim, 0);
}

/// Marks `fd` as belonging to a sim that is gone, if `sim` still owns it: its placeholder stays
/// open, so the number is not reused, and a later call on it fails with `EBADF`.
pub fn bury_fd(fd: c_int, sim: SimId) {
    replace(fd, sim, GONE);
}

/// Process-local descriptors whose sim is gone, each set with the state its backend gave up
/// (see [`Net::hand_over`](crate::Net::hand_over)).
static ORPHANS: Mutex<Vec<Orphaned>> = Mutex::new(Vec::new());

type Orphaned = (Vec<c_int>, Box<dyn Any + Send>);

/// Keeps process-local descriptors of `sim`, which is going away, for the next sim that reaches
/// one of them to take over with `state` (see [`Net::take_over`](crate::Net::take_over)): a
/// process keeps such objects whatever becomes of the worlds built around it. An fd `sim` no
/// longer owns (its placeholder closed behind the backend's back) is left out.
pub fn orphan(fds: Vec<c_int>, sim: SimId, state: Box<dyn Any + Send>) {
    let _passthrough = Passthrough::enter();
    let mut orphans = lock_orphans();
    let kept: Vec<c_int> = fds
        .into_iter()
        .filter(|&fd| replace(fd, sim, ORPHAN))
        .collect();
    if kept.is_empty() {
        drop(orphans);
        drop(state);
        return;
    }
    orphans.push((kept, state));
}

/// Takes the orphaned set holding `fd`, for `take` to offer its state, with the descriptors of it
/// still open, to a backend; a set no backend takes goes back.
pub(crate) fn adopt_orphan(
    fd: c_int,
    take: impl FnOnce(Box<dyn Any + Send>, &[c_int]) -> Result<(), Box<dyn Any + Send>>,
) -> bool {
    let mut orphans = lock_orphans();
    let Some(i) = orphans.iter().position(|(fds, _)| fds.contains(&fd)) else {
        return false;
    };
    let (fds, state) = orphans.swap_remove(i);
    match take(state, &fds) {
        Ok(()) => true,
        Err(state) => {
            orphans.push((fds, state));
            false
        }
    }
}

/// Forgets whatever sim `fd` was recorded against, as its real descriptor is about to be closed
/// or replaced by the OS: the number then names nothing of any sim, and the OS may hand it out
/// again. An orphaned descriptor leaves its set, so no later sim takes it over.
pub(crate) fn forget_real(fd: c_int) {
    release_file(fd);
    let Some(entry) = slot(fd, false) else {
        return;
    };
    let current = entry.load(Ordering::Acquire);
    if current == 0 {
        return;
    }
    if current != ORPHAN {
        let _ = entry.compare_exchange(current, 0, Ordering::AcqRel, Ordering::Acquire);
        return;
    }
    let _passthrough = Passthrough::enter();
    let emptied = {
        let mut orphans = lock_orphans();
        if entry
            .compare_exchange(ORPHAN, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let Some(i) = orphans.iter().position(|(fds, _)| fds.contains(&fd)) else {
            return;
        };
        orphans[i].0.retain(|&held| held != fd);
        orphans[i].0.is_empty().then(|| orphans.swap_remove(i))
    };
    drop(emptied);
}

/// Records that the file plane of sim `serial` minted `fd`.
pub(crate) fn claim_file(fd: c_int, serial: u64) {
    if let Some(entry) = slot_in(&FILES, fd, true) {
        entry.store(serial, Ordering::Release);
    }
}

/// Forgets which file plane minted `fd`: closed, or replaced by another descriptor.
pub(crate) fn release_file(fd: c_int) {
    if let Some(entry) = slot_in(&FILES, fd, false) {
        entry.store(0, Ordering::Release);
    }
}

/// The serial of the sim whose file plane minted `fd`, if one did.
pub(crate) fn file_owner(fd: c_int) -> Option<u64> {
    match slot_in(&FILES, fd, false)?.load(Ordering::Acquire) {
        0 => None,
        serial => Some(serial),
    }
}

/// Forgets `fd` as a file of sim `serial`, if it still is one.
pub(crate) fn release_file_of(fd: c_int, serial: u64) {
    if let Some(entry) = slot_in(&FILES, fd, false) {
        let _ = entry.compare_exchange(serial, 0, Ordering::AcqRel, Ordering::Acquire);
    }
}

fn lock_orphans() -> std::sync::MutexGuard<'static, Vec<Orphaned>> {
    ORPHANS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Moves `fd`'s entry from `sim` to `with`, if `sim` still owns it; whether it did.
fn replace(fd: c_int, sim: SimId, with: u64) -> bool {
    let Some(entry) = slot(fd, false) else {
        return false;
    };
    let mut current = entry.load(Ordering::Acquire);
    while current != 0 && current != GONE && current != ORPHAN && current >> 1 == sim.0 {
        match entry.compare_exchange(current, with, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(seen) => current = seen,
        }
    }
    false
}
