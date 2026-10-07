//! Advisory locks on a virtual inode: `fcntl(2)` record locks and `flock(2)` locks.
//!
//! Record locks are owned by the process (`F_SETLK`, `F_SETLKW`) or by an open file description
//! (`F_OFD_SETLK`, `F_OFD_SETLKW`). Every thread is in the one process, so process-owned locks
//! never conflict with each other: they only split, merge and replace one another, and they all go
//! when any descriptor of the inode is closed (POSIX.1-2017, `fcntl`, "all locks associated with a
//! file for a given process shall be removed when a file descriptor for that file is closed by
//! that process"). Description-owned locks conflict with every other owner and go when the last
//! descriptor of their description closes. `flock` locks are whole-file, owned by the description,
//! and independent of record locks, as on Linux (man 2 flock, NOTES).
//!
//! A blocking request waits on [`readiness`], so the wait is seen by quiescence and the
//! deterministic schedule like any other blocked call; a release wakes every waiter to retry.

use std::ffi::c_int;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use snare_interpose::NetResult as FsResult;

use crate::fs_sim::{err, ok};
use crate::readiness::readiness;

/// The end of a range that runs to the end of the file, however far it grows (`l_len` 0).
const TO_END: u64 = u64::MAX;

/// The `l_type` values, `c_short` on macOS and `c_int` in Linux's `libc`.
const READ: c_int = libc::F_RDLCK as c_int;
const WRITE: c_int = libc::F_WRLCK as c_int;
const UNLOCK: c_int = libc::F_UNLCK as c_int;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Owner {
    Process,
    Description(u64),
}

#[derive(Clone, Copy)]
struct Range {
    start: u64,
    /// Exclusive; [`TO_END`] for a lock that covers any later growth.
    end: u64,
    write: bool,
    owner: Owner,
}

impl Range {
    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }
}

#[derive(Default)]
struct Table {
    records: Vec<Range>,
    /// `flock` holders: the description and whether its lock is exclusive.
    flocks: Vec<(u64, bool)>,
}

impl Table {
    fn conflict(&self, owner: Owner, start: u64, end: u64, write: bool) -> Option<Range> {
        self.records
            .iter()
            .copied()
            .find(|r| r.owner != owner && (write || r.write) && r.overlaps(start, end))
    }

    /// Replaces `owner`'s locks over `[start, end)` with one of type `write`, or with none,
    /// trimming the locks it overlaps and merging with adjacent ones of the same type.
    fn set(&mut self, owner: Owner, start: u64, end: u64, write: Option<bool>) -> bool {
        let mut released = false;
        let mut kept = Vec::with_capacity(self.records.len() + 2);
        for r in self.records.drain(..) {
            if r.owner != owner || !r.overlaps(start, end) {
                kept.push(r);
                continue;
            }
            released |= write != Some(true) || r.write;
            if r.start < start {
                kept.push(Range { end: start, ..r });
            }
            if r.end > end {
                kept.push(Range { start: end, ..r });
            }
        }
        if let Some(write) = write {
            let (mut low, mut high) = (start, end);
            kept.retain(|r| {
                let joins =
                    r.owner == owner && r.write == write && r.start <= end && start <= r.end;
                if joins {
                    low = low.min(r.start);
                    high = high.max(r.end);
                }
                !joins
            });
            kept.push(Range {
                start: low,
                end: high,
                write,
                owner,
            });
        }
        kept.sort_by_key(|r| r.start);
        self.records = kept;
        released
    }

    fn flock_conflict(&self, description: u64, exclusive: bool) -> bool {
        self.flocks
            .iter()
            .any(|&(holder, held)| holder != description && (exclusive || held))
    }
}

/// The advisory locks of one inode.
#[derive(Default)]
pub(crate) struct Locks(Mutex<Table>);

/// A fresh open-file-description identity to own OFD and `flock` locks.
pub(crate) fn description() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// What a lock call needs from its descriptor, read under the open-file table.
pub(crate) struct Target {
    pub(crate) readable: bool,
    pub(crate) writable: bool,
    pub(crate) cursor: u64,
    pub(crate) len: u64,
    pub(crate) description: u64,
}

enum Request {
    Get,
    Set,
    Wait,
}

fn classify(cmd: c_int) -> Option<(Request, bool)> {
    Some(match cmd {
        libc::F_GETLK => (Request::Get, false),
        libc::F_SETLK => (Request::Set, false),
        libc::F_SETLKW => (Request::Wait, false),
        libc::F_OFD_GETLK => (Request::Get, true),
        libc::F_OFD_SETLK => (Request::Set, true),
        libc::F_OFD_SETLKW => (Request::Wait, true),
        _ => return None,
    })
}

/// Whether `cmd` is a record-lock command [`Locks::fcntl`] serves.
pub(crate) fn is_record_lock(cmd: c_int) -> bool {
    classify(cmd).is_some()
}

/// The byte range `[start, end)` a `struct flock` names (man 2 fcntl, "Advisory record locking"):
/// `l_start` from `l_whence`, extending `l_len` bytes forward, `-l_len` bytes back when negative,
/// or to the end of the file when 0.
fn span(lock: &libc::flock, target: &Target) -> Result<(u64, u64), c_int> {
    let base = match c_int::from(lock.l_whence) {
        libc::SEEK_SET => 0,
        libc::SEEK_CUR => target.cursor as i64,
        libc::SEEK_END => target.len as i64,
        _ => return Err(libc::EINVAL),
    };
    let start = base.checked_add(lock.l_start).ok_or(libc::EOVERFLOW)?;
    let (start, end) = match lock.l_len {
        0 => (start, None),
        len if len > 0 => (start, Some(start.checked_add(len).ok_or(libc::EOVERFLOW)?)),
        len => (start.checked_add(len).ok_or(libc::EINVAL)?, Some(start)),
    };
    if start < 0 {
        return Err(libc::EINVAL);
    }
    Ok((start as u64, end.map_or(TO_END, |end| end as u64)))
}

impl Locks {
    /// Serves a record-lock `fcntl` (`cmd` such that [`is_record_lock`]) with `arg` the caller's
    /// `struct flock *`.
    ///
    /// # Safety
    /// `arg` must be null or point to a `struct flock`.
    pub(crate) unsafe fn fcntl(&self, cmd: c_int, arg: i64, target: &Target) -> Option<FsResult> {
        let (request, ofd) = classify(cmd)?;
        let lock = arg as *mut libc::flock;
        if lock.is_null() {
            return err(libc::EFAULT);
        }
        // SAFETY: the caller passes `struct flock *` for these commands.
        let mut fl = unsafe { lock.read() };
        #[cfg(target_os = "linux")]
        if ofd && fl.l_pid != 0 {
            return err(libc::EINVAL);
        }
        let (start, end) = match span(&fl, target) {
            Ok(span) => span,
            Err(errno) => return err(errno),
        };
        let owner = if ofd {
            Owner::Description(target.description)
        } else {
            Owner::Process
        };
        let kind = match c_int::from(fl.l_type) {
            READ => Some(false),
            WRITE => Some(true),
            UNLOCK => None,
            _ => return err(libc::EINVAL),
        };
        if let Request::Get = request {
            let Some(write) = kind.or(cfg!(target_os = "macos").then_some(true)) else {
                return err(libc::EINVAL);
            };
            let table = self.0.lock().unwrap();
            match table.conflict(owner, start, end, write) {
                Some(held) => {
                    fl.l_type = if held.write { WRITE } else { READ } as _;
                    fl.l_whence = libc::SEEK_SET as _;
                    fl.l_start = held.start as _;
                    fl.l_len = if held.end == TO_END {
                        0
                    } else {
                        (held.end - held.start) as _
                    };
                    fl.l_pid = match held.owner {
                        Owner::Process => std::process::id() as _,
                        Owner::Description(_) => -1,
                    };
                }
                None => fl.l_type = UNLOCK as _,
            }
            drop(table);
            // SAFETY: as above.
            unsafe { lock.write(fl) };
            return ok(0);
        }
        match kind {
            Some(false) if !target.readable => return err(libc::EBADF),
            Some(true) if !target.writable => return err(libc::EBADF),
            _ => {}
        }
        let attempt = || {
            let mut table = self.0.lock().unwrap();
            if let Some(write) = kind
                && table.conflict(owner, start, end, write).is_some()
            {
                return None;
            }
            Some(table.set(owner, start, end, kind))
        };
        let released = match request {
            Request::Wait => wait("fcntl lock", attempt),
            _ => attempt(),
        };
        let Some(released) = released else {
            return err(match request {
                Request::Wait => libc::EINTR,
                _ => libc::EAGAIN,
            });
        };
        if released {
            wake();
        }
        ok(0)
    }

    /// Serves `flock(2)` for `description`.
    pub(crate) fn flock(&self, description: u64, operation: c_int) -> Option<FsResult> {
        let nonblocking = operation & libc::LOCK_NB != 0;
        let Some(exclusive) = operation_kind(operation) else {
            if self.release_flock(description) {
                wake();
            }
            return ok(0);
        };
        let Ok(exclusive) = exclusive else {
            return err(exclusive.unwrap_err());
        };
        let converted = {
            let mut table = self.0.lock().unwrap();
            match table
                .flocks
                .iter()
                .position(|&(holder, _)| holder == description)
            {
                Some(at) if table.flocks[at].1 == exclusive => return ok(0),
                // man 2 flock: converting a lock is not atomic; the existing lock goes first.
                Some(at) => {
                    table.flocks.remove(at);
                    true
                }
                None => false,
            }
        };
        if converted {
            wake();
        }
        let attempt = || {
            let mut table = self.0.lock().unwrap();
            if table.flock_conflict(description, exclusive) {
                return None;
            }
            table.flocks.push((description, exclusive));
            Some(())
        };
        let acquired = if nonblocking {
            attempt()
        } else {
            wait("flock", attempt)
        };
        match acquired {
            Some(()) => ok(0),
            None if nonblocking => err(libc::EWOULDBLOCK),
            None => err(libc::EINTR),
        }
    }

    /// Drops the process's record locks, as closing any descriptor of the inode does.
    pub(crate) fn release_process(&self) {
        let released = {
            let mut table = self.0.lock().unwrap();
            let before = table.records.len();
            table.records.retain(|r| r.owner != Owner::Process);
            table.records.len() != before
        };
        if released {
            wake();
        }
    }

    /// Drops the OFD and `flock` locks of `description`, whose last descriptor has closed.
    pub(crate) fn release_description(&self, description: u64) {
        let released = {
            let mut table = self.0.lock().unwrap();
            let before = table.records.len();
            table
                .records
                .retain(|r| r.owner != Owner::Description(description));
            table.records.len() != before || Self::drop_flock(&mut table, description)
        };
        if released {
            wake();
        }
    }

    fn release_flock(&self, description: u64) -> bool {
        Self::drop_flock(&mut self.0.lock().unwrap(), description)
    }

    fn drop_flock(table: &mut Table, description: u64) -> bool {
        let before = table.flocks.len();
        table.flocks.retain(|&(holder, _)| holder != description);
        table.flocks.len() != before
    }
}

/// A `flock` operation: `None` to unlock, else whether it locks exclusively, or the errno of an
/// operation that names no lock. Linux takes exactly one of `LOCK_SH`, `LOCK_EX` and `LOCK_UN`
/// (fs/locks.c `flock_make_lock`); macOS tests `LOCK_UN`, then `LOCK_EX`, then `LOCK_SH`, and
/// fails with `EBADF` when none is set (bsd/kern/kern_descrip.c `sys_flock`).
fn operation_kind(operation: c_int) -> Option<Result<bool, c_int>> {
    #[cfg(target_os = "macos")]
    {
        if operation & libc::LOCK_UN != 0 {
            None
        } else if operation & libc::LOCK_EX != 0 {
            Some(Ok(true))
        } else if operation & libc::LOCK_SH != 0 {
            Some(Ok(false))
        } else {
            Some(Err(libc::EBADF))
        }
    }
    #[cfg(not(target_os = "macos"))]
    match operation & !libc::LOCK_NB {
        libc::LOCK_SH => Some(Ok(false)),
        libc::LOCK_EX => Some(Ok(true)),
        libc::LOCK_UN => None,
        _ => Some(Err(libc::EINVAL)),
    }
}

/// Retries `attempt` until it succeeds; `None` if the wait ends first.
fn wait<R>(label: &'static str, mut attempt: impl FnMut() -> Option<R>) -> Option<R> {
    let mut result = None;
    readiness().wait_until(label, None, || {
        result = attempt();
        result.is_some()
    });
    result
}

/// Wakes every waiter to retry: a lock's waiters may be in any sim sharing the file system.
fn wake() {
    readiness().bump(0);
}
