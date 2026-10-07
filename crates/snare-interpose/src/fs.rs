//! A per-domain file-system backend, sibling to [`Net`](crate::Net). When a domain has one, the
//! file-operation and generic-fd hooks offer each call to it before the OS. It serves the paths
//! and file descriptors it owns from its own state (an in-memory tree, for tests) and declines
//! the rest, which then reach the real OS — the basis of wildcard passthrough.
//!
//! Every method returns `Option<FsResult>`: `Some` handles the call (`Ok(n)` or `Err(errno)`);
//! `None` declines it. `owns` is the fast path for the shared generic-fd hooks (`read`, `write`,
//! `close`, `fcntl`, `ioctl`): it must be cheap and answer for every fd the backend minted.
//!
//! The file plane is asked before the network plane on the shared generic-fd hooks, and a backend
//! runs with the calling thread in passthrough (see `domain::dispatch_fs`), so its own file I/O
//! reaches the OS.

use core::ffi::{c_char, c_int};

pub use crate::net::NetResult as FsResult;

/// `mode_t` is `u16` on macOS (`<sys/_types.h>`: `__darwin_mode_t` is `__uint16_t`) and
/// `u32` on Linux (glibc `__mode_t`, `unsigned int`); the hooks widen the real value into this.
type Mode = u32;

/// One timestamp a [`SetTimes`] call sets: left alone, the current time (`UTIME_NOW`), or an
/// instant in nanoseconds since the Unix epoch, negative before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeSet {
    Omit,
    Now,
    At(i128),
}

/// The timestamps a `utimensat`-family call sets. `created` is set only through macOS
/// `setattrlist(2)` (`ATTR_CMN_CRTIME`); Linux has no call that sets a birth time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetTimes {
    pub accessed: TimeSet,
    pub modified: TimeSet,
    pub created: TimeSet,
}

/// A file system the interposer routes a managed thread's file calls to.
///
/// All methods default to declining. They fall into four groups:
///
/// - Path-keyed calls (`open` … `statfs`) are offered for every path. The backend consults its
///   passthrough policy and may mint an fd; a path it does not own is declined.
/// - Fd-keyed calls (`fstat` … `getdents64`) concern an fd the backend minted.
/// - Directory streams: a `DIR*` is opaque to the caller, so the backend backs each stream with an
///   fd of its own, and the hooks encode that fd in an opaque `DIR*` token.
/// - The shared generic-fd calls (`read`, `write`, `close`, `fcntl`, `ioctl`), consulted only when
///   [`owns`](Self::owns) says so; they mirror [`Net`](crate::Net)'s.
///
/// # Safety
/// Pointer arguments carry the hooked libc call's contract: C strings are NUL-terminated, and
/// buffers hold the documented structure or `len` bytes. Path strings may be resolved against
/// the virtual working directory before dispatch.
#[allow(unused_variables, clippy::missing_safety_doc)]
pub trait Fs: Send + Sync + 'static {
    /// Whether `fd` (or a directory stream's fd) is one this backend minted. Called with the
    /// thread in passthrough on every generic fd call, so it must not block, and it must turn
    /// false once the fd is closed, since the OS may reuse the number.
    fn owns(&self, fd: c_int) -> bool {
        false
    }

    fn cwd_path(&self) -> Option<Result<Vec<u8>, c_int>> {
        None
    }

    fn cwd_changed(&self) {}

    /// Models `open(2)`; `flags` are `O_*` and `mode` the `mode_t` create bits (`<fcntl.h>`,
    /// `<sys/stat.h>`).
    unsafe fn open(&self, path: *const c_char, flags: c_int, mode: Mode) -> Option<FsResult> {
        None
    }
    /// Models `openat(2)`; `dirfd` may be `AT_FDCWD` for a path relative to the cwd.
    unsafe fn openat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        flags: c_int,
        mode: Mode,
    ) -> Option<FsResult> {
        None
    }
    /// Models `stat(2)`; `buf` is a `struct stat` (`<sys/stat.h>`).
    unsafe fn stat(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        None
    }
    /// Models `lstat(2)` (does not follow a terminal symlink).
    unsafe fn lstat(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        None
    }
    /// Models `fstatat(2)`; `flags` may carry `AT_SYMLINK_NOFOLLOW`/`AT_EMPTY_PATH` (`<fcntl.h>`).
    unsafe fn fstatat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        buf: *mut u8,
        flags: c_int,
    ) -> Option<FsResult> {
        None
    }
    /// Linux `statx(dirfd, path, flags, mask, *statx)`, which Rust's `std::fs::metadata` tries
    /// before `stat64` on Linux.
    ///
    /// Models `statx(2)`; `mask` is a set of `STATX_*` request bits and `buf` a `struct statx`
    /// (`<linux/stat.h>`).
    unsafe fn statx(
        &self,
        dirfd: c_int,
        path: *const c_char,
        flags: c_int,
        mask: u32,
        buf: *mut u8,
    ) -> Option<FsResult> {
        None
    }
    /// Models `access(2)`; `mode` is `R_OK`/`W_OK`/`X_OK`/`F_OK` (`<unistd.h>`).
    unsafe fn access(&self, path: *const c_char, mode: c_int) -> Option<FsResult> {
        None
    }
    /// Models `faccessat(2)`; `flags` may carry `AT_EACCESS`/`AT_SYMLINK_NOFOLLOW` (`<fcntl.h>`).
    unsafe fn faccessat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        mode: c_int,
        flags: c_int,
    ) -> Option<FsResult> {
        None
    }
    /// Models `readlink(2)`; returns the byte count written, never NUL-terminating `buf`.
    unsafe fn readlink(&self, path: *const c_char, buf: *mut u8, len: usize) -> Option<FsResult> {
        None
    }
    /// Models `readlinkat(2)`.
    unsafe fn readlinkat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        buf: *mut u8,
        len: usize,
    ) -> Option<FsResult> {
        None
    }
    unsafe fn symlink(&self, target: *const c_char, link: *const c_char) -> Option<FsResult> {
        None
    }
    unsafe fn symlinkat(
        &self,
        target: *const c_char,
        dirfd: c_int,
        link: *const c_char,
    ) -> Option<FsResult> {
        None
    }
    unsafe fn chdir(&self, path: *const c_char) -> Option<FsResult> {
        None
    }
    unsafe fn fchdir(&self, fd: c_int) -> Option<FsResult> {
        None
    }
    unsafe fn getcwd(&self, buf: *mut c_char, len: usize) -> Option<FsResult> {
        None
    }
    /// Models `unlink(2)`.
    unsafe fn unlink(&self, path: *const c_char) -> Option<FsResult> {
        None
    }
    unsafe fn unlinkat(&self, dirfd: c_int, path: *const c_char, flags: c_int) -> Option<FsResult> {
        None
    }
    unsafe fn rmdir(&self, path: *const c_char) -> Option<FsResult> {
        None
    }
    /// Models `mkdir(2)`; `mode` is masked by the process umask by the kernel.
    unsafe fn mkdir(&self, path: *const c_char, mode: Mode) -> Option<FsResult> {
        None
    }
    unsafe fn mkdirat(&self, dirfd: c_int, path: *const c_char, mode: Mode) -> Option<FsResult> {
        None
    }
    /// Models `rename(2)`.
    unsafe fn rename(&self, from: *const c_char, to: *const c_char) -> Option<FsResult> {
        None
    }
    unsafe fn renameat(
        &self,
        fromfd: c_int,
        from: *const c_char,
        tofd: c_int,
        to: *const c_char,
    ) -> Option<FsResult> {
        None
    }
    unsafe fn link(&self, from: *const c_char, to: *const c_char) -> Option<FsResult> {
        None
    }
    unsafe fn linkat(
        &self,
        fromfd: c_int,
        from: *const c_char,
        tofd: c_int,
        to: *const c_char,
        flags: c_int,
    ) -> Option<FsResult> {
        None
    }
    /// Models `realpath(3)`; `resolved`, when non-null, holds up to `PATH_MAX` bytes.
    unsafe fn realpath(&self, path: *const c_char, resolved: *mut c_char) -> Option<FsResult> {
        None
    }
    /// Models `statfs(2)`; `buf` is a `struct statfs` (`<sys/vfs.h>` on Linux, `<sys/mount.h>` on
    /// macOS).
    unsafe fn statfs(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        None
    }
    unsafe fn fstatfs(&self, fd: c_int, buf: *mut u8) -> Option<FsResult> {
        None
    }

    /// Models `fstat(2)`; `buf` is a `struct stat` (`<sys/stat.h>`).
    unsafe fn fstat(&self, fd: c_int, buf: *mut u8) -> Option<FsResult> {
        None
    }
    /// Models `lseek(2)`; `whence` is `SEEK_SET`/`SEEK_CUR`/`SEEK_END` (`<unistd.h>`).
    unsafe fn lseek(&self, fd: c_int, offset: i64, whence: c_int) -> Option<FsResult> {
        None
    }
    /// Models `pread(2)` — read at `offset` without moving the file position.
    unsafe fn pread(&self, fd: c_int, buf: *mut u8, len: usize, offset: i64) -> Option<FsResult> {
        None
    }
    /// Models `pwrite(2)` — write at `offset` without moving the file position.
    unsafe fn pwrite(
        &self,
        fd: c_int,
        buf: *const u8,
        len: usize,
        offset: i64,
    ) -> Option<FsResult> {
        None
    }
    /// Models `ftruncate(2)`.
    unsafe fn ftruncate(&self, fd: c_int, len: i64) -> Option<FsResult> {
        None
    }
    /// Models `fsync(2)`.
    unsafe fn fsync(&self, fd: c_int) -> Option<FsResult> {
        None
    }
    /// Models `flock(2)`; `operation` is `LOCK_SH`/`LOCK_EX`/`LOCK_UN`, optionally with `LOCK_NB`
    /// (`<sys/file.h>`).
    unsafe fn flock(&self, fd: c_int, operation: c_int) -> Option<FsResult> {
        None
    }
    /// Models `utimensat(2)`, and through it `utimes(2)`, `futimens(3)`, `futimes(3)` and macOS
    /// `setattrlist(2)`/`fsetattrlist(2)` restricted to the common time attributes. A null `path`
    /// names `dirfd` itself, as Linux's `utimensat(fd, NULL, ...)` does (man 2 utimensat, NOTES);
    /// such a call is offered only to the plane owning `dirfd`. `flags` may carry
    /// `AT_SYMLINK_NOFOLLOW`.
    unsafe fn set_times(
        &self,
        dirfd: c_int,
        path: *const c_char,
        times: &SetTimes,
        flags: c_int,
    ) -> Option<FsResult> {
        None
    }
    /// Told after the OS itself set the timestamps of a file no plane served, with the call's
    /// arguments as [`set_times`](Self::set_times) takes them.
    unsafe fn host_times_set(
        &self,
        dirfd: c_int,
        path: *const c_char,
        times: &SetTimes,
        flags: c_int,
    ) {
    }
    /// Shown a `struct stat` (or, when `statx`, a Linux `struct statx`) the OS just filled for a
    /// file no plane served, before the caller sees it; a plane may rewrite its timestamps.
    unsafe fn host_metadata(&self, buf: *mut u8, statx: bool) {}
    /// Linux `getdents64` / macOS `getdirentries$INODE64` packing over a dir stream's snapshot.
    ///
    /// Models `getdents64(2)`; `buf` is packed with `struct linux_dirent64` records
    /// (`<dirent.h>`/`<linux/dirent.h>`), each `d_reclen` bytes long.
    unsafe fn getdents64(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<FsResult> {
        None
    }

    /// Models `opendir(3)`: `Ok(fd)` identifies the directory stream.
    unsafe fn opendir(&self, path: *const c_char) -> Option<FsResult> {
        None
    }
    /// Models `fdopendir(3)` — turn an already-open fd into a directory stream.
    unsafe fn fdopendir(&self, fd: c_int) -> Option<FsResult> {
        None
    }
    /// `readdir`: `Ok(*dirent as i64)` for an entry, `Ok(0)` at end of stream. The returned
    /// pointer stays valid until the next `readdir`/`closedir` on the same stream.
    ///
    /// Models `readdir(3)`; each entry is a `struct dirent` (`<dirent.h>`).
    unsafe fn readdir(&self, fd: c_int) -> Option<FsResult> {
        None
    }
    /// `readdir_r(dirp, entry, result)`: copies the next entry into `entry` and writes it (or null
    /// at end) to `*result`. macOS `std::fs::read_dir` uses this reentrant form.
    ///
    /// Models `readdir_r(3)` (deprecated since glibc 2.24 in favour of `readdir(3)`; see
    /// man 3 readdir_r).
    unsafe fn readdir_r(
        &self,
        fd: c_int,
        entry: *mut u8,
        result: *mut *mut u8,
    ) -> Option<FsResult> {
        None
    }
    /// Models `closedir(3)`.
    unsafe fn closedir(&self, fd: c_int) -> Option<FsResult> {
        None
    }

    /// Models `read(2)` on an owned file fd.
    unsafe fn read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<FsResult> {
        None
    }
    /// Models `write(2)` on an owned file fd.
    unsafe fn write(&self, fd: c_int, buf: *const u8, len: usize) -> Option<FsResult> {
        None
    }
    /// Models `close(2)` on an owned file fd.
    unsafe fn close(&self, fd: c_int) -> Option<FsResult> {
        None
    }
    /// Models `fcntl(2)` on an owned file fd (see [`Net::fcntl`](crate::Net::fcntl)). For the
    /// record-lock commands (`F_GETLK`, `F_SETLK`, `F_SETLKW` and their `F_OFD_*` forms) `arg` is
    /// the caller's `struct flock *`.
    unsafe fn fcntl(&self, fd: c_int, cmd: c_int, arg: i64) -> Option<FsResult> {
        None
    }
    /// Models `ioctl(2)` on an owned file fd.
    unsafe fn ioctl(&self, fd: c_int, request: u64, arg: i64) -> Option<FsResult> {
        None
    }

    /// Atomically duplicates an owned file onto `newfd`, retaining shared open-file state.
    /// `None` flags selects `dup2`; `Some(flags)` selects `dup3`.
    unsafe fn dup_to(&self, fd: c_int, newfd: c_int, flags: Option<c_int>) -> Option<FsResult> {
        let _ = (fd, newfd, flags);
        None
    }

    /// Releases file ownership after an atomic kernel descriptor replacement, without closing
    /// the replacement descriptor.
    unsafe fn fd_replaced(&self, fd: c_int) -> Option<FsResult> {
        let _ = fd;
        None
    }

    /// `dup`/`dup2`/`dup3` of an owned fd: copy this plane's ownership tag to `newfd`.
    ///
    /// Models `dup(2)`/`dup2(2)`/`dup3(2)`.
    unsafe fn dup(&self, oldfd: c_int, newfd: c_int) -> Option<FsResult> {
        None
    }
}
