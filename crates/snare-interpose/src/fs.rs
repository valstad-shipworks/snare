//! A per-domain file-system backend, sibling to [`Net`](crate::Net). When a domain has one, the
//! file-operation and generic-fd hooks offer each call to it before the OS. It serves the paths
//! and file descriptors it owns from its own state (an in-memory tree, for tests) and declines
//! the rest, which then reach the real OS — the basis of wildcard passthrough.
//!
//! Every method returns `Option<FsResult>`: `Some` handles the call (`Ok(n)` or `Err(errno)`);
//! `None` declines it. `owns` is the fast path for the shared generic-fd hooks (`read`, `write`,
//! `close`, `fcntl`, `ioctl`): it must be cheap and answer for every fd the backend minted.

use core::ffi::{c_char, c_int};

pub use crate::net::NetResult as FsResult;

/// `mode_t` is `u16` on macOS and `u32` on Linux; the hooks widen the real value into this.
type Mode = u32;

#[allow(unused_variables, clippy::missing_safety_doc)]
pub trait Fs: Send + Sync + 'static {
    fn owns(&self, fd: c_int) -> bool {
        false
    }

    // --- path-keyed (consult the passthrough policy; may mint an fd) ---
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
    /// Linux `statx(dirfd, path, flags, mask, *statx)` — the primary metadata path on modern glibc.
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
    /// Models `unlink(2)`.
    unsafe fn unlink(&self, path: *const c_char) -> Option<FsResult> {
        None
    }
    /// Models `mkdir(2)`; `mode` is masked by the process umask by the kernel.
    unsafe fn mkdir(&self, path: *const c_char, mode: Mode) -> Option<FsResult> {
        None
    }
    /// Models `rename(2)`.
    unsafe fn rename(&self, from: *const c_char, to: *const c_char) -> Option<FsResult> {
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

    // --- fd-keyed on an owned fd ---
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
    /// Linux `getdents64` / macOS `getdirentries$INODE64` packing over a dir stream's snapshot.
    ///
    /// Models `getdents64(2)`; `buf` is packed with `struct linux_dirent64` records
    /// (`<dirent.h>`/`<linux/dirent.h>`), each `d_reclen`-aligned.
    unsafe fn getdents64(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<FsResult> {
        None
    }

    // --- dir streams (DIR* is opaque, so it gets its own owned fd-backed stream) ---
    /// Models `opendir(3)`.
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
    /// Models `readdir_r(3)` (deprecated on Linux in favour of `readdir(3)`).
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

    // --- shared generic-fd (consulted only when owns(fd)); mirror Net's defaults ---
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
    /// Models `fcntl(2)` on an owned file fd (see [`Net::fcntl`](crate::Net::fcntl)).
    unsafe fn fcntl(&self, fd: c_int, cmd: c_int, arg: i64) -> Option<FsResult> {
        None
    }
    /// Models `ioctl(2)` on an owned file fd.
    unsafe fn ioctl(&self, fd: c_int, request: u64, arg: i64) -> Option<FsResult> {
        None
    }

    /// `dup`/`dup2`/`dup3` of an owned fd: copy this plane's ownership tag to `newfd`.
    ///
    /// Models `dup(2)`/`dup2(2)`/`dup3(2)`.
    unsafe fn dup(&self, oldfd: c_int, newfd: c_int) -> Option<FsResult> {
        None
    }
}
