//! File-path and file-descriptor hooks that consult the calling thread's [`Fs`](crate::Fs) before
//! the OS. Path-keyed calls (`open`, `openat`, `creat`) offer the path to the backend, which may
//! mint a virtual fd or decline (passthrough). The generic fd calls (`read`, `write`, `close`,
//! `fcntl`, `ioctl`) are handled by the shared hooks in `sockets.rs`, gated on `fs_owns`; this
//! module adds `lseek`, which is file-specific.
//!
//! `open`/`openat`/`creat` are variadic in C (`..., mode_t`). On Linux (x86_64 and AArch64 both
//! pass the first variadic word in a register) and on macOS x86_64 a fixed-arity hook reads it
//! correctly and a fixed-arity forwarder hands it back. macOS aarch64 passes the variadic `mode`
//! on the stack, so those hooks enter through the naked trampolines in [`crate::os::variadic`] and
//! forward through a variadic pointer.

use std::ffi::{c_char, c_int};
use std::sync::atomic::AtomicUsize;

use libc::{mode_t, off_t};

use crate::domain::{dispatch_fs, fs_owns};
use crate::hooks::{Hook, hook, original};
use crate::os::sockets::{finish, finish_ptr};

/// Widen `mode_t` (u16 on macOS, u32 on Linux) to the Fs trait's `u32` without a lint either way.
#[allow(clippy::useless_conversion)]
fn mode_u32(mode: mode_t) -> u32 {
    u32::from(mode)
}

macro_rules! slot {
    ($name:ident) => {
        static $name: AtomicUsize = AtomicUsize::new(0);
    };
}

slot!(OPEN);
slot!(OPENAT);
slot!(CREAT);
slot!(LSEEK);
slot!(STAT);
slot!(LSTAT);
slot!(FSTAT);
slot!(FSTATAT);
slot!(OPENDIR);
slot!(READDIR);
slot!(CLOSEDIR);
slot!(DIRFD);
#[cfg(target_os = "macos")]
slot!(READDIR2);
slot!(REALPATH);
slot!(READLINK);
slot!(READLINKAT);
slot!(ACCESS);
slot!(FACCESSAT);
#[cfg(target_os = "linux")]
slot!(STATX);
#[cfg(target_os = "linux")]
slot!(OPEN64);
#[cfg(target_os = "linux")]
slot!(OPENAT64);
#[cfg(target_os = "linux")]
slot!(CREAT64);
#[cfg(target_os = "linux")]
slot!(LSEEK64);

pub(crate) fn hooks() -> Vec<Hook> {
    vec![
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        hook!("open", open, OPEN),
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        hook!("open", crate::os::variadic::open, OPEN),
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        hook!("openat", openat, OPENAT),
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        hook!("openat", crate::os::variadic::openat, OPENAT),
        hook!("creat", creat, CREAT),
        hook!("lseek", lseek, LSEEK),
        // stat family — names differ by OS and arch (see the sub-step-3 spec). man 2 stat.
        // macOS x86_64 exports `stat$INODE64` etc.: the `$INODE64` suffix selects the 64-bit-inode
        // `struct stat` (Apple <sys/cdefs.h> __DARWIN_INODE64); arm64 has only the 64-bit layout, so
        // the bare names are hooked. Linux `stat64`/`fstatat64` are the glibc LFS aliases
        // (_FILE_OFFSET_BITS=64) over the same `struct stat`.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        hook!("stat", stat, STAT),
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        hook!("lstat", lstat, LSTAT),
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        hook!("fstat", fstat, FSTAT),
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        hook!("fstatat", fstatat, FSTATAT),
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        hook!("stat$INODE64", stat, STAT),
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        hook!("lstat$INODE64", lstat, LSTAT),
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        hook!("fstat$INODE64", fstat, FSTAT),
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        hook!("fstatat$INODE64", fstatat, FSTATAT),
        #[cfg(target_os = "linux")]
        hook!("stat64", stat, STAT),
        #[cfg(target_os = "linux")]
        hook!("lstat64", lstat, LSTAT),
        #[cfg(target_os = "linux")]
        hook!("fstat64", fstat, FSTAT),
        #[cfg(target_os = "linux")]
        hook!("fstatat64", fstatat, FSTATAT),
        #[cfg(target_os = "linux")]
        hook!("statx", statx, STATX),
        // dir streams (man 3 opendir / readdir). Linux `readdir64` is the LFS alias returning
        // `struct dirent64` (d_off/d_ino are 64-bit); macOS x86_64 uses the `$INODE64` variants.
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        hook!("opendir$INODE64", opendir, OPENDIR),
        #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
        hook!("opendir", opendir, OPENDIR),
        #[cfg(target_os = "linux")]
        hook!("readdir64", readdir, READDIR),
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        hook!("readdir_r$INODE64", readdir_r, READDIR),
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        hook!("readdir_r", readdir_r, READDIR),
        hook!("closedir", closedir, CLOSEDIR),
        hook!("dirfd", dirfd, DIRFD),
        // macOS std read_dir uses readdir_r above, but a plain readdir consumer (or std drift)
        // would deref our fake DIR*; hook it too. (Linux std uses readdir64, hooked above.)
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        hook!("readdir$INODE64", readdir_plain, READDIR2),
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        hook!("readdir", readdir_plain, READDIR2),
        #[cfg(target_os = "macos")]
        hook!("realpath$DARWIN_EXTSN", realpath, REALPATH),
        #[cfg(target_os = "linux")]
        hook!("realpath", realpath, REALPATH),
        hook!("readlink", readlink, READLINK),
        hook!("readlinkat", readlinkat, READLINKAT),
        hook!("access", access, ACCESS),
        hook!("faccessat", faccessat, FACCESSAT),
        #[cfg(target_os = "linux")]
        hook!("open64", open64, OPEN64),
        #[cfg(target_os = "linux")]
        hook!("openat64", openat64, OPENAT64),
        #[cfg(target_os = "linux")]
        hook!("creat64", creat64, CREAT64),
        #[cfg(target_os = "linux")]
        hook!("lseek64", lseek64, LSEEK64),
    ]
}

// man 2 open: `mode` supplies the new file's permission bits and is consulted only when `flags`
// contains O_CREAT (or O_TMPFILE); the backend applies the same rule.
unsafe fn do_open(slot: &AtomicUsize, path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
    // SAFETY: `path` is the caller's C string.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.open(path, flags, mode_u32(mode)) }) {
        return finish(r) as c_int;
    }
    // SAFETY: the slot holds libc's open; forwarding the caller's arguments.
    unsafe { forward_open(slot, path, flags, mode) }
}

/// macOS aarch64 wants `mode` back on the stack, where libc's variadic `open` reads it, and as a
/// promoted `int`; every other target passes it in a register like a named argument.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
unsafe fn forward_open(slot: &AtomicUsize, path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
    // SAFETY: the slot holds libc's open.
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, c_int, mode_t) -> c_int>(slot)(
            path, flags, mode,
        )
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe fn forward_open(slot: &AtomicUsize, path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
    // SAFETY: the slot holds libc's open.
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, c_int, ...) -> c_int>(slot)(
            path,
            flags,
            c_int::from(mode),
        )
    }
}

unsafe fn do_openat(
    slot: &AtomicUsize,
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: mode_t,
) -> c_int {
    // SAFETY: `path` is the caller's C string.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.openat(dirfd, path, flags, mode_u32(mode)) }) {
        return finish(r) as c_int;
    }
    // SAFETY: the slot holds libc's openat.
    unsafe { forward_openat(slot, dirfd, path, flags, mode) }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
unsafe fn forward_openat(
    slot: &AtomicUsize,
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: mode_t,
) -> c_int {
    // SAFETY: the slot holds libc's openat.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_char, c_int, mode_t) -> c_int>(slot)(
            dirfd, path, flags, mode,
        )
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe fn forward_openat(
    slot: &AtomicUsize,
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: mode_t,
) -> c_int {
    // SAFETY: the slot holds libc's openat.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_char, c_int, ...) -> c_int>(slot)(
            dirfd,
            path,
            flags,
            c_int::from(mode),
        )
    }
}

// The macOS-aarch64 trampolines tail-branch here from another codegen unit, so these symbols must
// have external linkage to be resolvable; `sym` still emits the right (mangled) reference.
#[cfg_attr(
    all(target_os = "macos", target_arch = "aarch64"),
    unsafe(export_name = "__snare_interpose_open")
)]
pub(crate) unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
    // SAFETY: forwards to the shared implementation.
    unsafe { do_open(&OPEN, path, flags, mode) }
}

#[cfg_attr(
    all(target_os = "macos", target_arch = "aarch64"),
    unsafe(export_name = "__snare_interpose_openat")
)]
pub(crate) unsafe extern "C" fn openat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: mode_t,
) -> c_int {
    // SAFETY: forwards to the shared implementation.
    unsafe { do_openat(&OPENAT, dirfd, path, flags, mode) }
}

unsafe extern "C" fn creat(path: *const c_char, mode: mode_t) -> c_int {
    // man 2 creat: creat(path, mode) == open(path, O_CREAT|O_WRONLY|O_TRUNC, mode).
    // SAFETY: `path` is the caller's C string.
    if let Some(r) = dispatch_fs(|fs| unsafe {
        fs.open(
            path,
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            mode_u32(mode),
        )
    }) {
        return finish(r) as c_int;
    }
    // SAFETY: CREAT holds libc's creat.
    unsafe { original::<unsafe extern "C" fn(*const c_char, mode_t) -> c_int>(&CREAT)(path, mode) }
}

// man 2 lseek: `whence` is SEEK_SET/SEEK_CUR/SEEK_END (Linux also SEEK_DATA/SEEK_HOLE); returns the
// resulting absolute offset. The backend owns the position for fds it minted.
unsafe extern "C" fn lseek(fd: c_int, offset: off_t, whence: c_int) -> off_t {
    if fs_owns(fd)
        // SAFETY: no pointers.
        && let Some(r) = dispatch_fs(|fs| unsafe { fs.lseek(fd, offset, whence) })
    {
        return finish(r) as off_t;
    }
    // SAFETY: LSEEK holds libc's lseek.
    unsafe {
        original::<unsafe extern "C" fn(c_int, off_t, c_int) -> off_t>(&LSEEK)(fd, offset, whence)
    }
}

#[cfg(target_os = "linux")]
unsafe extern "C" fn open64(path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
    // SAFETY: forwards to the shared implementation.
    unsafe { do_open(&OPEN64, path, flags, mode) }
}

#[cfg(target_os = "linux")]
unsafe extern "C" fn openat64(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: mode_t,
) -> c_int {
    // SAFETY: forwards to the shared implementation.
    unsafe { do_openat(&OPENAT64, dirfd, path, flags, mode) }
}

#[cfg(target_os = "linux")]
unsafe extern "C" fn creat64(path: *const c_char, mode: mode_t) -> c_int {
    // SAFETY: `path` is the caller's C string.
    if let Some(r) = dispatch_fs(|fs| unsafe {
        fs.open(
            path,
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            mode_u32(mode),
        )
    }) {
        return finish(r) as c_int;
    }
    // SAFETY: CREAT64 holds libc's creat64.
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, mode_t) -> c_int>(&CREAT64)(path, mode)
    }
}

#[cfg(target_os = "linux")]
unsafe extern "C" fn lseek64(fd: c_int, offset: i64, whence: c_int) -> i64 {
    if fs_owns(fd)
        // SAFETY: no pointers.
        && let Some(r) = dispatch_fs(|fs| unsafe { fs.lseek(fd, offset, whence) })
    {
        return finish(r);
    }
    // SAFETY: LSEEK64 holds libc's lseek64.
    unsafe {
        original::<unsafe extern "C" fn(c_int, i64, c_int) -> i64>(&LSEEK64)(fd, offset, whence)
    }
}

unsafe extern "C" fn stat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    // SAFETY: `path` is the caller's C string; `buf` a writable struct stat.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.stat(path, buf.cast()) }) {
        return finish(r) as c_int;
    }
    // SAFETY: STAT holds libc's stat.
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int>(&STAT)(path, buf)
    }
}

unsafe extern "C" fn lstat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    // SAFETY: as for `stat`.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.lstat(path, buf.cast()) }) {
        return finish(r) as c_int;
    }
    // SAFETY: LSTAT holds libc's lstat.
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int>(&LSTAT)(path, buf)
    }
}

unsafe extern "C" fn fstat(fd: c_int, buf: *mut libc::stat) -> c_int {
    if fs_owns(fd)
        // SAFETY: `buf` a writable struct stat.
        && let Some(r) = dispatch_fs(|fs| unsafe { fs.fstat(fd, buf.cast()) })
    {
        return finish(r) as c_int;
    }
    // SAFETY: FSTAT holds libc's fstat.
    unsafe { original::<unsafe extern "C" fn(c_int, *mut libc::stat) -> c_int>(&FSTAT)(fd, buf) }
}

unsafe extern "C" fn fstatat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flags: c_int,
) -> c_int {
    // SAFETY: caller's path + writable struct stat.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.fstatat(dirfd, path, buf.cast(), flags) }) {
        return finish(r) as c_int;
    }
    // SAFETY: FSTATAT holds libc's fstatat.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_char, *mut libc::stat, c_int) -> c_int>(
            &FSTATAT,
        )(dirfd, path, buf, flags)
    }
}

// man 2 statx: `flags` carries the AT_* lookup bits plus AT_STATX_SYNC_TYPE; `mask` (STATX_* from
// <linux/stat.h>) requests fields, and the kernel reports which it filled in `stx_mask`. The buffer
// is the fixed-offset `struct statx` of <linux/stat.h>, an explicit kernel ABI independent of glibc.
#[cfg(target_os = "linux")]
unsafe extern "C" fn statx(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mask: u32,
    buf: *mut libc::statx,
) -> c_int {
    // SAFETY: caller's path + writable struct statx.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.statx(dirfd, path, flags, mask, buf.cast()) }) {
        return finish(r) as c_int;
    }
    // SAFETY: STATX holds libc's statx.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_char, c_int, u32, *mut libc::statx) -> c_int>(
            &STATX,
        )(dirfd, path, flags, mask, buf)
    }
}

/// Our `DIR*` is the reserved fd cast to a pointer, so it is a small integer; a real `DIR*` is a
/// heap address. Recover our fd only from a small pointer value.
fn dir_fd(dirp: *mut libc::DIR) -> Option<c_int> {
    let raw = dirp as usize;
    (raw != 0 && raw < 0x1_0000).then_some(raw as c_int)
}

unsafe extern "C" fn opendir(path: *const c_char) -> *mut libc::DIR {
    // SAFETY: `path` is the caller's C string.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.opendir(path) }) {
        return finish_ptr(r).cast();
    }
    // SAFETY: OPENDIR holds libc's opendir.
    unsafe { original::<unsafe extern "C" fn(*const c_char) -> *mut libc::DIR>(&OPENDIR)(path) }
}

#[cfg(target_os = "linux")]
unsafe extern "C" fn readdir(dirp: *mut libc::DIR) -> *mut libc::dirent64 {
    if let Some(fd) = dir_fd(dirp)
        && let Some(r) = dispatch_fs(|fs| unsafe { fs.readdir(fd) })
    {
        return finish_ptr(r).cast();
    }
    // SAFETY: READDIR holds libc's readdir64.
    unsafe {
        original::<unsafe extern "C" fn(*mut libc::DIR) -> *mut libc::dirent64>(&READDIR)(dirp)
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn readdir_r(
    dirp: *mut libc::DIR,
    entry: *mut libc::dirent,
    result: *mut *mut libc::dirent,
) -> c_int {
    if let Some(fd) = dir_fd(dirp)
        // SAFETY: `entry`/`result` are the caller's dirent and result slots.
        && let Some(r) = dispatch_fs(|fs| unsafe { fs.readdir_r(fd, entry.cast(), result.cast()) })
    {
        return finish(r) as c_int;
    }
    // SAFETY: READDIR holds libc's readdir_r.
    unsafe {
        original::<
            unsafe extern "C" fn(
                *mut libc::DIR,
                *mut libc::dirent,
                *mut *mut libc::dirent,
            ) -> c_int,
        >(&READDIR)(dirp, entry, result)
    }
}

unsafe extern "C" fn closedir(dirp: *mut libc::DIR) -> c_int {
    if let Some(fd) = dir_fd(dirp)
        && fs_owns(fd)
        && let Some(r) = dispatch_fs(|fs| unsafe { fs.closedir(fd) })
    {
        return finish(r) as c_int;
    }
    // SAFETY: CLOSEDIR holds libc's closedir.
    unsafe { original::<unsafe extern "C" fn(*mut libc::DIR) -> c_int>(&CLOSEDIR)(dirp) }
}

unsafe extern "C" fn dirfd(dirp: *mut libc::DIR) -> c_int {
    if let Some(fd) = dir_fd(dirp)
        && fs_owns(fd)
    {
        return fd; // our DIR* is the fd
    }
    // SAFETY: DIRFD holds libc's dirfd.
    unsafe { original::<unsafe extern "C" fn(*mut libc::DIR) -> c_int>(&DIRFD)(dirp) }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn readdir_plain(dirp: *mut libc::DIR) -> *mut libc::dirent {
    if let Some(fd) = dir_fd(dirp)
        && let Some(r) = dispatch_fs(|fs| unsafe { fs.readdir(fd) })
    {
        return finish_ptr(r).cast();
    }
    // SAFETY: READDIR2 holds libc's readdir.
    unsafe {
        original::<unsafe extern "C" fn(*mut libc::DIR) -> *mut libc::dirent>(&READDIR2)(dirp)
    }
}

// man 3 realpath: a non-null `resolved` must hold PATH_MAX bytes; passing null asks libc to
// malloc the result. macOS exports the null-supporting form as `realpath$DARWIN_EXTSN`.
unsafe extern "C" fn realpath(path: *const c_char, resolved: *mut c_char) -> *mut c_char {
    // SAFETY: `path` is the caller's C string; `resolved` its output buffer (or null).
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.realpath(path, resolved) }) {
        return finish_ptr(r).cast();
    }
    // SAFETY: REALPATH holds libc's realpath.
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut c_char>(&REALPATH)(
            path, resolved,
        )
    }
}

// man 2 readlink: writes at most `len` bytes and does NOT null-terminate; the return is the byte
// count, silently truncated to `len`. The backend preserves that (no terminator, no error on fit).
unsafe extern "C" fn readlink(path: *const c_char, buf: *mut c_char, len: usize) -> isize {
    // SAFETY: `path` is the caller's C string; `buf` its `len`-byte output.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.readlink(path, buf.cast(), len) }) {
        return finish(r) as isize;
    }
    // SAFETY: READLINK holds libc's readlink.
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> isize>(&READLINK)(
            path, buf, len,
        )
    }
}

unsafe extern "C" fn readlinkat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut c_char,
    len: usize,
) -> isize {
    // SAFETY: `path`/`buf` as for `readlink`.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.readlinkat(dirfd, path, buf.cast(), len) }) {
        return finish(r) as isize;
    }
    // SAFETY: READLINKAT holds libc's readlinkat.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_char, *mut c_char, usize) -> isize>(
            &READLINKAT,
        )(dirfd, path, buf, len)
    }
}

// man 2 access: `mode` is F_OK or a bitwise-or of R_OK/W_OK/X_OK.
unsafe extern "C" fn access(path: *const c_char, mode: c_int) -> c_int {
    // SAFETY: `path` is the caller's C string.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.access(path, mode) }) {
        return finish(r) as c_int;
    }
    // SAFETY: ACCESS holds libc's access.
    unsafe { original::<unsafe extern "C" fn(*const c_char, c_int) -> c_int>(&ACCESS)(path, mode) }
}

// man 2 faccessat: resolves `path` relative to `dirfd` (or AT_FDCWD); `flags` may carry
// AT_EACCESS and AT_SYMLINK_NOFOLLOW.
unsafe extern "C" fn faccessat(
    dirfd: c_int,
    path: *const c_char,
    mode: c_int,
    flags: c_int,
) -> c_int {
    // SAFETY: `path` is the caller's C string.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.faccessat(dirfd, path, mode, flags) }) {
        return finish(r) as c_int;
    }
    // SAFETY: FACCESSAT holds libc's faccessat.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_char, c_int, c_int) -> c_int>(&FACCESSAT)(
            dirfd, path, mode, flags,
        )
    }
}
