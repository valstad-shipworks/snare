//! File-path and file-descriptor hooks that consult the calling thread's [`Fs`](crate::Fs) before
//! the OS. Path-keyed calls (`open`, `openat`, `creat`) offer the path to the backend, which may
//! mint a virtual fd or decline (passthrough). The generic fd calls (`read`, `write`, `close`,
//! `fcntl`, `ioctl`) are handled by the shared hooks in `sockets.rs` (`ioctl` in `unix.rs`), offered
//! to the plane that minted the fd (`domain::file_plane`); this module adds `lseek`, which is
//! file-specific.
//!
//! `open`/`openat` are variadic in C (`..., mode_t`); `creat` is not. On Linux (x86_64 and AArch64 both
//! pass the first variadic word in a register) and on macOS x86_64 a fixed-arity hook reads it
//! correctly and a fixed-arity forwarder hands it back. macOS aarch64 passes the variadic `mode`
//! on the stack, so those hooks enter through the naked trampolines in `crate::os::variadic` and
//! forward through a variadic pointer (Apple, "Writing ARM64 code for Apple platforms":
//! <https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms>; the
//! System V AMD64 ABI and AAPCS64 pass the first variadic words in registers).
//!
//! Unlike the socket hooks, a file call the backend declines is forwarded without being observed:
//! a test binary touches real files constantly (its own executable, shared libraries, `/proc`),
//! and passthrough is the policy for any path the backend does not own.

use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::atomic::AtomicUsize;

use libc::{mode_t, off_t};

use crate::domain::{self, FilePlane, dispatch_fs, dispatch_fs_fd, fs_owns};
use crate::fs::{SetTimes, TimeSet};
use crate::hooks::{Hook, hook, original};
use crate::os::sockets::{finish, finish_ptr};
use crate::state::Passthrough;

struct PathArgument {
    original: *const c_char,
    absolute: Option<CString>,
    error: Option<c_int>,
}

impl PathArgument {
    unsafe fn new(path: *const c_char, dirfd: c_int) -> Self {
        let mut argument = Self {
            original: path,
            absolute: None,
            error: None,
        };
        if path.is_null() || dirfd != libc::AT_FDCWD {
            return argument;
        }
        let mut cwd = None;
        dispatch_fs(|fs| {
            cwd = fs.cwd_path();
            None
        });
        let Some(cwd) = cwd else {
            return argument;
        };
        let mut relative = unsafe { CStr::from_ptr(path) }.to_bytes();
        if relative.is_empty() || relative.starts_with(b"/") {
            return argument;
        }
        match cwd {
            Ok(mut cwd) => {
                while let Some(separator) = relative.iter().position(|&byte| byte == b'/') {
                    let (component, suffix) = relative.split_at(separator);
                    if suffix.iter().all(|&byte| byte == b'/') {
                        break;
                    }
                    if component == b".." {
                        while cwd.len() > 1 && cwd.ends_with(b"/") {
                            cwd.pop();
                        }
                        let parent = cwd.iter().rposition(|&byte| byte == b'/').unwrap_or(0);
                        cwd.truncate(parent.max(1));
                    } else if component != b"." && !component.is_empty() {
                        break;
                    }
                    relative = &suffix[1..];
                }
                if !cwd.ends_with(b"/") {
                    cwd.push(b'/');
                }
                cwd.extend_from_slice(relative);
                match CString::new(cwd) {
                    Ok(path) => argument.absolute = Some(path),
                    Err(_) => argument.error = Some(libc::EINVAL),
                }
            }
            Err(error) => argument.error = Some(error),
        }
        argument
    }

    fn as_ptr(&self) -> *const c_char {
        self.absolute
            .as_ref()
            .map_or(self.original, |path| path.as_ptr())
    }
}

macro_rules! path_argument {
    ($path:ident, $storage:ident, $dirfd:expr) => {
        let $storage = unsafe { PathArgument::new($path, $dirfd) };
        let $path = $storage.as_ptr();
    };
}

macro_rules! path_fallback {
    ($($storage:ident),+) => {
        $(if let Some(error) = $storage.error {
            return finish(-i64::from(error)) as _;
        })+
    };
    (pointer; $($storage:ident),+) => {
        $(if let Some(error) = $storage.error {
            return finish_ptr(-i64::from(error)).cast();
        })+
    };
}

fn cwd_changed() {
    dispatch_fs(|fs| {
        fs.cwd_changed();
        None
    });
}

/// Widens `mode_t` (u16 on macOS, u32 on Linux) to the Fs trait's `u32` without a lint either way.
#[allow(clippy::useless_conversion)]
fn mode_u32(mode: mode_t) -> u32 {
    u32::from(mode)
}

/// Declares the `AtomicUsize` that holds one hooked function's original address.
macro_rules! slot {
    ($name:ident) => {
        static $name: AtomicUsize = AtomicUsize::new(0);
    };
}

slot!(OPEN);
slot!(OPENAT);
slot!(CREAT);
slot!(LSEEK);
slot!(PREAD);
slot!(PWRITE);
slot!(FTRUNCATE);
slot!(FSYNC);
slot!(FLOCK);
slot!(UNLINK);
slot!(UNLINKAT);
slot!(RMDIR);
slot!(MKDIR);
slot!(MKDIRAT);
slot!(RENAME);
slot!(RENAMEAT);
slot!(LINK);
slot!(LINKAT);
slot!(FDOPENDIR);
#[cfg(target_os = "linux")]
slot!(GETDENTS64);
#[cfg(target_os = "macos")]
slot!(GETDIRENTRIES);
slot!(STAT);
slot!(STATFS);
slot!(FSTATFS);
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
slot!(SYMLINK);
slot!(SYMLINKAT);
slot!(CHDIR);
slot!(FCHDIR);
slot!(GETCWD);
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
slot!(UTIMENSAT);
slot!(FUTIMENS);
slot!(UTIMES);
slot!(FUTIMES);
#[cfg(target_os = "macos")]
slot!(SETATTRLIST);
#[cfg(target_os = "macos")]
slot!(FSETATTRLIST);

/// The file hooks for this target, under each OS's exported symbol names.
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
        hook!("pread", pread, PREAD),
        hook!("pwrite", pwrite, PWRITE),
        hook!("ftruncate", ftruncate, FTRUNCATE),
        hook!("fsync", fsync, FSYNC),
        hook!("flock", flock, FLOCK),
        hook!("unlink", unlink, UNLINK),
        hook!("unlinkat", unlinkat, UNLINKAT),
        hook!("rmdir", rmdir, RMDIR),
        hook!("mkdir", mkdir, MKDIR),
        hook!("mkdirat", mkdirat, MKDIRAT),
        hook!("rename", rename, RENAME),
        hook!("renameat", renameat, RENAMEAT),
        hook!("link", link, LINK),
        hook!("linkat", linkat, LINKAT),
        #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
        hook!("statfs", statfs, STATFS),
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        hook!("statfs$INODE64", statfs, STATFS),
        #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
        hook!("fstatfs", fstatfs, FSTATFS),
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        hook!("fstatfs$INODE64", fstatfs, FSTATFS),
        #[cfg(target_os = "linux")]
        hook!("statfs64", statfs, STATFS),
        #[cfg(target_os = "linux")]
        hook!("fstatfs64", fstatfs, FSTATFS),
        #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
        hook!("fdopendir", fdopendir, FDOPENDIR),
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        hook!("fdopendir$INODE64", fdopendir, FDOPENDIR),
        #[cfg(target_os = "linux")]
        hook!("getdents64", getdents64, GETDENTS64),
        #[cfg(target_os = "macos")]
        hook!("__getdirentries64", getdirentries, GETDIRENTRIES),
        #[cfg(target_os = "linux")]
        hook!("pread64", pread, PREAD),
        #[cfg(target_os = "linux")]
        hook!("pwrite64", pwrite, PWRITE),
        #[cfg(target_os = "linux")]
        hook!("ftruncate64", ftruncate, FTRUNCATE),
        // stat family — names differ by OS and arch. man 2 stat.
        // macOS x86_64 exports `stat$INODE64` etc.: the `$INODE64` suffix selects the 64-bit-inode
        // `struct stat` (Apple <sys/cdefs.h> __DARWIN_INODE64); arm64 has only the 64-bit layout
        // (`__DARWIN_ONLY_64_BIT_INO_T` is 1 there, so the suffix is empty), so the bare names are
        // hooked. Linux `stat64`/`fstatat64` are the glibc LFS aliases
        // (_FILE_OFFSET_BITS=64) over the same `struct stat` on 64-bit targets (glibc manual,
        // "Feature Test Macros").
        #[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
        hook!("stat", stat, STAT),
        #[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
        hook!("lstat", lstat, LSTAT),
        #[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
        hook!("fstat", fstat, FSTAT),
        #[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
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
        #[cfg(target_os = "linux")]
        hook!("readdir", readdir, READDIR),
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
        hook!("symlink", symlink, SYMLINK),
        hook!("symlinkat", symlinkat, SYMLINKAT),
        hook!("chdir", chdir, CHDIR),
        hook!("fchdir", fchdir, FCHDIR),
        hook!("getcwd", getcwd, GETCWD),
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
        hook!("utimensat", utimensat, UTIMENSAT),
        hook!("futimens", futimens, FUTIMENS),
        hook!("utimes", utimes, UTIMES),
        hook!("futimes", futimes, FUTIMES),
        #[cfg(target_os = "macos")]
        hook!("setattrlist", setattrlist, SETATTRLIST),
        #[cfg(target_os = "macos")]
        hook!("fsetattrlist", fsetattrlist, FSETATTRLIST),
    ]
}

/// The body of `open` and `open64`: offers the path to the domain's [`Fs`](crate::Fs), else
/// forwards to the original in `slot`.
///
/// man 2 open: `mode` supplies the new file's permission bits and is consulted only when `flags`
/// contains O_CREAT (or O_TMPFILE); a backend should ignore it otherwise.
unsafe fn do_open(slot: &AtomicUsize, path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
    path_argument!(path, resolved_path, libc::AT_FDCWD);

    // SAFETY: `path` is the caller's C string.
    if let Some(r) = crate::domain::descriptor_transaction(|| {
        dispatch_fs(|fs| unsafe { fs.open(path, flags, mode_u32(mode)) })
            .inspect(|&fd| domain::file_opened(fd as c_int))
    }) {
        return finish(r) as c_int;
    }
    // SAFETY: the slot holds libc's open; forwarding the caller's arguments.
    path_fallback!(resolved_path);
    unsafe { forward_open(slot, path, flags, mode) }
}

/// Calls the original `open` in `slot`.
///
/// macOS aarch64 wants `mode` back on the stack, where libc's variadic `open` reads it, and as a
/// promoted `int` (C11 6.5.2.2p7: the default argument promotions apply to variadic arguments,
/// and Darwin's `mode_t` is 16 bits); every other target passes it in a register like a named
/// argument.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
unsafe fn forward_open(
    slot: &AtomicUsize,
    path: *const c_char,
    flags: c_int,
    mode: mode_t,
) -> c_int {
    // SAFETY: the slot holds libc's open.
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, c_int, mode_t) -> c_int>(slot)(
            path, flags, mode,
        )
    }
}

/// Calls the original `open` in `slot` through a variadic pointer, `mode` promoted to `int`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe fn forward_open(
    slot: &AtomicUsize,
    path: *const c_char,
    flags: c_int,
    mode: mode_t,
) -> c_int {
    // SAFETY: the slot holds libc's open.
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, c_int, ...) -> c_int>(slot)(
            path,
            flags,
            c_int::from(mode),
        )
    }
}

/// The body of `openat` and `openat64`, as [`do_open`] with a directory fd.
unsafe fn do_openat(
    slot: &AtomicUsize,
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: mode_t,
) -> c_int {
    path_argument!(path, resolved_path, dirfd);

    // SAFETY: `path` is the caller's C string.
    if let Some(r) = crate::domain::descriptor_transaction(|| {
        dispatch_fs(|fs| unsafe { fs.openat(dirfd, path, flags, mode_u32(mode)) })
            .inspect(|&fd| domain::file_opened(fd as c_int))
    }) {
        return finish(r) as c_int;
    }
    // SAFETY: the slot holds libc's openat.
    path_fallback!(resolved_path);
    unsafe { forward_openat(slot, dirfd, path, flags, mode) }
}

/// Calls the original `openat` in `slot`, `mode` in a register.
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

/// Calls the original `openat` in `slot` through a variadic pointer, `mode` promoted to `int`.
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

/// Hook for `open(2)`; on macOS aarch64 entered from the trampoline in `crate::os::variadic`.
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

/// Hook for `openat(2)`; on macOS aarch64 entered from the trampoline in
/// `crate::os::variadic`.
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

/// Hook for `creat(2)`, offered to the backend as the equivalent `open`. Not variadic, so no
/// trampoline is needed on any target.
unsafe extern "C" fn creat(path: *const c_char, mode: mode_t) -> c_int {
    path_argument!(path, resolved_path, libc::AT_FDCWD);

    // man 2 creat: creat(path, mode) == open(path, O_CREAT|O_WRONLY|O_TRUNC, mode).
    // SAFETY: `path` is the caller's C string.
    if let Some(r) = dispatch_fs(|fs| unsafe {
        fs.open(
            path,
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            mode_u32(mode),
        )
    }) {
        domain::file_opened(r as c_int);
        return finish(r) as c_int;
    }
    // SAFETY: CREAT holds libc's creat.
    path_fallback!(resolved_path);
    unsafe { original::<unsafe extern "C" fn(*const c_char, mode_t) -> c_int>(&CREAT)(path, mode) }
}

/// Hook for `lseek(2)`, offered only for an fd the backend owns.
///
/// man 2 lseek: `whence` is SEEK_SET/SEEK_CUR/SEEK_END (Linux also SEEK_DATA/SEEK_HOLE); returns
/// the resulting absolute offset. The backend owns the position for fds it minted.
unsafe extern "C" fn lseek(fd: c_int, offset: off_t, whence: c_int) -> off_t {
    // SAFETY: no pointers.
    if let Some(r) = dispatch_fs_fd(fd, |fs| unsafe { fs.lseek(fd, offset, whence) }) {
        return finish(r) as off_t;
    }
    // SAFETY: LSEEK holds libc's lseek.
    unsafe {
        original::<unsafe extern "C" fn(c_int, off_t, c_int) -> off_t>(&LSEEK)(fd, offset, whence)
    }
}

#[cfg(target_os = "linux")]
/// Hook for glibc's `open64`, the LFS alias of `open`.
unsafe extern "C" fn open64(path: *const c_char, flags: c_int, mode: mode_t) -> c_int {
    // SAFETY: forwards to the shared implementation.
    unsafe { do_open(&OPEN64, path, flags, mode) }
}

#[cfg(target_os = "linux")]
/// Hook for glibc's `openat64`, the LFS alias of `openat`.
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
/// Hook for glibc's `creat64`, the LFS alias of `creat`.
unsafe extern "C" fn creat64(path: *const c_char, mode: mode_t) -> c_int {
    path_argument!(path, resolved_path, libc::AT_FDCWD);

    // SAFETY: `path` is the caller's C string.
    if let Some(r) = dispatch_fs(|fs| unsafe {
        fs.open(
            path,
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            mode_u32(mode),
        )
    }) {
        domain::file_opened(r as c_int);
        return finish(r) as c_int;
    }
    // SAFETY: CREAT64 holds libc's creat64.
    path_fallback!(resolved_path);
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, mode_t) -> c_int>(&CREAT64)(path, mode)
    }
}

#[cfg(target_os = "linux")]
/// Hook for glibc's `lseek64`, the LFS alias of `lseek` (`off64_t` is `i64`).
unsafe extern "C" fn lseek64(fd: c_int, offset: i64, whence: c_int) -> i64 {
    // SAFETY: no pointers.
    if let Some(r) = dispatch_fs_fd(fd, |fs| unsafe { fs.lseek(fd, offset, whence) }) {
        return finish(r);
    }
    // SAFETY: LSEEK64 holds libc's lseek64.
    unsafe {
        original::<unsafe extern "C" fn(c_int, i64, c_int) -> i64>(&LSEEK64)(fd, offset, whence)
    }
}

/// Hook for `stat(2)` (`stat64` on Linux, `stat$INODE64` on macOS x86_64).
unsafe extern "C" fn stat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    path_argument!(path, resolved_path, libc::AT_FDCWD);

    // SAFETY: `path` is the caller's C string; `buf` a writable struct stat.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.stat(path, buf.cast()) }) {
        return finish(r) as c_int;
    }
    // SAFETY: STAT holds libc's stat.
    path_fallback!(resolved_path);
    let result = unsafe {
        original::<unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int>(&STAT)(path, buf)
    };
    host_metadata(result, buf.cast(), false)
}

/// Hook for `lstat(2)`.
unsafe extern "C" fn lstat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    path_argument!(path, resolved_path, libc::AT_FDCWD);

    // SAFETY: as for `stat`.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.lstat(path, buf.cast()) }) {
        return finish(r) as c_int;
    }
    // SAFETY: LSTAT holds libc's lstat.
    path_fallback!(resolved_path);
    let result = unsafe {
        original::<unsafe extern "C" fn(*const c_char, *mut libc::stat) -> c_int>(&LSTAT)(path, buf)
    };
    host_metadata(result, buf.cast(), false)
}

/// Hook for `fstat(2)`, offered only for an fd the backend owns.
unsafe extern "C" fn fstat(fd: c_int, buf: *mut libc::stat) -> c_int {
    // SAFETY: `buf` a writable struct stat.
    if let Some(r) = dispatch_fs_fd(fd, |fs| unsafe { fs.fstat(fd, buf.cast()) }) {
        return finish(r) as c_int;
    }
    // SAFETY: FSTAT holds libc's fstat.
    let result =
        unsafe { original::<unsafe extern "C" fn(c_int, *mut libc::stat) -> c_int>(&FSTAT)(fd, buf) };
    host_metadata(result, buf.cast(), false)
}

unsafe extern "C" fn pread(fd: c_int, buf: *mut libc::c_void, len: usize, offset: off_t) -> isize {
    if let Some(r) = dispatch_fs_fd(fd, |fs| unsafe { fs.pread(fd, buf.cast(), len, offset) }) {
        return finish(r) as isize;
    }
    unsafe {
        original::<unsafe extern "C" fn(c_int, *mut libc::c_void, usize, off_t) -> isize>(&PREAD)(
            fd, buf, len, offset,
        )
    }
}

unsafe extern "C" fn pwrite(
    fd: c_int,
    buf: *const libc::c_void,
    len: usize,
    offset: off_t,
) -> isize {
    if let Some(r) = dispatch_fs_fd(fd, |fs| unsafe { fs.pwrite(fd, buf.cast(), len, offset) }) {
        return finish(r) as isize;
    }
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const libc::c_void, usize, off_t) -> isize>(&PWRITE)(
            fd, buf, len, offset,
        )
    }
}

unsafe extern "C" fn ftruncate(fd: c_int, len: off_t) -> c_int {
    if let Some(r) = dispatch_fs_fd(fd, |fs| unsafe { fs.ftruncate(fd, len) }) {
        return finish(r) as c_int;
    }
    unsafe { original::<unsafe extern "C" fn(c_int, off_t) -> c_int>(&FTRUNCATE)(fd, len) }
}

unsafe extern "C" fn fsync(fd: c_int) -> c_int {
    if let Some(r) = dispatch_fs_fd(fd, |fs| unsafe { fs.fsync(fd) }) {
        return finish(r) as c_int;
    }
    unsafe { original::<unsafe extern "C" fn(c_int) -> c_int>(&FSYNC)(fd) }
}

unsafe extern "C" fn flock(fd: c_int, operation: c_int) -> c_int {
    if let Some(r) = dispatch_fs_fd(fd, |fs| unsafe { fs.flock(fd, operation) }) {
        return finish(r) as c_int;
    }
    unsafe { original::<unsafe extern "C" fn(c_int, c_int) -> c_int>(&FLOCK)(fd, operation) }
}

unsafe extern "C" fn unlink(path: *const c_char) -> c_int {
    path_argument!(path, resolved_path, libc::AT_FDCWD);

    if let Some(result) = dispatch_fs(|fs| unsafe { fs.unlink(path) }) {
        return finish(result) as c_int;
    }
    path_fallback!(resolved_path);
    unsafe { original::<unsafe extern "C" fn(*const c_char) -> c_int>(&UNLINK)(path) }
}

unsafe extern "C" fn mkdir(path: *const c_char, mode: mode_t) -> c_int {
    path_argument!(path, resolved_path, libc::AT_FDCWD);

    if let Some(result) = dispatch_fs(|fs| unsafe { fs.mkdir(path, mode_u32(mode)) }) {
        return finish(result) as c_int;
    }
    path_fallback!(resolved_path);
    unsafe { original::<unsafe extern "C" fn(*const c_char, mode_t) -> c_int>(&MKDIR)(path, mode) }
}

unsafe extern "C" fn rename(from: *const c_char, to: *const c_char) -> c_int {
    path_argument!(from, resolved_from, libc::AT_FDCWD);
    path_argument!(to, resolved_to, libc::AT_FDCWD);

    if let Some(result) = dispatch_fs(|fs| unsafe { fs.rename(from, to) }) {
        return finish(result) as c_int;
    }
    path_fallback!(resolved_from, resolved_to);
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, *const c_char) -> c_int>(&RENAME)(from, to)
    }
}

/// Hook for `fstatat(2)`, offered for every path: the backend resolves `dirfd` itself and
/// declines what it does not own.
unsafe extern "C" fn fstatat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flags: c_int,
) -> c_int {
    path_argument!(path, resolved_path, dirfd);

    // SAFETY: caller's path + writable struct stat.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.fstatat(dirfd, path, buf.cast(), flags) }) {
        return finish(r) as c_int;
    }
    // SAFETY: FSTATAT holds libc's fstatat.
    path_fallback!(resolved_path);
    let result = unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_char, *mut libc::stat, c_int) -> c_int>(
            &FSTATAT,
        )(dirfd, path, buf, flags)
    };
    host_metadata(result, buf.cast(), false)
}

/// Hook for `statx(2)` (Linux), which Rust's `std::fs::metadata` tries first on Linux.
///
/// man 2 statx: `flags` carries the AT_* lookup bits plus AT_STATX_SYNC_TYPE; `mask` (STATX_*
/// from <linux/stat.h>) requests fields, and the kernel reports which it filled in `stx_mask`. The
/// buffer is the fixed-offset `struct statx` of <linux/stat.h>, an explicit kernel ABI independent
/// of glibc.
#[cfg(target_os = "linux")]
unsafe extern "C" fn statx(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mask: u32,
    buf: *mut libc::statx,
) -> c_int {
    path_argument!(path, resolved_path, dirfd);

    // SAFETY: caller's path + writable struct statx.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.statx(dirfd, path, flags, mask, buf.cast()) }) {
        return finish(r) as c_int;
    }
    // SAFETY: STATX holds libc's statx.
    path_fallback!(resolved_path);
    let result = unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_char, c_int, u32, *mut libc::statx) -> c_int>(
            &STATX,
        )(dirfd, path, flags, mask, buf)
    };
    host_metadata(result, buf.cast(), true)
}

unsafe extern "C" fn rmdir(path: *const c_char) -> c_int {
    path_argument!(path, resolved_path, libc::AT_FDCWD);

    if let Some(result) = dispatch_fs(|fs| unsafe { fs.rmdir(path) }) {
        return finish(result) as c_int;
    }
    path_fallback!(resolved_path);
    unsafe { original::<unsafe extern "C" fn(*const c_char) -> c_int>(&RMDIR)(path) }
}

unsafe extern "C" fn statfs(path: *const c_char, buf: *mut libc::statfs) -> c_int {
    path_argument!(path, resolved_path, libc::AT_FDCWD);

    if let Some(result) = dispatch_fs(|fs| unsafe { fs.statfs(path, buf.cast()) }) {
        return finish(result) as c_int;
    }
    path_fallback!(resolved_path);
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, *mut libc::statfs) -> c_int>(&STATFS)(
            path, buf,
        )
    }
}

unsafe extern "C" fn fstatfs(fd: c_int, buf: *mut libc::statfs) -> c_int {
    if let Some(result) = dispatch_fs_fd(fd, |fs| unsafe { fs.fstatfs(fd, buf.cast()) }) {
        return finish(result) as c_int;
    }
    unsafe {
        original::<unsafe extern "C" fn(c_int, *mut libc::statfs) -> c_int>(&FSTATFS)(fd, buf)
    }
}

unsafe extern "C" fn unlinkat(fd: c_int, path: *const c_char, flags: c_int) -> c_int {
    path_argument!(path, resolved_path, fd);

    if let Some(result) = dispatch_fs(|fs| unsafe { fs.unlinkat(fd, path, flags) }) {
        return finish(result) as c_int;
    }
    path_fallback!(resolved_path);
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_char, c_int) -> c_int>(&UNLINKAT)(
            fd, path, flags,
        )
    }
}

unsafe extern "C" fn mkdirat(fd: c_int, path: *const c_char, mode: mode_t) -> c_int {
    path_argument!(path, resolved_path, fd);

    if let Some(result) = dispatch_fs(|fs| unsafe { fs.mkdirat(fd, path, mode_u32(mode)) }) {
        return finish(result) as c_int;
    }
    path_fallback!(resolved_path);
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_char, mode_t) -> c_int>(&MKDIRAT)(
            fd, path, mode,
        )
    }
}

unsafe extern "C" fn renameat(
    fromfd: c_int,
    from: *const c_char,
    tofd: c_int,
    to: *const c_char,
) -> c_int {
    path_argument!(from, resolved_from, fromfd);
    path_argument!(to, resolved_to, tofd);

    if let Some(result) = dispatch_fs(|fs| unsafe { fs.renameat(fromfd, from, tofd, to) }) {
        return finish(result) as c_int;
    }
    path_fallback!(resolved_from, resolved_to);
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char) -> c_int>(
            &RENAMEAT,
        )(fromfd, from, tofd, to)
    }
}

unsafe extern "C" fn fdopendir(fd: c_int) -> *mut libc::DIR {
    if let Some(result) = dispatch_fs_fd(fd, |fs| unsafe { fs.fdopendir(fd) }) {
        return finish_dir(result);
    }
    unsafe { original::<unsafe extern "C" fn(c_int) -> *mut libc::DIR>(&FDOPENDIR)(fd) }
}

unsafe extern "C" fn link(from: *const c_char, to: *const c_char) -> c_int {
    path_argument!(from, resolved_from, libc::AT_FDCWD);
    path_argument!(to, resolved_to, libc::AT_FDCWD);

    if let Some(result) = dispatch_fs(|fs| unsafe { fs.link(from, to) }) {
        return finish(result) as c_int;
    }
    path_fallback!(resolved_from, resolved_to);
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, *const c_char) -> c_int>(&LINK)(from, to)
    }
}

unsafe extern "C" fn linkat(
    fromfd: c_int,
    from: *const c_char,
    tofd: c_int,
    to: *const c_char,
    flags: c_int,
) -> c_int {
    path_argument!(from, resolved_from, fromfd);
    path_argument!(to, resolved_to, tofd);

    if let Some(result) = dispatch_fs(|fs| unsafe { fs.linkat(fromfd, from, tofd, to, flags) }) {
        return finish(result) as c_int;
    }
    path_fallback!(resolved_from, resolved_to);
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_char, c_int, *const c_char, c_int) -> c_int>(
            &LINKAT,
        )(fromfd, from, tofd, to, flags)
    }
}

#[cfg(target_os = "linux")]
unsafe extern "C" fn getdents64(fd: c_int, buf: *mut u8, len: usize) -> libc::ssize_t {
    if let Some(result) = dispatch_fs_fd(fd, |fs| unsafe {
        fs.getdents64(fd, buf, len.min(c_int::MAX as usize))
    }) {
        return finish(result) as libc::ssize_t;
    }
    unsafe {
        original::<unsafe extern "C" fn(c_int, *mut u8, usize) -> libc::ssize_t>(&GETDENTS64)(
            fd, buf, len,
        )
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" fn getdirentries(
    fd: c_int,
    buf: *mut u8,
    len: usize,
    base: *mut off_t,
) -> libc::ssize_t {
    if let Some(result) = dispatch_fs_fd(fd, |fs| unsafe { fs.getdents64(fd, buf, len) }) {
        if result >= 0 && !base.is_null() {
            unsafe { base.write(0) };
        }
        return finish(result) as libc::ssize_t;
    }
    unsafe {
        original::<unsafe extern "C" fn(c_int, *mut u8, usize, *mut off_t) -> libc::ssize_t>(
            &GETDIRENTRIES,
        )(fd, buf, len, base)
    }
}

const DIR_TAG: usize = usize::MAX & !(c_int::MAX as usize);

fn finish_dir(result: i64) -> *mut libc::DIR {
    if result < 0 {
        finish_ptr(result).cast()
    } else {
        (DIR_TAG | result as usize) as *mut libc::DIR
    }
}

fn dir_fd(dirp: *mut libc::DIR) -> Option<c_int> {
    let raw = dirp as usize;
    (raw & DIR_TAG == DIR_TAG).then_some((raw & !DIR_TAG) as c_int)
}

/// Hook for `opendir(3)`.
unsafe extern "C" fn opendir(path: *const c_char) -> *mut libc::DIR {
    path_argument!(path, resolved_path, libc::AT_FDCWD);

    // SAFETY: `path` is the caller's C string.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.opendir(path) }) {
        domain::file_opened(r as c_int);
        return finish_dir(r);
    }
    // SAFETY: OPENDIR holds libc's opendir.
    path_fallback!(pointer; resolved_path);
    unsafe { original::<unsafe extern "C" fn(*const c_char) -> *mut libc::DIR>(&OPENDIR)(path) }
}

#[cfg(target_os = "linux")]
/// Hook for `readdir64` (Linux), the LFS `readdir` that Rust's `std::fs::read_dir` uses there.
/// Returns the backend's `struct dirent64`, or NULL at end of stream without touching errno.
unsafe extern "C" fn readdir(dirp: *mut libc::DIR) -> *mut libc::dirent64 {
    if let Some(fd) = dir_fd(dirp) {
        let result = dispatch_fs_fd(fd, |fs| unsafe { fs.readdir(fd) }).unwrap_or(-i64::from(
            if domain::file_plane(fd).is_some() {
                libc::EOPNOTSUPP
            } else {
                libc::EBADF
            },
        ));
        return finish_ptr(result).cast();
    }
    // SAFETY: READDIR holds libc's readdir64.
    unsafe {
        original::<unsafe extern "C" fn(*mut libc::DIR) -> *mut libc::dirent64>(&READDIR)(dirp)
    }
}

#[cfg(target_os = "macos")]
/// Hook for `readdir_r(3)` (macOS), which Rust's `std::fs::read_dir` uses there. The backend
/// reports end of stream as `Ok(0)` with `*result` null. A handled error is returned as the
/// positive error number, not -1 with errno: readdir_r(3) (RETURN VALUES) reports failure through
/// its return value, and std's `ReadDir` reads it from there.
unsafe extern "C" fn readdir_r(
    dirp: *mut libc::DIR,
    entry: *mut libc::dirent,
    result: *mut *mut libc::dirent,
) -> c_int {
    if let Some(fd) = dir_fd(dirp)
        // SAFETY: `entry`/`result` are the caller's dirent and result slots.
        && let Some(r) =
            dispatch_fs_fd(fd, |fs| unsafe { fs.readdir_r(fd, entry.cast(), result.cast()) })
    {
        return if r < 0 { (-r) as c_int } else { r as c_int };
    }
    if let Some(fd) = dir_fd(dirp) {
        if !result.is_null() {
            unsafe {
                *result = std::ptr::null_mut();
            }
        }
        return if domain::file_plane(fd).is_some() {
            libc::EOPNOTSUPP
        } else {
            libc::EBADF
        };
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

/// Hook for `closedir(3)`, offered only for a stream fd the backend owns.
unsafe extern "C" fn closedir(dirp: *mut libc::DIR) -> c_int {
    if let Some(fd) = dir_fd(dirp) {
        let result = match domain::file_plane(fd) {
            Some(FilePlane::Served(fs, serial)) => {
                crate::owners::release_file_of(fd, serial);
                let _passthrough = Passthrough::enter();
                unsafe { fs.closedir(fd) }
                    .map_or(-i64::from(libc::EOPNOTSUPP), crate::fs::FsResult::into_raw)
            }
            _ => -i64::from(libc::EBADF),
        };
        return finish(result) as c_int;
    }
    // SAFETY: CLOSEDIR holds libc's closedir.
    unsafe { original::<unsafe extern "C" fn(*mut libc::DIR) -> c_int>(&CLOSEDIR)(dirp) }
}

/// Hook for `dirfd(3)`.
unsafe extern "C" fn dirfd(dirp: *mut libc::DIR) -> c_int {
    if let Some(fd) = dir_fd(dirp) {
        return if matches!(domain::file_plane(fd), Some(FilePlane::Served(..))) {
            fd
        } else {
            finish(-i64::from(libc::EBADF)) as c_int
        };
    }
    // SAFETY: DIRFD holds libc's dirfd.
    unsafe { original::<unsafe extern "C" fn(*mut libc::DIR) -> c_int>(&DIRFD)(dirp) }
}

#[cfg(target_os = "macos")]
/// Hook for plain `readdir(3)` on macOS, so a consumer that bypasses `readdir_r` never
/// dereferences our fake `DIR*`.
unsafe extern "C" fn readdir_plain(dirp: *mut libc::DIR) -> *mut libc::dirent {
    if let Some(fd) = dir_fd(dirp) {
        let result = dispatch_fs_fd(fd, |fs| unsafe { fs.readdir(fd) }).unwrap_or(-i64::from(
            if domain::file_plane(fd).is_some() {
                libc::EOPNOTSUPP
            } else {
                libc::EBADF
            },
        ));
        return finish_ptr(result).cast();
    }
    // SAFETY: READDIR2 holds libc's readdir.
    unsafe {
        original::<unsafe extern "C" fn(*mut libc::DIR) -> *mut libc::dirent>(&READDIR2)(dirp)
    }
}

/// Hook for `realpath(3)`.
///
/// man 3 realpath: a non-null `resolved` must hold PATH_MAX bytes; passing null asks libc to
/// malloc the result. On macOS, code built without strict POSIX, and the `libc` crate, bind
/// `realpath` to `realpath$DARWIN_EXTSN` (SDK `<_stdlib.h>`: `realpath(...)
/// __DARWIN_EXTSN(realpath)`; `<sys/cdefs.h>` `__DARWIN_SUF_EXTSN`), the only name hooked there.
/// Both Darwin variants accept a null `resolved`; they differ in how a relative path reads the cwd
/// (Libc stdlib/FreeBSD/realpath.c, `VARIANT_DARWINEXTSN`).
unsafe extern "C" fn realpath(path: *const c_char, resolved: *mut c_char) -> *mut c_char {
    path_argument!(path, resolved_path, libc::AT_FDCWD);

    // SAFETY: `path` is the caller's C string; `resolved` its output buffer (or null).
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.realpath(path, resolved) }) {
        return finish_ptr(r).cast();
    }
    // SAFETY: REALPATH holds libc's realpath.
    path_fallback!(pointer; resolved_path);
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut c_char>(&REALPATH)(
            path, resolved,
        )
    }
}

unsafe extern "C" fn symlink(target: *const c_char, link: *const c_char) -> c_int {
    path_argument!(link, resolved_link, libc::AT_FDCWD);

    if let Some(result) = dispatch_fs(|fs| unsafe { fs.symlink(target, link) }) {
        return finish(result) as c_int;
    }
    path_fallback!(resolved_link);
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, *const c_char) -> c_int>(&SYMLINK)(
            target, link,
        )
    }
}

unsafe extern "C" fn symlinkat(target: *const c_char, dirfd: c_int, link: *const c_char) -> c_int {
    path_argument!(link, resolved_link, dirfd);

    if let Some(result) = dispatch_fs(|fs| unsafe { fs.symlinkat(target, dirfd, link) }) {
        return finish(result) as c_int;
    }
    path_fallback!(resolved_link);
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, c_int, *const c_char) -> c_int>(&SYMLINKAT)(
            target, dirfd, link,
        )
    }
}

unsafe extern "C" fn chdir(path: *const c_char) -> c_int {
    path_argument!(path, resolved_path, libc::AT_FDCWD);

    if let Some(result) = dispatch_fs(|fs| unsafe { fs.chdir(path) }) {
        return finish(result) as c_int;
    }
    path_fallback!(resolved_path);
    let result = unsafe { original::<unsafe extern "C" fn(*const c_char) -> c_int>(&CHDIR)(path) };
    if result == 0 {
        cwd_changed();
    }
    result
}

unsafe extern "C" fn fchdir(fd: c_int) -> c_int {
    if fs_owns(fd)
        && let Some(result) = dispatch_fs(|fs| unsafe { fs.fchdir(fd) })
    {
        return finish(result) as c_int;
    }
    let result = unsafe { original::<unsafe extern "C" fn(c_int) -> c_int>(&FCHDIR)(fd) };
    if result == 0 {
        cwd_changed();
    }
    result
}

unsafe extern "C" fn getcwd(buf: *mut c_char, len: usize) -> *mut c_char {
    if let Some(result) = dispatch_fs(|fs| unsafe { fs.getcwd(buf, len) }) {
        return finish_ptr(result).cast();
    }
    unsafe {
        original::<unsafe extern "C" fn(*mut c_char, usize) -> *mut c_char>(&GETCWD)(buf, len)
    }
}

/// Hook for `readlink(2)`.
///
/// man 2 readlink: writes at most `len` bytes and does NOT null-terminate; the return is the byte
/// count, silently truncated to `len`. A backend keeps that contract: no terminator, and no error
/// when the target is truncated.
unsafe extern "C" fn readlink(path: *const c_char, buf: *mut c_char, len: usize) -> isize {
    path_argument!(path, resolved_path, libc::AT_FDCWD);

    // SAFETY: `path` is the caller's C string; `buf` its `len`-byte output.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.readlink(path, buf.cast(), len) }) {
        return finish(r) as isize;
    }
    // SAFETY: READLINK holds libc's readlink.
    path_fallback!(resolved_path);
    unsafe {
        original::<unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> isize>(&READLINK)(
            path, buf, len,
        )
    }
}

/// Hook for `readlinkat(2)`, as [`readlink`] relative to `dirfd`.
unsafe extern "C" fn readlinkat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut c_char,
    len: usize,
) -> isize {
    path_argument!(path, resolved_path, dirfd);

    // SAFETY: `path`/`buf` as for `readlink`.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.readlinkat(dirfd, path, buf.cast(), len) }) {
        return finish(r) as isize;
    }
    // SAFETY: READLINKAT holds libc's readlinkat.
    path_fallback!(resolved_path);
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_char, *mut c_char, usize) -> isize>(
            &READLINKAT,
        )(dirfd, path, buf, len)
    }
}

/// Hook for `access(2)`: `mode` is F_OK or a bitwise-or of R_OK/W_OK/X_OK.
unsafe extern "C" fn access(path: *const c_char, mode: c_int) -> c_int {
    path_argument!(path, resolved_path, libc::AT_FDCWD);

    // SAFETY: `path` is the caller's C string.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.access(path, mode) }) {
        return finish(r) as c_int;
    }
    // SAFETY: ACCESS holds libc's access.
    path_fallback!(resolved_path);
    unsafe { original::<unsafe extern "C" fn(*const c_char, c_int) -> c_int>(&ACCESS)(path, mode) }
}

/// Hook for `faccessat(2)`: resolves `path` relative to `dirfd` (or AT_FDCWD); `flags` may carry
/// AT_EACCESS and AT_SYMLINK_NOFOLLOW.
unsafe extern "C" fn faccessat(
    dirfd: c_int,
    path: *const c_char,
    mode: c_int,
    flags: c_int,
) -> c_int {
    path_argument!(path, resolved_path, dirfd);

    // SAFETY: `path` is the caller's C string.
    if let Some(r) = dispatch_fs(|fs| unsafe { fs.faccessat(dirfd, path, mode, flags) }) {
        return finish(r) as c_int;
    }
    // SAFETY: FACCESSAT holds libc's faccessat.
    path_fallback!(resolved_path);
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_char, c_int, c_int) -> c_int>(&FACCESSAT)(
            dirfd, path, mode, flags,
        )
    }
}

/// Shows the domain's file plane a `struct stat` (or `struct statx`) the OS filled successfully,
/// so it may restate the timestamps on the sim's clock ([`Fs::host_metadata`](crate::Fs)).
fn host_metadata(result: c_int, buf: *mut u8, statx: bool) -> c_int {
    if result == 0 && !buf.is_null() {
        dispatch_fs(|fs| {
            // SAFETY: the OS just filled `buf` as the structure `statx` names.
            unsafe { fs.host_metadata(buf, statx) };
            None
        });
    }
    result
}

/// man 2 utimensat: `UTIME_NOW` and `UTIME_OMIT` in `tv_nsec` select the current time or leave
/// the timestamp alone; any other `tv_nsec` outside `0..1e9` is `EINVAL`.
fn timespec_time(time: &libc::timespec) -> Option<TimeSet> {
    match time.tv_nsec {
        libc::UTIME_OMIT => Some(TimeSet::Omit),
        libc::UTIME_NOW => Some(TimeSet::Now),
        nanos @ 0..1_000_000_000 => Some(TimeSet::At(
            i128::from(time.tv_sec) * 1_000_000_000 + i128::from(nanos),
        )),
        _ => None,
    }
}

/// The access and modification times of a `utimensat`/`futimens` call; a null `times` sets both
/// to the current time (man 2 utimensat). `None` for an invalid `timespec`.
unsafe fn timespec_times(times: *const libc::timespec) -> Option<SetTimes> {
    if times.is_null() {
        return Some(SetTimes {
            accessed: TimeSet::Now,
            modified: TimeSet::Now,
            created: TimeSet::Omit,
        });
    }
    // SAFETY: a non-null `times` points to two timespecs (man 2 utimensat).
    let [accessed, modified] = unsafe { times.cast::<[libc::timespec; 2]>().read() };
    Some(SetTimes {
        accessed: timespec_time(&accessed)?,
        modified: timespec_time(&modified)?,
        created: TimeSet::Omit,
    })
}

/// The times of a `utimes`/`futimes` call: a null `times` is the current time for both, and a
/// `tv_usec` outside `0..1e6` is `EINVAL` (man 2 utimes; POSIX `utimes`).
unsafe fn timeval_times(times: *const libc::timeval) -> Option<SetTimes> {
    if times.is_null() {
        return Some(SetTimes {
            accessed: TimeSet::Now,
            modified: TimeSet::Now,
            created: TimeSet::Omit,
        });
    }
    // SAFETY: a non-null `times` points to two timevals (man 2 utimes).
    let [accessed, modified] = unsafe { times.cast::<[libc::timeval; 2]>().read() };
    let at = |time: libc::timeval| {
        (0..1_000_000).contains(&time.tv_usec).then(|| {
            TimeSet::At(
                i128::from(time.tv_sec) * 1_000_000_000 + i128::from(time.tv_usec) * 1_000,
            )
        })
    };
    Some(SetTimes {
        accessed: at(accessed)?,
        modified: at(modified)?,
        created: TimeSet::Omit,
    })
}

/// The body of every timestamp-setting hook: offers the call to the plane serving the file, else
/// runs `real` (with the path resolved against a virtual working directory) and, if the OS set
/// the times, tells the domain's plane. A null `path` names the descriptor `dirfd`.
unsafe fn set_times(
    dirfd: c_int,
    path: *const c_char,
    times: SetTimes,
    flags: c_int,
    real: impl FnOnce(*const c_char) -> c_int,
) -> c_int {
    let served = if path.is_null() {
        dispatch_fs_fd(dirfd, |fs| unsafe { fs.set_times(dirfd, path, &times, flags) })
    } else {
        None
    };
    if let Some(r) = served {
        return finish(r) as c_int;
    }
    path_argument!(path, resolved_path, dirfd);
    if !path.is_null()
        && let Some(r) = dispatch_fs(|fs| unsafe { fs.set_times(dirfd, path, &times, flags) })
    {
        return finish(r) as c_int;
    }
    path_fallback!(resolved_path);
    let result = real(path);
    if result == 0 {
        dispatch_fs(|fs| {
            unsafe { fs.host_times_set(dirfd, path, &times, flags) };
            None
        });
    }
    result
}

/// Hook for `utimensat(2)`. glibc rejects a null `path` itself (`EINVAL`), so only a named file is
/// offered to the planes.
unsafe extern "C" fn utimensat(
    dirfd: c_int,
    path: *const c_char,
    times: *const libc::timespec,
    flags: c_int,
) -> c_int {
    let real = |path| unsafe {
        original::<unsafe extern "C" fn(c_int, *const c_char, *const libc::timespec, c_int) -> c_int>(
            &UTIMENSAT,
        )(dirfd, path, times, flags)
    };
    match unsafe { timespec_times(times) } {
        Some(set) if !path.is_null() => unsafe { set_times(dirfd, path, set, flags, real) },
        _ => real(path),
    }
}

/// Hook for `futimens(3)`, `utimensat` on the descriptor itself.
unsafe extern "C" fn futimens(fd: c_int, times: *const libc::timespec) -> c_int {
    let real = |_| unsafe {
        original::<unsafe extern "C" fn(c_int, *const libc::timespec) -> c_int>(&FUTIMENS)(
            fd, times,
        )
    };
    match unsafe { timespec_times(times) } {
        Some(set) => unsafe { set_times(fd, std::ptr::null(), set, 0, real) },
        None => real(std::ptr::null()),
    }
}

/// Hook for `utimes(2)`: microsecond times, following a final symlink.
unsafe extern "C" fn utimes(path: *const c_char, times: *const libc::timeval) -> c_int {
    let real = |path| unsafe {
        original::<unsafe extern "C" fn(*const c_char, *const libc::timeval) -> c_int>(&UTIMES)(
            path, times,
        )
    };
    match unsafe { timeval_times(times) } {
        Some(set) if !path.is_null() => unsafe {
            set_times(libc::AT_FDCWD, path, set, 0, real)
        },
        _ => real(path),
    }
}

/// Hook for `futimes(3)`.
unsafe extern "C" fn futimes(fd: c_int, times: *const libc::timeval) -> c_int {
    let real = |_| unsafe {
        original::<unsafe extern "C" fn(c_int, *const libc::timeval) -> c_int>(&FUTIMES)(fd, times)
    };
    match unsafe { timeval_times(times) } {
        Some(set) => unsafe { set_times(fd, std::ptr::null(), set, 0, real) },
        None => real(std::ptr::null()),
    }
}

/// The times a macOS `setattrlist(2)` call sets, when it sets nothing but the creation,
/// modification and access times and takes no option beyond `FSOPT_NOFOLLOW`, as std's
/// `set_times` calls it; `(times, at_flags)`. The buffer packs the requested attributes as
/// `timespec`s in attribute-bit order (`<sys/attr.h>`; man 2 getattrlist, "attribute buffer").
#[cfg(target_os = "macos")]
unsafe fn attrlist_times(
    list: *const libc::attrlist,
    buf: *const libc::c_void,
    size: usize,
    options: u32,
) -> Option<(SetTimes, c_int)> {
    if list.is_null() || options & !libc::FSOPT_NOFOLLOW != 0 {
        return None;
    }
    // SAFETY: a non-null `list` is the caller's attrlist.
    let list = unsafe { list.read() };
    let settable = libc::ATTR_CMN_CRTIME | libc::ATTR_CMN_MODTIME | libc::ATTR_CMN_ACCTIME;
    if list.bitmapcount != libc::ATTR_BIT_MAP_COUNT
        || list.commonattr & !settable != 0
        || list.volattr | list.dirattr | list.fileattr | list.forkattr != 0
    {
        return None;
    }
    let count = list.commonattr.count_ones() as usize;
    let size_needed = count * std::mem::size_of::<libc::timespec>();
    if buf.is_null() || size < size_needed {
        return None;
    }
    let mut next = buf.cast::<libc::timespec>();
    let mut take = |bit| {
        if list.commonattr & bit == 0 {
            return Some(TimeSet::Omit);
        }
        // SAFETY: `size` covers one timespec per requested attribute, read unaligned.
        let time = unsafe { next.read_unaligned() };
        next = unsafe { next.add(1) };
        (0..1_000_000_000).contains(&time.tv_nsec).then(|| {
            TimeSet::At(i128::from(time.tv_sec) * 1_000_000_000 + i128::from(time.tv_nsec))
        })
    };
    let created = take(libc::ATTR_CMN_CRTIME)?;
    let modified = take(libc::ATTR_CMN_MODTIME)?;
    let accessed = take(libc::ATTR_CMN_ACCTIME)?;
    let flags = if options & libc::FSOPT_NOFOLLOW != 0 {
        libc::AT_SYMLINK_NOFOLLOW
    } else {
        0
    };
    Some((
        SetTimes {
            accessed,
            modified,
            created,
        },
        flags,
    ))
}

/// Hook for macOS `setattrlist(2)`, offered to the planes only as a pure timestamp call (see
/// [`attrlist_times`]).
#[cfg(target_os = "macos")]
unsafe extern "C" fn setattrlist(
    path: *const c_char,
    list: *mut libc::attrlist,
    buf: *mut libc::c_void,
    size: usize,
    options: u32,
) -> c_int {
    type SetattrlistFn = unsafe extern "C" fn(
        *const c_char,
        *mut libc::attrlist,
        *mut libc::c_void,
        usize,
        u32,
    ) -> c_int;
    let real = |path| unsafe {
        original::<SetattrlistFn>(&SETATTRLIST)(path, list, buf, size, options)
    };
    match unsafe { attrlist_times(list, buf, size, options) } {
        Some((set, flags)) if !path.is_null() => unsafe {
            set_times(libc::AT_FDCWD, path, set, flags, real)
        },
        _ => real(path),
    }
}

/// Hook for macOS `fsetattrlist(2)`, which std's `File::set_times` calls.
#[cfg(target_os = "macos")]
unsafe extern "C" fn fsetattrlist(
    fd: c_int,
    list: *mut libc::attrlist,
    buf: *mut libc::c_void,
    size: usize,
    options: u32,
) -> c_int {
    type FsetattrlistFn =
        unsafe extern "C" fn(c_int, *mut libc::attrlist, *mut libc::c_void, usize, u32) -> c_int;
    let real =
        |_| unsafe { original::<FsetattrlistFn>(&FSETATTRLIST)(fd, list, buf, size, options) };
    match unsafe { attrlist_times(list, buf, size, options) } {
        Some((set, _)) => unsafe { set_times(fd, std::ptr::null(), set, 0, real) },
        None => real(std::ptr::null()),
    }
}
