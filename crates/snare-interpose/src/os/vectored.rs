//! Vectored I/O hooks: `readv`/`writev`, the positional `preadv`/`pwritev`, and Linux's
//! `preadv2`/`pwritev2`. Each is offered to whichever plane serves the fd, as the scalar call is
//! (`read`/`write` in `sockets.rs`, `pread`/`pwrite` in `files.rs`): a backend sees one contiguous
//! buffer, gathered from the caller's iovecs before a write and scattered back into them after a
//! read. A stream write takes the iovecs as one run of bytes and a datagram write sends them as
//! one datagram, as `writev(2)` does. A descriptor no plane serves goes to the OS, unobserved.
//!
//! The positional calls are file calls: a network descriptor reaches its placeholder, which
//! refuses positioning with `ESPIPE` as a socket does.

use std::ffi::c_int;
use std::sync::atomic::AtomicUsize;

use libc::{iovec, off_t, ssize_t};

use crate::domain::{self, dispatch_fs_fd};
use crate::hooks::{Hook, hook, original};
use crate::net::NetResult;
use crate::os::sockets::finish;

macro_rules! slot {
    ($name:ident) => {
        static $name: AtomicUsize = AtomicUsize::new(0);
    };
}

slot!(READV);
slot!(WRITEV);
slot!(PREADV);
slot!(PWRITEV);
#[cfg(target_os = "linux")]
slot!(PREADV2);
#[cfg(target_os = "linux")]
slot!(PWRITEV2);

/// `UIO_MAXIOV`: the most iovecs one call takes (Linux include/uapi/linux/uio.h; XNU
/// bsd/sys/uio.h).
const UIO_MAXIOV: c_int = 1024;

/// The `preadv2`/`pwritev2` flags modelled (include/uapi/linux/fs.h).
#[cfg(target_os = "linux")]
const RWF_KNOWN: c_int =
    libc::RWF_HIPRI | libc::RWF_DSYNC | libc::RWF_SYNC | libc::RWF_NOWAIT | libc::RWF_APPEND;

pub(crate) fn hooks() -> Vec<Hook> {
    vec![
        hook!("readv", readv, READV),
        hook!("writev", writev, WRITEV),
        hook!("preadv", preadv, PREADV),
        hook!("pwritev", pwritev, PWRITEV),
        #[cfg(target_os = "linux")]
        hook!("preadv64", preadv, PREADV),
        #[cfg(target_os = "linux")]
        hook!("pwritev64", pwritev, PWRITEV),
        #[cfg(target_os = "linux")]
        hook!("preadv2", preadv2, PREADV2),
        #[cfg(target_os = "linux")]
        hook!("pwritev2", pwritev2, PWRITEV2),
        #[cfg(target_os = "linux")]
        hook!("preadv64v2", preadv2, PREADV2),
        #[cfg(target_os = "linux")]
        hook!("pwritev64v2", pwritev2, PWRITEV2),
    ]
}

/// A caller's iovec array, checked as the kernel checks it before moving any byte: Linux
/// `import_iovec` (lib/iov_iter.c) and XNU `readv`/`writev` (bsd/kern/sys_generic.c) refuse a
/// count past `UIO_MAXIOV` or lengths summing past `SSIZE_MAX` with `EINVAL`; XNU also refuses a
/// count of zero, where Linux transfers nothing.
struct Iovecs<'a> {
    iov: &'a [iovec],
    total: usize,
}

impl<'a> Iovecs<'a> {
    unsafe fn new(iov: *const iovec, count: c_int) -> Result<Self, c_int> {
        let least = if cfg!(target_os = "macos") { 1 } else { 0 };
        if !(least..=UIO_MAXIOV).contains(&count) {
            return Err(libc::EINVAL);
        }
        if count > 0 && iov.is_null() {
            return Err(libc::EFAULT);
        }
        let iov: &[iovec] = if count == 0 {
            &[]
        } else {
            // SAFETY: the caller passed `count` iovecs at `iov`.
            unsafe { std::slice::from_raw_parts(iov, count as usize) }
        };
        let mut total = 0usize;
        for entry in iov {
            total = total
                .checked_add(entry.iov_len)
                .filter(|&total| total <= isize::MAX as usize)
                .ok_or(libc::EINVAL)?;
            if entry.iov_len > 0 && entry.iov_base.is_null() {
                return Err(libc::EFAULT);
            }
        }
        Ok(Self { iov, total })
    }

    /// The one iovec holding every byte, when there is one: the call then needs no copy.
    fn single(&self) -> Option<&iovec> {
        let mut filled = self.iov.iter().filter(|entry| entry.iov_len > 0);
        match (filled.next(), filled.next()) {
            (Some(only), None) => Some(only),
            _ => None,
        }
    }

    /// Reads into the iovecs through `read`, which fills a buffer of `total` bytes and returns how
    /// many it filled.
    fn read(&self, read: impl FnOnce(*mut u8, usize) -> Option<NetResult>) -> Option<NetResult> {
        if let Some(only) = self.single() {
            return read(only.iov_base.cast(), only.iov_len);
        }
        let mut buf = vec![0u8; self.total];
        let result = read(buf.as_mut_ptr(), buf.len())?;
        if let NetResult::Ok(n) = result {
            let mut left = &buf[..(n as usize).min(buf.len())];
            for entry in self.iov {
                if left.is_empty() {
                    break;
                }
                let take = entry.iov_len.min(left.len());
                // SAFETY: each iovec names `iov_len` writable bytes (checked non-null above).
                unsafe {
                    std::ptr::copy_nonoverlapping(left.as_ptr(), entry.iov_base.cast(), take)
                };
                left = &left[take..];
            }
        }
        Some(result)
    }

    /// Writes the iovecs, gathered into one buffer, through `write`.
    fn write(&self, write: impl FnOnce(*const u8, usize) -> Option<NetResult>) -> Option<NetResult> {
        if let Some(only) = self.single() {
            return write(only.iov_base.cast_const().cast(), only.iov_len);
        }
        let mut buf = Vec::with_capacity(self.total);
        for entry in self.iov.iter().filter(|entry| entry.iov_len > 0) {
            // SAFETY: each iovec names `iov_len` readable bytes (checked non-null above).
            buf.extend_from_slice(unsafe {
                std::slice::from_raw_parts(entry.iov_base.cast::<u8>(), entry.iov_len)
            });
        }
        write(buf.as_ptr(), buf.len())
    }
}

/// The checked iovecs of a call, or the errno the check fails it with, for a handled call to
/// report.
type Checked<'a> = Result<Iovecs<'a>, c_int>;

fn reading(
    iovecs: &Checked<'_>,
    read: impl FnOnce(*mut u8, usize) -> Option<NetResult>,
) -> Option<NetResult> {
    match iovecs {
        Ok(iovecs) => iovecs.read(read),
        Err(errno) => Some(NetResult::Err(*errno)),
    }
}

fn writing(
    iovecs: &Checked<'_>,
    write: impl FnOnce(*const u8, usize) -> Option<NetResult>,
) -> Option<NetResult> {
    match iovecs {
        Ok(iovecs) => iovecs.write(write),
        Err(errno) => Some(NetResult::Err(*errno)),
    }
}

/// `readv(2)`: the owning plane's `read` into the iovecs, else the OS.
unsafe extern "C" fn readv(fd: c_int, iov: *const iovec, count: c_int) -> ssize_t {
    // SAFETY: `iov` holds `count` iovecs of writable buffers.
    let iovecs = unsafe { Iovecs::new(iov, count) };
    // SAFETY: each buffer handed on holds `len` writable bytes.
    if let Some(r) = dispatch_fs_fd(fd, |fs| {
        reading(&iovecs, |buf, len| unsafe { fs.read(fd, buf, len) })
    }) {
        return finish(r) as ssize_t;
    }
    if let Some(r) = domain::dispatch_owned(fd, |net| {
        reading(&iovecs, |buf, len| unsafe { net.read(fd, buf, len) })
    }) {
        return finish(r) as ssize_t;
    }
    // SAFETY: READV holds libc's readv.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const iovec, c_int) -> ssize_t>(&READV)(
            fd, iov, count,
        )
    }
}

/// `writev(2)`: the owning plane's `write` of the gathered iovecs, else the OS. A handled socket
/// write is an effect other threads see.
unsafe extern "C" fn writev(fd: c_int, iov: *const iovec, count: c_int) -> ssize_t {
    // SAFETY: `iov` holds `count` iovecs of readable buffers.
    let iovecs = unsafe { Iovecs::new(iov, count) };
    // SAFETY: each buffer handed on holds `len` readable bytes.
    if let Some(r) = dispatch_fs_fd(fd, |fs| {
        writing(&iovecs, |buf, len| unsafe { fs.write(fd, buf, len) })
    }) {
        return finish(r) as ssize_t;
    }
    let write = |net: &dyn crate::net::Net| {
        writing(&iovecs, |buf, len| unsafe { net.write(fd, buf, len) })
    };
    let handled = if cfg!(target_os = "linux") && iovecs.as_ref().is_ok_and(|i| i.total == 8) {
        domain::dispatch_wake(fd, write)
    } else {
        domain::dispatch_owned(fd, write)
    };
    if let Some(r) = handled {
        domain::note_effect("writev");
        return finish(r) as ssize_t;
    }
    // SAFETY: WRITEV holds libc's writev.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const iovec, c_int) -> ssize_t>(&WRITEV)(
            fd, iov, count,
        )
    }
}

/// `preadv(2)`: the file plane's `pread` into the iovecs, the file offset untouched, else the OS.
unsafe extern "C" fn preadv(fd: c_int, iov: *const iovec, count: c_int, offset: off_t) -> ssize_t {
    // SAFETY: `iov` holds `count` iovecs of writable buffers.
    let iovecs = unsafe { Iovecs::new(iov, count) };
    if let Some(r) = dispatch_fs_fd(fd, |fs| {
        reading(&iovecs, |buf, len| unsafe { fs.pread(fd, buf, len, offset) })
    }) {
        return finish(r) as ssize_t;
    }
    // SAFETY: PREADV holds libc's preadv.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const iovec, c_int, off_t) -> ssize_t>(&PREADV)(
            fd, iov, count, offset,
        )
    }
}

/// `pwritev(2)`: the file plane's `pwrite` of the gathered iovecs, the file offset untouched,
/// else the OS.
unsafe extern "C" fn pwritev(
    fd: c_int,
    iov: *const iovec,
    count: c_int,
    offset: off_t,
) -> ssize_t {
    // SAFETY: `iov` holds `count` iovecs of readable buffers.
    let iovecs = unsafe { Iovecs::new(iov, count) };
    if let Some(r) = dispatch_fs_fd(fd, |fs| {
        writing(&iovecs, |buf, len| unsafe { fs.pwrite(fd, buf, len, offset) })
    }) {
        return finish(r) as ssize_t;
    }
    // SAFETY: PWRITEV holds libc's pwritev.
    unsafe {
        original::<unsafe extern "C" fn(c_int, *const iovec, c_int, off_t) -> ssize_t>(&PWRITEV)(
            fd, iov, count, offset,
        )
    }
}

/// The iovecs of a `preadv2`/`pwritev2`, failed with `EOPNOTSUPP` for flags beyond those the
/// kernel knows (fs/read_write.c `kiocb_set_rw_flags`).
#[cfg(target_os = "linux")]
unsafe fn checked_v2<'a>(iov: *const iovec, count: c_int, flags: c_int) -> Checked<'a> {
    if flags & !RWF_KNOWN != 0 {
        return Err(libc::EOPNOTSUPP);
    }
    // SAFETY: as the caller promises.
    unsafe { Iovecs::new(iov, count) }
}

/// `preadv2(2)` (Linux): [`preadv`] at `offset`, or [`readv`] at the file offset for -1.
/// `RWF_NOWAIT` on a socket reads as `MSG_DONTWAIT` does (net/socket.c `sock_read_iter`); the
/// other flags change nothing a simulated read does.
#[cfg(target_os = "linux")]
unsafe extern "C" fn preadv2(
    fd: c_int,
    iov: *const iovec,
    count: c_int,
    offset: off_t,
    flags: c_int,
) -> ssize_t {
    // SAFETY: `iov` holds `count` iovecs of writable buffers.
    let iovecs = unsafe { checked_v2(iov, count, flags) };
    if let Some(r) = dispatch_fs_fd(fd, |fs| {
        reading(&iovecs, |buf, len| unsafe {
            if offset == -1 {
                fs.read(fd, buf, len)
            } else {
                fs.pread(fd, buf, len, offset)
            }
        })
    }) {
        return finish(r) as ssize_t;
    }
    if offset == -1
        && let Some(r) = domain::dispatch_owned(fd, |net| {
            reading(&iovecs, |buf, len| unsafe {
                if flags & libc::RWF_NOWAIT != 0 {
                    net.recv(fd, buf, len, libc::MSG_DONTWAIT)
                } else {
                    net.read(fd, buf, len)
                }
            })
        })
    {
        return finish(r) as ssize_t;
    }
    type Preadv2Fn = unsafe extern "C" fn(c_int, *const iovec, c_int, off_t, c_int) -> ssize_t;
    // SAFETY: PREADV2 holds libc's preadv2.
    unsafe { original::<Preadv2Fn>(&PREADV2)(fd, iov, count, offset, flags) }
}

/// `pwritev2(2)` (Linux): [`pwritev`] at `offset`, or [`writev`] at the file offset for -1.
/// `RWF_APPEND` writes at the end of the file whatever `offset` says, moving the file offset only
/// for -1 (man 2 pwritev2); `RWF_NOWAIT` on a socket writes as `MSG_DONTWAIT` does. Other flags
/// are as for [`preadv2`].
#[cfg(target_os = "linux")]
unsafe extern "C" fn pwritev2(
    fd: c_int,
    iov: *const iovec,
    count: c_int,
    offset: off_t,
    flags: c_int,
) -> ssize_t {
    // SAFETY: `iov` holds `count` iovecs of readable buffers.
    let iovecs = unsafe { checked_v2(iov, count, flags) };
    if let Some(r) = dispatch_fs_fd(fd, |fs| {
        writing(&iovecs, |buf, len| unsafe {
            if flags & libc::RWF_APPEND != 0 {
                append(fs, fd, buf, len, offset == -1)
            } else if offset == -1 {
                fs.write(fd, buf, len)
            } else {
                fs.pwrite(fd, buf, len, offset)
            }
        })
    }) {
        return finish(r) as ssize_t;
    }
    if offset == -1
        && let Some(r) = domain::dispatch_owned(fd, |net| {
            writing(&iovecs, |buf, len| unsafe {
                if flags & libc::RWF_NOWAIT != 0 {
                    net.send(fd, buf, len, libc::MSG_DONTWAIT)
                } else {
                    net.write(fd, buf, len)
                }
            })
        })
    {
        domain::note_effect("pwritev2");
        return finish(r) as ssize_t;
    }
    type Pwritev2Fn = unsafe extern "C" fn(c_int, *const iovec, c_int, off_t, c_int) -> ssize_t;
    // SAFETY: PWRITEV2 holds libc's pwritev2.
    unsafe { original::<Pwritev2Fn>(&PWRITEV2)(fd, iov, count, offset, flags) }
}

/// Writes `len` bytes at the end of `fd`'s file, leaving the file offset past them when `seek`.
#[cfg(target_os = "linux")]
unsafe fn append(
    fs: &dyn crate::Fs,
    fd: c_int,
    buf: *const u8,
    len: usize,
    seek: bool,
) -> Option<NetResult> {
    if seek {
        if let NetResult::Err(errno) = unsafe { fs.lseek(fd, 0, libc::SEEK_END) }? {
            return Some(NetResult::Err(errno));
        }
        return unsafe { fs.write(fd, buf, len) };
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if let NetResult::Err(errno) = unsafe { fs.fstat(fd, stat.as_mut_ptr().cast()) }? {
        return Some(NetResult::Err(errno));
    }
    // SAFETY: a handled fstat filled the struct.
    let end = unsafe { stat.assume_init() }.st_size;
    unsafe { fs.pwrite(fd, buf, len, end) }
}
