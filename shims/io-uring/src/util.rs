use std::num::NonZeroU32;
use std::os::unix::io::AsRawFd;
use std::sync::atomic;
use std::{io, ptr};

pub(crate) mod private {
    /// Private trait that we use as a supertrait of `EntryMarker` to prevent it from being
    /// implemented from outside this crate.
    ///
    /// See this [blog](https://jack.wrenn.fyi/blog/private-trait-methods/) for more details.
    pub trait Sealed {}
}

/// A region of memory mapped using `mmap(2)`.
pub(crate) struct Mmap {
    addr: ptr::NonNull<libc::c_void>,
    #[allow(dead_code)]
    len: usize,
}

impl Mmap {
    /// Map `len` bytes starting from the offset `offset` in the file descriptor `fd` into memory.
    pub fn new(fd: &OwnedFd, offset: libc::off_t, len: usize) -> io::Result<Mmap> {
        // The ring is backed by process memory the emulator owns, not a kernel mapping; hand back
        // a pointer into it for this offset. The memory outlives every `Mmap` (the emulator keeps
        // it), so `Drop` does nothing.
        let addr = crate::emu::map(fd.as_raw_fd(), offset as i64)?;
        let addr = ptr::NonNull::new(addr).ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        Ok(Mmap { addr, len })
    }

    /// Do not make the stored memory accessible by child processes after a `fork`.
    pub fn dontfork(&self) -> io::Result<()> {
        // The ring is ordinary heap memory here; nothing to advise the kernel about.
        Ok(())
    }

    /// Get a pointer to the memory.
    #[inline]
    pub fn as_mut_ptr(&self) -> *mut libc::c_void {
        self.addr.as_ptr()
    }

    /// Get a pointer to the data at the given offset.
    #[inline]
    pub unsafe fn offset(&self, offset: u32) -> *mut libc::c_void {
        self.as_mut_ptr().add(offset as usize)
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        // The emulator owns the backing memory; nothing to unmap.
    }
}

pub use fd::OwnedFd;

#[cfg(feature = "io_safety")]
mod fd {
    pub use std::os::unix::io::OwnedFd;
}

#[cfg(not(feature = "io_safety"))]
mod fd {
    use std::mem;
    use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

    /// API-compatible with the `OwnedFd` type in the Rust stdlib.
    pub struct OwnedFd(RawFd);

    impl AsRawFd for OwnedFd {
        #[inline]
        fn as_raw_fd(&self) -> RawFd {
            self.0
        }
    }

    impl IntoRawFd for OwnedFd {
        #[inline]
        fn into_raw_fd(self) -> RawFd {
            let fd = self.0;
            mem::forget(self);
            fd
        }
    }

    impl FromRawFd for OwnedFd {
        #[inline]
        unsafe fn from_raw_fd(fd: RawFd) -> OwnedFd {
            OwnedFd(fd)
        }
    }

    impl Drop for OwnedFd {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

#[inline(always)]
pub(crate) unsafe fn unsync_load(u: *const atomic::AtomicU32) -> u32 {
    *u.cast::<u32>()
}

#[inline]
pub(crate) const fn cast_ptr<T>(n: &T) -> *const T {
    n
}

/// Convert a valid `u32` constant.
///
/// This is a workaround for the lack of panic-in-const in older
/// toolchains.
#[allow(unconditional_panic, clippy::out_of_bounds_indexing)]
pub(crate) const fn unwrap_u32(t: Option<u32>) -> u32 {
    match t {
        Some(v) => v,
        None => [][1],
    }
}

/// Convert a valid `NonZeroU32` constant.
///
/// This is a workaround for the lack of panic-in-const in older
/// toolchains.
#[allow(unconditional_panic, clippy::out_of_bounds_indexing)]
pub(crate) const fn unwrap_nonzero(t: Option<NonZeroU32>) -> NonZeroU32 {
    match t {
        Some(v) => v,
        None => [][1],
    }
}
