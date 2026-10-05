//! Raw syscall entry points, rewritten to route through `libc`'s `syscall` symbol so an
//! import-table interposer (snare) can observe every call. Each function returns the kernel's own
//! value — a negative errno in `-4095..=-1` on failure — exactly as the original inline-asm
//! versions did, so `Errno::from_ret` and every other caller behave unchanged.

use core::ffi::c_long;

#[inline(always)]
unsafe fn raw(ret: c_long) -> usize {
    if ret == -1 {
        // SAFETY: valid to read on the calling thread.
        let errno = unsafe { *libc::__errno_location() };
        (-(errno as isize)) as usize
    } else {
        ret as usize
    }
}

/// # Safety
/// A system call is inherently unsafe; the caller ensures the number and arguments are valid.
#[inline]
pub unsafe fn syscall0(n: usize) -> usize {
    // SAFETY: forwarding to libc's variadic syscall with the expected argument count.
    unsafe { raw(libc::syscall(n as c_long)) }
}

/// # Safety
/// See [`syscall0`].
#[inline]
pub unsafe fn syscall1(n: usize, a1: usize) -> usize {
    // SAFETY: see `syscall0`.
    unsafe { raw(libc::syscall(n as c_long, a1)) }
}

/// # Safety
/// See [`syscall0`].
#[inline]
pub unsafe fn syscall2(n: usize, a1: usize, a2: usize) -> usize {
    // SAFETY: see `syscall0`.
    unsafe { raw(libc::syscall(n as c_long, a1, a2)) }
}

/// # Safety
/// See [`syscall0`].
#[inline]
pub unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> usize {
    // SAFETY: see `syscall0`.
    unsafe { raw(libc::syscall(n as c_long, a1, a2, a3)) }
}

/// # Safety
/// See [`syscall0`].
#[inline]
pub unsafe fn syscall4(n: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> usize {
    // SAFETY: see `syscall0`.
    unsafe { raw(libc::syscall(n as c_long, a1, a2, a3, a4)) }
}

/// # Safety
/// See [`syscall0`].
#[inline]
pub unsafe fn syscall5(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> usize {
    // SAFETY: see `syscall0`.
    unsafe { raw(libc::syscall(n as c_long, a1, a2, a3, a4, a5)) }
}

/// # Safety
/// See [`syscall0`].
#[inline]
#[allow(clippy::too_many_arguments)]
pub unsafe fn syscall6(
    n: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> usize {
    // SAFETY: see `syscall0`.
    unsafe { raw(libc::syscall(n as c_long, a1, a2, a3, a4, a5, a6)) }
}
