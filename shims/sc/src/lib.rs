//! A `[patch]` replacement for the [`sc`](https://crates.io/crates/sc) crate that issues each
//! system call through `libc`'s `syscall` symbol instead of an inline `syscall`/`svc`
//! instruction. The public surface — `syscall0`..`syscall7`, `nr::*`, and the `syscall!` macro —
//! matches sc 0.2, so a `[patch.crates-io] sc = { path = ... }` is a drop-in.
//!
//! Why: an import-table interposer (snare) hooks the `syscall` symbol but cannot see an inline
//! instruction. Routing raw syscalls through `libc::syscall` makes them observable and, for the
//! calls the interposer models, redirectable. Every `syscallN` returns the raw kernel value (a
//! negative errno in `-4095..=-1`), exactly as sc's asm does, so callers that decode the result
//! themselves — `io-uring`'s `direct-syscall` path among them — behave unchanged.

#![no_std]

#[cfg(target_arch = "x86_64")]
#[path = "nr_x86_64.rs"]
pub mod nr;
#[cfg(target_arch = "aarch64")]
#[path = "nr_aarch64.rs"]
pub mod nr;

pub use imp::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6, syscall7};

mod imp {
    use core::ffi::c_long;

    /// Turns `libc::syscall`'s `-1`-and-errno convention back into the kernel's own return value,
    /// where an error is the negated errno. A success passes through unchanged.
    #[inline(always)]
    unsafe fn raw(ret: c_long) -> usize {
        if ret == -1 {
            // SAFETY: `__errno_location` is always valid to read on the calling thread.
            let errno = unsafe { *libc::__errno_location() };
            (-(errno as isize)) as usize
        } else {
            ret as usize
        }
    }

    /// # Safety
    /// A system call is inherently unsafe; the caller ensures the number and arguments are valid.
    #[inline(always)]
    pub unsafe fn syscall0(n: usize) -> usize {
        // SAFETY: forwarding to libc's variadic syscall with the argument count the call expects.
        unsafe { raw(libc::syscall(n as c_long)) }
    }

    /// # Safety
    /// See [`syscall0`].
    #[inline(always)]
    pub unsafe fn syscall1(n: usize, a1: usize) -> usize {
        // SAFETY: see `syscall0`.
        unsafe { raw(libc::syscall(n as c_long, a1)) }
    }

    /// # Safety
    /// See [`syscall0`].
    #[inline(always)]
    pub unsafe fn syscall2(n: usize, a1: usize, a2: usize) -> usize {
        // SAFETY: see `syscall0`.
        unsafe { raw(libc::syscall(n as c_long, a1, a2)) }
    }

    /// # Safety
    /// See [`syscall0`].
    #[inline(always)]
    pub unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> usize {
        // SAFETY: see `syscall0`.
        unsafe { raw(libc::syscall(n as c_long, a1, a2, a3)) }
    }

    /// # Safety
    /// See [`syscall0`].
    #[inline(always)]
    pub unsafe fn syscall4(n: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> usize {
        // SAFETY: see `syscall0`.
        unsafe { raw(libc::syscall(n as c_long, a1, a2, a3, a4)) }
    }

    /// # Safety
    /// See [`syscall0`].
    #[inline(always)]
    pub unsafe fn syscall5(
        n: usize,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
        a5: usize,
    ) -> usize {
        // SAFETY: see `syscall0`.
        unsafe { raw(libc::syscall(n as c_long, a1, a2, a3, a4, a5)) }
    }

    /// # Safety
    /// See [`syscall0`].
    #[inline(always)]
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

    /// # Safety
    /// See [`syscall0`]. No Linux syscall takes seven arguments; provided only for source
    /// compatibility with sc's macro.
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn syscall7(
        n: usize,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
        a5: usize,
        a6: usize,
        _a7: usize,
    ) -> usize {
        // SAFETY: see `syscall0`.
        unsafe { raw(libc::syscall(n as c_long, a1, a2, a3, a4, a5, a6)) }
    }
}

/// Issues a system call named by an `nr::` constant, as in `sc::syscall!(READ, fd, buf, len)`.
#[macro_export]
macro_rules! syscall {
    ($nr:ident) => {
        $crate::syscall0($crate::nr::$nr)
    };
    ($nr:ident, $a1:expr) => {
        $crate::syscall1($crate::nr::$nr, $a1 as usize)
    };
    ($nr:ident, $a1:expr, $a2:expr) => {
        $crate::syscall2($crate::nr::$nr, $a1 as usize, $a2 as usize)
    };
    ($nr:ident, $a1:expr, $a2:expr, $a3:expr) => {
        $crate::syscall3($crate::nr::$nr, $a1 as usize, $a2 as usize, $a3 as usize)
    };
    ($nr:ident, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {
        $crate::syscall4(
            $crate::nr::$nr,
            $a1 as usize,
            $a2 as usize,
            $a3 as usize,
            $a4 as usize,
        )
    };
    ($nr:ident, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr) => {
        $crate::syscall5(
            $crate::nr::$nr,
            $a1 as usize,
            $a2 as usize,
            $a3 as usize,
            $a4 as usize,
            $a5 as usize,
        )
    };
    ($nr:ident, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr) => {
        $crate::syscall6(
            $crate::nr::$nr,
            $a1 as usize,
            $a2 as usize,
            $a3 as usize,
            $a4 as usize,
            $a5 as usize,
            $a6 as usize,
        )
    };
    ($nr:ident, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr, $a7:expr) => {
        $crate::syscall7(
            $crate::nr::$nr,
            $a1 as usize,
            $a2 as usize,
            $a3 as usize,
            $a4 as usize,
            $a5 as usize,
            $a6 as usize,
            $a7 as usize,
        )
    };
}
