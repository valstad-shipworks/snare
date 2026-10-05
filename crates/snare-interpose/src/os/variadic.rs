//! Naked entry trampolines for the variadic libc functions this crate interposes, on macOS
//! aarch64 only. There the C ABI passes named arguments in registers but every variadic argument
//! on the stack, so a fixed-arity Rust hook would read the first variadic argument from a register
//! the caller never wrote. Each trampoline copies that argument from the top of the stack into the
//! register the fixed-arity implementation expects, then tail-calls it, leaving the named argument
//! registers and the link register untouched.
//!
//! Apple's arm64 ABI assigns each variadic argument to its own 8-byte stack slot(s), unlike AAPCS64
//! which uses the next free register ([Apple: Writing ARM64 code for Apple platforms, "Update code
//! that passes arguments to variadic functions"](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms)).
//! At entry `sp` points at the first variadic slot, so `ldr xN, [sp]` loads it whole; an `int`
//! argument is read from the low 32 bits (`wN`) by the callee. Only the first variadic argument is
//! forwarded, which is all any of these functions takes. The signatures declare only the named
//! arguments, since a naked function's body never reads them.

use std::ffi::{c_char, c_int, c_ulong};

/// `ioctl(fd, request, ...)`: forwards the third argument (the `argp` pointer or integer) in `x2`
/// to [`crate::os::unix::ioctl`].
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn ioctl(fd: c_int, request: c_ulong) -> c_int {
    core::arch::naked_asm!("ldr x2, [sp]", "b {imp}", imp = sym crate::os::unix::ioctl)
}

/// `open(path, flags, ...)`: forwards `mode` in `x2` to `files::open`. When the caller passed no
/// mode (no `O_CREAT`) the slot holds whatever was on the stack; the callee passes it on to the
/// `Fs` backend or the real `open`, which must ignore it, since macOS open(2) requires `mode`
/// only with `O_CREAT`.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn open(path: *const c_char, flags: c_int) -> c_int {
    core::arch::naked_asm!("ldr x2, [sp]", "b {imp}", imp = sym crate::os::files::open)
}

/// `openat(dirfd, path, flags, ...)`: forwards `mode` in `x3` to `files::openat`; an absent mode
/// is garbage the callee ignores, as for [`open`].
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn openat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    core::arch::naked_asm!("ldr x3, [sp]", "b {imp}", imp = sym crate::os::files::openat)
}

/// `fcntl(fd, cmd, ...)`: forwards the third argument in `x2` to `sockets::fcntl`; for commands
/// that take no argument it is stack garbage, passed on to a backend or the real `fcntl`, which
/// ignore it for such commands.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn fcntl(fd: c_int, cmd: c_int) -> c_int {
    core::arch::naked_asm!("ldr x2, [sp]", "b {imp}", imp = sym crate::os::sockets::fcntl)
}
