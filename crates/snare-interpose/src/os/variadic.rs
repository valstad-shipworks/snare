//! Naked entry trampolines for the variadic libc functions this crate interposes, on macOS
//! aarch64 only. There the C ABI passes named arguments in registers but every variadic argument
//! on the stack, so a fixed-arity Rust hook would read the first variadic argument from a register
//! the caller never wrote. Each trampoline copies that argument from the top of the stack into the
//! register the fixed-arity implementation expects, then tail-calls it, leaving the named argument
//! registers and the link register untouched.

use std::ffi::{c_char, c_int, c_ulong};

#[unsafe(naked)]
pub(crate) unsafe extern "C" fn ioctl(fd: c_int, request: c_ulong) -> c_int {
    core::arch::naked_asm!("ldr x2, [sp]", "b {imp}", imp = sym crate::os::unix::ioctl)
}

#[unsafe(naked)]
pub(crate) unsafe extern "C" fn open(path: *const c_char, flags: c_int) -> c_int {
    core::arch::naked_asm!("ldr x2, [sp]", "b {imp}", imp = sym crate::os::files::open)
}

#[unsafe(naked)]
pub(crate) unsafe extern "C" fn openat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    core::arch::naked_asm!("ldr x3, [sp]", "b {imp}", imp = sym crate::os::files::openat)
}

#[unsafe(naked)]
pub(crate) unsafe extern "C" fn fcntl(fd: c_int, cmd: c_int) -> c_int {
    core::arch::naked_asm!("ldr x2, [sp]", "b {imp}", imp = sym crate::os::sockets::fcntl)
}
