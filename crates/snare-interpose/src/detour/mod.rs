//! Function detouring (inline hooking) at runtime.
//!
//! Derived from [detour](https://github.com/darfink/detour-rs) 0.10.0 by
//! Elliott Linder, under the BSD-2-Clause license (see `LICENSE` next to this
//! file), and narrowed to Windows on x86, x86-64 and AArch64. It differs from
//! that release as follows:
//!
//! - Windows all-thread suspension propagates failures for live threads; only
//!   verified thread exits are skipped. Handles are checked against the owning
//!   process.
//! - Typed hooks can resolve transparent direct tail-jump chains
//!   ([`resolve_tail_target`]) before selecting the implementation address.
//! - `validate_suspended_install` rejects calls with saved return addresses
//!   inside the exact overwritten span. Decoder tests cover the patch
//!   boundary.
//! - Generated call methods permit arbitrary argument counts under Clippy.
//!
//! The Rust sleep hook uses a [`TypedDetour`], which remains allocated for the
//! process lifetime.
//!
//! A detour redirects a function (the *target*) to another function or
//! closure (the *detour*). The first instructions of the target are replaced
//! with a jump to the detour, and copied to a *trampoline*, through which the
//! original function remains callable.
//!
//! # Detours
//!
//! - [`static_detour!`]: defines a static, type-safe detour, which accepts a
//!   closure as its detour. Any signature is supported, including references.
//! - [`TypedDetour`]: a type-safe detour created at runtime, whose detour is a
//!   function with the same signature as the target. Signatures with
//!   references are named with [`signature!`] first.
//! - [`RawDetour`]: an untyped detour of raw pointers, e.g. for functions whose
//!   signature is only known at runtime.
//!
//! # Thread safety
//!
//! `enable` and `disable` do not suspend other threads. A thread executing
//! the target's first instructions whilst they are replaced may resume in the
//! middle of the new jump, so doing so is undefined behavior.
//!
//! A [`Transaction`] enables and disables several detours at once, applied
//! completely or not at all, whilst the chosen [`Threads`] are suspended. A
//! suspended thread stopped within the replaced instructions has its
//! instruction pointer moved to the same instruction in the trampoline
//! (known as *EIP relocation*). See [`Transaction::commit`] for the
//! limitations.
//!
//! # How it works
//!
//! To illustrate a detour on x86:
//!
//! ```c
//! int return_five() {
//!     return 5;
//! 00400020 [b8 05 00 00 00] mov eax, 5
//! 00400025 [c3]             ret
//! }
//!
//! int detour_function() {
//!     return 10;
//! 00400040 [b8 0a 00 00 00] mov eax, 10
//! 00400045 [c3]             ret
//! }
//! ```
//!
//! The target's first instructions are disassembled, and relocated to a
//! trampoline allocated near the target, followed by a jump back to the rest
//! of the function. They are then replaced with a jump to the detour:
//!
//! ```c
//! int return_five() {
//!     return detour_function();
//! 00400020 [e9 1b 00 00 00] jmp 00400040 <detour_function>
//! 00400025 [c3]             ret
//! }
//! ```
//!
//! Relocation handles relative branches (including branches within the
//! replaced instructions), RIP-relative operands (x86-64) and all PC-relative
//! instructions (AArch64). If the detour is out of reach of a relative jump
//! (beyond ±2 GiB on x86-64, or ±128 MiB on AArch64), the jump leads to a
//! *relay*, an absolute jump allocated near the target. Functions too small
//! for the jump are supported if they are followed by padding, or preceded by
//! a hot-patching area. On AArch64, BTI and PAC landing pads are preserved.
//!
//! # Caveats
//!
//! - Only calls that reach the target are detoured; inlined calls are not.
//!   Mark your own targets `#[inline(never)]`. Calls to a function of the
//!   same crate may also be optimized in other ways (e.g. an unused argument
//!   may not be passed at all), so the detour must not rely on more than the
//!   target does.
//! - A dropped detour is disabled without suspending threads, and its
//!   trampoline is released immediately. Disable it with a [`Transaction`]
//!   first if other threads may be executing the target or the trampoline.
//! - Multiple detours of the same target must be disabled in the reverse order
//!   they were enabled in; otherwise [`Error::TargetModified`] is returned.

#![allow(dead_code, unused_imports, unused_macros)]

#[macro_use]
mod macros;

mod arch;
mod detours;
mod error;
mod hook;
mod memory;
mod sync;
mod thread;
mod traits;
mod transaction;

pub use detours::*;
pub use error::{Error, OsError, Result};
pub(crate) use macros::{__cfg_attrs, __signature, signature, static_detour};
pub use thread::{Thread, Threads};
pub use traits::{Function, HookableWith};
pub use transaction::{Detour, Transaction};

/// Implementation details of the macros.
#[doc(hidden)]
pub mod __private {
    pub use super::detours::statik::{StaticDetour, StaticHandle};
    pub use super::traits::private::Sealed;
}

/// Resolves a chain of initial direct tail jumps, including transparent landing pads.
///
/// State-changing prologues and indirect jumps are left intact. Cycles and chains longer
/// than eight jumps are rejected.
///
/// # Safety
///
/// `target` must remain valid and its code must not be modified concurrently. Each followed
/// destination must preserve the function's declared calling convention and arguments.
pub unsafe fn resolve_tail_target<T: Function>(target: T) -> Result<T> {
    let _lock = memory::patch_lock();
    let mut address = target.to_ptr() as usize;
    let mut visited = [0usize; 9];
    for index in 0..visited.len() {
        if visited[..index].contains(&address) {
            return Err(Error::UnsupportedInstruction);
        }
        if !memory::is_executable(address as *const ())? {
            return Err(Error::NotExecutable);
        }
        visited[index] = address;
        // SAFETY: The target is valid and each branch is inspected before it is followed.
        match unsafe { arch::initial_tail_jump(address)? } {
            None => {
                // SAFETY: The caller guarantees compatible calling conventions along the chain.
                return Ok(unsafe { T::from_ptr(address as *const ()) });
            }
            Some(next) => address = next,
        }
    }
    Err(Error::UnsupportedInstruction)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[unsafe(naked)]
    extern "C" fn tail_body() -> i32 {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        core::arch::naked_asm!("mov eax, 7", "ret");
        #[cfg(target_arch = "aarch64")]
        core::arch::naked_asm!("mov w0, #7", "ret");
    }

    macro_rules! tail_thunk {
    ($name:ident, $next:ident) => {
      #[unsafe(naked)]
      extern "C" fn $name() -> i32 {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        core::arch::naked_asm!("jmp {next}", next = sym $next);
        #[cfg(target_arch = "aarch64")]
        core::arch::naked_asm!("b {next}", next = sym $next);
      }
    };
  }
    tail_thunk!(tail1, tail_body);
    tail_thunk!(tail2, tail1);
    tail_thunk!(tail3, tail2);
    tail_thunk!(tail4, tail3);
    tail_thunk!(tail5, tail4);
    tail_thunk!(tail6, tail5);
    tail_thunk!(tail7, tail6);
    tail_thunk!(tail8, tail7);
    tail_thunk!(tail9, tail8);

    #[unsafe(naked)]
    extern "C" fn landing_tail() -> i32 {
        #[cfg(target_arch = "x86_64")]
        core::arch::naked_asm!(".byte 0xf3, 0x0f, 0x1e, 0xfa", "jmp {next}", next = sym tail_body);
        #[cfg(target_arch = "x86")]
        core::arch::naked_asm!(".byte 0xf3, 0x0f, 0x1e, 0xfb", "jmp {next}", next = sym tail_body);
        #[cfg(target_arch = "aarch64")]
        core::arch::naked_asm!(".inst 0xd503245f", "b {next}", next = sym tail_body);
    }

    #[unsafe(naked)]
    extern "C" fn stateful_tail() -> i32 {
        #[cfg(target_arch = "x86")]
        core::arch::naked_asm!("push eax", "pop eax", "jmp {next}", next = sym tail_body);
        #[cfg(target_arch = "x86_64")]
        core::arch::naked_asm!("push rax", "pop rax", "jmp {next}", next = sym tail_body);
        #[cfg(target_arch = "aarch64")]
        core::arch::naked_asm!(".inst 0xd503237f", ".inst 0xd50323ff", "b {next}", next = sym tail_body);
    }

    #[unsafe(naked)]
    extern "C" fn cyclic_tail() -> i32 {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        core::arch::naked_asm!("2:", "jmp 2b");
        #[cfg(target_arch = "aarch64")]
        core::arch::naked_asm!("2:", "b 2b");
    }

    #[test]
    fn resolves_only_transparent_tail_chains() -> Result<()> {
        for target in [tail1, tail8, landing_tail] {
            // SAFETY: Every thunk preserves this function's calling convention and arguments.
            let resolved = unsafe { resolve_tail_target(target as extern "C" fn() -> i32)? };
            assert_eq!(resolved as usize, tail_body as *const () as usize);
            assert_eq!(resolved(), 7);
        }
        // SAFETY: The valid function remains untouched at its state-changing prologue.
        let resolved = unsafe { resolve_tail_target(stateful_tail as extern "C" fn() -> i32)? };
        assert_eq!(resolved as usize, stateful_tail as *const () as usize);
        for target in [tail9, cyclic_tail] {
            // SAFETY: All inspected destinations have this function's calling convention.
            let result = unsafe { resolve_tail_target(target as extern "C" fn() -> i32) };
            assert!(matches!(result, Err(Error::UnsupportedInstruction)));
        }
        Ok(())
    }

    #[test]
    fn detours_share_target() -> Result<()> {
        #[inline(never)]
        extern "C" fn add(x: i32, y: i32) -> i32 {
            std::hint::black_box(x) + y + std::hint::black_box(0) * line!() as i32
        }

        extern "C" fn sub(x: i32, y: i32) -> i32 {
            x - y
        }

        extern "C" fn div(x: i32, y: i32) -> i32 {
            x / y
        }

        // SAFETY: The functions share the same signature.
        let hook1 = unsafe { TypedDetour::<extern "C" fn(i32, i32) -> i32>::new(add, sub)? };
        // SAFETY: No other thread is executing `add`.
        unsafe { hook1.enable()? };
        assert_eq!(add(5, 5), 0);

        // SAFETY: The functions share the same signature.
        let hook2 = unsafe { TypedDetour::<extern "C" fn(i32, i32) -> i32>::new(add, div)? };
        // SAFETY: No other thread is executing `add`.
        unsafe { hook2.enable()? };

        // This will call the previous hook's detour
        assert_eq!(hook2.call(5, 5), 0);
        assert_eq!(add(10, 5), 2);

        // The first hook cannot be disabled before the second
        // SAFETY: No other thread is executing `add`.
        let result = unsafe { hook1.disable() };
        assert!(matches!(result, Err(Error::TargetModified)));
        // SAFETY: No other thread is executing `add`.
        unsafe {
            hook2.disable()?;
            hook1.disable()?;
        }
        assert_eq!(add(10, 5), 15);
        Ok(())
    }

    #[test]
    fn same_detour_and_target() {
        #[inline(never)]
        extern "C" fn add(x: i32, y: i32) -> i32 {
            std::hint::black_box(x) + y + std::hint::black_box(0) * line!() as i32
        }

        // SAFETY: The detour is never enabled.
        let error = unsafe { RawDetour::new(add as *const (), add as *const ()) }.unwrap_err();
        assert!(matches!(error, Error::SameAddress));
    }

    #[test]
    fn non_executable_target() {
        let data = [0x90u8; 16];
        extern "C" fn detour() {}

        // SAFETY: The detour is never enabled.
        let error =
            unsafe { RawDetour::new(data.as_ptr().cast(), detour as *const ()) }.unwrap_err();
        assert!(matches!(error, Error::NotExecutable));
    }
}

#[cfg(test)]
mod scenarios;
