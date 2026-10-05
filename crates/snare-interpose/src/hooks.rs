//! The table of OS functions this crate interposes on, and how a replacement reaches the function
//! it replaced.
//!
//! Each [`Hook`] pairs a symbol name with a replacement and a static slot for the original. The
//! patcher (`crate::patch`) first resolves every hook's original by name (`dlsym`, or
//! `GetProcAddress` on Windows) into its slot, then writes the replacement's address into every
//! import of that name, so a replacement calls through [`original`] to reach the OS. A slot is
//! written once with `Release`, before any patched import can lead to its replacement, and read
//! with `Acquire` thereafter.

use crate::race::RaceCell;
use std::mem;
use std::sync::atomic::{AtomicUsize, Ordering};

/// One OS function this crate interposes on.
pub(crate) struct Hook {
    /// The C symbol name, without the Mach-O leading underscore.
    pub(crate) name: &'static str,
    /// Where to find the function on Windows; unused elsewhere.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) module: &'static str,
    /// The address of this crate's replacement function, written into the import slots.
    pub(crate) replacement: usize,
    /// Where the address of the real function is kept once resolved; 0 until then.
    pub(crate) original: &'static AtomicUsize,
    /// Whether the replacement models the function or only records the call.
    pub(crate) kind: Kind,
}

/// Whether a hook models its function or only observes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Translated into a [`Layer`](crate::Layer) operation.
    Modelled,
    /// Forwarded to the OS untouched; a managed thread's call is recorded as
    /// [`Unmodelled`](crate::Unmodelled).
    Observed,
}

impl Hook {
    /// Marks a hand-written hook that records its call rather than modelling it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn observed(self) -> Self {
        Self {
            kind: Kind::Observed,
            ..self
        }
    }

    /// Whether the original behind this hook has been found, so its replacement may be called.
    pub(crate) fn resolved(&self) -> bool {
        self.original.load(Ordering::Acquire) != 0
    }
}

/// Declares one hook: `hook!("clock_gettime", clock_gettime, CLOCK_GETTIME)` for a replacement
/// function `clock_gettime` whose original lives in `static CLOCK_GETTIME: AtomicUsize`. The
/// four-argument form names the Windows DLL that exports it.
macro_rules! hook {
    ($name:literal, $replacement:path, $original:path) => {
        hook!($name, "", $replacement, $original)
    };
    ($name:literal, $module:literal, $replacement:path, $original:path) => {
        $crate::hooks::Hook {
            name: $name,
            module: $module,
            replacement: $replacement as *const () as usize,
            original: &$original,
            kind: $crate::hooks::Kind::Modelled,
        }
    };
}
pub(crate) use hook;

/// Declares an observed hook: `observed!("connect", [fd, address, length])`, or
/// `observed!("GetQueuedCompletionStatus" in "kernel32.dll", [a, b, c, d, e])` on Windows, naming one
/// placeholder per parameter.
///
/// The forwarder passes every argument, and returns the result, as `usize`. On the 64-bit ABIs
/// this crate supports (SysV x86_64, AAPCS64 on Linux and Windows, Apple ARM64, Windows x64),
/// each integer or pointer argument occupies one register, or one 8-byte stack slot beyond the
/// register arguments, whatever its width. A forwarder with the same parameter count therefore
/// hands the original exactly what its caller passed, provided every parameter is an integer or
/// a pointer. Apple ARM64 packs stack arguments by size, so functions listed there take at most
/// 8 parameters, and variadic functions are listed only where their variadic arguments travel
/// like named ones.
///
/// Sources: System V AMD64 psABI §3.2.3 "Parameter Passing" (six integer registers, eightbyte
/// stack slots); Arm IHI 0055 AAPCS64 §6.8 "Parameter passing" (x0–x7; rule C.16 widens a stack
/// argument under 8 bytes to 8);
/// ([Microsoft Learn: x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention))
/// (four register arguments, 8-byte stack slots);
/// ([Microsoft Learn: Overview of ARM64 ABI conventions](https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions));
/// ([Apple: Writing ARM64 code for Apple platforms](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms))
/// (stack arguments packed by natural alignment, every variadic argument on the stack).
macro_rules! observed {
    ($name:literal $(in $module:literal)?, [$($arg:ident),*]) => {{
        static ORIGINAL: ::std::sync::atomic::AtomicUsize = ::std::sync::atomic::AtomicUsize::new(0);
        unsafe extern "system" fn forward($($arg: usize),*) -> usize {
            $crate::domain::observe($name, None);
            // SAFETY: ORIGINAL holds the OS function; see the macro's ABI note.
            unsafe {
                $crate::hooks::original::<unsafe extern "system" fn($($crate::hooks::observed!(@usize $arg)),*) -> usize>(
                    &ORIGINAL,
                )($($arg),*)
            }
        }
        $crate::hooks::Hook {
            name: $name,
            module: $crate::hooks::observed!(@module $($module)?),
            replacement: forward as *const () as usize,
            original: &ORIGINAL,
            kind: $crate::hooks::Kind::Observed,
        }
    }};
    (@usize $arg:ident) => { usize };
    (@module) => { "" };
    (@module $module:literal) => { $module };
}
pub(crate) use observed;

/// Every hook for this target, built once from [`crate::os::hooks`].
pub(crate) fn all() -> &'static [Hook] {
    static TABLE: RaceCell<Vec<Hook>> = RaceCell::new();
    TABLE.get_or_init(crate::os::hooks).0
}

/// The hook for the C symbol `name` (no Mach-O underscore), if this crate interposes on it.
pub(crate) fn find(name: &[u8]) -> Option<&'static Hook> {
    all().iter().find(|h| h.name.as_bytes() == name)
}

/// The original function behind `slot`, as a function pointer of type `F`.
///
/// # Safety
/// `slot` must hold a resolved original whose real signature is `F`.
pub(crate) unsafe fn original<F: Copy>(slot: &AtomicUsize) -> F {
    const { assert!(mem::size_of::<F>() == mem::size_of::<usize>()) };
    let address = slot.load(Ordering::Acquire);
    debug_assert_ne!(address, 0, "hook called before its original was resolved");
    // SAFETY: the caller guarantees `F` is the function pointer type stored in `slot`.
    unsafe { mem::transmute_copy(&address) }
}
