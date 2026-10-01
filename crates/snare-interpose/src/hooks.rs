use std::mem;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

/// One OS function this crate interposes on.
pub(crate) struct Hook {
    /// The C symbol name, without the Mach-O leading underscore.
    pub(crate) name: &'static str,
    /// Where to find the function on Windows; unused elsewhere.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) module: &'static str,
    pub(crate) replacement: usize,
    pub(crate) original: &'static AtomicUsize,
    pub(crate) kind: Kind,
}

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

    pub(crate) fn resolved(&self) -> bool {
        self.original.load(Ordering::Acquire) != 0
    }
}

/// Declares one hook: `hook!("clock_gettime", clock_gettime, CLOCK_GETTIME)` for a replacement
/// function `clock_gettime` whose original lives in `static CLOCK_GETTIME: AtomicUsize`.
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
/// `observed!("WSARecv" in "ws2_32.dll", [a, b, c, d, e, f, g])` on Windows, naming one
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

pub(crate) fn all() -> &'static [Hook] {
    static TABLE: OnceLock<Vec<Hook>> = OnceLock::new();
    TABLE.get_or_init(crate::os::hooks)
}

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
