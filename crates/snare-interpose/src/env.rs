//! A per-domain environment backend. When a domain has one, the `getenv`/`setenv`/`unsetenv`
//! hooks serve the calling thread's process environment from it instead of the real one — so a
//! test sees a deterministic, isolated environment (and Rust's `std::env::var`, which calls
//! `libc::getenv`, reads it). A `None` backend leaves the calls to the real OS environment.

use core::ffi::{c_char, c_int};

#[allow(unused_variables, clippy::missing_safety_doc)]
pub trait Env: Send + Sync + 'static {
    /// `getenv(name)`: the value as a NUL-terminated C string that stays valid until the next
    /// environment mutation on this backend, or null when the variable is unset. A backend that is
    /// present answers every read (the simulated environment is authoritative — the real one is
    /// never consulted for a managed thread).
    ///
    /// Models `getenv(3)` (POSIX). The returned pointer aliases storage the next `setenv(3)`/
    /// `unsetenv(3)` may invalidate, exactly as the C library warns.
    ///
    /// # Safety
    /// `name` is the caller's NUL-terminated variable name.
    unsafe fn getenv(&self, name: *const c_char) -> *mut c_char;

    /// `setenv(name, value, overwrite)`: `0` on success, `-1` with errno on error.
    ///
    /// Models `setenv(3)`; a zero `overwrite` leaves an existing variable unchanged.
    ///
    /// # Safety
    /// `name`/`value` are the caller's C strings.
    unsafe fn setenv(&self, name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int {
        0
    }

    /// `unsetenv(name)`: `0` on success.
    ///
    /// Models `unsetenv(3)`.
    ///
    /// # Safety
    /// `name` is the caller's C string.
    unsafe fn unsetenv(&self, name: *const c_char) -> c_int {
        0
    }
}
