#![cfg(unix)]
//! Mutating the simulated environment at runtime: `setenv(3)` (including the `overwrite == 0`
//! rule), `unsetenv(3)`, and the round-trip through Rust's `std::env::set_var` / `remove_var`,
//! which call those same libc entry points. See man 3 setenv, man 3 getenv.

use std::ffi::CString;

use snare::{HostProfile, Sim};

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[test]
fn setenv_then_getenv_roundtrips() {
    let host = HostProfile::new().isolate_env().build();
    Sim::builder().host(host).build().run(|| {
        let k = cstr("RUNTIME");
        let v = cstr("value");
        // man 3 setenv: overwrite != 0 sets (or replaces) the variable and returns 0.
        assert_eq!(unsafe { libc::setenv(k.as_ptr(), v.as_ptr(), 1) }, 0);
        assert_eq!(std::env::var("RUNTIME").as_deref(), Ok("value"));
    });
}

#[test]
fn setenv_with_overwrite_zero_keeps_an_existing_value() {
    let host = HostProfile::new().env("KEEP", "original").build();
    Sim::builder().host(host).build().run(|| {
        let k = cstr("KEEP");
        let v = cstr("replacement");
        // man 3 setenv: with overwrite == 0 an already-present variable is left unchanged and the
        // call still succeeds.
        assert_eq!(unsafe { libc::setenv(k.as_ptr(), v.as_ptr(), 0) }, 0);
        assert_eq!(std::env::var("KEEP").as_deref(), Ok("original"));
    });
}

#[test]
fn setenv_with_overwrite_zero_still_creates_a_new_variable() {
    let host = HostProfile::new().isolate_env().build();
    Sim::builder().host(host).build().run(|| {
        let k = cstr("FRESH");
        let v = cstr("made");
        // overwrite == 0 only protects an existing key; a new one is created regardless.
        assert_eq!(unsafe { libc::setenv(k.as_ptr(), v.as_ptr(), 0) }, 0);
        assert_eq!(std::env::var("FRESH").as_deref(), Ok("made"));
    });
}

#[test]
fn overwrite_nonzero_replaces_an_existing_value() {
    let host = HostProfile::new().env("K", "old").build();
    Sim::builder().host(host).build().run(|| {
        let k = cstr("K");
        let v = cstr("new");
        assert_eq!(unsafe { libc::setenv(k.as_ptr(), v.as_ptr(), 1) }, 0);
        assert_eq!(std::env::var("K").as_deref(), Ok("new"));
    });
}

#[test]
fn unsetenv_removes_a_variable() {
    let host = HostProfile::new().env("GONE", "soon").build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(std::env::var("GONE").as_deref(), Ok("soon"));
        let k = cstr("GONE");
        // man 3 setenv (unsetenv): removes the variable; a later getenv returns NULL.
        assert_eq!(unsafe { libc::unsetenv(k.as_ptr()) }, 0);
        assert!(std::env::var("GONE").is_err());
    });
}

#[test]
fn std_set_var_and_remove_var_route_through_the_sim() {
    let host = HostProfile::new().env("SEED", "1").build();
    Sim::builder().host(host).build().run(|| {
        // std::env::set_var is setenv(3) and remove_var is unsetenv(3); both hit the simulated
        // environment, so a following std::env::var observes the change.
        unsafe { std::env::set_var("VIA_STD", "yes") };
        assert_eq!(std::env::var("VIA_STD").as_deref(), Ok("yes"));

        unsafe { std::env::remove_var("SEED") };
        assert!(std::env::var("SEED").is_err());
    });
}

#[test]
fn a_variable_can_be_removed_then_set_again() {
    let host = HostProfile::new().env("CYCLE", "a").build();
    Sim::builder().host(host).build().run(|| {
        unsafe { std::env::remove_var("CYCLE") };
        assert!(std::env::var("CYCLE").is_err());
        unsafe { std::env::set_var("CYCLE", "b") };
        assert_eq!(std::env::var("CYCLE").as_deref(), Ok("b"));
    });
}

#[test]
fn a_null_name_to_setenv_fails() {
    let host = HostProfile::new().isolate_env().build();
    Sim::builder().host(host).build().run(|| {
        let v = cstr("x");
        // The sim rejects a NULL name rather than dereferencing it across the FFI boundary.
        assert_eq!(unsafe { libc::setenv(std::ptr::null(), v.as_ptr(), 1) }, -1);
    });
}
