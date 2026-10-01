#![cfg(unix)]
//! Environment isolation: whether the real process environment is visible to the code under test.
//! `HostProfile::env` / `isolate_env` hide it; a host that configures neither leaves `getenv(3)`
//! reading the real environment. See man 3 getenv.

use std::ffi::CString;

use snare::{HostProfile, Sim};

#[test]
fn isolate_env_with_no_variables_hides_everything() {
    // A variable set on the real machine must not leak into a fully isolated environment.
    let key = CString::new("SNARE_DEMO_LEAK").unwrap();
    let val = CString::new("real").unwrap();
    unsafe { libc::setenv(key.as_ptr(), val.as_ptr(), 1) };

    let host = HostProfile::new().isolate_env().build();
    Sim::builder().host(host).build().run(|| {
        assert!(std::env::var("SNARE_DEMO_LEAK").is_err());
        assert!(std::env::var("PATH").is_err(), "even PATH is absent in an empty isolated env");
    });

    unsafe { libc::unsetenv(key.as_ptr()) };
}

#[test]
fn declaring_a_variable_hides_the_real_one_of_the_same_name() {
    let key = CString::new("SNARE_DEMO_SHADOW").unwrap();
    let val = CString::new("from-machine").unwrap();
    unsafe { libc::setenv(key.as_ptr(), val.as_ptr(), 1) };

    let host = HostProfile::new().env("SNARE_DEMO_SHADOW", "from-sim").build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(std::env::var("SNARE_DEMO_SHADOW").as_deref(), Ok("from-sim"));
    });

    unsafe { libc::unsetenv(key.as_ptr()) };
}

#[test]
fn without_isolation_the_real_environment_shows_through() {
    let key = CString::new("SNARE_DEMO_PASS").unwrap();
    let val = CString::new("present").unwrap();
    unsafe { libc::setenv(key.as_ptr(), val.as_ptr(), 1) };

    // A HostProfile that configures no env leaves getenv on the real environment.
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(std::env::var("SNARE_DEMO_PASS").as_deref(), Ok("present"));
    });

    unsafe { libc::unsetenv(key.as_ptr()) };
}

#[test]
fn a_mutation_inside_an_isolated_env_does_not_touch_the_real_environment() {
    let host = HostProfile::new().isolate_env().build();
    Sim::builder().host(host).build().run(|| {
        unsafe { std::env::set_var("SNARE_DEMO_INSIDE", "sim-only") };
        assert_eq!(std::env::var("SNARE_DEMO_INSIDE").as_deref(), Ok("sim-only"));
    });

    // Outside the sim the variable was never set on the real machine.
    assert!(std::env::var("SNARE_DEMO_INSIDE").is_err());
}
