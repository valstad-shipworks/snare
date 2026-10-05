#![cfg(unix)]
//! Reading the simulated process environment. `HostProfile::env` declares variables the code under
//! test reads with `std::env::var` (which calls `getenv(3)`); declaring any variable isolates the
//! environment, so the real one is invisible. See man 3 getenv.

use snare::{HostProfile, Sim};

#[test]
fn a_declared_variable_is_readable() {
    let host = HostProfile::new().env("APP_MODE", "test").build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(std::env::var("APP_MODE").as_deref(), Ok("test"));
    });
}

#[test]
fn several_variables_coexist() {
    let host = HostProfile::new()
        .env("PATH", "/sim/bin")
        .env("HOME", "/sim/home")
        .env("LANG", "C.UTF-8")
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(std::env::var("PATH").as_deref(), Ok("/sim/bin"));
        assert_eq!(std::env::var("HOME").as_deref(), Ok("/sim/home"));
        assert_eq!(std::env::var("LANG").as_deref(), Ok("C.UTF-8"));
    });
}

#[test]
fn an_unset_variable_reads_as_not_present() {
    let host = HostProfile::new().env("ONLY", "1").build();
    Sim::builder().host(host).build().run(|| {
        // man 3 getenv: a variable that is not in the environment returns NULL, which std surfaces
        // as VarError::NotPresent.
        assert_eq!(
            std::env::var("MISSING"),
            Err(std::env::VarError::NotPresent)
        );
    });
}

#[test]
fn an_empty_value_is_present_and_distinct_from_absent() {
    let host = HostProfile::new().env("EMPTY", "").build();
    Sim::builder().host(host).build().run(|| {
        // An empty string is a set variable (getenv returns a pointer to ""), not an absent one.
        assert_eq!(std::env::var("EMPTY").as_deref(), Ok(""));
        assert!(std::env::var("NEVER_SET").is_err());
    });
}

#[test]
fn the_last_declaration_of_a_key_wins() {
    let host = HostProfile::new()
        .env("K", "first")
        .env("K", "second")
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(std::env::var("K").as_deref(), Ok("second"));
    });
}

#[test]
fn values_may_contain_equals_and_colons() {
    let host = HostProfile::new()
        .env("CONN", "host=db;port=5432")
        .env("PATH", "/a:/b:/c")
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(std::env::var("CONN").as_deref(), Ok("host=db;port=5432"));
        assert_eq!(
            std::env::var("PATH")
                .unwrap()
                .split(':')
                .collect::<Vec<_>>(),
            vec!["/a", "/b", "/c"]
        );
    });
}

#[test]
fn var_os_also_reads_the_simulated_environment() {
    let host = HostProfile::new().env("UNICODE", "café").build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(
            std::env::var_os("UNICODE").as_deref(),
            Some("café".as_ref())
        );
    });
}
