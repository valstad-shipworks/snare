#![cfg(unix)]
//! Edge cases of the isolated environment (`HostProfile::env` / `isolate_env`), pinned exactly
//! ahead of a performance pass: an empty value against an unset one, a later duplicate in the
//! profile winning, case, non-UTF-8 values, `getenv` handing out the same pointer until a
//! mutation, names the host's `setenv` refuses, isolation between sims and from the real process,
//! persistence across runs, which threads see which environment (spawned, unmanaged, under
//! `snare::real`), and an unisolated sim writing through to the real environment. Iterating the
//! environment is served through `_NSGetEnviron` on macOS; Linux reads `environ` directly.

use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;

use snare::{HostProfile, Sim};

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn isolated() -> Sim {
    Sim::builder()
        .host(HostProfile::new().isolate_env().build())
        .build()
}

fn with_env(pairs: &[(&str, &str)]) -> Sim {
    let mut profile = HostProfile::new();
    for (k, v) in pairs {
        profile = profile.env(*k, *v);
    }
    Sim::builder().host(profile.build()).build()
}

fn setenv(name: &str, value: &str, overwrite: i32) -> (i32, i32) {
    let (k, v) = (cstr(name), cstr(value));
    let r = unsafe { libc::setenv(k.as_ptr(), v.as_ptr(), overwrite) };
    (r, if r == 0 { 0 } else { errno() })
}

fn getenv(name: &str) -> Option<Vec<u8>> {
    let k = cstr(name);
    let p = unsafe { libc::getenv(k.as_ptr()) };
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

#[test]
fn an_empty_value_is_set_and_unset_is_absent() {
    isolated().run(|| {
        assert_eq!(setenv("EMPTY", "", 1), (0, 0));
        assert_eq!(std::env::var("EMPTY").as_deref(), Ok(""));
        assert_eq!(getenv("EMPTY"), Some(Vec::new()));
        assert_eq!(setenv("EMPTY", "ignored", 0), (0, 0));
        assert_eq!(
            std::env::var("EMPTY").as_deref(),
            Ok(""),
            "overwrite 0 keeps an empty value"
        );
        assert_eq!(unsafe { libc::unsetenv(cstr("EMPTY").as_ptr()) }, 0);
        assert_eq!(std::env::var("EMPTY"), Err(std::env::VarError::NotPresent));
        assert_eq!(unsafe { libc::unsetenv(cstr("NEVER_SET").as_ptr()) }, 0);
    });
}

#[test]
fn a_later_duplicate_in_the_profile_wins() {
    with_env(&[("DUP", "first"), ("OTHER", "x"), ("DUP", "second")]).run(|| {
        assert_eq!(std::env::var("DUP").as_deref(), Ok("second"));
        assert_eq!(std::env::var("OTHER").as_deref(), Ok("x"));
    });
}

#[test]
fn names_are_case_sensitive() {
    with_env(&[("PATH", "/sim/bin")]).run(|| {
        assert_eq!(std::env::var("PATH").as_deref(), Ok("/sim/bin"));
        assert!(std::env::var("Path").is_err());
        assert!(std::env::var("path").is_err());
    });
}

#[test]
fn a_non_utf8_value_round_trips_as_bytes() {
    isolated().run(|| {
        let k = cstr("BYTES");
        let v = CString::new(b"a\xffb".to_vec()).unwrap();
        assert_eq!(unsafe { libc::setenv(k.as_ptr(), v.as_ptr(), 1) }, 0);
        assert!(matches!(
            std::env::var("BYTES"),
            Err(std::env::VarError::NotUnicode(_))
        ));
        assert_eq!(
            std::env::var_os("BYTES").unwrap(),
            OsStr::from_bytes(b"a\xffb")
        );
    });
}

#[test]
fn getenv_hands_out_one_pointer_until_the_variable_changes() {
    with_env(&[("STABLE", "v")]).run(|| {
        let k = cstr("STABLE");
        let a = unsafe { libc::getenv(k.as_ptr()) };
        let b = unsafe { libc::getenv(k.as_ptr()) };
        assert!(!a.is_null());
        assert_eq!(a, b);
        assert_eq!(setenv("UNRELATED", "u", 1), (0, 0));
        assert_eq!(
            unsafe { libc::getenv(k.as_ptr()) },
            a,
            "another variable's change keeps it"
        );
        assert_eq!(setenv("STABLE", "w", 1), (0, 0));
        assert_eq!(getenv("STABLE"), Some(b"w".to_vec()));
        assert!(unsafe { libc::getenv(std::ptr::null()) }.is_null());
    });
}

#[test]
fn invalid_environment_names_are_rejected() {
    isolated().run(|| {
        assert_eq!(setenv("A=B", "v", 1), (-1, libc::EINVAL));
        assert_eq!(setenv("", "v", 1), (-1, libc::EINVAL));
        for name in ["", "A=B"] {
            assert_eq!(unsafe { libc::unsetenv(cstr(name).as_ptr()) }, -1);
            assert_eq!(errno(), libc::EINVAL);
        }
    });
}

#[test]
fn names_the_host_refuses_os_truth() {
    let real = snare::real(|| (setenv("A=B", "v", 1), setenv("", "v", 1)));
    assert_eq!(real, ((-1, libc::EINVAL), (-1, libc::EINVAL)));
    let got = isolated().run(|| (setenv("A=B", "v", 1), setenv("", "v", 1)));
    assert_eq!(got, real);
}

#[test]
#[cfg_attr(
    target_os = "linux",
    ignore = "bug: Linux environ is a directly accessed process-global variable"
)]
fn iterating_an_isolated_environment_lists_only_its_variables() {
    let got = with_env(&[("B_VAR", "2"), ("A_VAR", "1")]).run(|| {
        unsafe { std::env::set_var("C_VAR", "3") };
        let mut vars: Vec<(String, String)> = std::env::vars().collect();
        vars.sort();
        vars
    });
    assert_eq!(got.len(), 3, "{} variables listed", got.len());
    assert_eq!(
        got,
        [("A_VAR", "1"), ("B_VAR", "2"), ("C_VAR", "3")]
            .map(|(k, v)| (k.to_string(), v.to_string()))
    );
}

#[test]
fn two_sims_keep_their_own_environments() {
    let a = with_env(&[("WHO", "a")]);
    let b = with_env(&[("WHO", "b")]);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            a.run(|| {
                unsafe { std::env::set_var("ONLY_A", "1") };
                assert_eq!(std::env::var("WHO").as_deref(), Ok("a"));
            })
        });
        scope.spawn(|| {
            b.run(|| {
                unsafe { std::env::remove_var("WHO") };
                assert!(std::env::var("ONLY_A").is_err());
            })
        });
    });
    a.run(|| {
        assert_eq!(std::env::var("WHO").as_deref(), Ok("a"));
        assert_eq!(
            std::env::var("ONLY_A").as_deref(),
            Ok("1"),
            "kept across runs"
        );
    });
    b.run(|| {
        assert!(std::env::var("WHO").is_err(), "the removal is kept too");
        assert!(std::env::var("ONLY_A").is_err());
    });
    assert!(std::env::var("ONLY_A").is_err(), "the process never saw it");
    let fresh = with_env(&[("WHO", "fresh")]);
    fresh.run(|| {
        assert!(
            std::env::var("ONLY_A").is_err(),
            "a new sim starts from its profile"
        )
    });
}

#[test]
fn which_threads_see_the_isolated_environment() {
    let key = "SNARE_EDGE_ENV_THREADS";
    snare::real(|| unsafe { std::env::set_var(key, "real") });
    with_env(&[(key, "sim")]).run(|| {
        assert_eq!(std::env::var(key).as_deref(), Ok("sim"));
        let spawned = std::thread::spawn(move || std::env::var(key))
            .join()
            .unwrap();
        assert_eq!(spawned.as_deref(), Ok("sim"));
        let grandchild = std::thread::spawn(move || {
            std::thread::spawn(move || std::env::var(key))
                .join()
                .unwrap()
        })
        .join()
        .unwrap();
        assert_eq!(grandchild.as_deref(), Ok("sim"));
        assert_eq!(snare::real(|| std::env::var(key)).as_deref(), Ok("real"));
        let nested = snare::real(|| snare::real(|| std::env::var(key)));
        assert_eq!(nested.as_deref(), Ok("real"));
        assert_eq!(
            std::env::var(key).as_deref(),
            Ok("sim"),
            "the sim again once real returns"
        );
        let unmanaged = snare::real(|| std::thread::spawn(move || std::env::var(key)))
            .join()
            .unwrap();
        assert_eq!(unmanaged.as_deref(), Ok("real"));
        snare::real(|| unsafe { std::env::set_var(key, "real2") });
        assert_eq!(std::env::var(key).as_deref(), Ok("sim"));
    });
    assert_eq!(std::env::var(key).as_deref(), Ok("real2"));
    unsafe { std::env::remove_var(key) };
}

#[test]
fn an_unisolated_sim_writes_through_to_the_real_environment() {
    let key = "SNARE_EDGE_ENV_THROUGH";
    for sim in [
        Sim::new(),
        Sim::builder().host(HostProfile::new().build()).build(),
    ] {
        sim.run(|| unsafe { std::env::set_var(key, "from-sim") });
        assert_eq!(std::env::var(key).as_deref(), Ok("from-sim"));
        sim.run(|| unsafe { std::env::remove_var(key) });
        assert!(std::env::var(key).is_err());
    }
}
