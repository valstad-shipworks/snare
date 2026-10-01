#![cfg(unix)]

use snare::{HostProfile, Sim};

#[test]
fn code_under_test_sees_only_the_simulated_environment() {
    // A variable that (almost certainly) is not set on the real machine.
    let host = HostProfile::new()
        .env("SNARE_SIM_VAR", "hello")
        .env("PATH", "/sim/bin")
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(std::env::var("SNARE_SIM_VAR").as_deref(), Ok("hello"));
        assert_eq!(std::env::var("PATH").as_deref(), Ok("/sim/bin"));
        // An unset variable reads as absent — the real environment is invisible.
        assert!(std::env::var("HOME").is_err(), "real HOME must not leak into the sim");

        // setenv/getenv round-trip within the simulated environment.
        unsafe {
            let k = std::ffi::CString::new("RUNTIME_SET").unwrap();
            let v = std::ffi::CString::new("v2").unwrap();
            assert_eq!(libc::setenv(k.as_ptr(), v.as_ptr(), 1), 0);
        }
        assert_eq!(std::env::var("RUNTIME_SET").as_deref(), Ok("v2"));
    });
}

#[test]
fn without_env_isolation_the_real_environment_shows_through() {
    // No .env()/.isolate_env() → the env is NOT intercepted.
    unsafe {
        let k = std::ffi::CString::new("SNARE_REAL_ONLY").unwrap();
        let v = std::ffi::CString::new("present").unwrap();
        libc::setenv(k.as_ptr(), v.as_ptr(), 1);
    }
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(std::env::var("SNARE_REAL_ONLY").as_deref(), Ok("present"));
    });
    unsafe {
        let k = std::ffi::CString::new("SNARE_REAL_ONLY").unwrap();
        libc::unsetenv(k.as_ptr());
    }
}

#[test]
fn tester_can_reach_the_real_environment_and_files_via_snare() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("snare_real_{}.txt", std::process::id()));
    unsafe {
        let k = std::ffi::CString::new("SNARE_REAL_ENV").unwrap();
        let v = std::ffi::CString::new("from-the-machine").unwrap();
        libc::setenv(k.as_ptr(), v.as_ptr(), 1);
    }

    let host = HostProfile::new().isolate_env().build();
    let p = path.clone();
    Sim::builder().host(host).build().run(move || {
        // Inside the sim, the isolated environment hides the real var...
        assert!(std::env::var("SNARE_REAL_ENV").is_err());
        // ...but the escape hatch reaches the real machine.
        let real_var = snare::real(|| std::env::var("SNARE_REAL_ENV").ok());
        assert_eq!(real_var.as_deref(), Some("from-the-machine"));

        // And real file I/O bypasses the simulated file plane.
        snare::real(|| std::fs::write(&p, b"payload")).unwrap();
        let read_back = snare::real(|| std::fs::read_to_string(&p)).unwrap();
        assert_eq!(read_back, "payload");
    });

    // The write really hit the disk (observable outside the sim).
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "payload");
    let _ = std::fs::remove_file(&path);
    unsafe {
        let k = std::ffi::CString::new("SNARE_REAL_ENV").unwrap();
        libc::unsetenv(k.as_ptr());
    }
}
