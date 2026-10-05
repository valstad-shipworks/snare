#![cfg(unix)]
//! The `snare::real` escape hatch: inside `Sim::run`, tester/support code sometimes needs the real
//! machine rather than the simulated planes. `real(|| ...)` runs the closure with this thread's OS
//! calls going straight to the kernel — real files (man 2 open) and the real environment (man 3
//! getenv) — while the code under test around it keeps seeing the sim.

use std::ffi::CString;

use snare::{FsBuilder, HostProfile, Sim};

fn unique(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("snare-real-{tag}-{}", std::process::id()));
    p
}

#[test]
fn real_reads_a_file_the_virtual_plane_would_hide() {
    let real = unique("read");
    std::fs::write(&real, b"disk contents").unwrap();

    // The owned prefix would ENOENT any undeclared path, but `real` bypasses the virtual plane.
    let fs = FsBuilder::new().own_prefix("/").build();
    let p = real.clone();
    let got = Sim::builder().fs(fs).build().run(move || {
        assert!(
            std::fs::read_to_string(&p).is_err(),
            "sim plane must hide the real file"
        );
        snare::real(|| std::fs::read_to_string(&p)).unwrap()
    });
    assert_eq!(got, "disk contents");
    let _ = std::fs::remove_file(&real);
}

#[test]
fn real_writes_reach_the_disk() {
    let real = unique("write");
    let _ = std::fs::remove_file(&real);

    let fs = FsBuilder::new().build();
    let p = real.clone();
    Sim::builder().fs(fs).build().run(move || {
        snare::real(|| std::fs::write(&p, b"escaped")).unwrap();
    });
    // Observable outside the sim: the bytes really landed on disk.
    assert_eq!(std::fs::read_to_string(&real).unwrap(), "escaped");
    let _ = std::fs::remove_file(&real);
}

#[test]
fn real_reads_the_environment_the_sim_hides() {
    let key = CString::new("SNARE_REAL_ESC").unwrap();
    let val = CString::new("machine-value").unwrap();
    unsafe { libc::setenv(key.as_ptr(), val.as_ptr(), 1) };

    let host = HostProfile::new().isolate_env().build();
    Sim::builder().host(host).build().run(|| {
        // Inside the sim the isolated env hides it...
        assert!(std::env::var("SNARE_REAL_ESC").is_err());
        // ...but the escape hatch reaches the real environment.
        let v = snare::real(|| std::env::var("SNARE_REAL_ESC").ok());
        assert_eq!(v.as_deref(), Some("machine-value"));
    });

    unsafe { libc::unsetenv(key.as_ptr()) };
}

#[test]
fn real_returns_the_closures_value() {
    let sim = Sim::new();
    let n = sim.run(|| snare::real(|| 2 + 3));
    assert_eq!(n, 5);
}

#[test]
fn back_inside_the_sim_after_real_the_virtual_plane_is_active_again() {
    let fs = FsBuilder::new()
        .own_prefix("/o")
        .dir("/o")
        .file("/o/v", "virtual")
        .build();
    let tmp = unique("toggle");
    std::fs::write(&tmp, b"real").unwrap();
    let p = tmp.clone();
    Sim::builder().fs(fs).build().run(move || {
        assert_eq!(std::fs::read_to_string("/o/v").unwrap(), "virtual");
        let real = snare::real(|| std::fs::read_to_string(&p)).unwrap();
        assert_eq!(real, "real");
        // The escape hatch was scoped to the closure; the virtual file is served again here.
        assert_eq!(std::fs::read_to_string("/o/v").unwrap(), "virtual");
        assert_eq!(
            std::fs::read_to_string("/o/missing").unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    });
    let _ = std::fs::remove_file(&tmp);
}
