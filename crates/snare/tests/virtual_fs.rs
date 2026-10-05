#![cfg(unix)]
//! The code under test uses ordinary `std::fs`; declared files are served from memory, globs pass
//! through to the real OS, and undeclared paths under an owned prefix fail with ENOENT.

use std::io::{Read, Seek, SeekFrom, Write};

use snare::{FsBuilder, Sim};

#[test]
fn reads_a_virtual_file() {
    let fs = FsBuilder::new()
        .file("/etc/app.conf", "key = value\n")
        .build();
    let sim = Sim::builder().fs(fs).build();
    sim.run(|| {
        let contents = std::fs::read_to_string("/etc/app.conf").unwrap();
        assert_eq!(contents, "key = value\n");
    });
}

#[test]
fn fd_cursor_and_seek() {
    let fs = FsBuilder::new()
        .file("/data/blob", b"0123456789".to_vec())
        .build();
    let sim = Sim::builder().fs(fs).build();
    sim.run(|| {
        let mut f = std::fs::File::open("/data/blob").unwrap();
        let mut first = [0u8; 4];
        f.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"0123");
        f.seek(SeekFrom::Start(8)).unwrap();
        let mut rest = Vec::new();
        f.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"89");
    });
}

#[test]
fn writes_persist_within_the_sim() {
    let fs = FsBuilder::new().dir("/var").own_prefix("/var").build();
    let sim = Sim::builder().fs(fs).build();
    sim.run(|| {
        {
            let mut f = std::fs::File::create("/var/state").unwrap();
            f.write_all(b"written").unwrap();
        }
        let back = std::fs::read_to_string("/var/state").unwrap();
        assert_eq!(back, "written");
    });
}

#[test]
fn default_deny_under_owned_prefix() {
    let fs = FsBuilder::new()
        .own_prefix("/sys")
        .file("/sys/known", "x")
        .build();
    let sim = Sim::builder().fs(fs).build();
    sim.run(|| {
        assert_eq!(std::fs::read_to_string("/sys/known").unwrap(), "x");
        let err = std::fs::read_to_string("/sys/unknown").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    });
}

#[test]
fn passthrough_reaches_the_real_file() {
    let dir = std::env::temp_dir();
    let real = dir.join(format!("snare-fs-{}", std::process::id()));
    std::fs::write(&real, b"real bytes").unwrap();
    let glob = format!("{}/snare-fs-*", dir.display());

    let fs = FsBuilder::new().passthrough(&glob).build();
    let sim = Sim::builder().fs(fs).build();
    let got = sim.run(|| std::fs::read_to_string(&real).unwrap());
    assert_eq!(got, "real bytes");
    let _ = std::fs::remove_file(&real);
}

#[test]
fn undeclared_outside_owned_prefix_passes_through() {
    // Reading the test binary's own working dir entries still hits the real OS by default.
    let fs = FsBuilder::new().file("/virtual/only", "v").build();
    let sim = Sim::builder().fs(fs).build();
    sim.run(|| {
        assert_eq!(std::fs::read_to_string("/virtual/only").unwrap(), "v");
        // Cargo.toml exists for real relative to the workspace; an absolute real path passes through.
        assert!(std::fs::metadata("/").is_ok());
    });
}

#[test]
fn metadata_reports_type_and_size() {
    let fs = FsBuilder::new()
        .file("/etc/app.conf", "key = value\n")
        .dir("/etc")
        .own_prefix("/etc")
        .build();
    let sim = Sim::builder().fs(fs).build();
    sim.run(|| {
        let m = std::fs::metadata("/etc/app.conf").unwrap();
        assert!(m.is_file());
        assert_eq!(m.len(), 12);
        assert!(std::path::Path::new("/etc/app.conf").exists());

        let d = std::fs::metadata("/etc").unwrap();
        assert!(d.is_dir());

        assert!(!std::path::Path::new("/etc/missing").exists());

        // File::open then metadata (fstat path) reports the virtual size, not /dev/null.
        let f = std::fs::File::open("/etc/app.conf").unwrap();
        assert_eq!(f.metadata().unwrap().len(), 12);
    });
}

#[test]
fn lists_a_virtual_directory() {
    let fs = FsBuilder::new()
        .own_prefix("/d")
        .file("/d/alpha", "a")
        .file("/d/beta", "bb")
        .dir("/d/sub")
        .build();
    let sim = Sim::builder().fs(fs).build();
    sim.run(|| {
        let mut names: Vec<String> = std::fs::read_dir("/d")
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["alpha", "beta", "sub"]);

        let mut dirs = 0;
        for e in std::fs::read_dir("/d").unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                dirs += 1;
                assert_eq!(e.file_name().to_string_lossy(), "sub");
            }
        }
        assert_eq!(dirs, 1);
    });
}

#[test]
fn seek_past_eof_then_read_is_empty_not_a_crash() {
    let fs = FsBuilder::new().file("/f", "abc").build();
    let sim = Sim::builder().fs(fs).build();
    sim.run(|| {
        let mut f = std::fs::File::open("/f").unwrap();
        f.seek(SeekFrom::Start(1000)).unwrap();
        let mut buf = Vec::new();
        assert_eq!(f.read_to_end(&mut buf).unwrap(), 0);
        assert!(buf.is_empty());
    });
}

#[test]
fn canonicalize_a_virtual_path() {
    let fs = FsBuilder::new().file("/a/b/c.txt", "x").build();
    let sim = Sim::builder().fs(fs).build();
    sim.run(|| {
        let p = std::fs::canonicalize("/a/./b/../b/c.txt").unwrap();
        assert_eq!(p, std::path::Path::new("/a/b/c.txt"));
    });
}
