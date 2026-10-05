#![cfg(unix)]
//! The passthrough / deny escape valves at the path level. Each test owns the real temp directory
//! as a virtual prefix, so an undeclared path there would ENOENT by default; a passthrough glob is
//! what lets a specific real path reach the OS, and a deny glob blocks it. See man 2 open,
//! man 7 glob.

use std::io::Write;
use std::path::PathBuf;

use snare::{FsBuilder, Sim};

/// A unique real path under the temp dir plus a glob that matches it (built with `with_file_name`
/// so there is no stray `//` from a trailing separator on `temp_dir`).
fn real_and_glob(tag: &str) -> (PathBuf, String) {
    let real = std::env::temp_dir().join(format!("snare-demo-{tag}-{}", std::process::id()));
    let glob = real
        .with_file_name(format!("snare-demo-{tag}-*"))
        .to_string_lossy()
        .into_owned();
    (real, glob)
}

fn temp_prefix() -> PathBuf {
    // Strip any trailing separator so the owned prefix is a clean directory path.
    std::env::temp_dir().join("x").with_file_name("")
}

#[test]
fn a_passthrough_glob_reaches_a_real_file_inside_an_owned_prefix() {
    let (real, glob) = real_and_glob("pt-read");
    std::fs::write(&real, b"on disk").unwrap();

    let fs = FsBuilder::new()
        .own_prefix(temp_prefix())
        .passthrough(&glob)
        .build();
    let p = real.clone();
    let got = Sim::builder()
        .fs(fs)
        .build()
        .run(move || std::fs::read_to_string(&p).unwrap());
    assert_eq!(got, "on disk");
    let _ = std::fs::remove_file(&real);
}

#[test]
fn without_the_passthrough_the_owned_prefix_denies_the_same_path() {
    let (real, _glob) = real_and_glob("pt-denied-default");
    std::fs::write(&real, b"on disk").unwrap();

    // Same owned prefix, but no passthrough glob: the real file is invisible (default-deny ENOENT).
    let fs = FsBuilder::new().own_prefix(temp_prefix()).build();
    let p = real.clone();
    let kind = Sim::builder()
        .fs(fs)
        .build()
        .run(move || std::fs::read_to_string(&p).unwrap_err().kind());
    assert_eq!(kind, std::io::ErrorKind::NotFound);
    let _ = std::fs::remove_file(&real);
}

#[test]
fn a_passthrough_glob_writes_through_to_disk() {
    let (real, glob) = real_and_glob("pt-write");
    let _ = std::fs::remove_file(&real);

    let fs = FsBuilder::new()
        .own_prefix(temp_prefix())
        .passthrough(&glob)
        .build();
    let p = real.clone();
    Sim::builder().fs(fs).build().run(move || {
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"written through").unwrap();
    });
    // Observable outside the sim: the write reached the real OS.
    assert_eq!(std::fs::read_to_string(&real).unwrap(), "written through");
    let _ = std::fs::remove_file(&real);
}

#[test]
fn deny_wins_over_a_passthrough_for_the_same_path() {
    let (real, glob) = real_and_glob("pt-deny");
    std::fs::write(&real, b"secret").unwrap();

    // open() checks the deny list before the passthrough list, so deny shadows passthrough.
    let fs = FsBuilder::new()
        .own_prefix(temp_prefix())
        .passthrough(&glob)
        .deny(&glob)
        .build();
    let p = real.clone();
    let err = Sim::builder()
        .fs(fs)
        .build()
        .run(move || std::fs::read_to_string(&p).unwrap_err().raw_os_error());
    assert_eq!(err, Some(libc::EACCES));
    let _ = std::fs::remove_file(&real);
}

#[test]
fn a_passthrough_directory_lists_its_real_entries() {
    let (dir, _g) = real_and_glob("pt-dir");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("alpha"), b"a").unwrap();
    std::fs::write(dir.join("beta"), b"b").unwrap();
    let glob = dir
        .with_file_name("snare-demo-pt-dir-*")
        .to_string_lossy()
        .into_owned();
    let children = format!("{glob}/*");

    let fs = FsBuilder::new()
        .own_prefix(temp_prefix())
        .passthrough(&glob)
        .passthrough(&children)
        .build();
    let d = dir.clone();
    let mut got = Sim::builder().fs(fs).build().run(move || {
        std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
    });
    got.sort();
    assert_eq!(got, vec!["alpha", "beta"]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_passthrough_to_a_missing_real_file_reports_the_real_enoent() {
    let (missing, glob) = real_and_glob("pt-missing");
    let _ = std::fs::remove_file(&missing);

    let fs = FsBuilder::new()
        .own_prefix(temp_prefix())
        .passthrough(&glob)
        .build();
    let p = missing.clone();
    let kind = Sim::builder()
        .fs(fs)
        .build()
        .run(move || std::fs::read_to_string(&p).unwrap_err().kind());
    assert_eq!(kind, std::io::ErrorKind::NotFound);
}

#[test]
fn a_path_outside_any_owned_prefix_falls_through_by_default() {
    // With no owned prefix, an undeclared absolute path reaches the real OS; the virtual file is
    // still served from memory.
    let fs = FsBuilder::new().file("/virtual/only", "v").build();
    Sim::builder().fs(fs).build().run(|| {
        assert_eq!(std::fs::read_to_string("/virtual/only").unwrap(), "v");
        assert!(std::fs::metadata("/").unwrap().is_dir());
    });
}
