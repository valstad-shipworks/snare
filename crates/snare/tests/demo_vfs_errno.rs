#![cfg(unix)]
//! Error paths: the exact `errno` the virtual plane returns for denied, missing, and
//! wrong-type operations. Kept distinct from the happy-path files so a regression in the error
//! mapping is easy to localize. See man 2 open, man 2 read, man 3 opendir.

use std::os::unix::io::AsRawFd;

use snare::{FsBuilder, Sim};

#[test]
fn undeclared_under_owned_prefix_is_enoent() {
    let fs = FsBuilder::new().own_prefix("/sys").file("/sys/known", "x").build();
    Sim::builder().fs(fs).build().run(|| {
        assert_eq!(std::fs::read_to_string("/sys/known").unwrap(), "x");
        // Default-deny: an owned prefix never falls through to the real OS.
        let e = std::fs::read_to_string("/sys/unknown").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(e.raw_os_error(), Some(libc::ENOENT));
    });
}

#[test]
fn a_denied_glob_returns_eacces_even_for_a_declared_file() {
    let fs = FsBuilder::new()
        .file("/secret/token", "hunter2")
        .deny("/secret/*")
        .build();
    Sim::builder().fs(fs).build().run(|| {
        // The deny list is checked before the tree, so a declared file behind a deny glob still
        // fails with EACCES (man 2 open: EACCES is the access-denied errno).
        let e = std::fs::read_to_string("/secret/token").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(e.raw_os_error(), Some(libc::EACCES));
    });
}

#[test]
fn deny_also_blocks_stat_and_opendir() {
    let fs = FsBuilder::new()
        .file("/secret/f", "x")
        .dir("/secret/d")
        .deny("/secret/**")
        .build();
    Sim::builder().fs(fs).build().run(|| {
        assert_eq!(
            std::fs::metadata("/secret/f").unwrap_err().raw_os_error(),
            Some(libc::EACCES)
        );
        assert_eq!(
            std::fs::read_dir("/secret/d").unwrap_err().raw_os_error(),
            Some(libc::EACCES)
        );
    });
}

#[test]
fn reading_a_directory_as_a_file_is_eisdir() {
    let fs = FsBuilder::new().own_prefix("/d").dir("/d").build();
    Sim::builder().fs(fs).build().run(|| {
        // man 2 read: a read on a descriptor referring to a directory fails with EISDIR.
        let e = std::fs::read_to_string("/d").unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EISDIR));
    });
}

#[test]
fn opening_a_missing_owned_file_without_o_creat_is_enoent() {
    let fs = FsBuilder::new().own_prefix("/o").dir("/o").build();
    Sim::builder().fs(fs).build().run(|| {
        // man 2 open: without O_CREAT, a nonexistent path is ENOENT (here scoped to the owned
        // prefix; outside it the call would fall through to the OS).
        let e = std::fs::File::open("/o/nope").unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ENOENT));
    });
}

#[test]
fn writing_to_a_read_only_handle_is_ebadf() {
    let fs = FsBuilder::new().file("/data/ro", "x").build();
    Sim::builder().fs(fs).build().run(|| {
        let f = std::fs::File::open("/data/ro").unwrap();
        let buf = *b"!";
        let n = unsafe { libc::write(f.as_raw_fd(), buf.as_ptr().cast(), 1) };
        assert_eq!(n, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    });
}

#[test]
fn a_negative_lseek_is_einval() {
    let fs = FsBuilder::new().file("/f", "abc").build();
    Sim::builder().fs(fs).build().run(|| {
        let f = std::fs::File::open("/f").unwrap();
        let r = unsafe { libc::lseek(f.as_raw_fd(), -1, libc::SEEK_SET) };
        assert_eq!(r, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));
    });
}
