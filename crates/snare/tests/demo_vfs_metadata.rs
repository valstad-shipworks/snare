#![cfg(unix)]
//! `stat(2)` / `fstat(2)` over virtual nodes: file vs directory type, size, link count, inode,
//! block size, and permission bits, plus `exists()` and the `lstat == stat` (no symlinks) identity.
//! See man 2 stat, man 7 inode.

use std::os::unix::fs::{MetadataExt, PermissionsExt};

use snare::{FsBuilder, Sim};

#[test]
fn file_metadata_reports_type_and_size() {
    let fs = FsBuilder::new().file("/etc/conf", "0123456789").build();
    Sim::builder().fs(fs).build().run(|| {
        let m = std::fs::metadata("/etc/conf").unwrap();
        assert!(m.is_file());
        assert!(!m.is_dir());
        assert_eq!(m.len(), 10);
    });
}

#[test]
fn directory_metadata_reports_dir_type() {
    let fs = FsBuilder::new().dir("/etc").build();
    Sim::builder().fs(fs).build().run(|| {
        let m = std::fs::metadata("/etc").unwrap();
        assert!(m.is_dir());
        assert!(!m.is_file());
    });
}

#[test]
fn exists_tracks_declared_and_undeclared_paths() {
    let fs = FsBuilder::new()
        .own_prefix("/etc")
        .file("/etc/present", "x")
        .build();
    Sim::builder().fs(fs).build().run(|| {
        assert!(std::path::Path::new("/etc/present").exists());
        assert!(!std::path::Path::new("/etc/absent").exists());
    });
}

#[test]
fn fstat_through_an_open_handle_matches_the_declared_size() {
    let fs = FsBuilder::new().file("/data/f", "abcdef").build();
    Sim::builder().fs(fs).build().run(|| {
        // std's File::metadata is fstat(2) (statx with AT_EMPTY_PATH on Linux) on the open fd; it
        // must report the virtual size, not the /dev/null the fd was minted from.
        let f = std::fs::File::open("/data/f").unwrap();
        assert_eq!(f.metadata().unwrap().len(), 6);
    });
}

#[test]
fn permission_bits_follow_the_node_type() {
    let fs = FsBuilder::new().file("/etc/f", "x").dir("/etc").build();
    Sim::builder().fs(fs).build().run(|| {
        // inode(7): st_mode carries the low permission bits under the type bits. The sim reports
        // 0644 for a regular file and 0755 for a directory.
        let fm = std::fs::metadata("/etc/f").unwrap();
        assert_eq!(fm.permissions().mode() & 0o777, 0o644);
        let dm = std::fs::metadata("/etc").unwrap();
        assert_eq!(dm.permissions().mode() & 0o777, 0o755);
    });
}

#[test]
fn link_count_is_one_for_files_and_two_for_dirs() {
    let fs = FsBuilder::new().file("/etc/f", "x").dir("/etc").build();
    Sim::builder().fs(fs).build().run(|| {
        // inode(7): a regular file has st_nlink 1; a directory has at least 2 ("." plus its name).
        assert_eq!(std::fs::metadata("/etc/f").unwrap().nlink(), 1);
        assert_eq!(std::fs::metadata("/etc").unwrap().nlink(), 2);
    });
}

#[test]
fn inode_is_nonzero_and_stable_per_path() {
    let fs = FsBuilder::new().file("/etc/a", "1").file("/etc/b", "2").build();
    Sim::builder().fs(fs).build().run(|| {
        // inode(7): st_ino identifies the file within its filesystem; some callers treat 0 as
        // "no entry", so the sim never hands back 0 and keeps it stable across calls.
        let a1 = std::fs::metadata("/etc/a").unwrap().ino();
        let a2 = std::fs::metadata("/etc/a").unwrap().ino();
        let b = std::fs::metadata("/etc/b").unwrap().ino();
        assert_ne!(a1, 0);
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
    });
}

#[test]
fn block_size_is_reported() {
    let fs = FsBuilder::new().file("/etc/f", "x").build();
    Sim::builder().fs(fs).build().run(|| {
        // inode(7): st_blksize is the preferred I/O block size; the sim reports 4096.
        assert_eq!(std::fs::metadata("/etc/f").unwrap().blksize(), 4096);
    });
}

#[test]
fn symlink_metadata_equals_metadata_without_symlinks() {
    let fs = FsBuilder::new().file("/etc/f", "abc").build();
    Sim::builder().fs(fs).build().run(|| {
        // man 2 lstat: identical to stat when the final component is not a symlink. The sim models
        // no symlinks, so the two agree.
        let m = std::fs::metadata("/etc/f").unwrap();
        let l = std::fs::symlink_metadata("/etc/f").unwrap();
        assert_eq!(m.len(), l.len());
        assert_eq!(m.is_file(), l.is_file());
        assert!(!l.file_type().is_symlink());
    });
}

#[test]
fn metadata_on_a_missing_owned_path_is_enoent() {
    let fs = FsBuilder::new().own_prefix("/etc").dir("/etc").build();
    Sim::builder().fs(fs).build().run(|| {
        let e = std::fs::metadata("/etc/missing").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
    });
}
