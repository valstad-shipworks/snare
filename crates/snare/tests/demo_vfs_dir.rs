#![cfg(unix)]
//! Directory enumeration over virtual trees. `std::fs::read_dir` drives `opendir(3)` + `readdir(3)`
//! (on Linux ultimately `getdents64(2)`); the sim snapshots the directory and hands back one record
//! at a time. See man 3 opendir, man 3 readdir, man 2 getdents64.

use std::collections::BTreeSet;

use snare::{FsBuilder, Sim};

fn names(dir: &str) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn lists_files_and_subdirectories_sorted() {
    let fs = FsBuilder::new()
        .own_prefix("/d")
        .file("/d/one", "1")
        .file("/d/two", "22")
        .file("/d/three", "333")
        .dir("/d/sub")
        .build();
    Sim::builder().fs(fs).build().run(|| {
        assert_eq!(names("/d"), vec!["one", "sub", "three", "two"]);
    });
}

#[test]
fn read_dir_hides_dot_and_dotdot() {
    let fs = FsBuilder::new()
        .own_prefix("/d")
        .file("/d/only", "x")
        .build();
    Sim::builder().fs(fs).build().run(|| {
        // readdir(3) yields "." and ".."; std::fs::read_dir filters them, so only real entries show.
        let set: BTreeSet<String> = std::fs::read_dir("/d")
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(!set.contains("."));
        assert!(!set.contains(".."));
        assert_eq!(
            set.into_iter().collect::<Vec<_>>(),
            vec!["only".to_string()]
        );
    });
}

#[test]
fn entry_file_type_distinguishes_files_from_dirs() {
    let fs = FsBuilder::new()
        .own_prefix("/d")
        .file("/d/f", "x")
        .dir("/d/g")
        .build();
    Sim::builder().fs(fs).build().run(|| {
        // getdents64(2): d_type is DT_REG for a file and DT_DIR for a directory.
        let mut files = Vec::new();
        let mut dirs = Vec::new();
        for e in std::fs::read_dir("/d").unwrap() {
            let e = e.unwrap();
            let name = e.file_name().to_string_lossy().into_owned();
            if e.file_type().unwrap().is_dir() {
                dirs.push(name);
            } else {
                files.push(name);
            }
        }
        assert_eq!(files, vec!["f"]);
        assert_eq!(dirs, vec!["g"]);
    });
}

#[test]
fn an_empty_directory_lists_nothing() {
    let fs = FsBuilder::new().own_prefix("/empty").dir("/empty").build();
    Sim::builder().fs(fs).build().run(|| {
        assert!(names("/empty").is_empty());
    });
}

#[test]
fn only_immediate_children_appear_not_grandchildren() {
    let fs = FsBuilder::new()
        .own_prefix("/d")
        .file("/d/top", "t")
        .file("/d/sub/nested", "n")
        .build();
    Sim::builder().fs(fs).build().run(|| {
        // readdir lists one level; the nested file is reachable only by descending into "sub".
        assert_eq!(names("/d"), vec!["sub", "top"]);
        assert_eq!(names("/d/sub"), vec!["nested"]);
    });
}

#[test]
fn read_dir_on_a_missing_owned_directory_is_enoent() {
    let fs = FsBuilder::new().own_prefix("/d").dir("/d").build();
    Sim::builder().fs(fs).build().run(|| {
        // opendir(3) on a path with no entry under an owned prefix fails ENOENT (default-deny).
        let e = std::fs::read_dir("/d/ghost").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
    });
}

#[test]
fn read_dir_on_a_regular_file_is_enotdir() {
    let fs = FsBuilder::new().own_prefix("/d").file("/d/f", "x").build();
    Sim::builder().fs(fs).build().run(|| {
        // opendir(3): opening a non-directory fails ENOTDIR.
        let e = std::fs::read_dir("/d/f").unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ENOTDIR));
    });
}

#[test]
fn a_directory_with_many_entries_enumerates_all_of_them() {
    let mut b = FsBuilder::new().own_prefix("/big").dir("/big");
    for i in 0..256u32 {
        b = b.file(format!("/big/f{i:03}"), format!("{i}"));
    }
    Sim::builder().fs(b.build()).build().run(|| {
        let n = std::fs::read_dir("/big").unwrap().count();
        assert_eq!(n, 256);
        // The snapshot is stable: a second pass sees the same set.
        assert_eq!(names("/big").len(), 256);
        assert_eq!(names("/big")[0], "f000");
    });
}
