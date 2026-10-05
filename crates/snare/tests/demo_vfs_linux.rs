#![cfg(target_os = "linux")]
//! Linux-specific stat/enumeration paths. On Linux, std's `File::metadata` is
//! `statx(fd, "", AT_EMPTY_PATH, ...)` and `read_dir` is driven by `getdents64(2)`; this file pins
//! that both report the virtual node correctly. See man 2 statx, man 2 getdents64.

use std::os::unix::fs::MetadataExt;

use snare::{FsBuilder, Sim};

#[test]
fn file_metadata_via_statx_at_empty_path_reports_virtual_size() {
    let fs = FsBuilder::new().file("/data/f", "0123456789").build();
    Sim::builder().fs(fs).build().run(|| {
        // man 2 statx: an empty pathname with AT_EMPTY_PATH stats the fd itself; the STATX_SIZE
        // result must be the virtual length, not the /dev/null backing the descriptor.
        let f = std::fs::File::open("/data/f").unwrap();
        let m = f.metadata().unwrap();
        assert_eq!(m.len(), 10);
        assert!(m.is_file());
        assert_eq!(m.mode() & 0o170000, libc::S_IFREG);
    });
}

#[test]
fn statx_on_a_path_reports_type_size_and_inode() {
    let fs = FsBuilder::new().file("/etc/f", "abcd").dir("/etc").build();
    Sim::builder().fs(fs).build().run(|| {
        // std::fs::metadata on a path is statx on modern Linux; STATX_TYPE/SIZE/INO must be filled.
        let m = std::fs::metadata("/etc/f").unwrap();
        assert_eq!(m.len(), 4);
        assert_ne!(m.ino(), 0);
        assert_eq!(m.nlink(), 1);
        let d = std::fs::metadata("/etc").unwrap();
        assert!(d.is_dir());
        assert_eq!(d.nlink(), 2);
    });
}

#[test]
fn getdents64_enumerates_a_virtual_directory() {
    let mut b = FsBuilder::new().own_prefix("/d").dir("/d");
    for i in 0..300u32 {
        b = b.file(format!("/d/e{i:03}"), "x");
    }
    Sim::builder().fs(b.build()).build().run(|| {
        // man 2 getdents64: read_dir pulls records until the stream ends; every declared child
        // must appear exactly once.
        let mut names: Vec<String> = std::fs::read_dir("/d")
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names.len(), 300);
        assert_eq!(names.first().unwrap(), "e000");
        assert_eq!(names.last().unwrap(), "e299");
    });
}
