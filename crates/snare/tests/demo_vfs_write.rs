#![cfg(unix)]
//! Writing through the virtual file plane. `File::create`, `OpenOptions`, and raw `write(2)` land
//! in process memory; on close the bytes persist back into the sim's tree so a later open sees
//! them. See man 2 open (O_CREAT / O_TRUNC / O_WRONLY / O_RDWR), man 2 write, man 2 lseek.

use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;

use snare::{FsBuilder, Sim};

#[test]
fn create_then_read_back_within_the_sim() {
    let fs = FsBuilder::new().own_prefix("/var").dir("/var").build();
    Sim::builder().fs(fs).build().run(|| {
        std::fs::File::create("/var/state")
            .unwrap()
            .write_all(b"persisted")
            .unwrap();
        assert_eq!(std::fs::read_to_string("/var/state").unwrap(), "persisted");
    });
}

#[test]
fn file_create_truncates_an_existing_file() {
    let fs = FsBuilder::new()
        .own_prefix("/o")
        .dir("/o")
        .file("/o/log", "OLD-AND-LONG")
        .build();
    Sim::builder().fs(fs).build().run(|| {
        // man 2 open: File::create opens O_WRONLY|O_CREAT|O_TRUNC, so an existing file is emptied
        // before the new bytes are written.
        std::fs::File::create("/o/log")
            .unwrap()
            .write_all(b"new")
            .unwrap();
        assert_eq!(std::fs::read_to_string("/o/log").unwrap(), "new");
    });
}

#[test]
fn rdwr_write_then_seek_back_and_read() {
    let fs = FsBuilder::new().own_prefix("/o").dir("/o").file("/o/f", "").build();
    Sim::builder().fs(fs).build().run(|| {
        // man 2 open: O_RDWR opens for both reading and writing on one description/offset.
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/o/f")
            .unwrap();
        f.write_all(b"HELLO").unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "HELLO");
    });
}

#[test]
fn a_seek_past_end_then_write_leaves_a_zero_filled_hole() {
    let fs = FsBuilder::new().own_prefix("/o").dir("/o").file("/o/sparse", "abc").build();
    Sim::builder().fs(fs).build().run(|| {
        // man 2 lseek: seeking past end then writing creates a gap read back as NUL bytes (a hole).
        let mut f = std::fs::OpenOptions::new().write(true).open("/o/sparse").unwrap();
        f.seek(SeekFrom::Start(5)).unwrap();
        f.write_all(b"Z").unwrap();
        drop(f);
        assert_eq!(std::fs::read("/o/sparse").unwrap(), b"abc\0\0Z");
    });
}

#[test]
fn overwriting_at_offset_zero_keeps_trailing_bytes() {
    let fs = FsBuilder::new().own_prefix("/o").dir("/o").file("/o/f", "AAAAAAAA").build();
    Sim::builder().fs(fs).build().run(|| {
        // A write covers only the range it touches; bytes beyond the write stay as they were.
        let mut f = std::fs::OpenOptions::new().write(true).open("/o/f").unwrap();
        f.write_all(b"bb").unwrap();
        drop(f);
        assert_eq!(std::fs::read_to_string("/o/f").unwrap(), "bbAAAAAA");
    });
}

#[test]
fn creating_a_new_file_under_a_declared_directory_succeeds() {
    // man 2 open O_CREAT: a new file may be created when its parent directory is known, even
    // without an owned prefix.
    let fs = FsBuilder::new().dir("/known").build();
    Sim::builder().fs(fs).build().run(|| {
        std::fs::File::create("/known/child")
            .unwrap()
            .write_all(b"c")
            .unwrap();
        assert_eq!(std::fs::read_to_string("/known/child").unwrap(), "c");
    });
}

#[test]
fn writes_are_visible_to_a_later_independent_open() {
    let fs = FsBuilder::new().own_prefix("/o").dir("/o").build();
    Sim::builder().fs(fs).build().run(|| {
        {
            let mut w = std::fs::File::create("/o/handoff").unwrap();
            w.write_all(b"first").unwrap();
        }
        assert_eq!(std::fs::read_to_string("/o/handoff").unwrap(), "first");
        {
            let mut w = std::fs::File::create("/o/handoff").unwrap();
            w.write_all(b"second").unwrap();
        }
        assert_eq!(std::fs::read_to_string("/o/handoff").unwrap(), "second");
    });
}

#[test]
fn writing_to_a_read_only_descriptor_fails_with_ebadf() {
    let fs = FsBuilder::new().file("/data/ro", "locked").build();
    Sim::builder().fs(fs).build().run(|| {
        let f = std::fs::File::open("/data/ro").unwrap();
        let fd = f.as_raw_fd();
        let payload = b"nope";
        // man 2 write: a write on a descriptor not opened for writing fails with EBADF.
        let n = unsafe { libc::write(fd, payload.as_ptr().cast(), payload.len()) };
        assert_eq!(n, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        assert_eq!(std::fs::read_to_string("/data/ro").unwrap(), "locked");
    });
}

#[test]
fn many_small_writes_accumulate() {
    let fs = FsBuilder::new().own_prefix("/o").dir("/o").build();
    Sim::builder().fs(fs).build().run(|| {
        {
            let mut f = std::fs::File::create("/o/acc").unwrap();
            for i in 0..1000u32 {
                write!(f, "{i},").unwrap();
            }
        }
        let back = std::fs::read_to_string("/o/acc").unwrap();
        assert!(back.starts_with("0,1,2,"));
        assert!(back.ends_with(",999,"));
        assert_eq!(back.matches(',').count(), 1000);
    });
}
