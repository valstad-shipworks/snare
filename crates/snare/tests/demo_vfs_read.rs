#![cfg(unix)]
//! Reading declared virtual files through ordinary `std::fs` / `File`. The sim serves the bytes
//! from process memory; the code under test issues real `open(2)` + `read(2)` and never touches
//! the disk. See man 2 open, man 2 read.

use std::io::{Read, Seek, SeekFrom};

use snare::{FsBuilder, Sim};

#[test]
fn read_to_string_returns_declared_contents() {
    let fs = FsBuilder::new().file("/etc/motd", "welcome\n").build();
    Sim::builder().fs(fs).build().run(|| {
        assert_eq!(std::fs::read_to_string("/etc/motd").unwrap(), "welcome\n");
    });
}

#[test]
fn read_an_empty_file_yields_zero_bytes() {
    let fs = FsBuilder::new().file("/etc/empty", "").build();
    Sim::builder().fs(fs).build().run(|| {
        // man 2 read: a read at end-of-file returns 0 without error.
        let mut f = std::fs::File::open("/etc/empty").unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(f.read(&mut buf).unwrap(), 0);
        assert_eq!(std::fs::read("/etc/empty").unwrap(), Vec::<u8>::new());
    });
}

#[test]
fn binary_content_with_interior_nul_bytes_roundtrips() {
    let payload = vec![0x00u8, 0xFF, 0x00, 0x41, 0x00, 0x42];
    let fs = FsBuilder::new().file("/data/blob", payload.clone()).build();
    Sim::builder().fs(fs).build().run(move || {
        assert_eq!(std::fs::read("/data/blob").unwrap(), payload);
    });
}

#[test]
fn a_large_file_reads_back_whole() {
    let big: Vec<u8> = (0..64_000u32).map(|i| i as u8).collect();
    let fs = FsBuilder::new().file("/data/big", big.clone()).build();
    Sim::builder().fs(fs).build().run(move || {
        let got = std::fs::read("/data/big").unwrap();
        assert_eq!(got.len(), 64_000);
        assert_eq!(got, big);
    });
}

#[test]
fn short_reads_advance_the_cursor_across_successive_calls() {
    let fs = FsBuilder::new().file("/data/seq", b"abcdefgh".to_vec()).build();
    Sim::builder().fs(fs).build().run(|| {
        // man 2 read: each read advances the file offset by the number of bytes returned.
        let mut f = std::fs::File::open("/data/seq").unwrap();
        let mut a = [0u8; 3];
        f.read_exact(&mut a).unwrap();
        assert_eq!(&a, b"abc");
        let mut b = [0u8; 3];
        f.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"def");
        let mut rest = Vec::new();
        f.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"gh");
    });
}

#[test]
fn a_read_never_overruns_a_buffer_larger_than_the_file() {
    let fs = FsBuilder::new().file("/data/tiny", b"xy".to_vec()).build();
    Sim::builder().fs(fs).build().run(|| {
        // man 2 read: the count returned is at most the bytes remaining, even when the caller's
        // buffer is larger.
        let mut f = std::fs::File::open("/data/tiny").unwrap();
        let mut buf = [0xAAu8; 16];
        let n = f.read(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"xy");
        assert_eq!(buf[2], 0xAA, "bytes past the file must be untouched");
    });
}

#[test]
fn reopening_gives_a_fresh_independent_cursor() {
    let fs = FsBuilder::new().file("/data/x", b"0123456789".to_vec()).build();
    Sim::builder().fs(fs).build().run(|| {
        let mut f1 = std::fs::File::open("/data/x").unwrap();
        f1.seek(SeekFrom::Start(5)).unwrap();
        let mut a = [0u8; 2];
        f1.read_exact(&mut a).unwrap();
        assert_eq!(&a, b"56");

        // A second handle starts at offset 0, independent of the first.
        let mut f2 = std::fs::File::open("/data/x").unwrap();
        let mut b = [0u8; 2];
        f2.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"01");
    });
}

#[test]
fn a_file_declared_under_a_nested_path_creates_its_parents() {
    let fs = FsBuilder::new().file("/a/b/c/d.txt", "deep").build();
    Sim::builder().fs(fs).build().run(|| {
        assert_eq!(std::fs::read_to_string("/a/b/c/d.txt").unwrap(), "deep");
        // Each intermediate directory is a real directory node (man 2 stat: S_IFDIR).
        for dir in ["/a", "/a/b", "/a/b/c"] {
            assert!(std::fs::metadata(dir).unwrap().is_dir(), "{dir} must be a dir");
        }
    });
}
