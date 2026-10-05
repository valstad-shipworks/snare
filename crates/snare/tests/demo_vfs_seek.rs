#![cfg(unix)]
//! `lseek(2)` semantics on virtual files: SEEK_SET / SEEK_CUR / SEEK_END arithmetic, a negative
//! resulting offset rejected with EINVAL, and reads past end returning zero bytes. See man 2 lseek.

use std::io::{Read, Seek, SeekFrom};
use std::os::unix::io::AsRawFd;

use snare::{FsBuilder, Sim};

#[test]
fn seek_set_cur_and_end() {
    let fs = FsBuilder::new().file("/f", b"0123456789".to_vec()).build();
    Sim::builder().fs(fs).build().run(|| {
        let mut f = std::fs::File::open("/f").unwrap();

        assert_eq!(f.seek(SeekFrom::Start(3)).unwrap(), 3);
        let mut a = [0u8; 1];
        f.read_exact(&mut a).unwrap();
        assert_eq!(&a, b"3");

        // SEEK_CUR is relative to the position left by the read above (now 4).
        assert_eq!(f.seek(SeekFrom::Current(2)).unwrap(), 6);
        f.read_exact(&mut a).unwrap();
        assert_eq!(&a, b"6");

        // SEEK_END with a negative offset counts back from the 10-byte length.
        assert_eq!(f.seek(SeekFrom::End(-1)).unwrap(), 9);
        f.read_exact(&mut a).unwrap();
        assert_eq!(&a, b"9");
    });
}

#[test]
fn seek_to_a_negative_offset_is_einval() {
    let fs = FsBuilder::new().file("/f", b"abc".to_vec()).build();
    Sim::builder().fs(fs).build().run(|| {
        let f = std::fs::File::open("/f").unwrap();
        let fd = f.as_raw_fd();
        // man 2 lseek: a resulting offset before the start of the file is EINVAL.
        let off = unsafe { libc::lseek(fd, -5, libc::SEEK_SET) };
        assert_eq!(off, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINVAL)
        );
    });
}

#[test]
fn seek_to_end_reports_the_file_length() {
    let fs = FsBuilder::new()
        .file("/f", b"twelve bytes".to_vec())
        .build();
    Sim::builder().fs(fs).build().run(|| {
        let mut f = std::fs::File::open("/f").unwrap();
        assert_eq!(f.seek(SeekFrom::End(0)).unwrap(), 12);
        assert_eq!(f.stream_position().unwrap(), 12);
    });
}

#[test]
fn reading_past_end_of_file_returns_zero_bytes() {
    let fs = FsBuilder::new().file("/f", b"abc".to_vec()).build();
    Sim::builder().fs(fs).build().run(|| {
        // man 2 lseek: seeking beyond end is allowed; a subsequent read there returns 0 (not an
        // error) and must not panic on the clamp.
        let mut f = std::fs::File::open("/f").unwrap();
        assert_eq!(f.seek(SeekFrom::Start(9_999)).unwrap(), 9_999);
        let mut buf = Vec::new();
        assert_eq!(f.read_to_end(&mut buf).unwrap(), 0);
        assert!(buf.is_empty());
    });
}

#[test]
#[allow(clippy::seek_from_current)] // exercising the SEEK_CUR path is the point of this test
fn seek_cur_zero_reports_current_position_without_moving() {
    let fs = FsBuilder::new().file("/f", b"0123456789".to_vec()).build();
    Sim::builder().fs(fs).build().run(|| {
        let mut f = std::fs::File::open("/f").unwrap();
        let mut two = [0u8; 4];
        f.read_exact(&mut two).unwrap();
        // SEEK_CUR with offset 0 is the idiomatic "tell" (man 2 lseek).
        assert_eq!(f.seek(SeekFrom::Current(0)).unwrap(), 4);
    });
}
