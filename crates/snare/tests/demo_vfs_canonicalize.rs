#![cfg(unix)]
//! `realpath(3)` / `std::fs::canonicalize` over the virtual tree: lexical resolution of `.` and
//! `..` and redundant separators, both the caller-buffer and malloc'd-buffer forms, and the
//! ENOENT for a missing owned path. See man 3 realpath.

use std::ffi::{CStr, CString};

use snare::{FsBuilder, Sim};

#[test]
fn canonicalize_resolves_dot_dotdot_and_double_slash() {
    let fs = FsBuilder::new().file("/a/b/c.txt", "x").build();
    Sim::builder().fs(fs).build().run(|| {
        for input in [
            "/a/./b/c.txt",
            "/a/b/../b/c.txt",
            "/a//b///c.txt",
            "/a/b/./c.txt",
        ] {
            let p = std::fs::canonicalize(input).unwrap();
            assert_eq!(p, std::path::Path::new("/a/b/c.txt"), "input: {input}");
        }
    });
}

#[test]
fn canonicalize_a_directory() {
    let fs = FsBuilder::new().file("/a/b/c.txt", "x").build();
    Sim::builder().fs(fs).build().run(|| {
        assert_eq!(
            std::fs::canonicalize("/a/b").unwrap(),
            std::path::Path::new("/a/b")
        );
    });
}

#[test]
fn realpath_into_a_caller_supplied_buffer() {
    let fs = FsBuilder::new().file("/x/y", "1").build();
    Sim::builder().fs(fs).build().run(|| {
        let input = CString::new("/x/./y").unwrap();
        // man 3 realpath: a non-NULL `resolved_path` must point to a buffer of at least PATH_MAX
        // bytes; realpath writes the canonical path there and returns that pointer.
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        let ret = unsafe { libc::realpath(input.as_ptr(), buf.as_mut_ptr().cast()) };
        assert!(!ret.is_null());
        let got = unsafe { CStr::from_ptr(ret) }
            .to_string_lossy()
            .into_owned();
        assert_eq!(got, "/x/y");
    });
}

#[test]
fn realpath_with_null_buffer_mallocs_the_result() {
    let fs = FsBuilder::new().file("/x/y", "1").build();
    Sim::builder().fs(fs).build().run(|| {
        let input = CString::new("/x/y").unwrap();
        // man 3 realpath: a NULL `resolved_path` makes realpath malloc the buffer, which the caller
        // frees.
        let ret = unsafe { libc::realpath(input.as_ptr(), std::ptr::null_mut()) };
        assert!(!ret.is_null());
        let got = unsafe { CStr::from_ptr(ret) }
            .to_string_lossy()
            .into_owned();
        assert_eq!(got, "/x/y");
        unsafe { libc::free(ret.cast()) };
    });
}

#[test]
fn canonicalize_a_missing_owned_path_is_enoent() {
    let fs = FsBuilder::new().own_prefix("/x").dir("/x").build();
    Sim::builder().fs(fs).build().run(|| {
        // man 3 realpath: a component that does not exist yields ENOENT.
        let e = std::fs::canonicalize("/x/nope").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
    });
}
