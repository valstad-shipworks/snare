#![cfg(unix)]
#![allow(clippy::unnecessary_cast)]
//! Edge cases of the `VirtualFs` file plane, pinned exactly ahead of a performance pass: empty,
//! sparse and large files, unicode and non-UTF-8 names, trailing slashes and `..`, the order in
//! which deny / passthrough / declared / owned decide a path, the open flags (`O_CREAT`, `O_TRUNC`,
//! `O_EXCL`, `O_APPEND`) and their errnos, when a write becomes visible to another open, the raw
//! `readdir` order with `.` and `..`, the `stat` fields, which calls the plane declines (so they
//! reach the real OS or the `/dev/null` descriptor behind a virtual fd), and how a tree is shared
//! between runs and sims. The `*_os_truth` tests run the same steps in a real temporary directory
//! under `snare::real`; those the model departs from are ignored with the departure as reason.

use std::ffi::{CStr, CString, OsStr};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use snare::{FsBuilder, Sim, VirtualFs};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn sim(fs: Arc<VirtualFs>) -> Sim {
    Sim::builder().fs(fs).build()
}

fn owned() -> FsBuilder {
    FsBuilder::new().own_prefix("/o").dir("/o")
}

/// A fresh real directory for the `*_os_truth` side, removed on drop.
struct RealDir(PathBuf);

impl RealDir {
    fn new(tag: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = snare::real(|| {
            std::env::temp_dir().join(format!("snare-edge-fs-{}-{tag}-{n}", std::process::id()))
        });
        snare::real(|| {
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
        });
        RealDir(dir)
    }

    fn path(&self, rel: &str) -> String {
        format!("{}/{rel}", self.0.display())
    }
}

impl Drop for RealDir {
    fn drop(&mut self) {
        let _ = snare::real(|| std::fs::remove_dir_all(&self.0));
    }
}

/// Opens `path` with raw `flags`, returning the fd or the errno.
fn raw_open(path: &str, flags: i32) -> Result<i32, i32> {
    let c = CString::new(path).unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), flags, 0o644 as libc::c_uint) };
    if fd < 0 { Err(errno()) } else { Ok(fd) }
}

fn raw_write(fd: i32, bytes: &[u8]) -> isize {
    unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) }
}

fn raw_read_all(fd: i32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 64];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        assert!(n >= 0, "read: {}", errno());
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
}

fn raw_close(fd: i32) {
    assert_eq!(unsafe { libc::close(fd) }, 0);
}

/// Every entry of a raw `opendir`/`readdir` walk, `.` and `..` included, as (name, d_type, d_ino).
fn raw_listing(path: &str) -> Result<Vec<(Vec<u8>, u8, u64)>, i32> {
    let c = CString::new(path).unwrap();
    let dir = unsafe { libc::opendir(c.as_ptr()) };
    if dir.is_null() {
        return Err(errno());
    }
    let mut out = Vec::new();
    loop {
        #[cfg(target_os = "linux")]
        let entry = unsafe { libc::readdir64(dir) };
        #[cfg(not(target_os = "linux"))]
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }
        let entry = unsafe { &*entry };
        let name = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) }
            .to_bytes()
            .to_vec();
        out.push((name, entry.d_type, entry.d_ino as u64));
    }
    assert_eq!(unsafe { libc::closedir(dir) }, 0);
    Ok(out)
}

fn names(listing: &[(Vec<u8>, u8, u64)]) -> Vec<String> {
    listing
        .iter()
        .map(|(n, _, _)| String::from_utf8_lossy(n).into_owned())
        .collect()
}

#[cfg(not(target_os = "linux"))]
use libc::{fstat as sys_fstat, stat as Stat, stat as sys_stat};
#[cfg(target_os = "linux")]
use libc::{fstat64 as sys_fstat, stat64 as Stat, stat64 as sys_stat};

/// `stat` through the symbol std itself calls (`stat64` on glibc).
fn raw_stat(path: &str) -> Result<Stat, i32> {
    let c = CString::new(path).unwrap();
    let mut st: Stat = unsafe { std::mem::zeroed() };
    if unsafe { sys_stat(c.as_ptr(), &mut st) } == 0 {
        Ok(st)
    } else {
        Err(errno())
    }
}

#[test]
fn an_empty_file_reads_nothing_and_stats_zero() {
    sim(owned().file("/o/empty", "").build()).run(|| {
        assert_eq!(std::fs::read("/o/empty").unwrap(), b"");
        let m = std::fs::metadata("/o/empty").unwrap();
        assert!(m.is_file());
        assert_eq!((m.len(), m.blocks(), m.nlink()), (0, 0, 1));
        let mut f = std::fs::File::open("/o/empty").unwrap();
        assert_eq!(f.seek(SeekFrom::End(0)).unwrap(), 0);
        let mut one = [0u8; 1];
        assert_eq!(f.read(&mut one).unwrap(), 0);
    });
}

#[test]
fn stat_fields_are_fixed() {
    sim(owned().file("/o/f", vec![7u8; 1025]).dir("/o/d").build()).run(|| {
        let (uid, gid) = snare::real(|| unsafe { (libc::getuid(), libc::getgid()) });
        let st = raw_stat("/o/f").unwrap();
        assert_eq!(st.st_mode as u32, 0o100644);
        assert_eq!(st.st_size, 1025);
        assert_eq!(st.st_nlink as u64, 1);
        assert_eq!(st.st_blksize as i64, 4096);
        assert_eq!(st.st_blocks as i64, 8);
        assert_eq!((st.st_uid, st.st_gid), (uid, gid));
        assert_eq!(st.st_ino as u64 & 1, 1);
        assert_eq!(
            (st.st_mtime, st.st_atime, st.st_ctime, st.st_dev as i64),
            (0, 0, 0, 0)
        );
        assert_eq!(
            raw_stat("/o/f").unwrap().st_ino,
            st.st_ino,
            "a path's inode is stable"
        );
        let d = raw_stat("/o/d").unwrap();
        assert_eq!(d.st_mode as u32, 0o40755);
        assert_eq!(
            (d.st_size, d.st_nlink as u64, d.st_blocks as i64),
            (0, 2, 0)
        );
        assert_ne!(d.st_ino, st.st_ino);

        let m = std::fs::metadata("/o/f").unwrap();
        assert_eq!(m.modified().unwrap(), std::time::UNIX_EPOCH);
        assert_eq!(m.ino(), st.st_ino as u64);

        let f = std::fs::File::open("/o/f").unwrap();
        let fd = f.as_raw_fd();
        let mut fst: Stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { sys_fstat(fd, &mut fst) }, 0);
        assert_eq!(fst.st_ino, st.st_ino);
        assert_eq!((fst.st_mode as u32, fst.st_size), (0o100644, 1025));
    });
}

#[test]
fn the_plain_stat_symbols_reach_the_plane() {
    sim(owned().file("/o/f", "four").build()).run(|| {
        let c = CString::new("/o/f").unwrap();
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::stat(c.as_ptr(), &mut st) },
            0,
            "stat: {}",
            errno()
        );
        assert_eq!((st.st_mode as u32, st.st_size), (0o100644, 4));
        let mut lst: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::lstat(c.as_ptr(), &mut lst) },
            0,
            "lstat: {}",
            errno()
        );
        assert_eq!(lst.st_ino, st.st_ino);
        let mut at: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::fstatat(libc::AT_FDCWD, c.as_ptr(), &mut at, 0) },
            0,
            "fstatat: {}",
            errno()
        );
        assert_eq!(at.st_ino, st.st_ino);
        let f = std::fs::File::open("/o/f").unwrap();
        let mut fst: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(f.as_raw_fd(), &mut fst) }, 0);
        assert_eq!((fst.st_mode as u32, fst.st_size), (0o100644, 4));
    });
}

#[test]
fn trailing_slash_creation_matches_the_host() {
    let flags = [
        libc::O_RDONLY,
        libc::O_WRONLY,
        libc::O_CREAT | libc::O_RDONLY,
        libc::O_CREAT | libc::O_WRONLY,
        libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
    ];
    for name in ["file", "file/", "dir", "dir/", "missing", "missing/"] {
        for flags in flags {
            let real_dir = RealDir::new("slash-create");
            let real_result = snare::real(|| {
                std::fs::write(real_dir.path("file"), "abc").unwrap();
                std::fs::create_dir(real_dir.path("dir")).unwrap();
                raw_open(&real_dir.path(name), flags).map(raw_close)
            });
            let fs = owned().file("/o/file", "abc").dir("/o/dir").build();
            let simulated = sim(fs).run(|| {
                let result = raw_open(&format!("/o/{name}"), flags).map(raw_close);
                if name == "missing/" && result.is_err() {
                    assert!(!Path::new("/o/missing").exists());
                }
                result
            });
            assert_eq!(simulated, real_result, "{name}, flags={flags:#x}");
        }
    }
}

#[test]
fn a_seek_far_past_the_end_then_a_write_zero_fills_sparse_holes() {
    sim(owned().build()).run(|| {
        let mut f = std::fs::File::create("/o/sparse").unwrap();
        let at = 16 << 20;
        assert_eq!(f.seek(SeekFrom::Start(at)).unwrap(), at);
        f.write_all(b"!").unwrap();
        assert_eq!(
            f.metadata().unwrap().len(),
            at + 1,
            "fstat sees the unflushed size"
        );
        assert_eq!(
            std::fs::metadata("/o/sparse").unwrap().len(),
            at + 1,
            "stat sees the same live inode size"
        );
        drop(f);
        let m = std::fs::metadata("/o/sparse").unwrap();
        assert_eq!(m.len(), at + 1);
        assert_eq!(m.blocks(), 8);
        let back = std::fs::read("/o/sparse").unwrap();
        assert_eq!(back.len() as u64, at + 1);
        assert!(back[..at as usize].iter().all(|&b| b == 0));
        assert_eq!(back[at as usize], b'!');
    });
}

#[test]
fn a_large_file_reads_back_whole_and_by_offset() {
    let big: Vec<u8> = (0..(8u32 << 20))
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let expected = big.clone();
    sim(owned().file("/o/big", big).build()).run(|| {
        assert_eq!(std::fs::read("/o/big").unwrap(), expected);
        let mut f = std::fs::File::open("/o/big").unwrap();
        assert_eq!(f.seek(SeekFrom::End(-3)).unwrap(), (8 << 20) - 3);
        let mut tail = Vec::new();
        f.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, expected[expected.len() - 3..]);
        let mut chunk = vec![0u8; 1 << 20];
        f.seek(SeekFrom::Start(3 << 20)).unwrap();
        f.read_exact(&mut chunk).unwrap();
        assert_eq!(chunk, expected[3 << 20..4 << 20]);
    });
}

#[test]
fn readdir_lists_dot_entries_then_children_in_byte_order() {
    let fs = owned()
        .dir("/o/d")
        .file("/o/d/b", "")
        .file("/o/d/B", "")
        .file("/o/d/a", "")
        .file("/o/d/\u{e4}", "")
        .file("/o/d/a b", "")
        .file("/o/d/a.b", "")
        .file("/o/d/a-b", "")
        .file("/o/d/10", "")
        .file("/o/d/9", "")
        .dir("/o/d/sub")
        .file("/o/d/sub/deep", "")
        .build();
    sim(fs).run(|| {
        let listing = raw_listing("/o/d").unwrap();
        assert_eq!(
            names(&listing),
            [
                ".", "..", "10", "9", "B", "a", "a b", "a-b", "a.b", "b", "sub", "\u{e4}"
            ]
        );
        let types: Vec<u8> = listing.iter().map(|(_, t, _)| *t).collect();
        let (d, r) = (libc::DT_DIR, libc::DT_REG);
        assert_eq!(types, [d, d, r, r, r, r, r, r, r, r, d, r]);
        assert_eq!(
            listing[1].2,
            raw_stat("/o").unwrap().st_ino as u64,
            "`..` identifies the parent directory"
        );
        assert_eq!(listing[0].2, raw_stat("/o/d").unwrap().st_ino as u64);
        assert_eq!(listing[2].2, raw_stat("/o/d/10").unwrap().st_ino as u64);

        let std_names: Vec<String> = std::fs::read_dir("/o/d")
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(std_names, names(&listing)[2..]);
        assert_eq!(raw_listing("/o/d/b"), Err(libc::ENOTDIR));
        assert_eq!(raw_listing("/o/none"), Err(libc::ENOENT));
    });
}

#[test]
fn a_listing_is_a_snapshot_taken_at_opendir() {
    sim(owned().file("/o/a", "").build()).run(|| {
        let mut entries = std::fs::read_dir("/o").unwrap();
        std::fs::write("/o/b", "x").unwrap();
        let first: Vec<String> = entries
            .by_ref()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(first, ["a"]);
        assert_eq!(names(&raw_listing("/o").unwrap()), [".", "..", "a", "b"]);
    });
}

#[test]
fn unicode_names_round_trip() {
    let name = "/o/\u{fc}n\u{ef}c\u{f8}d\u{e9} \u{2713}.txt";
    sim(owned().file(name, "\u{1f980}").build()).run(|| {
        assert_eq!(std::fs::read_to_string(name).unwrap(), "\u{1f980}");
        let listed: Vec<_> = std::fs::read_dir("/o")
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(listed, [PathBuf::from(name)]);
        std::fs::write("/o/\u{65e5}\u{672c}", "jp").unwrap();
        assert_eq!(std::fs::read("/o/\u{65e5}\u{672c}").unwrap(), b"jp");
    });
}

#[test]
fn a_non_utf8_name_preserves_its_bytes() {
    sim(owned().build()).run(|| {
        let raw = Path::new(OsStr::from_bytes(b"/o/\xffname"));
        std::fs::write(raw, "x").unwrap();
        let listing = raw_listing("/o").unwrap();
        assert_eq!(listing[2].0, b"\xffname");
        assert_eq!(
            std::fs::read("/o/\u{fffd}name").unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
        assert_eq!(std::fs::read(raw).unwrap(), b"x");
    });
}

#[test]
fn dot_dot_and_dot_require_resolved_intermediate_components() {
    sim(owned().file("/o/f", "F").dir("/o/d").build()).run(|| {
        assert_eq!(std::fs::read("/o/./f").unwrap(), b"F");
        assert_eq!(
            std::fs::read("/o/missing/../f").unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
        assert_eq!(std::fs::read("/o/d/../f").unwrap(), b"F");
        assert_eq!(
            std::fs::read("/../../o/f").unwrap(),
            b"F",
            "`..` stops at the root"
        );
        assert_eq!(std::fs::read("//o//f").unwrap(), b"F");
        assert_eq!(
            std::fs::read("/o/f/..").unwrap_err().raw_os_error(),
            Some(libc::ENOTDIR)
        );
        assert_eq!(
            std::fs::canonicalize("/o/d/../f").unwrap(),
            Path::new("/o/f")
        );
    });
}

#[test]
fn a_trailing_slash_requires_a_directory() {
    sim(owned().file("/o/f", "F").dir("/o/d").build()).run(|| {
        assert_eq!(
            std::fs::read("/o/f/").unwrap_err().raw_os_error(),
            Some(libc::ENOTDIR)
        );
        assert_eq!(
            std::fs::metadata("/o/f/").unwrap_err().raw_os_error(),
            Some(libc::ENOTDIR)
        );
        assert!(std::fs::metadata("/o/d/").unwrap().is_dir());
        assert_eq!(names(&raw_listing("/o/d/").unwrap()), [".", ".."]);
    });
}

#[test]
fn a_trailing_slash_after_a_file_os_truth() {
    let dir = RealDir::new("slash");
    let real = snare::real(|| {
        std::fs::write(dir.path("f"), "F").unwrap();
        raw_open(&dir.path("f/"), libc::O_RDONLY).map(raw_close)
    });
    assert_eq!(real, Err(libc::ENOTDIR));
    let got = sim(owned().file("/o/f", "F").build())
        .run(|| raw_open("/o/f/", libc::O_RDONLY).map(raw_close));
    assert_eq!(got, real);
}

#[test]
fn a_trailing_slash_on_a_directory_lists_alike_os_truth() {
    let dir = RealDir::new("dirslash");
    let real = snare::real(|| {
        std::fs::create_dir(dir.0.join("d")).unwrap();
        std::fs::write(dir.0.join("d/x"), "").unwrap();
        let mut n = names(&raw_listing(&dir.path("d/")).unwrap());
        n.sort();
        n
    });
    let got = sim(owned().file("/o/d/x", "").build()).run(|| names(&raw_listing("/o/d/").unwrap()));
    assert_eq!(got, real);
}

#[test]
fn a_path_is_decided_deny_then_passthrough_then_tree_then_owned() {
    let dir = RealDir::new("order");
    snare::real(|| std::fs::write(dir.0.join("real"), "REAL").unwrap());
    let real_path = dir.path("real");
    let fs = FsBuilder::new()
        .own_prefix(dir.0.to_str().unwrap())
        .file(&real_path, "VIRTUAL")
        .file("/o/both", "B")
        .file("/o/secret", "S")
        .own_prefix("/o")
        .passthrough(&real_path)
        .passthrough("/o/both")
        .deny("/o/both")
        .deny("/o/secret")
        .build();
    sim(fs).run(|| {
        assert_eq!(
            std::fs::read(&real_path).unwrap(),
            b"REAL",
            "passthrough beats the tree"
        );
        assert_eq!(
            std::fs::read(dir.path("undeclared"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOENT)
        );
        assert_eq!(
            std::fs::read("/o/both").unwrap_err().raw_os_error(),
            Some(libc::EACCES)
        );
        assert_eq!(
            std::fs::read("/o/secret").unwrap_err().raw_os_error(),
            Some(libc::EACCES)
        );
        assert_eq!(
            std::fs::canonicalize("/o/secret").unwrap(),
            Path::new("/o/secret"),
            "realpath skips deny"
        );
        assert_eq!(
            std::fs::read("/o/nothing").unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
        assert_eq!(
            std::fs::read("/snare-edge-unowned/x")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOENT),
            "undeclared and unowned goes to the real OS"
        );
    });
}

#[test]
fn a_glob_star_crosses_slashes() {
    let fs = owned().file("/o/a/b/c", "C").deny("/o/*").build();
    sim(fs).run(|| {
        assert_eq!(
            std::fs::read("/o/a/b/c").unwrap_err().raw_os_error(),
            Some(libc::EACCES)
        );
    });
}

#[test]
fn o_creat_rules() {
    let fs = FsBuilder::new()
        .dir("/known")
        .dir("/o")
        .own_prefix("/o")
        .build();
    sim(fs).run(|| {
        assert_eq!(
            raw_open("/o/a/b/c", libc::O_WRONLY | libc::O_CREAT),
            Err(libc::ENOENT)
        );
        assert_eq!(
            std::fs::read("/o/a/b/c").unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
        assert_eq!(
            raw_listing("/o/a"),
            Err(libc::ENOENT),
            "failed creation leaves its parents undeclared"
        );
        let fd = raw_open("/known/new", libc::O_RDONLY | libc::O_CREAT).unwrap();
        assert_eq!(raw_write(fd, b"w"), -1);
        assert_eq!(errno(), libc::EBADF);
        raw_close(fd);
        assert_eq!(std::fs::read("/known/new").unwrap(), b"");
        assert_eq!(raw_open("/o/none", libc::O_RDONLY), Err(libc::ENOENT));
        assert_eq!(
            raw_open("/snare-edge-unowned/x", libc::O_WRONLY | libc::O_CREAT),
            Err(libc::ENOENT),
            "an unowned path with no declared parent is the real OS's"
        );
    });
}

#[test]
fn o_excl_on_an_existing_file_os_truth() {
    let dir = RealDir::new("excl");
    let real = snare::real(|| {
        std::fs::write(dir.0.join("f"), "abcdef").unwrap();
        raw_open(
            &dir.path("f"),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map(raw_close)
    });
    assert_eq!(real, Err(libc::EEXIST));
    let got = sim(owned().file("/o/f", "abcdef").build())
        .run(|| raw_open("/o/f", libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL).map(raw_close));
    assert_eq!(got, real);
}

#[test]
fn o_excl_on_a_new_file_creates_it_os_truth() {
    let dir = RealDir::new("exclnew");
    let real = snare::real(|| {
        let fd = raw_open(
            &dir.path("n"),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .unwrap();
        raw_write(fd, b"n");
        raw_close(fd);
        std::fs::read(dir.0.join("n")).unwrap()
    });
    let got = sim(owned().build()).run(|| {
        let fd = raw_open("/o/n", libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL).unwrap();
        raw_write(fd, b"n");
        raw_close(fd);
        std::fs::read("/o/n").unwrap()
    });
    assert_eq!(got, real);
}

#[test]
fn o_append_os_truth() {
    let dir = RealDir::new("append");
    let real = snare::real(|| {
        std::fs::write(dir.0.join("f"), "abcdef").unwrap();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.0.join("f"))
            .unwrap();
        f.write_all(b"XY").unwrap();
        drop(f);
        std::fs::read(dir.0.join("f")).unwrap()
    });
    assert_eq!(real, b"abcdefXY");
    let got = sim(owned().file("/o/f", "abcdef").build()).run(|| {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open("/o/f")
            .unwrap();
        f.write_all(b"XY").unwrap();
        drop(f);
        std::fs::read("/o/f").unwrap()
    });
    assert_eq!(got, real);
}

#[test]
fn o_trunc_read_only_matches_the_host_os_truth() {
    let dir = RealDir::new("readonly-trunc");
    let steps = |path: &str| {
        let fd = raw_open(path, libc::O_RDONLY | libc::O_TRUNC).unwrap();
        let contents = raw_read_all(fd);
        assert_eq!(raw_write(fd, b"x"), -1);
        let error = errno();
        raw_close(fd);
        (contents, error, std::fs::read(path).unwrap())
    };
    let real = snare::real(|| {
        std::fs::write(dir.0.join("f"), "kept").unwrap();
        steps(&dir.path("f"))
    });
    let modeled = sim(owned().file("/o/f", "kept").build()).run(|| steps("/o/f"));
    assert_eq!(modeled, real);
}

#[test]
fn o_trunc_with_write_access_matches_the_host_os_truth() {
    let dir = RealDir::new("trunc");
    let steps = |path: &str| {
        let fd = raw_open(path, libc::O_RDWR | libc::O_TRUNC).unwrap();
        let first = raw_read_all(fd);
        raw_write(fd, b"new");
        raw_close(fd);
        (first, std::fs::read(path).unwrap())
    };
    let real = snare::real(|| {
        std::fs::write(dir.0.join("f"), "old-and-long").unwrap();
        steps(&dir.path("f"))
    });
    let got = sim(owned().file("/o/f", "old-and-long").build()).run(|| steps("/o/f"));
    assert_eq!(got, real);
    assert_eq!(got, (Vec::new(), b"new".to_vec()));
}

#[test]
fn a_directory_opened_for_writing_os_truth() {
    let dir = RealDir::new("dirw");
    let real = snare::real(|| raw_open(dir.0.to_str().unwrap(), libc::O_WRONLY).map(raw_close));
    assert_eq!(real, Err(libc::EISDIR));
    let got =
        sim(owned().dir("/o/d").build()).run(|| raw_open("/o/d", libc::O_WRONLY).map(raw_close));
    assert_eq!(got, real);
}

#[test]
fn independent_writers_and_readers_share_live_contents_os_truth() {
    let dir = RealDir::new("live-writes");
    let steps = |path: &str| {
        let w1 = raw_open(path, libc::O_RDWR).unwrap();
        let w2 = raw_open(path, libc::O_RDWR).unwrap();
        let early = raw_open(path, libc::O_RDONLY).unwrap();
        assert_eq!(raw_write(w1, b"ONE!"), 4);
        let first = std::fs::read(path).unwrap();
        assert_eq!(raw_write(w2, b"TWO-TWO"), 7);
        let size = raw_stat(path).unwrap().st_size;
        raw_close(w2);
        let second = std::fs::read(path).unwrap();
        raw_close(w1);
        let third = std::fs::read(path).unwrap();
        let existing_reader = raw_read_all(early);
        raw_close(early);
        (first, second, third, existing_reader, size)
    };
    let real = snare::real(|| {
        std::fs::write(dir.0.join("f"), "orig").unwrap();
        steps(&dir.path("f"))
    });
    let modeled = sim(owned().file("/o/f", "orig").build()).run(|| steps("/o/f"));
    assert_eq!(modeled, real);
}

#[test]
fn lseek_whence_values() {
    sim(owned().file("/o/f", "0123456789").build()).run(|| {
        let fd = raw_open("/o/f", libc::O_RDONLY).unwrap();
        assert_eq!(unsafe { libc::lseek(fd, 4, libc::SEEK_SET) }, 4);
        assert_eq!(unsafe { libc::lseek(fd, -5, libc::SEEK_CUR) }, -1);
        assert_eq!(errno(), libc::EINVAL);
        assert_eq!(
            unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) },
            4,
            "a failed seek leaves the cursor"
        );
        assert_eq!(unsafe { libc::lseek(fd, 5, libc::SEEK_END) }, 15);
        assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_DATA) }, -1);
        assert_eq!(errno(), libc::EINVAL);
        assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_HOLE) }, -1);
        assert_eq!(errno(), libc::EINVAL);
        assert_eq!(unsafe { libc::lseek(fd, 0, 99) }, -1);
        assert_eq!(errno(), libc::EINVAL);
        raw_close(fd);
    });
}

#[test]
fn calls_the_plane_declines_reach_the_real_os() {
    let dir = RealDir::new("decline");
    let passed = dir.path("passed");
    let undeclared = dir.path("undeclared");
    snare::real(|| {
        std::fs::write(&passed, "native passed").unwrap();
        std::fs::write(&undeclared, "native undeclared").unwrap();
    });
    let fs = owned()
        .file("/o/f", "abc")
        .file(&passed, "virtual")
        .passthrough(&passed)
        .build();
    sim(fs).run(|| {
        let c = CString::new("/o/f").unwrap();
        assert_eq!(unsafe { libc::access(c.as_ptr(), libc::F_OK) }, 0);
        assert!(Path::new("/o/f").exists());
        for (path, expected) in [
            (&passed, b"native passed".as_slice()),
            (&undeclared, b"native undeclared".as_slice()),
        ] {
            let c = CString::new(path.as_str()).unwrap();
            assert_eq!(unsafe { libc::access(c.as_ptr(), libc::F_OK) }, 0);
            assert_eq!(std::fs::read(path).unwrap(), expected);
        }
    });
}

#[test]
fn positional_io_on_a_virtual_fd_uses_the_inode_contents() {
    sim(owned().file("/o/f", "abcdef").build()).run(|| {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/o/f")
            .unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(f.read_at(&mut buf, 1).unwrap(), 4);
        assert_eq!(&buf, b"bcde");
        assert_eq!(f.write_at(b"ZZ", 0).unwrap(), 2);
        f.sync_all().unwrap();
        drop(f);
        assert_eq!(std::fs::read("/o/f").unwrap(), b"ZZcdef");
    });
}

fn positional_trace(path: &str, flags: i32) -> (Vec<Result<i64, i32>>, Vec<u8>, Vec<u8>) {
    let fd = raw_open(path, flags).unwrap();
    let alias = unsafe { libc::dup(fd) };
    assert!(alias >= 0);
    let mut result = Vec::new();
    let mut bytes = [0u8; 4];
    let mut record = |value: i64| {
        result.push(if value < 0 { Err(errno()) } else { Ok(value) });
    };
    record(unsafe { libc::lseek(fd, 10, libc::SEEK_SET) });
    record(unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) } as i64);
    record(unsafe { libc::lseek(alias, 0, libc::SEEK_CUR) });
    record(unsafe { libc::write(fd, std::ptr::null(), 0) } as i64);
    record(unsafe { libc::lseek(alias, 0, libc::SEEK_CUR) });
    record(unsafe { libc::lseek(fd, 3, libc::SEEK_SET) });
    record(unsafe { libc::pread(alias, bytes.as_mut_ptr().cast(), 2, 1) } as i64);
    let read = bytes[..2].to_vec();
    record(unsafe { libc::pwrite(alias, b"ZZ".as_ptr().cast(), 2, 1) } as i64);
    record(unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) });
    record(unsafe { libc::pread(alias, bytes.as_mut_ptr().cast(), 2, -1) } as i64);
    record(unsafe { libc::pwrite(alias, b"ZZ".as_ptr().cast(), 2, -1) } as i64);
    record(unsafe { libc::ftruncate(alias, 3) } as i64);
    record(unsafe { libc::ftruncate(alias, 6) } as i64);
    record(unsafe { libc::ftruncate(alias, -1) } as i64);
    record(unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) });
    record(unsafe { libc::fsync(fd) } as i64);
    raw_close(alias);
    raw_close(fd);
    (result, read, std::fs::read(path).unwrap())
}

#[test]
fn positional_io_and_access_modes_match_the_host() {
    let dir = RealDir::new("positional");
    for flags in [
        libc::O_RDONLY,
        libc::O_WRONLY,
        libc::O_RDWR,
        libc::O_RDWR | libc::O_APPEND,
        libc::O_WRONLY | libc::O_APPEND,
    ] {
        let path = dir.path("f");
        let real = snare::real(|| {
            std::fs::write(&path, b"abcdef").unwrap();
            positional_trace(&path, flags)
        });
        let got =
            sim(owned().file("/o/f", "abcdef").build()).run(|| positional_trace("/o/f", flags));
        assert_eq!(got, real, "flags={flags}");
    }
}

#[test]
fn a_virtual_fd_under_real_is_dev_null() {
    sim(owned().file("/o/f", "abcdef").build()).run(|| {
        let mut f = std::fs::File::open("/o/f").unwrap();
        let fd = f.as_raw_fd();
        let mut buf = [0u8; 8];
        let n = snare::real(|| unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) });
        assert_eq!(n, 0);
        assert_eq!(
            snare::real(|| std::fs::read("/o/f").unwrap_err().kind()),
            ErrorKind::NotFound
        );
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "abcdef", "the cursor did not move");
    });
}

#[test]
fn a_virtual_fd_is_usable_from_another_thread_of_the_sim() {
    sim(owned().file("/o/f", "shared").build()).run(|| {
        let mut f = std::fs::File::open("/o/f").unwrap();
        let mut two = [0u8; 2];
        f.read_exact(&mut two).unwrap();
        let rest = std::thread::spawn(move || {
            let mut s = String::new();
            f.read_to_string(&mut s).unwrap();
            s
        })
        .join()
        .unwrap();
        assert_eq!((&two, rest.as_str()), (b"sh", "ared"));
        let unmanaged =
            snare::real(|| std::thread::spawn(|| std::fs::read("/o/f").map_err(|e| e.kind())))
                .join()
                .unwrap();
        assert_eq!(unmanaged, Err(ErrorKind::NotFound));
    });
}

#[test]
fn the_tree_persists_across_runs_and_is_shared_by_sims_sharing_the_plane() {
    let fs = owned().build();
    let a = sim(fs.clone());
    a.run(|| std::fs::write("/o/x", "one").unwrap());
    assert_eq!(a.run(|| std::fs::read("/o/x").unwrap()), b"one");
    let b = sim(fs);
    assert_eq!(b.run(|| std::fs::read("/o/x").unwrap()), b"one");
    b.run(|| std::fs::write("/o/x", "two").unwrap());
    assert_eq!(a.run(|| std::fs::read("/o/x").unwrap()), b"two");
    let c = sim(owned().build());
    assert_eq!(
        c.run(|| std::fs::read("/o/x").unwrap_err().raw_os_error()),
        Some(libc::ENOENT)
    );
    assert_eq!(
        std::fs::read("/o/x").unwrap_err().kind(),
        ErrorKind::NotFound,
        "never the real disk"
    );
}

#[test]
fn many_open_fds_are_distinct_and_released() {
    sim(owned().file("/o/f", "x").build()).run(|| {
        let fds: Vec<i32> = (0..200)
            .map(|_| raw_open("/o/f", libc::O_RDONLY).unwrap())
            .collect();
        let mut sorted = fds.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 200);
        assert!(fds.iter().all(|&fd| fd > 2));
        for fd in fds {
            raw_close(fd);
        }
    });
}
