//! Memory-mapped files against the host: the same `mmap`, `mprotect`, `msync` and I/O calls on
//! real temporary files and on `VirtualFs` files at the same paths must return the same results,
//! errnos and bytes. Shared mappings of a file see each other's writes and those of `write`,
//! `pwrite` and `ftruncate`, and those calls see the mappings'; a private mapping copies on write;
//! mapping marks the access time and a written mapping the modification time; touching a page past
//! the end of the file raises `SIGBUS`.
#![cfg(unix)]

use std::ffi::{CStr, CString, c_int, c_void};
use std::path::Path;

use snare::{FsBuilder, Sim};

/// A call's label, its result (an mmap's 0 for success), and its errno when it failed.
type Seen = (&'static str, i64, c_int);

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn seen(label: &'static str, result: i64) -> Seen {
    (label, result, if result < 0 { errno() } else { 0 })
}

fn open(path: &CStr, flags: c_int) -> c_int {
    let fd = unsafe { libc::open(path.as_ptr(), flags, 0o600) };
    assert!(fd >= 0, "open {path:?}: {}", errno());
    fd
}

fn close(fd: c_int) {
    assert_eq!(unsafe { libc::close(fd) }, 0);
}

fn pwrite(fd: c_int, bytes: &[u8], offset: i64) {
    let n = unsafe { libc::pwrite(fd, bytes.as_ptr().cast(), bytes.len(), offset as _) };
    assert_eq!(n, bytes.len() as isize, "pwrite: {}", errno());
}

fn pread(fd: c_int, len: usize, offset: i64) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let n = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), len, offset as _) };
    assert!(n >= 0, "pread: {}", errno());
    buf.truncate(n as usize);
    buf
}

fn truncate(fd: c_int, len: i64) {
    assert_eq!(
        unsafe { libc::ftruncate(fd, len as _) },
        0,
        "ftruncate: {}",
        errno()
    );
}

/// An mmap attempt: 0 and the mapping unmapped again on success, -1 and the errno on failure.
fn attempt(
    label: &'static str,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: i64,
) -> Seen {
    let address = unsafe { libc::mmap(std::ptr::null_mut(), len, prot, flags, fd, offset as _) };
    if address == libc::MAP_FAILED {
        return seen(label, -1);
    }
    assert_eq!(unsafe { libc::munmap(address, len) }, 0);
    (label, 0, 0)
}

fn map(len: usize, prot: c_int, flags: c_int, fd: c_int, offset: i64) -> *mut u8 {
    let address = unsafe { libc::mmap(std::ptr::null_mut(), len, prot, flags, fd, offset as _) };
    assert_ne!(address, libc::MAP_FAILED, "mmap: {}", errno());
    address.cast()
}

fn unmap(address: *mut u8, len: usize) {
    assert_eq!(unsafe { libc::munmap(address.cast::<c_void>(), len) }, 0);
}

fn byte(address: *mut u8, at: usize) -> i64 {
    i64::from(unsafe { address.add(at).read_volatile() })
}

fn poke(address: *mut u8, at: usize, value: u8) {
    unsafe { address.add(at).write_volatile(value) };
}

fn file_bytes(fd: c_int, len: usize, offset: i64) -> i64 {
    pread(fd, len, offset)
        .iter()
        .fold(0, |acc, &b| acc * 256 + i64::from(b))
}

fn stat(fd: c_int) -> libc::stat {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0);
    st
}

/// Sets the access and modification times far in the past, so a later stamp shows.
fn age(fd: c_int) {
    let times = [
        libc::timespec {
            tv_sec: 1000,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: 2000,
            tv_nsec: 0,
        },
    ];
    assert_eq!(unsafe { libc::futimens(fd, times.as_ptr()) }, 0);
}

fn errors(path: &CStr, dir: &CStr, page: usize) -> Vec<Seen> {
    let (r, w, rw) = (
        libc::PROT_READ,
        libc::PROT_WRITE,
        libc::PROT_READ | libc::PROT_WRITE,
    );
    let (shared, private) = (libc::MAP_SHARED, libc::MAP_PRIVATE);
    let fd = open(path, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC);
    truncate(fd, 2 * page as i64);
    let read_only = open(path, libc::O_RDONLY);
    let write_only = open(path, libc::O_WRONLY);
    let append = open(path, libc::O_RDWR | libc::O_APPEND);
    let directory = open(dir, libc::O_RDONLY | libc::O_DIRECTORY);
    let mut out = vec![
        attempt("shared rw", page, rw, shared, fd, 0),
        attempt("shared write-only prot", page, w, shared, fd, 0),
        attempt("private rw", page, rw, private, fd, 0),
        attempt("shared rw on read-only", page, rw, shared, read_only, 0),
        attempt("shared r on read-only", page, r, shared, read_only, 0),
        attempt("private rw on read-only", page, rw, private, read_only, 0),
        attempt("shared r on write-only", page, r, shared, write_only, 0),
        attempt(
            "private none on write-only",
            page,
            libc::PROT_NONE,
            private,
            write_only,
            0,
        ),
        attempt("shared rw on append", page, rw, shared, append, 0),
        attempt("exec", page, r | libc::PROT_EXEC, private, fd, 0),
        attempt("zero length", 0, r, shared, fd, 0),
        attempt("unaligned offset", page, r, shared, fd, 1),
        attempt("negative offset", page, r, shared, fd, -(page as i64)),
        attempt("no mapping type", page, r, 0, fd, 0),
        attempt("past the end", 16 * page, r, shared, fd, 0),
        attempt("offset past the end", page, r, shared, fd, 64 * page as i64),
        attempt("directory", page, r, shared, directory, 0),
        attempt("directory shared rw", page, rw, shared, directory, 0),
        attempt("directory private", page, r, private, directory, 0),
        attempt("directory zero length", 0, r, private, directory, 0),
    ];
    let mapping = map(page, r, shared, read_only, 0);
    out.push(seen(
        "mprotect shared read-only to rw",
        i64::from(unsafe { libc::mprotect(mapping.cast(), page, rw) }),
    ));
    unmap(mapping, page);
    let mapping = map(page, r, private, read_only, 0);
    out.push(seen(
        "mprotect private read-only to rw",
        i64::from(unsafe { libc::mprotect(mapping.cast(), page, rw) }),
    ));
    unmap(mapping, page);
    let mapping = map(page, r, shared, fd, 0);
    out.push(seen(
        "mprotect shared rw descriptor to rw",
        i64::from(unsafe { libc::mprotect(mapping.cast(), page, rw) }),
    ));
    unmap(mapping, page);
    for fd in [fd, read_only, write_only, append, directory] {
        close(fd);
    }
    out
}

fn coherence(path: &CStr, page: usize) -> Vec<Seen> {
    let (rw, shared, private) = (
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
        libc::MAP_PRIVATE,
    );
    let mut out = Vec::new();
    let fd = open(path, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC);
    pwrite(fd, b"hello", 0);
    truncate(fd, 2 * page as i64);
    let other = open(path, libc::O_RDWR);
    let a = map(2 * page, rw, shared, fd, 0);
    let b = map(2 * page, rw, shared, other, 0);
    out.push(("mapped existing bytes", byte(a, 0) * 256 + byte(a, 4), 0));

    poke(a, 1, b'E');
    out.push(("other mapping sees a mapping's write", byte(b, 1), 0));
    out.push(("pread sees a mapping's write", file_bytes(other, 2, 0), 0));
    pwrite(other, b"L", 2);
    out.push(("mapping sees pwrite", byte(a, 2), 0));
    assert_eq!(unsafe { libc::lseek(fd, 3, libc::SEEK_SET) }, 3);
    assert_eq!(unsafe { libc::write(fd, b"L".as_ptr().cast(), 1) }, 1);
    out.push(("mapping sees write", byte(b, 3), 0));
    poke(b, page + 7, 9);
    out.push((
        "second page through pread",
        file_bytes(fd, 1, page as i64 + 7),
        0,
    ));
    out.push(("size unchanged by mapping writes", stat(fd).st_size, 0));

    truncate(fd, page as i64 + 4);
    out.push(("tail of a shrunk page reads zero", byte(a, page + 7), 0));
    truncate(fd, 2 * page as i64);
    out.push(("regrown page reads zero", byte(b, page + 7), 0));

    let p = map(page, rw, private, fd, 0);
    out.push(("private sees the file", byte(p, 1), 0));
    poke(p, 0, b'P');
    out.push(("private write stays private", byte(a, 0), 0));
    out.push(("private write misses the file", file_bytes(fd, 1, 0), 0));
    out.push(("private keeps its copy", byte(p, 0), 0));
    pwrite(fd, b"Z", 0);
    out.push(("private copy ignores later writes", byte(p, 0), 0));
    unmap(p, page);

    unmap(b, 2 * page);
    poke(a, 4, b'!');
    unmap(a, 2 * page);
    close(other);
    out.push(("unmapped write kept", file_bytes(fd, 5, 0), 0));
    let st = stat(fd);
    out.push(("size", st.st_size, 0));
    close(fd);

    let fd = open(path, libc::O_RDWR);
    let a = map(page, rw, shared, fd, 0);
    close(fd);
    poke(a, 0, b'C');
    let fd = open(path, libc::O_RDONLY);
    out.push(("mapping outlives its descriptor", file_bytes(fd, 1, 0), 0));
    close(fd);
    unmap(a, page);
    out
}

fn times(path: &CStr, page: usize) -> Vec<Seen> {
    let (rw, shared) = (libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED);
    let mut out = Vec::new();
    let fd = open(path, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC);
    pwrite(fd, b"times", 0);
    age(fd);
    let a = map(page, libc::PROT_READ, shared, fd, 0);
    let st = stat(fd);
    out.push(("map marks access", i64::from(st.st_atime != 1000), 0));
    out.push(("map leaves modification", i64::from(st.st_mtime != 2000), 0));
    unmap(a, page);

    age(fd);
    let a = map(page, rw, shared, fd, 0);
    poke(a, 0, b'T');
    assert_eq!(unsafe { libc::msync(a.cast(), page, libc::MS_SYNC) }, 0);
    let st = stat(fd);
    out.push((
        "written mapping marks modification",
        i64::from(st.st_mtime != 2000),
        0,
    ));
    unmap(a, page);
    close(fd);
    out
}

fn observe(dir: &Path, page: usize) -> Vec<Seen> {
    let path = |name: &str| CString::new(dir.join(name).into_os_string().into_encoded_bytes());
    let dir = CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
    let mut out = errors(&path("errors").unwrap(), &dir, page);
    out.extend(coherence(&path("coherence").unwrap(), page));
    out.extend(times(&path("times").unwrap(), page));
    out
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("snare-mmap-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

#[test]
fn mapped_files_match_the_host() {
    let dir = scratch("truth");
    let page = page_size();
    let real = snare::real(|| observe(&dir, page));
    let fs = FsBuilder::new().dir(dir.to_str().unwrap()).build();
    let simulated = Sim::builder().fs(fs).build().run(|| observe(&dir, page));
    std::fs::remove_dir_all(&dir).ok();
    for (real, simulated) in real.iter().zip(&simulated) {
        assert_eq!(simulated, real);
    }
    assert_eq!(simulated.len(), real.len());
}

/// The second page of a two-page mapping of a one-byte file lies wholly past the end, so touching
/// it raises `SIGBUS` (man 2 mmap). Run in a child process, which the signal kills.
fn touch_past_the_end(path: &CStr) {
    let page = page_size();
    let fd = open(path, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC);
    pwrite(fd, b"x", 0);
    let a = map(2 * page, libc::PROT_READ, libc::MAP_SHARED, fd, 0);
    assert_eq!(byte(a, 0), i64::from(b'x'));
    assert_eq!(byte(a, page - 1), 0);
    byte(a, page);
}

const CHILD: &str = "SNARE_MMAP_SIGBUS_CHILD";

#[test]
fn touching_a_page_past_the_end_raises_sigbus() {
    if let Ok(side) = std::env::var(CHILD) {
        if side == "sim" {
            let fs = FsBuilder::new().dir("/mapped").build();
            Sim::builder()
                .fs(fs)
                .build()
                .run(|| touch_past_the_end(c"/mapped/short"));
        } else {
            touch_past_the_end(&CString::new(side).unwrap());
        }
        return;
    }
    use std::os::unix::process::ExitStatusExt;
    let dir = scratch("sigbus");
    let host = dir.join("short").into_os_string().into_string().unwrap();
    for side in [host.as_str(), "sim"] {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "touching_a_page_past_the_end_raises_sigbus",
                "--test-threads=1",
            ])
            .env(CHILD, side)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(libc::SIGBUS), "{side}: {status}");
    }
    std::fs::remove_dir_all(&dir).ok();
}
