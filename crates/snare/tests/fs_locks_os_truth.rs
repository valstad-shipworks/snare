//! Advisory file locks against the host: the same `fcntl` record-lock and `flock` calls on a real
//! temporary file and on a `VirtualFs` file must return the same results, errnos and `F_GETLK`
//! reports. Process locks never conflict within the process and go when any descriptor of the
//! file closes; open-file-description locks and `flock` locks conflict between two opens and go
//! with the description's last descriptor. A blocked `F_OFD_SETLKW` or `flock` waits on the sim's
//! clock.
#![cfg(unix)]

use std::ffi::{CStr, CString, c_int};
use std::path::Path;
use std::time::{Duration, Instant};

use snare::{FsBuilder, Sim};

/// A call's label, return, errno when it failed, and, for a lock query, the reported
/// `(l_type, l_whence, l_start, l_len, l_pid)` with this process's pid as `1`.
type Seen = (
    &'static str,
    c_int,
    c_int,
    Option<(c_int, c_int, i64, i64, i32)>,
);

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn seen(label: &'static str, result: c_int) -> Seen {
    (label, result, if result < 0 { errno() } else { 0 }, None)
}

fn flock_of(kind: c_int, whence: c_int, start: i64, len: i64) -> libc::flock {
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = kind as _;
    lock.l_whence = whence as _;
    lock.l_start = start;
    lock.l_len = len;
    lock
}

fn set(label: &'static str, fd: c_int, cmd: c_int, kind: c_int, at: (c_int, i64, i64)) -> Seen {
    let mut lock = flock_of(kind, at.0, at.1, at.2);
    seen(label, unsafe { libc::fcntl(fd, cmd, &mut lock) })
}

fn get(label: &'static str, fd: c_int, cmd: c_int, kind: c_int, start: i64, len: i64) -> Seen {
    let mut lock = flock_of(kind, libc::SEEK_SET, start, len);
    let result = unsafe { libc::fcntl(fd, cmd, &mut lock) };
    let pid = if lock.l_pid == unsafe { libc::getpid() } {
        1
    } else {
        lock.l_pid
    };
    let report = (result >= 0).then_some((
        c_int::from(lock.l_type),
        c_int::from(lock.l_whence),
        lock.l_start,
        lock.l_len,
        pid,
    ));
    (label, result, if result < 0 { errno() } else { 0 }, report)
}

fn flock(label: &'static str, fd: c_int, operation: c_int) -> Seen {
    seen(label, unsafe { libc::flock(fd, operation) })
}

fn open(path: &CStr, flags: c_int) -> c_int {
    let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CREAT, 0o600) };
    assert!(fd >= 0, "open: {}", errno());
    fd
}

fn close(fd: c_int) {
    assert_eq!(unsafe { libc::close(fd) }, 0);
}

const W: c_int = libc::F_WRLCK as c_int;
const R: c_int = libc::F_RDLCK as c_int;
const U: c_int = libc::F_UNLCK as c_int;
const SET: c_int = libc::SEEK_SET;

fn records(path: &CStr) -> Vec<Seen> {
    use libc::{F_GETLK, F_OFD_GETLK, F_OFD_SETLK, F_SETLK};
    let mut out = Vec::new();
    let a = open(path, libc::O_RDWR | libc::O_TRUNC);
    assert_eq!(
        unsafe { libc::write(a, b"0123456789".as_ptr().cast(), 10) },
        10
    );
    let b = open(path, libc::O_RDWR);

    out.push(set("process lock", a, F_SETLK, W, (SET, 0, 10)));
    out.push(set("process lock again", b, F_SETLK, W, (SET, 0, 10)));
    out.push(get("process query", b, F_GETLK, W, 0, 10));
    out.push(set("ofd over process", a, F_OFD_SETLK, W, (SET, 0, 5)));
    out.push(get("ofd query of process", b, F_OFD_GETLK, W, 0, 5));
    close(b);
    out.push(get("process gone on close", a, F_OFD_GETLK, W, 0, 0));

    let b = open(path, libc::O_RDWR);
    out.push(set("ofd lock", a, F_OFD_SETLK, W, (SET, 0, 5)));
    out.push(set("ofd conflict", b, F_OFD_SETLK, W, (SET, 3, 5)));
    out.push(get("ofd query of ofd", b, F_OFD_GETLK, R, 3, 5));
    out.push(get("process query of ofd", b, F_GETLK, R, 0, 0));
    out.push(set("process over ofd", b, F_SETLK, R, (SET, 4, 1)));
    out.push(set("ofd split", a, F_OFD_SETLK, U, (SET, 1, 2)));
    out.push(get("left of split", b, F_OFD_GETLK, W, 0, 0));
    out.push(get("right of split", b, F_OFD_GETLK, W, 1, 0));
    assert_eq!(unsafe { libc::lseek(a, 4, libc::SEEK_SET) }, 4);
    out.push(set(
        "ofd from cursor",
        a,
        F_OFD_SETLK,
        R,
        (libc::SEEK_CUR, 0, 2),
    ));
    out.push(get("converted", b, F_OFD_GETLK, W, 4, 0));
    out.push(get("shared", b, F_OFD_GETLK, R, 4, 0));
    out.push(set(
        "ofd from end",
        a,
        F_OFD_SETLK,
        W,
        (libc::SEEK_END, -2, 2),
    ));
    out.push(get("from end", b, F_OFD_GETLK, R, 7, 0));
    out.push(set("ofd backwards", a, F_OFD_SETLK, W, (SET, 20, -5)));
    out.push(get("backwards", b, F_OFD_GETLK, R, 12, 0));
    out.push(set("ofd to end", a, F_OFD_SETLK, R, (SET, 30, 0)));
    out.push(get("to end", b, F_OFD_GETLK, W, 1000, 1));
    out.push(set("ofd adjacent", a, F_OFD_SETLK, R, (SET, 25, 5)));
    out.push(get("merged", b, F_OFD_GETLK, W, 1000, 1));

    let read_only = open(path, libc::O_RDONLY);
    let write_only = open(path, libc::O_WRONLY);
    out.push(set(
        "write lock read-only",
        read_only,
        F_SETLK,
        W,
        (SET, 50, 1),
    ));
    out.push(set(
        "ofd write lock read-only",
        read_only,
        F_OFD_SETLK,
        W,
        (SET, 50, 1),
    ));
    out.push(set(
        "read lock write-only",
        write_only,
        F_SETLK,
        R,
        (SET, 50, 1),
    ));
    out.push(set("bad type", a, F_SETLK, 5, (SET, 50, 1)));
    out.push(set("bad whence", a, F_SETLK, W, (7, 50, 1)));
    out.push(set("negative start", a, F_SETLK, W, (SET, -1, 1)));
    out.push(set("backwards past zero", a, F_SETLK, W, (SET, 2, -5)));
    close(read_only);
    close(write_only);

    let alias = unsafe { libc::dup(a) };
    close(a);
    out.push(get("ofd kept by alias", b, F_OFD_GETLK, W, 0, 0));
    close(alias);
    out.push(get("ofd gone with description", b, F_OFD_GETLK, W, 0, 0));
    close(b);
    out
}

fn flocks(path: &CStr) -> Vec<Seen> {
    let (ex, sh, nb) = (libc::LOCK_EX, libc::LOCK_SH, libc::LOCK_NB);
    let mut out = Vec::new();
    let c = open(path, libc::O_RDWR);
    let d = open(path, libc::O_RDONLY);
    out.push(flock("exclusive", c, ex | nb));
    out.push(flock("exclusive again", c, ex | nb));
    out.push(flock("exclusive conflict", d, ex | nb));
    out.push(flock("shared conflict", d, sh | nb));
    out.push(flock("unlock", c, libc::LOCK_UN));
    out.push(flock("shared", c, sh | nb));
    out.push(flock("shared too", d, sh | nb));
    close(c);
    out.push(flock("upgrade after close", d, ex | nb));
    let alias = unsafe { libc::dup(d) };
    close(d);
    let f = open(path, libc::O_RDWR);
    out.push(flock("kept by alias", f, sh | nb));
    close(alias);
    out.push(flock("gone with description", f, sh | nb));
    out.push(flock("bad operation", f, 0));
    close(f);
    out
}

fn observe(dir: &Path) -> Vec<Seen> {
    let path = |name: &str| CString::new(dir.join(name).into_os_string().into_encoded_bytes());
    let mut out = records(&path("records").unwrap());
    out.extend(flocks(&path("flock").unwrap()));
    out
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("snare-locks-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn file_locks_match_the_host() {
    let dir = scratch("truth");
    let real = snare::real(|| observe(&dir));
    let fs = FsBuilder::new().dir(dir.to_str().unwrap()).build();
    let simulated = Sim::builder().fs(fs).build().run(|| observe(&dir));
    std::fs::remove_dir_all(&dir).ok();
    for (real, simulated) in real.iter().zip(&simulated) {
        assert_eq!(simulated, real);
    }
    assert_eq!(simulated.len(), real.len());
}

/// One thread holds an OFD lock for a virtual second and a `flock` lock for another; a second
/// thread blocks on each and gets it when it is let go, without waiting in real time.
fn blocked_waits(sim: Sim) {
    sim.run(|| {
        let holder = open(c"/locks/records", libc::O_RDWR);
        let waiter = open(c"/locks/records", libc::O_RDWR);
        let flock_holder = open(c"/locks/flock", libc::O_RDONLY);
        let flock_waiter = open(c"/locks/flock", libc::O_RDONLY);
        assert_eq!(set("hold", holder, libc::F_OFD_SETLK, W, (SET, 0, 0)).1, 0);
        assert_eq!(flock("hold", flock_holder, libc::LOCK_EX).1, 0);
        let start = Instant::now();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(1));
            close(holder);
            std::thread::sleep(Duration::from_secs(1));
            assert_eq!(flock("release", flock_holder, libc::LOCK_UN).1, 0);
        });
        assert_eq!(set("wait", waiter, libc::F_OFD_SETLKW, W, (SET, 0, 0)).1, 0);
        assert!(start.elapsed() >= Duration::from_secs(1));
        assert_eq!(flock("wait", flock_waiter, libc::LOCK_EX).1, 0);
        assert!(start.elapsed() >= Duration::from_secs(2));
        release.join().unwrap();
        close(waiter);
        close(flock_holder);
        close(flock_waiter);
    });
}

fn locks_fs() -> std::sync::Arc<snare::VirtualFs> {
    FsBuilder::new().dir("/locks").build()
}

#[test]
fn a_blocked_lock_waits_on_the_sim_clock() {
    let real = Instant::now();
    blocked_waits(Sim::builder().fs(locks_fs()).build());
    assert!(real.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_blocked_lock_waits_in_a_deterministic_schedule() {
    let real = Instant::now();
    blocked_waits(
        Sim::builder()
            .deterministic()
            .seed(7)
            .fs(locks_fs())
            .build(),
    );
    assert!(real.elapsed() < Duration::from_secs(2));
}
