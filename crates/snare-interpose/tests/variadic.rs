//! The variadic libc entry points (`ioctl`, `open`, `openat`, `fcntl`) must hand the backend the
//! exact third argument the caller passed. On macOS aarch64 that argument travels on the stack, so
//! these tests fail loudly if the hook reads it from the wrong place.

#![cfg(unix)]

use std::ffi::{CString, c_char, c_int};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use snare_interpose::{Domain, Fs, NetResult};

const OWNED_FD: c_int = 4242;
const SENTINEL: u64 = 0x0123_4567_89ab_cdef;

#[derive(Default)]
struct Recorder {
    ioctl_arg: AtomicI64,
    ioctl_sentinel: AtomicI64,
    open_mode: AtomicI64,
    openat_mode: AtomicI64,
    fcntl_arg: AtomicI64,
}

impl Fs for Recorder {
    fn owns(&self, fd: c_int) -> bool {
        fd == OWNED_FD
    }

    unsafe fn open(&self, _path: *const c_char, _flags: c_int, mode: u32) -> Option<NetResult> {
        self.open_mode.store(i64::from(mode), Ordering::SeqCst);
        Some(NetResult::Ok(OWNED_FD as i64))
    }

    unsafe fn openat(
        &self,
        _dirfd: c_int,
        _path: *const c_char,
        _flags: c_int,
        mode: u32,
    ) -> Option<NetResult> {
        self.openat_mode.store(i64::from(mode), Ordering::SeqCst);
        Some(NetResult::Ok(OWNED_FD as i64))
    }

    unsafe fn ioctl(&self, _fd: c_int, _request: u64, arg: i64) -> Option<NetResult> {
        self.ioctl_arg.store(arg, Ordering::SeqCst);
        // SAFETY: the test passes a pointer to a live `u64`; reading it proves the whole pointer
        // arrived, not just a value that happens to match.
        let seen = unsafe { *(arg as *const u64) };
        self.ioctl_sentinel.store(seen as i64, Ordering::SeqCst);
        Some(NetResult::Ok(0))
    }

    unsafe fn fcntl(&self, _fd: c_int, _cmd: c_int, arg: i64) -> Option<NetResult> {
        self.fcntl_arg.store(arg, Ordering::SeqCst);
        Some(NetResult::Ok(0))
    }
}

fn domain(recorder: Arc<Recorder>) -> Domain {
    Domain::builder().fs(recorder).install()
}

#[test]
fn ioctl_receives_the_exact_pointer() {
    let recorder = Arc::new(Recorder::default());
    let domain = domain(recorder.clone());
    let cell: u64 = SENTINEL;
    let request: libc::c_ulong = 0x8020_426c; // BIOCSETIF, from the field report
    let ptr = &cell as *const u64;
    domain.run(|| {
        // SAFETY: `OWNED_FD` is serviced entirely by the backend; the pointer is live.
        let rc = unsafe { libc::ioctl(OWNED_FD, request, ptr) };
        assert_eq!(rc, 0);
    });
    assert_eq!(recorder.ioctl_arg.load(Ordering::SeqCst), ptr as i64);
    assert_eq!(
        recorder.ioctl_sentinel.load(Ordering::SeqCst) as u64,
        SENTINEL
    );
}

#[test]
fn open_receives_the_creat_mode() {
    let recorder = Arc::new(Recorder::default());
    let domain = domain(recorder.clone());
    let path = CString::new("/snare-interpose/variadic-open").unwrap();
    domain.run(|| {
        // SAFETY: the backend claims the path and returns a fd without touching the real FS.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY,
                0o640 as libc::c_uint,
            )
        };
        assert_eq!(fd, OWNED_FD);
    });
    assert_eq!(recorder.open_mode.load(Ordering::SeqCst), 0o640);
}

#[test]
fn openat_receives_the_creat_mode() {
    let recorder = Arc::new(Recorder::default());
    let domain = domain(recorder.clone());
    let path = CString::new("/snare-interpose/variadic-openat").unwrap();
    domain.run(|| {
        // SAFETY: as for `open`.
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                path.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY,
                0o640 as libc::c_uint,
            )
        };
        assert_eq!(fd, OWNED_FD);
    });
    assert_eq!(recorder.openat_mode.load(Ordering::SeqCst), 0o640);
}

#[test]
fn fcntl_receives_the_flag_argument() {
    let recorder = Arc::new(Recorder::default());
    let domain = domain(recorder.clone());
    domain.run(|| {
        // SAFETY: `OWNED_FD` is serviced by the backend; F_SETFL takes an int.
        let rc = unsafe { libc::fcntl(OWNED_FD, libc::F_SETFL, libc::O_NONBLOCK) };
        assert_eq!(rc, 0);
    });
    // F_SETFL's argument is an `int`; the low word is what libc would read.
    assert_eq!(
        recorder.fcntl_arg.load(Ordering::SeqCst) as i32,
        libc::O_NONBLOCK
    );
}
