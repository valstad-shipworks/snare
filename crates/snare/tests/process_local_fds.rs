//! Descriptors that outlive the sim that made them. A kernel object of the process (an eventfd, a
//! timerfd, an epoll set, a kqueue) belongs to the process, which a test binary keeps across the
//! sims it builds: a later sim that reaches one takes it over, timers keeping the time they had
//! left. A socket belongs to its sim's network, so another sim reaching it gets `EBADF`, as for
//! a descriptor its world never opened, never the OS's placeholder behind it. Once such a
//! descriptor is closed, its number is the OS's again, for whatever real file it hands out next.

#![cfg(unix)]

use std::net::UdpSocket;
use std::os::fd::IntoRawFd;
use std::os::unix::net::UnixStream;

use snare::Sim;

/// Held by every test here: the ones that reuse a descriptor number need no other test opening
/// descriptors meanwhile.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

/// Opens a real file holding one byte, `b'x'`, under descriptor number `fd`, which must be free:
/// the OS hands out the lowest free number, so files are opened until one lands on it.
fn real_file_at(fd: i32) {
    let path = std::env::temp_dir().join(format!("snare-reuse-{}-{fd}", std::process::id()));
    std::fs::write(&path, b"x").unwrap();
    let path = std::ffi::CString::new(path.into_os_string().into_encoded_bytes()).unwrap();
    let mut extra = Vec::new();
    loop {
        let opened = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
        assert!(opened >= 0 && opened <= fd, "{fd} was not free");
        if opened == fd {
            break;
        }
        extra.push(opened);
    }
    for opened in extra {
        unsafe { libc::close(opened) };
    }
    unsafe { libc::unlink(path.as_ptr()) };
}

/// What a sim reads from `fd`, and the errno.
fn read_in_a_sim(fd: i32) -> (isize, u8, i32) {
    Sim::new().run(|| {
        let mut byte = 0u8;
        let read = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
        let errno = if read < 0 { errno() } else { 0 };
        unsafe { libc::close(fd) };
        (read, byte, errno)
    })
}

#[test]
fn a_socket_closed_outside_its_sim_frees_its_number() {
    let _turn = one_at_a_time();
    let sim = Sim::new();
    let bind = || sim.run(|| UdpSocket::bind("127.0.0.1:0").unwrap().into_raw_fd());
    let (before, after) = (bind(), bind());
    unsafe { libc::close(before) };
    drop(sim);
    real_file_at(before);
    assert_eq!(read_in_a_sim(before), (1, b'x', 0));
    unsafe { libc::close(after) };
    real_file_at(after);
    assert_eq!(read_in_a_sim(after), (1, b'x', 0));
}

#[test]
fn another_sims_socket_is_ebadf() {
    let _turn = one_at_a_time();
    let first = Sim::new();
    let (a, b) = first.run(|| {
        let (a, b) = UnixStream::pair().unwrap();
        (a.into_raw_fd(), b.into_raw_fd())
    });
    let check = || {
        Sim::new().run(|| {
            let written = unsafe { libc::write(a, b"hello".as_ptr().cast(), 5) };
            let written = (written, errno());
            let mut buf = [0u8; 8];
            let read = unsafe { libc::read(b, buf.as_mut_ptr().cast(), 8) };
            (written, (read, errno()))
        })
    };
    let expected = ((-1, libc::EBADF), (-1, libc::EBADF));
    assert_eq!(check(), expected);
    drop(first);
    assert_eq!(check(), expected);
}

#[cfg(target_os = "linux")]
#[test]
fn an_eventfd_outlives_its_sim() {
    let _turn = one_at_a_time();
    let fd = Sim::new().run(|| {
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
        let three = 3u64;
        assert_eq!(
            unsafe { libc::write(fd, (&three as *const u64).cast(), 8) },
            8
        );
        fd
    });
    let value = Sim::new().run(|| {
        let mut value = 0u64;
        assert_eq!(
            unsafe { libc::read(fd, (&mut value as *mut u64).cast(), 8) },
            8
        );
        unsafe { libc::close(fd) };
        value
    });
    assert_eq!(value, 3);
}

#[cfg(target_os = "linux")]
#[test]
fn a_timerfd_keeps_its_time_left() {
    let _turn = one_at_a_time();
    use std::time::{Duration, Instant};

    let fd = Sim::new().run(|| {
        let fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0) };
        let arm = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: 0,
                tv_nsec: 80_000_000,
            },
        };
        unsafe { libc::timerfd_settime(fd, 0, &arm, std::ptr::null_mut()) };
        std::thread::sleep(Duration::from_millis(30));
        fd
    });
    let (ticks, waited) = Sim::new().run(|| {
        let start = Instant::now();
        let mut ticks = 0u64;
        assert_eq!(
            unsafe { libc::read(fd, (&mut ticks as *mut u64).cast(), 8) },
            8
        );
        unsafe { libc::close(fd) };
        (ticks, start.elapsed())
    });
    assert_eq!(ticks, 1);
    assert!(
        waited >= Duration::from_millis(50) && waited < Duration::from_millis(80),
        "the read waited {waited:?}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn a_kqueue_outlives_its_sim() {
    let _turn = one_at_a_time();
    fn user(flags: u16, fflags: u32) -> libc::kevent {
        libc::kevent {
            ident: 1,
            filter: libc::EVFILT_USER,
            flags,
            fflags,
            data: 0,
            udata: 7 as *mut _,
        }
    }
    let kq = Sim::new().run(|| {
        let kq = unsafe { libc::kqueue() };
        let add = user(libc::EV_ADD | libc::EV_CLEAR, 0);
        let none = std::ptr::null_mut();
        assert_eq!(
            unsafe { libc::kevent(kq, &add, 1, none, 0, std::ptr::null()) },
            0
        );
        kq
    });
    let fired = Sim::new().run(|| {
        let trigger = user(0, libc::NOTE_TRIGGER);
        let mut out = user(0, 0);
        let n = unsafe { libc::kevent(kq, &trigger, 1, &mut out, 1, std::ptr::null()) };
        unsafe { libc::close(kq) };
        (n, out.udata as usize)
    });
    assert_eq!(fired, (1, 7));
}

#[test]
fn a_process_local_descriptor_closed_outside_a_sim_frees_its_number() {
    let _turn = one_at_a_time();
    #[cfg(target_os = "linux")]
    let make = || unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
    #[cfg(not(target_os = "linux"))]
    let make = || unsafe { libc::kqueue() };
    let fd = Sim::new().run(make);
    unsafe { libc::close(fd) };
    real_file_at(fd);
    assert_eq!(read_in_a_sim(fd), (1, b'x', 0));
}
