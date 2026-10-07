//! Descriptors that outlive the sim that made them. A kernel object of the process (an eventfd, a
//! timerfd, an epoll set, a kqueue) belongs to the process, which a test binary keeps across the
//! sims it builds: a later sim that reaches one takes it over, timers keeping the time they had
//! left. A socket belongs to its sim's network, so another sim reaching it finds a connection
//! that is gone (a reset, then end of stream, `EPIPE` and a hang-up), never the OS's placeholder
//! behind it, and closing it there ends it in the sim that made it; a socketpair end has no
//! network, so another sim reaching it gets an instance of the pair of its own, and a thread
//! outside every sim the real pair behind it. Once such a descriptor is closed, its number is the
//! OS's again, for whatever real file it hands out next.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
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

/// A connected TCP pair made in `sim`, as raw descriptors: the connecting end and the accepted
/// one.
fn connection_in(sim: &Sim) -> (i32, i32) {
    sim.run(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client.into_raw_fd(), server.into_raw_fd())
    })
}

/// What a connection that is gone answers: the hang-up of a `poll` that must not wait, the first
/// write, a second one, a read and `getpeername`, each with its errno.
fn gone_connection(fd: i32) -> Vec<(isize, i32)> {
    let mut seen = Vec::new();
    let mut record = |result: isize| seen.push((result, if result < 0 { errno() } else { 0 }));
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLOUT,
        revents: 0,
    };
    let polled = unsafe { libc::poll(&mut pfd, 1, -1) };
    record(if polled == 1 {
        (pfd.revents & libc::POLLHUP) as isize
    } else {
        -1
    });
    record(unsafe { libc::write(fd, b"hello".as_ptr().cast(), 5) });
    record(unsafe { libc::write(fd, b"hello".as_ptr().cast(), 5) });
    let mut buf = [0u8; 8];
    record(unsafe { libc::read(fd, buf.as_mut_ptr().cast(), 8) });
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    record(unsafe {
        libc::getpeername(
            fd,
            (&mut addr as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    } as isize);
    seen
}

fn expected_gone() -> Vec<(isize, i32)> {
    vec![
        (libc::POLLHUP as isize, 0),
        (-1, libc::ECONNRESET),
        (-1, libc::EPIPE),
        (0, 0),
        (-1, libc::ENOTCONN),
    ]
}

#[test]
fn another_sims_socket_is_a_connection_that_is_gone() {
    let _turn = one_at_a_time();
    let first = Sim::new();
    let (client, server) = connection_in(&first);
    let seen = Sim::new().run(|| {
        let seen = gone_connection(client);
        (seen, unsafe { libc::close(client) })
    });
    assert_eq!(seen, (expected_gone(), 0));
    let (read, peer_errno) = first.run(|| {
        let mut buf = [0u8; 4];
        let read = unsafe { libc::read(server, buf.as_mut_ptr().cast(), 4) };
        let peer_errno = if read < 0 { errno() } else { 0 };
        unsafe { libc::close(server) };
        (read, peer_errno)
    });
    assert_eq!(
        (read, peer_errno),
        (0, 0),
        "its peer in the sim that made it sees the connection end"
    );
    real_file_at(client);
    assert_eq!(
        read_in_a_sim(client),
        (1, b'x', 0),
        "its number is the OS's again"
    );
}

#[test]
fn a_gone_sims_socket_is_a_connection_that_is_gone() {
    let _turn = one_at_a_time();
    let first = Sim::new();
    let (client, _server) = connection_in(&first);
    let udp = first.run(|| UdpSocket::bind("127.0.0.1:0").unwrap().into_raw_fd());
    drop(first);
    let seen = Sim::new().run(|| {
        let seen = gone_connection(client);
        let written = unsafe { libc::write(udp, b"hello".as_ptr().cast(), 5) };
        let udp_errno = if written < 0 { errno() } else { 0 };
        let closed = unsafe { [libc::close(client), libc::close(udp)] };
        (seen, (written, udp_errno), closed)
    });
    assert_eq!(seen, (expected_gone(), (-1, libc::ECONNRESET), [0, 0]));
    real_file_at(client);
    assert_eq!(read_in_a_sim(client), (1, b'x', 0));
}

#[test]
fn another_sims_stream_drops_without_aborting() {
    let _turn = one_at_a_time();
    static KEPT: std::sync::Mutex<Option<TcpStream>> = std::sync::Mutex::new(None);
    let first = Sim::new();
    let (client, server) = connection_in(&first);
    *KEPT.lock().unwrap() = Some(unsafe { TcpStream::from_raw_fd(client) });
    Sim::new().run(|| {
        let mut kept = KEPT.lock().unwrap().take().unwrap();
        assert_eq!(
            kept.write(b"x").unwrap_err().kind(),
            std::io::ErrorKind::ConnectionReset
        );
        assert_eq!(kept.read(&mut [0u8; 4]).unwrap(), 0);
        drop(kept);
    });
    first.run(|| {
        let mut server = unsafe { TcpStream::from_raw_fd(server) };
        assert_eq!(server.read(&mut [0u8; 4]).unwrap(), 0);
    });
}

#[test]
fn a_socket_closed_outside_every_sim_ends_its_connection() {
    let _turn = one_at_a_time();
    let first = Sim::new();
    let (client, server) = connection_in(&first);
    assert_eq!(unsafe { libc::close(client) }, 0);
    first.run(|| {
        let mut server = unsafe { TcpStream::from_raw_fd(server) };
        assert_eq!(server.read(&mut [0u8; 4]).unwrap(), 0);
    });
    real_file_at(client);
    assert_eq!(read_in_a_sim(client), (1, b'x', 0));
}

/// A sim's socket reached from a thread outside every sim, where no hook serves it, is a peer that
/// has gone: a write fails rather than vanishing, and a read is at end of file.
#[test]
fn a_sim_socket_reached_outside_every_sim_fails_loudly() {
    let _turn = one_at_a_time();
    let sim = Sim::new();
    let fd = sim.run(|| UdpSocket::bind("127.0.0.1:0").unwrap().into_raw_fd());
    let written = unsafe { libc::write(fd, b"hello".as_ptr().cast(), 5) };
    assert_eq!((written, errno()), (-1, libc::EBADF));
    let mut buf = [0u8; 4];
    assert_eq!(unsafe { libc::read(fd, buf.as_mut_ptr().cast(), 4) }, 0);
    sim.run(|| assert_eq!(unsafe { libc::close(fd) }, 0));
}

#[test]
fn a_socketpair_made_in_a_sim_is_a_real_pair_outside_every_sim() {
    let _turn = one_at_a_time();
    let sim = Sim::new();
    let (a, b) = sim.run(|| {
        let (a, b) = UnixStream::pair().unwrap();
        unsafe { libc::write(a.as_raw_fd(), b"sim".as_ptr().cast(), 3) };
        (a.into_raw_fd(), b.into_raw_fd())
    });
    let (mut a, mut b) = unsafe { (UnixStream::from_raw_fd(a), UnixStream::from_raw_fd(b)) };
    a.write_all(b"outside").unwrap();
    let mut got = [0u8; 7];
    b.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"outside", "the sim's bytes stay in its world");
    let clone = b.try_clone().unwrap();
    drop(b);
    a.write_all(b"!").unwrap();
    assert_eq!((&clone).read(&mut got[..1]).unwrap(), 1);
    drop(sim);
}

#[test]
fn a_tokio_runtime_builds_outside_every_sim_after_one_built_in_a_sim() {
    let _turn = one_at_a_time();
    let build = || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    };
    Sim::new().run(|| {
        let runtime = build().unwrap();
        runtime.block_on(async { tokio::time::sleep(std::time::Duration::from_millis(1)).await });
    });
    let runtime = build().expect("a runtime outside every sim");
    runtime.block_on(async { tokio::time::sleep(std::time::Duration::from_millis(1)).await });
}

#[test]
fn another_sims_socketpair_is_this_sims_own() {
    let _turn = one_at_a_time();
    let first = Sim::new();
    let (a, b) = first.run(|| {
        let (a, b) = UnixStream::pair().unwrap();
        unsafe { libc::write(a.as_raw_fd(), b"first".as_ptr().cast(), 5) };
        (a.into_raw_fd(), b.into_raw_fd())
    });
    let check = || {
        Sim::new().run(|| {
            let written = unsafe { libc::write(a, b"hello".as_ptr().cast(), 5) };
            let written = (written, errno());
            let mut buf = [0u8; 8];
            let read = unsafe { libc::read(b, buf.as_mut_ptr().cast(), 8) };
            (written.0, read, buf[..read.max(0) as usize].to_vec())
        })
    };
    let expected = (5, 5, b"hello".to_vec());
    assert_eq!(check(), expected, "the first sim's bytes stay in its world");
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
