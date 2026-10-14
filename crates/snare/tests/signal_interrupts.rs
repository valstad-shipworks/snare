//! A signal handler running on a thread blocked in a call, against the host: the same program, a
//! thread blocked in each call and `pthread_kill(SIGINT)` aimed at it, run on the real OS and in
//! a sim must see each call fail with `EINTR` or go on alike, with and without `SA_RESTART`
//! (man 7 signal, "Interruption of system calls and library functions by signal handlers"), and
//! what the call's thread sees of it afterwards alike.
#![cfg(unix)]

use std::ffi::{CString, c_int};
use std::io::Write;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::unix::thread::JoinHandleExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use snare::{FsBuilder, Sim};

fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

static HANDLED: AtomicUsize = AtomicUsize::new(0);

extern "C" fn count(_: c_int) {
    HANDLED.fetch_add(1, Ordering::SeqCst);
}

fn install(sig: c_int, restart: bool) -> libc::sigaction {
    // SAFETY: an all-zero sigaction is valid; the calls fill the mask and read the old action.
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = count as *const () as libc::sighandler_t;
        act.sa_flags = if restart { libc::SA_RESTART } else { 0 };
        libc::sigemptyset(&mut act.sa_mask);
        let mut old: libc::sigaction = std::mem::zeroed();
        assert_eq!(libc::sigaction(sig, &act, &mut old), 0);
        old
    }
}

fn restore(sig: c_int, old: &libc::sigaction) {
    // SAFETY: putting back an action `install` read.
    assert_eq!(
        unsafe { libc::sigaction(sig, old, std::ptr::null_mut()) },
        0
    );
}

/// How a blocked call ended once its thread's handler had run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    /// -1 with `EINTR`.
    Interrupted,
    /// Went on and finished once released.
    Completed,
    /// Failed otherwise, with this errno.
    Failed(c_int),
}

/// A call's result as `(return, errno)`.
type Call = Box<dyn FnOnce() -> (isize, c_int) + Send>;

/// What a call's thread saw after the call, as `(return, errno)` of further calls: a second
/// `connect` after an interrupted one.
static AFTER: Mutex<Vec<(isize, c_int)>> = Mutex::new(Vec::new());

fn after(seen: (isize, c_int)) {
    AFTER.lock().unwrap().push(seen);
}

/// A call that blocks, and what lets it finish once it goes on.
type Scenario = (Call, Box<dyn FnOnce()>);

fn result(r: isize) -> (isize, c_int) {
    (r, if r < 0 { errno() } else { 0 })
}

/// Runs `call` on a thread of its own, sends that thread `SIGINT` once it has had 50 ms to block,
/// and 50 ms later runs `release`, which lets a call that went on finish.
fn interrupt(call: Call, release: Box<dyn FnOnce()>) -> (Ended, usize, Vec<(isize, c_int)>) {
    AFTER.lock().unwrap().clear();
    let before = HANDLED.load(Ordering::SeqCst);
    let thread = std::thread::spawn(call);
    std::thread::sleep(Duration::from_millis(50));
    // SAFETY: the thread runs until joined below.
    assert_eq!(
        unsafe { libc::pthread_kill(thread.as_pthread_t(), libc::SIGINT) },
        0
    );
    std::thread::sleep(Duration::from_millis(50));
    release();
    let (r, e) = thread.join().unwrap();
    let ended = match (r, e) {
        (r, _) if r >= 0 => Ended::Completed,
        (_, libc::EINTR) => Ended::Interrupted,
        (_, e) => Ended::Failed(e),
    };
    let seen = std::mem::take(&mut *AFTER.lock().unwrap());
    (ended, HANDLED.load(Ordering::SeqCst) - before, seen)
}

fn socketpair() -> [c_int; 2] {
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for both ends.
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
        0
    );
    fds
}

fn write_byte(fd: c_int) {
    // SAFETY: one byte from a static.
    assert_eq!(unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) }, 1);
}

fn recv_byte(fd: c_int) -> (isize, c_int) {
    let mut byte = 0u8;
    // SAFETY: one byte into `byte`.
    result(unsafe { libc::recv(fd, (&raw mut byte).cast(), 1, 0) })
}

fn set_rcvtimeo(fd: c_int, span: Duration) {
    set_timeout(fd, libc::SO_RCVTIMEO, span);
}

fn set_timeout(fd: c_int, name: c_int, span: Duration) {
    let tv = libc::timeval {
        tv_sec: span.as_secs() as _,
        tv_usec: span.subsec_micros() as _,
    };
    // SAFETY: a timeval of the size given.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                name,
                (&raw const tv).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        },
        0
    );
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

fn socketpair_recv() -> Scenario {
    let [a, b] = socketpair();
    (
        Box::new(move || recv_byte(a)),
        Box::new(move || write_byte(b)),
    )
}

fn tcp_recv(timeout: bool) -> Scenario {
    let (mut client, server) = tcp_pair();
    if timeout {
        set_rcvtimeo(server.as_raw_fd(), Duration::from_secs(5));
    }
    (
        Box::new(move || recv_byte(server.as_raw_fd())),
        Box::new(move || client.write_all(b"x").unwrap()),
    )
}

fn udp_recv() -> Scenario {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let to = socket.local_addr().unwrap();
    (
        Box::new(move || recv_byte(socket.as_raw_fd())),
        Box::new(move || {
            UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .send_to(b"x", to)
                .unwrap();
        }),
    )
}

fn accept(timeout: bool) -> Scenario {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let to = listener.local_addr().unwrap();
    if timeout {
        set_rcvtimeo(listener.as_raw_fd(), Duration::from_secs(5));
    }
    (
        Box::new(move || {
            // SAFETY: no address wanted.
            let r = result(unsafe {
                libc::accept(
                    listener.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            } as isize);
            drop(listener);
            r
        }),
        Box::new(move || drop(TcpStream::connect(to))),
    )
}

fn poll(timeout_ms: c_int) -> Scenario {
    let [a, b] = socketpair();
    (
        Box::new(move || {
            let mut fds = [libc::pollfd {
                fd: a,
                events: libc::POLLIN,
                revents: 0,
            }];
            // SAFETY: one pollfd.
            result(unsafe { libc::poll(fds.as_mut_ptr(), 1, timeout_ms) } as isize)
        }),
        Box::new(move || write_byte(b)),
    )
}

fn select() -> Scenario {
    let [a, b] = socketpair();
    (
        Box::new(move || {
            // SAFETY: an fd_set holding `a`, which is below FD_SETSIZE.
            unsafe {
                let mut set: libc::fd_set = std::mem::zeroed();
                libc::FD_ZERO(&mut set);
                libc::FD_SET(a, &mut set);
                result(libc::select(
                    a + 1,
                    &mut set,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                ) as isize)
            }
        }),
        Box::new(move || write_byte(b)),
    )
}

#[cfg(target_os = "linux")]
fn readiness_set() -> Scenario {
    let [a, b] = socketpair();
    // SAFETY: plain descriptor calls.
    let set = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    let mut event = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: 0,
    };
    // SAFETY: as above.
    assert_eq!(
        unsafe { libc::epoll_ctl(set, libc::EPOLL_CTL_ADD, a, &mut event) },
        0
    );
    (
        Box::new(move || {
            let mut events = [libc::epoll_event { events: 0, u64: 0 }];
            // SAFETY: room for one event.
            result(unsafe { libc::epoll_wait(set, events.as_mut_ptr(), 1, -1) } as isize)
        }),
        Box::new(move || write_byte(b)),
    )
}

#[cfg(target_os = "macos")]
fn readiness_set() -> Scenario {
    let [a, b] = socketpair();
    // SAFETY: plain descriptor calls.
    let set = unsafe { libc::kqueue() };
    let change = libc::kevent {
        ident: a as usize,
        filter: libc::EVFILT_READ,
        flags: libc::EV_ADD,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    // SAFETY: one change, no events.
    assert_eq!(
        unsafe { libc::kevent(set, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) },
        0
    );
    (
        Box::new(move || {
            // SAFETY: room for one event.
            let mut event: libc::kevent = unsafe { std::mem::zeroed() };
            result(unsafe {
                libc::kevent(set, std::ptr::null(), 0, &mut event, 1, std::ptr::null())
            } as isize)
        }),
        Box::new(move || write_byte(b)),
    )
}

fn nanosleep() -> Scenario {
    (
        Box::new(|| {
            let request = libc::timespec {
                tv_sec: 0,
                tv_nsec: 200_000_000,
            };
            // SAFETY: valid timespecs.
            let mut left: libc::timespec = unsafe { std::mem::zeroed() };
            let r = result(unsafe { libc::nanosleep(&request, &mut left) } as isize);
            if r.0 < 0 {
                assert!(left.tv_sec == 0 && left.tv_nsec > 0, "{}", left.tv_nsec);
                assert!(left.tv_nsec <= 150_000_000, "{}", left.tv_nsec);
            }
            r
        }),
        Box::new(|| {}),
    )
}

/// `clock_nanosleep` returns its error rather than setting `errno` (man 2 clock_nanosleep).
#[cfg(target_os = "linux")]
fn clock_nanosleep() -> Scenario {
    (
        Box::new(|| {
            let request = libc::timespec {
                tv_sec: 0,
                tv_nsec: 200_000_000,
            };
            // SAFETY: valid timespecs.
            let mut left: libc::timespec = unsafe { std::mem::zeroed() };
            let e = unsafe { libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &request, &mut left) };
            if e == libc::EINTR {
                assert!(left.tv_sec == 0 && left.tv_nsec > 0, "{}", left.tv_nsec);
            }
            if e == 0 { (0, 0) } else { (-1, e) }
        }),
        Box::new(|| {}),
    )
}

/// A semaphore with nothing posted; macOS only has named ones.
fn semaphore() -> *mut libc::sem_t {
    #[cfg(target_os = "linux")]
    {
        let sem = Box::into_raw(Box::new(unsafe { std::mem::zeroed::<libc::sem_t>() }));
        // SAFETY: room for a semaphore.
        assert_eq!(unsafe { libc::sem_init(sem, 0, 0) }, 0);
        sem
    }
    #[cfg(target_os = "macos")]
    {
        let name = CString::new(format!("/snare-intr-{}", std::process::id())).unwrap();
        // SAFETY: a NUL-terminated name; the variadic mode and value as sem_open takes them.
        let sem = unsafe {
            libc::sem_open(
                name.as_ptr(),
                libc::O_CREAT | libc::O_EXCL,
                0o600 as libc::c_uint,
                0 as libc::c_uint,
            )
        };
        assert_ne!(sem, libc::SEM_FAILED, "{}", errno());
        // SAFETY: as above.
        unsafe { libc::sem_unlink(name.as_ptr()) };
        sem
    }
}

fn sem_wait() -> Scenario {
    let sem = semaphore() as usize;
    (
        // SAFETY: the semaphore lives for the rest of the process.
        Box::new(move || result(unsafe { libc::sem_wait(sem as *mut libc::sem_t) } as isize)),
        // SAFETY: as above.
        Box::new(move || assert_eq!(unsafe { libc::sem_post(sem as *mut libc::sem_t) }, 0)),
    )
}

#[cfg(target_os = "linux")]
fn sem_timedwait() -> Scenario {
    let sem = semaphore() as usize;
    (
        Box::new(move || {
            // SAFETY: a timespec for clock_gettime to fill.
            let mut until: libc::timespec = unsafe { std::mem::zeroed() };
            // SAFETY: as above.
            unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut until) };
            until.tv_sec += 5;
            // SAFETY: the semaphore lives for the rest of the process.
            result(unsafe { libc::sem_timedwait(sem as *mut libc::sem_t, &until) } as isize)
        }),
        // SAFETY: as above.
        Box::new(move || assert_eq!(unsafe { libc::sem_post(sem as *mut libc::sem_t) }, 0)),
    )
}

fn open(path: &CString) -> c_int {
    // SAFETY: a NUL-terminated path.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600) };
    assert!(fd >= 0, "open: {}", errno());
    fd
}

fn flock(path: &CString) -> Scenario {
    let held = open(path);
    let waiting = open(path);
    // SAFETY: plain descriptor calls.
    assert_eq!(unsafe { libc::flock(held, libc::LOCK_EX) }, 0);
    (
        Box::new(move || result(unsafe { libc::flock(waiting, libc::LOCK_EX) } as isize)),
        Box::new(move || assert_eq!(unsafe { libc::flock(held, libc::LOCK_UN) }, 0)),
    )
}

fn record_lock(kind: c_int) -> libc::flock {
    // SAFETY: all-zero is a valid flock.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = kind as _;
    lock.l_whence = libc::SEEK_SET as _;
    lock.l_len = 1;
    lock
}

fn ofd_setlkw(path: &CString) -> Scenario {
    let held = open(path);
    let waiting = open(path);
    let mut lock = record_lock(libc::F_WRLCK as c_int);
    // SAFETY: a flock of the size fcntl reads.
    assert_eq!(
        unsafe { libc::fcntl(held, libc::F_OFD_SETLK, &mut lock) },
        0
    );
    (
        Box::new(move || {
            let mut lock = record_lock(libc::F_WRLCK as c_int);
            // SAFETY: as above.
            result(unsafe { libc::fcntl(waiting, libc::F_OFD_SETLKW, &mut lock) } as isize)
        }),
        Box::new(move || {
            let mut lock = record_lock(libc::F_UNLCK as c_int);
            // SAFETY: as above.
            assert_eq!(
                unsafe { libc::fcntl(held, libc::F_OFD_SETLK, &mut lock) },
                0
            );
        }),
    )
}

fn pipe_read() -> Scenario {
    let mut fds = [0; 2];
    // SAFETY: room for both ends.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let [read, write] = fds;
    (
        Box::new(move || {
            let mut byte = 0u8;
            // SAFETY: one byte into `byte`.
            let r = result(unsafe { libc::read(read, (&raw mut byte).cast(), 1) });
            // SAFETY: the read end made above.
            unsafe { libc::close(read) };
            r
        }),
        // SAFETY: one byte from a static, to the write end made above; with the read end closed
        // by an interrupted read it fails with EPIPE, which is all the same here.
        Box::new(move || unsafe {
            libc::write(write, b"x".as_ptr().cast(), 1);
            libc::close(write);
        }),
    )
}

fn pipe() -> [c_int; 2] {
    let mut fds = [0; 2];
    // SAFETY: room for both ends.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    fds
}

fn set_nonblocking(fd: c_int, on: bool) {
    // SAFETY: plain descriptor calls.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        let flags = if on {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        assert_eq!(libc::fcntl(fd, libc::F_SETFL, flags), 0);
    }
}

/// Writes `fd`, a pipe's write end, until it is full.
fn fill(fd: c_int) {
    set_nonblocking(fd, true);
    let chunk = [1u8; 4096];
    // SAFETY: bytes from a local buffer.
    while unsafe { libc::write(fd, chunk.as_ptr().cast(), chunk.len()) } > 0 {}
    // SAFETY: as above.
    while unsafe { libc::write(fd, chunk.as_ptr().cast(), 1) } > 0 {}
    set_nonblocking(fd, false);
}

/// Reads `fd`, a pipe's read end, until its writer has had 100 ms to write more, and closes it.
fn drain(fd: c_int) {
    set_nonblocking(fd, true);
    let mut buf = vec![0u8; 1 << 16];
    for _ in 0..50 {
        // SAFETY: into a local buffer.
        while unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
        std::thread::sleep(Duration::from_millis(2));
    }
    // SAFETY: the read end, no longer used.
    unsafe { libc::close(fd) };
}

fn pipe_readv() -> Scenario {
    let [read, write] = pipe();
    (
        Box::new(move || {
            let mut byte = 0u8;
            let iov = libc::iovec {
                iov_base: (&raw mut byte).cast(),
                iov_len: 1,
            };
            // SAFETY: one iovec of one byte.
            let r = result(unsafe { libc::readv(read, &iov, 1) });
            // SAFETY: the read end made above.
            unsafe { libc::close(read) };
            r
        }),
        // SAFETY: as in `pipe_read`.
        Box::new(move || unsafe {
            libc::write(write, b"x".as_ptr().cast(), 1);
            libc::close(write);
        }),
    )
}

/// A write of `len` bytes, by `writev` of two halves with `vectored`, to a pipe that `full` fills
/// first.
fn pipe_write(len: usize, vectored: bool, full: bool) -> Scenario {
    let [read, write] = pipe();
    if full {
        fill(write);
    }
    (
        Box::new(move || {
            let bytes = vec![2u8; len];
            let r = if vectored {
                let (first, second) = bytes.split_at(len / 2);
                let iov = [first, second].map(|half| libc::iovec {
                    iov_base: half.as_ptr().cast_mut().cast(),
                    iov_len: half.len(),
                });
                // SAFETY: two iovecs within `bytes`.
                result(unsafe { libc::writev(write, iov.as_ptr(), 2) })
            } else {
                // SAFETY: from `bytes`.
                result(unsafe { libc::write(write, bytes.as_ptr().cast(), len) })
            };
            // SAFETY: the write end made above.
            unsafe { libc::close(write) };
            r
        }),
        Box::new(move || drain(read)),
    )
}

/// A child, started as the call's thread starts, that ends by itself some 300 ms on, waited for by
/// `wait`, which reaps it either way.
fn any_child(wait: fn() -> (isize, c_int)) -> Scenario {
    (
        Box::new(move || {
            let child = std::process::Command::new("sleep")
                .arg("0.3")
                .spawn()
                .unwrap();
            let r = wait();
            if r.0 < 0 {
                assert!(wait().0 >= 0, "{}", errno());
            }
            drop(child);
            r
        }),
        Box::new(|| {}),
    )
}

fn wait_any() -> (isize, c_int) {
    let mut status = 0;
    // SAFETY: an int for the status.
    result(unsafe { libc::wait(&mut status) } as isize)
}

fn waitpid_any() -> (isize, c_int) {
    let mut status = 0;
    // SAFETY: as above.
    result(unsafe { libc::waitpid(-1, &mut status, 0) } as isize)
}

fn waitid_any() -> (isize, c_int) {
    // SAFETY: a siginfo_t for waitid to fill.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    result(unsafe { libc::waitid(libc::P_ALL, 0, &mut info, libc::WEXITED) } as isize)
}

fn loopback(port: u16) -> libc::sockaddr_in {
    // SAFETY: all-zero is a valid sockaddr_in.
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "macos")]
    {
        addr.sin_len = size_of::<libc::sockaddr_in>() as u8;
    }
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
    addr
}

fn tcp_socket() -> c_int {
    // SAFETY: no pointers.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0, "socket: {}", errno());
    fd
}

fn connect_to(fd: c_int, addr: &libc::sockaddr_in) -> (isize, c_int) {
    let len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: a sockaddr_in of the length given.
    result(unsafe { libc::connect(fd, (addr as *const libc::sockaddr_in).cast(), len) } as isize)
}

fn set_int(fd: c_int, level: c_int, name: c_int, value: c_int) {
    // SAFETY: an int of the size given.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                (&raw const value).cast(),
                size_of::<c_int>() as libc::socklen_t,
            )
        },
        0
    );
}

/// A blocking `connect` to a listener whose backlog is full, so that its SYN goes unanswered until
/// `release` accepts what is queued and a retransmission gets through. After an interrupted
/// connect the thread connects again, blocking.
fn connect(timeout: bool) -> Scenario {
    let listener = tcp_socket();
    let mut addr = loopback(0);
    let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: a sockaddr_in of the length given.
    unsafe {
        let at = (&raw mut addr).cast::<libc::sockaddr>();
        assert_eq!(libc::bind(listener, at, len), 0);
        assert_eq!(libc::listen(listener, 1), 0);
        assert_eq!(libc::getsockname(listener, at, &mut len), 0);
    }
    let fillers: Vec<c_int> = (0..64)
        .map(|_| {
            let filler = tcp_socket();
            set_nonblocking(filler, true);
            connect_to(filler, &addr);
            filler
        })
        .collect();
    std::thread::sleep(Duration::from_millis(50));
    (
        Box::new(move || {
            let fd = tcp_socket();
            if timeout {
                set_timeout(fd, libc::SO_SNDTIMEO, Duration::from_secs(5));
            }
            let r = connect_to(fd, &addr);
            if r.0 < 0 {
                after(connect_to(fd, &addr));
            }
            // SAFETY: the socket made above.
            unsafe { libc::close(fd) };
            r
        }),
        Box::new(move || {
            set_nonblocking(listener, true);
            for _ in 0..300 {
                // SAFETY: no address wanted.
                let accepted =
                    unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) };
                if accepted >= 0 {
                    // SAFETY: the connection just accepted.
                    unsafe { libc::close(accepted) };
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            for fd in fillers.into_iter().chain([listener]) {
                // SAFETY: sockets made above.
                unsafe { libc::close(fd) };
            }
        }),
    )
}

/// `SO_LINGER` in seconds: macOS's `SO_LINGER` counts clock ticks, its `SO_LINGER_SEC` seconds
/// (`<sys/socket.h>`).
#[cfg(target_os = "macos")]
const LINGER_SECONDS: c_int = 0x1080;
#[cfg(not(target_os = "macos"))]
const LINGER_SECONDS: c_int = libc::SO_LINGER;

/// A `close` of a TCP socket lingering (`SO_LINGER`, 5 s) over bytes its peer has no room for,
/// until `release` reads them.
fn linger_close() -> Scenario {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = tcp_socket();
    set_int(client, libc::SOL_SOCKET, libc::SO_SNDBUF, 4096);
    let port = listener.local_addr().unwrap().port();
    assert_eq!(connect_to(client, &loopback(port)), (0, 0));
    let (server, _) = listener.accept().unwrap();
    set_int(server.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, 4096);
    set_nonblocking(client, true);
    let chunk = vec![3u8; 1 << 16];
    // SAFETY: from a local buffer.
    let send = || unsafe { libc::write(client, chunk.as_ptr().cast(), chunk.len()) } > 0;
    loop {
        while send() {}
        std::thread::sleep(Duration::from_millis(20));
        if !send() {
            break;
        }
    }
    set_nonblocking(client, false);
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 5,
    };
    // SAFETY: a linger of the size given.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                client,
                libc::SOL_SOCKET,
                LINGER_SECONDS,
                (&raw const linger).cast(),
                size_of::<libc::linger>() as libc::socklen_t,
            )
        },
        0
    );
    (
        // SAFETY: the client's socket, closed here alone.
        // SAFETY: the client's socket, closed here alone.
        Box::new(move || result(unsafe { libc::close(client) } as isize)),
        Box::new(move || {
            set_nonblocking(server.as_raw_fd(), true);
            let mut buf = vec![0u8; 1 << 16];
            for _ in 0..100 {
                while std::io::Read::read(&mut &server, &mut buf).is_ok_and(|n| n > 0) {}
                std::thread::sleep(Duration::from_millis(2));
            }
        }),
    )
}

/// A child, started as the call's thread starts, that ends by itself some 300 ms on; reaped
/// either way.
fn waitpid() -> Scenario {
    (
        Box::new(move || {
            let child = std::process::Command::new("sleep")
                .arg("0.3")
                .spawn()
                .unwrap();
            let pid = child.id() as libc::pid_t;
            let mut status = 0;
            // SAFETY: a child of this process and an int for its status.
            let r = result(unsafe { libc::waitpid(pid, &mut status, 0) } as isize);
            if r.0 < 0 {
                // SAFETY: as above.
                assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            }
            drop(child);
            r
        }),
        Box::new(|| {}),
    )
}

fn pause() -> Scenario {
    // SAFETY: no arguments.
    (
        Box::new(|| result(unsafe { libc::pause() } as isize)),
        Box::new(|| {}),
    )
}

fn sigsuspend() -> Scenario {
    (
        Box::new(|| {
            // SAFETY: an empty mask.
            unsafe {
                let mut mask: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut mask);
                result(libc::sigsuspend(&mask) as isize)
            }
        }),
        Box::new(|| {}),
    )
}

type Seen = Vec<(&'static str, bool, Ended, usize, Vec<(isize, c_int)>)>;

/// A scenario, set up as its turn comes.
type Setup = Box<dyn FnOnce() -> Scenario>;

/// Every call, interrupted without and then with `SA_RESTART`. Files live in `dir`.
fn interruptions(dir: &str) -> Seen {
    let mut seen = Vec::new();
    for restart in [false, true] {
        let old = install(libc::SIGINT, restart);
        let path = |name: &str| CString::new(format!("{dir}/{name}-{restart}")).unwrap();
        let (flock_path, ofd_path) = (path("flock"), path("ofd"));
        #[allow(unused_mut)]
        let mut calls: Vec<(&'static str, Setup)> = vec![
            ("socketpair recv", Box::new(socketpair_recv)),
            ("tcp recv", Box::new(|| tcp_recv(false))),
            ("tcp recv with SO_RCVTIMEO", Box::new(|| tcp_recv(true))),
            ("udp recv", Box::new(udp_recv)),
            ("accept", Box::new(|| accept(false))),
            ("accept with SO_RCVTIMEO", Box::new(|| accept(true))),
            ("poll", Box::new(|| poll(-1))),
            ("poll with a timeout", Box::new(|| poll(5_000))),
            ("select", Box::new(select)),
            ("readiness set", Box::new(readiness_set)),
            ("nanosleep", Box::new(nanosleep)),
            ("sem_wait", Box::new(sem_wait)),
            ("pipe read", Box::new(pipe_read)),
            ("pipe readv", Box::new(pipe_readv)),
            ("pipe write", Box::new(|| pipe_write(1, false, true))),
            ("pipe writev", Box::new(|| pipe_write(2, true, true))),
            (
                "pipe write past its room",
                Box::new(|| pipe_write(200_000, false, false)),
            ),
            (
                "pipe writev past its room",
                Box::new(|| pipe_write(200_000, true, false)),
            ),
            ("waitpid", Box::new(waitpid)),
            ("wait", Box::new(|| any_child(wait_any))),
            ("waitpid of any child", Box::new(|| any_child(waitpid_any))),
            ("waitid of any child", Box::new(|| any_child(waitid_any))),
            ("connect", Box::new(|| connect(false))),
            ("connect with SO_SNDTIMEO", Box::new(|| connect(true))),
            ("close lingering", Box::new(linger_close)),
            ("flock", Box::new(move || flock(&flock_path))),
            ("F_OFD_SETLKW", Box::new(move || ofd_setlkw(&ofd_path))),
            ("pause", Box::new(pause)),
            ("sigsuspend", Box::new(sigsuspend)),
        ];
        #[cfg(target_os = "linux")]
        calls.extend([
            ("clock_nanosleep", Box::new(clock_nanosleep) as Setup),
            ("sem_timedwait", Box::new(sem_timedwait)),
        ]);
        for (label, setup) in calls {
            let (call, release) = setup();
            let (ended, handled, after) = interrupt(call, release);
            seen.push((label, restart, ended, handled, after));
        }
        restore(libc::SIGINT, &old);
    }
    seen
}

/// [`interruptions`] on the host, in a directory of its own: a lock taken by a call that went on
/// is held until the process ends.
fn on_the_host() -> Seen {
    static RUNS: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "snare-intr-{}-{}",
        std::process::id(),
        RUNS.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let seen = interruptions(dir.to_str().unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
    seen
}

#[test]
fn interruptions_match_the_host() {
    let _serial = serial();
    let host = on_the_host();
    let sim = Sim::builder()
        .fs(FsBuilder::new().dir("/intr").build())
        .build()
        .run(|| interruptions("/intr"));
    assert_eq!(sim, host);
}

#[test]
fn interruptions_match_the_host_deterministic() {
    let _serial = serial();
    let host = on_the_host();
    let sim = Sim::builder()
        .fs(FsBuilder::new().dir("/intr").build())
        .deterministic()
        .build()
        .run(|| interruptions("/intr"));
    assert_eq!(sim, host);
}

static ROOT: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_root(_: c_int) {
    // SAFETY: pthread_self has no preconditions.
    ROOT.store(unsafe { libc::pthread_self() } as usize, Ordering::SeqCst);
}

/// A signal sent to the process while its main thread is blocked in `accept` goes to that thread
/// and fails the call with `EINTR`, the shutdown path of a server that installs its handler
/// without `SA_RESTART`: the kernel picks the main thread (kernel/signal.c `complete_signal`; XNU
/// `get_signalthread`), and the sim its root thread.
#[test]
fn a_signal_to_the_process_interrupts_its_blocked_root_thread() {
    let _serial = serial();
    for sim in [Sim::new(), Sim::builder().deterministic().build()] {
        let signals = sim.signals();
        let (raised, r, e, root, me) = sim.run(|| {
            // SAFETY: an all-zero sigaction is valid; the calls fill the mask and set the action.
            let old = unsafe {
                let mut act: libc::sigaction = std::mem::zeroed();
                act.sa_sigaction = on_root as *const () as libc::sighandler_t;
                libc::sigemptyset(&mut act.sa_mask);
                let mut old: libc::sigaction = std::mem::zeroed();
                libc::sigaction(libc::SIGINT, &act, &mut old);
                old
            };
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let pending = signals.raise_after(snare::Signal::Interrupt, Duration::from_secs(1));
            // SAFETY: no address wanted.
            let r = unsafe {
                libc::accept(
                    listener.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            let e = errno();
            let raised = pending.wait();
            restore(libc::SIGINT, &old);
            // SAFETY: pthread_self has no preconditions.
            let me = unsafe { libc::pthread_self() } as usize;
            (raised, r, e, ROOT.load(Ordering::SeqCst), me)
        });
        assert_eq!(raised, snare::SignalDelivery::Handled);
        assert_eq!((r, e), (-1, libc::EINTR));
        assert_eq!(root, me, "the handler ran on the root thread");
    }
}
