//! `socketpair(AF_UNIX, ..)` served by the fabric: both ends are in-memory sockets that read,
//! write, poll and close as the host OS's unnamed pairs do.
#![cfg(unix)]

use std::ffi::c_int;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::thread;
use std::time::Duration;

use snare::Sim;

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

/// What the OS answers for an unnamed pair: `getsockname` of each kind, the errors of a write to a
/// stream end and a send to a datagram end whose other end is closed, and which protocols it takes.
fn observe() -> Vec<(c_int, Vec<u8>, c_int)> {
    [libc::SOCK_STREAM, libc::SOCK_DGRAM]
        .into_iter()
        .map(|ty| {
            let mut fds = [0; 2];
            // SAFETY: plain socket calls on fds this function owns.
            unsafe {
                assert_eq!(libc::socketpair(libc::AF_UNIX, ty, 0, fds.as_mut_ptr()), 0);
                let mut name = [0u8; 128];
                let mut len: libc::socklen_t = 128;
                assert_eq!(
                    libc::getsockname(fds[0], name.as_mut_ptr().cast(), &mut len),
                    0
                );
                libc::close(fds[1]);
                let r = libc::send(fds[0], b"x".as_ptr().cast(), 1, 0);
                let e = if r < 0 { errno() } else { 0 };
                libc::close(fds[0]);
                (ty, name[..len as usize].to_vec(), e)
            }
        })
        .chain([1, libc::IPPROTO_TCP].into_iter().map(|protocol| {
            let mut fds = [0; 2];
            // SAFETY: a socketpair call whose fds, if any, are closed at once.
            let e = unsafe {
                if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, protocol, fds.as_mut_ptr())
                    == 0
                {
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                    0
                } else {
                    errno()
                }
            };
            (-protocol, Vec::new(), e)
        }))
        .collect()
}

/// Whether `fd` is one of the sim's sockets rather than a real one: the sim backs each with a
/// real descriptor of `/dev/null`.
fn simulated(fd: c_int) -> bool {
    snare::real(|| {
        // SAFETY: fstat fills `st`.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0);
        st.st_mode & libc::S_IFMT != libc::S_IFSOCK
    })
}

#[test]
fn socketpair_os_truth() {
    let real = snare::real(observe);
    let sim = Sim::new();
    let simulated = sim.run(observe);
    assert_eq!(simulated, real);
}

#[test]
fn socketpair_stream() {
    let sim = Sim::new();
    sim.run(|| {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        assert!(simulated(a.as_raw_fd()) && simulated(b.as_raw_fd()));
        let reader = thread::spawn(move || {
            let mut got = String::new();
            b.read_to_string(&mut got).unwrap();
            b.write_all(b"bye").unwrap();
            got
        });
        a.write_all(b"hello ").unwrap();
        thread::sleep(Duration::from_millis(5));
        a.write_all(b"pair").unwrap();
        a.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(reader.join().unwrap(), "hello pair");
        let mut back = [0u8; 8];
        let n = a.read(&mut back).unwrap();
        assert_eq!(&back[..n], b"bye");
        assert_eq!(
            a.read(&mut back).unwrap(),
            0,
            "end of stream once the other end is gone"
        );
        let err = a.write_all(b"x").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::BrokenPipe);

        let (c, d) = UnixStream::pair().unwrap();
        c.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(
            (&c).read(&mut buf).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        (&d).write_all(b"z").unwrap();
        assert_eq!((&c).read(&mut buf).unwrap(), 1);
        let clone = c.try_clone().unwrap();
        drop(c);
        (&d).write_all(b"y").unwrap();
        assert_eq!(
            (&clone).read(&mut buf).unwrap(),
            1,
            "a dup keeps the end open"
        );
    });
}

#[test]
fn socketpair_dgram() {
    let sim = Sim::new();
    sim.run(|| {
        let (a, b) = UnixDatagram::pair().unwrap();
        assert!(simulated(a.as_raw_fd()) && simulated(b.as_raw_fd()));
        a.send(b"one").unwrap();
        a.send(b"two").unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(b.recv(&mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], b"one");
        let receiver = thread::spawn(move || {
            let mut buf = [0u8; 8];
            let n = b.recv(&mut buf).unwrap();
            let m = b.recv(&mut buf[n..]).unwrap();
            buf[..n + m].to_vec()
        });
        thread::sleep(Duration::from_millis(5));
        a.send(b"3").unwrap();
        assert_eq!(receiver.join().unwrap(), b"two3");
        a.set_nonblocking(true).unwrap();
        assert_eq!(a.recv(&mut buf).unwrap_err().kind(), ErrorKind::WouldBlock);
    });
}

#[cfg(target_os = "linux")]
#[test]
fn socketpair_epoll() {
    let sim = Sim::new();
    sim.run(|| {
        let (a, b) = UnixStream::pair().unwrap();
        // SAFETY: plain epoll calls on fds the test owns.
        unsafe {
            let ep = libc::epoll_create1(libc::EPOLL_CLOEXEC);
            assert!(ep >= 0);
            let mut ev = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: 7,
            };
            assert_eq!(
                libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, a.as_raw_fd(), &mut ev),
                0
            );
            let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
            assert_eq!(libc::epoll_wait(ep, out.as_mut_ptr(), 4, 0), 0);
            let writer = thread::spawn(move || {
                thread::sleep(Duration::from_secs(2));
                (&b).write_all(b"!").unwrap();
                b
            });
            assert_eq!(libc::epoll_wait(ep, out.as_mut_ptr(), 4, -1), 1);
            assert_eq!({ out[0].u64 }, 7);
            drop(writer.join().unwrap());
            libc::close(ep);
        }
    });
}

#[cfg(target_os = "macos")]
#[test]
fn socketpair_kqueue() {
    let sim = Sim::new();
    sim.run(|| {
        let (a, b) = UnixStream::pair().unwrap();
        // SAFETY: plain kqueue calls on fds the test owns.
        unsafe {
            let kq = libc::kqueue();
            assert!(kq >= 0);
            let mut change: libc::kevent = std::mem::zeroed();
            change.ident = a.as_raw_fd() as usize;
            change.filter = libc::EVFILT_READ;
            change.flags = libc::EV_ADD;
            change.udata = 7 as *mut libc::c_void;
            assert_eq!(
                libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()),
                0
            );
            let zero = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let mut out: [libc::kevent; 4] = std::mem::zeroed();
            assert_eq!(
                libc::kevent(kq, std::ptr::null(), 0, out.as_mut_ptr(), 4, &zero),
                0
            );
            let writer = thread::spawn(move || {
                thread::sleep(Duration::from_secs(2));
                (&b).write_all(b"!").unwrap();
                b
            });
            assert_eq!(
                libc::kevent(
                    kq,
                    std::ptr::null(),
                    0,
                    out.as_mut_ptr(),
                    4,
                    std::ptr::null()
                ),
                1
            );
            assert_eq!(out[0].udata as usize, 7);
            drop(writer.join().unwrap());
            libc::close(kq);
        }
    });
}
