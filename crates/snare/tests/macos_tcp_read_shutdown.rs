#![cfg(target_os = "macos")]

use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use snare::Sim;

fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let server = listener.accept().unwrap().0;
    client.set_nodelay(true).unwrap();
    server.set_nodelay(true).unwrap();
    (client, server)
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn send(fd: RawFd, bytes: &[u8]) -> Result<usize, i32> {
    let result = unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), libc::MSG_DONTWAIT) };
    if result < 0 {
        Err(errno())
    } else {
        Ok(result as usize)
    }
}

fn recv(fd: RawFd, peek: bool) -> Result<Vec<u8>, i32> {
    let mut bytes = [0; 32];
    let flags = libc::MSG_DONTWAIT | if peek { libc::MSG_PEEK } else { 0 };
    let result = unsafe { libc::recv(fd, bytes.as_mut_ptr().cast(), bytes.len(), flags) };
    if result < 0 {
        Err(errno())
    } else {
        Ok(bytes[..result as usize].to_vec())
    }
}

fn option(fd: RawFd, name: i32) -> i32 {
    let mut value = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    assert_eq!(
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                name,
                (&raw mut value).cast(),
                &mut length,
            )
        },
        0
    );
    value
}

fn queued(fd: RawFd) -> i32 {
    let mut bytes = 0;
    assert_eq!(unsafe { libc::ioctl(fd, libc::FIONREAD, &mut bytes) }, 0);
    bytes
}

fn wait_for_bytes(fd: RawFd, expected: i32) {
    for _ in 0..100 {
        if queued(fd) == expected {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("expected {expected} queued bytes, got {}", queued(fd));
}

fn settle() {
    std::thread::sleep(Duration::from_millis(5));
}

fn events(fd: RawFd, filters: &[i16]) -> Vec<(i16, bool, u32, isize)> {
    let raw = unsafe { libc::kqueue() };
    assert!(raw >= 0);
    let queue = unsafe { OwnedFd::from_raw_fd(raw) };
    let changes: Vec<_> = filters
        .iter()
        .map(|&filter| libc::kevent {
            ident: fd as usize,
            filter,
            flags: libc::EV_ADD,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        })
        .collect();
    let mut output = [unsafe { std::mem::zeroed::<libc::kevent>() }; 2];
    let zero = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let count = unsafe {
        libc::kevent(
            queue.as_raw_fd(),
            changes.as_ptr(),
            changes.len() as i32,
            output.as_mut_ptr(),
            output.len() as i32,
            &zero,
        )
    };
    assert!(count >= 0, "kevent failed: {}", errno());
    let mut observed: Vec<_> = output[..count as usize]
        .iter()
        .map(|event| {
            assert_eq!(event.flags & libc::EV_ERROR, 0);
            (
                event.filter,
                event.flags & libc::EV_EOF != 0,
                event.fflags,
                event.data,
            )
        })
        .collect();
    observed.sort_unstable();
    observed
}

fn eof_errors(fd: RawFd) -> Vec<(i16, bool, u32)> {
    events(fd, &[libc::EVFILT_READ, libc::EVFILT_WRITE])
        .into_iter()
        .map(|(filter, eof, error, _)| (filter, eof, error))
        .collect()
}

fn compare<R: std::fmt::Debug + PartialEq>(observe: impl Fn() -> R) {
    let native = snare::real(&observe);
    let plain = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Sim::new().run(&observe)));
    assert!(plain.is_ok(), "plain simulation observation failed");
    assert_eq!(plain.unwrap(), native, "plain simulation");
    let deterministic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Sim::builder().deterministic().build().run(&observe)
    }));
    assert!(
        deterministic.is_ok(),
        "deterministic simulation observation failed"
    );
    assert_eq!(deterministic.unwrap(), native, "deterministic simulation");
}

#[test]
fn read_shutdown_flushes_queued_bytes_and_kevent_data() {
    compare(|| {
        let (client, server) = pair();
        let fd = server.as_raw_fd();
        assert_eq!(send(client.as_raw_fd(), b"queued"), Ok(6));
        wait_for_bytes(fd, 6);
        server.shutdown(Shutdown::Read).unwrap();
        let observed = (
            queued(fd),
            option(fd, libc::SO_NREAD),
            events(fd, &[libc::EVFILT_READ]),
            recv(fd, false),
        );
        assert_eq!(
            observed,
            (0, 0, vec![(libc::EVFILT_READ, true, 0, 0)], Ok(vec![]))
        );
        observed
    });
}

#[test]
fn incoming_data_after_read_shutdown_resets_the_peer() {
    compare(|| {
        let (client, server) = pair();
        let (c, s) = (client.as_raw_fd(), server.as_raw_fd());
        server.shutdown(Shutdown::Read).unwrap();
        assert_eq!(recv(s, false), Ok(vec![]));
        assert_eq!(send(c, b"late"), Ok(4));
        settle();
        let before = eof_errors(c);
        assert_eq!(before.len(), 2);
        assert!(
            before
                .iter()
                .all(|(_, eof, error)| *eof && *error == libc::ECONNRESET as u32)
        );
        let observed = (
            send(s, b"reply"),
            recv(s, false),
            recv(c, false),
            recv(c, false),
        );
        assert_eq!(
            observed,
            (
                Err(libc::EPIPE),
                Ok(vec![]),
                Err(libc::ECONNRESET),
                Ok(vec![])
            )
        );
        let after = eof_errors(c);
        assert!(after.iter().all(|(_, eof, error)| *eof && *error == 0));
        (before, observed, after)
    });
}

#[test]
fn a_reset_after_both_read_shutdowns_is_preserved_by_peek() {
    compare(|| {
        let (client, server) = pair();
        let (c, s) = (client.as_raw_fd(), server.as_raw_fd());
        client.shutdown(Shutdown::Read).unwrap();
        server.shutdown(Shutdown::Read).unwrap();
        assert_eq!(send(c, b"late"), Ok(4));
        settle();
        let observed = (
            send(s, b"reply"),
            recv(c, true),
            recv(c, true),
            recv(c, false),
            recv(c, false),
            recv(s, false),
            option(c, libc::SO_ERROR),
        );
        assert_eq!(
            observed,
            (
                Err(libc::EPIPE),
                Err(libc::ECONNRESET),
                Err(libc::ECONNRESET),
                Err(libc::ECONNRESET),
                Ok(vec![]),
                Ok(vec![]),
                0
            )
        );
        observed
    });
}

#[test]
fn so_error_consumes_the_read_shutdown_reset_once() {
    compare(|| {
        let (client, server) = pair();
        let (c, s) = (client.as_raw_fd(), server.as_raw_fd());
        server.shutdown(Shutdown::Read).unwrap();
        assert_eq!(send(c, b"late"), Ok(4));
        settle();
        let observed = (
            option(c, libc::SO_ERROR),
            option(c, libc::SO_ERROR),
            recv(c, false),
            send(s, b"reply"),
        );
        assert_eq!(
            observed,
            (libc::ECONNRESET, 0, Ok(vec![]), Err(libc::EPIPE))
        );
        observed
    });
}

#[test]
fn queued_peer_data_precedes_the_read_shutdown_reset() {
    compare(|| {
        let (client, server) = pair();
        let (c, s) = (client.as_raw_fd(), server.as_raw_fd());
        assert_eq!(send(s, b"reply"), Ok(5));
        wait_for_bytes(c, 5);
        server.shutdown(Shutdown::Read).unwrap();
        assert_eq!(send(c, b"late"), Ok(4));
        settle();
        let observed = (
            recv(c, false),
            recv(c, true),
            recv(c, false),
            recv(c, false),
        );
        assert_eq!(
            observed,
            (
                Ok(b"reply".to_vec()),
                Err(libc::ECONNRESET),
                Err(libc::ECONNRESET),
                Ok(vec![])
            )
        );
        observed
    });
}

#[test]
fn unix_read_shutdown_does_not_raise_a_tcp_reset() {
    compare(|| {
        let (client, server) = UnixStream::pair().unwrap();
        let (c, s) = (client.as_raw_fd(), server.as_raw_fd());
        server.shutdown(Shutdown::Read).unwrap();
        let write = send(c, b"late");
        settle();
        let observed = (
            write,
            option(c, libc::SO_ERROR),
            recv(c, false),
            recv(s, false),
        );
        assert_ne!(observed.0, Err(libc::ECONNRESET));
        assert_eq!(observed.1, 0);
        assert_eq!(observed.2, Err(libc::EAGAIN));
        assert_eq!(observed.3, Ok(vec![]));
        observed
    });
}
