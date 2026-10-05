//! The code under test on both ends of a TCP connection: a std listener in the sim accepting a
//! std client in the sim, with the listener's identity, readiness, non-blocking and timeout
//! behaviour, address conflicts and `shutdown(2)` as the host OS has them.

#[path = "support/rawsock.rs"]
mod rawsock;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use snare::{Line, Sim, SocketKind, TesterAction, connect_tester, run_testers};

#[cfg(unix)]
mod code {
    pub const EAGAIN: i32 = libc::EAGAIN;
    pub const ENOTCONN: i32 = libc::ENOTCONN;
    pub const EINVAL: i32 = libc::EINVAL;
}

#[cfg(windows)]
mod code {
    pub const EAGAIN: i32 = 10035;
    pub const ENOTCONN: i32 = 10057;
    pub const EINVAL: i32 = 10022;
}

#[cfg(unix)]
fn raw_of(s: &impl std::os::fd::AsRawFd) -> rawsock::Raw {
    s.as_raw_fd()
}

#[cfg(windows)]
fn raw_of(s: &impl std::os::windows::io::AsRawSocket) -> rawsock::Raw {
    s.as_raw_socket() as rawsock::Raw
}

fn echo_once(listener: TcpListener) -> std::thread::JoinHandle<SocketAddr> {
    std::thread::spawn(move || {
        let (mut stream, peer) = listener.accept().unwrap();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).unwrap();
        stream.write_all(&buf[..n]).unwrap();
        peer
    })
}

#[test]
fn sut_listener_accepts_sut_client() {
    Sim::new().run(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert_ne!(addr.port(), 0);
        let server = echo_once(listener);

        let mut client = TcpStream::connect(addr).unwrap();
        assert_eq!(client.peer_addr().unwrap(), addr);
        client.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        assert_eq!(server.join().unwrap(), client.local_addr().unwrap());
    });
}

#[test]
fn accepted_stream_records_listener() {
    Sim::new().run(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let listener_id = snare::socket_id(&listener).unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (accepted, peer) = listener.accept().unwrap();

        let entry = snare::socket_entry(snare::socket_id(&accepted).unwrap()).unwrap();
        assert_eq!(entry.kind, SocketKind::TcpStream);
        assert_eq!(entry.listener, Some(listener_id));
        assert_eq!(entry.local, Some(addr));
        assert_eq!(entry.peer, Some(peer));
        assert_eq!(Some(peer), client.local_addr().ok());

        let listening = snare::socket_entry(listener_id).unwrap();
        assert_eq!(listening.kind, SocketKind::TcpListener);
        assert_eq!(listening.local, Some(addr));
    });
}

#[cfg(unix)]
#[test]
fn mio_tcp_listener_echo() {
    use mio::{Events, Interest, Poll, Token};

    Sim::new().run(|| {
        let mut poll = Poll::new().unwrap();
        let mut events = Events::with_capacity(8);
        let mut listener = mio::net::TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();
        poll.registry()
            .register(&mut listener, Token(0), Interest::READABLE)
            .unwrap();
        assert!(matches!(listener.accept(), Err(e) if e.kind() == ErrorKind::WouldBlock));

        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(b"hello").unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).unwrap();
            buf
        });

        let mut stream = loop {
            poll.poll(&mut events, Some(Duration::from_secs(1)))
                .unwrap();
            if events
                .iter()
                .any(|e| e.token() == Token(0) && e.is_readable())
            {
                break listener.accept().unwrap().0;
            }
        };
        poll.registry()
            .register(&mut stream, Token(1), Interest::READABLE)
            .unwrap();
        let mut buf = [0u8; 5];
        let mut got = 0;
        while got < buf.len() {
            match stream.read(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    poll.poll(&mut events, Some(Duration::from_secs(1)))
                        .unwrap();
                }
                Err(e) => panic!("{e}"),
            }
        }
        stream.write_all(&buf).unwrap();
        assert_eq!(&client.join().unwrap(), b"hello");
    });
}

#[cfg(windows)]
#[test]
fn mio_tcp_listener_echo() {
    use windows_sys::Win32::Networking::WinSock::{POLLRDNORM, WSAPOLLFD, WSAPoll};

    Sim::new().run(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let mut pfd = WSAPOLLFD {
            fd: raw_of(&listener),
            events: POLLRDNORM,
            revents: 0,
        };
        assert_eq!(unsafe { WSAPoll(&mut pfd, 1, 0) }, 0);

        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(b"hello").unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).unwrap();
            buf
        });

        assert_eq!(unsafe { WSAPoll(&mut pfd, 1, 1000) }, 1);
        assert_ne!(pfd.revents & POLLRDNORM, 0);
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(false).unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).unwrap();
        stream.write_all(&buf).unwrap();
        assert_eq!(&client.join().unwrap(), b"hello");
    });
}

#[test]
fn nonblocking_accept_would_block() {
    Sim::new().run(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let err = listener.accept().unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);

        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        assert!(listener.accept().is_ok());
    });
}

#[cfg(target_os = "linux")]
#[test]
fn accept4_flags() {
    Sim::new().run(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let fd = unsafe {
            libc::accept4(
                raw_of(&listener),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            )
        };
        assert!(fd >= 0);
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert_ne!(flags & libc::O_NONBLOCK, 0);
        let mut buf = [0u8; 4];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(n, -1);
        assert_eq!(rawsock::last_error(), libc::EAGAIN);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn accept_honours_rcvtimeo() {
    Sim::new().run(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        rawsock::set_rcvtimeo(raw_of(&listener), Duration::from_millis(100));
        let late = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            TcpStream::connect(addr).unwrap()
        });
        let start = Instant::now();
        let result = rawsock::accept(raw_of(&listener));
        let waited = start.elapsed();
        if cfg!(target_os = "linux") {
            assert_eq!(result, Err(code::EAGAIN));
            assert!(waited >= Duration::from_millis(100) && waited < Duration::from_millis(110));
            rawsock::set_rcvtimeo(raw_of(&listener), Duration::ZERO);
            listener.accept().unwrap();
        } else {
            // macOS and Windows apply SO_RCVTIMEO to receives only: accept waits for the client.
            let fd = result.unwrap();
            assert!(waited >= Duration::from_millis(300), "{waited:?}");
            rawsock::close(fd);
        }
        late.join().unwrap();
    });
}

#[test]
fn exact_bind_conflict_is_eaddrinuse() {
    Sim::new().run(|| {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = first.local_addr().unwrap();
        let err = TcpListener::bind(addr).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::AddrInUse);
        drop(first);
        TcpListener::bind(addr).unwrap();
    });
}

#[test]
fn tester_and_sut_listeners_coexist() {
    Sim::new().run(|| {
        let tester = connect_tester::<Line>("127.0.0.2:9710")
            .then_action(|msg, _| TesterAction::Send(Line(format!("tester:{}", msg.0))))
            .until_after(Duration::from_millis(300));
        let listener = TcpListener::bind("127.0.0.1:9710").unwrap();
        let server = echo_once(listener);

        let client = std::thread::spawn(|| {
            let mut to_tester = TcpStream::connect("127.0.0.2:9710").unwrap();
            to_tester.write_all(b"a\n").unwrap();
            let mut buf = [0u8; 9];
            to_tester.read_exact(&mut buf).unwrap();

            let mut to_sut = TcpStream::connect("127.0.0.1:9710").unwrap();
            to_sut.write_all(b"b").unwrap();
            let mut echo = [0u8; 1];
            to_sut.read_exact(&mut echo).unwrap();
            (buf, echo)
        });

        run_testers!(tester);
        let (from_tester, from_sut) = client.join().unwrap();
        assert_eq!(&from_tester, b"tester:a\n");
        assert_eq!(&from_sut, b"b");
        server.join().unwrap();
    });
}

fn connected_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

#[test]
fn shutdown_write_gives_the_peer_eof_and_fails_our_sends() {
    Sim::new().run(|| {
        let (mut ours, mut theirs) = connected_pair();
        ours.write_all(b"last").unwrap();
        ours.shutdown(std::net::Shutdown::Write).unwrap();
        let mut got = Vec::new();
        theirs.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"last");

        let err = ours.write(b"more").unwrap_err();
        if cfg!(windows) {
            assert_eq!(err.raw_os_error(), Some(10058)); // WSAESHUTDOWN
        } else {
            assert_eq!(err.kind(), ErrorKind::BrokenPipe);
        }
        theirs.write_all(b"reply").unwrap();
        let mut reply = [0u8; 5];
        ours.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"reply");
    });
}

#[test]
fn shutdown_read_sends_no_eof() {
    Sim::new().run(|| {
        let (ours, theirs) = connected_pair();
        ours.shutdown(std::net::Shutdown::Read).unwrap();
        theirs.set_nonblocking(true).unwrap();
        let err = (&theirs).read(&mut [0u8; 4]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);

        // std on Windows reads the recv's WSAESHUTDOWN as end of stream.
        assert_eq!((&ours).read(&mut [0u8; 4]).unwrap(), 0);
        (&ours).write_all(b"still").unwrap();
        theirs.set_nonblocking(false).unwrap();
        let mut buf = [0u8; 5];
        (&theirs).read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"still");

        (&theirs).write_all(b"late").unwrap();
        let mut late = [0u8; 4];
        let read = (&ours).read(&mut late);
        if cfg!(target_os = "linux") {
            assert_eq!(read.unwrap(), 4);
            assert_eq!(&late, b"late");
        } else if cfg!(target_os = "macos") {
            assert_eq!(read.unwrap(), 0);
        }
    });
}

#[test]
fn shutdown_of_an_unconnected_socket_and_a_bad_how() {
    Sim::new().run(|| {
        let raw = rawsock::tcp_socket(false);
        assert_eq!(rawsock::shutdown(raw, 1), Err(code::ENOTCONN));
        assert_eq!(rawsock::shutdown(raw, 7), Err(code::EINVAL));
        rawsock::close(raw);
    });
}

#[test]
fn closing_a_listener_refuses_new_connects() {
    Sim::new().run(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let err = TcpStream::connect(addr).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
    });
}

#[test]
fn wildcard_listener_takes_connects_to_any_address() {
    Sim::new().run(|| {
        let listener = TcpListener::bind("0.0.0.0:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let to: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let (tx, rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            tx.send(stream.local_addr().unwrap()).unwrap();
        });
        let _client = TcpStream::connect(to).unwrap();
        assert_eq!(rx.recv().unwrap(), to);
        server.join().unwrap();
    });
}
