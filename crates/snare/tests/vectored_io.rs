//! Vectored I/O on the sim's descriptors: `readv`/`writev` gather and scatter on TCP and UDP
//! sockets, socketpair ends and `VirtualFs` files, `preadv`/`pwritev` (and Linux's
//! `preadv2`/`pwritev2`) at an offset without moving the file's, and std's `write_vectored` and
//! `read_vectored`, tokio's included. `vectored_io_os_truth` holds the host comparison of the rules
//! the kernel decides (iovec counts, datagram boundaries, positioned calls on a socket).
#![cfg(unix)]

use std::ffi::c_int;
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;

use snare::{FsBuilder, Sim};

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn iovec(bytes: &[u8]) -> libc::iovec {
    libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    }
}

fn iovec_mut(bytes: &mut [u8]) -> libc::iovec {
    libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    }
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

#[test]
fn writev_on_a_tcp_stream_reaches_the_peer_in_order() {
    Sim::new().run(|| {
        let (client, mut server) = tcp_pair();
        let parts = [
            iovec(b"GET / HTTP/1.1\r\n"),
            iovec(b""),
            iovec(b"host: x\r\n\r\n"),
        ];
        let written = unsafe { libc::writev(client.as_raw_fd(), parts.as_ptr(), 3) };
        assert_eq!(written, 27);
        let mut got = [0u8; 27];
        server.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"GET / HTTP/1.1\r\nhost: x\r\n\r\n");
    });
}

#[test]
fn readv_on_a_tcp_stream_scatters_in_order() {
    Sim::new().run(|| {
        let (mut client, server) = tcp_pair();
        client.write_all(b"abcdefgh").unwrap();
        let (mut head, mut middle, mut tail) = ([0u8; 2], [0u8; 3], [0u8; 16]);
        let mut parts = [
            iovec_mut(&mut head),
            iovec_mut(&mut middle),
            iovec_mut(&mut tail),
        ];
        let read = unsafe { libc::readv(server.as_raw_fd(), parts.as_mut_ptr(), 3) };
        assert_eq!(read, 8);
        assert_eq!((&head, &middle, &tail[..3]), (b"ab", b"cde", &b"fgh"[..]));
    });
}

#[test]
fn std_vectored_calls_on_a_tcp_stream() {
    Sim::new().run(|| {
        let (mut client, mut server) = tcp_pair();
        let n = client
            .write_vectored(&[IoSlice::new(b"one "), IoSlice::new(b"two")])
            .unwrap();
        assert_eq!(n, 7);
        let (mut a, mut b) = ([0u8; 4], [0u8; 8]);
        let n = server
            .read_vectored(&mut [IoSliceMut::new(&mut a), IoSliceMut::new(&mut b)])
            .unwrap();
        assert_eq!((n, &a, &b[..3]), (7, b"one ", &b"two"[..]));
    });
}

#[test]
fn a_nonblocking_writev_writes_what_fits_and_no_more() {
    Sim::new().run(|| {
        let (client, mut server) = tcp_pair();
        client.set_nonblocking(true).unwrap();
        let chunk = vec![7u8; 64 * 1024];
        let parts = [iovec(&chunk), iovec(&chunk)];
        let mut sent = 0usize;
        loop {
            let n = unsafe { libc::writev(client.as_raw_fd(), parts.as_ptr(), 2) };
            if n < 0 {
                assert_eq!(errno(), libc::EAGAIN);
                break;
            }
            assert!(n > 0);
            sent += n as usize;
        }
        assert!(sent > 0);
        drop(client);
        let mut received = Vec::new();
        server.read_to_end(&mut received).unwrap();
        assert_eq!(
            received.len(),
            sent,
            "every byte a writev reported reaches the peer"
        );
        assert!(received.iter().all(|&b| b == 7));
    });
}

#[test]
fn writev_on_a_udp_socket_sends_one_datagram() {
    Sim::new().run(|| {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.connect(receiver.local_addr().unwrap()).unwrap();
        let parts = [iovec(b"head"), iovec(b"-"), iovec(b"tail")];
        assert_eq!(
            unsafe { libc::writev(sender.as_raw_fd(), parts.as_ptr(), 3) },
            9
        );
        assert_eq!(
            unsafe { libc::writev(sender.as_raw_fd(), parts.as_ptr(), 1) },
            4
        );
        let mut buf = [0u8; 32];
        let (n, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"head-tail");
        let (mut a, mut b) = ([0u8; 2], [0u8; 1]);
        let mut parts = [iovec_mut(&mut a), iovec_mut(&mut b)];
        assert_eq!(
            unsafe { libc::readv(receiver.as_raw_fd(), parts.as_mut_ptr(), 2) },
            3,
            "a datagram longer than the iovecs is cut to them"
        );
        assert_eq!((&a, &b), (b"he", b"a"));
        receiver.set_nonblocking(true).unwrap();
        assert!(receiver.recv(&mut buf).is_err(), "the rest of it is gone");
    });
}

#[test]
fn tokio_write_vectored_reaches_the_peer() {
    Sim::new().run(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut got = [0u8; 11];
            stream.read_exact(&mut got).unwrap();
            stream.write_all(&got).unwrap();
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let echoed = runtime.block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let parts = [
                IoSlice::new(b"hello"),
                IoSlice::new(b" "),
                IoSlice::new(b"world"),
            ];
            assert_eq!(stream.write_vectored(&parts).await.unwrap(), 11);
            let mut got = [0u8; 11];
            stream.read_exact(&mut got).await.unwrap();
            got
        });
        server.join().unwrap();
        assert_eq!(&echoed, b"hello world");
    });
}

#[test]
fn vectored_calls_on_a_virtual_file() {
    let fs = FsBuilder::new().dir("/data").build();
    Sim::builder().fs(fs).build().run(|| {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open("/data/v")
            .unwrap();
        let n = file
            .write_vectored(&[IoSlice::new(b"ab"), IoSlice::new(b"cd")])
            .unwrap();
        assert_eq!(n, 4);
        assert_eq!(std::fs::read("/data/v").unwrap(), b"abcd");

        let fd = file.as_raw_fd();
        let parts = [iovec(b"XY"), iovec(b"Z")];
        assert_eq!(unsafe { libc::pwritev(fd, parts.as_ptr(), 2, 1) }, 3);
        assert_eq!(std::fs::read("/data/v").unwrap(), b"aXYZ");
        assert_eq!(
            unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) },
            4,
            "offset untouched"
        );

        let (mut a, mut b) = ([0u8; 1], [0u8; 8]);
        let mut parts = [iovec_mut(&mut a), iovec_mut(&mut b)];
        assert_eq!(unsafe { libc::preadv(fd, parts.as_mut_ptr(), 2, 1) }, 3);
        assert_eq!((&a, &b[..2]), (b"X", &b"YZ"[..]));
        assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) }, 4);

        assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_SET) }, 0);
        let mut parts = [iovec_mut(&mut a), iovec_mut(&mut b)];
        assert_eq!(unsafe { libc::readv(fd, parts.as_mut_ptr(), 2) }, 4);
        assert_eq!((&a, &b[..3]), (b"a", &b"XYZ"[..]));
        assert_eq!(
            unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) },
            4,
            "readv moves it"
        );
    });
}

#[cfg(target_os = "linux")]
#[test]
fn preadv2_and_pwritev2_on_a_virtual_file() {
    let fs = FsBuilder::new().file("/data/v", "0123456789").build();
    Sim::builder().fs(fs).build().run(|| {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/data/v")
            .unwrap();
        let fd = file.as_raw_fd();
        let mut buf = [0u8; 3];
        let mut parts = [iovec_mut(&mut buf)];
        assert_eq!(
            unsafe { libc::preadv2(fd, parts.as_mut_ptr(), 1, -1, 0) },
            3
        );
        assert_eq!(&buf, b"012");
        assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) }, 3);
        assert_eq!(unsafe { libc::preadv2(fd, parts.as_mut_ptr(), 1, 7, 0) }, 3);
        assert_eq!(&buf, b"789");
        assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) }, 3);

        let tail = [iovec(b"!")];
        assert_eq!(
            unsafe { libc::pwritev2(fd, tail.as_ptr(), 1, 0, libc::RWF_APPEND) },
            1
        );
        assert_eq!(std::fs::read("/data/v").unwrap(), b"0123456789!");
        assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) }, 3);
        assert_eq!(
            unsafe { libc::pwritev2(fd, tail.as_ptr(), 1, -1, libc::RWF_APPEND) },
            1
        );
        assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) }, 12);
        assert_eq!(
            unsafe { libc::pwritev2(fd, tail.as_ptr(), 1, -1, 1 << 30) },
            -1
        );
        assert_eq!(errno(), libc::EOPNOTSUPP);
    });
}

#[cfg(target_os = "linux")]
#[test]
fn read_write_and_vectored_calls_on_a_host_udp_socket() {
    Sim::builder()
        .host(snare::HostProfile::new().build())
        .build()
        .run(|| {
            let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
            let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
            sender.connect(receiver.local_addr().unwrap()).unwrap();
            receiver.connect(sender.local_addr().unwrap()).unwrap();
            let fd = sender.as_raw_fd();
            assert_eq!(unsafe { libc::write(fd, b"plain".as_ptr().cast(), 5) }, 5);
            let parts = [iovec(b"vec"), iovec(b"tored")];
            assert_eq!(unsafe { libc::writev(fd, parts.as_ptr(), 2) }, 8);
            let mut buf = [0u8; 16];
            let n = unsafe { libc::read(receiver.as_raw_fd(), buf.as_mut_ptr().cast(), 16) };
            assert_eq!(&buf[..n as usize], b"plain");
            let (mut a, mut b) = ([0u8; 3], [0u8; 16]);
            let mut parts = [iovec_mut(&mut a), iovec_mut(&mut b)];
            assert_eq!(
                unsafe { libc::readv(receiver.as_raw_fd(), parts.as_mut_ptr(), 2) },
                8
            );
            assert_eq!((&a, &b[..5]), (b"vec", &b"tored"[..]));
        });
}
