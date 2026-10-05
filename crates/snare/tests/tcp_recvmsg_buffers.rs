#![cfg(unix)]

use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::time::Duration;

fn connected() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let sender = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let receiver = listener.accept().unwrap().0;
    (sender, receiver)
}

fn receive(stream: &TcpStream, buffers: &mut [&mut [u8]], flags: i32) -> usize {
    let mut iovecs: Vec<_> = buffers
        .iter_mut()
        .map(|buffer| libc::iovec {
            iov_base: if buffer.is_empty() {
                std::ptr::null_mut()
            } else {
                buffer.as_mut_ptr().cast()
            },
            iov_len: buffer.len(),
        })
        .collect();
    let mut name = [0u8; 128];
    let mut control = [0u8; 128];
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = if iovecs.is_empty() {
        std::ptr::null_mut()
    } else {
        iovecs.as_mut_ptr()
    };
    header.msg_iovlen = iovecs.len() as _;
    header.msg_name = name.as_mut_ptr().cast();
    header.msg_namelen = name.len() as _;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = control.len() as _;
    header.msg_flags = -1;
    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut header, flags) };
    assert!(n >= 0, "recvmsg: {}", std::io::Error::last_os_error());
    assert_eq!(header.msg_namelen, 0);
    assert_eq!(header.msg_controllen, 0);
    assert_eq!(header.msg_flags, 0);
    n as usize
}

fn run_each(f: impl Fn() + Copy) {
    snare::Sim::new().run(f);
    snare::Sim::builder().deterministic().build().run(f);
}

#[test]
fn single_buffer_peek_partial_read_and_eof_preserve_sentinels() {
    run_each(|| {
        let (mut sender, receiver) = connected();
        sender.write_all(b"abcdefgh").unwrap();
        sender.shutdown(Shutdown::Write).unwrap();
        let mut peek = [0xcc; 12];
        assert_eq!(receive(&receiver, &mut [&mut peek], libc::MSG_PEEK), 8);
        assert_eq!(&peek[..8], b"abcdefgh");
        assert_eq!(&peek[8..], &[0xcc; 4]);
        let mut prefix = [0; 3];
        assert_eq!(receive(&receiver, &mut [&mut prefix], 0), 3);
        assert_eq!(&prefix, b"abc");
        let mut rest = [0xcc; 12];
        assert_eq!(receive(&receiver, &mut [&mut rest], libc::MSG_WAITALL), 5);
        assert_eq!(&rest[..5], b"defgh");
        assert_eq!(&rest[5..], &[0xcc; 7]);
        assert_eq!(receive(&receiver, &mut [&mut rest], 0), 0);
    });
}

#[test]
fn single_buffer_waitall_spans_two_writes() {
    run_each(|| {
        let (mut sender, receiver) = connected();
        sender.write_all(b"abc").unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1));
            sender.write_all(b"defgh").unwrap();
        });
        let mut out = [0; 8];
        assert_eq!(receive(&receiver, &mut [&mut out], libc::MSG_WAITALL), 8);
        assert_eq!(&out, b"abcdefgh");
        writer.join().unwrap();
    });
}

#[test]
fn empty_and_multiple_buffers_preserve_the_stream() {
    run_each(|| {
        let (mut sender, receiver) = connected();
        sender.write_all(b"abcdefgh").unwrap();
        assert_eq!(receive(&receiver, &mut [], 0), 0);
        assert_eq!(receive(&receiver, &mut [&mut []], 0), 0);
        let mut first = [0; 3];
        let mut last = [0xcc; 8];
        assert_eq!(receive(&receiver, &mut [&mut first, &mut last], 0), 8);
        assert_eq!(&first, b"abc");
        assert_eq!(&last[..5], b"defgh");
        assert_eq!(&last[5..], &[0xcc; 3]);
    });
}

#[test]
fn peek_waitall_returns_short_data_at_fin_without_consuming_it() {
    run_each(|| {
        for multiple in [false, true] {
            let (mut sender, receiver) = connected();
            sender.write_all(b"abc").unwrap();
            sender.shutdown(Shutdown::Write).unwrap();
            let mut first = [0xcc; 2];
            let mut last = [0xcc; 8];
            let flags = libc::MSG_PEEK | libc::MSG_WAITALL;
            if multiple {
                assert_eq!(receive(&receiver, &mut [&mut first, &mut last], flags), 3);
                assert_eq!(&first, b"ab");
                assert_eq!(last[0], b'c');
                assert_eq!(&last[1..], &[0xcc; 7]);
            } else {
                assert_eq!(receive(&receiver, &mut [&mut last], flags), 3);
                assert_eq!(&last[..3], b"abc");
                assert_eq!(&last[3..], &[0xcc; 5]);
            }
            let mut consumed = [0xcc; 8];
            assert_eq!(receive(&receiver, &mut [&mut consumed], 0), 3);
            assert_eq!(&consumed[..3], b"abc");
            assert_eq!(&consumed[3..], &[0xcc; 5]);
            assert_eq!(receive(&receiver, &mut [&mut consumed], 0), 0);
        }
    });
}
