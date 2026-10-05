#![cfg(windows)]

//! Windows TCP: real `std::net::TcpListener`/`TcpStream` serviced from process memory by the
//! Winsock fabric — `socket`/`bind`/`listen`/`accept`/`connect`/`send`/`recv`. A listener thread
//! and a client thread, both inside the sim, are the two ends of the wire.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;

use snare::Sim;

#[test]
fn echo_roundtrip() {
    Sim::new().run(|| {
        let (tx, rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            let (mut stream, _peer) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).unwrap();
            let msg = std::str::from_utf8(&buf[..n]).unwrap();
            stream.write_all(format!("echo:{msg}").as_bytes()).unwrap();
        });

        let addr = rx.recv().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(b"hello\n").unwrap();
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"echo:hello\n");
        server.join().unwrap();
    });
}

#[test]
fn peer_addresses_round_trip() {
    Sim::new().run(|| {
        let (tx, rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            let (stream, peer) = listener.accept().unwrap();
            // The accepted socket's peer is the client's local address.
            assert_eq!(peer, stream.peer_addr().unwrap());
        });
        let addr = rx.recv().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        assert_eq!(client.peer_addr().unwrap(), addr);
        server.join().unwrap();
    });
}

#[test]
fn try_clone_shares_the_connection() {
    Sim::new().run(|| {
        let (tx, rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).unwrap();
            stream.write_all(&buf[..n]).unwrap();
        });
        let addr = rx.recv().unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        // A cloned handle refers to the same connection: write on one, read on the other.
        let mut writer = stream.try_clone().unwrap();
        let mut reader = stream;
        writer.write_all(b"split").unwrap();
        let mut buf = [0u8; 16];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"split");
        server.join().unwrap();
    });
}

#[test]
fn reader_sees_eof_when_peer_closes() {
    Sim::new().run(|| {
        let (tx, rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"bye").unwrap();
            // drop closes the connection
        });
        let addr = rx.recv().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"bye");
        server.join().unwrap();
    });
}

/// `TcpStream::peek` (`recv` with `MSG_PEEK`) shows queued bytes without taking them
/// ([Microsoft Learn: recv](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv),
/// `MSG_PEEK`): a peek then a read see the same bytes, on the real stack and in the sim.
fn peek_then_read() -> (Vec<u8>, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    client.write_all(b"peekaboo").unwrap();
    let mut peeked = [0u8; 8];
    let mut got = 0;
    while got < peeked.len() {
        got = server.peek(&mut peeked).unwrap();
    }
    let mut read = [0u8; 8];
    (&server).read_exact(&mut read).unwrap();
    (peeked.to_vec(), read.to_vec())
}

#[test]
fn peek_leaves_bytes_queued_os_truth() {
    let real = snare::real(peek_then_read);
    let simmed = Sim::new().run(peek_then_read);
    assert_eq!(real, (b"peekaboo".to_vec(), b"peekaboo".to_vec()));
    assert_eq!(simmed, real);
}
