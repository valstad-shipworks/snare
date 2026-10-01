#![cfg(windows)]

//! Windows UDP: `std::net::UdpSocket` serviced from process memory by the Winsock fabric, the way
//! the unix `tests/udp_fabric.rs` exercises the Berkeley-sockets path. Datagram semantics follow
//! Winsock `socket`/`bind`/`connect`/`sendto`/`recvfrom`.

use std::net::UdpSocket;
use std::time::Duration;

use snare::Sim;

#[test]
fn sendto_and_recvfrom() {
    Sim::new().run(|| {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b_addr = b.local_addr().unwrap();

        a.send_to(b"ping", b_addr).unwrap();

        let mut buf = [0u8; 16];
        let (n, from) = b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from, a.local_addr().unwrap());
    });
}

#[test]
fn blocking_recv_wakes_on_cross_thread_send() {
    Sim::new().run(|| {
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b_addr = b.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let a = UdpSocket::bind("127.0.0.1:0").unwrap();
            std::thread::sleep(Duration::from_millis(20));
            a.send_to(b"wake", b_addr).unwrap();
        });
        let mut buf = [0u8; 16];
        let (n, _) = b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"wake");
        sender.join().unwrap();
    });
}

#[test]
fn connect_fixes_peer() {
    Sim::new().run(|| {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(server_addr).unwrap();
        client.send(b"hello").unwrap();

        let mut buf = [0u8; 16];
        let (n, from) = server.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(from, client.local_addr().unwrap());
    });
}

#[test]
fn several_addresses_on_one_port() {
    Sim::new().run(|| {
        let port = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let one = UdpSocket::bind(("127.0.0.1", port)).unwrap();
        let two = UdpSocket::bind(("127.0.0.2", port)).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"to-one", ("127.0.0.1", port)).unwrap();
        sender.send_to(b"to-two", ("127.0.0.2", port)).unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = one.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"to-one");
        let (n, _) = two.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"to-two");
    });
}

#[test]
fn nonblocking_recv_is_wouldblock_when_empty() {
    Sim::new().run(|| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 16];
        let err = s.recv_from(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    });
}
