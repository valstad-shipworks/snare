#![cfg(unix)]

//! `SO_RCVTIMEO` (`set_read_timeout`): a blocking receive that outlives the timeout gives up with
//! `WouldBlock` rather than parking forever. On the wall clock it waits the real span; on the
//! (default) virtual clock the timeout is a pending deadline the quiescence time-skip jumps to, so
//! it returns as-fast-as-possible with virtual time advanced by the timeout.

use std::io::Read;
use std::net::{TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use snare::{Line, Sim, connect_tester};

#[test]
fn udp_recv_times_out_with_wouldblock() {
    Sim::builder().wall_clock().build().run(|| {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut buf = [0u8; 16];
        let start = Instant::now();
        let err = sock.recv_from(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        assert!(start.elapsed() >= Duration::from_millis(40), "waited out most of the timeout");
    });
}

#[test]
fn tcp_recv_times_out_with_wouldblock() {
    Sim::builder().wall_clock().build().run(|| {
        let _peer = connect_tester::<Line>("127.0.0.3:9500");
        let mut stream = TcpStream::connect("127.0.0.3:9500").unwrap();
        stream.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut buf = [0u8; 16];
        let start = Instant::now();
        let err = stream.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        assert!(start.elapsed() >= Duration::from_millis(40), "waited out most of the timeout");
    });
}

#[test]
fn recv_timeout_skips_virtual_time() {
    let real = Instant::now();
    Sim::builder().virtual_clock().build().run(|| {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 16];
        let start = Instant::now();
        let err = sock.recv_from(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        assert!(start.elapsed() >= Duration::from_millis(4900), "virtual time reached the timeout");
    });
    assert!(real.elapsed() < Duration::from_secs(5), "ran as-fast-as-possible, not 5 real s");
}

#[test]
fn a_waiting_peer_still_wins_before_the_timeout() {
    // The timeout must not pre-empt data that arrives first: a sender posts well within the window.
    Sim::new().run(|| {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let addr = receiver.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.send_to(b"hi", addr).unwrap();
        });
        let mut buf = [0u8; 16];
        let (n, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hi");
        sender.join().unwrap();
    });
}

#[test]
fn read_timeout_round_trips() {
    Sim::new().run(|| {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(sock.read_timeout().unwrap().is_none(), "unset by default");
        sock.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
        assert_eq!(sock.read_timeout().unwrap(), Some(Duration::from_millis(250)));
        sock.set_read_timeout(None).unwrap();
        assert!(sock.read_timeout().unwrap().is_none(), "cleared again");
    });
}
