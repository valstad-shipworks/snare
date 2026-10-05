#![cfg(unix)]

use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

fn run_each(f: impl Fn() + Copy) {
    snare::Sim::new().run(f);
    snare::Sim::builder().deterministic().build().run(f);
}

fn set_buffer(socket: &UdpSocket, option: i32, value: i32) {
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of_val(&value) as _,
        )
    };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
}

fn available(socket: &UdpSocket) -> usize {
    let mut bytes = -1;
    assert_eq!(
        unsafe { libc::ioctl(socket.as_raw_fd(), libc::FIONREAD, &mut bytes) },
        0
    );
    bytes as usize
}

#[test]
fn boundary_payloads_keep_peek_truncation_and_receive_accounting() {
    run_each(|| {
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        set_buffer(&sender, libc::SO_SNDBUF, 262_144);
        set_buffer(&receiver, libc::SO_RCVBUF, 262_144);
        receiver.set_nonblocking(true).unwrap();
        let destination = receiver.local_addr().unwrap();
        for (index, len) in [0, 127, 128, 129, 65_507].into_iter().enumerate() {
            let mut payload: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
            let expected = payload.clone();
            assert_eq!(sender.send_to(&payload, destination).unwrap(), len);
            payload.fill(255);
            let charge = if cfg!(target_os = "macos") {
                len + if index == 0 { 16 } else { 32 }
            } else {
                len
            };
            assert_eq!(available(&receiver), charge);
            let mut peek = vec![0xcc; len + 1];
            for _ in 0..2 {
                let (n, source) = receiver.peek_from(&mut peek).unwrap();
                assert_eq!(source, sender.local_addr().unwrap());
                assert_eq!(n, len);
                assert_eq!(&peek[..n], expected);
                assert_eq!(peek[n], 0xcc);
                assert_eq!(available(&receiver), charge);
            }
            let mut truncated = [0xcc; 17];
            let n = receiver.recv(&mut truncated).unwrap();
            assert_eq!(n, len.min(truncated.len()));
            assert_eq!(&truncated[..n], &expected[..n]);
            assert_eq!(available(&receiver), 0);
            assert_eq!(
                receiver.recv(&mut truncated).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    });
}

#[test]
fn delayed_duplicates_own_inline_and_heap_payloads() {
    run_each(|| {
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let destination = receiver.local_addr().unwrap();
        snare::set_udp_policy(destination, |policy| {
            policy.latency = Duration::from_millis(1);
            policy.duplicate_rate = 1.0;
        });
        for len in [0, 127, 128, 129] {
            let mut payload: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
            let expected = payload.clone();
            sender.send_to(&payload, destination).unwrap();
            payload.fill(255);
            drop(payload);
            let mut buffer = [0xcc; 130];
            assert_eq!(receiver.peek(&mut buffer).unwrap(), len);
            assert_eq!(&buffer[..len], expected);
            for _ in 0..2 {
                assert_eq!(receiver.recv(&mut buffer).unwrap(), len);
                assert_eq!(&buffer[..len], expected);
            }
            receiver.set_nonblocking(true).unwrap();
            assert_eq!(
                receiver.recv(&mut buffer).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            receiver.set_nonblocking(false).unwrap();
        }
    });
}

#[test]
fn unix_datagram_pairs_preserve_inline_boundary_payloads() {
    run_each(|| {
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        for len in [0, 127, 128, 129] {
            let mut payload: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
            let expected = payload.clone();
            assert_eq!(sender.send(&payload).unwrap(), len);
            payload.fill(255);
            let mut buffer = [0xcc; 130];
            assert_eq!(receiver.recv(&mut buffer).unwrap(), len);
            assert_eq!(&buffer[..len], expected);
            assert_eq!(buffer[len], 0xcc);
        }
    });
}
