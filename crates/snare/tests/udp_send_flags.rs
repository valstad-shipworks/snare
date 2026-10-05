#![cfg(unix)]

use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

fn stalled_send(directed: bool) {
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    let source = sender.local_addr().unwrap();
    let destination = receiver.local_addr().unwrap();
    sender.connect(destination).unwrap();
    snare::set_udp_policy(source, |policy| policy.send_queue_depth = Some(0));
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(1));
        snare::set_udp_policy(source, |policy| policy.send_queue_depth = None);
    });
    let result = if directed {
        let SocketAddr::V4(destination) = destination else {
            unreachable!()
        };
        let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        address.sin_family = libc::AF_INET as _;
        address.sin_port = destination.port().to_be();
        address.sin_addr.s_addr = u32::from_ne_bytes(destination.ip().octets());
        #[cfg(target_os = "macos")]
        {
            address.sin_len = std::mem::size_of_val(&address) as _;
        }
        unsafe {
            libc::sendto(
                sender.as_raw_fd(),
                b"blocked".as_ptr().cast(),
                7,
                libc::MSG_DONTWAIT,
                std::ptr::from_ref(&address).cast(),
                std::mem::size_of_val(&address) as _,
            )
        }
    } else {
        unsafe {
            libc::send(
                sender.as_raw_fd(),
                b"blocked".as_ptr().cast(),
                7,
                libc::MSG_DONTWAIT,
            )
        }
    };
    let error = std::io::Error::last_os_error().raw_os_error();
    release.join().unwrap();
    assert_eq!(result, -1);
    assert_eq!(error, Some(libc::EAGAIN));
    receiver.set_nonblocking(true).unwrap();
    let mut buffer = [0; 16];
    assert_eq!(
        receiver.recv(&mut buffer).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(sender.send(b"after").unwrap(), 5);
    assert_eq!(receiver.recv(&mut buffer).unwrap(), 5);
    assert_eq!(&buffer[..5], b"after");
}

#[test]
fn dontwait_send_does_not_wait_for_a_stalled_udp_link() {
    for directed in [false, true] {
        snare::Sim::new().run(|| stalled_send(directed));
        snare::Sim::builder()
            .deterministic()
            .build()
            .run(|| stalled_send(directed));
    }
}
