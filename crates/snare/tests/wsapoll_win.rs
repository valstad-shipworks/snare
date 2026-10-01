#![cfg(windows)]

//! `WSAPoll` over the Winsock fabric's sockets: readiness reporting and a blocking wait that wakes
//! on a cross-thread send. (`std` has no `WSAPoll` wrapper, so these call it via `windows-sys`.)

use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::windows::io::AsRawSocket;
use std::time::Duration;

use snare::Sim;
use windows_sys::Win32::Networking::WinSock::{POLLRDNORM, WSAPOLLFD, WSAPoll};

fn pollfd(fd: usize) -> WSAPOLLFD {
    WSAPOLLFD {
        fd,
        events: POLLRDNORM,
        revents: 0,
    }
}

#[test]
fn wsapoll_udp_readability() {
    Sim::new().run(|| {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b_addr = b.local_addr().unwrap();
        let mut pfd = pollfd(b.as_raw_socket() as usize);

        // Nothing sent yet: a zero-timeout poll finds nothing ready.
        assert_eq!(unsafe { WSAPoll(&mut pfd, 1, 0) }, 0);

        a.send_to(b"x", b_addr).unwrap();
        let n = unsafe { WSAPoll(&mut pfd, 1, 1000) };
        assert_eq!(n, 1);
        assert!(pfd.revents & POLLRDNORM != 0, "b reported readable");
    });
}

#[test]
fn wsapoll_blocks_until_cross_thread_send() {
    Sim::new().run(|| {
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b_addr = b.local_addr().unwrap();
        let sender = std::thread::spawn(move || {
            let a = UdpSocket::bind("127.0.0.1:0").unwrap();
            std::thread::sleep(Duration::from_millis(20));
            a.send_to(b"wake", b_addr).unwrap();
        });
        let mut pfd = pollfd(b.as_raw_socket() as usize);
        let n = unsafe { WSAPoll(&mut pfd, 1, 5000) };
        assert_eq!(n, 1);
        sender.join().unwrap();
    });
}

#[test]
fn wsapoll_listener_readable_on_pending_connection() {
    Sim::new().run(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut pfd = pollfd(listener.as_raw_socket() as usize);
        assert_eq!(unsafe { WSAPoll(&mut pfd, 1, 0) }, 0);

        let client = std::thread::spawn(move || {
            let _c = TcpStream::connect(addr).unwrap();
            std::thread::sleep(Duration::from_millis(50));
        });
        // The listener becomes readable once a connection is pending.
        let n = unsafe { WSAPoll(&mut pfd, 1, 5000) };
        assert_eq!(n, 1);
        assert!(pfd.revents & POLLRDNORM != 0);
        let _ = listener.accept().unwrap();
        client.join().unwrap();
    });
}
