#![cfg(windows)]

//! Winsock's socket buffers: `SO_RCVBUF`/`SO_SNDBUF` stored as given, a datagram admitted while
//! the queued payload is below `SO_RCVBUF`, and `FIONREAD` capped at it.

use std::net::UdpSocket;
use std::os::windows::io::AsRawSocket;

use snare::Sim;
use windows_sys::Win32::Networking::WinSock::{
    FIONREAD, SO_RCVBUF, SO_SNDBUF, SOL_SOCKET, WSAEFAULT, WSAGetLastError, getsockopt,
    ioctlsocket, setsockopt,
};

fn set(sock: &UdpSocket, name: i32, val: &[u8]) -> Result<(), i32> {
    let rc = unsafe {
        setsockopt(
            sock.as_raw_socket() as usize,
            SOL_SOCKET,
            name,
            val.as_ptr(),
            val.len() as i32,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(unsafe { WSAGetLastError() })
    }
}

fn get(sock: &UdpSocket, name: i32) -> i32 {
    let mut v = 0i32;
    let mut len = 4i32;
    let rc = unsafe {
        getsockopt(
            sock.as_raw_socket() as usize,
            SOL_SOCKET,
            name,
            (&mut v as *mut i32).cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0);
    v
}

fn fionread(sock: &UdpSocket) -> u32 {
    let mut v = 0u32;
    let rc = unsafe { ioctlsocket(sock.as_raw_socket() as usize, FIONREAD, &mut v) };
    assert_eq!(rc, 0);
    v
}

#[test]
fn sockbuf_as_given() {
    Sim::new().run(|| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(get(&s, SO_RCVBUF), 65536);
        assert_eq!(get(&s, SO_SNDBUF), 65536);
        for v in [-1i32, 0, 5, 10_000_000] {
            set(&s, SO_RCVBUF, &v.to_ne_bytes()).unwrap();
            assert_eq!(get(&s, SO_RCVBUF), v);
        }
        set(&s, SO_SNDBUF, &7i32.to_ne_bytes()).unwrap();
        assert_eq!(get(&s, SO_SNDBUF), 7);
        assert_eq!(set(&s, SO_RCVBUF, &[1, 0]), Err(WSAEFAULT));
    });
}

#[test]
fn overflow_admits_while_below_rcvbuf() {
    Sim::new().run(|| {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        set(&rx, SO_RCVBUF, &1000i32.to_ne_bytes()).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..5 {
            tx.send_to(&[0; 400], rx.local_addr().unwrap()).unwrap();
        }
        let e = snare::socket_entry(snare::socket_id(&rx).unwrap()).unwrap();
        assert_eq!((e.delivered, e.overflowed, e.queued_bytes), (3, 2, 1200));
    });
}

#[test]
fn fionread_capped() {
    Sim::new().run(|| {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        set(&rx, SO_RCVBUF, &1000i32.to_ne_bytes()).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(fionread(&rx), 0);
        tx.send_to(&[0; 400], rx.local_addr().unwrap()).unwrap();
        assert_eq!(fionread(&rx), 400);
        for _ in 0..2 {
            tx.send_to(&[0; 400], rx.local_addr().unwrap()).unwrap();
        }
        assert_eq!(fionread(&rx), 1000, "1200 queued, capped at SO_RCVBUF");
    });
}
