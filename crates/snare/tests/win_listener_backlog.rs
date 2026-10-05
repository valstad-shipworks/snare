#![cfg(windows)]

use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use snare::Sim;
use windows_sys::Win32::Networking::WinSock as ws;

fn backlog_capacity(backlog: i32, relisten: Option<i32>) -> usize {
    drop(UdpSocket::bind("127.0.0.1:0").unwrap());
    let fd = unsafe { ws::socket(ws::AF_INET as i32, ws::SOCK_STREAM, 0) };
    assert_ne!(fd, ws::INVALID_SOCKET);
    let mut address: ws::SOCKADDR_IN = unsafe { std::mem::zeroed() };
    address.sin_family = ws::AF_INET;
    address.sin_addr.S_un.S_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    assert_eq!(
        unsafe {
            ws::bind(
                fd,
                (&raw const address).cast(),
                std::mem::size_of_val(&address) as i32,
            )
        },
        0
    );
    let mut len = std::mem::size_of_val(&address) as i32;
    assert_eq!(
        unsafe { ws::getsockname(fd, (&raw mut address).cast(), &mut len) },
        0
    );
    let at = SocketAddr::from(([127, 0, 0, 1], u16::from_be(address.sin_port)));
    assert_eq!(unsafe { ws::listen(fd, backlog) }, 0);
    let mut clients = Vec::new();
    for _ in 0..5 {
        match TcpStream::connect_timeout(&at, Duration::from_millis(100)) {
            Ok(client) => {
                clients.push(client);
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
                break;
            }
        }
    }
    if let Some(backlog) = relisten {
        assert_eq!(unsafe { ws::listen(fd, backlog) }, 0);
        assert_eq!(
            TcpStream::connect_timeout(&at, Duration::from_millis(100))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::TimedOut
        );
    }
    for client in &clients {
        let accepted = unsafe { ws::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_ne!(accepted, ws::INVALID_SOCKET);
        let mut peer: ws::SOCKADDR_IN = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&peer) as i32;
        assert_eq!(
            unsafe { ws::getpeername(accepted, (&raw mut peer).cast(), &mut len) },
            0
        );
        assert_eq!(
            u16::from_be(peer.sin_port),
            client.local_addr().unwrap().port()
        );
        unsafe { ws::closesocket(accepted) };
    }
    unsafe { ws::closesocket(fd) };
    clients.len()
}

#[test]
fn listener_capacity_and_unchanged_relisten_match_winsock() {
    for (backlog, relisten) in [(0, None), (1, None), (2, None), (3, None), (1, Some(4))] {
        let native = snare::real(|| backlog_capacity(backlog, relisten));
        assert_eq!(native, backlog.max(1) as usize);
        for sim in [Sim::new(), Sim::builder().deterministic().seed(7).build()] {
            assert_eq!(sim.run(|| backlog_capacity(backlog, relisten)), native);
        }
    }
}
