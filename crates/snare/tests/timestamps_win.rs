#![cfg(windows)]

//! Winsock timestamping, as Microsoft documents it
//! ([Microsoft Learn: Winsock timestamping](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-timestamping)):
//! UDP only. `WSAIoctl(SIO_TIMESTAMPING)` with a `TIMESTAMPING_CONFIG` enables receive stamps
//! (`TIMESTAMPING_FLAG_RX`), which `WSARecvMsg` returns as an `SO_TIMESTAMP` (0x300A) control
//! message holding a `UINT64`, and transmit stamps (`TIMESTAMPING_FLAG_TX`, with
//! `TxTimestampsBuffered` the per-socket buffer), which a `WSASendMsg` tags with an
//! `SO_TIMESTAMP_ID` (0x300B) control message holding a `UINT32` and `SIO_GET_TX_TIMESTAMP` then
//! polls for by that id: the stamp, removed from the buffer, or `WSAEWOULDBLOCK` while it is not
//! there; a stamp generated while the buffer is full is discarded. Software stamps count on the
//! `QueryPerformanceCounter` clock.
//!
//! `tx_timestamp_before_configuring_on_windows` pins the one code measured on the real stack. A
//! real host also needs timestamping enabled system-wide, so the stamping itself is checked in
//! the sim only.

use std::net::UdpSocket;
use std::time::Duration;

use snare::Sim;
use windows_sys::Win32::Networking::WinSock as ws;

#[path = "support/winsock.rs"]
mod winsock;

use winsock::{cmsg, cmsgs, qpc, raw, recv_msg, send_msg, wsa_ioctl};

/// `SIO_TIMESTAMPING` with `flags` and a transmit buffer of `buffered` stamps.
fn configure(sock: &UdpSocket, flags: u32, buffered: u16) -> Result<u32, i32> {
    let config = ws::TIMESTAMPING_CONFIG {
        Flags: flags,
        TxTimestampsBuffered: buffered,
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&raw const config).cast::<u8>(),
            size_of::<ws::TIMESTAMPING_CONFIG>(),
        )
    };
    wsa_ioctl(raw(sock), ws::SIO_TIMESTAMPING, bytes, &mut [])
}

/// `SIO_GET_TX_TIMESTAMP` for `id`: the stamp, or the error.
fn tx_timestamp(sock: &UdpSocket, id: u32) -> Result<u64, i32> {
    let mut out = [0u8; 8];
    wsa_ioctl(
        raw(sock),
        ws::SIO_GET_TX_TIMESTAMP,
        &id.to_ne_bytes(),
        &mut out,
    )?;
    Ok(u64::from_ne_bytes(out))
}

/// Polling for a transmit stamp on a socket that never enabled them.
fn unconfigured_tx_timestamp() -> Result<u64, i32> {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    tx_timestamp(&sock, 1)
}

/// What the real Winsock answers when a transmit stamp is polled for before `SIO_TIMESTAMPING`
/// enabled them: `WSAEOPNOTSUPP` (measured on Windows 11).
#[test]
fn tx_timestamp_before_configuring_on_windows() {
    assert_eq!(
        snare::real(unconfigured_tx_timestamp),
        Err(ws::WSAEOPNOTSUPP)
    );
}

#[test]
fn tx_timestamp_before_configuring_os_truth() {
    let real = snare::real(unconfigured_tx_timestamp);
    let sim = Sim::new().run(unconfigured_tx_timestamp);
    assert_eq!(sim, real);
}

#[test]
fn unsupported_outbound_control_messages_fail_without_sending() {
    for deterministic in [false, true] {
        let mut builder = Sim::builder();
        if deterministic {
            builder = builder.deterministic();
        }
        builder.build().run(|| {
            let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
            rx.set_nonblocking(true).unwrap();
            let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut control = cmsg(ws::IPPROTO_IP, ws::IP_PKTINFO, &[0; 8]);
            assert_eq!(
                send_msg(
                    raw(&tx),
                    b"unselected",
                    Some(rx.local_addr().unwrap()),
                    &mut control
                ),
                Err(ws::WSAEOPNOTSUPP)
            );
            assert_eq!(
                rx.recv(&mut [0; 16]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        });
    }
}

/// A datagram received on a socket with receive stamps enabled carries one `SO_TIMESTAMP`
/// control message: the `QueryPerformanceCounter` value when it reached the socket, after the
/// send and no later than the receive.
#[test]
fn rx_timestamp_is_the_arrival_on_the_qpc_clock() {
    Sim::new().run(|| {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        configure(&rx, ws::TIMESTAMPING_FLAG_RX, 0).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let sent_at = qpc();
        tx.send_to(b"stamp me", rx.local_addr().unwrap()).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let mut data = [0u8; 64];
        let mut control = [0u8; 64];
        let (n, control_len, _) = recv_msg(raw(&rx), &mut data, &mut control).unwrap();
        let read_at = qpc();
        assert_eq!(&data[..n as usize], b"stamp me");
        let stamps: Vec<u64> = cmsgs(&control, control_len)
            .into_iter()
            .filter(|(level, ty, _)| *level == ws::SOL_SOCKET && *ty == ws::SO_TIMESTAMP as i32)
            .map(|(_, _, d)| u64::from_ne_bytes(d[..8].try_into().unwrap()))
            .collect();
        assert_eq!(stamps.len(), 1, "one SO_TIMESTAMP message");
        assert!(
            (sent_at as u64..=read_at as u64).contains(&stamps[0]),
            "stamp {} outside [{sent_at}, {read_at}]",
            stamps[0]
        );
    });
}

/// Without `SIO_TIMESTAMPING` a received datagram carries no `SO_TIMESTAMP` message.
#[test]
fn no_rx_timestamp_unless_enabled() {
    Sim::new().run(|| {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(b"plain", rx.local_addr().unwrap()).unwrap();
        let mut data = [0u8; 64];
        let mut control = [0u8; 64];
        let (n, control_len, _) = recv_msg(raw(&rx), &mut data, &mut control).unwrap();
        assert_eq!(&data[..n as usize], b"plain");
        assert!(cmsgs(&control, control_len).is_empty());
    });
}

/// A datagram sent with an `SO_TIMESTAMP_ID` on a socket buffering one transmit stamp: polling
/// that id returns its send time on the QPC clock once and then `WSAEWOULDBLOCK`, as does an id
/// never sent; a second datagram sent while the first stamp is still buffered loses its stamp.
#[test]
fn tx_timestamp_by_id() {
    Sim::new().run(|| {
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        configure(&tx, ws::TIMESTAMPING_FLAG_TX, 1).unwrap();
        let to = Some(rx.local_addr().unwrap());
        let before = qpc() as u64;
        let mut tag = cmsg(
            ws::SOL_SOCKET,
            ws::SO_TIMESTAMP_ID as i32,
            &123u32.to_ne_bytes(),
        );
        assert_eq!(send_msg(raw(&tx), b"first", to, &mut tag), Ok(5));
        let mut tag = cmsg(
            ws::SOL_SOCKET,
            ws::SO_TIMESTAMP_ID as i32,
            &124u32.to_ne_bytes(),
        );
        assert_eq!(send_msg(raw(&tx), b"second", to, &mut tag), Ok(6));
        let after = qpc() as u64;
        let stamp = tx_timestamp(&tx, 123).unwrap();
        assert!(
            (before..=after).contains(&stamp),
            "{stamp} outside [{before}, {after}]"
        );
        assert_eq!(
            tx_timestamp(&tx, 123),
            Err(ws::WSAEWOULDBLOCK),
            "taken once"
        );
        assert_eq!(
            tx_timestamp(&tx, 124),
            Err(ws::WSAEWOULDBLOCK),
            "discarded: buffer full"
        );
        assert_eq!(
            tx_timestamp(&tx, 999),
            Err(ws::WSAEWOULDBLOCK),
            "never sent"
        );
    });
}
