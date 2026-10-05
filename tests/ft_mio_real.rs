//! Without the shim, `snare::fast_talker::Timestamped` over
//! `snare::mio::net::UdpSocket` is fast-talker's over real mio.
#![cfg(not(feature = "shim"))]

use std::time::Duration;

use snare::fast_talker::{Source, Timestamped};
use snare::mio::event::Events;
use snare::mio::net::UdpSocket;
use snare::mio::{Interest, Poll, Token};

#[test]
fn a_real_mio_socket_in_timestamped_is_a_mio_source() {
    let mut rx = Timestamped::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let to = rx.local_addr().unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let mut poll = Poll::new().unwrap();
    poll.registry()
        .register(&mut rx, Token(7), Interest::READABLE)
        .unwrap();
    tx.send_to(b"ping", to).unwrap();

    let mut events = Events::with_capacity(4);
    let mut got = Vec::new();
    let mut buf = [0u8; 16];
    for _ in 0..50 {
        poll.poll(&mut events, Some(Duration::from_millis(100)))
            .unwrap();
        for e in events.iter() {
            assert_eq!(e.token(), Token(7));
            rx.drain(&mut buf, |p, r| got.push((p.to_vec(), r)))
                .unwrap();
        }
        if !got.is_empty() {
            break;
        }
    }
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, b"ping");
    assert!(got[0].1.timestamp.source >= Source::UserSpace);
    assert!(rx.source() >= Source::UserSpace);
}
