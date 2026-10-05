use std::io::ErrorKind;
use std::net::SocketAddr;

use snare::{UdpPolicy, UdpSocket, inject_udp_from_test, register_test, seed_rng, set_udp_policy};

const PACKETS: u32 = 400;

fn lossy_socket() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    set_udp_policy(addr, |p: &mut UdpPolicy| p.loss_rate = 0.5);
    socket.set_nonblocking(true).unwrap();
    (socket, addr)
}

fn drain(socket: &UdpSocket) -> Vec<u32> {
    let mut buf = [0u8; 4];
    let mut got = Vec::new();
    loop {
        match socket.recv_from(&mut buf) {
            Ok((4, _)) => got.push(u32::from_le_bytes(buf)),
            Ok(_) => panic!("short datagram"),
            Err(e) if e.kind() == ErrorKind::WouldBlock => return got,
            Err(e) => panic!("{e}"),
        }
    }
}

/// Which of flow A's packets survive, with flow B optionally sending from
/// another thread at the same time.
fn flow_a_survivors(
    (a, a_addr): &(UdpSocket, SocketAddr),
    (b, b_addr): &(UdpSocket, SocketAddr),
    with_b: bool,
) -> Vec<u32> {
    let (a_addr, b_addr) = (*a_addr, *b_addr);
    seed_rng(99);
    let src_a: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let src_b: SocketAddr = "10.0.0.2:6000".parse().unwrap();

    let other = with_b.then(|| {
        snare::thread::spawn(move || {
            for i in 0..PACKETS {
                inject_udp_from_test(src_b, b_addr, i.to_le_bytes().to_vec());
                if i % 7 == 0 {
                    std::thread::yield_now();
                }
            }
        })
    });
    for i in 0..PACKETS {
        inject_udp_from_test(src_a, a_addr, i.to_le_bytes().to_vec());
        if i % 5 == 0 {
            std::thread::yield_now();
        }
    }
    if let Some(h) = other {
        h.join().unwrap();
        let b_got = drain(b);
        assert!(!b_got.is_empty() && b_got.len() < PACKETS as usize);
    }
    drain(a)
}

#[test]
fn a_flows_losses_do_not_depend_on_other_flows() {
    register_test();
    let a = lossy_socket();
    let b = lossy_socket();
    let alone = flow_a_survivors(&a, &b, false);
    let shared = flow_a_survivors(&a, &b, true);
    assert!(
        alone.len() > PACKETS as usize / 4 && alone.len() < PACKETS as usize * 3 / 4,
        "{} of {PACKETS} survived",
        alone.len()
    );
    assert_eq!(alone, shared);
}
