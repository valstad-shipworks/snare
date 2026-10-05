//! The interface model under `--cfg snare_global`: every thread shares one
//! network, so an interface one thread adds is visible to all. Empty unless
//! the cfg is set. Run with:
//!
//! ```sh
//! RUSTFLAGS='--cfg snare_global' cargo test --features shim --test nic_model_global
//! ```
#![cfg(all(snare_global, feature = "shim"))]

use std::net::SocketAddr;
use std::thread;

use snare::{
    NicSpec, UdpSocket, add_nic, nic, nic_counters, route_lookup, socket_entry, socket_id,
};

#[test]
fn unregistered_threads_share_the_interfaces() {
    add_nic(NicSpec::new("glob0").address("10.77.0.1/24".parse::<snare::IpNet>().unwrap()))
        .unwrap();
    let rx = UdpSocket::bind("10.77.0.1:9000").unwrap();
    rx.set_nonblocking(true).unwrap();

    let entry = thread::spawn(|| {
        assert_eq!(
            route_lookup(None, "10.77.0.9".parse().unwrap()).unwrap().0,
            "glob0"
        );
        let tx = UdpSocket::bind("10.77.0.1:0").unwrap();
        tx.send_to(b"hello", "10.77.0.1:9000").unwrap();
        socket_entry(socket_id(&tx)).unwrap()
    })
    .join()
    .unwrap();
    assert_eq!(entry.nic.as_deref(), Some("glob0"));

    let mut buf = [0u8; 8];
    let (n, from): (usize, SocketAddr) = rx.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"hello");
    assert_eq!(from, entry.local);
    assert!(nic("glob0").unwrap().explicit);
    assert_eq!(nic_counters("glob0").unwrap().rx_packets, 1);
}
