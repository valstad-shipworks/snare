//! A UDP policy set at the address a connected socket reports as its own shapes what arrives at
//! it, whether the socket was bound there or at the wildcard. Windows keeps a wildcard-bound
//! socket at the wildcard for delivery after a connect while reporting the connected source as
//! its local address; the policy at the reported address must still apply.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use snare::{Sim, SocketKind};

fn received(rx: &UdpSocket, tx: &UdpSocket, to: SocketAddr, n: usize) -> usize {
    for i in 0..n {
        tx.send_to(&[i as u8], to).unwrap();
    }
    std::thread::sleep(Duration::from_millis(50));
    let mut got = 0;
    let mut buf = [0u8; 8];
    rx.set_nonblocking(true).unwrap();
    while rx.recv(&mut buf).is_ok() {
        got += 1;
    }
    got
}

fn check(bind_at: Ipv4Addr) {
    Sim::new().run(|| {
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx = UdpSocket::bind(SocketAddr::new(bind_at.into(), 0)).unwrap();
        let port = rx.local_addr().unwrap().port();
        let to = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
        rx.connect(tx.local_addr().unwrap()).unwrap();
        let reported = rx.local_addr().unwrap();
        let listed = snare::socket_table()
            .into_iter()
            .find(|s| s.kind == SocketKind::Udp && s.peer == Some(tx.local_addr().unwrap()))
            .and_then(|s| s.local)
            .expect("the connected socket is listed");
        assert_eq!(listed, reported, "getsockname and the socket table agree");

        assert_eq!(
            received(&rx, &tx, to, 20),
            20,
            "a perfect link delivers everything"
        );
        snare::set_udp_policy(reported, |p| p.loss_rate = 1.0);
        assert_eq!(
            received(&rx, &tx, to, 20),
            0,
            "the policy at the reported local address {reported} loses everything"
        );
        snare::set_udp_policy(reported, |p| p.loss_rate = 0.0);
        assert_eq!(received(&rx, &tx, to, 20), 20, "cleared");
    });
}

#[test]
fn policy_at_a_specifically_bound_connected_socket() {
    check(Ipv4Addr::LOCALHOST);
}

#[test]
fn policy_at_a_wildcard_bound_connected_socket() {
    check(Ipv4Addr::UNSPECIFIED);
}
