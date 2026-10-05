//! Multicast delivery against the machine the tests run on: whether a socket that did not join
//! a group receives it once another socket of the host has (Linux `IP_MULTICAST_ALL`), and whether
//! a member bound to a unicast address receives it, real and simulated side by side. Needs an interface multicast can loop back over, which any machine
//! with a default route has.

use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use snare::Sim;

/// Whether a wildcard socket on `port + 1` receives a datagram to the group while a socket on
/// `port` is its member; and whether the member receives its own.
fn delivery(port: u16) -> (bool, bool) {
    let group = Ipv4Addr::new(239, 255, 42, 98);
    let member = UdpSocket::bind(("0.0.0.0", port)).unwrap();
    member
        .join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)
        .unwrap();
    let bystander = UdpSocket::bind(("0.0.0.0", port + 1)).unwrap();
    let tx = UdpSocket::bind("0.0.0.0:0").unwrap();
    tx.set_multicast_loop_v4(true).unwrap();
    tx.send_to(b"m", (group, port)).unwrap();
    tx.send_to(b"b", (group, port + 1)).unwrap();
    let got = |s: &UdpSocket| {
        s.set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        s.recv_from(&mut [0u8; 8]).is_ok()
    };
    (got(&member), got(&bystander))
}

#[test]
fn multicast_all_matches_real_os() {
    let real = delivery(47120);
    let sim = Sim::new().run(|| delivery(47120));
    assert_eq!(sim, real);
    assert_eq!(real, (true, cfg!(target_os = "linux")));
}

/// Whether a socket bound to `127.0.0.1:port` that joined the group receives a datagram sent to it.
fn unicast_bound_delivery(port: u16) -> bool {
    let group = Ipv4Addr::new(239, 255, 42, 97);
    let member = UdpSocket::bind(("127.0.0.1", port)).unwrap();
    member
        .join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)
        .unwrap();
    let tx = UdpSocket::bind("0.0.0.0:0").unwrap();
    tx.set_multicast_loop_v4(true).unwrap();
    tx.send_to(b"u", (group, port)).unwrap();
    member
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    member.recv_from(&mut [0u8; 8]).is_ok()
}

#[test]
fn unicast_bound_member_matches_real_os() {
    let real = unicast_bound_delivery(47130);
    let sim = Sim::new().run(|| unicast_bound_delivery(47130));
    assert_eq!(sim, real);
}
