//! Multicast delivery: a socket receives a group's datagrams when it joined the group, and on
//! Linux also, through `IP_MULTICAST_ALL`, when any socket of the host did.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};

use snare::{Sim, proto_counters};

const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 99);

/// Whether `s` has a datagram waiting.
fn got(s: &UdpSocket) -> bool {
    s.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 16];
    match s.recv_from(&mut buf) {
        Ok(_) => true,
        Err(e) if e.kind() == ErrorKind::WouldBlock => false,
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn joined_socket_receives_its_group() {
    Sim::new().run(|| {
        let member = UdpSocket::bind("0.0.0.0:47001").unwrap();
        member
            .join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED)
            .unwrap();
        let tx = UdpSocket::bind("0.0.0.0:0").unwrap();
        tx.send_to(b"hi", (GROUP, 47001)).unwrap();
        assert!(got(&member));
    });
}

#[test]
fn unjoined_socket_follows_multicast_all() {
    Sim::new().run(|| {
        let member = UdpSocket::bind("0.0.0.0:47002").unwrap();
        member
            .join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED)
            .unwrap();
        let bystander = UdpSocket::bind("0.0.0.0:47003").unwrap();
        let tx = UdpSocket::bind("0.0.0.0:0").unwrap();
        tx.send_to(b"hi", (GROUP, 47003)).unwrap();
        assert_eq!(
            got(&bystander),
            cfg!(target_os = "linux"),
            "only Linux delivers a group the socket did not join"
        );
    });
}

#[test]
fn group_nobody_joined_reaches_no_one() {
    Sim::new().run(|| {
        let bystander = UdpSocket::bind("0.0.0.0:47004").unwrap();
        let tx = UdpSocket::bind("0.0.0.0:0").unwrap();
        tx.send_to(b"hi", (GROUP, 47004)).unwrap();
        assert!(!got(&bystander));
        assert_eq!(
            proto_counters().udp4.ignored_multi,
            0,
            "the host never took it in"
        );
    });
}

#[test]
fn joined_group_with_no_socket_on_the_port_is_ignored_multi() {
    Sim::new().run(|| {
        let member = UdpSocket::bind("0.0.0.0:47005").unwrap();
        member
            .join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED)
            .unwrap();
        let tx = UdpSocket::bind("0.0.0.0:0").unwrap();
        tx.send_to(b"hi", (GROUP, 47099)).unwrap();
        assert_eq!(proto_counters().udp4.ignored_multi, 1);
    });
}

#[test]
fn loopback_bound_socket_drops_multicast_from_the_default_interface() {
    Sim::new().run(|| {
        let member = UdpSocket::bind("127.0.0.1:47006").unwrap();
        member
            .join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED)
            .unwrap();
        let tx = UdpSocket::bind("0.0.0.0:0").unwrap();
        tx.send_to(b"hi", (GROUP, 47006)).unwrap();
        assert!(!got(&member));
    });
}

#[test]
fn ipv6_group_delivery() {
    Sim::new().run(|| {
        let group: Ipv6Addr = "ff15::4242".parse().unwrap();
        let member = UdpSocket::bind("[::]:47007").unwrap();
        member.join_multicast_v6(&group, 0).unwrap();
        let bystander = UdpSocket::bind("[::]:47008").unwrap();
        let tx = UdpSocket::bind("[::]:0").unwrap();
        tx.send_to(b"hi", (group, 47007)).unwrap();
        tx.send_to(b"hi", (group, 47008)).unwrap();
        assert!(got(&member));
        assert_eq!(got(&bystander), cfg!(target_os = "linux"));
    });
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::os::fd::AsRawFd;

    const IP_MULTICAST_ALL: i32 = 49;
    const IPV6_MULTICAST_ALL: i32 = 29;

    fn set(s: &UdpSocket, level: i32, name: i32, v: i32) -> Result<(), i32> {
        let rc =
            unsafe { libc::setsockopt(s.as_raw_fd(), level, name, (&v as *const i32).cast(), 4) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap())
        }
    }

    fn get(s: &UdpSocket, level: i32, name: i32) -> i32 {
        let mut v = -1i32;
        let mut len = 4u32;
        let rc = unsafe {
            libc::getsockopt(
                s.as_raw_fd(),
                level,
                name,
                (&mut v as *mut i32).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0);
        v
    }

    fn multicast_all_option_and_effect() {
        let member = UdpSocket::bind("0.0.0.0:47010").unwrap();
        member
            .join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED)
            .unwrap();
        let bystander = UdpSocket::bind("0.0.0.0:47011").unwrap();
        assert_eq!(get(&bystander, libc::IPPROTO_IP, IP_MULTICAST_ALL), 1);
        assert_eq!(get(&bystander, libc::IPPROTO_IPV6, IPV6_MULTICAST_ALL), 1);
        assert_eq!(
            set(&bystander, libc::IPPROTO_IP, IP_MULTICAST_ALL, 2),
            Err(libc::EINVAL)
        );
        set(&bystander, libc::IPPROTO_IP, IP_MULTICAST_ALL, 0).unwrap();
        assert_eq!(get(&bystander, libc::IPPROTO_IP, IP_MULTICAST_ALL), 0);
        let tx = UdpSocket::bind("0.0.0.0:0").unwrap();
        tx.send_to(b"hi", (GROUP, 47011)).unwrap();
        assert!(!got(&bystander), "off: only its own joins");
        assert_eq!(proto_counters().udp4.ignored_multi, 1);
        bystander
            .join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED)
            .unwrap();
        tx.send_to(b"hi", (GROUP, 47011)).unwrap();
        assert!(got(&bystander));
    }

    #[test]
    fn multicast_all_option() {
        Sim::new().run(multicast_all_option_and_effect);
    }

    #[test]
    fn multicast_all_option_under_simhost() {
        Sim::builder()
            .host(snare::HostProfile::new().build())
            .build()
            .run(multicast_all_option_and_effect);
    }
}
