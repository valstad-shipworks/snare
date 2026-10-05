#![cfg(windows)]

//! The Windows don't-fragment options: `IP_DONTFRAGMENT` at `IPPROTO_IP` and `IPV6_DONTFRAG` at
//! `IPPROTO_IPV6` (both 14, booleans), and `IP_MTU_DISCOVER`/`IPV6_MTU_DISCOVER` (71, a
//! `PMTUD_STATE`) ([Microsoft Learn: IPPROTO_IP socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options),
//! [IPPROTO_IPV6 socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options)).
//! A datagram that may not be fragmented and is larger than the egress interface's MTU fails
//! with `WSAEMSGSIZE`.
//!
//! The option round trip runs on the real stack and in the sim side by side; the size check needs
//! an interface with a small MTU, which real loopback is not, so it runs in the sim only.

use std::net::UdpSocket;
use std::time::Duration;

use snare::{IpNet, NicSpec, Sim};
use windows_sys::Win32::Networking::WinSock as ws;

#[path = "support/winsock.rs"]
mod winsock;

use winsock::{get, raw, set_int};

/// Reads, sets and reads back each don't-fragment option on an IPv4 and an IPv6 socket, and the
/// other family's option on each: every outcome, labelled.
fn round_trips() -> Vec<String> {
    let v4 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let v6 = UdpSocket::bind("[::1]:0").unwrap();
    let ip = ws::IPPROTO_IP;
    let ip6 = ws::IPPROTO_IPV6;
    let mut out = Vec::new();
    for (label, sock, level, name, value) in [
        ("v4 IP_DONTFRAGMENT", &v4, ip, ws::IP_DONTFRAGMENT, 1),
        ("v6 IPV6_DONTFRAG", &v6, ip6, ws::IPV6_DONTFRAG, 1),
        (
            "v4 IP_MTU_DISCOVER",
            &v4,
            ip,
            ws::IP_MTU_DISCOVER,
            ws::IP_PMTUDISC_DO,
        ),
        (
            "v6 IPV6_MTU_DISCOVER",
            &v6,
            ip6,
            ws::IPV6_MTU_DISCOVER,
            ws::IP_PMTUDISC_DO,
        ),
        ("v4 IPV6_DONTFRAG", &v4, ip6, ws::IPV6_DONTFRAG, 1),
        (
            "v4 IP_MTU_DISCOVER out of range",
            &v4,
            ip,
            ws::IP_MTU_DISCOVER,
            9,
        ),
    ] {
        let s = raw(sock);
        out.push(format!("{label} default: {:?}", get(s, level, name)));
        out.push(format!(
            "{label} set {value}: {:?}",
            set_int(s, level, name, value)
        ));
        out.push(format!("{label} after: {:?}", get(s, level, name)));
    }
    out
}

#[test]
fn dontfrag_options_os_truth() {
    let real = snare::real(round_trips);
    let sim = Sim::new().run(round_trips);
    let diff: Vec<String> = real
        .iter()
        .zip(&sim)
        .filter(|(r, s)| r != s)
        .map(|(r, s)| format!("real {r}\n sim {s}"))
        .collect();
    assert!(diff.is_empty(), "{}", diff.join("\n"));
}

/// Over an interface with a 1500-byte MTU: with `IP_DONTFRAGMENT` set, a datagram that fits
/// (1472 bytes of payload, 8 of UDP header, 20 of IP) arrives and one a byte larger fails
/// `WSAEMSGSIZE`; without it a 4000-byte datagram arrives whole.
#[test]
fn dont_fragment_follows_the_egress_mtu() {
    let sim = Sim::builder()
        .nic(
            NicSpec::new("eth0")
                .address("10.0.0.1/24".parse::<IpNet>().unwrap())
                .station("10.0.0.2".parse::<std::net::IpAddr>().unwrap())
                .mtu(1500),
        )
        .build();
    sim.run(|| {
        let host = UdpSocket::bind("10.0.0.1:0").unwrap();
        let station = UdpSocket::bind("10.0.0.2:0").unwrap();
        station
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let to = station.local_addr().unwrap();
        let mut buf = vec![0u8; 8192];
        assert_eq!(host.send_to(&[7u8; 4000], to).unwrap(), 4000);
        assert_eq!(station.recv_from(&mut buf).unwrap().0, 4000);
        set_int(raw(&host), ws::IPPROTO_IP, ws::IP_DONTFRAGMENT, 1).unwrap();
        assert_eq!(host.send_to(&[7u8; 1472], to).unwrap(), 1472);
        assert_eq!(station.recv_from(&mut buf).unwrap().0, 1472);
        let err = host.send_to(&[7u8; 1473], to).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(ws::WSAEMSGSIZE));
    });
}

#[test]
fn mtu_discovery_modes_match_the_host() {
    let probe = || {
        let _startup = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut results = Vec::new();
        for family in [ws::AF_INET, ws::AF_INET6] {
            for kind in [ws::SOCK_DGRAM, ws::SOCK_STREAM] {
                for level in [ws::IPPROTO_IP, ws::IPPROTO_IPV6] {
                    for mode in [-1, 0, 1, 2, 3, 4] {
                        let socket = unsafe { ws::socket(family as i32, kind, 0) };
                        assert_ne!(socket, ws::INVALID_SOCKET);
                        let result = set_int(socket, level, ws::IP_MTU_DISCOVER, mode);
                        results.push((
                            family,
                            kind,
                            level,
                            mode,
                            result,
                            get(socket, level, ws::IP_MTU_DISCOVER),
                        ));
                        unsafe { ws::closesocket(socket) };
                    }
                }
            }
        }
        results
    };
    let real = snare::real(probe);
    assert_eq!(Sim::new().run(probe), real);
}

#[test]
fn fragmentation_option_interactions_match_the_host() {
    let probe = || {
        let _startup = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut results = Vec::new();
        for family in [ws::AF_INET, ws::AF_INET6] {
            for flag_level in [ws::IPPROTO_IP, ws::IPPROTO_IPV6] {
                for flag in [0, 1] {
                    for mode_level in [ws::IPPROTO_IP, ws::IPPROTO_IPV6] {
                        for mode in [0, 1, 2, 3] {
                            let socket = unsafe { ws::socket(family as i32, ws::SOCK_DGRAM, 0) };
                            assert_ne!(socket, ws::INVALID_SOCKET);
                            let before = (
                                get(socket, ws::IPPROTO_IP, ws::IP_DONTFRAGMENT),
                                get(socket, ws::IPPROTO_IPV6, ws::IPV6_DONTFRAG),
                            );
                            let set_flag = set_int(socket, flag_level, ws::IP_DONTFRAGMENT, flag);
                            let set_mode = set_int(socket, mode_level, ws::IP_MTU_DISCOVER, mode);
                            let after = (
                                get(socket, ws::IPPROTO_IP, ws::IP_DONTFRAGMENT),
                                get(socket, ws::IPPROTO_IPV6, ws::IPV6_DONTFRAG),
                                get(socket, ws::IPPROTO_IP, ws::IP_MTU_DISCOVER),
                                get(socket, ws::IPPROTO_IPV6, ws::IPV6_MTU_DISCOVER),
                            );
                            results.push((
                                family, flag_level, flag, mode_level, mode, before, set_flag,
                                set_mode, after,
                            ));
                            unsafe { ws::closesocket(socket) };
                        }
                    }
                }
            }
        }
        results
    };
    let real = snare::real(probe);
    assert_eq!(Sim::new().run(probe), real);
}

#[test]
fn legacy_fragmentation_after_a_discovery_mode_matches_the_host() {
    let probe = || {
        let _startup = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut results = Vec::new();
        for family in [ws::AF_INET, ws::AF_INET6] {
            for level in [ws::IPPROTO_IP, ws::IPPROTO_IPV6] {
                for mode in [0, 1, 2, 3] {
                    let socket = unsafe { ws::socket(family as i32, ws::SOCK_DGRAM, 0) };
                    let discovery = set_int(socket, level, ws::IP_MTU_DISCOVER, mode);
                    let flag = set_int(socket, level, ws::IP_DONTFRAGMENT, 1);
                    results.push((
                        family,
                        level,
                        mode,
                        discovery,
                        flag,
                        get(socket, level, ws::IP_DONTFRAGMENT),
                        get(socket, level, ws::IP_MTU_DISCOVER),
                    ));
                    unsafe { ws::closesocket(socket) };
                }
            }
        }
        results
    };
    let real = snare::real(probe);
    assert_eq!(Sim::new().run(probe), real);
}
