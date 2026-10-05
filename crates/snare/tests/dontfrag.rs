#![cfg(unix)]

//! The don't-fragment options: Linux `IP_MTU_DISCOVER`, `IPV6_MTU_DISCOVER` and `IPV6_DONTFRAG`,
//! macOS `IP_DONTFRAG` and `IPV6_DONTFRAG`. They are modelled (strict mode accepts them), read
//! back with the host's semantics, and refuse a datagram larger than the egress interface's MTU
//! with `EMSGSIZE`, where without them the datagram is delivered whole. `dontfrag_os_truth`
//! compares the sim with the real stack on loopback (MTU 16384 on macOS `lo0`, 65536 on Linux
//! `lo`).

use std::net::UdpSocket;
use std::os::fd::AsRawFd;

use snare::{IpNet, NicSpec, Sim};

/// The `errno` of the last failed call.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

/// `setsockopt` of an `int`, passing `len` bytes of it.
fn set(s: &UdpSocket, level: i32, name: i32, value: i32, len: u32) -> Result<(), i32> {
    let value = (&raw const value).cast();
    let rc = unsafe { libc::setsockopt(s.as_raw_fd(), level, name, value, len) };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

/// `getsockopt` into a buffer of `len` bytes, returning the bytes written.
fn get(s: &UdpSocket, level: i32, name: i32, len: u32) -> Result<Vec<u8>, i32> {
    let mut buf = [0xa5u8; 4];
    let mut len = len;
    let out = buf.as_mut_ptr().cast();
    let rc = unsafe { libc::getsockopt(s.as_raw_fd(), level, name, out, &mut len) };
    if rc == 0 {
        Ok(buf[..len as usize].to_vec())
    } else {
        Err(errno())
    }
}

/// The option's `int` value.
fn get_int(s: &UdpSocket, level: i32, name: i32) -> Result<i32, i32> {
    get(s, level, name, 4).map(|b| i32::from_ne_bytes(b.try_into().unwrap()))
}

/// Sends `size` bytes from `tx` to `rx`, returning the send's outcome and, if it was sent, what
/// `rx` received.
fn send(tx: &UdpSocket, rx: &UdpSocket, size: usize) -> (Result<usize, i32>, Option<usize>) {
    let sent = tx
        .send_to(&vec![7u8; size], rx.local_addr().unwrap())
        .map_err(|e| e.raw_os_error().unwrap());
    let mut buf = vec![0u8; 70_000];
    let got = sent
        .is_ok()
        .then(|| rx.recv_from(&mut buf).ok().map(|(n, _)| n))
        .flatten();
    (sent, got)
}

/// A sender and a receiver on loopback of the family `v6` names, with buffers large enough for
/// any datagram (macOS refuses a datagram larger than `SO_SNDBUF`) and a receive timeout, since
/// real loopback delivers a moment after the send returns.
fn pair(v6: bool) -> (UdpSocket, UdpSocket) {
    let at = if v6 { "[::1]:0" } else { "127.0.0.1:0" };
    let tx = UdpSocket::bind(at).unwrap();
    let rx = UdpSocket::bind(at).unwrap();
    rx.set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .unwrap();
    set(&tx, libc::SOL_SOCKET, libc::SO_SNDBUF, 1 << 17, 4).unwrap();
    set(&rx, libc::SOL_SOCKET, libc::SO_RCVBUF, 1 << 20, 4).unwrap();
    (tx, rx)
}

#[cfg(target_os = "linux")]
mod os {
    pub const IP_MTU_DISCOVER: i32 = 10;
    pub const IPV6_MTU_DISCOVER: i32 = 23;
    pub const IPV6_DONTFRAG: i32 = 62;
}

#[cfg(target_os = "macos")]
mod os {
    pub const IP_DONTFRAG: i32 = 28;
    pub const IPV6_DONTFRAG: i32 = 62;
}

/// A labelled set of `(level, name, value)` options to set before sending.
#[cfg(target_os = "linux")]
type Mode<'a> = (&'a str, &'a [(i32, i32, i32)]);

/// Everything the host's stack answers about the options, as lines to compare.
#[cfg(target_os = "linux")]
fn scenario() -> Vec<String> {
    use libc::{IPPROTO_IP, IPPROTO_IPV6};
    use os::*;
    let mut out = Vec::new();
    for v6 in [false, true] {
        let at = if v6 { "[::1]:0" } else { "127.0.0.1:0" };
        for (level, name) in [
            (IPPROTO_IP, IP_MTU_DISCOVER),
            (IPPROTO_IPV6, IPV6_MTU_DISCOVER),
            (IPPROTO_IPV6, IPV6_DONTFRAG),
        ] {
            let s = UdpSocket::bind(at).unwrap();
            out.push(format!(
                "v6={v6} {level}/{name} default {:?}",
                get_int(&s, level, name)
            ));
            for value in [-1, 0, 1, 2, 3, 4, 5, 6, 9] {
                out.push(format!(
                    "v6={v6} {level}/{name} set {value} {:?} reads {:?}",
                    set(&s, level, name, value, 4),
                    get_int(&s, level, name)
                ));
            }
            out.push(format!(
                "v6={v6} {level}/{name} 1-byte set {:?} reads {:?}; 0-byte set {:?} reads {:?}",
                set(&s, level, name, 2, 1),
                get_int(&s, level, name),
                set(&s, level, name, 2, 0),
                get_int(&s, level, name),
            ));
            let _ = set(&s, level, name, 3, 4);
            out.push(format!(
                "v6={v6} {level}/{name} 1-byte read {:?}",
                get(&s, level, name, 1)
            ));
        }
        let sizes: &[usize] = if v6 {
            &[65488, 65489, 65527]
        } else {
            &[65000, 65507]
        };
        let modes: &[Mode] = if v6 {
            &[
                ("default", &[]),
                ("dont", &[(IPPROTO_IPV6, IPV6_MTU_DISCOVER, 0)]),
                ("do", &[(IPPROTO_IPV6, IPV6_MTU_DISCOVER, 2)]),
                ("probe", &[(IPPROTO_IPV6, IPV6_MTU_DISCOVER, 3)]),
                ("interface", &[(IPPROTO_IPV6, IPV6_MTU_DISCOVER, 4)]),
                ("omit", &[(IPPROTO_IPV6, IPV6_MTU_DISCOVER, 5)]),
                ("dontfrag", &[(IPPROTO_IPV6, IPV6_DONTFRAG, 1)]),
                (
                    "dontfrag+omit",
                    &[
                        (IPPROTO_IPV6, IPV6_MTU_DISCOVER, 5),
                        (IPPROTO_IPV6, IPV6_DONTFRAG, 1),
                    ],
                ),
                ("ipv4 do", &[(IPPROTO_IP, IP_MTU_DISCOVER, 2)]),
            ]
        } else {
            &[
                ("default", &[]),
                ("do", &[(IPPROTO_IP, IP_MTU_DISCOVER, 2)]),
            ]
        };
        for &(label, opts) in modes {
            let (tx, rx) = pair(v6);
            for &(level, name, value) in opts {
                set(&tx, level, name, value, 4).unwrap();
            }
            for &size in sizes {
                out.push(format!(
                    "v6={v6} {label} {size}: {:?}",
                    send(&tx, &rx, size)
                ));
            }
        }
    }
    out
}

/// Everything the host's stack answers about the options, as lines to compare.
#[cfg(target_os = "macos")]
fn scenario() -> Vec<String> {
    use libc::{IPPROTO_IP, IPPROTO_IPV6};
    use os::*;
    let mut out = Vec::new();
    for v6 in [false, true] {
        for (level, name) in [(IPPROTO_IP, IP_DONTFRAG), (IPPROTO_IPV6, IPV6_DONTFRAG)] {
            let s = UdpSocket::bind(if v6 { "[::1]:0" } else { "127.0.0.1:0" }).unwrap();
            out.push(format!(
                "v6={v6} {level}/{name} default {:?}",
                get_int(&s, level, name)
            ));
            for value in [-1, 0, 1, 2, 9] {
                out.push(format!(
                    "v6={v6} {level}/{name} set {value} {:?} reads {:?}",
                    set(&s, level, name, value, 4),
                    get_int(&s, level, name)
                ));
            }
            out.push(format!(
                "v6={v6} {level}/{name} short sets {:?} {:?} reads {:?}; 1-byte read {:?}",
                set(&s, level, name, 0, 1),
                set(&s, level, name, 0, 0),
                get_int(&s, level, name),
                get(&s, level, name, 1),
            ));
        }
        let (dontfrag, sizes): ((i32, i32), &[usize]) = if v6 {
            ((IPPROTO_IPV6, IPV6_DONTFRAG), &[16336, 16337, 20000])
        } else {
            ((IPPROTO_IP, IP_DONTFRAG), &[16356, 16357, 20000])
        };
        for df in [false, true, false] {
            let (tx, rx) = pair(v6);
            set(&tx, dontfrag.0, dontfrag.1, df.into(), 4).unwrap();
            for &size in sizes {
                out.push(format!(
                    "v6={v6} df={df} {size}: {:?}",
                    send(&tx, &rx, size)
                ));
            }
        }
    }
    let mapped = UdpSocket::bind("[::]:0").unwrap();
    set(&mapped, libc::SOL_SOCKET, libc::SO_SNDBUF, 1 << 17, 4).unwrap();
    set(&mapped, IPPROTO_IPV6, IPV6_DONTFRAG, 1, 4).unwrap();
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    rx.set_nonblocking(true).unwrap();
    let to: std::net::SocketAddr =
        format!("[::ffff:127.0.0.1]:{}", rx.local_addr().unwrap().port())
            .parse()
            .unwrap();
    for size in [16356usize, 16357] {
        let sent = mapped
            .send_to(&vec![7u8; size], to)
            .map_err(|e| e.raw_os_error().unwrap());
        out.push(format!("v4-mapped dontfrag6 {size}: {sent:?}"));
    }
    out
}

/// The sim answers as the host's stack does: values, optlen rules, the other family's options,
/// and which loopback datagrams fail `EMSGSIZE` or arrive whole.
#[test]
fn dontfrag_os_truth() {
    let real = scenario();
    let sim = Sim::builder().strict_sockopts().build().run(scenario);
    let diff: Vec<String> = real
        .iter()
        .zip(&sim)
        .filter(|(r, s)| r != s)
        .map(|(r, s)| format!("real {r}\n sim {s}"))
        .collect();
    assert!(diff.is_empty(), "{}", diff.join("\n"));
    assert_eq!(real.len(), sim.len());
}

/// What fast-talker's `SocketOption::DontFragment(true)` sets is accepted under strict mode.
#[test]
fn fast_talker_dont_fragment_is_modelled() {
    Sim::builder().strict_sockopts().build().run(|| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let s6 = UdpSocket::bind("[::1]:0").unwrap();
        #[cfg(target_os = "linux")]
        {
            let (ip, ip6) = (libc::IPPROTO_IP, libc::IPPROTO_IPV6);
            let r#do = libc::IP_PMTUDISC_DO;
            assert_eq!(set(&s, ip, os::IP_MTU_DISCOVER, r#do, 4), Ok(()));
            assert_eq!(get_int(&s, ip, os::IP_MTU_DISCOVER), Ok(r#do));
            assert_eq!(
                set(&s6, ip6, os::IPV6_MTU_DISCOVER, libc::IPV6_PMTUDISC_DO, 4),
                Ok(())
            );
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(set(&s, libc::IPPROTO_IP, os::IP_DONTFRAG, 1, 4), Ok(()));
            assert_eq!(get_int(&s, libc::IPPROTO_IP, os::IP_DONTFRAG), Ok(1));
            assert_eq!(
                set(&s6, libc::IPPROTO_IPV6, os::IPV6_DONTFRAG, 1, 4),
                Ok(())
            );
        }
        let id = snare::socket_id(&s).unwrap();
        assert!(
            snare::socket_entry(id)
                .unwrap()
                .unmodelled_options
                .is_empty()
        );
    });
}

/// Over an interface of the topology with a 1500-byte MTU: a don't-fragment datagram one byte past
/// it fails, one that fits arrives, and without don't-fragment a larger one arrives whole.
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
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        assert_eq!(send(&host, &station, 4000), (Ok(4000), Some(4000)));
        #[cfg(target_os = "linux")]
        set(
            &host,
            libc::IPPROTO_IP,
            os::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_DO,
            4,
        )
        .unwrap();
        #[cfg(target_os = "macos")]
        set(&host, libc::IPPROTO_IP, os::IP_DONTFRAG, 1, 4).unwrap();
        assert_eq!(send(&host, &station, 1472), (Ok(1472), Some(1472)));
        assert_eq!(send(&host, &station, 1473), (Err(libc::EMSGSIZE), None));
        let back = host.local_addr().unwrap();
        assert_eq!(
            station
                .send_to(&[1u8; 4000], back)
                .map_err(|e| e.raw_os_error()),
            Ok(4000),
            "a station's datagram leaves through no interface of the host"
        );
    });
}
