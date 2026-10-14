#![cfg(windows)]

//! Winsock's control messages against the real stack on loopback: the receive options
//! (`IP_PKTINFO`, `IP_RECVECN`, `IP_RECVTTL`, `IP_RECVTOS` and their `IPPROTO_IPV6` counterparts)
//! and UDP offload sizes (`UDP_SEND_MSG_SIZE`, `UDP_RECV_MAX_COALESCED_SIZE`) with their read-back,
//! short values and the sockets that refuse them; the control messages `WSASendMsg` takes (ECN,
//! TOS/traffic class, hop limit, source selection, segment size) and the ones it refuses; the
//! messages `WSARecvMsg` returns, in order, and what it does with a control buffer too short;
//! segmentation offload (USO) to sockets with and without receive coalescing (URO), its limits and
//! the coalescing rule. Each probe runs on the real Winsock (`snare::real`) and in a sim, and every
//! outcome is compared.
//!
//! Left out because the sim differs (OPEN_BUGS.md): an `IP_PKTINFO` with an unspecified source
//! address from a wildcard-bound socket, and the byte count of a `WSARecvMsg` that fails
//! `WSAEMSGSIZE`.

use std::net::{Ipv6Addr, UdpSocket};
use std::time::Duration;

use snare::Sim;
use windows_sys::Win32::Networking::WinSock as ws;

#[path = "support/winsock.rs"]
mod winsock;

use winsock::{Raw, cmsg, cmsgs, raw, send_msg, set_int, wsa_ioctl, wsa_recv_msg_fn};

const IP: i32 = ws::IPPROTO_IP;
const IP6: i32 = ws::IPPROTO_IPV6;
const UDP: i32 = ws::IPPROTO_UDP;

/// The real and simulated outcomes that differ.
#[track_caller]
fn assert_same(real: Vec<String>, sim: Vec<String>) {
    assert_eq!(real.len(), sim.len(), "real {real:#?}\nsim {sim:#?}");
    let differ: Vec<String> = real
        .iter()
        .zip(&sim)
        .filter(|(r, s)| r != s)
        .map(|(r, s)| format!("host {r}\n sim {s}"))
        .collect();
    assert!(differ.is_empty(), "{}", differ.join("\n"));
}

fn compare(probe: fn() -> Vec<String>) {
    let real = snare::real(probe);
    let sim = Sim::new().run(probe);
    assert_same(real, sim);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn int(v: i32) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

fn set_bytes(s: Raw, level: i32, name: i32, value: &[u8]) -> Result<(), i32> {
    let rc = unsafe { ws::setsockopt(s, level, name, value.as_ptr(), value.len() as i32) };
    if rc == 0 {
        Ok(())
    } else {
        Err(winsock::last_error())
    }
}

/// An option read into a buffer of `cap` bytes: the bytes written and the length reported.
fn get_bytes(s: Raw, level: i32, name: i32, cap: usize) -> Result<String, i32> {
    let mut value = vec![0xAAu8; cap];
    let mut len = cap as i32;
    let rc = unsafe { ws::getsockopt(s, level, name, value.as_mut_ptr(), &mut len) };
    if rc == 0 {
        let shown = (len.max(0) as usize).min(cap);
        Ok(format!("{} ({len})", hex(&value[..shown])))
    } else {
        Err(winsock::last_error())
    }
}

fn udp(at: &str) -> UdpSocket {
    let s = UdpSocket::bind(at).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    s
}

/// A raw socket of `family` and `ty`, closed by the caller.
fn socket(family: u16, ty: i32) -> Raw {
    let _ = UdpSocket::bind("127.0.0.1:0");
    let s = unsafe { ws::socket(family.into(), ty, 0) };
    assert_ne!(s, ws::INVALID_SOCKET, "socket: {}", winsock::last_error());
    s
}

/// A UDP socket at `at` with every receive option of its family on.
fn receiver(at: &str) -> UdpSocket {
    let s = udp(at);
    let level = if at.starts_with('[') { IP6 } else { IP };
    for name in [
        ws::IP_PKTINFO,
        ws::IP_RECVECN,
        ws::IP_RECVTTL,
        ws::IP_RECVTOS,
    ] {
        set_int(raw(&s), level, name, 1).unwrap();
    }
    s
}

fn pktinfo4(addr: [u8; 4], index: u32) -> Vec<u8> {
    [&addr[..], &index.to_ne_bytes()].concat()
}

fn pktinfo6(addr: &str, index: u32) -> Vec<u8> {
    let addr: Ipv6Addr = addr.parse().unwrap();
    [&addr.octets()[..], &index.to_ne_bytes()].concat()
}

/// One `WSARecvMsg` into `data_cap` bytes of data and `control_cap` of control: the result, the
/// source, `Control.len`, the flags, the messages (a receive stamp shown as such) and the control
/// bytes written. The byte count is shown only on success.
fn recv_full(s: &UdpSocket, data_cap: usize, control_cap: Option<usize>) -> String {
    let recv = wsa_recv_msg_fn(raw(s)).unwrap();
    let mut data = vec![0u8; data_cap];
    let mut control = vec![0xEEu8; control_cap.unwrap_or(0)];
    let mut buf = ws::WSABUF {
        len: data_cap as u32,
        buf: data.as_mut_ptr(),
    };
    let mut from: ws::SOCKADDR_STORAGE = unsafe { std::mem::zeroed() };
    let mut msg = ws::WSAMSG {
        name: (&raw mut from).cast(),
        namelen: size_of::<ws::SOCKADDR_STORAGE>() as i32,
        lpBuffers: &mut buf,
        dwBufferCount: 1,
        Control: ws::WSABUF {
            len: control.len() as u32,
            buf: if control_cap.is_some() {
                control.as_mut_ptr()
            } else {
                std::ptr::null_mut()
            },
        },
        dwFlags: 0,
    };
    let mut got = 0u32;
    let rc = unsafe {
        recv(
            raw(s),
            &mut msg,
            &mut got,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc != 0 && msg.dwFlags == 0 {
        return format!("err {}", winsock::last_error());
    }
    let result = if rc == 0 {
        format!("n={got}")
    } else {
        format!("err {}", winsock::last_error())
    };
    let from = unsafe { std::slice::from_raw_parts((&raw const from).cast::<u8>(), 28) };
    let src = if u16::from_ne_bytes([from[0], from[1]]) == ws::AF_INET {
        format!("{}.{}.{}.{}", from[4], from[5], from[6], from[7])
    } else {
        Ipv6Addr::from(<[u8; 16]>::try_from(&from[8..24]).unwrap()).to_string()
    };
    let shown = (msg.Control.len as usize).min(control.len());
    let msgs: Vec<String> = cmsgs(&control, shown as u32)
        .into_iter()
        .map(|(level, ty, d)| {
            if level == ws::SOL_SOCKET {
                format!("{level}/{ty}:stamp")
            } else {
                format!("{level}/{ty}:{}", hex(&d))
            }
        })
        .collect();
    let written = control
        .iter()
        .rposition(|&b| b != 0xEE)
        .map_or(0, |i| i + 1);
    format!(
        "{result} src={src} clen={} flags={:#x} [{}] written={}",
        msg.Control.len,
        msg.dwFlags,
        msgs.join(" "),
        if msgs.iter().any(|m| m.ends_with("stamp")) {
            written.to_string()
        } else {
            hex(&control[..written])
        }
    )
}

/// Everything waiting at `s`, read with `WSARecvMsg` until a receive times out: runs of equal
/// receives counted.
fn drain(s: &UdpSocket, data_cap: usize) -> String {
    let mut runs: Vec<(String, usize)> = Vec::new();
    for _ in 0..1000 {
        let r = recv_full(s, data_cap, Some(256));
        let stop = r.starts_with("err");
        match runs.last_mut() {
            Some((last, n)) if *last == r => *n += 1,
            _ => runs.push((r, 1)),
        }
        if stop {
            break;
        }
    }
    runs.into_iter()
        .map(|(r, n)| if n == 1 { r } else { format!("{n}x {r}") })
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Sets, reads back and refuses the receive options and offload sizes on IPv4, IPv6 and
/// dual-stack datagram sockets and on a TCP socket.
fn options() -> Vec<String> {
    let mut out = Vec::new();
    let v4 = udp("127.0.0.1:0");
    let v6 = udp("[::1]:0");
    let unbound_dual = socket(ws::AF_INET6, ws::SOCK_DGRAM);
    set_int(unbound_dual, IP6, ws::IPV6_V6ONLY, 0).unwrap();
    let wildcard_dual = socket(ws::AF_INET6, ws::SOCK_DGRAM);
    set_int(wildcard_dual, IP6, ws::IPV6_V6ONLY, 0).unwrap();
    let (mut any, len) = winsock::sockaddr("[::]:0".parse().unwrap());
    assert_eq!(
        unsafe { ws::bind(wildcard_dual, any.as_mut_ptr().cast(), len) },
        0
    );
    let loopback_dual = socket(ws::AF_INET6, ws::SOCK_DGRAM);
    set_int(loopback_dual, IP6, ws::IPV6_V6ONLY, 0).unwrap();
    let (mut lo, len) = winsock::sockaddr("[::1]:0".parse().unwrap());
    assert_eq!(
        unsafe { ws::bind(loopback_dual, lo.as_mut_ptr().cast(), len) },
        0
    );
    let tcp = socket(ws::AF_INET, ws::SOCK_STREAM);
    let receive = [
        ("IP_PKTINFO", IP, ws::IP_PKTINFO),
        ("IP_RECVECN", IP, ws::IP_RECVECN),
        ("IP_RECVTTL", IP, ws::IP_RECVTTL),
        ("IP_RECVTOS", IP, ws::IP_RECVTOS),
        ("IPV6_PKTINFO", IP6, ws::IPV6_PKTINFO),
        ("IPV6_RECVECN", IP6, ws::IPV6_RECVECN),
        ("IPV6_HOPLIMIT", IP6, ws::IPV6_HOPLIMIT),
        ("IPV6_RECVTCLASS", IP6, ws::IPV6_RECVTCLASS),
        ("UDP_SEND_MSG_SIZE", UDP, ws::UDP_SEND_MSG_SIZE),
        (
            "UDP_RECV_MAX_COALESCED_SIZE",
            UDP,
            ws::UDP_RECV_MAX_COALESCED_SIZE,
        ),
    ];
    for (sock, s) in [
        ("v4", raw(&v4)),
        ("v6", raw(&v6)),
        ("unbound dual", unbound_dual),
        ("[::] dual", wildcard_dual),
        ("[::1] v6only off", loopback_dual),
        ("tcp", tcp),
    ] {
        for (name, level, opt) in receive {
            let label = format!("{sock} {name}");
            out.push(format!("{label} default {:?}", get_bytes(s, level, opt, 8)));
            out.push(format!(
                "{label} 1-byte read {:?}",
                get_bytes(s, level, opt, 1)
            ));
            for value in [2, -1, 65536] {
                out.push(format!(
                    "{label} set {value} {:?} -> {:?}",
                    set_int(s, level, opt, value),
                    get_bytes(s, level, opt, 4)
                ));
            }
            out.push(format!(
                "{label} set 1 byte {:?}",
                set_bytes(s, level, opt, &[1])
            ));
            out.push(format!(
                "{label} set 8 bytes {:?} -> {:?}",
                set_bytes(s, level, opt, &[0, 0, 0, 0, 1, 0, 0, 0]),
                get_bytes(s, level, opt, 4)
            ));
        }
        for (name, opt) in [
            ("IP_TTL", ws::IP_TTL),
            ("IP_MTU_DISCOVER", ws::IP_MTU_DISCOVER),
            ("IP_DONTFRAGMENT", ws::IP_DONTFRAGMENT),
        ] {
            out.push(format!("{sock} {name} set {:?}", set_int(s, IP, opt, 1)));
        }
        out.push(format!(
            "{sock} IPV6_V6ONLY {:?} {:?}",
            get_bytes(s, IP6, ws::IPV6_V6ONLY, 4),
            get_bytes(s, IP6, ws::IPV6_V6ONLY, 1)
        ));
        for (name, level, opt) in [
            ("IP_TOS", IP, ws::IP_TOS),
            ("IPV6_TCLASS", IP6, ws::IPV6_TCLASS),
        ] {
            for value in [0, 1, 2, 3, 0xb8, 0xbb, 0xfc, 0xff, 0x100, -1] {
                out.push(format!(
                    "{sock} {name} set {value:#x} {:?} -> {:?}",
                    set_int(s, level, opt, value),
                    get_bytes(s, level, opt, 4)
                ));
            }
        }
    }
    let v6only = socket(ws::AF_INET6, ws::SOCK_DGRAM);
    for value in [
        &[0u8][..],
        &[1],
        &[0, 0, 0, 0, 1, 0, 0, 0],
        &2i32.to_ne_bytes(),
        &[],
    ] {
        out.push(format!(
            "IPV6_V6ONLY set {value:?} {:?} -> {:?}",
            set_bytes(v6only, IP6, ws::IPV6_V6ONLY, value),
            get_bytes(v6only, IP6, ws::IPV6_V6ONLY, 4)
        ));
    }
    out.push(format!(
        "v4 IPV6_V6ONLY set {:?}",
        set_int(raw(&v4), IP6, ws::IPV6_V6ONLY, 0)
    ));
    for s in [unbound_dual, wildcard_dual, loopback_dual, tcp, v6only] {
        unsafe { ws::closesocket(s) };
    }
    out
}

#[test]
#[cfg_attr(
    windows,
    ignore = "the model follows Windows 11 build 26200; the GitHub runners differ (OPEN_BUGS.md, Ignored validation)"
)]
fn receive_and_offload_options_match_the_host() {
    compare(options);
}

/// `WSASendMsg`s from a socket bound to loopback, each with one control buffer, to a receiver
/// with every receive option on: what the send returns and what the receiver reads.
fn sends(v6: bool) -> Vec<String> {
    let (at, level, tos) = if v6 {
        ("[::1]:0", IP6, ws::IPV6_TCLASS)
    } else {
        ("127.0.0.1:0", IP, ws::IP_TOS)
    };
    let other = if v6 { IP } else { IP6 };
    let tx = udp(at);
    let rx = receiver(at);
    let to = rx.local_addr().unwrap();
    let ecn = |v: i32| cmsg(level, ws::IP_ECN, &int(v));
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("none", vec![]),
        ("ECN 0", ecn(0)),
        ("ECN 1", ecn(1)),
        ("ECN 2", ecn(2)),
        ("ECN 3", ecn(3)),
        ("ECN 4", ecn(4)),
        ("ECN -1", ecn(-1)),
        ("ECN 1 byte", cmsg(level, ws::IP_ECN, &[2])),
        (
            "ECN 8 bytes",
            cmsg(level, ws::IP_ECN, &[2, 0, 0, 0, 0, 0, 0, 0]),
        ),
        ("ECN 1 then 2", [ecn(1), ecn(2)].concat()),
        ("ECN 1 then 3", [ecn(1), ecn(3)].concat()),
        ("other family's ECN", cmsg(other, ws::IP_ECN, &int(2))),
        ("TOS b8", cmsg(level, tos, &int(0xb8))),
        ("TOS b9", cmsg(level, tos, &int(0xb9))),
        ("TOS bb", cmsg(level, tos, &int(0xbb))),
        ("TOS 1ff", cmsg(level, tos, &int(0x1ff))),
        ("TOS -1", cmsg(level, tos, &int(-1))),
        ("TOS 1 byte", cmsg(level, tos, &[0xb8])),
        (
            "TOS b8 then ECN 1",
            [cmsg(level, tos, &int(0xb8)), ecn(1)].concat(),
        ),
        (
            "ECN 1 then TOS b8",
            [ecn(1), cmsg(level, tos, &int(0xb8))].concat(),
        ),
        (
            "ECN 1 then TOS ba",
            [ecn(1), cmsg(level, tos, &int(0xba))].concat(),
        ),
        ("IP_TTL 7", cmsg(level, ws::IP_TTL, &int(7))),
        ("HOPLIMIT 0", cmsg(level, ws::IP_HOPLIMIT, &int(0))),
        ("HOPLIMIT 7", cmsg(level, ws::IP_HOPLIMIT, &int(7))),
        ("HOPLIMIT 255", cmsg(level, ws::IP_HOPLIMIT, &int(255))),
        ("HOPLIMIT 256", cmsg(level, ws::IP_HOPLIMIT, &int(256))),
        ("HOPLIMIT -1", cmsg(level, ws::IP_HOPLIMIT, &int(-1))),
        ("HOPLIMIT 1 byte", cmsg(level, ws::IP_HOPLIMIT, &[9])),
        ("unknown type", cmsg(level, 99, &int(1))),
        ("unknown level", cmsg(1234, 1, &int(1))),
        ("unknown SOL_SOCKET type", cmsg(ws::SOL_SOCKET, 1, &int(1))),
        ("UDP_NOCHECKSUM", cmsg(UDP, 1, &int(1))),
        (
            "UDP_COALESCED_INFO",
            cmsg(UDP, ws::UDP_COALESCED_INFO as i32, &int(1000)),
        ),
        (
            "SEND_MSG_SIZE 2 bytes",
            cmsg(UDP, ws::UDP_SEND_MSG_SIZE, &[1, 0]),
        ),
        (
            "SEND_MSG_SIZE 8 bytes",
            cmsg(UDP, ws::UDP_SEND_MSG_SIZE, &[0xe8, 3, 0, 0, 0, 0, 0, 0]),
        ),
        (
            "TIMESTAMP_ID then ECN 1",
            [
                cmsg(ws::SOL_SOCKET, ws::SO_TIMESTAMP_ID as i32, &int(5)),
                ecn(1),
            ]
            .concat(),
        ),
        (
            "TIMESTAMP_ID 1 byte",
            cmsg(ws::SOL_SOCKET, ws::SO_TIMESTAMP_ID as i32, &[5]),
        ),
        ("cmsg_len 8", {
            let mut c = ecn(2);
            c[0] = 8;
            c
        }),
        ("cmsg_len past the buffer", {
            let mut c = ecn(2);
            c[0] = 64;
            c
        }),
        ("4-byte buffer", vec![0; 4]),
        ("zeroed header", vec![0; 16]),
        ("ECN then 8 bytes", [ecn(1), vec![0xff; 8]].concat()),
        ("ECN then a zeroed header", [ecn(1), vec![0; 16]].concat()),
        ("unpadded ECN then ECN", {
            let mut c = ecn(1);
            c.truncate(20);
            [c, ecn(2)].concat()
        }),
    ];
    if v6 {
        cases.extend([
            (
                "PKTINFO ::1 0",
                cmsg(IP6, ws::IPV6_PKTINFO, &pktinfo6("::1", 0)),
            ),
            (
                "PKTINFO ::2 9999",
                cmsg(IP6, ws::IPV6_PKTINFO, &pktinfo6("::2", 9999)),
            ),
            (
                "PKTINFO 2001:db8::1 0",
                cmsg(IP6, ws::IPV6_PKTINFO, &pktinfo6("2001:db8::1", 0)),
            ),
            ("PKTINFO 16 bytes", cmsg(IP6, ws::IPV6_PKTINFO, &[0; 16])),
            (
                "IPv4 PKTINFO",
                cmsg(IP, ws::IP_PKTINFO, &pktinfo4([127, 0, 0, 1], 0)),
            ),
        ]);
    } else {
        cases.extend([
            (
                "PKTINFO 127.0.0.1 0",
                cmsg(IP, ws::IP_PKTINFO, &pktinfo4([127, 0, 0, 1], 0)),
            ),
            (
                "PKTINFO 127.0.0.2 9999",
                cmsg(IP, ws::IP_PKTINFO, &pktinfo4([127, 0, 0, 2], 9999)),
            ),
            (
                "PKTINFO 10.255.255.1 0",
                cmsg(IP, ws::IP_PKTINFO, &pktinfo4([10, 255, 255, 1], 0)),
            ),
            ("PKTINFO 4 bytes", cmsg(IP, ws::IP_PKTINFO, &[127, 0, 0, 2])),
            (
                "IPv6 PKTINFO",
                cmsg(IP6, ws::IPV6_PKTINFO, &pktinfo6("::1", 0)),
            ),
        ]);
    }
    let mut out = Vec::new();
    for (label, mut control) in cases {
        let sent = send_msg(raw(&tx), b"payload", Some(to), &mut control);
        out.push(format!("{label}: {sent:?} -> {}", drain(&rx, 64)));
    }
    set_int(raw(&tx), level, tos, 0xb8).unwrap();
    set_int(raw(&tx), level, ws::IP_TTL, 9).unwrap();
    for (label, mut control) in [
        ("socket TOS and TTL", vec![]),
        ("socket TOS and TTL, ECN 1", ecn(1)),
        (
            "socket TOS and TTL, HOPLIMIT 3",
            cmsg(level, ws::IP_HOPLIMIT, &int(3)),
        ),
    ] {
        let sent = send_msg(raw(&tx), b"payload", Some(to), &mut control);
        out.push(format!("{label}: {sent:?} -> {}", drain(&rx, 64)));
    }
    out
}

#[test]
#[cfg_attr(
    windows,
    ignore = "the model follows Windows 11 build 26200; the GitHub runners differ (OPEN_BUGS.md, Ignored validation)"
)]
fn ipv4_send_control_messages_match_the_host() {
    compare(|| sends(false));
}

#[test]
#[cfg_attr(
    windows,
    ignore = "the model follows Windows 11 build 26200; the GitHub runners differ (OPEN_BUGS.md, Ignored validation)"
)]
fn ipv6_send_control_messages_match_the_host() {
    compare(|| sends(true));
}

/// `IP_PKTINFO`/`IPV6_PKTINFO` from a socket bound to the wildcard, which takes its source and
/// interface, and from a dual-stack IPv6 socket, which takes the IPv6 level only toward IPv6.
fn source_selection(v6: bool) -> Vec<String> {
    let (any, at) = if v6 {
        ("[::]:0", "[::1]:0")
    } else {
        ("0.0.0.0:0", "127.0.0.1:0")
    };
    let tx = udp(any);
    let rx = receiver(at);
    let to = rx.local_addr().unwrap();
    let cases: Vec<(&str, Vec<u8>)> = if v6 {
        vec![
            ("::1 0", cmsg(IP6, ws::IPV6_PKTINFO, &pktinfo6("::1", 0))),
            ("::1 1", cmsg(IP6, ws::IPV6_PKTINFO, &pktinfo6("::1", 1))),
            (
                "::1 9999",
                cmsg(IP6, ws::IPV6_PKTINFO, &pktinfo6("::1", 9999)),
            ),
            ("::2 0", cmsg(IP6, ws::IPV6_PKTINFO, &pktinfo6("::2", 0))),
            (
                "2001:db8::1 0",
                cmsg(IP6, ws::IPV6_PKTINFO, &pktinfo6("2001:db8::1", 0)),
            ),
            ("16 bytes", cmsg(IP6, ws::IPV6_PKTINFO, &[0; 16])),
        ]
    } else {
        vec![
            (
                "127.0.0.1 0",
                cmsg(IP, ws::IP_PKTINFO, &pktinfo4([127, 0, 0, 1], 0)),
            ),
            (
                "127.0.0.1 1",
                cmsg(IP, ws::IP_PKTINFO, &pktinfo4([127, 0, 0, 1], 1)),
            ),
            (
                "127.0.0.1 9999",
                cmsg(IP, ws::IP_PKTINFO, &pktinfo4([127, 0, 0, 1], 9999)),
            ),
            (
                "127.0.0.2 0",
                cmsg(IP, ws::IP_PKTINFO, &pktinfo4([127, 0, 0, 2], 0)),
            ),
            (
                "10.255.255.1 0",
                cmsg(IP, ws::IP_PKTINFO, &pktinfo4([10, 255, 255, 1], 0)),
            ),
            ("4 bytes", cmsg(IP, ws::IP_PKTINFO, &[127, 0, 0, 1])),
        ]
    };
    let mut out = Vec::new();
    for (label, mut control) in cases {
        let sent = send_msg(raw(&tx), b"payload", Some(to), &mut control);
        out.push(format!("wildcard {label}: {sent:?} -> {}", drain(&rx, 64)));
    }
    if v6 {
        let dual = socket(ws::AF_INET6, ws::SOCK_DGRAM);
        set_int(dual, IP6, ws::IPV6_V6ONLY, 0).unwrap();
        for (label, mut control) in [
            ("dual IP_ECN", cmsg(IP, ws::IP_ECN, &int(1))),
            ("dual IPV6_ECN", cmsg(IP6, ws::IPV6_ECN, &int(1))),
            (
                "dual IP_PKTINFO",
                cmsg(IP, ws::IP_PKTINFO, &pktinfo4([127, 0, 0, 1], 0)),
            ),
        ] {
            let sent = send_msg(dual, b"payload", Some(to), &mut control);
            out.push(format!("{label}: {sent:?} -> {}", drain(&rx, 64)));
        }
        unsafe { ws::closesocket(dual) };
    }
    out
}

#[test]
fn source_selection_matches_the_host() {
    compare(|| source_selection(false));
    compare(|| source_selection(true));
}

/// `WSARecvMsg` with every message there is to report (packet info, ECN, TTL, TOS, a receive
/// stamp and a coalesced segment size) into control buffers of each size around them, a data
/// buffer too short, no control buffer, and a plain `recv` of a coalesced datagram.
fn receive_buffers(v6: bool) -> Vec<String> {
    let at = if v6 { "[::1]:0" } else { "127.0.0.1:0" };
    let level = if v6 { IP6 } else { IP };
    let tx = udp(at);
    let rx = receiver(at);
    let to = rx.local_addr().unwrap();
    set_int(raw(&rx), UDP, ws::UDP_RECV_MAX_COALESCED_SIZE, 65535).unwrap();
    let stamps = [1u8, 0, 0, 0, 0, 0, 0, 0];
    wsa_ioctl(raw(&rx), ws::SIO_TIMESTAMPING, &stamps, &mut []).unwrap();
    let send = || {
        let mut control = [
            cmsg(UDP, ws::UDP_SEND_MSG_SIZE, &1000u32.to_ne_bytes()),
            cmsg(level, ws::IP_ECN, &int(1)),
        ]
        .concat();
        send_msg(raw(&tx), &[7; 2500], Some(to), &mut control).unwrap();
    };
    let mut out = Vec::new();
    for (data, control) in [
        (4000, Some(256)),
        (4000, Some(8)),
        (4000, Some(16)),
        (4000, Some(30)),
        (4000, Some(40)),
        (4000, Some(48)),
        (4000, Some(96)),
        (4000, Some(112)),
        (4000, Some(120)),
        (4000, Some(136)),
        (4000, Some(160)),
        (4000, None),
        (1500, Some(256)),
        (1500, Some(40)),
    ] {
        send();
        out.push(format!(
            "{data}/{control:?}: {} then {}",
            recv_full(&rx, data, control),
            drain(&rx, 4000)
        ));
    }
    send();
    let mut buf = [0u8; 4000];
    out.push(format!(
        "recv: {:?} then {}",
        rx.recv(&mut buf).map_err(|e| e.raw_os_error()),
        drain(&rx, 4000)
    ));
    out
}

#[test]
#[cfg_attr(
    windows,
    ignore = "the model follows Windows 11 build 26200; the GitHub runners differ (OPEN_BUGS.md, Ignored validation)"
)]
fn receive_control_buffers_match_the_host() {
    compare(|| receive_buffers(false));
    compare(|| receive_buffers(true));
}

/// Segmented sends (`UDP_SEND_MSG_SIZE`, as a control message and as the socket option) to a
/// socket without coalescing, which reads each segment, and to sockets coalescing up to several
/// sizes; segment sizes and whole datagrams at the family's limits.
fn segmentation(v6: bool) -> Vec<String> {
    let at = if v6 { "[::1]:0" } else { "127.0.0.1:0" };
    let tx = udp(at);
    let plain = udp(at);
    let uro = udp(at);
    for rx in [&plain, &uro] {
        set_int(raw(rx), ws::SOL_SOCKET, ws::SO_RCVBUF, 1 << 22).unwrap();
    }
    let seg = |n: u32| cmsg(UDP, ws::UDP_SEND_MSG_SIZE, &n.to_ne_bytes());
    let mut out = Vec::new();
    let mut send = |label: &str, rx: &UdpSocket, len: usize, control: Vec<u8>| {
        let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let mut control = control;
        let sent = send_msg(
            raw(&tx),
            &payload,
            Some(rx.local_addr().unwrap()),
            &mut control,
        );
        out.push(format!(
            "{label} len {len}: {sent:?} -> {}",
            drain(rx, 70000)
        ));
    };
    for (s, len) in [
        (1000, 2500),
        (1000, 1000),
        (1000, 999),
        (0, 2500),
        (1, 3),
        (1200, 4800),
    ] {
        send(&format!("plain seg {s}"), &plain, len, seg(s));
    }
    for max in [65535, 4000, 3500, 1000, 1, i32::MAX] {
        set_int(raw(&uro), UDP, ws::UDP_RECV_MAX_COALESCED_SIZE, max).unwrap();
        for (s, len) in [
            (1000, 2500),
            (1000, 1000),
            (1000, 10500),
            (1000, 65000),
            (1000, 65500),
            (1472, 65000),
            (60000, 65507),
            (1, 65508),
            (5, 65530),
            (21845, 65535),
            (1000, 100000),
        ] {
            send(&format!("max {max} seg {s}"), &uro, len, seg(s));
        }
    }
    for (s, len) in [
        (65507, 65517),
        (65508, 65518),
        (65527, 65537),
        (65528, 65538),
        (u32::MAX, 2500),
        (0, 65508),
        (0, 65528),
    ] {
        send(&format!("limit seg {s}"), &plain, len, seg(s));
    }
    for value in [1000, 0, 65508, -1] {
        set_int(raw(&tx), UDP, ws::UDP_SEND_MSG_SIZE, value).unwrap();
        let sent = tx.send_to(&[5; 2500], plain.local_addr().unwrap());
        out.push(format!(
            "option {value} send_to: {:?} -> {}",
            sent.map_err(|e| e.raw_os_error()),
            drain(&plain, 70000)
        ));
        let mut control = seg(600);
        let sent = send_msg(
            raw(&tx),
            &[5; 2500],
            Some(plain.local_addr().unwrap()),
            &mut control,
        );
        out.push(format!(
            "option {value} and seg 600: {sent:?} -> {}",
            drain(&plain, 70000)
        ));
    }
    out
}

#[test]
#[cfg_attr(
    windows,
    ignore = "the model follows Windows 11 build 26200; the GitHub runners differ (OPEN_BUGS.md, Ignored validation)"
)]
fn ipv4_segmentation_and_coalescing_match_the_host() {
    compare(|| segmentation(false));
}

#[test]
#[cfg_attr(
    windows,
    ignore = "the model follows Windows 11 build 26200; the GitHub runners differ (OPEN_BUGS.md, Ignored validation)"
)]
fn ipv6_segmentation_and_coalescing_match_the_host() {
    compare(|| segmentation(true));
}

/// Two loopback sends that are not segmented reach a coalescing socket apart.
fn separate_sends() -> Vec<String> {
    let tx = udp("127.0.0.1:0");
    let rx = udp("127.0.0.1:0");
    set_int(raw(&rx), UDP, ws::UDP_RECV_MAX_COALESCED_SIZE, 65535).unwrap();
    for n in 0..3u8 {
        tx.send_to(&[n; 1200], rx.local_addr().unwrap()).unwrap();
    }
    vec![drain(&rx, 70000)]
}

#[test]
fn separate_sends_are_not_coalesced_like_the_host() {
    compare(separate_sends);
}

/// Over an interface with a 1500-byte MTU a segmented send leaves as its segments, which a
/// coalescing socket at the station reads apart, and with `IP_DONTFRAGMENT` set its segment size,
/// not its length, must fit the MTU. Loopback has no such interface, so this runs in the sim only.
#[test]
fn segments_cross_an_interface_apart() {
    let sim = Sim::builder()
        .nic(
            snare::NicSpec::new("eth0")
                .address("10.0.0.1/24".parse::<snare::IpNet>().unwrap())
                .station("10.0.0.2".parse::<std::net::IpAddr>().unwrap())
                .mtu(1500),
        )
        .build();
    sim.run(|| {
        let host = udp("10.0.0.1:0");
        let station = udp("10.0.0.2:0");
        set_int(raw(&station), UDP, ws::UDP_RECV_MAX_COALESCED_SIZE, 65535).unwrap();
        let to = Some(station.local_addr().unwrap());
        let seg = |n: u32| cmsg(UDP, ws::UDP_SEND_MSG_SIZE, &n.to_ne_bytes());
        assert_eq!(
            send_msg(raw(&host), &[1; 2500], to, &mut seg(1000)),
            Ok(2500)
        );
        let mut buf = [0u8; 4000];
        let sizes: Vec<usize> = (0..3).map(|_| station.recv(&mut buf).unwrap()).collect();
        assert_eq!(sizes, [1000, 1000, 500]);
        set_int(raw(&host), IP, ws::IP_DONTFRAGMENT, 1).unwrap();
        assert_eq!(
            send_msg(raw(&host), &[2; 4000], to, &mut seg(1472)),
            Ok(4000)
        );
        assert_eq!(
            send_msg(raw(&host), &[2; 4000], to, &mut seg(1473)),
            Err(ws::WSAEMSGSIZE)
        );
    });
}
