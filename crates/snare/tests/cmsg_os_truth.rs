#![cfg(any(target_os = "linux", target_os = "macos"))]

//! Ancillary data on UDP sockets of a plain sim, compared with the host's loopback: the send
//! control messages each kernel accepts or refuses (`IP_TOS`, `IP_TTL`, `IP_PKTINFO`,
//! `IPV6_TCLASS`, `IPV6_HOPLIMIT`, `IPV6_PKTINFO`, Linux `UDP_SEGMENT`, malformed headers), the
//! receive options that ask for them back (`IP_RECVTOS`, `IP_PKTINFO`/`IP_RECVPKTINFO`, macOS
//! `IP_RECVDSTADDR`, `IP_RECVTTL`, `IPV6_RECVTCLASS`, `IPV6_RECVPKTINFO`, `IPV6_RECVHOPLIMIT`,
//! Linux `UDP_GRO`) and the exact bytes `recvmsg` writes for them.

use std::io::Read;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

use snare::Sim;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn setopt(s: &UdpSocket, level: i32, name: i32, value: i32) -> Result<(), i32> {
    setopt_len(s, level, name, value, 4)
}

fn setopt_len(s: &UdpSocket, level: i32, name: i32, value: i32, len: u32) -> Result<(), i32> {
    let rc =
        unsafe { libc::setsockopt(s.as_raw_fd(), level, name, (&raw const value).cast(), len) };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

fn getopt(s: &UdpSocket, level: i32, name: i32) -> Result<Vec<u8>, i32> {
    let mut buf = [0u8; 8];
    let mut len = 8;
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            level,
            name,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc == 0 {
        Ok(buf[..len as usize].to_vec())
    } else {
        Err(errno())
    }
}

/// One control message to send: `len` overrides the `cmsg_len` `CMSG_LEN(data.len())` gives.
struct Ctl {
    level: i32,
    ty: i32,
    data: Vec<u8>,
    len: Option<usize>,
}

fn ctl(level: i32, ty: i32, data: impl Into<Vec<u8>>) -> Ctl {
    Ctl {
        level,
        ty,
        data: data.into(),
        len: None,
    }
}

fn int(v: i32) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

fn v4_pktinfo(ifindex: i32, spec_dst: [u8; 4], addr: [u8; 4]) -> Vec<u8> {
    let mut out = ifindex.to_ne_bytes().to_vec();
    out.extend(spec_dst);
    out.extend(addr);
    out
}

fn v6_pktinfo(addr: std::net::Ipv6Addr, ifindex: u32) -> Vec<u8> {
    let mut out = addr.octets().to_vec();
    out.extend(ifindex.to_ne_bytes());
    out
}

fn sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            let sin = (&raw mut ss).cast::<libc::sockaddr_in>();
            unsafe {
                #[cfg(target_os = "macos")]
                {
                    (*sin).sin_len = size_of::<libc::sockaddr_in>() as u8;
                }
                (*sin).sin_family = libc::AF_INET as _;
                (*sin).sin_port = a.port().to_be();
                (*sin).sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
            }
            size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            let sin6 = (&raw mut ss).cast::<libc::sockaddr_in6>();
            unsafe {
                #[cfg(target_os = "macos")]
                {
                    (*sin6).sin6_len = size_of::<libc::sockaddr_in6>() as u8;
                }
                (*sin6).sin6_family = libc::AF_INET6 as _;
                (*sin6).sin6_port = a.port().to_be();
                (*sin6).sin6_addr.s6_addr = a.ip().octets();
            }
            size_of::<libc::sockaddr_in6>()
        }
    };
    (ss, len as _)
}

/// `sendmsg` of `payload` to `to` with `ctls` laid out as `CMSG_SPACE` records, the control
/// length `controllen` when given.
fn sendmsg(
    s: &UdpSocket,
    to: SocketAddr,
    payload: &[u8],
    ctls: &[Ctl],
    controllen: Option<usize>,
) -> Result<usize, i32> {
    let mut control = vec![0u64; 64];
    let base = control.as_mut_ptr().cast::<u8>();
    let mut used = 0;
    for c in ctls {
        let hdr = unsafe { base.add(used) }.cast::<libc::cmsghdr>();
        let data_at = unsafe { libc::CMSG_LEN(0) } as usize;
        unsafe {
            (*hdr).cmsg_len = c.len.unwrap_or(libc::CMSG_LEN(c.data.len() as _) as usize) as _;
            (*hdr).cmsg_level = c.level;
            (*hdr).cmsg_type = c.ty;
            std::ptr::copy_nonoverlapping(c.data.as_ptr(), base.add(used + data_at), c.data.len());
        }
        used += unsafe { libc::CMSG_SPACE(c.data.len() as _) } as usize;
    }
    let (mut name, namelen) = sockaddr(to);
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut _,
        iov_len: payload.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&raw mut name).cast();
    msg.msg_namelen = namelen;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    let explicit = controllen.is_some();
    let controllen = controllen.unwrap_or(used);
    if controllen > 0 || explicit {
        msg.msg_control = base.cast();
        msg.msg_controllen = controllen as _;
    }
    let n = unsafe { libc::sendmsg(s.as_raw_fd(), &msg, 0) };
    if n < 0 { Err(errno()) } else { Ok(n as usize) }
}

/// `sendmsg` of one byte on connected stream `fd` with `ctls`.
fn tcp_sendmsg(fd: i32, ctls: &[Ctl]) -> Result<usize, i32> {
    let mut control = vec![0u64; 16];
    let base = control.as_mut_ptr().cast::<u8>();
    let mut used = 0;
    for c in ctls {
        let hdr = unsafe { base.add(used) }.cast::<libc::cmsghdr>();
        unsafe {
            (*hdr).cmsg_len = c.len.unwrap_or(libc::CMSG_LEN(c.data.len() as _) as usize) as _;
            (*hdr).cmsg_level = c.level;
            (*hdr).cmsg_type = c.ty;
            std::ptr::copy_nonoverlapping(
                c.data.as_ptr(),
                base.add(used + libc::CMSG_LEN(0) as usize),
                c.data.len(),
            );
        }
        used += unsafe { libc::CMSG_SPACE(c.data.len() as _) } as usize;
    }
    let payload = [9u8];
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut _,
        iov_len: 1,
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = base.cast();
    msg.msg_controllen = used as _;
    let n = unsafe { libc::sendmsg(fd, &msg, 0) };
    if n < 0 { Err(errno()) } else { Ok(n as usize) }
}

/// One `recvmsg` with `cap` bytes of control buffer: the length, `msg_flags`, and each control
/// message as `level/type/cmsg_len:hex`.
#[allow(clippy::unnecessary_cast)]
fn recvmsg(s: &UdpSocket, cap: usize) -> Result<String, i32> {
    let mut buf = vec![0u8; 70_000];
    let mut control = vec![0u64; 64];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&raw mut name).cast();
    msg.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = cap as _;
    let n = unsafe { libc::recvmsg(s.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        return Err(errno());
    }
    let from = match name.ss_family as i32 {
        libc::AF_INET => {
            let sin = unsafe { &*(&raw const name).cast::<libc::sockaddr_in>() };
            IpAddr::from(sin.sin_addr.s_addr.to_ne_bytes())
        }
        _ => {
            let sin6 = unsafe { &*(&raw const name).cast::<libc::sockaddr_in6>() };
            IpAddr::from(sin6.sin6_addr.s6_addr)
        }
    };
    let mut out = format!(
        "{n} from {from} flags={:#x} controllen={}",
        msg.msg_flags, msg.msg_controllen
    );
    if msg.msg_controllen as usize >= size_of::<libc::cmsghdr>() {
        let mut c = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !c.is_null() {
            let (level, ty, len) = unsafe { ((*c).cmsg_level, (*c).cmsg_type, (*c).cmsg_len) };
            let data_len = (len as usize).saturating_sub(unsafe { libc::CMSG_LEN(0) } as usize);
            let data = unsafe { std::slice::from_raw_parts(libc::CMSG_DATA(c), data_len) };
            let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
            out.push_str(&format!(" [{level}/{ty}/{len}:{hex}]"));
            c = unsafe { libc::CMSG_NXTHDR(&msg, c) };
        }
    }
    Ok(out)
}

/// Every datagram `s` has queued, each as [`recvmsg`] reports it with `cap` bytes of control
/// buffer; a short timeout ends it.
fn drain(s: &UdpSocket, cap: usize) -> Vec<String> {
    s.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut out = Vec::new();
    while let Ok(got) = recvmsg(s, cap) {
        out.push(got);
    }
    out
}

fn pair(v6: bool) -> (UdpSocket, UdpSocket) {
    let at = if v6 { "[::1]:0" } else { "127.0.0.1:0" };
    (UdpSocket::bind(at).unwrap(), UdpSocket::bind(at).unwrap())
}

/// The receive options a socket of family `v6` can ask for, by label.
fn recv_opts(v6: bool) -> Vec<(&'static str, i32, i32)> {
    use libc::*;
    let mut out = Vec::new();
    if v6 {
        out.push(("recvtclass", IPPROTO_IPV6, IPV6_RECVTCLASS));
        out.push(("recvpktinfo6", IPPROTO_IPV6, IPV6_RECVPKTINFO));
        out.push(("recvhoplimit", IPPROTO_IPV6, IPV6_RECVHOPLIMIT));
    } else {
        out.push(("recvtos", IPPROTO_IP, IP_RECVTOS));
        out.push(("recvttl", IPPROTO_IP, IP_RECVTTL));
        out.push(("pktinfo", IPPROTO_IP, IP_PKTINFO));
        #[cfg(target_os = "macos")]
        out.push(("recvdstaddr", IPPROTO_IP, IP_RECVDSTADDR));
    }
    out
}

/// Sends that each family's stack accepts or refuses, by label.
fn send_cases(v6: bool) -> Vec<(&'static str, Vec<Ctl>, Option<usize>)> {
    use libc::*;
    let lo4 = [127, 0, 0, 1];
    let mut cases: Vec<(&'static str, Vec<Ctl>, Option<usize>)> = vec![
        ("none", vec![], None),
        (
            "tos int 0xb9",
            vec![ctl(IPPROTO_IP, IP_TOS, int(0xb9))],
            None,
        ),
        ("tos int 3", vec![ctl(IPPROTO_IP, IP_TOS, int(3))], None),
        ("tos int 256", vec![ctl(IPPROTO_IP, IP_TOS, int(256))], None),
        ("tos int -1", vec![ctl(IPPROTO_IP, IP_TOS, int(-1))], None),
        (
            "tos byte 0x2",
            vec![ctl(IPPROTO_IP, IP_TOS, vec![2u8])],
            None,
        ),
        (
            "tos short",
            vec![ctl(IPPROTO_IP, IP_TOS, vec![2u8, 0])],
            None,
        ),
        ("ttl 7", vec![ctl(IPPROTO_IP, IP_TTL, int(7))], None),
        ("ttl 0", vec![ctl(IPPROTO_IP, IP_TTL, int(0))], None),
        ("ttl 256", vec![ctl(IPPROTO_IP, IP_TTL, int(256))], None),
        ("ttl byte", vec![ctl(IPPROTO_IP, IP_TTL, vec![9u8])], None),
        (
            "pktinfo lo",
            vec![ctl(IPPROTO_IP, IP_PKTINFO, v4_pktinfo(0, lo4, [0; 4]))],
            None,
        ),
        (
            "pktinfo any",
            vec![ctl(IPPROTO_IP, IP_PKTINFO, v4_pktinfo(0, [0; 4], [0; 4]))],
            None,
        ),
        (
            "pktinfo ifindex 1",
            vec![ctl(IPPROTO_IP, IP_PKTINFO, v4_pktinfo(1, [0; 4], [0; 4]))],
            None,
        ),
        (
            "pktinfo ifindex 999",
            vec![ctl(IPPROTO_IP, IP_PKTINFO, v4_pktinfo(999, [0; 4], [0; 4]))],
            None,
        ),
        (
            "pktinfo short",
            vec![ctl(IPPROTO_IP, IP_PKTINFO, vec![0u8; 8])],
            None,
        ),
        ("ip unknown type", vec![ctl(IPPROTO_IP, 99, int(1))], None),
        (
            "ip recvtos type",
            vec![ctl(IPPROTO_IP, IP_RECVTOS, int(0xb8))],
            None,
        ),
        (
            "tclass 0xb9",
            vec![ctl(IPPROTO_IPV6, IPV6_TCLASS, int(0xb9))],
            None,
        ),
        (
            "tclass -1",
            vec![ctl(IPPROTO_IPV6, IPV6_TCLASS, int(-1))],
            None,
        ),
        (
            "tclass -2",
            vec![ctl(IPPROTO_IPV6, IPV6_TCLASS, int(-2))],
            None,
        ),
        (
            "tclass 256",
            vec![ctl(IPPROTO_IPV6, IPV6_TCLASS, int(256))],
            None,
        ),
        (
            "tclass byte",
            vec![ctl(IPPROTO_IPV6, IPV6_TCLASS, vec![1u8])],
            None,
        ),
        (
            "hoplimit 9",
            vec![ctl(IPPROTO_IPV6, IPV6_HOPLIMIT, int(9))],
            None,
        ),
        (
            "hoplimit -1",
            vec![ctl(IPPROTO_IPV6, IPV6_HOPLIMIT, int(-1))],
            None,
        ),
        (
            "hoplimit 256",
            vec![ctl(IPPROTO_IPV6, IPV6_HOPLIMIT, int(256))],
            None,
        ),
        (
            "pktinfo6 lo",
            vec![ctl(
                IPPROTO_IPV6,
                IPV6_PKTINFO,
                v6_pktinfo(std::net::Ipv6Addr::LOCALHOST, 0),
            )],
            None,
        ),
        (
            "pktinfo6 any",
            vec![ctl(
                IPPROTO_IPV6,
                IPV6_PKTINFO,
                v6_pktinfo(std::net::Ipv6Addr::UNSPECIFIED, 0),
            )],
            None,
        ),
        (
            "pktinfo6 foreign",
            vec![ctl(
                IPPROTO_IPV6,
                IPV6_PKTINFO,
                v6_pktinfo("2001:db8::9".parse().unwrap(), 0),
            )],
            None,
        ),
        (
            "pktinfo6 ifindex 1",
            vec![ctl(
                IPPROTO_IPV6,
                IPV6_PKTINFO,
                v6_pktinfo(std::net::Ipv6Addr::UNSPECIFIED, 1),
            )],
            None,
        ),
        (
            "pktinfo6 ifindex 999",
            vec![ctl(
                IPPROTO_IPV6,
                IPV6_PKTINFO,
                v6_pktinfo(std::net::Ipv6Addr::UNSPECIFIED, 999),
            )],
            None,
        ),
        (
            "pktinfo6 short",
            vec![ctl(IPPROTO_IPV6, IPV6_PKTINFO, vec![0u8; 16])],
            None,
        ),
        (
            "ipv6 unknown type",
            vec![ctl(IPPROTO_IPV6, 99, int(1))],
            None,
        ),
        (
            "socket unknown type",
            vec![ctl(SOL_SOCKET, 0x7777, int(1))],
            None,
        ),
        ("unknown level", vec![ctl(1234, 1, int(1))], None),
        (
            "cmsg_len short",
            vec![Ctl {
                level: IPPROTO_IP,
                ty: IP_TOS,
                data: int(1),
                len: Some(4),
            }],
            None,
        ),
        (
            "cmsg_len over",
            vec![Ctl {
                level: IPPROTO_IP,
                ty: IP_TOS,
                data: int(1),
                len: Some(200),
            }],
            None,
        ),
        (
            "controllen 4",
            vec![ctl(IPPROTO_IP, IP_TOS, int(1))],
            Some(4),
        ),
        (
            "tos then bad",
            vec![
                ctl(IPPROTO_IP, IP_TOS, int(0xb9)),
                ctl(IPPROTO_IP, IP_TTL, int(0)),
            ],
            None,
        ),
        (
            "tos and tclass",
            vec![
                ctl(IPPROTO_IP, IP_TOS, int(0x21)),
                ctl(IPPROTO_IPV6, IPV6_TCLASS, int(0x45)),
            ],
            None,
        ),
    ];
    if !v6 {
        cases.push((
            "pktinfo foreign",
            vec![ctl(
                IPPROTO_IP,
                IP_PKTINFO,
                v4_pktinfo(0, [10, 9, 9, 9], [0; 4]),
            )],
            None,
        ));
    }
    #[cfg(target_os = "macos")]
    cases.push(("dontfrag6 1", vec![ctl(IPPROTO_IPV6, 62, int(1))], None));
    #[cfg(target_os = "macos")]
    cases.push(("use min mtu 2", vec![ctl(IPPROTO_IPV6, 42, int(2))], None));
    #[cfg(target_os = "macos")]
    cases.push(("use min mtu 1", vec![ctl(IPPROTO_IPV6, 42, int(1))], None));
    #[cfg(target_os = "macos")]
    cases.push((
        "recvdstaddr lo",
        vec![ctl(IPPROTO_IP, IP_RECVDSTADDR, lo4.to_vec())],
        None,
    ));
    #[cfg(target_os = "linux")]
    {
        cases.push((
            "segment 1000 of 2500",
            vec![ctl(SOL_UDP, UDP_SEGMENT, 1000u16.to_ne_bytes())],
            None,
        ));
        cases.push((
            "segment int",
            vec![ctl(SOL_UDP, UDP_SEGMENT, int(1000))],
            None,
        ));
        cases.push((
            "segment 0",
            vec![ctl(SOL_UDP, UDP_SEGMENT, 0u16.to_ne_bytes())],
            None,
        ));
        cases.push(("udp unknown type", vec![ctl(SOL_UDP, 1, int(1))], None));
        cases.push((
            "timestamping 0",
            vec![ctl(SOL_SOCKET, SO_TIMESTAMPING, int(0))],
            None,
        ));
        cases.push((
            "timestamping rx flag",
            vec![ctl(SOL_SOCKET, SO_TIMESTAMPING, int(1 << 3))],
            None,
        ));
        cases.push((
            "timestamping short",
            vec![ctl(SOL_SOCKET, SO_TIMESTAMPING, vec![0u8; 2])],
            None,
        ));
        cases.push((
            "txtime off",
            vec![ctl(SOL_SOCKET, SCM_TXTIME, 0u64.to_ne_bytes())],
            None,
        ));
        cases.push((
            "priority 3",
            vec![ctl(SOL_SOCKET, SO_PRIORITY, int(3))],
            None,
        ));
        cases.push(("rights", vec![ctl(SOL_SOCKET, SCM_RIGHTS, int(0))], None));
        cases.push(("ip protocol", vec![ctl(IPPROTO_IP, 52, int(17))], None));
        cases.push(("ip protocol 0", vec![ctl(IPPROTO_IP, 52, int(0))], None));
        cases.push((
            "dontfrag6 1",
            vec![ctl(IPPROTO_IPV6, IPV6_DONTFRAG, int(1))],
            None,
        ));
        cases.push((
            "dontfrag6 byte",
            vec![ctl(IPPROTO_IPV6, IPV6_DONTFRAG, vec![1u8])],
            None,
        ));
        cases.push((
            "segment and tos",
            vec![
                ctl(IPPROTO_IP, IP_TOS, int(0x02)),
                ctl(SOL_UDP, UDP_SEGMENT, 1000u16.to_ne_bytes()),
            ],
            None,
        ));
    }
    cases
}

fn scenario() -> Vec<String> {
    let mut out = Vec::new();
    for v6 in [false, true] {
        let (_, probe) = pair(v6);
        for (label, level, name) in recv_opts(v6) {
            out.push(format!(
                "v6={v6} {label} default {:?} set {:?} reads {:?} 1-byte set {:?}",
                getopt(&probe, level, name),
                setopt(&probe, level, name, 1),
                getopt(&probe, level, name),
                setopt_len(&probe, level, name, 0, 1),
            ));
        }
        #[cfg(target_os = "linux")]
        out.push(format!(
            "v6={v6} gro default {:?} set {:?} reads {:?} segment set {:?} reads {:?}",
            getopt(&probe, libc::SOL_UDP, libc::UDP_GRO),
            setopt(&probe, libc::SOL_UDP, libc::UDP_GRO, 1),
            getopt(&probe, libc::SOL_UDP, libc::UDP_GRO),
            setopt(&probe, libc::SOL_UDP, libc::UDP_SEGMENT, 1400),
            getopt(&probe, libc::SOL_UDP, libc::UDP_SEGMENT),
        ));

        let (tx, rx) = pair(v6);
        let to = rx.local_addr().unwrap();
        for (_, level, name) in recv_opts(v6) {
            setopt(&rx, level, name, 1).unwrap();
        }
        let payload = vec![5u8; 2500];
        for (label, ctls, controllen) in send_cases(v6) {
            let sent = sendmsg(&tx, to, &payload, &ctls, controllen);
            out.push(format!("v6={v6} send {label}: {sent:?}"));
            for got in drain(&rx, 512) {
                out.push(format!("  {got}"));
            }
        }

        let (level, name) = if v6 {
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
        } else {
            (libc::IPPROTO_IP, libc::IP_TOS)
        };
        setopt(&tx, level, name, 0x2e).unwrap();
        out.push(format!(
            "v6={v6} sticky send {:?}",
            sendmsg(&tx, to, b"x", &[], None)
        ));
        for got in drain(&rx, 512) {
            out.push(format!("  {got}"));
        }
        out.push(format!(
            "v6={v6} sticky overridden {:?}",
            sendmsg(
                &tx,
                to,
                b"x",
                &[if v6 {
                    ctl(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, int(1))
                } else {
                    ctl(libc::IPPROTO_IP, libc::IP_TOS, int(1))
                }],
                None
            )
        ));
        for got in drain(&rx, 512) {
            out.push(format!("  {got}"));
        }
        for value in [0, 256, -1] {
            out.push(format!(
                "v6={v6} sticky then {value} {:?}",
                sendmsg(
                    &tx,
                    to,
                    b"x",
                    &[if v6 {
                        ctl(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, int(value))
                    } else {
                        ctl(libc::IPPROTO_IP, libc::IP_TOS, int(value))
                    }],
                    None
                )
            ));
            for got in drain(&rx, 512) {
                out.push(format!("  {got}"));
            }
        }
        for cap in [0, 8, 16, 20, 24, 32, 40] {
            tx.send_to(b"y", to).unwrap();
            out.push(format!("v6={v6} cap {cap}"));
            for got in drain(&rx, cap) {
                out.push(format!("  {got}"));
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let (tx, rx) = pair(false);
        let to = rx.local_addr().unwrap();
        setopt(&rx, libc::SOL_UDP, libc::UDP_GRO, 1).unwrap();
        setopt(&rx, libc::IPPROTO_IP, libc::IP_RECVTOS, 1).unwrap();
        for (len, seg) in [
            (2500usize, 1000u16),
            (3000, 1000),
            (900, 1000),
            (1000, 1000),
        ] {
            let sent = sendmsg(
                &tx,
                to,
                &vec![1u8; len],
                &[ctl(libc::SOL_UDP, libc::UDP_SEGMENT, seg.to_ne_bytes())],
                None,
            );
            out.push(format!("gro send {len}/{seg}: {sent:?}"));
            for got in drain(&rx, 512) {
                out.push(format!("  {got}"));
            }
        }
        for segs in [64usize, 65, 128, 129] {
            let sent = sendmsg(
                &tx,
                to,
                &vec![1u8; segs * 100],
                &[ctl(libc::SOL_UDP, libc::UDP_SEGMENT, 100u16.to_ne_bytes())],
                None,
            );
            out.push(format!("gso {segs} segments: {sent:?}"));
            out.push(format!("  {} received", drain(&rx, 512).len()));
        }
        setopt(&tx, libc::SOL_UDP, libc::UDP_SEGMENT, 700).unwrap();
        out.push(format!(
            "sticky segment {:?}",
            sendmsg(&tx, to, &[2u8; 1500], &[], None)
        ));
        for got in drain(&rx, 512) {
            out.push(format!("  {got}"));
        }
        setopt(&rx, libc::SOL_UDP, libc::UDP_GRO, 0).unwrap();
        out.push(format!(
            "sticky segment no gro {:?}",
            sendmsg(&tx, to, &[2u8; 1500], &[], None)
        ));
        for got in drain(&rx, 512) {
            out.push(format!("  {got}"));
        }
    }
    for v6 in [false, true] {
        let (socket, _) = pair(v6);
        let (level, names): (i32, &[i32]) = if v6 {
            (
                libc::IPPROTO_IP,
                &[libc::IP_RECVTOS, libc::IP_RECVTTL, libc::IP_PKTINFO],
            )
        } else {
            (
                libc::IPPROTO_IPV6,
                &[
                    libc::IPV6_RECVTCLASS,
                    libc::IPV6_RECVPKTINFO,
                    libc::IPV6_RECVHOPLIMIT,
                ],
            )
        };
        for &name in names {
            out.push(format!(
                "v6={v6} other family {level}/{name} get {:?} set {:?} get {:?}",
                getopt(&socket, level, name),
                setopt(&socket, level, name, 1),
                getopt(&socket, level, name),
            ));
        }
    }
    for v6 in [false, true] {
        let (tx, rx) = pair(v6);
        let to = rx.local_addr().unwrap();
        out.push(format!(
            "v6={v6} empty control {:?}",
            sendmsg(&tx, to, b"e", &[], Some(0))
        ));
        out.push(format!("  {} received", drain(&rx, 512).len()));
    }
    for v6 in [false, true] {
        let at = if v6 { "[::1]:0" } else { "127.0.0.1:0" };
        let listener = std::net::TcpListener::bind(at).unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let cases: Vec<(&str, Vec<Ctl>)> = vec![
            ("tcp tos", vec![ctl(libc::IPPROTO_IP, libc::IP_TOS, int(4))]),
            (
                "tcp tclass",
                vec![ctl(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, int(4))],
            ),
            (
                "tcp socket unknown",
                vec![ctl(libc::SOL_SOCKET, 0x7777, int(1))],
            ),
            ("tcp unknown level", vec![ctl(1234, 1, int(1))]),
            (
                "tcp cmsg_len short",
                vec![Ctl {
                    level: libc::IPPROTO_IP,
                    ty: libc::IP_TOS,
                    data: int(1),
                    len: Some(4),
                }],
            ),
        ];
        for (label, ctls) in cases {
            let sent = tcp_sendmsg(client.as_raw_fd(), &ctls);
            out.push(format!("v6={v6} {label}: {sent:?}"));
        }
        drop(client);
        let mut rest = Vec::new();
        server.read_to_end(&mut rest).unwrap();
        out.push(format!("v6={v6} tcp received {}", rest.len()));
    }
    out
}

/// Runs the scenario on the host and in `sim` and compares the lines. macOS accepts a source in
/// `IP_PKTINFO` that no interface holds, but now and then, under load, refuses it with
/// `EADDRNOTAVAIL`; the host's run is then taken again before the lines are compared.
fn compare(sim: Sim) {
    let sim = sim.run(scenario);
    let mut real = scenario();
    for _ in 0..5 {
        let refused_foreign_source = real.iter().zip(&sim).any(|(r, s)| {
            r != s && r.contains("pktinfo foreign: Err(49)") && s.contains("pktinfo foreign: Ok")
        });
        if !(cfg!(target_os = "macos") && refused_foreign_source) {
            break;
        }
        real = scenario();
    }
    let diff: Vec<String> = real
        .iter()
        .zip(&sim)
        .filter(|(r, s)| r != s)
        .map(|(r, s)| format!("real {r}\n sim {s}"))
        .collect();
    assert!(diff.is_empty(), "{}", diff.join("\n"));
    assert_eq!(real.len(), sim.len());
}

#[test]
fn cmsg_os_truth() {
    compare(Sim::builder().strict_sockopts().build());
}

/// A `SimHost`'s datagram sockets take and report the same control messages.
#[cfg(target_os = "linux")]
#[test]
fn cmsg_os_truth_simhost() {
    compare(
        Sim::builder()
            .host(snare::HostProfile::new().build())
            .strict_sockopts()
            .build(),
    );
}
