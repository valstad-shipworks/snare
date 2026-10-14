#![cfg(any(target_os = "linux", target_os = "macos", windows))]

//! Dual-stack IPv6 sockets (RFC 3493 §3.7) in a plain sim, compared with the host's loopback:
//! `IPV6_V6ONLY` (its default, values, size rules and the bind it must precede), binds of
//! v4-mapped addresses, which IPv4, IPv6, v4-mapped and dual-stack binds of one port collide for
//! TCP and UDP under every `SO_REUSEADDR` combination, IPv4 datagrams and connections reaching an
//! IPv6 socket and reported v4-mapped, an IPv6 socket's sends and connects to v4-mapped addresses
//! and the errors for the crossings a host refuses, the TTL and TOS such a send carries, and the
//! control messages an IPv4 datagram brings an IPv6 socket.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use snare::Sim;

/// One datagram: its length, its source and the length of that address, and its control messages
/// as `level/type:hex`.
type Received = (usize, (SocketAddr, u32), Vec<String>);

#[cfg(unix)]
mod os {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    pub type Fd = i32;
    pub const SOL_SOCKET: i32 = libc::SOL_SOCKET;
    pub const SO_REUSEADDR: i32 = libc::SO_REUSEADDR;
    pub const IPPROTO_IP: i32 = libc::IPPROTO_IP;
    pub const IPPROTO_IPV6: i32 = libc::IPPROTO_IPV6;
    pub const IPV6_V6ONLY: i32 = libc::IPV6_V6ONLY;
    pub const IPV6_UNICAST_HOPS: i32 = libc::IPV6_UNICAST_HOPS;
    pub const IPV6_TCLASS: i32 = libc::IPV6_TCLASS;
    pub const IP_TTL: i32 = libc::IP_TTL;
    pub const IP_TOS: i32 = libc::IP_TOS;
    /// The `IPPROTO_IP` options tried on an IPv6 socket.
    pub const IP_OPTIONS: [(&str, i32); 6] = [
        ("IP_TTL", libc::IP_TTL),
        ("IP_TOS", libc::IP_TOS),
        ("IP_RECVTOS", libc::IP_RECVTOS),
        ("IP_RECVTTL", libc::IP_RECVTTL),
        ("IP_PKTINFO", libc::IP_PKTINFO),
        ("IP_MULTICAST_TTL", libc::IP_MULTICAST_TTL),
    ];
    /// The receive options of an IPv4 socket that report a datagram's TTL and TOS.
    pub const V4_RECV: [i32; 2] = [libc::IP_RECVTTL, libc::IP_RECVTOS];
    /// The receive options of an IPv6 socket.
    pub const V6_RECV: [i32; 3] = [
        libc::IPV6_RECVPKTINFO,
        libc::IPV6_RECVHOPLIMIT,
        libc::IPV6_RECVTCLASS,
    ];

    fn last() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    pub fn error() -> String {
        let e = last();
        let name = match e {
            libc::EINVAL => "EINVAL",
            libc::EADDRINUSE => "EADDRINUSE",
            libc::EADDRNOTAVAIL => "EADDRNOTAVAIL",
            libc::EAFNOSUPPORT => "EAFNOSUPPORT",
            libc::ENOPROTOOPT => "ENOPROTOOPT",
            libc::EOPNOTSUPP => "EOPNOTSUPP",
            libc::ENETUNREACH => "ENETUNREACH",
            libc::EHOSTUNREACH => "EHOSTUNREACH",
            libc::ECONNREFUSED => "ECONNREFUSED",
            libc::ENOTCONN => "ENOTCONN",
            libc::EAGAIN => "EAGAIN",
            libc::EACCES => "EACCES",
            _ => return format!("errno {e}"),
        };
        name.to_string()
    }

    pub fn socket(v6: bool, tcp: bool) -> Fd {
        let family = if v6 { libc::AF_INET6 } else { libc::AF_INET };
        let ty = if tcp {
            libc::SOCK_STREAM
        } else {
            libc::SOCK_DGRAM
        };
        let fd = unsafe { libc::socket(family, ty, 0) };
        assert!(fd >= 0, "socket: {}", error());
        fd
    }

    pub fn close(fd: Fd) {
        unsafe { libc::close(fd) };
    }

    pub fn set_bytes(fd: Fd, level: i32, name: i32, value: &[u8]) -> Result<(), String> {
        let rc =
            unsafe { libc::setsockopt(fd, level, name, value.as_ptr().cast(), value.len() as u32) };
        if rc == 0 { Ok(()) } else { Err(error()) }
    }

    pub fn get_bytes(fd: Fd, level: i32, name: i32, cap: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; cap];
        let mut len = cap as libc::socklen_t;
        let rc = unsafe { libc::getsockopt(fd, level, name, buf.as_mut_ptr().cast(), &mut len) };
        if rc != 0 {
            return Err(error());
        }
        buf.truncate(len as usize);
        Ok(buf)
    }

    pub fn timeout(fd: Fd) {
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 200_000,
        };
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast(),
                size_of::<libc::timeval>() as u32,
            )
        };
        assert_eq!(rc, 0);
    }

    pub fn sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, u32) {
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let len = match addr {
            SocketAddr::V4(v4) => {
                let sin = (&raw mut storage).cast::<libc::sockaddr_in>();
                unsafe {
                    #[cfg(target_os = "macos")]
                    {
                        (*sin).sin_len = 16;
                    }
                    (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
                    (*sin).sin_port = v4.port().to_be();
                    (*sin).sin_addr.s_addr = u32::from(*v4.ip()).to_be();
                }
                size_of::<libc::sockaddr_in>()
            }
            SocketAddr::V6(v6) => {
                let sin6 = (&raw mut storage).cast::<libc::sockaddr_in6>();
                unsafe {
                    #[cfg(target_os = "macos")]
                    {
                        (*sin6).sin6_len = 28;
                    }
                    (*sin6).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    (*sin6).sin6_port = v6.port().to_be();
                    (*sin6).sin6_addr.s6_addr = v6.ip().octets();
                }
                size_of::<libc::sockaddr_in6>()
            }
        };
        (storage, len as u32)
    }

    pub fn parse(storage: &libc::sockaddr_storage, len: u32) -> (SocketAddr, u32) {
        let addr = match storage.ss_family as i32 {
            libc::AF_INET => {
                let sin = unsafe {
                    &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>()
                };
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))),
                    u16::from_be(sin.sin_port),
                )
            }
            _ => {
                let sin6 = unsafe {
                    &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
                };
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)),
                    u16::from_be(sin6.sin6_port),
                )
            }
        };
        (addr, len)
    }

    pub fn bind(fd: Fd, addr: SocketAddr) -> Result<(), String> {
        let (sa, len) = sockaddr(addr);
        let rc = unsafe { libc::bind(fd, (&raw const sa).cast(), len) };
        if rc == 0 { Ok(()) } else { Err(error()) }
    }

    pub fn connect(fd: Fd, addr: SocketAddr) -> Result<(), String> {
        let (sa, len) = sockaddr(addr);
        let rc = unsafe { libc::connect(fd, (&raw const sa).cast(), len) };
        if rc == 0 { Ok(()) } else { Err(error()) }
    }

    /// `connect` to an `AF_UNSPEC` address `len` bytes long, which dissolves a datagram socket's
    /// association.
    pub fn disconnect(fd: Fd, len: u32) -> Result<(), String> {
        let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        sa.ss_family = libc::AF_UNSPEC as libc::sa_family_t;
        let rc = unsafe { libc::connect(fd, (&raw const sa).cast(), len) };
        if rc == 0 { Ok(()) } else { Err(error()) }
    }

    pub fn listen(fd: Fd) -> Result<(), String> {
        if unsafe { libc::listen(fd, 8) } == 0 {
            Ok(())
        } else {
            Err(error())
        }
    }

    pub fn accept(fd: Fd) -> Result<(Fd, (SocketAddr, u32)), String> {
        let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = size_of::<libc::sockaddr_storage>() as u32;
        let new = unsafe { libc::accept(fd, (&raw mut sa).cast(), &mut len) };
        if new < 0 {
            return Err(error());
        }
        Ok((new, parse(&sa, len)))
    }

    fn named(
        fd: Fd,
        call: unsafe extern "C" fn(i32, *mut libc::sockaddr, *mut u32) -> i32,
    ) -> Result<(SocketAddr, u32), String> {
        let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = size_of::<libc::sockaddr_storage>() as u32;
        if unsafe { call(fd, (&raw mut sa).cast(), &mut len) } != 0 {
            return Err(error());
        }
        Ok(parse(&sa, len))
    }

    pub fn local(fd: Fd) -> Result<(SocketAddr, u32), String> {
        named(fd, libc::getsockname)
    }

    pub fn peer(fd: Fd) -> Result<(SocketAddr, u32), String> {
        named(fd, libc::getpeername)
    }

    pub fn send_to(fd: Fd, to: SocketAddr, data: &[u8]) -> Result<(), String> {
        let (sa, len) = sockaddr(to);
        let n = unsafe {
            libc::sendto(
                fd,
                data.as_ptr().cast(),
                data.len(),
                0,
                (&raw const sa).cast(),
                len,
            )
        };
        if n >= 0 { Ok(()) } else { Err(error()) }
    }

    pub fn send(fd: Fd, data: &[u8]) -> Result<(), String> {
        let n = unsafe { libc::send(fd, data.as_ptr().cast(), data.len(), 0) };
        if n >= 0 { Ok(()) } else { Err(error()) }
    }

    #[allow(clippy::unnecessary_cast)]
    pub fn recv(fd: Fd) -> Result<super::Received, String> {
        timeout(fd);
        let mut buf = [0u8; 256];
        let mut control = [0u64; 64];
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
        msg.msg_controllen = size_of_val(&control) as _;
        let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
        if n < 0 {
            return Err(error());
        }
        let mut cmsgs = Vec::new();
        let mut c = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !c.is_null() {
            let (level, ty, len) = unsafe { ((*c).cmsg_level, (*c).cmsg_type, (*c).cmsg_len) };
            let data_len = (len as usize).saturating_sub(unsafe { libc::CMSG_LEN(0) } as usize);
            let data = unsafe { std::slice::from_raw_parts(libc::CMSG_DATA(c), data_len) };
            let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
            cmsgs.push(format!("{level}/{ty}:{hex}"));
            c = unsafe { libc::CMSG_NXTHDR(&msg, c) };
        }
        Ok((n as usize, parse(&name, msg.msg_namelen), cmsgs))
    }
}

#[cfg(windows)]
mod os {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use windows_sys::Win32::Networking::WinSock as ws;

    pub type Fd = usize;
    pub const SOL_SOCKET: i32 = ws::SOL_SOCKET;
    pub const SO_REUSEADDR: i32 = ws::SO_REUSEADDR;
    pub const IPPROTO_IP: i32 = 0;
    pub const IPPROTO_IPV6: i32 = 41;
    pub const IPV6_V6ONLY: i32 = 27;
    pub const IPV6_UNICAST_HOPS: i32 = 4;
    pub const IPV6_TCLASS: i32 = 39;
    pub const IP_TTL: i32 = 4;
    pub const IP_TOS: i32 = 3;
    pub const IP_OPTIONS: [(&str, i32); 3] =
        [("IP_TTL", 4), ("IP_TOS", 3), ("IP_MULTICAST_TTL", 10)];
    pub const V4_RECV: [i32; 0] = [];
    pub const V6_RECV: [i32; 0] = [];

    pub fn error() -> String {
        let e = unsafe { ws::WSAGetLastError() };
        let name = match e {
            10013 => "WSAEACCES",
            10014 => "WSAEFAULT",
            10022 => "WSAEINVAL",
            10035 => "WSAEWOULDBLOCK",
            10042 => "WSAENOPROTOOPT",
            10045 => "WSAEOPNOTSUPP",
            10047 => "WSAEAFNOSUPPORT",
            10048 => "WSAEADDRINUSE",
            10049 => "WSAEADDRNOTAVAIL",
            10051 => "WSAENETUNREACH",
            10054 => "WSAECONNRESET",
            10057 => "WSAENOTCONN",
            10060 => "WSAETIMEDOUT",
            10061 => "WSAECONNREFUSED",
            10065 => "WSAEHOSTUNREACH",
            _ => return format!("error {e}"),
        };
        name.to_string()
    }

    pub fn socket(v6: bool, tcp: bool) -> Fd {
        let _ = std::net::UdpSocket::bind("127.0.0.1:0");
        let family = if v6 { ws::AF_INET6 } else { ws::AF_INET };
        let ty = if tcp { ws::SOCK_STREAM } else { ws::SOCK_DGRAM };
        let s = unsafe { ws::socket(family as i32, ty, 0) };
        assert_ne!(s, ws::INVALID_SOCKET, "socket: {}", error());
        s
    }

    pub fn close(fd: Fd) {
        unsafe { ws::closesocket(fd) };
    }

    pub fn set_bytes(fd: Fd, level: i32, name: i32, value: &[u8]) -> Result<(), String> {
        let rc = unsafe { ws::setsockopt(fd, level, name, value.as_ptr(), value.len() as i32) };
        if rc == 0 { Ok(()) } else { Err(error()) }
    }

    pub fn get_bytes(fd: Fd, level: i32, name: i32, cap: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; cap];
        let mut len = cap as i32;
        let rc = unsafe { ws::getsockopt(fd, level, name, buf.as_mut_ptr(), &mut len) };
        if rc != 0 {
            return Err(error());
        }
        buf.truncate(len.max(0) as usize);
        Ok(buf)
    }

    fn sockaddr(addr: SocketAddr) -> ([u8; 28], i32) {
        let mut buf = [0u8; 28];
        match addr {
            SocketAddr::V4(v4) => {
                buf[0..2].copy_from_slice(&ws::AF_INET.to_ne_bytes());
                buf[2..4].copy_from_slice(&v4.port().to_be_bytes());
                buf[4..8].copy_from_slice(&v4.ip().octets());
                (buf, 16)
            }
            SocketAddr::V6(v6) => {
                buf[0..2].copy_from_slice(&ws::AF_INET6.to_ne_bytes());
                buf[2..4].copy_from_slice(&v6.port().to_be_bytes());
                buf[8..24].copy_from_slice(&v6.ip().octets());
                (buf, 28)
            }
        }
    }

    fn parse(buf: &[u8], len: i32) -> (SocketAddr, u32) {
        let family = u16::from_ne_bytes([buf[0], buf[1]]);
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        let ip = if family == ws::AF_INET {
            IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]))
        } else {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).unwrap()))
        };
        (SocketAddr::new(ip, port), len as u32)
    }

    pub fn bind(fd: Fd, addr: SocketAddr) -> Result<(), String> {
        let (sa, len) = sockaddr(addr);
        let rc = unsafe { ws::bind(fd, sa.as_ptr().cast(), len) };
        if rc == 0 { Ok(()) } else { Err(error()) }
    }

    pub fn connect(fd: Fd, addr: SocketAddr) -> Result<(), String> {
        let (sa, len) = sockaddr(addr);
        let rc = unsafe { ws::connect(fd, sa.as_ptr().cast(), len) };
        if rc == 0 { Ok(()) } else { Err(error()) }
    }

    /// `connect` to the all-zero IPv6 address, which dissolves a datagram socket's association.
    pub fn disconnect(fd: Fd, len: u32) -> Result<(), String> {
        let (sa, _) = sockaddr(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0));
        let rc = unsafe { ws::connect(fd, sa.as_ptr().cast(), len as i32) };
        if rc == 0 { Ok(()) } else { Err(error()) }
    }

    pub fn listen(fd: Fd) -> Result<(), String> {
        if unsafe { ws::listen(fd, 8) } == 0 {
            Ok(())
        } else {
            Err(error())
        }
    }

    pub fn accept(fd: Fd) -> Result<(Fd, (SocketAddr, u32)), String> {
        let mut buf = [0u8; 64];
        let mut len = 64i32;
        let s = unsafe { ws::accept(fd, buf.as_mut_ptr().cast(), &mut len) };
        if s == ws::INVALID_SOCKET {
            return Err(error());
        }
        Ok((s, parse(&buf, len)))
    }

    pub fn local(fd: Fd) -> Result<(SocketAddr, u32), String> {
        let mut buf = [0u8; 64];
        let mut len = 64i32;
        if unsafe { ws::getsockname(fd, buf.as_mut_ptr().cast(), &mut len) } != 0 {
            return Err(error());
        }
        Ok(parse(&buf, len))
    }

    pub fn peer(fd: Fd) -> Result<(SocketAddr, u32), String> {
        let mut buf = [0u8; 64];
        let mut len = 64i32;
        if unsafe { ws::getpeername(fd, buf.as_mut_ptr().cast(), &mut len) } != 0 {
            return Err(error());
        }
        Ok(parse(&buf, len))
    }

    pub fn send_to(fd: Fd, to: SocketAddr, data: &[u8]) -> Result<(), String> {
        let (sa, len) = sockaddr(to);
        let n = unsafe {
            ws::sendto(
                fd,
                data.as_ptr(),
                data.len() as i32,
                0,
                sa.as_ptr().cast(),
                len,
            )
        };
        if n >= 0 { Ok(()) } else { Err(error()) }
    }

    pub fn send(fd: Fd, data: &[u8]) -> Result<(), String> {
        let n = unsafe { ws::send(fd, data.as_ptr(), data.len() as i32, 0) };
        if n >= 0 { Ok(()) } else { Err(error()) }
    }

    pub fn recv(fd: Fd) -> Result<super::Received, String> {
        let ms = 200i32.to_ne_bytes();
        set_bytes(fd, SOL_SOCKET, ws::SO_RCVTIMEO, &ms).unwrap();
        let mut buf = [0u8; 256];
        let mut name = [0u8; 64];
        let mut len = 64i32;
        let n = unsafe {
            ws::recvfrom(
                fd,
                buf.as_mut_ptr(),
                256,
                0,
                name.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if n < 0 {
            return Err(error());
        }
        Ok((n as usize, parse(&name, len), Vec::new()))
    }
}

use os::Fd;

const LO4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const ANY4: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
const LO6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
const ANY6: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

fn mapped(ip: Ipv4Addr) -> IpAddr {
    IpAddr::V6(ip.to_ipv6_mapped())
}

fn lo_mapped() -> IpAddr {
    mapped(Ipv4Addr::LOCALHOST)
}

/// The lines a scenario reports, with every port named by the order it first appears in its
/// line, so the host's ports and the sim's (which reuses a closed socket's) compare equal.
#[derive(Default)]
struct Log {
    lines: Vec<String>,
    ports: HashMap<u16, usize>,
}

impl Log {
    fn line(&mut self, line: impl Into<String>) {
        self.lines.push(line.into());
        self.ports.clear();
    }

    fn port(&mut self, port: u16) -> String {
        if port == 0 {
            return "0".into();
        }
        let next = self.ports.len();
        format!("p{}", self.ports.entry(port).or_insert(next))
    }

    fn addr(&mut self, (addr, len): (SocketAddr, u32)) -> String {
        let port = self.port(addr.port());
        match addr.ip() {
            IpAddr::V4(ip) => format!("{ip}:{port}/{len}"),
            IpAddr::V6(ip) => format!("[{ip}]:{port}/{len}"),
        }
    }

    fn named(&mut self, what: Result<(SocketAddr, u32), String>) -> String {
        match what {
            Ok(addr) => self.addr(addr),
            Err(e) => e,
        }
    }

    fn recv(&mut self, fd: Fd) -> String {
        match os::recv(fd) {
            Ok((n, from, cmsgs)) => format!("{n}B from {} {}", self.addr(from), cmsgs.join(" ")),
            Err(e) => e,
        }
    }
}

fn shown<T: std::fmt::Debug>(result: Result<T, String>) -> String {
    match result {
        Ok(v) => format!("{v:?}"),
        Err(e) => e,
    }
}

fn set_int(fd: Fd, level: i32, name: i32, value: i32) -> Result<(), String> {
    os::set_bytes(fd, level, name, &value.to_ne_bytes())
}

fn port(fd: Fd) -> u16 {
    os::local(fd).unwrap().0.port()
}

/// An IPv6 socket with `IPV6_V6ONLY` set to `only`, or left at the host's default.
fn v6(tcp: bool, only: Option<bool>) -> Fd {
    let fd = os::socket(true, tcp);
    if let Some(only) = only {
        set_int(fd, os::IPPROTO_IPV6, os::IPV6_V6ONLY, only as i32).unwrap();
    }
    fd
}

fn v4(tcp: bool) -> Fd {
    os::socket(false, tcp)
}

fn v6only(fd: Fd, cap: usize) -> String {
    shown(os::get_bytes(fd, os::IPPROTO_IPV6, os::IPV6_V6ONLY, cap))
}

fn options() -> Vec<String> {
    let mut log = Log::default();
    for tcp in [false, true] {
        let t = if tcp { "tcp" } else { "udp" };
        let fd = os::socket(true, tcp);
        log.line(format!("{t} default {}", v6only(fd, 8)));
        for (value, label) in [
            (&2i32.to_ne_bytes()[..], "2"),
            (&0i32.to_ne_bytes(), "0"),
            (&(-1i32).to_ne_bytes(), "-1"),
            (&0i32.to_ne_bytes(), "0"),
            (&[1u8][..], "byte 1"),
            (&[], "empty"),
            (&[0, 1, 0, 0], "0x100"),
            (&[1, 0, 0, 0, 0, 0, 0, 0], "long 1"),
        ] {
            let set = shown(os::set_bytes(fd, os::IPPROTO_IPV6, os::IPV6_V6ONLY, value));
            log.line(format!("{t} set {label}: {set} -> {}", v6only(fd, 8)));
        }
        for cap in [0, 1, 2] {
            log.line(format!("{t} get into {cap}: {}", v6only(fd, cap)));
        }
        os::close(fd);
        let fd = v4(tcp);
        let set = shown(set_int(fd, os::IPPROTO_IPV6, os::IPV6_V6ONLY, 0));
        log.line(format!("{t} ipv4 set: {set} -> {}", v6only(fd, 8)));
        os::close(fd);
        for only in [Some(false), Some(true)] {
            let fd = v6(tcp, only);
            os::bind(fd, SocketAddr::new(ANY6, 0)).unwrap();
            for value in [0, 1] {
                let set = shown(set_int(fd, os::IPPROTO_IPV6, os::IPV6_V6ONLY, value));
                log.line(format!(
                    "{t} {only:?} bound set {value}: {set} -> {}",
                    v6only(fd, 8)
                ));
            }
            os::close(fd);
        }
        for at in [LO6, lo_mapped()] {
            let fd = v6(tcp, Some(false));
            os::bind(fd, SocketAddr::new(at, 0)).unwrap();
            log.line(format!("{t} bound {at} reads {}", v6only(fd, 8)));
            os::close(fd);
        }
        for (label, at) in [("v6", LO6), ("v4", LO4)] {
            let server = if tcp {
                let l = os::socket(at.is_ipv6(), true);
                os::bind(l, SocketAddr::new(at, 0)).unwrap();
                os::listen(l).unwrap();
                l
            } else {
                let r = os::socket(at.is_ipv6(), false);
                os::bind(r, SocketAddr::new(at, 0)).unwrap();
                r
            };
            let to = SocketAddr::new(if at.is_ipv4() { lo_mapped() } else { at }, port(server));
            let fd = v6(tcp, Some(false));
            let connected = shown(os::connect(fd, to));
            let set = shown(set_int(fd, os::IPPROTO_IPV6, os::IPV6_V6ONLY, 1));
            log.line(format!("{t} connected to {label}: {connected}, set: {set}"));
            if tcp {
                let (accepted, _) = os::accept(server).unwrap();
                log.line(format!(
                    "{t} accepted from {label}: {}",
                    v6only(accepted, 8)
                ));
                os::close(accepted);
                let set = shown(set_int(server, os::IPPROTO_IPV6, os::IPV6_V6ONLY, 1));
                log.line(format!("{t} listener set: {set}"));
            } else {
                let fd = v6(false, Some(false));
                let sent = shown(os::send_to(fd, to, b"x"));
                let set = shown(set_int(fd, os::IPPROTO_IPV6, os::IPV6_V6ONLY, 1));
                log.line(format!("{t} sent to {label}: {sent}, set: {set}"));
                os::close(fd);
            }
            os::close(fd);
            os::close(server);
        }
        if tcp {
            for only in [false, true] {
                let l = v6(true, Some(only));
                os::bind(l, SocketAddr::new(ANY6, 0)).unwrap();
                os::listen(l).unwrap();
                let c = os::socket(true, true);
                os::connect(c, SocketAddr::new(LO6, port(l))).unwrap();
                let (a, _) = os::accept(l).unwrap();
                log.line(format!(
                    "accepted from v6only={only} listener: {}",
                    v6only(a, 8)
                ));
                for fd in [a, c, l] {
                    os::close(fd);
                }
            }
        }
    }
    for only in [Some(false), Some(true)] {
        let fd = v6(false, only);
        for (label, name) in os::IP_OPTIONS {
            let set = shown(set_int(fd, os::IPPROTO_IP, name, 5));
            let got = shown(os::get_bytes(fd, os::IPPROTO_IP, name, 4));
            log.line(format!("udp {only:?} {label}: {set} -> {got}"));
        }
        os::close(fd);
    }
    log.lines
}

fn binds() -> Vec<String> {
    let mut log = Log::default();
    for tcp in [false, true] {
        let t = if tcp { "tcp" } else { "udp" };
        for (label, only, at) in [
            ("v6only mapped", Some(true), lo_mapped()),
            ("dual mapped", Some(false), lo_mapped()),
            (
                "dual mapped wildcard",
                Some(false),
                mapped(Ipv4Addr::UNSPECIFIED),
            ),
            ("v6 sockaddr_in", Some(false), LO4),
        ] {
            let fd = v6(tcp, only);
            let bound = shown(os::bind(fd, SocketAddr::new(at, 0)));
            let name = log.named(os::local(fd));
            log.line(format!("{t} {label}: {bound} {name}"));
            os::close(fd);
        }
        for (label, at) in [("v6", LO6), ("mapped", lo_mapped())] {
            let fd = v4(tcp);
            let bound = shown(os::bind(fd, SocketAddr::new(at, 0)));
            log.line(format!("{t} v4 sockaddr_in6 {label}: {bound}"));
            os::close(fd);
        }
        for only in [None, Some(false), Some(true)] {
            let fd = v6(tcp, only);
            os::bind(fd, SocketAddr::new(ANY6, 0)).unwrap();
            let name = log.named(os::local(fd));
            let other = v4(tcp);
            let bound = shown(os::bind(other, SocketAddr::new(ANY4, port(fd))));
            log.line(format!("{t} {only:?} {name} then {ANY4}: {bound}"));
            os::close(other);
            os::close(fd);
        }
    }
    log.lines
}

#[derive(Clone, Copy)]
struct Kind {
    name: &'static str,
    v6: bool,
    only: Option<bool>,
    at: IpAddr,
}

fn kinds() -> [Kind; 7] {
    let kind = |name, v6, only, at| Kind { name, v6, only, at };
    [
        kind("v4 wildcard", false, None, ANY4),
        kind("v4 loopback", false, None, LO4),
        kind("dual wildcard", true, Some(false), ANY6),
        kind("v6only wildcard", true, Some(true), ANY6),
        kind("dual mapped loopback", true, Some(false), lo_mapped()),
        kind("v6 loopback", true, Some(false), LO6),
        kind("v6only loopback", true, Some(true), LO6),
    ]
}

#[derive(Clone, Copy)]
struct Case {
    tcp: bool,
    held: Kind,
    want: Kind,
    held_reuse: bool,
    want_reuse: bool,
    listening: bool,
}

fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for tcp in [false, true] {
        for held in kinds() {
            for want in kinds() {
                for bits in 0..if tcp { 8 } else { 4 } {
                    out.push(Case {
                        tcp,
                        held,
                        want,
                        held_reuse: bits & 1 != 0,
                        want_reuse: bits & 2 != 0,
                        listening: bits & 4 != 0,
                    });
                }
            }
        }
    }
    out
}

fn open(kind: Kind, tcp: bool, reuse: bool) -> Fd {
    let fd = if kind.v6 { v6(tcp, kind.only) } else { v4(tcp) };
    set_int(fd, os::SOL_SOCKET, os::SO_REUSEADDR, reuse as i32).unwrap();
    fd
}

/// The second bind of `case`: `Ok` or the error it fails with.
fn second_bind(case: Case) -> Result<(), String> {
    let held = open(case.held, case.tcp, case.held_reuse);
    os::bind(held, SocketAddr::new(case.held.at, 0)).unwrap();
    if case.listening {
        os::listen(held).unwrap();
    }
    let want = open(case.want, case.tcp, case.want_reuse);
    let result = os::bind(want, SocketAddr::new(case.want.at, port(held)));
    os::close(want);
    os::close(held);
    result
}

/// [`second_bind`] on the host, where another program may hold the port the first socket got in
/// the other family: a case two runs disagree on is decided by a third.
fn host_bind(case: Case) -> Result<(), String> {
    let (a, b) = (second_bind(case), second_bind(case));
    if a == b { a } else { second_bind(case) }
}

#[test]
fn overlapping_binds_across_families_os_truth() {
    let real: Vec<_> = cases().into_iter().map(|c| (c, host_bind(c))).collect();
    for (name, sim) in sims() {
        let sim: Vec<_> = sim.run(|| cases().into_iter().map(second_bind).collect());
        let differ: Vec<String> = real
            .iter()
            .zip(&sim)
            .filter(|((_, real), sim)| real != *sim)
            .map(|((case, real), sim)| {
                format!(
                    "{} {} then {} (reuse {}/{}, listening {}): host {real:?}, {name} {sim:?}",
                    if case.tcp { "tcp" } else { "udp" },
                    case.held.name,
                    case.want.name,
                    case.held_reuse,
                    case.want_reuse,
                    case.listening
                )
            })
            .collect();
        assert!(differ.is_empty(), "{}", differ.join("\n"));
    }
}

fn udp() -> Vec<String> {
    let mut log = Log::default();
    for only in [false, true] {
        let r = v6(false, Some(only));
        os::bind(r, SocketAddr::new(ANY6, 0)).unwrap();
        for name in os::V6_RECV {
            set_int(r, os::IPPROTO_IPV6, name, 1).unwrap();
        }
        let s = v4(false);
        let _ = set_int(s, os::IPPROTO_IP, os::IP_TTL, 33);
        let _ = set_int(s, os::IPPROTO_IP, os::IP_TOS, 0x28);
        let sent = shown(os::send_to(s, SocketAddr::new(LO4, port(r)), b"hello"));
        let from = log.named(os::local(s));
        let got = log.recv(r);
        log.line(format!("v4 to v6only={only}: {sent} from {from}: {got}"));
        os::close(s);
        os::close(r);
    }
    if cfg!(unix) {
        let r = v6(false, Some(false));
        os::bind(r, SocketAddr::new(ANY6, 0)).unwrap();
        for (label, name) in os::IP_OPTIONS {
            if label.starts_with("IP_RECV") || label == "IP_PKTINFO" {
                let set = shown(set_int(r, os::IPPROTO_IP, name, 1));
                log.line(format!("dual {label}: {set}"));
            }
        }
        let s = v4(false);
        let _ = set_int(s, os::IPPROTO_IP, os::IP_TTL, 33);
        let _ = set_int(s, os::IPPROTO_IP, os::IP_TOS, 0x28);
        os::send_to(s, SocketAddr::new(LO4, port(r)), b"hello").unwrap();
        let got = log.recv(r);
        log.line(format!("v4 to dual, IPv4 options: {got}"));
        for name in os::V6_RECV {
            set_int(r, os::IPPROTO_IPV6, name, 1).unwrap();
        }
        os::send_to(s, SocketAddr::new(LO4, port(r)), b"hello").unwrap();
        let got = log.recv(r);
        log.line(format!("v4 to dual, both: {got}"));
        let s6 = os::socket(true, false);
        os::send_to(s6, SocketAddr::new(LO6, port(r)), b"hello6").unwrap();
        let got = log.recv(r);
        log.line(format!("v6 to dual, both: {got}"));
        for fd in [s6, s, r] {
            os::close(fd);
        }
    }
    for only in [false, true] {
        let r = v4(false);
        os::bind(r, SocketAddr::new(LO4, 0)).unwrap();
        for name in os::V4_RECV {
            set_int(r, os::IPPROTO_IP, name, 1).unwrap();
        }
        let to = SocketAddr::new(lo_mapped(), port(r));
        let s = v6(false, Some(only));
        let sent = shown(os::send_to(s, to, b"hi"));
        let name = log.named(os::local(s));
        let got = log.recv(r);
        log.line(format!("v6only={only} to mapped: {sent} as {name}: {got}"));
        if cfg!(unix) {
            let hops = shown(set_int(s, os::IPPROTO_IPV6, os::IPV6_UNICAST_HOPS, 7));
            let tclass = shown(set_int(s, os::IPPROTO_IPV6, os::IPV6_TCLASS, 0x20));
            let _ = os::send_to(s, to, b"hops");
            let got = log.recv(r);
            log.line(format!("  hops {hops} tclass {tclass}: {got}"));
            let ttl = shown(set_int(s, os::IPPROTO_IP, os::IP_TTL, 9));
            let tos = shown(set_int(s, os::IPPROTO_IP, os::IP_TOS, 0x40));
            let _ = os::send_to(s, to, b"ttl");
            let got = log.recv(r);
            log.line(format!("  ttl {ttl} tos {tos}: {got}"));
            let fresh = v6(false, Some(only));
            let ttl = shown(set_int(fresh, os::IPPROTO_IP, os::IP_TTL, 9));
            let _ = os::send_to(fresh, to, b"ttl only");
            let got = log.recv(r);
            log.line(format!("  fresh ttl {ttl}: {got}"));
            os::close(fresh);
        }
        os::close(s);
        os::close(r);
    }
    let r4 = v4(false);
    os::bind(r4, SocketAddr::new(LO4, 0)).unwrap();
    let r6 = os::socket(true, false);
    os::bind(r6, SocketAddr::new(LO6, 0)).unwrap();
    let to4 = SocketAddr::new(lo_mapped(), port(r4));
    let to6 = SocketAddr::new(LO6, port(r6));
    for (label, at) in [("::1", LO6), ("mapped", lo_mapped()), ("::", ANY6)] {
        let s = v6(false, Some(false));
        os::bind(s, SocketAddr::new(at, 0)).unwrap();
        let a = shown(os::send_to(s, to4, b"a"));
        let b = shown(os::send_to(s, to6, b"b"));
        let (got4, got6) = (log.recv(r4), log.recv(r6));
        log.line(format!(
            "bound {label}: to mapped {a}, to ::1 {b}; {got4}; {got6}"
        ));
        let connected = shown(os::connect(s, to4));
        let (name, peer) = (log.named(os::local(s)), log.named(os::peer(s)));
        log.line(format!("  connect mapped: {connected} {name} {peer}"));
        os::close(s);
        let s = v6(false, Some(false));
        os::bind(s, SocketAddr::new(at, 0)).unwrap();
        let connected = shown(os::connect(s, to6));
        let (name, peer) = (log.named(os::local(s)), log.named(os::peer(s)));
        log.line(format!("  connect ::1: {connected} {name} {peer}"));
        os::close(s);
    }
    let s = v4(false);
    let sent = shown(os::send_to(s, to4, b"x"));
    let connected = shown(os::connect(s, to4));
    log.line(format!("v4 to sockaddr_in6: {sent}, connect {connected}"));
    os::close(s);
    let s = v6(false, Some(false));
    let sent = shown(os::send_to(s, SocketAddr::new(LO4, port(r4)), b"x"));
    let got = log.recv(r4);
    let connected = shown(os::connect(s, SocketAddr::new(LO4, port(r4))));
    let peer = log.named(os::peer(s));
    log.line(format!(
        "dual to sockaddr_in: {sent} {got}, connect {connected} {peer}"
    ));
    os::close(s);
    if cfg!(not(target_os = "macos")) {
        let s = v6(false, Some(true));
        let sent = shown(os::send_to(s, SocketAddr::new(LO4, port(r4)), b"x"));
        let connected = shown(os::connect(s, SocketAddr::new(LO4, port(r4))));
        log.line(format!(
            "v6only to sockaddr_in: {sent}, connect {connected}"
        ));
        os::close(s);
    }
    let s = v6(false, Some(false));
    let connected = shown(os::connect(s, to4));
    let (name, peer) = (log.named(os::local(s)), log.named(os::peer(s)));
    log.line(format!("connect mapped: {connected} {name} {peer}"));
    os::send(s, b"ping").unwrap();
    let got = log.recv(r4);
    os::send_to(r4, SocketAddr::new(LO4, port(s)), b"pong").unwrap();
    let back = log.recv(s);
    log.line(format!("  {got}; reply {back}"));
    let again = shown(os::connect(s, to6));
    let (name, peer) = (log.named(os::local(s)), log.named(os::peer(s)));
    log.line(format!("  then connect ::1: {again} {name} {peer}"));
    os::close(s);
    for len in [16, 28] {
        for (label, bound) in [("unbound", None), ("bound ::", Some(ANY6))] {
            let s = v6(false, Some(false));
            if let Some(at) = bound {
                os::bind(s, SocketAddr::new(at, 0)).unwrap();
            }
            os::connect(s, to4).unwrap();
            let dissolved = shown(os::disconnect(s, len));
            let (name, peer) = (log.named(os::local(s)), log.named(os::peer(s)));
            log.line(format!(
                "{label} mapped dissolve {len}: {dissolved} {name} {peer}"
            ));
            let a = shown(os::send_to(s, to4, b"a"));
            let b = shown(os::send_to(s, to6, b"b"));
            let (got4, got6) = (log.recv(r4), log.recv(r6));
            log.line(format!("  to mapped {a}, to ::1 {b}; {got4}; {got6}"));
            os::close(s);
        }
    }
    if cfg!(not(target_os = "macos")) {
        let s = v6(false, Some(true));
        let sent = shown(os::send_to(s, to4, b"x"));
        let connected = shown(os::connect(s, to4));
        log.line(format!("v6only to mapped: {sent}, connect {connected}"));
        os::close(s);
    } else {
        let s = v6(false, Some(true));
        let sent = shown(os::send_to(s, to4, b"x"));
        let got = log.recv(r4);
        os::send_to(r4, SocketAddr::new(LO4, port(s)), b"back").unwrap();
        let back = log.recv(s);
        log.line(format!("v6only to mapped: {sent} {got}; reply {back}"));
        os::close(s);
    }
    let r = v6(false, Some(false));
    os::bind(r, SocketAddr::new(lo_mapped(), 0)).unwrap();
    let s = v4(false);
    os::send_to(s, SocketAddr::new(LO4, port(r)), b"to mapped").unwrap();
    let got = log.recv(r);
    log.line(format!("v4 to mapped bind: {got}"));
    let s6 = os::socket(true, false);
    let sent = shown(os::send_to(s6, SocketAddr::new(LO6, port(r)), b"x"));
    let got = log.recv(r);
    log.line(format!("v6 to mapped bind: {sent} {got}"));
    for fd in [s6, s, r] {
        os::close(fd);
    }
    let a = v4(false);
    set_int(a, os::SOL_SOCKET, os::SO_REUSEADDR, 1).unwrap();
    os::bind(a, SocketAddr::new(ANY4, 0)).unwrap();
    let d = v6(false, Some(false));
    set_int(d, os::SOL_SOCKET, os::SO_REUSEADDR, 1).unwrap();
    let shared = shown(os::bind(d, SocketAddr::new(ANY6, port(a))));
    let s = v4(false);
    os::send_to(s, SocketAddr::new(LO4, port(a)), b"who").unwrap();
    let (to_a, to_d) = (log.recv(a), log.recv(d));
    log.line(format!(
        "v4 and dual wildcards: {shared}; v4 {to_a}; dual {to_d}"
    ));
    for fd in [s, d, a, r6, r4] {
        os::close(fd);
    }
    log.lines
}

fn tcp() -> Vec<String> {
    let mut log = Log::default();
    for only in [false, true] {
        let l = v6(true, Some(only));
        os::bind(l, SocketAddr::new(ANY6, 0)).unwrap();
        os::listen(l).unwrap();
        let c = v4(true);
        let connected = shown(os::connect(c, SocketAddr::new(LO4, port(l))));
        log.line(format!("v4 to v6only={only} listener: {connected}"));
        if !only {
            let (a, from) = os::accept(l).unwrap();
            let from = log.addr(from);
            let (name, peer) = (log.named(os::local(a)), log.named(os::peer(a)));
            log.line(format!("  accepted {from}: {name} {peer}"));
            let (name, peer) = (log.named(os::local(c)), log.named(os::peer(c)));
            log.line(format!("  client {name} {peer}"));
            os::close(a);
        }
        os::close(c);
        os::close(l);
    }
    let l = v4(true);
    os::bind(l, SocketAddr::new(LO4, 0)).unwrap();
    os::listen(l).unwrap();
    let to = SocketAddr::new(lo_mapped(), port(l));
    for only in [false, true] {
        let c = v6(true, Some(only));
        let connected = shown(os::connect(c, to));
        log.line(format!("v6only={only} to mapped: {connected}"));
        if !only {
            let (name, peer) = (log.named(os::local(c)), log.named(os::peer(c)));
            let (a, from) = os::accept(l).unwrap();
            let from = log.addr(from);
            let server = log.named(os::local(a));
            log.line(format!("  client {name} {peer}; server {from} {server}"));
            os::close(a);
        }
        os::close(c);
    }
    for (label, at) in [("::1", LO6), ("::", ANY6)] {
        let c = v6(true, Some(false));
        os::bind(c, SocketAddr::new(at, 0)).unwrap();
        let connected = shown(os::connect(c, to));
        let name = log.named(os::local(c));
        log.line(format!("bound {label} to mapped: {connected} {name}"));
        if connected == "()" {
            let (a, _) = os::accept(l).unwrap();
            os::close(a);
        }
        os::close(c);
    }
    let c = v4(true);
    let connected = shown(os::connect(c, to));
    log.line(format!("v4 to sockaddr_in6: {connected}"));
    os::close(c);
    let c = v6(true, Some(false));
    let connected = shown(os::connect(c, SocketAddr::new(LO4, port(l))));
    log.line(format!("dual to sockaddr_in: {connected}"));
    os::close(c);
    os::close(l);
    let l6 = os::socket(true, true);
    os::bind(l6, SocketAddr::new(LO6, 0)).unwrap();
    os::listen(l6).unwrap();
    let l = v6(true, Some(false));
    os::bind(l, SocketAddr::new(lo_mapped(), 0)).unwrap();
    os::listen(l).unwrap();
    let name = log.named(os::local(l));
    let c = v4(true);
    let connected = shown(os::connect(c, SocketAddr::new(LO4, port(l))));
    let (a, from) = os::accept(l).unwrap();
    let from = log.addr(from);
    let accepted = log.named(os::local(a));
    log.line(format!(
        "mapped listener {name}: {connected} {from} {accepted}"
    ));
    os::close(a);
    os::close(c);
    let c = os::socket(true, true);
    let connected = shown(os::connect(c, SocketAddr::new(LO6, port(l))));
    log.line(format!("  v6 to it: {connected}"));
    os::close(c);
    let c = v6(true, Some(false));
    os::bind(c, SocketAddr::new(lo_mapped(), 0)).unwrap();
    let connected = shown(os::connect(c, SocketAddr::new(LO6, port(l6))));
    log.line(format!("mapped bind to ::1: {connected}"));
    for fd in [c, l, l6] {
        os::close(fd);
    }
    if cfg!(unix) {
        let l = v6(true, Some(false));
        os::listen(l).unwrap();
        let name = log.named(os::local(l));
        let c = v4(true);
        let connected = shown(os::connect(c, SocketAddr::new(LO4, port(l))));
        log.line(format!("unbound dual listener {name}: {connected}"));
        os::close(c);
        os::close(l);
    }
    log.lines
}

/// The sims a scenario runs in: a plain one, and on Linux one whose datagram sockets a `SimHost`
/// serves.
fn sims() -> Vec<(&'static str, Sim)> {
    let sim = || {
        Sim::builder()
            .strict_sockopts()
            .stuck_after(Duration::from_secs(20))
    };
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut sims = vec![("sim", sim().build())];
    #[cfg(target_os = "linux")]
    sims.push((
        "host",
        sim().host(snare::HostProfile::new().build()).build(),
    ));
    sims
}

/// Runs `scenario` on the host and in each of [`sims`] and compares the lines.
fn compare(scenario: fn() -> Vec<String>) {
    let real = scenario();
    for (name, sim) in sims() {
        let sim = sim.run(scenario);
        let diff: Vec<String> = real
            .iter()
            .zip(&sim)
            .filter(|(r, s)| r != s)
            .map(|(r, s)| format!("real {r}\n{name:>4} {s}"))
            .collect();
        assert!(diff.is_empty(), "{}", diff.join("\n"));
        assert_eq!(real.len(), sim.len());
    }
}

#[test]
#[cfg_attr(
    windows,
    ignore = "IP_TOS on a dual-stack socket: the model refuses it as Windows 11 build 26200 does; Windows Server on the GitHub runner accepts it (OPEN_BUGS.md, Ignored validation)"
)]
fn v6only_option_os_truth() {
    compare(options);
}

#[test]
fn mapped_binds_os_truth() {
    compare(binds);
}

#[test]
fn dual_stack_datagrams_os_truth() {
    compare(udp);
}

#[test]
fn dual_stack_streams_os_truth() {
    compare(tcp);
}

/// A tokio listener on the IPv6 wildcard accepts an IPv4 client, as a dual-stack socket does.
#[cfg(unix)]
#[test]
fn tokio_dual_stack_listener_accepts_ipv4() {
    Sim::builder().strict_sockopts().build().run(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let listener = tokio::net::TcpListener::bind("[::]:7400").await.unwrap();
                let client = tokio::spawn(async {
                    let mut stream = tokio::net::TcpStream::connect("127.0.0.1:7400")
                        .await
                        .unwrap();
                    stream.write_all(b"over ipv4").await.unwrap();
                    stream.local_addr().unwrap()
                });
                let (mut stream, from) = listener.accept().await.unwrap();
                let mut got = Vec::new();
                stream.read_to_end(&mut got).await.unwrap();
                let client = client.await.unwrap();
                assert_eq!(got, b"over ipv4");
                assert_eq!(
                    from,
                    SocketAddr::new(Ipv4Addr::LOCALHOST.to_ipv6_mapped().into(), client.port())
                );
                assert_eq!(
                    stream.local_addr().unwrap(),
                    "[::ffff:127.0.0.1]:7400".parse().unwrap()
                );
            });
    });
}
