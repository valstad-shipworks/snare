#![cfg(any(target_os = "linux", target_os = "macos", windows))]

//! Sharing a port, in a plain sim and on the host's loopback: which second binds `SO_REUSEADDR`
//! and `SO_REUSEPORT` (Windows: `SO_REUSEADDR` and `SO_EXCLUSIVEADDRUSE`) let through for TCP and
//! UDP, IPv4 and IPv6, and the listens that follow; which of several datagram sockets sharing an
//! address a unicast datagram reaches; every member of a group sharing a port receiving a
//! multicast datagram; and which of several listeners sharing an address accepts a connection.
//! Linux spreads datagrams and connections over a `SO_REUSEPORT` group by a keyed hash, so there
//! only the properties the hash keeps are compared: each flow reaches one socket, every datagram
//! and connection lands once.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use snare::Sim;

#[cfg(unix)]
mod os {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    pub type Fd = i32;
    pub const SOL_SOCKET: i32 = libc::SOL_SOCKET;
    pub const IPPROTO_IPV6: i32 = libc::IPPROTO_IPV6;
    pub const IPV6_V6ONLY: i32 = libc::IPV6_V6ONLY;
    /// The two port-sharing options, each tried alone and together.
    pub const SHARING: [(&str, i32); 2] = [
        ("SO_REUSEADDR", libc::SO_REUSEADDR),
        ("SO_REUSEPORT", libc::SO_REUSEPORT),
    ];
    /// What a program sets for several receivers to share a port.
    pub const SHARE: &[i32] = &[libc::SO_REUSEADDR, libc::SO_REUSEPORT];

    fn last() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    pub fn error() -> String {
        let e = last();
        let name = match e {
            libc::EINVAL => "EINVAL",
            libc::EADDRINUSE => "EADDRINUSE",
            libc::EADDRNOTAVAIL => "EADDRNOTAVAIL",
            libc::EAGAIN => "EAGAIN",
            libc::EACCES => "EACCES",
            libc::ECONNREFUSED => "ECONNREFUSED",
            libc::ENOPROTOOPT => "ENOPROTOOPT",
            libc::EOPNOTSUPP => "EOPNOTSUPP",
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

    pub fn set_int(fd: Fd, level: i32, name: i32, value: i32) -> Result<(), String> {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                (&raw const value).cast(),
                size_of::<i32>() as u32,
            )
        };
        if rc == 0 { Ok(()) } else { Err(error()) }
    }

    pub fn get_int(fd: Fd, level: i32, name: i32) -> Result<i32, String> {
        let mut value = 0i32;
        let mut len = size_of::<i32>() as libc::socklen_t;
        let rc = unsafe { libc::getsockopt(fd, level, name, (&raw mut value).cast(), &mut len) };
        if rc == 0 { Ok(value) } else { Err(error()) }
    }

    pub fn nonblocking(fd: Fd) {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
    }

    fn sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, u32) {
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

    fn parse(storage: &libc::sockaddr_storage) -> SocketAddr {
        match storage.ss_family as i32 {
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
        }
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

    pub fn listen(fd: Fd) -> Result<(), String> {
        if unsafe { libc::listen(fd, 16) } == 0 {
            Ok(())
        } else {
            Err(error())
        }
    }

    pub fn accept(fd: Fd) -> Result<Fd, String> {
        let new = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if new < 0 { Err(error()) } else { Ok(new) }
    }

    pub fn local(fd: Fd) -> SocketAddr {
        let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = size_of::<libc::sockaddr_storage>() as u32;
        assert_eq!(
            unsafe { libc::getsockname(fd, (&raw mut sa).cast(), &mut len) },
            0
        );
        parse(&sa)
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

    pub fn recv(fd: Fd) -> Result<Vec<u8>, String> {
        let mut buf = [0u8; 64];
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(error());
        }
        Ok(buf[..n as usize].to_vec())
    }

    pub fn join(fd: Fd, group: Ipv4Addr) -> Result<(), String> {
        let mreq = libc::ip_mreq {
            imr_multiaddr: libc::in_addr {
                s_addr: u32::from(group).to_be(),
            },
            imr_interface: libc::in_addr { s_addr: 0 },
        };
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_ADD_MEMBERSHIP,
                (&raw const mreq).cast(),
                size_of::<libc::ip_mreq>() as u32,
            )
        };
        if rc == 0 { Ok(()) } else { Err(error()) }
    }
}

#[cfg(windows)]
mod os {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use windows_sys::Win32::Networking::WinSock as ws;

    pub type Fd = usize;
    pub const SOL_SOCKET: i32 = ws::SOL_SOCKET;
    pub const IPPROTO_IPV6: i32 = 41;
    pub const IPV6_V6ONLY: i32 = 27;
    pub const SHARING: [(&str, i32); 2] = [
        ("SO_REUSEADDR", ws::SO_REUSEADDR),
        ("SO_EXCLUSIVEADDRUSE", ws::SO_EXCLUSIVEADDRUSE),
    ];
    pub const SHARE: &[i32] = &[ws::SO_REUSEADDR];

    pub fn error() -> String {
        let e = unsafe { ws::WSAGetLastError() };
        let name = match e {
            10013 => "WSAEACCES",
            10014 => "WSAEFAULT",
            10022 => "WSAEINVAL",
            10035 => "WSAEWOULDBLOCK",
            10042 => "WSAENOPROTOOPT",
            10045 => "WSAEOPNOTSUPP",
            10048 => "WSAEADDRINUSE",
            10049 => "WSAEADDRNOTAVAIL",
            10054 => "WSAECONNRESET",
            10060 => "WSAETIMEDOUT",
            10061 => "WSAECONNREFUSED",
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

    pub fn set_int(fd: Fd, level: i32, name: i32, value: i32) -> Result<(), String> {
        let bytes = value.to_ne_bytes();
        let rc = unsafe { ws::setsockopt(fd, level, name, bytes.as_ptr(), 4) };
        if rc == 0 { Ok(()) } else { Err(error()) }
    }

    pub fn get_int(fd: Fd, level: i32, name: i32) -> Result<i32, String> {
        let mut bytes = [0u8; 4];
        let mut len = 4i32;
        let rc = unsafe { ws::getsockopt(fd, level, name, bytes.as_mut_ptr(), &mut len) };
        if rc == 0 {
            Ok(i32::from_ne_bytes(bytes))
        } else {
            Err(error())
        }
    }

    pub fn nonblocking(fd: Fd) {
        let mut on = 1u32;
        assert_eq!(unsafe { ws::ioctlsocket(fd, ws::FIONBIO, &mut on) }, 0);
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

    fn parse(buf: &[u8]) -> SocketAddr {
        let family = u16::from_ne_bytes([buf[0], buf[1]]);
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        let ip = if family == ws::AF_INET {
            IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]))
        } else {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).unwrap()))
        };
        SocketAddr::new(ip, port)
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

    pub fn listen(fd: Fd) -> Result<(), String> {
        if unsafe { ws::listen(fd, 16) } == 0 {
            Ok(())
        } else {
            Err(error())
        }
    }

    pub fn accept(fd: Fd) -> Result<Fd, String> {
        let s = unsafe { ws::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if s == ws::INVALID_SOCKET {
            Err(error())
        } else {
            Ok(s)
        }
    }

    pub fn local(fd: Fd) -> SocketAddr {
        let mut buf = [0u8; 64];
        let mut len = 64i32;
        assert_eq!(
            unsafe { ws::getsockname(fd, buf.as_mut_ptr().cast(), &mut len) },
            0
        );
        parse(&buf)
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

    pub fn recv(fd: Fd) -> Result<Vec<u8>, String> {
        let mut buf = [0u8; 64];
        let n = unsafe { ws::recv(fd, buf.as_mut_ptr(), 64, 0) };
        if n < 0 {
            return Err(error());
        }
        Ok(buf[..n as usize].to_vec())
    }

    pub fn join(fd: Fd, group: Ipv4Addr) -> Result<(), String> {
        let mut mreq = [0u8; 8];
        mreq[..4].copy_from_slice(&group.octets());
        let rc = unsafe { ws::setsockopt(fd, 0, ws::IP_ADD_MEMBERSHIP, mreq.as_ptr(), 8) };
        if rc == 0 { Ok(()) } else { Err(error()) }
    }
}

use os::Fd;

const LO4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const ANY4: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
const LO6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
const ANY6: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

/// Linux picks a member of a `SO_REUSEPORT` group by a hash keyed with a boot-time secret.
const HASHED: bool = cfg!(target_os = "linux");

fn shown(result: Result<(), String>) -> String {
    match result {
        Ok(()) => "ok".into(),
        Err(e) => e,
    }
}

fn port(fd: Fd) -> u16 {
    os::local(fd).port()
}

#[derive(Clone, Copy)]
struct Kind {
    name: &'static str,
    v6: bool,
    only: Option<bool>,
    at: IpAddr,
}

fn kinds() -> [Kind; 5] {
    let kind = |name, v6, only, at| Kind { name, v6, only, at };
    [
        kind("v4 wildcard", false, None, ANY4),
        kind("v4 loopback", false, None, LO4),
        kind("dual wildcard", true, Some(false), ANY6),
        kind("v6only wildcard", true, Some(true), ANY6),
        kind("v6 loopback", true, Some(true), LO6),
    ]
}

/// A socket of `kind` with the sharing options whose bits are set in `share`, and what setting
/// them answered.
fn open(kind: Kind, tcp: bool, share: u8) -> (Fd, String) {
    let fd = os::socket(kind.v6, tcp);
    if let Some(only) = kind.only {
        os::set_int(fd, os::IPPROTO_IPV6, os::IPV6_V6ONLY, only as i32).unwrap();
    }
    let mut set = Vec::new();
    for (bit, (name, option)) in os::SHARING.iter().enumerate() {
        if share & (1 << bit) != 0 {
            let result = shown(os::set_int(fd, os::SOL_SOCKET, *option, 1));
            set.push(format!("{name}={result}"));
        }
    }
    (fd, set.join(","))
}

/// A second bind over a first on its port, for every pair of kinds and every combination of the
/// sharing options on either socket, the first listening or not for TCP; then for TCP, whether
/// the two listen.
fn binds() -> Vec<String> {
    let mut lines = Vec::new();
    for tcp in [false, true] {
        for held in kinds() {
            for want in kinds() {
                for bits in 0..if tcp { 32 } else { 16 } {
                    let once = || second_bind(tcp, held, want, bits);
                    let (a, b) = (once(), once());
                    lines.push(if a == b { a } else { once() });
                }
            }
        }
    }
    lines
}

/// One case of [`binds`]. Another program on the host may hold the port the first socket got in
/// the other family, so [`binds`] runs a case again when two runs disagree and takes the third.
fn second_bind(tcp: bool, held: Kind, want: Kind, bits: u8) -> String {
    let t = if tcp { "tcp" } else { "udp" };
    let (held_share, want_share, listening) = (bits & 3, (bits >> 2) & 3, bits & 16 != 0);
    let (first, first_set) = open(held, tcp, held_share);
    os::bind(first, SocketAddr::new(held.at, 0)).unwrap();
    if listening {
        os::listen(first).unwrap();
    }
    let (second, second_set) = open(want, tcp, want_share);
    let bound = shown(os::bind(second, SocketAddr::new(want.at, port(first))));
    let mut line = format!(
        "{t} {} [{first_set}]{} then {} [{second_set}]: {bound}",
        held.name,
        if listening { " listening" } else { "" },
        want.name,
    );
    if tcp && bound == "ok" {
        let second_listen = shown(os::listen(second));
        line += &format!(", listen {second_listen}");
        if !listening {
            line += &format!(", first listens {}", shown(os::listen(first)));
        }
    }
    os::close(second);
    os::close(first);
    line
}

/// `count` sockets sharing `at`, each set up with `share` before its bind, with the bind results.
fn group(v6: bool, tcp: bool, at: IpAddr, count: usize, share: &[i32]) -> (Vec<Fd>, String) {
    let mut fds = Vec::new();
    let mut results = Vec::new();
    let mut port = 0;
    for _ in 0..count {
        let fd = os::socket(v6, tcp);
        for &option in share {
            os::set_int(fd, os::SOL_SOCKET, option, 1).unwrap();
        }
        results.push(shown(os::bind(fd, SocketAddr::new(at, port))));
        if port == 0 {
            port = self::port(fd);
        }
        os::nonblocking(fd);
        fds.push(fd);
    }
    (fds, results.join(","))
}

/// Which of `receivers` holds each queued datagram, by its payload.
fn drain(receivers: &[Fd]) -> HashMap<Vec<u8>, Vec<usize>> {
    let mut got: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();
    std::thread::sleep(Duration::from_millis(50));
    for (i, &fd) in receivers.iter().enumerate() {
        while let Ok(data) = os::recv(fd) {
            got.entry(data).or_default().push(i);
        }
    }
    got
}

/// Datagrams from `senders` flows, `per` each, to `to`, and which receiver took each: the exact
/// indices where the host's choice is fixed, else whether every flow kept to one receiver and how
/// many datagrams arrived once.
fn spread(receivers: &[Fd], to: SocketAddr, senders: usize, per: usize, hashed: bool) -> String {
    let flows: Vec<Fd> = (0..senders)
        .map(|_| os::socket(to.is_ipv6(), false))
        .collect();
    for round in 0..per {
        for (i, &fd) in flows.iter().enumerate() {
            os::send_to(fd, to, &[i as u8, round as u8]).unwrap();
        }
    }
    let got = drain(receivers);
    let mut per_flow = vec![Vec::new(); senders];
    let mut once = 0;
    for (data, at) in &got {
        per_flow[data[0] as usize].extend(at.iter().copied());
        once += usize::from(at.len() == 1);
    }
    for fd in flows {
        os::close(fd);
    }
    if hashed {
        let sticky = per_flow
            .iter()
            .all(|at| at.windows(2).all(|w| w[0] == w[1]));
        format!("{once} of {} once, flows sticky {sticky}", senders * per)
    } else {
        let mut at: Vec<_> = per_flow
            .iter()
            .map(|at| {
                let mut at = at.clone();
                at.sort();
                format!("{at:?}")
            })
            .collect();
        at.dedup();
        format!("{once} of {} once, to {}", senders * per, at.join(" "))
    }
}

/// Unicast datagrams to sockets sharing one address, as the group changes.
fn unicast() -> Vec<String> {
    let mut lines = Vec::new();
    for (label, share) in [("shared", os::SHARE), ("SO_REUSEADDR", &os::SHARE[..1])] {
        let hashed = HASHED && share.len() > 1;
        for (v6, at) in [(false, LO4), (false, ANY4), (true, LO6), (true, ANY6)] {
            let (mut fds, bound) = group(v6, false, at, 3, share);
            if bound.contains('E') {
                lines.push(format!("{label} {at}: {bound}"));
                for fd in fds {
                    os::close(fd);
                }
                continue;
            }
            let to = SocketAddr::new(if v6 { LO6 } else { LO4 }, port(fds[0]));
            lines.push(format!("{label} {at}: {}", spread(&fds, to, 6, 3, hashed)));
            os::close(fds.remove(2));
            lines.push(format!("  last closed: {}", spread(&fds, to, 6, 3, hashed)));
            let fd = os::socket(v6, false);
            for &option in share {
                os::set_int(fd, os::SOL_SOCKET, option, 1).unwrap();
            }
            os::bind(fd, SocketAddr::new(at, to.port())).unwrap();
            os::nonblocking(fd);
            fds.push(fd);
            lines.push(format!("  rebound: {}", spread(&fds, to, 6, 3, hashed)));
            os::close(fds.remove(0));
            lines.push(format!(
                "  first closed: {}",
                spread(&fds, to, 6, 3, hashed)
            ));
            let stranger = os::socket(v6, false);
            os::bind(stranger, SocketAddr::new(if v6 { LO6 } else { LO4 }, 0)).unwrap();
            let sender = os::socket(v6, false);
            os::bind(sender, SocketAddr::new(if v6 { LO6 } else { LO4 }, 0)).unwrap();
            let connected = shown(os::connect(fds[1], os::local(sender)));
            for i in 0..4u8 {
                os::send_to(sender, to, &[i]).unwrap();
            }
            let got = drain(&fds);
            let mut at: Vec<_> = got.values().flatten().copied().collect();
            at.sort();
            lines.push(format!("  first connected {connected}: to {at:?}"));
            os::send_to(stranger, to, b"s").unwrap();
            let got = drain(&fds);
            let at: Vec<_> = got.values().flatten().copied().collect();
            lines.push(format!(
                "  from a stranger: {} copies, to the connected {}",
                at.len(),
                at.contains(&1)
            ));
            let connected = shown(os::connect(fds[0], os::local(stranger)));
            os::send_to(sender, to, b"p").unwrap();
            os::send_to(stranger, to, b"s").unwrap();
            let got = drain(&fds);
            let mut at: Vec<_> = got
                .iter()
                .flat_map(|(data, at)| at.iter().map(move |i| format!("{}>{i}", data[0] as char)))
                .collect();
            at.sort();
            lines.push(format!("  both connected {connected}: {at:?}"));
            os::close(stranger);
            os::close(sender);
            for fd in fds {
                os::close(fd);
            }
        }
    }
    let (fds, bound) = group(false, false, LO4, 2, &[]);
    lines.push(format!("unshared: {bound}"));
    for fd in fds {
        os::close(fd);
    }
    let wildcard = os::socket(false, false);
    let specific = os::socket(false, false);
    for &fd in &[wildcard, specific] {
        for &option in os::SHARE {
            os::set_int(fd, os::SOL_SOCKET, option, 1).unwrap();
        }
    }
    os::bind(wildcard, SocketAddr::new(ANY4, 0)).unwrap();
    let bound = shown(os::bind(specific, SocketAddr::new(LO4, port(wildcard))));
    os::nonblocking(wildcard);
    os::nonblocking(specific);
    let to = SocketAddr::new(LO4, port(wildcard));
    lines.push(format!(
        "wildcard then loopback {bound}: {}",
        spread(&[wildcard, specific], to, 2, 2, HASHED)
    ));
    os::close(specific);
    os::close(wildcard);
    lines
}

/// Several members of one group sharing its port, and a socket on the port that did not join.
fn multicast() -> Vec<String> {
    let group = Ipv4Addr::new(239, 255, 42, 91);
    let mut lines = Vec::new();
    let places = [("wildcard", ANY4), ("group", IpAddr::V4(group))];
    for ((label, share), (place, at)) in [("shared", os::SHARE), ("SO_REUSEADDR", &os::SHARE[..1])]
        .into_iter()
        .flat_map(|share| places.map(|place| (share, place)))
    {
        let (fds, bound) = group_members(at, group, share);
        lines.push(format!("{label} {place}: {bound}"));
        if fds.is_empty() {
            continue;
        }
        let to = SocketAddr::new(IpAddr::V4(group), port(fds[0]));
        let tx = os::socket(false, false);
        os::send_to(tx, to, b"m").unwrap();
        let got = drain(&fds);
        let mut at: Vec<_> = got.values().flatten().copied().collect();
        at.sort();
        lines.push(format!("  group datagram to {at:?}"));
        if !at.is_empty() {
            os::send_to(tx, SocketAddr::new(LO4, to.port()), b"u").unwrap();
            let got = drain(&fds);
            let n = got.values().map(Vec::len).sum::<usize>();
            lines.push(format!("  unicast to {n}"));
        }
        os::close(tx);
        for fd in fds {
            os::close(fd);
        }
    }
    lines
}

/// Three sockets sharing a port at `at`, each set up with `share`, the first two members of
/// `group`.
fn group_members(at: IpAddr, group: Ipv4Addr, share: &[i32]) -> (Vec<Fd>, String) {
    let mut fds = Vec::new();
    let mut results = Vec::new();
    let mut port = 0;
    for i in 0..3 {
        let fd = os::socket(false, false);
        for &option in share {
            os::set_int(fd, os::SOL_SOCKET, option, 1).unwrap();
        }
        let bound = os::bind(fd, SocketAddr::new(at, port));
        results.push(shown(bound.clone()));
        if bound.is_err() {
            os::close(fd);
            for fd in fds {
                os::close(fd);
            }
            return (Vec::new(), results.join(","));
        }
        if port == 0 {
            port = self::port(fd);
        }
        if i < 2 {
            results.push(format!("join {}", shown(os::join(fd, group))));
        }
        os::nonblocking(fd);
        fds.push(fd);
    }
    (fds, results.join(","))
}

/// Which of several listeners sharing an address accepts each connection.
fn listeners() -> Vec<String> {
    let mut lines = Vec::new();
    for (v6, at) in [(false, LO4), (false, ANY4), (true, LO6), (true, ANY6)] {
        let (mut fds, bound) = group(v6, true, at, 3, os::SHARE);
        let listened: Vec<_> = fds.iter().map(|&fd| shown(os::listen(fd))).collect();
        lines.push(format!(
            "{at}: bound {bound}, listen {}",
            listened.join(",")
        ));
        if listened.iter().any(|l| l != "ok") {
            for fd in fds {
                os::close(fd);
            }
            continue;
        }
        let to = SocketAddr::new(if v6 { LO6 } else { LO4 }, port(fds[0]));
        lines.push(format!("  {}", accepts(&fds, to, 6)));
        os::close(fds.remove(2));
        lines.push(format!("  last closed: {}", accepts(&fds, to, 6)));
        os::close(fds.remove(0));
        lines.push(format!("  first closed: {}", accepts(&fds, to, 6)));
        for fd in fds {
            os::close(fd);
        }
    }
    lines
}

fn accepts(listeners: &[Fd], to: SocketAddr, count: usize) -> String {
    let clients: Vec<Fd> = (0..count)
        .map(|_| {
            let fd = os::socket(to.is_ipv6(), true);
            os::connect(fd, to).unwrap();
            fd
        })
        .collect();
    std::thread::sleep(Duration::from_millis(50));
    let mut at = Vec::new();
    for (i, &fd) in listeners.iter().enumerate() {
        while let Ok(accepted) = os::accept(fd) {
            at.push(i);
            os::close(accepted);
        }
    }
    for fd in clients {
        os::close(fd);
    }
    if HASHED {
        format!("{} of {count} accepted", at.len())
    } else {
        format!("accepted by {at:?}")
    }
}

/// The options' defaults and values read back.
fn options() -> Vec<String> {
    let mut lines = Vec::new();
    for tcp in [false, true] {
        for (name, option) in os::SHARING {
            let fd = os::socket(false, tcp);
            let default = os::get_int(fd, os::SOL_SOCKET, option);
            let set = shown(os::set_int(fd, os::SOL_SOCKET, option, 5));
            let read = os::get_int(fd, os::SOL_SOCKET, option);
            lines.push(format!(
                "{} {name}: {default:?}, set 5 {set} -> {read:?}",
                if tcp { "tcp" } else { "udp" }
            ));
            os::close(fd);
        }
        let fd = os::socket(false, tcp);
        let set: Vec<_> = os::SHARING
            .iter()
            .rev()
            .map(|(name, option)| {
                format!(
                    "{name} {}",
                    shown(os::set_int(fd, os::SOL_SOCKET, *option, 1))
                )
            })
            .collect();
        let read: Vec<_> = os::SHARING
            .iter()
            .map(|(_, option)| format!("{:?}", os::get_int(fd, os::SOL_SOCKET, *option)))
            .collect();
        lines.push(format!(
            "{} reversed: {} -> {}",
            if tcp { "tcp" } else { "udp" },
            set.join(", "),
            read.join(", ")
        ));
        os::close(fd);
    }
    lines
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
fn sharing_options_os_truth() {
    compare(options);
}

#[test]
fn shared_binds_os_truth() {
    compare(binds);
}

#[test]
fn shared_unicast_os_truth() {
    compare(unicast);
}

#[test]
fn shared_multicast_os_truth() {
    let unroutable = snare::real(|| {
        let tx = os::socket(false, false);
        let to = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 42, 91)), 9);
        let sent = os::send_to(tx, to, b"m");
        os::close(tx);
        matches!(&sent, Err(e) if e.ends_with(" 65") || e.ends_with(" 51"))
    });
    if unroutable {
        eprintln!("skipped: this host has no route for multicast");
        return;
    }
    compare(multicast);
}

#[test]
fn shared_listeners_os_truth() {
    compare(listeners);
}

/// Which of four `SO_REUSEPORT` members each of 64 flows reaches in `sim`: a datagram socket's
/// index, or for `tcp` a listener's.
#[cfg(target_os = "linux")]
fn members_by_flow(sim: Sim, tcp: bool) -> Vec<usize> {
    sim.run(move || {
        let (members, _) = group(false, tcp, LO4, 4, os::SHARE);
        if tcp {
            for &fd in &members {
                os::listen(fd).unwrap();
            }
        }
        let to = SocketAddr::new(LO4, port(members[0]));
        let mut clients = Vec::new();
        let reached = (0..64)
            .map(|_| {
                let client = os::socket(false, tcp);
                clients.push(client);
                if tcp {
                    os::connect(client, to).unwrap();
                } else {
                    for _ in 0..2 {
                        os::send_to(client, to, b"f").unwrap();
                    }
                }
                let mut at = Vec::new();
                for (i, &fd) in members.iter().enumerate() {
                    let take = || {
                        if tcp {
                            os::accept(fd).map(os::close)
                        } else {
                            os::recv(fd).map(drop)
                        }
                    };
                    while take().is_ok() {
                        at.push(i);
                    }
                }
                let once = if tcp { 1 } else { 2 };
                assert!(at.len() == once && at.windows(2).all(|w| w[0] == w[1]));
                at[0]
            })
            .collect();
        for fd in clients.into_iter().chain(members) {
            os::close(fd);
        }
        reached
    })
}

/// A Linux `SO_REUSEPORT` group picks a member per flow by a hash snare keys with the sim's seed
/// (`netif::pick_shared`): each flow keeps to one member, every member takes some of 64 flows,
/// and the same seed spreads them the same way while another seed spreads them otherwise.
#[cfg(target_os = "linux")]
#[test]
fn reuseport_groups_spread_flows_by_the_seed() {
    for tcp in [false, true] {
        let spread = |seed| members_by_flow(Sim::builder().seed(seed).build(), tcp);
        let first = spread(7);
        assert!((0..4).all(|member| first.contains(&member)), "{first:?}");
        assert_eq!(first, spread(7));
        assert_ne!(first, spread(8));
    }
}
