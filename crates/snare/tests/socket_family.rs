#![cfg(any(target_os = "linux", windows))]
//! What a socket says it is. Linux `SO_DOMAIN` and `SO_PROTOCOL` report the family and the
//! protocol the kernel resolved (`IPPROTO_UDP` for a datagram socket opened with 0; 0 for packet
//! and unix sockets whatever they were opened with; a netlink socket's own protocol), are
//! read-only (`ENOPROTOOPT`), and an accepted socket takes its listener's. Windows
//! `SO_PROTOCOL_INFOW`/`SO_PROTOCOL_INFOA` return the host's Winsock catalog entry for the
//! socket. macOS has neither. The `*_os_truth` tests compare the sim with the real stack.

#[cfg(windows)]
#[path = "support/winsock.rs"]
mod winsock;

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::os::fd::AsRawFd;

    use snare::{HostProfile, Privileges, Sim};

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    }

    /// `SO_TYPE`, `SO_DOMAIN` and `SO_PROTOCOL` read into 4-, 2- and 8-byte buffers, and set.
    fn ident(fd: i32) -> Vec<String> {
        let read = |name: i32, cap: u32| {
            let mut v = [0xa5u8; 8];
            let mut len = cap;
            let rc = unsafe {
                libc::getsockopt(fd, libc::SOL_SOCKET, name, v.as_mut_ptr().cast(), &mut len)
            };
            if rc == 0 {
                format!("{:?} len {len}", &v[..cap as usize])
            } else {
                format!("errno {}", errno())
            }
        };
        let set = |name: i32| {
            let v = 2i32;
            let rc =
                unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, name, (&raw const v).cast(), 4) };
            if rc == 0 { 0 } else { errno() }
        };
        [libc::SO_TYPE, libc::SO_DOMAIN, libc::SO_PROTOCOL]
            .into_iter()
            .flat_map(|name| {
                [
                    format!("{name} {}", read(name, 4)),
                    format!("{name} short {}", read(name, 2)),
                    format!("{name} long {}", read(name, 8)),
                    format!("{name} set {}", set(name)),
                ]
            })
            .collect()
    }

    fn opened(domain: i32, ty: i32, protocol: i32) -> Vec<String> {
        let fd = unsafe { libc::socket(domain, ty, protocol) };
        if fd < 0 {
            return vec![format!(
                "socket({domain}, {ty}, {protocol}) errno {}",
                errno()
            )];
        }
        let mut out = vec![format!("socket({domain}, {ty}, {protocol})")];
        out.extend(ident(fd));
        unsafe { libc::close(fd) };
        out
    }

    fn pair(ty: i32, protocol: i32) -> Vec<String> {
        let mut fds = [0; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, ty, protocol, fds.as_mut_ptr()) },
            0
        );
        let mut out = vec![format!("socketpair({ty}, {protocol})")];
        out.extend(ident(fds[1]));
        unsafe { libc::close(fds[0]) };
        unsafe { libc::close(fds[1]) };
        out
    }

    fn probe() -> Vec<String> {
        let all = (libc::ETH_P_ALL as u16).to_be() as i32;
        let mut out = Vec::new();
        out.extend(opened(libc::AF_INET, libc::SOCK_DGRAM, 0));
        out.extend(opened(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP));
        out.extend(opened(libc::AF_INET6, libc::SOCK_DGRAM, 0));
        out.extend(opened(libc::AF_INET, libc::SOCK_STREAM, 0));
        out.extend(opened(libc::AF_INET6, libc::SOCK_STREAM, libc::IPPROTO_TCP));
        out.extend(opened(libc::AF_PACKET, libc::SOCK_RAW, all));
        out.extend(opened(libc::AF_PACKET, libc::SOCK_DGRAM, 0));
        out.extend(pair(libc::SOCK_STREAM, 0));
        out.extend(pair(libc::SOCK_DGRAM, libc::PF_UNIX));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        out.push("accepted".into());
        out.extend(ident(accepted.as_raw_fd()));
        out
    }

    #[test]
    fn socket_family_os_truth() {
        let real = snare::real(probe);
        let simulated = Sim::builder()
            .privileges(Privileges::from_real_process().unwrap())
            .strict_sockopts()
            .build()
            .run(probe);
        assert_eq!(simulated, real);
    }

    fn read(fd: i32, name: i32) -> Result<i32, i32> {
        let mut v = 0i32;
        let mut len = 4u32;
        let rc =
            unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, name, (&raw mut v).cast(), &mut len) };
        if rc == 0 { Ok(v) } else { Err(errno()) }
    }

    /// A `SimHost`'s datagram and netlink sockets, which the real stack's own netlink would
    /// answer for the real host.
    #[test]
    fn simhost_sockets_report_their_family() {
        Sim::builder()
            .host(HostProfile::new().build())
            .strict_sockopts()
            .build()
            .run(|| {
                let udp = UdpSocket::bind("[::1]:0").unwrap();
                let fd = udp.as_raw_fd();
                assert_eq!(read(fd, libc::SO_DOMAIN), Ok(libc::AF_INET6));
                assert_eq!(read(fd, libc::SO_PROTOCOL), Ok(libc::IPPROTO_UDP));
                for (ty, protocol) in [
                    (libc::SOCK_RAW, libc::NETLINK_ROUTE),
                    (libc::SOCK_DGRAM, libc::NETLINK_GENERIC),
                ] {
                    let nl = unsafe { libc::socket(libc::AF_NETLINK, ty, protocol) };
                    assert!(nl >= 0);
                    assert_eq!(read(nl, libc::SO_TYPE), Ok(ty));
                    assert_eq!(read(nl, libc::SO_DOMAIN), Ok(libc::AF_NETLINK));
                    assert_eq!(read(nl, libc::SO_PROTOCOL), Ok(protocol));
                    assert_eq!(read(nl, libc::SO_ERROR), Ok(0));
                    unsafe { libc::close(nl) };
                }
                assert_eq!(read(fd, libc::SO_TYPE), Ok(libc::SOCK_DGRAM));
                let stream = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_STREAM, 0) };
                assert_eq!((stream, errno()), (-1, libc::ESOCKTNOSUPPORT));
            });
    }

    /// Options a `SimHost`'s netlink socket does not model read back what was set, as on a
    /// UDP socket.
    #[test]
    fn simhost_netlink_options_read_back() {
        const SOL_NETLINK: i32 = 270;
        const NETLINK_EXT_ACK: i32 = 11;
        Sim::builder()
            .host(HostProfile::new().build())
            .build()
            .run(|| {
                let nl = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, 0) };
                assert!(nl >= 0);
                let on = 1i32;
                let rc = unsafe {
                    libc::setsockopt(nl, SOL_NETLINK, NETLINK_EXT_ACK, (&raw const on).cast(), 4)
                };
                assert_eq!(rc, 0, "errno {}", errno());
                let mut v = 0i32;
                let mut len = 4u32;
                let rc = unsafe {
                    libc::getsockopt(
                        nl,
                        SOL_NETLINK,
                        NETLINK_EXT_ACK,
                        (&raw mut v).cast(),
                        &mut len,
                    )
                };
                assert_eq!((rc, v, len), (0, 1, 4));
                unsafe { libc::close(nl) };
            });
    }
}

#[cfg(windows)]
mod windows {
    use std::net::{TcpListener, TcpStream, UdpSocket};

    use snare::Sim;
    use windows_sys::Win32::Networking::WinSock as ws;

    use super::winsock::{last_error, raw};

    /// The option's bytes with a full buffer, then the error and length a 4-byte buffer gets,
    /// then the error setting it.
    fn info(s: usize, name: i32) -> Vec<String> {
        let mut full = vec![0u8; 1024];
        let mut len = full.len() as i32;
        let rc = unsafe { ws::getsockopt(s, ws::SOL_SOCKET, name, full.as_mut_ptr(), &mut len) };
        let whole = if rc == 0 {
            format!("{:?}", &full[..len as usize])
        } else {
            format!("error {}", last_error())
        };
        let mut short = [0u8; 4];
        let mut short_len = 4;
        let rc =
            unsafe { ws::getsockopt(s, ws::SOL_SOCKET, name, short.as_mut_ptr(), &mut short_len) };
        let short = format!("short {rc} {} len {short_len}", last_error());
        let rc = unsafe { ws::setsockopt(s, ws::SOL_SOCKET, name, full.as_ptr(), len) };
        let set = format!("set {rc} {}", if rc == 0 { 0 } else { last_error() });
        vec![format!("{name} len {len}: {whole}"), short, set]
    }

    fn probe() -> Vec<String> {
        let udp4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp6 = UdpSocket::bind("[::1]:0").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let listener6 = TcpListener::bind("[::1]:0").unwrap();
        let mut out = Vec::new();
        for s in [
            raw(&udp4),
            raw(&udp6),
            raw(&listener),
            raw(&tcp),
            raw(&listener6),
        ] {
            out.extend(info(s, ws::SO_PROTOCOL_INFOW));
            out.extend(info(s, ws::SO_PROTOCOL_INFOA));
        }
        out
    }

    #[test]
    fn protocol_info_os_truth() {
        let real = snare::real(probe);
        let simulated = Sim::builder().strict_sockopts().build().run(probe);
        assert_eq!(simulated, real);
    }
}
