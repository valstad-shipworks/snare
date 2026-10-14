//! A UDP socket bound with `SO_REUSEADDR` set first, as a program sets it to bind a wildcard and a
//! specific address of one port side by side, which Linux refuses unless both sockets set it and
//! macOS unless the second does. std's `UdpSocket::bind` has no way to set it before binding.

#![allow(dead_code)]

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};

/// A UDP socket with `SO_REUSEADDR` on, bound to `addr`.
pub fn udp_reuse(addr: impl ToSocketAddrs) -> std::io::Result<UdpSocket> {
    let addr = addr.to_socket_addrs()?.next().expect("an address");
    os::bound(addr)
}

#[cfg(unix)]
mod os {
    use std::os::fd::FromRawFd;

    use super::*;

    pub fn bound(addr: SocketAddr) -> std::io::Result<UdpSocket> {
        let family = if addr.is_ipv6() {
            libc::AF_INET6
        } else {
            libc::AF_INET
        };
        let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let socket = unsafe { UdpSocket::from_raw_fd(fd) };
        let on = 1i32;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                (&raw const on).cast(),
                size_of::<i32>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let len = match addr {
            SocketAddr::V4(v4) => {
                let sin = (&raw mut storage).cast::<libc::sockaddr_in>();
                unsafe {
                    #[cfg(target_os = "macos")]
                    {
                        (*sin).sin_len = size_of::<libc::sockaddr_in>() as u8;
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
                        (*sin6).sin6_len = size_of::<libc::sockaddr_in6>() as u8;
                    }
                    (*sin6).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    (*sin6).sin6_port = v6.port().to_be();
                    (*sin6).sin6_addr.s6_addr = v6.ip().octets();
                }
                size_of::<libc::sockaddr_in6>()
            }
        };
        let rc = unsafe { libc::bind(fd, (&raw const storage).cast(), len as libc::socklen_t) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(socket)
    }
}

#[cfg(windows)]
mod os {
    use std::os::windows::io::FromRawSocket;

    use windows_sys::Win32::Networking::WinSock as ws;

    use super::*;

    fn last() -> std::io::Error {
        std::io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() })
    }

    pub fn bound(addr: SocketAddr) -> std::io::Result<UdpSocket> {
        let mut data = unsafe { std::mem::zeroed::<ws::WSADATA>() };
        unsafe { ws::WSAStartup(0x0202, &mut data) };
        let family = if addr.is_ipv6() {
            ws::AF_INET6
        } else {
            ws::AF_INET
        };
        let s = unsafe { ws::socket(family as i32, ws::SOCK_DGRAM, 0) };
        if s == ws::INVALID_SOCKET {
            return Err(last());
        }
        let socket = unsafe { UdpSocket::from_raw_socket(s as u64) };
        let on = 1i32.to_ne_bytes();
        if unsafe { ws::setsockopt(s, ws::SOL_SOCKET, ws::SO_REUSEADDR, on.as_ptr(), 4) } != 0 {
            return Err(last());
        }
        let mut buf = [0u8; 28];
        let len = match addr {
            SocketAddr::V4(v4) => {
                buf[0..2].copy_from_slice(&ws::AF_INET.to_ne_bytes());
                buf[2..4].copy_from_slice(&v4.port().to_be_bytes());
                buf[4..8].copy_from_slice(&v4.ip().octets());
                16
            }
            SocketAddr::V6(v6) => {
                buf[0..2].copy_from_slice(&ws::AF_INET6.to_ne_bytes());
                buf[2..4].copy_from_slice(&v6.port().to_be_bytes());
                buf[8..24].copy_from_slice(&v6.ip().octets());
                28
            }
        };
        if unsafe { ws::bind(s, buf.as_ptr().cast(), len) } != 0 {
            return Err(last());
        }
        Ok(socket)
    }
}
