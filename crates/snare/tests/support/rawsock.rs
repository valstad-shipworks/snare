//! Raw TCP socket calls for tests that need the steps std folds together (socket, setsockopt,
//! bind and listen one at a time) or options std has no API for.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::Duration;

#[cfg(unix)]
pub type Raw = std::os::fd::RawFd;
#[cfg(windows)]
pub type Raw = usize;

#[cfg(unix)]
mod os {
    use super::*;

    pub fn last_error() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    pub fn tcp_socket(v6: bool) -> Raw {
        let family = if v6 { libc::AF_INET6 } else { libc::AF_INET };
        let fd = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0, "socket: {}", last_error());
        fd
    }

    pub fn set_int(raw: Raw, name: i32, value: i32) {
        let rc = unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                name,
                (&value as *const i32).cast(),
                size_of::<i32>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "setsockopt: {}", last_error());
    }

    pub fn set_reuseaddr(raw: Raw, on: bool) {
        set_int(raw, libc::SO_REUSEADDR, on as i32);
    }

    pub fn set_rcvtimeo(raw: Raw, d: Duration) {
        let tv = libc::timeval {
            tv_sec: d.as_secs() as libc::time_t,
            tv_usec: d.subsec_micros() as libc::suseconds_t,
        };
        let rc = unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&tv as *const libc::timeval).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "setsockopt: {}", last_error());
    }

    fn sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let len = match addr {
            SocketAddr::V4(v4) => {
                let sa = (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>();
                unsafe {
                    (*sa).sin_family = libc::AF_INET as libc::sa_family_t;
                    (*sa).sin_port = v4.port().to_be();
                    (*sa).sin_addr.s_addr = u32::from(*v4.ip()).to_be();
                }
                size_of::<libc::sockaddr_in>()
            }
            SocketAddr::V6(v6) => {
                let sa = (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>();
                unsafe {
                    (*sa).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    (*sa).sin6_port = v6.port().to_be();
                    (*sa).sin6_addr.s6_addr = v6.ip().octets();
                }
                size_of::<libc::sockaddr_in6>()
            }
        };
        (storage, len as libc::socklen_t)
    }

    pub fn bind(raw: Raw, addr: SocketAddr) -> Result<(), i32> {
        let (sa, len) = sockaddr(addr);
        let rc = unsafe { libc::bind(raw, (&sa as *const libc::sockaddr_storage).cast(), len) };
        if rc == 0 { Ok(()) } else { Err(last_error()) }
    }

    pub fn listen(raw: Raw) {
        assert_eq!(
            unsafe { libc::listen(raw, 16) },
            0,
            "listen: {}",
            last_error()
        );
    }

    pub fn local_port(raw: Raw) -> u16 {
        let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockname(
                raw,
                (&mut sa as *mut libc::sockaddr_storage).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockname: {}", last_error());
        let sin = (&sa as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>();
        u16::from_be(unsafe { (*sin).sin_port })
    }

    pub fn accept(raw: Raw) -> Result<Raw, i32> {
        let fd = unsafe { libc::accept(raw, std::ptr::null_mut(), std::ptr::null_mut()) };
        if fd >= 0 { Ok(fd) } else { Err(last_error()) }
    }

    pub fn shutdown(raw: Raw, how: i32) -> Result<(), i32> {
        if unsafe { libc::shutdown(raw, how) } == 0 {
            Ok(())
        } else {
            Err(last_error())
        }
    }

    pub fn close(raw: Raw) {
        unsafe { libc::close(raw) };
    }
}

#[cfg(windows)]
mod os {
    use super::*;
    use windows_sys::Win32::Networking::WinSock as ws;

    pub fn last_error() -> i32 {
        unsafe { ws::WSAGetLastError() }
    }

    pub fn tcp_socket(v6: bool) -> Raw {
        let _ = std::net::UdpSocket::bind("127.0.0.1:0");
        let family = if v6 { ws::AF_INET6 } else { ws::AF_INET };
        let s = unsafe { ws::socket(family as i32, ws::SOCK_STREAM, 0) };
        assert_ne!(s, ws::INVALID_SOCKET, "socket: {}", last_error());
        s
    }

    pub fn set_int(raw: Raw, name: i32, value: i32) {
        let rc =
            unsafe { ws::setsockopt(raw, ws::SOL_SOCKET, name, (&value as *const i32).cast(), 4) };
        assert_eq!(rc, 0, "setsockopt: {}", last_error());
    }

    pub fn set_reuseaddr(raw: Raw, on: bool) {
        set_int(raw, ws::SO_REUSEADDR, on as i32);
    }

    pub fn set_rcvtimeo(raw: Raw, d: Duration) {
        set_int(raw, ws::SO_RCVTIMEO, d.as_millis() as i32);
    }

    fn sockaddr(addr: SocketAddr) -> ([u8; 28], i32) {
        let mut buf = [0u8; 28];
        match addr {
            SocketAddr::V4(v4) => {
                buf[0..2].copy_from_slice(&(ws::AF_INET).to_ne_bytes());
                buf[2..4].copy_from_slice(&v4.port().to_be_bytes());
                buf[4..8].copy_from_slice(&v4.ip().octets());
                (buf, 16)
            }
            SocketAddr::V6(v6) => {
                buf[0..2].copy_from_slice(&(ws::AF_INET6).to_ne_bytes());
                buf[2..4].copy_from_slice(&v6.port().to_be_bytes());
                buf[8..24].copy_from_slice(&v6.ip().octets());
                (buf, 28)
            }
        }
    }

    pub fn bind(raw: Raw, addr: SocketAddr) -> Result<(), i32> {
        let (sa, len) = sockaddr(addr);
        let rc = unsafe { ws::bind(raw, sa.as_ptr().cast(), len) };
        if rc == 0 { Ok(()) } else { Err(last_error()) }
    }

    pub fn listen(raw: Raw) {
        assert_eq!(
            unsafe { ws::listen(raw, 16) },
            0,
            "listen: {}",
            last_error()
        );
    }

    pub fn local_port(raw: Raw) -> u16 {
        let mut sa = [0u8; 28];
        let mut len = 28i32;
        let rc = unsafe { ws::getsockname(raw, sa.as_mut_ptr().cast(), &mut len) };
        assert_eq!(rc, 0, "getsockname: {}", last_error());
        u16::from_be_bytes([sa[2], sa[3]])
    }

    pub fn accept(raw: Raw) -> Result<Raw, i32> {
        let s = unsafe { ws::accept(raw, std::ptr::null_mut(), std::ptr::null_mut()) };
        if s != ws::INVALID_SOCKET {
            Ok(s)
        } else {
            Err(last_error())
        }
    }

    pub fn shutdown(raw: Raw, how: i32) -> Result<(), i32> {
        if unsafe { ws::shutdown(raw, how) } == 0 {
            Ok(())
        } else {
            Err(last_error())
        }
    }

    pub fn close(raw: Raw) {
        unsafe { ws::closesocket(raw) };
    }
}

pub use os::*;
