//! Socket calls and host error codes for the fault tests: options std has no API for (linger,
//! the send buffer, `IP_RECVERR`, `SIO_UDP_CONNRESET`) and a one-socket poll.

#![allow(dead_code)]

#[cfg(unix)]
pub type Raw = std::os::fd::RawFd;
#[cfg(windows)]
pub type Raw = usize;

#[cfg(unix)]
pub fn raw<S: std::os::fd::AsRawFd>(s: &S) -> Raw {
    s.as_raw_fd()
}

#[cfg(windows)]
pub fn raw<S: std::os::windows::io::AsRawSocket>(s: &S) -> Raw {
    s.as_raw_socket() as Raw
}

#[cfg(unix)]
pub mod code {
    pub const ECONNRESET: i32 = libc::ECONNRESET;
    pub const ECONNABORTED: i32 = libc::ECONNABORTED;
    pub const ECONNREFUSED: i32 = libc::ECONNREFUSED;
    pub const ETIMEDOUT: i32 = libc::ETIMEDOUT;
    pub const EPIPE: i32 = libc::EPIPE;
    pub const ENOTCONN: i32 = libc::ENOTCONN;
    pub const ENETUNREACH: i32 = libc::ENETUNREACH;
    pub const EHOSTUNREACH: i32 = libc::EHOSTUNREACH;
    pub const ENETDOWN: i32 = libc::ENETDOWN;
    pub const EADDRNOTAVAIL: i32 = libc::EADDRNOTAVAIL;
    /// What an ICMP port unreachable fails a datagram socket's call with.
    pub const ICMP: i32 = libc::ECONNREFUSED;
}

#[cfg(windows)]
pub mod code {
    pub const ECONNRESET: i32 = 10054;
    pub const ECONNABORTED: i32 = 10053;
    pub const ECONNREFUSED: i32 = 10061;
    pub const ETIMEDOUT: i32 = 10060;
    pub const EPIPE: i32 = 10058;
    pub const ENOTCONN: i32 = 10057;
    pub const ENETUNREACH: i32 = 10051;
    pub const EHOSTUNREACH: i32 = 10065;
    pub const ENETDOWN: i32 = 10050;
    pub const EADDRNOTAVAIL: i32 = 10049;
    pub const ICMP: i32 = 10054;
}

pub fn errno(e: std::io::Error) -> i32 {
    e.raw_os_error()
        .unwrap_or_else(|| panic!("not an OS error: {e:?}"))
}

/// Turns `SO_LINGER` on with `secs`, through `SO_LINGER_SEC` on macOS as std and socket2 do.
#[cfg(unix)]
pub fn set_linger(s: Raw, secs: i32) {
    #[cfg(target_os = "macos")]
    const NAME: i32 = 0x1080;
    #[cfg(not(target_os = "macos"))]
    const NAME: i32 = libc::SO_LINGER;
    let l = libc::linger {
        l_onoff: 1,
        l_linger: secs,
    };
    let rc = unsafe {
        libc::setsockopt(
            s,
            libc::SOL_SOCKET,
            NAME,
            (&l as *const libc::linger).cast(),
            size_of::<libc::linger>() as u32,
        )
    };
    assert_eq!(rc, 0, "setsockopt SO_LINGER");
}

#[cfg(windows)]
pub fn set_linger(s: Raw, secs: u16) {
    use windows_sys::Win32::Networking::WinSock::{LINGER, SO_LINGER, SOL_SOCKET, setsockopt};
    let l = LINGER {
        l_onoff: 1,
        l_linger: secs,
    };
    let rc = unsafe {
        setsockopt(
            s,
            SOL_SOCKET,
            SO_LINGER,
            (&l as *const LINGER).cast(),
            size_of::<LINGER>() as i32,
        )
    };
    assert_eq!(rc, 0, "setsockopt SO_LINGER");
}

/// `SO_SNDBUF` as getsockopt reports it.
#[cfg(unix)]
pub fn sndbuf(s: Raw) -> usize {
    let mut v: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            s,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0, "getsockopt SO_SNDBUF");
    v as usize
}

#[cfg(windows)]
pub fn sndbuf(s: Raw) -> usize {
    use windows_sys::Win32::Networking::WinSock::{SO_SNDBUF, SOL_SOCKET, getsockopt};
    let mut v: i32 = 0;
    let mut len = size_of::<i32>() as i32;
    let rc = unsafe {
        getsockopt(
            s,
            SOL_SOCKET,
            SO_SNDBUF,
            (&mut v as *mut i32).cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0, "getsockopt SO_SNDBUF");
    v as usize
}

/// Sets `SO_RCVBUF` (`rcv`) or `SO_SNDBUF` to `v`.
#[cfg(unix)]
pub fn set_buf(s: Raw, rcv: bool, v: i32) {
    let name = if rcv {
        libc::SO_RCVBUF
    } else {
        libc::SO_SNDBUF
    };
    let rc = unsafe {
        libc::setsockopt(
            s,
            libc::SOL_SOCKET,
            name,
            (&v as *const i32).cast(),
            size_of::<i32>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "setsockopt buffer");
}

#[cfg(windows)]
pub fn set_buf(s: Raw, rcv: bool, v: i32) {
    use windows_sys::Win32::Networking::WinSock::{SO_RCVBUF, SO_SNDBUF, SOL_SOCKET, setsockopt};
    let name = if rcv { SO_RCVBUF } else { SO_SNDBUF };
    let rc = unsafe { setsockopt(s, SOL_SOCKET, name, (&v as *const i32).cast(), 4) };
    assert_eq!(rc, 0, "setsockopt buffer");
}

/// `SO_RCVBUF` as getsockopt reports it.
#[cfg(unix)]
pub fn rcvbuf(s: Raw) -> usize {
    let mut v: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            s,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0, "getsockopt SO_RCVBUF");
    v as usize
}

#[cfg(windows)]
pub fn rcvbuf(s: Raw) -> usize {
    use windows_sys::Win32::Networking::WinSock::{SO_RCVBUF, SOL_SOCKET, getsockopt};
    let mut v: i32 = 0;
    let mut len = size_of::<i32>() as i32;
    let rc = unsafe {
        getsockopt(
            s,
            SOL_SOCKET,
            SO_RCVBUF,
            (&mut v as *mut i32).cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0, "getsockopt SO_RCVBUF");
    v as usize
}

pub struct Ready {
    pub readable: bool,
    pub writable: bool,
    pub error: bool,
}

/// Polls one socket for reading and writing, waiting up to `timeout_ms` (-1 forever).
#[cfg(unix)]
pub fn poll(s: Raw, read: bool, write: bool, timeout_ms: i32) -> Ready {
    let mut events = 0;
    if read {
        events |= libc::POLLIN;
    }
    if write {
        events |= libc::POLLOUT;
    }
    let mut pfd = libc::pollfd {
        fd: s,
        events,
        revents: 0,
    };
    let n = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    assert!(n >= 0, "poll");
    Ready {
        readable: pfd.revents & libc::POLLIN != 0,
        writable: pfd.revents & libc::POLLOUT != 0,
        error: pfd.revents & libc::POLLERR != 0,
    }
}

#[cfg(windows)]
pub fn poll(s: Raw, read: bool, write: bool, timeout_ms: i32) -> Ready {
    use windows_sys::Win32::Networking::WinSock::{
        POLLERR, POLLRDNORM, POLLWRNORM, WSAPOLLFD, WSAPoll,
    };
    let mut events = 0;
    if read {
        events |= POLLRDNORM;
    }
    if write {
        events |= POLLWRNORM;
    }
    let mut pfd = WSAPOLLFD {
        fd: s,
        events,
        revents: 0,
    };
    let n = unsafe { WSAPoll(&mut pfd, 1, timeout_ms) };
    assert!(n >= 0, "WSAPoll");
    Ready {
        readable: pfd.revents & POLLRDNORM != 0,
        writable: pfd.revents & POLLWRNORM != 0,
        error: pfd.revents & POLLERR != 0,
    }
}

/// Linux `IP_RECVERR`.
#[cfg(target_os = "linux")]
pub fn set_recverr(s: Raw) {
    let on: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            s,
            libc::IPPROTO_IP,
            libc::IP_RECVERR,
            (&on as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as u32,
        )
    };
    assert_eq!(rc, 0, "setsockopt IP_RECVERR");
}

/// Windows `SIO_UDP_CONNRESET`.
#[cfg(windows)]
pub fn set_connreset(s: Raw, on: bool) {
    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn WSAIoctl(
            s: usize,
            code: u32,
            input: *const std::ffi::c_void,
            input_len: u32,
            output: *mut std::ffi::c_void,
            output_len: u32,
            returned: *mut u32,
            overlapped: *mut std::ffi::c_void,
            routine: *mut std::ffi::c_void,
        ) -> i32;
    }
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
    let value: i32 = on as i32;
    let mut returned = 0u32;
    let rc = unsafe {
        WSAIoctl(
            s,
            SIO_UDP_CONNRESET,
            (&value as *const i32).cast(),
            size_of::<i32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "WSAIoctl SIO_UDP_CONNRESET");
}
