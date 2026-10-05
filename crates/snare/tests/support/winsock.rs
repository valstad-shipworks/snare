//! Winsock calls std has no API for, for the Windows tests: raw `setsockopt`/`getsockopt` at any
//! level, `ioctlsocket`, a synchronous `WSAIoctl`, and the `WSARecvMsg` extension function. Each
//! returns the `WSAGetLastError` code on failure.

#![cfg(windows)]
#![allow(dead_code)]

use std::ffi::c_void;
use std::os::windows::io::AsRawSocket;

use windows_sys::Win32::Networking::WinSock as ws;

pub type Raw = usize;

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSAIoctl(
        s: usize,
        code: u32,
        input: *const c_void,
        input_len: u32,
        output: *mut c_void,
        output_len: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
        routine: *mut c_void,
    ) -> i32;
    fn WSASendMsg(
        s: usize,
        msg: *const ws::WSAMSG,
        flags: u32,
        sent: *mut u32,
        overlapped: *mut c_void,
        routine: *mut c_void,
    ) -> i32;
}

/// `LPFN_WSARECVMSG`, called synchronously (no overlapped, no completion routine)
/// ([Microsoft Learn: LPFN_WSARECVMSG](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_wsarecvmsg)).
pub type WsaRecvMsg =
    unsafe extern "system" fn(usize, *mut ws::WSAMSG, *mut u32, *mut c_void, *mut c_void) -> i32;

pub fn raw(s: &impl AsRawSocket) -> Raw {
    s.as_raw_socket() as Raw
}

pub fn last_error() -> i32 {
    unsafe { ws::WSAGetLastError() }
}

pub fn set_int(s: Raw, level: i32, name: i32, value: i32) -> Result<(), i32> {
    let rc = unsafe { ws::setsockopt(s, level, name, (&raw const value).cast(), 4) };
    if rc == 0 { Ok(()) } else { Err(last_error()) }
}

/// Reads an option into a 4-byte buffer: its value and the length Winsock wrote.
pub fn get_int(s: Raw, level: i32, name: i32) -> Result<(i32, i32), i32> {
    let mut v = 0i32;
    let mut len = 4i32;
    let rc = unsafe { ws::getsockopt(s, level, name, (&raw mut v).cast(), &mut len) };
    if rc == 0 {
        Ok((v, len))
    } else {
        Err(last_error())
    }
}

/// Reads an option's value alone, the length aside.
pub fn get(s: Raw, level: i32, name: i32) -> Result<i32, i32> {
    get_int(s, level, name).map(|(v, _)| v)
}

pub fn ioctlsocket(s: Raw, cmd: u32, arg: &mut u32) -> Result<(), i32> {
    let rc = unsafe { ws::ioctlsocket(s, cmd as i32, arg) };
    if rc == 0 { Ok(()) } else { Err(last_error()) }
}

/// A synchronous `WSAIoctl`: the bytes returned, or the error.
pub fn wsa_ioctl(s: Raw, code: u32, input: &[u8], output: &mut [u8]) -> Result<u32, i32> {
    let mut returned = 0u32;
    let rc = unsafe {
        WSAIoctl(
            s,
            code,
            if input.is_empty() {
                std::ptr::null()
            } else {
                input.as_ptr().cast()
            },
            input.len() as u32,
            if output.is_empty() {
                std::ptr::null_mut()
            } else {
                output.as_mut_ptr().cast()
            },
            output.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc == 0 {
        Ok(returned)
    } else {
        Err(last_error())
    }
}

/// `WSARecvMsg` for `s`, fetched with `SIO_GET_EXTENSION_FUNCTION_POINTER` as Microsoft documents
/// ([Microsoft Learn: LPFN_WSARECVMSG](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_wsarecvmsg)).
pub fn wsa_recv_msg_fn(s: Raw) -> Result<WsaRecvMsg, i32> {
    let guid = ws::WSAID_WSARECVMSG;
    let guid_bytes =
        unsafe { std::slice::from_raw_parts((&raw const guid).cast::<u8>(), size_of_val(&guid)) };
    let mut out = [0u8; size_of::<usize>()];
    wsa_ioctl(
        s,
        ws::SIO_GET_EXTENSION_FUNCTION_POINTER,
        guid_bytes,
        &mut out,
    )?;
    let ptr = usize::from_ne_bytes(out);
    assert_ne!(ptr, 0, "WSARecvMsg pointer");
    Ok(unsafe { std::mem::transmute::<usize, WsaRecvMsg>(ptr) })
}

/// One `WSARecvMsg` into `data` with a `control` buffer: the bytes read, the control bytes
/// written and the message flags.
pub fn recv_msg(s: Raw, data: &mut [u8], control: &mut [u8]) -> Result<(u32, u32, u32), i32> {
    let recv = wsa_recv_msg_fn(s)?;
    let mut buf = ws::WSABUF {
        len: data.len() as u32,
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
            buf: control.as_mut_ptr(),
        },
        dwFlags: 0,
    };
    let mut got = 0u32;
    let rc = unsafe {
        recv(
            s,
            &mut msg,
            &mut got,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc == 0 {
        Ok((got, msg.Control.len, msg.dwFlags))
    } else {
        Err(last_error())
    }
}

/// The control messages in the first `len` bytes of `control`: level, type and data, walked as
/// `WSA_CMSG_FIRSTHDR`/`WSA_CMSG_NXTHDR` do (`WSACMSGHDR`, pointer-size aligned).
pub fn cmsgs(control: &[u8], len: u32) -> Vec<(i32, i32, Vec<u8>)> {
    let align = |n: usize| (n + size_of::<usize>() - 1) & !(size_of::<usize>() - 1);
    let header = size_of::<ws::CMSGHDR>();
    let mut out = Vec::new();
    let mut at = 0usize;
    let end = (len as usize).min(control.len());
    while at + header <= end {
        let h = unsafe {
            control
                .as_ptr()
                .add(at)
                .cast::<ws::CMSGHDR>()
                .read_unaligned()
        };
        if h.cmsg_len < header || at + h.cmsg_len > end {
            break;
        }
        let data = &control[at + align(header)..at + h.cmsg_len];
        out.push((h.cmsg_level, h.cmsg_type, data.to_vec()));
        at += align(h.cmsg_len);
    }
    out
}

/// One synchronous `WSASendMsg` of `data` to `to` with a `control` buffer: the bytes sent
/// ([Microsoft Learn: WSASendMsg](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendmsg)).
pub fn send_msg(
    s: Raw,
    data: &[u8],
    to: Option<std::net::SocketAddr>,
    control: &mut [u8],
) -> Result<u32, i32> {
    let mut buf = ws::WSABUF {
        len: data.len() as u32,
        buf: data.as_ptr().cast_mut(),
    };
    let (mut addr, addr_len) = to.map_or(([0u8; 28], 0), sockaddr);
    let msg = ws::WSAMSG {
        name: if addr_len == 0 {
            std::ptr::null_mut()
        } else {
            addr.as_mut_ptr().cast()
        },
        namelen: addr_len,
        lpBuffers: &mut buf,
        dwBufferCount: 1,
        Control: ws::WSABUF {
            len: control.len() as u32,
            buf: if control.is_empty() {
                std::ptr::null_mut()
            } else {
                control.as_mut_ptr()
            },
        },
        dwFlags: 0,
    };
    let mut sent = 0u32;
    let rc = unsafe {
        WSASendMsg(
            s,
            &msg,
            0,
            &mut sent,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc == 0 { Ok(sent) } else { Err(last_error()) }
}

/// A control buffer holding one message of `level`/`ty` carrying `data`, laid out as
/// `WSA_CMSG_LEN`/`WSA_CMSG_SPACE` do.
pub fn cmsg(level: i32, ty: i32, data: &[u8]) -> Vec<u8> {
    let align = |n: usize| (n + size_of::<usize>() - 1) & !(size_of::<usize>() - 1);
    let header = align(size_of::<ws::CMSGHDR>());
    let mut out = vec![0u8; header + align(data.len())];
    let h = ws::CMSGHDR {
        cmsg_len: header + data.len(),
        cmsg_level: level,
        cmsg_type: ty,
    };
    unsafe { out.as_mut_ptr().cast::<ws::CMSGHDR>().write_unaligned(h) };
    out[header..header + data.len()].copy_from_slice(data);
    out
}

/// `addr` as a `SOCKADDR_IN`/`SOCKADDR_IN6` in a 28-byte buffer, and its length.
pub fn sockaddr(addr: std::net::SocketAddr) -> ([u8; 28], i32) {
    let mut buf = [0u8; 28];
    match addr {
        std::net::SocketAddr::V4(v4) => {
            buf[0..2].copy_from_slice(&ws::AF_INET.to_ne_bytes());
            buf[2..4].copy_from_slice(&v4.port().to_be_bytes());
            buf[4..8].copy_from_slice(&v4.ip().octets());
            (buf, 16)
        }
        std::net::SocketAddr::V6(v6) => {
            buf[0..2].copy_from_slice(&ws::AF_INET6.to_ne_bytes());
            buf[2..4].copy_from_slice(&v6.port().to_be_bytes());
            buf[8..24].copy_from_slice(&v6.ip().octets());
            (buf, 28)
        }
    }
}

/// `QueryPerformanceCounter`, through the import the sim interposes.
pub fn qpc() -> i64 {
    let mut count = 0i64;
    unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut count) };
    count
}
