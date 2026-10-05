//! Parity with the machine the tests run on: the same socket-buffer calls, datagram floods and
//! reserved-port binds made against the real OS and inside a sim built from
//! `SysLimits::from_real_host`, compared result for result.

use std::net::UdpSocket;
use std::time::Duration;

use snare::{Sim, SysLimits};

#[cfg(unix)]
mod os {
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    pub const RCVBUF: i32 = libc::SO_RCVBUF;
    pub const SNDBUF: i32 = libc::SO_SNDBUF;

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    }

    pub fn set(s: &UdpSocket, name: i32, v: i32) -> Result<(), i32> {
        let rc = unsafe {
            libc::setsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                name,
                (&v as *const i32).cast(),
                4,
            )
        };
        if rc == 0 { Ok(()) } else { Err(errno()) }
    }

    pub fn get(s: &UdpSocket, name: i32) -> Result<i32, i32> {
        let mut v = 0i32;
        let mut len = 4u32;
        let rc = unsafe {
            libc::getsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                name,
                (&mut v as *mut i32).cast(),
                &mut len,
            )
        };
        if rc == 0 { Ok(v) } else { Err(errno()) }
    }

    pub fn elevated() -> bool {
        unsafe { libc::geteuid() == 0 }
    }
}

#[cfg(windows)]
mod os {
    use std::net::UdpSocket;
    use std::os::windows::io::AsRawSocket;

    use windows_sys::Win32::Networking::WinSock::{
        SOL_SOCKET, WSAGetLastError, getsockopt, setsockopt,
    };

    pub use windows_sys::Win32::Networking::WinSock::{SO_RCVBUF as RCVBUF, SO_SNDBUF as SNDBUF};

    pub fn set(s: &UdpSocket, name: i32, v: i32) -> Result<(), i32> {
        let raw = s.as_raw_socket() as usize;
        let rc = unsafe { setsockopt(raw, SOL_SOCKET, name, (&v as *const i32).cast(), 4) };
        if rc == 0 {
            Ok(())
        } else {
            Err(unsafe { WSAGetLastError() })
        }
    }

    pub fn get(s: &UdpSocket, name: i32) -> Result<i32, i32> {
        let mut v = 0i32;
        let mut len = 4i32;
        let raw = s.as_raw_socket() as usize;
        let rc =
            unsafe { getsockopt(raw, SOL_SOCKET, name, (&mut v as *mut i32).cast(), &mut len) };
        if rc == 0 {
            Ok(v)
        } else {
            Err(unsafe { WSAGetLastError() })
        }
    }
}

/// Makes the process's first real UDP socket on its own. On Windows, the first UDP sockets of a
/// process created concurrently can read back `SO_RCVBUF` as 0 (measured on Windows 11 ARM64, native
/// and x64-emulated, about one process in six with four racing threads); a socket created alone
/// first prevents it, so this runs before either test's real measurements.
fn first_socket_alone() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| snare::real(|| drop(UdpSocket::bind("127.0.0.1:0").unwrap())));
}

fn host_sim() -> Sim {
    Sim::builder()
        .sys_limits(SysLimits::from_real_host().unwrap())
        .build()
}

/// What setting each buffer size reads back as, or the error it fails with, starting from the
/// defaults of a fresh UDP socket.
fn sockbuf_semantics() -> Vec<(i32, i32, Result<i32, i32>)> {
    let mut out = Vec::new();
    for name in [os::RCVBUF, os::SNDBUF] {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        out.push((name, i32::MIN, os::get(&s, name)));
        for v in [-1, 0, 1, 1000, 5000, 100_000, 10_000_000, i32::MAX] {
            let got = os::set(&s, name, v).and_then(|()| os::get(&s, name));
            out.push((name, v, got));
        }
    }
    out
}

#[test]
fn sockbuf_semantics_match_real_os() {
    first_socket_alone();
    let real = snare::real(sockbuf_semantics);
    let sim = host_sim().run(sockbuf_semantics);
    assert_eq!(sim, real);
}

/// How many of `count` `len`-byte datagrams a socket with `SO_RCVBUF` `rcvbuf` holds when nothing
/// reads it.
fn admitted(rcvbuf: i32, len: usize, count: usize) -> usize {
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    os::set(&rx, os::RCVBUF, rcvbuf).unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let to = rx.local_addr().unwrap();
    let payload = vec![0u8; len];
    for _ in 0..count {
        tx.send_to(&payload, to).unwrap();
    }
    // macOS loopback delivers on another thread: give it time to land everything.
    std::thread::sleep(Duration::from_millis(30));
    rx.set_nonblocking(true).unwrap();
    let mut n = 0;
    let mut buf = vec![0u8; 2048];
    while rx.recv(&mut buf).is_ok() {
        n += 1;
    }
    n
}

#[test]
fn overflow_counts_match_real_os() {
    let cases: Vec<(i32, usize)> = [2000, 8000]
        .into_iter()
        .flat_map(|r| [1, 10, 100, 200, 500, 1000, 1472].map(|s| (r, s)))
        .collect();
    let count = 120;
    first_socket_alone();
    let real: Vec<usize> =
        snare::real(|| cases.iter().map(|&(r, s)| admitted(r, s, count)).collect());
    let sim: Vec<usize> =
        host_sim().run(|| cases.iter().map(|&(r, s)| admitted(r, s, count)).collect());
    for (i, (r, s)) in cases.iter().enumerate() {
        assert_eq!(
            sim[i], real[i],
            "SO_RCVBUF {r}, {s}-byte datagrams: sim admits {} of {count}, the OS {}",
            sim[i], real[i]
        );
    }
}

#[cfg(unix)]
#[test]
fn privileged_port_matches_real_os() {
    if snare::real(os::elevated) {
        return;
    }
    let binds = || {
        ["127.0.0.1:999", "0.0.0.0:999", "127.0.0.1:1024"].map(|addr| {
            UdpSocket::bind(addr)
                .map(drop)
                .map_err(|e| e.raw_os_error())
        })
    };
    let in_use = |r: &[Result<(), Option<i32>>; 3]| r.contains(&Err(Some(libc::EADDRINUSE)));
    let real = snare::real(|| {
        let mut real = binds();
        for _ in 0..200 {
            if !in_use(&real) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
            real = binds();
        }
        real
    });
    if in_use(&real) {
        return;
    }
    let sim = Sim::builder()
        .sys_limits(SysLimits::from_real_host().unwrap())
        .privileges(snare::Privileges::none())
        .build()
        .run(binds);
    assert_eq!(sim, real);
}
