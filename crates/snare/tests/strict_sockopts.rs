//! Socket options and ioctls the sim does not model are never silently swallowed: each is listed
//! in the socket's `unmodelled_options` and logged as `RecordedEvent::UnmodelledOption`, and under
//! `SimBuilder::strict_sockopts()` the call fails with the host's own code for an unknown option
//! (`ENOPROTOOPT`; Winsock `WSAENOPROTOOPT`, `WSAEINVAL` at `SOL_SOCKET`) or ioctl request (Linux
//! `ENOTTY`, macOS `ENXIO`). The options ignored on purpose as harmless are neither listed nor
//! refused, and read back what was set. The `*_os_truth` tests compare the strict sim with the
//! real stack.
//!
//! On Windows an unmodelled option is also read back as set, an option or `ioctlsocket` command
//! Winsock does not define fails as the host fails it with or without strict mode, and a
//! `WSAIoctl` code the sim does not carry out always fails, listed as refused.
//! `unknown_option_codes_on_windows` pins what the real Winsock answers.

use std::net::{TcpListener, TcpStream, UdpSocket};
use std::time::Duration;

use snare::{RecordedEvent, Sim, UnmodelledOption, socket_entry, socket_id};

#[path = "support/winsock.rs"]
mod winsock;

#[cfg(unix)]
mod os {
    use std::os::fd::AsRawFd;

    pub type Raw = i32;
    pub const ENOPROTOOPT: i32 = libc::ENOPROTOOPT;
    /// What an unknown option at `SOL_SOCKET` fails with.
    pub const UNKNOWN_AT_SOCKET: i32 = libc::ENOPROTOOPT;
    /// An option number no host defines at `SOL_SOCKET`.
    pub const UNKNOWN_OPTION: i32 = 0x7777;
    /// An ioctl request no socket knows.
    pub const UNKNOWN_IOCTL: u64 = 0x5fff;
    pub const SOL_SOCKET: i32 = libc::SOL_SOCKET;
    pub const IPPROTO_IP: i32 = libc::IPPROTO_IP;
    pub const IP_MULTICAST_LOOP: i32 = libc::IP_MULTICAST_LOOP;
    /// A socket-level option the sim keeps as harmless, on a datagram socket.
    pub const HARMLESS_AT_SOCKET: i32 = libc::SO_KEEPALIVE;
    /// A socket-level option the sim does not model.
    pub const UNMODELLED_AT_SOCKET: i32 = libc::SO_REUSEPORT;

    pub fn raw(s: &impl AsRawFd) -> Raw {
        s.as_raw_fd()
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    }

    pub fn set(s: Raw, level: i32, name: i32, value: i32) -> Result<(), i32> {
        let rc = unsafe { libc::setsockopt(s, level, name, (&raw const value).cast(), 4) };
        if rc == 0 { Ok(()) } else { Err(errno()) }
    }

    pub fn get(s: Raw, level: i32, name: i32) -> Result<i32, i32> {
        let mut v = 0i32;
        let mut len = 4u32;
        let rc = unsafe { libc::getsockopt(s, level, name, (&raw mut v).cast(), &mut len) };
        if rc == 0 { Ok(v) } else { Err(errno()) }
    }

    pub fn ioctl(s: Raw, request: u64) -> Result<(), i32> {
        let mut v = 0i32;
        let rc = unsafe { libc::ioctl(s, request as _, &mut v) };
        if rc == 0 { Ok(()) } else { Err(errno()) }
    }

    /// A request the sim does not model, used on `s`: the request and whether the sim refused it.
    /// An unknown ioctl succeeds without effect outside strict mode.
    pub fn unmodelled_request(s: Raw) -> (u64, bool) {
        assert_eq!(ioctl(s, UNKNOWN_IOCTL), Ok(()));
        (UNKNOWN_IOCTL, false)
    }

    /// A sim that refuses unmodelled options.
    pub fn strict_sim() -> snare::Sim {
        snare::Sim::builder().strict_sockopts().build()
    }
}

/// Winsock's side: the measured codes for options and ioctls nobody defines
/// ([Microsoft Learn: Windows Sockets Error Codes](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2)).
#[cfg(windows)]
mod os {
    use windows_sys::Win32::Networking::WinSock as ws;

    pub use crate::winsock::{Raw, get, raw, set_int as set};

    /// `WSAENOPROTOOPT`, what an unknown option at `IPPROTO_IP` fails with.
    pub const ENOPROTOOPT: i32 = ws::WSAENOPROTOOPT;
    /// `WSAEINVAL`, what an unknown option at `SOL_SOCKET` fails with (measured; the
    /// [setsockopt](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-setsockopt)
    /// page lists `WSAENOPROTOOPT` for "an unknown or unsupported option").
    pub const UNKNOWN_AT_SOCKET: i32 = ws::WSAEINVAL;
    /// `WSAEOPNOTSUPP`, what an unknown `ioctlsocket` command or `WSAIoctl` code fails with
    /// (measured).
    pub const UNKNOWN_REQUEST: i32 = ws::WSAEOPNOTSUPP;
    /// An option number no host defines at `SOL_SOCKET`.
    pub const UNKNOWN_OPTION: i32 = 0x7777;
    /// An `ioctlsocket` command no socket knows: `_IOR('z', 99, u_long)`.
    pub const UNKNOWN_IOCTL: u64 = 0x4004_7a63;
    pub const SOL_SOCKET: i32 = ws::SOL_SOCKET;
    pub const IPPROTO_IP: i32 = ws::IPPROTO_IP;
    pub const IP_MULTICAST_LOOP: i32 = ws::IP_MULTICAST_LOOP;
    /// A socket-level option the sim keeps as harmless, on a datagram socket (`SO_KEEPALIVE` is
    /// stream-only on Windows).
    pub const HARMLESS_AT_SOCKET: i32 = ws::SO_DEBUG;
    /// A socket-level option the sim does not model.
    pub const UNMODELLED_AT_SOCKET: i32 = ws::SO_EXCLUSIVEADDRUSE;
    /// A `WSAIoctl` code the sim does not carry out.
    pub const UNMODELLED_WSAIOCTL: u32 = ws::SIO_ADDRESS_LIST_QUERY;

    pub fn ioctl(s: Raw, request: u64) -> Result<(), i32> {
        crate::winsock::ioctlsocket(s, request as u32, &mut 0)
    }

    /// A synchronous `WSAIoctl` with a 4-byte input and no output.
    pub fn wsa_ioctl(s: Raw, code: u32) -> Result<(), i32> {
        crate::winsock::wsa_ioctl(s, code, &[0; 4], &mut []).map(|_| ())
    }

    /// A request the sim does not model, used on `s`: the request and whether the sim refused it.
    /// A `WSAIoctl` code the sim cannot carry out always fails, as Winsock fails one it does not
    /// know.
    pub fn unmodelled_request(s: Raw) -> (u64, bool) {
        assert_eq!(wsa_ioctl(s, UNMODELLED_WSAIOCTL), Err(UNKNOWN_REQUEST));
        (UNMODELLED_WSAIOCTL.into(), true)
    }

    /// A sim that refuses unmodelled options.
    pub fn strict_sim() -> snare::Sim {
        snare::Sim::builder().strict_sockopts().build()
    }
}

use os::*;

/// An unmodelled option succeeds without strict mode but is listed once on the socket and logged
/// once; a harmless one is neither, and reads back what was set.
#[test]
fn unmodelled_options_are_recorded() {
    let sim = Sim::new();
    sim.run(|| {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let s = raw(&sock);
        assert_eq!(set(s, IPPROTO_IP, IP_MULTICAST_LOOP, 0), Ok(()));
        assert_eq!(set(s, IPPROTO_IP, IP_MULTICAST_LOOP, 0), Ok(()));
        assert_eq!(get(s, SOL_SOCKET, UNMODELLED_AT_SOCKET), Ok(0));
        assert_eq!(set(s, SOL_SOCKET, HARMLESS_AT_SOCKET, 1), Ok(()));
        assert_eq!(
            get(s, SOL_SOCKET, HARMLESS_AT_SOCKET).map(|v| v != 0),
            Ok(true)
        );
        let (request, request_refused) = unmodelled_request(s);
        let id = socket_id(&sock).unwrap();
        let entry = socket_entry(id).unwrap();
        assert_eq!(
            entry.unmodelled_options,
            [
                UnmodelledOption::Set {
                    level: IPPROTO_IP,
                    name: IP_MULTICAST_LOOP
                },
                UnmodelledOption::Get {
                    level: SOL_SOCKET,
                    name: UNMODELLED_AT_SOCKET
                },
                UnmodelledOption::Ioctl { request },
            ]
        );
        let logged: Vec<_> = snare::recorded_events()
            .into_iter()
            .filter_map(|e| match e.event {
                RecordedEvent::UnmodelledOption {
                    socket,
                    option,
                    refused,
                    ..
                } => Some((socket, option, refused)),
                _ => None,
            })
            .collect();
        assert_eq!(logged.len(), 3);
        assert!(logged.iter().all(|&(socket, option, refused)| {
            socket == id
                && refused == (option == UnmodelledOption::Ioctl { request } && request_refused)
        }));
    });
}

/// Under strict mode the same calls fail with the host's codes, and the event says so.
#[test]
fn strict_refuses_unmodelled() {
    strict_sim().run(|| {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let s = raw(&sock);
        assert_eq!(set(s, IPPROTO_IP, IP_MULTICAST_LOOP, 0), Err(ENOPROTOOPT));
        assert_eq!(
            get(s, SOL_SOCKET, UNMODELLED_AT_SOCKET),
            Err(UNKNOWN_AT_SOCKET)
        );
        assert_eq!(set(s, SOL_SOCKET, HARMLESS_AT_SOCKET, 1), Ok(()));
        assert!(ioctl(s, UNKNOWN_IOCTL).is_err());
        let refused = snare::recorded_events().into_iter().any(|e| {
            matches!(
                e.event,
                RecordedEvent::UnmodelledOption { refused: true, .. }
            )
        });
        assert!(refused);
    });
}

/// What std's own socket calls do on each host is all modelled or harmless: a strict sim runs
/// them and lists nothing.
#[test]
fn std_sockets_are_clean_under_strict() {
    strict_sim().run(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        client.set_nodelay(true).unwrap();
        assert!(client.nodelay().unwrap());
        client
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        client.set_ttl(32).unwrap();
        assert_eq!(client.ttl().unwrap(), 32);
        client.set_nonblocking(true).unwrap();
        let _ = client.try_clone().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_broadcast(true).unwrap();
        udp.set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        udp.connect(server.local_addr().unwrap()).unwrap();
        for id in [
            socket_id(&listener),
            socket_id(&client),
            socket_id(&server),
            socket_id(&udp),
        ] {
            let entry = socket_entry(id.unwrap()).unwrap();
            assert!(entry.unmodelled_options.is_empty(), "{entry:?}");
        }
    });
}

/// Options nobody defines, at the socket level and at `IPPROTO_IP`, and an unknown ioctl request,
/// fail the same way on the real stack and in a strict sim.
fn unknown_option_probe() -> Vec<Result<i32, i32>> {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let s = raw(&sock);
    vec![
        set(s, SOL_SOCKET, UNKNOWN_OPTION, 1).map(|()| 0),
        get(s, SOL_SOCKET, UNKNOWN_OPTION),
        set(s, IPPROTO_IP, 250, 1).map(|()| 0),
        get(s, IPPROTO_IP, 250),
        ioctl(s, UNKNOWN_IOCTL).map(|()| 0),
    ]
}

#[test]
fn unknown_option_os_truth() {
    let real = snare::real(unknown_option_probe);
    let simulated = strict_sim().run(unknown_option_probe);
    assert_eq!(simulated, real);
}

/// What the real Winsock answers for an option nobody defines at `SOL_SOCKET` (`WSAEINVAL`) and at
/// `IPPROTO_IP` (`WSAENOPROTOOPT`), and for an unknown `ioctlsocket` command or `WSAIoctl` code
/// (`WSAEOPNOTSUPP`) — the codes a strict Winsock backend has to give.
#[cfg(windows)]
#[test]
fn unknown_option_codes_on_windows() {
    let probed = snare::real(|| {
        let mut out = unknown_option_probe();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        out.push(wsa_ioctl(raw(&sock), 0x9800_7777).map(|()| 0));
        out
    });
    assert_eq!(
        probed,
        [
            Err(UNKNOWN_AT_SOCKET),
            Err(UNKNOWN_AT_SOCKET),
            Err(ENOPROTOOPT),
            Err(ENOPROTOOPT),
            Err(UNKNOWN_REQUEST),
            Err(UNKNOWN_REQUEST),
        ]
    );
}
