#![cfg(windows)]

//! The Winsock backend against the real Winsock of the machine the tests run on: the same calls on
//! loopback sockets, real (`snare::real`) and simulated side by side, for the error codes of calls
//! made in the wrong state and the `SOL_SOCKET` options' defaults and read-back. Nothing here needs
//! administrator rights or a network beyond loopback, so it means the same on a VM and on real
//! hardware.
//!
//! The options at the other levels and `SO_KEEPALIVE`, `getsockname` of an unbound socket and
//! `WSARecvMsg`/`WSASendMsg` on a stream are compared the same way.

use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::windows::io::AsRawSocket;
use std::time::Duration;

use snare::Sim;
use windows_sys::Win32::Networking::WinSock as ws;

#[path = "support/winsock.rs"]
mod winsock;

use winsock::{Raw, get, get_int, raw, set_int, wsa_recv_msg_fn};

/// An outcome as a label and its result: the value, or the `WSAGetLastError` code.
type Probe = (&'static str, Result<i32, i32>);

/// An option read as a label and its value with the length `getsockopt` wrote, or the code.
type OptionRead = (&'static str, Result<(i32, i32), i32>);

/// The calls' outcomes, real and simulated, that differ.
fn differences(real: &[Probe], sim: &[Probe]) -> Vec<String> {
    assert_eq!(real.len(), sim.len());
    real.iter()
        .zip(sim)
        .filter(|(r, s)| r != s)
        .map(|((what, r), (_, s))| format!("{what}: host {r:?}, sim {s:?}"))
        .collect()
}

#[track_caller]
fn assert_same(real: Vec<Probe>, sim: Vec<Probe>) {
    let differ = differences(&real, &sim);
    assert!(differ.is_empty(), "{}", differ.join("\n"));
}

fn rc(result: i32) -> Result<i32, i32> {
    if result == 0 {
        Ok(0)
    } else {
        Err(winsock::last_error())
    }
}

fn tcp_socket() -> Raw {
    let _ = UdpSocket::bind("127.0.0.1:0");
    let s = unsafe { ws::socket(ws::AF_INET as i32, ws::SOCK_STREAM, ws::IPPROTO_TCP) };
    assert_ne!(s, ws::INVALID_SOCKET, "socket: {}", winsock::last_error());
    s
}

fn bind(s: Raw, addr: SocketAddr) -> Result<i32, i32> {
    let (sa, len) = winsock::sockaddr(addr);
    rc(unsafe { ws::bind(s, sa.as_ptr().cast(), len) })
}

fn close(s: Raw) {
    unsafe { ws::closesocket(s) };
}

fn recv(s: Raw) -> Result<i32, i32> {
    let mut buf = [0u8; 8];
    let n = unsafe { ws::recv(s, buf.as_mut_ptr(), buf.len() as i32, 0) };
    if n >= 0 {
        Ok(n)
    } else {
        Err(winsock::last_error())
    }
}

fn send(s: Raw) -> Result<i32, i32> {
    let n = unsafe { ws::send(s, b"x".as_ptr(), 1, 0) };
    if n >= 0 {
        Ok(n)
    } else {
        Err(winsock::last_error())
    }
}

fn peer(s: Raw) -> Result<i32, i32> {
    let mut sa = [0u8; 28];
    let mut len = sa.len() as i32;
    rc(unsafe { ws::getpeername(s, sa.as_mut_ptr().cast(), &mut len) })
}

/// A connected loopback pair: the client and the accepted server end.
fn connected() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

/// Calls made in a state that does not allow them, each on a fresh socket: listen, accept, bind,
/// recv, send, getpeername and shutdown on TCP sockets that are unbound, bound or connected, and
/// listen, accept, getpeername and a nonblocking recv on an unconnected UDP socket
/// ([Microsoft Learn: Windows Sockets Error Codes](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2);
/// each call's own page lists the codes it returns).
fn wrong_state_calls() -> Vec<Probe> {
    let any = SocketAddr::from(([127, 0, 0, 1], 0));
    let mut out = Vec::new();

    let s = tcp_socket();
    out.push(("listen, unbound", rc(unsafe { ws::listen(s, 4) })));
    out.push(("recv, unconnected", recv(s)));
    out.push(("send, unconnected", send(s)));
    out.push(("getpeername, unconnected", peer(s)));
    out.push((
        "shutdown, unconnected",
        rc(unsafe { ws::shutdown(s, ws::SD_BOTH) }),
    ));
    out.push(("bind", bind(s, any)));
    out.push(("bind again", bind(s, any)));
    let accepted = unsafe { ws::accept(s, std::ptr::null_mut(), std::ptr::null_mut()) };
    out.push((
        "accept, not listening",
        if accepted == ws::INVALID_SOCKET {
            Err(winsock::last_error())
        } else {
            Ok(0)
        },
    ));
    close(s);

    let udp = UdpSocket::bind(any).unwrap();
    let u = raw(&udp);
    out.push(("udp listen", rc(unsafe { ws::listen(u, 4) })));
    let accepted = unsafe { ws::accept(u, std::ptr::null_mut(), std::ptr::null_mut()) };
    out.push((
        "udp accept",
        if accepted == ws::INVALID_SOCKET {
            Err(winsock::last_error())
        } else {
            Ok(0)
        },
    ));
    out.push(("udp getpeername, unconnected", peer(u)));
    udp.set_nonblocking(true).unwrap();
    out.push(("udp recv, nonblocking and empty", recv(u)));

    let (client, server) = connected();
    let c = client.as_raw_socket() as Raw;
    out.push(("shutdown, how 7", rc(unsafe { ws::shutdown(c, 7) })));
    client.set_nonblocking(true).unwrap();
    out.push(("recv, nonblocking and empty", recv(c)));
    out.push((
        "shutdown SD_RECEIVE",
        rc(unsafe { ws::shutdown(c, ws::SD_RECEIVE) }),
    ));
    out.push(("recv after SD_RECEIVE", recv(c)));
    out.push((
        "shutdown SD_SEND",
        rc(unsafe { ws::shutdown(c, ws::SD_SEND) }),
    ));
    out.push(("send after SD_SEND", send(c)));
    let s = server.as_raw_socket() as Raw;
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    out.push(("peer recv after its peer's SD_SEND", recv(s)));
    out
}

#[test]
fn wrong_state_codes_match_the_host() {
    let real = snare::real(wrong_state_calls);
    let sim = Sim::new().run(wrong_state_calls);
    assert_same(real, sim);
}

/// The `SOL_SOCKET` options of a fresh TCP socket, a listener and a fresh UDP socket as
/// `getsockopt` reads them, value and written length
/// ([Microsoft Learn: SOL_SOCKET socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/sol-socket-socket-options)).
fn socket_defaults() -> Vec<OptionRead> {
    let tcp = tcp_socket();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let l = raw(&listener);
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let u = raw(&udp);
    let sol = ws::SOL_SOCKET;
    let out = vec![
        ("tcp SO_TYPE", get_int(tcp, sol, ws::SO_TYPE)),
        ("tcp SO_REUSEADDR", get_int(tcp, sol, ws::SO_REUSEADDR)),
        ("tcp SO_RCVTIMEO", get_int(tcp, sol, ws::SO_RCVTIMEO)),
        ("tcp SO_SNDTIMEO", get_int(tcp, sol, ws::SO_SNDTIMEO)),
        ("tcp SO_ERROR", get_int(tcp, sol, ws::SO_ERROR)),
        ("tcp SO_ACCEPTCONN", get_int(tcp, sol, ws::SO_ACCEPTCONN)),
        ("tcp SO_LINGER", get_int(tcp, sol, ws::SO_LINGER)),
        ("tcp SO_DONTLINGER", get_int(tcp, sol, ws::SO_DONTLINGER)),
        ("listener SO_ACCEPTCONN", get_int(l, sol, ws::SO_ACCEPTCONN)),
        ("udp SO_TYPE", get_int(u, sol, ws::SO_TYPE)),
        ("udp SO_REUSEADDR", get_int(u, sol, ws::SO_REUSEADDR)),
        ("udp SO_BROADCAST", get_int(u, sol, ws::SO_BROADCAST)),
        ("udp SO_RCVTIMEO", get_int(u, sol, ws::SO_RCVTIMEO)),
        ("udp SO_ERROR", get_int(u, sol, ws::SO_ERROR)),
    ];
    close(tcp);
    out
}

#[test]
fn socket_option_defaults_match_the_host() {
    let real = snare::real(socket_defaults);
    let sim = Sim::new().run(socket_defaults);
    let differ: Vec<String> = real
        .iter()
        .zip(&sim)
        .filter(|(r, s)| r != s)
        .map(|((what, r), (_, s))| format!("{what}: host {r:?}, sim {s:?}"))
        .collect();
    assert!(differ.is_empty(), "{}", differ.join("\n"));
}

/// `SOL_SOCKET` options set and read back: the timeouts (a `DWORD` of milliseconds),
/// `SO_REUSEADDR`, `SO_LINGER` (a `struct linger` of two `u_short`s) and the `SO_DONTLINGER` it
/// implies, and `SO_BROADCAST`.
fn socket_round_trips() -> Vec<Probe> {
    let tcp = tcp_socket();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let u = raw(&udp);
    let sol = ws::SOL_SOCKET;
    let linger = |on: u16, secs: u16| {
        i32::from_ne_bytes({
            let mut b = [0u8; 4];
            b[..2].copy_from_slice(&on.to_ne_bytes());
            b[2..].copy_from_slice(&secs.to_ne_bytes());
            b
        })
    };
    let mut out = Vec::new();
    for (what, s, name, value) in [
        ("tcp SO_RCVTIMEO", tcp, ws::SO_RCVTIMEO, 1234),
        ("tcp SO_SNDTIMEO", tcp, ws::SO_SNDTIMEO, 4321),
        ("tcp SO_REUSEADDR", tcp, ws::SO_REUSEADDR, 1),
        ("tcp SO_LINGER", tcp, ws::SO_LINGER, linger(1, 5)),
        ("udp SO_BROADCAST", u, ws::SO_BROADCAST, 1),
        ("udp SO_RCVTIMEO", u, ws::SO_RCVTIMEO, 50),
    ] {
        out.push((
            what,
            set_int(s, sol, name, value).and_then(|()| get(s, sol, name)),
        ));
    }
    out.push((
        "tcp SO_DONTLINGER after SO_LINGER",
        get(tcp, sol, ws::SO_DONTLINGER),
    ));
    close(tcp);
    out
}

#[test]
fn socket_option_round_trips_match_the_host() {
    let real = snare::real(socket_round_trips);
    let sim = Sim::new().run(socket_round_trips);
    assert_same(real, sim);
}

/// What std's option getters read on fresh sockets and after its setters, at the levels the
/// backend keeps as harmless or unmodelled: `IP_TTL`, `IP_MULTICAST_TTL`, `IP_MULTICAST_LOOP`, `TCP_NODELAY` and
/// `SO_KEEPALIVE`
/// ([Microsoft Learn: IPPROTO_IP socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options),
/// [IPPROTO_TCP socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-tcp-socket-options)).
fn harmless_round_trips() -> Vec<Probe> {
    let (client, _server) = connected();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let c = client.as_raw_socket() as Raw;
    let io = |r: std::io::Result<u32>| r.map(|v| v as i32).map_err(|e| e.raw_os_error().unwrap());
    let mut out = vec![
        ("tcp ttl default", io(client.ttl())),
        ("tcp nodelay default", io(client.nodelay().map(u32::from))),
        ("udp multicast ttl default", io(udp.multicast_ttl_v4())),
        (
            "udp multicast loop default",
            io(udp.multicast_loop_v4().map(u32::from)),
        ),
        (
            "tcp SO_KEEPALIVE default",
            get(c, ws::SOL_SOCKET, ws::SO_KEEPALIVE),
        ),
    ];
    client.set_ttl(32).unwrap();
    client.set_nodelay(true).unwrap();
    udp.set_multicast_ttl_v4(4).unwrap();
    udp.set_multicast_loop_v4(false).unwrap();
    set_int(c, ws::SOL_SOCKET, ws::SO_KEEPALIVE, 1).unwrap();
    out.extend([
        ("tcp ttl", io(client.ttl())),
        ("tcp nodelay", io(client.nodelay().map(u32::from))),
        ("udp multicast ttl", io(udp.multicast_ttl_v4())),
        (
            "udp multicast loop",
            io(udp.multicast_loop_v4().map(u32::from)),
        ),
        (
            "tcp SO_KEEPALIVE",
            get(c, ws::SOL_SOCKET, ws::SO_KEEPALIVE).map(|v| (v != 0) as i32),
        ),
    ]);
    out
}

#[test]
fn harmless_option_round_trips_match_the_host() {
    let real = snare::real(harmless_round_trips);
    let sim = Sim::new().run(harmless_round_trips);
    assert_same(real, sim);
}

/// `getsockname` on a socket never bound fails with `WSAEINVAL`
/// ([Microsoft Learn: getsockname](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getsockname)).
fn unbound_name() -> Vec<Probe> {
    let s = tcp_socket();
    let mut sa = [0u8; 28];
    let mut len = sa.len() as i32;
    let out = vec![(
        "getsockname, unbound",
        rc(unsafe { ws::getsockname(s, sa.as_mut_ptr().cast(), &mut len) }),
    )];
    close(s);
    out
}

#[test]
fn unbound_getsockname_matches_the_host() {
    let real = snare::real(unbound_name);
    let sim = Sim::new().run(unbound_name);
    assert_eq!(real, [("getsockname, unbound", Err(ws::WSAEINVAL))]);
    assert_same(real, sim);
}

/// `WSARecvMsg` and `WSASendMsg` on a TCP socket: the empty non-null control buffer fails
/// `WSAEFAULT` before the stream-type check; sending fails `WSAEINVAL` (Windows 11 build
/// 26200.9457;
/// [Microsoft Learn: LPFN_WSARECVMSG](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_wsarecvmsg),
/// [WSASendMsg](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendmsg)).
fn msg_calls_on_tcp() -> Vec<Probe> {
    let (client, _server) = connected();
    let c = client.as_raw_socket() as Raw;
    let recv = wsa_recv_msg_fn(c).and_then(|_| {
        let mut data = [0u8; 8];
        winsock::recv_msg(c, &mut data, &mut []).map(|(n, _, _)| n as i32)
    });
    let send = winsock::send_msg(c, b"x", None, &mut []).map(|n| n as i32);
    vec![("WSARecvMsg on TCP", recv), ("WSASendMsg on TCP", send)]
}

#[test]
fn msg_calls_on_tcp_on_windows() {
    let real = snare::real(msg_calls_on_tcp);
    assert_eq!(
        real,
        [
            ("WSARecvMsg on TCP", Err(ws::WSAEFAULT)),
            ("WSASendMsg on TCP", Err(ws::WSAEINVAL)),
        ]
    );
}

#[test]
fn msg_calls_on_tcp_match_the_host() {
    let real = snare::real(msg_calls_on_tcp);
    let sim = Sim::new().run(msg_calls_on_tcp);
    assert_same(real, sim);
}

#[test]
fn extended_option_defaults_match_the_host() {
    let probe = || {
        let (tcp, _server) = connected();
        let v4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let v6 = UdpSocket::bind("[::1]:0").unwrap();
        vec![
            ("v4 TTL", get(raw(&v4), ws::IPPROTO_IP, ws::IP_TTL)),
            (
                "v6 hops",
                get(raw(&v6), ws::IPPROTO_IPV6, ws::IPV6_UNICAST_HOPS),
            ),
            (
                "v4 broadcast",
                get(raw(&v4), ws::IPPROTO_IP, ws::IP_RECEIVE_BROADCAST),
            ),
            (
                "tcp keepcnt",
                get(raw(&tcp), ws::IPPROTO_TCP, ws::TCP_KEEPCNT),
            ),
            (
                "tcp keepidle",
                get(raw(&tcp), ws::IPPROTO_TCP, ws::TCP_KEEPIDLE),
            ),
            (
                "tcp keepinterval",
                get(raw(&tcp), ws::IPPROTO_TCP, ws::TCP_KEEPINTVL),
            ),
            (
                "v4 v6hops",
                get(raw(&v4), ws::IPPROTO_IPV6, ws::IPV6_UNICAST_HOPS),
            ),
            ("v6 v4ttl", get(raw(&v6), ws::IPPROTO_IP, ws::IP_TTL)),
        ]
    };
    let real = snare::real(probe);
    assert_same(real.clone(), Sim::new().run(probe));
    assert_same(real, Sim::builder().deterministic().build().run(probe));
}

#[test]
fn waitall_partial_completion_matches_the_host() {
    let probe = || {
        let mut results = Vec::new();
        for (eof, wsa) in [(false, false), (true, false), (false, true), (true, true)] {
            let (client, mut server) = connected();
            client
                .set_read_timeout(Some(Duration::from_millis(80)))
                .unwrap();
            std::io::Write::write_all(&mut server, b"ab").unwrap();
            if eof {
                server.shutdown(std::net::Shutdown::Write).unwrap();
            }
            let mut buffer = [0xccu8; 8];
            let result = if wsa {
                let buf = ws::WSABUF {
                    len: buffer.len() as u32,
                    buf: buffer.as_mut_ptr(),
                };
                let mut flags = ws::MSG_WAITALL as u32;
                let mut got = 0x7777u32;
                let value = unsafe {
                    ws::WSARecv(
                        raw(&client),
                        &buf,
                        1,
                        &mut got,
                        &mut flags,
                        std::ptr::null_mut(),
                        None,
                    )
                };
                if value == ws::SOCKET_ERROR {
                    Err(winsock::last_error())
                } else {
                    Ok(got as i32)
                }
            } else {
                let value = unsafe {
                    ws::recv(
                        raw(&client),
                        buffer.as_mut_ptr(),
                        buffer.len() as i32,
                        ws::MSG_WAITALL,
                    )
                };
                if value == ws::SOCKET_ERROR {
                    Err(winsock::last_error())
                } else {
                    Ok(value)
                }
            };
            results.push((eof, wsa, result, buffer));
        }
        results
    };
    let real = snare::real(probe);
    assert_eq!(Sim::new().run(probe), real);
    assert_eq!(Sim::builder().deterministic().build().run(probe), real);
}

#[test]
fn recvmsg_tcp_parameters_match_the_host() {
    let probe = || {
        let mut results = Vec::new();
        for address in [false, true] {
            for control in [None, Some(0), Some(8), Some(15), Some(16), Some(64)] {
                let (client, _server) = connected();
                client.set_nonblocking(true).unwrap();
                let socket = raw(&client);
                let recv = wsa_recv_msg_fn(socket).unwrap();
                let mut data = [0u8; 8];
                let mut from: ws::SOCKADDR_STORAGE = unsafe { std::mem::zeroed() };
                let mut ancillary = [0u8; 64];
                let mut buf = ws::WSABUF {
                    len: data.len() as u32,
                    buf: data.as_mut_ptr(),
                };
                let mut msg = ws::WSAMSG {
                    name: if address {
                        (&raw mut from).cast()
                    } else {
                        std::ptr::null_mut()
                    },
                    namelen: if address {
                        size_of::<ws::SOCKADDR_STORAGE>() as i32
                    } else {
                        0
                    },
                    lpBuffers: &mut buf,
                    dwBufferCount: 1,
                    Control: ws::WSABUF {
                        len: control.unwrap_or(0),
                        buf: if control.is_some() {
                            ancillary.as_mut_ptr()
                        } else {
                            std::ptr::null_mut()
                        },
                    },
                    dwFlags: 0,
                };
                let mut got = 0u32;
                let result = rc(unsafe {
                    recv(
                        socket,
                        &mut msg,
                        &mut got,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                });
                results.push((address, control, result));
            }
        }
        results
    };
    let real = snare::real(probe);
    assert_eq!(Sim::new().run(probe), real);
}

#[test]
fn unicast_hop_options_across_families_match_the_host() {
    let probe = || {
        let _startup = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut results = Vec::new();
        for family in [ws::AF_INET, ws::AF_INET6] {
            for level in [ws::IPPROTO_IP, ws::IPPROTO_IPV6] {
                for value in [-2, -1, 0, 1, 255, 256] {
                    let socket = unsafe { ws::socket(family as i32, ws::SOCK_DGRAM, 0) };
                    assert_ne!(socket, ws::INVALID_SOCKET);
                    let set = set_int(socket, level, ws::IP_TTL, value);
                    results.push((
                        family,
                        level,
                        value,
                        set,
                        get(socket, ws::IPPROTO_IP, ws::IP_TTL),
                        get(socket, ws::IPPROTO_IPV6, ws::IPV6_UNICAST_HOPS),
                    ));
                    close(socket);
                }
            }
        }
        results
    };
    let real = snare::real(probe);
    assert_eq!(Sim::new().run(probe), real);
    assert_eq!(Sim::builder().deterministic().build().run(probe), real);
}

fn waitall_receive(socket: Raw, wsa: bool) -> (Result<i32, i32>, [u8; 8]) {
    let mut buffer = [0xcc; 8];
    let result = if wsa {
        let buf = ws::WSABUF {
            len: buffer.len() as u32,
            buf: buffer.as_mut_ptr(),
        };
        let mut flags = ws::MSG_WAITALL as u32;
        let mut got = 0x7777;
        let value = unsafe {
            ws::WSARecv(
                socket,
                &buf,
                1,
                &mut got,
                &mut flags,
                std::ptr::null_mut(),
                None,
            )
        };
        if value == ws::SOCKET_ERROR {
            Err(winsock::last_error())
        } else {
            Ok(got as i32)
        }
    } else {
        let value = unsafe {
            ws::recv(
                socket,
                buffer.as_mut_ptr(),
                buffer.len() as i32,
                ws::MSG_WAITALL,
            )
        };
        if value == ws::SOCKET_ERROR {
            Err(winsock::last_error())
        } else {
            Ok(value)
        }
    };
    (result, buffer)
}

fn abort_stream(stream: TcpStream) {
    let linger = ws::LINGER {
        l_onoff: 1,
        l_linger: 0,
    };
    assert_eq!(
        unsafe {
            ws::setsockopt(
                raw(&stream),
                ws::SOL_SOCKET,
                ws::SO_LINGER,
                std::ptr::from_ref(&linger).cast(),
                size_of::<ws::LINGER>() as i32,
            )
        },
        0
    );
    drop(stream);
}

#[test]
fn waitall_partial_reset_and_shutdown_match_the_host() {
    let probe = || {
        let mut results = Vec::new();
        for termination in 0..3 {
            for wsa in [false, true] {
                let (client, mut server) = connected();
                client
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                std::io::Write::write_all(&mut server, b"ab").unwrap();
                let mut peeked = [0; 2];
                assert_eq!(client.peek(&mut peeked).unwrap(), 2);
                assert_eq!(peeked, *b"ab");
                let local = client.try_clone().unwrap();
                let actor = std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(50));
                    match termination {
                        0 => abort_stream(server),
                        1 => local.shutdown(std::net::Shutdown::Read).unwrap(),
                        _ => local.shutdown(std::net::Shutdown::Both).unwrap(),
                    }
                });
                let first = waitall_receive(raw(&client), wsa);
                actor.join().unwrap();
                results.push((termination, wsa, first, recv(raw(&client))));
            }
        }
        results
    };
    let real = snare::real(probe);
    assert_eq!(Sim::new().run(probe), real);
    assert_eq!(Sim::builder().deterministic().build().run(probe), real);
}

#[test]
fn reset_pending_before_receive_matches_the_host() {
    let probe = || {
        let mut results = Vec::new();
        for clear in [false, true] {
            for wsa in [false, true] {
                let (client, mut server) = connected();
                client
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                std::io::Write::write_all(&mut server, b"ab").unwrap();
                let mut peeked = [0; 2];
                assert_eq!(client.peek(&mut peeked).unwrap(), 2);
                abort_stream(server);
                snare::real(|| std::thread::sleep(Duration::from_millis(50)));
                let error = clear.then(|| get(raw(&client), ws::SOL_SOCKET, ws::SO_ERROR));
                results.push((
                    clear,
                    wsa,
                    error,
                    waitall_receive(raw(&client), wsa),
                    recv(raw(&client)),
                ));
            }
        }
        results
    };
    let real = snare::real(probe);
    assert_eq!(Sim::new().run(probe), real);
    assert_eq!(Sim::builder().deterministic().build().run(probe), real);
}

#[test]
fn udp_pending_error_and_queued_data_match_the_host() {
    let probe = || {
        let mut results = Vec::new();
        for queued_first in [true, false] {
            for clear in [false, true] {
                let client = UdpSocket::bind("127.0.0.1:0").unwrap();
                let server = UdpSocket::bind("127.0.0.1:0").unwrap();
                let peer = server.local_addr().unwrap();
                client.connect(peer).unwrap();
                client
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                winsock::wsa_ioctl(raw(&client), 0x9800_000c, &1u32.to_ne_bytes(), &mut [])
                    .unwrap();
                if queued_first {
                    server.send_to(b"ab", client.local_addr().unwrap()).unwrap();
                    let mut peeked = [0; 2];
                    assert_eq!(client.peek(&mut peeked).unwrap(), 2);
                }
                drop(server);
                assert_eq!(client.send(b"x").unwrap(), 1);
                let ready = if queued_first {
                    snare::real(|| std::thread::sleep(Duration::from_millis(50)));
                    None
                } else {
                    let mut poll = ws::WSAPOLLFD {
                        fd: raw(&client),
                        events: ws::POLLRDNORM,
                        revents: 0,
                    };
                    let result = unsafe { ws::WSAPoll(&mut poll, 1, 1000) };
                    assert_eq!(result, 1);
                    let server = UdpSocket::bind(peer).unwrap();
                    server.send_to(b"ab", client.local_addr().unwrap()).unwrap();
                    snare::real(|| std::thread::sleep(Duration::from_millis(50)));
                    Some(poll.revents)
                };
                let error = clear.then(|| get(raw(&client), ws::SOL_SOCKET, ws::SO_ERROR));
                let received: Vec<_> = (0..3)
                    .map(|_| {
                        let mut data = [0xcc; 8];
                        let count = unsafe {
                            ws::recv(raw(&client), data.as_mut_ptr(), data.len() as i32, 0)
                        };
                        let result = if count >= 0 {
                            Ok(count)
                        } else {
                            Err(winsock::last_error())
                        };
                        (result, data)
                    })
                    .collect();
                results.push((queued_first, clear, ready, error, received));
            }
        }
        results
    };
    let real = snare::real(probe);
    assert_eq!(Sim::new().run(probe), real);
    assert_eq!(Sim::builder().deterministic().build().run(probe), real);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UdpIndicationCase {
    connected: bool,
    reset: bool,
    errors: usize,
    placement: usize,
    peek: bool,
    spaced: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct UdpIndicationTrace {
    sends: Vec<Result<usize, i32>>,
    readiness: (i32, i16),
    error: Result<i32, i32>,
    reads: Vec<(Result<i32, i32>, [u8; 8])>,
}

fn udp_indication_probe(case: UdpIndicationCase) -> UdpIndicationTrace {
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = server.local_addr().unwrap();
    let local = client.local_addr().unwrap();
    if case.connected {
        client.connect(peer).unwrap();
    }
    client.set_nonblocking(true).unwrap();
    winsock::wsa_ioctl(
        raw(&client),
        0x9800_000c,
        &u32::from(case.reset).to_ne_bytes(),
        &mut [],
    )
    .unwrap();
    if case.placement == 1 {
        server.send_to(b"ab", local).unwrap();
        let mut data = [0; 8];
        assert_eq!(client.peek_from(&mut data).unwrap().0, 2);
    }
    drop(server);
    let send_data = || {
        let server = UdpSocket::bind(peer).unwrap();
        server.send_to(b"ab", local).unwrap();
        snare::real(|| std::thread::sleep(Duration::from_millis(50)));
    };
    let mut sends = Vec::new();
    for index in 0..case.errors {
        let sent = if case.connected {
            client.send(b"x")
        } else {
            client.send_to(b"x", peer)
        };
        sends.push(sent.map_err(|error| error.raw_os_error().unwrap()));
        if case.spaced {
            snare::real(|| std::thread::sleep(Duration::from_millis(50)));
        }
        if case.placement == 2 && index == 0 {
            send_data();
        }
    }
    if !case.spaced {
        snare::real(|| std::thread::sleep(Duration::from_millis(50)));
    }
    if case.placement == 3 {
        send_data();
    }
    let mut poll = ws::WSAPOLLFD {
        fd: raw(&client),
        events: ws::POLLRDNORM,
        revents: 0,
    };
    let readiness = (unsafe { ws::WSAPoll(&mut poll, 1, 0) }, poll.revents);
    let error = get(raw(&client), ws::SOL_SOCKET, ws::SO_ERROR);
    let reads = (0..case.errors + 5)
        .map(|index| {
            let mut data = [0xcc; 8];
            let flags = if case.peek && index < 2 {
                ws::MSG_PEEK
            } else {
                0
            };
            let received =
                unsafe { ws::recv(raw(&client), data.as_mut_ptr(), data.len() as i32, flags) };
            let result = if received >= 0 {
                Ok(received)
            } else {
                Err(winsock::last_error())
            };
            (result, data)
        })
        .collect();
    UdpIndicationTrace {
        sends,
        readiness,
        error,
        reads,
    }
}

#[test]
fn udp_indications_match_the_host() {
    for connected in [false, true] {
        for reset in [false, true] {
            for errors in [1, 3] {
                for placement in 0..4 {
                    for peek in [false, true] {
                        let case = UdpIndicationCase {
                            connected,
                            reset,
                            errors,
                            placement,
                            peek,
                            spaced: true,
                        };
                        let real = snare::real(|| udp_indication_probe(case));
                        assert_eq!(
                            Sim::new().run(|| udp_indication_probe(case)),
                            real,
                            "{case:?}"
                        );
                        assert_eq!(
                            Sim::builder()
                                .deterministic()
                                .build()
                                .run(|| udp_indication_probe(case)),
                            real,
                            "det {case:?}"
                        );
                    }
                }
            }
        }
    }
}

fn udp_reset_toggle_probe(connected: bool, initial: bool) -> Vec<Result<i32, i32>> {
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = server.local_addr().unwrap();
    if connected {
        client.connect(peer).unwrap();
    }
    client.set_nonblocking(true).unwrap();
    drop(server);
    let reset = |enabled: bool| {
        winsock::wsa_ioctl(
            raw(&client),
            0x9800_000c,
            &u32::from(enabled).to_ne_bytes(),
            &mut [],
        )
        .unwrap()
    };
    let send = || {
        if connected {
            client.send(b"x").unwrap();
        } else {
            client.send_to(b"x", peer).unwrap();
        }
        snare::real(|| std::thread::sleep(Duration::from_millis(50)));
    };
    reset(initial);
    send();
    reset(!initial);
    let mut results = vec![recv(raw(&client))];
    send();
    for _ in 0..3 {
        results.push(recv(raw(&client)));
    }
    reset(initial);
    send();
    for _ in 0..3 {
        results.push(recv(raw(&client)));
    }
    results
}

#[test]
fn udp_bursts_and_reset_toggles_match_the_host() {
    for connected in [false, true] {
        for reset in [false, true] {
            for peek in [false, true] {
                let case = UdpIndicationCase {
                    connected,
                    reset,
                    errors: 8,
                    placement: 0,
                    peek,
                    spaced: false,
                };
                let real = snare::real(|| udp_indication_probe(case));
                assert_eq!(
                    Sim::new().run(|| udp_indication_probe(case)),
                    real,
                    "{case:?}"
                );
                assert_eq!(
                    Sim::builder()
                        .deterministic()
                        .build()
                        .run(|| udp_indication_probe(case)),
                    real,
                    "det {case:?}"
                );
            }
        }
        for initial in [false, true] {
            let probe = || udp_reset_toggle_probe(connected, initial);
            let real = snare::real(probe);
            assert_eq!(
                Sim::new().run(probe),
                real,
                "connected={connected} initial={initial}"
            );
            assert_eq!(
                Sim::builder().deterministic().build().run(probe),
                real,
                "det connected={connected} initial={initial}"
            );
        }
    }
}

#[test]
fn delayed_udp_statuses_follow_arrival_order() {
    let probe = || {
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let first = UdpSocket::bind("127.0.0.1:0").unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").unwrap();
        let first_peer = first.local_addr().unwrap();
        let second_peer = second.local_addr().unwrap();
        drop((first, second));
        snare::set_udp_policy(first_peer, |policy| {
            policy.latency = Duration::from_millis(10)
        });
        snare::set_udp_policy(second_peer, |policy| {
            policy.latency = Duration::from_millis(1)
        });
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client.send_to(b"x", first_peer).unwrap();
        client.send_to(b"x", second_peer).unwrap();
        assert_eq!(recv(raw(&client)), Err(ws::WSAECONNRESET));
        assert_eq!(recv(raw(&client)), Err(ws::WSAECONNRESET));
        let statuses: Vec<_> = snare::recorded_events()
            .into_iter()
            .filter_map(|entry| match entry.event {
                snare::RecordedEvent::Fault {
                    fault: snare::Fault::IcmpPortUnreachable { from },
                    ..
                } => Some(from),
                _ => None,
            })
            .collect();
        assert_eq!(statuses, vec![second_peer, first_peer]);
    };
    Sim::new().run(probe);
    Sim::builder().deterministic().build().run(probe);
}

#[test]
fn raised_udp_errors_preserve_queued_receive_statuses() {
    let probe = || {
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let local = client.local_addr().unwrap();
        snare::inject_icmp_port_unreachable(local, server.local_addr().unwrap());
        snare::raise_socket_error(local, std::io::Error::from_raw_os_error(ws::WSAEACCES));
        assert_eq!(
            get(raw(&client), ws::SOL_SOCKET, ws::SO_ERROR),
            Ok(ws::WSAEACCES)
        );
        assert_eq!(get(raw(&client), ws::SOL_SOCKET, ws::SO_ERROR), Ok(0));
        assert_eq!(recv(raw(&client)), Err(ws::WSAECONNRESET));
        client.set_nonblocking(true).unwrap();
        assert_eq!(recv(raw(&client)), Err(ws::WSAEWOULDBLOCK));
    };
    Sim::new().run(probe);
    Sim::builder().deterministic().build().run(probe);
}
