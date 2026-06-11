//! Compile-only parity check: every method we expose on `snare::net::*` and
//! `snare::thread::*` matches the corresponding `std` signature. The test
//! body never actually runs the operations — `return;` short-circuits before
//! any I/O — so the value is purely "does this compile?"
//!
//! If you add a new method to a shim, mirror it here. If `std` adds a new
//! method, add it here and the missing-from-shim case will fail to build.

#![allow(unused_must_use, unused_variables, dead_code, unreachable_code)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr};
use std::time::Duration;

#[test]
fn tcp_stream_full_surface() {
    return; // compile-only

    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

    // Constructors.
    let mut s = snare::net::TcpStream::connect(addr).unwrap();
    let _ = snare::net::TcpStream::connect("127.0.0.1:1").unwrap();
    let _ = snare::net::TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap();

    // Address / clone / shutdown.
    let _: SocketAddr = s.peer_addr().unwrap();
    let _: SocketAddr = s.local_addr().unwrap();
    let _: snare::net::TcpStream = s.try_clone().unwrap();
    s.shutdown(Shutdown::Both).unwrap();

    // Socket options.
    s.set_nonblocking(true).unwrap();
    s.set_nodelay(true).unwrap();
    let _: bool = s.nodelay().unwrap();
    s.set_ttl(64).unwrap();
    let _: u32 = s.ttl().unwrap();
    // `linger` / `set_linger` are still unstable in std::net::TcpStream
    // (rust issue #88494). The shim exposes them as a convenience feature,
    // but they're skipped here so the parity test compiles on stable.
    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let _: Option<Duration> = s.read_timeout().unwrap();
    s.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
    let _: Option<Duration> = s.write_timeout().unwrap();
    let _: Option<std::io::Error> = s.take_error().unwrap();

    // Peek + Read + Write on owned.
    let mut buf = [0u8; 8];
    let _: usize = s.peek(&mut buf).unwrap();
    let _: usize = s.read(&mut buf).unwrap();
    let _: usize = s.write(b"hi").unwrap();
    s.flush().unwrap();

    // Read + Write on a shared reference (matches std::net).
    let r: &snare::net::TcpStream = &s;
    let mut shared_r = r;
    let _: usize = (&mut shared_r).read(&mut buf).unwrap();
    let mut shared_w = r;
    let _: usize = (&mut shared_w).write(b"hi").unwrap();

    #[cfg(unix)]
    let _: std::os::fd::RawFd = std::os::fd::AsRawFd::as_raw_fd(&s);
}

#[test]
fn tcp_listener_full_surface() {
    return; // compile-only

    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

    // Constructors / address / clone.
    let l = snare::net::TcpListener::bind(addr).unwrap();
    let _ = snare::net::TcpListener::bind("127.0.0.1:1").unwrap();
    let _: SocketAddr = l.local_addr().unwrap();
    let _: snare::net::TcpListener = l.try_clone().unwrap();

    // Accept + Incoming.
    let _: (snare::net::TcpStream, SocketAddr) = l.accept().unwrap();
    let inc: snare::net::Incoming<'_> = l.incoming();
    for stream in inc {
        let _: snare::net::TcpStream = stream.unwrap();
    }

    // Socket options.
    l.set_nonblocking(true).unwrap();
    l.set_ttl(64).unwrap();
    let _: u32 = l.ttl().unwrap();
    let _: Option<std::io::Error> = l.take_error().unwrap();

    #[cfg(unix)]
    let _: std::os::fd::RawFd = std::os::fd::AsRawFd::as_raw_fd(&l);
}

#[test]
fn udp_socket_full_surface() {
    return; // compile-only

    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

    // Constructors / address / clone / connect.
    let s = snare::net::UdpSocket::bind(addr).unwrap();
    let _ = snare::net::UdpSocket::bind("127.0.0.1:1").unwrap();
    let _: SocketAddr = s.local_addr().unwrap();
    let _: SocketAddr = s.peer_addr().unwrap();
    let _: snare::net::UdpSocket = s.try_clone().unwrap();
    s.connect(addr).unwrap();
    s.connect("127.0.0.1:1").unwrap();

    // Send / recv.
    let mut buf = [0u8; 8];
    let _: usize = s.send_to(&buf, addr).unwrap();
    let _: usize = s.send_to(&buf, "127.0.0.1:1").unwrap();
    let _: (usize, SocketAddr) = s.recv_from(&mut buf).unwrap();
    let _: (usize, SocketAddr) = s.peek_from(&mut buf).unwrap();
    let _: usize = s.send(&buf).unwrap();
    let _: usize = s.recv(&mut buf).unwrap();
    let _: usize = s.peek(&mut buf).unwrap();

    // Timeouts.
    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let _: Option<Duration> = s.read_timeout().unwrap();
    s.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
    let _: Option<Duration> = s.write_timeout().unwrap();

    // Socket options.
    s.set_nonblocking(true).unwrap();
    s.set_broadcast(true).unwrap();
    let _: bool = s.broadcast().unwrap();
    s.set_multicast_loop_v4(true).unwrap();
    let _: bool = s.multicast_loop_v4().unwrap();
    s.set_multicast_ttl_v4(1).unwrap();
    let _: u32 = s.multicast_ttl_v4().unwrap();
    s.set_multicast_loop_v6(true).unwrap();
    let _: bool = s.multicast_loop_v6().unwrap();
    s.set_ttl(64).unwrap();
    let _: u32 = s.ttl().unwrap();
    let _: Option<std::io::Error> = s.take_error().unwrap();

    // Multicast groups.
    let v4 = Ipv4Addr::new(224, 0, 0, 1);
    let iface_v4 = Ipv4Addr::new(0, 0, 0, 0);
    s.join_multicast_v4(&v4, &iface_v4).unwrap();
    s.leave_multicast_v4(&v4, &iface_v4).unwrap();
    let v6 = std::net::Ipv6Addr::LOCALHOST;
    s.join_multicast_v6(&v6, 0).unwrap();
    s.leave_multicast_v6(&v6, 0).unwrap();

    #[cfg(unix)]
    let _: std::os::fd::RawFd = std::os::fd::AsRawFd::as_raw_fd(&s);
}

// ---- snare::thread ----

#[test]
fn thread_module_surface() {
    return; // compile-only

    // spawn / join.
    let h = snare::thread::spawn(|| 42_i32);
    let _: i32 = h.join().unwrap();

    // Builder.
    let b = snare::thread::Builder::new()
        .name("worker".to_string())
        .stack_size(64 * 1024);
    let h = b.spawn(|| 7_u32).unwrap();
    let _: u32 = h.join().unwrap();

    // Builder::spawn_scoped (within std::thread::scope).
    snare::thread::scope(|scope| {
        let _h = snare::thread::Builder::new()
            .spawn_scoped(scope, || 1_u8)
            .unwrap();
    });

    // Re-exports.
    let _: snare::thread::Thread = snare::thread::current();
    let _: snare::thread::ThreadId = snare::thread::current().id();
    snare::thread::sleep(Duration::from_millis(0));
    snare::thread::yield_now();
    snare::thread::park_timeout(Duration::from_millis(0));
    let _: bool = snare::thread::panicking();
    let _ = snare::thread::available_parallelism();
}
