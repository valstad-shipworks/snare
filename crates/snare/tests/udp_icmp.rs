//! ICMP port unreachables on datagram sockets, as the host kernel takes them: injected, from a
//! tester, and sent back automatically for a datagram that reaches no socket at an address that
//! answers, after the link's round trip.

#[path = "support/netfault.rs"]
mod netfault;

use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use netfault::{code, errno};
use snare::{
    Bytes, IpNet, NicSpec, Sim, TesterAction, inject_icmp_port_unreachable, run_testers,
    set_udp_policy, udp_tester,
};

fn bound() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").unwrap()
}

fn addr(s: &UdpSocket) -> SocketAddr {
    s.local_addr().unwrap()
}

#[test]
fn icmp_on_connected_udp_fails_next_recv() {
    Sim::new().run(|| {
        let (a, b) = (bound(), bound());
        a.connect(addr(&b)).unwrap();
        inject_icmp_port_unreachable(addr(&a), addr(&b));
        let mut buf = [0u8; 4];
        assert_eq!(errno(a.recv(&mut buf).unwrap_err()), code::ICMP);
        a.set_nonblocking(true).unwrap();
        assert_eq!(a.recv(&mut buf).unwrap_err().kind(), ErrorKind::WouldBlock);
    });
}

#[test]
fn icmp_on_connected_udp_fails_next_send_on_unix() {
    Sim::new().run(|| {
        let (a, b) = (bound(), bound());
        a.connect(addr(&b)).unwrap();
        inject_icmp_port_unreachable(addr(&a), addr(&b));
        if cfg!(windows) {
            assert_eq!(
                a.send(b"x").unwrap(),
                1,
                "Windows reports it to receives only"
            );
            let mut buf = [0u8; 4];
            assert_eq!(errno(a.recv(&mut buf).unwrap_err()), code::ICMP);
        } else {
            assert_eq!(errno(a.send(b"x").unwrap_err()), code::ICMP);
            assert_eq!(a.send(b"x").unwrap(), 1);
        }
    });
}

#[test]
fn icmp_on_unconnected_udp() {
    Sim::new().run(|| {
        let (a, b) = (bound(), bound());
        inject_icmp_port_unreachable(addr(&a), addr(&b));
        let mut buf = [0u8; 4];
        a.set_nonblocking(true).unwrap();
        if cfg!(windows) {
            assert!(netfault::poll(netfault::raw(&a), true, false, 0).readable);
            assert_eq!(errno(a.recv_from(&mut buf).unwrap_err()), code::ICMP);
        } else {
            assert_eq!(
                a.recv_from(&mut buf).unwrap_err().kind(),
                ErrorKind::WouldBlock
            );
            assert!(a.take_error().unwrap().is_none());
        }
    });
}

#[test]
#[cfg(target_os = "linux")]
fn linux_ip_recverr_reports_icmp_on_unconnected() {
    Sim::new().run(|| {
        let (a, b) = (bound(), bound());
        netfault::set_recverr(netfault::raw(&a));
        inject_icmp_port_unreachable(addr(&a), addr(&b));
        let mut buf = [0u8; 4];
        assert_eq!(
            errno(a.recv_from(&mut buf).unwrap_err()),
            libc::ECONNREFUSED
        );
    });
}

/// One `recvmsg(MSG_ERRQUEUE)` on `fd`: the offender's port, the `sock_extended_err` and the
/// message flags, or the errno.
#[cfg(target_os = "linux")]
fn read_errqueue(fd: i32) -> Result<(u16, libc::sock_extended_err, i32), i32> {
    let mut payload = [0u8; 16];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut name: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut control = [0u8; 128];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&mut name as *mut libc::sockaddr_in).cast();
    msg.msg_namelen = size_of::<libc::sockaddr_in>() as u32;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap());
    }
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    assert!(!cmsg.is_null());
    let (level, ty) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
    assert_eq!((level, ty), (libc::SOL_IP, libc::IP_RECVERR));
    let ee = unsafe {
        libc::CMSG_DATA(cmsg)
            .cast::<libc::sock_extended_err>()
            .read_unaligned()
    };
    Ok((u16::from_be(name.sin_port), ee, msg.msg_flags))
}

/// An injected ICMP error reaches an `IP_RECVERR` socket's error queue with its offender, and
/// an empty queue reads `EAGAIN`.
#[cfg(target_os = "linux")]
fn injected_icmp_on_error_queue() {
    let (a, b) = (bound(), bound());
    let fd = netfault::raw(&a);
    assert_eq!(read_errqueue(fd).unwrap_err(), libc::EAGAIN);
    netfault::set_recverr(fd);
    inject_icmp_port_unreachable(addr(&a), addr(&b));
    let (_, ee, flags) = read_errqueue(fd).unwrap();
    assert!(flags & libc::MSG_ERRQUEUE != 0);
    assert_eq!(ee.ee_errno, libc::ECONNREFUSED as u32);
    assert_eq!((ee.ee_origin, ee.ee_type, ee.ee_code), (2, 3, 3));
    assert_eq!(read_errqueue(fd).unwrap_err(), libc::EAGAIN);
}

#[test]
#[cfg(target_os = "linux")]
fn ip_recverr_error_queue_takes_injected_icmp() {
    Sim::new().run(injected_icmp_on_error_queue);
    Sim::builder()
        .host(snare::HostProfile::new().build())
        .build()
        .run(injected_icmp_on_error_queue);
}

#[test]
#[cfg(target_os = "linux")]
fn plain_ip_recverr_queues_extended_error() {
    Sim::new().run(recverr_queues_extended_error);
}

#[test]
#[cfg(target_os = "linux")]
fn simhost_ip_recverr_queues_extended_error() {
    let host = snare::HostProfile::new().build();
    Sim::builder()
        .host(host)
        .build()
        .run(recverr_queues_extended_error);
}

/// A datagram to a closed port comes back as an extended error on the error queue, which
/// clears the pending error when read.
#[cfg(target_os = "linux")]
fn recverr_queues_extended_error() {
    let a = bound();
    let fd = netfault::raw(&a);
    netfault::set_recverr(fd);
    a.send_to(b"x", "127.0.0.1:9").unwrap();
    let (port, ee, flags) = read_errqueue(fd).unwrap();
    assert!(flags & libc::MSG_ERRQUEUE != 0);
    assert_eq!(port, 9);
    assert_eq!(ee.ee_errno, libc::ECONNREFUSED as u32);
    assert_eq!((ee.ee_origin, ee.ee_type, ee.ee_code), (2, 3, 3));
    let mut buf = [0u8; 4];
    a.set_nonblocking(true).unwrap();
    assert_eq!(
        a.recv(&mut buf).unwrap_err().kind(),
        ErrorKind::WouldBlock,
        "reading the error queue cleared the pending error"
    );
}

fn closed_port_round_trip() {
    let a = bound();
    a.connect("127.0.0.1:9").unwrap();
    a.send(b"anyone?").unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(errno(a.recv(&mut buf).unwrap_err()), code::ICMP);
}

#[test]
fn send_to_closed_loopback_port_auto_icmp() {
    Sim::new().run(closed_port_round_trip);
    #[cfg(target_os = "linux")]
    {
        let host = snare::HostProfile::new().build();
        Sim::builder()
            .host(host)
            .build()
            .run(closed_port_round_trip);
    }
}

#[test]
fn send_to_absent_address_no_icmp() {
    let nic = NicSpec::new("eth0").address("192.168.50.2/24".parse::<IpNet>().unwrap());
    Sim::builder().nic(nic).build().run(|| {
        let a = UdpSocket::bind("192.168.50.2:0").unwrap();
        a.connect("192.168.50.77:9").unwrap();
        a.send(b"anyone?").unwrap();
        a.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut buf = [0u8; 4];
        let e = a.recv(&mut buf).unwrap_err();
        assert!(
            matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
            "no answer from an absent address: {e:?}"
        );
    });
}

#[test]
fn icmp_arrives_after_round_trip_latency() {
    Sim::new().run(|| {
        set_udp_policy("127.0.0.1:9", |p| p.latency = Duration::from_millis(40));
        let a = bound();
        a.connect("127.0.0.1:9").unwrap();
        let start = Instant::now();
        a.send(b"x").unwrap();
        a.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(a.recv(&mut buf).unwrap_err().kind(), ErrorKind::WouldBlock);
        a.set_nonblocking(false).unwrap();
        assert_eq!(errno(a.recv(&mut buf).unwrap_err()), code::ICMP);
        assert!(
            start.elapsed() >= Duration::from_millis(80),
            "{:?}",
            start.elapsed()
        );
    });
}

#[test]
fn tester_action_icmp_port_unreachable() {
    Sim::new().run(|| {
        let tester = udp_tester::<Bytes>("127.0.0.7:7900")
            .then_action(|_, _| TesterAction::IcmpPortUnreachable)
            .until_after(Duration::from_millis(100));
        let client = std::thread::spawn(|| {
            let a = bound();
            a.connect("127.0.0.7:7900").unwrap();
            a.send(b"hi").unwrap();
            let mut buf = [0u8; 4];
            errno(a.recv(&mut buf).unwrap_err())
        });
        run_testers!(tester);
        assert_eq!(client.join().unwrap(), code::ICMP);
    });
}

#[test]
#[cfg(windows)]
fn sio_udp_connreset_false_suppresses_reset() {
    Sim::new().run(|| {
        let (a, b) = (bound(), bound());
        netfault::set_connreset(netfault::raw(&a), false);
        inject_icmp_port_unreachable(addr(&a), addr(&b));
        a.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(
            a.recv_from(&mut buf).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
    });
}
