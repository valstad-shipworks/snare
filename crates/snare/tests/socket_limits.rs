//! Socket buffer limits: the receive buffer each datagram is admitted against at its arrival, the
//! host OS's `SO_RCVBUF`/`SO_SNDBUF` rounding, `FIONREAD` and its relatives, and the counters that
//! tell overflow, wire loss and injected drops apart.

use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use snare::{Bytes, Sim, SocketEntry, SysLimits, run_testers, udp_tester};

const PAYLOAD: [u8; 1000] = [7; 1000];

/// A receive buffer that holds one 1000-byte datagram and not two, on every OS: Linux admits into
/// an empty queue and charges 2304; macOS needs 1016 of `sb_hiwat`; Windows admits while the
/// queued payload is below it.
fn one_datagram_buffer(limits: &mut SysLimits) {
    limits.rmem_default = if cfg!(windows) { 1000 } else { 1100 };
}

fn entry(socket: &UdpSocket) -> SocketEntry {
    snare::socket_entry(snare::socket_id(socket).unwrap()).unwrap()
}

fn drain(socket: &UdpSocket) -> Vec<Vec<u8>> {
    socket.set_nonblocking(true).unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 2048];
    loop {
        match socket.recv(&mut buf) {
            Ok(n) => got.push(buf[..n].to_vec()),
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) => panic!("recv: {e}"),
        }
    }
    socket.set_nonblocking(false).unwrap();
    got
}

#[test]
fn overflow_lands_at_arrival_not_observation() {
    Sim::new().run(|| {
        snare::set_sys_limits(one_datagram_buffer);
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = rx.local_addr().unwrap();
        snare::set_udp_policy(to, |p| p.latency = Duration::from_millis(10));
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(&PAYLOAD, to).unwrap();
        tx.send_to(&PAYLOAD, to).unwrap();
        let e = entry(&rx);
        assert_eq!(
            (e.delivered, e.overflowed, e.queued),
            (0, 0, 0),
            "both still in flight"
        );

        std::thread::sleep(Duration::from_millis(20));
        let e = entry(&rx);
        assert_eq!((e.delivered, e.overflowed, e.drops), (1, 1, 1));
        assert_eq!(
            drain(&rx).len(),
            1,
            "the second was dropped when it arrived"
        );

        for _ in 0..2 {
            tx.send_to(&PAYLOAD, to).unwrap();
            std::thread::sleep(Duration::from_millis(20));
            assert_eq!(drain(&rx).len(), 1, "a read between arrivals makes room");
        }
        assert_eq!(entry(&rx).overflowed, 1);
    });
}

/// What a deterministic run of three jittery senders into a small buffer delivers.
fn jittery_run(seed: u64) -> (u64, u64, Vec<Vec<u8>>) {
    Sim::builder().deterministic().seed(seed).build().run(|| {
        snare::set_sys_limits(|l| l.rmem_default = if cfg!(windows) { 3000 } else { 5000 });
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = rx.local_addr().unwrap();
        snare::set_udp_policy(to, |p| {
            p.latency = Duration::from_millis(1);
            p.jitter = Duration::from_millis(5);
        });
        let senders: Vec<_> = (0..3u8)
            .map(|t| {
                std::thread::spawn(move || {
                    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
                    for i in 0..5u8 {
                        let mut msg = vec![t, i];
                        msg.resize(900, 0);
                        tx.send_to(&msg, to).unwrap();
                        std::thread::sleep(Duration::from_micros(300));
                    }
                })
            })
            .collect();
        for s in senders {
            s.join().unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
        let got = drain(&rx);
        let e = entry(&rx);
        (e.delivered, e.overflowed, got)
    })
}

#[test]
fn overflow_is_deterministic_under_deterministic_scheduler() {
    let first = jittery_run(11);
    assert!(first.1 > 0, "the buffer overflowed");
    assert_eq!(first.0 + first.1, 15);
    assert_eq!(first.2.len() as u64, first.0);
    for _ in 0..3 {
        assert_eq!(jittery_run(11), first);
    }
}

#[test]
fn tester_endpoints_are_not_limited() {
    Sim::new().run(|| {
        snare::set_sys_limits(one_datagram_buffer);
        let sink = udp_tester::<Bytes>("127.0.0.5:7100")
            .recording()
            .until_after(Duration::from_millis(50));
        let client = std::thread::spawn(|| {
            let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
            for _ in 0..20 {
                tx.send_to(&PAYLOAD, "127.0.0.5:7100").unwrap();
            }
        });
        run_testers!(sink);
        client.join().unwrap();
        assert_eq!(sink.recorded().len(), 20);
    });
}

#[test]
fn enforce_rcvbuf_false_disables_overflow() {
    let mut limits = SysLimits::host();
    one_datagram_buffer(&mut limits);
    limits.enforce_rcvbuf = false;
    Sim::builder().sys_limits(limits).build().run(|| {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..20 {
            tx.send_to(&PAYLOAD, rx.local_addr().unwrap()).unwrap();
        }
        assert_eq!(drain(&rx).len(), 20);
        let e = entry(&rx);
        assert_eq!((e.delivered, e.overflowed, e.drops), (20, 0, 0));
    });
}

#[test]
fn set_sys_limits_affects_later_sockets_only() {
    let sim = Sim::new();
    sim.run(|| {
        let before = UdpSocket::bind("127.0.0.1:0").unwrap();
        snare::set_sys_limits(|l| l.rmem_default = 12_345);
        let after = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(entry(&before).rcvbuf, SysLimits::host().rmem_default as u32);
        assert_eq!(entry(&after).rcvbuf, 12_345);
        assert_eq!(snare::sys_limits().rmem_default, 12_345);
    });
    assert_eq!(sim.sys_limits().rmem_default, 12_345);
}

#[test]
fn delivered_wire_lost_and_drops() {
    Sim::new().run(|| {
        snare::set_sys_limits(one_datagram_buffer);
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to: SocketAddr = rx.local_addr().unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        snare::set_udp_policy(to, |p| p.loss_rate = 1.0);
        for _ in 0..3 {
            tx.send_to(&PAYLOAD, to).unwrap();
        }
        let e = entry(&rx);
        assert_eq!(
            (e.delivered, e.wire_lost, e.drops),
            (0, 3, 0),
            "wire loss is not a drop"
        );

        snare::set_udp_policy(to, |p| p.loss_rate = 0.0);
        tx.send_to(&PAYLOAD, to).unwrap();
        tx.send_to(&PAYLOAD, to).unwrap();
        let e = entry(&rx);
        assert_eq!(
            (e.delivered, e.overflowed, e.wire_lost, e.drops),
            (1, 1, 3, 1)
        );
        assert!(e.rmem_alloc > 0);

        let id = snare::socket_id(&rx).unwrap();
        snare::inject_socket_drops(id, 5).unwrap();
        assert_eq!(entry(&rx).drops, 6);
        drop(rx);
        let err = snare::inject_socket_drops(id, 1).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    });
}

#[cfg(unix)]
mod raw {
    use std::ffi::c_int;

    pub fn errno() -> c_int {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    }

    pub fn set_int(fd: c_int, level: c_int, name: c_int, v: c_int) -> Result<(), c_int> {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                (&v as *const c_int).cast(),
                size_of::<c_int>() as u32,
            )
        };
        if rc == 0 { Ok(()) } else { Err(errno()) }
    }

    pub fn get_int(fd: c_int, level: c_int, name: c_int) -> Result<c_int, c_int> {
        let mut v: c_int = 0;
        let mut len = size_of::<c_int>() as u32;
        let rc =
            unsafe { libc::getsockopt(fd, level, name, (&mut v as *mut c_int).cast(), &mut len) };
        if rc == 0 { Ok(v) } else { Err(errno()) }
    }

    pub fn ioctl_int(fd: c_int, request: libc::c_ulong) -> c_int {
        let mut v: c_int = -1;
        let rc = unsafe { libc::ioctl(fd, request as _, &mut v) };
        assert_eq!(rc, 0, "ioctl {request:#x}: {}", errno());
        v
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use snare::{HostProfile, Privileges, Sim, SysLimits};

    use super::raw::{get_int, ioctl_int, set_int};

    const SO_RCVBUFFORCE: i32 = 33;
    const SO_RXQ_OVFL: i32 = 40;
    const SO_MEMINFO: i32 = 55;
    const SO_COOKIE: i32 = 57;

    fn rcvbuf_after(fd: i32, v: i32) -> i32 {
        set_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, v).unwrap();
        get_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF).unwrap()
    }

    #[test]
    fn linux_rcvbuf_doubles_and_caps() {
        Sim::new().run(|| {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            let fd = s.as_raw_fd();
            let max = snare::sys_limits().rmem_max as i32;
            assert_eq!(rcvbuf_after(fd, 1000), 2304);
            assert_eq!(rcvbuf_after(fd, 5000), 10_000);
            assert_eq!(rcvbuf_after(fd, -1), 2 * max);
            assert_eq!(rcvbuf_after(fd, i32::MAX), 2 * max);
            set_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, 0).unwrap();
            assert_eq!(get_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF), Ok(4608));
            let short: u16 = 1;
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    (&short as *const u16).cast(),
                    2,
                )
            };
            assert_eq!((rc, super::raw::errno()), (-1, libc::EINVAL));
            let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            assert_eq!(
                get_int(tcp.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF),
                Ok(131_072)
            );
            assert_eq!(
                get_int(tcp.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF),
                Ok(16_384)
            );
        });
    }

    #[test]
    fn linux_rcvbufforce_needs_net_admin() {
        let sim = Sim::builder().privileges(Privileges::none()).build();
        sim.run(|| {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            let fd = s.as_raw_fd();
            assert_eq!(
                set_int(fd, libc::SOL_SOCKET, SO_RCVBUFFORCE, 1 << 20),
                Err(libc::EPERM)
            );
            snare::set_privileges(|p| p.net_admin = true);
            set_int(fd, libc::SOL_SOCKET, SO_RCVBUFFORCE, 1 << 20).unwrap();
            assert_eq!(
                get_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF),
                Ok(2 << 20),
                "beyond rmem_max"
            );
        });
    }

    fn truesize_admission() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(rcvbuf_after(rx.as_raw_fd(), 1), 2304);
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = rx.local_addr().unwrap();
        for (len, admitted) in [(100, 2), (500, 1), (1000, 1)] {
            for _ in 0..5 {
                tx.send_to(&vec![0u8; len], to).unwrap();
            }
            assert_eq!(super::drain(&rx).len(), admitted, "{len}-byte datagrams");
        }
        let e = super::entry(&rx);
        assert_eq!((e.overflowed, e.drops), (11, 11));
    }

    #[test]
    fn linux_overflow_follows_truesize_admission() {
        Sim::new().run(truesize_admission);
        Sim::builder()
            .host(HostProfile::new().build())
            .build()
            .run(truesize_admission);
    }

    #[test]
    fn linux_siocinq_is_next_datagram_size() {
        let check = || {
            let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
            let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
            let fd = rx.as_raw_fd();
            assert_eq!(ioctl_int(fd, libc::FIONREAD), 0);
            tx.send_to(&[1; 10], rx.local_addr().unwrap()).unwrap();
            tx.send_to(&[2; 20], rx.local_addr().unwrap()).unwrap();
            assert_eq!(ioctl_int(fd, libc::FIONREAD), 10);
            assert_eq!(ioctl_int(fd, libc::TIOCOUTQ), 0);
            rx.recv(&mut [0; 64]).unwrap();
            assert_eq!(ioctl_int(fd, libc::FIONREAD), 20);
            rx.recv(&mut [0; 64]).unwrap();
            assert_eq!(ioctl_int(fd, libc::FIONREAD), 0);
        };
        Sim::new().run(check);
        Sim::builder()
            .host(HostProfile::new().build())
            .build()
            .run(check);
        Sim::new().run(|| {
            use std::io::Write;
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            client.write_all(b"seven!!").unwrap();
            assert_eq!(
                ioctl_int(server.as_raw_fd(), libc::FIONREAD),
                7,
                "a stream's unread bytes"
            );
        });
    }

    /// The `SO_RXQ_OVFL` count a `recvmsg` on `fd` reports, if any.
    fn recv_ovfl(fd: i32) -> Option<u32> {
        let mut buf = [0u8; 2048];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut control = [0u64; 16];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of_val(&control);
        let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
        assert!(n >= 0, "recvmsg: {}", super::raw::errno());
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        if cmsg.is_null() {
            return None;
        }
        let (level, ty) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
        assert_eq!((level, ty), (libc::SOL_SOCKET, SO_RXQ_OVFL));
        Some(unsafe { libc::CMSG_DATA(cmsg).cast::<u32>().read_unaligned() })
    }

    fn meminfo(fd: i32) -> [u32; 9] {
        let mut words = [0u32; 9];
        let mut len = size_of_val(&words) as u32;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_MEMINFO,
                words.as_mut_ptr().cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0);
        words
    }

    #[test]
    fn inject_socket_drops_shows_in_rxq_ovfl() {
        let check = || {
            let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
            let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
            let fd = rx.as_raw_fd();
            let to = rx.local_addr().unwrap();
            set_int(fd, libc::SOL_SOCKET, SO_RXQ_OVFL, 1).unwrap();
            assert_eq!(get_int(fd, libc::SOL_SOCKET, SO_RXQ_OVFL), Ok(1));
            tx.send_to(b"before", to).unwrap();
            assert_eq!(recv_ovfl(fd), None, "no cmsg while nothing was dropped");
            snare::inject_socket_drops(snare::socket_id(&rx).unwrap(), 3).unwrap();
            tx.send_to(b"after", to).unwrap();
            assert_eq!(recv_ovfl(fd), Some(3));
            let m = meminfo(fd);
            assert_eq!(m[8], 3, "SK_MEMINFO_DROPS");
            assert_eq!(
                m[1] as i32,
                get_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF).unwrap()
            );
            assert_eq!(m[0], 0, "nothing queued");
            tx.send_to(b"queued", to).unwrap();
            let small = snare::sys_limits().skb_small_truesize as u32;
            assert_eq!(meminfo(fd)[0], small);
            assert_eq!(meminfo(fd)[4], 4096 - small);
        };
        Sim::new().run(check);
        Sim::builder()
            .host(HostProfile::new().build())
            .build()
            .run(check);
    }

    #[test]
    fn so_cookie_is_the_socket_id() {
        Sim::new().run(|| {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut cookie = 0u64;
            let mut len = 8u32;
            let rc = unsafe {
                libc::getsockopt(
                    s.as_raw_fd(),
                    libc::SOL_SOCKET,
                    SO_COOKIE,
                    (&mut cookie as *mut u64).cast(),
                    &mut len,
                )
            };
            assert_eq!(rc, 0);
            assert_eq!(cookie, snare::socket_id(&s).unwrap().get());
        });
    }

    /// The `SK_MEMINFO_RMEM_ALLOC` a lone `len`-byte datagram leaves queued on a loopback socket
    /// at `ip`, for each `len`.
    fn truesizes(ip: std::net::IpAddr, lens: &[usize]) -> Vec<u32> {
        let rx = UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap();
        let tx = UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap();
        let to = rx.local_addr().unwrap();
        set_int(rx.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, 1 << 20).unwrap();
        let payload = vec![0u8; lens.iter().copied().max().unwrap_or(0)];
        let mut buf = vec![0u8; payload.len() + 1];
        lens.iter()
            .map(|&len| {
                tx.send_to(&payload[..len], to).unwrap();
                let mut pfd = libc::pollfd {
                    fd: rx.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                assert_eq!(
                    unsafe { libc::poll(&mut pfd, 1, 1000) },
                    1,
                    "{len} bytes arrive"
                );
                let queued = meminfo(rx.as_raw_fd())[0];
                rx.recv(&mut buf).unwrap();
                queued
            })
            .collect()
    }

    /// The sim's datagram truesize against the kernel it runs on, for a sim built from
    /// [`SysLimits::from_real_host`]: every step boundary scripts/measure-sockbuf.sh found on the
    /// kernels it measured, one byte either side, over IPv4 and IPv6.
    #[test]
    fn truesize_os_truth() {
        let mut lens = vec![0, 1, 100, 1000, 1472, 17_000];
        for edge in [
            313, 326, 441, 454, 569, 582, 633, 646, 1593, 1606, 1657, 1670, 3641, 3654, 3705, 3718,
            7737, 7750, 7801, 7814, 15_928, 15_941, 15_992, 16_005,
        ] {
            lens.extend([edge - 1, edge, edge + 1]);
        }
        for ip in [Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()] {
            let real = snare::real(|| truesizes(ip, &lens));
            let sim = Sim::builder()
                .sys_limits(SysLimits::from_real_host().unwrap())
                .build()
                .run(|| truesizes(ip, &lens));
            for (i, len) in lens.iter().enumerate() {
                assert_eq!(sim[i], real[i], "{ip}: truesize of a {len}-byte datagram");
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    use snare::Sim;

    use super::raw::{get_int, ioctl_int, set_int};

    #[test]
    fn macos_sockbuf_clamps_then_enobufs() {
        Sim::new().run(|| {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            let fd = s.as_raw_fd();
            assert_eq!(get_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF), Ok(786_896));
            assert_eq!(get_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF), Ok(9216));
            for bad in [0, -1] {
                assert_eq!(
                    set_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, bad),
                    Err(libc::EINVAL)
                );
            }
            set_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, 1000).unwrap();
            assert_eq!(get_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF), Ok(1000));
            set_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, 9_000_000).unwrap();
            assert_eq!(
                get_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF),
                Ok(8_388_608)
            );
            assert_eq!(
                set_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, 9_000_000),
                Err(libc::ENOBUFS),
                "already at kern.ipc.maxsockbuf"
            );
            set_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, 8_000_000).unwrap();
            snare::set_sys_limits(|l| l.sockbuf_reject_at = 9_000_000);
            let fresh = UdpSocket::bind("127.0.0.1:0").unwrap();
            assert_eq!(
                set_int(
                    fresh.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    9_000_000
                ),
                Err(libc::ENOBUFS)
            );
        });
    }

    #[test]
    fn macos_overflow_and_fionread() {
        Sim::new().run(|| {
            let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
            let fd = rx.as_raw_fd();
            set_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, 1000).unwrap();
            let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
            for _ in 0..7 {
                tx.send_to(&[0; 100], rx.local_addr().unwrap()).unwrap();
            }
            // sb_cc: the socket's first record is 16 + 100 bytes, every later one 32 + 100.
            assert_eq!(ioctl_int(fd, libc::FIONREAD as _), 776);
            assert_eq!(get_int(fd, libc::SOL_SOCKET, libc::SO_NREAD), Ok(100));
            assert_eq!(get_int(fd, libc::SOL_SOCKET, libc::SO_NWRITE), Ok(0));
            let mut after = Vec::new();
            for _ in 0..6 {
                rx.recv(&mut [0; 200]).unwrap();
                after.push(ioctl_int(fd, libc::FIONREAD as _));
            }
            assert_eq!(after, [660, 528, 396, 264, 132, 0]);
            let e = super::entry(&rx);
            assert_eq!((e.delivered, e.overflowed), (6, 1));
        });
    }

    #[test]
    fn macos_udp_send_over_sndbuf_is_emsgsize() {
        Sim::new().run(|| {
            let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
            let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
            let to = rx.local_addr().unwrap();
            let err = tx.send_to(&[0; 9217], to).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EMSGSIZE));
            set_int(tx.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF, 100).unwrap();
            assert!(tx.send_to(&[0; 101], to).is_err());
            assert_eq!(tx.send_to(&[0; 100], to).unwrap(), 100);
        });
    }
}
