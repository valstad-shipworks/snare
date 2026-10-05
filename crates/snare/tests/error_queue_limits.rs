#![cfg(target_os = "linux")]

use std::mem::size_of;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;

use snare::{Sim, SysLimits};

fn set(fd: i32, level: i32, option: i32, value: i32) {
    assert_eq!(
        unsafe {
            libc::setsockopt(
                fd,
                level,
                option,
                (&raw const value).cast(),
                size_of::<i32>() as _,
            )
        },
        0
    );
}

fn mem(fd: i32) -> [u32; 9] {
    let mut words = [0; 9];
    let mut len = size_of::<[u32; 9]>() as libc::socklen_t;
    assert_eq!(
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                55,
                words.as_mut_ptr().cast(),
                &mut len,
            )
        },
        0
    );
    words
}

fn drain(fd: i32) -> Vec<usize> {
    let mut data = [0u8; 65536];
    let mut out = Vec::new();
    loop {
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };
        if n < 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EAGAIN)
            );
            break;
        }
        out.push(n as usize);
    }
    out
}

fn burst(addr: &str, kind: u8, len: usize, buffer: i32) -> (u32, u32, u32, Vec<usize>, u32) {
    let sender = UdpSocket::bind(addr).unwrap();
    let peer = UdpSocket::bind(addr).unwrap();
    let to = peer.local_addr().unwrap();
    let fd = sender.as_raw_fd();
    set(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, buffer);
    let peer = if kind == 2 {
        let (level, option) = if to.is_ipv6() {
            (libc::SOL_IPV6, libc::IPV6_RECVERR)
        } else {
            (libc::SOL_IP, libc::IP_RECVERR)
        };
        set(fd, level, option, 1);
        drop(peer);
        None
    } else {
        set(
            fd,
            libc::SOL_SOCKET,
            37,
            (1 << 1) | (1 << 4) | if kind == 1 { 1 << 11 } else { 0 },
        );
        Some(peer)
    };
    let payload = vec![0u8; len];
    for _ in 0..32 {
        sender.take_error().unwrap();
        assert_eq!(sender.send_to(&payload, to).unwrap(), len);
    }
    let before = mem(fd);
    let reports = drain(fd);
    let after = mem(fd);
    drop(peer);
    (before[0], before[1], before[8], reports, after[0])
}

#[test]
fn report_capacity_charge_and_payload_match_linux() {
    let probe = || {
        let mut out = Vec::new();
        for addr in ["127.0.0.1:0", "[::1]:0"] {
            for kind in 0..3 {
                for len in [
                    0, 1, 425, 426, 440, 441, 453, 454, 512, 521, 581, 582, 1000, 2000, 16000,
                    64000,
                ] {
                    for buffer in [512, 4096, 16384] {
                        out.push(burst(addr, kind, len, buffer));
                    }
                }
            }
        }
        out
    };
    let real = probe();
    let outside: Vec<_> = real
        .iter()
        .filter(|(memory, limit, drops, reports, after)| {
            !(memory < limit && *drops == 0 && reports.len() < 32 && *after == 0)
        })
        .collect();
    assert!(
        outside.is_empty(),
        "bursts outside the calibrated range: {outside:?}"
    );
    let limits = SysLimits::from_real_host().unwrap();
    assert_eq!(
        Sim::builder().sys_limits(limits.clone()).build().run(probe),
        real
    );
    assert_eq!(
        Sim::builder()
            .sys_limits(limits)
            .host(snare::HostProfile::new().build())
            .build()
            .run(probe),
        real
    );
}

#[test]
fn ordinary_data_and_error_reports_share_the_receive_budget() {
    let probe = || {
        let mut out = Vec::new();
        for addr in ["127.0.0.1:0", "[::1]:0"] {
            for errors_first in [false, true] {
                let socket = UdpSocket::bind(addr).unwrap();
                let peer = UdpSocket::bind(addr).unwrap();
                let fd = socket.as_raw_fd();
                set(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, 4096);
                set(fd, libc::SOL_SOCKET, 37, (1 << 1) | (1 << 4) | (1 << 11));
                let ordinary = || {
                    for _ in 0..4 {
                        peer.send_to(b"data", socket.local_addr().unwrap()).unwrap();
                    }
                };
                let reports = || {
                    for _ in 0..4 {
                        socket
                            .send_to(b"stamp", peer.local_addr().unwrap())
                            .unwrap();
                    }
                };
                if errors_first {
                    reports();
                    ordinary();
                } else {
                    ordinary();
                    reports();
                }
                let before = mem(fd);
                let read_reports = drain(fd).len();
                let after_reports = mem(fd);
                socket.set_nonblocking(true).unwrap();
                let mut data = [0; 16];
                let mut read_data = 0;
                while socket.recv(&mut data).is_ok() {
                    read_data += 1;
                }
                out.push((
                    before[0],
                    before[8],
                    read_reports,
                    after_reports[0],
                    read_data,
                    mem(fd)[0],
                ));
            }
        }
        out
    };
    let real = probe();
    let outside: Vec<_> = real
        .iter()
        .filter(|(_, _, errors, _, data, after)| !(errors + data < 8 && *after == 0))
        .collect();
    assert!(
        outside.is_empty(),
        "bursts outside the calibrated range: {outside:?}"
    );
    let limits = SysLimits::from_real_host().unwrap();
    assert_eq!(
        Sim::builder().sys_limits(limits.clone()).build().run(probe),
        real
    );
    assert_eq!(
        Sim::builder()
            .sys_limits(limits)
            .host(snare::HostProfile::new().build())
            .build()
            .run(probe),
        real
    );
}

#[test]
fn a_report_consumes_memory_when_it_arrives() {
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    for deterministic in [false, true] {
        let mut builder = Sim::builder();
        if deterministic {
            builder = builder.deterministic();
        }
        builder.build().run(|| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            snare::set_tcp_policy(addr, |p| p.latency = Duration::from_millis(20));
            let mut client = TcpStream::connect(addr).unwrap();
            let (_server, _) = listener.accept().unwrap();
            let fd = client.as_raw_fd();
            set(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, 512);
            set(fd, libc::SOL_SOCKET, 37, (1 << 4) | (1 << 9) | (1 << 11));
            for _ in 0..3 {
                client.write_all(b"x").unwrap();
            }
            assert_eq!(mem(fd)[0], 0);
            assert!(drain(fd).is_empty());
            std::thread::sleep(Duration::from_millis(50));
            let small = snare::sys_limits().skb_small_truesize as u32;
            let count = (mem(fd)[1] - 1) / small;
            assert_eq!(mem(fd)[0], count * small);
            assert_eq!(drain(fd).len(), count as usize);
            assert_eq!(mem(fd)[0], 0);
        });
    }
}

#[test]
fn tcp_report_charge_and_release_match_linux() {
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};

    let probe = || {
        let mut out = Vec::new();
        for only in [false, true] {
            for len in [1, 100, 500, 1000, 16000] {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
                let (_server, _) = listener.accept().unwrap();
                let fd = client.as_raw_fd();
                set(
                    fd,
                    libc::SOL_SOCKET,
                    37,
                    (1 << 1) | (1 << 4) | if only { 1 << 11 } else { 0 },
                );
                client.write_all(&vec![0; len]).unwrap();
                out.push((mem(fd)[0], drain(fd), mem(fd)[0]));
            }
        }
        out
    };
    let real = probe();
    let limits = SysLimits::from_real_host().unwrap();
    assert_eq!(Sim::builder().sys_limits(limits).build().run(probe), real);
}

#[test]
fn ordinary_tcp_data_and_transmit_reports_share_the_receive_budget() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    let probe = || {
        let mut results = Vec::new();
        for payload in [1, 100, 500, 1500] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (mut server, _) = listener.accept().unwrap();
            let fd = client.as_raw_fd();
            set(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, 4096);
            set(fd, libc::SOL_TCP, libc::TCP_NODELAY, 1);
            server.write_all(&vec![7; payload]).unwrap();
            let mut readable = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut readable, 1, 2000) }, 1);
            let ordinary = mem(fd)[0];
            set(fd, libc::SOL_SOCKET, 37, (1 << 1) | (1 << 4) | (1 << 11));
            for _ in 0..16 {
                client.write_all(b"x").unwrap();
            }
            let total = mem(fd)[0];
            let reports = drain(fd);
            assert_eq!(mem(fd)[0], ordinary);
            let mut data = vec![0; payload];
            if payload > 1 {
                client.read_exact(&mut data[..payload / 2]).unwrap();
                assert_eq!(mem(fd)[0], ordinary);
            }
            let read = if payload > 1 { payload / 2 } else { 0 };
            client.read_exact(&mut data[read..]).unwrap();
            assert_eq!(data, vec![7; payload]);
            assert_eq!(mem(fd)[0], 0);
            results.push((ordinary, total, reports));
        }
        results
    };
    let real = probe();
    let limits = SysLimits::from_real_host().unwrap();
    for deterministic in [false, true] {
        for host in [false, true] {
            let mut builder = Sim::builder().sys_limits(limits.clone());
            if deterministic {
                builder = builder.deterministic();
            }
            if host {
                builder = builder.host(snare::HostProfile::new().build());
            }
            assert_eq!(builder.build().run(probe), real);
        }
    }
}

#[test]
fn earlier_in_flight_data_takes_the_budget_before_a_later_icmp_report() {
    use std::time::Duration;

    for host in [false, true] {
        for first in 0..6 {
            let mut builder = Sim::builder();
            if host {
                builder = builder.host(snare::HostProfile::new().build());
            }
            builder.build().run(|| {
                let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
                let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
                let closed = UdpSocket::bind("127.0.0.1:0").unwrap();
                let to = closed.local_addr().unwrap();
                drop(closed);
                let fd = socket.as_raw_fd();
                set(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, 512);
                set(fd, libc::SOL_IP, libc::IP_RECVERR, 1);
                snare::set_udp_policy(socket.local_addr().unwrap(), |p| {
                    p.latency = Duration::from_millis(20)
                });
                snare::set_udp_policy(to, |p| p.latency = Duration::from_millis(20));
                for _ in 0..2 {
                    peer.send_to(b"data", socket.local_addr().unwrap()).unwrap();
                }
                for _ in 0..2 {
                    socket.send_to(b"fault", to).unwrap();
                }
                std::thread::sleep(Duration::from_millis(60));
                match first {
                    1 => {
                        assert_eq!(
                            socket.recv(&mut [0; 16]).unwrap_err().raw_os_error(),
                            Some(libc::ECONNREFUSED)
                        );
                    }
                    2 => {
                        assert_eq!(
                            socket
                                .send_to(b"x", peer.local_addr().unwrap())
                                .unwrap_err()
                                .raw_os_error(),
                            Some(libc::ECONNREFUSED)
                        );
                    }
                    3 => {
                        let mut pfd = libc::pollfd {
                            fd,
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        assert_eq!(unsafe { libc::poll(&mut pfd, 1, 0) }, 1);
                        assert_eq!(pfd.revents & libc::POLLIN, libc::POLLIN);
                    }
                    4 => assert!(drain(fd).is_empty()),
                    5 => set(fd, libc::SOL_SOCKET, libc::SO_BROADCAST, 1),
                    _ => {}
                }
                assert_eq!(
                    mem(fd)[0],
                    2 * snare::sys_limits().skb_small_truesize as u32
                );
                assert!(drain(fd).is_empty());
                socket.take_error().unwrap();
                let mut data = [0; 16];
                assert_eq!(socket.recv(&mut data).unwrap(), 4);
                assert_eq!(socket.recv(&mut data).unwrap(), 4);
                assert_eq!(mem(fd)[0], 0);
            });
        }
    }
}
