#![cfg(target_os = "linux")]

use std::io::Read;
use std::mem::size_of;
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::time::Duration;

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

fn rmem(fd: i32) -> u32 {
    let mut words = [0u32; 9];
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
    words[0]
}

#[derive(Debug, PartialEq, Eq)]
struct Report {
    write: usize,
    receive_buffer: i32,
    maxseg: i32,
    payload: Vec<u8>,
    charge: u32,
    key: u32,
}

fn probe(write: usize, receive_buffer: i32, maxseg: i32) -> Report {
    probe_with_pending_report(write, receive_buffer, maxseg, false, false)
}

fn probe_with_pending_report(
    write: usize,
    receive_buffer: i32,
    maxseg: i32,
    check_pending: bool,
    delayed: bool,
) -> Report {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    set(
        listener.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_RCVBUF,
        receive_buffer,
    );
    if delayed {
        snare::set_listener_behavior(
            listener.local_addr().unwrap(),
            snare::ListenerBehavior::DelayingUntil(
                std::time::Instant::now() + Duration::from_millis(1),
            ),
        );
    }
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let fd = client.as_raw_fd();
    set(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, 1_000_000);
    set(fd, libc::SOL_TCP, libc::TCP_NODELAY, 1);
    if maxseg != 0 {
        set(fd, libc::SOL_TCP, libc::TCP_MAXSEG, maxseg);
    }
    set(
        fd,
        libc::SOL_SOCKET,
        37,
        (1 << 1) | (1 << 4) | (1 << 7) | (1 << 16),
    );
    let bytes: Vec<_> = (0..write).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        unsafe { libc::send(fd, bytes.as_ptr().cast(), bytes.len(), 0) },
        write as isize
    );
    if check_pending {
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLERR,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 0) }, 0);
        assert_eq!(rmem(fd), 0);
    }
    let (mut server, _) = listener.accept().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut received = vec![0; write];
    server.read_exact(&mut received).unwrap();
    assert_eq!(received, bytes);
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLERR,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 2000) }, 1);
    let charge = rmem(fd);
    let mut data = vec![0u8; write + 256];
    let mut control = [0usize; 64];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = size_of::<[usize; 64]>();
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };
    assert!(n > 0);
    data.truncate(n as usize);
    let mut key = None;
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        if unsafe { (*cmsg).cmsg_level == libc::SOL_IP && (*cmsg).cmsg_type == libc::IP_RECVERR } {
            let error = unsafe {
                libc::CMSG_DATA(cmsg)
                    .cast::<libc::sock_extended_err>()
                    .read_unaligned()
            };
            assert_eq!(error.ee_origin, 4);
            key = Some(error.ee_data);
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    assert_eq!(&data[12..14], &[8, 0]);
    let ip = 14;
    assert_eq!(data[ip] >> 4, 4);
    let tcp = ip + (data[ip] as usize & 15) * 4;
    let start = tcp + ((data[tcp + 12] >> 4) as usize) * 4;
    let payload = data[start..].to_vec();
    assert!(!payload.is_empty());
    assert_eq!(payload, bytes[write - payload.len()..]);
    assert_eq!(rmem(fd), 0);
    Report {
        write,
        receive_buffer,
        maxseg,
        payload,
        charge,
        key: key.unwrap(),
    }
}

#[test]
fn linux_tcp_reports_quote_the_transmitted_tail_and_charge_its_payload() {
    let limits = SysLimits::from_real_host().unwrap();
    for receive_buffer in [4096, 16384, 65536] {
        for write in [32742, 64000, 65536, 128000] {
            let report = probe(write, receive_buffer, 0);
            assert_eq!(report.key, write as u32 - 1);
            assert_eq!(
                report.charge as usize,
                limits.skb_small_truesize + report.payload.len()
            );
        }
    }
}

#[test]
fn large_tcp_timestamp_payload_and_charge_follow_gso_segments_os_truth() {
    let limits = SysLimits::from_real_host().unwrap();
    let mut differences = Vec::new();
    for receive_buffer in [4096, 16384, 65536, 131072, 262144] {
        for write in [32742, 64000, 65536, 128000] {
            let real = probe(write, receive_buffer, 0);
            for deterministic in [false, true] {
                for host in [false, true] {
                    let mut builder = Sim::builder().sys_limits(limits.clone());
                    if deterministic {
                        builder = builder.deterministic();
                    }
                    if host {
                        builder = builder.host(snare::HostProfile::new().build());
                    }
                    let model = builder.build().run(|| probe(write, receive_buffer, 0));
                    if model.payload != real.payload
                        || model.charge != real.charge
                        || model.key != real.key
                    {
                        differences.push((
                            write,
                            receive_buffer,
                            deterministic,
                            host,
                            (model.payload.len(), model.charge, model.key),
                            (real.payload.len(), real.charge, real.key),
                        ));
                    }
                }
            }
        }
    }
    assert!(differences.is_empty(), "{differences:?}");
}

#[test]
fn a_tcp_report_waits_for_the_final_segment_to_transmit_os_truth() {
    let limits = SysLimits::from_real_host().unwrap();
    let real = probe_with_pending_report(128000, 4096, 0, true, false);
    for deterministic in [false, true] {
        for host in [false, true] {
            for delayed in [false, true] {
                let mut builder = Sim::builder().sys_limits(limits.clone());
                if deterministic {
                    builder = builder.deterministic();
                }
                if host {
                    builder = builder.host(snare::HostProfile::new().build());
                }
                let model = builder
                    .build()
                    .run(|| probe_with_pending_report(128000, 4096, 0, true, delayed));
                assert_eq!(
                    model, real,
                    "deterministic={deterministic}, host={host}, delayed={delayed}"
                );
            }
        }
    }
}
