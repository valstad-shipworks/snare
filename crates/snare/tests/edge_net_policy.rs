#![cfg(unix)]

//! Link policies replay exactly from a seed. With a fixed seed, which datagrams a `UdpPolicy` or a
//! `NicPolicy` (and both compounded) delivers, loses and duplicates, each copy's arrival stamp
//! (`SO_TIMESTAMP`, relative to the first send) and the `RecordedEvent::Link` entries are pinned to
//! goldens under `tests/golden/`, on the free-running virtual clock and under `deterministic()`.
//! Also pinned: a second run with the same seed is identical, a jittery `TcpPolicy` or `NicPolicy`
//! never reorders TCP bytes (with exact read times), and a link that goes down while a datagram or
//! TCP bytes are in flight drops or stalls them with exact counters and arrival times.

#[path = "support/golden.rs"]
mod golden;

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::mem::size_of;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use snare::{
    IpNet, NicPolicy, NicSpec, RecordedEvent, Sim, SimBuilder, nic_counters, schedule_link,
    set_tcp_policy, set_udp_policy,
};

const MS: Duration = Duration::from_millis(1);

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn realtime() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

fn stamp_on(sock: &UdpSocket) {
    let on: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMP,
            (&on as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as u32,
        )
    };
    assert_eq!(rc, 0, "SO_TIMESTAMP");
}

#[repr(C, align(8))]
struct Control([u8; 256]);

/// One nonblocking `recvmsg`: the payload and its `SCM_TIMESTAMP`, or `None` once the queue is
/// empty.
#[allow(clippy::unnecessary_cast)]
fn recv_stamped(sock: &UdpSocket) -> Option<(Vec<u8>, Duration)> {
    let mut data = [0u8; 64];
    let mut control = Control([0; 256]);
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = control.0.len() as _;
    let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        let e = std::io::Error::last_os_error();
        assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock, "recvmsg: {e}");
        return None;
    }
    let hdr: libc::cmsghdr = unsafe { control.0.as_ptr().cast::<libc::cmsghdr>().read_unaligned() };
    assert!(
        msg.msg_controllen as usize >= size_of::<libc::cmsghdr>(),
        "a stamp"
    );
    assert_eq!(
        (hdr.cmsg_level, hdr.cmsg_type),
        (libc::SOL_SOCKET, libc::SCM_TIMESTAMP)
    );
    let at = unsafe { libc::CMSG_LEN(0) } as usize;
    let tv: libc::timeval = unsafe {
        control
            .0
            .as_ptr()
            .add(at)
            .cast::<libc::timeval>()
            .read_unaligned()
    };
    let stamp = Duration::new(tv.tv_sec as u64, tv.tv_usec as u32 * 1000);
    Some((data[..n as usize].to_vec(), stamp))
}

/// Every datagram queued at `sock`, in receive order, as `index @ µs after t0` lines.
fn drain(sock: &UdpSocket, t0: Duration, out: &mut String) -> Vec<u8> {
    let mut got = Vec::new();
    while let Some((data, stamp)) = recv_stamped(sock) {
        let rel = stamp.checked_sub(t0).expect("stamped after the first send");
        writeln!(out, "rx {} @ {}us", data[0], rel.as_micros()).unwrap();
        got.push(data[0]);
    }
    got
}

/// The run's `Link` entries as `fault from->to len @ µs after t0` lines.
fn link_lines(sim: &Sim, out: &mut String) {
    for entry in sim.recorded_events() {
        if let RecordedEvent::Link {
            from,
            to,
            len,
            fault,
        } = entry.event
        {
            writeln!(
                out,
                "link {fault:?} {from}->{to} len {len} @ {}us",
                entry.at.as_micros()
            )
            .unwrap();
        }
    }
}

/// 48 one-byte datagrams, 100 µs apart, from 127.0.0.1:41000 to 127.0.0.1:41001 under a lossy,
/// duplicating, jittery `UdpPolicy`, received with their arrival stamps.
fn udp_policy_run(builder: SimBuilder) -> String {
    let sim = builder.build();
    let mut out = sim.run(|| {
        let rx = UdpSocket::bind("127.0.0.1:41001").unwrap();
        stamp_on(&rx);
        set_udp_policy("127.0.0.1:41001", |p| {
            p.latency = 2 * MS;
            p.jitter = 3 * MS;
            p.loss_rate = 0.2;
            p.duplicate_rate = 0.2;
        });
        let tx = UdpSocket::bind("127.0.0.1:41000").unwrap();
        let t0 = realtime();
        for i in 0..48u8 {
            tx.send_to(&[i], "127.0.0.1:41001").unwrap();
            std::thread::sleep(Duration::from_micros(100));
        }
        std::thread::sleep(20 * MS);
        let mut out = String::new();
        drain(&rx, t0, &mut out);
        out
    });
    link_lines(&sim, &mut out);
    out
}

fn eth0(policy: NicPolicy) -> NicSpec {
    NicSpec::new("eth0")
        .index(4)
        .address(net("10.0.0.1/24"))
        .station(ip("10.0.0.2"))
        .policy(policy)
}

/// 48 datagrams from the host to a station across eth0, whose `NicPolicy` and the station's
/// `UdpPolicy` both lose, duplicate and delay, so their draws compound.
fn nic_policy_run(builder: SimBuilder) -> String {
    let sim = builder
        .nic(eth0(NicPolicy {
            latency: MS,
            jitter: 2 * MS,
            loss_rate: 0.15,
            duplicate_rate: 0.15,
        }))
        .build();
    let mut out = sim.run(|| {
        let station = UdpSocket::bind("10.0.0.2:42001").unwrap();
        stamp_on(&station);
        set_udp_policy("10.0.0.2:42001", |p| {
            p.jitter = MS;
            p.loss_rate = 0.1;
            p.duplicate_rate = 0.1;
        });
        let host = UdpSocket::bind("10.0.0.1:42000").unwrap();
        let t0 = realtime();
        for i in 0..48u8 {
            host.send_to(&[i], "10.0.0.2:42001").unwrap();
            std::thread::sleep(Duration::from_micros(50));
        }
        std::thread::sleep(20 * MS);
        let mut out = String::new();
        drain(&station, t0, &mut out);
        let c = nic_counters("eth0").unwrap();
        writeln!(
            out,
            "eth0 tx {} {}B rx {} {}B dropped tx {} rx {}",
            c.tx_packets, c.tx_bytes, c.rx_packets, c.rx_bytes, c.tx_dropped, c.rx_dropped
        )
        .unwrap();
        out
    });
    link_lines(&sim, &mut out);
    out
}

#[test]
fn udp_policy_sequence_is_golden() {
    let out = udp_policy_run(Sim::builder().seed(0x5eed));
    assert_eq!(
        out,
        udp_policy_run(Sim::builder().seed(0x5eed)),
        "the seed replays"
    );
    assert_ne!(
        out,
        udp_policy_run(Sim::builder().seed(0x5eee)),
        "another seed differs"
    );
    golden::check_text("edge_net_policy_udp.txt", &out);
}

#[test]
fn udp_policy_sequence_is_golden_deterministic() {
    let out = udp_policy_run(Sim::builder().seed(0x5eed).deterministic());
    assert_eq!(
        out,
        udp_policy_run(Sim::builder().seed(0x5eed).deterministic())
    );
    golden::check_text("edge_net_policy_udp_deterministic.txt", &out);
}

#[test]
fn nic_and_udp_policies_compound_golden() {
    let out = nic_policy_run(Sim::builder().seed(77));
    assert_eq!(
        out,
        nic_policy_run(Sim::builder().seed(77)),
        "the seed replays"
    );
    golden::check_text("edge_net_policy_nic.txt", &out);
}

#[test]
fn nic_and_udp_policies_compound_golden_deterministic() {
    let out = nic_policy_run(Sim::builder().seed(77).deterministic());
    assert_eq!(out, nic_policy_run(Sim::builder().seed(77).deterministic()));
    golden::check_text("edge_net_policy_nic_deterministic.txt", &out);
}

/// Every datagram's copies: without duplication each index arrives at most once, duplicates arrive
/// exactly twice, and lost plus delivered accounts for all 48 against the `Link` log.
#[test]
fn every_datagram_is_accounted_for_by_the_link_log() {
    let sim = Sim::builder().seed(9).build();
    let got = sim.run(|| {
        let rx = UdpSocket::bind("127.0.0.1:43001").unwrap();
        stamp_on(&rx);
        set_udp_policy("127.0.0.1:43001", |p| {
            p.loss_rate = 0.3;
            p.duplicate_rate = 0.3;
            p.jitter = MS;
        });
        let tx = UdpSocket::bind("127.0.0.1:43000").unwrap();
        let t0 = realtime();
        for i in 0..48u8 {
            tx.send_to(&[i], "127.0.0.1:43001").unwrap();
        }
        std::thread::sleep(5 * MS);
        drain(&rx, t0, &mut String::new())
    });
    let mut lost = 0;
    let mut doubled = 0;
    for entry in sim.recorded_events() {
        if let RecordedEvent::Link { fault, .. } = entry.event {
            match fault {
                snare::LinkFault::Lost => lost += 1,
                snare::LinkFault::Duplicated => doubled += 1,
                snare::LinkFault::TooBig => panic!("no MTU set"),
            }
        }
    }
    assert_eq!(got.len(), 48 - lost + doubled);
    for i in 0..48u8 {
        let n = got.iter().filter(|&&b| b == i).count();
        assert!(n <= 2, "{i} arrived {n} times");
    }
    assert_eq!(
        got.iter()
            .filter(|&&b| got.iter().filter(|&&c| c == b).count() == 2)
            .count(),
        2 * doubled
    );
}

/// A `UdpPolicy` MTU drops exactly the datagrams longer than it, logging `TooBig` without drawing
/// from the seed: the loss pattern of the datagrams that fit is the same with or without the
/// oversized ones interleaved.
#[test]
fn policy_mtu_boundary_draws_nothing() {
    let run = |with_big: bool| {
        let sim = Sim::builder().seed(3).build();
        let got = sim.run(|| {
            let rx = UdpSocket::bind("127.0.0.1:44001").unwrap();
            set_udp_policy("127.0.0.1:44001", |p| {
                p.mtu = Some(8);
                p.loss_rate = 0.5;
            });
            let tx = UdpSocket::bind("127.0.0.1:44000").unwrap();
            for i in 0..32u8 {
                tx.send_to(&[i; 8], "127.0.0.1:44001").unwrap();
                if with_big {
                    tx.send_to(&[i; 9], "127.0.0.1:44001").unwrap();
                }
            }
            rx.set_nonblocking(true).unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 16];
            while let Ok((n, _)) = rx.recv_from(&mut buf) {
                assert_eq!(n, 8);
                got.push(buf[0]);
            }
            got
        });
        let too_big = sim
            .recorded_events()
            .iter()
            .filter(|e| {
                matches!(
                    e.event,
                    RecordedEvent::Link {
                        fault: snare::LinkFault::TooBig,
                        len: 9,
                        ..
                    }
                )
            })
            .count();
        (got, too_big)
    };
    let (plain, none) = run(false);
    let (mixed, big) = run(true);
    assert_eq!(none, 0);
    assert_eq!(big, 32);
    assert_eq!(plain, mixed);
    assert!(!plain.is_empty() && plain.len() < 32, "{plain:?}");
}

/// Reads one byte at a time, noting each byte and the µs since `t0` when the read returned.
fn read_each(server: &mut TcpStream, n: usize, t0: Instant, out: &mut String) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0u8; 1];
    for _ in 0..n {
        server.read_exact(&mut buf).unwrap();
        got.push(buf[0]);
        writeln!(out, "read {} @ {}us", buf[0], t0.elapsed().as_micros()).unwrap();
    }
    got
}

/// 40 one-byte writes under a `TcpPolicy` with jitter far larger than the gap between writes:
/// read back one byte at a time, every byte is in order and the read times are golden.
fn tcp_jitter_run(builder: SimBuilder) -> String {
    builder.build().run(|| {
        let listener = TcpListener::bind("127.0.0.1:45001").unwrap();
        set_tcp_policy("127.0.0.1:45001", |p| {
            p.latency = MS;
            p.jitter = 10 * MS;
        });
        let mut client = TcpStream::connect("127.0.0.1:45001").unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let t0 = Instant::now();
        for i in 0..40u8 {
            client.write_all(&[i]).unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        let mut out = String::new();
        let got = read_each(&mut server, 40, t0, &mut out);
        assert_eq!(got, (0..40).collect::<Vec<u8>>(), "TCP never reorders");
        out
    })
}

#[test]
fn tcp_jitter_never_reorders_golden() {
    let out = tcp_jitter_run(Sim::builder().seed(21));
    assert_eq!(out, tcp_jitter_run(Sim::builder().seed(21)));
    golden::check_text(
        &format!("edge_net_policy_tcp_jitter.{}.txt", std::env::consts::OS),
        &out,
    );
}

#[test]
fn tcp_jitter_never_reorders_golden_deterministic() {
    let out = tcp_jitter_run(Sim::builder().seed(21).deterministic());
    golden::check_text(
        &format!(
            "edge_net_policy_tcp_jitter_deterministic.{}.txt",
            std::env::consts::OS
        ),
        &out,
    );
}

/// The same across an interface whose `NicPolicy` jitters: bytes stay in order.
#[test]
fn nic_jitter_never_reorders_tcp_golden() {
    let out = Sim::builder()
        .seed(22)
        .nic(eth0(NicPolicy {
            latency: MS,
            jitter: 8 * MS,
            ..NicPolicy::default()
        }))
        .build()
        .run(|| {
            let listener = TcpListener::bind("10.0.0.2:45002").unwrap();
            let mut client = TcpStream::connect("10.0.0.2:45002").unwrap();
            let (mut server, _) = listener.accept().unwrap();
            let t0 = Instant::now();
            for i in 0..40u8 {
                client.write_all(&[i]).unwrap();
            }
            let mut out = String::new();
            let got = read_each(&mut server, 40, t0, &mut out);
            assert_eq!(got, (0..40).collect::<Vec<u8>>());
            out
        });
    golden::check_text(
        &format!(
            "edge_net_policy_nic_tcp_jitter.{}.txt",
            std::env::consts::OS
        ),
        &out,
    );
}

/// eth0 with 10 ms latency: datagram 0 leaves at 0 and is in flight when the link drops at 4 ms
/// (discarded), datagram 1 is sent while it is down (a carrier drop), the link returns at 6 ms and
/// datagram 2 sent at 7 ms lands at 17 ms. Pinned as the arrivals and eth0's counters.
fn flap_mid_flight_run(builder: SimBuilder) -> String {
    builder
        .nic(eth0(NicPolicy {
            latency: 10 * MS,
            ..NicPolicy::default()
        }))
        .build()
        .run(|| {
            let station = UdpSocket::bind("10.0.0.2:46001").unwrap();
            stamp_on(&station);
            let host = UdpSocket::bind("10.0.0.1:46000").unwrap();
            let t0 = realtime();
            schedule_link("eth0", 4 * MS, false).unwrap();
            host.send_to(&[0], "10.0.0.2:46001").unwrap();
            std::thread::sleep(5 * MS);
            host.send_to(&[1], "10.0.0.2:46001").unwrap();
            schedule_link("eth0", MS, true).unwrap();
            std::thread::sleep(2 * MS);
            host.send_to(&[2], "10.0.0.2:46001").unwrap();
            std::thread::sleep(20 * MS);
            let mut out = String::new();
            let got = drain(&station, t0, &mut out);
            assert_eq!(got, [2]);
            let c = nic_counters("eth0").unwrap();
            writeln!(
                out,
                "eth0 tx {} {}B dropped {} carrier {} rx {} rx_dropped {}",
                c.tx_packets,
                c.tx_bytes,
                c.tx_dropped,
                c.tx_carrier_errors,
                c.rx_packets,
                c.rx_dropped
            )
            .unwrap();
            out
        })
}

#[test]
fn link_down_mid_flight_drops_datagrams_golden() {
    let out = flap_mid_flight_run(Sim::builder().seed(1));
    assert_eq!(
        out,
        flap_mid_flight_run(Sim::builder().seed(1).deterministic())
    );
    golden::check_text("edge_net_policy_flap_udp.txt", &out);
}

/// TCP bytes in flight when the link goes down are not lost: written at 0 with 10 ms latency, the
/// link down from 4 ms to 30 ms, they arrive once it returns, in order with what was written while
/// it was down.
fn tcp_flap_run(builder: SimBuilder) -> String {
    builder
        .nic(eth0(NicPolicy {
            latency: 10 * MS,
            ..NicPolicy::default()
        }))
        .build()
        .run(|| {
            let listener = TcpListener::bind("10.0.0.2:46002").unwrap();
            let mut client = TcpStream::connect("10.0.0.2:46002").unwrap();
            let (mut server, _) = listener.accept().unwrap();
            let t0 = Instant::now();
            schedule_link("eth0", 4 * MS, false).unwrap();
            client.write_all(b"ab").unwrap();
            std::thread::sleep(5 * MS);
            client.write_all(b"cd").unwrap();
            schedule_link("eth0", 25 * MS, true).unwrap();
            let mut out = String::new();
            let got = read_each(&mut server, 4, t0, &mut out);
            assert_eq!(got, b"abcd");
            out
        })
}

#[test]
fn link_down_mid_flight_stalls_tcp_golden() {
    let out = tcp_flap_run(Sim::builder().seed(1));
    assert_eq!(out, tcp_flap_run(Sim::builder().seed(1)));
    golden::check_text("edge_net_policy_flap_tcp.txt", &out);
}

/// A sender's address is part of the `Link` entry and the policy at the destination decides: a
/// lossy policy on the sender's own address does nothing to what it sends.
#[test]
fn policy_applies_at_the_destination_only() {
    let sim = Sim::builder().seed(4).build();
    let got = sim.run(|| {
        let rx = UdpSocket::bind("127.0.0.1:47001").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:47000").unwrap();
        set_udp_policy("127.0.0.1:47000", |p| p.loss_rate = 1.0);
        for i in 0..8u8 {
            tx.send_to(&[i], "127.0.0.1:47001").unwrap();
        }
        rx.send_to(b"x", "127.0.0.1:47000").unwrap();
        rx.set_nonblocking(true).unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4];
        while let Ok((n, _)) = rx.recv_from(&mut buf) {
            got.extend_from_slice(&buf[..n]);
        }
        got
    });
    assert_eq!(got, (0..8).collect::<Vec<u8>>());
    let links: Vec<_> = sim
        .recorded_events()
        .into_iter()
        .filter_map(|e| match e.event {
            RecordedEvent::Link {
                from,
                to,
                len,
                fault,
            } => Some((from, to, len, fault)),
            _ => None,
        })
        .collect();
    let from: SocketAddr = "127.0.0.1:47001".parse().unwrap();
    let to: SocketAddr = "127.0.0.1:47000".parse().unwrap();
    assert_eq!(links, [(from, to, 1, snare::LinkFault::Lost)]);
}
