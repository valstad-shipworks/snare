#![cfg(target_os = "linux")]

//! The socket-buffer model (src/limits.rs) against the kernel of the machine under test, beyond
//! what `socket_limits.rs`'s loopback truth covers. scripts/measure-sockbuf.sh measured stock
//! kernels in QEMU; a hardware host runs its own configuration (a PREEMPT_RT or vendor kernel,
//! tuned sysctls), and a datagram that arrives through a NIC is charged the receive buffer its
//! driver allocated, not what loopback allocates.
//!
//! - `hw_sockbuf_limits_match`: [`SysLimits::from_real_host`] against this host's sysctls, then
//!   `SO_RCVBUF`/`SO_SNDBUF`/`SO_*BUFFORCE` rounding and clamping on a real socket and in a sim
//!   built from it. Where this host differs from the stock table ([`SysLimits::host`]) it is
//!   noted, not failed: the stock table describes stock kernels.
//! - `hw_sockbuf_peer_truesize_matches` (needs `SNARE_HW_PEER`): the `SK_MEMINFO_RMEM_ALLOC` a
//!   lone datagram leaves queued when it came back from the peer through the NIC, against the
//!   sim's `truesize` for the same length.
//! - `hw_sockbuf_peer_flood_matches` (needs `SNARE_HW_PEER`): a burst echoed into a small
//!   receive buffer that is not read until it is over — how many datagrams the buffer admitted
//!   and what `SO_RXQ_OVFL` counted as dropped.
//!
//! References: net/core/sock.c (`sk_setsockopt` `SO_RCVBUF`: doubled, at least `SOCK_MIN_RCVBUF`,
//! capped by `rmem_max`), net/ipv4/udp.c (`__udp_enqueue_schedule_skb`), include/net/sock.h
//! (`SOCK_MIN_RCVBUF`), include/uapi/linux/sock_diag.h (`SK_MEMINFO_*`),
//! Documentation/admin-guide/sysctl/net.rst.

#[path = "support/hw.rs"]
mod hw;

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

use hw::linux::{nic_profile, sim_builder};
use hw::need;
use hw::sock::*;
use snare::{Privileges, Sim, SysLimits};

const SO_RXQ_OVFL: i32 = 40;

fn set_int(fd: i32, name: i32, v: i32) -> Result<(), i32> {
    setsockopt(fd, libc::SOL_SOCKET, name, &v)
}

/// `(option, requested value, the set's result, what the option reads back)`.
type BufferStep = (i32, i32, Result<(), i32>, Result<i32, i32>);

/// Each request's result and what the option reads back, for receive and send buffers.
fn buffer_probe(rmem_max: usize, wmem_max: usize) -> Vec<BufferStep> {
    let mut out = Vec::new();
    for (name, force, max) in [
        (libc::SO_RCVBUF, libc::SO_RCVBUFFORCE, rmem_max),
        (libc::SO_SNDBUF, libc::SO_SNDBUFFORCE, wmem_max),
    ] {
        let max = i32::try_from(max).unwrap_or(i32::MAX);
        for (opt, v) in [
            (name, 0),
            (name, 1),
            (name, 1024),
            (name, 2304),
            (name, 65_536),
            (name, max),
            (name, max.saturating_add(1)),
            (name, i32::MAX),
            (name, -1),
            (force, 65_536),
            (force, max.saturating_mul(2)),
        ] {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            let fd = sock.as_raw_fd();
            let set = set_int(fd, opt, v);
            out.push((opt, v, set, getsockopt_int(fd, libc::SOL_SOCKET, name)));
        }
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        out.push((
            name,
            -2,
            Ok(()),
            getsockopt_int(sock.as_raw_fd(), libc::SOL_SOCKET, name),
        ));
    }
    out
}

#[test]
fn hw_sockbuf_limits_match() {
    let real_limits = SysLimits::from_real_host().expect("this host's sysctls");
    let stock = SysLimits::host();
    if real_limits != stock {
        hw::note(&format!(
            "this host differs from the stock table: real {real_limits:?}, stock {stock:?} ({})",
            hw::hw().kernel
        ));
    }
    let (rmem_max, wmem_max) = (real_limits.rmem_max, real_limits.wmem_max);
    let real = snare::real(|| buffer_probe(rmem_max, wmem_max));
    let sim = Sim::builder()
        .sys_limits(real_limits.clone())
        .privileges(Privileges::from_real_process().unwrap())
        .build()
        .run(|| buffer_probe(rmem_max, wmem_max));
    for (r, s) in real.iter().zip(&sim) {
        assert_eq!(
            s, r,
            "(option, request, set, read back) with {real_limits:?}"
        );
    }
}

/// The interface's first address in the peer's family that is not link-local.
fn local_for(iface: &str, peer: SocketAddr) -> Option<IpAddr> {
    hw::linux::addresses(iface)
        .into_iter()
        .map(|(ip, _)| ip)
        .find(|ip| {
            ip.is_ipv4() == peer.is_ipv4()
                && !matches!(ip, IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80)
        })
}

fn readable(fd: i32, ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut pfd, 1, ms) == 1 }
}

/// For each length, the receive-buffer charge of one datagram of that length echoed by `peer`.
fn peer_truesizes(local: IpAddr, peer: SocketAddr, lens: &[usize]) -> Vec<(usize, Option<u32>)> {
    let sock = UdpSocket::bind(SocketAddr::new(local, 0)).unwrap();
    let fd = sock.as_raw_fd();
    set_int(fd, libc::SO_RCVBUF, 1 << 20).unwrap();
    let mut buf = vec![0u8; 65_536];
    lens.iter()
        .map(|&len| {
            sock.send_to(&vec![0x33; len], peer).unwrap();
            if !readable(fd, 2000) {
                return (len, None);
            }
            std::thread::sleep(Duration::from_millis(5));
            let charged = meminfo(fd)[0];
            sock.recv(&mut buf).unwrap();
            (len, Some(charged))
        })
        .collect()
}

/// The sim for an exchange with the peer: the real NIC with the peer as a station, this host's
/// limits and privileges, and a reflector inside it. Runs `f` there and stops the reflector.
fn with_sim_peer<R: Send + 'static>(
    iface: &str,
    local: IpAddr,
    peer: SocketAddr,
    f: impl FnOnce() -> R + Send + 'static,
) -> R {
    let (nic, _) = snare::real(|| nic_profile(iface));
    let sim = sim_builder(nic.station(peer.ip()))
        .sys_limits(SysLimits::from_real_host().unwrap())
        .build();
    sim.run(move || {
        let reflector = UdpSocket::bind(peer).unwrap();
        let echo = std::thread::spawn(move || hw::reflect(&reflector, Duration::from_secs(30)));
        let out = f();
        UdpSocket::bind(SocketAddr::new(local, 0))
            .unwrap()
            .send_to(b"quit", peer)
            .unwrap();
        echo.join().unwrap();
        out
    })
}

fn peer_setup() -> Option<(String, SocketAddr, IpAddr)> {
    let h = hw::hw();
    let iface = h.iface.clone()?;
    let peer = h.peer?;
    let local = local_for(&iface, peer)?;
    Some((iface, peer, local))
}

const NEEDS_PEER: &str = "needs a NIC with an address and a second machine running the reflector (set SNARE_HW_IFACE and SNARE_HW_PEER=<ip>[:port])";

#[test]
#[ignore = "hardware: needs a NIC and a peer running the reflector"]
fn hw_sockbuf_peer_truesize_matches() {
    let (iface, peer, local) = need!(peer_setup(), "{NEEDS_PEER}");
    let mtu: usize = hw::linux::sysfs(&iface, "mtu")
        .and_then(|m| m.parse().ok())
        .unwrap_or(1500);
    let header = if peer.is_ipv4() { 28 } else { 48 };
    let mut lens = vec![1, 64, 100, 200, 500, 1000];
    lens.extend([mtu - header - 1, mtu - header, mtu - header + 1, 3000, 9000]);
    let real = snare::real(|| peer_truesizes(local, peer, &lens));
    let lens2 = lens.clone();
    let sim = with_sim_peer(&iface, local, peer, move || {
        peer_truesizes(local, peer, &lens2)
    });
    let driver = hw::hw().driver.clone().unwrap_or_default();
    eprintln!("{iface} ({driver}) MTU {mtu}: (length, real, sim)");
    for ((len, r), (_, s)) in real.iter().zip(&sim) {
        eprintln!("{len:>6} {r:?} {s:?}");
    }
    assert!(
        real.iter().all(|(_, r)| r.is_some()),
        "every datagram came back from {peer} (is the reflector running?)"
    );
    assert_eq!(
        sim, real,
        "receive-buffer charge per echoed datagram through {iface} ({driver})"
    );
}

/// A burst of `count` datagrams of `len` bytes echoed into a socket with `SO_RCVBUF` `rcvbuf`,
/// read only after it is over: how many were queued, and the drop count `SO_RXQ_OVFL` reported
/// with the last of them.
fn flood(
    local: IpAddr,
    peer: SocketAddr,
    rcvbuf: i32,
    count: usize,
    len: usize,
) -> (usize, Option<u32>) {
    let sock = UdpSocket::bind(SocketAddr::new(local, 0)).unwrap();
    let fd = sock.as_raw_fd();
    set_int(fd, libc::SO_RCVBUF, rcvbuf).unwrap();
    set_int(fd, SO_RXQ_OVFL, 1).unwrap();
    let payload = vec![0x44; len];
    for _ in 0..count {
        sock.send_to(&payload, peer).unwrap();
    }
    std::thread::sleep(Duration::from_millis(500));
    let mut queued = 0;
    let mut dropped = None;
    loop {
        let got = recvmsg(fd, len + 1, libc::MSG_DONTWAIT);
        if got.n.is_err() {
            break;
        }
        queued += 1;
        if let Some((_, _, v)) = got
            .cmsgs
            .iter()
            .find(|(l, t, _)| *l == libc::SOL_SOCKET && *t == SO_RXQ_OVFL)
        {
            dropped = Some(u32::from_ne_bytes(v[..4].try_into().unwrap()));
        }
    }
    (queued, dropped)
}

#[test]
#[ignore = "hardware: needs a NIC and a peer running the reflector"]
fn hw_sockbuf_peer_flood_matches() {
    let (iface, peer, local) = need!(peer_setup(), "{NEEDS_PEER}");
    let cases = [(4096, 64, 100), (16_384, 64, 1000), (65_536, 200, 1400)];
    let real: Vec<_> = cases
        .iter()
        .map(|&(b, n, l)| snare::real(|| flood(local, peer, b, n, l)))
        .collect();
    let sim = with_sim_peer(&iface, local, peer, move || {
        cases
            .iter()
            .map(|&(b, n, l)| flood(local, peer, b, n, l))
            .collect::<Vec<_>>()
    });
    for ((case, r), s) in cases.iter().zip(&real).zip(&sim) {
        eprintln!(
            "SO_RCVBUF {} x{} of {} bytes: real {r:?} sim {s:?}",
            case.0, case.1, case.2
        );
    }
    assert!(
        real.iter().all(|r| r.0 > 0),
        "the bursts came back from {peer} (is the reflector running?)"
    );
    assert_eq!(
        sim.iter().map(|s| s.0).collect::<Vec<_>>(),
        real.iter().map(|r| r.0).collect::<Vec<_>>(),
        "datagrams admitted per burst (SO_RCVBUF, count, length) {cases:?}"
    );
    for ((case, r), s) in cases.iter().zip(&real).zip(&sim) {
        if r.1 != s.1 {
            hw::note(&format!(
                "SO_RXQ_OVFL after a burst {case:?}: real {:?}, sim {:?} (the wire and the peer may drop too)",
                r.1, s.1
            ));
        }
    }
}
