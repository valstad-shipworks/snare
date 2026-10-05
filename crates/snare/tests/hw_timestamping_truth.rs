#![cfg(target_os = "linux")]

//! Packet timestamps through a real NIC against the sim's model (src/tstamp.rs and the
//! `SIOC[GS]HWTSTAMP` handling of src/simhost.rs): the device's hardware timestamping
//! configuration, `SO_TIMESTAMPING`'s `BIND_PHC`, and, with a peer running the reflector
//! (`SNARE_HW_PEER`), the control messages and error-queue entries of datagrams that really
//! cross the wire — which slots of `struct scm_timestamping` are filled, how many entries each
//! send queues, their `sock_extended_err` (`ee_origin`, `ee_info`, the `OPT_ID` key in
//! `ee_data`) and what `OPT_TSONLY` loops back. The sim's side is a `Nic` built from the real
//! interface with the peer as a station, answered by a reflector inside the sim.
//!
//! Hardware stamps need the NIC configured with `SIOCSHWTSTAMP`, which changes it: only with
//! `SNARE_HW_MUTATE=1` (the configuration is restored), or when another program (ptp4l) has
//! already turned on transmit stamps and `HWTSTAMP_FILTER_ALL`. Otherwise the exchange runs with
//! software stamps.
//!
//! References: Documentation/networking/timestamping.rst; include/uapi/linux/net_tstamp.h
//! (`SOF_TIMESTAMPING_*`, `struct hwtstamp_config`, `HWTSTAMP_*`), errqueue.h
//! (`struct sock_extended_err`, `SCM_TSTAMP_*`); net/core/dev_ioctl.c (`dev_set_hwtstamp`,
//! `net_hwtstamp_validate`); net/core/sock.c (`sock_timestamping_bind_phc`).

#[path = "support/hw.rs"]
mod hw;

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

use hw::linux::{IfreqData, nic_profile, sim_with};
use hw::sock::*;
use hw::{need, require};

const SIOCSHWTSTAMP: u64 = 0x89b0;
const SIOCGHWTSTAMP: u64 = 0x89b1;
const HWTSTAMP_TX_OFF: i32 = 0;
const HWTSTAMP_TX_ON: i32 = 1;
const HWTSTAMP_FILTER_NONE: i32 = 0;
const HWTSTAMP_FILTER_ALL: i32 = 1;
const HWTSTAMP_FILTER_PTP_V2_L4_EVENT: i32 = 6;
const HWTSTAMP_FILTER_PTP_V2_EVENT: i32 = 12;

const NEEDS_IFACE: &str = "needs a wired NIC (set SNARE_HW_IFACE=<name>)";

/// `SIOCGHWTSTAMP` / `SIOCSHWTSTAMP` with `struct hwtstamp_config { flags, tx_type, rx_filter }`;
/// the config the kernel wrote back, or the errno.
fn hwtstamp(iface: &str, request: u64, cfg: [i32; 3]) -> Result<[i32; 3], i32> {
    let mut cfg = cfg;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    let mut req = IfreqData::new(iface, cfg.as_mut_ptr().cast());
    let rc = unsafe { libc::ioctl(fd, request as _, &mut req) };
    let e = errno();
    unsafe { libc::close(fd) };
    if rc == 0 { Ok(cfg) } else { Err(e) }
}

/// The device's timestamping configuration at the start, set back when dropped.
struct RestoreHwtstamp {
    iface: String,
    saved: [i32; 3],
}

impl Drop for RestoreHwtstamp {
    fn drop(&mut self) {
        let back = snare::real(|| hwtstamp(&self.iface, SIOCSHWTSTAMP, self.saved));
        if let Err(e) = back {
            eprintln!(
                "could not restore {}'s hwtstamp_config {:?}: errno {e}",
                self.iface, self.saved
            );
        }
    }
}

/// Reading the configuration needs no privilege; a device starts with transmit stamps off and no
/// receive filter, which is all the sim's NIC can start with.
#[test]
#[ignore = "hardware: needs a NIC"]
fn hw_hwtstamp_get_matches() {
    let iface = need!(hw::hw().iface.clone(), "{NEEDS_IFACE}");
    let real = snare::real(|| hwtstamp(&iface, SIOCGHWTSTAMP, [0; 3]));
    if let Ok(cfg) = real {
        require!(
            cfg == [0, HWTSTAMP_TX_OFF, HWTSTAMP_FILTER_NONE],
            "{iface}'s timestamping is already configured {cfg:?} (stop ptp4l or whatever set it)"
        );
    }
    let (nic, _) = snare::real(|| nic_profile(&iface));
    let sim = sim_with(nic).run(|| hwtstamp(&iface, SIOCGHWTSTAMP, [0; 3]));
    assert_eq!(sim, real, "SIOCGHWTSTAMP on {iface}");
}

/// A sequence of `SIOCSHWTSTAMP` requests, each answered with the configuration the driver
/// applied (it may widen a filter, as igb turns PTP filters into `HWTSTAMP_FILTER_ALL` on an
/// i210) and read back; out-of-range types and unknown flags are refused by the core.
#[test]
#[ignore = "hardware: needs a NIC with hardware timestamping, CAP_NET_ADMIN and SNARE_HW_MUTATE=1"]
fn hw_hwtstamp_set_matches() {
    let h = hw::hw();
    let iface = need!(h.iface.clone(), "{NEEDS_IFACE}");
    require!(
        h.mutate,
        "changes {iface}'s timestamping configuration (set SNARE_HW_MUTATE=1; it is restored after)"
    );
    require!(
        h.cap(hw::CAP_NET_ADMIN),
        "needs CAP_NET_ADMIN (run as root)"
    );
    let saved = need!(
        snare::real(|| hwtstamp(&iface, SIOCGHWTSTAMP, [0; 3])).ok(),
        "needs a driver that reports its timestamping configuration (SIOCGHWTSTAMP)"
    );
    let _lock = hw::nic_lock();
    let (nic, _) = snare::real(|| nic_profile(&iface));
    let _restore = RestoreHwtstamp {
        iface: iface.clone(),
        saved,
    };
    let probe = || {
        let mut out = Vec::new();
        for cfg in [
            [0, HWTSTAMP_TX_ON, HWTSTAMP_FILTER_ALL],
            [0, HWTSTAMP_TX_ON, HWTSTAMP_FILTER_PTP_V2_EVENT],
            [0, HWTSTAMP_TX_OFF, HWTSTAMP_FILTER_PTP_V2_L4_EVENT],
            [0, 99, HWTSTAMP_FILTER_NONE],
            [0, HWTSTAMP_TX_OFF, 99],
            [2, HWTSTAMP_TX_OFF, HWTSTAMP_FILTER_NONE],
            [0, HWTSTAMP_TX_OFF, HWTSTAMP_FILTER_NONE],
        ] {
            out.push((
                cfg,
                hwtstamp(&iface, SIOCSHWTSTAMP, cfg),
                hwtstamp(&iface, SIOCGHWTSTAMP, [0; 3]),
            ));
        }
        out
    };
    let real = snare::real(probe);
    let sim = sim_with(nic).run(probe);
    for (r, s) in real.iter().zip(&sim) {
        assert_eq!(s, r, "SIOCSHWTSTAMP {:?} -> (applied, read back)", r.0);
    }
}

/// `SOF_TIMESTAMPING_BIND_PHC` names a PHC virtual clock of the device the socket is bound to:
/// unbound it is `EOPNOTSUPP`, bound to the device with its physical PHC (not a vclock) `EINVAL`.
#[test]
#[ignore = "hardware: needs a NIC with a PTP clock"]
fn hw_bind_phc_matches() {
    let iface = need!(hw::hw().iface.clone(), "{NEEDS_IFACE}");
    let phc = snare::real(|| hw::linux::ts_info(&iface))
        .map(|t| t.phc_index)
        .unwrap_or(-1);
    require!(
        phc >= 0,
        "needs a NIC with a PTP hardware clock ({iface} reports phc_index {phc})"
    );
    let (nic, _) = snare::real(|| nic_profile(&iface));
    let probe = || {
        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        let fd = sock.as_raw_fd();
        let req = [SOF_FLAGS | BIND_PHC, phc as u32];
        let unbound = setsockopt(fd, libc::SOL_SOCKET, SO_TIMESTAMPING, &req);
        let bound = setsockopt_bytes(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface.as_bytes(),
        );
        let after = setsockopt(fd, libc::SOL_SOCKET, SO_TIMESTAMPING, &req);
        (unbound, bound, after)
    };
    let real = snare::real(probe);
    let sim = sim_with(nic).run(probe);
    assert_eq!(
        sim, real,
        "(unbound, SO_BINDTODEVICE {iface}, bound) with phc {phc}"
    );
}

const SOF_FLAGS: u32 = TX_SOFTWARE | RX_SOFTWARE | SOFTWARE;

fn setsockopt_bytes(fd: i32, level: i32, name: i32, value: &[u8]) -> Result<(), i32> {
    let rc =
        unsafe { libc::setsockopt(fd, level, name, value.as_ptr().cast(), value.len() as u32) };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

/// A control message reduced to what both sides must agree on: level, type and length, the
/// filled `scm_timestamping` slots, and `sock_extended_err`'s errno, origin, info and data.
type CmsgShape = (i32, i32, usize, Option<[bool; 3]>, Option<[u32; 4]>);

fn shape(got: &Got) -> (Result<usize, i32>, i32, Vec<CmsgShape>) {
    let msgs = got
        .cmsgs
        .iter()
        .map(|(level, ty, data)| {
            let slots = (*level == libc::SOL_SOCKET && *ty == SO_TIMESTAMPING && data.len() >= 48)
                .then(|| filled_slots(data));
            let ee = (*ty == libc::IP_RECVERR || *ty == libc::IPV6_RECVERR).then(|| {
                let e: libc::sock_extended_err = unsafe {
                    data.as_ptr()
                        .cast::<libc::sock_extended_err>()
                        .read_unaligned()
                };
                [e.ee_errno, u32::from(e.ee_origin), e.ee_info, e.ee_data]
            });
            (*level, *ty, data.len(), slots, ee)
        })
        .collect();
    (got.n, got.flags, msgs)
}

/// Whether `fd` polls with any of `want` within `ms` (`POLLERR` is reported unasked).
fn wait(fd: i32, want: i16, ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: want & !libc::POLLERR,
        revents: 0,
    };
    unsafe { libc::poll(&mut pfd, 1, ms) == 1 && pfd.revents & want != 0 }
}

type Exchange = Vec<(&'static str, (Result<usize, i32>, i32, Vec<CmsgShape>))>;

/// Three datagrams of different sizes to the peer with `flags` on: after each, whether the socket
/// polls `POLLERR`, every error-queue entry it earned (read once the transmit stamps have had
/// time to arrive), then the echo.
fn exchange(local: IpAddr, peer: SocketAddr, flags: u32) -> Exchange {
    let sock = UdpSocket::bind(SocketAddr::new(local, 0)).unwrap();
    let fd = sock.as_raw_fd();
    setsockopt(fd, libc::SOL_SOCKET, SO_TIMESTAMPING, &flags).unwrap();
    let mut out = Vec::new();
    for len in [8usize, 200, 1400] {
        sock.send_to(&vec![0x5a; len], peer).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let polled = wait(fd, libc::POLLERR, 0);
        out.push(("poll POLLERR", (Ok(usize::from(polled)), 0, Vec::new())));
        loop {
            let got = recvmsg(fd, 2048, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT);
            if got.n.is_err() {
                break;
            }
            out.push(("errqueue", shape(&got)));
        }
        if wait(fd, libc::POLLIN, 2000) {
            out.push(("echo", shape(&recvmsg(fd, 2048, libc::MSG_DONTWAIT))));
        } else {
            out.push(("echo", (Err(libc::ETIMEDOUT), 0, Vec::new())));
        }
    }
    out
}

/// The interface's first address in the peer's family.
fn local_for(iface: &str, peer: SocketAddr) -> Option<IpAddr> {
    hw::linux::addresses(iface)
        .into_iter()
        .map(|(ip, _)| ip)
        .find(|ip| {
            ip.is_ipv4() == peer.is_ipv4()
                && !matches!(ip, IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80)
        })
}

/// The same exchange on the real wire and in a sim whose NIC is the real one's with the peer as a
/// station.
fn compare_exchange(iface: &str, peer: SocketAddr, local: IpAddr, flags: u32) {
    let real = snare::real(|| exchange(local, peer, flags));
    let (nic, _) = snare::real(|| nic_profile(iface));
    let sim = sim_with(nic.station(peer.ip())).run(|| {
        let reflector = UdpSocket::bind(peer).unwrap();
        let echo = std::thread::spawn(move || hw::reflect(&reflector, Duration::from_secs(30)));
        let out = exchange(local, peer, flags);
        UdpSocket::bind(SocketAddr::new(local, 0))
            .unwrap()
            .send_to(b"quit", peer)
            .unwrap();
        echo.join().unwrap();
        out
    });
    eprintln!("flags {flags:#x}\nreal: {real:#?}\nsim: {sim:#?}");
    assert!(
        real.iter().any(|(what, r)| *what == "echo" && r.0.is_ok()),
        "the peer at {peer} echoes (is the reflector running?)"
    );
    let differ: Vec<String> = real
        .iter()
        .zip(&sim)
        .enumerate()
        .filter(|(_, (r, s))| r != s)
        .map(|(i, (r, s))| format!("entry {i}: real {r:?}\n      sim  {s:?}"))
        .collect();
    assert!(
        differ.is_empty(),
        "flags {flags:#x}, entries that differ:\n      {}",
        differ.join("\n      ")
    );
    assert_eq!(sim.len(), real.len(), "entries per send (flags {flags:#x})");
}

#[test]
#[ignore = "hardware: needs a NIC and a peer running the reflector"]
fn hw_timestamping_software_exchange_matches() {
    let h = hw::hw();
    let iface = need!(h.iface.clone(), "{NEEDS_IFACE}");
    let peer = need!(
        h.peer,
        "needs a second machine running the reflector (set SNARE_HW_PEER=<ip>[:port])"
    );
    let local = need!(
        local_for(&iface, peer),
        "needs an address on {iface} in {peer}'s family"
    );
    compare_exchange(&iface, peer, local, SOF_FLAGS | OPT_ID);
    compare_exchange(
        &iface,
        peer,
        local,
        SOF_FLAGS | OPT_ID | OPT_TSONLY | TX_SCHED,
    );
}

#[test]
#[ignore = "hardware: needs a NIC with hardware timestamping, a peer running the reflector, and SNARE_HW_MUTATE=1 or ptp4l"]
fn hw_timestamping_hardware_exchange_matches() {
    let h = hw::hw();
    let iface = need!(h.iface.clone(), "{NEEDS_IFACE}");
    let peer = need!(
        h.peer,
        "needs a second machine running the reflector (set SNARE_HW_PEER=<ip>[:port])"
    );
    let local = need!(
        local_for(&iface, peer),
        "needs an address on {iface} in {peer}'s family"
    );
    let current = snare::real(|| hwtstamp(&iface, SIOCGHWTSTAMP, [0; 3]));
    let wanted = [0, HWTSTAMP_TX_ON, HWTSTAMP_FILTER_ALL];
    let _lock = hw::nic_lock();
    let _restore = if current == Ok(wanted) {
        None
    } else {
        require!(
            h.mutate && h.cap(hw::CAP_NET_ADMIN),
            "needs {iface} stamping all packets: run as root with SNARE_HW_MUTATE=1 (restored after), or configure it first (now {current:?})"
        );
        let saved = need!(current.ok(), "needs SIOCGHWTSTAMP on {iface}");
        let applied = snare::real(|| hwtstamp(&iface, SIOCSHWTSTAMP, wanted));
        let restore = RestoreHwtstamp {
            iface: iface.clone(),
            saved,
        };
        require!(
            applied == Ok(wanted),
            "{iface} cannot stamp all packets in hardware (SIOCSHWTSTAMP gave {applied:?})"
        );
        Some(restore)
    };
    let hard = TX_HARDWARE | RX_HARDWARE | RAW_HARDWARE;
    compare_exchange(&iface, peer, local, hard | OPT_ID | OPT_TSONLY);
    compare_exchange(&iface, peer, local, hard | SOF_FLAGS | OPT_ID);
}
