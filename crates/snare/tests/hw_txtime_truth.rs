#![cfg(target_os = "linux")]

//! `SO_TXTIME` and the `etf` qdisc against the sim's model (src/qdisc.rs, the `SO_TXTIME`
//! handling of src/simhost.rs). The socket option needs no hardware and runs on any Linux host;
//! the qdisc sequence replaces the real NIC's root qdisc, so it needs `CAP_NET_ADMIN` and
//! `SNARE_HW_MUTATE=1`, starts only from the kernel's default root qdisc, and deletes its root
//! afterwards, which puts the default back.
//!
//! The sim's NIC is the real one ([`hw::linux::nic_profile`]) with the host's
//! `net.core.default_qdisc`, marked `IFF_NO_QUEUE` when the kernel gave it a `noqueue` root (a
//! virtual device such as veth); `ETHTOOL_GCHANNELS`' maxima stand for the transmit queues the
//! driver allocated. Which transmit queues can launch frames at their time is a driver
//! fact `ethtool` does not report, so the sim is given the queues the real driver accepted an
//! offloaded `etf` on; what the comparison checks is everything else, and the errno each refused
//! queue gets (`EINVAL` for a queue the driver cannot launch on, `EOPNOTSUPP` for a driver
//! without `ndo_setup_tc`).
//!
//! References: net/sched/sch_etf.c (`etf_init`, `validate_input_params`, `etf_enable_offload`),
//! net/sched/sch_api.c (`tc_modify_qdisc`, `tc_get_qdisc`), net/sched/sch_mq.c (`mq_init`),
//! include/uapi/linux/pkt_sched.h (`struct tc_etf_qopt`), include/uapi/linux/net_tstamp.h
//! (`struct sock_txtime`, `SOF_TXTIME_*`), net/core/sock.c (`SO_TXTIME` in `sk_setsockopt`),
//! man 8 tc-etf.

#[path = "support/hw.rs"]
mod hw;

use std::net::UdpSocket;
use std::os::fd::AsRawFd;

use hw::linux::nic_profile;
use hw::sock::{SCM_TXTIME, SO_TXTIME, errno};
use hw::{need, require};
use snare::{HostProfile, Privileges, Sim};

const RTM_NEWQDISC: u16 = 36;
const RTM_DELQDISC: u16 = 37;
const RTM_GETQDISC: u16 = 38;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const TC_H_ROOT: u32 = 0xffff_ffff;
const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const TCA_ETF_PARMS: u16 = 1;
const TC_ETF_OFFLOAD_ON: u32 = 1 << 1;
const MQ_HANDLE: u32 = 0x7ff0_0000;
const SOF_TXTIME_DEADLINE_MODE: u32 = 1 << 0;
const SOF_TXTIME_REPORT_ERRORS: u32 = 1 << 1;

fn put_attr(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    out.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn kind(name: &str) -> Vec<u8> {
    let mut attrs = Vec::new();
    put_attr(&mut attrs, TCA_KIND, format!("{name}\0").as_bytes());
    attrs
}

/// `etf` with `struct tc_etf_qopt { delta, clockid, flags }`.
fn etf(delta: i32, clockid: i32, flags: u32) -> Vec<u8> {
    let mut parms = Vec::new();
    parms.extend_from_slice(&delta.to_ne_bytes());
    parms.extend_from_slice(&clockid.to_ne_bytes());
    parms.extend_from_slice(&flags.to_ne_bytes());
    let mut options = Vec::new();
    put_attr(&mut options, TCA_ETF_PARMS, &parms);
    let mut attrs = kind("etf");
    put_attr(&mut attrs, TCA_OPTIONS, &options);
    attrs
}

/// One rtnetlink request with a `struct tcmsg` body on a fresh socket; every reply message
/// `(type, body)` up to the ack or `NLMSG_DONE`.
fn rtnl(
    ty: u16,
    flags: u16,
    ifindex: u32,
    handle: u32,
    parent: u32,
    attrs: &[u8],
) -> Vec<(u16, Vec<u8>)> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    assert!(fd >= 0, "a NETLINK_ROUTE socket: errno {}", errno());
    let mut body = vec![0u8; 4];
    body.extend_from_slice(&(ifindex as i32).to_ne_bytes());
    body.extend_from_slice(&handle.to_ne_bytes());
    body.extend_from_slice(&parent.to_ne_bytes());
    body.extend_from_slice(&0u32.to_ne_bytes());
    body.extend_from_slice(attrs);
    let mut msg = Vec::new();
    msg.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    msg.extend_from_slice(&ty.to_ne_bytes());
    msg.extend_from_slice(&(flags | NLM_F_REQUEST).to_ne_bytes());
    msg.extend_from_slice(&7u32.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.extend_from_slice(&body);
    assert_eq!(
        unsafe { libc::send(fd, msg.as_ptr().cast(), msg.len(), 0) },
        msg.len() as isize
    );
    let mut out = Vec::new();
    'recv: loop {
        let mut buf = vec![0u8; 65_536];
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        assert!(n > 0, "rtnetlink reply: errno {}", errno());
        let mut at = 0;
        while at + 16 <= n as usize {
            let len = u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
            let t = u16::from_ne_bytes(buf[at + 4..at + 6].try_into().unwrap());
            out.push((t, buf[at + 16..at + len.max(16)].to_vec()));
            if t == NLMSG_ERROR || t == NLMSG_DONE {
                break 'recv;
            }
            at += len.max(16).next_multiple_of(4);
        }
        if flags & NLM_F_DUMP == 0 {
            break;
        }
    }
    unsafe { libc::close(fd) };
    out
}

/// The errno of an acked change, 0 for success.
fn change(ty: u16, ifindex: u32, handle: u32, parent: u32, attrs: &[u8]) -> i32 {
    let r = rtnl(
        ty,
        NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        ifindex,
        handle,
        parent,
        attrs,
    );
    assert_eq!(r.last().map(|m| m.0), Some(NLMSG_ERROR), "an ack");
    -i32::from_ne_bytes(r.last().unwrap().1[..4].try_into().unwrap())
}

/// `(handle, parent, kind, etf (delta, clockid, flags))` of each qdisc on `ifindex`.
type QdiscRow = (u32, u32, String, Option<(i32, i32, u32)>);

fn qdiscs(ifindex: u32) -> Vec<QdiscRow> {
    rtnl(RTM_GETQDISC, NLM_F_DUMP, 0, 0, 0, &[])
        .into_iter()
        .filter(|(t, b)| {
            *t == RTM_NEWQDISC
                && b.len() >= 20
                && u32::from_ne_bytes(b[4..8].try_into().unwrap()) == ifindex
        })
        .map(|(_, b)| {
            let word = |at: usize| u32::from_ne_bytes(b[at..at + 4].try_into().unwrap());
            let mut name = String::new();
            let mut parms = None;
            let mut at = 20;
            while at + 4 <= b.len() {
                let len = u16::from_ne_bytes(b[at..at + 2].try_into().unwrap()) as usize;
                let ty = u16::from_ne_bytes(b[at + 2..at + 4].try_into().unwrap()) & 0x3fff;
                if len < 4 || at + len > b.len() {
                    break;
                }
                let payload = &b[at + 4..at + len];
                if ty == TCA_KIND {
                    name = String::from_utf8_lossy(payload)
                        .trim_end_matches('\0')
                        .to_string();
                }
                if ty == TCA_OPTIONS && name == "etf" && payload.len() >= 16 {
                    let p = &payload[4..16];
                    let i = |o: usize| i32::from_ne_bytes(p[o..o + 4].try_into().unwrap());
                    parms = Some((i(0), i(4), i(8) as u32));
                }
                at += len.next_multiple_of(4);
            }
            (word(8), word(12), name, parms)
        })
        .collect()
}

/// Puts the default root qdisc back when dropped.
struct RestoreRoot(u32);

impl Drop for RestoreRoot {
    fn drop(&mut self) {
        let e = snare::real(|| change(RTM_DELQDISC, self.0, 0, TC_H_ROOT, &[]));
        if e != 0 && e != libc::ENOENT {
            eprintln!(
                "could not put back interface {}'s default root qdisc: errno {e}",
                self.0
            );
        }
    }
}

/// The ETF parameter checks at the root, then `mq` with an offloaded `etf` tried on every
/// transmit queue, a software `etf` on the first, the resulting table, and the defaults again.
#[test]
#[ignore = "hardware: needs a NIC, CAP_NET_ADMIN and SNARE_HW_MUTATE=1"]
fn hw_etf_qdisc_changes_match() {
    let h = hw::hw();
    let iface = need!(
        h.iface.clone(),
        "needs a wired NIC (set SNARE_HW_IFACE=<name>)"
    );
    require!(
        h.mutate,
        "replaces {iface}'s root qdisc (set SNARE_HW_MUTATE=1; the default is put back)"
    );
    require!(
        h.cap(hw::CAP_NET_ADMIN),
        "needs CAP_NET_ADMIN (run as root)"
    );
    let ifindex = need!(hw::linux::ifindex(&iface), "needs {iface}'s ifindex");
    let _lock = hw::nic_lock();
    let start = snare::real(|| qdiscs(ifindex));
    require!(
        start.iter().any(|q| q.1 == TC_H_ROOT && q.0 == 0),
        "needs {iface} on the kernel's default root qdisc so it can be put back (now {start:?})"
    );
    let tx_queues = snare::real(|| {
        std::fs::read_dir(format!("/sys/class/net/{iface}/queues"))
            .map(|d| {
                d.flatten()
                    .filter(|e| e.file_name().to_string_lossy().starts_with("tx-"))
                    .count()
            })
            .unwrap_or(1)
    }) as u32;
    let _restore = RestoreRoot(ifindex);

    let checks = || {
        let bare = kind("etf");
        vec![
            (
                "etf without options",
                change(RTM_NEWQDISC, ifindex, 0, TC_H_ROOT, &bare),
            ),
            (
                "etf on CLOCK_REALTIME",
                change(
                    RTM_NEWQDISC,
                    ifindex,
                    0,
                    TC_H_ROOT,
                    &etf(300_000, libc::CLOCK_REALTIME, 0),
                ),
            ),
            (
                "etf on a dynamic clock",
                change(RTM_NEWQDISC, ifindex, 0, TC_H_ROOT, &etf(300_000, -3, 0)),
            ),
            (
                "etf with a negative delta",
                change(
                    RTM_NEWQDISC,
                    ifindex,
                    0,
                    TC_H_ROOT,
                    &etf(-1, libc::CLOCK_TAI, 0),
                ),
            ),
            (
                "an unknown kind",
                change(RTM_NEWQDISC, ifindex, 0, TC_H_ROOT, &kind("snare_nonesuch")),
            ),
            (
                "mq at the root",
                change(RTM_NEWQDISC, ifindex, MQ_HANDLE, TC_H_ROOT, &kind("mq")),
            ),
        ]
    };
    let real_checks = snare::real(checks);
    require!(
        real_checks[1].1 != libc::ENOENT,
        "needs the kernel's etf qdisc (sch_etf; modprobe sch_etf)"
    );
    let offload = |queues: u32| {
        (0..queues)
            .map(|q| {
                change(
                    RTM_NEWQDISC,
                    ifindex,
                    0,
                    MQ_HANDLE + q + 1,
                    &etf(300_000, libc::CLOCK_TAI, TC_ETF_OFFLOAD_ON),
                )
            })
            .collect::<Vec<i32>>()
    };
    let rest = || {
        let software = change(
            RTM_NEWQDISC,
            ifindex,
            0,
            MQ_HANDLE + 1,
            &etf(200_000, libc::CLOCK_TAI, 0),
        );
        let table: Vec<_> = qdiscs(ifindex)
            .into_iter()
            .map(|(_, parent, kind, etf)| (parent, kind, etf))
            .collect();
        let back = change(RTM_DELQDISC, ifindex, 0, TC_H_ROOT, &[]);
        let again = change(RTM_DELQDISC, ifindex, 0, TC_H_ROOT, &[]);
        let defaults: Vec<_> = qdiscs(ifindex)
            .into_iter()
            .map(|(_, parent, kind, _)| (parent, kind))
            .collect();
        (software, table, back, again, defaults)
    };
    let mq_ok = real_checks[5].1 == 0;
    let real_offload = if mq_ok {
        snare::real(|| offload(tx_queues))
    } else {
        Vec::new()
    };
    let real_rest = snare::real(rest);

    let accepted: Vec<u16> = (0..real_offload.len())
        .filter(|&q| real_offload[q] == 0)
        .map(|q| q as u16)
        .collect();
    let no_offload =
        !real_offload.is_empty() && real_offload.iter().all(|&e| e == libc::EOPNOTSUPP);
    let (mut nic, _) = snare::real(|| nic_profile(&iface));
    if start
        .iter()
        .any(|q| q.1 == TC_H_ROOT && q.0 == 0 && q.2 == "noqueue")
    {
        nic = nic.no_queue();
    }
    if !no_offload {
        nic = nic.etf_offload(accepted.clone());
    }
    let default_qdisc = snare::real(|| std::fs::read_to_string("/proc/sys/net/core/default_qdisc"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "pfifo_fast".into());
    let host = HostProfile::new()
        .nic(nic)
        .default_qdisc(default_qdisc)
        .cap(hw::CAP_NET_ADMIN as i32)
        .build();
    let sim = Sim::builder()
        .host(host)
        .privileges(Privileges::from_real_process().unwrap())
        .build();
    let (sim_checks, sim_offload, sim_rest) = sim.run(|| {
        let c = checks();
        let o = if c[5].1 == 0 {
            offload(tx_queues)
        } else {
            Vec::new()
        };
        (c, o, rest())
    });
    eprintln!("start {start:?}\nreal: {real_checks:?} {real_offload:?} {real_rest:#?}");
    assert_eq!(
        sim_checks, real_checks,
        "root qdisc checks (errno per step)"
    );
    assert_eq!(
        sim_offload, real_offload,
        "offloaded etf per transmit queue (driver accepted {accepted:?})"
    );
    assert_eq!(sim_rest.0, real_rest.0, "software etf under mq");
    assert_eq!(
        sim_rest.1, real_rest.1,
        "the qdisc table (parent, kind, etf parms)"
    );
    assert_eq!(
        (sim_rest.2, sim_rest.3),
        (real_rest.2, real_rest.3),
        "deleting the root, twice"
    );
    assert_eq!(sim_rest.4, real_rest.4, "the default table again");
}

fn txtime_opt(fd: i32, clockid: i32, flags: u32, len: u32) -> Result<(), i32> {
    let v = [clockid as u32, flags];
    let rc = unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, SO_TXTIME, v.as_ptr().cast(), len) };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

fn get_txtime(fd: i32) -> Result<([u32; 2], u32), i32> {
    let mut v = [0u32; 2];
    let mut len = 8u32;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_TXTIME,
            v.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc == 0 { Ok((v, len)) } else { Err(errno()) }
}

/// A datagram to `to` with an `SCM_TXTIME` control message of `len` bytes holding `at`.
fn send_txtime(fd: i32, to: &libc::sockaddr_in, at: u64, len: usize) -> Result<isize, i32> {
    let payload = *b"etf!";
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut _,
        iov_len: payload.len(),
    };
    #[repr(C, align(8))]
    struct Control([u8; 64]);
    let mut control = Control([0; 64]);
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (to as *const libc::sockaddr_in).cast_mut().cast();
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(len as u32) } as _;
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = SCM_TXTIME;
        (*c).cmsg_len = libc::CMSG_LEN(len as u32) as _;
        let data = libc::CMSG_DATA(c);
        std::ptr::copy_nonoverlapping(at.to_ne_bytes().as_ptr(), data, len.min(8));
    }
    let n = unsafe { libc::sendmsg(fd, &msg, 0) };
    if n >= 0 { Ok(n) } else { Err(errno()) }
}

/// `SO_TXTIME`'s validation and read-back, and `SCM_TXTIME` on a loopback send.
fn txtime_probe() -> Vec<String> {
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let fd = tx.as_raw_fd();
    let port = rx.local_addr().unwrap().port();
    let mut to: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    to.sin_family = libc::AF_INET as u16;
    to.sin_port = port.to_be();
    to.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
    let mut out = vec![format!("get before set {:?}", get_txtime(fd))];
    let now = {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe { libc::clock_gettime(libc::CLOCK_TAI, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    };
    out.push(format!(
        "send before set {:?}",
        send_txtime(fd, &to, now, 8)
    ));
    for (what, clockid, flags, len) in [
        ("TAI", libc::CLOCK_TAI, 0, 8),
        (
            "MONOTONIC deadline+errors",
            libc::CLOCK_MONOTONIC,
            SOF_TXTIME_DEADLINE_MODE | SOF_TXTIME_REPORT_ERRORS,
            8,
        ),
        ("unknown flag", libc::CLOCK_TAI, 1 << 7, 8),
        ("short", libc::CLOCK_TAI, 0, 4),
        ("long", libc::CLOCK_TAI, 0, 12),
        ("REALTIME", libc::CLOCK_REALTIME, 0, 8),
        ("unknown clock", 99, 0, 8),
        ("back to TAI", libc::CLOCK_TAI, 0, 8),
    ] {
        out.push(format!(
            "{what}: set {:?} get {:?}",
            txtime_opt(fd, clockid, flags, len),
            get_txtime(fd)
        ));
    }
    out.push(format!("send now {:?}", send_txtime(fd, &to, now, 8)));
    out.push(format!(
        "send 4-byte cmsg {:?}",
        send_txtime(fd, &to, now, 4)
    ));
    out.push(format!("send past {:?}", send_txtime(fd, &to, 1, 8)));
    out
}

/// Runs on any Linux host: no NIC is touched.
#[test]
fn hw_txtime_sockopt_matches() {
    let real = snare::real(txtime_probe);
    let sim = Sim::builder()
        .host(HostProfile::new().build())
        .privileges(Privileges::from_real_process().unwrap())
        .build()
        .run(txtime_probe);
    let differ: Vec<String> = real
        .iter()
        .zip(&sim)
        .filter(|(r, s)| r != s)
        .map(|(r, s)| format!("real {r}\n      sim  {s}"))
        .collect();
    assert!(
        differ.is_empty(),
        "SO_TXTIME steps that differ:\n      {}",
        differ.join("\n      ")
    );
    assert_eq!(sim.len(), real.len());
}
