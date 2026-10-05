//! Pins, as transcripts kept in `golden/edge_host_nic.linux.txt`, the exact answer of a
//! `SimHost`'s NIC planes to fixed request sequences: every `SIOCETHTOOL` command (each reply's
//! errno and the whole buffer after the call) on a tuned driver with and without `CAP_NET_ADMIN`,
//! a bare driver and the `EasyBuilder::realtime()` NIC; the `/dev/ptp*` ioctls (capabilities,
//! every offset request at and past its sample limits, channel requests on read-only and writable
//! fds, unknown requests) and the dynamic clock id's `clock_gettime`; and rtnetlink qdisc changes
//! and dumps (every reply message's type and bytes) through create, replace, exclusive create,
//! missing parents and devices, unknown kinds, deletes and an unprivileged caller. A second run of
//! each sequence on a fresh sim must give the same transcript.
#![cfg(target_os = "linux")]

#[path = "support/golden.rs"]
mod golden;

use std::fmt::Write as _;
use std::sync::Arc;

use snare::{
    CAP_NET_ADMIN, Channels, Coalesce, CoalesceParams, EasyBuilder, Eee, HostProfile, Nic, Pause,
    PtpCaps, Rings, Sim, SimHost,
};

const SIOCETHTOOL: libc::c_ulong = 0x8946;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[repr(C)]
struct Ifreq {
    name: [libc::c_char; 16],
    data: usize,
}

fn ethtool(name: &str, data: &mut [u8]) -> i32 {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0);
    let mut req = Ifreq {
        name: [0; 16],
        data: data.as_mut_ptr() as usize,
    };
    for (i, b) in name.bytes().enumerate() {
        req.name[i] = b as libc::c_char;
    }
    let rc = unsafe { libc::ioctl(fd, SIOCETHTOOL, &mut req as *mut Ifreq) };
    let e = errno();
    unsafe { libc::close(fd) };
    if rc == 0 { 0 } else { e }
}

fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|w| w.to_ne_bytes()).collect()
}

/// One ethtool call on `name` with the buffer `init`, recorded as its errno and the buffer after.
fn step(out: &mut String, name: &str, what: &str, mut buf: Vec<u8>) -> Vec<u8> {
    let e = ethtool(name, &mut buf);
    let _ = write!(out, "{what}: errno {e}\n{}", golden::hex(&buf));
    buf
}

fn tuned_nic() -> Nic {
    Nic::new("eth0", 3)
        .driver("igb", "6.12.0")
        .bus_info("0000:03:00.0")
        .firmware("1.63, 0x80000f3a")
        .expansion_rom("1.1824.0")
        .rings(Rings {
            rx_max: 4096,
            tx_max: 4096,
            rx: 256,
            tx: 256,
            ..Rings::default()
        })
        .coalesce(
            CoalesceParams::USECS,
            Coalesce {
                rx_usecs: 3,
                tx_usecs: 3,
                ..Coalesce::default()
            },
        )
        .coalesce_limits(10_000, u32::MAX)
        .channels(Channels {
            combined_max: 8,
            other_max: 1,
            combined: 4,
            other: 1,
            ..Channels::default()
        })
        .pause(Pause {
            autoneg: true,
            rx: true,
            tx: true,
        })
        .eee(Eee {
            supported: 0x28,
            advertised: 0x28,
            lp_advertised: 0x28,
            enabled: true,
            tx_lpi_enabled: true,
            ..Eee::default()
        })
        .ntuple(16)
        .driver_stats([("rx_packets", 10), ("rx_no_buffer_count", 2)])
}

/// Every read command, then each setter at, inside and past its limits, then the reads again.
fn ethtool_transcript(nic: &str) -> String {
    let mut out = String::new();
    let o = &mut out;
    let mut drv = vec![0u8; 196];
    drv[..4].copy_from_slice(&0x03u32.to_ne_bytes());
    step(o, nic, "GDRVINFO", drv);
    step(o, nic, "GLINK", words(&[0x0a, 0]));
    let rings = step(o, nic, "GRINGPARAM", words(&[0x10, 0, 0, 0, 0, 0, 0, 0, 0]));
    let mut coalesce = vec![0u32; 23];
    coalesce[0] = 0x0e;
    let coal = step(o, nic, "GCOALESCE", words(&coalesce));
    let chans = step(o, nic, "GCHANNELS", words(&[0x3c, 0, 0, 0, 0, 0, 0, 0, 0]));
    step(o, nic, "GPAUSEPARAM", words(&[0x12, 0, 0, 0]));
    let eee = step(o, nic, "GEEE", words(&[0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    step(o, nic, "GFLAGS", words(&[0x25, 0]));
    step(
        o,
        nic,
        "GET_TS_INFO",
        words(&[0x41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    );
    let sset = step(o, nic, "GSSET_INFO stats", words(&[0x37, 0, 1 << 1, 0, 0]));
    let n = u32::from_ne_bytes(sset[16..20].try_into().unwrap()) as usize;
    let mut strings = vec![0u32; 3 + n * 8];
    strings[0] = 0x1b;
    strings[1] = 1;
    step(o, nic, "GSTRINGS stats", words(&strings));
    let mut stats = vec![0u8; 8 + n * 8];
    stats[..4].copy_from_slice(&0x1du32.to_ne_bytes());
    step(o, nic, "GSTATS", stats);
    step(
        o,
        nic,
        "GSSET_INFO priv+test",
        words(&[0x37, 0, 1 | 1 << 2, 0, 0]),
    );

    let w = |b: &[u8]| -> Vec<u32> {
        b.chunks(4)
            .map(|c| u32::from_ne_bytes(c.try_into().unwrap()))
            .collect()
    };
    let mut r = w(&rings);
    r[0] = 0x11;
    for (field, value, what) in [
        (5, 4097, "SRINGPARAM rx past max"),
        (5, 0, "SRINGPARAM rx 0"),
        (6, 1, "SRINGPARAM mini past max"),
        (8, 4096, "SRINGPARAM tx at max"),
    ] {
        let mut s = r.clone();
        s[field] = value;
        step(o, nic, what, words(&s));
    }
    let mut c = w(&coal);
    c[0] = 0x0f;
    for (field, value, what) in [
        (2, 8, "SCOALESCE rx-frames"),
        (10, 1, "SCOALESCE adaptive-rx"),
        (1, 10_001, "SCOALESCE usecs past limit"),
        (1, 10_000, "SCOALESCE usecs at limit"),
    ] {
        let mut s = c.clone();
        s[field] = value;
        step(o, nic, what, words(&s));
    }
    let mut ch = w(&chans);
    ch[0] = 0x3d;
    for (field, value, what) in [
        (8, 9, "SCHANNELS combined past max"),
        (8, 0, "SCHANNELS no queues"),
        (5, 1, "SCHANNELS rx only"),
        (8, 2, "SCHANNELS combined 2"),
    ] {
        let mut s = ch.clone();
        s[field] = value;
        step(o, nic, what, words(&s));
    }
    step(o, nic, "SPAUSEPARAM", words(&[0x13, 0, 1, 0]));
    let mut e = w(&eee);
    e[0] = 0x45;
    let mut bad = e.clone();
    bad[2] = 0x1000;
    step(o, nic, "SEEE unsupported mode", words(&bad));
    e[5] = 0;
    step(o, nic, "SEEE disable", words(&e));
    step(o, nic, "SFLAGS LRO", words(&[0x26, 1 << 15]));
    step(o, nic, "SFLAGS not a flag", words(&[0x26, 1]));
    step(o, nic, "SFLAGS NTUPLE", words(&[0x26, 1 << 27]));
    step(o, nic, "unknown command", words(&[0x7777, 0]));
    step(
        o,
        nic,
        "GRINGPARAM after",
        words(&[0x10, 0, 0, 0, 0, 0, 0, 0, 0]),
    );
    step(o, nic, "GCOALESCE after", words(&coalesce));
    step(
        o,
        nic,
        "GCHANNELS after",
        words(&[0x3c, 0, 0, 0, 0, 0, 0, 0, 0]),
    );
    step(o, nic, "GPAUSEPARAM after", words(&[0x12, 0, 0, 0]));
    step(
        o,
        nic,
        "GEEE after",
        words(&[0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    );
    step(o, nic, "GFLAGS after", words(&[0x25, 0]));
    out
}

fn admin_tuned() -> Arc<SimHost> {
    HostProfile::new()
        .cap(CAP_NET_ADMIN)
        .nic(tuned_nic())
        .build()
}

fn ethtool_hosts() -> Vec<(&'static str, Arc<SimHost>)> {
    vec![
        ("tuned, CAP_NET_ADMIN", admin_tuned()),
        (
            "tuned, unprivileged",
            HostProfile::new().nic(tuned_nic()).build(),
        ),
        (
            "bare, CAP_NET_ADMIN",
            HostProfile::new()
                .cap(CAP_NET_ADMIN)
                .nic(Nic::new("eth0", 3))
                .build(),
        ),
        ("EasyBuilder::realtime()", EasyBuilder::realtime().build()),
    ]
}

fn ethtool_golden() -> String {
    let mut text = String::new();
    for (what, host) in ethtool_hosts() {
        let _ = writeln!(text, "# {what}");
        text.push_str(
            &Sim::builder()
                .host(host)
                .build()
                .run(|| ethtool_transcript("eth0")),
        );
    }
    text
}

const fn ioc(dir: u64, nr: u64, size: usize) -> libc::c_ulong {
    ((dir << 30) | ((b'=' as u64) << 8) | nr | ((size as u64) << 16)) as libc::c_ulong
}

fn ptp(out: &mut String, fd: i32, what: &str, request: libc::c_ulong, mut buf: Vec<u8>) {
    let rc = unsafe { libc::ioctl(fd, request, buf.as_mut_ptr()) };
    let e = if rc == 0 { 0 } else { errno() };
    let _ = write!(out, "{what}: errno {e}\n{}", golden::hex(&buf));
}

fn with_head(len: usize, head: &[u32]) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    buf[..head.len() * 4].copy_from_slice(&words(head));
    buf
}

fn open(path: &std::ffi::CStr, flags: i32) -> i32 {
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    if fd < 0 { -errno() } else { fd }
}

fn ptp_transcript() -> String {
    let mut out = String::new();
    let o = &mut out;
    for (path, flags) in [
        (c"/dev/ptp7", libc::O_RDONLY),
        (c"/dev/ptp0", libc::O_WRONLY),
    ] {
        let fd = open(path, flags);
        let _ = writeln!(
            o,
            "open {path:?} {flags:#x}: {}",
            if fd < 0 { fd } else { 0 }
        );
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }
    for (path, label) in [(c"/dev/ptp0", "ptp0"), (c"/dev/ptp1", "ptp1")] {
        let ro = open(path, libc::O_RDONLY);
        let rw = open(path, libc::O_RDWR);
        assert!(ro >= 0 && rw >= 0, "{label}");
        let _ = writeln!(o, "## {label}");
        ptp(o, ro, "GETCAPS", ioc(2, 1, 80), vec![0xff; 80]);
        ptp(o, ro, "GETCAPS2", ioc(2, 10, 80), vec![0xff; 80]);
        for n in [0u32, 1, 3, 25, 26] {
            ptp(
                o,
                ro,
                &format!("SYS_OFFSET n={n}"),
                ioc(1, 5, 832),
                with_head(832, &[n]),
            );
        }
        for (n, clock, rsv) in [
            (2u32, libc::CLOCK_REALTIME as u32, 0u32),
            (1, libc::CLOCK_MONOTONIC as u32, 0),
            (1, libc::CLOCK_MONOTONIC_RAW as u32, 0),
            (1, libc::CLOCK_TAI as u32, 0),
            (1, 0, 1),
            (26, 0, 0),
        ] {
            ptp(
                o,
                ro,
                &format!("SYS_OFFSET_EXTENDED n={n} clock={clock} rsv={rsv}"),
                ioc(3, 9, 1216),
                with_head(1216, &[n, clock, rsv]),
            );
        }
        ptp(o, ro, "SYS_OFFSET_PRECISE", ioc(3, 8, 64), vec![0; 64]);
        ptp(
            o,
            ro,
            "SYS_OFFSET_PRECISE_CYCLES",
            ioc(3, 21, 64),
            vec![0; 64],
        );
        for (fd, mode) in [(ro, "ro"), (rw, "rw")] {
            for index in [0u32, 1, 2] {
                ptp(
                    o,
                    fd,
                    &format!("EXTTS_REQUEST {mode} index={index}"),
                    ioc(1, 2, 16),
                    with_head(16, &[index, 1]),
                );
            }
            ptp(
                o,
                fd,
                &format!("ENABLE_PPS {mode} on"),
                ioc(1, 4, 4),
                with_head(4, &[1]),
            );
            ptp(
                o,
                fd,
                &format!("PEROUT_REQUEST {mode} index=0"),
                ioc(1, 3, 56),
                with_head(56, &[0, 0, 0, 0, 1]),
            );
        }
        ptp(o, rw, "unknown request", ioc(3, 99, 64), vec![0; 64]);
        let clock = ((!rw) << 3) | 3;
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let rc = unsafe { libc::clock_gettime(clock, &mut ts) };
        let _ = writeln!(
            o,
            "clock_gettime(FD_TO_CLOCKID): {} {}.{:09}",
            if rc == 0 { 0 } else { errno() },
            ts.tv_sec,
            ts.tv_nsec
        );
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let rc = unsafe { libc::clock_getres(clock, &mut ts) };
        let _ = writeln!(
            o,
            "clock_getres(FD_TO_CLOCKID): {} {}.{:09}",
            if rc == 0 { 0 } else { errno() },
            ts.tv_sec,
            ts.tv_nsec
        );
        unsafe {
            libc::close(ro);
            libc::close(rw);
        }
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let rc = unsafe { libc::clock_gettime(clock, &mut ts) };
        let _ = writeln!(
            o,
            "clock_gettime on the closed fd's id: {}",
            if rc == 0 { 0 } else { errno() }
        );
    }
    out
}

fn ptp_host() -> Arc<SimHost> {
    HostProfile::new()
        .ptp_clock_offset(0, 500)
        .ptp_clock_caps(
            0,
            PtpCaps {
                max_adj: 62_499_999,
                n_ext_ts: 2,
                n_per_out: 1,
                pps: true,
                n_pins: 4,
                cross_timestamping: true,
                adjust_phase: true,
                max_phase_adj: 1000,
                ..PtpCaps::default()
            },
        )
        .ptp_clock_offset(1, -250)
        .ptp_clock_caps(
            1,
            PtpCaps {
                extended: false,
                ..PtpCaps::default()
            },
        )
        .build()
}

fn ptp_golden() -> String {
    let root = HostProfile::new()
        .root(true)
        .ptp_clock_caps(
            0,
            PtpCaps {
                pps: true,
                n_ext_ts: 1,
                ..PtpCaps::default()
            },
        )
        .ptp_clock(1)
        .build();
    let mut text = String::from("# unprivileged\n");
    text.push_str(&Sim::builder().host(ptp_host()).build().run(ptp_transcript));
    text.push_str("# root\n");
    text.push_str(&Sim::builder().host(root).build().run(ptp_transcript));
    text
}

const RTM_NEWQDISC: u16 = 36;
const RTM_DELQDISC: u16 = 37;
const RTM_GETQDISC: u16 = 38;
const NLM_F_ACK: u16 = 4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const TC_H_ROOT: u32 = 0xffff_ffff;
const MQ: u32 = 0x7ff0_0000;

fn rtnl(
    ty: u16,
    flags: u16,
    ifindex: u32,
    handle: u32,
    parent: u32,
    kind: &str,
) -> Vec<(u16, Vec<u8>)> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    assert!(fd >= 0);
    let mut body = vec![0u8; 4];
    for w in [ifindex, handle, parent, 0] {
        body.extend_from_slice(&w.to_ne_bytes());
    }
    if !kind.is_empty() {
        body.extend_from_slice(&((4 + kind.len() + 1) as u16).to_ne_bytes());
        body.extend_from_slice(&1u16.to_ne_bytes());
        body.extend_from_slice(kind.as_bytes());
        body.push(0);
        body.resize(body.len().next_multiple_of(4), 0);
    }
    let mut msg = Vec::new();
    msg.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    msg.extend_from_slice(&ty.to_ne_bytes());
    msg.extend_from_slice(&(flags | 1).to_ne_bytes());
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
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
        if n <= 0 {
            out.push((0, (-errno()).to_ne_bytes().to_vec()));
            break;
        }
        let mut at = 0;
        while at + 16 <= n as usize {
            let len = u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
            let t = u16::from_ne_bytes(buf[at + 4..at + 6].try_into().unwrap());
            out.push((t, buf[at..at + len.max(16)].to_vec()));
            if t == NLMSG_ERROR || t == NLMSG_DONE {
                break 'recv;
            }
            at += len.max(16).next_multiple_of(4);
        }
    }
    unsafe { libc::close(fd) };
    out
}

fn qdisc_transcript() -> String {
    let mut out = String::new();
    let change = NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    let steps: &[(&str, u16, u16, u32, u32, u32, &str)] = &[
        ("dump", RTM_GETQDISC, NLM_F_DUMP, 0, 0, 0, ""),
        (
            "root fq_codel",
            RTM_NEWQDISC,
            change,
            2,
            0,
            TC_H_ROOT,
            "fq_codel",
        ),
        (
            "root fq_codel again, exclusive",
            RTM_NEWQDISC,
            NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            2,
            0,
            TC_H_ROOT,
            "fq_codel",
        ),
        ("dump", RTM_GETQDISC, NLM_F_DUMP, 0, 0, 0, ""),
        ("root mq", RTM_NEWQDISC, change, 2, MQ, TC_H_ROOT, "mq"),
        (
            "pfifo on class 2 with a handle",
            RTM_NEWQDISC,
            change,
            2,
            0x10_0000,
            MQ | 2,
            "pfifo",
        ),
        (
            "pfifo on class 9",
            RTM_NEWQDISC,
            change,
            2,
            0,
            MQ | 9,
            "pfifo",
        ),
        ("unknown kind", RTM_NEWQDISC, change, 2, 0, MQ | 1, "bogus"),
        (
            "no such device",
            RTM_NEWQDISC,
            change,
            99,
            0,
            TC_H_ROOT,
            "pfifo",
        ),
        (
            "replace without create",
            RTM_NEWQDISC,
            NLM_F_ACK,
            2,
            0,
            MQ | 3,
            "pfifo",
        ),
        (
            "no ack asked",
            RTM_NEWQDISC,
            NLM_F_CREATE | NLM_F_REPLACE,
            2,
            0,
            MQ | 4,
            "pfifo",
        ),
        ("dump", RTM_GETQDISC, NLM_F_DUMP, 0, 0, 0, ""),
        ("delete root", RTM_DELQDISC, NLM_F_ACK, 2, 0, TC_H_ROOT, ""),
        (
            "delete root again",
            RTM_DELQDISC,
            NLM_F_ACK,
            2,
            0,
            TC_H_ROOT,
            "",
        ),
        ("dump", RTM_GETQDISC, NLM_F_DUMP, 0, 0, 0, ""),
    ];
    for &(what, ty, flags, ifindex, handle, parent, kind) in steps {
        let _ = writeln!(out, "{what}:");
        for (t, bytes) in rtnl(ty, flags, ifindex, handle, parent, kind) {
            let _ = write!(out, "  type {t}\n{}", golden::hex(&bytes));
        }
    }
    out
}

fn qdisc_golden() -> String {
    let nic = || {
        Nic::new("eth0", 2).channels(Channels {
            combined_max: 4,
            combined: 4,
            ..Channels::default()
        })
    };
    let mut text = String::from("# CAP_NET_ADMIN\n");
    let admin = HostProfile::new()
        .nic(nic())
        .default_qdisc("fq_codel")
        .cap(CAP_NET_ADMIN)
        .build();
    text.push_str(&Sim::builder().host(admin).build().run(qdisc_transcript));
    text.push_str("# unprivileged\n");
    let user = HostProfile::new().nic(nic()).build();
    text.push_str(&Sim::builder().host(user).build().run(qdisc_transcript));
    text
}

fn transcript() -> String {
    format!(
        "### ethtool\n{}### ptp\n{}### qdisc\n{}",
        ethtool_golden(),
        ptp_golden(),
        qdisc_golden()
    )
}

#[test]
fn request_sequences_match_the_golden() {
    golden::check_text("edge_host_nic.linux.txt", &transcript());
}

#[test]
fn a_second_sim_gives_the_same_transcript() {
    assert_eq!(ethtool_golden(), ethtool_golden());
    assert_eq!(ptp_golden(), ptp_golden());
    assert_eq!(qdisc_golden(), qdisc_golden());
}

#[test]
fn ethtool_state_is_per_host_and_kept_across_runs() {
    let host = admin_tuned();
    let sim = Sim::builder().host(host.clone()).build();
    let rings = |n: &str| {
        let mut buf = words(&[0x10, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(ethtool(n, &mut buf), 0);
        u32::from_ne_bytes(buf[20..24].try_into().unwrap())
    };
    sim.run(|| {
        let mut s = words(&[0x11, 4096, 0, 0, 4096, 1024, 0, 0, 256]);
        assert_eq!(ethtool("eth0", &mut s), 0);
    });
    assert_eq!(sim.run(|| rings("eth0")), 1024);
    assert_eq!(host.ethtool("eth0").unwrap().rings.unwrap().rx, 1024);
    let other = Sim::builder().host(admin_tuned()).build();
    assert_eq!(other.run(|| rings("eth0")), 256);
    let shared = Sim::builder().host(host).build();
    assert_eq!(
        shared.run(|| rings("eth0")),
        1024,
        "a second sim on the same host sees it"
    );
}

#[test]
fn the_dynamic_clock_id_reads_the_phc() {
    Sim::builder().host(ptp_host()).build().run(|| {
        let fd = open(c"/dev/ptp0", libc::O_RDONLY);
        assert!(fd >= 0);
        let clock = ((!fd) << 3) | 3;
        let mut phc = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(
            unsafe { libc::clock_gettime(clock, &mut phc) },
            0,
            "errno {}",
            errno()
        );
        let mut res = phc;
        assert_eq!(
            unsafe { libc::clock_getres(clock, &mut res) },
            0,
            "errno {}",
            errno()
        );
        assert!(phc.tv_sec >= 1_700_000_000);
        unsafe { libc::close(fd) };
    });
}
