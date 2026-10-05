#![cfg(target_os = "linux")]

//! RTM_GETQDISC dump parsing against the SimHost rtnetlink backend.
//!
//! Protocol reference: man 7 rtnetlink (RTM_GETQDISC / RTM_NEWQDISC carry a struct tcmsg and
//! TCA_* attributes; TCA_KIND names the qdisc and TCA_OPTIONS nests qdisc-specific parameters).
//! The etf qdisc and its struct tc_etf_qopt are from <linux/pkt_sched.h>; see also man 8 tc-etf.

use snare::{HostProfile, Nic, Sim};

const NETLINK_ROUTE: i32 = 0;
const RTM_GETQDISC: u16 = 38;
const RTM_NEWQDISC: u16 = 36;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const TCA_ETF_PARMS: u16 = 1;
const TC_H_ROOT: u32 = 0xFFFF_FFFF; // <linux/pkt_sched.h>: the root qdisc's parent handle

fn u16at(b: &[u8], o: usize) -> u16 {
    u16::from_ne_bytes([b[o], b[o + 1]])
}
fn u32at(b: &[u8], o: usize) -> u32 {
    u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn i32at(b: &[u8], o: usize) -> i32 {
    i32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Find an attribute payload by type within a run of nlattrs (man 7 netlink's NLA layout).
fn find_attr(attrs: &[u8], want: u16) -> Option<&[u8]> {
    let mut pos = 0;
    while pos + 4 <= attrs.len() {
        let len = u16at(attrs, pos) as usize;
        let ty = u16at(attrs, pos + 2);
        if len < 4 || pos + len > attrs.len() {
            break;
        }
        if ty == want {
            return Some(&attrs[pos + 4..pos + len]);
        }
        pos += len.next_multiple_of(4);
    }
    None
}

struct Qdisc {
    kind: String,
    ifindex: i32,
    parent: u32,
    /// (delta, clockid, flags) from TCA_ETF_PARMS when the root qdisc is etf.
    etf: Option<(i32, i32, u32)>,
}

fn getqdisc(fd: i32, seq: u32) -> Qdisc {
    // The request body is a struct tcmsg (20 bytes); its contents are ignored for a dump.
    let tcmsg = [0u8; 20];
    let mut req = Vec::new();
    req.extend_from_slice(&(16u32 + 20).to_ne_bytes());
    req.extend_from_slice(&RTM_GETQDISC.to_ne_bytes());
    req.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    req.extend_from_slice(&seq.to_ne_bytes());
    req.extend_from_slice(&0u32.to_ne_bytes());
    req.extend_from_slice(&tcmsg);

    let sent = unsafe { libc::send(fd, req.as_ptr() as *const libc::c_void, req.len(), 0) };
    assert_eq!(sent, req.len() as isize, "send RTM_GETQDISC");
    let mut reply = vec![0u8; 4096];
    let got = unsafe { libc::recv(fd, reply.as_mut_ptr() as *mut libc::c_void, reply.len(), 0) };
    assert!(got > 0, "recv qdisc dump");
    reply.truncate(got as usize);

    let msglen = u32at(&reply, 0) as usize;
    let ty = u16at(&reply, 4);
    assert_eq!(ty, RTM_NEWQDISC, "first message is RTM_NEWQDISC");
    let mut at = 0;
    while u16at(&reply, at + 4) != NLMSG_DONE {
        at += (u32at(&reply, at) as usize).next_multiple_of(4);
        assert!(at < reply.len(), "dump terminated by NLMSG_DONE");
    }

    // tcmsg begins right after the 16-byte nlmsghdr: family u8, pad1 u8, pad2 u16, ifindex i32,
    // handle u32, parent u32, info u32. Attributes follow at offset 16 + 20 = 36.
    let ifindex = i32at(&reply, 16 + 4);
    let parent = u32at(&reply, 16 + 12);
    let attrs = &reply[36..msglen];
    let kind_raw = find_attr(attrs, TCA_KIND).expect("TCA_KIND present");
    let end = kind_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(kind_raw.len());
    let kind = String::from_utf8_lossy(&kind_raw[..end]).into_owned();
    let etf = find_attr(attrs, TCA_OPTIONS)
        .and_then(|opts| find_attr(opts, TCA_ETF_PARMS))
        .map(|p| (i32at(p, 0), i32at(p, 4), u32at(p, 8)));

    Qdisc {
        kind,
        ifindex,
        parent,
        etf,
    }
}

fn route_socket() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
    assert!(fd >= 0);
    fd
}

#[test]
fn default_root_qdisc_is_fq_codel_without_options() {
    let host = HostProfile::new().nic(Nic::new("eth0", 2)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = route_socket();
        let q = getqdisc(fd, 1);
        unsafe { libc::close(fd) };
        assert_eq!(q.kind, "fq_codel", "default net.core.default_qdisc");
        assert!(q.etf.is_none(), "a non-etf qdisc carries no TCA_ETF_PARMS");
        assert_eq!(q.parent, TC_H_ROOT, "the dumped qdisc is the root");
    });
}

#[test]
fn custom_default_qdisc_is_reported() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 2))
        .default_qdisc("fq")
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = route_socket();
        let q = getqdisc(fd, 1);
        unsafe { libc::close(fd) };
        assert_eq!(q.kind, "fq");
        assert!(q.etf.is_none());
    });
}

#[test]
fn etf_root_qdisc_carries_its_parms() {
    // struct tc_etf_qopt { s32 delta; clockid_t clockid; u32 flags; } (<linux/pkt_sched.h>).
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 2))
        .etf_qdisc(300_000, libc::CLOCK_TAI, 0)
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = route_socket();
        let q = getqdisc(fd, 1);
        unsafe { libc::close(fd) };
        assert_eq!(q.kind, "etf");
        assert_eq!(q.etf, Some((300_000, libc::CLOCK_TAI, 0)));
    });
}

#[test]
fn etf_clockid_realtime_and_flags_round_trip() {
    // ETF's SO_TXTIME deadline-mode flag is 0x1 (SOF_TXTIME_DEADLINE_MODE per man 8 tc-etf).
    const DEADLINE_MODE: u32 = 0x1;
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 2))
        .etf_qdisc(500_000, libc::CLOCK_REALTIME, DEADLINE_MODE)
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = route_socket();
        let q = getqdisc(fd, 1);
        unsafe { libc::close(fd) };
        assert_eq!(q.etf, Some((500_000, libc::CLOCK_REALTIME, DEADLINE_MODE)));
    });
}

#[test]
fn qdisc_reports_the_first_interfaces_index() {
    // The dump walks the interfaces in index order, as tc_dump_qdisc walks the devices.
    let host = HostProfile::new()
        .nic(Nic::new("eth9", 9))
        .nic(Nic::new("eth0", 5))
        .etf_qdisc(100, libc::CLOCK_TAI, 0)
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = route_socket();
        let q = getqdisc(fd, 1);
        unsafe { libc::close(fd) };
        assert_eq!(
            q.ifindex, 5,
            "eth0 has the lower index, so it is dumped first"
        );
    });
}

#[test]
fn qdisc_dump_echoes_sequence_number() {
    let host = HostProfile::new().nic(Nic::new("eth0", 2)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = route_socket();
        let tcmsg = [0u8; 20];
        let mut req = Vec::new();
        req.extend_from_slice(&(36u32).to_ne_bytes());
        req.extend_from_slice(&RTM_GETQDISC.to_ne_bytes());
        req.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        req.extend_from_slice(&4242u32.to_ne_bytes());
        req.extend_from_slice(&0u32.to_ne_bytes());
        req.extend_from_slice(&tcmsg);
        unsafe { libc::send(fd, req.as_ptr() as *const libc::c_void, req.len(), 0) };
        let mut reply = vec![0u8; 4096];
        let got =
            unsafe { libc::recv(fd, reply.as_mut_ptr() as *mut libc::c_void, reply.len(), 0) };
        reply.truncate(got as usize);
        unsafe { libc::close(fd) };
        assert_eq!(
            u32at(&reply, 8),
            4242,
            "RTM_NEWQDISC echoes the request seq"
        );
    });
}
