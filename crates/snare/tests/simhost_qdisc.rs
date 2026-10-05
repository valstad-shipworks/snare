#![cfg(target_os = "linux")]

//! `mq` against a device's transmit queues: the kernel decides multiqueue by the queues the driver
//! allocated (`num_tx_queues`, include/linux/netdevice.h `netif_is_multiqueue`), not by those in
//! use (`real_num_tx_queues`), and `mq` creates a qdisc for every allocated queue but lists only
//! those in use (net/sched/sch_mq.c `mq_init_common`, `mq_attach`, Linux 7.0).

use snare::{CAP_NET_ADMIN, Channels, HostProfile, Nic, Sim};

const RTM_NEWQDISC: u16 = 36;
const RTM_DELQDISC: u16 = 37;
const RTM_GETQDISC: u16 = 38;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const TC_H_ROOT: u32 = 0xffff_ffff;
const TCA_KIND: u16 = 1;
const MQ: u32 = 0x7ff0_0000;
const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_SCHANNELS: u32 = 0x3d;

/// One rtnetlink `tcmsg` request; every reply `(type, body)` up to the ack or `NLMSG_DONE`.
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
        body.extend_from_slice(&TCA_KIND.to_ne_bytes());
        body.extend_from_slice(kind.as_bytes());
        body.push(0);
        body.resize(body.len().next_multiple_of(4), 0);
    }
    let mut msg = Vec::new();
    msg.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    msg.extend_from_slice(&ty.to_ne_bytes());
    msg.extend_from_slice(&(flags | NLM_F_REQUEST).to_ne_bytes());
    msg.extend_from_slice(&[0; 8]);
    msg.extend_from_slice(&body);
    assert_eq!(
        unsafe { libc::send(fd, msg.as_ptr().cast(), msg.len(), 0) },
        msg.len() as isize
    );
    let mut out = Vec::new();
    'recv: loop {
        let mut buf = vec![0u8; 65_536];
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        assert!(n > 0);
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
    }
    unsafe { libc::close(fd) };
    out
}

/// The errno an acked change got, 0 for success.
fn change(ty: u16, ifindex: u32, handle: u32, parent: u32, kind: &str) -> i32 {
    let flags = NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    let r = rtnl(ty, flags, ifindex, handle, parent, kind);
    -i32::from_ne_bytes(r.last().unwrap().1[..4].try_into().unwrap())
}

/// `(parent, kind)` of each qdisc dumped for `ifindex`.
fn qdiscs(ifindex: u32) -> Vec<(u32, String)> {
    rtnl(RTM_GETQDISC, NLM_F_DUMP, 0, 0, 0, "")
        .into_iter()
        .filter(|(t, b)| {
            *t == RTM_NEWQDISC && u32::from_ne_bytes(b[4..8].try_into().unwrap()) == ifindex
        })
        .map(|(_, b)| {
            let parent = u32::from_ne_bytes(b[12..16].try_into().unwrap());
            let len = u16::from_ne_bytes(b[20..22].try_into().unwrap()) as usize;
            let kind = String::from_utf8_lossy(&b[24..20 + len])
                .trim_end_matches('\0')
                .to_string();
            (parent, kind)
        })
        .collect()
}

fn set_channels(iface: &str, combined: u32) -> i32 {
    let mut words = [0u32; 9];
    words[0] = ETHTOOL_SCHANNELS;
    words[8] = combined;
    #[repr(C)]
    struct Ifreq {
        name: [u8; 16],
        data: *mut u32,
    }
    let mut req = Ifreq {
        name: [0; 16],
        data: words.as_mut_ptr(),
    };
    req.name[..iface.len()].copy_from_slice(iface.as_bytes());
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    let rc = unsafe { libc::ioctl(fd, SIOCETHTOOL, &mut req) };
    unsafe { libc::close(fd) };
    rc
}

fn four_queue_nic(combined: u32) -> Nic {
    Nic::new("eth0", 2).channels(Channels {
        combined_max: 4,
        combined,
        ..Channels::default()
    })
}

fn host(nic: Nic) -> std::sync::Arc<snare::SimHost> {
    HostProfile::new()
        .nic(nic)
        .default_qdisc("fq_codel")
        .cap(CAP_NET_ADMIN)
        .build()
}

/// A device that allocated four queues starts on `mq` even when one is in use, and the dump
/// shows only the queue in use.
#[test]
fn a_device_reduced_to_one_queue_starts_on_mq() {
    Sim::builder()
        .host(host(four_queue_nic(1)))
        .build()
        .run(|| {
            assert_eq!(
                qdiscs(2),
                vec![(TC_H_ROOT, "mq".to_string()), (1, "fq_codel".to_string())]
            );
        });
}

/// `mq_init_common`: `mq` is accepted at the root of a device allocated several queues however
/// few are in use, refused (`EOPNOTSUPP`) on one allocated a single queue; a class of a queue
/// allocated but not in use takes a qdisc, which, created with a handle, is listed.
#[test]
fn mq_goes_by_the_queues_allocated() {
    Sim::builder()
        .host(host(four_queue_nic(4)))
        .build()
        .run(|| {
            assert_eq!(set_channels("eth0", 1), 0);
            assert_eq!(change(RTM_NEWQDISC, 2, MQ, TC_H_ROOT, "mq"), 0);
            assert_eq!(
                qdiscs(2),
                vec![
                    (TC_H_ROOT, "mq".to_string()),
                    (MQ | 1, "fq_codel".to_string())
                ]
            );
            assert_eq!(change(RTM_NEWQDISC, 2, 0x10_0000, MQ | 3, "pfifo"), 0);
            assert_eq!(
                change(RTM_NEWQDISC, 2, 0, MQ | 5, "pfifo"),
                libc::ENOENT,
                "no fifth queue"
            );
            assert_eq!(
                qdiscs(2),
                vec![
                    (TC_H_ROOT, "mq".to_string()),
                    (MQ | 1, "fq_codel".to_string()),
                    (MQ | 3, "pfifo".to_string())
                ]
            );
            assert_eq!(change(RTM_DELQDISC, 2, 0, TC_H_ROOT, ""), 0);
        });
    let single = Nic::new("eth0", 2).queues(1, 1);
    Sim::builder().host(host(single)).build().run(|| {
        assert_eq!(
            change(RTM_NEWQDISC, 2, MQ, TC_H_ROOT, "mq"),
            libc::EOPNOTSUPP
        );
    });
}

/// `IFF_NO_QUEUE` (veth): `noqueue` at the root whatever the queue count, `mq` still accepted on
/// several allocated queues, and `noqueue` again once the root is deleted.
#[test]
fn a_no_queue_device_starts_and_ends_on_noqueue() {
    let veth = Nic::new("eth0", 2).no_queue().channels(Channels {
        rx_max: 8,
        tx_max: 8,
        rx: 1,
        tx: 1,
        ..Channels::default()
    });
    Sim::builder().host(host(veth)).build().run(|| {
        assert_eq!(qdiscs(2), vec![(TC_H_ROOT, "noqueue".to_string())]);
        assert_eq!(change(RTM_NEWQDISC, 2, MQ, TC_H_ROOT, "mq"), 0);
        assert_eq!(qdiscs(2).len(), 2, "mq and the one queue in use");
        assert_eq!(change(RTM_DELQDISC, 2, 0, TC_H_ROOT, ""), 0);
        assert_eq!(qdiscs(2), vec![(TC_H_ROOT, "noqueue".to_string())]);
    });
}
