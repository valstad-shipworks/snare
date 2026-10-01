#![cfg(target_os = "linux")]

//! RTM_GETLINK dump parsing against the SimHost rtnetlink backend.
//!
//! Protocol reference: man 7 netlink (message framing, NLMSG_* macros) and man 7 rtnetlink
//! (RTM_GETLINK / RTM_NEWLINK and the IFLA_* attributes). Message and attribute type numbers are
//! from <linux/rtnetlink.h>; struct rtnl_link_stats64 (carried in IFLA_STATS64) is from
//! <linux/if_link.h>.

use snare::{HostProfile, LinkStats, Nic, Sim};

const NETLINK_ROUTE: i32 = 0;
const RTM_GETLINK: u16 = 18;
const RTM_NEWLINK: u16 = 16;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_MULTI: u16 = 2; // <linux/netlink.h>: part of a multipart dump
const NLM_F_DUMP: u16 = 0x300;
const IFLA_IFNAME: u16 = 3;
const IFLA_STATS64: u16 = 23;
const ARPHRD_ETHER: u16 = 1; // <linux/if_arp.h>

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn u16at(b: &[u8], o: usize) -> u16 {
    u16::from_ne_bytes([b[o], b[o + 1]])
}
fn u32at(b: &[u8], o: usize) -> u32 {
    u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn i32at(b: &[u8], o: usize) -> i32 {
    i32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64at(b: &[u8], o: usize) -> u64 {
    u64::from_ne_bytes(b[o..o + 8].try_into().unwrap())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Link {
    name: String,
    ifindex: i32,
    ifi_type: u16,
    ifi_flags: u32,
    seq: u32,
    multi: bool,
    stats: [u64; 8],
}

/// Walk a multipart RTM_GETLINK reply and decode every RTM_NEWLINK message. Framing per man 7
/// netlink: each message is a 16-byte nlmsghdr (len, type, flags, seq, pid) followed by the body,
/// 4-byte aligned; the dump ends at NLMSG_DONE.
fn parse_links(buf: &[u8]) -> Vec<Link> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 16 <= buf.len() {
        let msg_len = u32at(buf, off) as usize;
        let msg_type = u16at(buf, off + 4);
        let flags = u16at(buf, off + 6);
        let seq = u32at(buf, off + 8);
        if msg_len < 16 || off + msg_len > buf.len() {
            break;
        }
        if msg_type == NLMSG_DONE {
            break;
        }
        if msg_type == RTM_NEWLINK {
            // ifinfomsg (<linux/rtnetlink.h>): family u8, pad u8, type u16, index i32, flags u32,
            // change u32 — 16 bytes right after the nlmsghdr.
            let ifi_type = u16at(buf, off + 18);
            let ifindex = i32at(buf, off + 20);
            let ifi_flags = u32at(buf, off + 24);
            let mut name = String::new();
            let mut stats = [0u64; 8];
            let mut a = off + 32;
            let end = off + msg_len;
            while a + 4 <= end {
                let rta_len = u16at(buf, a) as usize;
                let rta_type = u16at(buf, a + 2);
                if rta_len < 4 || a + rta_len > end {
                    break;
                }
                let payload = &buf[a + 4..a + rta_len];
                match rta_type {
                    IFLA_IFNAME => {
                        let s = payload.split(|&c| c == 0).next().unwrap_or(&[]);
                        name = String::from_utf8_lossy(s).into_owned();
                    }
                    IFLA_STATS64 => {
                        for (i, slot) in stats.iter_mut().enumerate() {
                            *slot = u64at(payload, i * 8);
                        }
                    }
                    _ => {}
                }
                a += align4(rta_len);
            }
            out.push(Link {
                name,
                ifindex,
                ifi_type,
                ifi_flags,
                seq,
                multi: flags & NLM_F_MULTI != 0,
                stats,
            });
        }
        off += align4(msg_len);
    }
    out
}

/// Issue an RTM_GETLINK dump on `fd` with the given sequence number and return the raw reply.
fn getlink_dump(fd: i32, seq: u32) -> Vec<u8> {
    #[repr(C)]
    struct Request {
        nlmsg_len: u32,
        nlmsg_type: u16,
        nlmsg_flags: u16,
        nlmsg_seq: u32,
        nlmsg_pid: u32,
        ifi_family: u8,
        pad: u8,
        ifi_type: u16,
        ifi_index: i32,
        ifi_flags: u32,
        ifi_change: u32,
    }
    let req = Request {
        nlmsg_len: 32,
        nlmsg_type: RTM_GETLINK,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
        nlmsg_seq: seq,
        nlmsg_pid: 0,
        ifi_family: 0,
        pad: 0,
        ifi_type: 0,
        ifi_index: 0,
        ifi_flags: 0,
        ifi_change: 0,
    };
    let mut dest: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    dest.nl_family = libc::AF_NETLINK as u16;
    let sent = unsafe {
        libc::sendto(
            fd,
            &req as *const _ as *const libc::c_void,
            32,
            0,
            &dest as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    assert_eq!(sent, 32, "sendto the RTM_GETLINK request");
    let mut buf = vec![0u8; 65536];
    let got = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
    assert!(got > 0, "recv the dump");
    buf.truncate(got as usize);
    buf
}

fn route_socket() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
    assert!(fd >= 0, "AF_NETLINK/NETLINK_ROUTE socket");
    fd
}

#[test]
fn empty_host_dumps_only_nlmsg_done() {
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let fd = route_socket();
        let links = parse_links(&getlink_dump(fd, 1));
        unsafe { libc::close(fd) };
        assert!(links.is_empty(), "no NICs means the dump is just NLMSG_DONE");
    });
}

#[test]
fn interfaces_are_enumerated_sorted_by_name() {
    // Deliberately out of order; the backend sorts by name so enumeration is deterministic.
    let host = HostProfile::new()
        .nic(Nic::new("eth2", 4))
        .nic(Nic::new("eth0", 2))
        .nic(Nic::new("eth1", 3))
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = route_socket();
        let links = parse_links(&getlink_dump(fd, 1));
        unsafe { libc::close(fd) };
        let names: Vec<_> = links.iter().map(|l| l.name.clone()).collect();
        assert_eq!(names, vec!["eth0", "eth1", "eth2"]);
        assert_eq!(links[0].ifindex, 2);
        assert_eq!(links[1].ifindex, 3);
        assert_eq!(links[2].ifindex, 4);
    });
}

#[test]
fn each_message_carries_arphrd_ether_and_nlm_f_multi() {
    let host = HostProfile::new().nic(Nic::new("eth0", 2)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = route_socket();
        let links = parse_links(&getlink_dump(fd, 7));
        unsafe { libc::close(fd) };
        assert_eq!(links.len(), 1);
        // A dump's constituent messages set NLM_F_MULTI (man 7 netlink).
        assert!(links[0].multi, "RTM_NEWLINK carries NLM_F_MULTI");
        // ifi_type is ARPHRD_ETHER for an ethernet link (<linux/if_arp.h>).
        assert_eq!(links[0].ifi_type, ARPHRD_ETHER);
    });
}

#[test]
fn sequence_number_is_echoed() {
    let host = HostProfile::new().nic(Nic::new("eth0", 2)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = route_socket();
        let links = parse_links(&getlink_dump(fd, 0xDEAD_BEEF));
        unsafe { libc::close(fd) };
        assert_eq!(links[0].seq, 0xDEAD_BEEF, "reply echoes the request seq");
    });
}

#[test]
fn operstate_up_sets_iff_running() {
    let host = HostProfile::new()
        .nic(Nic::new("up0", 2).operstate("up"))
        .nic(Nic::new("dn0", 3).operstate("down"))
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = route_socket();
        let links = parse_links(&getlink_dump(fd, 1));
        unsafe { libc::close(fd) };
        let by = |n: &str| links.iter().find(|l| l.name == n).unwrap();
        // IFF_UP is always set; IFF_RUNNING tracks carrier/operstate (man 7 netdevice).
        assert_eq!(by("up0").ifi_flags & libc::IFF_UP as u32, libc::IFF_UP as u32);
        assert_eq!(by("up0").ifi_flags & libc::IFF_RUNNING as u32, libc::IFF_RUNNING as u32);
        assert_eq!(by("dn0").ifi_flags & libc::IFF_UP as u32, libc::IFF_UP as u32);
        assert_eq!(by("dn0").ifi_flags & libc::IFF_RUNNING as u32, 0, "down link is not RUNNING");
    });
}

#[test]
fn all_eight_stats64_fields_round_trip() {
    let stats = LinkStats {
        rx_packets: 1,
        tx_packets: 2,
        rx_bytes: 3,
        tx_bytes: 4,
        rx_errors: 5,
        tx_errors: 6,
        rx_dropped: 7,
        tx_dropped: 8,
    };
    let host = HostProfile::new().nic(Nic::new("eth0", 2).link_stats(stats)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = route_socket();
        let links = parse_links(&getlink_dump(fd, 1));
        unsafe { libc::close(fd) };
        // Field order matches struct rtnl_link_stats64 (<linux/if_link.h>).
        assert_eq!(links[0].stats, [1, 2, 3, 4, 5, 6, 7, 8]);
    });
}

#[test]
fn large_stats_values_are_preserved() {
    let stats = LinkStats {
        rx_packets: u64::MAX,
        tx_bytes: 1 << 40,
        ..Default::default()
    };
    let host = HostProfile::new().nic(Nic::new("eth0", 2).link_stats(stats)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = route_socket();
        let links = parse_links(&getlink_dump(fd, 1));
        unsafe { libc::close(fd) };
        assert_eq!(links[0].stats[0], u64::MAX);
        assert_eq!(links[0].stats[3], 1 << 40);
    });
}

#[test]
fn unknown_message_type_yields_bare_done() {
    // RTM_GETADDR (22) is not modelled; the backend answers with a lone NLMSG_DONE, which parses
    // as an empty link set rather than an error.
    const RTM_GETADDR: u16 = 22;
    let host = HostProfile::new().nic(Nic::new("eth0", 2)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = route_socket();
        #[repr(C)]
        struct Hdr {
            len: u32,
            ty: u16,
            flags: u16,
            seq: u32,
            pid: u32,
            body: [u8; 16],
        }
        let req = Hdr {
            len: 32,
            ty: RTM_GETADDR,
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            seq: 9,
            pid: 0,
            body: [0u8; 16],
        };
        let sent = unsafe {
            libc::send(fd, &req as *const _ as *const libc::c_void, 32, 0)
        };
        assert_eq!(sent, 32);
        let mut buf = vec![0u8; 4096];
        let got = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        assert!(got > 0);
        buf.truncate(got as usize);
        unsafe { libc::close(fd) };
        assert!(parse_links(&buf).is_empty());
    });
}

#[test]
fn many_interfaces_dump_in_one_buffer() {
    let mut host = HostProfile::new();
    for i in 0..16u32 {
        host = host.nic(Nic::new(format!("eth{i:02}"), i + 2).link_stats(LinkStats {
            rx_packets: i as u64 * 10,
            ..Default::default()
        }));
    }
    Sim::builder().host(host.build()).build().run(|| {
        let fd = route_socket();
        let links = parse_links(&getlink_dump(fd, 1));
        unsafe { libc::close(fd) };
        assert_eq!(links.len(), 16);
        for (i, l) in links.iter().enumerate() {
            assert_eq!(l.name, format!("eth{i:02}"));
            assert_eq!(l.stats[0], i as u64 * 10);
        }
    });
}
