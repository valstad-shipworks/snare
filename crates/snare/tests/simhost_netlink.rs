#![cfg(target_os = "linux")]

use snare::{HostProfile, LinkStats, Nic, Sim};

const NETLINK_ROUTE: i32 = 0;
const RTM_GETLINK: u16 = 18;
const RTM_NEWLINK: u16 = 16;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const IFLA_IFNAME: u16 = 3;
const IFLA_STATS64: u16 = 23;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Read one u16/u32/u64 from a byte slice (native endian, as netlink uses).
fn u16at(b: &[u8], o: usize) -> u16 {
    u16::from_ne_bytes([b[o], b[o + 1]])
}
fn u32at(b: &[u8], o: usize) -> u32 {
    u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64at(b: &[u8], o: usize) -> u64 {
    u64::from_ne_bytes(b[o..o + 8].try_into().unwrap())
}

/// Parse an RTM_GETLINK dump into (ifname, rx_packets, tx_bytes) tuples.
fn parse_links(buf: &[u8]) -> Vec<(String, u64, u64)> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 16 <= buf.len() {
        let msg_len = u32at(buf, off) as usize;
        let msg_type = u16at(buf, off + 4);
        if msg_len < 16 || off + msg_len > buf.len() {
            break;
        }
        if msg_type == NLMSG_DONE {
            break;
        }
        if msg_type == RTM_NEWLINK {
            // nlmsghdr(16) + ifinfomsg(16), then rtattrs.
            let mut a = off + 32;
            let end = off + msg_len;
            let mut name = String::new();
            let mut rx_packets = 0u64;
            let mut tx_bytes = 0u64;
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
                        rx_packets = u64at(payload, 0);
                        tx_bytes = u64at(payload, 24);
                    }
                    _ => {}
                }
                a += align4(rta_len);
            }
            out.push((name, rx_packets, tx_bytes));
        }
        off += align4(msg_len);
    }
    out
}

fn getlink_dump(fd: i32) -> Vec<u8> {
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
        nlmsg_seq: 1,
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

#[test]
fn rtm_getlink_reports_interfaces_and_stats() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 2).link_stats(LinkStats {
            rx_packets: 1000,
            tx_bytes: 55555,
            ..Default::default()
        }))
        .nic(Nic::new("eth1", 3).link_stats(LinkStats {
            rx_packets: 7,
            tx_bytes: 42,
            ..Default::default()
        }))
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
        assert!(fd >= 0);
        let links = parse_links(&getlink_dump(fd));
        unsafe { libc::close(fd) };

        assert_eq!(links.len(), 2, "two interfaces in the dump");
        assert_eq!(links[0], ("eth0".to_string(), 1000, 55555));
        assert_eq!(links[1], ("eth1".to_string(), 7, 42));
    });
}

/// The canonical netlink I/O path (rtnetlink/netlink-sys) uses sendmsg+recvmsg, not sendto+recv.
#[test]
fn rtm_getlink_via_sendmsg_recvmsg() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 2).link_stats(LinkStats {
            rx_packets: 99,
            tx_bytes: 12345,
            ..Default::default()
        }))
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
        assert!(fd >= 0);

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
        let mut req = Request {
            nlmsg_len: 32,
            nlmsg_type: RTM_GETLINK,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
            nlmsg_seq: 1,
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

        let mut iov = libc::iovec {
            iov_base: &mut req as *mut _ as *mut libc::c_void,
            iov_len: 32,
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &mut dest as *mut _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        let sent = unsafe { libc::sendmsg(fd, &msg, 0) };
        assert_eq!(sent, 32, "sendmsg the RTM_GETLINK request");

        let mut buf = vec![0u8; 65536];
        let mut riov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut rmsg: libc::msghdr = unsafe { std::mem::zeroed() };
        rmsg.msg_iov = &mut riov;
        rmsg.msg_iovlen = 1;
        let got = unsafe { libc::recvmsg(fd, &mut rmsg, 0) };
        assert!(got > 0, "recvmsg the dump (got {got})");
        buf.truncate(got as usize);

        let links = parse_links(&buf);
        unsafe { libc::close(fd) };
        assert_eq!(links, vec![("eth0".to_string(), 99, 12345)]);
    });
}
