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

        assert_eq!(links.len(), 3, "loopback and two interfaces in the dump");
        assert_eq!(links[0], ("lo".to_string(), 0, 0));
        assert_eq!(links[1], ("eth0".to_string(), 1000, 55555));
        assert_eq!(links[2], ("eth1".to_string(), 7, 42));
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
        assert_eq!(links[1..], [("eth0".to_string(), 99, 12345)]);
    });
}

#[test]
fn duplicated_netlink_descriptors_share_flags_and_replies_os_truth() {
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
    let probe = || {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_ROUTE,
            )
        };
        assert!(fd >= 0);
        let original = unsafe { std::fs::File::from_raw_fd(fd) };
        let cloned = original.try_clone().unwrap();
        assert_eq!(
            unsafe { libc::fcntl(cloned.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let nonblocking = unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0;
        let copied = unsafe { libc::dup(fd) };
        assert!(copied >= 0);
        let copy = unsafe { std::fs::File::from_raw_fd(copied) };
        let flags =
            [fd, copied, cloned.as_raw_fd()].map(|fd| unsafe { libc::fcntl(fd, libc::F_GETFD) });
        drop(original);
        drop(copy);
        let target = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let old_address = target.local_addr().unwrap();
        let targetfd = target.into_raw_fd();
        assert_eq!(
            unsafe { libc::dup2(cloned.as_raw_fd(), targetfd) },
            targetfd
        );
        let target = unsafe { std::fs::File::from_raw_fd(targetfd) };
        drop(cloned);
        let old_released = std::net::UdpSocket::bind(old_address).is_ok();
        let reply = getlink_dump(target.as_raw_fd());
        (
            nonblocking,
            flags,
            u16at(&reply, 4),
            u32at(&reply, 8),
            old_released,
        )
    };
    let real = probe();
    assert_eq!(
        real,
        (
            true,
            [libc::FD_CLOEXEC, 0, libc::FD_CLOEXEC],
            RTM_NEWLINK,
            1,
            true
        )
    );
    let host = HostProfile::new().build();
    assert_eq!(Sim::builder().host(host).build().run(probe), real);
}

/// Sends an `RTM_GETLINK` with `flags` for `index`, naming `name` in an `IFLA_IFNAME`, and returns
/// every message of the reply as (type, flags, body).
fn getlink(fd: i32, flags: u16, index: i32, name: Option<&str>) -> Vec<(u16, u16, Vec<u8>)> {
    let mut req = Vec::new();
    req.extend_from_slice(&0u32.to_ne_bytes());
    req.extend_from_slice(&RTM_GETLINK.to_ne_bytes());
    req.extend_from_slice(&(NLM_F_REQUEST | flags).to_ne_bytes());
    req.extend_from_slice(&7u32.to_ne_bytes());
    req.extend_from_slice(&0u32.to_ne_bytes());
    req.extend_from_slice(&[0, 0, 0, 0]);
    req.extend_from_slice(&index.to_ne_bytes());
    req.extend_from_slice(&[0; 8]);
    if let Some(name) = name {
        let len = 4 + name.len() + 1;
        req.extend_from_slice(&(len as u16).to_ne_bytes());
        req.extend_from_slice(&IFLA_IFNAME.to_ne_bytes());
        req.extend_from_slice(name.as_bytes());
        req.push(0);
        req.resize(align4(req.len()), 0);
    }
    let len = req.len() as u32;
    req[..4].copy_from_slice(&len.to_ne_bytes());
    let sent = unsafe { libc::send(fd, req.as_ptr().cast(), req.len(), 0) };
    assert_eq!(sent, req.len() as isize);

    let mut buf = vec![0u8; 65536];
    let got = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
    assert!(got > 0, "recv the reply");
    let buf = &buf[..got as usize];
    let mut out = Vec::new();
    let mut off = 0;
    while off + 16 <= buf.len() {
        let msg_len = u32at(buf, off) as usize;
        out.push((
            u16at(buf, off + 4),
            u16at(buf, off + 6),
            buf[off + 16..off + msg_len].to_vec(),
        ));
        off += align4(msg_len);
    }
    out
}

/// The (ifname, rx_packets, tx_bytes) of one `RTM_NEWLINK` body.
fn link_of(body: &[u8]) -> (String, u64, u64) {
    let mut msg = vec![0u8; 16];
    msg[..4].copy_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    msg[4..6].copy_from_slice(&RTM_NEWLINK.to_ne_bytes());
    msg.extend_from_slice(body);
    parse_links(&msg).remove(0)
}

/// What a non-dump `RTM_GETLINK` returns, reduced to what the sim and the kernel share: the
/// message types, whether any is part of a multipart reply, the interface name and index of an
/// `RTM_NEWLINK`, and the errno of an `NLMSG_ERROR`.
#[derive(Debug, PartialEq, Eq)]
enum Reply {
    Link {
        name: String,
        index: i32,
        multi: bool,
    },
    Error(i32),
    Other(Vec<u16>),
}

fn getlink_one(index: i32, name: Option<&str>) -> Reply {
    const NLMSG_ERROR: u16 = 2;
    const NLM_F_MULTI: u16 = 2;
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
    assert!(fd >= 0);
    let reply = getlink(fd, 0, index, name);
    unsafe { libc::close(fd) };
    match reply.as_slice() {
        [(RTM_NEWLINK, flags, body)] => {
            let link = link_of(body);
            Reply::Link {
                name: link.0,
                index: i32::from_ne_bytes(body[4..8].try_into().unwrap()),
                multi: flags & NLM_F_MULTI != 0,
            }
        }
        [(NLMSG_ERROR, _, body)] => {
            Reply::Error(-i32::from_ne_bytes(body[..4].try_into().unwrap()))
        }
        other => Reply::Other(other.iter().map(|m| m.0).collect()),
    }
}

#[test]
fn rtm_getlink_without_dump_answers_one_link() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 2).link_stats(LinkStats {
            rx_packets: 1000,
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
        let by_index = getlink(fd, 0, 3, None);
        let by_name = getlink(fd, 0, 0, Some("eth0"));
        unsafe { libc::close(fd) };
        assert_eq!(by_index.len(), 1, "no NLMSG_DONE after a single link");
        assert_eq!(link_of(&by_index[0].2), ("eth1".to_string(), 7, 42));
        assert_eq!(by_name.len(), 1);
        assert!(matches!(
            getlink_one(0, Some("eth0")),
            Reply::Link { ref name, index: 2, multi: false } if name == "eth0"
        ));
        assert_eq!(getlink_one(99, None), Reply::Error(libc::ENODEV));
        assert_eq!(getlink_one(0, Some("nope0")), Reply::Error(libc::ENODEV));
        assert_eq!(getlink_one(0, None), Reply::Error(libc::EINVAL));
    });
}

#[test]
fn rtm_getlink_without_dump_matches_the_host_os_truth() {
    let probe = || {
        [
            getlink_one(1, None),
            getlink_one(0, Some("lo")),
            getlink_one(9999, None),
            getlink_one(0, Some("nope0")),
            getlink_one(0, None),
        ]
    };
    let real = probe();
    let simulated = Sim::builder()
        .host(HostProfile::new().build())
        .build()
        .run(probe);
    assert_eq!(simulated, real);
}
