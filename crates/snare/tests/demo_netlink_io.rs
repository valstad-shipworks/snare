#![cfg(target_os = "linux")]

//! Netlink socket I/O: the send/receive call variants, queueing, truncation re-queue, and the
//! error paths.
//!
//! Protocol reference: man 7 netlink. A netlink socket is AF_NETLINK, opened SOCK_RAW or
//! SOCK_DGRAM (the kernel treats them alike), and requests may be issued with send/sendto/sendmsg;
//! replies drained with recv/recvfrom/recvmsg. rtnetlink message numbers are from
//! <linux/rtnetlink.h>.

use snare::{HostProfile, LinkStats, Nic, Sim};

const NETLINK_ROUTE: i32 = 0;
const NETLINK_GENERIC: i32 = 16;
const NETLINK_XFRM: i32 = 6;
const RTM_GETLINK: u16 = 18;
const RTM_NEWLINK: u16 = 16;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const IFLA_IFNAME: u16 = 3;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}
fn u16at(b: &[u8], o: usize) -> u16 {
    u16::from_ne_bytes([b[o], b[o + 1]])
}
fn u32at(b: &[u8], o: usize) -> u32 {
    u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// A 32-byte RTM_GETLINK dump request (16-byte nlmsghdr + 16-byte ifinfomsg).
fn getlink_request(seq: u32) -> [u8; 32] {
    let mut req = [0u8; 32];
    req[0..4].copy_from_slice(&32u32.to_ne_bytes());
    req[4..6].copy_from_slice(&RTM_GETLINK.to_ne_bytes());
    req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    req[8..12].copy_from_slice(&seq.to_ne_bytes());
    req
}

/// Names of the interfaces in a (possibly reassembled) RTM_GETLINK dump.
fn link_names(buf: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 16 <= buf.len() {
        let msg_len = u32at(buf, off) as usize;
        let msg_type = u16at(buf, off + 4);
        if msg_len < 16 || off + msg_len > buf.len() || msg_type == NLMSG_DONE {
            break;
        }
        if msg_type == RTM_NEWLINK {
            let mut a = off + 32;
            let end = off + msg_len;
            while a + 4 <= end {
                let rta_len = u16at(buf, a) as usize;
                let rta_type = u16at(buf, a + 2);
                if rta_len < 4 || a + rta_len > end {
                    break;
                }
                if rta_type == IFLA_IFNAME {
                    let p = &buf[a + 4..a + rta_len];
                    let s = p.split(|&c| c == 0).next().unwrap_or(&[]);
                    out.push(String::from_utf8_lossy(s).into_owned());
                }
                a += align4(rta_len);
            }
        }
        off += align4(msg_len);
    }
    out
}

fn two_nic_host() -> std::sync::Arc<snare::SimHost> {
    HostProfile::new()
        .nic(Nic::new("eth0", 2).link_stats(LinkStats { rx_packets: 10, ..Default::default() }))
        .nic(Nic::new("eth1", 3))
        .build()
}

#[test]
fn socket_opens_on_several_protocols_and_types() {
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        // The protocol subscription and datagram-vs-raw distinction do not change socket creation
        // in the model; all of these are valid AF_NETLINK sockets (man 7 netlink).
        for proto in [NETLINK_ROUTE, NETLINK_GENERIC, NETLINK_XFRM] {
            let raw = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, proto) };
            assert!(raw >= 0, "SOCK_RAW proto {proto}");
            let dgram = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, proto) };
            assert!(dgram >= 0, "SOCK_DGRAM proto {proto}");
            unsafe {
                libc::close(raw);
                libc::close(dgram);
            }
        }
    });
}

#[test]
fn recv_on_an_idle_socket_is_eagain() {
    Sim::builder().host(two_nic_host()).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
        let mut buf = [0u8; 4096];
        // Nothing has been requested, so there is no reply queued: EAGAIN, not a block or error.
        let got = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        assert_eq!(got, -1);
        assert_eq!(errno(), libc::EAGAIN);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn send_sendto_and_sendmsg_all_produce_a_dump() {
    Sim::builder().host(two_nic_host()).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
        let req = getlink_request(1);

        // send(): no destination address.
        let n = unsafe { libc::send(fd, req.as_ptr() as *const _, 32, 0) };
        assert_eq!(n, 32);
        let mut buf = vec![0u8; 8192];
        let got = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        assert!(got > 0);
        buf.truncate(got as usize);
        assert_eq!(link_names(&buf), vec!["eth0", "eth1"]);

        // sendto() with an explicit sockaddr_nl destination (nl_pid 0 = the kernel).
        let mut dest: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dest.nl_family = libc::AF_NETLINK as u16;
        let n = unsafe {
            libc::sendto(
                fd,
                req.as_ptr() as *const _,
                32,
                0,
                &dest as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        assert_eq!(n, 32);
        let got = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        buf.truncate(got as usize);
        assert_eq!(link_names(&buf), vec!["eth0", "eth1"]);

        // sendmsg() with the request scattered across one iovec.
        let mut req2 = getlink_request(2);
        let mut iov = libc::iovec {
            iov_base: req2.as_mut_ptr() as *mut libc::c_void,
            iov_len: 32,
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &mut dest as *mut _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        let n = unsafe { libc::sendmsg(fd, &msg, 0) };
        assert_eq!(n, 32);
        let mut buf = vec![0u8; 8192];
        let got = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        buf.truncate(got as usize);
        assert_eq!(link_names(&buf), vec!["eth0", "eth1"]);

        unsafe { libc::close(fd) };
    });
}

#[test]
fn queued_dumps_drain_in_fifo_order() {
    // One request per NIC set; the sim queues a reply per request and hands them back in order.
    let host = HostProfile::new().nic(Nic::new("eth0", 2)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
        for seq in [11u32, 22, 33] {
            let req = getlink_request(seq);
            unsafe { libc::send(fd, req.as_ptr() as *const _, 32, 0) };
        }
        for seq in [11u32, 22, 33] {
            let mut buf = vec![0u8; 8192];
            let got = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
            assert!(got > 0);
            // The seq of the first message identifies which request this reply answers.
            assert_eq!(u32at(&buf, 8), seq, "FIFO: reply {seq} arrives in order");
        }
        unsafe { libc::close(fd) };
    });
}

#[test]
fn recvmsg_scatters_the_reply_across_iovecs() {
    Sim::builder().host(two_nic_host()).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
        let req = getlink_request(1);
        unsafe { libc::send(fd, req.as_ptr() as *const _, 32, 0) };

        // Three segments; the reply is gathered into them in order (man 2 recvmsg).
        let mut a = [0u8; 40];
        let mut b = [0u8; 40];
        let mut c = [0u8; 8192];
        let mut iov = [
            libc::iovec { iov_base: a.as_mut_ptr() as *mut _, iov_len: a.len() },
            libc::iovec { iov_base: b.as_mut_ptr() as *mut _, iov_len: b.len() },
            libc::iovec { iov_base: c.as_mut_ptr() as *mut _, iov_len: c.len() },
        ];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = iov.len();
        let got = unsafe { libc::recvmsg(fd, &mut msg, 0) };
        assert!(got > 0);

        let mut whole = Vec::new();
        whole.extend_from_slice(&a);
        whole.extend_from_slice(&b);
        whole.extend_from_slice(&c);
        whole.truncate(got as usize);
        assert_eq!(link_names(&whole), vec!["eth0", "eth1"]);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn small_buffer_truncation_requeues_the_tail() {
    // The real kernel would set MSG_TRUNC and drop the remainder of an oversized datagram; this
    // sim instead re-queues the unread tail (including the terminating NLMSG_DONE) so a reader
    // that drains in small reads still reassembles the whole dump.
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 2))
        .nic(Nic::new("eth1", 3))
        .nic(Nic::new("eth2", 4))
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
        let req = getlink_request(1);
        unsafe { libc::send(fd, req.as_ptr() as *const _, 32, 0) };

        let mut whole = Vec::new();
        loop {
            let mut chunk = [0u8; 24];
            let got = unsafe { libc::recv(fd, chunk.as_mut_ptr() as *mut _, chunk.len(), 0) };
            if got <= 0 {
                assert_eq!(errno(), libc::EAGAIN, "drained cleanly to EAGAIN");
                break;
            }
            whole.extend_from_slice(&chunk[..got as usize]);
        }
        unsafe { libc::close(fd) };
        assert_eq!(link_names(&whole), vec!["eth0", "eth1", "eth2"]);
    });
}

#[test]
fn recvmsg_small_iovec_requeues_the_tail() {
    let host = HostProfile::new().nic(Nic::new("eth0", 2)).nic(Nic::new("eth1", 3)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
        let req = getlink_request(1);
        unsafe { libc::send(fd, req.as_ptr() as *const _, 32, 0) };

        let mut whole = Vec::new();
        loop {
            let mut seg = [0u8; 20];
            let mut iov = libc::iovec {
                iov_base: seg.as_mut_ptr() as *mut _,
                iov_len: seg.len(),
            };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            let got = unsafe { libc::recvmsg(fd, &mut msg, 0) };
            if got <= 0 {
                assert_eq!(errno(), libc::EAGAIN);
                break;
            }
            whole.extend_from_slice(&seg[..got as usize]);
        }
        unsafe { libc::close(fd) };
        assert_eq!(link_names(&whole), vec!["eth0", "eth1"]);
    });
}

#[test]
fn a_short_request_yields_a_bare_done() {
    // A request too short to hold a full nlmsghdr (< 12 bytes) cannot name a type; the backend
    // answers with a lone NLMSG_DONE, i.e. an empty dump.
    Sim::builder().host(two_nic_host()).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
        let stub = [0u8; 4];
        let n = unsafe { libc::send(fd, stub.as_ptr() as *const _, stub.len(), 0) };
        assert_eq!(n, 4);
        let mut buf = vec![0u8; 4096];
        let got = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        assert!(got > 0);
        buf.truncate(got as usize);
        unsafe { libc::close(fd) };
        assert!(link_names(&buf).is_empty());
        assert_eq!(u16at(&buf, 4), NLMSG_DONE);
    });
}

#[test]
fn close_releases_the_socket() {
    Sim::builder().host(two_nic_host()).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
        assert!(fd >= 0);
        assert_eq!(unsafe { libc::close(fd) }, 0, "close a netlink socket");
    });
}
