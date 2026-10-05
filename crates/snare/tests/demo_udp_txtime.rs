#![cfg(target_os = "linux")]

//! SO_TXTIME / SCM_TXTIME launch-time pacing. An ETF-paced sender arms a socket with SO_TXTIME
//! (a `struct sock_txtime { clockid_t clockid; __u32 flags; }`) and then attaches a per-packet
//! transmit deadline to each sendmsg as an SCM_TXTIME control message (a `__u64` nanosecond time
//! in that clock). See Documentation/networking/timestamping.rst ("SCM_TXTIME"), the definitions
//! in <linux/net_tstamp.h>, and man 8 tc-etf. The sim records the most recent deadline per socket;
//! `SimHost::last_tx_deadline(fd)` reads it back.

use snare::{HostProfile, Sim};

const SO_TXTIME: i32 = 61;
const SCM_TXTIME: i32 = 61;
// CLOCK_TAI (11) is the usual base clock for ETF pacing and needs CAP_NET_ADMIN (net/core/sock.c
// sk_setsockopt); CLOCK_MONOTONIC (1) is accepted from anyone.
const CLOCK_TAI: u32 = 11;

fn etf_host() -> std::sync::Arc<snare::SimHost> {
    HostProfile::new().cap(snare::CAP_NET_ADMIN).build()
}

fn udp_socket() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(fd >= 0);
    fd
}

fn loopback(port: u16) -> libc::sockaddr_in {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as u16;
    sa.sin_port = port.to_be();
    sa.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
    sa
}

fn arm_txtime(fd: i32, clockid: u32) {
    // struct sock_txtime { clockid_t clockid; __u32 flags; } — two 32-bit words.
    let sk_txtime = [clockid, 0u32];
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_TXTIME,
            sk_txtime.as_ptr() as *const libc::c_void,
            std::mem::size_of_val(&sk_txtime) as u32,
        )
    };
    assert_eq!(rc, 0);
}

/// sendmsg one payload to `port` with an SCM_TXTIME deadline attached, returning the send result.
fn sendmsg_with_deadline(fd: i32, port: u16, payload: &[u8], deadline: u64) -> isize {
    let dest = loopback(port);
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u64>() as u32) } as usize;
    let mut control = vec![0u8; space];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &dest as *const _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space;

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    assert!(!cmsg.is_null());
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = SCM_TXTIME;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u64>() as u32) as _;
        let data = libc::CMSG_DATA(cmsg) as *mut u64;
        data.write_unaligned(deadline);
    }
    unsafe { libc::sendmsg(fd, &msg, 0) }
}

fn sendmsg_plain(fd: i32, port: u16, payload: &[u8]) -> isize {
    let dest = loopback(port);
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &dest as *const _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    unsafe { libc::sendmsg(fd, &msg, 0) }
}

#[test]
fn scm_txtime_deadline_is_recorded() {
    let host = etf_host();
    Sim::builder().host(host.clone()).build().run(|| {
        let fd = udp_socket();
        arm_txtime(fd, CLOCK_TAI);
        let deadline: u64 = 1_700_000_123_456_789;
        assert_eq!(sendmsg_with_deadline(fd, 9600, b"etf", deadline), 3);
        assert_eq!(host.last_tx_deadline(fd), Some(deadline));
        unsafe { libc::close(fd) };
    });
}

#[test]
fn the_latest_deadline_wins() {
    // Each paced send overwrites the recorded deadline; a test asserts the most recent pacing
    // request, matching how ETF consumes one SCM_TXTIME per packet.
    let host = etf_host();
    Sim::builder().host(host.clone()).build().run(|| {
        let fd = udp_socket();
        arm_txtime(fd, CLOCK_TAI);
        assert_eq!(sendmsg_with_deadline(fd, 9610, b"a", 1_000), 1);
        assert_eq!(host.last_tx_deadline(fd), Some(1_000));
        assert_eq!(sendmsg_with_deadline(fd, 9610, b"b", 2_000), 1);
        assert_eq!(host.last_tx_deadline(fd), Some(2_000));
        assert_eq!(sendmsg_with_deadline(fd, 9610, b"c", 500), 1);
        assert_eq!(
            host.last_tx_deadline(fd),
            Some(500),
            "the newest deadline replaces the old"
        );
        unsafe { libc::close(fd) };
    });
}

#[test]
fn a_plain_sendmsg_leaves_no_deadline() {
    // A send with no SCM_TXTIME control message records nothing, even on an SO_TXTIME-armed socket.
    let host = etf_host();
    Sim::builder().host(host.clone()).build().run(|| {
        let fd = udp_socket();
        arm_txtime(fd, CLOCK_TAI);
        assert_eq!(sendmsg_plain(fd, 9620, b"nodeadline"), 10);
        assert_eq!(host.last_tx_deadline(fd), None);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn deadlines_are_tracked_per_socket() {
    let host = etf_host();
    Sim::builder().host(host.clone()).build().run(|| {
        let a = udp_socket();
        let b = udp_socket();
        arm_txtime(a, CLOCK_TAI);
        arm_txtime(b, CLOCK_TAI);
        assert_eq!(sendmsg_with_deadline(a, 9630, b"a", 111), 1);
        assert_eq!(sendmsg_with_deadline(b, 9631, b"b", 222), 1);
        assert_eq!(host.last_tx_deadline(a), Some(111));
        assert_eq!(
            host.last_tx_deadline(b),
            Some(222),
            "sockets do not share a deadline"
        );
        unsafe {
            libc::close(a);
            libc::close(b);
        }
    });
}

#[test]
fn so_txtime_config_reads_back() {
    // The `sock_txtime` armed with setsockopt reads back verbatim through getsockopt.
    Sim::builder().host(etf_host()).build().run(|| {
        let fd = udp_socket();
        arm_txtime(fd, CLOCK_TAI);
        let mut got = [0u32; 2];
        let mut len = std::mem::size_of_val(&got) as u32;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_TXTIME,
                got.as_mut_ptr() as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(got[0], CLOCK_TAI, "clockid preserved");
        assert_eq!(got[1], 0, "flags preserved");
        unsafe { libc::close(fd) };
    });
}

#[test]
fn deadline_for_an_unknown_fd_is_none() {
    let host = HostProfile::new().build();
    Sim::builder().host(host.clone()).build().run(|| {
        assert_eq!(host.last_tx_deadline(4242), None, "no socket, no deadline");
    });
}

#[test]
fn a_monotonic_clock_base_is_also_accepted() {
    // ETF may pace against CLOCK_MONOTONIC instead of CLOCK_TAI; the deadline is opaque to the sim.
    const CLOCK_MONOTONIC: u32 = 1;
    let host = HostProfile::new().build();
    Sim::builder().host(host.clone()).build().run(|| {
        let fd = udp_socket();
        arm_txtime(fd, CLOCK_MONOTONIC);
        assert_eq!(sendmsg_with_deadline(fd, 9640, b"m", 42), 1);
        assert_eq!(host.last_tx_deadline(fd), Some(42));
        unsafe { libc::close(fd) };
    });
}
