//! Arm a UDP socket for ETF launch-time pacing and send one packet with a transmit deadline.
//!
//! An SO_TXTIME-armed socket carries a per-packet launch time as an SCM_TXTIME control message on
//! sendmsg (a `__u64` nanosecond deadline in the socket's clock). The sim records the deadline the
//! code under test requested; `SimHost::last_tx_deadline(fd)` reads it back, which is how a test
//! checks that an ETF/TSN sender paced a packet correctly. See
//! Documentation/networking/timestamping.rst ("SCM_TXTIME"), <linux/net_tstamp.h>, and man 8 tc-etf.
//!
//! Run with: `cargo run -p snare --example udp_txtime_pacing`

#[cfg(target_os = "linux")]
fn main() {
    use snare::{HostProfile, Sim};

    const SO_TXTIME: i32 = 61;
    const SCM_TXTIME: i32 = 61;
    const CLOCK_TAI: u32 = 11;

    let host = HostProfile::new().build();
    Sim::builder().host(host.clone()).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(fd >= 0);

        // struct sock_txtime { clockid_t clockid; __u32 flags; }
        let sk_txtime = [CLOCK_TAI, 0u32];
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_TXTIME,
                sk_txtime.as_ptr() as *const libc::c_void,
                std::mem::size_of_val(&sk_txtime) as u32,
            );
        }

        let mut dest: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        dest.sin_family = libc::AF_INET as u16;
        dest.sin_port = 5100u16.to_be();
        dest.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();

        let payload = b"frame";
        let mut iov = libc::iovec { iov_base: payload.as_ptr() as *mut libc::c_void, iov_len: payload.len() };
        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u64>() as u32) } as usize;
        let mut control = vec![0u8; space];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &dest as *const _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space;

        let deadline: u64 = 1_700_000_500_000_000;
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = SCM_TXTIME;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u64>() as u32) as _;
            (libc::CMSG_DATA(cmsg) as *mut u64).write_unaligned(deadline);
        }

        let sent = unsafe { libc::sendmsg(fd, &msg, 0) };
        assert_eq!(sent, payload.len() as isize);

        println!(
            "paced {} bytes with SCM_TXTIME deadline {}; recorded={:?}",
            sent,
            deadline,
            host.last_tx_deadline(fd),
        );
        assert_eq!(host.last_tx_deadline(fd), Some(deadline));
        unsafe { libc::close(fd) };
    });
}

#[cfg(not(target_os = "linux"))]
fn main() {
    // SO_TXTIME / SCM_TXTIME pacing is a Linux-only feature (man 8 tc-etf); the UDP fabric is
    // modelled only on Linux.
    println!("udp_txtime_pacing: requires Linux (SO_TXTIME); skipping on this OS");
}
