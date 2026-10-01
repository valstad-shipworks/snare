#![cfg(target_os = "linux")]

use snare::{HostProfile, Sim};

const SO_TXTIME: i32 = 61;
const SCM_TXTIME: i32 = 61;

fn loopback(port: u16) -> libc::sockaddr_in {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as u16;
    sa.sin_port = port.to_be();
    sa.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
    sa
}

#[test]
fn sendmsg_records_the_scm_txtime_deadline() {
    let host = HostProfile::new().build();
    let sim = Sim::builder().host(host.clone()).build();
    sim.run(|| {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(fd >= 0);

        // fast-talker/ETF arms the socket clock, then paces each packet with SCM_TXTIME.
        let txtime = [libc::CLOCK_TAI as u32, 0u32]; // struct sock_txtime { clockid; flags; }
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_TXTIME,
                txtime.as_ptr() as *const libc::c_void,
                std::mem::size_of_val(&txtime) as u32,
            )
        };
        assert_eq!(rc, 0);

        let deadline: u64 = 1_700_000_123_456_789;
        let dest = loopback(9400);
        let payload = b"etf";
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

        let sent = unsafe { libc::sendmsg(fd, &msg, 0) };
        assert_eq!(sent, payload.len() as isize);

        assert_eq!(
            host.last_tx_deadline(fd),
            Some(deadline),
            "the SCM_TXTIME pacing deadline is recorded per socket"
        );

        unsafe { libc::close(fd) };
    });
}

#[test]
fn a_plain_send_leaves_no_deadline() {
    let host = HostProfile::new().build();
    let sim = Sim::builder().host(host.clone()).build();
    sim.run(|| {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(fd >= 0);
        let dest = loopback(9401);
        let payload = b"x";
        unsafe {
            libc::sendto(
                fd,
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
                0,
                &dest as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            );
        }
        assert_eq!(host.last_tx_deadline(fd), None);
        unsafe { libc::close(fd) };
    });
}
