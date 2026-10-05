#![cfg(target_os = "linux")]

use snare::{HostProfile, Privileges, Sim};

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
    let host = HostProfile::new().cap(snare::CAP_NET_ADMIN).build();
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

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn set_txtime(fd: i32, clockid: i32, flags: u32, len: u32) -> Result<(), i32> {
    let v = [clockid as u32, flags];
    let rc = unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, SO_TXTIME, v.as_ptr().cast(), len) };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

fn get_txtime(fd: i32) -> Result<([u32; 2], u32), i32> {
    let mut v = [0u32; 2];
    let mut len = 8u32;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_TXTIME,
            v.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc == 0 { Ok((v, len)) } else { Err(errno()) }
}

/// A datagram to loopback `port` with an `SCM_TXTIME` message of `len` data bytes.
fn send_txtime(fd: i32, port: u16, len: usize) -> Result<isize, i32> {
    let dest = loopback(port);
    let payload = *b"etf!";
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    #[repr(C, align(8))]
    struct Control([u8; 64]);
    let mut control = Control([0; 64]);
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &dest as *const _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(len as u32) } as _;
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = SCM_TXTIME;
        (*c).cmsg_len = libc::CMSG_LEN(len as u32) as _;
    }
    let n = unsafe { libc::sendmsg(fd, &msg, 0) };
    if n >= 0 { Ok(n) } else { Err(errno()) }
}

/// net/core/sock.c `sk_setsockopt` `SO_TXTIME` (Linux 7.0): the value is exactly a `struct
/// sock_txtime` (`EINVAL` otherwise), its flags within `SOF_TXTIME_FLAGS_MASK` (`EINVAL`), its
/// clock one of `CLOCK_REALTIME`, `CLOCK_MONOTONIC` and `CLOCK_TAI` (`EINVAL`); a refused request
/// keeps the setting before it, and `getsockopt` reads the whole struct (8 bytes, `sk_clockid` 0
/// before any set).
#[test]
fn so_txtime_is_validated_and_reads_back_whole() {
    let host = HostProfile::new().cap(snare::CAP_NET_ADMIN).build();
    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert_eq!(get_txtime(fd), Ok(([0, 0], 8)), "before any set");
        assert_eq!(set_txtime(fd, libc::CLOCK_MONOTONIC, 0b11, 8), Ok(()));
        assert_eq!(get_txtime(fd), Ok(([1, 3], 8)));
        for (clockid, flags, len) in [
            (libc::CLOCK_TAI, 1 << 7, 8),
            (libc::CLOCK_TAI, 0, 4),
            (libc::CLOCK_TAI, 0, 12),
            (99, 0, 8),
        ] {
            assert_eq!(
                set_txtime(fd, clockid, flags, len),
                Err(libc::EINVAL),
                "clock {clockid} flags {flags:#x} optlen {len}"
            );
            assert_eq!(get_txtime(fd), Ok(([1, 3], 8)), "unchanged");
        }
        assert_eq!(set_txtime(fd, libc::CLOCK_TAI, 0, 8), Ok(()));
        assert_eq!(get_txtime(fd), Ok(([libc::CLOCK_TAI as u32, 0], 8)));
        let mut word = 0u32;
        let mut len = 4u32;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_TXTIME,
                (&raw mut word).cast(),
                &mut len,
            )
        };
        assert_eq!(
            (rc, word, len),
            (0, libc::CLOCK_TAI as u32, 4),
            "cut to the buffer"
        );
        unsafe { libc::close(fd) };
    });
}

/// `sk_setsockopt`: a clock other than `CLOCK_MONOTONIC` needs `CAP_NET_ADMIN` (`EPERM`, checked
/// before the clock itself, so an unknown clock is `EPERM` too).
#[test]
fn so_txtime_off_monotonic_needs_net_admin() {
    Sim::builder()
        .host(HostProfile::new().build())
        .privileges(Privileges::none())
        .build()
        .run(|| {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            assert_eq!(set_txtime(fd, libc::CLOCK_TAI, 0, 8), Err(libc::EPERM));
            assert_eq!(set_txtime(fd, libc::CLOCK_REALTIME, 0, 8), Err(libc::EPERM));
            assert_eq!(set_txtime(fd, 99, 0, 8), Err(libc::EPERM));
            assert_eq!(set_txtime(fd, libc::CLOCK_MONOTONIC, 1, 8), Ok(()));
            assert_eq!(get_txtime(fd), Ok(([1, 1], 8)));
            unsafe { libc::close(fd) };
        });
}

/// net/core/sock.c `__sock_cmsg_send`: `SCM_TXTIME` on a socket without `SO_TXTIME`, or with a
/// `cmsg_len` other than `CMSG_LEN(sizeof(u64))`, fails the whole `sendmsg` with `EINVAL`.
#[test]
fn scm_txtime_needs_so_txtime_and_a_u64() {
    let host = HostProfile::new().cap(snare::CAP_NET_ADMIN).build();
    Sim::builder().host(host.clone()).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert_eq!(
            send_txtime(fd, 9402, 8),
            Err(libc::EINVAL),
            "without SO_TXTIME"
        );
        assert_eq!(host.last_tx_deadline(fd), None);
        assert_eq!(set_txtime(fd, libc::CLOCK_TAI, 0, 8), Ok(()));
        assert_eq!(
            send_txtime(fd, 9402, 4),
            Err(libc::EINVAL),
            "a 4-byte message"
        );
        assert_eq!(send_txtime(fd, 9402, 8), Ok(4));
        assert_eq!(host.last_tx_deadline(fd), Some(0));
        unsafe { libc::close(fd) };
    });
}

/// The plain fabric's sockets keep `SO_TXTIME` by the same rules as a `SimHost`'s.
#[test]
fn fabric_so_txtime_follows_the_same_rules() {
    Sim::builder()
        .privileges(Privileges::none())
        .build()
        .run(|| {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            assert_eq!(get_txtime(fd), Ok(([0, 0], 8)));
            assert_eq!(set_txtime(fd, libc::CLOCK_TAI, 0, 8), Err(libc::EPERM));
            assert_eq!(
                set_txtime(fd, libc::CLOCK_MONOTONIC, 1 << 2, 8),
                Err(libc::EINVAL)
            );
            assert_eq!(
                set_txtime(fd, libc::CLOCK_MONOTONIC, 0, 4),
                Err(libc::EINVAL)
            );
            assert_eq!(set_txtime(fd, libc::CLOCK_MONOTONIC, 2, 8), Ok(()));
            assert_eq!(get_txtime(fd), Ok(([1, 2], 8)));
            unsafe { libc::close(fd) };
        });
}
