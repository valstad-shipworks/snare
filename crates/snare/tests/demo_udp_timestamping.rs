#![cfg(target_os = "linux")]

//! Software receive timestamping: SO_TIMESTAMPING requests per-datagram timestamps that recvmsg
//! delivers as an SCM_TIMESTAMPING control message carrying `struct scm_timestamping`.
//! See Documentation/networking/timestamping.rst, the SOF_TIMESTAMPING_* flags and the
//! `scm_timestamping` layout in <linux/net_tstamp.h>. The stamps come from the sim's virtual clock
//! (fixed epoch 2023-11-14T00:00:00Z), so seconds are deterministic and ordering is monotonic.

use snare::{HostProfile, Sim};

// SO_TIMESTAMPING == SCM_TIMESTAMPING == 37 (asm-generic/socket.h). The SOF_TIMESTAMPING_* bits
// are the generation/reporting flags from <linux/net_tstamp.h>.
const SO_TIMESTAMPING: i32 = 37;
const SCM_TIMESTAMPING: i32 = 37;
const SOF_TIMESTAMPING_TX_SOFTWARE: u32 = 1 << 1;
const SOF_TIMESTAMPING_RX_SOFTWARE: u32 = 1 << 3;
const SOF_TIMESTAMPING_SOFTWARE: u32 = 1 << 4;

const VIRTUAL_EPOCH_SECS: i64 = 1_700_000_000;

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

fn bind4(fd: i32, port: u16) {
    let sa = loopback(port);
    let rc = unsafe {
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    assert_eq!(rc, 0);
}

fn sendto4(fd: i32, port: u16, payload: &[u8]) -> isize {
    let dest = loopback(port);
    unsafe {
        libc::sendto(
            fd,
            payload.as_ptr() as *const _,
            payload.len(),
            0,
            &dest as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    }
}

fn enable_rx_sw_timestamping(fd: i32) {
    let flags = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_TIMESTAMPING,
            &flags as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as u32,
        )
    };
    assert_eq!(rc, 0);
}

/// Receive one datagram on `fd` and return the SCM_TIMESTAMPING `scm_timestamping` (3 timespecs),
/// if the kernel attached one, along with the payload length.
fn recv_with_timestamp(fd: i32) -> (isize, Option<[libc::timespec; 3]>) {
    let mut buf = [0u8; 64];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };
    let mut control = [0u8; 128];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut _;
    msg.msg_controllen = control.len();

    let got = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if got < 0 {
        return (got, None);
    }
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let (level, ty) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
        if level == libc::SOL_SOCKET && ty == SCM_TIMESTAMPING {
            let data = unsafe { libc::CMSG_DATA(cmsg) } as *const [libc::timespec; 3];
            return (got, Some(unsafe { data.read_unaligned() }));
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    (got, None)
}

fn nanos(ts: libc::timespec) -> i128 {
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

#[test]
fn recvmsg_carries_a_software_rx_timestamp() {
    Sim::builder()
        .host(HostProfile::new().build())
        .fixed_epoch()
        .build()
        .run(|| {
            let tx = udp_socket();
            let rx = udp_socket();
            bind4(rx, 9300);
            enable_rx_sw_timestamping(rx);
            assert_eq!(sendto4(tx, 9300, b"tsdata"), 6);

            let (got, ts) = recv_with_timestamp(rx);
            assert_eq!(got, 6);
            let scm = ts.expect("SCM_TIMESTAMPING control message present");
            // Slot 0 is the software timestamp; the hardware slots (1: legacy, 2: raw hw) stay zero.
            assert_eq!(
                scm[0].tv_sec, VIRTUAL_EPOCH_SECS,
                "software stamp sits at the virtual epoch"
            );
            assert!(scm[0].tv_nsec > 0);
            assert_eq!(
                scm[0].tv_nsec % 1000,
                0,
                "virtual clock ticks in microseconds"
            );
            assert_eq!(nanos(scm[1]), 0, "no legacy hardware timestamp");
            assert_eq!(nanos(scm[2]), 0, "no raw hardware timestamp");

            unsafe {
                libc::close(tx);
                libc::close(rx);
            }
        });
}

#[test]
fn no_control_message_when_timestamping_is_off() {
    // Without SO_TIMESTAMPING the datagram is delivered with an empty control buffer.
    Sim::builder()
        .host(HostProfile::new().build())
        .fixed_epoch()
        .build()
        .run(|| {
            let tx = udp_socket();
            let rx = udp_socket();
            bind4(rx, 9310);
            assert_eq!(sendto4(tx, 9310, b"plain"), 5);

            let mut buf = [0u8; 16];
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut _,
                iov_len: buf.len(),
            };
            let mut control = [0u8; 128];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr() as *mut _;
            msg.msg_controllen = control.len();

            let got = unsafe { libc::recvmsg(rx, &mut msg, 0) };
            assert_eq!(got, 5);
            assert_eq!(
                msg.msg_controllen, 0,
                "no SCM_TIMESTAMPING when timestamping is disabled"
            );
            assert!(unsafe { libc::CMSG_FIRSTHDR(&msg) }.is_null());
            unsafe {
                libc::close(tx);
                libc::close(rx);
            }
        });
}

#[test]
fn receive_timestamps_advance_between_datagrams() {
    // Each datagram is stamped at send time from the monotonically advancing virtual clock, so a
    // later datagram carries a strictly later timestamp (Documentation/networking/timestamping.rst).
    Sim::builder()
        .host(HostProfile::new().build())
        .fixed_epoch()
        .build()
        .run(|| {
            let tx = udp_socket();
            let rx = udp_socket();
            bind4(rx, 9320);
            enable_rx_sw_timestamping(rx);
            assert_eq!(sendto4(tx, 9320, b"one"), 3);
            assert_eq!(sendto4(tx, 9320, b"two"), 3);

            let (_, first) = recv_with_timestamp(rx);
            let (_, second) = recv_with_timestamp(rx);
            let a = nanos(first.expect("first stamp")[0]);
            let b = nanos(second.expect("second stamp")[0]);
            assert!(b > a, "second datagram stamped later ({a} -> {b})");
            unsafe {
                libc::close(tx);
                libc::close(rx);
            }
        });
}

#[test]
fn rx_timestamp_survives_a_small_control_buffer_without_ub() {
    // recvmsg(2): a control buffer too small for the cmsg drops the ancillary data (and would set
    // MSG_CTRUNC); the datagram payload is still delivered. The sim reports zero control length.
    Sim::builder()
        .host(HostProfile::new().build())
        .fixed_epoch()
        .build()
        .run(|| {
            let tx = udp_socket();
            let rx = udp_socket();
            bind4(rx, 9330);
            enable_rx_sw_timestamping(rx);
            assert_eq!(sendto4(tx, 9330, b"tiny"), 4);

            let mut buf = [0u8; 8];
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut _,
                iov_len: buf.len(),
            };
            let mut control = [0u8; 4];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr() as *mut _;
            msg.msg_controllen = control.len();

            let got = unsafe { libc::recvmsg(rx, &mut msg, 0) };
            assert_eq!(got, 4);
            assert_eq!(&buf[..4], b"tiny");
            assert_eq!(msg.msg_controllen, 0, "cmsg dropped when it does not fit");
            unsafe {
                libc::close(tx);
                libc::close(rx);
            }
        });
}

#[test]
fn getsockopt_reads_back_the_timestamping_flags() {
    // The generation/reporting bitmask set with SO_TIMESTAMPING reads back verbatim.
    Sim::builder()
        .host(HostProfile::new().build())
        .fixed_epoch()
        .build()
        .run(|| {
            let fd = udp_socket();
            let flags = SOF_TIMESTAMPING_SOFTWARE
                | SOF_TIMESTAMPING_RX_SOFTWARE
                | SOF_TIMESTAMPING_TX_SOFTWARE;
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    SO_TIMESTAMPING,
                    &flags as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as u32,
                )
            };
            assert_eq!(rc, 0);

            let mut got: u32 = 0;
            let mut len = std::mem::size_of::<u32>() as u32;
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    SO_TIMESTAMPING,
                    &mut got as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            assert_eq!(rc, 0);
            assert_eq!(got, flags);
            unsafe { libc::close(fd) };
        });
}
