#![cfg(target_os = "linux")]

//! Transmit timestamping via the socket error queue. A socket with SOF_TIMESTAMPING_TX_SOFTWARE
//! gets a timestamped completion queued on its error queue, read back with recvmsg(MSG_ERRQUEUE).
//! See Documentation/networking/timestamping.rst ("Transmit timestamping"), the SOF_TIMESTAMPING_*
//! flags in <linux/net_tstamp.h>, and the error-queue delivery model in <linux/errqueue.h>.

use snare::{HostProfile, Sim};

const SO_TIMESTAMPING: i32 = 37;
const SCM_TIMESTAMPING: i32 = 37;
const SOF_TIMESTAMPING_TX_SOFTWARE: u32 = 1 << 1;
const SOF_TIMESTAMPING_RX_SOFTWARE: u32 = 1 << 3;
const SOF_TIMESTAMPING_SOFTWARE: u32 = 1 << 4;
/// Loop the stamp back without the packet (timestamping.rst, "SOF_TIMESTAMPING_OPT_TSONLY"); without
/// it the entry carries the sent frame, headers included.
const SOF_TIMESTAMPING_OPT_TSONLY: u32 = 1 << 11;
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

fn enable_tx_sw_timestamping(fd: i32) {
    let flags =
        SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_OPT_TSONLY;
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

/// Drain one error-queue entry and return `(rc, Some(scm_timestamping[0]))` when a tx stamp rode
/// along. `rc` is the recvmsg return (0 for the zero-length completion payload, -1 on EAGAIN).
fn drain_errqueue(fd: i32) -> (isize, Option<libc::timespec>) {
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

    let rc = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE) };
    if rc < 0 {
        return (rc, None);
    }
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let (level, ty) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
        if level == libc::SOL_SOCKET && ty == SCM_TIMESTAMPING {
            let data = unsafe { libc::CMSG_DATA(cmsg) } as *const [libc::timespec; 3];
            let arr = unsafe { data.read_unaligned() };
            return (rc, Some(arr[0]));
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    (rc, None)
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[test]
fn tx_completion_carries_a_timestamp_on_the_error_queue() {
    Sim::builder()
        .host(HostProfile::new().build())
        .fixed_epoch()
        .build()
        .run(|| {
            let tx = udp_socket();
            bind4(tx, 9500);
            enable_tx_sw_timestamping(tx);
            assert_eq!(sendto4(tx, 9501, b"x"), 1);

            let (rc, ts) = drain_errqueue(tx);
            assert_eq!(
                rc, 0,
                "the completion payload is empty; the stamp is ancillary data"
            );
            let ts = ts.expect("SCM_TIMESTAMPING on the error queue");
            assert_eq!(ts.tv_sec, VIRTUAL_EPOCH_SECS);
            assert!(ts.tv_nsec > 0);
            unsafe { libc::close(tx) };
        });
}

#[test]
fn error_queue_is_empty_without_tx_timestamping() {
    // No SOF_TIMESTAMPING_TX_SOFTWARE means no completion is queued; MSG_ERRQUEUE sees EAGAIN.
    Sim::builder()
        .host(HostProfile::new().build())
        .fixed_epoch()
        .build()
        .run(|| {
            let tx = udp_socket();
            bind4(tx, 9510);
            assert_eq!(sendto4(tx, 9511, b"x"), 1);

            let (rc, _) = drain_errqueue(tx);
            assert_eq!(rc, -1);
            assert_eq!(errno(), libc::EAGAIN, "nothing on the error queue");
            unsafe { libc::close(tx) };
        });
}

#[test]
fn one_completion_is_queued_per_send() {
    // Each timestamped send enqueues exactly one completion; draining them yields non-decreasing
    // stamps and then EAGAIN.
    Sim::builder()
        .host(HostProfile::new().build())
        .fixed_epoch()
        .build()
        .run(|| {
            let tx = udp_socket();
            bind4(tx, 9520);
            enable_tx_sw_timestamping(tx);
            assert_eq!(sendto4(tx, 9521, b"a"), 1);
            assert_eq!(sendto4(tx, 9521, b"b"), 1);

            let (rc0, ts0) = drain_errqueue(tx);
            let (rc1, ts1) = drain_errqueue(tx);
            assert_eq!(rc0, 0);
            assert_eq!(rc1, 0);
            let a = ts0.expect("first tx stamp");
            let b = ts1.expect("second tx stamp");
            let an = a.tv_sec as i128 * 1_000_000_000 + a.tv_nsec as i128;
            let bn = b.tv_sec as i128 * 1_000_000_000 + b.tv_nsec as i128;
            assert!(
                bn > an,
                "tx completions are stamped in send order ({an} -> {bn})"
            );

            let (rc2, _) = drain_errqueue(tx);
            assert_eq!(rc2, -1);
            assert_eq!(errno(), libc::EAGAIN, "only two completions were queued");
            unsafe { libc::close(tx) };
        });
}

#[test]
fn error_queue_and_receive_queue_are_independent() {
    // A plain recvmsg drains the normal receive queue; MSG_ERRQUEUE drains the error queue. A tx
    // completion must never appear on the normal path (Documentation/networking/timestamping.rst).
    Sim::builder()
        .host(HostProfile::new().build())
        .fixed_epoch()
        .build()
        .run(|| {
            // rx receives real traffic; tx wants its own tx completions.
            let tx = udp_socket();
            let rx = udp_socket();
            bind4(tx, 9530);
            bind4(rx, 9531);
            enable_tx_sw_timestamping(tx);

            assert_eq!(sendto4(tx, 9531, b"payload"), 7);

            // The receiver got the datagram on its normal queue.
            let mut buf = [0u8; 16];
            let got = unsafe {
                libc::recvfrom(
                    rx,
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(got, 7);
            assert_eq!(&buf[..7], b"payload");

            // The sender's normal queue is empty; its completion waits on the error queue only.
            let got = unsafe {
                libc::recvfrom(
                    tx,
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(got, -1);
            assert_eq!(
                errno(),
                libc::EAGAIN,
                "the tx completion is not on the normal receive queue"
            );

            let (rc, ts) = drain_errqueue(tx);
            assert_eq!(rc, 0);
            assert!(ts.is_some(), "the completion is on the error queue");
            unsafe {
                libc::close(tx);
                libc::close(rx);
            }
        });
}

#[test]
fn both_rx_and_tx_timestamping_coexist_on_one_socket() {
    // A socket may request rx and tx software stamps at once; the rx stamp rides the normal recv
    // and the tx stamp rides MSG_ERRQUEUE.
    Sim::builder()
        .host(HostProfile::new().build())
        .fixed_epoch()
        .build()
        .run(|| {
            let a = udp_socket();
            let b = udp_socket();
            bind4(a, 9540);
            bind4(b, 9541);
            let flags = SOF_TIMESTAMPING_SOFTWARE
                | SOF_TIMESTAMPING_RX_SOFTWARE
                | SOF_TIMESTAMPING_TX_SOFTWARE
                | SOF_TIMESTAMPING_OPT_TSONLY;
            let rc = unsafe {
                libc::setsockopt(
                    a,
                    libc::SOL_SOCKET,
                    SO_TIMESTAMPING,
                    &flags as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as u32,
                )
            };
            assert_eq!(rc, 0);

            // a -> b, then b -> a so that `a` has both an incoming datagram (rx stamp) and an
            // outgoing completion (tx stamp).
            assert_eq!(sendto4(a, 9541, b"hi"), 2);
            let (rc, tx_ts) = drain_errqueue(a);
            assert_eq!(rc, 0);
            assert!(tx_ts.is_some(), "tx completion queued for a's send");

            assert_eq!(sendto4(b, 9540, b"yo"), 2);
            let mut buf = [0u8; 8];
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
            let got = unsafe { libc::recvmsg(a, &mut msg, 0) };
            assert_eq!(got, 2);
            let mut has_rx = false;
            let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
            while !cmsg.is_null() {
                let (level, ty) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
                if level == libc::SOL_SOCKET && ty == SCM_TIMESTAMPING {
                    has_rx = true;
                }
                cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
            }
            assert!(has_rx, "rx stamp delivered on the normal receive path");
            unsafe {
                libc::close(a);
                libc::close(b);
            }
        });
}
