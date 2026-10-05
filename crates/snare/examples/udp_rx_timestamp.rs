//! Receive a UDP datagram and read its software receive timestamp.
//!
//! A receiver enables SO_TIMESTAMPING with the software generation/reporting flags, then reads the
//! datagram with recvmsg and pulls the SCM_TIMESTAMPING control message out of the ancillary data.
//! The whole exchange runs inside a `Sim`, so the timestamp comes from the virtual clock rather
//! than the wall clock. See Documentation/networking/timestamping.rst and the SOF_TIMESTAMPING_*
//! flags plus the `struct scm_timestamping` layout in <linux/net_tstamp.h>.
//!
//! Run with: `cargo run -p snare --example udp_rx_timestamp`

#[cfg(target_os = "linux")]
fn main() {
    use snare::{HostProfile, Sim};

    const SO_TIMESTAMPING: i32 = 37;
    const SCM_TIMESTAMPING: i32 = 37;
    const SOF_TIMESTAMPING_RX_SOFTWARE: u32 = 1 << 3;
    const SOF_TIMESTAMPING_SOFTWARE: u32 = 1 << 4;

    Sim::builder()
        .host(HostProfile::new().build())
        .build()
        .run(|| {
            let tx = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            let rx = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            assert!(tx >= 0 && rx >= 0);

            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa.sin_family = libc::AF_INET as u16;
            sa.sin_port = 5000u16.to_be();
            sa.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
            let rc = unsafe {
                libc::bind(
                    rx,
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                )
            };
            assert_eq!(rc, 0);

            let flags = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE;
            unsafe {
                libc::setsockopt(
                    rx,
                    libc::SOL_SOCKET,
                    SO_TIMESTAMPING,
                    &flags as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as u32,
                );
            }

            let payload = b"telemetry";
            unsafe {
                libc::sendto(
                    tx,
                    payload.as_ptr() as *const _,
                    payload.len(),
                    0,
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                );
            }

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

            let got = unsafe { libc::recvmsg(rx, &mut msg, 0) };
            assert!(got > 0);

            let mut stamp = None;
            let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
            while !cmsg.is_null() {
                let (level, ty) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
                if level == libc::SOL_SOCKET && ty == SCM_TIMESTAMPING {
                    let data = unsafe { libc::CMSG_DATA(cmsg) } as *const [libc::timespec; 3];
                    stamp = Some(unsafe { data.read_unaligned() }[0]);
                    break;
                }
                cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
            }

            let ts = stamp.expect("SCM_TIMESTAMPING present");
            println!(
                "received {} bytes ({:?}) with sw rx timestamp {}.{:09}",
                got,
                std::str::from_utf8(&buf[..got as usize]).unwrap_or("?"),
                ts.tv_sec,
                ts.tv_nsec,
            );

            unsafe {
                libc::close(tx);
                libc::close(rx);
            }
        });
}

#[cfg(not(target_os = "linux"))]
fn main() {
    // SO_TIMESTAMPING / SCM_TIMESTAMPING are Linux socket features; the UDP fabric is modelled only
    // on Linux (Documentation/networking/timestamping.rst).
    println!("udp_rx_timestamp: requires Linux (SO_TIMESTAMPING); skipping on this OS");
}
