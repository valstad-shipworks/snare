#![cfg(target_os = "linux")]

use snare::{HostProfile, Sim};

const SO_TIMESTAMPING: i32 = 37;
const SCM_TIMESTAMPING: i32 = 37;
const SOF_TIMESTAMPING_TX_SOFTWARE: u32 = 1 << 1;
const SOF_TIMESTAMPING_RX_SOFTWARE: u32 = 1 << 3;
const SOF_TIMESTAMPING_SOFTWARE: u32 = 1 << 4;

fn udp_socket() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(fd >= 0, "socket failed");
    fd
}

fn loopback(port: u16) -> libc::sockaddr_in {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as u16;
    sa.sin_port = port.to_be();
    sa.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
    sa
}

fn bind(fd: i32, port: u16) {
    let sa = loopback(port);
    let rc = unsafe {
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    assert_eq!(rc, 0, "bind failed");
}

#[test]
fn datagram_loopback_between_two_sockets() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let tx = udp_socket();
        let rx = udp_socket();
        bind(rx, 9000);

        let dest = loopback(9000);
        let msg = b"ping";
        let sent = unsafe {
            libc::sendto(
                tx,
                msg.as_ptr() as *const _,
                msg.len(),
                0,
                &dest as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        assert_eq!(sent, 4);

        let mut buf = [0u8; 16];
        let mut from: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut fromlen = std::mem::size_of::<libc::sockaddr_in>() as u32;
        let got = unsafe {
            libc::recvfrom(
                rx,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                0,
                &mut from as *mut _ as *mut libc::sockaddr,
                &mut fromlen,
            )
        };
        assert_eq!(got, 4);
        assert_eq!(&buf[..4], b"ping");
        assert_eq!(from.sin_family, libc::AF_INET as u16);
        // The unbound sender was assigned an ephemeral source port, reported back to the receiver.
        assert!(u16::from_be(from.sin_port) >= 49152, "ephemeral source port");

        unsafe {
            libc::close(tx);
            libc::close(rx);
        }
    });
}

#[test]
fn recvmsg_delivers_a_software_timestamp() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let tx = udp_socket();
        let rx = udp_socket();
        bind(rx, 9100);

        // Enable software receive timestamping on the receiver.
        let flags = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE;
        let rc = unsafe {
            libc::setsockopt(
                rx,
                libc::SOL_SOCKET,
                SO_TIMESTAMPING,
                &flags as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as u32,
            )
        };
        assert_eq!(rc, 0);

        let dest = loopback(9100);
        let payload = b"tsdata";
        unsafe {
            libc::sendto(
                tx,
                payload.as_ptr() as *const _,
                payload.len(),
                0,
                &dest as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            );
        }

        let mut buf = [0u8; 32];
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
        assert_eq!(got, 6);
        assert_eq!(&buf[..6], b"tsdata");

        // Walk the control messages for SCM_TIMESTAMPING.
        let mut found = None;
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !cmsg.is_null() {
            let (level, ty) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
            if level == libc::SOL_SOCKET && ty == SCM_TIMESTAMPING {
                let data = unsafe { libc::CMSG_DATA(cmsg) } as *const libc::timespec;
                let ts = unsafe { data.read_unaligned() };
                found = Some(ts);
                break;
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
        }
        let ts = found.expect("SCM_TIMESTAMPING control message present");
        assert!(
            ts.tv_sec > 0 || ts.tv_nsec > 0,
            "software timestamp is non-zero (virtual clock)"
        );

        unsafe {
            libc::close(tx);
            libc::close(rx);
        }
    });
}

#[test]
fn tx_timestamp_arrives_on_the_error_queue() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let tx = udp_socket();
        bind(tx, 9200);
        let flags = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_TX_SOFTWARE;
        unsafe {
            libc::setsockopt(
                tx,
                libc::SOL_SOCKET,
                SO_TIMESTAMPING,
                &flags as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as u32,
            );
        }

        let dest = loopback(9201);
        let payload = b"x";
        unsafe {
            libc::sendto(
                tx,
                payload.as_ptr() as *const _,
                payload.len(),
                0,
                &dest as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            );
        }

        // The tx-completion timestamp is read back with MSG_ERRQUEUE.
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

        let rc = unsafe { libc::recvmsg(tx, &mut msg, libc::MSG_ERRQUEUE) };
        assert!(rc >= 0, "an error-queue entry is waiting");

        let mut found = false;
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !cmsg.is_null() {
            let (level, ty) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
            if level == libc::SOL_SOCKET && ty == SCM_TIMESTAMPING {
                found = true;
                break;
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
        }
        assert!(found, "tx timestamp present on the error queue");
        unsafe { libc::close(tx) };
    });
}

#[test]
fn getsockopt_reads_back_a_stored_option() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let fd = udp_socket();
        let want: i32 = 7;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PRIORITY,
                &want as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as u32,
            )
        };
        assert_eq!(rc, 0);

        let mut got: i32 = 0;
        let mut len = std::mem::size_of::<i32>() as u32;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PRIORITY,
                &mut got as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(got, 7);
        unsafe { libc::close(fd) };
    });
}
