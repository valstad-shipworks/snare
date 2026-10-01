#![cfg(target_os = "linux")]

//! UDP datagram fabric: socket / bind / sendto / recvfrom / sendmsg / recvmsg and their errno
//! paths, serviced from process memory by the sim. Datagram semantics follow udp(7) and the
//! socket calls in socket(2), bind(2), sendto(2), recvfrom(2), sendmsg(2), recvmsg(2).

use snare::{HostProfile, Sim};

fn udp_socket() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(fd >= 0, "socket(AF_INET, SOCK_DGRAM) failed");
    fd
}

fn udp6_socket() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    assert!(fd >= 0, "socket(AF_INET6, SOCK_DGRAM) failed");
    fd
}

fn loopback(port: u16) -> libc::sockaddr_in {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as u16;
    sa.sin_port = port.to_be();
    sa.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
    sa
}

fn loopback6(port: u16) -> libc::sockaddr_in6 {
    let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sa.sin6_family = libc::AF_INET6 as u16;
    sa.sin6_port = port.to_be();
    sa.sin6_addr.s6_addr = std::net::Ipv6Addr::LOCALHOST.octets();
    sa
}

fn bind4(fd: i32, port: u16) -> i32 {
    let sa = loopback(port);
    unsafe {
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    }
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

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[test]
fn loopback_datagram_delivers_payload_and_source() {
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let tx = udp_socket();
        let rx = udp_socket();
        assert_eq!(bind4(rx, 9000), 0);

        assert_eq!(sendto4(tx, 9000, b"ping"), 4);

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
        assert_eq!(from.sin_addr.s_addr, u32::from(std::net::Ipv4Addr::LOCALHOST).to_be());
        assert!(u16::from_be(from.sin_port) >= 49152, "ephemeral source port");

        unsafe {
            libc::close(tx);
            libc::close(rx);
        }
    });
}

#[test]
fn request_reply_round_trip_on_one_thread() {
    // The unbound sender is assigned an ephemeral source port (udp(7): implicit bind on first
    // send), so the peer's reply routes straight back to it.
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let client = udp_socket();
        let server = udp_socket();
        assert_eq!(bind4(server, 9010), 0);

        assert_eq!(sendto4(client, 9010, b"q"), 1);

        let mut buf = [0u8; 8];
        let mut from: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut fromlen = std::mem::size_of::<libc::sockaddr_in>() as u32;
        let got = unsafe {
            libc::recvfrom(
                server,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                0,
                &mut from as *mut _ as *mut libc::sockaddr,
                &mut fromlen,
            )
        };
        assert_eq!(got, 1);
        let client_port = u16::from_be(from.sin_port);

        let reply = unsafe {
            libc::sendto(
                server,
                b"a".as_ptr() as *const _,
                1,
                0,
                &from as *const _ as *const libc::sockaddr,
                fromlen,
            )
        };
        assert_eq!(reply, 1);

        let mut rbuf = [0u8; 8];
        let got = unsafe {
            libc::recvfrom(
                client,
                rbuf.as_mut_ptr() as *mut _,
                rbuf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(got, 1);
        assert_eq!(&rbuf[..1], b"a");

        let _ = client_port;
        unsafe {
            libc::close(client);
            libc::close(server);
        }
    });
}

#[test]
fn datagrams_are_received_in_send_order() {
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let tx = udp_socket();
        let rx = udp_socket();
        assert_eq!(bind4(rx, 9020), 0);

        for n in 0u8..4 {
            assert_eq!(sendto4(tx, 9020, &[n]), 1);
        }
        for n in 0u8..4 {
            let mut buf = [0u8; 1];
            let got = unsafe {
                libc::recvfrom(rx, buf.as_mut_ptr() as *mut _, 1, 0, std::ptr::null_mut(), std::ptr::null_mut())
            };
            assert_eq!(got, 1);
            assert_eq!(buf[0], n, "datagrams preserve FIFO order");
        }
        unsafe {
            libc::close(tx);
            libc::close(rx);
        }
    });
}

#[test]
fn zero_length_datagram_is_a_valid_message() {
    // A zero-length UDP datagram is legal and delivered as a 0-byte message (udp(7)).
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let tx = udp_socket();
        let rx = udp_socket();
        assert_eq!(bind4(rx, 9030), 0);

        let sent = sendto4(tx, 9030, b"");
        assert_eq!(sent, 0);

        let mut buf = [0u8; 4];
        let got = unsafe {
            libc::recvfrom(rx, buf.as_mut_ptr() as *mut _, buf.len(), 0, std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(got, 0, "an empty datagram reads back as zero bytes, not EAGAIN");
        unsafe {
            libc::close(tx);
            libc::close(rx);
        }
    });
}

#[test]
fn oversized_datagram_is_truncated_to_the_buffer() {
    // recvfrom(2): a datagram larger than the buffer fills it and the excess is discarded.
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let tx = udp_socket();
        let rx = udp_socket();
        assert_eq!(bind4(rx, 9040), 0);
        assert_eq!(sendto4(tx, 9040, b"abcdefgh"), 8);

        let mut buf = [0u8; 3];
        let got = unsafe {
            libc::recvfrom(rx, buf.as_mut_ptr() as *mut _, buf.len(), 0, std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(got, 3);
        assert_eq!(&buf, b"abc");

        // The whole datagram was consumed; a second read blocks (EAGAIN), it does not return the tail.
        let got = unsafe {
            libc::recvfrom(rx, buf.as_mut_ptr() as *mut _, buf.len(), 0, std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(got, -1);
        assert_eq!(errno(), libc::EAGAIN);
        unsafe {
            libc::close(tx);
            libc::close(rx);
        }
    });
}

#[test]
fn ipv6_datagram_reports_a_v6_source() {
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let tx = udp6_socket();
        let rx = udp6_socket();
        let sa = loopback6(9050);
        let rc = unsafe {
            libc::bind(rx, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in6>() as u32)
        };
        assert_eq!(rc, 0);

        let dest = loopback6(9050);
        let sent = unsafe {
            libc::sendto(
                tx,
                b"v6".as_ptr() as *const _,
                2,
                0,
                &dest as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as u32,
            )
        };
        assert_eq!(sent, 2);

        let mut buf = [0u8; 4];
        let mut from: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut fromlen = std::mem::size_of::<libc::sockaddr_in6>() as u32;
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
        assert_eq!(got, 2);
        assert_eq!(&buf[..2], b"v6");
        assert_eq!(from.sin6_family, libc::AF_INET6 as u16);
        assert_eq!(from.sin6_addr.s6_addr, std::net::Ipv6Addr::LOCALHOST.octets());
        unsafe {
            libc::close(tx);
            libc::close(rx);
        }
    });
}

#[test]
fn sendmsg_gathers_scattered_iovecs_into_one_datagram() {
    // sendmsg(2): the iovec array is gathered into a single datagram on the wire.
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let tx = udp_socket();
        let rx = udp_socket();
        assert_eq!(bind4(rx, 9060), 0);

        let a = b"foo";
        let b = b"bar";
        let mut iov = [
            libc::iovec { iov_base: a.as_ptr() as *mut _, iov_len: a.len() },
            libc::iovec { iov_base: b.as_ptr() as *mut _, iov_len: b.len() },
        ];
        let dest = loopback(9060);
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &dest as *const _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = iov.len();

        let sent = unsafe { libc::sendmsg(tx, &msg, 0) };
        assert_eq!(sent, 6);

        let mut buf = [0u8; 16];
        let got = unsafe {
            libc::recvfrom(rx, buf.as_mut_ptr() as *mut _, buf.len(), 0, std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(got, 6);
        assert_eq!(&buf[..6], b"foobar");
        unsafe {
            libc::close(tx);
            libc::close(rx);
        }
    });
}

#[test]
fn recvmsg_scatters_one_datagram_across_iovecs() {
    // recvmsg(2): a received datagram is scattered across the caller's iovec array in order.
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let tx = udp_socket();
        let rx = udp_socket();
        assert_eq!(bind4(rx, 9070), 0);
        assert_eq!(sendto4(tx, 9070, b"HELLO!"), 6);

        let mut head = [0u8; 2];
        let mut tail = [0u8; 8];
        let mut iov = [
            libc::iovec { iov_base: head.as_mut_ptr() as *mut _, iov_len: head.len() },
            libc::iovec { iov_base: tail.as_mut_ptr() as *mut _, iov_len: tail.len() },
        ];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = iov.len();

        let got = unsafe { libc::recvmsg(rx, &mut msg, 0) };
        assert_eq!(got, 6);
        assert_eq!(&head, b"HE");
        assert_eq!(&tail[..4], b"LLO!");
        unsafe {
            libc::close(tx);
            libc::close(rx);
        }
    });
}

#[test]
fn recv_on_empty_queue_is_eagain() {
    // A non-blocking receive with nothing queued returns EAGAIN (recvfrom(2) ERRORS).
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let rx = udp_socket();
        assert_eq!(bind4(rx, 9080), 0);
        let mut buf = [0u8; 4];
        let got = unsafe {
            libc::recvfrom(rx, buf.as_mut_ptr() as *mut _, buf.len(), 0, std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(got, -1);
        assert_eq!(errno(), libc::EAGAIN);
        unsafe { libc::close(rx) };
    });
}

#[test]
fn send_without_destination_is_edestaddrreq() {
    // send(2) on an unconnected datagram socket with no peer set fails with EDESTADDRREQ.
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let tx = udp_socket();
        let rc = unsafe { libc::send(tx, b"x".as_ptr() as *const _, 1, 0) };
        assert_eq!(rc, -1);
        assert_eq!(errno(), libc::EDESTADDRREQ);
        unsafe { libc::close(tx) };
    });
}

#[test]
fn sendto_with_invalid_address_is_einval() {
    // A sockaddr too short to hold a family/port is rejected with EINVAL.
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let tx = udp_socket();
        let junk = [0u8; 4];
        let rc = unsafe {
            libc::sendto(tx, b"x".as_ptr() as *const _, 1, 0, junk.as_ptr() as *const libc::sockaddr, junk.len() as u32)
        };
        assert_eq!(rc, -1);
        assert_eq!(errno(), libc::EINVAL);
        unsafe { libc::close(tx) };
    });
}

#[test]
fn binding_a_used_port_is_eaddrinuse() {
    // bind(2): a second bind to an already-bound port fails with EADDRINUSE.
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let a = udp_socket();
        let b = udp_socket();
        assert_eq!(bind4(a, 9090), 0);
        let rc = bind4(b, 9090);
        assert_eq!(rc, -1);
        assert_eq!(errno(), libc::EADDRINUSE);
        unsafe {
            libc::close(a);
            libc::close(b);
        }
    });
}

#[test]
fn closing_a_socket_frees_its_port() {
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let a = udp_socket();
        assert_eq!(bind4(a, 9095), 0);
        unsafe { libc::close(a) };

        let b = udp_socket();
        assert_eq!(bind4(b, 9095), 0, "the port is reusable after close");
        unsafe { libc::close(b) };
    });
}

#[test]
fn datagram_to_an_unbound_port_is_dropped() {
    // With no socket bound to the destination port the datagram is silently dropped, as on a real
    // host with no listener; the send still reports success (udp(7): unreliable, connectionless).
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let tx = udp_socket();
        let rx = udp_socket();
        assert_eq!(bind4(rx, 9100), 0);

        assert_eq!(sendto4(tx, 9999, b"lost"), 4);

        let mut buf = [0u8; 4];
        let got = unsafe {
            libc::recvfrom(rx, buf.as_mut_ptr() as *mut _, buf.len(), 0, std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(got, -1);
        assert_eq!(errno(), libc::EAGAIN, "nothing was delivered to the bound receiver");
        unsafe {
            libc::close(tx);
            libc::close(rx);
        }
    });
}

#[test]
fn nonblocking_via_sock_flag_and_via_fcntl() {
    // SOCK_NONBLOCK at creation and F_SETFL/O_NONBLOCK via fcntl(2) both make an empty receive
    // return EAGAIN rather than block.
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let a = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0) };
        assert!(a >= 0);
        let mut buf = [0u8; 4];
        let got = unsafe {
            libc::recvfrom(a, buf.as_mut_ptr() as *mut _, buf.len(), 0, std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(got, -1);
        assert_eq!(errno(), libc::EAGAIN);

        let b = udp_socket();
        assert_eq!(unsafe { libc::fcntl(b, libc::F_SETFL, libc::O_NONBLOCK) }, 0);
        let flags = unsafe { libc::fcntl(b, libc::F_GETFL) };
        assert!(flags & libc::O_NONBLOCK != 0, "O_NONBLOCK reads back set");

        unsafe {
            libc::close(a);
            libc::close(b);
        }
    });
}

#[test]
fn implicit_bind_assigns_an_ephemeral_port_in_range() {
    // udp(7): a send from an unbound socket auto-binds a local port from the ephemeral range.
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let tx = udp_socket();
        let rx = udp_socket();
        assert_eq!(bind4(rx, 9110), 0);
        assert_eq!(sendto4(tx, 9110, b"z"), 1);

        let mut from: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut fromlen = std::mem::size_of::<libc::sockaddr_in>() as u32;
        let mut buf = [0u8; 4];
        unsafe {
            libc::recvfrom(
                rx,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                0,
                &mut from as *mut _ as *mut libc::sockaddr,
                &mut fromlen,
            );
        }
        let p = u16::from_be(from.sin_port);
        assert!((49152..=65535).contains(&p), "ephemeral port {p} within IANA dynamic range");
        unsafe {
            libc::close(tx);
            libc::close(rx);
        }
    });
}
