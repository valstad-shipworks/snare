#![cfg(target_os = "linux")]

use snare::{HostProfile, IpNet, Nic, Sim};

#[test]
fn duplicated_udp_descriptors_share_state_and_last_close_os_truth() {
    use std::os::fd::{AsRawFd, FromRawFd};
    let probe = || {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0);
        let original = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        bind(fd, 0);
        let address = original.local_addr().unwrap();
        let rawfd = unsafe { libc::dup(fd) };
        assert!(rawfd >= 0);
        let raw = unsafe { std::net::UdpSocket::from_raw_fd(rawfd) };
        let minimum = fd + 16;
        let copiedfd = unsafe { libc::fcntl(fd, libc::F_DUPFD, minimum) };
        assert!(copiedfd >= minimum);
        let copied = unsafe { std::net::UdpSocket::from_raw_fd(copiedfd) };
        let cloned = original.try_clone().unwrap();
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_DUPFD, -1) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINVAL)
        );
        let descriptor_flags = |fd| unsafe { libc::fcntl(fd, libc::F_GETFD) };
        let initial_flags = [fd, rawfd, copiedfd, cloned.as_raw_fd()].map(descriptor_flags);
        assert_eq!(
            unsafe { libc::fcntl(rawfd, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
        let changed_flags = [fd, rawfd, copiedfd].map(descriptor_flags);
        raw.set_nonblocking(true).unwrap();
        let shared_nonblocking = [fd, copiedfd, cloned.as_raw_fd()]
            .map(|fd| unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0);
        copied.set_broadcast(true).unwrap();
        let shared_broadcast = original.broadcast().unwrap();
        let access_mode = unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_ACCMODE;
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"shared queue", address).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut bytes = [0u8; 64];
        let n = cloned.recv(&mut bytes).unwrap();
        let received = bytes[..n].to_vec();
        let consumed_once = original.recv(&mut bytes).unwrap_err().raw_os_error();
        drop(original);
        drop(raw);
        drop(copied);
        let bound_while_aliased = std::net::UdpSocket::bind(address)
            .unwrap_err()
            .raw_os_error();
        sender.send_to(b"after close", address).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let n = cloned.recv(&mut bytes).unwrap();
        let after_close = bytes[..n].to_vec();
        drop(cloned);
        let rebound = std::net::UdpSocket::bind(address).is_ok();
        (
            initial_flags,
            changed_flags,
            shared_nonblocking,
            shared_broadcast,
            access_mode,
            received,
            consumed_once,
            bound_while_aliased,
            after_close,
            rebound,
        )
    };
    let real = probe();
    assert_eq!(real.0, [libc::FD_CLOEXEC, 0, 0, libc::FD_CLOEXEC]);
    assert_eq!(real.2, [true; 3]);
    assert!(real.3 && real.9);
    assert_eq!(real.4, libc::O_RDWR);
    assert_eq!(real.6, Some(libc::EAGAIN));
    assert_eq!(real.7, Some(libc::EADDRINUSE));
    assert_eq!(Sim::new().run(probe), real);
    assert_eq!(
        Sim::builder()
            .host(HostProfile::new().build())
            .build()
            .run(probe),
        real
    );
}

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
        assert!(
            u16::from_be(from.sin_port) >= 49152,
            "ephemeral source port"
        );

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
    // A priority above 6 needs CAP_NET_ADMIN (socket(7)).
    let host = HostProfile::new().cap(snare::CAP_NET_ADMIN).build();
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

fn poll_one(fd: i32, events: i16) -> (i32, i16) {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let n = unsafe { libc::poll(&mut pfd, 1, 0) };
    (n, pfd.revents)
}

fn set_timestamping(fd: i32, flags: u32) {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_TIMESTAMPING,
            (&raw const flags).cast(),
            std::mem::size_of::<u32>() as u32,
        )
    };
    assert_eq!(rc, 0);
}

fn send_to(fd: i32, port: u16, payload: &[u8]) {
    let dest = loopback(port);
    let n = unsafe {
        libc::sendto(
            fd,
            payload.as_ptr().cast(),
            payload.len(),
            0,
            (&raw const dest).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    assert_eq!(n, payload.len() as isize);
}

/// net/core/datagram.c `datagram_poll` (Linux 7.0): a datagram socket is always writable,
/// readable with a datagram queued, and reports `POLLERR` unasked while its error queue holds a
/// transmit stamp; reading the stamp clears it.
#[test]
fn poll_reports_readable_datagrams_and_pollerr_for_a_queued_stamp() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let rx = udp_socket();
        bind(rx, 9230);
        let tx = udp_socket();
        bind(tx, 9231);
        assert_eq!(
            poll_one(rx, libc::POLLIN | libc::POLLOUT),
            (1, libc::POLLOUT)
        );
        set_timestamping(tx, SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_TX_SOFTWARE);
        send_to(tx, 9230, b"stamped");
        assert_eq!(poll_one(rx, libc::POLLIN), (1, libc::POLLIN));
        assert_eq!(poll_one(tx, 0), (1, libc::POLLERR), "POLLERR comes unasked");
        let mut buf = [0u8; 64];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut control = [0u8; 256];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len();
        assert!(unsafe { libc::recvmsg(tx, &mut msg, libc::MSG_ERRQUEUE) } >= 0);
        assert_eq!(poll_one(tx, 0), (0, 0), "the error queue is empty again");
        unsafe {
            libc::close(rx);
            libc::close(tx);
        }
    });
}

/// fs/eventpoll.c reports `EPOLLERR` whether or not it was asked for, and an edge-triggered
/// registration once per datagram that lands.
#[test]
fn epoll_reports_epollerr_and_datagram_edges() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let rx = udp_socket();
        bind(rx, 9232);
        let tx = udp_socket();
        bind(tx, 9233);
        set_timestamping(tx, SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_TX_SOFTWARE);
        let ep = unsafe { libc::epoll_create1(0) };
        assert!(ep >= 0);
        for (fd, events) in [(rx, (libc::EPOLLIN | libc::EPOLLET) as u32), (tx, 0)] {
            let mut ev = libc::epoll_event {
                events,
                u64: fd as u64,
            };
            assert_eq!(
                unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev) },
                0
            );
        }
        let wait = || {
            let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
            let n = unsafe { libc::epoll_wait(ep, events.as_mut_ptr(), 4, 0) };
            let mut got: Vec<(u64, u32)> = events[..n as usize]
                .iter()
                .map(|e| (e.u64, e.events))
                .collect();
            got.sort();
            got
        };
        assert_eq!(wait(), vec![]);
        send_to(tx, 9232, b"one");
        let (rx, tx) = (rx as u64, tx as u64);
        let mut expected = vec![(rx, libc::EPOLLIN as u32), (tx, libc::EPOLLERR as u32)];
        expected.sort();
        assert_eq!(wait(), expected);
        assert_eq!(
            wait(),
            vec![(tx, libc::EPOLLERR as u32)],
            "the edge was taken"
        );
        unsafe {
            libc::close(ep);
            libc::close(rx as i32);
            libc::close(tx as i32);
        }
    });
}

/// `SK_MEMINFO_RMEM_ALLOC`, what `fd`'s queued datagrams are charged.
fn rmem_alloc(fd: i32) -> u32 {
    const SO_MEMINFO: i32 = 55;
    let mut words = [0u32; 9];
    let mut len = std::mem::size_of_val(&words) as u32;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_MEMINFO,
            words.as_mut_ptr().cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0);
    words[0]
}

/// A datagram longer than its path's MTU crossed as IP fragments, each received into its own
/// buffer and chained by reassembly (net/ipv4/inet_fragment.c `inet_frag_reasm_finish`), so the
/// receive buffer is charged the sum of the fragments' truesizes: measured through veth with a
/// 1500-byte MTU on Linux 7.0 (tests/hw_sockbuf_truth.rs) as 2304 + 1152 for 1473 bytes,
/// 2 × 2304 + 1152 for 3000 and 6 × 2304 + 1152 for 9000, 1152 being that kernel's small
/// truesize. Over loopback (MTU 65536) the same datagram is one buffer.
#[test]
fn a_datagram_past_the_mtu_is_charged_per_fragment() {
    let nic = Nic::new("eth0", 2)
        .network("192.168.7.10/24".parse::<IpNet>().unwrap())
        .station("192.168.7.20".parse::<std::net::IpAddr>().unwrap());
    let host = HostProfile::new().nic(nic).build();
    Sim::builder()
        .host(host)
        .sys_limits(snare::SysLimits::host())
        .build()
        .run(|| {
            let small = snare::SysLimits::host().skb_small_truesize as u32;
            let station = std::net::UdpSocket::bind("192.168.7.20:0").unwrap();
            let sock = std::net::UdpSocket::bind("192.168.7.10:0").unwrap();
            let local = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut buf = vec![0u8; 65_536];
            let mut charge = |from: &std::net::UdpSocket, to: &std::net::UdpSocket, len: usize| {
                from.send_to(&vec![7; len], to.local_addr().unwrap())
                    .unwrap();
                let charged = rmem_alloc(std::os::fd::AsRawFd::as_raw_fd(to));
                assert_eq!(to.recv(&mut buf).unwrap(), len);
                charged
            };
            assert_eq!(charge(&station, &sock, 1472), 2304, "one packet");
            assert_eq!(charge(&station, &sock, 1473), 2304 + small);
            assert_eq!(charge(&station, &sock, 3000), 2 * 2304 + small);
            assert_eq!(charge(&station, &sock, 9000), 6 * 2304 + small);
            assert_eq!(
                charge(&local, &local, 3000),
                4096 + 256,
                "loopback: one buffer"
            );
        });
}

fn station_host(latency: std::time::Duration) -> std::sync::Arc<snare::SimHost> {
    HostProfile::new()
        .nic(
            Nic::new("eth0", 2)
                .network("10.0.0.10/24".parse::<IpNet>().unwrap())
                .station("10.0.0.20".parse::<std::net::IpAddr>().unwrap())
                .policy(snare::NicPolicy {
                    latency,
                    ..snare::NicPolicy::default()
                }),
        )
        .build()
}

/// One `recvmsg` into `buf`: the byte count or the errno.
fn recvmsg_into(fd: i32, buf: &mut [u8], flags: i32) -> Result<usize, i32> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    let n = unsafe { libc::recvmsg(fd, &mut msg, flags) };
    if n < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        Ok(n as usize)
    }
}

#[test]
fn a_blocking_recvmsg_waits_for_a_datagram_in_flight() {
    use std::os::fd::AsRawFd;
    let latency = std::time::Duration::from_millis(2);
    Sim::builder().host(station_host(latency)).build().run(|| {
        let rx = std::net::UdpSocket::bind("10.0.0.10:7011").unwrap();
        let sender = std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(10));
            let station = std::net::UdpSocket::bind("10.0.0.20:0").unwrap();
            station.send_to(b"ping", "10.0.0.10:7011").unwrap();
            std::time::Instant::now()
        });
        let mut buf = [0u8; 16];
        assert_eq!(
            recvmsg_into(rx.as_raw_fd(), &mut buf, libc::MSG_DONTWAIT),
            Err(libc::EAGAIN)
        );
        assert_eq!(recvmsg_into(rx.as_raw_fd(), &mut buf, 0), Ok(4));
        let arrived = std::time::Instant::now();
        assert_eq!(&buf[..4], b"ping");
        assert!(arrived >= sender.join().unwrap() + latency);

        rx.set_read_timeout(Some(std::time::Duration::from_millis(5)))
            .unwrap();
        assert_eq!(recvmsg_into(rx.as_raw_fd(), &mut buf, 0), Err(libc::EAGAIN));
    });
}

/// `recvmmsg` into `count` 8-byte buffers: the first byte of each message received, or the errno.
fn recvmmsg_firsts(
    fd: i32,
    count: usize,
    flags: i32,
    timeout: Option<&mut libc::timespec>,
) -> Result<Vec<u8>, i32> {
    let mut bufs = vec![[0u8; 8]; count];
    let mut iovs: Vec<libc::iovec> = bufs
        .iter_mut()
        .map(|b| libc::iovec {
            iov_base: b.as_mut_ptr().cast(),
            iov_len: b.len(),
        })
        .collect();
    let mut msgs: Vec<libc::mmsghdr> = iovs
        .iter_mut()
        .map(|iov| {
            let mut m: libc::mmsghdr = unsafe { std::mem::zeroed() };
            m.msg_hdr.msg_iov = iov;
            m.msg_hdr.msg_iovlen = 1;
            m
        })
        .collect();
    let timeout = timeout.map_or(std::ptr::null_mut(), |t| t as *mut libc::timespec);
    let n = unsafe { libc::recvmmsg(fd, msgs.as_mut_ptr(), count as u32, flags, timeout) };
    if n < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap());
    }
    assert!(msgs[..n as usize].iter().all(|m| m.msg_len == 1));
    Ok(bufs[..n as usize].iter().map(|b| b[0]).collect())
}

/// Three datagrams queued on a socket, read by `recvmmsg` four ways; returns each call's result.
fn recvmmsg_rounds(rx: &std::net::UdpSocket, send: impl Fn(u8)) -> Vec<Result<Vec<u8>, i32>> {
    use std::os::fd::AsRawFd;
    let fd = rx.as_raw_fd();
    let mut out = vec![recvmmsg_firsts(fd, 4, libc::MSG_DONTWAIT, None)];
    for i in 0..3 {
        send(i);
    }
    std::thread::sleep(std::time::Duration::from_millis(5));
    out.push(recvmmsg_firsts(fd, 2, libc::MSG_WAITFORONE, None));
    out.push(recvmmsg_firsts(fd, 4, libc::MSG_WAITFORONE, None));
    let mut bad = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000_000,
    };
    out.push(recvmmsg_firsts(fd, 4, libc::MSG_DONTWAIT, Some(&mut bad)));
    send(9);
    std::thread::sleep(std::time::Duration::from_millis(5));
    let mut zero = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    out.push(recvmmsg_firsts(fd, 4, 0, Some(&mut zero)));
    out
}

fn expected_recvmmsg_rounds() -> Vec<Result<Vec<u8>, i32>> {
    vec![
        Err(libc::EAGAIN),
        Ok(vec![0, 1]),
        Ok(vec![2]),
        Err(libc::EINVAL),
        Ok(vec![9]),
    ]
}

#[test]
fn recvmmsg_takes_what_is_queued_os_truth() {
    let probe = || {
        let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = rx.local_addr().unwrap();
        recvmmsg_rounds(&rx, |i| {
            tx.send_to(&[i], to).unwrap();
        })
    };
    assert_eq!(probe(), expected_recvmmsg_rounds());
    assert_eq!(Sim::new().run(probe), expected_recvmmsg_rounds());
}

/// A blocking two-message `recvmmsg` takes one datagram, then an ICMP port unreachable for a send
/// to a closed port ends its wait for the second: the batch returns the first and the error stays
/// pending for the next receive (net/socket.c `do_recvmmsg` stores it in `sk_err`).
#[test]
fn recvmmsg_keeps_an_error_after_the_first_message_os_truth() {
    use std::os::fd::AsRawFd;
    let probe = || {
        let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let closed = tx.local_addr().unwrap();
        rx.connect(closed).unwrap();
        tx.send_to(&[1], rx.local_addr().unwrap()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        drop(tx);
        let sender = rx.try_clone().unwrap();
        let send = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            sender.send(&[2]).unwrap();
        });
        let batch = recvmmsg_firsts(rx.as_raw_fd(), 2, 0, None);
        send.join().unwrap();
        rx.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 8];
        let next = rx.recv(&mut buf).map_err(|e| e.raw_os_error().unwrap());
        let after = rx.recv(&mut buf).map_err(|e| e.raw_os_error().unwrap());
        (batch, next, after)
    };
    let expected = (Ok(vec![1]), Err(libc::ECONNREFUSED), Err(libc::EAGAIN));
    assert_eq!(probe(), expected);
    assert_eq!(Sim::new().run(probe), expected);
}

#[test]
fn recvmmsg_on_a_simhost_socket() {
    Sim::builder()
        .host(station_host(std::time::Duration::ZERO))
        .build()
        .run(|| {
            let rx = std::net::UdpSocket::bind("10.0.0.10:7050").unwrap();
            let station = std::net::UdpSocket::bind("10.0.0.20:0").unwrap();
            let rounds = recvmmsg_rounds(&rx, |i| {
                station.send_to(&[i], "10.0.0.10:7050").unwrap();
            });
            assert_eq!(rounds, expected_recvmmsg_rounds());
        });
}

/// `sendmmsg` of three datagrams of 1, 2 and 3 bytes to `to`: the call's result and each
/// message's `msg_len`.
fn sendmmsg_three(fd: i32, to: std::net::SocketAddr) -> (i32, Vec<u32>) {
    let std::net::SocketAddr::V4(to) = to else {
        unreachable!()
    };
    let mut dest = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: to.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(to.ip().octets()),
        },
        sin_zero: [0; 8],
    };
    let payloads = [vec![1u8], vec![2u8; 2], vec![3u8; 3]];
    let mut iovs: Vec<libc::iovec> = payloads
        .iter()
        .map(|p| libc::iovec {
            iov_base: p.as_ptr() as *mut _,
            iov_len: p.len(),
        })
        .collect();
    let mut msgs: Vec<libc::mmsghdr> = iovs
        .iter_mut()
        .map(|iov| {
            let mut m: libc::mmsghdr = unsafe { std::mem::zeroed() };
            m.msg_hdr.msg_name = (&raw mut dest).cast();
            m.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
            m.msg_hdr.msg_iov = iov;
            m.msg_hdr.msg_iovlen = 1;
            m
        })
        .collect();
    let n = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), 3, 0) };
    (n, msgs.iter().map(|m| m.msg_len).collect())
}

#[test]
fn sendmmsg_sends_each_message_os_truth() {
    use std::os::fd::AsRawFd;
    let probe = || {
        let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let sent = sendmmsg_three(tx.as_raw_fd(), rx.local_addr().unwrap());
        let mut buf = [0u8; 8];
        let got: Vec<usize> = (0..3).map(|_| rx.recv(&mut buf).unwrap()).collect();
        (sent, got)
    };
    let expected = ((3, vec![1, 2, 3]), vec![1, 2, 3]);
    assert_eq!(probe(), expected);
    assert_eq!(Sim::new().run(probe), expected);
    let host = Sim::builder()
        .host(station_host(std::time::Duration::ZERO))
        .build()
        .run(|| {
            let rx = std::net::UdpSocket::bind("10.0.0.10:7060").unwrap();
            let station = std::net::UdpSocket::bind("10.0.0.20:0").unwrap();
            let sent = sendmmsg_three(rx.as_raw_fd(), station.local_addr().unwrap());
            let mut buf = [0u8; 8];
            let got: Vec<usize> = (0..3).map(|_| station.recv(&mut buf).unwrap()).collect();
            (sent, got)
        });
    assert_eq!(host, expected);
}
