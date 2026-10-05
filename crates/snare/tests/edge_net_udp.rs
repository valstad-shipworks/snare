#![cfg(unix)]

//! UDP edge cases pinned ahead of a performance pass, so an optimisation of the datagram path
//! (zero-copy queues, batched deliveries, cached receive filters) that changes what the code under
//! test observes fails here. The `*_os_truth` tests run one probe on the host's loopback and in a
//! sim and require identical answers: zero-length datagrams, the 65507/65527 payload limits,
//! truncation (`MSG_TRUNC` in and out, scattered iovecs), `MSG_PEEK`, connected filtering through
//! connect, disconnect (`AF_UNSPEC`) and reconnect, an ICMP port unreachable reported once and in
//! the host's order against queued data, and a long queue drained in order. The sim-only tests pin
//! exact values the host cannot reproduce on demand: receive-buffer overflow counts against
//! `SysLimits::host()`, the `SO_RXQ_OVFL` and timestamp control bytes of a `deterministic()` run,
//! broadcast permission and recipients, and Linux `IP_MULTICAST_ALL`.

use std::mem::size_of;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

use snare::{Sim, SysLimits};

type Res = Result<usize, i32>;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn res(rc: isize) -> Res {
    if rc < 0 {
        Err(errno())
    } else {
        Ok(rc as usize)
    }
}

fn set_int(fd: i32, level: i32, name: i32, v: i32) -> Result<(), i32> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&v as *const i32).cast(),
            size_of::<i32>() as u32,
        )
    };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

fn recv(fd: i32, cap: usize, flags: i32) -> (Res, Vec<u8>) {
    let mut buf = vec![0u8; cap];
    let n = res(unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), cap, flags) });
    let copied = (*n.as_ref().unwrap_or(&0)).min(cap);
    buf.truncate(copied);
    (n, buf)
}

fn recvfrom(fd: i32, cap: usize, flags: i32) -> (Res, Vec<u8>, Option<u16>) {
    let mut buf = vec![0u8; cap];
    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let n = res(unsafe {
        libc::recvfrom(
            fd,
            buf.as_mut_ptr().cast(),
            cap,
            flags,
            (&raw mut name).cast(),
            &mut len,
        )
    });
    buf.truncate((*n.as_ref().unwrap_or(&0)).min(cap));
    (n, buf, n.is_ok().then(|| port_of(&name)))
}

fn port_of(name: &libc::sockaddr_storage) -> u16 {
    match name.ss_family as i32 {
        libc::AF_INET => {
            let sin =
                unsafe { &*(name as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            u16::from_be(sin.sin_port)
        }
        libc::AF_INET6 => {
            let sin6 =
                unsafe { &*(name as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>() };
            u16::from_be(sin6.sin6_port)
        }
        _ => 0,
    }
}

/// The control buffer is 8-aligned so `CMSG_*` walks it on both hosts.
#[repr(C, align(8))]
struct Control([u8; 256]);

/// One `recvmsg`: the return, `msg_flags` (with only `MSG_TRUNC`/`MSG_CTRUNC` kept), each iovec's
/// bytes, the source port and the control bytes as written.
#[derive(Debug, Clone, PartialEq)]
struct Msg {
    n: Res,
    flags: i32,
    iovs: Vec<Vec<u8>>,
    from: Option<u16>,
    control: Vec<u8>,
}

fn recvmsg(fd: i32, iov_lens: &[usize], control_cap: usize, flags: i32) -> Msg {
    let mut bufs: Vec<Vec<u8>> = iov_lens.iter().map(|&l| vec![0u8; l]).collect();
    let mut iovs: Vec<libc::iovec> = bufs
        .iter_mut()
        .map(|b| libc::iovec {
            iov_base: b.as_mut_ptr().cast(),
            iov_len: b.len(),
        })
        .collect();
    let mut control = Control([0xAA; 256]);
    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&raw mut name).cast();
    msg.msg_namelen = size_of::<libc::sockaddr_storage>() as u32;
    msg.msg_iov = iovs.as_mut_ptr();
    msg.msg_iovlen = iovs.len() as _;
    if control_cap > 0 {
        msg.msg_control = control.0.as_mut_ptr().cast();
        msg.msg_controllen = control_cap as _;
    }
    let n = res(unsafe { libc::recvmsg(fd, &mut msg, flags) });
    let mut left = *n.as_ref().unwrap_or(&0);
    for b in &mut bufs {
        let take = left.min(b.len());
        b.truncate(take);
        left -= take;
    }
    let used = if control_cap > 0 && n.is_ok() {
        msg.msg_controllen as usize
    } else {
        0
    };
    Msg {
        n,
        flags: msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC),
        iovs: bufs,
        from: n.is_ok().then(|| port_of(&name)),
        control: control.0[..used].to_vec(),
    }
}

fn fionread(fd: i32) -> i32 {
    let mut v: i32 = -1;
    let rc = unsafe { libc::ioctl(fd, libc::FIONREAD, &mut v) };
    assert_eq!(rc, 0, "FIONREAD: {}", errno());
    v
}

/// A pause long enough for real loopback to have delivered a datagram or its ICMP answer; virtual
/// in the sim.
fn settle() {
    std::thread::sleep(Duration::from_millis(20));
}

fn bound() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").unwrap()
}

fn port(s: &UdpSocket) -> u16 {
    s.local_addr().unwrap().port()
}

/// Empty datagrams queue, report their source and count as datagrams; a zero-length buffer
/// consumes a whole datagram; `FIONREAD` along the way.
fn zero_length_probe() -> Vec<String> {
    let (rx, tx) = (bound(), bound());
    let fd = rx.as_raw_fd();
    let to = rx.local_addr().unwrap();
    let mut out = Vec::new();
    out.push(format!(
        "send empty {:?}",
        tx.send_to(b"", to).map_err(|e| e.raw_os_error())
    ));
    settle();
    out.push(format!("fionread {}", fionread(fd)));
    let (n, data, from) = recvfrom(fd, 8, 0);
    out.push(format!(
        "recvfrom {n:?} {data:?} from_tx {}",
        from == Some(port(&tx))
    ));
    tx.send_to(b"abc", to).unwrap();
    tx.send_to(b"", to).unwrap();
    tx.send_to(b"de", to).unwrap();
    settle();
    out.push(format!("fionread {}", fionread(fd)));
    out.push(format!("recv into nothing {:?}", recv(fd, 0, 0)));
    out.push(format!("fionread {}", fionread(fd)));
    let m = recvmsg(fd, &[8], 0, 0);
    out.push(format!(
        "recvmsg {:?} flags {:#x} {:?}",
        m.n, m.flags, m.iovs
    ));
    let m = recvmsg(fd, &[0], 0, 0);
    out.push(format!(
        "recvmsg into nothing {:?} flags {:#x}",
        m.n, m.flags
    ));
    out.push(format!("then {:?}", recv(fd, 8, libc::MSG_DONTWAIT)));
    out
}

#[test]
fn zero_length_datagrams_os_truth() {
    let real = zero_length_probe();
    let sim = Sim::new().run(zero_length_probe);
    assert_eq!(sim, real);
}

const SIZES: [usize; 10] = [
    0, 1472, 9216, 9217, 16384, 65507, 65508, 65527, 65528, 70000,
];

/// For each payload size: the send's result and, when it went, the length received.
fn size_probe(rx_addr: &str) -> Option<Vec<(usize, Res, Option<usize>)>> {
    let rx = UdpSocket::bind(rx_addr).ok()?;
    let tx = UdpSocket::bind(rx_addr).unwrap();
    set_int(rx.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, 1 << 20).unwrap();
    set_int(tx.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF, 1 << 20).unwrap();
    rx.set_nonblocking(true).unwrap();
    let to = rx.local_addr().unwrap();
    let mut buf = vec![0u8; 80_000];
    let mut out = Vec::new();
    for len in SIZES {
        let sent = tx
            .send_to(&vec![0x5A; len], to)
            .map_err(|e| e.raw_os_error().unwrap());
        settle();
        let got = rx.recv(&mut buf).ok();
        out.push((len, sent, got));
    }
    Some(out)
}

#[test]
fn ipv4_payload_limits_os_truth() {
    let real = size_probe("127.0.0.1:0").unwrap();
    let sim = Sim::new().run(|| size_probe("127.0.0.1:0")).unwrap();
    assert_eq!(sim, real);
}

#[test]
fn ipv6_payload_limits_os_truth() {
    let Some(real) = size_probe("[::1]:0") else {
        eprintln!("skipped: the host has no ::1");
        return;
    };
    let sim = Sim::new().run(|| size_probe("[::1]:0")).unwrap();
    assert_eq!(sim, real);
}

#[test]
fn payload_limits_in_the_sim() {
    for addr in ["127.0.0.1:0", "[::1]:0"] {
        let got = Sim::new().run(|| size_probe(addr)).unwrap();
        let expected: Vec<_> = SIZES
            .iter()
            .map(|&l| {
                let limit = if addr.contains('[') { 65527 } else { 65507 };
                if l <= limit {
                    (l, Ok(l), Some(l))
                } else if cfg!(target_os = "macos") && addr.contains('[') {
                    (l, Ok(l), None)
                } else {
                    (l, Err(libc::EMSGSIZE), None)
                }
            })
            .collect();
        assert_eq!(got, expected, "{addr}");
    }
}

/// Up to 65507 bytes the host and the sim agree.
#[test]
fn payload_up_to_ipv4_limit_os_truth() {
    let upto = |v: Vec<(usize, Res, Option<usize>)>| -> Vec<_> {
        v.into_iter().filter(|(l, _, _)| *l <= 65507).collect()
    };
    let real = upto(size_probe("127.0.0.1:0").unwrap());
    let sim = upto(Sim::new().run(|| size_probe("127.0.0.1:0")).unwrap());
    assert_eq!(sim, real);
}

/// Ten-byte datagrams read every way a buffer can be too small or exactly right.
fn truncation_probe() -> Vec<String> {
    let (rx, tx) = (bound(), bound());
    let fd = rx.as_raw_fd();
    let to = rx.local_addr().unwrap();
    for _ in 0..7 {
        tx.send_to(b"0123456789", to).unwrap();
    }
    settle();
    vec![
        format!("recv 4 {:?}", recv(fd, 4, 0)),
        format!("recvmsg 4 {:?}", recvmsg(fd, &[4], 0, 0)),
        format!(
            "recvmsg 4 TRUNC {:?}",
            recvmsg(fd, &[4], 0, libc::MSG_TRUNC)
        ),
        format!("recvmsg 3+0+4 {:?}", recvmsg(fd, &[3, 0, 4], 0, 0)),
        format!("recvmsg 10 {:?}", recvmsg(fd, &[10], 0, 0)),
        format!("peek 4 {:?}", recv(fd, 4, libc::MSG_PEEK)),
        format!("recvmsg 6+6 {:?}", recvmsg(fd, &[6, 6], 0, 0)),
        format!("empty {:?}", recv(fd, 4, libc::MSG_DONTWAIT)),
    ]
    .into_iter()
    .map(|s| s.replace(&format!("from: Some({})", port(&tx)), "from: tx"))
    .collect()
}

#[test]
fn truncation_os_truth() {
    let real = truncation_probe();
    let sim = Sim::new().run(truncation_probe);
    assert_eq!(sim, real);
}

/// `recv`, `recvfrom` and a peeking `recv` with `MSG_TRUNC` in the flags: Linux returns the
/// datagram's real length.
#[cfg(target_os = "linux")]
#[test]
fn msg_trunc_input_flag_on_recv_os_truth() {
    let probe = || {
        let (rx, tx) = (bound(), bound());
        tx.send_to(b"0123456789", rx.local_addr().unwrap()).unwrap();
        tx.send_to(b"0123456789", rx.local_addr().unwrap()).unwrap();
        settle();
        (
            recv(rx.as_raw_fd(), 4, libc::MSG_PEEK | libc::MSG_TRUNC).0,
            recv(rx.as_raw_fd(), 4, libc::MSG_TRUNC).0,
            recvfrom(rx.as_raw_fd(), 4, libc::MSG_TRUNC).0,
        )
    };
    let real = probe();
    assert_eq!(real, (Ok(10), Ok(10), Ok(10)));
    assert_eq!(Sim::new().run(probe), real);
}

/// Peeking leaves a datagram whole, truncated or not, and a receive then takes it.
fn peek_probe() -> Vec<String> {
    let (rx, tx) = (bound(), bound());
    let fd = rx.as_raw_fd();
    let to = rx.local_addr().unwrap();
    tx.send_to(b"first-long-datagram!", to).unwrap();
    tx.send_to(b"second", to).unwrap();
    settle();
    let mut out = vec![
        format!("{:?}", recvfrom(fd, 5, libc::MSG_PEEK).0),
        format!("{:?}", recvmsg(fd, &[5], 0, libc::MSG_PEEK).flags),
        format!("{:?}", recv(fd, 64, libc::MSG_PEEK)),
        format!("fionread {}", fionread(fd)),
        format!("{:?}", recv(fd, 64, 0)),
        format!("{:?}", recv(fd, 3, libc::MSG_PEEK)),
        format!("{:?}", recv(fd, 64, 0)),
        format!("{:?}", recv(fd, 64, libc::MSG_PEEK | libc::MSG_DONTWAIT)),
    ];
    tx.send_to(b"third", to).unwrap();
    settle();
    out.push(format!(
        "{:?}",
        recv(fd, 64, libc::MSG_PEEK | libc::MSG_DONTWAIT)
    ));
    out.push(format!("{:?}", recv(fd, 64, libc::MSG_DONTWAIT)));
    out
}

#[test]
fn peek_then_recv_os_truth() {
    let real = peek_probe();
    let sim = Sim::new().run(peek_probe);
    assert_eq!(sim, real);
}

fn drain(s: &UdpSocket, names: &[(u16, &str)]) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = [0u8; 64];
    s.set_nonblocking(true).unwrap();
    loop {
        match s.recv_from(&mut buf) {
            Ok((n, from)) => {
                let who = names
                    .iter()
                    .find(|(p, _)| *p == from.port())
                    .map_or("?", |(_, name)| *name);
                out.push(format!("{}<{who}", String::from_utf8_lossy(&buf[..n])));
            }
            Err(e) => {
                out.push(format!("{:?}", e.raw_os_error()));
                break;
            }
        }
    }
    s.set_nonblocking(false).unwrap();
    out
}

/// What datagrams from a peer and a stranger reach a connected socket: the stranger's, sent
/// after the connect, never.
fn connected_probe() -> Vec<String> {
    let (rx, peer, stranger) = (bound(), bound(), bound());
    let to = rx.local_addr().unwrap();
    let names = [(port(&peer), "peer"), (port(&stranger), "stranger")];
    rx.connect(peer.local_addr().unwrap()).unwrap();
    peer.send_to(b"p1", to).unwrap();
    stranger.send_to(b"s1", to).unwrap();
    peer.send_to(b"p2", to).unwrap();
    settle();
    let mut out = drain(&rx, &names);
    out.push(format!(
        "peer_addr {:?}",
        rx.peer_addr().map(|a| a.port() == port(&peer))
    ));
    out.push(format!("stranger {:?}", drain(&stranger, &names)));
    out
}

#[test]
fn connected_filtering_os_truth() {
    let real = connected_probe();
    assert_eq!(Sim::new().run(connected_probe), real);
}

fn disconnect(s: &UdpSocket) -> Res {
    let unspec = libc::sockaddr_in {
        #[cfg(target_os = "macos")]
        sin_len: size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_UNSPEC as _,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    res(unsafe {
        libc::connect(
            s.as_raw_fd(),
            (&unspec as *const libc::sockaddr_in).cast(),
            size_of::<libc::sockaddr_in>() as u32,
        )
    } as isize)
}

/// A stranger's datagram queued before the connect, one sent while connected, a disconnect with
/// an `AF_UNSPEC` address and a reconnect to the stranger.
fn reconnect_probe() -> Vec<String> {
    let (rx, peer, stranger) = (bound(), bound(), bound());
    let to = rx.local_addr().unwrap();
    let names = [(port(&peer), "peer"), (port(&stranger), "stranger")];
    stranger.send_to(b"s-before", to).unwrap();
    settle();
    rx.connect(peer.local_addr().unwrap()).unwrap();
    peer.send_to(b"p1", to).unwrap();
    stranger.send_to(b"s1", to).unwrap();
    settle();
    let mut out = drain(&rx, &names);
    out.push(format!("disconnect {:?}", disconnect(&rx)));
    out.push(format!(
        "peer_addr {:?}",
        rx.peer_addr()
            .map(|a| a.port() == port(&peer))
            .map_err(|e| e.raw_os_error())
    ));
    stranger.send_to(b"s2", to).unwrap();
    peer.send_to(b"p2", to).unwrap();
    settle();
    out.extend(drain(&rx, &names));
    rx.connect(stranger.local_addr().unwrap()).unwrap();
    peer.send_to(b"p3", to).unwrap();
    stranger.send_to(b"s3", to).unwrap();
    settle();
    out.extend(drain(&rx, &names));
    out
}

#[test]
fn reconnect_in_the_sim() {
    let empty = format!("Some({})", libc::EAGAIN);
    let mut expected = vec![
        "s-before<stranger".into(),
        "p1<peer".into(),
        empty.clone(),
        if cfg!(target_os = "macos") {
            format!("disconnect Err({})", libc::EAFNOSUPPORT)
        } else {
            "disconnect Ok(0)".into()
        },
        format!("peer_addr Err(Some({}))", libc::ENOTCONN),
    ];
    if cfg!(target_os = "linux") {
        expected.extend([empty.clone(), empty]);
    } else {
        expected.extend([
            "s2<stranger".into(),
            "p2<peer".into(),
            empty.clone(),
            "s3<stranger".into(),
            empty,
        ]);
    }
    assert_eq!(Sim::new().run(reconnect_probe), expected);
}

#[test]
fn reconnect_os_truth() {
    let real = reconnect_probe();
    assert_eq!(Sim::new().run(reconnect_probe), real);
}

/// A connected socket whose peer closed, with one datagram from it still queued: the port
/// unreachable its next send draws, against that datagram and later calls. One unreachable only,
/// since hosts rate-limit them.
fn icmp_probe() -> Vec<String> {
    let (a, b) = (bound(), bound());
    a.connect(b.local_addr().unwrap()).unwrap();
    b.send_to(b"last", a.local_addr().unwrap()).unwrap();
    drop(b);
    let mut out = vec![format!(
        "send {:?}",
        a.send(b"x").map_err(|e| e.raw_os_error())
    )];
    settle();
    a.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 16];
    for _ in 0..3 {
        out.push(format!(
            "recv {:?}",
            a.recv(&mut buf)
                .map(|n| buf[..n].to_vec())
                .map_err(|e| e.raw_os_error())
        ));
    }
    out.push(format!(
        "so_error {:?}",
        a.take_error().map(|e| e.map(|e| e.raw_os_error()))
    ));
    out
}

#[test]
fn icmp_port_unreachable_once_os_truth() {
    let real = icmp_probe();
    let sim = Sim::new().run(icmp_probe);
    assert_eq!(sim, real);
}

#[cfg(target_os = "linux")]
#[test]
fn taking_so_error_preserves_the_icmp_error_queue_os_truth() {
    let probe = || {
        let (sender, peer) = (bound(), bound());
        set_int(sender.as_raw_fd(), libc::SOL_IP, libc::IP_RECVERR, 1).unwrap();
        sender.connect(peer.local_addr().unwrap()).unwrap();
        drop(peer);
        sender.send(b"").unwrap();
        settle();
        let pending = sender.take_error().unwrap().map(|e| e.raw_os_error());
        let report = recvmsg(sender.as_raw_fd(), &[64], 256, libc::MSG_ERRQUEUE);
        let drained = recvmsg(sender.as_raw_fd(), &[64], 256, libc::MSG_ERRQUEUE);
        (pending, report.n, report.iovs, drained.n)
    };
    let real = probe();
    assert_eq!(real.0, Some(Some(libc::ECONNREFUSED)));
    assert_eq!(real.1, Ok(0));
    assert_eq!(real.3, Err(libc::EAGAIN));
    assert_eq!(Sim::new().run(probe), real);
    assert_eq!(
        Sim::builder()
            .host(snare::HostProfile::new().build())
            .build()
            .run(probe),
        real
    );
}

#[cfg(target_os = "linux")]
fn icmp_error_queue_probe(tx_timestamp: bool) -> Vec<(usize, Vec<u8>, u8)> {
    let (sender, peer) = (bound(), bound());
    let fd = sender.as_raw_fd();
    set_int(fd, libc::SOL_IP, libc::IP_RECVERR, 1).unwrap();
    if tx_timestamp {
        set_int(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPING,
            (1 << 1) | (1 << 4) | (1 << 11),
        )
        .unwrap();
    }
    sender.connect(peer.local_addr().unwrap()).unwrap();
    drop(peer);
    sender.send(b"error payload").unwrap();
    settle();
    let mut out = Vec::new();
    loop {
        let report = recvmsg(fd, &[64], 256, libc::MSG_ERRQUEUE);
        let n = match report.n {
            Err(e) if e == libc::EAGAIN => break,
            n => n.unwrap(),
        };
        let mut control = Control([0; 256]);
        control.0[..report.control.len()].copy_from_slice(&report.control);
        let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        hdr.msg_control = control.0.as_mut_ptr().cast();
        hdr.msg_controllen = report.control.len();
        let mut origin = None;
        let mut c = unsafe { libc::CMSG_FIRSTHDR(&hdr) };
        while !c.is_null() {
            if unsafe { (*c).cmsg_level == libc::SOL_IP && (*c).cmsg_type == libc::IP_RECVERR } {
                assert!(unsafe { (*c).cmsg_len } >= unsafe { libc::CMSG_LEN(16) } as usize);
                origin = Some(unsafe { *libc::CMSG_DATA(c).add(4) });
            }
            c = unsafe { libc::CMSG_NXTHDR(&hdr, c) };
        }
        out.push((n, report.iovs.concat(), origin.expect("sock_extended_err")));
    }
    out
}

#[cfg(target_os = "linux")]
#[test]
fn icmp_error_queue_preserves_original_payload_os_truth() {
    let probe = || icmp_error_queue_probe(false);
    let real = probe();
    let fabric = Sim::new().run(probe);
    let simhost = Sim::builder()
        .host(snare::HostProfile::new().build())
        .build()
        .run(probe);
    assert_eq!(real, vec![(13, b"error payload".to_vec(), 2)]);
    assert_eq!((fabric, simhost), (real.clone(), real));
}

#[cfg(target_os = "linux")]
#[test]
fn mixed_error_queue_reports_follow_arrival_order_os_truth() {
    let probe = || {
        icmp_error_queue_probe(true)
            .into_iter()
            .map(|(_, _, origin)| origin)
            .collect::<Vec<_>>()
    };
    let real = probe();
    let fabric = Sim::new().run(probe);
    let simhost = Sim::builder()
        .host(snare::HostProfile::new().build())
        .build()
        .run(probe);
    assert_eq!(real, vec![4, 2]);
    assert_eq!((fabric, simhost), (real.clone(), real));
}

#[cfg(target_os = "linux")]
#[test]
fn icmp_error_payload_scatter_and_truncation_os_truth() {
    let probe = || {
        let mut out = Vec::new();
        for addr in ["127.0.0.1:0", "[::1]:0"] {
            for flags in [0, libc::MSG_TRUNC] {
                for caps in [&[][..], &[0][..], &[2, 0, 3][..], &[64][..]] {
                    let sender = UdpSocket::bind(addr).unwrap();
                    let peer = UdpSocket::bind(addr).unwrap();
                    let fd = sender.as_raw_fd();
                    let (level, option) = if addr.starts_with('[') {
                        (libc::SOL_IPV6, libc::IPV6_RECVERR)
                    } else {
                        (libc::SOL_IP, libc::IP_RECVERR)
                    };
                    set_int(fd, level, option, 1).unwrap();
                    sender.connect(peer.local_addr().unwrap()).unwrap();
                    drop(peer);
                    sender.send(b"error payload").unwrap();
                    settle();
                    let got = recvmsg(fd, caps, 256, libc::MSG_ERRQUEUE | flags);
                    out.push((got.n, got.flags, got.iovs));
                }
            }
        }
        out
    };
    let real = probe();
    let expected = vec![
        (Ok(0), libc::MSG_TRUNC, vec![]),
        (Ok(0), libc::MSG_TRUNC, vec![vec![]]),
        (
            Ok(5),
            libc::MSG_TRUNC,
            vec![b"er".to_vec(), vec![], b"ror".to_vec()],
        ),
        (Ok(13), 0, vec![b"error payload".to_vec()]),
    ];
    assert_eq!(real, vec![expected; 4].concat());
    assert_eq!(Sim::new().run(probe), real);
    assert_eq!(Sim::builder().deterministic().build().run(probe), real);
    assert_eq!(
        Sim::builder()
            .host(snare::HostProfile::new().build())
            .build()
            .run(probe),
        real
    );
}

/// Each datagram to the closed port draws its own unreachable, reported once by the next call:
/// the sim has no ICMP rate limit (a host may drop some of a burst).
#[test]
fn icmp_rearms_per_datagram_in_the_sim() {
    let got = Sim::new().run(|| {
        let mut out = icmp_probe();
        let (a, b) = (bound(), bound());
        a.connect(b.local_addr().unwrap()).unwrap();
        drop(b);
        for _ in 0..3 {
            a.send(b"w").unwrap();
            settle();
            out.push(format!("{:?}", a.send(b"v").map_err(|e| e.raw_os_error())));
            out.push(format!(
                "{:?}",
                a.take_error().unwrap().map(|e| e.raw_os_error())
            ));
        }
        out
    });
    let refused = format!("{:?}", Err::<usize, _>(Some(libc::ECONNREFUSED)));
    let expected: Vec<String> = (0..3)
        .flat_map(|_| [refused.clone(), "None".into()])
        .collect();
    assert_eq!(got[got.len() - 6..], expected[..]);
}

/// Two senders interleave 200 datagrams of varied length; the receiver drains them in send order.
fn order_probe() -> Vec<(u8, usize, u8)> {
    let rx = bound();
    set_int(rx.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, 1 << 20).unwrap();
    let to = rx.local_addr().unwrap();
    let senders = [bound(), bound()];
    for i in 0..200usize {
        let len = 1 + (i * 37) % 300;
        let mut msg = vec![i as u8; len];
        msg[0] = (i % 2) as u8;
        senders[i % 2].send_to(&msg, to).unwrap();
    }
    settle();
    rx.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 512];
    let mut got = Vec::new();
    while let Ok((n, from)) = rx.recv_from(&mut buf) {
        let who = senders
            .iter()
            .position(|s| s.local_addr().unwrap() == from)
            .unwrap() as u8;
        got.push((who, n, buf[n - 1]));
    }
    got
}

#[test]
fn many_queued_drain_in_order_os_truth() {
    let real = order_probe();
    assert_eq!(real.len(), 200);
    assert_eq!(Sim::new().run(order_probe), real);
    assert_eq!(
        Sim::builder().deterministic().build().run(order_probe),
        real
    );
}

/// What a receive buffer asked for as `rcvbuf` admits of `count` datagrams of `len` bytes, and the
/// socket's counters after: `(admitted, delivered, overflowed, drops, rmem_alloc)` with the queue
/// still full, then `rmem_alloc` once drained.
fn overflow(rcvbuf: i32, len: usize, count: usize) -> (usize, u64, u64, u32, usize, usize) {
    let (rx, tx) = (bound(), bound());
    set_int(rx.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, rcvbuf).unwrap();
    let to = rx.local_addr().unwrap();
    for _ in 0..count {
        tx.send_to(&vec![1u8; len], to).unwrap();
    }
    let id = snare::socket_id(&rx).unwrap();
    let full = snare::socket_entry(id).unwrap();
    rx.set_nonblocking(true).unwrap();
    let mut admitted = 0;
    while rx.recv(&mut [0u8; 2048]).is_ok() {
        admitted += 1;
    }
    let after = snare::socket_entry(id).unwrap();
    (
        admitted,
        full.delivered,
        full.overflowed,
        full.drops,
        full.rmem_alloc,
        after.rmem_alloc,
    )
}

/// Exact admission against the stock limits of the build host, for a spread of buffer and
/// datagram sizes.
#[test]
fn overflow_counts_exact() {
    let cases: [(i32, usize, usize); 6] = [
        (1, 100, 10),
        (2048, 1, 40),
        (4096, 512, 20),
        (8192, 1000, 20),
        (16384, 1400, 30),
        (65536, 64, 400),
    ];
    let got: Vec<_> = Sim::builder()
        .sys_limits(SysLimits::host())
        .build()
        .run(|| cases.iter().map(|&(b, l, c)| overflow(b, l, c)).collect());
    #[cfg(target_os = "linux")]
    let expected = [
        (2, 2, 8, 8, 1920, 0),
        (4, 4, 36, 36, 3840, 0),
        (6, 6, 14, 14, 7680, 0),
        (7, 7, 13, 13, 16128, 0),
        (14, 14, 16, 16, 32256, 0),
        (136, 136, 264, 264, 130560, 0),
    ];
    #[cfg(target_os = "macos")]
    let expected = [
        (0, 0, 10, 10, 0, 0),
        (11, 11, 29, 29, 16896, 0),
        (7, 7, 13, 13, 25088, 0),
        (7, 7, 13, 13, 25088, 0),
        (11, 11, 19, 19, 39424, 0),
        (342, 342, 58, 58, 525312, 0),
    ];
    assert_eq!(got, expected);
}

/// `SO_RXQ_OVFL` on Linux: each datagram carries the drop count as it stood when it was queued
/// (none while 0), in a 24-byte `CMSG_SPACE`, cut to its 16-byte header with `MSG_CTRUNC` when the
/// control buffer is short.
#[cfg(target_os = "linux")]
#[test]
fn rxq_ovfl_control_bytes_exact() {
    const SO_RXQ_OVFL: i32 = 40;
    let got = Sim::builder()
        .sys_limits(SysLimits::host())
        .build()
        .run(|| {
            let (rx, tx) = (bound(), bound());
            let fd = rx.as_raw_fd();
            set_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, 1).unwrap();
            let to = rx.local_addr().unwrap();
            let send = |n: usize| {
                for i in 0..n {
                    tx.send_to(&[i as u8; 100], to).unwrap();
                }
            };
            send(2);
            set_int(fd, libc::SOL_SOCKET, SO_RXQ_OVFL, 1).unwrap();
            let mut out = vec![recvmsg(fd, &[128], 64, 0)];
            send(5);
            out.push(recvmsg(fd, &[128], 64, 0));
            out.push(recvmsg(fd, &[128], 64, 0));
            send(3);
            out.push(recvmsg(fd, &[128], 64, 0));
            out.push(recvmsg(fd, &[128], 16, 0));
            set_int(fd, libc::SOL_SOCKET, SO_RXQ_OVFL, 0).unwrap();
            send(1);
            out.push(recvmsg(fd, &[128], 64, 0));
            out.iter()
                .map(|m| (m.n, m.flags, m.control.clone()))
                .collect::<Vec<_>>()
        });
    let header = |len: u8| vec![len, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 40, 0, 0, 0];
    let mut four = header(20);
    four.extend(4u32.to_ne_bytes());
    four.extend([0; 4]);
    assert_eq!(
        got,
        [
            (Ok(100), 0, vec![]),
            (Ok(100), 0, vec![]),
            (Ok(100), 0, vec![]),
            (Ok(100), 0, four),
            (Ok(100), libc::MSG_CTRUNC, header(16)),
            (Ok(100), 0, vec![]),
        ]
    );
}

/// The receive stamps of a `deterministic()` run, control bytes exact: they move only if the
/// clock's charging or the stamping point changes.
#[test]
fn timestamp_control_bytes_exact() {
    #[cfg(target_os = "linux")]
    const OPT: i32 = 29;
    #[cfg(target_os = "macos")]
    const OPT: i32 = libc::SO_TIMESTAMP;
    let run = || {
        Sim::builder().deterministic().seed(7).build().run(|| {
            let (rx, tx) = (bound(), bound());
            let fd = rx.as_raw_fd();
            set_int(fd, libc::SOL_SOCKET, OPT, 1).unwrap();
            snare::set_udp_policy(rx.local_addr().unwrap(), |p| {
                p.latency = Duration::from_micros(250)
            });
            tx.send_to(b"a", rx.local_addr().unwrap()).unwrap();
            std::thread::sleep(Duration::from_millis(3));
            tx.send_to(b"bb", rx.local_addr().unwrap()).unwrap();
            let first = recvmsg(fd, &[8], 64, 0);
            let second = recvmsg(fd, &[8], 64, 0);
            (first.control, second.control)
        })
    };
    let (first, second) = run();
    assert_eq!(run(), (first.clone(), second.clone()));
    let stamp = |usec: i64| {
        #[cfg(target_os = "linux")]
        let mut c = vec![32, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 29, 0, 0, 0];
        #[cfg(target_os = "macos")]
        let mut c = vec![28, 0, 0, 0, 255, 255, 0, 0, 2, 0, 0, 0];
        c.extend(1_700_000_000i64.to_ne_bytes());
        c.extend(usec.to_ne_bytes());
        c
    };
    assert_eq!((first, second), (stamp(250), stamp(3250)));
}

/// Without `SO_BROADCAST` a broadcast send is refused with `EACCES`; with it every socket bound
/// on the port gets one copy, and one on another port or the sender's ephemeral one none.
#[test]
fn broadcast_permission_and_recipients() {
    Sim::new().run(|| {
        let p = port(&bound());
        let wild = UdpSocket::bind(("0.0.0.0", p)).unwrap();
        let lo2 = UdpSocket::bind(("127.0.0.2", p)).unwrap();
        let other_port = UdpSocket::bind(("0.0.0.0", p + 1)).unwrap();
        let tx = UdpSocket::bind("0.0.0.0:0").unwrap();
        let refused = tx.send_to(b"x", (Ipv4Addr::BROADCAST, p)).unwrap_err();
        assert_eq!(refused.raw_os_error(), Some(libc::EACCES));
        assert!(!tx.broadcast().unwrap());
        tx.set_broadcast(true).unwrap();
        assert_eq!(tx.send_to(b"all", (Ipv4Addr::BROADCAST, p)).unwrap(), 3);
        let names = [(port(&tx), "tx")];
        let empty = format!("{:?}", Some(libc::EAGAIN));
        assert_eq!(drain(&wild, &names), ["all<tx", empty.as_str()]);
        assert_eq!(drain(&lo2, &names), ["all<tx", empty.as_str()]);
        assert_eq!(drain(&other_port, &names), [empty.as_str()]);
        assert_eq!(drain(&tx, &names), [empty.as_str()]);
    });
}

/// `setsockopt` answers for joining and leaving a group: a second join, a leave without a join, a
/// leave after one and a second leave.
fn membership_probe() -> Vec<Result<(), i32>> {
    let s = UdpSocket::bind("0.0.0.0:0").unwrap();
    let mreq = libc::ip_mreq {
        imr_multiaddr: libc::in_addr {
            s_addr: u32::from(Ipv4Addr::new(239, 255, 42, 77)).to_be(),
        },
        imr_interface: libc::in_addr { s_addr: 0 },
    };
    let opt = |name: i32| {
        let rc = unsafe {
            libc::setsockopt(
                s.as_raw_fd(),
                libc::IPPROTO_IP,
                name,
                (&mreq as *const libc::ip_mreq).cast(),
                size_of::<libc::ip_mreq>() as u32,
            )
        };
        if rc == 0 { Ok(()) } else { Err(errno()) }
    };
    vec![
        opt(libc::IP_DROP_MEMBERSHIP),
        opt(libc::IP_ADD_MEMBERSHIP),
        opt(libc::IP_ADD_MEMBERSHIP),
        opt(libc::IP_DROP_MEMBERSHIP),
        opt(libc::IP_DROP_MEMBERSHIP),
    ]
}

#[test]
fn membership_calls_in_the_sim() {
    assert_eq!(
        Sim::new().run(membership_probe),
        [
            Err(libc::EADDRNOTAVAIL),
            Ok(()),
            Err(libc::EADDRINUSE),
            Ok(()),
            Err(libc::EADDRNOTAVAIL)
        ]
    );
}

#[test]
fn membership_calls_os_truth() {
    let real = membership_probe();
    assert_eq!(Sim::new().run(membership_probe), real);
}

/// Linux delivers a group joined by any socket of the host to every socket on the port bound to
/// the wildcard or the group while `IP_MULTICAST_ALL` is on (the default), and only its own joins
/// once it is off; the member keeps receiving throughout.
#[cfg(target_os = "linux")]
#[test]
fn multicast_all_toggles_delivery() {
    Sim::new().run(|| {
        let group = Ipv4Addr::new(239, 255, 42, 78);
        let p = port(&bound());
        let member = UdpSocket::bind(("0.0.0.0", p)).unwrap();
        member
            .join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)
            .unwrap();
        let bystander = UdpSocket::bind(("0.0.0.0", p + 1)).unwrap();
        let on_group = UdpSocket::bind((group, p)).unwrap();
        for s in [&bystander, &on_group] {
            assert_eq!(
                get_int(s.as_raw_fd(), libc::IPPROTO_IP, libc::IP_MULTICAST_ALL),
                1
            );
        }
        let tx = bound();
        let names = [(port(&tx), "tx")];
        let empty = format!("{:?}", Some(libc::EAGAIN));
        tx.send_to(b"one", (group, p)).unwrap();
        tx.send_to(b"by", (group, p + 1)).unwrap();
        assert_eq!(drain(&member, &names), ["one<tx", empty.as_str()]);
        assert_eq!(drain(&on_group, &names), ["one<tx", empty.as_str()]);
        assert_eq!(drain(&bystander, &names), ["by<tx", empty.as_str()]);
        for s in [&bystander, &on_group] {
            set_int(s.as_raw_fd(), libc::IPPROTO_IP, libc::IP_MULTICAST_ALL, 0).unwrap();
            assert_eq!(
                get_int(s.as_raw_fd(), libc::IPPROTO_IP, libc::IP_MULTICAST_ALL),
                0
            );
        }
        tx.send_to(b"two", (group, p)).unwrap();
        tx.send_to(b"by2", (group, p + 1)).unwrap();
        assert_eq!(drain(&member, &names), ["two<tx", empty.as_str()]);
        assert_eq!(drain(&on_group, &names), [empty.as_str()]);
        assert_eq!(drain(&bystander, &names), [empty.as_str()]);
    });
}

#[cfg(target_os = "linux")]
fn get_int(fd: i32, level: i32, name: i32) -> i32 {
    let mut v: i32 = -1;
    let mut len = size_of::<i32>() as u32;
    let rc = unsafe { libc::getsockopt(fd, level, name, (&mut v as *mut i32).cast(), &mut len) };
    assert_eq!(rc, 0, "getsockopt: {}", errno());
    v
}
