#![cfg(unix)]

//! Kernel receive and transmit timestamps on the plain `Sim`'s fabric: `SO_TIMESTAMP`,
//! `SO_TIMESTAMPNS`, `SO_TIMESTAMPING` and the `MSG_ERRQUEUE` transmit stamps on Linux;
//! `SO_TIMESTAMP`, `SO_TIMESTAMP_MONOTONIC` and `SO_TIMESTAMP_CONTINUOUS` on macOS. Each stamp is
//! the sim's clock when the packet reached the socket, so a datagram sent across a 30 ms link and
//! read late still carries its arrival time. The `*_os_truth` tests run one probe on the real
//! stack and in the sim and require the same outcome.

#[cfg(target_os = "linux")]
use std::io::Read;
use std::io::Write;
use std::mem::size_of;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

use snare::Sim;

const LATENCY: Duration = Duration::from_millis(30);

fn setsockopt<T>(fd: i32, level: i32, name: i32, value: &T) -> Result<(), i32> {
    setsockopt_len(fd, level, name, value, size_of::<T>() as u32)
}

fn setsockopt_len<T>(fd: i32, level: i32, name: i32, value: &T, len: u32) -> Result<(), i32> {
    let rc = unsafe { libc::setsockopt(fd, level, name, (value as *const T).cast(), len) };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

fn getsockopt_bytes(fd: i32, level: i32, name: i32, cap: u32) -> Result<Vec<u8>, i32> {
    let mut buf = vec![0u8; cap as usize];
    let mut len = cap;
    let rc = unsafe { libc::getsockopt(fd, level, name, buf.as_mut_ptr().cast(), &mut len) };
    if rc != 0 {
        return Err(errno());
    }
    buf.truncate(len as usize);
    Ok(buf)
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

/// What one `recvmsg` returned: the byte count (or errno), `msg_flags`, `msg_namelen`, and the
/// control buffer as written.
#[derive(Debug, Clone, PartialEq)]
struct Got {
    n: Result<usize, i32>,
    flags: i32,
    namelen: u32,
    control: Vec<u8>,
    data: Vec<u8>,
}

/// The control buffer is 8-aligned so `CMSG_*` walks it on both hosts.
#[repr(C, align(8))]
struct Control([u8; 512]);

fn recvmsg(fd: i32, cap: usize, data_cap: usize, flags: i32) -> Got {
    let mut data = vec![0u8; data_cap];
    let mut control = Control([0xAA; 512]);
    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&raw mut name).cast();
    msg.msg_namelen = size_of::<libc::sockaddr_storage>() as u32;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if cap > 0 {
        msg.msg_control = control.0.as_mut_ptr().cast();
        msg.msg_controllen = cap as _;
    }
    let rc = unsafe { libc::recvmsg(fd, &mut msg, flags) };
    let n = if rc < 0 {
        Err(errno())
    } else {
        Ok(rc as usize)
    };
    let used = if cap > 0 {
        msg.msg_controllen as usize
    } else {
        0
    };
    data.truncate(*n.as_ref().unwrap_or(&0));
    Got {
        n,
        flags: msg.msg_flags,
        namelen: msg.msg_namelen,
        control: control.0[..used].to_vec(),
        data,
    }
}

/// The complete control messages in `control`: `(level, type, payload)`.
#[allow(clippy::unnecessary_cast)]
fn cmsgs(control: &[u8]) -> Vec<(i32, i32, Vec<u8>)> {
    let hdr = size_of::<libc::cmsghdr>();
    let align = std::mem::align_of::<libc::cmsghdr>();
    let mut out = Vec::new();
    let mut off = 0;
    while off + hdr <= control.len() {
        let c: libc::cmsghdr = unsafe {
            control
                .as_ptr()
                .add(off)
                .cast::<libc::cmsghdr>()
                .read_unaligned()
        };
        let len = c.cmsg_len as usize;
        if len < hdr || off + len > control.len() {
            break;
        }
        let data_at = off + unsafe { libc::CMSG_LEN(0) } as usize;
        out.push((
            c.cmsg_level,
            c.cmsg_type,
            control[data_at..off + len].to_vec(),
        ));
        off += (len + align - 1) & !(align - 1);
    }
    out
}

/// What a control buffer looks like with the payload bytes blanked: the headers as written and the
/// lengths, which match between the real stack and the sim even though the times differ.
#[allow(clippy::unnecessary_cast)]
fn shape(control: &[u8]) -> Vec<u8> {
    let hdr = size_of::<libc::cmsghdr>();
    let align = std::mem::align_of::<libc::cmsghdr>();
    let mut out = control.to_vec();
    let mut off = 0;
    while off < control.len() {
        let end = (off + hdr).min(control.len());
        if end - off < hdr {
            break;
        }
        let c: libc::cmsghdr = unsafe {
            control
                .as_ptr()
                .add(off)
                .cast::<libc::cmsghdr>()
                .read_unaligned()
        };
        let data_at = off + unsafe { libc::CMSG_LEN(0) } as usize;
        let full = c.cmsg_len as usize;
        for b in out
            .iter_mut()
            .take((off + full).min(control.len()))
            .skip(data_at)
        {
            *b = 0xDD;
        }
        off += (full.max(hdr) + align - 1) & !(align - 1);
    }
    out
}

fn timeval_of(payload: &[u8]) -> Duration {
    let tv: libc::timeval = unsafe { payload.as_ptr().cast::<libc::timeval>().read_unaligned() };
    Duration::new(tv.tv_sec as u64, tv.tv_usec as u32 * 1000)
}

#[cfg(target_os = "linux")]
fn timespec_of(payload: &[u8]) -> Duration {
    let ts: libc::timespec = unsafe { payload.as_ptr().cast::<libc::timespec>().read_unaligned() };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

fn realtime() -> Duration {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

fn pair() -> (UdpSocket, UdpSocket) {
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    (rx, tx)
}

#[cfg(target_os = "linux")]
mod linux {
    pub const SO_TIMESTAMP: i32 = 29;
    pub const SO_TIMESTAMPNS: i32 = 35;
    pub const SO_TIMESTAMPING: i32 = 37;
    pub const TX_SOFTWARE: u32 = 1 << 1;
    pub const RX_SOFTWARE: u32 = 1 << 3;
    pub const SOFTWARE: u32 = 1 << 4;
    pub const OPT_ID: u32 = 1 << 7;
    pub const TX_SCHED: u32 = 1 << 8;
    pub const TX_ACK: u32 = 1 << 9;
    pub const OPT_TSONLY: u32 = 1 << 11;
    pub const OPT_STATS: u32 = 1 << 12;
    pub const BIND_PHC: u32 = 1 << 15;
    pub const OPT_ID_TCP: u32 = 1 << 16;
    pub const OPT_RX_FILTER: u32 = 1 << 17;
}

/// A datagram sent across a 30 ms link and read 50 ms after it was sent is stamped with its
/// arrival: send time plus 30 ms, exactly, on the virtual clock. This is the shape of telegenic's
/// `received_after_acquisition` check.
#[test]
fn udp_rx_stamp_is_the_arrival_time() {
    for _ in 0..5 {
        Sim::new().run(|| {
            let (rx, tx) = pair();
            let to = rx.local_addr().unwrap();
            snare::set_udp_policy(to, |p| p.latency = LATENCY);
            #[cfg(target_os = "linux")]
            {
                let flags = linux::RX_SOFTWARE | linux::SOFTWARE;
                setsockopt(
                    rx.as_raw_fd(),
                    libc::SOL_SOCKET,
                    linux::SO_TIMESTAMPING,
                    &flags,
                )
                .unwrap();
                setsockopt(
                    rx.as_raw_fd(),
                    libc::SOL_SOCKET,
                    linux::SO_TIMESTAMPNS,
                    &1i32,
                )
                .unwrap();
            }
            #[cfg(target_os = "macos")]
            setsockopt(rx.as_raw_fd(), libc::SOL_SOCKET, libc::SO_TIMESTAMP, &1i32).unwrap();
            let sent = realtime();
            tx.send_to(b"frame", to).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            let got = recvmsg(rx.as_raw_fd(), 256, 64, 0);
            assert_eq!(got.n, Ok(5));
            assert!(realtime() >= sent + Duration::from_millis(50));
            let msgs = cmsgs(&got.control);
            #[cfg(target_os = "linux")]
            {
                assert_eq!(
                    msgs.len(),
                    2,
                    "SCM_TIMESTAMPNS then SCM_TIMESTAMPING: {msgs:?}"
                );
                assert_eq!(
                    (msgs[0].0, msgs[0].1),
                    (libc::SOL_SOCKET, linux::SO_TIMESTAMPNS)
                );
                assert_eq!(timespec_of(&msgs[0].2), sent + LATENCY);
                assert_eq!(
                    (msgs[1].0, msgs[1].1),
                    (libc::SOL_SOCKET, linux::SO_TIMESTAMPING)
                );
                assert_eq!(msgs[1].2.len(), 3 * size_of::<libc::timespec>());
                assert_eq!(timespec_of(&msgs[1].2), sent + LATENCY);
                assert_eq!(timespec_of(&msgs[1].2[16..]), Duration::ZERO);
                assert_eq!(timespec_of(&msgs[1].2[32..]), Duration::ZERO);
            }
            #[cfg(target_os = "macos")]
            {
                assert_eq!(msgs.len(), 1, "{msgs:?}");
                assert_eq!(
                    (msgs[0].0, msgs[0].1),
                    (libc::SOL_SOCKET, libc::SCM_TIMESTAMP)
                );
                assert_eq!(timeval_of(&msgs[0].2), sent + LATENCY);
            }
        });
    }
}

/// The stamps hold under `deterministic()` too, and a plain `SO_TIMESTAMP` gets a `timeval`.
#[test]
fn so_timestamp_timeval_under_deterministic() {
    for _ in 0..5 {
        Sim::builder().deterministic().build().run(|| {
            let (rx, tx) = pair();
            let to = rx.local_addr().unwrap();
            snare::set_udp_policy(to, |p| p.latency = LATENCY);
            setsockopt(rx.as_raw_fd(), libc::SOL_SOCKET, libc::SO_TIMESTAMP, &1i32).unwrap();
            let sent = realtime();
            let sender = std::thread::spawn(move || tx.send_to(b"x", to).unwrap());
            let got = recvmsg(rx.as_raw_fd(), 256, 64, 0);
            sender.join().unwrap();
            let msgs = cmsgs(&got.control);
            assert_eq!(msgs.len(), 1, "{msgs:?}");
            assert_eq!(msgs[0].1, libc::SCM_TIMESTAMP);
            let at = timeval_of(&msgs[0].2);
            assert!(
                at >= sent + LATENCY && at < sent + LATENCY + Duration::from_millis(1),
                "{at:?}"
            );
        });
    }
}

/// macOS `SO_TIMESTAMP_MONOTONIC` and `SO_TIMESTAMP_CONTINUOUS` carry Mach ticks of the arrival,
/// on the clock `mach_absolute_time` reads in the sim.
#[cfg(target_os = "macos")]
#[test]
fn mach_time_stamps_are_the_arrival() {
    const SO_TIMESTAMP_CONTINUOUS: i32 = 0x40000;
    unsafe extern "C" {
        fn mach_absolute_time() -> u64;
    }
    for _ in 0..5 {
        Sim::new().run(|| {
            let (rx, tx) = pair();
            let to = rx.local_addr().unwrap();
            snare::set_udp_policy(to, |p| p.latency = LATENCY);
            let fd = rx.as_raw_fd();
            setsockopt(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMP, &1i32).unwrap();
            setsockopt(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMP_MONOTONIC, &1i32).unwrap();
            setsockopt(fd, libc::SOL_SOCKET, SO_TIMESTAMP_CONTINUOUS, &1i32).unwrap();
            tx.send_to(b"x", to).unwrap();
            std::thread::sleep(LATENCY);
            let arrived = unsafe { mach_absolute_time() };
            std::thread::sleep(LATENCY);
            let got = recvmsg(fd, 256, 64, 0);
            let msgs = cmsgs(&got.control);
            let types: Vec<i32> = msgs.iter().map(|m| m.1).collect();
            assert_eq!(types, [libc::SCM_TIMESTAMP, 0x04, 0x07]);
            let ticks = |p: &[u8]| u64::from_ne_bytes(p.try_into().unwrap());
            let mono = ticks(&msgs[1].2);
            assert_eq!(mono, ticks(&msgs[2].2));
            assert!(mono.abs_diff(arrived) <= 1, "{mono} vs {arrived}");
        });
    }
}

#[cfg(target_os = "macos")]
fn macos_timestamp_option_shapes() -> Vec<Vec<(i32, i32, usize)>> {
    let mut out = Vec::new();
    for realtime in [false, true] {
        for monotonic in [false, true] {
            for continuous in [false, true] {
                let (rx, tx) = pair();
                rx.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                for (option, enabled) in [
                    (libc::SO_TIMESTAMP, realtime),
                    (libc::SO_TIMESTAMP_MONOTONIC, monotonic),
                    (0x40000, continuous),
                ] {
                    setsockopt(rx.as_raw_fd(), libc::SOL_SOCKET, option, &(enabled as i32))
                        .unwrap();
                }
                tx.send_to(b"options", rx.local_addr().unwrap()).unwrap();
                let got = recvmsg(rx.as_raw_fd(), 256, 64, 0);
                assert_eq!(got.n, Ok(7));
                assert_eq!(got.data, b"options");
                assert_eq!(got.flags, 0);
                let fields: Vec<_> = cmsgs(&got.control)
                    .into_iter()
                    .map(|(level, kind, bytes)| (level, kind, bytes.len()))
                    .collect();
                let mut expected = Vec::new();
                if realtime {
                    expected.push((
                        libc::SOL_SOCKET,
                        libc::SCM_TIMESTAMP,
                        size_of::<libc::timeval>(),
                    ));
                }
                if monotonic {
                    expected.push((libc::SOL_SOCKET, 0x04, size_of::<u64>()));
                }
                if continuous {
                    expected.push((libc::SOL_SOCKET, 0x07, size_of::<u64>()));
                }
                assert_eq!(fields, expected);
                out.push(fields);
            }
        }
    }
    out
}

#[cfg(target_os = "macos")]
#[test]
fn timestamp_option_combinations_preserve_cmsg_order_os_truth() {
    let real = snare::real(macos_timestamp_option_shapes);
    assert_eq!(Sim::new().run(macos_timestamp_option_shapes), real);
    assert_eq!(
        Sim::builder()
            .deterministic()
            .build()
            .run(macos_timestamp_option_shapes),
        real
    );
}

/// Linux reports a TCP read's stamp: the arrival of the last byte it took. macOS attaches nothing
/// to a stream.
#[test]
fn tcp_rx_stamp_is_the_last_byte_read() {
    for _ in 0..5 {
        Sim::new().run(|| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            snare::set_tcp_policy(addr, |p| p.latency = LATENCY);
            let mut client = TcpStream::connect(addr).unwrap();
            let (server, _) = listener.accept().unwrap();
            #[cfg(target_os = "linux")]
            setsockopt(
                server.as_raw_fd(),
                libc::SOL_SOCKET,
                linux::SO_TIMESTAMPING,
                &(linux::RX_SOFTWARE | linux::SOFTWARE),
            )
            .unwrap();
            #[cfg(target_os = "macos")]
            setsockopt(
                server.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMP,
                &1i32,
            )
            .unwrap();
            let first = realtime();
            client.write_all(b"abc").unwrap();
            std::thread::sleep(Duration::from_millis(10));
            client.write_all(b"def").unwrap();
            std::thread::sleep(Duration::from_millis(100));
            let got = recvmsg(server.as_raw_fd(), 256, 64, 0);
            assert_eq!(got.data, b"abcdef");
            assert_eq!(got.namelen, 0);
            let msgs = cmsgs(&got.control);
            #[cfg(target_os = "linux")]
            {
                assert_eq!(msgs.len(), 1, "{msgs:?}");
                assert_eq!(msgs[0].1, linux::SO_TIMESTAMPING);
                let at = timespec_of(&msgs[0].2);
                let second = first + Duration::from_millis(10) + LATENCY;
                assert!(
                    at >= second && at < second + Duration::from_millis(1),
                    "{at:?}"
                );
            }
            #[cfg(target_os = "macos")]
            assert!(msgs.is_empty(), "{msgs:?} at {first:?}");
        });
    }
}

/// What the same receive with control buffers of several sizes looks like.
fn short_control_buffer_probe() -> Vec<(usize, i32, Vec<u8>)> {
    let (rx, tx) = pair();
    let to = rx.local_addr().unwrap();
    let fd = rx.as_raw_fd();
    #[cfg(target_os = "linux")]
    {
        setsockopt(fd, libc::SOL_SOCKET, linux::SO_TIMESTAMPNS, &1i32).unwrap();
        let flags = linux::RX_SOFTWARE | linux::SOFTWARE;
        setsockopt(fd, libc::SOL_SOCKET, linux::SO_TIMESTAMPING, &flags).unwrap();
    }
    #[cfg(target_os = "macos")]
    {
        setsockopt(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMP, &1i32).unwrap();
        setsockopt(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMP_MONOTONIC, &1i32).unwrap();
        setsockopt(fd, libc::SOL_SOCKET, 0x40000, &1i32).unwrap();
    }
    rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut out = Vec::new();
    for cap in [512, 0, 8, 20, 28, 30, 32, 40, 48, 64] {
        // The deferred static key can leave the first packets after enabling unstamped on Linux;
        // the probe retries until a stamped one comes, as the drivers' own tests do.
        let got = loop {
            tx.send_to(b"ping", to).unwrap();
            let got = recvmsg(fd, cap, 64, 0);
            let full = recvmsg_check(&got, cap);
            if full {
                break got;
            }
        };
        out.push((cap, got.flags & libc::MSG_CTRUNC, shape(&got.control)));
    }
    out
}

/// Whether `got` (with a `cap`-byte control buffer) shows the packet was stamped: with a big
/// buffer, that both messages came.
fn recvmsg_check(got: &Got, cap: usize) -> bool {
    cap != 512 || cmsgs(&got.control).len() >= 2
}

#[test]
fn short_control_buffer_os_truth() {
    let real = snare::real(short_control_buffer_probe);
    let simulated = Sim::new().run(short_control_buffer_probe);
    assert_eq!(simulated, real);
}

/// Option handling: short values, read-back, and on Linux the `SO_TIMESTAMPING` validation.
fn option_validation_probe() -> Vec<(&'static str, Result<Vec<u8>, i32>)> {
    let (rx, _tx) = pair();
    let fd = rx.as_raw_fd();
    let mut out = Vec::new();
    let unit = |r: Result<(), i32>| r.map(|()| Vec::new());
    out.push((
        "SO_TIMESTAMP 1-byte",
        unit(setsockopt_len(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMP,
            &1u8,
            1,
        )),
    ));
    out.push((
        "SO_TIMESTAMP 7",
        unit(setsockopt(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMP, &7i32)),
    ));
    out.push((
        "get SO_TIMESTAMP",
        getsockopt_bytes(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMP, 4),
    ));
    #[cfg(target_os = "macos")]
    {
        out.push((
            "SO_TIMESTAMP_MONOTONIC",
            unit(setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMP_MONOTONIC,
                &1i32,
            )),
        ));
        out.push((
            "get SO_TIMESTAMP_MONOTONIC",
            getsockopt_bytes(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMP_MONOTONIC, 4),
        ));
        out.push((
            "get SO_TIMESTAMP_CONTINUOUS",
            getsockopt_bytes(fd, libc::SOL_SOCKET, 0x40000, 4),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        use linux::*;
        let set = |flags: u32| unit(setsockopt(fd, libc::SOL_SOCKET, SO_TIMESTAMPING, &flags));
        out.push((
            "SO_TIMESTAMPNS",
            unit(setsockopt(fd, libc::SOL_SOCKET, SO_TIMESTAMPNS, &1i32)),
        ));
        out.push((
            "get SO_TIMESTAMP after NS",
            getsockopt_bytes(fd, libc::SOL_SOCKET, SO_TIMESTAMP, 4),
        ));
        out.push((
            "get SO_TIMESTAMPNS",
            getsockopt_bytes(fd, libc::SOL_SOCKET, SO_TIMESTAMPNS, 4),
        ));
        out.push(("bit 18", set(1 << 18)));
        out.push(("bit 19", set(1 << 19)));
        out.push(("OPT_ID_TCP alone", set(OPT_ID_TCP)));
        out.push(("OPT_STATS without TSONLY", set(OPT_STATS)));
        out.push(("OPT_STATS with TSONLY", set(OPT_STATS | OPT_TSONLY)));
        out.push(("BIND_PHC unbound", set(BIND_PHC)));
        out.push(("RX_FILTER", set(OPT_RX_FILTER | SOFTWARE | OPT_ID)));
        out.push((
            "TIMESTAMPING short",
            unit(setsockopt_len(
                fd,
                libc::SOL_SOCKET,
                SO_TIMESTAMPING,
                &1u8,
                1,
            )),
        ));
        out.push((
            "get TIMESTAMPING 4",
            getsockopt_bytes(fd, libc::SOL_SOCKET, SO_TIMESTAMPING, 4),
        ));
        out.push((
            "get TIMESTAMPING 12",
            getsockopt_bytes(fd, libc::SOL_SOCKET, SO_TIMESTAMPING, 12),
        ));
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        out.push((
            "OPT_ID on a listener",
            unit(setsockopt(
                tcp.as_raw_fd(),
                libc::SOL_SOCKET,
                SO_TIMESTAMPING,
                &OPT_ID,
            )),
        ));
    }
    out
}

#[test]
fn option_validation_os_truth() {
    let real = snare::real(option_validation_probe);
    let simulated = Sim::new().run(option_validation_probe);
    assert_eq!(simulated, real);
}

/// A transmit-stamp read's outcome with the times left out: bytes, flags, name length, the
/// messages' `(level, type, length)`, and the `sock_extended_err` fields that are not times.
#[cfg(target_os = "linux")]
type ErrqEntry = (
    Result<usize, i32>,
    i32,
    u32,
    Vec<(i32, i32, usize)>,
    Option<[u32; 4]>,
);

#[cfg(target_os = "linux")]
fn errqueue_entry(fd: i32, data_cap: usize) -> ErrqEntry {
    let got = recvmsg(fd, 512, data_cap, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT);
    let msgs = cmsgs(&got.control);
    let ee = msgs
        .iter()
        .find(|m| m.1 == libc::IP_RECVERR || m.1 == libc::IPV6_RECVERR)
        .map(|m| {
            let e: libc::sock_extended_err = unsafe {
                m.2.as_ptr()
                    .cast::<libc::sock_extended_err>()
                    .read_unaligned()
            };
            [e.ee_errno, u32::from(e.ee_origin), e.ee_info, e.ee_data]
        });
    let shape = msgs.iter().map(|m| (m.0, m.1, m.2.len())).collect();
    let namelen = if got.n.is_ok() { got.namelen } else { 0 };
    (
        got.n,
        got.flags & !libc::MSG_CMSG_CLOEXEC,
        namelen,
        shape,
        ee,
    )
}

#[cfg(target_os = "linux")]
fn tx_errqueue_probe() -> Vec<ErrqEntry> {
    use linux::*;
    let (rx, tx) = pair();
    let to = rx.local_addr().unwrap();
    let fd = tx.as_raw_fd();
    let mut out = Vec::new();
    setsockopt(
        fd,
        libc::SOL_SOCKET,
        SO_TIMESTAMPING,
        &(TX_SOFTWARE | SOFTWARE | OPT_ID),
    )
    .unwrap();
    tx.send_to(b"abcd", to).unwrap();
    tx.send_to(b"efghij", to).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    out.push(errqueue_entry(fd, 64));
    out.push(errqueue_entry(fd, 64));
    out.push(errqueue_entry(fd, 64));
    setsockopt(
        fd,
        libc::SOL_SOCKET,
        SO_TIMESTAMPING,
        &(TX_SOFTWARE | SOFTWARE | OPT_ID | OPT_TSONLY | TX_SCHED),
    )
    .unwrap();
    tx.send_to(b"abcd", to).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    out.push(errqueue_entry(fd, 64));
    out.push(errqueue_entry(fd, 64));
    out.push(errqueue_entry(fd, 64));

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    let c = client.as_raw_fd();
    let flags = TX_SOFTWARE | TX_SCHED | TX_ACK | SOFTWARE | OPT_ID | OPT_TSONLY;
    setsockopt(c, libc::SOL_SOCKET, SO_TIMESTAMPING, &flags).unwrap();
    client.write_all(b"0123456789").unwrap();
    let mut buf = [0u8; 10];
    server.read_exact(&mut buf).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    for _ in 0..4 {
        out.push(errqueue_entry(c, 64));
    }
    setsockopt(
        c,
        libc::SOL_SOCKET,
        SO_TIMESTAMPING,
        &(TX_SOFTWARE | SOFTWARE | OPT_ID),
    )
    .unwrap();
    client.write_all(b"abc").unwrap();
    std::thread::sleep(Duration::from_millis(50));
    out.push(errqueue_entry(c, 64));
    out.push(errqueue_entry(c, 64));
    out
}

#[cfg(target_os = "linux")]
#[test]
fn tx_errqueue_os_truth() {
    let real = snare::real(tx_errqueue_probe);
    let simulated = Sim::new().run(tx_errqueue_probe);
    assert_eq!(simulated, real);
}

#[cfg(target_os = "linux")]
#[test]
fn later_send_reports_precede_delayed_acknowledgments() {
    use linux::*;
    for drain_before_ack in [false, true] {
        Sim::new().run(|| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            snare::set_tcp_policy(addr, |p| p.latency = Duration::from_millis(20));
            let mut client = TcpStream::connect(addr).unwrap();
            let (_server, _) = listener.accept().unwrap();
            let fd = client.as_raw_fd();
            let flags = TX_SOFTWARE | TX_ACK | SOFTWARE | OPT_ID | OPT_TSONLY;
            setsockopt(fd, libc::SOL_SOCKET, SO_TIMESTAMPING, &flags).unwrap();
            client.write_all(b"0123456789").unwrap();
            std::thread::sleep(Duration::from_millis(5));
            client.write_all(b"x").unwrap();
            let read = || {
                let ee = errqueue_entry(fd, 0).4.expect("transmit report");
                (ee[2], ee[3])
            };
            if !drain_before_ack {
                std::thread::sleep(Duration::from_millis(50));
            }
            assert_eq!([read(), read()], [(0, 9), (0, 10)]);
            if drain_before_ack {
                assert_eq!(errqueue_entry(fd, 0).0, Err(libc::EAGAIN));
                std::thread::sleep(Duration::from_millis(50));
            }
            assert_eq!([read(), read()], [(2, 9), (2, 10)]);
            assert_eq!(errqueue_entry(fd, 0).0, Err(libc::EAGAIN));
        });
    }
}

/// A transmit stamp is the virtual send time, and the error queue makes the socket poll `POLLERR`
/// until it is read.
#[cfg(target_os = "linux")]
#[test]
fn tx_stamp_is_the_send_time_and_polls_err() {
    use linux::*;
    for _ in 0..5 {
        Sim::new().run(|| {
            let (rx, tx) = pair();
            let to = rx.local_addr().unwrap();
            let fd = tx.as_raw_fd();
            let flags = TX_SOFTWARE | SOFTWARE | OPT_ID | OPT_TSONLY;
            setsockopt(fd, libc::SOL_SOCKET, SO_TIMESTAMPING, &flags).unwrap();
            std::thread::sleep(Duration::from_millis(7));
            let sent = realtime();
            tx.send_to(b"abcd", to).unwrap();
            let mut pfd = libc::pollfd {
                fd,
                events: 0,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut pfd, 1, 0) }, 1);
            assert_eq!(pfd.revents & libc::POLLERR, libc::POLLERR);
            let got = recvmsg(fd, 512, 64, libc::MSG_ERRQUEUE);
            assert_eq!(got.n, Ok(0));
            let msgs = cmsgs(&got.control);
            assert_eq!(msgs[0].1, SO_TIMESTAMPING);
            let at = timespec_of(&msgs[0].2);
            assert!(
                at >= sent && at < sent + Duration::from_millis(1),
                "{at:?} vs {sent:?}"
            );
            pfd.revents = 0;
            assert_eq!(unsafe { libc::poll(&mut pfd, 1, 0) }, 0);
        });
    }
}

/// `SIOCGHWTSTAMP` on an interface with no hardware timestamping is `EOPNOTSUPP`, on an unknown
/// name `ENODEV`.
#[cfg(target_os = "linux")]
fn hwtstamp_probe() -> Vec<i32> {
    #[repr(C)]
    struct Ifreq {
        name: [u8; 16],
        data: *mut libc::c_void,
        _pad: [u8; 16],
    }
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut cfg = [0i32; 3];
    let mut out = Vec::new();
    for name in ["lo", "nope0"] {
        let mut req = Ifreq {
            name: [0; 16],
            data: cfg.as_mut_ptr().cast(),
            _pad: [0; 16],
        };
        req.name[..name.len()].copy_from_slice(name.as_bytes());
        let rc = unsafe { libc::ioctl(sock.as_raw_fd(), 0x89b1, &mut req) };
        out.push(if rc == 0 { 0 } else { errno() });
    }
    out
}

#[cfg(target_os = "linux")]
#[test]
fn hwtstamp_ioctl_os_truth() {
    let real = snare::real(hwtstamp_probe);
    let simulated = Sim::new().run(hwtstamp_probe);
    assert_eq!(simulated, real);
}

/// A tester's reply carries its arrival stamp too.
#[test]
fn tester_datagram_is_stamped() {
    Sim::new().run(|| {
        let peer = snare::udp_tester::<snare::Bytes>("127.0.0.9:7000")
            .then_action(|msg, _| snare::TesterAction::Send(msg))
            .until_after(Duration::from_millis(100));
        let client = std::thread::spawn(|| {
            let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
            let me: SocketAddr = rx.local_addr().unwrap();
            snare::set_udp_policy(me, |p| p.latency = LATENCY);
            setsockopt(rx.as_raw_fd(), libc::SOL_SOCKET, libc::SO_TIMESTAMP, &1i32).unwrap();
            let sent = realtime();
            rx.send_to(b"hi", "127.0.0.9:7000").unwrap();
            let got = recvmsg(rx.as_raw_fd(), 256, 64, 0);
            assert_eq!(got.data, b"hi");
            let msgs = cmsgs(&got.control);
            assert_eq!(msgs.len(), 1);
            (sent, timeval_of(&msgs[0].2))
        });
        snare::run_testers!(peer);
        let (sent, at) = client.join().unwrap();
        assert!(
            at >= sent + LATENCY && at < sent + LATENCY + Duration::from_millis(1),
            "{at:?}"
        );
    });
}

/// Which control messages a TCP read with receive stamps on gets: Linux's `SCM_TIMESTAMPING`,
/// nothing on macOS.
fn tcp_rx_probe() -> Vec<(i32, i32, usize)> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    #[cfg(target_os = "linux")]
    setsockopt(
        server.as_raw_fd(),
        libc::SOL_SOCKET,
        linux::SO_TIMESTAMPING,
        &(linux::RX_SOFTWARE | linux::SOFTWARE),
    )
    .unwrap();
    #[cfg(target_os = "macos")]
    setsockopt(
        server.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_TIMESTAMP,
        &1i32,
    )
    .unwrap();
    let attempts = if cfg!(target_os = "linux") { 20 } else { 1 };
    for attempt in 0..attempts {
        client.write_all(b"abc").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let got = recvmsg(server.as_raw_fd(), 256, 64, 0);
        assert_eq!(got.data, b"abc");
        let messages: Vec<_> = cmsgs(&got.control)
            .into_iter()
            .map(|(level, ty, data)| (level, ty, data.len()))
            .collect();
        // Linux enables receive timestamping through deferred static-key work.
        if !messages.is_empty() || attempt + 1 == attempts {
            return messages;
        }
    }
    unreachable!()
}

#[test]
fn tcp_rx_steady_state_os_truth() {
    let real = snare::real(tcp_rx_probe);
    let simulated = Sim::new().run(tcp_rx_probe);
    #[cfg(target_os = "linux")]
    assert_eq!(
        real,
        [(
            libc::SOL_SOCKET,
            linux::SO_TIMESTAMPING,
            3 * size_of::<libc::timespec>()
        )]
    );
    assert_eq!(simulated, real);
}
