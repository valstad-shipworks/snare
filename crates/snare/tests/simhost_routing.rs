#![cfg(target_os = "linux")]
//! A `SimHost`'s interfaces join the sim's topology, so its UDP sockets route like the fabric's:
//! across a link that can go down, taking the interface's latency.

use std::net::{IpAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

use snare::{HostProfile, IpNet, Nic, NicPolicy, Sim, set_link};

const SO_TIMESTAMPING: i32 = 37;
const SOF_TIMESTAMPING_RX_SOFTWARE: u32 = 1 << 3;
const SOF_TIMESTAMPING_SOFTWARE: u32 = 1 << 4;

fn realtime() -> Duration {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// The software receive stamp of the next datagram on `fd`, or `None` if none has arrived.
fn recv_stamp(fd: i32) -> Option<Duration> {
    let mut buf = [0u8; 32];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut control = [0u8; 128];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();
    if unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) } < 0 {
        return None;
    }
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    assert!(!cmsg.is_null(), "SCM_TIMESTAMPING present");
    let ts = unsafe {
        libc::CMSG_DATA(cmsg)
            .cast::<libc::timespec>()
            .read_unaligned()
    };
    Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

#[test]
fn simhost_udp_routes_like_fabric() {
    let latency = Duration::from_millis(3);
    let host = HostProfile::new()
        .nic(
            Nic::new("eth0", 2)
                .network("10.0.0.1/24".parse::<IpNet>().unwrap())
                .station("10.0.0.2".parse::<IpAddr>().unwrap())
                .policy(NicPolicy {
                    latency,
                    ..NicPolicy::default()
                }),
        )
        .build();
    let sim = Sim::builder().host(host).build();
    assert_eq!(sim.nic("eth0").unwrap().index, 2);
    sim.run(|| {
        let rx = UdpSocket::bind("10.0.0.1:9000").unwrap();
        let flags = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE;
        let rc = unsafe {
            libc::setsockopt(
                rx.as_raw_fd(),
                libc::SOL_SOCKET,
                SO_TIMESTAMPING,
                (&flags as *const u32).cast(),
                4,
            )
        };
        assert_eq!(rc, 0);
        let station = UdpSocket::bind("10.0.0.2:0").unwrap();

        let sent = realtime();
        station.send_to(b"stamp", "10.0.0.1:9000").unwrap();
        assert_eq!(recv_stamp(rx.as_raw_fd()), None, "still crossing eth0");
        std::thread::sleep(latency * 2);
        let stamp = recv_stamp(rx.as_raw_fd()).expect("arrived");
        assert!(
            stamp >= sent + latency,
            "rx stamp {stamp:?} after {sent:?} + {latency:?}"
        );

        set_link("eth0", false).unwrap();
        station.send_to(b"lost", "10.0.0.1:9000").unwrap();
        std::thread::sleep(latency * 2);
        assert_eq!(recv_stamp(rx.as_raw_fd()), None, "lost while down");
        set_link("eth0", true).unwrap();

        let err = UdpSocket::bind("10.0.0.9:0").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EADDRNOTAVAIL));
        let local = UdpSocket::bind("127.0.0.1:0").unwrap();
        let err = local.send_to(b"x", "10.0.0.2:1").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    });
}
