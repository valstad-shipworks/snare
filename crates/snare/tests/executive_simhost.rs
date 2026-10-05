#![cfg(target_os = "linux")]

//! An executive driving a `SimHost`'s clock: receive timestamps and the PHC follow it exactly.

use std::thread;
use std::time::{Duration, Instant};

use snare::sched::{Executive, ExecutiveConfig};
use snare::{HostProfile, PtpCaps, Sim};

const MS: Duration = Duration::from_millis(1);
const EPOCH_NANOS: u64 = 1_700_000_000 * 1_000_000_000;
const PHC_OFFSET: i64 = 750;

// SO_TIMESTAMPING == SCM_TIMESTAMPING == 37 (asm-generic/socket.h); the flag bits are from
// <linux/net_tstamp.h>.
const SO_TIMESTAMPING: i32 = 37;
const SOF_TIMESTAMPING_RX_SOFTWARE: u32 = 1 << 3;
const SOF_TIMESTAMPING_SOFTWARE: u32 = 1 << 4;

const fn ioc(dir: u64, ty: u8, nr: u64, size: usize) -> libc::c_ulong {
    ((dir << 30) | ((ty as u64) << 8) | nr | ((size as u64) << 16)) as libc::c_ulong
}

// <linux/ptp_clock.h>: struct ptp_sys_offset_precise is 64 bytes.
const PTP_SYS_OFFSET_PRECISE: libc::c_ulong = ioc(3, b'=', 8, 64);

fn nanos(ts: libc::timespec) -> u64 {
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn loopback(port: u16) -> libc::sockaddr_in {
    // SAFETY: an all-zero sockaddr_in is valid.
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as u16;
    sa.sin_port = port.to_be();
    sa.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
    sa
}

const SOCKADDR_IN_LEN: u32 = std::mem::size_of::<libc::sockaddr_in>() as u32;

/// (PHC, CLOCK_REALTIME) from one PTP_SYS_OFFSET_PRECISE sample, in nanoseconds.
fn phc_sample(fd: i32) -> (u64, u64) {
    let mut buf = [0u8; 64];
    // SAFETY: the ioctl fills the 64-byte struct.
    assert_eq!(
        unsafe { libc::ioctl(fd, PTP_SYS_OFFSET_PRECISE, buf.as_mut_ptr()) },
        0
    );
    let at = |off: usize| {
        let sec = i64::from_ne_bytes(buf[off..off + 8].try_into().unwrap());
        let nsec = u32::from_ne_bytes(buf[off + 8..off + 12].try_into().unwrap());
        sec as u64 * 1_000_000_000 + nsec as u64
    };
    (at(0), at(16))
}

/// Receives one datagram, returning its software receive stamp.
fn recv_stamp(fd: i32) -> u64 {
    let mut buf = [0u8; 16];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut control = [0u8; 128];
    // SAFETY: an all-zero msghdr is valid; the fields set below point at live buffers.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();
    // SAFETY: as above.
    assert!(unsafe { libc::recvmsg(fd, &mut msg, 0) } > 0);
    // SAFETY: walking the control buffer recvmsg filled.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == SO_TIMESTAMPING {
                let stamps = (libc::CMSG_DATA(cmsg) as *const [libc::timespec; 3]).read_unaligned();
                return nanos(stamps[0]);
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    panic!("no SCM_TIMESTAMPING");
}

fn jump(exec: &Executive, t: Duration) -> u32 {
    let start = snare::real(Instant::now);
    loop {
        let q = exec.quiescence();
        if q.quiescent
            && q.blocked > 0
            && let Ok(fired) = exec.jump_to(t)
        {
            return fired;
        }
        assert!(
            snare::real(|| start.elapsed()) < Duration::from_secs(20),
            "{q:?}"
        );
        snare::real(|| thread::sleep(Duration::from_micros(200)));
    }
}

#[test]
fn so_timestamping_rx_stamps_follow_the_landing_and_the_phc_follows_the_driven_clock() {
    let caps = PtpCaps {
        cross_timestamping: true,
        ..PtpCaps::default()
    };
    let host = HostProfile::new()
        .ptp_clock_offset(0, PHC_OFFSET)
        .ptp_clock_caps(0, caps)
        .build();
    let sim = Sim::builder().host(host).build();
    thread::scope(|s| {
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let run = s.spawn(|| {
            sim.run(|| {
                // SAFETY: plain socket and device calls on fresh descriptors.
                unsafe {
                    let ptp = libc::open(c"/dev/ptp0".as_ptr(), libc::O_RDWR);
                    assert!(ptp >= 0);
                    let rx = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
                    let tx = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
                    let sa = loopback(9400);
                    assert_eq!(
                        libc::bind(
                            rx,
                            (&sa as *const libc::sockaddr_in).cast(),
                            SOCKADDR_IN_LEN
                        ),
                        0
                    );
                    let flags = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE;
                    assert_eq!(
                        libc::setsockopt(
                            rx,
                            libc::SOL_SOCKET,
                            SO_TIMESTAMPING,
                            (&flags as *const u32).cast(),
                            4,
                        ),
                        0
                    );
                    thread::sleep(7 * MS);
                    assert_eq!(
                        libc::sendto(
                            tx,
                            b"tick".as_ptr().cast(),
                            4,
                            0,
                            (&sa as *const libc::sockaddr_in).cast(),
                            SOCKADDR_IN_LEN
                        ),
                        4
                    );
                    let stamp = recv_stamp(rx);
                    let first = phc_sample(ptp);
                    thread::sleep(13 * MS);
                    let second = phc_sample(ptp);
                    libc::close(rx);
                    libc::close(tx);
                    libc::close(ptp);
                    (stamp, first, second)
                }
            })
        });
        assert_eq!(jump(&exec, Duration::from_secs(1)), 1);
        assert_eq!(exec.now(), 7 * MS);
        assert_eq!(jump(&exec, Duration::from_secs(1)), 1);
        let ns = Duration::from_nanos(1);
        assert!(
            (20 * MS + ns..=20 * MS + 2 * ns).contains(&exec.now()),
            "the sleep began 1 ns past the first landing"
        );
        let (stamp, (phc1, real1), (phc2, real2)) = run.join().unwrap();
        let at = |t: Duration| EPOCH_NANOS + t.as_nanos() as u64;
        assert_eq!(
            stamp,
            at(7 * MS + ns),
            "the rx stamp is the landing, crept past by the send"
        );
        assert_eq!(real1, at(7 * MS + ns));
        assert_eq!(phc1, real1.wrapping_add_signed(PHC_OFFSET));
        assert_eq!(
            real2,
            at(20 * MS + 2 * ns),
            "the PHC moves only with the driven clock"
        );
        assert_eq!(phc2, real2.wrapping_add_signed(PHC_OFFSET));
    });
}
