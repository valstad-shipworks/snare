#![cfg(target_os = "linux")]
//! pcapng capture of a `SimHost`'s datagram sockets: per-interface blocks, frames stamped with the
//! same instant as their SO_TIMESTAMPING TX stamp, one frame per datagram each way, and no effect
//! on an as-fast-as-possible clock.

#[path = "support/pcapng_reader.rs"]
mod reader;

use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use snare::{Bytes, HostProfile, IpNet, Nic, Sim, TesterAction, run_testers, udp_tester};

const SO_TIMESTAMPING: i32 = 37;
const SCM_TIMESTAMPING: i32 = 37;
const SOF_TIMESTAMPING_TX_SOFTWARE: u32 = 1 << 1;
const SOF_TIMESTAMPING_SOFTWARE: u32 = 1 << 4;

fn scratch(name: &str) -> PathBuf {
    snare::real(|| {
        let dir = std::env::temp_dir().join(format!("snare-pcapng-host-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(format!("{name}.pcapng"))
    })
}

fn two_nic_host() -> std::sync::Arc<snare::SimHost> {
    HostProfile::new()
        .nic(Nic::new("enp1s0", 2).network("10.41.0.1/24".parse::<IpNet>().unwrap()))
        .nic(Nic::new("enp2s0", 3).network("10.42.0.1/24".parse::<IpNet>().unwrap()))
        .build()
}

#[test]
fn per_nic_idbs() {
    let path = scratch("per_nic");
    let sim = Sim::builder().host(two_nic_host()).pcapng(&path).build();
    sim.run(|| {
        let s = UdpSocket::bind("0.0.0.0:0").unwrap();
        s.send_to(b"a", "10.42.0.9:9000").unwrap();
        s.send_to(b"b", "10.41.0.9:9000").unwrap();
    });
    drop(sim);
    let file = reader::read(&path);
    assert_eq!(file.ifaces, ["enp2s0", "enp1s0"]);
    let srcs: Vec<String> = file
        .packets
        .iter()
        .map(|p| reader::decode(&p.data).src.to_string())
        .collect();
    assert_eq!(srcs, ["10.42.0.1", "10.41.0.1"]);
}

#[test]
fn epb_stamp_equals_so_timestamping_tx_stamp() {
    let path = scratch("tx_stamp");
    let sim = Sim::builder()
        .host(HostProfile::new().build())
        .pcapng(&path)
        .build();
    let tx_ns = sim.run(|| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = s.as_raw_fd();
        let flags = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_TX_SOFTWARE;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_TIMESTAMPING,
                (&flags as *const u32).cast(),
                size_of::<u32>() as u32,
            )
        };
        assert_eq!(rc, 0);
        std::thread::sleep(Duration::from_millis(3));
        s.send_to(b"stamp", "127.0.0.1:9100").unwrap();
        let mut buf = [0u8; 8];
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
        assert!(unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE) } >= 0);
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !cmsg.is_null() {
            let (level, ty) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
            if level == libc::SOL_SOCKET && ty == SCM_TIMESTAMPING {
                let ts: libc::timespec =
                    unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast()) };
                return ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
        }
        panic!("no TX timestamp");
    });
    drop(sim);
    let file = reader::read(&path);
    let udp = file
        .packets
        .iter()
        .find(|p| reader::decode(&p.data).l4 == reader::L4::Udp)
        .unwrap();
    assert_eq!(udp.ns, tx_ns);
}

#[test]
fn simhost_socket_and_udp_tester_captured_once_each_way() {
    let path = scratch("tester");
    let sim = Sim::builder()
        .host(HostProfile::new().build())
        .pcapng(&path)
        .build();
    sim.run(|| {
        let tester = udp_tester::<Bytes>("127.0.0.2:9101")
            .then_action(|msg, _| TesterAction::Send(msg))
            .until_after(Duration::from_millis(50));
        let client = std::thread::spawn(|| {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.send_to(b"echo", "127.0.0.2:9101").unwrap();
            let mut buf = [0u8; 8];
            s.recv_from(&mut buf).unwrap().0
        });
        run_testers!(tester);
        assert_eq!(client.join().unwrap(), 4);
    });
    drop(sim);
    let file = reader::read(&path);
    let dirs: Vec<bool> = file.packets.iter().map(|p| p.inbound).collect();
    assert_eq!(dirs, [false, true]);
    for p in &file.packets {
        assert_eq!(reader::decode(&p.data).payload, b"echo");
    }
}

fn afap_run() -> Vec<Duration> {
    let rx = UdpSocket::bind("127.0.0.1:9102").unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let start = Instant::now();
    let mut seen = Vec::new();
    for i in 0..5u8 {
        tx.send_to(&[i], "127.0.0.1:9102").unwrap();
        let mut buf = [0u8; 1];
        rx.recv_from(&mut buf).unwrap();
        seen.push(start.elapsed());
    }
    seen
}

#[test]
fn afap_capture_does_not_tick_the_clock() {
    let afap = || Sim::builder().host(HostProfile::new().build()).wall_clock();
    let without = afap().build().run(afap_run);
    let path = scratch("afap");
    let sim = afap().pcapng(&path).build();
    let with = sim.run(afap_run);
    drop(sim);
    assert_eq!(with, without);
    assert_eq!(reader::read(&path).packets.len(), 5);
}
