#![cfg(target_os = "macos")]

//! Fan-out and blocking behaviour of the simulated `/dev/bpf*` shared medium. bpf(4): a frame
//! written on a bound device is delivered to every other device bound to the same interface, and a
//! device opened without `O_NONBLOCK` blocks in read(2) until a frame arrives.

use std::ffi::CString;

use snare::{NicSpec, Sim, add_nic};

const BIOCSETIF: libc::c_ulong = 0x8020_426c;
const BIOCIMMEDIATE: libc::c_ulong = 0x8004_4270;
const BIOCGBLEN: libc::c_ulong = 0x4004_4266;
const BPF_HDRLEN: usize = 18;

fn open_bpf(dev: &str, nonblocking: bool) -> i32 {
    let path = CString::new(dev).unwrap();
    let mut flags = libc::O_RDWR;
    if nonblocking {
        flags |= libc::O_NONBLOCK;
    }
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    assert!(fd >= 0, "open {dev}");
    let mut on: u32 = 1;
    assert_eq!(unsafe { libc::ioctl(fd, BIOCIMMEDIATE, &mut on) }, 0);
    fd
}

fn bind(fd: i32, iface: &str) {
    let mut ifr: [u8; 32] = [0; 32];
    ifr[..iface.len()].copy_from_slice(iface.as_bytes());
    assert_eq!(unsafe { libc::ioctl(fd, BIOCSETIF, ifr.as_mut_ptr()) }, 0);
}

fn blen(fd: i32) -> usize {
    let mut n: u32 = 0;
    assert_eq!(unsafe { libc::ioctl(fd, BIOCGBLEN, &mut n) }, 0);
    n as usize
}

fn frame_with_marker(marker: u8) -> [u8; 60] {
    let mut f = [0u8; 60];
    f[12] = 0x88;
    f[13] = 0xa4;
    f[14] = marker;
    f
}

#[test]
fn a_frame_fans_out_to_every_other_listener() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let sender = open_bpf("/dev/bpf0", true);
        let l1 = open_bpf("/dev/bpf1", true);
        let l2 = open_bpf("/dev/bpf2", true);
        for fd in [sender, l1, l2] {
            bind(fd, "en0");
        }

        let frame = frame_with_marker(0x42);
        unsafe { libc::write(sender, frame.as_ptr().cast(), frame.len()) };

        // Both other devices on en0 receive the one write; the shared medium copies to each.
        for fd in [l1, l2] {
            let mut buf = vec![0u8; blen(fd)];
            let got = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            assert!(got as usize >= BPF_HDRLEN, "listener got the frame");
            assert_eq!(buf[BPF_HDRLEN + 14], 0x42);
        }
        unsafe {
            libc::close(sender);
            libc::close(l1);
            libc::close(l2);
        }
    });
}

#[test]
fn closing_a_listener_stops_its_delivery() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let sender = open_bpf("/dev/bpf0", true);
        let keep = open_bpf("/dev/bpf1", true);
        let gone = open_bpf("/dev/bpf2", true);
        for fd in [sender, keep, gone] {
            bind(fd, "en0");
        }
        unsafe { libc::close(gone) };

        let frame = frame_with_marker(0x7);
        unsafe { libc::write(sender, frame.as_ptr().cast(), frame.len()) };

        let mut buf = vec![0u8; blen(keep)];
        let got = unsafe { libc::read(keep, buf.as_mut_ptr().cast(), buf.len()) };
        assert!(
            got as usize >= BPF_HDRLEN,
            "the surviving listener still receives"
        );
        unsafe {
            libc::close(sender);
            libc::close(keep);
        }
    });
}

#[test]
fn a_blocking_read_wakes_when_a_peer_transmits() {
    // bpf(4): without O_NONBLOCK a read blocks until the buffer has a packet. The reader thread
    // parks in the fabric's readiness wait and the writer's transmit wakes it — both threads are
    // managed because they are spawned inside Sim::run.
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let reader = open_bpf("/dev/bpf0", false);
        let writer = open_bpf("/dev/bpf1", true);
        bind(reader, "en0");
        bind(writer, "en0");

        let rx = std::thread::spawn(move || {
            let mut buf = vec![0u8; blen(reader)];
            let got = unsafe { libc::read(reader, buf.as_mut_ptr().cast(), buf.len()) };
            assert!(got as usize >= BPF_HDRLEN, "blocking read returned a frame");
            buf[BPF_HDRLEN + 14]
        });

        let frame = frame_with_marker(0x99);
        unsafe { libc::write(writer, frame.as_ptr().cast(), frame.len()) };

        assert_eq!(rx.join().unwrap(), 0x99, "the awaited frame's marker");
        unsafe {
            libc::close(reader);
            libc::close(writer);
        }
    });
}

#[test]
fn two_stations_exchange_frames_both_ways() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let a = open_bpf("/dev/bpf0", true);
        let b = open_bpf("/dev/bpf1", true);
        bind(a, "en0");
        bind(b, "en0");

        let req = frame_with_marker(0x10);
        unsafe { libc::write(a, req.as_ptr().cast(), req.len()) };
        let mut buf = vec![0u8; blen(b)];
        let got = unsafe { libc::read(b, buf.as_mut_ptr().cast(), buf.len()) } as usize;
        assert_eq!(buf[BPF_HDRLEN + 14], 0x10);
        assert!(got >= BPF_HDRLEN);

        let resp = frame_with_marker(0x20);
        unsafe { libc::write(b, resp.as_ptr().cast(), resp.len()) };
        let mut buf = vec![0u8; blen(a)];
        let got = unsafe { libc::read(a, buf.as_mut_ptr().cast(), buf.len()) } as usize;
        assert_eq!(buf[BPF_HDRLEN + 14], 0x20);
        assert!(got >= BPF_HDRLEN);

        unsafe {
            libc::close(a);
            libc::close(b);
        }
    });
}
