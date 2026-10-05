#![cfg(target_os = "macos")]

//! Raw L2 over `/dev/bpf*`, the BSD packet-capture device ethercrab's macOS transport drives.
//! Every ioctl code and the read framing are defined in bpf(4) (`<net/bpf.h>`); the fabric serves
//! these when a `Sim` has no `SimHost` occupying the file plane.

use std::ffi::CString;

use snare::{NicSpec, Sim, add_nic};

// bpf(4): ioctl request codes built with _IOW/_IOR from <net/bpf.h>. BIOCSETIF binds the device to
// a named interface (struct ifreq), BIOCIMMEDIATE selects immediate/unbuffered read mode, and
// BIOCGBLEN reads the required read-buffer length.
const BIOCSETIF: libc::c_ulong = 0x8020_426c;
const BIOCIMMEDIATE: libc::c_ulong = 0x8004_4270;
const BIOCGBLEN: libc::c_ulong = 0x4004_4266;

// bpf(4) struct bpf_hdr: bh_tstamp(8), bh_caplen@8, bh_datalen@12, bh_hdrlen@16, then the frame.
// BPF_WORDALIGN(sizeof(bpf_hdr)) leaves an 18-byte header before the captured bytes.
const BPF_HDRLEN: usize = 18;

fn open_bpf(dev: &str) -> i32 {
    let path = CString::new(dev).unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    assert!(fd >= 0, "open {dev}");
    fd
}

fn bind(fd: i32, iface: &str) -> i32 {
    // bpf(4): BIOCSETIF takes a struct ifreq whose ifr_name is the interface. A 32-byte scratch
    // buffer covers ifr_name (IFNAMSIZ = 16) plus the ifr_ifru union.
    let mut ifr: [u8; 32] = [0; 32];
    ifr[..iface.len()].copy_from_slice(iface.as_bytes());
    unsafe { libc::ioctl(fd, BIOCSETIF, ifr.as_mut_ptr()) }
}

fn immediate(fd: i32) -> i32 {
    let mut on: u32 = 1;
    unsafe { libc::ioctl(fd, BIOCIMMEDIATE, &mut on) }
}

fn blen(fd: i32) -> u32 {
    let mut n: u32 = 0;
    let rc = unsafe { libc::ioctl(fd, BIOCGBLEN, &mut n) };
    assert_eq!(rc, 0, "BIOCGBLEN");
    n
}

fn bound_device(iface: &str, dev: &str) -> i32 {
    let fd = open_bpf(dev);
    assert_eq!(immediate(fd), 0, "BIOCIMMEDIATE");
    assert_eq!(bind(fd, iface), 0, "BIOCSETIF {iface}");
    fd
}

fn ethercat_frame() -> [u8; 60] {
    // A minimal EtherCAT frame: broadcast dst, a src, ethertype 0x88a4, one command byte.
    let mut f = [0u8; 60];
    f[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    f[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    f[12] = 0x88;
    f[13] = 0xa4;
    f[14] = 0x42;
    f
}

fn caplen(hdr: &[u8]) -> usize {
    u32::from_ne_bytes(hdr[8..12].try_into().unwrap()) as usize
}

fn datalen(hdr: &[u8]) -> usize {
    u32::from_ne_bytes(hdr[12..16].try_into().unwrap()) as usize
}

fn hdrlen(hdr: &[u8]) -> usize {
    u16::from_ne_bytes(hdr[16..18].try_into().unwrap()) as usize
}

#[test]
fn immediate_mode_is_accepted() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let fd = open_bpf("/dev/bpf0");
        // bpf(4): BIOCIMMEDIATE returns 0 on success; ethercrab always enables it.
        assert_eq!(immediate(fd), 0);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn buffer_length_is_at_least_an_mtu() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let fd = open_bpf("/dev/bpf0");
        // bpf(4): BIOCGBLEN reports the buffer a read() must supply; it bounds a whole MTU frame
        // plus the bpf_hdr.
        let n = blen(fd);
        assert!(n >= 1500 + BPF_HDRLEN as u32, "blen {n} fits a framed MTU");
        unsafe { libc::close(fd) };
    });
}

#[test]
fn biocgblen_null_pointer_is_efault() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let fd = open_bpf("/dev/bpf0");
        // A null result pointer cannot receive the length; ioctl(2) reports EFAULT for a bad
        // address argument.
        let rc = unsafe { libc::ioctl(fd, BIOCGBLEN, std::ptr::null_mut::<u32>()) };
        assert_eq!(rc, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EFAULT)
        );
        unsafe { libc::close(fd) };
    });
}

#[test]
fn frame_round_trips_between_two_devices() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let a = bound_device("en0", "/dev/bpf0");
        let b = bound_device("en0", "/dev/bpf1");
        let frame = ethercat_frame();

        let n = unsafe { libc::write(a, frame.as_ptr().cast(), frame.len()) };
        assert_eq!(n, frame.len() as isize, "the whole frame is written");

        let mut buf = vec![0u8; blen(b) as usize];
        let got = unsafe { libc::read(b, buf.as_mut_ptr().cast(), buf.len()) };
        assert!(got as usize >= BPF_HDRLEN, "at least a bpf_hdr is read");

        assert_eq!(caplen(&buf), frame.len(), "bh_caplen");
        assert_eq!(datalen(&buf), frame.len(), "bh_datalen");
        assert_eq!(caplen(&buf), datalen(&buf), "nothing truncated");
        assert_eq!(hdrlen(&buf), BPF_HDRLEN, "bh_hdrlen");
        assert_eq!(&buf[BPF_HDRLEN..BPF_HDRLEN + frame.len()], &frame[..]);

        unsafe {
            libc::close(a);
            libc::close(b);
        }
    });
}

#[test]
fn header_timestamp_is_deterministic_zero() {
    // The sim clock is virtual; bpf(4)'s bh_tstamp is filled from it, so a capture carries a stable
    // zero rather than a wall-clock time a test could not predict.
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let a = bound_device("en0", "/dev/bpf0");
        let b = bound_device("en0", "/dev/bpf1");
        let frame = ethercat_frame();
        unsafe { libc::write(a, frame.as_ptr().cast(), frame.len()) };

        let mut buf = vec![0u8; blen(b) as usize];
        let got = unsafe { libc::read(b, buf.as_mut_ptr().cast(), buf.len()) } as usize;
        assert!(got >= BPF_HDRLEN);
        assert_eq!(&buf[0..8], &[0u8; 8], "bh_tstamp is a deterministic zero");

        unsafe {
            libc::close(a);
            libc::close(b);
        }
    });
}

#[test]
fn sender_never_reads_its_own_frame() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let a = bound_device("en0", "/dev/bpf0");
        let _b = bound_device("en0", "/dev/bpf1");
        let frame = ethercat_frame();
        unsafe { libc::write(a, frame.as_ptr().cast(), frame.len()) };

        // The shared medium has no loopback: the writer sees nothing, and a non-blocking read on an
        // empty device is EAGAIN (read(2) / bpf(4)).
        let mut buf = vec![0u8; blen(a) as usize];
        let rc = unsafe { libc::read(a, buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(rc, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN)
        );
        unsafe { libc::close(a) };
    });
}

#[test]
fn nonblocking_read_on_empty_device_is_eagain() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let fd = bound_device("en0", "/dev/bpf0");
        let mut buf = vec![0u8; blen(fd) as usize];
        let rc = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(rc, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN)
        );
        unsafe { libc::close(fd) };
    });
}

#[test]
fn write_before_bind_is_einval() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        // An unbound device has no interface to transmit on; a write is rejected with EINVAL.
        let fd = open_bpf("/dev/bpf0");
        let frame = ethercat_frame();
        let rc = unsafe { libc::write(fd, frame.as_ptr().cast(), frame.len()) };
        assert_eq!(rc, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINVAL)
        );
        unsafe { libc::close(fd) };
    });
}

#[test]
fn biocsetif_unknown_interface_is_enxio() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let fd = open_bpf("/dev/bpf0");
        // bpf(4): BIOCSETIF on an interface that does not exist fails with ENXIO.
        let rc = bind(fd, "en9");
        assert_eq!(rc, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENXIO)
        );
        unsafe { libc::close(fd) };
    });
}

#[test]
fn devices_on_different_interfaces_do_not_cross_talk() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        add_nic(NicSpec::new("en1").index(5).mtu(1500)).unwrap();
        let a = bound_device("en0", "/dev/bpf0");
        let b = bound_device("en1", "/dev/bpf1");
        let frame = ethercat_frame();
        unsafe { libc::write(a, frame.as_ptr().cast(), frame.len()) };

        // b is on a different link; nothing is delivered to it.
        let mut buf = vec![0u8; blen(b) as usize];
        let rc = unsafe { libc::read(b, buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(rc, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN)
        );
        unsafe {
            libc::close(a);
            libc::close(b);
        }
    });
}

#[test]
fn a_short_read_truncates_the_frame_but_reports_full_caplen() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let a = bound_device("en0", "/dev/bpf0");
        let b = bound_device("en0", "/dev/bpf1");
        let frame = ethercat_frame();
        unsafe { libc::write(a, frame.as_ptr().cast(), frame.len()) };

        // read(2): a buffer smaller than the framed packet copies only what fits; bh_caplen still
        // records the full captured length.
        let mut buf = [0u8; BPF_HDRLEN + 10];
        let got = unsafe { libc::read(b, buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(got, buf.len() as isize, "read fills the short buffer");
        assert_eq!(
            caplen(&buf),
            frame.len(),
            "bh_caplen is the untruncated length"
        );
        assert_eq!(&buf[BPF_HDRLEN..], &frame[..10], "the first bytes survive");
        unsafe {
            libc::close(a);
            libc::close(b);
        }
    });
}

#[test]
fn distinct_device_paths_open_independently() {
    // Any /dev/bpfN path is accepted; the trailing minor is cosmetic in the sim.
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let a = bound_device("en0", "/dev/bpf3");
        let b = bound_device("en0", "/dev/bpf42");
        assert_ne!(a, b, "each open mints a distinct fd");
        let frame = ethercat_frame();
        unsafe { libc::write(a, frame.as_ptr().cast(), frame.len()) };
        let mut buf = vec![0u8; blen(b) as usize];
        let got = unsafe { libc::read(b, buf.as_mut_ptr().cast(), buf.len()) } as usize;
        assert_eq!(&buf[BPF_HDRLEN..BPF_HDRLEN + datalen(&buf)], &frame[..]);
        assert!(got >= BPF_HDRLEN);
        unsafe {
            libc::close(a);
            libc::close(b);
        }
    });
}

#[test]
fn two_frames_are_read_back_in_order() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let a = bound_device("en0", "/dev/bpf0");
        let b = bound_device("en0", "/dev/bpf1");

        let mut first = ethercat_frame();
        first[14] = 0x01;
        let mut second = ethercat_frame();
        second[14] = 0x02;
        unsafe {
            libc::write(a, first.as_ptr().cast(), first.len());
            libc::write(a, second.as_ptr().cast(), second.len());
        }

        // bpf(4): the read buffer is a FIFO of framed packets; two writes are two reads, in order.
        for expected in [0x01u8, 0x02] {
            let mut buf = vec![0u8; blen(b) as usize];
            let got = unsafe { libc::read(b, buf.as_mut_ptr().cast(), buf.len()) } as usize;
            assert!(got >= BPF_HDRLEN);
            assert_eq!(
                buf[BPF_HDRLEN + 14],
                expected,
                "command byte preserves order"
            );
        }
        unsafe {
            libc::close(a);
            libc::close(b);
        }
    });
}

#[test]
fn a_full_mtu_frame_survives_the_round_trip() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let a = bound_device("en0", "/dev/bpf0");
        let b = bound_device("en0", "/dev/bpf1");

        let mut frame = vec![0u8; 1514];
        for (i, byte) in frame.iter_mut().enumerate() {
            *byte = (i & 0xff) as u8;
        }
        frame[12] = 0x88;
        frame[13] = 0xa4;
        let n = unsafe { libc::write(a, frame.as_ptr().cast(), frame.len()) };
        assert_eq!(n, frame.len() as isize);

        let mut buf = vec![0u8; blen(b) as usize];
        let got = unsafe { libc::read(b, buf.as_mut_ptr().cast(), buf.len()) } as usize;
        assert_eq!(datalen(&buf), frame.len());
        assert_eq!(&buf[BPF_HDRLEN..BPF_HDRLEN + frame.len()], &frame[..]);
        assert_eq!(got, BPF_HDRLEN + frame.len());
        unsafe {
            libc::close(a);
            libc::close(b);
        }
    });
}
