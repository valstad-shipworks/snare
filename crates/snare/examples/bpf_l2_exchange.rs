//! A two-station raw-L2 exchange over the simulated `/dev/bpf*` device, the way ethercrab's macOS
//! transport talks to the wire. Run with `cargo run -p snare --example bpf_l2_exchange`.
//!
//! bpf(4): open `/dev/bpfN`, enable immediate mode (BIOCIMMEDIATE), bind to an interface
//! (BIOCSETIF), then write raw Ethernet frames and read them back framed with a `struct bpf_hdr`.

#[cfg(target_os = "macos")]
fn main() {
    use snare::{Sim, add_interface};

    const BIOCSETIF: libc::c_ulong = 0x8020_426c;
    const BIOCIMMEDIATE: libc::c_ulong = 0x8004_4270;
    const BIOCGBLEN: libc::c_ulong = 0x4004_4266;
    const BPF_HDRLEN: usize = 18; // BPF_WORDALIGN(sizeof(bpf_hdr)) before the frame.

    Sim::new().run(|| {
        add_interface("en0", 4, 1500);

        let open = |dev: &str| {
            let path = std::ffi::CString::new(dev).unwrap();
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
            assert!(fd >= 0, "open {dev}");
            let mut on: u32 = 1;
            assert_eq!(unsafe { libc::ioctl(fd, BIOCIMMEDIATE, &mut on) }, 0);
            let mut ifr: [u8; 32] = [0; 32];
            ifr[..3].copy_from_slice(b"en0");
            assert_eq!(unsafe { libc::ioctl(fd, BIOCSETIF, ifr.as_mut_ptr()) }, 0);
            fd
        };

        let a = open("/dev/bpf0");
        let b = open("/dev/bpf1");

        let mut blen: u32 = 0;
        assert_eq!(unsafe { libc::ioctl(a, BIOCGBLEN, &mut blen) }, 0);

        let mut frame = [0u8; 60];
        frame[12] = 0x88; // EtherCAT ethertype 0x88a4
        frame[13] = 0xa4;
        frame[14] = 0x42;
        let written = unsafe { libc::write(a, frame.as_ptr().cast(), frame.len()) };
        assert_eq!(written, frame.len() as isize);

        let mut buf = vec![0u8; blen as usize];
        let got = unsafe { libc::read(b, buf.as_mut_ptr().cast(), buf.len()) } as usize;
        let datalen = u32::from_ne_bytes(buf[12..16].try_into().unwrap()) as usize;

        assert_eq!(&buf[BPF_HDRLEN..BPF_HDRLEN + datalen], &frame[..]);
        println!(
            "bpf: wrote {written} bytes on en0, read {got} back ({datalen}-byte frame, ethertype 0x{:02x}{:02x})",
            buf[BPF_HDRLEN + 12],
            buf[BPF_HDRLEN + 13],
        );

        unsafe {
            libc::close(a);
            libc::close(b);
        }
    });
}

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("bpf_l2_exchange: /dev/bpf raw L2 is a macOS-only example");
}
