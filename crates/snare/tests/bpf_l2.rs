#![cfg(target_os = "macos")]

use snare::{NicSpec, Sim, add_nic};

const BIOCSETIF: libc::c_ulong = 0x8020_426c;
const BIOCIMMEDIATE: libc::c_ulong = 0x8004_4270;
const BIOCGBLEN: libc::c_ulong = 0x4004_4266;
const BPF_HDRLEN: usize = 18;

/// Open a BPF device and bind it to `iface`, exactly as ethercrab's macOS transport does.
fn open_bpf(iface: &str) -> i32 {
    let path = std::ffi::CString::new("/dev/bpf0").unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    assert!(fd >= 0, "open /dev/bpf0");

    let mut on: u32 = 1;
    let rc = unsafe { libc::ioctl(fd, BIOCIMMEDIATE, &mut on) };
    assert_eq!(rc, 0, "BIOCIMMEDIATE");

    let mut ifr: [u8; 32] = [0; 32];
    ifr[..iface.len()].copy_from_slice(iface.as_bytes());
    let rc = unsafe { libc::ioctl(fd, BIOCSETIF, ifr.as_mut_ptr()) };
    assert_eq!(rc, 0, "BIOCSETIF");
    fd
}

#[test]
fn two_bpf_devices_exchange_a_frame() {
    let sim = Sim::new();
    sim.run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let a = open_bpf("en0");
        let b = open_bpf("en0");

        let mut blen: u32 = 0;
        let rc = unsafe { libc::ioctl(a, BIOCGBLEN, &mut blen) };
        assert_eq!(rc, 0);
        assert!(blen >= 1500, "buffer length is at least an MTU, got {blen}");

        // A writes a minimal EtherCAT frame (dst, src, ethertype 0x88a4, payload).
        let mut frame = [0u8; 60];
        frame[12] = 0x88;
        frame[13] = 0xa4;
        frame[14] = 0x42;
        let n = unsafe { libc::write(a, frame.as_ptr() as *const libc::c_void, frame.len()) };
        assert_eq!(n, frame.len() as isize, "write the frame");

        // B reads it, framed with a bpf_hdr.
        let mut buf = vec![0u8; blen as usize];
        let got = unsafe { libc::read(b, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        assert!(got as usize >= BPF_HDRLEN, "read at least a bpf_hdr");

        let caplen = u32::from_ne_bytes(buf[8..12].try_into().unwrap()) as usize;
        let datalen = u32::from_ne_bytes(buf[12..16].try_into().unwrap()) as usize;
        assert_eq!(caplen, datalen);
        assert_eq!(datalen, frame.len(), "frame length in the bpf header");
        assert_eq!(
            &buf[BPF_HDRLEN..BPF_HDRLEN + datalen],
            &frame[..],
            "frame bytes"
        );

        // A does not receive its own frame (no loopback on the shared medium).
        let mut buf2 = vec![0u8; blen as usize];
        let rc = unsafe { libc::read(a, buf2.as_mut_ptr() as *mut libc::c_void, buf2.len()) };
        assert_eq!(rc, -1, "nothing to read on the sender");
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
fn biocsetif_unknown_interface_errors() {
    let sim = Sim::new();
    sim.run(|| {
        let path = std::ffi::CString::new("/dev/bpf0").unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
        assert!(fd >= 0);
        let mut ifr: [u8; 32] = [0; 32];
        ifr[..4].copy_from_slice(b"en9\0");
        let rc = unsafe { libc::ioctl(fd, BIOCSETIF, ifr.as_mut_ptr()) };
        assert_eq!(rc, -1, "unknown interface is rejected");
        unsafe { libc::close(fd) };
    });
}

#[test]
fn duplicated_bpf_device_keeps_interface_and_shared_receive_queue() {
    Sim::new().run(|| {
        add_nic(NicSpec::new("en0").index(4).mtu(1500)).unwrap();
        let sender = open_bpf("en0");
        let original = open_bpf("en0");
        let copy = unsafe { libc::dup(original) };
        assert!(copy >= 0);
        assert_eq!(unsafe { libc::close(original) }, 0);
        let mut frame = [0u8; 60];
        frame[12] = 0x88;
        frame[13] = 0xa4;
        frame[14] = 0x42;
        assert_eq!(
            unsafe { libc::write(sender, frame.as_ptr().cast(), frame.len()) },
            frame.len() as isize
        );
        let mut bytes = [0; 4096];
        let n = unsafe { libc::read(copy, bytes.as_mut_ptr().cast(), bytes.len()) };
        assert!(n as usize >= BPF_HDRLEN + frame.len());
        assert_eq!(&bytes[BPF_HDRLEN..BPF_HDRLEN + frame.len()], frame);
        unsafe {
            libc::close(sender);
            libc::close(copy);
        }
    });
}
