#![cfg(target_os = "linux")]
//! AF_PACKET raw L2 (ethercrab's default Linux transport): socket(AF_PACKET, SOCK_RAW) +
//! ioctl(SIOCGIFINDEX) to resolve the interface by name + bind(sockaddr_ll) + read/write whole
//! frames. Frames cross a virtual per-interface bus, never the real NIC.

use snare::Sim;

fn open_on(name: &str) -> i32 {
    let proto: u16 = 0x88A4; // EtherCAT ethertype
    unsafe {
        let fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK,
            i32::from((proto).to_be()),
        );
        assert!(fd >= 0, "socket(AF_PACKET) = {fd}");

        let mut ifreq: libc::ifreq = std::mem::zeroed();
        let bytes = name.as_bytes();
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr().cast(),
            ifreq.ifr_name.as_mut_ptr(),
            bytes.len(),
        );
        assert_eq!(
            libc::ioctl(fd, libc::SIOCGIFINDEX, &mut ifreq),
            0,
            "SIOCGIFINDEX"
        );
        let ifindex = std::ptr::read_unaligned(
            (&ifreq as *const libc::ifreq as *const u8)
                .add(16)
                .cast::<i32>(),
        );

        let mut sll: libc::sockaddr_ll = std::mem::zeroed();
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = proto.to_be();
        sll.sll_ifindex = ifindex;
        assert_eq!(
            libc::bind(
                fd,
                (&sll as *const libc::sockaddr_ll).cast(),
                size_of::<libc::sockaddr_ll>() as u32
            ),
            0,
            "bind(sockaddr_ll)"
        );
        fd
    }
}

#[test]
fn af_packet_frames_cross_the_virtual_bus() {
    let sim = Sim::new();
    sim.run(|| {
        snare::add_nic(snare::NicSpec::new("sneth0").index(7).mtu(1500)).unwrap();
        let a = open_on("sneth0");
        let b = open_on("sneth0");

        let frame: &[u8] = b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x01\x88\xa4ECAT-PDU";
        let sent = unsafe { libc::write(a, frame.as_ptr().cast(), frame.len()) };
        assert_eq!(sent, frame.len() as isize, "write frame");

        let mut buf = [0u8; 128];
        let got = unsafe { libc::read(b, buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(got, frame.len() as isize, "peer receives the frame");
        assert_eq!(&buf[..got as usize], frame);

        // No loopback: the sender does not receive its own frame.
        let self_rx = unsafe { libc::read(a, buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(self_rx, -1, "sender sees no loopback (EAGAIN)");

        unsafe {
            libc::close(a);
            libc::close(b);
        }
    });
}

#[test]
fn unknown_interface_is_enodev() {
    let sim = Sim::new();
    sim.run(|| {
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
        assert!(fd >= 0);
        let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
        let name = b"nope0";
        unsafe {
            std::ptr::copy_nonoverlapping(
                name.as_ptr().cast(),
                ifreq.ifr_name.as_mut_ptr(),
                name.len(),
            )
        };
        let r = unsafe { libc::ioctl(fd, libc::SIOCGIFINDEX, &mut ifreq) };
        assert_eq!(r, -1, "unknown interface fails");
        unsafe { libc::close(fd) };
    });
}

#[test]
fn duplicated_packet_socket_survives_original_close_os_truth() {
    let probe = || {
        let sender = open_on("lo");
        let original = open_on("lo");
        let receiver = unsafe { libc::dup(original) };
        assert!(receiver >= 0);
        assert_eq!(unsafe { libc::fcntl(receiver, libc::F_SETFL, 0) }, 0);
        let shared_blocking =
            unsafe { libc::fcntl(original, libc::F_GETFL) } & libc::O_NONBLOCK == 0;
        assert_eq!(unsafe { libc::close(original) }, 0);
        let frame: &[u8] =
            b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x01\x88\xa4duplicate raw endpoint";
        assert_eq!(
            unsafe { libc::write(sender, frame.as_ptr().cast(), frame.len()) },
            frame.len() as isize
        );
        let mut pfd = libc::pollfd {
            fd: receiver,
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut pfd, 1, 1000) }, 1);
        let mut bytes = [0; 128];
        let n = unsafe { libc::read(receiver, bytes.as_mut_ptr().cast(), bytes.len()) };
        assert!(n > 0);
        unsafe {
            libc::close(sender);
            libc::close(receiver);
        }
        (shared_blocking, bytes[..n as usize].to_vec())
    };
    let real = probe();
    assert!(real.0);
    assert_eq!(Sim::new().run(probe), real);
}

#[test]
fn sending_through_a_packet_alias_excludes_its_own_receive_queue() {
    Sim::new().run(|| {
        snare::add_nic(snare::NicSpec::new("sneth0").index(7).mtu(1500)).unwrap();
        let original = open_on("sneth0");
        let copy = unsafe { libc::dup(original) };
        assert!(copy >= 0);
        let other = open_on("sneth0");
        let frame: &[u8] = b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x01\x88\xa4alias sender";
        assert_eq!(
            unsafe { libc::write(copy, frame.as_ptr().cast(), frame.len()) },
            frame.len() as isize
        );
        let mut bytes = [0; 128];
        assert_eq!(
            unsafe { libc::read(original, bytes.as_mut_ptr().cast(), bytes.len()) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN)
        );
        assert_eq!(
            unsafe { libc::read(other, bytes.as_mut_ptr().cast(), bytes.len()) },
            frame.len() as isize
        );
        unsafe {
            libc::close(original);
            libc::close(copy);
            libc::close(other);
        }
    });
}
