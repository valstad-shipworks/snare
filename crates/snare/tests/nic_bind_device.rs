//! Binding a socket to an interface: Linux `SO_BINDTODEVICE`/`SO_BINDTOIFINDEX`, macOS
//! `IP_BOUND_IF`/`IPV6_BOUND_IF`, Windows `IP_UNICAST_IF`/`IPV6_UNICAST_IF`, and what the socket
//! table shows for it.

use std::io::ErrorKind;
use std::net::{IpAddr, UdpSocket};

use snare::{IpNet, NicSpec, Sim, socket_entry, socket_id};

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// eth0 10.0.0.1/24 (index 4) with station .2, eth1 10.1.0.1/24 (index 5) with station .2.
fn two_nics() -> Sim {
    Sim::builder()
        .nic(
            NicSpec::new("eth0")
                .index(4)
                .address(net("10.0.0.1/24"))
                .station(ip("10.0.0.2")),
        )
        .nic(
            NicSpec::new("eth1")
                .index(5)
                .address(net("10.1.0.1/24"))
                .station(ip("10.1.0.2")),
        )
        .build()
}

fn try_recv(sock: &UdpSocket) -> Option<Vec<u8>> {
    sock.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 64];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => Some(buf[..n].to_vec()),
        Err(e) if e.kind() == ErrorKind::WouldBlock => None,
        Err(e) => panic!("recv failed: {e}"),
    }
}

#[cfg(unix)]
mod opt {
    use std::io;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    pub fn set(sock: &UdpSocket, level: i32, name: i32, val: &[u8]) -> io::Result<()> {
        let rc = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                level,
                name,
                val.as_ptr().cast(),
                val.len() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn get(sock: &UdpSocket, level: i32, name: i32) -> Vec<u8> {
        let mut buf = [0u8; 32];
        let mut len = buf.len() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                sock.as_raw_fd(),
                level,
                name,
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt");
        buf[..len as usize].to_vec()
    }

    pub fn get_int(sock: &UdpSocket, level: i32, name: i32) -> i32 {
        i32::from_ne_bytes(get(sock, level, name)[..4].try_into().unwrap())
    }
}

#[cfg(windows)]
mod opt {
    use std::io;
    use std::net::UdpSocket;
    use std::os::windows::io::AsRawSocket;

    use windows_sys::Win32::Networking::WinSock::{WSAGetLastError, getsockopt, setsockopt};

    pub fn set(sock: &UdpSocket, level: i32, name: i32, val: &[u8]) -> io::Result<()> {
        let rc = unsafe {
            setsockopt(
                sock.as_raw_socket() as usize,
                level,
                name,
                val.as_ptr(),
                val.len() as i32,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
        }
    }

    pub fn get_int(sock: &UdpSocket, level: i32, name: i32) -> i32 {
        let mut buf = [0u8; 4];
        let mut len = 4i32;
        let rc = unsafe {
            getsockopt(
                sock.as_raw_socket() as usize,
                level,
                name,
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt");
        i32::from_ne_bytes(buf)
    }
}

/// Binds `sock` to interface `name` the way fast-talker's `bind_device` does on this OS.
fn bind_device(sock: &UdpSocket, name: &str) -> std::io::Result<()> {
    let index = snare::nic(name).map_or(999, |n| n.index);
    #[cfg(target_os = "linux")]
    {
        let _ = index;
        opt::set(
            sock,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_bytes(),
        )
    }
    #[cfg(target_os = "macos")]
    {
        opt::set(
            sock,
            libc::IPPROTO_IP,
            libc::IP_BOUND_IF,
            &(index as i32).to_ne_bytes(),
        )
    }
    #[cfg(windows)]
    {
        opt::set(sock, 0, 31, &index.to_be().to_ne_bytes())
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_so_bindtodevice_semantics() {
    const SO_BINDTOIFINDEX: i32 = 62;
    two_nics().run(|| {
        let s0 = UdpSocket::bind("10.0.0.2:7000").unwrap();
        let s1 = UdpSocket::bind("10.1.0.2:7000").unwrap();
        let sock = UdpSocket::bind("0.0.0.0:7001").unwrap();
        let err = opt::set(&sock, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, b"nope").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENODEV));
        assert!(opt::get(&sock, libc::SOL_SOCKET, libc::SO_BINDTODEVICE).is_empty());
        opt::set(&sock, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, b"eth1\0").unwrap();
        assert_eq!(
            opt::get(&sock, libc::SOL_SOCKET, libc::SO_BINDTODEVICE),
            b"eth1\0"
        );
        assert_eq!(opt::get_int(&sock, libc::SOL_SOCKET, SO_BINDTOIFINDEX), 5);

        sock.send_to(b"on-link", "10.0.0.2:7000").unwrap();
        assert!(
            try_recv(&s0).is_none(),
            "left through eth1, not eth0's segment"
        );
        sock.send_to(b"eth1", "10.1.0.2:7000").unwrap();
        assert_eq!(try_recv(&s1).unwrap(), b"eth1");

        s0.send_to(b"via eth0", "10.0.0.1:7001").unwrap();
        assert!(try_recv(&sock).is_none(), "arrived on another interface");
        let local = UdpSocket::bind("127.0.0.1:0").unwrap();
        local.send_to(b"via lo", "127.0.0.1:7001").unwrap();
        assert!(
            try_recv(&sock).is_none(),
            "host-local traffic arrives on lo"
        );
        s1.send_to(b"via eth1", "10.1.0.1:7001").unwrap();
        assert_eq!(try_recv(&sock).unwrap(), b"via eth1");

        opt::set(&sock, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, b"").unwrap();
        assert!(opt::get(&sock, libc::SOL_SOCKET, libc::SO_BINDTODEVICE).is_empty());
        let err = opt::set(
            &sock,
            libc::SOL_SOCKET,
            SO_BINDTOIFINDEX,
            &99i32.to_ne_bytes(),
        )
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENODEV));
        opt::set(
            &sock,
            libc::SOL_SOCKET,
            SO_BINDTOIFINDEX,
            &5i32.to_ne_bytes(),
        )
        .unwrap();
        assert_eq!(
            opt::get(&sock, libc::SOL_SOCKET, libc::SO_BINDTODEVICE),
            b"eth1\0"
        );

        snare::set_nic("eth1", |spec| spec.admin_up = false).unwrap();
        let err = sock.send_to(b"down", "10.1.0.2:7000").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENETUNREACH));
    });
}

#[cfg(target_os = "macos")]
#[test]
fn macos_ip_bound_if_semantics() {
    two_nics().run(|| {
        let s1 = UdpSocket::bind("10.1.0.2:7000").unwrap();
        let sock = UdpSocket::bind("0.0.0.0:7001").unwrap();
        let err = opt::set(
            &sock,
            libc::IPPROTO_IP,
            libc::IP_BOUND_IF,
            &99i32.to_ne_bytes(),
        )
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENXIO));
        opt::set(
            &sock,
            libc::IPPROTO_IP,
            libc::IP_BOUND_IF,
            &5i32.to_ne_bytes(),
        )
        .unwrap();
        assert_eq!(opt::get_int(&sock, libc::IPPROTO_IP, libc::IP_BOUND_IF), 5);

        sock.send_to(b"eth1", "10.1.0.2:7000").unwrap();
        assert_eq!(try_recv(&s1).unwrap(), b"eth1");
        let err = sock.send_to(b"miss", "10.0.0.2:7000").unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ENETUNREACH),
            "scoped routes only"
        );

        let s0 = UdpSocket::bind("10.0.0.2:7002").unwrap();
        s0.send_to(b"via eth0", "10.0.0.1:7001").unwrap();
        assert!(try_recv(&sock).is_none(), "arrived on another interface");

        snare::set_nic("eth1", |spec| spec.admin_up = false).unwrap();
        let err = sock.send_to(b"down", "10.1.0.2:7000").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENETDOWN));
        opt::set(
            &sock,
            libc::IPPROTO_IP,
            libc::IP_BOUND_IF,
            &0i32.to_ne_bytes(),
        )
        .unwrap();
        assert_eq!(opt::get_int(&sock, libc::IPPROTO_IP, libc::IP_BOUND_IF), 0);
    });
}

#[cfg(windows)]
#[test]
fn windows_ip_unicast_if_semantics() {
    const IPPROTO_IP: i32 = 0;
    const IP_UNICAST_IF: i32 = 31;
    two_nics().run(|| {
        let s0 = UdpSocket::bind("10.0.0.2:7000").unwrap();
        let s1 = UdpSocket::bind("10.1.0.2:7000").unwrap();
        let sock = UdpSocket::bind("0.0.0.0:7001").unwrap();
        let err = opt::set(
            &sock,
            IPPROTO_IP,
            IP_UNICAST_IF,
            &99u32.to_be().to_ne_bytes(),
        )
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(10022));
        opt::set(
            &sock,
            IPPROTO_IP,
            IP_UNICAST_IF,
            &5u32.to_be().to_ne_bytes(),
        )
        .unwrap();
        assert_eq!(
            opt::get_int(&sock, IPPROTO_IP, IP_UNICAST_IF) as u32,
            5u32.to_be()
        );
        sock.send_to(b"eth1", "10.1.0.2:7000").unwrap();
        assert_eq!(try_recv(&s1).unwrap(), b"eth1");
        sock.send_to(b"on-link", "10.0.0.2:7000").unwrap();
        assert!(try_recv(&s0).is_none(), "left through eth1");
        s0.send_to(b"in", "10.0.0.1:7001").unwrap();
        assert_eq!(try_recv(&sock).unwrap(), b"in", "unicast sends only");
    });
}

#[test]
fn fast_talker_bind_device_path() {
    two_nics().run(|| {
        let s1 = UdpSocket::bind("10.1.0.2:7100").unwrap();
        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        bind_device(&sock, "eth1").unwrap();
        sock.send_to(b"rt", "10.1.0.2:7100").unwrap();
        assert_eq!(try_recv(&s1).unwrap(), b"rt");
        assert!(bind_device(&sock, "nope0").is_err());
    });
}

#[test]
fn socket_entry_shows_interface_and_bound_device() {
    two_nics().run(|| {
        let s0 = UdpSocket::bind("10.0.0.2:7200").unwrap();
        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        let id = socket_id(&sock).unwrap();
        let entry = socket_entry(id).unwrap();
        assert_eq!((entry.interface, entry.bound_device), (None, None));
        sock.send_to(b"x", "10.0.0.2:7200").unwrap();
        assert_eq!(socket_entry(id).unwrap().interface.as_deref(), Some("eth0"));
        bind_device(&sock, "eth1").unwrap();
        let entry = socket_entry(id).unwrap();
        assert_eq!(entry.bound_device.as_deref(), Some("eth1"));
        assert_eq!(entry.multicast_if, None);
        let rx = socket_id(&s0).unwrap();
        assert_eq!(
            socket_entry(rx).unwrap().interface,
            None,
            "a station socket"
        );
        let host = UdpSocket::bind("10.1.0.1:0").unwrap();
        let s1 = UdpSocket::bind("10.1.0.2:0").unwrap();
        s1.send_to(b"y", host.local_addr().unwrap()).unwrap();
        let host_id = socket_id(&host).unwrap();
        assert_eq!(
            socket_entry(host_id).unwrap().interface.as_deref(),
            Some("eth1")
        );
    });
}

#[test]
fn set_socket_device_from_the_test() {
    let sim = two_nics();
    sim.run(|| {
        let s1 = UdpSocket::bind("10.1.0.2:7300").unwrap();
        let s0 = UdpSocket::bind("10.0.0.2:7300").unwrap();
        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        let id = socket_id(&sock).unwrap();
        snare::set_socket_device(id, Some("eth1")).unwrap();
        assert_eq!(
            socket_entry(id).unwrap().bound_device.as_deref(),
            Some("eth1")
        );
        sock.send_to(b"eth1", "10.1.0.2:7300").unwrap();
        assert_eq!(try_recv(&s1).unwrap(), b"eth1");
        #[cfg(target_os = "linux")]
        assert_eq!(
            opt::get(&sock, libc::SOL_SOCKET, libc::SO_BINDTODEVICE),
            b"eth1\0"
        );
        #[cfg(target_os = "macos")]
        assert_eq!(opt::get_int(&sock, libc::IPPROTO_IP, libc::IP_BOUND_IF), 5);
        let err = snare::set_socket_device(id, Some("nope0")).unwrap_err();
        let expect = if cfg!(target_os = "linux") {
            19
        } else if cfg!(target_os = "macos") {
            6
        } else {
            10022
        };
        assert_eq!(
            err.raw_os_error(),
            Some(expect),
            "ENODEV / ENXIO / WSAEINVAL"
        );
        snare::set_socket_device(id, None).unwrap();
        assert_eq!(socket_entry(id).unwrap().bound_device, None);
        sock.send_to(b"routed", "10.0.0.2:7300").unwrap();
        assert_eq!(try_recv(&s0).unwrap(), b"routed");
        drop(sock);
        let err = snare::set_socket_device(id, Some("eth1")).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
    });
    let sock_id = sim.run(|| {
        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        let id = socket_id(&sock).unwrap();
        std::mem::forget(sock);
        id
    });
    sim.set_socket_device(sock_id, Some("eth0")).unwrap();
    assert_eq!(
        sim.socket_entry(sock_id).unwrap().bound_device.as_deref(),
        Some("eth0")
    );
}

#[test]
fn last_tx_and_rx_interfaces() {
    two_nics().run(|| {
        let s1 = UdpSocket::bind("10.1.0.2:7400").unwrap();
        let sock = UdpSocket::bind("0.0.0.0:7401").unwrap();
        let id = socket_id(&sock).unwrap();
        sock.send_to(b"out", "10.1.0.2:7400").unwrap();
        let entry = socket_entry(id).unwrap();
        assert_eq!(entry.last_tx_nic.as_deref(), Some("eth1"));
        assert_eq!(entry.last_rx_nic, None);
        let s0 = UdpSocket::bind("10.0.0.2:7400").unwrap();
        s0.send_to(b"in", "10.0.0.1:7401").unwrap();
        let entry = socket_entry(id).unwrap();
        assert_eq!(
            (entry.last_tx_nic.as_deref(), entry.last_rx_nic.as_deref()),
            (Some("eth1"), Some("eth0"))
        );
        assert_eq!(
            entry.interface.as_deref(),
            Some("eth0"),
            "the latest either way"
        );
        sock.send_to(b"repeat", "10.1.0.2:7400").unwrap();
        let entry = socket_entry(id).unwrap();
        assert_eq!(entry.interface.as_deref(), Some("eth1"));
        assert_eq!(entry.last_tx_nic.as_deref(), Some("eth1"));
        assert_eq!(entry.last_rx_nic.as_deref(), Some("eth0"));
        sock.send_to(b"changed", "10.0.0.2:7400").unwrap();
        let entry = socket_entry(id).unwrap();
        assert_eq!(entry.interface.as_deref(), Some("eth0"));
        assert_eq!(entry.last_tx_nic.as_deref(), Some("eth0"));
        assert_eq!(entry.last_rx_nic.as_deref(), Some("eth0"));
        s1.send_to(b"reverse", "10.1.0.1:7401").unwrap();
        let entry = socket_entry(id).unwrap();
        assert_eq!(entry.interface.as_deref(), Some("eth1"));
        assert_eq!(entry.last_tx_nic.as_deref(), Some("eth0"));
        assert_eq!(entry.last_rx_nic.as_deref(), Some("eth1"));
        drop(s1);

        let listener = std::net::TcpListener::bind("10.1.0.1:7402").unwrap();
        let client = std::net::TcpStream::connect("10.1.0.1:7402").unwrap();
        let (server, _) = listener.accept().unwrap();
        let lo = snare::nics()
            .into_iter()
            .find(|n| n.loopback)
            .unwrap()
            .spec
            .name;
        for s in [&client, &server] {
            let e = socket_entry(socket_id(s).unwrap()).unwrap();
            assert_eq!(e.last_tx_nic.as_deref(), Some(lo.as_str()));
            assert_eq!(e.last_rx_nic.as_deref(), Some(lo.as_str()));
        }
    });
}
