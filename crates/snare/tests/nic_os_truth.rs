//! Routing error codes measured against the real OS of the build host: each test makes the same
//! call on a real socket (under `snare::real`) and on a simulated one, and requires the same
//! outcome.

use std::io;
use std::net::{IpAddr, UdpSocket};

use snare::{IpNet, NicSpec, Sim};

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// A routed sim whose default route leaves through `sim0`, like a host with one uplink.
fn routed() -> Sim {
    Sim::builder()
        .nic(
            NicSpec::new("eth0")
                .index(4)
                .address(net("10.0.0.1/24"))
                .station(ip("10.0.0.2")),
        )
        .nic(NicSpec::new("eth1").index(5).address(net("10.1.0.1/24")))
        .build()
}

fn outcome(result: io::Result<usize>) -> Option<i32> {
    result.err().map(|e| e.raw_os_error().expect("an OS error"))
}

/// A datagram from a socket bound to `127.0.0.1` toward a TEST-NET-1 address (RFC 5737).
fn loopback_source_send() -> io::Result<usize> {
    let sock = UdpSocket::bind("127.0.0.1:0")?;
    sock.send_to(b"x", "192.0.2.1:9")
}

#[test]
fn loopback_source_off_host_matches_real_os() {
    let real = outcome(snare::real(loopback_source_send));
    let sim = outcome(routed().run(loopback_source_send));
    assert!(
        real.is_some(),
        "the real OS refuses a loopback source leaving the host"
    );
    assert_eq!(sim, real);
}

#[cfg(target_os = "macos")]
fn bind_to_loopback(sock: &UdpSocket) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let index: i32 = 1;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_BOUND_IF,
            (&index as *const i32).cast(),
            4,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn bind_to_loopback(sock: &UdpSocket) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            b"lo".as_ptr().cast(),
            2,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// A wildcard socket bound to the loopback interface sends to a TEST-NET-1 address no route on
/// that interface covers: macOS scoped routing refuses it, Linux assumes it is on-link.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn bound_if_send() -> io::Result<usize> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    bind_to_loopback(&sock)?;
    sock.send_to(b"x", "192.0.2.1:9")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn bound_if_scope_miss_matches_real_os() {
    let real = outcome(snare::real(bound_if_send));
    let sim = outcome(routed().run(bound_if_send));
    assert_eq!(sim, real);
}

#[cfg(target_os = "linux")]
fn sh(cmd: &str) {
    let status = std::process::Command::new("sh")
        .args(["-c", cmd])
        .status()
        .expect("sh");
    assert!(status.success(), "{cmd}");
}

/// A private network namespace with iproute2: a dummy interface taken down keeps its address
/// bindable but withdraws its routes.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs CAP_SYS_ADMIN, CAP_NET_ADMIN and iproute2; creates a private network namespace"]
fn linux_netns_ground_truth() {
    let probe = || {
        let bind = UdpSocket::bind("10.77.0.1:0").map(|_| 0usize);
        let send = UdpSocket::bind("0.0.0.0:0").and_then(|s| s.send_to(b"x", "10.77.0.2:9"));
        (outcome(bind), outcome(send))
    };
    snare::real(|| {
        assert_eq!(
            unsafe { libc::unshare(libc::CLONE_NEWNET) },
            0,
            "{}",
            io::Error::last_os_error()
        );
        sh("ip link add dummy0 type dummy");
        sh("ip addr add 10.77.0.1/24 dev dummy0");
        sh("ip link set dummy0 up");
    });
    let real_up = snare::real(probe);
    snare::real(|| sh("ip link set dummy0 down"));
    let real_down = snare::real(probe);
    snare::real(|| sh("ip link del dummy0"));

    let sim = Sim::builder()
        .nic(NicSpec::new("dummy0").address(net("10.77.0.1/24")))
        .build();
    sim.set_default_route(None).unwrap();
    let sim_up = sim.run(probe);
    sim.set_nic("dummy0", |spec| spec.admin_up = false).unwrap();
    let sim_down = sim.run(probe);
    assert_eq!(sim_up, real_up);
    assert_eq!(sim_down, real_down);
    assert_eq!(real_down, (None, Some(libc::ENETUNREACH)));
}

/// Windows is a strong host: a source address leaves only through its own interface. The real
/// loopback-source send is that same violation on the build host, so both report one code; a
/// carrier-less interface's routes are withdrawn (media sense) and give WSAENETUNREACH.
#[cfg(windows)]
#[test]
fn windows_strong_host_and_media_sense() {
    let real = outcome(snare::real(loopback_source_send));
    let sim = routed();
    let strong = outcome(sim.run(|| {
        let sock = UdpSocket::bind("10.1.0.1:0")?;
        sock.send_to(b"x", "10.0.0.2:9")
    }));
    assert_eq!(strong, real);
    sim.set_link("eth0", false).unwrap();
    let media = outcome(sim.run(|| {
        sim_default_off();
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.send_to(b"x", "10.0.0.2:9")
    }));
    assert_eq!(media, Some(10051));
    let bind = sim.run(|| UdpSocket::bind("10.0.0.1:0").map(|_| 0usize));
    assert_eq!(outcome(bind), Some(10049));
}

#[cfg(windows)]
fn sim_default_off() {
    snare::set_default_route(None).unwrap();
}

/// The shape `GetAdaptersAddresses` hands back, as a caller that does not know the machine sees
/// it: the `ERROR_BUFFER_OVERFLOW` size handshake (with no buffer, then with one too short),
/// `ERROR_INVALID_PARAMETER` for a family other than `AF_UNSPEC`, `AF_INET` and `AF_INET6`, the
/// `Length` of each adapter and unicast record, and a software-loopback adapter (`IfType` 24),
/// up, without a hardware address, holding `127.0.0.1`
/// ([Microsoft Learn: GetAdaptersAddresses](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses),
/// [IP_ADAPTER_ADDRESSES_LH](https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh)).
#[cfg(windows)]
fn adapters_shape() -> Vec<(&'static str, u64)> {
    use std::net::Ipv4Addr;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR_IN};
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    const IF_OPER_STATUS_UP: i32 = 1;

    let mut size = 0u32;
    let unsized_rc = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    let mut short_buf = [0u64; 4];
    let mut short = 32u32;
    let short_rc = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            0,
            std::ptr::null(),
            short_buf.as_mut_ptr().cast(),
            &mut short,
        )
    };
    let mut probe = 0u32;
    let family_rc =
        unsafe { GetAdaptersAddresses(5, 0, std::ptr::null(), std::ptr::null_mut(), &mut probe) };
    let mut size = size.max(short) + 4096;
    let mut buf = vec![0u64; size as usize / 8 + 1];
    let rc = unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            0,
            std::ptr::null(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    };
    let mut lengths_ok = true;
    let mut loopback = 0u64;
    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while rc == 0 && !cur.is_null() {
        let a = unsafe { &*cur };
        lengths_ok &= unsafe { a.Anonymous1.Anonymous.Length } as usize
            == size_of::<IP_ADAPTER_ADDRESSES_LH>();
        let mut addrs = Vec::new();
        let mut u = a.FirstUnicastAddress;
        while !u.is_null() {
            let entry = unsafe { &*u };
            lengths_ok &= unsafe { entry.Anonymous.Anonymous.Length } as usize
                == size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>();
            let sa = entry.Address.lpSockaddr as *const SOCKADDR_IN;
            addrs.push(Ipv4Addr::from(
                unsafe { (*sa).sin_addr.S_un.S_addr }.to_ne_bytes(),
            ));
            u = entry.Next;
        }
        if a.IfType == IF_TYPE_SOFTWARE_LOOPBACK
            && a.OperStatus == IF_OPER_STATUS_UP
            && a.PhysicalAddressLength == 0
            && addrs.contains(&Ipv4Addr::LOCALHOST)
        {
            loopback += 1;
        }
        cur = a.Next;
    }
    vec![
        ("no buffer", u64::from(unsized_rc)),
        ("sized", u64::from(size > 0)),
        ("short buffer", u64::from(short_rc)),
        ("short buffer asks for a size", u64::from(short > 32)),
        ("family 5", u64::from(family_rc)),
        ("AF_INET listing", u64::from(rc)),
        ("record lengths", u64::from(lengths_ok)),
        ("loopback adapters", loopback),
    ]
}

#[cfg(windows)]
#[test]
fn adapters_addresses_shape_matches_real_os() {
    let real = snare::real(adapters_shape);
    let sim = Sim::new().run(adapters_shape);
    assert_eq!(real[0], ("no buffer", 111));
    assert_eq!(real[7], ("loopback adapters", 1));
    assert_eq!(sim, real);
}
