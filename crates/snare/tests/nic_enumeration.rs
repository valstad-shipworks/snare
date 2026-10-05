//! Interface enumeration answers from the sim's topology: the name/index calls, `getifaddrs`, the
//! `SIOCGIF*` ioctls and the counters, all following `set_link` / `set_nic_counters`.

use std::net::{IpAddr, UdpSocket};

use snare::{IpNet, NicSpec, Sim};

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn sim() -> Sim {
    Sim::builder()
        .nic(
            NicSpec::new("eth0")
                .index(4)
                .address(net("10.0.0.1/24"))
                .address(net("fd00::1/64"))
                .station(ip("10.0.0.2"))
                .mtu(9000),
        )
        .nic(NicSpec::new("eth1").index(7).address(net("10.1.0.1/16")))
        .build()
}

#[cfg(unix)]
fn loopback() -> &'static str {
    if cfg!(target_os = "linux") {
        "lo"
    } else {
        "lo0"
    }
}

#[cfg(unix)]
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

#[cfg(unix)]
fn name_to_index(name: &str) -> (u32, i32) {
    let c = std::ffi::CString::new(name).unwrap();
    let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (index, if index == 0 { errno() } else { 0 })
}

#[cfg(unix)]
fn index_to_name(index: u32) -> Result<String, i32> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    let p = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if p.is_null() {
        return Err(errno());
    }
    Ok(unsafe { std::ffi::CStr::from_ptr(p) }
        .to_string_lossy()
        .into_owned())
}

#[cfg(unix)]
fn name_index() -> Vec<(u32, String)> {
    let list = unsafe { libc::if_nameindex() };
    assert!(!list.is_null());
    let mut out = Vec::new();
    let mut at = list;
    unsafe {
        while (*at).if_index != 0 {
            let name = std::ffi::CStr::from_ptr((*at).if_name)
                .to_string_lossy()
                .into_owned();
            out.push(((*at).if_index, name));
            at = at.add(1);
        }
        libc::if_freenameindex(list);
    }
    out
}

#[cfg(unix)]
#[test]
fn if_nametoindex_indextoname_nameindex_roundtrip() {
    sim().run(|| {
        assert_eq!(name_to_index("eth0"), (4, 0));
        assert_eq!(name_to_index("eth1"), (7, 0));
        assert_eq!(name_to_index(loopback()).0, 1);
        assert_eq!(index_to_name(4).as_deref(), Ok("eth0"));
        assert_eq!(index_to_name(1).as_deref(), Ok(loopback()));
        let list = name_index();
        assert_eq!(
            list,
            vec![
                (1, loopback().to_string()),
                (2, "sim0".to_string()),
                (4, "eth0".to_string()),
                (7, "eth1".to_string()),
            ]
        );
        for (index, name) in list {
            assert_eq!(name_to_index(&name).0, index);
            assert_eq!(index_to_name(index), Ok(name));
        }
    });
}

#[cfg(unix)]
#[test]
fn unknown_names_os_truth() {
    let unknown = "snarenope0";
    let real_name = snare::real(|| name_to_index(unknown));
    let real_index = snare::real(|| index_to_name(0x7fff_fff0));
    let (sim_name, sim_index) = sim().run(|| (name_to_index(unknown), index_to_name(0x7fff_fff0)));
    assert_eq!(real_name.0, 0);
    assert_eq!(sim_name, real_name);
    assert_eq!(sim_index, real_index);
}

#[cfg(unix)]
struct Entry {
    name: String,
    family: i32,
    flags: u32,
    addr: Option<IpAddr>,
    netmask: Option<IpAddr>,
    broadaddr: Option<IpAddr>,
}

#[cfg(unix)]
fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    match unsafe { (*sa).sa_family } as i32 {
        libc::AF_INET => {
            let sin = unsafe { *(sa as *const libc::sockaddr_in) };
            Some(IpAddr::from(
                u32::from_be(sin.sin_addr.s_addr).to_be_bytes(),
            ))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { *(sa as *const libc::sockaddr_in6) };
            Some(IpAddr::from(sin6.sin6_addr.s6_addr))
        }
        _ => None,
    }
}

#[cfg(unix)]
fn ifaddrs() -> Vec<Entry> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    assert_eq!(unsafe { libc::getifaddrs(&mut head) }, 0);
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        #[cfg(target_os = "linux")]
        let broad = ifa.ifa_ifu;
        #[cfg(target_os = "macos")]
        let broad = ifa.ifa_dstaddr;
        out.push(Entry {
            name: unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned(),
            family: unsafe { (*ifa.ifa_addr).sa_family } as i32,
            flags: ifa.ifa_flags,
            addr: sockaddr_ip(ifa.ifa_addr),
            netmask: sockaddr_ip(ifa.ifa_netmask),
            broadaddr: sockaddr_ip(broad),
        });
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    out
}

#[cfg(target_os = "linux")]
fn link_family() -> i32 {
    libc::AF_PACKET
}

#[cfg(target_os = "macos")]
fn link_family() -> i32 {
    libc::AF_LINK
}

#[cfg(unix)]
#[test]
fn getifaddrs_lists_link_and_ip_entries() {
    let sim = Sim::builder()
        .nic(
            NicSpec::new("eth0")
                .index(4)
                .address(net("10.0.0.1/24"))
                .address(net("fd00::1/64"))
                .station(ip("10.0.0.2")),
        )
        .build();
    sim.run(|| {
        let entries = ifaddrs();
        let links: Vec<(&str, i32)> = entries
            .iter()
            .filter(|e| e.family == link_family())
            .map(|e| (e.name.as_str(), e.family))
            .collect();
        let names: Vec<&str> = links.iter().map(|l| l.0).collect();
        assert_eq!(
            names,
            vec![loopback(), "sim0", "eth0"],
            "one link entry each, by index"
        );

        let eth0: Vec<&Entry> = entries.iter().filter(|e| e.name == "eth0").collect();
        let v4 = eth0.iter().find(|e| e.family == libc::AF_INET).unwrap();
        assert_eq!(v4.addr, Some(ip("10.0.0.1")));
        assert_eq!(v4.netmask, Some(ip("255.255.255.0")));
        assert_eq!(v4.broadaddr, Some(ip("10.0.0.255")));
        let v6 = eth0.iter().find(|e| e.family == libc::AF_INET6).unwrap();
        assert_eq!(v6.addr, Some(ip("fd00::1")));
        assert_eq!(v6.netmask, Some(ip("ffff:ffff:ffff:ffff::")));
        assert!(
            entries.iter().all(|e| e.addr != Some(ip("10.0.0.2"))),
            "stations are not the host's"
        );
        let lo = entries
            .iter()
            .find(|e| e.name == loopback() && e.family == libc::AF_INET)
            .unwrap();
        assert_eq!(lo.addr, Some(ip("127.0.0.1")));
        assert_ne!(lo.flags & libc::IFF_LOOPBACK as u32, 0);

        let flags = |name: &str| {
            entries
                .iter()
                .find(|e| e.name == name && e.family == libc::AF_INET)
                .unwrap()
                .flags
        };
        let up =
            (libc::IFF_UP | libc::IFF_RUNNING | libc::IFF_BROADCAST | libc::IFF_MULTICAST) as u32;
        assert_eq!(flags("eth0") & up, up);

        snare::set_link("eth0", false).unwrap();
        let after = ifaddrs();
        let eth0 = after
            .iter()
            .find(|e| e.name == "eth0" && e.family == libc::AF_INET)
            .expect("addresses stay while the carrier is lost");
        assert_ne!(eth0.flags & libc::IFF_UP as u32, 0);
        assert_eq!(eth0.flags & libc::IFF_RUNNING as u32, 0);
    });
}

#[cfg(unix)]
fn ifreq(name: &str) -> [u8; 40] {
    let mut req = [0u8; 40];
    req[..name.len()].copy_from_slice(name.as_bytes());
    req
}

#[cfg(target_os = "linux")]
mod sioc {
    pub const FLAGS: libc::c_ulong = libc::SIOCGIFFLAGS;
    pub const MTU: libc::c_ulong = libc::SIOCGIFMTU;
}

#[cfg(target_os = "macos")]
mod sioc {
    pub const FLAGS: libc::c_ulong = 0xc020_6911;
    pub const MTU: libc::c_ulong = 0xc020_6933;
}

#[cfg(unix)]
fn ioctl(fd: i32, request: libc::c_ulong, req: &mut [u8; 40]) -> Result<(), i32> {
    if unsafe { libc::ioctl(fd, request, req.as_mut_ptr()) } == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

#[cfg(unix)]
fn word(req: &[u8; 40]) -> i32 {
    i32::from_ne_bytes(req[16..20].try_into().unwrap())
}

#[cfg(unix)]
fn short(req: &[u8; 40]) -> u16 {
    u16::from_ne_bytes(req[16..18].try_into().unwrap())
}

#[cfg(unix)]
#[test]
fn siocgif_ioctls_on_udp_socket() {
    use std::os::fd::AsRawFd;
    sim().run(|| {
        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        let fd = sock.as_raw_fd();
        let mut req = ifreq("eth0");
        ioctl(fd, sioc::MTU, &mut req).unwrap();
        assert_eq!(word(&req), 9000);
        let mut req = ifreq("eth0");
        ioctl(fd, sioc::FLAGS, &mut req).unwrap();
        let flags = short(&req) as i32;
        assert_eq!(flags & libc::IFF_UP, libc::IFF_UP);
        assert_eq!(flags & libc::IFF_RUNNING, libc::IFF_RUNNING);

        snare::set_nic("eth0", |n| n.admin_up = false).unwrap();
        let mut req = ifreq("eth0");
        ioctl(fd, sioc::FLAGS, &mut req).unwrap();
        assert_eq!(short(&req) as i32 & (libc::IFF_UP | libc::IFF_RUNNING), 0);

        #[cfg(target_os = "linux")]
        {
            let mut req = ifreq("eth1");
            ioctl(fd, libc::SIOCGIFINDEX, &mut req).unwrap();
            assert_eq!(word(&req), 7);
            let mut req = ifreq("eth1");
            ioctl(fd, libc::SIOCGIFHWADDR, &mut req).unwrap();
            assert_eq!(u16::from_ne_bytes([req[16], req[17]]), 1, "ARPHRD_ETHER");
            assert_eq!(&req[18..24], &[0x02, 0x00, 0, 0, 0, 7]);
        }
    });
}

#[cfg(unix)]
#[test]
fn siocgif_unknown_name_os_truth() {
    let probe = || {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(fd >= 0);
        let mut req = ifreq("snarenope0");
        let flags = ioctl(fd, sioc::FLAGS, &mut req);
        let mut req = ifreq("snarenope0");
        let mtu = ioctl(fd, sioc::MTU, &mut req);
        unsafe { libc::close(fd) };
        (flags, mtu)
    };
    let real = snare::real(probe);
    let simulated = sim().run(probe);
    assert!(real.0.is_err());
    assert_eq!(simulated, real);
}

#[test]
fn counters_track_traffic() {
    let sim = sim();
    sim.run(|| {
        let station = UdpSocket::bind("10.0.0.2:7000").unwrap();
        let sock = UdpSocket::bind("10.0.0.1:0").unwrap();
        sock.send_to(&[0u8; 100], "10.0.0.2:7000").unwrap();
        let mut buf = [0u8; 200];
        assert_eq!(station.recv_from(&mut buf).unwrap().0, 100);
        let eth0 = snare::nic_counters("eth0").unwrap();
        assert_eq!(eth0.tx_packets, 1);
        assert_eq!(
            eth0.tx_bytes, 142,
            "payload + Ethernet, IPv4 and UDP headers"
        );

        let lo_name = snare::nics()
            .into_iter()
            .find(|n| n.loopback)
            .unwrap()
            .spec
            .name;
        let before = snare::nic_counters(&lo_name).unwrap();
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        a.send_to(&[0u8; 10], b.local_addr().unwrap()).unwrap();
        b.recv_from(&mut buf).unwrap();
        let after = snare::nic_counters(&lo_name).unwrap();
        assert_eq!(after.tx_packets, before.tx_packets + 1);
        assert_eq!(after.tx_bytes, before.tx_bytes + 52);
    });
    sim.set_nic_counters("eth1", |c| c.rx_errors = 5).unwrap();
    assert_eq!(sim.nic_counters("eth1").unwrap().rx_errors, 5);
    #[cfg(target_os = "linux")]
    sim.run(|| {
        let entries = {
            let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
            assert_eq!(unsafe { libc::getifaddrs(&mut head) }, 0);
            let mut stats = None;
            let mut cur = head;
            while !cur.is_null() {
                let ifa = unsafe { &*cur };
                let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
                if name.to_bytes() == b"eth1"
                    && unsafe { (*ifa.ifa_addr).sa_family } as i32 == libc::AF_PACKET
                {
                    stats = Some(unsafe { *(ifa.ifa_data as *const [u32; 24]) });
                }
                cur = ifa.ifa_next;
            }
            unsafe { libc::freeifaddrs(head) };
            stats.unwrap()
        };
        assert_eq!(entries[4], 5, "rtnl_link_stats.rx_errors");
    });
}
