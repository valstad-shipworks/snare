#![cfg(any(target_os = "linux", target_os = "macos"))]

//! A SimHost's interfaces are the sim's topology: every way to enumerate them — the name/index
//! calls, `getifaddrs`, `SIOCGIF*`, `/sys/class/net`, rtnetlink and macOS's `NET_RT_IFLIST2` —
//! reads the same state, so a link change shows everywhere at once.

#[cfg(target_os = "macos")]
use snare::{HostProfile, Nic, Sim};

#[cfg(target_os = "linux")]
mod linux {
    use std::net::Ipv4Addr;

    use snare::{HostProfile, IpNet, Nic, Sim, set_link, set_nic};

    const NLMSG_DONE: u16 = 3;
    const RTM_NEWLINK: u16 = 16;
    const RTM_GETLINK: u16 = 18;
    const RTM_NEWADDR: u16 = 20;
    const RTM_GETADDR: u16 = 22;
    const RTM_NEWROUTE: u16 = 24;
    const RTM_GETROUTE: u16 = 26;
    const IFLA_OPERSTATE: u16 = 16;
    const IFLA_CARRIER: u16 = 33;
    const IFLA_MTU: u16 = 4;
    const IFA_ADDRESS: u16 = 1;
    const RTA_DST: u16 = 1;
    const RTA_OIF: u16 = 4;

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    }

    /// One message of a dump: its type, its fixed header and its attributes.
    struct Msg {
        ty: u16,
        head: Vec<u8>,
        attrs: Vec<(u16, Vec<u8>)>,
    }

    fn dump(ty: u16, head_len: usize) -> Vec<Msg> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, 0) };
        assert!(fd >= 0);
        let mut req = vec![0u8; 16 + head_len];
        let len = req.len() as u32;
        req[0..4].copy_from_slice(&len.to_ne_bytes());
        req[4..6].copy_from_slice(&ty.to_ne_bytes());
        req[6..8].copy_from_slice(&0x301u16.to_ne_bytes());
        req[8..12].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(
            unsafe { libc::send(fd, req.as_ptr().cast(), req.len(), 0) },
            req.len() as isize
        );
        let mut buf = vec![0u8; 65536];
        let got = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        assert!(got > 0);
        unsafe { libc::close(fd) };
        buf.truncate(got as usize);
        let mut out = Vec::new();
        let mut off = 0;
        while off + 16 <= buf.len() {
            let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            let ty = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
            if ty == NLMSG_DONE {
                break;
            }
            let head = buf[off + 16..off + 16 + head_len].to_vec();
            let mut attrs = Vec::new();
            let mut a = off + 16 + head_len;
            while a + 4 <= off + len {
                let alen = u16::from_ne_bytes([buf[a], buf[a + 1]]) as usize;
                let aty = u16::from_ne_bytes([buf[a + 2], buf[a + 3]]);
                attrs.push((aty, buf[a + 4..a + alen].to_vec()));
                a += alen.next_multiple_of(4);
            }
            out.push(Msg { ty, head, attrs });
            off += len.next_multiple_of(4);
        }
        out
    }

    fn attr(msg: &Msg, ty: u16) -> Option<&[u8]> {
        msg.attrs.iter().find(|a| a.0 == ty).map(|a| a.1.as_slice())
    }

    fn index_of(msg: &Msg, at: usize) -> u32 {
        u32::from_ne_bytes(msg.head[at..at + 4].try_into().unwrap())
    }

    fn sys(attr: &str) -> std::io::Result<String> {
        std::fs::read_to_string(format!("/sys/class/net/eth0/{attr}")).map(|s| s.trim().to_string())
    }

    fn ifflags() -> i32 {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        let mut req = [0u8; 40];
        req[..4].copy_from_slice(b"eth0");
        assert_eq!(
            unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS, req.as_mut_ptr()) },
            0
        );
        unsafe { libc::close(fd) };
        i16::from_ne_bytes([req[16], req[17]]) as u16 as i32
    }

    fn getifaddrs_flags() -> Option<u32> {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        assert_eq!(unsafe { libc::getifaddrs(&mut head) }, 0);
        let mut flags = None;
        let mut cur = head;
        while !cur.is_null() {
            let ifa = unsafe { &*cur };
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
            if name.to_bytes() == b"eth0"
                && unsafe { (*ifa.ifa_addr).sa_family } as i32 == libc::AF_INET
            {
                flags = Some(ifa.ifa_flags);
            }
            cur = ifa.ifa_next;
        }
        unsafe { libc::freeifaddrs(head) };
        flags
    }

    fn link() -> (u32, u8, u8, u32) {
        let links = dump(RTM_GETLINK, 16);
        let eth0 = links
            .iter()
            .find(|m| m.ty == RTM_NEWLINK && index_of(m, 4) == 5)
            .expect("eth0 in the link dump");
        (
            index_of(eth0, 8),
            attr(eth0, IFLA_OPERSTATE).unwrap()[0],
            attr(eth0, IFLA_CARRIER).unwrap()[0],
            u32::from_ne_bytes(attr(eth0, IFLA_MTU).unwrap().try_into().unwrap()),
        )
    }

    fn routes_via_eth0() -> Vec<Vec<u8>> {
        dump(RTM_GETROUTE, 12)
            .iter()
            .filter(|m| m.ty == RTM_NEWROUTE && attr(m, RTA_OIF) == Some(&5u32.to_ne_bytes()[..]))
            .map(|m| attr(m, RTA_DST).unwrap_or_default().to_vec())
            .collect()
    }

    #[test]
    fn unknown_operstate_with_carrier_is_consistent_across_interfaces() {
        for deterministic in [false, true] {
            let host = HostProfile::new()
                .nic(
                    Nic::new("eth0", 5)
                        .operstate("unknown")
                        .carrier(true)
                        .network("192.168.5.10/24".parse::<IpNet>().unwrap()),
                )
                .build();
            let mut builder = Sim::builder().host(host);
            if deterministic {
                builder = builder.deterministic();
            }
            builder.build().run(|| {
                let flags = (libc::IFF_UP | libc::IFF_RUNNING) as u32;
                let lower_up = 1u32 << 16;
                let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
                let glink = || {
                    let mut request = [0u8; 40];
                    request[..4].copy_from_slice(b"eth0");
                    let mut value = [0xau32, 0];
                    unsafe {
                        request
                            .as_mut_ptr()
                            .add(16)
                            .cast::<usize>()
                            .write_unaligned(value.as_mut_ptr() as usize);
                    }
                    assert_eq!(unsafe { libc::ioctl(fd, 0x8946, request.as_mut_ptr()) }, 0);
                    value[1]
                };
                assert!(snare::nic("eth0").unwrap().spec.carrier);
                assert_eq!(sys("operstate").unwrap(), "unknown");
                assert_eq!(sys("carrier").unwrap(), "1");
                assert_eq!(glink(), 1);
                assert_eq!(ifflags() as u32 & flags, flags);
                assert_eq!(getifaddrs_flags().unwrap() & flags, flags);
                let (netlink_flags, oper, carrier, _) = link();
                assert_eq!(netlink_flags & (flags | lower_up), flags | lower_up);
                assert_eq!((oper, carrier), (0, 1));
                set_link("eth0", false).unwrap();
                assert_eq!(sys("operstate").unwrap(), "down");
                assert_eq!(sys("carrier").unwrap(), "0");
                assert_eq!(glink(), 0);
                assert_eq!((link().1, link().2), (2, 0));
                set_link("eth0", true).unwrap();
                assert_eq!(sys("operstate").unwrap(), "unknown");
                assert_eq!((link().1, link().2), (0, 1));
                assert_eq!(glink(), 1);
                set_nic("eth0", |n| n.admin_up = false).unwrap();
                assert_eq!(sys("operstate").unwrap(), "down");
                assert_eq!(
                    sys("carrier").unwrap_err().raw_os_error(),
                    Some(libc::EINVAL)
                );
                assert_eq!(glink(), 0);
                unsafe { libc::close(fd) };
            });
        }
    }

    #[test]
    fn simhost_nics_are_the_topology() {
        let host = HostProfile::new()
            .nic(
                Nic::new("eth0", 5)
                    .mtu(9000)
                    .network("192.168.5.10/24".parse::<IpNet>().unwrap()),
            )
            .build();
        Sim::builder().host(host).build().run(|| {
            let name = c"eth0";
            assert_eq!(unsafe { libc::if_nametoindex(name.as_ptr()) }, 5);
            assert_eq!(sys("ifindex").unwrap(), "5");
            assert_eq!(sys("mtu").unwrap(), "9000");
            assert_eq!(sys("operstate").unwrap(), "up");
            assert_eq!(sys("carrier").unwrap(), "1");
            assert_eq!(sys("flags").unwrap(), "0x1003");
            assert_eq!(sys("address").unwrap(), "02:00:00:00:00:05");
            let running = libc::IFF_UP | libc::IFF_RUNNING;
            assert_eq!(ifflags() & running, running);
            assert_eq!(getifaddrs_flags().unwrap() & running as u32, running as u32);
            assert_eq!(
                link(),
                (
                    libc::IFF_UP as u32
                        | libc::IFF_BROADCAST as u32
                        | libc::IFF_RUNNING as u32
                        | libc::IFF_MULTICAST as u32
                        | libc::IFF_LOWER_UP as u32,
                    6,
                    1,
                    9000
                )
            );
            let addrs = dump(RTM_GETADDR, 8);
            let eth0 = addrs
                .iter()
                .find(|m| m.ty == RTM_NEWADDR && index_of(m, 4) == 5)
                .unwrap();
            assert_eq!(eth0.head[1], 24, "ifa_prefixlen");
            assert_eq!(
                attr(eth0, IFA_ADDRESS).unwrap(),
                Ipv4Addr::new(192, 168, 5, 10).octets()
            );
            assert!(
                routes_via_eth0().contains(&vec![192, 168, 5, 0]),
                "connected route"
            );

            set_link("eth0", false).unwrap();
            assert_eq!(sys("operstate").unwrap(), "down");
            assert_eq!(sys("carrier").unwrap(), "0");
            assert_eq!(ifflags() & running, libc::IFF_UP);
            assert_eq!(
                getifaddrs_flags().unwrap() & running as u32,
                libc::IFF_UP as u32
            );
            let (flags, oper, carrier, _) = link();
            assert_eq!(flags & libc::IFF_RUNNING as u32, 0);
            assert_eq!((oper, carrier), (2, 0));
            assert!(
                !routes_via_eth0().is_empty(),
                "routes stay while the interface is up"
            );

            set_nic("eth0", |n| n.admin_up = false).unwrap();
            let err = sys("carrier").unwrap_err();
            assert_eq!(
                err.raw_os_error(),
                Some(libc::EINVAL),
                "carrier_show of a down device"
            );
            assert_eq!(ifflags() & running, 0);
            assert!(
                routes_via_eth0().is_empty(),
                "a down interface's routes are withdrawn"
            );

            set_nic("eth0", |n| {
                n.admin_up = true;
                n.carrier = true;
            })
            .unwrap();
            assert_eq!(sys("operstate").unwrap(), "up");
            assert_eq!(link().1, 6);
            let bogus = c"eth9";
            assert_eq!(unsafe { libc::if_nametoindex(bogus.as_ptr()) }, 0);
            assert_eq!(errno(), libc::ENODEV);
        });
    }

    #[test]
    fn statistics_follow_traffic() {
        let host = HostProfile::new()
            .nic(
                Nic::new("eth0", 5)
                    .network("192.168.5.10/24".parse::<IpNet>().unwrap())
                    .station("192.168.5.20".parse::<std::net::IpAddr>().unwrap())
                    .link_stats(snare::LinkStats {
                        tx_packets: 10,
                        ..Default::default()
                    }),
            )
            .build();
        Sim::builder().host(host).build().run(|| {
            assert_eq!(sys("statistics/tx_packets").unwrap(), "10");
            let station = std::net::UdpSocket::bind("192.168.5.20:7000").unwrap();
            let sock = std::net::UdpSocket::bind("192.168.5.10:0").unwrap();
            sock.send_to(&[1; 58], "192.168.5.20:7000").unwrap();
            let mut buf = [0u8; 100];
            station.recv_from(&mut buf).unwrap();
            assert_eq!(sys("statistics/tx_packets").unwrap(), "11");
            assert_eq!(sys("statistics/tx_bytes").unwrap(), "100");
        });
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_simhost_iflist2_from_topology() {
    const IF_MSGHDR2_LEN: usize = 168;
    let host = HostProfile::new().nic(Nic::new("en0", 4).mtu(9000)).build();
    let sim = Sim::builder().host(host).build();
    let iflist = || {
        let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, 6, 0];
        let mut len = 0usize;
        assert_eq!(
            unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    6,
                    std::ptr::null_mut(),
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            },
            0
        );
        let mut buf = vec![0u8; len];
        assert_eq!(
            unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    6,
                    buf.as_mut_ptr().cast(),
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            },
            0
        );
        buf.chunks(IF_MSGHDR2_LEN)
            .map(|m| {
                let flags = i32::from_ne_bytes(m[8..12].try_into().unwrap());
                let index = u16::from_ne_bytes([m[12], m[13]]);
                let mtu = u32::from_ne_bytes(m[40..44].try_into().unwrap());
                (index, flags, mtu)
            })
            .collect::<Vec<_>>()
    };
    sim.run(|| {
        let list = iflist();
        assert_eq!(list.iter().map(|l| l.0).collect::<Vec<_>>(), vec![1, 4]);
        let en0 = list[1];
        assert_eq!(en0.2, 9000);
        assert_eq!(en0.1 & libc::IFF_RUNNING, libc::IFF_RUNNING);
        snare::set_link("en0", false).unwrap();
        assert_eq!(iflist()[1].1 & libc::IFF_RUNNING, 0);
        let name = c"en0";
        assert_eq!(unsafe { libc::if_nametoindex(name.as_ptr()) }, 4);
    });
}
