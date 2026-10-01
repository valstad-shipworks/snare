#![cfg(target_os = "linux")]

use std::ffi::CString;

use snare::{CAP_NET_ADMIN, HostProfile, Nic, Sim};

const SIOCETHTOOL: libc::c_ulong = 0x8946;
const SIOCGIFINDEX: libc::c_ulong = 0x8933;
const SIOCSHWTSTAMP: libc::c_ulong = 0x89b0;
const SIOCGHWTSTAMP: libc::c_ulong = 0x89b1;
const ETHTOOL_GDRVINFO: u32 = 0x3;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn control_socket() -> i32 {
    // A real AF_INET datagram socket, exactly as fast-talker opens for ethtool ioctls.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(fd >= 0);
    fd
}

#[repr(C)]
struct Ifreq {
    name: [libc::c_char; 16],
    data: usize,
}

fn ifreq(name: &str) -> Ifreq {
    let mut n = [0 as libc::c_char; 16];
    for (i, b) in name.bytes().enumerate() {
        n[i] = b as libc::c_char;
    }
    Ifreq { name: n, data: 0 }
}

#[test]
fn if_nametoindex_resolves_a_virtual_interface() {
    let host = HostProfile::new().nic(Nic::new("eth0", 7)).build();
    Sim::builder().host(host).build().run(|| {
        let name = CString::new("eth0").unwrap();
        assert_eq!(unsafe { libc::if_nametoindex(name.as_ptr()) }, 7);

        let missing = CString::new("eth9").unwrap();
        assert_eq!(unsafe { libc::if_nametoindex(missing.as_ptr()) }, 0);
        assert_eq!(errno(), libc::ENODEV);
    });
}

#[test]
fn siocgifindex_on_a_real_control_socket() {
    let host = HostProfile::new().nic(Nic::new("eth0", 7).mtu(9000)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        let mut req = ifreq("eth0");
        let rc = unsafe { libc::ioctl(fd, SIOCGIFINDEX, &mut req as *mut Ifreq) };
        assert_eq!(rc, 0);
        let index = unsafe { (&req.data as *const usize as *const i32).read() };
        assert_eq!(index, 7);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn ethtool_drvinfo_reports_the_driver() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 7).driver("igb", "5.6.0").bus_info("0000:01:00.0"))
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        let mut drvinfo = [0u8; 196];
        drvinfo[0..4].copy_from_slice(&ETHTOOL_GDRVINFO.to_ne_bytes());
        let mut req = ifreq("eth0");
        req.data = drvinfo.as_mut_ptr() as usize;
        let rc = unsafe { libc::ioctl(fd, SIOCETHTOOL, &mut req as *mut Ifreq) };
        assert_eq!(rc, 0);

        let read_field = |off: usize| {
            let end = drvinfo[off..off + 32].iter().position(|&b| b == 0).unwrap();
            String::from_utf8(drvinfo[off..off + end].to_vec()).unwrap()
        };
        assert_eq!(read_field(4), "igb");
        assert_eq!(read_field(36), "5.6.0");
        assert_eq!(read_field(100), "0000:01:00.0");
        unsafe { libc::close(fd) };
    });
}

#[test]
fn hwtstamp_set_needs_cap_and_reads_back() {
    // struct hwtstamp_config { int flags; int tx_type; int rx_filter; }
    fn set_hwtstamp(fd: i32, tx: i32, rx: i32) -> i32 {
        let mut cfg = [0i32; 3];
        cfg[1] = tx;
        cfg[2] = rx;
        let mut req = ifreq("eth0");
        req.data = cfg.as_mut_ptr() as usize;
        unsafe { libc::ioctl(fd, SIOCSHWTSTAMP, &mut req as *mut _ as *mut libc::c_void) }
    }

    // Supported NIC but no CAP_NET_ADMIN → EPERM.
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 7).hardware_timestamping(true))
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        assert_eq!(set_hwtstamp(fd, 1, 1), -1);
        assert_eq!(errno(), libc::EPERM);
        unsafe { libc::close(fd) };
    });

    // With the capability, the config sticks and SIOCGHWTSTAMP reads it back.
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 7).hardware_timestamping(true))
        .cap(CAP_NET_ADMIN)
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        assert_eq!(set_hwtstamp(fd, 1, 5), 0);

        let mut cfg = [0i32; 3];
        let mut req = ifreq("eth0");
        req.data = cfg.as_mut_ptr() as usize;
        let rc = unsafe { libc::ioctl(fd, SIOCGHWTSTAMP, &mut req as *mut _ as *mut libc::c_void) };
        assert_eq!(rc, 0);
        assert_eq!(cfg[1], 1, "tx_type");
        assert_eq!(cfg[2], 5, "rx_filter");
        unsafe { libc::close(fd) };
    });
}

#[test]
fn sysfs_attributes_and_default_qdisc() {
    let host = HostProfile::new()
        .default_qdisc("fq")
        .nic(Nic::new("eth0", 7).mtu(9000).operstate("up"))
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(
            std::fs::read_to_string("/sys/class/net/eth0/mtu").unwrap(),
            "9000\n"
        );
        assert_eq!(
            std::fs::read_to_string("/sys/class/net/eth0/operstate").unwrap(),
            "up\n"
        );
        assert_eq!(
            std::fs::read_to_string("/sys/class/net/eth0/carrier").unwrap(),
            "1\n"
        );
        assert_eq!(
            std::fs::read_to_string("/proc/sys/net/core/default_qdisc").unwrap(),
            "fq\n"
        );
        // An unmodelled interface under the owned subtree is ENOENT, not a leak to the real host.
        assert!(std::fs::read_to_string("/sys/class/net/eth9/mtu").is_err());
    });
}

#[test]
fn device_subsystem_symlink_detects_virtio() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 7).subsystem("virtio"))
        .build();
    Sim::builder().host(host).build().run(|| {
        let target = std::fs::read_link("/sys/class/net/eth0/device/subsystem").unwrap();
        assert!(
            target.to_string_lossy().ends_with("virtio"),
            "got {target:?}"
        );
    });
}

#[test]
fn getifaddrs_lists_configured_interfaces() {
    use std::net::Ipv4Addr;
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 7).address(Ipv4Addr::new(10, 0, 0, 1)))
        .nic(Nic::new("eth1", 8).address(Ipv4Addr::new(10, 0, 0, 2)))
        .nic(Nic::new("lo0", 1)) // no address → excluded
        .build();
    Sim::builder().host(host).build().run(|| {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        let rc = unsafe { libc::getifaddrs(&mut head) };
        assert_eq!(rc, 0);

        let mut found = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            let name = unsafe { std::ffi::CStr::from_ptr((*cur).ifa_name) }
                .to_string_lossy()
                .into_owned();
            let addr = unsafe { (*cur).ifa_addr };
            let ip = if !addr.is_null()
                && unsafe { (*(addr as *const libc::sockaddr_in)).sin_family } == libc::AF_INET as u16
            {
                let s = unsafe { *(addr as *const libc::sockaddr_in) };
                Some(Ipv4Addr::from(u32::from_be(s.sin_addr.s_addr)))
            } else {
                None
            };
            found.push((name, ip));
            cur = unsafe { (*cur).ifa_next };
        }
        unsafe { libc::freeifaddrs(head) };

        assert_eq!(found.len(), 2, "only addressed interfaces are listed");
        assert_eq!(found[0], ("eth0".to_string(), Some(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(found[1], ("eth1".to_string(), Some(Ipv4Addr::new(10, 0, 0, 2))));
    });
}

#[test]
fn queues_and_msi_irqs_directories_list() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 7).queues(4, 4).msi_irqs([128, 129, 130]))
        .build();
    Sim::builder().host(host).build().run(|| {
        let mut queues: Vec<String> = std::fs::read_dir("/sys/class/net/eth0/queues")
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        queues.sort();
        assert_eq!(
            queues,
            vec!["rx-0", "rx-1", "rx-2", "rx-3", "tx-0", "tx-1", "tx-2", "tx-3"]
        );

        let mut irqs: Vec<String> = std::fs::read_dir("/sys/class/net/eth0/device/msi_irqs")
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        irqs.sort();
        assert_eq!(irqs, vec!["128", "129", "130"]);

        // An unmodelled interface's queue dir is ENOENT, not a leak to the real host.
        assert!(std::fs::read_dir("/sys/class/net/eth9/queues").is_err());
    });
}

#[test]
fn hwtstamp_unsupported_nic_is_erange() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 7))
        .cap(CAP_NET_ADMIN)
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        let mut cfg = [0i32; 3];
        let mut req = ifreq("eth0");
        req.data = cfg.as_mut_ptr() as usize;
        let rc = unsafe { libc::ioctl(fd, SIOCSHWTSTAMP, &mut req as *mut _ as *mut libc::c_void) };
        assert_eq!(rc, -1);
        assert_eq!(errno(), libc::ERANGE);
        unsafe { libc::close(fd) };
    });
}
