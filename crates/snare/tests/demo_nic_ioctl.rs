#![cfg(target_os = "linux")]

//! NIC configuration ioctls driven over a real `AF_INET` datagram socket, per man 7 netdevice.
//! Request numbers are from `<linux/sockios.h>`; `SIOCETHTOOL` nests a command from
//! `<linux/ethtool.h>`.

use snare::{HostProfile, Nic, Sim};

const SIOCGIFINDEX: libc::c_ulong = 0x8933;
const SIOCGIFMTU: libc::c_ulong = 0x8921;
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_GDRVINFO: u32 = 0x3;
// ETHTOOL_GLINKSETTINGS (<linux/ethtool.h>): the sim only models GDRVINFO, so any other command
// is rejected with EOPNOTSUPP.
const ETHTOOL_GLINKSETTINGS: u32 = 0x4c;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn control_socket() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(fd >= 0, "control socket: {}", errno());
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
fn siocgifindex_reads_the_index() {
    let host = HostProfile::new().nic(Nic::new("eth0", 42)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        let mut req = ifreq("eth0");
        let rc = unsafe { libc::ioctl(fd, SIOCGIFINDEX, &mut req as *mut Ifreq) };
        assert_eq!(rc, 0);
        // SIOCGIFINDEX returns ifr_ifindex, an `int` in the ifreq union at offset 16.
        let index = unsafe { (&req.data as *const usize as *const i32).read() };
        assert_eq!(index, 42);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn siocgifmtu_reads_default_and_custom_mtu() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 1)) // default MTU 1500
        .nic(Nic::new("eth1", 2).mtu(9000))
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        let read_mtu = |name: &str| {
            let mut req = ifreq(name);
            let rc = unsafe { libc::ioctl(fd, SIOCGIFMTU, &mut req as *mut Ifreq) };
            assert_eq!(rc, 0);
            unsafe { (&req.data as *const usize as *const i32).read() }
        };
        assert_eq!(read_mtu("eth0"), 1500);
        assert_eq!(read_mtu("eth1"), 9000);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn siocgifflags_reports_running_only_when_up() {
    // man 7 netdevice: SIOCGIFFLAGS returns ifr_flags, a `short`. IFF_RUNNING (<net/if.h>) is set
    // only while the link carrier is present, which the sim ties to operstate == "up".
    let host = HostProfile::new()
        .nic(Nic::new("up0", 1).operstate("up"))
        .nic(Nic::new("dn0", 2).operstate("down"))
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        let read_flags = |name: &str| -> libc::c_short {
            let mut req = ifreq(name);
            let rc = unsafe { libc::ioctl(fd, SIOCGIFFLAGS, &mut req as *mut Ifreq) };
            assert_eq!(rc, 0);
            unsafe { (&req.data as *const usize as *const libc::c_short).read() }
        };
        let up = read_flags("up0");
        assert_ne!(up & libc::IFF_UP as libc::c_short, 0, "IFF_UP");
        assert_ne!(
            up & libc::IFF_RUNNING as libc::c_short,
            0,
            "IFF_RUNNING when up"
        );

        let down = read_flags("dn0");
        assert_ne!(
            down & libc::IFF_UP as libc::c_short,
            0,
            "IFF_UP even when down"
        );
        assert_eq!(
            down & libc::IFF_RUNNING as libc::c_short,
            0,
            "no IFF_RUNNING when down"
        );
        unsafe { libc::close(fd) };
    });
}

fn ethtool_drvinfo(fd: i32, name: &str) -> [u8; 196] {
    // struct ethtool_drvinfo (<linux/ethtool.h>): cmd @0, then 32-byte char fields driver @4,
    // version @36, fw_version @68, bus_info @100.
    let mut drvinfo = [0u8; 196];
    drvinfo[0..4].copy_from_slice(&ETHTOOL_GDRVINFO.to_ne_bytes());
    let mut req = ifreq(name);
    req.data = drvinfo.as_mut_ptr() as usize;
    let rc = unsafe { libc::ioctl(fd, SIOCETHTOOL, &mut req as *mut Ifreq) };
    assert_eq!(rc, 0);
    drvinfo
}

fn field(buf: &[u8], off: usize) -> String {
    let end = buf[off..off + 32].iter().position(|&b| b == 0).unwrap();
    String::from_utf8(buf[off..off + end].to_vec()).unwrap()
}

#[test]
fn ethtool_gdrvinfo_reports_driver_version_and_bus() {
    let host = HostProfile::new()
        .nic(
            Nic::new("eth0", 1)
                .driver("igb", "5.6.0")
                .bus_info("0000:01:00.0"),
        )
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        let info = ethtool_drvinfo(fd, "eth0");
        assert_eq!(field(&info, 4), "igb");
        assert_eq!(field(&info, 36), "5.6.0");
        assert_eq!(field(&info, 100), "0000:01:00.0");
        unsafe { libc::close(fd) };
    });
}

#[test]
fn ethtool_gdrvinfo_default_driver_is_sim() {
    let host = HostProfile::new().nic(Nic::new("eth0", 1)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        let info = ethtool_drvinfo(fd, "eth0");
        assert_eq!(field(&info, 4), "sim");
        assert_eq!(field(&info, 36), "0");
        assert_eq!(field(&info, 100), "");
        unsafe { libc::close(fd) };
    });
}

#[test]
fn ethtool_gdrvinfo_truncates_to_the_fixed_field_width() {
    // Each char field is 32 bytes and must stay NUL-terminated, so at most 31 bytes of the name
    // survive (<linux/ethtool.h> declares `char driver[32]`).
    let long = "abcdefghijklmnopqrstuvwxyz0123456789"; // 36 chars
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 1).driver(long, "0"))
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        let info = ethtool_drvinfo(fd, "eth0");
        let driver = field(&info, 4);
        assert_eq!(driver.len(), 31);
        assert_eq!(driver, &long[..31]);
        assert_eq!(info[35], 0, "field stays NUL-terminated at byte 31");
        unsafe { libc::close(fd) };
    });
}

#[test]
fn ethtool_unsupported_command_is_eopnotsupp() {
    let host = HostProfile::new().nic(Nic::new("eth0", 1)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        let mut cmd = [0u8; 256];
        cmd[0..4].copy_from_slice(&ETHTOOL_GLINKSETTINGS.to_ne_bytes());
        let mut req = ifreq("eth0");
        req.data = cmd.as_mut_ptr() as usize;
        let rc = unsafe { libc::ioctl(fd, SIOCETHTOOL, &mut req as *mut Ifreq) };
        assert_eq!(rc, -1);
        assert_eq!(errno(), libc::EOPNOTSUPP);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn many_interfaces_resolve_independently() {
    let mut host = HostProfile::new();
    for i in 0..16u32 {
        host = host.nic(Nic::new(format!("eth{i}"), 100 + i).mtu(1000 + i as i32 * 100));
    }
    let host = host.build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        for i in 0..16u32 {
            let mut req = ifreq(&format!("eth{i}"));
            assert_eq!(
                unsafe { libc::ioctl(fd, SIOCGIFINDEX, &mut req as *mut Ifreq) },
                0
            );
            let index = unsafe { (&req.data as *const usize as *const i32).read() };
            assert_eq!(index as u32, 100 + i);

            let mut req = ifreq(&format!("eth{i}"));
            assert_eq!(
                unsafe { libc::ioctl(fd, SIOCGIFMTU, &mut req as *mut Ifreq) },
                0
            );
            let mtu = unsafe { (&req.data as *const usize as *const i32).read() };
            assert_eq!(mtu, 1000 + i as i32 * 100);
        }
        unsafe { libc::close(fd) };
    });
}
