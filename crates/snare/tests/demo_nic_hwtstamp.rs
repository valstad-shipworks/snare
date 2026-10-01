#![cfg(target_os = "linux")]

//! `SIOC[GS]HWTSTAMP` gating and round-trip. The ioctl carries a `struct hwtstamp_config`
//! (`<linux/net_tstamp.h>`, Documentation/networking/timestamping.rst). Per net/core/dev_ioctl.c
//! the kernel enforces `CAP_NET_ADMIN` before asking the driver, and a driver that cannot honour
//! the requested filter reports `ERANGE`.

use snare::{CAP_NET_ADMIN, HostProfile, Nic, Sim};

const SIOCSHWTSTAMP: libc::c_ulong = 0x89b0;
const SIOCGHWTSTAMP: libc::c_ulong = 0x89b1;

// tx_type / rx_filter values from <linux/net_tstamp.h>.
const HWTSTAMP_TX_OFF: i32 = 0;
const HWTSTAMP_TX_ON: i32 = 1;
const HWTSTAMP_FILTER_NONE: i32 = 0;
const HWTSTAMP_FILTER_ALL: i32 = 1;
const HWTSTAMP_FILTER_PTP_V2_EVENT: i32 = 12;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn control_socket() -> i32 {
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

// struct hwtstamp_config { int flags; int tx_type; int rx_filter; }
fn set_hwtstamp(fd: i32, name: &str, tx: i32, rx: i32) -> i32 {
    let mut cfg = [0i32; 3];
    cfg[1] = tx;
    cfg[2] = rx;
    let mut req = ifreq(name);
    req.data = cfg.as_mut_ptr() as usize;
    unsafe { libc::ioctl(fd, SIOCSHWTSTAMP, &mut req as *mut _ as *mut libc::c_void) }
}

fn get_hwtstamp(fd: i32, name: &str) -> (i32, [i32; 3]) {
    let mut cfg = [0i32; 3];
    let mut req = ifreq(name);
    req.data = cfg.as_mut_ptr() as usize;
    let rc = unsafe { libc::ioctl(fd, SIOCGHWTSTAMP, &mut req as *mut _ as *mut libc::c_void) };
    (rc, cfg)
}

#[test]
fn set_without_cap_net_admin_is_eperm() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 1).hardware_timestamping(true))
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        assert_eq!(set_hwtstamp(fd, "eth0", HWTSTAMP_TX_ON, HWTSTAMP_FILTER_ALL), -1);
        assert_eq!(errno(), libc::EPERM);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn set_on_unsupported_nic_is_erange_even_with_cap() {
    // The privilege check passes, but a NIC that does not advertise timestamping cannot honour
    // any filter → ERANGE.
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 1)) // hardware_timestamping defaults to false
        .cap(CAP_NET_ADMIN)
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        assert_eq!(set_hwtstamp(fd, "eth0", HWTSTAMP_TX_ON, HWTSTAMP_FILTER_ALL), -1);
        assert_eq!(errno(), libc::ERANGE);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn privilege_is_checked_before_device_capability() {
    // net/core/dev_ioctl.c: CAP_NET_ADMIN is checked first, so an unsupported NIC without the
    // capability still reports EPERM (not ERANGE).
    let host = HostProfile::new().nic(Nic::new("eth0", 1)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        assert_eq!(set_hwtstamp(fd, "eth0", HWTSTAMP_TX_ON, HWTSTAMP_FILTER_ALL), -1);
        assert_eq!(errno(), libc::EPERM);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn set_then_get_round_trips_the_config() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 1).hardware_timestamping(true))
        .cap(CAP_NET_ADMIN)
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        assert_eq!(set_hwtstamp(fd, "eth0", HWTSTAMP_TX_ON, HWTSTAMP_FILTER_PTP_V2_EVENT), 0);
        let (rc, cfg) = get_hwtstamp(fd, "eth0");
        assert_eq!(rc, 0);
        assert_eq!(cfg[1], HWTSTAMP_TX_ON, "tx_type");
        assert_eq!(cfg[2], HWTSTAMP_FILTER_PTP_V2_EVENT, "rx_filter");
        unsafe { libc::close(fd) };
    });
}

#[test]
fn get_before_any_set_reports_disabled() {
    // SIOCGHWTSTAMP needs no capability and, before any SIOCSHWTSTAMP, reports the off/none state.
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 1).hardware_timestamping(true))
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        let (rc, cfg) = get_hwtstamp(fd, "eth0");
        assert_eq!(rc, 0);
        assert_eq!(cfg[1], HWTSTAMP_TX_OFF);
        assert_eq!(cfg[2], HWTSTAMP_FILTER_NONE);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn last_set_config_wins_across_reconfiguration() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 1).hardware_timestamping(true))
        .cap(CAP_NET_ADMIN)
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        assert_eq!(set_hwtstamp(fd, "eth0", HWTSTAMP_TX_ON, HWTSTAMP_FILTER_ALL), 0);
        assert_eq!(set_hwtstamp(fd, "eth0", HWTSTAMP_TX_OFF, HWTSTAMP_FILTER_NONE), 0);
        let (_, cfg) = get_hwtstamp(fd, "eth0");
        assert_eq!(cfg[1], HWTSTAMP_TX_OFF);
        assert_eq!(cfg[2], HWTSTAMP_FILTER_NONE);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn per_interface_config_is_independent() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 1).hardware_timestamping(true))
        .nic(Nic::new("eth1", 2).hardware_timestamping(true))
        .cap(CAP_NET_ADMIN)
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = control_socket();
        assert_eq!(set_hwtstamp(fd, "eth0", HWTSTAMP_TX_ON, HWTSTAMP_FILTER_PTP_V2_EVENT), 0);
        // eth1 is untouched and still reports disabled.
        let (_, cfg1) = get_hwtstamp(fd, "eth1");
        assert_eq!(cfg1[1], HWTSTAMP_TX_OFF);
        assert_eq!(cfg1[2], HWTSTAMP_FILTER_NONE);

        let (_, cfg0) = get_hwtstamp(fd, "eth0");
        assert_eq!(cfg0[1], HWTSTAMP_TX_ON);
        assert_eq!(cfg0[2], HWTSTAMP_FILTER_PTP_V2_EVENT);
        unsafe { libc::close(fd) };
    });
}
