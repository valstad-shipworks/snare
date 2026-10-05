#![cfg(unix)]

//! `if_nametoindex(3)` name resolution. Per man 3 if_nametoindex the call maps an interface name
//! to its 1-based index (see man 7 rtnetlink) and returns `0` for an unknown name, setting errno
//! as the host's libc does: `ENODEV` from glibc, `ENXIO` on macOS.

use std::ffi::CString;

use snare::{HostProfile, Nic, Sim};

const UNKNOWN: i32 = if cfg!(target_os = "linux") {
    libc::ENODEV
} else {
    libc::ENXIO
};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn name_to_index(name: &str) -> u32 {
    let c = CString::new(name).unwrap();
    unsafe { libc::if_nametoindex(c.as_ptr()) }
}

#[test]
fn resolves_a_configured_interface() {
    let host = HostProfile::new().nic(Nic::new("eth0", 7)).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(name_to_index("eth0"), 7);
    });
}

#[test]
fn unknown_interface_returns_zero_and_the_hosts_errno() {
    let host = HostProfile::new().nic(Nic::new("eth0", 7)).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(name_to_index("eth9"), 0);
        assert_eq!(errno(), UNKNOWN);
    });
}

#[test]
fn resolves_each_of_several_interfaces() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 2))
        .nic(Nic::new("eth1", 3))
        .nic(Nic::new("wlan0", 5))
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(name_to_index("eth0"), 2);
        assert_eq!(name_to_index("eth1"), 3);
        assert_eq!(name_to_index("wlan0"), 5);
    });
}

#[test]
fn a_host_with_no_interfaces_resolves_nothing() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(name_to_index("eth0"), 0);
        assert_eq!(errno(), UNKNOWN);
    });
}

#[test]
fn index_survives_a_large_ifindex() {
    // ifindex is a kernel u32; a high value round-trips through the c_uint return unchanged.
    let host = HostProfile::new().nic(Nic::new("eth0", 4_000_000)).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(name_to_index("eth0"), 4_000_000);
    });
}

#[test]
fn a_long_interface_name_resolves() {
    // IFNAMSIZ is 16, so the longest usable name is 15 characters (man 7 netdevice).
    let name = "verylongifname0"; // 15 chars
    let host = HostProfile::new().nic(Nic::new(name, 9)).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(name_to_index(name), 9);
    });
}
