#![cfg(target_os = "linux")]

//! `getifaddrs(3)` enumeration. Per man 3 getifaddrs the call builds a linked list of
//! `struct ifaddrs` that the caller releases with `freeifaddrs(3)`; `ifa_flags` carries the
//! `SIOCGIFFLAGS` word (`IFF_UP`/`IFF_RUNNING`, `<net/if.h>`) and `ifa_addr` points at a
//! `sockaddr_in` for an IPv4 entry. The sim lists every interface of its topology (loopback
//! included) with one `AF_PACKET` entry, then one entry per address, in index order.

use std::net::Ipv4Addr;

use snare::{HostProfile, Nic, Sim};

struct Iface {
    name: String,
    family: i32,
    ip: Option<Ipv4Addr>,
    flags: u32,
}

fn collect() -> Vec<Iface> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    let rc = unsafe { libc::getifaddrs(&mut head) };
    assert_eq!(rc, 0, "getifaddrs: {}", std::io::Error::last_os_error());
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        let name = unsafe { std::ffi::CStr::from_ptr((*cur).ifa_name) }
            .to_string_lossy()
            .into_owned();
        let flags = unsafe { (*cur).ifa_flags };
        let addr = unsafe { (*cur).ifa_addr };
        let family = unsafe { (*addr).sa_family } as i32;
        let ip = (family == libc::AF_INET).then(|| {
            let s = unsafe { *(addr as *const libc::sockaddr_in) };
            Ipv4Addr::from(u32::from_be(s.sin_addr.s_addr))
        });
        out.push(Iface {
            name,
            family,
            ip,
            flags,
        });
        cur = unsafe { (*cur).ifa_next };
    }
    unsafe { libc::freeifaddrs(head) };
    out
}

/// The IPv4 entries of the host's own interfaces, loopback left out.
fn inet() -> Vec<Iface> {
    collect()
        .into_iter()
        .filter(|i| i.ip.is_some() && i.name != "lo")
        .collect()
}

#[test]
fn ipv4_entries_follow_index_order() {
    let host = HostProfile::new()
        .nic(Nic::new("eth1", 7).address(Ipv4Addr::new(10, 0, 0, 2)))
        .nic(Nic::new("eth0", 8).address(Ipv4Addr::new(10, 0, 0, 1)))
        .nic(Nic::new("eth9", 2))
        .build();
    Sim::builder().host(host).build().run(|| {
        let ifaces = inet();
        assert_eq!(
            ifaces.len(),
            2,
            "only addressed interfaces have IPv4 entries"
        );
        assert_eq!(ifaces[0].name, "eth1");
        assert_eq!(ifaces[0].ip, Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(ifaces[1].name, "eth0");
        assert_eq!(ifaces[1].ip, Some(Ipv4Addr::new(10, 0, 0, 1)));
    });
}

#[test]
fn an_unaddressed_interface_has_only_its_link_entry() {
    let host = HostProfile::new().nic(Nic::new("eth0", 1)).build();
    Sim::builder().host(host).build().run(|| {
        let entries: Vec<_> = collect().into_iter().filter(|i| i.name == "eth0").collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].family, libc::AF_PACKET);
    });
}

#[test]
fn up_interface_carries_iff_up_and_iff_running() {
    let host = HostProfile::new()
        .nic(
            Nic::new("eth0", 1)
                .address(Ipv4Addr::new(192, 168, 1, 10))
                .operstate("up"),
        )
        .build();
    Sim::builder().host(host).build().run(|| {
        let ifaces = inet();
        assert_eq!(ifaces.len(), 1);
        assert_ne!(ifaces[0].flags & libc::IFF_UP as u32, 0, "IFF_UP");
        assert_ne!(ifaces[0].flags & libc::IFF_RUNNING as u32, 0, "IFF_RUNNING");
    });
}

#[test]
fn down_interface_is_listed_without_iff_running() {
    let host = HostProfile::new()
        .nic(
            Nic::new("eth0", 1)
                .address(Ipv4Addr::new(192, 168, 1, 10))
                .operstate("down"),
        )
        .build();
    Sim::builder().host(host).build().run(|| {
        let ifaces = inet();
        assert_eq!(ifaces.len(), 1);
        assert_ne!(ifaces[0].flags & libc::IFF_UP as u32, 0, "IFF_UP");
        assert_eq!(
            ifaces[0].flags & libc::IFF_RUNNING as u32,
            0,
            "no IFF_RUNNING without carrier"
        );
    });
}

#[test]
fn addresses_survive_many_interfaces() {
    let mut host = HostProfile::new();
    for i in 0..8u8 {
        host = host
            .nic(Nic::new(format!("eth{i}"), 10 + i as u32).address(Ipv4Addr::new(10, 0, 0, i)));
    }
    let host = host.build();
    Sim::builder().host(host).build().run(|| {
        let ifaces = inet();
        assert_eq!(ifaces.len(), 8);
        for (i, iface) in ifaces.iter().enumerate() {
            assert_eq!(iface.name, format!("eth{i}"));
            assert_eq!(iface.ip, Some(Ipv4Addr::new(10, 0, 0, i as u8)));
        }
    });
}

#[test]
fn mixed_addressed_and_unaddressed_only_addressed_have_ipv4() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 1).address(Ipv4Addr::new(10, 0, 0, 1)))
        .nic(Nic::new("eth1", 2))
        .nic(Nic::new("eth2", 3).address(Ipv4Addr::new(10, 0, 0, 3)))
        .build();
    Sim::builder().host(host).build().run(|| {
        let names: Vec<_> = inet().into_iter().map(|i| i.name).collect();
        assert_eq!(names, vec!["eth0", "eth2"]);
    });
}
