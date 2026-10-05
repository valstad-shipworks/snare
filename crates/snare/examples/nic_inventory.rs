//! Resolve a host's interfaces by name and print an inventory.
//!
//! `if_nametoindex(3)` maps a name to its 1-based index (man 3 if_nametoindex); on Linux the
//! sim additionally serves `/sys/class/net/<if>/{mtu,operstate}`
//! (Documentation/ABI/testing/sysfs-class-net), which this example reads when present.
//!
//! Run with: `cargo run -p snare --example nic_inventory`

#[cfg(unix)]
use std::ffi::CString;

#[cfg(unix)]
use snare::{HostProfile, Nic, Sim};

#[cfg(unix)]
fn main() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 2).mtu(1500).operstate("up"))
        .nic(Nic::new("eth1", 3).mtu(9000).operstate("down"))
        .build();

    Sim::builder().host(host).build().run(|| {
        for name in ["eth0", "eth1"] {
            let c = CString::new(name).unwrap();
            let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
            let detail = interface_detail(name);
            println!("{name}: ifindex={index}{detail}");
        }
    });
}

#[cfg(target_os = "linux")]
fn interface_detail(name: &str) -> String {
    let read = |attr: &str| {
        std::fs::read_to_string(format!("/sys/class/net/{name}/{attr}"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };
    format!(" mtu={} operstate={}", read("mtu"), read("operstate"))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn interface_detail(_name: &str) -> String {
    String::new()
}

#[cfg(not(unix))]
fn main() {}
