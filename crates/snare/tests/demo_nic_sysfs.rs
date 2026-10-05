#![cfg(target_os = "linux")]

//! `/sys/class/net/<if>/*` scalar attributes. Semantics from
//! Documentation/ABI/testing/sysfs-class-net: `ifindex`, `mtu`, `operstate` and `carrier`
//! (which is `1` only while the interface is operationally up). Each attribute is one line with a
//! trailing newline, as sysfs renders it.

use snare::{HostProfile, Nic, Sim};

fn read(path: &str) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}

fn attr(iface: &str, name: &str) -> std::io::Result<String> {
    read(&format!("/sys/class/net/{iface}/{name}"))
}

#[test]
fn ifindex_mtu_operstate_for_an_up_interface() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 7).mtu(9000).operstate("up"))
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(attr("eth0", "ifindex").unwrap(), "7\n");
        assert_eq!(attr("eth0", "mtu").unwrap(), "9000\n");
        assert_eq!(attr("eth0", "operstate").unwrap(), "up\n");
        assert_eq!(attr("eth0", "carrier").unwrap(), "1\n");
    });
}

#[test]
fn carrier_is_zero_when_operstate_is_not_up() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 7).operstate("down"))
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(attr("eth0", "operstate").unwrap(), "down\n");
        assert_eq!(attr("eth0", "carrier").unwrap(), "0\n");
    });
}

#[test]
fn intermediate_operstate_has_no_carrier() {
    // operstate strings other than "up" (e.g. "lowerlayerdown", "dormant") all mean no carrier.
    for state in ["lowerlayerdown", "dormant", "testing", "unknown"] {
        let host = HostProfile::new()
            .nic(Nic::new("eth0", 1).operstate(state))
            .build();
        Sim::builder().host(host).build().run(|| {
            assert_eq!(attr("eth0", "operstate").unwrap(), format!("{state}\n"));
            assert_eq!(attr("eth0", "carrier").unwrap(), "0\n");
        });
    }
}

#[test]
fn default_mtu_is_the_ethernet_default() {
    let host = HostProfile::new().nic(Nic::new("eth0", 1)).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(attr("eth0", "mtu").unwrap(), "1500\n");
    });
}

#[test]
fn unmodelled_attribute_is_enoent_not_a_leak() {
    // A file under the owned /sys/class/net subtree that the sim does not model is reported as
    // ENOENT rather than falling through to the real host.
    let host = HostProfile::new().nic(Nic::new("eth0", 1)).build();
    Sim::builder().host(host).build().run(|| {
        let err = attr("eth0", "speed").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    });
}

#[test]
fn unknown_interface_attribute_is_enoent() {
    let host = HostProfile::new().nic(Nic::new("eth0", 1)).build();
    Sim::builder().host(host).build().run(|| {
        assert!(attr("eth9", "mtu").is_err());
        assert!(attr("eth9", "operstate").is_err());
    });
}

#[test]
fn attributes_are_independent_per_interface() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 3).mtu(1500).operstate("up"))
        .nic(Nic::new("eth1", 4).mtu(9000).operstate("down"))
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(attr("eth0", "ifindex").unwrap(), "3\n");
        assert_eq!(attr("eth1", "ifindex").unwrap(), "4\n");
        assert_eq!(attr("eth0", "mtu").unwrap(), "1500\n");
        assert_eq!(attr("eth1", "mtu").unwrap(), "9000\n");
        assert_eq!(attr("eth0", "carrier").unwrap(), "1\n");
        assert_eq!(attr("eth1", "carrier").unwrap(), "0\n");
    });
}

#[test]
fn attribute_reads_are_repeatable() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 1).mtu(1500))
        .build();
    Sim::builder().host(host).build().run(|| {
        for _ in 0..3 {
            assert_eq!(attr("eth0", "mtu").unwrap(), "1500\n");
        }
    });
}
