#![cfg(target_os = "linux")]

//! Directory listings and the device symlink under `/sys/class/net/<if>/`. Queue subdirectories
//! (`rx-N`/`tx-N`) follow Documentation/ABI/testing/sysfs-class-net-queues; `device/msi_irqs`
//! follows Documentation/ABI/testing/sysfs-pci-devices; and `device/subsystem` is a symlink into
//! `/sys/bus/<type>` per the sysfs device model (Documentation/ABI/testing/sysfs-class-net).

use snare::{HostProfile, Nic, Sim};

fn list_dir(path: &str) -> std::io::Result<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir(path)?
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    Ok(names)
}

#[test]
fn queues_default_to_one_rx_and_one_tx() {
    let host = HostProfile::new().nic(Nic::new("eth0", 1)).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(list_dir("/sys/class/net/eth0/queues").unwrap(), vec!["rx-0", "tx-0"]);
    });
}

#[test]
fn queues_list_all_configured_rx_and_tx() {
    let host = HostProfile::new().nic(Nic::new("eth0", 1).queues(4, 4)).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(
            list_dir("/sys/class/net/eth0/queues").unwrap(),
            vec!["rx-0", "rx-1", "rx-2", "rx-3", "tx-0", "tx-1", "tx-2", "tx-3"]
        );
    });
}

#[test]
fn queues_can_be_asymmetric() {
    let host = HostProfile::new().nic(Nic::new("eth0", 1).queues(1, 8)).build();
    Sim::builder().host(host).build().run(|| {
        let listing = list_dir("/sys/class/net/eth0/queues").unwrap();
        let rx: Vec<_> = listing.iter().filter(|n| n.starts_with("rx-")).collect();
        let tx: Vec<_> = listing.iter().filter(|n| n.starts_with("tx-")).collect();
        assert_eq!(rx.len(), 1);
        assert_eq!(tx.len(), 8);
    });
}

#[test]
fn msi_irqs_lists_configured_vectors() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 1).msi_irqs([128, 129, 130, 131]))
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(
            list_dir("/sys/class/net/eth0/device/msi_irqs").unwrap(),
            vec!["128", "129", "130", "131"]
        );
    });
}

#[test]
fn msi_irqs_directory_is_empty_without_vectors() {
    // A NIC with no MSI-X vectors still exposes the directory, but it lists nothing.
    let host = HostProfile::new().nic(Nic::new("eth0", 1)).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(list_dir("/sys/class/net/eth0/device/msi_irqs").unwrap(), Vec::<String>::new());
    });
}

#[test]
fn queue_and_msi_dirs_for_unknown_interface_error() {
    let host = HostProfile::new().nic(Nic::new("eth0", 1)).build();
    Sim::builder().host(host).build().run(|| {
        assert!(list_dir("/sys/class/net/eth9/queues").is_err());
        assert!(list_dir("/sys/class/net/eth9/device/msi_irqs").is_err());
    });
}

#[test]
fn device_subsystem_symlink_defaults_to_pci() {
    let host = HostProfile::new().nic(Nic::new("eth0", 1)).build();
    Sim::builder().host(host).build().run(|| {
        let target = std::fs::read_link("/sys/class/net/eth0/device/subsystem").unwrap();
        assert!(target.to_string_lossy().ends_with("/bus/pci"), "got {target:?}");
    });
}

#[test]
fn device_subsystem_symlink_detects_virtio() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 1).subsystem("virtio"))
        .build();
    Sim::builder().host(host).build().run(|| {
        let target = std::fs::read_link("/sys/class/net/eth0/device/subsystem").unwrap();
        // fast-talker treats a target ending in /bus/virtio as a virtio-net device.
        assert!(target.to_string_lossy().ends_with("/bus/virtio"), "got {target:?}");
    });
}

#[test]
fn reading_a_non_symlink_owned_path_as_a_link_errors() {
    // A plain attribute file is not a symlink; readlink over the owned subtree reports ENOENT
    // rather than leaking to the real host.
    let host = HostProfile::new().nic(Nic::new("eth0", 1)).build();
    Sim::builder().host(host).build().run(|| {
        assert!(std::fs::read_link("/sys/class/net/eth0/mtu").is_err());
    });
}

#[test]
fn distinct_interfaces_have_distinct_subsystems() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 1).subsystem("pci"))
        .nic(Nic::new("eth1", 2).subsystem("virtio"))
        .build();
    Sim::builder().host(host).build().run(|| {
        let a = std::fs::read_link("/sys/class/net/eth0/device/subsystem").unwrap();
        let b = std::fs::read_link("/sys/class/net/eth1/device/subsystem").unwrap();
        assert!(a.to_string_lossy().ends_with("/bus/pci"));
        assert!(b.to_string_lossy().ends_with("/bus/virtio"));
    });
}
