//! A `SimHost`'s interrupt lines under `/proc/irq` and `/sys/kernel/irq`: a NIC's MSI vectors
//! named as igb names them and the profile's own lines, each line's affinity read in mask and
//! list form and written as kernel/irq/proc.c takes it (root only, `EIO` for a managed line, a
//! mask naming no online CPU falling back to the default), and the default affinity.
#![cfg(target_os = "linux")]

use std::io::ErrorKind;

use snare::{HostProfile, Nic, Sim};

fn host(root: bool) -> Sim {
    let host = HostProfile::new()
        .cpus(8)
        .online([0, 1, 2, 3, 4, 5, 6])
        .isolated([2, 3])
        .root(root)
        .nic(Nic::new("eth0", 2).msi_irqs([128, 129, 130]))
        .irq(9, "acpi")
        .managed_irq(60, "nvme0q1", [2, 3])
        .build();
    Sim::builder().host(host).build()
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap()
}

fn write(path: &str, text: &str) -> std::io::Result<()> {
    std::fs::write(path, text)
}

#[test]
fn lines_are_listed_and_named() {
    host(true).run(|| {
        let mut listed: Vec<String> = std::fs::read_dir("/proc/irq")
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        listed.sort();
        assert_eq!(
            listed,
            ["128", "129", "130", "60", "9", "default_smp_affinity"]
        );
        assert_eq!(read("/sys/kernel/irq/128/actions"), "eth0\n");
        assert_eq!(read("/sys/kernel/irq/129/actions"), "eth0-TxRx-0\n");
        assert_eq!(read("/sys/kernel/irq/130/actions"), "eth0-TxRx-1\n");
        assert_eq!(read("/sys/kernel/irq/60/actions"), "nvme0q1\n");
        assert_eq!(read("/proc/irq/default_smp_affinity"), "7f\n");
        assert_eq!(read("/proc/irq/129/smp_affinity_list"), "0-6\n");
        assert_eq!(read("/proc/irq/129/effective_affinity_list"), "0\n");
        assert_eq!(read("/proc/irq/60/smp_affinity_list"), "2-3\n");
        assert_eq!(
            read("/proc/irq/60/effective_affinity_list"),
            "2\n",
            "a managed line spread only onto isolated CPUs still lands on one of them"
        );
        assert!(std::fs::metadata("/proc/irq/131").is_err());
    });
}

#[test]
fn a_line_moves_where_it_is_told() {
    host(true).run(|| {
        write("/proc/irq/129/smp_affinity_list", "4-5\n").unwrap();
        assert_eq!(read("/proc/irq/129/smp_affinity_list"), "4-5\n");
        assert_eq!(read("/proc/irq/129/smp_affinity"), "30\n");
        assert_eq!(read("/proc/irq/129/effective_affinity_list"), "4\n");

        write("/proc/irq/130/smp_affinity", "c0").unwrap();
        assert_eq!(read("/proc/irq/130/smp_affinity_list"), "6-7\n");
        assert_eq!(
            read("/proc/irq/130/effective_affinity_list"),
            "6\n",
            "the offline CPU stays in the affinity but never takes the interrupt"
        );

        write("/proc/irq/9/smp_affinity_list", "0-7:2/4").unwrap();
        assert_eq!(read("/proc/irq/9/smp_affinity_list"), "0-1,4-5\n");
    });
}

#[test]
fn writes_are_refused_as_the_kernel_refuses_them() {
    host(true).run(|| {
        let errno = |r: std::io::Result<()>| r.unwrap_err().raw_os_error();
        assert_eq!(
            errno(write("/proc/irq/60/smp_affinity_list", "0")),
            Some(libc::EIO)
        );
        assert_eq!(
            errno(write("/proc/irq/129/smp_affinity_list", "0-x")),
            Some(libc::EINVAL)
        );
        assert_eq!(
            errno(write("/proc/irq/129/smp_affinity_list", "8")),
            Some(libc::ERANGE)
        );
        assert_eq!(
            errno(write("/proc/irq/129/smp_affinity", "1ff")),
            Some(libc::EOVERFLOW)
        );
        assert_eq!(
            errno(write("/proc/irq/default_smp_affinity", "80")),
            Some(libc::EINVAL)
        );
        assert_eq!(read("/proc/irq/60/smp_affinity_list"), "2-3\n");
    });
}

#[test]
fn a_mask_naming_no_online_cpu_falls_back_to_the_default() {
    host(true).run(|| {
        write("/proc/irq/default_smp_affinity", "3").unwrap();
        assert_eq!(read("/proc/irq/default_smp_affinity"), "03\n");
        write("/proc/irq/129/smp_affinity", "80").unwrap();
        assert_eq!(read("/proc/irq/129/smp_affinity_list"), "0-1\n");
    });
}

#[test]
fn only_root_may_move_an_interrupt() {
    host(false).run(|| {
        let refused = write("/proc/irq/129/smp_affinity_list", "1").unwrap_err();
        assert_eq!(refused.kind(), ErrorKind::PermissionDenied);
        assert_eq!(read("/proc/irq/129/smp_affinity_list"), "0-6\n");
    });
}
