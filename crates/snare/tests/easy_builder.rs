#![cfg(target_os = "linux")]

use std::ffi::CString;

use snare::{EasyBuilder, Sim};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn set_fifo(priority: i32) -> i64 {
    let tid = unsafe { libc::gettid() };
    let param = libc::sched_param {
        sched_priority: priority,
    };
    unsafe {
        libc::syscall(
            libc::SYS_sched_setscheduler,
            tid,
            libc::SCHED_FIFO,
            &param as *const libc::sched_param,
        )
    }
}

fn ifindex(name: &str) -> u32 {
    let c = CString::new(name).unwrap();
    unsafe { libc::if_nametoindex(c.as_ptr()) }
}

#[test]
fn realtime_preset_lets_all_tuning_succeed() {
    Sim::builder()
        .host(EasyBuilder::realtime().build())
        .build()
        .run(|| {
            // Real-time scheduling and memory locking succeed (the host is privileged).
            assert_eq!(set_fifo(80), 0);
            assert_eq!(
                unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) },
                0
            );
            // The preset NIC resolves and its sysfs is readable.
            assert_eq!(ifindex("eth0"), 2);
            assert_eq!(
                std::fs::read_to_string("/sys/class/net/eth0/operstate").unwrap(),
                "up\n"
            );
            // Isolated CPUs come from the preset.
            assert_eq!(
                std::fs::read_to_string("/sys/devices/system/cpu/isolated").unwrap(),
                "2-7\n"
            );
            assert_eq!(
                std::fs::read_to_string("/sys/kernel/realtime").unwrap(),
                "1\n"
            );
        });
}

#[test]
fn laptop_preset_is_unprivileged_and_plain() {
    Sim::builder()
        .host(EasyBuilder::laptop().build())
        .build()
        .run(|| {
            // No CAP_SYS_NICE → real-time scheduling is refused.
            assert_eq!(set_fifo(80), -1);
            assert_eq!(errno(), libc::EPERM);
            // No CAP_IPC_LOCK → mlockall is refused: the process exceeds the stock RLIMIT_MEMLOCK.
            assert_eq!(unsafe { libc::mlockall(libc::MCL_CURRENT) }, -1);
            assert_eq!(errno(), libc::ENOMEM);
            // A wireless NIC with no real-time kernel.
            assert_eq!(ifindex("wlan0"), 2);
            assert!(std::fs::read_to_string("/sys/kernel/realtime").is_err());
        });
}

#[test]
fn unprivileged_preset_has_the_hardware_but_not_the_rights() {
    Sim::builder()
        .host(EasyBuilder::unprivileged().build())
        .build()
        .run(|| {
            // Same NIC as realtime()...
            assert_eq!(ifindex("eth0"), 2);
            // ...but scheduling is denied.
            assert_eq!(set_fifo(80), -1);
            assert_eq!(errno(), libc::EPERM);
        });
}

#[test]
fn minimal_preset_has_no_interfaces() {
    Sim::builder()
        .host(EasyBuilder::minimal().build())
        .build()
        .run(|| {
            assert_eq!(ifindex("eth0"), 0);
            assert_eq!(errno(), libc::ENODEV);
        });
}

#[test]
fn tweaks_compose_on_a_preset() {
    let host = EasyBuilder::realtime()
        .cpus(4)
        .privileged(false)
        .nic("eth1", 3, std::net::Ipv4Addr::new(10, 0, 0, 99))
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(
            std::fs::read_to_string("/sys/devices/system/cpu/online").unwrap(),
            "0-3\n"
        );
        // privileged(false) revoked the caps.
        assert_eq!(set_fifo(80), -1);
        assert_eq!(errno(), libc::EPERM);
        // Both the preset NIC and the added one resolve.
        assert_eq!(ifindex("eth0"), 2);
        assert_eq!(ifindex("eth1"), 3);
    });
}
