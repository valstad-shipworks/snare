#![cfg(target_os = "linux")]
//! `EasyBuilder` presets and tweaks, asserted through the calls real tuning code makes:
//! `sched_setscheduler` (man 2 sched_setscheduler), `mlockall` (man 2 mlockall), `if_nametoindex`
//! (man 3 if_nametoindex) and the sysfs/procfs reads in Documentation/ABI/testing/sysfs-class-net,
//! sysfs-devices-system-cpu and man 5 proc. A preset sets host *facts*; whether a call succeeds or
//! returns EPERM follows from the capabilities the preset grants (man 7 capabilities).

use std::ffi::CString;

use snare::{EasyBuilder, Sim};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn set_fifo(priority: i32) -> i64 {
    let tid = unsafe { libc::gettid() };
    let param = libc::sched_param { sched_priority: priority };
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

fn read(path: &str) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}

#[test]
fn server_preset_is_a_large_privileged_non_rt_box() {
    Sim::builder().host(EasyBuilder::server().build()).build().run(|| {
        assert_eq!(read("/sys/devices/system/cpu/online").unwrap(), "0-15\n");
        assert_eq!(read("/sys/devices/system/cpu/isolated").unwrap(), "4-15\n");
        assert_eq!(
            read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").unwrap(),
            "performance\n"
        );
        assert_eq!(read("/proc/sys/net/core/default_qdisc").unwrap(), "fq\n");
        // A production server is not a PREEMPT_RT kernel, so the attribute is absent.
        assert!(read("/sys/kernel/realtime").is_err());
        // Privileged: real-time scheduling and memory locking succeed.
        assert_eq!(set_fifo(90), 0);
        assert_eq!(unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) }, 0);
        // A 9000-MTU (jumbo-frame) NIC.
        assert_eq!(ifindex("eth0"), 2);
        assert_eq!(read("/sys/class/net/eth0/mtu").unwrap(), "9000\n");
        assert_eq!(read("/sys/class/net/eth0/carrier").unwrap(), "1\n");
    });
}

#[test]
fn realtime_preset_reports_preempt_rt_and_isolation() {
    Sim::builder().host(EasyBuilder::realtime().build()).build().run(|| {
        assert_eq!(read("/sys/kernel/realtime").unwrap(), "1\n");
        assert_eq!(read("/sys/devices/system/cpu/nohz_full").unwrap(), "2-7\n");
        assert_eq!(read("/sys/devices/system/cpu/isolated").unwrap(), "2-7\n");
        assert_eq!(
            read("/sys/devices/system/cpu/cpu3/cpufreq/scaling_governor").unwrap(),
            "performance\n"
        );
        assert_eq!(read("/proc/sys/net/core/default_qdisc").unwrap(), "fq\n");
        assert_eq!(set_fifo(80), 0);
    });
}

#[test]
fn laptop_preset_is_powersave_and_unprivileged() {
    Sim::builder().host(EasyBuilder::laptop().build()).build().run(|| {
        assert_eq!(
            read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").unwrap(),
            "powersave\n"
        );
        assert_eq!(read("/proc/sys/net/core/default_qdisc").unwrap(), "fq_codel\n");
        assert_eq!(read("/sys/devices/system/cpu/online").unwrap(), "0-3\n");
        assert!(read("/sys/kernel/realtime").is_err());
        assert_eq!(ifindex("wlan0"), 2);
        // No CAP_SYS_NICE / CAP_IPC_LOCK: the graceful-degradation paths see EPERM.
        assert_eq!(set_fifo(80), -1);
        assert_eq!(errno(), libc::EPERM);
        assert_eq!(unsafe { libc::mlockall(libc::MCL_CURRENT) }, -1);
        assert_eq!(errno(), libc::EPERM);
    });
}

#[test]
fn unprivileged_preset_keeps_the_hardware_loses_the_rights() {
    Sim::builder().host(EasyBuilder::unprivileged().build()).build().run(|| {
        assert_eq!(ifindex("eth0"), 2);
        assert_eq!(read("/sys/kernel/realtime").unwrap(), "1\n");
        assert_eq!(set_fifo(80), -1);
        assert_eq!(errno(), libc::EPERM);
    });
}

#[test]
fn minimal_preset_is_a_blank_single_cpu_slate() {
    Sim::builder().host(EasyBuilder::minimal().build()).build().run(|| {
        assert_eq!(read("/sys/devices/system/cpu/online").unwrap(), "0\n");
        // man 3 if_nametoindex: returns 0 and sets ENODEV for an unknown interface.
        assert_eq!(ifindex("eth0"), 0);
        assert_eq!(errno(), libc::ENODEV);
        assert_eq!(set_fifo(80), -1);
        assert_eq!(errno(), libc::EPERM);
    });
}

#[test]
fn privileged_false_revokes_caps_on_a_privileged_preset() {
    let host = EasyBuilder::server().privileged(false).build();
    Sim::builder().host(host).build().run(|| {
        // The NIC and topology are unchanged...
        assert_eq!(ifindex("eth0"), 2);
        assert_eq!(read("/sys/devices/system/cpu/online").unwrap(), "0-15\n");
        // ...but the process can no longer apply the tuning.
        assert_eq!(set_fifo(80), -1);
        assert_eq!(errno(), libc::EPERM);
        assert_eq!(unsafe { libc::mlockall(libc::MCL_CURRENT) }, -1);
        assert_eq!(errno(), libc::EPERM);
    });
}

#[test]
fn privileged_true_grants_caps_on_an_unprivileged_preset() {
    let host = EasyBuilder::laptop().privileged(true).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(set_fifo(80), 0);
        assert_eq!(unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) }, 0);
    });
}

#[test]
fn realtime_kernel_toggle_controls_the_attribute() {
    let off = EasyBuilder::realtime().realtime_kernel(false).build();
    Sim::builder().host(off).build().run(|| {
        assert!(read("/sys/kernel/realtime").is_err());
    });
    let on = EasyBuilder::server().realtime_kernel(true).build();
    Sim::builder().host(on).build().run(|| {
        assert_eq!(read("/sys/kernel/realtime").unwrap(), "1\n");
    });
}

#[test]
fn without_nics_drops_the_preset_interface() {
    let host = EasyBuilder::realtime().without_nics().build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(ifindex("eth0"), 0);
        assert_eq!(errno(), libc::ENODEV);
    });
}

#[test]
fn nic_and_add_nic_register_extra_interfaces() {
    use snare::Nic;
    let host = EasyBuilder::minimal()
        .nic("eth7", 7, std::net::Ipv4Addr::new(10, 0, 0, 7))
        .add_nic(Nic::new("mgmt0", 8).mtu(1400).operstate("up"))
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(ifindex("eth7"), 7);
        assert_eq!(ifindex("mgmt0"), 8);
        assert_eq!(read("/sys/class/net/mgmt0/mtu").unwrap(), "1400\n");
        assert_eq!(read("/sys/class/net/eth7/mtu").unwrap(), "1500\n");
    });
}

#[test]
fn tweaks_override_preset_topology() {
    let host = EasyBuilder::realtime()
        .cpus(4)
        .isolate([1, 3])
        .governor("schedutil")
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(read("/sys/devices/system/cpu/online").unwrap(), "0-3\n");
        assert_eq!(read("/sys/devices/system/cpu/isolated").unwrap(), "1,3\n");
        assert_eq!(
            read("/sys/devices/system/cpu/cpu2/cpufreq/scaling_governor").unwrap(),
            "schedutil\n"
        );
    });
}
