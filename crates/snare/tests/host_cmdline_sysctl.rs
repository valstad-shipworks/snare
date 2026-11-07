//! A `SimHost`'s `/proc/cmdline` and its sysctl table: the command line derived from the
//! profile's CPU partitioning or given outright, the scheduler sysctls at the kernel's defaults
//! or the profile's, and root's writes checked as kernel/sysctl.c's handlers check them.
#![cfg(target_os = "linux")]

use snare::{HostProfile, Sim};

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn the_command_line_follows_the_profile() {
    let host = HostProfile::new()
        .cpus(8)
        .isolated([4, 5])
        .nohz_full([4, 5, 6])
        .kernel_release("6.18.55")
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(
            read("/proc/cmdline"),
            "BOOT_IMAGE=/boot/vmlinuz-6.18.55 root=/dev/vda1 ro isolcpus=4-5 nohz_full=4-6\n"
        );
    });
    let host = HostProfile::new()
        .kernel_cmdline("rcu_nocbs=2-31 quiet")
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(read("/proc/cmdline"), "rcu_nocbs=2-31 quiet\n");
    });
}

#[test]
fn scheduler_sysctls_start_at_the_kernels_defaults_and_take_valid_writes() {
    let host = HostProfile::new()
        .root(true)
        .sysctl("vm.stat_interval", "10")
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(read("/proc/sys/kernel/sched_rt_runtime_us"), "950000\n");
        assert_eq!(read("/proc/sys/kernel/sched_rt_period_us"), "1000000\n");
        assert_eq!(read("/proc/sys/kernel/timer_migration"), "1\n");
        assert_eq!(read("/proc/sys/vm/stat_interval"), "10\n");

        std::fs::write("/proc/sys/kernel/sched_rt_runtime_us", "-1\n").unwrap();
        assert_eq!(read("/proc/sys/kernel/sched_rt_runtime_us"), "-1\n");
        std::fs::write("/proc/sys/kernel/timer_migration", "0").unwrap();
        assert_eq!(read("/proc/sys/kernel/timer_migration"), "0\n");

        let errno = |r: std::io::Result<()>| r.unwrap_err().raw_os_error();
        assert_eq!(
            errno(std::fs::write("/proc/sys/kernel/timer_migration", "2")),
            Some(libc::EINVAL)
        );
        assert_eq!(
            errno(std::fs::write(
                "/proc/sys/kernel/sched_rt_runtime_us",
                "2000000"
            )),
            Some(libc::EINVAL)
        );
        assert_eq!(
            errno(std::fs::write("/proc/sys/vm/stat_interval", "often")),
            Some(libc::EINVAL)
        );
    });
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let refused = std::fs::write("/proc/sys/kernel/timer_migration", "0").unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
    });
}

#[test]
fn udp_lite_rows_follow_the_simulated_kernel() {
    let rows = |release: &str| {
        let host = HostProfile::new().kernel_release(release).build();
        Sim::builder().host(host).build().run(|| {
            let snmp = read("/proc/net/snmp");
            let snmp6 = read("/proc/net/snmp6");
            (
                snmp.contains("\nUdpLite:"),
                snmp6.contains("\nUdpLite6InDatagrams"),
            )
        })
    };
    assert_eq!(rows("6.12.0"), (true, true));
    assert_eq!(rows("7.0.9-rt5"), (true, true));
    assert_eq!(rows("7.1.0"), (false, false), "Linux 7.1 removed UDP-Lite");
}
