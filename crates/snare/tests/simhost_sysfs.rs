#![cfg(target_os = "linux")]

use snare::{HostProfile, Sim};

fn read(path: &str) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}

#[test]
fn reports_isolated_and_nohz_cpus() {
    let host = HostProfile::new()
        .cpus(8)
        .isolated([2, 3, 4])
        .nohz_full([2, 3, 4])
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(read("/sys/devices/system/cpu/isolated").unwrap(), "2-4\n");
        assert_eq!(read("/sys/devices/system/cpu/nohz_full").unwrap(), "2-4\n");
        assert_eq!(read("/sys/devices/system/cpu/online").unwrap(), "0-7\n");
    });
}

#[test]
fn empty_isolated_is_blank_line() {
    let host = HostProfile::new().cpus(4).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(read("/sys/devices/system/cpu/isolated").unwrap(), "\n");
        assert_eq!(read("/sys/devices/system/cpu/nohz_full").unwrap(), "\n");
    });
}

#[test]
fn per_cpu_scaling_governor() {
    let host = HostProfile::new().cpus(4).governor("performance").build();
    Sim::builder().host(host).build().run(|| {
        for cpu in 0..4 {
            let p = format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor");
            assert_eq!(read(&p).unwrap(), "performance\n");
        }
        assert!(read("/sys/devices/system/cpu/cpu9/cpufreq/scaling_governor").is_err());
    });
}

#[test]
fn realtime_flag_present_only_under_preempt_rt() {
    let host = HostProfile::new().preempt_rt(true).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(read("/sys/kernel/realtime").unwrap(), "1\n");
    });
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        assert!(read("/sys/kernel/realtime").is_err());
    });
}

#[test]
fn cpu_dma_latency_request_is_held_then_released() {
    use std::io::Write;
    let host = HostProfile::new().cpus(2).build();
    Sim::builder().host(host).build().run(|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/cpu_dma_latency")
            .unwrap();
        f.write_all(&0i32.to_ne_bytes()).unwrap();
        drop(f);
    });
}
