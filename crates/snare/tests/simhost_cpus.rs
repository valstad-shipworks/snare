//! A `SimHost`'s CPU count is what the code under test counts: `sysconf(_SC_NPROCESSORS_CONF)`
//! is every CPU and `_SC_NPROCESSORS_ONLN` the online ones (man 3 sysconf), and
//! `std::thread::available_parallelism` follows (from `sched_getaffinity` on Linux, `sysconf` on
//! macOS). Without a host, the counts are the machine's.
#![cfg(unix)]

use snare::{HostProfile, Sim};

fn counts() -> (libc::c_long, libc::c_long, usize) {
    (
        unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) },
        unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) },
        std::thread::available_parallelism().unwrap().get(),
    )
}

#[test]
fn the_profiles_cpus_are_counted() {
    let host = HostProfile::new().cpus(3).build();
    assert_eq!(Sim::builder().host(host).build().run(counts), (3, 3, 3));
}

#[test]
fn offline_cpus_are_configured_but_not_online() {
    let host = HostProfile::new().cpus(4).online([0, 2]).build();
    let (conf, online, _) = Sim::builder().host(host).build().run(counts);
    assert_eq!((conf, online), (4, 2));
}

#[test]
fn each_sim_counts_its_own_cpus() {
    let a = Sim::builder()
        .host(HostProfile::new().cpus(3).build())
        .build()
        .run(|| std::thread::spawn(counts).join().unwrap());
    let b = Sim::builder()
        .host(HostProfile::new().cpus(5).build())
        .build()
        .run(counts);
    assert_eq!((a, b), ((3, 3, 3), (5, 5, 5)));
}

#[test]
fn without_a_host_the_machines_counts_apply() {
    let outside = counts();
    assert_eq!(Sim::builder().build().run(counts), outside);
}

/// The `cpuN` names `/proc/stat` lists and each one's idle ticks, as sysinfo reads them.
#[cfg(target_os = "linux")]
fn proc_stat_cpus() -> Vec<(String, u64)> {
    std::fs::read_to_string("/proc/stat")
        .unwrap()
        .lines()
        .skip(1)
        .take_while(|line| line.starts_with("cpu"))
        .map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields[0].to_string(), fields[4].parse().unwrap())
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn proc_cpuinfo_processors() -> Vec<usize> {
    std::fs::read_to_string("/proc/cpuinfo")
        .unwrap()
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.trim() == "processor")
        .map(|(_, n)| n.trim().parse().unwrap())
        .collect()
}

#[cfg(target_os = "linux")]
#[test]
fn proc_stat_lists_the_online_cpus() {
    let host = HostProfile::new().cpus(4).online([0, 2]).build();
    let (before, after, text) = Sim::builder().host(host).build().run(|| {
        let before = proc_stat_cpus();
        std::thread::sleep(std::time::Duration::from_millis(200));
        (
            before,
            proc_stat_cpus(),
            std::fs::read_to_string("/proc/stat").unwrap(),
        )
    });
    let names: Vec<&str> = before.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["cpu0", "cpu2"]);
    assert!(after[0].1 >= before[0].1 + 20, "{before:?} then {after:?}");
    assert_eq!(after[0].1, after[1].1);
    let total: Vec<&str> = text.lines().next().unwrap().split(' ').collect();
    assert_eq!(total[..2], ["cpu", ""]);
    assert!(text.lines().any(|l| l.starts_with("btime ")), "{text}");
}

#[cfg(target_os = "linux")]
#[test]
fn proc_cpuinfo_has_an_entry_per_online_cpu() {
    let host = HostProfile::new().cpus(4).online([0, 2, 3]).build();
    let (processors, text) = Sim::builder().host(host).build().run(|| {
        (
            proc_cpuinfo_processors(),
            std::fs::read_to_string("/proc/cpuinfo").unwrap(),
        )
    });
    assert_eq!(processors, [0, 2, 3]);
    let machine = std::fs::read_to_string("/proc/cpuinfo").unwrap();
    let first = |text: &str| {
        text.split("\n\n")
            .next()
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("processor"))
            .filter(|line| !line.starts_with("siblings") && !line.starts_with("cpu cores"))
            .filter(|line| !line.starts_with("cpu MHz") && !line.starts_with("bogomips"))
            .filter(|line| !line.contains("id\t") && !line.starts_with("apicid"))
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    assert_eq!(first(&text), first(&machine));
}

#[cfg(target_os = "linux")]
#[test]
fn without_a_host_proc_listings_are_the_machines() {
    let outside = (proc_stat_cpus().len(), proc_cpuinfo_processors());
    let inside = Sim::builder()
        .build()
        .run(|| (proc_stat_cpus().len(), proc_cpuinfo_processors()));
    assert_eq!(inside, outside);
}

/// `host_processor_info` of `flavor` on the task's host port: the processor count and the
/// records, freed as sysinfo frees them.
#[cfg(target_os = "macos")]
fn processor_info(flavor: libc::c_int) -> (libc::c_int, u32, Vec<libc::c_int>) {
    let mut count = 0;
    let mut info: libc::processor_info_array_t = std::ptr::null_mut();
    let mut words = 0;
    #[allow(deprecated)]
    unsafe {
        let host = libc::mach_host_self();
        let kr = libc::host_processor_info(host, flavor, &mut count, &mut info, &mut words);
        if kr != libc::KERN_SUCCESS {
            return (kr, 0, Vec::new());
        }
        let records = std::slice::from_raw_parts(info, words as usize).to_vec();
        libc::vm_deallocate(
            libc::mach_task_self(),
            info as libc::vm_address_t,
            words as usize * std::mem::size_of::<libc::c_int>(),
        );
        (kr, count, records)
    }
}

#[cfg(target_os = "macos")]
#[test]
fn host_processor_info_lists_the_profiles_cpus() {
    let host = HostProfile::new().cpus(4).online([0, 1, 3]).build();
    let (basic, before, after) = Sim::builder().host(host).build().run(|| {
        let basic = processor_info(libc::PROCESSOR_BASIC_INFO);
        let before = processor_info(libc::PROCESSOR_CPU_LOAD_INFO);
        std::thread::sleep(std::time::Duration::from_millis(200));
        (basic, before, processor_info(libc::PROCESSOR_CPU_LOAD_INFO))
    });
    let real = processor_info(libc::PROCESSOR_BASIC_INFO).2;
    assert_eq!((basic.0, basic.1, basic.2.len()), (0, 4, 20));
    for (cpu, record) in basic.2.chunks(5).enumerate() {
        let running = cpu != 2;
        assert_eq!(record[..2], real[..2], "cpu type of {cpu}");
        assert_eq!(
            record[2..],
            [running.into(), cpu as libc::c_int, (cpu == 0).into()]
        );
    }
    assert_eq!((before.0, before.1, before.2.len()), (0, 4, 16));
    let idle = |load: &[libc::c_int], cpu: usize| load[cpu * 4 + libc::CPU_STATE_IDLE as usize];
    assert!(idle(&after.2, 0) >= idle(&before.2, 0) + 20);
    assert_eq!(idle(&after.2, 2), 0);
    assert_eq!(idle(&after.2, 3), idle(&after.2, 0));
    let busy: Vec<_> = after.2.chunks(4).map(|t| (t[0], t[1], t[3])).collect();
    assert_eq!(busy, [(0, 0, 0); 4]);
}

#[cfg(target_os = "macos")]
#[test]
fn without_a_host_host_processor_info_is_the_machines() {
    let outside = processor_info(libc::PROCESSOR_BASIC_INFO);
    let inside = Sim::builder()
        .build()
        .run(|| processor_info(libc::PROCESSOR_BASIC_INFO));
    assert_eq!(inside, outside);
}

#[cfg(target_os = "macos")]
#[test]
fn other_flavors_and_ports_reach_the_kernel() {
    let host = HostProfile::new().cpus(3).build();
    let (temperature, null_port) = Sim::builder().host(host).build().run(|| {
        let temperature = processor_info(3).0;
        let mut count = 0;
        let mut info: libc::processor_info_array_t = std::ptr::null_mut();
        let mut words = 0;
        let null_port = unsafe {
            libc::host_processor_info(
                libc::MACH_PORT_NULL as libc::mach_port_t,
                libc::PROCESSOR_CPU_LOAD_INFO,
                &mut count,
                &mut info,
                &mut words,
            )
        };
        (temperature, null_port)
    });
    assert_eq!(temperature, processor_info(3).0);
    assert_ne!(null_port, libc::KERN_SUCCESS);
}

#[test]
fn other_sysconf_names_reach_libc() {
    let outside = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let host = HostProfile::new().cpus(3).build();
    let inside = Sim::builder()
        .host(host)
        .build()
        .run(|| unsafe { libc::sysconf(libc::_SC_PAGESIZE) });
    assert_eq!(inside, outside);
}
