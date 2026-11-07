//! A `SimHost`'s kernel: per-CPU threads (`ksoftirqd/N`, and on `PREEMPT_RT` `ktimers/N`,
//! `rcuc/N`, `irq_work/N` at `SCHED_FIFO` 1, bound to their CPU), forced-threaded interrupt
//! handlers (`irq/<n>-<name>` at `SCHED_FIFO` 50, following their line's affinity), NAPI
//! instances with their `napi/<if>-<id>` threads and the `netdev` netlink dump of them, a queue
//! count change rebuilding an interface's vectors, and the per-queue tuning files under
//! `/sys/class/net/<if>/`.
#![cfg(target_os = "linux")]

use snare::{CAP_NET_ADMIN, CAP_SYS_NICE, Channels, HostProfile, Nic, Sim};

const NETLINK_GENERIC: i32 = 16;
const NETDEV_FAMILY: u16 = 24;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const SIOCETHTOOL: u64 = 0x8946;
const ETHTOOL_SCHANNELS: u32 = 0x3d;

fn host(rt: bool, caps: &[i32], root: bool) -> Sim {
    let mut profile = HostProfile::new()
        .cpus(4)
        .isolated([3])
        .preempt_rt(rt)
        .root(root)
        .nic(
            Nic::new("eth0", 2)
                .msi_irqs([128, 129, 130, 131, 132])
                .channels(Channels {
                    combined_max: 4,
                    other_max: 1,
                    combined: 2,
                    other: 1,
                    ..Channels::default()
                }),
        )
        .irq(9, "acpi");
    for &cap in caps {
        profile = profile.cap(cap);
    }
    Sim::builder().host(profile.build()).build()
}

fn kthreads() -> Vec<(i32, String)> {
    let mut out: Vec<(i32, String)> = std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .filter_map(|pid: i32| {
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
            Some((pid, comm.trim_end().to_string()))
        })
        .collect();
    out.sort();
    out
}

fn pid_of(name: &str) -> i32 {
    kthreads()
        .into_iter()
        .find(|(_, n)| n == name)
        .unwrap_or_else(|| panic!("no {name} in {:?}", kthreads()))
        .0
}

fn scheduler(pid: i32) -> (i32, i32) {
    let mut param = libc::sched_param { sched_priority: -1 };
    assert_eq!(unsafe { libc::sched_getparam(pid, &mut param) }, 0);
    (
        unsafe { libc::sched_getscheduler(pid) },
        param.sched_priority,
    )
}

fn affinity(pid: i32) -> Vec<usize> {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::cpu_set_t>();
    assert_eq!(unsafe { libc::sched_getaffinity(pid, size, &mut set) }, 0);
    (0..4)
        .filter(|&c| unsafe { libc::CPU_ISSET(c, &set) })
        .collect()
}

fn set_affinity(pid: i32, cpus: &[usize]) -> i32 {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    for &c in cpus {
        unsafe { libc::CPU_SET(c, &mut set) };
    }
    let size = std::mem::size_of::<libc::cpu_set_t>();
    if unsafe { libc::sched_setaffinity(pid, size, &set) } == 0 {
        0
    } else {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    }
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap()
}

fn errno(r: std::io::Result<()>) -> Option<i32> {
    r.err().and_then(|e| e.raw_os_error())
}

fn nl_message(ty: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(body);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out
}

fn attrs(attrs: &[u8]) -> Vec<(u16, u32)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 4 <= attrs.len() {
        let len = u16::from_ne_bytes([attrs[pos], attrs[pos + 1]]) as usize;
        let ty = u16::from_ne_bytes([attrs[pos + 2], attrs[pos + 3]]);
        if len < 8 || pos + len > attrs.len() {
            break;
        }
        out.push((
            ty,
            u32::from_ne_bytes(attrs[pos + 4..pos + 8].try_into().unwrap()),
        ));
        pos += len.next_multiple_of(4);
    }
    out
}

/// Every NAPI instance the `netdev` family dumps, as (ifindex, id, irq, pid).
fn napi_dump() -> Vec<(u32, u32, Option<u32>, Option<u32>)> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_GENERIC) };
    assert!(fd >= 0);
    let request = nl_message(NETDEV_FAMILY, NLM_F_REQUEST | NLM_F_DUMP, 7, &[11, 1, 0, 0]);
    let sent = unsafe { libc::send(fd, request.as_ptr().cast(), request.len(), 0) };
    assert_eq!(sent, request.len() as isize);
    let mut reply = vec![0u8; 8192];
    let got = unsafe { libc::recv(fd, reply.as_mut_ptr().cast(), reply.len(), 0) };
    assert!(got > 0);
    reply.truncate(got as usize);
    unsafe { libc::close(fd) };
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 16 <= reply.len() {
        let len = u32::from_ne_bytes(reply[pos..pos + 4].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes([reply[pos + 4], reply[pos + 5]]);
        if ty == NETDEV_FAMILY {
            let a = attrs(&reply[pos + 20..pos + len]);
            let get = |want| a.iter().find(|(t, _)| *t == want).map(|(_, v)| *v);
            out.push((get(1).unwrap(), get(2).unwrap(), get(3), get(4)));
        }
        pos += len.next_multiple_of(4);
    }
    out
}

fn set_combined(n: u32) -> std::io::Result<()> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(fd >= 0);
    let mut channels = [ETHTOOL_SCHANNELS, 0, 0, 0, 0, 0, 0, 1, n];
    let mut ifr = [0u8; 40];
    ifr[..4].copy_from_slice(b"eth0");
    let data = channels.as_mut_ptr() as usize;
    ifr[16..24].copy_from_slice(&data.to_ne_bytes());
    let rc = unsafe { libc::ioctl(fd, SIOCETHTOOL as _, ifr.as_mut_ptr()) };
    let result = if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    };
    unsafe { libc::close(fd) };
    result
}

#[test]
fn a_preempt_rt_kernel_runs_its_per_cpu_threads_bound_at_fifo_1() {
    host(true, &[CAP_SYS_NICE], false).run(|| {
        for cpu in 0..4 {
            for kind in ["ktimers", "rcuc", "irq_work"] {
                let pid = pid_of(&format!("{kind}/{cpu}"));
                assert_eq!(scheduler(pid), (libc::SCHED_FIFO, 1));
                assert_eq!(affinity(pid), [cpu]);
            }
            let ksoftirqd = pid_of(&format!("ksoftirqd/{cpu}"));
            assert_eq!(scheduler(ksoftirqd), (libc::SCHED_OTHER, 0));
        }
        let ktimers = pid_of("ktimers/2");
        assert_eq!(
            set_affinity(ktimers, &[0]),
            libc::EINVAL,
            "a bound kthread stays"
        );
        let p = libc::sched_param { sched_priority: 99 };
        assert_eq!(
            unsafe { libc::sched_setscheduler(ktimers, libc::SCHED_FIFO, &p) },
            0
        );
        assert_eq!(scheduler(ktimers), (libc::SCHED_FIFO, 99));
        let me = unsafe { libc::gettid() };
        let tasks: Vec<i32> = std::fs::read_dir("/proc/self/task")
            .unwrap()
            .map(|e| e.unwrap().file_name().to_str().unwrap().parse().unwrap())
            .collect();
        assert!(
            tasks.contains(&me)
                && tasks
                    .iter()
                    .all(|t| kthreads().iter().all(|(pid, _)| pid != t)),
            "kernel threads are processes of their own, not the caller's tasks"
        );
    });
}

#[test]
fn a_stock_kernel_has_only_ksoftirqd_and_no_irq_threads() {
    host(false, &[], false).run(|| {
        let names: Vec<String> = kthreads().into_iter().map(|(_, n)| n).collect();
        assert!(names.iter().any(|n| n == "ksoftirqd/0"));
        assert!(
            !names
                .iter()
                .any(|n| n.starts_with("ktimers/") || n.starts_with("irq/"))
        );
    });
}

#[test]
fn an_irq_thread_follows_its_line() {
    host(true, &[CAP_SYS_NICE], true).run(|| {
        let thread = pid_of("irq/129-eth0-TxRx-0");
        assert_eq!(scheduler(thread), (libc::SCHED_FIFO, 50));
        assert_eq!(affinity(thread), [0]);
        assert!(pid_of("irq/128-eth0") > 0 && pid_of("irq/9-acpi") > 0);
        std::fs::write("/proc/irq/129/smp_affinity_list", "1-2").unwrap();
        assert_eq!(affinity(thread), [1], "the effective CPU of its line");
        assert_eq!(set_affinity(thread, &[2]), 0, "an irq thread is not bound");
        assert_eq!(
            read("/proc/interrupts")
                .lines()
                .last()
                .unwrap()
                .split_whitespace()
                .last(),
            Some("eth0-TxRx-1")
        );
    });
}

#[test]
fn threaded_napi_starts_a_thread_per_instance_and_netlink_reports_them() {
    host(true, &[CAP_NET_ADMIN], true).run(|| {
        assert_eq!(
            napi_dump(),
            [(2, 8193, Some(129), None), (2, 8194, Some(130), None)]
        );
        std::fs::write("/sys/class/net/eth0/threaded", "1").unwrap();
        let first = pid_of("napi/eth0-8193") as u32;
        let second = pid_of("napi/eth0-8194") as u32;
        assert_eq!(
            napi_dump(),
            [
                (2, 8193, Some(129), Some(first)),
                (2, 8194, Some(130), Some(second))
            ]
        );
        assert_eq!(scheduler(first as i32), (libc::SCHED_OTHER, 0));
        assert_eq!(affinity(first as i32), [0, 1, 2, 3]);
        std::fs::write("/sys/class/net/eth0/threaded", "0").unwrap();
        assert!(!kthreads().iter().any(|(_, n)| n.starts_with("napi/")));
        assert_eq!(napi_dump()[0].3, None);
    });
}

#[test]
fn changing_the_queue_count_requests_every_vector_anew() {
    host(true, &[CAP_NET_ADMIN, CAP_SYS_NICE], true).run(|| {
        std::fs::write("/sys/class/net/eth0/threaded", "1").unwrap();
        std::fs::write("/proc/irq/129/smp_affinity_list", "2").unwrap();
        let old_thread = pid_of("irq/129-eth0-TxRx-0");
        let p = libc::sched_param { sched_priority: 90 };
        let napi = pid_of("napi/eth0-8193");
        assert_eq!(
            unsafe { libc::sched_setscheduler(napi, libc::SCHED_FIFO, &p) },
            0
        );

        set_combined(1).unwrap();
        let mut lines: Vec<String> = std::fs::read_dir("/proc/irq")
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        lines.sort();
        assert_eq!(lines, ["128", "129", "9", "default_smp_affinity"]);
        assert_eq!(
            read("/proc/irq/129/smp_affinity_list"),
            "0-3\n",
            "back on the default"
        );
        let new_thread = pid_of("irq/129-eth0-TxRx-0");
        assert_ne!(new_thread, old_thread);
        assert_eq!(affinity(new_thread), [0]);
        let dump = napi_dump();
        assert_eq!(dump.len(), 1);
        let (_, id, irq, pid) = dump[0];
        assert_eq!((id, irq), (8195, Some(129)));
        assert_eq!(
            scheduler(pid.unwrap() as i32),
            (libc::SCHED_OTHER, 0),
            "a recreated NAPI thread loses the priority its predecessor was given"
        );
        assert!(!kthreads().iter().any(|(_, n)| n == "napi/eth0-8193"));
    });
}

#[test]
fn queue_tuning_files_read_and_write_as_the_kernel_has_them() {
    host(true, &[CAP_NET_ADMIN], true).run(|| {
        let base = "/sys/class/net/eth0";
        assert_eq!(read(&format!("{base}/queues/rx-0/rps_cpus")), "0\n");
        assert_eq!(
            read(&format!("{base}/queues/tx-1/byte_queue_limits/limit_max")),
            "1879048192\n"
        );
        std::fs::write(format!("{base}/queues/rx-0/rps_cpus"), "a").unwrap();
        assert_eq!(
            read(&format!("{base}/queues/rx-0/rps_cpus")),
            "2\n",
            "CPU 3 is isolated"
        );
        assert_eq!(
            errno(std::fs::write(format!("{base}/queues/rx-1/rps_cpus"), "8")),
            Some(libc::EINVAL)
        );
        std::fs::write(format!("{base}/queues/tx-1/xps_cpus"), "c").unwrap();
        assert_eq!(read(&format!("{base}/queues/tx-1/xps_cpus")), "c\n");
        std::fs::write(
            format!("{base}/queues/tx-0/byte_queue_limits/limit_max"),
            "3000",
        )
        .unwrap();
        assert_eq!(
            read(&format!("{base}/queues/tx-0/byte_queue_limits/limit_max")),
            "3000\n"
        );
        std::fs::write(format!("{base}/napi_defer_hard_irqs"), "2").unwrap();
        std::fs::write(format!("{base}/gro_flush_timeout"), "200000").unwrap();
        assert_eq!(read(&format!("{base}/napi_defer_hard_irqs")), "2\n");
        assert_eq!(read(&format!("{base}/gro_flush_timeout")), "200000\n");
        assert_eq!(
            errno(std::fs::write(
                format!("{base}/napi_defer_hard_irqs"),
                "4294967295"
            )),
            Some(libc::ERANGE)
        );
        assert!(std::fs::metadata(format!("{base}/queues/rx-2/rps_cpus")).is_err());
    });
    host(true, &[], true).run(|| {
        assert_eq!(
            errno(std::fs::write(
                "/sys/class/net/eth0/napi_defer_hard_irqs",
                "1"
            )),
            Some(libc::EPERM)
        );
    });
}
