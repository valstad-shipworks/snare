#![cfg(target_os = "linux")]

//! Real-time host facts and the calls that use them, on the machine under test against a
//! `SimHost` built from that machine: its CPU sets and PREEMPT_RT marker as `/sys` shows them,
//! and the scheduling, affinity, priority, memory-locking and `/dev/cpu_dma_latency` calls a
//! real-time program makes, run with the privileges the runner really has (root and
//! `CAP_SYS_NICE`/`CAP_IPC_LOCK` on a tuned host, where the Docker `*_os_truth` runs in
//! tests/rlimits.rs have every gate closed). The real calls run in a forked child, so the test
//! process keeps its policy, affinity and locks.
//!
//! References: man 2 sched_setscheduler, sched_setaffinity, setpriority, mlockall, getrlimit;
//! Documentation/ABI/testing/sysfs-devices-system-cpu (`online`, `isolated`, `nohz_full`);
//! Documentation/admin-guide/pm/cpuidle.rst and Documentation/power/pm_qos_interface.rst
//! (`/dev/cpu_dma_latency`); kernel/ksysfs.c of the -rt patch set (`/sys/kernel/realtime`).
//! `sched_setattr(2)` (`SCHED_DEADLINE`) is not modelled and so not compared: in a sim it would
//! reach the real kernel.

#[path = "support/hw.rs"]
mod hw;

use snare::{HostProfile, Privileges, Sim};

fn errno() -> i64 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64
}

fn rc(r: i32) -> i64 {
    if r == 0 { 0 } else { errno() }
}

/// A kernel cpu list (`0-3,8,10-11`); anything else, such as `(null)`, is no CPUs.
fn parse_cpus(s: &str) -> Vec<usize> {
    s.trim()
        .split(',')
        .filter(|p| !p.is_empty())
        .filter_map(|p| match p.split_once('-') {
            Some((a, b)) => Some(a.parse().ok()?..=b.parse().ok()?),
            None => {
                let n = p.parse().ok()?;
                Some(n..=n)
            }
        })
        .flatten()
        .collect()
}

fn read(path: &str) -> Result<String, i32> {
    std::fs::read_to_string(path).map_err(|e| e.raw_os_error().unwrap_or(-1))
}

/// A `HostProfile` with this machine's CPUs, CPU sets, governor, PREEMPT_RT marker and the
/// running process's capabilities.
fn real_profile() -> HostProfile {
    snare::real(|| {
        let possible = read("/sys/devices/system/cpu/possible")
            .map(|s| parse_cpus(&s))
            .unwrap_or_default();
        let count = possible.iter().max().map_or(1, |m| m + 1);
        let mut p = HostProfile::new()
            .cpus(count)
            .online(
                read("/sys/devices/system/cpu/online")
                    .map(|s| parse_cpus(&s))
                    .unwrap_or_default(),
            )
            .isolated(
                read("/sys/devices/system/cpu/isolated")
                    .map(|s| parse_cpus(&s))
                    .unwrap_or_default(),
            )
            .nohz_full(
                read("/sys/devices/system/cpu/nohz_full")
                    .map(|s| parse_cpus(&s))
                    .unwrap_or_default(),
            )
            .preempt_rt(read("/sys/kernel/realtime").is_ok_and(|s| s.trim() == "1"));
        if let Ok(g) = read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") {
            p = p.governor(g.trim());
        }
        let privileges = Privileges::from_real_process().unwrap();
        p = p.root(privileges.root);
        for (held, cap) in [
            (privileges.sys_nice, hw::CAP_SYS_NICE),
            (privileges.ipc_lock, hw::CAP_IPC_LOCK),
        ] {
            if held {
                p = p.cap(cap as i32);
            }
        }
        p
    })
}

fn sim() -> Sim {
    Sim::builder()
        .host(real_profile().build())
        .privileges(Privileges::from_real_process().unwrap())
        .build()
}

fn facts() -> Vec<(&'static str, Result<String, i32>)> {
    let mut out: Vec<(&'static str, Result<String, i32>)> = [
        "/sys/devices/system/cpu/online",
        "/sys/devices/system/cpu/isolated",
        "/sys/devices/system/cpu/nohz_full",
        "/sys/kernel/realtime",
    ]
    .into_iter()
    .map(|p| (p, read(p)))
    .collect();
    out.push((
        "sysconf(_SC_NPROCESSORS_ONLN)",
        Ok(unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.to_string()),
    ));
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) };
    out.push((
        "sched_getaffinity count",
        if r == 0 {
            Ok(unsafe { libc::CPU_COUNT(&set) }.to_string())
        } else {
            Err(errno() as i32)
        },
    ));
    out
}

/// The CPU facts as `/sys`, `sysconf` and `sched_getaffinity` report them.
#[test]
fn hw_rt_host_facts_match() {
    let real = snare::real(facts);
    let simulated = sim().run(facts);
    eprintln!("{}\nreal: {real:#?}", hw::hw().summary());
    for (r, s) in real.iter().zip(&simulated) {
        if r.1 == Err(libc::ENOENT) && r.0 == "/sys/devices/system/cpu/nohz_full" {
            hw::note(&format!(
                "{} is absent here (no CONFIG_NO_HZ_FULL); the sim always renders it ({:?})",
                r.0, s.1
            ));
            continue;
        }
        // With CONFIG_CPUMASK_OFFSTACK and no nohz_full= argument the mask is never allocated,
        // and the attribute prints the null cpumask pointer.
        if r.1.as_deref() == Ok("(null)\n") && r.0 == "/sys/devices/system/cpu/nohz_full" {
            hw::note(&format!(
                "{} is an unallocated mask here; the sim renders an empty set ({:?})",
                r.0, s.1
            ));
            continue;
        }
        assert_eq!(s, r);
    }
    if hw::hw().preempt_rt && real[3].1.is_err() {
        hw::note(
            "a PREEMPT_RT kernel without /sys/kernel/realtime (mainline RT): HostProfile::preempt_rt(true) would render the file",
        );
    }
    let governor = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor";
    let real_gov = snare::real(|| read(governor));
    let sim_gov = sim().run(|| read(governor));
    if real_gov.is_err() {
        hw::note(&format!(
            "no cpufreq on this host ({real_gov:?}); the sim always renders {governor} ({sim_gov:?})"
        ));
    } else {
        assert_eq!(sim_gov, real_gov, "{governor}");
    }
}

/// The CPU to pin to: the last isolated one, else the last online one.
fn pin_cpu() -> usize {
    snare::real(|| {
        let isolated = read("/sys/devices/system/cpu/isolated")
            .map(|s| parse_cpus(&s))
            .unwrap_or_default();
        let online = read("/sys/devices/system/cpu/online")
            .map(|s| parse_cpus(&s))
            .unwrap_or_default();
        isolated.last().or(online.last()).copied().unwrap_or(0)
    })
}

static mut PIN: usize = 0;

/// The real-time setup sequence a tuned program runs, each step's result in `out`.
fn sequence(out: &mut [i64; 64]) {
    let mut i = 0;
    let mut put = |v: i64| {
        out[i] = v;
        i += 1;
    };
    let sched = |policy: i32, prio: i32| {
        let p = libc::sched_param {
            sched_priority: prio,
        };
        rc(unsafe { libc::sched_setscheduler(0, policy, &p) })
    };
    put(i64::from(unsafe {
        libc::sched_get_priority_max(libc::SCHED_FIFO)
    }));
    put(i64::from(unsafe {
        libc::sched_get_priority_min(libc::SCHED_FIFO)
    }));
    put(i64::from(unsafe {
        libc::sched_get_priority_max(libc::SCHED_RR)
    }));
    put(sched(libc::SCHED_FIFO, 1));
    put(sched(libc::SCHED_FIFO, 50));
    put(sched(libc::SCHED_FIFO, 99));
    put(i64::from(unsafe { libc::sched_getscheduler(0) }));
    let mut sp = libc::sched_param { sched_priority: 0 };
    put(rc(unsafe { libc::sched_getparam(0, &mut sp) }));
    put(i64::from(sp.sched_priority));
    put(sched(libc::SCHED_RR, 10));
    let p = libc::sched_param { sched_priority: 20 };
    put(i64::from(unsafe {
        libc::pthread_setschedparam(libc::pthread_self(), libc::SCHED_FIFO, &p)
    }));
    let mut policy = 0;
    let mut got = libc::sched_param { sched_priority: 0 };
    put(i64::from(unsafe {
        libc::pthread_getschedparam(libc::pthread_self(), &mut policy, &mut got)
    }));
    put(i64::from(policy));
    put(i64::from(got.sched_priority));
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe { libc::CPU_SET(PIN, &mut set) };
    put(rc(unsafe {
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set)
    }));
    let mut back: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    put(rc(unsafe {
        libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut back)
    }));
    put(i64::from(unsafe { libc::CPU_COUNT(&back) }));
    put(i64::from(unsafe { libc::CPU_ISSET(PIN, &back) }));
    put(rc(unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, -20) }));
    put(rc(unsafe {
        libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE)
    }));
    put(rc(unsafe { libc::munlockall() }));
    let fd = unsafe {
        libc::open(
            c"/dev/cpu_dma_latency".as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC,
        )
    };
    put(if fd >= 0 { 0 } else { errno() });
    if fd >= 0 {
        let zero = 0i32;
        let n = unsafe { libc::write(fd, (&zero as *const i32).cast(), 4) };
        put(if n == 4 { 0 } else { errno() });
        unsafe { libc::close(fd) };
    } else {
        put(-1);
    }
    put(sched(libc::SCHED_OTHER, 0));
    put(i64::from(unsafe { libc::sched_getscheduler(0) }));
}

/// Runs `f` in a forked child of the real process and returns what it wrote; the child makes only
/// system calls, so no lock another test thread holds is touched.
fn in_child(f: fn(&mut [i64; 64])) -> [i64; 64] {
    snare::real(|| {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let mut out = [0i64; 64];
            f(&mut out);
            unsafe {
                libc::write(fds[1], out.as_ptr().cast(), std::mem::size_of_val(&out));
                libc::_exit(0);
            }
        }
        unsafe { libc::close(fds[1]) };
        let mut out = [0i64; 64];
        let want = std::mem::size_of_val(&out);
        let mut got = 0;
        while got < want {
            let n = unsafe {
                libc::read(
                    fds[0],
                    out.as_mut_ptr().cast::<u8>().add(got).cast(),
                    want - got,
                )
            };
            assert!(n > 0, "child wrote {got} of {want} bytes");
            got += n as usize;
        }
        let mut status = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
            libc::close(fds[0]);
        }
        out
    })
}

#[test]
fn hw_rt_scheduling_matches() {
    unsafe { PIN = pin_cpu() };
    let real = in_child(sequence);
    let before = snare::real(|| unsafe { libc::sched_getscheduler(0) });
    let mut simulated = [0i64; 64];
    sim().run(|| sequence(&mut simulated));
    let after = snare::real(|| unsafe { libc::sched_getscheduler(0) });
    assert_eq!(
        after, before,
        "the sim's calls stayed out of the real scheduler"
    );
    let names = [
        "prio_max(FIFO)",
        "prio_min(FIFO)",
        "prio_max(RR)",
        "FIFO 1",
        "FIFO 50",
        "FIFO 99",
        "getscheduler",
        "getparam",
        "getparam prio",
        "RR 10",
        "pthread_setschedparam FIFO 20",
        "pthread_getschedparam",
        "  policy",
        "  prio",
        "setaffinity",
        "getaffinity",
        "  count",
        "  isset",
        "setpriority -20",
        "mlockall",
        "munlockall",
        "open cpu_dma_latency",
        "write 0",
        "OTHER 0",
        "getscheduler",
    ];
    let h = hw::hw();
    let no_dma_latency = real[21] == i64::from(libc::ENOENT) || real[21] == i64::from(libc::EACCES);
    if real[21] == i64::from(libc::ENOENT) {
        hw::note("/dev/cpu_dma_latency is absent here; the sim always has it");
    } else if real[21] == i64::from(libc::EACCES) {
        hw::note("/dev/cpu_dma_latency is root-only here; the sim opens it without privilege");
    }
    for (i, name) in names.iter().enumerate() {
        if no_dma_latency && (i == 21 || i == 22) {
            continue;
        }
        assert_eq!(
            simulated[i],
            real[i],
            "step {i} {name} (root {}, CAP_SYS_NICE {}, CAP_IPC_LOCK {}, PREEMPT_RT {}, pinned to {})",
            h.root,
            h.cap(hw::CAP_SYS_NICE),
            h.cap(hw::CAP_IPC_LOCK),
            h.preempt_rt,
            unsafe { PIN }
        );
    }
}
