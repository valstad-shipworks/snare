#![cfg(target_os = "linux")]

use snare::{CAP_IPC_LOCK, CAP_SYS_NICE, HostProfile, Sim};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// fast-talker sets the scheduler through the raw syscall (musl stubs the wrapper).
fn set_scheduler_raw(tid: i64, policy: i32, priority: i32) -> i64 {
    let param = libc::sched_param { sched_priority: priority };
    unsafe {
        libc::syscall(
            libc::SYS_sched_setscheduler,
            tid,
            policy,
            &param as *const libc::sched_param,
        )
    }
}

#[test]
fn gettid_is_a_virtual_tid() {
    let host = HostProfile::new().cpus(4).build();
    Sim::builder().host(host).build().run(|| {
        let a = unsafe { libc::gettid() };
        let b = unsafe { libc::gettid() };
        assert!(a >= 4000, "expected a synthetic tid, got {a}");
        assert_eq!(a, b, "the same thread keeps one tid");
    });
}

#[test]
fn realtime_policy_needs_cap_sys_nice() {
    let host = HostProfile::new().cpus(4).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() } as i64;
        assert_eq!(set_scheduler_raw(tid, libc::SCHED_FIFO, 80), -1);
        assert_eq!(errno(), libc::EPERM);
    });

    let host = HostProfile::new().cpus(4).cap(CAP_SYS_NICE).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() } as i64;
        assert_eq!(set_scheduler_raw(tid, libc::SCHED_FIFO, 80), 0);

        let policy = unsafe { libc::syscall(libc::SYS_sched_getscheduler, tid) };
        assert_eq!(policy as i32, libc::SCHED_FIFO);

        let mut param = libc::sched_param { sched_priority: 0 };
        let rc = unsafe {
            libc::syscall(
                libc::SYS_sched_getparam,
                tid,
                &mut param as *mut libc::sched_param,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(param.sched_priority, 80);
    });
}

#[test]
fn affinity_round_trips_through_named_symbols() {
    let host = HostProfile::new().cpus(8).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() };
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::CPU_ZERO(&mut set);
            libc::CPU_SET(2, &mut set);
            libc::CPU_SET(5, &mut set);
        }
        let rc = unsafe {
            libc::sched_setaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &set)
        };
        assert_eq!(rc, 0);

        let mut read: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::sched_getaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &mut read)
        };
        assert_eq!(rc, 0);
        for cpu in 0..8 {
            let want = cpu == 2 || cpu == 5;
            assert_eq!(unsafe { libc::CPU_ISSET(cpu, &read) }, want, "cpu {cpu}");
        }
    });
}

#[test]
fn affinity_to_out_of_range_cpu_is_einval() {
    let host = HostProfile::new().cpus(2).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() };
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::CPU_ZERO(&mut set);
            libc::CPU_SET(7, &mut set);
        }
        let rc = unsafe {
            libc::sched_setaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &set)
        };
        assert_eq!(rc, -1);
        assert_eq!(errno(), libc::EINVAL);
    });
}

#[test]
fn nice_lowering_needs_cap_and_reads_back() {
    let host = HostProfile::new().cpus(2).cap(CAP_SYS_NICE).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() } as u32;
        assert_eq!(unsafe { libc::setpriority(libc::PRIO_PROCESS, tid, -10) }, 0);
        // The named getpriority returns the nice value directly.
        assert_eq!(unsafe { libc::getpriority(libc::PRIO_PROCESS, tid) }, -10);
        // fast-talker reads it raw as 20 - nice.
        let raw = unsafe { libc::syscall(libc::SYS_getpriority, libc::PRIO_PROCESS, tid) };
        assert_eq!(raw, (20 - (-10)) as i64);
    });

    let host = HostProfile::new().cpus(2).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() } as u32;
        assert_eq!(unsafe { libc::setpriority(libc::PRIO_PROCESS, tid, -10) }, -1);
        assert_eq!(errno(), libc::EACCES);
    });
}

#[test]
fn mlockall_gated_on_cap_ipc_lock() {
    let host = HostProfile::new().cpus(2).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) }, -1);
        assert_eq!(errno(), libc::EPERM);
    });

    let host = HostProfile::new().cpus(2).cap(CAP_IPC_LOCK).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) }, 0);
        assert_eq!(unsafe { libc::munlockall() }, 0);
    });
}
