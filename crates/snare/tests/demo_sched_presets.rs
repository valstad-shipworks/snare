#![cfg(target_os = "linux")]

//! End-to-end scheduling setup through the `EasyBuilder` presets: the sequence a real-time thread
//! actually performs — lock memory, go SCHED_FIFO, pin to an isolated CPU, drop nice — and how it
//! degrades on an unprivileged host.
//!
//! man 7 sched / man 2 sched_setscheduler describe the real-time policies; man 2 mlockall the
//! page-locking step; man 2 sched_setaffinity the CPU pinning. The isolated-CPU list itself comes
//! from `isolcpus=` (Documentation/admin-guide/kernel-parameters.txt), surfaced at
//! /sys/devices/system/cpu/isolated.

use snare::{CAP_IPC_LOCK, CAP_SYS_NICE, EasyBuilder, HostProfile, Sim};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn set_scheduler_raw(tid: i64, policy: i32, priority: i32) -> i64 {
    let param = libc::sched_param {
        sched_priority: priority,
    };
    unsafe {
        libc::syscall(
            libc::SYS_sched_setscheduler,
            tid,
            policy,
            &param as *const libc::sched_param,
        )
    }
}

fn pin_to(cpu: usize) -> i32 {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let tid = unsafe { libc::gettid() };
    unsafe {
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &set)
    }
}

#[test]
fn full_realtime_setup_succeeds_on_the_realtime_preset() {
    Sim::builder()
        .host(EasyBuilder::realtime().build())
        .build()
        .run(|| {
            assert_eq!(
                unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) },
                0,
                "lock memory"
            );
            let tid = unsafe { libc::gettid() } as i64;
            assert_eq!(set_scheduler_raw(tid, libc::SCHED_FIFO, 80), 0, "go FIFO");
            assert_eq!(pin_to(3), 0, "pin to an isolated CPU");
            assert_eq!(
                unsafe { libc::setpriority(libc::PRIO_PROCESS, tid as u32, -20) },
                0,
                "drop nice"
            );
            assert_eq!(
                unsafe { libc::sched_getscheduler(tid as i32) },
                libc::SCHED_FIFO
            );
        });
}

#[test]
fn unprivileged_preset_fails_every_privileged_step() {
    Sim::builder()
        .host(EasyBuilder::unprivileged().build())
        .build()
        .run(|| {
            assert_eq!(unsafe { libc::mlockall(libc::MCL_CURRENT) }, -1);
            assert_eq!(errno(), libc::ENOMEM, "past the stock RLIMIT_MEMLOCK");

            let tid = unsafe { libc::gettid() } as i64;
            assert_eq!(set_scheduler_raw(tid, libc::SCHED_FIFO, 80), -1);
            assert_eq!(errno(), libc::EPERM);

            assert_eq!(
                unsafe { libc::setpriority(libc::PRIO_PROCESS, tid as u32, -5) },
                -1
            );
            assert_eq!(errno(), libc::EACCES);

            // Affinity is not privilege-gated, so pinning still works even unprivileged.
            assert_eq!(pin_to(1), 0, "affinity needs no capability");
        });
}

#[test]
fn server_preset_has_nice_and_lock_but_pins_within_sixteen_cpus() {
    // EasyBuilder::server: 16 CPUs, privileged, not a PREEMPT_RT kernel. FIFO, mlock and nice all
    // succeed; affinity to CPU 15 is in range but CPU 16 is not.
    Sim::builder()
        .host(EasyBuilder::server().build())
        .build()
        .run(|| {
            assert_eq!(unsafe { libc::mlockall(libc::MCL_FUTURE) }, 0);
            let tid = unsafe { libc::gettid() } as i64;
            assert_eq!(set_scheduler_raw(tid, libc::SCHED_RR, 10), 0);
            assert_eq!(pin_to(15), 0);
            assert_eq!(pin_to(16), -1);
            assert_eq!(errno(), libc::EINVAL);
        });
}

#[test]
fn laptop_preset_is_the_degradation_path() {
    Sim::builder()
        .host(EasyBuilder::laptop().build())
        .build()
        .run(|| {
            let tid = unsafe { libc::gettid() } as i64;
            assert_eq!(set_scheduler_raw(tid, libc::SCHED_FIFO, 50), -1);
            assert_eq!(errno(), libc::EPERM);
            // A 4-CPU laptop: CPU 3 is valid, CPU 4 is not.
            assert_eq!(pin_to(3), 0);
            assert_eq!(pin_to(4), -1);
            assert_eq!(errno(), libc::EINVAL);
        });
}

#[test]
fn granular_caps_gate_independently() {
    // CAP_SYS_NICE alone enables FIFO but not memory locking; CAP_IPC_LOCK alone the reverse. The
    // two capabilities are checked independently (man 7 capabilities).
    let nice_only = HostProfile::new().cpus(4).cap(CAP_SYS_NICE).build();
    Sim::builder().host(nice_only).build().run(|| {
        let tid = unsafe { libc::gettid() } as i64;
        assert_eq!(set_scheduler_raw(tid, libc::SCHED_FIFO, 20), 0);
        assert_eq!(unsafe { libc::mlockall(libc::MCL_CURRENT) }, -1);
        assert_eq!(errno(), libc::ENOMEM, "past the stock RLIMIT_MEMLOCK");
    });

    let lock_only = HostProfile::new().cpus(4).cap(CAP_IPC_LOCK).build();
    Sim::builder().host(lock_only).build().run(|| {
        let tid = unsafe { libc::gettid() } as i64;
        assert_eq!(unsafe { libc::mlockall(libc::MCL_CURRENT) }, 0);
        assert_eq!(set_scheduler_raw(tid, libc::SCHED_FIFO, 20), -1);
        assert_eq!(errno(), libc::EPERM);
    });
}
