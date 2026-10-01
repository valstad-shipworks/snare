#![cfg(target_os = "linux")]

//! Scheduling-policy coverage: `sched_setscheduler`/`sched_getscheduler` and the
//! `sched_setparam`/`sched_getparam` priority pair, through both the named libc wrappers and the
//! raw `syscall(SYS_sched_setscheduler, …)` form that musl-linked programs use.
//!
//! man 2 sched_setscheduler: policy is one of SCHED_OTHER/SCHED_BATCH/SCHED_IDLE (the normal
//! policies) or SCHED_FIFO/SCHED_RR (the real-time policies); switching into a real-time policy
//! requires CAP_SYS_NICE (man 7 capabilities). SCHED_RESET_ON_FORK may be OR'd into the policy.

use snare::{CAP_SYS_NICE, HostProfile, Sim};

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

fn get_scheduler_raw(tid: i64) -> i32 {
    unsafe { libc::syscall(libc::SYS_sched_getscheduler, tid) as i32 }
}

fn get_param_raw(tid: i64) -> i32 {
    let mut param = libc::sched_param { sched_priority: -1 };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_sched_getparam,
            tid,
            &mut param as *mut libc::sched_param,
        )
    };
    assert_eq!(rc, 0, "sched_getparam");
    param.sched_priority
}

fn privileged() -> std::sync::Arc<snare::SimHost> {
    HostProfile::new().cpus(4).cap(CAP_SYS_NICE).build()
}

#[test]
fn default_policy_is_sched_other() {
    // man 7 sched: a thread starts life under SCHED_OTHER (the round-robin time-sharing policy),
    // whose numeric value is 0, with a static (real-time) priority of 0.
    Sim::builder().host(privileged()).build().run(|| {
        let tid = unsafe { libc::gettid() };
        assert_eq!(unsafe { libc::sched_getscheduler(tid) }, libc::SCHED_OTHER);
        let mut param = libc::sched_param { sched_priority: -1 };
        assert_eq!(unsafe { libc::sched_getparam(tid, &mut param) }, 0);
        assert_eq!(param.sched_priority, 0);
    });
}

#[test]
fn fifo_and_rr_require_cap_sys_nice() {
    // man 2 sched_setscheduler ERRORS: EPERM when the caller lacks CAP_SYS_NICE for a real-time
    // policy. Without the capability both SCHED_FIFO and SCHED_RR must be refused.
    let host = HostProfile::new().cpus(4).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() } as i64;
        for policy in [libc::SCHED_FIFO, libc::SCHED_RR] {
            assert_eq!(set_scheduler_raw(tid, policy, 50), -1, "policy {policy}");
            assert_eq!(errno(), libc::EPERM, "policy {policy}");
        }
    });
}

#[test]
fn normal_policies_do_not_need_a_capability() {
    // SCHED_OTHER/SCHED_BATCH/SCHED_IDLE are not real-time policies, so man 2 sched_setscheduler
    // does not gate them on CAP_SYS_NICE for an unprivileged self-transition.
    let host = HostProfile::new().cpus(4).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() };
        for policy in [libc::SCHED_OTHER, libc::SCHED_BATCH, libc::SCHED_IDLE] {
            let param = libc::sched_param { sched_priority: 0 };
            let rc = unsafe { libc::sched_setscheduler(tid, policy, &param) };
            assert_eq!(rc, 0, "policy {policy}");
            assert_eq!(unsafe { libc::sched_getscheduler(tid) }, policy);
        }
    });
}

#[test]
fn fifo_round_trips_through_named_wrappers() {
    Sim::builder().host(privileged()).build().run(|| {
        let tid = unsafe { libc::gettid() };
        let param = libc::sched_param { sched_priority: 80 };
        assert_eq!(
            unsafe { libc::sched_setscheduler(tid, libc::SCHED_FIFO, &param) },
            0
        );
        assert_eq!(unsafe { libc::sched_getscheduler(tid) }, libc::SCHED_FIFO);
        let mut got = libc::sched_param { sched_priority: -1 };
        assert_eq!(unsafe { libc::sched_getparam(tid, &mut got) }, 0);
        assert_eq!(got.sched_priority, 80);
    });
}

#[test]
fn rr_round_trips_through_the_raw_syscall() {
    Sim::builder().host(privileged()).build().run(|| {
        let tid = unsafe { libc::gettid() } as i64;
        assert_eq!(set_scheduler_raw(tid, libc::SCHED_RR, 42), 0);
        assert_eq!(get_scheduler_raw(tid), libc::SCHED_RR);
        assert_eq!(get_param_raw(tid), 42);
    });
}

#[test]
fn reset_on_fork_is_masked_for_the_capability_check_and_preserved() {
    // man 2 sched_setscheduler: SCHED_RESET_ON_FORK may be OR'd into the policy word. It must not
    // change whether the policy counts as real-time (the flag is masked before that test), and the
    // kernel reports it back through sched_getscheduler, so the stored policy keeps the flag.
    Sim::builder().host(privileged()).build().run(|| {
        let tid = unsafe { libc::gettid() };
        let policy = libc::SCHED_FIFO | libc::SCHED_RESET_ON_FORK;
        let param = libc::sched_param { sched_priority: 10 };
        assert_eq!(unsafe { libc::sched_setscheduler(tid, policy, &param) }, 0);
        assert_eq!(unsafe { libc::sched_getscheduler(tid) }, policy);
    });
}

#[test]
fn reset_on_fork_fifo_still_needs_the_capability() {
    let host = HostProfile::new().cpus(4).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() } as i64;
        let policy = libc::SCHED_FIFO | libc::SCHED_RESET_ON_FORK;
        assert_eq!(set_scheduler_raw(tid, policy, 10), -1);
        assert_eq!(errno(), libc::EPERM);
    });
}

#[test]
fn sched_setparam_changes_priority_without_touching_policy() {
    // man 2 sched_setparam: adjusts only sched_priority within the thread's current policy.
    Sim::builder().host(privileged()).build().run(|| {
        let tid = unsafe { libc::gettid() };
        let param = libc::sched_param { sched_priority: 20 };
        assert_eq!(
            unsafe { libc::sched_setscheduler(tid, libc::SCHED_FIFO, &param) },
            0
        );
        let reparam = libc::sched_param { sched_priority: 90 };
        assert_eq!(unsafe { libc::sched_setparam(tid, &reparam) }, 0);
        assert_eq!(unsafe { libc::sched_getscheduler(tid) }, libc::SCHED_FIFO);
        let mut got = libc::sched_param { sched_priority: -1 };
        assert_eq!(unsafe { libc::sched_getparam(tid, &mut got) }, 0);
        assert_eq!(got.sched_priority, 90);
    });
}

#[test]
fn pid_zero_targets_the_calling_thread() {
    // man 2 sched_setscheduler: a pid of 0 means the calling thread. Setting via 0 and reading via
    // the thread's real tid must observe the same state.
    Sim::builder().host(privileged()).build().run(|| {
        assert_eq!(set_scheduler_raw(0, libc::SCHED_FIFO, 55), 0);
        let tid = unsafe { libc::gettid() } as i64;
        assert_eq!(get_scheduler_raw(tid), libc::SCHED_FIFO);
        assert_eq!(get_param_raw(tid), 55);
    });
}

#[test]
fn each_thread_carries_its_own_policy() {
    // Scheduling state is per-thread (man 2 sched_setscheduler operates on a TID). Two threads in
    // the same sim must not share a policy.
    Sim::builder().host(privileged()).build().run(|| {
        let main_tid = unsafe { libc::gettid() } as i64;
        assert_eq!(set_scheduler_raw(main_tid, libc::SCHED_RR, 30), 0);

        let child = std::thread::spawn(|| {
            let tid = unsafe { libc::gettid() } as i64;
            assert_eq!(set_scheduler_raw(tid, libc::SCHED_FIFO, 70), 0);
            (tid, get_scheduler_raw(tid), get_param_raw(tid))
        });
        let (child_tid, child_policy, child_prio) = child.join().unwrap();

        assert_ne!(child_tid, main_tid, "distinct tids");
        assert_eq!(child_policy, libc::SCHED_FIFO);
        assert_eq!(child_prio, 70);
        assert_eq!(get_scheduler_raw(main_tid), libc::SCHED_RR, "main unchanged");
        assert_eq!(get_param_raw(main_tid), 30);
    });
}

#[test]
fn dropping_from_fifo_back_to_other_needs_no_capability() {
    // Returning to SCHED_OTHER is always permitted; only entering a real-time policy is gated.
    Sim::builder().host(privileged()).build().run(|| {
        let tid = unsafe { libc::gettid() };
        let param = libc::sched_param { sched_priority: 60 };
        assert_eq!(
            unsafe { libc::sched_setscheduler(tid, libc::SCHED_FIFO, &param) },
            0
        );
        let zero = libc::sched_param { sched_priority: 0 };
        assert_eq!(
            unsafe { libc::sched_setscheduler(tid, libc::SCHED_OTHER, &zero) },
            0
        );
        assert_eq!(unsafe { libc::sched_getscheduler(tid) }, libc::SCHED_OTHER);
    });
}

#[test]
#[ignore = "sim does not range-check sched_priority; the real kernel returns EINVAL for a \
            non-zero priority under SCHED_OTHER or one outside 1..=99 under SCHED_FIFO"]
fn out_of_range_priority_should_be_einval() {
    // man 2 sched_setscheduler ERRORS: EINVAL when sched_priority is outside the policy's range
    // (non-zero for SCHED_OTHER, or not in sched_get_priority_min..=max for SCHED_FIFO/RR). The sim
    // records whatever value it is given, so it cannot reproduce this rejection.
    Sim::builder().host(privileged()).build().run(|| {
        let tid = unsafe { libc::gettid() };
        let bad = libc::sched_param {
            sched_priority: 500,
        };
        assert_eq!(
            unsafe { libc::sched_setscheduler(tid, libc::SCHED_FIFO, &bad) },
            -1
        );
        assert_eq!(errno(), libc::EINVAL);
    });
}
