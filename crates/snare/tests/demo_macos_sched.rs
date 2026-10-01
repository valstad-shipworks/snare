#![cfg(target_os = "macos")]

//! POSIX per-thread scheduling on macOS, set through `pthread_setschedparam(3)` rather than the
//! Linux `sched_setscheduler(2)` syscall. A `SimHost` records each managed thread's policy and
//! sched_param so `pthread_getschedparam(3)` reads back what was set, without touching the real
//! Mach scheduler.

use snare::{HostProfile, Sim};

fn set(policy: libc::c_int, priority: libc::c_int) -> libc::c_int {
    let me = unsafe { libc::pthread_self() };
    let mut param: libc::sched_param = unsafe { std::mem::zeroed() };
    param.sched_priority = priority;
    unsafe { libc::pthread_setschedparam(me, policy, &param) }
}

fn get() -> (libc::c_int, libc::c_int) {
    let me = unsafe { libc::pthread_self() };
    let mut policy: libc::c_int = -1;
    let mut param: libc::sched_param = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::pthread_getschedparam(me, &mut policy, &mut param) };
    assert_eq!(rc, 0, "pthread_getschedparam succeeds");
    (policy, param.sched_priority)
}

#[test]
fn sched_fifo_round_trips() {
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        // pthread_setschedparam(3): SCHED_FIFO is a fixed-priority real-time policy.
        assert_eq!(set(libc::SCHED_FIFO, 47), 0);
        assert_eq!(get(), (libc::SCHED_FIFO, 47));
    });
}

#[test]
fn sched_rr_round_trips() {
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        // pthread_setschedparam(3): SCHED_RR is round-robin real-time.
        assert_eq!(set(libc::SCHED_RR, 31), 0);
        assert_eq!(get(), (libc::SCHED_RR, 31));
    });
}

#[test]
fn sched_other_round_trips() {
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        // pthread_setschedparam(3): SCHED_OTHER is the standard time-sharing policy.
        assert_eq!(set(libc::SCHED_OTHER, 0), 0);
        assert_eq!(get(), (libc::SCHED_OTHER, 0));
    });
}

#[test]
fn an_unset_thread_reads_the_default() {
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        // A thread that never called pthread_setschedparam reads the SimHost's default: policy 0,
        // priority 0 (time-sharing, lowest real-time priority).
        assert_eq!(get(), (0, 0));
    });
}

#[test]
fn re_setting_replaces_the_previous_policy() {
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        assert_eq!(set(libc::SCHED_FIFO, 47), 0);
        assert_eq!(get(), (libc::SCHED_FIFO, 47));
        assert_eq!(set(libc::SCHED_RR, 10), 0);
        assert_eq!(get(), (libc::SCHED_RR, 10), "the second call wins");
    });
}

#[test]
fn each_thread_keeps_its_own_scheduling() {
    // pthread_setschedparam(3) acts on a single thread; the SimHost keys its record by pthread_t,
    // so a child thread's policy does not leak into the parent's.
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        assert_eq!(set(libc::SCHED_FIFO, 60), 0);

        let child = std::thread::spawn(|| {
            assert_eq!(get(), (0, 0), "child starts at the default");
            assert_eq!(set(libc::SCHED_RR, 5), 0);
            get()
        });
        assert_eq!(child.join().unwrap(), (libc::SCHED_RR, 5));

        assert_eq!(get(), (libc::SCHED_FIFO, 60), "parent is unchanged");
    });
}

#[test]
fn a_range_of_fifo_priorities_round_trip() {
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        // The whole SCHED_FIFO priority band is stored verbatim; sched_get_priority_min/max(2) on
        // Darwin span 15..=47 for the real-time policies.
        for prio in [15, 24, 37, 47] {
            assert_eq!(set(libc::SCHED_FIFO, prio), 0);
            assert_eq!(get(), (libc::SCHED_FIFO, prio));
        }
    });
}
