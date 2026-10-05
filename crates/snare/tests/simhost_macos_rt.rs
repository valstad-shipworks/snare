#![cfg(target_os = "macos")]

use snare::{HostProfile, Sim};

#[test]
fn pthread_schedparam_round_trips_through_the_sim() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let me = unsafe { libc::pthread_self() };

        let mut param: libc::sched_param = unsafe { std::mem::zeroed() };
        param.sched_priority = 42;
        let rc = unsafe { libc::pthread_setschedparam(me, libc::SCHED_FIFO, &param) };
        assert_eq!(rc, 0, "pthread_setschedparam should succeed");

        let mut got_policy: libc::c_int = -1;
        let mut got_param: libc::sched_param = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::pthread_getschedparam(me, &mut got_policy, &mut got_param) };
        assert_eq!(rc, 0);
        assert_eq!(got_policy, libc::SCHED_FIFO, "policy read back");
        assert_eq!(got_param.sched_priority, 42, "priority read back");
    });
}

#[test]
fn qos_class_self_is_accepted() {
    // QOS_CLASS_USER_INTERACTIVE = 0x21.
    const QOS_CLASS_USER_INTERACTIVE: libc::c_int = 0x21;
    unsafe extern "C" {
        fn pthread_set_qos_class_self_np(
            qos_class: libc::c_int,
            relative_priority: libc::c_int,
        ) -> libc::c_int;
    }
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let rc = unsafe { pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) };
        assert_eq!(rc, 0, "QoS class accepted deterministically");
    });
}

#[test]
fn time_constraint_policy_is_accepted() {
    // thread_policy_set(mach_thread_self(), THREAD_TIME_CONSTRAINT_POLICY, info, count).
    const THREAD_TIME_CONSTRAINT_POLICY: libc::c_int = 2;
    unsafe extern "C" {
        fn mach_thread_self() -> u32;
        fn thread_policy_set(
            thread: u32,
            flavor: libc::c_int,
            info: *mut u32,
            count: u32,
        ) -> libc::c_int;
    }
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        // struct thread_time_constraint_policy { period, computation, constraint, preemptible }
        let mut info: [u32; 4] = [1_000_000, 500_000, 800_000, 0];
        let rc = unsafe {
            thread_policy_set(
                mach_thread_self(),
                THREAD_TIME_CONSTRAINT_POLICY,
                info.as_mut_ptr(),
                4,
            )
        };
        assert_eq!(rc, 0, "KERN_SUCCESS");
    });
}

#[test]
fn unset_thread_reads_default_scheduling() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let me = unsafe { libc::pthread_self() };
        let mut policy: libc::c_int = -1;
        let mut param: libc::sched_param = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::pthread_getschedparam(me, &mut policy, &mut param) };
        assert_eq!(rc, 0);
        assert_eq!(policy, 0, "SCHED_OTHER by default");
        assert_eq!(param.sched_priority, 0);
    });
}
