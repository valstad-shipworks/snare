#![cfg(target_os = "macos")]

//! Mach thread-policy and QoS knobs a real-time program sets on macOS instead of SCHED_FIFO.
//! `thread_policy_set` (<mach/thread_policy.h>) and `pthread_set_qos_class_self_np`
//! (<pthread/qos.h>) are accepted deterministically by a `SimHost`, which records the intent and
//! returns success without engaging the real Mach scheduler.

use snare::{HostProfile, Sim};

// <mach/thread_policy.h>: the thread_policy_flavor_t values.
const THREAD_EXTENDED_POLICY: libc::c_int = 1;
const THREAD_TIME_CONSTRAINT_POLICY: libc::c_int = 2;
const THREAD_PRECEDENCE_POLICY: libc::c_int = 3;
// Word counts (mach_msg_type_number_t) of each policy struct.
const THREAD_TIME_CONSTRAINT_POLICY_COUNT: u32 = 4;
const THREAD_PRECEDENCE_POLICY_COUNT: u32 = 1;
const THREAD_EXTENDED_POLICY_COUNT: u32 = 1;

// <pthread/qos.h>: qos_class_t values and the minimum relative priority.
const QOS_CLASS_USER_INTERACTIVE: libc::c_int = 0x21;
const QOS_CLASS_USER_INITIATED: libc::c_int = 0x19;
const QOS_CLASS_DEFAULT: libc::c_int = 0x15;
const QOS_CLASS_UTILITY: libc::c_int = 0x11;
const QOS_CLASS_BACKGROUND: libc::c_int = 0x09;
const QOS_MIN_RELATIVE_PRIORITY: libc::c_int = -15;

// KERN_SUCCESS from <mach/kern_return.h>.
const KERN_SUCCESS: libc::c_int = 0;

unsafe extern "C" {
    fn mach_thread_self() -> u32;
    fn thread_policy_set(thread: u32, flavor: libc::c_int, info: *mut u32, count: u32)
    -> libc::c_int;
    fn pthread_set_qos_class_self_np(qos_class: libc::c_int, relative_priority: libc::c_int)
    -> libc::c_int;
}

fn with_host<R>(f: impl FnOnce() -> R) -> R {
    let sim = Sim::builder().host(HostProfile::new().build()).build();
    sim.run(f)
}

#[test]
fn time_constraint_policy_is_kern_success() {
    with_host(|| {
        // thread_time_constraint_policy_data_t { period, computation, constraint, preemptible }
        // in absolute-time units — the classic 60 Hz audio-thread shape.
        let mut info: [u32; 4] = [1_000_000, 500_000, 800_000, 0];
        let rc = unsafe {
            thread_policy_set(
                mach_thread_self(),
                THREAD_TIME_CONSTRAINT_POLICY,
                info.as_mut_ptr(),
                THREAD_TIME_CONSTRAINT_POLICY_COUNT,
            )
        };
        assert_eq!(rc, KERN_SUCCESS);
    });
}

#[test]
fn precedence_policy_is_kern_success() {
    with_host(|| {
        // thread_precedence_policy_data_t { importance } — a single natural_t.
        let mut info: [u32; 1] = [63];
        let rc = unsafe {
            thread_policy_set(
                mach_thread_self(),
                THREAD_PRECEDENCE_POLICY,
                info.as_mut_ptr(),
                THREAD_PRECEDENCE_POLICY_COUNT,
            )
        };
        assert_eq!(rc, KERN_SUCCESS);
    });
}

#[test]
fn extended_policy_toggles_timeshare() {
    with_host(|| {
        // thread_extended_policy_data_t { timeshare } — 0 pins a thread off the timeshare demotion.
        let mut info: [u32; 1] = [0];
        let rc = unsafe {
            thread_policy_set(
                mach_thread_self(),
                THREAD_EXTENDED_POLICY,
                info.as_mut_ptr(),
                THREAD_EXTENDED_POLICY_COUNT,
            )
        };
        assert_eq!(rc, KERN_SUCCESS);
    });
}

#[test]
fn a_non_preemptible_time_constraint_is_accepted() {
    with_host(|| {
        // preemptible = 0 is the hard-realtime request; the sim still succeeds without a real
        // realtime slot to grant.
        let mut info: [u32; 4] = [2_000_000, 1_000_000, 1_500_000, 0];
        let rc = unsafe {
            thread_policy_set(
                mach_thread_self(),
                THREAD_TIME_CONSTRAINT_POLICY,
                info.as_mut_ptr(),
                THREAD_TIME_CONSTRAINT_POLICY_COUNT,
            )
        };
        assert_eq!(rc, KERN_SUCCESS);
    });
}

#[test]
fn every_qos_class_is_accepted() {
    with_host(|| {
        for class in [
            QOS_CLASS_USER_INTERACTIVE,
            QOS_CLASS_USER_INITIATED,
            QOS_CLASS_DEFAULT,
            QOS_CLASS_UTILITY,
            QOS_CLASS_BACKGROUND,
        ] {
            // pthread_set_qos_class_self_np returns 0 on success.
            let rc = unsafe { pthread_set_qos_class_self_np(class, 0) };
            assert_eq!(rc, 0, "qos class {class:#x} accepted");
        }
    });
}

#[test]
fn a_negative_relative_priority_is_accepted() {
    with_host(|| {
        // <pthread/qos.h>: relative_priority is 0 down to QOS_MIN_RELATIVE_PRIORITY (-15).
        let rc = unsafe {
            pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, QOS_MIN_RELATIVE_PRIORITY)
        };
        assert_eq!(rc, 0);
    });
}

#[test]
fn qos_then_time_constraint_compose() {
    // A worker commonly opts into a QoS class and then upgrades to a time-constraint policy; both
    // calls succeed on the same thread.
    with_host(|| {
        assert_eq!(unsafe { pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) }, 0);
        let mut info: [u32; 4] = [500_000, 250_000, 400_000, 1];
        let rc = unsafe {
            thread_policy_set(
                mach_thread_self(),
                THREAD_TIME_CONSTRAINT_POLICY,
                info.as_mut_ptr(),
                THREAD_TIME_CONSTRAINT_POLICY_COUNT,
            )
        };
        assert_eq!(rc, KERN_SUCCESS);
    });
}

#[test]
fn a_child_thread_sets_its_own_qos() {
    with_host(|| {
        let child = std::thread::spawn(|| unsafe {
            pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0)
        });
        assert_eq!(child.join().unwrap(), 0, "the managed child's QoS call succeeds");
    });
}
