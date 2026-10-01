//! Configuring a real-time thread on macOS against a `SimHost`: a SCHED_FIFO priority via
//! `pthread_setschedparam(3)`, a Mach `THREAD_TIME_CONSTRAINT_POLICY`
//! (<mach/thread_policy.h>), and a QoS class via `pthread_set_qos_class_self_np` (<pthread/qos.h>).
//! The sim records the intent and reads it back without touching the real scheduler.
//! Run with `cargo run -p snare --example macos_rt_thread`.

#[cfg(target_os = "macos")]
fn main() {
    use snare::{HostProfile, Sim};

    const THREAD_TIME_CONSTRAINT_POLICY: libc::c_int = 2;
    const THREAD_TIME_CONSTRAINT_POLICY_COUNT: u32 = 4;
    const QOS_CLASS_USER_INTERACTIVE: libc::c_int = 0x21;

    unsafe extern "C" {
        fn mach_thread_self() -> u32;
        fn thread_policy_set(t: u32, flavor: libc::c_int, info: *mut u32, count: u32) -> libc::c_int;
        fn pthread_set_qos_class_self_np(qos: libc::c_int, rel: libc::c_int) -> libc::c_int;
    }

    let sim = Sim::builder().host(HostProfile::new().build()).build();
    sim.run(|| {
        let me = unsafe { libc::pthread_self() };

        let mut param: libc::sched_param = unsafe { std::mem::zeroed() };
        param.sched_priority = 47;
        assert_eq!(
            unsafe { libc::pthread_setschedparam(me, libc::SCHED_FIFO, &param) },
            0
        );

        let mut tc: [u32; 4] = [1_000_000, 500_000, 800_000, 0];
        assert_eq!(
            unsafe {
                thread_policy_set(
                    mach_thread_self(),
                    THREAD_TIME_CONSTRAINT_POLICY,
                    tc.as_mut_ptr(),
                    THREAD_TIME_CONSTRAINT_POLICY_COUNT,
                )
            },
            0
        );

        assert_eq!(
            unsafe { pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) },
            0
        );

        let mut policy: libc::c_int = -1;
        let mut got: libc::sched_param = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::pthread_getschedparam(me, &mut policy, &mut got) },
            0
        );
        let policy_name = if policy == libc::SCHED_FIFO { "SCHED_FIFO" } else { "other" };
        println!(
            "rt thread: policy={policy_name} priority={} time-constraint+QoS accepted",
            got.sched_priority,
        );
    });
}

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("macos_rt_thread: Mach thread policies are a macOS-only example");
}
