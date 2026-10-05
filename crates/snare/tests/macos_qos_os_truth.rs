//! A thread's QoS requests succeed or fail in the sim exactly as on macOS: any successful
//! `pthread_setschedparam` opts the thread out of QoS for good, before or after a QoS class was
//! requested, and out-of-range classes and relative priorities are rejected.
#![cfg(target_os = "macos")]

use libc::c_int;
use snare::{HostProfile, Sim};

const QOS_CLASS_USER_INTERACTIVE: c_int = 0x21;
const QOS_CLASS_UTILITY: c_int = 0x11;

unsafe extern "C" {
    fn pthread_set_qos_class_self_np(qos_class: c_int, relative_priority: c_int) -> c_int;
}

#[derive(Clone, Copy, Debug)]
enum Step {
    Qos(c_int, c_int),
    Sched(c_int, c_int),
}

fn scenarios() -> Vec<Vec<Step>> {
    use Step::{Qos, Sched};
    vec![
        vec![
            Qos(QOS_CLASS_USER_INTERACTIVE, 0),
            Qos(QOS_CLASS_UTILITY, -15),
        ],
        vec![
            Qos(0x99, 0),
            Qos(QOS_CLASS_UTILITY, 1),
            Qos(QOS_CLASS_UTILITY, -16),
        ],
        vec![
            Sched(libc::SCHED_FIFO, 40),
            Qos(QOS_CLASS_USER_INTERACTIVE, 0),
        ],
        vec![Sched(libc::SCHED_RR, 40), Qos(QOS_CLASS_UTILITY, 0)],
        vec![Sched(libc::SCHED_OTHER, 31), Qos(QOS_CLASS_UTILITY, 0)],
        vec![
            Sched(libc::SCHED_FIFO, 40),
            Sched(libc::SCHED_OTHER, 31),
            Qos(QOS_CLASS_UTILITY, 0),
        ],
        vec![
            Qos(QOS_CLASS_UTILITY, 0),
            Sched(libc::SCHED_FIFO, 40),
            Qos(QOS_CLASS_USER_INTERACTIVE, 0),
        ],
        vec![
            Sched(libc::SCHED_FIFO, 40),
            Qos(0x99, 0),
            Qos(QOS_CLASS_UTILITY, 1),
        ],
        vec![Sched(99, 40), Qos(QOS_CLASS_UTILITY, 0)],
    ]
}

/// The return code of each step, run on a fresh thread since opting out cannot be undone.
fn run(steps: Vec<Step>) -> Vec<c_int> {
    std::thread::spawn(move || {
        steps
            .into_iter()
            .map(|step| match step {
                Step::Qos(class, relative) => unsafe {
                    pthread_set_qos_class_self_np(class, relative)
                },
                Step::Sched(policy, priority) => {
                    let mut param: libc::sched_param = unsafe { std::mem::zeroed() };
                    param.sched_priority = priority;
                    unsafe { libc::pthread_setschedparam(libc::pthread_self(), policy, &param) }
                }
            })
            .collect()
    })
    .join()
    .unwrap()
}

#[test]
fn qos_opt_out_matches_the_host() {
    let real: Vec<_> = scenarios().into_iter().map(run).collect();
    let host = HostProfile::new().build();
    let simulated: Vec<_> = Sim::builder()
        .host(host)
        .build()
        .run(|| scenarios().into_iter().map(run).collect());
    let differ: Vec<String> = scenarios()
        .iter()
        .zip(real.iter().zip(&simulated))
        .filter(|(_, (real, sim))| real != sim)
        .map(|(steps, (real, sim))| format!("{steps:?}: host {real:?}, sim {sim:?}"))
        .collect();
    assert!(differ.is_empty(), "{}", differ.join("\n"));
    assert_eq!(
        real[2],
        [0, libc::EPERM],
        "macOS opts a SCHED_FIFO thread out of QoS"
    );
}
