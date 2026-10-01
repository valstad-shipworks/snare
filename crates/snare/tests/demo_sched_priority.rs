#![cfg(target_os = "linux")]

//! Nice-value coverage: `setpriority`/`getpriority` for `PRIO_PROCESS`, the CAP_SYS_NICE gate on
//! lowering the nice value, and the two return conventions.
//!
//! man 2 getpriority: the library call returns the nice value directly (range -20..=19), but
//! because that can legitimately be negative the *raw* syscall instead returns `20 - nice` (range
//! 1..=40) so a genuine error is always distinguishable as -1. man 2 setpriority: only a process
//! with CAP_SYS_NICE may lower a nice value (raise scheduling priority); otherwise EACCES.

use snare::{CAP_SYS_NICE, HostProfile, Sim};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn raw_getpriority(who: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_getpriority, libc::PRIO_PROCESS, who) }
}

#[test]
fn default_nice_is_zero() {
    let host = HostProfile::new().cpus(2).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() } as u32;
        assert_eq!(unsafe { libc::getpriority(libc::PRIO_PROCESS, tid) }, 0);
        // Raw form: 20 - 0 == 20.
        assert_eq!(raw_getpriority(tid), 20);
    });
}

#[test]
fn raising_nice_needs_no_capability() {
    // Increasing the nice value (yielding CPU) is always allowed, even unprivileged.
    let host = HostProfile::new().cpus(2).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() } as u32;
        assert_eq!(unsafe { libc::setpriority(libc::PRIO_PROCESS, tid, 15) }, 0);
        assert_eq!(unsafe { libc::getpriority(libc::PRIO_PROCESS, tid) }, 15);
        assert_eq!(raw_getpriority(tid), 20 - 15);
    });
}

#[test]
fn lowering_nice_requires_cap_sys_nice() {
    let host = HostProfile::new().cpus(2).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() } as u32;
        assert_eq!(unsafe { libc::setpriority(libc::PRIO_PROCESS, tid, -1) }, -1);
        assert_eq!(errno(), libc::EACCES);
        // The failed call must not have mutated the stored nice value.
        assert_eq!(unsafe { libc::getpriority(libc::PRIO_PROCESS, tid) }, 0);
    });
}

#[test]
fn lowering_nice_succeeds_with_cap_sys_nice() {
    let host = HostProfile::new().cpus(2).cap(CAP_SYS_NICE).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() } as u32;
        assert_eq!(unsafe { libc::setpriority(libc::PRIO_PROCESS, tid, -20) }, 0);
        assert_eq!(unsafe { libc::getpriority(libc::PRIO_PROCESS, tid) }, -20);
        // Raw: the most-favoured nice -20 reads back as 40.
        assert_eq!(raw_getpriority(tid), 40);
    });
}

#[test]
fn nice_boundary_values_round_trip() {
    // man 2 setpriority: the nice range is -20 (highest priority) through 19 (lowest). Both ends
    // and the raw `20 - nice` mapping (1..=40) must round-trip.
    let host = HostProfile::new().cpus(2).cap(CAP_SYS_NICE).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() } as u32;
        for nice in [-20, -1, 0, 1, 19] {
            assert_eq!(unsafe { libc::setpriority(libc::PRIO_PROCESS, tid, nice) }, 0);
            assert_eq!(unsafe { libc::getpriority(libc::PRIO_PROCESS, tid) }, nice);
            assert_eq!(raw_getpriority(tid), (20 - nice) as i64);
        }
    });
}

#[test]
fn who_zero_targets_the_calling_thread() {
    // man 2 setpriority: `who == 0` with PRIO_PROCESS means the calling process/thread.
    let host = HostProfile::new().cpus(2).cap(CAP_SYS_NICE).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, -5) }, 0);
        let tid = unsafe { libc::gettid() } as u32;
        assert_eq!(unsafe { libc::getpriority(libc::PRIO_PROCESS, tid) }, -5);
    });
}

#[test]
fn nice_is_per_thread() {
    let host = HostProfile::new().cpus(2).cap(CAP_SYS_NICE).build();
    Sim::builder().host(host).build().run(|| {
        let main_tid = unsafe { libc::gettid() } as u32;
        assert_eq!(unsafe { libc::setpriority(libc::PRIO_PROCESS, main_tid, 3) }, 0);

        let child = std::thread::spawn(|| {
            let ctid = unsafe { libc::gettid() } as u32;
            assert_eq!(unsafe { libc::setpriority(libc::PRIO_PROCESS, ctid, -8) }, 0);
            unsafe { libc::getpriority(libc::PRIO_PROCESS, ctid) }
        });
        assert_eq!(child.join().unwrap(), -8);
        assert_eq!(unsafe { libc::getpriority(libc::PRIO_PROCESS, main_tid) }, 3);
    });
}

#[test]
fn unprivileged_may_still_raise_its_own_nice() {
    // A thread may always make itself nicer; only the privileged direction is gated. Confirm the
    // unprivileged host accepts a positive nice and reflects it in both conventions.
    let host = HostProfile::new().cpus(2).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() } as u32;
        assert_eq!(unsafe { libc::setpriority(libc::PRIO_PROCESS, tid, 10) }, 0);
        assert_eq!(unsafe { libc::setpriority(libc::PRIO_PROCESS, tid, 19) }, 0);
        assert_eq!(raw_getpriority(tid), 1);
    });
}
