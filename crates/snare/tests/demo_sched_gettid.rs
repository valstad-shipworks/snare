#![cfg(target_os = "linux")]

//! `gettid` coverage: the sim mints a synthetic, stable, per-thread kernel thread id.
//!
//! man 2 gettid: returns the caller's kernel thread id (TID). In a single-threaded process the TID
//! equals the PID; each additional thread gets a distinct TID. The sim's TID is also the `pid`
//! argument the sched_* calls key their per-thread state on.

use snare::{HostProfile, Sim};

const TID_BASE: i32 = 4000;

#[test]
fn gettid_is_stable_within_a_thread() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let a = unsafe { libc::gettid() };
        let b = unsafe { libc::gettid() };
        assert!(a >= TID_BASE, "synthetic tid, got {a}");
        assert_eq!(a, b, "the same thread keeps one tid");
    });
}

#[test]
fn spawned_threads_get_distinct_tids() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let main = unsafe { libc::gettid() };

        let mut handles = Vec::new();
        for _ in 0..4 {
            handles.push(std::thread::spawn(|| unsafe { libc::gettid() }));
        }
        let mut tids: Vec<i32> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        tids.push(main);
        tids.sort_unstable();
        tids.dedup();
        assert_eq!(tids.len(), 5, "main plus four children are all distinct");
        assert!(tids.iter().all(|&t| t >= TID_BASE));
    });
}

#[test]
fn gettid_matches_the_sched_pid_argument() {
    // The TID gettid reports is exactly what sched_getscheduler accepts to name this thread, so a
    // program that caches gettid and later queries its own policy sees consistent state.
    let host = HostProfile::new().cpus(2).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() };
        assert_eq!(unsafe { libc::sched_getscheduler(tid) }, libc::SCHED_OTHER);
        assert_eq!(unsafe { libc::sched_getscheduler(0) }, libc::SCHED_OTHER);
    });
}

#[test]
fn a_thread_that_never_called_gettid_still_has_state() {
    // A child that touches only sched_* (never gettid) must still resolve pid 0 to its own state,
    // independent of the parent's.
    let host = HostProfile::new().cpus(2).build();
    Sim::builder().host(host).build().run(|| {
        let child = std::thread::spawn(|| unsafe { libc::sched_getscheduler(0) });
        assert_eq!(child.join().unwrap(), libc::SCHED_OTHER);
    });
}
