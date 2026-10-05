//! Pins the exact errno sequences of the process-limit plane at its edges: invalid resources,
//! policies, pids and `which` values, a soft limit above the hard one leaving the limit as it was,
//! `RLIM_INFINITY` round trips, limits shared across a sim's threads and kept across its runs but
//! never between sims, scheduling state per thread, and zero-length or never-locked `mlock` ranges
//! — on a `SimHost` and on a plain sim. The `*_os_truth` tests replay only calls that fail on the
//! real kernel, so nothing changes in the test process.
#![cfg(unix)]

use snare::{HostProfile, Privileges, Rlimit, Sim};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn rc(r: i32) -> i32 {
    if r == 0 { 0 } else { errno() }
}

fn page() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

#[cfg(target_os = "linux")]
type Resource = libc::__rlimit_resource_t;
#[cfg(not(target_os = "linux"))]
type Resource = libc::c_int;

fn get(resource: Resource) -> (i32, libc::rlim_t, libc::rlim_t) {
    let mut r = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let x = unsafe { libc::getrlimit(resource, &mut r) };
    (rc(x), r.rlim_cur, r.rlim_max)
}

fn set(resource: Resource, cur: libc::rlim_t, max: libc::rlim_t) -> i32 {
    let r = libc::rlimit {
        rlim_cur: cur,
        rlim_max: max,
    };
    rc(unsafe { libc::setrlimit(resource, &r) })
}

fn buffer(pages: usize) -> *const u8 {
    let layout = std::alloc::Layout::from_size_align(pages * page(), page()).unwrap();
    let p = unsafe { std::alloc::alloc_zeroed(layout) };
    assert!(!p.is_null());
    p
}

fn mlock(buf: *const u8, offset: usize, len: usize) -> i32 {
    rc(unsafe { libc::mlock(buf.add(offset).cast(), len) })
}

fn munlock(buf: *const u8, offset: usize, len: usize) -> i32 {
    rc(unsafe { libc::munlock(buf.add(offset).cast(), len) })
}

fn hosted(privileges: Privileges) -> Sim {
    Sim::builder()
        .host(HostProfile::new().build())
        .privileges(privileges)
        .build()
}

fn plain(privileges: Privileges) -> Sim {
    Sim::builder().privileges(privileges).build()
}

/// Calls that fail on any kernel whatever the caller may do: an unknown resource, a soft limit
/// above the hard one (and the limit read back unchanged).
fn failing_limit_calls() -> Vec<i64> {
    let before = get(libc::RLIMIT_MEMLOCK);
    let mut out = vec![get(99).0 as i64, set(99, 1, 1) as i64];
    out.push(set(libc::RLIMIT_MEMLOCK, 2, 1) as i64);
    out.push((get(libc::RLIMIT_MEMLOCK) == before) as i64);
    out
}

fn null_rlimit() -> i32 {
    rc(unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, std::ptr::null_mut()) })
}

#[test]
fn failing_limit_calls_os_truth() {
    let real = snare::real(failing_limit_calls);
    assert_eq!(
        real,
        [
            libc::EINVAL as i64,
            libc::EINVAL as i64,
            libc::EINVAL as i64,
            1
        ]
    );
    let privileges = Privileges::from_real_process().unwrap();
    assert_eq!(
        hosted(privileges.clone()).run(failing_limit_calls),
        real,
        "SimHost"
    );
    assert_eq!(
        plain(privileges).run(failing_limit_calls),
        real,
        "plain sim"
    );
}

#[test]
fn a_null_rlimit_pointer_os_truth() {
    let real = snare::real(null_rlimit);
    assert_eq!(
        real,
        if cfg!(target_os = "linux") {
            0
        } else {
            libc::EFAULT
        }
    );
    let privileges = Privileges::from_real_process().unwrap();
    assert_eq!(hosted(privileges.clone()).run(null_rlimit), real, "SimHost");
    assert_eq!(plain(privileges).run(null_rlimit), real, "plain sim");
}

#[test]
fn unmodelled_resources_pass_through_to_the_process() {
    let real = snare::real(|| get(libc::RLIMIT_NOFILE));
    for sim in [hosted(Privileges::none()), plain(Privileges::none())] {
        assert_eq!(sim.run(|| get(libc::RLIMIT_NOFILE)), real);
    }
}

#[test]
fn infinity_round_trips_and_lowering_from_it_is_final_without_privilege() {
    let inf = libc::RLIM_INFINITY;
    for sim in [hosted(Privileges::none()), plain(Privileges::none())] {
        sim.set_privileges(|p| p.memlock_limit = Rlimit::new(Rlimit::INFINITY));
        sim.run(|| {
            assert_eq!(get(libc::RLIMIT_MEMLOCK), (0, inf, inf));
            assert_eq!(set(libc::RLIMIT_MEMLOCK, 4096, inf), 0);
            assert_eq!(get(libc::RLIMIT_MEMLOCK), (0, 4096, inf));
            assert_eq!(
                set(libc::RLIMIT_MEMLOCK, inf, inf),
                0,
                "soft back up to the hard limit"
            );
            assert_eq!(set(libc::RLIMIT_MEMLOCK, 4096, 8192), 0);
            assert_eq!(set(libc::RLIMIT_MEMLOCK, 4096, inf), libc::EPERM);
            assert_eq!(get(libc::RLIMIT_MEMLOCK), (0, 4096, 8192));
        });
        assert_eq!(
            sim.privileges().memlock_limit,
            Rlimit {
                cur: 4096,
                max: 8192
            }
        );
    }
}

#[test]
fn limits_are_shared_by_a_sims_threads_and_kept_across_its_runs() {
    let sim = hosted(Privileges {
        memlock_limit: Rlimit::new(1 << 20),
        ..Privileges::none()
    });
    sim.run(|| {
        std::thread::spawn(|| assert_eq!(set(libc::RLIMIT_MEMLOCK, 4096, 1 << 20), 0))
            .join()
            .unwrap();
        assert_eq!(get(libc::RLIMIT_MEMLOCK), (0, 4096, 1 << 20));
    });
    assert_eq!(sim.run(|| get(libc::RLIMIT_MEMLOCK)), (0, 4096, 1 << 20));
    sim.set_privileges(|p| p.memlock_limit.cur = 8192);
    assert_eq!(sim.run(|| get(libc::RLIMIT_MEMLOCK)), (0, 8192, 1 << 20));
    let other = hosted(Privileges {
        memlock_limit: Rlimit::new(1 << 20),
        ..Privileges::none()
    });
    assert_eq!(
        other.run(|| get(libc::RLIMIT_MEMLOCK)),
        (0, 1 << 20, 1 << 20)
    );
}

#[test]
fn a_change_from_outside_the_run_is_seen_by_its_threads_at_once() {
    let sim = hosted(Privileges {
        memlock_limit: Rlimit::new(1 << 20),
        ..Privileges::none()
    });
    let handle = &sim;
    sim.run(|| {
        std::thread::scope(|s| {
            s.spawn(|| {
                snare::real(|| handle.set_privileges(|p| p.memlock_limit = Rlimit::new(77)))
            });
        });
        assert_eq!(get(libc::RLIMIT_MEMLOCK), (0, 77, 77));
    });
}

#[test]
fn zero_length_and_never_locked_ranges() {
    let buf = buffer(4);
    let ps = page();
    let check = || {
        assert_eq!(set(libc::RLIMIT_MEMLOCK, ps as u64, ps as u64), 0);
        assert_eq!(munlock(buf, 0, ps), 0, "unlocking what was never locked");
        assert_eq!(mlock(buf, 0, 0), 0);
        assert_eq!(mlock(buf, 1, 1), 0, "an unaligned byte is its page");
        assert_eq!(
            mlock(buf, ps - 1, 2),
            unlimited_page_error(),
            "straddling: a second page"
        );
        assert_eq!(munlock(buf, 0, ps), 0);
        assert_eq!(
            mlock(buf, ps - 1, 2),
            unlimited_page_error(),
            "two pages still exceed one"
        );
        assert_eq!(mlock(buf, ps, ps), 0);
        assert_eq!(munlock(buf, 0, 4 * ps), 0);
    };
    let mem = Privileges {
        memlock_limit: Rlimit::new(1 << 20),
        ..Privileges::none()
    };
    hosted(mem.clone()).run(check);
    #[cfg(target_os = "macos")]
    plain(mem).run(check);
}

fn unlimited_page_error() -> i32 {
    if cfg!(target_os = "linux") {
        libc::ENOMEM
    } else {
        libc::EAGAIN
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    fn sched(pid: i32, policy: i32, priority: i32) -> i32 {
        let p = libc::sched_param {
            sched_priority: priority,
        };
        rc(unsafe { libc::sched_setscheduler(pid, policy, &p) })
    }

    fn getsched(pid: i32) -> (i32, i32) {
        let r = unsafe { libc::sched_getscheduler(pid) };
        (r, if r < 0 { errno() } else { 0 })
    }

    fn unprivileged(rtprio: u64) -> Privileges {
        Privileges {
            rtprio_limit: Rlimit::new(rtprio),
            nice_limit: Rlimit::new(0),
            ..Privileges::none()
        }
    }

    /// Scheduling and nice calls with arguments every kernel refuses before any privilege check.
    fn failing_sched_calls() -> Vec<i32> {
        let p = libc::sched_param { sched_priority: 0 };
        vec![
            sched(-1, libc::SCHED_OTHER, 0),
            rc(unsafe { libc::sched_setscheduler(0, libc::SCHED_OTHER, std::ptr::null()) }),
            sched(0, -1, 0),
            sched(0, libc::SCHED_OTHER, -1),
            rc(unsafe { libc::sched_setparam(-1, &p) }),
            rc(unsafe { libc::sched_setparam(0, std::ptr::null()) }),
            rc(unsafe { libc::setpriority(99, 0, 0) }),
        ]
    }

    #[test]
    fn failing_sched_calls_os_truth() {
        let real = snare::real(failing_sched_calls);
        assert_eq!(real, [libc::EINVAL; 7]);
        let privileges = Privileges::from_real_process().unwrap();
        assert_eq!(hosted(privileges).run(failing_sched_calls), real, "SimHost");
    }

    fn failing_queries() -> Vec<i32> {
        vec![
            getsched(-1).1,
            rc(unsafe { libc::sched_getparam(0, std::ptr::null_mut()) }),
            rc(unsafe { libc::setpriority(libc::PRIO_PROCESS, u32::MAX >> 1, 0) }),
        ]
    }

    #[test]
    fn failing_queries_os_truth() {
        let real = snare::real(failing_queries);
        assert_eq!(real, [libc::EINVAL, libc::EINVAL, libc::ESRCH]);
        let privileges = Privileges::from_real_process().unwrap();
        assert_eq!(hosted(privileges).run(failing_queries), real);
    }

    #[test]
    fn each_thread_keeps_its_own_policy() {
        let sim = hosted(unprivileged(50));
        let (root, child, root_after) = sim.run(|| {
            assert_eq!(sched(0, libc::SCHED_FIFO, 10), 0);
            let child = std::thread::spawn(|| {
                let inherited = getsched(0).0;
                assert_eq!(sched(0, libc::SCHED_RR, 20), 0);
                (inherited, getsched(0).0)
            })
            .join()
            .unwrap();
            (getsched(0).0, child, getsched(0).0)
        });
        assert_eq!(root, libc::SCHED_FIFO);
        assert_eq!(child, (libc::SCHED_FIFO, libc::SCHED_RR));
        assert_eq!(root_after, libc::SCHED_FIFO);
    }

    #[test]
    fn a_child_inherits_its_creators_policy() {
        let sim = hosted(unprivileged(50));
        let child = sim.run(|| {
            assert_eq!(sched(0, libc::SCHED_FIFO, 10), 0);
            std::thread::spawn(|| getsched(0).0).join().unwrap()
        });
        assert_eq!(child, libc::SCHED_FIFO);
    }

    #[test]
    fn policy_is_kept_on_a_thread_across_runs() {
        let sim = hosted(unprivileged(50));
        sim.run(|| assert_eq!(sched(0, libc::SCHED_FIFO, 5), 0));
        assert_eq!(sim.run(|| getsched(0).0), libc::SCHED_FIFO);
        let fresh = hosted(unprivileged(50));
        assert_eq!(fresh.run(|| getsched(0).0), libc::SCHED_OTHER);
    }

    #[test]
    fn the_rtprio_gate_sequence_is_exact() {
        let sim = hosted(unprivileged(10));
        let seq = sim.run(|| {
            vec![
                sched(0, libc::SCHED_FIFO, 10),
                sched(0, libc::SCHED_FIFO, 11),
                sched(0, libc::SCHED_FIFO, 99),
                sched(0, libc::SCHED_FIFO, 100),
                sched(0, libc::SCHED_RR, 1),
                sched(0, libc::SCHED_OTHER, 0),
                sched(0, libc::SCHED_IDLE, 0),
                sched(0, libc::SCHED_BATCH, 0),
                sched(0, libc::SCHED_FIFO, 1),
                getsched(0).0,
            ]
        });
        assert_eq!(
            seq,
            [
                0,
                libc::EPERM,
                libc::EPERM,
                libc::EINVAL,
                0,
                0,
                0,
                libc::EPERM,
                libc::EPERM,
                libc::SCHED_IDLE
            ],
            "leaving SCHED_IDLE needs RLIMIT_NICE to allow the current nice value"
        );
    }

    #[test]
    fn nice_values_clamp_and_read_back_exactly() {
        let sim = hosted(unprivileged(0));
        let seq = sim.run(|| {
            let mut out = Vec::new();
            for n in [-100, 100, 19, 20, -21, 0, 3] {
                out.push((
                    n,
                    rc(unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, n) }),
                ));
                out.push((99, unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) }));
            }
            out
        });
        assert_eq!(
            seq,
            [
                (-100, libc::EACCES),
                (99, 0),
                (100, 0),
                (99, 19),
                (19, 0),
                (99, 19),
                (20, 0),
                (99, 19),
                (-21, libc::EACCES),
                (99, 19),
                (0, libc::EACCES),
                (99, 19),
                (3, libc::EACCES),
                (99, 19)
            ]
        );
    }

    #[test]
    fn a_plain_sim_refuses_before_the_kernel_and_lets_allowed_calls_through() {
        let real = snare::real(|| getsched(0).0);
        let sim = plain(unprivileged(0));
        let seq = sim.run(|| {
            vec![
                sched(0, libc::SCHED_FIFO, 1),
                sched(0, libc::SCHED_FIFO, 0),
                sched(0, libc::SCHED_OTHER, 0),
                getsched(0).0,
            ]
        });
        assert_eq!(seq, [libc::EPERM, libc::EINVAL, 0, real]);
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    #[test]
    fn mlockall_is_enosys_os_truth() {
        let real = snare::real(|| rc(unsafe { libc::mlockall(libc::MCL_CURRENT) }));
        assert_eq!(real, libc::ENOSYS);
        for sim in [hosted(Privileges::all()), plain(Privileges::all())] {
            assert_eq!(
                sim.run(|| rc(unsafe { libc::mlockall(libc::MCL_CURRENT) })),
                real
            );
            assert_eq!(
                sim.run(|| rc(unsafe { libc::munlockall() })),
                snare::real(|| rc(unsafe { libc::munlockall() }))
            );
        }
    }

    #[test]
    fn wiring_is_per_sim() {
        let buf = buffer(4);
        let ps = page();
        let mem = Privileges {
            memlock_limit: Rlimit::new(ps as u64),
            ..Privileges::none()
        };
        let a = hosted(mem.clone());
        let b = hosted(mem);
        a.run(|| assert_eq!(mlock(buf, 0, ps), 0));
        b.run(|| {
            assert_eq!(
                mlock(buf, ps, ps),
                0,
                "the other sim's wiring is not counted"
            )
        });
        a.run(|| assert_eq!(mlock(buf, ps, ps), libc::EAGAIN, "kept across runs"));
        a.run(|| assert_eq!(munlock(buf, 0, 4 * ps), 0));
        b.run(|| assert_eq!(munlock(buf, 0, 4 * ps), 0));
    }
}
