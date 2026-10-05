//! Process resource limits and the calls they gate: `getrlimit`/`setrlimit`/`prlimit` on the
//! sim's own limits, `RLIMIT_RTPRIO`/`RLIMIT_NICE` behind `sched_setscheduler`, `setpriority`
//! and `pthread_setschedparam`, and `RLIMIT_MEMLOCK` behind `mlock`/`mlockall` — on a
//! `SimHost`, on a plain sim, and (the `*_os_truth` tests) against the real kernel, in a forked
//! child so nothing changes in the test process.
//!
//! The truth tests take the sim's privileges from the real process
//! (`Privileges::from_real_process`), so they hold whatever the runner may do. In Docker's
//! default container (root without `CAP_SYS_NICE`, `CAP_IPC_LOCK` or `CAP_SYS_RESOURCE`, all
//! limits at the kernel's defaults) every gate is closed; to exercise the limit paths run them
//! again with, for example,
//! `docker run --ulimit rtprio=10:20 --ulimit nice=25:30 --ulimit memlock=65536:131072 ...` and
//! with `--cap-add SYS_NICE --cap-add IPC_LOCK --cap-add SYS_RESOURCE`.

#![cfg(unix)]

use snare::{Privileges, Rlimit, Sim};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// `0`, or the errno of a `-1` return.
fn rc(r: i32) -> i32 {
    if r == 0 { 0 } else { errno() }
}

fn page() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

/// The type `getrlimit` takes its resource as.
#[cfg(target_os = "linux")]
type Resource = libc::__rlimit_resource_t;
#[cfg(not(target_os = "linux"))]
type Resource = libc::c_int;

fn get(resource: Resource) -> (i32, libc::rlimit) {
    let mut r = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let x = unsafe { libc::getrlimit(resource, &mut r) };
    (rc(x), r)
}

fn set(resource: Resource, cur: libc::rlim_t, max: libc::rlim_t) -> i32 {
    let r = libc::rlimit {
        rlim_cur: cur,
        rlim_max: max,
    };
    rc(unsafe { libc::setrlimit(resource, &r) })
}

fn mlock(buf: *const u8, pages: usize, len: usize) -> i32 {
    rc(unsafe { libc::mlock(buf.add(pages * page()).cast(), len) })
}

fn munlock(buf: *const u8, pages: usize, len: usize) -> i32 {
    rc(unsafe { libc::munlock(buf.add(pages * page()).cast(), len) })
}

/// A page-aligned buffer of `pages` pages that outlives the test.
fn buffer(pages: usize) -> *const u8 {
    let layout = std::alloc::Layout::from_size_align(pages * page(), page()).unwrap();
    let p = unsafe { std::alloc::alloc_zeroed(layout) };
    assert!(!p.is_null());
    p
}

/// Runs `f` in a forked child of the real process and returns what it wrote. The child only
/// makes system calls into a fixed array, so it never touches a lock another thread of the test
/// process might hold.
fn in_child(f: fn(&mut [i64; 64])) -> [i64; 64] {
    snare::real(|| {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let mut out = [0i64; 64];
            f(&mut out);
            unsafe {
                libc::write(fds[1], out.as_ptr().cast(), std::mem::size_of_val(&out));
                libc::_exit(0);
            }
        }
        unsafe { libc::close(fds[1]) };
        let mut out = [0i64; 64];
        let want = std::mem::size_of_val(&out);
        let mut got = 0;
        while got < want {
            let n = unsafe {
                libc::read(
                    fds[0],
                    out.as_mut_ptr().cast::<u8>().add(got).cast(),
                    want - got,
                )
            };
            assert!(n > 0, "child wrote {got} of {want} bytes");
            got += n as usize;
        }
        let mut status = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
            libc::close(fds[0]);
        }
        out
    })
}

/// An unlimited `rlim_t` normalised to `-1` so real and sim reports compare on every OS.
fn lim(v: libc::rlim_t) -> i64 {
    if v == libc::RLIM_INFINITY {
        -1
    } else {
        v as i64
    }
}

#[test]
fn sim_limits_never_reach_the_real_process() {
    let real = snare::real(|| get(libc::RLIMIT_MEMLOCK).1);
    let sim = Sim::builder()
        .privileges(Privileges {
            memlock_limit: Rlimit {
                cur: 4096,
                max: 1 << 20,
            },
            ..Privileges::all()
        })
        .build();
    sim.run(|| {
        let (e, r) = get(libc::RLIMIT_MEMLOCK);
        assert_eq!((e, r.rlim_cur, r.rlim_max), (0, 4096, 1 << 20));
        assert_eq!(set(libc::RLIMIT_MEMLOCK, 8192, 1 << 20), 0);
        assert_eq!(set(libc::RLIMIT_MEMLOCK, 1 << 21, 1 << 20), libc::EINVAL);
    });
    assert_eq!(
        sim.privileges().memlock_limit,
        Rlimit {
            cur: 8192,
            max: 1 << 20
        }
    );
    let after = snare::real(|| get(libc::RLIMIT_MEMLOCK).1);
    assert_eq!(
        (after.rlim_cur, after.rlim_max),
        (real.rlim_cur, real.rlim_max)
    );
}

#[test]
fn raising_a_hard_limit_needs_privilege() {
    let sim = Sim::builder()
        .privileges(Privileges {
            memlock_limit: Rlimit::new(1 << 20),
            ..Privileges::none()
        })
        .build();
    sim.run(|| {
        assert_eq!(set(libc::RLIMIT_MEMLOCK, 4096, 1 << 21), libc::EPERM);
        assert_eq!(
            set(libc::RLIMIT_MEMLOCK, 4096, 1 << 19),
            0,
            "lowering is free"
        );
        assert_eq!(
            set(libc::RLIMIT_MEMLOCK, 4096, 1 << 20),
            libc::EPERM,
            "and final"
        );
    });
    sim.set_privileges(|p| {
        p.root = true;
        p.sys_resource = true;
    });
    sim.run(|| assert_eq!(set(libc::RLIMIT_MEMLOCK, 4096, 1 << 21), 0));
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use snare::{CAP_IPC_LOCK, CAP_SYS_NICE, HostProfile};

    fn sched(policy: i32, priority: i32) -> i32 {
        let p = libc::sched_param {
            sched_priority: priority,
        };
        rc(unsafe { libc::sched_setscheduler(0, policy, &p) })
    }

    fn sched_raw(policy: i32, priority: i32) -> i32 {
        let p = libc::sched_param {
            sched_priority: priority,
        };
        rc(unsafe { libc::syscall(libc::SYS_sched_setscheduler, 0, policy, &p) } as i32)
    }

    fn nice(n: i32) -> i32 {
        rc(unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, n) })
    }

    fn unprivileged(rtprio: u64, nice_limit: u64) -> Privileges {
        Privileges {
            rtprio_limit: Rlimit::new(rtprio),
            nice_limit: Rlimit::new(nice_limit),
            ..Privileges::none()
        }
    }

    #[test]
    fn rtprio_limit_gates_real_time_policies() {
        let host = HostProfile::new().build();
        let sim = Sim::builder()
            .host(host)
            .privileges(unprivileged(0, 0))
            .build();
        sim.run(|| {
            assert_eq!(sched(libc::SCHED_FIFO, 1), libc::EPERM, "RLIMIT_RTPRIO 0");
            assert_eq!(
                sched(libc::SCHED_FIFO, 0),
                libc::EINVAL,
                "FIFO needs 1..=99"
            );
            assert_eq!(sched(libc::SCHED_OTHER, 5), libc::EINVAL, "OTHER takes 0");
            assert_eq!(sched(libc::SCHED_RR, 100), libc::EINVAL);
            assert_eq!(sched(77, 0), libc::EINVAL, "no such policy");
            assert_eq!(
                sched(6, 0),
                libc::EINVAL,
                "SCHED_DEADLINE needs sched_setattr"
            );
            assert_eq!(sched(libc::SCHED_BATCH, 0), 0);
        });
        sim.set_privileges(|p| p.rtprio_limit = Rlimit::new(20));
        sim.run(|| {
            assert_eq!(sched(libc::SCHED_FIFO, 21), libc::EPERM);
            assert_eq!(
                sched_raw(libc::SCHED_FIFO, 20),
                0,
                "the raw syscall fast-talker makes"
            );
            assert_eq!(unsafe { libc::sched_getscheduler(0) }, libc::SCHED_FIFO);
            assert_eq!(sched(libc::SCHED_RR, 10), 0, "lowering is always allowed");
            assert_eq!(sched(libc::SCHED_RR, 15), 0, "back up to the limit");
            let p = libc::sched_param { sched_priority: 30 };
            assert_eq!(rc(unsafe { libc::sched_setparam(0, &p) }), libc::EPERM);
            let ret =
                unsafe { libc::pthread_setschedparam(libc::pthread_self(), libc::SCHED_FIFO, &p) };
            assert_eq!(ret, libc::EPERM, "pthread_setschedparam returns the error");
            let p = libc::sched_param { sched_priority: 12 };
            assert_eq!(
                unsafe { libc::pthread_setschedparam(libc::pthread_self(), libc::SCHED_FIFO, &p) },
                0
            );
            let (mut policy, mut got) = (0, libc::sched_param { sched_priority: 0 });
            assert_eq!(
                unsafe { libc::pthread_getschedparam(libc::pthread_self(), &mut policy, &mut got) },
                0
            );
            assert_eq!((policy, got.sched_priority), (libc::SCHED_FIFO, 12));
            let mut sp = libc::sched_param { sched_priority: 0 };
            assert_eq!(unsafe { libc::sched_getparam(0, &mut sp) }, 0);
            assert_eq!(
                sp.sched_priority, 12,
                "the pthread and tid views are one thread"
            );
        });
        sim.set_privileges(|p| p.sys_nice = true);
        sim.run(|| assert_eq!(sched(libc::SCHED_FIFO, 99), 0, "CAP_SYS_NICE"));
    }

    #[test]
    fn nice_limit_gates_lowering_the_nice_value() {
        let host = HostProfile::new().build();
        let sim = Sim::builder()
            .host(host)
            .privileges(unprivileged(0, 0))
            .build();
        sim.run(|| {
            assert_eq!(nice(5), 0, "raising nice is always allowed");
            assert_eq!(nice(0), libc::EACCES, "RLIMIT_NICE 0 allows no lowering");
            assert_eq!(nice(40), 0, "clamped to 19");
            assert_eq!(unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) }, 19);
            let raw = unsafe { libc::syscall(libc::SYS_getpriority, libc::PRIO_PROCESS, 0) };
            assert_eq!(raw, 1, "the raw syscall returns 20 - nice");
        });
        sim.set_privileges(|p| p.nice_limit = Rlimit::new(25));
        sim.run(|| {
            assert_eq!(nice(-5), 0, "20 - (-5) = 25 is within RLIMIT_NICE");
            assert_eq!(nice(-6), libc::EACCES);
        });
        sim.set_privileges(|p| p.sys_nice = true);
        sim.run(|| assert_eq!(nice(-20), 0));
    }

    #[test]
    fn memlock_limit_gates_mlock_and_mlockall() {
        let buf = buffer(8);
        let ps = page();
        let host = HostProfile::new().build();
        let sim = Sim::builder()
            .host(host)
            .privileges(Privileges {
                memlock_limit: Rlimit::new(2 * ps as u64),
                ..Privileges::none()
            })
            .build();
        sim.run(|| {
            assert_eq!(mlock(buf, 0, ps), 0);
            assert_eq!(mlock(buf, 0, ps), 0, "a page locked twice counts once");
            assert_eq!(mlock(buf, 1, ps), 0, "two pages");
            assert_eq!(mlock(buf, 2, 1), libc::ENOMEM, "a third");
            assert_eq!(mlock(buf, 0, 2 * ps), 0, "the same two");
            assert_eq!(munlock(buf, 0, ps), 0);
            assert_eq!(mlock(buf, 3, ps), 0, "one unlock frees its page");
            assert_eq!(
                rc(unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) }),
                libc::ENOMEM
            );
            assert_eq!(
                rc(unsafe { libc::mlockall(libc::MCL_FUTURE) }),
                0,
                "nothing locked now"
            );
            assert_eq!(rc(unsafe { libc::mlockall(0) }), libc::EINVAL);
            assert_eq!(
                rc(unsafe { libc::mlockall(libc::MCL_ONFAULT) }),
                libc::EINVAL
            );
            assert_eq!(rc(unsafe { libc::munlockall() }), 0);
            assert_eq!(mlock(buf, 4, 2 * ps), 0, "munlockall released everything");
            assert_eq!(set(libc::RLIMIT_MEMLOCK, 0, 2 * ps as u64), 0);
            assert_eq!(
                mlock(buf, 6, ps),
                libc::EPERM,
                "RLIMIT_MEMLOCK 0: can_do_mlock"
            );
            assert_eq!(
                rc(unsafe { libc::mlockall(libc::MCL_CURRENT) }),
                libc::EPERM
            );
            let raw = unsafe { libc::syscall(libc::SYS_mlock, buf, ps) };
            assert_eq!(rc(raw as i32), libc::EPERM, "the raw syscall too");
        });
        let host = HostProfile::new().cap(CAP_IPC_LOCK).build();
        Sim::builder().host(host).build().run(|| {
            assert_eq!(
                rc(unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) }),
                0
            );
            assert_eq!(rc(unsafe { libc::munlockall() }), 0);
        });
    }

    #[test]
    fn prlimit_reads_and_writes_the_sims_limits() {
        let sim = Sim::builder()
            .host(HostProfile::new().build())
            .privileges(unprivileged(7, 3))
            .build();
        sim.run(|| {
            let new = libc::rlimit {
                rlim_cur: 5,
                rlim_max: 7,
            };
            let mut old = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            let r = unsafe { libc::prlimit(0, libc::RLIMIT_RTPRIO, &new, &mut old) };
            assert_eq!(rc(r), 0);
            assert_eq!((old.rlim_cur, old.rlim_max), (7, 7));
            let mut now = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            let raw = unsafe {
                libc::syscall(
                    libc::SYS_prlimit64,
                    0,
                    libc::RLIMIT_RTPRIO,
                    std::ptr::null::<libc::rlimit>(),
                    &mut now,
                )
            };
            assert_eq!(rc(raw as i32), 0);
            assert_eq!((now.rlim_cur, now.rlim_max), (5, 7));
            let (_, n) = get(libc::RLIMIT_NICE);
            assert_eq!(n.rlim_cur, 3);
        });
    }

    #[test]
    fn a_plain_sim_gates_before_the_real_call() {
        let buf = buffer(4);
        let sim = Sim::builder().privileges(unprivileged(0, 0)).build();
        sim.run(|| {
            assert_eq!(sched(libc::SCHED_FIFO, 1), libc::EPERM);
            assert_eq!(nice(-1), libc::EACCES);
            assert_eq!(set(libc::RLIMIT_MEMLOCK, 0, 8 << 20), 0);
            assert_eq!(mlock(buf, 0, page()), libc::EPERM);
            let (_, r) = get(libc::RLIMIT_RTPRIO);
            assert_eq!(r.rlim_cur, 0);
        });
    }

    #[test]
    fn limits_hold_under_deterministic_scheduling() {
        let outcome = || {
            let host = HostProfile::new().build();
            let sim = Sim::builder()
                .host(host)
                .privileges(unprivileged(10, 0))
                .deterministic()
                .build();
            sim.run(|| {
                let workers: Vec<_> = (1..=4)
                    .map(|i| std::thread::spawn(move || sched(libc::SCHED_FIFO, i * 4)))
                    .collect();
                workers
                    .into_iter()
                    .map(|w| w.join().unwrap())
                    .collect::<Vec<_>>()
            })
        };
        let first = outcome();
        assert_eq!(first, vec![0, 0, libc::EPERM, libc::EPERM]);
        assert_eq!(first, outcome());
    }

    /// The scheduling, nice and memory-locking sequence both truth tests run, writing each
    /// result to `out` in order.
    fn sequence(out: &mut [i64; 64], buf: *const u8) {
        let ps = page();
        let mut i = 0;
        let mut put = |v: i64| {
            out[i] = v;
            i += 1;
        };
        for res in [libc::RLIMIT_RTPRIO, libc::RLIMIT_NICE, libc::RLIMIT_MEMLOCK] {
            let (e, r) = get(res);
            put(e as i64);
            put(lim(r.rlim_cur));
            put(lim(r.rlim_max));
        }
        let (_, mem) = get(libc::RLIMIT_MEMLOCK);
        put(sched(libc::SCHED_FIFO, 0) as i64);
        put(sched(libc::SCHED_OTHER, 3) as i64);
        put(sched(libc::SCHED_RR, 100) as i64);
        put(sched(libc::SCHED_FIFO, 1) as i64);
        put(sched(libc::SCHED_FIFO, 50) as i64);
        put(sched(libc::SCHED_OTHER, 0) as i64);
        put(nice(5) as i64);
        put(nice(0) as i64);
        put(nice(-20) as i64);
        put(nice(30) as i64);
        put(unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) } as i64);
        put(set(libc::RLIMIT_MEMLOCK, 2 * ps as u64, mem.rlim_max) as i64);
        put(mlock(buf, 0, ps) as i64);
        put(mlock(buf, 1, ps) as i64);
        put(mlock(buf, 0, 3 * ps) as i64);
        put(munlock(buf, 0, 2 * ps) as i64);
        put(rc(unsafe { libc::mlockall(libc::MCL_CURRENT) }) as i64);
        put(rc(unsafe { libc::munlockall() }) as i64);
        put(rc(unsafe { libc::mlockall(0) }) as i64);
        put(set(libc::RLIMIT_MEMLOCK, 4 * ps as u64, 2 * ps as u64) as i64);
        put(set(libc::RLIMIT_MEMLOCK, 0, mem.rlim_max) as i64);
        put(mlock(buf, 0, ps) as i64);
        put(set(libc::RLIMIT_MEMLOCK, 0, 2 * ps as u64) as i64);
        put(set(libc::RLIMIT_MEMLOCK, 0, 4 * ps as u64) as i64);
    }

    static mut TRUTH_BUF: usize = 0;

    #[test]
    fn rlimit_sequence_os_truth() {
        let buf = buffer(8);
        unsafe { TRUTH_BUF = buf as usize };
        let real = in_child(|out| sequence(out, unsafe { TRUTH_BUF } as *const u8));
        let privileges = Privileges::from_real_process().unwrap();
        let host = HostProfile::new().build();
        let sim = Sim::builder()
            .host(host)
            .privileges(privileges.clone())
            .build();
        let mut simulated = [0i64; 64];
        sim.run(|| sequence(&mut simulated, buf));
        assert_eq!(
            simulated,
            real,
            "sim vs real (privileges {privileges:?}, CAP_SYS_NICE {}, CAP_IPC_LOCK {})",
            privileges.has_cap(CAP_SYS_NICE),
            privileges.has_cap(CAP_IPC_LOCK)
        );
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use snare::HostProfile;

    #[test]
    fn mlock_wiring_nests_and_is_capped_by_memlock() {
        let buf = buffer(8);
        let ps = page();
        let check = || {
            assert_eq!(set(libc::RLIMIT_MEMLOCK, 2 * ps as u64, 1 << 30), 0);
            assert_eq!(mlock(buf, 0, 0), 0, "a zero length is a no-op");
            assert_eq!(mlock(buf, 0, 2 * ps), 0);
            assert_eq!(mlock(buf, 0, 2 * ps), 0, "wiring again nests");
            assert_eq!(mlock(buf, 2, ps), libc::EAGAIN, "a third page");
            assert_eq!(munlock(buf, 0, ps), 0);
            assert_eq!(
                mlock(buf, 2, ps),
                libc::EAGAIN,
                "page 0 is still wired once"
            );
            assert_eq!(munlock(buf, 0, 2 * ps), 0);
            assert_eq!(mlock(buf, 2, ps), 0);
            assert_eq!(munlock(buf, 0, 4 * ps), 0);
        };
        Sim::builder()
            .host(HostProfile::new().build())
            .build()
            .run(check);
        Sim::new().run(check);
    }

    /// The `RLIMIT_MEMLOCK` and wiring sequence the truth test runs.
    fn sequence(out: &mut [i64; 64], buf: *const u8) {
        let ps = page();
        let mut i = 0;
        let mut put = |v: i64| {
            out[i] = v;
            i += 1;
        };
        let (e, r) = get(libc::RLIMIT_MEMLOCK);
        put(e as i64);
        put(lim(r.rlim_cur));
        put(lim(r.rlim_max));
        put(set(libc::RLIMIT_MEMLOCK, 2 * ps as u64, r.rlim_max) as i64);
        put(mlock(buf, 0, 2 * ps) as i64);
        put(mlock(buf, 0, 2 * ps) as i64);
        put(mlock(buf, 1, ps) as i64);
        put(munlock(buf, 0, ps) as i64);
        put(mlock(buf, 5, ps) as i64);
        put(mlock(buf, 0, 0) as i64);
        put(munlock(buf, 20, ps) as i64);
        put(rc(unsafe { libc::mlockall(libc::MCL_CURRENT) }) as i64);
        put(set(libc::RLIMIT_MEMLOCK, 1 << 20, 1 << 20) as i64);
        put(set(libc::RLIMIT_MEMLOCK, 2 << 20, 1 << 20) as i64);
        put(set(libc::RLIMIT_MEMLOCK, 1 << 20, 2 << 20) as i64);
        put(set(
            libc::RLIMIT_MEMLOCK,
            libc::RLIM_INFINITY,
            libc::RLIM_INFINITY,
        ) as i64);
        put(get(99).0 as i64);
    }

    static mut TRUTH_BUF: usize = 0;

    #[test]
    fn memlock_os_truth() {
        let buf = buffer(32);
        unsafe { TRUTH_BUF = buf as usize };
        let real = in_child(|out| sequence(out, unsafe { TRUTH_BUF } as *const u8));
        let privileges = Privileges::from_real_process().unwrap();
        let mut simulated = [0i64; 64];
        Sim::builder()
            .host(HostProfile::new().build())
            .privileges(privileges.clone())
            .build()
            .run(|| sequence(&mut simulated, buf));
        assert_eq!(simulated, real, "SimHost vs real ({privileges:?})");
        let mut plain = [0i64; 64];
        Sim::builder()
            .privileges(privileges)
            .build()
            .run(|| sequence(&mut plain, buf));
        assert_eq!(plain, real, "plain sim vs real");
    }
}
