#![cfg(target_os = "linux")]

//! Memory-locking coverage: `mlockall`/`munlockall` and the CAP_IPC_LOCK gate.
//!
//! man 2 mlockall: locks all of the calling process's pages into RAM so they are never paged out —
//! the standard latency-hygiene step for a real-time thread. The `flags` argument selects
//! MCL_CURRENT (pages mapped now), MCL_FUTURE (pages mapped later) and optionally MCL_ONFAULT.
//! Locking more than RLIMIT_MEMLOCK requires CAP_IPC_LOCK (man 7 capabilities), else EPERM.

use snare::{CAP_IPC_LOCK, EasyBuilder, HostProfile, Sim};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[test]
fn mlockall_without_cap_is_eperm() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(
            unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) },
            -1
        );
        assert_eq!(errno(), libc::EPERM);
    });
}

#[test]
fn mlockall_with_cap_succeeds_for_each_flag_combo() {
    // Every documented flag combination should be accepted once the capability is present; the sim
    // records the locked state rather than touching real memory.
    let host = HostProfile::new().cap(CAP_IPC_LOCK).build();
    Sim::builder().host(host).build().run(|| {
        for flags in [
            libc::MCL_CURRENT,
            libc::MCL_FUTURE,
            libc::MCL_CURRENT | libc::MCL_FUTURE,
        ] {
            assert_eq!(unsafe { libc::mlockall(flags) }, 0, "flags {flags}");
        }
    });
}

#[test]
fn munlockall_always_succeeds() {
    // man 2 munlockall: unlocking is not privilege-gated. It must succeed whether or not anything
    // was locked, and whether or not the process holds CAP_IPC_LOCK.
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(unsafe { libc::munlockall() }, 0);
    });

    let host = HostProfile::new().cap(CAP_IPC_LOCK).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(unsafe { libc::mlockall(libc::MCL_CURRENT) }, 0);
        assert_eq!(unsafe { libc::munlockall() }, 0);
        // Re-locking after an unlock still works.
        assert_eq!(unsafe { libc::mlockall(libc::MCL_FUTURE) }, 0);
    });
}

#[test]
fn realtime_preset_permits_locking() {
    // EasyBuilder::realtime grants CAP_IPC_LOCK, so the canonical mlockall(MCL_CURRENT|MCL_FUTURE)
    // of an RT setup path succeeds out of the box.
    Sim::builder()
        .host(EasyBuilder::realtime().build())
        .build()
        .run(|| {
            assert_eq!(
                unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) },
                0
            );
        });
}

#[test]
fn unprivileged_preset_refuses_locking() {
    // EasyBuilder::unprivileged models the same hardware with no capabilities — the graceful
    // degradation path where a program must tolerate EPERM from mlockall.
    Sim::builder()
        .host(EasyBuilder::unprivileged().build())
        .build()
        .run(|| {
            assert_eq!(
                unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) },
                -1
            );
            assert_eq!(errno(), libc::EPERM);
        });
}

#[test]
fn laptop_preset_refuses_locking() {
    Sim::builder()
        .host(EasyBuilder::laptop().build())
        .build()
        .run(|| {
            assert_eq!(unsafe { libc::mlockall(libc::MCL_CURRENT) }, -1);
            assert_eq!(errno(), libc::EPERM);
        });
}
