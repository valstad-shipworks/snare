#![cfg(windows)]

use snare::Sim;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_NOT_SUPPORTED, GetLastError, HANDLE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Threading::{
    CancelWaitableTimer, CreateWaitableTimerA, CreateWaitableTimerExA, CreateWaitableTimerExW,
    CreateWaitableTimerW, SetWaitableTimer, TIMER_ALL_ACCESS, WaitForSingleObject,
};

#[derive(Clone, Copy, Debug)]
enum Creation {
    Wide,
    Ansi,
    ExtendedWide,
    ExtendedAnsi,
}

const CREATIONS: [Creation; 4] = [
    Creation::Wide,
    Creation::Ansi,
    Creation::ExtendedWide,
    Creation::ExtendedAnsi,
];

fn create_api(
    api: Creation,
    manual: bool,
    access: u32,
    attributes: *const SECURITY_ATTRIBUTES,
    named: bool,
) -> HANDLE {
    let wide = [b's' as u16, 0];
    let ansi = b"s\0";
    let wide_name = if named {
        wide.as_ptr()
    } else {
        std::ptr::null()
    };
    let ansi_name = if named {
        ansi.as_ptr()
    } else {
        std::ptr::null()
    };
    unsafe {
        match api {
            Creation::Wide => CreateWaitableTimerW(attributes, i32::from(manual), wide_name),
            Creation::Ansi => CreateWaitableTimerA(attributes, i32::from(manual), ansi_name),
            Creation::ExtendedWide => {
                CreateWaitableTimerExW(attributes, wide_name, u32::from(manual), access)
            }
            Creation::ExtendedAnsi => {
                CreateWaitableTimerExA(attributes, ansi_name, u32::from(manual), access)
            }
        }
    }
}

fn creation_probe(api: Creation, manual: bool, measured: bool) -> Vec<u32> {
    let timer = create_api(api, manual, TIMER_ALL_ACCESS, std::ptr::null(), false);
    assert!(!timer.is_null(), "{api:?}: {}", unsafe { GetLastError() });
    let mut observed = vec![unsafe { WaitForSingleObject(timer, 0) }];
    let start = Instant::now();
    assert_eq!(
        unsafe { SetWaitableTimer(timer, &-20_000, 0, None, std::ptr::null(), 0) },
        1
    );
    observed.push(unsafe { WaitForSingleObject(timer, 5000) });
    if measured {
        assert_eq!(start.elapsed(), Duration::from_millis(2), "{api:?}");
    }
    observed.push(unsafe { WaitForSingleObject(timer, 0) });
    assert_eq!(unsafe { CancelWaitableTimer(timer) }, 1);
    observed.push(unsafe { WaitForSingleObject(timer, 0) });
    assert_eq!(
        unsafe { SetWaitableTimer(timer, &-10_000_000, 0, None, std::ptr::null(), 0) },
        1
    );
    assert_eq!(unsafe { CancelWaitableTimer(timer) }, 1);
    observed.push(unsafe { WaitForSingleObject(timer, 0) });
    assert_eq!(unsafe { CloseHandle(timer) }, 1);
    observed
}

#[test]
fn all_timer_creation_apis_preserve_reset_behavior_os_truth() {
    let _installed = Sim::new();
    for api in CREATIONS {
        for manual in [false, true] {
            let native = snare::real(|| creation_probe(api, manual, false));
            let retained = if manual { 0 } else { 258 };
            assert_eq!(native, [258, 0, retained, retained, 258]);
            for deterministic in [false, true] {
                let mut builder = Sim::builder();
                if deterministic {
                    builder = builder.deterministic();
                }
                let observed = builder.build().run(|| creation_probe(api, manual, true));
                assert_eq!(observed, native, "{api:?}, manual={manual}");
            }
        }
    }
}

#[test]
fn extended_timer_creation_access_rights_match_the_host() {
    let probe = |api| {
        let timer = create_api(api, false, 0x100000, std::ptr::null(), false);
        assert!(!timer.is_null());
        let set = unsafe { SetWaitableTimer(timer, &-20_000, 0, None, std::ptr::null(), 0) };
        let set_error = unsafe { GetLastError() };
        let cancel = unsafe { CancelWaitableTimer(timer) };
        let cancel_error = unsafe { GetLastError() };
        let wait = unsafe { WaitForSingleObject(timer, 0) };
        assert_eq!(unsafe { CloseHandle(timer) }, 1);
        (set, set_error, cancel, cancel_error, wait)
    };
    let _installed = Sim::new();
    for api in [Creation::ExtendedWide, Creation::ExtendedAnsi] {
        let native = snare::real(|| probe(api));
        assert_eq!(native, (0, 5, 0, 5, 258));
        assert_eq!(Sim::new().run(|| probe(api)), native);
        assert_eq!(
            Sim::builder().deterministic().build().run(|| probe(api)),
            native
        );
    }
}

#[test]
fn all_timer_creation_apis_reject_named_and_security_modes_in_the_model() {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 0,
    };
    for api in CREATIONS {
        let timer = snare::real(|| create_api(api, false, TIMER_ALL_ACCESS, &attributes, false));
        assert!(!timer.is_null());
        assert_eq!(unsafe { CloseHandle(timer) }, 1);
        for deterministic in [false, true] {
            let mut builder = Sim::builder();
            if deterministic {
                builder = builder.deterministic();
            }
            builder.build().run(|| {
                for (attributes, named) in
                    [(&raw const attributes, false), (std::ptr::null(), true)]
                {
                    let timer = create_api(api, false, TIMER_ALL_ACCESS, attributes, named);
                    assert!(timer.is_null());
                    assert_eq!(unsafe { GetLastError() }, ERROR_NOT_SUPPORTED, "{api:?}");
                }
            });
        }
    }
}

fn feature_probe(manual: bool) -> Vec<u32> {
    use windows_sys::Win32::Foundation::{
        DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetWaitableTimerEx};
    let timer = unsafe {
        CreateWaitableTimerExW(
            std::ptr::null(),
            std::ptr::null(),
            u32::from(manual),
            TIMER_ALL_ACCESS,
        )
    };
    assert!(!timer.is_null());
    let process = unsafe { GetCurrentProcess() };
    let mut alias = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            DuplicateHandle(
                process,
                timer,
                process,
                &mut alias,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        },
        1
    );
    assert_eq!(unsafe { CloseHandle(timer) }, 1);
    let absolute = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .saturating_add(Duration::from_secs(11_644_473_600))
        .saturating_add(Duration::from_millis(3))
        .as_nanos()
        / 100;
    assert_eq!(
        unsafe {
            SetWaitableTimerEx(
                alias,
                &(absolute as i64),
                1000,
                None,
                std::ptr::null(),
                std::ptr::null(),
                2,
            )
        },
        1
    );
    let mut results = vec![unsafe { WaitForSingleObject(alias, u32::MAX) }, unsafe {
        WaitForSingleObject(alias, 0)
    }];
    assert_eq!(unsafe { CancelWaitableTimer(alias) }, 1);
    results.push(unsafe { WaitForSingleObject(alias, 0) });
    assert_eq!(
        unsafe { SetWaitableTimer(alias, &-20_000, 0, None, std::ptr::null(), 0) },
        1
    );
    results.push(unsafe { WaitForSingleObject(alias, 0) });
    results.push(unsafe { WaitForSingleObject(alias, u32::MAX) });
    let mut moved = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            DuplicateHandle(
                process,
                alias,
                process,
                &mut moved,
                0,
                0,
                DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
            )
        },
        1
    );
    assert_eq!(
        unsafe { SetWaitableTimer(moved, &-10_000, 0, None, std::ptr::null(), 0) },
        1
    );
    results.push(unsafe { WaitForSingleObject(moved, u32::MAX) });
    assert_eq!(unsafe { CloseHandle(moved) }, 1);
    results
}

#[test]
fn absolute_periodic_extended_and_duplicated_timers_match_native_signal_state() {
    for manual in [false, true] {
        let native = feature_probe(manual);
        assert_eq!(
            native,
            vec![
                0,
                if manual { 0 } else { 258 },
                if manual { 0 } else { 258 },
                258,
                0,
                0
            ]
        );
        for deterministic in [false, true] {
            let builder = Sim::builder();
            let sim = if deterministic {
                builder.deterministic()
            } else {
                builder
            }
            .build();
            assert_eq!(sim.run(|| feature_probe(manual)), native);
        }
    }
}

#[test]
fn an_unwaited_periodic_timer_does_not_hold_unrelated_sleep_at_its_first_tick() {
    for deterministic in [false, true] {
        let builder = Sim::builder();
        let sim = if deterministic {
            builder.deterministic()
        } else {
            builder
        }
        .build();
        sim.run(|| {
            for manual in [false, true] {
                let timer = unsafe {
                    CreateWaitableTimerExW(
                        std::ptr::null(),
                        std::ptr::null(),
                        u32::from(manual),
                        TIMER_ALL_ACCESS,
                    )
                };
                assert!(!timer.is_null());
                assert_eq!(
                    unsafe { SetWaitableTimer(timer, &-10_000, 1, None, std::ptr::null(), 0) },
                    1
                );
                let before = snare::sched::now();
                std::thread::sleep(Duration::from_millis(20));
                assert_eq!(
                    snare::sched::now() - before,
                    Duration::from_nanos(20_000_001)
                );
                assert_eq!(unsafe { WaitForSingleObject(timer, 0) }, 0);
                assert_eq!(unsafe { CancelWaitableTimer(timer) }, 1);
                assert_eq!(unsafe { CloseHandle(timer) }, 1);
            }
        });
    }
}

#[test]
fn periodic_auto_reset_waits_follow_successive_deadlines() {
    for deterministic in [false, true] {
        let builder = Sim::builder();
        let sim = if deterministic {
            builder.deterministic()
        } else {
            builder
        }
        .build();
        sim.run(|| {
            let timer = unsafe {
                CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), 0, TIMER_ALL_ACCESS)
            };
            let before = snare::sched::now();
            assert_eq!(
                unsafe { SetWaitableTimer(timer, &-20_000, 2, None, std::ptr::null(), 0) },
                1
            );
            for tick in 1..=5 {
                assert_eq!(unsafe { WaitForSingleObject(timer, u32::MAX) }, 0);
                assert_eq!(
                    snare::sched::now() - before,
                    Duration::from_nanos(tick * 2_000_000 + 1)
                );
            }
            assert_eq!(unsafe { CancelWaitableTimer(timer) }, 1);
            assert_eq!(unsafe { CloseHandle(timer) }, 1);
        });
    }
}

fn multiple_probe(manual: bool) -> Vec<u32> {
    use windows_sys::Win32::System::Threading::{
        WaitForMultipleObjects, WaitForMultipleObjectsEx, WaitForSingleObjectEx,
    };
    let handles = [0, 1].map(|_| unsafe {
        CreateWaitableTimerExW(
            std::ptr::null(),
            std::ptr::null(),
            u32::from(manual),
            TIMER_ALL_ACCESS,
        )
    });
    assert!(handles.iter().all(|handle| !handle.is_null()));
    let mut results = vec![unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 1, 2) }];
    for (handle, due) in handles.iter().zip([-20_000, -50_000]) {
        assert_eq!(
            unsafe { SetWaitableTimer(*handle, &due, 0, None, std::ptr::null(), 0) },
            1
        );
    }
    results.push(unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, u32::MAX) });
    if manual {
        assert_eq!(
            unsafe { SetWaitableTimer(handles[0], &-100_000_000, 0, None, std::ptr::null(), 0) },
            1
        );
    }
    results.push(unsafe { WaitForMultipleObjectsEx(2, handles.as_ptr(), 0, u32::MAX, 0) });
    for (handle, due) in handles.iter().zip([-20_000, -30_000]) {
        assert_eq!(
            unsafe { SetWaitableTimer(*handle, &due, 0, None, std::ptr::null(), 0) },
            1
        );
    }
    results.push(unsafe { WaitForMultipleObjectsEx(2, handles.as_ptr(), 1, u32::MAX, 0) });
    results.push(unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 1, 0) });
    assert_eq!(
        unsafe { SetWaitableTimer(handles[0], &-10_000, 0, None, std::ptr::null(), 0) },
        1
    );
    results.push(unsafe { WaitForSingleObjectEx(handles[0], u32::MAX, 0) });
    for handle in handles {
        assert_eq!(unsafe { CloseHandle(handle) }, 1);
    }
    results
}

#[test]
fn multiple_waits_preserve_any_index_and_atomic_all_consumption() {
    for manual in [false, true] {
        let native = multiple_probe(manual);
        assert_eq!(native, vec![258, 0, 1, 0, if manual { 0 } else { 258 }, 0]);
        for deterministic in [false, true] {
            let builder = Sim::builder();
            let sim = if deterministic {
                builder.deterministic()
            } else {
                builder
            }
            .build();
            let (model, domain) = sim.run(|| {
                (
                    multiple_probe(manual),
                    snare_interpose::Domain::current().unwrap(),
                )
            });
            assert_eq!(model, native);
            assert_eq!(
                domain.outside_wakes(),
                0,
                "manual={manual} deterministic={deterministic}"
            );
        }
    }
}

#[test]
fn multiple_timer_waits_left_after_a_run_finish_at_real_pace() {
    for deterministic in [false, true] {
        let builder = Sim::builder();
        let sim = if deterministic {
            builder.deterministic()
        } else {
            builder
        }
        .build();
        let (tx, rx) = std::sync::mpsc::channel();
        let domain = sim.run(|| {
            std::thread::spawn(move || {
                tx.send(multiple_probe(false)).unwrap();
            });
            snare_interpose::Domain::current().unwrap()
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            vec![258, 0, 1, 0, 258, 0]
        );
        assert_eq!(domain.outside_wakes(), 0);
    }
}

#[test]
fn a_native_timer_wait_released_after_reentry_keeps_the_domain_settling() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    for deterministic in [false, true] {
        let mut builder = Sim::builder();
        if deterministic {
            builder = builder.deterministic();
        }
        let sim = builder.build();
        let starting = Arc::new(AtomicU64::new(u64::MAX));
        let begin = Arc::new(AtomicBool::new(false));
        let admitted = Arc::new(AtomicBool::new(false));
        let resume = Arc::new(AtomicBool::new(false));
        let (domain, waiter) = sim.run(|| {
            let starting = starting.clone();
            let begin = begin.clone();
            let (ready, ready_rx) = std::sync::mpsc::channel();
            let waiter = std::thread::spawn(move || {
                ready.send(()).unwrap();
                std::thread::park();
                starting.store(snare_interpose::thread_lineage(), Ordering::Release);
                let start = snare::real(Instant::now);
                while !begin.load(Ordering::Acquire) {
                    assert!(snare::real(|| start.elapsed()) < Duration::from_secs(5));
                    snare::real(|| std::thread::sleep(Duration::from_millis(1)));
                }
                assert!(snare_interpose::dormant());
                let timer = unsafe {
                    CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), 1, TIMER_ALL_ACCESS)
                };
                assert!(!timer.is_null());
                assert_eq!(
                    unsafe { SetWaitableTimer(timer, &-600_000_000, 0, None, std::ptr::null(), 0) },
                    1
                );
                let result = unsafe { WaitForSingleObject(timer, u32::MAX) };
                assert_eq!(unsafe { CloseHandle(timer) }, 1);
                result
            });
            ready_rx.recv().unwrap();
            (snare_interpose::Domain::current().unwrap(), waiter)
        });
        waiter.thread().unpark();
        let start = Instant::now();
        while starting.load(Ordering::Acquire) == u64::MAX {
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(1));
        }
        let lease = sim.busy("timer admission");
        let outside_before = domain.outside_wakes();
        let lineage = starting.load(Ordering::Acquire);
        let key = domain.key();
        domain.arm(domain.epoch(), {
            let admitted = admitted.clone();
            let resume = resume.clone();
            Arc::new(move || {
                assert_eq!(snare_interpose::Domain::current().unwrap().key(), key);
                assert_eq!(snare_interpose::thread_lineage(), lineage);
                assert!(!snare_interpose::det_active());
                admitted.store(true, Ordering::Release);
                let start = Instant::now();
                while !resume.load(Ordering::Acquire) {
                    assert!(start.elapsed() < Duration::from_secs(5));
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        });
        begin.store(true, Ordering::Release);
        while !admitted.load(Ordering::Acquire) {
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(1));
        }
        let row = domain
            .participants()
            .into_iter()
            .find(|row| row.id == lineage)
            .unwrap();
        assert_eq!(row.state, snare_interpose::PState::Blocked);
        assert_eq!(row.wait, Some("sleep"));
        let observed = sim.run(|| {
            sim.time().advance(Duration::from_secs(61));
            snare::sched::mark_background("timer observer");
            drop(lease);
            let observed = domain.quiescence(false, || None);
            resume.store(true, Ordering::Release);
            observed
        });
        assert_eq!(waiter.join().unwrap(), 0);
        assert_eq!(
            observed.blocker.as_ref().map(|(kind, _)| *kind),
            Some(snare_interpose::BlockerKind::Settling),
            "deterministic={deterministic}: {observed:?}"
        );
        assert!(!observed.quiescent);
        assert_eq!(domain.outside_wakes(), outside_before);
    }
}

fn read_only_alias_probe() -> (i32, u32, i32, u32) {
    use windows_sys::Win32::Foundation::DuplicateHandle;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let timer =
        unsafe { CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), 0, TIMER_ALL_ACCESS) };
    let process = unsafe { GetCurrentProcess() };
    let mut alias = std::ptr::null_mut();
    assert_eq!(
        unsafe { DuplicateHandle(process, timer, process, &mut alias, 0x100000, 0, 0) },
        1
    );
    let cancel = unsafe { CancelWaitableTimer(alias) };
    let cancel_error = unsafe { GetLastError() };
    let set = unsafe { SetWaitableTimer(alias, &-10_000, 0, None, std::ptr::null(), 0) };
    let set_error = unsafe { GetLastError() };
    assert_eq!(unsafe { CloseHandle(alias) }, 1);
    assert_eq!(unsafe { CloseHandle(timer) }, 1);
    (cancel, cancel_error, set, set_error)
}

#[test]
fn timer_aliases_preserve_each_handles_access_rights() {
    let native = read_only_alias_probe();
    assert_eq!(native, (0, 5, 0, 5));
    for deterministic in [false, true] {
        let builder = Sim::builder();
        let sim = if deterministic {
            builder.deterministic()
        } else {
            builder
        }
        .build();
        assert_eq!(sim.run(read_only_alias_probe), native);
    }
}

fn timer_probe(manual: bool) {
    let timer = unsafe {
        CreateWaitableTimerExW(
            std::ptr::null(),
            std::ptr::null(),
            2 | u32::from(manual),
            TIMER_ALL_ACCESS,
        )
    };
    assert!(!timer.is_null());
    let start = Instant::now();
    assert_eq!(
        unsafe { SetWaitableTimer(timer, &-65_000, 0, None, std::ptr::null(), 0) },
        1
    );
    assert_eq!(unsafe { WaitForSingleObject(timer, u32::MAX) }, 0);
    assert_eq!(start.elapsed(), Duration::from_micros(6500));
    assert_eq!(
        unsafe { WaitForSingleObject(timer, 0) },
        if manual { 0 } else { 258 }
    );
    assert_eq!(unsafe { CancelWaitableTimer(timer) }, 1);
    assert_eq!(
        unsafe { WaitForSingleObject(timer, 0) },
        if manual { 0 } else { 258 }
    );
    assert_eq!(
        unsafe { SetWaitableTimer(timer, &-10_000_000, 0, None, std::ptr::null(), 0) },
        1
    );
    assert_eq!(unsafe { CancelWaitableTimer(timer) }, 1);
    assert_eq!(unsafe { WaitForSingleObject(timer, 0) }, 258);
    assert_eq!(unsafe { CloseHandle(timer) }, 1);
}

#[test]
fn relative_timer_precision_reset_and_cancellation() {
    for manual in [false, true] {
        Sim::new().run(|| timer_probe(manual));
        Sim::builder()
            .deterministic()
            .build()
            .run(|| timer_probe(manual));
    }
}

#[test]
fn cancelling_an_armed_timer_removes_its_far_deadline() {
    for deterministic in [false, true] {
        let builder = Sim::builder();
        let builder = if deterministic {
            builder.deterministic()
        } else {
            builder
        };
        builder.build().run(|| {
            let timer = unsafe {
                CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), 2, TIMER_ALL_ACCESS)
            };
            assert!(!timer.is_null());
            assert_eq!(
                unsafe { SetWaitableTimer(timer, &-1_000_000_000, 0, None, std::ptr::null(), 0) },
                1
            );
            assert_eq!(unsafe { CancelWaitableTimer(timer) }, 1);
            let start = Instant::now();
            std::thread::sleep(Duration::from_micros(1500));
            assert_eq!(start.elapsed(), Duration::from_micros(1500));
            assert_eq!(unsafe { WaitForSingleObject(timer, 0) }, 258);
            assert_eq!(unsafe { CloseHandle(timer) }, 1);
        });
    }
}

#[test]
fn apc_timer_mode_is_explicitly_rejected() {
    Sim::new().run(|| {
        let timer = unsafe {
            CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), 2, TIMER_ALL_ACCESS)
        };
        assert!(!timer.is_null());
        unsafe extern "system" fn callback(_: *const std::ffi::c_void, _: u32, _: u32) {}
        assert_eq!(
            unsafe { SetWaitableTimer(timer, &-10_000, 0, Some(callback), std::ptr::null(), 0) },
            0
        );
        assert_eq!(unsafe { GetLastError() }, ERROR_NOT_SUPPORTED);
        assert_eq!(unsafe { CloseHandle(timer) }, 1);
    });
}

#[test]
fn closing_a_fired_timer_outside_the_sim_releases_its_deadline_hold() {
    for deterministic in [false, true] {
        let builder = Sim::builder();
        let sim = if deterministic {
            builder.deterministic()
        } else {
            builder
        }
        .build();
        let handle = sim.run(|| {
            let timer = unsafe {
                CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), 2, TIMER_ALL_ACCESS)
            };
            assert!(!timer.is_null());
            assert_eq!(
                unsafe { SetWaitableTimer(timer, &-10_000, 0, None, std::ptr::null(), 0) },
                1
            );
            timer
        });
        sim.advance_time(Duration::from_millis(1));
        assert_eq!(unsafe { CloseHandle(handle) }, 1);
        sim.run(|| {
            let start = Instant::now();
            std::thread::sleep(Duration::from_micros(1500));
            assert_eq!(start.elapsed(), Duration::from_micros(1500));
        });
    }
}

#[test]
fn failed_close_keeps_a_protected_timer_live() {
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_PROTECT_FROM_CLOSE, SetHandleInformation};
    Sim::new().run(|| {
        let timer = unsafe {
            CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), 2, TIMER_ALL_ACCESS)
        };
        assert!(!timer.is_null());
        assert_eq!(
            unsafe {
                SetHandleInformation(
                    timer,
                    HANDLE_FLAG_PROTECT_FROM_CLOSE,
                    HANDLE_FLAG_PROTECT_FROM_CLOSE,
                )
            },
            1
        );
        assert_eq!(unsafe { CloseHandle(timer) }, 0);
        assert_eq!(
            unsafe { SetWaitableTimer(timer, &-10_000, 0, None, std::ptr::null(), 0) },
            1
        );
        assert_eq!(unsafe { WaitForSingleObject(timer, u32::MAX) }, 0);
        assert_eq!(
            unsafe { SetHandleInformation(timer, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0) },
            1
        );
        assert_eq!(unsafe { CloseHandle(timer) }, 1);
    });
}

#[test]
fn relative_timer_deadlines_use_the_100_nanosecond_api_grid() {
    for deterministic in [false, true] {
        let builder = Sim::builder();
        let builder = if deterministic {
            builder.deterministic()
        } else {
            builder
        };
        builder.build().run(|| {
            let timer = unsafe {
                CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), 2, TIMER_ALL_ACCESS)
            };
            assert!(!timer.is_null());
            for nanos in [100u64, 200, 900, 1000, 650_000, 6_500_000] {
                let before = snare::sched::now();
                let due = -((nanos / 100) as i64);
                assert_eq!(
                    unsafe { SetWaitableTimer(timer, &due, 0, None, std::ptr::null(), 0) },
                    1
                );
                assert_eq!(unsafe { WaitForSingleObject(timer, u32::MAX) }, 0);
                assert_eq!(
                    snare::sched::now() - before,
                    Duration::from_nanos(nanos + 1)
                );
            }
            assert_eq!(unsafe { CloseHandle(timer) }, 1);
        });
    }
}

#[test]
fn concurrent_clock_advances_release_timer_waits_without_outside_wakes() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    for manual in [false, true] {
        let sim = Sim::new();
        let time = sim.time();
        let requests = Arc::new(AtomicUsize::new(0));
        let pending = requests.clone();
        let driver = std::thread::spawn(move || {
            let mut completed = 0;
            while completed < 500 {
                let request = pending.load(Ordering::Acquire);
                if request != completed {
                    time.advance(Duration::from_micros(100));
                    completed = request;
                }
                std::thread::yield_now();
            }
        });
        let domain = sim.run(|| {
            let timer = unsafe {
                CreateWaitableTimerExW(
                    std::ptr::null(),
                    std::ptr::null(),
                    2 | u32::from(manual),
                    TIMER_ALL_ACCESS,
                )
            };
            assert!(!timer.is_null());
            for request in 1..=500 {
                assert_eq!(
                    unsafe { SetWaitableTimer(timer, &-1000, 0, None, std::ptr::null(), 0) },
                    1
                );
                requests.store(request, Ordering::Release);
                assert_eq!(unsafe { WaitForSingleObject(timer, u32::MAX) }, 0);
                assert_eq!(
                    unsafe { WaitForSingleObject(timer, 0) },
                    if manual { 0 } else { 258 }
                );
            }
            assert_eq!(unsafe { CloseHandle(timer) }, 1);
            snare_interpose::Domain::current().unwrap()
        });
        driver.join().unwrap();
        assert_eq!(domain.outside_wakes(), 0);
    }
}

#[test]
fn a_child_left_after_the_run_finishes_timer_sleeps_at_real_pace() {
    for deterministic in [false, true] {
        let builder = Sim::builder();
        let sim = if deterministic {
            builder.deterministic()
        } else {
            builder
        }
        .build();
        let (tx, rx) = std::sync::mpsc::channel();
        let real_start = snare::real(Instant::now);
        let domain = sim.run(|| {
            std::thread::spawn(move || {
                let mut readings = Vec::new();
                for _ in 0..5 {
                    std::thread::sleep(Duration::from_micros(1500));
                    readings.push(snare::sched::now().as_nanos());
                }
                tx.send(readings).unwrap();
            });
            snare_interpose::Domain::current().unwrap()
        });
        let readings = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            readings,
            vec![1_500_001, 3_000_002, 4_500_003, 6_000_004, 7_500_005]
        );
        assert!(snare::real(|| real_start.elapsed()) >= Duration::from_nanos(7_500_005));
        assert_eq!(domain.outside_wakes(), 0);
    }
}

#[test]
fn a_scaled_timer_keeps_waiting_when_its_clock_is_paused() {
    let sim = Sim::builder().time_rate(1.0).build();
    let time = sim.time();
    let (ready, ready_rx) = std::sync::mpsc::channel();
    let (finished, finished_rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| {
            sim.run(|| {
                let timer = unsafe {
                    CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), 2, TIMER_ALL_ACCESS)
                };
                assert!(!timer.is_null());
                let start = snare::sched::now();
                assert_eq!(
                    unsafe { SetWaitableTimer(timer, &-2_500_000, 0, None, std::ptr::null(), 0) },
                    1
                );
                time.pause();
                ready.send(()).unwrap();
                assert_eq!(unsafe { WaitForSingleObject(timer, u32::MAX) }, 0);
                let elapsed = snare::sched::now() - start;
                finished.send(elapsed).unwrap();
                assert_eq!(unsafe { CloseHandle(timer) }, 1);
            });
        });
        ready_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let while_paused = finished_rx.recv_timeout(Duration::from_millis(400));
        time.resume();
        waiter.join().unwrap();
        assert_eq!(
            while_paused,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        );
        assert!(finished_rx.recv().unwrap() >= Duration::from_millis(250));
    });
}

#[test]
fn native_events_keep_their_identity_during_timer_handle_reuse() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use windows_sys::Win32::System::Threading::{CreateEventExW, EVENT_ALL_ACCESS};

    let sim = Sim::new();
    let stop = Arc::new(AtomicBool::new(false));
    let observed = Arc::new(AtomicUsize::new(0));
    let native = {
        let stop = stop.clone();
        let observed = observed.clone();
        std::thread::spawn(move || {
            assert!(snare_interpose::Domain::current().is_none());
            let start = Instant::now();
            while !stop.load(Ordering::Acquire) && start.elapsed() < Duration::from_secs(10) {
                let event = unsafe {
                    CreateEventExW(std::ptr::null(), std::ptr::null(), 0, EVENT_ALL_ACCESS)
                };
                if event.is_null() {
                    return Err(("create", u32::MAX, unsafe { GetLastError() }));
                }
                let result = unsafe { WaitForSingleObject(event, 0) };
                let error = unsafe { GetLastError() };
                let closed = unsafe { CloseHandle(event) };
                if result != 258 {
                    return Err(("wait", result, error));
                }
                if closed != 1 {
                    return Err(("close", closed as u32, unsafe { GetLastError() }));
                }
                observed.fetch_add(1, Ordering::Release);
            }
            Ok(())
        })
    };
    let result = sim.run(|| {
        let observed = observed.clone();
        std::thread::spawn(move || {
            snare::sched::mark_background("timer handles");
            let start = snare::real(Instant::now);
            while observed.load(Ordering::Acquire) == 0 {
                if snare::real(|| start.elapsed()) >= Duration::from_secs(5) {
                    return Err(("native startup", u32::MAX));
                }
                snare::real(std::thread::yield_now);
            }
            for _ in 0..5000 {
                if snare::real(|| start.elapsed()) >= Duration::from_secs(10) {
                    return Err(("timer deadline", u32::MAX));
                }
                let timer = unsafe {
                    CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), 0, TIMER_ALL_ACCESS)
                };
                if timer.is_null() {
                    return Err(("timer create", unsafe { GetLastError() }));
                }
                let set =
                    unsafe { SetWaitableTimer(timer, &-10_000_000, 0, None, std::ptr::null(), 0) };
                let error = unsafe { GetLastError() };
                let closed = unsafe { CloseHandle(timer) };
                if set != 1 {
                    return Err(("timer set", error));
                }
                if closed != 1 {
                    return Err(("timer close", unsafe { GetLastError() }));
                }
            }
            Ok(())
        })
        .join()
        .unwrap()
    });
    stop.store(true, Ordering::Release);
    let native_result = native.join().unwrap();
    assert_eq!(result, Ok(()));
    assert_eq!(native_result, Ok(()));
    assert!(observed.load(Ordering::Acquire) > 0);
}

#[test]
fn duplicate_close_source_matches_native_alias_lifetime() {
    use windows_sys::Win32::Foundation::{
        CompareObjectHandles, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle,
        GetLastError,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let probe = |invalid_target: bool| {
        let timer = unsafe {
            CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), 0, TIMER_ALL_ACCESS)
        };
        assert!(!timer.is_null());
        let process = unsafe { GetCurrentProcess() };
        let mut alias = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                DuplicateHandle(
                    process,
                    timer,
                    process,
                    &mut alias,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            },
            1
        );
        let mut rejected = std::ptr::null_mut();
        let result = unsafe {
            DuplicateHandle(
                process,
                timer,
                if invalid_target {
                    1usize as HANDLE
                } else {
                    process
                },
                &mut rejected,
                0,
                0,
                DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
            )
        };
        let error = unsafe { GetLastError() };
        if result != 0 {
            unsafe { CloseHandle(rejected) };
        }
        let source_valid = unsafe { CompareObjectHandles(timer, alias) };
        if source_valid != 0 {
            unsafe { CloseHandle(timer) };
        }
        assert_eq!(
            unsafe { SetWaitableTimer(alias, &-10_000, 0, None, std::ptr::null(), 0) },
            1
        );
        let signal = unsafe { WaitForSingleObject(alias, 100) };
        assert_eq!(unsafe { CloseHandle(alias) }, 1);
        (result, (result == 0).then_some(error), source_valid, signal)
    };
    for invalid_target in [false, true] {
        let native = snare::real(|| probe(invalid_target));
        assert_eq!(native.0, i32::from(!invalid_target));
        assert_eq!(native.2, 0);
        assert_eq!(native.3, 0);
        for det in [false, true] {
            let sim = if det {
                Sim::builder().deterministic().build()
            } else {
                Sim::new()
            };
            assert_eq!(
                sim.run(|| probe(invalid_target)),
                native,
                "det={det} invalid_target={invalid_target}"
            );
        }
    }
}

#[test]
fn duplicate_close_only_matches_native_target_output() {
    use windows_sys::Win32::Foundation::{
        CompareObjectHandles, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let probe = || {
        let timer = unsafe {
            CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), 0, TIMER_ALL_ACCESS)
        };
        assert!(!timer.is_null());
        let mut alias = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    timer,
                    GetCurrentProcess(),
                    &mut alias,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            },
            1
        );
        let mut target = 0x1234usize as HANDLE;
        let result = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                timer,
                std::ptr::null_mut(),
                &mut target,
                0,
                0,
                DUPLICATE_CLOSE_SOURCE,
            )
        };
        let source_valid = unsafe { CompareObjectHandles(timer, alias) };
        if source_valid != 0 {
            unsafe { CloseHandle(timer) };
        }
        assert_eq!(unsafe { CloseHandle(alias) }, 1);
        (result, target as usize, source_valid)
    };
    let native = snare::real(probe);
    assert_eq!(native, (1, 0, 0));
    for det in [false, true] {
        let sim = if det {
            Sim::builder().deterministic().build()
        } else {
            Sim::new()
        };
        assert_eq!(sim.run(probe), native, "det={det}");
    }
}

#[test]
fn rejected_foreign_timer_duplication_still_closes_the_source() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{
        CompareObjectHandles, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, GetProcessId,
    };
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["__foreign_timer_target__", "--exact"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    assert!(child.wait().unwrap().success());
    let foreign = child.as_raw_handle();
    let pid = unsafe { GetProcessId(foreign) };
    assert_ne!(pid, 0);
    assert_ne!(pid, unsafe { GetCurrentProcessId() });
    let probe = || {
        let timer = unsafe {
            CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), 0, TIMER_ALL_ACCESS)
        };
        assert!(!timer.is_null());
        let process = unsafe { GetCurrentProcess() };
        let mut alias = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                DuplicateHandle(
                    process,
                    timer,
                    process,
                    &mut alias,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            },
            1
        );
        let mut target = std::ptr::null_mut();
        let result = unsafe {
            DuplicateHandle(
                process,
                timer,
                foreign,
                &mut target,
                0,
                0,
                DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
            )
        };
        let error = unsafe { GetLastError() };
        let source_valid = unsafe { CompareObjectHandles(timer, alias) };
        if source_valid != 0 {
            unsafe { CloseHandle(timer) };
        }
        assert_eq!(
            unsafe { SetWaitableTimer(alias, &-10_000, 0, None, std::ptr::null(), 0) },
            1
        );
        let signal = unsafe { WaitForSingleObject(alias, 100) };
        assert_eq!(unsafe { CloseHandle(alias) }, 1);
        (result, error, source_valid, signal)
    };
    let native = snare::real(probe);
    assert_eq!((native.0, native.2, native.3), (0, 0, 0));
    assert_ne!(native.1, 0);
    for det in [false, true] {
        let sim = if det {
            Sim::builder().deterministic().build()
        } else {
            Sim::new()
        };
        let model = sim.run(probe);
        assert_eq!((model.0, model.2, model.3), (native.0, native.2, native.3));
        assert_eq!(model.1, ERROR_NOT_SUPPORTED);
    }
}
