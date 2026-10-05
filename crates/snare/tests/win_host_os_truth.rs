#![cfg(windows)]

//! The Windows host plane against the machine the tests run on, real (`snare::real`) and simulated
//! side by side: the clocks' invariants (`QueryPerformanceCounter`, `GetTickCount64`,
//! `QueryUnbiasedInterruptTime`, the two system-time reads), the timer-resolution calls and the
//! thread-priority round trip. None needs administrator rights; the priority one changes the
//! calling thread's real priority for a moment and restores it.

use std::time::Duration;

use snare::Sim;
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, FILETIME, GetLastError, HANDLE,
    SetLastError,
};
use windows_sys::Win32::System::Memory::{GetProcessWorkingSetSizeEx, SetProcessWorkingSetSizeEx};
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows_sys::Win32::System::SystemInformation::{
    GetSystemTimeAsFileTime, GetSystemTimePreciseAsFileTime, GetTickCount64,
};
use windows_sys::Win32::System::Threading::{
    ABOVE_NORMAL_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS, CreateEventW, GetCurrentProcess,
    GetCurrentThread, GetPriorityClass, GetThreadPriority, HIGH_PRIORITY_CLASS,
    IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS, PROCESS_MODE_BACKGROUND_BEGIN,
    PROCESS_MODE_BACKGROUND_END, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SET_INFORMATION, PROCESS_SET_QUOTA, REALTIME_PRIORITY_CLASS, SetPriorityClass,
    SetThreadAffinityMask, SetThreadPriority, THREAD_MODE_BACKGROUND_BEGIN,
    THREAD_MODE_BACKGROUND_END, THREAD_PRIORITY_ABOVE_NORMAL, THREAD_PRIORITY_HIGHEST,
    THREAD_PRIORITY_LOWEST, THREAD_PRIORITY_NORMAL, THREAD_PRIORITY_TIME_CRITICAL,
    THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SET_INFORMATION,
    THREAD_SET_LIMITED_INFORMATION,
};

/// Serializes the tests: the real side of each changes or reads the process's priority class, its
/// background mode or the calling thread's priority, which another test running beside it would
/// change under it.
fn host_state() -> std::sync::MutexGuard<'static, ()> {
    static HOST: std::sync::Mutex<()> = std::sync::Mutex::new(());
    HOST.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct TestHandle(HANDLE);

impl Drop for TestHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn duplicate(handle: HANDLE, access: Option<u32>) -> TestHandle {
    let process = unsafe { GetCurrentProcess() };
    let mut result = std::ptr::null_mut();
    assert_ne!(
        unsafe {
            DuplicateHandle(
                process,
                handle,
                process,
                &mut result,
                access.unwrap_or(0),
                0,
                if access.is_none() {
                    DUPLICATE_SAME_ACCESS
                } else {
                    0
                },
            )
        },
        0
    );
    TestHandle(result)
}

fn scheduling_handle_matrix() -> Vec<(&'static str, i64, u32)> {
    let thread = unsafe { GetCurrentThread() };
    let process = unsafe { GetCurrentProcess() };
    let event = TestHandle(unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) });
    assert!(!event.0.is_null());
    let mut rows = Vec::new();
    for (kind, source, access) in [
        ("thread full", thread, None),
        ("thread query", thread, Some(THREAD_QUERY_INFORMATION)),
        (
            "thread limited query",
            thread,
            Some(THREAD_QUERY_LIMITED_INFORMATION),
        ),
        ("thread set", thread, Some(THREAD_SET_INFORMATION)),
        (
            "thread limited set",
            thread,
            Some(THREAD_SET_LIMITED_INFORMATION),
        ),
        (
            "thread affinity",
            thread,
            Some(THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_LIMITED_INFORMATION),
        ),
        ("thread no access", thread, Some(0)),
        ("process full", process, None),
        ("process query", process, Some(PROCESS_QUERY_INFORMATION)),
        (
            "process limited query",
            process,
            Some(PROCESS_QUERY_LIMITED_INFORMATION),
        ),
        ("process set", process, Some(PROCESS_SET_INFORMATION)),
        ("process no access", process, Some(0)),
        ("event", event.0, None),
    ] {
        let handle = duplicate(source, access);
        unsafe { SetLastError(1234) };
        let result = unsafe { GetThreadPriority(handle.0) };
        rows.push((kind, result as i64, unsafe { GetLastError() }));
        unsafe { SetLastError(1234) };
        let result = unsafe { SetThreadPriority(handle.0, THREAD_PRIORITY_NORMAL) };
        rows.push((kind, i64::from(result != 0), unsafe { GetLastError() }));
        unsafe { SetLastError(1234) };
        let result = unsafe { SetThreadAffinityMask(handle.0, 0) };
        rows.push((kind, result as i64, unsafe { GetLastError() }));
        unsafe { SetLastError(1234) };
        let previous = unsafe { SetThreadAffinityMask(handle.0, 1) };
        rows.push((kind, i64::from(previous != 0), unsafe { GetLastError() }));
        if previous != 0 {
            assert_ne!(unsafe { SetThreadAffinityMask(handle.0, previous) }, 0);
        }
        unsafe { SetLastError(1234) };
        let result = unsafe { GetPriorityClass(handle.0) };
        rows.push((kind, result as i64, unsafe { GetLastError() }));
        unsafe { SetLastError(1234) };
        let result = unsafe { SetPriorityClass(handle.0, NORMAL_PRIORITY_CLASS) };
        rows.push((kind, i64::from(result != 0), unsafe { GetLastError() }));
        unsafe { SetLastError(1234) };
        let result = unsafe { SetThreadPriority(handle.0, 3) };
        rows.push((kind, i64::from(result != 0), unsafe { GetLastError() }));
        unsafe { SetLastError(1234) };
        let result = unsafe { SetPriorityClass(handle.0, 0) };
        rows.push((kind, i64::from(result != 0), unsafe { GetLastError() }));
    }
    let closed = duplicate(thread, None);
    let handle = closed.0;
    drop(closed);
    for (kind, handle) in [
        ("closed", handle),
        ("null", std::ptr::null_mut()),
        ("invalid", 0x123456usize as HANDLE),
    ] {
        unsafe { SetLastError(1234) };
        rows.push((kind, unsafe { GetThreadPriority(handle) } as i64, unsafe {
            GetLastError()
        }));
        unsafe { SetLastError(1234) };
        rows.push((
            kind,
            unsafe { SetThreadPriority(handle, 0) } as i64,
            unsafe { GetLastError() },
        ));
        unsafe { SetLastError(1234) };
        rows.push((
            kind,
            unsafe { SetThreadAffinityMask(handle, 1) } as i64,
            unsafe { GetLastError() },
        ));
        unsafe { SetLastError(1234) };
        rows.push((kind, unsafe { GetPriorityClass(handle) } as i64, unsafe {
            GetLastError()
        }));
        unsafe { SetLastError(1234) };
        rows.push((
            kind,
            unsafe { SetPriorityClass(handle, NORMAL_PRIORITY_CLASS) } as i64,
            unsafe { GetLastError() },
        ));
    }
    rows
}

#[test]
fn scheduling_handle_access_and_errors_match_the_host() {
    let _host = host_state();
    let real = snare::real(scheduling_handle_matrix);
    let modeled = Sim::new().run(scheduling_handle_matrix);
    for (index, (model, native)) in modeled.iter().zip(&real).enumerate() {
        assert_eq!(model, native, "case {index}");
    }
    assert_eq!(modeled.len(), real.len());
}

fn scheduling_aliases() -> Vec<i64> {
    let thread = unsafe { GetCurrentThread() };
    let first = duplicate(thread, None);
    let second = duplicate(first.0, None);
    let saved = unsafe { GetThreadPriority(thread) };
    assert_ne!(
        unsafe { SetThreadPriority(first.0, THREAD_PRIORITY_ABOVE_NORMAL) },
        0
    );
    let mut result =
        vec![
            unsafe { GetThreadPriority(second.0) } as i64,
            unsafe { GetThreadPriority(thread) } as i64,
        ];
    drop(first);
    result.push(unsafe { GetThreadPriority(second.0) } as i64);
    assert_ne!(
        unsafe { SetThreadPriority(second.0, THREAD_PRIORITY_LOWEST) },
        0
    );
    result.push(unsafe { GetThreadPriority(thread) } as i64);
    assert_ne!(unsafe { SetThreadPriority(thread, saved) }, 0);
    let previous = unsafe { SetThreadAffinityMask(thread, 1) };
    assert_ne!(previous, 0);
    result.push(unsafe { SetThreadAffinityMask(second.0, 1) } as i64);
    assert_ne!(unsafe { SetThreadAffinityMask(thread, previous) }, 0);
    let process = unsafe { GetCurrentProcess() };
    let first = duplicate(process, None);
    let second = duplicate(first.0, None);
    let saved = unsafe { GetPriorityClass(process) };
    assert_ne!(
        unsafe { SetPriorityClass(first.0, BELOW_NORMAL_PRIORITY_CLASS) },
        0
    );
    result.push(unsafe { GetPriorityClass(second.0) } as i64);
    drop(first);
    result.push(unsafe { GetPriorityClass(process) } as i64);
    assert_ne!(unsafe { SetPriorityClass(second.0, saved) }, 0);
    result
}

#[test]
fn duplicated_scheduling_handles_share_their_objects_state() {
    let _host = host_state();
    let real = snare::real(scheduling_aliases);
    assert_eq!(Sim::new().run(scheduling_aliases), real);
}

fn set_only_thread_handle() -> i32 {
    let handle = duplicate(
        unsafe { GetCurrentThread() },
        Some(THREAD_SET_LIMITED_INFORMATION),
    );
    assert_ne!(
        unsafe { SetThreadPriority(handle.0, THREAD_PRIORITY_ABOVE_NORMAL) },
        0
    );
    let result = unsafe { GetThreadPriority(GetCurrentThread()) };
    assert_ne!(
        unsafe { SetThreadPriority(handle.0, THREAD_PRIORITY_NORMAL) },
        0
    );
    result
}

#[test]
fn a_set_only_handle_can_initialize_a_threads_scheduling_state() {
    let _host = host_state();
    assert_eq!(
        Sim::new().run(set_only_thread_handle),
        snare::real(set_only_thread_handle)
    );
}

fn working_set_handle_matrix() -> Vec<(i32, u32)> {
    let process = unsafe { GetCurrentProcess() };
    let mut min = 0;
    let mut max = 0;
    let mut flags = 0;
    assert_ne!(
        unsafe { GetProcessWorkingSetSizeEx(process, &mut min, &mut max, &mut flags) },
        0
    );
    let thread = unsafe { GetCurrentThread() };
    let event = TestHandle(unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) });
    let mut rows = Vec::new();
    for (source, access) in [
        (process, None),
        (process, Some(PROCESS_QUERY_INFORMATION)),
        (process, Some(PROCESS_QUERY_LIMITED_INFORMATION)),
        (process, Some(PROCESS_SET_QUOTA)),
        (process, Some(0)),
        (thread, None),
        (event.0, None),
    ] {
        let handle = duplicate(source, access);
        let mut out_min = 0;
        let mut out_max = 0;
        let mut out_flags = 0;
        unsafe { SetLastError(1234) };
        let read = unsafe {
            GetProcessWorkingSetSizeEx(handle.0, &mut out_min, &mut out_max, &mut out_flags)
        };
        rows.push((read, unsafe { GetLastError() }));
        unsafe { SetLastError(1234) };
        let set = unsafe { SetProcessWorkingSetSizeEx(handle.0, min, max, flags) };
        rows.push((set, unsafe { GetLastError() }));
    }
    rows
}

#[test]
fn working_set_handles_and_access_match_the_host() {
    let _host = host_state();
    let native = snare::real(working_set_handle_matrix);
    assert_eq!(Sim::new().run(working_set_handle_matrix), native);
}

fn child_thread_scheduling_aliases() -> Vec<i32> {
    use std::os::windows::io::AsRawHandle;
    let (ready, started) = std::sync::mpsc::channel();
    let (send, receive) = std::sync::mpsc::channel();
    let child = std::thread::spawn(move || {
        let thread = unsafe { GetCurrentThread() };
        assert_ne!(
            unsafe { SetThreadPriority(thread, THREAD_PRIORITY_ABOVE_NORMAL) },
            0
        );
        ready.send(()).unwrap();
        receive.recv().unwrap();
        unsafe { GetThreadPriority(thread) }
    });
    started.recv().unwrap();
    let alias = duplicate(child.as_raw_handle(), None);
    let mut result = vec![unsafe { GetThreadPriority(alias.0) }, unsafe {
        GetThreadPriority(GetCurrentThread())
    }];
    assert_ne!(
        unsafe { SetThreadPriority(alias.0, THREAD_PRIORITY_LOWEST) },
        0
    );
    send.send(()).unwrap();
    result.push(child.join().unwrap());
    result.push(unsafe { GetThreadPriority(alias.0) });
    result
}

#[test]
fn another_threads_handle_and_pseudo_handle_share_its_state() {
    let _host = host_state();
    let native = snare::real(child_thread_scheduling_aliases);
    assert_eq!(Sim::new().run(child_thread_scheduling_aliases), native);
    assert_eq!(
        Sim::builder()
            .deterministic()
            .build()
            .run(child_thread_scheduling_aliases),
        native
    );
}

#[test]
fn a_foreign_process_handle_does_not_change_the_simulated_current_process() {
    let _host = host_state();
    use std::os::windows::io::AsRawHandle;
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["__foreign_handle_child__", "--exact"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let process = duplicate(child.as_raw_handle(), None);
    assert!(child.wait().unwrap().success());
    Sim::new().run(|| {
        assert_eq!(
            unsafe { SetPriorityClass(process.0, BELOW_NORMAL_PRIORITY_CLASS) },
            0
        );
        assert_eq!(
            unsafe { GetLastError() },
            windows_sys::Win32::Foundation::ERROR_NOT_SUPPORTED
        );
        assert_eq!(unsafe { GetPriorityClass(process.0) }, 0);
        assert_eq!(
            unsafe { GetLastError() },
            windows_sys::Win32::Foundation::ERROR_NOT_SUPPORTED
        );
        assert_eq!(
            unsafe { GetPriorityClass(GetCurrentProcess()) },
            NORMAL_PRIORITY_CLASS
        );
    });
}

fn duplicated_current_thread_background_mode() -> Vec<(i32, u32)> {
    let handle = duplicate(unsafe { GetCurrentThread() }, None);
    [THREAD_MODE_BACKGROUND_BEGIN, THREAD_MODE_BACKGROUND_END]
        .map(|mode| {
            unsafe { SetLastError(1234) };
            let result = unsafe { SetThreadPriority(handle.0, mode) };
            (result, unsafe { GetLastError() })
        })
        .to_vec()
}

#[test]
fn background_mode_on_a_duplicate_current_thread_matches_the_host() {
    let _host = host_state();
    let native = snare::real(duplicated_current_thread_background_mode);
    assert_eq!(
        Sim::new().run(duplicated_current_thread_background_mode),
        native
    );
}

#[link(name = "winmm")]
unsafe extern "system" {
    fn timeBeginPeriod(period: u32) -> u32;
    fn timeEndPeriod(period: u32) -> u32;
    fn timeGetDevCaps(caps: *mut [u32; 2], size: u32) -> u32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn QueryUnbiasedInterruptTime(time: *mut u64) -> i32;
}

/// `TIMERR_NOCANDO`, `TIMERR_BASE + 1`.
const TIMERR_NOCANDO: u32 = 97;

fn qpc() -> i64 {
    let mut count = 0;
    assert_ne!(unsafe { QueryPerformanceCounter(&mut count) }, 0);
    count
}

fn unbiased() -> u64 {
    let mut time = 0;
    assert_ne!(unsafe { QueryUnbiasedInterruptTime(&mut time) }, 0);
    time
}

fn file_time(read: unsafe extern "system" fn(*mut FILETIME)) -> u64 {
    let mut ft = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    unsafe { read(&mut ft) };
    (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)
}

/// Each clock's invariant and whether it held: a thousand reads of each never go backwards; the
/// coarse system time read first is never past the precise one read after it; and a 50 ms `Sleep`
/// moves `QueryPerformanceCounter` at least 40 ms, at the frequency
/// `QueryPerformanceFrequency` reports
/// ([Microsoft Learn: Acquiring high-resolution time stamps](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps),
/// [GetTickCount64](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64),
/// [QueryUnbiasedInterruptTime](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttime),
/// [GetSystemTimePreciseAsFileTime](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimepreciseasfiletime),
/// [Sleep](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleep)).
fn clock_invariants() -> Vec<(&'static str, bool)> {
    fn monotone<T: PartialOrd>(read: impl Fn() -> T) -> bool {
        let mut last = read();
        (0..1000).all(|_| {
            let now = read();
            let ok = now >= last;
            last = now;
            ok
        })
    }
    let mut frequency = 0;
    unsafe { QueryPerformanceFrequency(&mut frequency) };
    let coarse = file_time(GetSystemTimeAsFileTime);
    let precise = file_time(GetSystemTimePreciseAsFileTime);
    let before = qpc();
    std::thread::sleep(Duration::from_millis(50));
    let slept = (qpc() - before) as f64 / frequency as f64;
    vec![
        ("QueryPerformanceFrequency is positive", frequency > 0),
        ("QueryPerformanceCounter is monotone", monotone(qpc)),
        (
            "GetTickCount64 is monotone",
            monotone(|| unsafe { GetTickCount64() }),
        ),
        ("QueryUnbiasedInterruptTime is monotone", monotone(unbiased)),
        (
            "GetSystemTimePreciseAsFileTime is monotone",
            monotone(|| file_time(GetSystemTimePreciseAsFileTime)),
        ),
        (
            "the coarse system time trails the precise one",
            coarse <= precise,
        ),
        ("a 50 ms Sleep moves QPC 40 ms or more", slept >= 0.040),
    ]
}

#[test]
fn clock_invariants_hold_on_the_host_and_in_the_sim() {
    let _host = host_state();
    let real = snare::real(clock_invariants);
    let sim = Sim::new().run(clock_invariants);
    assert!(real.iter().all(|(_, held)| *held), "host: {real:?}");
    assert_eq!(sim, real);
}

#[test]
fn query_performance_frequency_is_the_hosts() {
    let _host = host_state();
    let read = || {
        let mut frequency = 0;
        unsafe { QueryPerformanceFrequency(&mut frequency) };
        frequency
    };
    assert_eq!(Sim::new().run(read), snare::real(read));
}

/// A matched `timeBeginPeriod(1)`/`timeEndPeriod(1)` succeed with `TIMERR_NOERROR`; 1 ms is the
/// smallest period `timeGetDevCaps` reports on current Windows
/// ([Microsoft Learn: timeBeginPeriod](https://learn.microsoft.com/en-us/windows/win32/api/timeapi/nf-timeapi-timebeginperiod)).
fn period_round_trip() -> (u32, u32) {
    let begin = unsafe { timeBeginPeriod(1) };
    let end = unsafe { timeEndPeriod(1) };
    (begin, end)
}

#[test]
fn time_period_round_trip_matches_the_host() {
    let _host = host_state();
    let real = snare::real(period_round_trip);
    assert_eq!(real, (0, 0));
    assert_eq!(Sim::new().run(period_round_trip), real);
}

/// A period of 0 is out of range: `timeBeginPeriod` and `timeEndPeriod` both return
/// `TIMERR_NOCANDO`.
fn period_out_of_range() -> (u32, u32) {
    let begin = unsafe { timeBeginPeriod(0) };
    let end = unsafe { timeEndPeriod(0) };
    (begin, end)
}

#[test]
fn time_period_out_of_range_matches_the_host() {
    let _host = host_state();
    let real = snare::real(period_out_of_range);
    assert_eq!(real, (TIMERR_NOCANDO, TIMERR_NOCANDO));
    assert_eq!(Sim::new().run(period_out_of_range), real);
}

fn period_boundaries() -> Vec<(u32, u32, u32)> {
    let mut caps = [0; 2];
    assert_eq!(unsafe { timeGetDevCaps(&mut caps, 8) }, 0);
    let [minimum, maximum] = caps;
    let mut result: Vec<_> = [
        0,
        minimum.saturating_sub(1),
        minimum,
        minimum + 1,
        maximum,
        maximum + 1,
        u32::MAX,
    ]
    .into_iter()
    .map(|period| {
        (period, unsafe { timeBeginPeriod(period) }, unsafe {
            timeEndPeriod(period)
        })
    })
    .collect();
    result.push((minimum, unsafe { timeEndPeriod(minimum) }, unsafe {
        timeEndPeriod(minimum)
    }));
    result
}

#[test]
fn timer_period_boundaries_match_the_host() {
    let _host = host_state();
    let real = snare::real(period_boundaries);
    assert_eq!(Sim::new().run(period_boundaries), real);
}

/// Each documented thread priority set on the calling thread and read back, then normal again
/// ([Microsoft Learn: SetThreadPriority](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadpriority)).
fn priority_round_trips() -> Vec<(i32, i32, i32)> {
    let thread = unsafe { GetCurrentThread() };
    let out = [
        THREAD_PRIORITY_LOWEST,
        THREAD_PRIORITY_ABOVE_NORMAL,
        THREAD_PRIORITY_HIGHEST,
        THREAD_PRIORITY_TIME_CRITICAL,
        THREAD_PRIORITY_NORMAL,
    ]
    .into_iter()
    .map(|p| {
        (p, unsafe { SetThreadPriority(thread, p) }, unsafe {
            GetThreadPriority(thread)
        })
    })
    .collect();
    unsafe { SetThreadPriority(thread, THREAD_PRIORITY_NORMAL) };
    out
}

#[test]
fn thread_priority_round_trips_match_the_host() {
    let _host = host_state();
    let real = snare::real(priority_round_trips);
    let sim = Sim::new().run(priority_round_trips);
    assert!(
        real.iter().all(|&(set, ok, got)| ok != 0 && got == set),
        "host: {real:?}"
    );
    assert_eq!(sim, real);
}

/// A priority outside the documented set fails with `ERROR_INVALID_PARAMETER`.
fn invalid_priority() -> (i32, u32) {
    let thread = unsafe { GetCurrentThread() };
    let ok = unsafe { SetThreadPriority(thread, 7) };
    let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    unsafe { SetThreadPriority(thread, THREAD_PRIORITY_NORMAL) };
    (ok, if ok == 0 { error } else { 0 })
}

#[test]
fn invalid_thread_priority_matches_the_host() {
    let _host = host_state();
    let real = snare::real(invalid_priority);
    assert_eq!(real, (0, 87));
    assert_eq!(Sim::new().run(invalid_priority), real);
}

fn background_priorities() -> Vec<(i32, u32, i32)> {
    let thread = unsafe { GetCurrentThread() };
    let initial = unsafe { GetThreadPriority(thread) };
    let result = [
        THREAD_MODE_BACKGROUND_END,
        THREAD_MODE_BACKGROUND_BEGIN,
        THREAD_MODE_BACKGROUND_BEGIN,
        THREAD_MODE_BACKGROUND_END,
        THREAD_MODE_BACKGROUND_END,
    ]
    .into_iter()
    .map(|priority| {
        let ok = unsafe { SetThreadPriority(thread, priority) };
        let error = if ok == 0 {
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        } else {
            0
        };
        (ok, error, unsafe { GetThreadPriority(thread) })
    })
    .collect();
    unsafe { SetThreadPriority(thread, initial) };
    result
}

#[test]
fn background_priority_transitions_match_the_host() {
    let _host = host_state();
    let real = snare::real(background_priorities);
    assert_eq!(Sim::new().run(background_priorities), real);
}

fn priority_boundaries() -> Vec<(i32, i32, u32, i32)> {
    let thread = unsafe { GetCurrentThread() };
    let initial = unsafe { GetThreadPriority(thread) };
    let result = [
        i32::MIN,
        -100,
        -17,
        -16,
        -15,
        -14,
        -7,
        -3,
        -2,
        -1,
        0,
        1,
        2,
        3,
        6,
        7,
        14,
        15,
        16,
        17,
        100,
        12_345,
        i32::MAX,
    ]
    .into_iter()
    .map(|priority| {
        let ok = unsafe { SetThreadPriority(thread, priority) };
        let error = if ok == 0 {
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        } else {
            0
        };
        (priority, ok, error, unsafe { GetThreadPriority(thread) })
    })
    .collect();
    unsafe { SetThreadPriority(thread, initial) };
    result
}

#[test]
fn thread_priority_boundaries_match_the_host() {
    let _host = host_state();
    let real = snare::real(priority_boundaries);
    assert_eq!(Sim::new().run(priority_boundaries), real);
}

fn background_priority_levels() -> Vec<(i32, i32, i32)> {
    let thread = unsafe { GetCurrentThread() };
    let initial = unsafe { GetThreadPriority(thread) };
    let result = [-15, -2, 0, 1, 2, 15]
        .into_iter()
        .map(|priority| {
            assert_ne!(unsafe { SetThreadPriority(thread, priority) }, 0);
            assert_ne!(
                unsafe { SetThreadPriority(thread, THREAD_MODE_BACKGROUND_BEGIN) },
                0
            );
            let during = unsafe { GetThreadPriority(thread) };
            assert_ne!(
                unsafe { SetThreadPriority(thread, THREAD_MODE_BACKGROUND_END) },
                0
            );
            (priority, during, unsafe { GetThreadPriority(thread) })
        })
        .collect();
    unsafe { SetThreadPriority(thread, initial) };
    result
}

#[test]
fn background_priority_levels_match_the_host() {
    let _host = host_state();
    let real = snare::real(background_priority_levels);
    assert_eq!(Sim::new().run(background_priority_levels), real);
}

fn background_priority_classes() -> Vec<(u32, i32, i32)> {
    let process = unsafe { GetCurrentProcess() };
    let thread = unsafe { GetCurrentThread() };
    let initial_class = unsafe { GetPriorityClass(process) };
    let initial_priority = unsafe { GetThreadPriority(thread) };
    let result = [
        IDLE_PRIORITY_CLASS,
        BELOW_NORMAL_PRIORITY_CLASS,
        NORMAL_PRIORITY_CLASS,
        ABOVE_NORMAL_PRIORITY_CLASS,
        HIGH_PRIORITY_CLASS,
    ]
    .into_iter()
    .map(|class| {
        assert_ne!(unsafe { SetPriorityClass(process, class) }, 0);
        assert_ne!(
            unsafe { SetThreadPriority(thread, THREAD_PRIORITY_NORMAL) },
            0
        );
        assert_ne!(
            unsafe { SetThreadPriority(thread, THREAD_MODE_BACKGROUND_BEGIN) },
            0
        );
        let during = unsafe { GetThreadPriority(thread) };
        assert_ne!(
            unsafe { SetThreadPriority(thread, THREAD_MODE_BACKGROUND_END) },
            0
        );
        (class, during, unsafe { GetThreadPriority(thread) })
    })
    .collect();
    unsafe {
        SetPriorityClass(process, initial_class);
        SetThreadPriority(thread, initial_priority);
    }
    result
}

#[test]
fn background_priority_classes_match_the_host() {
    let _host = host_state();
    let real = snare::real(background_priority_classes);
    assert_eq!(Sim::new().run(background_priority_classes), real);
}

fn priority_class_flags() -> Vec<(i32, u32, u32)> {
    use windows_sys::Win32::Foundation::{GetLastError, SetLastError};
    let process = unsafe { GetCurrentProcess() };
    let initial = unsafe { GetPriorityClass(process) };
    let flags = [
        IDLE_PRIORITY_CLASS,
        BELOW_NORMAL_PRIORITY_CLASS,
        NORMAL_PRIORITY_CLASS,
        ABOVE_NORMAL_PRIORITY_CLASS,
        HIGH_PRIORITY_CLASS,
    ];
    let classes = (0..32).flat_map(|mask| {
        let class = flags.iter().enumerate().fold(0, |word, (bit, flag)| {
            word | if mask & (1 << bit) != 0 { *flag } else { 0 }
        });
        [class, class | 0x11]
    });
    let result = classes
        .chain([u32::MAX])
        .map(|class| {
            unsafe { SetLastError(0) };
            let rc = unsafe { SetPriorityClass(process, class) };
            let error = unsafe { GetLastError() };
            (rc, error, unsafe { GetPriorityClass(process) })
        })
        .collect();
    unsafe { SetPriorityClass(process, initial) };
    result
}

#[test]
fn priority_class_flags_match_the_host() {
    let _host = host_state();
    let real = snare::real(priority_class_flags);
    assert_eq!(Sim::new().run(priority_class_flags), real);
}

type PrioritySnapshot = (&'static str, i64, i32, u32, u32, i32);

fn record_priority(
    rows: &mut Vec<PrioritySnapshot>,
    operation: &'static str,
    request: i64,
    call: impl FnOnce() -> i32,
) {
    unsafe { SetLastError(1234) };
    let result = call();
    let error = unsafe { GetLastError() };
    rows.push((
        operation,
        request,
        result,
        error,
        unsafe { GetPriorityClass(GetCurrentProcess()) },
        unsafe { GetThreadPriority(GetCurrentThread()) },
    ));
}

struct RestorePriority {
    class: u32,
    thread: i32,
}

impl RestorePriority {
    fn new() -> Self {
        Self {
            class: unsafe { GetPriorityClass(GetCurrentProcess()) },
            thread: unsafe { GetThreadPriority(GetCurrentThread()) },
        }
    }
}

impl Drop for RestorePriority {
    fn drop(&mut self) {
        unsafe {
            SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_END);
            SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END);
            SetPriorityClass(GetCurrentProcess(), self.class);
            SetThreadPriority(GetCurrentThread(), self.thread);
        }
    }
}

fn current_process_background_matrix() -> Vec<PrioritySnapshot> {
    let _restore = RestorePriority::new();
    let process = unsafe { GetCurrentProcess() };
    let thread = unsafe { GetCurrentThread() };
    let mut rows = Vec::new();
    for class in [
        IDLE_PRIORITY_CLASS,
        BELOW_NORMAL_PRIORITY_CLASS,
        NORMAL_PRIORITY_CLASS,
        ABOVE_NORMAL_PRIORITY_CLASS,
        HIGH_PRIORITY_CLASS,
        REALTIME_PRIORITY_CLASS,
    ] {
        record_priority(&mut rows, "class", class as i64, || unsafe {
            SetPriorityClass(process, class)
        });
        for priority in -16..=16 {
            record_priority(&mut rows, "thread", priority as i64, || unsafe {
                SetThreadPriority(thread, priority)
            });
        }
        for priority in [-15, -2, 0, 2, 15] {
            record_priority(&mut rows, "thread initial", priority as i64, || unsafe {
                SetThreadPriority(thread, priority)
            });
            for mode in [THREAD_MODE_BACKGROUND_BEGIN, THREAD_MODE_BACKGROUND_BEGIN] {
                record_priority(&mut rows, "thread background", mode as i64, || unsafe {
                    SetThreadPriority(thread, mode)
                });
            }
            for priority in [-16, -15, -2, 0, 2, 15, 16] {
                record_priority(
                    &mut rows,
                    "thread in background",
                    priority as i64,
                    || unsafe { SetThreadPriority(thread, priority) },
                );
            }
            for mode in [THREAD_MODE_BACKGROUND_END, THREAD_MODE_BACKGROUND_END] {
                record_priority(&mut rows, "thread background", mode as i64, || unsafe {
                    SetThreadPriority(thread, mode)
                });
            }
        }
        record_priority(&mut rows, "process initial", 1, || unsafe {
            SetThreadPriority(thread, 1)
        });
        for mode in [PROCESS_MODE_BACKGROUND_BEGIN, PROCESS_MODE_BACKGROUND_END] {
            record_priority(
                &mut rows,
                "process direct background",
                mode as i64,
                || unsafe { SetPriorityClass(process, mode) },
            );
        }
        for mode in [
            PROCESS_MODE_BACKGROUND_END,
            PROCESS_MODE_BACKGROUND_BEGIN,
            PROCESS_MODE_BACKGROUND_BEGIN,
        ] {
            record_priority(&mut rows, "process background", mode as i64, || unsafe {
                SetPriorityClass(process, mode)
            });
        }
        let inherited = std::thread::spawn(|| {
            let mut rows = Vec::new();
            record_priority(&mut rows, "inherited thread", 0, || 1);
            for mode in [
                THREAD_MODE_BACKGROUND_END,
                THREAD_MODE_BACKGROUND_BEGIN,
                THREAD_MODE_BACKGROUND_END,
            ] {
                record_priority(&mut rows, "inherited background", mode as i64, || unsafe {
                    SetThreadPriority(GetCurrentThread(), mode)
                });
            }
            rows
        })
        .join()
        .unwrap();
        rows.extend(inherited);
        for mode in [THREAD_MODE_BACKGROUND_BEGIN, THREAD_MODE_BACKGROUND_END] {
            record_priority(
                &mut rows,
                "thread in process background",
                mode as i64,
                || unsafe { SetThreadPriority(thread, mode) },
            );
        }
        record_priority(&mut rows, "thread in process background", 2, || unsafe {
            SetThreadPriority(thread, 2)
        });
        for next_class in [HIGH_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS] {
            record_priority(
                &mut rows,
                "class in process background",
                next_class as i64,
                || unsafe { SetPriorityClass(process, next_class) },
            );
        }
        for mode in [PROCESS_MODE_BACKGROUND_END, PROCESS_MODE_BACKGROUND_END] {
            record_priority(&mut rows, "process background", mode as i64, || unsafe {
                SetPriorityClass(process, mode)
            });
        }
    }
    record_priority(&mut rows, "overlap thread initial", 1, || unsafe {
        SetThreadPriority(thread, 1)
    });
    record_priority(&mut rows, "overlap thread begin", 0, || unsafe {
        SetThreadPriority(thread, THREAD_MODE_BACKGROUND_BEGIN)
    });
    record_priority(&mut rows, "overlap process begin", 0, || unsafe {
        SetPriorityClass(process, PROCESS_MODE_BACKGROUND_BEGIN)
    });
    record_priority(&mut rows, "overlap repeated thread begin", 0, || unsafe {
        SetThreadPriority(thread, THREAD_MODE_BACKGROUND_BEGIN)
    });
    record_priority(&mut rows, "overlap process end", 0, || unsafe {
        SetPriorityClass(process, PROCESS_MODE_BACKGROUND_END)
    });
    record_priority(&mut rows, "overlap thread end", 0, || unsafe {
        SetThreadPriority(thread, THREAD_MODE_BACKGROUND_END)
    });
    for request in [
        PROCESS_MODE_BACKGROUND_BEGIN | NORMAL_PRIORITY_CLASS,
        PROCESS_MODE_BACKGROUND_END | HIGH_PRIORITY_CLASS,
        PROCESS_MODE_BACKGROUND_BEGIN | PROCESS_MODE_BACKGROUND_END,
        PROCESS_MODE_BACKGROUND_BEGIN | 0x11,
    ] {
        record_priority(&mut rows, "background flags", request as i64, || unsafe {
            SetPriorityClass(process, request)
        });
        record_priority(&mut rows, "background flags cleanup", 0, || unsafe {
            SetPriorityClass(process, PROCESS_MODE_BACKGROUND_END)
        });
    }
    record_priority(
        &mut rows,
        "thread class initial",
        NORMAL_PRIORITY_CLASS as i64,
        || unsafe { SetPriorityClass(process, NORMAL_PRIORITY_CLASS) },
    );
    record_priority(&mut rows, "thread class initial", 1, || unsafe {
        SetThreadPriority(thread, 1)
    });
    record_priority(&mut rows, "thread class begin", 0, || unsafe {
        SetThreadPriority(thread, THREAD_MODE_BACKGROUND_BEGIN)
    });
    for class in [HIGH_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS] {
        record_priority(
            &mut rows,
            "class in thread background",
            class as i64,
            || unsafe { SetPriorityClass(process, class) },
        );
    }
    record_priority(&mut rows, "thread class end", 0, || unsafe {
        SetThreadPriority(thread, THREAD_MODE_BACKGROUND_END)
    });
    let alias = duplicate(process, None);
    for mode in [PROCESS_MODE_BACKGROUND_BEGIN, PROCESS_MODE_BACKGROUND_END] {
        record_priority(
            &mut rows,
            "aliased process background",
            mode as i64,
            || unsafe { SetPriorityClass(alias.0, mode) },
        );
    }
    rows
}

#[test]
fn child_current_process_background_matrix() {
    let _host = host_state();
    if std::env::var_os("SNARE_PRIORITY_MATRIX_CHILD").is_none() {
        return;
    }
    let real = snare::real(current_process_background_matrix);
    let realtime = real
        .iter()
        .any(|row| row.0 == "class" && row.4 == REALTIME_PRIORITY_CLASS);
    for deterministic in [false, true] {
        let sim = if deterministic {
            Sim::builder().deterministic().build()
        } else {
            Sim::new()
        };
        sim.set_privileges(|privileges| privileges.sys_nice = realtime);
        let modeled = sim.run(current_process_background_matrix);
        assert_eq!(real.len(), modeled.len());
        for (index, (model, native)) in modeled.iter().zip(&real).enumerate() {
            assert_eq!(model, native, "case {index}, deterministic={deterministic}");
        }
    }
}

#[test]
fn current_process_background_and_priority_classes_match_the_host() {
    let _host = host_state();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "child_current_process_background_matrix",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SNARE_PRIORITY_MATRIX_CHILD", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > Duration::from_secs(10) {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "priority child timed out: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let child = child.wait_with_output().unwrap();
    assert!(
        child.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
}
