//! A simulated Windows host behind [`snare_interpose::Host`], the peer of the unix
//! `SimHost`. It answers the Win32 scheduling calls a real-time program makes —
//! `SetThreadPriority`/`GetThreadPriority`, `SetThreadAffinityMask`, `SetPriorityClass`/
//! `GetPriorityClass`, `timeBeginPeriod`/`timeEndPeriod` — against in-process state, deterministically,
//! without ever touching the real scheduler or timer resolution.
//!
//! It also models the process's working-set bounds (`SetProcessWorkingSetSizeEx` /
//! `GetProcessWorkingSetSizeEx`) and, through [`crate::win_adapter`], the network adapters'
//! device nodes and registry keys that SetupAPI, the registry and the Configuration Manager reach.
//!
//! `WinHost` is the Host plane only: sockets are `win_net`'s, and there is no file system. The
//! [`Sim`] around it serves time from the shared virtual [`Clock`] unless built with `wall_clock`.
//!
//! The host models the current process. All state sits behind one mutex, taken briefly per call and never held across a wait
//! or a call into the sim. This file also holds the Windows [`Sim`] and [`SimBuilder`], which
//! mirror the unix ones in `lib.rs` method for method, minus the file system and `SimHost`.

use std::collections::HashMap;
use std::ffi::c_int;
use std::mem::size_of_val;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use snare_interpose::NetResult as HostResult;
use snare_interpose::{Domain, Host, Layer};

use crate::clock::{Clock, ClockLayer};
use crate::scope::SimShared;
use windows_sys::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ACCESS_DENIED,
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER,
    ERROR_NO_SYSTEM_RESOURCES, ERROR_NOT_SUPPORTED, ERROR_PRIVILEGE_NOT_HELD,
    ERROR_PROCESS_MODE_ALREADY_BACKGROUND, ERROR_PROCESS_MODE_NOT_BACKGROUND,
    ERROR_THREAD_MODE_ALREADY_BACKGROUND, ERROR_THREAD_MODE_NOT_BACKGROUND, GetLastError, HANDLE,
    SetLastError, UNICODE_STRING,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    QUOTA_LIMITS_HARDWS_MAX_DISABLE, QUOTA_LIMITS_HARDWS_MAX_ENABLE,
    QUOTA_LIMITS_HARDWS_MIN_DISABLE, QUOTA_LIMITS_HARDWS_MIN_ENABLE,
};
use windows_sys::Win32::System::Threading::{
    ABOVE_NORMAL_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS, GetCurrentProcess,
    GetCurrentProcessId, GetCurrentThread, GetProcessIdOfThread, HIGH_PRIORITY_CLASS,
    IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS, PROCESS_MODE_BACKGROUND_BEGIN,
    PROCESS_MODE_BACKGROUND_END, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SET_INFORMATION, PROCESS_SET_QUOTA, REALTIME_PRIORITY_CLASS,
    THREAD_MODE_BACKGROUND_BEGIN, THREAD_MODE_BACKGROUND_END, THREAD_PRIORITY_NORMAL,
    THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SET_INFORMATION,
    THREAD_SET_LIMITED_INFORMATION,
};

/// Per-thread scheduling state. `priority` is the `SetThreadPriority` view; `affinity` the explicit
/// mask from `SetThreadAffinityMask` (`None` means the thread follows the process affinity mask).
/// A thread starts at `THREAD_PRIORITY_NORMAL`, as every Windows thread is created
/// ([Microsoft Learn: Scheduling Priorities, Priority Level](https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities)).
#[derive(Clone)]
struct ThreadState {
    priority: i32,
    affinity: Option<u64>,
    background_priority: Option<i32>,
}

impl Default for ThreadState {
    fn default() -> Self {
        ThreadState {
            priority: THREAD_PRIORITY_NORMAL,
            affinity: None,
            background_priority: None,
        }
    }
}

/// Keeps object identity intact when a caller closes or reuses its handle.
struct NativeHandle(usize);

impl Drop for NativeHandle {
    fn drop(&mut self) {
        snare_interpose::real(|| unsafe { CloseHandle(self.0 as HANDLE) });
    }
}

struct PreservedLastError(u32);

impl PreservedLastError {
    fn new() -> Self {
        Self(unsafe { GetLastError() })
    }
}

impl Drop for PreservedLastError {
    fn drop(&mut self) {
        unsafe { SetLastError(self.0) };
    }
}

type QueryObject =
    unsafe extern "system" fn(HANDLE, i32, *mut std::ffi::c_void, u32, *mut u32) -> i32;
type StatusError = unsafe extern "system" fn(i32) -> u32;

#[repr(C)]
#[derive(Default)]
struct HandleBasic {
    _attributes: u32,
    granted_access: u32,
    _handle_count: u32,
    _pointer_count: u32,
    _reserved: [u32; 10],
}

fn handle_access(handle: u64, kind: &str) -> Result<u32, u32> {
    let _error = PreservedLastError::new();
    static APIS: std::sync::OnceLock<Option<(QueryObject, StatusError)>> =
        std::sync::OnceLock::new();
    let (query, error) = APIS
        .get_or_init(|| unsafe {
            let library = GetModuleHandleW(windows_sys::core::w!("ntdll.dll"));
            let query = GetProcAddress(library, c"NtQueryObject".as_ptr().cast())?;
            let error = GetProcAddress(library, c"RtlNtStatusToDosError".as_ptr().cast())?;
            Some((
                std::mem::transmute::<unsafe extern "system" fn() -> isize, QueryObject>(query),
                std::mem::transmute::<unsafe extern "system" fn() -> isize, StatusError>(error),
            ))
        })
        .ok_or(ERROR_CALL_NOT_IMPLEMENTED)?;
    let mut basic = HandleBasic::default();
    let status = unsafe {
        query(
            handle as HANDLE,
            0,
            std::ptr::from_mut(&mut basic).cast(),
            size_of_val(&basic) as u32,
            std::ptr::null_mut(),
        )
    };
    if status < 0 {
        return Err(unsafe { error(status) });
    }
    let mut buffer = [0usize; 128];
    let status = unsafe {
        query(
            handle as HANDLE,
            2,
            buffer.as_mut_ptr().cast(),
            size_of_val(&buffer) as u32,
            std::ptr::null_mut(),
        )
    };
    if status < 0 {
        return Err(unsafe { error(status) });
    }
    let name = unsafe { &*buffer.as_ptr().cast::<UNICODE_STRING>() };
    let name = unsafe { std::slice::from_raw_parts(name.Buffer, usize::from(name.Length) / 2) };
    if !name.iter().copied().eq(kind.encode_utf16()) {
        return Err(ERROR_INVALID_HANDLE);
    }
    Ok(basic.granted_access)
}

fn require_access(handle: u64, kind: &str, requirements: &[u32]) -> Result<(), u32> {
    let access = handle_access(handle, kind)?;
    if requirements.iter().any(|mask| access & mask == 0) {
        return Err(ERROR_ACCESS_DENIED);
    }
    Ok(())
}

fn current_process(handle: u64, access: u32) -> Result<(), u32> {
    let _error = PreservedLastError::new();
    require_access(handle, "Process", &[access])?;
    if unsafe { CompareObjectHandles(handle as HANDLE, GetCurrentProcess()) } == 0 {
        return Err(ERROR_NOT_SUPPORTED);
    }
    Ok(())
}

/// The process's working-set bounds, as `GetProcessWorkingSetSizeEx` reports them
/// ([Microsoft Learn: GetProcessWorkingSetSizeEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-getprocessworkingsetsizeex)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkingSet {
    /// The minimum working set, in bytes.
    pub min: usize,
    /// The maximum working set, in bytes.
    pub max: usize,
    /// The `QUOTA_LIMITS_HARDWS_*` flags: one of `MIN_ENABLE`/`MIN_DISABLE` and one of
    /// `MAX_ENABLE`/`MAX_DISABLE`.
    pub flags: u32,
}

impl WorkingSet {
    /// A new process's bounds: 204 800 and 1 413 120 bytes (50 and 345 pages), both limits soft
    /// (`QUOTA_LIMITS_HARDWS_MIN_DISABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE`). Measured with
    /// `GetProcessWorkingSetSizeEx` in a fresh process on the Windows 11 test VM.
    const INITIAL: WorkingSet = WorkingSet {
        min: 204_800,
        max: 1_413_120,
        flags: QUOTA_LIMITS_HARDWS_MIN_DISABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE,
    };
}

/// The page size the working-set bounds are rounded down to: 4 KiB, the page size of Windows on
/// x64 and ARM64. Measured: `SetProcessWorkingSetSizeEx` with 204 801 and 1 413 121 bytes leaves
/// 204 800 and 1 413 120 on the test VM.
const PAGE: usize = 4096;

/// The smallest minimum working set, in pages. Measured on the test VM: a minimum of 77 824 bytes
/// (19 pages) succeeds and reads back as 81 920 (20 pages).
const MIN_WORKING_SET_PAGES: usize = 20;

/// The physical memory the simulated machine has, 16 GiB: a snare choice of a typical
/// workstation. A minimum working set above seven eighths of it fails with
/// `ERROR_NO_SYSTEM_RESOURCES`; the real bound is the memory manager's and undocumented, and seven
/// eighths fits the test VM (8 583 315 456 bytes of RAM: a 6 GiB minimum succeeded, 7 GiB failed
/// with `ERROR_NO_SYSTEM_RESOURCES`).
const PHYSICAL_MEMORY: usize = 16 << 30;

/// Everything [`WinHost`] models, behind its one mutex.
struct HostState {
    /// One bit per simulated logical CPU, low bits first; fixed at build.
    process_affinity: u64,
    /// The `*_PRIORITY_CLASS` value `GetPriorityClass` reports; starts `NORMAL_PRIORITY_CLASS`,
    /// the Windows default ([Microsoft Learn: Scheduling Priorities, Priority Class](https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities)).
    priority_class: u32,
    process_background: bool,
    threads: Vec<(NativeHandle, ThreadState)>,
    /// Outstanding timer-resolution requests, counted separately for each period.
    time_periods: HashMap<u32, u64>,
    /// The working-set bounds `SetProcessWorkingSetSizeEx` last set.
    working_set: WorkingSet,
}

impl HostState {
    /// Resolves a Win32 thread handle to the key its state lives under, ensuring an entry exists.
    fn resolve(&mut self, handle: u64) -> Result<usize, u32> {
        let _error = PreservedLastError::new();
        if let Some(key) = self.threads.iter().position(|(known, _)| unsafe {
            CompareObjectHandles(handle as HANDLE, known.0 as HANDLE) != 0
        }) {
            return Ok(key);
        }
        let process = unsafe { GetCurrentProcess() };
        let mut pid = unsafe { GetProcessIdOfThread(handle as HANDLE) };
        if pid == 0 {
            let mut query = std::ptr::null_mut();
            if unsafe {
                DuplicateHandle(
                    process,
                    handle as HANDLE,
                    process,
                    &mut query,
                    THREAD_QUERY_LIMITED_INFORMATION,
                    0,
                    0,
                )
            } == 0
            {
                return Err(ERROR_NOT_SUPPORTED);
            }
            let query = NativeHandle(query as usize);
            pid = unsafe { GetProcessIdOfThread(query.0 as HANDLE) };
        }
        if pid != unsafe { GetCurrentProcessId() } {
            return Err(ERROR_NOT_SUPPORTED);
        }
        let mut owned = std::ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                process,
                handle as HANDLE,
                process,
                &mut owned,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(unsafe { GetLastError() });
        }
        self.threads
            .push((NativeHandle(owned as usize), ThreadState::default()));
        Ok(self.threads.len() - 1)
    }
}

/// A simulated Windows host serving the Win32 scheduling plane from in-memory state. Attach it to a
/// [`Sim`] with [`SimBuilder`]; it never touches the real scheduler.
pub struct WinHost {
    state: Mutex<HostState>,
    /// The sim it serves, for its privileges; set once in `build`. Weak so the host never keeps
    /// the sim's state alive; once the sim is gone, a realtime request is granted.
    shared: std::sync::OnceLock<std::sync::Weak<SimShared>>,
    /// The network adapters' device nodes and registry keys.
    adapters: crate::win_adapter::Adapters,
}

impl WinHost {
    /// A host with `cpus` logical CPUs in its process affinity mask, clamped to 1..=64: an
    /// affinity mask is one `DWORD_PTR`
    /// ([Microsoft Learn: SetThreadAffinityMask, Syntax](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadaffinitymask))
    /// and covers one processor group, "a static set of up to 64 logical processors"
    /// ([Microsoft Learn: Processor Groups](https://learn.microsoft.com/en-us/windows/win32/procthread/processor-groups)).
    /// 64 is special-cased because `1 << 64` overflows.
    fn new(cpus: usize) -> Self {
        let cpus = cpus.clamp(1, 64);
        let process_affinity = if cpus == 64 {
            u64::MAX
        } else {
            (1u64 << cpus) - 1
        };
        WinHost {
            state: Mutex::new(HostState {
                process_affinity,
                priority_class: NORMAL_PRIORITY_CLASS,
                process_background: false,
                threads: Vec::new(),
                time_periods: HashMap::new(),
                working_set: WorkingSet::INITIAL,
            }),
            shared: std::sync::OnceLock::new(),
            adapters: crate::win_adapter::Adapters::default(),
        }
    }
}

impl Host for WinHost {
    /// Validates the thread priority against its process class and tracks background mode.
    fn set_thread_priority(&self, thread: u64, priority: c_int) -> Option<HostResult> {
        if let Err(error) = require_access(
            thread,
            "Thread",
            &[THREAD_SET_INFORMATION | THREAD_SET_LIMITED_INFORMATION],
        ) {
            return Some(HostResult::Err(error as c_int));
        }
        let mut state = self.state.lock().unwrap();
        let background = matches!(
            priority,
            THREAD_MODE_BACKGROUND_BEGIN | THREAD_MODE_BACKGROUND_END
        );
        if background {
            let _error = PreservedLastError::new();
            if unsafe { CompareObjectHandles(thread as HANDLE, GetCurrentThread()) } == 0 {
                return Some(HostResult::Err(ERROR_INVALID_PARAMETER as c_int));
            }
        }
        if !background
            && !matches!(priority, -16 | -15 | -2..=2 | 15 | 16)
            && !(state.priority_class == REALTIME_PRIORITY_CLASS && (-7..=6).contains(&priority))
        {
            return Some(HostResult::Err(ERROR_INVALID_PARAMETER as c_int));
        }
        let key = match state.resolve(thread) {
            Ok(key) => key,
            Err(error) => return Some(HostResult::Err(error as c_int)),
        };
        let background_priority = match state.priority_class {
            IDLE_PRIORITY_CLASS => 0,
            BELOW_NORMAL_PRIORITY_CLASS => -2,
            ABOVE_NORMAL_PRIORITY_CLASS => -6,
            HIGH_PRIORITY_CLASS => -9,
            REALTIME_PRIORITY_CLASS => -20,
            _ => -4,
        };
        let process_background = state.process_background;
        let thread = &mut state.threads[key].1;
        match priority {
            THREAD_MODE_BACKGROUND_BEGIN => {
                if thread.background_priority.is_some() {
                    return Some(HostResult::Err(
                        ERROR_THREAD_MODE_ALREADY_BACKGROUND as c_int,
                    ));
                }
                if process_background {
                    return Some(HostResult::Err(
                        ERROR_PROCESS_MODE_ALREADY_BACKGROUND as c_int,
                    ));
                }
                thread.background_priority = Some(thread.priority);
                thread.priority = background_priority;
            }
            THREAD_MODE_BACKGROUND_END => {
                let Some(priority) = thread.background_priority.take() else {
                    return Some(HostResult::Err(ERROR_THREAD_MODE_NOT_BACKGROUND as c_int));
                };
                thread.priority = priority;
            }
            _ => thread.priority = priority.clamp(-15, 15),
        }
        Some(HostResult::Ok(1))
    }

    /// `GetThreadPriority`: the stored priority, `THREAD_PRIORITY_NORMAL` for a thread never set.
    fn get_thread_priority(&self, thread: u64) -> Option<HostResult> {
        if let Err(error) = require_access(
            thread,
            "Thread",
            &[THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION],
        ) {
            return Some(HostResult::Err(error as c_int));
        }
        let mut state = self.state.lock().unwrap();
        let key = match state.resolve(thread) {
            Ok(key) => key,
            Err(error) => return Some(HostResult::Err(error as c_int)),
        };
        Some(HostResult::Ok(state.threads[key].1.priority as i64))
    }

    fn set_thread_affinity_mask(&self, thread: u64, mask: u64) -> Option<HostResult> {
        if let Err(error) = require_access(
            thread,
            "Thread",
            &[THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION],
        ) {
            return Some(HostResult::Err(error as c_int));
        }
        let mut state = self.state.lock().unwrap();
        let process_affinity = state.process_affinity;
        // A mask selecting a CPU outside the process affinity mask fails with 0, which the hook
        // returns verbatim, preserving all 64 bits: "A thread affinity mask must be a subset of the
        // process affinity mask"; on success the return is "the thread's previous affinity mask"
        // ([Microsoft Learn: SetThreadAffinityMask](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadaffinitymask)).
        if mask == 0 || mask & !process_affinity != 0 {
            return Some(HostResult::Err(ERROR_INVALID_PARAMETER as c_int));
        }
        if let Err(error) = require_access(
            thread,
            "Thread",
            &[THREAD_SET_INFORMATION | THREAD_SET_LIMITED_INFORMATION],
        ) {
            return Some(HostResult::Err(error as c_int));
        }
        let key = match state.resolve(thread) {
            Ok(key) => key,
            Err(error) => return Some(HostResult::Err(error as c_int)),
        };
        let entry = &mut state.threads[key].1;
        let previous = entry.affinity.unwrap_or(process_affinity);
        entry.affinity = Some(mask);
        Some(HostResult::Ok(previous as i64))
    }

    /// `SetPriorityClass` on the one simulated process. Without the
    /// sim's `sys_nice` privilege (the stand-in for `SeIncreaseBasePriorityPrivilege`) a realtime
    /// request returns `TRUE` but records `HIGH_PRIORITY_CLASS`; with no sim attached, it is
    /// granted.
    fn set_priority_class(&self, process: u64, class: u32) -> Option<HostResult> {
        if matches!(
            class,
            PROCESS_MODE_BACKGROUND_BEGIN | PROCESS_MODE_BACKGROUND_END
        ) {
            if let Err(error) = current_process(process, PROCESS_SET_INFORMATION) {
                return Some(HostResult::Err(error as c_int));
            }
            let mut state = self.state.lock().unwrap();
            if class == PROCESS_MODE_BACKGROUND_BEGIN {
                if state.process_background {
                    return Some(HostResult::Err(
                        ERROR_PROCESS_MODE_ALREADY_BACKGROUND as c_int,
                    ));
                }
                state.process_background = true;
                state.priority_class = NORMAL_PRIORITY_CLASS;
            } else {
                if !state.process_background {
                    return Some(HostResult::Err(ERROR_PROCESS_MODE_NOT_BACKGROUND as c_int));
                }
                state.process_background = false;
            }
            return Some(HostResult::Ok(1));
        }
        let Some(class) = [
            IDLE_PRIORITY_CLASS,
            BELOW_NORMAL_PRIORITY_CLASS,
            NORMAL_PRIORITY_CLASS,
            ABOVE_NORMAL_PRIORITY_CLASS,
            HIGH_PRIORITY_CLASS,
            REALTIME_PRIORITY_CLASS,
        ]
        .into_iter()
        .find(|flag| class & flag != 0) else {
            return Some(HostResult::Err(ERROR_INVALID_PARAMETER as c_int));
        };
        if let Err(error) = current_process(process, PROCESS_SET_INFORMATION) {
            return Some(HostResult::Err(error as c_int));
        }
        // Without SeIncreaseBasePriorityPrivilege "the highest the priority can be set to is High
        // Priority" ([Microsoft Learn: SetPriority method of the Win32_Process class](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/setpriority-method-in-class-win32-process)).
        let sys_nice = self
            .shared
            .get()
            .and_then(std::sync::Weak::upgrade)
            .is_none_or(|shared| shared.sys.privileges().sys_nice);
        let class = if class == REALTIME_PRIORITY_CLASS && !sys_nice {
            HIGH_PRIORITY_CLASS
        } else {
            class
        };
        self.state.lock().unwrap().priority_class = class;
        Some(HostResult::Ok(1))
    }

    /// `SetProcessWorkingSetSizeEx` on the one simulated process, never the real one
    /// ([Microsoft Learn: SetProcessWorkingSetSizeEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessworkingsetsizeex)).
    /// Both bounds `(SIZE_T)-1` trims the working set and changes nothing. Otherwise, in order:
    /// a flag word with both `ENABLE` and `DISABLE` of one limit is `ERROR_INVALID_PARAMETER`;
    /// the bounds are rounded down to [`PAGE`] and the minimum raised to
    /// [`MIN_WORKING_SET_PAGES`]; a minimum above the maximum is `ERROR_INVALID_PARAMETER`; a
    /// minimum beyond the machine ([`PHYSICAL_MEMORY`]) is `ERROR_NO_SYSTEM_RESOURCES` (all
    /// measured on the test VM). Raising either bound needs `SE_INC_WORKING_SET_NAME`, whose
    /// stand-in is the sim's `ipc_lock` privilege, as the page states; without it the call fails
    /// with `ERROR_PRIVILEGE_NOT_HELD`, the code for a missing privilege
    /// ([Microsoft Learn: System Error Codes (1300-1699)](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1300-1699-)),
    /// not measured. A flag word of 0 keeps both limits' hard/soft state (measured).
    fn set_working_set(
        &self,
        process: u64,
        min: usize,
        max: usize,
        flags: u32,
    ) -> Option<HostResult> {
        if let Err(error) = current_process(process, PROCESS_SET_QUOTA) {
            return Some(HostResult::Err(error as c_int));
        }
        if min == usize::MAX && max == usize::MAX {
            return Some(HostResult::Ok(1));
        }
        let fail = |e: u32| Some(HostResult::Err(e as c_int));
        let both_min = QUOTA_LIMITS_HARDWS_MIN_ENABLE | QUOTA_LIMITS_HARDWS_MIN_DISABLE;
        let both_max = QUOTA_LIMITS_HARDWS_MAX_ENABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE;
        if flags & both_min == both_min || flags & both_max == both_max {
            return fail(ERROR_INVALID_PARAMETER);
        }
        let min = (min / PAGE * PAGE).max(MIN_WORKING_SET_PAGES * PAGE);
        let max = max / PAGE * PAGE;
        if min > max {
            return fail(ERROR_INVALID_PARAMETER);
        }
        if min > PHYSICAL_MEMORY / 8 * 7 {
            return fail(ERROR_NO_SYSTEM_RESOURCES);
        }
        let ipc_lock = self
            .shared
            .get()
            .and_then(std::sync::Weak::upgrade)
            .is_none_or(|shared| shared.sys.privileges().ipc_lock);
        let mut state = self.state.lock().unwrap();
        let current = state.working_set;
        if (min > current.min || max > current.max) && !ipc_lock {
            return fail(ERROR_PRIVILEGE_NOT_HELD);
        }
        let mut kept = current.flags;
        if flags & both_min != 0 {
            kept = (kept & !both_min) | (flags & both_min);
        }
        if flags & both_max != 0 {
            kept = (kept & !both_max) | (flags & both_max);
        }
        state.working_set = WorkingSet {
            min,
            max,
            flags: kept,
        };
        Some(HostResult::Ok(1))
    }

    /// `GetProcessWorkingSetSizeEx`: the bounds last set, [`WorkingSet::INITIAL`] at first.
    unsafe fn get_working_set(
        &self,
        process: u64,
        min: *mut usize,
        max: *mut usize,
        flags: *mut u32,
    ) -> Option<HostResult> {
        if let Err(error) = current_process(
            process,
            PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
        ) {
            return Some(HostResult::Err(error as c_int));
        }
        let ws = self.state.lock().unwrap().working_set;
        // SAFETY: the caller's out-pointers, each written only when non-null.
        unsafe {
            if !min.is_null() {
                min.write_unaligned(ws.min);
            }
            if !max.is_null() {
                max.write_unaligned(ws.max);
            }
            if !flags.is_null() {
                flags.write_unaligned(ws.flags);
            }
        }
        Some(HostResult::Ok(1))
    }

    /// The adapters' SetupAPI, Configuration Manager and registry calls; see
    /// [`crate::win_adapter`]. Declined once the sim is gone.
    unsafe fn device(&self, call: snare_interpose::DevCall<'_>) -> Option<HostResult> {
        let shared = self.shared.get()?.upgrade()?;
        // SAFETY: the caller's pointers, passed through.
        unsafe { self.adapters.call(&shared, call) }
    }

    /// `GetPriorityClass`: the class last set, `NORMAL_PRIORITY_CLASS` at first.
    fn get_priority_class(&self, process: u64) -> Option<HostResult> {
        if let Err(error) = current_process(
            process,
            PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
        ) {
            return Some(HostResult::Err(error as c_int));
        }
        Some(HostResult::Ok(
            self.state.lock().unwrap().priority_class as i64,
        ))
    }

    /// Timer-resolution requests are paired by period. They do not change the virtual clock's
    /// resolution. Winmm accepts positive periods above `timeGetDevCaps`' reported maximum.
    fn time_period(&self, begin: bool, period: u32) -> Option<HostResult> {
        const TIMERR_NOCANDO: i64 = 97;
        if period == 0 {
            return Some(HostResult::Ok(TIMERR_NOCANDO));
        }
        let mut state = self.state.lock().unwrap();
        if begin {
            *state.time_periods.entry(period).or_default() += 1;
        } else {
            let Some(count) = state.time_periods.get_mut(&period) else {
                return Some(HostResult::Ok(TIMERR_NOCANDO));
            };
            *count -= 1;
            if *count == 0 {
                state.time_periods.remove(&period);
            }
        }
        Some(HostResult::Ok(0))
    }
}

/// A running Windows simulation: a [`Domain`] whose managed threads' Win32 scheduling calls are
/// serviced by a [`WinHost`] and whose clock is virtual. One per test.
pub struct Sim {
    /// The interposer domain the run's threads join; dropping it uninstalls the sim's backends.
    domain: Domain,
    /// Everything the sim owns: clock, sockets, topology, DNS, events, capture.
    shared: Arc<SimShared>,
    /// The scheduling backend; held for the sim's lifetime.
    _host: Arc<WinHost>,
    /// The Winsock backend; its registries are entered for the duration of each [`Sim::run`].
    _net: Arc<crate::win_net::WinNet>,
    /// This sim's place among the console-control-event forwarders; dropping it unregisters.
    _forward: Option<crate::signals::forward::Registration>,
}

impl std::fmt::Debug for Sim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sim")
            .field("id", &self.domain.id())
            .finish_non_exhaustive()
    }
}

/// Writes out the frames still due and closes the capture file: threads that outlive the sim
/// may still hold its registries.
impl Drop for Sim {
    fn drop(&mut self) {
        if let Some(capture) = self.shared.capture() {
            capture.finish();
        }
    }
}

impl Default for Sim {
    fn default() -> Self {
        Self::new()
    }
}

impl Sim {
    /// Starts a fresh simulation with a default 8-CPU host.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Composes a simulation.
    pub fn builder() -> SimBuilder {
        SimBuilder::default()
    }

    /// Runs `f` with the calling thread — and every thread it spawns — inside the simulation.
    pub fn run<R>(&self, f: impl FnOnce() -> R) -> R {
        // Scope this sim's address registries to the run so testers built here reach exactly
        // this sim, never another test's.
        let _registries = crate::win_net::enter(self._net.registries());
        self.domain.run(f)
    }

    /// Holds virtual time; see the unix `Sim::pause_time`.
    #[track_caller]
    pub fn pause_time(&self) {
        self.time().pause();
    }

    /// Restarts a paused clock in the mode and at the rate it had before the pause.
    #[track_caller]
    pub fn resume_time(&self) {
        self.time().resume();
    }

    /// Moves virtual time forward by `by`, whether or not it is paused.
    #[track_caller]
    pub fn advance_time(&self, by: Duration) {
        self.time().advance(by);
    }

    /// Scales the clock to real time, pauses it or returns it to virtual time; see the unix
    /// `Sim::set_time_rate`.
    #[track_caller]
    pub fn set_time_rate(&self, rate: f64) {
        self.time().set_rate(rate);
    }

    /// 0.0 while paused, the rate while scaled to real time, `f64::INFINITY` on virtual time.
    #[track_caller]
    pub fn time_rate(&self) -> f64 {
        self.time().rate()
    }

    /// Sets sim time forward to `value`; see the unix `Sim::set_time_value`.
    #[track_caller]
    pub fn set_time_value(&self, value: Duration) {
        self.time().set_value(value);
    }

    /// Sim time, without ticking the clock; see the unix `Sim::time_value`.
    #[track_caller]
    pub fn time_value(&self) -> Duration {
        self.time().value()
    }

    /// A cloneable, `Send`-able handle to this sim's clock, usable from any thread. Panics for a
    /// plain wall-clock sim; use `time_rate(1.0)` for a controllable clock tracking real time.
    #[track_caller]
    pub fn time(&self) -> crate::TimeHandle {
        self.shared.time()
    }

    /// The pcapng file this sim captures to, if it captures; see [`SimBuilder::pcapng`].
    pub fn pcapng_path(&self) -> Option<&std::path::Path> {
        self.shared.capture().map(|c| c.path())
    }

    /// Everything this sim has recorded so far; see the unix `Sim::recorded_events`.
    pub fn recorded_events(&self) -> Vec<crate::RecordedEntry> {
        self.shared.events.snapshot()
    }

    /// Empties this sim's log; see the unix `Sim::clear_recorded_events`.
    pub fn clear_recorded_events(&self) {
        self.shared.events.clear();
    }

    /// Socket `id` of this sim, open or closed; see [`crate::socket_entry`].
    pub fn socket_entry(&self, id: crate::SocketId) -> Option<crate::SocketEntry> {
        self.shared.socket_entry(id)
    }

    /// This sim's open sockets, oldest first; see [`crate::socket_table`].
    pub fn socket_table(&self) -> Vec<crate::SocketEntry> {
        self.shared.socket_table()
    }

    /// This sim's closed sockets, in the order they closed; see [`crate::closed_sockets`].
    pub fn closed_sockets(&self) -> Vec<crate::SocketEntry> {
        self.shared.closed_sockets()
    }

    /// See [`crate::inject_socket_drops`].
    pub fn inject_socket_drops(&self, id: crate::SocketId, n: u32) -> std::io::Result<()> {
        self.shared.inject_socket_drops(id, n)
    }

    /// See [`crate::set_socket_device`].
    pub fn set_socket_device(&self, id: crate::SocketId, nic: Option<&str>) -> std::io::Result<()> {
        self.shared.set_socket_device(id, nic)
    }

    /// This sim's protocol counters; see [`crate::proto_counters`].
    pub fn proto_counters(&self) -> crate::ProtoCounters {
        self.shared.proto_counters()
    }

    /// The working-set bounds the code under test last set with `SetProcessWorkingSetSizeEx`.
    pub fn working_set(&self) -> WorkingSet {
        self._host.state.lock().unwrap().working_set
    }

    /// Describes the adapter of interface `nic` from now on (see [`SimBuilder::adapter`]),
    /// discarding what the code under test wrote to its registry keys.
    pub fn set_adapter(&self, nic: &str, adapter: crate::Adapter) {
        self._host.adapters.configure(&self.shared, nic, adapter);
    }

    /// The registry value `name` under `path` (`""` for the key itself, `Ndi\Params\*RSS`, ...)
    /// of `nic`'s adapter `key`, as the code under test would read it now; `None` if the
    /// interface, key or value does not exist. Names match case-insensitively.
    pub fn adapter_value(
        &self,
        nic: &str,
        key: crate::AdapterKey,
        path: &str,
        name: &str,
    ) -> Option<crate::RegValue> {
        self._host
            .adapters
            .value(&self.shared, nic, key, path, name)
    }

    /// The current value of advanced property `keyword` of `nic`'s adapter, as the driver key
    /// holds it; `None` if it has no such property.
    pub fn adapter_property(&self, nic: &str, keyword: &str) -> Option<String> {
        match self.adapter_value(nic, crate::AdapterKey::Driver, "", keyword)? {
            crate::RegValue::Sz(value) => Some(value),
            _ => None,
        }
    }

    /// How many times the code under test has restarted `nic`'s adapter (`CM_Enable_DevNode`
    /// after `CM_Disable_DevNode`).
    pub fn adapter_restarts(&self, nic: &str) -> u32 {
        self._host.adapters.restarts(nic)
    }

    /// What the code under test may do in this sim; see [`crate::set_privileges`].
    pub fn privileges(&self) -> crate::Privileges {
        self.shared.sys.privileges()
    }

    /// Changes this sim's privileges from then on, from any thread.
    pub fn set_privileges(&self, change: impl FnOnce(&mut crate::Privileges)) {
        self.shared.sys.set_privileges(change);
    }

    /// This sim's socket limits; see [`crate::set_sys_limits`].
    pub fn sys_limits(&self) -> crate::SysLimits {
        self.shared.sys.limits()
    }

    /// Changes this sim's socket limits for sockets created from then on, from any thread.
    pub fn set_sys_limits(&self, change: impl FnOnce(&mut crate::SysLimits)) {
        self.shared.sys.set_limits(change);
    }

    /// Adds an interface to this sim; see [`add_nic`](crate::add_nic).
    pub fn add_nic(&self, spec: crate::NicSpec) -> std::io::Result<u32> {
        self.shared.add_nic(spec)
    }

    /// See [`remove_nic`](crate::remove_nic).
    pub fn remove_nic(&self, name: &str) -> std::io::Result<()> {
        self.shared.remove_nic(name)
    }

    /// See [`set_nic`](crate::set_nic).
    pub fn set_nic(
        &self,
        name: &str,
        change: impl FnOnce(&mut crate::NicSpec),
    ) -> std::io::Result<()> {
        self.shared.set_nic(name, change)
    }

    /// See [`set_link`](crate::set_link).
    pub fn set_link(&self, name: &str, carrier: bool) -> std::io::Result<()> {
        self.shared.set_link(name, carrier)
    }

    /// See [`schedule_link`](crate::schedule_link).
    pub fn schedule_link(&self, name: &str, after: Duration, carrier: bool) -> std::io::Result<()> {
        self.shared.schedule_link(name, after, carrier)
    }

    /// See [`set_nic_policy`](crate::set_nic_policy).
    pub fn set_nic_policy(
        &self,
        name: &str,
        change: impl FnOnce(&mut crate::NicPolicy),
    ) -> std::io::Result<()> {
        self.shared.set_nic_policy(name, change)
    }

    /// See [`set_nic_counters`](crate::set_nic_counters).
    pub fn set_nic_counters(
        &self,
        name: &str,
        change: impl FnOnce(&mut crate::NicCounters),
    ) -> std::io::Result<()> {
        self.shared.set_nic_counters(name, change)
    }

    /// This sim's interface `name`, if it has one; see [`nic`](crate::nic).
    pub fn nic(&self, name: &str) -> Option<crate::NicSnapshot> {
        self.shared.nic(name)
    }

    /// This sim's interfaces; see [`nics`](crate::nics).
    pub fn nics(&self) -> Vec<crate::NicSnapshot> {
        self.shared.nics()
    }

    /// The counters of this sim's interface `name`; see [`nic_counters`](crate::nic_counters).
    pub fn nic_counters(&self, name: &str) -> Option<crate::NicCounters> {
        self.shared.nic_counters(name)
    }

    /// Adds a route to this sim; see [`add_route`](crate::add_route).
    pub fn add_route(&self, route: crate::Route) -> std::io::Result<()> {
        self.shared.add_route(route)
    }

    /// Removes this sim's route to `dest`, returning whether there was one; see
    /// [`remove_route`](crate::remove_route).
    pub fn remove_route(&self, dest: crate::IpNet) -> bool {
        self.shared.remove_route(dest)
    }

    /// See [`set_default_route`](crate::set_default_route).
    pub fn set_default_route(&self, nic: Option<&str>) -> std::io::Result<()> {
        self.shared.set_default_route(nic)
    }

    /// This sim's routing table; see [`routes`](crate::routes).
    pub fn routes(&self) -> Vec<crate::Route> {
        self.shared.routes()
    }

    /// See [`route_lookup`](crate::route_lookup).
    pub fn route_lookup(
        &self,
        src: Option<std::net::IpAddr>,
        dst: std::net::IpAddr,
    ) -> std::io::Result<crate::RouteChoice> {
        self.shared.route_lookup(src, dst)
    }

    /// Holds this sim busy until the lease drops, from any thread; see [`crate::sched::busy`].
    pub fn busy(&self, label: &'static str) -> crate::sched::BusyLease {
        crate::sched::BusyLease::take(self.domain.clone(), label)
    }

    /// The leases holding this sim busy; see [`crate::sched::held_leases`].
    pub fn held_leases(&self) -> Vec<crate::sched::LeaseInfo> {
        self.domain.leases()
    }

    /// This sim's id: what [`crate::sched::current_sim`] returns on its threads.
    pub fn id(&self) -> crate::sched::SimId {
        self.domain.id()
    }

    /// Every OS thread of the process, this sim's told apart from other sims' and from unmanaged
    /// ones, from any thread; see [`crate::sched::thread_census`].
    pub fn thread_census(&self) -> Option<crate::sched::ThreadCensus> {
        snare_interpose::census(Some(&self.domain))
    }

    /// Resolves `name` to `addrs` in this sim, from any thread; see [`crate::add_host`].
    pub fn add_host(&self, name: &str, addrs: impl IntoIterator<Item = std::net::IpAddr>) {
        self.shared.dns.add(name, addrs);
    }

    /// Forgets `name` in this sim, from any thread; see [`crate::remove_host`].
    pub fn remove_host(&self, name: &str) {
        self.shared.dns.remove(name);
    }

    /// Changes how this sim answers lookups of `name`, from any thread; see
    /// [`crate::set_dns_policy`].
    pub fn set_dns_policy(&self, name: &str, change: impl FnOnce(&mut crate::DnsPolicy)) {
        self.shared.dns.update_policy(name, change);
    }

    /// Changes how this sim answers names without a policy of their own, from any thread; see
    /// [`crate::set_default_dns_policy`].
    pub fn set_default_dns_policy(&self, change: impl FnOnce(&mut crate::DnsPolicy)) {
        self.shared.dns.update_default_policy(change);
    }

    /// Delivers `signal` as Windows would; see the unix `Sim::raise_signal`.
    pub fn raise_signal(&self, signal: crate::Signal) -> crate::SignalDelivery {
        self.signals().raise(signal)
    }

    /// Delivers `signal` after `delay` of sim time; see the unix `Sim::raise_signal_after`.
    pub fn raise_signal_after(
        &self,
        signal: crate::Signal,
        delay: Duration,
    ) -> crate::PendingSignal {
        self.signals().raise_after(signal, delay)
    }

    /// A cloneable handle that sends signals into this sim from any thread.
    pub fn signals(&self) -> crate::SignalHandle {
        crate::SignalHandle::new(self.shared.clone())
    }

    /// Makes `addr` answer connects as `behavior` says, from any thread; see the unix
    /// `Sim::set_listener_behavior`.
    pub fn set_listener_behavior(
        &self,
        addr: impl std::net::ToSocketAddrs,
        behavior: crate::ListenerBehavior,
    ) {
        crate::faults::set_listener_behavior_on(&self.shared, addr, behavior);
    }

    /// Raises `error` on the sockets at `addr`, from any thread, inside the run or outside it; see
    /// [`raise_socket_error`](crate::raise_socket_error).
    pub fn raise_socket_error(&self, addr: impl std::net::ToSocketAddrs, error: std::io::Error) {
        crate::faults::raise_socket_error_on(&self.shared, addr, error);
    }

    /// Delivers an ICMP port unreachable from `from` to the datagram sockets at `to`, from any
    /// thread; see [`inject_icmp_port_unreachable`](crate::inject_icmp_port_unreachable).
    pub fn inject_icmp_port_unreachable(
        &self,
        to: impl std::net::ToSocketAddrs,
        from: impl std::net::ToSocketAddrs,
    ) {
        crate::faults::inject_icmp_on(&self.shared, to, from);
    }

    /// Holds the traffic at `addr` for `span` in `direction`, from any thread; see
    /// [`quiesce`](crate::quiesce).
    pub fn quiesce(
        &self,
        addr: impl std::net::ToSocketAddrs,
        span: Duration,
        direction: crate::Direction,
    ) {
        crate::faults::quiesce_on(&self.shared, addr, span, direction);
    }

    /// Changes the TCP link policy at `addr`, from any thread; see
    /// [`set_tcp_policy`](crate::set_tcp_policy).
    pub fn set_tcp_policy(
        &self,
        addr: impl std::net::ToSocketAddrs,
        change: impl FnOnce(&mut crate::TcpPolicy),
    ) {
        crate::netpolicy::set_tcp_policy_on(&self.shared, addr, change);
    }

    /// Changes the datagram link policy at `addr`, from any thread; see
    /// [`set_udp_policy`](crate::set_udp_policy).
    pub fn set_udp_policy(
        &self,
        addr: impl std::net::ToSocketAddrs,
        change: impl FnOnce(&mut crate::UdpPolicy),
    ) {
        crate::netpolicy::set_udp_policy_on(&self.shared, addr, change);
    }

    /// Hands this sim's clock to an executive; see the unix `Sim::executive`.
    pub fn executive(
        &self,
        cfg: crate::sched::ExecutiveConfig,
    ) -> Result<crate::sched::Executive, crate::sched::AttachError> {
        crate::executive::attach_to(self.shared.clone(), self.domain.clone(), cfg)
    }
}

/// Composes a [`Sim`] around a [`WinHost`].
#[derive(Default)]
pub struct SimBuilder {
    /// `None` means the default of 8.
    cpus: Option<usize>,
    /// Set by [`wall_clock`](Self::wall_clock); overridden by `time_rate` and cleared by
    /// `deterministic`.
    wall_clock: bool,
    time_rate: Option<f64>,
    seed: u64,
    deterministic: bool,
    /// The inverse of [`record_events`](Self::record_events), so `Default` records.
    quiet: bool,
    nics: Vec<crate::NicSpec>,
    routes: Vec<crate::Route>,
    /// Names, real-resolver snapshots and the real-DNS fallback, applied at `build`.
    dns: crate::dns::DnsSetup,
    forward_signals: bool,
    privileges: Option<crate::Privileges>,
    sys_limits: Option<crate::SysLimits>,
    pcapng: Option<std::path::PathBuf>,
    /// See [`pcapng_wall_comment`](Self::pcapng_wall_comment).
    pcapng_wall_comment: bool,
    /// See [`stuck_after`](Self::stuck_after).
    stuck_after: Option<Duration>,
    /// See [`adapter`](Self::adapter).
    adapters: Vec<(String, crate::Adapter)>,
    /// See [`strict_sockopts`](Self::strict_sockopts).
    strict_sockopts: bool,
}

impl SimBuilder {
    /// What the code under test may do (default [`Privileges::all`](crate::Privileges::all)); see
    /// [`crate::set_privileges`].
    pub fn privileges(mut self, privileges: crate::Privileges) -> Self {
        self.privileges = Some(privileges);
        self
    }

    /// The socket limits the sim starts with (default
    /// [`SysLimits::host`](crate::SysLimits::host)).
    pub fn sys_limits(mut self, limits: crate::SysLimits) -> Self {
        self.sys_limits = Some(limits);
        self
    }

    /// Gives the sim an interface; see [`add_nic`](crate::add_nic).
    pub fn nic(mut self, spec: crate::NicSpec) -> Self {
        self.nics.push(spec);
        self
    }

    /// Describes the network adapter behind interface `nic`: the driver version, advanced
    /// properties and restart flap its device node shows SetupAPI and the registry (see the
    /// [`Adapter`](crate::Adapter) docs). An interface without one gets
    /// [`Adapter::new`](crate::Adapter::new).
    pub fn adapter(mut self, nic: impl Into<String>, adapter: crate::Adapter) -> Self {
        self.adapters.push((nic.into(), adapter));
        self
    }

    /// Gives the sim a route; see [`add_route`](crate::add_route).
    pub fn route(mut self, route: crate::Route) -> Self {
        self.routes.push(route);
        self
    }

    /// The number of logical CPUs the process affinity mask spans (default 8, clamped to 1..=64).
    /// 8 is a snare choice: a typical small workstation, enough for affinity tests to pin
    /// threads apart.
    pub fn cpus(mut self, count: usize) -> Self {
        self.cpus = Some(count);
        self
    }

    /// Runs the sim on the discrete-event virtual clock — the default, so this only states it. See
    /// the unix `SimBuilder::virtual_clock`.
    pub fn virtual_clock(mut self) -> Self {
        self.wall_clock = false;
        self
    }

    /// Runs the sim on the real wall clock instead of the virtual one. Such a sim has no clock
    /// to control; `time_rate(1.0)` provides a controllable clock that tracks real time.
    pub fn wall_clock(mut self) -> Self {
        self.wall_clock = true;
        self
    }

    /// Starts the virtual clock scaled to real time at `rate`; see the unix
    /// `SimBuilder::time_rate`.
    #[track_caller]
    pub fn time_rate(mut self, rate: f64) -> Self {
        crate::clock::validate_rate(rate, false);
        self.time_rate = Some(rate);
        self
    }

    /// Runs the sim's threads deterministically, one at a time in a fixed order; see the unix
    /// `SimBuilder::deterministic`. Implies the virtual clock.
    pub fn deterministic(mut self) -> Self {
        self.deterministic = true;
        self.wall_clock = false;
        self
    }

    /// Seeds the sim's randomness (default 0); see the unix `SimBuilder::seed`.
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Whether the sim keeps its recorded events (default on); see the unix
    /// `SimBuilder::record_events`.
    pub fn record_events(mut self, on: bool) -> Self {
        self.quiet = !on;
        self
    }

    /// Resolves `name` to `addrs` from the start; see the unix `SimBuilder::add_host`.
    pub fn add_host(
        mut self,
        name: &str,
        addrs: impl IntoIterator<Item = std::net::IpAddr>,
    ) -> Self {
        self.dns.add_host(name, addrs);
        self
    }

    /// Forwards the real console control events the process receives into this sim while it lives;
    /// see the unix `SimBuilder::forward_real_signals`.
    pub fn forward_real_signals(mut self) -> Self {
        self.forward_signals = true;
        self
    }

    /// Snapshots `name` from the real resolver at build; see the unix `SimBuilder::resolve_real`.
    pub fn resolve_real(mut self, name: &str) -> Self {
        self.dns.resolve_real(name);
        self
    }

    /// Sends unknown names to the real resolver; see the unix `SimBuilder::real_dns`.
    pub fn real_dns(mut self) -> Self {
        self.dns.real_dns();
        self
    }

    /// Writes every frame that crosses the sim's network to a pcapng file at `path`; see the unix
    /// `SimBuilder::pcapng`.
    pub fn pcapng(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.pcapng = Some(path.into());
        self
    }

    /// Whether each captured frame also carries the real wall time it was sent at as a pcapng
    /// comment (default off); see the unix `SimBuilder::pcapng_wall_comment`.
    pub fn pcapng_wall_comment(mut self, on: bool) -> Self {
        self.pcapng_wall_comment = on;
        self
    }

    /// Fails every socket option the sim does not model rather than accepting it without effect,
    /// with what Winsock answers for an option it does not know: `WSAEINVAL` at `SOL_SOCKET`,
    /// `WSAENOPROTOOPT` at the protocol levels (both measured by tests/strict_sockopts.rs); see
    /// the unix `SimBuilder::strict_sockopts`. A `WSAIoctl` code the sim does not carry out fails
    /// with `WSAEOPNOTSUPP` with or without it. Either way each is listed in the socket's
    /// [`SocketEntry::unmodelled_options`](crate::SocketEntry::unmodelled_options) and logged as
    /// [`RecordedEvent::UnmodelledOption`](crate::RecordedEvent::UnmodelledOption). The options
    /// the sim keeps on purpose as harmless are not refused.
    pub fn strict_sockopts(mut self) -> Self {
        self.strict_sockopts = true;
        self
    }

    /// Aborts the process with a report when the sim makes no progress for `after` of real time
    /// while a participant keeps it busy (default off); see the unix `SimBuilder::stuck_after`.
    /// Panics if `after` is zero.
    #[track_caller]
    pub fn stuck_after(mut self, after: Duration) -> Self {
        assert!(!after.is_zero(), "stuck_after must be longer than zero");
        self.stuck_after = Some(after);
        self
    }

    /// Builds the sim and installs its domain. The clock is configured before `SimShared`
    /// captures it, topology, names, privileges and limits are loaded before any backend can
    /// serve a call, the host learns its sim before the domain is installed, and the domain's weak
    /// handle is stored in `SimShared` only once it exists. The domain offers each call to its
    /// layers first to last: the clock, the registry scope, then the seeded random layer.
    ///
    /// Panics if [`real_dns`](Self::real_dns) is combined with
    /// [`deterministic`](Self::deterministic), if a [`resolve_real`](Self::resolve_real) lookup
    /// fails, or if the [`pcapng`](Self::pcapng) file cannot be created.
    #[track_caller]
    pub fn build(self) -> Sim {
        self.dns.check(self.deterministic);
        let clock = (!self.wall_clock || self.time_rate.is_some()).then(|| Arc::new(Clock::new(0)));
        if let Some(clock) = &clock {
            clock.set_discrete(true);
            clock.set_deterministic(self.deterministic);
            if let Some(rate) = self.time_rate {
                clock.check_rate(rate);
                clock.set_rate(rate);
            }
        }
        let shared = SimShared::new(self.seed, clock.clone());
        shared.events.set_enabled(!self.quiet);
        shared
            .strict_sockopts
            .store(self.strict_sockopts, std::sync::atomic::Ordering::Relaxed);
        crate::pcapng::attach(&shared, self.pcapng, self.pcapng_wall_comment);
        shared.init_topology(Vec::new(), Vec::new(), self.nics, self.routes);
        self.dns.apply(&shared);
        if let Some(privileges) = self.privileges {
            shared.sys.set_privileges(|p| *p = privileges);
        }
        if let Some(limits) = self.sys_limits {
            shared.sys.set_limits(|l| *l = limits);
        }
        let host = Arc::new(WinHost::new(self.cpus.unwrap_or(8)));
        for (nic, adapter) in self.adapters {
            host.adapters.configure(&shared, &nic, adapter);
        }
        let _ = host.shared.set(Arc::downgrade(&shared));
        let net = Arc::new(crate::win_net::WinNet::new(shared.clone()));
        let mut builder = Domain::builder()
            .resolver(crate::dns::DnsSetup::resolver(&shared))
            .signals(Arc::new(crate::signals::SimSignals(shared.clone())))
            .layers([
                Arc::new(crate::win_net::ScopeLayer(net.registries())) as Arc<dyn Layer>,
                Arc::new(crate::random::RandomLayer::new(shared.seed)),
            ])
            .net(net.clone())
            .host(host.clone());
        if let Some(clock) = clock {
            builder = builder.layers([Arc::new(ClockLayer(clock)) as Arc<dyn Layer>]);
        }
        if self.deterministic {
            builder = builder.deterministic();
        }
        if let Some(after) = self.stuck_after {
            builder = builder.stuck_after(after);
        }
        let domain = builder.install();
        let _ = shared.domain.set(domain.downgrade());
        if let Some(clock) = &shared.clock {
            clock.set_domain(&domain);
        }
        let forward = self
            .forward_signals
            .then(|| crate::signals::forward::register(shared.clone()));
        Sim {
            domain,
            shared,
            _host: host,
            _net: net,
            _forward: forward,
        }
    }
}
