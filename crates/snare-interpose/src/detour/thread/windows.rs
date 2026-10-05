//! Thread suspension using the Win32 API.

use super::Thread;
use crate::detour::error::{Error, OsError, Result};
use core::mem;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT, GetThreadContext, SetThreadContext};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, GetCurrentThreadId, GetProcessIdOfThread, GetThreadId, OpenThread,
    ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION,
    THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME, THREAD_SYNCHRONIZE, WaitForSingleObject,
};

#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64 as CONTEXT_CONTROL;
#[cfg(target_arch = "aarch64")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_ARM64 as CONTEXT_CONTROL;
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_X86 as CONTEXT_CONTROL;

/// A `HANDLE`, stored as an integer so threads are `Send` & `Sync`.
pub(crate) type RawThread = usize;

/// The suspended threads, resumed once dropped.
pub(crate) type Session = Vec<Suspended>;

/// A thread context, which must be 16-byte aligned on x86-64.
#[repr(C, align(16))]
struct Context(CONTEXT);

fn last_error() -> Error {
    Error::Thread(OsError::last_os_error())
}

/// A suspended thread, which is resumed once dropped.
pub(crate) struct Suspended {
    handle: HANDLE,
    id: u32,
    /// Whether the handle is owned (and must be closed).
    owned: bool,
    context: Context,
    modified: bool,
}

impl Suspended {
    /// Suspends the thread of `handle`, closing the handle on failure if owned.
    fn new(handle: HANDLE, id: u32, owned: bool, allow_exited: bool) -> Result<Option<Self>> {
        let fail = |error| {
            // SAFETY: The handle is open and has SYNCHRONIZE rights in this mode.
            let exited = allow_exited && unsafe { WaitForSingleObject(handle, 0) } == WAIT_OBJECT_0;
            if owned {
                // SAFETY: The handle is owned.
                unsafe { CloseHandle(handle) };
            }
            if exited { Ok(None) } else { Err(error) }
        };

        // SAFETY: Suspending a thread has no memory safety implications.
        if unsafe { SuspendThread(handle) } == u32::MAX {
            return fail(last_error());
        }

        // Suspension is asynchronous; retrieving the context waits for it.
        // SAFETY: A zeroed context is valid.
        let mut context: Context = unsafe { mem::zeroed() };
        context.0.ContextFlags = CONTEXT_CONTROL;
        // SAFETY: The context is aligned, and the thread is suspended.
        if unsafe { GetThreadContext(handle, &mut context.0) } == 0 {
            let error = last_error();
            // SAFETY: The thread was suspended above.
            unsafe { ResumeThread(handle) };
            return fail(error);
        }

        Ok(Some(Suspended {
            handle,
            id,
            owned,
            context,
            modified: false,
        }))
    }

    /// Returns the program counter.
    pub fn pc(&self) -> usize {
        #[cfg(target_arch = "aarch64")]
        return self.context.0.Pc as usize;
        #[cfg(target_arch = "x86_64")]
        return self.context.0.Rip as usize;
        #[cfg(target_arch = "x86")]
        return self.context.0.Eip as usize;
    }

    /// Sets the program counter, which is applied by [`Suspended::apply`].
    pub fn set_pc(&mut self, pc: usize) {
        #[cfg(target_arch = "aarch64")]
        {
            self.context.0.Pc = pc as u64;
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.context.0.Rip = pc as u64;
        }
        #[cfg(target_arch = "x86")]
        {
            self.context.0.Eip = pc as u32;
        }
        self.modified = true;
    }

    /// Applies a modified program counter.
    pub(super) fn apply(&mut self) -> Result<()> {
        if !mem::take(&mut self.modified) {
            return Ok(());
        }
        // SAFETY: The context was retrieved from the (suspended) thread.
        if unsafe { SetThreadContext(self.handle, &self.context.0) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }
}

impl Drop for Suspended {
    fn drop(&mut self) {
        // SAFETY: The thread was suspended by `self`, and the handle is closed
        // only if owned.
        unsafe {
            ResumeThread(self.handle);
            if self.owned {
                CloseHandle(self.handle);
            }
        }
    }
}

/// Suspends all other threads of the process.
///
/// The threads are enumerated repeatedly until no new threads appear. A
/// snapshot is allocated using virtual memory (not the process heap), so
/// this is safe whilst threads are suspended.
pub(super) fn suspend_all() -> Result<Session> {
    const RIGHTS: u32 = THREAD_SUSPEND_RESUME
        | THREAD_GET_CONTEXT
        | THREAD_SET_CONTEXT
        | THREAD_SYNCHRONIZE
        | THREAD_QUERY_LIMITED_INFORMATION;

    // SAFETY: These have no preconditions.
    let (process, current) = unsafe { (GetCurrentProcessId(), GetCurrentThreadId()) };
    let mut suspended: Vec<Suspended> = Vec::new();

    loop {
        let (mut added, mut complete, mut count) = (false, true, 0);
        for_each_thread(|entry| {
            let id = entry.th32ThreadID;
            if entry.th32OwnerProcessID == process && id != current {
                count += 1;
                if suspended.iter().all(|thread| thread.id != id) {
                    if suspended.len() == suspended.capacity() {
                        complete = false;
                    } else {
                        // SAFETY: Opening a thread has no memory safety implications.
                        let handle = unsafe { OpenThread(RIGHTS, 0, id) };
                        if handle.is_null() {
                            let error = last_error();
                            if !matches!(&error, Error::Thread(error) if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32))
                                || thread_exists(process, id)?
                            {
                                return Err(error);
                            }
                        } else {
                            // SAFETY: The open thread handle has query rights.
                            let owner = unsafe { GetProcessIdOfThread(handle) };
                            if owner != process {
                                let error = last_error();
                                // SAFETY: The handle is owned and has not been suspended.
                                unsafe { CloseHandle(handle) };
                                if owner == 0 {
                                    return Err(error);
                                }
                            } else if let Some(thread) = Suspended::new(handle, id, true, true)? {
                                suspended.push(thread);
                                added = true;
                            }
                        }
                    }
                }
            }
            Ok(())
        })?;

        if !complete {
            // Resume all threads before allocating, and retry with a larger capacity
            drop(mem::take(&mut suspended));
            suspended = Vec::with_capacity(count * 2 + 16);
        } else if !added {
            return Ok(suspended);
        }
    }
}

fn for_each_thread(mut visit: impl FnMut(&THREADENTRY32) -> Result<()>) -> Result<()> {
    struct Snapshot(HANDLE);
    impl Drop for Snapshot {
        fn drop(&mut self) {
            // SAFETY: The snapshot handle is owned.
            unsafe { CloseHandle(self.0) };
        }
    }

    // SAFETY: Creates a snapshot of all threads in the system.
    let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    let snapshot = Snapshot(handle);
    // SAFETY: A zeroed entry is valid.
    let mut entry: THREADENTRY32 = unsafe { mem::zeroed() };
    entry.dwSize = mem::size_of::<THREADENTRY32>() as u32;
    // SAFETY: The snapshot and writable entry are valid.
    let mut more = unsafe { Thread32First(snapshot.0, &mut entry) } != 0;
    while more {
        visit(&entry)?;
        // SAFETY: The snapshot and writable entry are valid.
        more = unsafe { Thread32Next(snapshot.0, &mut entry) } != 0;
    }
    let error = last_error();
    if matches!(&error, Error::Thread(error) if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32))
    {
        Ok(())
    } else {
        Err(error)
    }
}

fn thread_exists(process: u32, id: u32) -> Result<bool> {
    let mut exists = false;
    for_each_thread(|entry| {
        exists |= entry.th32OwnerProcessID == process && entry.th32ThreadID == id;
        Ok(())
    })?;
    Ok(exists)
}

/// Suspends the given threads, ignoring the current thread.
pub(super) fn suspend(threads: &[Thread]) -> Result<Session> {
    // SAFETY: This has no preconditions.
    let current = unsafe { GetCurrentThreadId() };
    let mut suspended = Vec::with_capacity(threads.len());

    for thread in threads {
        let handle = thread.0 as HANDLE;
        // SAFETY: Querying an invalid handle fails gracefully.
        let id = unsafe { GetThreadId(handle) };
        if id == 0 {
            return Err(last_error());
        }
        if id != current {
            suspended.push(Suspended::new(handle, id, false, false)?.expect("live thread"));
        }
    }
    Ok(suspended)
}
