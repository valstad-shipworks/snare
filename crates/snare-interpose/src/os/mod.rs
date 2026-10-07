//! The OS-facing half of interposition: one submodule per family of hooked functions, the
//! per-OS `hooks()` table that [`crate::hooks::all`] is built from, and a few direct OS queries the
//! rest of the crate needs. Everything here that calls the OS itself is meant to run under
//! passthrough, so its own calls are not taken for the code under test's.

#[cfg(windows)]
mod devices_windows;
#[cfg(unix)]
mod dns;
#[cfg(windows)]
mod dns_windows;
#[cfg(unix)]
mod files;
mod gai;
#[cfg(target_os = "linux")]
mod host;
#[cfg(target_os = "macos")]
mod host_macos;
#[cfg(windows)]
mod iphlp_windows;
mod nested;
pub(crate) use nested::startup as thread_startup;
#[cfg(unix)]
mod signal_hooks;
#[cfg(unix)]
mod sockets;
#[cfg(unix)]
mod vectored;
#[cfg(target_os = "linux")]
pub(crate) use sockets::{recvmmsg_each, sendmmsg_each};
#[cfg(unix)]
pub(crate) mod sync;
#[cfg(unix)]
pub(crate) mod tz;
#[cfg(target_os = "macos")]
mod tz_macos;
#[cfg(unix)]
mod unix;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod variadic;
#[cfg(windows)]
pub(crate) mod windows;
#[cfg(windows)]
pub(crate) mod windows_std_sleep;
#[cfg(windows)]
mod wsa_windows;

#[doc(hidden)]
pub use gai::joined_lists;

#[cfg(unix)]
pub(crate) use unix::hooks;
#[cfg(windows)]
pub(crate) use windows::hooks;
#[cfg(windows)]
pub use windows::{next_performance_count, performance_count};

/// Whether `addr` lies inside a loaded image (a binary's or library's mapped sections, static data
/// included) rather than the heap or a stack. Called under passthrough.
///
/// `dladdr` returns nonzero whenever the address falls in some loaded object, even where no
/// symbol covers it (man 3 dladdr, RETURN VALUE).
#[cfg(target_os = "linux")]
pub(crate) fn address_in_image(addr: usize) -> bool {
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    // SAFETY: dladdr only reads the loader's image list for this address and fills `info`.
    unsafe { libc::dladdr(addr as *const libc::c_void, &mut info) != 0 }
}

/// Whether `addr` lies inside a loaded module. Called under passthrough.
///
/// `GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS` makes the name argument an address in the module, and
/// `GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT` leaves the module's reference count alone, so
/// nothing needs releasing
/// ([Microsoft Learn: GetModuleHandleExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexw)).
#[cfg(windows)]
pub(crate) fn address_in_image(addr: usize) -> bool {
    use windows_sys::Win32::System::LibraryLoader::{
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        GetModuleHandleExW,
    };
    let mut module = std::ptr::null_mut();
    // SAFETY: with FROM_ADDRESS the "name" is the address to look up; the refcount is untouched.
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            addr as *const u16,
            &mut module,
        ) != 0
    }
}

/// The calling thread's OS handle, as thread-creation hooks record a child's: its `pthread_t`
/// (an opaque pointer on macOS, an integer on Linux, hence the cast).
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
pub(crate) fn current_thread_handle() -> usize {
    // SAFETY: pthread_self has no preconditions.
    unsafe { libc::pthread_self() as usize }
}

/// The calling thread's OS handle, as thread-creation hooks record a child's: its thread id rather than
/// a `HANDLE`, since an id names the thread from any thread and needs no closing.
#[cfg(windows)]
pub(crate) fn current_thread_handle() -> usize {
    // SAFETY: GetCurrentThreadId has no preconditions.
    unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() as usize }
}

/// The name the OS holds for a thread (`pthread_getname_np(3)`), the caller's for `None`; `None`
/// when it has none. Called under passthrough.
#[cfg(unix)]
pub(crate) fn thread_name(handle: Option<usize>) -> Option<String> {
    let thread = handle.map_or_else(
        // SAFETY: pthread_self has no preconditions.
        || unsafe { libc::pthread_self() },
        |handle| handle as libc::pthread_t,
    );
    // Large enough for both OSes' limits: 16 bytes with the NUL on Linux (man 3
    // pthread_setname_np; ERANGE below that), MAXTHREADNAMESIZE = 64 on macOS
    // (<sys/proc_info.h>).
    let mut buf = [0 as std::ffi::c_char; 64];
    // SAFETY: `buf` is writable for its length; the OS NUL-terminates what it writes.
    if unsafe { libc::pthread_getname_np(thread, buf.as_mut_ptr(), buf.len()) } != 0 {
        return None;
    }
    // SAFETY: as above.
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_string_lossy();
    (!name.is_empty()).then(|| name.into_owned())
}

/// The description the OS holds for a thread (`GetThreadDescription`), the caller's for `None`;
/// `None` when it has none or the thread cannot be opened. Called under passthrough.
///
/// The handle needs `THREAD_QUERY_LIMITED_INFORMATION`; success is a non-negative `HRESULT`, and
/// the returned string is freed with `LocalFree`
/// ([Microsoft Learn: GetThreadDescription](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreaddescription)).
#[cfg(windows)]
pub(crate) fn thread_name(handle: Option<usize>) -> Option<String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::System::Threading::{
        GetCurrentThread, GetThreadDescription, OpenThread, THREAD_QUERY_LIMITED_INFORMATION,
    };
    let (thread, owned) = match handle {
        // SAFETY: GetCurrentThread returns a pseudo-handle and has no preconditions.
        None => (unsafe { GetCurrentThread() }, false),
        Some(id) => {
            // SAFETY: OpenThread accepts any id and returns null if it cannot open it.
            let thread = unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, id as u32) };
            if thread.is_null() {
                return None;
            }
            (thread, true)
        }
    };
    let mut description = std::ptr::null_mut();
    // SAFETY: a thread handle with query access, and a place for the OS to put its allocation.
    let hresult = unsafe { GetThreadDescription(thread, &mut description) };
    let name = (hresult >= 0 && !description.is_null()).then(|| {
        // SAFETY: on success the OS returns a NUL-terminated UTF-16 string, freed with LocalFree.
        unsafe {
            let mut len = 0;
            while *description.add(len) != 0 {
                len += 1;
            }
            let name = String::from_utf16_lossy(std::slice::from_raw_parts(description, len));
            LocalFree(description.cast());
            name
        }
    });
    if owned {
        // SAFETY: the handle OpenThread returned above.
        unsafe { windows::close_internal_handle(thread) };
    }
    name.filter(|name| !name.is_empty())
}
