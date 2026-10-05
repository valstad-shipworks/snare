use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicUsize;
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::{GetLastError, RtlNtStatusToDosError, SetLastError};

use crate::domain::{self, Domain, WeakDomain};
use crate::hooks::{Hook, hook, original};
use crate::net::{CompletionCall, CompletionQuery};
use crate::state;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSetIoCompletion(
        port: *mut u8,
        key: *mut u8,
        context: *mut u8,
        status: i32,
        information: usize,
    ) -> i32;
}

static CREATE: AtomicUsize = AtomicUsize::new(0);
static GET: AtomicUsize = AtomicUsize::new(0);
static GET_EX: AtomicUsize = AtomicUsize::new(0);
static POST: AtomicUsize = AtomicUsize::new(0);
static POLL: AtomicUsize = AtomicUsize::new(0);
static CANCEL: AtomicUsize = AtomicUsize::new(0);
static CREATE_FILE: AtomicUsize = AtomicUsize::new(0);

fn owners() -> &'static Mutex<HashMap<usize, WeakDomain>> {
    static OWNERS: OnceLock<Mutex<HashMap<usize, WeakDomain>>> = OnceLock::new();
    OWNERS.get_or_init(Mutex::default)
}

fn afd_files() -> &'static Mutex<HashSet<usize>> {
    static FILES: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();
    FILES.get_or_init(Mutex::default)
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum: u16,
    buffer: *const u16,
}
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root: usize,
    name: *const UnicodeString,
    attributes: u32,
    security: usize,
    quality: usize,
}

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn create_file(
    file: *mut usize,
    access: u32,
    attributes: *const ObjectAttributes,
    status: *mut u8,
    size: *mut i64,
    file_attributes: u32,
    share: u32,
    disposition: u32,
    options: u32,
    buffer: *mut u8,
    length: u32,
) -> i32 {
    let native = unsafe {
        original::<
            unsafe extern "system" fn(
                *mut usize,
                u32,
                *const ObjectAttributes,
                *mut u8,
                *mut i64,
                u32,
                u32,
                u32,
                u32,
                *mut u8,
                u32,
            ) -> i32,
        >(&CREATE_FILE)
    };
    let owner = if state::passthrough() {
        None
    } else {
        Domain::current()
    };
    let pass = state::Passthrough::enter();
    let result = unsafe {
        native(
            file,
            access,
            attributes,
            status,
            size,
            file_attributes,
            share,
            disposition,
            options,
            buffer,
            length,
        )
    };
    let error = unsafe { GetLastError() };
    let mut modeled = false;
    if result >= 0
        && let Some(owner) = owner
        && !file.is_null()
        && !attributes.is_null()
    {
        let name = unsafe { (*attributes).name };
        if !name.is_null() {
            let name = unsafe { &*name };
            if !name.buffer.is_null() && name.length as usize == "\\Device\\Afd\\Mio".len() * 2 {
                let actual =
                    unsafe { std::slice::from_raw_parts(name.buffer, name.length as usize / 2) };
                if actual
                    .iter()
                    .copied()
                    .eq("\\Device\\Afd\\Mio".encode_utf16())
                {
                    let handle = unsafe { *file };
                    let mut table = owners().lock().unwrap();
                    table.insert(handle, owner.downgrade());
                    afd_files().lock().unwrap().insert(handle);
                    modeled = true;
                }
            }
        }
    }
    drop(pass);
    if !modeled {
        domain::observe("NtCreateFile", None);
    }
    unsafe { SetLastError(error) };
    result
}

fn owner(handle: usize) -> Option<Domain> {
    owners()
        .lock()
        .unwrap()
        .get(&handle)
        .and_then(WeakDomain::upgrade)
}

fn dispatch(
    handle: usize,
    mut call: impl FnMut(&dyn crate::Net) -> Option<crate::NetResult>,
) -> Option<i64> {
    if state::passthrough() {
        return None;
    }
    let owner = owner(handle)?;
    domain::dispatch_net_for(&owner, |net| call(net))
}

pub(super) fn hooks() -> Vec<Hook> {
    vec![
        hook!("CreateIoCompletionPort", "kernel32.dll", create, CREATE),
        hook!("GetQueuedCompletionStatus", "kernel32.dll", get, GET),
        hook!(
            "GetQueuedCompletionStatusEx",
            "kernel32.dll",
            get_ex,
            GET_EX
        ),
        hook!("PostQueuedCompletionStatus", "kernel32.dll", post, POST),
        hook!("NtDeviceIoControlFile", "ntdll.dll", poll, POLL),
        hook!("NtCancelIoFileEx", "ntdll.dll", cancel, CANCEL),
        hook!("NtCreateFile", "ntdll.dll", create_file, CREATE_FILE),
    ]
}

unsafe extern "system" fn create(
    file: *mut u8,
    port: *mut u8,
    key: usize,
    threads: u32,
) -> *mut u8 {
    let native = unsafe {
        original::<unsafe extern "system" fn(*mut u8, *mut u8, usize, u32) -> *mut u8>(&CREATE)
    };
    if state::passthrough() {
        return unsafe { native(file, port, key, threads) };
    }
    let _pass = state::Passthrough::enter();
    let current = Domain::current();
    let mut table = owners().lock().unwrap();
    let supplied_owner = table.get(&(port as usize)).and_then(WeakDomain::upgrade);
    if file as usize != usize::MAX
        && let Some(owner) = &supplied_owner
        && let Some(result) = domain::dispatch_net_for(owner, |net| unsafe {
            net.completion(CompletionCall::Associate {
                port: port as usize,
                afd: afd_files().lock().unwrap().contains(&(file as usize)),
            })
        })
        && result < 0
    {
        unsafe { SetLastError((-result) as u32) };
        return std::ptr::null_mut();
    }
    let result = unsafe { native(file, port, key, threads) };
    let error = unsafe { GetLastError() };
    if !result.is_null()
        && let Some(owner) = supplied_owner.or(current)
    {
        let post = NtSetIoCompletion;
        if domain::dispatch_net_for(&owner, |net| unsafe {
            net.completion(CompletionCall::Register {
                file: file as usize,
                port: result as usize,
                key,
                post,
                afd: afd_files().lock().unwrap().contains(&(file as usize)),
            })
        })
        .is_some()
        {
            table.insert(result as usize, owner.downgrade());
            if file as usize != usize::MAX {
                table.insert(file as usize, owner.downgrade());
            }
        }
    }
    unsafe { SetLastError(error) };
    result
}

unsafe extern "system" fn get_ex(
    port: *mut u8,
    entries: *mut u8,
    count: u32,
    removed: *mut u32,
    timeout: u32,
    alertable: i32,
) -> i32 {
    let native = unsafe { original::<CompletionQuery>(&GET_EX) };
    if let Some(result) = dispatch(port as usize, |net| unsafe {
        net.completion(CompletionCall::Get {
            port: port as usize,
            entries,
            count,
            removed,
            timeout,
            alertable,
            query: native,
        })
    }) {
        if result < 0 {
            unsafe { SetLastError((-result) as u32) };
            return 0;
        }
        return result as i32;
    }
    unsafe { native(port, entries, count, removed, timeout, alertable) }
}

#[repr(C)]
struct Entry {
    key: usize,
    overlapped: *mut u8,
    internal: usize,
    bytes: u32,
}

unsafe extern "system" fn get(
    port: *mut u8,
    bytes: *mut u32,
    key: *mut usize,
    overlapped: *mut *mut u8,
    timeout: u32,
) -> i32 {
    if !state::passthrough()
        && owner(port as usize).is_some()
        && !bytes.is_null()
        && !key.is_null()
        && !overlapped.is_null()
    {
        let mut entry = Entry {
            key: 0,
            overlapped: std::ptr::null_mut(),
            internal: 0,
            bytes: 0,
        };
        let mut removed = 0;
        let result = unsafe { get_ex(port, (&raw mut entry).cast(), 1, &mut removed, timeout, 0) };
        unsafe {
            *overlapped = entry.overlapped;
        }
        if result != 0 {
            unsafe {
                *bytes = entry.bytes;
                *key = entry.key;
            }
            if (entry.internal as i32) < 0 {
                unsafe { SetLastError(RtlNtStatusToDosError(entry.internal as i32)) };
                return 0;
            }
        }
        return result;
    }
    unsafe {
        original::<unsafe extern "system" fn(*mut u8, *mut u32, *mut usize, *mut *mut u8, u32) -> i32>(
            &GET,
        )(port, bytes, key, overlapped, timeout)
    }
}

unsafe extern "system" fn post(port: *mut u8, bytes: u32, key: usize, overlapped: *mut u8) -> i32 {
    let native = unsafe {
        original::<unsafe extern "system" fn(*mut u8, u32, usize, *mut u8) -> i32>(&POST)
    };
    let result = unsafe { native(port, bytes, key, overlapped) };
    let error = unsafe { GetLastError() };
    if result != 0 {
        dispatch(port as usize, |net| unsafe {
            net.completion(CompletionCall::Notify {
                port: port as usize,
            })
        });
    }
    unsafe { SetLastError(error) };
    result
}

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn poll(
    file: *mut u8,
    event: *mut u8,
    routine: *mut u8,
    context: *mut u8,
    status: *mut u8,
    code: u32,
    input: *mut u8,
    input_len: u32,
    output: *mut u8,
    output_len: u32,
) -> i32 {
    if code == 0x12024
        && event.is_null()
        && routine.is_null()
        && let Some(result) = dispatch(file as usize, |net| unsafe {
            net.completion(CompletionCall::Poll {
                file: file as usize,
                status,
                context: context as usize,
                input,
                input_len,
                output,
                output_len,
            })
        })
    {
        return result as i32;
    }
    domain::observe("NtDeviceIoControlFile", None);
    unsafe {
        original::<
            unsafe extern "system" fn(
                *mut u8,
                *mut u8,
                *mut u8,
                *mut u8,
                *mut u8,
                u32,
                *mut u8,
                u32,
                *mut u8,
                u32,
            ) -> i32,
        >(&POLL)(
            file, event, routine, context, status, code, input, input_len, output, output_len,
        )
    }
}

unsafe extern "system" fn cancel(file: *mut u8, status: *mut u8, result: *mut u8) -> i32 {
    if let Some(code) = dispatch(file as usize, |net| unsafe {
        net.completion(CompletionCall::Cancel {
            file: file as usize,
            status,
            result,
        })
    }) {
        return code as i32;
    }
    unsafe {
        original::<unsafe extern "system" fn(*mut u8, *mut u8, *mut u8) -> i32>(&CANCEL)(
            file, status, result,
        )
    }
}

pub(super) unsafe fn close(
    handle: *mut u8,
    native: unsafe extern "system" fn(*mut u8) -> i32,
) -> Option<i32> {
    let _pass = state::Passthrough::enter();
    let mut table = owners().lock().unwrap();
    let weak = table.get(&(handle as usize))?;
    let result = if let Some(owner) = weak.upgrade() {
        domain::dispatch_net_for(&owner, |net| unsafe {
            net.completion(CompletionCall::Close {
                handle: handle as usize,
                native,
            })
        })?
    } else {
        let result = unsafe { native(handle) };
        if result == 0 {
            -(unsafe { GetLastError() } as i64)
        } else {
            result as i64
        }
    };
    let error = unsafe { GetLastError() };
    if result > 0 {
        table.remove(&(handle as usize));
        afd_files().lock().unwrap().remove(&(handle as usize));
        unsafe { SetLastError(error) };
        Some(result as i32)
    } else {
        unsafe { SetLastError((-result) as u32) };
        Some(0)
    }
}

pub(super) unsafe fn duplicate_boundary(
    source_process: *mut u8,
    source: *mut u8,
    options: u32,
    native_close: unsafe extern "system" fn(*mut u8) -> i32,
) -> Option<i32> {
    if state::passthrough() {
        return None;
    }
    use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetProcessId};
    let _pass = state::Passthrough::enter();
    if unsafe { GetProcessId(source_process.cast()) } != unsafe { GetCurrentProcessId() } {
        return None;
    }
    let mut table = owners().lock().unwrap();
    let owner = table
        .get(&(source as usize))
        .and_then(WeakDomain::upgrade)?;
    let afd = afd_files().lock().unwrap().contains(&(source as usize));
    let modeled = domain::dispatch_net_for(&owner, |net| unsafe {
        net.completion(CompletionCall::Duplicate {
            handle: source as usize,
        })
    })
    .is_some();
    if !afd && !modeled {
        return None;
    }
    if options & 1 != 0
        && domain::dispatch_net_for(&owner, |net| unsafe {
            net.completion(CompletionCall::Close {
                handle: source as usize,
                native: native_close,
            })
        })
        .is_some_and(|result| result > 0)
    {
        table.remove(&(source as usize));
        afd_files().lock().unwrap().remove(&(source as usize));
    }
    unsafe { SetLastError(50) };
    Some(0)
}
