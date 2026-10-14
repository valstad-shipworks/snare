//! The environment hooks: kernel32's environment-variable and environment-block calls, the UCRT's
//! `getenv` family, and `CreateProcessW`/`A`, whose child gets the sim's block when the caller
//! passes none. A managed thread whose domain has a [`WinEnv`] is served from it; every other call
//! goes to the real function.
//!
//! The ANSI calls convert through the ANSI code page and keep the limits their kernelbase forms
//! have, measured on Windows 11 ARM64 under code page 1252 (a single-byte page, so an ANSI string
//! there is as long as its UTF-16 form).
//!
//! `FreeEnvironmentStringsW`/`A` are not hooked: the real ones free a block from the process heap
//! (measured: `HeapValidate` passes on the real `GetEnvironmentStringsW` block), where the sim's
//! blocks are allocated too. Calls a system library makes internally (`GetTempPathW` reading
//! `TMP`, path resolution reading the `=C:` drive directories, `CreateProcessW` searching `PATH`
//! for a command line without an application name) read the real process environment.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::AtomicUsize;

use windows_sys::Win32::Foundation::SetLastError;
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapAlloc};

use crate::domain::dispatch_env;
use crate::env::windows::{
    CrtChar, ENOMEM, ERANGE, MAX_ENV, STATUS_BUFFER_TOO_SMALL, WinEnv, from_ansi, to_ansi,
};
use crate::hooks::{Hook, hook, original};

static GET_ENVIRONMENT_VARIABLE_W: AtomicUsize = AtomicUsize::new(0);
static GET_ENVIRONMENT_VARIABLE_A: AtomicUsize = AtomicUsize::new(0);
static SET_ENVIRONMENT_VARIABLE_W: AtomicUsize = AtomicUsize::new(0);
static SET_ENVIRONMENT_VARIABLE_A: AtomicUsize = AtomicUsize::new(0);
static GET_ENVIRONMENT_STRINGS_W: AtomicUsize = AtomicUsize::new(0);
static GET_ENVIRONMENT_STRINGS_A: AtomicUsize = AtomicUsize::new(0);
static GET_ENVIRONMENT_STRINGS: AtomicUsize = AtomicUsize::new(0);
static SET_ENVIRONMENT_STRINGS_W: AtomicUsize = AtomicUsize::new(0);
static EXPAND_ENVIRONMENT_STRINGS_W: AtomicUsize = AtomicUsize::new(0);
static EXPAND_ENVIRONMENT_STRINGS_A: AtomicUsize = AtomicUsize::new(0);
static CREATE_PROCESS_W: AtomicUsize = AtomicUsize::new(0);
static CREATE_PROCESS_A: AtomicUsize = AtomicUsize::new(0);
static CRT_GETENV: AtomicUsize = AtomicUsize::new(0);
static CRT_WGETENV: AtomicUsize = AtomicUsize::new(0);
static CRT_GETENV_S: AtomicUsize = AtomicUsize::new(0);
static CRT_WGETENV_S: AtomicUsize = AtomicUsize::new(0);
static CRT_DUPENV_S: AtomicUsize = AtomicUsize::new(0);
static CRT_WDUPENV_S: AtomicUsize = AtomicUsize::new(0);
static CRT_PUTENV: AtomicUsize = AtomicUsize::new(0);
static CRT_WPUTENV: AtomicUsize = AtomicUsize::new(0);
static CRT_PUTENV_S: AtomicUsize = AtomicUsize::new(0);
static CRT_WPUTENV_S: AtomicUsize = AtomicUsize::new(0);

// The UCRT exports its environment functions through this API set (Microsoft Learn: getenv,
// _wgetenv, "Requirements"; the import name binaries linked against the UCRT carry).
const CRT_ENVIRONMENT: &str = "api-ms-win-crt-environment-l1-1-0.dll";

/// winbase.h `CREATE_UNICODE_ENVIRONMENT`: the environment passed is UTF-16
/// ([Microsoft Learn: Process Creation Flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)).
const CREATE_UNICODE_ENVIRONMENT: u32 = 0x400;
/// winerror.h codes the ANSI calls fail with, measured: `ERROR_NOT_ENOUGH_MEMORY` (8) from
/// `GetEnvironmentVariableA` for a value of 32767 units or more, `ERROR_GEN_FAILURE` (31) from
/// `ExpandEnvironmentStringsA` for an expansion that long, and from `SetEnvironmentVariableA`
/// `ERROR_INVALID_PARAMETER` (87) for a string of 32767 bytes or more and
/// `ERROR_FILENAME_EXCED_RANGE` (206) for one of 65535 or more.
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_GEN_FAILURE: u32 = 31;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_FILENAME_EXCED_RANGE: u32 = 206;
/// The longest string a `UNICODE_STRING` holds with its terminator, in units (`USHORT` bytes).
const UNICODE_STRING_MAX_CHARS: usize = 32767;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn _errno() -> *mut c_int;
}

pub(super) fn hooks() -> Vec<Hook> {
    vec![
        hook!(
            "GetEnvironmentVariableW",
            "kernel32.dll",
            get_environment_variable_w,
            GET_ENVIRONMENT_VARIABLE_W
        ),
        hook!(
            "GetEnvironmentVariableA",
            "kernel32.dll",
            get_environment_variable_a,
            GET_ENVIRONMENT_VARIABLE_A
        ),
        hook!(
            "SetEnvironmentVariableW",
            "kernel32.dll",
            set_environment_variable_w,
            SET_ENVIRONMENT_VARIABLE_W
        ),
        hook!(
            "SetEnvironmentVariableA",
            "kernel32.dll",
            set_environment_variable_a,
            SET_ENVIRONMENT_VARIABLE_A
        ),
        hook!(
            "GetEnvironmentStringsW",
            "kernel32.dll",
            get_environment_strings_w,
            GET_ENVIRONMENT_STRINGS_W
        ),
        hook!(
            "GetEnvironmentStringsA",
            "kernel32.dll",
            get_environment_strings_a,
            GET_ENVIRONMENT_STRINGS_A
        ),
        hook!(
            "GetEnvironmentStrings",
            "kernel32.dll",
            get_environment_strings,
            GET_ENVIRONMENT_STRINGS
        ),
        hook!(
            "SetEnvironmentStringsW",
            "kernel32.dll",
            set_environment_strings_w,
            SET_ENVIRONMENT_STRINGS_W
        ),
        hook!(
            "ExpandEnvironmentStringsW",
            "kernel32.dll",
            expand_environment_strings_w,
            EXPAND_ENVIRONMENT_STRINGS_W
        ),
        hook!(
            "ExpandEnvironmentStringsA",
            "kernel32.dll",
            expand_environment_strings_a,
            EXPAND_ENVIRONMENT_STRINGS_A
        ),
        hook!(
            "CreateProcessW",
            "kernel32.dll",
            create_process_w,
            CREATE_PROCESS_W
        ),
        hook!(
            "CreateProcessA",
            "kernel32.dll",
            create_process_a,
            CREATE_PROCESS_A
        ),
        Hook {
            module: CRT_ENVIRONMENT,
            ..hook!("getenv", crt_getenv, CRT_GETENV)
        },
        Hook {
            module: CRT_ENVIRONMENT,
            ..hook!("_wgetenv", crt_wgetenv, CRT_WGETENV)
        },
        Hook {
            module: CRT_ENVIRONMENT,
            ..hook!("getenv_s", crt_getenv_s, CRT_GETENV_S)
        },
        Hook {
            module: CRT_ENVIRONMENT,
            ..hook!("_wgetenv_s", crt_wgetenv_s, CRT_WGETENV_S)
        },
        Hook {
            module: CRT_ENVIRONMENT,
            ..hook!("_dupenv_s", crt_dupenv_s, CRT_DUPENV_S)
        },
        Hook {
            module: CRT_ENVIRONMENT,
            ..hook!("_wdupenv_s", crt_wdupenv_s, CRT_WDUPENV_S)
        },
        Hook {
            module: CRT_ENVIRONMENT,
            ..hook!("_putenv", crt_putenv, CRT_PUTENV)
        },
        Hook {
            module: CRT_ENVIRONMENT,
            ..hook!("_wputenv", crt_wputenv, CRT_WPUTENV)
        },
        Hook {
            module: CRT_ENVIRONMENT,
            ..hook!("_putenv_s", crt_putenv_s, CRT_PUTENV_S)
        },
        Hook {
            module: CRT_ENVIRONMENT,
            ..hook!("_wputenv_s", crt_wputenv_s, CRT_WPUTENV_S)
        },
    ]
}

/// Runs `op` on the calling thread's [`WinEnv`], if its domain has one.
fn with_env<T>(op: impl FnOnce(&WinEnv) -> T) -> Option<T> {
    dispatch_env(|env| env.windows().map(op)).flatten()
}

/// A Win32 result: `Err(code)` returns 0 with `code` as the thread's last error.
fn finish(result: Result<u32, u32>) -> u32 {
    result.unwrap_or_else(|code| {
        unsafe { SetLastError(code) };
        0
    })
}

/// kernelbase's reading of an `Rtl*` length result: the length on success, and on
/// `STATUS_BUFFER_TOO_SMALL` too (the size needed), the status as a Win32 error otherwise.
fn length_result(status: i32, length: usize) -> Result<u32, u32> {
    if status >= 0 || status == STATUS_BUFFER_TOO_SMALL {
        Ok(length as u32)
    } else {
        // SAFETY: a pure status translation.
        Err(unsafe { RtlNtStatusToDosError(status) })
    }
}

/// The units of a NUL-terminated string, without the NUL; empty for null.
///
/// # Safety
/// `at` is null or a NUL-terminated string that outlives the slice.
unsafe fn units<'a, C: Copy + Default + PartialEq>(at: *const C) -> &'a [C] {
    if at.is_null() {
        return &[];
    }
    let mut length = 0;
    // SAFETY: the caller's terminated string.
    unsafe {
        while *at.add(length) != C::default() {
            length += 1;
        }
        std::slice::from_raw_parts(at, length)
    }
}

/// An ANSI argument as kernelbase converts it for the `W` call: `ERROR_FILENAME_EXCED_RANGE` from
/// 65535 bytes, `ERROR_INVALID_PARAMETER` from 32767 (its UTF-16 form no longer fits a
/// `UNICODE_STRING`).
fn ansi_argument(bytes: &[u8]) -> Result<Vec<u16>, u32> {
    match bytes.len() {
        65535.. => Err(ERROR_FILENAME_EXCED_RANGE),
        UNICODE_STRING_MAX_CHARS.. => Err(ERROR_INVALID_PARAMETER),
        _ => Ok(from_ansi(bytes)),
    }
}

/// A copy of `units` on the process heap, where `FreeEnvironmentStrings*` frees it.
fn heap_copy<C: Copy>(units: &[C]) -> *mut C {
    // SAFETY: the process heap; the block holds `units.len()` elements.
    unsafe {
        let block = HeapAlloc(GetProcessHeap(), 0, size_of_val(units)).cast::<C>();
        if !block.is_null() {
            std::ptr::copy_nonoverlapping(units.as_ptr(), block, units.len());
        }
        block
    }
}

/// `GetEnvironmentVariableW`: the value's length on success; the size needed, NUL included, when
/// `size` is too small, a NUL then written at `buffer[0]` if `size` is not 0; 0 with
/// `ERROR_ENVVAR_NOT_FOUND` for an unset name. Names compare without regard to case; an empty
/// name, a null one, and one with `=` past its first character are never set. The last error is
/// left alone on success. All measured to match `RtlQueryEnvironmentVariable`, which answers here.
unsafe extern "system" fn get_environment_variable_w(
    name: *const u16,
    buffer: *mut u16,
    size: u32,
) -> u32 {
    // SAFETY: the caller's name.
    let served = with_env(|env| {
        let (status, length) = env.query(unsafe { units(name) }, buffer, size as usize);
        length_result(status, length)
    });
    match served {
        Some(result) => finish(result),
        // SAFETY: the original GetEnvironmentVariableW and the caller's arguments.
        None => unsafe {
            original::<unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32>(
                &GET_ENVIRONMENT_VARIABLE_W,
            )(name, buffer, size)
        },
    }
}

/// `GetEnvironmentVariableA`, measured: the value in the ANSI code page and its length when it
/// fits with its NUL, else its size with the NUL and nothing written; 0 with `ERROR_ENVVAR_NOT_FOUND`
/// for an unset name, and with `ERROR_NOT_ENOUGH_MEMORY` for a value of 32767 units or more,
/// whatever `size` is.
unsafe extern "system" fn get_environment_variable_a(
    name: *const u8,
    buffer: *mut u8,
    size: u32,
) -> u32 {
    // SAFETY: the caller's name.
    let served = with_env(|env| {
        let name = ansi_argument(unsafe { units(name) })?;
        let value = env.value(&name).ok_or_else(|| {
            // SAFETY: a pure status translation of STATUS_VARIABLE_NOT_FOUND.
            unsafe { RtlNtStatusToDosError(0xC000_0100_u32 as i32) }
        })?;
        if value.len() >= UNICODE_STRING_MAX_CHARS {
            return Err(ERROR_NOT_ENOUGH_MEMORY);
        }
        Ok(to_ansi(&value))
    });
    let Some(result) = served else {
        // SAFETY: the original GetEnvironmentVariableA and the caller's arguments.
        return unsafe {
            original::<unsafe extern "system" fn(*const u8, *mut u8, u32) -> u32>(
                &GET_ENVIRONMENT_VARIABLE_A,
            )(name, buffer, size)
        };
    };
    finish(result.map(|value| {
        if value.len() < size as usize {
            // SAFETY: the caller's buffer holds `size` bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(value.as_ptr(), buffer, value.len());
                *buffer.add(value.len()) = 0;
            }
            value.len() as u32
        } else {
            value.len() as u32 + 1
        }
    }))
}

/// `SetEnvironmentVariableW`: a null `value` removes the variable, which succeeds when it is not
/// set; an empty name or one with `=` past its first character fails with
/// `ERROR_INVALID_PARAMETER`. Values have no length limit (measured with 100000 units). A null
/// name goes to the real function, which faults on it.
unsafe extern "system" fn set_environment_variable_w(name: *const u16, value: *const u16) -> i32 {
    if !name.is_null() {
        // SAFETY: the caller's strings.
        let served = with_env(|env| unsafe {
            let value = (!value.is_null()).then(|| units(value));
            env.set(units(name), value).map(|()| 1)
        });
        if let Some(result) = served {
            return finish(result) as i32;
        }
    }
    // SAFETY: the original SetEnvironmentVariableW and the caller's arguments.
    unsafe {
        original::<unsafe extern "system" fn(*const u16, *const u16) -> i32>(
            &SET_ENVIRONMENT_VARIABLE_W,
        )(name, value)
    }
}

/// `SetEnvironmentVariableA`: the strings from the ANSI code page, then as
/// [`set_environment_variable_w`].
unsafe extern "system" fn set_environment_variable_a(name: *const u8, value: *const u8) -> i32 {
    if !name.is_null() {
        // SAFETY: the caller's strings.
        let served = with_env(|env| unsafe {
            let name = ansi_argument(units(name))?;
            let value = match value.is_null() {
                true => None,
                false => Some(ansi_argument(units(value))?),
            };
            env.set(&name, value.as_deref()).map(|()| 1)
        });
        if let Some(result) = served {
            return finish(result) as i32;
        }
    }
    // SAFETY: the original SetEnvironmentVariableA and the caller's arguments.
    unsafe {
        original::<unsafe extern "system" fn(*const u8, *const u8) -> i32>(
            &SET_ENVIRONMENT_VARIABLE_A,
        )(name, value)
    }
}

/// `GetEnvironmentStringsW`: a copy of the block on the process heap, for
/// `FreeEnvironmentStringsW` to free.
unsafe extern "system" fn get_environment_strings_w() -> *mut u16 {
    match with_env(WinEnv::block) {
        Some(block) => heap_copy(&block),
        // SAFETY: the original GetEnvironmentStringsW.
        None => unsafe {
            original::<unsafe extern "system" fn() -> *mut u16>(&GET_ENVIRONMENT_STRINGS_W)()
        },
    }
}

/// The block in the ANSI code page, as `GetEnvironmentStringsA` returns it (measured: a fresh
/// heap block each call, characters the code page lacks as `?`).
fn ansi_block() -> Option<*mut u8> {
    with_env(|env| heap_copy(&to_ansi(&env.block())))
}

/// `GetEnvironmentStringsA`; see [`ansi_block`].
unsafe extern "system" fn get_environment_strings_a() -> *mut u8 {
    ansi_block().unwrap_or_else(|| {
        // SAFETY: the original GetEnvironmentStringsA.
        unsafe { original::<unsafe extern "system" fn() -> *mut u8>(&GET_ENVIRONMENT_STRINGS_A)() }
    })
}

/// `GetEnvironmentStrings`, kernel32's other name for the ANSI block; see [`ansi_block`].
unsafe extern "system" fn get_environment_strings() -> *mut u8 {
    ansi_block().unwrap_or_else(|| {
        // SAFETY: the original GetEnvironmentStrings.
        unsafe { original::<unsafe extern "system" fn() -> *mut u8>(&GET_ENVIRONMENT_STRINGS)() }
    })
}

/// `SetEnvironmentStringsW`: replaces the block with `block`'s entries, as given; see
/// [`WinEnv`]. A null block goes to the real function.
unsafe extern "system" fn set_environment_strings_w(block: *const u16) -> i32 {
    if !block.is_null() {
        // SAFETY: the caller's block: terminated entries ended by an empty one.
        let served = with_env(|env| unsafe {
            let mut entries = Vec::new();
            let mut at = block;
            loop {
                let entry = units(at);
                if entry.is_empty() {
                    break;
                }
                at = at.add(entry.len() + 1);
                entries.push(entry.to_vec());
            }
            env.replace(entries).map(|()| 1)
        });
        if let Some(result) = served {
            return finish(result) as i32;
        }
    }
    // SAFETY: the original SetEnvironmentStringsW and the caller's block.
    unsafe {
        original::<unsafe extern "system" fn(*const u16) -> i32>(&SET_ENVIRONMENT_STRINGS_W)(block)
    }
}

/// `ExpandEnvironmentStringsW`: the expansion's size with its NUL, whether or not it fits; a
/// buffer too small holds what `RtlExpandEnvironmentStrings` fit in it (measured identical), and
/// the last error is left alone. `%name%` is replaced by a set variable's value (names compare
/// without regard to case) and left as written otherwise. A null source goes to the real function.
unsafe extern "system" fn expand_environment_strings_w(
    source: *const u16,
    destination: *mut u16,
    size: u32,
) -> u32 {
    if !source.is_null() {
        // SAFETY: the caller's source.
        let served = with_env(|env| {
            let (status, length) = env.expand(unsafe { units(source) }, destination, size as usize);
            length_result(status, length)
        });
        if let Some(result) = served {
            return finish(result);
        }
    }
    // SAFETY: the original ExpandEnvironmentStringsW and the caller's arguments.
    unsafe {
        original::<unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32>(
            &EXPAND_ENVIRONMENT_STRINGS_W,
        )(source, destination, size)
    }
}

/// `ExpandEnvironmentStringsA`, measured: `destination[0]` is set to NUL first, even when `size`
/// is 0. The expansion is made in UTF-16 into room for `min(size, 32765) - 1` units with a NUL; if
/// it fits, it is copied out in the ANSI code page and its size with the NUL returned, and
/// otherwise its UTF-16 size with the NUL plus one is returned and nothing more written (so an
/// ANSI caller needs a buffer one larger than the result, as
/// [Microsoft Learn: ExpandEnvironmentStringsA](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-expandenvironmentstringsa)
/// warns). An expansion of 32767 units or more fails with `ERROR_GEN_FAILURE`.
unsafe extern "system" fn expand_environment_strings_a(
    source: *const u8,
    destination: *mut u8,
    size: u32,
) -> u32 {
    if !source.is_null() {
        // SAFETY: the caller's source.
        let served = with_env(|env| {
            let source = ansi_argument(unsafe { units(source) })?;
            let (_, needed) = env.expand(&source, std::ptr::null_mut(), 0);
            let mut expanded = vec![0u16; needed];
            let (status, length) = env.expand(&source, expanded.as_mut_ptr(), needed);
            length_result(status, length)?;
            expanded.truncate(length.saturating_sub(1));
            if expanded.len() >= UNICODE_STRING_MAX_CHARS {
                return Err(ERROR_GEN_FAILURE);
            }
            Ok(expanded)
        });
        if let Some(result) = served {
            if !destination.is_null() {
                // SAFETY: the caller's buffer, whose first byte is written even for a size of 0.
                unsafe { *destination = 0 };
            }
            return finish(result.map(|expanded| {
                let room = (size as usize).min(UNICODE_STRING_MAX_CHARS - 2).saturating_sub(1);
                if expanded.len() + 1 > room {
                    return expanded.len() as u32 + 2;
                }
                let ansi = to_ansi(&expanded);
                if ansi.len() + 1 > size as usize {
                    return ansi.len() as u32 + 1;
                }
                // SAFETY: the caller's buffer holds `size` bytes.
                unsafe {
                    std::ptr::copy_nonoverlapping(ansi.as_ptr(), destination, ansi.len());
                    *destination.add(ansi.len()) = 0;
                }
                ansi.len() as u32 + 1
            }));
        }
    }
    // SAFETY: the original ExpandEnvironmentStringsA and the caller's arguments.
    unsafe {
        original::<unsafe extern "system" fn(*const u8, *mut u8, u32) -> u32>(
            &EXPAND_ENVIRONMENT_STRINGS_A,
        )(source, destination, size)
    }
}

type CreateProcess<C> = unsafe extern "system" fn(
    *const C,
    *mut C,
    *const c_void,
    *const c_void,
    i32,
    u32,
    *const c_void,
    *const C,
    *const c_void,
    *mut c_void,
) -> i32;

/// The sim's block for a child about to be created with `environment`, when that is null (the
/// child would inherit the real one) and the caller's domain has a [`WinEnv`].
fn child_block(environment: *const c_void) -> Option<Vec<u16>> {
    if environment.is_null() {
        with_env(WinEnv::block)
    } else {
        None
    }
}

/// `CreateProcessW`: a child given no environment of its own inherits the caller's
/// ([Microsoft Learn: CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw),
/// `lpEnvironment`), so it is handed the sim's block.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn create_process_w(
    application: *const u16,
    command_line: *mut u16,
    process_attributes: *const c_void,
    thread_attributes: *const c_void,
    inherit_handles: i32,
    flags: u32,
    environment: *const c_void,
    directory: *const u16,
    startup: *const c_void,
    information: *mut c_void,
) -> i32 {
    let block = child_block(environment);
    let (flags, environment) = match &block {
        Some(block) => (flags | CREATE_UNICODE_ENVIRONMENT, block.as_ptr().cast()),
        None => (flags, environment),
    };
    // SAFETY: the original CreateProcessW; the caller's arguments and a terminated block.
    unsafe {
        original::<CreateProcess<u16>>(&CREATE_PROCESS_W)(
            application,
            command_line,
            process_attributes,
            thread_attributes,
            inherit_handles,
            flags,
            environment,
            directory,
            startup,
            information,
        )
    }
}

/// `CreateProcessA`, as [`create_process_w`]; the flag marks the block UTF-16 for it too.
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn create_process_a(
    application: *const u8,
    command_line: *mut u8,
    process_attributes: *const c_void,
    thread_attributes: *const c_void,
    inherit_handles: i32,
    flags: u32,
    environment: *const c_void,
    directory: *const u8,
    startup: *const c_void,
    information: *mut c_void,
) -> i32 {
    let block = child_block(environment);
    let (flags, environment) = match &block {
        Some(block) => (flags | CREATE_UNICODE_ENVIRONMENT, block.as_ptr().cast()),
        None => (flags, environment),
    };
    // SAFETY: the original CreateProcessA; the caller's arguments and a terminated block.
    unsafe {
        original::<CreateProcess<u8>>(&CREATE_PROCESS_A)(
            application,
            command_line,
            process_attributes,
            thread_attributes,
            inherit_handles,
            flags,
            environment,
            directory,
            startup,
            information,
        )
    }
}

fn set_errno(value: c_int) {
    // SAFETY: the UCRT's per-thread errno.
    unsafe { *_errno() = value };
}

/// Whether the UCRT rejects `name` through its invalid-parameter handler before reading anything:
/// a null name, or one of `_MAX_ENV` characters or more. Such calls go to the real function, which
/// does exactly that.
///
/// # Safety
/// `name` is null or a NUL-terminated string.
unsafe fn invalid_name<C: Copy + Default + PartialEq>(name: *const C) -> bool {
    // SAFETY: the caller's string.
    name.is_null() || unsafe { units(name) }.len() >= MAX_ENV
}

/// `getenv`: the value in the C runtime's narrow table, which starts as the sim's environment and
/// follows `_putenv` but not `SetEnvironmentVariable`; see [`WinEnv`].
unsafe extern "C" fn crt_getenv(name: *const c_char) -> *mut c_char {
    // SAFETY: the caller's name, checked non-null.
    if !unsafe { invalid_name(name) }
        && let Some(value) = dispatch_env(|env| unsafe { env.getenv(name) })
    {
        return value;
    }
    // SAFETY: the original getenv.
    unsafe { original::<unsafe extern "C" fn(*const c_char) -> *mut c_char>(&CRT_GETENV)(name) }
}

/// `_wgetenv`: as [`crt_getenv`] from the wide table, which is copied from the sim's block when
/// first used.
unsafe extern "C" fn crt_wgetenv(name: *const u16) -> *mut u16 {
    // SAFETY: the caller's name, checked non-null.
    if !unsafe { invalid_name(name) }
        && let Some(value) = with_env(|env| env.crt_get(unsafe { units(name) }))
    {
        return value;
    }
    // SAFETY: the original _wgetenv.
    unsafe { original::<unsafe extern "C" fn(*const u16) -> *mut u16>(&CRT_WGETENV)(name) }
}

/// `getenv_s`/`_wgetenv_s`, measured: `*required` is the value's size with its NUL (0 when unset,
/// or for a null name), `buffer[0]` is NUL first, a value that does not fit returns `ERANGE`
/// without setting `errno`, and a null `buffer` with a `count` of 0 only asks the size. A null
/// `required`, or a buffer and count that disagree, go to the real function, whose
/// invalid-parameter handler rejects them.
unsafe fn getenv_s<C: CrtChar>(
    required: *mut usize,
    buffer: *mut C,
    count: usize,
    name: *const C,
) -> Option<c_int> {
    if required.is_null() || buffer.is_null() != (count == 0) {
        return None;
    }
    // SAFETY: the caller's name.
    let value = with_env(|env| env.crt_value(unsafe { units(name) }))?;
    // SAFETY: the caller's `required`, and `buffer` of `count` elements.
    unsafe {
        *required = 0;
        if !buffer.is_null() {
            *buffer = C::default();
        }
        let Some(value) = value else { return Some(0) };
        *required = value.len() + 1;
        if count == 0 {
            return Some(0);
        }
        if value.len() + 1 > count {
            return Some(ERANGE);
        }
        std::ptr::copy_nonoverlapping(value.as_ptr(), buffer, value.len());
        *buffer.add(value.len()) = C::default();
    }
    Some(0)
}

/// `getenv_s`; see [`getenv_s`].
unsafe extern "C" fn crt_getenv_s(
    required: *mut usize,
    buffer: *mut c_char,
    count: usize,
    name: *const c_char,
) -> c_int {
    // SAFETY: the caller's arguments.
    unsafe { getenv_s(required, buffer.cast::<u8>(), count, name.cast()) }.unwrap_or_else(|| {
        // SAFETY: the original getenv_s and the caller's arguments.
        unsafe {
            original::<unsafe extern "C" fn(*mut usize, *mut c_char, usize, *const c_char) -> c_int>(
                &CRT_GETENV_S,
            )(required, buffer, count, name)
        }
    })
}

/// `_wgetenv_s`; see [`getenv_s`].
unsafe extern "C" fn crt_wgetenv_s(
    required: *mut usize,
    buffer: *mut u16,
    count: usize,
    name: *const u16,
) -> c_int {
    // SAFETY: the caller's arguments.
    unsafe { getenv_s(required, buffer, count, name) }.unwrap_or_else(|| {
        // SAFETY: the original _wgetenv_s and the caller's arguments.
        unsafe {
            original::<unsafe extern "C" fn(*mut usize, *mut u16, usize, *const u16) -> c_int>(
                &CRT_WGETENV_S,
            )(required, buffer, count, name)
        }
    })
}

/// `_dupenv_s`/`_wdupenv_s`, measured: a copy of the value from the C runtime's `malloc`, for the
/// caller to `free`, and its size in characters with the NUL; null and 0 when unset. A null
/// `buffer` or name goes to the real function, whose invalid-parameter handler rejects it.
unsafe fn dupenv_s<C: CrtChar>(
    buffer: *mut *mut C,
    count: *mut usize,
    name: *const C,
) -> Option<c_int> {
    if buffer.is_null() || name.is_null() {
        return None;
    }
    // SAFETY: the caller's name.
    let value = with_env(|env| env.crt_value(unsafe { units(name) }))?;
    // SAFETY: the caller's pointers; the copy holds the value and its NUL.
    unsafe {
        *buffer = std::ptr::null_mut();
        if !count.is_null() {
            *count = 0;
        }
        let Some(value) = value else { return Some(0) };
        let copy = malloc((value.len() + 1) * size_of::<C>()).cast::<C>();
        if copy.is_null() {
            set_errno(ENOMEM);
            return Some(ENOMEM);
        }
        std::ptr::copy_nonoverlapping(value.as_ptr(), copy, value.len());
        *copy.add(value.len()) = C::default();
        *buffer = copy;
        if !count.is_null() {
            *count = value.len() + 1;
        }
    }
    Some(0)
}

/// `_dupenv_s`; see [`dupenv_s`].
unsafe extern "C" fn crt_dupenv_s(
    buffer: *mut *mut c_char,
    count: *mut usize,
    name: *const c_char,
) -> c_int {
    // SAFETY: the caller's arguments.
    unsafe { dupenv_s(buffer.cast::<*mut u8>(), count, name.cast()) }.unwrap_or_else(|| {
        // SAFETY: the original _dupenv_s and the caller's arguments.
        unsafe {
            original::<unsafe extern "C" fn(*mut *mut c_char, *mut usize, *const c_char) -> c_int>(
                &CRT_DUPENV_S,
            )(buffer, count, name)
        }
    })
}

/// `_wdupenv_s`; see [`dupenv_s`].
unsafe extern "C" fn crt_wdupenv_s(
    buffer: *mut *mut u16,
    count: *mut usize,
    name: *const u16,
) -> c_int {
    // SAFETY: the caller's arguments.
    unsafe { dupenv_s(buffer, count, name) }.unwrap_or_else(|| {
        // SAFETY: the original _wdupenv_s and the caller's arguments.
        unsafe {
            original::<unsafe extern "C" fn(*mut *mut u16, *mut usize, *const u16) -> c_int>(
                &CRT_WDUPENV_S,
            )(buffer, count, name)
        }
    })
}

/// `_putenv`/`_wputenv` of `option`, `name=value`: 0, or -1 with `errno` set. Measured: no `=`, or
/// one first, fails with `EINVAL`; an empty value removes the variable, from the tables and the
/// block; names match without regard to ASCII case. A null option, or a name or value of
/// `_MAX_ENV` characters or more, goes to the real function, whose invalid-parameter handler
/// rejects it.
fn putenv<C: CrtChar>(option: &[C]) -> Option<c_int> {
    if let Some(equals) = option.iter().position(|&c| c == C::EQUALS)
        && (equals >= MAX_ENV || option.len() - equals > MAX_ENV)
    {
        return None;
    }
    let result = with_env(|env| env.crt_put(option))?;
    Some(match result {
        Ok(()) => 0,
        Err(errno) => {
            set_errno(errno);
            -1
        }
    })
}

/// `_putenv`; see [`putenv`].
unsafe extern "C" fn crt_putenv(option: *const c_char) -> c_int {
    // SAFETY: the caller's option, checked non-null.
    if !option.is_null()
        && let Some(r) = putenv(unsafe { units(option.cast::<u8>()) })
    {
        return r;
    }
    // SAFETY: the original _putenv.
    unsafe { original::<unsafe extern "C" fn(*const c_char) -> c_int>(&CRT_PUTENV)(option) }
}

/// `_wputenv`; see [`putenv`].
unsafe extern "C" fn crt_wputenv(option: *const u16) -> c_int {
    // SAFETY: the caller's option, checked non-null.
    if !option.is_null()
        && let Some(r) = putenv(unsafe { units(option) })
    {
        return r;
    }
    // SAFETY: the original _wputenv.
    unsafe { original::<unsafe extern "C" fn(*const u16) -> c_int>(&CRT_WPUTENV)(option) }
}

/// `_putenv_s(name, value)`/`_wputenv_s`: [`putenv`] of `name=value`, returning 0 or the `errno`
/// it set (measured: an empty name gives `EINVAL`, and a name with `=` in it sets the part before
/// the `=` to the rest). A null name or value goes to the real function.
///
/// # Safety
/// `name` and `value` are null or NUL-terminated.
unsafe fn putenv_s<C: CrtChar>(
    name: *const C,
    value: *const C,
) -> Option<c_int> {
    if name.is_null() || value.is_null() {
        return None;
    }
    // SAFETY: the caller's strings.
    let (name, value) = unsafe { (units(name), units(value)) };
    if name.len() >= MAX_ENV || value.len() >= MAX_ENV {
        return None;
    }
    let mut option = name.to_vec();
    option.push(C::EQUALS);
    option.extend_from_slice(value);
    let result = with_env(|env| env.crt_put(&option))?;
    Some(match result {
        Ok(()) => 0,
        Err(errno) => {
            set_errno(errno);
            errno
        }
    })
}

/// `_putenv_s`; see [`putenv_s`].
unsafe extern "C" fn crt_putenv_s(name: *const c_char, value: *const c_char) -> c_int {
    // SAFETY: the caller's strings.
    unsafe { putenv_s(name.cast::<u8>(), value.cast()) }.unwrap_or_else(|| {
        // SAFETY: the original _putenv_s and the caller's arguments.
        unsafe {
            original::<unsafe extern "C" fn(*const c_char, *const c_char) -> c_int>(&CRT_PUTENV_S)(
                name, value,
            )
        }
    })
}

/// `_wputenv_s`; see [`putenv_s`].
unsafe extern "C" fn crt_wputenv_s(name: *const u16, value: *const u16) -> c_int {
    // SAFETY: the caller's strings.
    unsafe { putenv_s(name, value) }.unwrap_or_else(|| {
        // SAFETY: the original _wputenv_s and the caller's arguments.
        unsafe {
            original::<unsafe extern "C" fn(*const u16, *const u16) -> c_int>(&CRT_WPUTENV_S)(
                name, value,
            )
        }
    })
}
