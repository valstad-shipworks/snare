//! [`WinEnv`]: a Windows process environment held apart from the real one — the environment block
//! the Win32 calls read and write, and the C runtime's own copies of it.
//!
//! The block is kept as the system keeps the real one, a run of NUL-terminated `name=value`
//! entries ended by an empty one, and the ntdll routines kernelbase answers from read it in place:
//! `GetEnvironmentVariableW` reports exactly what `RtlQueryEnvironmentVariable` does and
//! `ExpandEnvironmentStringsW` exactly what `RtlExpandEnvironmentStrings` does (status, length and
//! every buffer element, measured side by side for found, empty, missing, case-folded and
//! `=`-containing names, and for expansions of present, empty, missing and adjacent variables and
//! bare `%` signs into buffers of 0 to 30 elements, on Windows 11 ARM64). Changes are made here
//! as `SetEnvironmentVariableW` makes them, measured on the same machine.
//!
//! The UCRT keeps its own tables of the environment, one of narrow strings and one of wide, which
//! `getenv`, `_putenv` and their kin use instead of the block ([Microsoft Learn: getenv, _wgetenv](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/getenv-wgetenv),
//! "getenv operates only on the data structures accessible to the run-time library and not on the
//! environment 'segment' created for the process by the operating system"). A program entered at
//! `main`, as every Rust program is, has the narrow table from start-up; the wide one is copied
//! from the block the first time it is used. Both are modelled the same way here, the sim's start
//! standing in for the process's: measured, a variable `SetEnvironmentVariableW` adds after
//! start-up is missing from `getenv` but present in a first `_wgetenv`, and `_putenv` changes the
//! block and the tables that exist, never creating the other.

use std::ffi::{OsStr, c_char, c_int};
use std::os::windows::ffi::OsStrExt;
use std::sync::{Mutex, MutexGuard};

use windows_sys::Win32::Globalization::{CP_ACP, MultiByteToWideChar, WideCharToMultiByte};

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlQueryEnvironmentVariable(
        environment: *const u16,
        name: *const u16,
        name_length: usize,
        value: *mut u16,
        value_length: usize,
        return_length: *mut usize,
    ) -> i32;
    fn RtlExpandEnvironmentStrings(
        environment: *const u16,
        source: *const u16,
        source_length: usize,
        destination: *mut u16,
        destination_length: usize,
        return_length: *mut usize,
    ) -> i32;
    fn RtlCompareUnicodeStrings(
        string1: *const u16,
        length1: usize,
        string2: *const u16,
        length2: usize,
        case_insensitive: u8,
    ) -> i32;
}

/// ntstatus.h `STATUS_BUFFER_TOO_SMALL`.
pub(crate) const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32 as i32;
/// winerror.h `ERROR_INVALID_PARAMETER`, what `SetEnvironmentVariableW` fails an empty name or one
/// with `=` past its first character with (measured).
pub(crate) const ERROR_INVALID_PARAMETER: u32 = 87;
/// errno.h `EINVAL`, `ERANGE`, `EILSEQ` and `ENOMEM` (UCRT values).
pub(crate) const EINVAL: c_int = 22;
pub(crate) const ERANGE: c_int = 34;
pub(crate) const EILSEQ: c_int = 42;
pub(crate) const ENOMEM: c_int = 12;

/// The UCRT's `_MAX_ENV` (stdlib.h): the longest name or value, plus its terminator, `_putenv` and
/// `getenv` accept; longer ones go to the invalid-parameter handler.
pub(crate) const MAX_ENV: usize = 32767;

/// A Windows process environment a sim serves in place of the real one: the environment block
/// behind `GetEnvironmentVariableW`, `SetEnvironmentVariableW`, `GetEnvironmentStringsW`,
/// `ExpandEnvironmentStringsW` and their ANSI forms, and the C runtime's narrow and wide tables
/// behind `getenv`, `_putenv` and their kin. Child processes created without an environment of
/// their own get the block.
///
/// Hand it to [`DomainBuilder::env`](crate::DomainBuilder::env); it is its own [`Env`](crate::Env).
pub struct WinEnv {
    state: Mutex<State>,
}

pub(crate) struct State {
    /// Each entry's units followed by its NUL; the block's final NUL is added when it is read.
    block: Vec<u16>,
    /// The UCRT's narrow table: `name=value` entries, each with its NUL, in table order.
    narrow: Vec<Box<[u8]>>,
    /// The UCRT's wide table, once something has used it.
    wide: Option<Vec<Box<[u16]>>>,
}

impl WinEnv {
    /// An environment holding `vars`, set in order (so a later duplicate, compared as Windows
    /// compares names, without regard to case, replaces the earlier value and keeps the earlier
    /// spelling). The C runtime's narrow table starts as a copy of it, as a process's does.
    ///
    /// # Panics
    /// If a name is empty or holds `=` past its first character, which `SetEnvironmentVariableW`
    /// rejects.
    #[track_caller]
    pub fn new<K: AsRef<OsStr>, V: AsRef<OsStr>>(vars: impl IntoIterator<Item = (K, V)>) -> Self {
        let mut state = State {
            block: Vec::new(),
            narrow: Vec::new(),
            wide: None,
        };
        for (name, value) in vars {
            let name: Vec<u16> = name.as_ref().encode_wide().collect();
            let value: Vec<u16> = value.as_ref().encode_wide().collect();
            assert!(
                state.set(&name, Some(&value)).is_ok(),
                "{:?} is not a Windows environment variable name",
                String::from_utf16_lossy(&name)
            );
        }
        state.narrow = state
            .entries()
            .filter(|entry| entry[0] != u16::from(b'='))
            .map(|entry| nul_terminated(&to_ansi(entry)))
            .collect();
        WinEnv {
            state: Mutex::new(state),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `RtlQueryEnvironmentVariable` on the block: its status and length.
    pub(crate) fn query(&self, name: &[u16], value: *mut u16, length: usize) -> (i32, usize) {
        let state = self.lock();
        let block = state.terminated();
        let mut returned = 0;
        // SAFETY: a terminated block, the caller's name, and its buffer of `length` units.
        let status = unsafe {
            RtlQueryEnvironmentVariable(
                block.as_ptr(),
                name.as_ptr(),
                name.len(),
                value,
                length,
                &mut returned,
            )
        };
        (status, returned)
    }

    /// The value of `name`, as `GetEnvironmentVariableW` would read it, if set.
    pub(crate) fn value(&self, name: &[u16]) -> Option<Vec<u16>> {
        let (status, length) = self.query(name, std::ptr::null_mut(), 0);
        if status != STATUS_BUFFER_TOO_SMALL {
            return (status >= 0).then(Vec::new);
        }
        let mut value = vec![0u16; length];
        let (status, length) = self.query(name, value.as_mut_ptr(), value.len());
        (status >= 0).then(|| {
            value.truncate(length);
            value
        })
    }

    /// `RtlExpandEnvironmentStrings` against the block: its status and length.
    pub(crate) fn expand(&self, source: &[u16], destination: *mut u16, length: usize) -> (i32, usize) {
        let state = self.lock();
        let block = state.terminated();
        let mut returned = 0;
        // SAFETY: a terminated block, the caller's source, and its buffer of `length` units.
        let status = unsafe {
            RtlExpandEnvironmentStrings(
                block.as_ptr(),
                source.as_ptr(),
                source.len(),
                destination,
                length,
                &mut returned,
            )
        };
        (status, returned)
    }

    /// `SetEnvironmentVariableW(name, value)`, `None` removing it: the Win32 error on failure.
    pub(crate) fn set(&self, name: &[u16], value: Option<&[u16]>) -> Result<(), u32> {
        self.lock().set(name, value)
    }

    /// The block as `GetEnvironmentStringsW` returns it, ended by an empty entry.
    pub fn block(&self) -> Vec<u16> {
        self.lock().terminated()
    }

    /// `SetEnvironmentStringsW`: replaces the block with `entries`, kept as given. Measured, an
    /// empty block, or an entry with no `=` past its first character, fails with
    /// `ERROR_INVALID_PARAMETER` and changes nothing; a repeated name is kept.
    pub(crate) fn replace(&self, entries: Vec<Vec<u16>>) -> Result<(), u32> {
        if entries.is_empty() || entries.iter().any(|entry| name_length(entry).is_none()) {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let mut state = self.lock();
        state.block.clear();
        for entry in entries {
            state.block.extend_from_slice(&entry);
            state.block.push(0);
        }
        Ok(())
    }

    /// The C runtime's `getenv` (or `_wgetenv`): a pointer to the value in its table, valid until
    /// that entry changes, or null. The UCRT matches a name to the first entry it begins without
    /// regard to ASCII case and that has `=` right after it, so a name with `=` in it can match
    /// part of a value (measured: `getenv("A=x")` is `"y"` once `A` is `x=y`).
    pub(crate) fn crt_get<C: CrtChar>(&self, name: &[C]) -> *mut C {
        let mut state = self.lock();
        let table = C::table(&mut state);
        match find_value(table, name) {
            Some((entry, start)) => table[entry][start..].as_mut_ptr(),
            None => std::ptr::null_mut(),
        }
    }

    /// The value `getenv_s` and `_dupenv_s` copy out, if set, without its NUL.
    pub(crate) fn crt_value<C: CrtChar>(&self, name: &[C]) -> Option<Vec<C>> {
        let mut state = self.lock();
        let table = C::table(&mut state);
        let (entry, start) = find_value(table, name)?;
        let entry = &table[entry];
        Some(entry[start..entry.len() - 1].to_vec())
    }

    /// `_putenv(option)` (or `_wputenv`), `option` being `name=value` without its NUL: `Err(errno)`
    /// on failure. An empty value removes the variable. The table of `option`'s width is changed
    /// (copied from the block first if it is the wide one and has not been used), then the block,
    /// then the other table if it exists.
    pub(crate) fn crt_put<C: CrtChar>(&self, option: &[C]) -> Result<(), c_int> {
        let equals = option
            .iter()
            .position(|&c| c == C::EQUALS)
            .filter(|&at| at > 0)
            .ok_or(EINVAL)?;
        let removal = equals + 1 == option.len();
        let mut state = self.lock();
        if !C::put(&mut state, option, equals) {
            return Ok(());
        }
        let (name, value) = (&option[..equals], &option[equals + 1..]);
        C::set_block(&mut state, name, (!removal).then_some(value)).map_err(|_| EILSEQ)?;
        C::put_other(&mut state, option);
        Ok(())
    }
}

impl State {
    /// The entries, without their NULs.
    fn entries(&self) -> impl Iterator<Item = &[u16]> {
        self.block.split_inclusive(|&c| c == 0).map(|entry| &entry[..entry.len() - 1])
    }

    fn terminated(&self) -> Vec<u16> {
        let mut block = self.block.clone();
        if block.is_empty() {
            block.push(0);
        }
        block.push(0);
        block
    }

    /// `RtlSetEnvironmentVar` on the block, as measured through `SetEnvironmentVariableW`: the
    /// entries are scanned in order for the first whose name compares, ignoring case, at or past
    /// `name`; an equal one has its value replaced (its spelling kept) or is removed, and a new
    /// variable goes before the greater one, or last. So a block kept in that order stays sorted,
    /// and `=`-prefixed names such as the `=C:` drive directories sort first.
    fn set(&mut self, name: &[u16], value: Option<&[u16]>) -> Result<(), u32> {
        if name.is_empty() || name[1..].contains(&u16::from(b'=')) {
            return Err(ERROR_INVALID_PARAMETER);
        }
        let mut start = 0;
        let mut position = self.block.len();
        let mut equal = false;
        for entry in self.entries() {
            let own = &entry[..name_length(entry).unwrap_or(entry.len())];
            // SAFETY: two slices and their lengths.
            let order = unsafe {
                RtlCompareUnicodeStrings(own.as_ptr(), own.len(), name.as_ptr(), name.len(), 1)
            };
            if order >= 0 {
                position = start;
                equal = order == 0;
                break;
            }
            start += entry.len() + 1;
        }
        let end = if equal {
            position
                + self.block[position..]
                    .iter()
                    .position(|&c| c == 0)
                    .map_or(0, |at| at + 1)
        } else {
            position
        };
        let replacement = match (equal, value) {
            (_, None) => Vec::new(),
            (true, Some(value)) => {
                let entry = &self.block[position..end - 1];
                let mut kept = entry[..name_length(entry).unwrap_or(entry.len())].to_vec();
                kept.push(u16::from(b'='));
                kept.extend_from_slice(value);
                kept.push(0);
                kept
            }
            (false, Some(value)) => {
                let mut entry = name.to_vec();
                entry.push(u16::from(b'='));
                entry.extend_from_slice(value);
                entry.push(0);
                entry
            }
        };
        self.block.splice(position..end, replacement);
        Ok(())
    }
}

/// The length of an entry's name: up to the first `=` past its first unit (so `=C:=C:\` is named
/// `=C:`), or `None` for an entry with no such `=`.
fn name_length(entry: &[u16]) -> Option<usize> {
    entry
        .get(1..)?
        .iter()
        .position(|&c| c == u16::from(b'='))
        .map(|at| at + 1)
}

/// The entry of a C runtime table `getenv(name)` reads and where its value starts.
fn find_value<C: CrtChar>(table: &[Box<[C]>], name: &[C]) -> Option<(usize, usize)> {
    table.iter().position(|entry| {
        let entry = &entry[..entry.len() - 1];
        entry.len() > name.len()
            && entry[name.len()] == C::EQUALS
            && C::eq_ignore_case(&entry[..name.len()], name)
    })
    .map(|at| (at, name.len() + 1))
}

fn nul_terminated<C: Copy + Default>(units: &[C]) -> Box<[C]> {
    units.iter().copied().chain([C::default()]).collect()
}

/// `units` in the ANSI code page, unmappable characters as its default character, as
/// `WideCharToMultiByte(CP_ACP, 0, ..)` converts them
/// ([Microsoft Learn: WideCharToMultiByte](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte)).
pub(crate) fn to_ansi(units: &[u16]) -> Vec<u8> {
    if units.is_empty() {
        return Vec::new();
    }
    let length = i32::try_from(units.len()).unwrap_or(i32::MAX);
    // SAFETY: a null output with size 0 asks for the size.
    let size = unsafe {
        WideCharToMultiByte(
            CP_ACP,
            0,
            units.as_ptr(),
            length,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    };
    let mut bytes = vec![0u8; size.max(0) as usize];
    // SAFETY: `bytes` holds `size` bytes.
    let written = unsafe {
        WideCharToMultiByte(
            CP_ACP,
            0,
            units.as_ptr(),
            length,
            bytes.as_mut_ptr(),
            size,
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    };
    bytes.truncate(written.max(0) as usize);
    bytes
}

/// `bytes` from the ANSI code page, as `MultiByteToWideChar(CP_ACP, 0, ..)` converts them
/// ([Microsoft Learn: MultiByteToWideChar](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar)).
pub(crate) fn from_ansi(bytes: &[u8]) -> Vec<u16> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let length = i32::try_from(bytes.len()).unwrap_or(i32::MAX);
    // SAFETY: a null output with size 0 asks for the size.
    let size =
        unsafe { MultiByteToWideChar(CP_ACP, 0, bytes.as_ptr(), length, std::ptr::null_mut(), 0) };
    let mut units = vec![0u16; size.max(0) as usize];
    // SAFETY: `units` holds `size` units.
    let written =
        unsafe { MultiByteToWideChar(CP_ACP, 0, bytes.as_ptr(), length, units.as_mut_ptr(), size) };
    units.truncate(written.max(0) as usize);
    units
}

/// The character width of one of the C runtime's tables: `u8` for the narrow one `getenv` reads
/// and `u16` for the wide one `_wgetenv` reads.
pub(crate) trait CrtChar: Copy + Default + Eq + 'static {
    const NUL: Self;
    const EQUALS: Self;

    /// This width's table, copied from the block, `=`-prefixed entries left out as the UCRT leaves
    /// them out, if it has not been used yet.
    fn table(state: &mut State) -> &mut Vec<Box<[Self]>>;

    /// `_strnicmp`/`_wcsnicmp` equality in the C locale: ASCII letters fold.
    fn eq_ignore_case(a: &[Self], b: &[Self]) -> bool;

    /// The block change `_putenv` makes through `SetEnvironmentVariableA` (or `W`).
    fn set_block(state: &mut State, name: &[Self], value: Option<&[Self]>) -> Result<(), u32>;

    /// The other width's table, if it exists, changed as `option` (converted) changes this one.
    fn put_other(state: &mut State, option: &[Self]);

    /// Changes this width's table as `_putenv(option)` does, `equals` being where the name ends:
    /// whether it changed. Removing a variable the table lacks changes nothing, and the UCRT then
    /// leaves the block and the other table alone too (measured: `_putenv("X=")` keeps an `X` only
    /// `SetEnvironmentVariableW` set).
    fn put(state: &mut State, option: &[Self], equals: usize) -> bool {
        let removal = equals + 1 == option.len();
        let table = Self::table(state);
        let name = &option[..equals];
        let found = table.iter().position(|entry| {
            entry.len() > name.len()
                && Self::eq_ignore_case(&entry[..name.len()], name)
                && (entry[name.len()] == Self::EQUALS || entry[name.len()] == Self::NUL)
        });
        match (found, removal) {
            (Some(at), true) => {
                table.remove(at);
            }
            (Some(at), false) => table[at] = nul_terminated(option),
            (None, true) => return false,
            (None, false) => table.push(nul_terminated(option)),
        }
        true
    }
}

impl CrtChar for u8 {
    const NUL: u8 = 0;
    const EQUALS: u8 = b'=';

    fn table(state: &mut State) -> &mut Vec<Box<[u8]>> {
        &mut state.narrow
    }

    fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
        a.eq_ignore_ascii_case(b)
    }

    fn set_block(state: &mut State, name: &[u8], value: Option<&[u8]>) -> Result<(), u32> {
        let value = value.map(from_ansi);
        state.set(&from_ansi(name), value.as_deref())
    }

    fn put_other(state: &mut State, option: &[u8]) {
        if state.wide.is_some() {
            let option = from_ansi(option);
            if let Some(equals) = option.iter().position(|&c| c == u16::EQUALS) {
                u16::put(state, &option, equals);
            }
        }
    }
}

impl CrtChar for u16 {
    const NUL: u16 = 0;
    const EQUALS: u16 = b'=' as u16;

    fn table(state: &mut State) -> &mut Vec<Box<[u16]>> {
        if state.wide.is_none() {
            let wide = state
                .entries()
                .filter(|entry| entry[0] != u16::EQUALS)
                .map(nul_terminated)
                .collect();
            state.wide = Some(wide);
        }
        state.wide.as_mut().unwrap()
    }

    fn eq_ignore_case(a: &[u16], b: &[u16]) -> bool {
        let fold = |c: u16| match c {
            0x41..=0x5a => c + 0x20,
            _ => c,
        };
        a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| fold(x) == fold(y))
    }

    fn set_block(state: &mut State, name: &[u16], value: Option<&[u16]>) -> Result<(), u32> {
        state.set(name, value)
    }

    fn put_other(state: &mut State, option: &[u16]) {
        let option = to_ansi(option);
        if let Some(equals) = option.iter().position(|&c| c == u8::EQUALS) {
            u8::put(state, &option, equals);
        }
    }
}

impl crate::Env for WinEnv {
    /// The C runtime's `getenv`, from its narrow table.
    unsafe fn getenv(&self, name: *const c_char) -> *mut c_char {
        // SAFETY: the caller's C string.
        let name = unsafe { std::ffi::CStr::from_ptr(name) }.to_bytes();
        self.crt_get::<u8>(name).cast()
    }

    fn windows(&self) -> Option<&WinEnv> {
        Some(self)
    }
}
