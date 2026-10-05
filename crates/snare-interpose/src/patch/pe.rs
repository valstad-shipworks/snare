//! PE import address table rebinding.
//!
//! The loader binds every imported function into a module's IAT before `main`; calls read their
//! target from there. Every loaded module is patched, not just the executable, so a hooked
//! function is redirected however deep in the dependency graph it is imported. Modules loaded
//! later are patched from the `LoadLibrary*` hooks, and each module's delay-load table is
//! patched too, so a delay-loaded import is redirected before its first call resolves it.
//!
//! Only PE32+ images (64-bit) are handled; header offsets and table layouts follow
//! ([Microsoft Learn: PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)).

use std::collections::HashSet;
use std::ffi::CStr;
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{PAGE_READWRITE, VirtualProtect};
use windows_sys::Win32::System::ProcessStatus::EnumProcessModules;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::record;
use crate::hooks::{self, Hook};

/// Index of the Import Table in the optional header's data directories (winnt.h
/// `IMAGE_DIRECTORY_ENTRY_IMPORT`; PE Format, "Optional Header Data Directories").
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
/// Index of the Delay Import Descriptor directory (winnt.h `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`;
/// PE Format, "Optional Header Data Directories").
const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
/// In a PE32+ import lookup table entry, the top bit set means "by ordinal", the low 16 bits being
/// the ordinal; clear means the low 31 bits are a Hint/Name RVA (winnt.h `IMAGE_ORDINAL_FLAG64`;
/// PE Format, "Import Lookup Table").
const IMAGE_ORDINAL_FLAG64: u64 = 1 << 63;
/// Optional-header magic of a PE32+ image (winnt.h `IMAGE_NT_OPTIONAL_HDR64_MAGIC`; PE Format,
/// "Optional Header Standard Fields").
const PE32_PLUS_MAGIC: u16 = 0x20b;
/// `dlattrRva`: the delay descriptor's fields are RVAs, not absolute addresses (delayimp.h
/// `DLAttr`; [Microsoft Learn: Understand the delay load helper function](https://learn.microsoft.com/en-us/cpp/build/reference/understanding-the-helper-function);
/// PE Format, "Delay-Load Directory Table", whose table says "Must be zero" for the field but
/// whose "Attributes" subsection defines this bit as `RvaBased`).
const DLATTR_RVA: u32 = 1;

/// `IMAGE_IMPORT_DESCRIPTOR` (winnt.h; PE Format, "Import Directory Table"). The table ends at an
/// all-zero entry; a zero `name` is taken as that terminator.
#[repr(C)]
struct ImportDescriptor {
    /// RVA of the import lookup (name) table, which the loader leaves unbound. When it is zero,
    /// `first_thunk` is read as the name table instead; PE Format says the IAT matches the lookup
    /// table until binding, so that only works for slots not yet bound.
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    /// RVA of the imported DLL's NUL-terminated ASCII name.
    name: u32,
    /// RVA of the import address table, the slots calls read their targets from.
    first_thunk: u32,
}

/// `ImgDelayDescr` (delayimp.h; PE Format, "Delay-Load Directory Table"). The table ends at a
/// zero entry. With [`DLATTR_RVA`] set every address field is an RVA.
#[repr(C)]
struct DelayDescriptor {
    /// `grAttrs`; only [`DLATTR_RVA`] is defined.
    attributes: u32,
    /// RVA of the DLL name.
    name: u32,
    /// RVA of the `HMODULE` the helper fills in on first use.
    module_handle: u32,
    /// RVA of the delay IAT, whose slots initially point at the resolver thunk.
    import_address_table: u32,
    /// RVA of the delay import name table, laid out like an import lookup table.
    import_name_table: u32,
    bound_import_address_table: u32,
    unload_import_address_table: u32,
    time_date_stamp: u32,
}

/// Modules already patched, by base address. Lazily created; taken before
/// [`RECORDS`](super::RECORDS).
static SEEN: Mutex<Option<HashSet<usize>>> = Mutex::new(None);

/// The real address of `hook.name` exported by `hook.module`, or 0 if the module cannot be loaded
/// or does not export it. The reference `LoadLibraryA` takes is never released, so the module and
/// the address stay valid for the life of the process.
pub(super) fn resolve(hook: &Hook) -> usize {
    let module = format!("{}\0", hook.module);
    let name = format!("{}\0", hook.name);
    // SAFETY: both strings are NUL-terminated; nothing is patched yet, so these are the real
    // loader functions.
    unsafe {
        let module = LoadLibraryA(module.as_ptr());
        if module.is_null() {
            return 0;
        }
        GetProcAddress(module, name.as_ptr()).map_or(0, |f| f as usize)
    }
}

/// Patches every module loaded so far; later modules are patched from the `LoadLibrary*` hooks.
pub(super) fn patch_all() {
    patch_new_modules();
}

/// Patches every loaded module not patched before. Runs at install and from the `LoadLibrary*`
/// hooks, so a module loaded at run time is patched before control returns to its loader.
///
/// `EnumProcessModules` is called twice: once with no buffer for the byte count, then to fill.
/// A module loaded between the two calls is missed this pass and picked up by the next one
/// ([Microsoft Learn: EnumProcessModules](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodules)).
/// Holds [`SEEN`] for the whole pass, serialising concurrent loads' passes. A module is marked
/// seen even when it is skipped as a system module.
pub(crate) fn patch_new_modules() {
    // Keep this thread's own loader calls (and any delay-load they trigger, which re-enters the
    // `LoadLibrary` hook) out of the hooks while patching.
    let _passthrough = crate::state::Passthrough::enter();
    let mut count = 0u32;
    // SAFETY: a null buffer with zero size asks only for the required byte count.
    unsafe { EnumProcessModules(GetCurrentProcess(), std::ptr::null_mut(), 0, &mut count) };
    let mut modules =
        vec![std::ptr::null_mut::<core::ffi::c_void>(); count as usize / size_of::<HMODULE>()];
    let bytes = (modules.len() * size_of::<HMODULE>()) as u32;
    // SAFETY: `modules` has room for `bytes` bytes; the count is written back.
    if unsafe { EnumProcessModules(GetCurrentProcess(), modules.as_mut_ptr(), bytes, &mut count) }
        == 0
    {
        return;
    }
    modules.truncate(count as usize / size_of::<HMODULE>());

    let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    let seen = seen.get_or_insert_with(HashSet::new);
    for module in modules {
        let base = module as usize;
        if base == 0 || !seen.insert(base) {
            continue;
        }
        let path = name_of(base);
        // Patching the system libraries themselves (kernel32, ntdll, the CRT) redirects their
        // internal calls too, which recurses through the runtime. As on Linux and macOS, only the
        // executable and non-system modules are patched; a system DLL's own OS calls are the
        // "work inside system libraries" gap, seen only where the app calls the entry point.
        if is_system(&path) {
            continue;
        }
        // SAFETY: `base` is a module handle EnumProcessModules just returned, so it is the base
        // of a mapped image that stays loaded while we patch it.
        let (symbols, others) = unsafe { patch_module(base) };
        record(base, Some(path), symbols, others);
    }
}

/// Whether a module lives in a Windows system directory (`System32`, `SysWOW64`, `WinSxS`,
/// `SystemApps`). A snare choice of directories; matched case-insensitively on the path, with
/// `/` normalised to `\`.
fn is_system(path: &str) -> bool {
    let lower = path.to_ascii_lowercase().replace('/', "\\");
    [
        "\\system32\\",
        "\\syswow64\\",
        "\\winsxs\\",
        "\\systemapps\\",
    ]
    .iter()
    .any(|dir| lower.contains(dir))
}

/// The module's full path, or a placeholder if `GetModuleFileNameW` fails. The buffer is a
/// snare-chosen 1024 UTF-16 units; a longer path still succeeds, truncated to 1023 units plus
/// a NUL that then ends the returned string, with the last error set to
/// `ERROR_INSUFFICIENT_BUFFER`
/// ([Microsoft Learn: GetModuleFileNameW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamew)).
pub(super) fn name_of(key: usize) -> String {
    let mut buffer = [0u16; 1024];
    // SAFETY: `key` is a module handle; the buffer length is passed.
    let length =
        unsafe { GetModuleFileNameW(key as _, buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 {
        return format!("<module at {key:#x}>");
    }
    String::from_utf16_lossy(&buffer[..length])
}

/// The RVA and size of data directory `index` of the PE32+ image at `base`, or `None` if the
/// image is not PE32+ or the directory is absent.
///
/// Offsets (PE Format): the `e_lfanew` file offset of the signature is at `0x3c`; the signature
/// is `"PE\0\0"`; the COFF file header after it is 20 bytes; the PE32+ optional header's data
/// directories start at its offset 112, 8 bytes (RVA, size) each. A mapped image's RVAs equal
/// its offsets from `base`. `NumberOfRvaAndSizes` (PE32+ optional-header offset 108) is not
/// checked, so an image declaring fewer directories than `index + 1` would be misread; snare
/// assumes the 16 directories its tested linkers emit.
unsafe fn directory(base: usize, index: usize) -> Option<(usize, usize)> {
    // SAFETY (whole function): `base` is a mapped PE image; header fields lie inside it.
    unsafe {
        if *((base + 0x3c) as *const i32) < 0 {
            return None;
        }
        let nt = base + *((base + 0x3c) as *const i32) as usize;
        if *(nt as *const u32) != 0x0000_4550 {
            return None; // "PE\0\0"
        }
        let optional = nt + 4 + 20;
        if *(optional as *const u16) != PE32_PLUS_MAGIC {
            return None;
        }
        let entry = optional + 112 + index * 8;
        let rva = *(entry as *const u32) as usize;
        let size = *((entry + 4) as *const u32) as usize;
        (rva != 0).then_some((rva, size))
    }
}

/// Patches the import and delay-import tables of the module at `base`, returning the hooks patched
/// and every other import, by name or as `dll#ordinal`.
unsafe fn patch_module(base: usize) -> (Vec<&'static str>, Vec<String>) {
    let mut patched = Vec::new();
    let mut others = Vec::new();
    // SAFETY: `base` is a mapped PE image; `directory` validated the headers.
    unsafe {
        if let Some((imports_rva, _)) = directory(base, IMAGE_DIRECTORY_ENTRY_IMPORT) {
            let mut descriptor = (base + imports_rva) as *const ImportDescriptor;
            while (*descriptor).name != 0 {
                let d = &*descriptor;
                let names = if d.original_first_thunk != 0 {
                    d.original_first_thunk
                } else {
                    d.first_thunk
                };
                let dll = CStr::from_ptr((base + d.name as usize) as *const _)
                    .to_string_lossy()
                    .into_owned();
                patch_thunks(
                    base,
                    names as usize,
                    d.first_thunk as usize,
                    &dll,
                    &mut patched,
                    &mut others,
                );
                descriptor = descriptor.add(1);
            }
        }
        if let Some((delay_rva, _)) = directory(base, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) {
            let mut descriptor = (base + delay_rva) as *const DelayDescriptor;
            while (*descriptor).name != 0 {
                let d = &*descriptor;
                // Old toolchains stored preferred VAs; modern ones store RVAs. Only the RVA form
                // is handled, which every linker since Visual C++ 7.0 emits (Microsoft Learn:
                // Understand the delay load helper function).
                if d.attributes & DLATTR_RVA == 0 {
                    descriptor = descriptor.add(1);
                    continue;
                }
                let dll = CStr::from_ptr((base + d.name as usize) as *const _)
                    .to_string_lossy()
                    .into_owned();
                patch_thunks(
                    base,
                    d.import_name_table as usize,
                    d.import_address_table as usize,
                    &dll,
                    &mut patched,
                    &mut others,
                );
                descriptor = descriptor.add(1);
            }
        }
    }
    (patched, others)
}

/// Patches one thunk table: `names_rva` is the import name table, `iat_rva` the parallel address
/// table whose slots are rewritten. A delay-load slot initially points at the loader's resolver
/// stub, so overwriting it installs the hook and the stub never runs.
///
/// A by-name import is matched against the hooks by name. A by-ordinal import has no name in the
/// image, so it is matched by comparing the bound slot with every hook's resolved original; this
/// relies on [`resolve`] having run first and on the slot being bound, so an unresolved
/// delay-load ordinal import is reported in `others` rather than patched.
unsafe fn patch_thunks(
    base: usize,
    names_rva: usize,
    iat_rva: usize,
    dll: &str,
    patched: &mut Vec<&'static str>,
    others: &mut Vec<String>,
) {
    // SAFETY (whole function): both tables lie inside the mapped image and end at a zero entry.
    unsafe {
        let mut name_thunk = (base + names_rva) as *const u64;
        let mut slot = (base + iat_rva) as *mut usize;
        while *name_thunk != 0 {
            let current = slot.read_volatile();
            let (hook, label) = if *name_thunk & IMAGE_ORDINAL_FLAG64 == 0 {
                // IMAGE_IMPORT_BY_NAME: a u16 hint, then the name.
                let name = CStr::from_ptr((base + *name_thunk as usize + 2) as *const _).to_bytes();
                (
                    hooks::find(name),
                    String::from_utf8_lossy(name).into_owned(),
                )
            } else {
                // By ordinal: the bound slot holds the same address the hook resolved by name, so
                // match on that.
                let by_address = hooks::all()
                    .iter()
                    .find(|h| h.original.load(Ordering::Acquire) == current);
                (by_address, format!("{dll}#{}", *name_thunk & 0xffff))
            };
            match hook {
                Some(hook)
                    if hook.resolved()
                        && current != hook.replacement
                        && write_slot(slot, hook.replacement) =>
                {
                    patched.push(hook.name)
                }
                Some(_) => {}
                None => others.push(label),
            }
            name_thunk = name_thunk.add(1);
            slot = slot.add(1);
        }
    }
}

/// Stores `value` in `slot`, making it writable for the store and restoring its previous protection
/// afterwards. The slot's current protection is not inspected; the change is made
/// unconditionally. `VirtualProtect` acts on every page the range touches, so the page is
/// briefly writable to every thread
/// ([Microsoft Learn: VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)).
unsafe fn write_slot(slot: *mut usize, value: usize) -> bool {
    let mut previous = 0;
    // SAFETY: `slot` is an IAT entry of a mapped image; protection is restored after.
    unsafe {
        if VirtualProtect(
            slot.cast(),
            size_of::<usize>(),
            PAGE_READWRITE,
            &mut previous,
        ) == 0
        {
            return false;
        }
        slot.write_volatile(value);
        VirtualProtect(slot.cast(), size_of::<usize>(), previous, &mut previous);
    }
    true
}
