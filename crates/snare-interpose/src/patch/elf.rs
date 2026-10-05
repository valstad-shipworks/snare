//! ELF GOT rebinding.
//!
//! Every call from an object to an imported function reads its target from a GOT slot that the
//! dynamic linker filled from a `JUMP_SLOT` (PLT) or `GLOB_DAT` relocation. rustc skips the PLT
//! on x86_64 Linux by default, as if given `-Z plt=no` (`plt_by_default = false` in
//! `rustc_target`'s `x86_64_unknown_linux_gnu.rs`, honoured by `Session::needs_plt` under the
//! Linux default of full RELRO), so most calls from Rust code use `GLOB_DAT`; both kinds are
//! rewritten.
//!
//! Objects are found with `dl_iterate_phdr(3)`, and each object's `PT_DYNAMIC` segment gives its
//! symbol and string tables and its two `Elf64_Rela` tables (`DT_RELA`, `DT_JMPREL`). Every
//! constant and struct below is the System V gABI's, as spelled in glibc's `elf/elf.h`. The
//! `dlopen` hook calls [`patch_new_objects`] after each successful load.

use std::collections::HashSet;
use std::ffi::{CStr, c_int, c_void};
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use super::record;
use crate::hooks::{self, Hook};
use crate::state::Passthrough;

/// The dynamic-section segment (glibc `elf/elf.h`, `PT_DYNAMIC`).
const PT_DYNAMIC: u32 = 2;
/// The span the loader makes read-only once relocation is done (glibc `elf/elf.h`,
/// `PT_GNU_RELRO`; applied by `_dl_protect_relro` in `elf/dl-reloc.c`). Under `-z relro` it
/// covers the `GLOB_DAT` GOT, and under `-z now` the PLT GOT too.
const PT_GNU_RELRO: u32 = 0x6474_e552;

// Dynamic-section tags (glibc `elf/elf.h`, `DT_*`; elf(5)).
/// Ends the dynamic section.
const DT_NULL: i64 = 0;
/// Byte size of the `DT_JMPREL` table.
const DT_PLTRELSZ: i64 = 2;
/// Address of the dynamic string table.
const DT_STRTAB: i64 = 5;
/// Address of the dynamic symbol table.
const DT_SYMTAB: i64 = 6;
/// Address of the non-PLT `Elf64_Rela` table, which holds the `GLOB_DAT` relocations.
const DT_RELA: i64 = 7;
/// Byte size of the `DT_RELA` table.
const DT_RELASZ: i64 = 8;
/// Address of the PLT relocation table, which holds the `JUMP_SLOT` relocations. Assumed to be
/// `Elf64_Rela` (`DT_PLTREL == DT_RELA`): the x86-64 psABI ("Relocation") says the architecture
/// uses only `Elf64_Rela`, and glibc's dynamic linker for both x86_64 and AArch64 takes
/// `sysdeps/generic/dl-machine-rel.h`, which sets `ELF_MACHINE_NO_REL` and `PLTREL` to
/// `Elf64_Rela`.
const DT_JMPREL: i64 = 23;

/// The relocation types whose target is a GOT slot holding a symbol's address:
/// `R_X86_64_GLOB_DAT` (6) and `R_X86_64_JUMP_SLOT` (7), glibc `elf/elf.h`.
#[cfg(target_arch = "x86_64")]
const GOT_RELOCATIONS: [u32; 2] = [6, 7];
/// `R_AARCH64_GLOB_DAT` (1025) and `R_AARCH64_JUMP_SLOT` (1026), glibc `elf/elf.h`.
#[cfg(target_arch = "aarch64")]
const GOT_RELOCATIONS: [u32; 2] = [1025, 1026];

/// Path prefixes of distribution-installed libraries, which are never patched (see
/// [`Object::is_system`]). A snare choice: the FHS library directories.
const SYSTEM_PREFIXES: [&str; 4] = ["/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/"];

/// `Elf64_Dyn` (glibc `elf/elf.h`): a tag and its `d_val`/`d_ptr` union.
#[repr(C)]
struct Dyn {
    tag: i64,
    value: u64,
}

/// `Elf64_Rela` (glibc `elf/elf.h`).
#[repr(C)]
struct Rela {
    /// The slot's address relative to the object's load base.
    offset: u64,
    /// Symbol index in the high 32 bits, relocation type in the low 32 (`ELF64_R_SYM`,
    /// `ELF64_R_TYPE`).
    info: u64,
    addend: i64,
}

/// `Elf64_Sym` (glibc `elf/elf.h`). Only `name` is read.
#[repr(C)]
struct Sym {
    /// Byte offset of the symbol's name in the dynamic string table.
    name: u32,
    info: u8,
    other: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

/// Objects already patched, by load address. Each object is patched once: an overwritten lazy
/// `JUMP_SLOT` no longer leads into the loader's resolver, so the loader never rebinds it. Lazily created; taken before [`RECORDS`].
///
/// [`RECORDS`]: super::RECORDS
static SEEN: Mutex<Option<HashSet<usize>>> = Mutex::new(None);

/// The address the process's default symbol lookup gives `hook.name`, or 0 if no loaded object
/// defines it (`dlsym(3)`, `RTLD_DEFAULT`).
pub(super) fn resolve(hook: &Hook) -> usize {
    let name = format!("{}\0", hook.name);
    // SAFETY: `name` is NUL-terminated; nothing is patched yet, so this is the real dlsym.
    unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr().cast()) as usize }
}

/// Patches every object loaded so far; later objects are patched from the `dlopen` hook.
pub(super) fn patch_all() {
    patch_new_objects();
}

/// A placeholder name; every ELF record carries its path, so this is never needed in practice.
pub(super) fn name_of(key: usize) -> String {
    format!("<object at {key:#x}>")
}

/// Patches every loaded object not patched before.
///
/// Runs under passthrough, so nothing it calls is diverted into a domain. Holds [`SEEN`]
/// for the whole pass, which serialises concurrent `dlopen`s' passes; a second pass sees the first
/// one's objects as seen. An object is marked seen even when it is skipped as a system object.
pub(crate) fn patch_new_objects() {
    let _passthrough = Passthrough::enter();
    let mut found: Vec<Object> = Vec::new();
    // SAFETY: the callback only reads the program headers it is handed and pushes to `found`.
    unsafe { libc::dl_iterate_phdr(Some(collect), (&raw mut found).cast()) };

    let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
    let seen = seen.get_or_insert_with(HashSet::new);
    for object in found {
        if !seen.insert(object.base) || object.is_system() {
            continue;
        }
        // SAFETY: `object` describes a loaded object, and it stays loaded while we patch: it was
        // just reported by the loader and nothing here unloads it.
        let (symbols, others) = unsafe { patch_object(&object) };
        record(object.base, Some(object.path.clone()), symbols, others);
    }
}

/// One loaded object, as `dl_iterate_phdr` reported it.
struct Object {
    /// `dlpi_addr`: the difference between run-time and link-time addresses, which is 0 for a
    /// non-PIE executable. Added to every `p_vaddr` and `r_offset` (man 3 dl_iterate_phdr).
    base: usize,
    /// `dlpi_name`, or the executable's path for the main program, whose `dlpi_name` is empty.
    path: String,
    /// The object's program headers, mapped for as long as the object is loaded.
    phdrs: *const libc::Elf64_Phdr,
    phnum: usize,
}

impl Object {
    /// Whether the object is left unpatched: the vDSO (named `linux-vdso.so.1`, or
    /// `linux-gate.so.1` on 32-bit x86; man 7 vdso), anything under [`SYSTEM_PREFIXES`], or the
    /// C library wherever it lives. Patching libc would redirect its own internal calls into the
    /// hooks, which then recurse through the very functions they forward to.
    fn is_system(&self) -> bool {
        self.path.contains("linux-vdso")
            || self.path.contains("linux-gate")
            || SYSTEM_PREFIXES.iter().any(|p| self.path.starts_with(p))
            || self.defines_a_hooked_function()
    }

    /// The C library itself, wherever it is installed (on NixOS, in the store): the object whose
    /// `PT_LOAD` segments contain any hook's resolved original. Relies on [`super::install`]
    /// having resolved every original before the first pass.
    fn defines_a_hooked_function(&self) -> bool {
        hooks::all().iter().any(|h| {
            let address = h.original.load(Ordering::Acquire);
            // SAFETY: `phdrs` holds `phnum` headers of a loaded object.
            address != 0
                && unsafe { std::slice::from_raw_parts(self.phdrs, self.phnum) }
                    .iter()
                    .any(|p| {
                        let start = self.base + p.p_vaddr as usize;
                        p.p_type == libc::PT_LOAD
                            && (start..start + p.p_memsz as usize).contains(&address)
                    })
        })
    }
}

/// The `dl_iterate_phdr` callback: appends one [`Object`] to the `Vec<Object>` behind `found`.
/// Returning 0 continues the walk (man 3 dl_iterate_phdr). glibc runs it with
/// `dl_load_write_lock` held (`elf/dl-iteratephdr.c`), so it only copies; patching happens after
/// the walk returns.
unsafe extern "C" fn collect(
    info: *mut libc::dl_phdr_info,
    _size: usize,
    found: *mut c_void,
) -> c_int {
    // SAFETY: the loader passes a valid info struct and our `found` vector.
    unsafe {
        let info = &*info;
        let path = if info.dlpi_name.is_null() || *info.dlpi_name == 0 {
            std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<main>".into())
        } else {
            CStr::from_ptr(info.dlpi_name)
                .to_string_lossy()
                .into_owned()
        };
        (*found.cast::<Vec<Object>>()).push(Object {
            base: info.dlpi_addr as usize,
            path,
            phdrs: info.dlpi_phdr,
            phnum: info.dlpi_phnum as usize,
        });
    }
    0
}

/// Rewrites every `GLOB_DAT`/`JUMP_SLOT` slot of `object` that names a resolved hook, and returns
/// the hooks patched and the names of every other symbol those relocations import.
///
/// An object without a dynamic section, or without symbol or string tables, imports nothing and
/// is skipped. A slot already holding the replacement is left alone and not reported again.
unsafe fn patch_object(object: &Object) -> (Vec<&'static str>, Vec<String>) {
    // SAFETY (whole function): `object` is loaded; its dynamic section and the tables it points to
    // are mapped for the object's lifetime.
    unsafe {
        let phdrs = std::slice::from_raw_parts(object.phdrs, object.phnum);
        let Some(dynamic) = phdrs.iter().find(|p| p.p_type == PT_DYNAMIC) else {
            return Default::default();
        };
        let relro: Vec<(usize, usize)> = phdrs
            .iter()
            .filter(|p| p.p_type == PT_GNU_RELRO)
            .map(|p| {
                (
                    object.base + p.p_vaddr as usize,
                    object.base + (p.p_vaddr + p.p_memsz) as usize,
                )
            })
            .collect();

        // glibc relocates these entries in place (`elf_get_dynamic_info` in
        // elf/get-dynamic-info.h) unless `dl_relocate_ld` (sysdeps/generic/ldsodefs.h) says no: a
        // read-only dynamic section or a `DL_RO_DYN_SECTION` architecture. musl never does
        // (`decode_dyn` in ldso/dynlink.c copies the entries and adds the base on use). A
        // link-time address of a PIE or DSO is below its load base, which tells the two apart.
        let address = |value: u64| {
            let value = value as usize;
            if value < object.base {
                object.base + value
            } else {
                value
            }
        };

        let (mut strtab, mut symtab) = (0, 0);
        let mut tables = [(0usize, 0usize); 2];
        let mut entry = (object.base + dynamic.p_vaddr as usize) as *const Dyn;
        while (*entry).tag != DT_NULL {
            let Dyn { tag, value } = *entry;
            match tag {
                DT_STRTAB => strtab = address(value),
                DT_SYMTAB => symtab = address(value),
                DT_RELA => tables[0].0 = address(value),
                DT_RELASZ => tables[0].1 = value as usize,
                DT_JMPREL => tables[1].0 = address(value),
                DT_PLTRELSZ => tables[1].1 = value as usize,
                _ => {}
            }
            entry = entry.add(1);
        }
        if strtab == 0 || symtab == 0 {
            return Default::default();
        }

        let mut patched = Vec::new();
        let mut others = Vec::new();
        for (table, size) in tables {
            if table == 0 {
                continue;
            }
            let relocations =
                std::slice::from_raw_parts(table as *const Rela, size / size_of::<Rela>());
            for relocation in relocations {
                if !GOT_RELOCATIONS.contains(&((relocation.info & 0xffff_ffff) as u32)) {
                    continue;
                }
                let symbol = &*(symtab as *const Sym).add((relocation.info >> 32) as usize);
                let name = CStr::from_ptr((strtab + symbol.name as usize) as *const _).to_bytes();
                let Some(hook) = hooks::find(name) else {
                    if !name.is_empty() {
                        others.push(String::from_utf8_lossy(name).into_owned());
                    }
                    continue;
                };
                if !hook.resolved() {
                    continue;
                }
                let slot = (object.base + relocation.offset as usize) as *mut usize;
                let read_only = relro
                    .iter()
                    .any(|&(start, end)| (start..end).contains(&(slot as usize)));
                if slot.read_volatile() != hook.replacement
                    && write_slot(slot, hook.replacement, read_only)
                {
                    patched.push(hook.name);
                }
            }
        }
        (patched, others)
    }
}

/// Stores `value` in `slot`, returning whether it was written.
///
/// A slot inside `PT_GNU_RELRO` has already been made read-only by the loader, so its page is
/// made writable for the store and put back to `PROT_READ`, as `_dl_protect_relro`
/// (glibc `elf/dl-reloc.c`) protects it (man 2 mprotect: `addr` must be page-aligned, hence the
/// rounding down). `_dl_protect_relro` rounds the span's end down to a page, so a slot on a
/// trailing partial page was left writable by the loader yet still ends up `PROT_READ` here.
/// The page is briefly writable to every thread; a concurrent call through another slot on it
/// is unaffected, since only this one word changes.
unsafe fn write_slot(slot: *mut usize, value: usize, read_only: bool) -> bool {
    // SAFETY (whole function): `slot` is an aligned GOT entry of a loaded object; the page
    // arithmetic stays within the page that contains it.
    unsafe {
        if !read_only {
            slot.write_volatile(value);
            return true;
        }
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let page = (slot as usize & !(page_size - 1)) as *mut c_void;
        if libc::mprotect(page, page_size, libc::PROT_READ | libc::PROT_WRITE) != 0 {
            return false;
        }
        slot.write_volatile(value);
        libc::mprotect(page, page_size, libc::PROT_READ);
        true
    }
}
