//! ELF GOT rebinding.
//!
//! Every call from an object to an imported function reads its target from a GOT slot that the
//! dynamic linker filled from a `JUMP_SLOT` (PLT) or `GLOB_DAT` relocation. Rust links x86_64
//! with `-Z plt=no`, so most calls use `GLOB_DAT`; both kinds are rewritten.

use std::collections::HashSet;
use std::ffi::{CStr, c_int, c_void};
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use super::record;
use crate::hooks::{self, Hook};
use crate::state::Passthrough;

const PT_DYNAMIC: u32 = 2;
const PT_GNU_RELRO: u32 = 0x6474_e552;

const DT_NULL: i64 = 0;
const DT_PLTRELSZ: i64 = 2;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_JMPREL: i64 = 23;

#[cfg(target_arch = "x86_64")]
const GOT_RELOCATIONS: [u32; 2] = [6, 7];
#[cfg(target_arch = "aarch64")]
const GOT_RELOCATIONS: [u32; 2] = [1025, 1026];

const SYSTEM_PREFIXES: [&str; 4] = ["/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/"];

#[repr(C)]
struct Dyn {
    tag: i64,
    value: u64,
}

#[repr(C)]
struct Rela {
    offset: u64,
    info: u64,
    addend: i64,
}

#[repr(C)]
struct Sym {
    name: u32,
    info: u8,
    other: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

/// Objects already patched, by load address.
static SEEN: Mutex<Option<HashSet<usize>>> = Mutex::new(None);

pub(super) fn resolve(hook: &Hook) -> usize {
    let name = format!("{}\0", hook.name);
    // SAFETY: `name` is NUL-terminated; nothing is patched yet, so this is the real dlsym.
    unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr().cast()) as usize }
}

pub(super) fn patch_all() {
    patch_new_objects();
}

pub(super) fn name_of(key: usize) -> String {
    format!("<object at {key:#x}>")
}

/// Patches every loaded object not patched before.
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

struct Object {
    base: usize,
    path: String,
    phdrs: *const libc::Elf64_Phdr,
    phnum: usize,
}

impl Object {
    fn is_system(&self) -> bool {
        self.path.contains("linux-vdso")
            || self.path.contains("linux-gate")
            || SYSTEM_PREFIXES.iter().any(|p| self.path.starts_with(p))
            || self.defines_a_hooked_function()
    }

    /// The C library itself, wherever it is installed (on NixOS, in the store).
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

        // glibc relocates these entries in place; musl and a few architectures leave them as
        // link-time addresses.
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
