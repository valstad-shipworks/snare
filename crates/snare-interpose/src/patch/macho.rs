//! Mach-O symbol-pointer rebinding, after the technique of Facebook's fishhook.
//!
//! Calls to imported functions go through pointer sections (`__got`, `__la_symbol_ptr`) whose
//! entries the indirect symbol table names. Rewriting an entry redirects every call from that
//! image, and only from that image, without touching code pages.

use std::ffi::{CStr, c_char};
use std::ptr;

use super::record;
use crate::hooks::{self, Hook};
use crate::state::Passthrough;

const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xb;

const MH_EXECUTE: u32 = 0x2;
const MH_DYLIB: u32 = 0x6;
const MH_BUNDLE: u32 = 0x8;
const MH_DYLIB_IN_CACHE: u32 = 0x8000_0000;

const SG_READ_ONLY: u32 = 0x10;

const SECTION_TYPE: u32 = 0xff;
const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;

const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;

#[repr(C)]
struct MachHeader64 {
    magic: u32,
    cputype: i32,
    cpusubtype: i32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: u32,
}

#[repr(C)]
struct LoadCommand {
    cmd: u32,
    cmdsize: u32,
}

#[repr(C)]
struct SegmentCommand64 {
    cmd: u32,
    cmdsize: u32,
    segname: [u8; 16],
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: i32,
    initprot: i32,
    nsects: u32,
    flags: u32,
}

#[repr(C)]
struct Section64 {
    sectname: [u8; 16],
    segname: [u8; 16],
    addr: u64,
    size: u64,
    offset: u32,
    align: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    reserved3: u32,
}

#[repr(C)]
struct SymtabCommand {
    cmd: u32,
    cmdsize: u32,
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
}

#[repr(C)]
struct DysymtabCommand {
    cmd: u32,
    cmdsize: u32,
    ilocalsym: u32,
    nlocalsym: u32,
    iextdefsym: u32,
    nextdefsym: u32,
    iundefsym: u32,
    nundefsym: u32,
    tocoff: u32,
    ntoc: u32,
    modtaboff: u32,
    nmodtab: u32,
    extrefsymoff: u32,
    nextrefsyms: u32,
    indirectsymoff: u32,
    nindirectsyms: u32,
    extreloff: u32,
    nextrel: u32,
    locreloff: u32,
    nlocrel: u32,
}

#[repr(C)]
struct Nlist64 {
    n_strx: u32,
    n_type: u8,
    n_sect: u8,
    n_desc: u16,
    n_value: u64,
}

unsafe extern "C" {
    fn _dyld_register_func_for_add_image(callback: extern "C" fn(*const MachHeader64, isize));
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_header(index: u32) -> *const MachHeader64;
    fn _dyld_get_image_name(index: u32) -> *const c_char;
}

pub(super) fn resolve(hook: &Hook) -> usize {
    let name = format!("{}\0", hook.name);
    // SAFETY: `name` is NUL-terminated; nothing is patched yet, so this is the real dlsym.
    unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr().cast()) as usize }
}

pub(super) fn patch_all() {
    // dyld calls back once for every image already loaded, then for each one loaded later.
    // SAFETY: `on_add_image` matches the callback signature and lives for the whole process.
    unsafe { _dyld_register_func_for_add_image(on_add_image) };
}

pub(super) fn name_of(key: usize) -> String {
    // SAFETY: plain dyld queries; indices below the count are valid, and names are C strings
    // owned by dyld for as long as the image stays loaded.
    unsafe {
        (0.._dyld_image_count())
            .find(|&i| _dyld_get_image_header(i) as usize == key)
            .map(|i| {
                CStr::from_ptr(_dyld_get_image_name(i))
                    .to_string_lossy()
                    .into_owned()
            })
            .unwrap_or_else(|| format!("<image at {key:#x}>"))
    }
}

extern "C" fn on_add_image(header: *const MachHeader64, slide: isize) {
    let _passthrough = Passthrough::enter();
    // SAFETY: dyld passes the header of a mapped image and its slide.
    let (symbols, others) = unsafe { patch_image(header, slide) };
    record(header as usize, None, symbols, others);
}

unsafe fn patch_image(
    header: *const MachHeader64,
    slide: isize,
) -> (Vec<&'static str>, Vec<String>) {
    // SAFETY (whole function): `header` is a mapped Mach-O image; its load commands, and the
    // tables they locate once shifted by `slide`, are readable for the image's lifetime.
    unsafe {
        let h = &*header;
        if h.flags & MH_DYLIB_IN_CACHE != 0
            || !matches!(h.filetype, MH_EXECUTE | MH_DYLIB | MH_BUNDLE)
        {
            return Default::default();
        }

        let mut segments = Vec::new();
        let mut linkedit = ptr::null::<SegmentCommand64>();
        let mut symtab = ptr::null::<SymtabCommand>();
        let mut dysymtab = ptr::null::<DysymtabCommand>();
        let mut cursor = header.add(1).cast::<u8>();
        for _ in 0..h.ncmds {
            let command = &*cursor.cast::<LoadCommand>();
            match command.cmd {
                LC_SEGMENT_64 => {
                    let segment = cursor.cast::<SegmentCommand64>();
                    if segment_name(&(*segment).segname) == b"__LINKEDIT" {
                        linkedit = segment;
                    } else {
                        segments.push(segment);
                    }
                }
                LC_SYMTAB => symtab = cursor.cast(),
                LC_DYSYMTAB => dysymtab = cursor.cast(),
                _ => {}
            }
            cursor = cursor.add(command.cmdsize as usize);
        }
        if linkedit.is_null()
            || symtab.is_null()
            || dysymtab.is_null()
            || (*dysymtab).nindirectsyms == 0
        {
            return Default::default();
        }

        let linkedit_base = (slide as usize)
            .wrapping_add((*linkedit).vmaddr as usize)
            .wrapping_sub((*linkedit).fileoff as usize);
        let tables = Tables {
            symbols: (linkedit_base + (*symtab).symoff as usize) as *const Nlist64,
            strings: (linkedit_base + (*symtab).stroff as usize) as *const u8,
            indirect: (linkedit_base + (*dysymtab).indirectsymoff as usize) as *const u32,
        };

        let mut patched = Vec::new();
        let mut others = Vec::new();
        for segment in segments {
            // dyld write-protects these once fixups are applied.
            let read_only = segment_name(&(*segment).segname) == b"__DATA_CONST"
                || (*segment).flags & SG_READ_ONLY != 0;
            let sections = segment.add(1).cast::<Section64>();
            for s in 0..(*segment).nsects as usize {
                let section = &*sections.add(s);
                if matches!(
                    section.flags & SECTION_TYPE,
                    S_NON_LAZY_SYMBOL_POINTERS
                        | S_LAZY_SYMBOL_POINTERS
                        | S_LAZY_DYLIB_SYMBOL_POINTERS
                ) {
                    patch_section(
                        section,
                        slide,
                        &tables,
                        read_only,
                        &mut patched,
                        &mut others,
                    );
                }
            }
        }
        (patched, others)
    }
}

struct Tables {
    symbols: *const Nlist64,
    strings: *const u8,
    indirect: *const u32,
}

unsafe fn patch_section(
    section: &Section64,
    slide: isize,
    tables: &Tables,
    read_only: bool,
    patched: &mut Vec<&'static str>,
    others: &mut Vec<String>,
) {
    // SAFETY (whole function): `section` is a symbol-pointer section of a mapped image, and
    // `reserved1` is its first entry's index into the indirect symbol table.
    unsafe {
        let slots = (slide as usize).wrapping_add(section.addr as usize) as *mut usize;
        let indices = tables.indirect.add(section.reserved1 as usize);
        for i in 0..section.size as usize / size_of::<usize>() {
            let index = *indices.add(i);
            if index & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) != 0 {
                continue;
            }
            let symbol = &*tables.symbols.add(index as usize);
            let name = CStr::from_ptr(tables.strings.add(symbol.n_strx as usize).cast()).to_bytes();
            let name = name.strip_prefix(b"_").unwrap_or(name);
            let Some(hook) = hooks::find(name) else {
                others.push(String::from_utf8_lossy(name).into_owned());
                continue;
            };
            if !hook.resolved() {
                continue;
            }
            let slot = slots.add(i);
            if slot.read_volatile() != hook.replacement
                && write_slot(slot, hook.replacement, read_only)
            {
                patched.push(hook.name);
            }
        }
    }
}

/// Writes one pointer, lifting the page's read-only protection for the write when `read_only`.
unsafe fn write_slot(slot: *mut usize, value: usize, read_only: bool) -> bool {
    // SAFETY (whole function): `slot` is an aligned pointer slot inside a mapped image; the page
    // arithmetic stays within the page that contains it.
    unsafe {
        if !read_only {
            slot.write_volatile(value);
            return true;
        }
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let page = (slot as usize & !(page_size - 1)) as *mut libc::c_void;
        if libc::mprotect(page, page_size, libc::PROT_READ | libc::PROT_WRITE) != 0 {
            return false;
        }
        slot.write_volatile(value);
        libc::mprotect(page, page_size, libc::PROT_READ);
        true
    }
}

fn segment_name(raw: &[u8; 16]) -> &[u8] {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    &raw[..end]
}
