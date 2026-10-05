//! Mach-O symbol-pointer rebinding, after the technique of Facebook's fishhook.
//!
//! Calls to imported functions go through pointer sections (`__got`, `__la_symbol_ptr`) whose
//! entries the indirect symbol table names. Rewriting an entry redirects every call from that
//! image, and only from that image, without touching code pages.
//!
//! Constants and struct layouts are those of the macOS SDK's `<mach-o/loader.h>` and
//! `<mach-o/nlist.h>`; the walk follows `rebind_symbols_for_image` in fishhook's `fishhook.c`
//! (github.com/facebook/fishhook). There is no `SEEN` set: dyld reports each image to
//! [`on_add_image`] once per load (`<mach-o/dyld.h>`).

use std::ffi::{CStr, c_char};
use std::ptr;

use super::record;
use crate::hooks::{self, Hook};
use crate::state::Passthrough;

// Load-command types (`<mach-o/loader.h>`).
/// A 64-bit segment, followed by its `section_64` headers.
const LC_SEGMENT_64: u32 = 0x19;
/// The symbol and string table locations.
const LC_SYMTAB: u32 = 0x2;
/// The dynamic symbol table, which locates the indirect symbol table.
const LC_DYSYMTAB: u32 = 0xb;

// File types patched, and the header flag that excludes an image (`<mach-o/loader.h>`).
const MH_EXECUTE: u32 = 0x2;
const MH_DYLIB: u32 = 0x6;
const MH_BUNDLE: u32 = 0x8;
/// Set on a dylib that lives in the dyld shared cache, i.e. a system library.
const MH_DYLIB_IN_CACHE: u32 = 0x8000_0000;

/// Segment flag: dyld makes the segment read-only after fixups (`<mach-o/loader.h>`).
const SG_READ_ONLY: u32 = 0x10;

/// Mask selecting a section's type from its `flags` (`<mach-o/loader.h>`).
const SECTION_TYPE: u32 = 0xff;
// Section types whose entries are symbol pointers named by the indirect symbol table
// (`<mach-o/loader.h>`): `__got`, `__la_symbol_ptr`, and lazy-dylib pointers.
const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;

/// Indirect-table entry for a non-lazy pointer to a defined symbol strip(1) removed: no name to
/// look up (`<mach-o/loader.h>`).
const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
/// Or'ed into [`INDIRECT_SYMBOL_LOCAL`] when that symbol was also absolute (`<mach-o/loader.h>`).
const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;

/// `struct mach_header_64` (`<mach-o/loader.h>`); load commands follow it directly.
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

/// `struct load_command` (`<mach-o/loader.h>`): the prefix every load command shares;
/// `cmdsize` is the command's full size, so the next one starts `cmdsize` bytes later.
#[repr(C)]
struct LoadCommand {
    cmd: u32,
    cmdsize: u32,
}

/// `struct segment_command_64` (`<mach-o/loader.h>`); `nsects` `section_64`s follow it.
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

/// `struct section_64` (`<mach-o/loader.h>`).
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
    /// Section type in the low byte ([`SECTION_TYPE`]), attributes above.
    flags: u32,
    /// For symbol-pointer sections, the index of the section's first entry in the indirect
    /// symbol table; entries correspond one-to-one, in order (`<mach-o/loader.h>`).
    reserved1: u32,
    reserved2: u32,
    reserved3: u32,
}

/// `struct symtab_command` (`<mach-o/loader.h>`); offsets are file offsets into `__LINKEDIT`.
#[repr(C)]
struct SymtabCommand {
    cmd: u32,
    cmdsize: u32,
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
}

/// `struct dysymtab_command` (`<mach-o/loader.h>`). Only `indirectsymoff` (a file offset into
/// `__LINKEDIT`) and `nindirectsyms` are read.
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

/// `struct nlist_64` (`<mach-o/nlist.h>`); `n_strx` is the name's offset in the string table.
#[repr(C)]
struct Nlist64 {
    n_strx: u32,
    n_type: u8,
    n_sect: u8,
    n_desc: u16,
    n_value: u64,
}

// dyld's image-list API (`<mach-o/dyld.h>`; man 3 dyld).
unsafe extern "C" {
    fn _dyld_register_func_for_add_image(callback: extern "C" fn(*const MachHeader64, isize));
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_header(index: u32) -> *const MachHeader64;
    fn _dyld_get_image_name(index: u32) -> *const c_char;
}

/// The address the default symbol lookup gives `hook.name`, or 0 if no loaded image defines it
/// (`RTLD_DEFAULT`; macOS man 3 dlsym, NOTES: the name is the C one, without the leading
/// underscore of the Mach-O symbol).
pub(super) fn resolve(hook: &Hook) -> usize {
    let name = format!("{}\0", hook.name);
    // SAFETY: `name` is NUL-terminated; nothing is patched yet, so this is the real dlsym.
    unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr().cast()) as usize }
}

pub(super) fn patch_all() {
    // dyld calls back once for every image already loaded, then for each one loaded later, after
    // binding but before its initializers run (`<mach-o/dyld.h>`).
    // SAFETY: `on_add_image` matches the callback signature and lives for the whole process.
    unsafe { _dyld_register_func_for_add_image(on_add_image) };
}

/// The path dyld holds for the image whose header is at `key`, or a placeholder if it is no longer
/// loaded. A linear scan of dyld's image list; only used when building a report.
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

/// dyld's add-image callback: patches one image under passthrough and records it by header
/// address. `slide` is the image's ASLR offset from its link-time addresses.
extern "C" fn on_add_image(header: *const MachHeader64, slide: isize) {
    let _passthrough = Passthrough::enter();
    // SAFETY: dyld passes the header of a mapped image and its slide.
    let (symbols, others) = unsafe { patch_image(header, slide) };
    record(header as usize, None, symbols, others);
}

/// Rewrites every symbol-pointer slot of the image at `header` that names a resolved hook, and
/// returns the hooks patched and every other imported name.
///
/// Shared-cache dylibs and file types other than executables, dylibs and bundles are skipped, as
/// are images without `__LINKEDIT`, a symbol table or indirect symbols (nothing to rebind).
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

        // The address at which file offset 0 would be mapped, so that `base + fileoff` addresses
        // anything inside `__LINKEDIT` (fishhook's `linkedit_base`).
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
            // dyld's `Loader::makeSegmentsReadOnly` (dyld/Loader.cpp) mprotects every segment
            // flagged `SG_READ_ONLY` to `PROT_READ` after fixups, and dyld's
            // mach_o/UnsafeHeader.cpp rejects a `__DATA_CONST` without that flag except in a few
            // exempt images, which are treated as read-only here by name.
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

/// The run-time addresses of one image's `__LINKEDIT` tables.
struct Tables {
    /// The `nlist_64` symbol table.
    symbols: *const Nlist64,
    /// The string table that `n_strx` indexes.
    strings: *const u8,
    /// The indirect symbol table: one `u32` symbol index (or `INDIRECT_SYMBOL_*`) per pointer slot.
    indirect: *const u32,
}

/// Rewrites the slots of one symbol-pointer section. Slot `i` is named by the indirect-table
/// entry at `reserved1 + i` (`<mach-o/loader.h>`, the comment above
/// `S_NON_LAZY_SYMBOL_POINTERS`). That comment gives 4-byte entries, which is the 32-bit layout;
/// in a 64-bit image they are pointer-sized, so there are `size / 8`, as fishhook counts them.
/// Symbol names carry the C leading underscore, which is stripped before matching hooks.
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

/// Writes one pointer, lifting the page's read-only protection for the write when `read_only`,
/// then restoring `PROT_READ` (man 2 mprotect: the address must be page-aligned, hence the
/// rounding down). Returns whether the slot was written.
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

/// A segment's name without the NUL padding of its fixed 16-byte field.
fn segment_name(raw: &[u8; 16]) -> &[u8] {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    &raw[..end]
}
