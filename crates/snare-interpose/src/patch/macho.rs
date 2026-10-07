//! Mach-O symbol-pointer rebinding, after the technique of Facebook's fishhook.
//!
//! Calls to imported functions go through pointer sections (`__got`, `__la_symbol_ptr`) whose
//! entries the indirect symbol table names. Rewriting an entry redirects every call from that
//! image, and only from that image, without touching code pages.
//!
//! A function's address stored in data (a C table such as SQLite's `aSyscall[]`, or a Rust
//! `static F: unsafe extern "C" fn(..) = libc::fstat`) is bound by dyld like a `__got` entry, but
//! sits in `__const` or `__data` where the indirect symbol table does not reach. Those binds are
//! read from the image's own fixup description and rewritten too: the bind opcodes of
//! `LC_DYLD_INFO`/`LC_DYLD_INFO_ONLY` (what ld emits for a deployment target below macOS 12,
//! rustc's default of 11.0 included), or the chains of `LC_DYLD_CHAINED_FIXUPS` (12 and later).
//!
//! Constants and struct layouts are those of the macOS SDK's `<mach-o/loader.h>`,
//! `<mach-o/nlist.h>`, `<mach-o/fat.h>` and `<mach-o/fixup-chains.h>`; the indirect-table walk
//! follows `rebind_symbols_for_image` in fishhook's `fishhook.c` (github.com/facebook/fishhook).
//! There is no `SEEN` set: dyld reports each image to [`on_add_image`] once per load
//! (`<mach-o/dyld.h>`).

use std::ffi::{CStr, c_char};
use std::os::unix::fs::FileExt;
use std::ptr;
use std::sync::atomic::Ordering;

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
/// Compressed dyld information: rebase and bind opcode streams (`dyld_info_command`).
const LC_DYLD_INFO: u32 = 0x22;
/// The same, required to load (`LC_DYLD_INFO | LC_REQ_DYLD`).
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
/// Chained fixups (`linkedit_data_command`; `LC_DYLD_CHAINED_FIXUPS`, `0x34 | LC_REQ_DYLD`).
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;

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

/// `struct dyld_info_command` (`<mach-o/loader.h>`); offsets are file offsets into `__LINKEDIT`.
/// Only the non-lazy bind stream is read: lazy binds fill `__la_symbol_ptr`, which the indirect
/// symbol table already covers, and weak binds coalesce symbols the images define themselves.
#[repr(C)]
struct DyldInfoCommand {
    cmd: u32,
    cmdsize: u32,
    rebase_off: u32,
    rebase_size: u32,
    bind_off: u32,
    bind_size: u32,
    weak_bind_off: u32,
    weak_bind_size: u32,
    lazy_bind_off: u32,
    lazy_bind_size: u32,
    export_off: u32,
    export_size: u32,
}

/// `struct linkedit_data_command` (`<mach-o/loader.h>`): a blob in `__LINKEDIT`.
#[repr(C)]
struct LinkeditDataCommand {
    cmd: u32,
    cmdsize: u32,
    dataoff: u32,
    datasize: u32,
}

// Bind opcodes (`<mach-o/loader.h>`): the high nibble is the opcode, the low one an immediate.
const BIND_OPCODE_DONE: u8 = 0x00;
const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
const BIND_OPCODE_DO_BIND: u8 = 0x90;
const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xa0;
const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xb0;
const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xc0;
/// A bind that stores the symbol's address in a pointer (`<mach-o/loader.h>`); the other types
/// patch 32-bit text operands.
const BIND_TYPE_POINTER: u8 = 1;

// `<mach-o/fixup-chains.h>`.
/// `dyld_chained_fixups_header.imports_format`: one `u32` per import.
const DYLD_CHAINED_IMPORT: u32 = 1;
/// The same, followed by an `i32` addend.
const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
/// A `u64` import followed by a `u64` addend.
const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;
/// `dyld_chained_starts_in_segment.pointer_format`: plain 64-bit pointers, rebase targets as
/// addresses or (`_OFFSET`) as image offsets; the binds are laid out alike. The arm64e formats
/// carry pointer-authentication bits and appear only in arm64e images, which are left alone.
const DYLD_CHAINED_PTR_64: u16 = 2;
const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
/// `page_start` of a page with no fixups.
const DYLD_CHAINED_PTR_START_NONE: u16 = 0xffff;

// `<mach-o/fat.h>`; the fat header and its arch entries are big-endian.
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;

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

/// Rewrites every symbol-pointer slot, and every data pointer bound to a function, of the image at
/// `header` that names a resolved hook, and returns the hooks patched and every other imported
/// name.
///
/// Shared-cache dylibs and file types other than executables, dylibs and bundles are skipped, as
/// are images without `__LINKEDIT`. The symbol-pointer sections need a symbol table and indirect
/// symbols; the data binds need `LC_DYLD_INFO` or `LC_DYLD_CHAINED_FIXUPS`.
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
        let mut dyld_info = ptr::null::<DyldInfoCommand>();
        let mut chained = ptr::null::<LinkeditDataCommand>();
        let mut cursor = header.add(1).cast::<u8>();
        for _ in 0..h.ncmds {
            let command = &*cursor.cast::<LoadCommand>();
            match command.cmd {
                LC_SEGMENT_64 => {
                    let segment = cursor.cast::<SegmentCommand64>();
                    if segment_name(&(*segment).segname) == b"__LINKEDIT" {
                        linkedit = segment;
                    }
                    segments.push(segment);
                }
                LC_SYMTAB => symtab = cursor.cast(),
                LC_DYSYMTAB => dysymtab = cursor.cast(),
                LC_DYLD_INFO | LC_DYLD_INFO_ONLY => dyld_info = cursor.cast(),
                LC_DYLD_CHAINED_FIXUPS => chained = cursor.cast(),
                _ => {}
            }
            cursor = cursor.add(command.cmdsize as usize);
        }
        if linkedit.is_null() {
            return Default::default();
        }

        // The address at which file offset 0 would be mapped, so that `base + fileoff` addresses
        // anything inside `__LINKEDIT` (fishhook's `linkedit_base`).
        let linkedit_base = (slide as usize)
            .wrapping_add((*linkedit).vmaddr as usize)
            .wrapping_sub((*linkedit).fileoff as usize);

        let mut patched = Vec::new();
        let mut others = Vec::new();
        if !symtab.is_null() && !dysymtab.is_null() && (*dysymtab).nindirectsyms != 0 {
            let tables = Tables {
                symbols: (linkedit_base + (*symtab).symoff as usize) as *const Nlist64,
                strings: (linkedit_base + (*symtab).stroff as usize) as *const u8,
                indirect: (linkedit_base + (*dysymtab).indirectsymoff as usize) as *const u32,
            };
            for &segment in &segments {
                let read_only = is_read_only(&*segment);
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
        }

        let image = Image {
            header,
            slide,
            segments,
        };
        let mut bind = |segment: usize, offset: u64, name: &[u8], addend: i64| {
            patch_bind(&image, segment, offset, name, addend, &mut patched, &mut others);
        };
        if !dyld_info.is_null() && (*dyld_info).bind_size != 0 {
            let opcodes = std::slice::from_raw_parts(
                (linkedit_base + (*dyld_info).bind_off as usize) as *const u8,
                (*dyld_info).bind_size as usize,
            );
            for_each_bind(opcodes, &mut bind);
        } else if !chained.is_null() && (*chained).datasize != 0 {
            let fixups = std::slice::from_raw_parts(
                (linkedit_base + (*chained).dataoff as usize) as *const u8,
                (*chained).datasize as usize,
            );
            for_each_chained_bind(&image, fixups, &mut bind);
        }
        (patched, others)
    }
}

/// Whether dyld leaves the segment read-only once fixups are done. dyld's
/// `Loader::makeSegmentsReadOnly` (dyld/Loader.cpp) mprotects every segment flagged
/// `SG_READ_ONLY` to `PROT_READ` after fixups, and dyld's mach_o/UnsafeHeader.cpp rejects a
/// `__DATA_CONST` without that flag except in a few exempt images, which are treated as read-only
/// here by name.
fn is_read_only(segment: &SegmentCommand64) -> bool {
    segment_name(&segment.segname) == b"__DATA_CONST" || segment.flags & SG_READ_ONLY != 0
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

/// One image as the bind walks see it.
struct Image {
    header: *const MachHeader64,
    slide: isize,
    /// Every `LC_SEGMENT_64`, in load-command order, which is the order bind segment indices and
    /// `dyld_chained_starts_in_image.seg_info_offset` follow.
    segments: Vec<*const SegmentCommand64>,
}

/// Rewrites one pointer that dyld bound to `name` (with its leading underscore) plus `addend`, at
/// `offset` into segment `segment`, if `name` is a resolved hook.
///
/// Only a word holding exactly the hook's resolved original is rewritten: a nonzero addend points
/// into or past the function, and a different value means dyld bound another definition
/// (a flat-namespace or weak lookup), or the image has since stored something else there. A
/// `__got` slot the indirect-table pass already rewrote holds the replacement and is skipped.
unsafe fn patch_bind(
    image: &Image,
    segment: usize,
    offset: u64,
    name: &[u8],
    addend: i64,
    patched: &mut Vec<&'static str>,
    others: &mut Vec<String>,
) {
    let name = name.strip_prefix(b"_").unwrap_or(name);
    let Some(hook) = hooks::find(name) else {
        if !name.is_empty() {
            others.push(String::from_utf8_lossy(name).into_owned());
        }
        return;
    };
    let Some(&segment) = image.segments.get(segment) else {
        return;
    };
    // SAFETY: `segment` is a load command of the mapped image; the slot is checked to lie inside
    // the segment's mapping and to be aligned before it is read.
    unsafe {
        let segment = &*segment;
        if !hook.resolved()
            || addend != 0
            || offset.saturating_add(size_of::<usize>() as u64) > segment.vmsize
        {
            return;
        }
        let slot = (image.slide as usize)
            .wrapping_add(segment.vmaddr as usize)
            .wrapping_add(offset as usize) as *mut usize;
        if !(slot as usize).is_multiple_of(align_of::<usize>())
            || slot.read_volatile() != hook.original.load(Ordering::Acquire)
        {
            return;
        }
        if write_slot(slot, hook.replacement, is_read_only(segment)) {
            patched.push(hook.name);
        }
    }
}

/// Calls `bind(segment, offset, name, addend)` for every pointer bind of a non-lazy bind opcode
/// stream (`<mach-o/loader.h>`, the `BIND_OPCODE_*` comments; the interpreter mirrors dyld's
/// `MachOAnalyzer::forEachBind`). `BIND_OPCODE_DONE` ends this stream. An opcode not listed,
/// such as arm64e's `BIND_OPCODE_THREADED`, or a truncated operand, ends the walk.
fn for_each_bind(opcodes: &[u8], bind: &mut impl FnMut(usize, u64, &[u8], i64)) {
    let mut at = 0;
    let mut name: &[u8] = b"";
    let (mut segment, mut offset, mut addend, mut kind) = (0usize, 0u64, 0i64, BIND_TYPE_POINTER);
    let step = size_of::<usize>() as u64;
    let mut emit = |segment: usize, offset: u64, name: &[u8], addend: i64, kind: u8| {
        if kind == BIND_TYPE_POINTER {
            bind(segment, offset, name, addend);
        }
    };
    while let Some(&byte) = opcodes.get(at) {
        at += 1;
        let immediate = byte & 0x0f;
        match byte & 0xf0 {
            BIND_OPCODE_DONE => return,
            BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {}
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                if uleb128(opcodes, &mut at).is_none() {
                    return;
                }
            }
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                let Some(length) = opcodes[at..].iter().position(|&b| b == 0) else {
                    return;
                };
                name = &opcodes[at..at + length];
                at += length + 1;
            }
            BIND_OPCODE_SET_TYPE_IMM => kind = immediate,
            BIND_OPCODE_SET_ADDEND_SLEB => match sleb128(opcodes, &mut at) {
                Some(value) => addend = value,
                None => return,
            },
            BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                segment = immediate as usize;
                match uleb128(opcodes, &mut at) {
                    Some(value) => offset = value,
                    None => return,
                }
            }
            BIND_OPCODE_ADD_ADDR_ULEB => match uleb128(opcodes, &mut at) {
                Some(value) => offset = offset.wrapping_add(value),
                None => return,
            },
            BIND_OPCODE_DO_BIND => {
                emit(segment, offset, name, addend, kind);
                offset = offset.wrapping_add(step);
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                emit(segment, offset, name, addend, kind);
                let Some(value) = uleb128(opcodes, &mut at) else {
                    return;
                };
                offset = offset.wrapping_add(step).wrapping_add(value);
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                emit(segment, offset, name, addend, kind);
                offset = offset.wrapping_add(step * (u64::from(immediate) + 1));
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let (Some(count), Some(skip)) =
                    (uleb128(opcodes, &mut at), uleb128(opcodes, &mut at))
                else {
                    return;
                };
                for _ in 0..count {
                    emit(segment, offset, name, addend, kind);
                    offset = offset.wrapping_add(step).wrapping_add(skip);
                }
            }
            _ => return,
        }
    }
}

/// Reads an unsigned LEB128 value at `*at`, advancing past it.
fn uleb128(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = *bytes.get(*at)?;
        *at += 1;
        if shift < 64 {
            value |= u64::from(byte & 0x7f) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
}

/// Reads a signed LEB128 value at `*at`, advancing past it.
fn sleb128(bytes: &[u8], at: &mut usize) -> Option<i64> {
    let mut value = 0i64;
    let mut shift = 0;
    loop {
        let byte = *bytes.get(*at)?;
        *at += 1;
        if shift < 64 {
            value |= i64::from(byte & 0x7f) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                value |= -1 << shift;
            }
            return Some(value);
        }
    }
}

/// Calls `bind(segment, offset, name, addend)` for every bind of the chained fixups in `fixups`
/// (the `LC_DYLD_CHAINED_FIXUPS` blob; layouts from `<mach-o/fixup-chains.h>`).
///
/// dyld overwrites each chain entry with its final pointer as it applies it, so the links between
/// entries survive only in the file. The chains are therefore walked over the image's segments as
/// read back from its file, after checking that the file still holds the image that was loaded
/// (see [`image_file`]); if it cannot be read, no data bind is rewritten. Only the plain 64-bit
/// pointer formats are walked, and a compressed symbol table (`symbols_format` 1, zlib) is not
/// read.
unsafe fn for_each_chained_bind(
    image: &Image,
    fixups: &[u8],
    bind: &mut impl FnMut(usize, u64, &[u8], i64),
) {
    let u16_at = |at: usize| Some(u16::from_le_bytes(fixups.get(at..at + 2)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(fixups.get(at..at + 4)?.try_into().ok()?));
    let u64_at = |at: usize| Some(u64::from_le_bytes(fixups.get(at..at + 8)?.try_into().ok()?));
    let name_at = |at: usize| {
        let tail = fixups.get(at..)?;
        Some(&tail[..tail.iter().position(|&b| b == 0)?])
    };

    // `struct dyld_chained_fixups_header`: fixups_version, starts_offset, imports_offset,
    // symbols_offset, imports_count, imports_format, symbols_format.
    let header = (0..7).map(|i| u32_at(i * 4)).collect::<Option<Vec<_>>>();
    let Some(&[version, starts, imports, symbols, count, format, compressed]) = header.as_deref()
    else {
        return;
    };
    if version != 0 || compressed != 0 {
        return;
    }
    let (starts, imports, symbols) = (starts as usize, imports as usize, symbols as usize);
    let import = |ordinal: usize| -> Option<(&[u8], i64)> {
        if ordinal >= count as usize {
            return None;
        }
        // `dyld_chained_import`: lib_ordinal:8, weak_import:1, name_offset:23;
        // `dyld_chained_import_addend` adds an `int32_t`; `dyld_chained_import_addend64` is
        // lib_ordinal:16, weak_import:1, reserved:15, name_offset:32, then a `uint64_t` addend.
        let (name, addend) = match format {
            DYLD_CHAINED_IMPORT => (u64::from(u32_at(imports + ordinal * 4)? >> 9), 0),
            DYLD_CHAINED_IMPORT_ADDEND => {
                let at = imports + ordinal * 8;
                (u64::from(u32_at(at)? >> 9), i64::from(u32_at(at + 4)? as i32))
            }
            DYLD_CHAINED_IMPORT_ADDEND64 => {
                let at = imports + ordinal * 16;
                (u64_at(at)? >> 32, u64_at(at + 8)? as i64)
            }
            _ => return None,
        };
        Some((name_at(symbols + name as usize)?, addend))
    };

    let mut file = None;
    // `struct dyld_chained_starts_in_image`: seg_count, then one offset per segment from the
    // start of this struct, 0 for a segment without fixups.
    let Some(segment_count) = u32_at(starts) else {
        return;
    };
    for segment in 0..segment_count as usize {
        let Some(info) = u32_at(starts + 4 + segment * 4) else {
            return;
        };
        if info == 0 {
            continue;
        }
        // `struct dyld_chained_starts_in_segment`: size:u32, page_size:u16, pointer_format:u16,
        // segment_offset:u64, max_valid_pointer:u32, page_count:u16, page_start[page_count]:u16.
        let at = starts + info as usize;
        let (Some(page_size), Some(pointer_format), Some(page_count)) =
            (u16_at(at + 4), u16_at(at + 6), u16_at(at + 20))
        else {
            return;
        };
        if !matches!(
            pointer_format,
            DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET
        ) {
            continue;
        }
        let Some(&command) = image.segments.get(segment) else {
            return;
        };
        if file.is_none() {
            // SAFETY: `image.header` is a mapped image.
            file = Some(unsafe { image_file(image.header) });
        }
        let Some(Some((handle, slice))) = &file else {
            return;
        };
        // SAFETY: `command` is a load command of the mapped image.
        let command = unsafe { &*command };
        let mut contents = vec![0u8; command.filesize as usize];
        if handle
            .read_exact_at(&mut contents, slice + command.fileoff)
            .is_err()
        {
            return;
        }
        for page in 0..page_count as usize {
            let Some(start) = u16_at(at + 22 + page * 2) else {
                return;
            };
            if start == DYLD_CHAINED_PTR_START_NONE {
                continue;
            }
            let mut offset = page * page_size as usize + start as usize;
            // `dyld_chained_ptr_64_bind`: ordinal:24, addend:8, reserved:19, next:12, bind:1;
            // the rebase shares `next` and `bind`. `next` counts 4-byte strides.
            while let Some(raw) = contents
                .get(offset..offset + 8)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            {
                if raw >> 63 != 0
                    && let Some((name, addend)) = import((raw & 0xff_ffff) as usize)
                {
                    bind(
                        segment,
                        offset as u64,
                        name,
                        addend.wrapping_add(((raw >> 24) & 0xff) as i64),
                    );
                }
                let next = ((raw >> 51) & 0xfff) as usize;
                if next == 0 {
                    break;
                }
                offset += next * 4;
            }
        }
    }
}

/// The image's file, opened read-only, and the offset of the image's slice in it: 0 for a thin
/// file, or the matching architecture's `offset` in a fat one (`<mach-o/fat.h>`).
///
/// The path is the one dyld loaded the image from (`dladdr` of its header). The file is accepted
/// only if its slice begins with the very header and load commands that are mapped (they carry
/// `LC_UUID` and every segment's file offset), so a file rebuilt or replaced since the load is
/// never walked.
unsafe fn image_file(header: *const MachHeader64) -> Option<(std::fs::File, u64)> {
    // SAFETY (whole function): `header` is a mapped image; its header and load commands are
    // `sizeof(mach_header_64) + sizeofcmds` readable bytes.
    unsafe {
        let mut info: libc::Dl_info = std::mem::zeroed();
        if libc::dladdr(header.cast(), &mut info) == 0 || info.dli_fname.is_null() {
            return None;
        }
        let path = CStr::from_ptr(info.dli_fname).to_str().ok()?;
        let file = std::fs::File::open(path).ok()?;
        let mapped = std::slice::from_raw_parts(
            header.cast::<u8>(),
            size_of::<MachHeader64>() + (*header).sizeofcmds as usize,
        );
        let matches = |slice: u64| {
            let mut on_disk = vec![0u8; mapped.len()];
            file.read_exact_at(&mut on_disk, slice).is_ok() && on_disk == mapped
        };

        let mut magic = [0u8; 8];
        file.read_exact_at(&mut magic, 0).ok()?;
        let fat = u32::from_be_bytes(magic[..4].try_into().unwrap());
        if fat != FAT_MAGIC && fat != FAT_MAGIC_64 {
            return matches(0).then_some((file, 0));
        }
        // `struct fat_arch` is cputype, cpusubtype, offset:u32, size:u32, align (20 bytes);
        // `struct fat_arch_64` is cputype, cpusubtype, offset:u64, size:u64, align, reserved
        // (32 bytes).
        let entry = if fat == FAT_MAGIC { 20 } else { 32 };
        let count = u32::from_be_bytes(magic[4..].try_into().unwrap());
        for i in 0..u64::from(count) {
            let mut arch = [0u8; 32];
            file.read_exact_at(&mut arch[..entry], 8 + i * entry as u64)
                .ok()?;
            let cputype = i32::from_be_bytes(arch[..4].try_into().unwrap());
            let slice = if fat == FAT_MAGIC {
                u64::from(u32::from_be_bytes(arch[8..12].try_into().unwrap()))
            } else {
                u64::from_be_bytes(arch[8..16].try_into().unwrap())
            };
            if cputype == (*header).cputype && matches(slice) {
                return Some((file, slice));
            }
        }
        None
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
