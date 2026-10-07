//! Import-table interposition: the platform-neutral half.
//!
//! Each OS has one image-format module (`elf`, `macho`, `pe`) exposing the same three functions,
//! reached through the `image` alias: `resolve` finds a hook's real implementation, `patch_all`
//! rewrites every loaded image's import slots and data pointers bound to hooked functions (and
//! arranges for later images to be patched), and
//! `name_of` names an image from its key. This module owns the one-time install sequence and the
//! [`RECORDS`] log that [`install`] reports from.
//!
//! Lock order: the ELF and PE modules take their own `SEEN` set first and call [`record`] (which
//! takes [`RECORDS`]) while still holding it; nothing takes them in the other order. Patching
//! passes run under [`Passthrough`], so any hooked function called while either lock is held
//! goes straight to the OS and cannot re-enter a domain.

use std::sync::atomic::Ordering;
use std::sync::{Mutex, Once};

use crate::hooks::{self, Kind};
use crate::state::Passthrough;

#[cfg(target_os = "linux")]
mod elf;
#[cfg(target_os = "macos")]
mod macho;
#[cfg(windows)]
mod pe;

#[cfg(target_os = "linux")]
use elf as image;
#[cfg(target_os = "macos")]
use macho as image;
#[cfg(windows)]
use pe as image;

#[cfg(target_os = "linux")]
pub(crate) use elf::patch_new_objects;
#[cfg(windows)]
pub(crate) use pe::patch_new_modules;

/// What [`install`] changed.
#[derive(Clone, Debug, Default)]
pub struct InstallReport {
    /// One entry per image that imports anything, in the order the images were first patched.
    pub images: Vec<ImagePatches>,
    /// Hooked functions the OS does not provide, so nothing can call them.
    pub unresolved: Vec<&'static str>,
}

impl InstallReport {
    /// Imports of any image that no hook covers, with the images importing them.
    pub fn other_imports(&self) -> Vec<(&str, Vec<&str>)> {
        let mut by_name: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
        for image in &self.images {
            for name in &image.other_imports {
                by_name.entry(name).or_default().push(&image.path);
            }
        }
        by_name.into_iter().collect()
    }

    /// Whether any image's calls to `symbol` now land in a hook.
    pub fn patched(&self, symbol: &str) -> bool {
        self.images
            .iter()
            .any(|i| i.modelled.contains(&symbol) || i.observed.contains(&symbol))
    }
}

/// The import slots rewritten in one loaded image.
#[derive(Clone, Debug)]
pub struct ImagePatches {
    /// The image's file path, or a `<… at 0x…>` placeholder when the loader does not name it.
    pub path: String,
    /// Imports now translated into layer operations.
    pub modelled: Vec<&'static str>,
    /// Imports now recorded as [`Unmodelled`](crate::Unmodelled) calls on their way to the OS.
    pub observed: Vec<&'static str>,
    /// Every other function or data symbol the image imports, sorted.
    ///
    /// Most are harmless (allocation, string and memory functions, TLS setup), but an OS call in
    /// this list reaches the OS unobserved even from managed threads.
    pub other_imports: Vec<String>,
}

/// What has been patched in one image, accumulated across every pass that visited it.
struct Record {
    /// The image's identity: `dlpi_addr` on Linux (0 for a non-PIE executable), the module base
    /// on Windows, the Mach-O header address on macOS. Stable for as long as the image stays
    /// loaded.
    key: usize,
    /// The path the image module knew at patch time; `None` defers to `image::name_of` at report
    /// time (macOS, whose add-image callback carries only the header).
    path: Option<String>,
    /// Hooked symbols whose slots in this image now point at a replacement, without duplicates.
    symbols: Vec<&'static str>,
    /// Sorted, deduplicated imports no hook covers; never contains a name in `symbols`.
    other_imports: Vec<String>,
}

/// Every image patched so far. Append-only: images are never removed, even if later unloaded,
/// so a stale key may be reported (and `name_of` falls back to a placeholder for it).
static RECORDS: Mutex<Vec<Record>> = Mutex::new(Vec::new());

/// Rewrites the import tables of every non-system image in the process so hooked OS functions
/// land in this crate, and returns what has been patched so far.
///
/// The first call resolves every hook's original before rewriting any slot, under passthrough so
/// the resolution itself (`dlsym`, `LoadLibraryA`/`GetProcAddress`) cannot be redirected. `hook.original` is published with `Release`, pairing with the `Acquire` loads in
/// `Hook::resolved` and `hooks::original`.
///
/// Idempotent and cheap after the first call. Images loaded later are patched as they load
/// (`dlopen` on Linux, dyld's add-image callback on macOS, `LoadLibrary*` on Windows). No thread is redirected until it
/// enters a [`Domain`](crate::Domain).
pub fn install() -> InstallReport {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _passthrough = Passthrough::enter();
        // Every original is resolved before any slot changes: once a table is patched, a call
        // this crate makes to a hooked function (dlsym included) goes through that table too.
        for hook in hooks::all() {
            let address = image::resolve(hook);
            hook.original.store(address, Ordering::Release);
        }
        image::patch_all();
        #[cfg(windows)]
        crate::os::windows_std_sleep::install();
    });
    report()
}

/// Snapshots [`RECORDS`] into an [`InstallReport`], splitting each image's symbols by hook kind
/// and listing every hook whose original the OS did not provide.
fn report() -> InstallReport {
    let records = RECORDS.lock().unwrap_or_else(|e| e.into_inner());
    InstallReport {
        images: records
            .iter()
            .map(|r| ImagePatches {
                path: r.path.clone().unwrap_or_else(|| image::name_of(r.key)),
                modelled: of_kind(&r.symbols, Kind::Modelled),
                observed: of_kind(&r.symbols, Kind::Observed),
                other_imports: r.other_imports.clone(),
            })
            .collect(),
        unresolved: hooks::all()
            .iter()
            .filter(|h| !h.resolved())
            .map(|h| h.name)
            .collect(),
    }
}

/// The subset of `symbols` whose hook is of `kind`.
fn of_kind(symbols: &[&'static str], kind: Kind) -> Vec<&'static str> {
    symbols
        .iter()
        .copied()
        .filter(|s| hooks::find(s.as_bytes()).is_some_and(|h| h.kind == kind))
        .collect()
}

/// Merges one patching pass over image `key` into [`RECORDS`].
///
/// An image with neither patched slots nor other imports is not recorded at all. Repeated passes
/// over one image (a slot rewritten later, or a delay-load table seen after the main one) union
/// into the same [`Record`]; `path` is kept from the first pass. `other_imports` is re-sorted and
/// stripped of any name that has since been hooked in this image, so a symbol imported both
/// through a hooked slot and through an unhooked one is reported only as patched.
///
/// Called with the image module's `SEEN` lock held; takes [`RECORDS`] after it.
fn record(
    key: usize,
    path: Option<String>,
    symbols: Vec<&'static str>,
    other_imports: Vec<String>,
) {
    if symbols.is_empty() && other_imports.is_empty() {
        return;
    }
    let mut records = RECORDS.lock().unwrap_or_else(|e| e.into_inner());
    let index = match records.iter().position(|r| r.key == key) {
        Some(index) => index,
        None => {
            records.push(Record {
                key,
                path,
                symbols: Vec::new(),
                other_imports: Vec::new(),
            });
            records.len() - 1
        }
    };
    let record = &mut records[index];
    for symbol in symbols {
        if !record.symbols.contains(&symbol) {
            record.symbols.push(symbol);
        }
    }
    record.other_imports.extend(other_imports);
    record.other_imports.sort_unstable();
    record.other_imports.dedup();
    let hooked = &record.symbols;
    record
        .other_imports
        .retain(|name| !hooked.contains(&name.as_str()));
}
