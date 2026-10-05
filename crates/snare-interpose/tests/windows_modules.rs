#![cfg(windows)]
//! A module loaded after `install` must be patched and redirected, not only the executable (the
//! earlier gap). The `interpose-probe` cdylib reads the monotonic counter through its own import;
//! loading it at run time, then reading it under a frozen clock, proves both.
//!
//! One test, loaded once and never freed: two tests loading and freeing the same DLL in parallel
//! would race on its reference count and on the interposer's already-patched set.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::sync::Arc;
use std::time::Duration;

use snare_interpose::{ClockKind, Domain, Flow, Layer};

unsafe extern "system" {
    fn LoadLibraryW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetCurrentProcess() -> *mut c_void;
    fn IsWow64Process2(
        process: *mut c_void,
        process_machine: *mut u16,
        native_machine: *mut u16,
    ) -> i32;
}

const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

/// Whether this x86/x64 process runs under emulation on an ARM64 host. That emulator services
/// `QueryPerformanceCounter` itself and translates a runtime-loaded module's code at load, so
/// patching its import table cannot redirect it — a property of the emulator, not of native
/// execution, where the executable's own counter redirection (the clock tests) works.
fn emulated_on_arm() -> bool {
    let (mut process, mut native) = (0u16, 0u16);
    let ok = unsafe { IsWow64Process2(GetCurrentProcess(), &mut process, &mut native) };
    ok != 0 && native == IMAGE_FILE_MACHINE_ARM64 && !cfg!(target_arch = "aarch64")
}

struct Frozen(Duration);

impl Layer for Frozen {
    fn now(&self, clock: ClockKind) -> Flow<Duration> {
        match clock {
            ClockKind::Monotonic => Flow::Done(self.0),
            ClockKind::Realtime | ClockKind::Tai => Flow::Pass,
        }
    }
}

#[test]
fn a_later_loaded_module_is_patched_and_redirected() {
    let domain = Domain::new([Arc::new(Frozen(Duration::from_secs(1234))) as Arc<dyn Layer>]);

    // Beside the deps/ this test runs from: target/<triple>/debug/interpose_probe.dll.
    let exe = std::env::current_exe().unwrap();
    let path = exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("interpose_probe.dll");
    assert!(
        path.exists(),
        "run cargo build -p interpose-probe for the same target and profile first: {}",
        path.display()
    );

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let module = unsafe { LoadLibraryW(wide.as_ptr()) };
    assert!(!module.is_null(), "failed to load {}", path.display());
    let proc = unsafe { GetProcAddress(module, c"interpose_probe_qpc".as_ptr().cast()) };
    assert!(!proc.is_null(), "export not found");
    // SAFETY: the export is `extern "C" fn() -> i64`. The module is never freed.
    let probe = unsafe { std::mem::transmute::<*mut c_void, extern "C" fn() -> i64>(proc) };

    // Loading it entered it into the install report.
    let report = snare_interpose::install();
    assert!(
        report
            .images
            .iter()
            .any(|i| i.path.to_ascii_lowercase().contains("interpose_probe")),
        "the loaded fixture is missing from the report",
    );

    if emulated_on_arm() {
        eprintln!(
            "skipped redirection check: QueryPerformanceCounter is serviced by the x86-on-ARM emulator"
        );
        return;
    }

    // On a managed thread the module's counter import is the hook, frozen, so two reads match.
    let (first, second) = domain.run(|| (probe(), probe()));
    assert_eq!(
        first, second,
        "frozen clock should give the later-loaded module a stable counter"
    );

    // Off any domain the same import forwards to the real counter, which advances.
    let before = probe();
    let mut after = before;
    while after == before {
        after = probe();
    }
    assert!(
        after > before,
        "real counter should advance outside a domain"
    );
}
