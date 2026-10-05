//! The process's OS threads as the host reports them: each one's
//! system-wide id and name, the calling thread's id, and on macOS which
//! threads the kernel created for libdispatch rather than the process
//! creating them.
//!
//! On macOS a pthread introspection hook, installed when the image loads,
//! sees every thread start. A thread `pthread_create` makes is announced by
//! its creator; a workqueue thread is announced by itself, because the
//! kernel creates it. The hook keeps the live workqueue threads (system
//! threads: they only run libdispatch blocks, never a Rust entry point) and
//! every other thread that started and has not registered with snare, so a
//! thread that lives and dies unregistered between two censuses is still
//! seen. A workqueue thread the kernel has created but never sent to user
//! space has no pthread yet, so it has announced nothing; it is a system
//! thread too, recognised by having no pthread at all (`pthread_create`
//! gives a thread its pthread before it first runs).
#![cfg_attr(any(not(test), snare_global), allow(dead_code))]

/// One OS thread of this process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostThread {
    pub tid: u64,
    pub name: Option<String>,
    /// The OS created this thread for itself and it has never run any of
    /// the process's code (on macOS: it has no pthread).
    pub system: bool,
}

/// The calling thread's system-wide id: `pthread_threadid_np` on macOS,
/// `gettid` on Linux, `GetCurrentThreadId` on Windows.
pub(crate) fn current_tid() -> Option<u64> {
    imp::current_tid()
}

/// Every thread of this process, or `None` where the platform offers no way
/// to list them.
pub(crate) fn enumerate() -> Option<Vec<HostThread>> {
    imp::enumerate()
}

/// Whether `tid` is a thread the OS created for itself rather than the
/// process: on macOS a libdispatch workqueue thread. Never true elsewhere.
pub(crate) fn is_system(tid: u64) -> bool {
    imp::is_system(tid)
}

/// Threads that started since creation tracking began and never
/// registered, or `None` where starts are not tracked.
pub(crate) fn unregistered_starts() -> Option<Vec<u64>> {
    imp::unregistered_starts()
}

/// Stop tracking the start of `tid`: it registered with snare, or a
/// census has put it on record.
pub(crate) fn forget_start(tid: u64) {
    imp::forget_start(tid);
}

/// The host id of the thread that created `tid` with `pthread_create`, while
/// `tid` lives. `None` where creators are not tracked (only macOS tracks
/// them), for a thread the OS created, or once more threads started than the
/// tracker holds.
pub(crate) fn creator_of(tid: u64) -> Option<u64> {
    imp::creator_of(tid)
}

/// Whether every thread start since the image loaded was seen: false where
/// starts are not tracked, when the hook went in late, or when more
/// unregistered threads started than the tracker holds.
pub(crate) fn creation_tracked() -> bool {
    imp::creation_tracked()
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::{c_uint, c_void};
    use std::sync::Once;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    use super::HostThread;

    type Hook = unsafe extern "C" fn(event: c_uint, thread: usize, addr: *mut c_void, size: usize);

    unsafe extern "C" {
        fn pthread_self() -> usize;
        fn pthread_threadid_np(thread: usize, id: *mut u64) -> i32;
        fn pthread_introspection_hook_install(hook: Option<Hook>) -> Option<Hook>;
        static mach_task_self_: u32;
        fn task_threads(task: u32, list: *mut *mut u32, count: *mut u32) -> i32;
        fn thread_info(thread: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
        fn mach_port_deallocate(task: u32, name: u32) -> i32;
        fn vm_deallocate(task: u32, addr: usize, size: usize) -> i32;
    }

    const EVENT_CREATE: c_uint = 1;
    const EVENT_START: c_uint = 2;
    const EVENT_TERMINATE: c_uint = 3;

    const THREAD_IDENTIFIER_INFO: i32 = 4;
    const THREAD_EXTENDED_INFO: i32 = 5;

    #[repr(C)]
    #[derive(Default)]
    struct IdentifierInfo {
        thread_id: u64,
        thread_handle: u64,
        dispatch_qaddr: u64,
    }

    #[repr(C)]
    struct ExtendedInfo {
        user_time: u64,
        system_time: u64,
        cpu_usage: i32,
        policy: i32,
        run_state: i32,
        flags: i32,
        sleep_time: i32,
        curpri: i32,
        priority: i32,
        maxpriority: i32,
        name: [u8; 64],
    }

    fn words<T>() -> u32 {
        (std::mem::size_of::<T>() / std::mem::size_of::<i32>()) as u32
    }

    const SLOTS: usize = 4096;

    /// A fixed-size lock-free set of thread ids, safe to touch from inside
    /// the introspection hook (no allocation, no locks).
    struct TidSet {
        slots: [AtomicU64; SLOTS],
        overflowed: AtomicBool,
    }

    impl TidSet {
        const fn new() -> Self {
            Self {
                slots: [const { AtomicU64::new(0) }; SLOTS],
                overflowed: AtomicBool::new(false),
            }
        }

        fn insert(&self, tid: u64) {
            for slot in &self.slots {
                if slot
                    .compare_exchange(0, tid, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
            }
            self.overflowed.store(true, Ordering::Release);
        }

        fn remove(&self, tid: u64) {
            for slot in &self.slots {
                if slot
                    .compare_exchange(tid, 0, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
            }
        }

        fn contains(&self, tid: u64) -> bool {
            self.slots.iter().any(|s| s.load(Ordering::Acquire) == tid)
        }

        fn collect(&self) -> Vec<u64> {
            self.slots
                .iter()
                .map(|s| s.load(Ordering::Acquire))
                .filter(|&t| t != 0)
                .collect()
        }
    }

    /// A fixed-size lock-free map of nonzero keys to nonzero values, safe
    /// to touch from inside the introspection hook. A reader that finds a
    /// key whose value is not stored yet sees no entry.
    struct TidMap {
        keys: [AtomicU64; SLOTS],
        values: [AtomicU64; SLOTS],
    }

    impl TidMap {
        const fn new() -> Self {
            Self {
                keys: [const { AtomicU64::new(0) }; SLOTS],
                values: [const { AtomicU64::new(0) }; SLOTS],
            }
        }

        fn insert(&self, key: u64, value: u64) {
            for (k, v) in self.keys.iter().zip(&self.values) {
                if k.compare_exchange(0, key, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    v.store(value, Ordering::Release);
                    return;
                }
            }
        }

        fn get(&self, key: u64) -> Option<u64> {
            self.keys
                .iter()
                .zip(&self.values)
                .find(|(k, _)| k.load(Ordering::Acquire) == key)
                .map(|(_, v)| v.load(Ordering::Acquire))
                .filter(|&v| v != 0)
        }

        fn take(&self, key: u64) -> Option<u64> {
            let (k, v) = self
                .keys
                .iter()
                .zip(&self.values)
                .find(|(k, _)| k.load(Ordering::Acquire) == key)?;
            let value = v.swap(0, Ordering::AcqRel);
            k.store(0, Ordering::Release);
            (value != 0).then_some(value)
        }
    }

    static WORKQUEUE: TidSet = TidSet::new();
    /// pthread handle of a thread being created → its creator's id.
    static CREATING: TidMap = TidMap::new();
    /// Live thread id → its creator's id.
    static CREATORS: TidMap = TidMap::new();
    static STARTED: TidSet = TidSet::new();
    static PREVIOUS: AtomicUsize = AtomicUsize::new(0);
    static INSTALL: Once = Once::new();
    static AT_LOAD: AtomicBool = AtomicBool::new(false);

    #[used]
    #[unsafe(link_section = "__DATA,__mod_init_func")]
    static INSTALL_AT_LOAD: extern "C" fn() = install_at_load;

    extern "C" fn install_at_load() {
        INSTALL.call_once(|| {
            AT_LOAD.store(true, Ordering::Release);
            install_hook();
        });
    }

    fn install() {
        INSTALL.call_once(install_hook);
    }

    fn install_hook() {
        let previous = unsafe { pthread_introspection_hook_install(Some(hook)) };
        PREVIOUS.store(previous.map_or(0, |h| h as usize), Ordering::Release);
    }

    fn tid_of(thread: usize) -> Option<u64> {
        let mut id = 0u64;
        let rc = unsafe { pthread_threadid_np(thread, &mut id) };
        (rc == 0 && id != 0).then_some(id)
    }

    unsafe extern "C" fn hook(event: c_uint, thread: usize, addr: *mut c_void, size: usize) {
        match event {
            EVENT_CREATE if thread == unsafe { pthread_self() } => {
                if let Some(tid) = tid_of(thread) {
                    WORKQUEUE.insert(tid);
                }
            }
            EVENT_CREATE => {
                if let Some(creator) = tid_of(0) {
                    CREATING.insert(thread as u64, creator);
                }
            }
            EVENT_START => {
                if let Some(tid) = tid_of(0)
                    && !WORKQUEUE.contains(tid)
                {
                    STARTED.insert(tid);
                    if let Some(creator) = CREATING.take(unsafe { pthread_self() } as u64) {
                        CREATORS.insert(tid, creator);
                    }
                }
            }
            EVENT_TERMINATE => {
                if let Some(tid) = tid_of(0) {
                    WORKQUEUE.remove(tid);
                    CREATORS.take(tid);
                }
            }
            _ => {}
        }
        let previous = PREVIOUS.load(Ordering::Acquire);
        if previous != 0 {
            let previous: Hook = unsafe { std::mem::transmute::<usize, Hook>(previous) };
            unsafe { previous(event, thread, addr, size) };
        }
    }

    pub(super) fn current_tid() -> Option<u64> {
        install();
        tid_of(0)
    }

    pub(super) fn is_system(tid: u64) -> bool {
        WORKQUEUE.contains(tid)
    }

    pub(super) fn unregistered_starts() -> Option<Vec<u64>> {
        install();
        Some(STARTED.collect())
    }

    pub(super) fn forget_start(tid: u64) {
        STARTED.remove(tid);
    }

    pub(super) fn creator_of(tid: u64) -> Option<u64> {
        install();
        CREATORS.get(tid)
    }

    pub(super) fn creation_tracked() -> bool {
        AT_LOAD.load(Ordering::Acquire) && !STARTED.overflowed.load(Ordering::Acquire)
    }

    pub(super) fn enumerate() -> Option<Vec<HostThread>> {
        install();
        let task = unsafe { mach_task_self_ };
        let mut list: *mut u32 = std::ptr::null_mut();
        let mut count = 0u32;
        if unsafe { task_threads(task, &mut list, &mut count) } != 0 {
            return None;
        }
        let ports = unsafe { std::slice::from_raw_parts(list, count as usize) };
        let mut out = Vec::with_capacity(ports.len());
        for &port in ports {
            let mut id = IdentifierInfo::default();
            let mut n = words::<IdentifierInfo>();
            let ok = unsafe {
                thread_info(
                    port,
                    THREAD_IDENTIFIER_INFO,
                    (&mut id as *mut IdentifierInfo).cast(),
                    &mut n,
                )
            } == 0;
            let mut ext: ExtendedInfo = unsafe { std::mem::zeroed() };
            let mut n = words::<ExtendedInfo>();
            let named = unsafe {
                thread_info(
                    port,
                    THREAD_EXTENDED_INFO,
                    (&mut ext as *mut ExtendedInfo).cast(),
                    &mut n,
                )
            } == 0;
            unsafe { mach_port_deallocate(task, port) };
            if !ok || id.thread_id == 0 {
                continue;
            }
            let name = named
                .then(|| {
                    let end = ext
                        .name
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(ext.name.len());
                    String::from_utf8_lossy(&ext.name[..end]).into_owned()
                })
                .filter(|n| !n.is_empty());
            out.push(HostThread {
                tid: id.thread_id,
                name,
                system: id.thread_handle == 0,
            });
        }
        unsafe { vm_deallocate(task, list as usize, std::mem::size_of_val(ports)) };
        Some(out)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use super::HostThread;

    unsafe extern "C" {
        fn gettid() -> i32;
    }

    pub(super) fn current_tid() -> Option<u64> {
        u64::try_from(unsafe { gettid() }).ok()
    }

    pub(super) fn is_system(_tid: u64) -> bool {
        false
    }

    pub(super) fn unregistered_starts() -> Option<Vec<u64>> {
        None
    }

    pub(super) fn forget_start(_tid: u64) {}

    pub(super) fn creator_of(_tid: u64) -> Option<u64> {
        None
    }

    pub(super) fn creation_tracked() -> bool {
        false
    }

    pub(super) fn enumerate() -> Option<Vec<HostThread>> {
        let dir = std::fs::read_dir("/proc/self/task").ok()?;
        let mut out = Vec::new();
        for entry in dir.flatten() {
            let Some(tid) = entry.file_name().to_str().and_then(|s| s.parse().ok()) else {
                continue;
            };
            let name = std::fs::read_to_string(entry.path().join("comm"))
                .ok()
                .map(|s| s.trim_end_matches('\n').to_string())
                .filter(|s| !s.is_empty());
            out.push(HostThread {
                tid,
                name,
                system: false,
            });
        }
        Some(out)
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;

    use super::HostThread;

    type Handle = *mut c_void;

    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
    const TH32CS_SNAPTHREAD: u32 = 0x4;
    const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;

    #[repr(C)]
    struct ThreadEntry32 {
        size: u32,
        usage: u32,
        thread_id: u32,
        owner_process_id: u32,
        base_priority: i32,
        delta_priority: i32,
        flags: u32,
    }

    type GetThreadDescription = unsafe extern "system" fn(Handle, *mut *mut u16) -> i32;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentThreadId() -> u32;
        fn GetCurrentProcessId() -> u32;
        fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;
        fn Thread32First(snapshot: Handle, entry: *mut ThreadEntry32) -> i32;
        fn Thread32Next(snapshot: Handle, entry: *mut ThreadEntry32) -> i32;
        fn OpenThread(access: u32, inherit: i32, thread_id: u32) -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
        fn GetModuleHandleW(name: *const u16) -> Handle;
        fn GetProcAddress(module: Handle, name: *const u8) -> *const c_void;
        fn LocalFree(mem: *mut c_void) -> *mut c_void;
    }

    pub(super) fn current_tid() -> Option<u64> {
        Some(u64::from(unsafe { GetCurrentThreadId() }))
    }

    pub(super) fn is_system(_tid: u64) -> bool {
        false
    }

    pub(super) fn unregistered_starts() -> Option<Vec<u64>> {
        None
    }

    pub(super) fn forget_start(_tid: u64) {}

    pub(super) fn creator_of(_tid: u64) -> Option<u64> {
        None
    }

    pub(super) fn creation_tracked() -> bool {
        false
    }

    fn describe() -> Option<GetThreadDescription> {
        let kernel32: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        let module = unsafe { GetModuleHandleW(kernel32.as_ptr()) };
        if module.is_null() {
            return None;
        }
        let f = unsafe { GetProcAddress(module, c"GetThreadDescription".as_ptr().cast()) };
        (!f.is_null())
            .then(|| unsafe { std::mem::transmute::<*const c_void, GetThreadDescription>(f) })
    }

    fn name_of(describe: GetThreadDescription, tid: u32) -> Option<String> {
        let handle = unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, tid) };
        if handle.is_null() {
            return None;
        }
        let mut text: *mut u16 = std::ptr::null_mut();
        let ok = unsafe { describe(handle, &mut text) } >= 0 && !text.is_null();
        let name = ok.then(|| {
            let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) })
        });
        if !text.is_null() {
            unsafe { LocalFree(text.cast()) };
        }
        unsafe { CloseHandle(handle) };
        name.filter(|n| !n.is_empty())
    }

    pub(super) fn enumerate() -> Option<Vec<HostThread>> {
        let pid = unsafe { GetCurrentProcessId() };
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        let describe = describe();
        let mut entry = ThreadEntry32 {
            size: std::mem::size_of::<ThreadEntry32>() as u32,
            usage: 0,
            thread_id: 0,
            owner_process_id: 0,
            base_priority: 0,
            delta_priority: 0,
            flags: 0,
        };
        let mut out = Vec::new();
        let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
        while more {
            if entry.owner_process_id == pid {
                out.push(HostThread {
                    tid: u64::from(entry.thread_id),
                    name: describe.and_then(|d| name_of(d, entry.thread_id)),
                    system: false,
                });
            }
            more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
        }
        unsafe { CloseHandle(snapshot) };
        Some(out)
    }
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "android",
    windows
)))]
mod imp {
    use super::HostThread;

    pub(super) fn current_tid() -> Option<u64> {
        None
    }

    pub(super) fn is_system(_tid: u64) -> bool {
        false
    }

    pub(super) fn unregistered_starts() -> Option<Vec<u64>> {
        None
    }

    pub(super) fn forget_start(_tid: u64) {}

    pub(super) fn creator_of(_tid: u64) -> Option<u64> {
        None
    }

    pub(super) fn creation_tracked() -> bool {
        false
    }

    pub(super) fn enumerate() -> Option<Vec<HostThread>> {
        None
    }
}
