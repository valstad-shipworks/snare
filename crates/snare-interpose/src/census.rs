//! The thread census: every OS thread of the process held against the domains' thread registries,
//! so a run can tell its own sim's threads from another sim's, from snare's own service threads
//! and from threads no sim manages.
//!
//! A domain learns a thread's OS id when the thread itself becomes managed (it records its handle
//! on its own thread, see `Accounting::record_handle`) and forgets it as the thread leaves, so a
//! thread counts as a sim's from its first line under the sim until its last. Snare's service
//! threads, which run unmanaged by design, announce themselves with [`service_thread`]. The OS's
//! list is read under passthrough, so none of it reaches a sim's own file or thread model.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::accounting::ThreadClass;
use crate::domain::{Domain, WeakDomain};
use crate::state::Passthrough;

/// Identifies one domain (one `Sim`) for the life of the process: an id is never reused.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SimId(pub(crate) u64);

/// Whose an OS thread is, as a [`ThreadCensus`] found it.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ThreadOwner {
    /// Managed by the sim the census was taken for, in this class.
    ThisSim(ThreadClass),
    /// Managed by another sim of the process, in this class.
    OtherSim(SimId, ThreadClass),
    /// One of snare's own service threads (a real-time waker, an executive's flow thread, a
    /// watchdog), which run outside every sim by design.
    Snare,
    /// No sim manages it: the test harness's threads, threads started outside every sim or under
    /// passthrough, and threads the OS or a runtime started for itself.
    Unmanaged,
}

/// One OS thread of the process, as a [`ThreadCensus`] saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CensusThread {
    /// The OS's id for the thread: `pthread_threadid_np` on macOS (man 3 pthread_threadid_np),
    /// `gettid` on Linux (man 2 gettid), `GetCurrentThreadId` on Windows.
    pub os_id: u64,
    /// The name its sim lists it under, else the name the OS holds for it.
    pub name: Option<Arc<str>>,
    /// Whose it is.
    pub owner: ThreadOwner,
}

/// Every OS thread of the process at one moment, each with its owner.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThreadCensus {
    /// The sim it was taken for, whose threads are [`ThreadOwner::ThisSim`]; `None` when taken
    /// for none, so every managed thread is [`ThreadOwner::OtherSim`].
    pub sim: Option<SimId>,
    /// The threads, in OS id order.
    pub threads: Vec<CensusThread>,
}

impl ThreadCensus {
    /// The threads no sim manages and that are not snare's own.
    pub fn unmanaged(&self) -> impl Iterator<Item = &CensusThread> {
        self.threads
            .iter()
            .filter(|t| t.owner == ThreadOwner::Unmanaged)
    }

    /// The threads of the sim the census was taken for.
    pub fn this_sim(&self) -> impl Iterator<Item = &CensusThread> {
        self.threads
            .iter()
            .filter(|t| matches!(t.owner, ThreadOwner::ThisSim(_)))
    }

    /// The threads of other sims.
    pub fn other_sims(&self) -> impl Iterator<Item = &CensusThread> {
        self.threads
            .iter()
            .filter(|t| matches!(t.owner, ThreadOwner::OtherSim(..)))
    }
}

/// Locks `mutex`, carrying on through poisoning.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// Every domain made in the process that may still be alive, by id.
static DOMAINS: Mutex<Vec<(SimId, WeakDomain)>> = Mutex::new(Vec::new());

/// The OS ids of snare's live service threads.
static SERVICE: Mutex<Option<HashSet<u64>>> = Mutex::new(None);

/// Lists a new domain for later censuses.
pub(crate) fn register(domain: &Domain) {
    let _passthrough = Passthrough::enter();
    let mut domains = lock(&DOMAINS);
    domains.retain(|(_, weak)| weak.upgrade().is_some());
    domains.push((domain.id(), domain.downgrade()));
}

/// The live domain with serial `serial`.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn find(serial: u64) -> Option<Domain> {
    let _passthrough = Passthrough::enter();
    lock(&DOMAINS)
        .iter()
        .find(|(id, _)| id.0 == serial)
        .and_then(|(_, weak)| weak.upgrade())
}

thread_local! {
    /// Whether the calling thread is one of snare's service threads (see [`service_thread`]).
    static SERVING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether the calling thread is one of snare's own service threads: what it wakes, it wakes on
/// a sim's behalf (a clock's wakers), never as a thread outside it.
pub(crate) fn serving() -> bool {
    SERVING.try_with(std::cell::Cell::get).unwrap_or(false)
}

/// Returned by [`service_thread`]: the calling thread counts as snare's own until it drops.
#[must_use]
#[derive(Debug)]
pub struct ServiceThread {
    /// The OS id registered; `None` where ids are not known.
    os_id: Option<u64>,
    /// Whether the thread already counted as one when this guard was made.
    was: bool,
}

/// Marks the calling thread as one of snare's own service threads for every census, until the
/// returned guard drops: a thread snare starts outside every sim on purpose, which would otherwise
/// read as [`ThreadOwner::Unmanaged`].
pub fn service_thread() -> ServiceThread {
    let os_id = current_os_thread_id();
    if let Some(id) = os_id {
        let _passthrough = Passthrough::enter();
        lock(&SERVICE).get_or_insert_with(HashSet::new).insert(id);
    }
    let was = SERVING.try_with(|s| s.replace(true)).unwrap_or(false);
    ServiceThread { os_id, was }
}

impl Drop for ServiceThread {
    fn drop(&mut self) {
        let _ = SERVING.try_with(|s| s.set(self.was));
        if let Some(id) = self.os_id {
            let _passthrough = Passthrough::enter();
            if let Some(set) = lock(&SERVICE).as_mut() {
                set.remove(&id);
            }
        }
    }
}

/// Whether a thread some sim of the process manages, running or left over from an ended run,
/// holds the pthread mutex at `mutex`; `false` when no sim's thread does, or the mutex names no
/// holder.
#[cfg(target_os = "macos")]
pub(crate) fn mutex_held_by_managed(mutex: usize) -> bool {
    let _passthrough = Passthrough::enter();
    let domains: Vec<Domain> = lock(&DOMAINS)
        .iter()
        .filter_map(|(_, weak)| weak.upgrade())
        .collect();
    domains.iter().any(|domain| domain.holds_native_mutex(mutex))
}

/// Takes a census of every OS thread of the process, relative to `sim`; `None` where the OS's
/// threads cannot be listed.
pub fn census(sim: Option<&Domain>) -> Option<ThreadCensus> {
    let _passthrough = Passthrough::enter();
    let mut os = os_threads()?;
    os.sort_by_key(|&(id, _)| id);
    let domains: Vec<Domain> = lock(&DOMAINS)
        .iter()
        .filter_map(|(_, weak)| weak.upgrade())
        .collect();
    let mut managed = std::collections::HashMap::new();
    for domain in &domains {
        for (os_id, lineage, class) in domain.os_threads() {
            managed.insert(os_id, (domain, lineage, class));
        }
    }
    let service = lock(&SERVICE).clone().unwrap_or_default();
    let this = sim.map(Domain::id);
    let threads = os
        .into_iter()
        .map(|(os_id, os_name)| {
            let os_name = || os_name.map(Arc::<str>::from);
            match managed.get(&os_id) {
                Some(&(domain, lineage, class)) => CensusThread {
                    os_id,
                    name: domain.thread_name(lineage).or_else(os_name),
                    owner: if Some(domain.id()) == this {
                        ThreadOwner::ThisSim(class)
                    } else {
                        ThreadOwner::OtherSim(domain.id(), class)
                    },
                },
                None => CensusThread {
                    os_id,
                    name: os_name(),
                    owner: if service.contains(&os_id) {
                        ThreadOwner::Snare
                    } else {
                        ThreadOwner::Unmanaged
                    },
                },
            }
        })
        .collect();
    drop(managed);
    drop(domains);
    Some(ThreadCensus { sim: this, threads })
}

/// The calling thread's OS id (see [`CensusThread::os_id`]); `None` where it is not known.
pub fn current_os_thread_id() -> Option<u64> {
    imp::current()
}

/// Every thread of the process as (OS id, the name the OS holds for it); `None` where the OS's
/// threads cannot be listed. Called under passthrough.
fn os_threads() -> Option<Vec<(u64, Option<String>)>> {
    imp::list()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    /// `gettid` (man 2 gettid): the caller's kernel thread id.
    pub(super) fn current() -> Option<u64> {
        // SAFETY: gettid has no preconditions and cannot fail.
        u64::try_from(unsafe { libc::gettid() }).ok()
    }

    /// The entries of `/proc/self/task`, one directory per thread named by its id, and each one's
    /// `comm`, the name `pthread_setname_np` sets, newline-terminated (man 5 proc_pid_task, man 5
    /// proc_pid_comm).
    pub(super) fn list() -> Option<Vec<(u64, Option<String>)>> {
        let tasks = std::fs::read_dir("/proc/self/task").ok()?;
        Some(
            tasks
                .filter_map(|entry| {
                    let entry = entry.ok()?;
                    let id: u64 = entry.file_name().to_str()?.parse().ok()?;
                    let name = std::fs::read_to_string(entry.path().join("comm"))
                        .ok()
                        .map(|comm| comm.trim_end_matches('\n').to_owned())
                        .filter(|comm| !comm.is_empty());
                    Some((id, name))
                })
                .collect(),
        )
    }
}

#[cfg(target_os = "macos")]
mod imp {
    unsafe extern "C" {
        /// The caller's task port, which `mach_task_self()` reads (`<mach/mach_init.h>`).
        static mach_task_self_: libc::mach_port_t;
        /// Drops a send right (`<mach/mach_port.h>`); `task_threads` hands one per thread to the
        /// caller.
        fn mach_port_deallocate(task: libc::mach_port_t, name: libc::mach_port_t) -> i32;
    }

    /// `pthread_threadid_np` for the calling thread (null `thread` means the caller), the id
    /// `THREAD_IDENTIFIER_INFO` reports for it too.
    pub(super) fn current() -> Option<u64> {
        let mut id = 0u64;
        // SAFETY: a null thread names the caller; `id` is writable.
        (unsafe { libc::pthread_threadid_np(0 as libc::pthread_t, &mut id) } == 0).then_some(id)
    }

    /// `task_threads` lists the task's threads as ports, each a send right the caller drops with
    /// `mach_port_deallocate`, in an array it frees with `vm_deallocate` (XNU osfmk
    /// mach/task.defs). Each port's `THREAD_IDENTIFIER_INFO` gives the thread id and its
    /// `THREAD_EXTENDED_INFO` the name the thread set (`pth_name`; XNU osfmk/mach/thread_info.h).
    /// Both are kernel queries on a port the caller holds, safe however far the thread got in
    /// exiting.
    pub(super) fn list() -> Option<Vec<(u64, Option<String>)>> {
        // SAFETY: set once as the process starts and never written again.
        let task = unsafe { mach_task_self_ };
        let mut ports: libc::thread_act_array_t = std::ptr::null_mut();
        let mut count: libc::mach_msg_type_number_t = 0;
        // SAFETY: both out-pointers are writable.
        if unsafe { libc::task_threads(task, &mut ports, &mut count) } != libc::KERN_SUCCESS {
            return None;
        }
        // SAFETY: on success the kernel wrote `count` ports at `ports`.
        let list = unsafe { std::slice::from_raw_parts(ports, count as usize) };
        let threads = list
            .iter()
            .filter_map(|&port| {
                let id = thread_id(port);
                let name = thread_name(port);
                // SAFETY: drops the send right task_threads gave for this port.
                unsafe { mach_port_deallocate(task, port) };
                Some((id?, name))
            })
            .collect();
        // SAFETY: frees the array task_threads allocated in the caller's address space.
        unsafe {
            libc::vm_deallocate(
                task,
                ports as libc::vm_address_t,
                count as usize * std::mem::size_of::<libc::thread_act_t>(),
            )
        };
        Some(threads)
    }

    /// The id of the thread behind `port`.
    fn thread_id(port: libc::thread_act_t) -> Option<u64> {
        // SAFETY: a plain C struct; all zeroes is valid.
        let mut info: libc::thread_identifier_info = unsafe { std::mem::zeroed() };
        let mut n = libc::THREAD_IDENTIFIER_INFO_COUNT;
        // SAFETY: `info` holds `n` words of the flavour asked for.
        let r = unsafe {
            libc::thread_info(
                port,
                libc::THREAD_IDENTIFIER_INFO as libc::thread_flavor_t,
                (&raw mut info).cast(),
                &mut n,
            )
        };
        (r == libc::KERN_SUCCESS).then_some(info.thread_id)
    }

    /// The name of the thread behind `port`, if it set one.
    fn thread_name(port: libc::thread_act_t) -> Option<String> {
        // SAFETY: a plain C struct; all zeroes is valid.
        let mut info: libc::thread_extended_info = unsafe { std::mem::zeroed() };
        let mut n = libc::THREAD_EXTENDED_INFO_COUNT;
        // SAFETY: `info` holds `n` words of the flavour asked for.
        let r = unsafe {
            libc::thread_info(
                port,
                libc::THREAD_EXTENDED_INFO as libc::thread_flavor_t,
                (&raw mut info).cast(),
                &mut n,
            )
        };
        if r != libc::KERN_SUCCESS {
            return None;
        }
        let bytes: Vec<u8> = info
            .pth_name
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).into_owned())
    }
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};

    /// `GetCurrentThreadId`.
    pub(super) fn current() -> Option<u64> {
        // SAFETY: GetCurrentThreadId has no preconditions.
        Some(u64::from(unsafe { GetCurrentThreadId() }))
    }

    /// A `TH32CS_SNAPTHREAD` snapshot lists every thread of the system; those whose
    /// `th32OwnerProcessID` is this process's are its threads. `dwSize` must be set before the
    /// first `Thread32First`, and the snapshot is closed with `CloseHandle`
    /// ([Microsoft Learn: Taking a snapshot and viewing processes / Traversing the thread
    /// list](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)).
    /// Names come from `GetThreadDescription`.
    pub(super) fn list() -> Option<Vec<(u64, Option<String>)>> {
        // SAFETY: GetCurrentProcessId has no preconditions.
        let pid = unsafe { GetCurrentProcessId() };
        // SAFETY: a thread snapshot ignores the process id argument.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        // SAFETY: a plain C struct; all zeroes is valid.
        let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut ids = Vec::new();
        // SAFETY: `snapshot` is open and `entry` has its size set.
        let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
        while more {
            if entry.th32OwnerProcessID == pid {
                ids.push(entry.th32ThreadID);
            }
            // SAFETY: as above.
            more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
        }
        // SAFETY: closes the snapshot opened above.
        unsafe { crate::os::windows::close_internal_handle(snapshot) };
        Some(
            ids.into_iter()
                .map(|id| (u64::from(id), crate::os::thread_name(Some(id as usize))))
                .collect(),
        )
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    windows
)))]
mod imp {
    pub(super) fn current() -> Option<u64> {
        None
    }

    pub(super) fn list() -> Option<Vec<(u64, Option<String>)>> {
        None
    }
}
