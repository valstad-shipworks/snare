//! The threads a state slot knows about: every thread spawned through
//! [`crate::thread`], threads that registered themselves on first use, and
//! threads that marked their class or became participants, threads a
//! census adopted by name, and synthetic kernel threads. Each gets a
//! synthetic tid and, when it runs on a host thread, the host's thread id;
//! its class is read live from the thread's own marking and the participant
//! registry.
#![cfg_attr(any(not(test), snare_global), allow(dead_code))]

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Weak};
use std::thread::ThreadId;

use parking_lot::Mutex;

use crate::sched::ThreadClass;

const FIRST_TID: u64 = 1000;
const FIRST_KERNEL_TID: u64 = 1 << 32;

const MARK_NONE: u8 = 0;
const MARK_BACKGROUND: u8 = 1;
const MARK_HELPER: u8 = 2;
const MARK_DRIVER: u8 = 3;
const MARK_PARTICIPANT: u8 = 4;

pub(crate) struct ThreadEntry {
    pub tid: u64,
    pub std_id: Option<ThreadId>,
    pub name: Option<String>,
    pub kernel: bool,
    host_tid: Mutex<Option<u64>>,
    mark: AtomicU8,
    exited: AtomicBool,
}

impl ThreadEntry {
    pub(crate) fn set_host_tid(&self, tid: u64) {
        *self.host_tid.lock() = Some(tid);
    }
}

/// A point-in-time view of one registered thread.
#[derive(Debug, Clone)]
pub(crate) struct ThreadInfo {
    pub tid: u64,
    pub std_id: Option<ThreadId>,
    pub name: Option<String>,
    pub host_tid: Option<u64>,
    pub kernel: bool,
    pub class: ThreadClass,
    pub exited: bool,
}

#[derive(Default)]
pub(crate) struct ThreadRegistry {
    inner: Mutex<Inner>,
    pub(crate) census: Mutex<crate::census::CensusState>,
}

#[derive(Default)]
struct Inner {
    threads: Vec<Arc<ThreadEntry>>,
    next_tid: Option<u64>,
    next_kernel_tid: Option<u64>,
}

/// The calling thread's registry entry, marked exited when the thread's
/// locals are torn down.
struct Current(Weak<ThreadRegistry>, Arc<ThreadEntry>);

impl Drop for Current {
    fn drop(&mut self) {
        self.1.exited.store(true, Ordering::Release);
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Current>> = const { RefCell::new(None) };
}

/// Marks the thread exited when dropped.
pub(crate) struct ExitGuard(Option<Arc<ThreadEntry>>);

impl Drop for ExitGuard {
    fn drop(&mut self) {
        if let Some(e) = self.0.take() {
            let participant = e.mark.load(Ordering::Acquire) == MARK_NONE
                && e.std_id.is_some_and(|id| {
                    crate::sched::try_slot().is_some_and(|s| s.reg().has_thread(id))
                });
            if participant {
                e.mark.store(MARK_PARTICIPANT, Ordering::Release);
            }
            e.exited.store(true, Ordering::Release);
        }
    }
}

fn mark_of(class: Option<ThreadClass>) -> u8 {
    match class {
        Some(ThreadClass::Background) => MARK_BACKGROUND,
        Some(ThreadClass::Helper) => MARK_HELPER,
        Some(ThreadClass::Driver) => MARK_DRIVER,
        _ => MARK_NONE,
    }
}

fn current_mark() -> u8 {
    if crate::sched::is_driver_thread() {
        MARK_DRIVER
    } else {
        mark_of(crate::sched::classified())
    }
}

/// Register the calling thread in its state slot's registry, once per
/// slot. `None` when the thread has no state slot.
pub(crate) fn register_current() -> Option<Arc<ThreadEntry>> {
    crate::sched::try_slot()?;
    let registry = crate::state::thread_registry();
    let known = CURRENT
        .try_with(|c| {
            c.borrow()
                .as_ref()
                .filter(|c| std::ptr::eq(c.0.as_ptr(), Arc::as_ptr(&registry)))
                .map(|c| Arc::clone(&c.1))
        })
        .ok()
        .flatten();
    if known.is_some() {
        return known;
    }
    let host_tid = crate::host_threads::current_tid();
    let entry = {
        let mut g = registry.inner.lock();
        let entry = Arc::new(ThreadEntry {
            tid: g.next_tid(),
            std_id: Some(std::thread::current().id()),
            name: std::thread::current().name().map(String::from),
            kernel: false,
            host_tid: Mutex::new(host_tid),
            mark: AtomicU8::new(current_mark()),
            exited: AtomicBool::new(false),
        });
        g.threads.push(Arc::clone(&entry));
        entry
    };
    if let Some(t) = host_tid {
        crate::host_threads::forget_start(t);
    }
    let _ = CURRENT.try_with(|c| {
        *c.borrow_mut() = Some(Current(Arc::downgrade(&registry), Arc::clone(&entry)));
    });
    Some(entry)
}

impl Inner {
    fn next_tid(&mut self) -> u64 {
        let tid = self.next_tid.unwrap_or(FIRST_TID);
        self.next_tid = Some(tid + 1);
        tid
    }
}

/// Register the host thread `host_tid`, which runs no code snare can hook,
/// as background. Returns its synthetic tid.
pub(crate) fn adopt_background(host_tid: u64, name: &str) -> u64 {
    let registry = crate::state::thread_registry();
    let tid = {
        let mut g = registry.inner.lock();
        let tid = g.next_tid();
        g.threads.push(Arc::new(ThreadEntry {
            tid,
            std_id: None,
            name: Some(name.to_string()),
            kernel: false,
            host_tid: Mutex::new(Some(host_tid)),
            mark: AtomicU8::new(MARK_BACKGROUND),
            exited: AtomicBool::new(false),
        }));
        tid
    };
    crate::host_threads::forget_start(host_tid);
    tid
}

/// Register the calling thread for the rest of its life: the returned guard
/// marks it exited when dropped.
pub(crate) fn enter() -> ExitGuard {
    ExitGuard(register_current())
}

/// Record the calling thread's new class on its registry entry,
/// registering it first if needed.
pub(crate) fn note_class(class: ThreadClass) {
    let noted = CURRENT
        .try_with(|c| {
            c.borrow().as_ref().map(|c| {
                c.1.mark.store(mark_of(Some(class)), Ordering::Release);
            })
        })
        .ok()
        .flatten();
    if noted.is_none() {
        register_current();
    }
}

/// The calling thread's synthetic tid, registering it first if needed.
pub(crate) fn current_tid() -> Option<u64> {
    register_current().map(|e| e.tid)
}

/// Add a synthetic kernel thread (an IRQ or NAPI thread, `ksoftirqd`) with
/// no std thread behind it. Returns its tid.
pub(crate) fn add_kernel_thread(name: &str) -> u64 {
    let registry = crate::state::thread_registry();
    let mut g = registry.inner.lock();
    let tid = g.next_kernel_tid.unwrap_or(FIRST_KERNEL_TID);
    g.next_kernel_tid = Some(tid + 1);
    g.threads.push(Arc::new(ThreadEntry {
        tid,
        std_id: None,
        name: Some(name.to_string()),
        kernel: true,
        host_tid: Mutex::new(None),
        mark: AtomicU8::new(MARK_BACKGROUND),
        exited: AtomicBool::new(false),
    }));
    tid
}

/// Mark the synthetic kernel thread `tid` exited, as when its interface
/// drops the queue or NAPI it served.
#[cfg(feature = "fast-talker-core")]
pub(crate) fn exit_kernel_thread(tid: u64) {
    let registry = crate::state::thread_registry();
    let g = registry.inner.lock();
    if let Some(e) = g.threads.iter().find(|e| e.tid == tid && e.kernel) {
        e.exited.store(true, Ordering::Release);
    }
}

fn snapshot(pred: impl Fn(&ThreadEntry) -> bool) -> Vec<ThreadInfo> {
    let registry = crate::state::thread_registry();
    let entries: Vec<Arc<ThreadEntry>> = registry
        .inner
        .lock()
        .threads
        .iter()
        .filter(|e| pred(e))
        .cloned()
        .collect();
    let reg = crate::sched::try_slot().map(|s| Arc::clone(s.reg()));
    entries
        .into_iter()
        .map(|e| {
            let class = match e.mark.load(Ordering::Acquire) {
                MARK_BACKGROUND => ThreadClass::Background,
                MARK_HELPER => ThreadClass::Helper,
                MARK_DRIVER => ThreadClass::Driver,
                MARK_PARTICIPANT => ThreadClass::Participant,
                _ if e
                    .std_id
                    .zip(reg.as_ref())
                    .is_some_and(|(id, reg)| reg.has_thread(id)) =>
                {
                    ThreadClass::Participant
                }
                _ => ThreadClass::Unclassified,
            };
            ThreadInfo {
                tid: e.tid,
                std_id: e.std_id,
                name: e.name.clone(),
                host_tid: *e.host_tid.lock(),
                kernel: e.kernel,
                class,
                exited: e.exited.load(Ordering::Acquire),
            }
        })
        .collect()
}

/// Every thread registered in the calling thread's state slot, oldest
/// first.
pub(crate) fn all() -> Vec<ThreadInfo> {
    snapshot(|_| true)
}

pub(crate) fn by_std(id: ThreadId) -> Option<ThreadInfo> {
    snapshot(|e| e.std_id == Some(id)).pop()
}

pub(crate) fn by_tid(tid: u64) -> Option<ThreadInfo> {
    snapshot(|e| e.tid == tid).pop()
}

/// The thread whose host thread id is `tid`.
#[cfg(feature = "fast-talker-core")]
pub(crate) fn by_host_tid(tid: u64) -> Option<ThreadInfo> {
    snapshot(|e| *e.host_tid.lock() == Some(tid)).pop()
}

/// The newest thread named `name`.
pub(crate) fn by_name(name: &str) -> Option<ThreadInfo> {
    snapshot(|e| e.name.as_deref() == Some(name)).pop()
}

#[cfg(all(test, not(snare_global)))]
mod tests {
    use super::*;

    #[test]
    fn spawned_threads_are_registered_and_follow_their_class() {
        crate::register_test();
        let (tx, rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let handle = crate::thread::Builder::new()
            .name("registry-probe".into())
            .spawn(move || {
                tx.send(std::thread::current().id()).unwrap();
                go_rx.recv().unwrap();
                crate::sched::mark_background("registry-probe");
                tx.send(std::thread::current().id()).unwrap();
                go_rx.recv().unwrap();
            })
            .unwrap();
        let std_id = rx.recv().unwrap();

        let t = by_name("registry-probe").expect("registered");
        assert_eq!(t.std_id, Some(std_id));
        assert!(t.tid >= FIRST_TID && t.tid < FIRST_KERNEL_TID);
        assert_eq!(t.class, ThreadClass::Unclassified);
        assert!(!t.exited);
        assert_eq!(by_tid(t.tid).unwrap().std_id, Some(std_id));
        assert_eq!(by_std(std_id).unwrap().tid, t.tid);

        go_tx.send(()).unwrap();
        rx.recv().unwrap();
        assert_eq!(by_std(std_id).unwrap().class, ThreadClass::Background);

        go_tx.send(()).unwrap();
        handle.join().unwrap();
        assert!(by_std(std_id).unwrap().exited);
    }

    #[test]
    fn spawn_background_never_runs_as_a_participant() {
        crate::register_test();
        let clock =
            crate::sched::testkit::StrictClock::start(Default::default()).expect("driver attaches");
        let (tx, rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let participant = crate::thread::Builder::new()
            .name("registry-participant".into())
            .spawn(move || {
                ready_tx.send(()).unwrap();
                go_rx.recv().unwrap();
            })
            .unwrap();
        ready_rx.recv().unwrap();
        let background = crate::thread::spawn_background("registry-background", move || {
            tx.send(crate::sched::thread_class()).unwrap();
        })
        .unwrap();
        assert_eq!(rx.recv().unwrap(), ThreadClass::Background);
        background.join().unwrap();
        let names: Vec<String> = clock
            .driver()
            .participants()
            .into_iter()
            .map(|p| p.name.to_string())
            .collect();
        assert!(
            !names.iter().any(|n| n == "registry-background"),
            "{names:?}"
        );
        assert_eq!(
            by_name("registry-background").unwrap().class,
            ThreadClass::Background
        );
        assert_eq!(
            by_name("registry-participant").unwrap().class,
            ThreadClass::Participant
        );
        go_tx.send(()).unwrap();
        participant.join().unwrap();
    }

    #[test]
    fn marking_a_class_registers_the_thread_with_its_host_id() {
        crate::register_test();
        let parent = std::thread::current().id();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("registry-marked".into())
            .spawn(move || {
                crate::register_thread_child_of(parent);
                crate::sched::mark_helper();
                tx.send(crate::host_threads::current_tid()).unwrap();
            })
            .unwrap()
            .join()
            .unwrap();
        let host = rx.recv().unwrap();
        let t = by_name("registry-marked").expect("registered by its mark");
        assert_eq!(t.class, ThreadClass::Helper);
        assert_eq!(t.host_tid, host);
        if cfg!(any(target_os = "macos", target_os = "linux", windows)) {
            assert!(host.is_some());
        }
        assert!(t.exited, "the entry is marked exited when the thread ends");
    }

    #[test]
    fn unspawned_threads_register_on_demand_and_kernel_tids_are_apart() {
        crate::register_test();
        let tid = current_tid().unwrap();
        assert_eq!(current_tid(), Some(tid));
        assert_eq!(by_std(std::thread::current().id()).unwrap().tid, tid);
        register_current().unwrap().set_host_tid(4242);
        assert_eq!(by_tid(tid).unwrap().host_tid, Some(4242));
        let k = add_kernel_thread("ksoftirqd/0");
        assert!(k >= FIRST_KERNEL_TID);
        let info = by_tid(k).unwrap();
        assert!(info.kernel && info.std_id.is_none());
        assert_eq!(info.name.as_deref(), Some("ksoftirqd/0"));
        assert_eq!(all().len(), 2);

        crate::register_test();
        assert!(all().is_empty());
        let again = current_tid().unwrap();
        assert_eq!(again, FIRST_TID);
    }
}
