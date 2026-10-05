//! The thread census needs a process whose every thread belongs to one state
//! slot, so this binary runs without libtest's harness threads: `main` is
//! the only thread until a check spawns one.

use std::sync::mpsc;
use std::thread::ThreadId;

use snare::sched::{self, DriverConfig, HostThreadKind, ThreadCensus, ThreadClass};

fn census() -> ThreadCensus {
    sched::thread_census().expect("this platform lists its threads")
}

fn kind_of(c: &ThreadCensus, name: &str) -> Vec<HostThreadKind> {
    c.threads
        .iter()
        .filter(|t| t.name.as_deref() == Some(name))
        .map(|t| t.kind)
        .collect()
}

fn is_unknown(c: &ThreadCensus, name: &str) -> bool {
    c.unknown.iter().any(|u| u.name.as_deref() == Some(name))
}

/// A thread that stays alive until the returned sender is dropped, after
/// running `setup` in the parent's state slot.
fn hold(
    name: &str,
    parent: Option<ThreadId>,
    setup: impl FnOnce() + Send + 'static,
) -> (mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let (ready_tx, ready_rx) = mpsc::channel();
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let handle = std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            if let Some(p) = parent {
                snare::register_thread_child_of(p);
            }
            setup();
            ready_tx.send(()).unwrap();
            let _ = stop_rx.recv();
        })
        .unwrap();
    ready_rx.recv().unwrap();
    (stop_tx, handle)
}

fn classified_threads_are_known() {
    let me = Some(std::thread::current().id());
    let (b, bh) = hold("census-background", me, || sched::mark_background("bg"));
    let (h, hh) = hold("census-helper", me, sched::mark_helper);
    let (d, dh) = hold("census-driver", me, sched::mark_driver_thread);
    let (p, ph) = hold("census-participant", me, || {
        std::mem::forget(sched::participate("census-participant"))
    });
    let (sp_tx, sp_rx) = mpsc::channel::<()>();
    let (up_tx, up_rx) = mpsc::channel();
    let spawned = snare::thread::Builder::new()
        .name("census-spawned".into())
        .spawn(move || {
            up_tx.send(()).unwrap();
            let _ = sp_rx.recv();
        })
        .unwrap();
    up_rx.recv().unwrap();

    for _ in 0..2 {
        let c = census();
        assert_eq!(
            kind_of(&c, "census-background"),
            [HostThreadKind::Known(ThreadClass::Background)]
        );
        assert_eq!(
            kind_of(&c, "census-helper"),
            [HostThreadKind::Known(ThreadClass::Helper)]
        );
        assert_eq!(
            kind_of(&c, "census-driver"),
            [HostThreadKind::Known(ThreadClass::Driver)]
        );
        assert_eq!(
            kind_of(&c, "census-participant"),
            [HostThreadKind::Known(ThreadClass::Participant)]
        );
        assert_eq!(kind_of(&c, "census-spawned").len(), 1);
        assert!(c.unknown.is_empty(), "{:?}", c.unknown);
    }
    for (tx, handle) in [(b, bh), (h, hh), (d, dh), (p, ph)] {
        drop(tx);
        handle.join().unwrap();
    }
    drop(sp_tx);
    spawned.join().unwrap();
}

fn an_unregistered_thread_is_unknown_on_the_second_census() {
    let (stop, handle) = hold("census-stranger", None, || {});
    let first = census();
    assert_eq!(
        kind_of(&first, "census-stranger"),
        [HostThreadKind::Unregistered]
    );
    assert!(!is_unknown(&first, "census-stranger"));
    let second = census();
    assert!(
        is_unknown(&second, "census-stranger"),
        "{:?}",
        second.unknown
    );
    let recorded = second
        .unknown
        .iter()
        .find(|u| u.name.as_deref() == Some("census-stranger"))
        .unwrap();
    assert!(!recorded.exited);

    drop(stop);
    handle.join().unwrap();
    let after = census();
    let recorded = after
        .unknown
        .iter()
        .find(|u| u.name.as_deref() == Some("census-stranger"))
        .expect("an unknown thread stays on record");
    assert!(recorded.exited);
}

fn a_thread_that_registers_late_is_not_unknown() {
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel();
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let me = std::thread::current().id();
    let handle = std::thread::Builder::new()
        .name("census-late".into())
        .spawn(move || {
            snare::register_thread_child_of(me);
            done_tx.send(()).unwrap();
            go_rx.recv().unwrap();
            sched::mark_background("late");
            done_tx.send(()).unwrap();
            let _ = stop_rx.recv();
        })
        .unwrap();
    done_rx.recv().unwrap();
    assert_eq!(
        kind_of(&census(), "census-late"),
        [HostThreadKind::Unregistered]
    );
    go_tx.send(()).unwrap();
    done_rx.recv().unwrap();
    let c = census();
    assert_eq!(
        kind_of(&c, "census-late"),
        [HostThreadKind::Known(ThreadClass::Background)]
    );
    assert!(!is_unknown(&c, "census-late"));
    drop(stop_tx);
    handle.join().unwrap();
}

fn name_rules_adopt_foreign_threads() {
    sched::classify_background_by_name(|n| n.starts_with("census-foreign-"));
    let (stop, handle) = hold("census-foreign-0", None, || {});
    for _ in 0..2 {
        let c = census();
        assert_eq!(
            kind_of(&c, "census-foreign-0"),
            [HostThreadKind::Known(ThreadClass::Background)]
        );
        assert!(!is_unknown(&c, "census-foreign-0"));
    }
    drop(stop);
    handle.join().unwrap();
}

fn audit_reports_the_unknown_threads(driver: &sched::Driver) {
    let c = census();
    assert!(!c.unknown.is_empty());
    assert_eq!(driver.audit().unknown_threads, c.unknown);
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::c_void;
    use std::sync::mpsc;

    use snare::sched::HostThreadKind;

    use super::{census, kind_of};

    unsafe extern "C" {
        fn pthread_threadid_np(thread: usize, id: *mut u64) -> i32;
        fn dispatch_get_global_queue(identifier: isize, flags: usize) -> *mut c_void;
        fn dispatch_async_f(queue: *mut c_void, ctx: *mut c_void, work: extern "C" fn(*mut c_void));
    }

    extern "C" fn report_tid(ctx: *mut c_void) {
        let tx = unsafe { Box::from_raw(ctx.cast::<mpsc::Sender<u64>>()) };
        let mut id = 0u64;
        unsafe { pthread_threadid_np(0, &mut id) };
        tx.send(id).unwrap();
    }

    pub(super) fn every_start_since_load_is_tracked() {
        assert!(census().creation_tracked);
    }

    pub(super) fn dispatch_workqueue_threads_are_system() {
        let (tx, rx) = mpsc::channel::<u64>();
        let ctx = Box::into_raw(Box::new(tx)).cast::<c_void>();
        unsafe { dispatch_async_f(dispatch_get_global_queue(0, 0), ctx, report_tid) };
        let tid = rx.recv().unwrap();
        for _ in 0..2 {
            let c = census();
            let kind = c.threads.iter().find(|t| t.host_tid == tid).map(|t| t.kind);
            if let Some(kind) = kind {
                assert_eq!(kind, HostThreadKind::System);
            }
            assert!(!c.unknown.iter().any(|u| u.host_tid == tid));
        }
    }

    pub(super) fn a_thread_that_lived_and_died_unregistered_is_unknown() {
        std::thread::Builder::new()
            .name("census-blip".into())
            .spawn(|| {})
            .unwrap()
            .join()
            .unwrap();
        let c = census();
        assert_eq!(kind_of(&c, "census-blip"), []);
        assert!(
            c.unknown.iter().any(|u| u.exited && u.name.is_none()),
            "{:?}",
            c.unknown
        );
    }
}

fn main() {
    snare::register_test();
    sched::mark_background("census-main");
    let driver = sched::attach_driver(DriverConfig {
        seed: 1,
        accounting: true,
        audit: false,
    })
    .unwrap();
    let c = census();
    let me = c
        .threads
        .iter()
        .find(|t| t.kind == HostThreadKind::Known(ThreadClass::Background))
        .expect("the main thread is registered by its mark");
    assert!(me.host_tid != 0);
    assert!(c.unknown.is_empty(), "{:?}", c.unknown);

    #[cfg(target_os = "macos")]
    {
        macos::every_start_since_load_is_tracked();
        macos::dispatch_workqueue_threads_are_system();
    }
    classified_threads_are_known();
    a_thread_that_registers_late_is_not_unknown();
    name_rules_adopt_foreign_threads();
    assert!(census().unknown.is_empty(), "{:?}", census().unknown);
    #[cfg(target_os = "macos")]
    macos::a_thread_that_lived_and_died_unregistered_is_unknown();
    an_unregistered_thread_is_unknown_on_the_second_census();
    audit_reports_the_unknown_threads(&driver);
    println!("thread_census: ok");
}
