//! fast-talker's `rt` under the shim: threads from snare's registry, and
//! real-time settings recorded per thread and process, with the emulated
//! OS's availability, privileges and errors.

use std::io;
use std::sync::mpsc;
use std::time::Duration;

use snare::fast_talker::rt::{
    self, CpuDmaLatency, Mmcss, ProcessPriority, QosClass, Scheduler, ThreadPriority,
    TimerResolution,
};
use snare::fast_talker::sim::{self, CpuTopology, FtEvent};
use snare::sched::ThreadClass;
use snare::{OsSemantics, os_error_code, register_test, set_os_semantics, set_privileges};

/// A snare thread named `name` that waits until the returned sender fires.
fn parked(name: &str) -> (mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let (ready_tx, ready_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let handle = snare::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            ready_tx.send(()).unwrap();
            go_rx.recv().unwrap();
        })
        .unwrap();
    ready_rx.recv().unwrap();
    (go_tx, handle)
}

/// The shim thread for the registered thread named `name`, found without
/// `Thread::find` (Linux only).
fn by_name(name: &str) -> rt::Thread {
    let tid = sim::thread_named(name).expect("registered").tid;
    rt::Thread::from_tid(i32::try_from(tid).unwrap())
}

fn unsupported(r: io::Result<impl std::fmt::Debug>) -> String {
    let e = r.unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::Unsupported, "{e}");
    e.to_string()
}

#[test]
fn spawned_threads_are_found_before_any_rt_call() {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    let (go, gvsp) = parked("telegenic-gvsp0");
    let (go_long, long) = parked("telegenic-gvsp-stream1");

    let found = rt::Thread::find("telegenic-gvsp0").unwrap();
    assert_eq!(found.len(), 1);
    let t = found[0];
    assert_eq!(t.name().unwrap(), "telegenic-gvsp0");
    let snap = sim::thread_named("telegenic-gvsp0").unwrap();
    assert_eq!(snap.tid, t.id());
    assert!(snap.log.is_empty() && snap.scheduler.is_none());

    t.pin_scheduler(&[3], Scheduler::Fifo(80)).unwrap();
    let snap = sim::thread_named("telegenic-gvsp0").unwrap();
    assert_eq!(snap.scheduler, Some(Scheduler::Fifo(80)));
    assert_eq!(snap.affinity, Some(vec![3]));
    assert_eq!(snap.log.len(), 2);
    assert!(snap.log.iter().all(|a| a.result.is_ok()));
    assert_eq!(t.scheduler().unwrap(), Scheduler::Fifo(80));

    let cut = rt::Thread::find("telegenic-gvsp-").unwrap();
    assert_eq!(cut.len(), 1);
    assert_eq!(cut[0].name().unwrap(), "telegenic-gvsp-");
    assert!(
        rt::Thread::find("telegenic-gvsp-stream")
            .unwrap()
            .is_empty()
    );
    assert_eq!(rt::Thread::find("telegenic-").unwrap().len(), 2);
    set_os_semantics(OsSemantics::MacOs);
    assert_eq!(cut[0].name().unwrap(), "telegenic-gvsp-stream1");
    unsupported(rt::Thread::find("telegenic-"));

    go.send(()).unwrap();
    go_long.send(()).unwrap();
    gvsp.join().unwrap();
    long.join().unwrap();
    set_os_semantics(OsSemantics::Linux);
    assert!(rt::Thread::find("telegenic-").unwrap().is_empty());
    assert_eq!(os_error_code(&t.name().unwrap_err()), Some(3));
}

#[test]
fn realtime_priorities_need_the_privilege() {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    set_privileges(|p| {
        p.sys_nice = false;
        p.rtprio_limit = 0;
    });
    let me = rt::Thread::current();
    let e = me.set_scheduler(Scheduler::Fifo(10)).unwrap_err();
    assert_eq!(os_error_code(&e), Some(1));
    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    me.set_scheduler(Scheduler::Other).unwrap();

    set_privileges(|p| p.rtprio_limit = 20);
    me.set_scheduler(Scheduler::RoundRobin(20)).unwrap();
    let e = me.set_scheduler(Scheduler::Fifo(21)).unwrap_err();
    assert_eq!(os_error_code(&e), Some(1));
    for p in [0, 100] {
        let e = me.set_scheduler(Scheduler::Fifo(p)).unwrap_err();
        assert_eq!(os_error_code(&e), Some(22));
    }
    assert_eq!(me.scheduler().unwrap(), Scheduler::RoundRobin(20));

    let snap = sim::thread_of(std::thread::current().id()).unwrap();
    let codes: Vec<Option<i32>> = snap.log.iter().map(|a| a.os_error).collect();
    assert_eq!(codes, [Some(1), None, None, Some(1), Some(22), Some(22)]);
    assert!(sim::events().iter().any(|e| matches!(
        &e.event,
        FtEvent::Rt {
            result: Err(io::ErrorKind::PermissionDenied),
            ..
        }
    )));

    set_os_semantics(OsSemantics::Windows);
    set_privileges(|p| p.ipc_lock = false);
    let e = rt::reserve_working_set(16 << 20, 64 << 20).unwrap_err();
    assert_eq!(os_error_code(&e), Some(1314));
    let e = rt::set_process_priority(ProcessPriority::Realtime).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(rt::process_priority().unwrap(), ProcessPriority::High);
    let p = sim::process();
    assert_eq!(p.priority, Some(ProcessPriority::High));
    assert_eq!(p.working_set, None);
    assert_eq!(p.log.len(), 2);
}

#[test]
fn macos_clamps_priorities_and_has_no_affinity() {
    register_test();
    set_os_semantics(OsSemantics::MacOs);
    let me = rt::Thread::current();
    me.set_scheduler(Scheduler::Fifo(90)).unwrap();
    assert_eq!(me.scheduler().unwrap(), Scheduler::Fifo(47));
    me.set_scheduler(Scheduler::RoundRobin(1)).unwrap();
    assert_eq!(me.scheduler().unwrap(), Scheduler::RoundRobin(15));
    unsupported(me.set_scheduler(Scheduler::Batch));

    let msg = unsupported(me.set_affinity(&[0]));
    assert_eq!(
        msg,
        "thread CPU affinity is not supported on macos (snare simulated)"
    );
    unsupported(me.affinity());
    unsupported(me.set_nice(-5));
    unsupported(rt::lock_memory());

    me.set_qos(QosClass::UserInteractive).unwrap();
    me.set_time_constraint(
        Duration::from_micros(1000),
        Duration::from_micros(200),
        Duration::from_micros(500),
    )
    .unwrap();
    let e = me
        .set_time_constraint(
            Duration::from_micros(1000),
            Duration::from_micros(500),
            Duration::from_micros(200),
        )
        .unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::Other);

    let (go, other) = parked("macos-other");
    let t = by_name("macos-other");
    let e = t.set_qos(QosClass::Utility).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    t.set_scheduler(Scheduler::Fifo(30)).unwrap();
    go.send(()).unwrap();
    other.join().unwrap();

    let snap = sim::thread_of(std::thread::current().id()).unwrap();
    assert_eq!(snap.scheduler, Some(Scheduler::RoundRobin(15)));
    assert_eq!(snap.qos, Some(QosClass::UserInteractive));
    assert_eq!(
        snap.time_constraint.unwrap().computation,
        Duration::from_micros(200)
    );
    let other = sim::thread_named("macos-other").unwrap();
    assert_eq!(other.qos, None);
    assert_eq!(other.scheduler, Some(Scheduler::Fifo(30)));
}

#[test]
fn windows_has_priorities_instead_of_schedulers() {
    register_test();
    set_os_semantics(OsSemantics::Windows);
    let me = rt::Thread::current();
    let msg = unsupported(me.set_scheduler(Scheduler::Fifo(80)));
    assert!(msg.contains("POSIX thread scheduling"), "{msg}");
    unsupported(me.scheduler());
    unsupported(rt::Thread::find(""));
    assert_eq!(me.priority().unwrap(), ThreadPriority::Normal);
    me.set_priority(ThreadPriority::TimeCritical).unwrap();
    assert_eq!(me.priority().unwrap(), ThreadPriority::TimeCritical);
    me.pin_priority(&[1], ThreadPriority::Highest).unwrap();
    me.disable_power_throttling().unwrap();

    rt::set_process_priority(ProcessPriority::Realtime).unwrap();
    rt::disable_power_throttling().unwrap();
    rt::set_process_cpus(&[0, 1]).unwrap();
    let e = rt::set_process_cpus(&[8]).unwrap_err();
    assert_eq!(e.to_string(), "no CPU 8");
    rt::reserve_working_set(32 << 20, 16 << 20).unwrap();
    {
        let _coarse = TimerResolution::request(Duration::from_millis(4)).unwrap();
        let _fine = TimerResolution::request(Duration::from_micros(100)).unwrap();
        let p = sim::process();
        assert_eq!(p.timer_resolution_effective, Some(Duration::from_millis(1)));
        assert_eq!(p.timer_resolution.len(), 2);
    }
    assert!(sim::process().timer_resolution.is_empty());
    {
        let _mmcss = Mmcss::join("pro audio").unwrap();
        let e = Mmcss::join("Audio").unwrap_err();
        assert_eq!(os_error_code(&e), Some(1552));
        let snap = sim::thread_of(std::thread::current().id()).unwrap();
        assert_eq!(snap.mmcss.as_deref(), Some("Pro Audio"));
    }
    let e = Mmcss::join("Karaoke").unwrap_err();
    assert_eq!(os_error_code(&e), Some(1550));

    let snap = sim::thread_of(std::thread::current().id()).unwrap();
    assert_eq!(snap.win_priority, Some(ThreadPriority::Highest));
    assert_eq!(snap.affinity, Some(vec![1]));
    assert!(snap.power_throttling_disabled);
    assert_eq!(snap.mmcss, None);
    assert_eq!(snap.scheduler, None);
    let p = sim::process();
    assert_eq!(p.priority, Some(ProcessPriority::Realtime));
    assert!(p.power_throttling_disabled);
    assert_eq!(p.process_cpus, Some(vec![0, 1]));
    assert_eq!(p.working_set, Some((32 << 20, 32 << 20)));

    set_os_semantics(OsSemantics::Linux);
    unsupported(me.set_priority(ThreadPriority::Normal));
    unsupported(rt::process_priority());
    unsupported(TimerResolution::request(Duration::from_millis(1)));
}

#[test]
fn rt_settings_never_change_snare_thread_classes() {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    let (to_parent, from_child) = mpsc::channel();
    let (to_child, from_parent) = mpsc::channel::<()>();
    let worker = snare::thread::Builder::new()
        .name("rt-class".into())
        .spawn(move || {
            let before = snare::sched::thread_class();
            let me = rt::Thread::current();
            me.pin_scheduler(&[2], Scheduler::Fifo(80)).unwrap();
            me.set_nice(-10).unwrap();
            rt::lock_memory().unwrap();
            to_parent
                .send((before, snare::sched::thread_class()))
                .unwrap();
            from_parent.recv().unwrap();
            snare::sched::mark_background("rt-class");
            to_parent
                .send((before, snare::sched::thread_class()))
                .unwrap();
            from_parent.recv().unwrap();
        })
        .unwrap();
    let (before, after) = from_child.recv().unwrap();
    assert_eq!(before, after);
    let snap = sim::thread_named("rt-class").unwrap();
    assert_eq!(snap.class, after);
    assert_eq!(snap.nice, Some(-10));

    to_child.send(()).unwrap();
    let (_, marked) = from_child.recv().unwrap();
    assert_eq!(marked, ThreadClass::Background);
    let snap = sim::thread_named("rt-class").unwrap();
    assert_eq!(snap.class, ThreadClass::Background);
    assert_eq!(snap.scheduler, Some(Scheduler::Fifo(80)));
    to_child.send(()).unwrap();
    worker.join().unwrap();
    assert!(sim::thread_named("rt-class").unwrap().exited);
}

#[test]
fn lock_memory_follows_the_memlock_privilege() {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    set_privileges(|p| {
        p.ipc_lock = false;
        p.memlock_limit = Some(0);
    });
    assert_eq!(os_error_code(&rt::lock_memory().unwrap_err()), Some(1));
    set_privileges(|p| p.memlock_limit = Some(64 << 10));
    assert_eq!(os_error_code(&rt::lock_memory().unwrap_err()), Some(12));
    assert!(!sim::process().memory_locked);
    set_privileges(|p| p.memlock_limit = None);
    rt::lock_memory().unwrap();
    let p = sim::process();
    assert!(p.memory_locked);
    let codes: Vec<Option<i32>> = p.log.iter().map(|a| a.os_error).collect();
    assert_eq!(codes, [Some(1), Some(12), None]);

    register_test();
    set_os_semantics(OsSemantics::Windows);
    unsupported(rt::lock_memory());
    assert!(!sim::process().memory_locked);
}

#[test]
fn cpu_dma_latency_holds_the_smallest_request() {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    let loose = CpuDmaLatency::request(Duration::from_micros(100)).unwrap();
    let tight = CpuDmaLatency::request(Duration::ZERO).unwrap();
    let p = sim::process();
    assert_eq!(p.dma_latency.len(), 2);
    assert_eq!(p.dma_latency_effective, Some(Duration::ZERO));
    drop(tight);
    assert_eq!(
        sim::process().dma_latency_effective,
        Some(Duration::from_micros(100))
    );
    drop(loose);
    assert_eq!(sim::process().dma_latency_effective, None);

    set_privileges(|p| p.root = false);
    let e = CpuDmaLatency::request(Duration::ZERO).unwrap_err();
    assert_eq!(os_error_code(&e), Some(13));
    assert!(sim::process().dma_latency.is_empty());

    set_os_semantics(OsSemantics::MacOs);
    unsupported(CpuDmaLatency::request(Duration::ZERO));
}

#[test]
fn affinity_outside_the_simulated_cpus_is_refused() {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    sim::set_cpus(CpuTopology {
        count: 4,
        isolated: vec![2, 3],
        nohz_full: vec![3],
        ..CpuTopology::default()
    });
    let me = rt::Thread::current();
    assert_eq!(me.affinity().unwrap(), [0, 1, 2, 3]);
    for cpus in [&[4][..], &[1, 4], &[]] {
        let e = me.set_affinity(cpus).unwrap_err();
        assert_eq!(os_error_code(&e), Some(22), "{cpus:?}");
    }
    let e = me.set_affinity(&[4096]).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(os_error_code(&e), None);
    me.set_affinity(&[3, 2, 3]).unwrap();
    assert_eq!(me.affinity().unwrap(), [2, 3]);
    assert_eq!(rt::isolated_cpus().unwrap(), [2, 3]);
    assert_eq!(rt::nohz_full_cpus().unwrap(), [3]);

    set_os_semantics(OsSemantics::Windows);
    let e = me.set_affinity(&[4]).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(e.to_string(), "no CPU 4");
    let e = me.set_affinity(&[]).unwrap_err();
    assert_eq!(e.to_string(), "no CPUs given");
    me.set_affinity(&[0]).unwrap();
    assert_eq!(me.affinity().unwrap(), [0]);
}

#[test]
fn fast_talkers_own_threads_convert_to_the_same_snapshot() {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    let host = ::fast_talker::rt::Thread::current();
    let me = rt::Thread::from(host);
    assert_eq!(me, rt::Thread::current());
    let snap = sim::thread_of(std::thread::current().id()).unwrap();
    assert_eq!(snap.tid, me.id());
    assert_eq!(snap.host_tid, Some(host.id()));

    let (to_parent, from_child) = mpsc::channel();
    let (to_child, from_parent) = mpsc::channel::<()>();
    let worker = snare::thread::Builder::new()
        .name("ft-host".into())
        .spawn(move || {
            to_parent
                .send(::fast_talker::rt::Thread::current())
                .unwrap();
            from_parent.recv().unwrap();
        })
        .unwrap();
    let worker_host = from_child.recv().unwrap();
    let t = rt::Thread::from(worker_host);
    t.set_scheduler(Scheduler::Fifo(60)).unwrap();
    let snap = sim::thread_named("ft-host").unwrap();
    assert_eq!(snap.tid, t.id());
    assert_eq!(snap.scheduler, Some(Scheduler::Fifo(60)));
    to_child.send(()).unwrap();
    worker.join().unwrap();

    let (to_parent, from_stranger) = mpsc::channel();
    let (to_stranger, from_parent) = mpsc::channel::<()>();
    let stranger = std::thread::spawn(move || {
        to_parent
            .send(::fast_talker::rt::Thread::current())
            .unwrap();
        from_parent.recv().unwrap();
    });
    let unknown = rt::Thread::from(from_stranger.recv().unwrap());
    let e = unknown.set_scheduler(Scheduler::Fifo(10)).unwrap_err();
    assert_eq!(os_error_code(&e), Some(3));
    to_stranger.send(()).unwrap();
    stranger.join().unwrap();
}

#[test]
fn prefault_stack_is_recorded() {
    register_test();
    rt::prefault_stack(32 * 1024);
    rt::prefault_stack(128 * 1024);
    rt::prefault_stack(64 * 1024);
    let snap = sim::thread_of(std::thread::current().id()).unwrap();
    assert_eq!(snap.prefault_bytes, 128 * 1024);
}
