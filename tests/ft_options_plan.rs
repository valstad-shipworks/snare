//! fast-talker's thread and process options and its plans under the shim:
//! fast-talker's own rules and reports, carried out on snare's simulated
//! host and recorded for the test.

use std::any::TypeId;
use std::io;
use std::sync::mpsc;
use std::time::Duration;

use snare::fast_talker::monitor;
use snare::fast_talker::options::{Failure, Policy, ProcessOption, Reason, Rules, ThreadOption};
use snare::fast_talker::plan::{InterfacePlan, Plan};
use snare::fast_talker::rt::{self, Scheduler, ThreadPriority};
use snare::fast_talker::sim::{self, FtEvent};
use snare::fast_talker::{compat, nic::Nic};
use snare::{IpNet, NicSpec, OsSemantics, add_nic, register_test, set_os_semantics};

fn same<A: 'static, B: 'static>() -> bool {
    TypeId::of::<A>() == TypeId::of::<B>()
}

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn me() -> sim::ThreadSnapshot {
    sim::thread_of(std::thread::current().id()).expect("registered")
}

fn logged(t: &sim::ThreadSnapshot) -> Vec<String> {
    t.log.iter().map(|a| a.what.clone()).collect()
}

fn setup(os: OsSemantics) {
    register_test();
    set_os_semantics(os);
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/24"))).unwrap();
}

#[test]
fn thread_options_follow_the_emulated_os_and_fast_talkers_rules() {
    setup(OsSemantics::Linux);
    let options = [
        ThreadOption::RtPriority(80),
        ThreadOption::CpuAffinity(vec![2]),
        ThreadOption::WinPriority(ThreadPriority::Highest),
    ];
    let report = ThreadOption::apply_all(&options, &Rules::default()).unwrap();
    assert_eq!(report.applied, options[..2]);
    assert!(matches!(
        report.skipped[0].reason,
        Reason::OtherPlatform("Windows")
    ));
    let t = me();
    assert_eq!(t.scheduler, Some(Scheduler::Fifo(80)));
    assert_eq!(t.affinity, Some(vec![2]));
    let log = logged(&t);
    assert!(log.contains(&"RtPriority(80)".to_string()), "{log:?}");
    assert!(log.contains(&"CpuAffinity([2])".to_string()), "{log:?}");
    assert!(!log.iter().any(|w| w.contains("WinPriority")), "{log:?}");

    set_os_semantics(OsSemantics::MacOs);
    let lenient = Rules {
        unsupported: Policy::Report,
        ..Rules::default()
    };
    let report = ThreadOption::apply_all(&options[..2], &lenient).unwrap();
    assert_eq!(report.applied, [ThreadOption::RtPriority(80)]);
    let Reason::Unsupported(why) = &report.skipped[0].reason else {
        panic!("{:?}", report.skipped);
    };
    assert!(why.starts_with("macOS has no CPU affinity"), "{why}");
    let t = me();
    assert_eq!(t.scheduler, Some(Scheduler::Fifo(47)), "clamped on macOS");
    assert!(logged(&t).contains(&"skipped:CpuAffinity([2])".to_string()));

    let e = ThreadOption::apply_all(&options[..2], &Rules::default()).unwrap_err();
    assert_eq!(e.option, ThreadOption::CpuAffinity(vec![2]));
    assert!(matches!(
        e.failure,
        Failure::Skipped(Reason::Unsupported(_))
    ));
    assert_eq!(e.report.applied, [ThreadOption::RtPriority(80)]);
    assert_eq!(io::Error::from(e).kind(), io::ErrorKind::Unsupported);

    set_os_semantics(OsSemantics::Linux);
    let e =
        ThreadOption::apply_all(&[ThreadOption::RtPriority(120)], &Rules::default()).unwrap_err();
    let Failure::Failed(err) = &e.failure else {
        panic!("{e:?}");
    };
    assert_eq!(snare::os_error_code(err), Some(22));
    let last = me().log.pop().unwrap();
    assert_eq!(last.what, "RtPriority(120)");
    assert_eq!(last.os_error, Some(22));
}

#[test]
fn apply_all_to_a_host_thread_is_answered_by_snare() {
    setup(OsSemantics::Linux);
    let report = ThreadOption::apply_all_to(
        ::fast_talker::rt::Thread::current(),
        &[ThreadOption::LinuxNice(5)],
        &Rules::default(),
    )
    .unwrap();
    assert_eq!(report.applied.len(), 1);
    assert_eq!(me().nice, Some(5));

    let (host_tx, host_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let worker = snare::thread::Builder::new()
        .name("ft-opt-worker".into())
        .spawn(move || {
            host_tx.send(::fast_talker::rt::Thread::current()).unwrap();
            go_rx.recv().unwrap();
        })
        .unwrap();
    let host = host_rx.recv().unwrap();
    ThreadOption::apply_all_to(
        host,
        &[ThreadOption::CpuAffinity(vec![1, 3])],
        &Rules::default(),
    )
    .unwrap();
    let e = ThreadOption::apply_all_to(
        host,
        &[ThreadOption::PrefaultStack(4096)],
        &Rules::default(),
    )
    .unwrap_err();
    let Failure::Failed(err) = &e.failure else {
        panic!("{e:?}");
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    let worker_snap = sim::thread_named("ft-opt-worker").unwrap();
    assert_eq!(worker_snap.affinity, Some(vec![1, 3]));
    assert!(logged(&worker_snap).contains(&"CpuAffinity([1, 3])".to_string()));

    let shim_thread = rt::Thread::from(host);
    compat::apply_thread_options_to(
        shim_thread,
        &[ThreadOption::RtPriority(60)],
        &Rules::default(),
    )
    .unwrap();
    assert_eq!(
        sim::thread_named("ft-opt-worker").unwrap().scheduler,
        Some(Scheduler::Fifo(60))
    );
    assert_eq!(me().scheduler, None, "not the calling thread");
    go_tx.send(()).unwrap();
    worker.join().unwrap();
}

#[test]
fn process_option_guards_live_as_long_as_the_report() {
    setup(OsSemantics::Linux);
    let report = ProcessOption::apply_all(
        &[
            ProcessOption::LinuxCpuDmaLatency(10),
            ProcessOption::LockMemory,
        ],
        &Rules::default(),
    )
    .unwrap();
    let p = sim::process();
    assert_eq!(p.dma_latency_effective, Some(Duration::from_micros(10)));
    assert!(p.memory_locked);
    let whats: Vec<_> = p.log.iter().map(|a| a.what.as_str()).collect();
    assert!(whats.contains(&"LinuxCpuDmaLatency(10)"), "{whats:?}");
    drop(report);
    assert_eq!(sim::process().dma_latency_effective, None);

    set_os_semantics(OsSemantics::Windows);
    let lenient = Rules {
        unsupported: Policy::Report,
        ..Rules::default()
    };
    let report = ProcessOption::apply_all(
        &[
            ProcessOption::LockMemory,
            ProcessOption::WinTimerResolution(1),
        ],
        &lenient,
    )
    .unwrap();
    let Reason::Unsupported(why) = &report.skipped[0].reason else {
        panic!("{:?}", report.skipped);
    };
    assert_eq!(
        why,
        "Windows cannot lock all memory; use WinReserveWorkingSet"
    );
    assert_eq!(
        sim::process().timer_resolution_effective,
        Some(Duration::from_millis(1))
    );
    drop(report);
    assert_eq!(sim::process().timer_resolution_effective, None);
}

#[test]
fn options_plans_and_monitor_configs_are_fast_talkers_own_types() {
    assert!(same::<ThreadOption, ::fast_talker::options::ThreadOption>());
    assert!(same::<ProcessOption, ::fast_talker::options::ProcessOption>());
    assert!(same::<Plan, ::fast_talker::plan::Plan>());
    assert!(same::<monitor::Config, ::fast_talker::monitor::Config>());
    assert!(same::<monitor::Monitor, ::fast_talker::monitor::Monitor>());
    assert!(same::<
        monitor::WatchedSocket,
        ::fast_talker::monitor::WatchedSocket,
    >());
}

fn eth0_plan() -> Plan {
    Plan {
        housekeeping_irqs: None,
        interfaces: vec![InterfacePlan {
            name: "eth0".into(),
            rx_ring: Some(1024),
            ..InterfacePlan::default()
        }],
    }
}

#[test]
fn an_unknown_interface_fails_the_plan_before_any_change() {
    setup(OsSemantics::Linux);
    let mut plan = eth0_plan();
    plan.interfaces.push(InterfacePlan {
        name: "eth9".into(),
        channels: Some(1),
        ..InterfacePlan::default()
    });
    let e = plan.apply().unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::NotFound);
    assert!(e.to_string().starts_with("eth9: open:"), "{e}");
    let eth0 = sim::interface("eth0").unwrap();
    assert!(eth0.apply_log.is_empty(), "{:?}", eth0.apply_log);
    assert_eq!(eth0.settings.rings.rx, 256);

    let records = sim::plans_applied();
    assert_eq!(records.len(), 1);
    assert!(!records[0].check);
    assert_eq!(records[0].plan, plan);
    assert!(
        records[0]
            .error
            .as_deref()
            .unwrap()
            .starts_with("eth9: open:")
    );

    let drift = plan.check();
    assert!(drift.iter().any(|d| d.interface.as_deref() == Some("eth9")
        && d.setting == "interface"
        && d.expected == "present"));
    assert!(
        sim::events()
            .iter()
            .any(|e| matches!(&e.event, FtEvent::PlanApplied { error: Some(_), .. }))
    );
}

#[test]
fn plan_settings_follow_the_emulated_os() {
    setup(OsSemantics::Windows);
    let mut plan = eth0_plan();
    plan.interfaces[0].rps_cpus = Some(vec![1]);
    let e = plan.apply().unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    assert_eq!(
        e.to_string(),
        "eth0: rps_cpus: RPS is not available on this platform"
    );
    assert_eq!(
        sim::interface("eth0").unwrap().settings.rings.rx,
        1024,
        "link settings come first"
    );
    let drift = plan.check();
    assert_eq!(drift.len(), 1);
    assert_eq!(drift[0].setting, "rps_cpus");

    set_os_semantics(OsSemantics::MacOs);
    let e = eth0_plan().apply().unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    assert!(e.to_string().starts_with("eth0: rings: "), "{e}");
}

#[test]
fn housekeeping_moves_every_interrupt_on_linux() {
    setup(OsSemantics::Linux);
    let plan = Plan {
        housekeeping_irqs: Some(vec![1, 0]),
        interfaces: Vec::new(),
    };
    Nic::open("eth0").unwrap().irqs().unwrap();
    plan.apply().unwrap();
    assert!(plan.check().is_empty(), "{:?}", plan.check());
    for irq in sim::irqs() {
        assert_eq!(irq.affinity, [0, 1], "{irq:?}");
    }
}

#[cfg(feature = "fast-talker-serde")]
#[test]
fn a_toml_plan_applies_and_drift_is_reported() {
    setup(OsSemantics::Linux);
    let plan: Plan = toml::from_str(
        r#"
        [[interfaces]]
        name = "eth0"
        rx_ring = 1024
        tx_ring = 512
        channels = 2
        rps_cpus = []
        receive = { cpus = [3], priority = 80 }
        coalesce = { adaptive_rx = false, rx_usecs = 0, rx_frames = 1 }
        "#,
    )
    .unwrap();
    plan.apply().unwrap();

    let eth0 = sim::interface("eth0").unwrap();
    let s = &eth0.settings;
    assert_eq!((s.rings.rx, s.rings.tx), (1024, 512));
    assert_eq!(s.channels.combined, 2);
    assert_eq!(
        (
            s.coalesce.adaptive_rx,
            s.coalesce.rx_usecs,
            s.coalesce.rx_frames
        ),
        (false, 0, 1)
    );
    assert!(s.threaded_napi);
    assert_eq!(
        s.rps.values().collect::<Vec<_>>(),
        [&Vec::<usize>::new(); 2]
    );
    assert_eq!(eth0.napis.len(), 2);
    for napi in &eth0.napis {
        let t = sim::thread_by_tid(napi.thread.expect("threaded")).unwrap();
        assert_eq!(t.affinity, Some(vec![3]));
        assert_eq!(t.scheduler, Some(Scheduler::Fifo(80)));
        let irq = sim::irq(napi.irq.unwrap()).unwrap();
        assert_eq!(irq.affinity, [3]);
    }
    assert!(plan.check().is_empty(), "{:?}", plan.check());

    sim::mutate_interface("eth0", |s| s.rings.rx = 256).unwrap();
    let drift = plan.check();
    assert_eq!(drift.len(), 1, "{drift:?}");
    assert_eq!(drift[0].interface.as_deref(), Some("eth0"));
    assert_eq!(drift[0].setting, "rx_ring");
    assert_eq!(
        (drift[0].expected.as_str(), drift[0].actual.as_str()),
        ("1024", "256")
    );
    assert_eq!(
        drift[0].to_string(),
        "eth0: rx_ring: expected 1024, found 256"
    );

    let records = sim::plans_applied();
    assert_eq!(records.len(), 3);
    assert!(!records[0].check && records[0].error.is_none());
    assert!(records[2].check);
    assert_eq!(records[2].drift, drift);
}

#[test]
fn options_for_a_snare_thread_from_a_thread_with_no_slot_fail_cleanly() {
    setup(OsSemantics::Linux);
    let thread = rt::Thread::current();
    let kind = std::thread::spawn(move || {
        let e = compat::apply_thread_options_to(
            thread,
            &[ThreadOption::RtPriority(10)],
            &Rules::default(),
        )
        .unwrap_err();
        match e.failure {
            Failure::Failed(err) => err.kind(),
            other => panic!("{other:?}"),
        }
    })
    .join()
    .unwrap();
    assert_eq!(kind, io::ErrorKind::NotFound);
    assert_eq!(me().scheduler, None);
}
