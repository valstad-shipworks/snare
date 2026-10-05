//! fast-talker's `Monitor` under the shim: a background snare thread
//! sampling snare's NICs, counters and sockets on virtual time.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, SystemTime};

use snare::fast_talker::monitor::{Config, Monitor, Sample, WatchedSocket};
use snare::fast_talker::options::ThreadOption;
use snare::fast_talker::plan::{InterfacePlan, Plan};
use snare::fast_talker::rt::QosClass;
use snare::fast_talker::sim::{self, FtEvent};
use snare::net::UdpSocket;
use snare::sched::testkit::{StrictClock, StrictConfig};
use snare::sched::{self, ThreadClass};
use snare::time::Instant;
use snare::{
    IpNet, NicSpec, OsSemantics, add_nic, advance_time, pause_time, register_test, set_nic_policy,
    set_os_semantics, socket_id,
};

const WAIT: Duration = Duration::from_secs(5);

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn setup(os: OsSemantics) {
    register_test();
    set_os_semantics(os);
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/24"))).unwrap();
    add_nic(NicSpec::new("eth1").address(net("10.0.1.1/24"))).unwrap();
}

fn virtual_wall() -> SystemTime {
    snare::time::SystemTime::now().into()
}

#[test]
fn samples_follow_virtual_time_and_record_the_whole_config() {
    setup(OsSemantics::Linux);
    pause_time();
    let rx = UdpSocket::bind("10.0.1.1:5000").unwrap();
    let tx = UdpSocket::bind("10.0.0.1:0").unwrap();
    let plan = Plan {
        housekeeping_irqs: None,
        interfaces: vec![InterfacePlan {
            name: "eth1".into(),
            rx_ring: Some(256),
            ..InterfacePlan::default()
        }],
    };
    let (samples_tx, samples) = mpsc::channel::<Sample>();
    let monitor = Monitor::start(
        Config {
            interval: Duration::from_millis(100),
            interfaces: vec!["eth1".into()],
            sockets: vec![WatchedSocket::new("rx", &rx).unwrap()],
            plan: Some(plan.clone()),
            plan_every: 2,
            ..Config::default()
        },
        move |s| {
            let _ = samples_tx.send(s.clone());
        },
    )
    .unwrap();

    let first = samples.recv_timeout(WAIT).unwrap();
    assert_eq!(first.sequence, 0);
    assert_eq!(first.time, virtual_wall());
    assert!(first.interfaces[0].link.is_some());
    assert!(first.interfaces[0].link_delta.is_none());
    assert!(first.sockets[0].memory.is_some());
    assert_eq!(first.drift, Some(Vec::new()));
    assert!(first.errors.is_empty(), "{:?}", first.errors);

    set_nic_policy("eth1", |p| p.loss_rate = 1.0).unwrap();
    for _ in 0..3 {
        tx.send_to(b"lost", addr("10.0.1.1:5000")).unwrap();
    }

    let mut all = vec![first];
    for step in 1..=3u64 {
        advance_time(Duration::from_millis(100));
        let s = samples.recv_timeout(WAIT).unwrap();
        assert_eq!(s.sequence, step);
        assert_eq!(s.time, virtual_wall());
        assert_eq!(s.elapsed, Duration::from_millis(100));
        all.push(s);
    }
    let second = &all[1];
    assert_eq!(second.interfaces[0].link_delta.unwrap().rx_dropped, 3);
    assert!(second.has_loss());
    assert!(second.udp.is_some());
    assert!(second.drift.is_none());
    assert_eq!(all[2].drift, Some(Vec::new()));
    assert_eq!(all[3].interfaces[0].link_delta.unwrap().rx_dropped, 0);

    let thread = sim::thread_named("fast-talker-mon").unwrap();
    assert_eq!(thread.class, ThreadClass::Background);
    assert_eq!(thread.nice, Some(19), "the default thread options applied");

    monitor.stop();
    let record = sim::monitors().pop().unwrap();
    assert!(record.stopped_at.is_some());
    assert_eq!(record.thread_tid, Some(thread.tid));
    assert_eq!(record.samples, 4);
    assert_eq!(record.interval, Duration::from_millis(100));
    assert_eq!(record.interfaces, ["eth1"]);
    assert_eq!(record.sockets, [("rx".to_string(), socket_id(&rx), false)]);
    assert!(record.protocol_counters && record.queue_stats && !record.driver_stats);
    assert_eq!(record.clock_every, None);
    assert_eq!(record.plan, Some(plan));
    assert_eq!(record.plan_every, 2);
    assert_eq!(record.thread, Config::default().thread);
    assert_eq!(record.last_sample.unwrap().sequence, 3);
    assert!(sim::thread_named("fast-talker-mon").unwrap().exited);

    advance_time(Duration::from_millis(500));
    assert!(samples.try_recv().is_err(), "no samples after stop");
    assert!(
        sim::events()
            .iter()
            .any(|e| matches!(e.event, FtEvent::MonitorStopped { id } if id == record.id))
    );
}

#[test]
fn unknown_interfaces_fail_at_start() {
    setup(OsSemantics::Linux);
    let e = Monitor::start(
        Config {
            interfaces: vec!["eth9".into()],
            ..Config::default()
        },
        |_| {},
    )
    .unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::NotFound);
    assert!(sim::monitors().is_empty());
}

#[test]
fn os_sockets_and_unsupported_sources_are_reported_as_fast_talker_does() {
    setup(OsSemantics::MacOs);
    pause_time();
    let os_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let (samples_tx, samples) = mpsc::channel::<Sample>();
    let monitor = Monitor::start(
        Config {
            interval: Duration::from_millis(10),
            interfaces: vec!["eth0".into()],
            sockets: vec![WatchedSocket::new("os", &os_socket).unwrap()],
            thread: vec![ThreadOption::MacOsQos(QosClass::Utility)],
            ..Config::default()
        },
        move |s| {
            let _ = samples_tx.send(s.clone());
        },
    )
    .unwrap();
    let first = samples.recv_timeout(WAIT).unwrap();
    let os = first
        .errors
        .iter()
        .find(|e| e.owner.as_deref() == Some("os"))
        .expect("the OS socket is reported");
    assert_eq!(os.source, "memory");
    assert!(os.disabled);
    assert!(first.sockets[0].memory.is_none());
    advance_time(Duration::from_millis(10));
    let second = samples.recv_timeout(WAIT).unwrap();
    assert!(second.errors.is_empty(), "{:?}", second.errors);
    assert_eq!(
        sim::thread_named("fast-talker-mon").unwrap().qos,
        Some(QosClass::Utility)
    );
    drop(monitor);
    assert!(sim::monitors()[0].sockets.is_empty());
}

#[test]
fn a_monitor_dropped_inside_a_driver_timestamp_does_not_deadlock() {
    setup(OsSemantics::Linux);
    let clock = StrictClock::start(StrictConfig::default()).unwrap();
    let (samples_tx, samples) = mpsc::channel::<u64>();
    let monitor = Monitor::start(
        Config {
            interval: Duration::from_millis(50),
            ..Config::default()
        },
        move |s| {
            let _ = samples_tx.send(s.sequence);
        },
    )
    .unwrap();
    samples.recv_timeout(WAIT).unwrap();
    sched::with_driver_time(clock.now(), move || drop(monitor));
    let deadline = std::time::Instant::now() + WAIT;
    while !sim::thread_named("fast-talker-mon").unwrap().exited {
        assert!(
            std::time::Instant::now() < deadline,
            "monitor thread still running"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(sim::monitors()[0].stopped_at.is_some());
}

#[test]
fn virtual_time_stands_still_while_a_sample_is_handled() {
    setup(OsSemantics::Linux);
    let _clock = StrictClock::start(StrictConfig::default()).unwrap();
    let ticking = Arc::new(AtomicBool::new(true));
    let ticker = {
        let ticking = Arc::clone(&ticking);
        snare::thread::spawn(move || {
            while ticking.load(Ordering::Relaxed) {
                snare::thread::sleep(Duration::from_micros(100));
            }
        })
    };
    let tx = UdpSocket::bind("10.0.0.1:0").unwrap();
    let _rx = UdpSocket::bind("10.0.1.1:6000").unwrap();
    let (spans_tx, spans) = mpsc::channel::<(Instant, Instant)>();
    let monitor = Monitor::start(
        Config {
            interval: Duration::from_millis(20),
            interfaces: vec!["eth0".into()],
            ..Config::default()
        },
        move |_| {
            let entry = Instant::now();
            tx.send_to(b"sample", addr("10.0.1.1:6000")).unwrap();
            std::thread::sleep(Duration::from_millis(2));
            let _ = spans_tx.send((entry, Instant::now()));
        },
    )
    .unwrap();
    let mut seen = Vec::new();
    for _ in 0..8 {
        seen.push(spans.recv_timeout(WAIT).unwrap());
    }
    monitor.stop();
    ticking.store(false, Ordering::Relaxed);
    ticker.join().unwrap();
    for (entry, exit) in &seen {
        assert_eq!(entry, exit);
    }
    for pair in seen.windows(2) {
        assert!(pair[1].0 - pair[0].0 >= Duration::from_millis(20));
    }
}

#[test]
fn a_real_monitor_off_snare_threads_is_untouched() {
    register_test();
    let (samples_tx, samples) = mpsc::channel::<Sample>();
    let host = std::thread::spawn(move || {
        ::fast_talker::monitor::Monitor::start(
            ::fast_talker::monitor::Config {
                interval: Duration::from_millis(20),
                thread: Vec::new(),
                ..::fast_talker::monitor::Config::default()
            },
            move |s| {
                let _ = samples_tx.send(s.clone());
            },
        )
        .unwrap()
    })
    .join()
    .unwrap();
    let first = samples.recv_timeout(WAIT).unwrap();
    let second = samples.recv_timeout(WAIT).unwrap();
    drop(host);
    assert_eq!((first.sequence, second.sequence), (0, 1));
    assert!(second.elapsed >= Duration::from_millis(10), "real time");
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        assert!(second.counters.is_some());
    }
    assert!(sim::monitors().is_empty());
    assert!(sim::thread_named("fast-talker-mon").is_none());
}
