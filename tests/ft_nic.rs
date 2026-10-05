//! fast-talker's `nic` and `irq` under the shim, over snare's own NICs:
//! validation and privileges per emulated OS, kernel objects, flow
//! steering in the data path, qdiscs, PTP, counters and the Windows
//! adapter restart.

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use snare::fast_talker::irq::{self, Irq};
use snare::fast_talker::nic::{
    Channels, Coalesce, Etf, FlowAction, FlowMatch, FlowProtocol, FlowRule, Nic, QueueKind, Rings,
    Rss,
};
use snare::fast_talker::rt::{self, Scheduler};
use snare::fast_talker::sim::{self, FtEvent, PtpSeed};
use snare::fast_talker::{Config, Hardware, Timestamped, TxTime, compat};
use snare::net::{TcpListener, TcpStream, UdpSocket};
use snare::sched::testkit::{StrictClock, StrictConfig};
use snare::{
    CoalesceSupport, IpNet, NicCaps, NicSpec, OsSemantics, add_ip_addr, add_nic, advance_time,
    os_error_code, pause_time, register_test, set_nic_counters, set_nic_policy, set_os_semantics,
    set_privileges,
};

const LATENCY: Duration = Duration::from_millis(5);

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

/// A fresh slot on `os` with a paused clock, `eth0` at 10.0.0.1 with
/// `caps` and `eth1` at 10.0.0.2.
fn setup(os: OsSemantics, caps: NicCaps) -> Nic {
    register_test();
    set_os_semantics(os);
    pause_time();
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/24")).caps(caps)).unwrap();
    add_nic(NicSpec::new("eth1").address(net("10.0.0.2/24"))).unwrap();
    Nic::open("eth0").unwrap()
}

fn code<T: std::fmt::Debug>(r: io::Result<T>) -> Option<i32> {
    os_error_code(&r.unwrap_err())
}

fn unsupported<T: std::fmt::Debug>(r: io::Result<T>) {
    assert_eq!(r.unwrap_err().kind(), io::ErrorKind::Unsupported);
}

fn live_kernel_threads(prefix: &str, nic: &str) -> Vec<sim::ThreadSnapshot> {
    sim::threads()
        .into_iter()
        .filter(|t| t.kernel && !t.exited)
        .filter(|t| {
            t.name
                .as_deref()
                .is_some_and(|n| n.starts_with(prefix) && n.contains(nic))
        })
        .collect()
}

#[test]
fn rings_are_validated_and_need_net_admin() {
    let nic = setup(OsSemantics::Linux, NicCaps::default());
    let r = nic.rings().unwrap();
    assert_eq!((r.rx, r.rx_max, r.tx, r.tx_max), (256, 4096, 256, 4096));

    assert_eq!(
        code(nic.set_rings(&Rings { rx: 8192, ..r })),
        Some(22),
        "over rx_max"
    );
    assert_eq!(code(nic.set_rings(&Rings { tx: 0, ..r })), Some(22));
    nic.set_rings(&Rings { rx: 1024, ..r }).unwrap();
    assert_eq!(nic.rings().unwrap().rx, 1024);

    set_privileges(|p| p.net_admin = false);
    let e = nic.set_rings(&Rings { rx: 512, ..r }).unwrap_err();
    assert_eq!(os_error_code(&e), Some(1));
    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(nic.rings().unwrap().rx, 1024, "reading needs nothing");

    let snap = sim::interface("eth0").unwrap();
    assert_eq!(snap.settings.rings.rx, 1024);
    let results: Vec<_> = snap
        .apply_log
        .iter()
        .map(|a| (a.result, a.os_error))
        .collect();
    assert_eq!(
        results,
        [
            (Err(io::ErrorKind::InvalidInput), Some(22)),
            (Err(io::ErrorKind::InvalidInput), Some(22)),
            (Ok(()), None),
            (Err(io::ErrorKind::PermissionDenied), Some(1)),
        ]
    );
    assert!(snap.apply_log[2].what.starts_with("set_rings("));
    assert_eq!(
        sim::events()
            .iter()
            .filter(|e| matches!(&e.event, FtEvent::Nic { nic, .. } if nic == "eth0"))
            .count(),
        4
    );

    assert_eq!(code(Nic::open("lo").unwrap().rings()), Some(95));
    set_os_semantics(OsSemantics::MacOs);
    unsupported(nic.rings());
}

#[test]
fn coalescing_follows_the_drivers_mask_and_limits() {
    let caps = NicCaps {
        coalesce_supported: CoalesceSupport::RX_USECS
            | CoalesceSupport::RX_MAX_FRAMES
            | CoalesceSupport::USE_ADAPTIVE_RX,
        coalesce_usecs_max: 100,
        coalesce_frames_max: 64,
        ..NicCaps::default()
    };
    let nic = setup(OsSemantics::Linux, caps);
    let c = nic.coalesce().unwrap();
    assert!(c.adaptive_rx && !c.adaptive_tx);
    assert_eq!((c.rx_usecs, c.tx_usecs), (3, 0));
    nic.set_coalesce(&c).unwrap();

    assert_eq!(
        code(nic.set_coalesce(&Coalesce { tx_usecs: 5, ..c })),
        Some(95)
    );
    assert_eq!(
        code(nic.set_coalesce(&Coalesce {
            adaptive_tx: true,
            ..c
        })),
        Some(95)
    );
    assert_eq!(
        code(nic.set_coalesce(&Coalesce { rx_usecs: 101, ..c })),
        Some(22)
    );
    assert_eq!(
        code(nic.set_coalesce(&Coalesce { rx_frames: 65, ..c })),
        Some(22)
    );
    let low = Coalesce {
        adaptive_rx: false,
        rx_usecs: 0,
        rx_frames: 1,
        ..c
    };
    nic.set_coalesce(&low).unwrap();
    assert_eq!(nic.coalesce().unwrap(), low);

    let none = NicCaps {
        coalesce_supported: CoalesceSupport::NONE,
        ..NicCaps::default()
    };
    add_nic(NicSpec::new("eth2").address(net("10.0.2.1/24")).caps(none)).unwrap();
    assert_eq!(code(Nic::open("eth2").unwrap().coalesce()), Some(95));
}

#[test]
fn set_channels_recreates_interrupts_napis_and_kernel_threads() {
    let nic = setup(OsSemantics::Linux, NicCaps::default());
    let before = nic.irqs().unwrap();
    assert_eq!(before.len(), 4);
    let napis = nic.napis().unwrap();
    assert_eq!(napis.len(), 4);
    assert!(napis.iter().all(|n| n.id >= 8193 && n.thread.is_none()));
    assert_eq!(
        napis.iter().map(|n| n.irq).collect::<Vec<_>>(),
        nic.queue_irqs()
            .unwrap()
            .into_iter()
            .map(Some)
            .collect::<Vec<_>>()
    );
    assert_eq!(before[0].name().unwrap(), "eth0-TxRx-0");
    assert_eq!(live_kernel_threads("irq/", "eth0").len(), 4);
    let irq_thread = sim::thread_named(&format!("irq/{}-eth0-TxRx-0", before[0].number())).unwrap();
    assert_eq!(irq_thread.scheduler, Some(Scheduler::Fifo(50)));
    assert!(sim::thread_named("ksoftirqd/7").is_some_and(|t| t.kernel));
    let found = rt::Thread::find(&format!("irq/{}-", before[0].number())).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id(), irq_thread.tid);

    let c = nic.channels().unwrap();
    assert_eq!((c.combined, c.combined_max), (4, 8));
    assert_eq!(
        code(nic.set_channels(&Channels { combined: 9, ..c })),
        Some(22)
    );
    nic.set_channels(&Channels { combined: 2, ..c }).unwrap();
    let after = nic.irqs().unwrap();
    assert_eq!(after.len(), 2);
    assert!(after.iter().all(|i| !before.contains(i)), "new numbers");
    assert_eq!(nic.rx_queues().unwrap(), 2);
    let new_napis = nic.napis().unwrap();
    assert_eq!(new_napis.len(), 2);
    assert!(new_napis.iter().all(|n| napis.iter().all(|o| o.id != n.id)));
    assert_eq!(live_kernel_threads("irq/", "eth0").len(), 2);
    assert!(
        sim::thread_by_tid(irq_thread.tid).is_some_and(|t| t.exited),
        "the old handler threads exited"
    );
    assert_eq!(
        code(Irq::new(before[0].number()).affinity()),
        Some(2),
        "the old vector is gone"
    );
}

#[test]
fn threaded_napi_is_linux_only() {
    let nic = setup(OsSemantics::Linux, NicCaps::default());
    assert!(!nic.threaded_napi().unwrap());
    nic.set_threaded_napi(true).unwrap();
    let napis = nic.napis().unwrap();
    assert!(napis.iter().all(|n| n.thread.is_some()));
    let name = napis[0].thread.unwrap().name().unwrap();
    assert_eq!(name, format!("napi/eth0-{}", napis[0].id));
    assert_eq!(rt::Thread::find("napi/eth0-").unwrap().len(), 4);
    nic.set_threaded_napi(false).unwrap();
    assert!(nic.napis().unwrap().iter().all(|n| n.thread.is_none()));
    assert!(rt::Thread::find("napi/eth0-").unwrap().is_empty());

    add_nic(
        NicSpec::new("eth2")
            .address(net("10.0.2.1/24"))
            .caps(NicCaps {
                threaded_napi: false,
                ..NicCaps::default()
            }),
    )
    .unwrap();
    assert_eq!(
        code(Nic::open("eth2").unwrap().set_threaded_napi(true)),
        Some(95)
    );
    set_privileges(|p| p.root = false);
    assert_eq!(code(nic.set_threaded_napi(true)), Some(13), "sysfs");
    set_privileges(|p| {
        p.root = true;
        p.net_admin = false;
    });
    assert_eq!(code(nic.set_threaded_napi(true)), Some(1));

    for os in [OsSemantics::MacOs, OsSemantics::Windows] {
        set_os_semantics(os);
        unsupported(nic.threaded_napi());
        unsupported(nic.set_threaded_napi(true));
        unsupported(nic.napis());
    }
}

#[test]
fn pinning_a_napi_shows_on_its_interrupt_and_threads() {
    let nic = setup(OsSemantics::Linux, NicCaps::default());
    nic.set_threaded_napi(true).unwrap();
    let napi = nic.napis().unwrap()[1];
    napi.pin(&[2], Scheduler::Fifo(60)).unwrap();

    let irq = napi.irq.unwrap();
    assert_eq!(irq.affinity().unwrap(), [2]);
    assert_eq!(irq.effective_affinity().unwrap(), [2]);
    let isnap = sim::irq(irq.number()).unwrap();
    assert_eq!(isnap.nic.as_deref(), Some("eth0"));
    assert_eq!(isnap.affinity, [2]);
    assert_eq!(isnap.log.len(), 1);
    let handler = sim::thread_by_tid(isnap.threads[0]).unwrap();
    assert_eq!(handler.scheduler, Some(Scheduler::Fifo(60)));
    assert_eq!(handler.affinity, Some(vec![2]));

    let thread = napi.thread.unwrap();
    let tsnap = sim::thread_by_tid(thread.id()).unwrap();
    assert_eq!(tsnap.scheduler, Some(Scheduler::Fifo(60)));
    assert_eq!(tsnap.affinity, Some(vec![2]));

    let nsnap = &sim::interface("eth0").unwrap().napis[1];
    assert_eq!(nsnap.id, napi.id);
    assert_eq!(nsnap.queue, 1);
    assert_eq!(nsnap.irq_affinity, Some(vec![2]));
    assert_eq!(nsnap.thread_scheduler, Some(Scheduler::Fifo(60)));
    assert_eq!(nsnap.thread_affinity, Some(vec![2]));
    assert_eq!(
        nsnap.thread_name.as_deref(),
        Some(format!("napi/eth0-{}", napi.id).as_str())
    );
}

fn udp_rule(dst_port: u16, action: FlowAction) -> FlowRule {
    FlowRule {
        matches: FlowMatch::Ip {
            protocol: FlowProtocol::Udp,
            ipv6: false,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: Some(dst_port),
        },
        action,
        location: None,
    }
}

fn recv_all(s: &UdpSocket) -> usize {
    let mut buf = [0u8; 64];
    let mut n = 0;
    while s.recv_from(&mut buf).is_ok() {
        n += 1;
    }
    n
}

#[test]
fn flow_rules_steer_and_drop_traffic() {
    let caps = NicCaps {
        ntuple: true,
        flow_rule_slots: 2,
        ..NicCaps::default()
    };
    let nic = setup(OsSemantics::Linux, caps);
    let drop = udp_rule(7000, FlowAction::Drop);
    assert_eq!(code(nic.add_flow_rule(&drop)), Some(95), "ntuple off");
    nic.set_ntuple(true).unwrap();
    assert_eq!(nic.add_flow_rule(&drop).unwrap(), 0);
    assert_eq!(
        nic.add_flow_rule(&udp_rule(7001, FlowAction::Queue(3)))
            .unwrap(),
        1
    );
    let full = nic
        .add_flow_rule(&udp_rule(7002, FlowAction::Drop))
        .unwrap_err();
    assert!(full.to_string().contains("table is full"), "{full}");
    assert_eq!(
        code(nic.add_flow_rule(&FlowRule {
            location: Some(1),
            ..udp_rule(7003, FlowAction::Queue(9))
        })),
        Some(22),
        "no queue 9"
    );
    let rules = nic.flow_rules().unwrap();
    assert_eq!(rules.len(), 2);
    assert!(rules[0].same_as(&FlowRule {
        location: Some(0),
        ..drop
    }));

    let rx = UdpSocket::bind("10.0.0.1:7000").unwrap();
    rx.set_nonblocking(true).unwrap();
    let steered = UdpSocket::bind("10.0.0.1:7001").unwrap();
    steered.set_nonblocking(true).unwrap();
    let tx = UdpSocket::bind("10.0.0.2:5000").unwrap();
    for _ in 0..3 {
        tx.send_to(b"x", addr("10.0.0.1:7000")).unwrap();
    }
    snare::inject_udp_from_test(addr("10.0.0.9:1"), addr("10.0.0.1:7000"), b"y".to_vec());
    assert_eq!(recv_all(&rx), 0);
    let counters = snare::nic_counters("eth0").unwrap();
    assert_eq!(counters.rx_dropped, 4);
    assert_eq!(counters.rx_packets, 0);
    assert_eq!(nic.link_stats().unwrap().rx_dropped, 4);

    tx.send_to(b"z", addr("10.0.0.1:7001")).unwrap();
    assert_eq!(recv_all(&steered), 1);
    let napi = nic.napi_for_socket(&steered).unwrap().unwrap();
    assert_eq!(napi, nic.napis().unwrap()[3]);
    assert_eq!(nic.napi_for_socket(&rx).unwrap(), None, "nothing arrived");
    assert_eq!(
        Nic::open("eth1")
            .unwrap()
            .napi_for_socket(&steered)
            .unwrap(),
        None,
        "another interface"
    );

    nic.remove_flow_rule(0).unwrap();
    assert_eq!(code(nic.remove_flow_rule(0)), Some(2));
    tx.send_to(b"x", addr("10.0.0.1:7000")).unwrap();
    assert_eq!(recv_all(&rx), 1);

    nic.set_ntuple(false).unwrap();
    assert!(nic.flow_rules().unwrap().is_empty());
    set_privileges(|p| p.net_admin = false);
    assert_eq!(code(nic.set_ntuple(true)), Some(1));
}

fn timed() -> Config {
    Config {
        hardware: Hardware::Off,
        txtime: Some(TxTime::Launch),
        ..Config::default()
    }
}

#[test]
fn etf_holds_timed_sends_until_their_launch() {
    let caps = NicCaps {
        combined_channels: 2,
        ..NicCaps::default()
    };
    let nic = setup(OsSemantics::Linux, caps);
    let kinds = |n: &Nic| -> Vec<(String, u32, u32)> {
        n.qdiscs()
            .unwrap()
            .into_iter()
            .map(|q| (q.kind.clone(), q.handle, q.parent))
            .collect()
    };
    assert_eq!(
        kinds(&nic),
        [
            ("mq".into(), 0, 0xffff_ffff),
            ("pfifo_fast".into(), 0, 1),
            ("pfifo_fast".into(), 0, 2),
        ]
    );
    let offload = Etf {
        offload: true,
        ..Etf::default()
    };
    assert_eq!(code(nic.set_etf(Some(1), &offload)), Some(95));
    nic.set_etf(Some(1), &Etf::default()).unwrap();
    let tree = kinds(&nic);
    assert_eq!(tree[0], ("mq".into(), 0x7ff0_0000, 0xffff_ffff));
    assert_eq!(tree[2].0, "etf");
    assert_eq!(tree[2].2, 0x7ff0_0002);
    assert_eq!(code(nic.set_etf(Some(5), &Etf::default())), Some(2));
    nic.restore_qdisc(Some(1)).unwrap();
    assert_eq!(kinds(&nic)[2].0, "pfifo_fast");
    nic.restore_qdisc(None).unwrap();
    assert_eq!(kinds(&nic)[0], ("mq".into(), 0, 0xffff_ffff));

    set_privileges(|p| p.net_admin = false);
    assert_eq!(code(nic.set_etf(None, &Etf::default())), Some(1));
    set_privileges(|p| p.net_admin = true);
    nic.set_etf(None, &Etf::default()).unwrap();
    assert!(nic.qdiscs().unwrap()[0].is_root());
    assert_eq!(nic.qdiscs().unwrap()[0].kind, "etf");
    let err = nic.set_etf(Some(0), &Etf::default()).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "root is etf");

    set_nic_policy("eth1", |p| p.latency = LATENCY).unwrap();
    let tx = Timestamped::with_config(UdpSocket::bind("10.0.0.1:7001").unwrap(), timed());
    let rx = UdpSocket::bind("10.0.0.2:7000").unwrap();
    rx.set_nonblocking(true).unwrap();
    let launch = compat::now() + Duration::from_millis(10);
    tx.send_to_at(b"x", addr("10.0.0.2:7000"), launch).unwrap();
    advance_time(Duration::from_millis(9) + LATENCY);
    assert_eq!(recv_all(&rx), 0, "held until launch");
    advance_time(Duration::from_millis(1));
    assert_eq!(recv_all(&rx), 1);
    assert!(
        !sim::events()
            .iter()
            .any(|e| matches!(e.event, FtEvent::TxTimeWithoutEtf { .. }))
    );
}

#[test]
fn clock_offset_reads_the_seeded_ptp_clock() {
    let caps = NicCaps {
        hw_rx_timestamp: true,
        phc_index: Some(0),
        ..NicCaps::default()
    };
    let nic = setup(OsSemantics::Linux, caps);
    assert_eq!(nic.ptp_clock().unwrap(), Some(0));
    sim::set_tai_offset(Duration::from_secs(37));
    sim::set_ptp(
        "eth0",
        PtpSeed {
            clock: 3,
            offset_nanos: 500,
            uncertainty: Duration::from_nanos(20),
            tai: true,
        },
    )
    .unwrap();
    assert_eq!(nic.ptp_clock().unwrap(), Some(3));
    let off = nic.clock_offset().unwrap();
    assert_eq!(off.clock, 3);
    assert_eq!(off.offset_nanos, 37_000_000_500);
    assert_eq!(off.tai_offset, Duration::from_secs(37));
    assert_eq!(off.effective_offset_nanos(), 500);
    assert!(off.is_disciplined(Duration::from_micros(1)));
    assert!(!off.is_disciplined(Duration::from_nanos(500)));
    assert_eq!(off.uncertainty, Duration::from_nanos(20));

    let plain = Nic::open("eth1").unwrap();
    assert_eq!(plain.ptp_clock().unwrap(), None);
    let e = plain.clock_offset().unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    assert!(e.to_string().contains("eth1 has no PTP hardware clock"));

    set_privileges(|p| p.root = false);
    assert_eq!(code(nic.clock_offset()), Some(13));
    set_os_semantics(OsSemantics::MacOs);
    unsupported(nic.clock_offset());
}

#[test]
fn link_stats_follow_traffic_and_injections() {
    let nic = setup(OsSemantics::Linux, NicCaps::default());
    let rx = UdpSocket::bind("10.0.0.1:7000").unwrap();
    rx.set_nonblocking(true).unwrap();
    let tx = UdpSocket::bind("10.0.0.2:5000").unwrap();
    let before = nic.link_stats().unwrap();
    for _ in 0..3 {
        tx.send_to(b"hello", addr("10.0.0.1:7000")).unwrap();
    }
    assert_eq!(recv_all(&rx), 3);
    let after = nic.link_stats().unwrap();
    let d = after.since(&before);
    assert_eq!((d.rx_packets, d.rx_bytes), (3, 15));
    assert!(!d.has_loss());
    let out = Nic::open("eth1").unwrap().link_stats().unwrap();
    assert_eq!((out.tx_packets, out.tx_bytes), (3, 15));

    set_nic_counters("eth0", |c| {
        c.rx_missed_errors += 7;
        c.rx_over_errors += 2;
    })
    .unwrap();
    let later = nic.link_stats().unwrap();
    let d = later.since(&after);
    assert_eq!((d.rx_missed_errors, d.rx_over_errors), (7, 2));
    assert!(d.has_loss());

    set_os_semantics(OsSemantics::Windows);
    let win = nic.link_stats().unwrap();
    assert_eq!((win.rx_missed_errors, win.rx_over_errors), (7, 0));
    set_os_semantics(OsSemantics::MacOs);
    let mac = nic.link_stats().unwrap();
    assert_eq!((mac.rx_packets, mac.rx_missed_errors), (3, 0));
}

#[test]
fn driver_stats_refresh_sees_traffic_and_seeds() {
    let nic = setup(OsSemantics::Linux, NicCaps::default());
    let mut stats = nic.driver_stats().unwrap();
    assert_eq!(stats.get("rx_packets"), Some(0));
    let names = stats.names().to_vec();

    let rx = UdpSocket::bind("10.0.0.1:7000").unwrap();
    let tx = UdpSocket::bind("10.0.0.2:5000").unwrap();
    tx.send_to(b"x", addr("10.0.0.1:7000")).unwrap();
    sim::bump_driver_stat("eth0", "rx_missed_errors", 5).unwrap();
    sim::bump_driver_stat("eth0", "rx_missed_errors", 1).unwrap();
    stats.refresh(&nic).unwrap();
    assert_eq!(stats.get("rx_packets"), Some(1));
    assert_eq!(stats.get("rx_missed_errors"), Some(6));
    assert_eq!(stats.names(), names.as_slice());

    sim::set_driver_stats("eth0", vec![("rx_queue_0_drops".into(), 9)]).unwrap();
    stats.refresh(&nic).unwrap();
    assert_eq!(stats.len(), names.len() + 1);
    assert_eq!(stats.get("rx_queue_0_drops"), Some(9));
    drop(rx);

    add_nic(
        NicSpec::new("eth2")
            .address(net("10.0.2.1/24"))
            .caps(NicCaps {
                driver_stats: vec!["port.rx_dropped".into(), "rx_packets".into()],
                ..NicCaps::default()
            }),
    )
    .unwrap();
    let own = Nic::open("eth2").unwrap().driver_stats().unwrap();
    assert_eq!(own.names(), ["port.rx_dropped", "rx_packets"]);
    assert!(Nic::open("lo").unwrap().driver_stats().unwrap().is_empty());

    set_os_semantics(OsSemantics::MacOs);
    stats.refresh(&nic).unwrap();
    assert!(stats.get("rx_queue_drops").is_some());
    assert_eq!(stats.get("rx_packets"), Some(1));
}

#[test]
fn set_all_affinity_moves_every_interrupt_and_needs_privilege() {
    let nic = setup(OsSemantics::Linux, NicCaps::default());
    sim::set_irq(9, "acpi", None).unwrap();
    let all = Irq::all().unwrap();
    assert!(all.len() >= 9, "snare0, eth0, eth1 and acpi: {all:?}");
    assert_eq!(irq::default_affinity().unwrap(), (0..8).collect::<Vec<_>>());

    assert_eq!(irq::set_all_affinity(&[0, 1]).unwrap(), all.len());
    assert_eq!(irq::default_affinity().unwrap(), [0, 1]);
    assert!(all.iter().all(|i| i.affinity().unwrap() == [0, 1]));
    assert_eq!(Irq::new(9).name().unwrap(), "acpi");
    assert_eq!(code(irq::set_all_affinity(&[99])), Some(22));

    set_privileges(|p| {
        p.root = false;
        p.net_admin = false;
    });
    assert_eq!(code(irq::set_all_affinity(&[2])), Some(13));
    let q = nic.irqs().unwrap()[0];
    assert_eq!(code(q.set_affinity(&[2])), Some(13));
    assert_eq!(q.affinity().unwrap(), [0, 1], "nothing moved");
    assert_eq!(code(nic.set_irq_affinity(&[2])), Some(13));
    set_privileges(|p| p.net_admin = true);
    nic.set_irq_affinity(&[3]).unwrap();
    assert!(
        nic.irqs()
            .unwrap()
            .iter()
            .all(|i| i.affinity().unwrap() == [3])
    );
    assert_eq!(code(Irq::new(9999).affinity()), Some(2));
    let refused = sim::events()
        .iter()
        .filter(|e| matches!(&e.event, FtEvent::Irq { result: Err(_), .. }))
        .count();
    assert_eq!(refused, 4);

    set_os_semantics(OsSemantics::MacOs);
    unsupported(Irq::all());
    unsupported(irq::set_all_affinity(&[0]));
}

#[test]
fn with_address_finds_the_nic_an_address_lives_on() {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    add_ip_addr("192.168.5.5".parse().unwrap());
    let nic = Nic::with_address("192.168.5.5".parse().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(nic.name(), "snare0");
    assert_eq!(nic.index(), 2);
    assert_eq!(
        Nic::with_address("127.0.0.1".parse().unwrap())
            .unwrap()
            .unwrap()
            .name(),
        "lo"
    );
    assert!(
        Nic::with_address("192.168.9.9".parse().unwrap())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        Nic::open("lo0").unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    set_os_semantics(OsSemantics::MacOs);
    assert_eq!(Nic::open("lo0").unwrap().index(), 1);
    assert!(Nic::open("lo").is_err());
}

#[test]
fn windows_adapter_settings_restart_the_adapter() {
    let nic = setup(OsSemantics::Windows, NicCaps::default());
    assert_eq!(nic.rss().unwrap().base_cpu, None);
    assert!(nic.rss().unwrap().enabled);
    let rss = Rss {
        enabled: true,
        base_cpu: Some(2),
        max_cpu: None,
        max_processors: Some(2),
    };
    nic.set_rss(&rss).unwrap();
    assert_eq!(nic.rss().unwrap(), rss);
    assert!(!nic.link_up().unwrap(), "the adapter restarts");
    advance_time(Duration::from_secs(2));
    assert!(nic.link_up().unwrap());

    assert_eq!(nic.irq_affinity().unwrap(), None);
    nic.set_irq_affinity(&[3, 1]).unwrap();
    assert_eq!(nic.irq_affinity().unwrap(), Some(vec![1, 3]));
    advance_time(Duration::from_secs(2));
    nic.set_irq_affinity(&[]).unwrap();
    assert_eq!(nic.irq_affinity().unwrap(), None);
    advance_time(Duration::from_secs(2));
    assert!(nic.tx_timestamping().unwrap());
    unsupported(nic.irqs());
    unsupported(nic.flow_rules());

    set_privileges(|p| p.root = false);
    assert_eq!(code(nic.set_rss(&rss)), Some(5));
    set_privileges(|p| p.root = true);

    let tx = UdpSocket::bind("10.0.0.1:5000").unwrap();
    let rx = UdpSocket::bind("10.0.0.2:7000").unwrap();
    rx.set_nonblocking(true).unwrap();
    let listener = TcpListener::bind("10.0.0.1:9000").unwrap();
    let mut client = TcpStream::connect("10.0.0.1:9000").unwrap();
    let (mut server, _) = listener.accept().unwrap();
    server.set_nonblocking(true).unwrap();

    let r = nic.rings().unwrap();
    nic.set_rings(&r).unwrap();
    assert!(nic.link_up().unwrap(), "unchanged: no restart");
    nic.set_rings(&Rings { rx: 512, ..r }).unwrap();
    assert!(!nic.link_up().unwrap());
    let snap = sim::interface("eth0").unwrap();
    assert!(!snap.link_up);
    assert_eq!(snap.settings.rings.rx, 512);

    let e = tx.send_to(b"x", addr("10.0.0.2:7000")).unwrap_err();
    assert_eq!(os_error_code(&e), Some(10050));
    client.write_all(b"held").unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(
        server.read(&mut buf).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );

    advance_time(Duration::from_millis(1999));
    assert!(!nic.link_up().unwrap());
    advance_time(Duration::from_millis(1));
    assert!(nic.link_up().unwrap());
    tx.send_to(b"x", addr("10.0.0.2:7000")).unwrap();
    assert_eq!(recv_all(&rx), 1);
    assert_eq!(server.read(&mut buf).unwrap(), 4);
    assert_eq!(&buf[..4], b"held");
}

#[test]
fn mutate_interface_drift_is_read_back() {
    let nic = setup(OsSemantics::Linux, NicCaps::default());
    let low = Coalesce {
        adaptive_rx: false,
        rx_usecs: 0,
        ..nic.coalesce().unwrap()
    };
    nic.set_coalesce(&low).unwrap();
    let logged = sim::interface("eth0").unwrap().apply_log.len();

    sim::mutate_interface("eth0", |s| {
        s.coalesce.adaptive_rx = true;
        s.rings.rx = 512;
        s.eee.enabled = true;
        s.channels.combined = 2;
    })
    .unwrap();
    assert!(nic.coalesce().unwrap().adaptive_rx);
    assert_eq!(nic.rings().unwrap().rx, 512);
    assert_eq!(nic.irqs().unwrap().len(), 2);
    assert_eq!(nic.napis().unwrap().len(), 2);
    let snap = sim::interface("eth0").unwrap();
    assert_eq!(snap.apply_log.len(), logged, "drift is not the SUT's doing");
    assert_eq!(snap.settings.channels.combined, 2);

    sim::mutate_interface("eth0", |s| s.threaded_napi = true).unwrap();
    assert!(nic.napis().unwrap().iter().all(|n| n.thread.is_some()));

    sim::set_queue_stats("eth0", |q| {
        q[0].hw_drops = Some(4);
    })
    .unwrap();
    assert_eq!(code(nic.queue_stats()), Some(95), "the driver keeps none");
    add_nic(
        NicSpec::new("eth2")
            .address(net("10.0.2.1/24"))
            .caps(NicCaps {
                queue_stats: true,
                ..NicCaps::default()
            }),
    )
    .unwrap();
    sim::set_queue_stats("eth2", |q| {
        q[0].hw_drops = Some(4);
    })
    .unwrap();
    let qs = Nic::open("eth2").unwrap().queue_stats().unwrap();
    assert_eq!(qs.len(), 8);
    assert_eq!((qs[0].kind, qs[0].queue), (QueueKind::Rx, 0));
    assert!(qs[0].has_loss());
}

#[test]
fn concurrent_first_use_builds_the_kernel_objects_once() {
    for _ in 0..50 {
        let nic = setup(OsSemantics::Linux, NicCaps::default());
        let users: Vec<_> = (0..4)
            .map(|_| {
                let nic = nic.clone();
                snare::thread::spawn(move || nic.napis().unwrap().len())
            })
            .collect();
        for u in users {
            assert_eq!(u.join().unwrap(), 4);
        }
        let eth0 = sim::irqs()
            .into_iter()
            .filter(|i| i.nic.as_deref() == Some("eth0"))
            .count();
        assert_eq!(eth0, 4);
        assert_eq!(live_kernel_threads("irq/", "eth0").len(), 4);
    }
}

#[test]
fn removing_a_nic_retires_its_interrupts_and_threads() {
    let nic = setup(OsSemantics::Linux, NicCaps::default());
    nic.set_threaded_napi(true).unwrap();
    let irqs = nic.irqs().unwrap();
    assert!(snare::remove_nic("eth0"));
    assert!(irqs.iter().all(|i| sim::irq(i.number()).is_none()));
    assert!(live_kernel_threads("irq/", "eth0").is_empty());
    assert!(live_kernel_threads("napi/", "eth0").is_empty());
}

#[test]
fn set_irq_moves_a_vector_off_its_old_interface() {
    let nic = setup(OsSemantics::Linux, NicCaps::default());
    let first = nic.irqs().unwrap()[0].number();
    sim::set_irq(first, "eth1-TxRx-0", Some("eth1")).unwrap();
    assert!(nic.irqs().unwrap().iter().all(|i| i.number() != first));
    let eth1 = Nic::open("eth1").unwrap().irqs().unwrap();
    assert!(eth1.iter().any(|i| i.number() == first));
}

#[test]
fn a_blocked_reader_wakes_when_the_windows_restart_ends() {
    register_test();
    set_os_semantics(OsSemantics::Windows);
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/24"))).unwrap();
    let nic = Nic::open("eth0").unwrap();
    let listener = TcpListener::bind("10.0.0.1:9000").unwrap();
    let mut client = TcpStream::connect("10.0.0.1:9000").unwrap();
    let (mut server, _) = listener.accept().unwrap();
    let _clock = StrictClock::start(StrictConfig::default()).unwrap();
    let start = snare::time_value();
    let r = nic.rings().unwrap();
    nic.set_rings(&Rings { rx: 512, ..r }).unwrap();
    client.write_all(b"held").unwrap();
    let got = snare::thread::spawn(move || {
        let mut buf = [0u8; 8];
        let n = server.read(&mut buf).unwrap();
        buf[..n].to_vec()
    })
    .join()
    .unwrap();
    assert_eq!(got, b"held");
    assert_eq!(snare::time_value() - start, Duration::from_secs(2));
}
