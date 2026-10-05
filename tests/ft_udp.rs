//! fast-talker's `Timestamped` over snare's UDP sockets: stamps on the
//! virtual clock, drops, transmit stamps, timed sends and memory.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use snare::fast_talker::latency::RoundTrips;
use snare::fast_talker::nic::Etf;
use snare::fast_talker::sim::{self, FtEvent, PtpSeed};
use snare::fast_talker::sockets::SocketMemory;
use snare::fast_talker::{
    Config, Hardware, Received, Source, Timestamped, TxTime, TxTimeErrorKind, TxTimestamp, compat,
};
use snare::net::UdpSocket;
use snare::sched::testkit::{StrictClock, StrictConfig};
use snare::{
    DropAccounting, IpNet, NicCaps, NicSpec, OsSemantics, add_nic, advance_time, os_error_code,
    pause_time, register_test, set_nic_policy, set_os_semantics, set_privileges, set_sys_limits,
    set_time_value, socket_entry, socket_id, time_value,
};

const ALL: [OsSemantics; 3] = [OsSemantics::Linux, OsSemantics::MacOs, OsSemantics::Windows];
const RX: &str = "10.0.0.2:7000";
const LATENCY: Duration = Duration::from_millis(5);

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn hw_caps() -> NicCaps {
    NicCaps {
        hw_rx_timestamp: true,
        hw_tx_timestamp: true,
        phc_index: Some(0),
        ..NicCaps::default()
    }
}

/// A fresh slot on `os` with a paused clock, `eth0` at 10.0.0.1 and `eth1`
/// at 10.0.0.2 (hardware stamping, a PTP clock, 5 ms latency), and a
/// socket on each: the sender on `eth0`, the receiver on `eth1`.
fn setup(os: OsSemantics) -> (UdpSocket, UdpSocket) {
    register_test();
    set_os_semantics(os);
    pause_time();
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/24"))).unwrap();
    add_nic(
        NicSpec::new("eth1")
            .address(net("10.0.0.2/24"))
            .caps(hw_caps()),
    )
    .unwrap();
    set_nic_policy("eth1", |p| p.latency = LATENCY).unwrap();
    let tx = UdpSocket::bind("10.0.0.1:7001").unwrap();
    let rx = UdpSocket::bind(RX).unwrap();
    rx.set_nonblocking(true).unwrap();
    (tx, rx)
}

fn kernel_only() -> Config {
    Config {
        hardware: Hardware::Off,
        ..Config::default()
    }
}

fn micros(t: SystemTime) -> SystemTime {
    let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    SystemTime::UNIX_EPOCH + Duration::from_micros(d.as_micros() as u64)
}

fn drain(rx: &Timestamped<UdpSocket>) -> Vec<(Vec<u8>, Received)> {
    let mut buf = [0u8; 256];
    let mut out = Vec::new();
    rx.drain(&mut buf, |p, r| out.push((p.to_vec(), r)))
        .unwrap();
    out
}

fn stamps(ts: &Timestamped<UdpSocket>) -> Vec<TxTimestamp> {
    let mut out = Vec::new();
    ts.tx_timestamps(&mut out).unwrap();
    out
}

#[test]
fn the_stamp_is_the_delivery_instant_not_the_read_time() {
    for os in ALL {
        let (tx, rx) = setup(os);
        let rx = Timestamped::with_config(rx, kernel_only());
        let sent = compat::now();
        tx.send_to(b"a", addr(RX)).unwrap();
        advance_time(Duration::from_millis(20));
        let mut buf = [0u8; 16];
        let r = rx.recv_from(&mut buf).unwrap();
        assert_eq!(r.len, 1);
        assert_eq!(r.from, addr("10.0.0.1:7001"));
        let (want, source) = match os {
            OsSemantics::MacOs => (micros(sent + LATENCY), Source::Kernel),
            _ => (sent + LATENCY, Source::Kernel),
        };
        assert_eq!(r.timestamp.source, source, "{os}");
        assert_eq!(r.timestamp.time, want, "{os}");
        if os != OsSemantics::MacOs {
            assert_eq!(r.timestamp.elapsed(), Duration::from_millis(15), "{os}");
        }
    }
}

#[test]
fn a_backlog_keeps_distinct_stamps() {
    let (tx, rx) = setup(OsSemantics::Linux);
    let rx = Timestamped::with_config(rx, kernel_only());
    let t0 = compat::now();
    for i in 0..3u8 {
        tx.send_to(&[i], addr(RX)).unwrap();
        advance_time(Duration::from_millis(1));
    }
    advance_time(Duration::from_millis(10));
    let got = drain(&rx);
    let times: Vec<_> = got.iter().map(|(_, r)| r.timestamp.time).collect();
    let want: Vec<_> = (0..3)
        .map(|i| t0 + LATENCY + Duration::from_millis(i))
        .collect();
    assert_eq!(times, want);
    assert_eq!(
        got.iter().map(|(p, _)| p[0]).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
}

#[test]
fn a_send_under_driver_time_is_stamped_at_that_time() {
    let (tx, rx) = setup(OsSemantics::Linux);
    set_nic_policy("eth1", |p| p.latency = Duration::ZERO).unwrap();
    let tx = Timestamped::with_config(
        tx,
        Config {
            transmit: true,
            ..kernel_only()
        },
    );
    let rx = Timestamped::with_config(rx, kernel_only());
    set_time_value(Duration::from_millis(10));
    let t = Duration::from_millis(7);
    let (at, sent) =
        snare::sched::with_driver_time(t, || (compat::now(), tx.send_to(b"x", addr(RX)).unwrap()));
    assert_eq!(sent.id, Some(0));
    let stamps = stamps(&tx);
    assert_eq!(stamps.len(), 1);
    assert_eq!(stamps[0].timestamp.time, at);
    assert_eq!(stamps[0].timestamp.source, Source::Kernel);
    let got = drain(&rx);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1.timestamp.time, at);
    assert_eq!(compat::now() - Duration::from_millis(3), at);
}

#[test]
fn the_source_follows_the_os_privileges_and_the_ptp_clock() {
    for os in ALL {
        let (tx, rx) = setup(os);
        let rx = Timestamped::new(rx);
        if os == OsSemantics::Linux {
            assert_eq!(rx.source(), Source::Hardware);
            assert_eq!(rx.hardware_interface(), Some("eth1"));
        } else {
            assert_eq!(rx.source(), Source::Kernel, "{os}");
            assert_eq!(rx.hardware_interface(), None);
        }
        let sent = compat::now();
        tx.send_to(b"a", addr(RX)).unwrap();
        advance_time(LATENCY);
        let got = drain(&rx);
        let stamp = got[0].1.timestamp;
        match os {
            OsSemantics::Linux => {
                assert_eq!(stamp.source, Source::Hardware);
                let hw = sent + LATENCY - Duration::from_micros(2);
                assert_eq!(stamp.time, hw);
                let raw =
                    hw.duration_since(SystemTime::UNIX_EPOCH).unwrap() + Duration::from_secs(37);
                assert_eq!(stamp.hardware_raw, Some(raw));
            }
            OsSemantics::MacOs => {
                assert_eq!(stamp.source, Source::Kernel);
                assert_eq!(stamp.time, micros(sent + LATENCY));
            }
            _ => {
                assert_eq!(stamp.source, Source::Kernel);
                assert_eq!(stamp.time, sent + LATENCY);
            }
        }
        let tx_side = Timestamped::new(tx);
        assert_eq!(
            tx_side.source(),
            Source::Kernel,
            "{os}: eth0 has no hardware"
        );
    }

    let (tx, rx) = setup(OsSemantics::Linux);
    let rx = Timestamped::new(rx);
    sim::set_ptp(
        "eth1",
        PtpSeed {
            offset_nanos: 1_000_000_000,
            ..PtpSeed::default()
        },
    )
    .unwrap();
    tx.send_to(b"a", addr(RX)).unwrap();
    advance_time(LATENCY);
    let stamp = drain(&rx)[0].1.timestamp;
    assert_eq!(stamp.source, Source::Kernel, "an undisciplined clock");
    assert!(stamp.hardware_raw.is_some());

    let (_tx, rx) = setup(OsSemantics::Linux);
    set_privileges(|p| {
        p.root = false;
        p.net_admin = false;
    });
    let rx = Timestamped::new(rx);
    assert_eq!(rx.source(), Source::Kernel, "no CAP_NET_ADMIN");

    register_test();
    set_os_semantics(OsSemantics::Linux);
    let wildcard = Timestamped::new(UdpSocket::bind("0.0.0.0:0").unwrap());
    assert_eq!(wildcard.source(), Source::Kernel);
}

#[test]
fn try_with_config_reports_what_cannot_be_enabled() {
    let hw = |name: &str| Config {
        hardware: Hardware::Interface(name.into()),
        ..Config::default()
    };
    let timed = Config {
        txtime: Some(TxTime::Launch),
        ..kernel_only()
    };

    let (_tx, rx) = setup(OsSemantics::Linux);
    let err = Timestamped::try_with_config(rx, hw("nope")).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
    let (tx, rx) = setup(OsSemantics::Linux);
    let err = Timestamped::try_with_config(tx, hw("eth0")).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    let ok = Timestamped::try_with_config(rx, hw("eth1")).unwrap();
    assert_eq!(ok.source(), Source::Hardware);

    let (tx, rx) = setup(OsSemantics::Linux);
    set_privileges(|p| {
        p.root = false;
        p.net_admin = false;
    });
    let err = Timestamped::try_with_config(rx, hw("eth1")).unwrap_err();
    assert_eq!(os_error_code(&err), Some(1));
    let err = Timestamped::try_with_config(tx, timed.clone()).unwrap_err();
    assert_eq!(os_error_code(&err), Some(1));

    for os in [OsSemantics::MacOs, OsSemantics::Windows] {
        let (tx, rx) = setup(os);
        let err = Timestamped::try_with_config(rx, hw("eth1")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{os}");
        let err = Timestamped::try_with_config(tx, timed.clone()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{os}");
    }
}

#[test]
fn overflow_drops_show_on_the_next_datagram() {
    let (tx, rx) = setup(OsSemantics::Linux);
    set_sys_limits(|l| {
        l.enforce_default_rcvbuf = true;
        l.rmem_default = 1000;
    });
    let rx = Timestamped::with_config(rx, kernel_only());
    for i in 0..5u8 {
        tx.send_to(&[i; 100], addr(RX)).unwrap();
    }
    advance_time(LATENCY);
    let first = drain(&rx);
    assert_eq!(first.len(), 3);
    assert!(first.iter().all(|(_, r)| r.drops == Some(0)));
    assert_eq!(socket_entry(socket_id(rx.get_ref())).unwrap().overflowed, 2);
    tx.send_to(&[9; 100], addr(RX)).unwrap();
    advance_time(LATENCY);
    let next = drain(&rx);
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].1.drops, Some(2));

    let (tx, rx) = setup(OsSemantics::MacOs);
    let rx = Timestamped::with_config(rx, kernel_only());
    tx.send_to(b"a", addr(RX)).unwrap();
    advance_time(LATENCY);
    assert_eq!(drain(&rx)[0].1.drops, None);
}

#[test]
fn wire_loss_counts_as_a_drop_unless_only_overflow_does() {
    for accounting in [
        DropAccounting::PolicyAndOverflow,
        DropAccounting::OverflowOnly,
    ] {
        let (tx, rx) = setup(OsSemantics::Linux);
        set_sys_limits(|l| l.drop_accounting = accounting);
        let rx = Timestamped::with_config(rx, kernel_only());
        set_nic_policy("eth1", |p| p.loss_rate = 1.0).unwrap();
        tx.send_to(b"lost", addr(RX)).unwrap();
        tx.send_to(b"lost", addr(RX)).unwrap();
        set_nic_policy("eth1", |p| p.loss_rate = 0.0).unwrap();
        tx.send_to(b"kept", addr(RX)).unwrap();
        advance_time(LATENCY);
        let got = drain(&rx);
        assert_eq!(got.len(), 1);
        let want = match accounting {
            DropAccounting::PolicyAndOverflow => 2,
            _ => 0,
        };
        assert_eq!(got[0].1.drops, Some(want), "{accounting:?}");
        assert_eq!(socket_entry(socket_id(rx.get_ref())).unwrap().wire_lost, 2);
    }
}

#[test]
fn transmit_ids_count_from_zero() {
    let transmit = Config {
        transmit: true,
        ..kernel_only()
    };
    let (tx, _rx) = setup(OsSemantics::Linux);
    let tx = Timestamped::with_config(tx, transmit.clone());
    let ids: Vec<_> = (0..3)
        .map(|_| tx.send_to(b"x", addr(RX)).unwrap().id)
        .collect();
    assert_eq!(ids, vec![Some(0), Some(1), Some(2)]);
    tx.get_ref().send_to(b"raw", addr(RX)).unwrap();
    let got = stamps(&tx);
    assert_eq!(got.iter().map(|s| s.id).collect::<Vec<_>>(), [0, 1, 2, 3]);
    assert!(got.iter().all(|s| s.timestamp.source == Source::Kernel));
    assert!(stamps(&tx).is_empty());

    let (tx, _rx) = setup(OsSemantics::MacOs);
    let tx = Timestamped::with_config(tx, transmit.clone());
    for _ in 0..3 {
        tx.send_to(b"x", addr(RX)).unwrap();
    }
    tx.get_ref().send_to(b"raw", addr(RX)).unwrap();
    let got = stamps(&tx);
    assert_eq!(got.iter().map(|s| s.id).collect::<Vec<_>>(), [0, 1, 2]);
    assert!(got.iter().all(|s| s.timestamp.source == Source::UserSpace));
    tx.send_to(b"unread", addr(RX)).unwrap();
    let tx = Timestamped::with_config(tx.into_inner(), transmit);
    assert!(stamps(&tx).is_empty(), "a new wrapper forgets unread sends");
    assert_eq!(tx.send_to(b"x", addr(RX)).unwrap().id, Some(0));

    let (tx, _rx) = setup(OsSemantics::Linux);
    let tx = Timestamped::with_config(tx, kernel_only());
    assert_eq!(tx.send_to(b"x", addr(RX)).unwrap().id, None);
}

fn timed(mode: TxTime) -> Config {
    Config {
        txtime: Some(mode),
        ..kernel_only()
    }
}

#[test]
fn send_at_without_etf_leaves_at_once() {
    let (tx, rx) = setup(OsSemantics::Linux);
    let tx = Timestamped::with_config(tx, timed(TxTime::Launch));
    let rx = Timestamped::with_config(rx, kernel_only());
    let now = compat::now();
    tx.send_to_at(b"x", addr(RX), now + Duration::from_millis(50))
        .unwrap();
    advance_time(LATENCY);
    let got = drain(&rx);
    assert_eq!(got[0].1.timestamp.time, now + LATENCY);
    let id = socket_id(tx.get_ref());
    assert!(
        sim::events()
            .iter()
            .any(|e| e.event == FtEvent::TxTimeWithoutEtf { socket: id })
    );

    let plain = Timestamped::with_config(UdpSocket::bind("10.0.0.1:0").unwrap(), kernel_only());
    let err = plain.send_to_at(b"x", addr(RX), now).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

    for os in [OsSemantics::MacOs, OsSemantics::Windows] {
        let (tx, _rx) = setup(os);
        let tx = Timestamped::with_config(tx, timed(TxTime::Launch));
        let err = tx.send_to_at(b"x", addr(RX), compat::now()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{os}");
    }
}

#[test]
fn a_launch_wakes_a_blocked_reader_at_launch_plus_latency() {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/24"))).unwrap();
    add_nic(NicSpec::new("eth1").address(net("10.0.0.2/24"))).unwrap();
    set_nic_policy("eth1", |p| p.latency = LATENCY).unwrap();
    sim::set_etf("eth0", None, Some(Etf::default())).unwrap();
    let tx = Timestamped::with_config(
        UdpSocket::bind("10.0.0.1:7001").unwrap(),
        timed(TxTime::Launch),
    );
    let rx = Timestamped::with_config(UdpSocket::bind(RX).unwrap(), kernel_only());
    let _clock = StrictClock::start(StrictConfig::default()).unwrap();
    let start = time_value();
    let (launch, got) = snare::thread::spawn(move || {
        let launch = compat::now() + Duration::from_millis(10);
        tx.send_to_at(b"x", addr(RX), launch).unwrap();
        let mut buf = [0u8; 16];
        (launch, rx.recv_from(&mut buf).unwrap())
    })
    .join()
    .unwrap();
    assert_eq!(time_value() - start, Duration::from_millis(10) + LATENCY);
    assert_eq!(got.timestamp.time, launch + LATENCY);
}

#[test]
fn etf_rejects_late_and_mismatched_times_and_reports_misses() {
    let (tx, rx) = setup(OsSemantics::Linux);
    sim::set_etf("eth0", None, Some(Etf::default())).unwrap();
    let tx = Timestamped::with_config(tx, timed(TxTime::Launch));
    let rx = Timestamped::with_config(rx, kernel_only());
    advance_time(Duration::from_millis(100));
    let now = compat::now();

    tx.send_to_at(b"late", addr(RX), now - Duration::from_millis(1))
        .unwrap();
    let mut errors = Vec::new();
    assert_eq!(tx.txtime_errors(&mut errors).unwrap(), 1);
    assert_eq!(errors[0].kind, TxTimeErrorKind::Invalid);
    assert_eq!(errors[0].time, now - Duration::from_millis(1));

    sim::inject_txtime_missed(socket_id(tx.get_ref()), 1).unwrap();
    let at = now + Duration::from_millis(3);
    tx.send_to_at(b"missed", addr(RX), at).unwrap();
    errors.clear();
    assert_eq!(
        tx.txtime_errors(&mut errors).unwrap(),
        0,
        "not before launch"
    );
    advance_time(Duration::from_millis(3));
    assert_eq!(tx.txtime_errors(&mut errors).unwrap(), 1);
    assert_eq!(errors[0].kind, TxTimeErrorKind::Missed);
    assert_eq!(errors[0].time, at);

    let second = compat::now() + Duration::from_millis(20);
    let first = compat::now() + Duration::from_millis(10);
    tx.send_to_at(b"second", addr(RX), second).unwrap();
    tx.send_to_at(b"first", addr(RX), first).unwrap();
    advance_time(Duration::from_millis(30));
    let got = drain(&rx);
    let order: Vec<_> = got.iter().map(|(p, _)| p.as_slice()).collect();
    assert_eq!(order, [b"first".as_slice(), b"second".as_slice()]);
    assert_eq!(got[0].1.timestamp.time, first + LATENCY);
    assert_eq!(got[1].1.timestamp.time, second + LATENCY);

    let deadline = Timestamped::with_config(
        UdpSocket::bind("10.0.0.1:7002").unwrap(),
        timed(TxTime::Deadline),
    );
    let now = compat::now();
    deadline
        .send_to_at(b"d", addr(RX), now + Duration::from_millis(50))
        .unwrap();
    errors.clear();
    assert_eq!(deadline.txtime_errors(&mut errors).unwrap(), 1);
    assert_eq!(
        errors[0].kind,
        TxTimeErrorKind::Invalid,
        "launch-mode qdisc"
    );

    sim::set_etf(
        "eth0",
        None,
        Some(Etf {
            deadline: true,
            ..Etf::default()
        }),
    )
    .unwrap();
    deadline
        .send_to_at(b"d", addr(RX), now + Duration::from_millis(50))
        .unwrap();
    advance_time(LATENCY);
    let got = drain(&rx);
    assert_eq!(got.len(), 1, "a deadline leaves at once");
    assert_eq!(got[0].1.timestamp.time, now + LATENCY);
}

#[test]
fn the_socket_snapshot_shows_what_was_configured() {
    let (tx, _rx) = setup(OsSemantics::Linux);
    let config = Config {
        transmit: true,
        txtime: Some(TxTime::Launch),
        ..Config::default()
    };
    let tx = Timestamped::with_config(tx, config.clone());
    tx.send_to(b"x", addr(RX)).unwrap();
    tx.send_to(b"y", addr(RX)).unwrap();
    let id = socket_id(tx.get_ref());
    let snap = sim::socket(id).unwrap();
    assert_eq!(snap.entry.id, id);
    assert_eq!(snap.timestamping, Some(config));
    assert_eq!(snap.source, Some(Source::Kernel));
    assert_eq!(snap.hardware_interface, None);
    assert_eq!(snap.txtime, Some(TxTime::Launch));
    assert_eq!(snap.tx_ids_issued, 2);
    assert_eq!(snap.pending_tx_stamps, 2);
    assert_eq!(stamps(&tx).len(), 2);
    assert_eq!(sim::socket(id).unwrap().pending_tx_stamps, 0);
    assert!(sim::sockets().iter().any(|s| s.entry.id == id));
    drop(tx);
    let closed = sim::socket(id).unwrap();
    assert!(closed.entry.closed);
    assert_eq!(closed.timestamping, None);
}

#[test]
fn stamps_age_and_round_trips_run_on_virtual_time() {
    let (tx, rx) = setup(OsSemantics::Linux);
    set_nic_policy("eth1", |p| p.latency = Duration::from_millis(3)).unwrap();
    let tx = Timestamped::with_config(tx, kernel_only());
    let rx = Timestamped::with_config(rx, kernel_only());
    let mut trips = RoundTrips::new(Duration::from_secs(1));
    let sent = tx.send_to(b"ping", addr(RX)).unwrap();
    trips.sent(1u32, &sent);
    advance_time(Duration::from_millis(3));
    let reply = drain(&rx)[0].1.timestamp;
    assert!(trips.replied(&1, reply));
    let (mut done, mut lost) = (Vec::new(), Vec::new());
    trips.poll(compat::now(), &mut done, &mut lost);
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].rtt, Duration::from_millis(3));
    assert!(lost.is_empty());
    advance_time(Duration::from_millis(40));
    assert_eq!(reply.elapsed(), Duration::from_millis(40));
}

#[test]
fn socket_memory_of_a_snare_socket_matches_timestamped_memory() {
    for os in ALL {
        let (tx, rx) = setup(os);
        let rx = Timestamped::with_config(rx, kernel_only());
        tx.send_to(&[0; 100], addr(RX)).unwrap();
        tx.send_to(&[0; 50], addr(RX)).unwrap();
        advance_time(LATENCY);
        let of = SocketMemory::of(rx.get_ref()).unwrap();
        assert_eq!(of, rx.memory().unwrap(), "{os}");
        match os {
            OsSemantics::Linux => {
                assert_eq!(of.rmem_alloc, 150 + 2 * 768);
                assert_eq!(of.rcvbuf, 212_992);
                assert_eq!(of.drops, Some(0));
            }
            OsSemantics::MacOs => {
                assert_eq!(of.rmem_alloc, 150 + 2 * 16);
                assert_eq!(of.drops, None);
            }
            _ => {
                assert_eq!(of.rmem_alloc, 100);
                assert_eq!(of.drops, None);
            }
        }
    }
}

#[test]
fn windows_loopback_falls_back_to_user_space() {
    register_test();
    set_os_semantics(OsSemantics::Windows);
    pause_time();
    let transmit = Config {
        transmit: true,
        ..kernel_only()
    };
    let tx = Timestamped::with_config(UdpSocket::bind("127.0.0.1:7001").unwrap(), transmit);
    let rx = Timestamped::with_config(UdpSocket::bind("127.0.0.1:7000").unwrap(), kernel_only());
    let sent = compat::now();
    tx.send_to(b"a", addr("127.0.0.1:7000")).unwrap();
    advance_time(Duration::from_millis(3));
    let got = drain(&rx);
    assert_eq!(got[0].1.timestamp.source, Source::UserSpace);
    assert_eq!(got[0].1.timestamp.time, compat::now());
    let tx_stamps = stamps(&tx);
    assert_eq!(tx_stamps.len(), 1);
    assert_eq!(tx_stamps[0].timestamp.source, Source::UserSpace);
    assert_eq!(tx_stamps[0].timestamp.time, sent);
}
