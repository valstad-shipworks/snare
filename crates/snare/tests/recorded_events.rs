//! The sim-wide event log: what crossed a tester's boundary, what the link did to datagrams and
//! which policies changed, stamped on the sim's own timeline.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use snare::{
    Bytes, Line, LinkFault, RecordedEntry, RecordedEvent, Sim, TcpPolicy, TesterAction, Toward,
    Transport, UdpPolicy, connect_tester, recorded_events, run_testers, set_tcp_policy,
    set_udp_policy, udp_tester,
};

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn events(entries: &[RecordedEntry]) -> Vec<RecordedEvent> {
    entries.iter().map(|e| e.event.clone()).collect()
}

fn assert_ordered(entries: &[RecordedEntry]) {
    for pair in entries.windows(2) {
        assert!(
            pair[0].seq < pair[1].seq,
            "seq strictly increases: {pair:?}"
        );
        assert!(pair[0].at <= pair[1].at, "stamps never decrease: {pair:?}");
    }
}

#[test]
fn a_tcp_session_is_logged_in_order() {
    let sim = Sim::new();
    let tester = addr("127.0.0.41:9200");
    let peer = sim.run(|| {
        let server = connect_tester::<Line>(tester)
            .then_action(|msg, _| TesterAction::Send(Line(format!("ack:{}", msg.0))))
            .until_after(Duration::from_millis(200));
        let client = std::thread::spawn(move || {
            let stream = TcpStream::connect(tester).unwrap();
            let local = stream.local_addr().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            for msg in ["hi", "bye"] {
                (&stream).write_all(format!("{msg}\n").as_bytes()).unwrap();
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
            }
            local
        });
        run_testers!(server);
        client.join().unwrap()
    });
    let log = sim.recorded_events();
    assert_ordered(&log);
    assert_eq!(
        events(&log),
        [
            RecordedEvent::Accepted { tester, peer },
            RecordedEvent::Received {
                transport: Transport::Tcp,
                tester,
                peer,
                len: 3
            },
            RecordedEvent::Sent {
                transport: Transport::Tcp,
                tester,
                peer,
                len: 7
            },
            RecordedEvent::Received {
                transport: Transport::Tcp,
                tester,
                peer,
                len: 4
            },
            RecordedEvent::Sent {
                transport: Transport::Tcp,
                tester,
                peer,
                len: 8
            },
            RecordedEvent::PeerClosed { tester, peer },
            RecordedEvent::Closed { tester, peer },
        ]
    );
}

#[test]
fn udp_sends_and_receives_are_logged() {
    let sim = Sim::new();
    let tester = addr("127.0.0.41:9201");
    let peer = addr("127.0.0.41:9202");
    sim.run(|| {
        let device = udp_tester::<Bytes>(tester)
            .then_action(|msg, _| TesterAction::Send(msg))
            .until_after(Duration::from_millis(100));
        let sock = UdpSocket::bind(peer).unwrap();
        sock.send_to(b"ab", tester).unwrap();
        sock.send_to(b"cde", tester).unwrap();
        run_testers!(device);
    });
    let udp = |len| {
        [
            RecordedEvent::Received {
                transport: Transport::Udp,
                tester,
                peer,
                len,
            },
            RecordedEvent::Sent {
                transport: Transport::Udp,
                tester,
                peer,
                len,
            },
        ]
    };
    assert_eq!(events(&sim.recorded_events()), [udp(2), udp(3)].concat());
}

/// A tester's reset is logged once, as the tester's own act: the code under test's read fails with
/// ECONNRESET (WSAECONNRESET), and the tester does not log the reset coming back as the peer's.
#[test]
fn reset_and_peer_reset_are_logged() {
    let sim = Sim::new();
    let tester = addr("127.0.0.41:9203");
    let peer = sim.run(|| {
        let server = connect_tester::<Line>(tester)
            .then_action(|_, _| TesterAction::Reset)
            .until_after(Duration::from_millis(200));
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(tester).unwrap();
            stream.write_all(b"boom\n").unwrap();
            let err = stream.read(&mut [0u8; 8]).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
            stream.local_addr().unwrap()
        });
        run_testers!(server);
        client.join().unwrap()
    });
    assert_eq!(
        events(&sim.recorded_events()),
        [
            RecordedEvent::Accepted { tester, peer },
            RecordedEvent::Received {
                transport: Transport::Tcp,
                tester,
                peer,
                len: 5
            },
            RecordedEvent::Reset { tester, peer },
        ]
    );
}

#[test]
fn quiesce_logs_span_and_suppressed_traffic() {
    let sim = Sim::new();
    let tester = addr("127.0.0.41:9204");
    let span = Duration::from_millis(100);
    let peer = sim.run(|| {
        let server = connect_tester::<Line>(tester)
            .then_action(move |msg, _| match msg.0.as_str() {
                "quiet" => TesterAction::Multiple(vec![
                    TesterAction::Quiesce(span),
                    TesterAction::Send(Line("late".into())),
                ]),
                _ => TesterAction::Send(msg),
            })
            .until_after(Duration::from_millis(400));
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(tester).unwrap();
            stream.write_all(b"quiet\nlost\n").unwrap();
            std::thread::sleep(Duration::from_millis(200));
            stream.write_all(b"back\n").unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            assert_eq!(line, "back\n");
            stream.local_addr().unwrap()
        });
        run_testers!(server);
        client.join().unwrap()
    });
    let log = events(&sim.recorded_events());
    assert_eq!(
        log[..7],
        [
            RecordedEvent::Accepted { tester, peer },
            RecordedEvent::Received {
                transport: Transport::Tcp,
                tester,
                peer,
                len: 6
            },
            RecordedEvent::Quiesced { tester, peer, span },
            RecordedEvent::Suppressed {
                tester,
                peer,
                toward: Toward::CodeUnderTest,
                len: 5
            },
            RecordedEvent::Suppressed {
                tester,
                peer,
                toward: Toward::Tester,
                len: 5
            },
            RecordedEvent::Received {
                transport: Transport::Tcp,
                tester,
                peer,
                len: 5
            },
            RecordedEvent::Sent {
                transport: Transport::Tcp,
                tester,
                peer,
                len: 5
            },
        ]
    );
}

#[test]
fn link_faults_are_logged_both_directions() {
    let sim = Sim::new();
    let tester = addr("127.0.0.41:9205");
    let cut = addr("127.0.0.41:9206");
    sim.run(|| {
        let device = udp_tester::<Bytes>(tester)
            .then_action(|msg, _| TesterAction::Send(msg))
            .until_after(Duration::from_millis(100));
        set_udp_policy(tester, |p| {
            p.duplicate_rate = 1.0;
            p.mtu = Some(4);
        });
        set_udp_policy(cut, |p| p.loss_rate = 1.0);
        let sock = UdpSocket::bind(cut).unwrap();
        sock.send_to(b"ab", tester).unwrap();
        sock.send_to(b"abcdefgh", tester).unwrap();
        run_testers!(device);
    });
    let links: Vec<_> = events(&sim.recorded_events())
        .into_iter()
        .filter(|e| matches!(e, RecordedEvent::Link { .. }))
        .collect();
    assert_eq!(
        links,
        [
            RecordedEvent::Link {
                from: cut,
                to: tester,
                len: 2,
                fault: LinkFault::Duplicated
            },
            RecordedEvent::Link {
                from: cut,
                to: tester,
                len: 8,
                fault: LinkFault::TooBig
            },
            RecordedEvent::Link {
                from: tester,
                to: cut,
                len: 2,
                fault: LinkFault::Lost
            },
            RecordedEvent::Link {
                from: tester,
                to: cut,
                len: 2,
                fault: LinkFault::Lost
            },
        ]
    );
}

#[test]
fn policy_changes_are_logged() {
    let sim = Sim::new();
    sim.run(|| {
        set_udp_policy("127.0.0.41:9207", |p| p.loss_rate = 0.5);
        set_udp_policy("127.0.0.41:9207", |p| p.loss_rate = 0.0);
        set_tcp_policy("127.0.0.41:9208", |p| p.latency = Duration::from_millis(3));
    });
    assert_eq!(
        events(&sim.recorded_events()),
        [
            RecordedEvent::UdpPolicyChanged {
                addr: addr("127.0.0.41:9207"),
                policy: UdpPolicy {
                    loss_rate: 0.5,
                    ..UdpPolicy::default()
                },
            },
            RecordedEvent::UdpPolicyChanged {
                addr: addr("127.0.0.41:9207"),
                policy: UdpPolicy::default(),
            },
            RecordedEvent::TcpPolicyChanged {
                addr: addr("127.0.0.41:9208"),
                policy: TcpPolicy {
                    latency: Duration::from_millis(3),
                    ..TcpPolicy::default()
                },
            },
        ]
    );
}

#[test]
fn clear_scopes_the_log_to_a_phase() {
    Sim::new().run(|| {
        set_udp_policy("127.0.0.41:9209", |p| p.loss_rate = 0.5);
        set_udp_policy("127.0.0.41:9209", |p| p.loss_rate = 0.25);
        snare::clear_recorded_events();
        assert!(recorded_events().is_empty());
        set_udp_policy("127.0.0.41:9209", |p| p.loss_rate = 0.0);
        let log = recorded_events();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].seq, 2, "sequence numbers carry on across a clear");
    });
}

#[test]
fn stamps_are_virtual_time() {
    let sim = Sim::new();
    let target = addr("127.0.0.41:9211");
    let real = Instant::now();
    sim.run(|| {
        let _sink = UdpSocket::bind(target).unwrap();
        let ticker = udp_tester::<Bytes>("127.0.0.41:9210")
            .with_cyclic_action(Duration::from_millis(100), move || {
                TesterAction::SendTo(target, Bytes(b"tick".to_vec()))
            })
            .until_after(Duration::from_secs(1));
        run_testers!(ticker);
    });
    let real = real.elapsed();
    let stamps: Vec<_> = sim
        .recorded_events()
        .into_iter()
        .filter(|e| matches!(e.event, RecordedEvent::Sent { .. }))
        .map(|e| e.at)
        .collect();
    assert!(
        stamps.len() >= 9,
        "a tick every 100 ms for a second: {stamps:?}"
    );
    for pair in stamps.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(
            gap >= Duration::from_millis(100) && gap < Duration::from_millis(101),
            "ticks are 100 ms apart in virtual time: {stamps:?}"
        );
    }
    assert!(
        real < Duration::from_millis(500),
        "virtual time outran real time: {real:?}"
    );
}

#[test]
fn log_readable_from_any_sim_thread_and_after_run() {
    let sim = Sim::new();
    let seen_inside = sim.run(|| {
        set_udp_policy("127.0.0.41:9212", |p| p.loss_rate = 0.5);
        std::thread::spawn(recorded_events).join().unwrap()
    });
    assert_eq!(seen_inside.len(), 1);
    assert_eq!(sim.recorded_events(), seen_inside);
    let from_outside = std::thread::scope(|s| s.spawn(|| sim.recorded_events()).join().unwrap());
    assert_eq!(from_outside, seen_inside);
    sim.clear_recorded_events();
    assert!(sim.recorded_events().is_empty());
}

#[test]
fn parallel_sims_keep_separate_logs() {
    let runs: Vec<_> = (0..4u16)
        .map(|i| {
            std::thread::spawn(move || {
                let sim = Sim::new();
                let at = SocketAddr::from(([127, 0, 0, 42], 9300 + i));
                sim.run(|| {
                    for _ in 0..50 {
                        set_udp_policy(at, |p| p.loss_rate = 0.5);
                        std::thread::yield_now();
                    }
                });
                (at, sim.recorded_events())
            })
        })
        .collect();
    for run in runs {
        let (at, log) = run.join().unwrap();
        assert_eq!(log.len(), 50);
        assert!(log.iter().all(
            |e| matches!(&e.event, RecordedEvent::UdpPolicyChanged { addr, .. } if *addr == at)
        ));
    }
}

#[cfg(unix)]
#[test]
fn wall_clock_stamps_are_real_elapsed() {
    let sim = Sim::builder().wall_clock().build();
    sim.run(|| {
        set_udp_policy("127.0.0.41:9213", |p| p.loss_rate = 0.5);
        std::thread::sleep(Duration::from_millis(50));
        set_udp_policy("127.0.0.41:9213", |p| p.loss_rate = 0.0);
    });
    let log = sim.recorded_events();
    let gap = log[1].at - log[0].at;
    assert!(
        gap >= Duration::from_millis(50),
        "real time passed between the two: {gap:?}"
    );
    assert!(
        log[1].at < Duration::from_secs(60),
        "stamped from the sim's build: {log:?}"
    );
}

#[cfg(windows)]
#[test]
fn wall_clock_stamps_are_monotone() {
    let sim = Sim::builder().wall_clock().build();
    let tester = addr("127.0.0.41:9214");
    sim.run(|| {
        let device = udp_tester::<Bytes>(tester)
            .then_action(|msg, _| TesterAction::Send(msg))
            .until_after(Duration::from_millis(50));
        let sock = UdpSocket::bind("127.0.0.41:9215").unwrap();
        for _ in 0..20 {
            sock.send_to(b"x", tester).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
        run_testers!(device);
    });
    let log = sim.recorded_events();
    assert!(log.len() >= 2, "{log:?}");
    assert_ordered(&log);
}

#[test]
fn record_events_off_records_nothing() {
    let sim = Sim::builder().record_events(false).build();
    let tester = addr("127.0.0.41:9216");
    sim.run(|| {
        set_udp_policy(tester, |p| p.duplicate_rate = 1.0);
        let device = udp_tester::<Bytes>(tester)
            .then_action(|msg, _| TesterAction::Send(msg))
            .until_after(Duration::from_millis(50));
        let sock = UdpSocket::bind("127.0.0.41:9217").unwrap();
        sock.send_to(b"x", tester).unwrap();
        run_testers!(device);
        assert!(recorded_events().is_empty());
    });
    assert!(sim.recorded_events().is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn simhost_udp_link_faults_are_logged() {
    let sim = Sim::builder()
        .host(snare::HostProfile::new().build())
        .build();
    let rx_addr = addr("127.0.0.1:9218");
    let tx_addr = addr("127.0.0.1:9219");
    let tester = addr("127.0.0.41:9220");
    sim.run(|| {
        let _rx = UdpSocket::bind(rx_addr).unwrap();
        set_udp_policy(rx_addr, |p| p.loss_rate = 1.0);
        let tx = UdpSocket::bind(tx_addr).unwrap();
        tx.send_to(b"lost", rx_addr).unwrap();
        let device = udp_tester::<Bytes>(tester)
            .with_cyclic_action(Duration::from_millis(10), move || {
                TesterAction::SendTo(rx_addr, Bytes(b"gone".to_vec()))
            })
            .until_after(Duration::from_millis(15));
        run_testers!(device);
    });
    let links: Vec<_> = events(&sim.recorded_events())
        .into_iter()
        .filter(|e| matches!(e, RecordedEvent::Link { .. }))
        .collect();
    assert_eq!(
        links,
        [
            RecordedEvent::Link {
                from: tx_addr,
                to: rx_addr,
                len: 4,
                fault: LinkFault::Lost
            },
            RecordedEvent::Link {
                from: tester,
                to: rx_addr,
                len: 4,
                fault: LinkFault::Lost
            },
        ]
    );
}
