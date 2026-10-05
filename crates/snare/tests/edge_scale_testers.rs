//! Behaviour pins for many testers at once, ahead of performance work on the tester runtime:
//!
//! - Two hundred UDP echo testers, each sent one datagram, each answer exactly once to the
//!   sender, and the sim's log holds exactly one `Received` and one `Sent` per tester; under
//!   `deterministic()` the order the answers arrive in and the log are pinned to a golden.
//! - A hundred TCP line-echo testers, each with its own client thread exchanging twenty lines,
//!   echo every line in order, with one `Accepted` per tester and an exact count of each event.

#![cfg(unix)]

#[path = "support/golden.rs"]
mod golden;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use snare::{
    Bytes, Line, RecordedEntry, RecordedEvent, Sim, TesterAction, connect_tester, udp_tester,
};

const UDP_TESTERS: usize = 200;
const TCP_TESTERS: usize = 100;
const LINES: usize = 20;

fn udp_addr(i: usize) -> SocketAddr {
    SocketAddr::from(([127, 0, 1, (i / 100 + 1) as u8], 7_000 + (i % 100) as u16))
}

fn tcp_addr(i: usize) -> SocketAddr {
    SocketAddr::from(([127, 0, 2, 1], 8_000 + i as u16))
}

/// The variant name of each logged event, counted.
fn census(events: &[RecordedEntry]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for e in events {
        let name = format!("{:?}", e.event);
        let name = name.split([' ', '{', '(']).next().unwrap().to_string();
        *counts.entry(name).or_default() += 1;
    }
    counts
}

/// Runs two hundred UDP echo testers against one client that sends to each in reverse order and
/// collects the answers in arrival order.
fn udp_echoes(sim: &Sim) -> Vec<(SocketAddr, Vec<u8>)> {
    sim.run(|| {
        let testers: Vec<_> = (0..UDP_TESTERS)
            .map(|i| {
                udp_tester::<Bytes>(udp_addr(i))
                    .then_action(|msg, _from| {
                        let mut reply = b"ack:".to_vec();
                        reply.extend(msg.0);
                        TesterAction::Send(Bytes(reply))
                    })
                    .until_after(Duration::from_millis(100))
            })
            .collect();
        let client = std::thread::spawn(|| {
            let sock = UdpSocket::bind("127.0.0.1:9000").unwrap();
            for i in (0..UDP_TESTERS).rev() {
                sock.send_to(format!("{i}").as_bytes(), udp_addr(i))
                    .unwrap();
            }
            let mut buf = [0u8; 64];
            (0..UDP_TESTERS)
                .map(|_| {
                    let (n, from) = sock.recv_from(&mut buf).unwrap();
                    (from, buf[..n].to_vec())
                })
                .collect::<Vec<_>>()
        });
        let refs: Vec<&dyn snare::__RunTester> = testers
            .iter()
            .map(|t| t as &dyn snare::__RunTester)
            .collect();
        snare::__run_testers(&refs);
        client.join().unwrap()
    })
}

#[test]
fn two_hundred_udp_testers_each_answer_once() {
    let sim = Sim::new();
    let mut got = udp_echoes(&sim);
    got.sort();
    let mut want: Vec<_> = (0..UDP_TESTERS)
        .map(|i| (udp_addr(i), format!("ack:{i}").into_bytes()))
        .collect();
    want.sort();
    assert_eq!(got, want);
    let counts = census(&sim.recorded_events());
    assert_eq!(counts.get("Received"), Some(&UDP_TESTERS));
    assert_eq!(counts.get("Sent"), Some(&UDP_TESTERS));
    assert_eq!(
        counts.values().sum::<usize>(),
        2 * UDP_TESTERS,
        "{counts:?}"
    );
}

#[test]
fn two_hundred_udp_testers_replay_a_golden_log_under_deterministic() {
    let sim = || Sim::builder().deterministic().seed(11).build();
    let first = sim();
    let got = udp_echoes(&first);
    let again = sim();
    assert_eq!(udp_echoes(&again), got, "the same seed replays");
    let mut out = String::new();
    for (from, body) in &got {
        out.push_str(&format!("{from} {}\n", String::from_utf8_lossy(body)));
    }
    for e in first.recorded_events() {
        out.push_str(&format!("{} {} {:?}\n", e.at.as_nanos(), e.seq, e.event));
    }
    golden::check_text("edge_scale_udp_testers.txt", &out);
}

#[test]
fn a_hundred_tcp_testers_echo_every_line_in_order() {
    let sim = Sim::new();
    sim.run(|| {
        let testers: Vec<_> = (0..TCP_TESTERS)
            .map(|i| {
                connect_tester::<Line>(tcp_addr(i))
                    .then_action(|msg, _from| TesterAction::Send(Line(format!("echo:{}", msg.0))))
                    .until_after(Duration::from_millis(200))
            })
            .collect();
        let clients: Vec<_> = (0..TCP_TESTERS)
            .map(|i| {
                std::thread::spawn(move || {
                    let mut s = TcpStream::connect(tcp_addr(i)).unwrap();
                    let mut reader = BufReader::new(s.try_clone().unwrap());
                    (0..LINES)
                        .map(|n| {
                            s.write_all(format!("{i}.{n}\n").as_bytes()).unwrap();
                            let mut line = String::new();
                            reader.read_line(&mut line).unwrap();
                            line
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let refs: Vec<&dyn snare::__RunTester> = testers
            .iter()
            .map(|t| t as &dyn snare::__RunTester)
            .collect();
        snare::__run_testers(&refs);
        for (i, c) in clients.into_iter().enumerate() {
            let want: Vec<String> = (0..LINES).map(|n| format!("echo:{i}.{n}\n")).collect();
            assert_eq!(c.join().unwrap(), want);
        }
    });
    let events = sim.recorded_events();
    let accepted = events
        .iter()
        .filter(|e| matches!(e.event, RecordedEvent::Accepted { .. }))
        .count();
    assert_eq!(accepted, TCP_TESTERS);
    let counts = census(&events);
    assert_eq!(counts.get("Received"), Some(&(TCP_TESTERS * LINES)));
    assert_eq!(counts.get("Sent"), Some(&(TCP_TESTERS * LINES)));
}
