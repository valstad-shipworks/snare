//! A tester with a cyclic action handles what the code under test sends at the instant it arrives
//! — sent plus the link's latency — however long the tester has been running, on the plain clock
//! and under `deterministic()`, over UDP and TCP.
//!
//! The tester finishes on an opaque `until` condition, so it wakes every millisecond to re-check
//! it, reading the clock in its loop and its handlers but making no hooked call between its waits:
//! the shape of a driver crate's emulated device, run until the client is done.

use std::io::Write;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use snare::{Bytes, Sim, TesterAction, connect_tester, run_testers, udp_tester};

/// How long the code under test idles before it sends: long enough for the tester's loop to have
/// run hundreds of times.
const LEAD_IN: Duration = Duration::from_millis(800);

/// The gaps the code under test leaves between sends: none falls on the testers' 4 ms tick.
const GAPS_US: [u64; 8] = [3_000, 4_100, 1_250, 7_500, 2_000, 13_000, 500, 9_100];

/// The testers' cyclic period.
const TICK: Duration = Duration::from_millis(4);

/// One handled message: when it was sent and when the tester handled it, both since the run's
/// start.
type Handled = Arc<Mutex<Vec<(Duration, Duration)>>>;

/// What one run's tester saw: each message as [`Handled`] records it, and how often it ticked.
#[derive(Debug, PartialEq)]
struct Run {
    handled: Vec<(Duration, Duration)>,
    ticks: u32,
}

fn stamp(since: Duration) -> [u8; 8] {
    u64::try_from(since.as_nanos()).unwrap().to_be_bytes()
}

fn unstamp(bytes: &[u8; 8]) -> Duration {
    Duration::from_nanos(u64::from_be_bytes(*bytes))
}

/// Sets the flag when dropped, so the tester stops even if the code under test panics.
struct SetOnDrop(Arc<AtomicBool>);

impl Drop for SetOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Runs `send` (given the run's start) on a thread of its own after [`LEAD_IN`], against a tester
/// whose handler records each message's stamp and when it ran, and whose cyclic action runs `tick`
/// every [`TICK`], until `send` returns.
fn arrivals(
    tester: snare::Tester<Bytes>,
    mut tick: impl FnMut() -> TesterAction<Bytes> + Send + 'static,
    send: impl FnOnce(Instant) + Send + 'static,
) -> Run {
    let handled: Handled = Arc::default();
    let ticks = Arc::new(Mutex::new(0u32));
    let done = Arc::new(AtomicBool::new(false));
    let start = Instant::now();
    let seen = handled.clone();
    let counted = ticks.clone();
    let finished = done.clone();
    let tester = tester
        .then_action(move |msg, _| {
            let now = start.elapsed();
            let mut seen = seen.lock().unwrap();
            for chunk in msg.0.as_chunks::<8>().0 {
                seen.push((unstamp(chunk), now));
            }
            TesterAction::Nothing
        })
        .with_cyclic_action(TICK, move || {
            *counted.lock().unwrap() += 1;
            tick()
        })
        .until(move |_| finished.load(Ordering::SeqCst));
    let sut = std::thread::spawn(move || {
        let _done = SetOnDrop(done);
        std::thread::sleep(LEAD_IN);
        send(start);
        std::thread::sleep(TICK);
    });
    run_testers!(tester);
    sut.join().unwrap();
    let handled = handled.lock().unwrap().clone();
    let ticks = *ticks.lock().unwrap();
    Run { handled, ticks }
}

/// A UDP tester's view of datagrams sent after each of [`GAPS_US`], with `latency` on the link to
/// the tester, which sends to the code under test's socket on each tick.
fn udp_arrivals(latency: Duration) -> Run {
    let tester_addr: SocketAddr = "10.0.0.2:5000".parse().unwrap();
    let sut_addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    snare::set_udp_policy(tester_addr, |p| p.latency = latency);
    let sock = UdpSocket::bind(sut_addr).unwrap();
    let tick = move || TesterAction::SendTo(sut_addr, Bytes(vec![0; 4]));
    arrivals(udp_tester::<Bytes>(tester_addr), tick, move |start| {
        for gap in GAPS_US {
            std::thread::sleep(Duration::from_micros(gap));
            sock.send_to(&stamp(start.elapsed()), tester_addr).unwrap();
        }
    })
}

/// As [`udp_arrivals`], over a TCP connection the tester accepts and writes to on each tick.
fn tcp_arrivals(latency: Duration) -> Run {
    let tester_addr: SocketAddr = "10.0.0.2:6000".parse().unwrap();
    snare::set_tcp_policy(tester_addr, |p| p.latency = latency);
    let tick = || TesterAction::Send(Bytes(vec![0; 4]));
    arrivals(connect_tester::<Bytes>(tester_addr), tick, move |start| {
        let mut stream = TcpStream::connect(tester_addr).unwrap();
        stream.set_nodelay(true).unwrap();
        for gap in GAPS_US {
            std::thread::sleep(Duration::from_micros(gap));
            stream.write_all(&stamp(start.elapsed())).unwrap();
        }
    })
}

/// Every message was handled within a few charged calls of its arrival, and the cyclic action
/// ticked on every period of the run.
#[track_caller]
fn assert_on_arrival(run: &Run, latency: Duration) {
    let handled = &run.handled;
    assert_eq!(
        handled.len(),
        GAPS_US.len(),
        "every message was handled: {handled:?}"
    );
    for &(sent, at) in handled {
        let arrival = sent + latency;
        assert!(
            at >= arrival && at - arrival <= Duration::from_micros(50),
            "sent at {sent:?}, due at {arrival:?}, handled at {at:?}: {handled:?}"
        );
    }
    let last = handled.last().map_or(LEAD_IN, |&(_, at)| at);
    let periods = u32::try_from(last.as_nanos() / TICK.as_nanos()).unwrap();
    assert!(run.ticks >= periods, "{} ticks in {last:?}", run.ticks);
}

fn det() -> Sim {
    Sim::builder().deterministic().seed(7).build()
}

#[test]
fn a_udp_tester_with_a_cyclic_action_handles_each_datagram_on_arrival() {
    for latency in [Duration::ZERO, Duration::from_micros(1_500)] {
        let plain = Sim::new().run(move || udp_arrivals(latency));
        assert_on_arrival(&plain, latency);
        let first = det().run(move || udp_arrivals(latency));
        assert_on_arrival(&first, latency);
        assert_eq!(first, det().run(move || udp_arrivals(latency)), "replays");
    }
}

#[test]
fn a_tcp_tester_with_a_cyclic_action_handles_each_write_on_arrival() {
    for latency in [Duration::ZERO, Duration::from_micros(1_500)] {
        let plain = Sim::new().run(move || tcp_arrivals(latency));
        assert_on_arrival(&plain, latency);
        let first = det().run(move || tcp_arrivals(latency));
        assert_on_arrival(&first, latency);
        assert_eq!(first, det().run(move || tcp_arrivals(latency)), "replays");
    }
}
