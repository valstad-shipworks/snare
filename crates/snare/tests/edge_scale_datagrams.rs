//! Behaviour pins for datagram queues at scale, ahead of performance work on the fabric's queues:
//! ten thousand 100-byte datagrams sent at a socket nobody reads are admitted against its default
//! receive buffer until it is full, with exact delivered, overflowed and dropped counts and the
//! host's `UDP` counters to match, whether they arrive at once or after a link delay; the ones
//! admitted are the first sent, in order. With `enforce_rcvbuf` off all ten thousand queue and
//! drain in order, and a recording tester takes all ten thousand in send order.
//!
//! The admitted count follows the host OS's accounting (Linux `truesize`, macOS `sb_mbcnt`), so it
//! is pinned per OS.

#![cfg(unix)]

use std::io::ErrorKind;
use std::net::UdpSocket;
use std::time::Duration;

use snare::{Bytes, Sim, SocketEntry, run_testers, udp_tester};

const DATAGRAMS: u32 = 10_000;
const LEN: usize = 100;

/// How many 100-byte datagrams the default UDP receive buffer admits: Linux charges each its
/// `truesize`, macOS its mbufs against `sb_mbmax`.
#[cfg(target_os = "linux")]
const ADMITTED: u64 = 221;
#[cfg(target_os = "macos")]
const ADMITTED: u64 = 4_099;

fn payload(n: u32) -> Vec<u8> {
    n.to_be_bytes().repeat(LEN / 4)
}

fn entry(sock: &UdpSocket) -> SocketEntry {
    snare::socket_entry(snare::socket_id(sock).unwrap()).unwrap()
}

/// Every datagram queued on `sock`, as the sequence numbers they carry.
fn drain(sock: &UdpSocket) -> Vec<u32> {
    sock.set_nonblocking(true).unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 2 * LEN];
    loop {
        match sock.recv(&mut buf) {
            Ok(n) => {
                assert_eq!(n, LEN);
                got.push(u32::from_be_bytes(buf[..4].try_into().unwrap()));
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => return got,
            Err(e) => panic!("recv: {e}"),
        }
    }
}

/// Sends ten thousand datagrams at a socket nobody reads across a link of `latency`, then reads
/// back its counters and queue.
fn flood(sim: &Sim, latency: Duration) -> (SocketEntry, Vec<u32>, Duration) {
    sim.run(|| {
        let rx = UdpSocket::bind("127.0.0.1:9000").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:9001").unwrap();
        snare::set_udp_policy("127.0.0.1:9000", |p| p.latency = latency);
        for n in 0..DATAGRAMS {
            tx.send_to(&payload(n), "127.0.0.1:9000").unwrap();
        }
        std::thread::sleep(latency + Duration::from_millis(5));
        let e = entry(&rx);
        (e, drain(&rx), snare::time().value())
    })
}

#[test]
fn ten_thousand_datagrams_overflow_the_default_buffer_exactly() {
    for latency in [Duration::ZERO, Duration::from_millis(1)] {
        let sim = Sim::new();
        let (e, got, at) = flood(&sim, latency);
        let dropped = u64::from(DATAGRAMS) - ADMITTED;
        assert_eq!(
            (e.delivered, e.overflowed, u64::from(e.drops), e.wire_lost),
            (ADMITTED, dropped, dropped, 0),
            "latency {latency:?}"
        );
        assert_eq!(
            (e.queued as u64, e.queued_bytes as u64),
            (ADMITTED, ADMITTED * LEN as u64)
        );
        assert_eq!(
            got,
            (0..ADMITTED as u32).collect::<Vec<_>>(),
            "the first sent are kept"
        );
        assert_eq!(
            at,
            latency + Duration::from_millis(5) + Duration::from_nanos(1) + Duration::from_micros(1),
            "the sleep lands 1 ns past its deadline and the drain's last empty read costs 1 µs"
        );
        let udp = sim.proto_counters().udp4;
        assert_eq!(
            (udp.sent, udp.received, udp.rcvbuf_errors, udp.no_ports),
            (u64::from(DATAGRAMS), ADMITTED, dropped, 0)
        );
    }
}

#[test]
fn without_enforcement_ten_thousand_datagrams_queue_in_order() {
    let sim = Sim::new();
    sim.set_sys_limits(|l| l.enforce_rcvbuf = false);
    let (e, got, _) = flood(&sim, Duration::from_millis(1));
    assert_eq!(
        (e.delivered, e.overflowed, e.drops),
        (u64::from(DATAGRAMS), 0, 0)
    );
    assert_eq!(got, (0..DATAGRAMS).collect::<Vec<_>>());
}

#[test]
fn a_recording_tester_takes_ten_thousand_datagrams_in_send_order() {
    Sim::new().run(|| {
        let sink = udp_tester::<Bytes>("127.0.0.5:7000")
            .recording()
            .until_after(Duration::from_millis(50));
        let client = std::thread::spawn(|| {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            for n in 0..DATAGRAMS {
                sock.send_to(&payload(n), "127.0.0.5:7000").unwrap();
            }
        });
        run_testers!(sink);
        client.join().unwrap();
        let got: Vec<u32> = sink
            .recorded()
            .iter()
            .map(|(_, b)| u32::from_be_bytes(b.0[..4].try_into().unwrap()))
            .collect();
        assert_eq!(got, (0..DATAGRAMS).collect::<Vec<_>>());
    });
}
