//! Behaviour pins for large TCP transfers, ahead of performance work on the stream pipes: 16 MiB
//! written in 64 KiB chunks across a link with 1 ms of latency arrives intact (length and FNV-1a
//! checksum), in an exact virtual time and segment count, on the free-running virtual clock and
//! under `deterministic()`; a small receive window stretches the same transfer to an exact longer
//! time; and an echo of 4 MiB in both directions at once comes back byte for byte. Each transfer
//! starts once the connection is accepted.
//!
//! Connections waiting in the listener's backlog use the same buffer limits as accepted streams
//! (see `writes_before_accept_are_flow_controlled`).

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use snare::{Sim, TcpPolicy};

const MIB: usize = 1 << 20;
const CHUNK: usize = 64 * 1024;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// What one transfer of `len` bytes saw at the reader: length, checksum, the virtual time from the
/// connect to end-of-stream, and the host's TCP segment counters.
#[derive(Debug, PartialEq)]
struct Transfer {
    len: usize,
    checksum: u64,
    took: Duration,
    in_segs: u64,
    out_segs: u64,
}

fn transfer(sim: &Sim, len: usize, policy: impl FnOnce(&mut TcpPolicy)) -> Transfer {
    let got = sim.run(|| {
        let listener = TcpListener::bind("127.0.0.1:7000").unwrap();
        snare::set_tcp_policy("127.0.0.1:7000", policy);
        let data = pattern(len);
        let start = Instant::now();
        let mut c = TcpStream::connect("127.0.0.1:7000").unwrap();
        let (mut s, _) = listener.accept().unwrap();
        let writer = std::thread::spawn(move || {
            for chunk in data.chunks(CHUNK) {
                c.write_all(chunk).unwrap();
            }
        });
        let mut got = Vec::with_capacity(len);
        s.read_to_end(&mut got).unwrap();
        writer.join().unwrap();
        (got, start.elapsed())
    });
    let tcp = sim.proto_counters().tcp4;
    Transfer {
        len: got.0.len(),
        checksum: fnv1a(&got.0),
        took: got.1,
        in_segs: tcp.in_segs,
        out_segs: tcp.out_segs,
    }
}

/// The pinned outcomes per OS: transfer time and deterministic segment count for 16 MiB,
/// transfer time and deterministic segment count for 4 MiB under a 64 KiB window, and echo time.
#[cfg(target_os = "linux")]
const PINS: (u64, u64, u64, u64, u64) = (114_000_114, 512, 52_000_052, 128, 30_000_030);
#[cfg(target_os = "macos")]
const PINS: (u64, u64, u64, u64, u64) = (64_000_064, 1280, 22_000_022, 320, 17_000_017);

fn check_plain_transfer(got: Transfer, len: usize, nanos: u64) {
    assert_eq!(
        (got.len, got.checksum, got.took),
        (len, fnv1a(&pattern(len)), Duration::from_nanos(nanos))
    );
    assert!(got.in_segs > 0);
    assert_eq!(got.in_segs, got.out_segs);
}

fn latency(p: &mut TcpPolicy) {
    p.latency = Duration::from_millis(1);
}

#[test]
fn sixteen_mib_across_a_millisecond_link_arrive_intact_in_exact_time() {
    let want = |segs| Transfer {
        len: 16 * MIB,
        checksum: fnv1a(&pattern(16 * MIB)),
        took: Duration::from_nanos(PINS.0),
        in_segs: segs,
        out_segs: segs,
    };
    check_plain_transfer(transfer(&Sim::new(), 16 * MIB, latency), 16 * MIB, PINS.0);
    let det = Sim::builder().deterministic().seed(1).build();
    assert_eq!(transfer(&det, 16 * MIB, latency), want(PINS.1));
}

#[test]
fn a_small_receive_window_stretches_the_transfer_exactly() {
    let policy = |p: &mut TcpPolicy| {
        p.latency = Duration::from_millis(1);
        p.recv_window = Some(64 * 1024);
    };
    check_plain_transfer(transfer(&Sim::new(), 4 * MIB, policy), 4 * MIB, PINS.2);
    let deterministic = Sim::builder().deterministic().seed(1).build();
    assert_eq!(
        transfer(&deterministic, 4 * MIB, policy),
        Transfer {
            len: 4 * MIB,
            checksum: fnv1a(&pattern(4 * MIB)),
            took: Duration::from_nanos(PINS.2),
            in_segs: PINS.3,
            out_segs: PINS.3,
        }
    );
}

#[test]
fn four_mib_echoed_both_ways_at_once_come_back_intact() {
    const LEN: usize = 4 * MIB;
    let sim = Sim::builder().deterministic().seed(2).build();
    let (back, took) = sim.run(|| {
        let listener = TcpListener::bind("127.0.0.1:7001").unwrap();
        snare::set_tcp_policy("127.0.0.1:7001", latency);
        let echo = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = s.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&buf[..n]).unwrap();
            }
        });
        let data = pattern(LEN);
        let start = Instant::now();
        let mut c = TcpStream::connect("127.0.0.1:7001").unwrap();
        let mut reader = c.try_clone().unwrap();
        let read = std::thread::spawn(move || {
            let mut got = Vec::with_capacity(LEN);
            reader.read_to_end(&mut got).unwrap();
            got
        });
        for chunk in data.chunks(CHUNK) {
            c.write_all(chunk).unwrap();
        }
        c.shutdown(std::net::Shutdown::Write).unwrap();
        echo.join().unwrap();
        let back = read.join().unwrap();
        (back, start.elapsed())
    });
    assert_eq!((back.len(), fnv1a(&back)), (LEN, fnv1a(&pattern(LEN))));
    assert_eq!(took, Duration::from_nanos(PINS.4));
}

#[test]
fn writes_before_accept_are_flow_controlled() {
    Sim::new().run(|| {
        let listener = TcpListener::bind("127.0.0.1:7002").unwrap();
        let fill = |c: &mut TcpStream| {
            c.set_nonblocking(true).unwrap();
            let buf = vec![0u8; CHUNK];
            let mut total = 0;
            while total <= 64 * MIB {
                match c.write(&buf) {
                    Ok(n) => total += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("write: {e}"),
                }
            }
            total
        };
        let mut accepted_first = TcpStream::connect("127.0.0.1:7002").unwrap();
        let _server = listener.accept().unwrap();
        let after_accept = fill(&mut accepted_first);
        let mut queued = TcpStream::connect("127.0.0.1:7002").unwrap();
        assert_eq!(
            fill(&mut queued),
            after_accept,
            "the backlog holds the same buffers"
        );
    });
}
