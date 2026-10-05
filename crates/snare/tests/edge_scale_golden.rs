//! Behaviour pin for a long deterministic run, ahead of performance work anywhere in the
//! scheduler, clock or fabric: eight threads take 2 000 steps each, every step chosen by a
//! per-thread generator among a yield, a short sleep, a contended mutex, a condvar handoff, a UDP
//! datagram to another thread and a nonblocking receive, and log what they did and when on the
//! sim's clock.
//! Under `deterministic()` the 16 000-entry trace replays exactly in-process, and its FNV-1a hash,
//! length, final time and per-kind counts are pinned to one golden, the same on macOS and Linux,
//! so any change to the baton order, a timer's firing or a datagram's arrival shows up.

#![cfg(unix)]

#[path = "support/golden.rs"]
mod golden;

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use snare::Sim;

const THREADS: usize = 8;
const STEPS: usize = 2_000;

fn addr(t: usize) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 30_000 + t as u16))
}

/// A tiny xorshift generator, seeded per thread.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[derive(Default)]
struct Shared {
    counter: u64,
    handoffs: u64,
}

/// One run's trace: one line per step, in the order the steps were logged.
fn run(seed: u64) -> Vec<String> {
    Sim::builder().deterministic().seed(seed).build().run(|| {
        let log = Arc::new(Mutex::new(Vec::with_capacity(THREADS * STEPS)));
        let shared = Arc::new((Mutex::new(Shared::default()), Condvar::new()));
        let socks: Vec<UdpSocket> = (0..THREADS)
            .map(|t| UdpSocket::bind(addr(t)).unwrap())
            .collect();
        for s in &socks {
            s.set_nonblocking(true).unwrap();
        }
        let threads: Vec<_> = socks
            .into_iter()
            .enumerate()
            .map(|(t, sock)| {
                let log = log.clone();
                let shared = shared.clone();
                std::thread::spawn(move || {
                    let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ (t as u64 + 1));
                    let mut buf = [0u8; 16];
                    for step in 0..STEPS {
                        let roll = rng.next();
                        let what = match roll % 6 {
                            0 => {
                                std::thread::yield_now();
                                "yield".to_string()
                            }
                            1 => {
                                let us = 1 + roll / 6 % 50;
                                std::thread::sleep(Duration::from_micros(us));
                                format!("sleep {us}")
                            }
                            2 => {
                                let mut g = shared.0.lock().unwrap();
                                g.counter += 1;
                                format!("lock {}", g.counter)
                            }
                            3 => {
                                let (lock, cv) = &*shared;
                                let mut g = lock.lock().unwrap();
                                g.handoffs += 1;
                                cv.notify_all();
                                let seen = g.handoffs;
                                let (_g, timeout) =
                                    cv.wait_timeout(g, Duration::from_micros(20)).unwrap();
                                format!("handoff {seen} {}", timeout.timed_out())
                            }
                            4 => {
                                let to = (t + 1 + (roll / 6) as usize % (THREADS - 1)) % THREADS;
                                sock.send_to(&(step as u32).to_be_bytes(), addr(to))
                                    .unwrap();
                                format!("send {to}")
                            }
                            _ => match sock.recv_from(&mut buf) {
                                Ok((n, from)) => format!("recv {} {n}", from.port() - 30_000),
                                Err(e) if e.kind() == ErrorKind::WouldBlock => "recv none".into(),
                                Err(e) => panic!("recv: {e}"),
                            },
                        };
                        let at = snare::time().value().as_nanos();
                        log.lock().unwrap().push(format!("{at} {t} {step} {what}"));
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        Arc::try_unwrap(log).unwrap().into_inner().unwrap()
    })
}

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

#[test]
fn a_long_deterministic_run_replays_a_golden_trace() {
    let trace = run(42);
    assert_eq!(trace.len(), THREADS * STEPS);
    assert_eq!(run(42), trace, "the same seed replays");

    let text = trace.join("\n");
    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
    for line in &trace {
        let kind = line.split(' ').nth(3).unwrap();
        let kind = if line.ends_with("recv none") {
            "recv none"
        } else {
            kind
        };
        *kinds.entry(kind).or_default() += 1;
    }
    let mut out = format!(
        "entries {}\nfnv1a {:016x}\nlast {}\n",
        trace.len(),
        fnv1a(text.as_bytes()),
        trace.last().unwrap()
    );
    for (kind, n) in kinds {
        out.push_str(&format!("{kind} {n}\n"));
    }
    golden::check_text("edge_scale_trace.txt", &out);
}
