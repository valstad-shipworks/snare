//! Golden traces of the deterministic schedule, ahead of performance work on the scheduler and the
//! clock: for a set of fixed scenarios, the exact order in which the threads' events happen and
//! the exact virtual time of each, under `deterministic()` with a fixed seed, compared line for
//! line with a file in `tests/golden/`. An optimisation that changes who runs next, when a wake is
//! delivered or where a time skip lands changes a trace and fails here.
//!
//! Each scenario first runs twice and must replay exactly; then its trace must equal
//! `tests/golden/edge_time_<scenario>.<os>.txt` if that file exists, else
//! `tests/golden/edge_time_<scenario>.txt`. To regenerate after an intended change, run with
//! `SNARE_BLESS=1` (writes the shared file) or `SNARE_BLESS=os` (writes this OS's file, for a
//! trace that legitimately differs between platforms), and review the diff before committing.
//!
//! The scenarios record their events under `snare::real`, so the recording itself is invisible
//! to the schedule. Seed sensitivity is pinned too: the seed changes only what randomness decides
//! (random bytes, link jitter), so a scenario without randomness traces the same under any seed,
//! and one with it traces differently under different seeds and identically under the same one.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use snare::{Bytes, Line, Sim, TesterAction, connect_tester, run_testers, sched, udp_tester};

#[path = "support/golden.rs"]
mod golden_paths;

const MS: Duration = Duration::from_millis(1);
const US: Duration = Duration::from_micros(1);

/// A scenario's event log: one line per event, `<virtual ns> <who> <what>`.
#[derive(Clone, Default)]
struct Trace(Arc<Mutex<Vec<String>>>);

impl Trace {
    fn note(&self, who: &str, what: impl std::fmt::Display) {
        let at = sched::now().as_nanos();
        let line = format!("{at:>12} {who} {what}");
        snare::real(|| self.0.lock().unwrap().push(line));
    }

    fn lines(&self) -> Vec<String> {
        snare::real(|| self.0.lock().unwrap().clone())
    }
}

/// Runs `scenario` under `deterministic()` with `seed` and returns its trace.
fn trace(seed: u64, scenario: fn(&Trace)) -> Vec<String> {
    let log = Trace::default();
    let sim = Sim::builder().deterministic().seed(seed).build();
    sim.run(|| scenario(&log));
    log.lines()
}

fn golden_dir() -> PathBuf {
    golden_paths::path("")
}

/// Checks `lines` against the scenario's golden file, or writes it under `SNARE_BLESS`.
fn check_golden(name: &str, lines: &[String]) {
    let dir = golden_dir();
    let shared = dir.join(format!("edge_time_{name}.txt"));
    let own = dir.join(format!("edge_time_{name}.{}.txt", std::env::consts::OS));
    let text = lines.iter().fold(String::new(), |mut text, line| {
        text.push_str(line);
        text.push('\n');
        text
    });
    match std::env::var("SNARE_BLESS").as_deref() {
        Ok("os") => {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&own, text).unwrap();
            return;
        }
        Ok(v) if !v.is_empty() && v != "0" => {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&shared, text).unwrap();
            return;
        }
        _ => {}
    }
    let path = if own.exists() { own } else { shared };
    let golden = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "no golden trace at {} ({e}); run with SNARE_BLESS=1 to write it",
            path.display()
        )
    });
    let golden: Vec<&str> = golden.lines().collect();
    if let Some(i) = (0..golden.len().max(lines.len()))
        .find(|&i| golden.get(i).copied() != lines.get(i).map(String::as_str))
    {
        panic!(
            "trace {name} departs from {} at line {}:\n  golden: {:?}\n  traced: {:?}\n\
             ({} golden lines, {} traced; SNARE_BLESS=1 regenerates after an intended change)\n\
             actual trace:\n{}",
            path.display(),
            i + 1,
            golden.get(i),
            lines.get(i),
            golden.len(),
            lines.len(),
            lines.join("\n")
        );
    }
}

/// Replays `scenario` under seed 1, checks it against its golden trace, and returns the trace.
fn pinned(name: &str, scenario: fn(&Trace)) -> Vec<String> {
    let first = trace(1, scenario);
    assert_eq!(trace(1, scenario), first, "{name} replays");
    assert!(!first.is_empty(), "{name} traced nothing");
    check_golden(name, &first);
    first
}

fn mutex_contention(log: &Trace) {
    let lock = Arc::new(Mutex::new(0u32));
    let workers: Vec<_> = (0..5)
        .map(|w| {
            let lock = lock.clone();
            let log = log.clone();
            thread::spawn(move || {
                for round in 0..3 {
                    let mut held = lock.lock().unwrap();
                    *held += 1;
                    log.note(&format!("w{w}"), format_args!("holds {round} count {held}"));
                    thread::yield_now();
                    drop(held);
                    thread::sleep(US * (w + 1));
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    log.note("main", "joined");
}

fn condvar_ping_pong(log: &Trace) {
    let state = Arc::new((Mutex::new(0u32), Condvar::new()));
    let pong = {
        let state = state.clone();
        let log = log.clone();
        thread::spawn(move || {
            let (lock, cv) = &*state;
            for _ in 0..8 {
                let mut turn = lock.lock().unwrap();
                while *turn % 2 == 0 {
                    turn = cv.wait(turn).unwrap();
                }
                log.note("pong", *turn);
                *turn += 1;
                cv.notify_one();
            }
        })
    };
    let (lock, cv) = &*state;
    for _ in 0..8 {
        let mut turn = lock.lock().unwrap();
        while *turn % 2 == 1 {
            turn = cv.wait(turn).unwrap();
        }
        log.note("ping", *turn);
        *turn += 1;
        cv.notify_one();
        drop(turn);
        thread::sleep(10 * US);
    }
    pong.join().unwrap();
}

fn channel_producers(log: &Trace) {
    let (tx, rx) = mpsc::sync_channel(2);
    let producers: Vec<_> = (0..6u32)
        .map(|p| {
            let tx = tx.clone();
            thread::spawn(move || {
                for n in 0..4u32 {
                    tx.send((p, n)).unwrap();
                    if p % 2 == 0 {
                        thread::yield_now();
                    } else {
                        thread::sleep(US * (p * 3 + n));
                    }
                }
            })
        })
        .collect();
    drop(tx);
    for (p, n) in rx {
        log.note("rx", format_args!("p{p} n{n}"));
    }
    for producer in producers {
        producer.join().unwrap();
    }
}

fn sleeps_with_ties(log: &Trace) {
    let sleepers: Vec<_> = [3u64, 1, 3, 2, 1, 3, 2, 1]
        .into_iter()
        .enumerate()
        .map(|(i, ms)| {
            let log = log.clone();
            thread::spawn(move || {
                thread::sleep(MS * ms as u32);
                log.note(&format!("s{i}"), "woke");
                thread::sleep(MS * (ms as u32 % 2));
                log.note(&format!("s{i}"), "again");
            })
        })
        .collect();
    for sleeper in sleepers {
        sleeper.join().unwrap();
    }
}

fn node(log: Trace, path: String, depth: u32) {
    log.note(&path, "start");
    let children: Vec<_> = (0..2)
        .filter(|_| depth < 3)
        .map(|c| {
            let log = log.clone();
            let child = format!("{path}.{c}");
            thread::spawn(move || node(log, child, depth + 1))
        })
        .collect();
    thread::sleep(US * (depth + 1));
    for child in children {
        child.join().unwrap();
    }
    log.note(&path, "end");
}

fn spawn_join_tree(log: &Trace) {
    node(log.clone(), "n".into(), 0);
}

fn testers(log: &Trace) {
    let server = connect_tester::<Line>("127.0.0.9:9600")
        .then_action(|msg, _| TesterAction::Send(Line(format!("echo:{}", msg.0))))
        .until_after(20 * MS);
    let ticker = udp_tester::<Bytes>("127.0.0.10:9601")
        .with_cyclic_action(3 * MS, || TesterAction::Send(Bytes(b"tick".to_vec())))
        .until_after(10 * MS);
    let reader = UdpSocket::bind("127.0.0.1:9602").unwrap();
    reader.send_to(b"hello", "127.0.0.10:9601").unwrap();
    let client = {
        let log = log.clone();
        thread::spawn(move || {
            let stream = TcpStream::connect("127.0.0.9:9600").unwrap();
            let mut lines = BufReader::new(stream.try_clone().unwrap());
            for i in 0..3 {
                (&stream).write_all(format!("m{i}\n").as_bytes()).unwrap();
                let mut line = String::new();
                lines.read_line(&mut line).unwrap();
                log.note("client", line.trim_end());
                thread::sleep(2 * MS);
            }
        })
    };
    let ticks = {
        let log = log.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 8];
            for _ in 0..3 {
                let (n, _) = reader.recv_from(&mut buf).unwrap();
                log.note("ticks", String::from_utf8_lossy(&buf[..n]));
            }
        })
    };
    run_testers!(server, ticker);
    client.join().unwrap();
    ticks.join().unwrap();
    log.note("main", "testers done");
}

fn udp_tcp_exchange(log: &Trace) {
    snare::set_udp_policy("127.0.0.1:9701", |p| {
        p.latency = 100 * US;
        p.jitter = 50 * US;
    });
    let echo = UdpSocket::bind("127.0.0.1:9701").unwrap();
    let udp_peer = {
        let log = log.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 8];
            for _ in 0..6 {
                let (n, from) = echo.recv_from(&mut buf).unwrap();
                log.note("udp-echo", String::from_utf8_lossy(&buf[..n]));
                echo.send_to(&buf[..n], from).unwrap();
            }
        })
    };
    let listener = TcpListener::bind("127.0.0.1:9702").unwrap();
    let tcp_peer = {
        let log = log.clone();
        thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            log.note("tcp-server", "accepted");
            let mut buf = [0u8; 16];
            loop {
                let n = conn.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                log.note("tcp-server", format_args!("read {n}"));
                conn.write_all(&buf[..n]).unwrap();
            }
            log.note("tcp-server", "eof");
        })
    };
    let sock = UdpSocket::bind("127.0.0.1:9700").unwrap();
    for i in 0..6 {
        sock.send_to(format!("d{i}").as_bytes(), "127.0.0.1:9701")
            .unwrap();
    }
    let mut buf = [0u8; 8];
    for _ in 0..6 {
        let (n, _) = sock.recv_from(&mut buf).unwrap();
        log.note("udp-client", String::from_utf8_lossy(&buf[..n]));
    }
    let mut stream = TcpStream::connect("127.0.0.1:9702").unwrap();
    for chunk in ["abc", "defgh", "ij"] {
        stream.write_all(chunk.as_bytes()).unwrap();
        let mut back = vec![0u8; chunk.len()];
        stream.read_exact(&mut back).unwrap();
        log.note("tcp-client", String::from_utf8_lossy(&back));
    }
    drop(stream);
    udp_peer.join().unwrap();
    tcp_peer.join().unwrap();
}

fn clock_spins(log: &Trace) {
    let origin = Instant::now();
    let spinner = {
        let log = log.clone();
        thread::spawn(move || {
            for at in [300u32, 550, 700] {
                while Instant::now() < origin + US * at {}
                log.note("spinner", at);
            }
        })
    };
    let yielder = {
        let log = log.clone();
        thread::spawn(move || {
            for at in [200u32, 600] {
                while Instant::now() < origin + US * at {
                    thread::yield_now();
                }
                log.note("yielder", at);
            }
        })
    };
    let sleeper = {
        let log = log.clone();
        thread::spawn(move || {
            for at in [150u32, 400, 650] {
                thread::sleep((origin + US * at).saturating_duration_since(Instant::now()));
                log.note("sleeper", at);
            }
        })
    };
    for t in [spinner, yielder, sleeper] {
        t.join().unwrap();
    }
}

fn rayon_pool(log: &Trace) {
    use rayon::prelude::*;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(3)
        .build()
        .unwrap();
    let items: Vec<(u64, Option<usize>)> = pool.install(|| {
        (0..24u64)
            .into_par_iter()
            .map(|x| (x * x % 17, rayon::current_thread_index()))
            .collect()
    });
    for (i, (v, worker)) in items.iter().enumerate() {
        log.note(
            "rayon",
            format_args!("item {i} value {v} worker {worker:?}"),
        );
    }
    drop(pool);
    log.note("main", "pool dropped");
}

fn crossbeam_sync(log: &Trace) {
    let wg = crossbeam_utils::sync::WaitGroup::new();
    let parker = crossbeam_utils::sync::Parker::new();
    let unparker = parker.unparker().clone();
    let shared = Arc::new(Mutex::new(Vec::new()));
    crossbeam_utils::thread::scope(|s| {
        for w in 0..4u32 {
            let wg = wg.clone();
            let shared = shared.clone();
            let log = log.clone();
            s.spawn(move |_| {
                let backoff = crossbeam_utils::Backoff::new();
                for _ in 0..w {
                    backoff.snooze();
                }
                thread::sleep(US * (4 - w));
                shared.lock().unwrap().push(w);
                log.note(&format!("cb{w}"), "done");
                drop(wg);
            });
        }
        let unparker_log = log.clone();
        s.spawn(move |_| {
            thread::sleep(20 * US);
            unparker_log.note("unparker", "unpark");
            unparker.unpark();
        });
        wg.wait();
        log.note("main", format_args!("waited {:?}", shared.lock().unwrap()));
        parker.park();
        log.note("main", "parked");
    })
    .unwrap();
}

/// Randomness the seed decides: each thread's OS random bytes (through std's `RandomState`) and
/// the jitter of a link.
fn seeded(log: &Trace) {
    let hashes: Vec<_> = (0..3)
        .map(|_| thread::spawn(|| RandomState::new().hash_one(7u64)))
        .collect();
    for (i, h) in hashes.into_iter().enumerate() {
        log.note(
            &format!("hash{i}"),
            format_args!("{:016x}", h.join().unwrap()),
        );
    }
    snare::set_udp_policy("127.0.0.1:9801", |p| {
        p.latency = 10 * US;
        p.jitter = 400 * US;
    });
    let rx = UdpSocket::bind("127.0.0.1:9801").unwrap();
    let tx = UdpSocket::bind("127.0.0.1:9800").unwrap();
    for i in 0..8u8 {
        tx.send_to(&[i], "127.0.0.1:9801").unwrap();
    }
    let mut buf = [0u8; 1];
    for _ in 0..8 {
        rx.recv_from(&mut buf).unwrap();
        log.note("rx", buf[0]);
    }
}

#[test]
fn golden_mutex_contention() {
    pinned("mutex_contention", mutex_contention);
}

#[test]
fn golden_condvar_ping_pong() {
    pinned("condvar_ping_pong", condvar_ping_pong);
}

#[test]
fn golden_channel_producers() {
    pinned("channel_producers", channel_producers);
}

#[test]
fn golden_sleeps_with_ties() {
    pinned("sleeps_with_ties", sleeps_with_ties);
}

#[test]
fn golden_spawn_join_tree() {
    pinned("spawn_join_tree", spawn_join_tree);
}

#[test]
fn golden_testers() {
    pinned("testers", testers);
}

#[test]
fn golden_udp_tcp_exchange() {
    pinned("udp_tcp_exchange", udp_tcp_exchange);
}

#[test]
fn golden_clock_spins() {
    pinned("clock_spins", clock_spins);
}

#[test]
fn golden_rayon_pool() {
    pinned("rayon_pool", rayon_pool);
}

#[test]
fn golden_crossbeam_sync() {
    pinned("crossbeam_sync", crossbeam_sync);
}

#[test]
fn golden_seeded() {
    pinned("seeded", seeded);
}

/// The seed decides randomness and nothing else: scenarios without randomness trace the same under
/// any seed; the seeded scenario traces differently under another seed, and identically under the
/// same one.
#[test]
fn only_randomness_depends_on_the_seed() {
    for scenario in [mutex_contention, sleeps_with_ties, clock_spins] {
        assert_eq!(trace(1, scenario), trace(99, scenario));
    }
    let one = trace(1, seeded);
    let two = trace(2, seeded);
    assert_eq!(trace(2, seeded), two, "seed 2 replays");
    let hashes = |t: &[String]| -> Vec<String> {
        t.iter().filter(|l| l.contains(" hash")).cloned().collect()
    };
    let arrivals = |t: &[String]| -> Vec<String> {
        t.iter().filter(|l| l.contains(" rx ")).cloned().collect()
    };
    assert_ne!(hashes(&one), hashes(&two), "random bytes follow the seed");
    assert_ne!(
        arrivals(&one),
        arrivals(&two),
        "link jitter follows the seed"
    );
}
