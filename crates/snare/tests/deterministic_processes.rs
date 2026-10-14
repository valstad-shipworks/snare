//! A `deterministic()` run replays in a fresh process, not just in the one that ran it first.
//!
//! The other replay tests run a scenario twice in one process, where whatever the process drew
//! once (std's per-thread hash keys, a library's statics) is the same for both runs. Here a
//! representative workload runs in child processes of this test binary, each with its own address
//! layout, entropy and statics, and every child must log the same events at the same sim times:
//! threads handing off through a mutex, condition variable, rwlock, barrier, channel and parker,
//! sleepers with tied deadlines, TCP echoes, datagrams over a lossy, jittery link, `HashMap` order
//! on the thread that builds and runs the sim, absolute wall-clock readings and a multi-thread
//! tokio runtime. The parent re-runs the binary on [`child_workload`] with
//! `SNARE_REPLAY_CHILD` set; without it that test returns at once.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::Command;
use std::sync::{Arc, Barrier, Condvar, Mutex, RwLock, mpsc};
use std::time::{Duration, Instant, SystemTime};

use snare::Sim;

const CHILDREN: usize = 3;

type Log = Arc<Mutex<Vec<String>>>;

fn note(log: &Log, start: Instant, event: String) {
    let at = start.elapsed().as_nanos();
    log.lock().unwrap().push(format!("{at} {event}"));
}

fn threads(log: &Log, start: Instant) {
    let pair = Arc::new((Mutex::new(Vec::<u32>::new()), Condvar::new()));
    let rw = Arc::new(RwLock::new(0u64));
    let barrier = Arc::new(Barrier::new(4));
    let (tx, rx) = mpsc::sync_channel::<(u32, u32)>(2);
    let workers: Vec<_> = (0..4u32)
        .map(|w| {
            let (log, pair, rw, barrier, tx) = (
                log.clone(),
                pair.clone(),
                rw.clone(),
                barrier.clone(),
                tx.clone(),
            );
            std::thread::spawn(move || {
                for i in 0..12u32 {
                    pair.0.lock().unwrap().push(w * 100 + i);
                    pair.1.notify_one();
                    if i % 3 == w % 3 {
                        std::thread::sleep(Duration::from_micros(100 * u64::from(w % 2 + 1)));
                    }
                    if i % 4 == 0 {
                        *rw.write().unwrap() += u64::from(w);
                    } else {
                        let seen = *rw.read().unwrap();
                        note(&log, start, format!("read {w} {i} {seen}"));
                    }
                    tx.send((w, i)).unwrap();
                    if i == 6 {
                        let leader = barrier.wait().is_leader();
                        note(&log, start, format!("barrier {w} {leader}"));
                    }
                    std::thread::yield_now();
                }
            })
        })
        .collect();
    drop(tx);
    let consumer = {
        let (log, pair) = (log.clone(), pair.clone());
        std::thread::spawn(move || {
            let mut got = 0;
            while got < 48 {
                let mut queue = pair.0.lock().unwrap();
                while queue.is_empty() {
                    let (next, wait) = pair
                        .1
                        .wait_timeout(queue, Duration::from_millis(1))
                        .unwrap();
                    queue = next;
                    if wait.timed_out() {
                        note(&log, start, "condvar timeout".into());
                    }
                }
                got += queue.len();
                note(
                    &log,
                    start,
                    format!("took {:?}", std::mem::take(&mut *queue)),
                );
            }
        })
    };
    for (w, i) in rx {
        note(log, start, format!("sent {w} {i}"));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    consumer.join().unwrap();
    let parked = {
        let log = log.clone();
        std::thread::spawn(move || {
            for i in 0..4 {
                std::thread::park_timeout(Duration::from_millis(3));
                note(&log, start, format!("unparked {i}"));
            }
        })
    };
    for _ in 0..2 {
        std::thread::sleep(Duration::from_millis(2));
        parked.thread().unpark();
    }
    parked.join().unwrap();
}

fn network(log: &Log, start: Instant) {
    let listener = TcpListener::bind("127.0.0.1:7100").unwrap();
    let server = {
        let log = log.clone();
        std::thread::spawn(move || {
            let echoes: Vec<_> = (0..4)
                .map(|_| {
                    let (mut conn, peer) = listener.accept().unwrap();
                    note(&log, start, format!("accepted {peer}"));
                    std::thread::spawn(move || {
                        let mut buf = [0u8; 64];
                        loop {
                            let n = conn.read(&mut buf).unwrap();
                            if n == 0 {
                                break;
                            }
                            conn.write_all(&buf[..n]).unwrap();
                        }
                    })
                })
                .collect();
            for echo in echoes {
                echo.join().unwrap();
            }
        })
    };
    let clients: Vec<_> = (0..4u64)
        .map(|c| {
            let log = log.clone();
            std::thread::spawn(move || {
                let mut conn = TcpStream::connect("127.0.0.1:7100").unwrap();
                for i in 0..4 {
                    let line = format!("{c}:{i}");
                    conn.write_all(line.as_bytes()).unwrap();
                    let mut back = vec![0u8; line.len()];
                    conn.read_exact(&mut back).unwrap();
                    note(&log, start, format!("echoed {c} {i}"));
                    std::thread::sleep(Duration::from_micros(150 * (c % 2 + 1)));
                }
            })
        })
        .collect();
    for client in clients {
        client.join().unwrap();
    }
    server.join().unwrap();

    snare::set_udp_policy("127.0.0.9:7500", |p| {
        p.loss_rate = 0.3;
        p.duplicate_rate = 0.2;
        p.latency = Duration::from_micros(300);
        p.jitter = Duration::from_micros(400);
    });
    let rx = UdpSocket::bind("127.0.0.9:7500").unwrap();
    rx.set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    let senders: Vec<_> = (0..3u8)
        .map(|k| {
            std::thread::spawn(move || {
                let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
                for i in 0..8u8 {
                    tx.send_to(&[k, i], "127.0.0.9:7500").unwrap();
                    if i % 3 == k {
                        std::thread::sleep(Duration::from_micros(150));
                    }
                }
            })
        })
        .collect();
    let mut buf = [0u8; 4];
    while let Ok((n, from)) = rx.recv_from(&mut buf) {
        note(log, start, format!("datagram {from} {:?}", &buf[..n]));
    }
    for sender in senders {
        sender.join().unwrap();
    }
}

fn runtime(log: &Log, start: Instant) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(3)
        .enable_all()
        .build()
        .unwrap();
    let log = log.clone();
    rt.block_on(async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<u64>(2);
        for p in 0..3u64 {
            let tx = tx.clone();
            tokio::spawn(async move {
                for i in 0..4 {
                    tx.send(p * 10 + i).await.unwrap();
                    tokio::time::sleep(Duration::from_micros(100 * (p + 1))).await;
                }
            });
        }
        drop(tx);
        while let Some(v) = rx.recv().await {
            note(&log, start, format!("task {v}"));
        }
        let mut set = tokio::task::JoinSet::new();
        for k in 0..6u64 {
            set.spawn(async move {
                tokio::time::sleep(Duration::from_millis(k % 3)).await;
                k
            });
        }
        while let Some(k) = set.join_next().await {
            note(&log, start, format!("joined {}", k.unwrap()));
        }
    });
}

fn workload() -> Vec<String> {
    let log: Log = Arc::default();
    let start = Instant::now();
    threads(&log, start);
    network(&log, start);
    runtime(&log, start);
    let map: HashMap<u32, ()> = (0..24).map(|i| (i, ())).collect();
    note(
        &log,
        start,
        format!("map {:?}", map.keys().collect::<Vec<_>>()),
    );
    let wall = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    note(&log, start, format!("wall {wall:?}"));
    Arc::try_unwrap(log).unwrap().into_inner().unwrap()
}

#[test]
fn child_workload() {
    if std::env::var_os("SNARE_REPLAY_CHILD").is_none() {
        return;
    }
    let log = Sim::builder()
        .deterministic()
        .seed(11)
        .build()
        .run(workload);
    for line in log {
        println!("event {line}");
    }
}

fn child_log() -> Vec<String> {
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_workload",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SNARE_REPLAY_CHILD", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "the child failed: {stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("event "))
        .map(str::to_owned)
        .collect()
}

#[test]
fn a_run_replays_in_fresh_processes() {
    if std::env::var_os("SNARE_REPLAY_CHILD").is_some() {
        return;
    }
    let first = child_log();
    assert!(first.len() > 100, "{first:?}");
    for _ in 1..CHILDREN {
        let again = child_log();
        let at = first.iter().zip(&again).position(|(a, b)| a != b);
        assert!(
            at.is_none() && first.len() == again.len(),
            "diverged at event {at:?}: {:?} vs {:?}",
            at.map(|i| &first[i]),
            at.map(|i| &again[i])
        );
    }
}
