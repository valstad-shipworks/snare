//! tokio runtimes under sims: each sim builds its own runtime, as `#[tokio::test]` does per test.
//! The io and time drivers and the blocking pool belong to the runtime, but with the `signal` or
//! `process` feature every runtime with I/O enabled dups one process-wide socketpair, so sims
//! after the first, and sims running alongside it, must still be able to build one.

#![cfg(unix)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use snare::{Signal, SignalDelivery, Sim};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::runtime::{Builder, Runtime};
use tokio::signal::unix::{SignalKind, signal};

fn sim(deterministic: bool) -> Sim {
    let builder = Sim::builder()
        .stuck_after(Duration::from_secs(10))
        .process_signal_handlers();
    if deterministic {
        builder.deterministic().build()
    } else {
        builder.build()
    }
}

fn current_thread() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

fn multi_thread() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

async fn tcp_echo() {
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(any).await.unwrap();
    let to = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(&buf).await.unwrap();
    });
    let mut client = TcpStream::connect(to).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    server.await.unwrap();
}

async fn udp_round_trip() {
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let a = UdpSocket::bind(any).await.unwrap();
    let b = UdpSocket::bind(any).await.unwrap();
    a.send_to(b"ping", b.local_addr().unwrap()).await.unwrap();
    let mut buf = [0u8; 16];
    let (n, from) = b.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ping");
    assert_eq!(from, a.local_addr().unwrap());
}

/// Two 50 ms sleeps around TCP and UDP traffic, returning the sim time it took.
fn exercise(runtime: Runtime) -> Duration {
    let start = Instant::now();
    runtime.block_on(async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        tcp_echo().await;
        udp_round_trip().await;
        let blocking = tokio::task::spawn_blocking(|| 7).await.unwrap();
        assert_eq!(blocking, 7);
        tokio::time::sleep(Duration::from_millis(50)).await;
    });
    drop(runtime);
    start.elapsed()
}

fn assert_virtual(elapsed: Duration) {
    assert!(
        (Duration::from_millis(100)..Duration::from_millis(150)).contains(&elapsed),
        "two 50 ms sleeps took {elapsed:?} of sim time"
    );
}

#[test]
fn a_current_thread_runtime_per_sim() {
    for deterministic in [false, true, false] {
        assert_virtual(sim(deterministic).run(|| exercise(current_thread())));
    }
}

#[test]
fn a_multi_thread_runtime_per_sim() {
    for _ in 0..3 {
        assert_virtual(sim(false).run(|| exercise(multi_thread())));
    }
}

#[test]
fn runtimes_in_concurrent_sims() {
    let workers: Vec<_> = (0..4)
        .map(|i| {
            std::thread::spawn(move || {
                for _ in 0..3 {
                    let runtime = if i % 2 == 0 {
                        current_thread
                    } else {
                        multi_thread
                    };
                    assert_virtual(sim(false).run(|| exercise(runtime())));
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn a_timeout_fires_on_the_sim_clock() {
    let elapsed = sim(false).run(|| {
        let start = Instant::now();
        current_thread().block_on(async {
            let never = std::future::pending::<()>();
            let timed_out = tokio::time::timeout(Duration::from_secs(30), never).await;
            assert!(timed_out.is_err());
        });
        start.elapsed()
    });
    assert!(
        (Duration::from_secs(30)..Duration::from_secs(31)).contains(&elapsed),
        "a 30 s timeout took {elapsed:?} of sim time"
    );
}

/// Raises `SIGINT` in a fresh sim whose runtime listens for it, returning what the delivery did.
fn sigint_reaches_tokio(sim: Sim, runtime: fn() -> Runtime) -> SignalDelivery {
    let signals = sim.signals();
    sim.run(|| {
        runtime().block_on(async move {
            let mut interrupts = signal(SignalKind::interrupt()).unwrap();
            let delivery = signals.raise(Signal::Interrupt);
            tokio::time::timeout(Duration::from_secs(5), interrupts.recv())
                .await
                .expect("SIGINT reached the runtime")
                .unwrap();
            delivery
        })
    })
}

#[test]
fn signals_reach_the_runtime_of_every_sim() {
    let runtimes: [(bool, fn() -> Runtime); 4] = [
        (false, current_thread),
        (false, current_thread),
        (false, multi_thread),
        (true, current_thread),
    ];
    for (deterministic, runtime) in runtimes {
        assert_eq!(
            sigint_reaches_tokio(sim(deterministic), runtime),
            SignalDelivery::Handled
        );
    }
}

#[test]
fn signals_reach_the_runtimes_of_concurrent_sims() {
    let workers: Vec<_> = (0..4)
        .map(|i| {
            std::thread::spawn(move || {
                for _ in 0..3 {
                    let runtime = if i % 2 == 0 {
                        current_thread
                    } else {
                        multi_thread
                    };
                    assert_eq!(
                        sigint_reaches_tokio(sim(false), runtime),
                        SignalDelivery::Handled
                    );
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

/// A socketpair kept in a static, as tokio keeps its signal pipe: every sim reaches it under the
/// same numbers, each with an instance of its own, so bytes one sim leaves unread never reach
/// another, and a sim that ends leaves it usable.
#[test]
fn a_static_socketpair_is_each_sims_own() {
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::OnceLock;

    static PAIR: OnceLock<(UnixStream, UnixStream)> = OnceLock::new();
    let round = |leave: &'static [u8]| {
        sim(false).run(|| {
            let (a, b) = PAIR.get_or_init(|| UnixStream::pair().unwrap());
            b.set_nonblocking(true).unwrap();
            let mut buf = [0u8; 16];
            assert_eq!(
                (&*b).read(&mut buf).unwrap_err().kind(),
                ErrorKind::WouldBlock,
                "a byte from another sim"
            );
            (&*a).write_all(b"ping").unwrap();
            let mut dup = b.try_clone().unwrap();
            dup.read_exact(&mut buf[..4]).unwrap();
            assert_eq!(&buf[..4], b"ping");
            (&*a).write_all(leave).unwrap();
        })
    };
    round(b"left");
    round(b"over");
    std::thread::scope(|scope| {
        for _ in 0..3 {
            scope.spawn(|| round(b"both"));
        }
    });
}
