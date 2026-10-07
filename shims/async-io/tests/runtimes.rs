//! smol and async-std on the shim, in sequential and concurrent sims. Both drive I/O and timers
//! through async-io; their executors and `blocking`'s thread pool are their own statics.

#![cfg(unix)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use futures_lite::{AsyncReadExt, AsyncWriteExt};
use snare::Sim;

fn sim(deterministic: bool) -> Sim {
    let builder = Sim::builder().stuck_after(Duration::from_secs(10));
    if deterministic {
        builder.deterministic().build()
    } else {
        builder.build()
    }
}

fn assert_virtual(elapsed: Duration) {
    assert!(
        (Duration::from_millis(100)..Duration::from_millis(150)).contains(&elapsed),
        "two 50 ms timers took {elapsed:?} of sim time"
    );
}

fn concurrently(f: fn(bool)) {
    let workers: Vec<_> = (0..4)
        .map(|i| std::thread::spawn(move || (0..3).for_each(|_| f(i % 2 == 0))))
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

fn smol_exercise() -> Duration {
    let start = Instant::now();
    smol::block_on(async {
        smol::Timer::after(Duration::from_millis(50)).await;
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = smol::net::TcpListener::bind(any).await.unwrap();
        let to = listener.local_addr().unwrap();
        let ex = smol::LocalExecutor::new();
        let server = ex.spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
        });
        ex.run(async {
            let mut client = smol::net::TcpStream::connect(to).await.unwrap();
            client.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            server.await;
        })
        .await;
        let udp = smol::net::UdpSocket::bind(any).await.unwrap();
        udp.send_to(b"self", udp.local_addr().unwrap())
            .await
            .unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(udp.recv(&mut buf).await.unwrap(), 4);
        smol::Timer::after(Duration::from_millis(50)).await;
    });
    start.elapsed()
}

fn smol_run(deterministic: bool) {
    assert_virtual(sim(deterministic).run(smol_exercise));
}

#[test]
fn smol_in_sequential_sims() {
    for deterministic in [false, true, false, true] {
        smol_run(deterministic);
    }
}

#[test]
fn smol_in_concurrent_sims() {
    concurrently(smol_run);
}

#[test]
fn smol_global_executor_and_unblock() {
    for _ in 0..3 {
        let elapsed = sim(false).run(|| {
            let start = Instant::now();
            let n = smol::block_on(async {
                let task = smol::spawn(async {
                    smol::Timer::after(Duration::from_millis(50)).await;
                    smol::unblock(|| 21).await * 2
                });
                smol::Timer::after(Duration::from_millis(50)).await;
                task.await
            });
            assert_eq!(n, 42);
            start.elapsed()
        });
        assert!(
            (Duration::from_millis(50)..Duration::from_millis(100)).contains(&elapsed),
            "took {elapsed:?} of sim time"
        );
    }
}

fn async_std_exercise() -> Duration {
    let start = Instant::now();
    async_std::task::block_on(async {
        async_std::task::sleep(Duration::from_millis(50)).await;
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = async_std::net::TcpListener::bind(any).await.unwrap();
        let to = listener.local_addr().unwrap();
        let server = async_std::task::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
        });
        let mut client = async_std::net::TcpStream::connect(to).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.await;
        let blocking = async_std::task::spawn_blocking(|| 7).await;
        assert_eq!(blocking, 7);
        async_std::task::sleep(Duration::from_millis(50)).await;
    });
    start.elapsed()
}

fn async_std_run(deterministic: bool) {
    assert_virtual(sim(deterministic).run(async_std_exercise));
}

#[test]
fn async_std_in_sequential_sims() {
    for deterministic in [false, true, false, true] {
        async_std_run(deterministic);
    }
}

#[test]
fn async_std_in_concurrent_sims() {
    concurrently(async_std_run);
}
