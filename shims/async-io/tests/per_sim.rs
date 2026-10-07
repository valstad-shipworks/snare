#![cfg(unix)]

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use async_io::{Async, Timer};
use snare::Sim;

fn sim(deterministic: bool) -> Sim {
    let builder = Sim::builder().stuck_after(Duration::from_secs(10));
    if deterministic {
        builder.deterministic().build()
    } else {
        builder.build()
    }
}

fn timers_and_udp() -> Duration {
    let start = Instant::now();
    async_io::block_on(async {
        Timer::after(Duration::from_millis(50)).await;
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let a = Async::<UdpSocket>::bind(any).unwrap();
        let b = Async::<UdpSocket>::bind(any).unwrap();
        let to = b.get_ref().local_addr().unwrap();
        a.send_to(b"ping", to).await.unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = b.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from, a.get_ref().local_addr().unwrap());
        Timer::after(Duration::from_millis(50)).await;
    });
    start.elapsed()
}

fn assert_virtual(elapsed: Duration) {
    assert!(
        (Duration::from_millis(100)..Duration::from_millis(150)).contains(&elapsed),
        "two 50 ms timers took {elapsed:?} of sim time"
    );
}

#[test]
fn sequential_sims_each_get_a_reactor() {
    for deterministic in [false, true, false, true] {
        let sim = sim(deterministic);
        assert_virtual(sim.run(timers_and_udp));
    }
}

#[test]
fn concurrent_sims_each_get_a_reactor() {
    let workers: Vec<_> = (0..4)
        .map(|i| {
            std::thread::spawn(move || {
                for _ in 0..5 {
                    let sim = sim(i % 2 == 0);
                    assert_virtual(sim.run(timers_and_udp));
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn a_timer_on_a_spawned_thread_uses_its_sims_reactor() {
    let sim = sim(false);
    let elapsed = sim.run(|| {
        std::thread::spawn(|| {
            let start = Instant::now();
            futures_lite::future::block_on(Timer::after(Duration::from_millis(30)));
            start.elapsed()
        })
        .join()
        .unwrap()
    });
    assert!(
        (Duration::from_millis(30)..Duration::from_millis(60)).contains(&elapsed),
        "a 30 ms timer took {elapsed:?} of sim time"
    );
}

#[test]
fn the_reactor_thread_exits_with_its_sim() {
    let sim = sim(false);
    let driver = sim.run(|| {
        async_io::block_on(Timer::after(Duration::from_millis(5)));
        let census = snare::sched::thread_census().unwrap();
        census
            .threads
            .iter()
            .find(|t| {
                matches!(t.owner, snare_interpose::ThreadOwner::ThisSim(_))
                    && t.name.as_deref() == Some("async-io")
            })
            .map(|t| t.os_id)
            .unwrap_or_else(|| panic!("no async-io thread in {census:?}"))
    });
    drop(sim);
    let gone = (0..100).any(|_| {
        let census = snare_interpose::census(None).unwrap();
        if census.threads.iter().all(|t| t.os_id != driver) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
        false
    });
    assert!(gone, "the async-io thread outlived its sim");
}

#[test]
fn outside_a_sim_the_reactor_is_the_process_one() {
    let start = Instant::now();
    async_io::block_on(Timer::after(Duration::from_millis(10)));
    assert!(start.elapsed() >= Duration::from_millis(10));
}
