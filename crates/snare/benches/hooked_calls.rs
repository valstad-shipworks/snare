//! Criterion benchmarks of snare's hot paths; see `benches/README.md` for measurement scope.
//!
//! Managed workloads use real-time stopwatches under `snare::real`, inside `iter_custom`.
//! Each sample runs on a fresh `Sim`, built and torn down outside the timed region. The lifecycle
//! benchmarks include that work and run outside a sim.
//!
//! Clock-read workloads yield once every 32 reads. Reads and yields share the clock-spin counter,
//! so managed samples enter the caught-spin path. The yield is included in the per-read figure,
//! including the matching installed-hook passthrough workload.

#[cfg(unix)]
mod benches {
    use std::hint::black_box;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use criterion::{BenchmarkId, Criterion};
    use snare::{Bytes, Sim, TesterAction, udp_tester};

    /// Real time `f` takes on a thread of a fresh sim built by `sim`.
    fn timed_in(sim: Sim, f: impl FnOnce() -> Duration) -> Duration {
        let took = sim.run(f);
        drop(sim);
        took
    }

    /// Times `f` in real time from inside a sim.
    fn stopwatch(f: impl FnOnce()) -> Duration {
        let start = snare::real(Instant::now);
        f();
        snare::real(|| start.elapsed())
    }

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn clock_reads_with_yields(iters: u64) {
        for i in 0..iters {
            black_box(Instant::now());
            if i % 32 == 31 {
                std::thread::yield_now();
            }
        }
    }

    pub fn passthrough(c: &mut Criterion) {
        Sim::new().run(|| ());
        let mut g = c.benchmark_group("passthrough");
        g.bench_function("clock_gettime_outside_a_sim", |b| {
            b.iter(|| black_box(Instant::now()))
        });
        g.bench_function("clock_gettime_with_yield_32_outside_a_sim", |b| {
            b.iter_custom(|iters| stopwatch(|| clock_reads_with_yields(iters)))
        });
        g.bench_function("sched_yield_outside_a_sim", |b| {
            b.iter(std::thread::yield_now)
        });
        g.finish();
    }

    pub fn in_sim(c: &mut Criterion) {
        let mut g = c.benchmark_group("in_sim");
        g.bench_function("clock_gettime", |b| {
            b.iter_custom(|iters| {
                timed_in(Sim::new(), || stopwatch(|| clock_reads_with_yields(iters)))
            })
        });
        g.bench_function("sched_yield", |b| {
            b.iter_custom(|iters| {
                timed_in(Sim::new(), || {
                    stopwatch(|| (0..iters).for_each(|_| std::thread::yield_now()))
                })
            })
        });
        g.bench_function("udp_send_recv_loopback", |b| {
            b.iter_custom(|iters| {
                timed_in(Sim::new(), || {
                    let a = UdpSocket::bind(loopback(9000)).unwrap();
                    let z = UdpSocket::bind(loopback(9001)).unwrap();
                    let mut buf = [0u8; 64];
                    stopwatch(|| {
                        for _ in 0..iters {
                            a.send_to(b"ping", loopback(9001)).unwrap();
                            black_box(z.recv(&mut buf).unwrap());
                        }
                    })
                })
            })
        });
        g.bench_function("tcp_write_read_1k_loopback", |b| {
            b.iter_custom(|iters| {
                timed_in(Sim::new(), || {
                    let listener = TcpListener::bind(loopback(9002)).unwrap();
                    let mut client = TcpStream::connect(loopback(9002)).unwrap();
                    let (mut server, _) = listener.accept().unwrap();
                    let chunk = [7u8; 1024];
                    let mut buf = [0u8; 1024];
                    stopwatch(|| {
                        for _ in 0..iters {
                            client.write_all(&chunk).unwrap();
                            server.read_exact(&mut buf).unwrap();
                        }
                    })
                })
            })
        });
        for fds in [1usize, 64, 1024] {
            g.bench_with_input(
                BenchmarkId::new("mio_poll_zero_timeout", fds),
                &fds,
                |b, &fds| {
                    b.iter_custom(|iters| {
                        timed_in(Sim::new(), || {
                            let mut poll = mio::Poll::new().unwrap();
                            let mut socks: Vec<_> = (0..fds)
                                .map(|i| {
                                    mio::net::UdpSocket::bind(loopback(20_000 + i as u16)).unwrap()
                                })
                                .collect();
                            for (i, s) in socks.iter_mut().enumerate() {
                                poll.registry()
                                    .register(s, mio::Token(i), mio::Interest::READABLE)
                                    .unwrap();
                            }
                            let mut events = mio::Events::with_capacity(64);
                            stopwatch(|| {
                                for _ in 0..iters {
                                    poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
                                }
                            })
                        })
                    })
                },
            );
        }
        g.bench_function("thread_spawn_join", |b| {
            b.iter_custom(|iters| {
                timed_in(Sim::new(), || {
                    stopwatch(|| {
                        for _ in 0..iters {
                            std::thread::spawn(|| ()).join().unwrap();
                        }
                    })
                })
            })
        });
        g.bench_function("time_skip_1ms_sleep", |b| {
            b.iter_custom(|iters| {
                timed_in(Sim::new(), || {
                    stopwatch(|| {
                        (0..iters).for_each(|_| std::thread::sleep(Duration::from_millis(1)))
                    })
                })
            })
        });
        g.bench_function("mutex_uncontended", |b| {
            b.iter_custom(|iters| {
                timed_in(Sim::new(), || {
                    let m = Mutex::new(0u64);
                    stopwatch(|| (0..iters).for_each(|_| *m.lock().unwrap() += 1))
                })
            })
        });
        g.bench_function("mutex_2_threads_with_spawn_join", |b| {
            b.iter_custom(|iters| {
                timed_in(Sim::new(), || {
                    let m = Arc::new(Mutex::new(0u64));
                    let child_iters = iters / 2;
                    let parent_iters = iters - child_iters;
                    stopwatch(|| {
                        let other = {
                            let m = m.clone();
                            std::thread::spawn(move || {
                                (0..child_iters).for_each(|_| *m.lock().unwrap() += 1)
                            })
                        };
                        (0..parent_iters).for_each(|_| *m.lock().unwrap() += 1);
                        other.join().unwrap();
                    })
                })
            })
        });
        g.finish();
    }

    pub fn lifecycle(c: &mut Criterion) {
        let mut g = c.benchmark_group("lifecycle");
        g.bench_function("sim_build_drop", |b| b.iter(|| drop(black_box(Sim::new()))));
        g.bench_function("sim_build_run_drop", |b| {
            b.iter(|| {
                let sim = Sim::new();
                sim.run(|| ());
            })
        });
        g.finish();
    }

    pub fn deterministic(c: &mut Criterion) {
        let mut g = c.benchmark_group("deterministic");
        g.bench_function("yield_2_threads_with_spawn_join", |b| {
            b.iter_custom(|iters| {
                let sim = Sim::builder().deterministic().seed(1).build();
                timed_in(sim, || {
                    let child_iters = iters / 2;
                    let parent_iters = iters - child_iters;
                    stopwatch(|| {
                        let other = std::thread::spawn(move || {
                            (0..child_iters).for_each(|_| std::thread::yield_now())
                        });
                        (0..parent_iters).for_each(|_| std::thread::yield_now());
                        other.join().unwrap();
                    })
                })
            })
        });
        g.bench_function("time_skip_1ms_sleep", |b| {
            b.iter_custom(|iters| {
                let sim = Sim::builder().deterministic().seed(1).build();
                timed_in(sim, || {
                    stopwatch(|| {
                        (0..iters).for_each(|_| std::thread::sleep(Duration::from_millis(1)))
                    })
                })
            })
        });
        g.finish();
    }

    pub fn testers(c: &mut Criterion) {
        let mut g = c.benchmark_group("testers");
        g.bench_function("udp_tester_round_trip", |b| {
            b.iter_custom(|iters| {
                timed_in(Sim::new(), || {
                    let echo = udp_tester::<Bytes>("127.0.0.5:7000")
                        .with_state(0u64)
                        .then_stateful_action(|n, msg, _from| {
                            *n += 1;
                            TesterAction::Send(msg)
                        })
                        .until_state(move |n| *n >= iters);
                    let client = std::thread::spawn(move || {
                        let sock = UdpSocket::bind(loopback(9003)).unwrap();
                        let mut buf = [0u8; 64];
                        stopwatch(|| {
                            for _ in 0..iters {
                                sock.send_to(b"ping", "127.0.0.5:7000").unwrap();
                                black_box(sock.recv(&mut buf).unwrap());
                            }
                        })
                    });
                    snare::run_testers!(echo);
                    client.join().unwrap()
                })
            })
        });
        g.finish();
    }
}

#[cfg(unix)]
criterion::criterion_group! {
    name = benches;
    config = criterion::Criterion::default()
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(3));
    targets = benches::passthrough, benches::in_sim, benches::lifecycle, benches::deterministic,
        benches::testers
}

#[cfg(unix)]
criterion::criterion_main!(benches);

#[cfg(not(unix))]
fn main() {}
