//! Criterion benchmarks of snare's hot paths; see `benches/README.md` for measurement scope.
//!
//! Managed workloads use real-time stopwatches under `snare::real`, inside `iter_custom`.
//! Each sample runs on a fresh `Sim`, built and torn down outside the timed region. The lifecycle
//! benchmarks include that work and run outside a sim.
//!
//! Clock-read workloads yield once every 32 reads. Reads and yields share the clock-spin counter,
//! so managed samples enter the caught-spin path. The yield is included in the per-read figure,
//! including the matching installed-hook passthrough workload.

mod benches {
    use std::future::Future;
    use std::hint::black_box;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::sync::{Arc, Barrier, Condvar, Mutex, mpsc};
    use std::task::{Context, Wake, Waker};
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

    /// Raises the soft descriptor limit toward the hard one, which a sim inherits: each managed
    /// socket holds a real descriptor, and the larger workloads exceed a 1,024 soft limit. macOS
    /// refuses a soft limit above `kern.maxfilesperproc`, so it stops at 100,000.
    #[cfg(unix)]
    fn raise_nofile() {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a live rlimit.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            return;
        }
        let want = limit.rlim_max.min(100_000);
        if limit.rlim_cur < want {
            limit.rlim_cur = want;
            // SAFETY: as above.
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
        }
    }

    struct NoWake;

    #[allow(
        clippy::manual_noop_waker,
        reason = "the timers are registered and cancelled under a task-owned waker"
    )]
    impl Wake for NoWake {
        fn wake(self: Arc<Self>) {}
    }

    struct Baton {
        turn: usize,
        passes: u64,
    }

    /// Real time `workers` long-lived threads take to pass a baton round a ring `passes` times,
    /// each waiting on its own condition variable for the previous one to hand over. Spawning
    /// and the start barrier precede the stopwatch; the final joins are inside it.
    fn condvar_ring(workers: usize, passes: u64) -> Duration {
        let ring = Arc::new((
            Mutex::new(Baton {
                turn: usize::MAX,
                passes: 0,
            }),
            (0..workers).map(|_| Condvar::new()).collect::<Vec<_>>(),
        ));
        let ready = Arc::new(Barrier::new(workers + 1));
        let threads: Vec<_> = (0..workers)
            .map(|me| {
                let ring = ring.clone();
                let ready = ready.clone();
                std::thread::spawn(move || {
                    let (baton, turns) = &*ring;
                    ready.wait();
                    let mut held = baton.lock().unwrap();
                    loop {
                        while held.turn != me && held.passes < passes {
                            held = turns[me].wait(held).unwrap();
                        }
                        if held.passes >= passes {
                            return;
                        }
                        held.passes += 1;
                        if held.passes == passes {
                            turns.iter().for_each(Condvar::notify_one);
                            return;
                        }
                        held.turn = (me + 1) % workers;
                        turns[held.turn].notify_one();
                    }
                })
            })
            .collect();
        ready.wait();
        stopwatch(|| {
            let (baton, turns) = &*ring;
            baton.lock().unwrap().turn = 0;
            turns[0].notify_one();
            for thread in threads {
                thread.join().unwrap();
            }
        })
    }

    /// As [`condvar_ring`], passing a counter through a ring of channels.
    fn channel_ring(workers: usize, passes: u64) -> Duration {
        let (senders, receivers): (Vec<_>, Vec<_>) =
            (0..workers).map(|_| mpsc::channel::<u64>()).unzip();
        let first = senders[0].clone();
        let ready = Arc::new(Barrier::new(workers + 1));
        let threads: Vec<_> = receivers
            .into_iter()
            .enumerate()
            .map(|(me, inbox)| {
                let next = senders[(me + 1) % workers].clone();
                let ready = ready.clone();
                std::thread::spawn(move || {
                    ready.wait();
                    loop {
                        let count = inbox.recv().unwrap();
                        if count >= passes {
                            let _ = next.send(count);
                            return;
                        }
                        let _ = next.send(count + 1);
                    }
                })
            })
            .collect();
        drop(senders);
        ready.wait();
        stopwatch(|| {
            first.send(0).unwrap();
            drop(first);
            for thread in threads {
                thread.join().unwrap();
            }
        })
    }

    /// Real time a producer takes to send `messages` values over a channel in bursts of `burst`,
    /// waiting after each burst for the consumer to acknowledge it on a second channel. The first
    /// value of a burst makes the consumer ready while the producer still has the rest to send.
    /// Spawning and the start barrier precede the stopwatch; the final join is inside it.
    fn channel_burst(burst: u64, messages: u64) -> Duration {
        let (values, inbox) = mpsc::channel::<u64>();
        let (ack, acks) = mpsc::channel::<()>();
        let ready = Arc::new(Barrier::new(2));
        let consumer = {
            let ready = ready.clone();
            std::thread::spawn(move || {
                ready.wait();
                for got in 1..=messages {
                    black_box(inbox.recv().unwrap());
                    if got % burst == 0 || got == messages {
                        ack.send(()).unwrap();
                    }
                }
            })
        };
        ready.wait();
        stopwatch(|| {
            let mut sent = 0;
            while sent < messages {
                let n = burst.min(messages - sent);
                (sent..sent + n).for_each(|value| values.send(value).unwrap());
                sent += n;
                acks.recv().unwrap();
            }
            consumer.join().unwrap();
        })
    }

    type Group<'a> = criterion::BenchmarkGroup<'a, criterion::measurement::WallTime>;

    type Ring = fn(usize, u64) -> Duration;

    /// The handoff rings for 2, 3 and 8 workers and a burst of 64 channel sends, each sample on a
    /// fresh sim from `sim`, or outside one when it gives none.
    fn handoff_rings(g: &mut Group<'_>, sim: impl Fn() -> Option<Sim>) {
        let rings: [(&str, Ring); 2] = [
            ("handoff_condvar_ring", condvar_ring),
            ("handoff_channel_ring", channel_ring),
        ];
        for workers in [2usize, 3, 8] {
            for (name, ring) in rings {
                g.bench_with_input(BenchmarkId::new(name, workers), &workers, |b, &workers| {
                    b.iter_custom(|iters| match sim() {
                        Some(sim) => timed_in(sim, || ring(workers, iters)),
                        None => ring(workers, iters),
                    })
                });
            }
        }
        g.bench_function(BenchmarkId::new("channel_burst", 64), |b| {
            b.iter_custom(|iters| match sim() {
                Some(sim) => timed_in(sim, || channel_burst(64, iters)),
                None => channel_burst(64, iters),
            })
        });
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
        handoff_rings(&mut g, || None);
        g.finish();
    }

    pub fn in_sim(c: &mut Criterion) {
        #[cfg(unix)]
        raise_nofile();
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
        g.bench_function("udp_send_recv_beside_256_tcp_listeners", |b| {
            b.iter_custom(|iters| {
                timed_in(Sim::new(), || {
                    let listeners: Vec<_> = (0..256)
                        .map(|i| TcpListener::bind(loopback(30_000 + i)).unwrap())
                        .collect();
                    let a = UdpSocket::bind(loopback(9000)).unwrap();
                    let z = UdpSocket::bind(loopback(9001)).unwrap();
                    let mut buf = [0u8; 64];
                    stopwatch(|| {
                        for _ in 0..iters {
                            a.send_to(b"ping", loopback(9001)).unwrap();
                            black_box(z.recv(&mut buf).unwrap());
                        }
                        black_box(&listeners);
                    })
                })
            })
        });
        g.bench_function("timer_cancel_1000_tied", |b| {
            b.iter_custom(|iters| {
                timed_in(Sim::new(), || {
                    snare::time().pause();
                    let waker = Waker::from(Arc::new(NoWake));
                    let mut context = Context::from_waker(&waker);
                    let deadline = Instant::now() + Duration::from_secs(1);
                    (0..iters)
                        .map(|_| {
                            let mut timers: Vec<_> = (0..1000)
                                .map(|_| Box::pin(snare::sched::sleep_until(deadline)))
                                .collect();
                            for timer in &mut timers {
                                assert!(timer.as_mut().poll(&mut context).is_pending());
                            }
                            stopwatch(|| while timers.pop().is_some() {})
                        })
                        .sum()
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
        for idle in [1usize, 1024] {
            g.bench_with_input(
                BenchmarkId::new("mio_poll_wake_beside_idle", idle),
                &idle,
                |b, &idle| {
                    b.iter_custom(|iters| {
                        timed_in(Sim::new(), || mio_wake_round_trips(idle, iters))
                    })
                },
            );
        }
        g.bench_with_input(
            BenchmarkId::new("mio_poll_all_ready", 1024),
            &1024usize,
            |b, &fds| b.iter_custom(|iters| timed_in(Sim::new(), || mio_all_ready(fds, iters))),
        );
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        g.bench_with_input(
            BenchmarkId::new("poll_level_all_ready", 1024),
            &1024usize,
            |b, &fds| b.iter_custom(|iters| timed_in(Sim::new(), || level_all_ready(fds, iters))),
        );
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
        handoff_rings(&mut g, || Some(Sim::new()));
        g.finish();
        let mut g = c.benchmark_group("in_sim");
        g.sample_size(10);
        for listeners in [1024u16, 16_384] {
            g.bench_with_input(
                BenchmarkId::new("tcp_bind_listen_close_beside_listeners", listeners),
                &listeners,
                |b, &listeners| {
                    b.iter_custom(|iters| {
                        timed_in(Sim::new(), || {
                            let held = tcp_listeners(listeners);
                            stopwatch(|| {
                                for _ in 0..iters {
                                    drop(black_box(TcpListener::bind(loopback(9003)).unwrap()));
                                }
                                black_box(&held);
                            })
                        })
                    })
                },
            );
            g.bench_with_input(
                BenchmarkId::new("tcp_connect_accept_close_beside_listeners", listeners),
                &listeners,
                |b, &listeners| {
                    b.iter_custom(|iters| {
                        timed_in(Sim::new(), || {
                            let held = tcp_listeners(listeners);
                            let target = TcpListener::bind(loopback(9002)).unwrap();
                            stopwatch(|| {
                                for _ in 0..iters {
                                    let client = TcpStream::connect(loopback(9002)).unwrap();
                                    let (server, _) = target.accept().unwrap();
                                    drop(black_box((client, server)));
                                }
                                black_box(&held);
                            })
                        })
                    })
                },
            );
        }
        g.finish();
    }

    /// `count` TCP listeners on consecutive loopback ports from 20,000.
    fn tcp_listeners(count: u16) -> Vec<TcpListener> {
        (0..count)
            .map(|i| TcpListener::bind(loopback(20_000 + i)).unwrap())
            .collect()
    }

    /// `count` Mio UDP sockets on consecutive loopback ports from 20,000, registered readable with
    /// `poll` under tokens from `first`.
    fn mio_udp_sockets(poll: &mio::Poll, count: usize, first: usize) -> Vec<mio::net::UdpSocket> {
        (0..count)
            .map(|i| {
                let mut sock = mio::net::UdpSocket::bind(loopback(20_000 + i as u16)).unwrap();
                poll.registry()
                    .register(&mut sock, mio::Token(first + i), mio::Interest::READABLE)
                    .unwrap();
                sock
            })
            .collect()
    }

    /// Real time `iters` round trips take between a thread blocked in a Mio poll, with `idle`
    /// other UDP sockets registered, and an echo thread: the poller sends, blocks until the reply
    /// makes its socket readable and reads it. Binding, registration and spawning the echo thread
    /// precede the stopwatch.
    fn mio_wake_round_trips(idle: usize, iters: u64) -> Duration {
        let mut poll = mio::Poll::new().unwrap();
        let idle = mio_udp_sockets(&poll, idle, 1);
        let mut active = mio::net::UdpSocket::bind(loopback(9004)).unwrap();
        poll.registry()
            .register(&mut active, mio::Token(0), mio::Interest::READABLE)
            .unwrap();
        let echo = UdpSocket::bind(loopback(9005)).unwrap();
        let echo = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            for _ in 0..iters {
                let (n, from) = echo.recv_from(&mut buf).unwrap();
                echo.send_to(&buf[..n], from).unwrap();
            }
        });
        let mut events = mio::Events::with_capacity(64);
        let mut buf = [0u8; 64];
        let took = stopwatch(|| {
            for _ in 0..iters {
                active.send_to(b"ping", loopback(9005)).unwrap();
                while !events.iter().any(|event| event.token() == mio::Token(0)) {
                    poll.poll(&mut events, None).unwrap();
                }
                events.clear();
                black_box(active.recv(&mut buf).unwrap());
                would_block(&active);
            }
        });
        echo.join().unwrap();
        black_box(&idle);
        took
    }

    /// Mio's Windows selector polls a socket again only once a call on it would block, so a
    /// reader there drains it; elsewhere the next datagram reports it ready again.
    fn would_block(sock: &mio::net::UdpSocket) {
        if cfg!(windows) {
            let error = sock.recv(&mut [0u8; 64]).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        }
    }

    /// Real time `iters` rounds take in which a datagram lands on each of `fds` UDP sockets
    /// registered with Mio, zero-timeout polls report every one of them, and each is read.
    fn mio_all_ready(fds: usize, iters: u64) -> Duration {
        let mut poll = mio::Poll::new().unwrap();
        let socks = mio_udp_sockets(&poll, fds, 0);
        let addrs: Vec<SocketAddr> = socks.iter().map(|s| s.local_addr().unwrap()).collect();
        let sender = UdpSocket::bind(loopback(9006)).unwrap();
        let mut events = mio::Events::with_capacity(fds);
        let mut buf = [0u8; 64];
        stopwatch(|| {
            for _ in 0..iters {
                for addr in &addrs {
                    sender.send_to(b"ping", addr).unwrap();
                }
                let mut seen = 0;
                while seen < fds {
                    poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
                    seen += events.iter().count();
                }
                for sock in &socks {
                    black_box(sock.recv(&mut buf).unwrap());
                    would_block(sock);
                }
            }
        })
    }

    /// Real time `iters` zero-timeout waits take on a level-triggered epoll set (Linux) or kqueue
    /// (macOS) of `fds` UDP sockets, each holding an unread datagram, so that every wait reports
    /// all of them.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn level_all_ready(fds: usize, iters: u64) -> Duration {
        use std::os::fd::AsRawFd;
        let socks: Vec<UdpSocket> = (0..fds)
            .map(|i| UdpSocket::bind(loopback(20_000 + i as u16)).unwrap())
            .collect();
        let sender = UdpSocket::bind(loopback(9006)).unwrap();
        for sock in &socks {
            sender.send_to(b"ping", sock.local_addr().unwrap()).unwrap();
        }
        let raw: Vec<i32> = socks.iter().map(AsRawFd::as_raw_fd).collect();
        #[cfg(target_os = "linux")]
        let (set, wait) = {
            // SAFETY: no pointers.
            let set = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
            for &fd in &raw {
                let mut event = libc::epoll_event {
                    events: libc::EPOLLIN as u32,
                    u64: fd as u64,
                };
                // SAFETY: `event` is a live epoll_event.
                assert_eq!(
                    unsafe { libc::epoll_ctl(set, libc::EPOLL_CTL_ADD, fd, &mut event) },
                    0
                );
            }
            let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; fds];
            let wait = move || {
                // SAFETY: `events` has room for `fds` entries.
                unsafe { libc::epoll_wait(set, events.as_mut_ptr(), fds as i32, 0) as usize }
            };
            (set, wait)
        };
        #[cfg(target_os = "macos")]
        let (set, wait) = {
            let event = |fd: i32, flags: u16| libc::kevent {
                ident: fd as usize,
                filter: libc::EVFILT_READ,
                flags,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            // SAFETY: no pointers.
            let set = unsafe { libc::kqueue() };
            let changes: Vec<libc::kevent> =
                raw.iter().map(|&fd| event(fd, libc::EV_ADD)).collect();
            // SAFETY: `changes` holds `changes.len()` entries and no events are asked for.
            let added = unsafe {
                libc::kevent(
                    set,
                    changes.as_ptr(),
                    changes.len() as i32,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            };
            assert_eq!(added, 0);
            let mut events = vec![event(0, 0); fds];
            let zero = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let wait = move || {
                // SAFETY: `events` has room for `fds` entries.
                unsafe {
                    libc::kevent(
                        set,
                        std::ptr::null(),
                        0,
                        events.as_mut_ptr(),
                        fds as i32,
                        &zero,
                    ) as usize
                }
            };
            (set, wait)
        };
        let mut wait = wait;
        while wait() < fds {
            std::thread::sleep(Duration::from_millis(1));
        }
        let took = stopwatch(|| {
            for _ in 0..iters {
                assert_eq!(black_box(wait()), fds);
            }
        });
        // SAFETY: `set` is the wait's own descriptor.
        unsafe { libc::close(set) };
        took
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
        handoff_rings(&mut g, || {
            Some(Sim::builder().deterministic().seed(1).build())
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

criterion::criterion_group! {
    name = benches;
    config = criterion::Criterion::default()
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(3));
    targets = benches::passthrough, benches::in_sim, benches::lifecycle, benches::deterministic,
        benches::testers
}

criterion::criterion_main!(benches);
