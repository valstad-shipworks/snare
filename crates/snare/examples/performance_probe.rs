use std::future::Future;
use std::hint::black_box;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::task::{Context, Wake, Waker};
use std::time::{Duration, Instant};

use snare::Sim;

#[cfg(unix)]
fn receive_message(fd: libc::c_int, buffer: &mut [u8], vectored: bool) -> usize {
    let split = if vectored {
        buffer.len() / 2
    } else {
        buffer.len()
    };
    let (first, second) = buffer.split_at_mut(split);
    let mut iov = [
        libc::iovec {
            iov_base: first.as_mut_ptr().cast(),
            iov_len: first.len(),
        },
        libc::iovec {
            iov_base: second.as_mut_ptr().cast(),
            iov_len: second.len(),
        },
    ];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = iov.as_mut_ptr();
    message.msg_iovlen = if vectored { 2 } else { 1 };
    let received = unsafe { libc::recvmsg(fd, &mut message, 0) };
    assert!(received >= 0, "{}", std::io::Error::last_os_error());
    received as usize
}

fn address(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn stopwatch(action: impl FnOnce()) -> Duration {
    snare::real(|| eprintln!("SNARE_PROFILE_READY"));
    let start = snare::real(Instant::now);
    action();
    snare::real(|| start.elapsed())
}

struct Noop;

#[allow(
    clippy::manual_noop_waker,
    reason = "the workload measures registration and cancellation of task-owned wakers"
)]
impl Wake for Noop {
    fn wake(self: Arc<Self>) {}
}

fn workload(case: &str, size: usize, iterations: usize) -> Duration {
    if iterations > 1
        && matches!(
            case,
            "explicit_bind" | "ephemeral_bind" | "timer_register" | "timer_cancel_reverse"
        )
    {
        return (0..iterations).map(|_| workload(case, size, 1)).sum();
    }
    match case {
        "clock" => stopwatch(|| {
            for index in 0..iterations {
                black_box(Instant::now());
                if index % 32 == 31 {
                    std::thread::yield_now();
                }
            }
        }),
        "yield" => stopwatch(|| {
            for _ in 0..iterations {
                std::thread::yield_now();
            }
        }),
        "sleep" => stopwatch(|| {
            for _ in 0..iterations {
                std::thread::sleep(Duration::from_millis(1));
            }
        }),
        "spawn" => stopwatch(|| {
            for _ in 0..iterations {
                std::thread::spawn(|| ()).join().unwrap();
            }
        }),
        "mutex" => {
            let mutex = Mutex::new(0usize);
            stopwatch(|| {
                for _ in 0..iterations {
                    *mutex.lock().unwrap() += 1;
                }
                black_box(*mutex.lock().unwrap());
            })
        }
        "empty" => {
            let socket = UdpSocket::bind(address(9000)).unwrap();
            socket.set_nonblocking(true).unwrap();
            let mut buffer = [0u8; 64];
            stopwatch(|| {
                for _ in 0..iterations {
                    assert_eq!(
                        socket.recv(&mut buffer).unwrap_err().kind(),
                        std::io::ErrorKind::WouldBlock
                    );
                }
            })
        }
        case if case.starts_with("udp_threaded_") => {
            assert!(size >= 2 && size.is_multiple_of(2));
            let sockets: Vec<_> = (0..size)
                .map(|index| UdpSocket::bind(address(9000 + index as u16)).unwrap())
                .collect();
            let payload_size: usize = case.rsplit('_').next().unwrap().parse().unwrap();
            assert!((1..=8192).contains(&payload_size));
            let barrier = Arc::new(std::sync::Barrier::new(size + 1));
            let mut workers = Vec::with_capacity(size);
            for (index, socket) in sockets.into_iter().enumerate() {
                socket.connect(address(9000 + (index ^ 1) as u16)).unwrap();
                let barrier = barrier.clone();
                workers.push(std::thread::spawn(move || {
                    let data = vec![7u8; payload_size];
                    let mut buffer = vec![0u8; payload_size];
                    barrier.wait();
                    for _ in 0..iterations {
                        assert_eq!(socket.send(&data).unwrap(), payload_size);
                        assert_eq!(socket.recv(&mut buffer).unwrap(), payload_size);
                        black_box(&buffer);
                    }
                }));
            }
            stopwatch(|| {
                barrier.wait();
                for worker in workers {
                    worker.join().unwrap();
                }
            })
        }
        case if case.starts_with("udp_mesh_") || case.starts_with("udp_burst_") => {
            assert!(size >= 2 && size.is_multiple_of(2));
            let sockets: Vec<_> = (0..size)
                .map(|index| UdpSocket::bind(address(9000 + index as u16)).unwrap())
                .collect();
            let payload_size: usize = case.rsplit('_').next().unwrap().parse().unwrap();
            assert!((1..=8192).contains(&payload_size));
            let data = vec![7u8; payload_size];
            let mut buffer = vec![0u8; payload_size];
            let connected = case.contains("_connected_");
            let burst = case.starts_with("udp_burst_");
            if connected {
                for (index, socket) in sockets.iter().enumerate() {
                    socket.connect(address(9000 + (index ^ 1) as u16)).unwrap();
                }
            }
            let send = |index: usize| {
                let sent = if connected {
                    sockets[index].send(&data)
                } else {
                    sockets[index].send_to(&data, address(9000 + (index ^ 1) as u16))
                }
                .unwrap();
                assert_eq!(sent, payload_size);
            };
            stopwatch(|| {
                for iteration in 0..iterations {
                    if burst {
                        for index in 0..size {
                            send(index);
                        }
                        for socket in &sockets {
                            assert_eq!(socket.recv(&mut buffer).unwrap(), payload_size);
                            black_box(&buffer);
                        }
                    } else {
                        let index = iteration % size;
                        send(index);
                        assert_eq!(sockets[index ^ 1].recv(&mut buffer).unwrap(), payload_size);
                        black_box(&buffer);
                    }
                }
            })
        }
        case if case == "udp" || case.starts_with("udp_") => {
            let sender = UdpSocket::bind(address(9000)).unwrap();
            let receiver = UdpSocket::bind(address(9001)).unwrap();
            let held: Vec<_> = (0..size.saturating_sub(2))
                .map(|index| UdpSocket::bind(address(20_000 + index as u16)).unwrap())
                .collect();
            let payload_size = case.rsplit('_').next().unwrap().parse().unwrap_or(4);
            assert!(payload_size <= 8192);
            let data = vec![7u8; payload_size];
            let mut buffer = vec![0u8; payload_size];
            let connected = case.starts_with("udp_connected_");
            if connected {
                sender.connect(address(9001)).unwrap();
                receiver.connect(address(9000)).unwrap();
            }
            stopwatch(|| {
                for _ in 0..iterations {
                    let sent = if connected {
                        sender.send(&data)
                    } else {
                        sender.send_to(&data, address(9001))
                    }
                    .unwrap();
                    assert_eq!(sent, payload_size);
                    let received = {
                        #[cfg(unix)]
                        if case.starts_with("udp_recvmsg_") {
                            use std::os::fd::AsRawFd;
                            receive_message(
                                receiver.as_raw_fd(),
                                &mut buffer,
                                case.contains("vectored"),
                            )
                        } else {
                            receiver.recv(&mut buffer).unwrap()
                        }
                        #[cfg(not(unix))]
                        receiver.recv(&mut buffer).unwrap()
                    };
                    assert_eq!(received, payload_size);
                    black_box(&buffer);
                }
                black_box(&held);
            })
        }
        case if case == "tcp" || case.starts_with("tcp_") => {
            let listener = TcpListener::bind(address(9002)).unwrap();
            let mut sender = TcpStream::connect(address(9002)).unwrap();
            let (mut receiver, _) = listener.accept().unwrap();
            let payload_size = case.rsplit('_').next().unwrap().parse().unwrap_or(1024);
            assert!(payload_size <= 8192);
            let data = vec![7u8; payload_size];
            let mut buffer = vec![0u8; payload_size];
            stopwatch(|| {
                for _ in 0..iterations {
                    sender.write_all(&data).unwrap();
                    #[cfg(unix)]
                    if case.starts_with("tcp_recvmsg_") {
                        use std::os::fd::AsRawFd;
                        let mut received = 0;
                        while received < payload_size {
                            let n = receive_message(
                                receiver.as_raw_fd(),
                                &mut buffer[received..],
                                case.contains("vectored"),
                            );
                            assert!(n > 0);
                            received += n;
                        }
                    } else {
                        receiver.read_exact(&mut buffer).unwrap();
                    }
                    #[cfg(not(unix))]
                    receiver.read_exact(&mut buffer).unwrap();
                    black_box(&buffer);
                }
            })
        }
        case if case == "poll" || case.starts_with("poll_ready_") => {
            let mut poll = mio::Poll::new().unwrap();
            let mut sockets: Vec<_> = (0..size)
                .map(|index| mio::net::UdpSocket::bind(address(20_000 + index as u16)).unwrap())
                .collect();
            for (index, socket) in sockets.iter_mut().enumerate() {
                poll.registry()
                    .register(socket, mio::Token(index), mio::Interest::READABLE)
                    .unwrap();
            }
            let payload_size: Option<usize> = case
                .strip_prefix("poll_ready_")
                .map(|value| value.parse().unwrap());
            if let Some(payload_size) = payload_size {
                assert!(payload_size <= 60_000);
                let sender = UdpSocket::bind(address(9000)).unwrap();
                let data = vec![1u8; payload_size];
                for index in 0..size {
                    sender
                        .send_to(&data, address(20_000 + index as u16))
                        .unwrap();
                }
            }
            let mut events = mio::Events::with_capacity(64);
            stopwatch(|| {
                for _ in 0..iterations {
                    poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
                    if payload_size.is_none() {
                        assert!(events.is_empty());
                    }
                    black_box(&events);
                }
            })
        }
        "explicit_bind" | "ephemeral_bind" => {
            let mut sockets = Vec::with_capacity(size);
            stopwatch(|| {
                for index in 0..size {
                    let port = if case == "ephemeral_bind" {
                        0
                    } else {
                        20_000 + index as u16
                    };
                    sockets.push(UdpSocket::bind(address(port)).unwrap());
                }
                black_box(&sockets);
            })
        }
        "timer_register" | "timer_cancel_reverse" => {
            snare::time().pause();
            let deadline = Instant::now() + Duration::from_secs(1);
            let waker = Waker::from(Arc::new(Noop));
            let mut context = Context::from_waker(&waker);
            let mut timers = Vec::with_capacity(size);
            let mut register = |timers: &mut Vec<_>| {
                for index in 0..size {
                    let at = deadline + Duration::from_nanos(index as u64);
                    let mut timer = Box::pin(snare::sched::sleep_until(at));
                    assert!(timer.as_mut().poll(&mut context).is_pending());
                    timers.push(timer);
                }
            };
            if case == "timer_register" {
                stopwatch(|| register(&mut timers))
            } else {
                register(&mut timers);
                stopwatch(|| {
                    while let Some(timer) = timers.pop() {
                        drop(timer);
                    }
                })
            }
        }
        _ => panic!("unknown case: {case}"),
    }
}

fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    assert_eq!(arguments.len(), 4, "MODE CASE SIZE ITERATIONS");
    let mode = &arguments[0];
    let case = &arguments[1];
    let size: usize = arguments[2].parse().unwrap();
    let iterations: usize = arguments[3].parse().unwrap();
    assert!(size <= 10_000 && size > 0 && iterations > 0);
    assert!(mode != "native" && mode != "passthrough" || !case.starts_with("timer_"));
    let start = Instant::now();
    let (elapsed, startup) = match mode.as_str() {
        "native" => (workload(case, size, iterations), Duration::ZERO),
        "passthrough" => {
            Sim::new().run(|| ());
            let startup = start.elapsed();
            (snare::real(|| workload(case, size, iterations)), startup)
        }
        "plain" | "det" => {
            let builder = Sim::builder();
            let sim = if mode == "det" {
                builder.deterministic()
            } else {
                builder
            }
            .build();
            let startup = start.elapsed();
            (sim.run(|| workload(case, size, iterations)), startup)
        }
        #[cfg(unix)]
        "host" => {
            let sim = Sim::builder()
                .host(snare::HostProfile::new().build())
                .build();
            let startup = start.elapsed();
            (sim.run(|| workload(case, size, iterations)), startup)
        }
        _ => panic!("unknown mode: {mode}"),
    };
    let operations = if matches!(
        case.as_str(),
        "explicit_bind" | "ephemeral_bind" | "timer_register" | "timer_cancel_reverse"
    ) || case.starts_with("udp_burst_")
        || case.starts_with("udp_threaded_")
    {
        size.checked_mul(iterations).unwrap()
    } else {
        iterations
    };
    println!(
        "{{\"mode\":\"{mode}\",\"case\":\"{case}\",\"size\":{size},\"iterations\":{iterations},\"operations\":{operations},\"elapsed_ns\":{},\"ns_per_operation\":{},\"startup_ns\":{}}}",
        elapsed.as_nanos(),
        elapsed.as_nanos() as f64 / operations as f64,
        startup.as_nanos()
    );
}
