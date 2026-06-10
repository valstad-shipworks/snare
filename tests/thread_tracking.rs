use std::{
    net::SocketAddr,
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use snare::{
    Packetable, SocketType, ThreadExt, TimerState, UdpSocket, connect_tester, register_test,
    run_testers,
};

#[derive(Clone)]
struct SimplePacket(Vec<u8>);

impl Packetable for SimplePacket {
    const CAN_BE_FLATTENED: bool = false;
    const SOCKET_TYPE: SocketType = SocketType::Udp;

    fn encode(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.is_empty() {
            None
        } else {
            Some((Self(data.to_vec()), data.len()))
        }
    }
}

/// Many child threads all registering and using shim sockets concurrently.
#[test]
fn many_concurrent_child_threads_sending_udp() {
    register_test();

    let tester_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let thread_count = 32;
    let packets_per_thread = 4;
    let total_expected = thread_count * packets_per_thread;

    #[derive(Default)]
    struct Count(usize);

    let mut tester = connect_tester::<SimplePacket>(tester_addr)
        .then_stateful_test::<Count>(|state, pkt, _src| {
            state.0 += 1;
            Some(pkt)
        })
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_secs(5));

    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::new();

    for i in 0..thread_count {
        let bar = barrier.clone();
        let h = std::thread::spawn(move || {
            bar.wait(); // all threads start sending simultaneously
            let client_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 5100 + i as u16));
            let socket = UdpSocket::bind(client_addr).unwrap();
            for j in 0..packets_per_thread {
                let data = vec![i as u8, j as u8];
                socket.send_to(&data, tester_addr).unwrap();
            }
        })
        .register_as_child();
        handles.push(h);
    }

    run_testers!(tester);

    for h in handles {
        h.join().unwrap();
    }

    let count = tester.peek_state::<Count>().0;
    assert_eq!(
        count, total_expected,
        "expected {total_expected} packets, got {count}"
    );
}

/// Child thread spawns a grandchild — the grandchild must also resolve to the
/// root test thread when accessing shim state.
#[test]
fn grandchild_thread_inherits_test_context() {
    register_test();

    let tester_addr: SocketAddr = "127.0.0.1:5200".parse().unwrap();

    #[derive(Default)]
    struct Count(usize);

    let mut tester = connect_tester::<SimplePacket>(tester_addr)
        .then_stateful_test::<Count>(|state, pkt, _src| {
            state.0 += 1;
            Some(pkt)
        })
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_secs(5));

    let child = std::thread::spawn(move || {
        // Child spawns a grandchild that does the actual sending
        let grandchild = std::thread::spawn(move || {
            let client_addr: SocketAddr = "127.0.0.1:5201".parse().unwrap();
            let socket = UdpSocket::bind(client_addr).unwrap();
            for i in 0..5u8 {
                socket.send_to(&[i], tester_addr).unwrap();
            }
        })
        .register_as_child();
        grandchild.join().unwrap();
    })
    .register_as_child();

    run_testers!(tester);
    child.join().unwrap();

    assert_eq!(tester.peek_state::<Count>().0, 5);
}

/// Three levels deep: test → child → grandchild → great-grandchild, each
/// registering its own spawned thread.
#[test]
fn deep_thread_hierarchy() {
    register_test();

    let tester_addr: SocketAddr = "127.0.0.1:5300".parse().unwrap();

    #[derive(Default)]
    struct Count(usize);

    let mut tester = connect_tester::<SimplePacket>(tester_addr)
        .then_stateful_test::<Count>(|state, pkt, _src| {
            state.0 += 1;
            Some(pkt)
        })
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_secs(5));

    // depth 1 → depth 2 → depth 3, the deepest thread sends a packet
    let child = std::thread::spawn(move || {
        let grandchild = std::thread::spawn(move || {
            let great_grandchild = std::thread::spawn(move || {
                let client_addr: SocketAddr = "127.0.0.1:5301".parse().unwrap();
                let socket = UdpSocket::bind(client_addr).unwrap();
                socket.send_to(&[42], tester_addr).unwrap();
            })
            .register_as_child();
            great_grandchild.join().unwrap();
        })
        .register_as_child();
        grandchild.join().unwrap();
    })
    .register_as_child();

    run_testers!(tester);
    child.join().unwrap();

    assert_eq!(tester.peek_state::<Count>().0, 1);
}

/// Stress test: many threads race to register_as_child at the same instant,
/// verifying the hierarchy mutex handles contention.
#[test]
fn concurrent_registration_contention() {
    register_test();

    let thread_count = 64;
    let barrier = Arc::new(Barrier::new(thread_count));
    let success_count = Arc::new(AtomicUsize::new(0));

    let tester_addr: SocketAddr = "127.0.0.1:5400".parse().unwrap();

    #[derive(Default)]
    struct Count(usize);

    let mut tester = connect_tester::<SimplePacket>(tester_addr)
        .then_stateful_test::<Count>(|state, pkt, _src| {
            state.0 += 1;
            Some(pkt)
        })
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_secs(5));

    let mut handles = Vec::new();

    for i in 0..thread_count {
        let bar = barrier.clone();
        let ok = success_count.clone();
        let h = std::thread::spawn(move || {
            bar.wait(); // synchronize all registrations + sends
            let client_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 5500 + i as u16));
            let socket = UdpSocket::bind(client_addr).unwrap();
            socket.send_to(&[i as u8], tester_addr).unwrap();
            ok.fetch_add(1, Ordering::SeqCst);
        })
        .register_as_child();
        handles.push(h);
    }

    run_testers!(tester);

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(success_count.load(Ordering::SeqCst), thread_count);
    assert_eq!(tester.peek_state::<Count>().0, thread_count);
}

/// ThreadExt on JoinHandle, ThreadId, and Thread all work correctly.
#[test]
fn all_thread_ext_variants() {
    register_test();

    let tester_addr: SocketAddr = "127.0.0.1:5600".parse().unwrap();

    #[derive(Default)]
    struct Count(usize);

    let mut tester = connect_tester::<SimplePacket>(tester_addr)
        .then_stateful_test::<Count>(|state, pkt, _src| {
            state.0 += 1;
            Some(pkt)
        })
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_secs(5));

    // register via JoinHandle::register_as_child
    let h1 = std::thread::spawn(move || {
        let socket = UdpSocket::bind("127.0.0.1:5601".parse::<SocketAddr>().unwrap()).unwrap();
        socket.send_to(&[1], tester_addr).unwrap();
    })
    .register_as_child();

    // register via ThreadId::register_as_child
    let h2 = std::thread::spawn(move || {
        let socket = UdpSocket::bind("127.0.0.1:5602".parse::<SocketAddr>().unwrap()).unwrap();
        socket.send_to(&[2], tester_addr).unwrap();
    });
    h2.thread().id().register_as_child();

    // register via Thread::register_as_child
    let h3 = std::thread::spawn(move || {
        let socket = UdpSocket::bind("127.0.0.1:5603".parse::<SocketAddr>().unwrap()).unwrap();
        socket.send_to(&[3], tester_addr).unwrap();
    });
    h3.thread().clone().register_as_child();

    run_testers!(tester);

    h1.join().unwrap();
    h2.join().unwrap();
    h3.join().unwrap();

    assert_eq!(tester.peek_state::<Count>().0, 3);
}

/// Verify the 50ms grace window: spawn a child that immediately uses a shim
/// socket, then register it slightly after. The child should survive because
/// `TestThreadId::of` sleeps 50ms before panicking.
#[test]
fn late_registration_within_grace_period() {
    register_test();

    let tester_addr: SocketAddr = "127.0.0.1:5700".parse().unwrap();

    #[derive(Default)]
    struct Count(usize);

    let mut tester = connect_tester::<SimplePacket>(tester_addr)
        .then_stateful_test::<Count>(|state, pkt, _src| {
            state.0 += 1;
            Some(pkt)
        })
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_secs(5));

    let h = std::thread::spawn(move || {
        // Small sleep to ensure the socket call hits the 50ms grace window
        std::thread::sleep(Duration::from_millis(10));
        let socket = UdpSocket::bind("127.0.0.1:5701".parse::<SocketAddr>().unwrap()).unwrap();
        socket.send_to(&[99], tester_addr).unwrap();
    });

    // Register after spawn — the child will have to wait in the grace window
    let thread_id = h.thread().id();
    std::thread::sleep(Duration::from_millis(5));
    thread_id.register_as_child();

    run_testers!(tester);
    h.join().unwrap();

    assert_eq!(tester.peek_state::<Count>().0, 1);
}

/// Multiple child threads sending high volumes of small UDP packets.
#[test]
fn high_volume_concurrent_sends() {
    register_test();

    let tester_addr: SocketAddr = "127.0.0.1:5800".parse().unwrap();
    let thread_count = 8;
    let packets_per_thread = 50;
    let total_expected = thread_count * packets_per_thread;

    #[derive(Default)]
    struct Count(usize);

    let mut tester = connect_tester::<SimplePacket>(tester_addr)
        .then_stateful_test::<Count>(|state, pkt, _src| {
            state.0 += 1;
            Some(pkt)
        })
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_secs(10));

    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::new();

    for i in 0..thread_count {
        let bar = barrier.clone();
        let h = std::thread::spawn(move || {
            let client_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 5900 + i as u16));
            let socket = UdpSocket::bind(client_addr).unwrap();
            bar.wait();
            for j in 0..packets_per_thread {
                socket.send_to(&[i as u8, j as u8], tester_addr).unwrap();
            }
        })
        .register_as_child();
        handles.push(h);
    }

    run_testers!(tester);

    for h in handles {
        h.join().unwrap();
    }

    let count = tester.peek_state::<Count>().0;
    assert_eq!(
        count, total_expected,
        "expected {total_expected} packets from high-volume sends, got {count}"
    );
}

// ---- snare::thread auto-registration ----

/// Confirms `snare::thread::spawn` attaches the spawned thread to the test's
/// state slot before user code runs — touching shim state inside the closure
/// must not panic.
#[test]
fn snare_thread_spawn_auto_registers_child() {
    register_test();
    let listener: SocketAddr = "127.0.0.1:5800".parse().unwrap();
    let _tester = connect_tester::<SimplePacket>(listener);

    // The closure does NOT call register_thread_child_of itself — yet the
    // shim TcpListener::bind / TcpStream::connect both touch state and would
    // panic ("Thread not registered as test thread or child thread") without
    // the wrapper.
    let h = snare::thread::spawn(move || {
        let socket = UdpSocket::bind("127.0.0.1:5801".parse::<SocketAddr>().unwrap()).unwrap();
        socket.send_to(&[1u8], listener).unwrap();
    });

    let mut tester = connect_tester::<SimplePacket>(listener)
        .with_state::<usize>(|_| {})
        .then_stateful_test::<usize>(|n, pkt, _| {
            *n += 1;
            Some(pkt)
        })
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_secs(2));
    run_testers!(tester);
    h.join().unwrap();

    assert_eq!(*tester.peek_state::<usize>(), 1);
}

#[test]
fn snare_thread_builder_spawn_auto_registers_child() {
    register_test();
    let listener: SocketAddr = "127.0.0.1:5802".parse().unwrap();
    let _tester = connect_tester::<SimplePacket>(listener);

    let h = snare::thread::Builder::new()
        .name("snare-thread-test".to_string())
        .spawn(move || {
            let socket = UdpSocket::bind("127.0.0.1:5803".parse::<SocketAddr>().unwrap()).unwrap();
            socket.send_to(&[2u8], listener).unwrap();
        })
        .unwrap();

    let mut tester = connect_tester::<SimplePacket>(listener)
        .with_state::<usize>(|_| {})
        .then_stateful_test::<usize>(|n, pkt, _| {
            *n += 1;
            Some(pkt)
        })
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_secs(2));
    run_testers!(tester);
    h.join().unwrap();

    assert_eq!(*tester.peek_state::<usize>(), 1);
}

/// Nested spawn: thread A → thread B. B is registered as a child of A, which
/// is itself a child of the test thread, so B can transitively touch shim
/// state without manual registration.
#[test]
fn snare_thread_nested_spawn_chains_registration() {
    register_test();
    let listener: SocketAddr = "127.0.0.1:5804".parse().unwrap();
    let _tester = connect_tester::<SimplePacket>(listener);

    let outer = snare::thread::spawn(move || {
        let inner = snare::thread::spawn(move || {
            let socket = UdpSocket::bind("127.0.0.1:5805".parse::<SocketAddr>().unwrap()).unwrap();
            socket.send_to(&[3u8], listener).unwrap();
        });
        inner.join().unwrap();
    });

    let mut tester = connect_tester::<SimplePacket>(listener)
        .with_state::<usize>(|_| {})
        .then_stateful_test::<usize>(|n, pkt, _| {
            *n += 1;
            Some(pkt)
        })
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_secs(2));
    run_testers!(tester);
    outer.join().unwrap();

    assert_eq!(*tester.peek_state::<usize>(), 1);
}
