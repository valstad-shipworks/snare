use std::{
    io::ErrorKind,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI32, Ordering},
    },
    time::{Duration, Instant},
};

use std::io::Read;

use snare::{
    Packetable, SocketType, TcpListener, TcpStream, TesterAction, ThreadExt, TimerState, UdpSocket,
    connect_tester,
    mio::{
        Interest, Poll, Token, Waker, event::Events, net::TcpStream as MioTcpStream,
        net::UdpSocket as MioUdpSocket,
    },
    register_test, run_testers,
};

fn accept_with_timeout(listener: &TcpListener, timeout: Duration) -> TcpStream {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    panic!("accept timeout");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(err) => panic!("accept failed: {err}"),
        }
    }
}

#[test]
fn waker_emits_event() {
    register_test();
    let mut poll = Poll::new().unwrap();
    let waker = Waker::new(poll.registry(), Token(7)).unwrap();
    let mut events = Events::with_capacity(4);

    waker.wake().unwrap();
    poll.poll(&mut events, Some(Duration::from_millis(10)))
        .unwrap();

    assert!(
        events
            .iter()
            .any(|evt| evt.token() == Token(7) && evt.is_readable() && evt.is_writable())
    );
}

#[test]
fn listener_readable_on_connect() {
    register_test();
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(4);
    let mut listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let addr = listener.local_addr().unwrap();
    poll.registry()
        .register(&mut listener, Token(1), Interest::READABLE)
        .unwrap();

    let _client = TcpStream::connect(addr).unwrap();
    poll.poll(&mut events, Some(Duration::from_secs(1)))
        .unwrap();
    assert!(
        events
            .iter()
            .any(|evt| evt.token() == Token(1) && evt.is_readable())
    );

    listener.set_nonblocking(true).unwrap();
    let _ = accept_with_timeout(&listener, Duration::from_secs(1));
}

#[test]
fn stream_readable_after_peer_write() {
    register_test();
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(4);
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client_stream = TcpStream::connect(addr).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut server_stream = accept_with_timeout(&listener, Duration::from_secs(1));
    poll.registry()
        .register(&mut server_stream, Token(2), Interest::READABLE)
        .unwrap();

    client_stream.write_all(b"ping").unwrap();
    poll.poll(&mut events, Some(Duration::from_secs(1)))
        .unwrap();
    assert!(
        events
            .iter()
            .any(|evt| evt.token() == Token(2) && evt.is_readable())
    );
}

const UDP_TEST_LISTENER: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 21000);

const UDP_TEST_TESTER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 21001);

#[derive(Clone)]
struct Ping;

impl Packetable for Ping {
    const CAN_BE_FLATTENED: bool = false;
    const SOCKET_TYPE: SocketType = SocketType::Udp;

    fn encode(&self) -> Vec<u8> {
        b"ping".to_vec()
    }

    fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() >= 4 {
            Some((Ping, 4))
        } else {
            None
        }
    }
}

#[derive(Default)]
struct SendCount(i32);

fn send_dozen(state: &mut SendCount) -> Option<TesterAction<Ping>> {
    state.0 += 12;
    Some(TesterAction::Multiple(
        (0..12)
            .map(|_| TesterAction::Send(UDP_TEST_LISTENER, Ping))
            .collect(),
    ))
}

fn timer_100ms(t: &mut TimerState) -> bool {
    t.poll_elapsed() >= Duration::from_millis(100)
}

#[test]
fn udp_cyclic_send_recv_count() {
    register_test();

    let recv_count = Arc::new(AtomicI32::new(0));
    let recv_count_clone = recv_count.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();

    // Spawn listener thread with mio Poll-driven recv loop
    let _handle = std::thread::spawn(move || {
        let std_socket = UdpSocket::bind(UDP_TEST_LISTENER).unwrap();
        let mut socket = MioUdpSocket::from_std(std_socket.try_clone().unwrap());
        let mut poll = Poll::new().unwrap();
        let mut events = Events::with_capacity(16);

        poll.registry()
            .register(&mut socket, Token(1), Interest::READABLE)
            .unwrap();

        socket.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 64];

        while !stop_clone.load(Ordering::Relaxed) {
            poll.poll(&mut events, Some(Duration::from_millis(5)))
                .unwrap();

            for event in events.iter() {
                if event.token() == Token(1) && event.is_readable() {
                    loop {
                        match socket.recv_from(&mut buf) {
                            Ok(_) => {
                                recv_count_clone.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(e) => panic!("recv error: {e}"),
                        }
                    }
                }
            }
        }
    })
    .register_as_child();

    // NetTester sends 12 packets every 2ms, stops after 100ms
    let mut tester = connect_tester::<Ping>(UDP_TEST_TESTER)
        .with_stateful_cyclic_action::<SendCount>(Duration::from_millis(2), send_dozen)
        .until_stateful_condition::<TimerState>(timer_100ms);

    run_testers!(tester);

    // Give listener time to drain remaining packets
    std::thread::sleep(Duration::from_millis(50));
    stop.store(true, Ordering::Relaxed);

    let expected = tester.peek_state::<SendCount>().0;
    let actual = recv_count.load(Ordering::Relaxed);
    assert_eq!(
        actual, expected,
        "Expected {expected} packets received, got {actual}"
    );
}

/// Length-prefixed TCP packet for echo testing.
#[derive(Clone, Debug)]
struct TcpEchoPacket(Vec<u8>);

impl Packetable for TcpEchoPacket {
    const CAN_BE_FLATTENED: bool = false;
    const SOCKET_TYPE: SocketType = SocketType::Tcp;

    fn encode(&self) -> Vec<u8> {
        let len = self.0.len() as u32;
        let mut buf = len.to_le_bytes().to_vec();
        buf.extend_from_slice(&self.0);
        buf
    }

    fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        if data.len() < 4 + len {
            return None;
        }
        Some((TcpEchoPacket(data[4..4 + len].to_vec()), 4 + len))
    }
}

const TCP_ECHO_TESTER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22000);

#[derive(Default)]
struct EchoCount {
    echoed: usize,
}

fn echo_back(
    state: &mut EchoCount,
    pkt: TcpEchoPacket,
    src: SocketAddr,
) -> TesterAction<TcpEchoPacket> {
    state.echoed += 1;
    TesterAction::Send(src, pkt)
}

#[test]
fn tcp_echo_with_mio_poll() {
    register_test();

    const PACKET_COUNT: usize = 5;
    let recv_count = Arc::new(AtomicI32::new(0));
    let recv_count_clone = recv_count.clone();

    // Bind the tester's listener BEFORE spawning the SUT, so the SUT's
    // `TcpStream::connect` can't race ahead and hit ConnectionRefused under
    // contention from parallel test runs.
    let tester = connect_tester::<TcpEchoPacket>(TCP_ECHO_TESTER).then_stateful_action(echo_back);

    let _handle = std::thread::spawn(move || {
        let std_stream = TcpStream::connect(TCP_ECHO_TESTER).unwrap();
        let mut stream = MioTcpStream::from_std(std_stream.try_clone().unwrap());
        let mut poll = Poll::new().unwrap();
        let mut events = Events::with_capacity(16);

        poll.registry()
            .register(
                &mut stream,
                Token(1),
                Interest::READABLE | Interest::WRITABLE,
            )
            .unwrap();

        // Send 5 packets
        for i in 0..PACKET_COUNT {
            let pkt = TcpEchoPacket(vec![i as u8; i + 1]);
            let encoded = pkt.encode();
            stream.write_all(&encoded).unwrap();
        }

        // Poll for echoed responses
        let mut buf = [0u8; 256];
        let mut recv_buf = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);

        while recv_count_clone.load(Ordering::Relaxed) < PACKET_COUNT as i32 {
            if Instant::now() >= deadline {
                panic!(
                    "timeout waiting for echoes, got {} of {}",
                    recv_count_clone.load(Ordering::Relaxed),
                    PACKET_COUNT
                );
            }

            poll.poll(&mut events, Some(Duration::from_millis(50)))
                .unwrap();

            for event in events.iter() {
                if event.token() == Token(1) && event.is_readable() {
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                recv_buf.extend_from_slice(&buf[..n]);
                                while let Some((_, consumed)) = TcpEchoPacket::decode(&recv_buf) {
                                    recv_count_clone.fetch_add(1, Ordering::Relaxed);
                                    recv_buf.drain(..consumed);
                                }
                            }
                            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(e) => panic!("read error: {e}"),
                        }
                    }
                }
            }
        }
    })
    .register_as_child();

    let mut tester = tester
        .until_stateful_condition::<EchoCount>(|state| state.echoed >= PACKET_COUNT)
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_secs(5));

    run_testers!(tester);

    // Wait for the client thread to finish receiving all echoes
    let deadline = Instant::now() + Duration::from_secs(2);
    while recv_count.load(Ordering::Relaxed) < PACKET_COUNT as i32 {
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let echoed = tester.peek_state::<EchoCount>().echoed;
    assert_eq!(
        echoed, PACKET_COUNT,
        "Tester should have echoed {PACKET_COUNT} packets, got {echoed}"
    );

    let received = recv_count.load(Ordering::Relaxed);
    assert_eq!(
        received, PACKET_COUNT as i32,
        "Client should have received {PACKET_COUNT} echoes via mio poll, got {received}"
    );
}

// ---- API-surface parity with real mio ----
//
// These compile-only tests exercise the surface that used to differ between
// the snare shim and real mio. They don't need to do useful work; if they
// build and pass it means the shim accepts the same syntax real mio does.

#[test]
fn events_into_iterator_for_ref_works() {
    register_test();
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(4);
    poll.poll(&mut events, Some(Duration::from_millis(1)))
        .unwrap();
    // `for ev in &events` — was broken in the shim before the parity fix
    // (only impl'd `IntoIterator for Events`, not `&Events`).
    let mut count = 0;
    for _ev in &events {
        count += 1;
    }
    assert_eq!(count, 0);
    let _ = count; // silence unused
}

#[test]
fn events_iter_returns_named_iter_type() {
    register_test();
    let events = Events::with_capacity(4);
    // snare::mio::event::Iter must exist as a named type matching real mio.
    let it: snare::mio::event::Iter<'_> = events.iter();
    assert_eq!(it.count(), 0);
}

#[test]
fn source_trait_requires_explicit_reregister() {
    // The Source trait must NOT supply a default body for `reregister` —
    // real mio doesn't, and a custom user impl missing it would silently
    // compile against the old shim. Verify by manually impl'ing Source on
    // a stub and using it with Registry::reregister.
    register_test();

    struct Stub;
    impl snare::mio::event::Source for Stub {
        fn register(
            &mut self,
            _r: &snare::mio::Registry,
            _t: snare::mio::Token,
            _i: snare::mio::Interest,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn reregister(
            &mut self,
            _r: &snare::mio::Registry,
            _t: snare::mio::Token,
            _i: snare::mio::Interest,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn deregister(&mut self, _r: &snare::mio::Registry) -> std::io::Result<()> {
            Ok(())
        }
    }

    let poll = Poll::new().unwrap();
    let mut s = Stub;
    poll.registry()
        .register(&mut s, Token(99), Interest::READABLE)
        .unwrap();
    poll.registry()
        .reregister(&mut s, Token(99), Interest::WRITABLE)
        .unwrap();
    poll.registry().deregister(&mut s).unwrap();
}

#[cfg(unix)]
#[test]
fn poll_and_registry_expose_raw_fd() {
    use std::os::fd::AsRawFd;
    let poll = Poll::new().unwrap();
    assert_eq!(poll.as_raw_fd(), -1);
    assert_eq!(poll.registry().as_raw_fd(), -1);
}
