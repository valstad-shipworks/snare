use std::{
    io::ErrorKind,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicI32, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use snare::{
    TcpListener, TcpStream, UdpSocket, register_test,
    mio::{Interest, Poll, Token, Waker, event::Events, net::UdpSocket as MioUdpSocket},
    Packetable, SocketType, TesterAction, TimerState, ThreadExt,
    connect_tester, run_testers,
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
    poll.poll(&mut events, Some(Duration::from_millis(10))).unwrap();

    assert!(
        events.iter().any(|evt| evt.token() == Token(7) && evt.is_readable() && evt.is_writable())
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
    poll.poll(&mut events, Some(Duration::from_secs(1))).unwrap();
    assert!(events.iter().any(|evt| evt.token() == Token(1) && evt.is_readable()));

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
    poll.poll(&mut events, Some(Duration::from_secs(1))).unwrap();
    assert!(events.iter().any(|evt| evt.token() == Token(2) && evt.is_readable()));
}

const UDP_TEST_LISTENER: SocketAddr = SocketAddr::new(
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    21000,
);

const UDP_TEST_TESTER: SocketAddr = SocketAddr::new(
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    21001,
);

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
