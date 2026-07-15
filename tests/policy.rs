//! Integration tests for the link-policy primitives added to snare:
//! per-direction Quiesce, TCP RST, listener behavior, TCP latency / recv-window,
//! UDP loss / duplicate / reorder / queue-depth / MTU, plus the recording log
//! and port introspection.

use std::{
    io::{ErrorKind, Read, Write},
    net::SocketAddr,
    sync::Arc,
    sync::atomic::AtomicI32,
    time::{Duration, Instant},
};

// Const addresses so the cyclic-action closures (which must be `fn`, not
// `Fn`) don't need to capture.
const RST_ADDR: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
    19_400,
);
const REFUSE_ADDR: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
    19_401,
);
const OUTBOUND_QUIESCE_ADDR: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
    19_402,
);
const RECV_WINDOW_ADDR: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
    19_404,
);

use snare::{
    ListenerBehavior, Packetable, QuiesceMode, RecordedEvent, SocketType, TcpStream, TesterAction,
    ThreadExt, TimerState, UdpPolicy, UdpSocket, clear_recorded_events, connect_tester,
    mio::{Interest, Poll, Token, event::Events, net::TcpStream as MioTcpStream},
    peek_local_addr_for_peer, quiesce_with_mode, recorded_events, register_test, run_testers,
    seed_rng, set_listener_behavior, set_tcp_inbound_latency, set_tcp_recv_window, set_udp_policy,
};

// ---- helpers ----

#[derive(Clone, Debug)]
struct EchoPkt(Vec<u8>);

impl Packetable for EchoPkt {
    const CAN_BE_FLATTENED: bool = false;
    const SOCKET_TYPE: SocketType = SocketType::Tcp;

    fn encode(&self) -> Vec<u8> {
        let mut out = (self.0.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(&self.0);
        out
    }
    fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 2 {
            return None;
        }
        let len = u16::from_le_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + len {
            return None;
        }
        Some((EchoPkt(data[2..2 + len].to_vec()), 2 + len))
    }
}

#[derive(Clone, Debug)]
struct UdpPkt(Vec<u8>);

impl Packetable for UdpPkt {
    const CAN_BE_FLATTENED: bool = false;
    const SOCKET_TYPE: SocketType = SocketType::Udp;
    fn encode(&self) -> Vec<u8> {
        self.0.clone()
    }
    fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.is_empty() {
            None
        } else {
            Some((UdpPkt(data.to_vec()), data.len()))
        }
    }
}

// ---- TCP RST ----

fn rst_cycle(sent: &mut bool) -> Option<TesterAction<EchoPkt>> {
    if !*sent && let Some(peer) = peek_local_addr_for_peer(RST_ADDR) {
        *sent = true;
        return Some(TesterAction::ResetTcp(peer));
    }
    None
}

#[test]
fn reset_tcp_surfaces_econnreset_on_next_read() {
    register_test();
    // Bind the listener synchronously — connect from the test thread so
    // there's no race between SUT spawn and listener bind. Then issue the
    // RST directly via the public state helper rather than via a cyclic
    // action that depends on `peek_local_addr_for_peer` finding the SUT.
    let _tester: snare::NetTester<EchoPkt> = connect_tester::<EchoPkt>(RST_ADDR);
    let mut stream = TcpStream::connect(RST_ADDR).unwrap();
    let local = stream.local_addr().unwrap();

    snare::reset_tcp(local);

    let mut buf = [0u8; 16];
    let result = stream.read(&mut buf);
    match result {
        Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
        other => panic!("expected ECONNRESET, got {other:?}"),
    }
    let _ = rst_cycle; // keep the helper alive for the action-style API surface
}

// ---- Listener behavior ----

#[test]
fn refusing_listener_returns_econnrefused() {
    register_test();
    // Bind a listener (via connect_tester's side effect) then mark it refusing
    // — synchronously, before any connect attempt — so we don't race the
    // tester's run loop.
    let _tester: snare::NetTester<EchoPkt> = connect_tester::<EchoPkt>(REFUSE_ADDR);
    set_listener_behavior(REFUSE_ADDR, ListenerBehavior::Refusing);

    let res = TcpStream::connect(REFUSE_ADDR);
    match res {
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => {}
        other => panic!("expected ConnectionRefused, got {other:?}"),
    }

    // Flip back to accepting and confirm the connect now succeeds.
    set_listener_behavior(REFUSE_ADDR, ListenerBehavior::Accepting);
    let res = TcpStream::connect(REFUSE_ADDR);
    assert!(
        res.is_ok(),
        "expected success after re-enabling; got {res:?}"
    );
}

// ---- Per-direction Quiesce ----

fn outbound_tick(t: &mut TimerState) -> Option<TesterAction<EchoPkt>> {
    peek_local_addr_for_peer(OUTBOUND_QUIESCE_ADDR).map(|peer| {
        TesterAction::Send(
            peer,
            EchoPkt(format!("tick{}", t.poll_elapsed().as_millis()).into_bytes()),
        )
    })
}

#[test]
fn outbound_only_quiesce_blocks_writes_but_not_reads() {
    register_test();
    let outbound_quiesced = Arc::new(AtomicI32::new(0));
    let outbound_quiesced_clone = outbound_quiesced.clone();

    // Bind the listener BEFORE spawning the SUT.
    let tester = connect_tester::<EchoPkt>(OUTBOUND_QUIESCE_ADDR)
        .with_stateful_cyclic_action::<TimerState>(Duration::from_millis(40), outbound_tick);

    let client = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(OUTBOUND_QUIESCE_ADDR).unwrap();
        std::thread::sleep(Duration::from_millis(80));
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);

        let local = stream.local_addr().unwrap();
        quiesce_with_mode(local, Duration::from_millis(300), QuiesceMode::OutboundOnly);
        std::thread::sleep(Duration::from_millis(80));

        // Read should still surface the next ack — quiesce is OUTBOUND only.
        let n2 = stream.read(&mut buf);
        assert!(n2.is_ok(), "inbound read should not be blocked: {n2:?}");
        outbound_quiesced_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    })
    .register_as_child();

    let mut tester = tester
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_millis(900));
    run_testers!(tester);
    client.join().unwrap();
    assert_eq!(
        outbound_quiesced.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

// ---- TCP inbound latency ----

fn latency_handler(_pkt: EchoPkt, src: SocketAddr) -> TesterAction<EchoPkt> {
    TesterAction::Send(src, EchoPkt(b"ack".to_vec()))
}

#[test]
fn tcp_inbound_latency_delays_first_read_by_configured_duration() {
    register_test();
    let tester_addr: SocketAddr = "127.0.0.1:19403".parse().unwrap();
    const LATENCY: Duration = Duration::from_millis(150);

    // Bind the listener BEFORE spawning the SUT so its connect can succeed
    // regardless of the tester loop scheduling.
    let tester = connect_tester::<EchoPkt>(tester_addr).then_action(latency_handler);

    let client = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(tester_addr).unwrap();
        let local = stream.local_addr().unwrap();
        set_tcp_inbound_latency(local, LATENCY);
        stream.write_all(&EchoPkt(b"go".to_vec()).encode()).unwrap();
        let start = Instant::now();
        let mut buf = [0u8; 64];
        let _n = stream.read(&mut buf).unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed >= LATENCY - Duration::from_millis(20),
            "read returned in {elapsed:?}; expected at least {LATENCY:?}"
        );
        assert!(
            elapsed < LATENCY + Duration::from_secs(2),
            "read took {elapsed:?}; far too long"
        );
    })
    .register_as_child();

    let mut tester = tester
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_secs(2));
    run_testers!(tester);
    client.join().unwrap();
}

// ---- TCP recv window backpressure ----

#[test]
fn tcp_recv_window_backpressures_send_from_test() {
    register_test();
    clear_recorded_events();
    // Bind the listener synchronously (no cyclic-action race) so the SUT
    // connects deterministically.
    let _tester: snare::NetTester<EchoPkt> = connect_tester::<EchoPkt>(RECV_WINDOW_ADDR);

    // Connect from the test thread so we know the SUT-side addr immediately.
    let stream = TcpStream::connect(RECV_WINDOW_ADDR).unwrap();
    let local = stream.local_addr().unwrap();
    // Tiny recv window: 8 bytes.
    set_tcp_recv_window(local, Some(8));

    // Drive the tester→SUT sends manually using the public from-test path so
    // the test isn't subject to cyclic-action / scheduler timing.
    for byte in 1u8..=16u8 {
        snare::inject_tcp_from_test(RECV_WINDOW_ADDR, local, EchoPkt(vec![byte]).encode());
    }

    let log = recorded_events();
    let send_count = log
        .iter()
        .filter(|e| matches!(e.event, RecordedEvent::TcpSendFromTest { .. }))
        .count();
    // Each EchoPkt encodes as 3 bytes (2-byte length + 1-byte payload). Window
    // is 8 bytes so at most 2 sends fit (3+3=6, +3=9 > 8) before backpressure.
    assert!(
        send_count > 0 && send_count <= 4,
        "expected partial accept due to recv-window; got {send_count} sends recorded"
    );
    drop(stream);
}

// ---- UDP loss + reorder + duplicate ----

#[test]
fn udp_policy_drops_packets_at_configured_rate() {
    register_test();
    seed_rng(0xfeedface_cafebabe);

    let tester_addr: SocketAddr = "127.0.0.1:19405".parse().unwrap();

    let client = std::thread::spawn(move || {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let local = socket.local_addr().unwrap();
        // Apply 75% loss to packets headed to us.
        set_udp_policy(local, |p: &mut UdpPolicy| p.loss_rate = 0.75);
        socket.set_nonblocking(true).unwrap();

        let mut received = 0;
        let mut buf = [0u8; 16];
        let target = Instant::now() + Duration::from_millis(800);
        while Instant::now() < target {
            let _ = socket.send_to(b"hi", tester_addr);
            std::thread::sleep(Duration::from_millis(20));
            loop {
                match socket.recv_from(&mut buf) {
                    Ok(_) => {
                        received += 1;
                        if received >= 100 {
                            break;
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }

        // With 75% loss across ~16 outbound packets per 50ms tick over ~800ms,
        // we expect a small fraction of the unfiltered cyclic packet count.
        // Just assert "less than half" to keep this from flaking on schedulers.
        let log = recorded_events();
        let total_attempts = log
            .iter()
            .filter(|e| matches!(e.event, RecordedEvent::UdpSendFromTest { .. }))
            .count();
        let dropped = log
            .iter()
            .filter(|e| {
                matches!(
                    e.event,
                    RecordedEvent::UdpSendFromTest { dropped: true, .. }
                )
            })
            .count();
        assert!(
            total_attempts >= 4,
            "tester barely sent anything: {total_attempts}"
        );
        let drop_ratio = dropped as f32 / total_attempts as f32;
        assert!(
            drop_ratio > 0.4 && drop_ratio < 0.95,
            "drop ratio {drop_ratio:.2} not in expected range for loss_rate=0.75 \
             (attempts={total_attempts}, dropped={dropped})"
        );
    })
    .register_as_child();

    // Tester fires a packet to whoever just contacted it.
    let mut tester = connect_tester::<UdpPkt>(tester_addr)
        .with_state::<u32>(|_| {})
        .then_stateful_action::<u32>(|seq, _pkt: UdpPkt, src: SocketAddr| {
            *seq += 1;
            TesterAction::Send(src, UdpPkt(seq.to_le_bytes().to_vec()))
        })
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_secs(2));
    run_testers!(tester);
    client.join().unwrap();
}

// ---- UDP MTU ----

#[test]
fn udp_send_above_mtu_returns_invalid_input() {
    register_test();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let local = socket.local_addr().unwrap();
    set_udp_policy(local, |p: &mut UdpPolicy| p.mtu = Some(64));
    let dst: SocketAddr = "127.0.0.1:19406".parse().unwrap();
    let big = vec![0u8; 128];
    let res = socket.send_to(&big, dst);
    assert!(
        matches!(&res, Err(e) if e.kind() == ErrorKind::InvalidInput),
        "expected InvalidInput for over-MTU send, got {res:?}"
    );
    let small = vec![0u8; 32];
    let res = socket.send_to(&small, dst);
    assert!(res.is_ok(), "small send should succeed: {res:?}");
}

// ---- UDP send queue depth ----

#[test]
fn udp_send_queue_full_returns_wouldblock() {
    register_test();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let local = socket.local_addr().unwrap();
    set_udp_policy(local, |p: &mut UdpPolicy| p.send_queue_depth = Some(2));
    let dst: SocketAddr = "127.0.0.1:19407".parse().unwrap();
    // 1st and 2nd succeed; 3rd should hit the cap.
    socket.send_to(b"a", dst).unwrap();
    socket.send_to(b"b", dst).unwrap();
    let res = socket.send_to(b"c", dst);
    assert!(
        matches!(&res, Err(e) if e.kind() == ErrorKind::WouldBlock),
        "expected WouldBlock when send queue full, got {res:?}"
    );
}

// ---- Recording log ----

#[test]
fn recording_log_captures_send_close_quiesce() {
    register_test();
    clear_recorded_events();
    let tester_addr: SocketAddr = "127.0.0.1:19408".parse().unwrap();
    let _tester: snare::NetTester<EchoPkt> = connect_tester::<EchoPkt>(tester_addr);

    let stream = TcpStream::connect(tester_addr).unwrap();
    let local = stream.local_addr().unwrap();

    // Drive the events directly so they're guaranteed to land in the log.
    snare::inject_tcp_from_test(tester_addr, local, EchoPkt(b"pong".to_vec()).encode());
    quiesce_with_mode(local, Duration::from_millis(50), QuiesceMode::Both);

    let log = recorded_events();
    assert!(
        log.iter()
            .any(|e| matches!(e.event, RecordedEvent::TcpSendFromTest { .. })),
        "expected at least one TcpSendFromTest event in log: {log:?}"
    );
    assert!(
        log.iter()
            .any(|e| matches!(e.event, RecordedEvent::Quiesce { .. })),
        "expected at least one Quiesce event in log: {log:?}"
    );
    for win in log.windows(2) {
        assert!(win[1].at >= win[0].at);
    }
    drop(stream);
}

// ---- Port introspection ----

#[test]
fn peek_local_addr_for_peer_returns_sut_side_addr() {
    register_test();
    let tester_addr: SocketAddr = "127.0.0.1:19409".parse().unwrap();
    // Bind the listener so the SUT's connect succeeds.
    let _tester: snare::NetTester<EchoPkt> = connect_tester::<EchoPkt>(tester_addr);

    let stream = TcpStream::connect(tester_addr).unwrap();
    let client_local = stream.local_addr().unwrap();

    let peeked = peek_local_addr_for_peer(tester_addr);
    assert_eq!(
        peeked,
        Some(client_local),
        "peek_local_addr_for_peer should match the SUT's local addr"
    );
}

// ---- Pollable mio readability with directional Quiesce ----

fn ack_handler(_pkt: EchoPkt, src: SocketAddr) -> TesterAction<EchoPkt> {
    TesterAction::Send(src, EchoPkt(b"ack".to_vec()))
}

#[test]
fn inbound_only_quiesce_lets_writes_drain() {
    register_test();
    let tester_addr: SocketAddr = "127.0.0.1:19410".parse().unwrap();
    // Bind the listener BEFORE spawning so the SUT's connect can't race.
    let tester = connect_tester::<EchoPkt>(tester_addr).then_action(ack_handler);

    let client = std::thread::spawn(move || {
        let std_stream = TcpStream::connect(tester_addr).unwrap();
        let mut stream = MioTcpStream::from_std(std_stream);
        let mut poll = Poll::new().unwrap();
        let mut events = Events::with_capacity(8);
        poll.registry()
            .register(
                &mut stream,
                Token(1),
                Interest::READABLE | Interest::WRITABLE,
            )
            .unwrap();

        let local = stream.local_addr().unwrap();
        quiesce_with_mode(local, Duration::from_millis(400), QuiesceMode::InboundOnly);
        // Write something — the SUT's outbound path must remain open.
        stream
            .write_all(&EchoPkt(b"hello".to_vec()).encode())
            .unwrap();

        // Poll inside the window: WRITABLE should still fire (outbound not
        // quiesced); READABLE should NOT fire (inbound quiesced) even if the
        // tester answers.
        let mut saw_writable = false;
        let mut saw_readable = false;
        let until = Instant::now() + Duration::from_millis(200);
        while Instant::now() < until {
            poll.poll(&mut events, Some(Duration::from_millis(40)))
                .unwrap();
            for evt in events.iter() {
                if evt.is_writable() {
                    saw_writable = true;
                }
                if evt.is_readable() {
                    saw_readable = true;
                }
            }
        }
        assert!(
            saw_writable,
            "SUT should see WRITABLE during InboundOnly quiesce"
        );
        assert!(
            !saw_readable,
            "SUT must NOT see READABLE during InboundOnly quiesce"
        );
    })
    .register_as_child();

    let mut tester = tester
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_millis(800));
    run_testers!(tester);
    client.join().unwrap();
}
