use std::{
    io::{Read, Write},
    net::SocketAddr,
    time::{Duration, Instant},
};

use snare::{
    Packetable, SocketType, TcpStream, TesterAction, ThreadExt, TimerState, connect_tester,
    mio::{Interest, Poll, Token, event::Events, net::TcpStream as MioTcpStream},
    register_test, run_testers,
};

#[derive(Clone, Debug)]
struct EchoPacket(Vec<u8>);

impl Packetable for EchoPacket {
    const CAN_BE_FLATTENED: bool = false;
    const SOCKET_TYPE: SocketType = SocketType::Tcp;

    fn encode(&self) -> Vec<u8> {
        let mut bytes = (self.0.len() as u16).to_le_bytes().to_vec();
        bytes.extend_from_slice(&self.0);
        bytes
    }

    fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 2 {
            return None;
        }
        let len = u16::from_le_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + len {
            return None;
        }
        Some((EchoPacket(data[2..2 + len].to_vec()), 2 + len))
    }
}

const TESTER_ADDR: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
    19_201,
);

const QUIESCE_WINDOW: Duration = Duration::from_millis(400);

#[test]
fn quiesce_suppresses_mio_readiness() {
    register_test();

    let _client = std::thread::spawn(move || {
        let std_stream = TcpStream::connect(TESTER_ADDR).unwrap();
        let mut stream = MioTcpStream::from_std(std_stream);
        let mut poll = Poll::new().unwrap();
        let mut events = Events::with_capacity(8);
        poll.registry()
            .register(&mut stream, Token(1), Interest::READABLE)
            .unwrap();

        // Phase 1: baseline — send "probe" and confirm we see the ack within 200ms.
        stream
            .write_all(&EchoPacket(b"probe".to_vec()).encode())
            .unwrap();
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut got_ack = false;
        while Instant::now() < deadline && !got_ack {
            poll.poll(&mut events, Some(Duration::from_millis(50)))
                .unwrap();
            for evt in events.iter() {
                if evt.token() == Token(1) && evt.is_readable() {
                    let mut buf = [0u8; 64];
                    let _ = stream.read(&mut buf);
                    got_ack = true;
                }
            }
        }
        assert!(got_ack, "phase 1: expected readable for probe ack");

        // Phase 2: trigger quiesce. Tester will Send("during") + Quiesce(self, 400ms).
        // The Send buffers bytes into our incoming queue; quiesce immediately
        // takes effect, so Poll must NOT surface the readable event.
        stream
            .write_all(&EchoPacket(b"trigger".to_vec()).encode())
            .unwrap();

        // Give the tester loop a moment to process the trigger and apply the
        // quiesce + queued bytes.
        std::thread::sleep(Duration::from_millis(50));

        // Phase 3: across ~250ms of the quiesce window, Poll should never fire.
        let quiesce_check_end = Instant::now() + Duration::from_millis(250);
        let mut events_during_quiesce = 0;
        while Instant::now() < quiesce_check_end {
            poll.poll(&mut events, Some(Duration::from_millis(40)))
                .unwrap();
            events_during_quiesce += events.iter().count();
        }
        assert_eq!(
            events_during_quiesce, 0,
            "phase 3: Poll fired {events_during_quiesce} events during quiesce window"
        );

        // Phase 4: after the window closes, the buffered "during" bytes finally
        // surface as a readable event.
        let post_deadline = Instant::now() + QUIESCE_WINDOW + Duration::from_millis(200);
        let mut got_post = false;
        while Instant::now() < post_deadline && !got_post {
            poll.poll(&mut events, Some(Duration::from_millis(50)))
                .unwrap();
            for evt in events.iter() {
                if evt.token() == Token(1) && evt.is_readable() {
                    let mut buf = [0u8; 64];
                    let _ = stream.read(&mut buf);
                    got_post = true;
                }
            }
        }
        assert!(got_post, "phase 4: expected readable after quiesce expiry");
    })
    .register_as_child();

    let mut tester = connect_tester::<EchoPacket>(TESTER_ADDR)
        .then_action(|pkt: EchoPacket, src: SocketAddr| match pkt.0.as_slice() {
            b"probe" => TesterAction::Send(src, EchoPacket(b"ack".to_vec())),
            b"trigger" => TesterAction::Multiple(vec![
                TesterAction::Send(src, EchoPacket(b"during".to_vec())),
                TesterAction::Quiesce(src, QUIESCE_WINDOW),
            ]),
            _ => TesterAction::Send(src, EchoPacket(pkt.0)),
        })
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_secs(3));

    run_testers!(tester);
}
