
//! The tester API beyond request/response: UDP peers, explicit destinations, typed state read back
//! after the run, recordings, connect hooks, several handlers and cyclic actions, background peers,
//! shutdown, and panics — the shapes the driver crates' tests take.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use snare::{Bytes, Line, Sim, TesterAction, connect_tester, run_testers, udp_tester};

#[test]
fn udp_tester_answers_the_sender() {
    Sim::new().run(|| {
        let device = udp_tester::<Bytes>("127.0.0.5:3956")
            .then_action(|msg, _from| {
                let mut reply = b"ack:".to_vec();
                reply.extend(msg.0);
                TesterAction::Send(Bytes(reply))
            })
            .until_after(Duration::from_secs(1));

        let client = std::thread::spawn(|| {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.send_to(b"hello", "127.0.0.5:3956").unwrap();
            let mut buf = [0u8; 32];
            let (n, from) = sock.recv_from(&mut buf).unwrap();
            assert_eq!(from, "127.0.0.5:3956".parse().unwrap(), "reply comes from the tester");
            buf[..n].to_vec()
        });

        run_testers!(device);
        assert_eq!(client.join().unwrap(), b"ack:hello");
    });
}

#[test]
fn state_is_read_back_after_the_run() {
    #[derive(Default)]
    struct Registers {
        writes: Vec<String>,
    }

    Sim::new().run(|| {
        let robot = connect_tester::<Line>("127.0.0.5:9100")
            .with_state(Registers::default())
            .then_stateful_action(|regs, msg, _| {
                regs.writes.push(msg.0.clone());
                TesterAction::Send(Line(format!("ok {}", regs.writes.len())))
            })
            .until_state(|regs| regs.writes.len() == 3)
            .until_after(Duration::from_secs(5));

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.5:9100").unwrap();
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            for cmd in ["a", "b", "c"] {
                writeln!(w, "{cmd}").unwrap();
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
            }
        });

        run_testers!(robot);
        client.join().unwrap();
        robot.inspect(|regs| assert_eq!(regs.writes, ["a", "b", "c"]));
    });
}

#[test]
fn a_recording_keeps_what_the_code_under_test_sent() {
    Sim::new().run(|| {
        let sink = udp_tester::<Bytes>("127.0.0.5:7000")
            .recording()
            .until_after(Duration::from_millis(50));
        let recorder = sink.recorder();

        let client = std::thread::spawn(move || {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            for n in 0..4u8 {
                sock.send_to(&[n], "127.0.0.5:7000").unwrap();
            }
            sock.local_addr().unwrap()
        });

        run_testers!(sink);
        let sender = client.join().unwrap();
        let got = sink.recorded();
        assert_eq!(got.len(), 4);
        assert_eq!(recorder.len(), 4, "the live handle sees the same messages");
        assert!(got.iter().all(|(from, _)| *from == sender));
        let payloads: Vec<u8> = got.iter().map(|(_, b)| b.0[0]).collect();
        assert_eq!(payloads, [0, 1, 2, 3]);
    });
}

#[test]
fn on_connect_greets_a_new_client() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.5:9200")
            .on_connect(|_, _peer| TesterAction::Send(Line("READY".into())))
            .until_after(Duration::from_millis(50));

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.5:9200").unwrap();
            let mut line = String::new();
            BufReader::new(stream).read_line(&mut line).unwrap();
            line
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), "READY\n");
    });
}

#[test]
fn every_handler_and_cyclic_action_runs() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.5:9300")
            .then_action(|msg, _| TesterAction::Send(Line(format!("first:{}", msg.0))))
            .then_action(|msg, _| TesterAction::Send(Line(format!("second:{}", msg.0))))
            .with_cyclic_action(Duration::from_millis(10), || {
                TesterAction::Send(Line("tick".into()))
            })
            .until_after(Duration::from_millis(15));

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.5:9300").unwrap();
            let mut w = stream.try_clone().unwrap();
            writeln!(w, "x").unwrap();
            let mut all = String::new();
            BufReader::new(stream).read_to_string(&mut all).unwrap();
            all
        });

        run_testers!(server);
        // Both handlers answered, the tick fired once (at 10ms of the 15ms run), and the tester
        // closed the connection when it finished, which is what ended `read_to_string`.
        assert_eq!(client.join().unwrap(), "first:x\nsecond:x\ntick\n");
    });
}

#[test]
fn a_finished_tester_closes_its_connections_and_stops_listening() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.5:9400").until_after(Duration::from_millis(20));
        let stream = TcpStream::connect("127.0.0.5:9400").unwrap();

        run_testers!(server);

        let mut buf = [0u8; 8];
        assert_eq!((&stream).read(&mut buf).unwrap(), 0, "end-of-stream, not a hang");
        let refused = TcpStream::connect("127.0.0.5:9400").unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
    });
}

#[test]
fn multiple_sends_then_closes() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.5:9500")
            .then_action(|_, _| {
                TesterAction::Multiple(vec![
                    TesterAction::Send(Line("one".into())),
                    TesterAction::Send(Line("two".into())),
                    TesterAction::Close,
                ])
            })
            .until_after(Duration::from_secs(1));

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.5:9500").unwrap();
            (&stream).write_all(b"go\n").unwrap();
            let mut all = String::new();
            BufReader::new(stream).read_to_string(&mut all).unwrap();
            all
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), "one\ntwo\n");
    });
}

#[test]
fn a_udp_peer_learns_the_client_and_drives_a_script() {
    // The device only knows the client once it hears from it; from then on it pushes a scripted
    // sequence on its own clock, one step per tick, to the address it learned.
    #[derive(Default)]
    struct Script {
        client: Option<SocketAddr>,
        step: u8,
    }

    Sim::new().run(|| {
        let device = udp_tester::<Bytes>("127.0.0.5:4000")
            .with_state(Script::default())
            .on_connect(|script, peer| {
                script.client = Some(peer);
                TesterAction::Nothing
            })
            .with_stateful_cyclic_action(Duration::from_millis(5), |script| {
                let Some(client) = script.client else {
                    return TesterAction::Nothing;
                };
                script.step += 1;
                TesterAction::SendTo(client, Bytes(vec![script.step]))
            })
            .until_state(|script| script.step == 3)
            .until_after(Duration::from_secs(1));

        let client = std::thread::spawn(|| {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.send_to(b"hello", "127.0.0.5:4000").unwrap();
            let mut steps = Vec::new();
            let mut buf = [0u8; 4];
            while steps.len() < 3 {
                let (n, _) = sock.recv_from(&mut buf).unwrap();
                steps.push(buf[..n][0]);
            }
            steps
        });

        run_testers!(device);
        assert_eq!(client.join().unwrap(), [1, 2, 3]);
    });
}

#[test]
fn a_background_peer_streams_until_the_command_tester_finishes() {
    // A TCP command channel gates a UDP stream to the client's wildcard-bound port — the shape of
    // a sensor with a control link and a data link. The stream tester has no finish condition of
    // its own, so it runs until the command tester is done.
    Sim::new().run(|| {
        let streaming = Arc::new(AtomicBool::new(false));
        let gate = streaming.clone();
        let control = connect_tester::<Line>("127.0.0.5:5000")
            .then_action(move |msg, _| {
                if msg.0 == "START" {
                    gate.store(true, Ordering::Release);
                }
                TesterAction::Send(Line("OK".into()))
            })
            .until_after(Duration::from_millis(30));
        let stream = udp_tester::<Bytes>("127.0.0.5:5001").with_cyclic_action(
            Duration::from_millis(1),
            move || {
                if streaming.load(Ordering::Acquire) {
                    TesterAction::SendTo("0.0.0.0:32100".parse().unwrap(), Bytes(vec![7]))
                } else {
                    TesterAction::Nothing
                }
            },
        );

        let client = std::thread::spawn(|| {
            let data = UdpSocket::bind("0.0.0.0:32100").unwrap();
            let ctl = TcpStream::connect("127.0.0.5:5000").unwrap();
            (&ctl).write_all(b"START\n").unwrap();
            let mut ok = String::new();
            BufReader::new(&ctl).read_line(&mut ok).unwrap();
            let mut buf = [0u8; 4];
            let (n, from) = data.recv_from(&mut buf).unwrap();
            (buf[..n].to_vec(), from)
        });

        run_testers!(control, stream);
        let (payload, from) = client.join().unwrap();
        assert_eq!(payload, [7]);
        assert_eq!(from, "127.0.0.5:5001".parse().unwrap());
    });
}

#[test]
#[should_panic(expected = "the device rejected the frame")]
fn a_panicking_tester_fails_the_test_with_its_own_message() {
    Sim::new().run(|| {
        let device = udp_tester::<Bytes>("127.0.0.5:6000")
            .then_action(|_, _| panic!("the device rejected the frame"))
            .until_after(Duration::from_secs(1));
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.send_to(b"bad", "127.0.0.5:6000").unwrap();
        run_testers!(device);
    });
}

#[test]
#[should_panic(expected = "no tester has a finish condition")]
fn run_testers_needs_a_finish_condition() {
    Sim::new().run(|| {
        let background = udp_tester::<Bytes>("127.0.0.5:6100");
        run_testers!(background);
    });
}
