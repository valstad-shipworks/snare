//! TCP fabric + tester-builder coverage: happy paths, framing, multi-connection, error/errno
//! paths and boundary conditions. The code under test uses real `std::net::TcpStream`; the sim
//! services its socket calls and the tester is the far end of the wire.
//!
//! TCP is a byte stream with no message boundaries (man 7 tcp, "TCP provides a reliable,
//! ordered... stream of bytes"), so all framing — newline for `Line`, length-prefix for the
//! custom `Packet` below — is the application's, which is exactly what these exercise.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use snare::{Bytes, Line, Packet, Sim, TesterAction, connect_tester, run_testers};

const SHORT: Duration = Duration::from_millis(300);

#[test]
fn echo_line_roundtrip() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9410")
            .then_action(|msg, _| TesterAction::Send(Line(format!("echo:{}", msg.0))))
            .until_after(SHORT);

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.2:9410").unwrap();
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            w.write_all(b"hello\n").unwrap();
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            line
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), "echo:hello\n");
    });
}

#[test]
fn empty_line_roundtrips_as_empty_string() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9411")
            .then_action(|msg, _| TesterAction::Send(Line(format!("[{}]", msg.0))))
            .until_after(SHORT);

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.2:9411").unwrap();
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            w.write_all(b"\n").unwrap();
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            line
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), "[]\n");
    });
}

#[test]
fn bytes_packet_sees_the_raw_stream() {
    Sim::new().run(|| {
        let server = connect_tester::<Bytes>("127.0.0.2:9412")
            .then_action(|msg, _| {
                let mut up = msg.0;
                up.make_ascii_uppercase();
                TesterAction::Send(Bytes(up))
            })
            .until_after(SHORT);

        let client = std::thread::spawn(|| {
            let mut stream = TcpStream::connect("127.0.0.2:9412").unwrap();
            stream.write_all(b"abcxyz").unwrap();
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).unwrap();
            buf.to_vec()
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), b"ABCXYZ");
    });
}

#[test]
fn send_all_delivers_frames_in_order() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9413")
            .then_action(|_msg, _| {
                TesterAction::SendAll(vec![
                    Line("one".into()),
                    Line("two".into()),
                    Line("three".into()),
                ])
            })
            .until_after(SHORT);

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.2:9413").unwrap();
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            w.write_all(b"go\n").unwrap();
            let mut lines = Vec::new();
            for _ in 0..3 {
                let mut l = String::new();
                r.read_line(&mut l).unwrap();
                lines.push(l.trim().to_string());
            }
            lines
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), vec!["one", "two", "three"]);
    });
}

#[test]
fn nothing_action_sends_no_bytes() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9414")
            .then_action(|_msg, _| TesterAction::Nothing)
            .until_after(SHORT);

        let client = std::thread::spawn(|| {
            let mut stream = TcpStream::connect("127.0.0.2:9414").unwrap();
            stream.write_all(b"anyone there?\n").unwrap();
            // man 7 socket: O_NONBLOCK makes recv return EAGAIN/WouldBlock when no data is queued,
            // which is what an idle peer that answered with `Nothing` leaves behind.
            stream.set_nonblocking(true).unwrap();
            let mut buf = [0u8; 16];
            stream.read(&mut buf).unwrap_err().kind()
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), std::io::ErrorKind::WouldBlock);
    });
}

#[test]
fn close_action_is_seen_as_eof() {
    Sim::new().run(|| {
        let server = connect_tester::<Bytes>("127.0.0.2:9415")
            .then_action(|_msg, _| TesterAction::Close)
            .until_after(SHORT);

        let client = std::thread::spawn(|| {
            let mut stream = TcpStream::connect("127.0.0.2:9415").unwrap();
            stream.write_all(b"bye").unwrap();
            let mut rest = Vec::new();
            // man 2 recv: a return of 0 is the orderly-shutdown (EOF) indication.
            stream.read_to_end(&mut rest).unwrap();
            rest
        });

        run_testers!(server);
        assert!(client.join().unwrap().is_empty());
    });
}

#[test]
fn stateful_then_action_counts_requests() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9416")
            .then_action({
                let mut seen = 0u64;
                move |msg, _| {
                    seen += 1;
                    TesterAction::Send(Line(format!("{seen}:{}", msg.0)))
                }
            })
            .until_after(SHORT);

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.2:9416").unwrap();
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            let mut out = Vec::new();
            for tag in ["a", "b", "c"] {
                writeln!(w, "{tag}").unwrap();
                let mut l = String::new();
                r.read_line(&mut l).unwrap();
                out.push(l.trim().to_string());
            }
            out
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), vec!["1:a", "2:b", "3:c"]);
    });
}

#[test]
fn from_addr_identifies_the_client() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9417")
            .then_action(|_msg, from| {
                // The ephemeral client port is in the IANA dynamic range (RFC 6335 / man 7 ip).
                assert!(
                    from.port() >= 49152,
                    "client port {} not ephemeral",
                    from.port()
                );
                assert!(from.ip().is_loopback());
                TesterAction::Send(Line("seen".into()))
            })
            .until_after(SHORT);

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.2:9417").unwrap();
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            w.write_all(b"hi\n").unwrap();
            let mut l = String::new();
            r.read_line(&mut l).unwrap();
            l
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), "seen\n");
    });
}

#[test]
fn addr_reports_the_listening_socket() {
    Sim::new().run(|| {
        let server =
            connect_tester::<Line>("127.0.0.2:9418").until_after(Duration::from_millis(20));
        assert_eq!(
            server.addr(),
            SocketAddr::from((Ipv4Addr::new(127, 0, 0, 2), 9418))
        );
        run_testers!(server);
    });
}

#[test]
fn custom_until_condition_finishes_the_run() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9419")
            .then_action(|msg, _| TesterAction::Send(Line(msg.0)))
            .until(|elapsed| elapsed >= Duration::from_millis(120));

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.2:9419").unwrap();
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            w.write_all(b"ping\n").unwrap();
            let mut l = String::new();
            r.read_line(&mut l).unwrap();
            l
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), "ping\n");
    });
}

#[test]
fn connection_refused_has_no_listener() {
    Sim::new().run(|| {
        // man 2 connect: a stream connect to an address with no listener fails ECONNREFUSED.
        let err = TcpStream::connect("127.0.0.2:9420").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    });
}

#[test]
fn ipv6_loopback_tester() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("[::1]:9421")
            .then_action(|msg, from| {
                assert!(from.is_ipv6());
                TesterAction::Send(Line(format!("v6:{}", msg.0)))
            })
            .until_after(SHORT);

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("[::1]:9421").unwrap();
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            w.write_all(b"hi\n").unwrap();
            let mut l = String::new();
            r.read_line(&mut l).unwrap();
            l
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), "v6:hi\n");
    });
}

#[test]
fn large_payload_survives_chunking() {
    const N: usize = 100_000;
    Sim::new().run(|| {
        let server = connect_tester::<Bytes>("127.0.0.2:9422")
            .then_action(|msg, _| TesterAction::Send(Bytes(msg.0)))
            .until_after(Duration::from_millis(500));

        let client = std::thread::spawn(|| {
            let mut stream = TcpStream::connect("127.0.0.2:9422").unwrap();
            let payload: Vec<u8> = (0..N).map(|i| (i % 251) as u8).collect();
            let mut w = stream.try_clone().unwrap();
            let writer = std::thread::spawn(move || w.write_all(&payload).unwrap());
            let mut got = vec![0u8; N];
            stream.read_exact(&mut got).unwrap();
            writer.join().unwrap();
            got
        });

        run_testers!(server);
        let got = client.join().unwrap();
        assert_eq!(got.len(), N);
        assert!(got.iter().enumerate().all(|(i, &b)| b == (i % 251) as u8));
    });
}

#[derive(Clone, Debug)]
struct Frame(Vec<u8>);

impl Packet for Frame {
    // A 4-byte big-endian length prefix ahead of the body: the classic way an application draws
    // message boundaries on top of TCP's boundary-free byte stream (man 7 tcp).
    fn parse(buf: &mut Vec<u8>) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if buf.len() < 4 + len {
            return None;
        }
        buf.drain(..4);
        Some(Frame(buf.drain(..len).collect()))
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = (self.0.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&self.0);
        out
    }
}

#[test]
fn custom_packet_reassembles_length_prefixed_frames() {
    Sim::new().run(|| {
        let server = connect_tester::<Frame>("127.0.0.2:9423")
            .then_action(|msg, _| {
                let mut body = msg.0;
                body.reverse();
                TesterAction::Send(Frame(body))
            })
            .until_after(SHORT);

        let client = std::thread::spawn(|| {
            let mut stream = TcpStream::connect("127.0.0.2:9423").unwrap();
            let mut wire = Vec::new();
            for body in [b"first".as_slice(), b"second".as_slice()] {
                wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
                wire.extend_from_slice(body);
            }
            stream.write_all(&wire).unwrap();

            let mut replies = Vec::new();
            for _ in 0..2 {
                let mut len = [0u8; 4];
                stream.read_exact(&mut len).unwrap();
                let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                stream.read_exact(&mut body).unwrap();
                replies.push(body);
            }
            replies
        });

        run_testers!(server);
        assert_eq!(
            client.join().unwrap(),
            vec![b"tsrif".to_vec(), b"dnoces".to_vec()]
        );
    });
}

#[test]
fn cyclic_action_streams_without_a_prompt() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9424")
            .with_cyclic_action(Duration::from_millis(5), || {
                TesterAction::Send(Line("tick".into()))
            })
            .until_after(Duration::from_millis(400));

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.2:9424").unwrap();
            let mut r = BufReader::new(stream);
            let mut ticks = 0;
            let mut l = String::new();
            while ticks < 4 {
                l.clear();
                if r.read_line(&mut l).unwrap() == 0 {
                    break;
                }
                if l.trim() == "tick" {
                    ticks += 1;
                }
            }
            ticks
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), 4);
    });
}

#[test]
fn several_requests_over_one_connection() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9425")
            .then_action(|msg, _| {
                let n: u64 = msg.0.parse().unwrap_or(0);
                TesterAction::Send(Line((n * n).to_string()))
            })
            .until_after(SHORT);

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.2:9425").unwrap();
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            let mut squares = Vec::new();
            for i in 1..=6u64 {
                writeln!(w, "{i}").unwrap();
                let mut l = String::new();
                r.read_line(&mut l).unwrap();
                squares.push(l.trim().parse::<u64>().unwrap());
            }
            squares
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), vec![1, 4, 9, 16, 25, 36]);
    });
}

#[test]
fn many_clients_share_one_tester() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9426")
            .then_action(|msg, _| TesterAction::Send(Line(format!("pong:{}", msg.0))))
            .until_after(Duration::from_millis(500));

        let clients: Vec<_> = (0..5)
            .map(|i| {
                std::thread::spawn(move || {
                    let stream = TcpStream::connect("127.0.0.2:9426").unwrap();
                    let mut w = stream.try_clone().unwrap();
                    let mut r = BufReader::new(stream);
                    writeln!(w, "c{i}").unwrap();
                    let mut l = String::new();
                    r.read_line(&mut l).unwrap();
                    l.trim().to_string()
                })
            })
            .collect();

        run_testers!(server);
        let mut got: Vec<String> = clients.into_iter().map(|c| c.join().unwrap()).collect();
        got.sort();
        assert_eq!(
            got,
            vec!["pong:c0", "pong:c1", "pong:c2", "pong:c3", "pong:c4"]
        );
    });
}

#[test]
fn two_testers_on_distinct_addresses() {
    Sim::new().run(|| {
        let upper = connect_tester::<Line>("127.0.0.2:9427")
            .then_action(|msg, _| TesterAction::Send(Line(msg.0.to_uppercase())))
            .until_after(SHORT);
        let lower = connect_tester::<Line>("127.0.0.2:9428")
            .then_action(|msg, _| TesterAction::Send(Line(msg.0.to_lowercase())))
            .until_after(SHORT);

        let client = std::thread::spawn(|| {
            let ask = |addr: &str, text: &str| {
                let stream = TcpStream::connect(addr).unwrap();
                let mut w = stream.try_clone().unwrap();
                let mut r = BufReader::new(stream);
                writeln!(w, "{text}").unwrap();
                let mut l = String::new();
                r.read_line(&mut l).unwrap();
                l.trim().to_string()
            };
            (ask("127.0.0.2:9427", "Hi"), ask("127.0.0.2:9428", "Hi"))
        });

        run_testers!(upper, lower);
        assert_eq!(client.join().unwrap(), ("HI".into(), "hi".into()));
    });
}
