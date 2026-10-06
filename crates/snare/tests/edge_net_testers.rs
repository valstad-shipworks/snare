//! Behaviour pins for the testers ahead of a performance pass: each framing (`Line`, `Bytes`,
//! `Delimited` with one- and multi-byte delimiters whose bytes overlap the body, `LengthPrefixed`
//! at every field width and endianness) cuts a stream into the same frames however the stream is
//! split into reads — fed straight to `Packet::parse` and through a TCP tester, a fixed seed
//! choosing the splits — while a UDP tester parses each datagram on its own; per-connection
//! state is fresh per TCP connection and kept per UDP source, in the order peers appeared;
//! cyclic ticks land on their exact instants; and a scripted TCP session logs exactly the
//! recorded events and stamps of the golden `edge_net_testers_events.txt`.

#[path = "support/golden.rs"]
mod golden;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

#[path = "support/landing.rs"]
mod landing;

use snare::{
    Bytes, CrLf, Delimited, Delimiter, Endian, FrameLength, LengthField, LengthPrefixed, Line,
    Packet, Sim, TcpPolicy, TesterAction, connect_tester, run_testers, set_tcp_policy, udp_tester,
};

/// SplitMix64: a fixed, dependency-free generator so the splits are the same on every host.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `lo..=hi`.
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next() % (hi - lo + 1) as u64) as usize
    }
}

/// `stream` cut into chunks of 1 to `max` bytes.
fn split(stream: &[u8], rng: &mut Rng, max: usize) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();
    let mut at = 0;
    while at < stream.len() {
        let n = rng.range(1, max).min(stream.len() - at);
        chunks.push(stream[at..at + n].to_vec());
        at += n;
    }
    chunks
}

/// Feeds `chunks` to `P::parse` one read at a time, taking every whole frame after each; returns
/// the frames' bytes and what was left unparsed.
fn parse_chunks<P: Packet>(chunks: &[Vec<u8>]) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut buf = Vec::new();
    let mut frames = Vec::new();
    for chunk in chunks {
        buf.extend_from_slice(chunk);
        while let Some(frame) = P::parse(&mut buf) {
            frames.push(frame.to_bytes());
        }
    }
    (frames, buf)
}

/// A delimiter whose first two bytes repeat, so a partial match restarts inside itself.
struct Overlap;
impl Delimiter for Overlap {
    const DELIMITER: &'static [u8] = b"\xAA\xAA\xBB";
}

struct U8Whole;
impl FrameLength for U8Whole {
    const FIELD: LengthField = LengthField {
        offset: 0,
        width: 1,
        endian: Endian::Big,
        adjust: 0,
    };
}

struct U16Payload;
impl FrameLength for U16Payload {
    const FIELD: LengthField = LengthField {
        offset: 2,
        width: 2,
        endian: Endian::Little,
        adjust: 5,
    };
}

struct U32Big;
impl FrameLength for U32Big {
    const FIELD: LengthField = LengthField {
        offset: 1,
        width: 4,
        endian: Endian::Big,
        adjust: 5,
    };
}

struct U64Little;
impl FrameLength for U64Little {
    const FIELD: LengthField = LengthField {
        offset: 0,
        width: 8,
        endian: Endian::Little,
        adjust: 0,
    };
}

/// A body of `len` bytes drawn from `alphabet`.
fn body(rng: &mut Rng, len: usize, alphabet: &[u8]) -> Vec<u8> {
    (0..len)
        .map(|_| alphabet[rng.range(0, alphabet.len() - 1)])
        .collect()
}

/// `count` `Overlap` frames whose bodies are runs of `0xAA` and `0xBB` that never contain the
/// delimiter, the empty body among them.
fn overlap_frames(rng: &mut Rng, count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            let mut b = if i == 3 {
                Vec::new()
            } else {
                let len = rng.range(0, 12);
                body(rng, len, b"\xAA\xBB\x01")
            };
            while b.windows(3).any(|w| w == Overlap::DELIMITER) || b.ends_with(b"\xAA") {
                b.pop();
            }
            let mut frame = b;
            frame.extend_from_slice(Overlap::DELIMITER);
            frame
        })
        .collect()
}

fn length_frames(rng: &mut Rng, count: usize, field: LengthField, min: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|_| {
            let total = rng.range(min, min + 40);
            let mut frame = body(rng, total, b"\x00\x01\x7F\xFF");
            let value = (total as i64 - field.adjust) as u64;
            let bytes = match field.endian {
                Endian::Big => value.to_be_bytes()[8 - field.width..].to_vec(),
                Endian::Little => value.to_le_bytes()[..field.width].to_vec(),
            };
            frame[field.offset..field.offset + field.width].copy_from_slice(&bytes);
            frame
        })
        .collect()
}

/// Every frame comes out whole and in order for 300 split plans of `frames`, with only
/// `tail` (an incomplete frame) left over.
fn assert_split_invariant<P: Packet>(name: &str, frames: &[Vec<u8>], tail: &[u8], seed: u64) {
    let mut stream: Vec<u8> = frames.concat();
    stream.extend_from_slice(tail);
    let mut rng = Rng(seed);
    for plan in 0..300 {
        let max = [1, 2, 3, 7, 64][plan % 5];
        let chunks = split(&stream, &mut rng, max);
        let (got, rest) = parse_chunks::<P>(&chunks);
        assert_eq!(got, frames, "{name}: plan {plan} ({} chunks)", chunks.len());
        assert_eq!(rest, tail, "{name}: plan {plan} leaves only the tail");
    }
    let (whole, rest) = parse_chunks::<P>(&[stream]);
    assert_eq!(whole, frames, "{name}: one read");
    assert_eq!(rest, tail);
}

#[test]
fn every_framing_is_independent_of_how_reads_split_the_stream() {
    let mut rng = Rng(0x5EED_0001);

    let lines: Vec<Vec<u8>> = ["", "a", "\r", "two words", "\u{e9}t\u{e9}", "x\ry"]
        .iter()
        .map(|l| format!("{l}\n").into_bytes())
        .collect();
    assert_split_invariant::<Line>("Line", &lines, b"partial", rng.next());

    let crlf: Vec<Vec<u8>> = [&b""[..], b"\r", b"\n", b"\r\r", b"a\nb", b"{\"j\":1}"]
        .iter()
        .map(|b| [*b, b"\r\n"].concat())
        .collect();
    assert_split_invariant::<Delimited<CrLf>>("CrLf", &crlf, b"tail\r", rng.next());

    let overlap = overlap_frames(&mut rng, 24);
    assert_split_invariant::<Delimited<Overlap>>("Overlap", &overlap, b"\xAA\xAA", rng.next());

    let field = U8Whole::FIELD;
    let u8_frames = length_frames(&mut rng, 20, field, 1);
    assert_split_invariant::<LengthPrefixed<U8Whole>>("u8", &u8_frames, &[9, 1, 2], rng.next());

    let field = U16Payload::FIELD;
    let u16_frames = length_frames(&mut rng, 20, field, 5);
    assert_split_invariant::<LengthPrefixed<U16Payload>>("u16", &u16_frames, &[2, 0, 9], 7);

    let field = U32Big::FIELD;
    let u32_frames = length_frames(&mut rng, 20, field, 5);
    assert_split_invariant::<LengthPrefixed<U32Big>>("u32", &u32_frames, &[0, 0, 0, 0], 8);

    let field = U64Little::FIELD;
    let u64_frames = length_frames(&mut rng, 20, field, 8);
    assert_split_invariant::<LengthPrefixed<U64Little>>("u64", &u64_frames, &[30, 0, 0], 9);
}

#[test]
fn bytes_framing_returns_each_read_whole_and_nothing_for_an_empty_one() {
    let mut rng = Rng(0x5EED_0002);
    let stream = body(&mut rng, 500, b"\x00\x0A\x0D\xFF");
    let mut chunks = split(&stream, &mut rng, 9);
    chunks.insert(3, Vec::new());
    let (got, rest) = parse_chunks::<Bytes>(&chunks);
    let nonempty: Vec<Vec<u8>> = chunks.into_iter().filter(|c| !c.is_empty()).collect();
    assert_eq!(got, nonempty);
    assert!(rest.is_empty());
}

#[test]
fn invalid_utf8_in_a_line_becomes_replacement_characters() {
    let mut buf = b"a\xFF\xFEb\r\nrest".to_vec();
    assert_eq!(
        Line::parse(&mut buf),
        Some(Line("a\u{FFFD}\u{FFFD}b\r".into()))
    );
    assert_eq!(buf, b"rest");
    assert_eq!(Line::parse(&mut buf), None);
    assert_eq!(
        buf, b"rest",
        "an incomplete line leaves the buffer untouched"
    );
}

/// The default sim and a deterministic one.
fn sims() -> [Sim; 2] {
    [Sim::new(), Sim::builder().deterministic().build()]
}

#[test]
fn a_tcp_tester_frames_a_stream_written_in_seeded_random_pieces() {
    let mut rng = Rng(0x5EED_0003);
    let frames = overlap_frames(&mut rng, 40);
    let stream: Vec<u8> = frames.concat();
    let chunks = split(&stream, &mut rng, 11);
    for sim in sims() {
        let (frames, chunks) = (frames.clone(), chunks.clone());
        sim.run(move || {
            let tester = connect_tester::<Delimited<Overlap>>("127.0.0.62:16200")
                .recording()
                .until_after(Duration::from_millis(200));
            let client = std::thread::spawn(move || {
                let mut s = TcpStream::connect("127.0.0.62:16200").unwrap();
                for chunk in &chunks {
                    s.write_all(chunk).unwrap();
                    std::thread::sleep(Duration::from_millis(1));
                }
            });
            run_testers!(tester);
            client.join().unwrap();
            let got: Vec<Vec<u8>> = tester
                .recorded()
                .into_iter()
                .map(|(_, f)| f.frame().to_vec())
                .collect();
            assert_eq!(got, frames);
            let lens: Vec<usize> = snare::recorded_events()
                .into_iter()
                .filter_map(|e| match e.event {
                    snare::RecordedEvent::Received { len, .. } => Some(len),
                    _ => None,
                })
                .collect();
            let frame_lens: Vec<usize> = frames.iter().map(Vec::len).collect();
            assert_eq!(lens, frame_lens, "Received.len is each frame's length");
        });
    }
}

#[test]
fn a_udp_tester_parses_each_datagram_from_its_own_start() {
    let mut rng = Rng(0x5EED_0004);
    let crlf: Vec<u8> = (0..30)
        .flat_map(|i| [format!("m{i}").into_bytes(), b"\r\n".to_vec()].concat())
        .collect();
    let datagrams = split(&crlf, &mut rng, 13);
    let expected: Vec<Vec<u8>> = datagrams
        .iter()
        .flat_map(|d| parse_chunks::<Delimited<CrLf>>(std::slice::from_ref(d)).0)
        .collect();
    for sim in sims() {
        let (datagrams, expected) = (datagrams.clone(), expected.clone());
        sim.run(move || {
            let tester = udp_tester::<Delimited<CrLf>>("127.0.0.62:16210")
                .recording()
                .until_after(Duration::from_millis(200));
            let client = std::thread::spawn(move || {
                let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                for d in &datagrams {
                    s.send_to(d, "127.0.0.62:16210").unwrap();
                }
            });
            run_testers!(tester);
            client.join().unwrap();
            let got: Vec<Vec<u8>> = tester
                .recorded()
                .into_iter()
                .map(|(_, f)| f.frame().to_vec())
                .collect();
            assert_eq!(got, expected);
        });
    }
}

#[test]
fn tcp_connection_state_is_fresh_per_connection_and_listed_in_arrival_order() {
    for sim in sims() {
        sim.run(|| {
            let device = connect_tester::<Line>("127.0.0.62:16220")
                .with_state(Vec::<String>::new())
                .with_conn_state(|_| Vec::<String>::new())
                .then_conn_action(|conn, all, msg, _| {
                    conn.push(msg.0.clone());
                    all.push(msg.0.clone());
                    TesterAction::Send(Line(format!("{}/{}", conn.len(), all.len())))
                })
                .until_conns(|all, conns| all.len() == 6 && conns.len() == 3)
                .until_after(Duration::from_secs(1));

            let client = std::thread::spawn(|| {
                let mut replies = Vec::new();
                let mut peers = Vec::new();
                for (session, count) in [("a", 3), ("b", 1), ("c", 2)] {
                    let stream = TcpStream::connect("127.0.0.62:16220").unwrap();
                    peers.push(stream.local_addr().unwrap());
                    let mut w = stream.try_clone().unwrap();
                    let mut r = BufReader::new(stream);
                    for k in 0..count {
                        writeln!(w, "{session}{k}").unwrap();
                        let mut line = String::new();
                        r.read_line(&mut line).unwrap();
                        replies.push(line.trim_end().to_owned());
                    }
                }
                (peers, replies)
            });
            run_testers!(device);
            let (peers, replies) = client.join().unwrap();
            assert_eq!(replies, ["1/1", "2/2", "3/3", "1/4", "1/5", "2/6"]);
            device.inspect(|all| assert_eq!(all, &["a0", "a1", "a2", "b0", "c0", "c1"]));
            device.inspect_conns(|conns| {
                let listed: Vec<(SocketAddr, Vec<String>)> = conns.to_vec();
                assert_eq!(
                    listed,
                    [
                        (peers[0], vec!["a0".into(), "a1".into(), "a2".into()]),
                        (peers[1], vec!["b0".into()]),
                        (peers[2], vec!["c0".into(), "c1".into()]),
                    ]
                );
            });
        });
    }
}

#[test]
fn udp_source_state_is_kept_per_source_address_across_sends() {
    for sim in sims() {
        sim.run(|| {
            let device = udp_tester::<Bytes>("127.0.0.62:16230")
                .with_conn_state(|_| 0u32)
                .then_conn_action(|count, _, msg, from| {
                    *count += 1;
                    TesterAction::SendTo(from, Bytes([msg.0.clone(), vec![*count as u8]].concat()))
                })
                .until_after(Duration::from_millis(100));
            let client = std::thread::spawn(|| {
                let a = UdpSocket::bind("127.0.0.1:0").unwrap();
                let b = UdpSocket::bind("127.0.0.1:0").unwrap();
                let mut got = Vec::new();
                let mut buf = [0u8; 8];
                for (sock, tag) in [(&a, b'a'), (&b, b'b'), (&a, b'a'), (&a, b'a'), (&b, b'b')] {
                    sock.send_to(&[tag], "127.0.0.62:16230").unwrap();
                    let n = sock.recv(&mut buf).unwrap();
                    got.push(buf[..n].to_vec());
                }
                (vec![a.local_addr().unwrap(), b.local_addr().unwrap()], got)
            });
            run_testers!(device);
            let (peers, got) = client.join().unwrap();
            assert_eq!(
                got,
                [
                    b"a\x01".to_vec(),
                    b"b\x01".to_vec(),
                    b"a\x02".to_vec(),
                    b"a\x03".to_vec(),
                    b"b\x02".to_vec()
                ]
            );
            device.inspect_conns(|conns| {
                assert_eq!(conns.to_vec(), [(peers[0], 3), (peers[1], 2)]);
            });
        });
    }
}

/// When each of three cyclic emitters ticked, relative to the instant before the run: period
/// 7 ms at phase 3 ms, at phase 0 and with no phase (first tick one period in).
fn cyclic_ticks() -> [Vec<Duration>; 3] {
    let sink: SocketAddr = "127.0.0.1:16240".parse().unwrap();
    let _sink = UdpSocket::bind(sink).unwrap();
    let period = Duration::from_millis(7);
    let emitter = |addr: &str, phase: Option<Duration>| {
        let t = udp_tester::<Bytes>(addr).with_state(Vec::<Duration>::new());
        let tick = move |ticks: &mut Vec<Duration>| {
            ticks.push(snare::time().value());
            TesterAction::SendTo(sink, Bytes(vec![ticks.len() as u8]))
        };
        match phase {
            Some(p) => t.with_stateful_cyclic_action_at(period, p, tick),
            None => t.with_stateful_cyclic_action(period, tick),
        }
        .until_after(Duration::from_millis(30))
    };
    let phased = emitter("127.0.0.62:16241", Some(Duration::from_millis(3)));
    let zero = emitter("127.0.0.62:16242", Some(Duration::ZERO));
    let plain = emitter("127.0.0.62:16243", None);
    let start = snare::time().value();
    run_testers!(phased, zero, plain);
    let rel = |t: &snare::Tester<Bytes, Vec<Duration>>| {
        t.inspect(|ticks| ticks.iter().map(|&at| at - start).collect::<Vec<_>>())
    };
    [rel(&phased), rel(&zero), rel(&plain)]
}

/// Every tick but a zero phase's first is a timed wake, landing just past its deadline as every
/// time skip does; the lattice itself never drifts.
#[test]
fn cyclic_ticks_land_on_their_exact_lattice() {
    let at = |ms: u64| Duration::from_nanos(landing::past(ms * 1_000_000));
    for sim in sims() {
        let [phased, zero, plain] = sim.run(cyclic_ticks);
        assert_eq!(phased, [at(3), at(10), at(17), at(24)]);
        assert_eq!(zero, [Duration::ZERO, at(7), at(14), at(21), at(28)]);
        assert_eq!(plain, [at(7), at(14), at(21), at(28)]);
    }
}

/// A TCP echo session under 2 ms of latency each way: two lines, the reply to each read, then a
/// half-close and the tester's close, rendered one entry per line.
fn echo_session_log() -> String {
    let sim = Sim::builder().deterministic().seed(11).build();
    sim.run(|| {
        set_tcp_policy("127.0.0.63:16250", |p: &mut TcpPolicy| {
            p.latency = Duration::from_millis(2);
        });
        let server = connect_tester::<Line>("127.0.0.63:16250")
            .then_action(|msg, _| TesterAction::Send(Line(format!("echo:{}", msg.0))))
            .until_after(Duration::from_millis(100));
        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.63:16250").unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            for msg in ["one", "two"] {
                (&stream).write_all(format!("{msg}\n").as_bytes()).unwrap();
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
            }
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            let mut rest = Vec::new();
            reader.read_to_end(&mut rest).unwrap();
            rest
        });
        run_testers!(server);
        assert!(client.join().unwrap().is_empty());
    });
    let log = sim.recorded_events();
    let first = log.first().map_or(0, |e| e.seq);
    log.iter()
        .map(|e| format!("{:>12?} +{} {:?}\n", e.at, e.seq - first, e.event))
        .collect()
}

#[test]
fn a_deterministic_echo_session_logs_the_golden_events() {
    let log = echo_session_log();
    assert_eq!(
        log,
        echo_session_log(),
        "the same seed logs the same entries"
    );
    let name = if cfg!(windows) {
        "edge_net_testers_events.windows.txt"
    } else {
        "edge_net_testers_events.txt"
    };
    golden::check_text(name, &log);
}
