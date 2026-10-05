//! The ready-made framings: `Delimited` frames ended by any byte string and `LengthPrefixed` frames
//! sized by a header field, over TCP (frames split across reads, several in one read) and UDP
//! (several frames in one datagram, a tail dropped with it), under the default sim and a
//! deterministic one.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

use snare::{
    Cr, CrLf, Delimited, Endian, FrameLength, LengthField, LengthPrefixed, Packet, Sim,
    TesterAction, connect_tester, run_testers, udp_tester,
};

/// The default sim and a deterministic one; every test runs under both.
fn sims() -> [Sim; 2] {
    [Sim::new(), Sim::builder().deterministic().build()]
}

/// Writes `chunks` one at a time with a millisecond of sim time between them, so the tester reads
/// each separately.
fn write_chunks(stream: &mut TcpStream, chunks: &[&[u8]]) {
    for chunk in chunks {
        stream.write_all(chunk).unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn crlf_frames_split_and_joined_across_reads() {
    for sim in sims() {
        sim.run(|| {
            let robot = connect_tester::<Delimited<CrLf>>("127.0.0.60:16001")
                .recording()
                .then_action(|frame, _| {
                    TesterAction::Send(Delimited::new(format!("ok {}", frame.text())))
                })
                .until_after(Duration::from_millis(50));

            let client = std::thread::spawn(|| {
                let mut stream = TcpStream::connect("127.0.0.60:16001").unwrap();
                write_chunks(
                    &mut stream,
                    &[
                        b"{\"a\":1}\r\n{\"b\"",
                        b":2}\r",
                        b"\n{\"c\":3}\r\n{\"d\":4}\r\n",
                    ],
                );
                let mut replies = String::new();
                stream.read_to_string(&mut replies).unwrap();
                replies
            });

            run_testers!(robot);
            assert_eq!(
                client.join().unwrap(),
                "ok {\"a\":1}\r\nok {\"b\":2}\r\nok {\"c\":3}\r\nok {\"d\":4}\r\n"
            );
            let frames: Vec<_> = robot.recorded().into_iter().map(|(_, f)| f).collect();
            assert_eq!(frames.len(), 4);
            assert_eq!(
                frames[1].frame(),
                b"{\"b\":2}\r\n",
                "the raw frame keeps its delimiter"
            );
            assert_eq!(frames[1].body(), b"{\"b\":2}");
        });
    }
}

#[test]
fn cr_frames_answer_a_text_command() {
    for sim in sims() {
        sim.run(|| {
            let scanner = connect_tester::<Delimited<Cr>>("127.0.0.60:16002")
                .then_action(|cmd, _| match cmd.body() {
                    b"SetInitializeAcquisition" => TesterAction::Send(Delimited::new("OK")),
                    _ => TesterAction::Send(Delimited::new("ERR")),
                })
                .until_after(Duration::from_millis(20));

            let client = std::thread::spawn(|| {
                let stream = TcpStream::connect("127.0.0.60:16002").unwrap();
                let mut w = stream.try_clone().unwrap();
                w.write_all(b"SetInitializeAcquisition\rBogus\r").unwrap();
                let mut r = BufReader::new(stream);
                let mut replies = Vec::new();
                r.read_until(b'\r', &mut replies).unwrap();
                r.read_until(b'\r', &mut replies).unwrap();
                replies
            });

            run_testers!(scanner);
            assert_eq!(client.join().unwrap(), b"OK\rERR\r");
        });
    }
}

/// `[0x02][type][len: u16 LE][payload][0x03]`: the length counts the payload only.
struct Gcom;
impl FrameLength for Gcom {
    const FIELD: LengthField = LengthField {
        offset: 2,
        width: 2,
        endian: Endian::Little,
        adjust: 5,
    };
}

/// A GCOM socket frame around `payload`.
fn gcom(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x02, kind];
    frame.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    frame.extend_from_slice(payload);
    frame.push(0x03);
    frame
}

#[test]
fn a_payload_length_frame_is_put_back_together() {
    for sim in sims() {
        sim.run(|| {
            let tracker = connect_tester::<LengthPrefixed<Gcom>>("127.0.0.60:16003")
                .recording()
                .then_action(|frame, _| {
                    let payload = &frame.frame()[4..frame.frame().len() - 1];
                    TesterAction::Send(LengthPrefixed::new(gcom(0x81, payload)))
                })
                .until_after(Duration::from_millis(50));

            let first = gcom(1, b"hello");
            let second = gcom(2, b"");
            let third = gcom(3, &[0xAA; 300]);
            let (f, s, t) = (first.clone(), second.clone(), third.clone());
            let client = std::thread::spawn(move || {
                let mut stream = TcpStream::connect("127.0.0.60:16003").unwrap();
                let mut both = s.clone();
                both.extend_from_slice(&t[..2]);
                write_chunks(&mut stream, &[&f[..1], &f[1..3], &f[3..], &both, &t[2..]]);
                let mut replies = Vec::new();
                stream.read_to_end(&mut replies).unwrap();
                replies
            });

            run_testers!(tracker);
            let mut expected = gcom(0x81, b"hello");
            expected.extend(gcom(0x81, b""));
            expected.extend(gcom(0x81, &[0xAA; 300]));
            assert_eq!(client.join().unwrap(), expected);
            assert_eq!(raw_frames(&tracker.recorded()), [first, second, third]);
            assert_eq!(tracker.recorded()[2].1.length_field(), 300);
        });
    }
}

/// The raw frames of a recording.
fn raw_frames<L: FrameLength>(
    recorded: &[(std::net::SocketAddr, LengthPrefixed<L>)],
) -> Vec<Vec<u8>> {
    recorded.iter().map(|(_, f)| f.frame().to_vec()).collect()
}

/// A 56-byte SNP-X message whose `u16` LE text length at byte 4 counts the text after it.
struct Snpx;
impl FrameLength for Snpx {
    const FIELD: LengthField = LengthField {
        offset: 4,
        width: 2,
        endian: Endian::Little,
        adjust: 56,
    };
}

#[test]
fn a_header_plus_text_frame_waits_for_its_text() {
    for sim in sims() {
        sim.run(|| {
            let robot = connect_tester::<LengthPrefixed<Snpx>>("127.0.0.60:16004")
                .recording()
                .until_after(Duration::from_millis(20));

            let mut message = vec![0u8; 56];
            message[4..6].copy_from_slice(&6u16.to_le_bytes());
            message.extend_from_slice(b"abcdef");
            let short = vec![0u8; 56];
            let (m, sh) = (message.clone(), short.clone());
            let client = std::thread::spawn(move || {
                let mut stream = TcpStream::connect("127.0.0.60:16004").unwrap();
                write_chunks(&mut stream, &[&m[..5], &m[5..58], &m[58..], &sh]);
            });

            run_testers!(robot);
            client.join().unwrap();
            assert_eq!(raw_frames(&robot.recorded()), [message, short]);
        });
    }
}

/// A big-endian `u32` at the very start that counts the whole frame, itself included.
struct WholeFrame;
impl FrameLength for WholeFrame {
    const FIELD: LengthField = LengthField {
        offset: 0,
        width: 4,
        endian: Endian::Big,
        adjust: 0,
    };
}

#[test]
fn several_frames_in_one_datagram_and_the_tail_is_dropped() {
    for sim in sims() {
        sim.run(|| {
            let lines = udp_tester::<Delimited<CrLf>>("127.0.0.60:16005")
                .recording()
                .until_after(Duration::from_millis(20));
            let sized = udp_tester::<LengthPrefixed<WholeFrame>>("127.0.0.60:16006")
                .recording()
                .then_action(|frame, _| TesterAction::Send(frame))
                .until_after(Duration::from_millis(20));

            let client = std::thread::spawn(|| {
                let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
                sock.send_to(b"one\r\ntwo\r\nthr", "127.0.0.60:16005")
                    .unwrap();
                sock.send_to(b"ee\r\n", "127.0.0.60:16005").unwrap();
                sock.send_to(&[0, 0, 0, 6, 1, 2, 0, 0, 0, 5, 9, 0, 0], "127.0.0.60:16006")
                    .unwrap();
                let mut echoes = Vec::new();
                for _ in 0..2 {
                    let mut buf = [0u8; 64];
                    let n = sock.recv(&mut buf).unwrap();
                    echoes.push(buf[..n].to_vec());
                }
                echoes
            });

            run_testers!(lines, sized);
            assert_eq!(
                client.join().unwrap(),
                [vec![0, 0, 0, 6, 1, 2], vec![0, 0, 0, 5, 9]]
            );
            let texts: Vec<_> = lines
                .recorded()
                .iter()
                .map(|(_, f)| f.text().into_owned())
                .collect();
            assert_eq!(texts, ["one", "two", "ee"], "a frame never spans datagrams");
            assert_eq!(sized.recorded().len(), 2);
        });
    }
}

#[test]
fn a_length_field_reads_every_width_and_order() {
    let field = |width, endian, adjust| LengthField {
        offset: 1,
        width,
        endian,
        adjust,
    };
    let buf = [0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    assert_eq!(field(1, Endian::Big, 2).frame_len(&buf), Some(3));
    assert_eq!(field(2, Endian::Big, 0).frame_len(&buf), Some(0x0102));
    assert_eq!(field(2, Endian::Little, 0).frame_len(&buf), Some(0x0201));
    assert_eq!(
        field(4, Endian::Little, -3).frame_len(&buf),
        Some(0x0403_0201 - 3)
    );
    assert_eq!(
        field(8, Endian::Big, 0).frame_len(&buf),
        Some(0x0102_0304_0506_0708)
    );
    assert_eq!(
        field(8, Endian::Big, 0).frame_len(&buf[..8]),
        None,
        "the field is incomplete"
    );

    let mut stream = vec![0u8, 0, 0, 6, 1];
    assert_eq!(LengthPrefixed::<WholeFrame>::parse(&mut stream), None);
    assert_eq!(
        stream.len(),
        5,
        "an incomplete frame leaves the buffer untouched"
    );
    stream.push(2);
    assert!(LengthPrefixed::<WholeFrame>::parse(&mut stream).is_some());
    assert!(stream.is_empty());

    let mut text = b"abc\r".to_vec();
    assert_eq!(Delimited::<CrLf>::parse(&mut text), None);
    text.extend_from_slice(b"\nd");
    assert_eq!(Delimited::<CrLf>::parse(&mut text).unwrap().body(), b"abc");
    assert_eq!(text, b"d");
}

#[test]
#[should_panic(expected = "shorter than the 4 bytes up to the end of the field")]
fn a_malformed_length_fails_the_test() {
    Sim::new().run(|| {
        let device = connect_tester::<LengthPrefixed<WholeFrame>>("127.0.0.60:16007")
            .until_after(Duration::from_millis(20));
        let client = std::thread::spawn(|| {
            let mut stream = TcpStream::connect("127.0.0.60:16007").unwrap();
            stream.write_all(&[0, 0, 0, 2, 0xEE]).unwrap();
        });
        run_testers!(device);
        client.join().unwrap();
    });
}
