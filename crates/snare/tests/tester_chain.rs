//! A tester's message chain: tests that drop or rewrite a message before the stages after them,
//! state edits, and actions, all run in the order they were added.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

use snare::{Bytes, Line, Sim, TesterAction, connect_tester, run_testers, udp_tester};

/// Sends each line on its own, then reads every reply line until the tester closes.
fn converse(
    addr: &'static str,
    lines: &'static [&'static str],
) -> std::thread::JoinHandle<Vec<String>> {
    std::thread::spawn(move || {
        let mut stream = TcpStream::connect(addr).unwrap();
        for line in lines {
            stream.write_all(format!("{line}\n").as_bytes()).unwrap();
        }
        BufReader::new(stream).lines().map(Result::unwrap).collect()
    })
}

#[test]
fn then_test_none_stops_the_chain() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.31:9100")
            .then_test(|msg, _| (msg.0 != "drop").then_some(msg))
            .then_action(|msg, _| TesterAction::Send(Line(format!("got:{}", msg.0))))
            .until_after(Duration::from_millis(200));
        let client = converse("127.0.0.31:9100", &["a", "drop", "b"]);
        run_testers!(server);
        assert_eq!(client.join().unwrap(), ["got:a", "got:b"]);
    });
}

#[test]
fn then_test_some_forwards_a_rewritten_message() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.31:9101")
            .then_test(|msg, _| Some(Line(msg.0.to_uppercase())))
            .then_action(|msg, _| TesterAction::Send(msg))
            .until_after(Duration::from_millis(200));
        let client = converse("127.0.0.31:9101", &["hello", "there"]);
        run_testers!(server);
        assert_eq!(client.join().unwrap(), ["HELLO", "THERE"]);
    });
}

#[test]
fn then_stateful_test_filters_with_state() {
    Sim::new().run(|| {
        let device = udp_tester::<Bytes>("127.0.0.31:9102")
            .with_state(Vec::<u8>::new())
            .then_stateful_test(|seen, msg, _| {
                let first = !seen.contains(&msg.0[0]);
                seen.push(msg.0[0]);
                first.then_some(msg)
            })
            .then_action(|msg, _| TesterAction::Send(msg))
            .until_after(Duration::from_millis(200));
        let client = std::thread::spawn(|| {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            for b in [1u8, 2, 1, 3, 2] {
                sock.send_to(&[b], "127.0.0.31:9102").unwrap();
            }
            sock.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let mut echoed = Vec::new();
            let mut buf = [0u8; 8];
            while let Ok((n, _)) = sock.recv_from(&mut buf) {
                echoed.extend_from_slice(&buf[..n]);
            }
            echoed
        });
        run_testers!(device);
        assert_eq!(
            client.join().unwrap(),
            [1, 2, 3],
            "repeats are filtered out"
        );
        device.inspect(|seen| assert_eq!(seen, &[1, 2, 1, 3, 2], "the test saw every datagram"));
    });
}

#[test]
fn then_edit_state_counts_and_forwards() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.31:9103")
            .with_state(0usize)
            .then_edit_state(|count, _| *count += 1)
            .then_stateful_action(|count, msg, _| {
                TesterAction::Send(Line(format!("{}#{count}", msg.0)))
            })
            .until_after(Duration::from_millis(200));
        let client = converse("127.0.0.31:9103", &["x", "y", "z"]);
        run_testers!(server);
        assert_eq!(client.join().unwrap(), ["x#1", "y#2", "z#3"]);
        server.inspect(|count| assert_eq!(*count, 3));
    });
}

#[test]
fn stages_run_in_insertion_order() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.31:9104")
            .with_state(Vec::<String>::new())
            .then_stateful_action(|log, msg, _| {
                log.push(format!("act1:{}", msg.0));
                TesterAction::Send(Line(format!("first:{}", msg.0)))
            })
            .then_stateful_test(|log, msg, _| {
                log.push(format!("test:{}", msg.0));
                (msg.0 != "stop").then(|| Line(format!("{}!", msg.0)))
            })
            .then_edit_state(|log, _| log.push("edit".into()))
            .then_stateful_action(|log, msg, _| {
                log.push(format!("act2:{}", msg.0));
                TesterAction::Send(Line(format!("second:{}", msg.0)))
            })
            .until_after(Duration::from_millis(200));
        let client = converse("127.0.0.31:9104", &["go", "stop"]);
        run_testers!(server);
        assert_eq!(
            client.join().unwrap(),
            ["first:go", "second:go!", "first:stop"],
            "an action before a dropping test still acts, in order"
        );
        server.inspect(|log| {
            assert_eq!(
                log,
                &[
                    "act1:go",
                    "test:go",
                    "edit",
                    "act2:go!",
                    "act1:stop",
                    "test:stop"
                ]
            )
        });
    });
}

#[test]
fn handlers_added_before_with_state_keep_filtering() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.31:9105")
            .then_test(|msg, _| (!msg.0.starts_with('#')).then_some(msg))
            .with_state(Vec::<String>::new())
            .then_stateful_action(|kept, msg, _| {
                kept.push(msg.0.clone());
                TesterAction::Nothing
            })
            .until_after(Duration::from_millis(200));
        let client = converse("127.0.0.31:9105", &["a", "#comment", "b"]);
        run_testers!(server);
        client.join().unwrap();
        server.inspect(|kept| assert_eq!(kept, &["a", "b"]));
    });
}

#[test]
fn recording_captures_messages_a_filter_dropped() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.31:9106")
            .recording()
            .then_test(|_, _| None)
            .until_after(Duration::from_millis(200));
        let client = converse("127.0.0.31:9106", &["one", "two"]);
        run_testers!(server);
        client.join().unwrap();
        let recorded: Vec<_> = server.recorded().into_iter().map(|(_, m)| m.0).collect();
        assert_eq!(
            recorded,
            ["one", "two"],
            "the recording is what the code under test sent"
        );
    });
}
