#![cfg(unix)]
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use snare::{Bytes, Line, Sim, TesterAction, connect_tester, run_testers};

#[test]
fn request_response_echo() {
    let sim = Sim::new();
    sim.run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9401")
            .then_action(|msg, _from| TesterAction::Send(Line(format!("echo:{}", msg.0))))
            .until_after(Duration::from_millis(300));

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.2:9401").unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            writer.write_all(b"hello\n").unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            line
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), "echo:hello\n");
    });
}

#[test]
fn several_requests_over_one_connection() {
    let sim = Sim::new();
    sim.run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9402")
            .then_action(|msg, _| {
                let n: u64 = msg.0.parse().unwrap_or(0);
                TesterAction::Send(Line((n * 2).to_string()))
            })
            .until_after(Duration::from_millis(300));

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.2:9402").unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let mut doubled = Vec::new();
            for i in 1..=5u64 {
                writeln!(writer, "{i}").unwrap();
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                doubled.push(line.trim().parse::<u64>().unwrap());
            }
            doubled
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), vec![2, 4, 6, 8, 10]);
    });
}

#[test]
fn peer_close_is_eof() {
    let sim = Sim::new();
    sim.run(|| {
        let server = connect_tester::<Bytes>("127.0.0.2:9403")
            .then_action(|_msg, _| TesterAction::Close)
            .until_after(Duration::from_millis(300));

        let client = std::thread::spawn(|| {
            let mut stream = TcpStream::connect("127.0.0.2:9403").unwrap();
            stream.write_all(b"bye").unwrap();
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).unwrap();
            rest
        });

        run_testers!(server);
        assert!(client.join().unwrap().is_empty());
    });
}

#[test]
fn connection_refused_without_a_tester() {
    let sim = Sim::new();
    sim.run(|| {
        let err = TcpStream::connect("127.0.0.2:9404").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    });
}

#[test]
fn cyclic_action_streams_unprompted() {
    let sim = Sim::new();
    sim.run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9405")
            .with_cyclic_action(Duration::from_millis(5), || {
                TesterAction::Send(Line("tick".into()))
            })
            .until_after(Duration::from_millis(200));

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.2:9405").unwrap();
            let mut reader = BufReader::new(stream);
            let mut ticks = 0;
            let mut line = String::new();
            while ticks < 3 {
                line.clear();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                if line.trim() == "tick" {
                    ticks += 1;
                }
            }
            ticks
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), 3);
    });
}
