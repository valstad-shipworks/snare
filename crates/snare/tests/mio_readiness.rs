#![cfg(target_os = "linux")]
//! The code under test drives readiness with `mio` (epoll + eventfd on Linux), the way the real
//! drivers do. These exercise the fabric's epoll/eventfd emulation, not just the socket calls.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mio::{Events, Interest, Poll, Token, Waker};
use snare::{Line, Sim, TesterAction, connect_tester, run_testers};

#[test]
fn mio_client_echo_over_epoll() {
    let sim = Sim::new();
    sim.run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9600")
            .then_action(|msg, _| TesterAction::Send(Line(format!("echo:{}", msg.0))))
            .until_after(Duration::from_millis(500));

        let client = std::thread::spawn(|| {
            let mut poll = Poll::new().unwrap();
            let mut events = Events::with_capacity(16);
            let mut stream =
                mio::net::TcpStream::connect("127.0.0.2:9600".parse().unwrap()).unwrap();
            poll.registry()
                .register(
                    &mut stream,
                    Token(0),
                    Interest::READABLE | Interest::WRITABLE,
                )
                .unwrap();

            let (mut sent, mut got) = (false, String::new());
            let deadline = Instant::now() + Duration::from_secs(3);
            while !got.contains('\n') && Instant::now() < deadline {
                poll.poll(&mut events, Some(Duration::from_millis(50)))
                    .unwrap();
                for event in events.iter() {
                    if event.is_writable() && !sent {
                        stream.write_all(b"hello\n").unwrap();
                        sent = true;
                    }
                    if event.is_readable() {
                        let mut buf = [0u8; 64];
                        match stream.read(&mut buf) {
                            Ok(n) => got.push_str(&String::from_utf8_lossy(&buf[..n])),
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(e) => panic!("read: {e}"),
                        }
                    }
                }
            }
            got
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap().trim(), "echo:hello");
    });
}

#[test]
fn mio_waker_wakes_a_blocked_poll() {
    let sim = Sim::new();
    sim.run(|| {
        let woke = std::thread::spawn(|| {
            let mut poll = Poll::new().unwrap();
            let waker = Arc::new(Waker::new(poll.registry(), Token(9)).unwrap());
            let waker2 = waker.clone();
            let waking = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(30));
                waker2.wake().unwrap();
            });

            let mut events = Events::with_capacity(4);
            poll.poll(&mut events, Some(Duration::from_secs(3)))
                .unwrap();
            waking.join().unwrap();
            events.iter().any(|e| e.token() == Token(9))
        });
        assert!(woke.join().unwrap(), "the waker should have woken the poll");
    });
}
