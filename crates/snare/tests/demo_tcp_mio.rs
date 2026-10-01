#![cfg(target_os = "linux")]
//! Readiness-driven TCP the way the real drivers do it: `mio` on Linux is epoll (man 7 epoll)
//! plus an eventfd for its cross-thread `Waker` (man 2 eventfd — "a Waker allows waking up a Poll
//! from another thread"). These drive the fabric's epoll/eventfd emulation, not just the socket
//! calls, so they belong to the tcp-easy readiness surface.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mio::{Events, Interest, Poll, Token, Waker};
use snare::{Line, Sim, TesterAction, connect_tester, run_testers};

fn deadline(d: Duration) -> Instant {
    Instant::now() + d
}

#[test]
fn epoll_reports_writable_then_readable() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9630")
            .then_action(|msg, _| TesterAction::Send(Line(format!("echo:{}", msg.0))))
            .until_after(Duration::from_millis(500));

        let client = std::thread::spawn(|| {
            let mut poll = Poll::new().unwrap();
            let mut events = Events::with_capacity(16);
            let mut stream = mio::net::TcpStream::connect("127.0.0.2:9630".parse().unwrap()).unwrap();
            poll.registry()
                .register(&mut stream, Token(0), Interest::READABLE | Interest::WRITABLE)
                .unwrap();

            let (mut sent, mut got) = (false, String::new());
            let end = deadline(Duration::from_secs(3));
            while !got.contains('\n') && Instant::now() < end {
                poll.poll(&mut events, Some(Duration::from_millis(50))).unwrap();
                for event in events.iter() {
                    if event.is_writable() && !sent {
                        stream.write_all(b"hi\n").unwrap();
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
        assert_eq!(client.join().unwrap().trim(), "echo:hi");
    });
}

#[test]
fn poll_times_out_with_no_ready_fd() {
    Sim::new().run(|| {
        // No writable/readable interest can fire on a socket that is connected but idle and whose
        // peer never speaks. man 7 epoll: epoll_wait returns 0 when the timeout expires first.
        let server = connect_tester::<Line>("127.0.0.2:9631")
            .then_action(|_msg, _| TesterAction::Nothing)
            .until_after(Duration::from_millis(300));

        let client = std::thread::spawn(|| {
            let mut poll = Poll::new().unwrap();
            let mut events = Events::with_capacity(8);
            let mut stream = mio::net::TcpStream::connect("127.0.0.2:9631".parse().unwrap()).unwrap();
            poll.registry()
                .register(&mut stream, Token(1), Interest::READABLE)
                .unwrap();
            poll.poll(&mut events, Some(Duration::from_millis(50))).unwrap();
            events.iter().filter(|e| e.is_readable()).count()
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), 0);
    });
}

#[test]
fn waker_wakes_a_blocked_poll() {
    Sim::new().run(|| {
        let woke = std::thread::spawn(|| {
            let mut poll = Poll::new().unwrap();
            let waker = Arc::new(Waker::new(poll.registry(), Token(9)).unwrap());
            let w2 = waker.clone();
            let waking = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(30));
                w2.wake().unwrap();
            });
            let mut events = Events::with_capacity(4);
            poll.poll(&mut events, Some(Duration::from_secs(3))).unwrap();
            waking.join().unwrap();
            events.iter().any(|e| e.token() == Token(9))
        });
        assert!(woke.join().unwrap(), "the waker should have woken the poll");
    });
}

#[test]
fn two_sockets_multiplexed_on_one_poll() {
    Sim::new().run(|| {
        let a = connect_tester::<Line>("127.0.0.2:9632")
            .then_action(|msg, _| TesterAction::Send(Line(format!("A:{}", msg.0))))
            .until_after(Duration::from_millis(500));
        let b = connect_tester::<Line>("127.0.0.2:9633")
            .then_action(|msg, _| TesterAction::Send(Line(format!("B:{}", msg.0))))
            .until_after(Duration::from_millis(500));

        let client = std::thread::spawn(|| {
            let mut poll = Poll::new().unwrap();
            let mut events = Events::with_capacity(16);
            let mut s0 = mio::net::TcpStream::connect("127.0.0.2:9632".parse().unwrap()).unwrap();
            let mut s1 = mio::net::TcpStream::connect("127.0.0.2:9633".parse().unwrap()).unwrap();
            poll.registry()
                .register(&mut s0, Token(0), Interest::READABLE | Interest::WRITABLE)
                .unwrap();
            poll.registry()
                .register(&mut s1, Token(1), Interest::READABLE | Interest::WRITABLE)
                .unwrap();

            let (mut sent0, mut sent1) = (false, false);
            let mut got0 = String::new();
            let mut got1 = String::new();
            let end = deadline(Duration::from_secs(3));
            while (!got0.contains('\n') || !got1.contains('\n')) && Instant::now() < end {
                poll.poll(&mut events, Some(Duration::from_millis(50))).unwrap();
                for event in events.iter() {
                    let (stream, sent, got) = if event.token() == Token(0) {
                        (&mut s0, &mut sent0, &mut got0)
                    } else {
                        (&mut s1, &mut sent1, &mut got1)
                    };
                    if event.is_writable() && !*sent {
                        stream.write_all(b"q\n").unwrap();
                        *sent = true;
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
            (got0.trim().to_string(), got1.trim().to_string())
        });

        run_testers!(a, b);
        assert_eq!(client.join().unwrap(), ("A:q".into(), "B:q".into()));
    });
}

#[test]
fn peer_close_wakes_poll_with_readable_eof() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9634")
            .then_action(|_msg, _| TesterAction::Close)
            .until_after(Duration::from_millis(500));

        let client = std::thread::spawn(|| {
            let mut poll = Poll::new().unwrap();
            let mut events = Events::with_capacity(8);
            let mut stream = mio::net::TcpStream::connect("127.0.0.2:9634".parse().unwrap()).unwrap();
            poll.registry()
                .register(&mut stream, Token(0), Interest::READABLE | Interest::WRITABLE)
                .unwrap();

            let (mut sent, mut eof) = (false, false);
            let end = deadline(Duration::from_secs(3));
            while !eof && Instant::now() < end {
                poll.poll(&mut events, Some(Duration::from_millis(50))).unwrap();
                for event in events.iter() {
                    if event.is_writable() && !sent {
                        stream.write_all(b"go\n").unwrap();
                        sent = true;
                    }
                    if event.is_readable() {
                        let mut buf = [0u8; 64];
                        // man 2 recv over an epoll-readable fd: a 0-length read is EOF.
                        if let Ok(0) = stream.read(&mut buf) {
                            eof = true;
                        }
                    }
                }
            }
            eof
        });

        run_testers!(server);
        assert!(client.join().unwrap(), "the peer close should surface as a readable EOF");
    });
}
