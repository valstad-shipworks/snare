#![cfg(target_os = "macos")]

//! On macOS `mio`'s event loop is `kqueue`/`kevent`; the sim now models them (incl. the `Waker`'s
//! cloned-kqueue `EVFILT_USER` trigger), so mio-based drivers run in-process natively. The Linux
//! counterpart is `tests/mio_readiness.rs` over epoll.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use mio::{Events, Interest, Poll, Token, Waker};
use snare::{Line, Sim, TesterAction, connect_tester, run_testers};

#[test]
fn mio_client_echo_over_kqueue() {
    let sim = Sim::new();
    sim.run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9900")
            .then_action(|msg, _| TesterAction::Send(Line(format!("echo:{}", msg.0))))
            .until_after(Duration::from_millis(500));

        let client = std::thread::spawn(|| {
            let mut poll = Poll::new().unwrap();
            let mut events = Events::with_capacity(16);
            let mut stream =
                mio::net::TcpStream::connect("127.0.0.2:9900".parse().unwrap()).unwrap();
            poll.registry()
                .register(&mut stream, Token(0), Interest::READABLE | Interest::WRITABLE)
                .unwrap();

            let mut wrote = false;
            let mut got = String::new();
            while !got.contains('\n') {
                poll.poll(&mut events, Some(Duration::from_millis(50))).unwrap();
                for ev in events.iter() {
                    if ev.token() == Token(0) {
                        if ev.is_writable() && !wrote {
                            stream.write_all(b"hi\n").unwrap();
                            wrote = true;
                        }
                        if ev.is_readable() {
                            let mut buf = [0u8; 64];
                            if let Ok(n) = stream.read(&mut buf)
                                && n > 0
                            {
                                got.push_str(std::str::from_utf8(&buf[..n]).unwrap());
                            }
                        }
                    }
                }
            }
            got
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), "echo:hi\n");
    });
}

#[test]
fn mio_waker_wakes_the_poll() {
    let sim = Sim::new();
    sim.run(|| {
        let mut poll = Poll::new().unwrap();
        let waker = Arc::new(Waker::new(poll.registry(), Token(10)).unwrap());
        let w = waker.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(5));
            w.wake().unwrap();
        });
        let mut events = Events::with_capacity(8);
        let mut woken = false;
        while !woken {
            poll.poll(&mut events, Some(Duration::from_millis(100))).unwrap();
            woken = events.iter().any(|e| e.token() == Token(10));
        }
        t.join().unwrap();
        assert!(woken);
    });
}
