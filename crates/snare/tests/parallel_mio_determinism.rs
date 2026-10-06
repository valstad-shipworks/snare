//! Many deterministic sims in one process, each a mio client exchanging requests and replies with
//! a blocking server, all at once. A reply's readiness reaches the client's poll before its timeout
//! in every sim, and every sim run with the same seed logs the same trace, however the sims contend
//! for the process meanwhile.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use mio::net::TcpStream as MioStream;
use mio::{Events, Interest, Poll, Token};
use snare::Sim;

const SIMS: usize = 12;
const ROUNDS: u8 = 40;
const POLL_TIMEOUT: Duration = Duration::from_millis(500);
const SERVICE: Duration = Duration::from_millis(3);

/// One run: the client's log of each reply as (virtual time, byte), or why it gave up. Every round
/// opens a fresh connection and poll, so the sims keep registering and closing IOCP handles while
/// others wait in theirs.
fn run(seed: u64) -> Result<Vec<(Duration, u8)>, String> {
    Sim::builder().deterministic().seed(seed).build().run(|| {
        let listener = TcpListener::bind("127.0.0.1:7100").unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..ROUNDS {
                let (mut conn, _) = listener.accept().unwrap();
                let mut byte = [0];
                conn.read_exact(&mut byte).unwrap();
                std::thread::sleep(SERVICE);
                conn.write_all(&byte).unwrap();
            }
        });

        let origin = Instant::now();
        let mut log = Vec::new();
        let outcome = (|| {
            for round in 0..ROUNDS {
                let mut stream = MioStream::from_std(TcpStream::connect("127.0.0.1:7100").unwrap());
                let mut poll = Poll::new().unwrap();
                poll.registry()
                    .register(&mut stream, Token(0), Interest::READABLE)
                    .unwrap();
                let mut events = Events::with_capacity(8);
                stream.write_all(&[round]).map_err(|e| e.to_string())?;
                let sent = Instant::now();
                let mut byte = [0];
                loop {
                    match stream.read(&mut byte) {
                        Ok(1) => break,
                        Ok(_) => return Err(format!("round {round}: closed")),
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                        Err(e) => return Err(format!("round {round}: {e}")),
                    }
                    poll.poll(&mut events, Some(POLL_TIMEOUT)).unwrap();
                    if events.is_empty() {
                        return Err(format!(
                            "round {round}: no readable event {:?} after the request",
                            sent.elapsed()
                        ));
                    }
                }
                log.push((origin.elapsed(), byte[0]));
            }
            Ok(())
        })();
        server.join().unwrap();
        outcome.map(|()| log)
    })
}

#[test]
fn concurrent_sims_lose_no_readable_wake_and_replay_alike() {
    let expected = run(7).expect("a sim on its own");
    let sims: Vec<_> = (0..SIMS).map(|_| std::thread::spawn(|| run(7))).collect();
    for (i, sim) in sims.into_iter().enumerate() {
        let trace = sim
            .join()
            .unwrap()
            .unwrap_or_else(|e| panic!("sim {i}: {e}"));
        assert_eq!(trace, expected, "sim {i} replays the lone run");
    }
}
