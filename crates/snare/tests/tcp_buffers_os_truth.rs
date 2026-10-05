//! TCP buffer limits against the machine the tests run on: how much a nonblocking writer gets
//! into a loopback stream whose reader never reads, with both buffers set, and whether a large
//! nonblocking write is taken whole, real and simulated side by side.

#[path = "support/netfault.rs"]
mod netfault;

use std::io::{ErrorKind, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use snare::Sim;

/// A loopback stream whose listener asked for `rcv` and client for `snd`, the server end kept
/// alive and never read.
fn pair(snd: i32, rcv: i32) -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    netfault::set_buf(netfault::raw(&listener), true, rcv);
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    netfault::set_buf(netfault::raw(&client), false, snd);
    let (server, _) = listener.accept().unwrap();
    client.set_nonblocking(true).unwrap();
    (client, server)
}

/// What a writer of 1024-byte pieces gets in before `WouldBlock`, retried after a pause until a
/// round adds nothing, since a real stack moves bytes on asynchronously.
fn fill(snd: i32, rcv: i32) -> usize {
    let (mut client, _server) = pair(snd, rcv);
    let data = [5u8; 1024];
    let mut total = 0;
    for _ in 0..6 {
        let before = total;
        loop {
            match client.write(&data) {
                Ok(n) => total += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => panic!("{e}"),
            }
        }
        if total == before && before > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    total
}

/// The first nonblocking write of 100000 bytes into a stream with 16 KiB buffers.
fn big_write() -> usize {
    let (mut client, _server) = pair(16384, 16384);
    client.write(&vec![1u8; 100_000]).unwrap()
}

const CASES: [(i32, i32); 4] = [(4096, 4096), (16384, 16384), (65536, 16384), (16384, 65536)];

/// Linux within 40%, Windows within 5%. On macOS both only have to back-pressure: its loopback
/// totals vary between runs for the same buffers (measured 36864 to 403456 bytes with 16 KiB to
/// send and 64 KiB to receive).
#[test]
fn unread_stream_fill_matches_real_os() {
    for (snd, rcv) in CASES {
        let real = fill(snd, rcv);
        let sim = Sim::new().run(move || fill(snd, rcv));
        if cfg!(target_os = "linux") {
            let off = real.abs_diff(sim) as f64 / sim as f64;
            assert!(off <= 0.4, "snd {snd} rcv {rcv}: real {real}, sim {sim}");
        } else if cfg!(windows) {
            let off = real.abs_diff(sim) as f64 / sim as f64;
            assert!(off <= 0.05, "snd {snd} rcv {rcv}: real {real}, sim {sim}");
        } else {
            assert!(
                real > 0 && sim > 0,
                "snd {snd} rcv {rcv}: real {real}, sim {sim}"
            );
        }
    }
}

#[test]
fn large_nonblocking_write_matches_real_os() {
    let real = big_write();
    let sim = Sim::new().run(big_write);
    assert_eq!(real == 100_000, sim == 100_000, "real {real}, sim {sim}");
}
