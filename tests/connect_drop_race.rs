//! Concurrent connect/accept/drop churn under `--cfg snare_global`, the mode a
//! simulated cell runs in: many unregistered threads sharing one network, each
//! standing up and tearing down TCP connections at the same time.
//!
//! Reproduces a panic seen ~1 in 5 whole-cell simulations, always while a
//! second connection was being established:
//!
//! ```text
//! thread 'material' panicked at snare/src/state.rs:937:
//! No connection found for stream id: 11
//! ```
//!
//! Run with:
//!
//! ```sh
//! RUSTFLAGS='--cfg snare_global' cargo test --features shim --test connect_drop_race
//! ```
#![cfg(all(snare_global, feature = "shim"))]

use snare::add_ip_addr;
use snare::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// Each worker connects, exchanges a byte, and drops — both ends racing to tear
/// down, which is what a driver reconnecting against a serving device does.
fn churn(addr: SocketAddr, rounds: usize, errors: &AtomicUsize) {
    for _ in 0..rounds {
        match TcpStream::connect(addr) {
            Ok(mut s) => {
                let _ = s.write_all(b"x");
                let mut buf = [0u8; 1];
                let _ = s.read(&mut buf);
                // dropped here, concurrently with the server's own drop
            }
            Err(_) => {
                errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[test]
fn concurrent_connect_and_drop_does_not_panic() {
    let ip: std::net::IpAddr = "9.9.9.10".parse().unwrap();
    add_ip_addr(ip);
    let addr = SocketAddr::new(ip, 41000);

    let listener = TcpListener::bind(addr).expect("bind");
    let accepted = Arc::new(AtomicUsize::new(0));

    // Server: accept and immediately drop, so teardown overlaps the next
    // client's connect — the window the panic lives in.
    let srv_accepted = Arc::clone(&accepted);
    let server = thread::spawn(move || {
        while srv_accepted.load(Ordering::Relaxed) < 200 {
            match listener.accept() {
                Ok((mut s, _)) => {
                    let mut buf = [0u8; 1];
                    let _ = s.read(&mut buf);
                    let _ = s.write_all(b"y");
                    srv_accepted.fetch_add(1, Ordering::Relaxed);
                    // drop
                }
                Err(_) => thread::sleep(Duration::from_millis(1)),
            }
        }
    });

    let errors = Arc::new(AtomicUsize::new(0));
    let clients: Vec<_> = (0..4)
        .map(|_| {
            let errors = Arc::clone(&errors);
            thread::spawn(move || churn(addr, 50, &errors))
        })
        .collect();

    for c in clients {
        c.join()
            .expect("a client thread panicked — the race reproduced");
    }
    server
        .join()
        .expect("the server thread panicked — the race reproduced");

    // Connect failures are acceptable (a real stack refuses too); a panic is
    // not, which is what the joins above assert.
    println!(
        "accepted={} connect_errors={}",
        accepted.load(Ordering::Relaxed),
        errors.load(Ordering::Relaxed)
    );
}
