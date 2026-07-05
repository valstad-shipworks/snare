//! Exercises `--cfg snare_global`: one process-wide state slot shared by every
//! thread, with no `register_test` / child-thread registration. Empty unless
//! the cfg is set, so the normal `cargo test` run — which relies on per-test
//! isolation — skips it. Run with:
//!
//! ```sh
//! RUSTFLAGS='--cfg snare_global' cargo test --features shim,mio-compat --test global_shared
//! ```
#![cfg(all(snare_global, feature = "shim"))]

use snare::time::Instant;
use snare::{UdpSocket, add_ip_addr, advance_time, pause_time, set_time_value, time_value};
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

#[test]
fn unregistered_threads_share_one_network() {
    // No register_test(). The main thread seeds a non-default valid IP into the
    // shared valid-IP set.
    let ip = "9.9.9.9".parse().unwrap();
    add_ip_addr(ip);

    // A plain std::thread with no child registration must still resolve to the
    // same shared slot: it sees the seeded IP and binds without tripping the
    // "Not a valid test thread" panic that isolated mode raises here.
    let handle = thread::spawn(move || {
        UdpSocket::bind(SocketAddr::new(ip, 5000)).expect("bind must see shared valid-IP set");
    });
    handle.join().unwrap();
}

#[test]
fn unregistered_threads_share_one_clock() {
    // No register_test(). The virtual clock lives in the same shared slot, so a
    // plain std::thread sees the paused clock the main thread configured.
    pause_time();
    set_time_value(Duration::from_secs(1_000));

    let handle = thread::spawn(|| {
        let seen = time_value();
        advance_time(Duration::from_secs(1));
        (seen, Instant::now())
    });
    let (seen, _) = handle.join().unwrap();
    assert_eq!(seen, Duration::from_secs(1_000));
    assert_eq!(time_value(), Duration::from_secs(1_001));
}
