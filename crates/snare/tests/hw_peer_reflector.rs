//! The second machine's half of the peer tests: a UDP echo on `SNARE_HW_REFLECT_PORT` (default
//! 47000) that answers every datagram from the port it arrived on, so the machine under test
//! gets its own traffic back through its real NIC (`hw_timestamping_truth`,
//! `hw_sockbuf_truth`). It runs only with `SNARE_HW_REFLECT=1` — `scripts/test-hardware.sh
//! --reflector` or `scripts/test-hardware.ps1 -Reflector` — and stops after
//! `SNARE_HW_REFLECT_SECS` (default 600) without traffic or on a `quit` datagram. It never runs
//! inside a sim.

#[path = "support/hw.rs"]
mod hw;

use std::net::UdpSocket;
use std::time::Duration;

use hw::require;

#[test]
#[ignore = "hardware: the reflector for SNARE_HW_PEER, run on the peer machine"]
fn hw_peer_reflector() {
    require!(
        std::env::var("SNARE_HW_REFLECT").is_ok_and(|v| v == "1"),
        "runs only on the peer machine (set SNARE_HW_REFLECT=1, or use the runner's reflector mode)"
    );
    let port: u16 = std::env::var("SNARE_HW_REFLECT_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(hw::DEFAULT_PEER_PORT);
    let idle: u64 = std::env::var("SNARE_HW_REFLECT_SECS")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(600);
    let v4 = UdpSocket::bind(("0.0.0.0", port)).expect("bind the IPv4 reflector port");
    if let Ok(v6) = UdpSocket::bind(("::", port)) {
        std::thread::spawn(move || hw::reflect(&v6, Duration::from_secs(idle)));
    }
    eprintln!("reflecting UDP on port {port}; idle limit {idle} s");
    let echoed = hw::reflect(&v4, Duration::from_secs(idle));
    eprintln!("reflected {echoed} IPv4 datagrams");
}
