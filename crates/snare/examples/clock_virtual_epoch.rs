//! The virtual realtime clock sits at a fixed epoch (2023-11-14T00:00:00Z) so every run sees the
//! same wall-clock date. `std::time::SystemTime` reads it through the interposed
//! `clock_gettime(CLOCK_REALTIME)` / `gettimeofday` (man 2 clock_gettime).
//!
//! Run with: cargo run -p snare --example clock_virtual_epoch

#[cfg(unix)]
fn main() {
    use std::time::{SystemTime, UNIX_EPOCH};

    use snare::{HostProfile, Sim};

    let host = HostProfile::new().build();
    let sim = Sim::builder().host(host).build();
    sim.run(|| {
        let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        println!(
            "virtual realtime is {}s past the Unix epoch",
            since_epoch.as_secs()
        );
    });
}

#[cfg(not(unix))]
fn main() {}
