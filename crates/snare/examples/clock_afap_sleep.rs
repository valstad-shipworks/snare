//! As-fast-as-possible sleeping: a program paces itself with `std::thread::sleep`, but inside a
//! `Sim` the clock layer carries each sleep virtually and the wall clock barely moves. man 2
//! nanosleep describes the relative sleep std issues; here it returns instantly while virtual
//! monotonic time still advances by the slept amount.
//!
//! Run with: cargo run -p snare --example clock_afap_sleep

#[cfg(unix)]
fn main() {
    use std::time::{Duration, Instant};

    use snare::{HostProfile, Sim};

    // Real monotonic time, captured outside the sim where std reaches the OS.
    let wall_start = Instant::now();

    let host = HostProfile::new().build();
    let sim = Sim::builder().host(host).build();
    let virtual_elapsed = sim.run(|| {
        let start = Instant::now();
        for _ in 0..24 {
            std::thread::sleep(Duration::from_secs(3600));
        }
        start.elapsed()
    });

    let wall_elapsed = wall_start.elapsed();
    println!(
        "virtual time advanced {}h while only {}ms of wall time passed",
        virtual_elapsed.as_secs() / 3600,
        wall_elapsed.as_millis()
    );
}

#[cfg(not(unix))]
fn main() {}
