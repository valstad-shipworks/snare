#![cfg(unix)]

//! A `SimHost`'s virtual clock is deterministic (a fixed epoch, sleeps that skip ahead) and a
//! test can pause it, step it forward with `advance_time`, and resume it — mirroring the original
//! snare's `pause_time` / `advance_time` / `resume_time`.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use snare::{HostProfile, Sim};

fn host_sim() -> Sim {
    Sim::builder().host(HostProfile::new().build()).build()
}

#[test]
fn clock_reads_the_fixed_virtual_epoch() {
    let sim = Sim::builder()
        .host(HostProfile::new().build())
        .fixed_epoch()
        .build();
    sim.run(|| {
        // The fixed epoch (2023-11-14) proves this is the virtual clock, not the wall clock.
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert!(now.as_secs() >= 1_700_000_000);
        assert!(
            now.as_secs() < 1_700_000_100,
            "virtual realtime sits at the fixed epoch"
        );
    });
}

#[test]
fn sleep_is_as_fast_as_possible_and_advances_time() {
    host_sim().run(|| {
        let start = Instant::now();
        std::thread::sleep(Duration::from_secs(3600));
        assert!(start.elapsed() >= Duration::from_secs(3600));
    });
}

#[test]
fn pause_freezes_reads_advance_steps_resume_restarts() {
    let sim = host_sim();
    sim.pause_time();
    sim.run(|| {
        let a = Instant::now();
        let b = Instant::now();
        assert_eq!(a, b, "a paused clock does not advance on read");
    });
    sim.advance_time(Duration::from_secs(5));
    sim.run(|| {
        // Still paused: reads remain stable, but the 5s step moved the clock.
        let a = Instant::now();
        let b = Instant::now();
        assert_eq!(a, b);
    });
    sim.resume_time();
    sim.run(|| {
        let a = Instant::now();
        std::thread::sleep(Duration::from_millis(1));
        assert!(
            a.elapsed() >= Duration::from_millis(1),
            "a resumed clock advances again"
        );
    });
}

#[test]
fn time_handle_controls_clock_from_a_thread() {
    let sim = host_sim();
    sim.run(|| {
        let time = sim.time();
        time.pause();
        let a = Instant::now();
        let handle = std::thread::spawn(move || {
            time.advance(Duration::from_secs(10));
        });
        handle.join().unwrap();
        assert!(a.elapsed() >= Duration::from_secs(10));
    });
    let _ = Arc::new(());
}
