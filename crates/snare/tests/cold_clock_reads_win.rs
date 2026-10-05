#![cfg(windows)]

use std::sync::{Arc, Barrier};
use std::time::Instant;

use snare::Sim;

#[test]
fn concurrent_first_clock_reads_preserve_each_spins_count() {
    let ready = Arc::new(Barrier::new(8));
    let mut now = 0_u64;
    let expected: Arc<Vec<_>> = Arc::new(
        (1..=3_000)
            .map(|read| {
                if read >= 64 {
                    now += (now / 64).clamp(1_000, 1_000_000_000);
                }
                now
            })
            .collect(),
    );
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let ready = ready.clone();
            let expected = expected.clone();
            std::thread::spawn(move || {
                let sim = Sim::new();
                ready.wait();
                sim.run(|| {
                    for (read, &expected) in expected.iter().enumerate() {
                        std::hint::black_box(Instant::now());
                        let seen = snare::sched::now().as_nanos() as u64;
                        assert_eq!(seen, expected, "clock read {}", read + 1);
                    }
                });
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
}
