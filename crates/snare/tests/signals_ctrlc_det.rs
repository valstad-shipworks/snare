//! `ctrlc` under the deterministic scheduler: the handler thread it leaves behind waits on its
//! semaphore forever. Once a run is over the schedule lets it go instead of polling it, and in a
//! later run it takes the baton again before running the handler.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use snare::{Signal, SignalDelivery, Sim};

fn wait_for(count: &AtomicUsize, n: usize) {
    for _ in 0..5000 {
        if count.load(Ordering::SeqCst) >= n {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!(
        "the handler ran {} times, not {n}",
        count.load(Ordering::SeqCst)
    );
}

#[test]
fn ctrlc_crate_deterministic() {
    let sim = Sim::builder().deterministic().build();
    let signals = sim.signals();
    let count = Arc::new(AtomicUsize::new(0));
    let handled = count.clone();
    sim.run(|| {
        ctrlc::set_handler(move || {
            handled.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
        assert_eq!(signals.raise(Signal::Interrupt), SignalDelivery::Handled);
        wait_for(&count, 1);
    });
    sim.run(|| {
        assert_eq!(signals.raise(Signal::Interrupt), SignalDelivery::Handled);
        let until = snare::real(Instant::now) + Duration::from_millis(300);
        while snare::real(Instant::now) < until {
            assert_eq!(
                count.load(Ordering::SeqCst),
                1,
                "the handler ran beside the thread holding the baton"
            );
            std::hint::spin_loop();
        }
        wait_for(&count, 2);
    });
    #[cfg(unix)]
    {
        let report = snare::real(|| stderr_during(Duration::from_millis(1500)));
        assert!(!report.contains("no progress"), "{report}");
    }
    assert_eq!(
        sim.raise_signal(Signal::Interrupt),
        SignalDelivery::Handled,
        "after the runs"
    );
    snare::real(|| {
        let until = Instant::now() + Duration::from_secs(5);
        while count.load(Ordering::SeqCst) < 3 {
            assert!(
                Instant::now() < until,
                "the handler never ran after the runs"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    });
}

/// What the process writes to stderr for `span`.
#[cfg(unix)]
fn stderr_during(span: Duration) -> String {
    let mut fds = [0; 2];
    // SAFETY: swaps fd 2 for a pipe's write end and back, reading what arrived meanwhile.
    unsafe {
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        let saved = libc::dup(2);
        libc::dup2(fds[1], 2);
        std::thread::sleep(span);
        libc::dup2(saved, 2);
        libc::close(saved);
        libc::close(fds[1]);
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len());
            if n <= 0 {
                break;
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        libc::close(fds[0]);
        String::from_utf8_lossy(&out).into_owned()
    }
}
