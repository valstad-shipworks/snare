//! The real `ctrlc` crate, unchanged, inside a sim: its handler is installed in the sim's table and
//! a raised Ctrl-C reaches it through the semaphore its thread waits on. One installer per process,
//! so this binary holds this test alone.

use std::sync::mpsc;
use std::time::Duration;

use snare::{Signal, SignalDelivery, Sim};

#[cfg(unix)]
fn real_sigint() -> libc::sighandler_t {
    // SAFETY: a query only fills `old`.
    snare::real(|| unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGINT, std::ptr::null(), &mut old);
        old.sa_sigaction
    })
}

#[test]
fn ctrlc_crate() {
    #[cfg(unix)]
    let before = real_sigint();
    let sim = Sim::new();
    let signals = sim.signals();
    sim.run(|| {
        let (tx, rx) = mpsc::channel();
        ctrlc::set_handler(move || tx.send(()).unwrap()).unwrap();
        assert_eq!(signals.raise(Signal::Interrupt), SignalDelivery::Handled);
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(signals.raise(Signal::Interrupt), SignalDelivery::Handled);
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
    });
    #[cfg(unix)]
    assert_eq!(
        real_sigint(),
        before,
        "the process's own SIGINT is untouched"
    );
}
