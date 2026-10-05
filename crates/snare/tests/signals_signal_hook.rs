//! The real `signal-hook` iterator inside a sim: its registry installs through the sim's
//! `sigaction`, its self-pipe is a simulated socketpair, and a raised signal comes out of the
//! iterator. One installer per process, so this binary holds this test alone.
#![cfg(unix)]

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use snare::{Signal, SignalDelivery, Sim};

#[test]
fn signal_hook_iterator() {
    let sim = Sim::new();
    let handle = sim.signals();
    sim.run(|| {
        let mut signals = Signals::new([SIGINT, SIGTERM]).unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for sig in signals.forever() {
                tx.send(sig).unwrap();
            }
        });
        assert_eq!(handle.raise(Signal::Terminate), SignalDelivery::Handled);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), SIGTERM);
        assert_eq!(handle.raise(Signal::Interrupt), SignalDelivery::Handled);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), SIGINT);
    });
}
