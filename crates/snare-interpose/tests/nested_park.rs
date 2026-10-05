//! A layer runs on the thread whose wait made the domain quiescent, from inside that hooked wait:
//! when the wait is std's thread parker (`thread::park`, every channel and, on macOS, `Once`), the
//! thread is already parked on its own parker. A layer that blocks in std there parks that same
//! parker a second time — on a channel, or on a `OnceLock` another thread is still initialising,
//! whose waiters park with `thread::park` on macOS (library/std/src/sys/sync/once/queue.rs) — and
//! both the layer's wait and the outer park must still be woken.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::Duration;

use snare_interpose::{Domain, Layer};

/// A layer that makes one blocking wait from inside the first hooked wait that consults it.
struct WaitsOnce {
    wait: Box<dyn Fn() + Send + Sync>,
    waiting: AtomicBool,
    fired: AtomicBool,
}

impl WaitsOnce {
    fn wait_nested(&self) {
        if self.fired.swap(true, Ordering::SeqCst) {
            return;
        }
        self.waiting.store(true, Ordering::SeqCst);
        (self.wait)();
    }
}

impl Layer for WaitsOnce {
    fn try_time_skip(&self) -> bool {
        self.wait_nested();
        false
    }

    fn native_quiescence(&self, _domain: &Domain) {
        self.wait_nested();
    }
}

fn spin_until(flag: &AtomicBool) {
    while !flag.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_micros(200));
    }
}

/// Parks a participant of a domain until an unmanaged thread unparks it, with the layer's `wait`
/// nested in that park, ended by `release` once the layer has had time to block in it; panics if
/// either wait is never woken.
fn park_around(
    deterministic: bool,
    wait: impl Fn() + Send + Sync + 'static,
    release: impl FnOnce(),
) {
    let layer = Arc::new(WaitsOnce {
        wait: Box::new(wait),
        waiting: AtomicBool::new(false),
        fired: AtomicBool::new(false),
    });
    let builder = Domain::builder().layers([layer.clone() as Arc<dyn Layer>]);
    let domain = if deterministic {
        builder.deterministic().install()
    } else {
        builder.install()
    };

    let unparked = Arc::new(AtomicBool::new(false));
    let (parked_tx, parked_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    {
        let unparked = unparked.clone();
        thread::spawn(move || {
            domain.run(|| {
                parked_tx.send(thread::current()).unwrap();
                while !unparked.load(Ordering::SeqCst) {
                    thread::park();
                }
            });
            done_tx.send(()).unwrap();
        });
    }
    let participant = parked_rx.recv().unwrap();

    spin_until(&layer.waiting);
    // Long enough for the layer's thread to have blocked in its wait.
    thread::sleep(Duration::from_millis(50));
    release();

    unparked.store(true, Ordering::SeqCst);
    participant.unpark();
    assert!(
        done_rx.recv_timeout(Duration::from_secs(20)).is_ok(),
        "the participant's park, or the layer's wait nested in it, was never woken"
    );
}

/// The layer waits on a `OnceLock` an unmanaged thread is initialising.
fn contended_once(deterministic: bool) {
    #[derive(Default)]
    struct Contended {
        cell: OnceLock<u32>,
        initialising: AtomicBool,
        release: AtomicBool,
    }
    let contended = Arc::new(Contended::default());
    let initialiser = {
        let contended = contended.clone();
        thread::spawn(move || {
            contended.cell.get_or_init(|| {
                contended.initialising.store(true, Ordering::SeqCst);
                spin_until(&contended.release);
                7
            });
        })
    };
    spin_until(&contended.initialising);
    let waiter = contended.clone();
    park_around(
        deterministic,
        move || assert_eq!(*waiter.cell.get_or_init(|| unreachable!()), 7),
        || {
            contended.release.store(true, Ordering::SeqCst);
            initialiser.join().unwrap();
        },
    );
}

/// The layer receives on a channel an unmanaged thread sends on.
fn channel(deterministic: bool) {
    let (tx, rx) = mpsc::channel();
    let rx = Mutex::new(rx);
    park_around(
        deterministic,
        move || rx.lock().unwrap().recv().unwrap(),
        || tx.send(()).unwrap(),
    );
}

#[test]
fn a_layer_waiting_on_a_contended_once_inside_a_park_is_woken() {
    contended_once(false);
}

#[test]
fn a_layer_waiting_on_a_contended_once_inside_a_park_is_woken_under_deterministic() {
    contended_once(true);
}

#[test]
fn a_layer_receiving_on_a_channel_inside_a_park_is_woken() {
    channel(false);
}

#[test]
fn a_layer_receiving_on_a_channel_inside_a_park_is_woken_under_deterministic() {
    channel(true);
}

#[test]
fn a_layer_consuming_a_park_notification_without_an_os_wait_is_woken() {
    for deterministic in [false, true] {
        let notified = Arc::new(AtomicBool::new(false));
        let layer = Arc::new(WaitsOnce {
            wait: Box::new({
                let notified = notified.clone();
                move || {
                    while !notified.load(Ordering::Acquire) {
                        thread::yield_now();
                    }
                    thread::park();
                }
            }),
            waiting: AtomicBool::new(false),
            fired: AtomicBool::new(false),
        });
        let builder = Domain::builder().layers([layer.clone() as Arc<dyn Layer>]);
        let domain = if deterministic {
            builder.deterministic().install()
        } else {
            builder.install()
        };
        let (thread_tx, thread_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let participant = thread::spawn(move || {
            domain.run(|| {
                thread_tx.send(thread::current()).unwrap();
                thread::park();
            });
            done_tx.send(()).unwrap();
        });
        let parked = thread_rx.recv().unwrap();
        spin_until(&layer.waiting);
        parked.unpark();
        notified.store(true, Ordering::Release);
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        participant.join().unwrap();
    }
}
