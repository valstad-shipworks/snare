//! A minimal strict executive for tests of code that runs under a driver.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant as WallInstant};

use parking_lot::{Condvar, Mutex};

use super::{AttachError, Driver, DriverConfig, PState, attach_driver};

/// Configuration for [`StrictClock::start`].
#[derive(Clone, Debug)]
pub struct StrictConfig {
    pub seed: u64,
    /// Wall time the domain may stay busy, with a running participant that
    /// holds no lease, before the clock thread panics.
    pub stuck_after: Duration,
}

impl Default for StrictConfig {
    fn default() -> Self {
        Self {
            seed: 0,
            stuck_after: Duration::from_secs(10),
        }
    }
}

#[derive(Default)]
struct Signal {
    seq: Mutex<u64>,
    cv: Condvar,
}

impl Signal {
    fn kick(&self) {
        *self.seq.lock() += 1;
        self.cv.notify_all();
    }
}

/// An accounting driver on the calling thread's state slot plus a thread
/// that moves virtual time only when the domain is quiescent: it jumps to
/// the next timer deadline and otherwise waits for activity. It never lets
/// time flow. The calling thread is marked background, so a test main that
/// sleeps, joins or polls never holds up quiescence. That also means time
/// can move between two of its spawns: hold a
/// [`setup_scope`](super::setup_scope) while starting participants that must
/// all begin at the same instant.
pub struct StrictClock {
    driver: Arc<Driver>,
    stop: Arc<AtomicBool>,
    signal: Arc<Signal>,
    thread: Option<JoinHandle<()>>,
}

impl StrictClock {
    pub fn start(cfg: StrictConfig) -> Result<StrictClock, AttachError> {
        let driver = Arc::new(attach_driver(DriverConfig {
            seed: cfg.seed,
            accounting: true,
            audit: false,
        })?);
        super::mark_background("strict-clock-main");
        let stop = Arc::new(AtomicBool::new(false));
        let signal = Arc::new(Signal::default());
        let parent = std::thread::current().id();
        let thread = {
            let driver = Arc::clone(&driver);
            let stop = Arc::clone(&stop);
            let signal = Arc::clone(&signal);
            std::thread::Builder::new()
                .name("snare-strict-clock".into())
                .spawn(move || {
                    crate::register_thread_child_of(parent);
                    super::mark_driver_thread();
                    run(&driver, &stop, &signal, cfg.stuck_after);
                })
                .expect("failed to spawn snare-strict-clock")
        };
        Ok(StrictClock {
            driver,
            stop,
            signal,
            thread: Some(thread),
        })
    }

    /// Current virtual time.
    pub fn now(&self) -> Duration {
        self.driver.now()
    }

    pub fn driver(&self) -> &Driver {
        &self.driver
    }
}

fn run(driver: &Driver, stop: &AtomicBool, signal: &Arc<Signal>, stuck_after: Duration) {
    let mut busy_since: Option<WallInstant> = None;
    while !stop.load(Ordering::Acquire) {
        let seen = *signal.seq.lock();
        let q = driver.quiescence();
        if q.quiescent {
            busy_since = None;
            if let Some(d) = q.next_deadline {
                let _ = driver.jump_to(d);
                continue;
            }
        } else {
            let since = *busy_since.get_or_insert_with(WallInstant::now);
            if since.elapsed() >= stuck_after {
                let parts = driver.participants();
                let stuck = parts
                    .iter()
                    .any(|p| p.state == PState::Running && p.leases.is_empty());
                if stuck {
                    panic!(
                        "snare StrictClock: domain not quiescent for {:?} at virtual {:?} ({:?}); participants: {parts:#?}",
                        since.elapsed(),
                        driver.now(),
                        q.blocker,
                    );
                }
            }
        }
        let s = Arc::clone(signal);
        driver.arm_notify(q.epoch, Arc::new(move || s.kick()));
        let mut seq = signal.seq.lock();
        if *seq == seen && !stop.load(Ordering::Acquire) {
            let limit = if q.quiescent {
                stuck_after
            } else {
                stuck_after.min(Duration::from_millis(250))
            };
            signal.cv.wait_for(&mut seq, limit);
        }
    }
}

impl Drop for StrictClock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.signal.kick();
        if let Some(t) = self.thread.take()
            && let Err(e) = t.join()
            && !std::thread::panicking()
        {
            std::panic::resume_unwind(e);
        }
    }
}

impl std::fmt::Debug for StrictClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StrictClock")
            .field("now", &self.now())
            .finish_non_exhaustive()
    }
}
