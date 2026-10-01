use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// When a wait gives up: on the domain's discrete virtual clock when it runs on one — the clock
/// the code under test reads, which holds still until the sim moves it — and on the real clock
/// otherwise. Fixed when made, so a wait retried in a loop keeps its original deadline, and read
/// the same from the sim's own code (under passthrough) as from the code under test.
#[derive(Clone, Copy)]
pub(crate) struct Deadline {
    at: Duration,
    on_virtual: bool,
}

impl Deadline {
    /// `span` from now.
    pub(crate) fn after(span: Duration) -> Self {
        match snare_interpose::discrete_now() {
            Some(now) => Deadline {
                at: now.saturating_add(span),
                on_virtual: true,
            },
            None => Deadline {
                at: real_now().saturating_add(span),
                on_virtual: false,
            },
        }
    }

    fn now(&self) -> Duration {
        if self.on_virtual {
            snare_interpose::discrete_now().unwrap_or(Duration::MAX)
        } else {
            real_now()
        }
    }

    fn remaining(&self) -> Duration {
        self.at.saturating_sub(self.now())
    }

    /// Whether the deadline has been reached.
    pub(crate) fn passed(&self) -> bool {
        self.now() >= self.at
    }

    /// When the deadline falls, on its clock, for ordering deadlines made on the same clock.
    pub(crate) fn instant(&self) -> Duration {
        self.at
    }

    /// Arranges for waiters to re-check once the deadline passes: under a virtual clock it is a
    /// pending timer the sim can jump to; on the real clock a background waker bumps readiness
    /// then. Used for something that becomes ready at a set time — a datagram still in flight.
    pub(crate) fn wake_waiters_then(&self) {
        if self.on_virtual {
            // Left registered: the arrival is an event in its own right, consumed or not.
            let _ = snare_interpose::register_timer(self.remaining());
        } else {
            real_waker().schedule(self.at);
        }
    }
}

/// Bumps readiness at real-clock times on behalf of things that become ready on their own (a
/// datagram arriving after its link latency), for sims not on the virtual clock. One background
/// thread, started unmanaged on first use.
struct RealWaker {
    due: Mutex<std::collections::BinaryHeap<std::cmp::Reverse<Duration>>>,
    changed: Condvar,
}

fn real_waker() -> &'static RealWaker {
    static WAKER: OnceLock<RealWaker> = OnceLock::new();
    let mut started = false;
    let waker = WAKER.get_or_init(|| {
        started = true;
        RealWaker {
            due: Mutex::default(),
            changed: Condvar::new(),
        }
    });
    if started {
        // Spawned under passthrough, so the sim does not adopt it as a managed thread.
        snare_interpose::real(|| {
            std::thread::Builder::new()
                .name("snare-link-delay".into())
                .spawn(|| real_waker().run())
                .expect("start the link-delay waker")
        });
    }
    waker
}

impl RealWaker {
    fn schedule(&self, at: Duration) {
        snare_interpose::real(|| {
            self.due.lock().unwrap().push(std::cmp::Reverse(at));
            self.changed.notify_one();
        });
    }

    fn run(&self) {
        let mut due = self.due.lock().unwrap();
        loop {
            match due.peek().map(|r| r.0) {
                None => due = self.changed.wait(due).unwrap(),
                Some(at) => {
                    let now = real_now();
                    if now >= at {
                        due.pop();
                        drop(due);
                        readiness().bump();
                        due = self.due.lock().unwrap();
                    } else {
                        due = self.changed.wait_timeout(due, at - now).unwrap().0;
                    }
                }
            }
        }
    }
}

/// Real time since an arbitrary process-wide origin.
fn real_now() -> Duration {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    snare_interpose::real(|| ORIGIN.get_or_init(Instant::now).elapsed())
}

/// A process-global "some socket's readiness may have changed" signal, shared by every sim
/// backend (the unix fabric and `SimHost`, the Windows `WinNet`) and the discrete virtual clock.
/// Blocking receives, accepts, polls and virtual sleeps wait on it; every write, close, connect,
/// send and post bumps it. Coarse (one condvar for the whole process), which is fine at test scale.
pub(crate) struct Readiness {
    state: Mutex<State>,
    changed: Condvar,
}

/// Guarded by one lock so a quiescence check sees a consistent picture.
struct State {
    generation: u64,
    /// Threads currently asleep on `changed`.
    sleeping: usize,
    /// Sleepers woken by a bump that have not yet woken up and re-checked. A woken waiter still
    /// counts as parked until it runs, so while any is pending the domain only looks quiescent: a
    /// time skip then would race virtual time ahead of the work the woken thread is about to do.
    stale: usize,
}

impl State {
    fn bump(&mut self) {
        self.generation += 1;
        self.stale = self.sleeping;
    }
}

pub(crate) fn readiness() -> &'static Readiness {
    static READINESS: OnceLock<Readiness> = OnceLock::new();
    READINESS.get_or_init(|| Readiness {
        state: Mutex::new(State {
            generation: 0,
            sleeping: 0,
            stale: 0,
        }),
        changed: Condvar::new(),
    })
}

impl Readiness {
    pub(crate) fn bump(&self) {
        self.state.lock().unwrap().bump();
        self.changed.notify_all();
    }

    /// Whether a waiter has been woken but not yet run; see [`State::stale`].
    pub(crate) fn settling(&self) -> bool {
        self.state.lock().unwrap().stale > 0
    }

    /// Blocks until `ready()` holds or the deadline passes. Returns whether `ready()` held. The
    /// `ready` closure locks the backend's socket table; every waker (send/close/shutdown) releases
    /// that table before it bumps `Readiness`, so it is never held across a `state` acquisition
    /// and the two locks keep a consistent order.
    pub(crate) fn wait_until(&self, deadline: Option<Deadline>, ready: impl FnMut() -> bool) -> bool {
        // Under a virtual clock, a finite deadline must be a pending timer the quiescence time-skip
        // can jump to; otherwise a timeout nothing else can satisfy would read as a deadlock.
        // Register the remaining span and drop it again if the wait returns before it fires.
        let timer = deadline
            .filter(|d| d.on_virtual)
            .and_then(|d| snare_interpose::register_timer(d.remaining()));
        let result = self.wait_inner(deadline, ready);
        if let Some(key) = timer {
            snare_interpose::unregister_timer(key);
        }
        result
    }

    /// An indefinite (`None`) wait polls at `QUIESCENCE_POLL` so it can notice quiescence — every
    /// managed thread parked, none woken and still to run — and return `false` rather than block
    /// forever. A bump wakes it at once, so this only adds latency to a genuine deadlock.
    ///
    /// The thread counts as parked (per domain, so parallel tests don't see each other's threads)
    /// only once it has found `ready()` false, and stops counting before it lets go of the lock on
    /// its way out, so a peer checking quiescence under the same lock never sees it parked while
    /// it is running.
    fn wait_inner(&self, deadline: Option<Deadline>, mut ready: impl FnMut() -> bool) -> bool {
        const QUIESCENCE_POLL: Duration = Duration::from_millis(200);
        // How long to wait after a time-skip done on another thread's behalf before checking again;
        // a bump cuts it short. Skips that satisfy *this* thread don't wait at all.
        const SETTLE: Duration = Duration::from_millis(5);
        let mut state = self.state.lock().unwrap();
        if ready() {
            return true;
        }
        snare_interpose::mark_waiting(true);
        let leave = |result: bool| {
            snare_interpose::mark_waiting(false);
            result
        };
        let quiescent = |state: &State| {
            let live = snare_interpose::managed_live();
            state.stale == 0 && live > 0 && snare_interpose::managed_parked() >= live
        };
        loop {
            // A deadline already reached ends the wait before any time skip: a zero timeout is a
            // non-blocking check, not a request to move the clock.
            if deadline.is_some_and(|d| d.passed()) {
                return leave(ready());
            }
            // Quiescent with a pending virtual timer: jump time to it immediately rather than wait
            // out the poll. If the jump reached *our own* deadline we return at once (so a sleeper
            // fast-forwards its own sleeps); otherwise we settle to let the woken thread run.
            if quiescent(&state) && snare_interpose::time_skip() {
                state.bump();
                self.changed.notify_all();
                if ready() {
                    return leave(true);
                }
                // The skip may have reached our own deadline: return now rather than settle
                // while still counted as parked, which would let a peer skip time past us.
                if deadline.is_some_and(|d| d.passed()) {
                    return leave(false);
                }
                state = self.sleep(state, SETTLE).0;
                if ready() {
                    return leave(true);
                }
                continue;
            }
            let wait = deadline.map_or(QUIESCENCE_POLL, |d| d.remaining().min(QUIESCENCE_POLL));
            let before = state.generation;
            let (next, timed_out) = self.sleep(state, wait);
            state = next;
            if ready() {
                return leave(true);
            }
            if deadline.is_some_and(|d| d.passed()) {
                return leave(ready());
            }
            // Reached quiescence during the poll with no bump: time-skip if a timer is pending,
            // otherwise it is a genuine deadlock.
            if timed_out && state.generation == before && quiescent(&state) {
                if snare_interpose::time_skip() {
                    state.bump();
                    self.changed.notify_all();
                    continue;
                }
                return leave(false);
            }
        }
    }

    /// Sleeps on `changed` for at most `timeout`, keeping `sleeping`/`stale` accurate: a sleeper
    /// that a bump marked stale stops being stale once it is back holding the lock.
    fn sleep<'a>(
        &self,
        mut state: std::sync::MutexGuard<'a, State>,
        timeout: Duration,
    ) -> (std::sync::MutexGuard<'a, State>, bool) {
        let before = state.generation;
        state.sleeping += 1;
        let (mut state, result) = self.changed.wait_timeout(state, timeout).unwrap();
        state.sleeping -= 1;
        if state.generation != before {
            state.stale = state.stale.saturating_sub(1);
        }
        (state, result.timed_out())
    }
}
