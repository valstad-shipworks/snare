use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use snare_interpose::{ClockKind, Flow, Layer, SleepRequest};

/// A deterministic virtual clock shared by every [`Sim`](crate::Sim) — on its own in a plain sim,
/// or driving a [`SimHost`](crate::SimHost)'s timestamps as well. Each clock read advances virtual
/// time by 1µs, so time progresses (loops that poll it terminate) yet every run produces identical
/// timestamps. The clock can be paused: while paused, reads return the frozen time and sleeps
/// return without advancing, so a test can hold time still and step it forward explicitly with
/// [`advance_by`](Clock::advance_by).
pub(crate) struct Clock {
    monotonic_nanos: AtomicU64,
    base_realtime_nanos: u64,
    tai_offset_nanos: u64,
    paused: AtomicBool,
    /// Discrete-event mode: reads do not auto-tick and sleeps do not advance immediately. Instead
    /// a sleep registers its wake deadline and blocks; virtual time jumps forward to the earliest
    /// deadline only when the whole sim is quiescent (see [`try_advance`]). Off = the as-fast-as-
    /// possible mode a `SimHost` uses.
    discrete: bool,
    /// Pending sleep/timeout wake deadlines (monotonic nanos → how many waits want that instant),
    /// for the quiescence time-skip. Refcounted so a timed socket wait that returns early can drop
    /// its deadline without disturbing another wait that happens to share the same instant.
    pending: Mutex<BTreeMap<u64, u64>>,
}

impl Clock {
    pub(crate) fn new(tai_offset_secs: u64) -> Self {
        Self::build(tai_offset_secs, false)
    }

    /// A discrete-event clock: deterministic time that never advances on plain reads, only by the
    /// quiescence time-skip to a pending sleep/timeout or by the latency charged to calls that
    /// return without blocking. A plain `Sim`'s default.
    pub(crate) fn new_discrete(tai_offset_secs: u64) -> Self {
        Self::build(tai_offset_secs, true)
    }

    fn build(tai_offset_secs: u64, discrete: bool) -> Self {
        Clock {
            monotonic_nanos: AtomicU64::new(0),
            // A fixed epoch (2023-11-14T00:00:00Z) keeps `Realtime` deterministic and plausible.
            base_realtime_nanos: 1_700_000_000u64 * 1_000_000_000,
            tai_offset_nanos: tai_offset_secs * 1_000_000_000,
            paused: AtomicBool::new(false),
            discrete,
            pending: Mutex::new(BTreeMap::new()),
        }
    }

    fn advance(&self) -> u64 {
        // A discrete clock never auto-ticks on reads; time moves only via the scheduler.
        if self.discrete || self.paused.load(Ordering::Relaxed) {
            return self.monotonic_nanos.load(Ordering::Relaxed);
        }
        self.monotonic_nanos.fetch_add(1_000, Ordering::Relaxed) + 1_000
    }

    pub(crate) fn now(&self, kind: ClockKind) -> Duration {
        let m = self.advance();
        // man 2 clock_gettime: CLOCK_TAI = CLOCK_REALTIME plus the kernel's TAI-UTC offset (the
        // offset is maintained through adjtimex ADJ_TAI; see man 2 adjtimex).
        let nanos = match kind {
            ClockKind::Monotonic => m,
            ClockKind::Realtime => self.base_realtime_nanos + m,
            ClockKind::Tai => self.base_realtime_nanos + m + self.tai_offset_nanos,
        };
        Duration::from_nanos(nanos)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn tick_realtime(&self) -> Duration {
        Duration::from_nanos(self.base_realtime_nanos + self.advance())
    }

    /// One PTP cross-timestamp sample taken at a single virtual instant: the PHC (`device`) time,
    /// `CLOCK_REALTIME` and `CLOCK_MONOTONIC_RAW`, each as `(seconds, nanoseconds)`. The PHC leads
    /// realtime by `phc_offset_nanos`. All three come from one clock tick, so a consumer reads a
    /// consistent, deterministic offset.
    #[cfg(target_os = "linux")]
    pub(crate) fn ptp_sample(&self, phc_offset_nanos: i64) -> [(i64, u32); 3] {
        let m = self.advance();
        let realtime = self.base_realtime_nanos + m;
        let device = realtime.saturating_add_signed(phc_offset_nanos);
        let split = |nanos: u64| ((nanos / 1_000_000_000) as i64, (nanos % 1_000_000_000) as u32);
        [split(device), split(realtime), split(m)]
    }

    /// Carry out a sleep by advancing virtual time instead of blocking — the run executes
    /// as-fast-as-possible while the clock still moves forward by the requested amount. While
    /// paused the clock holds still, so the sleep returns at once without advancing.
    pub(crate) fn sleep(&self, request: SleepRequest) {
        if self.paused.load(Ordering::Relaxed) {
            return;
        }
        let nanos = |d: Duration| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        let wake = match request {
            SleepRequest::For(d) => self.monotonic_nanos.load(Ordering::Relaxed) + nanos(d),
            SleepRequest::Until(kind, t) => {
                let origin = match kind {
                    ClockKind::Monotonic => 0,
                    ClockKind::Realtime => self.base_realtime_nanos,
                    ClockKind::Tai => self.base_realtime_nanos + self.tai_offset_nanos,
                };
                nanos(t).saturating_sub(origin)
            }
        };
        if !self.discrete {
            // As-fast-as-possible: jump the clock forward and return at once.
            self.monotonic_nanos.fetch_max(wake, Ordering::Relaxed);
            return;
        }
        // Discrete: register the deadline and block until the quiescence time-skip reaches it, so
        // other threads make their progress at this instant before virtual time moves on.
        if self.monotonic_nanos.load(Ordering::Relaxed) >= wake {
            return;
        }
        *self.pending.lock().unwrap().entry(wake).or_insert(0) += 1;
        crate::readiness::readiness()
            .wait_until(None, || self.monotonic_nanos.load(Ordering::Relaxed) >= wake);
    }

    /// Registers a timed wait of `after` from now as a pending deadline, returning its absolute
    /// monotonic-nanos key (for [`unregister_timer`](Clock::unregister_timer)). A no-op returning
    /// `None` on a non-discrete clock, where sleeps and timeouts advance time directly.
    pub(crate) fn register_timer(&self, after: Duration) -> Option<u64> {
        if !self.discrete {
            return None;
        }
        let nanos = u64::try_from(after.as_nanos()).unwrap_or(u64::MAX);
        let wake = self.monotonic_nanos.load(Ordering::Relaxed).saturating_add(nanos);
        *self.pending.lock().unwrap().entry(wake).or_insert(0) += 1;
        Some(wake)
    }

    /// Advances a discrete clock by `latency` (see `Layer::charge_latency`), reporting whether it
    /// reached a pending deadline.
    fn charge(&self, latency: Duration) -> bool {
        if !self.discrete || self.paused.load(Ordering::Relaxed) {
            return false;
        }
        let nanos = u64::try_from(latency.as_nanos()).unwrap_or(u64::MAX);
        let before = self.monotonic_nanos.fetch_add(nanos, Ordering::Relaxed);
        let after = before.saturating_add(nanos);
        self.pending
            .lock()
            .unwrap()
            .range(before.saturating_add(1)..=after)
            .next()
            .is_some()
    }

    /// Drops one reference to a pending deadline from [`register_timer`](Clock::register_timer).
    pub(crate) fn unregister_timer(&self, wake: u64) {
        let mut pending = self.pending.lock().unwrap();
        if let Some(count) = pending.get_mut(&wake) {
            *count -= 1;
            if *count == 0 {
                pending.remove(&wake);
            }
        }
    }

    /// Stops automatic advance: reads return the current time and sleeps no longer move it.
    pub(crate) fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }

    /// Resumes automatic advance (the default).
    pub(crate) fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
    }

    /// Moves virtual time forward by `d`, whether or not the clock is paused.
    pub(crate) fn advance_by(&self, d: Duration) {
        let nanos = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        self.monotonic_nanos.fetch_add(nanos, Ordering::Relaxed);
    }

    /// The quiescence time-skip: jump to the earliest pending sleep/timeout deadline still in the
    /// future. `true` if time moved (a blocked sleeper can now wake), `false` if nothing is pending.
    fn advance_to_next_deadline(&self) -> bool {
        if !self.discrete {
            return false;
        }
        let now = self.monotonic_nanos.load(Ordering::Relaxed);
        let mut pending = self.pending.lock().unwrap();
        // Drop deadlines already reached (their waits have woken), then jump to the earliest still
        // in the future so the thread waiting on it can run.
        pending.retain(|&wake, _| wake > now);
        let Some((&next, _)) = pending.iter().next() else {
            return false;
        };
        // Land just past the deadline, as a real timer fires: discrete time never ticks on its
        // own, so landing exactly on it would leave `elapsed == timeout` and a caller's
        // "re-wait while elapsed < timeout" loop (std's `Condvar::wait_timeout_while`) re-waiting
        // with a zero timeout forever.
        self.monotonic_nanos.store(next + 1, Ordering::Relaxed);
        true
    }
}

pub(crate) struct ClockLayer(pub(crate) Arc<Clock>);

impl Layer for ClockLayer {
    fn now(&self, clock: ClockKind) -> Flow<Duration> {
        Flow::Done(self.0.now(clock))
    }

    fn sleep(&self, request: SleepRequest) -> Flow<()> {
        self.0.sleep(request);
        Flow::Done(())
    }

    fn try_time_skip(&self) -> bool {
        self.0.advance_to_next_deadline()
    }

    fn register_timer(&self, after: Duration) -> Option<u64> {
        self.0.register_timer(after)
    }

    fn unregister_timer(&self, key: u64) {
        self.0.unregister_timer(key);
    }

    fn charge_latency(&self, latency: Duration) -> bool {
        self.0.charge(latency)
    }

    fn discrete_now(&self) -> Option<Duration> {
        self.0
            .discrete
            .then(|| Duration::from_nanos(self.0.monotonic_nanos.load(Ordering::Relaxed)))
    }

    fn wake_waiters(&self) {
        crate::readiness::readiness().bump();
    }

    fn settling(&self) -> bool {
        crate::readiness::readiness().settling()
    }
}
