//! How the sim's threads block: the [`Readiness`] board every simulated blocking call waits on,
//! source-filtered wake channels behind one process-wide lock, the [`Deadline`]s those waits give
//! up at, and the `snare-link-delay` thread ([`RealWaker`]) that wakes things due at a real-time
//! instant.
//!
//! A wait here is also where a sim notices quiescence: a participant that finds every other
//! participant parked asks the domain to skip virtual time to the next timer, and with no timer
//! left the wait gives up (a deadlock reads as a timeout, not a hang).
//!
//! Socket and descriptor changes name stable open descriptions. Clock changes reach waits with
//! deadlines or delayed arrivals; global changes reach every wait in the domain. Backends without
//! source identities use broad subscriptions. Domain keys keep independent sims' wakeups and
//! settling state separate; key 0 reaches matching subscriptions in every domain.
//!
//! Lock order: a backend's socket table, then `Readiness::state` — a `ready` closure takes the
//! table under `state`, so nothing may bump readiness while holding the table. The real waker's
//! `due` lock is a leaf: no waker or bump runs under it.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::Waker;
use std::time::{Duration, Instant};

use snare_interpose::RaceCell;

/// When a wait gives up: on the domain's virtual clock when it runs on one — the clock the code
/// under test reads, which moves only as the sim moves it (discrete, scaled or paused) — and on
/// the real clock otherwise. Fixed when made, so a wait retried in a loop keeps its original
/// deadline, and read the same from the sim's own code (under passthrough) as from the code under
/// test.
#[derive(Clone, Copy)]
pub(crate) struct Deadline {
    /// When, on the clock `on_virtual` names: virtual monotonic time, or [`real_now`] time.
    at: Duration,
    /// Whether `at` is on the domain's virtual clock rather than real time.
    on_virtual: bool,
}

impl Deadline {
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn at(&self) -> Duration {
        self.at
    }

    /// `span` from now, for something the simulation makes happen then: on the domain's clock
    /// whichever thread asks.
    pub(crate) fn after(span: Duration) -> Self {
        match snare_interpose::virtual_now() {
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

    /// `span` from now, for how long the calling thread waits: as [`after`](Deadline::after),
    /// except that a driver thread, whose clock is real, waits in real time.
    pub(crate) fn timeout(span: Duration) -> Self {
        if real_clock_thread() {
            return Deadline {
                at: real_now().saturating_add(span),
                on_virtual: false,
            };
        }
        Self::after(span)
    }

    /// `span` from now on `clock`, from any thread: virtual while the clock does not run as fast
    /// as possible, real otherwise and with no clock.
    pub(crate) fn on_clock(clock: Option<&crate::clock::Clock>, span: Duration) -> Self {
        match clock.and_then(crate::clock::Clock::virtual_now) {
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

    /// `span` after this deadline, on the same clock.
    pub(crate) fn later(&self, span: Duration) -> Self {
        Deadline {
            at: self.at.saturating_add(span),
            on_virtual: self.on_virtual,
        }
    }

    /// As [`wake_waiters_then`](Self::wake_waiters_then), returning the virtual timer's key for
    /// `snare_interpose::unregister_event_timer` should the event be called off.
    pub(crate) fn arm(&self) -> Option<u64> {
        let domain = snare_interpose::domain_key();
        if self.on_virtual {
            let remaining = self.remaining();
            if let Some(real) = snare_interpose::real_span(remaining) {
                real_waker().schedule(real_now().saturating_add(real), domain);
            }
            snare_interpose::register_event_timer(remaining)
        } else {
            real_waker().schedule(self.at, domain);
            None
        }
    }

    /// The current time on the deadline's clock. A virtual deadline whose clock has since started
    /// running as fast as possible (no virtual reading) counts as passed.
    fn now(&self) -> Duration {
        if self.on_virtual {
            snare_interpose::virtual_now().unwrap_or(Duration::MAX)
        } else {
            real_now()
        }
    }

    /// How long until the deadline on its own clock; zero once it has passed.
    pub(crate) fn remaining(&self) -> Duration {
        self.at.saturating_sub(self.now())
    }

    /// How long the deadline is away in real time: a virtual deadline is only that close while its
    /// clock runs scaled; otherwise it is reached by a time skip or a clock writer, which wake the
    /// waiter, so a poll interval stands in.
    fn real_remaining(&self) -> Duration {
        if self.on_virtual {
            snare_interpose::real_span(self.remaining()).unwrap_or(QUIESCENCE_POLL)
        } else {
            self.remaining()
        }
    }

    /// Whether the deadline has been reached.
    pub(crate) fn passed(&self) -> bool {
        self.now() >= self.at
    }

    /// How long ago the deadline fell; zero while it is still ahead.
    pub(crate) fn overdue(&self) -> Duration {
        self.now().saturating_sub(self.at)
    }

    #[cfg(target_os = "macos")]
    fn now_on(&self, clock: Option<&crate::clock::Clock>) -> Duration {
        if self.on_virtual {
            clock
                .and_then(crate::clock::Clock::virtual_now)
                .unwrap_or(Duration::MAX)
        } else {
            real_now()
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn passed_on(&self, clock: Option<&crate::clock::Clock>) -> bool {
        self.now_on(clock) >= self.at
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn remaining_on(&self, clock: Option<&crate::clock::Clock>) -> Duration {
        self.at.saturating_sub(self.now_on(clock))
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn timeline_at(&self, real_origin: Duration) -> Duration {
        if self.on_virtual {
            self.at
        } else {
            self.at.saturating_sub(real_origin)
        }
    }

    /// When the deadline falls, on its clock, for ordering deadlines made on the same clock.
    pub(crate) fn instant(&self) -> Duration {
        self.at
    }

    /// Arranges for waiters to re-check once the deadline passes: under a virtual clock it is a
    /// pending timer the sim can jump to; on the real clock a background waker bumps readiness
    /// then. Used for something that becomes ready at a set time — a datagram still in flight.
    /// Called on a thread of the sim the deadline belongs to, as the timer it registers is that
    /// thread's domain's; the bump goes to that domain too.
    pub(crate) fn wake_waiters_then(&self) {
        let domain = snare_interpose::domain_key();
        if self.on_virtual {
            // Left registered: the arrival is an event in its own right, consumed or not.
            let remaining = self.remaining();
            let _ = snare_interpose::register_event_timer(remaining);
            if let Some(real) = snare_interpose::real_span(remaining) {
                real_waker().schedule(real_now().saturating_add(real), domain);
            }
        } else {
            real_waker().schedule(self.at, domain);
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn wake_waiters_quiet_on(&self, clock: Option<&crate::clock::Clock>) {
        match clock.filter(|_| self.on_virtual) {
            Some(clock) => {
                let now = clock.virtual_now().unwrap_or(self.at);
                if let Some(real) = clock.register_event_quiet(self.at.saturating_sub(now)) {
                    real_waker().schedule(real_now().saturating_add(real), clock.domain());
                }
            }
            None if !self.on_virtual => {
                let domain =
                    clock.map_or_else(snare_interpose::domain_key, crate::clock::Clock::domain);
                real_waker().schedule(self.at, domain);
            }
            None => {}
        }
    }

    /// As [`wake_waiters_then`](Self::wake_waiters_then) from any thread, for a deadline made on
    /// `clock` (see [`on_clock`](Self::on_clock)); a real-time bump goes to `clock`'s domain, or
    /// with no clock to the calling thread's.
    pub(crate) fn wake_waiters_on(&self, clock: Option<&crate::clock::Clock>) {
        match clock.filter(|_| self.on_virtual) {
            Some(clock) => {
                let now = clock.virtual_now().unwrap_or(self.at);
                let _ = clock.register_timer(self.at.saturating_sub(now), false, true);
            }
            None if !self.on_virtual => {
                let domain =
                    clock.map_or_else(snare_interpose::domain_key, crate::clock::Clock::domain);
                real_waker().schedule(self.at, domain);
            }
            None => {}
        }
    }
}

/// Bumps readiness at real-clock times on behalf of things that become ready on their own (a
/// datagram arriving after its link latency), for sims on the real clock or on a virtual clock
/// scaled to it, and wakes wakers due at a real instant: timers on real time or a scaled clock.
/// One background thread, started unmanaged on first use.
struct RealWaker {
    due: Mutex<Due>,
    /// Signalled when an earlier entry may have been pushed, so the thread re-reads its next wake.
    changed: Condvar,
}

/// What is due when: key 0 bumps readiness for the domain alongside it, any other wakes its waker
/// unless cancelled first.
#[derive(Default)]
struct Due {
    /// Min-heap of (real time since the process origin, key, the domain a key-0 entry bumps).
    at: BinaryHeap<Reverse<(Duration, u64, usize)>>,
    /// The waker behind each non-zero key still scheduled; a heap entry whose key is gone was
    /// cancelled and is skipped.
    wakers: HashMap<u64, Waker>,
}

/// Wakes `waker` once real time since the process origin reaches `at`, under key `id` (from
/// [`wake_id`](crate::clock::wake_id)) for [`cancel_wake`].
pub(crate) fn schedule_wake(at: Duration, id: u64, waker: Waker) {
    let waker_thread = real_waker();
    snare_interpose::real(|| {
        let mut due = waker_thread.due.lock().unwrap();
        due.wakers.insert(id, waker);
        due.at.push(Reverse((at, id, 0)));
        waker_thread.changed.notify_one();
    });
}

/// Drops a waker from [`schedule_wake`] that has not fired, and pops cancelled entries off the top
/// of the heap so it does not grow with timers that never fire. The waker is dropped outside the
/// lock, since dropping it may run arbitrary code.
pub(crate) fn cancel_wake(id: u64) {
    let Some(waker_thread) = REAL_WAKER.get() else {
        return;
    };
    let cancelled = snare_interpose::real(|| {
        let mut due = waker_thread.due.lock().unwrap();
        let cancelled = due.wakers.remove(&id);
        while let Some(&Reverse((_, top, _))) = due.at.peek()
            && top != 0
            && !due.wakers.contains_key(&top)
        {
            due.at.pop();
        }
        cancelled
    });
    drop(cancelled);
}

/// Runs [`Domain::skip_idle`](snare_interpose::Domain::skip_idle) on an unmanaged worker for
/// this domain, so a blocking waker never holds up another domain or the real-time waker thread.
/// Retries every millisecond while the domain remains quiescent.
pub(crate) fn skip_idle_later(domain: &snare_interpose::Domain) {
    static JOBS: RaceCell<Mutex<HashMap<usize, std::sync::Arc<IdleSkip>>>> = RaceCell::new();
    let jobs = JOBS.get_or_init(Mutex::default).0;
    let job = snare_interpose::real(|| {
        let mut jobs = jobs.lock().unwrap();
        jobs.retain(|_, job| job.domain.upgrade().is_some());
        jobs.entry(domain.key())
            .or_insert_with(|| {
                std::sync::Arc::new(IdleSkip {
                    domain: domain.downgrade(),
                    running: std::sync::atomic::AtomicBool::new(false),
                    pending: std::sync::atomic::AtomicBool::new(false),
                })
            })
            .clone()
    });
    job.pending
        .store(true, std::sync::atomic::Ordering::Release);
    job.start();
}

struct IdleSkip {
    domain: snare_interpose::WeakDomain,
    running: std::sync::atomic::AtomicBool,
    pending: std::sync::atomic::AtomicBool,
}

impl IdleSkip {
    fn start(self: std::sync::Arc<Self>) {
        use std::sync::atomic::Ordering;
        if self.running.swap(true, Ordering::AcqRel) {
            return;
        }
        snare_interpose::real(|| {
            std::thread::Builder::new()
                .name("snare-idle-skip".into())
                .spawn(move || {
                    let _service = snare_interpose::service_thread();
                    loop {
                        self.pending.store(false, Ordering::Release);
                        let retry = self.domain.upgrade().is_some_and(|domain| {
                            domain.skip_idle();
                            domain.quiescent(false)
                        });
                        if retry {
                            std::thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        self.running.store(false, Ordering::Release);
                        if self.pending.load(Ordering::Acquire) {
                            self.start();
                        }
                        break;
                    }
                })
                .expect("start the idle-skip worker");
        });
    }
}

static REAL_WAKER: RaceCell<RealWaker> = RaceCell::new();

/// The process-wide [`RealWaker`], starting its thread the first time it is asked for. A
/// [`RaceCell`], not a `OnceLock`: it is reached from inside hooked waits, where waiting for
/// another thread's initialisation would park the thread a second time (see `RaceCell`).
fn real_waker() -> &'static RealWaker {
    let (waker, started) = REAL_WAKER.get_or_init(|| RealWaker {
        due: Mutex::default(),
        changed: Condvar::new(),
    });
    if started {
        // Spawned under passthrough, so the sim does not adopt it as a managed thread.
        snare_interpose::real(|| {
            std::thread::Builder::new()
                .name("snare-link-delay".into())
                .spawn(|| {
                    let _service = snare_interpose::service_thread();
                    real_waker().run();
                })
                .expect("start the link-delay waker")
        });
    }
    waker
}

impl RealWaker {
    /// Bumps readiness for `domain` (a [`Domain::key`](snare_interpose::Domain::key), 0 for every
    /// domain) once real time since the process origin reaches `at` (key 0).
    fn schedule(&self, at: Duration, domain: usize) {
        snare_interpose::real(|| {
            self.due.lock().unwrap().at.push(Reverse((at, 0, domain)));
            self.changed.notify_one();
        });
    }

    /// The waker thread's loop: sleeps until the earliest entry, then pops it and wakes or bumps
    /// with `due` let go.
    fn run(&self) {
        let mut due = self.due.lock().unwrap();
        loop {
            match due.at.peek().map(|r| r.0) {
                None => due = self.changed.wait(due).unwrap(),
                Some((at, id, domain)) => {
                    let now = real_now();
                    if now >= at {
                        due.at.pop();
                        let waker = due.wakers.remove(&id);
                        drop(due);
                        match waker {
                            Some(waker) => waker.wake(),
                            None if id == 0 => readiness().bump_time(domain),
                            None => {}
                        }
                        due = self.due.lock().unwrap();
                    } else {
                        due = self.changed.wait_timeout(due, at - now).unwrap().0;
                    }
                }
            }
        }
    }
}

/// Whether the calling thread reads the real clock although it runs in a domain: a driver.
fn real_clock_thread() -> bool {
    snare_interpose::thread_class() == Some(snare_interpose::ThreadClass::Driver)
}

/// The process-wide origin [`real_now`] measures from.
pub(crate) fn real_origin() -> Instant {
    static ORIGIN: RaceCell<Instant> = RaceCell::new();
    *ORIGIN.get_or_init(|| snare_interpose::real(Instant::now)).0
}

/// Real time since an arbitrary process-wide origin.
pub(crate) fn real_now() -> Duration {
    let origin = real_origin();
    snare_interpose::real(|| origin.elapsed())
}

/// How often an indefinite wait wakes to check for quiescence when nothing bumps it. A snare
/// choice: a bump wakes a waiter at once, so this bounds only how long a genuine deadlock or a
/// missed bump takes to notice.
const QUIESCENCE_POLL: Duration = Duration::from_millis(200);

/// How long every thread may sit blocked on a held or slow-running clock before a wait says so.
/// A snare choice, well past any time skip or kick, so the warning fires only for a clock left
/// paused or scaled far below real time.
const HELD_WARNING: Duration = Duration::from_secs(5);

/// Blocking readiness subscriptions shared by the socket backends and virtual clock. The
/// process-wide lock keeps wake generations and domain settling checks consistent.
pub(crate) struct Readiness {
    state: Mutex<State>,
}

pub(crate) use snare_interpose::ReadinessKey as WakeKey;
pub(crate) struct WakeKeys {
    inline: [WakeKey; 8],
    len: usize,
    overflow: Vec<WakeKey>,
    indexed: Option<HashSet<WakeKey>>,
}

impl Default for WakeKeys {
    fn default() -> Self {
        Self {
            inline: [WakeKey::Socket(0); 8],
            len: 0,
            overflow: Vec::new(),
            indexed: None,
        }
    }
}

impl WakeKeys {
    fn clear(&mut self) {
        self.len = 0;
        self.overflow.clear();
        if let Some(indexed) = &mut self.indexed {
            indexed.clear();
        }
    }

    pub(crate) fn push(&mut self, key: WakeKey) {
        let present = if self.len < 64 {
            self.as_slice().contains(&key)
        } else {
            if self.len == 64 && self.indexed.as_ref().is_none_or(HashSet::is_empty) {
                self.indexed
                    .get_or_insert_with(HashSet::new)
                    .extend(self.overflow.iter().copied());
            }
            !self.indexed.as_mut().unwrap().insert(key)
        };
        if present {
            return;
        }
        if self.len < self.inline.len() {
            self.inline[self.len] = key;
        } else {
            if self.overflow.is_empty() {
                self.overflow.extend_from_slice(&self.inline);
            }
            self.overflow.push(key);
        }
        self.len += 1;
    }

    pub(crate) fn as_slice(&self) -> &[WakeKey] {
        if self.overflow.is_empty() {
            &self.inline[..self.len]
        } else {
            &self.overflow
        }
    }
}

use snare_interpose::ReadinessWake as WakeEvent;

/// Guarded by one lock so a quiescence check sees a consistent picture.
struct State {
    /// Active subscriptions, including their domain and unread wake generations.
    waiters: Vec<Waiters>,
    /// Retains condition variables and interest capacity between waits.
    spare: Vec<Waiters>,
    next_waiter: u64,
}

/// One blocking call's subscription.
struct Waiters {
    id: u64,
    /// The domain's key.
    domain: usize,
    /// Changes when a relevant event reaches this subscription.
    generation: u64,
    /// Its threads currently asleep on `changed`.
    sleeping: usize,
    /// Of those, the ones a bump woke that have not yet woken up and re-checked. A woken waiter
    /// still counts as parked until it runs, so while any is pending the domain only looks
    /// quiescent: a time skip then would race virtual time ahead of the work the woken thread is
    /// about to do.
    stale: usize,
    /// Paired with [`Readiness::state`].
    changed: Arc<Condvar>,
    keys: Vec<WakeKey>,
    broad: bool,
    time_sensitive: bool,
}

impl State {
    /// Records a bump of `domain` (0 for every domain): each current sleeper of that domain, and
    /// of the threads outside every domain, is stale until it runs. Hands `notify` the condvar of
    /// each entry reached.
    fn bump(&mut self, domain: usize, event: WakeEvent<'_>, mut notify: impl FnMut(&Arc<Condvar>)) {
        for waiters in &mut self.waiters {
            if domain != 0 && waiters.domain != domain && waiters.domain != 0 {
                continue;
            }
            let relevant = waiters.broad
                || match event {
                    WakeEvent::All => true,
                    WakeEvent::Timer => waiters.time_sensitive,
                    WakeEvent::Keys(keys) => keys.iter().any(|key| waiters.keys.contains(key)),
                };
            if relevant {
                waiters.generation += 1;
                waiters.stale = waiters.sleeping;
                if waiters.sleeping > 0 {
                    notify(&waiters.changed);
                }
            }
        }
    }

    fn register(&mut self, domain: usize, keys: Option<&[WakeKey]>) -> u64 {
        self.next_waiter += 1;
        let mut waiters = self.spare.pop().unwrap_or_else(|| Waiters {
            id: 0,
            domain: 0,
            generation: 0,
            sleeping: 0,
            stale: 0,
            changed: Arc::default(),
            keys: Vec::new(),
            broad: true,
            time_sensitive: true,
        });
        waiters.id = self.next_waiter;
        waiters.domain = domain;
        waiters.generation = 0;
        waiters.sleeping = 0;
        waiters.stale = 0;
        waiters.keys.clear();
        waiters.broad = keys.is_none();
        waiters.time_sensitive = keys.is_none();
        if let Some(keys) = keys {
            waiters.keys.extend_from_slice(keys);
        }
        self.waiters.push(waiters);
        self.next_waiter
    }

    fn unregister(&mut self, id: u64) {
        if let Some(i) = self.waiters.iter().position(|w| w.id == id) {
            self.spare.push(self.waiters.swap_remove(i));
        }
    }

    /// Whether a sleeper of `domain` was woken and has yet to re-check.
    fn settling(&self, domain: usize) -> bool {
        self.waiters
            .iter()
            .any(|w| w.domain == domain && w.stale > 0)
    }

    /// Counts a sleeper of `domain` asleep, returning the condvar it sleeps on and the domain's
    /// generation for [`awake`](Self::awake).
    fn asleep(
        &mut self,
        id: u64,
        time_sensitive: bool,
        keys: Option<&[WakeKey]>,
    ) -> (Arc<Condvar>, u64) {
        let waiters = self.waiters.iter_mut().find(|w| w.id == id).unwrap();
        waiters.time_sensitive = time_sensitive;
        if let Some(keys) = keys {
            waiters.keys.clear();
            waiters.keys.extend_from_slice(keys);
        }
        waiters.sleeping += 1;
        (waiters.changed.clone(), waiters.generation)
    }

    /// Counts a sleeper of `domain` awake again, before it takes any stale mark; `true` if a bump
    /// reached the domain since [`asleep`](Self::asleep) returned `generation`.
    fn awake(&mut self, id: u64, generation: u64) -> bool {
        match self.waiters.iter_mut().find(|w| w.id == id) {
            Some(waiters) => {
                waiters.sleeping = waiters.sleeping.saturating_sub(1);
                waiters.generation != generation
            }
            None => false,
        }
    }

    /// Takes one stale mark of `domain` for a sleeper a bump woke, now back holding the lock;
    /// `true` if it was the domain's last.
    fn rechecked(&mut self, id: u64) -> bool {
        let Some(waiters) = self.waiters.iter_mut().find(|w| w.id == id && w.stale > 0) else {
            return false;
        };
        waiters.stale -= 1;
        let domain = waiters.domain;
        !self.settling(domain)
    }
}

/// The process-wide [`Readiness`].
pub(crate) fn readiness() -> &'static Readiness {
    static READINESS: RaceCell<Readiness> = RaceCell::new();
    READINESS
        .get_or_init(|| Readiness {
            state: Mutex::new(State {
                waiters: Vec::new(),
                spare: Vec::new(),
                next_waiter: 0,
            }),
        })
        .0
}

impl Readiness {
    /// Wakes the waiters of the domain with key `domain` to re-check — those on its condvar and,
    /// when the calling thread runs in that domain, those parked in its deterministic schedule —
    /// along with every waiter outside a domain. `domain` is the
    /// [`Domain::key`](snare_interpose::Domain::key) of the sim that owns what changed; 0, where
    /// that is not known, wakes every domain's waiters. Called with no backend table lock held
    /// (see [`wait_until`](Self::wait_until)).
    pub(crate) fn bump(&self, domain: usize) {
        self.bump_event(domain, WakeEvent::All, true);
    }

    pub(crate) fn bump_keys(&self, domain: usize, keys: &[WakeKey]) {
        self.bump_event(domain, WakeEvent::Keys(keys), true);
    }

    pub(crate) fn bump_time(&self, domain: usize) {
        self.bump_event(domain, WakeEvent::Timer, true);
    }

    fn bump_event(&self, domain: usize, event: WakeEvent<'_>, scheduled: bool) {
        self.bump_unscheduled_event(domain, event);
        // Under deterministic scheduling the waiters park in the schedule, not on the condvar. The
        // schedule reached from here is the calling thread's domain's, so another sim's is left
        // alone; a thread outside the domain has none to wake.
        if scheduled && (domain == 0 || domain == snare_interpose::domain_key()) {
            snare_interpose::det_wake_readiness(event);
        }
    }

    /// As [`bump`](Self::bump), for the waiters on the condvar only: the threads that wait outside
    /// a deterministic schedule. Notifies once the lock is let go.
    pub(crate) fn bump_time_unscheduled(&self, domain: usize) {
        self.bump_unscheduled_event(domain, WakeEvent::Timer);
    }

    fn bump_unscheduled_event(&self, domain: usize, event: WakeEvent<'_>) {
        self.notify_bump(domain, event, |changed| changed.notify_all());
    }

    fn notify_bump(
        &self,
        domain: usize,
        event: WakeEvent<'_>,
        mut notify: impl FnMut(&Arc<Condvar>),
    ) {
        let mut woken: [Option<Arc<Condvar>>; 32] = std::array::from_fn(|_| None);
        let mut spill = Vec::new();
        let mut reached = 0;
        let mut state = self.state.lock().unwrap();
        state.bump(domain, event, |changed| match woken.get_mut(reached) {
            Some(slot) => {
                *slot = Some(changed.clone());
                reached += 1;
            }
            None => spill.push(changed.clone()),
        });
        drop(state);
        for changed in woken.into_iter().take(reached).flatten() {
            notify(&changed);
        }
        for changed in spill {
            notify(&changed);
        }
    }

    /// Bumps `domain`'s waiters from inside a wait, holding the lock, after the waiting thread
    /// moved its domain's time.
    fn bump_locked(state: &mut State, domain: usize) {
        state.bump(domain, WakeEvent::Timer, |changed| changed.notify_all());
    }

    /// Whether a waiter of the domain with key `domain` has been woken but not yet run; see
    /// [`Waiters::stale`].
    pub(crate) fn settling(&self, domain: usize) -> bool {
        self.state.lock().unwrap().settling(domain)
    }

    /// Blocks until `ready()` holds or the deadline passes. Returns whether `ready()` held. A wait
    /// ends the calling thread's clock spin, as a hooked call does, even when `ready()` already
    /// holds. The
    /// `ready` closure locks the backend's socket table; every waker (send/close/shutdown) releases
    /// that table before it bumps `Readiness`, so it is never held across a `state` acquisition
    /// and the two locks keep a consistent order. `label` names the wait for diagnostics.
    pub(crate) fn wait_until(
        &self,
        label: &'static str,
        deadline: Option<Deadline>,
        mut ready: impl FnMut() -> bool,
    ) -> bool {
        self.wait_interested(label, deadline, None, None, || true, &mut ready)
    }

    pub(crate) fn wait_until_on(
        &self,
        label: &'static str,
        deadline: Option<Deadline>,
        keys: &[WakeKey],
        time_sensitive: impl FnMut() -> bool,
        ready: impl FnMut() -> bool,
    ) -> bool {
        self.wait_interested(label, deadline, Some(keys), None, time_sensitive, ready)
    }

    pub(crate) fn wait_until_dynamic(
        &self,
        label: &'static str,
        deadline: Option<Deadline>,
        mut interests: impl FnMut(&mut WakeKeys) -> bool,
        ready: impl FnMut() -> bool,
    ) -> bool {
        let keys = std::cell::RefCell::new(WakeKeys::default());
        self.wait_interested(
            label,
            deadline,
            Some(&[]),
            Some(&keys),
            || {
                let mut keys = keys.borrow_mut();
                keys.clear();
                interests(&mut keys)
            },
            ready,
        )
    }

    fn wait_interested(
        &self,
        label: &'static str,
        deadline: Option<Deadline>,
        keys: Option<&[WakeKey]>,
        dynamic_keys: Option<&std::cell::RefCell<WakeKeys>>,
        mut time_sensitive: impl FnMut() -> bool,
        mut ready: impl FnMut() -> bool,
    ) -> bool {
        let _label = snare_interpose::wait_label(label);
        snare_interpose::end_spin();
        if snare_interpose::det_active()
            && let Some(result) = Self::wait_deterministic(
                deadline,
                keys,
                dynamic_keys,
                &mut time_sensitive,
                &mut ready,
            )
        {
            return result;
        }
        // Under a virtual clock, a finite deadline must be a pending timer the quiescence time-skip
        // can jump to; otherwise a timeout nothing else can satisfy would read as a deadlock.
        // Register the remaining span and drop it again if the wait returns before it fires.
        let mut deadline = deadline;
        let mut timer = deadline
            .filter(|d| d.on_virtual)
            .and_then(|d| snare_interpose::register_timer(d.remaining()));
        if let Some(d) = deadline.filter(|d| d.on_virtual) {
            snare_interpose::note_wait_deadline(Some(d.at));
        }
        let subscription = Subscription {
            readiness: self,
            id: self
                .state
                .lock()
                .unwrap()
                .register(snare_interpose::domain_key(), keys),
        };
        let timed = deadline.is_some();
        let initial_sensitive = time_sensitive();
        let sensitive = std::cell::Cell::new(timed || initial_sensitive);
        let mut parked = Parked {
            waiter: subscription.id,
            time_sensitive: Some(&sensitive),
            dynamic_keys,
            ..Parked::default()
        };
        let predicate = || {
            let needed = time_sensitive();
            sensitive.set(timed || needed);
            ready()
        };
        let result = self.wait_inner(&mut deadline, &mut timer, &mut parked, predicate);
        drop(parked);
        snare_interpose::note_wait_deadline(None);
        if let Some(key) = timer {
            snare_interpose::unregister_timer(key);
        }
        if let Some(d) = deadline.filter(|d| !result && d.on_virtual)
            && snare_interpose::virtual_now().is_none()
        {
            snare_interpose::expire_timer(d.at);
        }
        result
    }

    /// The wait under deterministic scheduling: park in the schedule until something bumps
    /// readiness, the deadline passes, or the scheduler finds every thread blocked with no time
    /// left (a deadlock, so the wait gives up), re-checking `ready` each time it runs again.
    /// `None` once the schedule has let the thread go (its last root left the run), for the wait
    /// to go on outside it.
    fn wait_deterministic(
        deadline: Option<Deadline>,
        keys: Option<&[WakeKey]>,
        dynamic_keys: Option<&std::cell::RefCell<WakeKeys>>,
        mut time_sensitive: impl FnMut() -> bool,
        mut ready: impl FnMut() -> bool,
    ) -> Option<bool> {
        loop {
            if ready() {
                return Some(true);
            }
            if deadline.is_some_and(|d| d.passed()) {
                return Some(ready());
            }
            if !snare_interpose::det_active() {
                return None;
            }
            let at = deadline.filter(|d| d.on_virtual).map(|d| d.at);
            let timed = time_sensitive();
            let dynamic = dynamic_keys.map(std::cell::RefCell::borrow);
            let interests = dynamic.as_ref().map(|keys| keys.as_slice()).or(keys);
            if snare_interpose::det_block_readiness(at, interests, timed)
                == snare_interpose::DetWake::Deadlock
            {
                return Some(ready());
            }
        }
    }

    /// An indefinite (`None`) wait polls at `QUIESCENCE_POLL` so it can notice quiescence — every
    /// managed thread parked, none woken and still to run — and return `false` rather than block
    /// forever. A bump wakes it at once, so this only adds latency to a genuine deadlock.
    ///
    /// The thread counts as parked (per domain, so parallel tests don't see each other's threads)
    /// only once it has found `ready()` false, and stops counting before it lets go of the lock on
    /// its way out, so a peer checking quiescence under the same lock never sees it parked while
    /// it is running. A thread that is not a participant is never counted and never gives up on
    /// quiescence: it waits for `ready()` or its deadline, and moves time to that deadline only once
    /// every participant is parked in a wait that never gives up (a join), which only it can end.
    ///
    /// A real-clock deadline moves onto the virtual clock, keeping what is left of it, once the
    /// clock it was made beside stops running as fast as possible (discrete, paused, scaled or
    /// driven), so the wait holds with that clock. A driver thread's deadline stays on real time.
    ///
    /// A thread left over from a run that has ended (its domain dormant) never gives up, and moves
    /// time itself, but only as fast as real time passes (see `Layer::dormant`).
    fn wait_inner(
        &self,
        deadline: &mut Option<Deadline>,
        timer: &mut Option<u64>,
        parked: &mut Parked,
        mut ready: impl FnMut() -> bool,
    ) -> bool {
        // How long to wait after a time-skip done on another thread's behalf before checking again;
        // a bump cuts it short. Skips that satisfy *this* thread don't wait at all. A snare choice:
        // long enough for the woken thread to take the lock and run.
        const SETTLE: Duration = Duration::from_millis(5);
        let mut state = self.state.lock().unwrap();
        if ready() {
            return true;
        }
        let class = snare_interpose::thread_class();
        let participant = class == Some(snare_interpose::ThreadClass::Participant);
        let real_clock = class == Some(snare_interpose::ThreadClass::Driver);
        if participant && let Some(bump) = parked.enter() {
            state = self.unlocked(state, parked, || drop(bump)).0;
            if ready() {
                return self.leave(state, parked, true);
            }
        }
        let mut held_since = None;
        let mut warned = false;
        let key = snare_interpose::domain_key();
        let quiescent = |state: &State| {
            participant
                && !snare_interpose::dormant()
                && snare_interpose::quiescent(state.settling(key))
        };
        let stalled = |state: &State, deadline: Option<Deadline>| {
            !participant
                && deadline.is_some_and(|d| d.on_virtual)
                && !snare_interpose::dormant()
                && snare_interpose::stalled(state.settling(key))
        };
        loop {
            if let Some(d) = deadline.filter(|d| !d.on_virtual && !real_clock)
                && let Some(now) = snare_interpose::virtual_now()
            {
                let remaining = d.remaining();
                *deadline = Some(Deadline {
                    at: now.saturating_add(remaining),
                    on_virtual: true,
                });
                *timer = snare_interpose::register_timer(remaining);
            }
            let deadline = *deadline;
            // A deadline already reached ends the wait before any time skip: a zero timeout is a
            // non-blocking check, not a request to move the clock.
            if deadline.is_some_and(|d| d.passed()) {
                let result = ready();
                return self.leave(state, parked, result);
            }
            // Left over from a run that has ended: nothing waits on this thread, so time moves to
            // the next timer once real time has caught up with it, whatever the domain's other
            // threads are doing, and with nothing pending the wait blocks rather than giving up
            // (see `Layer::dormant`).
            let mut moved = false;
            if snare_interpose::dormant() {
                let (next, bumped) = self.unlocked(state, parked, || {
                    moved = snare_interpose::foreign_time_skip()
                });
                state = next;
                if bumped && ready() {
                    return self.leave(state, parked, true);
                }
            }
            if moved {
                Self::bump_locked(&mut state, key);
                if ready() {
                    return self.leave(state, parked, true);
                }
                if deadline.is_some_and(|d| d.passed()) {
                    return self.leave(state, parked, false);
                }
                continue;
            }
            // Quiescent with a pending virtual timer: jump time to it immediately rather than wait
            // out the poll. If the jump reached *our own* deadline we return at once (so a sleeper
            // fast-forwards its own sleeps); otherwise we settle to let the woken thread run.
            moved = false;
            if !snare_interpose::executive_attached() && quiescent(&state) {
                let (next, bumped) =
                    self.unlocked(state, parked, || moved = snare_interpose::time_skip());
                state = next;
                if bumped && ready() {
                    return self.leave(state, parked, true);
                }
            }
            if moved {
                Self::bump_locked(&mut state, key);
                if ready() {
                    return self.leave(state, parked, true);
                }
                // The skip may have reached our own deadline: return now rather than settle
                // while still counted as parked, which would let a peer skip time past us.
                if deadline.is_some_and(|d| d.passed()) {
                    return self.leave(state, parked, false);
                }
                state = self.sleep(state, SETTLE, parked).0;
                if ready() {
                    return self.leave(state, parked, true);
                }
                continue;
            }
            // Every participant waits on what only a thread like this one can do: its own
            // deadline is what moves time on.
            moved = false;
            if !snare_interpose::executive_attached() && stalled(&state, deadline) {
                let (next, bumped) = self.unlocked(state, parked, || {
                    moved = snare_interpose::foreign_time_skip()
                });
                state = next;
                if bumped && ready() {
                    return self.leave(state, parked, true);
                }
            }
            if moved {
                Self::bump_locked(&mut state, key);
                if ready() {
                    return self.leave(state, parked, true);
                }
                if deadline.is_some_and(|d| d.passed()) {
                    return self.leave(state, parked, false);
                }
                continue;
            }
            let mut wait =
                deadline.map_or(QUIESCENCE_POLL, |d| d.real_remaining().min(QUIESCENCE_POLL));
            if let Some(idle) = snare_interpose::idle_wait() {
                wait = wait.min(idle);
            }
            let (next, timed_out, bumped) = self.sleep(state, wait, parked);
            state = next;
            if ready() {
                return self.leave(state, parked, true);
            }
            if deadline.is_some_and(|d| d.passed()) {
                let result = ready();
                return self.leave(state, parked, result);
            }
            // Reached quiescence during the poll with no bump: time-skip if a timer is pending,
            // otherwise it is a genuine deadlock.
            if timed_out && !bumped && quiescent(&state) {
                let mut moved = false;
                if !snare_interpose::executive_attached() {
                    let (next, bumped) =
                        self.unlocked(state, parked, || moved = snare_interpose::time_skip());
                    state = next;
                    if bumped && ready() {
                        return self.leave(state, parked, true);
                    }
                }
                if moved {
                    Self::bump_locked(&mut state, key);
                    continue;
                }
                if deadline.is_some_and(|d| !d.on_virtual) {
                    continue;
                }
                if snare_interpose::idle_wait().is_some() {
                    // Every thread waits on a clock that is held or still running toward a timer:
                    // time will move, so this is not a deadlock.
                    let held = *held_since.get_or_insert_with(real_now);
                    if !warned
                        && real_now().saturating_sub(held) > HELD_WARNING
                        && !snare_interpose::executive_attached()
                    {
                        warned = true;
                        eprintln!(
                            "snare: every thread has been blocked on the clock for {}s while it \
                             is held or running slowly toward its next timer; if it is paused, \
                             advance or resume it from outside the simulation",
                            HELD_WARNING.as_secs()
                        );
                    }
                    continue;
                }
                if !quiescent(&state) {
                    // A lease taken since the check above holds the domain busy.
                    continue;
                }
                let result = ready();
                return self.leave(state, parked, result);
            }
            held_since = None;
        }
    }

    /// Ends a wait with `result`, counting the waiter running again before it lets go of the lock.
    /// While an executive's timestamp is open the waiter first waits at the gate, with the lock let
    /// go meanwhile.
    fn leave<'a>(
        &'a self,
        mut state: MutexGuard<'a, State>,
        parked: &mut Parked,
        result: bool,
    ) -> bool {
        while !parked.leave() {
            drop(state);
            snare_interpose::pass_gate();
            state = self.state.lock().unwrap();
        }
        drop(state);
        result
    }

    /// Sleeps on its domain's condvar for at most `timeout`, keeping `sleeping`/`stale` accurate: a
    /// sleeper that a bump marked stale stops being stale once it is back holding the lock.
    /// Returns whether the sleep timed out and whether a bump of the domain came meanwhile.
    ///
    /// The last woken waiter to run moves the epoch, since the domain may be quiescent now and an
    /// executive waiting on the epoch must hear it; its callback runs once the waiter has re-checked
    /// and lets go of the lock, here on its way back to sleep or as it leaves the wait. Letting go
    /// any earlier would show it parked and no longer stale before it re-checked.
    fn sleep<'a>(
        &'a self,
        mut state: MutexGuard<'a, State>,
        timeout: Duration,
        parked: &mut Parked,
    ) -> (MutexGuard<'a, State>, bool, bool) {
        if let Some(settled) = parked.settled.take() {
            let (next, bumped) = self.unlocked(state, parked, || drop(settled));
            state = next;
            if bumped {
                return (state, false, true);
            }
        }
        let (changed, generation) = parked.asleep(&mut state);
        let (mut state, result) = changed.wait_timeout(state, timeout).unwrap();
        let bumped = state.awake(parked.waiter, generation);
        if bumped {
            Self::woke(&mut state, parked);
        }
        (state, result.timed_out(), bumped)
    }

    /// Lets go of the lock to run `f` and takes it back, the waiter counted asleep meanwhile: it
    /// is still parked, so a bump in between must mark it stale, as it would a sleeper, or the
    /// domain would look quiescent before it re-checks. Returns whether a bump came, in which case
    /// the waiter has taken its stale mark and must re-check before it waits again.
    fn unlocked<'a>(
        &'a self,
        mut state: MutexGuard<'a, State>,
        parked: &mut Parked,
        f: impl FnOnce(),
    ) -> (MutexGuard<'a, State>, bool) {
        let (_, generation) = parked.asleep(&mut state);
        drop(state);
        f();
        let mut state = self.state.lock().unwrap();
        let bumped = state.awake(parked.waiter, generation);
        if bumped {
            Self::woke(&mut state, parked);
        }
        (state, bumped)
    }

    /// A waiter back holding the lock after a bump stops being stale; the last to do so moves the
    /// epoch (see [`sleep`](Self::sleep)).
    fn woke(state: &mut State, parked: &mut Parked) {
        if state.rechecked(parked.waiter) && snare_interpose::executive_attached() {
            parked.settled = Some(snare_interpose::bump_epoch());
        }
    }

    /// Runs `f` under the readiness lock with whether a woken waiter of the domain with key
    /// `domain` has yet to run, so a check of that domain's quiescence made in `f` sees no waiter
    /// wake meanwhile. Runs under passthrough: called from a driver or background thread, the lock's
    /// own futex traffic must not count as an effect of that thread on the sim, which would hide a
    /// participant's outside wake.
    pub(crate) fn locked<R>(&self, domain: usize, f: impl FnOnce(bool) -> R) -> R {
        snare_interpose::real(|| {
            let state = self.state.lock().unwrap();
            f(state.settling(domain))
        })
    }

    #[cfg(windows)]
    pub(crate) fn skip_clock<R>(
        &self,
        domain: &snare_interpose::Domain,
        foreign: bool,
        skip: impl FnOnce() -> (bool, R),
    ) -> Option<(bool, R)> {
        snare_interpose::real(|| {
            let mut state = self.state.lock().unwrap();
            let result = domain.if_native_time_skip(state.settling(domain.key()), foreign, skip);
            if result.as_ref().is_some_and(|(moved, _)| *moved) {
                Self::bump_locked(&mut state, domain.key());
            }
            result
        })
    }

    #[cfg(windows)]
    pub(crate) fn spin_clock<R>(
        &self,
        domain: &snare_interpose::Domain,
        spin: impl FnOnce() -> (snare_interpose::SpinStep, R),
    ) -> Option<(snare_interpose::SpinStep, R)> {
        snare_interpose::real(|| {
            let mut state = self.state.lock().unwrap();
            let result = domain.if_native_spin_step(state.settling(domain.key()), spin);
            if result.as_ref().is_some_and(|(step, _)| {
                matches!(step, snare_interpose::SpinStep::Moved { fired: true })
            }) {
                Self::bump_locked(&mut state, domain.key());
            }
            result
        })
    }
}

struct Subscription<'a> {
    readiness: &'a Readiness,
    id: u64,
}

impl Drop for Subscription<'_> {
    fn drop(&mut self) {
        self.readiness
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .unregister(self.id);
    }
}

/// A waiter's place in its domain's parked count, and the epoch callback leaving it released, run
/// once the waiter has let go of the readiness lock.
#[derive(Default)]
struct Parked<'a> {
    waiter: u64,
    time_sensitive: Option<&'a std::cell::Cell<bool>>,
    dynamic_keys: Option<&'a std::cell::RefCell<WakeKeys>>,
    /// Counted as parked in the domain.
    entered: bool,
    /// Counted running again; the callback runs when the `Parked` drops, after the lock is let go.
    left: Option<snare_interpose::EpochBump>,
    /// The epoch callback released when this was the last woken waiter to run.
    settled: Option<snare_interpose::EpochBump>,
}

impl Parked<'_> {
    fn asleep(&self, state: &mut State) -> (Arc<Condvar>, u64) {
        let keys = self.dynamic_keys.map(std::cell::RefCell::borrow);
        state.asleep(
            self.waiter,
            self.timer_sensitive(),
            keys.as_ref().map(|keys| keys.as_slice()),
        )
    }

    fn timer_sensitive(&self) -> bool {
        self.time_sensitive.is_none_or(std::cell::Cell::get)
    }
    /// Counts the waiter as parked, returning the epoch callback that released, if any, for the
    /// caller to run once it has let go of the readiness lock.
    fn enter(&mut self) -> Option<snare_interpose::EpochBump> {
        self.entered = true;
        let bump = snare_interpose::mark_sim_waiting(true);
        bump.is_armed().then_some(bump)
    }

    /// Counts the waiter running again; `false`, changing nothing, while it must first wait at an
    /// open timestamp's gate.
    fn leave(&mut self) -> bool {
        if !self.entered || self.left.is_some() {
            return true;
        }
        match snare_interpose::try_leave_sim_wait() {
            Some(bump) => {
                self.left = Some(bump);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn idle_subscriptions_keep_generations_without_notifications() {
        crate::Sim::new().run(|| {
            let mut state = State {
                waiters: Vec::new(),
                spare: Vec::new(),
                next_waiter: 0,
            };
            let key = [WakeKey::Socket(7)];
            let id = state.register(7, Some(&key));
            let changed = state.waiters[0].changed.clone();
            let mut notified = 0;
            state.bump(7, WakeEvent::Keys(&key), |_| notified += 1);
            assert_eq!(notified, 0);
            assert_eq!(state.waiters[0].generation, 1);
            assert_eq!(state.waiters[0].stale, 0);

            let (_, generation) = state.asleep(id, false, None);
            assert_eq!(generation, 1);
            state.bump(7, WakeEvent::Keys(&key), |woken| {
                assert!(Arc::ptr_eq(woken, &changed));
                notified += 1;
            });
            assert_eq!(notified, 1);
            assert_eq!(state.waiters[0].generation, 2);
            assert_eq!(state.waiters[0].stale, 1);
            assert!(state.awake(id, generation));
            assert!(state.rechecked(id));
            state.bump(7, WakeEvent::Keys(&key), |_| notified += 1);
            assert_eq!(notified, 1);
            assert_eq!(state.waiters[0].generation, 3);
            assert_eq!(state.waiters[0].stale, 0);

            state.unregister(id);
            let reused = state.register(7, Some(&key));
            assert_ne!(reused, id);
            assert!(Arc::ptr_eq(&state.waiters[0].changed, &changed));
            assert_eq!(state.waiters[0].generation, 0);
            assert_eq!(state.waiters[0].sleeping, 0);
            assert_eq!(state.waiters[0].stale, 0);
            state.bump(7, WakeEvent::Keys(&key), |_| notified += 1);
            assert_eq!(notified, 1);
            assert_eq!(state.waiters[0].generation, 1);
            let (_, generation) = state.asleep(reused, false, None);
            state.bump(7, WakeEvent::Keys(&key), |_| notified += 1);
            assert_eq!(notified, 2);
            assert_eq!(state.waiters[0].stale, 1);
            assert!(state.awake(reused, generation));
            assert!(state.rechecked(reused));
            assert_eq!(state.waiters[0].sleeping, 0);
            assert_eq!(state.waiters[0].stale, 0);
            state.unregister(reused);
        });
    }

    #[test]
    fn keyed_bumps_filter_domains_and_preserve_domain_zero() {
        crate::Sim::new().run(|| {
            let mut state = State {
                waiters: Vec::new(),
                spare: Vec::new(),
                next_waiter: 0,
            };
            for domain in [0, 1, 2] {
                state.register(domain, Some(&[WakeKey::Socket(7)]));
                state.register(domain, Some(&[WakeKey::Socket(8)]));
                state.register(domain, None);
            }
            state.bump(1, WakeEvent::Keys(&[WakeKey::Socket(7)]), |_| {});
            assert_eq!(
                state
                    .waiters
                    .iter()
                    .map(|w| w.generation)
                    .collect::<Vec<_>>(),
                [1, 0, 1, 1, 0, 1, 0, 0, 0]
            );
            state.bump(0, WakeEvent::Keys(&[WakeKey::Socket(8)]), |_| {});
            assert_eq!(
                state
                    .waiters
                    .iter()
                    .map(|w| w.generation)
                    .collect::<Vec<_>>(),
                [1, 1, 2, 1, 1, 2, 0, 1, 1]
            );
        });
    }

    #[test]
    fn wake_keys_preserve_order_and_uniqueness_across_reuse() {
        crate::Sim::new().run(|| {
            let mut keys = WakeKeys::default();
            for size in [8, 64, 65, 1024, 3, 256] {
                keys.clear();
                for id in 0..size {
                    keys.push(WakeKey::Socket(id));
                    keys.push(WakeKey::Socket(id));
                    #[cfg(unix)]
                    keys.push(WakeKey::Descriptor(id));
                    #[cfg(windows)]
                    keys.push(WakeKey::CompletionPort(id));
                }
                let expected: Vec<_> = (0..size)
                    .flat_map(|id| {
                        #[cfg(unix)]
                        let second = WakeKey::Descriptor(id);
                        #[cfg(windows)]
                        let second = WakeKey::CompletionPort(id);
                        [WakeKey::Socket(id), second]
                    })
                    .collect();
                assert_eq!(keys.as_slice(), expected);
                for &key in &expected {
                    keys.push(key);
                }
                assert_eq!(keys.as_slice(), expected);
            }
        });
    }

    #[cfg(windows)]
    #[test]
    fn clock_waiters_are_stale_before_native_timer_callbacks_run() {
        struct Observe {
            domain: usize,
            stale: Arc<AtomicBool>,
        }

        impl std::task::Wake for Observe {
            fn wake(self: Arc<Self>) {
                self.stale
                    .store(readiness().settling(self.domain), Ordering::SeqCst);
            }
        }

        let clock = Arc::new(crate::clock::Clock::new(0));
        clock.set_discrete(true);
        let layer = Arc::new(crate::clock::ClockLayer(clock.clone()));
        let domain =
            snare_interpose::Domain::new([layer.clone() as Arc<dyn snare_interpose::Layer>]);
        clock.set_domain(&domain);
        let board = readiness();
        let waiter = {
            let mut state = board.state.lock().unwrap();
            let waiter = state.register(domain.key(), None);
            state.asleep(waiter, true, None);
            waiter
        };
        let stale = Arc::new(AtomicBool::new(false));
        let wake = clock
            .register_wake(
                1_000,
                Waker::from(Arc::new(Observe {
                    domain: domain.key(),
                    stale: stale.clone(),
                })),
                false,
            )
            .unwrap();
        domain.run(|| {
            drop(snare_interpose::mark_sim_waiting(true));
            assert!(snare_interpose::Layer::try_time_skip(layer.as_ref()));
            drop(snare_interpose::mark_sim_waiting(false));
        });
        {
            let mut state = board.state.lock().unwrap();
            state.unregister(waiter);
        }
        clock.cancel_wake(wake);
        assert!(stale.load(Ordering::SeqCst));
    }

    #[cfg(windows)]
    #[test]
    fn a_native_clock_rechecks_participants_after_a_quiescent_snapshot() {
        let clock = Arc::new(crate::clock::Clock::new(0));
        clock.set_discrete(true);
        let layer = Arc::new(crate::clock::ClockLayer(clock.clone()));
        let domain =
            snare_interpose::Domain::new([layer.clone() as Arc<dyn snare_interpose::Layer>]);
        clock.set_domain(&domain);
        domain.run(|| {
            let timer = snare_interpose::Layer::register_event_timer(
                layer.as_ref(),
                Duration::from_micros(1),
            )
            .unwrap();
            drop(snare_interpose::mark_sim_waiting(true));
            assert!(domain.quiescent(false));
            drop(snare_interpose::mark_sim_waiting(false));
            assert!(!snare_interpose::Layer::try_time_skip(layer.as_ref()));
            assert_eq!(clock.peek(), 0);
            clock.unregister_event(timer);
        });
    }

    #[cfg(windows)]
    #[test]
    fn a_native_spin_rechecks_participants_after_a_waiting_snapshot() {
        let clock = Arc::new(crate::clock::Clock::new(0));
        clock.set_discrete(true);
        let layer = Arc::new(crate::clock::ClockLayer(clock.clone()));
        let domain =
            snare_interpose::Domain::new([layer.clone() as Arc<dyn snare_interpose::Layer>]);
        clock.set_domain(&domain);
        domain.run(|| {
            drop(snare_interpose::mark_sim_waiting(true));
            assert!(domain.quiescent(false));
            drop(snare_interpose::mark_sim_waiting(false));
            assert!(matches!(
                snare_interpose::Layer::spin_step(layer.as_ref(), Duration::from_micros(1)),
                snare_interpose::SpinStep::Waking
            ));
            assert_eq!(clock.peek(), 0);
        });
    }

    #[test]
    fn an_arrival_published_during_a_rejected_skip_is_checked_before_sleeping() {
        struct Arrival(AtomicBool);

        impl snare_interpose::Layer for Arrival {
            fn try_time_skip(&self) -> bool {
                self.0.store(true, Ordering::SeqCst);
                readiness().bump_time_unscheduled(snare_interpose::domain_key());
                false
            }

            fn idle_wait(&self) -> Option<Duration> {
                assert!(!self.0.load(Ordering::SeqCst));
                None
            }
        }

        let arrival = Arc::new(Arrival(AtomicBool::new(false)));
        let domain =
            snare_interpose::Domain::new([arrival.clone() as Arc<dyn snare_interpose::Layer>]);
        domain.run(|| {
            assert!(readiness().wait_until("arrival while skipping", None, || {
                arrival.0.load(Ordering::SeqCst)
            }));
        });
    }

    #[test]
    fn an_arrival_reached_during_the_clock_check_is_not_a_deadlock() {
        struct Arrival {
            checks: AtomicUsize,
            ready: AtomicBool,
        }

        impl snare_interpose::Layer for Arrival {
            fn idle_wait(&self) -> Option<Duration> {
                if self.checks.fetch_add(1, Ordering::SeqCst) == 1 {
                    self.ready.store(true, Ordering::SeqCst);
                }
                None
            }
        }

        let arrival = Arc::new(Arrival {
            checks: AtomicUsize::new(0),
            ready: AtomicBool::new(false),
        });
        let domain =
            snare_interpose::Domain::new([arrival.clone() as Arc<dyn snare_interpose::Layer>]);
        domain.run(|| {
            assert!(readiness().wait_until("delayed arrival", None, || {
                arrival.ready.load(Ordering::SeqCst)
            }));
        });
    }

    #[test]
    fn deterministic_dynamic_subscriptions_refresh_their_sources() {
        crate::Sim::builder()
            .deterministic()
            .seed(17)
            .build()
            .run(|| {
                let board = Arc::new(Readiness {
                    state: Mutex::new(State {
                        waiters: Vec::new(),
                        spare: Vec::new(),
                        next_waiter: 0,
                    }),
                });
                let source = Arc::new(AtomicUsize::new(7));
                let ready = Arc::new(AtomicBool::new(false));
                let checks = Arc::new(AtomicUsize::new(0));
                let waiter = {
                    let board = board.clone();
                    let source = source.clone();
                    let ready = ready.clone();
                    let checks = checks.clone();
                    std::thread::spawn(move || {
                        board.wait_until_dynamic(
                            "dynamic subscription",
                            None,
                            |keys| {
                                keys.push(WakeKey::Socket(source.load(Ordering::SeqCst) as u64));
                                false
                            },
                            || {
                                checks.fetch_add(1, Ordering::SeqCst);
                                ready.load(Ordering::SeqCst)
                            },
                        )
                    })
                };
                while checks.load(Ordering::SeqCst) == 0 {
                    std::thread::yield_now();
                }
                let before = checks.load(Ordering::SeqCst);
                board.bump_keys(snare_interpose::domain_key(), &[WakeKey::Socket(8)]);
                std::thread::yield_now();
                let before_change = checks.load(Ordering::SeqCst);
                source.store(8, Ordering::SeqCst);
                board.bump_keys(snare_interpose::domain_key(), &[WakeKey::Socket(7)]);
                std::thread::yield_now();
                let after_change = checks.load(Ordering::SeqCst);
                board.bump_keys(snare_interpose::domain_key(), &[WakeKey::Socket(7)]);
                std::thread::yield_now();
                let after_old_source = checks.load(Ordering::SeqCst);
                ready.store(true, Ordering::SeqCst);
                board.bump_keys(snare_interpose::domain_key(), &[WakeKey::Socket(8)]);
                assert!(waiter.join().unwrap());
                assert_eq!(before_change, before);
                assert_eq!(after_change, before + 1);
                assert_eq!(after_old_source, after_change);
            });
    }

    #[test]
    fn deterministic_subscriptions_ignore_other_sources_and_accept_matching_wakes() {
        for event in [
            WakeEvent::Keys(&[WakeKey::Socket(8)]),
            WakeEvent::Timer,
            WakeEvent::All,
        ] {
            crate::Sim::builder()
                .deterministic()
                .seed(11)
                .build()
                .run(|| {
                    let board = Arc::new(Readiness {
                        state: Mutex::new(State {
                            waiters: Vec::new(),
                            spare: Vec::new(),
                            next_waiter: 0,
                        }),
                    });
                    let ready = Arc::new(AtomicBool::new(false));
                    let checks = Arc::new(AtomicUsize::new(0));
                    let waiter = {
                        let board = board.clone();
                        let ready = ready.clone();
                        let checks = checks.clone();
                        std::thread::spawn(move || {
                            board.wait_until_on(
                                "subscription",
                                None,
                                &[WakeKey::Socket(7), WakeKey::Socket(8)],
                                || matches!(event, WakeEvent::Timer),
                                || {
                                    checks.fetch_add(1, Ordering::SeqCst);
                                    ready.load(Ordering::SeqCst)
                                },
                            )
                        })
                    };
                    while checks.load(Ordering::SeqCst) == 0 {
                        std::thread::yield_now();
                    }
                    let before = checks.load(Ordering::SeqCst);
                    for _ in 0..1000 {
                        board.bump_keys(snare_interpose::domain_key(), &[WakeKey::Socket(99)]);
                        #[cfg(unix)]
                        board.bump_keys(snare_interpose::domain_key(), &[WakeKey::Descriptor(8)]);
                        if !matches!(event, WakeEvent::Timer) {
                            board.bump_time(snare_interpose::domain_key());
                        }
                        std::thread::yield_now();
                    }
                    let after = checks.load(Ordering::SeqCst);
                    ready.store(true, Ordering::SeqCst);
                    board.bump_event(snare_interpose::domain_key(), event, true);
                    assert!(waiter.join().unwrap());
                    assert_eq!(
                        after, before,
                        "unrelated readiness sources reached a deterministic wait"
                    );
                });
        }
    }

    #[test]
    fn subscriptions_filter_traffic_and_accept_each_wake_source() {
        for event in [
            WakeEvent::Keys(&[WakeKey::Socket(8)]),
            WakeEvent::Timer,
            WakeEvent::All,
        ] {
            let board = Arc::new(Readiness {
                state: Mutex::new(State {
                    waiters: Vec::new(),
                    spare: Vec::new(),
                    next_waiter: 0,
                }),
            });
            let ready = Arc::new(AtomicBool::new(false));
            let checks = Arc::new(AtomicUsize::new(0));
            let waiter = {
                let board = board.clone();
                let ready = ready.clone();
                let checks = checks.clone();
                std::thread::spawn(move || {
                    board.wait_until_on(
                        "subscription",
                        None,
                        &[WakeKey::Socket(7), WakeKey::Socket(8)],
                        || matches!(event, WakeEvent::Timer),
                        || {
                            checks.fetch_add(1, Ordering::SeqCst);
                            ready.load(Ordering::SeqCst)
                        },
                    )
                })
            };
            let limit = Instant::now() + Duration::from_secs(5);
            while !board
                .state
                .lock()
                .unwrap()
                .waiters
                .iter()
                .any(|w| w.sleeping > 0)
            {
                assert!(Instant::now() < limit, "waiter never slept");
                std::thread::yield_now();
            }
            let before = checks.load(Ordering::SeqCst);
            let started = Instant::now();
            for _ in 0..1_000 {
                board.bump_keys(0, &[WakeKey::Socket(99)]);
            }
            let periodic = started.elapsed().as_millis() / QUIESCENCE_POLL.as_millis() + 1;
            assert!(checks.load(Ordering::SeqCst) - before <= periodic as usize);
            ready.store(true, Ordering::SeqCst);
            board.bump_event(0, event, false);
            assert!(waiter.join().unwrap());
            assert!(!board.settling(0));
        }
    }
    #[test]
    fn broadcast_notifications_follow_the_complete_unlocked_state_update() {
        crate::Sim::new().run(|| {
            let board = Readiness {
                state: Mutex::new(State {
                    waiters: Vec::new(),
                    spare: Vec::new(),
                    next_waiter: 0,
                }),
            };
            {
                let mut state = board.state.lock().unwrap();
                for _ in 0..40 {
                    state.register(7, None);
                }
                for waiter in &mut state.waiters {
                    waiter.sleeping = 1;
                }
            }
            let mut notified = Vec::new();
            board.notify_bump(7, WakeEvent::All, |changed| {
                let state = board
                    .state
                    .try_lock()
                    .expect("notification under state lock");
                assert!(
                    state
                        .waiters
                        .iter()
                        .all(|w| { w.generation == 1 && w.stale == 1 && w.sleeping == 1 })
                );
                notified.push(Arc::as_ptr(changed));
            });
            notified.sort_unstable();
            notified.dedup();
            assert_eq!(notified.len(), 40);
        });
    }

    #[test]
    fn published_kicks_preserve_layer_wakes_without_a_second_generation() {
        struct WakeSpy {
            calls: AtomicUsize,
            domain: AtomicUsize,
        }
        impl snare_interpose::Layer for WakeSpy {
            fn wake_waiters(&self, domain: usize) {
                self.domain.store(domain, Ordering::SeqCst);
                self.calls.fetch_add(1, Ordering::SeqCst);
            }
        }

        crate::Sim::new().run(|| {
            let spy = Arc::new(WakeSpy {
                calls: AtomicUsize::new(0),
                domain: AtomicUsize::new(0),
            });
            let clock = Arc::new(crate::clock::Clock::new(0));
            let domain = snare_interpose::Domain::new([
                spy.clone() as Arc<dyn snare_interpose::Layer>,
                Arc::new(crate::clock::ClockLayer(clock)),
            ]);
            let board = readiness();
            let id = board.state.lock().unwrap().register(domain.key(), None);
            let _subscription = Subscription {
                readiness: board,
                id,
            };
            let generation = || {
                board
                    .state
                    .lock()
                    .unwrap()
                    .waiters
                    .iter()
                    .find(|waiter| waiter.id == id)
                    .unwrap()
                    .generation
            };

            board.bump(domain.key());
            let published = generation();
            domain.kick_after_readiness();
            assert_eq!(generation(), published);
            assert_eq!(spy.calls.load(Ordering::SeqCst), 1);
            assert_eq!(spy.domain.load(Ordering::SeqCst), domain.key());
            domain.kick();
            assert_eq!(generation(), published + 1);
            assert_eq!(spy.calls.load(Ordering::SeqCst), 2);
        });
    }
}
