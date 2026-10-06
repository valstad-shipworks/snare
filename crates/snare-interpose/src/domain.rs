//! Domains: the unit a simulation runs in, and the per-thread plumbing that routes a hooked OS call
//! to it.
//!
//! A [`Domain`] owns a stack of [`Layer`]s plus optional [`Net`], [`Fs`], [`Host`], [`Env`],
//! [`Resolver`] and [`Signals`] backends. A thread becomes *managed* by it through
//! [`Domain::enter`] (a root) or by being created by a managed thread ([`inherit`] / [`adopt`]);
//! the domain pointer lives in the thread-local `state`, and every hook asks
//! `state::domain()` / `state::passthrough()` to decide whether a call goes to the sim or the OS.
//! The sim's own code runs under [`Passthrough`] so its OS calls never loop back into itself.
//!
//! The domain also keeps the census its clock depends on: how many participants are live
//! (`Inner::participants`), how many are parked (`parked`, `sim_parked`), the per-thread rows,
//! leases and the timestamp gate in [`Accounting`]. *Quiescence* — every participant parked, none
//! settling, no lease held — is the one condition under which virtual time may skip and a sim wait
//! may give up as deadlocked. Built `deterministic`, it adds a [`crate::sched::Scheduler`] that
//! runs participants one at a time.
//!
//! Each managed thread has a *lineage*: a 64-bit id derived from its place in the domain's spawn
//! tree, not from OS scheduling, so per-thread state seeded from it and the deterministic
//! schedule's order replay exactly.
//!
//! Lock order: where both are held, the census lock (`Accounting::core`) is taken before the
//! scheduler's state lock ([`Domain::if_quiescent`], [`Domain::quiescence`]); the scheduler holds
//! its own lock across time skips, which take the skip gate (`Accounting::skip_gate`) and layer
//! locks after it. Callbacks armed with [`Domain::arm`] run when an [`EpochBump`] drops, so a
//! caller drops it only after releasing its own locks. The sim's locks are taken under
//! [`Passthrough`] on paths a managed thread runs, so a contended std mutex's own futex or
//! address wait is not counted as the code under test's native wait.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::accounting::{
    self, Accounting, AuditReport, BlockerKind, ClassEffect, Core, EpochBump, LeaseId, LeaseInfo,
    LeaseKind, PState, ParticipantInfo, Quiescence, QuiescenceViolation, RowWait, ThreadClass,
};
use crate::census::SimId;
use crate::env::Env;
use crate::fs::Fs;
use crate::host::Host;
use crate::layer::{Flow, Layer, Unmodelled};
use crate::net::Net;
use crate::resolve::Resolver;
use crate::signals::Signals;
use crate::state::{self, Passthrough};

#[cfg(windows)]
pub(crate) type TimerWordWake = (usize, usize, Arc<dyn Send + Sync>);

#[cfg(windows)]
thread_local! {
    static SKIP_YIELD: std::cell::Cell<(usize, Option<bool>)> = const { std::cell::Cell::new((0, None)) };
}

#[cfg(windows)]
struct SkipYield((usize, Option<bool>));

#[cfg(windows)]
impl SkipYield {
    fn enter(domain: usize, yielding: Option<bool>) -> Self {
        Self(SKIP_YIELD.with(|mode| mode.replace((domain, yielding))))
    }
}

#[cfg(windows)]
impl Drop for SkipYield {
    fn drop(&mut self) {
        SKIP_YIELD.with(|mode| mode.set(self.0));
    }
}

/// The shared state behind a [`Domain`] handle. Managed threads hold a strong count on it through
/// the raw pointer installed in their thread-local `state` (see [`Managed`]), so it outlives every
/// thread it manages.
pub(crate) struct Inner {
    /// The layer stack, offered each hooked call first to last; the first to answer
    /// [`Flow::Done`] handles it.
    layers: Vec<Arc<dyn Layer>>,
    /// The net backends, tried in order: the first whose call returns `Some` handles it, so a call
    /// a backend declines (`None`) falls through to the next and finally to the OS. This lets a
    /// `SimHost` (NIC ioctls, netlink, UDP) and a plain socket `Fabric` (TCP, raw L2) serve one
    /// domain together — ordered so the host claims what it models and the fabric takes the rest.
    #[cfg_attr(not(unix), allow(dead_code))]
    net: Vec<Arc<dyn Net>>,
    /// The file backend; see `dispatch_fs`.
    #[cfg_attr(not(unix), allow(dead_code))]
    fs: Option<Arc<dyn Fs>>,
    /// The process/scheduler backend; see [`dispatch_host`].
    #[allow(dead_code)] // read once the Host symbol hooks land
    host: Option<Arc<dyn Host>>,
    /// The environment-variable backend; see [`dispatch_env`].
    #[cfg_attr(not(unix), allow(dead_code))]
    env: Option<Arc<dyn Env>>,
    /// The name-lookup backend; see [`dispatch_resolver`].
    resolver: Option<Arc<dyn Resolver>>,
    /// The signal-disposition table; see [`dispatch_signals`]. Without one, signals aimed at the
    /// domain's threads go to the OS.
    signals: Option<Arc<dyn Signals>>,
    /// How many threads [`Domain::spawn_injected`] has started, for their lineages.
    injected: AtomicU64,
    /// How many times a thread has entered the domain ([`Domain::enter`]), for root lineages.
    entries: AtomicU64,
    /// Signals `pthread_kill` aimed at another of the domain's threads, by lineage, as bitmasks
    /// with bit `n` for signal `n` (see `post_signal`).
    #[cfg_attr(not(unix), allow(dead_code))]
    thread_signals: Mutex<std::collections::HashMap<u64, u64>>,
    /// Whether `thread_signals` may be non-empty: a lock-free fast check so every hooked call
    /// (see [`drain_signals`]) need not take the lock.
    #[cfg_attr(not(unix), allow(dead_code))]
    signals_pending: AtomicBool,
    /// Every unmodelled call the domain's threads made, with its count; see [`observe`].
    unmodelled: Mutex<BTreeMap<Unmodelled, u64>>,
    /// Count of the participants this domain currently manages — the basis for quiescence
    /// detection (a blocking sim wait that finds every participant parked knows no progress is
    /// possible). Threads of the other classes are left out.
    participants: AtomicUsize,
    /// Count of this domain's participants currently blocked in an in-memory wait. Per-domain
    /// (unlike the fabric's process-global readiness) so quiescence stays correct when tests run in
    /// parallel in one process.
    parked: AtomicUsize,
    /// Of `parked`, the participants in a sim wait: one that gives up once the domain is quiescent
    /// with no time left to pass. The rest wait natively (a join, a lock) and never give up.
    sim_parked: AtomicUsize,
    /// Participants caught in a spin (see [`clock_spin`]): running, but waiting on time like the
    /// parked ones. Not counted in `parked`, so no sim wait takes the domain for quiescent while
    /// one spins.
    spinning: AtomicUsize,
    /// Of `spinning`, the participants whose spin polls the clock, and so waits on a deadline of
    /// its own that a full time skip could jump past.
    clock_spinning: AtomicUsize,
    /// The census (per-thread rows, leases, the timestamp gate, the epoch, an executive's audit),
    /// behind its own lock.
    accounting: Accounting,
    /// Runs the domain's threads one at a time in a fixed order, when built `deterministic`.
    sched: Option<crate::sched::Scheduler>,
    #[cfg(windows)]
    timer_word_wakes: Mutex<Vec<TimerWordWake>>,
    /// The busy-stall watchdog, when built with [`DomainBuilder::stuck_after`]; stopped on drop.
    watchdog: std::sync::OnceLock<Arc<crate::stall::Watchdog>>,
    /// How many threads are inside the domain through [`Domain::enter`]: its runs in progress.
    /// Locked across the layers' [`Layer::dormant`] calls, so they arrive in the order the runs
    /// begin and end.
    runs: Mutex<usize>,
    /// Every run that began has ended, so the threads still managed are left over from one (see
    /// [`Layer::dormant`]). `false` until the first run ends.
    dormant: AtomicBool,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(watchdog) = self.watchdog.get() {
            watchdog.stop();
        }
    }
}

impl Inner {
    /// A fresh root for a thread entering the domain: 0 for the first entry, and for each later
    /// one an id of its own, so the threads a run spawns never share a lineage with threads an
    /// earlier run left alive.
    fn root_lineage(&self) -> Lineage {
        let entry = self.entries.fetch_add(1, Ordering::SeqCst);
        let id = if entry == 0 {
            0
        } else {
            mix_lineage(ROOT_SALT, entry)
        };
        Lineage { id, children: 0 }
    }

    /// This domain's [`Domain::key`].
    fn key(&self) -> usize {
        ptr::from_ref(self) as usize
    }

    /// Whether any layer has woken a waiter of this domain that has yet to run (see
    /// [`Layer::settling`]).
    fn settling(&self) -> bool {
        let key = self.key();
        self.layers.iter().any(|layer| layer.settling(key))
    }

    /// Counts a thread into the domain through [`Domain::enter`]; the first ends a dormant spell.
    fn begin_run(&self) {
        let _passthrough = Passthrough::enter();
        let mut runs = self.runs.lock().unwrap_or_else(|e| e.into_inner());
        if *runs == 0 && self.dormant.swap(false, Ordering::SeqCst) {
            for layer in &self.layers {
                layer.dormant(false);
            }
        }
        *runs += 1;
    }

    /// Counts a thread that entered through [`Domain::enter`] out again; the last to leave makes
    /// the domain dormant and wakes the waiters left over, so they re-time their waits.
    fn end_run(&self) {
        let _passthrough = Passthrough::enter();
        let mut runs = self.runs.lock().unwrap_or_else(|e| e.into_inner());
        *runs = runs.saturating_sub(1);
        if *runs > 0 {
            return;
        }
        self.dormant.store(true, Ordering::SeqCst);
        for layer in &self.layers {
            layer.dormant(true);
        }
        drop(runs);
        self.wake_waiters();
    }

    /// The first layer's answer to [`Layer::virtual_now`]; see the free [`virtual_now`].
    fn virtual_now(&self) -> Option<std::time::Duration> {
        self.layers.iter().find_map(|layer| layer.virtual_now())
    }

    /// The first layer's answer to [`Layer::real_span`]; see the free [`real_span`].
    fn real_span(&self, span: std::time::Duration) -> Option<std::time::Duration> {
        self.layers.iter().find_map(|layer| layer.real_span(span))
    }

    /// The first layer's answer to [`Layer::idle_wait`]; see the free [`idle_wait`].
    fn idle_wait(&self) -> Option<std::time::Duration> {
        self.layers.iter().find_map(|layer| layer.idle_wait())
    }

    /// The virtual and real time a thread's row changes state at, kept only while an executive is
    /// attached.
    fn row_stamp(&self) -> Option<(std::time::Duration, std::time::Duration)> {
        self.accounting.attached().then(|| {
            (
                self.virtual_now().unwrap_or_default(),
                accounting::real_elapsed(),
            )
        })
    }

    /// The name a thread is listed under: `"executive"` for [`crate::sched::EXTERNAL`], else its
    /// own name, else one made from its lineage. Allocates under passthrough, so the allocator's
    /// own OS calls (a contended lock, an `mmap`) are not taken for the code under test's.
    fn display_name(&self, lineage: u64) -> Arc<str> {
        if lineage == crate::sched::EXTERNAL {
            let _passthrough = Passthrough::enter();
            return Arc::from("executive");
        }
        self.thread_name(lineage)
            .unwrap_or_else(|| accounting::fallback_name(lineage))
    }

    /// The first running participant's name, for a blocker.
    fn first_running(&self, core: &Core) -> Arc<str> {
        let running = core
            .rows
            .iter()
            .find(|(_, row)| row.class == ThreadClass::Participant && row.wait.is_none())
            .map(|(&lineage, _)| lineage);
        match running {
            Some(lineage) => self.display_name(lineage),
            None => {
                let _passthrough = Passthrough::enter();
                Arc::from("participant")
            }
        }
    }

    /// What keeps the domain from being quiescent for an executive, checked under the census lock
    /// (and the schedule's, when deterministic), most pressing first; `None` when it is quiescent.
    fn blocker(
        &self,
        core: &mut Core,
        settling: bool,
        sched: Option<&crate::sched::State>,
        due: impl FnOnce() -> Option<Arc<str>>,
    ) -> Option<(BlockerKind, Arc<str>)> {
        let _passthrough = Passthrough::enter();
        #[cfg(windows)]
        self.accounting.flush_timer_signals(core);
        match sched {
            Some(st) => {
                if let Some(lineage) = st.running() {
                    return Some((BlockerKind::Runnable, self.display_name(lineage)));
                }
            }
            None => {
                if self.parked.load(Ordering::SeqCst) < self.participants.load(Ordering::SeqCst) {
                    return Some((BlockerKind::Runnable, self.first_running(core)));
                }
            }
        }
        if settling {
            return Some((BlockerKind::Settling, Arc::from("woken waiter")));
        }
        if core.released > 0 {
            return Some((BlockerKind::Settling, Arc::from("released joiner")));
        }
        if core.gated > 0 && !core.gate_closed {
            return Some((BlockerKind::Settling, Arc::from("timestamp gate release")));
        }
        if let Some(lineage) = core.first_released() {
            return Some((BlockerKind::Settling, self.display_name(lineage)));
        }
        if let Some((label, kind)) = self.accounting.first_lease() {
            let blocker = match kind {
                LeaseKind::Setup => BlockerKind::Setup,
                _ => BlockerKind::Lease,
            };
            return Some((blocker, Arc::from(label)));
        }
        if core.gated > 0 {
            return Some((BlockerKind::Deferred, Arc::from("timestamp gate")));
        }
        due().map(|owner| (BlockerKind::TimerDue, owner))
    }

    /// Every participant is parked, none is waking (`settling`, a timed wait the clock reached that
    /// its thread has yet to take, or a native wait the OS released it from) and no lease holds the
    /// domain busy: no participant can make progress until time does.
    ///
    /// The waking checks come before the parked count: a thread leaving a native wait counts itself
    /// running before it takes its release or its timed wait, so if either is gone by the time it
    /// is read, the count read after it shows the thread running.
    fn quiescent(&self, settling: bool) -> bool {
        if settling || self.accounting.leases_held() || self.wait_due() || self.released() {
            return false;
        }
        let live = self.participants.load(Ordering::SeqCst);
        live > 0 && self.parked.load(Ordering::SeqCst) >= live
    }

    /// Whether a participant the OS has released from a native wait (woken on its address, or its
    /// joined thread gone) has yet to count itself running: it still counts as parked meanwhile.
    /// So has one in a contended lock no other thread of the domain holds (see
    /// [`Inner::lock_unheld`]).
    fn released(&self) -> bool {
        let _passthrough = Passthrough::enter();
        let core = self.accounting.core();
        core.released > 0 || core.has_pending_releases() || core.first_unheld_lock().is_some()
    }

    /// Whether a participant counted parked in a contended pthread mutex waits on no other thread
    /// of this domain: the mutex is free or its own, about to return, or held by a thread outside
    /// the domain (another test's, an unmanaged one), which nothing here will make let go. Until it
    /// takes the lock the domain is not quiescent, so time does not skip past whatever it does
    /// next. Reads the census only while a mutex is watched.
    fn lock_unheld(&self) -> bool {
        if self.accounting.watching.load(Ordering::SeqCst) == 0 {
            return false;
        }
        let _passthrough = Passthrough::enter();
        self.accounting.core().first_unheld_lock().is_some()
    }

    /// Whether a layer's clock reached a participant's timed wait its thread has yet to take (see
    /// [`Layer::wait_due`]); never under a deterministic schedule, which runs the threads a time
    /// skip released before it moves time again.
    fn wait_due(&self) -> bool {
        if self.sched.is_some() {
            return false;
        }
        let _passthrough = Passthrough::enter();
        self.layers.iter().any(|layer| layer.wait_due())
    }

    /// Quiescent outside a deterministic schedule with every participant parked in a wait that never
    /// gives up: only a thread of another class can release them, so its timers may move time.
    fn stalled(&self, settling: bool) -> bool {
        self.sched.is_none()
            && self.quiescent(settling)
            && self.sim_parked.load(Ordering::SeqCst) == 0
    }

    /// Asks every layer to wake its blocked waiters to re-check (see [`Layer::wake_waiters`]).
    fn wake_waiters(&self) {
        let _passthrough = Passthrough::enter();
        let key = self.key();
        for layer in &self.layers {
            layer.wake_waiters(key);
        }
    }

    /// Whether any layer fired wakers from inside the sim since last asked, clearing each layer's
    /// flag (see [`Layer::take_timer_wakes`]). Every layer is asked, not just the first to say yes.
    fn take_timer_wakes(&self) -> bool {
        let _passthrough = Passthrough::enter();
        self.layers
            .iter()
            .fold(false, |woke, layer| layer.take_timer_wakes() | woke)
    }

    /// Whether the calling thread is managed by this domain.
    fn is_current(&self) -> bool {
        ptr::eq(state::domain(), self)
    }

    /// The name of the thread with this lineage: the one recorded when it named itself, else the
    /// one the OS holds for it, which also covers names set before the interposer was installed or
    /// through a function pointer cached before then.
    fn thread_name(&self, lineage: u64) -> Option<Arc<str>> {
        if let Some(name) = self.accounting.name(lineage) {
            return Some(name);
        }
        let _passthrough = Passthrough::enter();
        let handle = if self.is_current() && thread_lineage() == lineage {
            None
        } else {
            Some(self.accounting.handle_of(lineage)?)
        };
        crate::os::thread_name(handle).map(Arc::from)
    }
}

/// A stack of layers that managed threads' OS calls are offered to, first to last.
#[derive(Clone)]
pub struct Domain(Arc<Inner>);

/// A [`Domain`] reference that does not keep it alive, for a sim service that outlives or is
/// shared with the domain (a clock controlled from outside the run).
#[derive(Clone)]
pub struct WeakDomain(std::sync::Weak<Inner>);

impl std::fmt::Debug for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Domain").field(&self.id()).finish()
    }
}

impl std::fmt::Debug for WeakDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("WeakDomain")
            .field(&self.upgrade().map(|domain| domain.id()))
            .finish()
    }
}

impl WeakDomain {
    /// The domain, if it still exists.
    pub fn upgrade(&self) -> Option<Domain> {
        self.0.upgrade().map(Domain)
    }

    /// The domain's [`Domain::key`], read without upgrading; once the domain is gone a later one
    /// may share it.
    pub fn key(&self) -> usize {
        self.0.as_ptr() as usize
    }
}

impl Domain {
    /// Creates a domain, calling [`install`](crate::install) first if nothing has yet.
    pub fn new(layers: impl IntoIterator<Item = Arc<dyn Layer>>) -> Self {
        Self::build(layers, None)
    }

    /// Creates a domain whose managed threads' socket calls are serviced by `net`.
    pub fn with_net(layers: impl IntoIterator<Item = Arc<dyn Layer>>, net: Arc<dyn Net>) -> Self {
        Self::build(layers, Some(net))
    }

    fn build(layers: impl IntoIterator<Item = Arc<dyn Layer>>, net: Option<Arc<dyn Net>>) -> Self {
        let mut builder = DomainBuilder::default().layers(layers);
        builder.net = net.into_iter().collect();
        builder.install()
    }

    /// Starts a [`DomainBuilder`] for composing several backends.
    pub fn builder() -> DomainBuilder {
        DomainBuilder::default()
    }

    /// Makes the calling thread managed by this domain until the guard drops.
    ///
    /// Guards nest; each restores what the thread was before it. Drop them in reverse order.
    ///
    /// The thread becomes a participant with a fresh root lineage (`Inner::root_lineage`), is
    /// counted live before its row is added, and under a deterministic schedule waits here until it
    /// holds the baton (`Scheduler::enter_root`). It counts as a run in progress until the guard
    /// drops: the domain is dormant (see [`is_dormant`](Self::is_dormant)) once none is.
    pub fn enter(&self) -> Managed {
        self.0.begin_run();
        self.0.participants.fetch_add(1, Ordering::SeqCst);
        let domain = Arc::into_raw(self.0.clone());
        let mut managed = Managed {
            previous: state::replace_domain(domain),
            domain,
            root: true,
            previous_lineage: swap_lineage(self.0.root_lineage()),
            previous_class: accounting::swap_class(ThreadClass::Participant, None),
            previous_held: ptr::null(),
            _not_send: PhantomData,
        };
        self.0
            .accounting
            .record_handle(crate::os::current_thread_handle(), thread_lineage());
        let held = self
            .0
            .accounting
            .add_row(thread_lineage(), ThreadClass::Participant);
        managed.previous_held = accounting::swap_held(held);
        if let Some(sched) = &self.0.sched {
            sched.enter_root(thread_lineage());
        }
        managed
    }

    /// Runs `f` on the calling thread managed by this domain: [`enter`](Self::enter) for the
    /// duration of the call.
    pub fn run<R>(&self, f: impl FnOnce() -> R) -> R {
        let _managed = self.enter();
        f()
    }

    /// Unmodelled calls reported by registered hooks, with how often.
    ///
    /// An empty report does not cover unhooked functions, direct process-global reads or CPU
    /// instructions.
    pub fn unmodelled(&self) -> Vec<(Unmodelled, u64)> {
        let calls = self.0.unmodelled.lock().unwrap_or_else(|e| e.into_inner());
        calls.iter().map(|(call, count)| (*call, *count)).collect()
    }

    /// Forgets the unmodelled calls recorded so far, e.g. those made during setup.
    pub fn clear_unmodelled(&self) {
        self.0
            .unmodelled
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// A [`WeakDomain`] for this domain.
    pub fn downgrade(&self) -> WeakDomain {
        WeakDomain(Arc::downgrade(&self.0))
    }

    #[cfg(windows)]
    pub(crate) fn register_timer_wake(
        &self,
        at: std::time::Duration,
        waker: std::task::Waker,
        foreign: bool,
    ) -> Option<u64> {
        let _pass = Passthrough::enter();
        let wake = self
            .0
            .layers
            .iter()
            .find_map(|layer| layer.register_owned_wake(at, waker.clone(), foreign));
        if foreign && wake.is_some() {
            offer_idle_skip(Arc::as_ptr(&self.0));
        }
        wake
    }

    #[cfg(windows)]
    pub(crate) fn cancel_timer_wake(&self, key: u64) {
        let _passthrough = Passthrough::enter();
        for layer in &self.0.layers {
            layer.cancel_wake(key);
        }
    }

    #[cfg(windows)]
    pub(crate) fn wake_timer_waiters(&self, handle: usize) {
        let _passthrough = Passthrough::enter();
        if let Some(sched) = &self.0.sched {
            sched.wake(crate::DetKey::Addr(handle), usize::MAX);
        }
    }

    #[cfg(windows)]
    pub(crate) fn timer_now(&self) -> Option<std::time::Duration> {
        self.0.virtual_now()
    }

    #[cfg(windows)]
    pub(crate) fn timer_due(&self, deadline: std::time::Duration) -> bool {
        self.0.virtual_now().is_some_and(|now| now >= deadline)
    }

    #[cfg(windows)]
    pub(crate) fn signal_timer_waiters(
        &self,
        handle: usize,
        lifetime: Arc<dyn Send + Sync>,
        signal: impl FnOnce() -> usize,
    ) {
        let _passthrough = Passthrough::enter();
        // A scheduler can reactivate while a timer callback is running.
        if self.0.sched.is_some() {
            self.0
                .accounting
                .defer_timer_signal(handle, lifetime, signal);
            return;
        }
        let mut core = self.0.accounting.core();
        self.0
            .accounting
            .defer_timer_signal(handle, lifetime, signal);
        self.0.accounting.flush_timer_signals(&mut core);
        core.clear_quiet();
    }

    #[cfg(windows)]
    pub(crate) fn timer_probe<R>(&self, probe: impl FnOnce(&mut dyn FnMut(usize)) -> R) -> R {
        let _passthrough = Passthrough::enter();
        if accounting::timer_admitting() {
            return probe(&mut accounting::timer_consumed);
        }
        let mut core = self.0.accounting.core();
        let mut signals = self.0.accounting.timer_signals();
        self.0
            .accounting
            .drain_timer_signals(&mut core, &mut signals);
        probe(&mut |key| core.consume_timer_event(key))
    }

    #[cfg(windows)]
    pub(crate) fn queue_timer_word_wake(
        &self,
        key: usize,
        count: usize,
        lifetime: Arc<dyn Send + Sync>,
    ) {
        let _pass = Passthrough::enter();
        if self.0.sched.as_ref().is_some_and(|sched| !sched.detached()) {
            self.0
                .timer_word_wakes
                .lock()
                .unwrap()
                .push((key, count, lifetime));
        }
    }

    /// Tells the domain that something outside its threads' own calls changed — the clock was
    /// moved, paused or resumed from any thread, managed or not. Its layers wake their blocked
    /// waiters to re-check, and a deterministic schedule releases the waits that are now due and
    /// hands the baton on if no thread holds it.
    pub fn kick(&self) {
        self.kick_layers(false);
    }

    /// As [`kick`](Self::kick) after a full readiness broadcast for this domain. Layers sharing
    /// that readiness board may omit its publication; other layer wakeups and timer releases run.
    pub fn kick_after_readiness(&self) {
        self.kick_layers(true);
    }

    fn kick_layers(&self, readiness_published: bool) {
        let _passthrough = Passthrough::enter();
        let key = self.key();
        for layer in &self.0.layers {
            if readiness_published {
                layer.wake_waiters_after_readiness(key);
            } else {
                layer.wake_waiters(key);
            }
        }
        if let Some(sched) = &self.0.sched {
            sched.kick(self.0.virtual_now(), self.0.take_timer_wakes());
        }
    }

    /// As [`kick`](Self::kick) after a clock move that reached no timer, event or wait of the
    /// layers': only a deterministic schedule's own timed waits the clock reached are released, and
    /// no other waiter is woken to re-check, so a domain that was quiescent stays so.
    pub fn kick_due(&self) {
        if let Some(sched) = &self.0.sched {
            let _passthrough = Passthrough::enter();
            sched.release_due_at(self.0.virtual_now());
        }
    }

    /// Whether every participant is parked, none still waking (`settling`, as the caller's backend
    /// knows it) and no lease is held: the one test for a domain that cannot progress until time
    /// does.
    pub fn quiescent(&self, settling: bool) -> bool {
        self.0.quiescent(settling)
    }

    /// Holds the domain busy until [`release_lease`](Self::release_lease): it is never quiescent
    /// meanwhile, so time does not skip and blocked waits do not give up. Once this returns no time
    /// skip is in flight, so none lands after it. `label` says why, for diagnostics.
    pub fn take_lease(&self, label: &'static str) -> LeaseId {
        self.take_lease_of(label, LeaseKind::Busy)
    }

    /// [`take_lease`](Self::take_lease), for a lease of `kind`.
    pub fn take_lease_of(&self, label: &'static str, kind: LeaseKind) -> LeaseId {
        let holder = self.0.is_current().then(thread_lineage);
        let (id, bump) = self.0.accounting.take_lease(label, kind, holder);
        drop(bump);
        id
    }

    /// Gives back a lease from [`take_lease`](Self::take_lease) and wakes the domain's waiters to
    /// re-check, from any thread.
    pub fn release_lease(&self, id: LeaseId) {
        if let Some(bump) = self.0.accounting.release_lease(id) {
            drop(bump);
            self.kick();
            offer_idle_skip(Arc::as_ptr(&self.0));
        }
    }

    /// The leases held, oldest first.
    pub fn leases(&self) -> Vec<LeaseInfo> {
        self.0
            .accounting
            .leases()
            .into_iter()
            .map(|(label, kind, holder)| LeaseInfo {
                label,
                kind,
                holder: holder.map(|lineage| self.0.display_name(lineage)),
            })
            .collect()
    }

    /// A counter that moves on whenever the domain's quiescence may have changed: a participant
    /// parking or waking, a class change, a lease taken or given back, a deterministic schedule
    /// going idle.
    pub fn epoch(&self) -> u64 {
        self.0.accounting.epoch()
    }

    /// Runs `callback` once [`epoch`](Self::epoch) has moved past `seen`: at once if it already
    /// has, otherwise on the thread that next moves it, under passthrough and with no lock of the
    /// domain held. One callback is armed at a time; a later arm replaces it.
    pub fn arm(&self, seen: u64, callback: Arc<dyn Fn() + Send + Sync>) {
        self.0.accounting.arm(seen, callback);
    }

    /// Notes that `source` is starved of something with `severity`, for the domain's driver to
    /// collect with [`take_hints`](Self::take_hints).
    pub fn push_hint(&self, source: &str, severity: f32) {
        self.0.accounting.push_hint(source, severity);
    }

    /// The hints pushed since the last call, oldest first.
    pub fn take_hints(&self) -> Vec<(Arc<str>, f32)> {
        self.0.accounting.take_hints()
    }

    /// The name the thread with this lineage gave itself (`pthread_setname_np`,
    /// `SetThreadDescription`, std's `Builder::name`) or was given, if any. (man 3
    /// pthread_setname_np; [Microsoft Learn: SetThreadDescription function](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreaddescription))
    pub fn thread_name(&self, lineage: u64) -> Option<Arc<str>> {
        self.0.thread_name(lineage)
    }

    /// Hands the domain to an executive that moves its time from outside: its census is kept with
    /// timestamps, and with `audit` it logs effects and calls it cannot account for. `false` if an
    /// executive is already attached.
    pub fn attach_executive(&self, audit: bool) -> bool {
        self.0.accounting.attach(audit)
    }

    /// Ends an executive's ownership: an open timestamp's gate opens and its baton is let go.
    pub fn detach_executive(&self) {
        self.0.accounting.detach();
        if let Some(sched) = &self.0.sched {
            sched.release_external();
        }
        drop(self.0.accounting.bump());
    }

    /// Whether an executive owns this domain's time.
    pub fn executive_attached(&self) -> bool {
        self.0.accounting.attached()
    }

    /// Opens a timestamp: participants woken from here on wait at the gate until
    /// [`end_timestamp`](Self::end_timestamp), and a deterministic schedule is held by the caller
    /// once every thread in it has blocked.
    pub fn begin_timestamp(&self) {
        if let Some(sched) = &self.0.sched {
            sched.acquire_external();
        }
        let _passthrough = Passthrough::enter();
        self.0.accounting.core().gate_closed = true;
    }

    /// Closes a timestamp: the gate opens, and a deterministic schedule held by the caller moves on.
    pub fn end_timestamp(&self) {
        {
            let _passthrough = Passthrough::enter();
            let mut core = self.0.accounting.core();
            self.0.accounting.open_gate(&mut core);
        }
        if let Some(sched) = &self.0.sched {
            sched.release_external();
        }
    }

    /// Runs `f` only if the domain is quiescent, with the census (and a deterministic schedule)
    /// locked across the check and `f`, so no participant can start running in between. The caller
    /// holds its readiness lock and passes whether a waiter it woke has yet to run; `due` names the
    /// owner of a timer that is due but not yet taken. With `enter`, the timestamp gate closes and a
    /// deterministic schedule passes to the caller as part of the same step. `Err` names what
    /// blocks it, and nothing changed.
    pub fn if_quiescent<R>(
        &self,
        settling: bool,
        due: impl FnOnce() -> Option<Arc<str>>,
        enter: bool,
        f: impl FnOnce() -> R,
    ) -> Result<R, (BlockerKind, Arc<str>)> {
        let _passthrough = Passthrough::enter();
        let mut core = self.0.accounting.core();
        let mut sched = self.0.sched.as_ref().map(crate::sched::Scheduler::lock);
        if let Some(blocker) = self.0.blocker(&mut core, settling, sched.as_deref(), due) {
            return Err(blocker);
        }
        if enter {
            core.gate_closed = true;
            if let Some(st) = &mut sched {
                st.hold_external();
            }
        }
        Ok(f())
    }

    /// Rechecks a native clock skip under the census lock. The caller holds its readiness lock;
    /// `foreign` requires every participant to be in a native wait. Yield skips also count the
    /// admitted spinners. `f` must collect callbacks without running them under these locks.
    #[cfg(windows)]
    pub fn if_native_time_skip<R>(
        &self,
        settling: bool,
        foreign: bool,
        f: impl FnOnce() -> R,
    ) -> Option<R> {
        let _passthrough = Passthrough::enter();
        let core = self.0.accounting.core();
        if self.0.sched.is_some()
            || settling
            || self.0.accounting.leases_held()
            || self.0.wait_due()
            || core.released > 0
            || core.has_pending_releases()
            || core.first_unheld_lock().is_some()
        {
            return None;
        }
        let yielding = SKIP_YIELD.with(|mode| {
            let (domain, yielding) = mode.get();
            (domain == self.key()).then_some(yielding).flatten()
        });
        let live = self.0.participants.load(Ordering::SeqCst);
        let parked = self.0.parked.load(Ordering::SeqCst);
        let admitted = if foreign {
            live > 0 && parked >= live && self.0.sim_parked.load(Ordering::SeqCst) == 0
        } else if let Some(count_self) = yielding {
            self.0.clock_spinning.load(Ordering::SeqCst) == 0
                && parked + self.0.spinning.load(Ordering::SeqCst) + usize::from(count_self) >= live
        } else {
            live > 0 && parked >= live
        };
        admitted.then(f)
    }

    /// Runs a clock spin step with its participant counts and outstanding native releases held
    /// stable. The caller holds readiness and runs collected callbacks after both locks drop.
    #[cfg(windows)]
    pub fn if_native_spin_step<R>(&self, settling: bool, f: impl FnOnce() -> R) -> Option<R> {
        let _passthrough = Passthrough::enter();
        let core = self.0.accounting.core();
        let live = self.0.participants.load(Ordering::SeqCst);
        if self.0.sched.is_some()
            || settling
            || live == 0
            || self.0.parked.load(Ordering::SeqCst) + self.0.spinning.load(Ordering::SeqCst) < live
            || self.0.accounting.leases_held()
            || core.released > 0
            || core.has_pending_releases()
            || core.first_unheld_lock().is_some()
        {
            return None;
        }
        Some(f())
    }

    /// The domain's quiescence as an executive sees it, read under the same locks as
    /// [`if_quiescent`](Self::if_quiescent); `next_deadline` is left for the caller.
    pub fn quiescence(&self, settling: bool, due: impl FnOnce() -> Option<Arc<str>>) -> Quiescence {
        let _passthrough = Passthrough::enter();
        let mut core = self.0.accounting.core();
        let sched = self.0.sched.as_ref().map(crate::sched::Scheduler::lock);
        let epoch = self.0.accounting.epoch();
        let (runnable, blocked) = match &sched {
            Some(st) => st.counts(),
            None => {
                let parked = self.0.parked.load(Ordering::SeqCst);
                let live = self.0.participants.load(Ordering::SeqCst);
                (live.saturating_sub(parked), parked)
            }
        };
        let blocker = self.0.blocker(&mut core, settling, sched.as_deref(), due);
        Quiescence {
            quiescent: blocker.is_none(),
            epoch,
            runnable: u32::try_from(runnable).unwrap_or(u32::MAX),
            busy: u32::try_from(self.0.accounting.lease_count()).unwrap_or(u32::MAX),
            blocked: u32::try_from(blocked).unwrap_or(u32::MAX),
            next_deadline: None,
            blocker,
        }
    }

    /// Every participant's row, then one row per lease. Times are on the domain's monotonic
    /// clock as its layers report it.
    pub fn participants(&self) -> Vec<ParticipantInfo> {
        let _passthrough = Passthrough::enter();
        let now = (
            self.0.virtual_now().unwrap_or_default(),
            accounting::real_elapsed(),
        );
        let leases = self.0.accounting.leases();
        let rows: Vec<(u64, accounting::Row)> = {
            let core = self.0.accounting.core();
            core.rows
                .iter()
                .filter(|(_, row)| row.class == ThreadClass::Participant)
                .map(|(&lineage, row)| (lineage, *row))
                .collect()
        };
        let mut out: Vec<ParticipantInfo> = rows
            .into_iter()
            .map(|(lineage, row)| ParticipantInfo {
                id: lineage,
                name: self.0.display_name(lineage),
                state: if row.wait.is_some() {
                    PState::Blocked
                } else {
                    PState::Running
                },
                since_virtual: now.0.saturating_sub(row.since.0),
                since_wall: now.1.saturating_sub(row.since.1),
                deadline: row.wait.and_then(|w| w.deadline),
                wait: row.wait.and_then(|w| w.label),
                last_wait: row.last_wait,
                leases: leases
                    .iter()
                    .filter(|(_, _, holder)| *holder == Some(lineage))
                    .map(|(label, _, _)| *label)
                    .collect(),
                lease_kind: None,
            })
            .collect();
        out.extend(leases.iter().map(|&(label, kind, holder)| ParticipantInfo {
            id: holder.unwrap_or(u64::MAX),
            name: holder.map_or_else(|| Arc::from(label), |lineage| self.0.display_name(lineage)),
            state: PState::Busy(label),
            since_virtual: std::time::Duration::ZERO,
            since_wall: std::time::Duration::ZERO,
            deadline: None,
            wait: None,
            last_wait: None,
            leases: vec![label],
            lease_kind: Some(kind),
        }));
        out
    }

    /// How many times a participant was woken from a native wait by something outside the domain
    /// since it was made or an executive last attached: the domain was quiescent, and nothing the
    /// sim sees (an effect of one of its threads, a move of its epoch) happened before the wake.
    /// Counted with or without an audit.
    pub fn outside_wakes(&self) -> u64 {
        self.0.accounting.outside_wakes()
    }

    /// The domain's id, unique in the process.
    pub fn id(&self) -> SimId {
        SimId(self.0.accounting.serial.0)
    }

    /// Every live thread of the domain as (OS thread id, lineage, class), for a thread census.
    pub(crate) fn os_threads(&self) -> Vec<(u64, u64, ThreadClass)> {
        self.0.accounting.os_threads()
    }

    /// What the audit has seen since the executive attached (empty without audit).
    pub fn audit(&self) -> AuditReport {
        self.0.accounting.audit_report()
    }

    /// The name a thread of this domain is listed under: its own, or one made from its lineage.
    pub fn display_name(&self, lineage: u64) -> Arc<str> {
        self.0.display_name(lineage)
    }

    /// Moves time on for a domain whose participants are all blocked, from any thread: to the
    /// earliest pending timer of a participant, or, once every participant waits on what only a
    /// thread of another class can do, to the earliest of any thread's. Its layers' waiters then
    /// re-check. `false`, moving nothing, under a deterministic schedule (which moves time itself),
    /// while a participant runs, or with nothing pending.
    pub fn skip_idle(&self) -> bool {
        let _passthrough = Passthrough::enter();
        let inner = &*self.0;
        if inner.sched.is_some() {
            return false;
        }
        let Some(_gate) = inner.accounting.skip_gate() else {
            return false;
        };
        let settling = inner.settling();
        let moved = inner.quiescent(settling)
            && (inner.layers.iter().any(|layer| layer.try_time_skip())
                || (inner.stalled(settling)
                    && inner
                        .layers
                        .iter()
                        .any(|layer| layer.try_foreign_time_skip())));
        if moved {
            inner.wake_waiters();
        }
        moved
    }

    /// Whether the calling thread is managed by this domain.
    pub fn is_current(&self) -> bool {
        self.0.is_current()
    }

    /// An id for this domain, distinct from every other live domain's and never 0: what a backend
    /// shared between domains keys its per-domain state by (see [`Layer::settling`]). Stable for
    /// the domain's life; a later domain may reuse it once this one is gone.
    pub fn key(&self) -> usize {
        self.0.key()
    }

    /// Whether every run of this domain has ended: it was entered with [`enter`](Self::enter) and
    /// no thread entered that way is inside now. The threads it still manages are left over from
    /// a run (see [`Layer::dormant`]).
    pub fn is_dormant(&self) -> bool {
        self.0.dormant.load(Ordering::SeqCst)
    }

    /// What the stall watchdog compares between samples (see [`crate::stall::Progress`]).
    pub(crate) fn progress(&self) -> crate::stall::Progress {
        let _passthrough = Passthrough::enter();
        let waits = self.0.sched.as_ref().map_or(0, |sched| sched.lock().waits);
        (self.0.accounting.epoch(), self.0.virtual_now(), waits)
    }

    /// The name of the participant holding a deterministic schedule's baton, if one does.
    pub(crate) fn baton_holder(&self) -> Option<Arc<str>> {
        let _passthrough = Passthrough::enter();
        let holder = self.0.sched.as_ref()?.lock().holder()?;
        Some(self.0.display_name(holder))
    }

    /// Whether a participant runs while no lease is held and no executive's timestamp is open:
    /// the only state in which a lack of progress is a busy stall (see [`crate::stall`]). Takes
    /// the census lock before the schedule's.
    pub(crate) fn busy_unleased(&self) -> bool {
        let _passthrough = Passthrough::enter();
        if self.0.accounting.leases_held() {
            return false;
        }
        let core = self.0.accounting.core();
        if core.gate_closed {
            return false;
        }
        let sched = self.0.sched.as_ref().map(crate::sched::Scheduler::lock);
        if sched.as_ref().is_some_and(|st| st.held_externally()) {
            return false;
        }
        core.rows
            .values()
            .any(|row| row.class == ThreadClass::Participant && row.wait.is_none())
    }

    /// Starts a participant of this domain from any thread, inside the domain or outside it: a
    /// thread the code under test never created, such as the one a signal is delivered on. Its
    /// lineage comes from how many such threads the domain has started, so it replays like a
    /// spawned one. While an executive's timestamp is open it waits at the gate before `f` runs.
    pub fn spawn_injected(
        &self,
        name: &str,
        f: impl FnOnce() + Send + 'static,
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        let inner = &self.0;
        let order = inner.injected.fetch_add(1, Ordering::SeqCst) + 1;
        let lineage = mix_lineage(INJECT_SALT, order);
        inner.participants.fetch_add(1, Ordering::SeqCst);
        let held = inner.accounting.add_row(lineage, ThreadClass::Participant);
        if let Some(sched) = &inner.sched {
            sched.spawned(lineage);
        }
        let raw = Arc::into_raw(inner.clone());
        let inherited = SendInherited(Inherited {
            domain: raw,
            class: ThreadClass::Participant,
            label: None,
            lineage,
            held,
        });
        let spawned = real(|| {
            std::thread::Builder::new()
                .name(name.to_owned())
                .spawn(move || {
                    let inherited = inherited;
                    // SAFETY: the domain is kept alive by the reference `inherited` carries.
                    if let Some(sched) = unsafe { &(*inherited.0.domain).sched } {
                        sched.record_handle(crate::os::current_thread_handle(), lineage);
                    }
                    // SAFETY: made above for this thread alone.
                    let child = unsafe { adopt(inherited.0) };
                    // Parking and unparking at once passes an open timestamp's gate (see
                    // `unpark`); a deterministic schedule holds the thread in `started` instead.
                    if domain_sched_free() {
                        let _label = crate::wait_label("signal");
                        drop(mark_waiting(true));
                        drop(mark_waiting(false));
                    }
                    f();
                    drop(child);
                })
        });
        if spawned.is_err() {
            inner.accounting.remove_row(lineage);
            if let Some(sched) = &inner.sched {
                sched.unspawned(lineage);
            }
            inner.participants.fetch_sub(1, Ordering::SeqCst);
            // SAFETY: the closure holding the reference was dropped without running.
            unsafe { drop(Arc::from_raw(raw)) };
        }
        spawned
    }

    /// The domain managing the calling thread.
    pub fn current() -> Option<Self> {
        let domain = state::domain();
        if domain.is_null() {
            return None;
        }
        // SAFETY: a managed thread holds a strong count on its domain for as long as the
        // pointer is installed, so it is live here; we take one more for the returned handle.
        unsafe {
            Arc::increment_strong_count(domain);
            Some(Self(Arc::from_raw(domain)))
        }
    }
}

/// Composes a [`Domain`] from any of a layer stack and the [`Net`], [`Fs`] and [`Host`] backends.
#[derive(Default)]
///
/// Each field becomes the `Inner` field of the same name.
pub struct DomainBuilder {
    /// Whether the domain gets a [`crate::sched::Scheduler`]; see
    /// [`deterministic`](Self::deterministic).
    deterministic: bool,
    layers: Vec<Arc<dyn Layer>>,
    #[cfg_attr(not(unix), allow(dead_code))]
    net: Vec<Arc<dyn Net>>,
    #[cfg_attr(not(unix), allow(dead_code))]
    fs: Option<Arc<dyn Fs>>,
    #[cfg_attr(not(unix), allow(dead_code))]
    host: Option<Arc<dyn Host>>,
    #[cfg_attr(not(unix), allow(dead_code))]
    env: Option<Arc<dyn Env>>,
    resolver: Option<Arc<dyn Resolver>>,
    signals: Option<Arc<dyn Signals>>,
    /// See [`stuck_after`](Self::stuck_after).
    stuck_after: Option<std::time::Duration>,
}

impl DomainBuilder {
    /// Appends `layers` to the stack, after any added before; calls are offered first to last.
    pub fn layers(mut self, layers: impl IntoIterator<Item = Arc<dyn Layer>>) -> Self {
        self.layers.extend(layers);
        self
    }

    /// Runs the domain's managed threads one at a time, switching only where a thread waits and
    /// always to the next runnable thread in a fixed order (see [`crate::DetKey`]), so a run
    /// replays exactly. Needs a discrete virtual clock layer for timed waits to time out.
    pub fn deterministic(mut self) -> Self {
        self.deterministic = true;
        self
    }

    /// Appends a net backend. Backends are consulted in the order added; the first whose call
    /// returns `Some` handles it, so order them most-specific first (e.g. a `SimHost` before a
    /// catch-all socket `Fabric`).
    pub fn net(mut self, net: Arc<dyn Net>) -> Self {
        self.net.push(net);
        self
    }

    /// Serves the domain's file calls from `fs`, replacing any earlier one; see [`Fs`].
    pub fn fs(mut self, fs: Arc<dyn Fs>) -> Self {
        self.fs = Some(fs);
        self
    }

    /// Serves the domain's process and scheduler calls from `host`, replacing any earlier one; see
    /// [`Host`].
    pub fn host(mut self, host: Arc<dyn Host>) -> Self {
        self.host = Some(host);
        self
    }

    /// Serves the domain's environment-variable calls from `env`, replacing any earlier one; see
    /// [`Env`].
    pub fn env(mut self, env: Arc<dyn Env>) -> Self {
        self.env = Some(env);
        self
    }

    /// Answers the domain's name lookups from `resolver`; see [`Resolver`].
    pub fn resolver(mut self, resolver: Arc<dyn Resolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Keeps the domain's signal dispositions in `signals`; see [`Signals`].
    pub fn signals(mut self, signals: Arc<dyn Signals>) -> Self {
        self.signals = Some(signals);
        self
    }

    /// Aborts the process with a report once a participant has kept the domain busy for `after`
    /// of real time without progress: no participant blocking or waking, no lease taken or given
    /// back, virtual time standing still, and no wait begun in a deterministic schedule. Never
    /// while a lease is held, an executive's timestamp is open, every participant is blocked, or
    /// the clock is not virtual (see [`Layer::virtual_now`]), since such a clock moves on its own.
    /// The report, listing each participant, goes straight to the process's stderr, past a test
    /// harness's output capture, before the abort: a stuck thread cannot be unwound from outside.
    /// Panics on a zero `after`, under which every sample would be a stall.
    #[track_caller]
    pub fn stuck_after(mut self, after: std::time::Duration) -> Self {
        assert!(!after.is_zero(), "stuck_after must be longer than zero");
        self.stuck_after = Some(after);
        self
    }

    /// Builds the domain, installing the interposer first if nothing has yet.
    pub fn install(self) -> Domain {
        crate::install();
        #[cfg(windows)]
        crate::os::windows::start_std_winsock();
        let domain = Domain(Arc::new(Inner {
            layers: self.layers,
            net: self.net,
            fs: self.fs,
            host: self.host,
            env: self.env,
            resolver: self.resolver,
            signals: self.signals,
            injected: AtomicU64::new(0),
            entries: AtomicU64::new(0),
            thread_signals: Mutex::default(),
            signals_pending: AtomicBool::new(false),
            unmodelled: Mutex::default(),
            #[cfg(windows)]
            timer_word_wakes: Mutex::default(),
            participants: AtomicUsize::new(0),
            parked: AtomicUsize::new(0),
            sim_parked: AtomicUsize::new(0),
            spinning: AtomicUsize::new(0),
            clock_spinning: AtomicUsize::new(0),
            accounting: Accounting::default(),
            sched: self.deterministic.then(crate::sched::Scheduler::default),
            watchdog: std::sync::OnceLock::new(),
            runs: Mutex::new(0),
            dormant: AtomicBool::new(false),
        }));
        crate::census::register(&domain);
        if let Some(after) = self.stuck_after {
            let watchdog = crate::stall::Watchdog::start(domain.downgrade(), after);
            let _ = domain.0.watchdog.set(watchdog);
        }
        domain
    }
}

/// Guard returned by [`Domain::enter`].
///
/// Not `Send`: it restores thread-local state, so it must drop on the thread that made it. Its
/// drop leaves a deterministic schedule (for a root), restores the previous domain, lineage and
/// class, removes the thread's row and, for a participant, uncounts it and offers an idle skip,
/// then releases the strong count it held.
pub struct Managed {
    /// The domain the thread was in before this guard (null for none), reinstalled on drop.
    previous: *const Inner,
    /// The domain this guard installed: a strong count from `Arc::into_raw`, released on drop.
    domain: *const Inner,
    /// Entered the domain directly (`Domain::enter`) rather than being started inside it, so its
    /// leaving is the thread's exit from the domain's schedule.
    root: bool,
    /// The thread's lineage before this guard, restored on drop.
    previous_lineage: Lineage,
    /// The thread's class before this guard, restored on drop.
    previous_class: (ThreadClass, Option<&'static str>),
    /// The thread's mutex-hold record before this guard (see `accounting::Held`), restored on drop.
    previous_held: *const accounting::Held,
    /// Makes the guard `!Send` and `!Sync`.
    _not_send: PhantomData<*const ()>,
}

impl std::fmt::Debug for Managed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Managed")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

/// Where a managed thread sits in its domain's spawn tree, and how many children it has spawned.
/// The root (the thread that entered the domain) is 0 on the domain's first entry and a new id on
/// each later one (see `Inner::root_lineage`); a child's id mixes its parent's with its
/// birth order, so ids follow from what the code does, never from how the OS schedules it.
#[derive(Clone, Copy, Default)]
struct Lineage {
    /// The thread's lineage id.
    id: u64,
    /// How many children it has spawned: the birth order of the last one.
    children: u64,
}

thread_local! {
    /// The calling thread's lineage. Const-initialised with no destructor, so a hook can read it
    /// without allocating, and it reads as the default during thread teardown.
    static LINEAGE: std::cell::Cell<Lineage> = const {
        std::cell::Cell::new(Lineage { id: 0, children: 0 })
    };
}

/// Installs `next` as the calling thread's lineage and returns the one it replaced (the default
/// once the thread-local is gone).
fn swap_lineage(next: Lineage) -> Lineage {
    LINEAGE.try_with(|l| l.replace(next)).unwrap_or_default()
}

/// The calling thread's lineage id in its domain's spawn tree (0 for the thread that first entered
/// it).
/// Stable from run to run whenever the threads spawn in the same order, so per-thread state seeded
/// from it — a random stream — replays exactly regardless of scheduling.
pub fn thread_lineage() -> u64 {
    LINEAGE.try_with(|l| l.get().id).unwrap_or(0)
}

/// The lineage id of the calling thread's next child, counting it as born.
pub(crate) fn child_lineage() -> u64 {
    LINEAGE
        .try_with(|l| {
            let mut me = l.get();
            me.children += 1;
            l.set(me);
            mix_lineage(me.id, me.children)
        })
        .unwrap_or(0)
}

/// SplitMix64's finaliser over (parent, birth order): distinct, well-spread ids.
///
/// The constants are SplitMix64's: the golden-ratio increment `0x9e3779b97f4a7c15` and the
/// mixing multipliers and shifts (30, 27, 31) of Vigna's reference `splitmix64.c`
/// (<https://prng.di.unimi.it/splitmix64.c>), after Steele, Lea and Flood, "Fast Splittable
/// Pseudorandom Number Generators", OOPSLA 2014, in ACM SIGPLAN Notices 49(10)
/// (doi:10.1145/2714064.2660195). Here the parent stands in for the state and the increment,
/// multiplied by the birth order, is XORed in where `splitmix64.c` adds it; the increment is odd,
/// so siblings get distinct inputs, and each output is a bijective mix of its input.
fn mix_lineage(parent: u64, order: u64) -> u64 {
    let mut z = parent ^ order.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The parent every injected thread's lineage is mixed from, as though one invisible thread of
/// the domain had spawned them all. A snare choice: the ASCII bytes of `"SIGNALS!"`, any value
/// distinct from [`ROOT_SALT`] and from real lineages would do.
const INJECT_SALT: u64 = 0x5349_474e_414c_5321;

/// The parent every later entry's root lineage is mixed from, by entry order. A snare choice: the
/// ASCII bytes of `"ROOTENTR"`.
const ROOT_SALT: u64 = 0x524f_4f54_454e_5452;

impl Drop for Managed {
    fn drop(&mut self) {
        end_spin();
        if self.root
            && !self.domain.is_null()
            // SAFETY: the domain pointer is live until the Arc below is dropped.
            && let Some(sched) = unsafe { &(*self.domain).sched }
        {
            sched.exit(thread_lineage(), true);
        }
        state::replace_domain(self.previous);
        accounting::swap_held(self.previous_held);
        let lineage = swap_lineage(self.previous_lineage).id;
        let (class, _) = accounting::swap_class(self.previous_class.0, self.previous_class.1);
        if !self.domain.is_null() {
            if self.root {
                // SAFETY: the domain pointer is live until the Arc below is dropped.
                unsafe { (*self.domain).end_run() };
            }
            // SAFETY: the domain pointer is live until the Arc below is dropped.
            let accounting = unsafe { &(*self.domain).accounting };
            accounting.forget_handle(crate::os::current_thread_handle(), lineage);
            accounting.remove_row(lineage);
            {
                let _passthrough = Passthrough::enter();
                accounting.core().exited(lineage);
            }
            if class == ThreadClass::Participant {
                // SAFETY: the domain pointer is live until the Arc below is dropped.
                unsafe { (*self.domain).participants.fetch_sub(1, Ordering::SeqCst) };
                drop(accounting.bump());
                // SAFETY: as above.
                wake_if_quiescent(unsafe { &*self.domain });
                offer_idle_skip(self.domain);
            }
            // SAFETY: `domain` came from `Arc::into_raw` in `enter` or `inherit` and is released
            // exactly once, here.
            unsafe { drop(Arc::from_raw(self.domain)) };
        }
    }
}

/// Runs `f` with the calling thread's OS calls going to the OS, even on a managed thread.
pub fn real<R>(f: impl FnOnce() -> R) -> R {
    let _passthrough = Passthrough::enter();
    f()
}

/// Whether the calling thread is currently in passthrough — i.e. inside a [`real`] scope (or off a
/// managed thread), so its hooked calls reach the real OS. A drop-in shim (`io-uring`, `xsk-rs`)
/// reads this to tag a resource with the mode it was created in and to reject using it in the
/// other mode, where the simulated and real worlds would be mixed incoherently.
pub fn in_passthrough() -> bool {
    state::passthrough()
}

/// The calling thread's domain, if it is managed.
fn here() -> Option<&'static Inner> {
    let domain = state::domain();
    // SAFETY: on a managed thread the domain pointer is live for as long as it is installed, which
    // outlasts any use made of the reference on this thread.
    (!domain.is_null()).then(|| unsafe { &*domain })
}

/// Whether the calling thread's domain runs without a deterministic schedule (`false` off a
/// domain).
fn domain_sched_free() -> bool {
    here().is_some_and(|domain| domain.sched.is_none())
}

/// The signal table of the calling thread's domain, read in or out of passthrough.
#[cfg(unix)]
pub(crate) fn signals_here() -> Option<Arc<dyn Signals>> {
    let domain = here()?;
    let _passthrough = Passthrough::enter();
    domain.signals.clone()
}

/// Offers a signal call to the calling thread's [`Signals`], if it has one, with the thread in
/// passthrough. `None` means the call goes to the OS.
pub(crate) fn dispatch_signals<T>(op: impl FnOnce(&dyn Signals) -> T) -> Option<T> {
    if state::passthrough() {
        return None;
    }
    let domain = here()?;
    let _passthrough = Passthrough::enter();
    let signals = domain.signals.as_deref()?;
    Some(op(signals))
}

/// Leaves `sig` pending for the domain thread with OS handle `handle`, to be delivered at its next
/// hooked call. `false` when the thread is not one of the calling thread's domain.
///
/// This emulates `pthread_kill` (POSIX `pthread_kill`; man 3 pthread_kill): the signal is
/// directed at that thread and stays pending until it next enters a hook, standing in for the
/// kernel delivering it on return to user space. Pending signals form a set, so a signal posted
/// twice before delivery is delivered once, as for standard signals (man 7 signal, "Queueing
/// and delivery semantics for standard signals"). The only caller, the `pthread_kill` hook,
/// posts just the virtual signals (`signals::is_virtual`: `SIGHUP`, `SIGINT`, `SIGTERM`, all
/// standard signals); a real-time signal, which Linux would queue (man 7 signal, "Real-time
/// signals"), would be merged here. `sig` must lie in 1..=63 for the `u64` mask and for
/// [`drain_signals`] to see it: macOS numbers stop below `NSIG` = 32 (`<sys/signal.h>`), but Linux
/// numbers run to `SIGRTMAX` = `_NSIG` = 64 (include/uapi/asm-generic/signal.h).
#[cfg(unix)]
pub(crate) fn post_signal(handle: usize, sig: core::ffi::c_int) -> bool {
    let Some(domain) = here() else {
        return false;
    };
    if domain.signals.is_none() {
        return false;
    }
    let Some(lineage) = domain.accounting.lineage_of(handle) else {
        return false;
    };
    let _passthrough = Passthrough::enter();
    *domain
        .thread_signals
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(lineage)
        .or_default() |= 1 << sig;
    domain.signals_pending.store(true, Ordering::SeqCst);
    true
}

/// Delivers the signals left pending for the calling thread, if any, lowest number first, outside
/// the `thread_signals` lock. `signals_pending` is read `Relaxed` as a hint only: a post it misses
/// is delivered at the thread's next hooked call.
#[cfg(unix)]
fn drain_signals(domain: &Inner) {
    if !domain.signals_pending.load(Ordering::Relaxed) {
        return;
    }
    let bits = {
        let _passthrough = Passthrough::enter();
        let mut pending = domain
            .thread_signals
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let bits = pending.remove(&thread_lineage()).unwrap_or(0);
        domain
            .signals_pending
            .store(!pending.is_empty(), Ordering::SeqCst);
        bits
    };
    for sig in (1..64).filter(|sig| bits & (1 << sig) != 0) {
        crate::signals::deliver(sig, crate::SignalSource::Process, true);
    }
}

/// Windows has no `pthread_kill`, so nothing is ever left pending for a thread.
#[cfg(not(unix))]
fn drain_signals(_domain: &Inner) {}

/// Whether the calling thread's domain is quiescent (see [`Domain::quiescent`]); `false` off a
/// domain. A backend's blocking wait asks this under its own lock, passing whether a waiter it
/// woke has yet to run.
pub fn quiescent(settling: bool) -> bool {
    here().is_some_and(|domain| domain.quiescent(settling))
}

/// Whether a participant of the calling thread's domain is parked in a native wait on a word in a
/// loaded image: a lock in static data that a thread outside the domain may hold, so a quiescent
/// domain with no time left to pass is not deadlocked while it waits there.
pub fn parked_on_shared_word() -> bool {
    #[cfg(any(target_os = "linux", windows))]
    {
        let Some(domain) = here() else {
            return false;
        };
        let _passthrough = Passthrough::enter();
        let core = domain.accounting.core();
        core.rows.values().any(|row| {
            row.class == ThreadClass::Participant
                && row
                    .wait
                    .and_then(|wait| wait.key)
                    .is_some_and(crate::os::address_in_image)
        })
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    false
}

/// Marks the calling participant as entering (`true`) or leaving (`false`) a native wait that never
/// gives up (a join, a lock), for its domain's quiescence count; a no-op for other classes and off
/// a domain. The returned bump runs an armed epoch callback when dropped, so a caller holding a
/// lock drops it only after letting go.
pub fn mark_waiting(waiting: bool) -> EpochBump {
    mark(waiting, false)
}

/// As [`mark_waiting`], for a sim wait: one that gives up once its domain is quiescent with no time
/// left to pass. A backend's blocking wait brackets itself with `true`/`false`.
pub fn mark_sim_waiting(waiting: bool) -> EpochBump {
    mark(waiting, true)
}

/// [`mark_waiting`] and [`mark_sim_waiting`]: parks or unparks the calling participant, counted in
/// `sim_parked` too when `sim`. Leaving waits at an open timestamp's gate.
fn mark(waiting: bool, sim: bool) -> EpochBump {
    let Some(domain) = here() else {
        return EpochBump::NONE;
    };
    if !accounting::participant() {
        return EpochBump::NONE;
    }
    if waiting {
        park(domain, sim)
    } else {
        unpark(domain, sim, true).unwrap_or(EpochBump::NONE)
    }
}

/// Counts the calling participant parked, with its row showing what it waits in.
///
/// Under the census lock: the counts move, the row records the wait (a native wait also its wait
/// key and mutex, which `keyed` counts so [`note_release`] can skip the lock when none is
/// keyed), and the epoch moves on. Once every participant is parked the census notes the domain
/// quiet, for the audit's outside-wake detection.
fn park(domain: &Inner, sim: bool) -> EpochBump {
    park_if(domain, sim, || true).unwrap()
}

fn park_if(domain: &Inner, sim: bool, waiting: impl FnOnce() -> bool) -> Option<EpochBump> {
    end_spin();
    let _passthrough = Passthrough::enter();
    let stamp = domain.row_stamp();
    let wait = RowWait {
        label: accounting::current_wait_label(),
        deadline: accounting::take_wait_deadline(),
        key: if sim {
            None
        } else {
            accounting::current_wait_key()
        },
        mutex: if sim {
            None
        } else {
            accounting::current_wait_mutex()
        },
        #[cfg(target_os = "linux")]
        mask: accounting::wait_mask_value(),
        #[cfg(any(target_os = "linux", windows))]
        token: 0,
        #[cfg(target_os = "linux")]
        expected: accounting::wait_expected_value(),
        #[cfg(target_os = "linux")]
        futex_private: accounting::wait_futex_private(),
        #[cfg(target_os = "linux")]
        pre_released: false,
        #[cfg(target_os = "linux")]
        claimed: false,
        #[cfg(windows)]
        woken: false,
    };
    let mut core = domain.accounting.core();
    #[cfg(windows)]
    let mut signals = domain.accounting.timer_signals();
    #[cfg(windows)]
    domain
        .accounting
        .drain_timer_signals(&mut core, &mut signals);
    #[cfg(windows)]
    let admission = accounting::TimerAdmission::enter();
    if !waiting() {
        #[cfg(windows)]
        if let Some(key) = admission.consumed() {
            core.consume_timer_event(key);
        }
        return None;
    }
    if sim {
        domain.sim_parked.fetch_add(1, Ordering::SeqCst);
    }
    domain.parked.fetch_add(1, Ordering::SeqCst);
    let lineage = thread_lineage();
    #[cfg(windows)]
    let mut wait = wait;
    #[cfg(windows)]
    if wait.key.is_some() {
        wait.token = signals.admit();
    }
    let _ = core.set_waiting(lineage, Some(wait), stamp);
    if wait.key.is_some() && core.rows.contains_key(&lineage) {
        domain.accounting.keyed.fetch_add(1, Ordering::SeqCst);
    }
    let bump = domain.accounting.bump();
    if domain.parked.load(Ordering::SeqCst) >= domain.participants.load(Ordering::SeqCst) {
        domain.accounting.note_quiet(&mut core);
    }
    Some(bump)
}

/// Whether a participant leaving its wait now must first wait for an open timestamp to end. A
/// contended lock passes: it returns holding a lock of the code under test, and holding that at
/// the gate could block the executive's own threads on it. A condition variable's wait lets go of
/// its mutex to wait (see [`native_cond_wait`]).
fn held_at_gate(core: &Core) -> bool {
    core.gate_closed && accounting::current_wait_label() != Some("mutex")
}

/// Counts the calling participant running again. While a timestamp is open it first waits at the
/// gate, still counted parked, when `may_wait`; otherwise it returns `None`, counted held at the
/// gate but otherwise changing nothing, for a caller that must let go of its own lock before
/// waiting with [`pass_gate`].
fn unpark(domain: &Inner, sim: bool, may_wait: bool) -> Option<EpochBump> {
    unpark_inner(domain, sim, may_wait, false)
}

fn unpark_inner(domain: &Inner, sim: bool, may_wait: bool, woken: bool) -> Option<EpochBump> {
    let _passthrough = Passthrough::enter();
    let stamp = domain.row_stamp();
    let mut core = domain.accounting.core();
    if woken {
        domain.accounting.note_wake(&mut core);
    }
    while held_at_gate(&core) {
        if !may_wait {
            hold_at_gate(domain, &mut core);
            return None;
        }
        core = wait_at_gate(domain, core);
    }
    if accounting::swap_gated(false) {
        core.gated -= 1;
    }
    domain.parked.fetch_sub(1, Ordering::SeqCst);
    if sim {
        domain.sim_parked.fetch_sub(1, Ordering::SeqCst);
    }
    if let Some(target) = accounting::take_join_target() {
        core.joined(target);
    }
    if core
        .set_waiting(thread_lineage(), None, stamp)
        .is_some_and(|w| w.key.is_some())
    {
        domain.accounting.keyed.fetch_sub(1, Ordering::SeqCst);
    }
    Some(domain.accounting.bump())
}

/// As [`mark_sim_waiting`]`(false)`, for a backend that holds its own lock while it leaves the
/// wait: `None`, still parked, while the calling participant must wait at an open timestamp's
/// gate, which it does with [`pass_gate`] once it has let go of that lock.
pub fn try_leave_sim_wait() -> Option<EpochBump> {
    let Some(domain) = here() else {
        return Some(EpochBump::NONE);
    };
    if !accounting::participant() {
        return Some(EpochBump::NONE);
    }
    unpark(domain, true, false)
}

/// Waits, still counted parked, while an executive's timestamp holds the calling participant at
/// its domain's gate (see [`try_leave_sim_wait`]).
pub fn pass_gate() {
    let Some(domain) = here() else {
        return;
    };
    if !accounting::participant() {
        return;
    }
    let _passthrough = Passthrough::enter();
    let mut core = domain.accounting.core();
    while held_at_gate(&core) {
        core = wait_at_gate(domain, core);
    }
}

/// Holds the calling participant at the gate until it opens (see [`hold_at_gate`]).
fn wait_at_gate<'a>(
    domain: &'a Inner,
    mut core: std::sync::MutexGuard<'a, Core>,
) -> std::sync::MutexGuard<'a, Core> {
    hold_at_gate(domain, &mut core);
    domain.accounting.wait_at_gate(core)
}

/// Counts the calling participant held at the gate, as deferred: whatever woke it has been taken,
/// so it no longer counts as released. It stays counted after the gate opens until it counts
/// itself running ([`unpark`]), so the domain does not look quiescent while it has yet to run:
/// between the gate opening and its return there is no lock it holds that a check would see.
fn hold_at_gate(domain: &Inner, core: &mut Core) {
    if core.take_release(thread_lineage()) {
        domain.accounting.keyed.fetch_sub(1, Ordering::SeqCst);
    }
    if !accounting::swap_gated(true) {
        core.gated += 1;
    }
}

/// Whether an executive owns the calling thread's domain's time.
pub fn executive_attached() -> bool {
    here().is_some_and(|domain| domain.accounting.attached())
}

/// Notes that the calling thread did something the sim sees (`op`: a send, a wake, a timer), so a
/// participant it wakes does not count as woken from outside. Only threads of other classes than
/// participants count, and an executive's audit logs the effects of background and helper threads.
pub fn note_effect(op: &'static str) {
    let Some(domain) = here() else {
        return;
    };
    let class = accounting::class();
    if class == ThreadClass::Participant {
        return;
    }
    domain.accounting.note_effect(|| {
        (domain.accounting.auditing()
            && matches!(class, ThreadClass::Background | ThreadClass::Helper))
        .then(|| {
            let _passthrough = Passthrough::enter();
            ClassEffect {
                thread: domain.display_name(thread_lineage()),
                class,
                op,
                at: domain.virtual_now().unwrap_or_default(),
            }
        })
    });
}

/// A wake on the native wait object at `key` for up to `n` waiters (`FUTEX_WAKE`, a condition
/// variable's signal, `WakeByAddress*`), made before the OS wakes them: participants parked there
/// count as released, keeping the domain from looking quiescent until they run again — for an
/// executive, and for a time skip, which would otherwise carry the clock past work a woken thread
/// has yet to do. (man 2const FUTEX_WAKE; POSIX `pthread_cond_signal`;
/// [Microsoft Learn: WakeByAddressSingle function](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-wakebyaddresssingle))
///
/// Skips the census lock unless some participant is parked on a key (`Accounting::keyed`), so a
/// wake nobody in the sim waits on pays only an atomic load.
pub(crate) fn note_release(key: usize, n: usize) {
    if state::passthrough() {
        return;
    }
    let Some(domain) = here() else {
        return;
    };
    if domain.accounting.keyed.load(Ordering::SeqCst) == 0 {
        return;
    }
    let _passthrough = Passthrough::enter();
    let mut core = domain.accounting.core();
    core.signal(key, n);
    if accounting::participant() {
        core.clear_quiet();
    }
}

#[cfg(windows)]
pub(crate) fn release_native<R>(key: usize, n: usize, release: impl FnOnce() -> R) -> R {
    if state::passthrough() {
        return release();
    }
    let Some(domain) = here() else {
        return release();
    };
    let _passthrough = Passthrough::enter();
    let mut core = domain.accounting.core();
    core.signal(key, n);
    if accounting::participant() {
        core.clear_quiet();
    }
    release()
}

#[cfg(target_os = "linux")]
pub(crate) fn note_futex_release(key: usize, n: usize, mask: u32, private: bool) {
    if state::passthrough() {
        return;
    }
    let Some(domain) = here() else {
        return;
    };
    let _pass = Passthrough::enter();
    let mut core = domain.accounting.core();
    core.signal_masked_in_space(key, n, mask, Some(private));
    if accounting::participant() {
        core.clear_quiet();
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn note_futex_pre_enrollment_return() {
    if !counts_native_waits() {
        return;
    }
    let Some(domain) = here() else {
        return;
    };
    let _pass = Passthrough::enter();
    domain
        .accounting
        .core()
        .note_futex_pre_enrollment_return(thread_lineage());
}

#[cfg(target_os = "linux")]
pub(crate) fn release_native_futex(
    key: usize,
    mask: u32,
    private: bool,
    release: impl FnOnce() -> libc::c_long,
    word: impl FnOnce() -> Option<u32>,
) -> libc::c_long {
    if state::passthrough() {
        return release();
    }
    let Some(domain) = here() else {
        return release();
    };
    let _passthrough = Passthrough::enter();
    let mut core = domain.accounting.core();
    let result = release();
    core.signal_futex(key, result, mask, private, word);
    if accounting::participant() {
        core.clear_quiet();
    }
    result
}

/// A participant's wait on the pthread mutex at `mutex`, watched so the census knows whether the
/// waiter could take it, and whether a thread of the domain is what keeps it from doing so.
///
/// Dropping it stops the watch and refreshes `Accounting::watching`, the count that lets
/// [`note_mutex`] skip the census lock when nothing is watched.
#[cfg(any(unix, windows))]
pub(crate) struct MutexWatch {
    /// The waiter's domain; `'static` because a managed thread's domain outlives its waits.
    domain: &'static Inner,
    /// The watched mutex's address.
    mutex: usize,
}

#[cfg(any(unix, windows))]
impl Drop for MutexWatch {
    fn drop(&mut self) {
        let _passthrough = Passthrough::enter();
        let mut core = self.domain.accounting.core();
        core.unwatch_mutex(self.mutex);
        self.domain
            .accounting
            .watching
            .store(core.watching(), Ordering::SeqCst);
    }
}

/// Starts watching the pthread mutex at `mutex` for the calling participant, which is about to wait
/// for it: in a contended lock, or, `releasing`, in a condition variable's wait that lets go of it
/// first. `None` off a participant.
///
/// A condition variable's waiter records the mutex free, overriding what was recorded, since
/// `pthread_cond_wait` releases it atomically on entry (POSIX `pthread_cond_wait`). A contended
/// lock's holder is whichever thread of the domain records holding it (`accounting::Held`), or one
/// outside the domain if none does, unless an earlier watch already tracks it. The watch count is
/// published before those records are read, so a thread of the domain that takes the mutex
/// meanwhile is either read here or updates the watch itself (see [`note_mutex`]).
#[cfg(any(unix, windows))]
pub(crate) fn watch_mutex(mutex: usize, releasing: bool) -> Option<MutexWatch> {
    if !counts_native_waits() {
        return None;
    }
    let domain = here()?;
    let _passthrough = Passthrough::enter();
    let mut core = domain.accounting.core();
    domain.accounting.watching.fetch_add(1, Ordering::SeqCst);
    core.watch_mutex(mutex, releasing);
    #[cfg(target_os = "macos")]
    if !releasing
        && core.mutex_held_outside(mutex)
        && let Some(lineage) = domain.accounting.native_mutex_lineage(mutex)
    {
        core.mutex_taken(mutex, lineage);
    }
    domain
        .accounting
        .watching
        .store(core.watching(), Ordering::SeqCst);
    Some(MutexWatch { domain, mutex })
}

/// The calling thread took the pthread mutex at `mutex`.
#[cfg(any(unix, windows))]
pub(crate) fn note_mutex_taken(mutex: usize) {
    note_mutex(mutex, true);
}

/// The calling thread let go of the pthread mutex at `mutex`.
#[cfg(any(unix, windows))]
pub(crate) fn note_mutex_freed(mutex: usize) {
    note_mutex(mutex, false);
}

#[cfg(windows)]
pub(crate) fn note_shared_mutex(mutex: usize, taken: bool) {
    if state::passthrough() {
        return;
    }
    let Some(held) = accounting::held() else {
        return;
    };
    if taken {
        held.take(mutex);
    } else {
        held.free(mutex);
    }
    let Some(domain) = here() else {
        return;
    };
    let _pass = Passthrough::enter();
    let mut core = domain.accounting.core();
    if taken {
        core.shared_mutex_taken(mutex, thread_lineage());
    } else {
        core.shared_mutex_freed(mutex, thread_lineage());
    }
}

#[cfg(windows)]
pub(crate) fn mutex_held_inside(mutex: usize) -> bool {
    let Some(domain) = here() else {
        return false;
    };
    let _pass = Passthrough::enter();
    matches!(
        domain.accounting.core().holder_of(mutex),
        accounting::Owner::Thread(_)
    )
}

/// [`note_mutex_taken`] and [`note_mutex_freed`]: records the hold in the calling thread's
/// `accounting::Held`, then updates a watched mutex's owner in the census. Does nothing under
/// passthrough or off a domain, and skips the census while no mutex is watched (checked without
/// the lock, after the record, so a waiter that starts watching meanwhile reads the record).
#[cfg(any(unix, windows))]
fn note_mutex(mutex: usize, taken: bool) {
    if state::passthrough() {
        return;
    }
    let Some(held) = accounting::held() else {
        return;
    };
    if taken {
        held.take(mutex);
    } else {
        held.free(mutex);
    }
    let Some(domain) = here() else {
        return;
    };
    if domain.accounting.watching.load(Ordering::SeqCst) == 0 {
        return;
    }
    let _passthrough = Passthrough::enter();
    let lineage = thread_lineage();
    let mut core = domain.accounting.core();
    if taken {
        core.mutex_taken(mutex, lineage);
    } else {
        core.mutex_freed(mutex, lineage);
    }
}

/// [`note_effect`] from a hook: only the code under test's own calls count, not the sim's.
pub(crate) fn note_hook_effect(op: &'static str) {
    if !state::passthrough() {
        end_spin();
        note_effect(op);
    }
}

/// A deterministic waiter re-polled for something outside the sim made progress. Takes no lock, so
/// the schedule may count it under its own.
pub(crate) fn count_outside_wake() {
    if let Some(domain) = here() {
        domain.accounting.count_outside_wake();
    }
}

/// The calling thread's class, or `None` off a domain.
pub fn thread_class() -> Option<ThreadClass> {
    here().map(|_| accounting::class())
}

/// The calling thread's class as last set, managed or not: participant unless something changed
/// it.
pub fn recorded_thread_class() -> (ThreadClass, Option<&'static str>) {
    (accounting::class(), accounting::label())
}

/// Moves the calling managed thread into `class`, returning the class and label it had; `None`,
/// changing nothing, off a domain. A participant leaving stops counting toward quiescence and steps
/// out of a deterministic schedule, handing the baton on if it held it; one joining counts again
/// and waits in the schedule for its turn. Call it only on a running thread, never from inside a
/// wait.
pub fn set_thread_class(
    class: ThreadClass,
    label: Option<&'static str>,
) -> Option<(ThreadClass, Option<&'static str>)> {
    let domain = here()?;
    end_spin();
    let _passthrough = Passthrough::enter();
    let previous = accounting::swap_class(class, label);
    domain.accounting.set_row_class(thread_lineage(), class);
    let was = previous.0 == ThreadClass::Participant;
    let is = class == ThreadClass::Participant;
    if was == is {
        return Some(previous);
    }
    if is {
        domain.participants.fetch_add(1, Ordering::SeqCst);
    } else {
        domain.participants.fetch_sub(1, Ordering::SeqCst);
    }
    drop(domain.accounting.bump());
    if let Some(sched) = &domain.sched {
        if is {
            sched.attach_thread(thread_lineage());
        } else {
            sched.detach_thread(thread_lineage());
        }
    }
    if !is && domain.sched.is_none() {
        // One fewer participant can complete quiescence; the waiters re-check.
        domain.wake_waiters();
        offer_idle_skip(domain);
    }
    Some(previous)
}

/// Names the calling managed thread's row in its domain, or clears the name with `None`, returning
/// the name it replaced. Off a domain it does nothing.
pub fn set_thread_name(name: Option<&str>) -> Option<Arc<str>> {
    let domain = here()?;
    let name = name.map(|name| {
        let _passthrough = Passthrough::enter();
        Arc::<str>::from(name)
    });
    domain.accounting.set_name(thread_lineage(), name)
}

/// The calling managed thread's name in its domain, if it has one.
pub fn thread_name() -> Option<Arc<str>> {
    here()?.thread_name(thread_lineage())
}

/// Records that a thread of the calling thread's domain named itself, through a hook on the OS
/// naming call. `handle` picks the thread: `None` for the caller, else its OS handle. `name` is
/// decoded as UTF-8, lossily; a handle that is not one of the domain's threads is ignored.
pub(crate) fn record_thread_name(handle: Option<usize>, name: &[u8]) {
    if state::passthrough() {
        return;
    }
    let Some(domain) = here() else {
        return;
    };
    let lineage = match handle {
        None => thread_lineage(),
        Some(handle) => match domain.accounting.lineage_of(handle) {
            Some(lineage) => lineage,
            None => return,
        },
    };
    let _passthrough = Passthrough::enter();
    let name = Arc::<str>::from(String::from_utf8_lossy(name));
    domain.accounting.set_name(lineage, Some(name));
}

/// The calling thread's domain's [`Domain::key`], in or out of passthrough; 0 off a domain.
pub fn domain_key() -> usize {
    state::domain() as usize
}

/// Whether the calling thread's domain is dormant (see [`Domain::is_dormant`]): the thread is left
/// over from a run that has ended. `false` off a domain.
pub fn dormant() -> bool {
    here().is_some_and(|domain| domain.dormant.load(Ordering::SeqCst))
}

/// Whether the calling thread's domain holds a lease.
pub(crate) fn leases_held() -> bool {
    here().is_some_and(|domain| domain.accounting.leases_held())
}

/// Moves the calling thread's domain's epoch on: something its quiescence depends on changed. The
/// returned bump runs an armed epoch callback when dropped, so drop it with no lock held.
pub fn bump_epoch() -> EpochBump {
    here().map_or(EpochBump::NONE, |domain| domain.accounting.bump())
}

/// On quiescence, offers each of the calling thread's domain's layers the chance to jump virtual
/// time forward to its next pending timer (see [`Layer::try_time_skip`]). `true` means one did, so
/// a blocked wait can retry instead of treating the quiescence as a deadlock.
pub fn time_skip() -> bool {
    time_skip_inner(None)
}

fn time_skip_inner(yielding: Option<bool>) -> bool {
    let domain = state::domain();
    if domain.is_null() {
        return false;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    let Some(_gate) = domain.accounting.skip_gate() else {
        return false;
    };
    if domain.sched.is_none() {
        let settling = domain.settling();
        let quiescent = yielding.map_or_else(
            || domain.quiescent(settling),
            |count_self| {
                !settling
                    && !domain.wait_due()
                    && !domain.released()
                    && domain.clock_spinning.load(Ordering::SeqCst) == 0
                    && domain.parked.load(Ordering::SeqCst)
                        + domain.spinning.load(Ordering::SeqCst)
                        + usize::from(count_self)
                        >= domain.participants.load(Ordering::SeqCst)
            },
        );
        if !quiescent {
            return false;
        }
    }
    #[cfg(windows)]
    let _yielding = SkipYield::enter(domain as *const Inner as usize, yielding);
    let moved = domain.layers.iter().any(|layer| layer.try_time_skip());
    if moved && domain.sched.is_none() {
        domain.wake_waiters();
    }
    moved
}

/// Whether the calling thread's domain is stalled: quiescent outside a deterministic schedule, with
/// every participant parked in a wait that never gives up (a join, a lock), so only a thread of
/// another class can release them. `settling` is as for [`quiescent`]. `false` off a domain.
pub fn stalled(settling: bool) -> bool {
    here().is_some_and(|domain| domain.stalled(settling))
}

/// Jumps the calling thread's domain's virtual time to its earliest pending timer of any kind,
/// including those of threads that are not participants (see [`Layer::try_foreign_time_skip`]):
/// for a domain whose participants can only be released by such a thread. `true` if time moved.
pub fn foreign_time_skip() -> bool {
    let Some(domain) = here() else {
        return false;
    };
    let _passthrough = Passthrough::enter();
    let Some(_gate) = domain.accounting.skip_gate() else {
        return false;
    };
    let moved = domain
        .layers
        .iter()
        .any(|layer| layer.try_foreign_time_skip());
    if moved && domain.sched.is_none() {
        domain.wake_waiters();
    }
    moved
}

/// Registers a timed wait of `after` from now as a pending virtual timer on the calling thread's
/// domain, so [`time_skip`] can advance to it. Returns the opaque key a clock layer assigned (for
/// [`unregister_timer`]), or `None` off a domain or with no virtual clock.
pub fn register_timer(after: std::time::Duration) -> Option<u64> {
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    domain
        .layers
        .iter()
        .find_map(|layer| layer.register_timer(after))
}

/// Registers something that happens on its own `after` from now — a datagram arriving after its
/// link latency — as a pending virtual timer every thread may skip to, whoever registers it (see
/// [`Layer::register_event_timer`]).
pub fn register_event_timer(after: std::time::Duration) -> Option<u64> {
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    domain
        .layers
        .iter()
        .find_map(|layer| layer.register_event_timer(after))
}

/// Drops a pending timer from [`register_timer`] whose wait ended before the timeout fired.
pub fn unregister_timer(key: u64) {
    let domain = state::domain();
    if domain.is_null() {
        return;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    for layer in &domain.layers {
        layer.unregister_timer(key);
    }
}

/// Drops an event from [`register_event_timer`] that will no longer happen.
pub fn unregister_event_timer(key: u64) {
    let domain = state::domain();
    if domain.is_null() {
        return;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    for layer in &domain.layers {
        layer.unregister_event_timer(key);
    }
}

/// Wakes `waker` once the calling thread's domain's clock reaches monotonic time `at` (see
/// [`Layer::register_wake`]). `None` off a domain or where no layer registers it.
pub fn register_wake(at: std::time::Duration, waker: std::task::Waker) -> Option<u64> {
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    domain
        .layers
        .iter()
        .find_map(|layer| layer.register_wake(at, waker.clone()))
}

#[cfg(windows)]
pub(crate) fn supports_timer_wakes() -> bool {
    let _passthrough = Passthrough::enter();
    here().is_some_and(|domain| {
        domain
            .layers
            .iter()
            .any(|layer| layer.supports_timer_wakes())
    })
}

/// Drops a waker from [`register_wake`] that has not fired.
pub fn cancel_wake(key: u64) {
    let domain = state::domain();
    if domain.is_null() {
        return;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    for layer in &domain.layers {
        layer.cancel_wake(key);
    }
}

/// Carries the calling thread's domain's clock to `deadline`, where a timed wait timed out while
/// the clock ticks on each read (see [`Layer::expire_timer`]).
pub fn expire_timer(deadline: std::time::Duration) {
    let domain = state::domain();
    if domain.is_null() {
        return;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    for layer in &domain.layers {
        layer.expire_timer(deadline);
    }
}

/// Asks the calling thread's domain's layers to wake their blocked waiters (see
/// [`Layer::wake_waiters`]).
fn wake_waiters() {
    if let Some(domain) = here() {
        domain.wake_waiters();
    }
}

/// Asks the calling thread's domain's layers to wake their waiters outside a deterministic
/// schedule (see [`Layer::wake_unscheduled`]).
pub(crate) fn wake_unscheduled() {
    if let Some(domain) = here() {
        let _passthrough = Passthrough::enter();
        let key = domain.key();
        for layer in &domain.layers {
            layer.wake_unscheduled(key);
        }
    }
}

/// Whether any layer of the calling thread's domain has woken a waiter that has yet to run (see
/// [`Layer::settling`]); `false` off a domain.
fn settling() -> bool {
    let domain = state::domain();
    if domain.is_null() {
        return false;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    domain.settling()
}

/// Every managed thread is parked and none is waking: no thread can make progress until time does.
/// Called on managed threads only, never from inside a backend's wait loop (which checks the same
/// thing under its own lock).
fn quiescent_here() -> bool {
    here().is_some_and(|domain| domain.quiescent(settling()))
}

/// [`stalled`] for the calling thread's domain, with `settling` asked of its layers; the
/// counterpart of [`quiescent_here`] for threads that are not participants.
fn stalled_here() -> bool {
    here().is_some_and(|domain| domain.stalled(settling()))
}

/// Whether a native blocking wait on this thread is one the simulation should account for: a
/// participant running the code under test, not the sim's own internals (which run under
/// passthrough and keep their own count) nor a thread of another class.
pub(crate) fn counts_native_waits() -> bool {
    !state::passthrough() && !state::domain().is_null() && accounting::participant()
}

/// Whether a native wait's timeout on this thread was measured on the domain's clock: any managed
/// thread of the code under test except a driver, whose clock is real.
pub(crate) fn virtual_waits() -> bool {
    !state::passthrough()
        && !state::domain().is_null()
        && accounting::class() != ThreadClass::Driver
}

/// Whether this thread's wakes must reach its domain's deterministic schedule: any managed thread
/// of the code under test, of any class, since a participant may be waiting on what it releases.
pub(crate) fn det_wakes() -> bool {
    !state::passthrough() && with_sched(|_| ()).is_some()
}

/// Counts the calling participant parked in a native wait, then nudges the domain: wakes the
/// sim's waiters if that completed quiescence, and offers the layers an idle skip.
fn enter_native_wait() {
    drop(mark_waiting(true));
    notify_native_wait();
}

fn notify_native_wait() {
    // Completing quiescence from outside the sim's wait loops would otherwise go unnoticed until
    // their next quiescence poll; wake them so they time-skip or give up now.
    if !executive_attached() && quiescent_here() {
        wake_waiters();
    }
    offer_idle_skip(state::domain());
}

/// Wakes the sim's waiters of `domain` outside a deterministic schedule if a participant leaving
/// it completed quiescence, so a waiter that last looked while the leaver still ran time-skips now
/// rather than at its next poll.
fn wake_if_quiescent(domain: &Inner) {
    if domain.sched.is_some() {
        return;
    }
    let _passthrough = Passthrough::enter();
    let settling = domain.settling();
    if domain.quiescent(settling) {
        domain.wake_waiters();
    }
}

/// Tells the layers of the domain at `domain` (null for none) that every participant may now be
/// blocked in waits that run no time skip of its own (see [`Layer::native_quiescence`]).
fn offer_idle_skip(domain: *const Inner) {
    if domain.is_null() {
        return;
    }
    // SAFETY: the caller holds a strong count on the domain.
    let inner = unsafe { &*domain };
    if inner.sched.is_some() || !inner.quiescent(false) {
        return;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: as above; the handle takes one more count of its own.
    let handle = unsafe {
        Arc::increment_strong_count(domain);
        Domain(Arc::from_raw(domain))
    };
    for layer in &inner.layers {
        layer.native_quiescence(&handle);
    }
}

/// Whether the calling thread's domain's layers woke wakers from inside the sim since last asked
/// (see [`Layer::take_timer_wakes`]).
pub(crate) fn took_timer_wakes() -> bool {
    here().is_some_and(Inner::take_timer_wakes)
}

#[cfg(windows)]
pub(crate) fn take_timer_word_wakes() -> Vec<TimerWordWake> {
    here().map_or_else(Vec::new, |domain| {
        let _pass = Passthrough::enter();
        std::mem::take(&mut *domain.timer_word_wakes.lock().unwrap())
    })
}

/// Runs a native blocking wait (a futex, a condvar, a contended mutex) counted toward the domain's
/// quiescence, like the sim's own waits: a managed thread blocked here can only be released by
/// another managed thread, so without the count a peer parked in a sim wait could never see the
/// domain as quiescent and would wait forever. Off a domain, or inside the sim, it just runs.
///
/// On return the thread waits at an open timestamp's gate, rejoins a deterministic schedule that
/// let it go, and takes any signal posted to it while it was blocked: the wait is not interrupted
/// as a real `pthread_kill` would interrupt it (man 7 signal, "Interruption of system calls and
/// library functions by signal handlers"), so delivery waits for it to return.
pub(crate) fn native_wait<R>(wait: impl FnOnce() -> R) -> R {
    native_wait_if(wait, |_| true)
}

pub(crate) fn native_wait_if<R>(wait: impl FnOnce() -> R, woken: impl FnOnce(&R) -> bool) -> R {
    native_wait_inner(wait, woken)
}

#[cfg(any(windows, target_os = "linux"))]
pub(crate) fn native_wait_at_checked<R>(
    deadline: Option<std::time::Duration>,
    preflight: impl FnOnce() -> Option<R>,
    wait: impl FnOnce() -> R,
    woken: impl FnOnce(&R) -> bool,
) -> R {
    if !counts_native_waits() {
        return preflight().unwrap_or_else(wait);
    }
    accounting::note_wait_deadline(deadline);
    let mut ready = None;
    let bump = park_if(here().unwrap(), false, || {
        ready = preflight();
        ready.is_none()
    });
    let Some(bump) = bump else {
        return ready.unwrap();
    };
    drop(bump);
    notify_native_wait();
    native_wait_parked(wait, woken)
}

fn native_wait_inner<R>(wait: impl FnOnce() -> R, woken: impl FnOnce(&R) -> bool) -> R {
    if !counts_native_waits() {
        return wait();
    }
    enter_native_wait();
    native_wait_parked(wait, woken)
}

fn native_wait_parked<R>(wait: impl FnOnce() -> R, woken: impl FnOnce(&R) -> bool) -> R {
    let result = wait();
    drop(unpark_inner(here().unwrap(), false, true, woken(&result)));
    rejoin_schedule();
    if let Some(domain) = here() {
        drain_signals(domain);
    }
    result
}

/// As [`native_wait`], for a wait a [`det_wake`] on `key` ends: a thread the deterministic
/// schedule let go takes the baton in the order that wake gives it, when a run is active again.
pub(crate) fn native_wait_on<R>(key: crate::sched::DetKey, wait: impl FnOnce() -> R) -> R {
    if accounting::participant()
        && let Some(sched) = here().and_then(|domain| domain.sched.as_ref())
    {
        sched.wait_outside(thread_lineage(), key);
    }
    native_wait(wait)
}

/// A participant the deterministic schedule let go, back from a native wait while a run is active,
/// waits for the baton (see `Scheduler::rejoin`).
fn rejoin_schedule() {
    if !accounting::participant() {
        return;
    }
    if let Some(sched) = here().and_then(|domain| domain.sched.as_ref()) {
        sched.rejoin(thread_lineage());
    }
}

/// As [`native_wait`], for a condition-variable wait, which returns holding the caller's mutex:
/// woken during an executive's timestamp, it lets go of the mutex (`relock(false)`), waits at the
/// gate and takes the mutex back (`relock(true)`), so the gate never holds the code under test's
/// lock. A condition variable may wake spuriously (POSIX `pthread_cond_wait`: "Spurious wakeups
/// ... may occur"), so the caller cannot tell and re-checks its predicate either way. Unlike
/// [`native_wait`] it does not deliver signals posted meanwhile; the thread's next hooked call
/// does.
pub(crate) fn native_cond_wait<R>(relock: &dyn Fn(bool), wait: impl FnOnce() -> R) -> R {
    if !counts_native_waits() {
        return wait();
    }
    enter_native_wait();
    let result = wait();
    leave_cond_wait(relock, true);
    rejoin_schedule();
    result
}

/// Unparks a participant returning from a condition-variable wait. While a timestamp's gate is
/// closed it lets go of the caller's mutex, waits at the gate and retakes the mutex, then tries
/// again: the gate may close again while it retakes the mutex.
fn leave_cond_wait(relock: &dyn Fn(bool), mut woken: bool) {
    let Some(domain) = here() else {
        return;
    };
    loop {
        if let Some(bump) = unpark_inner(domain, false, false, woken) {
            drop(bump);
            return;
        }
        woken = false;
        relock(false);
        pass_gate();
        relock(true);
    }
}

/// Notes that the calling participant is about to join the thread with OS handle `handle`, so
/// that thread's exit counts as releasing it until it runs again (see [`native_wait`]).
pub(crate) fn begin_join(handle: usize) -> bool {
    if !counts_native_waits() {
        return false;
    }
    let Some(domain) = here() else {
        return false;
    };
    let Some(target) = domain.accounting.lineage_of(handle) else {
        return false;
    };
    let _passthrough = Passthrough::enter();
    let mut core = domain.accounting.core();
    if !core.rows.contains_key(&target) {
        return false;
    }
    *core.joining.entry(target).or_default() += 1;
    accounting::set_join_target(Some(target));
    true
}

/// How a [`timed_native_wait`] ended.
pub(crate) enum TimedWait<R> {
    /// The real wait returned before the timeout: woken, or a primitive-specific early return.
    Woken(R),
    /// The timeout elapsed — in virtual time under a virtual clock.
    TimedOut,
}

/// The longest real-time slice of one attempt in a [`timed_native_wait`] under a virtual clock: the
/// bound on how late the wait notices that virtual time reached its deadline. A snare choice:
/// short enough that a time skip is seen promptly, long enough that a waiting thread costs little
/// CPU; no OS value is involved.
const NATIVE_WAIT_SLICE: std::time::Duration = std::time::Duration::from_millis(2);

/// Runs a native wait with a timeout of `after`, measured in the domain's time.
///
/// `attempt(slice)` performs one real wait bounded by `slice` of real time, returning `Some` when
/// it ended for any reason other than that slice running out. Under a virtual clock the timeout is
/// registered as a pending timer and the wait proceeds in short slices, checking the virtual
/// deadline between them and, on a participant, time-skipping when the domain is quiescent — the
/// kernel cannot time out on a clock it does not know. A paused clock keeps the wait slicing until
/// something moves time. Elsewhere it is a single attempt of `after`, which on a clock that ticks
/// on each read carries the clock to the deadline if it times out. A thread of another class waits
/// the same way without being counted, and its timer never steers a skip.
///
/// `spurious` returns `Woken(value)` after any slice that times out short of the deadline instead
/// of waiting again: needed by condition variables, whose wakeups are not latched and would be lost
/// if signalled between two slices (POSIX `pthread_cond_signal`: no effect "if they determine that
/// there are no threads blocked on cond"). Futex-style waits, which re-check a value (man 2const
/// FUTEX_WAIT), and semaphores, which count signals (POSIX `sem_post`), can loop safely and pass
/// `None`.
///
/// `relock` is a condition variable's mutex, as for [`native_cond_wait`].
pub(crate) fn timed_native_wait<R>(
    after: std::time::Duration,
    spurious: Option<R>,
    relock: Option<&dyn Fn(bool)>,
    attempt: impl FnMut(std::time::Duration) -> Option<R>,
) -> TimedWait<R> {
    timed_native_wait_if(after, spurious, relock, attempt, |_| true)
}

pub(crate) fn timed_native_wait_if<R>(
    after: std::time::Duration,
    spurious: Option<R>,
    relock: Option<&dyn Fn(bool)>,
    attempt: impl FnMut(std::time::Duration) -> Option<R>,
    woken: impl Fn(&R) -> bool,
) -> TimedWait<R> {
    timed_native_wait_inner(after, spurious, relock, || None, attempt, woken)
}

#[cfg(any(windows, target_os = "linux"))]
pub(crate) fn timed_native_wait_checked<R>(
    after: std::time::Duration,
    preflight: impl FnOnce() -> Option<R>,
    attempt: impl FnMut(std::time::Duration) -> Option<R>,
    woken: impl Fn(&R) -> bool,
) -> TimedWait<R> {
    timed_native_wait_inner(after, None, None, preflight, attempt, woken)
}

fn timed_native_wait_inner<R>(
    after: std::time::Duration,
    mut spurious: Option<R>,
    relock: Option<&dyn Fn(bool)>,
    preflight: impl FnOnce() -> Option<R>,
    mut attempt: impl FnMut(std::time::Duration) -> Option<R>,
    woken: impl Fn(&R) -> bool,
) -> TimedWait<R> {
    use crate::layer::ClockKind;
    let single = |attempt: &mut dyn FnMut(std::time::Duration) -> Option<R>| match attempt(after) {
        Some(r) => TimedWait::Woken(r),
        None => TimedWait::TimedOut,
    };
    if !virtual_waits() {
        return single(&mut attempt);
    }
    let counted = counts_native_waits();
    if after.is_zero() {
        // A zero timeout is a non-blocking check, and a caller repeating it is busy-waiting for
        // time to pass: under a discrete clock nothing else would ever move it.
        yield_point();
        charge_latency();
        return single(&mut attempt);
    }
    let start = now(ClockKind::Monotonic);
    let (Some(start), Some(key)) = (start, register_timer(after)) else {
        let outcome = match relock {
            Some(relock) => native_cond_wait(relock, || single(&mut attempt)),
            None => native_wait(|| single(&mut attempt)),
        };
        if let (Some(start), TimedWait::TimedOut) = (start, &outcome) {
            expire_timer(start.saturating_add(after));
        }
        return outcome;
    };
    let deadline = start.saturating_add(after);
    if counted {
        accounting::note_wait_deadline(Some(deadline));
        let mut ready = None;
        let bump = park_if(here().unwrap(), false, || {
            ready = preflight();
            ready.is_none()
        });
        let Some(bump) = bump else {
            unregister_timer(key);
            return TimedWait::Woken(ready.unwrap());
        };
        drop(bump);
        notify_native_wait();
    }
    let mut was_woken = false;
    let outcome = loop {
        let slice = now(ClockKind::Monotonic)
            .and_then(|t| real_span(deadline.saturating_sub(t)))
            .map_or(NATIVE_WAIT_SLICE, |span| span.min(NATIVE_WAIT_SLICE));
        if let Some(r) = attempt(slice) {
            was_woken = woken(&r);
            break TimedWait::Woken(r);
        }
        if now(ClockKind::Monotonic).is_some_and(|t| t >= deadline) {
            break TimedWait::TimedOut;
        }
        if virtual_now().is_none() {
            expire_timer(deadline);
            break TimedWait::TimedOut;
        }
        if counted && quiescent_here() && time_skip() {
            wake_waiters();
            if now(ClockKind::Monotonic).is_some_and(|t| t >= deadline) {
                break TimedWait::TimedOut;
            }
        }
        if !counted && stalled_here() && foreign_time_skip() {
            wake_waiters();
            if now(ClockKind::Monotonic).is_some_and(|t| t >= deadline) {
                break TimedWait::TimedOut;
            }
        }
        if let Some(value) = spurious.take() {
            break TimedWait::Woken(value);
        }
    };
    // Counted running again before the deadline goes: a caller that re-waits after a spurious
    // return registers the same deadline anew, and in between a peer must not find the domain
    // quiescent with no timer of this thread's left to stop its skip.
    if counted {
        match relock {
            Some(relock) => leave_cond_wait(relock, was_woken),
            None => drop(unpark_inner(here().unwrap(), false, true, was_woken)),
        }
        rejoin_schedule();
    }
    unregister_timer(key);
    outcome
}

/// The virtual time a call that returns without blocking costs under a discrete clock — Shadow's
/// unblocked-syscall latency, whose default is the same 1 µs (Shadow configuration spec,
/// `experimental.unblocked_syscall_latency`, default "1 microseconds", off unless
/// `general.model_unblocked_syscall_latency` is set;
/// <https://shadow.github.io/docs/guide/shadow_config_spec.html>). Shadow applies it in batches
/// once `max_unapplied_cpu_latency` accumulates; snare charges it on every call.
///
/// A microsecond is coarser than the resolution of every clock a caller reads time back through,
/// so polling until a deadline always gets past it. On Windows, QueryPerformanceCounter's
/// frequency "is fixed to 10 MHz" under a hypervisor and on some newer versions (a 100 ns tick),
/// and Microsoft recommends it wherever a resolution of "1 microsecond or better" is needed
/// ([Microsoft Learn: Acquiring high-resolution time
/// stamps](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps)).
/// On macOS a Mach absolute-time tick is the ratio `mach_timebase_info` returns (XNU
/// osfmk/mach/mach_time.h): 1/1 on Intel Macs, and 125/3 ≈ 41.7 ns as measured on an Apple M5
/// Pro running macOS 26; Apple documents only that callers must apply the ratio. On Linux
/// `clock_getres(CLOCK_MONOTONIC)` (man 2 clock_getres) reported 1 ns, measured on kernel 7.0
/// (OrbStack, arm64) with high-resolution timers (man 7 time, "High-resolution timers").
const CALL_LATENCY: std::time::Duration = std::time::Duration::from_micros(1);

/// Charges the calling managed thread's domain `CALL_LATENCY` (1 µs) of virtual time for a call
/// that returned without blocking: a non-blocking receive that found nothing, a poll that returned
/// at once. A discrete clock otherwise only moves when every thread is blocked, so a thread that
/// busy-polls — never blocking, never yielding — would freeze it, and with it every sleeper the
/// poll is waiting on. Charged per call, time crawls under a spinner and timers fire in order as
/// it passes them, rather than jumping ahead of work the spinner is about to do. A no-op off a
/// domain, on clocks that are not discrete, and for threads that are not participants, which
/// never steer time. Backends call it from their non-blocking returns.
pub fn charge_latency() {
    let domain = state::domain();
    if domain.is_null() || !accounting::participant() {
        return;
    }
    if !state::passthrough() {
        end_spin();
    }
    let fired = {
        let _passthrough = Passthrough::enter();
        // SAFETY: see `Domain::current`.
        let domain = unsafe { &*domain };
        domain
            .layers
            .iter()
            .any(|layer| layer.charge_latency(CALL_LATENCY))
    };
    if fired {
        wake_waiters();
    }
    with_sched(|sched| sched.release_due_native_at(virtual_now()));
    // A thread busy-polling would otherwise keep the baton forever.
    det_yield();
}

/// A managed thread yielding the CPU (`sched_yield`, man 2 sched_yield; `SwitchToThread`,
/// [Microsoft Learn: SwitchToThread function](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-switchtothread)) — the spin phase of most
/// locks and channels before they block, and the whole of a hand-rolled spin-wait. A spinning
/// thread never parks, so under a discrete virtual clock a spin waiting on a timer would stall
/// the clock for good. If every other managed thread is parked, the spinner is waiting on time
/// itself, so offer a time skip. The yielder is deliberately not counted as parked: it may be
/// about to make progress, and counting it could make a peer's sim wait declare a false deadlock.
///
/// A yield is also one event of a spin (see [`clock_spin`]). A yielder that read the clock since
/// its last yield is polling it, waiting on a deadline of its own: it gets no time skip, which
/// would jump past that deadline to another thread's, but moves time by the steps its reads take
/// once its spin is caught, and its yield only hands other threads a turn. A yield-only spin gets
/// no skip while a thread polling the clock is about, for the same reason. Under a deterministic
/// schedule a yield-only spin is caught at its first yield, so a yield with no other thread able
/// to run time-skips there as it does here.
pub(crate) fn yield_point() {
    if !counts_native_waits() {
        return;
    }
    let (caught, polling) = note_spin(false);
    let det = det_active();
    if polling {
        if det {
            det_yield();
        }
        return;
    }
    if caught || det {
        clock_spin(false);
        return;
    }
    let Some(domain) = here() else {
        return;
    };
    let live = domain.participants.load(Ordering::SeqCst);
    // `+ 1` counts the yielder itself, which is running but waiting on time like the parked rest.
    if live == 0
        || domain.parked.load(Ordering::SeqCst) + domain.spinning.load(Ordering::SeqCst) + 1 < live
        || domain.clock_spinning.load(Ordering::SeqCst) > 0
        || domain.accounting.leases_held()
        || settling()
        || domain.lock_unheld()
    {
        return;
    }
    if time_skip_inner(Some(true)) {
        wake_waiters();
    }
}

/// How many clock reads and yields in a row, with no other hooked call between them, make a
/// participant's loop a *clock spin*: a thread waiting on time by polling it
/// (`while Instant::now() < deadline {}`, spin_sleep's final spin, a yield loop on a flag a timer
/// sets). A snare choice. Code that reads the clock for a timestamp or an elapsed time takes one
/// to a few reads between calls the sim sees (std's `Instant::now` and `SystemTime::now` read it
/// once), so it never gets near 64; a read-and-yield loop is caught after 32 turns, a few
/// microseconds of real time.
const SPIN_AFTER: u32 = 64;

/// The fraction of a clock spin's length each of its steps moves virtual time: 1/64 of the
/// virtual time since the spin was caught, between [`CALL_LATENCY`] and one second. The cap
/// keeps sustained clock polling from rapidly exhausting the clock's representable range.
const SPIN_STEP_DIVISOR: u32 = 64;

/// The longest a spin's step waits, in real time, for waiters already woken to run (see
/// [`clock_spin`]). A snare choice, the 5 ms a sim wait settles for after a time skip on another
/// thread's behalf; waiters normally take microseconds.
const SPIN_SETTLE: std::time::Duration = std::time::Duration::from_millis(5);

/// The calling thread's current spin: its clock reads and yields since its last other hooked call.
#[derive(Clone, Copy)]
struct Spin {
    /// Clock reads and yields in a row, saturating.
    events: u32,
    /// Whether the thread read the clock since its last yield: it polls the clock, waiting on a
    /// deadline of its own rather than only on what another thread does.
    polling: bool,
    /// Virtual monotonic time when the spin was caught, which its steps grow from.
    origin: Option<std::time::Duration>,
    /// The domain whose `spinning` count includes this thread; null while it is not counted.
    counted: *const Inner,
    /// Whether it is counted in that domain's `clock_spinning` too: its last counted step polled
    /// the clock.
    counted_clock: bool,
}

impl Spin {
    /// No spin.
    const IDLE: Spin = Spin {
        events: 0,
        polling: false,
        origin: None,
        counted: ptr::null(),
        counted_clock: false,
    };
}

thread_local! {
    /// The calling thread's spin. Const-initialised with no destructor, so a hook can read it
    /// without allocating; [`end_spin`] runs before the thread leaves its domain.
    static SPIN: std::cell::Cell<Spin> = const { std::cell::Cell::new(Spin::IDLE) };
}

/// Counts one clock read (`read`) or yield of the calling participant toward a spin, returning
/// whether the spin is caught ([`SPIN_AFTER`] events) and whether this event polls the clock: a
/// read does, and so does a yield that follows a read.
fn note_spin(read: bool) -> (bool, bool) {
    SPIN.try_with(|cell| {
        let mut spin = cell.get();
        spin.events = spin.events.saturating_add(1);
        let polling = read || spin.polling;
        spin.polling = read;
        cell.set(spin);
        (spin.events >= SPIN_AFTER, polling)
    })
    .unwrap_or((false, false))
}

/// Ends the calling thread's spin: it made a hooked call other than a clock read or a yield, began
/// a wait, changed class or is leaving its domain. Uncounts it where it was counted. A backend
/// calls it as one of its own waits begins, which no hook brackets: a tester's idle wait runs
/// under passthrough, and without it the clock reads of the tester's loop and handlers between
/// waits would add up to a spin and step time on.
pub fn end_spin() {
    let Ok(spin) = SPIN.try_with(|cell| cell.replace(Spin::IDLE)) else {
        return;
    };
    if spin.counted.is_null() {
        return;
    }
    // SAFETY: a thread is counted only in the domain managing it, whose `Managed` guard runs this
    // before it lets the domain go.
    let domain = unsafe { &*spin.counted };
    domain.spinning.fetch_sub(1, Ordering::SeqCst);
    if spin.counted_clock {
        domain.clock_spinning.fetch_sub(1, Ordering::SeqCst);
    }
    if let Some(sched) = &domain.sched {
        sched.unspin(thread_lineage());
    }
}

/// Counts the calling thread's caught spin in `domain`'s `spinning`, and in `clock_spinning` while
/// it polls the clock (`clock`), noting where it started; returns where its steps grow from.
fn count_spin(domain: &Inner, clock: bool) -> Option<std::time::Duration> {
    let Ok(mut spin) = SPIN.try_with(std::cell::Cell::get) else {
        return None;
    };
    if spin.counted.is_null() {
        domain.spinning.fetch_add(1, Ordering::SeqCst);
        spin.counted = domain;
        spin.origin = domain.virtual_now();
    }
    if clock != spin.counted_clock {
        if clock {
            domain.clock_spinning.fetch_add(1, Ordering::SeqCst);
        } else {
            domain.clock_spinning.fetch_sub(1, Ordering::SeqCst);
        }
        spin.counted_clock = clock;
    }
    let _ = SPIN.try_with(|cell| cell.set(spin));
    spin.origin
}

/// One step of the calling participant's caught spin, `clock` when the event polls the clock (a
/// read, or a yield after one): a thread that keeps reading the clock or yielding, with no other
/// hooked call between, is waiting on time, and nothing else would move a discrete clock while it
/// spins.
///
/// Time moves only when every other participant is parked or spinning too (counting itself, as
/// [`yield_point`] does), no waiter is waking (the step waits up to [`SPIN_SETTLE`] for woken ones
/// to run), no lease is held and no participant waits on a lock no thread of the domain holds
/// (`Inner::lock_unheld`): any other running thread may have work to do at the current instant,
/// which comes first. Then:
///
/// - A clock read of the spin moves time one step (see [`Layer::spin_step`]): 1/64 of the
///   virtual time since the spin was caught, between 1 µs and 1 s, landing 1 ns short of the earliest
///   timer it would reach and past it on the next step, so the threads woken there run at their
///   own instants and in order with the spinner. A yield-only spin, which waits on another
///   thread rather than on a deadline of its own, gets the full time skip [`yield_point`] offers,
///   unless a clock spinner is about.
/// - Under a deterministic schedule the step is a scheduling point: if another runnable thread is
///   not itself spinning, the spinner hands it the baton first; after a step, the threads it
///   released run before the spinner's next step (see `Scheduler::spin`).
/// - On a held clock (paused, or driven by an executive) the spin moves nothing and yields the CPU
///   for real; the stuck watchdog then sees a busy participant and no progress, and reports it.
///   A clock that moves on its own (scaled to real time, ticking on reads, the real clock) is left
///   alone.
fn clock_spin(clock: bool) {
    let Some(domain) = here() else {
        return;
    };
    let origin = count_spin(domain, clock);
    if let Some(sched) = domain.sched.as_ref().filter(|sched| !sched.detached()) {
        sched.spin(thread_lineage(), clock, || {
            if clock {
                spin_advance(domain, origin)
            } else {
                time_skip()
            }
        });
        return;
    }
    // `settling` first: a woken waiter stops settling only as it leaves the parked count, so a
    // count read after it never shows a waiter running as parked. Waking waiters run promptly, so
    // the spin waits them out rather than skip its step; how many steps a spin takes then does
    // not hang on how the OS schedules them.
    let settle = accounting::real_elapsed();
    while settling() {
        if accounting::real_elapsed().saturating_sub(settle) >= SPIN_SETTLE {
            return;
        }
        real(std::thread::yield_now);
    }
    let live = domain.participants.load(Ordering::SeqCst);
    let waiting = domain.parked.load(Ordering::SeqCst) + domain.spinning.load(Ordering::SeqCst)
        >= live
        && !domain.accounting.leases_held()
        && !domain.lock_unheld();
    if !waiting {
        real(std::thread::yield_now);
        return;
    }
    if !clock {
        if domain.clock_spinning.load(Ordering::SeqCst) == 0 && time_skip_inner(Some(false)) {
            wake_waiters();
        }
        return;
    }
    if spin_advance(domain, origin) {
        wake_waiters();
    }
}

/// Moves `domain`'s clock one step of a spin caught at `origin` (see [`clock_spin`]), returning
/// whether the step reached a pending timer. Yields the CPU for real when the clock is held or a
/// waiter it reached has yet to run.
fn spin_advance(domain: &Inner, origin: Option<std::time::Duration>) -> bool {
    let _passthrough = Passthrough::enter();
    let Some(_gate) = domain.accounting.skip_gate() else {
        return false;
    };
    let Some(now) = domain.virtual_now() else {
        return false;
    };
    let spun = now.saturating_sub(origin.unwrap_or(now));
    let step = (spun / SPIN_STEP_DIVISOR)
        .max(CALL_LATENCY)
        .min(std::time::Duration::from_secs(1));
    for layer in &domain.layers {
        match layer.spin_step(step) {
            crate::layer::SpinStep::Moved { fired } => return fired,
            crate::layer::SpinStep::Held | crate::layer::SpinStep::Waking => {
                std::thread::yield_now();
                return false;
            }
            crate::layer::SpinStep::Runs => {}
        }
    }
    false
}

/// A managed thread's read of `clock` from a clock hook (`clock_gettime`, `mach_absolute_time`,
/// `QueryPerformanceCounter` and the rest), as its layers answer it, or `None` where nothing
/// models the clock and the read goes to the OS. A participant's read is one event of a spin (see
/// [`clock_spin`]); once its spin is caught, the read steps it and then reads the moved clock.
pub(crate) fn read_clock(clock: crate::layer::ClockKind) -> Option<std::time::Duration> {
    let value = offer(|layer| layer.now(clock))?;
    if !counts_native_waits() {
        return Some(value);
    }
    if !note_spin(true).0 {
        return Some(value);
    }
    clock_spin(true);
    offer(|layer| layer.now(clock)).or(Some(value))
}

/// The calling thread's domain's time on a virtual clock that moves only as the sim moves it —
/// discrete, scaled to real time, or paused (see [`Layer::virtual_now`]) — or `None` off a domain
/// or on any other clock. Unlike [`now`] it never advances the clock, and it reads the same under
/// passthrough, so the sim's own code can measure deadlines on the clock the code under test sees.
pub fn virtual_now() -> Option<std::time::Duration> {
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    unsafe { &*domain }.virtual_now()
}

/// The real time `span` of the calling thread's domain's virtual time takes to pass on its own
/// (see [`Layer::real_span`]), or `None` when it does not pass on its own.
pub fn real_span(span: std::time::Duration) -> Option<std::time::Duration> {
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    unsafe { &*domain }.real_span(span)
}

/// Whether the calling thread's domain's clock is held or will move on its own (see
/// [`Layer::idle_wait`]), and how long to wait in real time before checking it again.
pub fn idle_wait() -> Option<std::time::Duration> {
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    unsafe { &*domain }.idle_wait()
}

/// The calling managed thread's virtual clock, as its layers report it, or `None` off a domain or
/// where nothing models the clock. A backend uses this to stamp timestamps against simulated time
/// rather than the host clock — it works even while the backend runs under passthrough.
pub fn now(clock: crate::layer::ClockKind) -> Option<std::time::Duration> {
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    domain
        .layers
        .iter()
        .find_map(|layer| match layer.now(clock) {
            Flow::Done(value) => Some(value),
            Flow::Pass => None,
        })
}

/// Offers one operation to the calling thread's layers. `None` means it goes to the OS. Any call
/// offered here ends the thread's clock spin (see [`clock_spin`]); a clock read goes through
/// [`read_clock`] instead.
pub(crate) fn dispatch<T>(op: impl FnMut(&dyn Layer) -> Flow<T>) -> Option<T> {
    if !state::passthrough() && !state::domain().is_null() {
        end_spin();
    }
    offer(op)
}

/// [`dispatch`] without ending a clock spin.
fn offer<T>(mut op: impl FnMut(&dyn Layer) -> Flow<T>) -> Option<T> {
    if state::passthrough() {
        return None;
    }
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    drain_signals(domain);
    let _passthrough = Passthrough::enter();
    domain
        .layers
        .iter()
        .find_map(|layer| match op(layer.as_ref()) {
            Flow::Done(value) => Some(value),
            Flow::Pass => None,
        })
}

/// Records an unmodelled call made by the calling thread, if it is managed.
pub(crate) fn observe(function: &'static str, detail: Option<i64>) {
    if state::passthrough() {
        return;
    }
    let domain = state::domain();
    if domain.is_null() {
        return;
    }
    end_spin();
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    let call = Unmodelled { function, detail };
    *domain
        .unmodelled
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(call)
        .or_default() += 1;
    for layer in &domain.layers {
        layer.unmodelled(call);
    }
    if domain.accounting.auditing() {
        domain.accounting.note_violation(QuiescenceViolation {
            thread: domain.display_name(thread_lineage()),
            op: function,
            blocked: false,
            fatal: false,
            at: domain.virtual_now().unwrap_or_default(),
        });
    }
}

#[cfg(unix)]
static DESCRIPTOR_MUTATIONS: Mutex<()> = Mutex::new(());

#[cfg(unix)]
type DescriptorCleanups = Vec<Box<dyn FnOnce()>>;

#[cfg(unix)]
thread_local! {
    static DESCRIPTOR_CLEANUPS: std::cell::RefCell<Option<DescriptorCleanups>> = const { std::cell::RefCell::new(None) };
}

#[cfg(unix)]
struct DescriptorTransaction {
    guard: Option<std::sync::MutexGuard<'static, ()>>,
}

#[cfg(unix)]
impl Drop for DescriptorTransaction {
    fn drop(&mut self) {
        let cleanups = DESCRIPTOR_CLEANUPS
            .with(|pending| pending.borrow_mut().take())
            .unwrap_or_default();
        real(|| drop(self.guard.take()));
        for cleanup in cleanups {
            real(cleanup);
        }
    }
}

/// Serializes descriptor ownership changes. Cleanup that can wait runs after the mutation lock
/// is released through [`defer_descriptor_cleanup`].
#[cfg(unix)]
pub fn descriptor_transaction<R>(op: impl FnOnce() -> R) -> R {
    if state::domain().is_null() || DESCRIPTOR_CLEANUPS.with(|pending| pending.borrow().is_some()) {
        return op();
    }
    let guard = real(|| DESCRIPTOR_MUTATIONS.lock().unwrap());
    DESCRIPTOR_CLEANUPS.with(|pending| *pending.borrow_mut() = Some(Vec::new()));
    let _transaction = DescriptorTransaction { guard: Some(guard) };
    op()
}

/// Defers descriptor cleanup until the current ownership transaction has completed.
#[cfg(unix)]
pub fn defer_descriptor_cleanup(cleanup: Box<dyn FnOnce()>) {
    let cleanup = DESCRIPTOR_CLEANUPS.with(|pending| {
        let mut pending = pending.borrow_mut();
        if let Some(pending) = pending.as_mut() {
            pending.push(cleanup);
            None
        } else {
            Some(cleanup)
        }
    });
    if let Some(cleanup) = cleanup {
        cleanup();
    }
}

#[cfg(unix)]
pub(crate) fn descriptor_close_can_wait(fd: core::ffi::c_int) -> bool {
    real(|| {
        let mut linger = libc::linger {
            l_onoff: 0,
            l_linger: 0,
        };
        let mut len = std::mem::size_of::<libc::linger>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                (&mut linger as *mut libc::linger).cast(),
                &mut len,
            )
        };
        result == 0 && linger.l_onoff != 0 && linger.l_linger > 0
    })
}

/// Offers a socket call to the calling thread's [`Net`], if it has one. `Some` handled it (as the
/// Linux kernel would, a negative errno on failure: man 2 intro, "RETURN VALUE"); `None` means the call goes to the OS. Available on
/// every platform: the unix socket hooks and the Windows `pcap`/`wpcap` hooks both consult it.
pub(crate) fn dispatch_net(
    mut op: impl FnMut(&dyn Net) -> Option<crate::net::NetResult>,
) -> Option<i64> {
    if state::passthrough() {
        return None;
    }
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    end_spin();
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    domain
        .net
        .iter()
        .find_map(|net| op(net.as_ref()))
        .map(crate::net::NetResult::into_raw)
}

#[cfg(windows)]
pub(crate) fn dispatch_net_for(
    domain: &Domain,
    mut op: impl FnMut(&dyn Net) -> Option<crate::net::NetResult>,
) -> Option<i64> {
    let _passthrough = Passthrough::enter();
    domain
        .0
        .net
        .iter()
        .find_map(|net| op(net.as_ref()))
        .map(crate::net::NetResult::into_raw)
}

#[cfg(unix)]
pub(crate) fn dispatch_dup_to(
    oldfd: core::ffi::c_int,
    newfd: core::ffi::c_int,
    flags: Option<core::ffi::c_int>,
    real: impl FnOnce() -> core::ffi::c_int,
) -> Option<i64> {
    if state::passthrough() {
        return None;
    }
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    end_spin();
    let _passthrough = Passthrough::enter();
    let domain = unsafe { &*domain };
    let source = domain.net.iter().position(|net| net.owns(oldfd));
    let target = domain.net.iter().position(|net| net.owns(newfd));
    let target_file = target.is_none() && domain.fs.as_ref().is_some_and(|fs| fs.owns(newfd));
    let source_file = source.is_none() && domain.fs.as_ref().is_some_and(|fs| fs.owns(oldfd));
    if target.is_none() && !target_file && oldfd != newfd && descriptor_close_can_wait(newfd) {
        if source.is_none() && !source_file {
            return None;
        }
        let retained = unsafe { libc::fcntl(newfd, libc::F_DUPFD_CLOEXEC, 0) };
        if retained < 0 {
            return Some(
                crate::net::NetResult::Err(
                    std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EMFILE),
                )
                .into_raw(),
            );
        }
        defer_descriptor_cleanup(Box::new(move || unsafe {
            libc::close(retained);
        }));
    }
    let result = if let Some(source) = source {
        unsafe { domain.net[source].dup_to(oldfd, newfd, flags) }
            .unwrap_or(crate::net::NetResult::Err(libc::EOPNOTSUPP))
    } else if source_file {
        unsafe { domain.fs.as_ref().unwrap().dup_to(oldfd, newfd, flags) }
            .unwrap_or(crate::net::NetResult::Err(libc::EOPNOTSUPP))
    } else {
        let result = real();
        if result < 0 {
            crate::net::NetResult::Err(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EBADF),
            )
        } else {
            crate::net::NetResult::Ok(result as i64)
        }
    };
    if matches!(result, crate::net::NetResult::Ok(_)) && oldfd != newfd {
        if let Some(target) = target {
            if Some(target) != source {
                unsafe { domain.net[target].fd_replaced(newfd) };
            }
        } else if target_file
            && !source_file
            && let Some(fs) = domain.fs.as_ref()
        {
            unsafe { fs.fd_replaced(newfd) };
        }
    }
    Some(result.into_raw())
}

/// Offers a name lookup to the calling thread's [`Resolver`], if it has one, with the thread in
/// passthrough. `None` means the call goes to the OS.
pub(crate) fn dispatch_resolver<T>(op: impl FnOnce(&dyn Resolver) -> T) -> Option<T> {
    if state::passthrough() {
        return None;
    }
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    end_spin();
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    let resolver = domain.resolver.as_deref()?;
    Some(op(resolver))
}

/// Whether the calling thread's [`Net`] owns `fd` — the fast path for the generic fd calls. On
/// Windows the Winsock hooks pass a `SOCKET` cast to `c_int` (the sim mints small handles). A real
/// `SOCKET` may take any value from 0 to `INVALID_SOCKET - 1` ([Microsoft Learn: Socket Data
/// Type](https://learn.microsoft.com/en-us/windows/win32/winsock/socket-data-type-2)), so the
/// truncated value only means something to a backend that minted it.
pub(crate) fn net_owns(fd: core::ffi::c_int) -> bool {
    if state::passthrough() {
        return false;
    }
    let domain = state::domain();
    if domain.is_null() {
        return false;
    }
    end_spin();
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    domain.net.iter().any(|net| net.owns(fd))
}

/// [`dispatch_net`] for a call that changes what other threads see (a send, a connect, a close),
/// noted for an executive's audit when a backend handled it.
pub(crate) fn dispatch_net_effect(
    op: &'static str,
    net: impl FnMut(&dyn Net) -> Option<crate::net::NetResult>,
) -> Option<i64> {
    let r = dispatch_net(net);
    if r.is_some() {
        note_effect(op);
    }
    r
}

/// Offers a file call to the calling thread's [`Fs`], if it has one. Mirrors [`dispatch_net`].
#[cfg(unix)]
pub(crate) fn dispatch_fs(op: impl FnOnce(&dyn Fs) -> Option<crate::fs::FsResult>) -> Option<i64> {
    if state::passthrough() {
        return None;
    }
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    end_spin();
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    let fs = domain.fs.as_deref()?;
    op(fs).map(crate::fs::FsResult::into_raw)
}

/// Whether the calling thread's [`Fs`] owns `fd` — the fast path for the generic fd calls.
#[cfg(unix)]
pub(crate) fn fs_owns(fd: core::ffi::c_int) -> bool {
    if state::passthrough() {
        return false;
    }
    let domain = state::domain();
    if domain.is_null() {
        return false;
    }
    end_spin();
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    domain.fs.as_deref().is_some_and(|fs| fs.owns(fd))
}

/// Offers a process/scheduler call to the calling thread's [`Host`], if it has one. No fd, so no
/// `owns` fast path — a `None` host simply declines and the call falls through to observe+forward.
/// Available on every platform: the Linux hooks and the Windows `SetThreadPriority` family both
/// consult it (macOS through the `pthread_*schedparam` hooks).
pub(crate) fn dispatch_host(
    op: impl FnOnce(&dyn Host) -> Option<crate::host::HostResult>,
) -> Option<i64> {
    if state::passthrough() {
        return None;
    }
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    end_spin();
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    let host = domain.host.as_deref()?;
    op(host).map(crate::host::HostResult::into_raw)
}

/// Offers an environment call to the calling thread's [`Env`], if it has one. `Some(r)` means the
/// simulated environment handled it (authoritatively); `None` means the call goes to the real OS
/// environment. Available on all platforms (unix `getenv`/`setenv`/`unsetenv` use it today).
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn dispatch_env<T>(op: impl FnOnce(&dyn Env) -> T) -> Option<T> {
    if state::passthrough() {
        return None;
    }
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    end_spin();
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    let env = domain.env.as_deref()?;
    Some(op(env))
}

/// What a thread being created takes from its creator: a strong reference to the domain, its
/// class and its lineage.
///
/// Holding one owes the domain a strong count and, for a participant, a live count and a queued
/// schedule slot: it must reach exactly one of [`adopt`] (on the new thread) or [`release`] (if
/// the OS failed to create it).
pub(crate) struct Inherited {
    /// A strong count on the domain from `Arc::increment_strong_count`.
    domain: *const Inner,
    /// The class the child starts in (see `accounting::child_class`).
    class: ThreadClass,
    /// The label that goes with `class`.
    label: Option<&'static str>,
    /// The child's lineage id, already counted as born (to its parent, or to the domain's
    /// injected-thread counter).
    pub(crate) lineage: u64,
    /// The child's mutex-hold record, owned by the domain's census.
    held: *const accounting::Held,
}

/// An [`Inherited`] handed to a thread [`Domain::spawn_injected`] creates.
struct SendInherited(Inherited);

// SAFETY: the domain pointer is a strong reference, which may move to another thread.
unsafe impl Send for SendInherited {}

/// What the calling thread's next child inherits, or `None` when the child should start real.
///
/// A participant child counts as live from here, while the parent is still creating it, not from
/// when it first runs: otherwise, in the gap before the OS schedules it, the parent and its peers
/// could all be parked and look quiescent, and the clock would time-skip past work the child has
/// yet to do. Under a deterministic schedule it is queued to run from here too.
pub(crate) fn inherit() -> Option<Inherited> {
    if state::passthrough() {
        return None;
    }
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    end_spin();
    let (class, label) = accounting::child_class();
    // SAFETY: see `Domain::current`.
    unsafe {
        Arc::increment_strong_count(domain);
        if class == ThreadClass::Participant {
            (*domain).participants.fetch_add(1, Ordering::SeqCst);
        }
    }
    let lineage = child_lineage();
    // SAFETY: see `Domain::current`.
    let held = unsafe { &(*domain).accounting }.add_row(lineage, class);
    if class == ThreadClass::Participant {
        with_sched(|sched| sched.spawned(lineage));
    }
    Some(Inherited {
        domain,
        class,
        label,
        lineage,
        held,
    })
}

/// Makes the calling (new) thread managed by the domain it inherited, taking over the reference
/// `inherit` made.
///
/// # Safety
/// `inherited` must come from [`inherit`] on the thread that created this one.
pub(crate) unsafe fn adopt(inherited: Inherited) -> Child {
    let _startup = crate::os::thread_startup();
    let Inherited {
        domain,
        class,
        label,
        lineage,
        held,
    } = inherited;
    // `inherit` already counted a participant live; `Managed::drop` does the matching decrement.
    let managed = Managed {
        previous: state::replace_domain(domain),
        domain,
        root: false,
        previous_lineage: swap_lineage(Lineage {
            id: lineage,
            children: 0,
        }),
        previous_class: accounting::swap_class(class, label),
        previous_held: accounting::swap_held(held),
        _not_send: PhantomData,
    };
    // SAFETY: `domain` is live (see above).
    unsafe { &(*domain).accounting }.record_handle(crate::os::current_thread_handle(), lineage);
    if class == ThreadClass::Participant
        // SAFETY: `domain` is live (see above).
        && let Some(sched) = unsafe { &(*domain).sched }
    {
        sched.started(lineage);
    }
    dispatch(|layer| {
        layer.thread_started();
        Flow::<()>::Pass
    });
    Child { _managed: managed }
}

/// Reclaims what [`inherit`] handed a thread the OS then failed to create.
///
/// # Safety
/// As for [`adopt`].
pub(crate) unsafe fn release(inherited: Inherited) {
    let participant = inherited.class == ThreadClass::Participant;
    // SAFETY: the caller hands back the reference `inherit` created, so the domain is live.
    unsafe { &(*inherited.domain).accounting }.remove_row(inherited.lineage);
    if participant {
        with_sched(|sched| sched.unspawned(inherited.lineage));
    }
    // SAFETY: the caller hands back the single reference `inherit` created, and with it the count
    // it took for a thread that never started.
    unsafe {
        if participant {
            (*inherited.domain)
                .participants
                .fetch_sub(1, Ordering::SeqCst);
        }
        drop(Arc::from_raw(inherited.domain));
    }
}

/// Records a created thread's OS handle against its lineage, so a join on it can wait in a
/// deterministic schedule and a signal aimed at it finds it before it first runs.
pub(crate) fn record_handle(handle: usize, child: u64) {
    if let Some(domain) = here() {
        domain.accounting.record_handle(handle, child);
    }
    with_sched(|sched| sched.record_handle(handle, child));
}

/// Guard returned by [`adopt`], held for the life of a thread the domain's code created. On drop
/// it tells the layers the thread is exiting and leaves a deterministic schedule (waking its
/// joiners), then its [`Managed`] restores the thread and releases the domain.
pub(crate) struct Child {
    _managed: Managed,
}

impl Drop for Child {
    fn drop(&mut self) {
        dispatch(|layer| {
            layer.thread_exiting();
            Flow::<()>::Pass
        });
        if let Some(sched) = here().and_then(|domain| domain.sched.as_ref()) {
            sched.exit(thread_lineage(), false);
        }
    }
}

/// Runs `f` on the calling thread's domain's deterministic scheduler, if it has one, whatever the
/// thread's class. A schedule that has detached (see `Scheduler::detached`) counts as none.
pub(crate) fn with_sched<R>(f: impl FnOnce(&crate::sched::Scheduler) -> R) -> Option<R> {
    here()?
        .sched
        .as_ref()
        .filter(|sched| !sched.detached())
        .map(f)
}

/// As [`with_sched`], for a participant only: the threads that wait and yield in the schedule.
fn with_det<R>(f: impl FnOnce(&crate::sched::Scheduler) -> R) -> Option<R> {
    if !accounting::participant() {
        return None;
    }
    with_sched(f)
}

/// Whether the calling thread runs in its domain's deterministic schedule: a participant of a
/// domain built `deterministic`. Threads of the other classes run outside it. A thread the
/// schedule let go when its last run ended waits here for the baton once a run is active again.
pub fn det_active() -> bool {
    with_det(|sched| sched.rejoin(thread_lineage())).is_some()
}

/// Under deterministic scheduling, parks the running participant on `key` until another thread
/// wakes it with [`det_wake`] or virtual time reaches `deadline` (on the discrete clock). The
/// caller re-checks whatever it waits for when this returns. Off a deterministic domain, or on a
/// thread outside the schedule, it returns at once. The wait ends the thread's clock spin (see
/// [`det_wait_begins`]).
pub fn det_block(
    key: crate::sched::DetKey,
    deadline: Option<std::time::Duration>,
) -> crate::sched::DetWake {
    det_block_with_timer(key, deadline, true, None)
}

/// Parks a simulated readiness wait with the sources that can change its predicate.
pub fn det_block_readiness(
    deadline: Option<std::time::Duration>,
    keys: Option<&[crate::ReadinessKey]>,
    time_sensitive: bool,
) -> crate::DetWake {
    det_block_with_timer(
        crate::DetKey::Readiness,
        deadline,
        true,
        Some(crate::sched::ReadinessInterest::new(
            keys,
            time_sensitive || deadline.is_some(),
        )),
    )
}

/// Wakes deterministic subscriptions reached by the readiness notification.
pub fn det_wake_readiness(event: crate::ReadinessWake<'_>) -> usize {
    with_sched(|sched| sched.wake_readiness(event)).unwrap_or(0)
}

#[cfg(windows)]
pub(crate) fn det_block_registered_timer(
    key: crate::sched::DetKey,
    deadline: Option<std::time::Duration>,
) -> crate::sched::DetWake {
    det_block_with_timer(key, deadline, false, None)
}

fn det_block_with_timer(
    key: crate::sched::DetKey,
    deadline: Option<std::time::Duration>,
    register_timer: bool,
    readiness: Option<crate::sched::ReadinessInterest>,
) -> crate::sched::DetWake {
    with_det(|sched| {
        det_wait_begins(deadline);
        let domain =
            here().expect("a deterministic schedule belongs to the calling thread's domain");
        let lineage = thread_lineage();
        let wait = RowWait {
            label: accounting::current_wait_label(),
            deadline,
            key: None,
            mutex: None,
            #[cfg(target_os = "linux")]
            mask: accounting::wait_mask_value(),
            #[cfg(any(target_os = "linux", windows))]
            token: 0,
            #[cfg(target_os = "linux")]
            expected: accounting::wait_expected_value(),
            #[cfg(target_os = "linux")]
            futex_private: accounting::wait_futex_private(),
            #[cfg(target_os = "linux")]
            pre_released: false,
            #[cfg(target_os = "linux")]
            claimed: false,
            #[cfg(windows)]
            woken: false,
        };
        {
            let _passthrough = Passthrough::enter();
            let stamp = domain.row_stamp();
            let _ = domain
                .accounting
                .core()
                .set_waiting(lineage, Some(wait), stamp);
        }
        #[cfg(target_os = "linux")]
        let mask = accounting::wait_mask_value();
        #[cfg(not(target_os = "linux"))]
        let mask = u32::MAX;
        let why = sched.block(lineage, key, deadline, register_timer, mask, readiness);
        let _passthrough = Passthrough::enter();
        let stamp = domain.row_stamp();
        let _ = domain.accounting.core().set_waiting(lineage, None, stamp);
        why
    })
    .unwrap_or(crate::sched::DetWake::Woken)
}

/// A participant's wait under the deterministic schedule, until `deadline`, has begun: it ends the
/// thread's clock spin (see [`end_spin`]) whether it then blocks or finds what it waits for already
/// there, as the same wait does in a free-running domain, where it is counted parked before the
/// real call. A wait whose deadline has already passed is a poll and leaves the spin running, so a
/// loop of zero-timeout waits and clock reads is still caught as a spin.
pub(crate) fn det_wait_begins(deadline: Option<std::time::Duration>) {
    let passed = deadline.is_some_and(|at| virtual_now().is_some_and(|now| now >= at));
    if !passed {
        end_spin();
    }
}

/// Under deterministic scheduling, makes up to `n` of `key`'s waiters runnable, oldest first, and
/// returns how many. Called from a thread outside the schedule while no thread holds the baton,
/// it hands the baton on. Off a deterministic domain it does nothing.
pub fn det_wake(key: crate::sched::DetKey, n: usize) -> usize {
    with_sched(|sched| sched.wake(key, n)).unwrap_or(0)
}

#[cfg(target_os = "linux")]
pub(crate) fn det_wake_futex(
    key: crate::sched::DetKey,
    n: usize,
    mask: u32,
    private: bool,
) -> usize {
    with_sched(|sched| sched.wake_masked(key, n, mask, Some(private))).unwrap_or(0)
}

/// Records that the running thread took the mutex at `addr` (deterministic scheduling).
#[cfg(any(unix, windows))]
pub(crate) fn det_took(addr: usize) {
    with_det(|sched| sched.took(addr, thread_lineage()));
}

/// Records that the mutex at `addr` was released (deterministic scheduling).
#[cfg(any(unix, windows))]
pub(crate) fn det_released(addr: usize) {
    with_det(|sched| sched.released(addr));
}

#[cfg(windows)]
pub(crate) fn det_took_shared(addr: usize) {
    with_det(|sched| sched.took_shared(addr, thread_lineage()));
}

#[cfg(windows)]
pub(crate) fn det_released_shared(addr: usize) {
    with_det(|sched| sched.released_shared(addr, thread_lineage()));
}

/// Whether one of this domain's threads holds the mutex at `addr`.
#[cfg(any(unix, windows))]
pub(crate) fn det_held_inside(addr: usize) -> bool {
    with_det(|sched| {
        if sched.held_inside(addr) {
            return true;
        }
        #[cfg(target_os = "macos")]
        if let Some(domain) = here()
            && let Some(lineage) = domain.accounting.native_mutex_lineage(addr)
        {
            sched.took(addr, lineage);
            return true;
        }
        false
    })
    .unwrap_or(false)
}

#[cfg(any(target_os = "linux", windows))]
/// Whether `addr` lies in a loaded image (static data), where a lock or futex word may be shared
/// with threads outside this simulation — other tests in the process, unmanaged threads — rather
/// than belong to this test alone.
pub(crate) fn in_static_image(addr: usize) -> bool {
    let _passthrough = Passthrough::enter();
    crate::os::address_in_image(addr)
}

/// The running thread steps aside for the domain's other runnable threads.
pub(crate) fn det_yield() {
    with_det(|sched| sched.yield_now(thread_lineage()));
}

/// The lineage of a running (not yet exited) thread of this domain, by its OS handle.
pub(crate) fn det_lineage_of(handle: usize) -> Option<u64> {
    with_sched(|sched| sched.lineage_of(handle)).flatten()
}

#[cfg(all(test, windows))]
mod timer_callback_tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn signal_before_core_is_released(deterministic: bool) -> bool {
        let builder = Domain::builder();
        let domain = if deterministic {
            builder.deterministic().install()
        } else {
            builder.install()
        };
        let core = domain.0.accounting.core();
        let (started_tx, started_rx) = mpsc::channel();
        let (signal_tx, signal_rx) = mpsc::channel();
        let owner = domain.clone();
        let callback = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            owner.signal_timer_waiters(7, Arc::new(()), || {
                signal_tx.send(()).unwrap();
                1
            });
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let early = signal_rx.recv_timeout(Duration::from_millis(100)).is_ok();
        drop(core);
        callback.join().unwrap();
        if !early {
            signal_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        early
    }

    #[test]
    fn deterministic_timer_callbacks_do_not_wait_on_the_census_lock() {
        assert!(signal_before_core_is_released(true));
    }

    #[test]
    fn native_timer_callbacks_publish_under_the_census_lock() {
        assert!(!signal_before_core_is_released(false));
    }

    #[test]
    fn a_native_spin_waits_until_a_signalled_timer_wait_returns() {
        let domain = Domain::builder().install();
        domain.run(|| {
            let _label = accounting::wait_label_on("sleep", 7);
            native_wait_at_checked(
                Some(Duration::from_nanos(1)),
                || None,
                || {
                    assert_eq!(domain.if_native_spin_step(false, || 1), Some(1));
                    domain.signal_timer_waiters(7, Arc::new(()), || 1);
                    assert_eq!(domain.if_native_spin_step(false, || 1), None);
                },
                |_| true,
            );
            drop(mark_sim_waiting(true));
            assert_eq!(domain.if_native_spin_step(false, || 1), Some(1));
            drop(mark_sim_waiting(false));
        });
    }
}
