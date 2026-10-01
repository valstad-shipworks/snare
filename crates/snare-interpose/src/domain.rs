use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::env::Env;
use crate::fs::Fs;
use crate::host::Host;
use crate::layer::{Flow, Layer, Unmodelled};
use crate::net::Net;
use crate::state::{self, Passthrough};

pub(crate) struct Inner {
    layers: Vec<Arc<dyn Layer>>,
    /// The net backends, tried in order: the first whose call returns `Some` handles it, so a call
    /// a backend declines (`None`) falls through to the next and finally to the OS. This lets a
    /// `SimHost` (NIC ioctls, netlink, UDP) and a plain socket `Fabric` (TCP, raw L2) serve one
    /// domain together — ordered so the host claims what it models and the fabric takes the rest.
    #[cfg_attr(not(unix), allow(dead_code))]
    net: Vec<Arc<dyn Net>>,
    #[cfg_attr(not(unix), allow(dead_code))]
    fs: Option<Arc<dyn Fs>>,
    #[allow(dead_code)] // read once the Host symbol hooks land
    host: Option<Arc<dyn Host>>,
    #[cfg_attr(not(unix), allow(dead_code))]
    env: Option<Arc<dyn Env>>,
    unmodelled: Mutex<BTreeMap<Unmodelled, u64>>,
    /// Count of threads currently managed by this domain — the basis for quiescence detection (a
    /// blocking sim wait that finds every managed thread parked knows no progress is possible).
    live: AtomicUsize,
    /// Count of this domain's threads currently blocked in an in-memory wait. Per-domain (unlike
    /// the fabric's process-global readiness) so quiescence stays correct when tests run in
    /// parallel in one process.
    parked: AtomicUsize,
}

/// A stack of layers that managed threads' OS calls are offered to, first to last.
#[derive(Clone)]
pub struct Domain(Arc<Inner>);

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
    pub fn enter(&self) -> Managed {
        self.0.live.fetch_add(1, Ordering::Relaxed);
        let domain = Arc::into_raw(self.0.clone());
        Managed {
            previous: state::replace_domain(domain),
            domain,
            previous_lineage: swap_lineage(Lineage::default()),
            _not_send: PhantomData,
        }
    }

    pub fn run<R>(&self, f: impl FnOnce() -> R) -> R {
        let _managed = self.enter();
        f()
    }

    /// Every unmodelled OS call this domain's threads have made, with how often.
    ///
    /// A test that expects its code to be fully simulated asserts this is empty.
    pub fn unmodelled(&self) -> Vec<(Unmodelled, u64)> {
        let calls = self.0.unmodelled.lock().unwrap_or_else(|e| e.into_inner());
        calls.iter().map(|(call, count)| (*call, *count)).collect()
    }

    pub fn clear_unmodelled(&self) {
        self.0
            .unmodelled
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
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
pub struct DomainBuilder {
    layers: Vec<Arc<dyn Layer>>,
    #[cfg_attr(not(unix), allow(dead_code))]
    net: Vec<Arc<dyn Net>>,
    #[cfg_attr(not(unix), allow(dead_code))]
    fs: Option<Arc<dyn Fs>>,
    #[cfg_attr(not(unix), allow(dead_code))]
    host: Option<Arc<dyn Host>>,
    #[cfg_attr(not(unix), allow(dead_code))]
    env: Option<Arc<dyn Env>>,
}

impl DomainBuilder {
    pub fn layers(mut self, layers: impl IntoIterator<Item = Arc<dyn Layer>>) -> Self {
        self.layers.extend(layers);
        self
    }

    /// Appends a net backend. Backends are consulted in the order added; the first whose call
    /// returns `Some` handles it, so order them most-specific first (e.g. a `SimHost` before a
    /// catch-all socket `Fabric`).
    pub fn net(mut self, net: Arc<dyn Net>) -> Self {
        self.net.push(net);
        self
    }

    pub fn fs(mut self, fs: Arc<dyn Fs>) -> Self {
        self.fs = Some(fs);
        self
    }

    pub fn host(mut self, host: Arc<dyn Host>) -> Self {
        self.host = Some(host);
        self
    }

    pub fn env(mut self, env: Arc<dyn Env>) -> Self {
        self.env = Some(env);
        self
    }

    /// Builds the domain, installing the interposer first if nothing has yet.
    pub fn install(self) -> Domain {
        crate::install();
        Domain(Arc::new(Inner {
            layers: self.layers,
            net: self.net,
            fs: self.fs,
            host: self.host,
            env: self.env,
            unmodelled: Mutex::default(),
            live: AtomicUsize::new(0),
            parked: AtomicUsize::new(0),
        }))
    }
}

/// Guard returned by [`Domain::enter`].
pub struct Managed {
    previous: *const Inner,
    domain: *const Inner,
    /// The thread's lineage before this guard, restored on drop.
    previous_lineage: Lineage,
    _not_send: PhantomData<*const ()>,
}

/// Where a managed thread sits in its domain's spawn tree, and how many children it has spawned.
/// The root (the thread that entered the domain) is 0; a child's id mixes its parent's with its
/// birth order, so ids follow from what the code does, never from how the OS schedules it.
#[derive(Clone, Copy, Default)]
struct Lineage {
    id: u64,
    children: u64,
}

thread_local! {
    static LINEAGE: std::cell::Cell<Lineage> = const {
        std::cell::Cell::new(Lineage { id: 0, children: 0 })
    };
}

fn swap_lineage(next: Lineage) -> Lineage {
    LINEAGE.try_with(|l| l.replace(next)).unwrap_or_default()
}

/// The calling thread's lineage id in its domain's spawn tree (0 for the thread that entered it).
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
            // SplitMix64's finaliser over (parent, birth order): distinct, well-spread ids.
            let mut z = me.id ^ me.children.wrapping_mul(0x9e37_79b9_7f4a_7c15);
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        })
        .unwrap_or(0)
}

impl Drop for Managed {
    fn drop(&mut self) {
        state::replace_domain(self.previous);
        swap_lineage(self.previous_lineage);
        if !self.domain.is_null() {
            // SAFETY: the domain pointer is live until the Arc below is dropped.
            unsafe { (*self.domain).live.fetch_sub(1, Ordering::Relaxed) };
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

/// How many threads the calling thread's domain currently manages (0 off a domain). A blocking
/// in-memory wait uses this to detect quiescence: if every managed thread is parked in such a
/// wait and none can be satisfied, no progress is possible and the wait gives up rather than hang.
pub fn managed_live() -> usize {
    let domain = state::domain();
    if domain.is_null() {
        return 0;
    }
    // SAFETY: on a managed thread the domain pointer is live (see `Domain::current`).
    unsafe { (*domain).live.load(Ordering::Relaxed) }
}

/// How many of the calling thread's domain's threads are currently blocked in an in-memory wait.
/// With [`managed_live`] this gives per-domain quiescence: equal counts mean no thread can progress.
pub fn managed_parked() -> usize {
    let domain = state::domain();
    if domain.is_null() {
        return 0;
    }
    // SAFETY: see `managed_live`.
    unsafe { (*domain).parked.load(Ordering::Relaxed) }
}

/// Marks the calling managed thread as entering (`+1`) or leaving (`-1`) an in-memory wait, for the
/// per-domain quiescence count. A backend's blocking wait brackets itself with `true`/`false`.
pub fn mark_waiting(waiting: bool) {
    let domain = state::domain();
    if domain.is_null() {
        return;
    }
    // SAFETY: see `managed_live`.
    let parked = unsafe { &(*domain).parked };
    if waiting {
        parked.fetch_add(1, Ordering::Relaxed);
    } else {
        parked.fetch_sub(1, Ordering::Relaxed);
    }
}

/// On quiescence, offers each of the calling thread's domain's layers the chance to jump virtual
/// time forward to its next pending timer (see [`Layer::try_time_skip`]). `true` means one did, so
/// a blocked wait can retry instead of treating the quiescence as a deadlock.
pub fn time_skip() -> bool {
    let domain = state::domain();
    if domain.is_null() {
        return false;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    domain.layers.iter().any(|layer| layer.try_time_skip())
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
    domain.layers.iter().find_map(|layer| layer.register_timer(after))
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

/// Asks the calling thread's domain's layers to wake their blocked waiters (see
/// [`Layer::wake_waiters`]).
fn wake_waiters() {
    let domain = state::domain();
    if domain.is_null() {
        return;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    for layer in &domain.layers {
        layer.wake_waiters();
    }
}

fn settling() -> bool {
    let domain = state::domain();
    if domain.is_null() {
        return false;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    domain.layers.iter().any(|layer| layer.settling())
}

/// Every managed thread is parked and none is waking: no thread can make progress until time does.
/// Called on managed threads only, never from inside a backend's wait loop (which checks the same
/// thing under its own lock).
fn quiescent() -> bool {
    let live = managed_live();
    live > 0 && managed_parked() >= live && !settling()
}

/// Whether a native blocking wait on this thread is one the simulation should account for: a
/// managed thread running the code under test, not the sim's own internals (which run under
/// passthrough and keep their own count).
pub(crate) fn counts_native_waits() -> bool {
    !state::passthrough() && !state::domain().is_null()
}

fn enter_native_wait() {
    mark_waiting(true);
    // Completing quiescence from outside the sim's wait loops would otherwise go unnoticed until
    // their next quiescence poll; wake them so they time-skip or give up now.
    if quiescent() {
        wake_waiters();
    }
}

/// Runs a native blocking wait (a futex, a condvar, a contended mutex) counted toward the domain's
/// quiescence, like the sim's own waits: a managed thread blocked here can only be released by
/// another managed thread, so without the count a peer parked in a sim wait could never see the
/// domain as quiescent and would wait forever. Off a domain, or inside the sim, it just runs.
pub(crate) fn native_wait<R>(wait: impl FnOnce() -> R) -> R {
    if !counts_native_waits() {
        return wait();
    }
    enter_native_wait();
    let result = wait();
    mark_waiting(false);
    result
}

/// How a [`timed_native_wait`] ended.
pub(crate) enum TimedWait<R> {
    /// The real wait returned before the timeout: woken, or a primitive-specific early return.
    Woken(R),
    /// The timeout elapsed — in virtual time under a virtual clock.
    TimedOut,
}

/// The longest real-time slice of one attempt in a [`timed_native_wait`] under a discrete virtual
/// clock: the bound on how late the wait notices that virtual time reached its deadline.
const NATIVE_WAIT_SLICE: std::time::Duration = std::time::Duration::from_millis(2);

/// Runs a native wait with a timeout of `after`, measured in the domain's time.
///
/// `attempt(slice)` performs one real wait bounded by `slice` of real time, returning `Some` when
/// it ended for any reason other than that slice running out. Under a discrete virtual clock the
/// timeout is registered as a pending timer and the wait proceeds in short slices, checking the
/// virtual deadline between them and time-skipping when the domain is quiescent — the kernel
/// cannot time out on a clock it does not know. Elsewhere it is a single attempt of `after`.
///
/// `spurious` returns `Woken(value)` after any slice that times out short of the deadline instead
/// of waiting again: needed by condition variables, whose wakeups are not latched and would be lost
/// if signalled between two slices. Futex-style waits (which re-check a value) and semaphores
/// (which count signals) can loop safely and pass `None`.
pub(crate) fn timed_native_wait<R>(
    after: std::time::Duration,
    mut spurious: Option<R>,
    mut attempt: impl FnMut(std::time::Duration) -> Option<R>,
) -> TimedWait<R> {
    use crate::layer::ClockKind;
    let single = |attempt: &mut dyn FnMut(std::time::Duration) -> Option<R>| match attempt(after) {
        Some(r) => TimedWait::Woken(r),
        None => TimedWait::TimedOut,
    };
    if !counts_native_waits() {
        return single(&mut attempt);
    }
    if after.is_zero() {
        // A zero timeout is a non-blocking check, and a caller repeating it is busy-waiting for
        // time to pass: under a discrete clock nothing else would ever move it.
        yield_point();
        charge_latency();
        return single(&mut attempt);
    }
    let start = now(ClockKind::Monotonic);
    let (Some(start), Some(key)) = (start, register_timer(after)) else {
        return native_wait(|| single(&mut attempt));
    };
    let deadline = start.saturating_add(after);
    enter_native_wait();
    let outcome = loop {
        if let Some(r) = attempt(NATIVE_WAIT_SLICE) {
            break TimedWait::Woken(r);
        }
        if now(ClockKind::Monotonic).is_some_and(|t| t >= deadline) {
            break TimedWait::TimedOut;
        }
        if quiescent() && time_skip() {
            wake_waiters();
            if now(ClockKind::Monotonic).is_some_and(|t| t >= deadline) {
                break TimedWait::TimedOut;
            }
        }
        if let Some(value) = spurious.take() {
            break TimedWait::Woken(value);
        }
    };
    unregister_timer(key);
    mark_waiting(false);
    outcome
}

/// The virtual time a call that returns without blocking costs under a discrete clock — Shadow's
/// unblocked-syscall latency. A microsecond is coarser than the resolution of every clock a caller
/// reads time back through (QueryPerformanceCounter and Mach ticks), so polling until a deadline
/// always gets past it.
const CALL_LATENCY: std::time::Duration = std::time::Duration::from_micros(1);

/// Charges the calling managed thread's domain [`CALL_LATENCY`] of virtual time for a call that
/// returned without blocking: a non-blocking receive that found nothing, a poll that returned at
/// once. A discrete clock otherwise only moves when every thread is blocked, so a thread that
/// busy-polls — never blocking, never yielding — would freeze it, and with it every sleeper the
/// poll is waiting on. Charged per call, time crawls under a spinner and timers fire in order as
/// it passes them, rather than jumping ahead of work the spinner is about to do. A no-op off a
/// domain and on clocks that are not discrete. Backends call it from their non-blocking returns.
pub fn charge_latency() {
    let domain = state::domain();
    if domain.is_null() {
        return;
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
}

/// A managed thread yielding the CPU (`sched_yield`, `SwitchToThread`) — the spin phase of most
/// locks and channels before they block, and the whole of a hand-rolled spin-wait. A spinning
/// thread never parks, so under a discrete virtual clock a spin waiting on a timer would stall
/// the clock for good. If every other managed thread is parked, the spinner is waiting on time
/// itself, so offer a time skip. The yielder is deliberately not counted as parked: it may be
/// about to make progress, and counting it could make a peer's sim wait declare a false deadlock.
pub(crate) fn yield_point() {
    if !counts_native_waits() {
        return;
    }
    let live = managed_live();
    if live == 0 || managed_parked() + 1 < live || settling() {
        return;
    }
    if time_skip() {
        wake_waiters();
    }
}

/// The calling thread's domain's time on a discrete virtual clock, or `None` off a domain or when
/// the domain's clock is not discrete. Unlike [`now`] it never advances the clock, and it reads the
/// same under passthrough, so the sim's own code can measure deadlines on the clock the code under
/// test sees.
pub fn discrete_now() -> Option<std::time::Duration> {
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    domain.layers.iter().find_map(|layer| layer.discrete_now())
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

/// Offers one operation to the calling thread's layers. `None` means it goes to the OS.
pub(crate) fn dispatch<T>(mut op: impl FnMut(&dyn Layer) -> Flow<T>) -> Option<T> {
    if state::passthrough() {
        return None;
    }
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
}

/// Offers a socket call to the calling thread's [`Net`], if it has one. `Some` handled it (as the
/// kernel would, negative errno on failure); `None` means the call goes to the OS. Available on
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
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    domain
        .net
        .iter()
        .find_map(|net| op(net.as_ref()))
        .map(crate::net::NetResult::into_raw)
}

/// Whether the calling thread's [`Net`] owns `fd` — the fast path for the generic fd calls. On
/// Windows the Winsock hooks pass a `SOCKET` cast to `c_int` (the sim mints small handles).
pub(crate) fn net_owns(fd: core::ffi::c_int) -> bool {
    if state::passthrough() {
        return false;
    }
    let domain = state::domain();
    if domain.is_null() {
        return false;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    domain.net.iter().any(|net| net.owns(fd))
}

#[cfg(unix)]
/// Offers a file call to the calling thread's [`Fs`], if it has one. Mirrors [`dispatch_net`].
pub(crate) fn dispatch_fs(op: impl FnOnce(&dyn Fs) -> Option<crate::fs::FsResult>) -> Option<i64> {
    if state::passthrough() {
        return None;
    }
    let domain = state::domain();
    if domain.is_null() {
        return None;
    }
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    let fs = domain.fs.as_deref()?;
    op(fs).map(crate::fs::FsResult::into_raw)
}

#[cfg(unix)]
/// Whether the calling thread's [`Fs`] owns `fd` — the fast path for the generic fd calls.
pub(crate) fn fs_owns(fd: core::ffi::c_int) -> bool {
    if state::passthrough() {
        return false;
    }
    let domain = state::domain();
    if domain.is_null() {
        return false;
    }
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
    let _passthrough = Passthrough::enter();
    // SAFETY: see `Domain::current`.
    let domain = unsafe { &*domain };
    let env = domain.env.as_deref()?;
    Some(op(env))
}

/// A strong reference to the calling thread's domain for a child thread to adopt, or null when
/// the child should start real.
///
/// The child counts as live from here, while the parent is still creating it, not from when it
/// first runs: otherwise, in the gap before the OS schedules it, the parent and its peers could
/// all be parked and look quiescent, and the clock would time-skip past work the child has yet to
/// do.
pub(crate) fn inherit() -> *const Inner {
    if state::passthrough() {
        return ptr::null();
    }
    let domain = state::domain();
    if !domain.is_null() {
        // SAFETY: see `Domain::current`.
        unsafe {
            Arc::increment_strong_count(domain);
            (*domain).live.fetch_add(1, Ordering::Relaxed);
        }
    }
    domain
}

/// Makes the calling (new) thread managed by `domain`, taking over the reference `inherit` made.
///
/// # Safety
/// `domain` must come from [`inherit`] and be adopted at most once.
pub(crate) unsafe fn adopt(domain: *const Inner, lineage: u64) -> Option<Child> {
    if domain.is_null() {
        return None;
    }
    // `inherit` already counted this thread live; `Managed::drop` does the matching decrement.
    let managed = Managed {
        previous: state::replace_domain(domain),
        domain,
        previous_lineage: swap_lineage(Lineage {
            id: lineage,
            children: 0,
        }),
        _not_send: PhantomData,
    };
    dispatch(|layer| {
        layer.thread_started();
        Flow::<()>::Pass
    });
    Some(Child { _managed: managed })
}

pub(crate) struct Child {
    _managed: Managed,
}

impl Drop for Child {
    fn drop(&mut self) {
        dispatch(|layer| {
            layer.thread_exiting();
            Flow::<()>::Pass
        });
    }
}

/// Reclaims a reference from [`inherit`] that no thread adopted.
///
/// # Safety
/// As for [`adopt`].
pub(crate) unsafe fn release(domain: *const Inner) {
    if !domain.is_null() {
        // SAFETY: the caller hands back the single reference `inherit` created, and with it the
        // live count it took for a thread that never started.
        unsafe {
            (*domain).live.fetch_sub(1, Ordering::Relaxed);
            drop(Arc::from_raw(domain));
        }
    }
}
