//! A simulated Windows host behind [`snare_interpose::Host`], the peer of the unix
//! [`SimHost`](crate::SimHost). It answers the Win32 scheduling calls a real-time program makes —
//! `SetThreadPriority`/`GetThreadPriority`, `SetThreadAffinityMask`, `SetPriorityClass`/
//! `GetPriorityClass`, `timeBeginPeriod`/`timeEndPeriod` — against in-process state, deterministically,
//! without ever touching the real scheduler or timer resolution.
//!
//! This is the Host plane only: no sockets, no filesystem. The [`Sim`] around it serves time from
//! the shared virtual [`Clock`](crate::clock::Clock), so `QueryPerformanceCounter` and
//! `GetSystemTimeAsFileTime` are deterministic too.

use std::collections::HashMap;
use std::ffi::c_int;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use snare_interpose::NetResult as HostResult;
use snare_interpose::{Domain, Host, Layer};

use crate::clock::{Clock, ClockLayer};
use windows_sys::Win32::System::Threading::{NORMAL_PRIORITY_CLASS, THREAD_PRIORITY_NORMAL};

/// `GetCurrentThread()` returns this pseudo-handle rather than a real one; every thread sees the
/// same value, so it is resolved to the caller's own synthetic key.
const CURRENT_THREAD_PSEUDO: u64 = -2i64 as u64;

/// Per-thread scheduling state. `priority` is the `SetThreadPriority` view; `affinity` the explicit
/// mask from `SetThreadAffinityMask` (`None` means the thread follows the process affinity mask).
#[derive(Clone)]
struct ThreadState {
    priority: i32,
    affinity: Option<u64>,
}

impl Default for ThreadState {
    fn default() -> Self {
        ThreadState {
            priority: THREAD_PRIORITY_NORMAL,
            affinity: None,
        }
    }
}

/// Synthetic keys for current-thread pseudo-handles start well above any real handle value, which
/// the loader hands out as small multiples of four.
const SYNTHETIC_BASE: u64 = 1 << 40;

struct HostState {
    process_affinity: u64,
    priority_class: u32,
    threads: HashMap<u64, ThreadState>,
    thread_keys: HashMap<std::thread::ThreadId, u64>,
    next_synthetic: u64,
    time_period: Option<u32>,
    time_period_depth: u32,
}

impl HostState {
    /// Maps the calling OS thread to a stable synthetic key, minted on first use.
    fn current_thread_key(&mut self) -> u64 {
        let id = std::thread::current().id();
        if let Some(&key) = self.thread_keys.get(&id) {
            return key;
        }
        let key = self.next_synthetic;
        self.next_synthetic += 1;
        self.thread_keys.insert(id, key);
        key
    }

    /// Resolves a Win32 thread handle to the key its state lives under, ensuring an entry exists.
    fn resolve(&mut self, handle: u64) -> u64 {
        let key = if handle == CURRENT_THREAD_PSEUDO {
            self.current_thread_key()
        } else {
            handle
        };
        self.threads.entry(key).or_default();
        key
    }
}

/// A simulated Windows host serving the Win32 scheduling plane from in-memory state. Attach it to a
/// [`Sim`] with [`SimBuilder`]; it never touches the real scheduler.
pub struct WinHost {
    state: Mutex<HostState>,
}

impl WinHost {
    fn new(cpus: usize) -> Self {
        let cpus = cpus.clamp(1, 64);
        let process_affinity = if cpus == 64 {
            u64::MAX
        } else {
            (1u64 << cpus) - 1
        };
        WinHost {
            state: Mutex::new(HostState {
                process_affinity,
                priority_class: NORMAL_PRIORITY_CLASS,
                threads: HashMap::new(),
                thread_keys: HashMap::new(),
                next_synthetic: SYNTHETIC_BASE,
                time_period: None,
                time_period_depth: 0,
            }),
        }
    }
}

impl Host for WinHost {
    fn set_thread_priority(&self, thread: u64, priority: c_int) -> Option<HostResult> {
        let mut state = self.state.lock().unwrap();
        let key = state.resolve(thread);
        state.threads.get_mut(&key).unwrap().priority = priority;
        Some(HostResult::Ok(1))
    }

    fn get_thread_priority(&self, thread: u64) -> Option<HostResult> {
        let mut state = self.state.lock().unwrap();
        let key = state.resolve(thread);
        Some(HostResult::Ok(state.threads[&key].priority as i64))
    }

    fn set_thread_affinity_mask(&self, thread: u64, mask: u64) -> Option<HostResult> {
        let mut state = self.state.lock().unwrap();
        let process_affinity = state.process_affinity;
        // Win32 rejects an empty mask, or one selecting a CPU outside the process affinity mask,
        // with `Ok(0)` — which the hook returns verbatim, preserving all 64 bits.
        if mask == 0 || mask & !process_affinity != 0 {
            return Some(HostResult::Ok(0));
        }
        let key = state.resolve(thread);
        let entry = state.threads.get_mut(&key).unwrap();
        let previous = entry.affinity.unwrap_or(process_affinity);
        entry.affinity = Some(mask);
        Some(HostResult::Ok(previous as i64))
    }

    fn set_priority_class(&self, _process: u64, class: u32) -> Option<HostResult> {
        self.state.lock().unwrap().priority_class = class;
        Some(HostResult::Ok(1))
    }

    fn get_priority_class(&self, _process: u64) -> Option<HostResult> {
        Some(HostResult::Ok(self.state.lock().unwrap().priority_class as i64))
    }

    fn time_period(&self, begin: bool, period: u32) -> Option<HostResult> {
        let mut state = self.state.lock().unwrap();
        if begin {
            state.time_period_depth += 1;
            state.time_period = Some(match state.time_period {
                Some(current) => current.min(period),
                None => period,
            });
        } else {
            state.time_period_depth = state.time_period_depth.saturating_sub(1);
            if state.time_period_depth == 0 {
                state.time_period = None;
            }
        }
        Some(HostResult::Ok(0))
    }
}

/// A running Windows simulation: a [`Domain`] whose managed threads' Win32 scheduling calls are
/// serviced by a [`WinHost`] and whose clock is virtual. One per test.
pub struct Sim {
    domain: Domain,
    _host: Arc<WinHost>,
    _net: Arc<crate::win_net::WinNet>,
    clock: Arc<Clock>,
}

impl Default for Sim {
    fn default() -> Self {
        Self::new()
    }
}

impl Sim {
    /// Starts a fresh simulation with a default 8-CPU host.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Composes a simulation.
    pub fn builder() -> SimBuilder {
        SimBuilder::default()
    }

    /// Runs `f` with the calling thread — and every thread it spawns — inside the simulation.
    pub fn run<R>(&self, f: impl FnOnce() -> R) -> R {
        // Scope this sim's address registries to the run so testers built here reach exactly
        // this sim, never another test's.
        let _registries = crate::win_net::enter(self._net.registries());
        self.domain.run(f)
    }

    /// Freezes virtual time; see the unix `Sim::pause_time`.
    pub fn pause_time(&self) {
        self.clock.pause();
    }

    /// Resumes automatic advance of virtual time (the default).
    pub fn resume_time(&self) {
        self.clock.resume();
    }

    /// Moves virtual time forward by `by`, whether or not it is paused.
    pub fn advance_time(&self, by: Duration) {
        self.clock.advance_by(by);
    }

    /// A cloneable, `Send`-able handle to this sim's clock, for use inside spawned threads.
    pub fn time(&self) -> crate::TimeHandle {
        crate::TimeHandle(self.clock.clone())
    }
}

/// Composes a [`Sim`] around a [`WinHost`].
#[derive(Default)]
pub struct SimBuilder {
    cpus: Option<usize>,
    wall_clock: bool,
    seed: u64,
}

impl SimBuilder {
    /// The number of logical CPUs the process affinity mask spans (default 8, clamped to 1..=64).
    pub fn cpus(mut self, count: usize) -> Self {
        self.cpus = Some(count);
        self
    }

    /// Runs the sim on the discrete-event virtual clock — the default, so this only states it. See
    /// the unix `SimBuilder::virtual_clock`.
    pub fn virtual_clock(mut self) -> Self {
        self.wall_clock = false;
        self
    }

    /// Runs the sim on an always-advancing virtual clock instead — each read ticks it, sleeps
    /// return at once — for code that measures elapsed time by reading the clock in a loop.
    pub fn wall_clock(mut self) -> Self {
        self.wall_clock = true;
        self
    }

    /// Seeds the sim's randomness (default 0); see the unix `SimBuilder::seed`.
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    pub fn build(self) -> Sim {
        let host = Arc::new(WinHost::new(self.cpus.unwrap_or(8)));
        let net = Arc::new(crate::win_net::WinNet::new());
        crate::win_net::with_policies(&net.registries(), |p| p.reseed(self.seed));
        // Windows has no TAI clock; the offset only matters on Linux.
        let clock = Arc::new(if self.wall_clock {
            Clock::new(0)
        } else {
            Clock::new_discrete(0)
        });
        let domain = Domain::builder()
            .layers([
                Arc::new(ClockLayer(clock.clone())) as Arc<dyn Layer>,
                Arc::new(crate::win_net::ScopeLayer(net.registries())),
                Arc::new(crate::random::RandomLayer { seed: self.seed }),
            ])
            .net(net.clone())
            .host(host.clone())
            .install();
        Sim {
            domain,
            _host: host,
            _net: net,
            clock,
        }
    }
}
