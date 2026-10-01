//! Ergonomic in-process network testing, built on [`snare_interpose`].
//!
//! Write the code under test against plain `std::net`. In a test, create a [`Sim`], run the code
//! inside it, and describe the peer it talks to with a [`Tester`] — the same shape as the original
//! snare's `connect_tester` / `then_action` / `with_cyclic_action` / `run_testers!`.
//!
//! ```no_run
//! use std::io::{BufRead, BufReader, Write};
//! use std::net::TcpStream;
//! use std::time::Duration;
//! use snare::{connect_tester, run_testers, Line, Sim, TesterAction};
//!
//! let sim = Sim::new();
//! sim.run(|| {
//!     let server = connect_tester::<Line>("127.0.0.2:9000")
//!         .then_action(|msg, _from| TesterAction::Send(Line(format!("echo:{}", msg.0))))
//!         .until_after(Duration::from_millis(200));
//!
//!     let client = std::thread::spawn(|| {
//!         let mut stream = TcpStream::connect("127.0.0.2:9000").unwrap();
//!         stream.write_all(b"hello\n").unwrap();
//!         let mut line = String::new();
//!         BufReader::new(stream).read_line(&mut line).unwrap();
//!         line
//!     });
//!
//!     run_testers!(server);
//!     assert_eq!(client.join().unwrap(), "echo:hello\n");
//! });
//! ```
//!
//! The code under test uses real `TcpStream`; its socket calls are serviced from process memory,
//! and the tester is the other end of the wire. Threads spawned inside [`Sim::run`] join the
//! simulation automatically.
//!
//! TCP (`SOCK_STREAM`) and UDP (`SOCK_DGRAM`) over IPv4/IPv6 are both serviced from memory, with
//! blocking or non-blocking sockets, `poll`, and readiness via `epoll` (Linux) or `kqueue` (macOS)
//! — so `mio`-based code runs on both. UDP covers `bind`/`connect`/`sendto`/`recvfrom`, blocking
//! cross-thread receive, broadcast, multicast and several addresses sharing a port.

mod clock;
#[cfg(unix)]
mod fabric;
#[cfg(unix)]
mod fs_sim;
mod packet;
mod netpolicy;
mod random;
mod readiness;
#[cfg(unix)]
mod simhost;
mod tester;

#[cfg(windows)]
mod win_host;
#[cfg(windows)]
mod win_net;

use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use snare_interpose::Domain;

use crate::clock::Clock;
#[cfg(unix)]
use crate::clock::ClockLayer;

#[cfg(unix)]
pub use fabric::{Fabric, add_interface};
#[cfg(unix)]
pub use fs_sim::{FsBuilder, VirtualFs};
pub use netpolicy::{TcpPolicy, UdpPolicy, set_tcp_policy, set_udp_policy};
pub use packet::{Bytes, Line, Packet};
#[cfg(unix)]
pub use simhost::{
    CAP_IPC_LOCK, CAP_NET_ADMIN, CAP_SYS_NICE, EasyBuilder, HostProfile, LinkStats, Nic, SimHost,
};
pub use tester::{Recorder, Tester, TesterAction, connect_tester, udp_tester};
#[doc(hidden)]
pub use tester::{RunTester as __RunTester, run_testers as __run_testers};

#[cfg(windows)]
pub use win_host::{Sim, SimBuilder, WinHost};

/// Runs `f` with the calling thread's OS calls going to the real OS, even inside a [`Sim::run`].
/// The escape hatch for tester code that needs to reach the real machine — real files, the real
/// environment, real sockets — rather than the simulated ones the code under test sees. Wrap an
/// ordinary std call in it, e.g. `snare::real(|| std::fs::read(path))` or
/// `snare::real(|| std::env::var("KEY"))`.
pub use snare_interpose::real;

/// A running simulation: a [`Domain`](snare_interpose::Domain) whose managed threads' sockets are
/// serviced by an in-memory [`Fabric`], and whose file operations may be served by a
/// [`VirtualFs`]. One per test.
#[cfg(unix)]
pub struct Sim {
    domain: Domain,
    _fabric: Arc<Fabric>,
    _fs: Option<Arc<VirtualFs>>,
    _host: Option<Arc<SimHost>>,
    clock: Arc<Clock>,
}

#[cfg(unix)]
impl Default for Sim {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
impl Sim {
    /// Starts a fresh simulation with just the network fabric.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Composes a simulation with an optional [`VirtualFs`].
    pub fn builder() -> SimBuilder {
        SimBuilder::default()
    }

    /// Runs `f` with the calling thread — and every thread it spawns — inside the simulation.
    pub fn run<R>(&self, f: impl FnOnce() -> R) -> R {
        // Scope this sim's listener/interface registries to the run so `connect_tester` /
        // `add_interface` (called on this thread) reach exactly this sim, never another test's.
        let _registries = fabric::enter(self._fabric.registries());
        self.domain.run(f)
    }

    /// Freezes virtual time: clock reads return the same instant and sleeps return without
    /// advancing, until [`resume_time`](Self::resume_time). Step it forward meanwhile with
    /// [`advance_time`](Self::advance_time). Mirrors the original snare's `pause_time`.
    pub fn pause_time(&self) {
        self.clock.pause();
    }

    /// Resumes automatic advance of virtual time (the default).
    pub fn resume_time(&self) {
        self.clock.resume();
    }

    /// Moves virtual time forward by `by`, whether or not it is paused — the deterministic way to
    /// drive timers and timeouts in a test.
    pub fn advance_time(&self, by: Duration) {
        self.clock.advance_by(by);
    }

    /// A cloneable, `Send`-able handle to this sim's clock, for controlling time from inside a
    /// thread spawned within [`run`](Self::run).
    pub fn time(&self) -> TimeHandle {
        TimeHandle(self.clock.clone())
    }
}

/// A handle to a [`Sim`]'s virtual clock that can be moved into threads running inside the sim.
#[derive(Clone)]
pub struct TimeHandle(Arc<Clock>);

impl TimeHandle {
    /// See [`Sim::pause_time`].
    pub fn pause(&self) {
        self.0.pause();
    }

    /// See [`Sim::resume_time`].
    pub fn resume(&self) {
        self.0.resume();
    }

    /// See [`Sim::advance_time`].
    pub fn advance(&self, by: Duration) {
        self.0.advance_by(by);
    }
}

/// Composes a [`Sim`] from a fabric plus optional backends.
#[cfg(unix)]
#[derive(Default)]
pub struct SimBuilder {
    fs: Option<Arc<VirtualFs>>,
    host: Option<Arc<SimHost>>,
    wall_clock: bool,
    seed: u64,
}

#[cfg(unix)]
impl SimBuilder {
    /// Serves the code under test's file operations from `fs`.
    pub fn fs(mut self, fs: Arc<VirtualFs>) -> Self {
        self.fs = Some(fs);
        self
    }

    /// Runs a plain `Sim` on the discrete-event virtual clock — the default, so this only states
    /// it. Time is deterministic and moves in two ways: when every managed thread is blocked it
    /// jumps to the next pending sleep or timeout (so a multi-second sleep finishes in
    /// microseconds of real time), and each call that returns without blocking costs a microsecond
    /// (so a thread busy-polling a ready socket still lets the timers it waits on fire). (A
    /// `SimHost` brings its own clock, so this has no effect with one.)
    pub fn virtual_clock(mut self) -> Self {
        self.wall_clock = false;
        self
    }

    /// Runs a plain `Sim` on the real wall clock instead of the virtual one, for a test that needs
    /// real elapsed time. (No effect with a `SimHost`, which brings its own clock.)
    pub fn wall_clock(mut self) -> Self {
        self.wall_clock = true;
        self
    }

    /// Seeds the sim's randomness (default 0): the random bytes the code under test reads, and
    /// the link faults of [`set_udp_policy`](crate::set_udp_policy). The same seed replays the same
    /// values — each thread draws its own stream, so scheduling cannot reorder them — and a
    /// different seed explores a different run.
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Serves scheduling, CPU-topology, NIC and socket-tuning calls from a [`SimHost`]. The host
    /// also serves its own synthetic `/sys`, `/proc` and `/dev` reads, so it occupies the file
    /// plane and takes precedence over any [`fs`](Self::fs) set alongside it; every path it does
    /// not model is declined and reaches the real OS.
    pub fn host(mut self, host: Arc<SimHost>) -> Self {
        self.host = Some(host);
        self
    }

    pub fn build(self) -> Sim {
        let fabric = Arc::new(Fabric::new());
        fabric.registries().policies.reseed(self.seed);
        let mut builder = Domain::builder().layers([
            Arc::new(fabric::ScopeLayer(fabric.registries())) as Arc<dyn snare_interpose::Layer>,
            Arc::new(random::RandomLayer { seed: self.seed }),
        ]);
        // A `SimHost` owns the virtual clock that answers `clock_gettime` and stamps timestamps;
        // its `pause`/`advance`/`resume` time controls act on that clock. A plain `Sim` runs on the
        // discrete-event virtual clock unless asked for the `wall_clock`, in which case it carries
        // an unregistered clock only so the time-control methods have a target.
        let clock = match &self.host {
            Some(host) => host.clock(),
            None if !self.wall_clock => {
                let clock = Arc::new(Clock::new_discrete(37));
                builder = builder.layers([
                    Arc::new(ClockLayer(clock.clone())) as Arc<dyn snare_interpose::Layer>
                ]);
                clock
            }
            None => Arc::new(Clock::new(37)),
        };
        if let Some(host) = &self.host {
            host.attach_fabric(fabric.registries());
            // The host owns the NIC/scheduling/synthetic-fs planes: its `Net` handles
            // `if_nametoindex`, the NIC ioctls, netlink and UDP; its `Fs` the synthetic
            // `/sys`·`/proc`; its `Host` the scheduling calls; and its clock layer makes
            // `clock_gettime` (incl. `CLOCK_TAI`) deterministic. The fabric sits behind it on the
            // net plane so the socket families the host declines — TCP streams, raw L2 — are still
            // simulated: a test gets host-modelled UDP and fabric-modelled TCP at once.
            builder = builder
                .layers([host.clock_layer()])
                .net(host.clone())
                .net(fabric.clone())
                .fs(host.clone())
                .host(host.clone());
            // Only isolate the environment when the test asked to (see `HostProfile::env`), so
            // hosts that do not configure env keep reading the real one.
            if host.isolate_env() {
                builder = builder.env(host.clone());
            }
        } else {
            builder = builder.net(fabric.clone());
            match &self.fs {
                Some(fs) => builder = builder.fs(fs.clone()),
                // With no explicit VirtualFs, the fabric serves the file plane: on macOS it owns
                // `/dev/bpf*` for raw L2; on Linux it declines every path (so this is a no-op).
                None => builder = builder.fs(fabric.clone()),
            }
        }
        Sim {
            domain: builder.install(),
            _fabric: fabric,
            _fs: self.fs,
            _host: self.host,
            clock,
        }
    }
}
