//! [`SimShared`]: the per-sim services every backend, tester and outside controller reaches
//! through one `Arc`, and how a thread finds the sim it runs in.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use snare_interpose::WeakDomain;

use crate::clock::Clock;
use crate::dns::Hosts;
use crate::events::{EventLog, RecordedEvent};
#[cfg(unix)]
use crate::fabric as peer;
use crate::faults::BehaviorTable;
use crate::limits::SysConfig;
use crate::netif::Topology;
use crate::netpolicy::{Policies, TcpPolicy, UdpPolicy};
use crate::netstats::ProtoStats;
use crate::pcapng::Capture;
use crate::signals::SignalTable;
use crate::sockets::SocketTable;
#[cfg(windows)]
use crate::win_net as peer;

/// The low end of the IANA dynamic/private port range 49152–65535 (RFC 6335 §6). It is also the
/// macOS and Windows default: XNU bsd/netinet/in_pcb.c `ipport_firstauto = IPPORT_HIFIRSTAUTO`
/// (bsd/netinet/in.h), and
/// [Microsoft Learn: The default dynamic port range for TCP/IP has changed since Windows Vista](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/default-dynamic-port-range-tcpip-chang).
/// Linux defaults to 32768–60999 instead (Documentation/networking/ip-sysctl.rst,
/// `ip_local_port_range`); snare uses the IANA range on every OS so runs match across them.
pub(crate) const EPHEMERAL_FIRST: u16 = 49152;

/// The services one [`Sim`](crate::Sim) shares across its backends, its testers and the threads
/// that control it from outside.
pub(crate) struct SimShared {
    /// The sim's seed, from which its policies' randomness derives.
    pub(crate) seed: u64,
    /// `None` for a sim on the real clock without a virtual host clock.
    pub(crate) clock: Option<Arc<Clock>>,
    pub(crate) policies: Policies,
    #[cfg(target_os = "linux")]
    pub(crate) rx_timestamp_startup: crate::tstamp::RxStartup,
    pub(crate) events: EventLog,
    /// The next port [`ephemeral_port`](Self::ephemeral_port) hands out.
    next_ephemeral: AtomicU16,
    /// The sim's domain, set once it is created; weak so the shared state never keeps it alive.
    pub(crate) domain: OnceLock<WeakDomain>,
    /// [`real_now`](crate::readiness::real_now) when the sim was built: the zero of its timeline
    /// with no virtual clock.
    real_origin: Duration,
    /// An [`Executive`](crate::sched::Executive) owns the clock.
    pub(crate) executive: AtomicBool,
    pub(crate) sockets: SocketTable,
    pub(crate) topology: Mutex<Topology>,
    pub(crate) dns: Hosts,
    pub(crate) signals: SignalTable,
    pub(crate) sys: SysConfig,
    /// How each TCP listening address answers connects
    /// ([`set_listener_behavior`](crate::faults::set_listener_behavior)).
    pub(crate) listener_behavior: BehaviorTable,
    /// The pcapng capture, once one is started.
    pub(crate) capture: OnceLock<Arc<Capture>>,
    /// The host's protocol counters, shared with every socket record.
    pub(crate) stats: Arc<ProtoStats>,
    /// [`SimBuilder::strict_sockopts`](crate::SimBuilder::strict_sockopts): an option or ioctl the
    /// sim does not model fails rather than succeeding without effect. Set before the sim runs.
    pub(crate) strict_sockopts: AtomicBool,
    /// The first strict refusal was written to stderr.
    pub(crate) strict_reported: AtomicBool,
}

impl SimShared {
    /// The shared services of a new sim seeded with `seed`, on `clock` (`None` for the real clock).
    pub(crate) fn new(seed: u64, clock: Option<Arc<Clock>>) -> Arc<Self> {
        // Initialised outside any domain: a hooked wait inside its lazy initialisation would
        // re-enter it from the hook.
        crate::readiness::readiness();
        Arc::new_cyclic(|me| SimShared {
            seed,
            clock,
            policies: Policies::with_seed(seed),
            #[cfg(target_os = "linux")]
            rx_timestamp_startup: crate::tstamp::RxStartup::default(),
            events: EventLog::new(),
            next_ephemeral: AtomicU16::new(EPHEMERAL_FIRST),
            domain: OnceLock::new(),
            real_origin: crate::readiness::real_now(),
            executive: AtomicBool::new(false),
            sockets: SocketTable::new(),
            topology: Mutex::new(Topology::new(me.clone())),
            dns: Hosts::default(),
            signals: SignalTable::new(),
            sys: SysConfig::new(),
            listener_behavior: BehaviorTable::default(),
            capture: OnceLock::new(),
            stats: Arc::default(),
            strict_sockopts: AtomicBool::new(false),
            strict_reported: AtomicBool::new(false),
        })
    }

    /// When something happened, on the sim's own timeline: sim time, read without ticking, or real
    /// time since the sim was built when it has no virtual clock.
    pub(crate) fn stamp(&self) -> Duration {
        timeline(self.clock.as_deref(), self.real_origin)
    }

    /// Real time when the sim was built (see the field).
    pub(crate) fn real_origin(&self) -> Duration {
        self.real_origin
    }

    /// Appends `event` to the sim's log. Never charges time, yields, registers a timer or wakes
    /// anything, so recording cannot change the run.
    pub(crate) fn record(&self, event: RecordedEvent) {
        if self.events.enabled() {
            self.events.push(|| self.stamp(), event);
        }
    }

    /// As [`record`](Self::record), for an event that happened `ago` before now.
    pub(crate) fn record_ago(&self, ago: Duration, event: RecordedEvent) {
        if self.events.enabled() {
            self.events.push(|| self.stamp().saturating_sub(ago), event);
        }
    }

    /// Changes the UDP policy for `addr` and records the result.
    pub(crate) fn update_udp_policy(&self, addr: SocketAddr, change: impl FnOnce(&mut UdpPolicy)) {
        let policy = self.policies.update(addr, change);
        self.record(RecordedEvent::UdpPolicyChanged { addr, policy });
    }

    /// Changes the TCP policy for `addr` and records the result.
    pub(crate) fn update_tcp_policy(&self, addr: SocketAddr, change: impl FnOnce(&mut TcpPolicy)) {
        let policy = self.policies.update_tcp(addr, change);
        self.record(RecordedEvent::TcpPolicyChanged { addr, policy });
    }

    /// Wakes everything that waits on the sim after a change made from any thread: blocked
    /// waiters re-check, and a deterministic schedule hands the baton on. Called with no sim lock
    /// held.
    pub(crate) fn kick(&self) {
        snare_interpose::real(|| {
            if let Some(clock) = &self.clock {
                clock.wake_due();
            }
            crate::readiness::readiness().bump(self.domain_key());
            if let Some(domain) = self.domain.get().and_then(WeakDomain::upgrade) {
                domain.kick_after_readiness();
            }
        });
    }

    pub(crate) fn kick_keys(&self, keys: &[crate::readiness::WakeKey]) {
        snare_interpose::real(|| {
            if let Some(clock) = &self.clock {
                clock.wake_due();
            }
            self.bump_keys(keys);
            if let Some(domain) = self.domain.get().and_then(WeakDomain::upgrade) {
                domain.kick();
            }
        });
    }

    /// The sim's [`Domain::key`](snare_interpose::Domain::key), which every readiness bump for a
    /// change to its state names; 0 before the domain is installed, when no thread waits in it
    /// and a bump reaches every domain.
    pub(crate) fn domain_key(&self) -> usize {
        self.domain.get().map_or(0, WeakDomain::key)
    }

    pub(crate) fn bump_keys(&self, keys: &[crate::readiness::WakeKey]) {
        crate::readiness::readiness().bump_keys(self.domain_key(), keys);
    }

    #[cfg(windows)]
    pub(crate) fn bump(&self) {
        crate::readiness::readiness().bump(self.domain_key());
    }

    /// Panics while an executive owns the clock: only it may move time then.
    #[track_caller]
    pub(crate) fn assert_clock_free(&self) {
        assert!(
            !self.executive.load(Ordering::Acquire),
            "this Sim's clock is owned by an Executive; move time through it"
        );
    }

    /// The next ephemeral TCP port of this sim, for an unbound connect or a bind to port 0,
    /// cycling through 49152..=65535 ([`EPHEMERAL_FIRST`]). Sequential rather than randomised, so
    /// runs replay.
    pub(crate) fn ephemeral_port(&self) -> u16 {
        let next = |port: u16| Some(port.checked_add(1).unwrap_or(EPHEMERAL_FIRST));
        self.next_ephemeral
            .try_update(Ordering::Relaxed, Ordering::Relaxed, next)
            .unwrap_or(EPHEMERAL_FIRST)
    }

    /// A handle to the sim's clock. Panics on a sim without a virtual clock.
    #[track_caller]
    pub(crate) fn time(self: &Arc<Self>) -> crate::TimeHandle {
        let Some(clock) = &self.clock else {
            panic!(
                "this Sim runs on the real clock (SimBuilder::wall_clock); build it with \
                 time_rate(1.0) for a controllable clock that tracks real time"
            );
        };
        crate::TimeHandle {
            clock: clock.clone(),
            shared: self.clone(),
        }
    }
}

/// A stamp on a sim's timeline: `clock`'s sim time, read without ticking, or real time since
/// `real_origin` without one.
pub(crate) fn timeline(clock: Option<&Clock>, real_origin: Duration) -> Duration {
    match clock {
        Some(clock) => clock.value(),
        None => crate::readiness::real_now().saturating_sub(real_origin),
    }
}

/// The shared services of the sim the calling thread runs in. Panics off a sim.
#[track_caller]
pub(crate) fn here() -> Arc<SimShared> {
    match try_here() {
        Some(shared) => shared,
        None => panic!("must be called from a thread running inside Sim::run"),
    }
}

/// The shared services of the sim the calling thread runs in, if it runs in one.
pub(crate) fn try_here() -> Option<Arc<SimShared>> {
    peer::try_registries_here().map(|regs| regs.shared.clone())
}
