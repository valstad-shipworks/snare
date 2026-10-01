//! Link faults for datagram traffic: latency, jitter (and so reordering), loss, duplication, an MTU
//! and a stalled sender, per address,
//! shared by every backend that delivers datagrams (the unix fabric and `SimHost`, the Windows
//! `WinNet`). Random decisions come from the sim's seeded generator, so a faulty run replays.

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Mutex;
use std::time::Duration;

#[cfg(unix)]
use crate::fabric as peer;
#[cfg(windows)]
use crate::win_net as peer;

/// How the simulated link treats datagrams to and from one address. Set with
/// [`set_udp_policy`](crate::set_udp_policy); the default is a perfect link.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UdpPolicy {
    /// How long a datagram to the address spends in flight before it can be received — in virtual
    /// time under the virtual clock, where the sim jumps to its arrival.
    pub latency: Duration,
    /// A further delay drawn uniformly from `0..jitter` for each datagram, so datagrams sent close
    /// together can arrive out of order: a receive always takes whichever arrived first.
    pub jitter: Duration,
    /// Probability, 0.0–1.0, that a datagram delivered to the address is lost.
    pub loss_rate: f64,
    /// Probability, 0.0–1.0, that a datagram delivered to the address arrives twice.
    pub duplicate_rate: f64,
    /// Datagrams to the address larger than this many bytes are dropped, as an IP path would
    /// drop an oversized datagram it may not fragment.
    pub mtu: Option<usize>,
    /// Room in the address's send queue. `Some(0)` stalls the socket bound there: a non-blocking
    /// send fails with `EAGAIN`/`WouldBlock` and a blocking one waits until the policy changes.
    /// Other depths are accepted but not modelled, since the simulated link never queues.
    pub send_queue_depth: Option<usize>,
}

/// How the simulated link delays a TCP connection's bytes. Set with
/// [`set_tcp_policy`](crate::set_tcp_policy); the default is an instant link.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TcpPolicy {
    /// How long each write's bytes spend in flight before the other end can read them.
    pub latency: Duration,
    /// A further delay drawn uniformly from `0..jitter` per write. TCP never reorders, so a write
    /// never overtakes an earlier one: jitter only bunches up and spreads out arrivals.
    pub jitter: Duration,
}

/// Changes the link policy for every TCP connection with `addr` at either end — a listener the
/// code under test connects to, a tester, or a known client address — in both directions.
/// Callable from any thread of the test.
pub fn set_tcp_policy(addr: impl ToSocketAddrs, change: impl FnOnce(&mut TcpPolicy)) {
    let addr = addr
        .to_socket_addrs()
        .expect("policy address must parse")
        .next()
        .expect("policy address resolved to nothing");
    let regs = peer::registries_here();
    snare_interpose::real(|| peer::with_policies(&regs, |p| p.update_tcp(addr, change)));
}

/// Changes the link policy for datagrams to and from `addr` in the current sim — the address of a
/// socket the code under test binds, or of a tester. Callable from any thread of the test.
///
/// ```no_run
/// # use snare::{Sim, set_udp_policy};
/// Sim::new().run(|| {
///     set_udp_policy("127.0.0.1:9000", |p| p.loss_rate = 0.25);
///     set_udp_policy("127.0.0.1:9001", |p| p.send_queue_depth = Some(0)); // stall its sends
/// });
/// ```
pub fn set_udp_policy(addr: impl ToSocketAddrs, change: impl FnOnce(&mut UdpPolicy)) {
    let addr = addr
        .to_socket_addrs()
        .expect("policy address must parse")
        .next()
        .expect("policy address resolved to nothing");
    let regs = peer::registries_here();
    snare_interpose::real(|| {
        peer::with_policies(&regs, |p| p.update(addr, change));
        // A send stalled on the old policy may go now.
        crate::readiness::readiness().bump();
    });
}

/// The per-sim policy table and the generator its random decisions draw from.
pub(crate) struct Policies {
    by_addr: Mutex<HashMap<SocketAddr, UdpPolicy>>,
    tcp_by_addr: Mutex<HashMap<SocketAddr, TcpPolicy>>,
    rng: Mutex<SplitMix64>,
}

impl Default for Policies {
    fn default() -> Self {
        Policies::with_seed(0)
    }
}

impl Policies {
    pub(crate) fn with_seed(seed: u64) -> Self {
        Policies {
            by_addr: Mutex::default(),
            tcp_by_addr: Mutex::default(),
            rng: Mutex::new(SplitMix64(seed)),
        }
    }

    /// Restarts the random decisions from `seed`.
    pub(crate) fn reseed(&self, seed: u64) {
        *self.rng.lock().unwrap() = SplitMix64(seed);
    }

    pub(crate) fn update(&self, addr: SocketAddr, change: impl FnOnce(&mut UdpPolicy)) {
        let mut by_addr = self.by_addr.lock().unwrap();
        let policy = by_addr.entry(addr).or_default();
        change(policy);
        if *policy == UdpPolicy::default() {
            by_addr.remove(&addr);
        }
    }

    /// The copies of a `len`-byte datagram addressed to `to` that arrive, each as the delay before
    /// it can be received: none (lost or too big), one, or two (duplicated, each with its own
    /// jitter).
    pub(crate) fn deliveries(&self, to: SocketAddr, len: usize) -> Vec<Duration> {
        let Some(policy) = self.by_addr.lock().unwrap().get(&to).cloned() else {
            return vec![Duration::ZERO];
        };
        if policy.mtu.is_some_and(|mtu| len > mtu) {
            return Vec::new();
        }
        let mut rng = self.rng.lock().unwrap();
        if policy.loss_rate > 0.0 && rng.unit() < policy.loss_rate {
            return Vec::new();
        }
        let copies = if policy.duplicate_rate > 0.0 && rng.unit() < policy.duplicate_rate {
            2
        } else {
            1
        };
        (0..copies)
            .map(|_| policy.latency + policy.jitter.mul_f64(rng.unit()))
            .collect()
    }

    pub(crate) fn update_tcp(&self, addr: SocketAddr, change: impl FnOnce(&mut TcpPolicy)) {
        let mut by_addr = self.tcp_by_addr.lock().unwrap();
        let policy = by_addr.entry(addr).or_default();
        change(policy);
        if *policy == TcpPolicy::default() {
            by_addr.remove(&addr);
        }
    }

    /// The delay before bytes written now on the connection between `a` and `b` can be read: the
    /// policy set on either end (the first found, checking `a` first).
    pub(crate) fn tcp_delay(&self, a: SocketAddr, b: SocketAddr) -> Duration {
        let by_addr = self.tcp_by_addr.lock().unwrap();
        let Some(policy) = by_addr.get(&a).or_else(|| by_addr.get(&b)).cloned() else {
            return Duration::ZERO;
        };
        drop(by_addr);
        if policy.jitter.is_zero() {
            return policy.latency;
        }
        policy.latency + policy.jitter.mul_f64(self.rng.lock().unwrap().unit())
    }

    /// Whether the socket bound at `from` is stalled and cannot send.
    pub(crate) fn send_stalled(&self, from: SocketAddr) -> bool {
        self.by_addr
            .lock()
            .unwrap()
            .get(&from)
            .is_some_and(|p| p.send_queue_depth == Some(0))
    }
}

/// SplitMix64 (Steele, Lea & Flood, "Fast splittable pseudorandom number generators", 2014): a
/// small, fast, well-distributed generator, ample for fault decisions.
pub(crate) struct SplitMix64(pub(crate) u64);

impl SplitMix64 {
    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A uniform value in [0, 1).
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}
