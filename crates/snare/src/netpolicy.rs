//! Link faults for datagram traffic: latency, jitter (and so reordering), loss, duplication, an MTU
//! and a stalled sender, per address,
//! shared by every backend that delivers datagrams (the unix fabric and `SimHost`, the Windows
//! `WinNet`). Random decisions come from the sim's seeded generator, so a faulty run replays.
//!
//! The same table also holds each address's TCP policy and the stalls `quiesce` sets. Its four
//! mutexes are leaves: no method holds two at once, and the only foreign code run under one is
//! the test's own `change` closure in `update`/`update_tcp`, which must not touch the sim. Callers
//! may hold the topology lock (`SimShared::fan_out`) but must not take it while holding one of
//! these. The draws from the generator are in a fixed order per decision, so a given seed and a
//! given sequence of sends replay the same faults.

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Mutex;
use std::time::Duration;

use crate::events::{Direction, LinkFault};
use crate::readiness::Deadline;

/// Interface and address policies each produce at most two copies.
#[derive(Default)]
pub(crate) struct Delays {
    values: [Duration; 4],
    len: usize,
}

impl Delays {
    pub(crate) fn one(delay: Duration) -> Self {
        Self {
            values: [delay, Duration::ZERO, Duration::ZERO, Duration::ZERO],
            len: 1,
        }
    }

    pub(crate) fn extend(&mut self, delays: impl IntoIterator<Item = Duration>) {
        for delay in delays {
            self.values[self.len] = delay;
            self.len += 1;
        }
    }
}

impl std::ops::Deref for Delays {
    type Target = [Duration];

    fn deref(&self) -> &Self::Target {
        &self.values[..self.len]
    }
}

impl std::ops::DerefMut for Delays {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values[..self.len]
    }
}

impl FromIterator<Duration> for Delays {
    fn from_iter<T: IntoIterator<Item = Duration>>(iter: T) -> Self {
        let mut delays = Self::default();
        delays.extend(iter);
        delays
    }
}

impl IntoIterator for Delays {
    type Item = Duration;
    type IntoIter = std::iter::Take<std::array::IntoIter<Duration, 4>>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter().take(self.len)
    }
}

impl<'a> IntoIterator for &'a Delays {
    type Item = &'a Duration;
    type IntoIter = std::slice::Iter<'a, Duration>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut Delays {
    type Item = &'a mut Duration;
    type IntoIter = std::slice::IterMut<'a, Duration>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

/// How the simulated link treats datagrams to and from one address. Set with
/// [`set_udp_policy`]; the default is a perfect link.
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
    /// send fails with `EAGAIN`/`WouldBlock` (man 2 send, EAGAIN; Winsock `WSAEWOULDBLOCK`, 10035,
    /// [Microsoft Learn: Windows Sockets Error Codes](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2))
    /// and a blocking one waits until the policy changes.
    /// Other depths are accepted but not modelled, since the simulated link never queues.
    pub send_queue_depth: Option<usize>,
}

/// How the simulated link delays a TCP connection's bytes. Set with
/// [`set_tcp_policy`]; the default is an instant link.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TcpPolicy {
    /// How long each write's bytes spend in flight before the other end can read them.
    pub latency: Duration,
    /// A further delay drawn uniformly from `0..jitter` per write. TCP delivers bytes in sequence
    /// order (RFC 9293 §2.2: "a reliable, in-order, byte-stream service"), so a write never
    /// overtakes an earlier one: jitter only bunches up and
    /// spreads out arrivals.
    pub jitter: Duration,
    /// The receive window of the endpoint bound at the policy's address: at most this many bytes
    /// may be in flight to it plus unread there, on top of the writer's send buffer. A writer that
    /// fills it blocks (or gets `EAGAIN`/`WSAEWOULDBLOCK`) until the reader frees room, as a
    /// sender facing a zero window would (RFC 9293 §3.8.6). `None` leaves the stream unbounded.
    pub recv_window: Option<usize>,
}

/// Changes the link policy for every TCP connection with `addr` at either end — a listener the
/// code under test connects to, a tester, or a known client address — in both directions.
/// Callable from any thread of the test.
pub fn set_tcp_policy(addr: impl ToSocketAddrs, change: impl FnOnce(&mut TcpPolicy)) {
    set_tcp_policy_on(&crate::scope::here(), addr, change);
}

/// [`set_tcp_policy`] against an explicit sim, for callers that hold its `SimShared` rather than
/// running on one of its threads. Records `TcpPolicyChanged` and then kicks the sim with no lock
/// held.
pub(crate) fn set_tcp_policy_on(
    shared: &crate::scope::SimShared,
    addr: impl ToSocketAddrs,
    change: impl FnOnce(&mut TcpPolicy),
) {
    let addr = policy_addr(addr);
    snare_interpose::real(|| shared.update_tcp_policy(addr, change));
    // A writer waiting on a window the policy just widened may go now.
    shared.kick();
}

/// The first address `addr` resolves to. Panics on an unparsable or empty address: a policy
/// with no address is a test bug, reported at the caller.
#[track_caller]
fn policy_addr(addr: impl ToSocketAddrs) -> SocketAddr {
    addr.to_socket_addrs()
        .expect("policy address must parse")
        .next()
        .expect("policy address resolved to nothing")
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
    set_udp_policy_on(&crate::scope::here(), addr, change);
}

/// [`set_udp_policy`] against an explicit sim; records `UdpPolicyChanged` and then kicks the sim
/// with no lock held.
pub(crate) fn set_udp_policy_on(
    shared: &crate::scope::SimShared,
    addr: impl ToSocketAddrs,
    change: impl FnOnce(&mut UdpPolicy),
) {
    let addr = policy_addr(addr);
    snare_interpose::real(|| shared.update_udp_policy(addr, change));
    // A send stalled on the old policy may go now.
    shared.kick();
}

/// The per-sim policy table and the generator its random decisions draw from.
pub(crate) struct Policies {
    /// UDP policy per address; an address back at the default policy is removed, so an empty map
    /// means a perfect link and costs one lookup.
    by_addr: Mutex<HashMap<SocketAddr, UdpPolicy>>,
    /// TCP policy per address, kept the same way.
    tcp_by_addr: Mutex<HashMap<SocketAddr, TcpPolicy>>,
    /// Quiesce windows per address. Entries are never removed; an expired one is ignored.
    stalls: Mutex<HashMap<SocketAddr, Stall>>,
    /// The fault generator, seeded from the sim's seed. Shared by every fault decision of the sim
    /// (including interface policies in `netif`), so the order of draws is part of the replay.
    rng: Mutex<SplitMix64>,
}

/// Until when traffic arriving at and leaving one address is held on the link.
#[derive(Clone, Default)]
#[cfg_attr(not(target_os = "macos"), derive(Copy))]
struct Stall {
    /// Datagrams addressed to the address are held until then.
    receive_until: Option<Deadline>,
    /// Datagrams sent from the address are held until then.
    send_until: Option<Deadline>,
    #[cfg(target_os = "macos")]
    receive_history: Vec<StallWindow>,
    #[cfg(target_os = "macos")]
    send_history: Vec<StallWindow>,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
struct StallWindow {
    since: Deadline,
    until: Deadline,
}

#[cfg(target_os = "macos")]
fn replace_stall(history: &mut Vec<StallWindow>, since: Deadline, until: Deadline) {
    if let Some(last) = history.last_mut()
        && last.until.instant() > since.instant()
    {
        last.until = since;
        if last.until.instant() <= last.since.instant() {
            history.pop();
        }
    }
    if until.instant() > since.instant() {
        history.push(StallWindow { since, until });
    }
}

impl Policies {
    /// An empty table (every link perfect) whose generator starts at `seed`.
    pub(crate) fn with_seed(seed: u64) -> Self {
        Policies {
            by_addr: Mutex::default(),
            tcp_by_addr: Mutex::default(),
            stalls: Mutex::default(),
            rng: Mutex::new(SplitMix64(seed)),
        }
    }

    /// Applies `change` to the policy at `addr` and returns the policy now in force.
    pub(crate) fn update(
        &self,
        addr: SocketAddr,
        change: impl FnOnce(&mut UdpPolicy),
    ) -> UdpPolicy {
        let mut by_addr = self.by_addr.lock().unwrap();
        let policy = by_addr.entry(addr).or_default();
        change(policy);
        let policy = policy.clone();
        if policy == UdpPolicy::default() {
            by_addr.remove(&addr);
        }
        policy
    }

    /// The copies of a `len`-byte datagram addressed to `to` that arrive, each as the delay before
    /// it can be received — none (lost or too big), one, or two (duplicated, each with its own
    /// jitter) — and the fault, if any. Draws in a fixed order: loss, then duplication, then one
    /// jitter per copy.
    pub(crate) fn deliveries(&self, to: SocketAddr, len: usize) -> (Delays, Option<LinkFault>) {
        let Some(policy) = self.by_addr.lock().unwrap().get(&to).cloned() else {
            return (Delays::one(Duration::ZERO), None);
        };
        if policy.mtu.is_some_and(|mtu| len > mtu) {
            return (Delays::default(), Some(LinkFault::TooBig));
        }
        let mut rng = self.rng.lock().unwrap();
        if policy.loss_rate > 0.0 && rng.unit() < policy.loss_rate {
            return (Delays::default(), Some(LinkFault::Lost));
        }
        let duplicated = policy.duplicate_rate > 0.0 && rng.unit() < policy.duplicate_rate;
        let delays = (0..if duplicated { 2 } else { 1 })
            .map(|_| policy.latency + policy.jitter.mul_f64(rng.unit()))
            .collect();
        (delays, duplicated.then_some(LinkFault::Duplicated))
    }

    /// Applies `change` to the TCP policy at `addr` and returns the policy now in force.
    pub(crate) fn update_tcp(
        &self,
        addr: SocketAddr,
        change: impl FnOnce(&mut TcpPolicy),
    ) -> TcpPolicy {
        let mut by_addr = self.tcp_by_addr.lock().unwrap();
        let policy = by_addr.entry(addr).or_default();
        change(policy);
        let policy = policy.clone();
        if policy == TcpPolicy::default() {
            by_addr.remove(&addr);
        }
        policy
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

    /// The receive window of the endpoint at `addr`, if its policy sets one.
    pub(crate) fn recv_window(&self, addr: SocketAddr) -> Option<usize> {
        self.tcp_by_addr.lock().unwrap().get(&addr)?.recv_window
    }

    /// The fixed part of a datagram's trip to `to`: its policy's latency, without jitter.
    pub(crate) fn udp_latency(&self, to: SocketAddr) -> Duration {
        self.by_addr
            .lock()
            .unwrap()
            .get(&to)
            .map_or(Duration::ZERO, |p| p.latency)
    }

    /// Holds the traffic `direction` names at `addr` until `until`, replacing an earlier window
    /// for the same direction even if that one ends later. `Direction::Both` sets both windows.
    #[cfg(not(target_os = "macos"))]
    pub(crate) fn stall(&self, addr: SocketAddr, direction: Direction, until: Deadline) {
        let mut stalls = self.stalls.lock().unwrap();
        let stall = stalls.entry(addr).or_default();
        if direction != Direction::Send {
            stall.receive_until = Some(until);
        }
        if direction != Direction::Receive {
            stall.send_until = Some(until);
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn stall_at(
        &self,
        addr: SocketAddr,
        direction: Direction,
        since: Deadline,
        until: Deadline,
    ) {
        let mut stalls = self.stalls.lock().unwrap();
        let stall = stalls.entry(addr).or_default();
        if direction != Direction::Send {
            stall.receive_until = Some(until);
            replace_stall(&mut stall.receive_history, since, until);
        }
        if direction != Direction::Receive {
            stall.send_until = Some(until);
            replace_stall(&mut stall.send_history, since, until);
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn held_until_on(
        &self,
        from: SocketAddr,
        to: SocketAddr,
        clock: Option<&crate::clock::Clock>,
    ) -> Option<Deadline> {
        let stalls = self.stalls.lock().unwrap();
        [
            stalls.get(&to).and_then(|s| s.receive_until),
            stalls.get(&from).and_then(|s| s.send_until),
        ]
        .into_iter()
        .flatten()
        .filter(|at| !at.passed_on(clock))
        .max_by_key(Deadline::instant)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn effective_arrival(
        &self,
        from: SocketAddr,
        to: SocketAddr,
        mut at: Deadline,
    ) -> Deadline {
        let stalls = self.stalls.lock().unwrap();
        let mut send = stalls
            .get(&from)
            .into_iter()
            .flat_map(|stall| &stall.send_history)
            .peekable();
        let mut receive = stalls
            .get(&to)
            .into_iter()
            .flat_map(|stall| &stall.receive_history)
            .peekable();
        loop {
            let window = match (send.peek(), receive.peek()) {
                (Some(a), Some(b)) if a.since.instant() <= b.since.instant() => send.next(),
                (Some(_), Some(_)) | (None, Some(_)) => receive.next(),
                (Some(_), None) => send.next(),
                (None, None) => break,
            }
            .expect("stall window");
            if window.since.instant() > at.instant() {
                break;
            }
            if window.until.instant() > at.instant() {
                at = window.until;
            }
        }
        at
    }

    /// Until when traffic from `from` to `to` is held, while a stall at either end lasts: the later
    /// of `to`'s receive window and `from`'s send window that has not yet passed.
    #[cfg(not(target_os = "macos"))]
    pub(crate) fn held_until(&self, from: SocketAddr, to: SocketAddr) -> Option<Deadline> {
        let stalls = self.stalls.lock().unwrap();
        if stalls.is_empty() {
            return None;
        }
        [
            stalls.get(&to).and_then(|s| s.receive_until),
            stalls.get(&from).and_then(|s| s.send_until),
        ]
        .into_iter()
        .flatten()
        .filter(|d| !d.passed())
        .max_by_key(Deadline::instant)
    }

    pub(crate) fn held_until_pair(
        &self,
        from: SocketAddr,
        to: SocketAddr,
        bound: SocketAddr,
    ) -> Option<Deadline> {
        let stalls = self.stalls.lock().unwrap();
        if stalls.is_empty() {
            return None;
        }
        [
            stalls.get(&from).and_then(|s| s.send_until),
            stalls.get(&to).and_then(|s| s.receive_until),
            (bound != to)
                .then(|| stalls.get(&bound).and_then(|s| s.receive_until))
                .flatten(),
        ]
        .into_iter()
        .flatten()
        .filter(|d| !d.passed())
        .max_by_key(Deadline::instant)
    }

    /// A uniform draw in \[0, 1) from the sim's generator.
    pub(crate) fn unit(&self) -> f64 {
        self.rng.lock().unwrap().unit()
    }

    /// A delay drawn uniformly from `0..span`; no draw for a zero span.
    pub(crate) fn jitter(&self, span: Duration) -> Duration {
        if span.is_zero() {
            return Duration::ZERO;
        }
        span.mul_f64(self.unit())
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

/// SplitMix64 (Steele, Lea & Flood, "Fast splittable pseudorandom number generators", OOPSLA
/// 2014): a small, fast, well-distributed generator, ample for fault decisions and for
/// [`RandomLayer`](crate::random::RandomLayer)'s per-thread streams. Not cryptographic. The
/// field is the generator's whole state.
pub(crate) struct SplitMix64(pub(crate) u64);

impl SplitMix64 {
    /// The next output. The increment `0x9e3779b97f4a7c15` (2^64 / golden ratio) and the
    /// shift/multiply finaliser constants are those of the reference implementation
    /// (Vigna, <https://prng.di.unimi.it/splitmix64.c>), so a given seed yields the published
    /// sequence.
    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A uniform value in \[0, 1): the top 53 bits of one draw scaled by 2^-53, the conversion
    /// Vigna recommends for doubles (<https://prng.di.unimi.it/>, "Generating uniform doubles in
    /// the unit interval"), exact in an `f64`'s 53-bit significand.
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}
