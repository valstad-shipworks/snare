//! Hermetic name resolution. Inside a [`Sim`](crate::Sim), `getaddrinfo`, `getnameinfo` and
//! `gethostbyname` answer names from the sim's host table and a built-in `localhost`; any other
//! name fails the way the host OS fails an unknown name, without a packet or a real lookup.
//! Numeric hosts, a missing node and service names are left to the OS's own code.
//!
//! The interposer's resolver hooks turn a [`Lookup`] / [`Reverse`] into each API's own error
//! space; this module only decides which outcome a name gets. Each sim owns one [`Hosts`], whose
//! single mutex is only ever taken under [`snare_interpose::real`] and never held across a wait,
//! so a lookup's simulated latency never blocks another thread's table edit.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use snare_interpose::{Lookup, Resolver, Reverse};

use crate::events::{Fault, RecordedEvent};
use crate::readiness::{Deadline, readiness};
use crate::scope::SimShared;

/// How the sim's resolver answers one name, or every name without a policy of its own. Set with
/// [`set_dns_policy`] and [`set_default_dns_policy`]; the default answers at once and never
/// fails.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DnsPolicy {
    /// How long a lookup takes, in virtual time under the virtual clock, where the sim jumps
    /// ahead to its answer.
    pub latency: Duration,
    /// Fails every lookup of the name this way, or, with a `failure_rate`, each failing one.
    pub failure: Option<DnsFailure>,
    /// Probability, 0.0–1.0, that a lookup fails: with `failure`, or `TryAgain` when it is unset.
    /// Drawn from the sim's seed, so a run replays.
    pub failure_rate: f64,
}

/// How a lookup fails, as the host OS reports it.
///
/// The `EAI_*` codes are `getaddrinfo`'s (man 3 getaddrinfo; POSIX `getaddrinfo`), the bare
/// names `gethostbyname`'s `h_errno` (man 3 gethostbyname), and the `WSA*` codes Winsock's
/// equivalents ([Microsoft Learn: getaddrinfo function, Return value](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfo)
/// pairs `EAI_NONAME`/`WSAHOST_NOT_FOUND`, `EAI_AGAIN`/`WSATRY_AGAIN`, `EAI_FAIL`/`WSANO_RECOVERY`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsFailure {
    /// No such name: `EAI_NONAME`, `HOST_NOT_FOUND`, `WSAHOST_NOT_FOUND`.
    NotFound,
    /// A temporary failure: `EAI_AGAIN`, `TRY_AGAIN`, `WSATRY_AGAIN`.
    TryAgain,
    /// A permanent failure: `EAI_FAIL`, `NO_RECOVERY`, `WSANO_RECOVERY`.
    Fail,
}

/// One name in a sim's host table.
struct Entry {
    /// The lookup key, see [`key`].
    key: String,
    /// The name as added, minus one trailing dot: what `ai_canonname` and reverse lookups return.
    canonical: String,
    /// The addresses in the order lookups return them; may be empty.
    addrs: Vec<IpAddr>,
}

/// The mutable state behind [`Hosts`]'s lock.
#[derive(Default)]
struct Table {
    /// Entries in insertion order, so a reverse lookup of an address several names share answers
    /// with the first name added.
    entries: Vec<Entry>,
    /// Per-name policies by key. A policy changed back to the default is removed, so presence
    /// means "differs from the default".
    policies: HashMap<String, DnsPolicy>,
    /// The policy for every name without an entry in `policies`.
    default: DnsPolicy,
}

/// One sim's host table and resolver policies.
#[derive(Default)]
pub(crate) struct Hosts {
    table: Mutex<Table>,
    /// Whether names the table does not know go to the real resolver
    /// ([`SimBuilder::real_dns`](crate::SimBuilder::real_dns)). Set once at build, before the
    /// domain is installed, so relaxed ordering suffices.
    real: AtomicBool,
}

/// The table key of `name`: ASCII-lowercased, one trailing dot dropped.
fn key(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

/// `localhost`'s addresses, `::1` first: the order RFC 6724 destination address selection gives
/// them (§6 Rule 6, prefer higher precedence; §2.1 default policy table: `::1/128` precedence 50
/// above `::ffff:0:0/96` at 35). The tests compare these against the real resolver as sets, so
/// the order itself is not pinned against any OS.
const LOOPBACKS: [IpAddr; 2] = [
    IpAddr::V6(Ipv6Addr::LOCALHOST),
    IpAddr::V4(Ipv4Addr::LOCALHOST),
];

/// The names every host resolves without a table entry: `localhost`, and on Windows the empty
/// name, which there means the local machine. Windows returns "all registered addresses on the
/// local computer" for an empty node and "all loopback addresses" for `localhost`
/// ([Microsoft Learn: getaddrinfo function, Remarks](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfo));
/// the sim models no other local addresses, so both answer the loopbacks (the set pinned by
/// `tests/dns_win.rs` `empty_node_is_local_host`, and against the real resolver by
/// `localhost_matches_host_resolver`).
fn builtin(key: &str) -> Option<Lookup> {
    (key == "localhost" || (cfg!(windows) && key.is_empty())).then(|| Lookup::Addrs {
        canonical: "localhost".into(),
        addrs: LOOPBACKS.to_vec(),
    })
}

impl Hosts {
    /// Runs `f` on the table under its lock. The lock is a real OS mutex taken through
    /// [`snare_interpose::real`], so neither the scheduler nor the clock sees it, and a poisoned
    /// lock is recovered rather than propagated: the table holds no invariant a panic can break.
    fn table<R>(&self, f: impl FnOnce(&mut Table) -> R) -> R {
        snare_interpose::real(|| f(&mut self.table.lock().unwrap_or_else(|e| e.into_inner())))
    }

    /// Sets `name`'s addresses, replacing an existing entry in place (it keeps its position for
    /// reverse lookups) and updating its canonical spelling.
    pub(crate) fn add(&self, name: &str, addrs: impl IntoIterator<Item = IpAddr>) {
        let canonical = name.strip_suffix('.').unwrap_or(name).to_string();
        let key = key(name);
        let addrs: Vec<IpAddr> = addrs.into_iter().collect();
        self.table(
            |table| match table.entries.iter_mut().find(|e| e.key == key) {
                Some(entry) => {
                    entry.canonical = canonical;
                    entry.addrs = addrs;
                }
                None => table.entries.push(Entry {
                    key,
                    canonical,
                    addrs,
                }),
            },
        );
    }

    /// Drops `name`'s entry; its policy, if any, stays.
    pub(crate) fn remove(&self, name: &str) {
        let key = key(name);
        self.table(|table| table.entries.retain(|e| e.key != key));
    }

    /// Edits `name`'s policy, starting from `DnsPolicy::default()` if it has none (not from the
    /// sim's default policy), and forgets it again if the edit leaves it at that default.
    pub(crate) fn update_policy(&self, name: &str, change: impl FnOnce(&mut DnsPolicy)) {
        let key = key(name);
        self.table(|table| {
            let policy = table.policies.entry(key.clone()).or_default();
            change(policy);
            if *policy == DnsPolicy::default() {
                table.policies.remove(&key);
            }
        });
    }

    /// Edits the policy for names without one of their own.
    pub(crate) fn update_default_policy(&self, change: impl FnOnce(&mut DnsPolicy)) {
        self.table(|table| change(&mut table.default));
    }

    /// Turns the real-resolver fallback on or off.
    pub(crate) fn set_real(&self, on: bool) {
        self.real.store(on, Ordering::Relaxed);
    }

    /// Looks `name` up as the sim's resolver: after the policy's latency, its failure, then the
    /// table, then the built-in names. Draws from the sim's generator only for a policy with a
    /// failure rate, once per lookup.
    ///
    /// The table is read before the latency elapses, so an edit made during the wait is not seen
    /// by this lookup. A zero latency still charges the per-call latency that keeps a polling
    /// thread from freezing the virtual clock (see [`snare_interpose::charge_latency`]); a
    /// non-zero one is a timed wait on the sim's readiness board that nothing satisfies early.
    fn lookup(&self, shared: &SimShared, name: &str) -> Lookup {
        let key = key(name);
        let (found, policy) = self.table(|table| {
            let found = table
                .entries
                .iter()
                .find(|e| e.key == key)
                .map(|e| Lookup::Addrs {
                    canonical: e.canonical.clone(),
                    addrs: e.addrs.clone(),
                });
            let policy = table.policies.get(&key).unwrap_or(&table.default).clone();
            (found, policy)
        });
        if policy.latency.is_zero() {
            snare_interpose::charge_latency();
        } else {
            let deadline = Deadline::after(policy.latency);
            readiness().wait_until("dns lookup", Some(deadline), || false);
        }
        let fails = if policy.failure_rate > 0.0 {
            shared.policies.unit() < policy.failure_rate
        } else {
            policy.failure.is_some()
        };
        if fails {
            let failure = policy.failure.unwrap_or(DnsFailure::TryAgain);
            shared.record(RecordedEvent::Fault {
                addr: None,
                fault: Fault::Dns {
                    name: name.to_string(),
                    failure,
                },
            });
            return match failure {
                DnsFailure::NotFound => Lookup::NotFound,
                DnsFailure::TryAgain => Lookup::TryAgain,
                DnsFailure::Fail => Lookup::Fail,
            };
        }
        match found.or_else(|| builtin(&key)) {
            Some(found) => found,
            None if self.real.load(Ordering::Relaxed) => Lookup::Real,
            None => Lookup::NotFound,
        }
    }

    /// Names `ip`: the first entry, in insertion order, listing it; then `localhost` for a
    /// loopback on Linux and macOS (not on Windows, where an unlisted loopback falls through); then
    /// the real resolver if enabled.
    fn reverse(&self, ip: IpAddr) -> Reverse {
        let found = self.table(|table| {
            table
                .entries
                .iter()
                .find(|e| e.addrs.contains(&ip))
                .map(|e| e.canonical.clone())
        });
        match found {
            Some(name) => Reverse::Name(name),
            // Linux and macOS name their loopbacks localhost from /etc/hosts (man 5 hosts lists
            // `127.0.0.1 localhost` and `::1 localhost`); tests/dns.rs `getnameinfo_reverse` pins
            // 127.0.0.1 against the real resolver. What Windows answers is not modelled or pinned.
            None if !cfg!(windows) && LOOPBACKS.contains(&ip) => Reverse::Name("localhost".into()),
            None if self.real.load(Ordering::Relaxed) => Reverse::Real,
            None => Reverse::NotFound,
        }
    }
}

/// The resolver a sim's domain answers lookups with. Holds the sim strongly: the domain it is
/// installed in belongs to the [`Sim`](crate::Sim), which outlives it.
pub(crate) struct SimResolver(pub(crate) Arc<SimShared>);

impl Resolver for SimResolver {
    fn lookup(&self, name: &str) -> Lookup {
        self.0.dns.lookup(&self.0, name)
    }

    fn reverse(&self, ip: IpAddr) -> Reverse {
        self.0.dns.reverse(ip)
    }
}

/// Resolves `name` to `addrs`, in that order, in the sim the calling thread runs in, replacing
/// any addresses it had. Case and one trailing dot do not matter. A name added with no addresses
/// is known but has none, which lookups report as the host OS reports such a name.
#[track_caller]
pub fn add_host(name: &str, addrs: impl IntoIterator<Item = IpAddr>) {
    crate::scope::here().dns.add(name, addrs);
}

/// Forgets `name` in the sim the calling thread runs in.
#[track_caller]
pub fn remove_host(name: &str) {
    crate::scope::here().dns.remove(name);
}

/// Changes how the sim the calling thread runs in answers lookups of `name`, known or not.
///
/// ```no_run
/// # use std::time::Duration;
/// # use snare::{DnsFailure, Sim, set_dns_policy};
/// Sim::new().run(|| {
///     set_dns_policy("robot1.local", |p| p.latency = Duration::from_millis(30));
///     set_dns_policy("flaky.local", |p| {
///         p.failure = Some(DnsFailure::TryAgain);
///         p.failure_rate = 0.5;
///     });
/// });
/// ```
#[track_caller]
pub fn set_dns_policy(name: &str, change: impl FnOnce(&mut DnsPolicy)) {
    crate::scope::here().dns.update_policy(name, change);
}

/// Changes how the sim the calling thread runs in answers lookups of names without a policy of
/// their own.
#[track_caller]
pub fn set_default_dns_policy(change: impl FnOnce(&mut DnsPolicy)) {
    crate::scope::here().dns.update_default_policy(change);
}

/// The names a [`SimBuilder`](crate::SimBuilder) loads into its sim's table.
#[derive(Default)]
pub(crate) struct DnsSetup {
    /// `add_host` calls, applied in order (a later one for the same name wins).
    hosts: Vec<(String, Vec<IpAddr>)>,
    /// Names to look up on the real resolver at build, after `hosts`, so they win over an
    /// `add_host` of the same name.
    resolve_real: Vec<String>,
    /// The real-resolver fallback for unknown names.
    real: bool,
}

impl DnsSetup {
    /// Queues `name` → `addrs` for [`apply`](Self::apply).
    pub(crate) fn add_host(&mut self, name: &str, addrs: impl IntoIterator<Item = IpAddr>) {
        self.hosts
            .push((name.to_string(), addrs.into_iter().collect()));
    }

    /// Queues `name` to be snapshotted from the real resolver at [`apply`](Self::apply).
    pub(crate) fn resolve_real(&mut self, name: &str) {
        self.resolve_real.push(name.to_string());
    }

    /// Enables the real-resolver fallback.
    pub(crate) fn real_dns(&mut self) {
        self.real = true;
    }

    /// Panics if the sim would ask the real resolver while it schedules deterministically: that
    /// call blocks in the OS outside the schedule.
    #[track_caller]
    pub(crate) fn check(&self, deterministic: bool) {
        assert!(
            !(self.real && deterministic),
            "SimBuilder::real_dns cannot be combined with deterministic(): a real lookup blocks \
             in the OS while the thread holds the schedule; snapshot names with resolve_real \
             instead"
        );
    }

    /// Loads the table, looking each `resolve_real` name up on the real resolver now, through
    /// std's `ToSocketAddrs` with port 0; repeated addresses are dropped and the resolver's order
    /// kept. Panics if a real lookup fails.
    #[track_caller]
    pub(crate) fn apply(self, shared: &Arc<SimShared>) {
        for (name, addrs) in self.hosts {
            shared.dns.add(&name, addrs);
        }
        for name in self.resolve_real {
            let found = snare_interpose::real(|| {
                use std::net::ToSocketAddrs;
                (name.as_str(), 0).to_socket_addrs()
            });
            let found = match found {
                Ok(found) => found,
                Err(e) => panic!("resolve_real({name:?}): the real resolver failed: {e}"),
            };
            let mut addrs: Vec<IpAddr> = Vec::new();
            for addr in found {
                if !addrs.contains(&addr.ip()) {
                    addrs.push(addr.ip());
                }
            }
            shared.dns.add(&name, addrs);
        }
        shared.dns.set_real(self.real);
    }

    /// The resolver to install in the sim's domain.
    pub(crate) fn resolver(shared: &Arc<SimShared>) -> Arc<dyn Resolver> {
        Arc::new(SimResolver(shared.clone()))
    }
}
