//! Injected faults with the host OS's semantics: how a listening address answers a SYN and the
//! SYN retransmission plan a connect waits out when nothing answers, raised socket errors, ICMP
//! port unreachables, and one-way link stalls — in virtual time under the virtual clock.
//!
//! Every function that reads or writes the sim's tables does so inside
//! [`snare_interpose::real`], so the mutexes and clock reads it makes reach the OS rather than
//! the sim (no per-call latency is charged and nothing re-enters the interposer). The
//! `listener_behavior` table is a leaf lock: nothing else is locked while it is held. A socket's
//! state lock is taken one record at a time and released before [`SimShared::kick`], which must
//! run with no sim lock held.
//!
//! A connect's SYN schedule follows the host kernel: Linux uses initial linear timeouts and
//! then doubles a 1 s timeout according to its retry limits, macOS walks `tcp_syn_backoff`
//! until `net.inet.tcp.keepinit` (bsd/netinet/tcp_timer.c), Windows doubles a 3 s initial timeout
//! over `MaxSynRetransmissions`. Each point of the schedule is a virtual timer the sim can jump
//! to, so a 127 s Linux connect timeout costs no wall time.

use std::collections::{HashMap, VecDeque};
use std::ffi::c_int;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::events::{Direction, Fault, RecordedEvent};
use crate::netif::{Presence, Sender};
use crate::pcapng::TcpTap;
use crate::readiness::Deadline;
use crate::scope::{self, SimShared};
use crate::sockets::{ErrorOrigin, SockOpts, SockRec, SocketKind};

/// How a TCP listening address answers connects, set with [`set_listener_behavior`]. It applies
/// to a tester's listener and to one of the code under test alike, and to an address nothing
/// listens on yet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ListenerBehavior {
    /// Answers as the address's own state says: a listener accepts, no listener resets. Setting
    /// it removes any behaviour the address had.
    #[default]
    Accepting,
    /// Answers every SYN with a reset: the connect fails with `ECONNREFUSED` at once on unix
    /// (RFC 9293 §3.10.7.3, a RST in SYN-SENT), and with `WSAECONNREFUSED` after the retries
    /// Windows makes on a reset (`WINDOWS_REFUSED_AFTER`, measured).
    Refusing,
    /// Drops every SYN until then, as a SYN-flooded listener does: the connect completes at the
    /// first SYN retransmission after it, or times out when the host OS gives up first.
    DelayingUntil(Instant),
}

/// A [`ListenerBehavior`] with its instant fixed on the sim's clock. A test hands in a real
/// [`Instant`]; the sim keeps the equivalent [`Deadline`] so the delay ends at the same virtual
/// moment however fast the clock runs.
#[derive(Clone, Copy)]
pub(crate) enum Behavior {
    /// Never stored: setting it removes the address's entry.
    Accepting,
    /// Every SYN is answered with a reset.
    Refusing,
    /// Every SYN is dropped until the deadline passes.
    Delaying(Deadline),
}

impl Behavior {
    /// `behavior` with an instant read as the calling thread reads `Instant`s.
    fn here(behavior: ListenerBehavior) -> Self {
        Self::convert(behavior, Deadline::timeout)
    }

    /// `behavior` with an instant that is `until - Instant::now()` away on `shared`'s clock, as
    /// read on a thread that may be outside the sim.
    fn on(shared: &SimShared, behavior: ListenerBehavior) -> Self {
        let mine = scope::try_here().is_some_and(|here| std::ptr::eq(&*here, shared));
        if mine {
            return Self::here(behavior);
        }
        Self::convert(behavior, |span| {
            Deadline::on_clock(shared.clock.as_deref(), span)
        })
    }

    /// `behavior` with a [`ListenerBehavior::DelayingUntil`] instant turned into a deadline by
    /// `deadline`, given how far ahead of the real now it lies (an instant already past is zero
    /// away).
    fn convert(behavior: ListenerBehavior, deadline: impl FnOnce(Duration) -> Deadline) -> Self {
        match behavior {
            ListenerBehavior::Accepting => Behavior::Accepting,
            ListenerBehavior::Refusing => Behavior::Refusing,
            ListenerBehavior::DelayingUntil(until) => {
                Behavior::Delaying(deadline(until.saturating_duration_since(Instant::now())))
            }
        }
    }
}

/// Makes `addr` (every address it resolves to) answer connects as `behavior` says, in the sim the
/// calling thread runs in. The wildcard address covers every address on its port that has no
/// behaviour of its own. Panics off a sim.
#[track_caller]
pub fn set_listener_behavior(addr: impl ToSocketAddrs, behavior: ListenerBehavior) {
    let shared = scope::here();
    let addrs = resolve(addr);
    shared.set_listener_behavior(&addrs, Behavior::here(behavior));
}

/// [`set_listener_behavior`] on `shared` from any thread, as a [`Sim`](crate::Sim) handle used
/// outside its run calls it.
pub(crate) fn set_listener_behavior_on(
    shared: &SimShared,
    addr: impl ToSocketAddrs,
    behavior: ListenerBehavior,
) {
    let addrs = resolve(addr);
    shared.set_listener_behavior(&addrs, Behavior::on(shared, behavior));
}

/// Every address `addr` resolves to. Panics when it does not parse; a fault address is a test's
/// literal, so a typo is a bug in the test.
#[track_caller]
fn resolve(addr: impl ToSocketAddrs) -> Vec<SocketAddr> {
    addr.to_socket_addrs()
        .expect("fault address must parse")
        .collect()
}

/// Makes `error` the pending error of every socket of the code under test at `addr` (every address
/// it resolves to): each stream whose local or peer address it is, and each datagram socket bound
/// at or connected to it. The next call that reports errors fails with it, as the host kernel
/// orders them: a send first everywhere (xnu bsd/kern/uipc_socket.c `sosendcheck`; Linux
/// net/ipv4/tcp.c `tcp_sendmsg_locked` and net/core/sock.c `sock_alloc_send_pskb`); a receive
/// after the data already queued on macOS (`soreceive` jumps to `dontblock` while `sb_mb` holds
/// data), and on Linux for a stream (net/ipv4/tcp.c `tcp_recvmsg_locked` reports `sk_err` only
/// once nothing was copied); before it on Linux for a datagram socket (net/ipv4/udp.c
/// `__skb_recv_udp` checks `sock_error` before dequeuing) and on Windows (undocumented;
/// tests/faults.rs `raised_error_on_udp_ordering` and
/// `raised_error_on_tcp_returns_buffered_data_first` pin the sim's order).
/// Reporting clears it, as `getsockopt(SO_ERROR)` does (man 7 socket, `SO_ERROR`). A blocked call
/// returns at once, and poll, epoll, kqueue, `WSAPoll` and select report the socket. Panics off a
/// sim, and for an error kind with no socket error code.
#[track_caller]
pub fn raise_socket_error(addr: impl ToSocketAddrs, error: io::Error) {
    let shared = scope::here();
    shared.raise_socket_error(&resolve(addr), socket_errno(&error));
}

/// Delivers an ICMP port unreachable from `from` to the datagram sockets of the code under test
/// bound at `to`, as the host kernel takes one: a socket connected to `from` fails its next
/// receive or send with `ECONNREFUSED` (its next receive with `WSAECONNRESET` on Windows); a
/// socket connected elsewhere ignores it; an unconnected one ignores it on macOS (xnu
/// bsd/netinet/udp_usrreq.c `udp_ctlinput` finds the socket with a non-wildcard
/// `in_pcblookup_hash` on the datagram's four-tuple, which only a socket connected to `from`
/// matches) and on Linux unless `IP_RECVERR` is on (net/ipv4/udp.c `__udp4_lib_err`, `udp_err` in
/// mainline: without `RECVERR` only a hard error on a `TCP_ESTABLISHED`, i.e. connected, socket
/// sets `sk_err`; man 2const `IP_RECVERR`),
/// and on Windows fails its next receive with `WSAECONNRESET` unless `SIO_UDP_CONNRESET` turned
/// that off ([Microsoft Learn: recvfrom](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom),
/// `WSAECONNRESET`; [Microsoft Learn: Winsock IOCTLs](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls),
/// `SIO_UDP_CONNRESET`). Panics off a sim.
#[track_caller]
pub fn inject_icmp_port_unreachable(to: impl ToSocketAddrs, from: impl ToSocketAddrs) {
    let shared = scope::here();
    let from = resolve(from)
        .into_iter()
        .next()
        .expect("fault address resolved to nothing");
    shared.inject_icmp(&resolve(to), from);
}

/// Holds the traffic at `addr` (every address it resolves to) for `span` on the sim's clock: what
/// arrives there for [`Direction::Receive`], what leaves it for [`Direction::Send`], both for
/// [`Direction::Both`]. TCP bytes in flight and written meanwhile, and a FIN, land in order once
/// the stall ends, still counting against the receive window; bytes already received stay
/// readable. Datagrams arrive once it ends. Panics off a sim.
#[track_caller]
pub fn quiesce(addr: impl ToSocketAddrs, span: Duration, direction: Direction) {
    let shared = scope::here();
    shared.quiesce(&resolve(addr), span, direction);
}

/// [`raise_socket_error`] on `shared` from any thread.
pub(crate) fn raise_socket_error_on(
    shared: &SimShared,
    addr: impl ToSocketAddrs,
    error: io::Error,
) {
    shared.raise_socket_error(&resolve(addr), socket_errno(&error));
}

/// [`inject_icmp_port_unreachable`] on `shared` from any thread.
pub(crate) fn inject_icmp_on(shared: &SimShared, to: impl ToSocketAddrs, from: impl ToSocketAddrs) {
    let from = resolve(from)
        .into_iter()
        .next()
        .expect("fault address resolved to nothing");
    shared.inject_icmp(&resolve(to), from);
}

/// [`quiesce`] on `shared` from any thread.
pub(crate) fn quiesce_on(
    shared: &SimShared,
    addr: impl ToSocketAddrs,
    span: Duration,
    direction: Direction,
) {
    shared.quiesce(&resolve(addr), span, direction);
}

/// The host's code for a socket error: its raw OS error as given, else the code the host OS uses
/// for its kind (see [`code`]). Panics for a kind no socket call reports.
#[track_caller]
pub(crate) fn socket_errno(error: &io::Error) -> c_int {
    if let Some(code) = error.raw_os_error() {
        return code;
    }
    use io::ErrorKind as K;
    match error.kind() {
        K::ConnectionReset => code::ECONNRESET,
        K::ConnectionAborted => code::ECONNABORTED,
        K::ConnectionRefused => code::ECONNREFUSED,
        K::TimedOut => code::ETIMEDOUT,
        K::BrokenPipe => code::EPIPE,
        K::NotConnected => code::ENOTCONN,
        K::NetworkUnreachable => code::ENETUNREACH,
        K::HostUnreachable => code::EHOSTUNREACH,
        K::NetworkDown => code::ENETDOWN,
        K::AddrNotAvailable => code::EADDRNOTAVAIL,
        kind => panic!("no socket error code for {kind:?}"),
    }
}

impl SimShared {
    /// A deadline `span` from now on this sim's clock, read from any thread.
    pub(crate) fn deadline_after(&self, span: Duration) -> Deadline {
        if self.is_here() {
            snare_interpose::real(|| Deadline::after(span))
        } else {
            Deadline::on_clock(self.clock.as_deref(), span)
        }
    }

    /// Makes waiters re-check once `at` (from [`deadline_after`](Self::deadline_after)) passes.
    pub(crate) fn wake_at(&self, at: Deadline) {
        snare_interpose::real(|| {
            if self.is_here() {
                at.wake_waiters_then();
            } else {
                at.wake_waiters_on(self.clock.as_deref());
            }
        });
    }

    /// Whether the calling thread runs in this sim, so its own clock reads are this sim's.
    fn is_here(&self) -> bool {
        scope::try_here().is_some_and(|here| std::ptr::eq(&*here, self))
    }

    /// Makes `errno` pending on every live stream or datagram socket whose local or peer address
    /// is one of `addrs`, then wakes waiters so a blocked call sees it. Each record's state lock
    /// is dropped before [`SockRec::raise_error`] takes it again.
    pub(crate) fn raise_socket_error(&self, addrs: &[SocketAddr], errno: c_int) {
        let keys = snare_interpose::real(|| {
            let mut keys = crate::readiness::WakeKeys::default();
            for rec in self.sockets.live_recs() {
                let state = rec.state();
                let at = |a: Option<SocketAddr>| a.is_some_and(|a| addrs.contains(&a));
                let hit = matches!(state.kind, SocketKind::TcpStream | SocketKind::Udp)
                    && (at(state.local) || at(state.peer));
                drop(state);
                if hit {
                    rec.raise_error(errno, ErrorOrigin::Raised, None);
                    keys.push(rec.wake_key());
                }
            }
            keys
        });
        self.kick_keys(keys.as_slice());
    }

    /// Delivers an ICMP port unreachable from `from` to every live datagram socket bound at one
    /// of `to`, or at the wildcard of the same family on its port, capturing it on the pcapng tap
    /// at once.
    pub(crate) fn inject_icmp(&self, to: &[SocketAddr], from: SocketAddr) {
        let keys = snare_interpose::real(|| {
            let mut keys = crate::readiness::WakeKeys::default();
            for rec in self.sockets.live_recs() {
                let local = rec.state().local;
                let bound_at = local.and_then(|l| {
                    to.iter().copied().find(|t| {
                        *t == l
                            || (l.ip().is_unspecified()
                                && l.port() == t.port()
                                && l.is_ipv4() == t.is_ipv4())
                    })
                });
                if let Some(at) = bound_at
                    && rec.kind() == SocketKind::Udp
                {
                    self.capture_icmp(&Sender::Station(from.ip()), at, from, &[], Duration::ZERO);
                    self.icmp_to(&rec, from, None, &[]);
                    keys.push(rec.wake_key());
                }
            }
            keys
        });
        self.kick_keys(keys.as_slice());
    }

    /// An ICMP port unreachable from `from` reaching datagram socket `rec`, readable once
    /// `arrives` has passed. Which sockets take it follows [`inject_icmp_port_unreachable`]; on
    /// Linux with `IP_RECVERR` it is also queued for `recvmsg(MSG_ERRQUEUE)` as `ECONNREFUSED`
    /// (net/ipv4/udp.c `__udp4_lib_err`, `udp_err` in mainline, calls `ip_icmp_error`; man 2const
    /// `IP_RECVERR`).
    pub(crate) fn icmp_to(
        &self,
        rec: &SockRec,
        from: SocketAddr,
        arrives: Option<Deadline>,
        payload: &[u8],
    ) {
        let (peer, opts) = {
            let state = rec.state();
            (state.peer, state.dgram)
        };
        let connected = match peer {
            Some(peer) if peer != from => return,
            Some(_) => true,
            None => false,
        };
        let taken = if cfg!(target_os = "linux") {
            connected || opts.recverr
        } else if cfg!(windows) {
            opts.connreset
        } else {
            connected
        };
        if cfg!(target_os = "linux") && opts.recverr {
            rec.queue_icmp_report(code::ECONNREFUSED, from, arrives, payload);
        }
        if taken {
            rec.raise_error(code::ICMP_UNREACH, ErrorOrigin::Icmp { from }, arrives);
        }
    }

    /// Answers `data`, a datagram `rec` sent from `src` to `dest` along `sender` that reached no
    /// socket: when an address answers there, an ICMP port unreachable comes back after the
    /// round trip (the link's fixed delays, no jitter, so no draws). `station` says whether
    /// `rec` is a tester or station socket rather than one of the code under test. The kernel
    /// sends this ICMP from the receiving host (RFC 1122 §4.1.3.1). The datagram counts in the
    /// host's UDP counters when the host was the one to take it
    /// ([`count_unreceived`](Self::count_unreceived)).
    pub(crate) fn unreachable_port(
        &self,
        rec: &Arc<SockRec>,
        sender: &Sender,
        src: SocketAddr,
        dest: SocketAddr,
        data: &[u8],
        station: bool,
    ) {
        self.count_unreceived(dest, station);
        let Some(nic) = self.icmp_one_way(sender, dest.ip(), station) else {
            return;
        };
        let one_way = nic + self.policies.udp_latency(dest);
        self.capture_icmp(sender, src, dest, data, one_way);
        let round_trip = one_way * 2;
        let arrives = (!round_trip.is_zero()).then(|| Deadline::after(round_trip));
        if let Some(arrives) = arrives {
            arrives.wake_waiters_then();
        }
        self.icmp_to(rec, dest, arrives, data);
    }

    /// Stalls `direction` at each of `addrs` until `span` from now on this sim's clock, records a
    /// [`Fault::Stalled`] per address, and arms a wake for the stall's end so held traffic lands
    /// then.
    pub(crate) fn quiesce(&self, addrs: &[SocketAddr], span: Duration, direction: Direction) {
        #[cfg(target_os = "macos")]
        let since = self.deadline_after(Duration::ZERO);
        let until = self.deadline_after(span);
        snare_interpose::real(|| {
            for &addr in addrs {
                #[cfg(target_os = "macos")]
                self.policies.stall_at(addr, direction, since, until);
                #[cfg(not(target_os = "macos"))]
                self.policies.stall(addr, direction, until);
                self.record(RecordedEvent::Fault {
                    addr: Some(addr),
                    fault: Fault::Stalled { span, direction },
                });
            }
            #[cfg(target_os = "macos")]
            for rec in self.sockets.live_recs() {
                rec.land();
            }
        });
        self.wake_at(until);
        self.kick();
    }
}

/// How the destination answered one SYN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Syn {
    /// A listener takes the connection (SYN-ACK).
    Accept,
    /// A reset: a [`Behavior::Refusing`] address, or a host that is there with nothing
    /// listening.
    Rst,
    /// Dropped: a [`Behavior::Delaying`] address before its deadline.
    Silent,
    /// Nobody is at the address; `on_link` when it sits on a segment the host is attached to, so
    /// neighbour resolution is what fails.
    Absent { on_link: bool },
}

impl SimShared {
    /// Stores `behavior` for each of `addrs`; [`Behavior::Accepting`] removes the entry instead.
    pub(crate) fn set_listener_behavior(&self, addrs: &[SocketAddr], behavior: Behavior) {
        snare_interpose::real(|| {
            let mut table = self.listener_behavior.lock().unwrap();
            for &addr in addrs {
                match behavior {
                    Behavior::Accepting => table.remove(&addr),
                    _ => table.insert(addr, behavior),
                };
            }
        });
    }

    /// The behaviour of `dest`: its own entry, else the entry of the wildcard of its family on
    /// its port, else [`Behavior::Accepting`].
    fn behavior_at(&self, dest: SocketAddr) -> Behavior {
        snare_interpose::real(|| {
            let table = self.listener_behavior.lock().unwrap();
            let wildcard = SocketAddr::new(unspecified_like(dest.ip()), dest.port());
            table
                .get(&dest)
                .or_else(|| table.get(&wildcard))
                .copied()
                .unwrap_or(Behavior::Accepting)
        })
    }

    /// How `dest` answers a SYN now: `listening` says whether a listener would take the
    /// connection, `station` whether a tester or station socket sits at its address. A listener
    /// behaviour wins over the address's own state; with none and no listener, a host that is
    /// present resets and an absent one answers [`Syn::Absent`].
    pub(crate) fn syn_probe(&self, dest: SocketAddr, listening: bool, station: bool) -> Syn {
        match self.behavior_at(dest) {
            Behavior::Refusing => return Syn::Rst,
            Behavior::Delaying(until) if !until.passed() => return Syn::Silent,
            _ => {}
        }
        if listening {
            return Syn::Accept;
        }
        let (presence, on_link) = self.syn_target(dest.ip(), station);
        match presence {
            Presence::Absent => Syn::Absent { on_link },
            _ => Syn::Rst,
        }
    }

    /// The plan a connect from a socket with `opts` follows after a first answer of `first`. An
    /// absent on-link address cuts the plan short where neighbour resolution fails
    /// ([`NEIGHBOUR_FAILURE`]), dropping the retransmissions after that point.
    pub(crate) fn syn_plan(&self, opts: &SockOpts, first: Syn) -> SynPlan {
        let mut plan = base_plan(self, opts);
        if let (Syn::Absent { on_link: true }, Some((at, errno))) = (first, NEIGHBOUR_FAILURE)
            && at < plan.give_up
        {
            plan.give_up = at;
            plan.errno = errno;
            plan.retransmits.retain(|t| *t < at);
        }
        plan
    }

    /// Records how a connect to `dest` that waited on its SYN, or was refused by its listener's
    /// behaviour, ended, counting a failure in the host's TCP `AttemptFails`. A connect that succeeded at once records nothing; an `ECONNREFUSED` is
    /// recorded only when a [`Behavior::Refusing`] caused it, since a refusal by an address with
    /// no listener is the ordinary outcome, not an injected fault.
    pub(crate) fn connect_settled(&self, dest: SocketAddr, outcome: Outcome, waited: bool) {
        if matches!(outcome, Outcome::Failed(_)) {
            crate::netstats::bump(&self.stats.tcp(dest.ip()).attempt_fails);
        }
        let fault = match outcome {
            Outcome::Connected if waited => Fault::ConnectDelayed {
                until: self.stamp(),
            },
            Outcome::Connected => return,
            Outcome::Failed(errno) if errno == code::ECONNREFUSED => {
                if !matches!(self.behavior_at(dest), Behavior::Refusing) {
                    return;
                }
                Fault::ConnectRefused
            }
            Outcome::Failed(errno) if errno == code::ETIMEDOUT => Fault::ConnectTimedOut,
            Outcome::Failed(errno) => Fault::Unreachable { errno },
        };
        self.record(RecordedEvent::Fault {
            addr: Some(dest),
            fault,
        });
    }
}

/// The wildcard address of `ip`'s family.
fn unspecified_like(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    }
}

/// The socket error codes faults report, by POSIX name: the `<errno.h>` values on unix (man 3
/// errno; IEEE Std 1003.1 `<errno.h>`).
#[cfg(unix)]
pub(crate) mod code {
    pub(crate) const ECONNREFUSED: i32 = libc::ECONNREFUSED;
    pub(crate) const ETIMEDOUT: i32 = libc::ETIMEDOUT;
    pub(crate) const EHOSTUNREACH: i32 = libc::EHOSTUNREACH;
    pub(crate) const ECONNRESET: i32 = libc::ECONNRESET;
    pub(crate) const ECONNABORTED: i32 = libc::ECONNABORTED;
    pub(crate) const EPIPE: i32 = libc::EPIPE;
    pub(crate) const ENOTCONN: i32 = libc::ENOTCONN;
    pub(crate) const ENETUNREACH: i32 = libc::ENETUNREACH;
    pub(crate) const ENETDOWN: i32 = libc::ENETDOWN;
    pub(crate) const EADDRNOTAVAIL: i32 = libc::EADDRNOTAVAIL;
    /// What an ICMP port unreachable makes a datagram socket's next call fail with: Linux
    /// net/ipv4/icmp.c `icmp_err_convert` maps `ICMP_PORT_UNREACH` to `ECONNREFUSED`; xnu
    /// bsd/netinet/ip_input.c `inetctlerrmap` maps `PRC_UNREACH_PORT` to it.
    pub(crate) const ICMP_UNREACH: i32 = libc::ECONNREFUSED;
}

/// Winsock codes (`<winerror.h>`), each named after the POSIX code it stands for: the value is
/// the `WSAE*` of the same name ([Microsoft Learn: Windows Sockets Error
/// Codes](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2)).
#[cfg(windows)]
pub(crate) mod code {
    /// `WSAECONNREFUSED`.
    pub(crate) const ECONNREFUSED: i32 = 10061;
    /// `WSAETIMEDOUT`.
    pub(crate) const ETIMEDOUT: i32 = 10060;
    /// `WSAEHOSTUNREACH`.
    pub(crate) const EHOSTUNREACH: i32 = 10065;
    /// `WSAECONNRESET`.
    pub(crate) const ECONNRESET: i32 = 10054;
    /// `WSAECONNABORTED`.
    pub(crate) const ECONNABORTED: i32 = 10053;
    /// `WSAESHUTDOWN`: what a send on a shut-down stream fails with.
    pub(crate) const EPIPE: i32 = 10058;
    /// `WSAENOTCONN`.
    pub(crate) const ENOTCONN: i32 = 10057;
    /// `WSAENETUNREACH`.
    pub(crate) const ENETUNREACH: i32 = 10051;
    /// `WSAENETDOWN`.
    pub(crate) const ENETDOWN: i32 = 10050;
    /// `WSAEADDRNOTAVAIL`.
    pub(crate) const EADDRNOTAVAIL: i32 = 10049;
    /// `WSAECONNRESET`: a UDP datagram that drew an ICMP port unreachable fails the next receive
    /// with it ([Microsoft Learn: recvfrom](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom)).
    pub(crate) const ICMP_UNREACH: i32 = 10054;
}

/// When the SYNs to an absent on-link address give up for want of a neighbour, and with what.
/// Measured with a blocking connect to an unused address on the local subnet, bound to the
/// primary NIC (tests/connect_faults.rs `real_os_on_link_absent_calibration`): Linux fails with
/// `EHOSTUNREACH` after its 3 neighbour solicitations a second apart (man 7 arp: `mcast_solicit`
/// defaults to 3 and `retrans_time_ms` to 1000). macOS
/// (bound with `IP_BOUND_IF` to en0) keeps retransmitting to `ETIMEDOUT` at keepinit, as its SYN
/// plan does. Windows has not been measured, so it follows its SYN plan to `WSAETIMEDOUT`.
#[cfg(target_os = "linux")]
const NEIGHBOUR_FAILURE: Option<(Duration, c_int)> =
    Some((Duration::from_secs(3), code::EHOSTUNREACH));
#[cfg(not(target_os = "linux"))]
const NEIGHBOUR_FAILURE: Option<(Duration, c_int)> = None;

/// Linux: the initial SYN retransmission timeout (`TCP_TIMEOUT_INIT`, `1*HZ`) and its cap
/// (`TCP_RTO_MAX`, `TCP_RTO_MAX_SEC` 120 s), include/net/tcp.h. With the default
/// `tcp_syn_retries` of 6 (Documentation/networking/ip-sysctl.rst) the connect gives up after
/// 1+2+4+8+16+32+64 = 127 s, as kernels before 6.5 do. Linux 6.5 added
/// `net.ipv4.tcp_syn_linear_timeouts` (default 4, net/ipv4/tcp_ipv4.c): a SYN-SENT socket makes
/// that many extra retransmissions, the first ones 1 s apart (net/ipv4/tcp_timer.c
/// `tcp_write_timeout` and `tcp_retransmit_timer`), so a stock 6.5+ kernel retransmits at
/// 1, 2, 3, 4, 5, 7, 11, 19, 35, 67 s and gives up at 131 s (ip-sysctl.rst, `tcp_syn_retries`).
#[cfg(target_os = "linux")]
const LINUX_RTO_INIT: Duration = Duration::from_secs(1);
#[cfg(target_os = "linux")]
const LINUX_RTO_MAX: Duration = Duration::from_secs(120);

/// macOS: the SYN backoff multipliers of the initial 1 s timeout (`tcp_syn_backoff`,
/// bsd/netinet/tcp_timer.c) and how long a connect may take (`net.inet.tcp.keepinit`,
/// `TCPTV_KEEP_INIT` 75 s in bsd/netinet/tcp_timer.h). xnu's table has 13 entries
/// (`TCP_MAXRXTSHIFT` 12 in bsd/netinet/tcp_timer.h, ending 64, 64, 64); the first 11 are kept,
/// which already reach past 75 s.
#[cfg(target_os = "macos")]
const MACOS_SYN_BACKOFF: [u64; 11] = [1, 1, 1, 1, 1, 2, 4, 8, 16, 32, 64];
#[cfg(target_os = "macos")]
const MACOS_KEEPINIT: Duration = Duration::from_secs(75);

/// Windows: `InitialRtoMs` 3000 and `MaxSynRetransmissions` 2, as `Get-NetTCPSetting` reports
/// them on a stock Windows 11 (the defaults are not documented; [Microsoft Learn:
/// Set-NetTCPSetting](https://learn.microsoft.com/en-us/powershell/module/nettcpip/set-nettcpsetting)
/// describes the knobs and caps `InitialRtoMs` at 3000). The timeout doubling on each
/// retransmission, which gives 3 + 6 + 12 = 21 s, is snare's assumption: Microsoft does not
/// document the SYN backoff and no test measures it.
#[cfg(windows)]
const WINDOWS_INITIAL_RTO: Duration = Duration::from_secs(3);
#[cfg(windows)]
const WINDOWS_MAX_SYN_RETRANSMISSIONS: u32 = 2;

/// Windows answers a reset by retrying the SYN, and reports the refusal this long after the first
/// reset. Measured, not documented: a loopback connect to a closed port sends five SYN/reset
/// pairs 500 ms apart and fails after about 2 s (tests/connect_faults.rs
/// `real_os_refusal_timing_calibration`, tests/proto_counters.rs
/// `refused_loopback_reset_counter_and_host_calibration`).
#[cfg(windows)]
pub(crate) const WINDOWS_REFUSED_AFTER: Duration = Duration::from_secs(2);

#[cfg(windows)]
const WINDOWS_REFUSED_RETRY: Duration = Duration::from_millis(500);

/// A connect's SYN schedule, as offsets from its start: when the SYN goes out again, and when the
/// OS gives up with `errno`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SynPlan {
    /// When each retransmitted SYN goes out, ascending, all before `give_up`.
    pub(crate) retransmits: Vec<Duration>,
    /// When the connect fails with `errno`; [`Duration::MAX`] when it never does (Windows
    /// `TCP_MAXRT` -1).
    pub(crate) give_up: Duration,
    pub(crate) errno: c_int,
    #[cfg(windows)]
    repeat_rto: Option<Duration>,
}

impl SynPlan {
    /// Retransmissions `rto` apart, doubling up to `cap`, `retries` of them, giving up one more
    /// timeout after the last.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    fn doubling(rto: Duration, cap: Duration, retries: u32) -> Self {
        let mut at = Duration::ZERO;
        let mut rto = rto;
        let mut retransmits = Vec::new();
        for _ in 0..retries {
            at += rto;
            retransmits.push(at);
            rto = (rto * 2).min(cap);
        }
        SynPlan {
            retransmits,
            give_up: at + rto,
            errno: code::ETIMEDOUT,
            #[cfg(windows)]
            repeat_rto: None,
        }
    }
}

/// Linux: retry-count and elapsed-time checks from `tcp_write_timeout`, with the initial
/// linear timeouts followed by exponential backoff from `tcp_retransmit_timer`.
#[cfg(target_os = "linux")]
fn base_plan(shared: &SimShared, opts: &SockOpts) -> SynPlan {
    let retries = opts
        .syncnt
        .unwrap_or_else(|| shared.sys.limits().tcp_syn_retries);
    linux_plan(retries, shared.sys.limits().tcp_syn_linear_timeouts)
}

#[cfg(target_os = "linux")]
fn linux_plan(retries: u8, linear: u8) -> SynPlan {
    let elapsed_limit = SynPlan::doubling(LINUX_RTO_INIT, LINUX_RTO_MAX, retries.into()).give_up;
    let mut at = Duration::ZERO;
    let mut rto = LINUX_RTO_INIT;
    let mut retransmits = Vec::new();
    for retry in 0..=u32::from(retries) + u32::from(linear) {
        at += rto;
        if at >= elapsed_limit || retry == u32::from(retries) + u32::from(linear) {
            break;
        }
        retransmits.push(at);
        if retry >= u32::from(linear) {
            rto = (rto * 2).min(LINUX_RTO_MAX);
        }
    }
    SynPlan {
        retransmits,
        give_up: at,
        errno: code::ETIMEDOUT,
    }
}

/// macOS: `TCP_CONNECTIONTIMEOUT` on the socket, else keepinit (bsd/netinet/tcp_timer.h
/// `TCP_CONN_KEEPINIT` falls back to `tcp_keepinit` while `t_keepinit` is 0).
#[cfg(target_os = "macos")]
fn base_plan(_shared: &SimShared, opts: &SockOpts) -> SynPlan {
    macos_plan(opts.connect_give_up.unwrap_or(MACOS_KEEPINIT))
}

/// The macOS plan giving up at `give_up`: retransmissions at the running sums of
/// [`MACOS_SYN_BACKOFF`] seconds, those before `give_up` kept.
#[cfg(target_os = "macos")]
fn macos_plan(give_up: Duration) -> SynPlan {
    let retransmits = MACOS_SYN_BACKOFF
        .iter()
        .scan(Duration::ZERO, |at, &k| {
            *at += Duration::from_secs(k);
            Some(*at)
        })
        .take_while(|at| *at < give_up)
        .collect();
    SynPlan {
        retransmits,
        give_up,
        errno: code::ETIMEDOUT,
    }
}

/// Windows: the stock plan, with `TCP_MAXRT` replacing its give-up point ([Microsoft Learn: IPPROTO_TCP socket
/// options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-tcp-socket-options),
/// `TCP_MAXRT`). Extended attempts continue exponential backoff capped at 60 seconds.
#[cfg(windows)]
fn base_plan(_shared: &SimShared, opts: &SockOpts) -> SynPlan {
    let mut plan = SynPlan::doubling(
        WINDOWS_INITIAL_RTO,
        Duration::MAX,
        WINDOWS_MAX_SYN_RETRANSMISSIONS,
    );
    if let Some(give_up) = opts.connect_give_up {
        if give_up > plan.give_up {
            plan.repeat_rto = Some(Duration::from_secs(12));
        }
        plan.give_up = give_up;
        plan.retransmits.retain(|t| *t < give_up);
    }
    plan
}

/// How a connect ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Connected,
    /// The connect failed with this host errno.
    Failed(c_int),
}

/// A point of a [`ConnectAttempt`]'s plan.
#[derive(Clone, Copy)]
enum Event {
    /// Windows: `WINDOWS_REFUSED_AFTER` after the first reset, when one more SYN is sent and a
    /// reset to it fails the connect.
    RefuseCheck,
    #[cfg(windows)]
    RefuseRetry,
    /// A SYN goes out again and its answer is probed.
    Retransmit,
    /// The OS gives up with the plan's errno.
    GiveUp,
}

/// A connect waiting on its SYN's answer, following its [`SynPlan`] from when it started. Each
/// point of the plan is an event the sim can skip to, called off when the connect resolves or the
/// attempt is dropped.
pub(crate) struct ConnectAttempt {
    /// Where the connect leaves from.
    pub(crate) client: SocketAddr,
    /// Captures the attempt's SYNs and resets while it waits; taken when it settles.
    tap: Option<TcpTap>,
    /// The retransmissions still to come, earliest first.
    retransmits: VecDeque<Deadline>,
    #[cfg(windows)]
    repeat_rto: Option<Duration>,
    #[cfg(windows)]
    dynamic_retransmit: bool,
    #[cfg(windows)]
    dynamic_timer: Option<u64>,
    give_up: Deadline,
    /// What the connect fails with at `give_up`.
    errno: c_int,
    /// Windows: when a reset already seen turns into a refusal (see [`Event::RefuseCheck`]).
    refuse_at: Option<Deadline>,
    #[cfg(windows)]
    refuse_retries: VecDeque<Deadline>,
    /// The point of the plan that settled the connect, so the handshake is captured then.
    settled_at: Option<Deadline>,
    /// The tap of a connect accepted but not yet established.
    accepted: Option<TcpTap>,
    /// Whether [`start`](Self::start) has armed the plan's timers, so a point added later is
    /// armed too.
    armed: bool,
    /// Keys of the virtual timers armed for the plan's points, unregistered when the attempt
    /// settles or is dropped so the sim does not jump to a point nobody waits on.
    timers: Vec<u64>,
}

impl ConnectAttempt {
    /// Starts following `plan` now from `client`, after a first answer of `first`; `Err` when
    /// that answer settles the connect at once. `tap` captures its SYNs and the resets answering
    /// them.
    pub(crate) fn start(
        plan: &SynPlan,
        first: Syn,
        client: SocketAddr,
        tap: Option<TcpTap>,
    ) -> Result<Self, Outcome> {
        let now = Deadline::timeout(Duration::ZERO);
        if let Some(tap) = &tap {
            tap.syn();
        }
        let mut attempt = ConnectAttempt {
            client,
            tap,
            retransmits: plan.retransmits.iter().map(|&t| now.later(t)).collect(),
            #[cfg(windows)]
            repeat_rto: plan.repeat_rto,
            #[cfg(windows)]
            dynamic_retransmit: false,
            #[cfg(windows)]
            dynamic_timer: None,
            give_up: now.later(plan.give_up),
            errno: plan.errno,
            refuse_at: None,
            #[cfg(windows)]
            refuse_retries: VecDeque::new(),
            settled_at: None,
            accepted: None,
            armed: false,
            timers: Vec::new(),
        };
        if let Some(outcome) = attempt.react(now, first) {
            return Err(outcome);
        }
        if let Some(tap) = &attempt.tap {
            tap.syn_plan(&plan.retransmits);
        }
        #[allow(unused_mut)]
        let mut points: Vec<Deadline> = attempt
            .retransmits
            .iter()
            .copied()
            .chain((plan.give_up != Duration::MAX).then_some(attempt.give_up))
            .chain(attempt.refuse_at)
            .collect();
        #[cfg(windows)]
        points.extend(attempt.refuse_retries.iter().copied());
        attempt.timers = points.iter().filter_map(Deadline::arm).collect();
        attempt.armed = true;
        Ok(attempt)
    }

    /// Takes answer `syn` to the SYN sent at `at`: `Some` when it settles the connect. A reset
    /// fails it at once on unix (RFC 9293 §3.10.7.3); Windows retries every 500 ms until the
    /// [`Event::RefuseCheck`] `WINDOWS_REFUSED_AFTER` later (measured).
    #[cfg_attr(not(windows), allow(unused_variables))]
    fn react(&mut self, at: Deadline, syn: Syn) -> Option<Outcome> {
        if let (Syn::Rst, Some(tap)) = (syn, &self.tap) {
            tap.refused(at.overdue());
        }
        match syn {
            Syn::Accept => Some(Outcome::Connected),
            #[cfg(windows)]
            Syn::Rst => {
                if self.refuse_at.is_none() {
                    let refuse_at = at.later(WINDOWS_REFUSED_AFTER);
                    self.refuse_at = Some(refuse_at);
                    self.refuse_retries = (1..4)
                        .map(|retry| at.later(WINDOWS_REFUSED_RETRY * retry))
                        .collect();
                    if self.armed {
                        self.timers.extend(refuse_at.arm());
                        self.timers
                            .extend(self.refuse_retries.iter().filter_map(Deadline::arm));
                    }
                }
                None
            }
            #[cfg(unix)]
            Syn::Rst => Some(Outcome::Failed(code::ECONNREFUSED)),
            Syn::Silent | Syn::Absent { .. } => None,
        }
    }

    /// The earliest point of the plan still to come.
    fn next(&self) -> (Deadline, Event) {
        [
            (self.refuse_at, Event::RefuseCheck),
            #[cfg(windows)]
            (self.refuse_retries.front().copied(), Event::RefuseRetry),
            (self.retransmits.front().copied(), Event::Retransmit),
            (Some(self.give_up), Event::GiveUp),
        ]
        .into_iter()
        .filter_map(|(at, event)| Some((at?, event)))
        .min_by_key(|(at, _)| at.instant())
        .expect("an attempt always has a give-up point")
    }

    /// Whether a point of the plan has come, so [`poll`](Self::poll) has something to do.
    pub(crate) fn due(&self) -> bool {
        self.next().0.passed()
    }

    /// Plays every point of the plan that has come, asking `probe` for the answer to each SYN
    /// retransmitted: `Ok` with the next point while the connect still waits.
    pub(crate) fn poll(&mut self, mut probe: impl FnMut() -> Syn) -> Result<Deadline, Outcome> {
        loop {
            let (at, event) = self.next();
            if !at.passed() {
                return Ok(at);
            }
            let outcome = match event {
                #[cfg(windows)]
                Event::RefuseRetry => {
                    self.refuse_retries.pop_front();
                    if let Some(tap) = &self.tap {
                        tap.resend_syn(at.overdue());
                    }
                    self.react(at, probe())
                }
                Event::RefuseCheck => {
                    self.refuse_at = None;
                    if let Some(tap) = &self.tap {
                        tap.resend_syn(at.overdue());
                    }
                    match probe() {
                        Syn::Rst => {
                            if let Some(tap) = &self.tap {
                                tap.refused(at.overdue());
                            }
                            Some(Outcome::Failed(code::ECONNREFUSED))
                        }
                        syn => self.react(at, syn),
                    }
                }
                Event::Retransmit => {
                    #[cfg(windows)]
                    if self.dynamic_retransmit
                        && let Some(tap) = &self.tap
                    {
                        tap.resend_syn(at.overdue());
                    }
                    self.retransmits.pop_front();
                    #[cfg(windows)]
                    if self.retransmits.is_empty()
                        && let Some(rto) = self.repeat_rto
                    {
                        let next = at.later(rto);
                        if next.instant() < self.give_up.instant() {
                            self.retransmits.push_back(next);
                            self.dynamic_timer = next.arm();
                            self.dynamic_retransmit = true;
                            self.repeat_rto = Some((rto * 2).min(Duration::from_secs(60)));
                        }
                    }
                    self.react(at, probe())
                }
                Event::GiveUp => Some(Outcome::Failed(self.errno)),
            };
            match outcome {
                Some(outcome) => {
                    if let Some(tap) = self.tap.take() {
                        match outcome {
                            Outcome::Connected => self.accepted = Some(tap),
                            Outcome::Failed(_) => tap.failed(at.overdue()),
                        }
                    }
                    self.settled_at = Some(at);
                    self.disarm();
                    return Err(outcome);
                }
                None => {
                    if let Some(tap) = &self.tap {
                        tap.confirm_plan(at.overdue());
                    }
                }
            }
        }
    }

    /// Captures the handshake of the connect [`poll`](Self::poll) found accepted, at the point of
    /// the plan that answered it, on `conn`'s tap.
    pub(crate) fn established(&mut self, conn: Option<&TcpTap>) {
        self.accepted = None;
        if let Some(tap) = conn {
            let ago = self.settled_at.map_or(Duration::ZERO, |at| at.overdue());
            tap.open(true, ago);
        }
    }

    /// Unregisters every timer the plan armed.
    fn disarm(&mut self) {
        #[cfg(windows)]
        if let Some(key) = self.dynamic_timer.take() {
            snare_interpose::unregister_event_timer(key);
        }
        for key in self.timers.drain(..) {
            snare_interpose::unregister_event_timer(key);
        }
    }
}

impl Drop for ConnectAttempt {
    /// A connect dropped before it settled or established ends its capture as failed and calls
    /// off its timers.
    fn drop(&mut self) {
        if let Some(tap) = self.tap.take().or_else(|| self.accepted.take()) {
            tap.failed(Duration::ZERO);
        }
        self.disarm();
    }
}

/// The per-socket option that shortens the SYN plan: Linux `TCP_SYNCNT` (man 7 tcp), macOS
/// `TCP_CONNECTIONTIMEOUT` (`<netinet/tcp.h>`), Windows `TCP_MAXRT` (`IPPROTO_TCP` option 5,
/// `<ws2ipdef.h>`), all at `IPPROTO_TCP`. Each is answered here and never reaches the OS.
pub(crate) mod sockopt {
    use std::ffi::c_int;
    #[cfg(not(target_os = "linux"))]
    use std::time::Duration;

    use crate::scope::SimShared;
    use crate::sockets::SockRec;

    /// include/uapi/linux/tcp.h `TCP_SYNCNT`.
    #[cfg(target_os = "linux")]
    const NAME: c_int = libc::TCP_SYNCNT;
    /// `<netinet/tcp.h>` `TCP_CONNECTIONTIMEOUT` (xnu bsd/netinet/tcp.h).
    #[cfg(target_os = "macos")]
    const NAME: c_int = 0x20;
    /// `<ws2ipdef.h>` `TCP_MAXRT`.
    #[cfg(windows)]
    const NAME: c_int = 5;

    /// include/net/tcp.h `MAX_TCP_SYNCNT`: the largest `TCP_SYNCNT` (net/ipv4/tcp.c
    /// `tcp_sock_set_syncnt` rejects values outside `1..=127` with `EINVAL`).
    #[cfg(target_os = "linux")]
    const MAX_TCP_SYNCNT: c_int = 127;

    #[cfg(unix)]
    const EINVAL: c_int = libc::EINVAL;
    /// The error a too-short value fails with: `EINVAL` on unix (net/ipv4/tcp.c
    /// `do_tcp_setsockopt`, `optlen < sizeof(int)`; xnu bsd/kern/uipc_socket.c `sooptcopyin`),
    /// `WSAEFAULT` 10014 on
    /// Windows ([Microsoft Learn: setsockopt](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-setsockopt)).
    #[cfg(unix)]
    const SHORT: c_int = EINVAL;
    #[cfg(windows)]
    const SHORT: c_int = 10014;

    /// Sets the option on `rec`; `None` when `name` is another `IPPROTO_TCP` option. A null `val`
    /// fails as a short one does (the kernels answer `EFAULT`). Linux takes a retry count in
    /// `1..=MAX_TCP_SYNCNT`; macOS seconds, 0 for the default and negative refused with `EINVAL`
    /// (xnu bsd/netinet/tcp_usrreq.c `tcp_ctloutput`, which also refuses values above
    /// `UINT32_MAX / TCP_RETRANSHZ`; the sim accepts those); Windows seconds and -1 for never
    /// giving up ([Microsoft Learn: IPPROTO_TCP socket
    /// options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-tcp-socket-options)),
    /// with 0 taken as the default and any negative as -1, which Microsoft does not document.
    ///
    /// # Safety
    /// `val` points to `len` readable bytes.
    pub(crate) unsafe fn set(
        rec: &SockRec,
        name: c_int,
        val: *const u8,
        len: u32,
    ) -> Option<Result<(), c_int>> {
        if name != NAME {
            return None;
        }
        if val.is_null() || (len as usize) < size_of::<c_int>() {
            return Some(Err(SHORT));
        }
        let v = unsafe { val.cast::<c_int>().read_unaligned() };
        let mut state = rec.state();
        #[cfg(target_os = "linux")]
        {
            if !(1..=MAX_TCP_SYNCNT).contains(&v) {
                return Some(Err(EINVAL));
            }
            state.opts.syncnt = Some(v as u8);
        }
        #[cfg(target_os = "macos")]
        {
            if v < 0 {
                return Some(Err(EINVAL));
            }
            state.opts.connect_give_up = (v > 0).then(|| Duration::from_secs(v as u64));
        }
        #[cfg(windows)]
        {
            state.opts.connect_give_up = match v {
                0 => None,
                v if v < 0 => Some(Duration::MAX),
                v => Some(Duration::from_secs(v as u64)),
            };
        }
        Some(Ok(()))
    }

    /// The option's value on `rec`; `None` when `name` is another `IPPROTO_TCP` option. Linux
    /// reports the sim's `tcp_syn_retries` while the socket has none of its own, as
    /// net/ipv4/tcp.c `do_tcp_getsockopt` does; macOS reports 0 for the default, as xnu
    /// `tcp_ctloutput` reads back `t_keepinit / TCP_RETRANSHZ`. Windows also reports 0 for the
    /// default and reads "never" back as `c_int::MAX` seconds, snare's choice.
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    pub(crate) fn get(shared: &SimShared, rec: &SockRec, name: c_int) -> Option<c_int> {
        if name != NAME {
            return None;
        }
        let opts = rec.opts();
        #[cfg(target_os = "linux")]
        let value = opts
            .syncnt
            .unwrap_or_else(|| shared.sys.limits().tcp_syn_retries)
            .into();
        #[cfg(not(target_os = "linux"))]
        let value = opts
            .connect_give_up
            .map_or(0, |d| d.as_secs().min(c_int::MAX as u64) as c_int);
        Some(value)
    }
}

/// Where each address's behaviour is kept, keyed by the address it was set for. Only refusing and
/// delaying entries are stored. A leaf lock: taken only inside [`snare_interpose::real`] with no
/// other sim lock held.
pub(crate) type BehaviorTable = std::sync::Mutex<HashMap<SocketAddr, Behavior>>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The stock Linux plan gives up at 127 s, and past `TCP_RTO_MAX` the timeout stops doubling.
    #[test]
    #[cfg(target_os = "linux")]
    fn linux_plan_doubles_to_127_s() {
        let plan = SynPlan::doubling(LINUX_RTO_INIT, LINUX_RTO_MAX, 6);
        let secs: Vec<u64> = plan.retransmits.iter().map(Duration::as_secs).collect();
        assert_eq!(secs, [1, 3, 7, 15, 31, 63]);
        assert_eq!(plan.give_up, Duration::from_secs(127));
        let capped = SynPlan::doubling(LINUX_RTO_INIT, LINUX_RTO_MAX, 8);
        assert_eq!(capped.give_up, Duration::from_secs(367));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_linear_plan_obeys_both_retry_limits() {
        let plan = linux_plan(6, 4);
        assert_eq!(
            plan.retransmits
                .iter()
                .map(Duration::as_secs)
                .collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 7, 11, 19, 35, 67]
        );
        assert_eq!(plan.give_up, Duration::from_secs(131));
        assert_eq!(
            linux_plan(6, 0),
            SynPlan::doubling(LINUX_RTO_INIT, LINUX_RTO_MAX, 6)
        );
        let short = linux_plan(1, 4);
        assert_eq!(
            short.retransmits,
            [Duration::from_secs(1), Duration::from_secs(2)]
        );
        assert_eq!(short.give_up, Duration::from_secs(3));
        assert_eq!(linux_plan(2, 4).give_up, Duration::from_secs(7));
    }

    /// The stock macOS plan retransmits on `tcp_syn_backoff` and gives up at keepinit.
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_plan_backs_off_to_keepinit() {
        let plan = macos_plan(MACOS_KEEPINIT);
        let secs: Vec<u64> = plan.retransmits.iter().map(Duration::as_secs).collect();
        assert_eq!(secs, [1, 2, 3, 4, 5, 7, 11, 19, 35, 67]);
        assert_eq!(plan.give_up, Duration::from_secs(75));
    }

    /// The stock Windows plan sends two retransmissions and gives up at 21 s.
    #[test]
    #[cfg(windows)]
    fn windows_plan_gives_up_at_21_s() {
        let plan = SynPlan::doubling(
            WINDOWS_INITIAL_RTO,
            Duration::MAX,
            WINDOWS_MAX_SYN_RETRANSMISSIONS,
        );
        assert_eq!(
            plan.retransmits,
            [Duration::from_secs(3), Duration::from_secs(9)]
        );
        assert_eq!(plan.give_up, Duration::from_secs(21));
    }
}
