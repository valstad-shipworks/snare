//! The sim's socket table: one record per open socket of the code under test, on every backend,
//! holding what the socket is bound and connected to, its per-socket options, its pending
//! `SO_ERROR` and its traffic counters. Tests read it through [`socket_table`] and friends.
//!
//! Locking: a [`SockRec`] has two mutexes, its receive-path `probe` and its `state`, and the
//! [`SocketTable`] three (`live`, `by_fd`, `closed`). No code here holds two of them at once:
//! each guard is a statement temporary or dropped before the next is taken. Landing arrived
//! data ([`SockRec::land`], and every reader that lands first) calls into the backend's receive
//! path, which takes the backend's lock and then this record's `state` to admit datagrams, so
//! it must run with neither a backend lock nor the record's `state` held. Table reads run inside
//! [`snare_interpose::real`] so their mutexes reach the OS, not the sim.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::c_int;
use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use crate::limits::{Charge, SockBuf};
use crate::netstats::ProtoStats;
use crate::readiness::Deadline;
use crate::scope::{self, SimShared};

/// One socket of a sim, numbered from 1 in creation order and never reused. Ids are per sim: two
/// sims both start at 1, so an id only means something in the sim that issued it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketId(u64);

impl SocketId {
    /// The raw number, 1 for the sim's first socket.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SocketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "socket#{}", self.0)
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketKind {
    /// A UDP (`SOCK_DGRAM`) socket, bound or not.
    Udp,
    /// A TCP socket that is not listening: unconnected, connected or accepted.
    TcpStream,
    /// A TCP socket after `listen`.
    TcpListener,
    /// A raw link-layer endpoint (`AF_PACKET`, or a `/dev/bpf*` device on macOS).
    Packet,
    /// An `AF_NETLINK` socket (Linux).
    Netlink,
    /// One end of an `AF_UNIX` `socketpair`.
    Unix,
}

/// A multicast group a socket joined: the group, the local interface address the join named (if
/// any) and the interface index (0 when the join left it to the routing table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub group: IpAddr,
    pub interface_addr: Option<IpAddr>,
    pub ifindex: u32,
}

/// A snapshot of one socket. `queued`/`delivered` count datagrams for UDP and written chunks for
/// TCP; `sent` counts successful sends. Times are on the sim's timeline (see
/// [`Sim::time_value`](crate::Sim::time_value)).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEntry {
    pub id: SocketId,
    pub kind: SocketKind,
    /// The bound address, once bound (explicitly or by a connect or send).
    pub local: Option<SocketAddr>,
    /// The connected peer, for a connected or accepted socket.
    pub peer: Option<SocketAddr>,
    /// The listener an accepted stream came from.
    pub listener: Option<SocketId>,
    /// The multicast groups joined and not left, in join order.
    pub memberships: Vec<Membership>,
    /// Datagrams (UDP) or chunks (TCP) arrived and not yet read.
    pub queued: usize,
    /// Bytes arrived and not yet read.
    pub queued_bytes: usize,
    /// Datagrams or chunks taken into the socket since it opened.
    pub delivered: u64,
    /// Bytes taken into the socket since it opened.
    pub delivered_bytes: u64,
    /// Successful sends since it opened.
    pub sent: u64,
    /// The pending socket error or receive status. Windows ICMP receive status is not returned
    /// or cleared by `getsockopt(SO_ERROR)`; other pending errors are.
    pub pending_error: Option<i32>,
    /// When the socket was created, on the sim's timeline.
    pub created_at: Duration,
    /// When its last descriptor closed; `None` while open.
    pub closed_at: Option<Duration>,
    /// The interface the socket's latest datagram or connection went out or came in on.
    pub interface: Option<String>,
    /// The interface the socket's latest datagram or connection left by.
    pub last_tx_nic: Option<String>,
    /// The interface the socket's latest datagram or connection arrived on.
    pub last_rx_nic: Option<String>,
    /// The interface `SO_BINDTODEVICE`/`IP_BOUND_IF`/`IP_UNICAST_IF` bound it to.
    pub bound_device: Option<String>,
    /// The interface `IP_MULTICAST_IF`/`IPV6_MULTICAST_IF` chose for its multicast sends.
    pub multicast_if: Option<String>,
    /// `SO_RCVBUF` and `SO_SNDBUF` as getsockopt reports them.
    pub rcvbuf: u32,
    /// See `rcvbuf`.
    pub sndbuf: u32,
    /// Receive-buffer memory charged to queued data and Linux error reports: `sk_rmem_alloc`
    /// on Linux, `sb_mbcnt` on macOS, payload bytes on Windows.
    pub rmem_alloc: usize,
    /// Datagrams dropped on arrival because the receive buffer was full.
    pub overflowed: u64,
    /// Datagrams to this socket the link lost on the way (link policy loss, oversize).
    pub wire_lost: u64,
    /// The kernel's drop counter (`sk_drops`): overflows plus injected drops, never wire loss.
    pub drops: u32,
    /// The socket options and ioctl requests the code under test used on this socket that the
    /// sim does not model, in first-use order, each once. Accepted without effect (an option's
    /// value is still read back on Windows), or refused under `SimBuilder::strict_sockopts`; on
    /// Windows a `WSAIoctl` code the sim cannot carry out is always refused.
    pub unmodelled_options: Vec<UnmodelledOption>,
}

/// A socket option or ioctl request the code under test used on a sim socket that the sim does
/// not model. Numbers are the host's own (`<sys/socket.h>`, `<winsock2.h>`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnmodelledOption {
    /// `setsockopt(level, name)`.
    Set { level: i32, name: i32 },
    /// `getsockopt(level, name)`.
    Get { level: i32, name: i32 },
    /// `ioctl` (`ioctlsocket` or `WSAIoctl` on Windows) with this request code.
    Ioctl { request: u64 },
}

impl fmt::Display for UnmodelledOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnmodelledOption::Set { level, name } => {
                write!(f, "setsockopt(level {level}, option {name})")
            }
            UnmodelledOption::Get { level, name } => {
                write!(f, "getsockopt(level {level}, option {name})")
            }
            UnmodelledOption::Ioctl { request } => write!(f, "ioctl(request {request:#x})"),
        }
    }
}

/// A receive path that can land what has arrived by now and report what waits to be read.
pub(crate) trait RxProbe: Send + Sync {
    fn pending_time(&self) -> bool {
        false
    }
    /// Moves what has arrived by now into the receive buffer. Takes the backend's lock and may
    /// take the record's `state` to admit datagrams.
    fn land(&self);
    /// Messages and bytes waiting to be read.
    fn queued(&self) -> (usize, usize);
    /// The length of the next message a read returns, for a message-oriented socket.
    fn next_len(&self) -> Option<usize> {
        None
    }
    /// Messages landed in the receive buffer so far: each one a wake of the socket's readers,
    /// a new edge for edge-triggered readiness.
    #[cfg_attr(windows, allow(dead_code))]
    fn landed(&self) -> u64 {
        0
    }
}

/// The per-socket options the sim answers itself rather than passing to the OS.
#[derive(Clone, Copy, Default)]
pub(crate) struct SockOpts {
    /// `SO_RCVTIMEO`; `None` blocks forever (man 7 socket).
    pub(crate) rcvtimeo: Option<Duration>,
    /// `SO_SNDTIMEO`; `None` blocks forever.
    pub(crate) sndtimeo: Option<Duration>,
    /// `SO_LINGER` when on, with its timeout (man 7 socket); `Some(ZERO)` makes close reset the
    /// connection (Linux net/ipv4/tcp.c `__tcp_close`; xnu bsd/netinet/tcp_usrreq.c
    /// `tcp_disconnect` calls `tcp_drop` for a zero `so_linger`).
    pub(crate) linger: Option<Duration>,
    /// `SO_REUSEADDR`.
    pub(crate) reuseaddr: bool,
    /// Linux `SO_PRIORITY`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) priority: c_int,
    /// Linux `SO_MARK`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) mark: u32,
    /// Linux `TCP_SYNCNT`; `None` uses `tcp_syn_retries`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) syncnt: Option<u8>,
    /// macOS `TCP_CONNECTIONTIMEOUT`, Windows `TCP_MAXRT`; `None` uses the stock plan,
    /// [`Duration::MAX`] never gives up (Windows `TCP_MAXRT` -1).
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    pub(crate) connect_give_up: Option<Duration>,
}

/// Where a socket's pending error came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ErrorOrigin {
    /// A connect that failed; recorded when it settled.
    Connect,
    /// [`raise_socket_error`](crate::raise_socket_error).
    Raised,
    /// An ICMP port unreachable from `from`.
    Icmp { from: SocketAddr },
}

/// A pending socket error or Windows ICMP receive indication.
struct PendingError {
    #[cfg(windows)]
    order: ErrorOrder,
    #[cfg(unix)]
    wake_counted: bool,
    errno: c_int,
    /// When it becomes readable (an ICMP error still on its way back); `None` at once.
    visible: Option<Deadline>,
    origin: ErrorOrigin,
}

/// Which call takes a pending error.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Taker {
    Send,
    Recv,
    /// A receive with `MSG_PEEK`.
    Peek,
    /// `getsockopt(SO_ERROR)`.
    SoError,
}

impl Taker {
    /// The call name recorded with a raised error's fault.
    fn call(self) -> &'static str {
        match self {
            Taker::Send => "send",
            Taker::Recv | Taker::Peek => "recv",
            Taker::SoError => "getsockopt",
        }
    }
}

/// How a datagram socket takes ICMP errors: Linux `IP_RECVERR`/`IPV6_RECVERR`, and Windows
/// `SIO_UDP_CONNRESET` (on unless turned off).
#[derive(Clone, Copy)]
pub(crate) struct DgramOpts {
    /// Linux `IP_RECVERR`/`IPV6_RECVERR`, off by default (man 2const `IP_RECVERR`,
    /// `IPV6_RECVERR`).
    pub(crate) recverr: bool,
    /// Windows `SIO_UDP_CONNRESET`: whether port unreachables are reported ([Microsoft Learn:
    /// Winsock IOCTLs](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls)).
    /// That page gives no default; on by default here, since [Microsoft Learn:
    /// recvfrom](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom)
    /// documents `WSAECONNRESET` for UDP without the option.
    pub(crate) connreset: bool,
    /// Linux `IP_MULTICAST_ALL`: an IPv4 multicast datagram reaches this socket for any group
    /// some socket of the host joined, not only its own. On by default (net/ipv4/af_inet.c
    /// `inet_create` sets `MC_ALL`; man 7 ip, `IP_MULTICAST_ALL`).
    pub(crate) mc_all: bool,
    /// Linux `IPV6_MULTICAST_ALL`, the same for IPv6 groups, also on by default
    /// (net/ipv6/af_inet6.c `inet6_create` sets `MC6_ALL`).
    pub(crate) mc6_all: bool,
    /// Windows `SIO_CPU_AFFINITY`: the processor whose receive queue the socket is tied to.
    #[cfg(windows)]
    pub(crate) cpu_affinity: Option<u16>,
}

impl Default for DgramOpts {
    fn default() -> Self {
        DgramOpts {
            recverr: false,
            connreset: true,
            mc_all: true,
            mc6_all: true,
            #[cfg(windows)]
            cpu_affinity: None,
        }
    }
}

/// The don't-fragment options of an IP socket, read by `netif::frag` (Windows: `win_sockopt`)
/// when a datagram leaves.
#[derive(Clone, Copy)]
pub(crate) struct FragOpts {
    /// Linux `IP_MTU_DISCOVER`: one of the `IP_PMTUDISC_*` modes, 0 to 5. `IP_PMTUDISC_WANT` (1)
    /// by default, as net/ipv4/af_inet.c `inet_create` sets it unless the
    /// `ip_no_pmtu_disc` sysctl is on (man 7 ip, `IP_MTU_DISCOVER`). Windows `IP_MTU_DISCOVER`, a
    /// `PMTUD_STATE` 0 to 3, `IP_PMTUDISC_NOT_SET` (0) by default
    /// ([Microsoft Learn: IPPROTO_IP socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options)).
    pub(crate) pmtudisc: u8,
    /// Linux `IPV6_MTU_DISCOVER`, the same modes for IPv6, also `IPV6_PMTUDISC_WANT` by default
    /// (man 7 ipv6, `IPV6_MTU_DISCOVER`); Windows `IPV6_MTU_DISCOVER`, also `NOT_SET` by default.
    pub(crate) pmtudisc6: u8,
    /// macOS `IP_DONTFRAG`, off by default (XNU bsd/netinet/in.h: "don't fragment packet");
    /// Windows `IP_DONTFRAGMENT`, also off.
    pub(crate) dontfrag: bool,
    /// `IPV6_DONTFRAG` (RFC 3542 §11.2), off by default on Linux, macOS and Windows.
    pub(crate) dontfrag6: bool,
}

impl Default for FragOpts {
    fn default() -> Self {
        let mode = if cfg!(windows) { 0 } else { 1 };
        FragOpts {
            pmtudisc: mode,
            pmtudisc6: mode,
            dontfrag: false,
            dontfrag6: false,
        }
    }
}

/// An ICMP error queued for `recvmsg(MSG_ERRQUEUE)` (Linux `IP_RECVERR`).
#[derive(Clone)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct IcmpReport {
    #[cfg(unix)]
    wake_counted: bool,
    /// `sock_extended_err.ee_errno` (include/uapi/linux/errqueue.h).
    pub(crate) errno: c_int,
    /// The address the ICMP error came from (`SO_EE_OFFENDER`).
    pub(crate) offender: SocketAddr,
    /// When it becomes readable; `None` at once.
    arrives: Option<Deadline>,
    pub(crate) payload: Vec<u8>,
    #[cfg(target_os = "linux")]
    order: ErrorOrder,
    #[cfg(target_os = "linux")]
    charge: usize,
    #[cfg(target_os = "linux")]
    charged: bool,
}

#[cfg(any(target_os = "linux", windows))]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ErrorOrder(Duration, u64);

#[cfg(any(target_os = "linux", windows))]
impl ErrorOrder {
    pub(crate) fn at(&self) -> Duration {
        self.0
    }

    pub(crate) fn new(arrives: Option<Deadline>) -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let arrives = arrives.unwrap_or_else(|| Deadline::after(Duration::ZERO));
        Self(arrives.at(), SEQUENCE.fetch_add(1, Ordering::Relaxed))
    }
}

#[cfg(target_os = "linux")]
pub(crate) enum ErrorReport {
    Icmp(IcmpReport),
    Tx(crate::tstamp::TxReport),
}

/// The mutable half of a [`SockRec`], behind its `state` lock.
pub(crate) struct SockState {
    pub(crate) kind: SocketKind,
    /// The descriptors open on this file description; it closes when the last goes.
    fds: BTreeSet<c_int>,
    pub(crate) local: Option<SocketAddr>,
    /// Bound at a station address: across a link from the host, so its datagrams are not the
    /// host's to count.
    station: bool,
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) tcp_established: bool,
    #[cfg(unix)]
    pub(crate) connect_ack: bool,
    #[cfg(unix)]
    pub(crate) tcp_failed: bool,
    /// The listener an accepted stream came from.
    listener: Option<SocketId>,
    memberships: Vec<Membership>,
    pub(crate) opts: SockOpts,
    pending_error: Option<PendingError>,
    #[cfg(windows)]
    icmp_errors: VecDeque<PendingError>,
    #[cfg(unix)]
    error_wakes: u64,
    pub(crate) dgram: DgramOpts,
    /// `IP_MTU_DISCOVER`, `IP_DONTFRAG` and their IPv6 counterparts.
    pub(crate) frag: FragOpts,
    /// Linux `MSG_ERRQUEUE` reports, oldest first.
    errq: VecDeque<IcmpReport>,
    delivered: u64,
    delivered_bytes: u64,
    sent: u64,
    closed_at: Option<Duration>,
    /// The interface (index and name) the socket is bound to.
    pub(crate) device: Option<(u32, String)>,
    /// The interface (index and name) `IP_MULTICAST_IF`/`IPV6_MULTICAST_IF` chose.
    pub(crate) mcast_if: Option<(u32, String)>,
    /// The interface the latest traffic crossed.
    last_nic: Option<String>,
    /// The interface the latest traffic left by.
    last_tx_nic: Option<String>,
    /// The interface the latest traffic arrived on.
    last_rx_nic: Option<String>,
    pub(crate) buf: SockBuf,
    /// Receive and transmit timestamping.
    #[cfg(unix)]
    pub(crate) ts: crate::tstamp::TsState,
    /// The socket's family and Winsock timestamping.
    #[cfg(windows)]
    pub(crate) win: crate::win_sockopt::WinSock,
    /// What [`SocketEntry::unmodelled_options`] lists.
    unmodelled: Vec<UnmodelledOption>,
    /// The values of options set that the sim ignores as harmless, by `(level, name)`, so a
    /// `getsockopt` reads back what was set. On Windows unmodelled options are kept here too.
    ignored: HashMap<(c_int, c_int), Vec<u8>>,
}

#[cfg(target_os = "linux")]
impl SockState {
    fn land_errors(&mut self, until: Option<Duration>) {
        loop {
            let icmp = self
                .errq
                .iter()
                .enumerate()
                .filter(|(_, r)| {
                    !r.charged
                        && r.arrives.is_none_or(|d| d.passed())
                        && until.is_none_or(|until| r.order.at() <= until)
                })
                .min_by_key(|(_, r)| r.order)
                .map(|(i, r)| (i, r.order, r.charge));
            let tx = crate::tstamp::pending_tx_report(&self.ts, until);
            if let Some((i, order, charge)) = tx
                && icmp.is_none_or(|(_, icmp, _)| order < icmp)
            {
                if self.buf.admit_error(charge) {
                    self.ts.admit_tx_report(i);
                } else {
                    self.ts.pop_tx_report(i);
                }
            } else if let Some((i, _, charge)) = icmp {
                if self.buf.admit_error(charge) {
                    self.errq[i].charged = true;
                } else {
                    self.errq.remove(i);
                }
            } else {
                break;
            }
        }
    }
}

/// The record of one open file description. Every fd of it (`dup`, `F_DUPFD`,
/// `WSADuplicateSocketW`) shares the one record; `accept` makes a new one.
pub(crate) struct SockRec {
    pub(crate) id: SocketId,
    created_at: Duration,
    /// The backend's receive path, once it has one. Weak so the record, which outlives the
    /// backend's socket in the closed history, does not keep it alive.
    probe: Mutex<Option<Weak<dyn RxProbe>>>,
    state: Mutex<SockState>,
    /// The sim's protocol counters, which this socket's traffic drives.
    stats: Arc<ProtoStats>,
    /// Error reports wait for earlier datagrams still pending in the backend's arrival queue.
    #[cfg(target_os = "linux")]
    next_data_arrival: AtomicU64,
}

impl SockRec {
    /// Locks the socket's state and admits arrived Linux error reports. Do not land arrived
    /// data (see [`land`](Self::land)) while the guard is held: landing takes this lock again.
    pub(crate) fn state(&self) -> MutexGuard<'_, SockState> {
        let state = self.state.lock().unwrap();
        #[cfg(target_os = "linux")]
        {
            let mut state = state;
            let next_data = self.next_data_arrival.load(Ordering::Acquire);
            if next_data == u64::MAX {
                state.land_errors(None);
            } else if next_data != 0 {
                state.land_errors(Some(Duration::from_nanos(next_data - 1)));
            }
            state
        }
        #[cfg(not(target_os = "linux"))]
        state
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn set_data_arrival(&self, arrives: Option<Deadline>) {
        let at = arrives.map_or(u64::MAX, |d| {
            d.at().as_nanos().min(u128::from(u64::MAX - 1)) as u64
        });
        self.next_data_arrival.store(at, Ordering::Release);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn note_data_arrival(&self, arrives: Deadline) {
        let at = arrives.at().as_nanos().min(u128::from(u64::MAX - 1)) as u64;
        self.next_data_arrival.fetch_min(at, Ordering::AcqRel);
    }

    /// A copy of the socket's options.
    pub(crate) fn opts(&self) -> SockOpts {
        self.state().opts
    }

    /// Changes the kind, as `listen` turns a stream into a listener.
    pub(crate) fn set_kind(&self, kind: SocketKind) {
        self.state().kind = kind;
    }

    /// Records the bound address, and whether it is a station address of the calling thread's sim.
    pub(crate) fn set_local(&self, local: SocketAddr) {
        let station = snare_interpose::real(|| {
            crate::scope::try_here().is_some_and(|shared| shared.topo().is_station_ip(local.ip()))
        });
        let mut state = self.state();
        state.local = Some(local);
        state.station = station;
    }

    /// Records the connected peer; `None` dissolves a datagram socket's association.
    pub(crate) fn set_peer(&self, peer: Option<SocketAddr>) {
        self.state().peer = peer;
    }

    /// Records both ends of a connection at once.
    pub(crate) fn set_ends(&self, local: SocketAddr, peer: SocketAddr) {
        let mut state = self.state();
        state.local = Some(local);
        state.peer = Some(peer);
        state.tcp_established = true;
    }

    /// Records the listener an accepted stream came from.
    pub(crate) fn set_listener(&self, listener: SocketId) {
        self.state().listener = Some(listener);
    }

    /// Records a multicast join; a membership already held is not listed twice.
    #[cfg(windows)]
    pub(crate) fn join(&self, membership: Membership) {
        let mut state = self.state();
        if !state.memberships.contains(&membership) {
            state.memberships.push(membership);
        }
    }

    #[cfg(unix)]
    pub(crate) fn change_membership(
        &self,
        membership: Membership,
        join: bool,
    ) -> Result<(), c_int> {
        let mut state = self.state();
        let present = state
            .memberships
            .iter()
            .position(|held| *held == membership);
        match (join, present) {
            (true, Some(_)) => Err(libc::EADDRINUSE),
            (true, None) => {
                state.memberships.push(membership);
                Ok(())
            }
            (false, Some(index)) => {
                state.memberships.remove(index);
                Ok(())
            }
            (false, None) => Err(libc::EADDRNOTAVAIL),
        }
    }

    /// Takes `listener`'s buffer sizes, as a stream accepted from it does: Linux
    /// `sk_clone_lock` (net/core/sock.c) copies the listener's `sk_rcvbuf`/`sk_sndbuf` and their
    /// lock flags; XNU `sonewconn` (bsd/kern/uipc_socket2.c) reserves the listener's `sb_hiwat`;
    /// Windows gives an accepted socket "the same properties as socket s" ([Microsoft Learn:
    /// accept](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept)).
    pub(crate) fn inherit_buffers(&self, listener: &SockRec) {
        let from = listener.state().buf;
        self.state().buf.inherit(&from);
    }

    /// Whether the socket is a member of multicast `group`.
    pub(crate) fn joined(&self, group: IpAddr) -> bool {
        self.state().memberships.iter().any(|m| m.group == group)
    }

    /// Whether this socket, bound at `local`, takes a datagram for multicast `group`;
    /// `host_joined` says whether any socket of the host is a member of it.
    ///
    /// - Linux delivers to a socket bound to the wildcard or to the group itself
    ///   (net/ipv4/udp.c `__udp_is_mcast_sock` skips a socket whose bound address is another),
    ///   that joined the group, or that has `IP_MULTICAST_ALL`/`IPV6_MULTICAST_ALL` on while the
    ///   host joined it (net/ipv4/igmp.c `ip_mc_sf_allow` returns the socket's `MC_ALL` bit when
    ///   it has no membership for the group; net/ipv6/mcast.c `inet6_mc_check` likewise).
    /// - macOS delivers to a socket bound to the wildcard or the group that joined it itself
    ///   (bsd/netinet/udp_usrreq.c `udp_input`: a bound address other than the destination is
    ///   skipped, and `imo_multi_filter` must find the socket's own membership).
    /// - Windows delivers only to a socket that joined the group, bound to the wildcard or to an
    ///   address of the host.
    ///
    /// All three are measured by tests/multicast_os_truth.rs. Which interface a membership
    /// names is not checked against the one the datagram arrived on, and macOS's delivery to
    /// only the first matching socket of a port shared without `SO_REUSEADDR`/`SO_REUSEPORT`
    /// is not modelled.
    pub(crate) fn takes_group(&self, local: SocketAddr, group: IpAddr, host_joined: bool) -> bool {
        if cfg!(unix) && !(local.ip().is_unspecified() || local.ip() == group) {
            return false;
        }
        let state = self.state();
        if state.memberships.iter().any(|m| m.group == group) {
            return true;
        }
        let all = if group.is_ipv6() {
            state.dgram.mc6_all
        } else {
            state.dgram.mc_all
        };
        cfg!(target_os = "linux") && all && host_joined
    }

    /// Attaches the backend's receive path.
    pub(crate) fn set_probe(&self, probe: Weak<dyn RxProbe>) {
        *self.probe.lock().unwrap() = Some(probe);
    }

    /// Counts a successful send.
    pub(crate) fn count_sent(&self) {
        self.state().sent += 1;
    }

    /// Counts a datagram sent to `dest`, on the socket and, when the host sent it rather than a
    /// station across a link, in the host's UDP counters.
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn count_udp_sent(&self, dest: SocketAddr, sender: &crate::netif::Sender) {
        self.count_sent();
        if let crate::netif::Sender::Host(_) = sender {
            self.stats
                .udp(dest.ip())
                .out
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(unix)]
    pub(crate) fn finish_udp_send(&self, dest: SocketAddr, sender: &crate::netif::Sender) -> bool {
        let mut state = self.state();
        if let Some(nic) = sender.egress_name() {
            Self::update_nic(&mut state.last_nic, nic);
            Self::update_nic(&mut state.last_tx_nic, nic);
            self.stats
                .udp(dest.ip())
                .out
                .fetch_add(1, Ordering::Relaxed);
        }
        state.sent += 1;
        Self::error_reports_pending(&state)
    }

    /// What the socket contributes to a route lookup from `local`.
    pub(crate) fn view(&self, local: Option<SocketAddr>) -> crate::netif::SockView {
        let state = self.state();
        crate::netif::SockView {
            local,
            device: state.device.as_ref().map(|(i, _)| *i),
            mcast_if: state.mcast_if.as_ref().map(|(i, _)| *i),
        }
    }

    /// Notes the interface the socket's latest traffic left by.
    pub(crate) fn note_tx_nic(&self, nic: Option<&str>) {
        if let Some(nic) = nic {
            let mut state = self.state();
            Self::update_nic(&mut state.last_nic, nic);
            Self::update_nic(&mut state.last_tx_nic, nic);
        }
    }

    /// Notes the interface the socket's latest traffic arrived on.
    pub(crate) fn note_rx_nic(&self, nic: Option<&str>) {
        if let Some(nic) = nic {
            let mut state = self.state();
            Self::update_nic(&mut state.last_nic, nic);
            Self::update_nic(&mut state.last_rx_nic, nic);
        }
    }

    fn update_nic(slot: &mut Option<String>, nic: &str) {
        match slot {
            Some(stored) if stored != nic => {
                stored.clear();
                stored.push_str(nic);
            }
            Some(_) => {}
            None => *slot = Some(nic.to_owned()),
        }
    }

    /// Notes a connection that crosses `nic` both ways.
    pub(crate) fn note_conn_nic(&self, nic: Option<&str>) {
        self.note_tx_nic(nic);
        self.note_rx_nic(nic);
    }

    /// Counts a message or chunk of `bytes` taken into the socket, for paths with no buffer
    /// accounting (see [`admit`](Self::admit) for datagrams).
    pub(crate) fn count_delivered(&self, bytes: usize) {
        let mut state = self.state();
        state.delivered += 1;
        state.delivered_bytes += bytes as u64;
    }

    /// Takes an arrived `len`-byte datagram, which crossed a path of MTU `mtu`, into the receive
    /// buffer if it fits, counting it as delivered; else counts the overflow. Returns its charge
    /// and the drop count to report with it.
    /// A UDP socket's datagram from `src` also counts in the host's UDP counters: admitted
    /// (`received`) or dropped for a full buffer (`rcvbuf_errors`).
    pub(crate) fn admit(
        &self,
        len: usize,
        src: SocketAddr,
        mtu: Option<u32>,
        arrives: Option<Deadline>,
    ) -> Option<(Charge, u32)> {
        let mut state = self.state.lock().unwrap();
        #[cfg(target_os = "linux")]
        state.land_errors(arrives.map(|d| d.at()));
        #[cfg(not(target_os = "linux"))]
        let _ = arrives;
        if state.kind == SocketKind::Udp && state.peer.is_some_and(|peer| peer != src) {
            return None;
        }
        let admitted = state.buf.admit(len, src.is_ipv6(), mtu);
        if admitted.is_some() {
            state.delivered += 1;
            state.delivered_bytes += len as u64;
        }
        if state.kind == SocketKind::Udp && !state.station {
            let udp = self.stats.udp(src.ip());
            match admitted {
                Some(_) => udp.received.fetch_add(1, Ordering::Relaxed),
                None => udp.rcvbuf_errors.fetch_add(1, Ordering::Relaxed),
            };
        }
        admitted
    }

    /// Returns the buffer charge of a `len`-byte datagram from `src` that was read, counting it
    /// as read in the host's UDP counters.
    pub(crate) fn consumed(&self, len: usize, charge: Charge, src: SocketAddr) {
        let mut state = self.state();
        state.buf.consumed(len, charge);
        if state.kind == SocketKind::Udp && !state.station {
            self.stats
                .udp(src.ip())
                .read
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Counts a datagram to this socket that the link lost.
    pub(crate) fn count_wire_lost(&self) {
        self.state().buf.wire_lost += 1;
    }

    /// The receive path, with what has arrived by now landed; `None` before the backend attached
    /// one or after it went away. Call with no backend lock and no `state` guard held.
    fn probe(&self) -> Option<Arc<dyn RxProbe>> {
        let probe = self.probe.lock().unwrap().as_ref().and_then(Weak::upgrade);
        if let Some(probe) = &probe {
            probe.land();
        }
        probe
    }

    /// For a UDP or netlink socket another backend serves (a `SimHost`'s), whose readiness the
    /// fabric's `poll` and epoll read through its record: whether a datagram is waiting, and how
    /// many have landed so far ([`RxProbe::landed`]). `None` for a socket of another kind or
    /// without a receive probe. Call with no backend lock held.
    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) fn dgram_readiness(&self) -> Option<(bool, u64)> {
        if !matches!(
            self.state.lock().unwrap().kind,
            SocketKind::Udp | SocketKind::Netlink
        ) {
            return None;
        }
        let probe = self.probe()?;
        Some((probe.queued().0 > 0, probe.landed()))
    }

    /// Lands what has arrived by now. Call with no backend lock held.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn land(&self) {
        self.probe();
    }

    /// What `FIONREAD` reports: for a datagram socket the next datagram's payload on Linux (man
    /// 7 udp, `FIONREAD`), the buffer's byte count `sb_cc` on macOS (xnu bsd/kern/sys_socket.c
    /// `soioctl`, `FIONREAD`), and the queued payload capped at `SO_RCVBUF` on Windows (all bytes
    /// available, not the first datagram: [Microsoft Learn: Winsock
    /// IOCTLs](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls),
    /// `FIONREAD`; the cap is pinned by tests/socket_limits_win.rs `fionread_capped`); for a
    /// stream the bytes unread (man 7 tcp, `SIOCINQ`). The Windows cap is snare's model, checked
    /// against no real Windows. Call with no backend lock held.
    pub(crate) fn fionread(&self) -> c_int {
        let Some(probe) = self.probe() else {
            return 0;
        };
        let kind = self.state().kind;
        let n = if kind != SocketKind::Udp {
            probe.queued().1
        } else if cfg!(target_os = "linux") {
            probe.next_len().unwrap_or(0)
        } else if cfg!(target_os = "macos") {
            self.state().buf.rx.cc
        } else {
            let buf = self.state().buf;
            buf.rx.queued_bytes.min(buf.rcvbuf.max(0) as usize)
        };
        n.min(c_int::MAX as usize) as c_int
    }

    /// macOS `SO_NREAD`: the next datagram's payload, or a stream's unread bytes (xnu
    /// `<sys/socket.h>`, "get 1st-packet byte count"; bsd/kern/uipc_socket.c `sogetoptlock`).
    /// Call with no backend lock held.
    #[cfg(target_os = "macos")]
    pub(crate) fn nread(&self) -> c_int {
        let Some(probe) = self.probe() else {
            return 0;
        };
        let udp = self.state().kind == SocketKind::Udp;
        let n = if udp {
            probe.next_len().unwrap_or(0)
        } else {
            probe.queued().1
        };
        n.min(c_int::MAX as usize) as c_int
    }

    /// Makes `errno` the socket's pending error, readable once `visible` has passed (at once when
    /// `None`).
    pub(crate) fn set_pending_error(&self, errno: c_int, visible: Option<Deadline>) {
        self.raise_error(errno, ErrorOrigin::Connect, visible);
    }

    pub(crate) fn wake_key(&self) -> crate::readiness::WakeKey {
        crate::readiness::WakeKey::Socket(self.id.get())
    }

    #[cfg(windows)]
    pub(crate) fn has_error_reports(&self) -> bool {
        Self::error_reports_pending(&self.state())
    }

    fn error_reports_pending(state: &SockState) -> bool {
        #[cfg(unix)]
        let stamps = state.ts.has_tx_reports();
        #[cfg(windows)]
        let stamps = false;
        #[cfg(windows)]
        let indications = !state.icmp_errors.is_empty();
        #[cfg(unix)]
        let indications = false;
        state.pending_error.is_some() || !state.errq.is_empty() || stamps || indications
    }

    pub(crate) fn pending_time(&self) -> bool {
        let pending = {
            let state = self.state();
            #[cfg(unix)]
            let stamps = state.ts.pending_time();
            #[cfg(windows)]
            let stamps = state
                .icmp_errors
                .iter()
                .any(|error| error.visible.is_some());
            state
                .pending_error
                .as_ref()
                .is_some_and(|e| e.visible.is_some())
                || state.errq.iter().any(|e| e.arrives.is_some())
                || stamps
        };
        let probe = self.probe.lock().unwrap().as_ref().and_then(Weak::upgrade);
        pending || probe.is_some_and(|probe| probe.pending_time())
    }

    /// Makes a socket error pending or queues a Windows receive indication.
    pub(crate) fn raise_error(&self, errno: c_int, origin: ErrorOrigin, visible: Option<Deadline>) {
        let mut state = self.state();
        let error = PendingError {
            #[cfg(windows)]
            order: ErrorOrder::new(visible),
            #[cfg(unix)]
            wake_counted: false,
            errno,
            visible,
            origin,
        };
        #[cfg(windows)]
        if matches!(origin, ErrorOrigin::Icmp { .. }) {
            let position = state
                .icmp_errors
                .partition_point(|pending| pending.order < error.order);
            state.icmp_errors.insert(position, error);
            return;
        }
        #[cfg(unix)]
        if matches!(origin, ErrorOrigin::Icmp { .. })
            && state
                .pending_error
                .as_ref()
                .is_some_and(|pending| matches!(pending.origin, ErrorOrigin::Icmp { .. }))
        {
            return;
        }
        state.pending_error = Some(error);
    }

    /// Reports the error visible to `taker`, recording the fault it reports.
    pub(crate) fn take_error_as(&self, shared: &SimShared, taker: Taker) -> Option<c_int> {
        self.take_error_when(shared, taker, |_| true)
    }

    #[cfg(windows)]
    pub(crate) fn take_error_before(
        &self,
        shared: &SimShared,
        taker: Taker,
        next: Option<ErrorOrder>,
        cutoff: Duration,
    ) -> Option<c_int> {
        self.take_error_when(shared, taker, |pending| {
            !matches!(pending.origin, ErrorOrigin::Icmp { .. })
                || (pending.order.at() <= cutoff && next.is_none_or(|data| pending.order < data))
        })
    }

    fn take_error_when(
        &self,
        shared: &SimShared,
        taker: Taker,
        eligible: impl FnOnce(&PendingError) -> bool,
    ) -> Option<c_int> {
        let mut state = self.state();
        #[cfg(unix)]
        Self::count_error_wakes(&mut state);
        #[cfg(windows)]
        let indication = state.pending_error.is_none();
        #[cfg(windows)]
        let pending = state
            .pending_error
            .as_ref()
            .or_else(|| state.icmp_errors.front())?;
        #[cfg(unix)]
        let pending = state.pending_error.as_ref()?;
        if !eligible(pending) || pending.visible.is_some_and(|d| !d.passed()) {
            return None;
        }
        let (errno, origin) = (pending.errno, pending.origin);
        if cfg!(windows)
            && matches!(taker, Taker::Send | Taker::SoError)
            && matches!(origin, ErrorOrigin::Icmp { .. })
        {
            return None;
        }
        #[cfg(windows)]
        if indication {
            if taker != Taker::Peek {
                state.icmp_errors.pop_front();
            }
        } else {
            state.pending_error = None;
        }
        #[cfg(unix)]
        if !(taker == Taker::Peek && cfg!(target_os = "macos")) {
            state.pending_error = None;
        }
        let local = state.local;
        drop(state);
        let fault = match origin {
            ErrorOrigin::Connect => return Some(errno),
            ErrorOrigin::Raised => crate::events::Fault::Error {
                errno,
                call: taker.call(),
            },
            ErrorOrigin::Icmp { from } => crate::events::Fault::IcmpPortUnreachable { from },
        };
        shared.record(crate::events::RecordedEvent::Fault { addr: local, fault });
        Some(errno)
    }

    /// Queues an ICMP error for `recvmsg(MSG_ERRQUEUE)`, readable once `arrives` has passed.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn queue_icmp_report(
        &self,
        errno: c_int,
        offender: SocketAddr,
        arrives: Option<Deadline>,
        payload: &[u8],
    ) {
        let mut state = self.state();
        #[cfg(target_os = "linux")]
        let payload = &payload[..payload
            .len()
            .min(if offender.is_ipv6() { 1184 } else { 520 })];
        #[cfg(target_os = "linux")]
        let charge = state.buf.error_charge(
            payload.len() + if offender.is_ipv6() { 48 } else { 28 },
            offender.is_ipv6(),
        );
        state.errq.push_back(IcmpReport {
            #[cfg(unix)]
            wake_counted: false,
            errno,
            offender,
            arrives,
            payload: payload.to_vec(),
            #[cfg(target_os = "linux")]
            order: ErrorOrder::new(arrives),
            #[cfg(target_os = "linux")]
            charge,
            #[cfg(target_os = "linux")]
            charged: false,
        });
    }

    /// The earliest arrived ICMP or transmit timestamp report for `MSG_ERRQUEUE`. An ICMP
    /// report also clears its pending socket error.
    #[cfg(target_os = "linux")]
    pub(crate) fn pop_error_report(&self) -> Option<ErrorReport> {
        let mut state = self.state();
        Self::count_error_wakes(&mut state);
        let icmp = state
            .errq
            .iter()
            .enumerate()
            .filter(|(_, report)| report.charged)
            .min_by_key(|(_, report)| report.order)
            .map(|(i, report)| (i, report.order));
        let tx = crate::tstamp::next_tx_report(&state.ts);
        if tx.is_some_and(|(_, order)| icmp.is_none_or(|(_, icmp)| order < icmp)) {
            let (i, _) = tx?;
            let report = state.ts.pop_tx_report(i)?;
            state.buf.consume_error(report.charge);
            return Some(ErrorReport::Tx(report));
        }
        let (i, _) = icmp?;
        let report = state.errq.remove(i)?;
        state.buf.consume_error(report.charge);
        if state
            .pending_error
            .as_ref()
            .is_some_and(|e| matches!(e.origin, ErrorOrigin::Icmp { .. }))
        {
            state.pending_error = None;
        }
        Some(ErrorReport::Icmp(report))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn icmp_report_ready(&self) -> bool {
        self.state().errq.iter().any(|r| r.charged)
    }

    /// The socket's kind now.
    pub(crate) fn kind(&self) -> SocketKind {
        self.state().kind
    }

    /// Reads and clears the pending error, as `getsockopt(SO_ERROR)` does (man 7 socket).
    pub(crate) fn take_error(&self) -> Option<c_int> {
        let mut state = self.state();
        #[cfg(unix)]
        Self::count_error_wakes(&mut state);
        let visible = state
            .pending_error
            .as_ref()
            .is_some_and(|e| e.visible.is_none_or(|d| d.passed()));
        if !visible {
            return None;
        }
        state.pending_error.take().map(|e| e.errno)
    }

    /// The pending error readable now, left pending, for readiness checks (poll reports `POLLERR`
    /// while an error is pending; man 2 poll).
    pub(crate) fn peek_error(&self) -> Option<c_int> {
        let state = self.state();
        let pending = state.pending_error.as_ref();
        #[cfg(windows)]
        let pending = pending.or_else(|| state.icmp_errors.front());
        pending
            .filter(|error| error.visible.is_none_or(|deadline| deadline.passed()))
            .map(|error| error.errno)
    }

    #[cfg(windows)]
    pub(crate) fn peek_socket_error(&self) -> Option<c_int> {
        self.state()
            .pending_error
            .as_ref()
            .filter(|error| error.visible.is_none_or(|deadline| deadline.passed()))
            .map(|error| error.errno)
    }

    #[cfg(windows)]
    pub(crate) fn icmp_order(&self) -> Option<ErrorOrder> {
        self.state()
            .icmp_errors
            .front()
            .filter(|error| error.visible.is_none_or(|deadline| deadline.passed()))
            .map(|error| error.order)
    }

    #[cfg(unix)]
    pub(crate) fn error_wakes(&self) -> u64 {
        Self::count_error_wakes(&mut self.state())
    }

    #[cfg(unix)]
    fn count_error_wakes(state: &mut SockState) -> u64 {
        let mut added = 0;
        if let Some(error) = &mut state.pending_error
            && !error.wake_counted
            && error.visible.is_none_or(|d| d.passed())
        {
            error.wake_counted = true;
            added += 1;
        }
        for report in &mut state.errq {
            #[cfg(target_os = "linux")]
            let ready = report.charged;
            #[cfg(not(target_os = "linux"))]
            let ready = report.arrives.is_none_or(|d| d.passed());
            if !report.wake_counted && ready {
                report.wake_counted = true;
                added += 1;
            }
        }
        state.error_wakes = state.error_wakes.saturating_add(added);
        let wakes = state.error_wakes;
        #[cfg(target_os = "linux")]
        let wakes = wakes.saturating_add(crate::tstamp::tx_report_wakes(&mut state.ts));
        wakes
    }

    /// A snapshot of the socket. Lands arrived data first, so call it with no backend lock held.
    fn entry(&self) -> SocketEntry {
        let probe = self.probe();
        let (queued, queued_bytes) = probe.map_or((0, 0), |p| p.queued());
        let state = self.state();
        let pending_error = state.pending_error.as_ref();
        #[cfg(windows)]
        let pending_error = pending_error.or_else(|| state.icmp_errors.front());
        SocketEntry {
            id: self.id,
            kind: state.kind,
            local: state.local,
            peer: state.peer,
            listener: state.listener,
            memberships: state.memberships.clone(),
            queued,
            queued_bytes,
            delivered: state.delivered,
            delivered_bytes: state.delivered_bytes,
            sent: state.sent,
            pending_error: pending_error
                .filter(|e| e.visible.is_none_or(|d| d.passed()))
                .map(|e| e.errno),
            created_at: self.created_at,
            closed_at: state.closed_at,
            interface: state.last_nic.clone(),
            last_tx_nic: state.last_tx_nic.clone(),
            last_rx_nic: state.last_rx_nic.clone(),
            bound_device: state.device.as_ref().map(|(_, n)| n.clone()),
            multicast_if: state.mcast_if.as_ref().map(|(_, n)| n.clone()),
            rcvbuf: state.buf.rcvbuf as u32,
            sndbuf: state.buf.sndbuf as u32,
            rmem_alloc: state.buf.rx.rmem_alloc,
            overflowed: state.buf.overflowed,
            wire_lost: state.buf.wire_lost,
            drops: state.buf.drops,
            unmodelled_options: state.unmodelled.clone(),
        }
    }

    /// Keeps the value of option `(level, name)`, which the sim accepts and ignores as harmless,
    /// for [`ignored_value`](Self::ignored_value).
    pub(crate) fn keep_ignored(&self, level: c_int, name: c_int, value: &[u8]) {
        self.state().ignored.insert((level, name), value.to_vec());
    }

    /// The value last set for ignored option `(level, name)`, if it was set.
    pub(crate) fn ignored_value(&self, level: c_int, name: c_int) -> Option<Vec<u8>> {
        self.state().ignored.get(&(level, name)).cloned()
    }
}

/// Every socket of one sim, live and closed.
pub(crate) struct SocketTable {
    /// The next [`SocketId`]; ids start at 1 and are never reused.
    next: AtomicU64,
    /// Open sockets by id, so iteration is in creation order.
    live: Mutex<BTreeMap<SocketId, Arc<SockRec>>>,
    /// Every open descriptor's socket, aliases included.
    by_fd: Mutex<HashMap<c_int, SocketId>>,
    /// Snapshots of closed sockets, in the order they closed.
    closed: Mutex<Vec<SocketEntry>>,
}

impl SocketTable {
    /// An empty table whose first socket is id 1.
    pub(crate) fn new() -> Self {
        SocketTable {
            next: AtomicU64::new(1),
            live: Mutex::default(),
            by_fd: Mutex::default(),
            closed: Mutex::default(),
        }
    }

    /// Records a new socket of `kind` open on `fd`, created at `now` with buffers `buf`, its
    /// traffic counted in `stats`.
    pub(crate) fn create(
        &self,
        kind: SocketKind,
        fd: c_int,
        now: Duration,
        buf: SockBuf,
        stats: Arc<ProtoStats>,
    ) -> Arc<SockRec> {
        let id = SocketId(self.next.fetch_add(1, Ordering::Relaxed));
        let rec = Arc::new(SockRec {
            id,
            created_at: now,
            probe: Mutex::new(None),
            #[cfg(target_os = "linux")]
            next_data_arrival: AtomicU64::new(u64::MAX),
            state: Mutex::new(SockState {
                kind,
                fds: BTreeSet::from([fd]),
                local: None,
                station: false,
                peer: None,
                tcp_established: false,
                #[cfg(unix)]
                connect_ack: false,
                #[cfg(unix)]
                tcp_failed: false,
                listener: None,
                memberships: Vec::new(),
                opts: SockOpts::default(),
                pending_error: None,
                #[cfg(windows)]
                icmp_errors: VecDeque::new(),
                #[cfg(unix)]
                error_wakes: 0,
                dgram: DgramOpts::default(),
                frag: FragOpts::default(),
                errq: VecDeque::new(),
                delivered: 0,
                delivered_bytes: 0,
                sent: 0,
                closed_at: None,
                device: None,
                mcast_if: None,
                last_nic: None,
                last_tx_nic: None,
                last_rx_nic: None,
                buf,
                #[cfg(unix)]
                ts: Default::default(),
                #[cfg(windows)]
                win: Default::default(),
                unmodelled: Vec::new(),
                ignored: HashMap::new(),
            }),
            stats,
        });
        self.live.lock().unwrap().insert(id, rec.clone());
        self.by_fd.lock().unwrap().insert(fd, id);
        rec
    }

    /// Records `fd` as another descriptor of `rec`'s file description.
    pub(crate) fn alias(&self, fd: c_int, rec: &Arc<SockRec>) {
        rec.state().fds.insert(fd);
        self.by_fd.lock().unwrap().insert(fd, rec.id);
    }

    /// Forgets `fd`; when it was the record's last descriptor the socket is closed at `now` and
    /// moves to the closed history, its snapshot taken (and its data landed) at the close. An
    /// fd the table does not know is ignored.
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn fd_closed(&self, fd: c_int, now: Duration) {
        let Some(id) = self.by_fd.lock().unwrap().remove(&fd) else {
            return;
        };
        let Some(rec) = self.live.lock().unwrap().get(&id).cloned() else {
            return;
        };
        let last = {
            let mut state = rec.state();
            state.fds.remove(&fd);
            let last = state.fds.is_empty();
            if last {
                state.closed_at = Some(now);
            }
            last
        };
        if last {
            let entry = rec.entry();
            self.live.lock().unwrap().remove(&id);
            self.closed.lock().unwrap().push(entry);
        }
    }

    #[cfg(unix)]
    pub(crate) fn detach_replaced_fd(
        &self,
        fd: c_int,
        previous: &Arc<SockRec>,
        now: Duration,
    ) -> bool {
        {
            let mut by_fd = self.by_fd.lock().unwrap();
            if by_fd.get(&fd) == Some(&previous.id) {
                by_fd.remove(&fd);
            }
        }
        let mut state = previous.state();
        state.fds.remove(&fd);
        let last = state.fds.is_empty();
        if last {
            state.closed_at = Some(now);
        }
        last
    }

    #[cfg(unix)]
    pub(crate) fn finish_replaced_fd(&self, previous: &Arc<SockRec>) {
        let entry = previous.entry();
        self.live.lock().unwrap().remove(&previous.id);
        self.closed.lock().unwrap().push(entry);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn fd_replaced(&self, fd: c_int, previous: &Arc<SockRec>, now: Duration) {
        if self.detach_replaced_fd(fd, previous, now) {
            self.finish_replaced_fd(previous);
        }
    }

    /// Every open socket's record, oldest first, copied out so the table lock is not held while
    /// the caller works on them.
    pub(crate) fn live_recs(&self) -> Vec<Arc<SockRec>> {
        self.live.lock().unwrap().values().cloned().collect()
    }

    /// The open socket on `fd`.
    pub(crate) fn lookup_fd(&self, fd: c_int) -> Option<Arc<SockRec>> {
        let id = *self.by_fd.lock().unwrap().get(&fd)?;
        self.live.lock().unwrap().get(&id).cloned()
    }

    /// The open socket `id`.
    fn lookup(&self, id: SocketId) -> Option<Arc<SockRec>> {
        self.live.lock().unwrap().get(&id).cloned()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn lookup_raw_id(&self, id: u64) -> Option<Arc<SockRec>> {
        self.lookup(SocketId(id))
    }

    /// A snapshot of socket `id`, open or closed.
    pub(crate) fn entry(&self, id: SocketId) -> Option<SocketEntry> {
        if let Some(rec) = self.lookup(id) {
            return Some(rec.entry());
        }
        self.closed
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.id == id)
            .cloned()
    }

    /// The `SIO_CPU_AFFINITY` processor of open socket `id`.
    #[cfg(windows)]
    pub(crate) fn cpu_affinity(&self, id: SocketId) -> Option<u16> {
        self.lookup(id)?.state().dgram.cpu_affinity
    }

    /// Snapshots of the open sockets, oldest first. The records are copied out before any is
    /// snapshotted, since a snapshot lands data and must not run under the table lock.
    pub(crate) fn live(&self) -> Vec<SocketEntry> {
        let recs: Vec<_> = self.live.lock().unwrap().values().cloned().collect();
        recs.iter().map(|rec| rec.entry()).collect()
    }

    /// The closed sockets, in the order they closed.
    pub(crate) fn closed(&self) -> Vec<SocketEntry> {
        self.closed.lock().unwrap().clone()
    }
}

impl SimShared {
    /// A record for a new socket of the code under test, open on `fd`, with the buffers the
    /// sim's limits give its kind now.
    pub(crate) fn new_socket(&self, kind: SocketKind, fd: c_int) -> Arc<SockRec> {
        let buf = SockBuf::new(kind, &self.sys.limits());
        self.sockets
            .create(kind, fd, self.stamp(), buf, self.stats.clone())
    }

    /// Notes that `fd` closed, now on the sim's timeline.
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn socket_closed(&self, fd: c_int) {
        self.sockets.fd_closed(fd, self.stamp());
    }

    /// See [`socket_entry`].
    pub(crate) fn socket_entry(&self, id: SocketId) -> Option<SocketEntry> {
        snare_interpose::real(|| self.sockets.entry(id))
    }

    /// See [`socket_table`].
    pub(crate) fn socket_table(&self) -> Vec<SocketEntry> {
        snare_interpose::real(|| self.sockets.live())
    }

    /// See [`closed_sockets`].
    pub(crate) fn closed_sockets(&self) -> Vec<SocketEntry> {
        snare_interpose::real(|| self.sockets.closed())
    }
}

/// The id of the sim socket on `fd` in the calling thread's sim; `None` off a sim or for an fd
/// the sim does not serve.
fn id_of_fd(fd: c_int) -> Option<SocketId> {
    let shared = scope::try_here()?;
    snare_interpose::real(|| shared.sockets.lookup_fd(fd).map(|rec| rec.id))
}

/// The id of `socket` in the sim the calling thread runs in, or `None` for a socket the sim does
/// not serve (a real OS socket) and off a sim.
#[cfg(unix)]
pub fn socket_id<S: std::os::fd::AsFd>(socket: &S) -> Option<SocketId> {
    use std::os::fd::AsRawFd;
    id_of_fd(socket.as_fd().as_raw_fd())
}

/// The id of `socket` in the sim the calling thread runs in, or `None` for a socket the sim does
/// not serve (a real OS socket) and off a sim. The sim's own handles fit an `int`; a `SOCKET` that
/// does not is a real one.
#[cfg(windows)]
pub fn socket_id<S: std::os::windows::io::AsSocket>(socket: &S) -> Option<SocketId> {
    use std::os::windows::io::AsRawSocket;
    let raw = socket.as_socket().as_raw_socket();
    id_of_fd(c_int::try_from(raw).ok()?)
}

/// Socket `id` of the calling thread's sim, open or closed. Panics off a sim.
#[track_caller]
pub fn socket_entry(id: SocketId) -> Option<SocketEntry> {
    scope::here().socket_entry(id)
}

/// The open sockets of the calling thread's sim, oldest first. Panics off a sim.
#[track_caller]
pub fn socket_table() -> Vec<SocketEntry> {
    scope::here().socket_table()
}

/// The closed sockets of the calling thread's sim, in the order they closed. Panics off a sim.
#[track_caller]
pub fn closed_sockets() -> Vec<SocketEntry> {
    scope::here().closed_sockets()
}

/// The open sockets of the calling thread's sim whose local address is `local` (any address it
/// resolves to): bound datagram sockets, a listener and the streams accepted from it. Panics off a
/// sim.
#[track_caller]
pub fn sockets_bound(local: impl ToSocketAddrs) -> Vec<SocketEntry> {
    let shared = scope::here();
    let addrs: Vec<SocketAddr> = snare_interpose::real(|| local.to_socket_addrs())
        .map(Iterator::collect)
        .unwrap_or_default();
    shared
        .socket_table()
        .into_iter()
        .filter(|e| e.local.is_some_and(|l| addrs.contains(&l)))
        .collect()
}

/// Makes `errno` the pending `SO_ERROR` of open socket `id` in the calling thread's sim, readable
/// at once and recorded as a connect's error. Does nothing for a socket that is not open. Panics
/// off a sim.
#[doc(hidden)]
pub fn __set_pending_error(id: SocketId, errno: i32) {
    let shared = scope::here();
    snare_interpose::real(|| {
        if let Some(rec) = shared.sockets.lookup(id) {
            rec.set_pending_error(errno, None);
        }
    });
}

/// Adds `n` to the drop counter of open socket `id` in the calling thread's sim, as drops the
/// kernel made below the socket: they show in `SO_RXQ_OVFL` and `SO_MEMINFO` and in
/// [`SocketEntry::drops`]. `NotFound` when no such socket is open. Panics off a sim.
#[track_caller]
pub fn inject_socket_drops(id: SocketId, n: u32) -> std::io::Result<()> {
    scope::here().inject_socket_drops(id, n)
}

impl SimShared {
    /// See [`inject_socket_drops`]. The counter wraps as the kernel's
    /// `u32` `sk_drops` does.
    pub(crate) fn inject_socket_drops(&self, id: SocketId, n: u32) -> std::io::Result<()> {
        snare_interpose::real(|| {
            let rec = self
                .sockets
                .lookup(id)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
            let mut state = rec.state();
            state.buf.drops = state.buf.drops.wrapping_add(n);
            Ok(())
        })
    }
}

/// Binds open socket `id` of the calling thread's sim to interface `nic`, or unbinds it with
/// `None`, as the code under test would with Linux `SO_BINDTODEVICE`, macOS `IP_BOUND_IF` or
/// Windows `IP_UNICAST_IF`: its sends leave through `nic` and, where the host OS filters receives
/// by device, it only receives what arrives there (the README's "Interfaces and routing" gives
/// each host's rules). An unknown interface fails with the
/// code the option gives for one: `ENODEV` on Linux (net/core/sock.c `sock_setbindtodevice`),
/// `ENXIO` on macOS (bsd/netinet/in_pcb.c `inp_bindif`) and `WSAEINVAL` on Windows; a socket that
/// is not open is `NotFound`. Unlike the option, it is never refused for want of privilege.
/// Panics off a sim.
#[track_caller]
pub fn set_socket_device(id: SocketId, nic: Option<&str>) -> std::io::Result<()> {
    scope::here().set_socket_device(id, nic)
}

impl SimShared {
    /// See [`set_socket_device`].
    pub(crate) fn set_socket_device(&self, id: SocketId, nic: Option<&str>) -> std::io::Result<()> {
        snare_interpose::real(|| {
            let rec = self
                .sockets
                .lookup(id)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
            let device = match nic {
                None => None,
                Some(name) => {
                    let index = self
                        .topo()
                        .index_of(name)
                        .ok_or_else(|| std::io::Error::from_raw_os_error(NO_SUCH_DEVICE))?;
                    Some((index, name.to_string()))
                }
            };
            rec.state().device = device;
            Ok::<(), std::io::Error>(())
        })?;
        self.kick();
        Ok(())
    }
}

/// What binding to an interface the host does not have fails with: `ENODEV` from Linux
/// `SO_BINDTODEVICE`, `ENXIO` from macOS `IP_BOUND_IF`, `WSAEINVAL` (10022) from Windows
/// `IP_UNICAST_IF` ([Microsoft Learn: Windows Sockets Error
/// Codes](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2)).
#[cfg(target_os = "linux")]
const NO_SUCH_DEVICE: c_int = libc::ENODEV;
#[cfg(target_os = "macos")]
const NO_SUCH_DEVICE: c_int = libc::ENXIO;
#[cfg(windows)]
const NO_SUCH_DEVICE: c_int = 10022;

impl SimShared {
    /// The code under test used `option` on `rec`, which the sim does not model. The first use on
    /// each socket is listed in its [`SocketEntry::unmodelled_options`] and logged as
    /// [`RecordedEvent::UnmodelledOption`](crate::RecordedEvent::UnmodelledOption). Returns
    /// whether the call must fail, which it does under
    /// [`strict_sockopts`](crate::SimBuilder::strict_sockopts); the first such failure in the sim
    /// is also written to stderr, so a test that swallows the error still shows why.
    pub(crate) fn unmodelled_option(&self, rec: &SockRec, option: UnmodelledOption) -> bool {
        let strict = self.strict_sockopts.load(Ordering::Relaxed);
        self.list_unmodelled(rec, option, strict);
        if strict && !self.strict_reported.swap(true, Ordering::Relaxed) {
            let id = rec.id;
            snare_interpose::real(|| {
                eprintln!(
                    "snare: strict_sockopts: {option} on {id} is not modelled by the sim; \
                     failing the call (later ones fail without this message, see \
                     SocketEntry::unmodelled_options)"
                )
            });
        }
        strict
    }

    /// The code under test used `option` on `rec`, which the sim does not model and cannot
    /// accept without effect either (a Windows `WSAIoctl` code whose output only the OS could
    /// give): listed and logged as [`unmodelled_option`](Self::unmodelled_option) does, as
    /// refused, whatever `strict_sockopts` says.
    #[cfg(windows)]
    pub(crate) fn unservable_option(&self, rec: &SockRec, option: UnmodelledOption) {
        self.list_unmodelled(rec, option, true);
    }

    /// Lists `option` on `rec` and logs it, the first time it is used there.
    fn list_unmodelled(&self, rec: &SockRec, option: UnmodelledOption, refused: bool) {
        let (first, local) = {
            let mut state = rec.state();
            let first = !state.unmodelled.contains(&option);
            if first {
                state.unmodelled.push(option);
            }
            (first, state.local)
        };
        if first {
            self.record(crate::events::RecordedEvent::UnmodelledOption {
                socket: rec.id,
                local,
                option,
                refused,
            });
        }
    }
}
