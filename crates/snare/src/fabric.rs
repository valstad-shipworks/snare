//! An in-memory TCP fabric behind [`snare_interpose::Net`]. The code under test uses ordinary
//! `std::net` types; their socket calls land here and are serviced from process memory. A
//! [`Listener`] registered by a tester is the peer side of a connection.
//!
//! [`Fabric`] owns a table of virtual descriptors ([`Sock`]): TCP sockets through their
//! fresh → connecting → stream / listener life, UDP and `AF_UNIX` datagram sockets, `socketpair`
//! ends, and the readiness objects (Linux eventfd and epoll, macOS kqueue) and raw L2 endpoints
//! (Linux `AF_PACKET`, macOS `/dev/bpf*`) that event loops and EtherCAT masters open. Each
//! descriptor is a real fd `dup`ed from `/dev/null`, so its number is unique in the process and is
//! freed by the real `close`. Every [`Net`]/[`Fs`] method returns `None` to decline an fd or call
//! it does not model, which passes the call on to the next backend or the OS.
//!
//! Per-`Sim` state that testers also reach (the listener and datagram address maps) lives in
//! [`Registries`], installed per thread by [`enter`] and [`ScopeLayer`]. Link policy, routing,
//! capture and socket accounting live in [`SimShared`]; byte streams in [`Pipe`].
//!
//! Lock order: [`Fabric::socks`], then a connect's `ConnectAttempt`, then the `Registries` maps,
//! then per-object locks (`Listener::pending`, `DgramQueue::packets`, pipe state). The global
//! [`Readiness`](crate::readiness::Readiness) state sits outside all of them: `wait_until` runs
//! its predicate (which takes `socks`) under that state, so nothing may bump readiness or block
//! while holding `socks` — every method copies what it needs out of the table and drops the guard
//! first.
//! Tester-facing entry points run under [`snare_interpose::real`], so their own waits on these
//! locks are not counted as blocked threads by quiescence detection.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::ffi::c_int;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use snare_interpose::{Fs, Net, NetResult};

#[cfg(target_os = "macos")]
mod mac_shutdown;

#[derive(Clone)]
enum Payload {
    Inline { bytes: [u8; 128], len: u8 },
    Heap(Vec<u8>),
}

impl Payload {
    fn copy_from(data: &[u8]) -> Self {
        if data.len() <= 128 {
            let mut bytes = [0; 128];
            bytes[..data.len()].copy_from_slice(data);
            Self::Inline {
                bytes,
                len: data.len() as u8,
            }
        } else {
            Self::Heap(data.to_vec())
        }
    }

    fn into_vec(self) -> Vec<u8> {
        match self {
            Self::Inline { bytes, len } => bytes[..len as usize].to_vec(),
            Self::Heap(data) => data,
        }
    }
}

impl std::ops::Deref for Payload {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Inline { bytes, len } => &bytes[..*len as usize],
            Self::Heap(data) => data,
        }
    }
}

/// One received datagram: its payload and the source address a `recvfrom` reports back.
#[derive(Clone)]
pub(crate) struct Datagram {
    /// The sender's address; [`UNNAMED`] for a datagram from a `socketpair` end.
    src: SocketAddr,
    /// The whole payload. A datagram is received whole or truncated, never split.
    data: Payload,
    /// Still in flight until then (link latency); `None` arrived on sending.
    arrives: Option<Deadline>,
    /// The link it crosses and that link's down epoch when it was sent.
    via: Option<(Arc<LinkState>, u64)>,
    /// When it reaches the socket (its send time plus its delay), for receive timestamps.
    stamp: Stamp,
    #[cfg(target_os = "linux")]
    rx_fallback: Arc<std::sync::OnceLock<Duration>>,
    /// The smallest MTU on its path ([`crate::netif::Copy::mtu`]).
    mtu: Option<u32>,
    sequence: u64,
}

/// What the receive-buffer accounting in [`RxQueue`] needs to know of a datagram.
impl Arrival for Datagram {
    fn src(&self) -> SocketAddr {
        self.src
    }

    fn payload(&self) -> usize {
        self.data.len()
    }

    fn arrives(&self) -> Option<Deadline> {
        self.arrives
    }

    /// Whether the link it crosses went down while it was still in flight, which loses it.
    fn lost(&self) -> bool {
        match (&self.via, self.arrives) {
            (Some((link, epoch)), Some(at)) => link.lost_in_flight(*epoch, at.instant()),
            _ => false,
        }
    }

    fn path_mtu(&self) -> Option<u32> {
        self.mtu
    }
}

/// A datagram socket's receive queue. Shared (behind an `Arc`) between the owning [`Sock::Dgram`]
/// and the per-`Sim` address registry, so a `sendto` on one socket can enqueue onto a peer's queue
/// by looking up its bound address. Blocking receives park on the sim's
/// [`Readiness`](crate::readiness::Readiness) channel (giving them quiescence detection), so no
/// per-queue condvar is needed.
#[derive(Default)]
pub(crate) struct DgramQueue {
    /// The datagrams, in flight or arrived, with the receive-buffer limits applied as they land.
    packets: Mutex<RxQueue<Datagram>>,
    /// The code under test's socket this queue belongs to; `None` for a tester endpoint.
    rec: Option<Arc<SockRec>>,
    next_port: AtomicU64,
}

impl DgramQueue {
    /// A queue for the code under test's socket `rec`, registered as that socket's [`RxProbe`] so
    /// its record can report queued bytes (`FIONREAD`, socket stats) without knowing the queue.
    /// The probe is weak: the record never keeps a closed socket's queue alive.
    fn for_socket(rec: &Arc<SockRec>) -> Arc<Self> {
        let queue = Arc::new(DgramQueue {
            packets: Mutex::default(),
            rec: Some(rec.clone()),
            next_port: AtomicU64::new(0),
        });
        rec.set_probe(Arc::downgrade(&queue) as std::sync::Weak<dyn RxProbe>);
        queue
    }

    /// Queues a datagram that becomes receivable `delay` from now (its link latency). A delayed
    /// arrival is registered as a wake-up point first, so a receiver blocked on the virtual clock
    /// is woken (and the quiescence time-skip can jump) when it lands. `via` is the link it
    /// crosses and that link's down epoch at sending, for [`Arrival::lost`]; `sent` when it left,
    /// which with `delay` stamps it; `mtu` its path's smallest MTU. Bumps readiness for `domain`,
    /// the key of the sim the queue belongs to, so it must not be called holding `Fabric::socks`.
    #[allow(clippy::too_many_arguments)]
    fn push_after(
        &self,
        src: SocketAddr,
        data: &[u8],
        delay: Duration,
        via: Option<(Arc<LinkState>, u64)>,
        sent: Stamp,
        mtu: Option<u32>,
        domain: usize,
    ) {
        let arrives = (!delay.is_zero()).then(|| Deadline::after(delay));
        if let Some(arrives) = arrives {
            arrives.wake_waiters_then();
        }
        let dg = Datagram {
            src,
            data: Payload::copy_from(data),
            arrives,
            via,
            stamp: sent.later(delay),
            #[cfg(target_os = "linux")]
            rx_fallback: Arc::default(),
            mtu,
            sequence: readiness_sequence(),
        };
        self.packets.lock().unwrap().push(dg, self.rec.as_deref());
        if let Some(rec) = &self.rec {
            readiness().bump_keys(domain, &[rec.wake_key()]);
        } else {
            readiness().bump_keys(domain, &[]);
        }
    }

    /// Pops the earliest-arrived datagram whose source passes `accept` (a connected socket only
    /// accepts from its peer), with the drop count it carries. `None` when nothing acceptable has
    /// arrived yet.
    fn pop(&self, accept: impl Fn(SocketAddr) -> bool) -> Option<(Datagram, u32)> {
        self.packets
            .lock()
            .unwrap()
            .pop(accept, self.rec.as_deref())
    }

    /// A copy of the datagram [`pop`](Self::pop) would take, left queued: what `MSG_PEEK` reads.
    fn peek(&self, accept: impl Fn(SocketAddr) -> bool) -> Option<(Datagram, u32)> {
        self.packets
            .lock()
            .unwrap()
            .peek(accept, self.rec.as_deref())
    }

    fn readiness_metadata(&self) -> Option<(Duration, u64, usize)> {
        self.packets
            .lock()
            .unwrap()
            .first_matching(|_| true, self.rec.as_deref())
            .map(|(d, _)| (d.stamp.mono, d.sequence, d.data.len()))
    }

    /// Whether a datagram whose source passes `accept` has arrived, without taking it.
    fn has(&self, accept: impl Fn(SocketAddr) -> bool) -> bool {
        self.packets
            .lock()
            .unwrap()
            .has(accept, self.rec.as_deref())
    }

    /// How many datagrams have landed so far: the socket's read wakes (see [`Wakes`]).
    fn landed(&self) -> u64 {
        self.packets.lock().unwrap().landed(self.rec.as_deref())
    }
}

/// Lets the socket's record see into this queue: landing in-flight datagrams whose time has come,
/// and the queued counts and next datagram length that `FIONREAD` and socket stats report.
impl RxProbe for DgramQueue {
    fn pending_time(&self) -> bool {
        self.packets.lock().unwrap().pending_time()
    }

    fn land(&self) {
        self.packets.lock().unwrap().land(self.rec.as_deref());
    }

    fn queued(&self) -> (usize, usize) {
        self.packets.lock().unwrap().queued()
    }

    fn next_len(&self) -> Option<usize> {
        self.packets.lock().unwrap().next_len(self.rec.as_deref())
    }
}

/// A bidirectional connection. The connecting side is `A`, the accepting side `B`: a tester, or
/// a socket of the code under test accepted from its listener.
///
/// Shared by both ends' descriptors (and every `dup` of them) and by the tester holding the peer
/// side; it lives until the last of them lets go. Closing one end closes only its write pipe.
pub(crate) struct Conn {
    /// Bytes the connecting side writes and the accepting side reads.
    a_to_b: Arc<Pipe>,
    /// Bytes the accepting side writes and the connecting side reads.
    b_to_a: Arc<Pipe>,
    /// The connecting side's address ([`UNNAMED`] for a socketpair).
    pub(crate) client: SocketAddr,
    /// The accepting side's address ([`UNNAMED`] for a socketpair).
    pub(crate) server: SocketAddr,
    /// The sim's registries, for the link policy (latency) on this connection's bytes.
    regs: Arc<Registries>,
    /// The interface the connection crosses, if it leaves the host.
    hop: Option<Hop>,
    /// The two unnamed ends of a `socketpair`: no addresses, and no link policy between them.
    pair: bool,
    /// The pcapng capture this connection's segments are written to, when capture is on.
    tap: Option<TcpTap>,
    /// For each direction (by the writing end's [`End::index`]), the chunks written and not yet
    /// read, each with when it reaches the reader: what a receive timestamp of the bytes read
    /// reports.
    stamps: [Mutex<VecDeque<(usize, Stamp)>>; 2],
    write_delays: [AtomicU64; 2],
    #[cfg(target_os = "macos")]
    mac_shutdown: Mutex<mac_shutdown::State>,
}

/// Which side of a [`Conn`] a descriptor is.
#[derive(Clone, Copy, PartialEq)]
enum End {
    A,
    B,
}

impl Conn {
    /// Writes what the window has room for from `end`; `None` once that direction is closed.
    /// The bytes arrive after the link policy's TCP delay for this address pair plus the delay of
    /// the interface hop they cross (none between socketpair ends), and are counted against the
    /// hop's interface statistics.
    fn write(&self, end: End, bytes: &[u8]) -> Option<usize> {
        #[cfg(target_os = "macos")]
        self.progress_tcp_shutdown();
        let pipe = self.write_pipe(end);
        if (pipe.reader_gone()
            || (cfg!(not(target_os = "macos"))
                && pipe.is_read_shut()
                && self.read_pipe(end).is_closed()))
            && !pipe.is_closed()
        {
            self.reset(if end == End::A { End::B } else { End::A });
            return Some(bytes.len());
        }
        let delay = self.delay();
        self.write_delays[end.index()].store(
            delay.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        #[cfg(target_os = "macos")]
        let mut shutdown_at = None;
        let written =
            self.write_pipe(end)
                .write_after(bytes, delay, |sent, arrival, _read_shutdown_at| {
                    self.record_write(end, sent, arrival, None, _read_shutdown_at.is_none());
                    #[cfg(target_os = "macos")]
                    if !sent.is_empty() {
                        shutdown_at = _read_shutdown_at;
                    }
                });
        #[cfg(target_os = "macos")]
        if let Some(at) = shutdown_at {
            self.schedule_read_shutdown_data(end, at);
        }
        written
    }

    fn record_write(
        &self,
        end: End,
        bytes: &[u8],
        arrival: Duration,
        mss: Option<usize>,
        _acknowledge: bool,
    ) {
        let shared = &self.regs.shared;
        if let Some(tap) = &self.tap {
            #[cfg(target_os = "macos")]
            if !_acknowledge {
                tap.data_mss_unacknowledged(end.index(), bytes, arrival, mss);
            } else {
                tap.data_mss(end.index(), bytes, arrival, mss);
            }
            #[cfg(not(target_os = "macos"))]
            tap.data_mss(end.index(), bytes, arrival, mss);
        }
        self.stamps[end.index()]
            .lock()
            .unwrap()
            .push_back((bytes.len(), shared.tstamp_now().later(arrival)));
        if !self.pair {
            let pipe = self.write_pipe(end);
            shared.account_tcp_mss(
                self.hop.as_ref(),
                end == End::A,
                bytes.len(),
                self.server.ip(),
                (pipe.has_writer(), pipe.has_reader()),
                mss,
            );
        }
    }

    /// The one-way delay of the connection's bytes: the TCP link policy between its two
    /// addresses plus the interface hop's own delay; none between socketpair ends.
    fn delay(&self) -> Duration {
        if self.pair {
            return Duration::ZERO;
        }
        let shared = &self.regs.shared;
        shared.policies.tcp_delay(self.server, self.client) + shared.hop_delay(self.hop.as_ref())
    }

    /// `end` read `n` bytes: drops their chunks' stamps and returns the arrival of the last byte
    /// read, the stamp Linux reports for a TCP read (net/ipv4/tcp.c `tcp_recvmsg_locked` keeps
    /// the stamp of each segment it copies from, so the last one's wins).
    fn took(&self, end: End, n: usize) -> Option<Stamp> {
        let writer = match end {
            End::A => End::B,
            End::B => End::A,
        };
        let mut chunks = self.stamps[writer.index()].lock().unwrap();
        let mut left = n;
        let mut last = None;
        while left > 0 {
            let Some((len, at)) = chunks.front_mut() else {
                break;
            };
            last = Some(*at);
            if *len <= left {
                left -= *len;
                chunks.pop_front();
            } else {
                *len -= left;
                left = 0;
            }
        }
        last
    }

    /// The pipe `end` reads from.
    fn read_pipe(&self, end: End) -> &Pipe {
        match end {
            End::A => &self.b_to_a,
            End::B => &self.a_to_b,
        }
    }

    /// The pipe `end` writes into.
    fn write_pipe(&self, end: End) -> &Arc<Pipe> {
        match end {
            End::A => &self.a_to_b,
            End::B => &self.b_to_a,
        }
    }

    /// Half-closes `end`'s sending direction (a FIN): the other side reads end of stream once the
    /// bytes already written have arrived.
    fn close(&self, end: End) {
        #[cfg(target_os = "macos")]
        self.progress_tcp_shutdown();
        self.write_pipe(end).close_writer();
        self.write_pipe(end).close(|arrival| {
            if let Some(tap) = &self.tap {
                tap.fin(end.index(), arrival);
            }
        });
    }

    /// `end`'s own address, as `getsockname` reports it.
    fn local(&self, end: End) -> SocketAddr {
        match end {
            End::A => self.client,
            End::B => self.server,
        }
    }

    /// The address of the side opposite `end`, as `getpeername` reports it.
    fn peer(&self, end: End) -> SocketAddr {
        match end {
            End::A => self.server,
            End::B => self.client,
        }
    }

    /// Aborts the connection with a reset sent from `from`: both directions fail at once, and
    /// either side's next read or write reports ECONNRESET (man 2 send; for an established
    /// connection net/ipv4/tcp_input.c tcp_reset sets `sk_err` to ECONNRESET).
    fn reset(&self, from: End) {
        if !self.a_to_b.is_reset() && !self.pair {
            self.regs.shared.count_reset(
                self.server.ip(),
                self.write_pipe(from).has_writer(),
                [
                    self.a_to_b.established_reader(),
                    self.b_to_a.established_reader(),
                ],
            );
        }
        if let Some(tap) = &self.tap {
            tap.rst(from.index());
        }
        if cfg!(target_os = "linux") {
            for (incoming, outgoing) in [(&self.a_to_b, &self.b_to_a), (&self.b_to_a, &self.a_to_b)]
            {
                if if incoming.is_read_shut() {
                    outgoing.is_write_shut()
                } else {
                    !incoming.is_closed()
                } {
                    incoming.reset_reader();
                }
            }
        } else {
            self.write_pipe(from).reset_reader();
        }
        self.a_to_b.reset();
        self.b_to_a.reset();
    }
}

impl End {
    /// The side's index in a [`TcpTap`]: 0 for the connecting side, 1 for the accepting side.
    fn index(self) -> usize {
        match self {
            End::A => 0,
            End::B => 1,
        }
    }
}

/// A listening address, a tester's or the code under test's: connections wait here to be
/// accepted.
///
pub struct Listener {
    rec: Option<std::sync::Weak<SockRec>>,
    /// The address it listens on, possibly a wildcard.
    addr: SocketAddr,
    /// Established connections not yet accepted, oldest first.
    pending: Mutex<VecDeque<Arc<Conn>>>,
    capacity: AtomicUsize,
    occupied: AtomicUsize,
    /// A tester's: a station at its address rather than a socket of the host.
    tester: bool,
    /// Connections queued so far. Each wakes the listening socket (Linux net/ipv4/tcp_ipv4.c
    /// `tcp_child_process` calls `sk_data_ready`; XNU bsd/kern/uipc_socket2.c `sonewconn` calls
    /// `sorwakeup`), a new edge for edge-triggered readiness.
    arrivals: AtomicU64,
    ready_order: AtomicU64,
    ready_at: AtomicU64,
}

impl Listener {
    fn wake_key(&self) -> Option<crate::readiness::WakeKey> {
        self.rec.as_ref()?.upgrade().map(|rec| rec.wake_key())
    }

    /// Takes the next connection, or `None` if none is waiting.
    pub(crate) fn try_accept(&self) -> Option<Arc<Conn>> {
        snare_interpose::real(|| {
            let conn = self.pending.lock().unwrap().pop_front()?;
            self.occupied.fetch_sub(1, Ordering::AcqRel);
            Some(conn)
        })
    }

    /// Whether a connection is waiting to be accepted.
    pub(crate) fn has_pending(&self) -> bool {
        snare_interpose::real(|| !self.pending.lock().unwrap().is_empty())
    }

    fn reserve(self: &Arc<Self>) -> Option<ListenerAdmission> {
        let mut used = self.occupied.load(Ordering::Acquire);
        loop {
            if used >= self.capacity.load(Ordering::Acquire) {
                return None;
            }
            match self.occupied.compare_exchange_weak(
                used,
                used + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ListenerAdmission {
                        listener: self.clone(),
                        reserved: true,
                    });
                }
                Err(current) => used = current,
            }
        }
    }

    fn queue(&self, conn: Arc<Conn>) {
        self.ready_at.store(
            conn.regs
                .shared
                .tstamp_now()
                .mono
                .as_nanos()
                .min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        self.pending.lock().unwrap().push_back(conn);
        self.arrivals.fetch_add(1, Ordering::Relaxed);
        self.ready_order
            .store(readiness_sequence(), Ordering::Relaxed);
    }
}

struct ListenerAdmission {
    listener: Arc<Listener>,
    reserved: bool,
}

impl ListenerAdmission {
    fn queue(mut self, conn: Arc<Conn>) {
        self.listener.queue(conn);
        self.reserved = false;
    }
}

impl Drop for ListenerAdmission {
    fn drop(&mut self) {
        if self.reserved {
            self.listener.occupied.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// The per-`Sim` listener and datagram registries, shared by the `Fabric` and the tester free
/// functions (via the thread-local scope below) so tests never clobber each other's state.
pub(crate) struct Registries {
    /// Address → the listener there, the code under test's or a tester's. Keyed on the exact
    /// address, so a wildcard listener is found only by [`Fabric::listener_for`]'s fallback.
    listeners: Mutex<HashMap<SocketAddr, Arc<Listener>>>,
    /// Where datagrams to each address land.
    udp: Mutex<UdpRegistry>,
    /// Backends that model datagram sockets of their own (a `SimHost`), so a tester's datagram to
    /// one of their sockets is handed over rather than lost.
    foreign_udp: Mutex<Vec<std::sync::Weak<dyn ForeignUdp>>>,
    /// The sim state the fabric shares with the other backends: topology, routing, link
    /// policies, capture and the socket table.
    pub(crate) shared: Arc<SimShared>,
}

impl Registries {
    /// Empty registries over `shared`.
    fn new(shared: Arc<SimShared>) -> Self {
        Registries {
            listeners: Mutex::default(),
            udp: Mutex::default(),
            foreign_udp: Mutex::default(),
            shared,
        }
    }

    /// Delivers one datagram from `src` to every queue `dest` reaches, through the links it
    /// crosses and each receiving address's link policy (which may drop or duplicate it).
    /// Returns how many sockets and endpoints it reached, lost on the way or not.
    ///
    /// `sender` is the route the datagram left by and `tx` whether it is counted as sent on the
    /// egress interface. A copy the policy drops is counted as lost on the wire against the
    /// receiving socket; each surviving copy is queued after its own delay. Zero means nothing is
    /// bound there, for the caller's ICMP port-unreachable handling. Takes `udp` then releases it
    /// before queueing, which bumps readiness.
    fn deliver(
        &self,
        sender: &Sender,
        src: SocketAddr,
        dest: SocketAddr,
        data: &[u8],
        tx: bool,
    ) -> usize {
        let sent = self.shared.tstamp_now();
        let joined = dest.ip().is_multicast() && self.shared.host_joined(dest.ip());
        let cands = self.udp.lock().unwrap().delivery_candidates(dest, joined);
        let station = match &cands {
            UdpCandidates::One(None) => false,
            UdpCandidates::One(Some(cand)) if cand.addr == dest => false,
            _ => self.station_at(dest.ip()),
        };
        let wire = Wire {
            src,
            dest,
            len: data.len(),
        };
        let emit = |copy: crate::netif::Copy<Arc<DgramQueue>>| {
            if let Some(rec) = &copy.q.rec {
                if copy.delays.is_empty() {
                    rec.count_wire_lost();
                } else {
                    rec.note_rx_nic(copy.nic.as_deref());
                }
            }
            for delay in copy.delays {
                copy.q.push_after(
                    src,
                    data,
                    delay,
                    copy.via.clone(),
                    sent,
                    copy.mtu,
                    self.shared.domain_key(),
                );
            }
        };
        match cands {
            UdpCandidates::One(cand) => {
                if let Some(copy) = self.shared.fan_out_one(sender, wire, station, cand, tx) {
                    emit(copy);
                    1
                } else {
                    0
                }
            }
            UdpCandidates::Many(cands) => {
                let copies = self.shared.fan_out(sender, wire, station, cands, tx);
                let reached = copies.len();
                for copy in copies {
                    emit(copy);
                }
                reached
            }
        }
    }

    /// Whether a tester's endpoint or listener is bound at `ip`, making it a station: an external
    /// host on the simulated network, which routing reaches over an interface rather than
    /// treating as one of the host's own addresses.
    pub(crate) fn station_at(&self, ip: IpAddr) -> bool {
        let endpoint = self.udp.lock().unwrap().endpoints.contains_key(&ip);
        endpoint
            || self
                .listeners
                .lock()
                .unwrap()
                .values()
                .any(|l| l.tester && l.addr.ip() == ip)
    }
}

/// A backend with datagram sockets of its own, which a tester's UDP endpoint can reach.
pub(crate) trait ForeignUdp: Send + Sync {
    /// Delivers `data` from `src` to every one of its sockets a datagram to `dest` reaches,
    /// returning how many it reached.
    fn deliver_from_peer(&self, src: SocketAddr, dest: SocketAddr, data: &[u8]) -> usize;
}

/// Makes `backend`'s datagram sockets reachable from this sim's tester endpoints.
pub(crate) fn attach_foreign_udp(regs: &Registries, backend: std::sync::Weak<dyn ForeignUdp>) {
    snare_interpose::real(|| regs.foreign_udp.lock().unwrap().push(backend));
}

/// Delivers a datagram another backend's socket sent to this sim's tester endpoints (and any
/// fabric socket) that `dest` reaches. Returns how many it reached. Not counted as a send here:
/// the other backend accounts for its own socket's transmission.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn deliver_to_endpoints(
    regs: &Registries,
    sender: &Sender,
    src: SocketAddr,
    dest: SocketAddr,
    data: &[u8],
) -> usize {
    snare_interpose::real(|| regs.deliver(sender, src, dest, data, false))
}

/// The datagram delivery map for one `Sim`: which receive queue a datagram sent to a given address
/// lands in. A bound datagram socket registers its queue here under its local address; `sendto`
/// resolves the destination against it. Multicast memberships live in the sockets' records.
#[derive(Default)]
struct UdpRegistry {
    /// Bound address → the queue to deliver unicast datagrams for that exact address into. Keyed on
    /// the full `SocketAddr`, so several addresses on one port (snare 1.x's `add_ip_addr`) and a
    /// wildcard `0.0.0.0`/`::` bind coexist.
    bound: HashMap<SocketAddr, Arc<DgramQueue>>,
    by_port: HashMap<u16, UdpBindings>,
    endpoints: HashMap<IpAddr, usize>,
    ports: HashMap<IpAddr, UdpPorts>,
    families: [UdpPorts; 2],
    references: HashMap<(bool, u16), usize>,
    addresses: HashMap<(IpAddr, u16), usize>,
}

enum UdpCandidates {
    One(Option<Cand<Arc<DgramQueue>>>),
    Many(Vec<Cand<Arc<DgramQueue>>>),
}

struct UdpBindings {
    first: (SocketAddr, Arc<DgramQueue>),
    rest: Vec<(SocketAddr, Arc<DgramQueue>)>,
}

#[derive(Default)]
struct UdpPorts {
    words: Vec<u64>,
    first: usize,
    count: usize,
}

impl UdpPorts {
    const FIRST: u16 = 49152;
    const WORDS: usize = 256;

    fn insert(&mut self, port: u16) {
        let bit = usize::from(port - Self::FIRST);
        if self.words.len() <= bit / 64 {
            self.words.resize(bit / 64 + 1, 0);
        }
        self.words[bit / 64] |= 1 << (bit % 64);
        self.count += 1;
        while self.first < self.words.len() && self.words[self.first] == u64::MAX {
            self.first += 1;
        }
    }

    fn remove(&mut self, port: u16) {
        let bit = usize::from(port - Self::FIRST);
        self.words[bit / 64] &= !(1 << (bit % 64));
        self.first = self.first.min(bit / 64);
        self.count -= 1;
    }

    fn find(&self, start: usize, end: usize) -> Option<u16> {
        if self.words.is_empty() {
            return (start < end).then_some(Self::FIRST + start as u16);
        }
        let mut word = (start / 64).max(self.first);
        while word < Self::WORDS && word * 64 < end {
            let low = start.saturating_sub(word * 64);
            let high = (end - word * 64).min(64);
            let mask = (u64::MAX << low)
                & if high == 64 {
                    u64::MAX
                } else {
                    (1 << high) - 1
                };
            let free = !self.words.get(word).copied().unwrap_or(0) & mask;
            if free != 0 {
                return Some(Self::FIRST + (word * 64 + free.trailing_zeros() as usize) as u16);
            }
            word += 1;
        }
        None
    }

    fn alloc_from(&self, first: u16) -> u16 {
        let start = usize::from(first.max(Self::FIRST) - Self::FIRST);
        self.find(start, Self::WORDS * 64)
            .or_else(|| self.find(0, start))
            .unwrap_or(0)
    }
}

impl UdpRegistry {
    fn add_endpoint(&mut self, ip: IpAddr) {
        *self.endpoints.entry(ip).or_default() += 1;
    }

    fn remove_endpoint(&mut self, ip: IpAddr) {
        let count = self.endpoints.get_mut(&ip).unwrap();
        *count -= 1;
        if *count == 0 {
            self.endpoints.remove(&ip);
        }
    }

    fn insert(&mut self, addr: SocketAddr, queue: Arc<DgramQueue>) {
        let endpoint = queue.rec.is_none();
        let indexed = queue.clone();
        if let Some(previous) = self.bound.insert(addr, queue) {
            let bucket = self.by_port.get_mut(&addr.port()).unwrap();
            let entry = if bucket.first.0 == addr {
                &mut bucket.first
            } else {
                bucket
                    .rest
                    .iter_mut()
                    .find(|entry| entry.0 == addr)
                    .unwrap()
            };
            entry.1 = indexed;
            if previous.rec.is_none() != endpoint {
                if endpoint {
                    self.add_endpoint(addr.ip());
                } else {
                    self.remove_endpoint(addr.ip());
                }
            }
            return;
        }
        if endpoint {
            self.add_endpoint(addr.ip());
        }
        match self.by_port.entry(addr.port()) {
            std::collections::hash_map::Entry::Occupied(mut bucket) => {
                bucket.get_mut().rest.push((addr, indexed));
            }
            std::collections::hash_map::Entry::Vacant(bucket) => {
                bucket.insert(UdpBindings {
                    first: (addr, indexed),
                    rest: Vec::new(),
                });
            }
        }
        if addr.port() < UdpPorts::FIRST {
            return;
        }
        let addresses = self.addresses.entry((addr.ip(), addr.port())).or_default();
        if *addresses == 0 {
            self.ports.entry(addr.ip()).or_default().insert(addr.port());
        }
        *addresses += 1;
        let references = self
            .references
            .entry((addr.is_ipv4(), addr.port()))
            .or_default();
        if *references == 0 {
            self.families[usize::from(addr.is_ipv4())].insert(addr.port());
        }
        *references += 1;
    }

    fn remove(&mut self, addr: &SocketAddr) -> Option<Arc<DgramQueue>> {
        let queue = self.bound.remove(addr)?;
        if queue.rec.is_none() {
            self.remove_endpoint(addr.ip());
        }
        let bucket = self.by_port.get_mut(&addr.port()).unwrap();
        if bucket.first.0 == *addr {
            if let Some(last) = bucket.rest.pop() {
                bucket.first = last;
            } else {
                self.by_port.remove(&addr.port());
            }
        } else {
            let index = bucket
                .rest
                .iter()
                .position(|bound| bound.0 == *addr)
                .unwrap();
            bucket.rest.swap_remove(index);
        }
        if addr.port() >= UdpPorts::FIRST {
            let address = (addr.ip(), addr.port());
            let addresses = self.addresses.get_mut(&address).unwrap();
            *addresses -= 1;
            if *addresses == 0 {
                self.addresses.remove(&address);
                let ports = self.ports.get_mut(&addr.ip()).unwrap();
                ports.remove(addr.port());
                if ports.count == 0 {
                    self.ports.remove(&addr.ip());
                }
            }
            let key = (addr.is_ipv4(), addr.port());
            let references = self.references.get_mut(&key).unwrap();
            *references -= 1;
            if *references == 0 {
                self.references.remove(&key);
                self.families[usize::from(addr.is_ipv4())].remove(addr.port());
            }
        }
        Some(queue)
    }

    /// Picks a free ephemeral port for `ip` from the IANA dynamic range (RFC 6335), skipping any
    /// already bound on that IP — any IP for the wildcard. Called while the registry is locked,
    /// so the result stays free until the caller inserts it. Returns 0 once the range is full.
    ///
    /// 49152–65535 is the dynamic/private range of RFC 6335 §6 and macOS's default
    /// (`net.inet.ip.portrange.first`/`last`, XNU bsd/netinet/in.h `IPPORT_HIFIRSTAUTO`/
    /// `IPPORT_HILASTAUTO`). Linux defaults to 32768–60999 (Documentation/networking/
    /// ip-sysctl.rst, `ip_local_port_range`); using the IANA range everywhere is a snare choice,
    /// so addresses are the same on every host. The lowest free port is taken, not a random one.
    fn alloc_port(&self, ip: IpAddr) -> u16 {
        self.alloc_port_from(ip, 49152)
    }

    fn alloc_port_from(&self, ip: IpAddr, first: u16) -> u16 {
        if ip.is_unspecified() {
            self.families[usize::from(ip.is_ipv4())].alloc_from(first)
        } else {
            self.ports
                .get(&ip)
                .map_or(first.max(UdpPorts::FIRST), |ports| ports.alloc_from(first))
        }
    }

    /// The queues a datagram to `dest` could reach: for a multicast group the sockets on the port
    /// that take it ([`SockRec::takes_group`], given whether the host `joined` the group), else
    /// every queue bound on the port. Which of them actually receive it (exact address,
    /// wildcard, broadcast, the receiving interface) is decided by `SimShared::fan_out`; each
    /// candidate carries whether it is a tester endpoint and the interface the socket is bound
    /// to, if any.
    fn delivery_candidates(&self, dest: SocketAddr, joined: bool) -> UdpCandidates {
        let Some(bucket) = self.by_port.get(&dest.port()) else {
            return UdpCandidates::One(None);
        };
        if !bucket.rest.is_empty() {
            return UdpCandidates::Many(self.candidates(dest, joined));
        }
        let (addr, queue) = &bucket.first;
        let group = dest.ip();
        let accepted = !group.is_multicast()
            || queue
                .rec
                .as_ref()
                .is_some_and(|rec| rec.takes_group(*addr, group, joined));
        UdpCandidates::One(accepted.then(|| Self::candidate(*addr, queue)))
    }

    fn candidate(addr: SocketAddr, queue: &Arc<DgramQueue>) -> Cand<Arc<DgramQueue>> {
        Cand {
            addr,
            endpoint: queue.rec.is_none(),
            device: queue
                .rec
                .as_ref()
                .and_then(|rec| rec.state().device.as_ref().map(|device| device.0)),
            q: queue.clone(),
        }
    }

    fn candidates(&self, dest: SocketAddr, joined: bool) -> Vec<Cand<Arc<DgramQueue>>> {
        let Some(bucket) = self.by_port.get(&dest.port()) else {
            return Vec::new();
        };
        let group = dest.ip();
        std::iter::once(&bucket.first)
            .chain(bucket.rest.iter())
            .filter(|(addr, q)| {
                !group.is_multicast()
                    || q.rec
                        .as_ref()
                        .is_some_and(|r| r.takes_group(*addr, group, joined))
            })
            .map(|(addr, q)| Self::candidate(*addr, q))
            .collect()
    }
}

/// The wildcard address (`0.0.0.0` or `::`) of `ip`'s family.
fn unspecified_like(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

thread_local! {
    /// The registries of the `Sim` this thread runs in, set by [`enter`].
    static CURRENT: std::cell::RefCell<Option<Arc<Registries>>> = const { std::cell::RefCell::new(None) };
}

/// Installs `regs` as the calling thread's current registries until the guard drops. `Sim::run`
/// wraps the test body in this so testers and topology calls reach this sim's registries.
pub(crate) fn enter(regs: Arc<Registries>) -> RegistryGuard {
    let previous = CURRENT.with(|c| c.replace(Some(regs)));
    RegistryGuard { previous }
}

/// Restores the thread's previous registries on drop, so nested `Sim::run`s unwind correctly.
pub(crate) struct RegistryGuard {
    /// What [`CURRENT`] held before [`enter`].
    previous: Option<Arc<Registries>>,
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        CURRENT.with(|c| *c.borrow_mut() = self.previous.take());
    }
}

/// The calling thread's registries. Panics outside `Sim::run`, where a tester call has no sim.
fn current() -> Arc<Registries> {
    try_registries_here().expect("snare tester functions must be called inside Sim::run")
}

/// The registries of the `Sim` the calling thread runs in, if it runs in one.
pub(crate) fn try_registries_here() -> Option<Arc<Registries>> {
    CURRENT.with(|c| c.borrow().clone())
}

/// The registries of the `Sim` the calling thread runs in, for a tester to keep once it leaves
/// that thread.
pub(crate) fn registries_here() -> Arc<Registries> {
    current()
}

/// Gives every thread the sim starts this sim's registries, as `Sim::run` gives its own thread, so
/// testers, link policies and other tester-side calls work from any thread of the test.
pub(crate) struct ScopeLayer(pub(crate) Arc<Registries>);

impl snare_interpose::Layer for ScopeLayer {
    fn thread_started(&self) {
        // The scope lasts as long as the thread does.
        std::mem::forget(enter(self.0.clone()));
    }
}

/// Withdraws `listener` from its address, so later connects there are refused (ECONNREFUSED) as
/// they would be once a real server exits. Leaves a listener that has since replaced it alone.
pub(crate) fn unlisten(regs: &Registries, listener: &Arc<Listener>) {
    snare_interpose::real(|| {
        let mut listeners = regs.listeners.lock().unwrap();
        if listeners
            .get(&listener.addr)
            .is_some_and(|l| Arc::ptr_eq(l, listener))
        {
            listeners.remove(&listener.addr);
        }
    });
}

/// A datagram endpoint a tester owns at a fixed address: datagrams the code under test sends there
/// land in its queue, and what it sends carries that address as the source. Registered like a
/// bound socket, so broadcasts and wildcard binds behave the same; unregistered on drop.
pub(crate) struct UdpEndpoint {
    regs: Arc<Registries>,
    /// The fixed address it is bound at; its IP makes a station (see [`Registries::station_at`]).
    addr: SocketAddr,
    /// Its receive queue, with no socket record (`rec` is `None`), which marks it a tester's.
    queue: Arc<DgramQueue>,
}

impl UdpEndpoint {
    /// Binds `addr`. Panics if a socket or another tester already holds it, as a real bind would
    /// fail with EADDRINUSE.
    pub(crate) fn bind(regs: Arc<Registries>, addr: SocketAddr) -> Self {
        let queue = Arc::new(DgramQueue::default());
        snare_interpose::real(|| {
            let mut udp = regs.udp.lock().unwrap();
            assert!(
                !udp.bound.contains_key(&addr),
                "udp tester address {addr} is already bound"
            );
            udp.insert(addr, queue.clone());
        });
        UdpEndpoint { regs, addr, queue }
    }

    /// The next datagram received, with its source.
    pub(crate) fn try_recv(&self) -> Option<(SocketAddr, Vec<u8>)> {
        snare_interpose::real(|| {
            self.queue
                .pop(|_| true)
                .map(|(dg, _)| (dg.src, dg.data.into_vec()))
        })
    }

    /// Whether a datagram has arrived for it.
    pub(crate) fn has_pending(&self) -> bool {
        snare_interpose::real(|| self.queue.has(|_| true))
    }

    /// Sends one datagram to `dest` — a socket's address, a wildcard bind's port, the broadcast
    /// address or a multicast group — from this endpoint's address. It is captured as inbound
    /// traffic, delivered to the fabric's sockets and other endpoints, then offered to every
    /// attached [`ForeignUdp`] backend. One nothing takes counts in the host's UDP counters when
    /// it was the host's to take.
    pub(crate) fn send_to(&self, dest: SocketAddr, data: &[u8]) {
        snare_interpose::real(|| {
            let sender = Sender::Station(self.addr.ip());
            self.regs
                .shared
                .capture_udp(&sender, self.addr, dest, Dir::In, data, None);
            let mut reached = self.regs.deliver(&sender, self.addr, dest, data, true);
            let foreign: Vec<_> = self.regs.foreign_udp.lock().unwrap().clone();
            for backend in foreign.iter().filter_map(std::sync::Weak::upgrade) {
                reached += backend.deliver_from_peer(self.addr, dest, data);
            }
            if reached == 0 {
                let station = self.regs.station_at(dest.ip());
                self.regs.shared.count_unreceived(dest, station);
            }
        });
    }
}

/// Unregisters the address, unless a later bind has since taken it over.
impl Drop for UdpEndpoint {
    fn drop(&mut self) {
        snare_interpose::real(|| {
            let mut udp = self.regs.udp.lock().unwrap();
            if udp
                .bound
                .get(&self.addr)
                .is_some_and(|q| Arc::ptr_eq(q, &self.queue))
            {
                udp.remove(&self.addr);
            }
        });
    }
}

/// Registers (and returns) the peer listener for `addr`, replacing any earlier one. Unlike a
/// socket's `listen`, it skips the bind-conflict rules: a tester stands in for another host.
pub(crate) fn listen_at(addr: SocketAddr) -> Arc<Listener> {
    let listener = Arc::new(Listener {
        rec: None,
        addr,
        pending: Mutex::default(),
        capacity: AtomicUsize::new(usize::MAX),
        occupied: AtomicUsize::new(0),
        tester: true,
        arrivals: AtomicU64::new(0),
        ready_order: AtomicU64::new(0),
        ready_at: AtomicU64::new(0),
    });
    snare_interpose::real(|| {
        current()
            .listeners
            .lock()
            .unwrap()
            .insert(addr, listener.clone())
    });
    listener
}

pub(crate) use crate::readiness::readiness;
use crate::scope::SimShared;
use std::time::Duration;

use crate::faults::{ConnectAttempt, Outcome, Syn};
use crate::limits::{Arrival, RxQueue};
use crate::netif::{Cand, Hop, LinkState, Op, Sender, Wire};
use crate::pcapng::{Dir, TcpTap};
use crate::readiness::Deadline;
use crate::sockets::{Membership, RxProbe, SockRec, SocketKind, Taker, UnmodelledOption};
use crate::stream::{Ends, Pipe, Read, Sent};
use crate::tstamp::{Rx, Stamp};

/// One open file description's state, shared by every descriptor that aliases it.
/// `nonblocking` is its `O_NONBLOCK`; `rec` holds socket options, pending errors and stats.
enum Sock {
    /// A TCP socket neither connected nor listening; `local` is where `bind` put it. Also what a
    /// socket whose connect failed returns to, with the error pending in `rec`.
    Fresh {
        /// `AF_INET` or `AF_INET6`, for the family of the wildcard address an unbound socket
        /// reports or listens on.
        domain: c_int,
        local: Option<SocketAddr>,
        nonblocking: bool,
        rec: Arc<SockRec>,
    },
    /// A TCP connect waiting on its SYN's answer; every descriptor of the socket shares the
    /// attempt.
    Connecting {
        domain: c_int,
        local: Option<SocketAddr>,
        nonblocking: bool,
        rec: Arc<SockRec>,
        /// The address being connected to.
        dest: SocketAddr,
        /// The SYN schedule (retransmits, the answer the fault plan gives), played forward by
        /// [`Fabric::advance_connect`].
        attempt: Arc<Mutex<ConnectAttempt>>,
    },
    /// One end of an established connection: a TCP socket, or a `SOCK_STREAM` socketpair end.
    Stream {
        conn: Arc<Conn>,
        end: End,
        nonblocking: bool,
        rec: Arc<SockRec>,
    },
    /// A listening TCP socket, its [`Listener`] registered under its address.
    Listener {
        listener: Arc<Listener>,
        nonblocking: bool,
        rec: Arc<SockRec>,
    },
    /// A UDP datagram socket. `local` is its bound address (registered in [`UdpRegistry`]); `peer`
    /// is the address a `connect` fixed, which filters receives and lets a plain `send` work.
    Dgram {
        queue: Arc<DgramQueue>,
        domain: c_int,
        local: Option<SocketAddr>,
        peer: Option<SocketAddr>,
        nonblocking: bool,
        /// `SO_BROADCAST`: whether sends to a broadcast address are allowed (man 7 socket).
        broadcast: bool,
        rec: Arc<SockRec>,
    },
    /// One end of an `AF_UNIX` `SOCK_DGRAM` socketpair: datagrams land in `queue`, and a send goes
    /// to the other end's queue while that end is open.
    UnixDgram {
        queue: Arc<DgramQueue>,
        /// The other end's queue; weak, so it dies with the other end's last descriptor.
        peer: std::sync::Weak<DgramQueue>,
        nonblocking: bool,
        rec: Arc<SockRec>,
    },
    /// A counting eventfd (readiness wakeups), man 2 eventfd.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Event {
        ready_order: u64,
        ready_at: Duration,
        /// The 64-bit counter; readable while nonzero.
        counter: u64,
        nonblocking: bool,
        /// `EFD_SEMAPHORE`: a read takes 1 rather than the whole counter.
        semaphore: bool,
        /// Writes so far. Linux fs/eventfd.c `eventfd_write` wakes the fd's waiters with `EPOLLIN`
        /// on every write, even one to a counter already nonzero.
        writes: u64,
        /// Reads so far; `eventfd_read` there wakes with `EPOLLOUT`.
        reads: u64,
    },
    /// An epoll set: each watched fd's registration. Level-triggered unless registered with
    /// `EPOLLET` (see [`Edge`]); `EPOLLONESHOT` disables a registration once reported.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Epoll {
        interests: HashMap<(c_int, EpollIdentity), EpollInterest>,
    },
    /// A raw L2 endpoint on a virtual interface: whole Ethernet frames. On Linux this is an
    /// `AF_PACKET` socket (packet(7)); on macOS it is a `/dev/bpf*` device (bpf(4)); both share
    /// the frame fan-out.
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    Raw {
        /// The interface it is bound to (`sockaddr_ll.sll_ifindex` or `BIOCSETIF`); `None` until
        /// bound, and an unbound endpoint can neither send nor receive.
        ifindex: Option<u32>,
        /// Frames other raw endpoints on the interface sent, unbounded, oldest first.
        rx: VecDeque<Vec<u8>>,
        /// Frames received so far, each a wake of the socket (net/packet/af_packet.c
        /// `packet_rcv` calls `sk_data_ready`; XNU bsd/net/bpf.c `bpf_wakeup` per buffer).
        arrived: u64,
        nonblocking: bool,
        rec: Arc<SockRec>,
    },
    /// A kqueue set (macOS): read/write interest per fd plus user-event (waker) triggers, each
    /// carrying the caller's `udata`. The kqueue analogue of [`Sock::Epoll`]. See kevent(2). The
    /// state is behind an `Arc` so a `dup`/`F_DUPFD` of the queue fd aliases the same set — which
    /// mio's macOS `Waker` relies on (it clones the kqueue fd and triggers through the clone).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Kqueue { state: Arc<Mutex<KqueueState>> },
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum EpollIdentity {
    Local(u64),
    Foreign(u64),
    Untracked,
}

/// One fd's registration in an epoll set (man 2 epoll_ctl).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct EpollInterest {
    order: u64,
    pending_order: Option<(Duration, u64)>,
    /// The `events` mask given to `epoll_ctl`, `EPOLLET` and `EPOLLONESHOT` included.
    events: u32,
    /// The caller's `epoll_data`, echoed back by `epoll_wait`.
    data: u64,
    edge: Edge,
    /// Registered `EPOLLONESHOT` and reported: disabled until the next `EPOLL_CTL_MOD` (man 2
    /// epoll_ctl; fs/eventpoll.c `ep_send_events` strips the item's events to
    /// `EP_PRIVATE_BITS`).
    spent: bool,
}

/// The interest set of one kqueue: read/write interests keyed by fd, and user events keyed by
/// ident.
#[derive(Default)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) struct KqueueState {
    /// `EVFILT_READ` registrations by fd.
    reads: HashMap<c_int, Knote>,
    /// `EVFILT_WRITE` registrations by fd.
    writes: HashMap<c_int, Knote>,
    /// `EVFILT_USER` registrations by ident.
    users: HashMap<usize, UserNote>,
}

/// An `EVFILT_READ` or `EVFILT_WRITE` registration.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
struct Knote {
    udata: u64,
    /// `EV_CLEAR`, `EV_ONESHOT` and `EV_DISPATCH` as given when it was added: XNU
    /// bsd/kern/kern_event.c `kevent_register` keeps an existing knote's flags when it is added
    /// again, updating only its `udata` and filter state.
    flags: u16,
    /// `EV_DISABLE`d, or `EV_DISPATCH` and reported: not returned until `EV_ENABLE`.
    disabled: bool,
    /// Its `EV_CLEAR` state.
    edge: Edge,
}

/// An `EVFILT_USER` registration (mio's macOS `Waker`).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
struct UserNote {
    udata: u64,
    /// As for [`Knote::flags`].
    flags: u16,
    disabled: bool,
    /// Fired by `NOTE_TRIGGER`. kevent(2): it stays fired until retrieved with `EV_CLEAR` set
    /// (XNU bsd/kern/kern_event.c `filt_userprocess` resets it only under `EV_CLEAR`).
    triggered: bool,
}

struct SocketDescription {
    id: u64,
    sock: Sock,
    status_flags: c_int,
    descriptors: BTreeSet<c_int>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DescriptionKey {
    slot: usize,
    id: u64,
}

#[derive(Default)]
struct Sockets {
    descriptions: Vec<Option<SocketDescription>>,
    free_slots: Vec<usize>,
    descriptors: HashMap<c_int, DescriptionKey>,
    #[cfg(target_os = "linux")]
    identities: HashMap<u64, usize>,
    next_id: u64,
}

impl Sockets {
    fn identity(&self, fd: c_int) -> Option<u64> {
        self.descriptors.get(&fd).map(|key| key.id)
    }

    #[cfg(target_os = "linux")]
    fn get_identity(&self, id: u64) -> Option<&Sock> {
        let description = self
            .descriptions
            .get(*self.identities.get(&id)?)?
            .as_ref()?;
        (description.id == id).then_some(&description.sock)
    }

    fn get(&self, fd: &c_int) -> Option<&Sock> {
        let key = self.descriptors.get(fd)?;
        let description = self.descriptions.get(key.slot)?.as_ref()?;
        (description.id == key.id).then_some(&description.sock)
    }

    fn get_mut(&mut self, fd: &c_int) -> Option<&mut Sock> {
        Some(&mut self.description_mut(fd)?.sock)
    }

    fn description_mut(&mut self, fd: &c_int) -> Option<&mut SocketDescription> {
        let key = self.descriptors.get(fd)?;
        self.descriptions
            .get_mut(key.slot)?
            .as_mut()
            .filter(|description| description.id == key.id)
    }

    fn contains_key(&self, fd: &c_int) -> bool {
        self.descriptors.contains_key(fd)
    }

    fn insert(&mut self, fd: c_int, sock: Sock) {
        if let Some(description) = self.description_mut(&fd) {
            description.sock = sock;
        } else {
            self.next_id += 1;
            let id = self.next_id;
            let slot = self.free_slots.pop().unwrap_or_else(|| {
                self.descriptions.push(None);
                self.descriptions.len() - 1
            });
            self.descriptions[slot] = Some(SocketDescription {
                id,
                sock,
                status_flags: libc::O_RDWR,
                descriptors: BTreeSet::from([fd]),
            });
            self.descriptors.insert(fd, DescriptionKey { slot, id });
            #[cfg(target_os = "linux")]
            self.identities.insert(id, slot);
        }
    }

    fn alias(&mut self, fd: c_int, new_fd: c_int) {
        let key = self.descriptors[&fd];
        self.descriptors.insert(new_fd, key);
        self.descriptions[key.slot]
            .as_mut()
            .unwrap()
            .descriptors
            .insert(new_fd);
    }

    fn remove(&mut self, fd: &c_int) -> Option<Option<Sock>> {
        let key = self.descriptors.remove(fd)?;
        let description = self.descriptions[key.slot].as_mut().unwrap();
        description.descriptors.remove(fd);
        Some(if description.descriptors.is_empty() {
            let retired = self.descriptions[key.slot].take().unwrap();
            self.free_slots.push(key.slot);
            #[cfg(target_os = "linux")]
            self.identities.remove(&key.id);
            Some(retired.sock)
        } else {
            None
        })
    }

    #[cfg(target_os = "macos")]
    fn values(&self) -> impl Iterator<Item = &Sock> {
        self.descriptions
            .iter()
            .flatten()
            .map(|description| &description.sock)
    }

    fn iter(&self) -> impl Iterator<Item = (&c_int, &Sock)> {
        self.descriptors
            .iter()
            .map(|(fd, key)| (fd, &self.descriptions[key.slot].as_ref().unwrap().sock))
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = (&c_int, &mut Sock)> {
        self.descriptions.iter_mut().flatten().map(|description| {
            (
                description.descriptors.first().unwrap(),
                &mut description.sock,
            )
        })
    }
}

/// The [`Net`] the code under test's sockets route through.
///
/// Also the [`Fs`] that serves macOS `/dev/bpf*` devices.
pub struct Fabric {
    /// Every descriptor the fabric serves, by fd number. The first lock in the fabric's lock order;
    /// never held across a readiness bump or wait.
    socks: Mutex<Sockets>,
    regs: Arc<Registries>,
    /// A real `/dev/null` descriptor, `dup`ed to mint each virtual fd.
    devnull: c_int,
}

struct UdpSendEndpoint {
    local: Option<SocketAddr>,
    queue: Arc<DgramQueue>,
    domain: c_int,
    broadcast: bool,
    nonblocking: bool,
    rec: Arc<SockRec>,
}

impl UdpSendEndpoint {
    fn from_sock(sock: &Sock) -> Option<Self> {
        match sock {
            Sock::Dgram {
                local,
                queue,
                domain,
                broadcast,
                nonblocking,
                rec,
                ..
            } => Some(Self {
                local: *local,
                queue: queue.clone(),
                domain: *domain,
                broadcast: *broadcast,
                nonblocking: *nonblocking,
                rec: rec.clone(),
            }),
            _ => None,
        }
    }
}

struct DgramRecvEndpoint {
    queue: Arc<DgramQueue>,
    nonblocking: bool,
    rec: Arc<SockRec>,
}

impl DgramRecvEndpoint {
    fn from_sock(sock: &Sock) -> Option<Self> {
        match sock {
            Sock::Dgram {
                queue,
                nonblocking,
                rec,
                ..
            }
            | Sock::UnixDgram {
                queue,
                nonblocking,
                rec,
                ..
            } => Some(Self {
                queue: queue.clone(),
                nonblocking: *nonblocking,
                rec: rec.clone(),
            }),
            _ => None,
        }
    }
}

impl Fabric {
    /// A fabric with empty registries over the sim state `shared`.
    pub(crate) fn new(shared: Arc<SimShared>) -> Self {
        // A real fd we `dup` per virtual socket, so each has a unique number the OS won't reuse
        // and `close` frees. Opened with redirection off — we are constructed outside a domain.
        let devnull = snare_interpose::real(|| unsafe {
            libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC)
        });
        Fabric {
            socks: Mutex::new(Sockets::default()),
            regs: Arc::new(Registries::new(shared)),
            devnull,
        }
    }

    fn detach_fd(&self, fd: c_int) -> Option<()> {
        let (removed, rec, key) = {
            let mut socks = self.socks.lock().unwrap();
            let rec = socks.get(&fd)?.rec().cloned();
            let key = rec.as_ref().map(|rec| rec.wake_key()).or_else(|| {
                socks
                    .identity(fd)
                    .map(crate::readiness::WakeKey::Descriptor)
            });
            (socks.remove(&fd)?, rec, key)
        };
        self.retire_descriptor(fd, removed, rec, key);
        Some(())
    }

    fn retire_descriptor(
        &self,
        fd: c_int,
        sock: Option<Sock>,
        rec: Option<Arc<SockRec>>,
        key: Option<crate::readiness::WakeKey>,
    ) {
        let regs = self.regs.clone();
        let retired = rec.filter(|rec| {
            regs.shared
                .sockets
                .detach_replaced_fd(fd, rec, regs.shared.stamp())
        });
        snare_interpose::defer_descriptor_cleanup(Box::new(move || {
            Self::release_sock(&regs, sock);
            if let Some(rec) = retired {
                regs.shared.sockets.finish_replaced_fd(&rec);
            }
            if let Some(key) = key {
                regs.shared.bump_keys(&[key]);
            }
        }));
    }

    fn release_sock(regs: &Registries, sock: Option<Sock>) {
        match sock {
            Some(Sock::Stream { conn, end, rec, .. }) => {
                match rec.opts().linger {
                    Some(linger) if linger.is_zero() => conn.reset(end),
                    Some(linger) => {
                        conn.close(end);
                        let pipe = conn.write_pipe(end).clone();
                        readiness().wait_until_on(
                            "linger",
                            Some(Deadline::timeout(linger)),
                            &[rec.wake_key()],
                            || rec.pending_time(),
                            || pipe.delivered(),
                        );
                    }
                    None if conn.read_pipe(end).has_unread() && !conn.pair => conn.reset(end),
                    None => conn.close(end),
                }
                conn.read_pipe(end).abandon_reader();
                if conn.pair {
                    conn.read_pipe(end).close(|_| {});
                }
            }
            Some(Sock::Dgram {
                local: Some(local), ..
            }) => {
                regs.udp.lock().unwrap().remove(&local);
            }
            Some(Sock::Listener { listener, .. }) => {
                unlisten(regs, &listener);
                let orphans: Vec<_> = listener.pending.lock().unwrap().drain(..).collect();
                for conn in orphans {
                    conn.reset(End::B);
                }
            }
            _ => {}
        }
    }

    /// The deadline a blocking receive on `fd` should honour: `now + SO_RCVTIMEO` if one is set,
    /// else `None` (wait indefinitely). Under the virtual clock the deadline is a pending timer the
    /// quiescence time-skip can jump to, so a receive timeout advances virtual time like a sleep.
    fn recv_deadline(&self, fd: c_int) -> Option<Deadline> {
        let rec = self.rec(fd)?;
        Some(Deadline::timeout(rec.opts().rcvtimeo?))
    }

    /// The socket record of `fd`; `None` for an fd the fabric does not serve or one with no
    /// record (eventfd, epoll, kqueue).
    fn rec(&self, fd: c_int) -> Option<Arc<SockRec>> {
        self.socks.lock().unwrap().get(&fd)?.rec().cloned()
    }

    fn fd_interests(
        &self,
        fds: impl IntoIterator<Item = c_int>,
        keys: &mut crate::readiness::WakeKeys,
    ) -> bool {
        let mut time_sensitive = false;
        for fd in fds {
            let connecting = matches!(
                self.socks.lock().unwrap().get(&fd),
                Some(Sock::Connecting { .. })
            );
            if let Some(rec) = self.rec(fd).or_else(|| self.shared().sockets.lookup_fd(fd)) {
                keys.push(rec.wake_key());
                time_sensitive |= connecting || rec.pending_time();
            } else if let Some(id) = self.socks.lock().unwrap().identity(fd) {
                keys.push(crate::readiness::WakeKey::Descriptor(id));
            }
        }
        time_sensitive
    }

    fn bump_fds(&self, fds: impl IntoIterator<Item = c_int>) {
        let mut keys = crate::readiness::WakeKeys::default();
        self.fd_interests(fds, &mut keys);
        self.shared().bump_keys(keys.as_slice());
    }

    #[cfg(target_os = "linux")]
    fn epoll_interests(&self, epfd: c_int, keys: &mut crate::readiness::WakeKeys) -> bool {
        self.fd_interests([epfd], keys);
        let watched: Vec<_> = {
            let socks = self.socks.lock().unwrap();
            let Some(Sock::Epoll { interests }) = socks.get(&epfd) else {
                return false;
            };
            interests.keys().copied().collect()
        };
        let mut time_sensitive = false;
        for (fd, identity) in watched {
            let rec = match identity {
                EpollIdentity::Local(id) => {
                    let socks = self.socks.lock().unwrap();
                    let sock = socks.get_identity(id);
                    time_sensitive |= matches!(sock, Some(Sock::Connecting { .. }));
                    if sock.is_some() {
                        keys.push(crate::readiness::WakeKey::Descriptor(id));
                    }
                    sock.and_then(Sock::rec).cloned()
                }
                EpollIdentity::Foreign(id) => self.shared().sockets.lookup_raw_id(id),
                EpollIdentity::Untracked => self.shared().sockets.lookup_fd(fd),
            };
            if let Some(rec) = rec {
                keys.push(rec.wake_key());
                time_sensitive |= rec.pending_time();
            }
        }
        time_sensitive
    }

    #[cfg(target_os = "macos")]
    fn kqueue_interests(&self, kq: c_int, keys: &mut crate::readiness::WakeKeys) -> bool {
        self.fd_interests([kq], keys);
        let state = match self.socks.lock().unwrap().get(&kq) {
            Some(Sock::Kqueue { state }) => state.clone(),
            _ => return false,
        };
        let mut fds: Vec<_> = {
            let state = state.lock().unwrap();
            state
                .reads
                .keys()
                .chain(state.writes.keys())
                .copied()
                .collect()
        };
        fds.sort_unstable();
        fds.dedup();
        self.fd_interests(fds, keys)
    }

    /// The sim state shared with the other backends.
    fn shared(&self) -> &SimShared {
        &self.regs.shared
    }

    /// Mints a socket fd served by the fabric, with its record. Fails with the errno `dup` gave
    /// (EMFILE once the process is out of descriptors, man 2 dup).
    fn open_socket(
        &self,
        kind: SocketKind,
        flags: c_int,
        sock: impl FnOnce(Arc<SockRec>) -> Sock,
    ) -> Option<NetResult> {
        match self.reserve_fd_flags(flags) {
            Ok(fd) => {
                let rec = self.shared().new_socket(kind, fd);
                self.socks.lock().unwrap().insert(fd, sock(rec));
                ok(fd as i64)
            }
            Err(e) => err(e.raw_os_error().unwrap_or(libc::EMFILE)),
        }
    }

    /// The per-`Sim` registries, shared with the tester free functions for the run's duration.
    pub(crate) fn registries(&self) -> Arc<Registries> {
        self.regs.clone()
    }

    /// A fresh real fd number for a virtual descriptor: a `dup` of `/dev/null`, which the OS
    /// will not hand out again until the virtual descriptor's `close` closes it.
    fn reserve_fd(&self) -> io::Result<c_int> {
        let fd = unsafe { libc::dup(self.devnull) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    fn reserve_fd_flags(&self, flags: c_int) -> io::Result<c_int> {
        let fd = self.reserve_fd()?;
        #[cfg(target_os = "linux")]
        if flags & libc::SOCK_CLOEXEC != 0 {
            let result = snare_interpose::real(|| unsafe {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC)
            });
            if result < 0 {
                let error = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(error);
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = flags;
        Ok(fd)
    }

    /// Delivers one datagram from `fd` to `dest` along the route the host picks, binding the
    /// socket to the wildcard address at an ephemeral port first if it is unbound, so a receiver
    /// can reply. Returns the bytes "sent" — UDP succeeds even when nothing listens at `dest`, or
    /// the link drops the frame.
    ///
    /// Order of checks: the macOS send-buffer size limit, a pending error (an earlier ICMP error
    /// reported on this send), the route (its errno decided by `SimShared::route_send`, which is
    /// told whether `SO_BROADCAST` is on), a don't-fragment datagram too large for the egress
    /// interface (`netif::frag`), the autobind, then a stalled link. A datagram nothing receives triggers the ICMP port-unreachable model.
    fn udp_send(
        &self,
        fd: c_int,
        endpoint: UdpSendEndpoint,
        data: &[u8],
        dest: SocketAddr,
        flags: c_int,
    ) -> Option<NetResult> {
        if data.len() > if dest.is_ipv4() { 65507 } else { 65527 } {
            return if cfg!(target_os = "macos") && dest.is_ipv6() {
                ok(data.len() as i64)
            } else {
                err(libc::EMSGSIZE)
            };
        }
        let UdpSendEndpoint {
            local,
            queue,
            domain,
            broadcast,
            nonblocking,
            rec,
        } = endpoint;
        let nonblocking = nonblocking || flags & libc::MSG_DONTWAIT != 0;
        // macOS refuses a datagram larger than the send buffer: XNU bsd/kern/uipc_socket.c
        // sosendcheck, `atomic && resid > so->so_snd.sb_hiwat` → EMSGSIZE. Linux has no such
        // check. Pinned by socket_limits' `macos_udp_send_over_sndbuf_is_emsgsize`.
        if cfg!(target_os = "macos") && data.len() > rec.state().buf.sndbuf.max(0) as usize {
            return err(libc::EMSGSIZE);
        }
        #[cfg(target_os = "linux")]
        rec.land();
        if let Some(errno) = rec.take_error_as(self.shared(), Taker::Send) {
            return err(errno);
        }
        let station = self.regs.station_at(dest.ip());
        let sender =
            match self
                .shared()
                .route_send(&rec.view(local), dest, Op::Send, station, broadcast)
            {
                Ok(sender) => sender,
                Err(errno) => return err(errno),
            };
        if let Err(errno) = crate::netif::frag::check_send(
            self.shared(),
            &rec,
            domain == libc::AF_INET6,
            &sender,
            dest,
            data.len(),
        ) {
            return err(errno);
        }
        let local = match local {
            Some(local) => local,
            None => {
                let ip = unspecified_like(loopback_for(domain));
                match self.autobind(fd, &queue, &rec, ip) {
                    Ok(local) => local,
                    Err(errno) => return err(errno),
                }
            }
        };
        let src = sender.source(local);
        // A stalled link (`UdpPolicy::send_queue_depth == Some(0)`) holds the send back. A blocking
        // send that never unstalls (a quiescent deadlock) gives EAGAIN, as SO_SNDTIMEO expiry does.
        let stalled = || {
            let policies = &self.regs.shared.policies;
            policies.send_stalled(local) || policies.send_stalled(src)
        };
        if stalled() {
            if nonblocking {
                return would_block();
            }
            if !readiness()
                .wait_until_on("udp send", None, &[rec.wake_key()], &stalled, || !stalled())
            {
                return err(libc::EAGAIN);
            }
        }
        self.shared()
            .capture_udp(&sender, src, dest, Dir::Out, data, None);
        #[cfg(target_os = "linux")]
        let now = self.shared().tstamp_now();
        #[cfg(target_os = "linux")]
        crate::tstamp::udp_sent(&rec, now, None, || {
            crate::tstamp::looped_frame(src, dest, false, data)
        });
        if self.regs.deliver(&sender, src, dest, data, true) == 0 {
            self.shared()
                .unreachable_port(&rec, &sender, src, dest, data, station);
        }
        if rec.finish_udp_send(dest, sender.egress_name()) {
            self.shared().bump_keys(&[rec.wake_key()]);
        }
        ok(data.len() as i64)
    }

    /// Binds unbound datagram socket `fd` to `ip` at an ephemeral port, as the kernel does on the
    /// first send or connect of an unbound socket (man 7 udp: the socket layer assigns a free
    /// local port and binds the socket to `INADDR_ANY`). Takes `udp`, releases it, then `socks`;
    /// called with neither held.
    fn autobind(
        &self,
        fd: c_int,
        queue: &Arc<DgramQueue>,
        rec: &Arc<SockRec>,
        ip: IpAddr,
    ) -> Result<SocketAddr, c_int> {
        let mut regs = self.regs.udp.lock().unwrap();
        let first = queue.next_port.load(Ordering::Relaxed) as u16;
        let port = regs.alloc_port_from(ip, first);
        if port == 0 {
            return Err(libc::EAGAIN);
        }
        let sa = SocketAddr::new(ip, port);
        regs.insert(sa, queue.clone());
        drop(regs);
        if let Some(Sock::Dgram { local, .. }) = self.socks.lock().unwrap().get_mut(&fd) {
            *local = Some(sa);
        }
        rec.set_local(sa);
        Ok(sa)
    }
}

impl Fabric {
    /// Whether `fd` is an IPv6 socket (`Some(false)` for IPv4); `None` for a descriptor that is
    /// not an IP socket, such as a socketpair end.
    fn ipv6(&self, fd: c_int) -> Option<bool> {
        match self.socks.lock().unwrap().get(&fd)? {
            Sock::Fresh { domain, .. }
            | Sock::Connecting { domain, .. }
            | Sock::Dgram { domain, .. } => Some(*domain == libc::AF_INET6),
            Sock::Stream { conn, .. } if conn.pair => None,
            Sock::Stream { conn, end, .. } => Some(conn.local(*end).is_ipv6()),
            Sock::Listener { listener, .. } => Some(listener.addr.is_ipv6()),
            _ => None,
        }
    }

    /// How `fd` stands for the timestamp options: a datagram socket, a connected stream, or a
    /// TCP socket that is not connected.
    fn ts_kind(&self, fd: c_int) -> crate::tstamp::Kind {
        match self.socks.lock().unwrap().get(&fd) {
            Some(Sock::Stream { .. }) => crate::tstamp::Kind::Established,
            Some(Sock::Fresh { .. } | Sock::Connecting { .. } | Sock::Listener { .. }) => {
                crate::tstamp::Kind::Unconnected
            }
            _ => crate::tstamp::Kind::Datagram,
        }
    }

    /// A `setsockopt` nothing modelled: a [`harmless`] option's value is kept for `getsockopt`
    /// and it succeeds; any other is recorded on the socket as unmodelled
    /// ([`SimShared::unmodelled_option`]) and succeeds with no effect, or fails with
    /// `ENOPROTOOPT` under `strict_sockopts` (man 2 setsockopt: "The option is unknown at the
    /// level indicated"). A descriptor with no socket record (an eventfd, epoll or kqueue) just
    /// succeeds.
    ///
    /// # Safety
    /// `val` is null or holds `len` bytes.
    unsafe fn unmodelled_set(
        &self,
        rec: Option<&Arc<SockRec>>,
        level: c_int,
        name: c_int,
        val: *const u8,
        len: u32,
    ) -> Option<NetResult> {
        let Some(rec) = rec else {
            return ok(0);
        };
        if harmless(level, name) {
            let bytes = if val.is_null() {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(val, len as usize) }.to_vec()
            };
            rec.keep_ignored(level, name, &bytes);
            return ok(0);
        }
        if self
            .shared()
            .unmodelled_option(rec, UnmodelledOption::Set { level, name })
        {
            return err(libc::ENOPROTOOPT);
        }
        ok(0)
    }

    /// A `getsockopt` nothing modelled: a [`harmless`] option reads back what was set, or an
    /// `int` 0 (each one's default on Linux and macOS); any other is recorded as unmodelled and
    /// reads as an `int` 0, or fails with `ENOPROTOOPT` under `strict_sockopts`.
    ///
    /// # Safety
    /// `val`/`len` are null or the caller's buffer and its length.
    unsafe fn unmodelled_get(
        &self,
        rec: Option<&Arc<SockRec>>,
        level: c_int,
        name: c_int,
        val: *mut u8,
        len: *mut u32,
    ) -> Option<NetResult> {
        if let Some(rec) = rec {
            if harmless(level, name) {
                match rec.ignored_value(level, name) {
                    Some(bytes) if !val.is_null() && !len.is_null() => unsafe {
                        let n = bytes.len().min(*len as usize);
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), val, n);
                        *len = n as u32;
                    },
                    _ => unsafe { write_opt(0, val, len) },
                }
                return ok(0);
            }
            if self
                .shared()
                .unmodelled_option(rec, UnmodelledOption::Get { level, name })
            {
                return err(libc::ENOPROTOOPT);
            }
        }
        unsafe { write_opt(0, val, len) };
        ok(0)
    }

    /// Linux `SIOCGHWTSTAMP`/`SIOCSHWTSTAMP` on an interface of the topology, as
    /// net/core/dev_ioctl.c answers them for a device whose driver has no hardware timestamping
    /// (the plain fabric's interfaces have no clock): setting needs `CAP_NET_ADMIN` (`EPERM`,
    /// checked first), an unknown `ifr_name` is `ENODEV` (`dev_ifsioc`), and a known one
    /// `EOPNOTSUPP` (`dev_get_hwtstamp`/`dev_set_hwtstamp` with no `ndo_hwtstamp_*`). Measured
    /// on loopback by tests/timestamps.rs `hwtstamp_ioctl_os_truth`. `None` for other requests.
    ///
    /// # Safety
    /// `arg` is null or the caller's `struct ifreq`.
    #[cfg(target_os = "linux")]
    unsafe fn hwtstamp_ioctl(&self, request: u64, arg: i64) -> Option<NetResult> {
        /// include/uapi/linux/sockios.h.
        const SIOCSHWTSTAMP: u64 = 0x89b0;
        /// include/uapi/linux/sockios.h.
        const SIOCGHWTSTAMP: u64 = 0x89b1;
        if request != SIOCSHWTSTAMP && request != SIOCGHWTSTAMP {
            return None;
        }
        if request == SIOCSHWTSTAMP && !self.shared().sys.privileges().net_admin {
            return err(libc::EPERM);
        }
        let base = arg as *const u8;
        if base.is_null() {
            return err(libc::EFAULT);
        }
        let name: Vec<u8> = (0..libc::IFNAMSIZ)
            .map(|i| unsafe { *base.add(i) })
            .take_while(|&b| b != 0)
            .collect();
        let known = std::str::from_utf8(&name)
            .ok()
            .and_then(|name| self.shared().nic(name))
            .is_some();
        err(if known {
            libc::EOPNOTSUPP
        } else {
            libc::ENODEV
        })
    }
}

/// The options the fabric (and `SimHost`) accept and ignore on purpose, because nothing a test
/// can observe in the sim depends on them; their values are kept and read back:
///
/// - `SO_KEEPALIVE` and the TCP keepalive timers (`TCP_KEEPIDLE`/`TCP_KEEPINTVL`/`TCP_KEEPCNT`,
///   macOS `TCP_KEEPALIVE`): a connection in the sim never dies idle, so a probe would never
///   change an outcome.
/// - `TCP_NODELAY`, Linux `TCP_QUICKACK`: the sim has no Nagle delay and no delayed ACKs; every
///   write leaves at once.
/// - `SO_OOBINLINE`, `SO_DEBUG`: the sim sends no urgent data and keeps no debug trace.
/// - macOS `SO_NOSIGPIPE`: the sim never raises `SIGPIPE`; a write to a closed stream fails with
///   `EPIPE`, as with the option set. std sets it on every macOS socket.
/// - `IP_TOS`, `IP_TTL`, `IP_MULTICAST_TTL`, `IPV6_TCLASS`, `IPV6_UNICAST_HOPS`,
///   `IPV6_MULTICAST_HOPS`: the sim's links have no QoS and no hop count to run out.
///
/// Everything else not modelled — `SO_REUSEPORT`, `IP_MULTICAST_LOOP`, `IP_DROP_MEMBERSHIP`,
/// `IPV6_V6ONLY`, `SO_RCVLOWAT` and the rest — changes behaviour the sim does not reproduce, so
/// it is recorded as unmodelled.
#[cfg(unix)]
pub(crate) fn harmless(level: c_int, name: c_int) -> bool {
    match level {
        libc::SOL_SOCKET => {
            matches!(
                name,
                libc::SO_KEEPALIVE | libc::SO_OOBINLINE | libc::SO_DEBUG
            ) || (cfg!(target_os = "macos") && name == SO_NOSIGPIPE)
        }
        libc::IPPROTO_TCP => {
            name == libc::TCP_NODELAY
                || TCP_KEEPALIVE_TIMERS.contains(&name)
                || (cfg!(target_os = "linux") && name == TCP_QUICKACK)
        }
        libc::IPPROTO_IP => matches!(name, libc::IP_TOS | libc::IP_TTL | libc::IP_MULTICAST_TTL),
        libc::IPPROTO_IPV6 => matches!(
            name,
            libc::IPV6_TCLASS | libc::IPV6_UNICAST_HOPS | libc::IPV6_MULTICAST_HOPS
        ),
        _ => false,
    }
}

/// macOS `SO_NOSIGPIPE` (0x1022, XNU bsd/sys/socket.h).
const SO_NOSIGPIPE: c_int = 0x1022;
/// Linux `TCP_QUICKACK` (12, include/uapi/linux/tcp.h).
const TCP_QUICKACK: c_int = 12;
/// The TCP keepalive timers: Linux `TCP_KEEPIDLE` (4), `TCP_KEEPINTVL` (5), `TCP_KEEPCNT` (6)
/// (include/uapi/linux/tcp.h); macOS `TCP_KEEPALIVE` (0x10), `TCP_KEEPINTVL` (0x101),
/// `TCP_KEEPCNT` (0x102) (XNU bsd/netinet/tcp.h).
#[cfg(target_os = "linux")]
const TCP_KEEPALIVE_TIMERS: [c_int; 3] = [4, 5, 6];
#[cfg(target_os = "macos")]
const TCP_KEEPALIVE_TIMERS: [c_int; 3] = [0x10, 0x101, 0x102];

/// What an `ioctl` request a socket does not know fails with: `ENOTTY` on Linux (net/socket.c
/// `sock_do_ioctl` turns `-ENOIOCTLCMD` into it), `ENXIO` on macOS (measured; XNU's
/// `soioctl` falls through to the protocol's `pru_control`). Measured by
/// tests/strict_sockopts.rs `unknown_option_os_truth`.
const UNKNOWN_IOCTL: c_int = if cfg!(target_os = "linux") {
    libc::ENOTTY
} else {
    libc::ENXIO
};

impl Fabric {
    /// Linux `recvmsg(MSG_ERRQUEUE)`: on a datagram socket the oldest ICMP error `IP_RECVERR`
    /// queued (see [`SimShared::icmp_to`]) or transmit timestamp that has arrived, in arrival
    /// order, written as the `SimHost` writes one (`simhost::read_error_report`). Never blocks: an
    /// empty queue is `EAGAIN`
    /// (net/ipv4/ip_sockglue.c `ip_recv_error` returns `-EAGAIN` when `sock_dequeue_err_skb`
    /// finds nothing), and the miss charges the per-call latency so a polling loop lets a
    /// discrete clock move. Reading the report clears the pending error it raised.
    ///
    /// # Safety
    /// `hdr` is a valid `msghdr` (see [`scatter`]).
    #[cfg(target_os = "linux")]
    unsafe fn recv_errqueue(&self, fd: c_int, hdr: *mut libc::msghdr) -> Option<NetResult> {
        let (rec, v6) = match self.socks.lock().unwrap().get(&fd)? {
            Sock::Dgram { rec, domain, .. } => (rec.clone(), *domain == libc::AF_INET6),
            Sock::Stream { rec, conn, end, .. } => (rec.clone(), conn.local(*end).is_ipv6()),
            _ => return err(libc::EAGAIN),
        };
        if let Some(read) = unsafe {
            crate::simhost::read_error_report(&rec, hdr, v6, self.shared().tstamp_now().real)
        } {
            return Some(read);
        }
        snare_interpose::charge_latency();
        err(libc::EAGAIN)
    }

    /// `recvmsg` on a connected stream: what [`Fabric::stream_read`] reads, gathered into the
    /// iovecs, with no source address (`msg_namelen` 0, as `recvmsg(2)` leaves it for a
    /// connected stream) and, when the read took bytes, the receive timestamps of the last byte
    /// (Linux `tcp_recv_timestamp`; none on macOS, see [`crate::tstamp`]).
    ///
    /// # Safety
    /// `hdr` is a valid `msghdr` (see [`scatter`]).
    #[allow(clippy::unnecessary_cast)]
    unsafe fn recvmsg_stream(
        &self,
        fd: c_int,
        hdr: *mut libc::msghdr,
        flags: c_int,
    ) -> Option<NetResult> {
        let (iov, iovlen) = unsafe { ((*hdr).msg_iov, (*hdr).msg_iovlen as usize) };
        let want = if iov.is_null() {
            0
        } else {
            (0..iovlen)
                .map(|i| unsafe { (*iov.add(i)).iov_len })
                .sum::<usize>()
        };
        let direct = iovlen == 1
            && !iov.is_null()
            && want > 0
            && want <= isize::MAX as usize
            && unsafe { !(*iov).iov_base.is_null() };
        let mut buf = if direct { Vec::new() } else { vec![0u8; want] };
        let out = if direct {
            unsafe { std::slice::from_raw_parts_mut((*iov).iov_base.cast::<u8>(), want) }
        } else {
            &mut buf
        };
        let (n, stamp) = match self.stream_read(fd, out, flags)? {
            Ok(got) => got,
            Err(errno) => return err(errno),
        };
        let copied = if direct {
            n
        } else {
            unsafe { scatter(hdr, &buf[..n]) }
        };
        let cmsgs = match (stamp, self.rec(fd)) {
            (Some(at), Some(rec)) => {
                crate::tstamp::rx_cmsgs(Some(self.shared()), &rec, at, Rx::Stream, None)
            }
            _ => Vec::new(),
        };
        if let Some(at) = stamp.filter(|_| !cmsgs.is_empty()) {
            self.shared().reach_stamp(at);
        }
        unsafe {
            if !(*hdr).msg_name.is_null() {
                (*hdr).msg_namelen = 0;
            }
            let truncated = write_cmsg_list(hdr, &cmsgs);
            (*hdr).msg_flags = if truncated { libc::MSG_CTRUNC } else { 0 };
        }
        ok(copied as i64)
    }

    /// Reads what has arrived on stream socket `fd` into `out`, blocking as the socket does, with
    /// the stamp of the last byte read; `None` for an fd that is not a connected stream. A read
    /// returns what has arrived (up to `out.len()`), 0 at end of stream or after `SHUT_RD`,
    /// ECONNRESET after a reset, and blocks for data otherwise.
    fn stream_read(
        &self,
        fd: c_int,
        out: &mut [u8],
        flags: c_int,
    ) -> Option<Result<(usize, Option<Stamp>), c_int>> {
        let (conn, end, nonblocking, rec) = match self.socks.lock().unwrap().get(&fd)? {
            Sock::Stream {
                conn,
                end,
                nonblocking,
                rec,
            } => (conn.clone(), *end, *nonblocking, rec.clone()),
            _ => return None,
        };
        #[cfg(target_os = "macos")]
        conn.progress_tcp_shutdown();
        let pipe = conn.read_pipe(end);
        if out.is_empty() && cfg!(target_os = "macos") {
            return Some(Ok((0, None)));
        }
        let peek = flags & libc::MSG_PEEK != 0;
        let waitall =
            flags & libc::MSG_WAITALL != 0 && !nonblocking && flags & libc::MSG_DONTWAIT == 0;
        let mut copied = 0;
        let mut stamp = None;
        // Fixed before the loop so the SO_RCVTIMEO budget covers the whole call, not each wakeup.
        let deadline = rec.opts().rcvtimeo.map(Deadline::timeout);
        let taker = if flags & libc::MSG_PEEK != 0 {
            Taker::Peek
        } else {
            Taker::Recv
        };
        // man 2 recv: MSG_DONTWAIT makes this one call nonblocking regardless of the fd's mode.
        // A blocking read parks on the sim's readiness channel (not a per-pipe condvar) so it is
        // counted in quiescence and woken by the virtual-clock time-skip, exactly like UDP/raw.
        // Both Linux and macOS return queued bytes before a pending error, and the error before
        // end of stream (net/ipv4/tcp.c tcp_recvmsg_locked checks sk_err only once nothing was
        // copied, then RCV_SHUTDOWN; XNU bsd/kern/uipc_socket.c soreceive reads queued data
        // before so_error and so_error before SS_CANTRCVMORE). Linux checks SOCK_DONE (a FIN
        // received) ahead of sk_err, so an error arriving after the peer's FIN reads as end of
        // stream there; that order is not modelled.
        loop {
            #[cfg(target_os = "macos")]
            conn.progress_tcp_shutdown();
            let read = if peek {
                pipe.peek(out)
            } else {
                pipe.read(&mut out[copied..])
            };
            if matches!(read, Read::Shut | Read::Eof | Read::WouldBlock)
                && let Some(errno) = rec.take_error_as(self.shared(), taker)
            {
                return Some(if copied > 0 {
                    Ok((copied, stamp))
                } else {
                    Err(errno)
                });
            }
            match read {
                Read::Data(n) => {
                    copied = if peek { n } else { copied + n };
                    if !peek {
                        stamp = conn.took(end, n).or(stamp);
                    }
                    if !waitall
                        || copied == out.len()
                        || n == 0
                        || (peek && (pipe.read_eof() || rec.peek_error().is_some()))
                    {
                        return Some(Ok((copied, stamp)));
                    }
                    if peek
                        && !readiness().wait_until_on(
                            "tcp peek",
                            deadline,
                            &[rec.wake_key()],
                            || rec.pending_time(),
                            || {
                                rec.fionread() as usize >= out.len()
                                    || pipe.read_eof()
                                    || rec.peek_error().is_some()
                            },
                        )
                    {
                        return Some(Ok((copied, stamp)));
                    }
                }
                Read::Reset => {
                    return Some(match rec.take_error_as(self.shared(), taker) {
                        Some(errno) if copied == 0 => Err(errno),
                        _ => Ok((copied, stamp)),
                    });
                }
                Read::Shut | Read::Eof => return Some(Ok((copied, stamp))),
                Read::WouldBlock if nonblocking || flags & libc::MSG_DONTWAIT != 0 => {
                    snare_interpose::charge_latency();
                    return Some(Err(libc::EAGAIN));
                }
                Read::WouldBlock => {
                    // `false` is a timeout (SO_RCVTIMEO) or a quiescent deadlock; both are EAGAIN.
                    if !readiness().wait_until_on(
                        "tcp recv",
                        deadline,
                        &[rec.wake_key()],
                        || rec.pending_time(),
                        || {
                            #[cfg(target_os = "macos")]
                            conn.progress_tcp_shutdown();
                            pipe.readable_or_closed() || rec.peek_error().is_some()
                        },
                    ) {
                        return Some(if copied > 0 {
                            Ok((copied, stamp))
                        } else {
                            Err(libc::EAGAIN)
                        });
                    }
                }
            }
        }
    }

    /// Takes the next datagram for `endpoint`, blocking as the socket does, or returns the errno
    /// a receive fails with. `MSG_PEEK` returns the
    /// next datagram and leaves it queued, and reads a pending error without clearing it; `MSG_DONTWAIT` makes this one call nonblocking
    /// (man 2 recv). A blocking receive gives EAGAIN when `SO_RCVTIMEO` expires (man 7 socket)
    /// or when the domain is quiescent with nothing left to deliver.
    fn recv_dgram(
        &self,
        endpoint: &DgramRecvEndpoint,
        flags: c_int,
    ) -> Result<(Datagram, u32), c_int> {
        let DgramRecvEndpoint {
            queue,
            nonblocking,
            rec,
        } = endpoint;
        let nonblocking = *nonblocking || flags & libc::MSG_DONTWAIT != 0;
        let taker = if flags & libc::MSG_PEEK != 0 {
            Taker::Peek
        } else {
            Taker::Recv
        };
        #[cfg(target_os = "linux")]
        rec.land();
        // Linux reports a pending error before the datagrams already queued (net/ipv4/udp.c
        // __skb_recv_udp checks sock_error() at the top of its loop); macOS after them (XNU
        // bsd/kern/uipc_socket.c soreceive: with so_error set and data queued it `goto dontblock`).
        let error_first = cfg!(target_os = "linux");
        // A connected datagram socket only receives from its peer; an unconnected one from anyone.
        let accept = |_: SocketAddr| true;
        let deadline = if nonblocking {
            None
        } else {
            rec.opts().rcvtimeo.map(Deadline::timeout)
        };
        loop {
            #[cfg(target_os = "linux")]
            rec.land();
            if error_first && let Some(errno) = rec.take_error_as(self.shared(), taker) {
                return Err(errno);
            }
            let got = if matches!(taker, Taker::Peek) {
                queue.peek(accept)
            } else {
                queue.pop(accept)
            };
            if let Some(got) = got {
                return Ok(got);
            }
            if let Some(errno) = rec.take_error_as(self.shared(), taker) {
                return Err(errno);
            }
            if nonblocking {
                snare_interpose::charge_latency();
                return Err(libc::EAGAIN);
            }
            if !readiness().wait_until_on(
                "udp recv",
                deadline,
                &[rec.wake_key()],
                || rec.pending_time(),
                || queue.has(accept) || rec.peek_error().is_some(),
            ) {
                return Err(libc::EAGAIN); // quiescent deadlock or SO_RCVTIMEO timeout
            }
        }
    }

    unsafe fn recvfrom_dgram(
        &self,
        endpoint: DgramRecvEndpoint,
        buf: *mut u8,
        len: usize,
        flags: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        let (dg, _) = match self.recv_dgram(&endpoint, flags) {
            Ok(got) => got,
            Err(errno) => return err(errno),
        };
        #[cfg(target_os = "linux")]
        crate::tstamp::note_datagram_read(self.shared(), &endpoint.rec, dg.stamp, &dg.rx_fallback);
        let n = len.min(dg.data.len());
        unsafe { std::ptr::copy_nonoverlapping(dg.data.as_ptr(), buf, n) };
        if !addr.is_null() && !addr_len.is_null() {
            if dg.src == UNNAMED {
                unsafe { write_unnamed(addr, addr_len) };
            } else {
                unsafe { write_addr(dg.src, addr, addr_len) };
            }
        }
        ok(
            if cfg!(target_os = "linux") && flags & libc::MSG_TRUNC != 0 {
                dg.data.len()
            } else {
                n
            } as i64,
        )
    }
}

/// Scatters `data` across the iovecs of `hdr`, returning how much fit. What did not fit is
/// discarded, as a datagram's tail is (the caller sets `MSG_TRUNC`, man 2 recvmsg).
///
/// # Safety
/// `hdr` must point to a valid `msghdr` whose `msg_iov` holds `msg_iovlen` iovecs, each either
/// null-based or writable for `iov_len` bytes.
#[allow(clippy::unnecessary_cast)]
pub(crate) unsafe fn scatter(hdr: *const libc::msghdr, data: &[u8]) -> usize {
    let (iov, iovlen) = unsafe { ((*hdr).msg_iov, (*hdr).msg_iovlen as usize) };
    let mut copied = 0;
    if iov.is_null() {
        return 0;
    }
    for i in 0..iovlen {
        let v = unsafe { &*iov.add(i) };
        let take = (data.len() - copied).min(v.iov_len);
        if take == 0 || v.iov_base.is_null() {
            continue;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(data[copied..].as_ptr(), v.iov_base.cast::<u8>(), take)
        };
        copied += take;
    }
    copied
}

/// [`write_cmsg_list`] over borrowed payloads; `true` when every message fit.
///
/// # Safety
/// As [`write_cmsg_list`].
#[cfg(target_os = "linux")]
pub(crate) unsafe fn write_cmsgs_at(
    hdr: *mut libc::msghdr,
    msgs: &[(c_int, c_int, &[u8])],
) -> bool {
    let owned: Vec<crate::tstamp::Cmsg> = msgs
        .iter()
        .map(|&(level, ty, data)| (level, ty, data.to_vec()))
        .collect();
    !unsafe { write_cmsg_list(hdr, &owned) }
}

/// Writes control messages `(level, type, payload)` into `hdr`'s control buffer in order, setting
/// `msg_controllen` to the bytes written, as the host kernel copies them out; `true` when the
/// buffer cut some short, for the caller's `MSG_CTRUNC` (man 2 recvmsg).
///
/// Each message is laid out per man 3 cmsg: `CMSG_LEN(len)` in `cmsg_len`, the payload at
/// `CMSG_DATA`, the whole taking `CMSG_SPACE(len)`, padding zeroed. A message that does not fit:
///
/// - Linux (net/core/scm.c `put_cmsg`): with room for at least a `cmsghdr`, the part that fits is
///   written with `cmsg_len` cut to it; with less, or no control buffer at all, nothing is.
///   Either way it is truncated, and so is every message after it.
/// - macOS (XNU bsd/kern/uipc_syscalls.c `copyout_control`): the bytes that fit are copied as
///   they are, the header's `cmsg_len` uncut, and that is truncated; a message that finds the
///   buffer already full, or no control buffer, is dropped without `MSG_CTRUNC`.
///
/// Both measured by tests/timestamps.rs `short_control_buffer_os_truth`.
///
/// # Safety
/// `hdr` must point to a valid `msghdr` whose `msg_control`, when non-null, is writable for
/// `msg_controllen` bytes and aligned for `cmsghdr`.
pub(crate) unsafe fn write_cmsg_list(hdr: *mut libc::msghdr, msgs: &[crate::tstamp::Cmsg]) -> bool {
    let control = unsafe { (*hdr).msg_control }.cast::<u8>();
    let cap = if control.is_null() {
        0
    } else {
        #[allow(clippy::unnecessary_cast)]
        unsafe {
            (*hdr).msg_controllen as usize
        }
    };
    let mut used = 0;
    let mut truncated = false;
    for (level, ty, data) in msgs {
        let space = unsafe { libc::CMSG_SPACE(data.len() as u32) } as usize;
        let len = unsafe { libc::CMSG_LEN(data.len() as u32) } as usize;
        let room = cap - used;
        if space <= room {
            unsafe {
                let cmsg = control.add(used).cast::<libc::cmsghdr>();
                std::ptr::write_bytes(cmsg.cast::<u8>(), 0, space);
                (*cmsg).cmsg_level = *level;
                (*cmsg).cmsg_type = *ty;
                (*cmsg).cmsg_len = len as _;
                std::ptr::copy_nonoverlapping(data.as_ptr(), libc::CMSG_DATA(cmsg), data.len());
            }
            used += space;
            continue;
        }
        if cfg!(target_os = "linux") {
            truncated = true;
            if room >= size_of::<libc::cmsghdr>() {
                let mut whole = vec![0u8; space];
                unsafe {
                    let cmsg = whole.as_mut_ptr().cast::<libc::cmsghdr>();
                    (*cmsg).cmsg_level = *level;
                    (*cmsg).cmsg_type = *ty;
                    (*cmsg).cmsg_len = room as _;
                    std::ptr::copy_nonoverlapping(data.as_ptr(), libc::CMSG_DATA(cmsg), data.len());
                    std::ptr::copy_nonoverlapping(whole.as_ptr(), control.add(used), room);
                }
                used = cap;
            }
            break;
        }
        if room == 0 {
            continue;
        }
        let mut whole = vec![0u8; space];
        unsafe {
            let cmsg = whole.as_mut_ptr().cast::<libc::cmsghdr>();
            (*cmsg).cmsg_level = *level;
            (*cmsg).cmsg_type = *ty;
            (*cmsg).cmsg_len = len as _;
            std::ptr::copy_nonoverlapping(data.as_ptr(), libc::CMSG_DATA(cmsg), data.len());
            std::ptr::copy_nonoverlapping(whole.as_ptr(), control.add(used), room);
        }
        used = cap;
        truncated = true;
    }
    if !control.is_null() {
        unsafe { (*hdr).msg_controllen = used as _ };
    }
    truncated
}

pub(crate) fn duplicate_to(fd: c_int, newfd: c_int, flags: Option<c_int>) -> c_int {
    snare_interpose::real(|| unsafe {
        #[cfg(target_os = "linux")]
        if let Some(flags) = flags {
            return libc::dup3(fd, newfd, flags);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = flags;
        libc::dup2(fd, newfd)
    })
}

/// The `SOCK_NONBLOCK` type flag on Linux; macOS has no such flag (it uses `fcntl`). man 2 socket:
/// `type` carries the base type in its low bits ORed with SOCK_NONBLOCK / SOCK_CLOEXEC. The fabric
/// takes the base type as `ty & 0xff`, wider than the kernel's `SOCK_TYPE_MASK` (0xf,
/// include/linux/net.h) but clear of both flags (`O_NONBLOCK` 0x800 and `O_CLOEXEC` 0x80000 on
/// x86_64 and aarch64, include/uapi/asm-generic/fcntl.h).
fn sock_nonblock() -> c_int {
    #[cfg(target_os = "linux")]
    {
        libc::SOCK_NONBLOCK
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// `FIONREAD` (`SIOCINQ` on Linux) and Linux's `SIOCOUTQ` (`TIOCOUTQ`, man 7 udp/tcp): bytes
/// waiting to be read, and bytes not yet sent, which is always none here.
const FIONREAD: libc::c_ulong = libc::FIONREAD as libc::c_ulong;

/// Whether `request` is Linux's `SIOCOUTQ`, which include/uapi/linux/sockios.h defines as
/// `TIOCOUTQ` (0x5411 on most architectures). Always 0 here: a write lands in the peer's pipe at
/// once, so nothing stays in a send queue.
fn is_siocoutq(request: libc::c_ulong) -> bool {
    cfg!(target_os = "linux") && request == libc::TIOCOUTQ as libc::c_ulong
}

/// A handled call that returns `n`.
fn ok(n: i64) -> Option<NetResult> {
    Some(NetResult::Ok(n))
}

/// A non-blocking call that found nothing to do: `EAGAIN`, charged the call latency so a caller
/// busy-polling it still lets a discrete virtual clock move (see `snare_interpose::charge_latency`).
/// Called with no fabric lock held, since charging can wake waiters.
fn would_block() -> Option<NetResult> {
    snare_interpose::charge_latency();
    err(libc::EAGAIN)
}

/// A handled call that fails with `errno` (the interposer sets `errno` and returns -1).
fn err(errno: c_int) -> Option<NetResult> {
    Some(NetResult::Err(errno))
}

/// The interface queries of man 7 netdevice that the fabric answers from the topology on any
/// socket: Linux `SIOCGIFINDEX`/`SIOCGIFMTU`/`SIOCGIFFLAGS`/`SIOCGIFHWADDR`, macOS
/// `SIOCGIFFLAGS`/`SIOCGIFMTU` (`<sys/sockio.h>`).
///
/// Each takes a `struct ifreq`: `ifr_name[IFNAMSIZ]` (16 bytes, `<net/if.h>`) then the union the
/// answer is written into, at offset 16 on both systems.
mod ifreq {
    #[cfg(target_os = "linux")]
    pub(super) const INDEX: libc::c_ulong = libc::SIOCGIFINDEX;
    #[cfg(target_os = "linux")]
    pub(super) const HWADDR: libc::c_ulong = libc::SIOCGIFHWADDR;
    #[cfg(target_os = "linux")]
    pub(super) const MTU: libc::c_ulong = libc::SIOCGIFMTU;
    #[cfg(target_os = "linux")]
    pub(super) const FLAGS: libc::c_ulong = libc::SIOCGIFFLAGS;
    /// `_IOWR('i', 51, struct ifreq)` (XNU bsd/sys/sockio.h): `IOC_INOUT` 0xc000_0000 | 32-byte
    /// `ifreq` << 16 | 'i' << 8 | 51. `libc` does not export it for Apple targets.
    #[cfg(target_os = "macos")]
    pub(super) const MTU: libc::c_ulong = 0xc020_6933;
    /// `_IOWR('i', 17, struct ifreq)` (XNU bsd/sys/sockio.h), encoded as for [`MTU`].
    #[cfg(target_os = "macos")]
    pub(super) const FLAGS: libc::c_ulong = 0xc020_6911;
    /// An unknown `ifr_name`: Linux fails with ENODEV (net/core/dev_ioctl.c dev_ifsioc_locked),
    /// macOS with ENXIO (XNU bsd/net/if.c ifioctl_ifreq). Measured by nic_enumeration's
    /// `siocgif_unknown_name_os_truth`.
    pub(super) const UNKNOWN: i32 = if cfg!(target_os = "linux") {
        libc::ENODEV
    } else {
        libc::ENXIO
    };
}

/// `if_nametoindex` of an unknown name: glibc passes on SIOCGIFINDEX's ENODEV (man 3
/// if_nametoindex), macOS's libc sets ENXIO (macOS man 3 if_nametoindex). Measured by
/// nic_enumeration's `unknown_names_os_truth`.
const NAMETOINDEX_UNKNOWN: i32 = if cfg!(target_os = "linux") {
    libc::ENODEV
} else {
    libc::ENXIO
};

impl Fabric {
    /// Answers a [`ifreq`] interface query from the topology. Keyed by the name in the `ifreq`,
    /// not by `fd`, so it answers on any socket, including a real one the fabric does not own.
    /// `None` for any other request.
    ///
    /// Linux `SIOCGIFHWADDR` writes a `sockaddr` whose `sa_family` is the ARP hardware type and
    /// whose `sa_data` starts with the MAC (man 7 netdevice); `SIOCGIFFLAGS` a `short` of
    /// `IFF_*` flags, `SIOCGIFMTU` and `SIOCGIFINDEX` an `int`.
    ///
    /// # Safety
    /// `arg` must be null or point to a writable `struct ifreq`.
    unsafe fn nic_ioctl(&self, request: u64, arg: i64) -> Option<NetResult> {
        let request = request as libc::c_ulong;
        #[cfg(target_os = "linux")]
        let modelled = [ifreq::INDEX, ifreq::MTU, ifreq::FLAGS, ifreq::HWADDR];
        #[cfg(target_os = "macos")]
        let modelled = [ifreq::MTU, ifreq::FLAGS];
        if !modelled.contains(&request) {
            return None;
        }
        let base = arg as *mut u8;
        if base.is_null() {
            return err(libc::EFAULT);
        }
        let mut name = Vec::new();
        for i in 0..libc::IFNAMSIZ {
            let b = unsafe { *base.add(i) };
            if b == 0 {
                break;
            }
            name.push(b);
        }
        let Some(nic) = std::str::from_utf8(&name)
            .ok()
            .and_then(|name| self.shared().nic(name))
        else {
            return err(ifreq::UNKNOWN);
        };
        let field = unsafe { base.add(16) };
        match request {
            ifreq::MTU => unsafe { field.cast::<c_int>().write_unaligned(nic.spec.mtu as c_int) },
            ifreq::FLAGS => unsafe {
                field
                    .cast::<libc::c_short>()
                    .write_unaligned(crate::ifaddrs::flags(&nic) as u16 as libc::c_short)
            },
            #[cfg(target_os = "linux")]
            ifreq::INDEX => unsafe { field.cast::<c_int>().write_unaligned(nic.index as c_int) },
            #[cfg(target_os = "linux")]
            ifreq::HWADDR => {
                // include/uapi/linux/if_arp.h.
                const ARPHRD_ETHER: u16 = 1;
                const ARPHRD_LOOPBACK: u16 = 772;
                let family = if nic.loopback {
                    ARPHRD_LOOPBACK
                } else {
                    ARPHRD_ETHER
                };
                let mut sa = [0u8; 16];
                sa[..2].copy_from_slice(&family.to_ne_bytes());
                sa[2..8].copy_from_slice(&nic.hw_addr());
                unsafe { std::ptr::copy_nonoverlapping(sa.as_ptr(), field, sa.len()) };
            }
            _ => return None,
        }
        ok(0)
    }
}

/// The socket calls of the code under test. Every method returns `None` for an fd, family or type
/// the fabric does not serve, so the call reaches the next backend or the OS, and otherwise the
/// result or errno the host OS would give.
impl Net for Fabric {
    /// Whether `fd` is one of the fabric's virtual descriptors.
    fn owns(&self, fd: c_int) -> bool {
        self.socks.lock().unwrap().contains_key(&fd)
    }

    /// Opens an `AF_INET`/`AF_INET6` stream or datagram socket, or on Linux an `AF_PACKET` one;
    /// declines any other family or type (`AF_UNIX` sockets other than socketpairs, raw IP).
    /// `protocol` is not checked.
    unsafe fn socket(&self, domain: c_int, ty: c_int, _protocol: c_int) -> Option<NetResult> {
        let base = ty & 0xff;
        let nonblocking = ty & sock_nonblock() != 0;
        // AF_PACKET gives raw L2 access: SOCK_RAW passes whole frames incl. the Ethernet header,
        // SOCK_DGRAM has the link header cooked off. See packet(7).
        #[cfg(target_os = "linux")]
        if domain == libc::AF_PACKET {
            if base != libc::SOCK_RAW && base != libc::SOCK_DGRAM {
                return None;
            }
            // packet(7): only processes with CAP_NET_RAW may open packet sockets (EPERM,
            // net/packet/af_packet.c packet_create).
            if !self.shared().sys.has_cap(crate::limits::CAP_NET_RAW) {
                return err(libc::EPERM);
            }
            return self.open_socket(SocketKind::Packet, ty, |rec| Sock::Raw {
                ifindex: None,
                rx: VecDeque::new(),
                arrived: 0,
                nonblocking,
                rec,
            });
        }
        if domain != libc::AF_INET && domain != libc::AF_INET6 {
            return None;
        }
        if base == libc::SOCK_DGRAM {
            return self.open_socket(SocketKind::Udp, ty, |rec| Sock::Dgram {
                queue: DgramQueue::for_socket(&rec),
                domain,
                local: None,
                peer: None,
                nonblocking,
                broadcast: false,
                rec,
            });
        }
        if base != libc::SOCK_STREAM {
            return None;
        }
        self.open_socket(SocketKind::TcpStream, ty, |rec| Sock::Fresh {
            domain,
            local: None,
            nonblocking,
            rec,
        })
    }

    /// Opens a connected pair of `AF_UNIX` stream or datagram sockets (man 2 socketpair): a
    /// `Conn` with no addresses and no link policy for `SOCK_STREAM`, two queues pointing at
    /// each other for `SOCK_DGRAM`. Both fds are reserved before either is registered, so a
    /// failure leaks neither.
    unsafe fn socketpair(
        &self,
        domain: c_int,
        ty: c_int,
        protocol: c_int,
        fds: *mut c_int,
    ) -> Option<NetResult> {
        if domain != libc::AF_UNIX {
            return None;
        }
        let base = ty & 0xff;
        if base != libc::SOCK_STREAM && base != libc::SOCK_DGRAM {
            return None;
        }
        // Linux's unix_create also takes PF_UNIX as the protocol (net/unix/af_unix.c,
        // `protocol && protocol != PF_UNIX` → EPROTONOSUPPORT); Darwin only 0 (XNU
        // bsd/kern/uipc_socket.c socreate_internal: pffindproto finds no AF_UNIX protocol).
        if protocol != 0 && (cfg!(not(target_os = "linux")) || protocol != libc::PF_UNIX) {
            return err(libc::EPROTONOSUPPORT);
        }
        let nonblocking = ty & sock_nonblock() != 0;
        let (a, b) = match (self.reserve_fd_flags(ty), self.reserve_fd_flags(ty)) {
            (Ok(a), Ok(b)) => (a, b),
            (a, b) => {
                let mut errno = libc::EMFILE;
                for r in [a, b] {
                    match r {
                        Ok(fd) => unsafe {
                            libc::close(fd);
                        },
                        Err(e) => errno = e.raw_os_error().unwrap_or(errno),
                    }
                }
                return err(errno);
            }
        };
        let (ra, rb) = (
            self.shared().new_socket(SocketKind::Unix, a),
            self.shared().new_socket(SocketKind::Unix, b),
        );
        let (sa, sb) = if base == libc::SOCK_STREAM {
            let conn = Arc::new(Conn {
                a_to_b: Pipe::new(None, None, self.shared().domain_key()),
                b_to_a: Pipe::new(None, None, self.shared().domain_key()),
                client: UNNAMED,
                server: UNNAMED,
                regs: self.regs.clone(),
                hop: None,
                pair: true,
                tap: None,
                stamps: Default::default(),
                write_delays: Default::default(),
                #[cfg(target_os = "macos")]
                mac_shutdown: Default::default(),
            });
            conn.b_to_a.read_by(&ra);
            conn.a_to_b.read_by(&rb);
            conn.a_to_b.write_by(&ra);
            conn.b_to_a.write_by(&rb);
            let end = |end, rec| Sock::Stream {
                conn: conn.clone(),
                end,
                nonblocking,
                rec,
            };
            (end(End::A, ra), end(End::B, rb))
        } else {
            let (qa, qb) = (DgramQueue::for_socket(&ra), DgramQueue::for_socket(&rb));
            (
                Sock::UnixDgram {
                    peer: Arc::downgrade(&qb),
                    queue: qa.clone(),
                    nonblocking,
                    rec: ra,
                },
                Sock::UnixDgram {
                    peer: Arc::downgrade(&qa),
                    queue: qb,
                    nonblocking,
                    rec: rb,
                },
            )
        };
        let mut socks = self.socks.lock().unwrap();
        socks.insert(a, sa);
        socks.insert(b, sb);
        drop(socks);
        unsafe {
            fds.write(a);
            fds.add(1).write(b);
        }
        ok(0)
    }

    /// Binds a fresh TCP socket, a UDP socket, or (Linux) a packet socket to its interface.
    ///
    /// For TCP and UDP the address must be one the host holds or the wildcard
    /// (`SimShared::claim_address`, EADDRNOTAVAIL otherwise, man 7 ip) and a port the process may
    /// take (`bind_denied`: EACCES for a privileged port without the capability, man 7 ip). TCP
    /// then applies `tcp_bind_conflict` against every socket of the sim; UDP refuses only an
    /// exact duplicate (EADDRINUSE), as `SO_REUSEADDR` is not modelled for datagram sockets. Port 0
    /// takes an ephemeral port. A second bind of a bound socket is EINVAL (man 2 bind).
    unsafe fn bind(&self, fd: c_int, addr: *const u8, len: u32) -> Option<NetResult> {
        #[cfg(target_os = "linux")]
        {
            let mut socks = self.socks.lock().unwrap();
            if let Some(Sock::Raw { ifindex, .. }) = socks.get_mut(&fd) {
                if (len as usize) < size_of::<libc::sockaddr_ll>() {
                    return err(libc::EINVAL);
                }
                // packet(7): binding an AF_PACKET socket takes a struct sockaddr_ll; sll_ifindex
                // selects the interface (0 = any). We only model that field.
                let sll = unsafe { std::ptr::read_unaligned(addr.cast::<libc::sockaddr_ll>()) };
                *ifindex = Some(sll.sll_ifindex as u32);
                return ok(0);
            }
        }
        let mut socks = self.socks.lock().unwrap();
        match socks.get(&fd) {
            Some(Sock::Fresh {
                local: None, rec, ..
            }) => {
                let rec = rec.clone();
                let Some(want) = (unsafe { parse_addr(addr, len) }) else {
                    return err(libc::EINVAL);
                };
                if let Err(errno) = self.shared().claim_address(want.ip()) {
                    return err(errno);
                }
                if let Some(errno) = self.shared().sys.bind_denied(want) {
                    return err(errno);
                }
                let Some(want) = self.tcp_bind_addr(&socks, want, rec.opts().reuseaddr) else {
                    return err(libc::EADDRINUSE);
                };
                if let Some(Sock::Fresh { local, .. }) = socks.get_mut(&fd) {
                    *local = Some(want);
                }
                rec.set_local(want);
                return ok(0);
            }
            Some(Sock::Fresh { .. } | Sock::Stream { .. } | Sock::Listener { .. }) => {
                return err(libc::EINVAL); // man 2 bind: already bound
            }
            _ => {}
        }
        let Some(Sock::Dgram {
            queue, local, rec, ..
        }) = socks.get_mut(&fd)
        else {
            return None;
        };
        if local.is_some() {
            return err(libc::EINVAL); // man 2 bind: already bound
        }
        let Some(mut want) = (unsafe { parse_addr(addr, len) }) else {
            return err(libc::EINVAL);
        };
        if let Err(errno) = self.shared().claim_address(want.ip()) {
            return err(errno);
        }
        if let Some(errno) = self.shared().sys.bind_denied(want) {
            return err(errno);
        }
        let (queue, rec) = (queue.clone(), rec.clone());
        let mut regs = self.regs.udp.lock().unwrap();
        if want.port() == 0 {
            let port = regs.alloc_port(want.ip());
            if port == 0 {
                return err(if cfg!(target_os = "linux") {
                    libc::EADDRINUSE
                } else {
                    libc::EADDRNOTAVAIL
                });
            }
            want.set_port(port);
        } else if regs.bound.contains_key(&want) {
            return err(libc::EADDRINUSE);
        }
        regs.insert(want, queue);
        drop(regs);
        if let Some(Sock::Dgram { local, .. }) = socks.get_mut(&fd) {
            *local = Some(want);
        }
        rec.set_local(want);
        ok(0)
    }

    /// Turns a fresh TCP socket into a listener registered at its address. Listening on a connected socket is EINVAL
    /// (net/ipv4/af_inet.c inet_listen; XNU bsd/kern/uipc_socket.c solisten; macOS listen(2))
    /// and on a datagram socket EOPNOTSUPP (man 2 listen). A connecting socket also gets
    /// EOPNOTSUPP here, where both kernels give EINVAL.
    unsafe fn listen(&self, fd: c_int, backlog: c_int) -> Option<NetResult> {
        let maximum = self.shared().sys.limits().listen_backlog_max;
        let capacity = if cfg!(target_os = "linux") {
            (if backlog < 0 {
                maximum
            } else {
                (backlog as usize).min(maximum)
            })
            .saturating_add(1)
        } else if backlog <= 0 {
            maximum
        } else {
            (backlog as usize).min(maximum)
        };
        let mut socks = self.socks.lock().unwrap();
        let (domain, local, nonblocking, rec) = match socks.get(&fd)? {
            Sock::Fresh {
                domain,
                local,
                nonblocking,
                rec,
            } => (*domain, *local, *nonblocking, rec.clone()),
            // Listening again only changes the backlog (net/ipv4/af_inet.c __inet_listen_sk).
            Sock::Listener { listener, .. } => {
                listener.capacity.store(capacity, Ordering::Release);
                return ok(0);
            }
            Sock::Stream { .. } => return err(libc::EINVAL),
            _ => return err(libc::EOPNOTSUPP),
        };
        // An unbound socket listens on the wildcard address at an ephemeral port (man 7 ip).
        let addr = match local {
            Some(addr) => addr,
            None => {
                let wildcard = SocketAddr::new(unspecified_like(loopback_for(domain)), 0);
                match self.tcp_bind_addr(&socks, wildcard, rec.opts().reuseaddr) {
                    Some(addr) => addr,
                    None => return err(libc::EADDRINUSE),
                }
            }
        };
        let listener = Arc::new(Listener {
            rec: Some(Arc::downgrade(&rec)),
            addr,
            pending: Mutex::default(),
            capacity: AtomicUsize::new(capacity),
            occupied: AtomicUsize::new(0),
            tester: false,
            arrivals: AtomicU64::new(0),
            ready_order: AtomicU64::new(0),
            ready_at: AtomicU64::new(0),
        });
        self.regs
            .listeners
            .lock()
            .unwrap()
            .insert(addr, listener.clone());
        rec.set_kind(SocketKind::TcpListener);
        rec.set_local(addr);
        socks.insert(
            fd,
            Sock::Listener {
                listener,
                nonblocking,
                rec,
            },
        );
        ok(0)
    }

    /// Takes the oldest pending connection as a new stream fd, writing the peer's address to
    /// `addr`. `flags` is `accept4`'s: `SOCK_NONBLOCK` makes the new fd nonblocking (man 2
    /// accept4); otherwise it starts blocking whatever the listener's mode. That is Linux's rule
    /// (man 2 accept: the new socket does not inherit `O_NONBLOCK`); macOS's accept(2) gives the
    /// new socket "the same properties" as the listener, which is not modelled. If no fd can be
    /// reserved the connection goes back to the head of the queue.
    unsafe fn accept(
        &self,
        fd: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
        flags: c_int,
    ) -> Option<NetResult> {
        let (listener, nonblocking, lrec) = match self.socks.lock().unwrap().get(&fd)? {
            Sock::Listener {
                listener,
                nonblocking,
                rec,
            } => (listener.clone(), *nonblocking, rec.clone()),
            // man 2 accept: EINVAL when the socket is not listening.
            Sock::Fresh { .. } | Sock::Stream { .. } => return err(libc::EINVAL),
            _ => return err(libc::EOPNOTSUPP),
        };
        let pop = || listener.pending.lock().unwrap().pop_front();
        let conn = if let Some(conn) = pop() {
            conn
        } else if nonblocking {
            return would_block();
        } else {
            // Linux bounds a blocking accept by SO_RCVTIMEO (EAGAIN): net/ipv4/
            // inet_connection_sock.c inet_csk_accept waits `sock_rcvtimeo()`. macOS ignores it:
            // XNU bsd/kern/uipc_syscalls.c accept_nocancel sleeps with no timeout. Pinned by
            // tcp_server's `accept_honours_rcvtimeo`.
            let deadline = if cfg!(target_os = "linux") {
                lrec.opts().rcvtimeo.map(Deadline::timeout)
            } else {
                None
            };
            if !readiness().wait_until_on(
                "accept",
                deadline,
                &[lrec.wake_key()],
                || lrec.pending_time(),
                || listener.has_pending(),
            ) {
                return err(libc::EAGAIN);
            }
            match pop() {
                Some(conn) => conn,
                None => return err(libc::EAGAIN),
            }
        };
        snare_interpose::descriptor_transaction(|| {
            let new_fd = match self.reserve_fd_flags(flags) {
                Ok(new_fd) => new_fd,
                Err(e) => {
                    listener.pending.lock().unwrap().push_front(conn);
                    return err(e.raw_os_error().unwrap_or(libc::EMFILE));
                }
            };
            listener.occupied.fetch_sub(1, Ordering::AcqRel);
            let rec = self.shared().new_socket(SocketKind::TcpStream, new_fd);
            rec.set_ends(conn.server, conn.client);
            rec.set_listener(lrec.id);
            rec.inherit_buffers(&lrec);
            rec.note_conn_nic(self.shared().hop_name(conn.hop.as_ref()).as_deref());
            conn.a_to_b.read_by(&rec);
            conn.b_to_a.write_by(&rec);
            #[cfg(target_os = "macos")]
            conn.attach_tcp_probe(End::B, &rec);
            let peer = conn.client;
            self.socks.lock().unwrap().insert(
                new_fd,
                Sock::Stream {
                    conn,
                    end: End::B,
                    nonblocking: flags & sock_nonblock() != 0,
                    rec,
                },
            );
            if !addr.is_null() && !addr_len.is_null() {
                unsafe { write_addr(peer, addr, addr_len) };
            }
            ok(new_fd as i64)
        })
    }

    /// Connects a socket. A datagram socket only fixes its peer. A TCP socket probes the
    /// destination's SYN answer (`SimShared::syn_probe`, which applies the fault plan): a SYN a
    /// listener accepts at once establishes the connection and queues it on the listener;
    /// anything else becomes a `ConnectAttempt` played forward on the clock, returning
    /// EINPROGRESS for a nonblocking socket (man 2 connect) or waiting it out otherwise.
    ///
    /// On a socket already connecting: a nonblocking call reports EALREADY while it is pending,
    /// the failure (consuming it) or EISCONN once settled (man 2 connect). A blocking call on
    /// Linux waits for the same attempt, as `__inet_stream_connect` (net/ipv4/af_inet.c) does for
    /// a socket in SYN_SENT.
    unsafe fn connect(&self, fd: c_int, addr: *const u8, len: u32) -> Option<NetResult> {
        if !Net::owns(self, fd) {
            return None;
        }
        if !addr.is_null() && len as usize >= size_of::<libc::sa_family_t>() {
            let family = unsafe { (*addr.cast::<libc::sockaddr>()).sa_family } as c_int;
            if family == libc::AF_UNSPEC {
                let mut socks = self.socks.lock().unwrap();
                if let Some(Sock::Dgram {
                    peer,
                    local,
                    queue,
                    rec,
                    ..
                }) = socks.get_mut(&fd)
                {
                    *peer = None;
                    rec.set_peer(None);
                    if cfg!(target_os = "linux") {
                        if let Some(bound) = local.take() {
                            queue.next_port.store(
                                bound.port().checked_add(1).unwrap_or(49152) as u64,
                                Ordering::Relaxed,
                            );
                            self.regs.udp.lock().unwrap().remove(&bound);
                        }
                        rec.state().local = None;
                    }
                    return if cfg!(target_os = "macos") {
                        err(libc::EAFNOSUPPORT)
                    } else {
                        ok(0)
                    };
                }
            }
        }
        let Some(server) = (unsafe { parse_addr(addr, len) }) else {
            return err(libc::EINVAL);
        };
        // man 2 connect on a datagram socket: it sends nothing, it just fixes the default peer so a
        // later plain `send`/`recv` works and receives from other addresses are filtered out. An
        // unbound socket takes the route's source address at an ephemeral port.
        let station = self.regs.station_at(server.ip());
        let (domain, nonblocking, bound, rec) = {
            let socks = self.socks.lock().unwrap();
            match socks.get(&fd)? {
                Sock::Dgram {
                    local,
                    queue,
                    rec,
                    broadcast,
                    ..
                } => {
                    let (local, queue, rec, broadcast) =
                        (*local, queue.clone(), rec.clone(), *broadcast);
                    drop(socks);
                    let sender = match self.shared().route_send(
                        &rec.view(local),
                        server,
                        Op::Connect,
                        station,
                        broadcast,
                    ) {
                        Ok(sender) => sender,
                        Err(errno) => return err(errno),
                    };
                    if local.is_none() {
                        let ip = sender
                            .source(SocketAddr::new(unspecified_like(server.ip()), 0))
                            .ip();
                        if let Err(errno) = self.autobind(fd, &queue, &rec, ip) {
                            return err(errno);
                        }
                    }
                    if let Some(Sock::Dgram { peer, .. }) = self.socks.lock().unwrap().get_mut(&fd)
                    {
                        *peer = Some(server);
                    }
                    rec.set_peer(Some(server));
                    rec.note_tx_nic(sender.egress_name());
                    return ok(0);
                }
                Sock::Fresh {
                    domain,
                    nonblocking,
                    local,
                    rec,
                } => (*domain, *nonblocking, *local, rec.clone()),
                #[cfg(target_os = "linux")]
                Sock::Connecting {
                    nonblocking: false, ..
                } => {
                    drop(socks);
                    return self.await_connect(fd);
                }
                Sock::Connecting { .. } => {
                    drop(socks);
                    return match self.advance_connect(fd) {
                        Progress::Pending(_) => {
                            snare_interpose::charge_latency();
                            err(libc::EALREADY)
                        }
                        Progress::Settled(Outcome::Failed(errno), rec) => {
                            rec.take_error();
                            err(errno)
                        }
                        Progress::Settled(Outcome::Connected, _) => err(libc::EISCONN),
                        Progress::Idle => unsafe { self.connect(fd, addr, len) },
                    };
                }
                Sock::Stream { rec, .. }
                    if cfg!(target_os = "linux") && rec.state().connect_ack =>
                {
                    rec.state().connect_ack = false;
                    return ok(0);
                }
                Sock::Stream { .. } | Sock::Listener { .. } => return err(libc::EISCONN),
                _ => return err(libc::EOPNOTSUPP),
            }
        };
        rec.state().tcp_failed = false;
        let sender =
            match self
                .shared()
                .route_send(&rec.view(bound), server, Op::Connect, station, true)
            {
                Ok(sender) => sender,
                Err(errno) => return err(errno),
            };
        if bound == Some(server) {
            if cfg!(target_os = "macos") {
                return err(libc::EINVAL);
            }
            let pipe = Pipe::new(None, None, self.shared().domain_key());
            pipe.read_by(&rec);
            pipe.write_by(&rec);
            rec.set_ends(server, server);
            let conn = Arc::new(Conn {
                a_to_b: pipe.clone(),
                b_to_a: pipe,
                client: server,
                server,
                regs: self.regs.clone(),
                hop: None,
                pair: false,
                tap: None,
                stamps: Default::default(),
                write_delays: Default::default(),
                #[cfg(target_os = "macos")]
                mac_shutdown: Default::default(),
            });
            self.socks.lock().unwrap().insert(
                fd,
                Sock::Stream {
                    conn,
                    end: End::A,
                    nonblocking,
                    rec,
                },
            );
            return if nonblocking {
                err(libc::EINPROGRESS)
            } else {
                ok(0)
            };
        }
        crate::netstats::bump(&self.shared().stats.tcp(server.ip()).active_opens);
        let host_local = matches!(&sender, Sender::Host(path) if path.local);
        let listener = self.listener_for(server, host_local);
        let mut syn = self.shared().syn_probe(server, listener.is_some(), station);
        let admission = if matches!(syn, Syn::Accept) {
            listener.as_ref().and_then(Listener::reserve)
        } else {
            None
        };
        if matches!(syn, Syn::Accept) && admission.is_none() {
            syn = Syn::Silent;
        }
        let client = self.client_addr(server, bound, &sender);
        if client.port() == 0 {
            return err(libc::EADDRNOTAVAIL);
        }
        if let (Syn::Accept, Some(listener)) = (syn, &listener) {
            let conn = self.establish(&rec, server, client, &sender, listener.tester);
            if let Some(lrec) = listener.rec.as_ref().and_then(std::sync::Weak::upgrade) {
                conn.a_to_b.pending_reader(lrec.state().buf);
            }
            if let Some(tap) = &conn.tap {
                tap.open(false, Duration::ZERO);
            }
            self.socks.lock().unwrap().insert(
                fd,
                Sock::Stream {
                    conn: conn.clone(),
                    end: End::A,
                    nonblocking,
                    rec,
                },
            );
            admission
                .expect("accepted SYN reserves a queue entry")
                .queue(conn);
            let mut keys = crate::readiness::WakeKeys::default();
            self.fd_interests([fd], &mut keys);
            if let Some(key) = listener.wake_key() {
                keys.push(key);
            }
            self.shared().bump_keys(keys.as_slice());
            if nonblocking {
                if let Some(rec) = self.rec(fd) {
                    rec.state().connect_ack = cfg!(target_os = "linux");
                }
                return err(libc::EINPROGRESS);
            }
            return ok(0);
        }
        let plan = self.shared().syn_plan(&rec.opts(), syn);
        let server_in = listener.as_ref().is_none_or(|l| l.tester);
        let tap = self.shared().tcp_tap(&sender, client, server, server_in);
        let attempt = match ConnectAttempt::start(&plan, syn, client, tap) {
            Ok(attempt) => attempt,
            Err(Outcome::Failed(errno)) => {
                self.shared()
                    .connect_settled(server, Outcome::Failed(errno), false);
                if errno == libc::ECONNREFUSED && host_local {
                    crate::netstats::bump(&self.shared().stats.tcp(server.ip()).out_rsts);
                }
                if nonblocking {
                    rec.state().tcp_failed = true;
                    rec.set_pending_error(errno, None);
                    return err(libc::EINPROGRESS);
                }
                return err(errno);
            }
            Err(Outcome::Connected) => unreachable!("a SYN a listener accepts connects at once"),
        };
        self.socks.lock().unwrap().insert(
            fd,
            Sock::Connecting {
                domain,
                local: bound,
                nonblocking,
                rec,
                dest: server,
                attempt: Arc::new(Mutex::new(attempt)),
            },
        );
        // man 2 connect: a nonblocking socket's connect that cannot complete at once fails with
        // EINPROGRESS; poll for POLLOUT, then read SO_ERROR.
        if nonblocking {
            return err(libc::EINPROGRESS);
        }
        self.await_connect(fd)
    }

    /// Sends on a connected socket. A stream write takes what the window has room for, blocking
    /// (up to `SO_SNDTIMEO`) for room unless nonblocking or `MSG_DONTWAIT`; a pending error is
    /// reported first. A datagram socket sends one datagram to its connected peer. Any other
    /// socket is ENOTCONN (man 2 send).
    unsafe fn send(
        &self,
        fd: c_int,
        buf: *const u8,
        len: usize,
        flags: c_int,
    ) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        match socks.get(&fd) {
            Some(Sock::Stream {
                conn,
                end,
                rec,
                nonblocking,
            }) => {
                let bytes = unsafe { std::slice::from_raw_parts(buf, len) };
                let (conn, end, rec) = (conn.clone(), *end, rec.clone());
                let nonblocking = *nonblocking || flags & libc::MSG_DONTWAIT != 0;
                drop(socks);
                #[cfg(target_os = "macos")]
                conn.progress_tcp_shutdown();
                if (cfg!(target_os = "macos") && conn.write_pipe(end).is_write_shut())
                    || (conn.is_reset() && conn.write_pipe(end).reader_gone())
                {
                    return err(libc::EPIPE);
                }
                if let Some(errno) = rec.take_error_as(self.shared(), Taker::Send) {
                    return err(errno);
                }
                let sent = conn.write_pipe(end).send(
                    bytes,
                    nonblocking,
                    rec.opts().sndtimeo,
                    |rest| conn.write(end, rest),
                    || {
                        #[cfg(target_os = "macos")]
                        conn.progress_tcp_shutdown();
                        rec.peek_error().is_some()
                    },
                );
                // man 2 send: writing after our side shut down (or the stream closed) fails with
                // EPIPE, or ECONNRESET once the connection was reset (man 2 send); a send that
                // could not start in time fails with EAGAIN.
                match sent {
                    Sent::Bytes(n) => {
                        rec.count_sent();
                        #[cfg(target_os = "linux")]
                        if !conn.pair {
                            conn.write_pipe(end).timestamp_write(
                                self.shared().tstamp_now(),
                                &bytes[..n],
                                Duration::from_nanos(
                                    conn.write_delays[end.index()].load(Ordering::Relaxed),
                                ) * 2,
                            );
                        }
                        ok(n as i64)
                    }
                    Sent::Closed if conn.is_reset() => err(rec
                        .take_error_as(self.shared(), Taker::Send)
                        .unwrap_or(libc::EPIPE)),
                    Sent::Closed => err(libc::EPIPE),
                    Sent::WouldBlock | Sent::TimedOut | Sent::Stuck => err(libc::EAGAIN),
                    Sent::Error => err(rec
                        .take_error_as(self.shared(), Taker::Send)
                        .unwrap_or(libc::EAGAIN)),
                }
            }
            Some(Sock::UnixDgram { peer, rec, .. }) => {
                let (peer, rec) = (peer.upgrade(), rec.clone());
                drop(socks);
                let Some(peer) = peer else {
                    return err(PAIR_PEER_GONE);
                };
                let data = unsafe { std::slice::from_raw_parts(buf, len) };
                peer.push_after(
                    UNNAMED,
                    data,
                    Duration::ZERO,
                    None,
                    self.shared().tstamp_now(),
                    None,
                    self.shared().domain_key(),
                );
                rec.count_sent();
                ok(len as i64)
            }
            Some(sock @ Sock::Dgram { peer, .. }) => {
                // man 2 send: a datagram socket with no connected peer has nowhere to send.
                let Some(dest) = *peer else {
                    return err(libc::EDESTADDRREQ);
                };
                let endpoint = UdpSendEndpoint::from_sock(sock).unwrap();
                drop(socks);
                let data = unsafe { std::slice::from_raw_parts(buf, len) };
                self.udp_send(fd, endpoint, data, dest, flags)
            }
            Some(_) => err(libc::ENOTCONN),
            None => None,
        }
    }

    /// Sends one datagram to `addr`; declines a non-datagram socket with an address, so a
    /// `sendto` on a TCP socket reaches its `send` only through a null address.
    unsafe fn sendto(
        &self,
        fd: c_int,
        buf: *const u8,
        len: usize,
        flags: c_int,
        addr: *const u8,
        addr_len: u32,
    ) -> Option<NetResult> {
        // man 2 sendto: a null destination means "use the connected peer", i.e. a plain send.
        if addr.is_null() {
            return unsafe { self.send(fd, buf, len, flags) };
        }
        let endpoint = {
            let socks = self.socks.lock().unwrap();
            UdpSendEndpoint::from_sock(socks.get(&fd)?)?
        };
        let Some(dest) = (unsafe { parse_addr(addr, addr_len) }) else {
            return err(libc::EINVAL);
        };
        let data = unsafe { std::slice::from_raw_parts(buf, len) };
        self.udp_send(fd, endpoint, data, dest, flags)
    }

    /// Receives one datagram, truncated to `len` (the rest is discarded, man 7 udp), and writes
    /// its source to `addr`: the unnamed `AF_UNIX` address for a socketpair end. Returns the
    /// bytes copied. Declines (`None`) any socket that is not a datagram socket.
    unsafe fn recvfrom(
        &self,
        fd: c_int,
        buf: *mut u8,
        len: usize,
        flags: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        let endpoint = {
            let socks = self.socks.lock().unwrap();
            DgramRecvEndpoint::from_sock(socks.get(&fd)?)?
        };
        unsafe { self.recvfrom_dgram(endpoint, buf, len, flags, addr, addr_len) }
    }

    /// Receives one datagram into `msg`'s iovecs (man 2 recvmsg), setting `MSG_TRUNC` in
    /// `msg_flags` when it did not fit and `MSG_CTRUNC` when its control messages did not. The
    /// receive timestamps the socket asked for come first (see [`crate::tstamp`]); then, with
    /// Linux's `SO_RXQ_OVFL` on, a `SOL_SOCKET`/`SO_RXQ_OVFL` message carries the `u32` count of
    /// datagrams the socket has dropped since its creation, as recorded on this datagram (man 7
    /// socket); none is attached while the count is 0 (net/socket.c `__sock_recv_cmsgs` writes
    /// the timestamps, then the drops). On Linux `MSG_ERRQUEUE` reads the error queue instead
    /// (`Fabric::recv_errqueue`). A stream socket reads what has arrived
    /// ([`Fabric::recvmsg_stream`]).
    unsafe fn recvmsg(&self, fd: c_int, msg: *mut u8, flags: c_int) -> Option<NetResult> {
        if msg.is_null() {
            return Net::owns(self, fd).then_some(NetResult::Err(libc::EFAULT));
        }
        #[cfg(target_os = "linux")]
        if flags & libc::MSG_ERRQUEUE != 0 {
            return unsafe { self.recv_errqueue(fd, msg.cast()) };
        }
        let endpoint = {
            let socks = self.socks.lock().unwrap();
            let sock = socks.get(&fd)?;
            if matches!(sock, Sock::Stream { .. }) {
                None
            } else {
                Some(DgramRecvEndpoint::from_sock(sock)?)
            }
        };
        let Some(endpoint) = endpoint else {
            return unsafe { self.recvmsg_stream(fd, msg.cast(), flags) };
        };
        #[cfg(target_os = "linux")]
        let rxq_ovfl = endpoint.rec.state().buf.rxq_ovfl;
        let (dg, drops) = match self.recv_dgram(&endpoint, flags) {
            Ok(got) => got,
            Err(errno) => return err(errno),
        };
        let hdr = msg.cast::<libc::msghdr>();
        let copied = unsafe { scatter(hdr, &dg.data) };
        let mut msg_flags = 0;
        if copied < dg.data.len() {
            msg_flags |= libc::MSG_TRUNC;
        }
        unsafe {
            let name = (*hdr).msg_name.cast::<u8>();
            if !name.is_null() {
                let mut name_len = (*hdr).msg_namelen;
                if dg.src == UNNAMED {
                    write_unnamed(name, &mut name_len);
                } else {
                    write_addr(dg.src, name, &mut name_len);
                }
                (*hdr).msg_namelen = name_len;
            }
        }
        #[cfg(target_os = "linux")]
        let fallback = Some(dg.rx_fallback.as_ref());
        #[cfg(not(target_os = "linux"))]
        let fallback = None;
        #[allow(unused_mut)]
        let mut cmsgs = crate::tstamp::rx_cmsgs(
            Some(self.shared()),
            &endpoint.rec,
            dg.stamp,
            Rx::Datagram,
            fallback,
        );
        if !cmsgs.is_empty() {
            self.shared().reach_stamp(dg.stamp);
        }
        #[cfg(target_os = "linux")]
        if rxq_ovfl && drops > 0 {
            cmsgs.push((
                libc::SOL_SOCKET,
                crate::limits::SO_RXQ_OVFL,
                drops.to_ne_bytes().to_vec(),
            ));
        }
        #[cfg(not(target_os = "linux"))]
        let _ = drops;
        if unsafe { write_cmsg_list(hdr, &cmsgs) } {
            msg_flags |= libc::MSG_CTRUNC;
        }
        unsafe { (*hdr).msg_flags = msg_flags };
        // man 2 recv, MSG_TRUNC: in the call's flags it returns the datagram's real length even
        // when longer than the buffer (Linux only; macOS has no such input flag).
        let real_len = cfg!(target_os = "linux") && flags & libc::MSG_TRUNC != 0;
        ok(if real_len { dg.data.len() } else { copied } as i64)
    }

    /// Reads from a connected stream, or one datagram from a datagram socket. A stream read
    /// returns what has arrived (up to `len`), 0 at end of stream or after `SHUT_RD`, ECONNRESET
    /// after a reset, and blocks for data otherwise. Fresh and listening sockets are ENOTCONN.
    unsafe fn recv(&self, fd: c_int, buf: *mut u8, len: usize, flags: c_int) -> Option<NetResult> {
        let endpoint = {
            let socks = self.socks.lock().unwrap();
            match socks.get(&fd)? {
                Sock::Stream { .. } => None,
                sock => match DgramRecvEndpoint::from_sock(sock) {
                    Some(endpoint) => Some(endpoint),
                    None => return err(libc::ENOTCONN),
                },
            }
        };
        if let Some(endpoint) = endpoint {
            return unsafe {
                self.recvfrom_dgram(
                    endpoint,
                    buf,
                    len,
                    flags,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
        }
        let out = unsafe { std::slice::from_raw_parts_mut(buf, len) };
        match self.stream_read(fd, out, flags)? {
            Ok((n, _)) => ok(n as i64),
            Err(errno) => err(errno),
        }
    }

    /// Shuts down a stream's sending side (a FIN to the peer), its receiving side (later reads
    /// return 0), or both. A no-op on a connected datagram socket, a datagram socketpair end, a
    /// connecting socket, and the fabric's eventfd, epoll, raw and kqueue descriptors (where a
    /// real kernel would refuse with ENOTSOCK or EOPNOTSUPP).
    unsafe fn shutdown(&self, fd: c_int, how: c_int) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        let sock = socks.get(&fd)?;
        // man 2 shutdown: `how` is SHUT_RD, SHUT_WR or SHUT_RDWR, else EINVAL; a socket that is
        // not connected gives ENOTCONN.
        if ![libc::SHUT_RD, libc::SHUT_WR, libc::SHUT_RDWR].contains(&how) {
            return err(libc::EINVAL);
        }
        match sock {
            Sock::Stream { conn, end, .. } => {
                let (conn, end) = (conn.clone(), *end);
                drop(socks);
                #[cfg(target_os = "macos")]
                conn.progress_tcp_shutdown();
                if how != libc::SHUT_WR {
                    if cfg!(target_os = "macos")
                        && (conn.read_pipe(end).is_read_shut() || conn.read_pipe(end).is_closed())
                    {
                        return err(libc::ENOTCONN);
                    }
                    #[cfg(target_os = "macos")]
                    conn.shut_read_tcp(end);
                    #[cfg(not(target_os = "macos"))]
                    conn.read_pipe(end).shut_read();
                }
                if how != libc::SHUT_RD {
                    #[cfg(target_os = "macos")]
                    if conn.write_pipe(end).is_write_closed() {
                        return err(libc::ENOTCONN);
                    }
                    conn.close(end);
                }
                ok(0)
            }
            Sock::Fresh { .. } | Sock::Listener { .. } | Sock::Dgram { peer: None, .. } => {
                err(libc::ENOTCONN)
            }
            _ => ok(0),
        }
    }

    /// Closes a descriptor. Only the last descriptor of a socket (see `F_DUPFD`) tears it down:
    /// a stream end sends its FIN (or RST, per `SO_LINGER`), a datagram socket leaves the address
    /// and group registries, and a listener unregisters and resets its unaccepted connections.
    /// The real fd behind it is closed in every case.
    unsafe fn close(&self, fd: c_int) -> Option<NetResult> {
        self.detach_fd(fd)?;
        let ret = unsafe { libc::close(fd) };
        ok(ret as i64)
    }

    unsafe fn fd_replaced(&self, fd: c_int) -> Option<NetResult> {
        self.detach_fd(fd)?;
        ok(0)
    }

    unsafe fn dup_to(&self, fd: c_int, newfd: c_int, flags: Option<c_int>) -> Option<NetResult> {
        let mut socks = self.socks.lock().unwrap();
        let rec = socks.get(&fd)?.rec().cloned();
        let result = duplicate_to(fd, newfd, flags);
        if result < 0 {
            return err(io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EBADF));
        }
        if fd == newfd || socks.descriptors.get(&fd) == socks.descriptors.get(&newfd) {
            return ok(result as i64);
        }
        let previous = socks.get(&newfd).and_then(Sock::rec).cloned();
        let previous_key = previous.as_ref().map(|rec| rec.wake_key()).or_else(|| {
            socks
                .identity(newfd)
                .map(crate::readiness::WakeKey::Descriptor)
        });
        let removed = socks.remove(&newfd).flatten();
        socks.alias(fd, newfd);
        if let Some(rec) = rec {
            self.shared().sockets.alias(newfd, &rec);
        }
        drop(socks);
        self.retire_descriptor(newfd, removed, previous, previous_key);
        ok(result as i64)
    }

    /// The connected peer's address; the unnamed `AF_UNIX` address for a socketpair end, ENOTCONN
    /// for an unconnected socket (man 2 getpeername). A truncated buffer gets the address's
    /// prefix and the full length, as man 2 getpeername describes.
    unsafe fn getpeername(
        &self,
        fd: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        let peer = match socks.get(&fd)? {
            Sock::Stream { conn, .. } if conn.pair => None,
            Sock::UnixDgram { .. } => None,
            Sock::Stream { conn, end, .. } => Some(conn.peer(*end)),
            Sock::Dgram {
                peer: Some(peer), ..
            } => Some(*peer),
            _ => return err(libc::ENOTCONN),
        };
        drop(socks);
        match peer {
            Some(peer) => unsafe { write_addr(peer, addr, addr_len) },
            None => unsafe { write_unnamed(addr, addr_len) },
        }
        ok(0)
    }

    /// The socket's own address; the unnamed `AF_UNIX` address for a socketpair end. An unbound
    /// socket reports its family's wildcard at port 0. Truncation is as for `getpeername`.
    unsafe fn getsockname(
        &self,
        fd: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        let local = match socks.get(&fd)? {
            Sock::Stream { conn, .. } if conn.pair => None,
            Sock::UnixDgram { .. } => None,
            Sock::Stream { conn, end, .. } => Some(conn.local(*end)),
            Sock::Listener { listener, .. } => Some(listener.addr),
            Sock::Dgram { local, domain, .. }
            | Sock::Fresh { local, domain, .. }
            | Sock::Connecting { local, domain, .. } => Some(
                local
                    .unwrap_or_else(|| SocketAddr::new(unspecified_like(loopback_for(*domain)), 0)),
            ),
            _ => return None,
        };
        drop(socks);
        match local {
            Some(local) => unsafe { write_addr(local, addr, addr_len) },
            None => unsafe { write_unnamed(addr, addr_len) },
        }
        ok(0)
    }

    /// Sets a socket option. The interface/routing options (`netif::sockopt`) and buffer/limit
    /// options (`limits::sockopt`) are tried first, then the don't-fragment options of an IP
    /// socket (`netif::frag`), the TCP fault options
    /// (`faults::sockopt`), the timestamp options and Linux `SO_TXTIME` (`tstamp`), then the ones
    /// kept here:
    /// `SO_BROADCAST`, the timeouts, `SO_REUSEADDR`, `SO_LINGER` (and macOS `SO_LINGER_SEC`),
    /// Linux `IP_RECVERR`/`IPV6_RECVERR`, and multicast joins. The rest go to
    /// [`Fabric::unmodelled_set`]: the [`harmless`] ones are kept and ignored, any other is
    /// recorded as unmodelled and accepted, or refused under `strict_sockopts`.
    unsafe fn setsockopt(
        &self,
        fd: c_int,
        level: c_int,
        name: c_int,
        val: *const u8,
        len: u32,
    ) -> Option<NetResult> {
        if !Net::owns(self, fd) {
            return None;
        }
        if let Some(rec) = self.rec(fd)
            && let Some(result) = unsafe {
                crate::netif::sockopt::set(self.shared(), &rec, level, name, val, len).or_else(
                    || crate::limits::sockopt::set(self.shared(), &rec, level, name, val, len),
                )
            }
        {
            return match result {
                Ok(()) => ok(0),
                Err(errno) => err(errno),
            };
        }
        if let Some(rec) = self.rec(fd)
            && let Some(v6) = self.ipv6(fd)
            && let Some(result) =
                unsafe { crate::netif::frag::set(&rec, v6, level, name, val, len) }
        {
            return match result {
                Ok(()) => ok(0),
                Err(errno) => err(errno),
            };
        }
        if level == libc::IPPROTO_TCP
            && let Some(rec) = self.rec(fd)
            && let Some(result) = unsafe { crate::faults::sockopt::set(&rec, name, val, len) }
        {
            return match result {
                Ok(()) => ok(0),
                Err(errno) => err(errno),
            };
        }
        if let Some(rec) = self.rec(fd)
            && let Some(result) = unsafe {
                crate::tstamp::set(
                    Some(self.shared()),
                    &rec,
                    self.ts_kind(fd),
                    level,
                    name,
                    val,
                    len,
                )
            }
        {
            return match result {
                Ok(()) => ok(0),
                Err(errno) => err(errno),
            };
        }
        #[cfg(target_os = "linux")]
        if let Some(rec) = self.rec(fd) {
            let net_admin = self.shared().sys.has_cap(crate::limits::CAP_NET_ADMIN);
            if let Some(result) =
                unsafe { crate::tstamp::set_txtime(&rec, net_admin, level, name, val, len) }
            {
                return match result {
                    Ok(()) => ok(0),
                    Err(errno) => err(errno),
                };
            }
        }
        // man 7 socket: SO_BROADCAST permits sending to a broadcast address.
        if level == libc::SOL_SOCKET && name == libc::SO_BROADCAST {
            let on = unsafe { read_int(val, len) } != 0;
            if let Some(Sock::Dgram { broadcast, .. }) = self.socks.lock().unwrap().get_mut(&fd) {
                *broadcast = on;
            }
            return ok(0);
        }
        if level == libc::SOL_SOCKET
            && let Some(rec) = self.rec(fd)
        {
            // man 7 socket: SO_RCVTIMEO/SO_SNDTIMEO bound how long a blocking receive/send waits;
            // a zero timeval clears them (block indefinitely again).
            let timeout = || unsafe { parse_timeval(val, len) }.filter(|d| !d.is_zero());
            let mut state = rec.state();
            match name {
                libc::SO_RCVTIMEO => state.opts.rcvtimeo = timeout(),
                libc::SO_SNDTIMEO => state.opts.sndtimeo = timeout(),
                libc::SO_REUSEADDR => state.opts.reuseaddr = unsafe { read_int(val, len) } != 0,
                libc::SO_LINGER => {
                    state.opts.linger = unsafe { parse_linger(val, len, LINGER_UNIT) }
                }
                #[cfg(target_os = "macos")]
                SO_LINGER_SEC => {
                    state.opts.linger = unsafe { parse_linger(val, len, Duration::from_secs(1)) }
                }
                _ => {
                    drop(state);
                    return unsafe { self.unmodelled_set(Some(&rec), level, name, val, len) };
                }
            }
            return ok(0);
        }
        // IP_RECVERR(2const): queues errors on a datagram socket. Without it Linux reports an
        // ICMP error only on a connected socket (net/ipv4/udp.c udp_err), so it is what makes
        // errors fail calls on an unconnected one too.
        #[cfg(target_os = "linux")]
        if (level, name) == (libc::IPPROTO_IP, libc::IP_RECVERR)
            || (level, name) == (libc::IPPROTO_IPV6, libc::IPV6_RECVERR)
        {
            if let Some(rec) = self.rec(fd) {
                rec.state().dgram.recverr = unsafe { read_int(val, len) } != 0;
            }
            return ok(0);
        }
        // IP_ADD_MEMBERSHIP(2const) / IPV6_ADD_MEMBERSHIP(2const): joining a multicast group so
        // datagrams to it are delivered here.
        let drop_group = (level == libc::IPPROTO_IP && name == libc::IP_DROP_MEMBERSHIP)
            || (level == libc::IPPROTO_IPV6 && name == IPV6_LEAVE);
        let membership_name = if drop_group {
            if level == libc::IPPROTO_IP {
                libc::IP_ADD_MEMBERSHIP
            } else {
                IPV6_JOIN
            }
        } else {
            name
        };
        if let Some(membership) = unsafe { parse_add_membership(level, membership_name, val, len) }
        {
            if let Some(rec) = self.rec(fd) {
                return match rec.change_membership(membership, !drop_group) {
                    Ok(()) => ok(0),
                    Err(errno) => err(errno),
                };
            }
            return err(libc::ENOTSOCK);
        }
        unsafe { self.unmodelled_set(self.rec(fd).as_ref(), level, name, val, len) }
    }

    /// Reads a socket option, consulting the same owners as [`setsockopt`](Net::setsockopt).
    /// `SO_ERROR` first moves a pending connect on, so a caller polling it after EINPROGRESS sees
    /// the attempt settle. Any other option goes to [`Fabric::unmodelled_get`].
    unsafe fn getsockopt(
        &self,
        fd: c_int,
        level: c_int,
        name: c_int,
        val: *mut u8,
        len: *mut u32,
    ) -> Option<NetResult> {
        if !Net::owns(self, fd) {
            return None;
        }
        if level == libc::SOL_SOCKET && name == libc::SO_ERROR {
            self.advance_connect(fd);
        }
        let rec = self.rec(fd);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(rec) = &rec {
            rec.land();
        }
        if let Some(rec) = &rec
            && unsafe { crate::tstamp::get(rec, level, name, val, len) }.is_some()
        {
            return ok(0);
        }
        if let Some(rec) = &rec
            && level == libc::SOL_SOCKET
            && let Some(unit) = linger_unit(name)
        {
            unsafe { write_linger(rec.opts().linger, unit, val, len) };
            return ok(0);
        }
        if let Some(rec) = &rec
            && unsafe { crate::netif::sockopt::get(rec, level, name, val, len) }.is_some()
        {
            return ok(0);
        }
        if let Some(rec) = &rec
            && let Some(v6) = self.ipv6(fd)
            && let Some(result) = unsafe { crate::netif::frag::get(rec, v6, level, name, val, len) }
        {
            return match result {
                Ok(()) => ok(0),
                Err(errno) => err(errno),
            };
        }
        if level == libc::IPPROTO_TCP
            && let Some(rec) = &rec
            && let Some(value) = crate::faults::sockopt::get(self.shared(), rec, name)
        {
            unsafe { write_opt(value, val, len) };
            return ok(0);
        }
        if let Some(rec) = &rec
            && let Some(result) = unsafe { crate::limits::sockopt::get(rec, level, name, val, len) }
        {
            return match result {
                Ok(()) => ok(0),
                Err(errno) => err(errno),
            };
        }
        // man 7 socket: report the stored SO_RCVTIMEO/SO_SNDTIMEO as a timeval (zero = unset), so
        // code that reads back what it set (e.g. std's `read_timeout`) sees it.
        if level == libc::SOL_SOCKET && (name == libc::SO_RCVTIMEO || name == libc::SO_SNDTIMEO) {
            let opts = rec.map(|rec| rec.opts()).unwrap_or_default();
            let d = if name == libc::SO_RCVTIMEO {
                opts.rcvtimeo
            } else {
                opts.sndtimeo
            };
            unsafe { write_timeval(d.unwrap_or_default(), val, len) };
            return ok(0);
        }
        // socket(7): SO_TYPE reports the socket's type, SO_ERROR reads and clears the pending
        // error, SO_ACCEPTCONN whether it listens.
        let value: i32 = if level != libc::SOL_SOCKET {
            return unsafe { self.unmodelled_get(rec.as_ref(), level, name, val, len) };
        } else {
            match name {
                libc::SO_TYPE => match self.kind(fd) {
                    Some(Kind::Dgram) => libc::SOCK_DGRAM,
                    _ => libc::SOCK_STREAM,
                },
                libc::SO_BROADCAST => matches!(
                    self.socks.lock().unwrap().get(&fd),
                    Some(Sock::Dgram {
                        broadcast: true,
                        ..
                    })
                ) as i32,
                libc::SO_ERROR => rec
                    .and_then(|rec| rec.take_error_as(self.shared(), Taker::SoError))
                    .unwrap_or(0),
                libc::SO_REUSEADDR => rec.is_some_and(|rec| rec.opts().reuseaddr) as i32,
                libc::SO_ACCEPTCONN => (self.kind(fd) == Some(Kind::Listener)) as i32,
                _ => return unsafe { self.unmodelled_get(rec.as_ref(), level, name, val, len) },
            }
        };
        unsafe { write_opt(value, val, len) };
        ok(0)
    }

    /// Duplicates a descriptor, sharing its open file description.
    unsafe fn dup(&self, fd: c_int) -> Option<NetResult> {
        unsafe { Net::fcntl(self, fd, libc::F_DUPFD, 0) }
    }

    unsafe fn fcntl(&self, fd: c_int, cmd: c_int, arg: i64) -> Option<NetResult> {
        if cmd == libc::F_DUPFD || cmd == libc::F_DUPFD_CLOEXEC {
            let mut socks = self.socks.lock().unwrap();
            let sock = socks.get(&fd)?;
            let rec = sock.rec().cloned();
            let new_fd = snare_interpose::real(|| unsafe { libc::fcntl(fd, cmd, arg as c_int) });
            if new_fd < 0 {
                return err(io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EMFILE));
            }
            socks.alias(fd, new_fd);
            if let Some(rec) = rec {
                self.shared().sockets.alias(new_fd, &rec);
            }
            return ok(new_fd as i64);
        }
        if cmd == libc::F_GETFD || cmd == libc::F_SETFD {
            if !self.socks.lock().unwrap().contains_key(&fd) {
                return None;
            }
            let result = snare_interpose::real(|| unsafe { libc::fcntl(fd, cmd, arg as c_int) });
            return if result < 0 {
                err(io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EBADF))
            } else {
                ok(result as i64)
            };
        }
        let mut socks = self.socks.lock().unwrap();
        if matches!(socks.get(&fd)?, Sock::Epoll { .. } | Sock::Kqueue { .. }) {
            let status = &mut socks.description_mut(&fd).unwrap().status_flags;
            return match cmd {
                libc::F_GETFL => ok(*status as i64),
                libc::F_SETFL => {
                    *status = libc::O_RDWR | (arg as c_int & libc::O_NONBLOCK);
                    ok(0)
                }
                _ => err(libc::EINVAL),
            };
        }
        let nb = match socks.get_mut(&fd) {
            Some(Sock::Fresh { nonblocking, .. })
            | Some(Sock::Connecting { nonblocking, .. })
            | Some(Sock::Stream { nonblocking, .. })
            | Some(Sock::Listener { nonblocking, .. })
            | Some(Sock::Dgram { nonblocking, .. })
            | Some(Sock::UnixDgram { nonblocking, .. })
            | Some(Sock::Event { nonblocking, .. })
            | Some(Sock::Raw { nonblocking, .. }) => nonblocking,
            _ => return None,
        };
        // man 2 fcntl: F_GETFL/F_SETFL read/set the fd's status flags (only O_NONBLOCK is settable
        // once open), F_GETFD/F_SETFD the FD_CLOEXEC flag. A socket's file is opened O_RDWR
        // (net/socket.c sock_alloc_file), so F_GETFL reports that access mode.
        match cmd {
            libc::F_GETFL => {
                let flags = libc::O_RDWR | if *nb { libc::O_NONBLOCK } else { 0 };
                ok(flags as i64)
            }
            libc::F_SETFL => {
                *nb = arg as c_int & libc::O_NONBLOCK != 0;
                ok(0)
            }
            _ => err(libc::EINVAL),
        }
    }

    /// The interface queries of `ifreq` on any fd, then on the fabric's own sockets `FIONREAD`
    /// (bytes readable: a stream's unread bytes, man 7 tcp; a datagram socket's next datagram
    /// length on Linux, man 7 udp), Linux `SIOCOUTQ` (always 0), `FIONBIO` (set nonblocking
    /// mode from the pointed-to `int`: Linux fs/ioctl.c ioctl_fionbio; macOS `<sys/filio.h>`,
    /// `_IOW('f', 126, int)`), `FIOCLEX`/`FIONCLEX`, and Linux `SIOCGHWTSTAMP`/`SIOCSHWTSTAMP`
    /// ([`Fabric::hwtstamp_ioctl`]). Any other request on a fabric socket is recorded as
    /// unmodelled and succeeds with no effect, or fails with the host's code for an unknown
    /// request under `strict_sockopts`.
    unsafe fn ioctl(&self, fd: c_int, request: u64, arg: i64) -> Option<NetResult> {
        if let Some(r) = unsafe { self.nic_ioctl(request, arg) } {
            return Some(r);
        }
        if request as libc::c_ulong == FIONREAD || is_siocoutq(request as libc::c_ulong) {
            let rec = match self.socks.lock().unwrap().get(&fd) {
                Some(
                    sock @ (Sock::Stream { .. } | Sock::Dgram { .. } | Sock::UnixDgram { .. }),
                ) => sock.rec().cloned(),
                Some(_) => None,
                None => return None,
            };
            if arg == 0 {
                return err(libc::EFAULT);
            }
            let value = match rec {
                Some(rec) if request as libc::c_ulong == FIONREAD => rec.fionread(),
                _ => 0,
            };
            unsafe { (arg as *mut c_int).write_unaligned(value) };
            return ok(0);
        }
        let mut socks = self.socks.lock().unwrap();
        let nb = match socks.get_mut(&fd) {
            Some(Sock::Fresh { nonblocking, .. })
            | Some(Sock::Connecting { nonblocking, .. })
            | Some(Sock::Stream { nonblocking, .. })
            | Some(Sock::Listener { nonblocking, .. })
            | Some(Sock::Dgram { nonblocking, .. })
            | Some(Sock::UnixDgram { nonblocking, .. })
            | Some(Sock::Raw { nonblocking, .. }) => nonblocking,
            _ => return None,
        };
        // FIONBIO toggles nonblocking mode from a pointed-to int (fs/ioctl.c ioctl_fionbio).
        if request as libc::c_ulong == libc::FIONBIO {
            let on = unsafe { *(arg as *const c_int) };
            *nb = on != 0;
            return ok(0);
        }
        let rec = socks.get(&fd).and_then(Sock::rec).cloned();
        drop(socks);
        if [libc::FIOCLEX, libc::FIONCLEX].contains(&(request as libc::c_ulong)) {
            let result = snare_interpose::real(|| unsafe {
                libc::fcntl(
                    fd,
                    libc::F_SETFD,
                    if request as libc::c_ulong == libc::FIOCLEX {
                        libc::FD_CLOEXEC
                    } else {
                        0
                    },
                )
            });
            return if result < 0 {
                err(io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EBADF))
            } else {
                ok(result as i64)
            };
        }
        #[cfg(target_os = "linux")]
        if let Some(r) = unsafe { self.hwtstamp_ioctl(request, arg) } {
            return Some(r);
        }
        match rec {
            Some(rec)
                if self
                    .shared()
                    .unmodelled_option(&rec, UnmodelledOption::Ioctl { request }) =>
            {
                err(UNKNOWN_IOCTL)
            }
            _ => ok(0),
        }
    }

    /// The index of a simulated interface by name (man 3 if_nametoindex); an unknown name fails
    /// with `NAMETOINDEX_UNKNOWN`.
    unsafe fn if_nametoindex(&self, name: *const std::ffi::c_char) -> Option<NetResult> {
        if name.is_null() {
            return err(libc::EFAULT);
        }
        let name = unsafe { std::ffi::CStr::from_ptr(name) };
        match name.to_str().ok().and_then(|n| self.shared().nic(n)) {
            Some(nic) => ok(nic.index as i64),
            None => err(NAMETOINDEX_UNKNOWN),
        }
    }

    /// Writes the name of interface `index` into `name`, a caller buffer of at least
    /// `IF_NAMESIZE` (16) bytes, and returns that pointer; an unknown index is ENXIO (man 3
    /// if_indextoname). A longer name is cut to 15 bytes plus the NUL.
    unsafe fn if_indextoname(&self, index: u32, name: *mut std::ffi::c_char) -> Option<NetResult> {
        let found = self.shared().nics().into_iter().find(|n| n.index == index);
        let Some(nic) = found else {
            return err(libc::ENXIO);
        };
        let bytes = nic.spec.name.as_bytes();
        let n = bytes.len().min(libc::IF_NAMESIZE - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), name.cast::<u8>(), n);
            *name.add(n) = 0;
        }
        ok(name as i64)
    }

    /// The simulated interfaces as an `if_nameindex` array (man 3 if_nameindex), allocated by
    /// `ifaddrs` and freed by [`if_freenameindex`](Net::if_freenameindex).
    unsafe fn if_nameindex(&self) -> Option<NetResult> {
        match crate::ifaddrs::nameindex(self.shared().nics()) {
            Ok(ptr) => ok(ptr as i64),
            Err(errno) => err(errno),
        }
    }

    /// Frees an array from [`if_nameindex`](Net::if_nameindex); declines a pointer it did not
    /// allocate, so a real one reaches the OS.
    unsafe fn if_freenameindex(&self, ptr: *mut u8) -> Option<NetResult> {
        crate::ifaddrs::release(ptr).then_some(NetResult::Ok(0))
    }

    /// The simulated interfaces and their addresses as a `struct ifaddrs` list (man 3
    /// getifaddrs), built by `ifaddrs`.
    unsafe fn getifaddrs(&self, ifap: *mut *mut u8) -> Option<NetResult> {
        if ifap.is_null() {
            return err(libc::EFAULT);
        }
        match crate::ifaddrs::getifaddrs(self.shared().nics()) {
            Ok(head) => {
                unsafe { *ifap = head.cast() };
                ok(0)
            }
            Err(errno) => err(errno),
        }
    }

    /// Frees a list from [`getifaddrs`](Net::getifaddrs); declines one it did not allocate.
    unsafe fn freeifaddrs(&self, ifa: *mut u8) -> Option<NetResult> {
        crate::ifaddrs::release(ifa).then_some(NetResult::Ok(0))
    }

    /// `poll(2)` over a set made entirely of the fabric's fds and the sim's other datagram
    /// sockets (a `SimHost`'s, [`foreign_ready`]); a set mixing in other fds is declined whole.
    /// Connecting sockets are moved on before each check, so a nonblocking connect's POLLOUT
    /// appears when its attempt settles. An fd closed during the wait reports `POLLNVAL` (man 2
    /// poll).
    unsafe fn poll(&self, fds: *mut u8, nfds: u64, timeout: c_int) -> Option<NetResult> {
        // man 2 poll: each pollfd has requested `events` and returned `revents`; a connected
        // stream is always writable (POLLOUT) and readable (POLLIN) once data or EOF is pending,
        // and POLLERR/POLLHUP are reported whether asked for or not. `timeout` is in ms, -1
        // blocking indefinitely. Only handle a poll set made entirely of our fds; otherwise decline
        // so the OS sees it.
        let pfds =
            unsafe { std::slice::from_raw_parts_mut(fds.cast::<libc::pollfd>(), nfds as usize) };
        let watched: Vec<(c_int, i16)> = pfds.iter().map(|p| (p.fd, p.events)).collect();
        if !self
            .foreign_masks(watched.iter().map(|w| w.0))
            .iter()
            .all(|(fd, ready)| {
                ready.is_some() || *fd < 0 || unsafe { libc::fcntl(*fd, libc::F_GETFD) } < 0
            })
        {
            return None;
        }
        let fds: Vec<c_int> = watched.iter().map(|(fd, _)| *fd).collect();
        let deadline = (timeout >= 0)
            .then(|| Deadline::timeout(std::time::Duration::from_millis(timeout as u64)));
        // A return that never blocked — fds already ready, or a zero timeout — is a busy-poll step
        // when repeated, so it is charged the call latency.
        let mut waited = false;
        let mut last = timeout == 0;
        loop {
            self.advance_connecting(Some(&fds));
            let revents = self.poll_revents(&watched);
            let ready = revents.iter().filter(|r| **r != 0).count();
            if ready > 0 || last {
                for (p, r) in pfds.iter_mut().zip(revents) {
                    p.revents = r;
                }
                if !waited {
                    snare_interpose::charge_latency();
                }
                return ok(ready as i64);
            }
            last = !readiness().wait_until_dynamic(
                "poll",
                deadline,
                |keys| self.fd_interests(fds.iter().copied(), keys),
                || {
                    self.poll_revents(&watched).iter().any(|r| *r != 0)
                        || self.connecting_due(Some(&fds))
                },
            );
            waited = true;
        }
    }

    unsafe fn select(
        &self,
        nfds: c_int,
        read: *mut u8,
        write: *mut u8,
        except: *mut u8,
        timeout: *const u8,
    ) -> Option<NetResult> {
        if nfds < 0 || nfds as usize > libc::FD_SETSIZE {
            return err(libc::EINVAL);
        }
        let sets = [read.cast::<libc::fd_set>(), write.cast(), except.cast()];
        let mut pfds = Vec::new();
        for fd in 0..nfds {
            let mut events = 0;
            for (set, event) in sets
                .iter()
                .zip([libc::POLLIN, libc::POLLOUT, libc::POLLPRI])
            {
                if !set.is_null() && unsafe { libc::FD_ISSET(fd, *set) } {
                    events |= event;
                }
            }
            if events != 0 {
                pfds.push(libc::pollfd {
                    fd,
                    events,
                    revents: 0,
                });
            }
        }
        if pfds
            .iter()
            .any(|p| unsafe { libc::fcntl(p.fd, libc::F_GETFD) } < 0)
        {
            return err(libc::EBADF);
        }
        let millis = if timeout.is_null() {
            -1
        } else {
            let tv = unsafe { timeout.cast::<libc::timeval>().read() };
            if tv.tv_sec < 0 || tv.tv_usec < 0 || tv.tv_usec >= 1_000_000 {
                return err(libc::EINVAL);
            }
            ((tv.tv_sec as u128 * 1000 + (tv.tv_usec as u128).div_ceil(1000))
                .min(c_int::MAX as u128)) as c_int
        };
        let result =
            unsafe { Net::poll(self, pfds.as_mut_ptr().cast(), pfds.len() as u64, millis) }?;
        if let NetResult::Err(_) = result {
            return Some(result);
        }
        for set in sets.into_iter().filter(|s| !s.is_null()) {
            unsafe { libc::FD_ZERO(set) };
        }
        let mut count = 0;
        for p in pfds {
            for (set, event) in sets
                .iter()
                .zip([libc::POLLIN, libc::POLLOUT, libc::POLLPRI])
            {
                if !set.is_null() && p.revents & event != 0 {
                    unsafe { libc::FD_SET(p.fd, *set) };
                    count += 1;
                }
            }
        }
        ok(count)
    }

    /// `read(2)` on a fabric fd: an eventfd's counter, a socket's `recv` with no flags, or a raw
    /// endpoint's next frame. EINVAL on an epoll or kqueue fd, as Linux's epoll file has no read
    /// operation (fs/eventpoll.c eventpoll_fops). A real kqueue fd gives ENXIO instead (XNU
    /// bsd/kern/kern_event.c kqueueops → fo_no_read), which is not modelled.
    unsafe fn read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<NetResult> {
        match self.kind(fd)? {
            Kind::Event => self.eventfd_read(fd, buf, len),
            Kind::Stream | Kind::Dgram | Kind::Fresh | Kind::Listener => unsafe {
                self.recv(fd, buf, len, 0)
            },
            Kind::Raw => self.raw_read(fd, buf, len),
            _ => err(libc::EINVAL),
        }
    }

    /// `write(2)` on a fabric fd: adds to an eventfd's counter, a socket's `send` with no flags,
    /// or a raw endpoint's frame. EINVAL on an epoll or kqueue fd (a real kqueue gives ENXIO,
    /// XNU fo_no_write; not modelled).
    unsafe fn write(&self, fd: c_int, buf: *const u8, len: usize) -> Option<NetResult> {
        match self.kind(fd)? {
            Kind::Event => self.eventfd_write(fd, buf, len),
            Kind::Stream | Kind::Dgram | Kind::Fresh | Kind::Listener => unsafe {
                self.send(fd, buf, len, 0)
            },
            Kind::Raw => self.raw_write(fd, buf, len),
            _ => err(libc::EINVAL),
        }
    }

    /// man 2 eventfd: a counting fd seeded with `initval`; EFD_NONBLOCK sets nonblocking mode and
    /// EFD_SEMAPHORE makes each read decrement by one (vs. draining the whole counter).
    #[cfg(target_os = "linux")]
    unsafe fn eventfd(&self, initval: u32, flags: c_int) -> Option<NetResult> {
        if flags & !(libc::EFD_NONBLOCK | libc::EFD_CLOEXEC | libc::EFD_SEMAPHORE) != 0 {
            return err(libc::EINVAL);
        }
        let nonblocking = flags & libc::EFD_NONBLOCK != 0;
        let semaphore = flags & libc::EFD_SEMAPHORE != 0;
        match self.reserve_fd_flags(flags) {
            Ok(fd) => {
                self.socks.lock().unwrap().insert(
                    fd,
                    Sock::Event {
                        ready_at: self.shared().tstamp_now().mono,
                        ready_order: readiness_sequence(),
                        counter: u64::from(initval),
                        nonblocking,
                        semaphore,
                        writes: 0,
                        reads: 0,
                    },
                );
                ok(fd as i64)
            }
            Err(e) => err(e.raw_os_error().unwrap_or(libc::EMFILE)),
        }
    }

    /// man 2 epoll_create1: creates an epoll instance and returns an fd referring to it.
    #[cfg(target_os = "linux")]
    unsafe fn epoll_create1(&self, flags: c_int) -> Option<NetResult> {
        if flags & !libc::EPOLL_CLOEXEC != 0 {
            return err(libc::EINVAL);
        }
        match self.reserve_fd_flags(flags) {
            Ok(fd) => {
                self.socks.lock().unwrap().insert(
                    fd,
                    Sock::Epoll {
                        interests: Default::default(),
                    },
                );
                ok(fd as i64)
            }
            Err(e) => err(e.raw_os_error().unwrap_or(libc::EMFILE)),
        }
    }

    /// Adds, changes or removes an open file description's interest in epoll set `epfd`.
    #[cfg(target_os = "linux")]
    unsafe fn epoll_ctl(
        &self,
        epfd: c_int,
        op: c_int,
        fd: c_int,
        event: *const u8,
    ) -> Option<NetResult> {
        let mut socks = self.socks.lock().unwrap();
        if !socks.contains_key(&epfd) {
            return None;
        }
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return err(libc::EBADF);
        }
        if fd == epfd {
            return err(libc::EINVAL);
        }
        let identity = socks
            .identity(fd)
            .map(EpollIdentity::Local)
            .unwrap_or_else(|| {
                self.shared()
                    .sockets
                    .lookup_fd(fd)
                    .map_or(EpollIdentity::Untracked, |rec| {
                        EpollIdentity::Foreign(rec.id.get())
                    })
            });
        if matches!(identity, EpollIdentity::Local(id) if Some(id) == socks.identity(epfd)) {
            return err(libc::EINVAL);
        }
        let Some(Sock::Epoll { interests }) = socks.get_mut(&epfd) else {
            return err(libc::EINVAL);
        };
        let key = (fd, identity);
        match op {
            libc::EPOLL_CTL_ADD | libc::EPOLL_CTL_MOD => {
                if op == libc::EPOLL_CTL_ADD && interests.contains_key(&key) {
                    return err(libc::EEXIST);
                }
                if op == libc::EPOLL_CTL_MOD && !interests.contains_key(&key) {
                    return err(libc::ENOENT);
                }
                if event.is_null() {
                    return err(libc::EFAULT);
                }
                let ev = unsafe { std::ptr::read_unaligned(event.cast::<libc::epoll_event>()) };
                interests.insert(
                    key,
                    EpollInterest {
                        events: ev.events,
                        data: ev.u64,
                        edge: Edge::default(),
                        spent: false,
                        order: readiness_sequence(),
                        pending_order: None,
                    },
                );
            }
            libc::EPOLL_CTL_DEL => {
                if interests.remove(&key).is_none() {
                    return err(libc::ENOENT);
                }
            }
            _ => return err(libc::EINVAL),
        }
        drop(socks);
        self.bump_fds([epfd]);
        ok(0)
    }

    /// man 2 epoll_wait: fills up to `maxevents` ready epoll_event structs; `timeout` in ms, -1
    /// blocks indefinitely, 0 returns at once. Returns the number of ready fds (0 on timeout).
    #[cfg(target_os = "linux")]
    unsafe fn epoll_wait(
        &self,
        epfd: c_int,
        events: *mut u8,
        maxevents: c_int,
        timeout: c_int,
    ) -> Option<NetResult> {
        if !Net::owns(self, epfd) {
            return None;
        }
        if maxevents <= 0 {
            return err(libc::EINVAL);
        }
        if events.is_null() {
            return err(libc::EFAULT);
        }
        if !matches!(
            self.socks.lock().unwrap().get(&epfd),
            Some(Sock::Epoll { .. })
        ) {
            return err(libc::EINVAL);
        }
        let deadline = (timeout >= 0)
            .then(|| Deadline::timeout(std::time::Duration::from_millis(timeout as u64)));
        // A wait that returns without blocking — events already pending, or a zero timeout — is a
        // busy-poll step when repeated, so it is charged the call latency.
        let mut waited = false;
        loop {
            self.advance_connecting(None);
            let ready = self.collect_ready(epfd, maxevents as usize, true);
            if !ready.is_empty() {
                if !waited {
                    snare_interpose::charge_latency();
                }
                for (i, (ev, data)) in ready.iter().enumerate() {
                    let slot = unsafe { events.cast::<libc::epoll_event>().add(i) };
                    unsafe {
                        std::ptr::write_unaligned(
                            slot,
                            libc::epoll_event {
                                events: *ev,
                                u64: *data,
                            },
                        )
                    };
                }
                return ok(ready.len() as i64);
            }
            let woke = readiness().wait_until_dynamic(
                "epoll_wait",
                deadline,
                |keys| self.epoll_interests(epfd, keys),
                || !self.collect_ready(epfd, 1, false).is_empty() || self.connecting_due(None),
            );
            if !woke {
                if timeout == 0 {
                    snare_interpose::charge_latency();
                }
                return ok(0);
            }
            waited = true;
        }
    }

    /// man 2 kqueue: a new kernel event queue.
    #[cfg(target_os = "macos")]
    unsafe fn kqueue(&self) -> Option<NetResult> {
        match self.reserve_fd() {
            Ok(fd) => {
                self.socks.lock().unwrap().insert(
                    fd,
                    Sock::Kqueue {
                        state: Arc::new(Mutex::new(KqueueState::default())),
                    },
                );
                ok(fd as i64)
            }
            Err(e) => err(e.raw_os_error().unwrap_or(libc::EMFILE)),
        }
    }

    /// Applies `changelist` to kqueue `kq`, then waits for up to `nevents` ready events (man 2
    /// kevent). Only `EVFILT_READ`, `EVFILT_WRITE` and `EVFILT_USER` are modelled; other filters
    /// are accepted and never fire. A registration is level-triggered unless added with
    /// `EV_CLEAR` (see [`Edge`]); `EV_ONESHOT` deletes it once reported, `EV_DISPATCH` disables
    /// it once reported, and `EV_DISABLE`/`EV_ENABLE` turn it off and on. Adding a registration
    /// that exists updates its `udata` and reports it again if it is ready, as XNU
    /// bsd/kern/kern_event.c `kevent_register` re-runs the filter's `f_touch` and activates the
    /// knote when that fires. With any `EV_RECEIPT` change the call
    /// returns only the receipts, without waiting: XNU bsd/kern/kern_event.c kevent_internal
    /// scans for events only when `noutputs == 0`.
    #[cfg(target_os = "macos")]
    unsafe fn kevent(
        &self,
        kq: c_int,
        changelist: *const u8,
        nchanges: c_int,
        eventlist: *mut u8,
        nevents: c_int,
        timeout: *const u8,
    ) -> Option<NetResult> {
        let state = {
            let socks = self.socks.lock().unwrap();
            match socks.get(&kq) {
                Some(Sock::Kqueue { state }) => state.clone(),
                _ => return None,
            }
        };
        // Apply the changelist, collecting any EV_RECEIPT acknowledgements to return at once.
        let valid_changes: Vec<bool> = {
            let socks = self.socks.lock().unwrap();
            (0..nchanges.max(0) as usize)
                .map(|i| {
                    let ch = unsafe { changelist.cast::<libc::kevent>().add(i).read_unaligned() };
                    !matches!(ch.filter, libc::EVFILT_READ | libc::EVFILT_WRITE)
                        || socks.contains_key(&(ch.ident as c_int))
                })
                .collect()
        };
        let mut receipts: Vec<libc::kevent> = Vec::new();
        let mut plain_error = None;
        let mut changed = false;
        {
            let mut guard = state.lock().unwrap();
            let KqueueState {
                reads,
                writes,
                users,
            } = &mut *guard;
            for (i, &valid) in valid_changes.iter().enumerate() {
                // `kevent` is a packed struct (`#pragma pack(4)` in <sys/event.h>,
                // `repr(packed(4))` in libc); read each entry by value to avoid unaligned refs.
                let ch = unsafe { changelist.cast::<libc::kevent>().add(i).read_unaligned() };
                let ident = ch.ident;
                let filter = ch.filter;
                let flags = ch.flags;
                let fflags = ch.fflags;
                let udata = ch.udata as u64;
                let adding = flags & libc::EV_ADD != 0;
                let deleting = flags & libc::EV_DELETE != 0;
                let kept =
                    flags & (libc::EV_ADD | libc::EV_CLEAR | libc::EV_ONESHOT | libc::EV_DISPATCH);
                let toggle = |disabled: &mut bool| {
                    if flags & libc::EV_DISABLE != 0 {
                        *disabled = true;
                    }
                    if flags & libc::EV_ENABLE != 0 {
                        *disabled = false;
                    }
                };
                let exists = match filter {
                    libc::EVFILT_READ => reads.contains_key(&(ident as c_int)),
                    libc::EVFILT_WRITE => writes.contains_key(&(ident as c_int)),
                    libc::EVFILT_USER => users.contains_key(&ident),
                    _ => false,
                };
                let change_error = if !valid {
                    libc::EBADF
                } else if !adding && !exists {
                    libc::ENOENT
                } else {
                    0
                };
                if change_error != 0 && flags & libc::EV_RECEIPT == 0 {
                    if nevents > receipts.len() as c_int {
                        let mut ev = ch;
                        ev.flags |= libc::EV_ERROR;
                        ev.data = change_error as _;
                        receipts.push(ev);
                    } else {
                        plain_error.get_or_insert(change_error);
                    }
                }
                if change_error == 0 {
                    changed |= matches!(
                        filter,
                        libc::EVFILT_READ | libc::EVFILT_WRITE | libc::EVFILT_USER
                    );
                    match filter {
                        libc::EVFILT_READ | libc::EVFILT_WRITE => {
                            let notes = if filter == libc::EVFILT_READ {
                                &mut *reads
                            } else {
                                &mut *writes
                            };
                            let fd = ident as c_int;
                            if deleting {
                                notes.remove(&fd);
                            } else {
                                if adding {
                                    let note = notes.entry(fd).or_insert(Knote {
                                        udata,
                                        flags: kept,
                                        disabled: false,
                                        edge: Edge::default(),
                                    });
                                    note.udata = udata;
                                    note.edge = Edge::default();
                                }
                                if let Some(note) = notes.get_mut(&fd) {
                                    toggle(&mut note.disabled);
                                }
                            }
                        }
                        libc::EVFILT_USER => {
                            if deleting {
                                users.remove(&ident);
                            } else {
                                let note = users.entry(ident).or_insert(UserNote {
                                    udata,
                                    flags: kept,
                                    disabled: false,
                                    triggered: false,
                                });
                                if adding {
                                    note.udata = udata;
                                }
                                toggle(&mut note.disabled);
                                // NOTE_TRIGGER fires the user event (mio's Waker).
                                if fflags & libc::NOTE_TRIGGER != 0 {
                                    note.triggered = true;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                // kevent(2) EV_RECEIPT: the change is echoed back with EV_ERROR set and `data` 0
                // for success.
                if flags & libc::EV_RECEIPT != 0 {
                    let mut ev = ch;
                    ev.flags = flags | libc::EV_ERROR;
                    ev.data = change_error as _;
                    receipts.push(ev);
                }
            }
        }
        if changed {
            self.bump_fds([kq]);
        }
        if let Some(errno) = plain_error {
            return err(errno);
        }
        let cap = nevents.max(0) as usize;
        // EV_RECEIPT acknowledgements return immediately, before any wait.
        if !receipts.is_empty() {
            let n = receipts.len().min(cap);
            for (i, ev) in receipts.iter().take(n).enumerate() {
                unsafe { std::ptr::write_unaligned(eventlist.cast::<libc::kevent>().add(i), *ev) };
            }
            return ok(n as i64);
        }
        if cap == 0 {
            return ok(0);
        }
        let deadline = unsafe { kevent_deadline(timeout) };
        let zero_timeout = !timeout.is_null()
            && unsafe {
                let span = timeout.cast::<libc::timespec>().read_unaligned();
                span.tv_sec == 0 && span.tv_nsec == 0
            };
        // As for epoll_wait: a return that never blocked is charged the call latency.
        let immediate = deadline.is_some_and(|d| d.passed());
        let mut waited = false;
        loop {
            self.advance_connecting(None);
            let ready = self.collect_kevents(kq, cap, true);
            if !ready.is_empty() {
                if !waited {
                    snare_interpose::charge_latency();
                }
                for (i, ev) in ready.iter().enumerate() {
                    unsafe {
                        std::ptr::write_unaligned(eventlist.cast::<libc::kevent>().add(i), *ev)
                    };
                }
                return ok(ready.len() as i64);
            }
            if zero_timeout {
                snare_interpose::end_spin();
                let ready = self.collect_kevents(kq, cap, true);
                snare_interpose::charge_latency();
                for (i, ev) in ready.iter().enumerate() {
                    unsafe {
                        std::ptr::write_unaligned(eventlist.cast::<libc::kevent>().add(i), *ev)
                    };
                }
                return ok(ready.len() as i64);
            }
            let woke = readiness().wait_until_dynamic(
                "kevent",
                deadline,
                |keys| self.kqueue_interests(kq, keys),
                || !self.collect_kevents(kq, 1, false).is_empty() || self.connecting_due(None),
            );
            if !woke {
                if immediate {
                    snare_interpose::charge_latency();
                }
                return ok(0);
            }
            waited = true;
        }
    }
}

/// The peer side of a connection, driven by a tester on a managed thread. Each runs under
/// passthrough like the rest of the fabric: a wait on one of the fabric's own locks is the sim's
/// business, not a blocked thread, and counting it toward quiescence could make a socket wait
/// holding that lock mistake the domain for deadlocked.
impl Conn {
    /// Writes what the window has room for; 0 once the stream is closed.
    pub(crate) fn write_from_peer(&self, bytes: &[u8]) -> usize {
        snare_interpose::real(|| self.write(End::B, bytes).unwrap_or(0))
    }

    /// Whether a peer's write of `len` bytes would take some of them, or fail at once.
    pub(crate) fn peer_can_write(&self, len: usize) -> bool {
        snare_interpose::real(|| {
            #[cfg(target_os = "macos")]
            self.progress_tcp_shutdown();
            self.write_pipe(End::B).can_write(len)
        })
    }

    /// Reads what the code under test has sent: `Ok(0)` at end of stream, `WouldBlock` when
    /// nothing has arrived yet (or the tester shut its reading side), `ConnectionReset` after a
    /// reset.
    pub(crate) fn read_from_peer(&self, out: &mut [u8]) -> io::Result<usize> {
        snare_interpose::real(|| {
            #[cfg(target_os = "macos")]
            self.progress_tcp_shutdown();
            match self.read_pipe(End::B).read(out) {
                Read::Data(n) => {
                    self.took(End::B, n);
                    Ok(n)
                }
                Read::Eof => Ok(0),
                Read::Reset => Err(io::ErrorKind::ConnectionReset.into()),
                Read::WouldBlock | Read::Shut => Err(io::ErrorKind::WouldBlock.into()),
            }
        })
    }

    /// Closes the peer's sending side (a FIN): the code under test reads end of stream once the
    /// bytes already written have arrived.
    pub(crate) fn close_peer(&self) {
        snare_interpose::real(|| self.close(End::B));
    }

    /// Aborts the connection with a reset (RST): the code under test's next read or write fails
    /// with ECONNRESET.
    pub(crate) fn reset_peer(&self) {
        snare_interpose::real(|| self.reset(End::B));
    }

    /// Whether the connection was reset. A reset hits both pipes at once, so one tells.
    fn is_reset(&self) -> bool {
        self.a_to_b.is_reset()
    }

    /// Whether the peer has bytes to read or has seen the code under test close its end.
    pub(crate) fn peer_readable(&self) -> bool {
        snare_interpose::real(|| {
            #[cfg(target_os = "macos")]
            self.progress_tcp_shutdown();
            self.read_pipe(End::B).readable_or_closed()
        })
    }
}

/// The loopback address of `domain`'s family; callers use it only for the family, via
/// [`unspecified_like`].
fn loopback_for(domain: c_int) -> IpAddr {
    if domain == libc::AF_INET6 {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }
}

/// A ready event for `ident` on `filter`, carrying the caller's `udata`, with no flags or data.
#[cfg(target_os = "macos")]
fn make_kevent(ident: usize, filter: i16, udata: u64) -> libc::kevent {
    libc::kevent {
        ident,
        filter,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: udata as *mut libc::c_void,
    }
}

/// A `kevent` timeout (`*const timespec`) as a deadline: null blocks indefinitely, `{0,0}` is an
/// already-passed deadline (a non-blocking poll), per man 2 kevent. Negative fields count as 0.
#[cfg(target_os = "macos")]
unsafe fn kevent_deadline(timeout: *const u8) -> Option<Deadline> {
    if timeout.is_null() {
        return None;
    }
    let ts = unsafe { timeout.cast::<libc::timespec>().read() };
    let d = std::time::Duration::new(ts.tv_sec.max(0) as u64, ts.tv_nsec.max(0) as u32);
    Some(Deadline::timeout(d))
}

/// Reads a C `int` option value (SO_BROADCAST et al.), zero if the buffer is null or too short.
unsafe fn read_int(val: *const u8, len: u32) -> c_int {
    if val.is_null() || (len as usize) < size_of::<c_int>() {
        return 0;
    }
    unsafe { val.cast::<c_int>().read_unaligned() }
}

/// Reads a `struct timeval` option value (SO_RCVTIMEO), `None` if the buffer is null or too short.
/// A negative `tv_sec` counts as 0 and a negative `tv_usec` as 0; `tv_usec` is otherwise taken
/// modulo one second. Linux's net/core/sock.c sock_set_timeout rejects an out-of-range `tv_usec`
/// with EDOM and turns a negative `tv_sec` into a zero (immediate) timeout; neither is modelled.
pub(crate) unsafe fn parse_timeval(val: *const u8, len: u32) -> Option<std::time::Duration> {
    if val.is_null() || (len as usize) < size_of::<libc::timeval>() {
        return None;
    }
    let tv = unsafe { val.cast::<libc::timeval>().read_unaligned() };
    let usecs = u64::try_from(tv.tv_usec).unwrap_or(0);
    Some(std::time::Duration::new(
        tv.tv_sec.max(0) as u64,
        (usecs % 1_000_000) as u32 * 1_000,
    ))
}

/// Writes a `struct timeval` option value back out (getsockopt SO_RCVTIMEO), clamped to the
/// caller's buffer; a null buffer or length is a no-op.
pub(crate) unsafe fn write_timeval(d: std::time::Duration, val: *mut u8, len: *mut u32) {
    if val.is_null() || len.is_null() || (unsafe { *len } as usize) < size_of::<libc::timeval>() {
        return;
    }
    let tv = libc::timeval {
        tv_sec: d.as_secs() as libc::time_t,
        tv_usec: d.subsec_micros() as libc::suseconds_t,
    };
    unsafe {
        val.cast::<libc::timeval>().write_unaligned(tv);
        *len = size_of::<libc::timeval>() as u32;
    }
}

/// The IPv6 "join a multicast group" setsockopt name. `libc` spells it `IPV6_JOIN_GROUP` (the
/// POSIX name, `<netinet/in.h>`) on the BSDs/macOS and `IPV6_ADD_MEMBERSHIP`
/// (IPV6_ADD_MEMBERSHIP(2const)) on Linux, where glibc defines both
/// (sysdeps/unix/sysv/linux/bits/in.h). The values differ per
/// OS — 20 on Linux (include/uapi/linux/in6.h), 12 on macOS (XNU bsd/netinet6/in6.h) — but the
/// `ipv6_mreq` payload is the same.
#[cfg(target_os = "linux")]
const IPV6_JOIN: c_int = libc::IPV6_ADD_MEMBERSHIP;
#[cfg(not(target_os = "linux"))]
const IPV6_JOIN: c_int = libc::IPV6_JOIN_GROUP;
#[cfg(target_os = "linux")]
const IPV6_LEAVE: c_int = libc::IPV6_DROP_MEMBERSHIP;
#[cfg(not(target_os = "linux"))]
const IPV6_LEAVE: c_int = libc::IPV6_LEAVE_GROUP;

/// If `(level, name)` is an `IP_ADD_MEMBERSHIP`/`IPV6_ADD_MEMBERSHIP`, reads the membership out of
/// the request the caller passed. IP_ADD_MEMBERSHIP(2const): `struct ip_mreq { imr_multiaddr;
/// imr_interface; }`, or on Linux `struct ip_mreqn`, which appends `int imr_ifindex`
/// (ip_mreqn(2type)); IPV6_ADD_MEMBERSHIP(2const):
/// `struct ipv6_mreq { ipv6mr_multiaddr; unsigned ipv6mr_interface; }`.
///
/// Offsets: `ip_mreq` is two 4-byte `in_addr`s (group at 0, interface at 4), and Linux tells an
/// `ip_mreqn` by its 12-byte length (`imr_ifindex` at 8; net/ipv4/ip_sockglue.c
/// do_ip_setsockopt checks `optlen >= sizeof(struct ip_mreqn)`). `ipv6_mreq` is a 16-byte
/// `in6_addr` then the interface index at 16. A wildcard interface address means "any". A
/// 4-to-7-byte `ip_mreq` is read as the group alone, where Linux refuses anything shorter than
/// `struct ip_mreq` with EINVAL (the same do_ip_setsockopt check).
unsafe fn parse_add_membership(
    level: c_int,
    name: c_int,
    val: *const u8,
    len: u32,
) -> Option<Membership> {
    if val.is_null() {
        return None;
    }
    let len = len as usize;
    if level == libc::IPPROTO_IP && name == libc::IP_ADD_MEMBERSHIP {
        if len < size_of::<libc::in_addr>() {
            return None;
        }
        let group = unsafe { val.cast::<libc::in_addr>().read_unaligned() };
        let interface = (len >= 2 * size_of::<libc::in_addr>())
            .then(|| unsafe { val.add(4).cast::<libc::in_addr>().read_unaligned() })
            .map(|a| Ipv4Addr::from(u32::from_be(a.s_addr)))
            .filter(|a| !a.is_unspecified());
        let ifindex = if cfg!(target_os = "linux") && len >= 12 {
            unsafe { val.add(8).cast::<c_int>().read_unaligned() }.max(0) as u32
        } else {
            0
        };
        return Some(Membership {
            group: IpAddr::V4(Ipv4Addr::from(u32::from_be(group.s_addr))),
            interface_addr: interface.map(IpAddr::V4),
            ifindex,
        });
    }
    if level == libc::IPPROTO_IPV6 && name == IPV6_JOIN {
        if len < size_of::<libc::in6_addr>() {
            return None;
        }
        let group = unsafe { val.cast::<libc::in6_addr>().read_unaligned() };
        let ifindex = if len >= size_of::<libc::ipv6_mreq>() {
            unsafe { val.add(16).cast::<u32>().read_unaligned() }
        } else {
            0
        };
        return Some(Membership {
            group: IpAddr::V6(Ipv6Addr::from(group.s6_addr)),
            interface_addr: None,
            ifindex,
        });
    }
    None
}

/// macOS `SO_LINGER_SEC` (`<sys/socket.h>`, 0x1080): `SO_LINGER` with the time in seconds, which
/// std and socket2 use, since macOS's own `SO_LINGER` counts clock ticks.
#[cfg(target_os = "macos")]
const SO_LINGER_SEC: c_int = 0x1080;

/// What `SO_LINGER`'s `l_linger` counts: seconds on Linux (man 7 socket), clock ticks of 1/100 s
/// on macOS. XNU bsd/kern/uipc_socket.c sosetoptlock stores `SO_LINGER`'s value as is in
/// `so_linger` (ticks) and scales `SO_LINGER_SEC`'s by `hz`, which bsd/kern/kern_clock.c fixes at
/// 100; `<sys/socket.h>` labels `SO_LINGER` "(in ticks)".
#[cfg(target_os = "linux")]
const LINGER_UNIT: Duration = Duration::from_secs(1);
#[cfg(not(target_os = "linux"))]
const LINGER_UNIT: Duration = Duration::from_millis(10);

/// The unit of `l_linger` for option `name`, or `None` if it is not a linger option.
fn linger_unit(name: c_int) -> Option<Duration> {
    match name {
        libc::SO_LINGER => Some(LINGER_UNIT),
        #[cfg(target_os = "macos")]
        SO_LINGER_SEC => Some(Duration::from_secs(1)),
        _ => None,
    }
}

/// Reads a `struct linger` (man 7 socket: `l_onoff`, `l_linger` in `unit`s): `Some` while on.
unsafe fn parse_linger(val: *const u8, len: u32, unit: Duration) -> Option<Duration> {
    if val.is_null() || (len as usize) < size_of::<libc::linger>() {
        return None;
    }
    let l = unsafe { val.cast::<libc::linger>().read_unaligned() };
    (l.l_onoff != 0).then(|| unit * l.l_linger.max(0) as u32)
}

/// Writes a `struct linger` for getsockopt, `l_linger` in `unit`s (rounded down); a buffer
/// shorter than the struct is left untouched.
unsafe fn write_linger(linger: Option<Duration>, unit: Duration, val: *mut u8, len: *mut u32) {
    if val.is_null() || len.is_null() || (unsafe { *len } as usize) < size_of::<libc::linger>() {
        return;
    }
    let l = libc::linger {
        l_onoff: linger.is_some() as c_int,
        l_linger: linger.map_or(0, |d| (d.as_nanos() / unit.as_nanos()) as c_int),
    };
    unsafe {
        val.cast::<libc::linger>().write_unaligned(l);
        *len = size_of::<libc::linger>() as u32;
    }
}

/// Reads a caller's `sockaddr_in`/`sockaddr_in6`; `None` for a null pointer, a length short of
/// the family's struct, or any other family.
unsafe fn parse_addr(ptr: *const u8, len: u32) -> Option<SocketAddr> {
    if ptr.is_null() || (len as usize) < size_of::<libc::sockaddr>() {
        return None;
    }
    // man 7 ip / man 7 ipv6: sin_family/sin6_family tags the union; sin_port/sin6_port and the
    // address fields are network (big-endian) byte order, hence the from_be/to_be conversions.
    let family = unsafe { (*ptr.cast::<libc::sockaddr>()).sa_family } as c_int;
    match family {
        libc::AF_INET => {
            if (len as usize) < size_of::<libc::sockaddr_in>() {
                return None;
            }
            let sa = unsafe { std::ptr::read_unaligned(ptr.cast::<libc::sockaddr_in>()) };
            let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            Some(SocketAddr::V4(SocketAddrV4::new(
                ip,
                u16::from_be(sa.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // The base guard only covers `sockaddr`; a v6 address reads more.
            if (len as usize) < size_of::<libc::sockaddr_in6>() {
                return None;
            }
            let sa = unsafe { std::ptr::read_unaligned(ptr.cast::<libc::sockaddr_in6>()) };
            let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be(sa.sin6_port),
                sa.sin6_flowinfo,
                sa.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// The placeholder address of a socketpair end, which has none. Never a real peer: no socket can
/// connect from `0.0.0.0:0`, so comparing against it is safe.
const UNNAMED: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

/// What a send on a datagram socketpair end whose other end is closed fails with. Measured on the
/// dev box and in docker (`socketpair_os_truth`): Linux refuses it, Darwin reports a reset.
#[cfg(target_os = "linux")]
const PAIR_PEER_GONE: c_int = libc::ECONNREFUSED;
#[cfg(not(target_os = "linux"))]
const PAIR_PEER_GONE: c_int = libc::ECONNRESET;

/// Writes the unnamed `AF_UNIX` address a socketpair end reports: just the family on Linux (length
/// `sizeof(sa_family_t)`, 2, per man 7 unix), a zeroed 16-byte `sockaddr` with `sa_len` 16 on
/// Darwin. Measured by `socketpair_os_truth`.
unsafe fn write_unnamed(out: *mut u8, out_len: *mut u32) {
    if out.is_null() || out_len.is_null() {
        return;
    }
    #[cfg(target_os = "linux")]
    let bytes: &[u8] = &(libc::AF_UNIX as u16).to_ne_bytes();
    #[cfg(not(target_os = "linux"))]
    let bytes: &[u8] = &{
        let mut b = [0u8; 16];
        b[0] = 16;
        b[1] = libc::AF_UNIX as u8;
        b
    };
    unsafe {
        let n = (*out_len as usize).min(bytes.len());
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, n);
        *out_len = bytes.len() as u32;
    }
}

/// Writes `addr` as a `sockaddr_in`/`sockaddr_in6` (port and IPv4 address in network byte order,
/// man 7 ip / man 7 ipv6) into a caller buffer of `*out_len` bytes, truncating, and sets
/// `*out_len` to the full size. The IPv6 flow info and scope id are written as 0, and the BSD
/// `sin_len` byte is left 0.
unsafe fn write_addr(addr: SocketAddr, out: *mut u8, out_len: *mut u32) {
    if out.is_null() || out_len.is_null() {
        return;
    }
    let cap = unsafe { *out_len } as usize;
    match addr {
        SocketAddr::V4(v4) => {
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
            unsafe { copy_out(&sa, out, out_len, cap) };
        }
        SocketAddr::V6(v6) => {
            let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_addr.s6_addr = v6.ip().octets();
            unsafe { copy_out(&sa, out, out_len, cap) };
        }
    }
}

/// Copies at most `cap` bytes of `src` to `out` and reports its full size in `*out_len`, the
/// truncation rule of man 2 getsockname.
unsafe fn copy_out<T>(src: &T, out: *mut u8, out_len: *mut u32, cap: usize) {
    let size = size_of::<T>();
    let n = size.min(cap);
    unsafe {
        std::ptr::copy_nonoverlapping(src as *const T as *const u8, out, n);
        *out_len = size as u32;
    }
}

/// Writes an `int` getsockopt value, truncated to the caller's `*len`, and sets `*len` to 4.
///
/// # Safety
/// `val` and `len` must each be null or valid, `val` writable for `*len` bytes.
pub(crate) unsafe fn write_opt(value: i32, val: *mut u8, len: *mut u32) {
    if val.is_null() || len.is_null() {
        return;
    }
    let cap = unsafe { *len } as usize;
    let n = size_of::<i32>().min(cap);
    unsafe {
        std::ptr::copy_nonoverlapping(&value as *const i32 as *const u8, val, n);
        *len = size_of::<i32>() as u32;
    }
}

/// Where a connect waiting on its SYN stands after it was moved on.
enum Progress {
    /// Still waiting; the next point of the attempt (a retransmit or the answer) is due then.
    Pending(Deadline),
    /// This call settled it; the socket's record comes with it.
    Settled(Outcome, Arc<SockRec>),
    /// The socket is not connecting.
    Idle,
}

impl Fabric {
    /// The listener a connect to `server` reaches: one on the exact address, else — for one of
    /// the host's own addresses — one on the wildcard address of that port.
    fn listener_for(&self, server: SocketAddr, host_local: bool) -> Option<Arc<Listener>> {
        let listeners = self.regs.listeners.lock().unwrap();
        listeners
            .get(&server)
            .or_else(|| {
                host_local
                    .then(|| {
                        listeners.get(&SocketAddr::new(
                            unspecified_like(server.ip()),
                            server.port(),
                        ))
                    })
                    .flatten()
            })
            .cloned()
    }

    /// The address a connect to `server` along `sender` leaves from, from a socket bound at
    /// `bound`: an unbound socket takes the next ephemeral port, and a wildcard bind keeps its
    /// port but takes the route's source address (man 7 ip: an unbound socket is bound on
    /// `connect`).
    fn client_addr(
        &self,
        server: SocketAddr,
        bound: Option<SocketAddr>,
        sender: &Sender,
    ) -> SocketAddr {
        let src = sender
            .source(SocketAddr::new(unspecified_like(server.ip()), 0))
            .ip();
        match bound {
            Some(local) if !local.ip().is_unspecified() => local,
            Some(local) => SocketAddr::new(src, local.port()),
            None => {
                let socks = self.socks.lock().unwrap();
                let local = self.tcp_bind_addr(&socks, SocketAddr::new(src, 0), false);
                local.unwrap_or(SocketAddr::new(src, 0))
            }
        }
    }

    /// A new connection from the socket `rec` at `client` to `server` along `sender`;
    /// `server_in` when a tester accepts it (the capture then records the server side as
    /// inbound). Both pipes cross the interface hop the route takes, so a link going down hits
    /// the bytes in flight. Records the ends and egress interface on `rec`, which becomes the
    /// reader of `b_to_a` and writer of `a_to_b`. A listener of the code under test taking it
    /// counts in the host's TCP `PassiveOpens`.
    fn establish(
        &self,
        rec: &Arc<SockRec>,
        server: SocketAddr,
        client: SocketAddr,
        sender: &Sender,
        server_in: bool,
    ) -> Arc<Conn> {
        let hop = self.shared().tcp_hop(sender, server.ip());
        let via = hop.as_ref().map(|hop| hop.link.clone());
        let ends = |from, to| {
            Some(Ends {
                shared: self.regs.shared.clone(),
                from,
                to,
            })
        };
        let conn = Arc::new(Conn {
            a_to_b: Pipe::new(
                via.clone(),
                ends(client, server),
                self.shared().domain_key(),
            ),
            b_to_a: Pipe::new(via, ends(server, client), self.shared().domain_key()),
            client,
            server,
            regs: self.regs.clone(),
            hop,
            pair: false,
            tap: self.shared().tcp_tap(sender, client, server, server_in),
            stamps: Default::default(),
            write_delays: Default::default(),
            #[cfg(target_os = "macos")]
            mac_shutdown: Default::default(),
        });
        #[cfg(target_os = "linux")]
        {
            let topo = self.shared().topo();
            let mtu = topo
                .mtu_of(conn.hop.as_ref().map_or(topo.loopback_index(), |h| h.index))
                .unwrap_or(1500);
            conn.a_to_b.set_mtu(mtu);
            conn.b_to_a.set_mtu(mtu);
            for end in [End::A, End::B] {
                let weak = Arc::downgrade(&conn);
                conn.write_pipe(end)
                    .on_transmit(Box::new(move |bytes, arrival, mss| {
                        if let Some(conn) = weak.upgrade() {
                            conn.record_write(end, bytes, arrival, Some(mss), true);
                        }
                    }));
            }
        }
        rec.set_ends(client, server);
        rec.note_conn_nic(sender.egress_name());
        if !server_in {
            crate::netstats::bump(&self.shared().stats.tcp(server.ip()).passive_opens);
        }
        conn.b_to_a.read_by(rec);
        conn.a_to_b.write_by(rec);
        #[cfg(target_os = "macos")]
        conn.attach_tcp_probe(End::A, rec);
        conn
    }

    /// Plays the points of `fd`'s connect that have come. Settling it makes the socket a stream
    /// handed to the listener, or leaves it unconnected with the error pending in `SO_ERROR`.
    /// Called with no fabric lock held. This is a blocking connect, so the error is consumed as it
    /// is returned. `Idle` means another descriptor of the socket settled it meanwhile: the
    /// socket's state then says how; ECONNABORTED stands in if its error was already taken.
    fn await_connect(&self, fd: c_int) -> Option<NetResult> {
        loop {
            match self.advance_connect(fd) {
                Progress::Pending(next) => {
                    readiness().wait_until_dynamic(
                        "connect",
                        Some(next),
                        |keys| self.fd_interests([fd], keys),
                        || self.connect_due(fd),
                    );
                }
                Progress::Settled(Outcome::Connected, _) => return ok(0),
                Progress::Settled(Outcome::Failed(errno), rec) => {
                    rec.take_error();
                    return err(errno);
                }
                Progress::Idle => {
                    return match self.socks.lock().unwrap().get(&fd) {
                        Some(Sock::Stream { .. }) => ok(0),
                        Some(Sock::Fresh { rec, .. }) => {
                            err(rec.take_error().unwrap_or(libc::ECONNABORTED))
                        }
                        _ => err(libc::EBADF),
                    };
                }
            }
        }
    }

    /// Plays `fd`'s connect attempt up to now. While it is pending, returns when the next point
    /// is due. Once it settles, every descriptor sharing the attempt (dups) becomes a stream on
    /// the new connection, which joins the listener's queue, or a fresh socket with the errno
    /// pending; a SYN the plan accepts but that finds no listener any more is ECONNREFUSED.
    ///
    /// Holds `socks` throughout so no other descriptor settles the same attempt concurrently;
    /// the attempt's lock and the registries are taken under it (see the module's lock order),
    /// and readiness is bumped only after `socks` is released.
    fn advance_connect(&self, fd: c_int) -> Progress {
        let mut socks = self.socks.lock().unwrap();
        let Some(Sock::Connecting {
            local,
            rec,
            dest,
            attempt,
            ..
        }) = socks.get(&fd)
        else {
            return Progress::Idle;
        };
        let (local, rec, dest, attempt) = (*local, rec.clone(), *dest, attempt.clone());
        let client = attempt.lock().unwrap().client;
        let mut listener = None;
        let mut admission = None;
        let step = attempt.lock().unwrap().poll(|| {
            let station = self.regs.station_at(dest.ip());
            listener = self.listener_for(dest, self.shared().dest_is_host(dest.ip(), station));
            let syn = self.shared().syn_probe(dest, listener.is_some(), station);
            if matches!(syn, Syn::Accept) {
                admission = listener.as_ref().and_then(Listener::reserve);
                if admission.is_none() {
                    return Syn::Silent;
                }
            }
            syn
        });
        let outcome = match step {
            Ok(next) => return Progress::Pending(next),
            Err(outcome) => outcome,
        };
        let conn = match (outcome, listener) {
            (Outcome::Connected, Some(listener)) => {
                let station = self.regs.station_at(dest.ip());
                self.shared()
                    .route_send(&rec.view(local), dest, Op::Connect, station, true)
                    .map(|sender| {
                        let conn = self.establish(&rec, dest, client, &sender, listener.tester);
                        if let Some(lrec) = listener.rec.as_ref().and_then(std::sync::Weak::upgrade)
                        {
                            conn.a_to_b.pending_reader(lrec.state().buf);
                        }
                        (conn, listener)
                    })
            }
            (Outcome::Connected, None) => Err(crate::faults::code::ECONNREFUSED),
            (Outcome::Failed(errno), _) => Err(errno),
        };
        let Some(Sock::Connecting {
            domain,
            local,
            nonblocking,
            rec: settled_rec,
            ..
        }) = socks.get(&fd)
        else {
            return Progress::Idle;
        };
        let settled = match &conn {
            Ok((conn, _)) => Sock::Stream {
                conn: conn.clone(),
                end: End::A,
                nonblocking: *nonblocking,
                rec: settled_rec.clone(),
            },
            Err(_) => Sock::Fresh {
                domain: *domain,
                local: *local,
                nonblocking: *nonblocking,
                rec: settled_rec.clone(),
            },
        };
        socks.insert(fd, settled);
        let mut keys = crate::readiness::WakeKeys::default();
        keys.push(rec.wake_key());
        let outcome = match conn {
            Ok((conn, listener)) => {
                attempt.lock().unwrap().established(conn.tap.as_ref());
                if let Some(key) = listener.wake_key() {
                    keys.push(key);
                }
                admission
                    .expect("accepted SYN reserves a queue entry")
                    .queue(conn);
                Outcome::Connected
            }
            Err(errno) => {
                rec.state().tcp_failed = true;
                rec.set_pending_error(errno, None);
                Outcome::Failed(errno)
            }
        };
        drop(socks);
        self.shared().connect_settled(dest, outcome, true);
        self.shared().bump_keys(keys.as_slice());
        Progress::Settled(outcome, rec)
    }

    /// Moves on every connecting socket among `fds` (all of them for `None`).
    fn advance_connecting(&self, fds: Option<&[c_int]>) {
        let connecting: Vec<c_int> = self
            .socks
            .lock()
            .unwrap()
            .iter()
            .filter(|(fd, sock)| {
                matches!(sock, Sock::Connecting { .. }) && fds.is_none_or(|fds| fds.contains(fd))
            })
            .map(|(fd, _)| *fd)
            .collect();
        for fd in connecting {
            self.advance_connect(fd);
        }
    }

    /// Whether `fd`'s connect has a point to play, or is no longer waiting.
    fn connect_due(&self, fd: c_int) -> bool {
        match self.socks.lock().unwrap().get(&fd) {
            Some(Sock::Connecting { attempt, .. }) => attempt.lock().unwrap().due(),
            _ => true,
        }
    }

    /// Whether any connecting socket among `fds` (all of them for `None`) has a point to play.
    fn connecting_due(&self, fds: Option<&[c_int]>) -> bool {
        self.socks
            .lock()
            .unwrap()
            .iter()
            .any(|(fd, sock)| match sock {
                Sock::Connecting { attempt, .. } => {
                    fds.is_none_or(|fds| fds.contains(fd)) && attempt.lock().unwrap().due()
                }
                _ => false,
            })
    }
}

/// A descriptor's kind without its state, for dispatching `read`/`write` and answering `SO_TYPE`.
/// `Fresh` covers connecting sockets; `Dgram` covers `AF_UNIX` datagram ends.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Fresh,
    Stream,
    Listener,
    Dgram,
    Event,
    Epoll,
    Raw,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Kqueue,
}

pub(crate) fn readiness_sequence() -> u64 {
    static SEQUENCE: AtomicU64 = AtomicU64::new(1);
    SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
fn readiness_order(sock: &Sock, fallback: u64) -> (Duration, u64) {
    match sock {
        Sock::Dgram { queue, .. } | Sock::UnixDgram { queue, .. } => queue
            .readiness_metadata()
            .map_or((Duration::MAX, fallback), |(at, sequence, _)| {
                (at, sequence)
            }),
        Sock::Stream { conn, end, .. } => {
            let writer = if *end == End::A { End::B } else { End::A };
            let at = conn.stamps[writer.index()]
                .lock()
                .unwrap()
                .front()
                .map_or(Duration::ZERO, |(_, stamp)| stamp.mono);
            (at, conn.read_pipe(*end).read_order().max(fallback))
        }
        Sock::Listener { listener, .. } => (
            Duration::from_nanos(listener.ready_at.load(Ordering::Relaxed)),
            listener.ready_order.load(Ordering::Relaxed),
        ),
        Sock::Event {
            ready_order,
            ready_at,
            ..
        } => (*ready_at, *ready_order),
        _ => (Duration::ZERO, fallback),
    }
}

/// The Linux epoll readiness bits, as constants so this compiles on every platform (only Linux
/// creates the fds these describe). Values from include/uapi/linux/eventpoll.h (`<sys/epoll.h>`,
/// man 2 epoll_ctl). They double as the fabric's internal readiness mask on every platform, from
/// which `poll` revents and kqueue filters are derived.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const EPOLLIN: u32 = 0x001;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLLRDHUP: u32 = 0x2000;

/// The readiness of `sock` as epoll bits: [`base_mask`] plus what a pending error adds, and on
/// Linux the `EPOLLERR` a readable transmit timestamp on the error queue adds.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn ready_mask(sock: &Sock) -> u32 {
    #[cfg(target_os = "macos")]
    if let Sock::Stream { conn, .. } = sock {
        conn.progress_tcp_shutdown();
    }
    let mask = base_mask(sock);
    // A pending error: Linux reports EPOLLERR (sk_err in net/ipv4/tcp.c tcp_poll and
    // net/core/datagram.c datagram_poll); macOS makes the socket readable (soreadable,
    // XNU bsd/kern/uipc_socket2.c, true while so_error is set), which kqueue's EVFILT_READ
    // reports.
    match sock {
        Sock::Fresh { rec, .. } if rec.state().tcp_failed && cfg!(target_os = "macos") => mask,
        Sock::Stream { rec, .. } | Sock::Dgram { rec, .. } | Sock::Fresh { rec, .. }
            if rec.peek_error().is_some() =>
        {
            mask | if cfg!(target_os = "linux") {
                EPOLLERR
            } else {
                EPOLLIN
            }
        }
        #[cfg(target_os = "linux")]
        Sock::Stream { rec, .. } | Sock::Dgram { rec, .. }
            if crate::tstamp::tx_report_ready(rec) || rec.icmp_report_ready() =>
        {
            mask | EPOLLERR
        }
        _ => mask,
    }
}

/// The readiness of a datagram socket another backend of the sim serves (a Linux `SimHost`'s),
/// read from its record, and its wakes: always writable, readable with a datagram waiting, and
/// `EPOLLERR` for a pending error or a readable transmit stamp, as Linux net/core/datagram.c
/// `datagram_poll` reports `sk_err` and a non-empty `sk_error_queue` (Linux 7.0); a pending
/// error makes it readable instead on macOS, as for the fabric's own ([`ready_mask`]). `None`
/// for any other socket.
fn foreign_ready(rec: &SockRec) -> Option<(u32, Wakes)> {
    let (readable, landed) = rec.dgram_readiness()?;
    let mut mask = EPOLLOUT;
    if readable {
        mask |= EPOLLIN;
    }
    if rec.peek_error().is_some() {
        mask |= if cfg!(target_os = "linux") {
            EPOLLERR
        } else {
            EPOLLIN
        };
    }
    #[cfg(target_os = "linux")]
    if crate::tstamp::tx_report_ready(rec) || rec.icmp_report_ready() {
        mask |= EPOLLERR;
    }
    Some((
        mask,
        Wakes {
            read: landed,
            write: 0,
            error: rec.error_wakes(),
        },
    ))
}

/// The readiness of `sock` apart from a pending error. A stream is writable while its window has
/// room and readable once data, end of stream or a reset is there; datagram, eventfd and raw
/// endpoints are always writable (sends never block on them here, bar a stalled link); a
/// listener is readable with a connection pending. Epoll and kqueue fds are never ready.
fn base_mask(sock: &Sock) -> u32 {
    let (epollin, epollout) = (EPOLLIN, EPOLLOUT);
    match sock {
        Sock::Stream { conn, end, .. } => {
            let mut m = 0;
            if conn.write_pipe(*end).writable() {
                m |= epollout;
            }
            let read = conn.read_pipe(*end);
            let write = conn.write_pipe(*end);
            if read.readable_or_closed() {
                m |= epollin;
            }
            if read.read_eof() {
                m |= EPOLLRDHUP;
            }
            #[cfg(target_os = "macos")]
            let hung_up = write.reader_gone() || (read.read_eof() && write.is_write_closed());
            #[cfg(not(target_os = "macos"))]
            let hung_up = read.read_eof() && write.is_closed();
            if hung_up {
                m |= EPOLLHUP;
                if cfg!(target_os = "macos") {
                    m &= !epollout;
                }
            }
            m
        }
        Sock::Dgram { queue, .. } | Sock::UnixDgram { queue, .. } => {
            let mut m = epollout;
            if queue.has(|_| true) {
                m |= epollin;
            }
            m
        }
        Sock::Event { counter, .. } => {
            let mut m = if *counter < u64::MAX - 1 { epollout } else { 0 };
            if *counter > 0 {
                m |= epollin;
            }
            m
        }
        Sock::Raw { rx, .. } => {
            let mut m = epollout;
            if !rx.is_empty() {
                m |= epollin;
            }
            m
        }
        Sock::Listener { listener, .. } if listener.has_pending() => epollin,
        // A connect that failed: writable, with its error and the hang-up of a closed socket
        // (net/ipv4/tcp.c tcp_poll: TCP_CLOSE gives EPOLLHUP, SEND_SHUTDOWN gives EPOLLOUT, sk_err
        // gives EPOLLERR).
        Sock::Fresh { rec, .. } if rec.state().tcp_failed => {
            epollin
                | EPOLLHUP
                | if cfg!(target_os = "linux") {
                    epollout
                } else {
                    0
                }
        }
        Sock::Fresh { rec, .. } if rec.peek_error().is_some() => epollout | EPOLLERR | EPOLLHUP,
        _ => 0,
    }
}

/// `poll(2)` revents for readiness `mask` (epoll bits), for the `events` asked. `POLLERR` and
/// `POLLHUP` are reported whether asked for or not (man 2 poll: they are ignored in `events`).
fn poll_bits(mask: u32, events: i16) -> i16 {
    let mut r = 0;
    if mask & EPOLLIN != 0 && events & libc::POLLIN != 0 {
        r |= libc::POLLIN;
    }
    if mask & EPOLLOUT != 0 && events & libc::POLLOUT != 0 {
        r |= libc::POLLOUT;
    }
    #[cfg(target_os = "linux")]
    if mask & EPOLLRDHUP != 0 && events & libc::POLLRDHUP != 0 {
        r |= libc::POLLRDHUP;
    }
    if mask & EPOLLERR != 0 {
        r |= libc::POLLERR;
    }
    if mask & EPOLLHUP != 0 {
        r |= libc::POLLHUP;
    }
    r
}

/// How many times a descriptor has been woken for reading and for writing. A kernel marks an
/// edge-triggered registration ready from the wake itself, not from a change in readiness: Linux
/// fs/eventpoll.c `ep_poll_callback` queues the item on every wake whose key meets its events,
/// and XNU bsd/kern/kern_event.c `knote` runs the filter on every wake and activates the knote
/// when it fires. So data arriving at a socket already readable, or a write to an eventfd whose
/// counter is already nonzero, is a new edge.
#[derive(Clone, Copy, Default)]
struct Wakes {
    read: u64,
    write: u64,
    error: u64,
}

/// `sock`'s [`Wakes`]. Call after [`ready_mask`], which lands what has arrived by now. Sockets
/// that have not connected count none: their one edge, becoming writable or failing, is a
/// readiness bit rising.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
fn wakes(sock: &Sock) -> Wakes {
    let mut wakes = match sock {
        Sock::Stream { conn, end, .. } => Wakes {
            read: conn.read_pipe(*end).read_wakes(),
            write: conn.write_pipe(*end).write_wakes(),
            ..Wakes::default()
        },
        Sock::Dgram { queue, .. } | Sock::UnixDgram { queue, .. } => Wakes {
            read: queue.landed(),
            write: 0,
            ..Wakes::default()
        },
        Sock::Event { writes, reads, .. } => Wakes {
            read: *writes,
            write: *reads,
            ..Wakes::default()
        },
        Sock::Raw { arrived, .. } => Wakes {
            read: *arrived,
            write: 0,
            ..Wakes::default()
        },
        Sock::Listener { listener, .. } => Wakes {
            read: listener.arrivals.load(Ordering::Relaxed),
            write: 0,
            ..Wakes::default()
        },
        _ => Wakes::default(),
    };
    wakes.error = sock.rec().map_or(0, |rec| rec.error_wakes());
    wakes
}

/// The edge-trigger state of one registration: `EPOLLET` (man 7 epoll: delivered "only when
/// changes occur on the monitored file descriptor", so a wait does not report an fd again merely
/// because it is still ready) or `EV_CLEAR` (kevent(2): "After the event is retrieved by the
/// user, its state is reset"). An edge is a readiness bit rising since it was last reported, or a
/// direction that is ready having been woken ([`Wakes`]) since. The report carries the full
/// current readiness, as Linux `ep_send_events` re-polls the item (`ep_item_poll`) before
/// copying it out.
#[derive(Clone, Copy, Default)]
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
struct Edge {
    /// The bits last reported, less any since seen clear.
    seen: u32,
    /// The descriptor's wakes when last reported.
    wakes: Wakes,
}

#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
impl Edge {
    /// Whether readiness `ready` (the registration's bits) with wakes `now` holds an edge not
    /// yet reported. Forgets any reported bit `ready` lacks, so its rising again is a new edge;
    /// consumes nothing else, so a wait's predicate may ask.
    fn pending(&mut self, ready: u32, now: Wakes) -> bool {
        self.seen &= ready;
        ready & !self.seen != 0
            || (ready & EPOLLIN != 0 && now.read != self.wakes.read)
            || (ready & EPOLLOUT != 0 && now.write != self.wakes.write)
            || (ready
                & if cfg!(target_os = "linux") {
                    EPOLLERR
                } else {
                    EPOLLIN | EPOLLOUT
                }
                != 0
                && now.error != self.wakes.error)
    }

    /// Consumes the edge: readiness `ready` with wakes `now` was reported.
    fn report(&mut self, ready: u32, now: Wakes) {
        self.seen = ready;
        self.wakes = now;
    }
}

impl Sock {
    /// The socket record, for every variant that is a socket.
    fn rec(&self) -> Option<&Arc<SockRec>> {
        match self {
            Sock::Fresh { rec, .. }
            | Sock::Connecting { rec, .. }
            | Sock::Stream { rec, .. }
            | Sock::Listener { rec, .. }
            | Sock::Dgram { rec, .. }
            | Sock::UnixDgram { rec, .. }
            | Sock::Raw { rec, .. } => Some(rec),
            _ => None,
        }
    }
}

/// Whether binding TCP address `want` (with SO_REUSEADDR as `reuse`) collides with a socket that
/// holds `held`. Two addresses overlap on the same port and family when they are equal or one is
/// the wildcard. Measured against the host OS (see the bind_os_truth test): Linux refuses any
/// overlap unless both sockets set SO_REUSEADDR and the held one is not listening; macOS refuses
/// an equal address always and a wildcard overlap unless the new socket sets SO_REUSEADDR.
/// `held` is (address, its SO_REUSEADDR, whether it listens). The test is
/// bind_os_truth.rs `overlapping_binds_match_the_host`, which runs every combination against the
/// real stack (Linux: net/ipv4/inet_connection_sock.c inet_bind_conflict; XNU:
/// bsd/netinet/in_pcb.c in_pcbbind).
fn tcp_bind_conflict(held: (SocketAddr, bool, bool), want: SocketAddr, reuse: bool) -> bool {
    let (held, held_reuse, held_listening) = held;
    if held.port() != want.port() || held.is_ipv4() != want.is_ipv4() {
        return false;
    }
    let exact = held.ip() == want.ip();
    if !exact && !held.ip().is_unspecified() && !want.ip().is_unspecified() {
        return false;
    }
    if cfg!(target_os = "linux") {
        !(reuse && held_reuse && !held_listening)
    } else {
        exact || !reuse
    }
}

impl Fabric {
    /// `want` with its port resolved (an ephemeral one for port 0), or `None` when it collides
    /// with a TCP socket already bound or listening there.
    ///
    /// The held addresses are every bound fresh or connecting socket and listener in `socks`
    /// (the caller holds it), plus every registered listener, testers' included, counted as
    /// listening without SO_REUSEADDR. Established streams do not hold their port here. For port
    /// 0 it draws from the sim's ephemeral counter at most once per port in the range, so a full
    /// range gives `None` (EADDRINUSE) rather than looping.
    fn tcp_bind_addr(
        &self,
        socks: &Sockets,
        mut want: SocketAddr,
        reuse: bool,
    ) -> Option<SocketAddr> {
        let mut held: Vec<(SocketAddr, bool, bool)> = socks
            .values()
            .filter_map(|sock| match sock {
                Sock::Fresh {
                    local: Some(local),
                    rec,
                    ..
                }
                | Sock::Connecting {
                    local: Some(local),
                    rec,
                    ..
                } => Some((*local, rec.opts().reuseaddr, false)),
                Sock::Listener { listener, rec, .. } => {
                    Some((listener.addr, rec.opts().reuseaddr, true))
                }
                Sock::Stream { conn, end, rec, .. } if !conn.pair => {
                    Some((conn.local(*end), rec.opts().reuseaddr, false))
                }
                _ => None,
            })
            .collect();
        held.extend(
            self.regs
                .listeners
                .lock()
                .unwrap()
                .keys()
                .map(|a| (*a, false, true)),
        );
        let free = |addr: SocketAddr| !held.iter().any(|&h| tcp_bind_conflict(h, addr, reuse));
        if want.port() != 0 {
            return free(want).then_some(want);
        }
        let port = (0..=u16::MAX - crate::scope::EPHEMERAL_FIRST)
            .map(|_| self.shared().ephemeral_port())
            .find(|&port| free(SocketAddr::new(want.ip(), port)))?;
        want.set_port(port);
        Some(want)
    }

    /// `fd`'s [`Kind`], or `None` if the fabric does not serve it.
    fn kind(&self, fd: c_int) -> Option<Kind> {
        let socks = self.socks.lock().unwrap();
        Some(match socks.get(&fd)? {
            Sock::Fresh { .. } | Sock::Connecting { .. } => Kind::Fresh,
            Sock::Stream { .. } => Kind::Stream,
            Sock::Listener { .. } => Kind::Listener,
            Sock::Dgram { .. } | Sock::UnixDgram { .. } => Kind::Dgram,
            Sock::Event { .. } => Kind::Event,
            Sock::Epoll { .. } => Kind::Epoll,
            Sock::Raw { .. } => Kind::Raw,
            Sock::Kqueue { .. } => Kind::Kqueue,
        })
    }

    /// Whether `fd` is in nonblocking mode; only asked of eventfds and raw endpoints, so fresh
    /// and listening sockets are not listed.
    fn is_nonblocking(&self, fd: c_int) -> bool {
        let socks = self.socks.lock().unwrap();
        matches!(
            socks.get(&fd),
            Some(Sock::Event {
                nonblocking: true,
                ..
            }) | Some(Sock::Stream {
                nonblocking: true,
                ..
            }) | Some(Sock::Dgram {
                nonblocking: true,
                ..
            }) | Some(Sock::UnixDgram {
                nonblocking: true,
                ..
            }) | Some(Sock::Raw {
                nonblocking: true,
                ..
            })
        )
    }

    /// The revents of each `(fd, events)`; `POLLNVAL` for an fd closed meanwhile.
    fn poll_revents(&self, watched: &[(c_int, i16)]) -> Vec<i16> {
        let foreign: HashMap<c_int, Option<(u32, Wakes)>> = self
            .foreign_masks(watched.iter().map(|w| w.0))
            .into_iter()
            .collect();
        let socks = self.socks.lock().unwrap();
        watched
            .iter()
            .map(|(fd, events)| match socks.get(fd) {
                Some(s) => poll_bits(ready_mask(s), *events),
                None if *fd < 0 => 0,
                None => foreign
                    .get(fd)
                    .copied()
                    .flatten()
                    .map_or(libc::POLLNVAL, |(mask, _)| poll_bits(mask, *events)),
            })
            .collect()
    }

    /// The readiness of each of `fds` that is not one of the fabric's own: `Some` with
    /// [`foreign_ready`]'s answer for a datagram socket another backend of the sim serves,
    /// `None` for any other fd. The fabric's fds are left out. Takes `socks` only to tell the two
    /// apart, and reads the others' records without it.
    fn foreign_masks(
        &self,
        fds: impl Iterator<Item = c_int>,
    ) -> Vec<(c_int, Option<(u32, Wakes)>)> {
        let others: Vec<c_int> = {
            let socks = self.socks.lock().unwrap();
            fds.filter(|fd| !socks.contains_key(fd)).collect()
        };
        others
            .into_iter()
            .map(|fd| {
                let rec = self.shared().sockets.lookup_fd(fd);
                (fd, rec.as_deref().and_then(foreign_ready))
            })
            .collect()
    }

    /// Ready registrations in activation order; reported level-triggered registrations move
    /// behind the remaining ready registrations. `take` consumes edges and one-shot events.
    #[cfg(target_os = "linux")]
    fn collect_ready(&self, epfd: c_int, max: usize, take: bool) -> Vec<(u32, u64)> {
        let interested: Vec<(c_int, EpollIdentity)> = {
            let socks = self.socks.lock().unwrap();
            let Some(Sock::Epoll { interests }) = socks.get(&epfd) else {
                return Vec::new();
            };
            interests
                .keys()
                .filter(|key| !matches!(key.1, EpollIdentity::Local(_)))
                .copied()
                .collect()
        };
        let foreign: HashMap<_, (u32, Wakes)> = interested
            .into_iter()
            .filter_map(|key| {
                let rec = match key.1 {
                    EpollIdentity::Foreign(id) => self.shared().sockets.lookup_raw_id(id),
                    EpollIdentity::Untracked => self.shared().sockets.lookup_fd(key.0),
                    EpollIdentity::Local(_) => None,
                }?;
                Some((key, foreign_ready(&rec)?))
            })
            .collect();
        let mut socks = self.socks.lock().unwrap();
        let Some(Sock::Epoll { interests }) = socks.get(&epfd) else {
            return Vec::new();
        };
        let watched: Vec<_> = interests
            .iter()
            .filter(|(_, i)| !i.spent)
            .map(|(key, i)| (*key, i.events, i.data, i.edge, i.order, i.pending_order))
            .collect();
        let mut pending = Vec::new();
        let mut seen = Vec::new();
        let mut gone = Vec::new();
        for (key, events, data, mut edge, order, pending_order) in watched {
            let sock = match key.1 {
                EpollIdentity::Local(id) => socks.get_identity(id),
                EpollIdentity::Untracked => socks.get(&key.0),
                EpollIdentity::Foreign(_) => None,
            };
            let (mask, now, arrival) = match sock {
                Some(sock) => {
                    let mask = ready_mask(sock);
                    (mask, wakes(sock), readiness_order(sock, order))
                }
                None => match foreign.get(&key) {
                    Some(&(mask, now)) => (mask, now, (Duration::ZERO, order)),
                    None => {
                        gone.push(key);
                        continue;
                    }
                },
            };
            let got = mask & (events | EPOLLERR | EPOLLHUP);
            let edged = edge.pending(got, now);
            let fire = got != 0 && (events & libc::EPOLLET as u32 == 0 || edged);
            if fire {
                pending.push((pending_order.unwrap_or(arrival), key, got, data, now));
            }
            seen.push((key, edge, fire.then_some(pending_order.unwrap_or(arrival))));
        }
        pending.sort_by_key(|p| (p.0, p.1.0));
        let mut out = Vec::new();
        if let Some(Sock::Epoll { interests }) = socks.get_mut(&epfd) {
            for key in gone {
                interests.remove(&key);
            }
            for (key, edge, pending_order) in seen {
                if let Some(i) = interests.get_mut(&key) {
                    i.edge = edge;
                    i.pending_order = pending_order;
                }
            }
            for (_, key, got, data, now) in pending.into_iter().take(max) {
                out.push((got, data));
                if take && let Some(i) = interests.get_mut(&key) {
                    i.edge.report(got, now);
                    i.spent |= i.events & libc::EPOLLONESHOT as u32 != 0;
                    i.pending_order = if i.events & libc::EPOLLET as u32 == 0 {
                        Some((Duration::MAX, readiness_sequence()))
                    } else {
                        None
                    };
                }
            }
        }
        out
    }

    /// The kqueue analogue of `collect_ready`: the ready `kevent`s for a kqueue's read/write
    /// interests and fired user events, up to `max`, level-triggered or once per edge as each was
    /// added; `take` as there, and a taken report also deletes `EV_ONESHOT` registrations,
    /// disables `EV_DISPATCH` ones and resets `EV_CLEAR` user events. The kqueue state's lock is
    /// released before `socks` is taken, so the two are never nested.
    #[cfg(target_os = "macos")]
    fn collect_kevents(&self, kq: c_int, max: usize, take: bool) -> Vec<libc::kevent> {
        let state = {
            let socks = self.socks.lock().unwrap();
            match socks.get(&kq) {
                Some(Sock::Kqueue { state }) => state.clone(),
                _ => return Vec::new(),
            }
        };
        type Watch = (c_int, u64, u16, Edge);
        let live = |notes: &HashMap<c_int, Knote>| -> Vec<Watch> {
            notes
                .iter()
                .filter(|(_, n)| !n.disabled)
                .map(|(fd, n)| (*fd, n.udata, n.flags, n.edge))
                .collect()
        };
        let g = state.lock().unwrap();
        let reads = live(&g.reads);
        let writes = live(&g.writes);
        let users_ready: Vec<(usize, u64)> = g
            .users
            .iter()
            .filter(|(_, n)| n.triggered && !n.disabled)
            .map(|(id, n)| (*id, n.udata))
            .collect();
        drop(g);
        let socks = self.socks.lock().unwrap();
        let mut out = Vec::new();
        let mut seen: Vec<(i16, c_int, Edge, bool)> = Vec::new();
        for (filter, watched) in [(libc::EVFILT_READ, reads), (libc::EVFILT_WRITE, writes)] {
            if out.len() >= max {
                break;
            }
            let bit = if filter == libc::EVFILT_READ {
                EPOLLIN
            } else {
                EPOLLOUT
            };
            let mut pending = Vec::new();
            for (fd, udata, flags, mut edge) in watched {
                let Some(sock) = socks.get(&fd) else {
                    continue;
                };
                let mask = ready_mask(sock);
                let got = if matches!(sock, Sock::Fresh { rec, .. } if rec.state().tcp_failed)
                    || (filter == libc::EVFILT_WRITE
                        && matches!(sock, Sock::Stream { conn, end, .. }
                            if conn.write_pipe(*end).is_write_closed()
                                || conn.write_pipe(*end).reader_gone()))
                {
                    bit
                } else {
                    mask & bit
                };
                let now = wakes(sock);
                let edged = edge.pending(got, now);
                let fire = got != 0 && (flags & libc::EV_CLEAR == 0 || edged);
                let seen_index = seen.len();
                seen.push((filter, fd, edge, false));
                if fire {
                    pending.push((
                        readiness_order(sock, fd as u64),
                        fd,
                        udata,
                        flags,
                        got,
                        now,
                        seen_index,
                    ));
                }
            }
            pending.sort_by_key(|p| (p.0, p.1));
            for (_, fd, udata, flags, got, now, seen_index) in
                pending.into_iter().take(max - out.len())
            {
                if let Some(sock) = socks.get(&fd) {
                    let mut ev = make_kevent(fd as usize, filter, udata);
                    ev.flags = flags;
                    if let Sock::Fresh { rec, .. } = sock
                        && rec.state().tcp_failed
                    {
                        ev.flags |= libc::EV_EOF;
                        ev.fflags = rec.peek_error().unwrap_or(0) as u32;
                    }
                    if filter == libc::EVFILT_READ {
                        // kevent(2): EVFILT_READ on a listening socket reports the backlog in
                        // `data`.
                        if let Sock::Stream { conn, end, rec, .. } = sock {
                            ev.data = conn.read_pipe(*end).queued_bytes() as _;
                            if conn.read_pipe(*end).read_eof() {
                                ev.flags |= libc::EV_EOF;
                                ev.fflags = rec.peek_error().unwrap_or(0) as u32;
                            }
                        }
                        if let Sock::Dgram { queue, .. } | Sock::UnixDgram { queue, .. } = sock {
                            ev.data = queue.readiness_metadata().map_or(0, |(_, _, len)| len) as _;
                        }
                        if let Sock::Listener { listener, .. } = sock {
                            ev.data =
                                snare_interpose::real(|| listener.pending.lock().unwrap().len())
                                    as _;
                        }
                    } else {
                        // kevent(2): EVFILT_WRITE reports the free space in the send buffer in
                        // `data`.
                        if let Sock::Stream { conn, end, rec, .. } = sock {
                            ev.data = conn.write_pipe(*end).room().unwrap_or(8192) as _;
                            if conn.write_pipe(*end).is_write_closed()
                                || conn.write_pipe(*end).reader_gone()
                            {
                                ev.flags |= libc::EV_EOF;
                                ev.fflags = rec.peek_error().unwrap_or(0) as u32;
                            }
                        }
                        if let Sock::Fresh { rec, .. } = sock {
                            // XNU tcp_attach keeps sb_preconn_hiwat at 2048 until soisconnected.
                            ev.data = rec.state().buf.tcp_send_space().min(2048) as _;
                        }
                        // A socket whose connect failed reports EV_EOF with the error in fflags
                        // (XNU bsd/kern/uipc_socket.c filt_sowrite_common: SS_CANTSENDMORE →
                        // EV_EOF, kn_fflags = so_error).
                        if let Sock::Fresh { rec, .. } = sock
                            && let Some(errno) = rec.peek_error()
                        {
                            ev.flags |= libc::EV_EOF;
                            ev.fflags = errno as u32;
                        }
                    }
                    out.push(ev);
                    if take {
                        seen[seen_index].2.report(got, now);
                        seen[seen_index].3 = true;
                    }
                }
            }
        }
        drop(socks);
        let mut users_taken = Vec::new();
        for (id, udata) in users_ready {
            if out.len() >= max {
                break;
            }
            let mut ev = make_kevent(id, libc::EVFILT_USER, udata);
            ev.flags = state.lock().unwrap().users.get(&id).map_or(0, |n| n.flags);
            out.push(ev);
            users_taken.push(id);
        }
        let mut g = state.lock().unwrap();
        for (filter, fd, edge, reported) in seen {
            let notes = if filter == libc::EVFILT_READ {
                &mut g.reads
            } else {
                &mut g.writes
            };
            let Some(note) = notes.get_mut(&fd) else {
                continue;
            };
            note.edge = edge;
            if reported {
                if note.flags & libc::EV_ONESHOT != 0 {
                    notes.remove(&fd);
                } else if note.flags & libc::EV_DISPATCH != 0 {
                    note.disabled = true;
                }
            }
        }
        if take {
            for id in users_taken {
                let Some(note) = g.users.get_mut(&id) else {
                    continue;
                };
                if note.flags & libc::EV_ONESHOT != 0 {
                    g.users.remove(&id);
                    continue;
                }
                if note.flags & libc::EV_DISPATCH != 0 {
                    note.disabled = true;
                }
                if note.flags & libc::EV_CLEAR != 0 {
                    note.triggered = false;
                }
            }
        }
        out
    }

    /// An eventfd's counter without taking it; 0 for any other fd.
    fn eventfd_peek(&self, fd: c_int) -> u64 {
        let socks = self.socks.lock().unwrap();
        match socks.get(&fd) {
            Some(Sock::Event { counter, .. }) => *counter,
            _ => 0,
        }
    }

    /// Takes what one read of an eventfd returns: the whole counter, or 1 in semaphore mode
    /// (man 2 eventfd). `None` while the counter is 0.
    fn eventfd_take(&self, fd: c_int) -> Option<u64> {
        let mut socks = self.socks.lock().unwrap();
        let Some(Sock::Event {
            counter,
            semaphore,
            reads,
            ..
        }) = socks.get_mut(&fd)
        else {
            return None;
        };
        if *counter == 0 {
            return None;
        }
        *reads += 1;
        let value = if *semaphore {
            *counter -= 1;
            1
        } else {
            std::mem::take(counter)
        };
        Some(value)
    }

    /// Takes a raw endpoint's oldest received frame.
    fn raw_pop(&self, fd: c_int) -> Option<Vec<u8>> {
        let mut socks = self.socks.lock().unwrap();
        match socks.get_mut(&fd) {
            Some(Sock::Raw { rx, .. }) => rx.pop_front(),
            _ => None,
        }
    }

    /// Whether a raw endpoint has a frame waiting.
    fn raw_has(&self, fd: c_int) -> bool {
        let socks = self.socks.lock().unwrap();
        matches!(socks.get(&fd), Some(Sock::Raw { rx, .. }) if !rx.is_empty())
    }

    /// Reads one whole frame from a Linux packet socket, truncated to `len` (the rest is
    /// discarded, as for any message-based socket, man 2 recv), blocking unless nonblocking. A
    /// frame is delivered with its Ethernet header whatever the socket type: the `SOCK_DGRAM`
    /// cooked mode is not modelled.
    fn raw_read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<NetResult> {
        let frame = if let Some(f) = self.raw_pop(fd) {
            f
        } else if self.is_nonblocking(fd) {
            return would_block();
        } else if readiness().wait_until_dynamic(
            "raw recv",
            self.recv_deadline(fd),
            |keys| self.fd_interests([fd], keys),
            || self.raw_has(fd),
        ) {
            self.raw_pop(fd)?
        } else {
            return err(libc::EAGAIN); // quiescent deadlock or SO_RCVTIMEO timeout
        };
        let n = len.min(frame.len());
        unsafe { std::ptr::copy_nonoverlapping(frame.as_ptr(), buf, n) };
        ok(n as i64)
    }

    /// Sends one whole frame from a bound raw endpoint (EINVAL unbound). `SimShared::raw_send`
    /// decides by the interface's state whether it fails, is lost on the wire (`Ok(false)`, still
    /// a successful send), or goes out (`Ok(true)`), in which case every other raw endpoint bound
    /// to the same interface receives a copy: the interface is one shared L2 segment. The sender
    /// does not receive its own frame.
    fn raw_write(&self, fd: c_int, buf: *const u8, len: usize) -> Option<NetResult> {
        let frame = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
        let (ifindex, rec) = match self.socks.lock().unwrap().get(&fd) {
            Some(Sock::Raw {
                ifindex: Some(i),
                rec,
                ..
            }) => (*i, rec.clone()),
            _ => return err(libc::EINVAL),
        };
        let sent = self.shared().raw_send(ifindex, len);
        if sent.is_ok() {
            self.shared().capture_l2(ifindex, &frame);
        }
        match sent {
            Err(errno) => return err(errno),
            Ok(false) => {
                rec.count_sent();
                return ok(len as i64);
            }
            Ok(true) => rec.count_sent(),
        }
        let mut keys = crate::readiness::WakeKeys::default();
        keys.push(rec.wake_key());
        {
            let mut socks = self.socks.lock().unwrap();
            // Fan out to every other raw socket on the same interface: the shared L2 medium.
            for (other, sock) in socks.iter_mut() {
                if *other == fd
                    || sock
                        .rec()
                        .is_some_and(|other_rec| Arc::ptr_eq(other_rec, &rec))
                {
                    continue;
                }
                if let Sock::Raw {
                    ifindex: Some(oi),
                    rx,
                    arrived,
                    rec,
                    ..
                } = sock
                    && *oi == ifindex
                {
                    rx.push_back(frame.clone());
                    *arrived += 1;
                    rec.count_delivered(frame.len());
                    keys.push(rec.wake_key());
                }
            }
        }
        self.shared().bump_keys(keys.as_slice());
        ok(len as i64)
    }

    /// man 2 eventfd: read/write transfer a single 8-byte native-endian u64; a buffer under 8 bytes
    /// is EINVAL. A read drains the counter (or subtracts 1 in semaphore mode).
    fn eventfd_read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<NetResult> {
        if len < 8 {
            return err(libc::EINVAL);
        }
        let value = if let Some(v) = self.eventfd_take(fd) {
            v
        } else if self.is_nonblocking(fd) {
            return would_block();
        } else if readiness().wait_until_dynamic(
            "eventfd",
            None,
            |keys| self.fd_interests([fd], keys),
            || self.eventfd_peek(fd) > 0,
        ) {
            self.eventfd_take(fd).unwrap_or(0)
        } else {
            return err(libc::EAGAIN); // quiescent: nothing will post to this eventfd
        };
        unsafe { std::ptr::copy_nonoverlapping(value.to_ne_bytes().as_ptr(), buf, 8) };
        self.bump_fds([fd]);
        ok(8)
    }

    /// Adds an 8-byte value to the counter, waiting for room unless the descriptor is nonblocking.
    fn eventfd_write(&self, fd: c_int, buf: *const u8, len: usize) -> Option<NetResult> {
        if len < 8 {
            return err(libc::EINVAL);
        }
        let mut bytes = [0u8; 8];
        unsafe { std::ptr::copy_nonoverlapping(buf, bytes.as_mut_ptr(), 8) };
        let add = u64::from_ne_bytes(bytes);
        // man 2 eventfd: writing 0xffffffffffffffff (u64::MAX) is rejected with EINVAL.
        if add == u64::MAX {
            return err(libc::EINVAL);
        }
        loop {
            let mut socks = self.socks.lock().unwrap();
            let Some(Sock::Event {
                counter,
                writes,
                nonblocking,
                ready_order,
                ready_at,
                ..
            }) = socks.get_mut(&fd)
            else {
                return err(libc::EINVAL);
            };
            if add <= (u64::MAX - 1).saturating_sub(*counter) {
                *counter += add;
                *writes += 1;
                *ready_order = readiness_sequence();
                *ready_at = self.shared().tstamp_now().mono;
                break;
            }
            if *nonblocking {
                return err(libc::EAGAIN);
            }
            drop(socks);
            if !readiness().wait_until_dynamic(
                "eventfd write",
                None,
                |keys| self.fd_interests([fd], keys),
                || add <= (u64::MAX - 1).saturating_sub(self.eventfd_peek(fd)),
            ) {
                return err(libc::EAGAIN);
            }
        }
        self.bump_fds([fd]);
        ok(8)
    }
}

/// The macOS BPF device constants (bpf(4), `<net/bpf.h>`).
#[cfg(target_os = "macos")]
mod bpf {
    // bpf(4): request codes encoded with _IOW/_IOR from <net/bpf.h>. BIOCSETIF binds the device to
    // an interface (struct ifreq), BIOCIMMEDIATE toggles immediate (unbuffered) read mode, and
    // BIOCGBLEN reads the required read-buffer length.
    /// `_IOW('B', 108, struct ifreq)`: `IOC_IN` 0x8000_0000 | 32-byte `ifreq` << 16 |
    /// 'B' << 8 | 108.
    pub(super) const BIOCSETIF: u64 = 0x8020_426c;
    /// `_IOW('B', 112, u_int)`. Accepted and ignored: reads already return each frame at once.
    pub(super) const BIOCIMMEDIATE: u64 = 0x8004_4270;
    /// `_IOR('B', 102, u_int)`: `IOC_OUT` 0x4000_0000 | 4 << 16 | 'B' << 8 | 102.
    pub(super) const BIOCGBLEN: u64 = 0x4004_4266;
    /// The header length ethercrab expects before the frame: `BPF_WORDALIGN(18+14) - 14 == 18`.
    /// bpf(4): each packet a read returns is prefixed by a struct bpf_hdr, word-aligned. XNU
    /// bsd/net/bpf.h defines `SIZEOF_BPF_HDR` as 18 whenever `sizeof(struct bpf_hdr)` is at most
    /// 20, which it is on LP64 (an 8-byte `timeval32` stamp, `bh_caplen`, `bh_datalen`, the
    /// 2-byte `bh_hdrlen`); XNU bsd/net/bpf.c bpf_attach sets
    /// `bif_hdrlen = BPF_WORDALIGN(hdrlen + SIZEOF_BPF_HDR) - hdrlen` with a 14-byte Ethernet
    /// header and `BPF_ALIGNMENT` `sizeof(int32_t)`, which is 18.
    pub(super) const BPF_HDRLEN: usize = 18;
    /// The buffer length `BIOCGBLEN` reports: XNU's default `BPF_BUFSIZE`, 4096 (bsd/net/bpf.c).
    /// Reads here return one frame each, so it only sizes the caller's buffer.
    pub(super) const BUF_LEN: u32 = 4096;
}

/// On macOS the fabric serves `/dev/bpf*` raw L2 (ethercrab's BSD transport); on Linux it declines
/// every path (the trait defaults), so registering it as the file plane is a no-op there. A BPF
/// device is a `Sock::Raw` minted by `open` and bound with `BIOCSETIF`, framed with a `bpf_hdr`
/// on read, sharing the sim's interfaces and frame fan-out with the socket path.
impl Fs for Fabric {
    /// Whether `fd` is a raw endpoint (on macOS, always a BPF device).
    #[cfg(target_os = "macos")]
    fn owns(&self, fd: c_int) -> bool {
        matches!(self.socks.lock().unwrap().get(&fd), Some(Sock::Raw { .. }))
    }

    /// Opens any `/dev/bpf*` path as an unbound raw endpoint (every unit number is free); declines
    /// every other path.
    #[cfg(target_os = "macos")]
    unsafe fn open(
        &self,
        path: *const std::ffi::c_char,
        flags: c_int,
        _mode: u32,
    ) -> Option<NetResult> {
        if path.is_null() {
            return None;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(path) }.to_str().ok()?;
        if !name.starts_with("/dev/bpf") {
            return None; // not a BPF device: let a VirtualFs or the real OS take it
        }
        // The /dev/bpf* nodes are root-only (crw------- root:wheel: XNU bsd/net/bpf.c
        // bpf_make_dev_t creates them with mode 0600). Wireshark's ChmodBPF can loosen this on a
        // real host; the sim keeps the default.
        if !self.shared().sys.privileges().root {
            return err(libc::EACCES);
        }
        let nonblocking = flags & libc::O_NONBLOCK != 0;
        self.open_socket(SocketKind::Packet, 0, |rec| Sock::Raw {
            ifindex: None,
            rx: VecDeque::new(),
            arrived: 0,
            nonblocking,
            rec,
        })
    }

    /// The BPF ioctls ethercrab uses: `BIOCSETIF` binds the device to the interface named in the
    /// `ifreq` (ENXIO for an unknown one, as XNU bsd/net/bpf.c bpfioctl's `BIOCSETIF` case gives
    /// when `ifunit` finds no interface), `BIOCGBLEN` reports
    /// `bpf::BUF_LEN`, `BIOCIMMEDIATE` is accepted. Others are declined.
    #[cfg(target_os = "macos")]
    unsafe fn ioctl(&self, fd: c_int, request: u64, arg: i64) -> Option<NetResult> {
        if !matches!(self.socks.lock().unwrap().get(&fd), Some(Sock::Raw { .. })) {
            return None;
        }
        match request {
            bpf::BIOCIMMEDIATE => ok(0),
            bpf::BIOCGBLEN => {
                if arg == 0 {
                    return err(libc::EFAULT);
                }
                unsafe { (arg as *mut u32).write_unaligned(bpf::BUF_LEN) };
                ok(0)
            }
            bpf::BIOCSETIF => {
                let base = arg as *const u8;
                if base.is_null() {
                    return err(libc::EFAULT);
                }
                let mut name = Vec::new();
                for i in 0..libc::IFNAMSIZ {
                    let b = unsafe { *base.add(i) };
                    if b == 0 {
                        break;
                    }
                    name.push(b);
                }
                let Ok(name) = String::from_utf8(name) else {
                    return err(libc::EINVAL);
                };
                let Some(index) = self.shared().topo().index_of(&name) else {
                    return err(libc::ENXIO);
                };
                if let Some(Sock::Raw { ifindex, .. }) = self.socks.lock().unwrap().get_mut(&fd) {
                    *ifindex = Some(index);
                }
                ok(0)
            }
            _ => None,
        }
    }

    /// Reads one frame behind a `bpf_hdr`, truncated to `len`. A real BPF read returns a whole
    /// buffer of packets and fails with EINVAL unless `len` equals the buffer length (bpf(4));
    /// here each read carries exactly one frame and any length is accepted.
    #[cfg(target_os = "macos")]
    unsafe fn read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<NetResult> {
        let frame = if let Some(f) = self.raw_pop(fd) {
            f
        } else if self.is_nonblocking(fd) {
            return would_block();
        } else if readiness().wait_until_dynamic(
            "bpf read",
            self.recv_deadline(fd),
            |keys| self.fd_interests([fd], keys),
            || self.raw_has(fd),
        ) {
            self.raw_pop(fd)?
        } else {
            return err(libc::EAGAIN); // quiescent deadlock or SO_RCVTIMEO timeout
        };
        // bpf(4) struct bpf_hdr with XNU's 8-byte `timeval32` stamp (bsd/net/bpf.h BPF_TIMEVAL):
        // bh_tstamp(8, zero), bh_caplen@8, bh_datalen@12, bh_hdrlen@16, frame@18. bh_caplen ==
        // bh_datalen since nothing is truncated.
        let fl = frame.len() as u32;
        let mut out = vec![0u8; bpf::BPF_HDRLEN + frame.len()];
        out[8..12].copy_from_slice(&fl.to_ne_bytes());
        out[12..16].copy_from_slice(&fl.to_ne_bytes());
        out[16..18].copy_from_slice(&(bpf::BPF_HDRLEN as u16).to_ne_bytes());
        out[bpf::BPF_HDRLEN..].copy_from_slice(&frame);
        let n = len.min(out.len());
        unsafe { std::ptr::copy_nonoverlapping(out.as_ptr(), buf, n) };
        ok(n as i64)
    }

    /// Sends one whole Ethernet frame, as `Fabric::raw_write`.
    #[cfg(target_os = "macos")]
    unsafe fn write(&self, fd: c_int, buf: *const u8, len: usize) -> Option<NetResult> {
        self.raw_write(fd, buf, len)
    }

    /// Closes a BPF device: forgets it and closes the real fd behind it.
    #[cfg(target_os = "macos")]
    unsafe fn close(&self, fd: c_int) -> Option<NetResult> {
        unsafe { Net::close(self, fd) }
    }

    #[cfg(target_os = "macos")]
    unsafe fn fd_replaced(&self, fd: c_int) -> Option<NetResult> {
        unsafe { Net::fd_replaced(self, fd) }
    }
}

#[cfg(test)]
mod socket_arena_tests {
    use super::*;

    fn event(counter: u64) -> Sock {
        Sock::Event {
            ready_order: 0,
            ready_at: Duration::ZERO,
            counter,
            nonblocking: false,
            semaphore: false,
            writes: 0,
            reads: 0,
        }
    }

    fn counter(sockets: &Sockets, fd: c_int) -> u64 {
        let Sock::Event { counter, .. } = sockets.get(&fd).unwrap() else {
            panic!("expected event")
        };
        *counter
    }

    #[test]
    fn aliases_share_status_flags_and_socket_state() {
        crate::Sim::new().run(|| {
            let mut sockets = Sockets::default();
            sockets.insert(30, event(1));
            sockets.alias(30, 10);
            let id = sockets.identity(30).unwrap();
            sockets.description_mut(&10).unwrap().status_flags |= libc::O_NONBLOCK;
            let Sock::Event {
                counter: value,
                nonblocking,
                ..
            } = sockets.get_mut(&10).unwrap()
            else {
                unreachable!()
            };
            *value = 7;
            *nonblocking = true;
            assert_eq!(counter(&sockets, 30), 7);
            assert_eq!(sockets.identity(10), Some(id));
            assert_eq!(
                sockets.description_mut(&30).unwrap().status_flags,
                libc::O_RDWR | libc::O_NONBLOCK
            );
            assert!(matches!(
                sockets.get(&30),
                Some(Sock::Event {
                    nonblocking: true,
                    ..
                })
            ));
            assert!(sockets.remove(&10).unwrap().is_none());
            assert_eq!(counter(&sockets, 30), 7);
            assert_eq!(sockets.identity(30), Some(id));
            assert!(sockets.remove(&30).unwrap().is_some());
        });
    }

    #[test]
    fn replacement_through_an_alias_keeps_identity_and_description_flags() {
        crate::Sim::new().run(|| {
            let mut sockets = Sockets::default();
            sockets.insert(10, event(1));
            sockets.alias(10, 20);
            let id = sockets.identity(10).unwrap();
            sockets.description_mut(&20).unwrap().status_flags |= libc::O_NONBLOCK;
            sockets.insert(20, event(9));
            assert_eq!(counter(&sockets, 10), 9);
            assert_eq!(counter(&sockets, 20), 9);
            assert_eq!(sockets.identity(10), Some(id));
            assert_eq!(sockets.identity(20), Some(id));
            assert_eq!(sockets.descriptions.len(), 1);
            assert!(sockets.free_slots.is_empty());
            assert_eq!(
                sockets.description_mut(&10).unwrap().status_flags,
                libc::O_RDWR | libc::O_NONBLOCK
            );
        });
    }

    #[test]
    fn retired_slots_are_recycled_without_reusing_open_description_identity() {
        crate::Sim::new().run(|| {
            let mut sockets = Sockets::default();
            sockets.insert(10, event(1));
            sockets.alias(10, 20);
            let previous = sockets.descriptors[&10];
            assert!(sockets.remove(&10).unwrap().is_none());
            assert!(sockets.free_slots.is_empty());
            assert!(sockets.remove(&20).unwrap().is_some());
            assert!(sockets.get(&10).is_none());
            sockets.insert(10, event(2));
            let current = sockets.descriptors[&10];
            assert_eq!(current.slot, previous.slot);
            assert_ne!(current.id, previous.id);
            assert_eq!(sockets.descriptions.len(), 1);
            assert_eq!(counter(&sockets, 10), 2);
            #[cfg(target_os = "linux")]
            {
                assert!(sockets.get_identity(previous.id).is_none());
                assert!(matches!(
                    sockets.get_identity(current.id),
                    Some(Sock::Event { counter: 2, .. })
                ));
            }
            sockets.insert(30, event(3));
            let replaced = sockets.identity(30).unwrap();
            assert!(sockets.remove(&30).unwrap().is_some());
            sockets.alias(10, 30);
            assert_eq!(sockets.identity(30), Some(current.id));
            assert_eq!(counter(&sockets, 30), 2);
            #[cfg(target_os = "linux")]
            assert!(sockets.get_identity(replaced).is_none());
            #[cfg(not(target_os = "linux"))]
            let _ = replaced;
        });
    }

    #[test]
    fn description_iteration_uses_one_smallest_live_descriptor_per_alias_group() {
        crate::Sim::new().run(|| {
            let mut sockets = Sockets::default();
            sockets.insert(30, event(1));
            sockets.alias(30, 10);
            sockets.alias(30, 20);
            sockets.insert(40, event(2));
            let mut descriptors: Vec<_> = sockets.iter().map(|(fd, _)| *fd).collect();
            descriptors.sort();
            assert_eq!(descriptors, [10, 20, 30, 40]);
            let mut representatives: Vec<_> = sockets.iter_mut().map(|(fd, _)| *fd).collect();
            representatives.sort();
            assert_eq!(representatives, [10, 40]);
            assert!(sockets.remove(&10).unwrap().is_none());
            representatives = sockets.iter_mut().map(|(fd, _)| *fd).collect();
            representatives.sort();
            assert_eq!(representatives, [20, 40]);
            #[cfg(target_os = "macos")]
            assert_eq!(sockets.values().count(), 2);
        });
    }
}

#[cfg(test)]
mod payload_tests {
    use super::*;

    #[test]
    fn inline_and_heap_payloads_preserve_bytes_and_owned_conversion() {
        crate::Sim::new().run(|| {
            println!(
                "Datagram={} Payload={} Vec={} alignments={}/{}",
                std::mem::size_of::<Datagram>(),
                std::mem::size_of::<Payload>(),
                std::mem::size_of::<Vec<u8>>(),
                std::mem::align_of::<Payload>(),
                std::mem::align_of::<Vec<u8>>()
            );
            for len in [0, 127, 128, 129, 65_507] {
                let mut bytes: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
                let expected = bytes.clone();
                let payload = Payload::copy_from(&bytes);
                bytes.fill(255);
                assert_eq!(&*payload, expected);
                assert_eq!(&*payload.clone(), expected);
                assert_eq!(matches!(payload, Payload::Inline { .. }), len <= 128);
                let ptr = payload.as_ptr();
                let converted = payload.into_vec();
                assert_eq!(converted, expected);
                if len > 128 {
                    assert_eq!(converted.as_ptr(), ptr);
                }
            }
        });
    }
}

#[cfg(test)]
mod udp_port_tests {
    use super::*;

    #[test]
    fn endpoint_replacement_and_removal_preserve_station_membership() {
        use std::os::fd::AsRawFd;

        crate::Sim::new().run(|| {
            let socket = std::net::UdpSocket::bind("127.0.0.1:9000").unwrap();
            let rec = current()
                .shared
                .sockets
                .lookup_fd(socket.as_raw_fd())
                .unwrap();
            let ordinary = Arc::new(DgramQueue {
                rec: Some(rec),
                ..DgramQueue::default()
            });
            let endpoint = Arc::new(DgramQueue::default());
            let mut registry = UdpRegistry::default();
            let first: SocketAddr = "127.0.0.5:9400".parse().unwrap();
            let second: SocketAddr = "127.0.0.5:9401".parse().unwrap();
            registry.insert(first, endpoint.clone());
            registry.insert(second, endpoint.clone());
            registry.insert(first, ordinary);
            assert!(registry.endpoints.contains_key(&first.ip()));
            registry.remove(&second).unwrap();
            assert!(!registry.endpoints.contains_key(&first.ip()));
            registry.insert(first, endpoint.clone());
            registry.insert(first, endpoint);
            assert!(registry.endpoints.contains_key(&first.ip()));
            registry.remove(&first).unwrap();
            assert!(!registry.endpoints.contains_key(&first.ip()));
            assert!(registry.candidates(first, false).is_empty());
        });
    }

    #[test]
    fn port_candidates_follow_bindings_through_bucket_removals() {
        crate::Sim::new().run(|| {
            let mut registry = UdpRegistry::default();
            let addresses: Vec<SocketAddr> = [
                "127.0.0.1:9400",
                "0.0.0.0:9400",
                "127.0.0.2:9400",
                "[::1]:9400",
                "127.0.0.1:9401",
            ]
            .map(|addr| addr.parse().unwrap())
            .to_vec();
            for &address in &addresses {
                registry.insert(address, Arc::new(DgramQueue::default()));
            }
            for &address in &addresses {
                let replacement = Arc::new(DgramQueue::default());
                registry.insert(address, replacement.clone());
                assert!(
                    registry
                        .candidates(address, false)
                        .iter()
                        .find(|candidate| candidate.addr == address)
                        .is_some_and(|candidate| Arc::ptr_eq(&candidate.q, &replacement))
                );
            }
            for &removed in &addresses {
                for &destination in &addresses {
                    let mut actual: Vec<_> = registry
                        .candidates(destination, false)
                        .into_iter()
                        .map(|candidate| {
                            assert!(Arc::ptr_eq(&candidate.q, &registry.bound[&candidate.addr]));
                            candidate.addr
                        })
                        .collect();
                    let mut expected: Vec<_> = registry
                        .bound
                        .keys()
                        .filter(|addr| addr.port() == destination.port())
                        .copied()
                        .collect();
                    actual.sort();
                    expected.sort();
                    assert_eq!(actual, expected);
                }
                registry.remove(&removed).unwrap();
            }
            assert!(registry.by_port.is_empty());
        });
    }

    #[test]
    fn allocation_wraps_and_reuses_both_edges_of_a_full_range() {
        crate::Sim::new().run(|| {
            let mut ports = UdpPorts::default();
            ports.insert(UdpPorts::FIRST);
            assert_eq!(ports.alloc_from(UdpPorts::FIRST), UdpPorts::FIRST + 1);
            assert_eq!(ports.alloc_from(u16::MAX), u16::MAX);
            ports.remove(UdpPorts::FIRST);
            for port in UdpPorts::FIRST..=u16::MAX {
                ports.insert(port);
            }
            assert_eq!(ports.alloc_from(UdpPorts::FIRST), 0);
            assert_eq!(ports.alloc_from(u16::MAX), 0);
            ports.remove(UdpPorts::FIRST);
            assert_eq!(ports.alloc_from(u16::MAX), UdpPorts::FIRST);
            ports.remove(u16::MAX);
            assert_eq!(ports.alloc_from(u16::MAX - 1), u16::MAX);
            assert_eq!(ports.alloc_from(UdpPorts::FIRST), UdpPorts::FIRST);
            ports.insert(UdpPorts::FIRST);
            assert_eq!(ports.alloc_from(UdpPorts::FIRST), u16::MAX);
            ports.insert(u16::MAX);
            assert_eq!(ports.alloc_from(UdpPorts::FIRST), 0);
        });
    }

    #[test]
    fn scoped_addresses_and_queue_replacement_keep_ports_occupied() {
        crate::Sim::new().run(|| {
            let mut registry = UdpRegistry::default();
            let ip: Ipv6Addr = "fe80::1".parse().unwrap();
            let first = SocketAddr::V6(std::net::SocketAddrV6::new(ip, 49152, 0, 1));
            let second = SocketAddr::V6(std::net::SocketAddrV6::new(ip, 49152, 0, 2));
            let queue = Arc::new(DgramQueue::default());
            registry.insert(first, queue.clone());
            registry.insert(first, Arc::new(DgramQueue::default()));
            registry.insert(second, queue);
            registry.remove(&first).unwrap();
            assert_eq!(registry.alloc_port(IpAddr::V6(ip)), 49153);
            assert_eq!(
                registry.alloc_port(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
                49153
            );
            registry.remove(&second).unwrap();
            assert_eq!(registry.alloc_port(IpAddr::V6(ip)), 49152);
            assert_eq!(
                registry.alloc_port(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
                49152
            );
        });
    }
}
