//! An in-memory TCP fabric behind [`snare_interpose::Net`]. The code under test uses ordinary
//! `std::net` types; their socket calls land here and are serviced from process memory. A
//! [`Listener`](crate::Listener) registered by a tester is the peer side of a connection.

use std::collections::{HashMap, VecDeque};
use std::ffi::c_int;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{Arc, Condvar, Mutex};

use snare_interpose::{Fs, Net, NetResult};

/// One direction of a byte stream, with blocking reads.
#[derive(Default)]
struct PipeInner {
    buf: VecDeque<u8>,
    closed: bool,
    /// Aborted with a TCP reset: reads and writes fail with ECONNRESET instead of EOF/EPIPE.
    reset: bool,
    /// Written bytes still crossing the link (TCP latency), each chunk with when it arrives.
    in_flight: VecDeque<(Deadline, Vec<u8>)>,
}

#[derive(Default)]
pub(crate) struct Pipe {
    inner: Mutex<PipeInner>,
}

impl Pipe {
    /// Moves every in-flight chunk whose arrival has passed into the readable buffer, in order.
    fn land(inner: &mut PipeInner) {
        while inner.in_flight.front().is_some_and(|(at, _)| at.passed()) {
            let (_, bytes) = inner.in_flight.pop_front().expect("chunk");
            inner.buf.extend(bytes);
        }
    }

    /// Writes `bytes` to be readable `delay` from now (link latency). A write never overtakes an
    /// earlier one still in flight: TCP delivers in order.
    fn write_after(&self, bytes: &[u8], delay: std::time::Duration) -> usize {
        let mut inner = self.inner.lock().unwrap();
        if inner.closed {
            return 0;
        }
        if delay.is_zero() && inner.in_flight.is_empty() {
            inner.buf.extend(bytes);
        } else {
            let mut arrives = Deadline::after(delay);
            if let Some((last, _)) = inner.in_flight.back()
                && last.instant() > arrives.instant()
            {
                arrives = *last;
            }
            arrives.wake_waiters_then();
            inner.in_flight.push_back((arrives, bytes.to_vec()));
        }
        drop(inner);
        readiness().bump();
        bytes.len()
    }

    /// Never blocks. `Err(WouldBlock)` when open but empty; `Ok(0)` at end of stream;
    /// `Err(ConnectionReset)` once the connection was reset.
    fn read_nonblocking(&self, out: &mut [u8]) -> io::Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        if inner.reset {
            return Err(io::Error::from(io::ErrorKind::ConnectionReset));
        }
        Self::land(&mut inner);
        if inner.buf.is_empty() {
            // End of stream only once everything sent before the close has arrived.
            if inner.closed && inner.in_flight.is_empty() {
                return Ok(0);
            }
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        Ok(drain(&mut inner.buf, out))
    }

    fn close(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.closed = true;
        drop(inner);
        readiness().bump();
    }

    /// Aborts the stream as a TCP RST does: anything unread is discarded.
    fn reset(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.reset = true;
        inner.closed = true;
        inner.buf.clear();
        inner.in_flight.clear();
        drop(inner);
        readiness().bump();
    }

    fn is_reset(&self) -> bool {
        self.inner.lock().unwrap().reset
    }

    fn is_readable_or_closed(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        Self::land(&mut inner);
        !inner.buf.is_empty() || inner.reset || (inner.closed && inner.in_flight.is_empty())
    }
}

fn drain(buf: &mut VecDeque<u8>, out: &mut [u8]) -> usize {
    let n = out.len().min(buf.len());
    for slot in out.iter_mut().take(n) {
        *slot = buf.pop_front().unwrap();
    }
    n
}

/// One received datagram: its payload and the source address a `recvfrom` reports back.
pub(crate) struct Datagram {
    src: SocketAddr,
    data: Vec<u8>,
    /// Still in flight until then (link latency); `None` arrived on sending.
    arrives: Option<Deadline>,
}

impl Datagram {
    fn arrived(&self) -> bool {
        self.arrives.is_none_or(|d| d.passed())
    }

    /// Sorts arrived datagrams by arrival, so a datagram that overtook another in flight is read
    /// first; ones that arrived on sending keep their send order.
    fn arrival(&self) -> Duration {
        self.arrives.map_or(Duration::ZERO, |d| d.instant())
    }
}

/// A datagram socket's receive queue. Shared (behind an `Arc`) between the owning [`Sock::Dgram`]
/// and the per-`Sim` address registry, so a `sendto` on one socket can enqueue onto a peer's queue
/// by looking up its bound address. Blocking receives park on the process-global [`Readiness`]
/// (giving them quiescence detection), so no per-queue condvar is needed.
#[derive(Default)]
pub(crate) struct DgramQueue {
    packets: Mutex<VecDeque<Datagram>>,
}

impl DgramQueue {
    /// Queues a datagram that becomes receivable `delay` from now (its link latency).
    fn push_after(&self, src: SocketAddr, data: Vec<u8>, delay: Duration) {
        let arrives = (!delay.is_zero()).then(|| Deadline::after(delay));
        if let Some(arrives) = arrives {
            arrives.wake_waiters_then();
        }
        self.packets.lock().unwrap().push_back(Datagram { src, data, arrives });
        readiness().bump();
    }

    /// Pops the earliest-arrived datagram whose source passes `accept` (a connected socket only
    /// accepts from its peer). `None` when nothing acceptable has arrived yet.
    fn pop(&self, accept: impl Fn(SocketAddr) -> bool) -> Option<Datagram> {
        let mut q = self.packets.lock().unwrap();
        let idx = q
            .iter()
            .enumerate()
            .filter(|(_, dg)| accept(dg.src) && dg.arrived())
            .min_by_key(|(i, dg)| (dg.arrival(), *i))?
            .0;
        q.remove(idx)
    }

    fn has(&self, accept: impl Fn(SocketAddr) -> bool) -> bool {
        self.packets
            .lock()
            .unwrap()
            .iter()
            .any(|dg| accept(dg.src) && dg.arrived())
    }
}

/// A bidirectional connection. The connecting side is `A`, the accepting (tester) side is `B`.
pub(crate) struct Conn {
    a_to_b: Pipe,
    b_to_a: Pipe,
    pub(crate) client: SocketAddr,
    pub(crate) server: SocketAddr,
    /// The sim's registries, for the link policy (latency) on this connection's bytes.
    regs: Arc<Registries>,
}

#[derive(Clone, Copy, PartialEq)]
enum End {
    A,
    B,
}

impl Conn {
    fn write(&self, end: End, bytes: &[u8]) -> usize {
        let delay = self.regs.policies.tcp_delay(self.server, self.client);
        match end {
            End::A => self.a_to_b.write_after(bytes, delay),
            End::B => self.b_to_a.write_after(bytes, delay),
        }
    }

    fn read_pipe(&self, end: End) -> &Pipe {
        match end {
            End::A => &self.b_to_a,
            End::B => &self.a_to_b,
        }
    }

    fn close(&self, end: End) {
        match end {
            End::A => self.a_to_b.close(),
            End::B => self.b_to_a.close(),
        }
    }
}

/// The peer side of a listening address: connections wait here to be accepted.
pub struct Listener {
    addr: SocketAddr,
    pending: Mutex<VecDeque<Arc<Conn>>>,
    arrived: Condvar,
}

impl Listener {
    /// Takes the next connection, or `None` if none is waiting.
    pub(crate) fn try_accept(&self) -> Option<Arc<Conn>> {
        snare_interpose::real(|| self.pending.lock().unwrap().pop_front())
    }

    /// Whether a connection is waiting to be accepted.
    pub(crate) fn has_pending(&self) -> bool {
        snare_interpose::real(|| !self.pending.lock().unwrap().is_empty())
    }
}

/// The address→listener registry the fabric and the testers share. Process-global: the harness
/// runs one test per process, and within a `cargo test` run tests use distinct addresses.
/// The per-`Sim` listener + interface registries, shared by the `Fabric` and the tester free
/// functions (via the thread-local scope below) so tests never clobber each other's state.
#[derive(Default)]
pub(crate) struct Registries {
    listeners: Mutex<HashMap<SocketAddr, Arc<Listener>>>,
    interfaces: Mutex<HashMap<String, Iface>>,
    udp: Mutex<UdpRegistry>,
    /// Backends that model datagram sockets of their own (a `SimHost`), so a tester's datagram to
    /// one of their sockets is handed over rather than lost.
    foreign_udp: Mutex<Vec<std::sync::Weak<dyn ForeignUdp>>>,
    /// Per-address link faults applied to every datagram this sim delivers.
    pub(crate) policies: Policies,
}

impl Registries {
    /// Delivers one datagram from `src` to every queue `dest` reaches, through each receiving
    /// address's link policy (which may drop or duplicate it).
    fn deliver(&self, src: SocketAddr, dest: SocketAddr, data: &[u8]) {
        let recipients = self.udp.lock().unwrap().recipients(dest);
        for (addr, q) in recipients {
            for delay in self.policies.deliveries(addr, data.len()) {
                q.push_after(src, data.to_vec(), delay);
            }
        }
    }
}

/// Runs `f` on the link-policy table of `regs`.
pub(crate) fn with_policies<R>(regs: &Registries, f: impl FnOnce(&Policies) -> R) -> R {
    f(&regs.policies)
}

/// A backend with datagram sockets of its own, which a tester's UDP endpoint can reach.
pub(crate) trait ForeignUdp: Send + Sync {
    /// Delivers `data` from `src` to every one of its sockets a datagram to `dest` reaches.
    fn deliver_from_peer(&self, src: SocketAddr, dest: SocketAddr, data: &[u8]);
}

/// Makes `backend`'s datagram sockets reachable from this sim's tester endpoints.
pub(crate) fn attach_foreign_udp(regs: &Registries, backend: std::sync::Weak<dyn ForeignUdp>) {
    snare_interpose::real(|| regs.foreign_udp.lock().unwrap().push(backend));
}

/// Delivers a datagram another backend's socket sent to this sim's tester endpoints (and any
/// fabric socket) that `dest` reaches.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn deliver_to_endpoints(regs: &Registries, src: SocketAddr, dest: SocketAddr, data: &[u8]) {
    snare_interpose::real(|| regs.deliver(src, dest, data));
}

/// The datagram delivery map for one `Sim`: which receive queue a datagram sent to a given address
/// lands in, and which sockets have joined each multicast group. A bound datagram socket registers
/// its queue here under its local address; `sendto` resolves the destination against it.
#[derive(Default)]
struct UdpRegistry {
    /// Bound address → the queue to deliver unicast datagrams for that exact address into. Keyed on
    /// the full `SocketAddr`, so several addresses on one port (snare 1.x's `add_ip_addr`) and a
    /// wildcard `0.0.0.0`/`::` bind coexist.
    bound: HashMap<SocketAddr, Arc<DgramQueue>>,
    /// Multicast group address → the queues that joined it via `IP_ADD_MEMBERSHIP`
    /// (`ip_mreq`, man 7 ip) / `IPV6_ADD_MEMBERSHIP`. A datagram to the group fans out to all.
    groups: HashMap<IpAddr, Vec<(SocketAddr, Arc<DgramQueue>)>>,
}

impl UdpRegistry {
    /// Picks a free ephemeral port for `ip` from the IANA dynamic range (RFC 6335), skipping any
    /// already bound on that IP. Called while the registry is locked, so the result stays free
    /// until the caller inserts it.
    fn alloc_port(&self, ip: IpAddr) -> u16 {
        for port in 49152..=65535 {
            if !self.bound.contains_key(&SocketAddr::new(ip, port)) {
                return port;
            }
        }
        0
    }

    /// Collects every queue a datagram to `dest` should be delivered to: the exact unicast match
    /// and any wildcard bind on the same port, or — for a broadcast/multicast destination — every
    /// socket bound on that port (broadcast) or joined to the group (multicast).
    fn recipients(&self, dest: SocketAddr) -> Vec<(SocketAddr, Arc<DgramQueue>)> {
        let port = dest.port();
        if is_broadcast(dest.ip()) {
            // A broadcast datagram reaches every socket bound on the port, regardless of its IP.
            return self
                .bound
                .iter()
                .filter(|(addr, _)| addr.port() == port)
                .map(|(addr, q)| (*addr, q.clone()))
                .collect();
        }
        if dest.ip().is_multicast() {
            return self
                .groups
                .get(&dest.ip())
                .into_iter()
                .flatten()
                .filter(|(addr, _)| addr.port() == port)
                .map(|(addr, q)| (*addr, q.clone()))
                .collect();
        }
        let mut out = Vec::new();
        if let Some(q) = self.bound.get(&dest) {
            out.push((dest, q.clone()));
        }
        // A socket bound to the wildcard address also receives unicast datagrams for the port.
        let wildcard = SocketAddr::new(unspecified_like(dest.ip()), port);
        if wildcard != dest
            && let Some(q) = self.bound.get(&wildcard)
        {
            out.push((wildcard, q.clone()));
        }
        out
    }
}

/// Whether `ip` is a broadcast destination: the limited broadcast `255.255.255.255`. (Subnet
/// directed broadcasts depend on a netmask the fabric does not model; tests use the limited form.)
fn is_broadcast(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4 == Ipv4Addr::BROADCAST)
}

fn unspecified_like(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

thread_local! {
    static CURRENT: std::cell::RefCell<Option<Arc<Registries>>> = const { std::cell::RefCell::new(None) };
}

/// Installs `regs` as the calling thread's current registries until the guard drops. `Sim::run`
/// wraps the test body in this so `connect_tester`/`add_interface` reach this sim's registries.
pub(crate) fn enter(regs: Arc<Registries>) -> RegistryGuard {
    let previous = CURRENT.with(|c| c.replace(Some(regs)));
    RegistryGuard { previous }
}

pub(crate) struct RegistryGuard {
    previous: Option<Arc<Registries>>,
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        CURRENT.with(|c| *c.borrow_mut() = self.previous.take());
    }
}

fn current() -> Arc<Registries> {
    CURRENT
        .with(|c| c.borrow().clone())
        .expect("snare tester functions must be called inside Sim::run")
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
    addr: SocketAddr,
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
            udp.bound.insert(addr, queue.clone());
        });
        UdpEndpoint { regs, addr, queue }
    }

    /// The next datagram received, with its source.
    pub(crate) fn try_recv(&self) -> Option<(SocketAddr, Vec<u8>)> {
        snare_interpose::real(|| self.queue.pop(|_| true).map(|dg| (dg.src, dg.data)))
    }

    pub(crate) fn has_pending(&self) -> bool {
        snare_interpose::real(|| self.queue.has(|_| true))
    }

    /// Sends one datagram to `dest` — a socket's address, a wildcard bind's port, the broadcast
    /// address or a multicast group — from this endpoint's address.
    pub(crate) fn send_to(&self, dest: SocketAddr, data: &[u8]) {
        snare_interpose::real(|| {
            self.regs.deliver(self.addr, dest, data);
            let foreign: Vec<_> = self.regs.foreign_udp.lock().unwrap().clone();
            for backend in foreign.iter().filter_map(std::sync::Weak::upgrade) {
                backend.deliver_from_peer(self.addr, dest, data);
            }
        });
    }
}

impl Drop for UdpEndpoint {
    fn drop(&mut self) {
        snare_interpose::real(|| {
            let mut udp = self.regs.udp.lock().unwrap();
            if udp
                .bound
                .get(&self.addr)
                .is_some_and(|q| Arc::ptr_eq(q, &self.queue))
            {
                udp.bound.remove(&self.addr);
            }
        });
    }
}

/// Registers (and returns) the peer listener for `addr`, replacing any earlier one.
pub(crate) fn listen_at(addr: SocketAddr) -> Arc<Listener> {
    let listener = Arc::new(Listener {
        addr,
        pending: Mutex::default(),
        arrived: Condvar::new(),
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

/// A virtual network interface the tester declares, resolved by name via SIOCGIFINDEX /
/// if_nametoindex (man 7 netdevice, man 3 if_nametoindex) the way ethercrab's AF_PACKET
/// transport looks up its link.
#[derive(Clone, Copy)]
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) struct Iface {
    pub(crate) ifindex: u32,
    // Only the Linux SIOCGIFMTU path reads this; macOS BPF sizes reads via BIOCGBLEN.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) mtu: u32,
}

/// Registers a virtual interface `name` with the given index and MTU.
pub fn add_interface(name: &str, ifindex: u32, mtu: u32) {
    snare_interpose::real(|| {
        current()
            .interfaces
            .lock()
            .unwrap()
            .insert(name.to_string(), Iface { ifindex, mtu })
    });
}

pub(crate) use crate::readiness::readiness;
use crate::netpolicy::Policies;
use std::time::Duration;

use crate::readiness::Deadline;

enum Sock {
    Fresh {
        nonblocking: bool,
    },
    Stream {
        conn: Arc<Conn>,
        end: End,
        nonblocking: bool,
    },
    /// A UDP datagram socket. `local` is its bound address (registered in [`UdpRegistry`]); `peer`
    /// is the address a `connect` fixed, which filters receives and lets a plain `send` work.
    Dgram {
        queue: Arc<DgramQueue>,
        domain: c_int,
        local: Option<SocketAddr>,
        peer: Option<SocketAddr>,
        nonblocking: bool,
        broadcast: bool,
    },
    /// A counting eventfd (readiness wakeups).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Event {
        counter: u64,
        nonblocking: bool,
        semaphore: bool,
    },
    /// An epoll set: fd -> (interest events, user data).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Epoll {
        interests: std::collections::HashMap<c_int, (u32, u64)>,
    },
    /// A raw L2 endpoint on a virtual interface: whole Ethernet frames. On Linux this is an
    /// `AF_PACKET` socket (packet(7)); on macOS it is a `/dev/bpf*` device (bpf(4)); both share
    /// the frame fan-out.
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    Raw {
        ifindex: Option<u32>,
        rx: VecDeque<Vec<u8>>,
        nonblocking: bool,
    },
    /// A kqueue set (macOS): read/write interest per fd plus user-event (waker) triggers, each
    /// carrying the caller's `udata`. The kqueue analogue of [`Sock::Epoll`]. See kevent(2). The
    /// state is behind an `Arc` so a `dup`/`F_DUPFD` of the queue fd aliases the same set — which
    /// mio's macOS `Waker` relies on (it clones the kqueue fd and triggers through the clone).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Kqueue { state: Arc<Mutex<KqueueState>> },
}

/// The interest set of one kqueue: read/write interests keyed by fd, and user events keyed by
/// ident, each with the caller's `udata` (and, for user events, whether it has been triggered).
#[derive(Default)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) struct KqueueState {
    reads: HashMap<c_int, u64>,
    writes: HashMap<c_int, u64>,
    users: HashMap<usize, (u64, bool)>,
}

/// The [`Net`] the code under test's sockets route through.
pub struct Fabric {
    socks: Mutex<HashMap<c_int, Sock>>,
    /// `SO_RCVTIMEO` per socket (man 7 socket): a blocking receive on this fd gives up after the
    /// stored span. Kept beside `socks` rather than in every `Sock` variant, since it is set rarely
    /// and read only on a blocking receive.
    rcvtimeo: Mutex<HashMap<c_int, std::time::Duration>>,
    regs: Arc<Registries>,
    devnull: c_int,
}

impl Default for Fabric {
    fn default() -> Self {
        Self::new()
    }
}

impl Fabric {
    pub fn new() -> Self {
        // A real fd we `dup` per virtual socket, so each has a unique number the OS won't reuse
        // and `close` frees. Opened with redirection off — we are constructed outside a domain.
        let devnull = snare_interpose::real(|| unsafe {
            libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC)
        });
        Fabric {
            socks: Mutex::new(HashMap::new()),
            rcvtimeo: Mutex::new(HashMap::new()),
            regs: Arc::new(Registries::default()),
            devnull,
        }
    }

    /// The deadline a blocking receive on `fd` should honour: `now + SO_RCVTIMEO` if one is set,
    /// else `None` (wait indefinitely). Under the virtual clock the deadline is a pending timer the
    /// quiescence time-skip can jump to, so a receive timeout advances virtual time like a sleep.
    fn recv_deadline(&self, fd: c_int) -> Option<Deadline> {
        let d = *self.rcvtimeo.lock().unwrap().get(&fd)?;
        Some(Deadline::after(d))
    }

    /// The per-`Sim` registries, shared with the tester free functions for the run's duration.
    pub(crate) fn registries(&self) -> Arc<Registries> {
        self.regs.clone()
    }

    fn reserve_fd(&self) -> io::Result<c_int> {
        let fd = unsafe { libc::dup(self.devnull) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    /// Delivers one datagram from `fd` to `dest`, resolving (and lazily assigning) the sender's
    /// local address so a receiver can reply. Returns the bytes "sent" — UDP succeeds even when no
    /// socket is bound at `dest`, so an unrouted datagram is simply dropped after the count.
    fn udp_send(&self, fd: c_int, data: Vec<u8>, dest: SocketAddr) -> Option<NetResult> {
        let (src_opt, queue, domain, broadcast, nonblocking) = {
            let socks = self.socks.lock().unwrap();
            match socks.get(&fd) {
                Some(Sock::Dgram {
                    local,
                    queue,
                    domain,
                    broadcast,
                    nonblocking,
                    ..
                }) => (*local, queue.clone(), *domain, *broadcast, *nonblocking),
                _ => return None,
            }
        };
        // man 7 socket: broadcasting needs SO_BROADCAST; without it the send is refused (EACCES).
        if is_broadcast(dest.ip()) && !broadcast {
            return err(libc::EACCES);
        }
        let src = match src_opt {
            Some(sa) => sa,
            None => {
                let ip = loopback_for(domain);
                let mut regs = self.regs.udp.lock().unwrap();
                let sa = SocketAddr::new(ip, regs.alloc_port(ip));
                regs.bound.insert(sa, queue);
                drop(regs);
                if let Some(Sock::Dgram { local, .. }) = self.socks.lock().unwrap().get_mut(&fd) {
                    *local = Some(sa);
                }
                sa
            }
        };
        // A stalled link (`UdpPolicy::send_queue_depth == Some(0)`) holds the send back.
        if self.regs.policies.send_stalled(src) {
            if nonblocking {
                return would_block();
            }
            if !readiness().wait_until(None, || !self.regs.policies.send_stalled(src)) {
                return err(libc::EAGAIN);
            }
        }
        self.regs.deliver(src, dest, &data);
        ok(data.len() as i64)
    }

    /// Records that `fd` joined multicast `group`, so `sendto` to that group reaches it. A socket
    /// must be bound first (its local address carries the port the group is matched on).
    fn join_group(&self, fd: c_int, group: IpAddr) {
        let (local, queue) = {
            let socks = self.socks.lock().unwrap();
            match socks.get(&fd) {
                Some(Sock::Dgram {
                    local: Some(local),
                    queue,
                    ..
                }) => (*local, queue.clone()),
                _ => return,
            }
        };
        self.regs
            .udp
            .lock()
            .unwrap()
            .groups
            .entry(group)
            .or_default()
            .push((local, queue));
    }
}

/// The `SOCK_NONBLOCK` type flag on Linux; macOS has no such flag (it uses `fcntl`). man 2 socket:
/// `type` carries the base type in its low bits ORed with SOCK_NONBLOCK / SOCK_CLOEXEC.
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

fn err(errno: c_int) -> Option<NetResult> {
    Some(NetResult::Err(errno))
}

impl Net for Fabric {
    fn owns(&self, fd: c_int) -> bool {
        self.socks.lock().unwrap().contains_key(&fd)
    }

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
            return match self.reserve_fd() {
                Ok(fd) => {
                    self.socks.lock().unwrap().insert(
                        fd,
                        Sock::Raw {
                            ifindex: None,
                            rx: VecDeque::new(),
                            nonblocking,
                        },
                    );
                    ok(fd as i64)
                }
                Err(e) => err(e.raw_os_error().unwrap_or(libc::EMFILE)),
            };
        }
        if domain != libc::AF_INET && domain != libc::AF_INET6 {
            return None;
        }
        if base == libc::SOCK_DGRAM {
            return match self.reserve_fd() {
                Ok(fd) => {
                    self.socks.lock().unwrap().insert(
                        fd,
                        Sock::Dgram {
                            queue: Arc::new(DgramQueue::default()),
                            domain,
                            local: None,
                            peer: None,
                            nonblocking,
                            broadcast: false,
                        },
                    );
                    ok(fd as i64)
                }
                Err(e) => err(e.raw_os_error().unwrap_or(libc::EMFILE)),
            };
        }
        if base != libc::SOCK_STREAM {
            return None;
        }
        match self.reserve_fd() {
            Ok(fd) => {
                self.socks
                    .lock()
                    .unwrap()
                    .insert(fd, Sock::Fresh { nonblocking });
                ok(fd as i64)
            }
            Err(e) => err(e.raw_os_error().unwrap_or(libc::EMFILE)),
        }
    }

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
        let Some(Sock::Dgram { queue, local, .. }) = socks.get_mut(&fd) else {
            return None;
        };
        if local.is_some() {
            return err(libc::EINVAL); // man 2 bind: already bound
        }
        let Some(mut want) = (unsafe { parse_addr(addr, len) }) else {
            return err(libc::EINVAL);
        };
        let queue = queue.clone();
        let mut regs = self.regs.udp.lock().unwrap();
        if want.port() == 0 {
            want.set_port(regs.alloc_port(want.ip()));
        } else if regs.bound.contains_key(&want) {
            return err(libc::EADDRINUSE);
        }
        regs.bound.insert(want, queue);
        drop(regs);
        if let Some(Sock::Dgram { local, .. }) = socks.get_mut(&fd) {
            *local = Some(want);
        }
        ok(0)
    }

    unsafe fn connect(&self, fd: c_int, addr: *const u8, len: u32) -> Option<NetResult> {
        let Some(server) = (unsafe { parse_addr(addr, len) }) else {
            return err(libc::EINVAL);
        };
        // man 2 connect on a datagram socket: it sends nothing, it just fixes the default peer so a
        // later plain `send`/`recv` works and receives from other addresses are filtered out.
        {
            let mut socks = self.socks.lock().unwrap();
            if let Some(Sock::Dgram {
                peer,
                local,
                queue,
                domain,
                ..
            }) = socks.get_mut(&fd)
            {
                *peer = Some(server);
                if local.is_none() {
                    let q = queue.clone();
                    let ip = loopback_for(*domain);
                    let mut regs = self.regs.udp.lock().unwrap();
                    let addr = SocketAddr::new(ip, regs.alloc_port(ip));
                    regs.bound.insert(addr, q);
                    drop(regs);
                    if let Some(Sock::Dgram { local, .. }) = socks.get_mut(&fd) {
                        *local = Some(addr);
                    }
                }
                return ok(0);
            }
        }
        let listener = self.regs.listeners.lock().unwrap().get(&server).cloned();
        // man 2 connect: a TCP connect to an address with no listener is refused with ECONNREFUSED.
        let Some(listener) = listener else {
            return err(libc::ECONNREFUSED);
        };

        let mut socks = self.socks.lock().unwrap();
        let nonblocking = matches!(socks.get(&fd), Some(Sock::Fresh { nonblocking: true }));
        let client = ephemeral_client(server);
        let conn = Arc::new(Conn {
            a_to_b: Pipe::default(),
            b_to_a: Pipe::default(),
            client,
            server,
            regs: self.regs.clone(),
        });
        socks.insert(
            fd,
            Sock::Stream {
                conn: conn.clone(),
                end: End::A,
                nonblocking,
            },
        );
        drop(socks);

        listener.pending.lock().unwrap().push_back(conn);
        listener.arrived.notify_all();
        ok(0)
    }

    unsafe fn send(
        &self,
        fd: c_int,
        buf: *const u8,
        len: usize,
        _flags: c_int,
    ) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        match socks.get(&fd) {
            Some(Sock::Stream { conn, end, .. }) => {
                let bytes = unsafe { std::slice::from_raw_parts(buf, len) };
                let (conn, end) = (conn.clone(), *end);
                drop(socks);
                let n = conn.write(end, bytes);
                // man 2 send: writing to a peer that has closed its read end fails with EPIPE,
                // or ECONNRESET once the connection was reset (man 7 tcp).
                if n == 0 && len > 0 && conn.is_reset() {
                    err(libc::ECONNRESET)
                } else if n == 0 && len > 0 {
                    err(libc::EPIPE)
                } else {
                    ok(n as i64)
                }
            }
            Some(Sock::Dgram { peer, .. }) => {
                let peer = *peer;
                drop(socks);
                // man 2 send: a datagram socket with no connected peer has nowhere to send.
                let Some(dest) = peer else {
                    return err(libc::EDESTADDRREQ);
                };
                let data = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
                self.udp_send(fd, data, dest)
            }
            Some(_) => err(libc::ENOTCONN),
            None => None,
        }
    }

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
        if !matches!(self.socks.lock().unwrap().get(&fd), Some(Sock::Dgram { .. })) {
            return None;
        }
        let Some(dest) = (unsafe { parse_addr(addr, addr_len) }) else {
            return err(libc::EINVAL);
        };
        let data = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
        self.udp_send(fd, data, dest)
    }

    unsafe fn recvfrom(
        &self,
        fd: c_int,
        buf: *mut u8,
        len: usize,
        flags: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        let (queue, peer, nonblocking) = {
            let socks = self.socks.lock().unwrap();
            match socks.get(&fd) {
                Some(Sock::Dgram {
                    queue,
                    peer,
                    nonblocking,
                    ..
                }) => (queue.clone(), *peer, *nonblocking),
                _ => return None,
            }
        };
        // A connected datagram socket only receives from its peer; an unconnected one from anyone.
        let accept = |src: SocketAddr| peer.is_none_or(|p| p == src);
        let dg = if let Some(dg) = queue.pop(accept) {
            dg
        } else if nonblocking || flags & libc::MSG_DONTWAIT != 0 {
            return would_block();
        } else if readiness().wait_until(self.recv_deadline(fd), || queue.has(accept)) {
            match queue.pop(accept) {
                Some(dg) => dg,
                None => return err(libc::EAGAIN),
            }
        } else {
            return err(libc::EAGAIN); // quiescent deadlock or SO_RCVTIMEO timeout
        };
        let n = len.min(dg.data.len());
        unsafe { std::ptr::copy_nonoverlapping(dg.data.as_ptr(), buf, n) };
        if !addr.is_null() && !addr_len.is_null() {
            unsafe { write_addr(dg.src, addr, addr_len) };
        }
        ok(n as i64)
    }

    unsafe fn recv(&self, fd: c_int, buf: *mut u8, len: usize, flags: c_int) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        let (conn, end, nonblocking) = match socks.get(&fd) {
            Some(Sock::Stream {
                conn,
                end,
                nonblocking,
            }) => (conn.clone(), *end, *nonblocking),
            Some(Sock::Dgram { .. }) => {
                drop(socks);
                return unsafe {
                    self.recvfrom(fd, buf, len, flags, std::ptr::null_mut(), std::ptr::null_mut())
                };
            }
            Some(_) => return err(libc::ENOTCONN),
            None => return None,
        };
        drop(socks);
        let out = unsafe { std::slice::from_raw_parts_mut(buf, len) };
        let pipe = conn.read_pipe(end);
        // Fixed before the loop so the SO_RCVTIMEO budget covers the whole call, not each wakeup.
        let deadline = self.recv_deadline(fd);
        // man 2 recv: MSG_DONTWAIT makes this one call nonblocking regardless of the fd's mode.
        // A blocking read parks on the process-global readiness (not a per-pipe condvar) so it is
        // counted in quiescence and woken by the virtual-clock time-skip, exactly like UDP/raw.
        loop {
            match pipe.read_nonblocking(out) {
                Ok(n) => return ok(n as i64),
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                    return err(libc::ECONNRESET);
                }
                Err(_) if nonblocking || flags & libc::MSG_DONTWAIT != 0 => return would_block(),
                Err(_) => {
                    // `false` is a timeout (SO_RCVTIMEO) or a quiescent deadlock; both are EAGAIN.
                    if !readiness().wait_until(deadline, || pipe.is_readable_or_closed()) {
                        return err(libc::EAGAIN);
                    }
                }
            }
        }
    }

    unsafe fn shutdown(&self, fd: c_int, _how: c_int) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        match socks.get(&fd) {
            Some(Sock::Stream { conn, end, .. }) => {
                let (conn, end) = (conn.clone(), *end);
                drop(socks);
                conn.close(end);
                ok(0)
            }
            Some(_) => ok(0),
            None => None,
        }
    }

    unsafe fn close(&self, fd: c_int) -> Option<NetResult> {
        // Decide what to tear down while holding `socks`, then release it BEFORE touching the
        // connection: `conn.close` bumps `Readiness` (locks its state), and `wait_until` takes
        // that state then `socks` — so holding `socks` across the bump would invert the lock
        // order and can deadlock a blocked epoll_wait / raw recv / eventfd read.
        let mut dgram_cleanup: Option<(Option<SocketAddr>, Arc<DgramQueue>)> = None;
        let to_close = {
            let mut socks = self.socks.lock().unwrap();
            let sock = socks.remove(&fd)?;
            // Drop any SO_RCVTIMEO so a later socket that reuses this fd number does not inherit it.
            self.rcvtimeo.lock().unwrap().remove(&fd);
            match sock {
                Sock::Stream { conn, end, .. } => {
                    let shared = socks.values().any(|other| match other {
                        Sock::Stream { conn: c, .. } => Arc::ptr_eq(c, &conn),
                        _ => false,
                    });
                    (!shared).then_some((conn, end))
                }
                Sock::Dgram { local, queue, .. } => {
                    let shared = socks.values().any(|other| {
                        matches!(other, Sock::Dgram { queue: q, .. } if Arc::ptr_eq(q, &queue))
                    });
                    if !shared {
                        dgram_cleanup = Some((local, queue));
                    }
                    None
                }
                _ => None,
            }
        };
        if let Some((conn, end)) = to_close {
            conn.close(end);
        }
        if let Some((local, queue)) = dgram_cleanup {
            let mut regs = self.regs.udp.lock().unwrap();
            if let Some(local) = local {
                regs.bound.remove(&local);
            }
            for members in regs.groups.values_mut() {
                members.retain(|(_, q)| !Arc::ptr_eq(q, &queue));
            }
            regs.groups.retain(|_, m| !m.is_empty());
        }
        let ret = unsafe { libc::close(fd) };
        readiness().bump();
        ok(ret as i64)
    }

    unsafe fn getpeername(
        &self,
        fd: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        match socks.get(&fd) {
            Some(Sock::Stream { conn, .. }) => {
                let peer = conn.server;
                drop(socks);
                unsafe { write_addr(peer, addr, addr_len) };
                ok(0)
            }
            Some(Sock::Dgram { peer: Some(peer), .. }) => {
                let peer = *peer;
                drop(socks);
                unsafe { write_addr(peer, addr, addr_len) };
                ok(0)
            }
            Some(_) => err(libc::ENOTCONN),
            None => None,
        }
    }

    unsafe fn getsockname(
        &self,
        fd: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        match socks.get(&fd) {
            Some(Sock::Stream { conn, .. }) => {
                let local = conn.client;
                drop(socks);
                unsafe { write_addr(local, addr, addr_len) };
                ok(0)
            }
            Some(Sock::Dgram { local, domain, .. }) => {
                let local =
                    local.unwrap_or_else(|| SocketAddr::new(unspecified_like(loopback_for(*domain)), 0));
                drop(socks);
                unsafe { write_addr(local, addr, addr_len) };
                ok(0)
            }
            Some(Sock::Fresh { .. }) => {
                drop(socks);
                unsafe { write_addr(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), addr, addr_len) };
                ok(0)
            }
            _ => None,
        }
    }

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
        // man 7 socket: SO_BROADCAST permits sending to a broadcast address.
        if level == libc::SOL_SOCKET && name == libc::SO_BROADCAST {
            let on = unsafe { read_int(val, len) } != 0;
            if let Some(Sock::Dgram { broadcast, .. }) = self.socks.lock().unwrap().get_mut(&fd) {
                *broadcast = on;
            }
            return ok(0);
        }
        // man 7 socket: SO_RCVTIMEO bounds how long a blocking receive waits; a zero timeval clears
        // it (block indefinitely again).
        if level == libc::SOL_SOCKET && name == libc::SO_RCVTIMEO {
            match unsafe { parse_timeval(val, len) } {
                Some(d) if !d.is_zero() => {
                    self.rcvtimeo.lock().unwrap().insert(fd, d);
                }
                _ => {
                    self.rcvtimeo.lock().unwrap().remove(&fd);
                }
            }
            return ok(0);
        }
        // man 7 ip / ipv6: joining a multicast group so datagrams to it are delivered here.
        if let Some(group) = unsafe { parse_add_membership(level, name, val, len) } {
            self.join_group(fd, group);
            return ok(0);
        }
        ok(0)
    }

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
        // man 7 socket: report the stored SO_RCVTIMEO as a timeval (zero = unset), so code that
        // reads back what it set (e.g. std's `read_timeout`) sees it.
        if level == libc::SOL_SOCKET && name == libc::SO_RCVTIMEO {
            let d = self.rcvtimeo.lock().unwrap().get(&fd).copied().unwrap_or_default();
            unsafe { write_timeval(d, val, len) };
            return ok(0);
        }
        // Report success for the option std checks after connecting, and the socket type.
        // socket(7): SO_TYPE reports the socket's type.
        let value: i32 = if level == libc::SOL_SOCKET && name == libc::SO_TYPE {
            match self.kind(fd) {
                Some(Kind::Dgram) => libc::SOCK_DGRAM,
                _ => libc::SOCK_STREAM,
            }
        } else if level == libc::SOL_SOCKET && name == libc::SO_BROADCAST {
            matches!(
                self.socks.lock().unwrap().get(&fd),
                Some(Sock::Dgram {
                    broadcast: true,
                    ..
                })
            ) as i32
        } else {
            0
        };
        unsafe { write_opt(value, val, len) };
        ok(0)
    }

    unsafe fn fcntl(&self, fd: c_int, cmd: c_int, arg: i64) -> Option<NetResult> {
        // man 2 fcntl: F_DUPFD(_CLOEXEC) duplicates any fd we own — including the kqueue/event/epoll
        // fds — so handle it before the status-flag paths, which only apply to data sockets.
        if cmd == libc::F_DUPFD || cmd == libc::F_DUPFD_CLOEXEC {
            let mut socks = self.socks.lock().unwrap();
            let cloned = match socks.get(&fd) {
                Some(Sock::Fresh { nonblocking }) => Sock::Fresh {
                    nonblocking: *nonblocking,
                },
                Some(Sock::Stream {
                    conn,
                    end,
                    nonblocking,
                }) => Sock::Stream {
                    conn: conn.clone(),
                    end: *end,
                    nonblocking: *nonblocking,
                },
                Some(Sock::Dgram {
                    queue,
                    domain,
                    local,
                    peer,
                    nonblocking,
                    broadcast,
                }) => Sock::Dgram {
                    queue: queue.clone(),
                    domain: *domain,
                    local: *local,
                    peer: *peer,
                    nonblocking: *nonblocking,
                    broadcast: *broadcast,
                },
                // A dup'd kqueue fd aliases the same interest set (mio's macOS waker clones it).
                #[cfg(target_os = "macos")]
                Some(Sock::Kqueue { state }) => Sock::Kqueue {
                    state: state.clone(),
                },
                Some(_) => return err(libc::EINVAL), // dup of an eventfd/epoll fd isn't modelled
                None => return None,
            };
            return match self.reserve_fd() {
                Ok(new_fd) => {
                    socks.insert(new_fd, cloned);
                    // A dup shares the file description, so it shares SO_RCVTIMEO.
                    let mut timeouts = self.rcvtimeo.lock().unwrap();
                    if let Some(d) = timeouts.get(&fd).copied() {
                        timeouts.insert(new_fd, d);
                    }
                    ok(new_fd as i64)
                }
                Err(e) => err(e.raw_os_error().unwrap_or(libc::EMFILE)),
            };
        }
        let mut socks = self.socks.lock().unwrap();
        let nb = match socks.get_mut(&fd) {
            Some(Sock::Fresh { nonblocking })
            | Some(Sock::Stream { nonblocking, .. })
            | Some(Sock::Dgram { nonblocking, .. }) => nonblocking,
            _ => return None,
        };
        // man 2 fcntl: F_GETFL/F_SETFL read/set the fd's status flags (only O_NONBLOCK is settable
        // once open), F_GETFD/F_SETFD the FD_CLOEXEC flag.
        match cmd {
            libc::F_GETFL => {
                let flags = libc::O_RDWR | if *nb { libc::O_NONBLOCK } else { 0 };
                ok(flags as i64)
            }
            libc::F_SETFL => {
                *nb = arg as c_int & libc::O_NONBLOCK != 0;
                ok(0)
            }
            libc::F_GETFD | libc::F_SETFD => ok(0),
            _ => ok(0),
        }
    }

    unsafe fn ioctl(&self, fd: c_int, request: u64, arg: i64) -> Option<NetResult> {
        #[cfg(target_os = "linux")]
        if matches!(
            request as libc::c_ulong,
            libc::SIOCGIFINDEX | libc::SIOCGIFMTU
        ) {
            if !matches!(self.socks.lock().unwrap().get(&fd), Some(Sock::Raw { .. })) {
                return None;
            }
            // man 7 netdevice: SIOCGIFINDEX/SIOCGIFMTU take a struct ifreq whose ifr_name[IFNAMSIZ]
            // (IFNAMSIZ == 16) is set by the caller; the kernel writes the result into the trailing
            // union. We read the name and write the index/mtu as an i32 at offset 16 (ifr_ifindex /
            // ifr_mtu).
            let ifreq = arg as *mut u8;
            let name = unsafe { std::ffi::CStr::from_ptr(ifreq.cast::<std::ffi::c_char>()) }
                .to_string_lossy()
                .into_owned();
            let Some(iface) = self.regs.interfaces.lock().unwrap().get(&name).copied() else {
                return err(libc::ENODEV);
            };
            let value = if request as libc::c_ulong == libc::SIOCGIFINDEX {
                iface.ifindex as i32
            } else {
                iface.mtu as i32
            };
            unsafe { std::ptr::write_unaligned(ifreq.add(16).cast::<i32>(), value) };
            return ok(0);
        }
        let mut socks = self.socks.lock().unwrap();
        let nb = match socks.get_mut(&fd) {
            Some(Sock::Fresh { nonblocking })
            | Some(Sock::Stream { nonblocking, .. })
            | Some(Sock::Dgram { nonblocking, .. })
            | Some(Sock::Raw { nonblocking, .. }) => nonblocking,
            _ => return None,
        };
        // man 2 ioctl / man 7 socket: FIONBIO toggles nonblocking mode from a pointed-to int.
        if request as libc::c_ulong == libc::FIONBIO {
            let on = unsafe { *(arg as *const c_int) };
            *nb = on != 0;
            return ok(0);
        }
        ok(0)
    }

    unsafe fn poll(&self, fds: *mut u8, nfds: u64, _timeout: c_int) -> Option<NetResult> {
        // man 2 poll: each pollfd has requested `events` and returned `revents`; a connected
        // stream is always writable (POLLOUT) and readable (POLLIN) once data or EOF is pending.
        // Only handle a poll set made entirely of our fds; otherwise decline so the OS sees it.
        let pfds =
            unsafe { std::slice::from_raw_parts_mut(fds.cast::<libc::pollfd>(), nfds as usize) };
        let socks = self.socks.lock().unwrap();
        if !pfds.iter().all(|p| socks.contains_key(&p.fd)) {
            return None;
        }
        let mut ready = 0;
        for p in pfds.iter_mut() {
            p.revents = 0;
            match socks.get(&p.fd) {
                Some(Sock::Stream { conn, end, .. }) => {
                    if p.events & libc::POLLIN != 0 && conn.read_pipe(*end).is_readable_or_closed()
                    {
                        p.revents |= libc::POLLIN;
                    }
                    if p.events & libc::POLLOUT != 0 {
                        p.revents |= libc::POLLOUT;
                    }
                }
                Some(Sock::Dgram { queue, .. }) => {
                    if p.events & libc::POLLIN != 0
                        && !queue.packets.lock().unwrap().is_empty()
                    {
                        p.revents |= libc::POLLIN;
                    }
                    if p.events & libc::POLLOUT != 0 {
                        p.revents |= libc::POLLOUT;
                    }
                }
                _ => {}
            }
            if p.revents != 0 {
                ready += 1;
            }
        }
        // This poll never blocks, so a caller looping on it is busy-polling.
        drop(socks);
        snare_interpose::charge_latency();
        ok(ready)
    }

    unsafe fn read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<NetResult> {
        match self.kind(fd)? {
            Kind::Event => self.eventfd_read(fd, buf, len),
            Kind::Stream | Kind::Dgram => unsafe { self.recv(fd, buf, len, 0) },
            Kind::Raw => self.raw_read(fd, buf, len),
            _ => err(libc::EINVAL),
        }
    }

    unsafe fn write(&self, fd: c_int, buf: *const u8, len: usize) -> Option<NetResult> {
        match self.kind(fd)? {
            Kind::Event => self.eventfd_write(fd, buf, len),
            Kind::Stream | Kind::Dgram => unsafe { self.send(fd, buf, len, 0) },
            Kind::Raw => self.raw_write(fd, buf, len),
            _ => err(libc::EINVAL),
        }
    }

    // man 2 eventfd: a counting fd seeded with `initval`; EFD_NONBLOCK sets nonblocking mode and
    // EFD_SEMAPHORE makes each read decrement by one (vs. draining the whole counter).
    #[cfg(target_os = "linux")]
    unsafe fn eventfd(&self, initval: u32, flags: c_int) -> Option<NetResult> {
        let nonblocking = flags & libc::EFD_NONBLOCK != 0;
        let semaphore = flags & libc::EFD_SEMAPHORE != 0;
        match self.reserve_fd() {
            Ok(fd) => {
                self.socks.lock().unwrap().insert(
                    fd,
                    Sock::Event {
                        counter: u64::from(initval),
                        nonblocking,
                        semaphore,
                    },
                );
                ok(fd as i64)
            }
            Err(e) => err(e.raw_os_error().unwrap_or(libc::EMFILE)),
        }
    }

    // man 2 epoll_create1: creates an epoll instance and returns an fd referring to it.
    #[cfg(target_os = "linux")]
    unsafe fn epoll_create1(&self, _flags: c_int) -> Option<NetResult> {
        match self.reserve_fd() {
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

    #[cfg(target_os = "linux")]
    unsafe fn epoll_ctl(
        &self,
        epfd: c_int,
        op: c_int,
        fd: c_int,
        event: *const u8,
    ) -> Option<NetResult> {
        // man 2 epoll_ctl: `event` is a struct epoll_event { u32 events; epoll_data_t data }; the
        // 64-bit data (typically .u64/.ptr) is opaque and echoed back by epoll_wait. ADD/MOD set
        // the interest set for `fd`, DEL removes it.
        let entry = if event.is_null() {
            (0u32, 0u64)
        } else {
            let ev = unsafe { std::ptr::read_unaligned(event.cast::<libc::epoll_event>()) };
            (ev.events, ev.u64)
        };
        let mut socks = self.socks.lock().unwrap();
        let Some(Sock::Epoll { interests }) = socks.get_mut(&epfd) else {
            return err(libc::EINVAL);
        };
        match op {
            libc::EPOLL_CTL_ADD | libc::EPOLL_CTL_MOD => {
                interests.insert(fd, entry);
            }
            libc::EPOLL_CTL_DEL => {
                interests.remove(&fd);
            }
            _ => return err(libc::EINVAL),
        }
        ok(0)
    }

    // man 2 epoll_wait: fills up to `maxevents` ready epoll_event structs; `timeout` in ms, -1
    // blocks indefinitely, 0 returns at once. Returns the number of ready fds (0 on timeout).
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
        let deadline =
            (timeout >= 0).then(|| Deadline::after(std::time::Duration::from_millis(timeout as u64)));
        // A wait that returns without blocking — events already pending, or a zero timeout — is a
        // busy-poll step when repeated, so it is charged the call latency.
        let mut waited = false;
        loop {
            let ready = self.collect_ready(epfd, maxevents as usize);
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
            let woke = readiness().wait_until(deadline, || !self.collect_ready(epfd, 1).is_empty());
            if !woke {
                if timeout == 0 {
                    snare_interpose::charge_latency();
                }
                return ok(0);
            }
            waited = true;
        }
    }

    // man 2 kqueue: a new kernel event queue.
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
        if !matches!(self.socks.lock().unwrap().get(&kq), Some(Sock::Kqueue { .. })) {
            return None;
        }
        let state = {
            let socks = self.socks.lock().unwrap();
            match socks.get(&kq) {
                Some(Sock::Kqueue { state }) => state.clone(),
                _ => return None,
            }
        };
        // Apply the changelist, collecting any EV_RECEIPT acknowledgements to return at once.
        let mut receipts: Vec<libc::kevent> = Vec::new();
        let mut triggered = false;
        {
            let mut guard = state.lock().unwrap();
            let KqueueState {
                reads,
                writes,
                users,
            } = &mut *guard;
            for i in 0..nchanges.max(0) as usize {
                // `kevent` is a packed struct; read each entry by value to avoid unaligned refs.
                let ch = unsafe { changelist.cast::<libc::kevent>().add(i).read_unaligned() };
                let ident = ch.ident;
                let filter = ch.filter;
                let flags = ch.flags;
                let fflags = ch.fflags;
                let udata = ch.udata as u64;
                let adding = flags & libc::EV_ADD != 0;
                let deleting = flags & libc::EV_DELETE != 0;
                match filter {
                    libc::EVFILT_READ => {
                        if deleting {
                            reads.remove(&(ident as c_int));
                        } else if adding {
                            reads.insert(ident as c_int, udata);
                        }
                    }
                    libc::EVFILT_WRITE => {
                        if deleting {
                            writes.remove(&(ident as c_int));
                        } else if adding {
                            writes.insert(ident as c_int, udata);
                        }
                    }
                    libc::EVFILT_USER => {
                        if deleting {
                            users.remove(&ident);
                        } else {
                            let entry = users.entry(ident).or_insert((udata, false));
                            if adding {
                                entry.0 = udata;
                            }
                            // NOTE_TRIGGER marks the user event ready (mio's Waker).
                            if fflags & libc::NOTE_TRIGGER != 0 {
                                entry.1 = true;
                                triggered = true;
                            }
                        }
                    }
                    _ => {}
                }
                if flags & libc::EV_RECEIPT != 0 {
                    let mut ev = ch;
                    ev.flags = libc::EV_ERROR;
                    ev.data = 0;
                    receipts.push(ev);
                }
            }
        }
        if triggered {
            readiness().bump();
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
        // As for epoll_wait: a return that never blocked is charged the call latency.
        let immediate = deadline.is_some_and(|d| d.passed());
        let mut waited = false;
        loop {
            let ready = self.collect_kevents(kq, cap);
            if !ready.is_empty() {
                if !waited {
                    snare_interpose::charge_latency();
                }
                for (i, ev) in ready.iter().enumerate() {
                    unsafe {
                        std::ptr::write_unaligned(eventlist.cast::<libc::kevent>().add(i), *ev)
                    };
                }
                self.clear_triggered_users(kq, &ready);
                return ok(ready.len() as i64);
            }
            let woke = readiness().wait_until(deadline, || !self.collect_kevents(kq, 1).is_empty());
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
    pub(crate) fn write_from_peer(&self, bytes: &[u8]) -> usize {
        snare_interpose::real(|| self.write(End::B, bytes))
    }

    pub(crate) fn read_from_peer(&self, out: &mut [u8]) -> io::Result<usize> {
        snare_interpose::real(|| self.read_pipe(End::B).read_nonblocking(out))
    }

    pub(crate) fn close_peer(&self) {
        snare_interpose::real(|| self.close(End::B));
    }

    /// Aborts the connection with a reset (RST): the code under test's next read or write fails
    /// with ECONNRESET.
    pub(crate) fn reset_peer(&self) {
        snare_interpose::real(|| {
            self.a_to_b.reset();
            self.b_to_a.reset();
        });
    }

    /// Whether the connection was reset.
    fn is_reset(&self) -> bool {
        self.a_to_b.is_reset()
    }

    /// Whether the peer has bytes to read or has seen the code under test close its end.
    pub(crate) fn peer_readable(&self) -> bool {
        snare_interpose::real(|| self.read_pipe(End::B).is_readable_or_closed())
    }
}

fn loopback_for(domain: c_int) -> IpAddr {
    if domain == libc::AF_INET6 {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }
}

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
/// already-passed deadline (a non-blocking poll).
#[cfg(target_os = "macos")]
unsafe fn kevent_deadline(timeout: *const u8) -> Option<Deadline> {
    if timeout.is_null() {
        return None;
    }
    let ts = unsafe { timeout.cast::<libc::timespec>().read() };
    let d = std::time::Duration::new(ts.tv_sec.max(0) as u64, ts.tv_nsec.max(0) as u32);
    Some(Deadline::after(d))
}

fn ephemeral_client(server: SocketAddr) -> SocketAddr {
    use std::sync::atomic::{AtomicU16, Ordering};
    // 49152 is the low end of the IANA dynamic/ephemeral range (RFC 6335); man 7 ip documents the
    // Linux default via /proc/sys/net/ipv4/ip_local_port_range.
    static NEXT: AtomicU16 = AtomicU16::new(49152);
    let port = NEXT.fetch_add(1, Ordering::Relaxed).max(49152);
    let ip = if server.is_ipv6() {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    SocketAddr::new(ip, port)
}

/// Reads a C `int` option value (SO_BROADCAST et al.), zero if the buffer is null or too short.
unsafe fn read_int(val: *const u8, len: u32) -> c_int {
    if val.is_null() || (len as usize) < size_of::<c_int>() {
        return 0;
    }
    unsafe { val.cast::<c_int>().read_unaligned() }
}

/// Reads a `struct timeval` option value (SO_RCVTIMEO), `None` if the buffer is null or too short.
unsafe fn parse_timeval(val: *const u8, len: u32) -> Option<std::time::Duration> {
    if val.is_null() || (len as usize) < size_of::<libc::timeval>() {
        return None;
    }
    let tv = unsafe { val.cast::<libc::timeval>().read_unaligned() };
    let usecs = u64::try_from(tv.tv_usec).unwrap_or(0);
    Some(std::time::Duration::new(tv.tv_sec.max(0) as u64, (usecs % 1_000_000) as u32 * 1_000))
}

/// Writes a `struct timeval` option value back out (getsockopt SO_RCVTIMEO), clamped to the
/// caller's buffer; a null buffer or length is a no-op.
unsafe fn write_timeval(d: std::time::Duration, val: *mut u8, len: *mut u32) {
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
/// POSIX name, man 7 ipv6) on the BSDs/macOS and `IPV6_ADD_MEMBERSHIP` on Linux; both carry the
/// same numeric value and the same `ipv6_mreq` payload.
#[cfg(target_os = "linux")]
const IPV6_JOIN: c_int = libc::IPV6_ADD_MEMBERSHIP;
#[cfg(not(target_os = "linux"))]
const IPV6_JOIN: c_int = libc::IPV6_JOIN_GROUP;

/// If `(level, name)` is an `IP_ADD_MEMBERSHIP`/`IPV6_ADD_MEMBERSHIP`, reads the group address out
/// of the `ip_mreq`/`ipv6_mreq` the caller passed (its multicast address is the first field).
/// man 7 ip: `struct ip_mreq { struct in_addr imr_multiaddr; struct in_addr imr_interface; }`.
unsafe fn parse_add_membership(
    level: c_int,
    name: c_int,
    val: *const u8,
    len: u32,
) -> Option<IpAddr> {
    if val.is_null() {
        return None;
    }
    if level == libc::IPPROTO_IP && name == libc::IP_ADD_MEMBERSHIP {
        if (len as usize) < size_of::<libc::in_addr>() {
            return None;
        }
        let a = unsafe { val.cast::<libc::in_addr>().read_unaligned() };
        return Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(a.s_addr))));
    }
    if level == libc::IPPROTO_IPV6 && name == IPV6_JOIN {
        if (len as usize) < size_of::<libc::in6_addr>() {
            return None;
        }
        let a = unsafe { val.cast::<libc::in6_addr>().read_unaligned() };
        return Some(IpAddr::V6(Ipv6Addr::from(a.s6_addr)));
    }
    None
}

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

unsafe fn copy_out<T>(src: &T, out: *mut u8, out_len: *mut u32, cap: usize) {
    let size = size_of::<T>();
    let n = size.min(cap);
    unsafe {
        std::ptr::copy_nonoverlapping(src as *const T as *const u8, out, n);
        *out_len = size as u32;
    }
}

unsafe fn write_opt(value: i32, val: *mut u8, len: *mut u32) {
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

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Fresh,
    Stream,
    Dgram,
    Event,
    Epoll,
    Raw,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Kqueue,
}

/// The Linux epoll readiness bits, as constants so this compiles on every platform (only Linux
/// creates the fds these describe). Values from `<sys/epoll.h>` / man 2 epoll_ctl.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const EPOLLIN: u32 = 0x001;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const EPOLLOUT: u32 = 0x004;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn ready_mask(sock: &Sock) -> u32 {
    let (epollin, epollout) = (EPOLLIN, EPOLLOUT);
    match sock {
        Sock::Stream { conn, end, .. } => {
            let mut m = epollout;
            if conn.read_pipe(*end).is_readable_or_closed() {
                m |= epollin;
            }
            m
        }
        Sock::Dgram { queue, .. } => {
            let mut m = epollout;
            if !queue.packets.lock().unwrap().is_empty() {
                m |= epollin;
            }
            m
        }
        Sock::Event { counter, .. } => {
            let mut m = epollout;
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
        _ => 0,
    }
}

impl Fabric {
    fn kind(&self, fd: c_int) -> Option<Kind> {
        let socks = self.socks.lock().unwrap();
        Some(match socks.get(&fd)? {
            Sock::Fresh { .. } => Kind::Fresh,
            Sock::Stream { .. } => Kind::Stream,
            Sock::Dgram { .. } => Kind::Dgram,
            Sock::Event { .. } => Kind::Event,
            Sock::Epoll { .. } => Kind::Epoll,
            Sock::Raw { .. } => Kind::Raw,
            Sock::Kqueue { .. } => Kind::Kqueue,
        })
    }

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
            }) | Some(Sock::Raw {
                nonblocking: true,
                ..
            })
        )
    }

    #[cfg(target_os = "linux")]
    fn collect_ready(&self, epfd: c_int, max: usize) -> Vec<(u32, u64)> {
        let socks = self.socks.lock().unwrap();
        let Some(Sock::Epoll { interests }) = socks.get(&epfd) else {
            return Vec::new();
        };
        let interests: Vec<(c_int, u32, u64)> = interests
            .iter()
            .map(|(fd, (ev, data))| (*fd, *ev, *data))
            .collect();
        let mut out = Vec::new();
        for (fd, want, data) in interests {
            if out.len() >= max {
                break;
            }
            if let Some(sock) = socks.get(&fd) {
                let got = ready_mask(sock) & want;
                if got != 0 {
                    out.push((got, data));
                }
            }
        }
        out
    }

    /// The kqueue analogue of [`collect_ready`](Self::collect_ready): the ready `kevent`s for a
    /// kqueue's read/write interests and triggered user events, up to `max`.
    #[cfg(target_os = "macos")]
    fn collect_kevents(&self, kq: c_int, max: usize) -> Vec<libc::kevent> {
        let state = {
            let socks = self.socks.lock().unwrap();
            match socks.get(&kq) {
                Some(Sock::Kqueue { state }) => state.clone(),
                _ => return Vec::new(),
            }
        };
        let g = state.lock().unwrap();
        let reads: Vec<(c_int, u64)> = g.reads.iter().map(|(f, u)| (*f, *u)).collect();
        let writes: Vec<(c_int, u64)> = g.writes.iter().map(|(f, u)| (*f, *u)).collect();
        let users_ready: Vec<(usize, u64)> = g
            .users
            .iter()
            .filter(|(_, (_, t))| *t)
            .map(|(id, (u, _))| (*id, *u))
            .collect();
        drop(g);
        let socks = self.socks.lock().unwrap();
        let mut out = Vec::new();
        for (fd, udata) in reads {
            if out.len() >= max {
                return out;
            }
            if let Some(sock) = socks.get(&fd)
                && ready_mask(sock) & EPOLLIN != 0
            {
                out.push(make_kevent(fd as usize, libc::EVFILT_READ, udata));
            }
        }
        for (fd, udata) in writes {
            if out.len() >= max {
                return out;
            }
            if let Some(sock) = socks.get(&fd)
                && ready_mask(sock) & EPOLLOUT != 0
            {
                out.push(make_kevent(fd as usize, libc::EVFILT_WRITE, udata));
            }
        }
        for (id, udata) in users_ready {
            if out.len() >= max {
                return out;
            }
            out.push(make_kevent(id, libc::EVFILT_USER, udata));
        }
        out
    }

    /// Clears the one-shot (`EV_CLEAR`) trigger on each user event just reported, so a waker fires
    /// once per `NOTE_TRIGGER` the way mio relies on.
    #[cfg(target_os = "macos")]
    fn clear_triggered_users(&self, kq: c_int, reported: &[libc::kevent]) {
        let state = {
            let socks = self.socks.lock().unwrap();
            match socks.get(&kq) {
                Some(Sock::Kqueue { state }) => state.clone(),
                _ => return,
            }
        };
        let mut g = state.lock().unwrap();
        for ev in reported {
            let ev = *ev;
            if ev.filter == libc::EVFILT_USER
                && let Some(entry) = g.users.get_mut(&{ ev.ident })
            {
                entry.1 = false;
            }
        }
    }

    fn eventfd_peek(&self, fd: c_int) -> u64 {
        let socks = self.socks.lock().unwrap();
        match socks.get(&fd) {
            Some(Sock::Event { counter, .. }) => *counter,
            _ => 0,
        }
    }

    fn eventfd_take(&self, fd: c_int) -> Option<u64> {
        let mut socks = self.socks.lock().unwrap();
        let Some(Sock::Event {
            counter, semaphore, ..
        }) = socks.get_mut(&fd)
        else {
            return None;
        };
        if *counter == 0 {
            return None;
        }
        let value = if *semaphore {
            *counter -= 1;
            1
        } else {
            std::mem::take(counter)
        };
        Some(value)
    }

    fn raw_pop(&self, fd: c_int) -> Option<Vec<u8>> {
        let mut socks = self.socks.lock().unwrap();
        match socks.get_mut(&fd) {
            Some(Sock::Raw { rx, .. }) => rx.pop_front(),
            _ => None,
        }
    }

    fn raw_has(&self, fd: c_int) -> bool {
        let socks = self.socks.lock().unwrap();
        matches!(socks.get(&fd), Some(Sock::Raw { rx, .. }) if !rx.is_empty())
    }

    fn raw_read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<NetResult> {
        let frame = if let Some(f) = self.raw_pop(fd) {
            f
        } else if self.is_nonblocking(fd) {
            return would_block();
        } else if readiness().wait_until(self.recv_deadline(fd), || self.raw_has(fd)) {
            self.raw_pop(fd)?
        } else {
            return err(libc::EAGAIN); // quiescent deadlock or SO_RCVTIMEO timeout
        };
        let n = len.min(frame.len());
        unsafe { std::ptr::copy_nonoverlapping(frame.as_ptr(), buf, n) };
        ok(n as i64)
    }

    fn raw_write(&self, fd: c_int, buf: *const u8, len: usize) -> Option<NetResult> {
        let frame = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
        {
            let mut socks = self.socks.lock().unwrap();
            let ifindex = match socks.get(&fd) {
                Some(Sock::Raw {
                    ifindex: Some(i), ..
                }) => *i,
                Some(Sock::Raw { ifindex: None, .. }) => return err(libc::EINVAL),
                _ => return err(libc::EINVAL),
            };
            // Fan out to every other raw socket on the same interface: the shared L2 medium.
            for (other, sock) in socks.iter_mut() {
                if *other == fd {
                    continue;
                }
                if let Sock::Raw {
                    ifindex: Some(oi),
                    rx,
                    ..
                } = sock
                    && *oi == ifindex
                {
                    rx.push_back(frame.clone());
                }
            }
        }
        readiness().bump();
        ok(len as i64)
    }

    // man 2 eventfd: read/write transfer a single 8-byte native-endian u64; a buffer under 8 bytes
    // is EINVAL. A read drains the counter (or subtracts 1 in semaphore mode).
    fn eventfd_read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<NetResult> {
        if len < 8 {
            return err(libc::EINVAL);
        }
        let value = if let Some(v) = self.eventfd_take(fd) {
            v
        } else if self.is_nonblocking(fd) {
            return would_block();
        } else if readiness().wait_until(None, || self.eventfd_peek(fd) > 0) {
            self.eventfd_take(fd).unwrap_or(0)
        } else {
            return err(libc::EAGAIN); // quiescent: nothing will post to this eventfd
        };
        unsafe { std::ptr::copy_nonoverlapping(value.to_ne_bytes().as_ptr(), buf, 8) };
        readiness().bump();
        ok(8)
    }

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
        {
            let mut socks = self.socks.lock().unwrap();
            let Some(Sock::Event { counter, .. }) = socks.get_mut(&fd) else {
                return err(libc::EINVAL);
            };
            *counter = counter.saturating_add(add);
        }
        readiness().bump();
        ok(8)
    }
}

#[cfg(target_os = "macos")]
mod bpf {
    // bpf(4): request codes encoded with _IOW/_IOR from <net/bpf.h>. BIOCSETIF binds the device to
    // an interface (struct ifreq), BIOCIMMEDIATE toggles immediate (unbuffered) read mode, and
    // BIOCGBLEN reads the required read-buffer length.
    pub(super) const BIOCSETIF: u64 = 0x8020_426c;
    pub(super) const BIOCIMMEDIATE: u64 = 0x8004_4270;
    pub(super) const BIOCGBLEN: u64 = 0x4004_4266;
    /// The header length ethercrab expects before the frame: `BPF_WORDALIGN(18+14) - 14 == 18`.
    /// bpf(4): each packet a read returns is prefixed by a struct bpf_hdr, word-aligned.
    pub(super) const BPF_HDRLEN: usize = 18;
    pub(super) const BUF_LEN: u32 = 4096;
}

/// On macOS the fabric serves `/dev/bpf*` raw L2 (ethercrab's BSD transport); on Linux it declines
/// every path (the trait defaults), so registering it as the file plane is a no-op there. A BPF
/// device is a [`Sock::Raw`] minted by `open` and bound with `BIOCSETIF`, framed with a `bpf_hdr`
/// on read, sharing the interface registry and frame fan-out with the socket path.
impl Fs for Fabric {
    #[cfg(target_os = "macos")]
    fn owns(&self, fd: c_int) -> bool {
        matches!(self.socks.lock().unwrap().get(&fd), Some(Sock::Raw { .. }))
    }

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
        let nonblocking = flags & libc::O_NONBLOCK != 0;
        match self.reserve_fd() {
            Ok(fd) => {
                self.socks.lock().unwrap().insert(
                    fd,
                    Sock::Raw {
                        ifindex: None,
                        rx: VecDeque::new(),
                        nonblocking,
                    },
                );
                ok(fd as i64)
            }
            Err(e) => err(e.raw_os_error().unwrap_or(libc::EMFILE)),
        }
    }

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
                for i in 0..16 {
                    let b = unsafe { *base.add(i) };
                    if b == 0 {
                        break;
                    }
                    name.push(b);
                }
                let Ok(name) = String::from_utf8(name) else {
                    return err(libc::EINVAL);
                };
                let Some(iface) = self.regs.interfaces.lock().unwrap().get(&name).copied() else {
                    return err(libc::ENXIO);
                };
                if let Some(Sock::Raw { ifindex, .. }) = self.socks.lock().unwrap().get_mut(&fd) {
                    *ifindex = Some(iface.ifindex);
                }
                ok(0)
            }
            _ => None,
        }
    }

    #[cfg(target_os = "macos")]
    unsafe fn read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<NetResult> {
        let frame = if let Some(f) = self.raw_pop(fd) {
            f
        } else if self.is_nonblocking(fd) {
            return would_block();
        } else if readiness().wait_until(self.recv_deadline(fd), || self.raw_has(fd)) {
            self.raw_pop(fd)?
        } else {
            return err(libc::EAGAIN); // quiescent deadlock or SO_RCVTIMEO timeout
        };
        // bpf(4) struct bpf_hdr: bh_tstamp(8, zero), bh_caplen@8, bh_datalen@12, bh_hdrlen@16,
        // frame@18. bh_caplen == bh_datalen since nothing is truncated.
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

    #[cfg(target_os = "macos")]
    unsafe fn write(&self, fd: c_int, buf: *const u8, len: usize) -> Option<NetResult> {
        self.raw_write(fd, buf, len)
    }

    #[cfg(target_os = "macos")]
    unsafe fn close(&self, fd: c_int) -> Option<NetResult> {
        self.socks.lock().unwrap().remove(&fd)?;
        let ret = unsafe { libc::close(fd) };
        readiness().bump();
        ok(ret as i64)
    }
}
