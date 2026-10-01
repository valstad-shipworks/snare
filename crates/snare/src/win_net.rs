//! An in-memory Winsock fabric behind [`snare_interpose::Net`] for Windows. The code under test
//! uses ordinary `std::net` types; their `ws2_32` socket calls land here and are serviced from
//! process memory. TCP (`SOCK_STREAM`) and UDP (`SOCK_DGRAM`) are both modelled. Handles are minted
//! in the `c_int` range (Winsock `SOCKET` is wider, but the sim's own handles stay small), so the
//! interposer casts between `SOCKET` and `c_int` losslessly for the sockets it owns.

use std::collections::{HashMap, VecDeque};
use std::ffi::{c_char, c_int};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicI32, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use snare_interpose::{Net, NetResult};

use crate::netpolicy::Policies;
use crate::readiness::{Deadline, readiness};

// Winsock error codes (`<winerror.h>` / WSAGetLastError). The hooks pass these to WSASetLastError.
const WSAEACCES: c_int = 10013;
const WSAEFAULT: c_int = 10014;
const WSAEINVAL: c_int = 10022;
const WSAEWOULDBLOCK: c_int = 10035;
const WSAENOTCONN: c_int = 10057;
const WSAEADDRINUSE: c_int = 10048;
const WSAEDESTADDRREQ: c_int = 10039;
const WSAECONNREFUSED: c_int = 10061;
const WSAECONNRESET: c_int = 10054;
const WSAETIMEDOUT: c_int = 10060;
const WSAESHUTDOWN: c_int = 10058;

// Winsock address families and socket types (`<winsock2.h>`): AF_INET = 2, AF_INET6 = 23,
// SOCK_STREAM = 1, SOCK_DGRAM = 2. The IPv6 family value differs from unix (10/30).
const AF_INET: c_int = 2;
const AF_INET6: c_int = 23;
const SOCK_STREAM: c_int = 1;
const SOCK_DGRAM: c_int = 2;
const SOL_SOCKET: c_int = 0xffff;
const SO_TYPE: c_int = 0x1008;
const SO_BROADCAST: c_int = 0x0020;
// winsock2.h: SO_RCVTIMEO takes a DWORD of milliseconds (0 = no timeout).
const SO_RCVTIMEO: c_int = 0x1006;
const IPPROTO_IP: c_int = 0;
const IPPROTO_IPV6: c_int = 41;
const IP_ADD_MEMBERSHIP: c_int = 12;
const IPV6_ADD_MEMBERSHIP: c_int = 12;
// ioctlsocket command: FIONBIO sets non-blocking mode (`<winsock2.h>`).
const FIONBIO: u64 = 0x8004667e;

// WSAPoll event bits (`<winsock2.h>`): POLLRDNORM = normal data readable, POLLWRNORM = writable.
// `std`/code commonly request POLLIN (= POLLRDNORM | POLLRDBAND) and POLLOUT (= POLLWRNORM).
const POLLRDNORM: i16 = 0x0100;
const POLLRDBAND: i16 = 0x0200;
const POLLIN: i16 = POLLRDNORM | POLLRDBAND;
const POLLWRNORM: i16 = 0x0010;
const POLLOUT: i16 = POLLWRNORM;

/// `WSAPOLLFD` (`<winsock2.h>`): a `SOCKET` with requested `events` and returned `revents`.
#[repr(C)]
#[derive(Clone, Copy)]
struct WsaPollfd {
    fd: usize,
    events: i16,
    revents: i16,
}

fn ok(n: i64) -> Option<NetResult> {
    Some(NetResult::Ok(n))
}

/// A non-blocking call that found nothing to do: `WSAEWOULDBLOCK`, charged the call latency so a
/// caller busy-polling it still lets a discrete virtual clock move (see
/// `snare_interpose::charge_latency`). Called with no `WinNet` lock held.
fn would_block() -> Option<NetResult> {
    snare_interpose::charge_latency();
    err(WSAEWOULDBLOCK)
}

fn err(code: c_int) -> Option<NetResult> {
    Some(NetResult::Err(code))
}

/// One direction of a TCP byte stream, with blocking reads that park on the shared readiness signal.
#[derive(Default)]
struct Pipe {
    inner: Mutex<PipeInner>,
}

#[derive(Default)]
struct PipeInner {
    buf: VecDeque<u8>,
    closed: bool,
    /// Aborted with a reset: reads and writes fail with WSAECONNRESET.
    reset: bool,
    /// Written bytes still crossing the link (TCP latency), each chunk with when it arrives.
    in_flight: VecDeque<(Deadline, Vec<u8>)>,
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

    fn read(&self, out: &mut [u8]) -> io_read::Outcome {
        let mut inner = self.inner.lock().unwrap();
        if inner.reset {
            return io_read::Outcome::Reset;
        }
        Self::land(&mut inner);
        if inner.buf.is_empty() {
            // End of stream only once everything sent before the close has arrived.
            return if inner.closed && inner.in_flight.is_empty() {
                io_read::Outcome::Eof
            } else {
                io_read::Outcome::WouldBlock
            };
        }
        let n = out.len().min(inner.buf.len());
        for slot in out.iter_mut().take(n) {
            *slot = inner.buf.pop_front().unwrap();
        }
        io_read::Outcome::Read(n)
    }

    fn close(&self) {
        self.inner.lock().unwrap().closed = true;
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

    fn readable_or_closed(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        Self::land(&mut inner);
        !inner.buf.is_empty() || inner.reset || (inner.closed && inner.in_flight.is_empty())
    }
}

mod io_read {
    pub(super) enum Outcome {
        Read(usize),
        WouldBlock,
        Eof,
        Reset,
    }
}

#[derive(Clone, Copy, PartialEq)]
enum End {
    A,
    B,
}

/// A bidirectional TCP connection. The connecting side is `A`, the accepting side `B`.
pub(crate) struct Conn {
    a_to_b: Pipe,
    b_to_a: Pipe,
    pub(crate) client: SocketAddr,
    server: SocketAddr,
    /// The sim's registries, for the link policy (latency) on this connection's bytes.
    regs: Arc<Registries>,
}

impl Conn {
    fn write(&self, end: End, bytes: &[u8]) -> usize {
        let delay = self
            .regs
            .lock()
            .unwrap()
            .policies
            .tcp_delay(self.server, self.client);
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

    fn local(&self, end: End) -> SocketAddr {
        match end {
            End::A => self.client,
            End::B => self.server,
        }
    }

    fn peer(&self, end: End) -> SocketAddr {
        match end {
            End::A => self.server,
            End::B => self.client,
        }
    }
}

/// A listening socket's queue of connections waiting to be accepted.
#[derive(Default)]
pub(crate) struct ListenerState {
    pending: Mutex<VecDeque<Arc<Conn>>>,
}

/// The peer side of a listening address, as a tester holds it.
pub(crate) type Listener = ListenerState;

/// One received datagram and the source a `recvfrom` reports.
struct Datagram {
    src: SocketAddr,
    data: Vec<u8>,
    /// Still in flight until then (link latency); `None` arrived on sending.
    arrives: Option<Deadline>,
}

impl Datagram {
    fn arrived(&self) -> bool {
        self.arrives.is_none_or(|d| d.passed())
    }

    fn arrival(&self) -> std::time::Duration {
        self.arrives.map_or(std::time::Duration::ZERO, |d| d.instant())
    }
}

/// A datagram socket's receive queue, shared (behind an `Arc`) between the owning socket and the
/// per-sim delivery registry. Blocking receives park on the shared readiness signal.
#[derive(Default)]
pub(crate) struct DgramQueue {
    packets: Mutex<VecDeque<Datagram>>,
}

impl DgramQueue {
    /// Queues a datagram that becomes receivable `delay` from now (its link latency).
    fn push_after(&self, src: SocketAddr, data: Vec<u8>, delay: std::time::Duration) {
        let arrives = (!delay.is_zero()).then(|| Deadline::after(delay));
        if let Some(arrives) = arrives {
            arrives.wake_waiters_then();
        }
        self.packets.lock().unwrap().push_back(Datagram { src, data, arrives });
        readiness().bump();
    }

    /// Pops the earliest-arrived datagram whose source passes `accept`.
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

enum Sock {
    Fresh {
        nonblocking: bool,
        local: Option<SocketAddr>,
    },
    Stream {
        conn: Arc<Conn>,
        end: End,
        nonblocking: bool,
    },
    Listener {
        state: Arc<ListenerState>,
        addr: SocketAddr,
        nonblocking: bool,
    },
    Dgram {
        queue: Arc<DgramQueue>,
        domain: c_int,
        local: Option<SocketAddr>,
        peer: Option<SocketAddr>,
        nonblocking: bool,
        broadcast: bool,
    },
}

#[derive(Default)]
pub(crate) struct Registry {
    /// Per-address link faults applied to every datagram this sim delivers.
    policies: Policies,
    udp: HashMap<SocketAddr, Arc<DgramQueue>>,
    groups: HashMap<IpAddr, Vec<(SocketAddr, Arc<DgramQueue>)>>,
    listeners: HashMap<SocketAddr, Arc<ListenerState>>,
}

impl Registry {
    fn alloc_port(&self, ip: IpAddr) -> u16 {
        (49152..=65535)
            .find(|&p| !self.udp.contains_key(&SocketAddr::new(ip, p)))
            .unwrap_or(0)
    }

    fn recipients(&self, dest: SocketAddr) -> Vec<(SocketAddr, Arc<DgramQueue>)> {
        let port = dest.port();
        if is_broadcast(dest.ip()) {
            return self
                .udp
                .iter()
                .filter(|(a, _)| a.port() == port)
                .map(|(a, q)| (*a, q.clone()))
                .collect();
        }
        if dest.ip().is_multicast() {
            return self
                .groups
                .get(&dest.ip())
                .into_iter()
                .flatten()
                .filter(|(a, _)| a.port() == port)
                .map(|(a, q)| (*a, q.clone()))
                .collect();
        }
        let mut out = Vec::new();
        if let Some(q) = self.udp.get(&dest) {
            out.push((dest, q.clone()));
        }
        let wildcard = SocketAddr::new(unspecified_like(dest.ip()), port);
        if wildcard != dest
            && let Some(q) = self.udp.get(&wildcard)
        {
            out.push((wildcard, q.clone()));
        }
        out
    }

    /// The queues a datagram to `dest` reaches, each with how many copies its link policy lets
    /// through.
    fn deliveries(
        &self,
        dest: SocketAddr,
        len: usize,
    ) -> Vec<(Arc<DgramQueue>, Vec<std::time::Duration>)> {
        self.recipients(dest)
            .into_iter()
            .map(|(addr, q)| (q, self.policies.deliveries(addr, len)))
            .collect()
    }
}

fn is_broadcast(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4 == Ipv4Addr::BROADCAST)
}

fn unspecified_like(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

fn loopback_for(domain: c_int) -> IpAddr {
    if domain == AF_INET6 {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }
}

fn ephemeral_client(server: SocketAddr) -> SocketAddr {
    static NEXT: AtomicU16 = AtomicU16::new(49152);
    let port = NEXT.fetch_add(1, Ordering::Relaxed).max(49152);
    let ip = if server.is_ipv6() {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    SocketAddr::new(ip, port)
}

/// One npcap capture handle on a virtual link: whole Ethernet frames, fanned out to every other
/// handle opened on the same device. `last_*` keep the most recently returned frame and its
/// `pcap_pkthdr` alive (behind the `Arc` so their heap buffers stay put) for `pcap_next_ex`, whose
/// returned pointers must stay valid until the next call.
struct PcapHandle {
    device: Vec<u8>,
    rx: VecDeque<Vec<u8>>,
    last_frame: Vec<u8>,
    last_hdr: Vec<u8>,
}

/// The [`Net`] Windows managed threads' sockets route through.
pub(crate) struct WinNet {
    socks: Mutex<HashMap<c_int, Sock>>,
    /// `SO_RCVTIMEO` per socket: a blocking receive gives up after the stored span.
    rcvtimeo: Mutex<HashMap<c_int, std::time::Duration>>,
    regs: Arc<Registries>,
    next_handle: AtomicI32,
    pcaps: Mutex<HashMap<u64, PcapHandle>>,
    next_pcap: std::sync::atomic::AtomicU64,
}

impl WinNet {
    pub(crate) fn new() -> Self {
        WinNet {
            socks: Mutex::new(HashMap::new()),
            rcvtimeo: Mutex::new(HashMap::new()),
            regs: Arc::default(),
            // Mint handles well above the stdio range so they never collide with low real fds.
            next_handle: AtomicI32::new(0x2000),
            pcaps: Mutex::new(HashMap::new()),
            // pcap_t handles are opaque pointers to the code under test; mint distinctive values.
            next_pcap: std::sync::atomic::AtomicU64::new(0x9000_0000),
        }
    }

    /// The per-sim registries, shared with the testers for the run's duration.
    pub(crate) fn registries(&self) -> Arc<Registries> {
        self.regs.clone()
    }

    /// The deadline a blocking receive on `fd` honours: `SO_RCVTIMEO` from now, if set.
    fn recv_deadline(&self, fd: c_int) -> Option<Deadline> {
        let span = *self.rcvtimeo.lock().unwrap().get(&fd)?;
        Some(Deadline::after(span))
    }

    fn mint(&self) -> c_int {
        self.next_handle.fetch_add(1, Ordering::Relaxed)
    }

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
        if is_broadcast(dest.ip()) && !broadcast {
            return err(WSAEACCES);
        }
        let src = match src_opt {
            Some(sa) => sa,
            None => {
                let ip = loopback_for(domain);
                let mut regs = self.regs.lock().unwrap();
                let sa = SocketAddr::new(ip, regs.alloc_port(ip));
                regs.udp.insert(sa, queue);
                drop(regs);
                if let Some(Sock::Dgram { local, .. }) = self.socks.lock().unwrap().get_mut(&fd) {
                    *local = Some(sa);
                }
                sa
            }
        };
        // A stalled link (`UdpPolicy::send_queue_depth == Some(0)`) holds the send back.
        let stalled = || self.regs.lock().unwrap().policies.send_stalled(src);
        if stalled() {
            if nonblocking {
                return would_block();
            }
            if !readiness().wait_until(None, || !stalled()) {
                return err(WSAEWOULDBLOCK);
            }
        }
        let deliveries = self.regs.lock().unwrap().deliveries(dest, data.len());
        for (q, delays) in deliveries {
            for delay in delays {
                q.push_after(src, data.clone(), delay);
            }
        }
        ok(data.len() as i64)
    }

    /// The `revents` for one `WSAPOLLFD`: which of the requested `events` are satisfied now.
    fn poll_revents(&self, fd: c_int, events: i16) -> i16 {
        let socks = self.socks.lock().unwrap();
        let Some(sock) = socks.get(&fd) else {
            return 0;
        };
        let (readable, writable) = match sock {
            Sock::Stream { conn, end, .. } => (conn.read_pipe(*end).readable_or_closed(), true),
            Sock::Dgram { queue, .. } => (!queue.packets.lock().unwrap().is_empty(), true),
            Sock::Listener { state, .. } => (!state.pending.lock().unwrap().is_empty(), false),
            Sock::Fresh { .. } => (false, false),
        };
        let mut r = 0i16;
        if events & POLLIN != 0 && readable {
            r |= POLLRDNORM;
        }
        if events & POLLOUT != 0 && writable {
            r |= POLLWRNORM;
        }
        r
    }

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
            .lock()
            .unwrap()
            .groups
            .entry(group)
            .or_default()
            .push((local, queue));
    }
}

impl Net for WinNet {
    fn owns(&self, fd: c_int) -> bool {
        self.socks.lock().unwrap().contains_key(&fd)
    }

    unsafe fn socket(&self, domain: c_int, ty: c_int, _protocol: c_int) -> Option<NetResult> {
        if domain != AF_INET && domain != AF_INET6 {
            return None;
        }
        let base = ty & 0xff;
        let sock = match base {
            SOCK_STREAM => Sock::Fresh {
                nonblocking: false,
                local: None,
            },
            SOCK_DGRAM => Sock::Dgram {
                queue: Arc::new(DgramQueue::default()),
                domain,
                local: None,
                peer: None,
                nonblocking: false,
                broadcast: false,
            },
            _ => return None,
        };
        let fd = self.mint();
        self.socks.lock().unwrap().insert(fd, sock);
        ok(fd as i64)
    }

    unsafe fn bind(&self, fd: c_int, addr: *const u8, len: u32) -> Option<NetResult> {
        let Some(want) = (unsafe { parse_addr(addr, len) }) else {
            return err(WSAEFAULT);
        };
        let mut socks = self.socks.lock().unwrap();
        match socks.get_mut(&fd) {
            Some(Sock::Fresh { local, .. }) => {
                *local = Some(want);
                ok(0)
            }
            Some(Sock::Dgram { local, queue, .. }) => {
                if local.is_some() {
                    return err(WSAEINVAL);
                }
                let queue = queue.clone();
                let mut want = want;
                let mut regs = self.regs.lock().unwrap();
                if want.port() == 0 {
                    want.set_port(regs.alloc_port(want.ip()));
                } else if regs.udp.contains_key(&want) {
                    return err(WSAEADDRINUSE);
                }
                regs.udp.insert(want, queue);
                drop(regs);
                if let Some(Sock::Dgram { local, .. }) = socks.get_mut(&fd) {
                    *local = Some(want);
                }
                ok(0)
            }
            _ => None,
        }
    }

    unsafe fn listen(&self, fd: c_int, _backlog: c_int) -> Option<NetResult> {
        let mut socks = self.socks.lock().unwrap();
        let Some(Sock::Fresh { local, .. }) = socks.get(&fd) else {
            return None;
        };
        let addr = local.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
        let state = Arc::new(ListenerState::default());
        self.regs
            .lock()
            .unwrap()
            .listeners
            .insert(addr, state.clone());
        socks.insert(
            fd,
            Sock::Listener {
                state,
                addr,
                nonblocking: false,
            },
        );
        ok(0)
    }

    unsafe fn accept(
        &self,
        fd: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
        _flags: c_int,
    ) -> Option<NetResult> {
        let (state, nonblocking) = {
            let socks = self.socks.lock().unwrap();
            match socks.get(&fd) {
                Some(Sock::Listener {
                    state, nonblocking, ..
                }) => (state.clone(), *nonblocking),
                _ => return None,
            }
        };
        let pop = || state.pending.lock().unwrap().pop_front();
        let conn = if let Some(c) = pop() {
            c
        } else if nonblocking {
            return would_block();
        } else if readiness().wait_until(None, || !state.pending.lock().unwrap().is_empty()) {
            match pop() {
                Some(c) => c,
                None => return err(WSAEWOULDBLOCK),
            }
        } else {
            return err(WSAEWOULDBLOCK);
        };
        let peer = conn.client;
        let new_fd = self.mint();
        self.socks.lock().unwrap().insert(
            new_fd,
            Sock::Stream {
                conn,
                end: End::B,
                nonblocking: false,
            },
        );
        if !addr.is_null() && !addr_len.is_null() {
            unsafe { write_addr(peer, addr, addr_len) };
        }
        ok(new_fd as i64)
    }

    unsafe fn connect(&self, fd: c_int, addr: *const u8, len: u32) -> Option<NetResult> {
        let Some(dest) = (unsafe { parse_addr(addr, len) }) else {
            return err(WSAEFAULT);
        };
        // UDP connect just fixes the default peer.
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
                *peer = Some(dest);
                if local.is_none() {
                    let q = queue.clone();
                    let ip = loopback_for(*domain);
                    let mut regs = self.regs.lock().unwrap();
                    let sa = SocketAddr::new(ip, regs.alloc_port(ip));
                    regs.udp.insert(sa, q);
                    drop(regs);
                    if let Some(Sock::Dgram { local, .. }) = socks.get_mut(&fd) {
                        *local = Some(sa);
                    }
                }
                return ok(0);
            }
            if !matches!(socks.get(&fd), Some(Sock::Fresh { .. })) {
                return None;
            }
        }
        // TCP connect: find the listener, hand it a fresh connection, become its A end.
        let listener = self.regs.lock().unwrap().listeners.get(&dest).cloned();
        let Some(listener) = listener else {
            return err(WSAECONNREFUSED);
        };
        let conn = Arc::new(Conn {
            a_to_b: Pipe::default(),
            b_to_a: Pipe::default(),
            client: ephemeral_client(dest),
            server: dest,
            regs: self.regs.clone(),
        });
        {
            let mut socks = self.socks.lock().unwrap();
            let nonblocking = matches!(
                socks.get(&fd),
                Some(Sock::Fresh {
                    nonblocking: true,
                    ..
                })
            );
            socks.insert(
                fd,
                Sock::Stream {
                    conn: conn.clone(),
                    end: End::A,
                    nonblocking,
                },
            );
        }
        listener.pending.lock().unwrap().push_back(conn);
        readiness().bump();
        ok(0)
    }

    unsafe fn send(&self, fd: c_int, buf: *const u8, len: usize, _flags: c_int) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        match socks.get(&fd) {
            Some(Sock::Stream { conn, end, .. }) => {
                let (conn, end) = (conn.clone(), *end);
                drop(socks);
                let bytes = unsafe { std::slice::from_raw_parts(buf, len) };
                let n = conn.write(end, bytes);
                if n == 0 && len > 0 && conn.a_to_b.is_reset() {
                    err(WSAECONNRESET)
                } else if n == 0 && len > 0 {
                    err(WSAESHUTDOWN)
                } else {
                    ok(n as i64)
                }
            }
            Some(Sock::Dgram { peer, .. }) => {
                let peer = *peer;
                drop(socks);
                let Some(dest) = peer else {
                    return err(WSAEDESTADDRREQ);
                };
                let data = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
                self.udp_send(fd, data, dest)
            }
            Some(_) => err(WSAENOTCONN),
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
        if addr.is_null() {
            return unsafe { self.send(fd, buf, len, flags) };
        }
        if !matches!(self.socks.lock().unwrap().get(&fd), Some(Sock::Dgram { .. })) {
            return None;
        }
        let Some(dest) = (unsafe { parse_addr(addr, addr_len) }) else {
            return err(WSAEFAULT);
        };
        let data = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
        self.udp_send(fd, data, dest)
    }

    unsafe fn recv(&self, fd: c_int, buf: *mut u8, len: usize, flags: c_int) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        match socks.get(&fd) {
            Some(Sock::Stream {
                conn,
                end,
                nonblocking,
            }) => {
                let (conn, end, nonblocking) = (conn.clone(), *end, *nonblocking);
                drop(socks);
                let out = unsafe { std::slice::from_raw_parts_mut(buf, len) };
                let pipe = conn.read_pipe(end);
                // Fixed before the loop so SO_RCVTIMEO bounds the whole call, not each wakeup.
                let deadline = self.recv_deadline(fd);
                loop {
                    match pipe.read(out) {
                        io_read::Outcome::Read(n) => return ok(n as i64),
                        io_read::Outcome::Eof => return ok(0),
                        io_read::Outcome::Reset => return err(WSAECONNRESET),
                        io_read::Outcome::WouldBlock => {
                            if nonblocking {
                                return would_block();
                            }
                            if !readiness().wait_until(deadline, || pipe.readable_or_closed()) {
                                let timed_out = deadline.is_some_and(|d| d.passed());
                                return err(if timed_out { WSAETIMEDOUT } else { WSAEWOULDBLOCK });
                            }
                        }
                    }
                }
            }
            Some(Sock::Dgram { .. }) => {
                drop(socks);
                unsafe {
                    self.recvfrom(fd, buf, len, flags, std::ptr::null_mut(), std::ptr::null_mut())
                }
            }
            Some(_) => err(WSAENOTCONN),
            None => None,
        }
    }

    unsafe fn recvfrom(
        &self,
        fd: c_int,
        buf: *mut u8,
        len: usize,
        _flags: c_int,
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
        let accept = |src: SocketAddr| peer.is_none_or(|p| p == src);
        let dg = if let Some(dg) = queue.pop(accept) {
            dg
        } else if nonblocking {
            return would_block();
        } else {
            let deadline = self.recv_deadline(fd);
            if readiness().wait_until(deadline, || queue.has(accept)) {
                match queue.pop(accept) {
                    Some(dg) => dg,
                    None => return err(WSAEWOULDBLOCK),
                }
            } else if deadline.is_some_and(|d| d.passed()) {
                return err(WSAETIMEDOUT);
            } else {
                return err(WSAEWOULDBLOCK);
            }
        };
        let n = len.min(dg.data.len());
        unsafe { std::ptr::copy_nonoverlapping(dg.data.as_ptr(), buf, n) };
        if !addr.is_null() && !addr_len.is_null() {
            unsafe { write_addr(dg.src, addr, addr_len) };
        }
        ok(n as i64)
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
        // A later socket reusing this handle must not inherit its receive timeout.
        self.rcvtimeo.lock().unwrap().remove(&fd);
        let sock = self.socks.lock().unwrap().remove(&fd)?;
        match sock {
            Sock::Stream { conn, end, .. } => {
                // Only a true dup (same conn AND same end) keeps the half open; the peer socket
                // shares the conn but is the other end, so closing here must still shut our side.
                let shared = self.socks.lock().unwrap().values().any(
                    |o| matches!(o, Sock::Stream { conn: c, end: e, .. } if Arc::ptr_eq(c, &conn) && *e == end),
                );
                if !shared {
                    conn.close(end);
                }
            }
            Sock::Listener { addr, .. } => {
                self.regs.lock().unwrap().listeners.remove(&addr);
            }
            Sock::Dgram { local, queue, .. } => {
                let mut regs = self.regs.lock().unwrap();
                if let Some(local) = local {
                    regs.udp.remove(&local);
                }
                for members in regs.groups.values_mut() {
                    members.retain(|(_, q)| !Arc::ptr_eq(q, &queue));
                }
                regs.groups.retain(|_, m| !m.is_empty());
            }
            Sock::Fresh { .. } => {}
        }
        readiness().bump();
        ok(0)
    }

    unsafe fn getsockname(
        &self,
        fd: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        let local = match socks.get(&fd)? {
            Sock::Stream { conn, end, .. } => conn.local(*end),
            Sock::Listener { addr, .. } => *addr,
            Sock::Dgram { local, domain, .. } => {
                local.unwrap_or_else(|| SocketAddr::new(unspecified_like(loopback_for(*domain)), 0))
            }
            Sock::Fresh { local, .. } => {
                local.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
            }
        };
        drop(socks);
        unsafe { write_addr(local, addr, addr_len) };
        ok(0)
    }

    unsafe fn getpeername(
        &self,
        fd: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        let peer = match socks.get(&fd)? {
            Sock::Stream { conn, end, .. } => conn.peer(*end),
            Sock::Dgram { peer: Some(p), .. } => *p,
            _ => return err(WSAENOTCONN),
        };
        drop(socks);
        unsafe { write_addr(peer, addr, addr_len) };
        ok(0)
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
        if level == SOL_SOCKET && name == SO_RCVTIMEO {
            let millis = unsafe { read_int(val, len) } as u32;
            let mut timeouts = self.rcvtimeo.lock().unwrap();
            if millis == 0 {
                timeouts.remove(&fd);
            } else {
                timeouts.insert(fd, std::time::Duration::from_millis(millis.into()));
            }
            return ok(0);
        }
        if level == SOL_SOCKET && name == SO_BROADCAST {
            let on = unsafe { read_int(val, len) } != 0;
            if let Some(Sock::Dgram { broadcast, .. }) = self.socks.lock().unwrap().get_mut(&fd) {
                *broadcast = on;
            }
            return ok(0);
        }
        if let Some(group) = unsafe { parse_add_membership(level, name, val, len) } {
            self.join_group(fd, group);
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
        let value: i32 = if level == SOL_SOCKET && name == SO_RCVTIMEO {
            self.rcvtimeo
                .lock()
                .unwrap()
                .get(&fd)
                .map_or(0, |d| d.as_millis().min(u32::MAX as u128) as u32 as i32)
        } else if level == SOL_SOCKET && name == SO_TYPE {
            match self.socks.lock().unwrap().get(&fd) {
                Some(Sock::Dgram { .. }) => SOCK_DGRAM,
                _ => SOCK_STREAM,
            }
        } else if level == SOL_SOCKET && name == SO_BROADCAST {
            matches!(
                self.socks.lock().unwrap().get(&fd),
                Some(Sock::Dgram { broadcast: true, .. })
            ) as i32
        } else {
            0
        };
        unsafe { write_opt(value, val, len) };
        ok(0)
    }

    unsafe fn ioctl(&self, fd: c_int, request: u64, arg: i64) -> Option<NetResult> {
        // ioctlsocket's command is a C `long`, and FIONBIO's high bit is set, so it arrives sign-
        // extended: compare the 32 bits Winsock defines.
        if request as u32 == FIONBIO as u32 {
            let on = unsafe { (arg as *const u32).read_unaligned() } != 0;
            match self.socks.lock().unwrap().get_mut(&fd) {
                Some(Sock::Fresh { nonblocking, .. })
                | Some(Sock::Stream { nonblocking, .. })
                | Some(Sock::Listener { nonblocking, .. })
                | Some(Sock::Dgram { nonblocking, .. }) => {
                    *nonblocking = on;
                    return ok(0);
                }
                None => return None,
            }
        }
        if Net::owns(self, fd) { ok(0) } else { None }
    }

    unsafe fn dup(&self, fd: c_int) -> Option<NetResult> {
        let mut socks = self.socks.lock().unwrap();
        let clone = match socks.get(&fd)? {
            Sock::Fresh { nonblocking, local } => Sock::Fresh {
                nonblocking: *nonblocking,
                local: *local,
            },
            Sock::Stream {
                conn,
                end,
                nonblocking,
            } => Sock::Stream {
                conn: conn.clone(),
                end: *end,
                nonblocking: *nonblocking,
            },
            Sock::Listener {
                state,
                addr,
                nonblocking,
            } => Sock::Listener {
                state: state.clone(),
                addr: *addr,
                nonblocking: *nonblocking,
            },
            Sock::Dgram {
                queue,
                domain,
                local,
                peer,
                nonblocking,
                broadcast,
            } => Sock::Dgram {
                queue: queue.clone(),
                domain: *domain,
                local: *local,
                peer: *peer,
                nonblocking: *nonblocking,
                broadcast: *broadcast,
            },
        };
        let new_fd = self.mint();
        socks.insert(new_fd, clone);
        ok(new_fd as i64)
    }

    unsafe fn poll(&self, fds: *mut u8, nfds: u64, timeout: c_int) -> Option<NetResult> {
        // WSAPoll over our own sockets. Decline (so the OS sees it) unless every fd is ours.
        let pfds = unsafe { std::slice::from_raw_parts_mut(fds.cast::<WsaPollfd>(), nfds as usize) };
        {
            let socks = self.socks.lock().unwrap();
            if !pfds.iter().all(|p| socks.contains_key(&(p.fd as c_int))) {
                return None;
            }
        }
        let deadline =
            (timeout >= 0).then(|| Deadline::after(std::time::Duration::from_millis(timeout as u64)));
        let collect = |pfds: &mut [WsaPollfd]| -> i64 {
            let mut n = 0;
            for p in pfds.iter_mut() {
                p.revents = self.poll_revents(p.fd as c_int, p.events);
                if p.revents != 0 {
                    n += 1;
                }
            }
            n
        };
        // A return that never blocked — sockets already ready, or a zero timeout — is a busy-poll
        // step when repeated, so it is charged the call latency.
        let mut waited = false;
        loop {
            let n = collect(pfds);
            if n > 0 {
                if !waited {
                    snare_interpose::charge_latency();
                }
                return ok(n);
            }
            if timeout == 0 {
                snare_interpose::charge_latency();
                return ok(0);
            }
            let woke = readiness().wait_until(deadline, || {
                pfds.iter().any(|p| self.poll_revents(p.fd as c_int, p.events) != 0)
            });
            if !woke {
                return ok(collect(pfds));
            }
            waited = true;
        }
    }

    // npcap raw-L2 (wpcap.dll), matching ethercrab's Windows transport: open a device, send whole
    // frames (via the send-queue path), and read them back on every other handle on the device.
    unsafe fn pcap_open(&self, device: *const c_char) -> Option<NetResult> {
        let dev = if device.is_null() {
            Vec::new()
        } else {
            unsafe { std::ffi::CStr::from_ptr(device) }.to_bytes().to_vec()
        };
        let handle = self.next_pcap.fetch_add(1, Ordering::Relaxed);
        self.pcaps.lock().unwrap().insert(
            handle,
            PcapHandle {
                device: dev,
                rx: VecDeque::new(),
                last_frame: Vec::new(),
                last_hdr: vec![0u8; 16],
            },
        );
        ok(handle as i64)
    }

    fn pcap_configure(&self, handle: u64) -> Option<NetResult> {
        if self.pcaps.lock().unwrap().contains_key(&handle) {
            ok(0)
        } else {
            None
        }
    }

    unsafe fn pcap_send(&self, handle: u64, buf: *const u8, len: usize) -> Option<NetResult> {
        let frame = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
        let mut pcaps = self.pcaps.lock().unwrap();
        let dev = pcaps.get(&handle).map(|h| h.device.clone())?;
        // The shared L2 medium. npcap loops a sent frame back to the sending capture too (ethercrab
        // relies on seeing its own frames), so deliver to every handle on the device, incl. this one.
        for h in pcaps.values_mut() {
            if h.device == dev {
                h.rx.push_back(frame.clone());
            }
        }
        drop(pcaps);
        readiness().bump();
        ok(len as i64)
    }

    unsafe fn pcap_next(
        &self,
        handle: u64,
        header: *mut *mut u8,
        data: *mut *const u8,
    ) -> Option<NetResult> {
        let mut pcaps = self.pcaps.lock().unwrap();
        let h = pcaps.get_mut(&handle)?;
        let Some(frame) = h.rx.pop_front() else {
            // Non-blocking (ethercrab sets non-block): no packet now reads as a timeout (0).
            return ok(0);
        };
        // pcap_pkthdr: ts(8, left zero) then caplen@8 and len@12, both the frame length.
        let fl = frame.len() as u32;
        h.last_hdr = vec![0u8; 16];
        h.last_hdr[8..12].copy_from_slice(&fl.to_ne_bytes());
        h.last_hdr[12..16].copy_from_slice(&fl.to_ne_bytes());
        h.last_frame = frame;
        unsafe {
            *header = h.last_hdr.as_mut_ptr();
            *data = h.last_frame.as_ptr();
        }
        ok(1)
    }

    fn pcap_close(&self, handle: u64) -> Option<NetResult> {
        if self.pcaps.lock().unwrap().remove(&handle).is_some() {
            ok(0)
        } else {
            None
        }
    }
}

unsafe fn read_int(val: *const u8, len: u32) -> c_int {
    if val.is_null() || (len as usize) < size_of::<c_int>() {
        return 0;
    }
    unsafe { val.cast::<c_int>().read_unaligned() }
}

/// Parses an `IP_ADD_MEMBERSHIP`/`IPV6_ADD_MEMBERSHIP` option into its group address.
unsafe fn parse_add_membership(level: c_int, name: c_int, val: *const u8, len: u32) -> Option<IpAddr> {
    if val.is_null() {
        return None;
    }
    if level == IPPROTO_IP && name == IP_ADD_MEMBERSHIP && (len as usize) >= 4 {
        let mut o = [0u8; 4];
        unsafe { std::ptr::copy_nonoverlapping(val, o.as_mut_ptr(), 4) };
        return Some(IpAddr::V4(Ipv4Addr::from(o)));
    }
    if level == IPPROTO_IPV6 && name == IPV6_ADD_MEMBERSHIP && (len as usize) >= 16 {
        let mut o = [0u8; 16];
        unsafe { std::ptr::copy_nonoverlapping(val, o.as_mut_ptr(), 16) };
        return Some(IpAddr::V6(Ipv6Addr::from(o)));
    }
    None
}

/// Reads a `SOCKADDR_IN`/`SOCKADDR_IN6` from `ptr`. The sockaddr layout is the BSD-sockets ABI
/// shared across platforms; only the IPv6 family tag differs (23 on Windows). Port and address are
/// network byte order.
unsafe fn parse_addr(ptr: *const u8, len: u32) -> Option<SocketAddr> {
    if ptr.is_null() || (len as usize) < 4 {
        return None;
    }
    let family = unsafe { ptr.cast::<u16>().read_unaligned() } as c_int;
    match family {
        AF_INET => {
            if (len as usize) < 8 {
                return None;
            }
            let port = u16::from_be(unsafe { ptr.add(2).cast::<u16>().read_unaligned() });
            let mut o = [0u8; 4];
            unsafe { std::ptr::copy_nonoverlapping(ptr.add(4), o.as_mut_ptr(), 4) };
            Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(o), port)))
        }
        AF_INET6 => {
            if (len as usize) < 28 {
                return None;
            }
            let port = u16::from_be(unsafe { ptr.add(2).cast::<u16>().read_unaligned() });
            let mut o = [0u8; 16];
            unsafe { std::ptr::copy_nonoverlapping(ptr.add(8), o.as_mut_ptr(), 16) };
            Some(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(o), port, 0, 0)))
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
            let mut buf = [0u8; 16];
            buf[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
            buf[2..4].copy_from_slice(&v4.port().to_be_bytes());
            buf[4..8].copy_from_slice(&v4.ip().octets());
            let n = cap.min(16);
            unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), out, n) };
            unsafe { *out_len = 16 };
        }
        SocketAddr::V6(v6) => {
            let mut buf = [0u8; 28];
            buf[0..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
            buf[2..4].copy_from_slice(&v6.port().to_be_bytes());
            buf[8..24].copy_from_slice(&v6.ip().octets());
            let n = cap.min(28);
            unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), out, n) };
            unsafe { *out_len = 28 };
        }
    }
}

unsafe fn write_opt(value: i32, val: *mut u8, len: *mut u32) {
    if val.is_null() || len.is_null() {
        return;
    }
    let cap = unsafe { *len } as usize;
    let n = size_of::<i32>().min(cap);
    unsafe {
        std::ptr::copy_nonoverlapping(value.to_ne_bytes().as_ptr(), val, n);
        *len = size_of::<i32>() as u32;
    }
}

/// The per-sim address registry: where datagrams and connects to an address go. Testers reach the
/// one of the `Sim` they were built in through the thread-local scope below.
pub(crate) type Registries = Mutex<Registry>;

thread_local! {
    static CURRENT: std::cell::RefCell<Option<Arc<Registries>>> = const { std::cell::RefCell::new(None) };
}

/// Installs `regs` as the calling thread's current registries until the guard drops. `Sim::run`
/// wraps the test body in this so testers built there reach this sim's registries.
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

/// The registries of the `Sim` the calling thread runs in, for a tester to keep once it leaves
/// that thread.
pub(crate) fn registries_here() -> Arc<Registries> {
    CURRENT
        .with(|c| c.borrow().clone())
        .expect("snare tester functions must be called inside Sim::run")
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


/// Registers (and returns) the peer listener for `addr`, replacing any earlier one.
pub(crate) fn listen_at(addr: SocketAddr) -> Arc<Listener> {
    let listener = Arc::new(Listener::default());
    let regs = registries_here();
    snare_interpose::real(|| {
        regs.lock()
            .unwrap()
            .listeners
            .insert(addr, listener.clone())
    });
    listener
}

/// Runs `f` on the link-policy table of `regs`.
pub(crate) fn with_policies<R>(regs: &Registries, f: impl FnOnce(&Policies) -> R) -> R {
    f(&regs.lock().unwrap().policies)
}

/// Withdraws `listener`, so later connects to its address are refused (WSAECONNREFUSED).
pub(crate) fn unlisten(regs: &Registries, listener: &Arc<Listener>) {
    snare_interpose::real(|| {
        regs.lock()
            .unwrap()
            .listeners
            .retain(|_, l| !Arc::ptr_eq(l, listener))
    });
}

impl ListenerState {
    /// Takes the next connection, or `None` if none is waiting.
    pub(crate) fn try_accept(&self) -> Option<Arc<Conn>> {
        snare_interpose::real(|| self.pending.lock().unwrap().pop_front())
    }

    /// Whether a connection is waiting to be accepted.
    pub(crate) fn has_pending(&self) -> bool {
        snare_interpose::real(|| !self.pending.lock().unwrap().is_empty())
    }
}

/// The peer (accepting) side of a connection, driven by a tester. Runs under passthrough like the
/// rest of `WinNet`: waits on its locks are the sim's business, not the code under test's.
impl Conn {
    pub(crate) fn write_from_peer(&self, bytes: &[u8]) -> usize {
        snare_interpose::real(|| self.write(End::B, bytes))
    }

    pub(crate) fn read_from_peer(&self, out: &mut [u8]) -> std::io::Result<usize> {
        snare_interpose::real(|| match self.read_pipe(End::B).read(out) {
            io_read::Outcome::Read(n) => Ok(n),
            io_read::Outcome::Eof => Ok(0),
            io_read::Outcome::Reset => Err(std::io::ErrorKind::ConnectionReset.into()),
            io_read::Outcome::WouldBlock => Err(std::io::ErrorKind::WouldBlock.into()),
        })
    }

    pub(crate) fn close_peer(&self) {
        snare_interpose::real(|| self.close(End::B));
    }

    /// Aborts the connection with a reset: the code under test's next read or write fails with
    /// WSAECONNRESET.
    pub(crate) fn reset_peer(&self) {
        snare_interpose::real(|| {
            self.a_to_b.reset();
            self.b_to_a.reset();
        });
    }

    /// Whether the peer has bytes to read or has seen the code under test close its end.
    pub(crate) fn peer_readable(&self) -> bool {
        snare_interpose::real(|| self.read_pipe(End::B).readable_or_closed())
    }
}

/// A datagram endpoint a tester owns at a fixed address; see the fabric's `UdpEndpoint`.
pub(crate) struct UdpEndpoint {
    regs: Arc<Registries>,
    addr: SocketAddr,
    queue: Arc<DgramQueue>,
}

impl UdpEndpoint {
    /// Binds `addr`; panics if a socket or another tester already holds it.
    pub(crate) fn bind(regs: Arc<Registries>, addr: SocketAddr) -> Self {
        let queue = Arc::new(DgramQueue::default());
        snare_interpose::real(|| {
            let mut reg = regs.lock().unwrap();
            assert!(
                !reg.udp.contains_key(&addr),
                "udp tester address {addr} is already bound"
            );
            reg.udp.insert(addr, queue.clone());
        });
        UdpEndpoint { regs, addr, queue }
    }

    pub(crate) fn try_recv(&self) -> Option<(SocketAddr, Vec<u8>)> {
        snare_interpose::real(|| self.queue.pop(|_| true).map(|dg| (dg.src, dg.data)))
    }

    pub(crate) fn has_pending(&self) -> bool {
        snare_interpose::real(|| self.queue.has(|_| true))
    }

    /// Sends one datagram to `dest` from this endpoint's address.
    pub(crate) fn send_to(&self, dest: SocketAddr, data: &[u8]) {
        snare_interpose::real(|| {
            let deliveries = self.regs.lock().unwrap().deliveries(dest, data.len());
            for (q, delays) in deliveries {
                for delay in delays {
                    q.push_after(self.addr, data.to_vec(), delay);
                }
            }
        });
    }
}

impl Drop for UdpEndpoint {
    fn drop(&mut self) {
        snare_interpose::real(|| {
            let mut reg = self.regs.lock().unwrap();
            if reg.udp.get(&self.addr).is_some_and(|q| Arc::ptr_eq(q, &self.queue)) {
                reg.udp.remove(&self.addr);
            }
        });
    }
}
