//! One direction of a TCP byte stream, shared by the unix fabric and `WinNet`: bytes in flight
//! across the link (latency, a link that is down, a stall at either end), the reader's receive
//! window that bounds what a writer may put in flight, and blocking reads and writes that park on
//! the shared readiness signal.
//!
//! Locking: a [`Pipe`]'s `inner` lock is taken before the policy table's stall lock (through
//! `held`) and the reader's `SockRec` state (through `arrive`), never after them; `capacity`,
//! which reads policies and the reader's and writer's `SockRec`, runs before `inner` is taken.
//! Readiness is bumped only after `inner` is released, since readiness waiters re-check pipes
//! under their own locks (see `Readiness::wait_until`).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use crate::netif::LinkState;
use crate::readiness::{Deadline, readiness};
use crate::scope::SimShared;
use crate::sockets::{RxProbe, SockRec};

/// macOS's default `SO_SNDLOWAT` for a stream: `MCLBYTES`, 2048 (see [`Pipe::writable`]).
const MAC_SNDLOWAT: usize = 2048;

#[cfg(target_os = "linux")]
type TransmitHook = dyn Fn(&[u8], Duration, usize) + Send + Sync;

/// What a read of a pipe found.
pub(crate) enum Read {
    /// This many bytes were copied out.
    Data(usize),
    /// Nothing readable yet, and the stream is not over.
    WouldBlock,
    /// End of stream: the writer closed and everything it wrote has been read, or (on Linux)
    /// the reader shut its receive side and the buffer is drained.
    Eof,
    /// The stream was reset; the caller fails the read with `ECONNRESET` (`WSAECONNRESET`).
    Reset,
    /// The reader shut its receive side down and the host reports that at once (macOS, Windows).
    Shut,
}

/// A pipe's state, behind [`Pipe::inner`].
#[derive(Default)]
struct PipeInner {
    /// Bytes that have arrived and wait to be read.
    buf: VecDeque<u8>,
    /// The sizes of the chunks `buf` holds, oldest first; the front one may be partly read.
    chunks: VecDeque<usize>,
    #[cfg(target_os = "linux")]
    rx_memory: VecDeque<(usize, usize)>,
    /// The writer closed (or the stream was reset): no more writes, and the reader sees end of
    /// stream once `buf` and `in_flight` are empty.
    closed: bool,
    #[cfg(unix)]
    write_shut: bool,
    #[cfg(target_os = "macos")]
    writer_aborted: bool,
    /// The reader shut its receive side down (`shutdown(SHUT_RD)` / `SD_RECEIVE`).
    read_shut: bool,
    #[cfg(unix)]
    reader_gone: bool,
    /// Aborted with a TCP reset: reads and writes fail instead of reaching end of stream.
    reset: bool,
    /// Written bytes still crossing the link, each chunk with when it arrives. Arrival times
    /// never decrease along the queue, so chunks land in write order.
    in_flight: VecDeque<Flight>,
    #[cfg(target_os = "linux")]
    transport: Option<crate::tcp_transport::TcpTransport>,
    #[cfg(target_os = "linux")]
    transport_delay: Duration,
    #[cfg(target_os = "linux")]
    tcp_tail: Option<(u64, Vec<u8>)>,
    #[cfg(target_os = "linux")]
    tcp_reports: VecDeque<(u64, crate::tstamp::TcpWrite, Duration)>,
}

struct Flight {
    at: Deadline,
    bytes: Vec<u8>,
    mss: usize,
}

impl PipeInner {
    fn copy_to(&self, out: &mut [u8]) -> usize {
        let (first, second) = self.buf.as_slices();
        let first_len = first.len().min(out.len());
        out[..first_len].copy_from_slice(&first[..first_len]);
        let second_len = second.len().min(out.len() - first_len);
        out[first_len..first_len + second_len].copy_from_slice(&second[..second_len]);
        first_len + second_len
    }

    fn sending_closed(&self) -> bool {
        #[cfg(target_os = "macos")]
        if self.writer_aborted {
            return true;
        }
        self.closed
    }

    /// Bytes the pipe holds against its window: unread plus in flight.
    fn used(&self) -> usize {
        let used = self.buf.len() + self.in_flight.iter().map(|f| f.bytes.len()).sum::<usize>();
        #[cfg(target_os = "linux")]
        let used = used + self.transport.as_ref().map_or(0, |t| t.pending_bytes());
        used
    }

    fn pending(&self) -> bool {
        let pending = !self.in_flight.is_empty();
        #[cfg(target_os = "linux")]
        let pending = pending
            || self
                .transport
                .as_ref()
                .is_some_and(|t| t.pending_bytes() > 0);
        pending
    }
}

/// The addresses a pipe carries bytes between, for the link policies on them.
pub(crate) struct Ends {
    pub(crate) shared: Arc<SimShared>,
    /// The writing end's address.
    pub(crate) from: SocketAddr,
    /// The reading end's address, whose TCP policy sets the receive window.
    pub(crate) to: SocketAddr,
}

/// One direction of a TCP connection (or of a stream socketpair): written at one end, read at
/// the other. A connection is two pipes; each backend owns them and calls in under no lock of
/// its own that a pipe could also take.
#[derive(Default)]
pub(crate) struct Pipe {
    inner: Mutex<PipeInner>,
    /// The code under test's socket that reads this pipe, if one does.
    reader: OnceLock<Arc<SockRec>>,
    /// The code under test's socket that writes it, whose send buffer adds to the window.
    writer: OnceLock<Arc<SockRec>>,
    pending_recv_space: OnceLock<usize>,
    #[cfg(target_os = "linux")]
    pending_recv_locked: OnceLock<bool>,
    #[cfg(target_os = "linux")]
    mtu: OnceLock<u32>,
    #[cfg(target_os = "linux")]
    transmitted: OnceLock<Box<TransmitHook>>,
    /// The link the connection crosses: bytes stall in flight while it is down.
    via: Option<Arc<LinkState>>,
    /// `None` for a socketpair, which has no addresses and no policy.
    ends: Option<Ends>,
    /// How many times the reading end has been woken: a chunk landing, the end of the stream, a
    /// reset, a shut receive side. Linux wakes a socket's wait queue on each (net/core/sock.c
    /// `sock_def_readable` per segment queued, `sock_def_wakeup` on a state change), and every
    /// wake is a new edge for an edge-triggered epoll or `EV_CLEAR` kqueue registration.
    read_wakes: AtomicU64,
    #[cfg(unix)]
    read_order: AtomicU64,
    /// How many times the writing end has been woken: a read freeing room in the window, the
    /// stream closing or resetting (net/core/stream.c `sk_stream_write_space`).
    write_wakes: AtomicU64,
    /// The [`Domain::key`](snare_interpose::Domain::key) of the sim the pipe belongs to, whose
    /// waiters its readiness bumps wake.
    domain: usize,
}

/// How a blocking or nonblocking send on a stream ended.
pub(crate) enum Sent {
    /// This many bytes were written, all of them for a blocking send that was not cut short.
    Bytes(usize),
    /// The stream is closed or reset: nothing more can be written.
    Closed,
    /// Nonblocking, and no room.
    WouldBlock,
    /// `SO_SNDTIMEO` passed with nothing written, which POSIX reports as `EAGAIN`/`EWOULDBLOCK`
    /// (POSIX.1-2024 XSH §2.10.16).
    TimedOut,
    /// Nothing will ever free room: the readiness wait gave up with no deadline passed, which it
    /// does when the sim is quiescent and nothing pending can wake it.
    Stuck,
    /// An error became pending while the send waited, with nothing written.
    Error,
}

impl Pipe {
    fn wake_keys(&self) -> ([crate::readiness::WakeKey; 2], usize) {
        let mut keys = [crate::readiness::WakeKey::Socket(0); 2];
        let mut len = 0;
        for rec in [self.reader.get(), self.writer.get()].into_iter().flatten() {
            keys[len] = rec.wake_key();
            len += 1;
        }
        (keys, len)
    }

    fn bump(&self) {
        let (keys, len) = self.wake_keys();
        if len == 0 {
            readiness().bump_keys(self.domain, &[]);
        } else {
            readiness().bump_keys(self.domain, &keys[..len]);
        }
    }

    /// A pipe crossing `via` (none for loopback and socketpairs) between `ends`, in the sim with
    /// domain key `domain`.
    pub(crate) fn new(via: Option<Arc<LinkState>>, ends: Option<Ends>, domain: usize) -> Arc<Self> {
        Arc::new(Pipe {
            via,
            ends,
            domain,
            ..Pipe::default()
        })
    }

    /// Until when a stall at either end holds this pipe's bytes. Takes the policy table's stall
    /// lock.
    fn held(&self) -> Option<Deadline> {
        let ends = self.ends.as_ref()?;
        #[cfg(target_os = "macos")]
        {
            ends.shared
                .policies
                .held_until_on(ends.from, ends.to, ends.shared.clock.as_deref())
        }
        #[cfg(not(target_os = "macos"))]
        {
            ends.shared.policies.held_until(ends.from, ends.to)
        }
    }

    /// Moves every in-flight chunk whose arrival has passed into the readable buffer, in order,
    /// while the link it crosses is up and no stall holds it.
    fn land(&self, inner: &mut PipeInner) {
        if self.via.as_ref().is_some_and(|link| !link.releases()) {
            return;
        }
        #[cfg(not(target_os = "macos"))]
        if self.held().is_some() {
            return;
        }
        #[cfg(target_os = "macos")]
        while inner.in_flight.front().is_some_and(|flight| {
            let at = self.effective_shutdown_arrival(flight.at);
            match &self.ends {
                Some(ends) => at.passed_on(ends.shared.clock.as_deref()),
                None => at.passed(),
            }
        }) {
            let flight = inner.in_flight.pop_front().expect("chunk");
            self.arrive(inner, &flight.bytes, flight.mss);
        }
        #[cfg(not(target_os = "macos"))]
        while inner.in_flight.front().is_some_and(|f| f.at.passed()) {
            let flight = inner.in_flight.pop_front().expect("chunk");
            self.arrive(inner, &flight.bytes, flight.mss);
        }
        #[cfg(target_os = "linux")]
        self.transmit(inner);
    }

    /// Makes `bytes` readable as one chunk and counts it as delivered to the reader's socket.
    /// Called with `inner` held.
    fn arrive(&self, inner: &mut PipeInner, bytes: &[u8], _mss: usize) {
        if bytes.is_empty() || (cfg!(target_os = "macos") && inner.read_shut) {
            return;
        }
        inner.buf.extend(bytes);
        inner.chunks.push_back(bytes.len());
        #[cfg(unix)]
        self.read_order
            .store(crate::fabric::readiness_sequence(), Ordering::Relaxed);
        self.read_wakes.fetch_add(1, Ordering::Relaxed);
        if let Some(rec) = self.reader.get() {
            rec.count_delivered(bytes.len());
        }
        #[cfg(target_os = "linux")]
        if let Some(ends) = self.ends.as_ref() {
            let (head, charge, memory) = if let Some(rec) = self.reader.get() {
                let mut state = rec.state();
                let head = state.buf.error_charge(0, false);
                let charge = state.buf.take_tcp(bytes.len());
                (head, charge, state.buf.rx.rmem_alloc)
            } else {
                let head = ends.shared.sys.limits().skb_small_truesize;
                let charge = head + bytes.len();
                let memory = inner
                    .rx_memory
                    .iter()
                    .map(|(_, charge)| charge)
                    .sum::<usize>()
                    + charge;
                (head, charge, memory)
            };
            inner.rx_memory.push_back((bytes.len(), charge));
            if let Some(transport) = inner.transport.as_mut() {
                transport.arrive(bytes.len(), _mss, memory, head);
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn transmit(&self, inner: &mut PipeInner) {
        while let Some(segment) = inner.transport.as_mut().and_then(|t| t.next()) {
            if let Some(rec) = self.writer.get()
                && crate::tstamp::tcp_requested(rec)
            {
                let ends = self.ends.as_ref().unwrap();
                while inner
                    .tcp_reports
                    .front()
                    .is_some_and(|(end, _, _)| *end <= segment.end)
                {
                    let (_, request, rtt) = inner.tcp_reports.pop_front().unwrap();
                    crate::tstamp::tcp_transmitted(
                        rec,
                        request,
                        ends.shared.tstamp_now(),
                        segment.bytes.len(),
                        rtt,
                        || crate::tstamp::looped_frame(ends.from, ends.to, true, &segment.bytes),
                    );
                }
                inner.tcp_tail = Some((segment.end, segment.bytes.clone()));
            }
            let delay = inner.transport_delay;
            let held = self.held();
            let link_up = self.via.as_ref().is_none_or(|link| link.releases());
            if delay.is_zero() && inner.in_flight.is_empty() && held.is_none() && link_up {
                if let Some(hook) = self.transmitted.get() {
                    hook(&segment.bytes, Duration::ZERO, segment.mss);
                }
                self.arrive(inner, &segment.bytes, segment.mss);
            } else {
                let mut at = Deadline::after(delay);
                for later in [inner.in_flight.back().map(|f| f.at), held]
                    .into_iter()
                    .flatten()
                {
                    if later.instant() > at.instant() {
                        at = later;
                    }
                }
                at.wake_waiters_then();
                if let Some(hook) = self.transmitted.get() {
                    hook(&segment.bytes, at.remaining(), segment.mss);
                }
                inner.in_flight.push_back(Flight {
                    at,
                    bytes: segment.bytes,
                    mss: segment.mss,
                });
            }
        }
    }

    /// The most bytes in flight plus unread this pipe holds: the receive side's room plus the
    /// writer's send buffer. The receive side is the reader's receive buffer when the code under
    /// test reads ([`SockBuf::tcp_recv_space`](crate::limits::SockBuf::tcp_recv_space)), capped by
    /// a [`TcpPolicy::recv_window`](crate::TcpPolicy::recv_window) at its address; the send side
    /// is the writer's send buffer when the code under test writes
    /// ([`SockBuf::tcp_send_space`](crate::limits::SockBuf::tcp_send_space)), else 0. `None` when
    /// neither a reading socket nor a window bounds it (a tester reading with no window), and
    /// always for a socketpair. Must be called without `inner` held.
    fn capacity(&self) -> Option<usize> {
        let ends = self.ends.as_ref()?;
        let window = ends.shared.policies.recv_window(ends.to);
        let room = self
            .reader
            .get()
            .map(|rec| rec.state().buf.tcp_recv_space())
            .or_else(|| self.pending_recv_space.get().copied());
        let window = match (window, room) {
            (Some(w), Some(r)) => w.min(r),
            (w, r) => w.or(r)?,
        };
        let send = self
            .writer
            .get()
            .map_or(0, |rec| rec.state().buf.tcp_send_space());
        Some(window.saturating_add(send))
    }

    /// How much of a `len`-byte write a pipe holding `used` of `cap` takes, as the host's send
    /// path does once the buffer is short of room for all of it. A tester's writes are segments
    /// from another host and take what fits; for the code under test's own sends (`own`):
    ///
    /// - Linux copies what fits (net/ipv4/tcp.c `tcp_sendmsg_locked` waits in
    ///   `sk_stream_wait_memory` only once nothing more can be queued, so a send returns a
    ///   partial count).
    /// - macOS takes nothing until the free room reaches the low-water mark, 2048 bytes
    ///   (`SO_SNDLOWAT`) capped at the buffer, then fills it (xnu bsd/kern/uipc_socket.c
    ///   `sosend`: `space < resid && space < sb_lowat` waits or fails with `EWOULDBLOCK`; see
    ///   [`writable`](Self::writable) for the 2048).
    /// - Windows takes the whole send while anything is free, which can carry it past the
    ///   capacity: measured on Windows 11 over loopback, a 100000-byte nonblocking send to a
    ///   connection with 16 KiB buffers is accepted whole (tests/tcp_buffers_os_truth.rs).
    fn takes(cap: usize, used: usize, len: usize, own: bool) -> usize {
        let free = cap.saturating_sub(used);
        if free >= len {
            len
        } else if !own {
            free
        } else if cfg!(windows) {
            if free > 0 { len } else { 0 }
        } else if cfg!(target_os = "macos") {
            if free >= MAC_SNDLOWAT.min(cap) {
                free
            } else {
                0
            }
        } else {
            free
        }
    }

    /// Whether the code under test writes this pipe.
    pub(crate) fn has_writer(&self) -> bool {
        self.writer.get().is_some()
    }

    /// Whether the code under test reads this pipe.
    pub(crate) fn has_reader(&self) -> bool {
        self.reader.get().is_some()
    }

    /// Writes as much of `bytes` as the window has room for, readable `delay` from now (link
    /// latency) or once a stall ends. A write never overtakes an earlier one still in flight:
    /// TCP delivers in order. `sent` sees what was written and how long until it arrives before
    /// the reader can. `None` once the stream is closed. A write with no delay, nothing in
    /// flight, the link up and no stall lands at once; otherwise its arrival is registered with
    /// `wake_waiters_then` so a virtual clock can jump to it.
    pub(crate) fn write_after(
        &self,
        bytes: &[u8],
        delay: Duration,
        sent: impl FnOnce(&[u8], Duration, Option<Deadline>),
    ) -> Option<usize> {
        let cap = self.capacity();
        let held = self.held();
        let mut inner = self.inner.lock().unwrap();
        if inner.sending_closed() {
            return None;
        }
        let own = self.has_writer();
        let n = cap.map_or(bytes.len(), |cap| {
            Self::takes(cap, inner.used(), bytes.len(), own)
        });
        if n == 0 {
            return Some(0);
        }
        let bytes = &bytes[..n];
        #[cfg(target_os = "linux")]
        if let Some(ends) = self.ends.as_ref()
            && (self
                .reader
                .get()
                .is_some_and(|reader| reader.state().buf.rcv_locked)
                || self.pending_recv_locked.get().copied().unwrap_or(false)
                || self
                    .writer
                    .get()
                    .is_some_and(|rec| crate::tstamp::tcp_requested(rec)))
        {
            if inner.transport.is_none() {
                let buffer = self
                    .reader
                    .get()
                    .map(|rec| rec.state().buf.rcvbuf.max(0) as usize)
                    .or_else(|| self.pending_recv_space.get().copied())
                    .unwrap_or_else(|| ends.shared.sys.limits().tcp_rmem_default);
                inner.transport = Some(crate::tcp_transport::TcpTransport::new(
                    buffer,
                    self.mtu.get().copied().unwrap_or(65536),
                    ends.to.is_ipv6(),
                    ends.shared.sys.limits().tcp_gso_max_size,
                ));
            }
            inner.transport_delay = delay;
            if delay.is_zero()
                && inner.in_flight.is_empty()
                && held.is_none()
                && self.via.as_ref().is_none_or(|link| link.releases())
                && let Some(mss) = inner.transport.as_mut().unwrap().direct(bytes.len())
            {
                self.arrive(&mut inner, bytes, mss);
                if let Some(hook) = self.transmitted.get() {
                    hook(bytes, Duration::ZERO, mss);
                }
                if let Some(rec) = self.writer.get()
                    && crate::tstamp::tcp_requested(rec)
                {
                    let end = inner.transport.as_ref().unwrap().transmitted;
                    inner.tcp_tail = Some((end, bytes.to_vec()));
                }
                drop(inner);
                self.bump();
                return Some(n);
            }
            inner.transport.as_mut().unwrap().push(bytes);
            self.transmit(&mut inner);
            drop(inner);
            self.bump();
            return Some(n);
        }
        let link_up = self.via.as_ref().is_none_or(|link| link.releases());
        let at = if delay.is_zero() && inner.in_flight.is_empty() && link_up && held.is_none() {
            self.arrive(&mut inner, bytes, 0);
            Deadline::after(Duration::ZERO)
        } else {
            let mut arrives = Deadline::after(delay);
            #[cfg(target_os = "macos")]
            let holds = [inner.in_flight.back().map(|f| f.at), None];
            #[cfg(not(target_os = "macos"))]
            let holds = [inner.in_flight.back().map(|f| f.at), held];
            for later in holds.into_iter().flatten() {
                if later.instant() > arrives.instant() {
                    arrives = later;
                }
            }
            arrives.wake_waiters_then();
            inner.in_flight.push_back(Flight {
                at: arrives,
                bytes: bytes.to_vec(),
                mss: 0,
            });
            arrives
        };
        #[cfg(target_os = "macos")]
        let arrival = match &self.ends {
            Some(ends) => self
                .effective_shutdown_arrival(at)
                .remaining_on(ends.shared.clock.as_deref()),
            None => at.remaining(),
        };
        #[cfg(not(target_os = "macos"))]
        let arrival = at.remaining();
        sent(bytes, arrival, inner.read_shut.then_some(at));
        drop(inner);
        self.bump();
        Some(n)
    }

    /// Copies out up to `out.len()` readable bytes, landing what has arrived first. Never blocks.
    /// Consumes `chunks` alongside `buf` so the front chunk's size stays the unread rest of it.
    /// On a pipe with a receive window, a read that frees room bumps readiness so a blocked
    /// writer re-checks.
    pub(crate) fn read(&self, out: &mut [u8]) -> Read {
        let mut copied = 0;
        loop {
            match self.read_chunk(&mut out[copied..]) {
                Read::Data(n) => copied += n,
                other if copied == 0 => return other,
                _ => return Read::Data(copied),
            }
            if copied == out.len() || !cfg!(target_os = "linux") || self.ends.is_none() {
                return Read::Data(copied);
            }
        }
    }

    fn read_chunk(&self, out: &mut [u8]) -> Read {
        let mut inner = self.inner.lock().unwrap();
        #[cfg(windows)]
        if inner.reset {
            return Read::Reset;
        }
        // After SHUT_RD macOS reads end of stream at once: XNU bsd/kern/uipc_socket.c
        // `soshutdownlock_final` calls `sorflush`, which discards the buffer and sets `SB_DROP`
        // against later appends. Linux still delivers what is queued or arrives:
        // net/ipv4/tcp.c `tcp_shutdown` ignores `RCV_SHUTDOWN`. Windows fails the read with
        // WSAESHUTDOWN (Microsoft Learn "recv"). The sim's side is pinned by
        // tests/tcp_server.rs shutdown_read_sends_no_eof.
        if inner.read_shut && !cfg!(target_os = "linux") {
            return Read::Shut;
        }
        self.land(&mut inner);
        if inner.buf.is_empty() {
            if inner.reset && !inner.pending() {
                return Read::Reset;
            }
            let fin = inner.closed && !inner.pending() && self.held().is_none();
            return if fin || inner.read_shut {
                Read::Eof
            } else {
                Read::WouldBlock
            };
        }
        let n = inner.copy_to(out);
        drop(inner.buf.drain(..n));
        let mut left = n;
        while left > 0 {
            let front = inner.chunks.front_mut().expect("chunk");
            if *front <= left {
                left -= *front;
                inner.chunks.pop_front();
            } else {
                *front -= left;
                left = 0;
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(rec) = self.reader.get() {
            let mut left = n;
            let mut returned = 0;
            while left > 0 {
                let Some((unread, charge)) = inner.rx_memory.front_mut() else {
                    break;
                };
                if *unread <= left {
                    left -= *unread;
                    returned += *charge;
                    inner.rx_memory.pop_front();
                } else {
                    *unread -= left;
                    left = 0;
                }
            }
            let memory = {
                let mut state = rec.state();
                state.buf.consume_tcp(returned);
                state.buf.rx.rmem_alloc
            };
            if let Some(transport) = inner.transport.as_mut() {
                transport.advertise(memory);
            }
            self.transmit(&mut inner);
        }
        drop(inner);
        if n > 0 {
            self.write_wakes.fetch_add(1, Ordering::Relaxed);
        }
        if n > 0 && self.capacity().is_some() {
            self.bump();
        }
        Read::Data(n)
    }

    /// Copies out up to `out.len()` readable bytes as [`read`](Pipe::read) does, leaving them
    /// queued: what a receive with `MSG_PEEK` returns ("The data is copied into the buffer, but
    /// is not removed from the input queue",
    /// [Microsoft Learn: recv](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv)).
    /// Frees no room, so no writer is woken.
    #[cfg_attr(unix, allow(dead_code))]
    pub(crate) fn peek(&self, out: &mut [u8]) -> Read {
        let mut inner = self.inner.lock().unwrap();
        #[cfg(windows)]
        if inner.reset {
            return Read::Reset;
        }
        if inner.read_shut && !cfg!(target_os = "linux") {
            return Read::Shut;
        }
        self.land(&mut inner);
        if inner.buf.is_empty() {
            if inner.reset && !inner.pending() {
                return Read::Reset;
            }
            let fin = inner.closed && !inner.pending() && self.held().is_none();
            return if fin || inner.read_shut {
                Read::Eof
            } else {
                Read::WouldBlock
            };
        }
        let n = inner.copy_to(out);
        Read::Data(n)
    }

    /// The reader shut its receive side down; see [`read`](Pipe::read) for what later reads
    /// return on each host. The writer is not told: no end of stream reaches it.
    pub(crate) fn shut_read(&self) {
        let mut inner = self.inner.lock().unwrap();
        #[cfg(target_os = "macos")]
        {
            self.land(&mut inner);
            inner.buf.clear();
            inner.chunks.clear();
        }
        inner.read_shut = true;
        drop(inner);
        #[cfg(unix)]
        self.read_order
            .store(crate::fabric::readiness_sequence(), Ordering::Relaxed);
        self.read_wakes.fetch_add(1, Ordering::Relaxed);
        self.bump();
    }

    /// Ends the stream. `closed` sees how long until what is still in flight has arrived, before
    /// the reader can see the end.
    pub(crate) fn close(&self, closed: impl FnOnce(Duration)) {
        let mut inner = self.inner.lock().unwrap();
        inner.closed = true;
        #[cfg(unix)]
        {
            inner.write_shut = true;
        }
        closed(
            inner
                .in_flight
                .back()
                .map_or(Duration::ZERO, |f| f.at.remaining()),
        );
        drop(inner);
        self.wake_both();
        self.bump();
    }

    /// Aborts the stream as a TCP RST does; bytes sent before it remain readable on unix.
    pub(crate) fn reset(&self) {
        self.reset_state();
        self.bump();
    }

    fn reset_state(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.reset = true;
        inner.closed = true;
        self.land(&mut inner);
        #[cfg(windows)]
        {
            if let Some(rec) = self.reader.get() {
                rec.state().tcp_established = false;
            }
            inner.buf.clear();
            inner.chunks.clear();
            inner.in_flight.clear();
        }
        drop(inner);
        self.wake_both();
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn reset_quiet_at(&self, cutoff: Deadline) {
        let mut inner = self.inner.lock().unwrap();
        while inner.in_flight.front().is_some_and(|flight| {
            let at = self.effective_shutdown_arrival(flight.at);
            at.instant() <= cutoff.instant()
                && match &self.ends {
                    Some(ends) => at.passed_on(ends.shared.clock.as_deref()),
                    None => at.passed(),
                }
        }) {
            let flight = inner.in_flight.pop_front().expect("chunk");
            self.arrive(&mut inner, &flight.bytes, flight.mss);
        }
        inner.in_flight.clear();
        inner.closed = true;
        inner.reset = true;
        drop(inner);
        self.wake_both();
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn shutdown_arrival(&self) -> Option<Deadline> {
        self.inner
            .lock()
            .unwrap()
            .in_flight
            .front()
            .map(|flight| flight.at)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn can_arrive(&self) -> bool {
        self.via.as_ref().is_none_or(|link| link.releases())
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn effective_shutdown_arrival(&self, mut at: Deadline) -> Deadline {
        loop {
            let before = at;
            if let Some(link) = &self.via {
                at = link.effective_arrival(at);
            }
            if let Some(ends) = &self.ends {
                at = ends
                    .shared
                    .policies
                    .effective_arrival(ends.from, ends.to, at);
            }
            if at.instant() == before.instant() {
                return at;
            }
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn abort_writer(&self) {
        {
            let mut inner = self.inner.lock().unwrap();
            inner.writer_aborted = true;
            inner.write_shut = true;
        }
        if let Some(rec) = self.writer.get() {
            rec.state().tcp_established = false;
        }
        self.wake_both();
    }

    /// Counts a wake of both ends, for a change of state either can see.
    fn wake_both(&self) {
        #[cfg(unix)]
        self.read_order
            .store(crate::fabric::readiness_sequence(), Ordering::Relaxed);
        self.read_wakes.fetch_add(1, Ordering::Relaxed);
        self.write_wakes.fetch_add(1, Ordering::Relaxed);
    }

    /// How many times the reading end has been woken; see `read_wakes`. Call after a readiness
    /// check, which lands what has arrived.
    #[cfg_attr(windows, allow(dead_code))]
    #[cfg(unix)]
    pub(crate) fn read_order(&self) -> u64 {
        self.read_order.load(Ordering::Relaxed)
    }

    #[cfg(unix)]
    pub(crate) fn read_wakes(&self) -> u64 {
        self.read_wakes.load(Ordering::Relaxed)
    }

    /// How many times the writing end has been woken; see `write_wakes`.
    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) fn write_wakes(&self) -> u64 {
        self.write_wakes.load(Ordering::Relaxed)
    }

    pub(crate) fn read_eof(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        self.land(&mut inner);
        inner.read_shut
            || inner.reset
            || (inner.closed && !inner.pending() && self.held().is_none())
    }

    #[cfg(target_os = "macos")]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn queued_bytes(&self) -> usize {
        let mut inner = self.inner.lock().unwrap();
        self.land(&mut inner);
        inner.buf.len()
    }

    #[cfg(unix)]
    pub(crate) fn is_write_shut(&self) -> bool {
        self.inner.lock().unwrap().write_shut
    }

    #[cfg(unix)]
    pub(crate) fn is_closed(&self) -> bool {
        self.inner.lock().unwrap().closed
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn is_write_closed(&self) -> bool {
        self.inner.lock().unwrap().sending_closed()
    }

    #[cfg(unix)]
    pub(crate) fn is_read_shut(&self) -> bool {
        self.inner.lock().unwrap().read_shut
    }

    #[cfg(unix)]
    pub(crate) fn reader_gone(&self) -> bool {
        self.inner.lock().unwrap().reader_gone
    }

    #[cfg(unix)]
    pub(crate) fn abandon_reader(&self) {
        self.inner.lock().unwrap().reader_gone = true;
    }

    #[cfg(unix)]
    pub(crate) fn pending_reader(&self, buf: crate::limits::SockBuf) {
        let space = buf.tcp_recv_space();
        let _ = self.pending_recv_space.set(space);
        #[cfg(target_os = "linux")]
        let _ = self.pending_recv_locked.set(buf.rcv_locked);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn set_mtu(&self, mtu: u32) {
        let _ = self.mtu.set(mtu);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn on_transmit(&self, hook: Box<TransmitHook>) {
        let _ = self.transmitted.set(hook);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn timestamp_write(&self, at: crate::tstamp::Stamp, bytes: &[u8], rtt: Duration) {
        let Some(rec) = self.writer.get() else {
            return;
        };
        let mut inner = self.inner.lock().unwrap();
        let Some(request) = crate::tstamp::tcp_written(rec, bytes.len()) else {
            return;
        };
        let ends = self.ends.as_ref().unwrap();
        if let Some(transport) = inner.transport.as_ref() {
            let end = transport.written;
            if transport.transmitted < end {
                inner.tcp_reports.push_back((end, request, rtt));
                return;
            }
            let Some((tail_end, tail)) = inner.tcp_tail.as_ref() else {
                return;
            };
            if *tail_end < end {
                return;
            }
            crate::tstamp::tcp_transmitted(rec, request, at, tail.len(), rtt, || {
                crate::tstamp::looped_frame(ends.from, ends.to, true, tail)
            });
        } else {
            crate::tstamp::tcp_transmitted(rec, request, at, bytes.len(), rtt, || {
                crate::tstamp::looped_frame(ends.from, ends.to, true, bytes)
            });
        }
    }

    #[cfg(unix)]
    pub(crate) fn has_unread(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        self.land(&mut inner);
        !inner.buf.is_empty()
    }

    #[cfg(unix)]
    pub(crate) fn reset_reader(&self) {
        if let Some(rec) = self.reader.get() {
            let visible = self.inner.lock().unwrap().in_flight.back().map(|f| f.at);
            rec.set_pending_error(libc::ECONNRESET, visible);
            rec.state().tcp_established = false;
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn reset_reader_at(&self, visible: Option<Deadline>) {
        if let Some(rec) = self.reader.get() {
            rec.set_pending_error(libc::ECONNRESET, visible);
            rec.state().tcp_established = false;
        }
    }

    pub(crate) fn established_reader(&self) -> bool {
        self.reader
            .get()
            .is_some_and(|rec| rec.state().tcp_established)
    }

    #[cfg(unix)]
    pub(crate) fn close_writer(&self) {
        if let Some(rec) = self.writer.get() {
            rec.state().tcp_established = false;
        }
    }

    /// Whether the stream was reset.
    pub(crate) fn is_reset(&self) -> bool {
        self.inner.lock().unwrap().reset
    }

    /// Whether a read would not block (it returns data, end of stream, a reset or a shut
    /// side), landing what has arrived first. What poll reports as readable.
    pub(crate) fn readable_or_closed(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        self.land(&mut inner);
        !inner.buf.is_empty()
            || (inner.reset && !inner.pending())
            || inner.read_shut
            || (inner.closed && !inner.pending() && self.held().is_none())
    }

    /// Whether everything written has crossed to the reader (or the stream was reset).
    pub(crate) fn delivered(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        self.land(&mut inner);
        !inner.pending() || inner.reset
    }

    /// Free room in the window, `None` while the pipe is unbounded.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn room(&self) -> Option<usize> {
        let cap = self.capacity()?;
        let mut inner = self.inner.lock().unwrap();
        self.land(&mut inner);
        Some(cap.saturating_sub(inner.used()))
    }

    /// Whether a blocked write of `len` more bytes can make progress: the pipe would take some
    /// of it, or the stream is closed or reset.
    pub(crate) fn can_write(&self, len: usize) -> bool {
        let Some(cap) = self.capacity() else {
            return true;
        };
        let mut inner = self.inner.lock().unwrap();
        self.land(&mut inner);
        inner.sending_closed() || Self::takes(cap, inner.used(), len, self.has_writer()) > 0
    }

    /// Whether poll reports the writing end writable: always for an unbounded pipe; on a bounded
    /// one as the host's threshold says. Linux: `sk_stream_is_writeable`, free space at least half
    /// of what is queued (include/net/sock.h `sk_stream_wspace` >= `sk_stream_min_wspace`, which
    /// is `sk_wmem_queued >> 1`). macOS: `SO_SNDLOWAT`, 2048 bytes free (XNU
    /// bsd/kern/uipc_socket2.c `sowriteable` compares free space with `so_snd.sb_lowat`, which
    /// `soreserve` there defaults to `MCLBYTES`, 2048 in bsd/arm/param.h and bsd/i386/param.h, and
    /// caps at the buffer's `sb_hiwat`; here the cap is the capacity, so a small window can still
    /// become writable). Windows: any free space, a snare choice, since Microsoft Learn "WSAPOLLFD"
    /// says only that POLLWRNORM means data "can be written without blocking". Pinned by
    /// tests/backpressure.rs.
    pub(crate) fn writable(&self) -> bool {
        let Some(cap) = self.capacity() else {
            return true;
        };
        let mut inner = self.inner.lock().unwrap();
        self.land(&mut inner);
        if inner.sending_closed() {
            return true;
        }
        let used = inner.used();
        let free = cap.saturating_sub(used);
        if cfg!(target_os = "linux") {
            free > 0 && free >= used / 2
        } else if cfg!(target_os = "macos") {
            free >= MAC_SNDLOWAT.min(cap)
        } else {
            free > 0
        }
    }

    /// Makes `rec` the reader of this pipe, counting what lands and probed for what waits.
    pub(crate) fn read_by(self: &Arc<Self>, rec: &Arc<SockRec>) {
        if self.reader.set(rec.clone()).is_ok() {
            #[cfg(target_os = "linux")]
            if self.ends.is_some() {
                let mut inner = self.inner.lock().unwrap();
                let charges: Vec<_> = inner.chunks.iter().copied().collect();
                inner.rx_memory.clear();
                for len in charges {
                    let charge = rec.state().buf.take_tcp(len);
                    inner.rx_memory.push_back((len, charge));
                }
            }
        }
        rec.set_probe(Arc::downgrade(self) as Weak<dyn RxProbe>);
    }

    /// Makes `rec` the writer of this pipe, whose send buffer adds to the capacity.
    pub(crate) fn write_by(&self, rec: &Arc<SockRec>) {
        let _ = self.writer.set(rec.clone());
    }

    /// Writes `bytes` through `write`, as a send on the stream does: all of it, blocking for room
    /// up to `sndtimeo` when `nonblocking` is off, or as much as fits when it is on. `error` says
    /// whether an error became pending meanwhile. A nonblocking send that writes nothing charges
    /// the per-call latency (`snare_interpose::charge_latency`) so a thread spinning on
    /// `EAGAIN`/`WSAEWOULDBLOCK` still moves a discrete virtual clock. A blocking send that
    /// wrote some bytes before timing out, getting stuck or seeing an error returns those bytes,
    /// as a real partial send does (POSIX.1-2024 XSH §2.10.16, `SO_SNDTIMEO`: a send that has
    /// blocked for the timeout "shall return with a partial count").
    pub(crate) fn send(
        &self,
        bytes: &[u8],
        nonblocking: bool,
        sndtimeo: Option<Duration>,
        mut write: impl FnMut(&[u8]) -> Option<usize>,
        error: impl Fn() -> bool,
    ) -> Sent {
        let deadline = sndtimeo.map(Deadline::timeout);
        let mut sent = 0;
        loop {
            match write(&bytes[sent..]) {
                None if sent == 0 => return Sent::Closed,
                None => return Sent::Bytes(sent),
                Some(n) => sent += n,
            }
            if sent == bytes.len() {
                return Sent::Bytes(sent);
            }
            if nonblocking {
                if sent > 0 {
                    return Sent::Bytes(sent);
                }
                snare_interpose::charge_latency();
                return Sent::WouldBlock;
            }
            let rest = bytes.len() - sent;
            let (keys, len) = self.wake_keys();
            let woke = if len == 0 {
                readiness().wait_until("tcp send", deadline, || self.can_write(rest) || error())
            } else {
                readiness().wait_until_on(
                    "tcp send",
                    deadline,
                    &keys[..len],
                    || self.pending_time(),
                    || self.can_write(rest) || error(),
                )
            };
            if sent > 0 && (!woke || error()) {
                return Sent::Bytes(sent);
            }
            if !woke {
                return if deadline.is_some_and(|d| d.passed()) {
                    Sent::TimedOut
                } else {
                    Sent::Stuck
                };
            }
            if error() {
                return Sent::Error;
            }
        }
    }
}

impl RxProbe for Pipe {
    fn pending_time(&self) -> bool {
        !self.inner.lock().unwrap().in_flight.is_empty() || self.held().is_some()
    }

    /// Lands what has arrived by now, for `SockRec` queries such as `FIONREAD`.
    fn land(&self) {
        let mut inner = self.inner.lock().unwrap();
        Pipe::land(self, &mut inner);
    }

    /// Chunks and bytes waiting to be read, without landing.
    fn queued(&self) -> (usize, usize) {
        let inner = self.inner.lock().unwrap();
        (inner.chunks.len(), inner.buf.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrapped_pipe() -> Arc<Pipe> {
        let pipe = Pipe::new(
            None,
            None,
            snare_interpose::Domain::current().unwrap().key(),
        );
        pipe.inner.lock().unwrap().buf = VecDeque::with_capacity(8);
        assert_eq!(
            pipe.write_after(b"012345", Duration::ZERO, |_, _, _| {}),
            Some(6)
        );
        let mut prefix = [0; 4];
        assert!(matches!(pipe.read(&mut prefix), Read::Data(4)));
        assert_eq!(&prefix, b"0123");
        assert_eq!(
            pipe.write_after(b"abcdef", Duration::ZERO, |_, _, _| {}),
            Some(6)
        );
        let inner = pipe.inner.lock().unwrap();
        let (first, second) = inner.buf.as_slices();
        assert!(!first.is_empty());
        assert!(!second.is_empty());
        drop(inner);
        pipe
    }

    #[test]
    fn wrapped_reads_preserve_partial_chunks_and_half_close() {
        crate::Sim::new().run(|| {
            for n in [0, 1, 3, 4, 5, 8, 12] {
                let pipe = wrapped_pipe();
                let mut out = vec![0xcc; n];
                let expected = n.min(8);
                assert!(matches!(pipe.read(&mut out), Read::Data(got) if got == expected));
                assert_eq!(&out[..expected], &b"45abcdef"[..expected]);
                assert!(out[expected..].iter().all(|b| *b == 0xcc));
                let remaining = &b"45abcdef"[expected..];
                let inner = pipe.inner.lock().unwrap();
                assert_eq!(inner.buf.iter().copied().collect::<Vec<_>>(), remaining);
                assert_eq!(inner.chunks.iter().sum::<usize>(), remaining.len());
                drop(inner);
                pipe.close(|_| {});
                if !remaining.is_empty() {
                    let mut tail = [0; 8];
                    assert!(
                        matches!(pipe.read(&mut tail), Read::Data(got) if got == remaining.len())
                    );
                    assert_eq!(&tail[..remaining.len()], remaining);
                }
                assert!(matches!(pipe.read(&mut [0; 1]), Read::Eof));
            }
        });
    }

    #[test]
    fn wrapped_peeks_leave_bytes_chunks_and_wakes_untouched() {
        crate::Sim::new().run(|| {
            let pipe = wrapped_pipe();
            let read_wakes = pipe.read_wakes.load(Ordering::Relaxed);
            let write_wakes = pipe.write_wakes.load(Ordering::Relaxed);
            for n in [0, 1, 3, 4, 5, 8, 12] {
                let mut out = vec![0xcc; n];
                let expected = n.min(8);
                assert!(matches!(pipe.peek(&mut out), Read::Data(got) if got == expected));
                assert_eq!(&out[..expected], &b"45abcdef"[..expected]);
                assert!(out[expected..].iter().all(|b| *b == 0xcc));
                assert_eq!(pipe.queued(), (2, 8));
                assert_eq!(pipe.read_wakes.load(Ordering::Relaxed), read_wakes);
                assert_eq!(pipe.write_wakes.load(Ordering::Relaxed), write_wakes);
            }
            let mut out = [0; 8];
            assert!(matches!(pipe.read(&mut out), Read::Data(8)));
            assert_eq!(&out, b"45abcdef");
            assert!(matches!(pipe.read(&mut [0; 1]), Read::WouldBlock));
        });
    }
}
