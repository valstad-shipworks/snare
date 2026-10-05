#![allow(dead_code)]

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    thread::ThreadId,
    time::Duration,
};

use anymap2::SendSyncAnyMap as AnyMap;
use parking_lot::{Mutex, ReentrantMutex};

use crate::SocketType;
use crate::mcast::McastState;
use crate::netif::{
    DropAccounting, NetModel, NicId, Proto, SockView, SocketId, bind_conflicts, listener_entry,
    rcvbuf_cap, tcp_entry, udp_entry,
};
use crate::os::{Errno, OsSemantics, os_err_for};
use crate::pcapng::PcapWriter;
use crate::sched::timer::TimerTarget;
use crate::sched::waitset::WaitKey;
use crate::sched::{SchedSlot, warn_driven};
use crate::time::Instant;

/// Maps every test/child thread to its oldest known test-thread ancestor.
static TEST_THREAD_HIERARCHY: LazyLock<Mutex<HashMap<ThreadId, ThreadId>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Per-test state slots, keyed by the root test thread.
static TEST_STATE: LazyLock<ReentrantMutex<RefCell<HashMap<TestThreadId, AnyMap>>>> =
    LazyLock::new(|| ReentrantMutex::new(RefCell::new(HashMap::new())));

/// Under `--cfg snare_global` every thread in the process funnels to this one
/// state slot instead of a per-test slot, so the whole process shares a single
/// in-memory network with no `register_test` / child-thread registration. The
/// slot is keyed by whichever thread resolves it first; the id is arbitrary —
/// the point is that every thread maps to the same key. For a long-running
/// single-process sim (driving real drivers against an in-process emulator),
/// not for isolated `#[test]`s, which want per-test isolation.
#[cfg(snare_global)]
static GLOBAL_SLOT_KEY: LazyLock<TestThreadId> =
    LazyLock::new(|| TestThreadId(std::thread::current().id()));

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct TestThreadId(ThreadId);

impl TestThreadId {
    fn of(id: ThreadId) -> Self {
        // Fast path: already registered.
        {
            crate::sched::note_lock();
            let hierarchy = TEST_THREAD_HIERARCHY.lock();
            if hierarchy.contains_key(&id) {
                return Self::resolve_from(&hierarchy, id);
            }
        }
        if let Some(root) = inherit_creator_slot(id) {
            return root;
        }
        // Slow path: poll until the parent registers us. The common case
        // resolves in a few ms; heavy CI contention gets up to GRACE_TOTAL.
        const GRACE_TOTAL: Duration = Duration::from_millis(2_000);
        const POLL_INTERVAL: Duration = Duration::from_millis(2);
        let deadline = std::time::Instant::now() + GRACE_TOTAL;
        loop {
            std::thread::sleep(POLL_INTERVAL);
            let hierarchy = TEST_THREAD_HIERARCHY.lock();
            if hierarchy.contains_key(&id) {
                return Self::resolve_from(&hierarchy, id);
            }
            if std::time::Instant::now() >= deadline {
                panic!(
                    "Thread {:?} not registered as test thread or child thread \
                     within {GRACE_TOTAL:?}",
                    id
                );
            }
        }
    }

    fn resolve_from(
        hierarchy: &parking_lot::lock_api::MutexGuard<
            '_,
            parking_lot::RawMutex,
            HashMap<ThreadId, ThreadId>,
        >,
        id: ThreadId,
    ) -> Self {
        let mut current_id = id;
        while let Some(parent_id) = hierarchy.get(&current_id) {
            if parent_id == &current_id {
                break;
            }
            current_id = *parent_id;
        }
        TestThreadId(current_id)
    }

    #[cfg(not(snare_global))]
    fn current() -> Self {
        Self::of(std::thread::current().id())
    }

    #[cfg(snare_global)]
    fn current() -> Self {
        *GLOBAL_SLOT_KEY
    }
}

/// Host thread id → std id of every thread that registered in the test
/// hierarchy, so a thread nobody registered can find its creator's slot.
static HOST_THREADS: LazyLock<Mutex<HashMap<u64, ThreadId>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn note_host_thread() {
    if let Some(host) = crate::host_threads::current_tid() {
        HOST_THREADS
            .lock()
            .insert(host, std::thread::current().id());
    }
}

/// Put the unregistered thread `id` (the calling thread) under the slot of
/// the nearest thread up its creation chain that is registered, where the
/// host tracks creators.
fn inherit_creator_slot(id: ThreadId) -> Option<TestThreadId> {
    const MAX_DEPTH: usize = 64;
    let mut host = crate::host_threads::current_tid()?;
    for _ in 0..MAX_DEPTH {
        host = crate::host_threads::creator_of(host)?;
        let Some(creator) = HOST_THREADS.lock().get(&host).copied() else {
            continue;
        };
        let root = {
            crate::sched::note_lock();
            let mut hierarchy = TEST_THREAD_HIERARCHY.lock();
            if !hierarchy.contains_key(&creator) {
                continue;
            }
            hierarchy.insert(id, creator);
            TestThreadId::resolve_from(&hierarchy, id)
        };
        note_host_thread();
        crate::sched::invalidate_slot_cache();
        return Some(root);
    }
    None
}

/// Mark the current thread as the root of a fresh per-test state slot. Call
/// at the top of every `#[test]` that uses snare.
pub fn register_test() {
    crate::os::force_env();
    #[cfg(feature = "fast-talker-core")]
    crate::fast_talker_shim::hooks::install();
    let thread_name = std::thread::current().name().map(String::from);

    #[cfg(not(snare_global))]
    {
        let thread_id = std::thread::current().id();
        let mut map = TEST_THREAD_HIERARCHY.lock();
        map.insert(thread_id, thread_id);
        drop(map);
        note_host_thread();
        let test_thread_id = TestThreadId(thread_id);
        TEST_STATE
            .lock()
            .borrow_mut()
            .insert(test_thread_id, AnyMap::new());
    }
    crate::sched::invalidate_slot_cache();

    // Under `snare_global` there is one shared slot that auto-vivifies on first
    // access, so calling `register_test` is optional; just run pcap init, which
    // attaches to that shared slot via the `state!` macro.

    // pcap init is in a helper defined after the `state!` macro.
    pcap_init_for_test(thread_name);
}

/// Attach a spawned thread to the current test's state slot. Call from the
/// parent right after `std::thread::spawn(...)` (or use [`ThreadExt::register_as_child`](crate::ThreadExt::register_as_child)).
pub fn register_child_thread(child_thread_id: ThreadId) {
    #[cfg(snare_global)]
    let _ = child_thread_id;
    #[cfg(not(snare_global))]
    {
        let test_thread_id = TestThreadId::current();
        TEST_THREAD_HIERARCHY
            .lock()
            .insert(child_thread_id, test_thread_id.0);
        crate::sched::invalidate_slot_cache();
    }
}

/// Variant of [`register_child_thread`] called from inside the spawned thread,
/// naming its parent's `ThreadId`.
pub fn register_thread_child_of(parent_thread_id: ThreadId) {
    #[cfg(snare_global)]
    let _ = parent_thread_id;
    #[cfg(not(snare_global))]
    {
        let child_thread_id = std::thread::current().id();
        TEST_THREAD_HIERARCHY
            .lock()
            .insert(child_thread_id, parent_thread_id);
        note_host_thread();
        crate::sched::invalidate_slot_cache();
    }
}

/// Begin pcapng capture for the current test. No-op unless `SNARE_PCAPNG_DIR`
/// is set in the environment. Already-enabled tests are unaffected.
pub fn enable_pcapng() {
    pcap_enable_for_current_test();
}

/// Resolve the current thread's state slot from a `&mut` borrow of the
/// `TEST_STATE` map. In isolated mode an unregistered thread is a hard error;
/// under `snare_global` every thread shares one slot that is created on demand.
#[cfg(not(snare_global))]
macro_rules! slot {
    ($borrow:ident) => {
        $borrow
            .get_mut(&TestThreadId::current())
            .expect("Not a valid test thread")
    };
}
#[cfg(snare_global)]
macro_rules! slot {
    ($borrow:ident) => {
        $borrow
            .entry(TestThreadId::current())
            .or_insert_with(AnyMap::new)
    };
}

macro_rules! state {
    ( $( $var:ident = $idx:ident $(? $default:expr)? );* $(;)? ) => {
        crate::os::force_env();
        #[cfg(feature = "fast-talker-core")]
        crate::fast_talker_shim::hooks::install();
        crate::sched::note_lock();
        let mut __guard = TEST_STATE.lock();
        let mut __borrow = __guard.borrow_mut();
        let mut __any_map = slot!(__borrow);
        $(
            $(
                if !__any_map.contains::<Mutex<$idx>>() {
                    __any_map.insert::<Mutex<$idx>>(Mutex::new($default));
                }
            )*
        )*
        $(
            #[allow(unused)]
            let mut $var = __any_map.get::<Mutex<$idx>>()
                .expect("Failed to get state")
                .lock();
        )*
    };
}

// macro_rules! drop_all {
//     ( $( $var:ident ),* $(,)? ) => {
//         $(
//             drop($var);
//         )*
//     };
// }

pub(crate) type TcpConnections = BTreeMap<usize, TcpConnection>;
pub(crate) type TcpListeners = BTreeMap<SocketAddr, TcpListenerState>;
pub(crate) type UdpConnections = Vec<UdpConnection>;
type LocalPortsUsed = HashSet<SocketAddr>;
type Next = (usize, u16);
type Quiescence = HashMap<SocketAddr, QuiesceEntry>;
type TcpPolicies = HashMap<SocketAddr, TcpPolicy>;
type UdpPolicies = HashMap<SocketAddr, UdpPolicy>;
type ListenerBehaviors = HashMap<SocketAddr, ListenerBehavior>;
type RecordedEvents = Vec<RecordedEntry>;
type RngState = NetRng;

/// Whether any state slot has ever opened a capture writer. Writers are
/// never closed while their slot lives, so `false` means no capture anywhere.
static PCAP_OPENED: AtomicBool = AtomicBool::new(false);

/// Whether any state slot has ever set a UDP or TCP policy. Policies are
/// never removed, so `false` means every address has the default policy.
static UDP_POLICY_SET: AtomicBool = AtomicBool::new(false);
static TCP_POLICY_SET: AtomicBool = AtomicBool::new(false);

#[derive(Default)]
pub(crate) struct PcapState {
    pub writer: Option<PcapWriter>,
    pub test_name: Option<String>,
}

fn pcap_init_for_test(thread_name: Option<String>) {
    state!(pcap = PcapState ? PcapState::default());
    pcap.test_name = thread_name.clone();
    if let Some(name) = thread_name.as_deref()
        && crate::pcapng::env_force_match(name)
    {
        pcap.writer = crate::pcapng::open_writer(name);
        note_pcap_opened(&pcap);
    }
}

fn note_pcap_opened(pcap: &PcapState) {
    if pcap.writer.is_some() {
        PCAP_OPENED.store(true, Ordering::Release);
    }
}

fn pcap_enable_for_current_test() {
    state!(pcap = PcapState ? PcapState::default());
    if pcap.writer.is_some() {
        return;
    }
    let name = pcap
        .test_name
        .clone()
        .or_else(|| std::thread::current().name().map(String::from));
    if let Some(name) = name {
        pcap.writer = crate::pcapng::open_writer(&name);
        note_pcap_opened(&pcap);
    }
}

#[inline]
fn with_pcap<F: FnOnce(&mut PcapWriter)>(f: F) {
    if !PCAP_OPENED.load(Ordering::Acquire) {
        return;
    }
    let now = crate::sched::wall_now();
    state!(pcap = PcapState ? PcapState::default());
    if let Some(w) = pcap.writer.as_mut() {
        w.set_time(now);
        f(w);
    }
}

pub(crate) fn pcap_tcp_open(client: SocketAddr, server: SocketAddr) {
    with_pcap(|w| w.tcp_open(client, server));
}

pub(crate) fn pcap_tcp_data(src: SocketAddr, dst: SocketAddr, data: &[u8]) {
    with_pcap(|w| w.tcp_data(src, dst, data));
}

pub(crate) fn pcap_tcp_fin(src: SocketAddr, dst: SocketAddr) {
    with_pcap(|w| w.tcp_fin(src, dst));
}

pub(crate) fn pcap_tcp_rst(src: SocketAddr, dst: SocketAddr) {
    with_pcap(|w| w.tcp_rst(src, dst));
}

/// Where a packet crossed the network: the interface (index and name) and
/// the instant it was on the wire.
pub(crate) type WireTap = (Instant, Option<(u32, String)>);

/// Capture a UDP datagram on the interface and at the instant of `tap`.
pub(crate) fn pcap_udp_on(tap: &WireTap, src: SocketAddr, dst: SocketAddr, data: &[u8]) {
    if !PCAP_OPENED.load(Ordering::Acquire) {
        return;
    }
    let (at, nic) = tap;
    let wall = crate::sched::wall_of(*at)
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    state!(pcap = PcapState ? PcapState::default());
    if let Some(w) = pcap.writer.as_mut() {
        match nic {
            Some((index, name)) => w.set_time_on(wall, *index, name),
            None => w.set_time(wall),
        }
        w.udp_datagram(src, dst, data);
    }
}

/// Which direction(s) a Quiesce window suppresses readiness in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuiesceMode {
    /// Both inbound (peer → SUT) and outbound (SUT → peer).
    Both,
    /// Inbound only — peer is "deaf"; SUT can still send.
    InboundOnly,
    /// Outbound only — SUT can read but its writes won't drain (stuck recv-window).
    OutboundOnly,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct QuiesceEntry {
    pub until: Instant,
    pub mode: QuiesceMode,
}

/// Per-link TCP policy applied to a SUT-side address.
#[derive(Debug, Default, Clone, Copy)]
pub struct TcpPolicy {
    /// Delay applied to bytes coming INTO this addr (peer → us).
    pub inbound_latency: Duration,
    /// Cap on the SUT-side incoming buffer. Writes back-pressure when full.
    pub recv_window: Option<usize>,
}

/// Per-socket UDP link policy.
#[derive(Debug, Default, Clone, Copy)]
pub struct UdpPolicy {
    /// Inbound latency (peer → us).
    pub inbound_latency: Duration,
    /// Per-packet drop probability in `[0, 1]`.
    pub loss_rate: f32,
    /// Per-packet duplicate probability in `[0, 1]`.
    pub duplicate_rate: f32,
    /// Extra per-packet random delay, uniform in `[0, jitter]`.
    pub reorder_jitter: Duration,
    /// Cap on the SUT's outbound queue. Sends return `WouldBlock` when full.
    pub send_queue_depth: Option<usize>,
    /// Max datagram size; oversized sends return `InvalidInput`.
    pub mtu: Option<usize>,
}

/// How a TCP listener responds to incoming `connect()` calls.
#[derive(Debug, Clone, Copy)]
pub enum ListenerBehavior {
    /// Accept immediately (default).
    Accepting,
    /// Refuse with `ECONNREFUSED`.
    Refusing,
    /// Reject connect attempts until `Instant`, then resume accepting.
    DelayingUntil(Instant),
}

/// An event captured by the per-test recording log. See [`recorded_events`].
#[derive(Debug, Clone)]
pub enum RecordedEvent {
    TcpSendFromTest {
        from: SocketAddr,
        to: SocketAddr,
        len: usize,
    },
    TcpResetFromTest {
        addr: SocketAddr,
    },
    TcpCloseFromTest {
        addr: SocketAddr,
    },
    UdpSendFromTest {
        from: SocketAddr,
        to: SocketAddr,
        len: usize,
        dropped: bool,
        duplicated: bool,
    },
    UdpCloseFromTest {
        addr: SocketAddr,
    },
    Quiesce {
        addr: SocketAddr,
        dur: Duration,
        mode: QuiesceMode,
    },
    SocketErrorFromTest {
        addr: SocketAddr,
        kind: io::ErrorKind,
    },
}

/// A timestamped [`RecordedEvent`].
#[derive(Debug, Clone)]
pub struct RecordedEntry {
    pub at: Instant,
    pub event: RecordedEvent,
}

static DEFAULT_NEXT: (usize, u16) = (0, 40_000);

#[derive(Debug)]
pub(crate) struct Packet {
    pub data: Vec<u8>,
    pub dest: SocketAddr,
    pub source: SocketAddr,
    /// When the datagram reaches (or reached) its destination socket.
    pub at: Instant,
    /// The destination socket's drop counter when the datagram joined its
    /// receive queue.
    pub drops_at_enqueue: u32,
    pub ingress: Option<NicId>,
    pub seq: u64,
    /// Counted in the ingress interface's receive counters when it joins
    /// the queue. A frame fanned out to several sockets counts once.
    pub counts_on_nic: bool,
}

impl Packet {
    fn new(data: Vec<u8>, dest: SocketAddr, source: SocketAddr, at: Instant) -> Self {
        Self {
            data,
            dest,
            source,
            at,
            drops_at_enqueue: 0,
            ingress: None,
            seq: 0,
            counts_on_nic: true,
        }
    }
}

#[derive(Debug)]
pub(crate) struct UdpConnection {
    pub id: SocketId,
    pub bound_addr: SocketAddr,
    pub from_local: VecDeque<Packet>,
    pub to_local: VecDeque<Packet>,
    /// Inbound datagrams in flight, sorted by `(at, seq)`, waiting to join
    /// `to_local`.
    pub pending_inbound: VecDeque<Packet>,
    pub failure_queue: Vec<io::Result<()>>,
    pub external_error: Option<io::Error>,
    /// Closed by the test side; the owner's operations fail.
    pub is_destroyed: bool,
    /// Every handle was dropped. Kept only while `from_local` still holds
    /// datagrams for virtual testers; every other lookup skips it.
    pub dropped: bool,
    pub connected: Option<SocketAddr>,
    pub bound_device: Option<NicId>,
    /// Windows' `IP_UNICAST_IF`: unicast sends leave through it, receives
    /// are not filtered.
    pub unicast_if: Option<NicId>,
    pub multicast_if: Option<NicId>,
    pub mcast: McastState,
    /// The don't-fragment bit: a datagram over the egress MTU fails with
    /// `EMSGSIZE`.
    pub dont_fragment: bool,
    pub last_tx_nic: Option<NicId>,
    pub last_rx_nic: Option<NicId>,
    pub rcvbuf: Option<usize>,
    pub sndbuf: Option<usize>,
    pub queued_bytes: usize,
    pub drops: u32,
    pub overflowed: u64,
    pub wire_lost: u64,
    pub delivered: u64,
    /// The error an ICMP port unreachable left on the socket, and when it
    /// arrives.
    pub icmp_error: Option<(Instant, Errno)>,
    pub created_at: Instant,
    pub closed_at: Option<Instant>,
    #[cfg(feature = "fast-talker-core")]
    pub ft: crate::fast_talker_shim::slot::UdpFt,
}

impl UdpConnection {
    fn new(id: SocketId, bound_addr: SocketAddr, now: Instant) -> Self {
        Self {
            id,
            bound_addr,
            from_local: VecDeque::new(),
            to_local: VecDeque::new(),
            pending_inbound: VecDeque::new(),
            failure_queue: Vec::new(),
            external_error: None,
            is_destroyed: false,
            dropped: false,
            connected: None,
            bound_device: None,
            unicast_if: None,
            multicast_if: None,
            mcast: McastState::default(),
            dont_fragment: false,
            last_tx_nic: None,
            last_rx_nic: None,
            rcvbuf: None,
            sndbuf: None,
            queued_bytes: 0,
            drops: 0,
            overflowed: 0,
            wire_lost: 0,
            delivered: 0,
            icmp_error: None,
            created_at: now,
            closed_at: None,
            #[cfg(feature = "fast-talker-core")]
            ft: Default::default(),
        }
    }

    fn live(&self) -> bool {
        !self.dropped
    }

    /// The routing view of this socket for a send to `dst`.
    fn view(&self, net: &NetModel, dst: IpAddr) -> SockView {
        let local_ip = self.bound_addr.ip();
        SockView {
            local_ip,
            bound_device: self
                .bound_device
                .or(self.unicast_if.filter(|_| !dst.is_multicast())),
            multicast_if: self.multicast_if,
            strong_host: net.strong_host_applies(local_ip, dst),
        }
    }

    /// Take the datagram at `idx` off the receive queue.
    pub(crate) fn take_local(&mut self, idx: usize) -> Option<Packet> {
        let pkt = self.to_local.remove(idx)?;
        self.queued_bytes = self.queued_bytes.saturating_sub(pkt.data.len());
        Some(pkt)
    }

    fn insert_pending(&mut self, pkt: Packet) {
        let key = (pkt.at, pkt.seq);
        let idx = self
            .pending_inbound
            .partition_point(|p| (p.at, p.seq) <= key);
        self.pending_inbound.insert(idx, pkt);
    }

    fn icmp_visible(&self, now: Instant) -> bool {
        self.icmp_error.is_some_and(|(at, _)| at <= now)
    }

    /// Take the ICMP-induced error once it has arrived.
    fn take_icmp(&mut self, now: Instant) -> Option<Errno> {
        if !self.icmp_visible(now) {
            return None;
        }
        self.icmp_error.take().map(|(_, e)| e)
    }

    /// Record an ICMP port unreachable for a datagram this socket sent to
    /// `to`, arriving at `at`, if `os` reports one to it. A connected socket
    /// hears about its peer; on Windows an unconnected one does too.
    fn icmp_port_unreachable(&mut self, os: OsSemantics, to: SocketAddr, at: Instant) -> bool {
        let err = match (os, self.connected) {
            (_, Some(peer)) if peer != to => return false,
            (OsSemantics::Windows, _) => Errno::ConnReset,
            (_, Some(_)) => Errno::ConnRefused,
            (_, None) => return false,
        };
        let at = self.icmp_error.map_or(at, |(earlier, _)| earlier.min(at));
        self.icmp_error = Some((at, err));
        true
    }

    fn charge_wire_loss(&mut self, accounting: DropAccounting) {
        self.wire_lost += 1;
        if accounting == DropAccounting::PolicyAndOverflow {
            self.drops = self.drops.wrapping_add(1);
        }
    }
}

#[derive(Debug)]
pub(crate) struct TcpConnection {
    pub id: SocketId,
    pub stream_id: usize,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub incoming: VecDeque<u8>,
    /// When each run of bytes in `incoming` arrived, and how many bytes it
    /// holds, oldest first.
    pub arrivals: VecDeque<(Instant, usize)>,
    /// Inbound chunks waiting on latency before joining `incoming`, in
    /// non-decreasing deadline order.
    pub pending_inbound: VecDeque<(Instant, Vec<u8>)>,
    /// Inbound chunks held while the connection's interface is down.
    pub stalled: VecDeque<Vec<u8>>,
    pub read_shutdown: bool,
    pub write_shutdown: bool,
    pub failure_queue: Vec<io::Result<()>>,
    pub external_error: Option<io::Error>,
    pub peer_stream_id: Option<usize>,
    pub nonblocking: bool,
    pub nodelay: bool,
    pub ttl: u32,
    pub linger: Option<Duration>,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
    pub ref_count: usize,
    pub owns_port: bool,
    pub is_destroyed: bool,
    /// Set by `TesterAction::ResetTcp`; surfaces `ECONNRESET` on the next read/write.
    pub reset_pending: bool,
    /// Writes that failed with `WouldBlock`; each one re-arms mio writability.
    pub write_blocks: u64,
    /// How the far end went away, under faithful semantics.
    pub peer_close: PeerClose,
    /// The interface the connection runs over.
    pub nic: Option<NicId>,
    pub listener: Option<SocketId>,
    pub bound_device: Option<NicId>,
    pub rcvbuf: Option<usize>,
    pub sndbuf: Option<usize>,
    pub delivered: u64,
    pub created_at: Instant,
    #[cfg(feature = "fast-talker-core")]
    pub ft: crate::fast_talker_shim::slot::TcpFt,
}

/// How the far end of a TCP connection went away, as faithful semantics
/// track it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerClose {
    Open,
    /// The peer closed its socket gracefully: its FIN arrived and nothing
    /// is left to read what this end writes.
    Fin,
    /// A RST arrived and has been reported.
    Reset,
}

impl TcpConnection {
    /// Queue `data` to become readable at `at`, never before an earlier
    /// chunk. Returns the instant it becomes readable.
    fn push_pending(&mut self, at: Instant, data: Vec<u8>) -> Instant {
        let at = self
            .pending_inbound
            .back()
            .map_or(at, |(last, _)| (*last).max(at));
        self.pending_inbound.push_back((at, data));
        at
    }

    /// Make `data` readable, as having arrived at `at`.
    fn append_incoming(&mut self, at: Instant, data: Vec<u8>) {
        if !data.is_empty() {
            self.arrivals.push_back((at, data.len()));
        }
        #[cfg(feature = "fast-talker-core")]
        {
            self.ft.bytes_received += data.len() as u64;
        }
        self.incoming.extend(data);
        self.delivered += 1;
    }

    /// Move up to `buf.len()` readable bytes into `buf`, returning how many
    /// with the arrival instant of the newest of them.
    pub(crate) fn take_incoming_into(&mut self, buf: &mut [u8]) -> (usize, Option<Instant>) {
        let n = buf.len().min(self.incoming.len());
        let (front, back) = self.incoming.as_slices();
        let head = n.min(front.len());
        buf[..head].copy_from_slice(&front[..head]);
        buf[head..n].copy_from_slice(&back[..n - head]);
        (n, self.discard_incoming(n))
    }

    /// Drop up to `n` readable bytes, returning the arrival instant of the
    /// newest of them.
    pub(crate) fn discard_incoming(&mut self, n: usize) -> Option<Instant> {
        let n = n.min(self.incoming.len());
        self.incoming.drain(..n);
        let mut left = n;
        let mut newest = None;
        while left > 0 {
            let Some(front) = self.arrivals.front_mut() else {
                break;
            };
            newest = Some(front.0);
            if front.1 <= left {
                left -= front.1;
                self.arrivals.pop_front();
            } else {
                front.1 -= left;
                left = 0;
            }
        }
        newest
    }

    pub(crate) fn clear_incoming(&mut self) {
        self.incoming.clear();
        self.arrivals.clear();
    }

    pub(crate) fn buffered(&self) -> usize {
        self.incoming.len()
            + self
                .pending_inbound
                .iter()
                .map(|(_, b)| b.len())
                .sum::<usize>()
            + self.stalled.iter().map(Vec::len).sum::<usize>()
    }

    /// Bytes a writer may still add under the receive `window`.
    pub(crate) fn room(&self, window: Option<usize>) -> usize {
        window.map_or(usize::MAX, |w| w.saturating_sub(self.buffered()))
    }
}

#[derive(Debug)]
pub(crate) struct TcpListenerState {
    pub id: SocketId,
    pub bound_addr: SocketAddr,
    pub pending_streams: VecDeque<usize>,
    pub nonblocking: bool,
    pub ttl: u32,
    pub error: Option<io::Error>,
    pub is_closed: bool,
    pub ref_count: usize,
    pub bound_device: Option<NicId>,
    pub created_at: Instant,
    #[cfg(feature = "fast-talker-core")]
    pub ft: crate::fast_talker_shim::slot::ListenerFt,
}

/// Whitelist `ip` as a bindable address for this test. The default whitelist
/// covers `0.0.0.0`, `127.0.0.1`, `::`, and `::1`. The address is assigned to
/// the default interface `snare0`, or to the loopback for a loopback address;
/// an address some interface already has is left where it is.
pub fn add_ip_addr(ip: IpAddr) {
    with_net(|ctx| ctx.net.add_ip_addr(ip));
}

#[derive(Default)]
struct HostTable(HashMap<String, Vec<IpAddr>>);

fn host_key(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

/// Make `name` resolve to `ip` inside this test's sim, without the host's
/// resolver. Each call adds one address; names are matched without regard
/// to ASCII case or a trailing dot. An entry for `localhost` replaces the
/// emulated OS's default loopback answer.
pub fn add_host(name: &str, ip: IpAddr) {
    state!(hosts = HostTable ? HostTable::default());
    let ips = hosts.0.entry(host_key(name)).or_default();
    if !ips.contains(&ip) {
        ips.push(ip);
    }
}

pub(crate) fn host_addrs(name: &str) -> Option<Vec<IpAddr>> {
    state!(hosts = HostTable ? HostTable::default());
    hosts.0.get(&host_key(name)).cloned()
}

pub(crate) fn is_ip_addr_valid(ip: IpAddr) -> bool {
    with_net(|ctx| ctx.net.is_ip_valid(ip))
}

/// Mutable access to the network model and every socket record, under one
/// lock scope.
pub(crate) struct NetCtx<'a> {
    pub net: &'a mut NetModel,
    pub udp: &'a mut UdpConnections,
    pub tcp: &'a mut TcpConnections,
    pub listeners: &'a mut TcpListeners,
}

pub(crate) fn with_net<R>(f: impl FnOnce(NetCtx<'_>) -> R) -> R {
    state!(
        net = NetModel ? NetModel::default();
        udp = UdpConnections ? Vec::new();
        tcp = TcpConnections ? BTreeMap::new();
        listeners = TcpListeners ? BTreeMap::new();
    );
    f(NetCtx {
        net: &mut net,
        udp: &mut udp,
        tcp: &mut tcp,
        listeners: &mut listeners,
    })
}

/// The slot's selected OS and whether it was chosen explicitly.
pub(crate) fn os_ctx() -> (OsSemantics, bool) {
    if let Some(ctx) = decode_os_ctx(crate::sched::with_slot(SchedSlot::os_ctx)) {
        return ctx;
    }
    let slot = crate::sched::slot();
    state!(net = NetModel ? NetModel::default());
    let ctx = (net.os, net.os_explicit);
    slot.set_os_ctx(encode_os_ctx(ctx));
    ctx
}

pub(crate) fn set_os(os: OsSemantics) {
    let slot = crate::sched::slot();
    state!(net = NetModel ? NetModel::default());
    net.set_os(os);
    slot.set_os_ctx(encode_os_ctx((net.os, net.os_explicit)));
}

fn encode_os_ctx((os, explicit): (OsSemantics, bool)) -> u8 {
    let os = match os {
        OsSemantics::Linux => 0,
        OsSemantics::MacOs => 1,
        OsSemantics::Windows => 2,
    };
    1 | os << 1 | u8::from(explicit) << 3
}

fn decode_os_ctx(v: u8) -> Option<(OsSemantics, bool)> {
    if v & 1 == 0 {
        return None;
    }
    let os = match (v >> 1) & 3 {
        0 => OsSemantics::Linux,
        1 => OsSemantics::MacOs,
        _ => OsSemantics::Windows,
    };
    Some((os, v & 8 != 0))
}

/// Wake the waiters on `key` (and the tester loop). Must not be called while
/// the state lock is held.
pub(crate) fn wake(key: WaitKey) {
    let waits = crate::sched::with_slot(|s| Arc::clone(s.waits()));
    waits.notify(key);
}

/// Wake the waiters on `key` once virtual time reaches `at`, so data that
/// becomes visible at `at` wakes a reader with no other deadline. Must not be
/// called while the state lock is held.
pub(crate) fn wake_at(at: Instant, key: WaitKey) {
    crate::sched::with_slot(|slot| {
        let waits = Arc::clone(slot.waits());
        slot.timers().insert(
            crate::sched::instant_ns(at),
            TimerTarget::Release(Box::new(move || waits.notify(key))),
        );
    });
}

pub(crate) fn set_quiesce(addr: SocketAddr, until: Instant, mode: QuiesceMode) {
    {
        state!(quiesce = Quiescence ? HashMap::new());
        quiesce.insert(addr, QuiesceEntry { until, mode });
    }
    wake(WaitKey::Addr(addr));
    wake_at(until, WaitKey::Addr(addr));
    record(RecordedEvent::Quiesce {
        addr,
        dur: until.saturating_duration_since(Instant::now()),
        mode,
    });
}

/// Suppress mio readiness on `addr` (both directions) for `dur`. Bytes still
/// buffer; `Waker::wake()` still fires.
pub fn quiesce(addr: SocketAddr, dur: Duration) {
    set_quiesce(addr, Instant::now() + dur, QuiesceMode::Both);
}

/// [`quiesce`] with an explicit [`QuiesceMode`].
pub fn quiesce_with_mode(addr: SocketAddr, dur: Duration, mode: QuiesceMode) {
    set_quiesce(addr, Instant::now() + dur, mode);
}

/// Whether `addr` is quiesced inbound and outbound at `now`. Prunes every
/// expired entry of the slot.
fn quiesced_dirs(quiesce: &mut Quiescence, addr: SocketAddr, now: Instant) -> (bool, bool) {
    if quiesce.is_empty() {
        return (false, false);
    }
    quiesce.retain(|_, entry| entry.until > now);
    match quiesce.get(&addr).map(|e| e.mode) {
        None => (false, false),
        Some(QuiesceMode::Both) => (true, true),
        Some(QuiesceMode::InboundOnly) => (true, false),
        Some(QuiesceMode::OutboundOnly) => (false, true),
    }
}

// ----- Policy helpers -----

/// Delay all inbound bytes for the SUT-side TCP `addr` by `latency`.
pub fn set_tcp_inbound_latency(addr: SocketAddr, latency: Duration) {
    {
        state!(policies = TcpPolicies ? HashMap::new());
        policies.entry(addr).or_default().inbound_latency = latency;
        TCP_POLICY_SET.store(true, Ordering::Release);
    }
    wake(WaitKey::Addr(addr));
}

/// Cap the SUT-side TCP receive buffer for `addr`. `None` removes the cap.
pub fn set_tcp_recv_window(addr: SocketAddr, window: Option<usize>) {
    let writers: Vec<usize> = {
        state!(
            policies = TcpPolicies ? HashMap::new();
            tcp = TcpConnections ? BTreeMap::new();
        );
        policies.entry(addr).or_default().recv_window = window;
        TCP_POLICY_SET.store(true, Ordering::Release);
        tcp.values()
            .filter(|c| c.local_addr == addr)
            .filter_map(|c| c.peer_stream_id)
            .collect()
    };
    wake(WaitKey::Addr(addr));
    for writer in writers {
        wake(WaitKey::Stream(writer));
    }
}

/// Wake the stream writing into `reader` if a read took its buffer from
/// `before` bytes, at or over its receive window, to below it.
pub(crate) fn wake_window_writer(reader: usize, before: usize) {
    if !TCP_POLICY_SET.load(Ordering::Acquire) {
        return;
    }
    let writer = {
        state!(
            policies = TcpPolicies ? HashMap::new();
            tcp = TcpConnections ? BTreeMap::new();
        );
        tcp.get(&reader).and_then(|c| {
            let window = policies.get(&c.local_addr)?.recv_window?;
            (before >= window && c.buffered() < window)
                .then_some(c.peer_stream_id)
                .flatten()
        })
    };
    if let Some(writer) = writer {
        wake(WaitKey::Stream(writer));
    }
}

pub(crate) fn tcp_policy(addr: SocketAddr) -> TcpPolicy {
    if !TCP_POLICY_SET.load(Ordering::Acquire) {
        return TcpPolicy::default();
    }
    state!(policies = TcpPolicies ? HashMap::new());
    policies.get(&addr).copied().unwrap_or_default()
}

/// Mutate the [`UdpPolicy`] for the socket bound at `addr`. The closure runs
/// against a default-initialized policy on first call.
pub fn set_udp_policy(addr: SocketAddr, policy_fn: impl FnOnce(&mut UdpPolicy)) {
    state!(policies = UdpPolicies ? HashMap::new());
    let entry = policies.entry(addr).or_default();
    policy_fn(entry);
    UDP_POLICY_SET.store(true, Ordering::Release);
}

pub(crate) fn udp_policy(addr: SocketAddr) -> UdpPolicy {
    if !UDP_POLICY_SET.load(Ordering::Acquire) {
        return UdpPolicy::default();
    }
    state!(policies = UdpPolicies ? HashMap::new());
    policies.get(&addr).copied().unwrap_or_default()
}

/// Configure how the listener bound at `addr` responds to new connects.
pub fn set_listener_behavior(addr: SocketAddr, behavior: ListenerBehavior) {
    {
        state!(behaviors = ListenerBehaviors ? HashMap::new());
        behaviors.insert(addr, behavior);
    }
    wake(WaitKey::Listener(addr));
}

pub(crate) fn listener_behavior(addr: SocketAddr) -> ListenerBehavior {
    state!(behaviors = ListenerBehaviors ? HashMap::new());
    behaviors
        .get(&addr)
        .copied()
        .unwrap_or(ListenerBehavior::Accepting)
}

// ----- Port introspection -----

/// Returns the SUT-side local addr of the connection whose peer is `peer_addr`.
/// Lets tests target the SUT's ephemeral port without sending a discovery packet.
pub fn peek_local_addr_for_peer(peer_addr: SocketAddr) -> Option<SocketAddr> {
    state!(tcp_connections = TcpConnections ? BTreeMap::new());
    tcp_connections
        .values()
        .find(|c| c.peer_addr == peer_addr && !c.is_destroyed)
        .map(|c| c.local_addr)
}

// ----- Recording -----

pub(crate) fn record(event: RecordedEvent) {
    let at = Instant::now();
    state!(log = RecordedEvents ? Vec::new());
    log.push(RecordedEntry { at, event });
}

/// Snapshot of the per-test event log, oldest first.
pub fn recorded_events() -> Vec<RecordedEntry> {
    state!(log = RecordedEvents ? Vec::new());
    log.clone()
}

/// Clear the per-test event log. Useful for scoping assertions to one phase.
pub fn clear_recorded_events() {
    state!(log = RecordedEvents ? Vec::new());
    log.clear();
}

// ----- RNG -----

static RNG_EPOCH: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);

const RNG_FALLBACK_SEED: u64 = 0xa5a5_a5a5_a5a5_a5a5;

/// Network RNG: one xorshift64 stream per `(source, destination)` flow, each
/// seeded from the slot seed and the flow's addresses. A draw on one flow
/// never moves another flow's stream, so sends made at the same instant on
/// different flows get the same draws whatever order their threads run in.
struct NetRng {
    seed: u64,
    flows: HashMap<(SocketAddr, SocketAddr), u64>,
}

impl NetRng {
    fn new(seed: u64) -> Self {
        Self {
            seed: if seed == 0 { RNG_FALLBACK_SEED } else { seed },
            flows: HashMap::new(),
        }
    }

    fn next(&mut self, src: SocketAddr, dst: SocketAddr) -> u32 {
        let seed = self.seed;
        let x = self
            .flows
            .entry((src, dst))
            .or_insert_with(|| flow_seed(seed, src, dst));
        *x ^= *x << 13;
        *x ^= *x >> 7;
        *x ^= *x << 17;
        (*x as u32) ^ ((*x >> 32) as u32)
    }
}

fn flow_seed(seed: u64, src: SocketAddr, dst: SocketAddr) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |bytes: &[u8]| {
        for b in bytes {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    };
    for addr in [src, dst] {
        match addr.ip() {
            IpAddr::V4(ip) => eat(&ip.octets()),
            IpAddr::V6(ip) => eat(&ip.octets()),
        }
        eat(&addr.port().to_be_bytes());
    }
    let mut z = (seed ^ h).wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    if z == 0 { RNG_FALLBACK_SEED } else { z }
}

/// A uniform draw in `[0, 1]` from the `src -> dst` flow's stream. Seeded
/// lazily from a process-wide monotonic epoch unless [`seed_rng`] ran first.
fn rand_unit(src: SocketAddr, dst: SocketAddr) -> f32 {
    state!(rng = RngState ? new_rng());
    rand_unit_locked(&mut rng, src, dst)
}

fn new_rng() -> NetRng {
    NetRng::new(RNG_EPOCH.elapsed().as_nanos() as u64)
}

fn rand_unit_locked(rng: &mut NetRng, src: SocketAddr, dst: SocketAddr) -> f32 {
    (rng.next(src, dst) as f32) / (u32::MAX as f32)
}

/// Loss, duplication and delay for one datagram under `policy`. Draws only
/// for the effects that are enabled, in the order loss, jitter, duplicate.
fn draw_link(
    rng: &mut NetRng,
    src: SocketAddr,
    dst: SocketAddr,
    loss_rate: f32,
    duplicate_rate: f32,
    jitter: Duration,
) -> (bool, Duration, bool) {
    if loss_rate > 0.0 && rand_unit_locked(rng, src, dst) < loss_rate {
        return (true, Duration::ZERO, false);
    }
    let jitter = if jitter.is_zero() {
        Duration::ZERO
    } else {
        Duration::from_nanos((rand_unit_locked(rng, src, dst) * jitter.as_nanos() as f32) as u64)
    };
    let duplicated = duplicate_rate > 0.0 && rand_unit_locked(rng, src, dst) < duplicate_rate;
    (false, jitter, duplicated)
}

/// Seed the per-test RNG used for UDP loss / duplicate / reorder, resetting
/// every flow's stream. Each `(source, destination)` flow draws from its own
/// stream derived from `seed`, so the outcome on one flow does not depend on
/// traffic on others or on thread order. Use for deterministic policy tests.
pub fn seed_rng(seed: u64) {
    state!(rng = RngState ? NetRng::new(seed));
    *rng = NetRng::new(seed);
}

// ----- Virtual clock (time-source shim) -----

type SchedSlotRef = Arc<SchedSlot>;

/// The current thread's scheduler slot (clock and timer heap). Hot paths go
/// through the thread-local cache in [`crate::sched`] instead.
pub(crate) fn sched_slot() -> Arc<SchedSlot> {
    state!(slot = SchedSlotRef ? Arc::new(SchedSlot::new()));
    Arc::clone(&slot)
}

type ThreadRegistryRef = Arc<crate::threads::ThreadRegistry>;

/// The current thread's state slot's thread registry.
pub(crate) fn thread_registry() -> Arc<crate::threads::ThreadRegistry> {
    state!(registry = ThreadRegistryRef ? Arc::default());
    Arc::clone(&registry)
}

#[cfg(feature = "ctrlc-compat")]
type CtrlcSlotRef = Arc<crate::ctrlc_shim::CtrlcSlot>;

/// The current thread's virtual Ctrl-C handler state.
#[cfg(feature = "ctrlc-compat")]
pub(crate) fn ctrlc_slot() -> Arc<crate::ctrlc_shim::CtrlcSlot> {
    state!(slot = CtrlcSlotRef ? Arc::default());
    Arc::clone(&slot)
}

#[cfg(feature = "fast-talker-core")]
type FtSlotRef = Arc<crate::fast_talker_shim::slot::FtSlot>;

/// The current thread's state slot's fast-talker state.
#[cfg(feature = "fast-talker-core")]
pub(crate) fn ft_slot() -> Arc<crate::fast_talker_shim::slot::FtSlot> {
    crate::fast_talker_shim::hooks::install();
    state!(slot = FtSlotRef ? Arc::default());
    Arc::clone(&slot)
}

/// Like [`sched_slot`], but `None` instead of a panic or a grace-period wait
/// when the calling thread has no state slot.
#[cfg(snare_global)]
pub(crate) fn try_sched_slot() -> Option<Arc<SchedSlot>> {
    Some(sched_slot())
}

#[cfg(not(snare_global))]
pub(crate) fn try_sched_slot() -> Option<Arc<SchedSlot>> {
    let id = std::thread::current().id();
    let root = {
        crate::sched::note_lock();
        let hierarchy = TEST_THREAD_HIERARCHY.lock();
        if hierarchy.contains_key(&id) {
            TestThreadId::resolve_from(&hierarchy, id)
        } else {
            drop(hierarchy);
            inherit_creator_slot(id)?
        }
    };
    let has_slot = {
        crate::sched::note_lock();
        TEST_STATE.lock().borrow().contains_key(&root)
    };
    has_slot.then(sched_slot)
}

/// Set how fast virtual time advances relative to real time: `1.0` tracks the
/// real clock, `0.0` pauses it (`Instant::now()` / `SystemTime::now()` stop
/// advancing), `>1.0` runs fast. Rates above `1e6` are clamped. Panics on a
/// negative or non-finite rate — a negative rate would violate the
/// monotonicity of `Instant::now()`. Ignored (with a one-time warning per call
/// site) while a [`sched::Driver`](crate::sched::Driver) owns the clock.
#[track_caller]
pub fn set_time_rate(rate: f64) {
    assert!(
        rate.is_finite() && rate >= 0.0,
        "time rate must be finite and non-negative (got {rate}); a negative \
         rate would break the monotonicity of Instant::now()"
    );
    let slot = crate::sched::slot();
    if slot.clock().set_rate(rate) {
        slot.timers().notify();
    } else {
        warn_driven("set_time_rate");
    }
}

/// The current virtual-time advance rate. See [`set_time_rate`].
pub fn time_rate() -> f64 {
    crate::sched::slot().clock().rate()
}

/// Freeze virtual time. Equivalent to `set_time_rate(0.0)`.
#[track_caller]
pub fn pause_time() {
    set_time_rate(0.0);
}

/// Resume virtual time at the rate it ran at before the last pause (`1.0` if
/// it was never paused). No-op if the clock is not paused.
#[track_caller]
pub fn resume_time() {
    let slot = crate::sched::slot();
    if slot.clock().resume() {
        slot.timers().notify();
    } else {
        warn_driven("resume_time");
    }
}

/// Set the clock's current value: the reading of `snare::time::Instant::now()`
/// measured from the virtual epoch, and the offset added to the wall base for
/// `SystemTime::now()`. Moving the value backwards breaks `Instant`
/// monotonicity, so only do it while the SUT holds no live `Instant`s.
#[track_caller]
pub fn set_time_value(value: Duration) {
    let slot = crate::sched::slot();
    let nanos = value.as_nanos().min(u64::MAX as u128) as u64;
    if slot.clock().set_value(nanos) {
        slot.timers().notify();
    } else {
        warn_driven("set_time_value");
    }
}

/// The clock's current value — the elapsed virtual time reported by
/// `snare::time::Instant::now()` since the virtual epoch.
pub fn time_value() -> Duration {
    crate::sched::mono_now()
}

/// Jump virtual time forward by `by`. Works regardless of rate, so it advances
/// the clock even while paused.
#[track_caller]
pub fn advance_time(by: Duration) {
    let slot = crate::sched::slot();
    let nanos = by.as_nanos().min(u64::MAX as u128) as u64;
    if slot.clock().advance(nanos) {
        slot.timers().notify();
    } else {
        warn_driven("advance_time");
    }
}

fn loopback_for(target: SocketAddr) -> IpAddr {
    match target {
        SocketAddr::V4(_) => IpAddr::from([127, 0, 0, 1]),
        SocketAddr::V6(_) => IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
    }
}

fn unspecified_for(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::from([0, 0, 0, 0]),
        IpAddr::V6(_) => IpAddr::from([0u16; 8]),
    }
}

fn port_taken(
    os: OsSemantics,
    udp: &UdpConnections,
    tcp: &TcpConnections,
    listeners: &TcpListeners,
    proto: Proto,
    addr: SocketAddr,
) -> bool {
    match proto {
        Proto::Udp => udp
            .iter()
            .filter(|c| c.live())
            .any(|c| bind_conflicts(os, c.bound_addr, addr)),
        Proto::Tcp => {
            listeners
                .values()
                .any(|l| bind_conflicts(os, l.bound_addr, addr))
                || tcp
                    .values()
                    .filter(|c| c.owns_port)
                    .any(|c| bind_conflicts(os, c.local_addr, addr))
        }
    }
}

fn reserve_legacy(ports: &mut LocalPortsUsed, next: &mut Next, ip: IpAddr) -> SocketAddr {
    loop {
        let mut port = next.1;
        if port == 0 {
            port = 40_000;
        }
        let addr = SocketAddr::new(ip, port);
        if ports.insert(addr) {
            next.1 = port.wrapping_add(1);
            break addr;
        }
        next.1 = port.wrapping_add(1);
    }
}

/// Choose the address a socket of `proto` binds when asked for `a`, and
/// reserve its port. `Err(None)` means the legacy rules skip `a` without
/// an error of its own.
#[allow(clippy::too_many_arguments)]
fn bind_port_locked(
    net: &mut NetModel,
    udp: &UdpConnections,
    tcp: &TcpConnections,
    listeners: &TcpListeners,
    ports: &mut LocalPortsUsed,
    next: &mut Next,
    proto: Proto,
    a: SocketAddr,
) -> Result<SocketAddr, Option<io::Error>> {
    let os = net.os;
    let faithful = net.faithful();
    let group = proto == Proto::Udp && a.ip().is_multicast();
    if group && os == OsSemantics::Windows {
        return Err(Some(os_err_for(os, Errno::AddrNotAvail)));
    }
    if !group && !net.is_ip_valid(a.ip()) {
        return Err(faithful.then(|| os_err_for(os, Errno::AddrNotAvail)));
    }
    if a.port() != 0
        && a.port() < 1024
        && os == OsSemantics::Linux
        && !(net.privileges.root || net.privileges.net_bind_service)
    {
        return Err(Some(os_err_for(os, Errno::Access)));
    }
    let bound = if faithful {
        if a.port() == 0 {
            let port = net
                .faithful_ephemeral(proto, |p| {
                    port_taken(os, udp, tcp, listeners, proto, SocketAddr::new(a.ip(), p))
                })
                .ok_or_else(|| Some(os_err_for(os, Errno::AddrInUse)))?;
            SocketAddr::new(a.ip(), port)
        } else if port_taken(os, udp, tcp, listeners, proto, a) {
            return Err(Some(os_err_for(os, Errno::AddrInUse)));
        } else {
            a
        }
    } else if a.port() == 0 {
        reserve_legacy(ports, next, a.ip())
    } else if !ports.contains(&a) {
        a
    } else if proto == Proto::Udp && a.ip().is_unspecified() {
        // A fixed local port chosen against the real OS (e.g. openport for a
        // Fanuc STMO client) is blind to the single global network, so two
        // in-process wildcard clients can pick the same port; a wildcard
        // client bind is free to move, so fall back to an ephemeral port.
        reserve_legacy(ports, next, a.ip())
    } else {
        return Err(None);
    };
    ports.insert(bound);
    Ok(bound)
}

/// Bind a UDP socket at `a`. `Err(None)`: skip to the caller's next address.
pub(crate) fn bind_udp(a: SocketAddr) -> Result<(SocketId, SocketAddr), Option<io::Error>> {
    #[cfg(feature = "fast-talker-core")]
    crate::fast_talker_shim::hooks::install();
    let now = Instant::now();
    state!(
        net = NetModel ? NetModel::default();
        udp = UdpConnections ? Vec::new();
        tcp = TcpConnections ? BTreeMap::new();
        listeners = TcpListeners ? BTreeMap::new();
        ports = LocalPortsUsed ? HashSet::new();
        next = Next ? DEFAULT_NEXT;
    );
    let bound = bind_port_locked(
        &mut net,
        &udp,
        &tcp,
        &listeners,
        &mut ports,
        &mut next,
        Proto::Udp,
        a,
    )?;
    let id = net.next_socket_id();
    udp.push(UdpConnection::new(id, bound, now));
    Ok((id, bound))
}

/// Bind a TCP listener at `a`. `Err(None)`: skip to the caller's next
/// address.
pub(crate) fn bind_tcp_listener(
    a: SocketAddr,
) -> Result<(SocketId, SocketAddr), Option<io::Error>> {
    #[cfg(feature = "fast-talker-core")]
    crate::fast_talker_shim::hooks::install();
    let now = Instant::now();
    state!(
        net = NetModel ? NetModel::default();
        udp = UdpConnections ? Vec::new();
        tcp = TcpConnections ? BTreeMap::new();
        listeners = TcpListeners ? BTreeMap::new();
        ports = LocalPortsUsed ? HashSet::new();
        next = Next ? DEFAULT_NEXT;
    );
    let bound = bind_port_locked(
        &mut net,
        &udp,
        &tcp,
        &listeners,
        &mut ports,
        &mut next,
        Proto::Tcp,
        a,
    )?;
    let id = net.next_socket_id();
    listeners.insert(bound, new_listener(id, bound, now));
    Ok((id, bound))
}

fn new_listener(id: SocketId, addr: SocketAddr, now: Instant) -> TcpListenerState {
    TcpListenerState {
        id,
        bound_addr: addr,
        pending_streams: VecDeque::new(),
        nonblocking: false,
        ttl: 64,
        error: None,
        is_closed: false,
        ref_count: 1,
        bound_device: None,
        created_at: now,
        #[cfg(feature = "fast-talker-core")]
        ft: Default::default(),
    }
}

pub(crate) fn add_tcp_connection(
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    owns_port: bool,
    nic: Option<NicId>,
    listener: Option<SocketId>,
) -> (usize, SocketId) {
    #[cfg(feature = "fast-talker-core")]
    crate::fast_talker_shim::hooks::install();
    let now = Instant::now();
    state!(
        net = NetModel ? NetModel::default();
        tcp_connections = TcpConnections ? BTreeMap::new();
        local_ports_used = LocalPortsUsed ? HashSet::new();
        next = Next ? DEFAULT_NEXT;
    );
    if owns_port {
        local_ports_used.insert(local_addr);
    }
    let stream_id = next.0;
    next.0 += 1;
    let id = net.next_socket_id();
    tcp_connections.insert(
        stream_id,
        TcpConnection {
            id,
            stream_id,
            local_addr,
            peer_addr,
            incoming: VecDeque::new(),
            arrivals: VecDeque::new(),
            pending_inbound: VecDeque::new(),
            stalled: VecDeque::new(),
            read_shutdown: false,
            write_shutdown: false,
            failure_queue: Vec::new(),
            external_error: None,
            peer_stream_id: None,
            nonblocking: false,
            nodelay: false,
            ttl: 64,
            linger: None,
            read_timeout: None,
            write_timeout: None,
            ref_count: 1,
            owns_port,
            is_destroyed: false,
            reset_pending: false,
            write_blocks: 0,
            peer_close: PeerClose::Open,
            nic,
            listener,
            bound_device: None,
            rcvbuf: None,
            sndbuf: None,
            delivered: 0,
            created_at: now,
            #[cfg(feature = "fast-talker-core")]
            ft: Default::default(),
        },
    );
    (stream_id, id)
}

/// Run `func` on the UDP socket `id`. Panics if it is gone.
pub(crate) fn with_udp_socket<T, F: FnOnce(&mut UdpConnection) -> T>(id: SocketId, func: F) -> T {
    state!(udp = UdpConnections ? Vec::new());
    match udp.iter_mut().find(|c| c.id == id && c.live()) {
        Some(conn) => func(conn),
        None => panic!("No UDP socket with id {}", id.get()),
    }
}

/// Forget the UDP socket `id` once its last handle is gone: free its port,
/// discard what it had queued and move it to the closed-socket history.
/// Datagrams it sent to virtual testers stay deliverable.
pub(crate) fn drop_udp_socket(id: SocketId) {
    if crate::sched::try_slot().is_none() {
        return;
    }
    let now = Instant::now();
    state!(
        net = NetModel ? NetModel::default();
        udp = UdpConnections ? Vec::new();
        ports = LocalPortsUsed ? HashSet::new();
    );
    if let Some(c) = udp.iter_mut().find(|c| c.id == id && c.live()) {
        c.dropped = true;
        c.closed_at = Some(now);
        c.to_local.clear();
        c.pending_inbound.clear();
        c.queued_bytes = 0;
        ports.remove(&c.bound_addr);
        let entry = udp_entry(&net, c);
        net.history.push(entry);
    }
    udp.retain(|c| c.live() || !c.from_local.is_empty());
}

/// A datagram taken off a UDP socket's receive queue.
#[derive(Debug)]
pub(crate) struct RxPacket {
    pub data: Vec<u8>,
    pub source: SocketAddr,
    /// When it reached the socket.
    pub at: Instant,
    pub drops_at_enqueue: u32,
    pub ingress: Option<NicId>,
}

/// Take (or with `consume == false`, copy) the next datagram of the UDP
/// socket `id`, optionally only one from `source`. Releases datagrams whose
/// delivery instant has passed first.
pub(crate) fn udp_take(
    id: SocketId,
    source: Option<SocketAddr>,
    consume: bool,
) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
    Ok(udp_take_packet(id, source, consume)?.map(|p| (p.data, p.source)))
}

/// [`udp_take`], with the datagram's arrival metadata.
pub(crate) fn udp_take_packet(
    id: SocketId,
    source: Option<SocketAddr>,
    consume: bool,
) -> io::Result<Option<RxPacket>> {
    let now = Instant::now();
    state!(
        net = NetModel ? NetModel::default();
        udp = UdpConnections ? Vec::new();
    );
    let Some(conn) = udp.iter_mut().find(|c| c.id == id && c.live()) else {
        panic!("No UDP socket with id {}", id.get());
    };
    release_due_locked(&mut net, conn, now);
    if conn.is_destroyed {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "connection destroyed",
        ));
    }
    if let Some(e) = conn.take_icmp(now) {
        return Err(os_err_for(net.os, e));
    }
    let idx = match source {
        Some(addr) => conn.to_local.iter().position(|pkt| pkt.source == addr),
        None => (!conn.to_local.is_empty()).then_some(0),
    };
    let Some(idx) = idx else {
        return Ok(None);
    };
    let meta = |pkt: &Packet, data: Vec<u8>| RxPacket {
        data,
        source: pkt.source,
        at: pkt.at,
        drops_at_enqueue: pkt.drops_at_enqueue,
        ingress: pkt.ingress,
    };
    if consume {
        Ok(conn.take_local(idx).map(|mut pkt| {
            net.udp_stats_mut(&pkt.dest).read += 1;
            let data = std::mem::take(&mut pkt.data);
            meta(&pkt, data)
        }))
    } else {
        Ok(conn
            .to_local
            .get(idx)
            .map(|pkt| meta(pkt, pkt.data.clone())))
    }
}

/// Connect the UDP socket `id` to `addr`, surfacing routing errors.
pub(crate) fn udp_connect(id: SocketId, addr: SocketAddr) -> io::Result<()> {
    with_net(|ctx| {
        let net = &*ctx.net;
        let Some(conn) = ctx.udp.iter_mut().find(|c| c.id == id && c.live()) else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no such UDP socket",
            ));
        };
        let dst = dual_stack_dst(net, conn.bound_addr, addr).ip();
        net.select_egress(&conn.view(net, dst), dst)
            .map_err(|e| os_err_for(net.os, e))?;
        conn.connected = Some(addr);
        Ok(())
    })
}

/// The interface a TCP connection to `target` runs over, and the client's
/// local IP.
pub(crate) fn tcp_connect_plan(target: SocketAddr) -> io::Result<(Option<NicId>, IpAddr)> {
    with_net(|ctx| {
        let net = &*ctx.net;
        let dst = target.ip();
        let unspecified = unspecified_for(dst);
        let view = SockView {
            local_ip: unspecified,
            bound_device: None,
            multicast_if: None,
            strong_host: false,
        };
        let (egress, route_src) = net
            .select_egress(&view, dst)
            .map_err(|e| os_err_for(net.os, e))?;
        let nic = net.ingress_for(dst, Some(egress));
        let legacy = if net.is_ip_valid(dst) {
            dst
        } else {
            loopback_for(target)
        };
        let client_ip = if net.modern(dst) || net.modern_source(egress) {
            net.select_source(unspecified, dst, egress, route_src)
                .unwrap_or(legacy)
        } else {
            legacy
        };
        Ok((nic, client_ip))
    })
}

/// What a SYN to a port with no listener meets.
pub(crate) enum SynFate {
    /// The host owns the address and answers with RST.
    Refused,
    /// Nothing answers: the SYN is retransmitted until the OS gives up.
    Silent,
}

/// What a TCP connect to `target` meets when no listener takes it, or the
/// routing error that stops it before a SYN is sent.
pub(crate) fn tcp_syn_fate(target: SocketAddr) -> io::Result<SynFate> {
    with_net(|ctx| {
        let net = &*ctx.net;
        let dst = target.ip();
        if dst.is_unspecified() || net.owner_of(dst).is_some() {
            return Ok(SynFate::Refused);
        }
        let view = SockView {
            local_ip: unspecified_for(dst),
            bound_device: None,
            multicast_if: None,
            strong_host: false,
        };
        net.select_egress(&view, dst)
            .map_err(|e| os_err_for(net.os, e))?;
        Ok(SynFate::Silent)
    })
}

/// Mark the peer's read side closed, if the peer is still around.
///
/// A peer that has already gone needs no telling: telling the other end about a
/// close is only meaningful while there *is* another end. See
/// [`notify_peer_dropped`] for why that absence must not panic.
pub(crate) fn mark_peer_read_shutdown(peer_id: usize) {
    mutate_tcp_connection(peer_id, |peer_state| {
        peer_state.read_shutdown = true;
    });
}

/// Run `func` on the connection. Does not wake anyone: callers that change
/// what a waiter on this stream is waiting for follow up with
/// [`wake`]`(WaitKey::Stream(stream_id))`, or use [`mutate_tcp_connection`].
pub(crate) fn with_tcp_connection<T, F: FnOnce(&mut TcpConnection) -> T>(
    stream_id: usize,
    func: F,
) -> T {
    state!(tcp_connections = TcpConnections ? BTreeMap::new());
    let connection = tcp_connections.get_mut(&stream_id);
    if let Some(conn) = connection {
        func(conn)
    } else {
        panic!("No connection found for stream id: {}", stream_id);
    }
}

/// Like [`with_tcp_connection`] but returns `None` when the connection has already
/// been removed instead of panicking. Callers on the hot path (socket read/write)
/// use this so a peer that closed/dropped its end surfaces as a graceful
/// `ConnectionReset`, matching a real socket, rather than panicking a driver's
/// I/O thread.
pub(crate) fn try_with_tcp_connection<T, F: FnOnce(&mut TcpConnection) -> T>(
    stream_id: usize,
    func: F,
) -> Option<T> {
    state!(tcp_connections = TcpConnections ? BTreeMap::new());
    tcp_connections.get_mut(&stream_id).map(func)
}

/// [`try_with_tcp_connection`], then wake the stream's waiters if the
/// connection still existed.
pub(crate) fn mutate_tcp_connection<T, F: FnOnce(&mut TcpConnection) -> T>(
    stream_id: usize,
    func: F,
) -> Option<T> {
    let ret = try_with_tcp_connection(stream_id, func);
    if ret.is_some() {
        wake(WaitKey::Stream(stream_id));
    }
    ret
}

pub(crate) fn remove_tcp_connection(stream_id: usize) -> Option<TcpConnection> {
    let now = Instant::now();
    let removed = {
        state!(
            net = NetModel ? NetModel::default();
            tcp_connections = TcpConnections ? BTreeMap::new();
            local_ports_used = LocalPortsUsed ? HashSet::new();
        );
        let conn = tcp_connections.remove(&stream_id);
        if let Some(conn) = &conn {
            if conn.owns_port {
                local_ports_used.remove(&conn.local_addr);
            }
            let mut entry = tcp_entry(&net, conn);
            entry.closed = true;
            entry.closed_at = Some(now);
            net.history.push(entry);
        }
        conn
    };
    if removed.is_some() {
        wake(WaitKey::Stream(stream_id));
    }
    removed
}

/// Register a listener for a virtual tester at `addr`, taking the port
/// unconditionally.
pub(crate) fn add_tcp_listener_state(addr: SocketAddr) {
    let now = Instant::now();
    state!(
        net = NetModel ? NetModel::default();
        tcp_listeners = TcpListeners ? BTreeMap::new();
        local_ports_used = LocalPortsUsed ? HashSet::new();
    );
    local_ports_used.insert(addr);
    let id = net.next_socket_id();
    tcp_listeners.insert(addr, new_listener(id, addr, now));
}

pub(crate) fn remove_tcp_listener_state(addr: SocketAddr) -> Option<TcpListenerState> {
    let now = Instant::now();
    let removed = {
        state!(
            net = NetModel ? NetModel::default();
            tcp_listeners = TcpListeners ? BTreeMap::new();
            local_ports_used = LocalPortsUsed ? HashSet::new();
        );
        let listener = tcp_listeners.get_mut(&addr)?;
        if listener.ref_count > 1 {
            listener.ref_count -= 1;
            return None;
        }
        let state = tcp_listeners.remove(&addr);
        if let Some(l) = &state {
            local_ports_used.remove(&addr);
            let mut entry = listener_entry(&net, l);
            entry.closed = true;
            entry.closed_at = Some(now);
            net.history.push(entry);
        }
        state
    };
    wake(WaitKey::Listener(addr));
    removed
}

pub(crate) fn clone_tcp_listener_state(addr: SocketAddr) -> io::Result<()> {
    with_tcp_listener_state(addr, |listener| {
        listener.ref_count += 1;
    });
    Ok(())
}

pub(crate) fn with_tcp_listener_state<T, F: FnOnce(&mut TcpListenerState) -> T>(
    addr: SocketAddr,
    func: F,
) -> T {
    state!(tcp_listeners = TcpListeners ? BTreeMap::new());
    let listener = tcp_listeners.get_mut(&addr);
    if let Some(listener) = listener {
        func(listener)
    } else {
        panic!("No listener found for address: {}", addr);
    }
}

pub(crate) fn find_tcp_listener(target: SocketAddr) -> Option<SocketAddr> {
    state!(
        net = NetModel ? NetModel::default();
        tcp_listeners = TcpListeners ? BTreeMap::new();
    );
    if !net.modern(target.ip()) {
        if tcp_listeners.contains_key(&target) {
            return Some(target);
        }
        return tcp_listeners
            .keys()
            .find(|addr| addr.port() == target.port() && addr.ip().is_unspecified())
            .copied();
    }
    let ingress = net.owner_id(target.ip());
    let device_ok = |l: &TcpListenerState| l.bound_device.is_none_or(|d| Some(d) == ingress);
    if let Some(l) = tcp_listeners.get(&target)
        && device_ok(l)
    {
        return Some(target);
    }
    tcp_listeners
        .values()
        .filter(|l| {
            l.bound_addr.port() == target.port()
                && l.bound_addr.ip().is_unspecified()
                && l.bound_addr.is_ipv4() == target.is_ipv4()
                && device_ok(l)
        })
        .max_by_key(|l| l.id)
        .map(|l| l.bound_addr)
}

pub(crate) fn assign_tcp_stream_to_listener(listener_addr: SocketAddr, stream_id: usize) {
    with_tcp_listener_state(listener_addr, |listener| {
        listener.pending_streams.push_back(stream_id);
    });
    wake(WaitKey::Listener(listener_addr));
}

/// Reserve an ephemeral port on `ip` for a TCP client.
pub(crate) fn reserve_ephemeral_addr(ip: IpAddr) -> io::Result<SocketAddr> {
    state!(
        net = NetModel ? NetModel::default();
        udp = UdpConnections ? Vec::new();
        tcp = TcpConnections ? BTreeMap::new();
        listeners = TcpListeners ? BTreeMap::new();
        local_ports_used = LocalPortsUsed ? HashSet::new();
        next = Next ? DEFAULT_NEXT
    );
    if !net.faithful() {
        return Ok(reserve_legacy(&mut local_ports_used, &mut next, ip));
    }
    let os = net.os;
    let port = net
        .faithful_ephemeral(Proto::Tcp, |p| {
            port_taken(
                os,
                &udp,
                &tcp,
                &listeners,
                Proto::Tcp,
                SocketAddr::new(ip, p),
            )
        })
        .ok_or_else(|| os_err_for(os, Errno::AddrInUse))?;
    let addr = SocketAddr::new(ip, port);
    local_ports_used.insert(addr);
    Ok(addr)
}

/// Run `func` on the live UDP socket bound at `binded_addr`. Panics if none.
pub(crate) fn with_udp_connection<T, F: FnOnce(&mut UdpConnection) -> T>(
    binded_addr: SocketAddr,
    func: F,
) -> T {
    state!(udp_connection = UdpConnections ? Vec::new());
    let connection = udp_connection
        .iter_mut()
        .find(|conn| conn.live() && conn.bound_addr == binded_addr);
    if let Some(conn) = connection {
        func(conn)
    } else {
        panic!("No connection found for address: {}", binded_addr);
    }
}

/// Drop one reference to `stream_id`, returning its peer's id if that was the
/// last one. `None` when the stream is already gone — a listener dropping
/// unaccepted streams ([`crate::shim_std_tcp`]'s `cleanup_unaccepted_stream`)
/// can remove a connection out from under an owner that still holds a handle to
/// it, and that owner's eventual drop is not a bug.
pub(crate) fn release_stream(stream_id: usize) -> Option<usize> {
    try_with_tcp_connection(stream_id, |conn| {
        if conn.ref_count > 1 {
            conn.ref_count -= 1;
            return None;
        }
        Some(())
    })??;
    if let Some(conn) = remove_tcp_connection(stream_id) {
        conn.peer_stream_id
    } else {
        None
    }
}

/// Tell the peer its other end went away, if the peer is still there.
///
/// Must not panic on a missing peer: this runs from `ShimStdTcpStream::drop`,
/// and when both ends of a connection drop at once — a driver hanging up on a
/// handshake socket exactly as the server hangs up its own end, which is the
/// shape of every real reconnect — each end finds the other already gone. That
/// is the normal outcome of a symmetric close, and panicking on it takes out
/// whichever thread happened to run its destructor second.
///
/// Under faithful semantics this is a graceful close: the peer reads EOF,
/// and its writes follow the FIN-then-RST sequence (see
/// [`PeerClose::Fin`]) instead of raising an error at once.
pub(crate) fn notify_peer_dropped(peer_id: usize) {
    let faithful = os_ctx().1;
    mutate_tcp_connection(peer_id, |peer| {
        peer.peer_stream_id = None;
        peer.read_shutdown = true;
        if faithful {
            if peer.peer_close == PeerClose::Open {
                peer.peer_close = PeerClose::Fin;
            }
        } else {
            peer.external_error = Some(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "peer disconnected",
            ));
        }
    });
}

/// Tell the peer its other end aborted the connection with a RST: its next
/// read or write reports `ECONNRESET` as `os` does. A no-op if the peer is
/// gone.
pub(crate) fn notify_peer_reset(peer_id: usize, os: OsSemantics) {
    mutate_tcp_connection(peer_id, |peer| {
        peer.peer_stream_id = None;
        peer.read_shutdown = true;
        peer.reset_pending = true;
        peer.external_error = Some(os_err_for(os, Errno::ConnReset));
    });
}

/// The live UDP socket that receives a datagram from `src` to `dst`
/// arriving on `ingress`. Legacy destinations match the bound address
/// exactly; modern ones prefer a socket connected to `src`, then an exact
/// bind, then a wildcard bind on an address the host owns, newest first.
fn find_udp_dest(
    net: &NetModel,
    udp: &UdpConnections,
    src: SocketAddr,
    dst: SocketAddr,
    ingress: Option<NicId>,
) -> Option<usize> {
    if !net.modern(dst.ip()) {
        return udp.iter().position(|c| c.live() && c.bound_addr == dst);
    }
    let eligible = |c: &UdpConnection| {
        c.live() && !c.is_destroyed && c.bound_device.is_none_or(|d| Some(d) == ingress)
    };
    let score = |c: &UdpConnection| match c.connected {
        Some(peer) if dual_stack_dst(net, c.bound_addr, peer) == src => 2,
        None => 1,
        Some(_) => 0,
    };
    let best = |pred: &dyn Fn(&UdpConnection) -> bool| {
        udp.iter()
            .enumerate()
            .filter(|(_, c)| eligible(c) && pred(c))
            .max_by_key(|(_, c)| (score(c), c.id))
            .map(|(i, _)| i)
    };
    let wildcard = |c: &UdpConnection, v4: bool| {
        c.bound_addr.ip().is_unspecified()
            && c.bound_addr.port() == dst.port()
            && c.bound_addr.is_ipv4() == v4
    };
    best(&|c| c.bound_addr == dst).or_else(|| {
        net.owner_of(dst.ip())?;
        best(&|c| wildcard(c, dst.is_ipv4())).or_else(|| {
            (dst.is_ipv4() && dual_stack(net))
                .then(|| best(&|c| wildcard(c, false)))
                .flatten()
        })
    })
}

/// Whether an IPv6 socket bound to `[::]` also takes IPv4 traffic, as
/// v4-mapped addresses: `IPV6_V6ONLY` is off by default on Linux and macOS,
/// on on Windows.
fn dual_stack(net: &NetModel) -> bool {
    net.faithful() && net.os != OsSemantics::Windows
}

/// Where a datagram from the socket bound at `bound` to `dst` goes: a
/// dual-stack IPv6 socket reaches a v4-mapped address over IPv4.
fn dual_stack_dst(net: &NetModel, bound: SocketAddr, dst: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = dst
        && bound.is_ipv6()
        && dual_stack(net)
        && let Some(v4) = v6.ip().to_ipv4_mapped()
    {
        return SocketAddr::new(IpAddr::V4(v4), v6.port());
    }
    dst
}

/// `src` as the socket bound at `bound` sees it: v4-mapped on an IPv6
/// socket.
fn seen_from(bound: SocketAddr, src: SocketAddr) -> SocketAddr {
    match (bound, src) {
        (SocketAddr::V6(_), SocketAddr::V4(v4)) => {
            SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
        }
        _ => src,
    }
}

/// Put a datagram that has reached `conn` on its receive queue, enforcing
/// the receive buffer and counting it on its ingress interface.
fn deliver_locked(net: &mut NetModel, conn: &mut UdpConnection, mut pkt: Packet) {
    if !net.nic_up(pkt.ingress) {
        return;
    }
    let len = pkt.data.len();
    if let Some(cap) = rcvbuf_cap(net, conn.rcvbuf) {
        let over = match net.os {
            OsSemantics::Linux => {
                conn.queued_bytes + conn.to_local.len() * net.limits.per_datagram_overhead > cap
            }
            _ => conn.queued_bytes + len > cap,
        };
        if over {
            conn.drops = conn.drops.wrapping_add(1);
            conn.overflowed += 1;
            if let Some(c) = net.counters_mut(pkt.ingress) {
                c.rx_dropped += 1;
            }
            let stats = net.udp_stats_mut(&pkt.dest);
            stats.rcvbuf_errors += 1;
            stats.in_errors += 1;
            return;
        }
    }
    pkt.drops_at_enqueue = conn.drops;
    if pkt.counts_on_nic
        && let Some(c) = net.counters_mut(pkt.ingress)
    {
        c.rx_packets += 1;
        c.rx_bytes += len as u64;
        if pkt.dest.ip().is_multicast() {
            c.multicast += 1;
        }
    }
    net.udp_stats_mut(&pkt.dest).queued += 1;
    conn.queued_bytes += len;
    conn.delivered += 1;
    if pkt.ingress.is_some() {
        conn.last_rx_nic = pkt.ingress;
    }
    #[cfg(feature = "fast-talker-core")]
    if let Some(ingress) = pkt.ingress
        && (conn.connected.is_some() || conn.ft.rx_flow.is_none())
    {
        conn.ft.rx_flow = Some((pkt.source, pkt.dest, ingress));
    }
    conn.to_local.push_back(pkt);
}

/// Deliver every in-flight datagram of `conn` whose instant has come.
pub(crate) fn release_due_locked(
    net: &mut NetModel,
    conn: &mut UdpConnection,
    now: Instant,
) -> bool {
    let mut released = false;
    while conn.pending_inbound.front().is_some_and(|p| p.at <= now) {
        let pkt = conn.pending_inbound.pop_front().expect("front checked");
        deliver_locked(net, conn, pkt);
        released = true;
    }
    released
}

/// Hand `copies` datagrams to `conn`, arriving at `at`. `count_nic` counts
/// the frame on its ingress interface.
#[allow(clippy::too_many_arguments)]
fn schedule_locked(
    net: &mut NetModel,
    conn: &mut UdpConnection,
    data: &[u8],
    src: SocketAddr,
    dst: SocketAddr,
    ingress: Option<NicId>,
    now: Instant,
    at: Instant,
    copies: usize,
    count_nic: bool,
) -> Wake {
    let due = at <= now;
    if due {
        release_due_locked(net, conn, now);
    }
    let src = seen_from(conn.bound_addr, src);
    for _ in 0..copies {
        let mut pkt = Packet::new(data.to_vec(), dst, src, at);
        pkt.ingress = ingress;
        pkt.seq = net.next_seq();
        pkt.counts_on_nic = count_nic;
        if due {
            deliver_locked(net, conn, pkt);
        } else {
            conn.insert_pending(pkt);
        }
    }
    Wake::when(at, now, WaitKey::Udp(conn.bound_addr))
}

enum Wake {
    None,
    Now(WaitKey),
    At(Instant, WaitKey),
}

impl Wake {
    /// Wake `key` at `at`, or at once if `at` has come.
    fn when(at: Instant, now: Instant, key: WaitKey) -> Self {
        if at <= now {
            Wake::Now(key)
        } else {
            Wake::At(at, key)
        }
    }

    fn fire(self) {
        match self {
            Wake::None => {}
            Wake::Now(key) => wake(key),
            Wake::At(at, key) => wake_at(at, key),
        }
    }
}

fn wire_loss_locked(net: &mut NetModel, conn: &mut UdpConnection, ingress: Option<NicId>) {
    if let Some(c) = net.counters_mut(ingress) {
        c.rx_dropped += 1;
    }
    let accounting = net.limits.drop_accounting;
    conn.charge_wire_loss(accounting);
}

pub(crate) fn send_udp_from_test(from_addr: SocketAddr, to_addr: SocketAddr, data: Vec<u8>) {
    let policy = udp_policy(to_addr);
    let len = data.len();
    let now = Instant::now();

    // MTU rejection: oversize datagram is silently dropped on the wire.
    if let Some(mtu) = policy.mtu
        && data.len() > mtu
    {
        record(RecordedEvent::UdpSendFromTest {
            from: from_addr,
            to: to_addr,
            len,
            dropped: true,
            duplicated: false,
        });
        return;
    }

    enum Outcome {
        Lost,
        NoSocket,
        Delivered(Vec<Wake>, bool, WireTap),
    }

    let outcome = {
        state!(
            net = NetModel ? NetModel::default();
            udp = UdpConnections ? Vec::new();
            rng = RngState ? new_rng();
        );
        let (lost, jitter, duplicated) = draw_link(
            &mut rng,
            from_addr,
            to_addr,
            policy.loss_rate,
            policy.duplicate_rate,
            policy.reorder_jitter,
        );
        let fan = crate::mcast::tester_fan_out(&net, &udp, from_addr, to_addr);
        let ingress = match &fan {
            Some((_, ingress)) => *ingress,
            None => net
                .owner_id(to_addr.ip())
                .or_else(|| net.default_nic().map(|n| n.id)),
        };
        let tap_of = |net: &NetModel| {
            (
                now,
                ingress
                    .and_then(|id| net.nic_by_id(id))
                    .map(|n| (n.id.0, n.spec.name.clone())),
            )
        };
        if let Some((targets, _)) = fan {
            if targets.is_empty() {
                Outcome::NoSocket
            } else if lost {
                for &di in &targets {
                    wire_loss_locked(&mut net, &mut udp[di], ingress);
                }
                Outcome::Lost
            } else {
                let wire = now + policy.inbound_latency + jitter;
                let mut wakes = Vec::new();
                for _ in 0..if duplicated { 2 } else { 1 } {
                    wakes.extend(fan_out_locked(
                        &mut net,
                        &mut udp,
                        &mut rng,
                        &targets,
                        &data,
                        (from_addr, to_addr),
                        ingress,
                        now,
                        wire,
                    ));
                }
                Outcome::Delivered(wakes, duplicated, tap_of(&net))
            }
        } else {
            // Soft-fail if the destination UDP socket isn't bound yet (matches
            // real wire — UDP send to a non-existent listener is silently
            // dropped). This avoids panicking the tester loop when there's a race
            // between the SUT calling `bind` and the tester firing its first
            // cyclic send.
            match find_udp_dest(&net, &udp, from_addr, to_addr, ingress) {
                Some(di) if lost => {
                    wire_loss_locked(&mut net, &mut udp[di], ingress);
                    Outcome::Lost
                }
                None if lost => Outcome::Lost,
                None => {
                    if net.icmp_answers(to_addr.ip()) && net.nic_up(ingress) {
                        net.udp_stats_mut(&to_addr).no_ports += 1;
                    }
                    Outcome::NoSocket
                }
                Some(_) if !net.nic_up(ingress) => Outcome::Lost,
                Some(_) if net.flow_drops(ingress, from_addr, to_addr) => Outcome::Lost,
                Some(di) => {
                    let nic = net.policy_of(ingress);
                    let (nic_lost, nic_jitter, nic_dup) = draw_link(
                        &mut rng,
                        from_addr,
                        to_addr,
                        nic.loss_rate,
                        nic.duplicate_rate,
                        nic.jitter,
                    );
                    if nic_lost {
                        wire_loss_locked(&mut net, &mut udp[di], ingress);
                        Outcome::Lost
                    } else {
                        let duplicated = duplicated || nic_dup;
                        let delay = policy.inbound_latency + jitter + nic.latency + nic_jitter;
                        let wake = schedule_locked(
                            &mut net,
                            &mut udp[di],
                            &data,
                            from_addr,
                            to_addr,
                            ingress,
                            now,
                            now + delay,
                            if duplicated { 2 } else { 1 },
                            true,
                        );
                        Outcome::Delivered(vec![wake], duplicated, tap_of(&net))
                    }
                }
            }
        }
    };

    match outcome {
        Outcome::NoSocket => {}
        Outcome::Lost => record(RecordedEvent::UdpSendFromTest {
            from: from_addr,
            to: to_addr,
            len,
            dropped: true,
            duplicated: false,
        }),
        Outcome::Delivered(wakes, duplicated, tap) => {
            for wake in wakes {
                wake.fire();
            }
            record(RecordedEvent::UdpSendFromTest {
                from: from_addr,
                to: to_addr,
                len,
                dropped: false,
                duplicated,
            });
            pcap_udp_on(&tap, from_addr, to_addr, &data);
            if duplicated {
                pcap_udp_on(&tap, from_addr, to_addr, &data);
            }
        }
    }
}

/// Inject a UDP datagram as if `from_addr` had sent it to the SUT socket
/// bound at `to_addr`. Honors the socket's [`UdpPolicy`] (loss, duplicate,
/// latency, jitter, MTU) and the receiving interface's link policy;
/// soft-fails if nothing is bound at `to_addr`.
pub fn inject_udp_from_test(from_addr: SocketAddr, to_addr: SocketAddr, data: Vec<u8>) {
    send_udp_from_test(from_addr, to_addr, data);
}

/// Deliver an ICMP port unreachable to the UDP sockets bound at `to`, as if
/// a datagram they sent to `from` had found no socket there. A socket
/// connected to `from` gets `ECONNREFUSED` on its next receive or send
/// (`WSAECONNRESET` on its next receive under Windows semantics); under
/// Windows semantics an unconnected socket gets `WSAECONNRESET` on its next
/// receive and polls readable until then. Linux and macOS ignore it on an
/// unconnected socket. Sockets bound to the wildcard address on `to`'s port
/// count when an interface owns `to`.
pub fn inject_icmp_port_unreachable(to: SocketAddr, from: SocketAddr) {
    let now = Instant::now();
    let hit: Vec<SocketAddr> = {
        state!(
            net = NetModel ? NetModel::default();
            udp = UdpConnections ? Vec::new();
        );
        let owned = net.owner_of(to.ip()).is_some();
        let os = net.os;
        udp.iter_mut()
            .filter(|c| c.live() && !c.is_destroyed)
            .filter(|c| {
                c.bound_addr == to
                    || (owned
                        && c.bound_addr.ip().is_unspecified()
                        && c.bound_addr.port() == to.port()
                        && c.bound_addr.is_ipv4() == to.is_ipv4())
            })
            .filter_map(|c| {
                c.icmp_port_unreachable(os, from, now)
                    .then_some(c.bound_addr)
            })
            .collect()
    };
    for addr in hit {
        wake(WaitKey::Udp(addr));
    }
}

/// Inject a TCP chunk as if `from_addr` had sent it to the SUT at `to_addr`.
/// Honors latency / recv_window / other policies; soft-fails if the SUT has
/// already disconnected.
pub fn inject_tcp_from_test(from_addr: SocketAddr, to_addr: SocketAddr, data: Vec<u8>) {
    send_tcp_from_test(from_addr, to_addr, data);
}

/// How a TCP chunk joined its receiver.
pub(crate) enum Pushed {
    Now,
    At(Instant),
    Stalled,
}

/// Queue `data` into `conn` after `base` latency plus its interface's
/// latency and jitter; held back while the interface is down.
fn push_chunk_locked(
    net: &NetModel,
    rng: &mut NetRng,
    conn: &mut TcpConnection,
    src: SocketAddr,
    data: Vec<u8>,
    base: Duration,
    now: Instant,
) -> Pushed {
    if !net.nic_up(conn.nic) || !conn.stalled.is_empty() {
        conn.stalled.push_back(data);
        return Pushed::Stalled;
    }
    let nic = net.policy_of(conn.nic);
    let jitter = if nic.jitter.is_zero() {
        Duration::ZERO
    } else {
        Duration::from_nanos(
            (rand_unit_locked(rng, src, conn.local_addr) * nic.jitter.as_nanos() as f32) as u64,
        )
    };
    let total = base + nic.latency + jitter;
    if total.is_zero() && conn.pending_inbound.is_empty() {
        conn.append_incoming(now, data);
        Pushed::Now
    } else {
        Pushed::At(conn.push_pending(now + total, data))
    }
}

/// Write the head of `data` from `src` into the stream `peer_id`, as much
/// as its receive window has room for, honouring its read shutdown, latency
/// and interface. Returns how the bytes joined and how many were taken;
/// `None` if the peer is gone.
pub(crate) fn tcp_push_chunk(
    peer_id: usize,
    src: SocketAddr,
    data: &[u8],
) -> Option<io::Result<(Pushed, usize)>> {
    let now = Instant::now();
    let (pushed, resumed) = {
        state!(
            net = NetModel ? NetModel::default();
            tcp = TcpConnections ? BTreeMap::new();
            rng = RngState ? new_rng();
            policies = TcpPolicies ? HashMap::new();
        );
        let resumed = resume_flapped_locked(&net, &mut tcp, peer_id, now);
        let pushed = (|| {
            let peer = tcp.get_mut(&peer_id)?;
            if peer.read_shutdown {
                return Some(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "peer closed the read half",
                )));
            }
            let policy = policies.get(&peer.local_addr).copied().unwrap_or_default();
            let take = peer.room(policy.recv_window).min(data.len());
            if take == 0 {
                return Some(Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "peer recv window full",
                )));
            }
            let pushed = push_chunk_locked(
                &net,
                &mut rng,
                peer,
                src,
                data[..take].to_vec(),
                policy.inbound_latency,
                now,
            );
            Some(Ok((pushed, take)))
        })();
        (pushed, resumed)
    };
    wake_stalled(resumed);
    pushed
}

pub(crate) fn send_tcp_from_test(from_addr: SocketAddr, to_addr: SocketAddr, data: Vec<u8>) {
    let policy = tcp_policy(to_addr);
    let len = data.len();
    let now = Instant::now();
    // Pcap path is opt-in; clone once up front (cheap vs. the I/O cost of
    // tests, only used by the pcap tap below).
    let data_for_pcap = data.clone();

    let mut resumed = Vec::new();
    let outcome: Option<(usize, Option<Pushed>)> = {
        state!(
            net = NetModel ? NetModel::default();
            tcp_connections = TcpConnections ? BTreeMap::new();
            rng = RngState ? new_rng();
        );
        let target = tcp_connections
            .values()
            .find(|conn| conn.local_addr == to_addr && conn.peer_addr == from_addr)
            .map(|conn| conn.stream_id);
        if let Some(id) = target {
            resumed = resume_flapped_locked(&net, &mut tcp_connections, id, now);
        }
        let connection = target.and_then(|id| tcp_connections.get_mut(&id));
        connection.map(|conn| {
            let accepted = match policy.recv_window {
                // Soft-drop on a stalled receive window. Test code that
                // cares can inspect the recv-window via policy.
                Some(window) => conn.buffered() + data.len() <= window,
                None => true,
            };
            let pushed = accepted.then(|| {
                push_chunk_locked(
                    &net,
                    &mut rng,
                    conn,
                    from_addr,
                    data,
                    policy.inbound_latency,
                    now,
                )
            });
            (conn.stream_id, pushed)
        })
    };
    wake_stalled(resumed);
    // `None`: soft-fail, the SUT dropped the connection before delivery. Real
    // wire would silently discard or surface RST; treat as a no-op here
    // rather than panicking and killing the tester loop.
    if let Some((stream_id, Some(pushed))) = outcome {
        match pushed {
            Pushed::Now => wake(WaitKey::Stream(stream_id)),
            Pushed::At(at) => wake_at(at, WaitKey::Stream(stream_id)),
            Pushed::Stalled => {}
        }
        record(RecordedEvent::TcpSendFromTest {
            from: from_addr,
            to: to_addr,
            len,
        });
        pcap_tcp_data(from_addr, to_addr, &data_for_pcap);
    }
}

/// Re-queue the chunks stalled on `nic`'s connections now that its link is
/// back, arriving after its latency. Returns the streams to wake and when.
pub(crate) fn resume_stalled_locked(
    tcp: &mut TcpConnections,
    net: &NetModel,
    nic: NicId,
    now: Instant,
) -> Vec<(usize, Instant)> {
    let latency = net.policy_of(Some(nic)).latency;
    let mut wakes = Vec::new();
    let mut senders = Vec::new();
    for conn in tcp
        .values_mut()
        .filter(|c| c.nic == Some(nic) && !c.stalled.is_empty())
    {
        let mut last = now;
        while let Some(chunk) = conn.stalled.pop_front() {
            last = conn.push_pending(now + latency, chunk);
        }
        wakes.push((conn.stream_id, last));
        senders.extend(conn.peer_stream_id.map(|p| (p, last)));
    }
    #[cfg(feature = "fast-talker-core")]
    for (sender, arrival) in senders {
        if let Some(at) = crate::fast_talker_shim::tcp::ack_held(tcp, net, sender, arrival) {
            wakes.push((sender, at));
        }
    }
    wakes
}

pub(crate) fn wake_stalled(wakes: Vec<(usize, Instant)>) {
    for (stream_id, at) in wakes {
        wake(WaitKey::Stream(stream_id));
        wake_at(at, WaitKey::Stream(stream_id));
    }
}

/// Move expired pending-inbound chunks of `stream_id` into `incoming`. The
/// waiters were already woken by the release timer; this only makes the
/// bytes visible to whoever looks next.
pub(crate) fn release_pending_for_stream(stream_id: usize) -> bool {
    let now = Instant::now();
    let (released, resumed) = {
        state!(
            net = NetModel ? NetModel::default();
            tcp_connections = TcpConnections ? BTreeMap::new();
        );
        release_stream_locked(&net, &mut tcp_connections, stream_id, now)
    };
    wake_stalled(resumed);
    released
}

/// [`release_pending_for_stream`] under the caller's lock scope. The
/// returned wakes are for [`wake_stalled`] once the scope ends.
fn release_stream_locked(
    net: &NetModel,
    tcp: &mut TcpConnections,
    stream_id: usize,
    now: Instant,
) -> (bool, Vec<(usize, Instant)>) {
    let resumed = resume_flapped_locked(net, tcp, stream_id, now);
    let mut released = false;
    if let Some(conn) = tcp.get_mut(&stream_id) {
        while let Some((deadline, _)) = conn.pending_inbound.front() {
            if *deadline > now {
                break;
            }
            let (at, data) = conn.pending_inbound.pop_front().unwrap();
            conn.append_incoming(at, data);
            released = true;
        }
    }
    (released, resumed)
}

/// Re-queue the bytes of `stream_id` held on an interface whose Windows
/// adapter restart is over, as if its link had come back when the restart
/// ended.
fn resume_flapped_locked(
    net: &NetModel,
    tcp: &mut TcpConnections,
    stream_id: usize,
    now: Instant,
) -> Vec<(usize, Instant)> {
    let Some(nic) = tcp
        .get(&stream_id)
        .filter(|c| !c.stalled.is_empty())
        .and_then(|c| c.nic)
    else {
        return Vec::new();
    };
    let Some(n) = net.nic_by_id(nic) else {
        return Vec::new();
    };
    let end = n.flap_end();
    if !n.spec.link_up || end.is_some_and(|end| now < end) {
        return Vec::new();
    }
    let at = end.map_or(now, |end| end.min(now));
    resume_stalled_locked(tcp, net, nic, at)
}

pub(crate) fn release_pending_for_udp(addr: SocketAddr) -> bool {
    let now = Instant::now();
    state!(
        net = NetModel ? NetModel::default();
        udp_connections = UdpConnections ? Vec::new();
    );
    match udp_connections
        .iter_mut()
        .find(|c| c.live() && c.bound_addr == addr)
    {
        Some(conn) => release_due_locked(&mut net, conn, now),
        None => false,
    }
}

/// Earliest pending-release deadline across all connections; the run loop
/// caps its sleep at this so delayed bytes surface on schedule.
pub(crate) fn earliest_pending_release() -> Option<Instant> {
    let mut earliest: Option<Instant> = None;
    {
        state!(tcp_connections = TcpConnections ? BTreeMap::new());
        for conn in tcp_connections.values() {
            if let Some((d, _)) = conn.pending_inbound.front() {
                earliest = Some(earliest.map_or(*d, |e| e.min(*d)));
            }
        }
    }
    {
        let now = Instant::now();
        state!(udp_connections = UdpConnections ? Vec::new());
        for conn in udp_connections.iter() {
            let tester = conn.from_local.iter().map(|p| p.at).filter(|&at| at > now);
            for at in conn
                .pending_inbound
                .front()
                .map(|p| p.at)
                .into_iter()
                .chain(tester)
            {
                earliest = Some(earliest.map_or(at, |e| e.min(at)));
            }
        }
    }
    earliest
}

/// Mark the TCP connection bound at `addr` as RST. The next read/write returns
/// `ECONNRESET`. Distinct from a clean close: this is the synchronous form of
/// [`TesterAction::ResetTcp`](crate::TesterAction::ResetTcp).
pub fn reset_tcp(addr: SocketAddr) {
    reset_tcp_from_test(addr);
}

/// Mark a TCP connection as RST (matched by SUT-side local addr).
pub(crate) fn reset_tcp_from_test(addr: SocketAddr) {
    let (os, faithful) = os_ctx();
    let hit = {
        state!(tcp_connections = TcpConnections ? BTreeMap::new());
        if let Some(conn) = tcp_connections.values_mut().find(|c| c.local_addr == addr) {
            conn.reset_pending = true;
            conn.read_shutdown = true;
            conn.external_error = Some(if faithful {
                os_err_for(os, Errno::ConnReset)
            } else {
                io::Error::new(io::ErrorKind::ConnectionReset, "connection reset by peer")
            });
            Some((conn.stream_id, conn.peer_addr))
        } else {
            None
        }
    };
    if let Some((stream_id, peer_addr)) = hit {
        wake(WaitKey::Stream(stream_id));
        record(RecordedEvent::TcpResetFromTest { addr });
        // RST is sourced from the test-side peer, since `reset_tcp_from_test`
        // is the "the remote side just sent a RST" path.
        pcap_tcp_rst(peer_addr, addr);
    }
}

pub(crate) fn raise_udp_socket_error_from_test(addr: SocketAddr, err: io::Error) {
    let hit = {
        state!(udp_connections = UdpConnections ? Vec::new());
        udp_connections
            .iter_mut()
            .find(|conn| conn.live() && conn.bound_addr == addr)
            .map(|conn| conn.external_error = Some(err))
            .is_some()
    };
    // Soft-fail: socket not bound yet / already gone. Match wire semantics.
    if hit {
        wake(WaitKey::Udp(addr));
    }
}

pub(crate) fn raise_tcp_socket_error_from_test(addr: SocketAddr, err: io::Error) {
    let hit = {
        state!(tcp_connections = TcpConnections ? BTreeMap::new());
        tcp_connections
            .values_mut()
            .find(|conn| conn.local_addr == addr)
            .map(|conn| {
                conn.external_error = Some(err);
                conn.stream_id
            })
    };
    // Soft-fail.
    if let Some(stream_id) = hit {
        wake(WaitKey::Stream(stream_id));
    }
}

pub(crate) fn close_socket_from_test(addr: SocketAddr, socket_type: SocketType) {
    match socket_type {
        SocketType::Udp => {
            let found = {
                state!(udp_connections = UdpConnections ? Vec::new());
                udp_connections
                    .iter_mut()
                    .find(|c| c.live() && c.bound_addr == addr)
                    .map(|conn| conn.is_destroyed = true)
                    .is_some()
            };
            // Soft-fail if the socket isn't bound (not yet, or already gone).
            if found {
                wake(WaitKey::Udp(addr));
                record(RecordedEvent::UdpCloseFromTest { addr });
            }
        }
        SocketType::Tcp => {
            let found = {
                state!(tcp_connections = TcpConnections ? BTreeMap::new());
                tcp_connections
                    .values_mut()
                    .find(|c| c.local_addr == addr)
                    .map(|conn| {
                        conn.is_destroyed = true;
                        conn.stream_id
                    })
            };
            // Soft-fail.
            if let Some(stream_id) = found {
                wake(WaitKey::Stream(stream_id));
                record(RecordedEvent::TcpCloseFromTest { addr });
            }
        }
    }
}

/// How a send through fast-talker's `Timestamped` differs from a plain one.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct FtSend {
    /// Sent through `Timestamped`, so the library's own transmit log sees it.
    pub via_ft: bool,
    /// The time a timed send asked to leave at.
    pub timed: Option<Timed>,
}

/// The time a timed send asked to leave at.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timed {
    /// On the virtual clock; `None` when it is before the clock's epoch.
    pub at: Option<Instant>,
    pub requested: std::time::SystemTime,
}

/// What a send did.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UdpSent {
    pub len: usize,
    /// The transmit stamp id the send was given.
    pub tx_id: Option<u32>,
    /// A timed send went out at once: no ETF qdisc on its interface.
    pub etf_ignored: bool,
}

/// SUT-outbound UDP send from socket `id` to `dst`. Checks the socket's
/// [`UdpPolicy`] (`InvalidInput` over MTU, `WouldBlock` on a full send
/// queue) and, for the selected OS, the datagram size, the route and
/// broadcast permission. A datagram to a bound socket goes through the
/// receiving interface's link policy into that socket; one to anything else
/// waits in `from_local` for a virtual tester.
pub(crate) fn udp_send(
    id: SocketId,
    bound_addr: SocketAddr,
    data: &[u8],
    dst: SocketAddr,
    broadcast_ok: bool,
) -> io::Result<usize> {
    udp_send_ex(id, bound_addr, data, dst, broadcast_ok, FtSend::default()).map(|s| s.len)
}

/// [`udp_send`], with fast-talker's transmit stamps and timed sends. A
/// timed send leaves at its launch instant: its datagram, capture and
/// stamp all carry that instant.
pub(crate) fn udp_send_ex(
    id: SocketId,
    bound_addr: SocketAddr,
    data: &[u8],
    dst: SocketAddr,
    broadcast_ok: bool,
    ft: FtSend,
) -> io::Result<UdpSent> {
    let now = Instant::now();
    let key = WaitKey::Udp(bound_addr);
    let mut wakes = Vec::new();
    let (tap, source, dst, sent) = {
        state!(
            net = NetModel ? NetModel::default();
            udp = UdpConnections ? Vec::new();
            rng = RngState ? new_rng();
            policies = UdpPolicies ? HashMap::new();
        );
        let policy = policies.get(&bound_addr).copied().unwrap_or_default();
        let os = net.os;
        let faithful = net.faithful();
        let sender_idx = udp
            .iter()
            .position(|c| c.id == id && c.live())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no such UDP socket"))?;
        let dst = dual_stack_dst(&net, udp[sender_idx].bound_addr, dst);
        if udp[sender_idx].is_destroyed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection destroyed",
            ));
        }
        if os != OsSemantics::Windows
            && let Some(e) = udp[sender_idx].take_icmp(now)
        {
            return Err(os_err_for(os, e));
        }
        if let Some(mtu) = policy.mtu
            && data.len() > mtu
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram exceeds configured MTU",
            ));
        }
        if let Some(cap) = policy.send_queue_depth
            && udp[sender_idx].from_local.len() >= cap
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "UDP send queue full",
            ));
        }
        if faithful {
            let max = if dst.is_ipv4() { 65_507 } else { 65_527 };
            let dgram_cap = match os {
                OsSemantics::MacOs => net.limits.udp_max_dgram,
                _ => None,
            };
            if data.len() > max || dgram_cap.is_some_and(|m| data.len() > m) {
                return Err(os_err_for(os, Errno::MsgSize));
            }
        }
        let sender = &udp[sender_idx];
        let local_ip = sender.bound_addr.ip();
        let (egress, route_src) = net
            .select_egress(&sender.view(&net, dst.ip()), dst.ip())
            .map_err(|e| os_err_for(os, e))?;
        if faithful && !broadcast_ok && net.is_broadcast(dst.ip()) {
            return Err(os_err_for(os, Errno::Access));
        }
        if sender.dont_fragment {
            let header = if dst.is_ipv4() { 28 } else { 48 };
            let mtu = net.nic_by_id(egress).map_or(u32::MAX, |n| n.spec.mtu) as usize;
            if data.len() + header > mtu {
                return Err(os_err_for(os, Errno::MsgSize));
            }
        }
        let source_ip = if net.modern_source(egress) {
            net.select_source(local_ip, dst.ip(), egress, route_src)
                .unwrap_or(local_ip)
        } else {
            local_ip
        };
        let source_ip = if source_ip.is_ipv4() == dst.is_ipv4() {
            source_ip
        } else {
            unspecified_for(dst.ip())
        };
        let source = SocketAddr::new(source_ip, sender.bound_addr.port());

        #[cfg(feature = "fast-talker-core")]
        let (wire, on_wire, tx_id, etf_ignored) = {
            use crate::fast_talker_shim::socket::{TimedFate, on_send, timed_fate};
            let ft_state = &mut udp[sender_idx].ft;
            let (wire, on_wire, etf_ignored) =
                match timed_fate(&net, ft_state, egress, ft.timed, now) {
                    TimedFate::Now => (now, true, false),
                    TimedFate::At(at) => (at, true, false),
                    TimedFate::Ignored => (now, true, true),
                    TimedFate::Dropped(visible) => {
                        wakes.push(Wake::when(visible, now, key));
                        (now, false, false)
                    }
                };
            let (tx_id, stamp_at) = on_send(&net, ft_state, egress, wire, now, ft.via_ft, on_wire);
            if let Some(at) = stamp_at {
                wakes.push(Wake::when(at, now, key));
            }
            (wire, on_wire, tx_id, etf_ignored)
        };
        #[cfg(not(feature = "fast-talker-core"))]
        let (wire, on_wire, tx_id, etf_ignored) = {
            let _ = ft;
            (now, true, None, false)
        };
        let sent = UdpSent {
            len: data.len(),
            tx_id,
            etf_ignored,
        };
        let tap = on_wire.then(|| {
            let nic = net.nic_by_id(egress).map(|n| (n.id.0, n.spec.name.clone()));
            (wire, nic)
        });
        if on_wire {
            net.udp_stats_mut(&dst).out += 1;
            if let Some(c) = net.counters_mut(Some(egress)) {
                c.tx_packets += 1;
                c.tx_bytes += data.len() as u64;
            }
            udp[sender_idx].last_tx_nic = Some(egress);
            let ingress = net.ingress_for(dst.ip(), Some(egress));
            // If a socket is bound at the destination, deliver straight into its
            // inbound queue — this is what lets two real in-process sockets (e.g.
            // a driver and a raw emulated device under `snare_global`) exchange
            // datagrams without the tester framework pumping `from_local`.
            // Virtual testers don't bind a UDP socket, so they fall through to
            // `from_local` and are still served by `pop_latest_packet`.
            let fan = crate::mcast::fan_out(&net, &udp, Some(sender_idx), source, dst, ingress);
            let wake_on = match fan {
                Some(targets) if !targets.is_empty() => {
                    wakes.extend(fan_out_locked(
                        &mut net,
                        &mut udp,
                        &mut rng,
                        &targets,
                        data,
                        (source, dst),
                        ingress,
                        now,
                        wire,
                    ));
                    Wake::None
                }
                Some(_) => to_testers(&mut udp[sender_idx], data, source, dst, now, wire),
                None => match find_udp_dest(&net, &udp, source, dst, ingress) {
                    Some(_) if !net.nic_up(ingress) => Wake::None,
                    Some(_) if net.flow_drops(ingress, source, dst) => Wake::None,
                    Some(di) => {
                        let nic = net.policy_of(ingress);
                        let (lost, jitter, duplicated) = draw_link(
                            &mut rng,
                            source,
                            dst,
                            nic.loss_rate,
                            nic.duplicate_rate,
                            nic.jitter,
                        );
                        if lost {
                            wire_loss_locked(&mut net, &mut udp[di], ingress);
                            Wake::None
                        } else {
                            schedule_locked(
                                &mut net,
                                &mut udp[di],
                                data,
                                source,
                                dst,
                                ingress,
                                now,
                                wire + nic.latency + jitter,
                                if duplicated { 2 } else { 1 },
                                true,
                            )
                        }
                    }
                    None if net.icmp_answers(dst.ip()) && net.nic_up(ingress) => {
                        net.udp_stats_mut(&dst).no_ports += 1;
                        let back = net.ingress_for(source.ip(), Some(egress));
                        let at =
                            wire + net.policy_of(ingress).latency + net.policy_of(back).latency;
                        if udp[sender_idx].icmp_port_unreachable(os, dst, at) {
                            Wake::At(at, key)
                        } else {
                            Wake::None
                        }
                    }
                    None => to_testers(&mut udp[sender_idx], data, source, dst, now, wire),
                },
            };
            wakes.push(wake_on);
        }
        (tap, source, dst, sent)
    };
    for w in wakes {
        w.fire();
    }
    if let Some(tap) = tap {
        pcap_udp_on(&tap, source, dst, data);
    }
    Ok(sent)
}

/// Leave a datagram from `conn` for the virtual tester at `dst`, reaching it
/// at `wire`.
fn to_testers(
    conn: &mut UdpConnection,
    data: &[u8],
    source: SocketAddr,
    dst: SocketAddr,
    now: Instant,
    wire: Instant,
) -> Wake {
    conn.from_local
        .push_back(Packet::new(data.to_vec(), dst, source, wire));
    Wake::when(wire, now, WaitKey::Udp(conn.bound_addr))
}

/// Deliver one group or broadcast frame from `flow.0` to `flow.1`, leaving
/// at `wire`, to every socket in `targets` over the interface `ingress`.
/// The interface's loss, duplication and jitter are drawn once per frame.
#[allow(clippy::too_many_arguments)]
fn fan_out_locked(
    net: &mut NetModel,
    udp: &mut UdpConnections,
    rng: &mut NetRng,
    targets: &[usize],
    data: &[u8],
    flow: (SocketAddr, SocketAddr),
    ingress: Option<NicId>,
    now: Instant,
    wire: Instant,
) -> Vec<Wake> {
    let (src, dst) = flow;
    if !net.nic_up(ingress) || net.flow_drops(ingress, src, dst) {
        return Vec::new();
    }
    let nic = net.policy_of(ingress);
    let (lost, jitter, duplicated) =
        draw_link(rng, src, dst, nic.loss_rate, nic.duplicate_rate, nic.jitter);
    if lost {
        if let Some(c) = net.counters_mut(ingress) {
            c.rx_dropped += 1;
        }
        let accounting = net.limits.drop_accounting;
        for &di in targets {
            udp[di].charge_wire_loss(accounting);
        }
        return Vec::new();
    }
    targets
        .iter()
        .enumerate()
        .map(|(n, &di)| {
            schedule_locked(
                net,
                &mut udp[di],
                data,
                src,
                dst,
                ingress,
                now,
                wire + nic.latency + jitter,
                if duplicated { 2 } else { 1 },
                n == 0,
            )
        })
        .collect()
}

/// Take the earliest datagram sent to the virtual tester at `addr` that has
/// reached it. A timed send reaches it at its launch instant.
pub(crate) fn pop_latest_packet(addr: SocketAddr) -> Option<Packet> {
    let now = Instant::now();
    state!(udp_connections = UdpConnections ? Vec::new());
    let (ci, pi) = udp_connections
        .iter()
        .enumerate()
        .flat_map(|(ci, conn)| {
            conn.from_local
                .iter()
                .enumerate()
                .filter(|(_, pkt)| pkt.dest == addr && pkt.at <= now)
                .map(move |(pi, pkt)| ((pkt.at, ci, pi), (ci, pi)))
        })
        .min_by_key(|(k, _)| *k)
        .map(|(_, v)| v)?;
    let found = udp_connections[ci].from_local.remove(pi);
    udp_connections.retain(|c| c.live() || !c.from_local.is_empty());
    found
}

pub(crate) fn has_pending_udp_packet(addr: SocketAddr) -> bool {
    let now = Instant::now();
    state!(udp_connections = UdpConnections ? Vec::new());
    udp_connections.iter().any(|conn| {
        conn.from_local
            .iter()
            .any(|pkt| pkt.dest == addr && pkt.at <= now)
    })
}

pub(crate) fn has_pending_tcp_data(addr: SocketAddr) -> bool {
    state!(tcp_connections = TcpConnections ? BTreeMap::new());
    tcp_connections
        .values()
        .any(|conn| conn.local_addr == addr && !conn.incoming.is_empty())
}

pub(crate) struct TcpListenerStatus {
    pub pending: bool,
    pub error: bool,
    pub closed: bool,
}

pub(crate) struct TcpStreamStatus {
    pub readable: bool,
    pub writable: bool,
    pub error: bool,
    pub read_closed: bool,
    pub write_closed: bool,
    pub write_blocks: u64,
}

pub(crate) struct UdpSocketStatus {
    pub readable: bool,
    pub writable: bool,
    pub error: bool,
    pub closed: bool,
}

pub(crate) fn tcp_listener_status(addr: SocketAddr) -> Option<TcpListenerStatus> {
    state!(tcp_listeners = TcpListeners ? BTreeMap::new());
    let listener = tcp_listeners.get(&addr)?;
    Some(TcpListenerStatus {
        pending: !listener.pending_streams.is_empty(),
        error: listener.error.is_some(),
        closed: listener.is_closed,
    })
}

pub(crate) fn tcp_stream_status(stream_id: usize) -> Option<TcpStreamStatus> {
    let now = Instant::now();
    let (status, resumed) = {
        state!(
            net = NetModel ? NetModel::default();
            tcp_connections = TcpConnections ? BTreeMap::new();
            policies = TcpPolicies ? HashMap::new();
            quiesce = Quiescence ? HashMap::new();
        );
        // Latency-released bytes move into `incoming` first, so the readiness
        // reflects the post-deadline state.
        let (_, resumed) = release_stream_locked(&net, &mut tcp_connections, stream_id, now);
        let status = tcp_connections.get(&stream_id).map(|conn| {
            let quiesced = quiesced_dirs(&mut quiesce, conn.local_addr, now);
            stream_status_locked(&net, &tcp_connections, &policies, conn, quiesced, now)
        });
        (status, resumed)
    };
    wake_stalled(resumed);
    status
}

fn stream_status_locked(
    net: &NetModel,
    tcp_connections: &TcpConnections,
    policies: &TcpPolicies,
    conn: &TcpConnection,
    (inbound_quiesced, outbound_quiesced): (bool, bool),
    now: Instant,
) -> TcpStreamStatus {
    let read_closed = conn.read_shutdown || conn.peer_stream_id.is_none() || conn.is_destroyed;
    let write_closed = conn.write_shutdown || conn.is_destroyed;
    let raw_readable = !conn.incoming.is_empty();
    let peer_writable =
        conn.peer_stream_id.is_some() || (net.faithful() && conn.peer_close != PeerClose::Open);
    let peer_room = conn
        .peer_stream_id
        .and_then(|p| tcp_connections.get(&p))
        .is_none_or(|p| {
            let window = policies.get(&p.local_addr).and_then(|x| x.recv_window);
            p.room(window) > 0
        });
    let raw_writable = !write_closed && peer_writable && peer_room;
    #[cfg(feature = "fast-talker-core")]
    let tx_events = conn.ft.error_ready(now);
    #[cfg(not(feature = "fast-talker-core"))]
    let tx_events = {
        let _ = now;
        false
    };
    TcpStreamStatus {
        readable: raw_readable && !inbound_quiesced,
        writable: raw_writable && !outbound_quiesced,
        error: conn.external_error.is_some() || tx_events,
        read_closed,
        write_closed,
        write_blocks: conn.write_blocks,
    }
}

pub(crate) fn udp_socket_status(addr: SocketAddr) -> Option<UdpSocketStatus> {
    let now = Instant::now();
    state!(
        net = NetModel ? NetModel::default();
        udp_connections = UdpConnections ? Vec::new();
        quiesce = Quiescence ? HashMap::new();
    );
    let (inbound_quiesced, outbound_quiesced) = quiesced_dirs(&mut quiesce, addr, now);
    let conn = udp_connections
        .iter_mut()
        .find(|conn| conn.live() && conn.bound_addr == addr)?;
    release_due_locked(&mut net, conn, now);
    let conn = &*conn;
    let closed = conn.is_destroyed;
    let icmp = conn.icmp_visible(now);
    let icmp_readable = icmp && net.os == OsSemantics::Windows;
    #[cfg(feature = "fast-talker-core")]
    let errq = conn.ft.error_ready(now);
    #[cfg(not(feature = "fast-talker-core"))]
    let errq = false;
    Some(UdpSocketStatus {
        readable: (!conn.to_local.is_empty() || icmp_readable) && !inbound_quiesced,
        writable: !closed && !outbound_quiesced,
        error: conn.external_error.is_some() || icmp || errq,
        closed,
    })
}

/// `SO_ERROR` for the UDP socket `id`: an error the test raised, else an
/// arrived ICMP error, which Windows reports only through the next receive.
pub(crate) fn udp_take_error(id: SocketId) -> io::Result<Option<io::Error>> {
    let now = Instant::now();
    state!(
        net = NetModel ? NetModel::default();
        udp = UdpConnections ? Vec::new();
    );
    let Some(conn) = udp.iter_mut().find(|c| c.id == id && c.live()) else {
        panic!("No UDP socket with id {}", id.get());
    };
    if let Some(e) = conn.external_error.take() {
        return Ok(Some(e));
    }
    if net.os == OsSemantics::Windows {
        return Ok(None);
    }
    Ok(conn.take_icmp(now).map(|e| os_err_for(net.os, e)))
}

pub(crate) fn tcp_connection_peer_addr(local_addr: SocketAddr) -> Option<SocketAddr> {
    state!(tcp_connections = TcpConnections ? BTreeMap::new());
    tcp_connections
        .values()
        .find(|conn| conn.local_addr == local_addr)
        .map(|conn| conn.peer_addr)
}

pub(crate) fn peek_tcp_stream_data(addr: SocketAddr) -> Vec<u8> {
    state!(tcp_connections = TcpConnections ? BTreeMap::new());
    let connection = tcp_connections
        .values_mut()
        .find(|conn| conn.local_addr == addr);
    if let Some(conn) = connection {
        conn.incoming.iter().copied().collect()
    } else {
        Vec::new()
    }
}

pub(crate) fn consume_tcp_stream_data(addr: SocketAddr, amount: usize) {
    let consumed = {
        state!(tcp_connections = TcpConnections ? BTreeMap::new());
        tcp_connections
            .values_mut()
            .find(|conn| conn.local_addr == addr)
            .map(|conn| {
                let before = conn.buffered();
                conn.discard_incoming(amount);
                (conn.stream_id, before)
            })
    };
    if let Some((stream_id, before)) = consumed {
        wake(WaitKey::Stream(stream_id));
        wake_window_writer(stream_id, before);
    }
}
