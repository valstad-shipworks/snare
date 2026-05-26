#![allow(dead_code)]

use std::{
    cell::RefCell, collections::{HashMap, HashSet, VecDeque}, io, net::{IpAddr, SocketAddr}, sync::{Arc, LazyLock}, thread::ThreadId, time::{Duration, Instant}, u32
};

use anymap2::SendSyncAnyMap as AnyMap;
use event_listener::{Event, Listener};
use parking_lot::{Mutex, ReentrantMutex};

use crate::SocketType;
use crate::pcapng::PcapWriter;

/// Maps every test/child thread to its oldest known test-thread ancestor.
static TEST_THREAD_HIERARCHY: LazyLock<Mutex<HashMap<ThreadId, ThreadId>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Per-test state slots, keyed by the root test thread.
static TEST_STATE: LazyLock<ReentrantMutex<RefCell<HashMap<TestThreadId, AnyMap>>>> = LazyLock::new(|| ReentrantMutex::new(RefCell::new(HashMap::new())));

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct TestThreadId(ThreadId);

impl TestThreadId {
    fn of(id: ThreadId) -> Self {
        // Fast path: already registered.
        {
            let hierarchy = TEST_THREAD_HIERARCHY.lock();
            if hierarchy.contains_key(&id) {
                return Self::resolve_from(&hierarchy, id);
            }
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
        hierarchy: &parking_lot::lock_api::MutexGuard<'_, parking_lot::RawMutex, HashMap<ThreadId, ThreadId>>,
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

    fn current() -> Self {
        Self::of(std::thread::current().id())
    }
}

/// Mark the current thread as the root of a fresh per-test state slot. Call
/// at the top of every `#[test]` that uses snare.
pub fn register_test() {
    let thread_id = std::thread::current().id();
    let thread_name = std::thread::current().name().map(String::from);
    let mut map = TEST_THREAD_HIERARCHY.lock();
    map.insert(thread_id, thread_id);
    drop(map);
    let test_thread_id = TestThreadId(thread_id);
    TEST_STATE.lock().borrow_mut().insert(test_thread_id, AnyMap::new());

    // pcap init is in a helper defined after the `state!` macro.
    pcap_init_for_test(thread_name);
}

/// Attach a spawned thread to the current test's state slot. Call from the
/// parent right after `std::thread::spawn(...)` (or use [`ThreadExt::register_as_child`](crate::ThreadExt::register_as_child)).
pub fn register_child_thread(child_thread_id: ThreadId) {
    let test_thread_id = TestThreadId::current();
    TEST_THREAD_HIERARCHY.lock().insert(child_thread_id, test_thread_id.0);
}

/// Variant of [`register_child_thread`] called from inside the spawned thread,
/// naming its parent's `ThreadId`.
pub fn register_thread_child_of(parent_thread_id: ThreadId) {
    let child_thread_id = std::thread::current().id();
    TEST_THREAD_HIERARCHY.lock().insert(child_thread_id, parent_thread_id);
}

/// Begin pcapng capture for the current test. No-op unless `SNARE_PCAPNG_DIR`
/// is set in the environment. Already-enabled tests are unaffected.
pub fn enable_pcapng() {
    pcap_enable_for_current_test();
}

macro_rules! state {
    ( $( $var:ident = $idx:ident $(? $default:expr)? );* $(;)? ) => {
        let mut __guard = TEST_STATE.lock();
        let mut __borrow = __guard.borrow_mut();
        let mut __any_map = __borrow.get_mut(&TestThreadId::current())
            .expect("Not a valid test thread");
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

type TcpConnections = HashMap<usize, TcpConnection>;
type TcpListeners = HashMap<SocketAddr, TcpListenerState>;
type UdpConnections = Vec<UdpConnection>;
type LocalPortsUsed = HashSet<u16>;
type ValidIpAddrs = HashSet<IpAddr>;
type Next = (usize, u16);
type NewDataEvent = Arc<Event>;
type Quiescence = HashMap<SocketAddr, QuiesceEntry>;
type TcpPolicies = HashMap<SocketAddr, TcpPolicy>;
type UdpPolicies = HashMap<SocketAddr, UdpPolicy>;
type ListenerBehaviors = HashMap<SocketAddr, ListenerBehavior>;
type RecordedEvents = Vec<RecordedEntry>;
type RngState = u64;

pub(crate) struct PcapState {
    pub writer: Option<PcapWriter>,
    pub test_name: Option<String>,
}

impl Default for PcapState {
    fn default() -> Self {
        Self { writer: None, test_name: None }
    }
}

fn pcap_init_for_test(thread_name: Option<String>) {
    state!(pcap = PcapState ? PcapState::default());
    pcap.test_name = thread_name.clone();
    if let Some(name) = thread_name.as_deref() {
        if crate::pcapng::env_force_match(name) {
            pcap.writer = crate::pcapng::open_writer(name);
        }
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
    }
}

#[inline]
fn with_pcap<F: FnOnce(&mut PcapWriter)>(f: F) {
    state!(pcap = PcapState ? PcapState::default());
    if let Some(w) = pcap.writer.as_mut() {
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

pub(crate) fn pcap_udp(src: SocketAddr, dst: SocketAddr, data: &[u8]) {
    with_pcap(|w| w.udp_datagram(src, dst, data));
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
    TcpSendFromTest { from: SocketAddr, to: SocketAddr, len: usize },
    TcpResetFromTest { addr: SocketAddr },
    TcpCloseFromTest { addr: SocketAddr },
    UdpSendFromTest { from: SocketAddr, to: SocketAddr, len: usize, dropped: bool, duplicated: bool },
    UdpCloseFromTest { addr: SocketAddr },
    Quiesce { addr: SocketAddr, dur: Duration, mode: QuiesceMode },
    SocketErrorFromTest { addr: SocketAddr, kind: io::ErrorKind },
}

/// A timestamped [`RecordedEvent`].
#[derive(Debug, Clone)]
pub struct RecordedEntry {
    pub at: Instant,
    pub event: RecordedEvent,
}

static DEFAULT_VALID_IP_ADDRS: LazyLock<HashSet<IpAddr>> = LazyLock::new(|| {
    let mut valid_ip_addrs = HashSet::new();
    valid_ip_addrs.insert("0.0.0.0".parse().unwrap());
    valid_ip_addrs.insert("127.0.0.1".parse().unwrap());
    valid_ip_addrs.insert("::1".parse().unwrap());
    valid_ip_addrs.insert("::".parse().unwrap());
    valid_ip_addrs
});
static  DEFAULT_NEXT: (usize, u16) = (0, 40_000);

#[derive(Debug)]
pub(crate) struct Packet {
    pub data: Vec<u8>,
    pub dest: SocketAddr,
    pub source: SocketAddr,
}

#[derive(Debug)]
pub(crate) struct UdpConnection {
    pub bound_addr: SocketAddr,
    pub from_local: VecDeque<Packet>,
    pub to_local: VecDeque<Packet>,
    /// Inbound packets waiting on latency / reorder jitter before joining `to_local`.
    pub pending_inbound: VecDeque<(Instant, Packet)>,
    pub failure_queue: Vec<io::Result<()>>,
    pub external_error: Option<io::Error>,
    pub is_destroyed: bool,
}

#[derive(Debug)]
pub(crate) struct TcpConnection {
    pub stream_id: usize,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub incoming: VecDeque<u8>,
    /// Inbound chunks waiting on latency before joining `incoming`.
    pub pending_inbound: VecDeque<(Instant, Vec<u8>)>,
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
}

#[derive(Debug)]
pub(crate) struct TcpListenerState {
    pub bound_addr: SocketAddr,
    pub pending_streams: VecDeque<usize>,
    pub nonblocking: bool,
    pub error: Option<io::Error>,
    pub is_closed: bool,
    pub ref_count: usize,
}

pub(crate) fn is_port_available(port: u16) -> bool {
    state!(local_ports_used = LocalPortsUsed ? HashSet::new());
    !local_ports_used.contains(&port)
}

/// Whitelist `ip` as a bindable address for this test. The default whitelist
/// covers `0.0.0.0`, `127.0.0.1`, `::`, and `::1`.
pub fn add_ip_addr(ip: IpAddr) {
    state!(valid_ip_addrs = ValidIpAddrs ? DEFAULT_VALID_IP_ADDRS.clone());
    valid_ip_addrs.insert(ip);
}

pub(crate) fn is_ip_addr_valid(ip: IpAddr) -> bool {
    state!(valid_ip_addrs = ValidIpAddrs ? DEFAULT_VALID_IP_ADDRS.clone());
    valid_ip_addrs.contains(&ip)
}

pub(crate) fn trigger_event() {
    state!(new_data_event = NewDataEvent ? Arc::new(Event::new()));
    new_data_event.notify(u32::MAX);
}

pub(crate) fn set_quiesce(addr: SocketAddr, until: Instant, mode: QuiesceMode) {
    {
        state!(quiesce = Quiescence ? HashMap::new());
        quiesce.insert(addr, QuiesceEntry { until, mode });
    }
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

/// Returns the active quiesce entry for `addr`, pruning if expired.
pub(crate) fn quiesce_entry(addr: SocketAddr) -> Option<QuiesceEntry> {
    state!(quiesce = Quiescence ? HashMap::new());
    let now = Instant::now();
    // Prune all expired entries; cheap because the map is usually tiny.
    quiesce.retain(|_, entry| entry.until > now);
    quiesce.get(&addr).copied()
}

pub(crate) fn is_quiesced_inbound(addr: SocketAddr) -> bool {
    matches!(
        quiesce_entry(addr),
        Some(QuiesceEntry { mode: QuiesceMode::Both | QuiesceMode::InboundOnly, .. })
    )
}

pub(crate) fn is_quiesced_outbound(addr: SocketAddr) -> bool {
    matches!(
        quiesce_entry(addr),
        Some(QuiesceEntry { mode: QuiesceMode::Both | QuiesceMode::OutboundOnly, .. })
    )
}

// ----- Policy helpers -----

/// Delay all inbound bytes for the SUT-side TCP `addr` by `latency`.
pub fn set_tcp_inbound_latency(addr: SocketAddr, latency: Duration) {
    state!(policies = TcpPolicies ? HashMap::new());
    policies.entry(addr).or_default().inbound_latency = latency;
}

/// Cap the SUT-side TCP receive buffer for `addr`. `None` removes the cap.
pub fn set_tcp_recv_window(addr: SocketAddr, window: Option<usize>) {
    state!(policies = TcpPolicies ? HashMap::new());
    policies.entry(addr).or_default().recv_window = window;
}

pub(crate) fn tcp_policy(addr: SocketAddr) -> TcpPolicy {
    state!(policies = TcpPolicies ? HashMap::new());
    policies.get(&addr).copied().unwrap_or_default()
}

/// Mutate the [`UdpPolicy`] for the socket bound at `addr`. The closure runs
/// against a default-initialized policy on first call.
pub fn set_udp_policy(addr: SocketAddr, policy_fn: impl FnOnce(&mut UdpPolicy)) {
    state!(policies = UdpPolicies ? HashMap::new());
    let entry = policies.entry(addr).or_default();
    policy_fn(entry);
}

pub(crate) fn udp_policy(addr: SocketAddr) -> UdpPolicy {
    state!(policies = UdpPolicies ? HashMap::new());
    policies.get(&addr).copied().unwrap_or_default()
}

/// Configure how the listener bound at `addr` responds to new connects.
pub fn set_listener_behavior(addr: SocketAddr, behavior: ListenerBehavior) {
    state!(behaviors = ListenerBehaviors ? HashMap::new());
    behaviors.insert(addr, behavior);
}

pub(crate) fn listener_behavior(addr: SocketAddr) -> ListenerBehavior {
    state!(behaviors = ListenerBehaviors ? HashMap::new());
    behaviors.get(&addr).copied().unwrap_or(ListenerBehavior::Accepting)
}

// ----- Port introspection -----

/// Returns the SUT-side local addr of the connection whose peer is `peer_addr`.
/// Lets tests target the SUT's ephemeral port without sending a discovery packet.
pub fn peek_local_addr_for_peer(peer_addr: SocketAddr) -> Option<SocketAddr> {
    state!(tcp_connections = TcpConnections ? HashMap::new());
    tcp_connections
        .values()
        .find(|c| c.peer_addr == peer_addr && !c.is_destroyed)
        .map(|c| c.local_addr)
}

// ----- Recording -----

pub(crate) fn record(event: RecordedEvent) {
    state!(log = RecordedEvents ? Vec::new());
    log.push(RecordedEntry {
        at: Instant::now(),
        event,
    });
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

static RNG_EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

fn next_rand() -> u32 {
    // Tiny xorshift64 PRNG. Seeded lazily from a process-wide monotonic epoch
    // on first use; tests that want determinism can call `seed_rng` first.
    state!(rng = RngState ? {
        let nanos = RNG_EPOCH.elapsed().as_nanos() as u64;
        if nanos == 0 { 0xa5a5_a5a5_a5a5_a5a5 } else { nanos }
    });
    let mut x = *rng;
    if x == 0 {
        x = 0xa5a5_a5a5_a5a5_a5a5;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *rng = x;
    (x as u32) ^ ((x >> 32) as u32)
}

fn rand_unit() -> f32 {
    (next_rand() as f32) / (u32::MAX as f32)
}

/// Seed the per-test RNG used for UDP loss / duplicate / reorder. Use for
/// deterministic policy tests.
pub fn seed_rng(seed: u64) {
    state!(rng = RngState ? 0);
    let s = if seed == 0 { 0xa5a5_a5a5_a5a5_a5a5 } else { seed };
    *rng = s;
}

pub(crate) fn wait_for_event(timeout: Option<Duration>) -> bool {
    let guard = TEST_STATE.lock();
    let mut borrow = guard.borrow_mut();
    let any_map = borrow
        .get_mut(&TestThreadId::current())
        .expect("Not a valid test thread");
    if !any_map.contains::<Mutex<NewDataEvent>>() {
        any_map.insert::<Mutex<NewDataEvent>>(Mutex::new(Arc::new(Event::new())));
    }
    #[allow(unused)]
    let mut new_data_event = any_map
        .get::<Mutex<NewDataEvent>>()
        .expect("Failed to get state")
        .lock();
    let listener = new_data_event.clone().listen();
    drop(new_data_event);
    drop(borrow);
    drop(guard);
    if let Some(dur) = timeout {
        listener.wait_timeout(dur).is_some()
    } else {
        listener.wait();
        true
    }
}

pub(crate) fn add_tcp_connection(
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    owns_port: bool,
) -> usize {
    state!(
        tcp_connections = TcpConnections ? HashMap::new();
        local_ports_used = LocalPortsUsed ? HashSet::new();
        next = Next ? DEFAULT_NEXT;
        new_data_event = NewDataEvent ? Arc::new(Event::new());
    );
    if owns_port {
        local_ports_used.insert(local_addr.port());
    }
    let stream_id = next.0;
    next.0 += 1;
    tcp_connections.insert(
        stream_id,
        TcpConnection {
            stream_id,
            local_addr,
            peer_addr,
            incoming: VecDeque::new(),
            pending_inbound: VecDeque::new(),
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
        },
    );
    new_data_event.notify(u32::MAX);
    stream_id
}

pub(crate) fn add_udp_connection(bound_addr: SocketAddr) {
    state!(
        udp_connections = UdpConnections ? Vec::new();
        local_ports_used = LocalPortsUsed ? HashSet::new();
        new_data_event = NewDataEvent ? Arc::new(Event::new());
    );

    local_ports_used.insert(bound_addr.port());
    udp_connections.push(UdpConnection {
        bound_addr,
        from_local: VecDeque::new(),
        to_local: VecDeque::new(),
        pending_inbound: VecDeque::new(),
        failure_queue: Vec::new(),
        external_error: None,
        is_destroyed: false,
    });
    new_data_event.notify(u32::MAX);
}

pub(crate) fn with_tcp_connection<T, F: FnOnce(&mut TcpConnection) -> T>(
    stream_id: usize,
    func: F,
) -> T {
    state!(
        tcp_connections = TcpConnections ? HashMap::new();
        new_data_event = NewDataEvent ? Arc::new(Event::new());
    );
    let connection = tcp_connections.get_mut(&stream_id);
    if let Some(conn) = connection {
        let ret = func(conn);
        new_data_event.notify(u32::MAX);
        ret
    } else {
        panic!("No connection found for stream id: {}", stream_id);
    }
}

pub(crate) fn remove_tcp_connection(stream_id: usize) -> Option<TcpConnection> {
    state!(
        tcp_connections = TcpConnections ? HashMap::new();
        local_ports_used = LocalPortsUsed ? HashSet::new();
    );
    if let Some(conn) = tcp_connections.remove(&stream_id) {
        if conn.owns_port {
            local_ports_used.remove(&conn.local_addr.port());
        }
        Some(conn)
    } else {
        None
    }
}

pub(crate) fn add_tcp_listener_state(addr: SocketAddr) {
    state!(
        tcp_listeners = TcpListeners ? HashMap::new();
        local_ports_used = LocalPortsUsed ? HashSet::new();
    );
    local_ports_used.insert(addr.port());
    tcp_listeners.insert(
        addr,
        TcpListenerState {
            bound_addr: addr,
            pending_streams: VecDeque::new(),
            nonblocking: false,
            error: None,
            is_closed: false,
            ref_count: 1,
        },
    );
}

pub(crate) fn remove_tcp_listener_state(addr: SocketAddr) -> Option<TcpListenerState> {
    state!(
        tcp_listeners = TcpListeners ? HashMap::new();
        local_ports_used = LocalPortsUsed ? HashSet::new();
    );
    if let Some(listener) = tcp_listeners.get_mut(&addr) {
        if listener.ref_count > 1 {
            listener.ref_count -= 1;
            return None;
        }
    } else {
        return None;
    }
    let state = tcp_listeners.remove(&addr);
    if state.is_some() {
        local_ports_used.remove(&addr.port());
    }
    state
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
    state!(tcp_listeners = TcpListeners ? HashMap::new());
    let listener = tcp_listeners.get_mut(&addr);
    if let Some(listener) = listener {
        func(listener)
    } else {
        panic!("No listener found for address: {}", addr);
    }
}

pub(crate) fn find_tcp_listener(target: SocketAddr) -> Option<SocketAddr> {
    state!(tcp_listeners = TcpListeners ? HashMap::new());
    if tcp_listeners.contains_key(&target) {
        return Some(target);
    }
    tcp_listeners
        .keys()
        .find(|addr| addr.port() == target.port() && addr.ip().is_unspecified())
        .copied()
}

pub(crate) fn assign_tcp_stream_to_listener(listener_addr: SocketAddr, stream_id: usize) {
    with_tcp_listener_state(listener_addr, |listener| {
        listener.pending_streams.push_back(stream_id);
    });
    state!(new_data_event = NewDataEvent ? Arc::new(Event::new()));
    new_data_event.notify(u32::MAX);
}

pub(crate) fn reserve_ephemeral_addr(ip: IpAddr) -> SocketAddr {
    state!(
        local_ports_used = LocalPortsUsed ? HashSet::new();
        next = Next ? DEFAULT_NEXT
    );
    loop {
        let mut port = next.1;
        if port == 0 {
            port = 40_000;
        }
        if local_ports_used.insert(port) {
            next.1 = port.wrapping_add(1);
            break SocketAddr::new(ip, port);
        }
        next.1 = port.wrapping_add(1);
    }
}

pub(crate) fn with_udp_connection<T, F: FnOnce(&mut UdpConnection) -> T>(
    binded_addr: SocketAddr,
    func: F,
) -> T {
    state!(
        udp_connection = UdpConnections ? Vec::new();
        new_data_event = NewDataEvent ? Arc::new(Event::new());
    );
    let connection = udp_connection
        .iter_mut()
        .find(|conn| conn.bound_addr == binded_addr);
    if let Some(conn) = connection {
        let ret = func(conn);
        new_data_event.notify(u32::MAX);
        ret
    } else {
        panic!("No connection found for address: {}", binded_addr);
    }
}

pub(crate) fn mark_peer_read_shutdown(peer_id: usize) {
    with_tcp_connection(peer_id, |peer_state| {
        peer_state.read_shutdown = true;
    });
}

pub(crate) fn release_stream(stream_id: usize) -> Option<usize> {
    with_tcp_connection(stream_id, |conn| {
        if conn.ref_count > 1 {
            conn.ref_count -= 1;
            return None;
        }
        Some(())
    })?;
    if let Some(conn) = remove_tcp_connection(stream_id) {
        conn.peer_stream_id
    } else {
        None
    }
}

pub(crate) fn notify_peer_dropped(peer_id: usize) {
    with_tcp_connection(peer_id, |peer| {
        peer.peer_stream_id = None;
        peer.read_shutdown = true;
        peer.external_error =
            Some(io::Error::new(io::ErrorKind::ConnectionReset, "peer disconnected"));
    });
}

pub(crate) fn send_udp_from_test(from_addr: SocketAddr, to_addr: SocketAddr, data: Vec<u8>) {
    let policy = udp_policy(to_addr);
    let len = data.len();
    let data_for_pcap = data.clone();

    // MTU rejection: oversize datagram is silently dropped on the wire.
    if let Some(mtu) = policy.mtu {
        if data.len() > mtu {
            record(RecordedEvent::UdpSendFromTest {
                from: from_addr,
                to: to_addr,
                len,
                dropped: true,
                duplicated: false,
            });
            return;
        }
    }

    let dropped = policy.loss_rate > 0.0 && rand_unit() < policy.loss_rate;
    if dropped {
        record(RecordedEvent::UdpSendFromTest {
            from: from_addr,
            to: to_addr,
            len,
            dropped: true,
            duplicated: false,
        });
        return;
    }

    let jitter_ns = if policy.reorder_jitter.is_zero() {
        0
    } else {
        (rand_unit() * policy.reorder_jitter.as_nanos() as f32) as u64
    };
    let total_delay = policy.inbound_latency + Duration::from_nanos(jitter_ns);
    let duplicated = policy.duplicate_rate > 0.0 && rand_unit() < policy.duplicate_rate;

    let pkt = |data: Vec<u8>| Packet {
        data,
        dest: to_addr,
        source: from_addr,
    };

    // Soft-fail if the destination UDP socket isn't bound yet (matches real
    // wire — UDP send to a non-existent listener is silently dropped). This
    // avoids panicking the tester loop when there's a race between the SUT
    // calling `bind` and the tester firing its first cyclic send.
    let delivered = {
        state!(
            udp_connections = UdpConnections ? Vec::new();
            new_data_event = NewDataEvent ? Arc::new(Event::new());
        );
        if let Some(conn) = udp_connections.iter_mut().find(|c| c.bound_addr == to_addr) {
            if total_delay.is_zero() {
                conn.to_local.push_back(pkt(data.clone()));
                if duplicated {
                    conn.to_local.push_back(pkt(data));
                }
            } else {
                let release_at = Instant::now() + total_delay;
                conn.pending_inbound.push_back((release_at, pkt(data.clone())));
                if duplicated {
                    conn.pending_inbound.push_back((release_at, pkt(data)));
                }
            }
            new_data_event.notify(u32::MAX);
            true
        } else {
            false
        }
    };

    if delivered {
        record(RecordedEvent::UdpSendFromTest {
            from: from_addr,
            to: to_addr,
            len,
            dropped: false,
            duplicated,
        });
        pcap_udp(from_addr, to_addr, &data_for_pcap);
        if duplicated {
            pcap_udp(from_addr, to_addr, &data_for_pcap);
        }
    }
}

/// Inject a TCP chunk as if `from_addr` had sent it to the SUT at `to_addr`.
/// Honors latency / recv_window / other policies; soft-fails if the SUT has
/// already disconnected.
pub fn inject_tcp_from_test(from_addr: SocketAddr, to_addr: SocketAddr, data: Vec<u8>) {
    send_tcp_from_test(from_addr, to_addr, data);
}

pub(crate) fn send_tcp_from_test(from_addr: SocketAddr, to_addr: SocketAddr, data: Vec<u8>) {
    let policy = tcp_policy(to_addr);
    let len = data.len();
    let total_delay = policy.inbound_latency;
    // Pcap path is opt-in; clone once up front (cheap vs. the I/O cost of
    // tests, only used by the pcap tap below).
    let data_for_pcap = data.clone();

    let outcome: Result<bool, ()> = {
        state!(
            tcp_connections = TcpConnections ? HashMap::new();
            new_data_event = NewDataEvent ? Arc::new(Event::new());
        );
        let connection = tcp_connections
            .values_mut()
            .find(|conn| conn.local_addr == to_addr && conn.peer_addr == from_addr);
        match connection {
            Some(conn) => {
                if let Some(window) = policy.recv_window {
                    let queued = conn.incoming.len()
                        + conn.pending_inbound.iter().map(|(_, b)| b.len()).sum::<usize>();
                    if queued + data.len() > window {
                        // Soft-drop on a stalled receive window. Test code
                        // that cares can inspect the recv-window via policy.
                        Ok(false)
                    } else {
                        if total_delay.is_zero() {
                            conn.incoming.extend(data);
                        } else {
                            conn.pending_inbound
                                .push_back((Instant::now() + total_delay, data));
                        }
                        new_data_event.notify(u32::MAX);
                        Ok(true)
                    }
                } else {
                    if total_delay.is_zero() {
                        conn.incoming.extend(data);
                    } else {
                        conn.pending_inbound
                            .push_back((Instant::now() + total_delay, data));
                    }
                    new_data_event.notify(u32::MAX);
                    Ok(true)
                }
            }
            None => Err(()),
        }
    };
    match outcome {
        Ok(true) => {
            record(RecordedEvent::TcpSendFromTest { from: from_addr, to: to_addr, len });
            pcap_tcp_data(from_addr, to_addr, &data_for_pcap);
        }
        Ok(false) => {}
        Err(()) => {
            // Soft-fail: SUT dropped the connection before delivery. Real
            // wire would silently discard or surface RST; treat as a no-op
            // here rather than panicking and killing the tester loop.
        }
    }
}

/// Move expired pending-inbound chunks into `incoming`. Driven by the
/// readiness oracle so latency-delayed bytes surface on time.
pub(crate) fn release_pending_for_tcp(addr: SocketAddr) -> bool {
    state!(
        tcp_connections = TcpConnections ? HashMap::new();
        new_data_event = NewDataEvent ? Arc::new(Event::new());
    );
    let now = Instant::now();
    let mut released = false;
    if let Some(conn) = tcp_connections.values_mut().find(|c| c.local_addr == addr) {
        while let Some((deadline, _)) = conn.pending_inbound.front() {
            if *deadline > now {
                break;
            }
            let (_, data) = conn.pending_inbound.pop_front().unwrap();
            conn.incoming.extend(data);
            released = true;
        }
    }
    if released {
        new_data_event.notify(u32::MAX);
    }
    released
}

pub(crate) fn release_pending_for_udp(addr: SocketAddr) -> bool {
    state!(
        udp_connections = UdpConnections ? Vec::new();
        new_data_event = NewDataEvent ? Arc::new(Event::new());
    );
    let now = Instant::now();
    let mut released = false;
    if let Some(conn) = udp_connections.iter_mut().find(|c| c.bound_addr == addr) {
        while let Some((deadline, _)) = conn.pending_inbound.front() {
            if *deadline > now {
                break;
            }
            let (_, pkt) = conn.pending_inbound.pop_front().unwrap();
            conn.to_local.push_back(pkt);
            released = true;
        }
    }
    if released {
        new_data_event.notify(u32::MAX);
    }
    released
}

/// Earliest pending-release deadline across all connections; the run loop
/// caps its sleep at this so delayed bytes surface on schedule.
pub(crate) fn earliest_pending_release() -> Option<Instant> {
    let mut earliest: Option<Instant> = None;
    {
        state!(tcp_connections = TcpConnections ? HashMap::new());
        for conn in tcp_connections.values() {
            if let Some((d, _)) = conn.pending_inbound.front() {
                earliest = Some(earliest.map_or(*d, |e| e.min(*d)));
            }
        }
    }
    {
        state!(udp_connections = UdpConnections ? Vec::new());
        for conn in udp_connections.iter() {
            if let Some((d, _)) = conn.pending_inbound.front() {
                earliest = Some(earliest.map_or(*d, |e| e.min(*d)));
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
    let peer = {
        state!(
            tcp_connections = TcpConnections ? HashMap::new();
            new_data_event = NewDataEvent ? Arc::new(Event::new());
        );
        if let Some(conn) =
            tcp_connections.values_mut().find(|c| c.local_addr == addr)
        {
            conn.reset_pending = true;
            conn.read_shutdown = true;
            conn.external_error = Some(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "connection reset by peer",
            ));
            new_data_event.notify(u32::MAX);
            Some(conn.peer_addr)
        } else {
            None
        }
    };
    if let Some(peer_addr) = peer {
        record(RecordedEvent::TcpResetFromTest { addr });
        // RST is sourced from the test-side peer, since `reset_tcp_from_test`
        // is the "the remote side just sent a RST" path.
        pcap_tcp_rst(peer_addr, addr);
    }
}

pub(crate) fn raise_udp_socket_error_from_test(addr: SocketAddr, err: io::Error) {
    state!(
        udp_connections = UdpConnections ? Vec::new();
        new_data_event = NewDataEvent ? Arc::new(Event::new());
    );
    if let Some(conn) =
        udp_connections.iter_mut().find(|conn| conn.bound_addr == addr)
    {
        conn.external_error = Some(err);
        new_data_event.notify(u32::MAX);
    }
    // Soft-fail: socket not bound yet / already gone. Match wire semantics.
}

pub(crate) fn raise_tcp_socket_error_from_test(addr: SocketAddr, err: io::Error) {
    state!(
        tcp_connections = TcpConnections ? HashMap::new();
        new_data_event = NewDataEvent ? Arc::new(Event::new());
    );
    if let Some(conn) =
        tcp_connections.values_mut().find(|conn| conn.local_addr == addr)
    {
        conn.external_error = Some(err);
        new_data_event.notify(u32::MAX);
    }
    // Soft-fail.
}

pub(crate) fn close_socket_from_test(addr: SocketAddr, socket_type: SocketType) {
    let mut found = false;
    match socket_type {
        SocketType::Udp => {
            {
                state!(
                    udp_connections = UdpConnections ? Vec::new();
                    new_data_event = NewDataEvent ? Arc::new(Event::new());
                );
                if let Some(conn) =
                    udp_connections.iter_mut().find(|c| c.bound_addr == addr)
                {
                    conn.is_destroyed = true;
                    new_data_event.notify(u32::MAX);
                    found = true;
                }
            }
            if found {
                record(RecordedEvent::UdpCloseFromTest { addr });
            }
            // Soft-fail if the socket isn't bound (not yet, or already gone).
        }
        SocketType::Tcp => {
            {
                state!(
                    tcp_connections = TcpConnections ? HashMap::new();
                    new_data_event = NewDataEvent ? Arc::new(Event::new());
                );
                if let Some(conn) =
                    tcp_connections.values_mut().find(|c| c.local_addr == addr)
                {
                    conn.is_destroyed = true;
                    new_data_event.notify(u32::MAX);
                    found = true;
                }
            }
            if found {
                record(RecordedEvent::TcpCloseFromTest { addr });
            }
            // Soft-fail.
        }
    }
}

/// SUT-outbound UDP send. Returns `WouldBlock` on a full send queue and
/// `InvalidInput` over MTU; otherwise enqueues into `from_local`.
pub(crate) fn enqueue_udp_outbound(
    bound_addr: SocketAddr,
    pkt: Packet,
) -> io::Result<()> {
    let policy = udp_policy(bound_addr);
    if let Some(mtu) = policy.mtu {
        if pkt.data.len() > mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram exceeds configured MTU",
            ));
        }
    }
    let pcap_capture = (pkt.source, pkt.dest, pkt.data.clone());
    {
        state!(
            udp_connections = UdpConnections ? Vec::new();
            new_data_event = NewDataEvent ? Arc::new(Event::new());
        );
        let conn = udp_connections
            .iter_mut()
            .find(|c| c.bound_addr == bound_addr)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "no such UDP socket")
            })?;
        if let Some(cap) = policy.send_queue_depth {
            if conn.from_local.len() >= cap {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "UDP send queue full",
                ));
            }
        }
        conn.from_local.push_back(pkt);
        new_data_event.notify(u32::MAX);
    }
    pcap_udp(pcap_capture.0, pcap_capture.1, &pcap_capture.2);
    Ok(())
}

pub(crate) fn pop_latest_packet(addr: SocketAddr) -> Option<Packet> {
    state!(udp_connections = UdpConnections ? Vec::new());
    for conn in udp_connections.iter_mut() {
        if let Some(idx) = conn.from_local.iter().position(|pkt| pkt.dest == addr) {
            return conn.from_local.remove(idx);
        }
    }
    None
}

pub(crate) fn has_pending_udp_packet(addr: SocketAddr) -> bool {
    state!(udp_connections = UdpConnections ? Vec::new());
    udp_connections
        .iter()
        .any(|conn| conn.from_local.iter().any(|pkt| pkt.dest == addr))
}

pub(crate) fn has_pending_tcp_data(addr: SocketAddr) -> bool {
    state!(tcp_connections = TcpConnections ? HashMap::new());
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
}

pub(crate) struct UdpSocketStatus {
    pub readable: bool,
    pub writable: bool,
    pub error: bool,
    pub closed: bool,
}

pub(crate) fn tcp_listener_status(addr: SocketAddr) -> Option<TcpListenerStatus> {
    state!(tcp_listeners = TcpListeners ? HashMap::new());
    let listener = tcp_listeners.get(&addr)?;
    Some(TcpListenerStatus {
        pending: !listener.pending_streams.is_empty(),
        error: listener.error.is_some(),
        closed: listener.is_closed,
    })
}

pub(crate) fn tcp_stream_status(addr: SocketAddr) -> Option<TcpStreamStatus> {
    // Move any latency-released bytes into `incoming` first so the readiness
    // we return reflects the post-deadline state.
    release_pending_for_tcp(addr);
    let inbound_quiesced = is_quiesced_inbound(addr);
    let outbound_quiesced = is_quiesced_outbound(addr);
    state!(tcp_connections = TcpConnections ? HashMap::new());
    let conn = tcp_connections.values().find(|conn| conn.local_addr == addr)?;
    let read_closed = conn.read_shutdown || conn.peer_stream_id.is_none() || conn.is_destroyed;
    let write_closed = conn.write_shutdown || conn.is_destroyed;
    let raw_readable = !conn.incoming.is_empty();
    let raw_writable = !write_closed && conn.peer_stream_id.is_some();
    Some(TcpStreamStatus {
        readable: raw_readable && !inbound_quiesced,
        writable: raw_writable && !outbound_quiesced,
        error: conn.external_error.is_some(),
        read_closed,
        write_closed,
    })
}

pub(crate) fn udp_socket_status(addr: SocketAddr) -> Option<UdpSocketStatus> {
    release_pending_for_udp(addr);
    let inbound_quiesced = is_quiesced_inbound(addr);
    let outbound_quiesced = is_quiesced_outbound(addr);
    state!(udp_connections = UdpConnections ? Vec::new());
    let conn = udp_connections.iter().find(|conn| conn.bound_addr == addr)?;
    let closed = conn.is_destroyed;
    Some(UdpSocketStatus {
        readable: !conn.to_local.is_empty() && !inbound_quiesced,
        writable: !closed && !outbound_quiesced,
        error: conn.external_error.is_some(),
        closed,
    })
}

pub(crate) fn tcp_connection_peer_addr(local_addr: SocketAddr) -> Option<SocketAddr> {
    state!(tcp_connections = TcpConnections ? HashMap::new());
    tcp_connections
        .values()
        .find(|conn| conn.local_addr == local_addr)
        .map(|conn| conn.peer_addr)
}

pub(crate) fn peek_tcp_stream_data(addr: SocketAddr) -> Vec<u8> {
    state!(tcp_connections = TcpConnections ? HashMap::new());
    let connection = tcp_connections
        .values_mut()
        .find(|conn| conn.local_addr == addr);
    if let Some(conn) = connection {
        conn.incoming.iter().copied().collect()
    } else {
        return Vec::new();
    }
}

pub(crate) fn consume_tcp_stream_data(addr: SocketAddr, amount: usize) {
    state!(tcp_connections = TcpConnections ? HashMap::new());
    let connection = tcp_connections
        .values_mut()
        .find(|conn| conn.local_addr == addr);
    if let Some(conn) = connection {
        for _ in 0..amount {
            conn.incoming.pop_front();
        }
    } else {
        return;
    }
}
