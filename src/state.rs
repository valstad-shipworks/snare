#![allow(dead_code)]

use std::{
    cell::RefCell, collections::{HashMap, HashSet, VecDeque}, io, net::{IpAddr, SocketAddr}, sync::{Arc, LazyLock}, thread::ThreadId, time::Duration, u32
};

use anymap2::SendSyncAnyMap as AnyMap;
use event_listener::{Event, Listener};
use parking_lot::{Mutex, ReentrantMutex};

use crate::SocketType;

/// A global mapping of thread IDs to their parent thread IDs for testing purposes.
/// The parent id is not necessarily the direct parent, but the oldest ancestor known.
static TEST_THREAD_HIERARCHY: LazyLock<Mutex<HashMap<ThreadId, ThreadId>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// A global mapping of test thread
static TEST_STATE: LazyLock<ReentrantMutex<RefCell<HashMap<TestThreadId, AnyMap>>>> = LazyLock::new(|| ReentrantMutex::new(RefCell::new(HashMap::new())));

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct TestThreadId(ThreadId);

impl TestThreadId {
    fn of(id: ThreadId) -> Self {
        let hierarchy = TEST_THREAD_HIERARCHY.lock();
        let mut current_id = id;
        if !hierarchy.contains_key(&current_id) {
            std::thread::sleep(Duration::from_millis(50));
        }
        if !hierarchy.contains_key(&current_id) {
            panic!("Thread not registered as test thread or child thread");
        }
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

pub fn register_test() {
    let thread_id = std::thread::current().id();
    let mut map = TEST_THREAD_HIERARCHY.lock();
    map.insert(thread_id, thread_id);
    drop(map);
    let test_thread_id = TestThreadId(thread_id);
    TEST_STATE.lock().borrow_mut().insert(test_thread_id, AnyMap::new());
}

pub fn register_child_thread(child_thread_id: ThreadId) {
    let test_thread_id = TestThreadId::current();
    TEST_THREAD_HIERARCHY.lock().insert(child_thread_id, test_thread_id.0);
}

pub fn register_thread_child_of(parent_thread_id: ThreadId) {
    let child_thread_id = std::thread::current().id();
    TEST_THREAD_HIERARCHY.lock().insert(child_thread_id, parent_thread_id);
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
    with_udp_connection(to_addr, |conn| {
        conn.to_local.push_back(Packet {
            data,
            dest: to_addr,
            source: from_addr,
        });
    });
}

pub(crate) fn send_tcp_from_test(from_addr: SocketAddr, to_addr: SocketAddr, data: Vec<u8>) {
    state!(
        tcp_connections = TcpConnections ? HashMap::new();
        new_data_event = NewDataEvent ? Arc::new(Event::new());
    );
    let connection = tcp_connections
        .values_mut()
        .find(|conn| conn.local_addr == to_addr && conn.peer_addr == from_addr);
    if let Some(conn) = connection {
        conn.incoming.extend(data);
        new_data_event.notify(u32::MAX);
    } else {
        panic!(
            "No TCP connection found for from: {} to: {}",
            from_addr, to_addr
        );
    }
}

pub(crate) fn raise_udp_socket_error_from_test(addr: SocketAddr, err: io::Error) {
    state!(
        udp_connections = UdpConnections ? Vec::new();
        new_data_event = NewDataEvent ? Arc::new(Event::new());
    );
    let connection = udp_connections
        .iter_mut()
        .find(|conn| conn.bound_addr == addr);
    if let Some(conn) = connection {
        conn.external_error = Some(err);
        new_data_event.notify(u32::MAX);
    } else {
        panic!("No UDP connection found for address: {}", addr);
    }
}

pub(crate) fn raise_tcp_socket_error_from_test(addr: SocketAddr, err: io::Error) {
    state!(
        tcp_connections = TcpConnections ? HashMap::new();
        new_data_event = NewDataEvent ? Arc::new(Event::new());
    );
    let connection = tcp_connections
        .values_mut()
        .find(|conn| conn.local_addr == addr);
    if let Some(conn) = connection {
        conn.external_error = Some(err);
        new_data_event.notify(u32::MAX);
    } else {
        panic!("No TCP connection found for address: {}", addr);
    }
}

pub(crate) fn close_socket_from_test(addr: SocketAddr, socket_type: SocketType) {
    match socket_type {
        SocketType::Udp => {
            state!(
                udp_connections = UdpConnections ? Vec::new();
                new_data_event = NewDataEvent ? Arc::new(Event::new());
            );
            let connection = udp_connections
                .iter_mut()
                .find(|conn| conn.bound_addr == addr);
            if let Some(conn) = connection {
                conn.is_destroyed = true;
                new_data_event.notify(u32::MAX);
            } else {
                panic!("No UDP connection found for address: {}", addr);
            }
        }
        SocketType::Tcp => {
            state!(
                tcp_connections = TcpConnections ? HashMap::new();
                new_data_event = NewDataEvent ? Arc::new(Event::new());
            );
            let connection = tcp_connections
                .values_mut()
                .find(|conn| conn.local_addr == addr);
            if let Some(conn) = connection {
                conn.is_destroyed = true;
                new_data_event.notify(u32::MAX);
            } else {
                panic!("No TCP connection found for address: {}", addr);
            }
        }
    }
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
    state!(tcp_connections = TcpConnections ? HashMap::new());
    let conn = tcp_connections.values().find(|conn| conn.local_addr == addr)?;
    let read_closed = conn.read_shutdown || conn.peer_stream_id.is_none() || conn.is_destroyed;
    let write_closed = conn.write_shutdown || conn.is_destroyed;
    Some(TcpStreamStatus {
        readable: !conn.incoming.is_empty(),
        writable: !write_closed && conn.peer_stream_id.is_some(),
        error: conn.external_error.is_some(),
        read_closed,
        write_closed,
    })
}

pub(crate) fn udp_socket_status(addr: SocketAddr) -> Option<UdpSocketStatus> {
    state!(udp_connections = UdpConnections ? Vec::new());
    let conn = udp_connections.iter().find(|conn| conn.bound_addr == addr)?;
    let closed = conn.is_destroyed;
    Some(UdpSocketStatus {
        readable: !conn.to_local.is_empty(),
        writable: !closed,
        error: conn.external_error.is_some(),
        closed,
    })
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
