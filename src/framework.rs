use std::{cell::RefCell, io, marker::PhantomData, net::SocketAddr, time::{Duration, Instant}};

use anymap2::AnyMap;

use crate::{SocketType, state::{self, wait_for_event}};

/// A type that can be encoded to / decoded from network bytes. See
/// [`tests/`](https://github.com/valstad-shipworks/snare/tree/main/tests)
/// for usage patterns.
pub trait Packetable: Clone + Send + Sync + 'static {
    /// Whether [`flatten`](Self::flatten) produces multiple packets.
    const CAN_BE_FLATTENED: bool;
    /// UDP or TCP.
    const SOCKET_TYPE: SocketType;

    /// Serialize the packet for transmission.
    fn encode(&self) -> Vec<u8>;

    /// Deserialize the packet from a byte slice. Returns `(packet, bytes_consumed)`,
    /// or `None` if the buffer doesn't yet contain a complete packet. For TCP the
    /// framework calls this repeatedly on a growing buffer.
    fn decode(data: &[u8]) -> Option<(Self, usize)>;

    /// Split a packet into multiple sub-packets. Defaults to a single-element vec.
    fn flatten(&self) -> Vec<Self> {
        vec![self.clone()]
    }
}

/// Marker trait for per-tester state. Auto-implemented for any
/// `Default + Send + Sync + 'static`.
pub trait StateKey: Default + Send + Sync + 'static {}
impl<T: Default + Send + Sync + 'static> StateKey for T {}

/// Tracks elapsed time within a tester. The first [`poll_elapsed`](Self::poll_elapsed)
/// call starts the clock and returns zero.
#[derive(Debug, Default)]
pub struct TimerState {
    start_instant: Option<Instant>,
}
impl TimerState {
    /// Returns the duration since the first call. The first call always returns zero.
    pub fn poll_elapsed(&mut self) -> Duration {
        if let Some(start) = self.start_instant {
            Instant::now().duration_since(start)
        } else {
            self.start_instant = Some(Instant::now());
            Duration::from_secs(0)
        }
    }
}

/// An action a tester can perform — returned from packet handlers and cyclic actions.
pub enum TesterAction<T: Packetable> {
    /// Send `T` to the given peer.
    Send(SocketAddr, T),
    /// Inject an `io::Error` on the socket bound at `addr`.
    RaiseSocketError(SocketAddr, io::Error),
    /// Close the socket bound at `addr` (graceful EOF).
    CloseSocket(SocketAddr),
    /// Run a list of actions in order.
    Multiple(Vec<TesterAction<T>>),
    /// Suppress mio readiness on `addr` for the duration (both directions).
    /// See [`QuiesceWithMode`](Self::QuiesceWithMode) for one-direction control.
    Quiesce(SocketAddr, Duration),
    /// Suppress mio readiness on `addr` in only the chosen direction.
    QuiesceWithMode(SocketAddr, Duration, crate::state::QuiesceMode),
    /// Send a TCP RST. The next read/write on `addr` returns `ECONNRESET`.
    /// Distinct from [`CloseSocket`](Self::CloseSocket) (graceful EOF).
    ResetTcp(SocketAddr),
    /// Configure how a TCP listener responds to new connection attempts.
    SetListenerBehavior(SocketAddr, crate::state::ListenerBehavior),
    /// Delay all bytes inbound to `addr` by `Duration`. Already-queued bytes unaffected.
    SetTcpInboundLatency(SocketAddr, Duration),
    /// Cap the SUT-side TCP receive buffer; writes block when full.
    SetTcpRecvWindow(SocketAddr, Option<usize>),
    /// Configure UDP link policy: loss / duplicate / reorder / latency / queue / MTU.
    SetUdpPolicy(SocketAddr, crate::state::UdpPolicy),
}

/// Type-erased [`NetTester`] interface used by [`run_testers!`](crate::run_testers!).
pub trait NetTesterInterface {
    /// Feed raw bytes into the tester. TCP returns `Some(consumed)`; UDP returns `None`.
    fn test(&mut self, data: &[u8], src_addr: SocketAddr) -> Option<usize>;
    /// Time until the next due cyclic action, or `None` if there are no cycles.
    fn duration_till_soonest_cycle(&self) -> Option<Duration>;
    /// Run every cyclic action whose interval has elapsed.
    fn run_due_cycles(&mut self);
    /// Whether any finish condition is satisfied.
    fn is_finished(&mut self) -> bool;
    /// The address the tester is bound to.
    fn get_addr(&self) -> SocketAddr;
    /// The socket type (UDP or TCP).
    fn get_socket_type(&self) -> SocketType;
}

/// Builder + runtime for one address worth of test handlers.
///
/// Built via [`connect_tester`], chained with packet handlers, cyclic actions, state,
/// and finish conditions, then driven by [`run_testers!`](crate::run_testers!). Method categories:
///
/// - **Packet handlers**: `then_test`, `then_stateful_test`, `then_action`,
///   `then_stateful_action`, `then_edit_state`. Run for every decoded packet in chain
///   order. Returning `None` from a `then_*_test` stops the chain for that packet.
/// - **Cyclic actions**: `with_cyclic_action`, `with_stateful_cyclic_action`. Fire at
///   a fixed interval regardless of incoming packets.
/// - **State**: `with_state` eagerly initializes a slot.
/// - **Finish conditions**: `until_condition`, `until_stateful_condition`. Tester
///   exits when any returns `true`. With no conditions, the tester exits when no
///   pending packets/data remain.
pub struct NetTester<P: Packetable> {
    phantom: PhantomData<P>,
    addr: SocketAddr,
    state: AnyMap,
    tests: Vec<Box<dyn Fn(&mut Self, P, SocketAddr) -> Option<P>>>,
    cycles: Vec<(Duration, RefCell<Instant>, Box<dyn Fn(&mut Self)>)>,
    finish_conditions: Vec<Box<dyn Fn(&mut Self) -> bool>>,
}

impl<P: Packetable> NetTester<P> {
    fn enact_action(& mut self, action: TesterAction<P>) {
        match action {
            TesterAction::Send(addr, pkt) => {
                if P::SOCKET_TYPE == SocketType::Udp {
                    state::send_udp_from_test(self.addr, addr, pkt.encode());
                } else {
                    state::send_tcp_from_test(self.addr, addr, pkt.encode());
                }
            },
            TesterAction::RaiseSocketError(addr, e) => {
                if P::SOCKET_TYPE == SocketType::Udp {
                    state::raise_udp_socket_error_from_test(addr, e);
                } else {
                    state::raise_tcp_socket_error_from_test(addr, e);
                }
            },
            TesterAction::CloseSocket(addr) => {
                state::close_socket_from_test(addr, P::SOCKET_TYPE);
            },
            TesterAction::Multiple(actions) => {
                for act in actions {
                    self.enact_action(act);
                }
            }
            TesterAction::Quiesce(addr, dur) => {
                state::set_quiesce(addr, Instant::now() + dur, state::QuiesceMode::Both);
            }
            TesterAction::QuiesceWithMode(addr, dur, mode) => {
                state::set_quiesce(addr, Instant::now() + dur, mode);
            }
            TesterAction::ResetTcp(addr) => {
                state::reset_tcp_from_test(addr);
            }
            TesterAction::SetListenerBehavior(addr, behavior) => {
                state::set_listener_behavior(addr, behavior);
            }
            TesterAction::SetTcpInboundLatency(addr, dur) => {
                state::set_tcp_inbound_latency(addr, dur);
            }
            TesterAction::SetTcpRecvWindow(addr, window) => {
                state::set_tcp_recv_window(addr, window);
            }
            TesterAction::SetUdpPolicy(addr, policy) => {
                state::set_udp_policy(addr, |p| *p = policy);
            }
        }
    }

    pub(crate) fn duration_till_soonest_cycle(& self) -> Option<Duration> {
        let now = Instant::now();
        let mut min_delta: Option<Duration> = None;
        for (delta, last_run_cell, _) in &self.cycles {
            let last_run = last_run_cell.borrow();
            let next_run = *last_run + *delta;
            if next_run <= now {
                return Some(Duration::from_secs(0));
            } else {
                let time_till_next = next_run - now;
                min_delta = match min_delta {
                    Some(current_min) => Some(std::cmp::min(current_min, time_till_next)),
                    None => Some(time_till_next),
                };
            }
        }
        min_delta
    }

    pub(crate) fn run_due_cycles(& mut self) {
        let now = Instant::now();
        let mut cycles = std::mem::take(&mut self.cycles);
        for (delta, last_run_cell, action) in cycles.iter_mut() {
            let mut last_run = last_run_cell.borrow_mut();
            let next_run = *last_run + *delta;
            if next_run <= now {
                action(self);
                *last_run = now;
            }
        }
        self.cycles = cycles;
    }

    /// Adds a packet handler with access to typed state `S`. State is lazily
    /// `Default`-initialized. Return `Some(pkt)` to forward to the next handler,
    /// `None` to stop the chain for this packet.
    pub fn then_stateful_test<S: StateKey>(mut self, tester: fn(&mut S, P, SocketAddr) -> Option<P>) -> NetTester<P> {
        let storable = move |slf: &mut Self, pkt: P, addr: SocketAddr| {
            let state = slf.state.entry::<S>().or_insert_with(Default::default);
            tester(state, pkt, addr)
        };
        self.tests.push(Box::new(storable));
        self
    }

    /// Stateless variant of [`then_stateful_test`](Self::then_stateful_test).
    pub fn then_test(mut self, tester: fn(P, SocketAddr) -> Option<P>) -> NetTester<P> {
        let stateless = move |_: &mut Self, pkt: P, addr: SocketAddr| tester(pkt, addr);
        self.tests.push(Box::new(stateless));
        self
    }

    /// Mutates state `S` per packet without inspecting it; the packet is always
    /// forwarded unchanged.
    pub fn then_edit_state<S: StateKey>(
        mut self,
        editor: fn(&mut S, SocketAddr),
    ) -> NetTester<P> {
        let stateful = move |slf: &mut Self, pkt: P, addr: SocketAddr| {
            let state = slf.state.entry::<S>().or_insert_with(Default::default);
            editor(state, addr);
            Some(pkt)
        };
        self.tests.push(Box::new(stateful));
        self
    }

    /// Adds a packet handler that returns a [`TesterAction`] (e.g. send a reply).
    /// The action runs immediately; the packet continues down the chain.
    pub fn then_stateful_action<S: StateKey>(
        mut self,
        actor: fn(&mut S, P, SocketAddr) -> TesterAction<P>,
    ) -> NetTester<P> {
        let stateful = move |slf: &mut Self, pkt: P, addr: SocketAddr| {
            let state = slf.state.entry::<S>().or_insert_with(Default::default);
            let action = actor(state, pkt.clone(), addr);
            slf.enact_action(action);
            Some(pkt)
        };
        self.tests.push(Box::new(stateful));
        self
    }

    /// Stateless variant of [`then_stateful_action`](Self::then_stateful_action).
    pub fn then_action(
        mut self,
        actor: fn(P, SocketAddr) -> TesterAction<P>,
    ) -> NetTester<P> {
        let stateless = move |slf: &mut Self, pkt: P, addr: SocketAddr| {
            let action = actor(pkt.clone(), addr);
            slf.enact_action(action);
            Some(pkt)
        };
        self.tests.push(Box::new(stateless));
        self
    }

    /// Runs `actor` every `delta` with access to state `S`. Return `None` to skip
    /// a tick. Useful for heartbeats, periodic polling, or scheduled sends.
    pub fn with_stateful_cyclic_action<S: StateKey>(
        mut self,
        delta: Duration,
        actor: fn(&mut S) -> Option<TesterAction<P>>,
    ) -> NetTester<P> {
        let stateful = move |slf: &mut Self| {
            let state = slf.state.entry::<S>().or_insert_with(Default::default);
            if let Some(action) = actor(state) {
                slf.enact_action(action);
            }
        };
        self.cycles.push((delta, RefCell::new(Instant::now()), Box::new(stateful)));
        self
    }

    /// Stateless variant of [`with_stateful_cyclic_action`](Self::with_stateful_cyclic_action).
    pub fn with_cyclic_action(
        mut self,
        delta: Duration,
        actor: fn() -> Option<TesterAction<P>>,
    ) -> NetTester<P> {
        let stateless = move |slf: &mut Self| {
            if let Some(action) = actor() {
                slf.enact_action(action);
            }
        };
        self.cycles.push((delta, RefCell::new(Instant::now()), Box::new(stateless)));
        self
    }

    /// Eagerly initializes state `S` then runs `initializer` to configure it.
    pub fn with_state<S: StateKey>(
        mut self,
        initializer: fn(&mut S),
    ) -> NetTester<P> {
        let stateful = move |slf: &mut Self| {
            let state = slf.state.entry::<S>().or_insert_with(Default::default);
            initializer(state);
        };
        stateful(&mut self);
        self
    }

    /// Stateless finish condition. Multiple conditions OR together — the tester
    /// exits when any returns `true`.
    pub fn until_condition(
        mut self,
        condition: fn() -> bool,
    ) -> NetTester<P> {
        let cond_box = Box::new(move |_: &mut Self| condition());
        self.finish_conditions.push(cond_box);
        self
    }

    /// Stateful finish condition. Commonly used with [`TimerState`] for a deadline:
    /// `.until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= dur)`.
    pub fn until_stateful_condition<S: StateKey>(
        mut self,
        condition: fn(&mut S) -> bool,
    ) -> NetTester<P> {
        let cond_box = Box::new(move |slf: &mut Self| {
            let state = slf.state.entry::<S>().or_insert_with(Default::default);
            condition(state)
        });
        self.finish_conditions.push(cond_box);
        self
    }

    /// Borrow the state of type `S`. Typically called after [`run_testers!`](crate::run_testers!) for
    /// post-run assertions.
    ///
    /// # Panics
    /// If no `S` was ever initialized.
    pub fn peek_state<'a, S: StateKey>(
        &'a self
    ) -> &'a S {
        self.state.get::<S>()
            .expect("State for type was not found")
    }
}

/// Build a [`NetTester`] bound to `addr`. For TCP this also registers a virtual
/// listener so the SUT can connect to it. Must be called after
/// [`register_test`](crate::register_test).
pub fn connect_tester<P: Packetable>(addr: SocketAddr) -> NetTester<P> {
    if P::SOCKET_TYPE == SocketType::Tcp {
        state::add_tcp_listener_state(addr);
    }
    let mut ret = NetTester {
        phantom: PhantomData,
        addr,
        state: AnyMap::new(),
        tests: Vec::new(),
        cycles: Vec::new(),
        finish_conditions: Vec::new(),
    };
    ret.state.entry::<()>().or_insert_with(|| ());
    ret
}

impl <P: Packetable> NetTesterInterface for NetTester<P> {
    fn test(&mut self, data: &[u8], src_addr: SocketAddr) -> Option<usize> {
        if P::SOCKET_TYPE == SocketType::Udp {
            let opt_pkt = P::decode(data).and_then(|(pkt, _)| Some(pkt));
            if let Some(mut pkt) = opt_pkt {
                let mut tests = std::mem::take(&mut self.tests);
                for test in tests.iter_mut() {
                    if let Some(new_pkt) = test(self, pkt, src_addr) {
                        pkt = new_pkt;
                    } else {
                        break;
                    }
                }
                self.tests = tests;
                self.run_due_cycles();
            }
            return None;
        } else {
            let mut offset = 0;
            while offset < data.len() {
                if let Some((mut pkt, read_bytes)) = P::decode(&data[offset..]) {
                    offset += read_bytes;
                    let mut tests = std::mem::take(&mut self.tests);
                    for test in tests.iter_mut() {
                        if let Some(new_pkt) = test(self, pkt, src_addr) {
                            pkt = new_pkt;
                        } else {
                            break;
                        }
                    }
                    self.tests = tests;
                    self.run_due_cycles();
                } else {
                    break;
                }
            }
            return Some(offset);
        }
    }

    fn duration_till_soonest_cycle(&self) -> Option<Duration> {
        self.duration_till_soonest_cycle()
    }

    fn run_due_cycles(&mut self) {
        self.run_due_cycles()
    }

    fn is_finished(&mut self) -> bool {
        let mut finish_conditions_taken = std::mem::take(&mut self.finish_conditions);
        if finish_conditions_taken.is_empty() {
            let has_pending = match P::SOCKET_TYPE {
                SocketType::Udp => state::has_pending_udp_packet(self.addr),
                SocketType::Tcp => state::has_pending_tcp_data(self.addr),
            };
            self.finish_conditions = finish_conditions_taken;
            return !has_pending;
        }
        for condition in finish_conditions_taken.iter_mut() {
            if condition(self) {
                self.finish_conditions = finish_conditions_taken;
                return true
            }
        }
        self.finish_conditions = finish_conditions_taken;
        false
    }

    fn get_addr(&self) -> SocketAddr {
        self.addr
    }

    fn get_socket_type(&self) -> SocketType {
        P::SOCKET_TYPE
    }
}

#[doc(hidden)]
pub fn _run_testers(mut testers: Vec<&mut dyn NetTesterInterface>) {
    for tester in testers.iter() {
        for other_tester in testers.iter() {
            if std::ptr::eq(*tester, *other_tester) {
                continue;
            }
            assert!(
                tester.get_addr() != other_tester.get_addr() ||
                tester.get_socket_type() != other_tester.get_socket_type(),
                "Overlapping testers detected for addr: {} and socket type: {:?}",
                tester.get_addr(),
                tester.get_socket_type()
            );
        }
    }

    loop {
        for tester in testers.iter_mut() {
            tester.run_due_cycles();
        }

        let mut did_work = false;
        for tester in testers.iter_mut() {
            match tester.get_socket_type() {
                SocketType::Udp => {
                    while let Some(pkt) = state::pop_latest_packet(tester.get_addr()) {
                        did_work = true;
                        tester.test(&pkt.data, pkt.source);
                    }
                }
                SocketType::Tcp => loop {
                    let data = state::peek_tcp_stream_data(tester.get_addr());
                    if data.is_empty() {
                        break;
                    }
                    let src_addr = state::tcp_connection_peer_addr(tester.get_addr())
                        .unwrap_or(tester.get_addr());
                    match tester.test(&data, src_addr) {
                        Some(used) if used > 0 => {
                            state::consume_tcp_stream_data(tester.get_addr(), used);
                            did_work = true;
                        }
                        _ => break,
                    }
                },
            }
        }

        for tester in testers.iter_mut() {
            if tester.is_finished() {
                return;
            }
        }

        if did_work {
            continue;
        }

        let mut min_duration: Option<Duration> = None;
        for tester in testers.iter() {
            let tester_duration = tester.duration_till_soonest_cycle();
            min_duration = match (min_duration, tester_duration) {
                (Some(current_min), Some(tester_dur)) => Some(std::cmp::min(current_min, tester_dur)),
                (None, Some(tester_dur)) => Some(tester_dur),
                (min, None) => min,
            };
        }

        // Wake at the next pending-release deadline so latency-delayed bytes
        // surface to readers without waiting for a cycle.
        if let Some(release) = state::earliest_pending_release() {
            let now = Instant::now();
            let until_release = release.saturating_duration_since(now);
            min_duration = match min_duration {
                Some(current) => Some(std::cmp::min(current, until_release)),
                None => Some(until_release),
            };
        }

        let duration = min_duration.unwrap_or_else(|| Duration::from_millis(10));
        if duration > Duration::from_secs(0) {
            wait_for_event(Some(duration));
        }
    }
}

/// Drive one or more [`NetTester`]s in a shared event loop until any tester's
/// finish condition fires.
///
/// Takes a comma-separated list of mutable tester bindings. Panics if two testers
/// share both the same address and socket type. Sleeps briefly before entering the
/// loop to give spawned client threads time to start.
#[macro_export]
macro_rules! run_testers {
    ($( $testr:ident ),* $(,)?) => {
        ({
            let mut testers_vec: Vec<&mut dyn $crate::NetTesterInterface> = Vec::new();
            $(
                testers_vec.push(&mut $testr);
            )*
            ::std::thread::sleep(::std::time::Duration::from_millis(500));
            $crate::_run_testers(testers_vec);
        });
    };
}
