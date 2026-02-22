use std::{cell::RefCell, io, marker::PhantomData, net::SocketAddr, time::{Duration, Instant}};

use anymap2::AnyMap;

use crate::{SocketType, state::{self, wait_for_event}};


/// A trait for types that can be serialized/deserialized as network packets.
///
/// Implementors define how packets are encoded to bytes and decoded from bytes,
/// along with metadata about the socket type and whether the packet can be flattened
/// into multiple sub-packets.
///
/// # Associated Constants
///
/// - `CAN_BE_FLATTENED` — Whether [`flatten`](Packetable::flatten) produces multiple packets.
/// - `SOCKET_TYPE` — Whether this packet type is used over [`Udp`](SocketType::Udp) or [`Tcp`](SocketType::Tcp).
///
/// # Example
///
/// ```
/// use snare::{Packetable, SocketType};
///
/// #[derive(Clone, Debug)]
/// struct BytePacket(Vec<u8>);
///
/// impl Packetable for BytePacket {
///     const CAN_BE_FLATTENED: bool = false;
///     const SOCKET_TYPE: SocketType = SocketType::Udp;
///
///     fn encode(&self) -> Vec<u8> {
///         self.0.clone()
///     }
///
///     fn decode(data: &[u8]) -> Option<(Self, usize)> {
///         if data.is_empty() {
///             None
///         } else {
///             Some((Self(data.to_vec()), data.len()))
///         }
///     }
/// }
///
/// let pkt = BytePacket(vec![1, 2, 3]);
/// let encoded = pkt.encode();
/// let (decoded, len) = BytePacket::decode(&encoded).unwrap();
/// assert_eq!(decoded.0, vec![1, 2, 3]);
/// assert_eq!(len, 3);
/// ```
pub trait Packetable: Clone + Send + Sync + 'static {
    const CAN_BE_FLATTENED: bool;
    const SOCKET_TYPE: SocketType;

    /// Serialize the packet into bytes for transmission.
    fn encode(&self) -> Vec<u8>;

    /// Attempt to deserialize a packet from bytes. Returns the decoded packet and
    /// the number of bytes consumed, or `None` if the data is incomplete or invalid.
    ///
    /// For TCP, `decode` is called repeatedly on a growing buffer, so it must
    /// return the exact byte count consumed to allow the framework to advance
    /// through the stream.
    fn decode(data: &[u8]) -> Option<(Self, usize)>;

    /// Split a packet into multiple sub-packets. The default implementation returns
    /// the packet as-is in a single-element vec.
    fn flatten(&self) -> Vec<Self> {
        vec![self.clone()]
    }
}

/// Marker trait for types that can be stored as per-tester state.
///
/// Automatically implemented for any type that is `Default + Send + Sync + 'static`.
/// Use custom state types with builder methods like [`NetTester::then_stateful_test`],
/// [`NetTester::with_state`], and [`NetTester::until_stateful_condition`].
///
/// ```
/// // Any Default + Send + Sync + 'static type automatically implements StateKey:
/// #[derive(Default)]
/// struct MyState {
///     packet_count: usize,
///     last_seen: Option<std::net::SocketAddr>,
/// }
/// ```
pub trait StateKey: Default + Send + Sync + 'static {}
impl<T: Default + Send + Sync + 'static> StateKey for T {}

/// Built-in state type for tracking elapsed time in a tester.
///
/// The timer starts on the first call to [`poll_elapsed`](TimerState::poll_elapsed)
/// and returns the duration since that first call on subsequent invocations.
/// Commonly used with [`NetTester::until_stateful_condition`] to add timeouts.
///
/// ```
/// use snare::TimerState;
/// use std::time::Duration;
///
/// let mut timer = TimerState::default();
/// // First poll starts the timer and returns zero.
/// assert_eq!(timer.poll_elapsed(), Duration::from_secs(0));
/// // Subsequent polls return elapsed time since the first call.
/// std::thread::sleep(Duration::from_millis(10));
/// assert!(timer.poll_elapsed() >= Duration::from_millis(10));
/// ```
#[derive(Debug, Default)]
pub struct TimerState {
    start_instant: Option<Instant>,
}
impl TimerState {
    /// Returns the duration elapsed since the first call to this method.
    /// The first call always returns [`Duration::from_secs(0)`] and starts the timer.
    pub fn poll_elapsed(&mut self) -> Duration {
        if let Some(start) = self.start_instant {
            Instant::now().duration_since(start)
        } else {
            self.start_instant = Some(Instant::now());
            Duration::from_secs(0)
        }
    }
}

/// An action that a tester can perform in response to a received packet or on a cycle.
///
/// Returned from callbacks passed to [`NetTester::then_action`],
/// [`NetTester::then_stateful_action`], [`NetTester::with_cyclic_action`], and
/// [`NetTester::with_stateful_cyclic_action`].
pub enum TesterAction<T: Packetable> {
    /// Send a packet to the given address.
    Send(SocketAddr, T),
    /// Inject an I/O error on the socket bound to the given address.
    RaiseSocketError(SocketAddr, io::Error),
    /// Close the socket bound to the given address.
    CloseSocket(SocketAddr),
    /// Execute multiple actions in sequence.
    Multiple(Vec<TesterAction<T>>),
}

/// Type-erased interface for [`NetTester`], used internally by [`run_testers!`] to
/// drive testers of different packet types in the same event loop.
pub trait NetTesterInterface {
    /// Feed raw bytes into the tester. For TCP, returns `Some(bytes_consumed)`.
    /// For UDP, returns `None` (each call is one datagram).
    fn test(&mut self, data: &[u8], src_addr: SocketAddr) -> Option<usize>;
    /// Returns the time until the next cyclic action is due, or `None` if there are no cycles.
    fn duration_till_soonest_cycle(&self) -> Option<Duration>;
    /// Execute all cyclic actions whose interval has elapsed.
    fn run_due_cycles(&mut self);
    /// Check whether any finish condition is satisfied.
    fn is_finished(&mut self) -> bool;
    /// The address this tester is bound to.
    fn get_addr(&self) -> SocketAddr;
    /// The socket type (UDP or TCP) this tester operates on.
    fn get_socket_type(&self) -> SocketType;
}

/// A builder and runtime for testing network packet handlers.
///
/// Created via [`connect_tester`], then configured with a chain of builder methods
/// that add packet handlers, cyclic actions, state, and finish conditions. Finally,
/// passed to [`run_testers!`] which drives the event loop until a finish condition
/// is met.
///
/// # Builder pattern
///
/// Methods fall into four categories:
///
/// - **Packet handlers** — [`then_test`](Self::then_test),
///   [`then_stateful_test`](Self::then_stateful_test),
///   [`then_action`](Self::then_action),
///   [`then_stateful_action`](Self::then_stateful_action),
///   [`then_edit_state`](Self::then_edit_state).
///   Called in order for every decoded packet. Returning `None` from a handler
///   stops the chain for that packet.
///
/// - **Cyclic actions** — [`with_cyclic_action`](Self::with_cyclic_action),
///   [`with_stateful_cyclic_action`](Self::with_stateful_cyclic_action).
///   Invoked repeatedly at a fixed interval regardless of incoming packets.
///
/// - **State** — [`with_state`](Self::with_state). Eagerly initializes a state slot.
///
/// - **Finish conditions** — [`until_condition`](Self::until_condition),
///   [`until_stateful_condition`](Self::until_stateful_condition).
///   When any condition returns `true`, [`run_testers!`] exits.
///   If no conditions are registered, the tester finishes when there are no pending
///   packets/data left to process.
///
/// # Example
///
/// ```
/// use snare::*;
/// use std::net::SocketAddr;
/// use std::time::Duration;
///
/// # #[derive(Clone)]
/// # struct Pkt(Vec<u8>);
/// # impl Packetable for Pkt {
/// #     const CAN_BE_FLATTENED: bool = false;
/// #     const SOCKET_TYPE: SocketType = SocketType::Udp;
/// #     fn encode(&self) -> Vec<u8> { self.0.clone() }
/// #     fn decode(data: &[u8]) -> Option<(Self, usize)> {
/// #         if data.is_empty() { None } else { Some((Self(data.to_vec()), data.len())) }
/// #     }
/// # }
/// #[derive(Default)]
/// struct Count(usize);
///
/// register_test();
/// let addr: SocketAddr = "127.0.0.1:19100".parse().unwrap();
///
/// let mut tester = connect_tester::<Pkt>(addr)
///     .with_state::<Count>(|_| {}) // initialize state so peek_state works
///     .then_stateful_test::<Count>(|state, pkt, _addr| {
///         state.0 += 1;
///         Some(pkt)
///     })
///     .until_condition(|| true); // finish immediately for this example
///
/// run_testers!(tester);
/// assert_eq!(tester.peek_state::<Count>().0, 0); // no packets were sent
/// ```
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

    /// Adds a packet handler that has access to typed state `S`.
    ///
    /// The state is lazily initialized via `Default::default()` on first access.
    /// Return `Some(pkt)` to pass the (possibly modified) packet to the next handler
    /// in the chain, or `None` to stop processing this packet.
    ///
    /// ```
    /// use snare::*;
    /// use std::net::SocketAddr;
    ///
    /// # #[derive(Clone)]
    /// # struct Pkt(Vec<u8>);
    /// # impl Packetable for Pkt {
    /// #     const CAN_BE_FLATTENED: bool = false;
    /// #     const SOCKET_TYPE: SocketType = SocketType::Udp;
    /// #     fn encode(&self) -> Vec<u8> { self.0.clone() }
    /// #     fn decode(data: &[u8]) -> Option<(Self, usize)> {
    /// #         if data.is_empty() { None } else { Some((Self(data.to_vec()), data.len())) }
    /// #     }
    /// # }
    /// #[derive(Default)]
    /// struct PacketCount(usize);
    ///
    /// fn count_packets(state: &mut PacketCount, pkt: Pkt, _src: SocketAddr) -> Option<Pkt> {
    ///     state.0 += 1;
    ///     Some(pkt)
    /// }
    ///
    /// register_test();
    /// let addr: SocketAddr = "127.0.0.1:19101".parse().unwrap();
    /// let mut tester = connect_tester::<Pkt>(addr)
    ///     .then_stateful_test(count_packets)
    ///     .until_condition(|| true);
    /// run_testers!(tester);
    /// ```
    pub fn then_stateful_test<S: StateKey>(mut self, tester: fn(&mut S, P, SocketAddr) -> Option<P>) -> NetTester<P> {
        let storable = move |slf: &mut Self, pkt: P, addr: SocketAddr| {
            let state = slf.state.entry::<S>().or_insert_with(Default::default);
            tester(state, pkt, addr)
        };
        self.tests.push(Box::new(storable));
        self
    }

    /// Adds a stateless packet handler.
    ///
    /// Like [`then_stateful_test`](Self::then_stateful_test) but without access to
    /// any state. Return `Some(pkt)` to continue the chain, `None` to stop.
    ///
    /// ```
    /// use snare::*;
    /// use std::net::SocketAddr;
    ///
    /// # #[derive(Clone)]
    /// # struct Pkt(Vec<u8>);
    /// # impl Packetable for Pkt {
    /// #     const CAN_BE_FLATTENED: bool = false;
    /// #     const SOCKET_TYPE: SocketType = SocketType::Udp;
    /// #     fn encode(&self) -> Vec<u8> { self.0.clone() }
    /// #     fn decode(data: &[u8]) -> Option<(Self, usize)> {
    /// #         if data.is_empty() { None } else { Some((Self(data.to_vec()), data.len())) }
    /// #     }
    /// # }
    /// fn reject_empty(pkt: Pkt, _src: SocketAddr) -> Option<Pkt> {
    ///     if pkt.0.is_empty() { None } else { Some(pkt) }
    /// }
    ///
    /// register_test();
    /// let addr: SocketAddr = "127.0.0.1:19102".parse().unwrap();
    /// let mut tester = connect_tester::<Pkt>(addr)
    ///     .then_test(reject_empty)
    ///     .until_condition(|| true);
    /// run_testers!(tester);
    /// ```
    pub fn then_test(mut self, tester: fn(P, SocketAddr) -> Option<P>) -> NetTester<P> {
        let stateless = move |_: &mut Self, pkt: P, addr: SocketAddr| tester(pkt, addr);
        self.tests.push(Box::new(stateless));
        self
    }

    /// Adds a handler that mutates state `S` for each packet without inspecting the
    /// packet itself. The packet is always forwarded unchanged.
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

    /// Adds a handler that performs a [`TesterAction`] with access to typed state `S`.
    ///
    /// The action is enacted immediately (e.g., sending a response packet) and the
    /// original packet is forwarded to the next handler in the chain.
    ///
    /// ```
    /// use snare::*;
    /// use std::net::SocketAddr;
    ///
    /// # #[derive(Clone)]
    /// # struct Pkt(Vec<u8>);
    /// # impl Packetable for Pkt {
    /// #     const CAN_BE_FLATTENED: bool = false;
    /// #     const SOCKET_TYPE: SocketType = SocketType::Udp;
    /// #     fn encode(&self) -> Vec<u8> { self.0.clone() }
    /// #     fn decode(data: &[u8]) -> Option<(Self, usize)> {
    /// #         if data.is_empty() { None } else { Some((Self(data.to_vec()), data.len())) }
    /// #     }
    /// # }
    /// #[derive(Default)]
    /// struct EchoState { sent: usize }
    ///
    /// fn echo_back(state: &mut EchoState, pkt: Pkt, src: SocketAddr) -> TesterAction<Pkt> {
    ///     state.sent += 1;
    ///     TesterAction::Send(src, pkt)
    /// }
    ///
    /// register_test();
    /// let addr: SocketAddr = "127.0.0.1:19103".parse().unwrap();
    /// let mut tester = connect_tester::<Pkt>(addr)
    ///     .then_stateful_action(echo_back)
    ///     .until_condition(|| true);
    /// run_testers!(tester);
    /// ```
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

    /// Adds a stateless handler that performs a [`TesterAction`].
    ///
    /// Like [`then_stateful_action`](Self::then_stateful_action) but without state.
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

    /// Registers a callback that runs repeatedly at a fixed interval with access to
    /// typed state `S`.
    ///
    /// The callback returns `Option<TesterAction<P>>` — return `None` to skip acting
    /// on a given cycle. Cyclic actions run independently of incoming packets and are
    /// useful for heartbeats, periodic polling, or timed sends.
    ///
    /// ```
    /// use snare::*;
    /// use std::net::SocketAddr;
    /// use std::time::Duration;
    ///
    /// # #[derive(Clone)]
    /// # struct Pkt(Vec<u8>);
    /// # impl Packetable for Pkt {
    /// #     const CAN_BE_FLATTENED: bool = false;
    /// #     const SOCKET_TYPE: SocketType = SocketType::Udp;
    /// #     fn encode(&self) -> Vec<u8> { self.0.clone() }
    /// #     fn decode(data: &[u8]) -> Option<(Self, usize)> {
    /// #         if data.is_empty() { None } else { Some((Self(data.to_vec()), data.len())) }
    /// #     }
    /// # }
    /// #[derive(Default)]
    /// struct CycleCount(usize);
    ///
    /// fn tick(state: &mut CycleCount) -> Option<TesterAction<Pkt>> {
    ///     state.0 += 1;
    ///     None // no network action, just bookkeeping
    /// }
    ///
    /// register_test();
    /// let addr: SocketAddr = "127.0.0.1:19104".parse().unwrap();
    /// let mut tester = connect_tester::<Pkt>(addr)
    ///     .with_stateful_cyclic_action::<CycleCount>(Duration::from_millis(5), tick)
    ///     .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_millis(30));
    /// run_testers!(tester);
    /// assert!(tester.peek_state::<CycleCount>().0 >= 3);
    /// ```
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

    /// Registers a stateless callback that runs repeatedly at a fixed interval.
    ///
    /// Like [`with_stateful_cyclic_action`](Self::with_stateful_cyclic_action) but
    /// without access to any state.
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

    /// Eagerly initializes a state slot of type `S` using `Default::default()`, then
    /// calls `initializer` to configure it. Use this to set initial values before the
    /// event loop starts.
    ///
    /// ```
    /// use snare::*;
    /// use std::net::SocketAddr;
    ///
    /// # #[derive(Clone)]
    /// # struct Pkt(Vec<u8>);
    /// # impl Packetable for Pkt {
    /// #     const CAN_BE_FLATTENED: bool = false;
    /// #     const SOCKET_TYPE: SocketType = SocketType::Udp;
    /// #     fn encode(&self) -> Vec<u8> { self.0.clone() }
    /// #     fn decode(data: &[u8]) -> Option<(Self, usize)> {
    /// #         if data.is_empty() { None } else { Some((Self(data.to_vec()), data.len())) }
    /// #     }
    /// # }
    /// #[derive(Default)]
    /// struct Config { expected_count: usize }
    ///
    /// register_test();
    /// let addr: SocketAddr = "127.0.0.1:19105".parse().unwrap();
    /// let mut tester = connect_tester::<Pkt>(addr)
    ///     .with_state::<Config>(|cfg| cfg.expected_count = 10)
    ///     .until_condition(|| true);
    /// run_testers!(tester);
    /// assert_eq!(tester.peek_state::<Config>().expected_count, 10);
    /// ```
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

    /// Adds a stateless finish condition. When `condition` returns `true`,
    /// [`run_testers!`] stops the event loop.
    ///
    /// Multiple conditions can be chained — the tester finishes when **any** of them
    /// returns `true`.
    pub fn until_condition(
        mut self,
        condition: fn() -> bool,
    ) -> NetTester<P> {
        let cond_box = Box::new(move |_: &mut Self| condition());
        self.finish_conditions.push(cond_box);
        self
    }

    /// Adds a finish condition with access to typed state `S`.
    ///
    /// Commonly used with [`TimerState`] to add a timeout:
    ///
    /// ```
    /// use snare::*;
    /// use std::net::SocketAddr;
    /// use std::time::Duration;
    ///
    /// # #[derive(Clone)]
    /// # struct Pkt(Vec<u8>);
    /// # impl Packetable for Pkt {
    /// #     const CAN_BE_FLATTENED: bool = false;
    /// #     const SOCKET_TYPE: SocketType = SocketType::Udp;
    /// #     fn encode(&self) -> Vec<u8> { self.0.clone() }
    /// #     fn decode(data: &[u8]) -> Option<(Self, usize)> {
    /// #         if data.is_empty() { None } else { Some((Self(data.to_vec()), data.len())) }
    /// #     }
    /// # }
    /// register_test();
    /// let addr: SocketAddr = "127.0.0.1:19106".parse().unwrap();
    /// let mut tester = connect_tester::<Pkt>(addr)
    ///     .until_stateful_condition::<TimerState>(|t| {
    ///         t.poll_elapsed() >= Duration::from_millis(50)
    ///     });
    /// run_testers!(tester);
    /// ```
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

    /// Returns a reference to the state of type `S`.
    ///
    /// Typically called after [`run_testers!`] has finished to inspect the final
    /// state and make test assertions.
    ///
    /// # Panics
    ///
    /// Panics if no state of type `S` was ever initialized (either via
    /// [`with_state`](Self::with_state) or lazily by a stateful handler).
    pub fn peek_state<'a, S: StateKey>(
        &'a self
    ) -> &'a S {
        self.state.get::<S>()
            .expect("State for type was not found")
    }
}

/// Creates a new [`NetTester`] bound to the given address.
///
/// For TCP packet types this also registers a virtual listener on the address.
/// The returned tester is configured via the builder methods on [`NetTester`] and
/// then driven by [`run_testers!`].
///
/// Must be called after [`register_test`](crate::register_test).
///
/// ```
/// use snare::*;
/// use std::net::SocketAddr;
///
/// # #[derive(Clone)]
/// # struct Pkt(Vec<u8>);
/// # impl Packetable for Pkt {
/// #     const CAN_BE_FLATTENED: bool = false;
/// #     const SOCKET_TYPE: SocketType = SocketType::Udp;
/// #     fn encode(&self) -> Vec<u8> { self.0.clone() }
/// #     fn decode(data: &[u8]) -> Option<(Self, usize)> {
/// #         if data.is_empty() { None } else { Some((Self(data.to_vec()), data.len())) }
/// #     }
/// # }
/// register_test();
/// let addr: SocketAddr = "127.0.0.1:19107".parse().unwrap();
/// let mut tester = connect_tester::<Pkt>(addr)
///     .until_condition(|| true);
/// run_testers!(tester);
/// ```
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

    fn duration_till_soonest_cycle(& self) -> Option<Duration> {
        NetTester::duration_till_soonest_cycle(self)
    }

    fn run_due_cycles(& mut self) {
        NetTester::run_due_cycles(self);
    }

    fn is_finished(&mut self) -> bool {
        let mut finishe_conditions = std::mem::take(&mut self.finish_conditions);
        if finishe_conditions.is_empty() {
            let has_pending = match P::SOCKET_TYPE {
                SocketType::Udp => state::has_pending_udp_packet(self.addr),
                SocketType::Tcp => state::has_pending_tcp_data(self.addr),
            };
            self.finish_conditions = finishe_conditions;
            return !has_pending;
        }
        for condition in finishe_conditions.iter_mut() {
            if condition(self) {
                self.finish_conditions = finishe_conditions;
                return true
            }
        }
        self.finish_conditions = finishe_conditions;
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

        let duration = min_duration.unwrap_or_else(|| Duration::from_millis(10));
        if duration > Duration::from_secs(0) {
            wait_for_event(Some(duration));
        }
    }
}

/// Drives one or more [`NetTester`]s in a shared event loop until any tester's
/// finish condition is met.
///
/// Accepts a comma-separated list of tester bindings. Panics if two testers share
/// the same address **and** socket type.
///
/// The macro sleeps briefly before entering the loop to allow spawned client threads
/// to start up.
///
/// # Example
///
/// ```
/// use snare::*;
/// use std::net::SocketAddr;
///
/// # #[derive(Clone)]
/// # struct Pkt(Vec<u8>);
/// # impl Packetable for Pkt {
/// #     const CAN_BE_FLATTENED: bool = false;
/// #     const SOCKET_TYPE: SocketType = SocketType::Udp;
/// #     fn encode(&self) -> Vec<u8> { self.0.clone() }
/// #     fn decode(data: &[u8]) -> Option<(Self, usize)> {
/// #         if data.is_empty() { None } else { Some((Self(data.to_vec()), data.len())) }
/// #     }
/// # }
/// register_test();
///
/// let addr_a: SocketAddr = "127.0.0.1:19108".parse().unwrap();
/// let addr_b: SocketAddr = "127.0.0.1:19109".parse().unwrap();
///
/// let mut tester_a = connect_tester::<Pkt>(addr_a)
///     .until_condition(|| true);
/// let mut tester_b = connect_tester::<Pkt>(addr_b)
///     .until_condition(|| true);
///
/// // Run both testers concurrently in the same event loop:
/// run_testers!(tester_a, tester_b);
/// ```
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