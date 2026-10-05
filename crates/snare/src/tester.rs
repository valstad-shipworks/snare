//! The peer side of a test: a builder that describes how to answer the code under test, in the
//! spirit of the original snare's `connect_tester` / `then_action` / `with_cyclic_action` /
//! `run_testers!` — over TCP ([`connect_tester`]) or UDP ([`udp_tester`]), with typed state,
//! peer-initiated sends on the (virtual) clock, and a record of what the code under test sent.
//!
//! ```no_run
//! use std::time::Duration;
//! use snare::{Line, Sim, TesterAction, connect_tester, run_testers};
//!
//! #[derive(Default)]
//! struct Seen(Vec<String>);
//!
//! Sim::new().run(|| {
//!     let server = connect_tester::<Line>("127.0.0.2:9000")
//!         .with_state(Seen::default())
//!         .then_stateful_action(|seen, msg, _from| {
//!             seen.0.push(msg.0.clone());
//!             TesterAction::Send(Line(format!("ack {}", msg.0)))
//!         })
//!         .until_state(|seen| seen.0.len() == 3)
//!         .until_after(Duration::from_secs(5));
//!
//!     // ... start the code under test on its own thread ...
//!
//!     run_testers!(server);
//!     server.inspect(|seen| assert_eq!(seen.0, ["a", "b", "c"]));
//! });
//! ```
//!
//! A tester runs on a thread of its own inside the sim but plays the far side of the network: it
//! reaches the code under test through the backend's peer half (`fabric` on unix, `win_net` on
//! Windows) rather than through interposed socket calls, so its traffic is never counted as the
//! code under test's. Its sleeps and waits go through the sim's readiness signal and clock.

use std::net::{SocketAddr, ToSocketAddrs};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::events::{Direction, RecordedEvent, Toward, Transport};
#[cfg(unix)]
use crate::fabric as peer;
use crate::faults::ListenerBehavior;
use crate::packet::Packet;
use crate::readiness::{Deadline, readiness};
use crate::scope::SimShared;
#[cfg(windows)]
use crate::win_net as peer;
use peer::{Conn, Listener, Registries, UdpEndpoint};

/// What a tester does in response to a message, a new peer, or a cyclic tick.
pub enum TesterAction<P> {
    /// Do nothing.
    Nothing,
    /// Send one message to the peer the event came from: the connection a TCP message arrived on,
    /// or the source of a UDP datagram. From a cyclic action, which has no sender, it goes to
    /// every peer: each open connection, or each address a datagram has come from.
    Send(P),
    /// Send one message to a specific address. Over TCP that is the open connection from that
    /// client address; over UDP, a datagram from the tester's address to any destination — a
    /// socket, a wildcard-bound port, the broadcast address or a multicast group.
    SendTo(SocketAddr, P),
    /// Several [`Send`](TesterAction::Send)s, in order.
    SendAll(Vec<P>),
    /// Close the connection the event came from (from a cyclic action, every connection), so the
    /// code under test reads end-of-stream. Nothing to close over UDP, so it does nothing there.
    Close,
    /// Several actions, in order.
    Multiple(Vec<TesterAction<P>>),
    /// Abort the connection the event came from (from a cyclic action, every connection) with a
    /// TCP reset: the code under test's next read or write fails with `ECONNRESET`
    /// (`WSAECONNRESET`), "a connection was forcibly closed by a peer" (POSIX `recv()` and
    /// `send()`; Microsoft Learn "recv" and "send"). Nothing to reset over UDP.
    Reset,
    /// Go silent toward the peer the event came from (from a cyclic action, every peer) for this
    /// long: its messages are read and dropped, and nothing is sent to it — a peer that hangs.
    Quiesce(Duration),
    /// Answer new connects to the tester's own address as `behavior` says (see
    /// [`set_listener_behavior`](crate::set_listener_behavior)). Nothing to answer over UDP.
    SetListenerBehavior(ListenerBehavior),
    /// Make the error pending on the code under test's socket the event came from (from a cyclic
    /// action, every peer's), as [`raise_socket_error`](crate::raise_socket_error) does.
    RaiseSocketError(std::io::Error),
    /// Answer the datagram the event came from (from a cyclic action, every peer) with an ICMP
    /// port unreachable from the tester's address, as
    /// [`inject_icmp_port_unreachable`](crate::inject_icmp_port_unreachable) does. Nothing over
    /// TCP.
    IcmpPortUnreachable,
    /// Hold the link to the peer the event came from (from a cyclic action, every peer) for this
    /// long, in the direction seen from the code under test (see [`quiesce`](crate::quiesce)):
    /// [`Receive`](Direction::Receive) holds what reaches the code under test.
    QuiesceLink(Duration, Direction),
    /// Set the receive window of the code under test's end the event came from (from a cyclic
    /// action, every peer's), as [`TcpPolicy::recv_window`](crate::TcpPolicy::recv_window) does at
    /// its address: the tester's writes then wait for it to read.
    SetRecvWindow(Option<usize>),
}

/// A message handler: tester state, the sender's connection state, message, sender; returns what
/// to do.
type OnMessage<P, S, C> = Box<dyn FnMut(&mut S, &mut C, P, SocketAddr) -> TesterAction<P> + Send>;
/// A filter stage: passes a (possibly rewritten) message on, or drops it with `None`.
type OnFilter<P, S, C> = Box<dyn FnMut(&mut S, &mut C, P, SocketAddr) -> Option<P> + Send>;
/// A new-peer handler: tester state, the new peer's connection state and its address.
type OnPeer<P, S, C> = Box<dyn FnMut(&mut S, &mut C, SocketAddr) -> TesterAction<P> + Send>;
/// A cyclic action run once per tick.
type OnTick<P, S> = Box<dyn FnMut(&mut S) -> TesterAction<P> + Send>;
/// A cyclic action run once per tick for each peer, with that peer's connection state.
type OnConnTick<P, S, C> = Box<dyn FnMut(&mut S, &mut C, SocketAddr) -> TesterAction<P> + Send>;
/// Makes a new peer's connection state from its address.
type NewConn<C> = Box<dyn FnMut(SocketAddr) -> C + Send>;

/// A finish condition on the tester state and the time elapsed since the run started.
type OnElapsed<S> = Box<dyn FnMut(&S, Duration) -> bool + Send>;
/// A finish condition on the tester state and every peer's connection state.
type OnConns<S, C> = Box<dyn FnMut(&S, &[(SocketAddr, C)]) -> bool + Send>;

/// A finish condition.
enum Finish<S, C> {
    /// Sees the tester state and the time elapsed since the run started.
    State(OnElapsed<S>),
    /// Sees the tester state and every peer's connection state.
    Conns(OnConns<S, C>),
}

/// One stage of the chain each message the code under test sends runs through, in the order the
/// stages were added.
enum Handler<P, S, C> {
    /// Acts on the message; the message continues to later stages.
    Act(OnMessage<P, S, C>),
    /// Passes the message on, rewritten or not, or drops it.
    Filter(OnFilter<P, S, C>),
}

/// What a cyclic action runs on each tick.
enum Tick<P, S, C> {
    /// Once, toward every peer.
    Once(OnTick<P, S>),
    /// Once for each live peer, toward that peer.
    PerConn(OnConnTick<P, S, C>),
}

/// An action run every `period`, first `phase` after the run starts.
struct Cyclic<P, S, C> {
    period: Duration,
    phase: Duration,
    action: Tick<P, S, C>,
    /// When it next runs; set to `phase` after the start when the run begins.
    next: Instant,
}

/// How a tester meets the code under test.
enum TesterTransport {
    /// A listener at the tester's address, registered in the sim so the code under test's
    /// connects reach it; withdrawn when the run ends.
    Tcp(Arc<Listener>),
    /// A datagram endpoint bound at the tester's address.
    Udp(UdpEndpoint),
}

/// Everything about a tester its run mutates, behind one lock so a tester can be run through a
/// shared reference and inspected once the run is over.
struct Inner<P, S, C> {
    transport: TesterTransport,
    /// The sim's peer-side registries (listeners, endpoints, the shared services), captured on
    /// the building thread so the tester can run on any thread.
    regs: Arc<Registries>,
    state: S,
    new_conn: NewConn<C>,
    /// Each peer of the last run and its connection state, in the order the peers appeared: one
    /// per TCP connection accepted, closed ones included, or one per UDP source address.
    conns: Vec<(SocketAddr, C)>,
    handlers: Vec<Handler<P, S, C>>,
    on_peer: Vec<OnPeer<P, S, C>>,
    cyclic: Vec<Cyclic<P, S, C>>,
    finish: Vec<Finish<S, C>>,
    /// The earliest `until_after` span, so the run can wake for it rather than poll.
    deadline: Option<Duration>,
    /// Whether an opaque [`until`](Tester::until) condition must be re-checked as time passes: it
    /// may watch elapsed time or a flag the test sets, neither of which wakes the tester.
    poll: bool,
}

/// How often an opaque [`until`](Tester::until) condition is re-checked while nothing else wakes
/// the tester. Under a virtual clock these checks are what carry time forward to it. A snare
/// choice: fine enough for timing-sensitive tests, coarse enough that an idle tester costs little
/// real time; an as-fast-as-possible clock also steps by it.
const UNTIL_POLL: Duration = Duration::from_millis(1);

/// Plays the peer at an address the code under test talks to. Build it with [`connect_tester`]
/// or [`udp_tester`], describe its behaviour, drive it with [`run_testers!`](crate::run_testers),
/// then read back its state ([`inspect`](Tester::inspect)) or what it received
/// ([`recorded`](Tester::recorded)).
///
/// Every handler, cyclic action and finish condition added runs; none replaces another. A tester
/// with no finish condition is a background peer: it runs until every tester in the same
/// `run_testers!` that has one has finished.
///
/// State comes at two levels. `S`, set with [`with_state`](Tester::with_state), is the tester's
/// own: one value every handler shares, as a device's global registers are. `C`, set with
/// [`with_conn_state`](Tester::with_conn_state), is one value per peer — each TCP connection
/// accepted, or each address UDP datagrams come from — as a device keeps a session per client;
/// the `conn` variants of the builder methods see both.
pub struct Tester<P: Packet, S = (), C = ()> {
    addr: SocketAddr,
    /// Locked for the whole of a run, so [`inspect`](Tester::inspect) during one panics rather
    /// than wait.
    inner: Mutex<Inner<P, S, C>>,
    /// Set by [`recording`](Tester::recording); shared with every [`Recorder`] handed out.
    recorder: Option<Recorder<P>>,
}

/// Registers a TCP tester as the peer the code under test will connect to at `addr`.
pub fn connect_tester<P: Packet>(addr: impl ToSocketAddrs) -> Tester<P> {
    let addr = resolve(addr);
    Tester::new(addr, TesterTransport::Tcp(peer::listen_at(addr)))
}

/// Binds a UDP tester at `addr`: datagrams the code under test sends there reach its handlers,
/// with their source address, and what it sends carries `addr` as the source.
pub fn udp_tester<P: Packet>(addr: impl ToSocketAddrs) -> Tester<P> {
    let addr = resolve(addr);
    Tester::new(
        addr,
        TesterTransport::Udp(UdpEndpoint::bind(peer::registries_here(), addr)),
    )
}

/// The first address `addr` resolves to. Panics when it does not parse or resolves to nothing.
fn resolve(addr: impl ToSocketAddrs) -> SocketAddr {
    addr.to_socket_addrs()
        .expect("tester address must parse")
        .next()
        .expect("tester address resolved to nothing")
}

impl<P: Packet> Tester<P> {
    /// A stateless tester at `addr` with nothing to do yet.
    fn new(addr: SocketAddr, transport: TesterTransport) -> Self {
        Tester {
            addr,
            inner: Mutex::new(Inner {
                transport,
                regs: peer::registries_here(),
                state: (),
                new_conn: Box::new(|_| ()),
                conns: Vec::new(),
                handlers: Vec::new(),
                on_peer: Vec::new(),
                cyclic: Vec::new(),
                finish: Vec::new(),
                deadline: None,
                poll: false,
            }),
            recorder: None,
        }
    }
}

impl<P: Packet, C: Send + 'static> Tester<P, (), C> {
    /// Gives the tester `state`, handed to every stateful handler, cyclic action and condition,
    /// and readable after the run with [`inspect`](Tester::inspect). Handlers added before this
    /// keep working; they just don't see the state.
    pub fn with_state<T: Send + 'static>(self, state: T) -> Tester<P, T, C> {
        let inner = self.inner.into_inner().unwrap();
        Tester {
            addr: self.addr,
            recorder: self.recorder,
            inner: Mutex::new(Inner {
                transport: inner.transport,
                regs: inner.regs,
                state,
                new_conn: inner.new_conn,
                conns: inner.conns,
                handlers: inner
                    .handlers
                    .into_iter()
                    .map(|handler| match handler {
                        Handler::Act(mut f) => {
                            Handler::Act(Box::new(move |_: &mut T, c, m, a| f(&mut (), c, m, a)))
                        }
                        Handler::Filter(mut f) => {
                            Handler::Filter(Box::new(move |_: &mut T, c, m, a| f(&mut (), c, m, a)))
                        }
                    })
                    .collect(),
                on_peer: inner
                    .on_peer
                    .into_iter()
                    .map(|mut f| {
                        Box::new(move |_: &mut T, c: &mut C, a| f(&mut (), c, a)) as OnPeer<P, T, C>
                    })
                    .collect(),
                cyclic: inner
                    .cyclic
                    .into_iter()
                    .map(|c| Cyclic {
                        period: c.period,
                        phase: c.phase,
                        next: c.next,
                        action: match c.action {
                            Tick::Once(mut f) => Tick::Once(Box::new(move |_: &mut T| f(&mut ()))),
                            Tick::PerConn(mut f) => {
                                Tick::PerConn(Box::new(move |_: &mut T, conn: &mut C, a| {
                                    f(&mut (), conn, a)
                                }))
                            }
                        },
                    })
                    .collect(),
                finish: inner
                    .finish
                    .into_iter()
                    .map(|finish| match finish {
                        Finish::State(mut f) => Finish::State(Box::new(move |_: &T, e| f(&(), e))),
                        Finish::Conns(mut f) => {
                            Finish::Conns(Box::new(move |_: &T, conns| f(&(), conns)))
                        }
                    })
                    .collect(),
                deadline: inner.deadline,
                poll: inner.poll,
            }),
        }
    }
}

impl<P: Packet, S: Send + 'static> Tester<P, S, ()> {
    /// Gives each peer a connection state of its own, made by `new` from the peer's address when
    /// it appears: as a TCP connection is accepted, or as the first datagram arrives from a UDP
    /// address. A real device keeps such a session per client; a second connection from the same
    /// client starts a fresh one.
    ///
    /// The `conn` builder methods — [`then_conn_action`](Tester::then_conn_action),
    /// [`then_conn_test`](Tester::then_conn_test), [`on_conn_connect`](Tester::on_conn_connect),
    /// [`with_conn_cyclic_action`](Tester::with_conn_cyclic_action) and
    /// [`until_conns`](Tester::until_conns) — see it alongside the tester's state, and
    /// [`inspect_conns`](Tester::inspect_conns) reads every peer's after the run. The states of
    /// a run are kept until the next run starts, closed connections' included. Handlers added
    /// before this keep working; they just don't see it.
    pub fn with_conn_state<D: Send + 'static>(
        self,
        new: impl FnMut(SocketAddr) -> D + Send + 'static,
    ) -> Tester<P, S, D> {
        let inner = self.inner.into_inner().unwrap();
        Tester {
            addr: self.addr,
            recorder: self.recorder,
            inner: Mutex::new(Inner {
                transport: inner.transport,
                regs: inner.regs,
                state: inner.state,
                new_conn: Box::new(new),
                conns: Vec::new(),
                handlers: inner
                    .handlers
                    .into_iter()
                    .map(|handler| match handler {
                        Handler::Act(mut f) => {
                            Handler::Act(Box::new(move |s, _: &mut D, m, a| f(s, &mut (), m, a)))
                        }
                        Handler::Filter(mut f) => {
                            Handler::Filter(Box::new(move |s, _: &mut D, m, a| f(s, &mut (), m, a)))
                        }
                    })
                    .collect(),
                on_peer: inner
                    .on_peer
                    .into_iter()
                    .map(|mut f| {
                        Box::new(move |s: &mut S, _: &mut D, a| f(s, &mut (), a)) as OnPeer<P, S, D>
                    })
                    .collect(),
                cyclic: inner
                    .cyclic
                    .into_iter()
                    .map(|c| Cyclic {
                        period: c.period,
                        phase: c.phase,
                        next: c.next,
                        action: match c.action {
                            Tick::Once(f) => Tick::Once(f),
                            Tick::PerConn(mut f) => {
                                Tick::PerConn(Box::new(move |s: &mut S, _: &mut D, a| {
                                    f(s, &mut (), a)
                                }))
                            }
                        },
                    })
                    .collect(),
                finish: inner
                    .finish
                    .into_iter()
                    .map(|finish| match finish {
                        Finish::State(f) => Finish::State(f),
                        Finish::Conns(mut f) => {
                            Finish::Conns(Box::new(move |s: &S, conns: &[(SocketAddr, D)]| {
                                let peers: Vec<(SocketAddr, ())> =
                                    conns.iter().map(|&(a, _)| (a, ())).collect();
                                f(s, &peers)
                            }))
                        }
                    })
                    .collect(),
                deadline: inner.deadline,
                poll: inner.poll,
            }),
        }
    }
}

impl<P: Packet, S: Send + 'static, C: Send + 'static> Tester<P, S, C> {
    /// The tester's insides while it is being built, through `&mut` so no lock is taken.
    fn setup(&mut self) -> &mut Inner<P, S, C> {
        self.inner.get_mut().unwrap()
    }

    /// Responds to each message the code under test sends.
    pub fn then_action(
        mut self,
        mut action: impl FnMut(P, SocketAddr) -> TesterAction<P> + Send + 'static,
    ) -> Self {
        self.setup()
            .handlers
            .push(Handler::Act(Box::new(move |_, _, m, from| action(m, from))));
        self
    }

    /// Responds to each message the code under test sends, with the tester's state.
    pub fn then_stateful_action(
        mut self,
        mut action: impl FnMut(&mut S, P, SocketAddr) -> TesterAction<P> + Send + 'static,
    ) -> Self {
        self.setup()
            .handlers
            .push(Handler::Act(Box::new(move |s, _, m, from| {
                action(s, m, from)
            })));
        self
    }

    /// Responds to each message the code under test sends, with the sending peer's connection
    /// state (see [`with_conn_state`](Tester::with_conn_state)) and the tester's state.
    pub fn then_conn_action(
        mut self,
        mut action: impl FnMut(&mut C, &mut S, P, SocketAddr) -> TesterAction<P> + Send + 'static,
    ) -> Self {
        self.setup()
            .handlers
            .push(Handler::Act(Box::new(move |s, c, m, from| {
                action(c, s, m, from)
            })));
        self
    }

    /// Passes each message through `test` before the stages added after it: `Some` hands them
    /// that message, rewritten or not, and `None` drops it there, so no later stage sees it.
    /// Stages added earlier have already run.
    pub fn then_test(
        mut self,
        mut test: impl FnMut(P, SocketAddr) -> Option<P> + Send + 'static,
    ) -> Self {
        self.setup()
            .handlers
            .push(Handler::Filter(Box::new(move |_, _, m, from| {
                test(m, from)
            })));
        self
    }

    /// As [`then_test`](Tester::then_test), with the tester's state.
    pub fn then_stateful_test(
        mut self,
        mut test: impl FnMut(&mut S, P, SocketAddr) -> Option<P> + Send + 'static,
    ) -> Self {
        self.setup()
            .handlers
            .push(Handler::Filter(Box::new(move |s, _, m, from| {
                test(s, m, from)
            })));
        self
    }

    /// As [`then_test`](Tester::then_test), with the sending peer's connection state and the
    /// tester's state.
    pub fn then_conn_test(
        mut self,
        mut test: impl FnMut(&mut C, &mut S, P, SocketAddr) -> Option<P> + Send + 'static,
    ) -> Self {
        self.setup()
            .handlers
            .push(Handler::Filter(Box::new(move |s, c, m, from| {
                test(c, s, m, from)
            })));
        self
    }

    /// Updates the tester's state for each message that reaches this stage, then passes the
    /// message on unchanged.
    pub fn then_edit_state(
        mut self,
        mut edit: impl FnMut(&mut S, SocketAddr) + Send + 'static,
    ) -> Self {
        self.setup()
            .handlers
            .push(Handler::Filter(Box::new(move |state, _, m, from| {
                edit(state, from);
                Some(m)
            })));
        self
    }

    /// Acts when a new peer appears: a TCP connection is accepted, or the first datagram arrives
    /// from a UDP address — the place to greet a client or learn its address.
    pub fn on_connect(
        mut self,
        mut action: impl FnMut(&mut S, SocketAddr) -> TesterAction<P> + Send + 'static,
    ) -> Self {
        self.setup()
            .on_peer
            .push(Box::new(move |s, _, from| action(s, from)));
        self
    }

    /// As [`on_connect`](Tester::on_connect), with the new peer's connection state, just made by
    /// [`with_conn_state`](Tester::with_conn_state)'s constructor, and the tester's state.
    pub fn on_conn_connect(
        mut self,
        mut action: impl FnMut(&mut C, &mut S, SocketAddr) -> TesterAction<P> + Send + 'static,
    ) -> Self {
        self.setup()
            .on_peer
            .push(Box::new(move |s, c, from| action(c, s, from)));
        self
    }

    /// Runs `action` every `period` of (virtual) time, first one period after the run starts.
    /// A plain [`Send`](TesterAction::Send) goes to every peer; use
    /// [`SendTo`](TesterAction::SendTo) to stream to an address that has not sent anything.
    /// Panics if `period` is zero.
    pub fn with_cyclic_action(
        self,
        period: Duration,
        action: impl FnMut() -> TesterAction<P> + Send + 'static,
    ) -> Self {
        self.with_cyclic_action_at(period, period, action)
    }

    /// As [`with_cyclic_action`](Tester::with_cyclic_action), with the tester's state.
    pub fn with_stateful_cyclic_action(
        self,
        period: Duration,
        action: impl FnMut(&mut S) -> TesterAction<P> + Send + 'static,
    ) -> Self {
        self.with_stateful_cyclic_action_at(period, period, action)
    }

    /// Runs `action` at `phase` into the run and every `period` after that: at `phase`,
    /// `phase + period`, `phase + 2 * period`, ... measured from the moment the run starts. Two
    /// emitters on the same `period` with phases `period / 2` apart tick exactly half a cycle
    /// apart; [`with_cyclic_action`](Tester::with_cyclic_action) is a `phase` of one `period`, and
    /// a `phase` of zero runs at the start. Testers in one [`run_testers!`](crate::run_testers)
    /// share that start, so phases line up across them. Panics if `period` is zero.
    pub fn with_cyclic_action_at(
        self,
        period: Duration,
        phase: Duration,
        mut action: impl FnMut() -> TesterAction<P> + Send + 'static,
    ) -> Self {
        self.with_stateful_cyclic_action_at(period, phase, move |_| action())
    }

    /// As [`with_cyclic_action_at`](Tester::with_cyclic_action_at), with the tester's state.
    pub fn with_stateful_cyclic_action_at(
        mut self,
        period: Duration,
        phase: Duration,
        action: impl FnMut(&mut S) -> TesterAction<P> + Send + 'static,
    ) -> Self {
        self.push_cyclic(period, phase, Tick::Once(Box::new(action)));
        self
    }

    /// Runs `action` every `period`, first one period after the run starts, once for each live
    /// peer — each open TCP connection, or each address a datagram has come from — in the order
    /// they appeared, with that peer's connection state, the tester's state and the peer's
    /// address. A plain [`Send`](TesterAction::Send) (and every other action aimed at "the peer
    /// the event came from") goes to that peer only. A peer that appears mid-run joins at the
    /// next tick. Panics if `period` is zero.
    pub fn with_conn_cyclic_action(
        self,
        period: Duration,
        action: impl FnMut(&mut C, &mut S, SocketAddr) -> TesterAction<P> + Send + 'static,
    ) -> Self {
        self.with_conn_cyclic_action_at(period, period, action)
    }

    /// As [`with_conn_cyclic_action`](Tester::with_conn_cyclic_action), first at `phase` into
    /// the run, as [`with_cyclic_action_at`](Tester::with_cyclic_action_at) does.
    pub fn with_conn_cyclic_action_at(
        mut self,
        period: Duration,
        phase: Duration,
        mut action: impl FnMut(&mut C, &mut S, SocketAddr) -> TesterAction<P> + Send + 'static,
    ) -> Self {
        self.push_cyclic(
            period,
            phase,
            Tick::PerConn(Box::new(move |s, c, from| action(c, s, from))),
        );
        self
    }

    /// Adds a cyclic action. Panics if `period` is zero.
    fn push_cyclic(&mut self, period: Duration, phase: Duration, action: Tick<P, S, C>) {
        assert!(
            !period.is_zero(),
            "a cyclic action's period must not be zero"
        );
        self.setup().cyclic.push(Cyclic {
            period,
            phase,
            action,
            next: Instant::now(),
        });
    }

    /// Finishes once `condition(elapsed)` returns true. Any finish condition firing ends the run.
    /// The condition is re-checked every millisecond while the tester is otherwise idle, so it can
    /// watch the clock or a flag the test sets; prefer [`until_after`](Tester::until_after) for a
    /// plain deadline and [`until_state`](Tester::until_state) for the tester's own progress.
    pub fn until(mut self, mut condition: impl FnMut(Duration) -> bool + Send + 'static) -> Self {
        let inner = self.setup();
        inner.poll = true;
        inner.finish.push(Finish::State(Box::new(move |_, elapsed| {
            condition(elapsed)
        })));
        self
    }

    /// Finishes once `condition` holds of the tester's state.
    pub fn until_state(mut self, mut condition: impl FnMut(&S) -> bool + Send + 'static) -> Self {
        self.setup()
            .finish
            .push(Finish::State(Box::new(move |state, _| condition(state))));
        self
    }

    /// Finishes once `condition` holds of the tester's state and every peer's connection state,
    /// given as (peer address, state) in the order the peers appeared, closed connections
    /// included.
    pub fn until_conns(
        mut self,
        condition: impl FnMut(&S, &[(SocketAddr, C)]) -> bool + Send + 'static,
    ) -> Self {
        self.setup().finish.push(Finish::Conns(Box::new(condition)));
        self
    }

    /// Finishes once `duration` has elapsed.
    pub fn until_after(mut self, duration: Duration) -> Self {
        let inner = self.setup();
        inner.deadline = Some(inner.deadline.map_or(duration, |d| d.min(duration)));
        self
    }

    /// Keeps every message the code under test sends, with its source — before any stage of the
    /// chain sees it, so a message a [`then_test`](Tester::then_test) drops is still kept — for
    /// [`recorded`](Tester::recorded) after the run or a [`recorder`](Tester::recorder) during it.
    pub fn recording(mut self) -> Self {
        self.recorder = Some(Recorder::default());
        self
    }

    /// The address this tester serves.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// A handle onto what the tester has received so far, readable from any thread while it runs.
    /// Panics unless the tester was built with [`recording`](Tester::recording).
    pub fn recorder(&self) -> Recorder<P> {
        self.recorder
            .clone()
            .expect("call .recording() on the tester to record what it receives")
    }

    /// Every message received, with its source, in arrival order. Panics unless the tester was
    /// built with [`recording`](Tester::recording).
    pub fn recorded(&self) -> Vec<(SocketAddr, P)> {
        self.recorder().snapshot()
    }

    /// Reads the tester's state. Meant for after the run: panics while the tester is running,
    /// since its handlers own the state then (share an `Arc` through the state to watch it live).
    pub fn inspect<R>(&self, read: impl FnOnce(&S) -> R) -> R {
        let inner = match self.inner.try_lock() {
            Ok(inner) => inner,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                panic!("Tester::inspect called while the tester is running")
            }
        };
        read(&inner.state)
    }

    /// Reads every peer's connection state from the last run, as (peer address, state) in the
    /// order the peers appeared, closed connections included. Like [`inspect`](Tester::inspect),
    /// meant for after the run: panics while the tester is running.
    pub fn inspect_conns<R>(&self, read: impl FnOnce(&[(SocketAddr, C)]) -> R) -> R {
        let inner = match self.inner.try_lock() {
            Ok(inner) => inner,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                panic!("Tester::inspect_conns called while the tester is running")
            }
        };
        read(&inner.conns)
    }

    /// Takes the tester's state back, ending the tester.
    pub fn into_state(self) -> S {
        self.inner
            .into_inner()
            .unwrap_or_else(|e| e.into_inner())
            .state
    }

    /// Runs the tester on the calling thread until one of its finish conditions fires.
    /// [`run_testers!`](crate::run_testers) runs several at once.
    pub fn run(&self) {
        self.run_until(&AtomicBool::new(false), Instant::now());
    }
}

/// What a tester received, shared with the code driving the test. Cheap to clone.
pub struct Recorder<P> {
    /// (source, message) pairs in arrival order. A plain lock: pushes happen on the tester's
    /// thread, reads on any thread, and neither blocks on the sim.
    received: Arc<Mutex<Vec<(SocketAddr, P)>>>,
}

impl<P> Clone for Recorder<P> {
    fn clone(&self) -> Self {
        Recorder {
            received: self.received.clone(),
        }
    }
}

impl<P> Default for Recorder<P> {
    fn default() -> Self {
        Recorder {
            received: Arc::default(),
        }
    }
}

impl<P: Clone> Recorder<P> {
    /// Every message received so far, with its source, in arrival order.
    pub fn snapshot(&self) -> Vec<(SocketAddr, P)> {
        self.received.lock().unwrap().clone()
    }

    /// How many messages have been received so far.
    pub fn len(&self) -> usize {
        self.received.lock().unwrap().len()
    }

    /// Whether nothing has been received yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Keeps a copy of `message` from `from`.
    fn push(&self, from: SocketAddr, message: &P) {
        self.received.lock().unwrap().push((from, message.clone()));
    }
}

/// Where a tester's traffic is logged: the sim's event log, under the tester's own address.
struct Log<'a> {
    shared: &'a SimShared,
    tester: SocketAddr,
}

impl Log<'_> {
    /// Records a message of `len` bytes received from `peer`.
    fn received(&self, transport: Transport, peer: SocketAddr, len: usize) {
        self.shared.record(RecordedEvent::Received {
            transport,
            tester: self.tester,
            peer,
            len,
        });
    }

    /// Records `len` bytes sent to `peer`.
    fn sent(&self, transport: Transport, peer: SocketAddr, len: usize) {
        self.shared.record(RecordedEvent::Sent {
            transport,
            tester: self.tester,
            peer,
            len,
        });
    }

    /// Records `len` bytes dropped while quiesced toward `peer`.
    fn suppressed(&self, peer: SocketAddr, toward: Toward, len: usize) {
        self.shared.record(RecordedEvent::Suppressed {
            tester: self.tester,
            peer,
            toward,
            len,
        });
    }

    /// Records that the tester went silent toward `peer` for `span`.
    fn quiesced(&self, peer: SocketAddr, span: Duration) {
        self.shared.record(RecordedEvent::Quiesced {
            tester: self.tester,
            peer,
            span,
        });
    }
}

/// A TCP connection the tester accepted.
struct Peer {
    conn: Arc<Conn>,
    /// Bytes read from the connection that do not yet make a whole message.
    buf: Vec<u8>,
    /// What the tester sent that the connection's window has not taken yet.
    outbox: Vec<u8>,
    /// The code under test closed its end: nothing more to read, nowhere to write.
    gone: bool,
    /// The tester's end is finished: it closed or reset it, or the code under test reset it.
    closed: bool,
    /// The tester closes its end once the outbox has gone.
    closing: bool,
    /// The tester itself reset the connection.
    reset: bool,
    /// Silent toward this peer until then (see [`TesterAction::Quiesce`]).
    silent_until: Option<Instant>,
}

impl Peer {
    /// Reads everything the code under test has sent so far into `buf`, without blocking. End of
    /// stream marks the peer gone; a reset the tester did not cause also finishes the tester's end
    /// and drops its outbox, as a received RST discards unsent data (RFC 9293 §3.10.7.4).
    fn pull(&mut self, log: &Log) {
        if self.gone {
            return;
        }
        let (tester, peer) = (log.tester, self.conn.client);
        let mut chunk = [0u8; 8192]; // a snare choice of read size; the loop drains the rest
        loop {
            match self.conn.read_from_peer(&mut chunk) {
                Ok(0) => {
                    self.gone = true;
                    log.shared
                        .record(RecordedEvent::PeerClosed { tester, peer });
                    break;
                }
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                // Reset: the connection is finished in both directions.
                Err(e) => {
                    self.gone = true;
                    if e.kind() == std::io::ErrorKind::ConnectionReset && !self.reset {
                        self.closed = true;
                        self.outbox.clear();
                        log.shared.record(RecordedEvent::PeerReset { tester, peer });
                    }
                    break;
                }
            }
        }
    }

    /// Whether the tester may still send on this connection.
    fn open(&self) -> bool {
        !self.gone && !self.closed && !self.closing
    }

    /// Whether the tester is currently quiesced toward this peer.
    fn silent(&self) -> bool {
        self.silent_until
            .is_some_and(|until| Instant::now() < until)
    }

    /// Queues `bytes` for the peer and flushes what the window takes; dropped (and logged as
    /// suppressed) while quiesced, and dropped silently once the connection is not open.
    fn send(&mut self, bytes: &[u8], log: &Log) {
        if !self.open() {
            return;
        }
        if self.silent() {
            log.suppressed(self.conn.client, Toward::CodeUnderTest, bytes.len());
            return;
        }
        self.outbox.extend_from_slice(bytes);
        self.flush(log);
    }

    /// Hands the connection as much of the outbox as its window takes, then closes the tester's
    /// end if it was asked to once the outbox is empty. When nothing is taken and the connection
    /// can no longer be written (closed or reset under it), the outbox is discarded.
    fn flush(&mut self, log: &Log) {
        if self.closed {
            return;
        }
        if !self.outbox.is_empty() {
            let n = self.conn.write_from_peer(&self.outbox);
            if n > 0 {
                log.sent(Transport::Tcp, self.conn.client, n);
                self.outbox.drain(..n);
            } else if !self.conn.peer_can_write(self.outbox.len()) {
                return;
            } else {
                self.outbox.clear();
            }
        }
        if self.closing && self.outbox.is_empty() {
            self.closing = false;
            self.close_now(log);
        }
    }

    /// Whether the outbox waits on room the window now has.
    fn flushable(&self) -> bool {
        !self.closed && !self.outbox.is_empty() && self.conn.peer_can_write(self.outbox.len())
    }

    /// Goes silent toward this peer until `until`.
    fn quiesce(&mut self, until: Instant, span: Duration, log: &Log) {
        self.silent_until = Some(until);
        log.quiesced(self.conn.client, span);
    }

    /// Aborts the connection with a reset, discarding the outbox. Once only.
    fn reset(&mut self, log: &Log) {
        if !self.closed {
            self.closed = true;
            self.closing = false;
            self.reset = true;
            self.outbox.clear();
            self.conn.reset_peer();
            log.shared.record(RecordedEvent::Reset {
                tester: log.tester,
                peer: self.conn.client,
            });
        }
    }

    /// Closes the tester's end once everything already queued has been sent (an orderly close
    /// sends queued data before its FIN, RFC 9293 §3.6).
    fn close(&mut self, log: &Log) {
        if self.closed || self.closing {
            return;
        }
        self.closing = true;
        self.flush(log);
    }

    /// Closes the tester's end now, dropping whatever the outbox still holds. Once only.
    fn close_now(&mut self, log: &Log) {
        if !self.closed {
            self.closed = true;
            self.closing = false;
            self.outbox.clear();
            self.conn.close_peer();
            log.shared.record(RecordedEvent::Closed {
                tester: log.tester,
                peer: self.conn.client,
            });
        }
    }
}

/// Where an action's plain `Send`/`Close` goes: back to the peer an event came from, or — for a
/// cyclic action — to every peer.
#[derive(Clone, Copy)]
enum Origin {
    /// The connection at this index of [`Peers::tcp`].
    Tcp(usize),
    /// The datagram source at this address.
    Udp(SocketAddr),
    /// Every peer: a cyclic action's.
    Everyone,
}

/// The run's view of who the tester is talking to.
struct Peers<'a> {
    transport: &'a TesterTransport,
    log: Log<'a>,
    /// Every connection accepted, in order; indices are stable for the run, closed ones
    /// included.
    tcp: Vec<Peer>,
    /// Every address a datagram has come from, in order of first arrival.
    udp: Vec<SocketAddr>,
    /// UDP peers the tester is silent toward, and until when.
    udp_silent: std::collections::HashMap<SocketAddr, Instant>,
}

impl Peers<'_> {
    /// Carries out `action` for an event from `origin`. Actions that do not apply to the
    /// tester's transport do nothing.
    fn apply<P: Packet>(&mut self, action: TesterAction<P>, origin: Origin) {
        match action {
            TesterAction::Nothing => {}
            TesterAction::Send(p) => self.send(&p.to_bytes(), origin),
            TesterAction::SendAll(ps) => {
                for p in ps {
                    self.send(&p.to_bytes(), origin);
                }
            }
            TesterAction::SendTo(to, p) => self.send_to(to, &p.to_bytes()),
            TesterAction::Close => match origin {
                Origin::Tcp(i) => self.tcp[i].close(&self.log),
                Origin::Everyone => self.tcp.iter_mut().for_each(|p| p.close(&self.log)),
                Origin::Udp(_) => {}
            },
            TesterAction::Multiple(actions) => {
                for a in actions {
                    self.apply(a, origin);
                }
            }
            TesterAction::Reset => match origin {
                Origin::Tcp(i) => self.tcp[i].reset(&self.log),
                Origin::Everyone => self.tcp.iter_mut().for_each(|p| p.reset(&self.log)),
                Origin::Udp(_) => {}
            },
            TesterAction::SetListenerBehavior(behavior) => {
                if matches!(self.transport, TesterTransport::Tcp(_)) {
                    crate::faults::set_listener_behavior_on(
                        self.log.shared,
                        self.log.tester,
                        behavior,
                    );
                }
            }
            TesterAction::RaiseSocketError(error) => {
                let errno = crate::faults::socket_errno(&error);
                let addrs = self.sut_addrs(origin);
                self.log.shared.raise_socket_error(&addrs, errno);
            }
            TesterAction::IcmpPortUnreachable => {
                if matches!(self.transport, TesterTransport::Udp(_)) {
                    let addrs = self.sut_addrs(origin);
                    self.log.shared.inject_icmp(&addrs, self.log.tester);
                }
            }
            TesterAction::QuiesceLink(span, direction) => {
                let addrs = self.sut_addrs(origin);
                self.log.shared.quiesce(&addrs, span, direction);
            }
            TesterAction::SetRecvWindow(window) => {
                for addr in self.sut_addrs(origin) {
                    self.log
                        .shared
                        .update_tcp_policy(addr, |p| p.recv_window = window);
                }
                self.log.shared.kick();
            }
            TesterAction::Quiesce(span) => {
                let until = Instant::now() + span;
                match origin {
                    Origin::Tcp(i) => self.tcp[i].quiesce(until, span, &self.log),
                    Origin::Udp(from) => {
                        self.udp_silent.insert(from, until);
                        self.log.quiesced(from, span);
                    }
                    Origin::Everyone => {
                        for peer in self.tcp.iter_mut().filter(|p| p.open()) {
                            peer.quiesce(until, span, &self.log);
                        }
                        for &from in &self.udp {
                            self.udp_silent.insert(from, until);
                            self.log.quiesced(from, span);
                        }
                    }
                }
            }
        }
    }

    /// The code under test's addresses an action from `origin` concerns.
    fn sut_addrs(&self, origin: Origin) -> Vec<SocketAddr> {
        match origin {
            Origin::Tcp(i) => vec![self.tcp[i].conn.client],
            Origin::Udp(from) => vec![from],
            Origin::Everyone => self
                .tcp
                .iter()
                .filter(|p| p.open())
                .map(|p| p.conn.client)
                .chain(self.udp.iter().copied())
                .collect(),
        }
    }

    /// Whether the tester is currently quiesced toward the datagram source `peer`.
    fn udp_silent(&self, peer: SocketAddr) -> bool {
        self.udp_silent
            .get(&peer)
            .is_some_and(|&until| Instant::now() < until)
    }

    /// Sends one datagram to `to`, or logs it suppressed while quiesced toward `to`.
    fn send_udp(&self, ep: &UdpEndpoint, to: SocketAddr, bytes: &[u8]) {
        if self.udp_silent(to) {
            self.log.suppressed(to, Toward::CodeUnderTest, bytes.len());
        } else {
            self.log.sent(Transport::Udp, to, bytes.len());
            ep.send_to(to, bytes);
        }
    }

    /// Sends `bytes` back to `origin`, or to every peer for [`Origin::Everyone`].
    fn send(&mut self, bytes: &[u8], origin: Origin) {
        match (origin, self.transport) {
            (Origin::Tcp(i), _) => self.tcp[i].send(bytes, &self.log),
            (Origin::Udp(to), TesterTransport::Udp(ep)) => self.send_udp(ep, to, bytes),
            (Origin::Everyone, TesterTransport::Tcp(_)) => {
                let log = &self.log;
                self.tcp.iter_mut().for_each(|peer| peer.send(bytes, log));
            }
            (Origin::Everyone, TesterTransport::Udp(ep)) => {
                for &to in &self.udp {
                    self.send_udp(ep, to, bytes);
                }
            }
            (Origin::Udp(_), TesterTransport::Tcp(_)) => {
                unreachable!("UDP origin on a TCP tester")
            }
        }
    }

    /// Sends `bytes` to `to`: a datagram to any address, or on the open connection from `to`.
    /// Panics on a TCP tester with no open connection from `to`.
    fn send_to(&mut self, to: SocketAddr, bytes: &[u8]) {
        match self.transport {
            TesterTransport::Udp(ep) => self.send_udp(ep, to, bytes),
            TesterTransport::Tcp(_) => self
                .tcp
                .iter_mut()
                .find(|peer| peer.conn.client == to && peer.open())
                .unwrap_or_else(|| panic!("tester has no open connection from {to}"))
                .send(bytes, &self.log),
        }
    }
}

impl<P: Packet, S, C> Inner<P, S, C> {
    /// Runs the event loop: accept, receive, tick, then sleep until something arrives or the next
    /// cyclic action or deadline is due. Ends on a finish condition or `stop`, closing every
    /// connection (the code under test reads end-of-stream) and withdrawing the listener.
    ///
    /// Time is read with `Instant::now`, which the sim interposes, so periods and deadlines are
    /// on the sim's clock. The idle wait runs inside `snare_interpose::real` on the sim's
    /// readiness signal, with a [`Deadline`] that measures on that same clock, so a virtual clock
    /// can jump straight to the tester's next wake-up. Cyclic actions are phased from `start`.
    fn run(
        &mut self,
        addr: SocketAddr,
        recorder: Option<&Recorder<P>>,
        stop: &AtomicBool,
        start: Instant,
    ) {
        #[cfg(windows)]
        let wake_origin = (Instant::now(), Deadline::after(Duration::ZERO));
        for c in &mut self.cyclic {
            c.next = start + c.phase;
        }
        self.conns.clear();
        // An as-fast-as-possible virtual clock (a `SimHost`'s) only moves when read or slept on,
        // so an idle tester must sleep its way to its next wake-up; a discrete clock is moved for
        // it by the sim, and the wall clock moves on its own.
        let as_fast_as_possible = snare_interpose::virtual_now().is_none()
            && snare_interpose::now(snare_interpose::ClockKind::Monotonic).is_some();
        let Inner {
            transport,
            regs,
            state,
            new_conn,
            conns,
            handlers,
            on_peer,
            cyclic,
            finish,
            deadline,
            poll,
        } = self;
        let mut peers = Peers {
            transport,
            log: Log {
                shared: &regs.shared,
                tester: addr,
            },
            tcp: Vec::new(),
            udp: Vec::new(),
            udp_silent: std::collections::HashMap::new(),
        };
        let mut deliver =
            |peers: &mut Peers, state: &mut S, conn: &mut C, message: P, from, origin| {
                if let Some(r) = recorder {
                    r.push(from, &message);
                }
                // Each stage in turn: a test passes the message on or drops it, and an action sees
                // a clone unless it is the last stage, which takes the message itself.
                let last = handlers.len().saturating_sub(1);
                let mut message = Some(message);
                for (i, handler) in handlers.iter_mut().enumerate() {
                    let Some(m) = message.take() else {
                        return;
                    };
                    match handler {
                        Handler::Filter(test) => message = test(state, conn, m, from),
                        Handler::Act(act) => {
                            let m = if i == last {
                                m
                            } else {
                                message.insert(m).clone()
                            };
                            let action = act(state, conn, m, from);
                            peers.apply(action, origin);
                        }
                    }
                }
            };
        loop {
            match peers.transport {
                TesterTransport::Tcp(listener) => {
                    while let Some(conn) = listener.try_accept() {
                        let from = conn.client;
                        peers.log.shared.record(RecordedEvent::Accepted {
                            tester: addr,
                            peer: from,
                        });
                        peers.tcp.push(Peer {
                            conn,
                            buf: Vec::new(),
                            outbox: Vec::new(),
                            gone: false,
                            closed: false,
                            closing: false,
                            reset: false,
                            silent_until: None,
                        });
                        let origin = Origin::Tcp(peers.tcp.len() - 1);
                        conns.push((from, new_conn(from)));
                        let conn = &mut conns.last_mut().expect("just pushed").1;
                        for handler in on_peer.iter_mut() {
                            let action = handler(state, conn, from);
                            peers.apply(action, origin);
                        }
                    }
                    for (i, (_, conn)) in conns.iter_mut().enumerate() {
                        peers.tcp[i].flush(&peers.log);
                        peers.tcp[i].pull(&peers.log);
                        let from = peers.tcp[i].conn.client;
                        loop {
                            let before = peers.tcp[i].buf.len();
                            let Some(message) = P::parse(&mut peers.tcp[i].buf) else {
                                break;
                            };
                            let len = before.saturating_sub(peers.tcp[i].buf.len());
                            if peers.tcp[i].silent() {
                                peers.log.suppressed(from, Toward::Tester, len);
                                continue;
                            }
                            peers.log.received(Transport::Tcp, from, len);
                            deliver(&mut peers, state, conn, message, from, Origin::Tcp(i));
                        }
                    }
                }
                TesterTransport::Udp(ep) => {
                    while let Some((from, mut datagram)) = ep.try_recv() {
                        if peers.udp_silent(from) {
                            peers.log.suppressed(from, Toward::Tester, datagram.len());
                            continue;
                        }
                        let index = match peers.udp.iter().position(|&p| p == from) {
                            Some(index) => index,
                            None => {
                                peers.udp.push(from);
                                conns.push((from, new_conn(from)));
                                let conn = &mut conns.last_mut().expect("just pushed").1;
                                for handler in on_peer.iter_mut() {
                                    let action = handler(state, conn, from);
                                    peers.apply(action, Origin::Udp(from));
                                }
                                peers.udp.len() - 1
                            }
                        };
                        loop {
                            let before = datagram.len();
                            let Some(message) = P::parse(&mut datagram) else {
                                break;
                            };
                            let len = before.saturating_sub(datagram.len());
                            peers.log.received(Transport::Udp, from, len);
                            let conn = &mut conns[index].1;
                            deliver(&mut peers, state, conn, message, from, Origin::Udp(from));
                        }
                    }
                }
            }
            let now = Instant::now();
            let cyclic_until = deadline.map_or(now, |span| now.min(start + span));
            for c in cyclic.iter_mut() {
                if cyclic_until >= c.next {
                    match &mut c.action {
                        Tick::Once(action) => {
                            let action = action(state);
                            peers.apply(action, Origin::Everyone);
                        }
                        Tick::PerConn(action) => {
                            for (i, (from, conn)) in conns.iter_mut().enumerate() {
                                let origin = match peers.transport {
                                    TesterTransport::Tcp(_) if peers.tcp[i].open() => {
                                        Origin::Tcp(i)
                                    }
                                    TesterTransport::Tcp(_) => continue,
                                    TesterTransport::Udp(_) => Origin::Udp(*from),
                                };
                                let action = action(state, conn, *from);
                                peers.apply(action, origin);
                            }
                        }
                    }
                    c.next += c.period;
                }
            }
            let elapsed = start.elapsed();
            let finished = finish.iter_mut().any(|f| match f {
                Finish::State(f) => f(state, elapsed),
                Finish::Conns(f) => f(state, conns),
            });
            if stop.load(Ordering::Acquire) || finished {
                break;
            }
            if let Some(span) = deadline.filter(|span| elapsed >= *span) {
                if cyclic.iter().any(|c| c.next <= start + span) {
                    continue;
                }
                break;
            }
            let now = Instant::now();
            let wake_at = cyclic
                .iter()
                .map(|c| c.next)
                .chain(deadline.map(|d| start + d))
                .chain((*poll || as_fast_as_possible).then_some(now + UNTIL_POLL))
                .min();
            let tcp = &peers.tcp;
            let pending = || {
                stop.load(Ordering::Acquire)
                    || match peers.transport {
                        TesterTransport::Tcp(listener) => {
                            listener.has_pending()
                                || tcp
                                    .iter()
                                    .any(|p| (!p.gone && p.conn.peer_readable()) || p.flushable())
                        }
                        TesterTransport::Udp(ep) => ep.has_pending(),
                    }
            };
            // `wake_at` is on the clock this thread reads (virtual under a virtual clock); turn it
            // into a deadline the sim's own wait measures on the same clock.
            #[cfg(unix)]
            let deadline = wake_at.map(|at| Deadline::after(at.saturating_duration_since(now)));
            #[cfg(windows)]
            let deadline = wake_at.map(|at| {
                wake_origin
                    .1
                    .later(at.saturating_duration_since(wake_origin.0))
            });
            let woke =
                snare_interpose::real(|| readiness().wait_until("tester", deadline, pending));
            if as_fast_as_possible
                && !woke
                && let Some(at) = wake_at
            {
                // A real millisecond passed with nothing to do: take the virtual step to the
                // wake-up, as the code under test's own sleeps would.
                std::thread::sleep(at.saturating_duration_since(Instant::now()));
            }
        }
        let Peers { tcp, log, .. } = &mut peers;
        for peer in tcp {
            peer.flush(log);
            peer.close_now(log);
        }
        if let TesterTransport::Tcp(listener) = peers.transport {
            peer::unlisten(regs, listener);
        }
    }
}

impl<P: Packet, S: Send + 'static, C: Send + 'static> Tester<P, S, C> {
    /// Runs until a finish condition fires or `stop` is set, holding the tester's lock
    /// throughout; cyclic actions are phased from `start`.
    fn run_until(&self, stop: &AtomicBool, start: Instant) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.run(self.addr, self.recorder.as_ref(), stop, start);
    }

    /// Whether any finish condition was added.
    fn has_finish(&self) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.deadline.is_some() || !inner.finish.is_empty()
    }
}

/// The type-erased view of a [`Tester`] that [`run_testers!`](crate::run_testers) drives, so
/// testers of different message and state types run together. Exported for the macro only.
#[doc(hidden)]
pub trait RunTester: Sync {
    fn has_finish(&self) -> bool;
    fn run_until(&self, stop: &AtomicBool, start: Instant);
}

impl<P: Packet, S: Send + 'static, C: Send + 'static> RunTester for Tester<P, S, C> {
    fn has_finish(&self) -> bool {
        Tester::has_finish(self)
    }

    fn run_until(&self, stop: &AtomicBool, start: Instant) {
        Tester::run_until(self, stop, start);
    }
}

/// Runs `testers` concurrently, one thread each, until every one with a finish condition has
/// finished; testers without one (background peers) are then stopped. A panic in any tester stops
/// the rest and is re-raised here with its original message.
///
/// Every tester is phased from one `start`, read on the calling thread before any is spawned, so
/// their cyclic actions line up exactly on the sim's clock. `remaining` counts finishing testers
/// still running; the one that brings it to zero, or any
/// that panics, sets `stop` (Release, paired with the Acquire loads in the run loop) and bumps
/// readiness so idle testers wake to see it.
#[doc(hidden)]
pub fn run_testers(testers: &[&dyn RunTester]) {
    let finishing = testers.iter().filter(|t| t.has_finish()).count();
    assert!(
        finishing > 0,
        "run_testers!: no tester has a finish condition (until, until_state or until_after), so \
         the run would never end"
    );
    let start = Instant::now();
    let stop = AtomicBool::new(false);
    let remaining = AtomicUsize::new(finishing);
    // The testers' threads run in the calling thread's sim, so they wait as its threads.
    let domain = snare_interpose::domain_key();
    let halt = || {
        stop.store(true, Ordering::Release);
        snare_interpose::real(|| readiness().bump(domain));
    };
    let mut panic = None;
    std::thread::scope(|scope| {
        let handles: Vec<_> = testers
            .iter()
            .map(|tester| {
                let (stop, remaining, halt) = (&stop, &remaining, &halt);
                scope.spawn(move || {
                    let result = catch_unwind(AssertUnwindSafe(|| tester.run_until(stop, start)));
                    if result.is_err()
                        || (tester.has_finish() && remaining.fetch_sub(1, Ordering::AcqRel) == 1)
                    {
                        halt();
                    }
                    result
                })
            })
            .collect();
        for handle in handles {
            if let Err(payload) = handle.join().expect("tester thread") {
                panic.get_or_insert(payload);
            }
        }
    });
    if let Some(payload) = panic {
        resume_unwind(payload);
    }
}

/// Runs every tester until each one with a finish condition has finished, one thread per tester;
/// testers without a finish condition run alongside as background peers and stop with the rest.
/// The testers are borrowed, so their state and recordings can be read afterwards.
///
/// ```ignore
/// run_testers!(connection_tester, command_tester);
/// ```
#[macro_export]
macro_rules! run_testers {
    ($($tester:expr),+ $(,)?) => {
        $crate::__run_testers(&[$( &$tester as &dyn $crate::__RunTester ),+])
    };
}
