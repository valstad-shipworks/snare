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

use std::net::{SocketAddr, ToSocketAddrs};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(unix)]
use crate::fabric as peer;
use crate::packet::Packet;
use crate::readiness::{Deadline, readiness};
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
    /// (`WSAECONNRESET`). Nothing to reset over UDP.
    Reset,
    /// Go silent toward the peer the event came from (from a cyclic action, every peer) for this
    /// long: its messages are read and dropped, and nothing is sent to it — a peer that hangs.
    Quiesce(Duration),
}

type OnMessage<P, S> = Box<dyn FnMut(&mut S, P, SocketAddr) -> TesterAction<P> + Send>;
type OnPeer<P, S> = Box<dyn FnMut(&mut S, SocketAddr) -> TesterAction<P> + Send>;
type OnTick<P, S> = Box<dyn FnMut(&mut S) -> TesterAction<P> + Send>;
type Finish<S> = Box<dyn FnMut(&S, Duration) -> bool + Send>;

struct Cyclic<P, S> {
    period: Duration,
    action: OnTick<P, S>,
    next: Instant,
}

enum Transport {
    Tcp(Arc<Listener>),
    Udp(UdpEndpoint),
}

/// Everything about a tester its run mutates, behind one lock so a tester can be run through a
/// shared reference and inspected once the run is over.
struct Inner<P, S> {
    transport: Transport,
    regs: Arc<Registries>,
    state: S,
    on_message: Vec<OnMessage<P, S>>,
    on_peer: Vec<OnPeer<P, S>>,
    cyclic: Vec<Cyclic<P, S>>,
    finish: Vec<Finish<S>>,
    /// The earliest `until_after` span, so the run can wake for it rather than poll.
    deadline: Option<Duration>,
    /// Whether an opaque [`until`](Tester::until) condition must be re-checked as time passes: it
    /// may watch elapsed time or a flag the test sets, neither of which wakes the tester.
    poll: bool,
}

/// How often an opaque [`until`](Tester::until) condition is re-checked while nothing else wakes
/// the tester. Under a virtual clock these checks are what carry time forward to it.
const UNTIL_POLL: Duration = Duration::from_millis(1);

/// Plays the peer at an address the code under test talks to. Build it with [`connect_tester`]
/// or [`udp_tester`], describe its behaviour, drive it with [`run_testers!`](crate::run_testers),
/// then read back its state ([`inspect`](Tester::inspect)) or what it received
/// ([`recorded`](Tester::recorded)).
///
/// Every handler, cyclic action and finish condition added runs; none replaces another. A tester
/// with no finish condition is a background peer: it runs until every tester in the same
/// `run_testers!` that has one has finished.
pub struct Tester<P: Packet, S = ()> {
    addr: SocketAddr,
    inner: Mutex<Inner<P, S>>,
    recorder: Option<Recorder<P>>,
}

/// Registers a TCP tester as the peer the code under test will connect to at `addr`.
pub fn connect_tester<P: Packet>(addr: impl ToSocketAddrs) -> Tester<P> {
    let addr = resolve(addr);
    Tester::new(addr, Transport::Tcp(peer::listen_at(addr)))
}

/// Binds a UDP tester at `addr`: datagrams the code under test sends there reach its handlers,
/// with their source address, and what it sends carries `addr` as the source.
pub fn udp_tester<P: Packet>(addr: impl ToSocketAddrs) -> Tester<P> {
    let addr = resolve(addr);
    Tester::new(
        addr,
        Transport::Udp(UdpEndpoint::bind(peer::registries_here(), addr)),
    )
}

fn resolve(addr: impl ToSocketAddrs) -> SocketAddr {
    addr.to_socket_addrs()
        .expect("tester address must parse")
        .next()
        .expect("tester address resolved to nothing")
}

impl<P: Packet> Tester<P> {
    fn new(addr: SocketAddr, transport: Transport) -> Self {
        Tester {
            addr,
            inner: Mutex::new(Inner {
                transport,
                regs: peer::registries_here(),
                state: (),
                on_message: Vec::new(),
                on_peer: Vec::new(),
                cyclic: Vec::new(),
                finish: Vec::new(),
                deadline: None,
                poll: false,
            }),
            recorder: None,
        }
    }

    /// Gives the tester `state`, handed to every stateful handler, cyclic action and condition,
    /// and readable after the run with [`inspect`](Tester::inspect). Handlers added before this
    /// keep working; they just don't see the state.
    pub fn with_state<T: Send + 'static>(self, state: T) -> Tester<P, T> {
        let inner = self.inner.into_inner().unwrap();
        Tester {
            addr: self.addr,
            recorder: self.recorder,
            inner: Mutex::new(Inner {
                transport: inner.transport,
                regs: inner.regs,
                state,
                on_message: inner
                    .on_message
                    .into_iter()
                    .map(|mut f| Box::new(move |_: &mut T, m, a| f(&mut (), m, a)) as OnMessage<P, T>)
                    .collect(),
                on_peer: inner
                    .on_peer
                    .into_iter()
                    .map(|mut f| Box::new(move |_: &mut T, a| f(&mut (), a)) as OnPeer<P, T>)
                    .collect(),
                cyclic: inner
                    .cyclic
                    .into_iter()
                    .map(|mut c| Cyclic {
                        period: c.period,
                        next: c.next,
                        action: Box::new(move |_: &mut T| (c.action)(&mut ())),
                    })
                    .collect(),
                finish: inner
                    .finish
                    .into_iter()
                    .map(|mut f| Box::new(move |_: &T, e| f(&(), e)) as Finish<T>)
                    .collect(),
                deadline: inner.deadline,
                poll: inner.poll,
            }),
        }
    }
}

impl<P: Packet, S: Send + 'static> Tester<P, S> {
    fn setup(&mut self) -> &mut Inner<P, S> {
        self.inner.get_mut().unwrap()
    }

    /// Responds to each message the code under test sends.
    pub fn then_action(
        mut self,
        mut action: impl FnMut(P, SocketAddr) -> TesterAction<P> + Send + 'static,
    ) -> Self {
        self.setup()
            .on_message
            .push(Box::new(move |_, m, from| action(m, from)));
        self
    }

    /// Responds to each message the code under test sends, with the tester's state.
    pub fn then_stateful_action(
        mut self,
        action: impl FnMut(&mut S, P, SocketAddr) -> TesterAction<P> + Send + 'static,
    ) -> Self {
        self.setup().on_message.push(Box::new(action));
        self
    }

    /// Acts when a new peer appears: a TCP connection is accepted, or the first datagram arrives
    /// from a UDP address — the place to greet a client or learn its address.
    pub fn on_connect(
        mut self,
        action: impl FnMut(&mut S, SocketAddr) -> TesterAction<P> + Send + 'static,
    ) -> Self {
        self.setup().on_peer.push(Box::new(action));
        self
    }

    /// Runs `action` every `period` of (virtual) time, first one period after the run starts.
    /// A plain [`Send`](TesterAction::Send) goes to every peer; use
    /// [`SendTo`](TesterAction::SendTo) to stream to an address that has not sent anything.
    pub fn with_cyclic_action(
        self,
        period: Duration,
        mut action: impl FnMut() -> TesterAction<P> + Send + 'static,
    ) -> Self {
        self.with_stateful_cyclic_action(period, move |_| action())
    }

    /// As [`with_cyclic_action`](Tester::with_cyclic_action), with the tester's state.
    pub fn with_stateful_cyclic_action(
        mut self,
        period: Duration,
        action: impl FnMut(&mut S) -> TesterAction<P> + Send + 'static,
    ) -> Self {
        self.setup().cyclic.push(Cyclic {
            period,
            action: Box::new(action),
            next: Instant::now(),
        });
        self
    }

    /// Finishes once `condition(elapsed)` returns true. Any finish condition firing ends the run.
    /// The condition is re-checked every millisecond while the tester is otherwise idle, so it can
    /// watch the clock or a flag the test sets; prefer [`until_after`](Tester::until_after) for a
    /// plain deadline and [`until_state`](Tester::until_state) for the tester's own progress.
    pub fn until(mut self, mut condition: impl FnMut(Duration) -> bool + Send + 'static) -> Self {
        let inner = self.setup();
        inner.poll = true;
        inner
            .finish
            .push(Box::new(move |_, elapsed| condition(elapsed)));
        self
    }

    /// Finishes once `condition` holds of the tester's state.
    pub fn until_state(mut self, mut condition: impl FnMut(&S) -> bool + Send + 'static) -> Self {
        self.setup()
            .finish
            .push(Box::new(move |state, _| condition(state)));
        self
    }

    /// Finishes once `duration` has elapsed.
    pub fn until_after(mut self, duration: Duration) -> Self {
        let inner = self.setup();
        inner.deadline = Some(inner.deadline.map_or(duration, |d| d.min(duration)));
        inner
            .finish
            .push(Box::new(move |_, elapsed| elapsed >= duration));
        self
    }

    /// Keeps every message the code under test sends, with its source, for
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
        self.run_until(&AtomicBool::new(false));
    }
}

/// What a tester received, shared with the code driving the test. Cheap to clone.
pub struct Recorder<P> {
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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn push(&self, from: SocketAddr, message: &P) {
        self.received.lock().unwrap().push((from, message.clone()));
    }
}

/// A TCP connection the tester accepted.
struct Peer {
    conn: Arc<Conn>,
    buf: Vec<u8>,
    /// The code under test closed its end: nothing more to read, nowhere to write.
    gone: bool,
    /// The tester closed its end.
    closed: bool,
    /// Silent toward this peer until then (see [`TesterAction::Quiesce`]).
    silent_until: Option<Instant>,
}

impl Peer {
    fn pull(&mut self) {
        if self.gone {
            return;
        }
        let mut chunk = [0u8; 8192];
        loop {
            match self.conn.read_from_peer(&mut chunk) {
                Ok(0) => {
                    self.gone = true;
                    break;
                }
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                // Reset: the connection is finished in both directions.
                Err(_) => {
                    self.gone = true;
                    break;
                }
            }
        }
    }

    fn open(&self) -> bool {
        !self.gone && !self.closed
    }

    fn silent(&self) -> bool {
        self.silent_until.is_some_and(|until| Instant::now() < until)
    }

    fn send(&self, bytes: &[u8]) {
        if self.open() && !self.silent() {
            self.conn.write_from_peer(bytes);
        }
    }

    fn reset(&mut self) {
        if !self.closed {
            self.closed = true;
            self.conn.reset_peer();
        }
    }

    fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            self.conn.close_peer();
        }
    }
}

/// Where an action's plain `Send`/`Close` goes: back to the peer an event came from, or — for a
/// cyclic action — to every peer.
#[derive(Clone, Copy)]
enum Origin {
    Tcp(usize),
    Udp(SocketAddr),
    Everyone,
}

/// The run's view of who the tester is talking to.
struct Peers<'a> {
    transport: &'a Transport,
    tcp: Vec<Peer>,
    udp: Vec<SocketAddr>,
    /// UDP peers the tester is silent toward, and until when.
    udp_silent: std::collections::HashMap<SocketAddr, Instant>,
}

impl Peers<'_> {
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
                Origin::Tcp(i) => self.tcp[i].close(),
                Origin::Everyone => self.tcp.iter_mut().for_each(Peer::close),
                Origin::Udp(_) => {}
            },
            TesterAction::Multiple(actions) => {
                for a in actions {
                    self.apply(a, origin);
                }
            }
            TesterAction::Reset => match origin {
                Origin::Tcp(i) => self.tcp[i].reset(),
                Origin::Everyone => self.tcp.iter_mut().for_each(Peer::reset),
                Origin::Udp(_) => {}
            },
            TesterAction::Quiesce(span) => {
                let until = Instant::now() + span;
                match origin {
                    Origin::Tcp(i) => self.tcp[i].silent_until = Some(until),
                    Origin::Udp(from) => {
                        self.udp_silent.insert(from, until);
                    }
                    Origin::Everyone => {
                        self.tcp.iter_mut().for_each(|p| p.silent_until = Some(until));
                        let udp = self.udp.clone();
                        self.udp_silent.extend(udp.into_iter().map(|a| (a, until)));
                    }
                }
            }
        }
    }

    fn udp_silent(&self, peer: SocketAddr) -> bool {
        self.udp_silent
            .get(&peer)
            .is_some_and(|&until| Instant::now() < until)
    }

    fn send(&self, bytes: &[u8], origin: Origin) {
        match (origin, self.transport) {
            (Origin::Tcp(i), _) => self.tcp[i].send(bytes),
            (Origin::Udp(to), Transport::Udp(ep)) => {
                if !self.udp_silent(to) {
                    ep.send_to(to, bytes);
                }
            }
            (Origin::Everyone, Transport::Tcp(_)) => {
                self.tcp.iter().for_each(|peer| peer.send(bytes));
            }
            (Origin::Everyone, Transport::Udp(ep)) => {
                for &to in self.udp.iter().filter(|&&to| !self.udp_silent(to)) {
                    ep.send_to(to, bytes);
                }
            }
            (Origin::Udp(_), Transport::Tcp(_)) => unreachable!("UDP origin on a TCP tester"),
        }
    }

    fn send_to(&self, to: SocketAddr, bytes: &[u8]) {
        match self.transport {
            Transport::Udp(ep) => {
                if !self.udp_silent(to) {
                    ep.send_to(to, bytes);
                }
            }
            Transport::Tcp(_) => self
                .tcp
                .iter()
                .find(|peer| peer.conn.client == to && peer.open())
                .unwrap_or_else(|| panic!("tester has no open connection from {to}"))
                .send(bytes),
        }
    }
}

impl<P: Packet, S> Inner<P, S> {
    /// Runs the event loop: accept, receive, tick, then sleep until something arrives or the next
    /// cyclic action or deadline is due. Ends on a finish condition or `stop`, closing every
    /// connection (the code under test reads end-of-stream) and withdrawing the listener.
    fn run(&mut self, recorder: Option<&Recorder<P>>, stop: &AtomicBool) {
        let start = Instant::now();
        for c in &mut self.cyclic {
            c.next = start + c.period;
        }
        // An as-fast-as-possible virtual clock (a `SimHost`'s) only moves when read or slept on,
        // so an idle tester must sleep its way to its next wake-up; a discrete clock is moved for
        // it by the sim, and the wall clock moves on its own.
        let as_fast_as_possible = snare_interpose::discrete_now().is_none()
            && snare_interpose::now(snare_interpose::ClockKind::Monotonic).is_some();
        let Inner {
            transport,
            regs,
            state,
            on_message,
            on_peer,
            cyclic,
            finish,
            deadline,
            poll,
        } = self;
        let mut peers = Peers {
            transport,
            tcp: Vec::new(),
            udp: Vec::new(),
            udp_silent: std::collections::HashMap::new(),
        };
        let mut deliver = |peers: &mut Peers, state: &mut S, message: P, from, origin| {
            if let Some(r) = recorder {
                r.push(from, &message);
            }
            // Every handler sees the message; the last one takes it, the rest get clones.
            let last = on_message.len().saturating_sub(1);
            let mut message = Some(message);
            for (i, handler) in on_message.iter_mut().enumerate() {
                let m = if i == last {
                    message.take()
                } else {
                    message.clone()
                };
                let action = handler(state, m.expect("message"), from);
                peers.apply(action, origin);
            }
        };
        loop {
            match peers.transport {
                Transport::Tcp(listener) => {
                    while let Some(conn) = listener.try_accept() {
                        let from = conn.client;
                        peers.tcp.push(Peer {
                            conn,
                            buf: Vec::new(),
                            gone: false,
                            closed: false,
                            silent_until: None,
                        });
                        let origin = Origin::Tcp(peers.tcp.len() - 1);
                        for handler in on_peer.iter_mut() {
                            let action = handler(state, from);
                            peers.apply(action, origin);
                        }
                    }
                    for i in 0..peers.tcp.len() {
                        peers.tcp[i].pull();
                        while let Some(message) = P::parse(&mut peers.tcp[i].buf) {
                            if peers.tcp[i].silent() {
                                continue;
                            }
                            let from = peers.tcp[i].conn.client;
                            deliver(&mut peers, state, message, from, Origin::Tcp(i));
                        }
                    }
                }
                Transport::Udp(ep) => {
                    while let Some((from, mut datagram)) = ep.try_recv() {
                        if peers.udp_silent(from) {
                            continue;
                        }
                        if !peers.udp.contains(&from) {
                            peers.udp.push(from);
                            for handler in on_peer.iter_mut() {
                                let action = handler(state, from);
                                peers.apply(action, Origin::Udp(from));
                            }
                        }
                        while let Some(message) = P::parse(&mut datagram) {
                            deliver(&mut peers, state, message, from, Origin::Udp(from));
                        }
                    }
                }
            }
            let now = Instant::now();
            for c in cyclic.iter_mut() {
                if now >= c.next {
                    let action = (c.action)(state);
                    peers.apply(action, Origin::Everyone);
                    c.next += c.period;
                    if c.next <= now {
                        c.next = now + c.period;
                    }
                }
            }
            let elapsed = start.elapsed();
            if stop.load(Ordering::Acquire) || finish.iter_mut().any(|f| f(state, elapsed)) {
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
                        Transport::Tcp(listener) => {
                            listener.has_pending()
                                || tcp.iter().any(|p| !p.gone && p.conn.peer_readable())
                        }
                        Transport::Udp(ep) => ep.has_pending(),
                    }
            };
            // `wake_at` is on the clock this thread reads (virtual under a virtual clock); turn it
            // into a deadline the sim's own wait measures on the same clock.
            let deadline = wake_at.map(|at| Deadline::after(at.saturating_duration_since(now)));
            let woke = snare_interpose::real(|| readiness().wait_until(deadline, pending));
            if as_fast_as_possible
                && !woke
                && let Some(at) = wake_at
            {
                // A real millisecond passed with nothing to do: take the virtual step to the
                // wake-up, as the code under test's own sleeps would.
                std::thread::sleep(at.saturating_duration_since(Instant::now()));
            }
        }
        for peer in &mut peers.tcp {
            peer.close();
        }
        if let Transport::Tcp(listener) = peers.transport {
            peer::unlisten(regs, listener);
        }
    }
}

impl<P: Packet, S: Send + 'static> Tester<P, S> {
    fn run_until(&self, stop: &AtomicBool) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.run(self.recorder.as_ref(), stop);
    }

    fn has_finish(&self) -> bool {
        !self.inner.lock().unwrap_or_else(|e| e.into_inner()).finish.is_empty()
    }
}

#[doc(hidden)]
pub trait RunTester: Sync {
    fn has_finish(&self) -> bool;
    fn run_until(&self, stop: &AtomicBool);
}

impl<P: Packet, S: Send + 'static> RunTester for Tester<P, S> {
    fn has_finish(&self) -> bool {
        Tester::has_finish(self)
    }

    fn run_until(&self, stop: &AtomicBool) {
        Tester::run_until(self, stop);
    }
}

/// Runs `testers` concurrently, one thread each, until every one with a finish condition has
/// finished; testers without one (background peers) are then stopped. A panic in any tester stops
/// the rest and is re-raised here with its original message.
#[doc(hidden)]
pub fn run_testers(testers: &[&dyn RunTester]) {
    let finishing = testers.iter().filter(|t| t.has_finish()).count();
    assert!(
        finishing > 0,
        "run_testers!: no tester has a finish condition (until, until_state or until_after), so \
         the run would never end"
    );
    let stop = AtomicBool::new(false);
    let remaining = AtomicUsize::new(finishing);
    let halt = || {
        stop.store(true, Ordering::Release);
        snare_interpose::real(|| readiness().bump());
    };
    let mut panic = None;
    std::thread::scope(|scope| {
        let handles: Vec<_> = testers
            .iter()
            .map(|tester| {
                let (stop, remaining, halt) = (&stop, &remaining, &halt);
                scope.spawn(move || {
                    let result = catch_unwind(AssertUnwindSafe(|| tester.run_until(stop)));
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
