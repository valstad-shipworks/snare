//! The sim-wide log of what happened at the edge of the code under test: what crossed a tester's
//! boundary, what the simulated link did to datagrams, which link policies changed and which
//! faults took effect — each stamped on the sim's own timeline.
//!
//! Recording only observes: [`EventLog::push`] takes a real (uninterposed) lock and reads the
//! clock without advancing it, so a run behaves the same with the log on or off
//! ([`SimBuilder::record_events`](crate::SimBuilder::record_events)).

use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::netpolicy::{TcpPolicy, UdpPolicy};

/// One entry of the log: when it happened in sim time (see `Sim::time_value`; real time since the
/// sim was built on a sim without a virtual clock), its place in the log, and what happened.
#[derive(Clone, Debug, PartialEq)]
pub struct RecordedEntry {
    /// Sim time of the event; never less than an earlier entry's.
    pub at: Duration,
    /// Strictly increasing across the sim's whole life; clearing the log does not reset it.
    pub seq: u64,
    pub event: RecordedEvent,
}

/// Which protocol a tester's traffic used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    Udp,
}

/// Which side a tester kept traffic from while it was quiesced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Toward {
    /// Sent by the code under test to the tester, and read and dropped by it.
    Tester,
    /// Sent by the tester's handlers toward the code under test, and never sent.
    CodeUnderTest,
}

/// What a [`UdpPolicy`] did to one datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LinkFault {
    /// Dropped by the policy's loss rate.
    Lost,
    /// Larger than the policy's MTU, so dropped.
    TooBig,
    /// Arrived twice.
    Duplicated,
}

/// Which traffic a stall holds, as seen from the code under test's address (see
/// [`quiesce`](crate::quiesce)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// What arrives at the address.
    Receive,
    /// What leaves the address.
    Send,
    Both,
}

/// Something that happened at the edge of the code under test. `tester` is the tester's own
/// address and `peer` the code under test's end; `len` counts bytes.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum RecordedEvent {
    /// A TCP tester accepted a connection.
    Accepted {
        tester: SocketAddr,
        peer: SocketAddr,
    },
    /// A tester received one message: `len` is the bytes the message was parsed from.
    Received {
        transport: Transport,
        tester: SocketAddr,
        peer: SocketAddr,
        len: usize,
    },
    /// A tester sent bytes toward the code under test.
    Sent {
        transport: Transport,
        tester: SocketAddr,
        peer: SocketAddr,
        len: usize,
    },
    /// The tester closed its end of a connection.
    Closed {
        tester: SocketAddr,
        peer: SocketAddr,
    },
    /// The tester aborted a connection with a reset.
    Reset {
        tester: SocketAddr,
        peer: SocketAddr,
    },
    /// The code under test closed its end: the tester read end-of-stream.
    PeerClosed {
        tester: SocketAddr,
        peer: SocketAddr,
    },
    /// The code under test reset the connection.
    PeerReset {
        tester: SocketAddr,
        peer: SocketAddr,
    },
    /// The tester went silent toward `peer` for `span`.
    Quiesced {
        tester: SocketAddr,
        peer: SocketAddr,
        span: Duration,
    },
    /// Traffic a quiesced tester dropped, in the direction it was headed.
    Suppressed {
        tester: SocketAddr,
        peer: SocketAddr,
        toward: Toward,
        len: usize,
    },
    /// The link policy at `to` lost, dropped or duplicated a datagram from `from`.
    Link {
        from: SocketAddr,
        to: SocketAddr,
        len: usize,
        fault: LinkFault,
    },
    /// The UDP link policy at `addr` changed; `policy` is the whole policy afterwards.
    UdpPolicyChanged { addr: SocketAddr, policy: UdpPolicy },
    /// The TCP link policy at `addr` changed; `policy` is the whole policy afterwards.
    TcpPolicyChanged { addr: SocketAddr, policy: TcpPolicy },
    /// An interface changed administrative state or carrier, or was added or removed.
    NicChanged {
        nic: String,
        admin_up: bool,
        carrier: bool,
    },
    /// An injected fault took effect on the code under test, at `addr` when it concerns one.
    Fault {
        addr: Option<SocketAddr>,
        fault: Fault,
    },
    /// The code under test used a socket option or ioctl the sim does not model on `socket`
    /// (bound at `local`), the first time it did on that socket; `refused` when it failed —
    /// under `SimBuilder::strict_sockopts`, or on Windows for a `WSAIoctl` code the sim cannot
    /// carry out — rather than succeeding without effect.
    UnmodelledOption {
        socket: crate::SocketId,
        local: Option<SocketAddr>,
        option: crate::UnmodelledOption,
        refused: bool,
    },
    /// A signal or console control event was delivered to the code under test.
    Signal {
        signal: crate::Signal,
        origin: crate::SignalOrigin,
        delivery: crate::SignalDelivery,
    },
}

/// A fault injected into the code under test, as it took effect.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum Fault {
    /// A call failed with `errno` (a WSA code on Windows), as the host OS reports it.
    Error { errno: i32, call: &'static str },
    /// A connect was refused by a listener set to refuse (see
    /// [`set_listener_behavior`](crate::set_listener_behavior)).
    ConnectRefused,
    /// A connect gave up with `ETIMEDOUT` (`WSAETIMEDOUT`).
    ConnectTimedOut,
    /// A connect held until `until` on the sim's clock.
    ConnectDelayed { until: Duration },
    /// An ICMP port unreachable from `from` reached a datagram socket of the code under test.
    IcmpPortUnreachable { from: SocketAddr },
    /// Traffic at the address was held for `span` (see [`quiesce`](crate::quiesce)).
    Stalled {
        span: Duration,
        direction: Direction,
    },
    /// A frame was dropped because the interface `nic` it left by had no usable link.
    LinkDown { nic: String },
    /// A call failed because the address could not be reached: `ENETUNREACH`, `EHOSTUNREACH` or
    /// `ENETDOWN` from routing, or a connect that failed with an errno other than
    /// `ECONNREFUSED`/`ETIMEDOUT` (the WSA codes on Windows).
    Unreachable { errno: i32 },
    /// A [`DnsPolicy`](crate::DnsPolicy) failed a lookup of `name`.
    Dns {
        name: String,
        failure: crate::DnsFailure,
    },
}

/// The log's contents, behind [`EventLog::log`].
struct Log {
    /// The next entry's sequence number; survives [`EventLog::clear`].
    next_seq: u64,
    /// The latest stamp handed out, the floor for the next one; survives
    /// [`EventLog::clear`].
    last_at: Duration,
    entries: Vec<RecordedEntry>,
}

/// The sim's event log, one per sim, shared through `SimShared::events`.
pub(crate) struct EventLog {
    log: Mutex<Log>,
    /// Whether events are recorded; off after `SimBuilder::record_events(false)`. `Relaxed`
    /// suffices: it is set once while the sim is built, before any thread of it runs, and only
    /// gates whether an entry is pushed.
    enabled: AtomicBool,
}

impl EventLog {
    /// An empty, enabled log.
    pub(crate) fn new() -> Self {
        EventLog {
            log: Mutex::new(Log {
                next_seq: 0,
                last_at: Duration::ZERO,
                entries: Vec::new(),
            }),
            enabled: AtomicBool::new(true),
        }
    }

    /// Turns recording on or off.
    pub(crate) fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    /// Whether events are recorded; callers check it before building an event.
    pub(crate) fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Appends `event`, stamped by `stamp` read under the log's lock so stamps never decrease
    /// along the sequence: a stamp earlier than the last one (an event reported `ago`) is raised
    /// to it. The lock is taken inside
    /// `snare_interpose::real`, so waiting for it is never a simulated block, and `stamp` must
    /// not itself take the log's lock.
    pub(crate) fn push(&self, stamp: impl FnOnce() -> Duration, event: RecordedEvent) {
        snare_interpose::real(|| {
            let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
            let at = stamp().max(log.last_at);
            let seq = log.next_seq;
            log.next_seq += 1;
            log.last_at = at;
            log.entries.push(RecordedEntry { at, seq, event });
        });
    }

    /// A copy of every entry, oldest first.
    pub(crate) fn snapshot(&self) -> Vec<RecordedEntry> {
        snare_interpose::real(|| {
            self.log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entries
                .clone()
        })
    }

    /// Drops every entry, keeping the sequence counter and the stamp floor.
    pub(crate) fn clear(&self) {
        snare_interpose::real(|| {
            self.log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entries
                .clear()
        });
    }
}

/// Everything the sim the calling thread runs in has recorded so far, oldest first. Panics off a
/// sim; [`Sim::recorded_events`](crate::Sim::recorded_events) reads it from anywhere. Scheduled
/// link transitions that have come due are applied first, so their events are included.
#[track_caller]
pub fn recorded_events() -> Vec<RecordedEntry> {
    let shared = crate::scope::here();
    shared.settle_links();
    shared.events.snapshot()
}

/// Empties the log of the sim the calling thread runs in, so what follows can be read on its own.
/// Sequence numbers carry on from where they were.
#[track_caller]
pub fn clear_recorded_events() {
    crate::scope::here().events.clear();
}
