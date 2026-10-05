//! fast-talker's `tcp` over snare's TCP streams. Every stamp comes from
//! snare's virtual clock: a read's stamp is the instant its newest bytes
//! reached the stream, and a send's stages are stamped when it was queued,
//! handed to the interface and acknowledged by the peer.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::time::Duration;

use ::fast_talker::__sim::ctor;
pub use ::fast_talker::tcp::{Stage, TcpInfo, TxEvent};
use ::fast_talker::{Config, Hardware, Sent, Source, Timestamp};

use super::slot::{TcpTxRecord, TxStamping};
use super::socket::{
    Clocks, NicStamping, TX_LOG_CAP, candidates, enable_hardware, phc_raw, resolve, rx_timestamp,
    unsupported,
};
use crate::netif::{SimSocket, SocketId};
use crate::os::OsSemantics;
use crate::sched::waitset::WaitKey;
use crate::shim_std_tcp::ShimStdTcpStream;
use crate::state::{tcp_policy, wake, wake_at, with_net};
use crate::time::Instant;

mod sealed {
    pub trait TcpShim {
        fn shim(&self) -> &crate::shim_std_tcp::ShimStdTcpStream;
    }
}

/// A TCP stream [`TimestampedStream`] can drive: snare's TCP stream, which
/// is also `mio::net::TcpStream` under snare's mio shim. Only snare's
/// streams qualify.
pub trait Stream: SimSocket + sealed::TcpShim {
    /// Runs one send or receive on the stream.
    fn try_io<R>(&self, f: impl FnOnce() -> io::Result<R>) -> io::Result<R> {
        f()
    }
}

impl sealed::TcpShim for crate::net::TcpStream {
    fn shim(&self) -> &ShimStdTcpStream {
        self
    }
}

impl Stream for crate::net::TcpStream {}

#[cfg(feature = "mio-compat")]
impl sealed::TcpShim for crate::mio_shim::net::TcpStream {
    fn shim(&self) -> &ShimStdTcpStream {
        self
    }
}

#[cfg(feature = "mio-compat")]
impl Stream for crate::mio_shim::net::TcpStream {}

/// A TCP stream whose reads report when their data arrived, and whose sends
/// report when they were queued, sent and acknowledged, on snare's virtual
/// clock.
///
/// What it can stamp follows the emulated OS
/// ([`os_semantics`](crate::os_semantics)), as fast-talker does:
///
/// | OS | Receive | Send stages |
/// |---|---|---|
/// | Linux | kernel, or hardware on an interface with hardware stamping | `Scheduled` and `Sent` at the send, `Acked` one round trip later, for every write on the stream |
/// | macOS, Windows | user space, when the read returns | `Sent` (user space), for sends through `TimestampedStream` |
///
/// A Linux receive stamp is the virtual instant the newest bytes the read
/// returned reached the stream, however long they then waited to be read.
/// An `Acked` stage is visible once the acknowledgement is back: after the
/// bytes' one-way trip to the peer (with jitter) and the return trip (the
/// `set_tcp_inbound_latency` of this end plus the interface latency).
/// Bytes held on a downed interface are acknowledged once the link returns
/// and they reach the peer. Linux signals
/// ready stages as an error condition, so the stream polls as errored until
/// they are read.
#[derive(Debug)]
pub struct TimestampedStream<S> {
    io: S,
    source: Source,
    interface: Option<String>,
    config: Config,
}

struct Setup {
    source: Source,
    interface: Option<String>,
    kernel_error: Option<io::Error>,
    hardware_error: Option<io::Error>,
}

impl<S: Stream> TimestampedStream<S> {
    /// Enables the best timestamp source available with [`Config::default`].
    pub fn new(io: S) -> Self {
        Self::with_config(io, Config::default())
    }

    /// Like [`TimestampedStream::new`] with explicit options. Never fails.
    pub fn with_config(io: S, config: Config) -> Self {
        let setup = setup(io.socket_id(), &config);
        Self::build(io, config, setup)
    }

    /// Like [`TimestampedStream::with_config`], but fails if kernel
    /// timestamps can't be enabled (anywhere but Linux), or if the
    /// [`Hardware::Interface`] can't be configured.
    pub fn try_with_config(io: S, config: Config) -> io::Result<Self> {
        let mut setup = setup(io.socket_id(), &config);
        if let Some(e) = setup.kernel_error.take() {
            return Err(e);
        }
        if let (Hardware::Interface(_), Some(e)) = (&config.hardware, setup.hardware_error.take()) {
            return Err(e);
        }
        Ok(Self::build(io, config, setup))
    }

    fn build(io: S, config: Config, setup: Setup) -> Self {
        Self {
            io,
            source: setup.source,
            interface: setup.interface,
            config,
        }
    }

    /// The best receive source configured.
    pub fn source(&self) -> Source {
        self.source
    }

    /// The interface hardware timestamping was enabled on, if any.
    pub fn hardware_interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }

    /// The wrapped stream.
    pub fn get_ref(&self) -> &S {
        &self.io
    }

    /// The wrapped stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.io
    }

    /// Unwraps the stream. Timestamping stays enabled on it.
    pub fn into_inner(self) -> S {
        self.io
    }

    /// Reads what is available, like `Read::read`, with the arrival time of
    /// the newest bytes it returned. Zero bytes means the peer closed.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Timestamp)> {
        self.io.try_io(|| self.read(buf, false))
    }

    /// Reads until the stream would block, calling `f` with each read's
    /// bytes and stamp. Never waits. Stops early at end of stream. Returns
    /// the number of reads.
    pub fn drain(&self, buf: &mut [u8], mut f: impl FnMut(&[u8], Timestamp)) -> io::Result<usize> {
        let mut n = 0;
        loop {
            match self.io.try_io(|| self.read(buf, true)) {
                Ok((0, _)) => return Ok(n),
                Ok((len, t)) => {
                    f(&buf[..len], t);
                    n += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Writes what the socket buffer takes, like `Write::write`. With
    /// [`Config::transmit`], [`Sent::id`] is the stream offset of the last
    /// byte written, counting from 0 when stamping started (wrapping at
    /// 2³²), which is how [`TxEvent::id`] names it. On Linux the offset
    /// counts every write on the stream, so it always matches the stages.
    pub fn send(&self, buf: &[u8]) -> io::Result<Sent> {
        self.io.try_io(|| {
            let (len, id) = self.io.shim().write_stamped(buf, true)?;
            Ok(ctor::sent(len, id))
        })
    }

    /// Appends every send stage stamped so far to `out` and returns how
    /// many. Never waits. Always empty without [`Config::transmit`].
    pub fn tx_events(&self, out: &mut Vec<TxEvent>) -> io::Result<usize> {
        let id = self.io.socket_id();
        let now = Instant::now();
        let records = with_net(|ctx| {
            let mut ready = Vec::new();
            if let Some(c) = ctx.tcp.values_mut().find(|c| c.id == id) {
                while c.ft.tx_events.front().is_some_and(|r| r.visible_at <= now) {
                    ready.extend(c.ft.tx_events.pop_front());
                }
            }
            ready
                .into_iter()
                .map(|r| (r, NicStamping::of(ctx.net, r.egress)))
                .collect::<Vec<_>>()
        });
        if records.is_empty() {
            return Ok(0);
        }
        let clocks = Clocks::read();
        for (r, nic) in &records {
            let wall = crate::sched::wall_of(r.at);
            let timestamp = match r.source {
                Source::Hardware => {
                    let raw = phc_raw(
                        nic.and_then(|n| n.ptp),
                        wall + clocks.stack.hw_tx_after_kernel,
                        r.at,
                        clocks.tai,
                    );
                    resolve(
                        Some(wall),
                        Some(raw),
                        &candidates(raw, clocks.tai),
                        clocks.user,
                        self.config.tolerance,
                    )
                }
                source => ctor::timestamp(wall, source, None),
            };
            out.push(ctor::tx_event(r.id, r.stage, timestamp));
        }
        Ok(records.len())
    }

    /// The connection's current health, as the emulated OS reports it.
    /// Same as [`compat::tcp_info`](crate::fast_talker::compat::tcp_info).
    pub fn info(&self) -> io::Result<TcpInfo> {
        tcp_info(self.io.socket_id())
    }

    fn read(&self, buf: &mut [u8], dontwait: bool) -> io::Result<(usize, Timestamp)> {
        let (n, arrived) = self.io.shim().read_stamped(buf, dontwait)?;
        Ok((n, self.stamp(arrived)))
    }

    fn stamp(&self, arrived: Option<Instant>) -> Timestamp {
        let id = self.io.socket_id();
        let nic = with_net(|ctx| {
            ctx.tcp
                .values()
                .find(|c| c.id == id)
                .and_then(|c| NicStamping::of(ctx.net, c.nic))
        });
        let clocks = Clocks::read();
        match (self.source, arrived) {
            (Source::UserSpace, _) | (_, None) => {
                ctor::timestamp(clocks.user, Source::UserSpace, None)
            }
            (_, Some(at)) => {
                rx_timestamp(OsSemantics::Linux, at, nic, &clocks, self.config.tolerance)
            }
        }
    }
}

impl<S> Deref for TimestampedStream<S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.io
    }
}

impl<S> DerefMut for TimestampedStream<S> {
    fn deref_mut(&mut self) -> &mut S {
        &mut self.io
    }
}

#[cfg(feature = "mio-compat")]
impl<S: crate::mio_shim::event::Source> crate::mio_shim::event::Source for TimestampedStream<S> {
    fn register(
        &mut self,
        registry: &crate::mio_shim::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> io::Result<()> {
        self.io.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &crate::mio_shim::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> io::Result<()> {
        self.io.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &crate::mio_shim::Registry) -> io::Result<()> {
        self.io.deregister(registry)
    }
}

/// Enable timestamping on the stream `id` as the emulated OS would, and
/// record it on the stream.
fn setup(id: SocketId, config: &Config) -> Setup {
    with_net(|ctx| {
        let net = &mut *ctx.net;
        let os = net.os;
        let privileged = net.privileges.net_admin || net.privileges.root;
        let Some(conn) = ctx.tcp.values_mut().find(|c| c.id == id && !c.is_destroyed) else {
            return Setup {
                source: Source::UserSpace,
                interface: None,
                kernel_error: Some(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "no such snare stream",
                )),
                hardware_error: None,
            };
        };
        let local = conn.local_addr.ip();
        let ft = &mut conn.ft;
        let previous = ft.tx;
        ft.tx_hw = None;
        let mut setup = Setup {
            source: Source::Kernel,
            interface: None,
            kernel_error: None,
            hardware_error: None,
        };
        if os == OsSemantics::Linux {
            let target = match &config.hardware {
                Hardware::Off => None,
                Hardware::Interface(name) => Some(Ok(name.clone())),
                Hardware::Auto if local.is_unspecified() => Some(Err(unsupported(
                    "socket is not bound to a specific address, so no interface to enable",
                ))),
                Hardware::Auto => Some(
                    net.owner_of(local)
                        .map(|n| n.spec.name.clone())
                        .ok_or_else(|| unsupported("no interface has the socket's address")),
                ),
            };
            let enabled = target.map(|t| {
                t.and_then(|name| {
                    enable_hardware(net, &name, config.transmit, privileged).map(|e| (name, e))
                })
            });
            match enabled {
                None => {}
                Some(Ok((name, (nic, tx)))) => {
                    setup.source = Source::Hardware;
                    setup.interface = Some(name);
                    ft.tx_hw = tx.then_some(nic);
                }
                Some(Err(e)) => setup.hardware_error = Some(e),
            }
            ft.tx = if config.transmit {
                TxStamping::Kernel
            } else {
                TxStamping::Off
            };
        } else {
            setup.source = Source::UserSpace;
            setup.kernel_error = Some(unsupported("TCP has no kernel timestamps on this platform"));
            if config.hardware != Hardware::Off {
                setup.hardware_error = Some(unsupported("hardware timestamps are Linux-only"));
            }
            ft.tx = if config.transmit {
                TxStamping::Library
            } else {
                TxStamping::Off
            };
        }
        let fresh = match ft.tx {
            TxStamping::Library => true,
            TxStamping::Kernel => previous != TxStamping::Kernel,
            TxStamping::Off => false,
        };
        if fresh {
            ft.tx_offset = 0;
            ft.stamped_sends = 0;
            ft.tx_events.clear();
            ft.held_acks.clear();
        }
        ft.timestamping = Some(config.clone());
        ft.source = Some(setup.source);
        ft.interface = setup.interface.clone();
        setup
    })
}

/// Account a write of `len` bytes on the stream `stream_id`, bound at
/// `local`, and stamp its stages. `arrival` is when the bytes reach the
/// peer, `None` while they are held on a downed interface. Returns the
/// write's transmit stamp id.
pub(crate) fn on_write(
    stream_id: usize,
    local: SocketAddr,
    len: usize,
    arrival: Option<Instant>,
    via_ft: bool,
) -> Option<u32> {
    let reverse = tcp_policy(local).inbound_latency;
    let now = Instant::now();
    let (id, kernel, acked) = with_net(|ctx| {
        let net = &*ctx.net;
        let Some(conn) = ctx.tcp.get_mut(&stream_id) else {
            return (None, false, None);
        };
        let egress = conn.nic;
        let ft = &mut conn.ft;
        ft.bytes_sent += len as u64;
        let issue = match ft.tx {
            TxStamping::Off => false,
            TxStamping::Kernel => true,
            TxStamping::Library => via_ft,
        };
        if !issue || len == 0 {
            return (None, false, None);
        }
        ft.tx_offset += len as u64;
        let id = (ft.tx_offset - 1) as u32;
        ft.stamped_sends = ft.stamped_sends.wrapping_add(1);
        let record = |stage, at, source| TcpTxRecord {
            id,
            stage,
            at,
            visible_at: at,
            source,
            egress,
        };
        if ft.tx == TxStamping::Library {
            push_event(
                &mut ft.tx_events,
                record(Stage::Sent, now, Source::UserSpace),
            );
            return (Some(id), false, None);
        }
        push_event(
            &mut ft.tx_events,
            record(Stage::Scheduled, now, Source::Kernel),
        );
        let nic = egress.and_then(|n| net.nic_by_id(n));
        if ft.tx_hw.is_some() && ft.tx_hw == egress && nic.is_some_and(|n| n.ft.hwtstamp.tx) {
            push_event(
                &mut ft.tx_events,
                record(Stage::Sent, now, Source::Hardware),
            );
        } else if nic.is_none_or(|n| n.spec.caps.sw_timestamp) {
            push_event(&mut ft.tx_events, record(Stage::Sent, now, Source::Kernel));
        }
        let acked = arrival.map(|arrived| arrived + reverse + net.policy_of(egress).latency);
        match acked {
            Some(at) => push_event(&mut ft.tx_events, record(Stage::Acked, at, Source::Kernel)),
            None => ft.held_acks.push((id, reverse)),
        }
        (Some(id), true, acked)
    });
    if kernel {
        wake(WaitKey::Stream(stream_id));
        if let Some(at) = acked {
            wake_at(at, WaitKey::Stream(stream_id));
        }
    }
    id
}

/// Acknowledge the sends of `sender` held on a downed interface, whose
/// bytes now reach the peer at `arrival`. Returns when the last
/// acknowledgement is back, if there was anything to acknowledge.
pub(crate) fn ack_held(
    tcp: &mut crate::state::TcpConnections,
    net: &crate::netif::NetModel,
    sender: usize,
    arrival: Instant,
) -> Option<Instant> {
    let conn = tcp.get_mut(&sender)?;
    if conn.ft.held_acks.is_empty() {
        return None;
    }
    let link = net.policy_of(conn.nic).latency;
    let egress = conn.nic;
    let mut last = arrival;
    for (id, reverse) in std::mem::take(&mut conn.ft.held_acks) {
        let at = arrival + reverse + link;
        last = last.max(at);
        push_event(
            &mut conn.ft.tx_events,
            TcpTxRecord {
                id,
                stage: Stage::Acked,
                at,
                visible_at: at,
                source: Source::Kernel,
                egress,
            },
        );
    }
    Some(last)
}

/// Queue a send stage in the order stages become visible, forgetting the
/// oldest when nobody reads them.
fn push_event(events: &mut VecDeque<TcpTxRecord>, r: TcpTxRecord) {
    if events.len() == TX_LOG_CAP {
        events.pop_front();
    }
    let idx = events.partition_point(|e| e.visible_at <= r.visible_at);
    events.insert(idx, r);
}

/// `TCP_INFO` (or the emulated OS's equivalent) for the stream `id`.
///
/// The round trip is the one-way latency each way: the peer's
/// `set_tcp_inbound_latency` plus this end's, plus the interface latency in
/// both directions. Its variation is the interface jitter. Nothing is ever
/// retransmitted.
pub(crate) fn tcp_info(id: SocketId) -> io::Result<TcpInfo> {
    let not_connected = || {
        io::Error::new(
            io::ErrorKind::NotConnected,
            format!("no connected snare stream with id {}", id.get()),
        )
    };
    let (stream_id, local, peer) = with_net(|ctx| {
        ctx.tcp
            .values()
            .find(|c| c.id == id && !c.is_destroyed)
            .map(|c| (c.stream_id, c.local_addr, c.peer_addr))
    })
    .ok_or_else(not_connected)?;
    crate::state::release_pending_for_stream(stream_id);
    let local_policy = tcp_policy(local);
    let peer_policy = tcp_policy(peer);
    with_net(|ctx| {
        let net = &*ctx.net;
        let conn = ctx
            .tcp
            .values()
            .find(|c| c.id == id && !c.is_destroyed)
            .ok_or_else(not_connected)?;
        let link = net.policy_of(conn.nic);
        let mtu = conn
            .nic
            .and_then(|n| net.nic_by_id(n))
            .map_or(1500, |n| n.spec.mtu);
        let header = if local.is_ipv4() { 40 } else { 60 };
        let mss = mtu.saturating_sub(header);
        let rtt = local_policy.inbound_latency + peer_policy.inbound_latency + link.latency * 2;
        let rtt_var = link.jitter;
        let send_window = conn
            .peer_stream_id
            .and_then(|p| ctx.tcp.get(&p))
            .and_then(|p| {
                peer_policy
                    .recv_window
                    .map(|w| w.saturating_sub(p.buffered()))
                    .or(p.rcvbuf)
            })
            .unwrap_or(65535) as u64;
        let millis = |d: Duration| Duration::from_millis(d.as_millis() as u64);
        let mut info = TcpInfo::default();
        info.mss = mss;
        info.cwnd = 10 * u64::from(mss);
        info.send_window = Some(send_window);
        info.bytes_sent = Some(conn.ft.bytes_sent);
        info.bytes_received = Some(conn.ft.bytes_received);
        info.bytes_retransmitted = Some(0);
        match net.os {
            OsSemantics::Linux => {
                info.rtt = rtt;
                info.rtt_var = Some(rtt_var);
                info.min_rtt = Some(rtt);
                info.rto = Some((rtt + rtt_var * 4).max(Duration::from_millis(200)));
                info.segments_retransmitted = Some(0);
            }
            OsSemantics::MacOs => {
                info.rtt = millis(rtt);
                info.rtt_var = Some(millis(rtt_var));
                info.rto = Some(Duration::from_secs(1));
                info.segments_retransmitted = Some(0);
            }
            _ => {
                info.rtt = rtt;
                info.min_rtt = Some(rtt);
            }
        }
        Ok(info)
    })
}
