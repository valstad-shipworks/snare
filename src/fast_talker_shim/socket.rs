//! `Timestamped` over snare's UDP sockets. Every stamp comes from snare's
//! virtual clock: a datagram's receive stamp is the instant it reached the
//! socket, a transmit stamp the instant it left, and a timed send leaves at
//! its launch instant.

use std::io;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ::fast_talker::__sim::ctor;
use ::fast_talker::sockets::SocketMemory;
use ::fast_talker::{
    Config, Hardware, Received, Sent, Source, Timestamp, TxTime, TxTimeError, TxTimeErrorKind,
    TxTimestamp,
};

use super::platform::{Item, require};
use super::sim::{FtEvent, StackDelay};
use super::slot::{PtpState, TxRecord, TxStamping, UdpFt};
use crate::netif::{NetModel, NicId, NicKind, SimSocket, SocketId};
use crate::os::{OsSemantics, SysErrno, sys_err_for};
use crate::shim_std_udp::{ShimStdUdpSocket, would_block};
use crate::state::{FtSend, RxPacket, Timed, with_net};
use crate::time::Instant;

/// How many transmit stamps a socket keeps while nobody reads them; older
/// ones are forgotten.
pub(super) const TX_LOG_CAP: usize = 4096;

mod sealed {
    pub trait UdpShim {
        fn shim(&self) -> &crate::shim_std_udp::ShimStdUdpSocket;
    }
}

/// A socket [`Timestamped`] can drive: snare's UDP socket, which is also
/// `mio::net::UdpSocket` under snare's mio shim. Only snare's sockets
/// qualify.
pub trait Socket: SimSocket + sealed::UdpShim {
    /// Runs one send or receive on the socket.
    fn try_io<R>(&self, f: impl FnOnce() -> io::Result<R>) -> io::Result<R> {
        f()
    }
}

impl sealed::UdpShim for crate::net::UdpSocket {
    fn shim(&self) -> &ShimStdUdpSocket {
        self
    }
}

impl Socket for crate::net::UdpSocket {}

#[cfg(feature = "mio-compat")]
impl sealed::UdpShim for crate::mio_shim::net::UdpSocket {
    fn shim(&self) -> &ShimStdUdpSocket {
        self
    }
}

#[cfg(feature = "mio-compat")]
impl Socket for crate::mio_shim::net::UdpSocket {}

/// A UDP socket whose receives report the arrival time of each datagram,
/// on snare's virtual clock.
///
/// What it can stamp follows the emulated OS
/// ([`os_semantics`](crate::os_semantics)):
///
/// | OS | Receive | Transmit | `drops` | `send_at` |
/// |---|---|---|---|---|
/// | Linux | kernel, or hardware on an interface with hardware stamping, `CAP_NET_ADMIN` and a PTP clock within [`Config::tolerance`] | every send on the socket, signalled as an error condition | yes | with an ETF qdisc |
/// | macOS | kernel, in microseconds | user space, sends through `Timestamped` | `None` | `Unsupported` |
/// | Windows | kernel, or user space over loopback | kernel, or user space over loopback | `None` | `Unsupported` |
///
/// A receive stamp is the virtual instant the datagram reached the socket,
/// however long it then waited to be read. A hardware stamp is taken
/// [`StackDelay::hw_rx_before_kernel`] earlier, on the interface's PTP
/// clock ([`sim::set_ptp`](super::sim::set_ptp)).
#[derive(Debug)]
pub struct Timestamped<S> {
    io: S,
    source: Source,
    interface: Option<String>,
    config: Config,
}

struct Setup {
    source: Source,
    interface: Option<String>,
    hardware_error: Option<io::Error>,
    txtime_error: Option<io::Error>,
}

impl<S: Socket> Timestamped<S> {
    /// Enables the best timestamp source available with [`Config::default`].
    pub fn new(io: S) -> Self {
        Self::with_config(io, Config::default())
    }

    /// Like [`Timestamped::new`] with explicit options. Never fails:
    /// whatever can't be enabled degrades to the next source.
    pub fn with_config(io: S, config: Config) -> Self {
        let setup = setup(io.socket_id(), &config);
        Self::build(io, config, setup)
    }

    /// Like [`Timestamped::with_config`], but fails if the
    /// [`Hardware::Interface`] can't be configured or [`Config::txtime`]
    /// can't be set.
    pub fn try_with_config(io: S, config: Config) -> io::Result<Self> {
        let mut setup = setup(io.socket_id(), &config);
        if let (Hardware::Interface(_), Some(e)) = (&config.hardware, setup.hardware_error.take()) {
            return Err(e);
        }
        if let Some(e) = setup.txtime_error.take() {
            return Err(e);
        }
        Ok(Self::build(io, config, setup))
    }

    fn build(io: S, mut config: Config, setup: Setup) -> Self {
        if setup.txtime_error.is_some() {
            config.txtime = None;
        }
        Self {
            io,
            source: setup.source,
            interface: setup.interface,
            config,
        }
    }

    /// The best source configured on this socket.
    pub fn source(&self) -> Source {
        self.source
    }

    /// The interface hardware timestamping was enabled on, if any.
    pub fn hardware_interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }

    /// The wrapped socket.
    pub fn get_ref(&self) -> &S {
        &self.io
    }

    /// The wrapped socket.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.io
    }

    /// Unwraps the socket. Timestamping stays enabled on it.
    pub fn into_inner(self) -> S {
        self.io
    }

    /// The socket's buffer use and, on Linux, drop count. Same as
    /// `SocketMemory::of` on the socket.
    pub fn memory(&self) -> io::Result<SocketMemory> {
        socket_memory(self.io.socket_id())
    }

    /// Appends every transmit timestamp ready so far to `out` and returns
    /// how many. Never waits. Always empty without [`Config::transmit`].
    pub fn tx_timestamps(&self, out: &mut Vec<TxTimestamp>) -> io::Result<usize> {
        let id = self.io.socket_id();
        let now = Instant::now();
        let (os, records) = with_net(|ctx| {
            let mut ready = Vec::new();
            if let Some(c) = ctx.udp.iter_mut().find(|c| c.id == id && !c.dropped) {
                while c.ft.errq.front().is_some_and(|r| r.visible_at <= now) {
                    ready.extend(c.ft.errq.pop_front());
                }
            }
            let records: Vec<(TxRecord, Option<NicStamping>)> = ready
                .into_iter()
                .map(|r| (r, NicStamping::of(ctx.net, r.egress)))
                .collect();
            (ctx.net.os, records)
        });
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
                Source::Kernel if os == OsSemantics::MacOs => {
                    ctor::timestamp(micros(wall), Source::Kernel, None)
                }
                source => ctor::timestamp(wall, source, None),
            };
            out.push(ctor::tx_timestamp(r.id, timestamp));
        }
        Ok(records.len())
    }

    /// Sends one datagram to `to`.
    pub fn send_to(&self, buf: &[u8], to: SocketAddr) -> io::Result<Sent> {
        self.io.try_io(|| self.send_inner(buf, Some(to), None))
    }

    /// Sends one datagram on a connected socket.
    pub fn send(&self, buf: &[u8]) -> io::Result<Sent> {
        self.io.try_io(|| self.send_inner(buf, None, None))
    }

    /// Sends one datagram to `to`, to leave at `at` (see [`Config::txtime`]).
    /// Take `at` from [`compat::now`](crate::fast_talker::compat::now), not
    /// `std::time::SystemTime::now()`. Fails with `InvalidInput` without
    /// [`Config::txtime`], and with `Unsupported` off Linux. Without an ETF
    /// qdisc on the outgoing interface the datagram leaves at once; a time
    /// the qdisc can't honour is reported by [`Timestamped::txtime_errors`].
    pub fn send_to_at(&self, buf: &[u8], to: SocketAddr, at: SystemTime) -> io::Result<Sent> {
        self.io.try_io(|| self.send_timed(buf, Some(to), at))
    }

    /// Like [`Timestamped::send_to_at`] on a connected socket.
    pub fn send_at(&self, buf: &[u8], at: SystemTime) -> io::Result<Sent> {
        self.io.try_io(|| self.send_timed(buf, None, at))
    }

    /// Appends every timed send the qdisc has dropped since the last call.
    /// Never waits.
    pub fn txtime_errors(&self, out: &mut Vec<TxTimeError>) -> io::Result<usize> {
        let id = self.io.socket_id();
        let now = Instant::now();
        let errors = with_net(|ctx| {
            let mut ready = Vec::new();
            if let Some(c) = ctx.udp.iter_mut().find(|c| c.id == id && !c.dropped) {
                while c.ft.txtime_errors.front().is_some_and(|(at, _)| *at <= now) {
                    ready.extend(c.ft.txtime_errors.pop_front().map(|(_, e)| e));
                }
            }
            ready
        });
        let n = errors.len();
        out.extend(errors);
        Ok(n)
    }

    /// Receives one datagram, waiting as the socket's `recv_from` does.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<Received> {
        self.io.try_io(|| {
            let pkt = self
                .io
                .shim()
                .take_packet(false, "ft udp recv")?
                .ok_or_else(would_block)?;
            self.received(buf, pkt)
        })
    }

    /// Receives one datagram.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Timestamp)> {
        self.recv_from(buf).map(|r| (r.len, r.timestamp))
    }

    /// Receives up to `bufs.len()` datagrams, one per buffer, appending a
    /// [`Received`] for each to `out`. Waits for the first datagram as
    /// [`Timestamped::recv_from`] does, then takes whatever else is queued.
    pub fn recv_batch(&self, bufs: &mut [&mut [u8]], out: &mut Vec<Received>) -> io::Result<usize> {
        let Some((first, rest)) = bufs.split_first_mut() else {
            return Ok(0);
        };
        out.push(self.recv_from(first)?);
        let mut n = 1;
        for buf in rest {
            let Some(pkt) = self.take_now()? else {
                break;
            };
            out.push(self.received(buf, pkt)?);
            n += 1;
        }
        Ok(n)
    }

    /// Calls `f` with the payload and metadata of every queued datagram and
    /// returns how many there were. Never waits.
    pub fn drain(&self, buf: &mut [u8], mut f: impl FnMut(&[u8], Received)) -> io::Result<usize> {
        let mut n = 0;
        while let Some(pkt) = self.take_now()? {
            let r = self.received(buf, pkt)?;
            f(&buf[..r.len], r);
            n += 1;
        }
        Ok(n)
    }

    fn take_now(&self) -> io::Result<Option<RxPacket>> {
        match self
            .io
            .try_io(|| self.io.shim().take_packet(true, "ft udp recv"))
        {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            r => r,
        }
    }

    fn received(&self, buf: &mut [u8], pkt: RxPacket) -> io::Result<Received> {
        let len = ShimStdUdpSocket::copy_into(buf, &pkt.data)?;
        let (os, nic) = with_net(|ctx| (ctx.net.os, NicStamping::of(ctx.net, pkt.ingress)));
        let clocks = Clocks::read();
        let timestamp = rx_timestamp(os, pkt.at, nic, &clocks, self.config.tolerance);
        let drops = (os == OsSemantics::Linux).then_some(pkt.drops_at_enqueue);
        Ok(ctor::received(len, pkt.source, timestamp, drops))
    }

    fn send_timed(&self, buf: &[u8], to: Option<SocketAddr>, at: SystemTime) -> io::Result<Sent> {
        require(Item::SendAt)?;
        if self.config.txtime.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "send_at needs Config::txtime",
            ));
        }
        let timed = Timed {
            at: crate::sched::instant_of_wall(at),
            requested: at,
        };
        self.send_inner(buf, to, Some(timed))
    }

    fn send_inner(
        &self,
        buf: &[u8],
        to: Option<SocketAddr>,
        timed: Option<Timed>,
    ) -> io::Result<Sent> {
        crate::sched::note_effect("ft udp send");
        let socket = self.io.shim();
        let dst = match to {
            Some(addr) => addr,
            None => socket.peer_addr()?,
        };
        crate::shim_std_udp::family_check(socket.local_addr()?, dst, false)?;
        let sent = crate::state::udp_send_ex(
            socket.id(),
            socket.local_addr()?,
            buf,
            dst,
            socket.broadcast_ok(),
            FtSend {
                via_ft: true,
                timed,
            },
        )?;
        if sent.etf_ignored {
            super::sim::log(FtEvent::TxTimeWithoutEtf {
                socket: socket.id(),
            });
        }
        Ok(ctor::sent(sent.len, sent.tx_id))
    }
}

impl<S> Deref for Timestamped<S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.io
    }
}

impl<S> DerefMut for Timestamped<S> {
    fn deref_mut(&mut self) -> &mut S {
        &mut self.io
    }
}

#[cfg(feature = "mio-compat")]
impl<S: crate::mio_shim::event::Source> crate::mio_shim::event::Source for Timestamped<S> {
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

/// Enable timestamping on the socket `id` as the emulated OS would, and
/// record it on the socket.
fn setup(id: SocketId, config: &Config) -> Setup {
    with_net(|ctx| {
        let net = &mut *ctx.net;
        let os = net.os;
        let privileged = net.privileges.net_admin || net.privileges.root;
        let Some(conn) = ctx.udp.iter_mut().find(|c| c.id == id && !c.dropped) else {
            return Setup {
                source: Source::UserSpace,
                interface: None,
                hardware_error: Some(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no such snare socket",
                )),
                txtime_error: None,
            };
        };
        let mut setup = Setup {
            source: Source::Kernel,
            interface: None,
            hardware_error: None,
            txtime_error: None,
        };
        let local = conn.bound_addr.ip();
        let ft = &mut conn.ft;
        let previous = ft.tx;
        ft.tx_hw = None;
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
            if config.txtime.is_some() && !privileged {
                setup.txtime_error = Some(sys_err_for(os, SysErrno::Perm));
            }
            ft.tx = if config.transmit {
                TxStamping::Kernel
            } else {
                TxStamping::Off
            };
        } else {
            if config.hardware != Hardware::Off {
                setup.hardware_error = Some(unsupported("hardware timestamps are Linux-only"));
            }
            if config.txtime.is_some() {
                setup.txtime_error = Some(unsupported("timed sends (SO_TXTIME) are Linux-only"));
            }
            ft.tx = if config.transmit {
                TxStamping::Library
            } else {
                TxStamping::Off
            };
        }
        let fresh_ids = match ft.tx {
            TxStamping::Library => true,
            TxStamping::Kernel => previous != TxStamping::Kernel,
            TxStamping::Off => false,
        };
        if fresh_ids {
            ft.next_tx_id = 0;
            ft.errq.clear();
        }
        ft.timestamping = Some(config.clone());
        ft.source = Some(setup.source);
        ft.interface = setup.interface.clone();
        ft.txtime = config.txtime.filter(|_| setup.txtime_error.is_none());
        setup
    })
}

/// Turn on hardware receive stamping on the interface `name`, and transmit
/// stamping when asked and the interface can. Returns the interface and
/// whether it stamps sends.
pub(super) fn enable_hardware(
    net: &mut NetModel,
    name: &str,
    transmit: bool,
    privileged: bool,
) -> io::Result<(NicId, bool)> {
    let os = net.os;
    let nic = net
        .nics
        .iter_mut()
        .find(|n| n.spec.name == name)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no interface named {name:?}"),
            )
        })?;
    if !nic.spec.caps.hw_rx_timestamp {
        return Err(unsupported(&format!(
            "interface {name:?} has no hardware timestamping"
        )));
    }
    if !privileged {
        return Err(sys_err_for(os, SysErrno::Perm));
    }
    nic.ft.hwtstamp.rx = true;
    let tx = transmit && nic.spec.caps.hw_tx_timestamp;
    if tx {
        nic.ft.hwtstamp.tx = true;
    }
    Ok((nic.id, tx))
}

pub(super) fn unsupported(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, what.to_owned())
}

/// What stamps the interface a datagram crossed can give.
#[derive(Debug, Clone, Copy)]
pub(super) struct NicStamping {
    loopback: bool,
    pub(super) software: bool,
    hardware_rx: bool,
    pub(super) ptp: Option<PtpState>,
}

impl NicStamping {
    pub(super) fn of(net: &NetModel, id: Option<NicId>) -> Option<Self> {
        let nic = net.nic_by_id(id?)?;
        Some(Self {
            loopback: nic.spec.kind == NicKind::Loopback,
            software: nic.spec.caps.sw_timestamp,
            hardware_rx: nic.ft.hwtstamp.rx && nic.spec.caps.hw_rx_timestamp,
            ptp: nic.ft.ptp,
        })
    }
}

/// The simulated host's clocks, read once per call.
pub(super) struct Clocks {
    pub(super) stack: StackDelay,
    pub(super) tai: Duration,
    pub(super) user: SystemTime,
}

impl Clocks {
    pub(super) fn read() -> Self {
        let slot = crate::state::ft_slot();
        let g = slot.inner.lock();
        Self {
            stack: g.stack_delay,
            tai: g.tai_offset,
            user: crate::time::SystemTime::now().into(),
        }
    }
}

pub(super) fn rx_timestamp(
    os: OsSemantics,
    arrived: Instant,
    nic: Option<NicStamping>,
    clocks: &Clocks,
    tolerance: Duration,
) -> Timestamp {
    let kernel = crate::sched::wall_of(arrived);
    match os {
        OsSemantics::Linux => match nic.filter(|n| n.hardware_rx && !n.loopback) {
            Some(n) => {
                let before = clocks.stack.hw_rx_before_kernel;
                let wall = kernel.checked_sub(before).unwrap_or(kernel);
                let at = arrived.checked_sub(before).unwrap_or(arrived);
                let raw = phc_raw(n.ptp, wall, at, clocks.tai);
                resolve(
                    Some(kernel),
                    Some(raw),
                    &candidates(raw, clocks.tai),
                    clocks.user,
                    tolerance,
                )
            }
            None => ctor::timestamp(kernel, Source::Kernel, None),
        },
        OsSemantics::MacOs => ctor::timestamp(micros(kernel), Source::Kernel, None),
        _ => match nic {
            Some(n) if n.loopback || !n.software => {
                ctor::timestamp(clocks.user, Source::UserSpace, None)
            }
            _ => ctor::timestamp(kernel, Source::Kernel, None),
        },
    }
}

/// The reading of an interface's PTP clock when the system clock read
/// `wall`. Without a PTP clock the interface counts from snare's virtual
/// epoch, a domain unrelated to the system clock.
pub(super) fn phc_raw(
    ptp: Option<PtpState>,
    wall: SystemTime,
    at: Instant,
    tai: Duration,
) -> Duration {
    let Some(p) = ptp else {
        return at.as_virtual();
    };
    let mut raw = wall.duration_since(UNIX_EPOCH).unwrap_or_default();
    if p.tai {
        raw += tai;
    }
    let offset = Duration::from_nanos(p.offset_nanos.unsigned_abs());
    if p.offset_nanos >= 0 {
        raw + offset
    } else {
        raw.saturating_sub(offset)
    }
}

/// A PTP clock reading as system-clock candidates: as is, and as TAI.
pub(super) fn candidates(raw: Duration, tai: Duration) -> Vec<SystemTime> {
    let mut out = vec![UNIX_EPOCH + raw];
    if !tai.is_zero() && raw > tai {
        out.push(UNIX_EPOCH + (raw - tai));
    }
    out
}

/// fast-talker's choice between the sources a packet offered: the first
/// hardware candidate within `tolerance` of the kernel stamp, else the
/// kernel stamp, else user space.
pub(super) fn resolve(
    kernel: Option<SystemTime>,
    hardware_raw: Option<Duration>,
    hardware: &[SystemTime],
    user: SystemTime,
    tolerance: Duration,
) -> Timestamp {
    let reference = kernel.unwrap_or(user);
    let diff = |a: SystemTime, b: SystemTime| a.duration_since(b).unwrap_or_else(|e| e.duration());
    if let Some(&time) = hardware.iter().find(|&&t| diff(t, reference) <= tolerance) {
        return ctor::timestamp(time, Source::Hardware, hardware_raw);
    }
    match kernel {
        Some(time) => ctor::timestamp(time, Source::Kernel, hardware_raw),
        None => ctor::timestamp(user, Source::UserSpace, hardware_raw),
    }
}

fn micros(t: SystemTime) -> SystemTime {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    UNIX_EPOCH + Duration::from_micros(d.as_micros() as u64)
}

/// What a timed send does on its outgoing interface.
pub(crate) enum TimedFate {
    /// Not timed, or an ETF deadline: leaves now.
    Now,
    /// Held by the ETF qdisc until its launch instant.
    At(Instant),
    /// No ETF qdisc on the interface: leaves now, its time ignored.
    Ignored,
    /// Dropped by the qdisc; the error is reported at this instant.
    Dropped(Instant),
}

/// Put a timed send through the outgoing interface's ETF qdisc. Runs under
/// snare's state lock.
pub(crate) fn timed_fate(
    net: &NetModel,
    ft: &mut UdpFt,
    egress: NicId,
    timed: Option<Timed>,
    now: Instant,
) -> TimedFate {
    let (Some(timed), Some(mode)) = (timed, ft.txtime) else {
        return TimedFate::Now;
    };
    let etf = net
        .nic_by_id(egress)
        .and_then(|n| n.ft.etf.get(&None).or_else(|| n.ft.etf.values().next()))
        .copied();
    let Some(etf) = etf else {
        return TimedFate::Ignored;
    };
    let deadline = mode == TxTime::Deadline;
    let launch = timed.at.filter(|&at| at >= now && etf.deadline == deadline);
    let Some(launch) = launch else {
        push_txtime_error(
            ft,
            now,
            ctor::tx_time_error(timed.requested, TxTimeErrorKind::Invalid),
        );
        return TimedFate::Dropped(now);
    };
    if ft.missed_budget > 0 {
        ft.missed_budget -= 1;
        push_txtime_error(
            ft,
            launch,
            ctor::tx_time_error(timed.requested, TxTimeErrorKind::Missed),
        );
        return TimedFate::Dropped(launch);
    }
    if deadline {
        TimedFate::Now
    } else {
        TimedFate::At(launch)
    }
}

/// Queue a dropped timed send's error, ready at `at`, in the order the
/// errors become ready.
fn push_txtime_error(ft: &mut UdpFt, at: Instant, error: TxTimeError) {
    let idx = ft.txtime_errors.partition_point(|(t, _)| *t <= at);
    ft.txtime_errors.insert(idx, (at, error));
}

/// Give a send its transmit stamp id and queue its stamp. Returns the id
/// and, for a stamp the kernel signals as an error condition, when it
/// becomes ready. Runs under snare's state lock.
pub(crate) fn on_send(
    net: &NetModel,
    ft: &mut UdpFt,
    egress: NicId,
    wire: Instant,
    now: Instant,
    via_ft: bool,
    on_wire: bool,
) -> (Option<u32>, Option<Instant>) {
    let issue = match ft.tx {
        TxStamping::Off => false,
        TxStamping::Kernel => true,
        TxStamping::Library => via_ft,
    };
    if !issue {
        return (None, None);
    }
    let id = ft.next_tx_id;
    ft.next_tx_id = id.wrapping_add(1);
    if !on_wire {
        return (Some(id), None);
    }
    let nic = net.nic_by_id(egress);
    let software = nic.is_some_and(|n| n.spec.caps.sw_timestamp);
    let loopback = nic.is_none_or(|n| n.spec.kind == NicKind::Loopback);
    let (source, at) = match (ft.tx, net.os) {
        (TxStamping::Kernel, _) => {
            if ft.tx_hw == Some(egress) && nic.is_some_and(|n| n.ft.hwtstamp.tx) {
                (Source::Hardware, wire)
            } else if software {
                (Source::Kernel, wire)
            } else {
                return (Some(id), None);
            }
        }
        (_, OsSemantics::Windows) if software && !loopback => (Source::Kernel, wire),
        _ => (Source::UserSpace, now),
    };
    let kernel = ft.tx == TxStamping::Kernel;
    let visible_at = if kernel { wire } else { now };
    if ft.errq.len() == TX_LOG_CAP {
        ft.errq.pop_front();
    }
    let idx = ft.errq.partition_point(|r| r.visible_at <= visible_at);
    ft.errq.insert(
        idx,
        TxRecord {
            id,
            at,
            visible_at,
            source,
            egress: Some(egress),
        },
    );
    (Some(id), kernel.then_some(visible_at))
}

/// `SocketMemory::of` a snare socket, as the emulated OS reports it.
pub(crate) fn socket_memory(id: SocketId) -> io::Result<SocketMemory> {
    let now = Instant::now();
    with_net(|mut ctx| {
        socket_memory_locked(&mut ctx, id, now).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no live snare socket with id {}", id.get()),
            )
        })
    })
}

/// [`socket_memory`] under the state lock. A listener reports its buffer
/// sizes with nothing queued.
pub(crate) fn socket_memory_locked(
    ctx: &mut crate::state::NetCtx<'_>,
    id: SocketId,
    now: Instant,
) -> Option<SocketMemory> {
    let net = &mut *ctx.net;
    let os = net.os;
    let clamp = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    let mut m = SocketMemory::default();
    if let Some(c) = ctx.udp.iter_mut().find(|c| c.id == id && !c.dropped) {
        crate::state::release_due_locked(net, c, now);
        let rmem = match os {
            OsSemantics::Linux => {
                c.queued_bytes + c.to_local.len() * net.limits.per_datagram_overhead
            }
            OsSemantics::MacOs => c
                .to_local
                .iter()
                .map(|p| p.data.len() + if p.source.is_ipv4() { 16 } else { 28 })
                .sum(),
            _ => c.to_local.front().map_or(0, |p| p.data.len()),
        };
        m.rmem_alloc = clamp(rmem);
        m.rcvbuf = clamp(c.rcvbuf.unwrap_or(net.limits.rmem_default));
        m.sndbuf = clamp(c.sndbuf.unwrap_or(net.limits.wmem_default));
        m.drops = (os == OsSemantics::Linux).then_some(c.drops);
        return Some(m);
    }
    let (rmem, rcvbuf, sndbuf) =
        if let Some(c) = ctx.tcp.values().find(|c| c.id == id && !c.is_destroyed) {
            (c.incoming.len(), c.rcvbuf, c.sndbuf)
        } else if ctx.listeners.values().any(|l| l.id == id && !l.is_closed) {
            (0, None, None)
        } else {
            return None;
        };
    m.rmem_alloc = clamp(rmem);
    m.rcvbuf = clamp(rcvbuf.unwrap_or(net.limits.rmem_default));
    m.sndbuf = clamp(sndbuf.unwrap_or(net.limits.wmem_default));
    m.drops = (os == OsSemantics::Linux).then_some(0);
    Some(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disciplined_tai_clock_resolves_to_hardware() {
        let wall = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let tai = Duration::from_secs(37);
        let ptp = PtpState {
            clock: 0,
            offset_nanos: 500,
            uncertainty: Duration::ZERO,
            tai: true,
        };
        let raw = phc_raw(Some(ptp), wall, Instant::from_virtual(Duration::ZERO), tai);
        let t = resolve(
            Some(wall),
            Some(raw),
            &candidates(raw, tai),
            wall,
            Duration::from_millis(100),
        );
        assert_eq!(t.source, Source::Hardware);
        assert_eq!(t.time, wall + Duration::from_nanos(500));
        assert_eq!(t.hardware_raw, Some(raw));
    }

    #[test]
    fn a_timed_send_reaches_a_virtual_tester_at_its_launch() {
        use crate::netif::{IpNet, NicSpec, add_nic};
        crate::register_test();
        crate::set_os_semantics(OsSemantics::Linux);
        crate::pause_time();
        add_nic(NicSpec::new("eth0").address("10.0.0.1/24".parse::<IpNet>().unwrap())).unwrap();
        crate::netif::set_etf_internal("eth0", None, Some(super::super::nic::Etf::default()))
            .unwrap();
        let tx = Timestamped::with_config(
            crate::net::UdpSocket::bind("10.0.0.1:7001").unwrap(),
            Config {
                txtime: Some(TxTime::Launch),
                ..Config::default()
            },
        );
        let tester: SocketAddr = "10.0.0.9:9000".parse().unwrap();
        let launch = crate::fast_talker::compat::now() + Duration::from_millis(10);
        tx.send_to_at(b"x", tester, launch).unwrap();
        tx.send_to(b"now", tester).unwrap();
        let first = crate::state::pop_latest_packet(tester).expect("the untimed send");
        assert_eq!(first.data, b"now");
        assert!(!crate::state::has_pending_udp_packet(tester));
        assert!(crate::state::pop_latest_packet(tester).is_none());
        let due = crate::state::earliest_pending_release().expect("a release deadline");
        assert_eq!(crate::sched::wall_of(due), launch);
        crate::advance_time(Duration::from_millis(10));
        assert!(crate::state::has_pending_udp_packet(tester));
        let pkt = crate::state::pop_latest_packet(tester).unwrap();
        assert_eq!(pkt.data, b"x");
        assert_eq!(crate::sched::wall_of(pkt.at), launch);
    }

    #[test]
    fn a_free_running_clock_falls_back_to_the_kernel() {
        let wall = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let at = Instant::from_virtual(Duration::from_secs(3));
        let raw = phc_raw(None, wall, at, Duration::from_secs(37));
        assert_eq!(raw, Duration::from_secs(3));
        let t = resolve(
            Some(wall),
            Some(raw),
            &candidates(raw, Duration::from_secs(37)),
            wall,
            Duration::from_millis(100),
        );
        assert_eq!(t.source, Source::Kernel);
        assert_eq!(t.hardware_raw, Some(raw));
    }
}
