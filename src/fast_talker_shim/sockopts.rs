//! fast-talker's `SocketOptions` and socket table over snare's sockets.
//! Options follow the emulated OS: which fields exist, the order they are
//! applied in, the privileges they need and the errors they give.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use ::fast_talker::__sim::ctor;
use ::fast_talker::sockets::{Protocol, SocketInfo, SocketOptions, State};

use super::platform::{Item, require};
use super::sim::{FtEvent, SockOptsSnapshot, SocketApply};
use crate::netif::{BufDir, NetModel, NicId, SocketId, SocketKind, set_socket_buffer};
use crate::os::{Errno, OsSemantics, SysErrno, os_err_for, os_error_code, sys_err_for};
use crate::state::{NetCtx, PeerClose, TcpConnection, TcpListenerState, UdpConnection, with_net};
use crate::time::Instant;

/// A snare socket of any kind, under the state lock.
enum Sock<'a> {
    Udp(&'a mut UdpConnection),
    Tcp(&'a mut TcpConnection),
    Listener(&'a mut TcpListenerState),
}

impl Sock<'_> {
    fn local(&self) -> SocketAddr {
        match self {
            Sock::Udp(c) => c.bound_addr,
            Sock::Tcp(c) => c.local_addr,
            Sock::Listener(l) => l.bound_addr,
        }
    }

    fn opts(&mut self) -> (&mut SocketOptions, &mut SockOptsSnapshot) {
        match self {
            Sock::Udp(c) => (&mut c.ft.sockopts, &mut c.ft.effective),
            Sock::Tcp(c) => (&mut c.ft.sockopts, &mut c.ft.effective),
            Sock::Listener(l) => (&mut l.ft.sockopts, &mut l.ft.effective),
        }
    }

    fn effective(&mut self) -> &mut SockOptsSnapshot {
        self.opts().1
    }
}

fn gone(id: SocketId) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("no live snare socket with id {}", id.get()),
    )
}

/// Run `f` on the socket `id` under the state lock.
fn with_sock<R>(
    id: SocketId,
    f: impl FnOnce(&NetModel, Sock<'_>) -> io::Result<R>,
) -> io::Result<R> {
    with_net(|ctx| {
        let NetCtx {
            net,
            udp,
            tcp,
            listeners,
        } = ctx;
        let sock = if let Some(c) = udp.iter_mut().find(|c| c.id == id && !c.dropped) {
            Sock::Udp(c)
        } else if let Some(c) = tcp.values_mut().find(|c| c.id == id && !c.is_destroyed) {
            Sock::Tcp(c)
        } else if let Some(l) = listeners.values_mut().find(|l| l.id == id && !l.is_closed) {
            Sock::Listener(l)
        } else {
            return Err(gone(id));
        };
        f(net, sock)
    })
}

/// Put one applied or refused setting in the socket's log and the shim's
/// events.
pub(crate) fn record(id: SocketId, what: String, r: &io::Result<()>) {
    let tid = crate::threads::current_tid();
    let at = Instant::now();
    let result = r.as_ref().map(|_| ()).map_err(io::Error::kind);
    let entry = SocketApply {
        at,
        tid,
        what: what.clone(),
        result,
        os_error: r.as_ref().err().and_then(os_error_code),
    };
    let _ = with_sock(id, |_, mut s| {
        s.effective().log.push(entry);
        Ok(())
    });
    super::sim::log(FtEvent::Socket {
        socket: id,
        what,
        result,
    });
}

fn step(id: SocketId, what: String, f: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    let r = f();
    record(id, what, &r);
    r
}

/// fast-talker's check for fields the platform lacks, with its text, for
/// the emulated OS.
fn unsupported(o: &SocketOptions, os: OsSemantics) -> io::Result<()> {
    let mut set = Vec::new();
    if os != OsSemantics::Linux {
        if o.priority.is_some() {
            set.push("priority");
        }
        if o.busy_poll.is_some() || o.prefer_busy_poll.is_some() || o.busy_poll_budget.is_some() {
            set.push("busy polling");
        }
    }
    if os != OsSemantics::Windows && o.cpu_affinity.is_some() {
        set.push("cpu_affinity");
    }
    if os == OsSemantics::Windows && o.dscp.is_some() {
        set.push("dscp");
    }
    if set.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{} not available on this platform", set.join(" and ")),
        ))
    }
}

/// `SocketOptions::apply` on the snare socket `id`: the set fields in
/// fast-talker's order for the emulated OS, stopping at the first failure.
pub(crate) fn apply(id: SocketId, o: &SocketOptions) -> io::Result<()> {
    let os = crate::os_semantics();
    let r = unsupported(o, os);
    if r.is_err() {
        record(id, "SocketOptions".into(), &r);
        return r;
    }
    if let Some(n) = o.recv_buffer {
        step(id, format!("recv_buffer({n})"), || {
            buffer(id, BufDir::Recv, n, os)
        })?;
    }
    if let Some(n) = o.send_buffer {
        step(id, format!("send_buffer({n})"), || {
            buffer(id, BufDir::Send, n, os)
        })?;
    }
    if os != OsSemantics::Windows
        && let Some(code) = o.dscp
    {
        step(id, format!("dscp({code})"), || dscp(id, code, os))?;
    }
    if os == OsSemantics::Linux
        && let Some(p) = o.priority
    {
        step(id, format!("priority({p})"), || priority(id, p, os))?;
    }
    if let Some(dev) = &o.bind_device {
        let modern = kernel_binds_unprivileged();
        step(id, format!("bind_device({dev:?})"), || {
            bind_device(id, dev, os, modern)
        })?;
    }
    if let Some(df) = o.dont_fragment {
        step(id, format!("dont_fragment({df})"), || {
            with_sock(id, |_, mut s| {
                if let Sock::Udp(c) = &mut s {
                    c.dont_fragment = df;
                }
                s.effective().dont_fragment = df;
                s.opts().0.dont_fragment = Some(df);
                Ok(())
            })
        })?;
    }
    if os == OsSemantics::Linux {
        if let Some(d) = o.busy_poll {
            step(id, format!("busy_poll({d:?})"), || busy_poll(id, d, os))?;
        }
        if let Some(on) = o.prefer_busy_poll {
            step(id, format!("prefer_busy_poll({on})"), || {
                admin_setting(id, os, on, |e, o| {
                    e.prefer_busy_poll = on;
                    o.prefer_busy_poll = Some(on);
                })
            })?;
        }
        if let Some(b) = o.busy_poll_budget {
            step(id, format!("busy_poll_budget({b})"), || {
                let raise = with_sock(id, |_, mut s| Ok(b > s.effective().busy_poll_budget))?;
                admin_setting(id, os, raise, |e, o| {
                    e.busy_poll_budget = b;
                    o.busy_poll_budget = Some(b);
                })
            })?;
        }
    }
    if os == OsSemantics::Windows
        && let Some(cpu) = o.cpu_affinity
    {
        step(id, format!("cpu_affinity({cpu})"), || cpu_affinity(cpu, os))?;
    }
    Ok(())
}

/// `SO_RCVBUF`/`SO_SNDBUF`. On Linux fast-talker tries the `FORCE` variant
/// first and falls back to the capped one when it is refused.
fn buffer(id: SocketId, dir: BufDir, n: usize, os: OsSemantics) -> io::Result<()> {
    let v = n.min(i32::MAX as usize);
    let effective = match os {
        OsSemantics::Linux => match set_socket_buffer(id, dir, v, true) {
            Err(e) if os_error_code(&e) == Some(os.sys_errno(SysErrno::Perm)) => {
                set_socket_buffer(id, dir, v, false)
            }
            r => r,
        },
        _ => set_socket_buffer(id, dir, v, false),
    }?;
    with_sock(id, |_, mut s| {
        let (asked, eff) = s.opts();
        match dir {
            BufDir::Recv => {
                asked.recv_buffer = Some(n);
                eff.recv_buffer = Some(effective);
            }
            BufDir::Send => {
                asked.send_buffer = Some(n);
                eff.send_buffer = Some(effective);
            }
        }
        Ok(())
    })
}

/// Linux's `rt_tos2priority`: the `SO_PRIORITY` an IPv4 TOS byte implies.
fn tos_priority(tos: u8) -> u32 {
    const MAP: [u32; 16] = [0, 0, 0, 0, 2, 2, 2, 2, 6, 6, 6, 6, 4, 4, 4, 4];
    MAP[usize::from((tos & 0x1e) >> 1)]
}

fn dscp(id: SocketId, code: u8, os: OsSemantics) -> io::Result<()> {
    if code > 63 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("DSCP {code} is out of range 0-63"),
        ));
    }
    let tos = code << 2;
    with_sock(id, |_, mut s| {
        let v4 = s.local().is_ipv4();
        let (asked, eff) = s.opts();
        if os == OsSemantics::Linux && v4 && eff.tos != Some(tos) {
            eff.priority = Some(tos_priority(tos));
        }
        eff.tos = Some(tos);
        asked.dscp = Some(code);
        Ok(())
    })
}

fn priority(id: SocketId, p: u32, os: OsSemantics) -> io::Result<()> {
    with_sock(id, |net, mut s| {
        let privileged = net.privileges.net_admin || net.privileges.net_raw;
        if p > 6 && !privileged {
            return Err(sys_err_for(os, SysErrno::Perm));
        }
        let (asked, eff) = s.opts();
        eff.priority = Some(p);
        asked.priority = Some(p);
        Ok(())
    })
}

/// Whether the simulated kernel lets an unprivileged socket bind to a
/// device it is not bound to yet (Linux 5.7 and later).
fn kernel_binds_unprivileged() -> bool {
    let kernel = crate::state::ft_slot()
        .inner
        .lock()
        .sys_facts
        .kernel
        .clone();
    let mut parts = kernel
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .map(|p| p.parse::<u32>().unwrap_or(0));
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    (major, minor) >= (5, 7)
}

fn bind_device(id: SocketId, dev: &str, os: OsSemantics, modern_kernel: bool) -> io::Result<()> {
    with_sock(id, |net, mut s| {
        let nic = |name: &str| net.nic_by_name(name).map(|n| n.id);
        let target: Option<NicId> = match os {
            OsSemantics::Linux => {
                let bound = match &s {
                    Sock::Udp(c) => c.bound_device.is_some(),
                    Sock::Tcp(c) => c.bound_device.is_some(),
                    Sock::Listener(l) => l.bound_device.is_some(),
                };
                if (bound || !modern_kernel) && !net.privileges.net_raw {
                    return Err(sys_err_for(os, SysErrno::Perm));
                }
                if dev.is_empty() {
                    None
                } else {
                    Some(nic(dev).ok_or_else(|| os_err_for(os, Errno::NoDev))?)
                }
            }
            OsSemantics::Windows => Some(nic(dev).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no interface named {dev:?}"),
                )
            })?),
            _ => Some(nic(dev).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("no interface {dev:?}"))
            })?),
        };
        let send_only = os == OsSemantics::Windows;
        match &mut s {
            Sock::Udp(c) if send_only => c.unicast_if = target,
            Sock::Udp(c) => c.bound_device = target,
            Sock::Tcp(c) if !send_only => c.bound_device = target,
            Sock::Listener(l) if !send_only => l.bound_device = target,
            _ => {}
        }
        let (asked, eff) = s.opts();
        eff.bind_device = target.and_then(|t| net.nic_name(Some(t)));
        eff.bind_device_send_only = send_only && target.is_some();
        asked.bind_device = Some(dev.to_string());
        Ok(())
    })
}

fn admin_setting(
    id: SocketId,
    os: OsSemantics,
    needs_admin: bool,
    set: impl FnOnce(&mut SockOptsSnapshot, &mut SocketOptions),
) -> io::Result<()> {
    with_sock(id, |net, mut s| {
        if needs_admin && !net.privileges.net_admin {
            return Err(sys_err_for(os, SysErrno::Perm));
        }
        let (asked, eff) = s.opts();
        set(eff, asked);
        Ok(())
    })
}

/// `SO_BUSY_POLL`: raising it needs `CAP_NET_ADMIN`.
fn busy_poll(id: SocketId, d: Duration, os: OsSemantics) -> io::Result<()> {
    let micros = d.as_micros().min(i32::MAX as u128) as u64;
    let d = Duration::from_micros(micros);
    let raise = with_sock(id, |_, mut s| Ok(d > s.effective().busy_poll))?;
    admin_setting(id, os, raise, |e, o| {
        e.busy_poll = d;
        o.busy_poll = Some(d);
    })
}

/// `SIO_CPU_AFFINITY` is accepted only before a socket is bound, and a
/// snare socket always is.
fn cpu_affinity(cpu: usize, os: OsSemantics) -> io::Result<()> {
    u16::try_from(cpu)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "CPU index out of range"))?;
    Err(os_err_for(os, Errno::Inval))
}

fn tcp_state(c: &TcpConnection) -> State {
    match (c.peer_close, c.write_shutdown) {
        (PeerClose::Reset, _) => State::Close,
        (PeerClose::Open, false) => State::Established,
        (PeerClose::Open, true) => State::FinWait2,
        (PeerClose::Fin, false) => State::CloseWait,
        (PeerClose::Fin, true) => State::LastAck,
    }
}

/// The owning uid the socket table reports.
fn uid(net: &NetModel) -> u32 {
    match (net.privileges.root, net.os) {
        (true, _) => 0,
        (false, OsSemantics::MacOs) => 501,
        (false, _) => 1000,
    }
}

/// `sockets::udp()` / `sockets::tcp()`: every live snare socket of
/// `protocol`, shaped as the emulated OS's socket table reports it.
pub(crate) fn list(protocol: Protocol) -> io::Result<Vec<SocketInfo>> {
    require(Item::SocketTable)?;
    let now = Instant::now();
    Ok(with_net(|mut ctx| {
        let table = crate::netif::socket_table_locked(&ctx);
        let mut out = Vec::new();
        for e in table {
            let wanted = match protocol {
                Protocol::Udp => e.kind == SocketKind::Udp,
                _ => e.kind != SocketKind::Udp,
            };
            if !wanted {
                continue;
            }
            let memory = super::socket::socket_memory_locked(&mut ctx, e.id, now);
            let net = &*ctx.net;
            let os = net.os;
            let (state, recv_queue, send_queue) = match e.kind {
                SocketKind::Udp => {
                    let state = if e.peer.is_some() {
                        State::Established
                    } else {
                        State::Close
                    };
                    (state, e.queued_bytes, 0)
                }
                SocketKind::TcpListener => (State::Listen, e.queued, 128),
                _ => {
                    let c = ctx.tcp.values().find(|c| c.id == e.id);
                    let state = c.map_or(State::Established, tcp_state);
                    (state, c.map_or(0, |c| c.incoming.len()), 0)
                }
            };
            let clamp = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
            let interface = e
                .bound_device
                .as_deref()
                .and_then(|n| net.nic_by_name(n))
                .map_or(0, |n| n.id.index());
            let info = match os {
                OsSemantics::Windows => {
                    let remote = match e.kind {
                        SocketKind::TcpStream => e.peer,
                        _ => None,
                    };
                    let state = if e.kind == SocketKind::Udp {
                        State::Close
                    } else {
                        state
                    };
                    let interface = match e.local {
                        SocketAddr::V6(v6) => v6.scope_id(),
                        SocketAddr::V4(_) => 0,
                    };
                    ctor::socket_info(
                        protocol,
                        e.local,
                        remote,
                        state,
                        None,
                        None,
                        None,
                        None,
                        Some(std::process::id()),
                        None,
                        interface,
                        None,
                    )
                }
                _ => {
                    let linux = os == OsSemantics::Linux;
                    let memory = memory.map(|m| {
                        if linux {
                            m
                        } else {
                            let mut mac = ::fast_talker::sockets::SocketMemory::default();
                            mac.rmem_alloc = clamp(recv_queue);
                            mac.rcvbuf = m.rcvbuf;
                            mac.wmem_queued = send_queue;
                            mac.sndbuf = m.sndbuf;
                            mac
                        }
                    });
                    ctor::socket_info(
                        protocol,
                        e.local,
                        e.peer.filter(|_| e.kind != SocketKind::TcpListener),
                        state,
                        Some(clamp(recv_queue)),
                        Some(send_queue),
                        memory,
                        Some(uid(net)),
                        None,
                        linux.then(|| e.id.get() as u32),
                        interface,
                        Some(e.id.get()),
                    )
                }
            };
            out.push(info);
        }
        out
    }))
}
