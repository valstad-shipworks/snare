//! fast-talker's `multicast` for snare sockets: memberships by interface
//! name, source-specific memberships, the sending interface, hops, loopback
//! and Linux's `IP_MULTICAST_ALL`, all on snare's own multicast state, so
//! std's `join_multicast_v4` and these see the same memberships.

use std::io;
use std::net::IpAddr;

use super::platform::{Item, require};
use super::sockopts::record;
use crate::mcast::{McastIf, McastOp};
use crate::netif::{SimSocket, SocketId, SocketKind};
use crate::os::{Errno, OsSemantics, os_err_for};

/// A snare socket multicast options can be set on:
/// [`crate::net::UdpSocket`], or [`crate::net::TcpStream`], which refuses
/// them with `EINVAL` as a kernel does.
pub trait Handle: SimSocket {}

impl Handle for crate::net::UdpSocket {}
impl Handle for crate::net::TcpStream {}
#[cfg(feature = "mio-compat")]
impl Handle for crate::mio_shim::net::UdpSocket {}
#[cfg(feature = "mio-compat")]
impl Handle for crate::mio_shim::net::TcpStream {}

/// Joins `group` on `interface`, receiving from any source.
pub fn join(socket: &impl Handle, group: IpAddr, interface: &str) -> io::Result<()> {
    group_op(socket, McastOp::Join, group, None, interface)
}

/// Leaves a group joined with [`join`].
pub fn leave(socket: &impl Handle, group: IpAddr, interface: &str) -> io::Result<()> {
    group_op(socket, McastOp::Leave, group, None, interface)
}

/// Joins `group` on `interface`, receiving only what `source` sends.
pub fn join_source(
    socket: &impl Handle,
    group: IpAddr,
    source: IpAddr,
    interface: &str,
) -> io::Result<()> {
    group_op(socket, McastOp::Join, group, Some(source), interface)
}

/// Leaves a membership made with [`join_source`].
pub fn leave_source(
    socket: &impl Handle,
    group: IpAddr,
    source: IpAddr,
    interface: &str,
) -> io::Result<()> {
    group_op(socket, McastOp::Leave, group, Some(source), interface)
}

/// Sends multicast out of `interface` instead of the one the routing table
/// picks.
pub fn set_send_interface(socket: &impl Handle, interface: &str) -> io::Result<()> {
    let id = socket.socket_id();
    run(id, format!("set_send_interface({interface:?})"), || {
        let index = index(interface)?;
        crate::mcast::set_send_interface(id, index)
    })
}

/// Hops a sent multicast datagram may take: the IPv4 TTL or IPv6 hop limit.
/// Recorded; snare delivers across its interfaces whatever the hop count.
pub fn set_hops(socket: &impl Handle, hops: u32) -> io::Result<()> {
    let id = socket.socket_id();
    run(id, format!("set_hops({hops})"), || {
        if !is_v4(socket) && i32::try_from(hops).is_err() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        crate::mcast::with_mcast(id, |net, c| {
            if hops > 255 {
                return Err(os_err_for(net.os, Errno::Inval));
            }
            if c.bound_addr.is_ipv4() {
                c.mcast.ttl_v4 = hops;
            } else {
                c.mcast.hops_v6 = hops;
            }
            Ok(())
        })
    })
}

/// Whether this host's own sockets receive what this socket sends to a
/// group. On by default.
pub fn set_loopback(socket: &impl Handle, on: bool) -> io::Result<()> {
    let id = socket.socket_id();
    run(id, format!("set_loopback({on})"), || {
        crate::mcast::with_mcast(id, |_, c| {
            if c.bound_addr.is_ipv4() {
                c.mcast.loop_v4 = on;
            } else {
                c.mcast.loop_v6 = on;
            }
            Ok(())
        })
    })
}

/// Deliver only groups this socket joined. Linux by default hands a socket
/// every group any socket on the host joined for its port; other systems
/// already behave this way, so there it does nothing.
pub fn only_joined(socket: &impl Handle, on: bool) -> io::Result<()> {
    let id = socket.socket_id();
    run(id, format!("only_joined({on})"), || {
        let stream = crate::netif::socket_entry(id).is_some_and(|e| e.kind != SocketKind::Udp);
        if stream || crate::os_semantics() != OsSemantics::Linux {
            return Ok(());
        }
        crate::mcast::with_mcast(id, |_, c| {
            c.mcast.only_joined = on;
            Ok(())
        })
    })
}

fn run(id: SocketId, what: String, f: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    require(Item::Multicast)?;
    let r = f();
    record(id, what, &r);
    r
}

fn is_v4(socket: &impl Handle) -> bool {
    crate::netif::socket_entry(socket.socket_id()).is_none_or(|e| e.local.is_ipv4())
}

fn index(interface: &str) -> io::Result<u32> {
    if interface.is_empty() {
        return Ok(0);
    }
    Ok(super::nic::Nic::open(interface)?.index())
}

fn check_group(group: IpAddr, source: Option<IpAddr>) -> io::Result<()> {
    if !group.is_multicast() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{group} is not a multicast address"),
        ));
    }
    if source.is_some_and(|s| s.is_ipv4() != group.is_ipv4()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source and group must be the same address family",
        ));
    }
    Ok(())
}

fn group_op(
    socket: &impl Handle,
    op: McastOp,
    group: IpAddr,
    source: Option<IpAddr>,
    interface: &str,
) -> io::Result<()> {
    let id = socket.socket_id();
    let verb = match (op, source) {
        (McastOp::Join, None) => "join",
        (McastOp::Leave, None) => "leave",
        (McastOp::Join, Some(_)) => "join_source",
        (McastOp::Leave, Some(_)) => "leave_source",
    };
    let what = match source {
        Some(s) => format!("{verb}({group}, {s}, {interface:?})"),
        None => format!("{verb}({group}, {interface:?})"),
    };
    run(id, what, || {
        let index = index(interface)?;
        check_group(group, source)?;
        crate::mcast::membership(id, op, group, source, McastIf::Index(index))
    })
}
