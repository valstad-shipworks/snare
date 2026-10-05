//! Multicast group membership and one-to-many delivery: datagrams to a group
//! or a broadcast address reach every socket the selected OS would hand them
//! to.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::netif::{NetModel, NicId, SockView, SocketId};
use crate::os::{Errno, OsSemantics, os_err_for};
use crate::state::{UdpConnection, with_net};

/// A multicast membership a socket holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub group: IpAddr,
    /// The one source a source-specific membership accepts.
    pub source: Option<IpAddr>,
    /// The interface joined on.
    pub nic: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Joined {
    pub group: IpAddr,
    pub source: Option<IpAddr>,
    pub nic: NicId,
}

impl Joined {
    fn accepts(&self, group: IpAddr, nic: Option<NicId>, src: IpAddr) -> bool {
        self.group == group && Some(self.nic) == nic && self.source.is_none_or(|s| s == src)
    }
}

/// A UDP socket's multicast settings, as the kernel keeps them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct McastState {
    pub joined: Vec<Joined>,
    pub loop_v4: bool,
    pub loop_v6: bool,
    pub ttl_v4: u32,
    pub hops_v6: u32,
    /// `IP_MULTICAST_ALL` off (Linux).
    pub only_joined: bool,
}

impl Default for McastState {
    fn default() -> Self {
        Self {
            joined: Vec::new(),
            loop_v4: true,
            loop_v6: true,
            ttl_v4: 1,
            hops_v6: 1,
            only_joined: false,
        }
    }
}

impl McastState {
    pub(crate) fn loops(&self, group: IpAddr) -> bool {
        if group.is_ipv4() {
            self.loop_v4
        } else {
            self.loop_v6
        }
    }
}

/// Where a membership is made.
#[derive(Debug, Clone, Copy)]
pub(crate) enum McastIf {
    /// By interface index; 0 lets routing pick.
    Index(u32),
    /// By one of the interface's addresses; the unspecified address lets
    /// routing pick.
    Addr(IpAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum McastOp {
    Join,
    Leave,
}

pub(crate) fn memberships(net: &NetModel, state: &McastState) -> Vec<Membership> {
    state
        .joined
        .iter()
        .map(|j| Membership {
            group: j.group,
            source: j.source,
            nic: net.nic_name(Some(j.nic)).unwrap_or_default(),
        })
        .collect()
}

fn unspecified(v4: bool) -> IpAddr {
    if v4 {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    }
}

/// The interface routing sends `group` out of.
fn route_nic(net: &NetModel, group: IpAddr) -> Result<NicId, Errno> {
    let view = SockView {
        local_ip: unspecified(group.is_ipv4()),
        bound_device: None,
        multicast_if: None,
        strong_host: false,
    };
    net.select_egress(&view, group).map(|(nic, _)| nic)
}

fn resolve_if(net: &NetModel, group: IpAddr, at: McastIf) -> io::Result<NicId> {
    let os = net.os;
    let unknown = || {
        os_err_for(
            os,
            if os == OsSemantics::Linux {
                Errno::NoDev
            } else {
                Errno::AddrNotAvail
            },
        )
    };
    match at {
        McastIf::Index(0) => route_nic(net, group).map_err(|e| os_err_for(os, e)),
        McastIf::Index(i) => net
            .nics
            .iter()
            .find(|n| n.id.index() == i)
            .map(|n| n.id)
            .ok_or_else(unknown),
        McastIf::Addr(ip) if ip.is_unspecified() => {
            route_nic(net, group).map_err(|e| os_err_for(os, e))
        }
        McastIf::Addr(ip) => net.owner_id(ip).ok_or_else(unknown),
    }
}

/// Run `f` on the multicast settings of the UDP socket `id`. A TCP socket
/// gets `EINVAL`, as the kernel refuses multicast options on a stream.
pub(crate) fn with_mcast<R>(
    id: SocketId,
    f: impl FnOnce(&NetModel, &mut UdpConnection) -> io::Result<R>,
) -> io::Result<R> {
    with_net(|ctx| {
        let net = &*ctx.net;
        if let Some(c) = ctx.udp.iter_mut().find(|c| c.id == id && !c.dropped) {
            return f(net, c);
        }
        let tcp = ctx.tcp.values().any(|c| c.id == id && !c.is_destroyed)
            || ctx.listeners.values().any(|l| l.id == id && !l.is_closed);
        if tcp {
            Err(os_err_for(net.os, Errno::Inval))
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no live snare socket with id {}", id.get()),
            ))
        }
    })
}

/// Join or leave `group` (from `source` only, when given) on the socket
/// `id`. Joining a membership held already gives `EADDRINUSE`, leaving one
/// never joined `EADDRNOTAVAIL`.
pub(crate) fn membership(
    id: SocketId,
    op: McastOp,
    group: IpAddr,
    source: Option<IpAddr>,
    at: McastIf,
) -> io::Result<()> {
    with_mcast(id, |net, c| {
        let os = net.os;
        if !group.is_multicast() || source.is_some_and(|s| s.is_ipv4() != group.is_ipv4()) {
            return Err(os_err_for(os, Errno::Inval));
        }
        let nic = resolve_if(net, group, at)?;
        let j = Joined { group, source, nic };
        let held = c.mcast.joined.iter().position(|m| *m == j);
        match (op, held) {
            (McastOp::Join, Some(_)) => Err(os_err_for(os, Errno::AddrInUse)),
            (McastOp::Join, None) => {
                c.mcast.joined.push(j);
                Ok(())
            }
            (McastOp::Leave, Some(i)) => {
                c.mcast.joined.remove(i);
                Ok(())
            }
            (McastOp::Leave, None) => Err(os_err_for(os, Errno::AddrNotAvail)),
        }
    })
}

#[cfg(feature = "fast-talker-core")]
/// Send the socket's multicast out of the interface with index `index`, or
/// let routing pick with 0.
pub(crate) fn set_send_interface(id: SocketId, index: u32) -> io::Result<()> {
    with_mcast(id, |net, c| {
        c.multicast_if = match index {
            0 => None,
            i => Some(
                net.nics
                    .iter()
                    .find(|n| n.id.index() == i)
                    .map(|n| n.id)
                    .ok_or_else(|| os_err_for(net.os, Errno::NoDev))?,
            ),
        };
        Ok(())
    })
}

fn same_family(bound: SocketAddr, dst: SocketAddr) -> bool {
    bound.is_ipv4() == dst.is_ipv4()
}

/// The sockets a datagram from `src` to the group or broadcast address `dst`
/// reaches over the interface `ingress`, or `None` when `dst` is neither or
/// the legacy rules deliver it like unicast. `sender` is the index of the
/// sending socket, which hears a group only through multicast loopback and
/// its own broadcast only under faithful semantics.
pub(crate) fn fan_out(
    net: &NetModel,
    udp: &[UdpConnection],
    sender: Option<usize>,
    src: SocketAddr,
    dst: SocketAddr,
    ingress: Option<NicId>,
) -> Option<Vec<usize>> {
    let targets = if dst.ip().is_multicast() {
        group_targets(net, udp, sender, src, dst, ingress)
    } else if net.is_broadcast(dst.ip()) {
        broadcast_targets(net, udp, sender, dst, ingress)
    } else {
        return None;
    };
    (!targets.is_empty() || net.faithful()).then_some(targets)
}

fn eligible(c: &UdpConnection, ingress: Option<NicId>) -> bool {
    !c.dropped && !c.is_destroyed && c.bound_device.is_none_or(|d| Some(d) == ingress)
}

fn group_targets(
    net: &NetModel,
    udp: &[UdpConnection],
    sender: Option<usize>,
    src: SocketAddr,
    dst: SocketAddr,
    ingress: Option<NicId>,
) -> Vec<usize> {
    let group = dst.ip();
    let joined = |c: &UdpConnection| {
        c.mcast
            .joined
            .iter()
            .any(|j| j.accepts(group, ingress, src.ip()))
    };
    let host_joined = udp.iter().any(|c| eligible(c, ingress) && joined(c));
    udp.iter()
        .enumerate()
        .filter(|(_, c)| eligible(c, ingress))
        .filter(|(_, c)| {
            c.bound_addr.port() == dst.port()
                && same_family(c.bound_addr, dst)
                && (c.bound_addr.ip().is_unspecified() || c.bound_addr.ip() == group)
        })
        .filter(|(_, c)| {
            joined(c) || (net.os == OsSemantics::Linux && !c.mcast.only_joined && host_joined)
        })
        .filter(|(i, c)| Some(*i) != sender || c.mcast.loops(group))
        .map(|(i, _)| i)
        .collect()
}

fn broadcast_targets(
    net: &NetModel,
    udp: &[UdpConnection],
    sender: Option<usize>,
    dst: SocketAddr,
    ingress: Option<NicId>,
) -> Vec<usize> {
    if ingress.and_then(|id| net.nic_by_id(id)).is_none() {
        return Vec::new();
    }
    udp.iter()
        .enumerate()
        .filter(|(_, c)| eligible(c, ingress))
        .filter(|(_, c)| {
            let ip = c.bound_addr.ip();
            c.bound_addr.port() == dst.port()
                && c.bound_addr.is_ipv4()
                && (ip.is_unspecified() || ip == dst.ip())
        })
        .filter(|(i, _)| Some(*i) != sender || net.faithful())
        .map(|(i, _)| i)
        .collect()
}

/// The interface a virtual tester at `from` reaches the group or broadcast
/// address `to` over: the interface owning `to` or `from`, else the one
/// routing reaches `from` through, else the default interface.
fn tester_ingress(net: &NetModel, from: SocketAddr, to: SocketAddr) -> Option<NicId> {
    net.owner_id(to.ip())
        .or_else(|| net.owner_id(from.ip()))
        .or_else(|| route_nic(net, from.ip()).ok())
        .or_else(|| net.default_nic().map(|n| n.id))
}

/// [`fan_out`] for a datagram a virtual tester at `from` sends to `to`,
/// with the interface it arrives on.
pub(crate) fn tester_fan_out(
    net: &NetModel,
    udp: &[UdpConnection],
    from: SocketAddr,
    to: SocketAddr,
) -> Option<(Vec<usize>, Option<NicId>)> {
    if !to.ip().is_multicast() && !net.is_broadcast(to.ip()) {
        return None;
    }
    let ingress = tester_ingress(net, from, to);
    fan_out(net, udp, None, from, to, ingress).map(|t| (t, ingress))
}
