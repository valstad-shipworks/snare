//! Receive flow steering over snare's data path. With `ntuple` on, rules
//! apply in slot order to datagrams and TCP bytes arriving on the
//! interface: a `Drop` rule drops matching UDP in hardware (counted in
//! `rx_dropped`), and a `Queue` rule picks the receive queue, and so the
//! NAPI and CPU, that [`Nic::napi_for_socket`] and `incoming_cpu` report.
//! Other flows hash to a queue.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::net::SocketAddr;

use super::{FlowAction, FlowMatch, FlowProtocol, FlowRule, Need, Nic, done, ensure, invalid};
use super::{not_supported, physical};
use crate::fast_talker_shim::platform::{Item, require};
use crate::netif::{NicId, NicRec, SocketId, with_nic_rec};
use crate::os::{OsSemantics, code_err};
use crate::state::with_net;

const ENOENT: i32 = 2;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;

fn matches(
    rule: &FlowRule,
    n: &NicRec,
    proto: FlowProtocol,
    src: SocketAddr,
    dst: SocketAddr,
) -> bool {
    match rule.matches {
        FlowMatch::Ip {
            protocol,
            ipv6,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        } => {
            protocol == proto
                && ipv6 == dst.is_ipv6()
                && src_ip.is_none_or(|ip| ip == src.ip())
                && dst_ip.is_none_or(|ip| ip == dst.ip())
                && src_port.is_none_or(|p| p == src.port())
                && dst_port.is_none_or(|p| p == dst.port())
        }
        FlowMatch::Ethernet {
            ethertype,
            src_mac,
            dst_mac,
            vlan_priority,
        } => {
            let ether = if dst.is_ipv6() { ETH_P_IPV6 } else { ETH_P_IP };
            ethertype.is_none_or(|e| e == ether)
                && src_mac.is_none()
                && dst_mac.is_none_or(|m| n.spec.mac == Some(m))
                && vlan_priority.is_none()
        }
    }
}

/// The action of the first rule, in slot order, that matches the flow.
fn action(n: &NicRec, proto: FlowProtocol, src: SocketAddr, dst: SocketAddr) -> Option<FlowAction> {
    if !n.ft.ntuple {
        return None;
    }
    let mut rules: Vec<&FlowRule> = n.ft.flow_rules.iter().collect();
    rules.sort_by_key(|r| r.location);
    rules
        .into_iter()
        .find(|r| matches(r, n, proto, src, dst))
        .map(|r| r.action)
}

/// Whether a flow rule on `n` drops a UDP datagram from `src` to `dst`.
pub(crate) fn udp_flow_dropped(n: &NicRec, src: SocketAddr, dst: SocketAddr) -> bool {
    action(n, FlowProtocol::Udp, src, dst) == Some(FlowAction::Drop)
}

fn flow_hash(proto: FlowProtocol, src: SocketAddr, dst: SocketAddr) -> u64 {
    let mut h = DefaultHasher::new();
    (proto, src, dst).hash(&mut h);
    h.finish()
}

fn rx_queues(n: &NicRec) -> u32 {
    if n.is_loopback() {
        return 1;
    }
    (n.ft.channels.combined + n.ft.channels.rx).max(1)
}

/// Where a socket's last packet came in.
pub(crate) struct Steer {
    pub nic: NicId,
    pub queue: u32,
    pub hash: u64,
    /// A TCP stream or a connected UDP socket.
    pub connected: bool,
}

/// The interface and receive queue the socket `id` last received through,
/// as Linux records it.
pub(crate) fn steer(id: SocketId) -> Option<Steer> {
    with_net(|ctx| {
        let (src, dst, nic, proto, connected) =
            if let Some(c) = ctx.udp.iter().find(|c| c.id == id && !c.dropped) {
                let (src, dst, nic) = c.ft.rx_flow?;
                (src, dst, nic, FlowProtocol::Udp, c.connected.is_some())
            } else {
                let c = ctx.tcp.values().find(|c| c.id == id && !c.is_destroyed)?;
                if c.ft.bytes_received == 0 {
                    return None;
                }
                (c.peer_addr, c.local_addr, c.nic?, FlowProtocol::Tcp, true)
            };
        let n = ctx.net.nic_by_id(nic)?;
        let hash = flow_hash(proto, src, dst);
        let queue = match action(n, proto, src, dst) {
            Some(FlowAction::Queue(q)) if q < rx_queues(n) => q,
            _ => (hash % u64::from(rx_queues(n))) as u32,
        };
        Some(Steer {
            nic,
            queue,
            hash,
            connected,
        })
    })
}

/// The CPU that processed the last packet the socket `id` received
/// (`SO_INCOMING_CPU`): an RPS CPU of its receive queue when RPS is set,
/// else the first CPU of the queue's interrupt affinity. Linux keeps it
/// only for TCP and connected UDP. On Windows, the queue's RSS processor.
pub(crate) fn incoming_cpu(id: SocketId) -> io::Result<Option<usize>> {
    require(Item::IncomingCpu)?;
    let os = crate::os_semantics();
    let Some(s) = steer(id) else {
        return Ok(None);
    };
    if os == OsSemantics::Linux && !s.connected {
        return Ok(None);
    }
    ensure(s.nic);
    let q = s.queue as usize;
    let Some((irq, rps, rss)) = with_nic_rec(s.nic, |n, _| {
        (
            n.ft.napis.get(q).and_then(|x| x.irq),
            n.ft.rps.get(&q).cloned().unwrap_or_default(),
            n.ft.rss,
        )
    }) else {
        return Ok(None);
    };
    let slot = crate::state::ft_slot();
    let g = slot.inner.lock();
    let count = g.cpus.count.max(1);
    if os == OsSemantics::Windows {
        if !rss.enabled {
            return Ok(Some(0));
        }
        let base = rss.base_cpu.unwrap_or(0) as usize;
        let spread = rss.max_processors.map_or(count, |m| m.max(1) as usize);
        return Ok(Some((base + q % spread).min(count - 1)));
    }
    if !rps.is_empty() {
        return Ok(Some(rps[(s.hash % rps.len() as u64) as usize]));
    }
    let cpu = irq
        .and_then(|n| g.irqs.get(&n))
        .and_then(|rec| rec.affinity.first().copied())
        .unwrap_or(0);
    Ok(Some(cpu))
}

fn no_rule(os: OsSemantics) -> io::Error {
    code_err(os, ENOENT, "ENOENT", io::ErrorKind::NotFound)
}

fn check_rule(rule: &FlowRule, n: &NicRec, os: OsSemantics) -> io::Result<()> {
    if let FlowMatch::Ip {
        ipv6,
        src_ip,
        dst_ip,
        ..
    } = rule.matches
        && [src_ip, dst_ip]
            .into_iter()
            .flatten()
            .any(|ip| ip.is_ipv6() != ipv6)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rule address does not match its IP version",
        ));
    }
    if let FlowAction::Queue(q) = rule.action
        && q >= rx_queues(n)
    {
        return Err(invalid(os));
    }
    Ok(())
}

impl Nic {
    /// Whether flow steering rules are enabled.
    pub fn ntuple(&self) -> io::Result<bool> {
        self.get(Item::LinuxNicTuning, |n, os| {
            physical(n, os)?;
            Ok(n.ft.ntuple)
        })
    }

    /// Turns flow steering rules on or off. `EOPNOTSUPP` without
    /// [`NicCaps::ntuple`](crate::NicCaps). Turning them off removes every
    /// rule.
    pub fn set_ntuple(&self, on: bool) -> io::Result<()> {
        self.set(
            Item::LinuxNicTuning,
            Need::NetAdmin,
            format!("set_ntuple({on})"),
            |n, os| {
                physical(n, os)?;
                if on && !n.spec.caps.ntuple {
                    return Err(not_supported(os));
                }
                n.ft.ntuple = on;
                if !on {
                    n.ft.flow_rules.clear();
                }
                done(())
            },
        )
    }

    /// Every flow steering rule installed, in slot order. `EOPNOTSUPP` on
    /// NICs without flow steering.
    pub fn flow_rules(&self) -> io::Result<Vec<FlowRule>> {
        self.get(Item::LinuxNicTuning, |n, os| {
            physical(n, os)?;
            if !n.spec.caps.ntuple {
                return Err(not_supported(os));
            }
            let mut rules = n.ft.flow_rules.clone();
            rules.sort_by_key(|r| r.location);
            Ok(rules)
        })
    }

    /// Installs `rule` and returns its slot: the one it names, replacing
    /// any rule there, or the first free one. Flow steering must be on
    /// (`EOPNOTSUPP` otherwise); a slot beyond the table or a queue the
    /// interface lacks is `EINVAL`, and a full table fails as fast-talker
    /// reports it.
    pub fn add_flow_rule(&self, rule: &FlowRule) -> io::Result<u32> {
        let rule = *rule;
        self.set(
            Item::LinuxNicTuning,
            Need::NetAdmin,
            format!("add_flow_rule({rule:?})"),
            |n, os| {
                physical(n, os)?;
                if !n.spec.caps.ntuple || !n.ft.ntuple {
                    return Err(not_supported(os));
                }
                check_rule(&rule, n, os)?;
                let slots = n.spec.caps.flow_rule_slots;
                let location = match rule.location {
                    Some(l) if l >= slots => return Err(invalid(os)),
                    Some(l) => l,
                    None => (0..slots)
                        .find(|l| !n.ft.flow_rules.iter().any(|r| r.location == Some(*l)))
                        .ok_or_else(|| io::Error::other("the NIC's flow rule table is full"))?,
                };
                n.ft.flow_rules.retain(|r| r.location != Some(location));
                n.ft.flow_rules.push(FlowRule {
                    location: Some(location),
                    ..rule
                });
                done(location)
            },
        )
    }

    /// Removes the rule in slot `location`. `ENOENT` when the slot is
    /// empty.
    pub fn remove_flow_rule(&self, location: u32) -> io::Result<()> {
        self.set(
            Item::LinuxNicTuning,
            Need::NetAdmin,
            format!("remove_flow_rule({location})"),
            |n, os| {
                physical(n, os)?;
                if !n.spec.caps.ntuple {
                    return Err(not_supported(os));
                }
                let before = n.ft.flow_rules.len();
                n.ft.flow_rules.retain(|r| r.location != Some(location));
                if n.ft.flow_rules.len() == before {
                    return Err(no_rule(os));
                }
                done(())
            },
        )
    }
}
