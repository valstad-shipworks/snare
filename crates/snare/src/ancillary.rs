//! IP- and UDP-level ancillary data of the sim's sockets: the control messages `sendmsg` takes
//! (TOS/traffic class, TTL/hop limit, source selection through `IP_PKTINFO`/`IPV6_PKTINFO`, Linux
//! `UDP_SEGMENT`, the `SOL_SOCKET` ones), the header fields a datagram carries to its receiver,
//! and the receive options that ask `recvmsg` to report them (`IP_RECVTOS`, `IP_RECVTTL`,
//! `IP_PKTINFO`/`IP_RECVPKTINFO`, macOS `IP_RECVDSTADDR`, `IPV6_RECVTCLASS`, `IPV6_RECVPKTINFO`,
//! `IPV6_RECVHOPLIMIT`, Linux `UDP_GRO`).
//!
//! Each kernel's rules are followed as tests/cmsg_os_truth.rs measured them on loopback (Linux
//! 7.0, macOS 26):
//!
//! - Linux walks the control buffer with `CMSG_OK` (net/core/scm.c): a header shorter than a
//!   `cmsghdr` or running past `msg_controllen` is `EINVAL`, and a buffer too short for one header
//!   carries none. `udp_cmsg_send` (net/ipv4/udp.c) takes the `SOL_UDP` messages first; then an
//!   IPv4 send (an IPv6 socket's to a v4-mapped address included) goes through `ip_cmsg_send`
//!   (net/ipv4/ip_sockglue.c), which skips other levels but refuses an unknown `SOL_IP` type, and
//!   an IPv6 send through `ip6_datagram_send_ctl` (net/ipv6/datagram.c), which skips other levels
//!   and refuses an unknown `SOL_IPV6` type. `SOL_SOCKET` messages go to `__sock_cmsg_send`
//!   (net/core/sock.c), which refuses an unknown type.
//! - macOS refuses a control buffer shorter than a `cmsghdr` (`sendit`, bsd/kern/uipc_syscalls.c)
//!   and stops at the first header that is too short or overruns the buffer. An IPv4 send
//!   (`udp_output`, bsd/netinet/udp_usrreq.c) takes the first `IP_TOS` or `IPV6_TCLASS` of exactly
//!   an `int` (`ip_tos_from_control`) and the first `IP_PKTINFO` (`udp_check_pktinfo`), and ignores
//!   everything else; an IPv6 send applies `ip6_setpktopts` (bsd/netinet6/ip6_output.c) to the
//!   `IPPROTO_IPV6` messages and refuses an unknown type with `ENOPROTOOPT`.
//!
//! The sim never routes by TOS and counts no hops: the fields only travel with the datagram, for
//! the receiver's control messages.
//!
//! On Windows only [`Header`] is shared: Winsock's control messages and receive options, which
//! fill and report it, are `win_sockopt`'s.

#[cfg(unix)]
use std::ffi::c_int;
use std::net::IpAddr;
#[cfg(unix)]
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[cfg(unix)]
use crate::scope::SimShared;
#[cfg(unix)]
use crate::sockets::SockRec;
#[cfg(unix)]
use crate::tstamp::Cmsg;

#[cfg(target_os = "linux")]
mod os {
    use std::ffi::c_int;

    pub(super) const IP_RETOPTS: c_int = 7;
    pub(super) const IP_PROTOCOL: c_int = 52;
    pub(super) const IPV6_2292PKTINFO: c_int = 2;
    pub(super) const IPV6_2292HOPOPTS: c_int = 3;
    pub(super) const IPV6_2292DSTOPTS: c_int = 4;
    pub(super) const IPV6_2292RTHDR: c_int = 5;
    pub(super) const IPV6_2292HOPLIMIT: c_int = 8;
    pub(super) const IPV6_NEXTHOP: c_int = 9;
    pub(super) const IPV6_FLOWINFO: c_int = 11;
    pub(super) const IPV6_HOPOPTS: c_int = 54;
    pub(super) const IPV6_RTHDRDSTOPTS: c_int = 55;
    pub(super) const IPV6_RTHDR: c_int = 57;
    pub(super) const IPV6_DSTOPTS: c_int = 59;
    pub(super) const IPV6_DONTFRAG: c_int = 62;
    pub(super) const SO_PRIORITY: c_int = 12;
    pub(super) const SO_MARK: c_int = 36;
    pub(super) const SO_TIMESTAMPING_OLD: c_int = 37;
    pub(super) const SO_TIMESTAMPING_NEW: c_int = 65;
    pub(super) const SCM_TXTIME: c_int = 61;
    pub(super) const SCM_TS_OPT_ID: c_int = 81;
    /// `TC_PRIO_INTERACTIVE` (include/uapi/linux/pkt_sched.h): the highest `SO_PRIORITY` an
    /// unprivileged socket may ask for (net/core/sock.c `sk_set_prio_allowed`).
    pub(super) const TC_PRIO_INTERACTIVE: c_int = 6;
}

#[cfg(target_os = "macos")]
mod os {
    use std::ffi::c_int;

    pub(super) const IPV6_2292PKTINFO: c_int = 19;
    pub(super) const IPV6_2292HOPLIMIT: c_int = 20;
    pub(super) const IPV6_2292NEXTHOP: c_int = 21;
    pub(super) const IPV6_2292HOPOPTS: c_int = 22;
    pub(super) const IPV6_2292DSTOPTS: c_int = 23;
    pub(super) const IPV6_2292RTHDR: c_int = 24;
    pub(super) const IPV6_USE_MIN_MTU: c_int = 42;
    pub(super) const IPV6_NEXTHOP: c_int = 48;
    pub(super) const IPV6_HOPOPTS: c_int = 49;
    pub(super) const IPV6_DSTOPTS: c_int = 50;
    pub(super) const IPV6_RTHDR: c_int = 51;
    pub(super) const IPV6_RTHDRDSTOPTS: c_int = 57;
    pub(super) const IPV6_DONTFRAG: c_int = 62;
    pub(super) const IPV6_PREFER_TEMPADDR: c_int = 63;
}

/// The default TTL and hop limit: 64 on Linux (`sysctl_ip_default_ttl`, IPv6 `hop_limit`) and
/// macOS (`ip_defttl`, `ip6_defhlim`), 128 on Windows (measured, as `IP_TTL` and
/// `IPV6_UNICAST_HOPS` read and a receiver's `IP_TTL` message reports); 1 toward a multicast group
/// (man 7 ip `IP_MULTICAST_TTL`, man 7 ipv6 `IPV6_MULTICAST_HOPS`; RFC 3493 §5.2; `ws2ipdef.h`
/// `IP_DEFAULT_MULTICAST_TTL`).
fn default_ttl(multicast: bool) -> u8 {
    if multicast {
        1
    } else if cfg!(windows) {
        128
    } else {
        64
    }
}

/// A socket's receive options and, on Linux, its UDP offload settings.
#[derive(Clone, Copy, Default)]
#[cfg(unix)]
pub(crate) struct Opts {
    /// `IP_RECVTOS`.
    tos: bool,
    /// `IP_RECVTTL`.
    ttl: bool,
    /// Linux `IP_PKTINFO`, macOS `IP_RECVPKTINFO`.
    pktinfo: bool,
    /// macOS `IP_RECVDSTADDR`.
    #[cfg(target_os = "macos")]
    dstaddr: bool,
    /// `IPV6_RECVTCLASS`.
    tclass: bool,
    /// `IPV6_RECVPKTINFO`.
    pktinfo6: bool,
    /// `IPV6_RECVHOPLIMIT`.
    hoplimit: bool,
    /// Linux `UDP_GRO`: a segmented send that reaches this socket over loopback is read whole,
    /// with a `UDP_GRO` message giving its segment size (net/ipv4/udp.c `udp_cmsg_recv`).
    #[cfg(target_os = "linux")]
    gro: bool,
    /// Linux `UDP_SEGMENT`: the segment size of every send that does not give its own.
    #[cfg(target_os = "linux")]
    gso: u16,
}

/// What a datagram carries in its IP header that a receiver's control messages report, and the
/// interface it arrived on.
#[derive(Clone, Copy)]
pub(crate) struct Header {
    /// The IPv4 TOS byte or IPv6 traffic class, ECN bits included.
    pub(crate) tos: u8,
    /// The TTL or hop limit as sent; the sim's links count no hops.
    pub(crate) ttl: u8,
    /// The destination address.
    pub(crate) dst: IpAddr,
    /// The receiving interface's index; 0 until delivered.
    pub(crate) ifindex: u32,
    /// Linux GRO, Windows URO: the segment size of a datagram delivered whole, or coalesced,
    /// from a segmented send.
    pub(crate) gso: u16,
}

impl Header {
    /// A datagram to `dst` with every field at the host's default.
    pub(crate) fn plain(dst: IpAddr) -> Self {
        Header {
            tos: 0,
            ttl: default_ttl(dst.is_multicast()),
            dst,
            ifindex: 0,
            gso: 0,
        }
    }
}

/// What one `sendmsg`'s control messages ask of its datagram.
#[derive(Clone, Copy, Default)]
#[cfg(unix)]
pub(crate) struct SendCtl {
    pub(crate) tos: Option<u8>,
    pub(crate) ttl: Option<u8>,
    /// The source address `IP_PKTINFO`/`IPV6_PKTINFO` chose.
    pub(crate) src: Option<IpAddr>,
    /// The interface `IP_PKTINFO`/`IPV6_PKTINFO` chose.
    pub(crate) oif: Option<u32>,
    /// `IPV6_DONTFRAG`.
    pub(crate) dontfrag: Option<bool>,
    /// Linux `UDP_SEGMENT`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) gso: Option<u16>,
    /// Linux `SO_TIMESTAMPING`: the transmit stamps asked for this send.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) tx_flags: Option<u32>,
    /// Linux `SCM_TXTIME`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) txtime: Option<u64>,
}

/// One control message of a send: its level, type, `cmsg_len` and data.
#[cfg(unix)]
struct Msg<'a> {
    level: c_int,
    ty: c_int,
    len: usize,
    data: &'a [u8],
}

#[cfg(unix)]
impl Msg<'_> {
    /// `cmsg_len` is exactly `CMSG_LEN(n)`.
    fn sized(&self, n: usize) -> bool {
        self.len == cmsg_len(n)
    }

    fn int(&self) -> c_int {
        self.read::<4>().map_or(0, c_int::from_ne_bytes)
    }

    fn read<const N: usize>(&self) -> Option<[u8; N]> {
        self.data.get(..N).map(|b| b.try_into().unwrap())
    }
}

#[cfg(unix)]
fn cmsg_len(n: usize) -> usize {
    // SAFETY: CMSG_LEN is arithmetic.
    unsafe { libc::CMSG_LEN(n as u32) as usize }
}

/// The control buffer of a `sendmsg`'s `hdr`, copied; `None` when it has none. Linux takes no
/// control buffer when `msg_controllen` is 0 and faults a null one (`EFAULT`, `____sys_sendmsg`
/// copying it in); macOS takes none when `msg_control` is null and refuses one shorter than a
/// `cmsghdr` with `EINVAL` (`sendit`, measured).
///
/// # Safety
/// `hdr` is a valid `msghdr` whose control buffer, when non-null, holds `msg_controllen` bytes.
#[allow(clippy::unnecessary_cast)]
#[cfg(unix)]
pub(crate) unsafe fn control(hdr: *const libc::msghdr) -> Result<Option<Vec<u8>>, c_int> {
    let (ptr, len) = unsafe { ((*hdr).msg_control, (*hdr).msg_controllen as usize) };
    if cfg!(target_os = "linux") && len == 0 {
        return Ok(None);
    }
    if ptr.is_null() {
        return if cfg!(target_os = "linux") {
            Err(libc::EFAULT)
        } else {
            Ok(None)
        };
    }
    if cfg!(target_os = "macos") && len < size_of::<libc::cmsghdr>() {
        return Err(libc::EINVAL);
    }
    Ok(Some(
        unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) }.to_vec(),
    ))
}

#[cfg(unix)]
fn header_at(buf: &[u8], off: usize) -> Option<(usize, c_int, c_int)> {
    let size = size_of::<libc::cmsghdr>();
    let raw = buf.get(off..off + size)?;
    // SAFETY: `raw` holds a whole cmsghdr; read unaligned.
    let hdr = unsafe { raw.as_ptr().cast::<libc::cmsghdr>().read_unaligned() };
    #[allow(clippy::unnecessary_cast)]
    Some((hdr.cmsg_len as usize, hdr.cmsg_level, hdr.cmsg_type))
}

/// The control messages in `buf` as Linux walks them: `Err(EINVAL)` at the first that fails
/// `CMSG_OK`.
#[cfg(target_os = "linux")]
fn walk(buf: &[u8]) -> Result<Vec<Msg<'_>>, c_int> {
    let size = size_of::<libc::cmsghdr>();
    let mut out = Vec::new();
    let mut off = 0;
    while off + size <= buf.len() {
        let (len, level, ty) = header_at(buf, off).unwrap();
        if len < size || len > buf.len() - off {
            return Err(libc::EINVAL);
        }
        out.push(Msg {
            level,
            ty,
            len,
            data: &buf[off + cmsg_len(0)..off + len],
        });
        off += len.next_multiple_of(size_of::<usize>());
    }
    Ok(out)
}

/// The control messages in `buf` as XNU walks them (`M_FIRST_CMSGHDR`, `M_NXT_CMSGHDR`,
/// `is_cmsg_valid`): up to the first header too short or overrunning the buffer.
#[cfg(target_os = "macos")]
fn walk(buf: &[u8]) -> Result<Vec<Msg<'_>>, c_int> {
    let size = size_of::<libc::cmsghdr>();
    let mut out = Vec::new();
    let mut off = 0;
    while off + size <= buf.len() {
        let (len, level, ty) = header_at(buf, off).unwrap();
        if len < size || len > buf.len() - off {
            break;
        }
        out.push(Msg {
            level,
            ty,
            len,
            data: &buf[off + cmsg_len(0)..off + len],
        });
        off += len.next_multiple_of(4);
    }
    Ok(out)
}

/// Whether `dest` is reached over IPv4: an IPv4 address, or a v4-mapped one.
#[cfg(unix)]
fn v4_dest(dest: SocketAddr) -> bool {
    match dest.ip() {
        IpAddr::V4(_) => true,
        IpAddr::V6(ip) => ip.to_ipv4_mapped().is_some(),
    }
}

#[cfg(unix)]
fn interface_exists(shared: &SimShared, index: u32) -> bool {
    shared.topo().name_of(index).is_some()
}

/// The control messages `buf` of a `sendmsg` on datagram socket `rec` (IPv6 if `v6`) to `dest`,
/// checked as the host checks them (see the module).
#[cfg_attr(target_os = "macos", allow(unused_variables))]
#[cfg(unix)]
pub(crate) fn datagram_send(
    shared: &SimShared,
    rec: &SockRec,
    buf: &[u8],
    v6: bool,
    dest: SocketAddr,
) -> Result<SendCtl, c_int> {
    let msgs = walk(buf)?;
    let mut ctl = SendCtl::default();
    #[cfg(target_os = "linux")]
    {
        let mut need_ip = false;
        for msg in &msgs {
            if msg.level != libc::SOL_UDP {
                need_ip = true;
                continue;
            }
            if msg.ty != libc::UDP_SEGMENT || !msg.sized(2) {
                return Err(libc::EINVAL);
            }
            ctl.gso = msg.read::<2>().map(u16::from_ne_bytes);
        }
        if !need_ip {
            return Ok(ctl);
        }
        if v4_dest(dest) {
            linux_ip(shared, rec, &msgs, v6, &mut ctl)?;
        } else {
            linux_ipv6(shared, rec, &msgs, &mut ctl)?;
        }
    }
    #[cfg(target_os = "macos")]
    if v4_dest(dest) {
        mac_ip(shared, &msgs, &mut ctl)?;
    } else {
        mac_ipv6(shared, &msgs, &mut ctl)?;
    }
    Ok(ctl)
}

/// The control messages `buf` of a `sendmsg` on a connected stream: Linux `tcp_sendmsg_locked`
/// passes them to `sock_cmsg_send`, which refuses a malformed header or an unacceptable
/// `SOL_SOCKET` message (every error `EINVAL`) and ignores other levels; a `SO_TIMESTAMPING`
/// one, which would ask stamps of this write alone, is not modelled (`EOPNOTSUPP`). macOS refuses
/// a first header shorter than a `cmsghdr` and otherwise drops them (measured).
#[cfg_attr(target_os = "macos", allow(unused_variables))]
#[cfg(unix)]
pub(crate) fn stream_send(shared: &SimShared, rec: &SockRec, buf: &[u8]) -> Result<(), c_int> {
    #[cfg(target_os = "linux")]
    {
        let mut ctl = SendCtl::default();
        for msg in walk(buf)? {
            if msg.level == libc::SOL_SOCKET {
                sock_cmsg(shared, rec, &msg, &mut ctl).map_err(|_| libc::EINVAL)?;
            }
        }
        if ctl.tx_flags.is_some() {
            return Err(libc::EOPNOTSUPP);
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    match header_at(buf, 0) {
        Some((len, _, _)) if len < size_of::<libc::cmsghdr>() => Err(libc::EINVAL),
        _ => Ok(()),
    }
}

/// `__sock_cmsg_send` (net/core/sock.c, Linux 7.0): `SO_MARK` (needing `CAP_NET_RAW` or
/// `CAP_NET_ADMIN`), `SO_TIMESTAMPING` (transmit-recording flags only), `SCM_TXTIME` (only with
/// `SO_TXTIME` on), `SO_PRIORITY` (above 6 only with either capability), `SCM_RIGHTS` and
/// `SCM_CREDENTIALS` ignored, anything else `EINVAL`. `SCM_TS_OPT_ID` is not modelled
/// (`EOPNOTSUPP`).
#[cfg(target_os = "linux")]
fn sock_cmsg(
    shared: &SimShared,
    rec: &SockRec,
    msg: &Msg<'_>,
    ctl: &mut SendCtl,
) -> Result<(), c_int> {
    use crate::limits::{CAP_NET_ADMIN, CAP_NET_RAW};
    let privileged = || shared.sys.has_cap(CAP_NET_RAW) || shared.sys.has_cap(CAP_NET_ADMIN);
    match msg.ty {
        os::SO_MARK => {
            if !privileged() {
                return Err(libc::EPERM);
            }
            if !msg.sized(4) {
                return Err(libc::EINVAL);
            }
        }
        os::SO_TIMESTAMPING_OLD | os::SO_TIMESTAMPING_NEW => {
            if !msg.sized(4) {
                return Err(libc::EINVAL);
            }
            let flags = msg.int() as u32;
            if flags & !crate::tstamp::TX_RECORD_MASK != 0 {
                return Err(libc::EINVAL);
            }
            ctl.tx_flags = Some(flags);
        }
        os::SCM_TXTIME => {
            if rec.state().ts.txtime.is_none() || !msg.sized(8) {
                return Err(libc::EINVAL);
            }
            ctl.txtime = msg.read::<8>().map(u64::from_ne_bytes);
        }
        os::SO_PRIORITY => {
            if !msg.sized(4) {
                return Err(libc::EINVAL);
            }
            if !(0..=os::TC_PRIO_INTERACTIVE).contains(&msg.int()) && !privileged() {
                return Err(libc::EPERM);
            }
        }
        os::SCM_TS_OPT_ID => return Err(libc::EOPNOTSUPP),
        libc::SCM_RIGHTS | libc::SCM_CREDENTIALS => {}
        _ => return Err(libc::EINVAL),
    }
    Ok(())
}

/// `ip_cmsg_send` (net/ipv4/ip_sockglue.c) for an IPv4 send; `allow_ipv6` on an IPv6 socket, whose
/// `IPV6_PKTINFO` then selects a v4-mapped source. `IP_PKTINFO` with a source that is not the
/// host's fails as `ip_route_output_key_hash_rcu` refuses it, `ENETUNREACH` (measured); one
/// naming an interface that does not exist fails `ENODEV` (measured). `IP_RETOPTS` is not
/// modelled (`EOPNOTSUPP`).
#[cfg(target_os = "linux")]
fn linux_ip(
    shared: &SimShared,
    rec: &SockRec,
    msgs: &[Msg<'_>],
    allow_ipv6: bool,
    ctl: &mut SendCtl,
) -> Result<(), c_int> {
    let mut oif = None;
    for msg in msgs {
        if allow_ipv6
            && msg.level == libc::IPPROTO_IPV6
            && matches!(msg.ty, libc::IPV6_PKTINFO | os::IPV6_2292PKTINFO)
        {
            if msg.len < cmsg_len(20) {
                return Err(libc::EINVAL);
            }
            let addr = Ipv6Addr::from(msg.read::<16>().unwrap());
            let Some(v4) = addr.to_ipv4_mapped() else {
                return Err(libc::EINVAL);
            };
            let index = u32::from_ne_bytes(msg.data[16..20].try_into().unwrap());
            if index != 0 {
                oif = Some(index);
            }
            ctl.src = (!v4.is_unspecified()).then_some(IpAddr::V4(v4));
            continue;
        }
        if msg.level == libc::SOL_SOCKET {
            sock_cmsg(shared, rec, msg, ctl)?;
            continue;
        }
        if msg.level != libc::IPPROTO_IP {
            continue;
        }
        match msg.ty {
            libc::IP_PKTINFO => {
                if !msg.sized(12) {
                    return Err(libc::EINVAL);
                }
                let index = c_int::from_ne_bytes(msg.read::<4>().unwrap());
                if index != 0 {
                    oif = Some(index as u32);
                }
                let spec = Ipv4Addr::from(<[u8; 4]>::try_from(&msg.data[4..8]).unwrap());
                ctl.src = (!spec.is_unspecified()).then_some(IpAddr::V4(spec));
            }
            libc::IP_TTL => {
                if !msg.sized(4) {
                    return Err(libc::EINVAL);
                }
                match msg.int() {
                    ttl @ 1..=255 => ctl.ttl = Some(ttl as u8),
                    _ => return Err(libc::EINVAL),
                }
            }
            libc::IP_TOS => {
                let tos = if msg.sized(4) {
                    msg.int()
                } else if msg.sized(1) {
                    c_int::from(msg.data[0])
                } else {
                    return Err(libc::EINVAL);
                };
                match tos {
                    0..=255 => ctl.tos = Some(tos as u8),
                    _ => return Err(libc::EINVAL),
                }
            }
            os::IP_PROTOCOL => {
                if !msg.sized(4) || !(1..=255).contains(&msg.int()) {
                    return Err(libc::EINVAL);
                }
            }
            os::IP_RETOPTS => return Err(libc::EOPNOTSUPP),
            _ => return Err(libc::EINVAL),
        }
    }
    if let Some(index) = oif {
        if !interface_exists(shared, index) {
            return Err(libc::ENODEV);
        }
        ctl.oif = Some(index);
    }
    if let Some(src) = ctl.src {
        let IpAddr::V4(v4) = src else { unreachable!() };
        if v4.is_multicast() || v4.is_broadcast() || v4.octets()[0] == 0 {
            return Err(libc::EINVAL);
        }
        if !shared.topo().is_host(src) {
            return Err(libc::ENETUNREACH);
        }
    }
    Ok(())
}

/// `ip6_datagram_send_ctl` (net/ipv6/datagram.c) for an IPv6 send: `IPV6_PKTINFO` (an interface
/// that does not exist `ENODEV`, one other than the socket's bound device `EINVAL`, a source that
/// is not the host's `EINVAL`), `IPV6_HOPLIMIT` and `IPV6_TCLASS` (exactly an `int`, -1 to 255;
/// -1 is the default hop limit, while a traffic class of -1 goes out as 0xff, measured),
/// `IPV6_DONTFRAG`. Flow labels and extension headers are not modelled (`EOPNOTSUPP`).
#[cfg(target_os = "linux")]
fn linux_ipv6(
    shared: &SimShared,
    rec: &SockRec,
    msgs: &[Msg<'_>],
    ctl: &mut SendCtl,
) -> Result<(), c_int> {
    for msg in msgs {
        if msg.level == libc::SOL_SOCKET {
            sock_cmsg(shared, rec, msg, ctl)?;
            continue;
        }
        if msg.level != libc::IPPROTO_IPV6 {
            continue;
        }
        match msg.ty {
            libc::IPV6_PKTINFO | os::IPV6_2292PKTINFO => {
                if msg.len < cmsg_len(20) {
                    return Err(libc::EINVAL);
                }
                let addr = Ipv6Addr::from(msg.read::<16>().unwrap());
                let index = u32::from_ne_bytes(msg.data[16..20].try_into().unwrap());
                if index != 0 {
                    let bound = rec.state().device.as_ref().map(|(i, _)| *i);
                    if bound.is_some_and(|bound| bound != index) {
                        return Err(libc::EINVAL);
                    }
                    if !interface_exists(shared, index) {
                        return Err(libc::ENODEV);
                    }
                    ctl.oif = Some(index);
                }
                if !addr.is_unspecified() {
                    if !shared.topo().is_host(IpAddr::V6(addr)) {
                        return Err(libc::EINVAL);
                    }
                    ctl.src = Some(IpAddr::V6(addr));
                }
            }
            libc::IPV6_HOPLIMIT | os::IPV6_2292HOPLIMIT => {
                if !msg.sized(4) {
                    return Err(libc::EINVAL);
                }
                match msg.int() {
                    -1 => ctl.ttl = None,
                    hops @ 0..=255 => ctl.ttl = Some(hops as u8),
                    _ => return Err(libc::EINVAL),
                }
            }
            libc::IPV6_TCLASS => {
                if !msg.sized(4) {
                    return Err(libc::EINVAL);
                }
                match msg.int() {
                    tclass @ -1..=255 => ctl.tos = Some(tclass as u8),
                    _ => return Err(libc::EINVAL),
                }
            }
            os::IPV6_DONTFRAG => {
                if !msg.sized(4) {
                    return Err(libc::EINVAL);
                }
                ctl.dontfrag = Some(msg.int() != 0);
            }
            os::IPV6_FLOWINFO
            | os::IPV6_HOPOPTS
            | os::IPV6_2292HOPOPTS
            | os::IPV6_DSTOPTS
            | os::IPV6_2292DSTOPTS
            | os::IPV6_RTHDRDSTOPTS
            | os::IPV6_RTHDR
            | os::IPV6_2292RTHDR
            | os::IPV6_NEXTHOP => return Err(libc::EOPNOTSUPP),
            _ => return Err(libc::EINVAL),
        }
    }
    Ok(())
}

/// XNU `udp_output` for an IPv4 send: the TOS from the first `IP_TOS` or `IPV6_TCLASS` of exactly
/// an `int`, its low byte (`ip_tos_from_control`), and the first `IP_PKTINFO`
/// (`udp_check_pktinfo`: not exactly an `in_pktinfo` `EINVAL`, an interface that does not exist
/// `ENXIO`; an interface wins over the address, which is not checked: a datagram can leave from
/// any source, measured). TTLs and every other message are ignored.
#[cfg(target_os = "macos")]
fn mac_ip(shared: &SimShared, msgs: &[Msg<'_>], ctl: &mut SendCtl) -> Result<(), c_int> {
    ctl.tos = msgs
        .iter()
        .find(|m| {
            m.sized(4)
                && ((m.level, m.ty) == (libc::IPPROTO_IP, libc::IP_TOS)
                    || (m.level, m.ty) == (libc::IPPROTO_IPV6, libc::IPV6_TCLASS))
        })
        .map(|m| m.int() as u8);
    if let Some(msg) = msgs
        .iter()
        .find(|m| (m.level, m.ty) == (libc::IPPROTO_IP, libc::IP_PKTINFO))
    {
        if !msg.sized(12) {
            return Err(libc::EINVAL);
        }
        let index = u32::from_ne_bytes(msg.read::<4>().unwrap());
        if index != 0 {
            if !interface_exists(shared, index) {
                return Err(libc::ENXIO);
            }
            ctl.oif = Some(index);
        } else {
            let spec = Ipv4Addr::from(<[u8; 4]>::try_from(&msg.data[4..8]).unwrap());
            ctl.src = (!spec.is_unspecified()).then_some(IpAddr::V4(spec));
        }
    }
    Ok(())
}

/// XNU `ip6_setpktopts` for an IPv6 send, each `IPPROTO_IPV6` message through `ip6_setpktopt`:
/// `IPV6_PKTINFO` (not exactly an `in6_pktinfo` `EINVAL`, an interface that does not exist
/// `ENXIO`, a source that is not the host's `EADDRNOTAVAIL`), `IPV6_HOPLIMIT` and `IPV6_TCLASS`
/// (exactly an `int`, -1 to 255, -1 the default), `IPV6_DONTFRAG`, `IPV6_USE_MIN_MTU` and
/// `IPV6_PREFER_TEMPADDR` (-1 to 1); an unknown type `ENOPROTOOPT`. Next hops and extension
/// headers are not modelled (`EOPNOTSUPP`).
#[cfg(target_os = "macos")]
fn mac_ipv6(shared: &SimShared, msgs: &[Msg<'_>], ctl: &mut SendCtl) -> Result<(), c_int> {
    for msg in msgs.iter().filter(|m| m.level == libc::IPPROTO_IPV6) {
        match msg.ty {
            libc::IPV6_PKTINFO | os::IPV6_2292PKTINFO => {
                if !msg.sized(20) {
                    return Err(libc::EINVAL);
                }
                let addr = Ipv6Addr::from(msg.read::<16>().unwrap());
                let index = u32::from_ne_bytes(msg.data[16..20].try_into().unwrap());
                if index != 0 {
                    if !interface_exists(shared, index) {
                        return Err(libc::ENXIO);
                    }
                    ctl.oif = Some(index);
                }
                if !addr.is_unspecified() {
                    if !shared.topo().is_host(IpAddr::V6(addr)) {
                        return Err(libc::EADDRNOTAVAIL);
                    }
                    ctl.src = Some(IpAddr::V6(addr));
                }
            }
            libc::IPV6_HOPLIMIT | os::IPV6_2292HOPLIMIT => {
                if !msg.sized(4) {
                    return Err(libc::EINVAL);
                }
                match msg.int() {
                    -1 => ctl.ttl = None,
                    hops @ 0..=255 => ctl.ttl = Some(hops as u8),
                    _ => return Err(libc::EINVAL),
                }
            }
            libc::IPV6_TCLASS => {
                if !msg.sized(4) {
                    return Err(libc::EINVAL);
                }
                match msg.int() {
                    -1 => ctl.tos = Some(0),
                    tclass @ 0..=255 => ctl.tos = Some(tclass as u8),
                    _ => return Err(libc::EINVAL),
                }
            }
            os::IPV6_DONTFRAG => {
                if !msg.sized(4) {
                    return Err(libc::EINVAL);
                }
                ctl.dontfrag = Some(msg.int() != 0);
            }
            os::IPV6_USE_MIN_MTU | os::IPV6_PREFER_TEMPADDR => {
                if !msg.sized(4) || !(-1..=1).contains(&msg.int()) {
                    return Err(libc::EINVAL);
                }
            }
            os::IPV6_2292NEXTHOP
            | os::IPV6_NEXTHOP
            | os::IPV6_2292HOPOPTS
            | os::IPV6_HOPOPTS
            | os::IPV6_2292DSTOPTS
            | os::IPV6_DSTOPTS
            | os::IPV6_RTHDRDSTOPTS
            | os::IPV6_2292RTHDR
            | os::IPV6_RTHDR => return Err(libc::EOPNOTSUPP),
            _ => return Err(libc::ENOPROTOOPT),
        }
    }
    Ok(())
}

/// The `int` a kept option holds: its value when set at least an `int` long, its one byte when
/// shorter (how Linux reads `IP_TOS`, `IP_TTL` and `IP_MULTICAST_TTL`, and macOS a one-byte
/// `IP_MULTICAST_TTL`).
#[cfg(unix)]
fn kept(rec: &SockRec, level: c_int, name: c_int) -> Option<c_int> {
    let bytes = rec.ignored_value(level, name)?;
    match bytes.len() {
        0 => None,
        1..4 => Some(c_int::from(bytes[0])),
        _ => Some(c_int::from_ne_bytes(bytes[..4].try_into().unwrap())),
    }
}

/// The header fields of a datagram socket `rec`'s send to `dest` with controls `ctl`: their
/// values, else the socket's `IP_TOS`/`IPV6_TCLASS` and `IP_TTL`/`IP_MULTICAST_TTL`/
/// `IPV6_UNICAST_HOPS`/`IPV6_MULTICAST_HOPS` (-1 or unset the default), else the defaults. An
/// IPv6 socket's IPv4 datagram takes the IPv4 options on Linux, which an IPv6 socket accepts
/// (net/ipv6/udp.c `udpv6_sendmsg` hands it to `udp_sendmsg`); macOS refuses those on an IPv6
/// socket and gives it a TOS of 0 and the `IPV6_UNICAST_HOPS` of a dual-stack socket as its TTL
/// (XNU bsd/netinet6/ip6_output.c `ip6_ctloutput` copies the hop limit to `inp_ip_ttl` while
/// the socket takes IPv4). Measured by tests/dual_stack_os_truth.rs.
#[cfg(unix)]
pub(crate) fn header(rec: &SockRec, dest: SocketAddr, ctl: &SendCtl) -> Header {
    let dst = dest.ip();
    let v4 = v4_dest(dest);
    let multicast = match dst {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or(v6.is_multicast(), |v4| v4.is_multicast()),
        IpAddr::V4(v4) => v4.is_multicast(),
    };
    if cfg!(target_os = "macos") && v4 && !multicast {
        let (inet6, v6only) = {
            let state = rec.state();
            (state.inet6, state.v6only)
        };
        if inet6 {
            let hops = kept(rec, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS)
                .filter(|ttl| (0..=255).contains(ttl) && !v6only);
            return Header {
                tos: ctl.tos.unwrap_or(0),
                ttl: ctl
                    .ttl
                    .unwrap_or_else(|| hops.map_or(default_ttl(false), |ttl| ttl as u8)),
                dst,
                ifindex: 0,
                gso: 0,
            };
        }
    }
    let (tos_opt, ttl_opt) = if v4 {
        (
            (libc::IPPROTO_IP, libc::IP_TOS),
            if multicast {
                (libc::IPPROTO_IP, libc::IP_MULTICAST_TTL)
            } else {
                (libc::IPPROTO_IP, libc::IP_TTL)
            },
        )
    } else {
        (
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS),
            if multicast {
                (libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS)
            } else {
                (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS)
            },
        )
    };
    let tos = ctl.tos.unwrap_or_else(|| {
        kept(rec, tos_opt.0, tos_opt.1)
            .filter(|tos| (0..=255).contains(tos))
            .unwrap_or(0) as u8
    });
    let ttl = ctl.ttl.unwrap_or_else(|| {
        kept(rec, ttl_opt.0, ttl_opt.1)
            .filter(|ttl| (0..=255).contains(ttl))
            .map_or(default_ttl(multicast), |ttl| ttl as u8)
    });
    Header {
        tos,
        ttl,
        dst,
        ifindex: 0,
        gso: 0,
    }
}

/// The segment size of a send with controls `ctl` on `rec`: its `UDP_SEGMENT` message, else the
/// socket's; 0 for none.
#[cfg(target_os = "linux")]
pub(crate) fn gso_size(rec: &SockRec, ctl: &SendCtl) -> u16 {
    ctl.gso.unwrap_or_else(|| rec.state().anc.gso)
}

/// Whether datagram socket `rec` reads a segmented send over loopback whole (Linux `UDP_GRO`).
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
#[cfg(unix)]
pub(crate) fn gro(rec: &SockRec) -> bool {
    #[cfg(target_os = "linux")]
    return rec.state().anc.gro;
    #[cfg(not(target_os = "linux"))]
    false
}

#[cfg(unix)]
fn int_bytes(v: c_int) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

/// The control messages `recvmsg` on `rec` (an IPv6 socket if `v6`) reports for a datagram from
/// `src` with header `h`, in the host's order, to follow the receive timestamps:
///
/// - Linux, IPv4 (`ip_cmsg_recv_offset`): `IP_PKTINFO` (`in_pktinfo`: the receiving interface,
///   the local address the datagram is for, the destination; for a broadcast or multicast one
///   that interface's address, `fib_compute_spec_dst`), `IP_TTL` (`int`), `IP_TOS` (one byte).
/// - Linux, IPv6 (`ip6_datagram_recv_common_ctl`, `ip6_datagram_recv_specific_ctl`):
///   `IPV6_PKTINFO` (`in6_pktinfo`), `IPV6_HOPLIMIT`, `IPV6_TCLASS` (`int`s).
/// - macOS, IPv4 (`ip_savecontrol`, bsd/netinet/ip_input.c): `IP_RECVDSTADDR` (`in_addr`),
///   `IP_RECVTTL` (one byte), `IP_RECVPKTINFO` (`in_pktinfo` without `ipi_spec_dst`),
///   `IP_RECVTOS` (one byte).
/// - macOS, IPv6 (`ip6_savecontrol`, bsd/netinet6/ip6_input.c): as Linux.
/// - An IPv4 datagram on an IPv6 socket (dual-stack, RFC 3493 §3.7): Linux `udpv6_recvmsg`
///   (net/ipv6/udp.c) gives the v4-mapped `IPV6_PKTINFO` (`ip6_datagram_recv_common_ctl`) and
///   then the IPv4 messages above, which an IPv6 socket may ask for; macOS `udp_input`
///   (bsd/netinet/udp_usrreq.c) gives `IPV6_TCLASS` carrying the TOS, then the v4-mapped
///   `IPV6_PKTINFO`, and no hop limit. Measured by tests/dual_stack_os_truth.rs.
#[cfg(unix)]
pub(crate) fn rx_cmsgs(
    shared: &SimShared,
    rec: &SockRec,
    v6: bool,
    src: IpAddr,
    h: &Header,
) -> Vec<Cmsg> {
    let opts = rec.state().anc;
    let mut out = Vec::new();
    match (h.dst, v6) {
        (IpAddr::V4(dst), false) => ipv4_cmsgs(&mut out, &opts, shared, h, src, dst),
        (IpAddr::V4(dst), true) => {
            let mapped = || {
                let mut info = dst.to_ipv6_mapped().octets().to_vec();
                info.extend(h.ifindex.to_ne_bytes());
                (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, info)
            };
            if cfg!(target_os = "macos") && opts.tclass {
                out.push((
                    libc::IPPROTO_IPV6,
                    libc::IPV6_TCLASS,
                    int_bytes(c_int::from(h.tos)),
                ));
            }
            if opts.pktinfo6 {
                out.push(mapped());
            }
            if cfg!(target_os = "linux") {
                ipv4_cmsgs(&mut out, &opts, shared, h, src, dst);
            }
        }
        (IpAddr::V6(dst), true) => {
            if opts.pktinfo6 {
                let mut info = dst.octets().to_vec();
                info.extend(h.ifindex.to_ne_bytes());
                out.push((libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, info));
            }
            if opts.hoplimit {
                out.push((
                    libc::IPPROTO_IPV6,
                    libc::IPV6_HOPLIMIT,
                    int_bytes(c_int::from(h.ttl)),
                ));
            }
            if opts.tclass {
                out.push((
                    libc::IPPROTO_IPV6,
                    libc::IPV6_TCLASS,
                    int_bytes(c_int::from(h.tos)),
                ));
            }
        }
        _ => {}
    }
    out
}

/// The IPv4 messages of [`rx_cmsgs`] for a datagram to `dst`.
#[cfg(unix)]
fn ipv4_cmsgs(
    out: &mut Vec<Cmsg>,
    opts: &Opts,
    shared: &SimShared,
    h: &Header,
    src: IpAddr,
    dst: Ipv4Addr,
) {
    #[cfg(target_os = "macos")]
    if opts.dstaddr {
        out.push((
            libc::IPPROTO_IP,
            libc::IP_RECVDSTADDR,
            dst.octets().to_vec(),
        ));
    }
    #[cfg(target_os = "macos")]
    if opts.ttl {
        out.push((libc::IPPROTO_IP, libc::IP_RECVTTL, vec![h.ttl]));
    }
    if opts.pktinfo {
        let mut info = h.ifindex.to_ne_bytes().to_vec();
        info.extend(spec_dst(shared, h, src).octets());
        info.extend(dst.octets());
        out.push((libc::IPPROTO_IP, libc::IP_PKTINFO, info));
    }
    #[cfg(target_os = "linux")]
    if opts.ttl {
        out.push((
            libc::IPPROTO_IP,
            libc::IP_TTL,
            int_bytes(c_int::from(h.ttl)),
        ));
    }
    if opts.tos {
        let ty = if cfg!(target_os = "linux") {
            libc::IP_TOS
        } else {
            libc::IP_RECVTOS
        };
        out.push((libc::IPPROTO_IP, ty, vec![h.tos]));
    }
}

/// Linux `fib_compute_spec_dst`: the destination of a datagram for one of the host's addresses,
/// else the receiving interface's address facing `src`.
#[cfg(target_os = "linux")]
fn spec_dst(shared: &SimShared, h: &Header, src: IpAddr) -> Ipv4Addr {
    let IpAddr::V4(dst) = h.dst else {
        return Ipv4Addr::UNSPECIFIED;
    };
    let topo = shared.topo();
    if !dst.is_multicast() && !topo.is_broadcast(h.dst) {
        return dst;
    }
    match topo.source_on(h.ifindex, src) {
        Some(IpAddr::V4(ip)) => ip,
        _ => Ipv4Addr::UNSPECIFIED,
    }
}

#[cfg(target_os = "macos")]
fn spec_dst(_: &SimShared, _: &Header, _: IpAddr) -> Ipv4Addr {
    Ipv4Addr::UNSPECIFIED
}

/// Linux `udp_cmsg_recv`: the `UDP_GRO` message (an `int` segment size) of a datagram read whole
/// from a segmented send, ahead of every other control message.
#[cfg(target_os = "linux")]
pub(crate) fn gro_cmsg(rec: &SockRec, h: &Header) -> Option<Cmsg> {
    (h.gso != 0 && rec.state().anc.gro)
        .then(|| (libc::SOL_UDP, libc::UDP_GRO, int_bytes(c_int::from(h.gso))))
}

/// The `int` of an option value at least an `int` long; `None` for a null or shorter one.
#[cfg(unix)]
fn full_int(val: *const u8, len: u32) -> Option<c_int> {
    if val.is_null() || (len as usize) < size_of::<c_int>() {
        return None;
    }
    Some(unsafe { val.cast::<c_int>().read_unaligned() })
}

/// The flag of [`Opts`] option `(level, name)` sets.
#[cfg(unix)]
fn flag(opts: &mut Opts, level: c_int, name: c_int) -> Option<&mut bool> {
    match (level, name) {
        (libc::IPPROTO_IP, libc::IP_RECVTOS) => Some(&mut opts.tos),
        (libc::IPPROTO_IP, libc::IP_RECVTTL) => Some(&mut opts.ttl),
        (libc::IPPROTO_IP, libc::IP_PKTINFO) => Some(&mut opts.pktinfo),
        #[cfg(target_os = "macos")]
        (libc::IPPROTO_IP, libc::IP_RECVDSTADDR) => Some(&mut opts.dstaddr),
        (libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS) => Some(&mut opts.tclass),
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO) => Some(&mut opts.pktinfo6),
        (libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT) => Some(&mut opts.hoplimit),
        #[cfg(target_os = "linux")]
        (libc::SOL_UDP, libc::UDP_GRO) => Some(&mut opts.gro),
        _ => None,
    }
}

/// Sets a receive option or Linux `UDP_GRO`/`UDP_SEGMENT` on `rec` (an IPv6 socket if `v6`);
/// `None` for any other option. Linux reads the `IP_*` flags as `do_ip_setsockopt` does (an
/// `int`, a single byte, or 0 for an empty value; an IPv6 socket takes them too), refuses an
/// `IPV6_*` flag shorter than an `int` (`EINVAL`) or on an IPv4 socket (`ENOPROTOOPT`), and the
/// `SOL_UDP` options shorter than an `int` (`EINVAL`), a segment size outside `0..=65535` too
/// (`udp_lib_setsockopt`). macOS refuses a value shorter than an `int` and an option of the other
/// family with `EINVAL`. All measured.
///
/// # Safety
/// `val` points to `len` readable bytes.
#[cfg(unix)]
pub(crate) unsafe fn set(
    rec: &SockRec,
    v6: bool,
    level: c_int,
    name: c_int,
    val: *const u8,
    len: u32,
) -> Option<Result<(), c_int>> {
    #[cfg(target_os = "linux")]
    if (level, name) == (libc::SOL_UDP, libc::UDP_SEGMENT) {
        return Some(match full_int(val, len) {
            Some(size @ 0..=0xffff) => {
                rec.state().anc.gso = size as u16;
                Ok(())
            }
            _ => Err(libc::EINVAL),
        });
    }
    let mut state = rec.state();
    let slot = flag(&mut state.anc, level, name)?;
    #[cfg(target_os = "linux")]
    let on = if level == libc::IPPROTO_IP {
        read_ip_int(val, len) != 0
    } else {
        if level == libc::IPPROTO_IPV6 && !v6 {
            return Some(Err(libc::ENOPROTOOPT));
        }
        match full_int(val, len) {
            Some(v) => v != 0,
            None => return Some(Err(libc::EINVAL)),
        }
    };
    #[cfg(target_os = "macos")]
    let on = {
        if (level == libc::IPPROTO_IPV6) != v6 {
            return Some(Err(libc::EINVAL));
        }
        match full_int(val, len) {
            Some(v) => v != 0,
            None => return Some(Err(libc::EINVAL)),
        }
    };
    *slot = on;
    Some(Ok(()))
}

/// The `int` Linux's `do_ip_setsockopt` reads: a full `int`, else a single byte, else 0.
#[cfg(target_os = "linux")]
fn read_ip_int(val: *const u8, len: u32) -> c_int {
    if val.is_null() || len == 0 {
        return 0;
    }
    if (len as usize) < size_of::<c_int>() {
        return c_int::from(unsafe { *val });
    }
    unsafe { val.cast::<c_int>().read_unaligned() }
}

/// Reads an option [`set`] keeps back as an `int`; `None` for any other option. The other
/// family's option is `EOPNOTSUPP` on Linux (an `IPV6_*` one on an IPv4 socket) and `EINVAL` on
/// macOS (measured).
///
/// # Safety
/// `val`/`len` are the caller's getsockopt buffer.
#[cfg(unix)]
pub(crate) unsafe fn get(
    rec: &SockRec,
    v6: bool,
    level: c_int,
    name: c_int,
    val: *mut u8,
    len: *mut u32,
) -> Option<Result<(), c_int>> {
    let mut opts = rec.state().anc;
    #[cfg(target_os = "linux")]
    if (level, name) == (libc::SOL_UDP, libc::UDP_SEGMENT) {
        unsafe { crate::netif::frag::write_int(c_int::from(opts.gso), val, len) };
        return Some(Ok(()));
    }
    let value = c_int::from(*flag(&mut opts, level, name)?);
    #[cfg(target_os = "linux")]
    if level == libc::IPPROTO_IPV6 && !v6 {
        return Some(Err(libc::EOPNOTSUPP));
    }
    #[cfg(target_os = "macos")]
    if (level == libc::IPPROTO_IPV6) != v6 {
        return Some(Err(libc::EINVAL));
    }
    unsafe { crate::netif::frag::write_int(value, val, len) };
    Some(Ok(()))
}
