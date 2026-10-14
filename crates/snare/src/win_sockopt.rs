//! Winsock socket options, don't-fragment and timestamping on the Windows fabric's sockets.
//!
//! Every option Windows defines at `SOL_SOCKET`, `IPPROTO_IP`, `IPPROTO_IPV6`, `IPPROTO_TCP` and
//! `IPPROTO_UDP` is known here by its level and number, as Microsoft's option tables list them
//! ([Microsoft Learn: SOL_SOCKET socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/sol-socket-socket-options),
//! [IPPROTO_IP](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options),
//! [IPPROTO_IPV6](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options),
//! [IPPROTO_TCP](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-tcp-socket-options),
//! [IPPROTO_UDP](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-udp-socket-options))
//! with the numbers of `ws2def.h`, `ws2ipdef.h` and `mswsock.h`. `win_net` models some itself
//! (timeouts, linger, buffers, broadcast, interfaces, memberships, don't-fragment); the rest are
//! either harmless — kept and read back, because nothing a test can observe in the sim depends on
//! them, as on unix (`fabric::harmless`) — or unmodelled: kept and read back as well, but listed
//! in the socket's `unmodelled_options` and refused under `strict_sockopts`. An option Windows
//! does not define fails as the host fails it: `WSAEINVAL` at `SOL_SOCKET` and `WSAENOPROTOOPT`
//! at `IPPROTO_IP` (both measured, tests/strict_sockopts.rs `unknown_option_codes_on_windows`),
//! `WSAENOPROTOOPT` at the other protocol levels (assumed equal to `IPPROTO_IP`'s), and
//! `WSAEINVAL` at a level Windows does not know ("level is not valid",
//! [Microsoft Learn: setsockopt](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-setsockopt)).
//! That is also the code a strict sim refuses an unmodelled option with, as
//! `SimBuilder::strict_sockopts` documents.

use std::collections::VecDeque;
use std::ffi::c_int;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::netif::Sender;
use crate::scope::SimShared;
use crate::sockets::{SockRec, UnmodelledOption};

/// `WSAEFAULT`: a null or short option value.
pub(crate) const WSAEFAULT: c_int = 10014;
/// `WSAEINVAL`: an option value out of range, or an option at an unknown level.
pub(crate) const WSAEINVAL: c_int = 10022;
/// `WSAEMSGSIZE`: a datagram that may not be fragmented and does not fit the egress MTU.
pub(crate) const WSAEMSGSIZE: c_int = 10040;
/// `WSAENOPROTOOPT`: an option the protocol level does not define or the socket type does not
/// take.
pub(crate) const WSAENOPROTOOPT: c_int = 10042;
/// `WSAEOPNOTSUPP`: an ioctl the socket cannot carry out.
pub(crate) const WSAEOPNOTSUPP: c_int = 10045;
/// `WSAEWOULDBLOCK`: no transmit stamp of that id is waiting.
pub(crate) const WSAEWOULDBLOCK: c_int = 10035;

/// `SOL_SOCKET` (`ws2def.h`).
pub(crate) const SOL_SOCKET: c_int = 0xffff;
/// `IPPROTO_IP` (`ws2def.h`).
pub(crate) const IPPROTO_IP: c_int = 0;
/// `IPPROTO_TCP` (`ws2def.h`).
pub(crate) const IPPROTO_TCP: c_int = 6;
/// `IPPROTO_UDP` (`ws2def.h`).
pub(crate) const IPPROTO_UDP: c_int = 17;
/// `IPPROTO_IPV6` (`ws2def.h`).
pub(crate) const IPPROTO_IPV6: c_int = 41;

/// `SO_PROTOCOL_INFOA` (`winsock2.h`): the socket's `WSAPROTOCOL_INFOA`, read-only.
pub(crate) const SO_PROTOCOL_INFOA: c_int = 0x2004;
/// `SO_PROTOCOL_INFOW` (`winsock2.h`): the socket's `WSAPROTOCOL_INFOW`, read-only.
pub(crate) const SO_PROTOCOL_INFOW: c_int = 0x2005;

/// `SO_KEEPALIVE` (`ws2def.h`).
pub(crate) const SO_KEEPALIVE: c_int = 0x0008;
/// `SO_OOBINLINE` (`ws2def.h`).
pub(crate) const SO_OOBINLINE: c_int = 0x0100;
/// `IP_DONTFRAGMENT` (`ws2ipdef.h`), a `DWORD` boolean.
const IP_DONTFRAGMENT: c_int = 14;
/// `IPV6_DONTFRAG` (`ws2ipdef.h`), a `DWORD` boolean.
const IPV6_DONTFRAG: c_int = 14;
/// `IP_MTU_DISCOVER` and `IPV6_MTU_DISCOVER` (`ws2ipdef.h`), a `PMTUD_STATE`.
const MTU_DISCOVER: c_int = 71;
/// `IP_PMTUDISC_DO` (`ws2ipdef.h` `PMTUD_STATE`): every datagram carries DF and one larger than
/// the path MTU fails.
const PMTUDISC_DO: u8 = 1;
/// `IP_PMTUDISC_PROBE`: DF on every datagram, and one larger than the interface MTU fails.
const PMTUDISC_PROBE: u8 = 3;
/// `IP_PMTUDISC_MAX`, one past the last `PMTUD_STATE` (`IP_PMTUDISC_NOT_SET` 0, `DO` 1, `DONT` 2,
/// `PROBE` 3).
const PMTUDISC_MAX: c_int = 4;

/// `IP_TOS` (`ws2ipdef.h`): the TOS byte, as an option and as a send's control message.
const IP_TOS: c_int = 3;
/// `IP_TTL` (`ws2ipdef.h`); `IPV6_UNICAST_HOPS` has the same number and is kept with it.
const IP_TTL: c_int = 4;
/// `IP_MULTICAST_TTL` and `IPV6_MULTICAST_HOPS` (`ws2ipdef.h`).
const MULTICAST_TTL: c_int = 10;
/// `IP_PKTINFO` and `IPV6_PKTINFO` (`ws2ipdef.h`): the option that asks for, and the control
/// message that carries, an `IN_PKTINFO` or `IN6_PKTINFO`.
const PKTINFO: c_int = 19;
/// `IP_HOPLIMIT` (also `IP_RECVTTL`) and `IPV6_HOPLIMIT` (`ws2ipdef.h`).
const HOPLIMIT: c_int = 21;
/// `IPV6_TCLASS` (`ws2ipdef.h`).
const IPV6_TCLASS: c_int = 39;
/// `IP_RECVTOS` and `IPV6_RECVTCLASS` (`ws2ipdef.h`).
const RECVTOS: c_int = 40;
/// `IP_ECN`/`IP_RECVECN` and `IPV6_ECN`/`IPV6_RECVECN` (`ws2ipdef.h`).
const ECN: c_int = 50;
/// `UDP_SEND_MSG_SIZE` (`ws2ipdef.h`).
const UDP_SEND_MSG_SIZE: c_int = 2;
/// `UDP_RECV_MAX_COALESCED_SIZE`, and `UDP_COALESCED_INFO`, the control message of a coalesced
/// datagram (`ws2ipdef.h`).
const UDP_COALESCED: c_int = 3;
/// `SO_TIMESTAMP_ID` (`mstcpip.h`, 0x300B), the control message tagging a datagram for a
/// transmit stamp.
const SO_TIMESTAMP_ID: c_int = 0x300B;

/// The Windows half of a socket's record: its family, timestamping, receive options and UDP
/// offloads.
#[derive(Default)]
pub(crate) struct WinSock {
    /// Created `AF_INET6`.
    pub(crate) v6: bool,
    legacy_frag: bool,
    /// `SIO_TIMESTAMPING` and the transmit stamps waiting for `SIO_GET_TX_TIMESTAMP`.
    pub(crate) stamping: Stamping,
    /// The receive options at `IPPROTO_IP`, which IPv4 datagrams answer.
    recv4: Recv,
    /// The receive options at `IPPROTO_IPV6`, which IPv6 datagrams answer.
    recv6: Recv,
    /// `UDP_SEND_MSG_SIZE`: the segment size of a send that gives none; 0 sends whole.
    uso: u32,
    /// `UDP_RECV_MAX_COALESCED_SIZE`: how much of a segmented send through loopback is read as
    /// one datagram; 0 reads each segment.
    uro: u32,
}

/// One level's receive options: the control messages `WSARecvMsg` returns.
#[derive(Default)]
struct Recv {
    /// `IP_PKTINFO`/`IPV6_PKTINFO`.
    pktinfo: bool,
    /// `IP_RECVECN`/`IPV6_RECVECN`.
    ecn: bool,
    /// `IP_RECVTTL`/`IPV6_HOPLIMIT`.
    ttl: bool,
    /// `IP_RECVTOS`/`IPV6_RECVTCLASS`.
    tos: bool,
}

/// What a socket's `SIO_TIMESTAMPING` asked for
/// ([Microsoft Learn: Winsock timestamping](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-timestamping)).
#[derive(Default)]
pub(crate) struct Stamping {
    /// `TIMESTAMPING_FLAG_RX`: received datagrams carry an `SO_TIMESTAMP` control message.
    rx: bool,
    /// `TIMESTAMPING_FLAG_TX` with its `TxTimestampsBuffered`; `None` while transmit stamps are
    /// off.
    tx: Option<usize>,
    /// Transmit stamps generated and not yet taken, by `SO_TIMESTAMP_ID`, oldest first.
    ready: VecDeque<(u32, u64)>,
}

/// How the sim treats an option Windows defines and `win_net` does not model.
#[derive(Clone, Copy, PartialEq)]
enum Class {
    /// Kept and read back, never listed.
    Harmless,
    /// Kept and read back, listed as unmodelled, refused under `strict_sockopts`.
    Unmodelled,
    /// Refused with this code whatever its value: Windows does not support it.
    Refused(c_int),
}

/// What an option's value is.
#[derive(Clone, Copy)]
enum Shape {
    /// A `DWORD` boolean: any value, read back as 0 or 1.
    Flag,
    /// A `DWORD` taken as given.
    Dword,
    /// A `DWORD` in `0..=max`; anything else is `WSAEINVAL`.
    UpTo(u32),
    /// A hop limit, 0 to 255, or `IP_UNSPECIFIED_HOP_LIMIT` (-1, `ws2ipdef.h`) for the default;
    /// anything else is `WSAEINVAL`.
    Hops,
    /// A TOS byte or traffic class, 0 to 255 with its two ECN bits clear; anything else is
    /// `WSAEINVAL` (measured on Windows 11 build 26200.9457, `cmsg_win_os_truth`).
    Tos,
    /// A structure or array, kept as given and read back as kept (empty until set).
    Bytes,
}

/// Which way an option goes.
#[derive(Clone, Copy, PartialEq)]
enum Access {
    Both,
    /// Read-only: setting it is the level's unknown-option code.
    Get,
    /// Write-only: reading it is the level's unknown-option code.
    Set,
}

/// Which sockets take an option.
#[derive(Clone, Copy, PartialEq)]
enum Takes {
    Any,
    /// Connection-oriented sockets only; a datagram socket fails with `WSAENOPROTOOPT`.
    Stream,
}

/// An option Windows defines, with its Windows default.
struct Known {
    level: c_int,
    name: c_int,
    class: Class,
    shape: Shape,
    access: Access,
    takes: Takes,
    default: i32,
}

const fn opt(level: c_int, name: c_int, class: Class, shape: Shape, default: i32) -> Known {
    Known {
        level,
        name,
        class,
        shape,
        access: Access::Both,
        takes: Takes::Any,
        default,
    }
}

const fn get_only(level: c_int, name: c_int, shape: Shape) -> Known {
    Known {
        access: Access::Get,
        ..opt(level, name, Class::Unmodelled, shape, 0)
    }
}

const fn set_only(level: c_int, name: c_int) -> Known {
    Known {
        access: Access::Set,
        ..opt(level, name, Class::Unmodelled, Shape::Bytes, 0)
    }
}

use Class::{Harmless, Unmodelled};
use Shape::{Bytes, Dword, Flag, Hops, Tos, UpTo};

/// The options Windows defines that `win_net` does not model itself, with Windows' defaults:
///
/// - `SO_KEEPALIVE` is off and stream-only (a datagram socket is `WSAENOPROTOOPT`), and
///   `TCP_KEEPIDLE` (`TCP_KEEPALIVE`) 7200 s and `TCP_KEEPINTVL` 1 s, the 2-hour timeout and
///   1-second interval [SO_KEEPALIVE](https://learn.microsoft.com/en-us/windows/win32/winsock/so-keepalive)
///   documents, which also gives 10 probes (`TCP_KEEPCNT`) from Vista on and refuses a count above
///   255. Harmless: a connection in the sim never dies idle.
/// - `TCP_NODELAY` is off (the IPPROTO_TCP page). Harmless: the sim has no Nagle delay.
/// - `SO_DEBUG` ("Microsoft providers currently do not output any debug information"),
///   `SO_DONTROUTE` ("Microsoft providers silently ignore this option") and `SO_OOBINLINE` (the sim
///   sends no urgent data) are off and harmless.
/// - `IP_TTL` and `IPV6_UNICAST_HOPS` default to 128, Windows' default hop limit (measured on Windows 11 build
///   26200.9457 by `winsock_os_truth::extended_option_defaults_match_the_host`); `IP_MULTICAST_TTL` and `IPV6_MULTICAST_HOPS` to 1
///   (`ws2ipdef.h` `IP_DEFAULT_MULTICAST_TTL`); `IP_TOS` and `IPV6_TCLASS` to 0, refusing a value
///   with ECN bits (`cmsg_win_os_truth`). Harmless: the sim's links count no hops and carry no
///   QoS; the values only travel in the header a receiver's control messages report. The pages
///   refuse IPv6 hop limits above 255; the IPv4 ones are held to the same range, an assumption.
/// - `IP_MULTICAST_LOOP` and `IPV6_MULTICAST_LOOP` default to on (`IP_DEFAULT_MULTICAST_LOOP`;
///   the IPPROTO_IP page: "By default, IP_MULTICAST_LOOP is enabled"), `TCP_BSDURGENT` to on (the
///   IPPROTO_TCP page), `IP_USER_MTU`/`IPV6_USER_MTU` to `IP_UNSPECIFIED_USER_MTU` (`MAXULONG`), and
///   `IP_RECEIVE_BROADCAST` to on (measured by the same default-option test). Everything else is 0. All of these are unmodelled: the sim's behaviour does not
///   follow them.
/// - `SO_SNDLOWAT`, `SO_RCVLOWAT` and `SO_USELOOPBACK` fail `WSAEINVAL` both ways, as the
///   SOL_SOCKET page says Windows Vista and later fail them.
static KNOWN: &[Known] = &[
    Known {
        takes: Takes::Stream,
        ..opt(SOL_SOCKET, SO_KEEPALIVE, Harmless, Flag, 0)
    },
    opt(SOL_SOCKET, 0x0001, Harmless, Flag, 0),
    opt(SOL_SOCKET, 0x0010, Harmless, Flag, 0),
    opt(SOL_SOCKET, SO_OOBINLINE, Harmless, Flag, 0),
    opt(SOL_SOCKET, 0x0040, Class::Refused(WSAEINVAL), Dword, 0),
    opt(SOL_SOCKET, 0x1003, Class::Refused(WSAEINVAL), Dword, 0),
    opt(SOL_SOCKET, 0x1004, Class::Refused(WSAEINVAL), Dword, 0),
    get_only(SOL_SOCKET, 0x1009, Bytes),
    get_only(SOL_SOCKET, 0x2001, Dword),
    opt(SOL_SOCKET, 0x2002, Unmodelled, Dword, 0),
    get_only(SOL_SOCKET, 0x2003, Dword),
    opt(SOL_SOCKET, 0x3002, Unmodelled, Flag, 0),
    opt(SOL_SOCKET, 0x3003, Unmodelled, Flag, 0),
    opt(SOL_SOCKET, 0x3005, Unmodelled, Flag, 0),
    opt(SOL_SOCKET, 0x3006, Unmodelled, Flag, 0),
    opt(SOL_SOCKET, 0x3007, Unmodelled, Flag, 0),
    opt(SOL_SOCKET, 0x3008, Unmodelled, Flag, 0),
    opt(SOL_SOCKET, 0x7008, Unmodelled, Dword, 0),
    get_only(SOL_SOCKET, 0x7009, Dword),
    get_only(SOL_SOCKET, 0x700A, Dword),
    set_only(SOL_SOCKET, 0x700B),
    get_only(SOL_SOCKET, 0x700C, Dword),
    set_only(SOL_SOCKET, 0x7010),
    opt(IPPROTO_IP, 1, Unmodelled, Bytes, 0),
    opt(IPPROTO_IP, 2, Unmodelled, Flag, 0),
    opt(IPPROTO_IP, IP_TOS, Harmless, Tos, 0),
    opt(IPPROTO_IP, 4, Harmless, Hops, 128),
    opt(IPPROTO_IP, 10, Harmless, Hops, 1),
    opt(IPPROTO_IP, 11, Unmodelled, Flag, 1),
    set_only(IPPROTO_IP, 13),
    set_only(IPPROTO_IP, 15),
    set_only(IPPROTO_IP, 16),
    set_only(IPPROTO_IP, 17),
    set_only(IPPROTO_IP, 18),
    opt(IPPROTO_IP, 22, Unmodelled, Flag, 1),
    opt(IPPROTO_IP, 24, Unmodelled, Flag, 0),
    opt(IPPROTO_IP, 28, Unmodelled, Flag, 0),
    set_only(IPPROTO_IP, 29),
    set_only(IPPROTO_IP, 30),
    get_only(IPPROTO_IP, 33, Bytes),
    opt(IPPROTO_IP, 47, Unmodelled, Flag, 0),
    opt(IPPROTO_IP, 60, Unmodelled, Bytes, 0),
    opt(IPPROTO_IP, 70, Unmodelled, Bytes, 0),
    get_only(IPPROTO_IP, 73, Dword),
    opt(IPPROTO_IP, 76, Unmodelled, Dword, -1),
    opt(IPPROTO_IPV6, 2, Unmodelled, Flag, 0),
    opt(IPPROTO_IPV6, 4, Harmless, Hops, 128),
    opt(IPPROTO_IPV6, 10, Harmless, Hops, 1),
    opt(IPPROTO_IPV6, 11, Unmodelled, Flag, 1),
    set_only(IPPROTO_IPV6, 13),
    opt(IPPROTO_IPV6, 23, Unmodelled, Dword, 0),
    opt(IPPROTO_IPV6, 24, Unmodelled, Flag, 0),
    opt(IPPROTO_IPV6, 28, Unmodelled, Flag, 0),
    set_only(IPPROTO_IPV6, 29),
    set_only(IPPROTO_IPV6, 30),
    get_only(IPPROTO_IPV6, 33, Bytes),
    opt(IPPROTO_IPV6, IPV6_TCLASS, Harmless, Tos, 0),
    opt(IPPROTO_IPV6, 47, Unmodelled, Flag, 0),
    get_only(IPPROTO_IPV6, 72, Dword),
    opt(IPPROTO_IPV6, 76, Unmodelled, Dword, -1),
    opt(IPPROTO_TCP, 1, Harmless, Flag, 0),
    opt(IPPROTO_TCP, 2, Unmodelled, Flag, 0),
    opt(IPPROTO_TCP, 3, Harmless, Dword, 7200),
    opt(IPPROTO_TCP, 10, Unmodelled, Flag, 0),
    opt(IPPROTO_TCP, 15, Unmodelled, Flag, 0),
    opt(IPPROTO_TCP, 16, Harmless, UpTo(255), 10),
    opt(IPPROTO_TCP, 17, Harmless, Dword, 1),
    opt(IPPROTO_TCP, 18, Unmodelled, Flag, 0),
    get_only(IPPROTO_TCP, 19, Bytes),
    opt(IPPROTO_TCP, 0x7000, Unmodelled, Flag, 1),
    opt(IPPROTO_UDP, 1, Unmodelled, Flag, 0),
    opt(IPPROTO_UDP, 20, Unmodelled, Flag, 0),
];

/// The code an option a level does not define fails with; see the module docs.
pub(crate) fn unknown(level: c_int) -> c_int {
    match level {
        IPPROTO_IP | IPPROTO_IPV6 | IPPROTO_TCP | IPPROTO_UDP => WSAENOPROTOOPT,
        _ => WSAEINVAL,
    }
}

/// What a socket is, as far as options care.
#[derive(Clone, Copy)]
pub(crate) struct Kind {
    /// A TCP socket (else UDP).
    pub(crate) stream: bool,
    /// A TCP connect is in progress.
    pub(crate) connecting: bool,
    /// Created `AF_INET6`.
    pub(crate) v6: bool,
    /// `IPV6_V6ONLY`.
    pub(crate) v6only: bool,
}

/// Protocol-level applicability. Unicast hops, fragmentation, the traffic class and the receive
/// options are accepted at the IPv6 level on IPv4 sockets, measured by `winsock_os_truth`,
/// `dontfrag_win` and `cmsg_win_os_truth` on Windows 11 build 26200.9457. Other IPv6-level
/// options on IPv4 sockets retain the unverified `WSAEINVAL` policy. TCP options on datagrams fail
/// `WSAENOPROTOOPT`; UDP options and the receive options on streams fail `WSAEINVAL` both ways
/// (measured).
pub(crate) fn level_applies(kind: Kind, level: c_int, name: c_int) -> Result<(), c_int> {
    let receive = matches!(name, PKTINFO | HOPLIMIT | RECVTOS | ECN);
    let any_family = matches!(name, 4 | IPV6_DONTFRAG | MTU_DISCOVER | IPV6_TCLASS);
    match level {
        IPPROTO_IPV6 if !kind.v6 && !receive && !any_family => Err(WSAEINVAL),
        IPPROTO_IP | IPPROTO_IPV6 if kind.stream && receive => Err(WSAEINVAL),
        IPPROTO_TCP if !kind.stream => Err(WSAENOPROTOOPT),
        IPPROTO_UDP if kind.stream => Err(WSAEINVAL),
        _ => Ok(()),
    }
}

/// Whether IPv6 socket `rec` also carries IPv4: `IPV6_V6ONLY` off, and bound to nothing, the
/// wildcard or a v4-mapped address.
fn dual_stack(rec: &SockRec) -> bool {
    let state = rec.state();
    !state.v6only
        && state.local.is_none_or(|local| match local.ip() {
            IpAddr::V6(ip) => ip.is_unspecified() || ip.to_ipv4_mapped().is_some(),
            IpAddr::V4(_) => true,
        })
}

/// Setting option `name` at `IPPROTO_IP` on IPv6 socket `rec`, as measured on Windows 11 build
/// 26200.9457 (`cmsg_win_os_truth`): the options that shape or report IPv4 traffic (`IP_TOS`,
/// `IP_TTL`, `IP_DONTFRAGMENT`, `IP_PKTINFO`, `IP_RECVTTL`, `IP_RECVIF`, `IP_RECVDSTADDR`,
/// `IP_RECVTOS`, `IP_ORIGINAL_ARRIVAL_IF`, `IP_RECVECN`, `IP_PKTINFO_EX`, `IP_RECVERR`,
/// `IP_MTU_DISCOVER`) fail `WSAEINVAL` unless the socket is dual-stack (`IPV6_V6ONLY` off, and
/// unbound or bound to the wildcard). Reading them never fails. Other options are not checked
/// here.
pub(crate) fn ip_on_v6(rec: &SockRec, name: c_int) -> Result<(), c_int> {
    match name {
        IP_TOS | IP_TTL | IP_DONTFRAGMENT | PKTINFO | HOPLIMIT | 24 | 25 | RECVTOS | 47 | ECN
        | 51 | MTU_DISCOVER | 75
            if !dual_stack(rec) =>
        {
            Err(WSAEINVAL)
        }
        _ => Ok(()),
    }
}

/// `(level, name)`'s entry, if Windows defines it and `win_net` leaves it to this module.
fn lookup(level: c_int, name: c_int) -> Option<&'static Known> {
    KNOWN.iter().find(|k| k.level == level && k.name == name)
}

/// Checks `known` applies to a socket of `kind` in direction `set`. An IPv6-only socket refuses to
/// set every `IPPROTO_IP` option with `WSAEINVAL`, though it reads them (measured by
/// tests/dual_stack_os_truth.rs); a dual-stack one takes `IP_TOS` as an IPv4 socket does, a value
/// with ECN bits refused (`cmsg_win_os_truth`).
fn usable(known: &Known, kind: Kind, set: bool) -> Result<(), c_int> {
    if let Class::Refused(code) = known.class {
        return Err(code);
    }
    let wrong_way = if set {
        known.access == Access::Get
    } else {
        known.access == Access::Set
    };
    if wrong_way {
        return Err(unknown(known.level));
    }
    if known.takes == Takes::Stream && !kind.stream {
        return Err(WSAENOPROTOOPT);
    }
    if set && kind.v6 && known.level == IPPROTO_IP && kind.v6only {
        return Err(WSAEINVAL);
    }
    // SO_KEEPALIVE: "If an application attempts to set the SO_KEEPALIVE socket option when a
    // connection request is still in process, the setsockopt function will fail and return
    // WSAEINVAL" (Microsoft Learn: SO_KEEPALIVE).
    if set && known.level == SOL_SOCKET && known.name == SO_KEEPALIVE && kind.connecting {
        return Err(WSAEINVAL);
    }
    Ok(())
}

/// `setsockopt` of an option `win_net` does not model: validated as its shape says, kept for
/// [`get`], and, if unmodelled, listed on the socket (and refused under `strict_sockopts`). An
/// option Windows does not define fails with [`unknown`]. A null or shorter-than-`DWORD` value of
/// a `DWORD` option is `WSAEFAULT` (setsockopt: "the optlen parameter is too small").
///
/// # Safety
/// `val` is null or points to `len` readable bytes.
pub(crate) unsafe fn set(
    shared: &SimShared,
    rec: &SockRec,
    kind: Kind,
    level: c_int,
    name: c_int,
    val: *const u8,
    len: u32,
) -> Result<(), c_int> {
    let known = lookup(level, name).ok_or(unknown(level))?;
    usable(known, kind, true)?;
    let bytes = match known.shape {
        Bytes => {
            if val.is_null() && len > 0 {
                return Err(WSAEFAULT);
            }
            if val.is_null() {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(val, len as usize) }.to_vec()
            }
        }
        shape => {
            if val.is_null() || (len as usize) < size_of::<c_int>() {
                return Err(WSAEFAULT);
            }
            let v = unsafe { val.cast::<c_int>().read_unaligned() };
            let stored = match shape {
                Flag => c_int::from(v != 0),
                UpTo(max) if v < 0 || v as u32 > max => return Err(WSAEINVAL),
                Hops if v == -1 && known.name == 4 => 255,
                Hops if v == -1 => known.default,
                Hops if !(0..=255).contains(&v) => return Err(WSAEINVAL),
                Tos if !(0..=255).contains(&v) || v & 3 != 0 => return Err(WSAEINVAL),
                _ => v,
            };
            stored.to_ne_bytes().to_vec()
        }
    };
    if known.class == Unmodelled
        && shared.unmodelled_option(rec, UnmodelledOption::Set { level, name })
    {
        return Err(unknown(level));
    }
    let stored_level = if name == 4 && matches!(level, IPPROTO_IP | IPPROTO_IPV6) {
        IPPROTO_IP
    } else {
        level
    };
    rec.keep_ignored(stored_level, name, &bytes);
    Ok(())
}

/// `getsockopt` of an option `win_net` does not model: the value [`set`] kept, else Windows'
/// default — a `DWORD`'s four bytes, or nothing for a structure never set. Unmodelled options are
/// listed (and refused under `strict_sockopts`) as for [`set`].
pub(crate) fn get(
    shared: &SimShared,
    rec: &SockRec,
    kind: Kind,
    level: c_int,
    name: c_int,
) -> Result<Vec<u8>, c_int> {
    let known = lookup(level, name).ok_or(unknown(level))?;
    usable(known, kind, false)?;
    if known.class == Unmodelled
        && shared.unmodelled_option(rec, UnmodelledOption::Get { level, name })
    {
        return Err(unknown(level));
    }
    let stored_level = if name == 4 && matches!(level, IPPROTO_IP | IPPROTO_IPV6) {
        IPPROTO_IP
    } else {
        level
    };
    Ok(match rec.ignored_value(stored_level, name) {
        Some(bytes) => bytes,
        None if matches!(known.shape, Bytes) => Vec::new(),
        None => known.default.to_ne_bytes().to_vec(),
    })
}

/// Sets a don't-fragment option; `None` for any other. `IP_DONTFRAGMENT` and `IPV6_DONTFRAG` are
/// flags; `IP_MTU_DISCOVER` and `IPV6_MTU_DISCOVER` take a `PMTUD_STATE` from 0 to 3.
/// The levels alias one socket-wide state. Selecting a legacy flag prevents later discovery
/// settings; a nonzero discovery mode prevents selecting a legacy flag. IPv6 sockets refuse
/// setting these options at `IPPROTO_IP` as [`ip_on_v6`] says. Measured on Windows 11 build
/// 26200.9457 by `dontfrag_win`'s mode and interaction parity tests. A short value is
/// `WSAEFAULT`.
///
/// # Safety
/// `val` is null or points to `len` readable bytes.
pub(crate) unsafe fn set_frag(
    rec: &SockRec,
    level: c_int,
    name: c_int,
    val: *const u8,
    len: u32,
) -> Option<Result<(), c_int>> {
    let which = match (level, name) {
        (IPPROTO_IP, IP_DONTFRAGMENT) | (IPPROTO_IPV6, IPV6_DONTFRAG) => true,
        (IPPROTO_IP | IPPROTO_IPV6, MTU_DISCOVER) => false,
        _ => return None,
    };
    if val.is_null() || (len as usize) < size_of::<c_int>() {
        return Some(Err(WSAEFAULT));
    }
    let v = unsafe { val.cast::<c_int>().read_unaligned() };
    if !which && !(0..PMTUDISC_MAX).contains(&v) {
        return Some(Err(WSAEINVAL));
    }
    let mut state = rec.state();
    if which {
        if state.frag.pmtudisc != 0 {
            return Some(Err(WSAEINVAL));
        }
        state.win.legacy_frag = true;
        state.frag.dontfrag = v != 0;
        state.frag.dontfrag6 = v != 0;
    } else {
        if state.win.legacy_frag {
            return Some(Err(WSAEINVAL));
        }
        state.frag.pmtudisc = v as u8;
        state.frag.pmtudisc6 = v as u8;
        let flag = matches!(v as u8, PMTUDISC_DO | PMTUDISC_PROBE);
        state.frag.dontfrag = flag;
        state.frag.dontfrag6 = flag;
    }
    Some(Ok(()))
}

/// A don't-fragment option's value (0 or 1 for the flags, the `PMTUD_STATE` for the others);
/// `None` for any other option.
pub(crate) fn get_frag(rec: &SockRec, level: c_int, name: c_int) -> Option<c_int> {
    let frag = rec.state().frag;
    Some(match (level, name) {
        (IPPROTO_IP, IP_DONTFRAGMENT) => c_int::from(frag.dontfrag),
        (IPPROTO_IP, MTU_DISCOVER) => c_int::from(frag.pmtudisc),
        (IPPROTO_IPV6, IPV6_DONTFRAG) => c_int::from(frag.dontfrag6),
        (IPPROTO_IPV6, MTU_DISCOVER) => c_int::from(frag.pmtudisc6),
        _ => return None,
    })
}

/// Refuses with `WSAEMSGSIZE` a datagram of `len` payload bytes to `dest` that may not be
/// fragmented and is larger, with its 8 bytes of UDP and 20 (IPv4) or 40 (IPv6) bytes of IP
/// header, than the MTU of the interface `sender` leaves through. An IPv4 datagram may not be
/// fragmented under `IP_DONTFRAGMENT` ("data should not be fragmented regardless of the local
/// MTU") or `IP_MTU_DISCOVER` `DO` or `PROBE` ("force all outgoing packets to have the DF bit set
/// and an attempt to send packets larger than path MTU will result in an error"); an IPv6 one
/// under `IPV6_DONTFRAG` or `IPV6_MTU_DISCOVER` `DO` or `PROBE`. The sim learns no path MTU below
/// the interface's, so `DO` and `PROBE` both hold to the interface MTU, and it never fragments:
/// any other datagram is delivered whole. The code is the one Microsoft gives a message "larger
/// than the maximum supported by the underlying transport"
/// ([Microsoft Learn: sendto](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-sendto)).
/// A station's datagram crosses no interface of the host and is never refused.
pub(crate) fn check_send(
    shared: &SimShared,
    rec: &SockRec,
    sender: &Sender,
    dest: SocketAddr,
    len: usize,
) -> Result<(), c_int> {
    let Sender::Host(path) = sender else {
        return Ok(());
    };
    let frag = rec.state().frag;
    let v4 = match dest {
        SocketAddr::V4(_) => true,
        SocketAddr::V6(v6) => v6.ip().to_ipv4_mapped().is_some(),
    };
    let no_frag = |flag: bool, mode: u8| flag || mode == PMTUDISC_DO || mode == PMTUDISC_PROBE;
    let (keep_whole, headers) = if v4 {
        (no_frag(frag.dontfrag, frag.pmtudisc), 8 + 20)
    } else {
        (no_frag(frag.dontfrag6, frag.pmtudisc6), 8 + 40)
    };
    if !keep_whole {
        return Ok(());
    }
    let Some(mtu) = shared.nic(&path.name).map(|nic| nic.spec.mtu as usize) else {
        return Ok(());
    };
    if len.saturating_add(headers) > mtu {
        return Err(WSAEMSGSIZE);
    }
    Ok(())
}

/// Whether a datagram to `dest` is IPv4, a v4-mapped address on an IPv6 socket included.
fn v4(dest: SocketAddr) -> bool {
    match dest {
        SocketAddr::V4(_) => true,
        SocketAddr::V6(v6) => v6.ip().to_ipv4_mapped().is_some(),
    }
}

/// The largest UDP payload to `dest`: 65507 bytes for IPv4 and 65527 for IPv6, what a 16-bit IP
/// or UDP length leaves. A larger datagram fails `WSAEMSGSIZE` (measured for IPv4).
pub(crate) fn max_payload(dest: SocketAddr) -> usize {
    if v4(dest) { 65507 } else { 65527 }
}

/// The receive option or UDP offload size `(level, name)` names in `win`.
enum Anc<'a> {
    Flag(&'a mut bool),
    Size(&'a mut u32),
}

fn anc(win: &mut WinSock, level: c_int, name: c_int) -> Option<Anc<'_>> {
    let recv = match level {
        IPPROTO_IP => &mut win.recv4,
        IPPROTO_IPV6 => &mut win.recv6,
        IPPROTO_UDP => {
            return match name {
                UDP_SEND_MSG_SIZE => Some(Anc::Size(&mut win.uso)),
                UDP_COALESCED => Some(Anc::Size(&mut win.uro)),
                _ => None,
            };
        }
        _ => return None,
    };
    Some(Anc::Flag(match name {
        PKTINFO => &mut recv.pktinfo,
        ECN => &mut recv.ecn,
        HOPLIMIT => &mut recv.ttl,
        RECVTOS => &mut recv.tos,
        _ => return None,
    }))
}

/// `setsockopt` of a receive option — `IP_PKTINFO`, `IP_RECVECN`, `IP_RECVTTL`, `IP_RECVTOS` and
/// their `IPPROTO_IPV6` counterparts, flags read back as 0 or 1 — or a UDP offload size,
/// `UDP_SEND_MSG_SIZE` or `UDP_RECV_MAX_COALESCED_SIZE`, a `DWORD` kept as given whatever its
/// value; `None` for any other option. A value shorter than a `DWORD` is `WSAEFAULT`, and a longer
/// one is read for its first four bytes. Measured on Windows 11 build 26200.9457
/// (`cmsg_win_os_truth`).
///
/// # Safety
/// `val` is null or points to `len` readable bytes.
pub(crate) unsafe fn set_anc(
    rec: &SockRec,
    level: c_int,
    name: c_int,
    val: *const u8,
    len: u32,
) -> Option<Result<(), c_int>> {
    let mut state = rec.state();
    let option = anc(&mut state.win, level, name)?;
    if val.is_null() || (len as usize) < size_of::<u32>() {
        return Some(Err(WSAEFAULT));
    }
    let v = unsafe { val.cast::<u32>().read_unaligned() };
    match option {
        Anc::Flag(on) => *on = v != 0,
        Anc::Size(size) => *size = v,
    }
    Some(Ok(()))
}

/// `getsockopt` of an option [`set_anc`] keeps; `None` for any other. A buffer shorter than a
/// `DWORD` is `WSAEFAULT` (measured).
pub(crate) fn get_anc(rec: &SockRec, level: c_int, name: c_int) -> Option<u32> {
    match anc(&mut rec.state().win, level, name)? {
        Anc::Flag(on) => Some(u32::from(*on)),
        Anc::Size(size) => Some(*size),
    }
}

/// What one send asks of its datagram: the socket's options, then what the control messages of a
/// `WSASendMsg` override.
pub(crate) struct SendCtl {
    /// The TOS byte or traffic class, ECN bits included.
    tos: u8,
    /// The TTL or hop limit.
    ttl: u8,
    /// The source address `IP_PKTINFO`/`IPV6_PKTINFO` chose.
    pub(crate) src: Option<IpAddr>,
    /// `UDP_SEND_MSG_SIZE`, the message's or else the socket's.
    seg: u32,
    /// `SO_TIMESTAMP_ID`.
    pub(crate) tx_id: Option<u32>,
}

/// The `int` value of option `(level, name)` as `rec` keeps it, if set.
fn kept(rec: &SockRec, level: c_int, name: c_int) -> Option<c_int> {
    let bytes = rec.ignored_value(level, name)?;
    Some(c_int::from_ne_bytes(bytes.get(..4)?.try_into().ok()?))
}

/// The `int` a control message carries in its first four bytes; `WSAEINVAL` when it holds fewer.
fn int(data: &[u8]) -> Result<c_int, c_int> {
    let bytes = data.get(..4).ok_or(WSAEINVAL)?;
    Ok(c_int::from_ne_bytes(bytes.try_into().unwrap()))
}

/// What a send from `rec` to `dest` asks, its control messages `msgs` (level, type, data) taken as
/// Windows 11 build 26200.9457 takes them (measured by `cmsg_win_os_truth`):
///
/// - The datagram starts with the socket's `IP_TOS`/`IPV6_TCLASS` and its `IP_TTL` (or
///   `IP_MULTICAST_TTL` toward a group), Windows' defaults until set.
/// - Messages apply at the level of `dest`'s family, `IPPROTO_IP` for IPv4 (a v4-mapped address
///   included) and `IPPROTO_IPV6` for IPv6, in order, a later one overriding an earlier: `IP_ECN`
///   sets the two ECN bits (0 to 2; CE, 3, is refused), `IP_TOS`/`IPV6_TCLASS` the whole byte
///   (unless its ECN bits are CE), `IP_HOPLIMIT`/`IPV6_HOPLIMIT` the TTL (0 to 255); each is an
///   `int`, refused when shorter and read for its first four bytes when longer.
/// - `IP_PKTINFO`/`IPV6_PKTINFO` is ignored, however short, on a socket bound to an address; on
///   one bound to the wildcard or unbound it chooses the source address, which must be one the
///   host holds (not merely in 127/8), and an interface index that, unless 0, must exist. An
///   unspecified address leaves the route's source.
/// - `UDP_SEND_MSG_SIZE` gives the send's segment size (0 sends it whole) and `SO_TIMESTAMP_ID`
///   tags it for a transmit stamp; each must be exactly a `DWORD`.
/// - Anything else — the other family's level, `IP_TTL`, an unknown type, level or value — is
///   `WSAEINVAL`.
pub(crate) fn send_ctl(
    shared: &SimShared,
    rec: &SockRec,
    dest: SocketAddr,
    msgs: &[(c_int, c_int, Vec<u8>)],
) -> Result<SendCtl, c_int> {
    let ipv4 = v4(dest);
    let (level, tos_type) = if ipv4 {
        (IPPROTO_IP, IP_TOS)
    } else {
        (IPPROTO_IPV6, IPV6_TCLASS)
    };
    let ttl = if dest.ip().is_multicast() {
        kept(rec, level, MULTICAST_TTL)
    } else {
        kept(rec, IPPROTO_IP, IP_TTL)
    };
    let mut ctl = SendCtl {
        tos: kept(rec, level, tos_type).unwrap_or(0) as u8,
        ttl: ttl.map_or(crate::ancillary::Header::plain(dest.ip()).ttl, |t| t as u8),
        src: None,
        seg: rec.state().win.uso,
        tx_id: None,
    };
    let bound = rec.state().local.is_some_and(|l| !l.ip().is_unspecified());
    for (msg_level, ty, data) in msgs {
        match (*msg_level, *ty) {
            (l, ECN) if l == level => match int(data)? {
                ecn @ 0..=2 => ctl.tos = (ctl.tos & !3) | ecn as u8,
                _ => return Err(WSAEINVAL),
            },
            (l, t) if l == level && t == tos_type => match int(data)? {
                tos @ 0..=255 if tos & 3 != 3 => ctl.tos = tos as u8,
                _ => return Err(WSAEINVAL),
            },
            (l, HOPLIMIT) if l == level => match int(data)? {
                ttl @ 0..=255 => ctl.ttl = ttl as u8,
                _ => return Err(WSAEINVAL),
            },
            (l, PKTINFO) if l == level => {
                if !bound {
                    ctl.src = pktinfo(shared, ipv4, data)?;
                }
            }
            (IPPROTO_UDP, UDP_SEND_MSG_SIZE) if data.len() == 4 => {
                ctl.seg = u32::from_ne_bytes(data[..4].try_into().unwrap());
            }
            (SOL_SOCKET, SO_TIMESTAMP_ID) if data.len() == 4 => {
                ctl.tx_id = Some(u32::from_ne_bytes(data[..4].try_into().unwrap()));
            }
            _ => return Err(WSAEINVAL),
        }
    }
    Ok(ctl)
}

/// The source address an `IN_PKTINFO` (`ipv4`) or `IN6_PKTINFO` chooses for a wildcard-bound
/// socket; see [`send_ctl`].
fn pktinfo(shared: &SimShared, ipv4: bool, data: &[u8]) -> Result<Option<IpAddr>, c_int> {
    let (addr, index): (IpAddr, &[u8]) = if ipv4 {
        let addr: [u8; 4] = data.get(..4).ok_or(WSAEINVAL)?.try_into().unwrap();
        (
            Ipv4Addr::from(addr).into(),
            data.get(4..8).ok_or(WSAEINVAL)?,
        )
    } else {
        let addr: [u8; 16] = data.get(..16).ok_or(WSAEINVAL)?.try_into().unwrap();
        (
            Ipv6Addr::from(addr).into(),
            data.get(16..20).ok_or(WSAEINVAL)?,
        )
    };
    let index = u32::from_ne_bytes(index.try_into().unwrap());
    let topo = shared.topo();
    if index != 0 && topo.name_of(index).is_none() {
        return Err(WSAEINVAL);
    }
    if addr.is_unspecified() {
        return Ok(None);
    }
    if !topo.holds(addr) {
        return Err(WSAEINVAL);
    }
    Ok(Some(addr))
}

/// The header a datagram to `dest` sent under `ctl` carries; one to a v4-mapped address is an
/// IPv4 datagram on the wire.
pub(crate) fn header(ctl: &SendCtl, dest: SocketAddr) -> crate::ancillary::Header {
    let dst = match dest.ip() {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    };
    crate::ancillary::Header {
        tos: ctl.tos,
        ttl: ctl.ttl,
        ..crate::ancillary::Header::plain(dst)
    }
}

/// The segment size a send of `len` bytes to `dest` under `ctl` is cut into, 0 for one datagram
/// (no `UDP_SEND_MSG_SIZE`, or one no smaller than `len`). A segment size larger than
/// [`max_payload`] is `WSAEINVAL`, whether a control message or the socket option gave it; a
/// datagram sent whole that is larger is `WSAEMSGSIZE`. The segmented send itself has no limit:
/// 200000 bytes went out on the measured host.
pub(crate) fn segment(ctl: &SendCtl, dest: SocketAddr, len: usize) -> Result<u16, c_int> {
    let max = max_payload(dest);
    let seg = ctl.seg as usize;
    if seg > max {
        return Err(WSAEINVAL);
    }
    if seg != 0 && len > seg {
        return Ok(seg as u16);
    }
    if len > max {
        return Err(WSAEMSGSIZE);
    }
    Ok(0)
}

/// How a send of `len` bytes cut into `seg`-byte segments reads at socket `rec` (`None` for a
/// tester's endpoint) when it reaches it through loopback: the lengths of the datagrams it is
/// read as. A socket without `UDP_RECV_MAX_COALESCED_SIZE` reads each segment. For one with it,
/// Windows first takes the send in pieces of as many segments as fit [`max_payload`], and reads
/// each piece as datagrams of as many segments as fit that size, the last short segment counting
/// as whole (measured on Windows 11 build 26200.9457 with sizes from 1 to 2^31-1).
pub(crate) fn coalesce(rec: Option<&SockRec>, seg: usize, len: usize, max: usize) -> Vec<usize> {
    let limit = rec.map_or(0, |r| r.state().win.uro as usize);
    let per_read = (limit / seg).max(1) * seg;
    let mut out = Vec::new();
    let mut at = 0;
    while at < len {
        let piece = if len - at <= max {
            len - at
        } else {
            (max / seg) * seg
        };
        out.extend(
            (0..piece)
                .step_by(per_read)
                .map(|from| per_read.min(piece - from)),
        );
        at += piece;
    }
    out
}

/// `SO_TIMESTAMP` (`mstcpip.h`, 0x300A), the control message of a receive stamp.
const SO_TIMESTAMP: c_int = 0x300A;

/// The control messages `WSARecvMsg` returns `rec` with a datagram of header `h` that arrived at
/// monotonic time `arrived`, in the order Windows 11 build 26200.9457 writes them (measured by
/// `cmsg_win_os_truth`), each when asked for: for an IPv4 datagram `IP_PKTINFO` (an `IN_PKTINFO`,
/// the destination address and the receiving interface's index), `IP_ECN`, `IP_TTL` (asked for
/// with `IP_RECVTTL`) and `IP_TOS` (asked for with `IP_RECVTOS`), `int`s; for an IPv6 one
/// `IPV6_PKTINFO` (an `IN6_PKTINFO`), `IPV6_ECN`, `IPV6_HOPLIMIT` and `IPV6_TCLASS`; then the
/// receive stamp, `SO_TIMESTAMP`; then, for a datagram coalesced from segments,
/// `UDP_COALESCED_INFO` with the segment size as a `DWORD`.
pub(crate) fn rx_cmsgs(
    rec: &SockRec,
    h: &crate::ancillary::Header,
    arrived: Duration,
) -> Vec<(c_int, c_int, Vec<u8>)> {
    let mut out = Vec::new();
    {
        let state = rec.state();
        let (level, recv, tos_type, ttl_type) = match h.dst {
            IpAddr::V4(_) => (IPPROTO_IP, &state.win.recv4, IP_TOS, IP_TTL),
            IpAddr::V6(_) => (IPPROTO_IPV6, &state.win.recv6, IPV6_TCLASS, HOPLIMIT),
        };
        let int = |v: u8| c_int::from(v).to_ne_bytes().to_vec();
        if recv.pktinfo {
            let mut info = match h.dst {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets().to_vec(),
            };
            info.extend(h.ifindex.to_ne_bytes());
            out.push((level, PKTINFO, info));
        }
        if recv.ecn {
            out.push((level, ECN, int(h.tos & 3)));
        }
        if recv.ttl {
            out.push((level, ttl_type, int(h.ttl)));
        }
        if recv.tos {
            out.push((level, tos_type, int(h.tos)));
        }
    }
    if let Some(stamp) = rx_stamp(rec, arrived) {
        out.push((SOL_SOCKET, SO_TIMESTAMP, stamp.to_ne_bytes().to_vec()));
    }
    if h.gso != 0 {
        out.push((
            IPPROTO_UDP,
            UDP_COALESCED,
            u32::from(h.gso).to_ne_bytes().to_vec(),
        ));
    }
    out
}

/// `TIMESTAMPING_FLAG_RX` (`mstcpip.h`).
const TIMESTAMPING_FLAG_RX: u32 = 1;
/// `TIMESTAMPING_FLAG_TX` (`mstcpip.h`).
const TIMESTAMPING_FLAG_TX: u32 = 2;
/// `sizeof(TIMESTAMPING_CONFIG)`: a `ULONG` of flags and a `USHORT` buffer count, padded to 8
/// ([Microsoft Learn: TIMESTAMPING_CONFIG](https://learn.microsoft.com/en-us/windows/win32/api/mstcpip/ns-mstcpip-timestamping_config)).
const TIMESTAMPING_CONFIG_LEN: usize = 8;

/// `SIO_TIMESTAMPING` on datagram socket `rec`: the `TIMESTAMPING_CONFIG` at `input` turns
/// receive and transmit stamps on or off and sets how many transmit stamps wait to be taken. A
/// short input is `WSAEFAULT`; flags other than `RX` and `TX` are `WSAEINVAL` (snare's choice;
/// the pages name no code). Shrinking the buffer drops the newest stamps beyond it; turning
/// transmit stamps off drops them all.
///
/// # Safety
/// `input` is null or points to `input_len` readable bytes.
pub(crate) unsafe fn configure_stamping(
    rec: &SockRec,
    input: *const u8,
    input_len: u32,
) -> Result<(), c_int> {
    if input.is_null() || (input_len as usize) < TIMESTAMPING_CONFIG_LEN {
        return Err(WSAEFAULT);
    }
    let flags = unsafe { input.cast::<u32>().read_unaligned() };
    let buffered = unsafe { input.add(4).cast::<u16>().read_unaligned() };
    if flags & !(TIMESTAMPING_FLAG_RX | TIMESTAMPING_FLAG_TX) != 0 {
        return Err(WSAEINVAL);
    }
    let mut state = rec.state();
    let stamping = &mut state.win.stamping;
    stamping.rx = flags & TIMESTAMPING_FLAG_RX != 0;
    stamping.tx = (flags & TIMESTAMPING_FLAG_TX != 0).then_some(usize::from(buffered));
    let keep = stamping.tx.unwrap_or(0);
    stamping.ready.truncate(keep);
    Ok(())
}

/// `SIO_GET_TX_TIMESTAMP` on `rec` for the `UINT32` id at `input`: the stamp, as a `UINT64`
/// written to `output`, removed from the socket's buffer. `WSAEOPNOTSUPP` while transmit stamps
/// are off (measured on Windows 11, tests/timestamps_win.rs
/// `tx_timestamp_before_configuring_on_windows`), `WSAEWOULDBLOCK` when no stamp of that id waits
/// ([Microsoft Learn: Winsock IOCTLs](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls#sio_get_tx_timestamp)),
/// and `WSAEFAULT` for a short input or output.
///
/// # Safety
/// `input`/`output` are null or hold their lengths; `returned` is null or writable.
pub(crate) unsafe fn take_tx_stamp(
    rec: &SockRec,
    input: *const u8,
    input_len: u32,
    output: *mut u8,
    output_len: u32,
    returned: *mut u32,
) -> Result<(), c_int> {
    let mut state = rec.state();
    let stamping = &mut state.win.stamping;
    if stamping.tx.is_none() {
        return Err(WSAEOPNOTSUPP);
    }
    if input.is_null() || (input_len as usize) < size_of::<u32>() {
        return Err(WSAEFAULT);
    }
    if output.is_null() || (output_len as usize) < size_of::<u64>() {
        return Err(WSAEFAULT);
    }
    let id = unsafe { input.cast::<u32>().read_unaligned() };
    let at = stamping
        .ready
        .iter()
        .position(|&(tag, _)| tag == id)
        .ok_or(WSAEWOULDBLOCK)?;
    let (_, stamp) = stamping.ready.remove(at).expect("position is in range");
    unsafe {
        output.cast::<u64>().write_unaligned(stamp);
        if !returned.is_null() {
            returned.write_unaligned(size_of::<u64>() as u32);
        }
    }
    Ok(())
}

/// A datagram tagged `SO_TIMESTAMP_ID` `id` left `rec` at monotonic time `sent`: its transmit
/// stamp is buffered while transmit stamps are on and the buffer has room, else discarded ("If a
/// transmit timestamp is generated while the buffer is full, the new timestamp is discarded",
/// Microsoft Learn: Winsock timestamping). The stamp is available as soon as the send returns,
/// which the page guarantees.
pub(crate) fn note_tx_stamp(rec: &SockRec, id: u32, sent: Duration) {
    let mut state = rec.state();
    let stamping = &mut state.win.stamping;
    if let Some(room) = stamping.tx
        && stamping.ready.len() < room
    {
        stamping
            .ready
            .push_back((id, snare_interpose::performance_count(sent)));
    }
}

/// The `SO_TIMESTAMP` value of a datagram that reached `rec` at monotonic time `arrived`, when
/// receive stamps are on: a software stamp, a `QueryPerformanceCounter` value on the counter the
/// code under test reads.
pub(crate) fn rx_stamp(rec: &SockRec, arrived: Duration) -> Option<u64> {
    rec.state()
        .win
        .stamping
        .rx
        .then(|| snare_interpose::performance_count(arrived))
}

/// `getsockopt` of `SO_PROTOCOL_INFOW` or `SO_PROTOCOL_INFOA`: the host's Winsock catalog entry
/// for the socket's family, type and protocol (`IPPROTO_UDP` or `IPPROTO_TCP` whatever `socket`
/// was given), the first `WSAEnumProtocols` lists as `WSASocket` picks it. Winsock returns the
/// entry unchanged. The wide form stores the structure's size in `*len`; the ANSI form stores it
/// only when the buffer is too short. A buffer shorter than the structure is `WSAEFAULT`.
/// Measured by tests/socket_family.rs.
///
/// # Safety
/// `val`/`len` are the caller's getsockopt buffer.
pub(crate) unsafe fn get_protocol_info(
    kind: Kind,
    name: c_int,
    val: *mut u8,
    len: *mut u32,
) -> Result<(), c_int> {
    use windows_sys::Win32::Networking::WinSock as ws;
    let family = if kind.v6 { ws::AF_INET6 } else { ws::AF_INET } as i32;
    let (ty, protocol) = if kind.stream {
        (ws::SOCK_STREAM, ws::IPPROTO_TCP)
    } else {
        (ws::SOCK_DGRAM, ws::IPPROTO_UDP)
    };
    let entry = if name == SO_PROTOCOL_INFOW {
        catalog_entry(
            ws::WSAEnumProtocolsW,
            protocol,
            |e: &ws::WSAPROTOCOL_INFOW| (e.iAddressFamily, e.iSocketType) == (family, ty),
        )
    } else {
        catalog_entry(
            ws::WSAEnumProtocolsA,
            protocol,
            |e: &ws::WSAPROTOCOL_INFOA| (e.iAddressFamily, e.iSocketType) == (family, ty),
        )
    };
    let size = entry.as_ref().map_or(0, Vec::len);
    if val.is_null() || len.is_null() || (unsafe { *len } as usize) < size {
        if name == SO_PROTOCOL_INFOA && !len.is_null() {
            unsafe { *len = size as u32 };
        }
        return Err(WSAEFAULT);
    }
    let entry = entry.ok_or(WSAENOPROTOOPT)?;
    unsafe {
        std::ptr::copy_nonoverlapping(entry.as_ptr(), val, size);
        if name == SO_PROTOCOL_INFOW {
            *len = size as u32;
        }
    }
    Ok(())
}

/// The bytes of the first entry of the real Winsock catalog of `protocol` that `matches`, read
/// with `enumerate` (`WSAEnumProtocolsW` or `WSAEnumProtocolsA`) outside the sim.
fn catalog_entry<T>(
    enumerate: unsafe extern "system" fn(*const i32, *mut T, *mut u32) -> i32,
    protocol: i32,
    matches: impl Fn(&T) -> bool,
) -> Option<Vec<u8>> {
    use windows_sys::Win32::Networking::WinSock as ws;
    snare_interpose::real(|| unsafe {
        let mut data: ws::WSADATA = std::mem::zeroed();
        if ws::WSAStartup(0x0202, &mut data) != 0 {
            return None;
        }
        let protocols = [protocol, 0];
        let mut bytes = 0u32;
        enumerate(protocols.as_ptr(), std::ptr::null_mut(), &mut bytes);
        let mut entries: Vec<T> = (0..bytes as usize / size_of::<T>() + 1)
            .map(|_| std::mem::zeroed())
            .collect();
        bytes = (entries.len() * size_of::<T>()) as u32;
        let count = enumerate(protocols.as_ptr(), entries.as_mut_ptr(), &mut bytes);
        ws::WSACleanup();
        let entry = entries
            .get(..usize::try_from(count).ok()?)?
            .iter()
            .find(|e| matches(e))?;
        Some(std::slice::from_raw_parts((entry as *const T).cast::<u8>(), size_of::<T>()).to_vec())
    })
}
