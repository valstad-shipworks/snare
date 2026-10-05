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
use std::net::SocketAddr;
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

/// The Windows half of a socket's record: its family and its timestamping.
#[derive(Default)]
pub(crate) struct WinSock {
    /// Created `AF_INET6`.
    pub(crate) v6: bool,
    legacy_frag: bool,
    /// `SIO_TIMESTAMPING` and the transmit stamps waiting for `SIO_GET_TX_TIMESTAMP`.
    pub(crate) stamping: Stamping,
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
use Shape::{Bytes, Dword, Flag, Hops, UpTo};

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
///   (`ws2ipdef.h` `IP_DEFAULT_MULTICAST_TTL`); `IP_TOS` and `IPV6_TCLASS` to 0. Harmless: the
///   sim's links count no hops and carry no QoS. The pages refuse IPv6 hop limits above 255; the
///   IPv4 ones are held to the same range, an assumption.
/// - `IP_MULTICAST_LOOP` and `IPV6_MULTICAST_LOOP` default to on (`IP_DEFAULT_MULTICAST_LOOP`;
///   the IPPROTO_IP page: "By default, IP_MULTICAST_LOOP is enabled"), `IPV6_V6ONLY` to on (the
///   IPPROTO_IPV6 page: "the default on Windows"), `TCP_BSDURGENT` to on (the IPPROTO_TCP page),
///   `IP_USER_MTU`/`IPV6_USER_MTU` to `IP_UNSPECIFIED_USER_MTU` (`MAXULONG`), and
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
    opt(SOL_SOCKET, !0x0004, Unmodelled, Flag, 0),
    get_only(SOL_SOCKET, 0x1009, Bytes),
    get_only(SOL_SOCKET, 0x2001, Dword),
    opt(SOL_SOCKET, 0x2002, Unmodelled, Dword, 0),
    get_only(SOL_SOCKET, 0x2003, Dword),
    get_only(SOL_SOCKET, 0x2004, Bytes),
    get_only(SOL_SOCKET, 0x2005, Bytes),
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
    opt(IPPROTO_IP, 3, Harmless, Dword, 0),
    opt(IPPROTO_IP, 4, Harmless, Hops, 128),
    opt(IPPROTO_IP, 10, Harmless, Hops, 1),
    opt(IPPROTO_IP, 11, Unmodelled, Flag, 1),
    set_only(IPPROTO_IP, 13),
    set_only(IPPROTO_IP, 15),
    set_only(IPPROTO_IP, 16),
    set_only(IPPROTO_IP, 17),
    set_only(IPPROTO_IP, 18),
    opt(IPPROTO_IP, 19, Unmodelled, Flag, 0),
    opt(IPPROTO_IP, 21, Unmodelled, Flag, 0),
    opt(IPPROTO_IP, 22, Unmodelled, Flag, 1),
    opt(IPPROTO_IP, 24, Unmodelled, Flag, 0),
    opt(IPPROTO_IP, 28, Unmodelled, Flag, 0),
    set_only(IPPROTO_IP, 29),
    set_only(IPPROTO_IP, 30),
    get_only(IPPROTO_IP, 33, Bytes),
    opt(IPPROTO_IP, 40, Unmodelled, Flag, 0),
    opt(IPPROTO_IP, 47, Unmodelled, Flag, 0),
    opt(IPPROTO_IP, 50, Unmodelled, Flag, 0),
    opt(IPPROTO_IP, 60, Unmodelled, Bytes, 0),
    opt(IPPROTO_IP, 70, Unmodelled, Bytes, 0),
    get_only(IPPROTO_IP, 73, Dword),
    opt(IPPROTO_IP, 76, Unmodelled, Dword, -1),
    opt(IPPROTO_IPV6, 2, Unmodelled, Flag, 0),
    opt(IPPROTO_IPV6, 4, Harmless, Hops, 128),
    opt(IPPROTO_IPV6, 10, Harmless, Hops, 1),
    opt(IPPROTO_IPV6, 11, Unmodelled, Flag, 1),
    set_only(IPPROTO_IPV6, 13),
    opt(IPPROTO_IPV6, 19, Unmodelled, Flag, 0),
    opt(IPPROTO_IPV6, 21, Unmodelled, Flag, 0),
    opt(IPPROTO_IPV6, 23, Unmodelled, Dword, 0),
    opt(IPPROTO_IPV6, 24, Unmodelled, Flag, 0),
    opt(IPPROTO_IPV6, 27, Unmodelled, Flag, 1),
    opt(IPPROTO_IPV6, 28, Unmodelled, Flag, 0),
    set_only(IPPROTO_IPV6, 29),
    set_only(IPPROTO_IPV6, 30),
    get_only(IPPROTO_IPV6, 33, Bytes),
    opt(IPPROTO_IPV6, 39, Harmless, Dword, 0),
    opt(IPPROTO_IPV6, 40, Unmodelled, Flag, 0),
    opt(IPPROTO_IPV6, 47, Unmodelled, Flag, 0),
    opt(IPPROTO_IPV6, 50, Unmodelled, Flag, 0),
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
    opt(IPPROTO_UDP, 2, Unmodelled, Dword, 0),
    opt(IPPROTO_UDP, 3, Unmodelled, Dword, 0),
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
}

/// Protocol-level applicability. Unicast hops and fragmentation options are accepted at the
/// IPv6 level on IPv4 sockets, measured by `winsock_os_truth` and `dontfrag_win` on Windows 11
/// build 26200.9457. Other IPv6-level options on IPv4 sockets retain the unverified `WSAEINVAL`
/// policy. TCP options on datagrams and UDP options on streams fail `WSAENOPROTOOPT`.
pub(crate) fn level_applies(kind: Kind, level: c_int, name: c_int) -> Result<(), c_int> {
    match level {
        IPPROTO_IPV6 if !kind.v6 && !matches!(name, 4 | IPV6_DONTFRAG | MTU_DISCOVER) => {
            Err(WSAEINVAL)
        }
        IPPROTO_TCP if !kind.stream => Err(WSAENOPROTOOPT),
        IPPROTO_UDP if kind.stream => Err(WSAENOPROTOOPT),
        _ => Ok(()),
    }
}

/// `(level, name)`'s entry, if Windows defines it and `win_net` leaves it to this module.
fn lookup(level: c_int, name: c_int) -> Option<&'static Known> {
    KNOWN.iter().find(|k| k.level == level && k.name == name)
}

/// Checks `known` applies to a socket of `kind` in direction `set`.
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
    if set && kind.v6 && known.level == IPPROTO_IP && known.name == 4 {
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
/// setting these options at `IPPROTO_IP`. Measured on Windows 11 build 26200.9457 by
/// `dontfrag_win`'s mode and interaction parity tests. A short value is `WSAEFAULT`.
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
    if level == IPPROTO_IP && state.win.v6 {
        return Some(Err(WSAEINVAL));
    }
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
