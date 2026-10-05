//! An in-memory Winsock fabric behind [`snare_interpose::Net`] for Windows. The code under test
//! uses ordinary `std::net` types; their `ws2_32` socket calls land here and are serviced from
//! process memory. TCP (`SOCK_STREAM`) and UDP (`SOCK_DGRAM`) are both modelled. Handles are minted
//! in the `c_int` range (Winsock `SOCKET` is wider, but the sim's own handles stay small), so the
//! interposer casts between `SOCKET` and `c_int` losslessly for the sockets it owns.
//!
//! The pieces:
//! - [`WinNet`] is the per-sim [`Net`]: its handle table maps each `SOCKET` to a [`Sock`], the
//!   state of that handle. Several handles can share one socket (`dup`, which `try_clone` uses);
//!   they then share its [`SockRec`], connection, queue or connect attempt.
//! - [`Registries`] is the per-sim address book, shared with the testers: which datagram queue is
//!   bound where, which queues joined which multicast group, and which listener answers a connect.
//! - A TCP connection is a [`Conn`], two [`Pipe`]s between its ends; a UDP socket's receive side
//!   is a [`DgramQueue`]. Both carry link latency and loss from the sim's topology and policies.
//! - The npcap (`wpcap.dll`) raw L2 calls are a shared medium of [`PcapHandle`]s per device name.
//!
//! Every [`Net`] method runs under passthrough (`snare_interpose`'s `dispatch_net` enters it), so
//! the locks and waits here are the sim's, invisible to the code under test. The tester-side
//! entry points at the bottom are called from test code directly and enter passthrough themselves
//! with [`snare_interpose::real`].
//!
//! Lock order: the handle table (`WinNet::socks`) before a connect attempt's mutex before the
//! [`Registry`] lock; a [`DgramQueue`]'s, a listener's `pending` and the `pcaps` locks are leaves.
//! No path takes the handle table while holding the registry. Nothing is held across a blocking
//! wait: every wait goes through [`readiness`], whose wakers bump it only after releasing the
//! table, and every call that returns early from a would-block path calls [`would_block`] with no
//! lock held.
//!
//! Where Winsock's behaviour differs from the BSD sockets the unix fabric models, the Winsock rule
//! is followed and cited at the point it applies.

use std::collections::{HashMap, VecDeque};
use std::ffi::{c_char, c_int};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use snare_interpose::{Net, NetResult};
#[path = "win_iocp.rs"]
mod iocp;

use crate::faults::{ConnectAttempt, Outcome, Syn};
use crate::limits::{Arrival, Buf, RxQueue};
use crate::netif::{Cand, Hop, LinkState, Op, Sender, Wire};
use crate::pcapng::{Dir, TcpTap};
use crate::readiness::{Deadline, readiness};
use crate::scope::SimShared;
use crate::sockets::{
    ErrorOrder, Membership, RxProbe, SockRec, SocketKind, Taker, UnmodelledOption,
};
use crate::stream::{Ends, Pipe, Read, Sent};
use crate::win_sockopt::{self, WSAENOPROTOOPT};

// Winsock error codes (`winsock2.h`, `WSABASEERR` 10000 plus the BSD errno;
// [Microsoft Learn: Windows Sockets Error Codes](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2)).
// The interposer stores the code as the thread's last error (`SetLastError`, read back through
// `WSAGetLastError`) and returns `SOCKET_ERROR`.
/// A null, short or malformed pointer argument (an address, option value or `fd_set`).
const WSAEFAULT: c_int = 10014;
/// An argument or state the call rejects: `bind` on a bound socket, `listen` on an unbound one,
/// `accept` before `listen`, a bad `shutdown` `how`, an unknown interface index.
const WSAEINVAL: c_int = 10022;
/// The operation does not apply to this socket type (`listen`/`accept` on a datagram socket).
const WSAEOPNOTSUPP: c_int = 10045;
/// The socket is already connected.
const WSAEISCONN: c_int = 10056;
/// A nonblocking call with nothing to do yet, or a blocking wait the sim had to abandon.
const WSAEWOULDBLOCK: c_int = 10035;
/// The socket is not connected.
const WSAENOTCONN: c_int = 10057;
/// A TCP bind over an equal address that only one of the two sockets set `SO_REUSEADDR` on.
const WSAEACCES: c_int = 10013;
/// The address is already bound.
const WSAEADDRINUSE: c_int = 10048;
/// `send` on a datagram socket with no default peer. Snare's choice: the `connect` page says
/// `send` on a datagram socket without a default destination fails with `WSAENOTCONN`
/// ([Microsoft Learn: connect](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect)).
const WSAEDESTADDRREQ: c_int = 10039;
/// No listener answered the connect.
const WSAECONNREFUSED: c_int = 10061;
/// A second `connect` while the first is still pending.
const WSAEALREADY: c_int = 10037;
/// A blocking connect that ended without a connection or a recorded error.
const WSAECONNABORTED: c_int = 10053;
/// The handle stopped being a socket the sim knows while a call ran.
const WSAENOTSOCK: c_int = 10038;
/// The peer reset the connection.
const WSAECONNRESET: c_int = 10054;
/// `SO_RCVTIMEO`/`SO_SNDTIMEO` expired.
const WSAETIMEDOUT: c_int = 10060;
/// The direction was shut down.
const WSAESHUTDOWN: c_int = 10058;
/// A datagram longer than the receive buffer, cut to it
/// ([Microsoft Learn: recvfrom](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom)),
/// or one that may not be fragmented and does not fit the egress MTU.
const WSAEMSGSIZE: c_int = win_sockopt::WSAEMSGSIZE;

// The message flags of the receive and send calls (`winsock2.h`, `ws2def.h`; their meanings in
// [Microsoft Learn: recv](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv),
// [WSARecv](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsarecv) and
// [LPFN_WSARECVMSG](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_wsarecvmsg)).
/// `MSG_OOB`: out-of-band data, which the sim never carries.
const MSG_OOB: c_int = 0x1;
/// `MSG_PEEK`: copy the data without taking it from the queue.
const MSG_PEEK: c_int = 0x2;
/// `MSG_DONTROUTE`, a send flag providers may ignore; the sim does.
const MSG_DONTROUTE: c_int = 0x4;
/// `MSG_WAITALL`: a blocking stream receive completes only with the buffer full, the
/// connection closed, or an error.
const MSG_WAITALL: c_int = 0x8;
/// `MSG_PUSH_IMMEDIATE`, a `WSARecv` hint not to hold a partly filled receive; every sim receive
/// completes with what has arrived.
const MSG_PUSH_IMMEDIATE: c_int = 0x20;
/// `MSG_PARTIAL`: on `WSARecv` input, complete with part of a message; the sim delivers whole
/// datagrams, so it changes nothing.
const MSG_PARTIAL: c_int = 0x8000;
/// `WSARecvMsg` output: the datagram was cut to the buffers.
const MSG_TRUNC: u32 = 0x0100;
/// `WSARecvMsg` output: the control data was cut to the control buffer.
const MSG_CTRUNC: u32 = 0x0200;
/// `WSARecvMsg` output: the datagram was sent to a broadcast address.
const MSG_BCAST: u32 = 0x0400;
/// `WSARecvMsg` output: the datagram was sent to a multicast address.
const MSG_MCAST: u32 = 0x0800;
/// `SO_TIMESTAMP` (`mstcpip.h`, 0x300A), the control message of a receive stamp
/// ([Microsoft Learn: Winsock timestamping](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-timestamping)).
const SO_TIMESTAMP: c_int = 0x300A;
/// `SO_TIMESTAMP_ID` (`mstcpip.h`, 0x300B), the control message tagging a datagram for a
/// transmit stamp.
const SO_TIMESTAMP_ID: c_int = 0x300B;

// Winsock address families and socket types (`<winsock2.h>`): AF_INET = 2, AF_INET6 = 23,
// SOCK_STREAM = 1, SOCK_DGRAM = 2. The IPv6 family value differs from unix (10/30).
/// `AF_UNSPEC` (`ws2def.h`).
const AF_UNSPEC: c_int = 0;
/// `AF_INET` (`ws2def.h`).
const AF_INET: c_int = 2;
/// `AF_INET6` (`ws2def.h`).
const AF_INET6: c_int = 23;
/// `SOCK_STREAM` (`winsock2.h`).
const SOCK_STREAM: c_int = 1;
/// `SOCK_DGRAM` (`winsock2.h`).
const SOCK_DGRAM: c_int = 2;
// SOL_SOCKET-level option names and values (`ws2def.h`, `winsock2.h`; semantics in
// [Microsoft Learn: SOL_SOCKET Socket Options](https://learn.microsoft.com/en-us/windows/win32/winsock/sol-socket-socket-options)).
/// `SOL_SOCKET`, the socket-level option level.
const SOL_SOCKET: c_int = 0xffff;
/// `SO_TYPE`: the socket type, read-only.
const SO_TYPE: c_int = 0x1008;
/// `SO_BROADCAST`: a `DWORD` boolean that lets a datagram socket send to broadcast addresses.
const SO_BROADCAST: c_int = 0x0020;
// SO_RCVTIMEO/SO_SNDTIMEO take a DWORD of milliseconds, 0 meaning no timeout (SOL_SOCKET Socket
// Options, above).
/// `SO_RCVTIMEO`: the timeout of blocking receive calls only.
const SO_RCVTIMEO: c_int = 0x1006;
/// `SO_SNDTIMEO`: the timeout of blocking send calls.
const SO_SNDTIMEO: c_int = 0x1005;
/// `SO_ERROR`: the socket's pending error, read-only.
const SO_ERROR: c_int = 0x1007;
/// `SO_REUSEADDR`: a `DWORD` boolean that lets a bind share an address and port in use.
const SO_REUSEADDR: c_int = 0x0004;
/// `SO_ACCEPTCONN`: whether the socket is listening, read-only.
const SO_ACCEPTCONN: c_int = 0x0002;
/// `SO_LINGER`: a `struct linger` governing `closesocket` with unsent data.
const SO_LINGER: c_int = 0x0080;
/// `<winsock2.h>`: `(int)(~SO_LINGER)`.
const SO_DONTLINGER: c_int = !SO_LINGER;
/// `<mstcpip.h>`: `_WSAIOW(IOC_VENDOR, 12)`, a `BOOL` that turns ICMP port unreachable resets on a
/// UDP socket on or off
/// ([Microsoft Learn: Winsock IOCTLs](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls),
/// SIO_UDP_CONNRESET).
const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
/// `SO_SNDBUF`: a `DWORD` byte count.
const SO_SNDBUF: c_int = 0x1001;
/// `SO_RCVBUF`: a `DWORD` byte count.
const SO_RCVBUF: c_int = 0x1002;
// winsock2.h: FIONREAD = _IOR('f', 127, u_long).
/// `FIONREAD`: the bytes available to read; on a datagram socket all queued bytes, not the size of
/// the first datagram
/// ([Microsoft Learn: Winsock IOCTLs](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls)).
const FIONREAD: u32 = 0x4004_667f;
// winsock2.h: shutdown's `how`.
/// Shut down receives.
const SD_RECEIVE: c_int = 0;
/// Shut down sends.
const SD_SEND: c_int = 1;
/// Shut down both directions.
const SD_BOTH: c_int = 2;
/// `IPPROTO_IP`, the IPv4 option level (`ws2def.h`).
const IPPROTO_IP: c_int = 0;
/// `IPPROTO_IPV6`, the IPv6 option level (`ws2def.h`).
const IPPROTO_IPV6: c_int = 41;
/// `IP_ADD_MEMBERSHIP` (`ws2ipdef.h`), taking an `ip_mreq`.
const IP_ADD_MEMBERSHIP: c_int = 12;
/// `IPV6_ADD_MEMBERSHIP`, the same value as `IPV6_JOIN_GROUP` (`ws2ipdef.h`), taking an
/// `ipv6_mreq`.
const IPV6_ADD_MEMBERSHIP: c_int = 12;
// The option values are `ws2ipdef.h`'s. Set, IP_UNICAST_IF takes an IPv4 interface index in
// network byte order, IPV6_UNICAST_IF one in host order; IP_MULTICAST_IF an IPv4 address (or an
// index in 0.0.0.0/8), IPV6_MULTICAST_IF an index. Read back, all four return the index in host
// byte order (the two pages cited below).
/// `IP_UNICAST_IF`
/// ([Microsoft Learn: IPPROTO_IP socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options)).
const IP_UNICAST_IF: c_int = 31;
/// `IPV6_UNICAST_IF`
/// ([Microsoft Learn: IPPROTO_IPV6 socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options)).
const IPV6_UNICAST_IF: c_int = 31;
/// `IP_MULTICAST_IF`.
const IP_MULTICAST_IF: c_int = 9;
/// `IPV6_MULTICAST_IF`.
const IPV6_MULTICAST_IF: c_int = 9;
// ioctlsocket command: FIONBIO sets non-blocking mode (`<winsock2.h>`).
/// `FIONBIO` = `_IOW('f', 126, u_long)`: a nonzero `u_long` makes the socket nonblocking. Bit 31
/// (`IOC_IN`) is set, which matters in `WinNet`'s `ioctl`.
const FIONBIO: u64 = 0x8004667e;
/// `SIOCATMARK` = `_IOR('s', 7, u_long)` (`winsock2.h`): whether all out-of-band data has been
/// read.
const SIOCATMARK: u32 = 0x4004_7307;
// The WSAIoctl codes the sim serves (`ws2def.h`, `mswsock.h`, `mstcpip.h`; Microsoft Learn: Winsock
// IOCTLs). `_WSAIOR(IOC_WS2, n)` is 0x4800_0000 | n, `_WSAIOW(IOC_VENDOR, n)` 0x9800_0000 | n.
/// `SIO_BASE_HANDLE`, `_WSAIOR(IOC_WS2, 34)`: the base provider's handle of a socket.
const SIO_BASE_HANDLE: u32 = 0x4800_0022;
/// `SIO_BSP_HANDLE`, `_WSAIOR(IOC_WS2, 27)`.
const SIO_BSP_HANDLE: u32 = 0x4800_001B;
/// `SIO_BSP_HANDLE_SELECT`, `_WSAIOR(IOC_WS2, 28)`.
const SIO_BSP_HANDLE_SELECT: u32 = 0x4800_001C;
/// `SIO_BSP_HANDLE_POLL`, `_WSAIOR(IOC_WS2, 29)`.
const SIO_BSP_HANDLE_POLL: u32 = 0x4800_001D;
/// `SIO_KEEPALIVE_VALS`, `_WSAIOW(IOC_VENDOR, 4)`.
const SIO_KEEPALIVE_VALS: u32 = 0x9800_0004;
/// `SIO_UDP_NETRESET`, `_WSAIOW(IOC_VENDOR, 15)`.
const SIO_UDP_NETRESET: u32 = 0x9800_000F;
/// `SIO_LOOPBACK_FAST_PATH`, `_WSAIOW(IOC_VENDOR, 16)`.
const SIO_LOOPBACK_FAST_PATH: u32 = 0x9800_0010;
/// `SIO_CPU_AFFINITY`, `_WSAIOW(IOC_VENDOR, 21)`.
const SIO_CPU_AFFINITY: u32 = 0x9800_0015;
/// `SIO_GET_TX_TIMESTAMP`, `_WSAIOW(IOC_VENDOR, 234)`.
const SIO_GET_TX_TIMESTAMP: u32 = 0x9800_00EA;
/// `SIO_TIMESTAMPING`, `_WSAIOW(IOC_VENDOR, 235)`.
const SIO_TIMESTAMPING: u32 = 0x9800_00EB;

// WSAPoll event bits (`<winsock2.h>`): POLLRDNORM = normal data readable, POLLWRNORM = writable.
// `std`/code commonly request POLLIN (= POLLRDNORM | POLLRDBAND) and POLLOUT (= POLLWRNORM).
// ([Microsoft Learn: WSAPoll](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsapoll).)
/// Normal data can be read (or, on a listener, a connection accepted) without blocking.
const POLLRDNORM: i16 = 0x0100;
/// Out-of-band data can be read; never reported by the sim.
const POLLRDBAND: i16 = 0x0200;
/// `POLLRDNORM | POLLRDBAND`.
const POLLIN: i16 = POLLRDNORM | POLLRDBAND;
/// Normal data can be written without blocking.
const POLLWRNORM: i16 = 0x0010;
/// The same value as `POLLWRNORM`.
const POLLOUT: i16 = POLLWRNORM;
/// An error is pending; reported whether requested or not.
const POLLERR: i16 = 0x0001;
/// The connection was disconnected or aborted.
const POLLHUP: i16 = 0x0002;
/// `IPPROTO_TCP`, the TCP option level (`ws2def.h`).
const IPPROTO_TCP: c_int = 6;

/// `WSAPOLLFD` (`<winsock2.h>`): a `SOCKET` with requested `events` and returned `revents`
/// ([Microsoft Learn: WSAPOLLFD](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-wsapollfd)).
#[repr(C)]
#[derive(Clone, Copy)]
struct WsaPollfd {
    fd: usize,
    events: i16,
    revents: i16,
}

/// The call handled, returning `n`.
fn ok(n: i64) -> Option<NetResult> {
    Some(NetResult::Ok(n))
}

/// A non-blocking call that found nothing to do: `WSAEWOULDBLOCK`, charged the call latency so a
/// caller busy-polling it still lets a discrete virtual clock move (see
/// `snare_interpose::charge_latency`). Called with no `WinNet` lock held.
fn would_block() -> Option<NetResult> {
    snare_interpose::charge_latency();
    err(WSAEWOULDBLOCK)
}

/// The call handled, failing with Winsock error `code`.
fn err(code: c_int) -> Option<NetResult> {
    Some(NetResult::Err(code))
}

/// `result` as a handled call.
fn done(result: Result<i64, c_int>) -> Option<NetResult> {
    Some(match result {
        Ok(n) => NetResult::Ok(n),
        Err(code) => NetResult::Err(code),
    })
}

/// The sim's monotonic time now, without ticking, or real elapsed time on its timeline.
fn monotonic(shared: &SimShared) -> Duration {
    shared.clock.as_ref().map_or_else(
        || shared.stamp(),
        |clock| Duration::from_nanos(clock.monotonic()),
    )
}

/// One end of a [`Conn`]: `A` the connecting socket, `B` the accepting one (a socket of the host
/// or a tester's listener).
#[derive(Clone, Copy, PartialEq)]
enum End {
    A,
    B,
}

/// A bidirectional TCP connection. The connecting side is `A`, the accepting side `B`.
pub(crate) struct Conn {
    /// The bytes `A` writes and `B` reads.
    a_to_b: Arc<Pipe>,
    /// The bytes `B` writes and `A` reads.
    b_to_a: Arc<Pipe>,
    /// `A`'s address.
    pub(crate) client: SocketAddr,
    /// `B`'s address, the one `A` connected to.
    server: SocketAddr,
    /// The sim's registries, for the link policy (latency) on this connection's bytes.
    regs: Arc<Registries>,
    /// The interface the connection crosses, if it leaves the host.
    hop: Option<Hop>,
    /// The pcapng capture of this connection's segments, when capture is on.
    tap: Option<TcpTap>,
}

impl Conn {
    /// Writes what the window has room for from `end`; `None` once that direction is closed.
    ///
    /// The bytes become readable after the link delay: the TCP link policy between the two
    /// addresses plus the interface hop's own delay. What was written is counted on the hop's
    /// interface.
    fn write(&self, end: End, bytes: &[u8]) -> Option<usize> {
        let shared = &self.regs.shared;
        let delay = shared.policies.tcp_delay(self.server, self.client)
            + shared.hop_delay(self.hop.as_ref());
        let n = self
            .write_pipe(end)
            .write_after(bytes, delay, |sent, arrival, _| {
                if let Some(tap) = &self.tap {
                    tap.data(end.index(), sent, arrival);
                }
            })?;
        let pipe = self.write_pipe(end);
        shared.account_tcp(
            self.hop.as_ref(),
            end == End::A,
            n,
            self.server.ip(),
            (pipe.has_writer(), pipe.has_reader()),
        );
        Some(n)
    }

    /// The pipe `end` reads from.
    fn read_pipe(&self, end: End) -> &Pipe {
        match end {
            End::A => &self.b_to_a,
            End::B => &self.a_to_b,
        }
    }

    /// The pipe `end` writes to.
    fn write_pipe(&self, end: End) -> &Pipe {
        match end {
            End::A => &self.a_to_b,
            End::B => &self.b_to_a,
        }
    }

    /// Closes `end`'s sending direction: the peer reads end of stream once the bytes before it have
    /// arrived (a FIN).
    fn close(&self, end: End) {
        self.write_pipe(end).close(|arrival| {
            if let Some(tap) = &self.tap {
                tap.fin(end.index(), arrival);
            }
        });
    }

    /// `end`'s own address.
    fn local(&self, end: End) -> SocketAddr {
        match end {
            End::A => self.client,
            End::B => self.server,
        }
    }

    /// The address of the other end.
    fn peer(&self, end: End) -> SocketAddr {
        match end {
            End::A => self.server,
            End::B => self.client,
        }
    }
}

/// A listening socket's queue of connections waiting to be accepted.
#[derive(Default)]
pub(crate) struct ListenerState {
    rec: Option<std::sync::Weak<SockRec>>,
    /// Connections the SYN exchange completed, oldest first, not yet accepted. A connect pushes
    /// here as it succeeds, so the connecting side is connected before `accept` runs, as with a
    /// kernel's accept queue.
    pending: Mutex<VecDeque<Arc<Conn>>>,
    capacity: AtomicUsize,
    occupied: AtomicUsize,
    /// A tester's: a station at its address rather than a socket of the host.
    tester: bool,
}

impl Conn {
    /// Aborts the connection with a reset sent from `from`.
    fn reset(&self, from: End) {
        if !self.a_to_b.is_reset() {
            self.regs.shared.count_reset(
                self.server.ip(),
                self.write_pipe(from).has_writer(),
                [
                    self.a_to_b.established_reader(),
                    self.b_to_a.established_reader(),
                ],
            );
        }
        if let Some(tap) = &self.tap {
            tap.rst(from.index());
        }
        self.a_to_b.reset();
        self.b_to_a.reset();
    }
}

impl End {
    /// The end's index in the pcapng tap's two-element tables.
    fn index(self) -> usize {
        match self {
            End::A => 0,
            End::B => 1,
        }
    }
}

/// The peer side of a listening address, as a tester holds it.
pub(crate) type Listener = ListenerState;

/// One received datagram and the source a `recvfrom` reports.
#[derive(Clone)]
struct Datagram {
    order: ErrorOrder,
    /// The sender's address, which `recvfrom` reports.
    src: SocketAddr,
    /// The address it was sent to: a unicast, broadcast or multicast address.
    dest: SocketAddr,
    /// When it reaches the socket, on the virtual monotonic clock: its receive stamp.
    at: Duration,
    /// The payload.
    data: Vec<u8>,
    /// Still in flight until then (link latency); `None` arrived on sending.
    arrives: Option<Deadline>,
    /// The link it crosses and that link's down epoch when it was sent.
    via: Option<(Arc<LinkState>, u64)>,
}

/// How the receive queue sees a datagram: its source, size, arrival time, and whether the link
/// it crossed went down while it was in flight, which loses it.
impl Arrival for Datagram {
    fn src(&self) -> SocketAddr {
        self.src
    }

    fn payload(&self) -> usize {
        self.data.len()
    }

    fn arrives(&self) -> Option<Deadline> {
        self.arrives
    }

    fn lost(&self) -> bool {
        match (&self.via, self.arrives) {
            (Some((link, epoch)), Some(at)) => link.lost_in_flight(*epoch, at.instant()),
            _ => false,
        }
    }
}

/// A datagram socket's receive queue, shared (behind an `Arc`) between the owning socket and the
/// per-sim delivery registry. Blocking receives park on the shared readiness signal.
#[derive(Default)]
pub(crate) struct DgramQueue {
    /// The queued datagrams, in arrival order, with the receive-buffer accounting of
    /// [`RxQueue`].
    packets: Mutex<RxQueue<Datagram>>,
    /// The code under test's socket this queue belongs to; `None` for a tester endpoint.
    rec: Option<Arc<SockRec>>,
}

impl DgramQueue {
    /// The queue of the code under test's socket `rec`, registered with it as its receive probe so
    /// `FIONREAD` and the socket table can see it. The record holds it weakly; the [`Sock`] and the
    /// [`Registry`] hold it strongly.
    fn for_socket(rec: &Arc<SockRec>) -> Arc<Self> {
        let queue = Arc::new(DgramQueue {
            packets: Mutex::default(),
            rec: Some(rec.clone()),
        });
        rec.set_probe(Arc::downgrade(&queue) as Weak<dyn RxProbe>);
        queue
    }

    /// Queues a datagram from `src` to `dest`, sent at monotonic time `sent`, that becomes
    /// receivable `delay` from now (its link latency), and bumps readiness for `domain`, the key
    /// of the sim the queue belongs to.
    fn push_after(
        &self,
        (src, dest): (SocketAddr, SocketAddr),
        sent: Duration,
        data: Vec<u8>,
        delay: std::time::Duration,
        via: Option<(Arc<LinkState>, u64)>,
        domain: usize,
    ) {
        let arrives = (!delay.is_zero()).then(|| Deadline::after(delay));
        if let Some(arrives) = arrives {
            arrives.wake_waiters_then();
        }
        let dg = Datagram {
            order: ErrorOrder::new(arrives),
            src,
            dest,
            at: sent.saturating_add(delay),
            data,
            arrives,
            via,
        };
        self.packets.lock().unwrap().push(dg, self.rec.as_deref());
        if let Some(rec) = &self.rec {
            readiness().bump_keys(domain, &[rec.wake_key()]);
        } else {
            readiness().bump_keys(domain, &[]);
        }
    }

    /// Pops the earliest-arrived datagram whose source passes `accept`.
    fn pop(&self, accept: impl Fn(SocketAddr) -> bool) -> Option<Datagram> {
        let mut q = self.packets.lock().unwrap();
        q.pop(accept, self.rec.as_deref()).map(|(dg, _)| dg)
    }

    fn take(
        &self,
        accept: impl Fn(SocketAddr) -> bool,
        shared: &SimShared,
        taker: Taker,
    ) -> Result<Option<Datagram>, c_int> {
        let cutoff = Deadline::after(Duration::ZERO).at();
        let mut queue = self.packets.lock().unwrap();
        let rec = self.rec.as_deref();
        let next = queue
            .first_matching_at(&accept, rec, cutoff)
            .map(|dg| dg.order);
        if let Some(rec) = rec
            && let Some(error) = rec.take_error_before(shared, taker, next, cutoff)
        {
            return Err(error);
        }
        if next.is_none_or(|data| data.at() > cutoff) {
            return Ok(None);
        }
        Ok(if taker == Taker::Peek {
            queue.peek_landed(accept)
        } else {
            queue.pop_landed(accept, rec)
        }
        .map(|(dg, _)| dg))
    }

    /// Whether a datagram whose source passes `accept` has arrived.
    fn has(&self, accept: impl Fn(SocketAddr) -> bool) -> bool {
        self.packets
            .lock()
            .unwrap()
            .has(accept, self.rec.as_deref())
    }
}

/// What the socket table and `FIONREAD` read of a datagram socket's queue.
impl RxProbe for DgramQueue {
    fn pending_time(&self) -> bool {
        self.packets.lock().unwrap().pending_time()
    }

    fn land(&self) {
        self.packets.lock().unwrap().land(self.rec.as_deref());
    }

    fn queued(&self) -> (usize, usize) {
        self.packets.lock().unwrap().queued()
    }

    fn next_len(&self) -> Option<usize> {
        self.packets.lock().unwrap().next_len(self.rec.as_deref())
    }
}

/// One handle's view of a socket. Every variant carries the socket's [`SockRec`], shared by all
/// handles of the socket and by the sim's socket table, and the handle's `nonblocking` flag
/// (`FIONBIO`), which a duplicated handle copies at the time of the `dup`.
enum Sock {
    /// A TCP socket that is neither connecting, connected nor listening: new, bound (`local`), or
    /// left unconnected by a failed connect with its error pending in `SO_ERROR`.
    Fresh {
        nonblocking: bool,
        local: Option<SocketAddr>,
        rec: Arc<SockRec>,
    },
    /// A TCP connect waiting on its SYN's answer; every handle of the socket shares the attempt.
    Connecting {
        nonblocking: bool,
        local: Option<SocketAddr>,
        rec: Arc<SockRec>,
        dest: SocketAddr,
        attempt: Arc<Mutex<ConnectAttempt>>,
    },
    /// A connected TCP socket: end `end` of `conn`.
    Stream {
        conn: Arc<Conn>,
        end: End,
        nonblocking: bool,
        rec: Arc<SockRec>,
    },
    /// A listening TCP socket at `addr`, whose `state` the [`Registry`] also holds.
    Listener {
        state: Arc<ListenerState>,
        addr: SocketAddr,
        nonblocking: bool,
        rec: Arc<SockRec>,
    },
    /// A UDP socket. `domain` is the family it was created with, `local` its bound address (set by
    /// `bind` or the implicit bind of a first send or connect), `peer` the default destination
    /// `connect` set, and `broadcast` its `SO_BROADCAST`.
    Dgram {
        queue: Arc<DgramQueue>,
        domain: c_int,
        local: Option<SocketAddr>,
        /// The address `bind` was given: what a disconnect returns the local address to.
        requested: Option<SocketAddr>,
        peer: Option<SocketAddr>,
        nonblocking: bool,
        broadcast: bool,
        rec: Arc<SockRec>,
    },
}

impl Sock {
    /// The socket's record.
    fn rec(&self) -> &Arc<SockRec> {
        match self {
            Sock::Fresh { rec, .. }
            | Sock::Connecting { rec, .. }
            | Sock::Stream { rec, .. }
            | Sock::Listener { rec, .. }
            | Sock::Dgram { rec, .. } => rec,
        }
    }
}

/// The error binding TCP address `want` (with SO_REUSEADDR as `reuse`) fails with over a socket
/// that holds `held` (with SO_REUSEADDR as `held_reuse`). Measured: a wildcard and a specific
/// address on one port coexist; an equal address is WSAEADDRINUSE without SO_REUSEADDR, and
/// WSAEACCES with it unless the held socket set it too.
///
/// The table is pinned against the host by `bind_os_truth`'s `overlapping_binds_match_the_host`,
/// which runs every combination in the sim and on the real OS and requires equal results. Microsoft
/// describes the rules in
/// [Microsoft Learn: Using SO_REUSEADDR and SO_EXCLUSIVEADDRUSE](https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse).
fn tcp_bind_conflict(
    (held, held_reuse): (SocketAddr, bool),
    want: SocketAddr,
    reuse: bool,
) -> Option<c_int> {
    match (held == want, reuse, held_reuse) {
        (false, _, _) | (true, true, true) => None,
        (true, false, _) => Some(WSAEADDRINUSE),
        (true, true, false) => Some(WSAEACCES),
    }
}

/// Where traffic to an address goes, for one sim. Lives behind [`Registries::lock`].
#[derive(Default)]
pub(crate) struct Registry {
    /// The datagram queue bound at each address: sockets of the code under test and tester
    /// endpoints alike. At most one queue per exact address.
    udp: HashMap<SocketAddr, Arc<DgramQueue>>,
    /// The listener at each address, the host's own and testers' alike.
    listeners: HashMap<SocketAddr, Arc<ListenerState>>,
}

impl Registry {
    /// A free ephemeral port for `ip` — on every address for the wildcard.
    ///
    /// Searches Windows' default dynamic port range, 49152-65535, lowest first, considering only
    /// datagram bindings of the same family; 0 if every port is taken
    /// ([Microsoft Learn: The default dynamic port range for TCP/IP has changed in Windows Vista and in Windows Server 2008](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/default-dynamic-port-range-tcpip-chang)).
    fn alloc_port(&self, ip: IpAddr) -> u16 {
        let taken = |port: u16| {
            self.udp.keys().any(|a| {
                a.port() == port
                    && a.is_ipv4() == ip.is_ipv4()
                    && (a.ip() == ip || ip.is_unspecified())
            })
        };
        (49152..=65535).find(|&p| !taken(p)).unwrap_or(0)
    }

    /// The queues a datagram to `dest` could reach: for a multicast group the sockets on the port
    /// that joined it ([`SockRec::takes_group`]), else every queue bound on the port.
    ///
    /// The choice among the candidates (exact bind, wildcard, broadcast) is the sim's `fan_out`.
    fn candidates(&self, dest: SocketAddr) -> Vec<Cand<Arc<DgramQueue>>> {
        let cand = |addr: SocketAddr, q: &Arc<DgramQueue>| Cand {
            addr,
            endpoint: q.rec.is_none(),
            device: q
                .rec
                .as_ref()
                .and_then(|r| r.state().device.as_ref().map(|d| d.0)),
            q: q.clone(),
        };
        let group = dest.ip();
        self.udp
            .iter()
            .filter(|(addr, _)| addr.port() == dest.port())
            .filter(|(addr, q)| {
                !group.is_multicast()
                    || q.rec
                        .as_ref()
                        .is_some_and(|r| r.takes_group(**addr, group, false))
            })
            .map(|(addr, q)| cand(*addr, q))
            .collect()
    }

    /// Whether a tester's endpoint or listener is bound at `ip`, making it a station.
    fn station_at(&self, ip: IpAddr) -> bool {
        self.udp
            .iter()
            .any(|(addr, q)| addr.ip() == ip && q.rec.is_none())
            || self
                .listeners
                .iter()
                .any(|(addr, l)| l.tester && addr.ip() == ip)
    }
}

/// The wildcard address of `ip`'s family.
fn unspecified_like(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

/// The loopback address of socket family `domain`.
fn loopback_for(domain: c_int) -> IpAddr {
    if domain == AF_INET6 {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }
}

/// `want` with its port resolved (an ephemeral one for port 0), or the error it fails with when it
/// collides with a TCP socket already bound or listening there.
///
/// The sockets considered are this sim's unconnected, connecting and listening TCP sockets, plus
/// testers' listeners, which count as holding their address without `SO_REUSEADDR`. Port 0 draws
/// the sim's sequential ephemeral ports until one is free, at most once around the range, and
/// fails with `WSAEADDRINUSE` when none is (Windows documents `WSAENOBUFS` for that case,
/// [Microsoft Learn: bind](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-bind)).
/// Called with the handle table locked; takes the registry lock briefly.
fn tcp_bind_addr(
    socks: &HashMap<c_int, Sock>,
    regs: &Registries,
    mut want: SocketAddr,
    reuse: bool,
) -> Result<SocketAddr, c_int> {
    let mut held: Vec<(SocketAddr, bool)> = socks
        .values()
        .filter_map(|sock| match sock {
            Sock::Fresh {
                local: Some(local),
                rec,
                ..
            }
            | Sock::Connecting {
                local: Some(local),
                rec,
                ..
            } => Some((*local, rec.opts().reuseaddr)),
            Sock::Listener { addr, rec, .. } => Some((*addr, rec.opts().reuseaddr)),
            _ => None,
        })
        .collect();
    let testers: Vec<SocketAddr> = regs
        .lock()
        .listeners
        .keys()
        .filter(|&addr| !held.iter().any(|&(h, _)| h == *addr))
        .copied()
        .collect();
    held.extend(testers.into_iter().map(|addr| (addr, false)));
    let conflict = |addr: SocketAddr| held.iter().find_map(|&h| tcp_bind_conflict(h, addr, reuse));
    if want.port() != 0 {
        return conflict(want).map_or(Ok(want), Err);
    }
    let port = (0..=u16::MAX - crate::scope::EPHEMERAL_FIRST)
        .map(|_| regs.shared.ephemeral_port())
        .find(|&port| conflict(SocketAddr::new(want.ip(), port)).is_none())
        .ok_or(WSAEADDRINUSE)?;
    want.set_port(port);
    Ok(want)
}

/// One npcap capture handle on a virtual link: whole Ethernet frames, fanned out to every handle
/// opened on the same device, the sender's included. `last_*` keep the most recently returned
/// frame and its `pcap_pkthdr` alive for `pcap_next_ex`, whose returned pointers must stay valid
/// until the next call; they are `Vec`s, so their heap buffers stay put when the map moves the
/// handle.
struct PcapHandle {
    /// The device name the handle was opened on, as given to `pcap_open`.
    device: Vec<u8>,
    /// Frames sent on the device and not yet read through this handle.
    rx: VecDeque<Vec<u8>>,
    /// The frame `pcap_next_ex` last returned; its pointer stays valid until the next call
    /// ([pcap_next_ex(3PCAP)](https://www.tcpdump.org/manpages/pcap_next_ex.3pcap.html)).
    last_frame: Vec<u8>,
    /// The `struct pcap_pkthdr` returned with it: 16 bytes on Windows, a `struct timeval` of two
    /// 32-bit `long`s, then `caplen` and `len` as `u32`s
    /// ([pcap(3PCAP)](https://www.tcpdump.org/manpages/pcap.3pcap.html), struct pcap_pkthdr;
    /// [Microsoft Learn: TIMEVAL](https://learn.microsoft.com/en-us/windows/win32/api/winsock/ns-winsock-timeval)).
    last_hdr: Vec<u8>,
}

/// The [`Net`] Windows managed threads' sockets route through.
///
/// Installed per sim on Windows; every managed thread of the sim offers its Winsock and npcap
/// calls here first, and a call on a handle the table does not hold is declined (`None`) to the
/// OS.
pub(crate) struct WinNet {
    /// Every handle the sim minted and has not closed. The outermost lock of the fabric.
    socks: Mutex<HashMap<c_int, Sock>>,
    /// The sim's address registry, shared with its testers.
    regs: Arc<Registries>,
    /// The next `SOCKET` value to mint; handles are never reused within a sim.
    next_handle: AtomicI32,
    /// Open npcap captures, by the `pcap_t` value handed out.
    pcaps: Mutex<HashMap<u64, PcapHandle>>,
    completions: Mutex<iocp::State>,
    /// The next `pcap_t` value to hand out.
    next_pcap: std::sync::atomic::AtomicU64,
}

impl WinNet {
    /// An empty fabric over `shared`'s topology. The first handle is `0x2000` and the first
    /// `pcap_t` `0x9000_0000`; both are snare's choices, distinctive in traces. Nothing reserves
    /// these values from the OS: a real handle that happened to equal a minted one would be
    /// taken for the sim's.
    pub(crate) fn new(shared: Arc<SimShared>) -> Self {
        WinNet {
            socks: Mutex::new(HashMap::new()),
            regs: Arc::new(Registries {
                reg: Mutex::default(),
                shared,
            }),
            next_handle: AtomicI32::new(0x2000),
            pcaps: Mutex::new(HashMap::new()),
            completions: Mutex::default(),
            // pcap_t handles are opaque pointers to the code under test; mint distinctive values.
            next_pcap: std::sync::atomic::AtomicU64::new(0x9000_0000),
        }
    }

    /// The per-sim registries, shared with the testers for the run's duration.
    pub(crate) fn registries(&self) -> Arc<Registries> {
        self.regs.clone()
    }

    /// The deadline a blocking receive on `fd` honours: `SO_RCVTIMEO` from now, if set.
    fn recv_deadline(&self, fd: c_int) -> Option<Deadline> {
        let span = self.rec(fd)?.opts().rcvtimeo?;
        Some(Deadline::timeout(span))
    }

    /// `fd`'s record, if the sim owns `fd`.
    fn rec(&self, fd: c_int) -> Option<Arc<SockRec>> {
        self.socks
            .lock()
            .unwrap()
            .get(&fd)
            .map(|sock| sock.rec().clone())
    }

    fn fd_interests(
        &self,
        fds: impl IntoIterator<Item = c_int>,
        keys: &mut crate::readiness::WakeKeys,
    ) -> bool {
        let mut time_sensitive = false;
        for fd in fds {
            let connecting = matches!(
                self.socks.lock().unwrap().get(&fd),
                Some(Sock::Connecting { .. })
            );
            if let Some(rec) = self.rec(fd) {
                keys.push(rec.wake_key());
                time_sensitive |= connecting || rec.pending_time();
            }
        }
        time_sensitive
    }

    /// A fresh handle. `Relaxed` suffices: only uniqueness matters.
    fn mint(&self) -> c_int {
        self.next_handle.fetch_add(1, Ordering::Relaxed)
    }

    /// Sends one datagram from UDP socket `fd` to `dest`; `None` if `fd` is not one.
    ///
    /// A pending error is reported first. The route decides the egress interface and source
    /// address; an unbound socket is then bound implicitly to its family's wildcard address at an
    /// ephemeral port, as `sendto` does on Windows
    /// ([Microsoft Learn: bind](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-bind)).
    /// A stalled send queue (`UdpPolicy::send_queue_depth == Some(0)`) makes a nonblocking send
    /// `WSAEWOULDBLOCK` and a blocking one wait. A datagram that reaches no socket may bring an
    /// ICMP port unreachable back to the sender (`unreachable_port`). A datagram the
    /// don't-fragment options keep whole that does not fit the egress MTU fails with
    /// `WSAEMSGSIZE` ([`win_sockopt::check_send`]). Called with no lock held.
    fn udp_send(&self, fd: c_int, data: Vec<u8>, dest: SocketAddr) -> Option<NetResult> {
        let (local, queue, domain, broadcast, nonblocking, rec) = {
            let socks = self.socks.lock().unwrap();
            match socks.get(&fd) {
                Some(Sock::Dgram {
                    local,
                    queue,
                    domain,
                    broadcast,
                    nonblocking,
                    rec,
                    ..
                }) => (
                    *local,
                    queue.clone(),
                    *domain,
                    *broadcast,
                    *nonblocking,
                    rec.clone(),
                ),
                _ => return None,
            }
        };
        if let Some(code) = rec.take_error_as(&self.regs.shared, Taker::Send) {
            return err(code);
        }
        let station = self.regs.lock().station_at(dest.ip());
        let sender =
            match self
                .regs
                .shared
                .route_send(&rec.view(local), dest, Op::Send, station, broadcast)
            {
                Ok(sender) => sender,
                Err(code) => return err(code),
            };
        if let Err(code) =
            win_sockopt::check_send(&self.regs.shared, &rec, &sender, dest, data.len())
        {
            return err(code);
        }
        let local = match local {
            Some(local) => local,
            None => self.autobind(fd, &queue, &rec, unspecified_like(loopback_for(domain))),
        };
        let src = sender.source(local);
        // A stalled link (`UdpPolicy::send_queue_depth == Some(0)`) holds the send back.
        let stalled = || {
            let policies = &self.regs.shared.policies;
            policies.send_stalled(local) || policies.send_stalled(src)
        };
        if stalled() {
            if nonblocking {
                return would_block();
            }
            if !readiness()
                .wait_until_on("udp send", None, &[rec.wake_key()], &stalled, || !stalled())
            {
                return err(WSAEWOULDBLOCK);
            }
        }
        self.regs
            .shared
            .capture_udp(&sender, src, dest, Dir::Out, &data, None);
        if self.regs.deliver(&sender, src, dest, &data) == 0 {
            self.regs
                .shared
                .unreachable_port(&rec, &sender, src, dest, &data, station);
        }
        rec.note_tx_nic(sender.egress_name());
        rec.count_udp_sent(dest, &sender);
        if rec.has_error_reports() {
            self.regs.shared.bump_keys(&[rec.wake_key()]);
        }
        ok(data.len() as i64)
    }

    /// Binds unbound datagram socket `fd` to `ip` at an ephemeral port.
    ///
    /// Takes the registry lock, then the handle table, one after the other, never both.
    fn autobind(
        &self,
        fd: c_int,
        queue: &Arc<DgramQueue>,
        rec: &Arc<SockRec>,
        ip: IpAddr,
    ) -> SocketAddr {
        let mut regs = self.regs.lock();
        let sa = SocketAddr::new(ip, regs.alloc_port(ip));
        regs.udp.insert(sa, queue.clone());
        drop(regs);
        if let Some(Sock::Dgram { local, .. }) = self.socks.lock().unwrap().get_mut(&fd) {
            *local = Some(sa);
        }
        rec.set_local(sa);
        sa
    }

    /// Moves the datagram socket on `queue` from `from` to `to` in the delivery map, for every
    /// descriptor of it, when a connect or disconnect changes its local address. An address
    /// another socket holds leaves it where it is.
    fn rehash(
        &self,
        queue: &Arc<DgramQueue>,
        rec: &Arc<SockRec>,
        from: SocketAddr,
        to: SocketAddr,
    ) {
        if from == to {
            return;
        }
        let mut regs = self.regs.lock();
        if regs.udp.contains_key(&to) {
            return;
        }
        regs.udp.remove(&from);
        regs.udp.insert(to, queue.clone());
        drop(regs);
        for sock in self.socks.lock().unwrap().values_mut() {
            if let Sock::Dgram {
                queue: q, local, ..
            } = sock
                && Arc::ptr_eq(q, queue)
            {
                *local = Some(to);
            }
        }
        rec.set_local(to);
    }

    /// Dissolves a datagram socket's association on a connect to an `AF_UNSPEC` address or the
    /// all-zero address: the peer is cleared and the local address returns to the one `bind`
    /// named, else the wildcard, keeping its port (measured by tests/udp_connect_source.rs).
    /// False when `fd` is not a datagram socket.
    fn disconnect_dgram(&self, fd: c_int) -> bool {
        let (queue, rec, local, requested) = {
            let mut socks = self.socks.lock().unwrap();
            let Some(Sock::Dgram {
                queue,
                rec,
                local,
                requested,
                peer,
                ..
            }) = socks.get_mut(&fd)
            else {
                return false;
            };
            *peer = None;
            (queue.clone(), rec.clone(), *local, *requested)
        };
        rec.set_peer(None);
        if let Some(bound) = local {
            let ip = requested.map_or(unspecified_like(bound.ip()), |r| r.ip());
            self.rehash(&queue, &rec, bound, SocketAddr::new(ip, bound.port()));
        }
        true
    }

    /// The `revents` for one `WSAPOLLFD`: which of the requested `events` are satisfied now.
    ///
    /// Follows WSAPoll: errors are reported whether asked for or not; a listener is readable when a
    /// connection waits; a datagram socket is always writable
    /// ([Microsoft Learn: WSAPoll](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsapoll)).
    /// A failed connect reports `POLLERR | POLLHUP`; Windows 10 2004 and later add `POLLWRNORM`,
    /// which the sim does not. A socket the sim does not own reports nothing.
    fn poll_revents(&self, fd: c_int, events: i16) -> i16 {
        let socks = self.socks.lock().unwrap();
        let Some(sock) = socks.get(&fd) else {
            return 0;
        };
        let (readable, writable) = match sock {
            // MS WSAPoll: a pending error is POLLERR, reported whether asked for or not; select
            // lists the socket as readable, where its recv fails with the error.
            Sock::Stream { rec, .. } | Sock::Dgram { rec, .. }
                if rec.peek_socket_error().is_some() =>
            {
                return POLLERR | if events & POLLIN != 0 { POLLRDNORM } else { 0 };
            }
            Sock::Stream { conn, end, .. } => (
                conn.read_pipe(*end).readable_or_closed(),
                conn.write_pipe(*end).writable(),
            ),
            Sock::Dgram { queue, rec, .. } => {
                (queue.has(|_| true) || rec.icmp_order().is_some(), true)
            }
            Sock::Listener { state, .. } => (!state.pending.lock().unwrap().is_empty(), false),
            // WSAPoll reports errors whether asked for or not. A failed connect is POLLERR |
            // POLLHUP here; the page documents POLLHUP | POLLERR | POLLWRNORM from Windows 10
            // 2004 and says nothing for earlier versions.
            Sock::Fresh { rec, .. } if rec.peek_error().is_some() => return POLLERR | POLLHUP,
            Sock::Fresh { .. } | Sock::Connecting { .. } => (false, false),
        };
        let mut r = 0i16;
        if events & POLLIN != 0 && readable {
            r |= POLLRDNORM;
        }
        if events & POLLOUT != 0 && writable {
            r |= POLLWRNORM;
        }
        r
    }

    /// Puts every handle state of `fd` in blocking or nonblocking mode (`FIONBIO`).
    fn set_nonblocking(&self, fd: c_int, on: bool) {
        if let Some(
            Sock::Fresh { nonblocking, .. }
            | Sock::Connecting { nonblocking, .. }
            | Sock::Stream { nonblocking, .. }
            | Sock::Listener { nonblocking, .. }
            | Sock::Dgram { nonblocking, .. },
        ) = self.socks.lock().unwrap().get_mut(&fd)
        {
            *nonblocking = on;
        }
    }

    /// Adds bound UDP socket `fd` to `membership`'s group, so datagrams to the group reach it
    /// (see [`SockRec::takes_group`]). An unbound or non-UDP `fd` is ignored.
    fn join_group(&self, fd: c_int, membership: Membership) {
        if let Some(Sock::Dgram {
            local: Some(_),
            rec,
            ..
        }) = self.socks.lock().unwrap().get(&fd)
        {
            rec.join(membership);
        }
    }
}

/// Where a connect waiting on its SYN stands after it was moved on.
enum Progress {
    /// Still waiting; the next point of the attempt is due at the deadline.
    Pending(Deadline),
    /// This call settled it; the socket's record comes with it.
    Settled(Outcome, Arc<SockRec>),
    /// The socket is not connecting.
    Idle,
}

/// `fd_set` (`<winsock2.h>`): a count, then up to `FD_SETSIZE` (64) `SOCKET`s
/// ([Microsoft Learn: select](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-select);
/// [Microsoft Learn: fd_set](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-fd_set)).
/// The sim reads and writes it unaligned through raw pointers, never as a reference.
#[repr(C)]
struct FdSet {
    fd_count: u32,
    fd_array: [usize; FD_SETSIZE],
}

/// The `winsock2.h` default, which code can raise by defining `FD_SETSIZE` before including it;
/// sets longer than 64 are cut to 64 here.
const FD_SETSIZE: usize = 64;

/// `TIMEVAL` (`<winsock2.h>`): `long` seconds and microseconds, 32-bit on Windows, where `long` is
/// 32 bits (LLP64)
/// ([Microsoft Learn: TIMEVAL](https://learn.microsoft.com/en-us/windows/win32/api/winsock/ns-winsock-timeval)).
#[repr(C)]
struct Timeval {
    tv_sec: i32,
    tv_usec: i32,
}

/// The sockets of the `fd_set` at `set`.
///
/// # Safety
/// `set` points to a readable `fd_set`.
unsafe fn read_fd_set(set: *const u8) -> Vec<c_int> {
    let set = set.cast::<FdSet>();
    let count = unsafe { std::ptr::addr_of!((*set).fd_count).read_unaligned() };
    let array = unsafe { std::ptr::addr_of!((*set).fd_array).cast::<usize>() };
    (0..(count as usize).min(FD_SETSIZE))
        .map(|i| unsafe { array.add(i).read_unaligned() } as c_int)
        .collect()
}

/// Leaves just `fds` in the `fd_set` at `set`.
///
/// # Safety
/// `set` points to a writable `fd_set`, and `fds` is no longer than [`FD_SETSIZE`] (it is a
/// subset of what [`read_fd_set`] read from it).
unsafe fn write_fd_set(set: *mut u8, fds: &[c_int]) {
    let set = set.cast::<FdSet>();
    unsafe { std::ptr::addr_of_mut!((*set).fd_count).write_unaligned(fds.len() as u32) };
    let array = unsafe { std::ptr::addr_of_mut!((*set).fd_array).cast::<usize>() };
    for (i, &fd) in fds.iter().enumerate() {
        unsafe { array.add(i).write_unaligned(fd as usize) };
    }
}

impl WinNet {
    /// The listener a connect to `dest` reaches: one on the exact address, else — for one of the
    /// host's own addresses — one on the wildcard address of that port.
    ///
    /// Takes the registry lock.
    fn listener_for(&self, dest: SocketAddr, host_local: bool) -> Option<Arc<ListenerState>> {
        let reg = self.regs.lock();
        reg.listeners
            .get(&dest)
            .or_else(|| {
                host_local
                    .then(|| {
                        reg.listeners
                            .get(&SocketAddr::new(unspecified_like(dest.ip()), dest.port()))
                    })
                    .flatten()
            })
            .cloned()
    }

    /// The address a connect to `dest` along `sender` leaves from, from a socket bound at
    /// `bound`: an unbound socket takes the next ephemeral port.
    fn client_addr(
        &self,
        dest: SocketAddr,
        bound: Option<SocketAddr>,
        sender: &Sender,
    ) -> SocketAddr {
        let src = sender
            .source(SocketAddr::new(unspecified_like(dest.ip()), 0))
            .ip();
        match bound {
            Some(local) if !local.ip().is_unspecified() => local,
            Some(local) => SocketAddr::new(src, local.port()),
            None => SocketAddr::new(src, self.regs.shared.ephemeral_port()),
        }
    }

    /// A new connection from the socket `rec` at `client` to `dest` along `sender`; `server_in`
    /// when a tester accepts it.
    ///
    /// Builds both pipes over the hop's link, records the ends on `rec` and registers `rec` as
    /// reader of `B`-to-`A` and writer of `A`-to-`B`. The caller queues the connection on the
    /// listener. A listener of the code under test taking it counts in the host's TCP
    /// `PassiveOpens`.
    fn establish(
        &self,
        rec: &Arc<SockRec>,
        dest: SocketAddr,
        client: SocketAddr,
        sender: &Sender,
        server_in: bool,
    ) -> Arc<Conn> {
        let hop = self.regs.shared.tcp_hop(sender, dest.ip());
        let via = hop.as_ref().map(|hop| hop.link.clone());
        let ends = |from, to| {
            Some(Ends {
                shared: self.regs.shared.clone(),
                from,
                to,
            })
        };
        let conn = Arc::new(Conn {
            a_to_b: Pipe::new(
                via.clone(),
                ends(client, dest),
                self.regs.shared.domain_key(),
            ),
            b_to_a: Pipe::new(via, ends(dest, client), self.regs.shared.domain_key()),
            client,
            server: dest,
            regs: self.regs.clone(),
            hop,
            tap: self.regs.shared.tcp_tap(sender, client, dest, server_in),
        });
        rec.set_ends(client, dest);
        rec.note_conn_nic(sender.egress_name());
        if !server_in {
            crate::netstats::bump(&self.regs.shared.stats.tcp(dest.ip()).passive_opens);
        }
        conn.b_to_a.read_by(rec);
        conn.a_to_b.write_by(rec);
        conn
    }

    /// Plays the points of `fd`'s connect that have come. Settling it makes the socket a stream
    /// handed to the listener, or leaves it unconnected with the error pending in `SO_ERROR`.
    /// Called with no `WinNet` lock held.
    ///
    /// Holds the handle table throughout, taking the attempt's lock and, inside its poll, the
    /// registry lock; both are released before `connect_settled` and the readiness bump. Every
    /// handle sharing the attempt (a `dup` made while connecting) settles together. On success the
    /// connection is pushed onto the listener's queue, so it is accepted later as on a kernel.
    fn advance_connect(&self, fd: c_int) -> Progress {
        let mut socks = self.socks.lock().unwrap();
        let Some(Sock::Connecting {
            local,
            rec,
            dest,
            attempt,
            ..
        }) = socks.get(&fd)
        else {
            return Progress::Idle;
        };
        let (local, rec, dest, attempt) = (*local, rec.clone(), *dest, attempt.clone());
        let client = attempt.lock().unwrap().client;
        let shared = &self.regs.shared;
        let mut listener = None;
        let mut admission = None;
        let step = attempt.lock().unwrap().poll(|| {
            let station = self.regs.lock().station_at(dest.ip());
            let host_local = shared.dest_is_host(dest.ip(), station);
            listener = self.listener_for(dest, host_local);
            let syn = shared.syn_probe(dest, listener.is_some(), station);
            if matches!(syn, Syn::Accept) {
                admission = listener.as_ref().and_then(ListenerState::reserve);
                if admission.is_none() {
                    return Syn::Silent;
                }
            }
            if host_local && matches!(syn, Syn::Rst) {
                crate::netstats::bump(&shared.stats.tcp(dest.ip()).out_rsts);
            }
            syn
        });
        let outcome = match step {
            Ok(next) => return Progress::Pending(next),
            Err(outcome) => outcome,
        };
        let conn = match (outcome, listener) {
            (Outcome::Connected, Some(listener)) => {
                let station = self.regs.lock().station_at(dest.ip());
                shared
                    .route_send(&rec.view(local), dest, Op::Connect, station, true)
                    .map(|sender| {
                        let conn = self.establish(&rec, dest, client, &sender, listener.tester);
                        (conn, listener)
                    })
            }
            (Outcome::Connected, None) => Err(WSAECONNREFUSED),
            (Outcome::Failed(code), _) => Err(code),
        };
        let aliases: Vec<c_int> = socks
            .iter()
            .filter(|(_, sock)| {
                matches!(sock, Sock::Connecting { attempt: a, .. } if Arc::ptr_eq(a, &attempt))
            })
            .map(|(fd, _)| *fd)
            .collect();
        for alias in aliases {
            let Some(Sock::Connecting {
                local,
                nonblocking,
                rec,
                ..
            }) = socks.remove(&alias)
            else {
                continue;
            };
            let settled = match &conn {
                Ok((conn, _)) => Sock::Stream {
                    conn: conn.clone(),
                    end: End::A,
                    nonblocking,
                    rec,
                },
                Err(_) => Sock::Fresh {
                    nonblocking,
                    local,
                    rec,
                },
            };
            socks.insert(alias, settled);
        }
        let mut keys = crate::readiness::WakeKeys::default();
        keys.push(rec.wake_key());
        let outcome = match conn {
            Ok((conn, listener)) => {
                attempt.lock().unwrap().established(conn.tap.as_ref());
                if let Some(key) = listener.wake_key() {
                    keys.push(key);
                }
                admission
                    .expect("accepted SYN reserves a queue entry")
                    .queue(conn);
                Outcome::Connected
            }
            Err(code) => {
                rec.set_pending_error(code, None);
                Outcome::Failed(code)
            }
        };
        drop(socks);
        shared.connect_settled(dest, outcome, true);
        shared.bump_keys(keys.as_slice());
        Progress::Settled(outcome, rec)
    }

    /// Moves on every connecting socket among `fds`.
    ///
    /// `None` means every connecting socket. Snapshots the handles first, so the table is not held
    /// while each connect advances.
    fn advance_connecting(&self, fds: Option<&[c_int]>) {
        let connecting: Vec<c_int> = self
            .socks
            .lock()
            .unwrap()
            .iter()
            .filter(|(fd, sock)| {
                matches!(sock, Sock::Connecting { .. }) && fds.is_none_or(|fds| fds.contains(fd))
            })
            .map(|(fd, _)| *fd)
            .collect();
        for fd in connecting {
            self.advance_connect(fd);
        }
    }

    /// Whether `fd`'s connect has a point to play, or is no longer waiting.
    fn connect_due(&self, fd: c_int) -> bool {
        match self.socks.lock().unwrap().get(&fd) {
            Some(Sock::Connecting { attempt, .. }) => attempt.lock().unwrap().due(),
            _ => true,
        }
    }

    /// Whether any connecting socket among `fds` has a point to play.
    fn connecting_due(&self, fds: Option<&[c_int]>) -> bool {
        self.socks
            .lock()
            .unwrap()
            .iter()
            .any(|(fd, sock)| match sock {
                Sock::Connecting { attempt, .. } => {
                    fds.is_none_or(|fds| fds.contains(fd)) && attempt.lock().unwrap().due()
                }
                _ => false,
            })
    }

    /// Which of `sets`' sockets select reports: readable, writable (connected), and with a failed
    /// connect.
    ///
    /// Readable and writable reuse [`WinNet::poll_revents`]; a socket with a pending error is
    /// readable, so its `recv` fails with it. The except set reports connects that failed, as
    /// select documents for a nonblocking connect
    /// ([Microsoft Learn: select](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-select)).
    /// Out-of-band data is not modelled.
    fn select_ready(&self, sets: &[Option<Vec<c_int>>; 3]) -> [Vec<c_int>; 3] {
        let [read, write, except] = sets;
        let pick = |set: &Option<Vec<c_int>>, ready: &dyn Fn(c_int) -> bool| -> Vec<c_int> {
            set.iter()
                .flatten()
                .copied()
                .filter(|fd| ready(*fd))
                .collect()
        };
        [
            pick(read, &|fd| self.poll_revents(fd, POLLIN) & POLLIN != 0),
            pick(write, &|fd| self.poll_revents(fd, POLLOUT) & POLLOUT != 0),
            pick(
                except,
                &|fd| matches!(self.socks.lock().unwrap().get(&fd), Some(Sock::Fresh { rec, .. }) if rec.peek_error().is_some()),
            ),
        ]
    }
}

impl WinNet {
    /// Handles the interface options: `IP_UNICAST_IF`/`IPV6_UNICAST_IF` bind unicast sends to an
    /// interface (an unknown index is WSAEINVAL), `IP_MULTICAST_IF`/`IPV6_MULTICAST_IF` pick the
    /// multicast one. `None` for any other option.
    ///
    /// Values are 4 bytes; shorter is `WSAEFAULT`. `IP_UNICAST_IF` takes an index in network byte
    /// order; `IP_MULTICAST_IF` an IPv4 address in network byte order, or an index in network byte
    /// order when the first octet is 0; the IPv6 options an index in host byte order. Index 0
    /// clears the choice
    /// ([Microsoft Learn: IPPROTO_IP socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options);
    /// [Microsoft Learn: IPPROTO_IPV6 socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options)).
    ///
    /// # Safety
    /// `val` is null or points to `len` readable bytes.
    unsafe fn interface_opt(
        &self,
        rec: &SockRec,
        level: c_int,
        name: c_int,
        val: *const u8,
        len: u32,
    ) -> Option<Result<(), c_int>> {
        let unicast = (level == IPPROTO_IP && name == IP_UNICAST_IF)
            || (level == IPPROTO_IPV6 && name == IPV6_UNICAST_IF);
        let multicast = (level == IPPROTO_IP && name == IP_MULTICAST_IF)
            || (level == IPPROTO_IPV6 && name == IPV6_MULTICAST_IF);
        if !unicast && !multicast {
            return None;
        }
        if val.is_null() || len < 4 {
            return Some(Err(WSAEFAULT));
        }
        let raw = unsafe { val.cast::<[u8; 4]>().read_unaligned() };
        let topo = self.regs.shared.topo();
        let index = if level == IPPROTO_IP && multicast && raw[0] != 0 {
            match topo.index_of_address(IpAddr::V4(Ipv4Addr::from(raw))) {
                Some(index) => index,
                None => return Some(Err(WSAEINVAL)),
            }
        } else if level == IPPROTO_IP {
            u32::from_be_bytes(raw)
        } else {
            u32::from_ne_bytes(raw)
        };
        let nic = match index {
            0 => None,
            index => match topo.name_of(index) {
                Some(name) => Some((index, name)),
                None => return Some(Err(WSAEINVAL)),
            },
        };
        drop(topo);
        let mut state = rec.state();
        if unicast {
            state.device = nic;
        } else {
            state.mcast_if = nic;
        }
        Some(Ok(()))
    }
}

/// Which receive call a set of flags came with: each takes its own flags.
#[derive(Clone, Copy, PartialEq)]
enum RecvCall {
    /// `recv` and `recvfrom`: `MSG_OOB`, `MSG_PEEK`, `MSG_WAITALL`
    /// ([Microsoft Learn: recv](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv)).
    Plain,
    /// `WSARecv` and `WSARecvFrom`, which add `MSG_PARTIAL` and `MSG_PUSH_IMMEDIATE`
    /// ([Microsoft Learn: WSARecv](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsarecv)).
    Wsa,
    /// `WSARecvMsg`, whose only input flag is `MSG_PEEK`
    /// ([Microsoft Learn: LPFN_WSARECVMSG](https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_wsarecvmsg)).
    Msg,
}

/// `WSABUF` (`ws2def.h`): a length and a buffer
/// ([Microsoft Learn: WSABUF](https://learn.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-wsabuf)).
type WsaBuf = windows_sys::Win32::Networking::WinSock::WSABUF;
/// `WSAMSG` (`ws2def.h`): the name, the data buffers, the control buffer and the flags of a
/// message call
/// ([Microsoft Learn: WSAMSG](https://learn.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-wsamsg)).
type WsaMsg = windows_sys::Win32::Networking::WinSock::WSAMSG;
/// `WSACMSGHDR` (`ws2def.h`): a `SIZE_T` length, then the level and type.
type CmsgHdr = windows_sys::Win32::Networking::WinSock::CMSGHDR;

/// `n` rounded up to the alignment of a control message header and its data, a pointer's size
/// (`ws2def.h` `WSA_CMSGHDR_ALIGN` and `WSA_CMSGDATA_ALIGN`).
fn cmsg_align(n: usize) -> usize {
    (n + size_of::<usize>() - 1) & !(size_of::<usize>() - 1)
}

/// The buffers of `msg`, empty for a null array.
///
/// # Safety
/// `msg.lpBuffers` is null or holds `msg.dwBufferCount` `WSABUF`s.
unsafe fn wsa_buffers(msg: &WsaMsg) -> Result<&[WsaBuf], c_int> {
    if msg.dwBufferCount == 0 {
        return Ok(&[]);
    }
    if msg.lpBuffers.is_null() {
        return Err(WSAEFAULT);
    }
    Ok(unsafe { std::slice::from_raw_parts(msg.lpBuffers, msg.dwBufferCount as usize) })
}

/// Copies `data` into `buffers` in order, packed with no holes (WSARecv: "The buffers are filled
/// in the order in which they appear in the array"); the bytes copied.
///
/// # Safety
/// Each buffer is null with length 0, or writable for its length.
unsafe fn scatter(buffers: &[WsaBuf], data: &[u8]) -> usize {
    let mut at = 0;
    for buf in buffers {
        let n = (buf.len as usize).min(data.len() - at);
        if n > 0 {
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr().add(at), buf.buf, n) };
        }
        at += n;
        if at == data.len() {
            break;
        }
    }
    at
}

/// The bytes of `buffers` gathered in order.
///
/// # Safety
/// Each buffer is null with length 0, or readable for its length.
unsafe fn gather(buffers: &[WsaBuf]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buffers.iter().map(|b| b.len as usize).sum());
    for buf in buffers.iter().filter(|b| b.len > 0) {
        out.extend_from_slice(unsafe { std::slice::from_raw_parts(buf.buf, buf.len as usize) });
    }
    out
}

/// Writes `messages` (level, type, data) into `msg`'s control buffer as `WSACMSGHDR`s, each
/// header and its data aligned to a pointer (`WSA_CMSG_SPACE`, with `cmsg_len` the unpadded
/// `WSA_CMSG_LEN`), and sets `Control.len` to the bytes used. A message that does not fit is
/// dropped and `MSG_CTRUNC` returned (snare's choice: Microsoft does not say how much of a
/// message that does not fit is written).
///
/// # Safety
/// `msg.Control.buf` is null with length 0, or writable for `msg.Control.len` bytes.
unsafe fn write_cmsgs(msg: &mut WsaMsg, messages: &[(c_int, c_int, Vec<u8>)]) -> u32 {
    let cap = msg.Control.len as usize;
    let header = size_of::<CmsgHdr>();
    let mut used = 0usize;
    let mut flags = 0;
    for (level, ty, data) in messages {
        let space = cmsg_align(header) + cmsg_align(data.len());
        if msg.Control.buf.is_null() || used + space > cap {
            flags |= MSG_CTRUNC;
            continue;
        }
        let at = unsafe { msg.Control.buf.add(used) };
        let hdr = CmsgHdr {
            cmsg_len: cmsg_align(header) + data.len(),
            cmsg_level: *level,
            cmsg_type: *ty,
        };
        unsafe {
            std::ptr::write_bytes(at, 0, space);
            at.cast::<CmsgHdr>().write_unaligned(hdr);
            std::ptr::copy_nonoverlapping(data.as_ptr(), at.add(cmsg_align(header)), data.len());
        }
        used += space;
    }
    msg.Control.len = used as u32;
    flags
}

/// The control messages in `msg`'s control buffer: level, type and data, walked as
/// `WSA_CMSG_FIRSTHDR`/`WSA_CMSG_NXTHDR` walk them; a header that runs past the buffer ends the
/// walk.
///
/// # Safety
/// `msg.Control.buf` is null or readable for `msg.Control.len` bytes.
unsafe fn read_cmsgs(msg: &WsaMsg) -> Vec<(c_int, c_int, Vec<u8>)> {
    let mut out = Vec::new();
    if msg.Control.buf.is_null() {
        return out;
    }
    let control = unsafe { std::slice::from_raw_parts(msg.Control.buf, msg.Control.len as usize) };
    let header = size_of::<CmsgHdr>();
    let mut at = 0usize;
    while at + header <= control.len() {
        let hdr = unsafe { control.as_ptr().add(at).cast::<CmsgHdr>().read_unaligned() };
        let data_at = at + cmsg_align(header);
        if hdr.cmsg_len < cmsg_align(header) || at + hdr.cmsg_len > control.len() {
            break;
        }
        out.push((
            hdr.cmsg_level,
            hdr.cmsg_type,
            control[data_at..at + hdr.cmsg_len].to_vec(),
        ));
        at += cmsg_align(hdr.cmsg_len);
    }
    out
}

impl WinNet {
    /// How `fd` stands for its options: stream or datagram, connecting, and its family.
    fn kind(&self, fd: c_int) -> Option<win_sockopt::Kind> {
        let socks = self.socks.lock().unwrap();
        let sock = socks.get(&fd)?;
        Some(match sock {
            Sock::Dgram { domain, .. } => win_sockopt::Kind {
                stream: false,
                connecting: false,
                v6: *domain == AF_INET6,
            },
            _ => win_sockopt::Kind {
                stream: true,
                connecting: matches!(sock, Sock::Connecting { .. }),
                v6: sock.rec().state().win.v6,
            },
        })
    }

    /// Checks receive `flags` from `call` on a socket (`stream` or datagram, `nonblocking` or
    /// not) against what Microsoft documents:
    ///
    /// - a flag the call does not take is `WSAEINVAL` ("an unknown flag was specified", recv);
    /// - `MSG_WAITALL` on a datagram socket, on a nonblocking one, or with `MSG_OOB`, `MSG_PEEK`
    ///   or `MSG_PARTIAL` is `WSAEOPNOTSUPP` (recv, `MSG_WAITALL`);
    /// - `MSG_OOB` is `WSAEINVAL` on a stream with `SO_OOBINLINE` (recv) and `WSAEOPNOTSUPP`
    ///   otherwise: on a datagram socket as recv documents, and on a stream because the sim's TCP
    ///   carries no urgent data, which recv words as "OOB data is not supported in the
    ///   communication domain" (snare's choice; a real stream would wait for urgent data).
    fn recv_flags(
        &self,
        rec: &SockRec,
        call: RecvCall,
        stream: bool,
        nonblocking: bool,
        flags: c_int,
    ) -> Result<(), c_int> {
        let known = match call {
            RecvCall::Plain => MSG_OOB | MSG_PEEK | MSG_WAITALL,
            RecvCall::Wsa => MSG_OOB | MSG_PEEK | MSG_WAITALL | MSG_PARTIAL | MSG_PUSH_IMMEDIATE,
            RecvCall::Msg => MSG_PEEK,
        };
        if flags & !known != 0 {
            return Err(WSAEINVAL);
        }
        if flags & MSG_WAITALL != 0
            && (!stream || nonblocking || flags & (MSG_OOB | MSG_PEEK | MSG_PARTIAL) != 0)
        {
            return Err(WSAEOPNOTSUPP);
        }
        if flags & MSG_OOB != 0 {
            let inline = rec
                .ignored_value(win_sockopt::SOL_SOCKET, win_sockopt::SO_OOBINLINE)
                .is_some_and(|v| v.iter().any(|&b| b != 0));
            return Err(if stream && inline {
                WSAEINVAL
            } else {
                WSAEOPNOTSUPP
            });
        }
        Ok(())
    }

    /// Reads connected stream `fd` into `out` as a receive with `flags` does; `None` when `fd` is
    /// not the sim's, `WSAENOTCONN` when it is not a connected stream.
    ///
    /// Returns what has arrived (up to `out.len()`), 0 at end of stream, `WSAECONNRESET` after a
    /// reset and `WSAESHUTDOWN` after `SD_RECEIVE`; a nonblocking read with nothing to take is
    /// `WSAEWOULDBLOCK`, and a blocking one waits up to `SO_RCVTIMEO` for the whole call, then
    /// fails with `WSAETIMEDOUT`
    /// ([std::net::TcpStream::set_read_timeout](https://doc.rust-lang.org/std/net/struct.TcpStream.html#method.set_read_timeout):
    /// "Windows may return TimedOut"). A socket-level pending error is reported before queued data;
    /// this ordering beyond peer resets remains unmeasured. `MSG_PEEK` copies without taking.
    /// `MSG_WAITALL` keeps reading until `out` is full, the stream ends or fails, or the timeout
    /// passes. EOF and local receive shutdown report the bytes copied; a peer reset reports
    /// `WSAECONNRESET` with the copied bytes retained. A timeout after partial data reports 0
    /// with those bytes retained, measured by `winsock_os_truth` on Windows 11 build
    /// 26200.9457. The result carries the copied and reported lengths separately.
    fn stream_take(
        &self,
        fd: c_int,
        out: &mut [u8],
        flags: c_int,
    ) -> Option<(usize, Result<usize, c_int>)> {
        let (conn, end, nonblocking, rec) = match self.socks.lock().unwrap().get(&fd)? {
            Sock::Stream {
                conn,
                end,
                nonblocking,
                rec,
            } => (conn.clone(), *end, *nonblocking, rec.clone()),
            _ => return Some((0, Err(WSAENOTCONN))),
        };
        let peek = flags & MSG_PEEK != 0;
        let all = flags & MSG_WAITALL != 0;
        let taker = if peek { Taker::Peek } else { Taker::Recv };
        let pipe = conn.read_pipe(end);
        let deadline = self.recv_deadline(fd);
        let mut got = 0usize;
        let partial =
            |got: usize, code: c_int| Some((got, if got > 0 { Ok(got) } else { Err(code) }));
        loop {
            if let Some(code) = rec.take_error_as(&self.regs.shared, taker) {
                return partial(got, code);
            }
            let rest = &mut out[got..];
            let read = if peek {
                pipe.peek(rest)
            } else {
                pipe.read(rest)
            };
            match read {
                Read::Data(n) => {
                    got += n;
                    if !all || got == out.len() {
                        return Some((got, Ok(got)));
                    }
                }
                Read::Eof => return Some((got, Ok(got))),
                Read::Reset => return Some((got, Err(WSAECONNRESET))),
                Read::Shut => return partial(got, WSAESHUTDOWN),
                Read::WouldBlock if nonblocking => {
                    snare_interpose::charge_latency();
                    return Some((got, Err(WSAEWOULDBLOCK)));
                }
                Read::WouldBlock => {
                    if !readiness().wait_until_on(
                        "tcp recv",
                        deadline,
                        &[rec.wake_key()],
                        || rec.pending_time(),
                        || pipe.readable_or_closed() || rec.peek_error().is_some(),
                    ) {
                        let timed_out = deadline.is_some_and(|d| d.passed());
                        if timed_out && got > 0 && all {
                            return Some((got, Ok(0)));
                        }
                        return partial(
                            got,
                            if timed_out {
                                WSAETIMEDOUT
                            } else {
                                WSAEWOULDBLOCK
                            },
                        );
                    }
                }
            }
        }
    }

    /// Takes the next datagram for datagram socket `fd`, or a copy of it under `MSG_PEEK`,
    /// blocking as the socket does; `None` when `fd` is not a datagram socket of the sim's.
    ///
    /// A connected socket takes only its peer's datagrams, as `connect` documents. A pending
    /// ICMP port-unreachable status (`WSAECONNRESET`) follows receive arrival order alongside
    /// datagrams and is unaffected by `SO_ERROR` or `MSG_PEEK`. Individual statuses, interleaved
    /// data and reset-option toggles have host comparisons in `winsock_os_truth` on Windows 11
    /// build 26200.9457. Other ICMP errors remain unmeasured.
    /// A blocking receive waits
    /// up to `SO_RCVTIMEO`, then fails with `WSAETIMEDOUT`.
    fn dgram_take(&self, fd: c_int, flags: c_int) -> Option<Result<Datagram, c_int>> {
        let (queue, peer, nonblocking, rec) = match self.socks.lock().unwrap().get(&fd)? {
            Sock::Dgram {
                queue,
                peer,
                nonblocking,
                rec,
                ..
            } => (queue.clone(), *peer, *nonblocking, rec.clone()),
            _ => return None,
        };
        let peek = flags & MSG_PEEK != 0;
        let taker = if peek { Taker::Peek } else { Taker::Recv };
        let accept = |src: SocketAddr| peer.is_none_or(|p| p == src);
        let deadline = self.recv_deadline(fd);
        loop {
            match queue.take(accept, &self.regs.shared, taker) {
                Ok(Some(dg)) => return Some(Ok(dg)),
                Err(error) => return Some(Err(error)),
                Ok(None) => {}
            }
            if nonblocking {
                snare_interpose::charge_latency();
                return Some(Err(WSAEWOULDBLOCK));
            }
            if !readiness().wait_until_on(
                "udp recv",
                deadline,
                &[rec.wake_key()],
                || rec.pending_time(),
                || queue.has(accept) || rec.peek_error().is_some(),
            ) {
                let timed_out = deadline.is_some_and(|d| d.passed());
                return Some(Err(if timed_out {
                    WSAETIMEDOUT
                } else {
                    WSAEWOULDBLOCK
                }));
            }
        }
    }

    /// The blocking mode and record of `fd`, and whether it is a datagram socket; `None` when the
    /// sim does not own it.
    fn recv_state(&self, fd: c_int) -> Option<(bool, Arc<SockRec>, bool)> {
        let socks = self.socks.lock().unwrap();
        let sock = socks.get(&fd)?;
        let nonblocking = match sock {
            Sock::Fresh { nonblocking, .. }
            | Sock::Connecting { nonblocking, .. }
            | Sock::Stream { nonblocking, .. }
            | Sock::Listener { nonblocking, .. }
            | Sock::Dgram { nonblocking, .. } => *nonblocking,
        };
        Some((
            nonblocking,
            sock.rec().clone(),
            matches!(sock, Sock::Dgram { .. }),
        ))
    }

    /// A receive of up to `len` bytes into `buf` with `flags` from `call`, the source written to
    /// `from` (an address buffer and its length) for a datagram: the bytes copied, or the error. A datagram longer than `len` is cut
    /// to it and fails with `WSAEMSGSIZE` after the copy, consumed unless peeked ("the buffer is
    /// filled with the first part of the datagram, and recvfrom generates the error WSAEMSGSIZE.
    /// For unreliable protocols (for example, UDP) the excess data is lost",
    /// [Microsoft Learn: recvfrom](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom)).
    /// On a stream `from` is ignored, as recvfrom documents for connection-oriented sockets.
    ///
    /// # Safety
    /// `buf` is writable for `len` bytes; `from`'s pointers are null or the caller's.
    unsafe fn receive(
        &self,
        fd: c_int,
        buf: *mut u8,
        len: usize,
        flags: c_int,
        call: RecvCall,
        (addr, addr_len): (*mut u8, *mut u32),
    ) -> Option<Result<i64, c_int>> {
        let (nonblocking, rec, dgram) = self.recv_state(fd)?;
        if let Err(code) = self.recv_flags(&rec, call, !dgram, nonblocking, flags) {
            return Some(Err(code));
        }
        let out: &mut [u8] = if len == 0 {
            &mut []
        } else {
            unsafe { std::slice::from_raw_parts_mut(buf, len) }
        };
        if !dgram {
            return self
                .stream_take(fd, out, flags)
                .map(|(_, reported)| reported.map(|reported| reported as i64));
        }
        let dg = match self.dgram_take(fd, flags)? {
            Ok(dg) => dg,
            Err(code) => return Some(Err(code)),
        };
        let n = len.min(dg.data.len());
        out[..n].copy_from_slice(&dg.data[..n]);
        if !addr.is_null() && !addr_len.is_null() {
            unsafe { write_addr(dg.src, addr, addr_len) };
        }
        Some(if dg.data.len() > len {
            Err(WSAEMSGSIZE)
        } else {
            Ok(n as i64)
        })
    }

    /// The `WSARecvMsg` output flags of datagram `dg`: `MSG_TRUNC` when it was cut, `MSG_MCAST`
    /// or `MSG_BCAST` for one sent to a multicast or broadcast address (LPFN_WSARECVMSG).
    fn msg_flags(&self, dg: &Datagram, truncated: bool) -> u32 {
        let mut flags = if truncated { MSG_TRUNC } else { 0 };
        if dg.dest.ip().is_multicast() {
            flags |= MSG_MCAST;
        } else if self.regs.shared.topo().is_broadcast(dg.dest.ip()) {
            flags |= MSG_BCAST;
        }
        flags
    }
}

impl Net for WinNet {
    unsafe fn completion(&self, call: snare_interpose::CompletionCall) -> Option<NetResult> {
        unsafe { iocp::call(self, call) }
    }

    /// IP Helper calls are answered from the sim's topology by [`crate::iphlp`].
    unsafe fn iphlp(&self, call: snare_interpose::IpHlpCall<'_>) -> Option<NetResult> {
        unsafe { crate::iphlp::call(&self.regs.shared, call) }
    }

    /// Whether `fd` is one of the sim's handles.
    fn owns(&self, fd: c_int) -> bool {
        self.socks.lock().unwrap().contains_key(&fd)
    }

    /// `socket`: a TCP or UDP socket of `AF_INET`/`AF_INET6`, blocking, unbound. Any other family
    /// or type is declined to the OS
    /// ([Microsoft Learn: socket](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket)).
    /// Only the low byte of `ty` is compared with the type; masking the bits above it is snare's
    /// choice, not something the page describes.
    unsafe fn socket(&self, domain: c_int, ty: c_int, _protocol: c_int) -> Option<NetResult> {
        if domain != AF_INET && domain != AF_INET6 {
            return None;
        }
        let kind = match ty & 0xff {
            SOCK_STREAM => SocketKind::TcpStream,
            SOCK_DGRAM => SocketKind::Udp,
            _ => return None,
        };
        let fd = self.mint();
        let rec = self.regs.shared.new_socket(kind, fd);
        rec.state().win.v6 = domain == AF_INET6;
        let sock = match kind {
            SocketKind::Udp => Sock::Dgram {
                queue: DgramQueue::for_socket(&rec),
                domain,
                local: None,
                requested: None,
                peer: None,
                nonblocking: false,
                broadcast: false,
                rec,
            },
            _ => Sock::Fresh {
                nonblocking: false,
                local: None,
                rec,
            },
        };
        self.socks.lock().unwrap().insert(fd, sock);
        ok(fd as i64)
    }

    /// `bind`. A malformed address is `WSAEFAULT`, an address the host does not have fails as
    /// `claim_address` says, a bound socket is `WSAEINVAL`
    /// ([Microsoft Learn: bind](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-bind)).
    /// TCP follows [`tcp_bind_addr`]; UDP refuses an exact address already bound (`WSAEADDRINUSE`)
    /// and takes port 0 from [`Registry::alloc_port`]. Holds the handle table throughout, then the
    /// registry.
    unsafe fn bind(&self, fd: c_int, addr: *const u8, len: u32) -> Option<NetResult> {
        let Some(want) = (unsafe { parse_addr(addr, len) }) else {
            return err(WSAEFAULT);
        };
        let mut socks = self.socks.lock().unwrap();
        match socks.get(&fd)? {
            Sock::Fresh {
                local: None, rec, ..
            } => {
                let rec = rec.clone();
                if let Err(code) = self.regs.shared.claim_address(want.ip()) {
                    return err(code);
                }
                let want = match tcp_bind_addr(&socks, &self.regs, want, rec.opts().reuseaddr) {
                    Ok(want) => want,
                    Err(code) => return err(code),
                };
                if let Some(Sock::Fresh { local, .. }) = socks.get_mut(&fd) {
                    *local = Some(want);
                }
                rec.set_local(want);
                ok(0)
            }
            Sock::Dgram {
                local: None,
                queue,
                rec,
                ..
            } => {
                let (queue, rec) = (queue.clone(), rec.clone());
                if let Err(code) = self.regs.shared.claim_address(want.ip()) {
                    return err(code);
                }
                let asked = want;
                let mut want = want;
                let mut regs = self.regs.lock();
                if want.port() == 0 {
                    want.set_port(regs.alloc_port(want.ip()));
                } else if regs.udp.contains_key(&want) {
                    return err(WSAEADDRINUSE);
                }
                regs.udp.insert(want, queue);
                drop(regs);
                if let Some(Sock::Dgram {
                    local, requested, ..
                }) = socks.get_mut(&fd)
                {
                    *local = Some(want);
                    *requested = Some(asked);
                }
                rec.set_local(want);
                ok(0)
            }
            // MS bind: WSAEINVAL when the socket is already bound.
            _ => err(WSAEINVAL),
        }
    }

    /// `listen`
    /// ([Microsoft Learn: listen](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-listen)).
    unsafe fn listen(&self, fd: c_int, backlog: c_int) -> Option<NetResult> {
        let mut socks = self.socks.lock().unwrap();
        let (addr, nonblocking, rec) = match socks.get(&fd)? {
            Sock::Fresh {
                local: Some(local),
                nonblocking,
                rec,
            } => (*local, *nonblocking, rec.clone()),
            // MS listen: on a listening socket it succeeds without changing the backlog.
            Sock::Listener { .. } => return ok(0),
            // MS listen: WSAEINVAL for an unbound socket, WSAEISCONN for a connected one.
            Sock::Fresh { local: None, .. } => return err(WSAEINVAL),
            Sock::Stream { .. } | Sock::Connecting { .. } => return err(WSAEISCONN),
            Sock::Dgram { .. } => return err(WSAEOPNOTSUPP),
        };
        let state = Arc::new(ListenerState {
            rec: Some(Arc::downgrade(&rec)),
            capacity: AtomicUsize::new(if backlog == i32::MAX {
                self.regs.shared.sys.limits().listen_backlog_max
            } else if backlog < 0 {
                (backlog.unsigned_abs() as usize).clamp(200, 65535)
            } else {
                (backlog as usize).max(1)
            }),
            ..ListenerState::default()
        });
        self.regs.lock().listeners.insert(addr, state.clone());
        rec.set_kind(SocketKind::TcpListener);
        socks.insert(
            fd,
            Sock::Listener {
                state,
                addr,
                nonblocking,
                rec,
            },
        );
        ok(0)
    }

    /// `accept`
    /// ([Microsoft Learn: accept](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept)):
    /// the oldest queued connection, as a new blocking handle for end `B`. A blocking accept waits
    /// without a timeout, since `SO_RCVTIMEO` covers receive calls only. The page says the new
    /// socket has the listening socket's properties; the sim starts it blocking whatever the
    /// listener's `FIONBIO` mode.
    unsafe fn accept(
        &self,
        fd: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
        _flags: c_int,
    ) -> Option<NetResult> {
        let (state, nonblocking, lrec) = match self.socks.lock().unwrap().get(&fd)? {
            Sock::Listener {
                state,
                nonblocking,
                rec,
                ..
            } => (state.clone(), *nonblocking, rec.clone()),
            // MS accept: WSAEINVAL until listen was called; WSAEOPNOTSUPP for a datagram socket.
            Sock::Dgram { .. } => return err(WSAEOPNOTSUPP),
            _ => return err(WSAEINVAL),
        };
        let pop = || state.pending.lock().unwrap().pop_front();
        // SO_RCVTIMEO covers only the receive calls (MS SOL_SOCKET options), so accept waits on.
        let conn = if let Some(c) = pop() {
            c
        } else if nonblocking {
            return would_block();
        } else if readiness().wait_until_on(
            "accept",
            None,
            &[lrec.wake_key()],
            || lrec.pending_time(),
            || !state.pending.lock().unwrap().is_empty(),
        ) {
            match pop() {
                Some(c) => c,
                None => return err(WSAEWOULDBLOCK),
            }
        } else {
            return err(WSAEWOULDBLOCK);
        };
        let peer = conn.client;
        let new_fd = self.mint();
        state.occupied.fetch_sub(1, Ordering::AcqRel);
        let rec = self.regs.shared.new_socket(SocketKind::TcpStream, new_fd);
        rec.set_ends(conn.server, conn.client);
        rec.set_listener(lrec.id);
        rec.inherit_buffers(&lrec);
        rec.state().win.v6 = lrec.state().win.v6;
        rec.note_conn_nic(self.regs.shared.hop_name(conn.hop.as_ref()).as_deref());
        conn.a_to_b.read_by(&rec);
        conn.b_to_a.write_by(&rec);
        self.socks.lock().unwrap().insert(
            new_fd,
            Sock::Stream {
                conn,
                end: End::B,
                nonblocking: false,
                rec,
            },
        );
        if !addr.is_null() && !addr_len.is_null() {
            unsafe { write_addr(peer, addr, addr_len) };
        }
        ok(new_fd as i64)
    }

    /// `connect`
    /// ([Microsoft Learn: connect](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect)).
    ///
    /// On a UDP socket it sets the default peer (binding implicitly first). On TCP it routes, then
    /// probes for a listener: a SYN the listener accepts at once connects immediately; otherwise a
    /// [`ConnectAttempt`] plays the SYN's retransmissions and answer on the sim's clock. A
    /// nonblocking socket returns `WSAEWOULDBLOCK` and is settled by later
    /// `select`/`WSAPoll`/`SO_ERROR`/`connect` calls; a second `connect` meanwhile is
    /// `WSAEALREADY`, and after success `WSAEISCONN`. A blocking socket waits, settling the attempt
    /// as its points come due.
    unsafe fn connect(&self, fd: c_int, addr: *const u8, len: u32) -> Option<NetResult> {
        if !addr.is_null()
            && len >= 2
            && unsafe { addr.cast::<u16>().read_unaligned() } == AF_UNSPEC as u16
            && let Some(Sock::Dgram { domain, .. }) = self.socks.lock().unwrap().get(&fd)
        {
            // Winsock holds the address to the socket family's size first (measured).
            let size = if *domain == AF_INET6 { 28 } else { 16 };
            if len < size {
                return err(WSAEFAULT);
            }
        }
        if !addr.is_null()
            && len >= 2
            && unsafe { addr.cast::<u16>().read_unaligned() } == AF_UNSPEC as u16
            && self.disconnect_dgram(fd)
        {
            return ok(0);
        }
        let Some(dest) = (unsafe { parse_addr(addr, len) }) else {
            return err(WSAEFAULT);
        };
        if dest.ip().is_unspecified() && dest.port() == 0 && self.disconnect_dgram(fd) {
            return ok(0);
        }
        // UDP connect fixes the default peer; an unbound socket takes the route's source address
        // at an ephemeral port. A connected socket is disconnected first, so a wildcard bind
        // picks its source anew (measured by tests/udp_connect_source.rs).
        let station = self.regs.lock().station_at(dest.ip());
        let (nonblocking, bound, rec) = {
            let socks = self.socks.lock().unwrap();
            match socks.get(&fd)? {
                Sock::Dgram { peer: Some(_), .. } => {
                    drop(socks);
                    self.disconnect_dgram(fd);
                    return unsafe { self.connect(fd, addr, len) };
                }
                Sock::Dgram {
                    local,
                    queue,
                    rec,
                    broadcast,
                    ..
                } => {
                    let (local, queue, rec, broadcast) =
                        (*local, queue.clone(), rec.clone(), *broadcast);
                    drop(socks);
                    let sender = match self.regs.shared.route_send(
                        &rec.view(local),
                        dest,
                        Op::Connect,
                        station,
                        broadcast,
                    ) {
                        Ok(sender) => sender,
                        Err(code) => return err(code),
                    };
                    match local {
                        None => {
                            let ip = sender
                                .connected_local(SocketAddr::new(unspecified_like(dest.ip()), 0))
                                .ip();
                            self.autobind(fd, &queue, &rec, ip);
                        }
                        Some(bound) => {
                            self.rehash(&queue, &rec, bound, sender.connected_local(bound))
                        }
                    }
                    if let Some(Sock::Dgram { peer, .. }) = self.socks.lock().unwrap().get_mut(&fd)
                    {
                        *peer = Some(dest);
                    }
                    rec.set_peer(Some(dest));
                    rec.note_tx_nic(sender.egress_name());
                    return ok(0);
                }
                Sock::Fresh {
                    nonblocking,
                    local,
                    rec,
                } => (*nonblocking, *local, rec.clone()),
                Sock::Connecting { .. } => {
                    drop(socks);
                    return match self.advance_connect(fd) {
                        Progress::Pending(_) => {
                            snare_interpose::charge_latency();
                            err(WSAEALREADY)
                        }
                        Progress::Settled(Outcome::Failed(code), rec) => {
                            rec.take_error();
                            err(code)
                        }
                        Progress::Settled(Outcome::Connected, _) => err(WSAEISCONN),
                        Progress::Idle => unsafe { self.connect(fd, addr, len) },
                    };
                }
                _ => return err(WSAEISCONN),
            }
        };
        let sender =
            match self
                .regs
                .shared
                .route_send(&rec.view(bound), dest, Op::Connect, station, true)
            {
                Ok(sender) => sender,
                Err(code) => return err(code),
            };
        crate::netstats::bump(&self.regs.shared.stats.tcp(dest.ip()).active_opens);
        let host_local = matches!(&sender, Sender::Host(path) if path.local);
        let listener = self.listener_for(dest, host_local);
        let mut syn = self
            .regs
            .shared
            .syn_probe(dest, listener.is_some(), station);
        let admission = if matches!(syn, Syn::Accept) {
            listener.as_ref().and_then(ListenerState::reserve)
        } else {
            None
        };
        if matches!(syn, Syn::Accept) && admission.is_none() {
            syn = Syn::Silent;
        }
        if host_local && matches!(syn, Syn::Rst) {
            crate::netstats::bump(&self.regs.shared.stats.tcp(dest.ip()).out_rsts);
        }
        let client = self.client_addr(dest, bound, &sender);
        if let (Syn::Accept, Some(listener)) = (syn, &listener) {
            let conn = self.establish(&rec, dest, client, &sender, listener.tester);
            if let Some(tap) = &conn.tap {
                tap.open(false, Duration::ZERO);
            }
            self.socks.lock().unwrap().insert(
                fd,
                Sock::Stream {
                    conn: conn.clone(),
                    end: End::A,
                    nonblocking,
                    rec,
                },
            );
            admission
                .expect("accepted SYN reserves a queue entry")
                .queue(conn);
            let mut keys = crate::readiness::WakeKeys::default();
            self.fd_interests([fd], &mut keys);
            if let Some(key) = listener.wake_key() {
                keys.push(key);
            }
            self.regs.shared.bump_keys(keys.as_slice());
            return ok(0);
        }
        let plan = self.regs.shared.syn_plan(&rec.opts(), syn);
        let server_in = listener.as_ref().is_none_or(|l| l.tester);
        let tap = self.regs.shared.tcp_tap(&sender, client, dest, server_in);
        let attempt = match ConnectAttempt::start(&plan, syn, client, tap) {
            Ok(attempt) => attempt,
            Err(Outcome::Failed(code)) => {
                self.regs
                    .shared
                    .connect_settled(dest, Outcome::Failed(code), false);
                return err(code);
            }
            Err(Outcome::Connected) => unreachable!("a SYN a listener accepts connects at once"),
        };
        self.socks.lock().unwrap().insert(
            fd,
            Sock::Connecting {
                nonblocking,
                local: bound,
                rec,
                dest,
                attempt: Arc::new(Mutex::new(attempt)),
            },
        );
        // MS connect: a nonblocking socket's connect fails with WSAEWOULDBLOCK while it is
        // attempted; select's writefds (or exceptfds) report how it ended.
        if nonblocking {
            return err(WSAEWOULDBLOCK);
        }
        loop {
            match self.advance_connect(fd) {
                Progress::Pending(next) => {
                    readiness().wait_until_dynamic(
                        "connect",
                        Some(next),
                        |keys| self.fd_interests([fd], keys),
                        || self.connect_due(fd),
                    );
                }
                Progress::Settled(Outcome::Connected, _) => return ok(0),
                Progress::Settled(Outcome::Failed(code), rec) => {
                    rec.take_error();
                    return err(code);
                }
                Progress::Idle => {
                    return match self.socks.lock().unwrap().get(&fd) {
                        Some(Sock::Stream { .. }) => ok(0),
                        Some(Sock::Fresh { rec, .. }) => {
                            err(rec.take_error().unwrap_or(WSAECONNABORTED))
                        }
                        _ => err(WSAENOTSOCK),
                    };
                }
            }
        }
    }

    /// `send`
    /// ([Microsoft Learn: send](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-send)).
    /// On TCP a pending error comes first; a blocking send waits for window up to `SO_SNDTIMEO`
    /// (`WSAETIMEDOUT`, the error `std` documents a Windows timeout as:
    /// [std::net::TcpStream::set_write_timeout](https://doc.rust-lang.org/std/net/struct.TcpStream.html#method.set_write_timeout)),
    /// a nonblocking one takes what fits. A reset connection is `WSAECONNRESET`, a shut one
    /// `WSAESHUTDOWN`. On UDP it sends to the connected peer; without one it is `WSAEDESTADDRREQ`
    /// where the `connect` page documents `WSAENOTCONN`. `MSG_OOB` is `WSAEOPNOTSUPP`, as send
    /// documents when "OOB data is not supported in the communication domain": the sim carries no
    /// urgent data. `MSG_DONTROUTE`, which providers may ignore, and any other flag are ignored.
    unsafe fn send(
        &self,
        fd: c_int,
        buf: *const u8,
        len: usize,
        flags: c_int,
    ) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        if flags & MSG_OOB != 0 && socks.contains_key(&fd) {
            return err(WSAEOPNOTSUPP);
        }
        match socks.get(&fd) {
            Some(Sock::Stream {
                conn,
                end,
                rec,
                nonblocking,
            }) => {
                let (conn, end, rec, nonblocking) = (conn.clone(), *end, rec.clone(), *nonblocking);
                drop(socks);
                if let Some(code) = rec.take_error_as(&self.regs.shared, Taker::Send) {
                    return err(code);
                }
                let bytes = unsafe { std::slice::from_raw_parts(buf, len) };
                // MS send: a blocking send waits for buffer space; a nonblocking one takes what
                // fits, or fails with WSAEWOULDBLOCK. The wait is bounded by SO_SNDTIMEO.
                let sent = conn.write_pipe(end).send(
                    bytes,
                    nonblocking,
                    rec.opts().sndtimeo,
                    |rest| conn.write(end, rest),
                    || rec.peek_error().is_some(),
                );
                match sent {
                    Sent::Bytes(n) => {
                        rec.count_sent();
                        ok(n as i64)
                    }
                    Sent::Closed if conn.a_to_b.is_reset() => err(WSAECONNRESET),
                    Sent::Closed => err(WSAESHUTDOWN),
                    Sent::WouldBlock | Sent::Stuck => err(WSAEWOULDBLOCK),
                    Sent::TimedOut => err(WSAETIMEDOUT),
                    Sent::Error => err(rec
                        .take_error_as(&self.regs.shared, Taker::Send)
                        .unwrap_or(WSAEWOULDBLOCK)),
                }
            }
            Some(Sock::Dgram { peer, .. }) => {
                let peer = *peer;
                drop(socks);
                let Some(dest) = peer else {
                    return err(WSAEDESTADDRREQ);
                };
                let data = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
                self.udp_send(fd, data, dest)
            }
            Some(_) => err(WSAENOTCONN),
            None => None,
        }
    }

    /// `sendto`
    /// ([Microsoft Learn: sendto](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-sendto)):
    /// a null address, or any address on a TCP socket ("the to and tolen parameters are
    /// ignored, making sendto equivalent to send"), is a `send`; otherwise a datagram to `addr`.
    unsafe fn sendto(
        &self,
        fd: c_int,
        buf: *const u8,
        len: usize,
        flags: c_int,
        addr: *const u8,
        addr_len: u32,
    ) -> Option<NetResult> {
        let dgram = matches!(self.socks.lock().unwrap().get(&fd)?, Sock::Dgram { .. });
        if addr.is_null() || !dgram {
            return unsafe { self.send(fd, buf, len, flags) };
        }
        if flags & MSG_OOB != 0 {
            return err(WSAEOPNOTSUPP);
        }
        let Some(dest) = (unsafe { parse_addr(addr, addr_len) }) else {
            return err(WSAEFAULT);
        };
        let data = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
        self.udp_send(fd, data, dest)
    }

    /// `recv`
    /// ([Microsoft Learn: recv](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv)):
    /// see [`WinNet::receive`], [`WinNet::stream_take`] and [`WinNet::dgram_take`]. A TCP socket
    /// that is not connected is `WSAENOTCONN`.
    unsafe fn recv(&self, fd: c_int, buf: *mut u8, len: usize, flags: c_int) -> Option<NetResult> {
        let r = unsafe {
            self.receive(
                fd,
                buf,
                len,
                flags,
                RecvCall::Plain,
                (std::ptr::null_mut(), std::ptr::null_mut()),
            )
        }?;
        done(r)
    }

    /// `recvfrom`
    /// ([Microsoft Learn: recvfrom](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom)):
    /// as `recv`, with a datagram's source written to `addr`.
    unsafe fn recvfrom(
        &self,
        fd: c_int,
        buf: *mut u8,
        len: usize,
        flags: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        let r = unsafe { self.receive(fd, buf, len, flags, RecvCall::Plain, (addr, addr_len)) }?;
        done(r)
    }

    /// `shutdown`
    /// ([Microsoft Learn: shutdown](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-shutdown)).
    /// `SD_SEND` sends a FIN after what was written; `SD_RECEIVE` makes later reads fail with
    /// `WSAESHUTDOWN` but does not reset the connection, which Windows does when data is queued or
    /// arrives. On a connected UDP socket it succeeds and changes nothing (Windows disallows later
    /// sends after `SD_SEND`); an unconnected UDP socket gets `WSAENOTCONN`, which the page
    /// reserves for connection-oriented sockets.
    unsafe fn shutdown(&self, fd: c_int, how: c_int) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        let sock = socks.get(&fd)?;
        // MS shutdown: `how` is SD_RECEIVE, SD_SEND or SD_BOTH, else WSAEINVAL; a
        // connection-oriented socket that is not connected gives WSAENOTCONN.
        if ![SD_RECEIVE, SD_SEND, SD_BOTH].contains(&how) {
            return err(WSAEINVAL);
        }
        match sock {
            Sock::Stream { conn, end, .. } => {
                let (conn, end) = (conn.clone(), *end);
                drop(socks);
                if how != SD_RECEIVE {
                    conn.close(end);
                }
                if how != SD_SEND {
                    conn.read_pipe(end).shut_read();
                }
                ok(0)
            }
            Sock::Dgram { peer: Some(_), .. } => ok(0),
            _ => err(WSAENOTCONN),
        }
    }

    /// `closesocket`
    /// ([Microsoft Learn: closesocket](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-closesocket)).
    ///
    /// Only the last handle of a socket releases it: the last handle of a connection end sends the
    /// FIN (or, with a zero `SO_LINGER`, a reset; with a nonzero one, waits up to it for delivery);
    /// the last handle of a listener withdraws it and resets the connections no one accepted; the
    /// last handle of a datagram socket unbinds it and leaves its groups.
    unsafe fn close(&self, fd: c_int) -> Option<NetResult> {
        // MS closesocket: on a nonblocking socket with a nonzero SO_LINGER and data still to
        // send, the call fails with WSAEWOULDBLOCK and the socket stays open.
        let would_linger = match self.socks.lock().unwrap().get(&fd)? {
            Sock::Stream {
                conn,
                end,
                rec,
                nonblocking: true,
            } => {
                rec.opts().linger.is_some_and(|l| !l.is_zero())
                    && !conn.write_pipe(*end).delivered()
            }
            _ => false,
        };
        if would_linger {
            return err(WSAEWOULDBLOCK);
        }
        let sock = self.socks.lock().unwrap().remove(&fd)?;
        let key = sock.rec().wake_key();
        match sock {
            Sock::Stream { conn, end, rec, .. } => {
                // Only a true dup (same conn AND same end) keeps the half open; the peer socket
                // shares the conn but is the other end, so closing here must still shut our side.
                let shared = self.socks.lock().unwrap().values().any(
                    |o| matches!(o, Sock::Stream { conn: c, end: e, .. } if Arc::ptr_eq(c, &conn) && *e == end),
                );
                if !shared {
                    // MS closesocket: SO_LINGER with a zero timeout aborts with a reset; another
                    // waits for what was written to cross, up to that long.
                    match rec.opts().linger {
                        Some(linger) if linger.is_zero() => conn.reset(end),
                        Some(linger) => {
                            conn.close(end);
                            let pipe = conn.write_pipe(end);
                            readiness().wait_until(
                                "linger",
                                Some(Deadline::timeout(linger)),
                                || pipe.delivered(),
                            );
                        }
                        None => conn.close(end),
                    }
                }
            }
            Sock::Listener { state, addr, .. } => {
                let shared = self.socks.lock().unwrap().values().any(
                    |o| matches!(o, Sock::Listener { state: s, .. } if Arc::ptr_eq(s, &state)),
                );
                if !shared {
                    self.regs
                        .lock()
                        .listeners
                        .retain(|a, l| *a != addr || !Arc::ptr_eq(l, &state));
                    let orphans: Vec<_> = state.pending.lock().unwrap().drain(..).collect();
                    for conn in orphans {
                        conn.reset(End::B);
                    }
                }
            }
            Sock::Dgram { local, queue, .. } => {
                let shared =
                    self.socks.lock().unwrap().values().any(
                        |o| matches!(o, Sock::Dgram { queue: q, .. } if Arc::ptr_eq(q, &queue)),
                    );
                if !shared {
                    let mut regs = self.regs.lock();
                    if let Some(local) = local {
                        regs.udp.remove(&local);
                    }
                }
            }
            Sock::Fresh { .. } | Sock::Connecting { .. } => {}
        }
        self.regs.shared.socket_closed(fd);
        self.regs.shared.bump_keys(&[key]);
        ok(0)
    }

    /// `getsockname`
    /// ([Microsoft Learn: getsockname](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getsockname)):
    /// the bound address, a connecting socket's implicit one, or a connection's local end. A
    /// socket never bound fails with `WSAEINVAL` ("The socket has not been bound to an address
    /// with bind"), as measured by tests/winsock_os_truth.rs `unbound_getsockname_matches_the_host`.
    unsafe fn getsockname(
        &self,
        fd: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        let local = match socks.get(&fd)? {
            Sock::Stream { conn, end, .. } => Some(conn.local(*end)),
            Sock::Listener { addr, .. } => Some(*addr),
            Sock::Dgram { local, .. } | Sock::Fresh { local, .. } => *local,
            Sock::Connecting { local, attempt, .. } => {
                local.or_else(|| Some(attempt.lock().unwrap().client))
            }
        };
        let Some(local) = local else {
            return err(WSAEINVAL);
        };
        drop(socks);
        unsafe { write_addr(local, addr, addr_len) };
        ok(0)
    }

    /// `getpeername`: the connected peer, else `WSAENOTCONN`.
    unsafe fn getpeername(
        &self,
        fd: c_int,
        addr: *mut u8,
        addr_len: *mut u32,
    ) -> Option<NetResult> {
        let socks = self.socks.lock().unwrap();
        let peer = match socks.get(&fd)? {
            Sock::Stream { conn, end, .. } => conn.peer(*end),
            Sock::Dgram { peer: Some(p), .. } => *p,
            _ => return err(WSAENOTCONN),
        };
        drop(socks);
        unsafe { write_addr(peer, addr, addr_len) };
        ok(0)
    }

    /// `setsockopt`
    /// ([Microsoft Learn: setsockopt](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-setsockopt)).
    ///
    /// A level the socket does not take fails first ([`win_sockopt::level_applies`]). Then, in
    /// order: the `IPPROTO_TCP` options the fault model owns (`faults::sockopt`), the interface
    /// options ([`WinNet::interface_opt`]), the don't-fragment options
    /// ([`win_sockopt::set_frag`]), `SO_BROADCAST`, the buffer sizes (stored as the host stores
    /// them, which `os_parity`'s `sockbuf_semantics_match_real_os` compares against the real OS),
    /// the timeouts and linger options, and the multicast joins (a value shorter than an
    /// `ip_mreq`/`ipv6_mreq` is `WSAEFAULT`). Every other option goes to [`win_sockopt::set`]:
    /// kept and read back, listed when unmodelled, refused when Windows does not define it. A
    /// value shorter than 4 bytes for `SO_BROADCAST`, the timeouts, `SO_REUSEADDR` or
    /// `SO_DONTLINGER` reads as 0 rather than failing with `WSAEFAULT` as the page documents for
    /// a short `optlen`.
    unsafe fn setsockopt(
        &self,
        fd: c_int,
        level: c_int,
        name: c_int,
        val: *const u8,
        len: u32,
    ) -> Option<NetResult> {
        let rec = self.rec(fd)?;
        let kind = self.kind(fd)?;
        if let Err(code) = win_sockopt::level_applies(kind, level, name) {
            return err(code);
        }
        // Read-only, refused as measured: WSAENOPROTOOPT, except WSAEINVAL for the wide form on
        // a datagram socket.
        if level == SOL_SOCKET
            && matches!(
                name,
                win_sockopt::SO_PROTOCOL_INFOA | win_sockopt::SO_PROTOCOL_INFOW
            )
        {
            return err(if name == win_sockopt::SO_PROTOCOL_INFOW && !kind.stream {
                WSAEINVAL
            } else {
                WSAENOPROTOOPT
            });
        }
        if level == IPPROTO_TCP
            && let Some(result) = unsafe { crate::faults::sockopt::set(&rec, name, val, len) }
        {
            return done(result.map(|()| 0));
        }
        if let Some(result) = unsafe { self.interface_opt(&rec, level, name, val, len) } {
            return done(result.map(|()| 0));
        }
        if let Some(result) = unsafe { win_sockopt::set_frag(&rec, level, name, val, len) } {
            return done(result.map(|()| 0));
        }
        if level == SOL_SOCKET && name == SO_BROADCAST {
            let on = unsafe { read_int(val, len) } != 0;
            if let Some(Sock::Dgram { broadcast, .. }) = self.socks.lock().unwrap().get_mut(&fd) {
                *broadcast = on;
            }
            return ok(0);
        }
        // MS setsockopt: a short optlen is WSAEFAULT. SO_RCVBUF/SO_SNDBUF are stored as
        // `limits::sockbuf_value` says the host stores them.
        if level == SOL_SOCKET && (name == SO_RCVBUF || name == SO_SNDBUF) {
            if val.is_null() || (len as usize) < size_of::<c_int>() {
                return err(WSAEFAULT);
            }
            let v = unsafe { read_int(val, len) };
            let which = if name == SO_RCVBUF {
                Buf::Rcv
            } else {
                Buf::Snd
            };
            let limits = self.regs.shared.sys.limits();
            let stored = match crate::limits::sockbuf_value(&limits, which, v, 0, false) {
                Ok(stored) => stored,
                Err(code) => return err(code),
            };
            rec.state().buf.set(which, stored);
            return ok(0);
        }
        if level == SOL_SOCKET
            && matches!(
                name,
                SO_RCVTIMEO | SO_SNDTIMEO | SO_REUSEADDR | SO_LINGER | SO_DONTLINGER
            )
        {
            let millis = || {
                let ms = unsafe { read_int(val, len) } as u32;
                (ms != 0).then(|| Duration::from_millis(ms.into()))
            };
            let mut state = rec.state();
            match name {
                SO_RCVTIMEO => state.opts.rcvtimeo = millis(),
                SO_SNDTIMEO => state.opts.sndtimeo = millis(),
                SO_REUSEADDR => state.opts.reuseaddr = unsafe { read_int(val, len) } != 0,
                SO_LINGER => state.opts.linger = unsafe { parse_linger(val, len) },
                _ if unsafe { read_int(val, len) } != 0 => state.opts.linger = None,
                _ => {}
            }
            return ok(0);
        }
        if (level == IPPROTO_IP && name == IP_ADD_MEMBERSHIP)
            || (level == IPPROTO_IPV6 && name == IPV6_ADD_MEMBERSHIP)
        {
            let Some(membership) = (unsafe { parse_add_membership(level, name, val, len) }) else {
                return err(WSAEFAULT);
            };
            self.join_group(fd, membership);
            return ok(0);
        }
        let set = unsafe { win_sockopt::set(&self.regs.shared, &rec, kind, level, name, val, len) };
        done(set.map(|()| 0))
    }

    /// `getsockopt`
    /// ([Microsoft Learn: getsockopt](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getsockopt)).
    ///
    /// `SO_ERROR` first advances a pending connect, so a nonblocking connect that has come due
    /// reports its outcome, then returns and clears the socket's error. Values are written as
    /// 4-byte `DWORD`s, except `SO_LINGER`, a `struct linger`. The interface options read back
    /// the index in host byte order, as the IPPROTO_IP and IPPROTO_IPV6 pages document, except
    /// `IP_UNICAST_IF`, returned in network byte order as it is set where the
    /// [IPPROTO_IP page](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options)
    /// says host byte order. The options the sim does not model come from
    /// [`win_sockopt::get`]: what was set, else Windows' default.
    unsafe fn getsockopt(
        &self,
        fd: c_int,
        level: c_int,
        name: c_int,
        val: *mut u8,
        len: *mut u32,
    ) -> Option<NetResult> {
        if level == SOL_SOCKET && name == SO_ERROR {
            self.advance_connect(fd);
        }
        let rec = self.rec(fd)?;
        let kind = self.kind(fd)?;
        if let Err(code) = win_sockopt::level_applies(kind, level, name) {
            return err(code);
        }
        if level == SOL_SOCKET
            && matches!(
                name,
                win_sockopt::SO_PROTOCOL_INFOA | win_sockopt::SO_PROTOCOL_INFOW
            )
        {
            return done(
                unsafe { win_sockopt::get_protocol_info(kind, name, val, len) }.map(|()| 0),
            );
        }
        if level == IPPROTO_TCP
            && let Some(value) = crate::faults::sockopt::get(&self.regs.shared, &rec, name)
        {
            unsafe { write_opt(value, val, len) };
            return ok(0);
        }
        let millis = |d: Option<Duration>| {
            d.map_or(0, |d| d.as_millis().min(u32::MAX as u128) as u32 as i32)
        };
        let index = |nic: &Option<(u32, String)>| nic.as_ref().map_or(0, |d| d.0);
        let value: Option<i32> = match (level, name) {
            (IPPROTO_IP, IP_UNICAST_IF) => Some(index(&rec.state().device).to_be() as i32),
            (IPPROTO_IPV6, IPV6_UNICAST_IF) => Some(index(&rec.state().device) as i32),
            (IPPROTO_IP, IP_MULTICAST_IF) | (IPPROTO_IPV6, IPV6_MULTICAST_IF) => {
                Some(index(&rec.state().mcast_if) as i32)
            }
            (SOL_SOCKET, SO_RCVTIMEO) => Some(millis(rec.opts().rcvtimeo)),
            (SOL_SOCKET, SO_SNDTIMEO) => Some(millis(rec.opts().sndtimeo)),
            // MS getsockopt: SO_ERROR returns and resets the per-socket error code.
            (SOL_SOCKET, SO_ERROR) => Some(
                rec.take_error_as(&self.regs.shared, Taker::SoError)
                    .unwrap_or(0),
            ),
            (SOL_SOCKET, SO_LINGER) => {
                let linger = rec.opts().linger;
                let secs = linger.map_or(0, |d| d.as_secs().min(u16::MAX.into()) as u16);
                if !val.is_null() && !len.is_null() && unsafe { *len } >= 4 {
                    unsafe {
                        val.cast::<u16>().write_unaligned(linger.is_some() as u16);
                        val.add(2).cast::<u16>().write_unaligned(secs);
                        *len = 4;
                    }
                }
                return ok(0);
            }
            (SOL_SOCKET, SO_DONTLINGER) => Some(rec.opts().linger.is_none() as i32),
            (SOL_SOCKET, SO_REUSEADDR) => Some(rec.opts().reuseaddr as i32),
            (SOL_SOCKET, SO_RCVBUF) => Some(rec.state().buf.rcvbuf),
            (SOL_SOCKET, SO_SNDBUF) => Some(rec.state().buf.sndbuf),
            (SOL_SOCKET, SO_TYPE) => Some(if kind.stream { SOCK_STREAM } else { SOCK_DGRAM }),
            (SOL_SOCKET, SO_BROADCAST) => Some(matches!(
                self.socks.lock().unwrap().get(&fd),
                Some(Sock::Dgram {
                    broadcast: true,
                    ..
                })
            ) as i32),
            (SOL_SOCKET, SO_ACCEPTCONN) => Some(matches!(
                self.socks.lock().unwrap().get(&fd),
                Some(Sock::Listener { .. })
            ) as i32),
            _ => win_sockopt::get_frag(&rec, level, name),
        };
        if let Some(value) = value {
            unsafe { write_opt(value, val, len) };
            return ok(0);
        }
        match win_sockopt::get(&self.regs.shared, &rec, kind, level, name) {
            Ok(bytes) => {
                unsafe { write_bytes(&bytes, val, len) };
                ok(0)
            }
            Err(code) => err(code),
        }
    }

    /// `ioctlsocket`
    /// ([Microsoft Learn: ioctlsocket](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-ioctlsocket)):
    /// the three commands Winsock defines for it
    /// ([Microsoft Learn: Winsock IOCTLs](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls)).
    /// `FIONBIO` sets the blocking mode. `FIONREAD` is the bytes available to read; on a datagram
    /// socket the total queued payload, not the first datagram's, capped at `SO_RCVBUF` (snare's
    /// model: `socket_limits_win`'s `fionread_capped` checks it inside the sim only and does not
    /// compare it with the host). `SIOCATMARK` is always `TRUE`: no out-of-band data is ever
    /// waiting. Any other command fails with `WSAEOPNOTSUPP`, as Winsock answers one it does not
    /// know (measured, tests/strict_sockopts.rs `unknown_option_codes_on_windows`); a null `argp`
    /// is `WSAEFAULT` ("The argp parameter is not a valid part of the user address space").
    unsafe fn ioctl(&self, fd: c_int, request: u64, arg: i64) -> Option<NetResult> {
        let rec = self.rec(fd)?;
        let argp = arg as *mut u32;
        // ioctlsocket's command is a C `long`, and FIONBIO's high bit is set, so it arrives sign-
        // extended: compare the 32 bits Winsock defines.
        let command = request as u32;
        if ![FIONBIO as u32, FIONREAD, SIOCATMARK].contains(&command) {
            return err(WSAEOPNOTSUPP);
        }
        if argp.is_null() {
            return err(WSAEFAULT);
        }
        match command {
            c if c == FIONBIO as u32 => {
                self.set_nonblocking(fd, unsafe { argp.read_unaligned() } != 0);
            }
            FIONREAD => unsafe { argp.write_unaligned(rec.fionread() as u32) },
            _ => unsafe { argp.write_unaligned(1) },
        }
        ok(0)
    }

    /// `WSAIoctl` on a sim socket
    /// ([Microsoft Learn: WSAIoctl](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaioctl);
    /// the codes in [Microsoft Learn: Winsock IOCTLs](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls)).
    /// The interposer answers `SIO_GET_EXTENSION_FUNCTION_POINTER` itself and never forwards a sim
    /// socket to Winsock, so every code ends here:
    ///
    /// - `FIONBIO`, `FIONREAD` and `SIOCATMARK` as `ioctlsocket` serves them, through the input
    ///   (`FIONBIO`) or output buffer; a buffer shorter than a `u_long` is `WSAEFAULT` ("the
    ///   cbInBuffer or cbOutBuffer parameter is too small").
    /// - `SIO_UDP_CONNRESET`: whether an ICMP port unreachable surfaces as `WSAECONNRESET` on this
    ///   UDP socket's receives. `SIO_UDP_NETRESET`, its TTL-expired counterpart, is accepted and
    ///   changes nothing: the sim never expires a TTL. Both are `WSAEINVAL` on a TCP socket,
    ///   snare's choice ("the command is not applicable to the type of socket specified").
    /// - `SIO_BASE_HANDLE` and the `SIO_BSP_HANDLE*` codes return the socket itself: no layered
    ///   provider sits over a sim socket.
    /// - `SIO_KEEPALIVE_VALS` (a `tcp_keepalive` of three `u_long`s) turns `SO_KEEPALIVE` on or
    ///   off on a TCP socket, harmless as that option is; on a datagram socket it is
    ///   `WSAENOPROTOOPT`, as the WSAIoctl page says. Its timeout and interval are not kept.
    /// - `SIO_LOOPBACK_FAST_PATH` is accepted on a TCP socket and changes nothing, the sim's
    ///   loopback having no slow path; on a datagram socket ("can be used only with TCP sockets")
    ///   it is `WSAEOPNOTSUPP`, snare's choice.
    /// - `SIO_CPU_AFFINITY` ties an unbound UDP socket to the processor in its `USHORT` input,
    ///   which is kept (see [`Sim::socket_cpu_affinity`](crate::Sim::socket_cpu_affinity)) and not
    ///   checked against the machine's processors. As measured on Windows 11: a TCP socket is
    ///   `WSAEOPNOTSUPP`, an input shorter than a `USHORT` `WSAEFAULT`, and a bound socket
    ///   `WSAEINVAL`.
    /// - `SIO_TIMESTAMPING` and `SIO_GET_TX_TIMESTAMP` on a datagram socket, as `win_sockopt`
    ///   models Winsock timestamping; "Valid only for datagram sockets", so on TCP the first is
    ///   `WSAEINVAL` and the second `WSAEOPNOTSUPP`, as on a socket that never enabled stamps.
    /// - Any other code fails with `WSAEOPNOTSUPP`, what Winsock answers a code it does not know
    ///   (measured, tests/strict_sockopts.rs `unknown_option_codes_on_windows`), and is listed in
    ///   the socket's `unmodelled_options` as refused: the sim cannot produce what only the OS
    ///   could.
    unsafe fn wsa_ioctl(
        &self,
        fd: c_int,
        code: u32,
        input: *const u8,
        input_len: u32,
        output: *mut u8,
        output_len: u32,
        returned: *mut u32,
    ) -> Option<NetResult> {
        let rec = self.rec(fd)?;
        let kind = self.kind(fd)?;
        let set_returned = |n: u32| {
            if !returned.is_null() {
                unsafe { returned.write_unaligned(n) };
            }
        };
        let input_dword = || {
            (!input.is_null() && (input_len as usize) >= size_of::<u32>())
                .then(|| unsafe { input.cast::<u32>().read_unaligned() })
        };
        let output_dword = |value: u32| {
            if output.is_null() || (output_len as usize) < size_of::<u32>() {
                return err(WSAEFAULT);
            }
            unsafe { output.cast::<u32>().write_unaligned(value) };
            set_returned(size_of::<u32>() as u32);
            ok(0)
        };
        match code {
            c if c == FIONBIO as u32 => {
                let Some(on) = input_dword() else {
                    return err(WSAEFAULT);
                };
                self.set_nonblocking(fd, on != 0);
                set_returned(0);
                ok(0)
            }
            FIONREAD => output_dword(rec.fionread() as u32),
            SIOCATMARK => output_dword(1),
            SIO_UDP_CONNRESET | SIO_UDP_NETRESET => {
                if kind.stream {
                    return err(WSAEINVAL);
                }
                let Some(on) = input_dword() else {
                    return err(WSAEFAULT);
                };
                if code == SIO_UDP_CONNRESET {
                    rec.state().dgram.connreset = on != 0;
                }
                set_returned(0);
                ok(0)
            }
            SIO_BASE_HANDLE | SIO_BSP_HANDLE | SIO_BSP_HANDLE_SELECT | SIO_BSP_HANDLE_POLL => {
                if output.is_null() || (output_len as usize) < size_of::<usize>() {
                    return err(WSAEFAULT);
                }
                unsafe { output.cast::<usize>().write_unaligned(fd as usize) };
                set_returned(size_of::<usize>() as u32);
                ok(0)
            }
            SIO_KEEPALIVE_VALS => {
                if !kind.stream {
                    return err(WSAENOPROTOOPT);
                }
                if input.is_null() || (input_len as usize) < 3 * size_of::<u32>() {
                    return err(WSAEFAULT);
                }
                let on = unsafe { input.cast::<u32>().read_unaligned() } != 0;
                rec.keep_ignored(
                    win_sockopt::SOL_SOCKET,
                    win_sockopt::SO_KEEPALIVE,
                    &c_int::from(on).to_ne_bytes(),
                );
                set_returned(0);
                ok(0)
            }
            SIO_LOOPBACK_FAST_PATH => {
                if !kind.stream {
                    return err(WSAEOPNOTSUPP);
                }
                if input_dword().is_none() {
                    return err(WSAEFAULT);
                }
                set_returned(0);
                ok(0)
            }
            SIO_CPU_AFFINITY => {
                if kind.stream {
                    return err(WSAEOPNOTSUPP);
                }
                if input.is_null() || (input_len as usize) < size_of::<u16>() {
                    return err(WSAEFAULT);
                }
                let mut state = rec.state();
                if state.local.is_some() {
                    return err(WSAEINVAL);
                }
                state.dgram.cpu_affinity = Some(unsafe { input.cast::<u16>().read_unaligned() });
                set_returned(0);
                ok(0)
            }
            SIO_TIMESTAMPING => {
                if kind.stream {
                    return err(WSAEINVAL);
                }
                let configured = unsafe { win_sockopt::configure_stamping(&rec, input, input_len) };
                set_returned(0);
                done(configured.map(|()| 0))
            }
            SIO_GET_TX_TIMESTAMP => {
                if kind.stream {
                    return err(WSAEOPNOTSUPP);
                }
                done(
                    unsafe {
                        win_sockopt::take_tx_stamp(
                            &rec, input, input_len, output, output_len, returned,
                        )
                    }
                    .map(|()| 0),
                )
            }
            _ => {
                self.regs.shared.unservable_option(
                    &rec,
                    UnmodelledOption::Ioctl {
                        request: code.into(),
                    },
                );
                err(WSAEOPNOTSUPP)
            }
        }
    }

    /// `WSARecv`, `WSARecvFrom` and `WSARecvMsg` on a sim socket: a receive into `msg`'s buffers
    /// with the flags in its `dwFlags`, as [`WinNet::receive`] describes, scattered over the
    /// buffers in order. `WSARecvMsg` takes datagram sockets only and fails with `WSAEINVAL` on a
    /// stream (measured on Windows 11, tests/winsock_os_truth.rs `msg_calls_on_tcp_on_windows`).
    ///
    /// On a datagram socket the source goes to `name` (`WSAEFAULT` when `namelen` is too short
    /// for it, or nonzero with a null `name`, as LPFN_WSARECVMSG documents) and `namelen` is set
    /// to its size; a datagram cut to the buffers fails with `WSAEMSGSIZE` after filling them.
    /// `WSARecvMsg` also returns an `SO_TIMESTAMP` control message, the arrival as a
    /// `QueryPerformanceCounter` value, while receive stamps are on (`SIO_TIMESTAMPING`), and the
    /// output flags `MSG_TRUNC`, `MSG_MCAST` and `MSG_BCAST`, with `MSG_CTRUNC` for a control
    /// buffer too short; the other calls' output flags are 0. A control buffer that is null with a
    /// nonzero length is `WSAEFAULT`. On a stream `name` is ignored, as `recvfrom` documents for
    /// connection-oriented sockets, and `Control.len` comes back 0.
    unsafe fn wsa_recv(&self, fd: c_int, msg: *mut u8, extension: bool) -> Option<NetResult> {
        let (nonblocking, rec, dgram) = self.recv_state(fd)?;
        let msg = unsafe { &mut *msg.cast::<WsaMsg>() };
        if extension && !msg.Control.buf.is_null() && msg.Control.len == 0 {
            return err(WSAEFAULT);
        }
        if extension && !dgram {
            return err(WSAEINVAL);
        }
        let call = if extension {
            RecvCall::Msg
        } else {
            RecvCall::Wsa
        };
        let flags = msg.dwFlags as c_int;
        if let Err(code) = self.recv_flags(&rec, call, !dgram, nonblocking, flags) {
            return err(code);
        }
        let buffers = match unsafe { wsa_buffers(msg) } {
            Ok(buffers) => buffers,
            Err(code) => return err(code),
        };
        if msg.Control.buf.is_null() && msg.Control.len != 0 {
            return err(WSAEFAULT);
        }
        let total = buffers
            .iter()
            .fold(0usize, |n, b| n.saturating_add(b.len as usize));
        if !dgram {
            let mut data = vec![0u8; total];
            let (copied, reported) = self.stream_take(fd, &mut data, flags)?;
            unsafe { scatter(buffers, &data[..copied]) };
            let reported = match reported {
                Ok(reported) => reported,
                Err(code) => return err(code),
            };
            msg.Control.len = 0;
            msg.dwFlags = 0;
            return ok(reported as i64);
        }
        let need = if self.kind(fd).is_some_and(|k| k.v6) {
            28
        } else {
            16
        };
        if (msg.name.is_null() && msg.namelen != 0)
            || (!msg.name.is_null() && (msg.namelen.max(0) as usize) < need)
        {
            return err(WSAEFAULT);
        }
        let dg = match self.dgram_take(fd, flags)? {
            Ok(dg) => dg,
            Err(code) => return err(code),
        };
        let n = unsafe { scatter(buffers, &dg.data) };
        let truncated = dg.data.len() > total;
        if !msg.name.is_null() {
            let mut len = msg.namelen as u32;
            unsafe { write_addr(dg.src, msg.name.cast(), &mut len) };
            msg.namelen = len as i32;
        }
        if extension {
            let stamps: Vec<(c_int, c_int, Vec<u8>)> = win_sockopt::rx_stamp(&rec, dg.at)
                .map(|stamp| (SOL_SOCKET, SO_TIMESTAMP, stamp.to_ne_bytes().to_vec()))
                .into_iter()
                .collect();
            let cut = unsafe { write_cmsgs(msg, &stamps) };
            msg.dwFlags = self.msg_flags(&dg, truncated) | cut;
        } else {
            msg.Control.len = 0;
            msg.dwFlags = 0;
        }
        if truncated {
            return err(WSAEMSGSIZE);
        }
        ok(n as i64)
    }

    /// `WSASend`, `WSASendTo` and `WSASendMsg` on a sim socket: `msg`'s buffers gathered in order
    /// and sent as one `send` (the connected peer, or any stream, when `name` is null) or one
    /// datagram to `name`. `WSASendMsg` takes datagram sockets only and fails with `WSAEINVAL` on
    /// a stream (measured, tests/winsock_os_truth.rs `msg_calls_on_tcp_on_windows`); its control
    /// data may carry an `SO_TIMESTAMP_ID` (a `UINT32`), which asks for a transmit stamp while
    /// `SIO_TIMESTAMPING` has them on; other control messages (`IP_PKTINFO` source selection
    /// among them) fail with `WSAEOPNOTSUPP`. `MSG_OOB` is `WSAEOPNOTSUPP` as for `send`,
    /// and `MSG_PARTIAL` too ("returned by transports that do not support partial message
    /// transmissions", [Microsoft Learn: WSASend](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasend));
    /// `MSG_DONTROUTE` is ignored. A null `name` with a nonzero `namelen`, or a null control
    /// buffer with a nonzero length, is `WSAEFAULT` (WSASendMsg).
    unsafe fn wsa_send(
        &self,
        fd: c_int,
        msg: *const u8,
        flags: u32,
        extension: bool,
    ) -> Option<NetResult> {
        let (_, rec, dgram) = self.recv_state(fd)?;
        let msg = unsafe { &*msg.cast::<WsaMsg>() };
        if extension && !dgram {
            return err(WSAEINVAL);
        }
        if flags as c_int & (MSG_OOB | MSG_PARTIAL) != 0 {
            return err(WSAEOPNOTSUPP);
        }
        let buffers = match unsafe { wsa_buffers(msg) } {
            Ok(buffers) => buffers,
            Err(code) => return err(code),
        };
        if (msg.name.is_null() && msg.namelen != 0)
            || (msg.Control.buf.is_null() && msg.Control.len != 0)
        {
            return err(WSAEFAULT);
        }
        let data = unsafe { gather(buffers) };
        let tx_id = if extension {
            let controls = unsafe { read_cmsgs(msg) };
            if controls
                .iter()
                .any(|(level, ty, _)| *level != SOL_SOCKET || *ty != SO_TIMESTAMP_ID)
            {
                return err(WSAEOPNOTSUPP);
            }
            if controls.iter().any(|(_, _, data)| data.len() != 4) {
                return err(WSAEINVAL);
            }
            controls
                .first()
                .map(|(_, _, data)| u32::from_ne_bytes([data[0], data[1], data[2], data[3]]))
        } else {
            None
        };
        let flags = flags as c_int & !MSG_DONTROUTE;
        let sent = if msg.name.is_null() || !dgram {
            unsafe { self.send(fd, data.as_ptr(), data.len(), flags) }
        } else {
            let Some(dest) = (unsafe { parse_addr(msg.name.cast(), msg.namelen.max(0) as u32) })
            else {
                return err(WSAEFAULT);
            };
            self.udp_send(fd, data, dest)
        };
        if let (Some(id), Some(NetResult::Ok(_))) = (tx_id, &sent) {
            win_sockopt::note_tx_stamp(&rec, id, monotonic(&self.regs.shared));
        }
        sent
    }

    /// Duplicates handle `fd` (`WSADuplicateSocket`, which `std`'s `try_clone` uses): a new handle
    /// for the same socket, sharing its record, connection, queue or connect attempt, and recorded
    /// in the socket table as another descriptor of it.
    unsafe fn dup(&self, fd: c_int) -> Option<NetResult> {
        let mut socks = self.socks.lock().unwrap();
        let clone = match socks.get(&fd)? {
            Sock::Fresh {
                nonblocking,
                local,
                rec,
            } => Sock::Fresh {
                nonblocking: *nonblocking,
                local: *local,
                rec: rec.clone(),
            },
            Sock::Connecting {
                nonblocking,
                local,
                rec,
                dest,
                attempt,
            } => Sock::Connecting {
                nonblocking: *nonblocking,
                local: *local,
                rec: rec.clone(),
                dest: *dest,
                attempt: attempt.clone(),
            },
            Sock::Stream {
                conn,
                end,
                nonblocking,
                rec,
            } => Sock::Stream {
                conn: conn.clone(),
                end: *end,
                nonblocking: *nonblocking,
                rec: rec.clone(),
            },
            Sock::Listener {
                state,
                addr,
                nonblocking,
                rec,
            } => Sock::Listener {
                state: state.clone(),
                addr: *addr,
                nonblocking: *nonblocking,
                rec: rec.clone(),
            },
            Sock::Dgram {
                queue,
                domain,
                local,
                requested,
                peer,
                nonblocking,
                broadcast,
                rec,
            } => Sock::Dgram {
                queue: queue.clone(),
                domain: *domain,
                local: *local,
                requested: *requested,
                peer: *peer,
                nonblocking: *nonblocking,
                broadcast: *broadcast,
                rec: rec.clone(),
            },
        };
        let new_fd = self.mint();
        self.regs.shared.sockets.alias(new_fd, clone.rec());
        socks.insert(new_fd, clone);
        ok(new_fd as i64)
    }

    /// `select`
    /// ([Microsoft Learn: select](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-select)),
    /// served when every listed socket is the sim's. Sets with none of the sim's go to the OS,
    /// including the `WSAEINVAL` of three empty sets; sets that mix the sim's sockets with others
    /// fail with `WSAEOPNOTSUPP` (snare's choice), since neither side can wait on both and a sim
    /// handle must not reach Winsock. `nfds` is ignored, as on Windows. A null timeout waits
    /// indefinitely; `{0, 0}` polls. Connecting sockets among the sets advance before each check. A
    /// return that never waited is charged the call latency, so a busy select loop lets a discrete
    /// clock move.
    unsafe fn select(
        &self,
        _nfds: c_int,
        read: *mut u8,
        write: *mut u8,
        except: *mut u8,
        timeout: *const u8,
    ) -> Option<NetResult> {
        // MS select: each non-null set lists sockets and is cut down to those ready; a null
        // timeout blocks indefinitely. Decline unless every socket listed is ours.
        let ptrs = [read, write, except];
        let sets = ptrs.map(|p| (!p.is_null()).then(|| unsafe { read_fd_set(p) }));
        let listed: Vec<c_int> = sets.iter().flatten().flatten().copied().collect();
        let owned = {
            let socks = self.socks.lock().unwrap();
            listed.iter().filter(|fd| socks.contains_key(fd)).count()
        };
        if owned == 0 {
            return None;
        }
        if owned < listed.len() {
            return err(WSAEOPNOTSUPP);
        }
        let deadline = (!timeout.is_null()).then(|| {
            let tv = unsafe { timeout.cast::<Timeval>().read_unaligned() };
            Deadline::timeout(
                Duration::from_secs(tv.tv_sec.max(0) as u64)
                    + Duration::from_micros(tv.tv_usec.max(0) as u64),
            )
        });
        let mut waited = false;
        let mut last = deadline.is_some_and(|d| d.passed());
        loop {
            self.advance_connecting(Some(&listed));
            let found = self.select_ready(&sets);
            let total: usize = found.iter().map(Vec::len).sum();
            if total > 0 || last {
                for (p, ready) in ptrs.into_iter().zip(&found) {
                    if !p.is_null() {
                        unsafe { write_fd_set(p, ready) };
                    }
                }
                if !waited {
                    snare_interpose::charge_latency();
                }
                return ok(total as i64);
            }
            last = !readiness().wait_until_dynamic(
                "select",
                deadline,
                |keys| self.fd_interests(listed.iter().copied(), keys),
                || {
                    self.select_ready(&sets)
                        .iter()
                        .any(|ready| !ready.is_empty())
                        || self.connecting_due(Some(&listed))
                },
            );
            waited = true;
        }
    }

    /// `WSAPoll`
    /// ([Microsoft Learn: WSAPoll](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsapoll)),
    /// served when every entry is the sim's; an array with none of the sim's (or none at all) goes
    /// to the OS, and one that mixes them fails with `WSAEOPNOTSUPP`, as for `select`. A negative timeout waits indefinitely, 0 returns
    /// at once, a positive one waits that many milliseconds. Readiness per entry is
    /// [`WinNet::poll_revents`].
    unsafe fn poll(&self, fds: *mut u8, nfds: u64, timeout: c_int) -> Option<NetResult> {
        if fds.is_null() || nfds == 0 {
            return None;
        }
        let pfds =
            unsafe { std::slice::from_raw_parts_mut(fds.cast::<WsaPollfd>(), nfds as usize) };
        let owned = {
            let socks = self.socks.lock().unwrap();
            pfds.iter()
                .filter(|p| c_int::try_from(p.fd).is_ok_and(|fd| socks.contains_key(&fd)))
                .count()
        };
        if owned == 0 {
            return None;
        }
        if owned < pfds.len() {
            return err(WSAEOPNOTSUPP);
        }
        let deadline = (timeout >= 0)
            .then(|| Deadline::timeout(std::time::Duration::from_millis(timeout as u64)));
        let collect = |pfds: &mut [WsaPollfd]| -> i64 {
            let mut n = 0;
            for p in pfds.iter_mut() {
                p.revents = self.poll_revents(p.fd as c_int, p.events);
                if p.revents != 0 {
                    n += 1;
                }
            }
            n
        };
        // A return that never blocked — sockets already ready, or a zero timeout — is a busy-poll
        // step when repeated, so it is charged the call latency.
        let fds: Vec<c_int> = pfds.iter().map(|p| p.fd as c_int).collect();
        let mut waited = false;
        loop {
            self.advance_connecting(Some(&fds));
            let n = collect(pfds);
            if n > 0 {
                if !waited {
                    snare_interpose::charge_latency();
                }
                return ok(n);
            }
            if timeout == 0 {
                snare_interpose::charge_latency();
                return ok(0);
            }
            let woke = readiness().wait_until_dynamic(
                "WSAPoll",
                deadline,
                |keys| self.fd_interests(fds.iter().copied(), keys),
                || {
                    pfds.iter()
                        .any(|p| self.poll_revents(p.fd as c_int, p.events) != 0)
                        || self.connecting_due(Some(&fds))
                },
            );
            if !woke {
                self.advance_connecting(Some(&fds));
                return ok(collect(pfds));
            }
            waited = true;
        }
    }

    // npcap raw-L2 (wpcap.dll), matching ethercrab's Windows transport: open a device, send whole
    // frames (via the send-queue path), and read them back on every handle open on the device,
    // the sender's included.
    /// `pcap_open_live`/`pcap_create` on `device` (null for none): a new capture handle with an
    /// empty receive queue. Every open succeeds; the device is matched by name only when frames are
    /// sent.
    unsafe fn pcap_open(&self, device: *const c_char) -> Option<NetResult> {
        let dev = if device.is_null() {
            Vec::new()
        } else {
            unsafe { std::ffi::CStr::from_ptr(device) }
                .to_bytes()
                .to_vec()
        };
        let handle = self.next_pcap.fetch_add(1, Ordering::Relaxed);
        self.pcaps.lock().unwrap().insert(
            handle,
            PcapHandle {
                device: dev,
                rx: VecDeque::new(),
                last_frame: Vec::new(),
                last_hdr: vec![0u8; 16],
            },
        );
        ok(handle as i64)
    }

    /// Any configuration call (`pcap_setnonblock`, `pcap_set_immediate_mode`, …) on a sim handle
    /// succeeds and changes nothing: the sim's captures are always nonblocking and immediate.
    fn pcap_configure(&self, handle: u64) -> Option<NetResult> {
        if self.pcaps.lock().unwrap().contains_key(&handle) {
            ok(0)
        } else {
            None
        }
    }

    /// `pcap_sendpacket` and the send-queue path: one whole Ethernet frame. When the device names
    /// an interface of the topology, its link decides: an error fails the send, a dropped frame is
    /// counted as sent but reaches no one. Delivered frames are queued on every handle open on the
    /// same device name. Frames are written to the pcapng capture unless the send failed.
    unsafe fn pcap_send(&self, handle: u64, buf: *const u8, len: usize) -> Option<NetResult> {
        let frame = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
        let dev = self
            .pcaps
            .lock()
            .unwrap()
            .get(&handle)
            .map(|h| h.device.clone())?;
        let name = String::from_utf8_lossy(&dev).into_owned();
        let index = self.regs.shared.topo().index_of(&name);
        let sent = index.map(|index| self.regs.shared.raw_send(index, len));
        if !matches!(sent, Some(Err(_))) {
            self.regs.shared.capture_l2_named(&name, &frame);
        }
        match sent {
            Some(Err(code)) => return err(code),
            Some(Ok(false)) => return ok(len as i64),
            _ => {}
        }
        let mut pcaps = self.pcaps.lock().unwrap();
        // The shared L2 medium. A sent frame comes back on the sending capture too, as ethercrab's
        // Windows transport observes ("We receive our own sent frames", src/std/windows.rs), so
        // deliver to every handle on the device, this one included.
        for h in pcaps.values_mut() {
            if h.device == dev {
                h.rx.push_back(frame.clone());
            }
        }
        drop(pcaps);
        self.regs.shared.bump_keys(&[]);
        ok(len as i64)
    }

    /// `pcap_next_ex`: 1 with the next queued frame, or 0 when none waits, the nonblocking return
    /// ([pcap_setnonblock(3PCAP)](https://www.tcpdump.org/manpages/pcap_setnonblock.3pcap.html)).
    /// The header's timestamp is left zero.
    unsafe fn pcap_next(
        &self,
        handle: u64,
        header: *mut *mut u8,
        data: *mut *const u8,
    ) -> Option<NetResult> {
        let mut pcaps = self.pcaps.lock().unwrap();
        let h = pcaps.get_mut(&handle)?;
        let Some(frame) = h.rx.pop_front() else {
            // Non-blocking (ethercrab sets non-block): no packet now reads as a timeout (0).
            return ok(0);
        };
        // pcap_pkthdr: ts(8, left zero) then caplen@8 and len@12, both the frame length.
        let fl = frame.len() as u32;
        h.last_hdr = vec![0u8; 16];
        h.last_hdr[8..12].copy_from_slice(&fl.to_ne_bytes());
        h.last_hdr[12..16].copy_from_slice(&fl.to_ne_bytes());
        h.last_frame = frame;
        unsafe {
            *header = h.last_hdr.as_mut_ptr();
            *data = h.last_frame.as_ptr();
        }
        ok(1)
    }

    /// `pcap_close`: forgets the handle and its queued frames.
    fn pcap_close(&self, handle: u64) -> Option<NetResult> {
        if self.pcaps.lock().unwrap().remove(&handle).is_some() {
            ok(0)
        } else {
            None
        }
    }
}

/// The `int`/`DWORD` option value at `val`, or 0 when it is null or shorter than 4 bytes.
///
/// # Safety
/// `val` is null or points to `len` readable bytes.
unsafe fn read_int(val: *const u8, len: u32) -> c_int {
    if val.is_null() || (len as usize) < size_of::<c_int>() {
        return 0;
    }
    unsafe { val.cast::<c_int>().read_unaligned() }
}

/// Parses an `IP_ADD_MEMBERSHIP`/`IPV6_ADD_MEMBERSHIP` option: `ip_mreq` is the group then the
/// interface address, `ipv6_mreq` the group then the interface index (MS `ip_mreq`, `ipv6_mreq`;
/// [Microsoft Learn: IP_MREQ](https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-ip_mreq);
/// [Microsoft Learn: IPV6_MREQ](https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-ipv6_mreq)).
/// An IPv4 interface of `0.0.0.0` and an IPv6 index of 0 both mean the default interface. An
/// `imr_interface` in 0.x.x.x, which the IP_MREQ page says names an interface index, is kept as
/// an address. `None` for any other option or a value too short.
///
/// # Safety
/// `val` is null or points to `len` readable bytes.
unsafe fn parse_add_membership(
    level: c_int,
    name: c_int,
    val: *const u8,
    len: u32,
) -> Option<Membership> {
    if val.is_null() {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(val, len as usize) };
    if level == IPPROTO_IP && name == IP_ADD_MEMBERSHIP && bytes.len() >= 4 {
        let group = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
        let interface = bytes
            .get(4..8)
            .map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            .filter(|a| !a.is_unspecified());
        return Some(Membership {
            group: IpAddr::V4(group),
            interface_addr: interface.map(IpAddr::V4),
            ifindex: 0,
        });
    }
    if level == IPPROTO_IPV6 && name == IPV6_ADD_MEMBERSHIP && bytes.len() >= 16 {
        let mut o = [0u8; 16];
        o.copy_from_slice(&bytes[..16]);
        let ifindex = bytes
            .get(16..20)
            .map_or(0, |b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]));
        return Some(Membership {
            group: IpAddr::V6(Ipv6Addr::from(o)),
            interface_addr: None,
            ifindex,
        });
    }
    None
}

/// Reads a `struct linger` (MS `linger`: `u_short l_onoff`, `u_short l_linger` in seconds;
/// [Microsoft Learn: LINGER](https://learn.microsoft.com/en-us/windows/win32/api/winsock/ns-winsock-linger)).
/// `None` when lingering is off (`l_onoff` 0) or the value is short; `Some(0)` asks for an
/// abortive close.
///
/// # Safety
/// `val` is null or points to `len` readable bytes.
unsafe fn parse_linger(val: *const u8, len: u32) -> Option<Duration> {
    if val.is_null() || len < 4 {
        return None;
    }
    let onoff = unsafe { val.cast::<u16>().read_unaligned() };
    let secs = unsafe { val.add(2).cast::<u16>().read_unaligned() };
    (onoff != 0).then(|| Duration::from_secs(secs.into()))
}

/// Reads a `SOCKADDR_IN`/`SOCKADDR_IN6` from `ptr`. The sockaddr layout is the BSD-sockets ABI
/// shared across platforms; only the IPv6 family tag differs (23 on Windows). Port and address are
/// network byte order.
///
/// A `SOCKADDR_IN` is 16 bytes (family, port at 2, address at 4), of which the first 8 are
/// required; a `SOCKADDR_IN6` is 28 (family, port at 2, flow info at 4, address at 8, scope id at
/// 24), all required. Flow info and scope id are ignored
/// ([Microsoft Learn: SOCKADDR_IN](https://learn.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-sockaddr_in);
/// [Microsoft Learn: SOCKADDR_IN6](https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-sockaddr_in6_lh)).
///
/// # Safety
/// `ptr` is null or points to `len` readable bytes.
unsafe fn parse_addr(ptr: *const u8, len: u32) -> Option<SocketAddr> {
    if ptr.is_null() || (len as usize) < 4 {
        return None;
    }
    let family = unsafe { ptr.cast::<u16>().read_unaligned() } as c_int;
    match family {
        AF_INET => {
            if (len as usize) < 8 {
                return None;
            }
            let port = u16::from_be(unsafe { ptr.add(2).cast::<u16>().read_unaligned() });
            let mut o = [0u8; 4];
            unsafe { std::ptr::copy_nonoverlapping(ptr.add(4), o.as_mut_ptr(), 4) };
            Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(o), port)))
        }
        AF_INET6 => {
            if (len as usize) < 28 {
                return None;
            }
            let port = u16::from_be(unsafe { ptr.add(2).cast::<u16>().read_unaligned() });
            let mut o = [0u8; 16];
            unsafe { std::ptr::copy_nonoverlapping(ptr.add(8), o.as_mut_ptr(), 16) };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(o),
                port,
                0,
                0,
            )))
        }
        _ => None,
    }
}

/// Writes `addr` as a `SOCKADDR_IN` or `SOCKADDR_IN6` into the caller's buffer of `*out_len`
/// bytes, truncated to fit, and stores the full size in `*out_len`. A short buffer is truncated
/// rather than failed with `WSAEFAULT` as Winsock would. Nothing is written when either pointer
/// is null.
///
/// # Safety
/// `out` and `out_len` are null or valid for the caller's declared length.
unsafe fn write_addr(addr: SocketAddr, out: *mut u8, out_len: *mut u32) {
    if out.is_null() || out_len.is_null() {
        return;
    }
    let cap = unsafe { *out_len } as usize;
    match addr {
        SocketAddr::V4(v4) => {
            let mut buf = [0u8; 16];
            buf[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
            buf[2..4].copy_from_slice(&v4.port().to_be_bytes());
            buf[4..8].copy_from_slice(&v4.ip().octets());
            let n = cap.min(16);
            unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), out, n) };
            unsafe { *out_len = 16 };
        }
        SocketAddr::V6(v6) => {
            let mut buf = [0u8; 28];
            buf[0..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
            buf[2..4].copy_from_slice(&v6.port().to_be_bytes());
            buf[8..24].copy_from_slice(&v6.ip().octets());
            let n = cap.min(28);
            unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr(), out, n) };
            unsafe { *out_len = 28 };
        }
    }
}

/// Writes a 4-byte option value, truncated to the caller's `*len`, and stores 4 in `*len`. A short
/// buffer is truncated where getsockopt documents `WSAEFAULT` for an `optlen` that is too small
/// ([Microsoft Learn: getsockopt](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getsockopt)).
///
/// # Safety
/// `val` and `len` are null or valid for the caller's declared length.
unsafe fn write_opt(value: i32, val: *mut u8, len: *mut u32) {
    if val.is_null() || len.is_null() {
        return;
    }
    let cap = unsafe { *len } as usize;
    let n = size_of::<i32>().min(cap);
    unsafe {
        std::ptr::copy_nonoverlapping(value.to_ne_bytes().as_ptr(), val, n);
        *len = size_of::<i32>() as u32;
    }
}

/// Writes an option value of any size: a 4-byte one as [`write_opt`] writes a `DWORD`, a longer
/// or empty one copied up to the caller's `*len`, with `*len` set to the bytes written.
///
/// # Safety
/// `val` and `len` are null or valid for the caller's declared length.
unsafe fn write_bytes(bytes: &[u8], val: *mut u8, len: *mut u32) {
    if let Ok(dword) = <[u8; 4]>::try_from(bytes) {
        return unsafe { write_opt(i32::from_ne_bytes(dword), val, len) };
    }
    if len.is_null() {
        return;
    }
    let n = bytes.len().min(unsafe { *len } as usize);
    if !val.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), val, n) };
    }
    unsafe { *len = n as u32 };
}

/// The per-sim address registry: where datagrams and connects to an address go. Testers reach the
/// one of the `Sim` they were built in through the thread-local scope below.
pub(crate) struct Registries {
    /// The address book. Taken after the handle table, never before it.
    reg: Mutex<Registry>,
    /// The sim's shared state: topology, routes, link policies, faults, capture and clock.
    pub(crate) shared: Arc<SimShared>,
}

impl Registries {
    /// Locks the address book. Poisoning panics: a panic while it was held means a fabric bug.
    fn lock(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.reg.lock().unwrap()
    }

    /// Delivers one datagram from `src` to every queue `dest` reaches, through the links it
    /// crosses and each receiving address's link policy.
    /// Returns how many sockets and endpoints it reached, lost on the way or not.
    fn deliver(&self, sender: &Sender, src: SocketAddr, dest: SocketAddr, data: &[u8]) -> usize {
        let sent = monotonic(&self.shared);
        let (cands, station) = {
            let reg = self.lock();
            (reg.candidates(dest), reg.station_at(dest.ip()))
        };
        let copies = self.shared.fan_out(
            sender,
            Wire {
                src,
                dest,
                len: data.len(),
            },
            station,
            cands,
            true,
        );
        let reached = copies.len();
        for copy in copies {
            if let Some(rec) = &copy.q.rec {
                if copy.delays.is_empty() {
                    rec.count_wire_lost();
                } else {
                    rec.note_rx_nic(copy.nic.as_deref());
                }
            }
            for delay in copy.delays {
                copy.q.push_after(
                    (src, dest),
                    sent,
                    data.to_vec(),
                    delay,
                    copy.via.clone(),
                    self.shared.domain_key(),
                );
            }
        }
        reached
    }
}

thread_local! {
    /// The registries of the sim the thread runs in, set by [`enter`].
    static CURRENT: std::cell::RefCell<Option<Arc<Registries>>> = const { std::cell::RefCell::new(None) };
}

/// Installs `regs` as the calling thread's current registries until the guard drops. `Sim::run`
/// wraps the test body in this so testers built there reach this sim's registries.
pub(crate) fn enter(regs: Arc<Registries>) -> RegistryGuard {
    let previous = CURRENT.with(|c| c.replace(Some(regs)));
    RegistryGuard { previous }
}

/// Restores the thread's previous registries on drop, so nested scopes unwind in order.
pub(crate) struct RegistryGuard {
    previous: Option<Arc<Registries>>,
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        CURRENT.with(|c| *c.borrow_mut() = self.previous.take());
    }
}

/// The registries of the `Sim` the calling thread runs in, for a tester to keep once it leaves
/// that thread.
pub(crate) fn registries_here() -> Arc<Registries> {
    try_registries_here().expect("snare tester functions must be called inside Sim::run")
}

/// The registries of the `Sim` the calling thread runs in, if it runs in one.
pub(crate) fn try_registries_here() -> Option<Arc<Registries>> {
    CURRENT.with(|c| c.borrow().clone())
}

/// Gives every thread the sim starts this sim's registries, as `Sim::run` gives its own thread, so
/// testers, link policies and other tester-side calls work from any thread of the test.
pub(crate) struct ScopeLayer(pub(crate) Arc<Registries>);

impl snare_interpose::Layer for ScopeLayer {
    fn thread_started(&self) {
        // The scope lasts as long as the thread does.
        std::mem::forget(enter(self.0.clone()));
    }
}

/// Registers (and returns) the peer listener for `addr`, replacing any earlier one.
pub(crate) fn listen_at(addr: SocketAddr) -> Arc<Listener> {
    let listener = Arc::new(Listener {
        tester: true,
        capacity: AtomicUsize::new(usize::MAX),
        ..Listener::default()
    });
    let regs = registries_here();
    snare_interpose::real(|| regs.lock().listeners.insert(addr, listener.clone()));
    listener
}

/// Withdraws `listener`, so later connects to its address are refused (WSAECONNREFUSED).
pub(crate) fn unlisten(regs: &Registries, listener: &Arc<Listener>) {
    snare_interpose::real(|| {
        regs.lock()
            .listeners
            .retain(|_, l| !Arc::ptr_eq(l, listener))
    });
}

impl ListenerState {
    fn reserve(self: &Arc<Self>) -> Option<ListenerAdmission> {
        let mut used = self.occupied.load(Ordering::Acquire);
        loop {
            if used >= self.capacity.load(Ordering::Acquire) {
                return None;
            }
            match self.occupied.compare_exchange_weak(
                used,
                used + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ListenerAdmission {
                        listener: self.clone(),
                        reserved: true,
                    });
                }
                Err(current) => used = current,
            }
        }
    }
    fn wake_key(&self) -> Option<crate::readiness::WakeKey> {
        self.rec.as_ref()?.upgrade().map(|rec| rec.wake_key())
    }

    /// Takes the next connection, or `None` if none is waiting.
    pub(crate) fn try_accept(&self) -> Option<Arc<Conn>> {
        snare_interpose::real(|| {
            let conn = self.pending.lock().unwrap().pop_front()?;
            self.occupied.fetch_sub(1, Ordering::AcqRel);
            Some(conn)
        })
    }

    /// Whether a connection is waiting to be accepted.
    pub(crate) fn has_pending(&self) -> bool {
        snare_interpose::real(|| !self.pending.lock().unwrap().is_empty())
    }
}

struct ListenerAdmission {
    listener: Arc<ListenerState>,
    reserved: bool,
}

impl ListenerAdmission {
    fn queue(mut self, conn: Arc<Conn>) {
        self.listener.pending.lock().unwrap().push_back(conn);
        self.reserved = false;
    }
}

impl Drop for ListenerAdmission {
    fn drop(&mut self) {
        if self.reserved {
            self.listener.occupied.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// The peer (accepting) side of a connection, driven by a tester. Runs under passthrough like the
/// rest of `WinNet`: waits on its locks are the sim's business, not the code under test's.
impl Conn {
    /// Writes what the window has room for; 0 once the stream is closed.
    pub(crate) fn write_from_peer(&self, bytes: &[u8]) -> usize {
        snare_interpose::real(|| self.write(End::B, bytes).unwrap_or(0))
    }

    /// Whether a peer's write of `len` bytes would take some of them, or fail at once.
    pub(crate) fn peer_can_write(&self, len: usize) -> bool {
        snare_interpose::real(|| self.write_pipe(End::B).can_write(len))
    }

    /// Reads what the code under test sent: 0 at end of stream, `ConnectionReset` after a reset,
    /// and `WouldBlock` when nothing has arrived yet.
    pub(crate) fn read_from_peer(&self, out: &mut [u8]) -> std::io::Result<usize> {
        snare_interpose::real(|| match self.read_pipe(End::B).read(out) {
            Read::Data(n) => Ok(n),
            Read::Eof => Ok(0),
            Read::Reset => Err(std::io::ErrorKind::ConnectionReset.into()),
            Read::WouldBlock | Read::Shut => Err(std::io::ErrorKind::WouldBlock.into()),
        })
    }

    /// Closes the peer's sending direction; the code under test reads end of stream after the
    /// bytes already sent.
    pub(crate) fn close_peer(&self) {
        snare_interpose::real(|| self.close(End::B));
    }

    /// Aborts the connection with a reset: the code under test's next read or write fails with
    /// WSAECONNRESET.
    pub(crate) fn reset_peer(&self) {
        snare_interpose::real(|| self.reset(End::B));
    }

    /// Whether the peer has bytes to read or has seen the code under test close its end.
    pub(crate) fn peer_readable(&self) -> bool {
        snare_interpose::real(|| self.read_pipe(End::B).readable_or_closed())
    }
}

/// A datagram endpoint a tester owns at a fixed address; see the fabric's `UdpEndpoint`.
pub(crate) struct UdpEndpoint {
    /// The registries of the sim the endpoint was bound in.
    regs: Arc<Registries>,
    /// The address it is bound at, also its source address.
    addr: SocketAddr,
    /// Its receive queue, as registered in [`Registry::udp`].
    queue: Arc<DgramQueue>,
}

impl UdpEndpoint {
    /// Binds `addr`; panics if a socket or another tester already holds it.
    pub(crate) fn bind(regs: Arc<Registries>, addr: SocketAddr) -> Self {
        let queue = Arc::new(DgramQueue::default());
        snare_interpose::real(|| {
            let mut reg = regs.lock();
            assert!(
                !reg.udp.contains_key(&addr),
                "udp tester address {addr} is already bound"
            );
            reg.udp.insert(addr, queue.clone());
        });
        UdpEndpoint { regs, addr, queue }
    }

    /// The next datagram that has arrived, with its source, if any.
    pub(crate) fn try_recv(&self) -> Option<(SocketAddr, Vec<u8>)> {
        snare_interpose::real(|| self.queue.pop(|_| true).map(|dg| (dg.src, dg.data)))
    }

    /// Whether a datagram has arrived.
    pub(crate) fn has_pending(&self) -> bool {
        snare_interpose::real(|| self.queue.has(|_| true))
    }

    /// Sends one datagram to `dest` from this endpoint's address. One nothing takes counts in
    /// the host's UDP counters when it was the host's to take.
    pub(crate) fn send_to(&self, dest: SocketAddr, data: &[u8]) {
        snare_interpose::real(|| {
            let sender = Sender::Station(self.addr.ip());
            self.regs
                .shared
                .capture_udp(&sender, self.addr, dest, Dir::In, data, None);
            if self.regs.deliver(&sender, self.addr, dest, data) == 0 {
                let station = self.regs.lock().station_at(dest.ip());
                self.regs.shared.count_unreceived(dest, station);
            }
        });
    }
}

/// Unbinds the address, unless something else was bound there since.
impl Drop for UdpEndpoint {
    fn drop(&mut self) {
        snare_interpose::real(|| {
            let mut reg = self.regs.lock();
            if reg
                .udp
                .get(&self.addr)
                .is_some_and(|q| Arc::ptr_eq(q, &self.queue))
            {
                reg.udp.remove(&self.addr);
            }
        });
    }
}
