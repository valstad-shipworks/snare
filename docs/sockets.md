# Sockets

## Socket faults and back-pressure

Faults on the code under test's sockets, with the host OS's codes and the order its kernel reports
them in. Every call works from any thread of a sim; the `Sim` methods of the same names also work
outside `run`.

| Call | Effect |
|---|---|
| `raise_socket_error(addr, io::Error)` | Makes the error pending on every stream whose local or peer address is `addr` and every datagram socket bound at or connected to it. A raw OS error passes as given; a kind maps to the host's code (`ConnectionReset` `ECONNRESET`/`WSAECONNRESET`, `BrokenPipe` `EPIPE`/`WSAESHUTDOWN`, ...); a kind with none panics. |
| `inject_icmp_port_unreachable(to, from)` | An ICMP port unreachable from `from` reaches the datagram sockets bound at `to`. |
| `quiesce(addr, span, Direction)` | Holds what arrives at (`Receive`), leaves (`Send`) or crosses (`Both`) `addr` for `span` of sim time: TCP bytes in flight and written meanwhile, and a FIN, land in order once it ends (counting against the window); bytes already received stay readable; datagrams arrive at its end. |
| `SO_SNDBUF` / `SO_RCVBUF` | Bound every stream of the code under test: what is in flight plus unread is capped at the reader's receive room plus the writer's send buffer (see [Socket limits and privileges](#socket-limits-and-privileges)). |
| `TcpPolicy::recv_window` | The receive window of the endpoint at the policy's address, capping its receive room below its `SO_RCVBUF` (a tester's endpoint, unlimited otherwise, takes the window alone). |
| `SO_LINGER` | A zero timeout makes the last close abort with a reset (the peer reads `ECONNRESET`, a tester logs `PeerReset`); another makes it wait, up to that long, until what was written has crossed. macOS also takes `SO_LINGER_SEC` (std and socket2 use it; its `SO_LINGER` counts 1/100 s ticks); Windows `SO_DONTLINGER`, and a nonblocking close with data still crossing fails with `WSAEWOULDBLOCK`. |
| `TesterAction::RaiseSocketError(e)` / `IcmpPortUnreachable` / `QuiesceLink(span, dir)` / `SetRecvWindow(w)` | The same for the code under test's end the event came from (every peer from a cyclic action); `QuiesceLink`'s direction is seen from the code under test. |

| OS | Raised error reported | ICMP port unreachable | Writable on a bounded stream |
|---|---|---|---|
| Linux | first by a send; a stream's receive returns queued bytes first, a datagram socket's the error first | `ECONNREFUSED` to the next send or receive of a socket connected to the sender; an unconnected one only with `IP_RECVERR`, which also queues a `sock_extended_err` (origin ICMP, type 3, code 3, the offender's address) for `recvmsg(MSG_ERRQUEUE)` | free space at least half of what is queued |
| macOS | first by a send; a receive returns queued bytes first (`MSG_PEEK` leaves the error pending) | `ECONNREFUSED` to a socket connected to the sender; an unconnected one ignores it | 2048 bytes free (`SO_SNDLOWAT`); `EVFILT_WRITE` reports the free space |
| Windows | first by any call | `WSAECONNRESET` in receive arrival order alongside queued datagrams, for a connected or unconnected socket unless `WSAIoctl(SIO_UDP_CONNRESET, FALSE)`; `MSG_PEEK` preserves the status; `SO_ERROR` does not return or consume this status | any free space |

Reporting clears the error, as `getsockopt(SO_ERROR)` does; while it is pending a blocked call
returns at once, epoll and poll report `EPOLLERR`/`POLLERR` (macOS poll and kqueue: readable),
`WSAPoll` `POLLERR` and select the read set. Windows ICMP receive status instead reports
`WSAPoll` readability and is consumed by a receive without `MSG_PEEK`, leaving `SO_ERROR` zero. A datagram sent to an address the host or a station
holds that reaches no socket or tester draws an ICMP error one round trip later (the policies'
fixed latency each way, no jitter, so seeds replay); broadcast, multicast and absent addresses draw
none. A full window makes a blocking send wait for room, up to `SO_SNDTIMEO` (then the bytes sent
so far, else `EAGAIN`/`WSAETIMEDOUT`), and a nonblocking one return what fit or
`EAGAIN`/`WSAEWOULDBLOCK`: on Linux what fits, on macOS nothing until 2048 bytes (`SO_SNDLOWAT`)
are free unless the whole write fits, on Windows the whole write while anything is free. A
tester's writes queue until the window takes them, and its close
waits for them.

## Connect faults

A connect asks the destination how it answers a SYN, as the host OS would:

- a listener there (the code under test's or a tester's) accepts at once;
- an address of the host or a station with no listener resets the SYN: `ECONNREFUSED` at once on
  unix; Windows retries on a reset and reports `WSAECONNREFUSED` 2 s later;
- an address nobody holds stays silent, and the connect follows the OS's SYN plan — Linux
  retransmits at 1, 2, 3, 4, 5, 7, 11, … s and gives up at 131 s with the modern default
  `SysLimits::tcp_syn_linear_timeouts` of 4. Setting it to 0 selects the older exponential
  schedule and 127 s timeout. `SysLimits::tcp_syn_retries` or the socket's `TCP_SYNCNT` sets
  the retry limit; both sysctls are exposed by `SimHost` under `/proc/sys/net/ipv4`.
  `SysLimits::from_real_host` reads the running kernel's settings. macOS retransmits at
  1, 2, 3, 4, 5, 7, 11, … s and gives up at 75 s
  (`TCP_CONNECTIONTIMEOUT`); Windows retransmits at 3 and 9 s and gives up at 21 s by default.
  Extending `TCP_MAXRT` continues with exponentially increasing intervals capped at 60 s;
  setting it to -1 keeps retrying until the connection completes or closes,
  each with `ETIMEDOUT`/`WSAETIMEDOUT`. On Linux an absent address on a connected subnet fails for
  want of a neighbour instead, with `EHOSTUNREACH` after 3 s; macOS (measured) and Windows follow
  their SYN plans there too;
- a listener that appears meanwhile is reached at the next retransmission.

While an open sim (no interface given an address) still lets the code under test bind any address,
only addresses it has bound, loopback and stations answer; a connect to any other address times
out — at once in virtual time, but for real under `wall_clock()`.

```rust,no_run
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};
use snare::{ListenerBehavior, Sim, set_listener_behavior};

Sim::new().run(|| {
    let _listener = TcpListener::bind("127.0.0.7:7000").unwrap();
    let until = Instant::now() + Duration::from_millis(1500);
    set_listener_behavior("127.0.0.7:7000", ListenerBehavior::DelayingUntil(until));
    TcpStream::connect("127.0.0.7:7000").unwrap(); // at the next SYN retransmission
    let err = TcpStream::connect_timeout(&"10.255.0.1:80".parse().unwrap(), Duration::from_secs(5));
    assert_eq!(err.unwrap_err().kind(), std::io::ErrorKind::TimedOut); // 5 s of virtual time
});
```

| Call | Effect |
|---|---|
| `set_listener_behavior(addr, b)` / `Sim::set_listener_behavior` | How `addr` answers from then on, kept per address (the wildcard covers its port), before or after anything listens there and across listener replacement. `DelayingUntil` reads its `Instant` on the calling thread's clock; the `Sim` method, called off the sim, takes it as that far ahead of the sim's clock. |
| `TesterAction::SetListenerBehavior(b)` | The same for the tester's own address. |

A nonblocking connect that cannot finish at once fails with `EINPROGRESS` (`WSAEWOULDBLOCK`); a
second connect meanwhile gives `EALREADY` and one after it succeeded `EISCONN`. The socket reports
nothing to `poll`/`epoll`/`kqueue`/`select` until it is settled: writable once connected, or
`POLLOUT | POLLERR | POLLHUP` (`EPOLLERR`, `EVFILT_WRITE` with `EV_EOF` and the error in `fflags`,
Windows `exceptfds` and `WSAPoll` `POLLERR | POLLHUP`) once it failed, the error waiting in
`SO_ERROR`. Each point of the plan is a timer the sim can skip to, dropped when the connect settles
or the socket closes.

## Socket table

Every socket the code under test opens — fabric TCP and UDP, raw L2, Winsock, a `SimHost`'s UDP and
netlink sockets — gets one record for its whole life. Supported duplicate operations share that
record; `accept` makes a new one. Unix socket aliases created by `dup`, `F_DUPFD`,
`F_DUPFD_CLOEXEC`, `dup2`, Linux `dup3` or `try_clone` share socket state; close-on-exec flags
belong to each descriptor. Replacement updates ownership across socket and virtual-file backends.
Linux eventfd/epoll aliases also share their counter and interest state; closing the last alias
retires the description. Remaining descriptor boundaries are listed in [open bugs](../OPEN_BUGS.md).
`snare::socket_id(&sock)`
names any std or mio socket of the calling thread's sim (`None` for a real OS socket), and
`socket_entry(id)`, `socket_table()` (open, oldest first), `closed_sockets()` (in close order) and
`sockets_bound(addr)` read snapshots, as do the `Sim` methods of the same names from any thread.

| Field | Meaning |
|---|---|
| `id` | Numbered from 1 per sim in creation order and never reused. Ids are per sim: two sims both start at 1. |
| `kind` | `Udp`, `TcpStream` (unconnected, connected or accepted), `TcpListener`, `Packet`, `Netlink`, `Unix` (a `socketpair` end). |
| `local` / `peer` / `listener` | Where it is bound and connected, and for an accepted stream its listener's id. |
| `memberships` | Multicast groups joined, with the interface address or index the join named. |
| `queued` / `queued_bytes` | Datagrams (UDP) or written chunks (TCP) that have arrived and wait to be read. |
| `delivered` / `delivered_bytes` / `sent` | What arrived at it, and its successful sends. |
| `pending_error` | The pending socket error or receive status. `SO_ERROR` returns and clears socket errors; Windows ICMP receive status is returned only by a receive. |
| `created_at` / `closed_at` | On the sim's timeline, like recorded events. |
| `interface` / `bound_device` / `multicast_if` | The interface its latest traffic crossed, the one it is bound to, and the one its multicast leaves through. |
| `last_tx_nic` / `last_rx_nic` | The interface its latest datagram or connection left by and arrived on (a connection notes both when it is made). |
| `unmodelled_options` | Each `setsockopt`/`getsockopt`/`ioctl` the sim does not model that was used on it, once, in first-use order. See [Unmodelled options](#unmodelled-options-and-strict_sockopts). |

Per-socket options (`SO_RCVTIMEO`, `SO_SNDTIMEO`, `SO_LINGER`, `SO_REUSEADDR`) live in the record, so
every descriptor of a socket sees the same values. Where the hosts differ, the sim follows the one it
runs on, as measured: a blocking `accept` honours `SO_RCVTIMEO` on Linux only; after `SHUT_RD` Linux
still delivers what arrives while macOS reads end of stream at once and Windows fails reads with
`WSAESHUTDOWN`; and a bind overlapping a wildcard or equal address follows each OS's
`SO_REUSEADDR`, `SO_REUSEPORT` and `SO_EXCLUSIVEADDRUSE` rules, across IPv4, IPv6, v4-mapped and
dual-stack binds (`tests/bind_os_truth.rs`, `tests/dual_stack_os_truth.rs` and
`tests/reuseport_os_truth.rs` compare the sim against the host).

On macOS, TCP read shutdown discards queued receive bytes. Subsequent incoming data closes
that endpoint at its arrival time and returns a reset after the reverse link delay. The local
endpoint writes with `EPIPE`; the peer retains previously received bytes, then reports
`ECONNRESET` once before EOF. `MSG_PEEK` preserves that error, `SO_ERROR` consumes it, and
kqueue EOF events carry the pending error in `fflags`. The native comparisons and exact
link-delay tests are in `tests/macos_tcp_read_shutdown*.rs`; Unix socket pairs do not send
TCP resets.

The data/reset exchange samples both link delays when it is scheduled. Directed stalls and
carrier outages can delay either delivery, including when the connection is inspected later.

## Packet timestamps

A socket that asks for kernel timestamps gets them from the sim's clock, on the plain `Sim`'s
fabric and under a `SimHost` alike, through one implementation (`tstamp.rs`) that keeps each
socket's timestamping state in its socket record. A packet is stamped at the instant it reaches
the receiving socket — its send time plus the link delay it crossed — so code that reads it late
still sees when it arrived, as with a real kernel's software receive stamp. Every stamp reports
`CLOCK_REALTIME` except where the option says otherwise; a clock that jumps is moved up to a stamp it
hands out, so no later clock read is earlier. What each host does was measured against it
(`tests/timestamps.rs`, the `*_os_truth` tests); Windows follows
[Microsoft Learn: Winsock timestamping](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-timestamping)
(`tests/timestamps_win.rs`).

| Host | Options | What the code under test reads |
|---|---|---|
| Linux | `SO_TIMESTAMP`, `SO_TIMESTAMPNS`, `SO_TIMESTAMPING` (flags or `struct so_timestamping`) | `recvmsg` on UDP and TCP: `SCM_TIMESTAMP` (`timeval`) or `SCM_TIMESTAMPNS` (`timespec`), then `SCM_TIMESTAMPING` with the software stamp in `ts[0]` when `SOF_TIMESTAMPING_SOFTWARE` reports it (`OPT_RX_FILTER` honoured); a TCP read gets the arrival of the last byte it took. Transmit stamps on `MSG_ERRQUEUE`: `TX_SCHED`/`TX_SOFTWARE` at the send time, TCP `TX_ACK` a round trip later, each with `IP_RECVERR`/`IPV6_RECVERR` `sock_extended_err` (`ENOMSG`, `SO_EE_ORIGIN_TIMESTAMPING`, `ee_info` the stage, `ee_data` the `OPT_ID` key, counted per datagram or by byte for TCP), the looped-back packet (a fabricated Ethernet/IP/UDP or TCP header and the payload) or nothing under `OPT_TSONLY`, and `POLLERR` while one waits. `SO_TIMESTAMPING` validates as the kernel does (unknown flags, `OPT_ID_TCP` without `OPT_ID`, `OPT_STATS` without `OPT_TSONLY`, `OPT_ID` on an unconnected TCP socket: `EINVAL`; `BIND_PHC`: `EOPNOTSUPP`/`EINVAL`, the interfaces having no PHC). `SIOCGHWTSTAMP`/`SIOCSHWTSTAMP` on the plain fabric's interfaces are `EOPNOTSUPP` (`EPERM` to set without `CAP_NET_ADMIN`, `ENODEV` for an unknown name). `SO_TXTIME` validates as `sk_setsockopt` does (exactly a `struct sock_txtime`, known flags and clocks: `EINVAL`; a clock other than `CLOCK_MONOTONIC` without `CAP_NET_ADMIN`: `EPERM`) and reads back all 8 bytes. |
| macOS | `SO_TIMESTAMP`, `SO_TIMESTAMP_MONOTONIC`, `SO_TIMESTAMP_CONTINUOUS` | `recvmsg` on UDP: `SCM_TIMESTAMP` (`timeval`), `SCM_TIMESTAMP_MONOTONIC` and `SCM_TIMESTAMP_CONTINUOUS` (Mach ticks, on the clock `mach_absolute_time` reads). Nothing on TCP, as XNU. `getsockopt` reports the option's bit. |
| Windows | `WSAIoctl(SIO_TIMESTAMPING)` with `TIMESTAMPING_FLAG_RX`/`TX` (UDP only; `WSAEINVAL` on TCP) | `WSARecvMsg` on UDP: one `SO_TIMESTAMP` control message, the arrival as a `QueryPerformanceCounter` value on the counter the code under test reads. A `WSASendMsg` carrying `SO_TIMESTAMP_ID` buffers its send time while `TxTimestampsBuffered` has room (a stamp generated with the buffer full is dropped); `SIO_GET_TX_TIMESTAMP` takes it by id, `WSAEWOULDBLOCK` when none waits, and `WSAEOPNOTSUPP` while transmit stamps are off (measured). |

On Linux, `Sim::builder().rx_timestamp_startup_delay(Duration::from_millis(5))` starts
software receive timestamp generation cold. The first successful `SO_TIMESTAMP`,
`SO_TIMESTAMPNS` or `SO_TIMESTAMPING` request for `RX_SOFTWARE` starts a single sim-wide
activation window on the sim's clock. Packets arriving before its end have no software receive
stamp, even if read after activation. Later option changes and other sockets do not restart
the window; hardware stamps and transmit reports are independent. The default delay is zero,
representing generation already active, so existing tests retain immediate timestamps.
`SO_TIMESTAMP` and `SO_TIMESTAMPNS` on a datagram supply a read-time fallback for an unstamped
packet, including the same fallback across repeated `MSG_PEEK` reads; TCP has no such fallback.
This configures an initial cold-to-warm profile; it does not replay Linux's host-wide static-key
reference counts or workqueue scheduling.

A Linux `SimHost` adds hardware stamps (`tests/simhost_hwtstamp.rs`). A NIC with
`Nic::hardware_timestamping` starts with the `struct hwtstamp_config` of `Nic::hwtstamp_config`
(off by default), and `SIOCSHWTSTAMP` changes the emulated configuration: `EPERM` without
`CAP_NET_ADMIN`, an unknown flag `EINVAL`, an unknown
transmit type or filter `ERANGE`, a NIC without hardware timestamping `EOPNOTSUPP` (and
`SIOCGHWTSTAMP` too); then a transmit type the driver's `ETHTOOL_GET_TS_INFO` lacks is `ERANGE` and
a filter it lacks is widened to the narrowest advertised filter that covers it, with the applied
configuration written back. This is a synthetic policy: capability bitmaps do not specify a
driver's requested-to-applied mappings. The I210 default turns PTP filters into
`HWTSTAMP_FILTER_ALL`. With
transmit stamping on, a send asking `TX_HARDWARE` gets a `SCM_TSTAMP_SND` report carrying only
`ts[2]` (the NIC's PHC at the send), and its software report is dropped unless
`SOF_TIMESTAMPING_OPT_TX_SWHW` asks for both (net/core/skbuff.c `__skb_tstamp_tx`); a datagram the
NIC's filter covers arrives with `ts[2]` for a socket reporting `RAW_HARDWARE`. UDP PTP filters
check a payload of at least 34 bytes and selected version/message fields on port 319; NTP filtering
selects destination port 123. These checks are a synthetic classifier, without complete packet or
declared-length validation. Hardware/software timestamp points have no independent NIC latency.
Hardware TX reports with legacy `SO_TIMESTAMP(NS)` enabled receive a software read-time fallback,
also visible in `ts[0]` when software reporting is enabled.
`SCM_TXTIME` on a `SimHost` socket without `SO_TXTIME`, or
not 8 bytes long, fails the `sendmsg` with `EINVAL` (`__sock_cmsg_send`). A `/dev/ptp<N>` answers
`ptp_ioctl` (drivers/ptp/ptp_chardev.c) from its `PtpCaps` (`HostProfile::ptp_clock_caps`; by
default nothing to adjust and no pins, channels or cross-timestamping): `PTP_CLOCK_GETCAPS`,
`PTP_SYS_OFFSET` (`EINVAL` past `PTP_MAX_SAMPLES`), `PTP_SYS_OFFSET_EXTENDED` (system clock, PHC,
system clock per sample, on `CLOCK_REALTIME`, `CLOCK_MONOTONIC` or `CLOCK_MONOTONIC_RAW`),
`PTP_SYS_OFFSET_PRECISE` only with `cross_timestamping` (else `EOPNOTSUPP`), and `EACCES` for the
changing requests on a read-only fd (`tests/simhost_ptp.rs`).

A control buffer too short for the messages is cut as the host cuts it: Linux writes the part that
fits with `cmsg_len` cut to it and sets `MSG_CTRUNC` (even with no control buffer); macOS copies the
bytes that fit, sets `MSG_CTRUNC` only for a message it had to cut, and drops a message that finds the
buffer full. The kernel's deferred enabling of
receive stamping (a static key that can leave the first packets after `setsockopt` unstamped) is not
modelled: every packet is stamped.

## Unmodelled options and `strict_sockopts`

Every `setsockopt`, `getsockopt` and `ioctl` on a sim socket is modelled, ignored on purpose as
harmless, or unmodelled. An unmodelled one succeeds with no effect (a `getsockopt` reads an `int` 0),
as before, but is listed in the socket's `SocketEntry::unmodelled_options` and logged once per socket
as `RecordedEvent::UnmodelledOption`, so a test can assert the code under test used nothing the sim
ignores. With `SimBuilder::strict_sockopts()` it fails instead, with what the host answers for an
option it does not know — `ENOPROTOOPT` for an option, `ENOTTY` (Linux) or `ENXIO` (macOS) for an
ioctl request, all measured — and the first refusal is also written to stderr.

On Windows every option Winsock defines is known by level and number. An unmodelled one is kept and
read back as well (with Windows' default until set, such as `IP_MULTICAST_LOOP` on), listed, and refused under `strict_sockopts()` with `WSAEINVAL` at `SOL_SOCKET` and
`WSAENOPROTOOPT` elsewhere, the codes Winsock gives an option it does not know (measured). An option
Winsock does not define fails with those codes with or without strict mode, as does an
`ioctlsocket` command other than `FIONBIO`, `FIONREAD` and `SIOCATMARK` (`WSAEOPNOTSUPP`, measured).
A `WSAIoctl` code the sim does not carry out cannot succeed without effect, since only the OS could
fill its output: it fails with `WSAEOPNOTSUPP` and is listed as refused. `SO_SNDLOWAT`,
`SO_RCVLOWAT` and `SO_USELOOPBACK` fail `WSAEINVAL`, as Microsoft documents. A level the socket does
not take fails first: `IPPROTO_IPV6` on an IPv4 socket (`WSAEINVAL`) except the hop limit,
fragmentation, traffic class and receive options, `IPPROTO_TCP` on a datagram socket
(`WSAENOPROTOOPT`), and `IPPROTO_UDP` and the receive options on a stream (`WSAEINVAL`, measured);
`SO_KEEPALIVE` is stream-only. An IPv6 socket takes the `IPPROTO_IP` options that shape or report
IPv4 traffic only while dual-stack (`IPV6_V6ONLY` off, unbound or bound to the wildcard), as
measured. `IP_TOS` and `IPV6_TCLASS` refuse a value with ECN bits (measured).

The harmless options are kept and read back but change nothing, because nothing a test can observe in
the sim depends on them: `SO_KEEPALIVE` and the TCP keepalive timers (no connection dies idle),
`TCP_NODELAY` and Linux `TCP_QUICKACK` (no Nagle or delayed ACKs), `SO_OOBINLINE` and `SO_DEBUG`, macOS
`SO_NOSIGPIPE` (the sim never raises `SIGPIPE`; std sets it on every socket; `F_GETNOSIGPIPE` reads
it), and `IP_TOS`, `IP_TTL`, `IP_MULTICAST_TTL`, `IPV6_TCLASS`, `IPV6_UNICAST_HOPS`,
`IPV6_MULTICAST_HOPS` (no QoS or hop count: they only set the header fields a receiver's
[control messages](#control-messages) report); `FIOCLEX`/`FIONCLEX` for ioctls. Windows keeps the
same, read back from Windows' defaults until set (`IP_TTL` and `IPV6_UNICAST_HOPS` 128, the multicast hop limits 1, the TCP keepalive timers 2 hours,
1 s and 10 probes), plus `SO_DEBUG` and `SO_DONTROUTE`, which Microsoft's providers ignore, and the
`SIO_KEEPALIVE_VALS`, `SIO_LOOPBACK_FAST_PATH` and `SIO_UDP_NETRESET` ioctls.

Some options are modelled although nothing in the sim depends on them, so code that sets or reads
them sees the host's answers. Linux `SO_BUSY_POLL`, `SO_PREFER_BUSY_POLL` and
`SO_BUSY_POLL_BUDGET` are kept per socket with the kernel's checks (Linux 7.0, measured): any
non-negative `SO_BUSY_POLL` (negative is `EINVAL`), `SO_PREFER_BUSY_POLL` on only with
`CAP_NET_ADMIN`, and `SO_BUSY_POLL_BUDGET` raised above its current value only with
`CAP_NET_ADMIN` (`EPERM`) and within `0..=65535` (`EINVAL`); the first two read back, the budget
does not (`ENOPROTOOPT`, as `sk_getsockopt`). Nothing is polled: delivery is unchanged. Linux
`SO_DOMAIN` and `SO_PROTOCOL` read the socket's family and the protocol the kernel resolved
(`IPPROTO_UDP`/`IPPROTO_TCP` for protocol 0, 0 for packet and unix sockets, a netlink socket's
own), and fail `ENOPROTOOPT` to set; macOS has neither. Windows `SO_PROTOCOL_INFOW` and
`SO_PROTOCOL_INFOA` return the host's Winsock catalog entry for the socket's family, type and
protocol, as Winsock does, and refuse to be set. `tests/busy_poll.rs` and
`tests/socket_family.rs` compare them with the real host.

Everything else the sim does not model — `IP_MULTICAST_LOOP`, `IP_DROP_MEMBERSHIP`,
`SO_RCVLOWAT`, `SIOCGSTAMP` and the rest — is unmodelled. A `SimHost` socket keeps its
existing read-back of every option set, and records the same way. std's own socket calls on each host
are all modelled or harmless (`tests/strict_sockopts.rs` runs them under `strict_sockopts`).

### Don't-fragment

The don't-fragment options are modelled on every IP socket of the fabric and a `SimHost`: Linux
`IP_MTU_DISCOVER` and `IPV6_MTU_DISCOVER` (`IP_PMTUDISC_DONT`, `WANT` — the default — `DO`, `PROBE`,
`INTERFACE`, `OMIT`; anything else `EINVAL`) and `IPV6_DONTFRAG`, macOS `IP_DONTFRAG` and
`IPV6_DONTFRAG` (flags, read back as 0 or 1). They read back as the host does, including the optlen
rules (Linux reads a short `IP_MTU_DISCOVER` as a byte, refuses a short `IPV6_MTU_DISCOVER` and
reads a short `IPV6_DONTFRAG` as 0; macOS refuses any short value) and the other family's errors
(Linux `ENOPROTOOPT` to set and `EOPNOTSUPP` to read an IPv6 option on an IPv4 socket, macOS
`EINVAL` either way). The sim never fragments: a datagram larger than its egress interface's MTU is
delivered whole, unless it may not be fragmented — Linux `DO`, `PROBE` or `INTERFACE` for its
family, or `IPV6_DONTFRAG` for IPv6; macOS `IP_DONTFRAG`, or `IPV6_DONTFRAG` on an IPv6 socket,
v4-mapped sends included — when the send fails `EMSGSIZE` once payload plus 8 bytes of UDP and 20
(IPv4) or 40 (IPv6) bytes of IP header pass the MTU. The MTU is the interface's configured one; no
smaller path MTU is learned. `tests/dontfrag.rs` `dontfrag_os_truth` compares all of it with the real
stack on loopback (16384 on macOS `lo0`, 65536 on Linux `lo`, which only IPv6 datagrams can exceed).

Windows has `IP_DONTFRAGMENT` and `IPV6_DONTFRAG` (flags) and `IP_MTU_DISCOVER`/`IPV6_MTU_DISCOVER`
(a `PMTUD_STATE`: `NOT_SET`, the default, `DO`, `DONT` or `PROBE`; anything else `WSAEINVAL`). A
datagram may not be fragmented under the flag or `DO`/`PROBE` for its family, and then fails with
`WSAEMSGSIZE` past the egress MTU, by the same header arithmetic (`tests/dontfrag_win.rs`).

### Control messages

`sendmsg` on a UDP socket of the fabric or a `SimHost` takes the control messages each host takes,
with its checks, and `recvmsg` reports what the datagram carried when the socket asked for it
(`src/ancillary.rs`):

- **Send.** TOS (`IP_TOS`) or traffic class (`IPV6_TCLASS`), ECN bits included; TTL (`IP_TTL`,
  Linux) or hop limit (`IPV6_HOPLIMIT`); source address and interface (`IP_PKTINFO`,
  `IPV6_PKTINFO`, and on Linux an IPv6 socket's v4-mapped `IPV6_PKTINFO`); `IPV6_DONTFRAG`; on Linux
  `UDP_SEGMENT`, `SO_TIMESTAMPING` (this send's transmit stamps), `SCM_TXTIME`, `SO_MARK` and
  `SO_PRIORITY`. A message's own value wins over the socket's option. Each host's rules hold: Linux
  refuses a malformed header, an unknown `SOL_IP`/`SOL_IPV6`/`SOL_SOCKET`/`SOL_UDP` type and an
  out-of-range value with `EINVAL`, a source that is not the host's (`ENETUNREACH` for IPv4,
  `EINVAL` for IPv6) and an interface that does not exist (`ENODEV`), and skips the other family's
  level; macOS refuses a control buffer shorter than a `cmsghdr`, takes an IPv4 send's TOS from the
  first `IP_TOS` or `IPV6_TCLASS` of an `int`, takes any `IP_PKTINFO` source unchecked (`ENXIO` for
  an unknown interface), ignores the rest of an IPv4 send, and on IPv6 refuses an unknown type with
  `ENOPROTOOPT` and a source that is not the host's with `EADDRNOTAVAIL`. Linux's quirk of sending
  a traffic class of -1 as 0xff is kept. A TCP `sendmsg` takes them as the host does too (Linux
  checks only the `SOL_SOCKET` ones; macOS drops them) and ignores them.
- **Segmentation offload (Linux).** A send with a segment size, from `UDP_SEGMENT` or the socket's
  option, is checked per segment against the egress MTU (`EMSGSIZE`) instead of the don't-fragment
  rules, and up to 128 segments (`EINVAL` past). Through loopback it stays whole, and a socket with
  `UDP_GRO` on reads it whole with a `UDP_GRO` message giving the segment size; any other receiver
  gets the segments. Across an interface it leaves as its segments.
- **Receive.** `IP_RECVTOS`, `IP_RECVTTL`, `IP_PKTINFO` (macOS `IP_RECVPKTINFO`), macOS
  `IP_RECVDSTADDR`, `IPV6_RECVTCLASS`, `IPV6_RECVPKTINFO`, `IPV6_RECVHOPLIMIT`, read back as each
  host does (Linux takes a short `IP_*` value as a byte and an IPv6 socket takes the `IP_*` ones;
  macOS refuses short values and the other family's options with `EINVAL`). The messages follow the
  receive timestamps in the host's order and layout: Linux `IP_PKTINFO` (receiving interface, local
  address, destination), `IP_TTL` (`int`), `IP_TOS` (one byte); macOS `IP_RECVDSTADDR`, `IP_RECVTTL`
  and `IP_RECVTOS` (one byte), `IP_RECVPKTINFO`; `IPV6_PKTINFO`, `IPV6_HOPLIMIT`, `IPV6_TCLASS`
  (`int`s) on both. A datagram carries its sender's TOS and TTL unchanged: the sim counts no hops.

Windows (`src/win_sockopt.rs`, measured on Windows 11 ARM64 build 26200.9457):

- **Send.** `WSASendMsg` takes, at the level of the destination's family, `IP_ECN`/`IPV6_ECN` (0 to
  2: Windows refuses to send CE), `IP_TOS`/`IPV6_TCLASS` (a byte whose ECN bits are not CE),
  `IP_HOPLIMIT`/`IPV6_HOPLIMIT` and `IP_PKTINFO`/`IPV6_PKTINFO`, in order, a later one overriding
  an earlier, over the socket's `IP_TOS` and `IP_TTL`; and `UDP_SEND_MSG_SIZE` and
  `SO_TIMESTAMP_ID`. A packet info is ignored on a socket bound to an address; on a wildcard-bound
  one it chooses the source, which must be an address the host holds, and an interface that must
  exist. Anything else — `IP_TTL`, the other family's level, an unknown type or level, a value out
  of range or too short, a malformed header — is `WSAEINVAL`; a buffer, or tail, shorter than a
  `WSACMSGHDR` holds no message.
- **Segmentation offload (USO).** A segment size from the message or the socket option, at most
  65507 bytes for IPv4 and 65527 for IPv6 (`WSAEINVAL` past), cuts a send of any length into
  segments. Through loopback a socket with `UDP_RECV_MAX_COALESCED_SIZE` set reads them coalesced:
  the send taken in pieces of as many segments as fit the family's largest datagram, each read as
  datagrams of as many segments as fit that size, with a `UDP_COALESCED_INFO` message giving the
  segment size; any other socket reads each segment, as it does over an interface. Separate sends
  are never coalesced.
- **Receive.** `WSARecvMsg` returns, each when asked for, `IP_PKTINFO` (destination and receiving
  interface), `IP_ECN`, `IP_TTL` (asked for with `IP_RECVTTL`) and `IP_TOS` (`IP_RECVTOS`), or their
  IPv6 counterparts, then `SO_TIMESTAMP` and `UDP_COALESCED_INFO`. A control buffer too short takes
  what fits, cut mid-message, reports the whole length and `MSG_CTRUNC`, and fails the receive with
  `WSAEMSGSIZE`, the datagram consumed.

`tests/cmsg_os_truth.rs` compares the sends, the receive options and the bytes `recvmsg` writes,
truncated control buffers included, with the real stack on loopback (macOS 26, Linux 7.0; on Linux
also through a `SimHost`), and `tests/cmsg_win_os_truth.rs` does the same on Windows, segmentation
and coalescing included. `tests/quinn_udp.rs` runs `quinn-udp`'s socket state (ECN, packet info,
GSO/GRO, Windows USO/URO) and a whole `quinn` connection over IPv4, over IPv6 and from a
dual-stack client to an IPv4 server, all under `strict_sockopts`.

An IPv4 datagram reaching a dual-stack IPv6 socket reports, as measured: on Linux the v4-mapped
`IPV6_PKTINFO`, then the IPv4 messages the socket asked for (an IPv6 socket takes `IP_PKTINFO`,
`IP_RECVTTL` and `IP_RECVTOS`); on macOS `IPV6_TCLASS` carrying its TOS, then the v4-mapped
`IPV6_PKTINFO`, and no hop limit (macOS refuses `IPPROTO_IP` options on an IPv6 socket with
`EINVAL`).

### `fcntl` on sockets

Besides duplication, `FD_CLOEXEC` and `O_NONBLOCK`, a sim socket keeps the status flags `F_SETFL`
keeps on the host (`O_APPEND` and `O_ASYNC`, and macOS `O_SYNC`; Linux refuses `O_DIRECT`) and the
signal-driven I/O owner: `F_SETOWN`/`F_GETOWN` (a negative value names a process group), Linux
`F_SETOWN_EX`/`F_GETOWN_EX` and `F_SETSIG`/`F_GETSIG`. No `SIGIO` is ever sent, and the owner is not
checked against the process table. Linux record locks on a socket succeed (`F_GETLK` reports
`F_UNLCK`), `F_GETLEASE` reads `F_UNLCK`, and leases, seals, `F_NOTIFY` and the pipe sizes fail as on
the host. macOS `F_SETNOSIGPIPE`/`F_GETNOSIGPIPE` are `SO_NOSIGPIPE`, and every other command is a
vnode command, `EBADF` on a socket. `tests/fcntl_os_truth.rs` compares them with the host.

## Socket limits and privileges

A datagram socket's receive buffer is enforced as the host's kernel does: each datagram is admitted
or dropped at the moment it arrives — not when the code under test next looks — against what the
buffer holds then. `SocketEntry` reports `rcvbuf`/`sndbuf` (what getsockopt returns), `rmem_alloc`,
`overflowed` (dropped for a full buffer), `wire_lost` (lost by a link policy, never counted as a
drop) and `drops` (the kernel's counter: overflows plus `inject_socket_drops(id, n)`, which
`SO_RXQ_OVFL` and `SO_MEMINFO` report). Testers' endpoints are unlimited.

A TCP stream's buffers bound it too. What the code under test has written and its peer not yet
read is capped at the writer's send buffer (its `SO_SNDBUF` as getsockopt reports it) plus the
reader's receive room (its `SO_RCVBUF` as reported; twice it on Windows), capped further by a
`TcpPolicy::recv_window`; a stream to a tester is bounded only by a window. An accepted stream
takes its listener's sizes. Measured against the real OS with a reader that never reads
(`tests/tcp_buffers_os_truth.rs`), this matches Windows exactly and Linux within 40%; macOS
rounds buffers to whole segments and grows a loopback receive buffer by an amount that varies
from run to run, and Linux autotunes a send buffer whose `SO_SNDBUF` was never set (measured
2.6 MB in flight); neither is modelled, so the sim usually back-pressures sooner there.

On Linux, streams with an explicitly configured receive buffer or transmit timestamps use
MSS, GSO grouping and advertised-window state to release pending data as reads create room.
Transmit reports quote the final transmitted segment and wait for that segment to cross the
link. `tests/tcp_error_queue_segments.rs` compares IPv4 payloads and memory charges for writes
through 128000 bytes across five receive-buffer sizes on both backends. Ordinary TCP segments share the
receive-memory budget with error reports and keep their charge until fully read. Default buffer
autotuning, kernel receive coalescing, congestion-window evolution and ACK pacing remain
approximations; this comparison does not establish arbitrary TCP traffic parity.

| OS | Buffer options | Admission | `FIONREAD` |
|---|---|---|---|
| Linux | `SO_RCVBUF` `v` stores `max(2 * min(v, rmem_max), 2304)` (`-1` asks for the cap), `SO_SNDBUF` likewise with floor 4608; `SO_*BUFFORCE` skip the cap and need `CAP_NET_ADMIN` | into an empty queue, or while `rmem_alloc + truesize <= rcvbuf` (6.18 on); while `rmem_alloc <= rcvbuf`, overshooting by one datagram, before 6.18 | the next datagram's payload (a stream's unread bytes); `SIOCOUTQ` 0 |
| macOS | `v <= 0` is `EINVAL`; above `kern.ipc.maxsockbuf` clamps, or `ENOBUFS` once the buffer is already at it | while the record fits `sb_hiwat - sb_cc` and `sb_mbcnt` is under `8 * sb_hiwat` | `sb_cc` (16 + payload for a socket's first datagram, 32 + payload after); `SO_NREAD` the next payload; a datagram over `SO_SNDBUF` is `EMSGSIZE` |
| Windows | stored as given | while the queued payload is below `SO_RCVBUF` | the queued payload capped at `SO_RCVBUF` |

`SysLimits` holds the sysctls (`rmem_default`, `rmem_max`, `wmem_*`, `tcp_*_default`,
`unprivileged_port_start`, `enforce_rcvbuf`) and, on Linux, the kernel facts behind admission
(`udp_rcvbuf_overshoot`, `skb_small_truesize`, `skb_head_overhead`): `SysLimits::host()` is a stock
install of the build host (Linux: a stock 6.18+ kernel, whatever the architecture),
`SysLimits::from_real_host()` reads this machine, measuring the running kernel's `truesize`
geometry over loopback with `SO_MEMINFO`. A datagram longer than the smallest MTU on its path
arrives as IP fragments and is charged one buffer per fragment, as reassembly chains them
(net/ipv4/inet_fragment.c `inet_frag_reasm_finish`; measured through veth by
`tests/hw_sockbuf_truth.rs`). The Linux skb sizes depend on the kernel's build, not its
architecture: Debian's 6.12 and 7.2 kernels charge the same on x86_64 and arm64 (a lone small
datagram 960 bytes), OrbStack's arm64 kernel 1152. `scripts/measure-sockbuf.sh` boots Debian's
x86_64 and arm64 kernels under QEMU and measures them (`KERNEL_SUITE`, and `TESTS` to run snare's
test binaries on those kernels). Set them with `SimBuilder::sys_limits`,
`set_sys_limits` or `Sim::set_sys_limits`; a change applies to sockets created after it.

`tcp_gso_max_size` selects Linux's device GSO limit for TCP grouping (65536 bytes by default).
Driver-specific values need a measured profile override; `from_real_host` does not discover that
device setting.

`Privileges { root, net_admin, net_raw, net_bind_service, sys_nice, ipc_lock, sys_resource,
rtprio_limit, nice_limit, memlock_limit }` is per sim: `Privileges::all()` by default (every
capability, `RLIMIT_RTPRIO` 99, `RLIMIT_NICE` 40, unlimited `RLIMIT_MEMLOCK`, as snare 1.x), a
`SimHost`'s profile (`HostProfile::cap`, `HostProfile::root`, with the kernel's stock limits) when it
has one, and `SimBuilder::privileges` over both; `Privileges::none()` is an ordinary user with the
stock limits (0, 0, 8 MiB on Linux) and `Privileges::from_real_process()` copies the machine's;
`set_privileges` / `Sim::set_privileges` change it from any thread. The host's scheduling,
`mlockall`, `SIOCSHWTSTAMP` and busy-poll gates read the same model, a `SimHost` answers `geteuid`/`getuid` (0
for root, else 1000 on Linux, 501 on macOS), `getegid`/`getgid` and `getgroups` (0 for root, else
1000 on Linux, 20 on macOS) and renders them, the umask and `CapEff`/`CapPrm`/`CapBnd` in
`/proc/self/status`. The same `root` decides what a `VirtualFs` lets the code under test do (see
[Files](files.md#files-virtualfs)).

### Process limits

The three limits are each an `Rlimit { cur, max }` (`Rlimit::INFINITY` is `RLIM_INFINITY`) and are
what `getrlimit`, `setrlimit` and `prlimit` (Linux, also `SYS_prlimit64` and x86_64's
`SYS_[gs]etrlimit` through `syscall`) see and change inside the sim; the real process's limits are
never touched, and other resources pass through. Raising a hard limit needs `sys_resource`
(`CAP_SYS_RESOURCE`; root on macOS), a soft limit above the hard one is `EINVAL`. The calls they
gate follow the build host's kernel:

| OS | Rule |
|---|---|
| Linux | `sched_setscheduler`/`sched_setparam`/`pthread_setschedparam` (and the raw syscalls): `EINVAL` for a bad policy or priority, then without `CAP_SYS_NICE` `EPERM` to enter a real-time policy with `RLIMIT_RTPRIO` 0 or to raise the priority above both the current one and the limit (kernel/sched/syscalls.c). `setpriority`: the value is clamped to −20..19 and lowering it needs `CAP_SYS_NICE` or `20 − nice <= RLIMIT_NICE` (`EACCES`). `mlock`: `EPERM` with `RLIMIT_MEMLOCK` 0, `ENOMEM` past it (locks do not nest); `mlockall(MCL_CURRENT)`: `ENOMEM` when the process's mapped size exceeds it; `CAP_IPC_LOCK` lifts both (mm/mlock.c). |
| macOS | `mlock` wires pages counted against `RLIMIT_MEMLOCK` whatever the privileges (`EAGAIN` past it); wiring nests per page, so a page is released after as many `munlock`s. `mlockall` is `ENOSYS`, as on the real system. A successful `pthread_setschedparam`, any policy, opts the thread out of QoS for good: later `pthread_set_qos_class_self_np` calls fail with `EPERM` (`<pthread/qos.h>`; `tests/macos_qos_os_truth.rs` checks it against the host). |

A `SimHost` applies these to its own simulated threads and never reaches the real scheduler or lock
memory. A plain sim gates the same calls on its privileges and then lets an allowed one through to the
real kernel. `tests/rlimits.rs` checks the rules, and its `rlimit_sequence_os_truth` (Linux) and
`memlock_os_truth` (macOS) replay one sequence against the real kernel in a forked child with
`Privileges::from_real_process()`; run them under Docker with `--ulimit rtprio=…`, `--ulimit
nice=…`, `--ulimit memlock=…` and `--cap-add SYS_NICE`/`IPC_LOCK`/`SYS_RESOURCE` to cover the other
branches.

| OS | Gated |
|---|---|
| Linux | binding a port below `unprivileged_port_start` (`EACCES` without `CAP_NET_BIND_SERVICE`), `SO_RCVBUFFORCE`/`SO_SNDBUFFORCE` (`CAP_NET_ADMIN`), `SO_PRIORITY` outside 0–6 and `SO_MARK` (`CAP_NET_ADMIN` or `CAP_NET_RAW`), changing the device of a bound socket (`CAP_NET_RAW`), `socket(AF_PACKET)` (`CAP_NET_RAW`); `EPERM` otherwise. |
| macOS | binding a port below 1024 on a specific address, and opening `/dev/bpf*`, need root (`EACCES`). |
| Windows | no socket call; without `sys_nice` a `REALTIME_PRIORITY_CLASS` request runs at `HIGH_PRIORITY_CLASS`. |

`tests/os_parity.rs` compares buffer options, flood admission counts and reserved-port binds against
the real OS, and `tests/socket_limits.rs` `truesize_os_truth` the charge of every datagram size
around each step.

## Protocol counters

Every sim keeps the host's UDP and TCP counters, moved by the code under test's sockets (a tester
is another machine) and readable as the code under test would read them:

| OS | Where | UDP | TCP |
|---|---|---|---|
| Linux | `/proc/net/snmp`, `/proc/net/snmp6` (with or without a `SimHost` or `VirtualFs`; a snapshot at the first read, fresh after a seek to 0) | `InDatagrams` (read), `NoPorts`, `InErrors`/`RcvbufErrors` (overflow), `OutDatagrams`, `IgnoredMulti` | `ActiveOpens`, `PassiveOpens`, `AttemptFails`, `EstabResets`, `CurrEstab`, `InSegs`/`OutSegs` (data segments), `OutRsts`; `RtoMin` 200, `RtoMax` 120000, `MaxConn` -1 |
| macOS | `sysctl`/`sysctlbyname` `net.inet.udp.stats` (`struct udpstat`, 104 bytes) | `udps_ipackets` (every arrival), `udps_noport`, `udps_noportbcast`, `udps_fullsock`, `udps_opackets` | — |
| Windows | `GetUdpStatistics(Ex/Ex2)`, `GetTcpStatistics(Ex/Ex2)` per family | `dwInDatagrams` (arrivals), `dwNoPorts`, `dwInErrors` (overflow), `dwOutDatagrams`, `dwNumAddrs` | as Linux, `RtoAlgorithm` 4, `dwRtoMin` 5 |

`proto_counters()` (and `Sim::proto_counters`) returns them per family for the test. A unicast
datagram to a port of the host nobody holds is a no-port; a broadcast, or a multicast one for a
group a socket of the host joined, that no socket took is ignored-multi; a group nobody joined
counts nowhere. The IP and ICMP lines count those datagrams and TCP data segments and the port
unreachables sent back; checksum, memory, send-buffer and retransmission counters stay 0.
`tests/proto_counters_os_truth.rs` compares the layouts and which counter a closed port and an
unread datagram move with the real host.
