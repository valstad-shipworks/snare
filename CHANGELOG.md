# Changelog

## Unreleased (1.6.0)

OS semantics, first-class interfaces and routing, socket identity, virtual
signals, a thread registry and the `snare::fast_talker` shim. Without an
explicitly selected OS and without `add_nic`, existing tests see the same
results as with 1.5.0, apart from the changes listed under Changed.

### Added

**OS semantics**

- `snare::OsSemantics { Linux, MacOs, Windows }` (defaults to the host),
  `os_semantics()`, and with `shim` `set_os_semantics(..)` per state slot or
  `SNARE_OS=linux|macos|windows` for the whole process (a bad value panics on
  the first snare call). Selecting an OS explicitly turns on its faithful
  rows: ephemeral port ranges, bind errors (`EADDRNOTAVAIL`, `EADDRINUSE`
  per protocol with Windows' specific-over-wildcard allowance, the loopback
  `/8` except on macOS), `EACCES` for broadcast without `SO_BROADCAST`,
  `EMSGSIZE` over 65507/65527 bytes and macOS's 9216-byte `maxdgram`,
  read-timeout and would-block errors with the OS's code, and Windows'
  `WSAEMSGSIZE` on a short receive buffer. Without an explicit OS every
  result stays as before.
- `Errno`, `SysErrno`, `SimOsError` and `os_error_code`: errors built for
  the host OS are `from_raw_os_error`; for another OS the code travels in a
  `SimOsError` payload.
- Faithful TCP connects wait in virtual time as the OS would: an address the
  host owns with no listener refuses at once, or after Windows' two-second
  SYN retry; any other routable address stays silent until the SYN
  retransmissions give up (127 s Linux, 75 s macOS, 21 s Windows) with
  `ETIMEDOUT`. `connect_timeout` caps the wait with std's own `TimedOut`
  error, and a listener that appears meanwhile is taken. Without a route the
  connect fails at once. This covers every `TcpStream::connect` under the
  shim, including `mio::net::TcpStream::connect`, which snare cannot tell
  apart; real mio returns at once and reports the result later.
- Faithful TCP close: a peer's graceful close reads as EOF with no pending
  error; the first write after it succeeds and draws a RST, later writes fail
  with `EPIPE` (`WSAECONNRESET` on Windows, where reads fail too). A received
  RST reports `ECONNRESET` once. `set_linger(Some(0))` is accepted and makes
  the last drop reset the peer; a listener dropped with unaccepted
  connections resets them. Write after `shutdown(Write)` is `EPIPE`
  (`WSAESHUTDOWN`).
- ICMP port unreachable, whatever the OS selection:
  `inject_icmp_port_unreachable(to, from)`, and
  `NicPolicy::icmp_port_unreachable` for datagrams to closed ports on an
  interface's own addresses (never on `add_ip_addr` addresses). A connected
  UDP socket gets `ECONNREFUSED` on its next receive or send; under Windows
  semantics connected and unconnected sockets get `WSAECONNRESET` on their
  next receive and poll readable until then. `SocketEntry::icmp_error` shows
  a pending one.
- `snare::ctrlc::raise_signal(VirtualSignal) -> SignalDelivery` delivers
  `SIGINT`/`SIGTERM`/`SIGHUP` or the Windows console events as the selected
  OS and `ctrlc` would: unavailable signals, `SIGTERM`/`SIGHUP` taking the
  default action without `ctrlc-termination`, and Windows close, logoff and
  shutdown reported as `HandledThenExit`. `raise()` is unchanged.
- Every thread spawned through `snare::thread` is registered in its state
  slot with a synthetic tid, its name and a class read live from its marking
  and the participant registry; an exited thread keeps the class it had.
  Threads that mark themselves (`mark_background`, `mark_helper`,
  `mark_driver_thread`) or become participants are registered too, and every
  entry records the host thread id (`pthread_threadid_np`, `gettid`,
  `GetCurrentThreadId`) with `shim` alone.
- `sched::thread_census()` holds every OS thread of the process (macOS
  `task_threads`, Linux `/proc/self/task`, Windows Toolhelp) against the
  registry and reports each as `Known(class)`, `System` or `Unregistered`.
  A live thread two censuses in a row find unregistered, or (on macOS, where
  a pthread introspection hook installed at load sees every thread start) a
  thread that started and exited unregistered, is recorded as an
  `UnknownThread`, read by `sched::unknown_threads()` and
  `AuditReport::unknown_threads`. System threads are only those the OS
  creates for itself: libdispatch workqueue threads on macOS, which announce
  their own creation to the hook or have no pthread yet.
  `sched::classify_background_by_name(fn)` accounts for a third-party
  runtime's threads that offer no start hook.

**Interfaces and routing** (`shim`)

- Interfaces are part of the network: the loopback (named for the selected
  OS) and `snare0`, which holds the default routes and every `add_ip_addr`
  address, plus whatever `add_nic(NicSpec)` adds. `set_nic`, `set_link`,
  `set_nic_policy` (latency, jitter, loss, duplication), `set_nic_counters`,
  `remove_nic`, `nic`/`nics`/`nic_counters`, `add_route`, `remove_route`,
  `set_default_route`, `routes` and `route_lookup`. Sends pick their
  interface from the bound device, then the multicast interface, then the
  routing table (longest prefix, metric; strong host on Windows), and fail
  with `ENETUNREACH`/`ENETDOWN`/`EHOSTUNREACH` as the OS would. Datagrams to
  a downed interface are lost; TCP over one stalls until it returns.
- Sockets have identity: `SocketId`, `socket_id(&s)` through the sealed
  `SimSocket` trait, `socket_entry`, `socket_table`, `sockets_bound`,
  `closed_sockets`, `set_socket_device` and `inject_socket_drops`. Ids are
  never reused, not even across state slots.
- `Privileges`, `SysLimits` and `DropAccounting` with `set_privileges`,
  `set_sys_limits` and their getters.
- Traffic to addresses of `add_nic` interfaces (or any traffic once an OS is
  selected) reaches wildcard-bound sockets and carries a routed source
  address; traffic among `add_ip_addr` addresses behaves as before.
- Multicast: `UdpSocket::join_multicast_v4`/`v6` and `leave_multicast_v4`/`v6`
  work (they used to panic), `SocketEntry::memberships` lists them
  (`Membership`), and multicast loop and TTL are kept per socket (loop on
  and TTL 1 by default, as std reports). A datagram to a group reaches every
  socket bound to the port on the wildcard or group address that joined it
  on the interface it arrives on; on Linux, unless `only_joined`, also
  sockets that did not join a group some other socket joined. The sender
  hears it only through multicast loopback. With no such socket it goes to
  virtual testers, and in legacy mode to a socket bound to the group
  address as before. An interface counts a fanned-out frame once, lost or
  delivered. Under Linux semantics, IPv4 multicast from a socket bound to a
  unicast address leaves through the interface owning that address unless
  a sending interface is set.
- Broadcast: a datagram to `255.255.255.255` (sent out of the interface
  owning the bound source address) or to a subnet's broadcast address
  reaches every socket bound to the port on the wildcard or broadcast
  address, except the sender unless an OS is selected; otherwise virtual
  testers.
- A UDP socket may bind a multicast group address; under Windows semantics
  that fails with `WSAEADDRNOTAVAIL`.
- Once an OS is selected, a UDP socket bound to `[::]` on Linux and macOS
  also receives IPv4 datagrams, from v4-mapped addresses, and sends to
  v4-mapped addresses over IPv4; Windows keeps `IPV6_V6ONLY` on.

**fast-talker** (`fast-talker-core` and its sub-features)

- `snare::fast_talker`: `fast_talker::` becomes `snare::fast_talker::`.
  Without `shim` it re-exports fast-talker unchanged. With `shim`, fast-talker's
  configuration, option, plan, check, monitor and result types stay its own
  (same `TypeId`), and its OS-facing items (`Timestamped`, `tcp`, `nic`,
  `irq`, `rt`, `multicast`) become snare's, working on snare's interfaces,
  threads and virtual clock. `nic::Nic::open` opens snare interfaces;
  `rt::Thread` is a snare thread.
- Features: `fast-talker-core`, `fast-talker-plan`, `fast-talker-options`,
  `fast-talker-sys-check`, `fast-talker-monitor`, `fast-talker-serde`,
  `fast-talker-pyo3`, and `fast-talker-compat` (fast-talker's default
  features). `shim` turns on fast-talker's hidden `sim` feature and every
  feature with a hook; `mio-compat` forwards `fast-talker/mio`.
- fast-talker's functions that take an OS socket (`SocketOptions::apply`,
  `SocketOption::apply_all`, `SocketMemory::of`, `sockets::incoming_cpu`,
  `WatchedSocket::new`) accept snare sockets and hand them to snare; raw-fd
  paths given a snare socket (`multicast::*`, `TcpInfo::of`) fail with
  `Unsupported` before any syscall. On a snare thread, `Timestamp::elapsed`
  reads the virtual clock, and fast-talker's platform choices
  (`Check::recommended`, `Check::privileges`, which options apply) follow
  `os_semantics()`. Threads with no state slot keep fast-talker's real
  behaviour.
- `snare::fast_talker::compat`: `now()`, `tcp_info(&stream)` and
  `apply_thread_options_to(thread, ..)`, spelled the same with and without
  `shim`.
- `snare::fast_talker::sim`: `install()`, `set_cpus`, `set_tai_offset`,
  `set_stack_delay`, `set_sys_facts`, `set_protocol_counters`, `threads`,
  `thread_named`, `thread_of`, `plans_applied`, `sys_checks`, `monitors`,
  `events` and `clear_events`.
- `From` conversions between `snare::time::SystemTime` and
  `std::time::SystemTime`.
- The thread registry records each thread's host thread id.
- `snare::fast_talker::Timestamped` works on snare's UDP sockets (including
  `snare::mio::net::UdpSocket`, which it registers as a mio source). A
  receive stamp is the virtual instant the datagram reached the socket, not
  when it was read; `Received::drops` is the socket's drop count when the
  datagram was queued (Linux only). Sources follow the emulated OS: Linux
  kernel stamps, or hardware ones on an interface with
  `NicCaps::hw_rx_timestamp`, `CAP_NET_ADMIN` and a PTP clock within the
  tolerance; macOS microsecond kernel stamps; Windows kernel stamps, user
  space over loopback. Transmit stamps carry the send (or launch) instant;
  on Linux every send on the socket is stamped and a ready stamp makes the
  socket poll as errored until read. `send_at`/`send_to_at` hold a datagram
  until its launch instant when the outgoing interface has an ETF qdisc,
  report late or mismatched times as `Invalid`, and send at once (logging
  `FtEvent::TxTimeWithoutEtf`) without one. `memory()` and
  `SocketMemory::of` on a snare socket report its queue, buffer sizes and
  drops as the emulated OS would.
- `snare::fast_talker::tcp::TimestampedStream` works on snare's TCP streams
  (including `snare::mio::net::TcpStream`, which it registers as a mio
  source). Under Linux semantics a read's stamp is the virtual instant the
  newest bytes it returned reached the stream (kernel, or hardware on an
  interface with hardware stamping); macOS and Windows stamp in user space
  when the read returns and refuse `try_with_config`, as fast-talker does.
  With `Config::transmit`, `Sent::id` is the offset of the last byte; Linux
  stamps `Scheduled` and `Sent` at every write on the stream and `Acked` one
  round trip later (for bytes held on a downed interface, once the link
  returns and they reach the peer), signalling ready stages as an error condition, while
  macOS and Windows stamp `Sent` in user space for sends through the
  wrapper. `info()` and `compat::tcp_info` report the round trip (inbound
  latency of both ends plus the interface latency each way), jitter, MSS
  from the interface MTU, the peer's window and byte counts, shaped as the
  emulated OS reports them. `sim::socket`/`sockets` include streams
  (`FtSocketSnapshot::stream`, `bytes_sent`, `bytes_received`).
- `snare::fast_talker::sim`: `set_ptp`/`PtpSeed`, `set_etf`,
  `inject_txtime_missed`, and `socket`/`sockets` (`FtSocketSnapshot`: the
  timestamping config, source, timed-send mode and pending stamps of each
  socket).
- `snare::fast_talker::rt` works on snare's thread registry. `Thread::find`
  sees every snare-spawned thread (and synthetic kernel threads) from the
  moment it starts, matching names cut to 15 bytes as Linux keeps them;
  `name()` is cut as the emulated OS cuts it. Scheduling, affinity, nice,
  `pin`, macOS time-constraint and QoS, Windows thread and process
  priorities, power throttling, CPU sets, working set, `TimerResolution`,
  `Mmcss`, `lock_memory`, `CpuDmaLatency`, `isolated_cpus` and
  `nohz_full_cpus` are recorded per thread or process, checked against
  `Privileges` and `CpuTopology`, and fail with the emulated OS's errors
  (`EPERM` without `sys_nice` above `rtprio_limit`, `EINVAL` for CPUs the
  host lacks, `ERROR_PRIVILEGE_NOT_HELD`, macOS priority clamping to 15-47,
  `Unsupported` for another OS's items). None of it changes how snare
  schedules a thread. `pin_scheduler` and `pin_priority` exist on every
  host beside the host-shaped `pin`, and `From<fast_talker::rt::Thread>`
  finds the snare thread by host thread id.
- `sys_check` on a snare thread answers every check from the simulated
  host (`SysFacts`, `CpuTopology`, privileges, socket limits, interfaces'
  PTP clocks) with fast-talker's expected and actual texts; another OS's
  checks are `Unsupported`. Each call is kept in `sim::sys_checks`.
  `SysFacts` gained `kernel`, `idle_states` (replacing
  `idle_max_latency_us`), `win_power_plan` and `win_unparked_percent`.
- `Counters::read` on a snare thread reports the emulated OS's counter
  names, counting the UDP datagrams snare carried (sent, queued or read,
  receive-buffer overflows, ports answered with ICMP) plus
  `sim::set_protocol_counters`.
- `snare::fast_talker::sim`: `process()` (`ProcessSnapshot`,
  `DmaLatencyRequest`), `IdleState`, and `FtEvent::Rt` and
  `FtEvent::SysCheck`.
- `snare::fast_talker::nic` and `irq` work on snare's own interfaces:
  rings, coalescing (checked against `NicCaps::coalesce_supported` and its
  limits), flow control and channels on Linux and Windows; EEE, threaded
  NAPI, NAPIs and their interrupts, XPS/RPS, byte queue limits, busy-poll
  deferral, GRO flush, hardware receive timestamping, queue statistics, the
  PTP clock and `clock_offset`, flow steering and qdiscs (ETF, `restore_qdisc`)
  on Linux; driver timestamping, the interrupt affinity policy and RSS on
  Windows. Setters check `net_admin` (sysfs ones also `root`) or, on
  Windows, an elevated process, and log to `sim::interface(..).apply_log`
  and `FtEvent::Nic`. Under Linux semantics each interface gets
  interrupts from 120 (`<nic>-TxRx-<q>` with `irq/<n>-<nic>-TxRx-<q>`
  threads at `Fifo(50)`), NAPIs from 8193 and, when threaded,
  `napi/<nic>-<id>` threads; a new channel count recreates them, and
  removing the interface retires them. `irq::Irq`, `default_affinity` and
  `set_all_affinity` move them, needing `root` or `net_admin`. `link_stats`
  and `driver_stats` follow the interface's `NicCounters` with the emulated
  OS's field and counter names.
- A flow rule's `Drop` drops matching UDP arriving on the interface
  (counted in `rx_dropped`); `Queue` picks the receive queue that
  `napi_for_socket` and `sockets::incoming_cpu` report.
- A Windows adapter change (rings, coalescing, pause, channels, EEE,
  timestamping, interrupt policy, RSS) restarts the adapter: its link is
  down for `NicCaps::win_restart_flap` (2 s) of virtual time, so sends that
  must use it fail with `WSAENETDOWN` and TCP bytes over it are held until
  it returns.
- `snare::fast_talker::sim`: `interface`/`interfaces`
  (`InterfaceSnapshot`, `InterfaceSettings`, `NapiSnapshot`,
  `QdiscSnapshot`, `NicApply`), `irq`/`irqs` (`IrqSnapshot`), `set_irq`,
  `set_driver_stats`, `bump_driver_stat`, `set_queue_stats`
  (`QueueStatsRec`), `mutate_interface`, `thread_by_tid`, and
  `FtEvent::Nic` and `FtEvent::Irq`.
- pcapng: each interface a packet crosses gets its own interface block,
  named after it and stamped in nanoseconds at the instant the packet was on
  the wire (a timed send's launch instant). Packets attributed to no
  interface, TCP among them, stay on interface 0.
- A timed send to a virtual tester reaches it at its launch instant:
  `pop_latest_packet` and `has_pending_udp_packet` skip datagrams whose
  instant is still ahead, and a tester takes datagrams in the order they
  reach it, across every socket sending to it.
- `SocketOptions::apply` and `SocketOption::apply_all` work on snare's
  sockets and follow the emulated OS: fast-talker's field table and text
  for fields the OS lacks, its order, `SO_RCVBUFFORCE` falling back to the
  capped size without `CAP_NET_ADMIN`, `SO_PRIORITY` over 6 and raising
  busy polling needing privileges, the IPv4 TOS resetting `SO_PRIORITY` on
  Linux, `SO_BINDTODEVICE` (`CAP_NET_RAW` to rebind, or always before Linux
  5.7), `IP_BOUND_IF`, Windows' send-only `IP_UNICAST_IF`, and
  `SIO_CPU_AFFINITY` refused on a bound socket. With `dont_fragment` a UDP
  send over the egress MTU fails with `EMSGSIZE`.
- `sockets::udp()`/`tcp()` list snare's sockets shaped as each OS's socket
  table (cookie and inode are the `SocketId`, `interface` the bound
  device), and `sockets::incoming_cpu` is answered by snare.
- `snare::fast_talker::multicast` works on snare's multicast state: join and
  leave (any-source and source-specific), the send interface, hops,
  loopback and `only_joined`.
- `snare::fast_talker::sim`: `SockOptsSnapshot` and `SocketApply` in
  `FtSocketSnapshot::sockopts`, memberships, hops and loopback from the
  socket's own state, `incoming_cpu(id)`, and `FtEvent::Socket`.
- `ThreadOption::apply_all`/`apply_all_to` and `ProcessOption::apply_all`
  on a snare thread run fast-talker's own rules and reports, with which
  options apply following the emulated OS, and carry each option out on
  `snare::fast_talker::rt` with fast-talker's per-OS texts (no CPU affinity
  on macOS, no numeric real-time priority or `mlockall` on Windows).
  `apply_all_to` finds the snare thread by host thread id; guards
  (`LinuxCpuDmaLatency`, `WinTimerResolution`, `WinMmcss`) live as long as
  the report. Each option attempted is logged on the thread (or process) as
  its `Debug` text, unsupported ones as `skipped:<option>`; an option
  variant snare does not know is `Unsupported` and logs
  `FtEvent::UnknownOption`. `compat::apply_thread_options_to` applies to
  any snare thread.
- `Plan::apply` and `Plan::check` on a snare thread work on snare's
  interfaces, interrupts and threads in fast-talker's order (every
  interface opened before any change, link settings read before written,
  housekeeping interrupts, then receive placement and queue settings), with
  its error contexts, drift names and per-OS `Unsupported` texts. Each call
  is kept in `sim::plans_applied` and logs `FtEvent::PlanApplied` or
  `FtEvent::PlanChecked`.
- `monitor::Monitor::start` on a snare thread samples on a background snare
  thread (`fast-talker-mon`) on virtual time: interfaces from their
  `NicCounters`, protocol counters, watched snare sockets and plan drift,
  with fast-talker's sample layout and source-error rules; a watched OS
  socket is reported as a disabled `memory` source. `Config::thread` is
  applied to it through the options above. Each sample holds a busy lease,
  taken as its interval's timer fires, until its callback returns, so under
  a driver samples land exactly on their interval and time stands still
  while one is handled; the callback must not block on a snare wait. Stopping or
  dropping the monitor wakes it at once, even inside a driver timestamp,
  and joins it unless called with driver time. `sim::monitors` keeps each
  monitor's whole config, its thread, sample count, last sample and errors;
  `FtEvent::MonitorStarted` and `MonitorStopped` mark its life.

- Hostnames resolve inside the sim. Every shim socket entry point takes
  `snare::net::ToSocketAddrs` (std's own trait without `shim`), which parses
  numeric addresses as std does and looks names up in `snare::add_host(name,
  ip)` entries, then `localhost` (`::1`, then `127.0.0.1`), before the
  host's `getaddrinfo`. In audit mode (`SNARE_SCHED_AUDIT`, or a driver with
  audit on) any other name fails with an error and is recorded as a
  `QuiescenceViolation` with the new `fatal` flag set (op
  `"host dns lookup"`); otherwise it warns once per name and resolves on the
  host. `SNARE_REAL_DNS=1` always sends such names to the host.
- `snare::thread::park` and `park_timeout` are snare waits under `shim`:
  a parked participant counts as blocked, and `park_timeout` runs on virtual
  time. `snare::thread::current()` returns `snare::thread::Thread`, which
  derefs to std's handle and whose `unpark` wakes them; convert a
  `JoinHandle::thread()` with `Thread::from`, since a std `unpark` does not
  reach a virtual park.
- `snare::mio::net::TcpListener::{set_ttl, ttl}`, `UdpSocket::only_v6`
  (off on a dual-stack Linux or macOS socket, on under Windows, `ENOPROTOOPT`
  on IPv4) and `TcpStream::try_io` / `UdpSocket::try_io`.
- `Errno::AfNoSupport`.

### Changed

- Under `shim`, `snare::mio::net::{TcpListener, TcpStream, UdpSocket}` are
  their own types wrapping (and dereferencing to) the `snare::net` sockets,
  instead of the same types. Like real mio they are nonblocking from
  creation: `bind`, `connect`, `from_std` and `accept` return nonblocking
  sockets, so `recv_from` before `register` and `accept` with nothing
  pending return `WouldBlock` instead of blocking. A snare socket
  registered directly is also switched to nonblocking, listeners included.
  Unlike real mio, `from_std` switches the socket to nonblocking instead of
  expecting the caller to have done so.
- Under `shim`, the socket constructors and `send_to`/`connect` are bounded
  by `snare::net::ToSocketAddrs` instead of `std::net::ToSocketAddrs`. Code
  generic over std's trait, or passing a third-party type that implements
  only std's trait, no longer compiles against the shim.
- An IPv4 UDP socket refuses an IPv6 destination, v4-mapped included, as
  the OS does: `EAFNOSUPPORT` on Linux, `WSAEAFNOSUPPORT` on Windows
  (not measured), and on macOS `EINVAL` for `connect` and for `send_to`
  from a wildcard-bound socket, `EHOSTUNREACH` for `send_to` from a socket
  bound to an address. Previously both succeeded.
- A UDP socket closes when its last handle (including `try_clone`
  copies) drops, freeing its port. Datagrams it had sent to virtual testers
  are still delivered.
- In-flight datagrams are delivered in deadline order, so
  `UdpPolicy::reorder_jitter` reorders instead of holding later datagrams
  behind an earlier one with a longer delay.
- `shim` enables fast-talker's hidden `sim` feature (and its `plan`,
  `options`, `sys-check` and `monitor` features) whenever fast-talker is in
  the build. Its hooks answer only on threads with a snare state slot, so
  fast-talker calls on other threads are unchanged.
- A TCP write into a peer with a `set_tcp_recv_window` cap takes what fits
  and returns the short count instead of all or nothing, and a stream is
  writable to mio only while the peer's window has room. A reader making
  room, a window change, and a peer's close or reset wake a writer blocked
  on a full window.
- Without an explicitly selected OS, would-block and read-timeout errors are
  plain `io::ErrorKind::WouldBlock` errors carrying std's message ("operation
  would block") instead of snare's own text, so building one no longer
  allocates.

### Notes

- `snare::mio::net`'s `bind`, `connect` and `send_to` still take any
  `ToSocketAddrs` where real mio takes a `SocketAddr`, so
  `UdpSocket::bind("..".parse().unwrap())` needs a type annotation under
  the shim. Narrowing them to `SocketAddr` is left for a later breaking
  release.
- Legacy mode keeps today's behaviour: until a slot selects an OS with
  `set_os_semantics` or `SNARE_OS`, every faithful row (ephemeral ports,
  bind errors, read-timeout and would-block codes, connect waits, TCP
  close errors, …) gives the pre-1.6 result, and `add_ip_addr` addresses
  keep their old delivery.
- Faithful mode (an explicit OS) and explicit interfaces (`add_nic`) opt
  into the modern semantics: wildcard delivery, routed source addresses and
  the selected OS's errors. Theater and similar harnesses switch with
  `SNARE_OS=linux` once their testers no longer read owned wildcard
  destinations from `from_local`.
- Not modelled: `EINPROGRESS` for mio connects (a mio connect is the
  blocking std connect), Windows timer granularity, and TCP retransmission
  timeouts on a dead link.
- Publishing needs a fast-talker release with the hidden `sim` feature;
  until then snare depends on fast-talker by path.

## 1.5.0 — unreleased

Not yet published to crates.io; dependents use it by path.

**Unreleased additions to 1.5.0**

- `sched::is_driven()`: whether a wait on the calling thread should be
  snare-visible with a virtual deadline (accounting driver attached, thread
  not background, helper or driver-class). `sched::is_participant()` is
  documented as never registering the caller.
- `sched::block_on_until(future, Option<Instant>)` and
  `sched::block_on_timeout(future, Duration)`: visible waits with virtual
  deadlines under a driver, wall waits otherwise. The future is polled once
  more at the deadline.
- `sched::WakerSet`: deduplicating waker registry with a register-then-recheck
  contract.
- Thread classes: `ThreadClass`, `thread_class()`, `mark_background(label)`,
  `mark_helper()`. Background and helper threads are never registered as
  participants or strays; their snare effects are recorded as `ClassEffect`s
  (`AuditReport::class_effects`, `total_class_effects`) whenever an
  accounting driver is attached, not only in audit mode.
- `sched::setup_scope(label) -> SetupScope`: background marking plus a
  `setup:<label>` busy lease; effects inside it count into
  `AuditReport::total_setup_effects`.
- `Driver::enter_timestamp_checked(t)`: quiescence check and clock move under
  one lock; `NotQuiescent` also when a timer is due before `t`.
- `ParticipantInfo::last_wait` and `ParticipantInfo::leases`;
  `Driver::held_leases()` and `sched::held_leases()` list leases with their
  holder; `Driver::detach()`.
- A timer added by a thread that is not a participant bumps the quiescence
  epoch, so a driver waiting for activity sees its new next deadline.
- Network RNG: loss, duplicate and jitter draws come from a per-flow
  `(source, destination)` xorshift stream seeded from the slot seed and the
  flow's addresses, and no draw is made when the probability is 0.
  `seed_rng` resets every flow. Same-instant sends on different flows no
  longer depend on thread order.
- `sched::testkit::StrictClock` (doc-hidden, `shim` only): a minimal strict
  executive for driver-crate tests.
- `snare::ctrlc` behind the new `ctrlc-compat` feature (`ctrlc-termination`
  forwards `ctrlc/termination`): `set_handler`, `try_set_handler`, `Error`,
  `Signal`, `SignalType`, a re-export of `ctrlc` without `shim`. With `shim`,
  one handler per state slot runs on a `ctrl-c` thread spawned through
  `snare::thread` that parks in a snare wait (`"ctrlc"`) while idle, and
  `ctrlc::raise()` delivers a virtual Ctrl-C with wake-transfer and
  timestamp deferral. A real Ctrl-C is forwarded to every virtual handler
  from `ctrlc`'s thread, marked background.

A scheduler interface so an outside simulation executive can drive the
virtual clock, participant accounting so it can tell when every thread is
waiting, and the network moved onto virtual time. The additions are additive
except for the items marked **breaking** and the timing behaviour changes
listed below.

**Clock and timers**

- The clock is lock-free: every thread caches its state slot's clock, a
  seqlock over an anchored line with the rate in 32.32 fixed point. Readings
  stay monotone across rate changes.
- One timer heap per state slot, fired in `(deadline, seq)` order by one
  lazily started `snare-sched-timer` thread. `thread::sleep` uses it, so
  sleepers no longer each hold an OS wait, and the per-slot `ClockEvent`
  broadcast is gone.
- New `thread::sleep_until(Instant)`, in both builds.
- `resume_time()` restores the rate from before the pause and does nothing
  when the clock is not paused. It used to set rate 1 unconditionally.
- Rates are capped at 1e6.

**New module `snare::sched`** (present without `shim` too)

- `attach_driver(DriverConfig { seed, accounting, audit }) -> Driver`, with
  `AttachError::{AlreadyAttached, NotGlobal, ShimDisabled}`. A driver puts the
  clock in Driven mode: `grant(Grant)` sets a flow line and a horizon the
  clock never passes, `freeze`, `jump_to` (re-checks quiescence under the
  scheduler lock and fires one timer group), `enter_timestamp` /
  `leave_timestamp` (the calling thread reads exactly `t`, everyone else is
  held at `t − 1 ns`, and wakes it causes are deferred until it leaves),
  `quiescence`, `next_deadline`, `arm_notify`, `participants`, `timers`,
  `drain_hints` and `audit`. Attaching seeds the RNG. While a driver is
  attached the legacy clock controls are ignored with a one-time warning per
  call site; dropping it returns to Scaled mode, frozen.
- Participant accounting: spawn handoff in `thread::spawn` and
  `Builder::spawn[_scoped]`, registration on a thread's first blocking call or
  when it wakes a participant (counted as a stray), and
  `participate(name) -> ParticipantGuard`. Wake-transfer happens under the
  scheduler lock before the OS wake. `mark_driver_thread` and
  `with_driver_time(t, f)` for executive-side threads.
- Blocking primitives: `park(deadline)`, `Unparker`, `current_unparker`,
  `block_on`, `Sleep`/`sleep_until` (dropping a `Sleep` cancels its timer).
  `busy(label) -> BusyLease` and `hint_starving(source, severity)`.
- Types: `Quiescence`, `BlockerKind`, `ParticipantInfo`, `PState`,
  `TimerInfo`, `AuditReport`, `QuiescenceViolation`, `ParkResult`,
  `NotQuiescent`.
- Audit mode (`DriverConfig.audit` or `SNARE_SCHED_AUDIT`) records socket
  writes, connects and wakes made by threads that are blocked or unknown and
  hold no lease.
- Without `shim`: `park`, `block_on` and `Sleep` run on wall time, the
  accounting calls are no-ops, and `attach_driver` returns `ShimDisabled`.

**Network**

- Every blocking site (TCP read, write window, accept, connect,
  linger; UDP receive; mio `Poll::poll`; the tester loop) registers with a
  per-resource wait set before checking readiness and then parks. This fixes
  lost wakeups, including the intermittent `accept` hang in the `pcapng`
  tests, and a mutation now wakes only its own resource's waiters. Blocked
  threads carry a wait label (`"tcp read"`, `"tcp accept"`, `"udp read"`,
  `"mio poll"`, …).
- `NewDataEvent`, `wait_for_event` and `trigger_event` are removed, and so is
  the `event-listener` dependency.
- `connect_timeout` honours its timeout.
- `TcpConnections` and `TcpListeners` are ordered maps, so iteration order is
  deterministic.
- New `inject_udp_from_test` for latency or loss on UDP sent between two
  in-process sockets, which bypasses the destination's `UdpPolicy`.
- Fixed: a blocking UDP `recv` never released latency-delayed datagrams;
  connected UDP `recv`/`peek` held the peer lock while blocked; mio stream
  status and TCP pending release could pick the wrong connection when several
  accepted connections share a local address; `poll(Some(0))` returned
  before scanning.
- mio TCP stream writability is edge-triggered, as in real mio: reported once
  after registration, then again only after it was lost or a non-blocking
  write returned `WouldBlock`. Level-triggered, an idle poller registered for
  `READABLE | WRITABLE` never blocked, so it spun a core and kept the
  scheduler from ever seeing it idle.


**Timing behaviour changes**

At rate 1 in Scaled mode nothing observable changes. At any other rate, and
whenever the clock is paused or driven, network timing now follows virtual
time instead of wall time:

- latency and jitter releases, quiesce windows, `DelayingUntil`, linger, and
  read, write and poll timeouts;
- the tester's `TimerState` and cyclic actions, its idle poll, and the
  `run_testers!` start-up sleep (500 ms virtual);
- `RecordedEntry.at` and pcapng packet timestamps (virtual `SystemTime`;
  `SNARE_PCAPNG_WALL_COMMENT` adds the wall time as a packet comment).

A paused clock therefore stalls every network timeout. Code that must wait on
wall time regardless should use `thread::real_sleep`.

**Breaking**

- `ListenerBehavior::DelayingUntil` and `RecordedEntry.at` hold
  `snare::time::Instant` instead of `std::time::Instant`.
