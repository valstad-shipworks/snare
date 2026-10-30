# Open bugs

Every known bug in snare, where the simulation differs from the real OS or breaks one of its own
rules. Keep it current: add an entry when a bug is found, and delete the entry in the same change
that fixes it.

The usage invariant is that every resource or object used by the code under test is created under
its active simulation. Passthrough is reserved for other-side emulation and harness operations.
Supplying the code under test with native objects created outside its simulation violates that
contract; robustness probes of such objects do not establish a gap in supported application usage.

Some entries have a regression test marked `#[ignore = "bug: …"]`. The test fails today and is
meant to pass once the bug is fixed: remove the `ignore`, run it, then delete the entry. List them
with:

```sh
rg -n 'ignore = "bug' crates
```

"Host" means the real OS on the same machine (the `*_os_truth` tests compare against it).

## Host planes

- **Local time** (`local_time.rs`, `local_time_os_truth.rs`, `local_time_win.rs`):
  - The `tzname`, `timezone` and `daylight` globals (and macOS's `altzone`) stay the process's.
    They are data every thread shares, read and written without a call snare could hook, so no
    sim can have its own: writing a sim's values into them at its `tzset` would show its zone to
    every concurrent sim and to code outside any sim. What the C library reads from them inside
    itself is answered from a per-sim copy (strftime's `%Z` of a `struct tm` without a zone
    name, macOS's `%z`). The copy moves with the sim's conversions as the library's does, but
    glibc also moves its own at each probe of mktime's search, and the sim only at the result.
  - In one strftime call, a `%Z` after a `%s` prints the name from before the conversion `%s`
    makes, where the C library prints the one after.
  - libc functions that convert inside themselves without a hook reaching them see the
    machine's zone: `getdate` and `getdate_r` (which also read the `DATEMSK` template through
    libc's own `fopen`), and strptime's `%s`.
  - `CFTimeZoneSetDefault` is process-wide; a sim that decides its zone answers
    `CFTimeZoneCopyDefault` with its own regardless. Leap-second records of `right/` zones are
    not applied.
  - jiff caches the system zone for the process for five minutes, so a jiff call in a sim can
    get the zone another sim (or the process) had when it filled the cache.
  - Windows: a sim's zone comes only from `SimBuilder::time_zone`. A `TZ` the code under test
    sets in an isolated environment does not choose it; one in the process's own C runtime
    environment hands the UCRT's calls to the real UCRT. `SetLocalTime`, `SetSystemTime`,
    `SetTimeZoneInformation` and `SetDynamicTimeZoneInformation` reach the machine (and need
    privileges the unelevated user lacks). The UCRT's `_getsystime`, `_setsystime`,
    `_timespec64_get` (`timespec_get`) and `clock` read or set the real clock. A UCRT linked
    statically (`crt-static`) is not interposed at all.

- **Environment** (`edge_host_env.rs`): on Linux, `std::env::vars` in an isolated sim lists the
  real process environment. It accesses the process-global `environ` variable directly, outside
  function interposition. Swapping `environ` would expose simulated values to concurrent sims and
  unmanaged threads. macOS enumeration is served through `_NSGetEnviron`.

## Linux error queues

UDP data and arrived error reports share a bounded receive-memory budget, measured across
IPv4/IPv6 payload sizes and buffer limits in `error_queue_limits.rs`. Remaining TCP differences
can change which reports fit and drop:

- The UDP budget is calibrated on the kernels it was measured on. On 6.17.0-azure (GitHub's
  `ubuntu-latest`), the real bursts in `report_capacity_charge_and_payload_match_linux` fall
  outside that calibration: every one of 32 reports fits within a 32768-byte limit at a
  30720-byte charge. In `ordinary_data_and_error_reports_share_the_receive_budget`, four errors
  plus four datagrams are all held. `SysLimits::from_real_host` does not measure the per-report
  charge or the minimum receive buffer, so the sim cannot follow such a kernel. CI skips both
  tests on Linux.

- TCP uses calibrated MSS, GSO grouping and advertised-window updates when the receiver has
  explicitly set `SO_RCVBUF` or the sender requests transmit timestamps. The enabled
  `tcp_error_queue_segments.rs` IPv4 host comparisons cover writes through 128000 bytes across
  five receive-buffer sizes, final-segment payload/charge, and reports deferred until transmission.
  Ordinary TCP data retains its segment charge until that segment is fully read and shares the
  error-report budget (`error_queue_limits.rs`). Default receive-buffer autotuning, kernel RX
  coalescing, congestion-window evolution and ACK pacing remain unmodelled. Streams with neither
  an explicitly set receive buffer nor transmit timestamp requests retain the byte-window
  approximation; their segment layout and report admission can differ.
- `SysLimits::tcp_gso_max_size` defaults to the legacy 65536-byte device limit. Driver-specific
  limits require a measured profile override; `from_real_host` does not discover them. Explicit
  `TCP_MAXSEG` overrides, large IPv6 reports and concurrent writes/timestamp-option changes are
  outside the tested transport matrix. These cases need host comparisons before claiming exact
  report grouping.

## Network model boundaries

- Dual-stack IPv6 is modelled on the plain fabric, a `SimHost`'s Linux datagram sockets and
  Winsock (`tests/dual_stack_os_truth.rs`). Unmeasured or not followed: IPv4 multicast on a
  dual-stack socket (Linux takes `IP_ADD_MEMBERSHIP` on one, macOS refuses it), a macOS
  `IPV6_V6ONLY` socket's connect to a v4-mapped address (the host picks an IPv6 source), a macOS
  socket once connected to IPv6 refusing a v4-mapped connect after an `AF_UNSPEC` dissolve, a
  Linux socket whose IPv6 source came from a connect rather than a bind connecting to a v4-mapped
  address (the host allows it; the sim refuses it as for a bind), the TTL macOS gives a v4-mapped
  send after `IPV6_V6ONLY` changes, and whether a Windows dual-stack datagram socket connected to
  an IPv4 address takes IPv6 datagrams sent to its port (the sim keeps a Windows socket where it
  was bound for delivery, so it does).
- Port sharing (`SO_REUSEADDR`, `SO_REUSEPORT`, Windows `SO_EXCLUSIVEADDRUSE`) follows the host's
  bind and listen rules and its choice among sockets sharing an address (`tests/
  reuseport_os_truth.rs`), except: a Linux `SO_REUSEPORT` group picks a member by a hash snare
  keys with the sim's seed, so which member a given flow reaches differs from a real kernel's
  (flows keep to one member, as there); `SO_ATTACH_REUSEPORT_CBPF`/`EBPF`, `SO_INCOMING_CPU` and
  a group's split by `SO_BINDTODEVICE` are unmodelled, and so is `TIME_WAIT` in the bind rules.
  macOS delivers a multicast datagram only up to the first matching socket without either option
  (newest first); the sim delivers to every member. Windows' earliest-bound choice is measured on
  loopback only; setting `SO_REUSEADDR` or `SO_EXCLUSIVEADDRUSE` to 0 while the other is on, and
  either after the bind, are unmeasured. A bind to port 0 always takes a port no socket of the
  family holds; Linux would also hand out a port held only by sockets the new one may share it
  with, and Windows' choice beside a wildcard bind is unmeasured.
- Control messages left out (`src/ancillary.rs`): IPv4 options (`IP_RETOPTS`), IPv6 flow labels,
  next hops and extension headers, Linux `SCM_TS_OPT_ID`, and a `SO_TIMESTAMPING` message on a TCP
  `sendmsg` fail with `EOPNOTSUPP`, as does any control message on a `socketpair` end
  (`SCM_RIGHTS`, credentials). Receive options other than the TOS/TTL/packet-info ones
  (`IP_RECVOPTS`, `IP_RECVORIGDSTADDR`, macOS `IP_RECVIF`, `IPV6_RECVRTHDR`, …) and the receive
  options of TCP sockets are unmodelled. On the plain fabric an `SCM_TXTIME` launch time is checked
  but not applied (no qdisc). Linux GRO is modelled only for a segmented send through loopback,
  which a `UDP_GRO` receiver reads whole whatever its size, though Linux 7.0 split a 66-segment
  send over a 1500-byte loopback MTU into datagrams; datagrams that crossed an interface are never
  coalesced.

- Completed TCP accept queues enforce the configured backlog, with host comparisons on macOS,
  Linux and Windows. Separate incomplete-handshake queues and simultaneous SYN/ACK completion
  races are not represented. Winsock can transiently accept more simultaneous handshakes than
  its completed-queue limit; the calibrated sequential comparison waits for each handshake to
  enter that queue.
- macOS TCP read shutdown follows the configured incoming-data and return-reset delays.
  Native syscall overlap while a writer copies data, Nagle delays and ACK pacing remain
  unmodelled; unpaced writes need not reproduce the host's frequencies of `EPIPE`
  versus `ECONNRESET`. Paced shutdown comparisons require exact native/model equality.

## Descriptor operations

- Replacing a real socket with positive `SO_LINGER` retains a temporary native alias and
  closes it after the descriptor mutation lock is released. This supports successful replacement
  without holding that lock across transport shutdown, but needs one spare descriptor; native
  `dup2` can succeed without that spare descriptor when the table is full.
- Socket `fcntl` keeps the signal-driven I/O owner, signal and `O_ASYNC`, but no `SIGIO` or
  `SIGURG` is ever sent, and `F_SETOWN` does not check that the process exists (no `ESRCH`).
  Linux `F_DUPFD_QUERY` and the write-life hints (`F_GET_RW_HINT`, `F_SET_RW_HINT`) still return
  `EINVAL`, as does every command beyond the flags and duplication on the fabric's epoll, kqueue,
  eventfd and timerfd descriptors, where the host answers some (Linux `F_SETOWN` takes any file).
  `strict_sockopts` does not validate these commands.
- `select` on fabric descriptors (`fabric.rs` `Net::select`) waits through the fabric's `poll`,
  so its microsecond timeout is rounded up to whole milliseconds: a 200 µs wait lasts 1 ms on the
  sim's clock, where the host waits the microseconds asked for. Code that waits out sub-millisecond
  deadlines with `select` (a raw-socket receive inside a 1 ms cycle) runs late under the sim.
  Linux's `select` also writes the time left back into the `timeval`, which the fabric never does.

## Windows

Runtime comparisons on Windows 11 ARM64 (10.0.26200.9457) cover socket defaults, hop-limit and
fragment-option aliases, partial `MSG_WAITALL` timeout/EOF behavior, TCP `WSARecvMsg` errors,
direct-import `WSASendMsg`, strict socket options, adapter restart cancellation, priorities,
timer-resolution requests, clock control and high-resolution sleep. This establishes the tested
cases on that host, not every Winsock hook or supported Windows release.

- Wrong-family socket options beyond the hop-limit, fragment and PMTU matrices still need host
  comparisons. Partial `MSG_WAITALL` with peer reset or local `SD_RECEIVE`/`SD_BOTH` shutdown,
  through both `recv` and `WSARecv`, has Windows 11 ARM64 host comparisons. Queued TCP data
  followed by peer reset also has comparisons. IPv4 loopback UDP port-unreachable statuses
  received through `recv` have comparisons with one or three spaced errors and queued data
  before, between and after statuses, plus bursts of eight errors without interleaved data.
  These cover connected and unconnected sockets, reset reporting enabled and disabled,
  `MSG_PEEK`, receive readiness, and `SO_ERROR` returning zero without consuming statuses.
  Reset-option toggles preserve an already queued status while controlling subsequent
  errors on the tested host. Larger receive-status queues, other ICMP errors and other pending
  socket errors remain unmeasured.
- Scheduling and working-set calls validate handle type and access rights. Duplicate and
  current-thread handles share thread state; each tracked thread retains one native handle until
  `WinHost` is dropped. Valid foreign process/thread objects return `ERROR_NOT_SUPPORTED` (50).
  Process/thread background transitions, inherited threads, overlaps and class changes have
  host comparisons, with `REALTIME_PRIORITY_CLASS` granted (run as SYSTEM) and refused
  (reported as `HIGH_PRIORITY_CLASS` to an unelevated user).
- MMCSS registrations (`AvSetMmThreadCharacteristicsW`, `AvSetMmThreadPriority`,
  `AvRevertMmThreadCharacteristics`) are kept apart from the thread's priority: on Windows 11
  `GetThreadPriority` reads 15 once a thread joins "Pro Audio", 17 and 18 after
  `AVRT_PRIORITY_HIGH`/`CRITICAL`, and 0 after the revert, while the sim keeps reporting the
  priority `SetThreadPriority` last set. A successful revert also leaves `ERROR_INVALID_HANDLE`
  (6) as the thread's last error on the host, which the sim does not. Task indices count from 1
  per host rather than following the system-wide counter, and only the task names of a stock
  Windows 11 installation are known.
- Power throttling covers `ProcessPowerThrottling` and `ThreadPowerThrottling`; the other
  `SetProcessInformation`/`SetThreadInformation` classes (memory priority, app memory, dynamic
  code policy, ...) still reach the real process. `GetThreadInformation`'s rules for a short or
  long buffer and a version of 0 are assumed to be the setter's, and are unmeasured.
- CPU sets: `GetSystemCpuSetInformation` groups logical processors into uniform cores of
  `SimBuilder::threads_per_core`, all in NUMA node 0 with no flags (`Parked`, `Allocated`,
  `RealTime`) and efficiency class 0, so hybrid machines with cores of different sizes or
  classes, or several nodes, are not represented; its `Process` and `Flags` arguments are
  ignored. Selected CPU sets do not interact with `SetThreadAffinityMask` or
  `SetProcessAffinityMask` as they do on Windows.
- Processor topology (`win_cpus_os_truth.rs`): the simulated machine has one package and one die,
  so a machine with several (the Parallels VM has one package per processor) is compared without
  its package and die records. The VM's caches are all per core, so where `RelationAll` and
  `GetLogicalProcessorInformation` list a cache several cores share (the sim lists it after the
  last core) is unmeasured, as is whether a module is always one core. Hybrid machines'
  efficiency classes and per-core cache differences are flattened to those of the core running
  logical processor 0. The calls that name the processor a thread is running on —
  `GetCurrentProcessorNumber(Ex)`, `GetNumaProcessorNode(Ex)` — and
  `NtQuerySystemInformation`'s processor classes (`SystemBasicInformation`, ...) still answer
  from the machine, so with fewer simulated processors than real ones a thread can report a
  processor number the sim does not have. sysinfo's per-processor usage comes from PDH counters
  (`\Processor(n)\% Processor Time`), which read the machine.
- Timers created through `CreateWaitableTimerW/A` and `CreateWaitableTimerExW/A` support unnamed
  relative/absolute deadlines, periodic auto/manual-reset signals, same-process handle aliases,
  cancellation,
  `SetWaitableTimerEx` without a reason context, and non-alertable single/timer-only multiple
  waits. Native comparisons cover signal state, atomic wait-all consumption, alias access rights
  and cleanup after a run. Named/security attributes, APC callbacks, resume requests, reason
  contexts, cross-process aliases, alertable timer waits and blocking mixed-object waits return
  `ERROR_NOT_SUPPORTED` (50). Tolerable-delay requests use the exact deadline
  rather than modelling the host's coalescing policy.
- Rust's Windows sleep conversion discards sub-100 ns precision; finite std synchronization
  timeouts use a millisecond `WaitOnAddress` timeout. Overflowing Rust sleep durations reach the
  clock through a typed hook before conversion and saturate at the finite clock limit. Native
  `Sleep(INFINITE)` and non-alertable `SleepEx(INFINITE)` retain their infinite waits.

- Loopback TCP fill differs on Windows Server 2025 (10.0.26100, x86_64 GitHub `windows-latest`):
  `tcp_buffers_os_truth::unread_stream_fill_matches_real_os` measured 4096 bytes taken before
  `WSAEWOULDBLOCK` with 4096-byte `SO_SNDBUF`/`SO_RCVBUF`, where Windows 11 (ARM64 26200 and the
  ARM64 runner) takes the 12288 the model gives. It is the only Windows test that still fails
  there. The comparison stops at its first case, so the larger buffer cases are unmeasured there.
  Telling the editions' rules apart needs native measurements on Server 2025; the model follows
  Windows 11. CI skips the test on `windows-latest`.

IOCP uses native completion ports with modeled non-alertable waits and Mio's single-socket
`\Device\Afd\Mio` poll profile (infinite timeout, non-exclusive). Native comparisons cover
posted packets, empty-port virtual deadlines, failed native-file completions, AFD cancellation
and immediately readable sockets, completion status/byte counts, native socket passthrough and
new delayed arrivals after an infinite wait starts. Modeled port and AFD-helper aliases, alertable
modeled-port waits, mixed native/modeled port traffic, multi-socket polls, finite AFD timeouts and
exclusive AFD polls are explicitly unsupported. These boundaries do not establish general
overlapped-I/O support.

Missing Windows features: overlapped and event-notified I/O, TCP urgent data and
keepalive-driven dead-peer detection.

- Control messages (`win_sockopt`), compared with Windows 11 ARM64 build 26200.9457 by
  `cmsg_win_os_truth`, leave out: an `IP_PKTINFO`/`IPV6_PKTINFO` with an unspecified source address
  from a wildcard-bound socket, which Windows fails with `WSAEINVAL` for interface 0 and otherwise
  reports sent and delivers nothing on loopback, while the sim sends from the route's source; the
  routing effect of a chosen source or interface on a host with several interfaces (unmeasured:
  the sim keeps the route and changes only the source); the receive options `IP_RECVIF`,
  `IP_RECVDSTADDR`, `IP_ORIGINAL_ARRIVAL_IF`, `IP_PKTINFO_EX` and `IP_RECVERR`, which return no
  message (and `IP_RECVDSTADDR`, which Windows accepts, fails `WSAENOPROTOOPT`). A `WSARecvMsg`
  that fails `WSAEMSGSIZE` (data or control cut) leaves its byte count unwritten, where Windows
  writes the bytes copied. Coalescing happens only for a segmented send through loopback; a
  segmented send checks don't-fragment by its segment size, unmeasured. A segmented send's own
  limits beyond 200000 bytes in 1000-byte segments or 65507 one-byte segments are unmeasured.
- Options read into a buffer shorter than 4 bytes are written cut with a length of 4, where
  Windows fails most with `WSAEFAULT` (the receive options, offload sizes and `IPV6_V6ONLY` do)
  and writes `IP_DONTFRAGMENT` as one byte.

Shared/exclusive SRW locks, critical sections and raw condition-variable waits have hooks and
native comparisons. Application objects initialized before entering the simulation are outside the
usage contract. Process-runtime synchronization can still lack owner metadata. Windows filesystem
APIs also reach real process state;
the corresponding isolation guarantees require additional hooks and parity tests.

An isolated Windows environment (`env_win.rs`) covers the kernel32 and UCRT environment calls
and `CreateProcessW`/`A`. Reads a system library makes internally still see the real process
environment: `GetTempPathW` (`std::env::temp_dir`) reading `TMP`/`TEMP`, drive-relative path
resolution reading the `=C:` drive directories, `CreateProcessW` searching `PATH` for a command
line given without an application name, and `CreateProcessAsUserW`/`ShellExecuteExW` children. The
UCRT's `_environ`/`_wenviron` tables, read directly rather than called, are the real ones. The
ANSI calls are compared under code page 1252 only, where an ANSI string is as long as its UTF-16
form; their limits under a double-byte code page are unmeasured.

## File plane

Regular virtual files support positional IO, truncate and sync without reaching the backing
`/dev/null`; proc/sysfs text snapshots support positional reads and handle write, truncate and sync
errors directly. Read-only proc/sysfs descriptor comparisons run against Linux. Remaining differences
are real model gaps:

- VirtualFs models directory descriptors, raw directory records, `fdopendir`, filesystem
  statistics, sparse pages with configured storage limits, hard links, working-directory-relative
  paths, and symbolic links within one plane. Native comparisons cover `chdir`/`fchdir`/`getcwd`,
  renamed and unlinked directory identity, relative/absolute link targets, `readlink`, final-link
  flags, loops and traversal limits, directory-relative calls, and pathname mutations. Symlink targets
  outside the owned namespace or into passthrough are rejected with `EXDEV`; cross-plane symlink
  traversal and interior parent traversal into another plane are not supported. Paths from an
  unlinked directory retain `.` identity, but parent/child traversal still requires a namespace
  path. Linux `O_PATH | O_NOFOLLOW` and macOS `O_SYMLINK` handles are rejected with `EOPNOTSUPP`.
  Full pathname length limits and mount semantics remain unmodeled.
- VirtualFs permissions (`fs_permissions.rs` compares them with the host as root and as an
  unprivileged user) leave out:
  - ACLs, BSD file flags (`chflags`), Linux `fs.protected_hardlinks`/`protected_regular` and
    capabilities finer than `Privileges::root`, which stands for all of the file ones.
  - Search permission is checked on every directory from the root, also for a path relative to
    the working directory or a directory descriptor, where the kernel starts at that directory: a
    sim that changes into a directory under one it may not search fails where the host succeeds.
  - macOS root's rules come from its manual pages (chmod(2), chown(2)), not a measurement: the
    comparisons there run as an ordinary user.
  - The umask is the sim's own. Real files a sim creates with `open`, `creat` or `mkdir` are masked
    by it and by the process's umask both; `mkfifo`, `mknod` and `AF_UNIX` `bind` use the process's
    alone.
  - `SimHost` files keep their modes: `chmod` fails with `EPERM`, and so does a `chown` naming an id,
    where root may change a sysfs attribute or device node on Linux.
- SimHost rejects positional writes to virtual device nodes with `EOPNOTSUPP`;
  device-specific parity is unmeasured.
- Mutable file flags cover append/nonblocking, not every host `fcntl` operation.
- A mapped `VirtualFs` file counts a page that a shared mapping first fills as allocated only once
  a `stat` or `statfs` finds data in it, and then beyond the storage limit if need be; a full disk
  would raise `SIGBUS` at the faulting write instead.
- A file another sim's plane opened is served by that plane for I/O and descriptor calls from any
  thread, but paths resolve per sim, and a directory descriptor another sim's plane opened is
  outside the usage contract as a base for them. The working directory says where a sim's relative
  paths resolve, and the interposer resolves them in the sim's own planes; a directory of another
  plane would have to send every relative path of the sim, `getcwd` and `chdir("..")` to that plane,
  under its passthrough and deny policy, while absolute paths stay in the sim's own, and would
  dangle once that sim ends. So `fchdir` through such a descriptor fails with `EXDEV` (as a symlink
  out of a plane's namespace does; `EBADF` once its sim is gone) and leaves the working directory
  alone (`fs_shared_descriptors.rs`). An `*at` call relative to such a descriptor still reaches its
  `/dev/null` placeholder and fails with `ENOTDIR`.
- File timestamps follow the sim's clock (README, "File timestamps"), with these limits:
  - Writes through a mapping of a `VirtualFs` file stamp its modification time at the first
    `stat` after the host object it is mapped from shows them in its own times: on Linux at the
    write fault, on macOS at `msync` or page-out. A mapping write within the same host timestamp
    tick as the plane's last look at the object (its own last write, or the last `stat`) goes
    unseen.
  - On real files the sim records only what it does through the hooked calls. Path `truncate(2)`,
    `fallocate`, `copy_file_range`, `sendfile`, writes through a mapping, writes through a descriptor
    opened before the sim or duplicated outside the hooks, and another process's changes
    show at the time of the first `stat` in the sim that sees the host's times move; so do access
    times, which the sim takes from the host's (its mount's `relatime`/`noatime`), not from its own
    reads. Records are per (device, inode); an inode freed and reused outside the sim is noticed
    through a different birth time, which Linux reports only through `statx`, so a reused inode
    seen first through plain `stat` keeps the old record's times. A file system without birth
    times (no `STATX_BTIME`) still reports none for a file the sim created.
  - A `VirtualFs` handed to several sims keeps the clock of the first one built.
  - Windows has no file plane: `GetFileTime`, `GetFileInformationByHandle(Ex)` and directory
    enumeration report host times next to the sim's clock. Following it there needs hooks on those
    calls and per-handle bookkeeping that do not exist yet.

## Ignored validation

Hardware and privileged tests remain opt-in when they require an adapter, PTP clock, peer
reflector, npcap, a private network namespace, or permission to change device settings. Their
guards do not establish that the model passes those comparisons. Windows adapter-row comparisons
now capture the measured physical medium; the UDP-statistics comparison runs by default without
adapter prerequisites.

Validated read-only (crates/snare/tests/README.md, "Recorded runs"): the `ethtool` reads, the
`CAP_NET_ADMIN` refusals, `SIOCGHWTSTAMP` and `BIND_PHC` on a Linux 6.8 x86_64 host's `atlantic`
(AQC107) and `igb` (I211) NICs; the on-link absent-neighbour calibration (`EHOSTUNREACH` after
3.1 s) on that host's LAN; `linux_netns_ground_truth` in a Docker namespace; and the three
read-only Windows adapter tests on the Windows 11 ARM64 VM's VirtIO adapter. The only mismatch,
`ETHTOOL_GDRVINFO`'s driver counts, is modelled. Still unrun: every mutating test, the peer
exchanges, `hw_ptp_truth` (the PHC there is root-only), Npcap and adapter writes, and any
physical Windows NIC.

Eight Windows OS-truth comparisons are ignored on Windows (`#[cfg_attr(windows, ignore)]`)
because the model follows a Windows 11 build 26200 machine and the GitHub runners (Windows
Server x64 and the Windows 11 ARM64 runner) answer differently; each is a model gap to resolve
by version or capability, not a runner fault:

- **UDP segmentation and coalescing** (`cmsg_win_os_truth::ipv4_segmentation_and_coalescing_match_the_host`,
  `ipv6_…`, `receive_control_buffers_match_the_host`, both runners): a receiver with
  `UDP_RECV_MAX_COALESCED_SIZE` set reads a segmented loopback send one segment at a time with no
  `UDP_COALESCED_INFO` control message on the runners; the model coalesces the segments into one
  datagram carrying `UDP_COALESCED_INFO`, as the 26200 machine did. Which Windows coalesce over
  loopback, and under what condition, is undetermined.
- **`IP_TOS`** (`cmsg_win_os_truth::receive_and_offload_options_match_the_host`,
  `ipv4_send_control_messages_match_the_host`, `dual_stack_os_truth::v6only_option_os_truth`,
  Windows Server runner only): `setsockopt(IP_TOS)` with 1 to 3 succeeds and reads back on the
  Server runner, and a `TOS` control message is accepted (sent with TOS 0); the model refuses
  both with `WSAEINVAL`, as Windows 11 26200 does. The Windows 11 ARM64 runner agrees with the
  model.
- **IPv6 send control messages** (`cmsg_win_os_truth::ipv6_send_control_messages_match_the_host`,
  Windows Server runner only): a send option the test takes for granted fails with
  `WSAENOPROTOOPT` on the Server runner before any comparison is made.
- **`GetLogicalProcessorInformationEx` with a short buffer**
  (`win_cpus_os_truth::logical_processor_information_matches_the_host`, both runners): with room
  for one record (32 or 63 bytes) the runners' kernels write the first record of relationship 3
  (cache) where the model writes relationship 0 (processor core) first; the record order is the
  kernel's and the model's differ.

- **Africa/Casablanca on macOS** (`local_time_os_truth::local_time_matches_the_c_library`, the
  zone is skipped there): the macOS runner's C library prints `%Z` as `XXX` or `+200` and `%z`
  as `+0200` for 2024 instants in that zone, where the model prints `+00`/`+0000` from the
  zone file's negative-daylight-time rules; which tzdata the runner carries, and what its
  `strftime` does with that zone's abbreviations, is undetermined.

Four tests retain guards for information unavailable at the current interception boundary:

- **Linux environment enumeration:** `edge_host_env::iterating_an_isolated_environment_lists_only_its_variables`
  and `demo_vfs_env_limits::vars_should_enumerate_the_simulated_environment` still expose the real
  environment. [Rust's enumeration](https://github.com/rust-lang/rust/blob/1.98.0/library/std/src/sys/env/unix.rs)
  reads `environ` directly. Swapping this process-global pointer cannot preserve isolated
  concurrent sims and unmanaged readers. A Rust-level enumeration hook or separately isolated
  worker processes can provide the missing boundary. Serial execution with an explicit ban on
  other environment readers is a narrower contract, not the existing isolation guarantee.
- **Outside-held std mutexes on Linux and Windows:**
  `outside_locks::a_std_mutex_held_outside_the_sim_holds_time_still` still permits time to advance
  while the outside holder owns the mutex. This fixture constructs the mutex inside `Sim::run`;
  its outside holder is a passthrough harness thread, so the creation invariant alone does not
  exclude it. The supported std mutex's inline atomic fast path
  records no owner, and futex/`WaitOnAddress` supplies the wait word without the holder's identity.
  Treating every such wait as outside-held would prevent an inside holder's virtual sleep from
  completing. Supporting both cases requires ownership instrumentation above the wait ABI,
  such as an instrumented std build or an owner-aware lock API. A `busy()` lease remains an
  explicit application workaround; it does not make this unchanged regression pass. A participant
  blocked on a word in static data no longer makes the run read as deadlocked, so blocking socket
  calls keep waiting instead of failing with `EAGAIN`/`WSAEWOULDBLOCK`
  (`blocking_read_outside_lock`); a genuine deadlock on such a word now stalls with the stall
  warning rather than giving up.

## Known limitations

Supported model boundaries and unverified approximations. These do not establish OS parity.

- **Windows Rust sleep implementation boundary:** overflow saturation depends on calls reaching
  the linked Rust sleep implementation. Transparent entry tail jumps are followed before
  installation. A compiler that inlines the entire implementation, or a separate module with
  its own statically linked std copy, can bypass that hook. Such builds need instrumentation
  before Rust's timer conversion; native `Sleep(INFINITE)` cannot recover the finite duration.
  Installation refuses unsafe prologues and propagates suspension or executable-memory errors.

- **Locks held outside the sim:** a wait on an ownerless lock held outside the sim can still let
  time skip. Linux futex and Windows `WaitOnAddress` waits in static data get a 1 ms real grace;
  an outside holder that keeps such a lock longer, and arbitrary heap-backed std mutexes, do not.
  Under `deterministic()` such a wait keeps the baton for 50 ms of real time before it passes it,
  after which the run's order depends on how long the outside holder took; std's thread-start lock,
  which parallel tests' spawning threads hold, otherwise broke replay under load
  (`edge_scale_testers`). A holder inside the domain costs a deterministic wait those 50 ms. macOS pthread mutexes name their owner; a
  deterministic wait on one held outside the schedule keeps the baton for the same 50 ms, then waits
  in the schedule for the unlock, so its order too depends on how long the holder took.
  std's one-time Windows Winsock startup, which holds its `Once` far longer, is run outside every
  domain before the first one is installed. macOS std `RwLock` and `Once` can park on ownerless
  semaphores.
- **Locks and statics shared by sims running at once:** parking_lot's bucket locks are
  process-wide, and on macOS its threads park on per-thread pthread condition variables that
  name no lock, so a thread of one sim can wait on a bucket a thread of another sim holds. A
  plain sim's untimed condition-variable wait, and a futex or `WaitOnAddress` wait in static data
  or after a back-off spin, is held off, uncounted, while a participant of another live sim
  running as it began may hold the lock: until each has parked, left, or run for 1 ms of CPU time
  as the OS last updated it, and for at most 1 s. A holder that is not a participant (another
  sim's background, helper or driver thread) is not waited on; nor, past its own sim's running
  participants, is one counted parked holding one bucket lock while it waits for another. A
  Linux futex or Windows `WaitOnAddress` wait on a bucket that queues behind another waiter
  without spinning is not held off. tokio's signal handling keeps one pending flag and one watch
  channel per signal for the whole process, so one sim's driver can take the record of a signal
  another sim raised and carry the wake for that sim's listener: a sim that reaches a socketpair
  another sim keeps in a static (tokio's signal pipe), plain or deterministic, holds its time
  skips back on the other sims' participants running as it became quiescent, the same way and for
  as long. The carried wake still comes after the skip when the thread carrying it is not a
  participant, runs for more than that 1 ms of CPU time or 1 s before making it, or is counted
  parked on the way (on a lock whose holder in a third sim outlasted the carrier's own hold-off);
  tokio's driver makes the wake a few calls after it takes the record, with only the locks of
  its signal registry between. An external holder's `sim.busy()` lease prevents an incorrect
  skip, and an owner-aware wrapper is another path.
- **Wakes taken by waiters the census does not list:** a condition-variable signal, futex wake or
  `WakeByAddressSingle` made while a participant is parked on the object counts that participant
  released until it returns, as the OS may hand the wake to any waiter there. A participant's own
  uncounted wait on the object (a grace for an outside holder, an attempt of a held-off wait)
  takes the release over when the wake reaches it (on Linux, while the word's pending wakes are
  one record, none of another mask or already claimed), but a waiter of another class or of no
  sim does not: if the wake goes to it, the parked participant stays counted released, and its
  domain is never quiescent, until something else wakes it. It needs a participant and such a
  thread waiting on one condition variable, futex word or address at once.
- **Restricted Linux futex introspection:** checked wait admission safely reads the futex word
  through `process_vm_readv`, falling back to readable mappings in `/proc/self/mem` when the
  syscall returns `EPERM`, `EACCES` or `ENOSYS`. Seccomp subprocess comparisons cover virtual
  `FUTEX_WAIT`/`FUTEX_WAIT_BITSET` deadlines and malformed pointers in native and deterministic
  modes. The fallback requires readable `/proc/self/maps` and `/proc/self/mem` and one spare
  native descriptor. If both read paths are unavailable, managed waits still fall back to
  untracked native waits without virtual timeout translation. A profile that traps or kills
  the helper syscall cannot take the fallback; it can terminate the process instead.
- **Shared futex mapping aliases:** private/shared key spaces and bitset masks are distinguished
  for a single address. Shared waits on different virtual addresses mapping the same backing
  object offset do not share a modeled key. Native kernel wakes still occur, but census wake
  attribution and deterministic wake selection do not resolve that backing-object identity.
- **Process statics across fixed-epoch sims:** a plain sim's clocks continue where the process's
  earlier sims left off, but a `deterministic()` or `fixed_epoch()` sim starts at monotonic zero
  and 2023-11-14T22:13:20Z so its absolute readings replay. A timestamp a library kept in a static
  from a sim that ran further (a static tokio runtime's timer wheel, a `#[cached(time = ..)]` memo,
  a global resolver or moka cache, jiff's time-zone cache, a UUIDv7 context) is then ahead of its
  clocks: short sleeps return at once and cache entries never expire. Make such runtimes and
  caches inside the sim. A thread-local cache goes stale the same way when one thread runs a
  fixed-epoch sim after another sim (chrono's 1 s `TZ_INFO` recheck window, kept per thread
  across `Sim::run`s), and a static that mixes readings
  from a sim with real ones (taken outside every sim or in a `wall_clock()` sim) sees two
  timelines.
- **Runtimes' process-wide state without `--parallel`:** smol's global executor (`smol::spawn`
  and its "smol-N" threads), async-io's reactor, async-std's global executor, `blocking`'s pool
  and rayon's global pool live in statics, made under the first sim that uses them. Later sims
  run in turn on those threads, each in the world of the sim that woke them ("Pool threads
  following a later sim" below), but two sims using one at once share it, and one sim's threads
  run the other's tasks. What they keep carries over from one sim to the next (async-io's reactor
  thread, born into the first sim, and its timer and source tables), so a deterministic sim that
  uses one replays only at the same point of the process's history.
  `cargo snare test --parallel <smol|async-std|rayon|all>` (or
  `parallel = [...]` in `[package.metadata.snare]`) patches in the shims that keep one per sim;
  otherwise take turns (a static `Mutex` held across the test, or `--test-threads=1`). With
  `--parallel smol`, tasks still pending on a sim's global executor are dropped when the sim
  ends, where smol keeps them forever.
- **rayon's global pool and deterministic replay:** without `--parallel rayon` the global pool's
  workers, and their steal-order generators, carry over from one sim to the next, so a
  deterministic sim using `par_iter` or `rayon::join` outside an `install` replays only when it
  runs at the same point of the process's history. Pools built with `ThreadPoolBuilder::build`
  inside a sim replay regardless (the rayon-core shim seeds each worker by its index). A
  `rayon::join` of two sleeps can take the sum of the sleeps rather than the longer of them,
  when the idle worker has not yet been woken to steal the second half.
- **Per-thread hash keys and tokio's seeds:** std draws a thread's `RandomState` keys at its first
  `HashMap` and adds one to them at each one after, for the thread's life. A thread that ran an
  earlier sim, or made a map before its sim began, enters the sim with keys its history chose, so
  its hash order replays only at the same point of that history; a scenario run once per thread
  (libtest's thread per test, or a thread spawned for each run) replays. tokio seeds its
  scheduling randomness (its workers' steal order) from those keys and a process-wide counter
  every runtime it builds moves on (tokio `src/loom/std/mod.rs`, `rand::seed`), so a deterministic
  sim that builds a multi-thread runtime replays only as the same runtime of its process: the
  second one a process builds orders its tasks differently from the first, on any thread.
- **quanta's recent time:** `quanta::Instant::recent()` reads one process-wide value that an
  `Upkeep` thread refreshes. The quanta shim makes every clock read the sim's clock, but an
  upkeep thread started in one sim keeps writing that sim's time, which another sim's `recent()`
  then reads. Start the `Upkeep` in the sim that reads `recent()`, or read `Instant::now()`.
- **Shimmed crates outside the shims' versions:** each shim replaces one release line (`quanta`
  0.12 and 0.13, `fastrand` 2, `rayon-core` 1, `minstant`/`fastant` 0.1, see
  `shims/README.md`). Older lines in the graph (`fastrand` 1.x, `quanta` 0.11 and earlier) are
  left unpatched: their TSC reads and thread-id seeds behave as upstream.
- **A thread pool kept across sims:** a multi-thread runtime made in one sim and kept in a
  static (tokio's, beside a global `reqwest::Client`) runs the next sim's tasks on workers that
  stay in the first sim's world until one of them reaches a descriptor of the running sim. Work
  they take over a channel, with no descriptor between, such as a request on a connection pooled
  in the first sim, is served from that world. Build the runtime in each sim.
- **Pool threads following a later sim:** a participant left over from an ended run follows a
  running sim that wakes it through a condition variable, futex, semaphore, parker or
  `WaitOnAddress` (README, "Process-wide pools"). Work it picks up with no wake stays in its old
  world: a worker still spinning when the later sim posts work (a run's end waits up to 200 ms of
  real time with no thread coming to rest, 1 s for one that has never blocked or keeps yielding,
  5 s in all, for its leftovers to park), or one polling
  an atomic. A yield gives nothing to tell which running sim, if any, posted the work it finds. Only
  participants are listed as waiters, so background, helper and driver leftovers never move. A
  futex word does not say whether it is a lock or a condition: on Linux a leftover parked on a
  std `Mutex` that a running sim's thread unlocks follows that sim as well. On macOS one parked on
  a contended pthread mutex (std's `Mutex` there) stays in its old world, and so does what it does
  once it holds the lock: a worker that then takes a job from a receiver kept behind that `Mutex`
  without waiting for it runs the job there. A follower that reaches
  a socket of its old sim finds a dead connection, as sockets never move: a client made in an
  earlier sim and kept in a static (reqwest's pooled connections) drops that connection and
  reconnects in the sim it now runs in instead of reaching the earlier sim's server. A wake the OS gives to a thread other than the
  ones listed keeps the later sim from going quiescent for 200 ms of real time, until the place it
  made is given back. Two sims running at once that share a pool still share its threads.
- **Deterministic stalls on outside wakes:** a wake from outside a deterministic schedule now
  reaches the waiter in it, but `stuck_after` still cannot tell a schedule cycling on timers (an
  executor's driver ticking) while a participant waits on something that never comes from one
  making progress: moving time counts as progress.
- **Outside workers drained on behalf of a sim:** a sim thread in a timed wait on a thread that is
  busy outside the sim (a `tracing_appender::non_blocking` worker made outside it or in another
  sim, flushing when its `WorkerGuard` drops in this one) gives snare no wake and no lock to see,
  so time skips to the timeout: the guard waits its 1 s of sim time in a few real milliseconds and
  returns before the worker has flushed. Make the writer and drop its guard in the same sim, or
  drop the guard outside every sim.
- **Real descriptors in a sim's waits:** a `poll`, `select`, `epoll_wait` or `kevent` that waits
  on a real descriptor beside the sim's own blocks on it through a probe set of the OS's, which a
  sim about to move time or give up its waits looks at first. Under `deterministic()` a real
  descriptor's readiness is seen only once the schedule has nothing else to run, so a participant
  that never blocks keeps a waiter from seeing a pipe it wrote. Time a thread spends waiting on a
  child process shows on the sim's clock only as far as a timer is reached meanwhile: the clock
  moves no faster than real time, but not with it. A pipe stops being the sim's own once a child
  process may hold it: an end named by a `posix_spawn` file action, or every pipe of the sim at a
  `fork`. One a child inherits otherwise (an end without `FD_CLOEXEC`, which a child another thread
  spawns meanwhile inherits) still counts as the sim's, so a wait only that child can end gives up
  as deadlocked. A real descriptor made outside the sim wakes its waiter but holds no time back. A
  poll over real descriptors only, none of them a pipe the sim made, goes to the OS, so the waiting
  thread counts as running and time stands still until it returns.
- **Child exits:** a sim delivers one `SIGCHLD` for each child a thread of it made (`fork`,
  `posix_spawn`, `posix_spawnp`) and drops the kernel's, but when the kernel folds the
  `SIGCHLD`s of a sim's child and of a child of no sim that end together into one naming the
  sim's, the process's own handler misses the other; and a child of no sim that ends while any
  thread is spawning has its `SIGCHLD` reach the process's handler only once the spawning is
  over, on the spawning thread. A child made
  otherwise (`vfork`, `clone`, `pidfd_spawnp`) is not seen: no `SIGCHLD` of the sim's, the
  kernel's reaching the process's handler, and no time held back; a sim on the real clock has no
  clock to hold. The `siginfo_t` carries no `si_utime`/`si_stime`. On Linux a child reaped by a
  call snare does not hook (a raw `wait4` syscall) before the sim looks reports exiting with 0. A
  stopped or continued child (`CLD_STOPPED`, `CLD_CONTINUED`) sends nothing. Past 512 children
  alive at once, the kernel's `SIGCHLD` for the later ones is not dropped. A process that inherited
  `SIGCHLD` ignored keeps having the kernel reap every child at its exit, a sim's included, even
  once the sim installs a handler. A handler installed outside every sim runs, in passthrough,
  for the children of no sim; with none, the one the code under test last installed in a sim does,
  as signal-hook-registry's dispatcher serves the whole process.
- **Signals and blocked calls:** a signal handler the sim runs on a thread blocked in a call
  interrupts it as the host does, failing it with `EINTR` or restarting it under `SA_RESTART`
  (tests/signal_interrupts.rs, against both hosts), for socket `recv`/`accept`/`send`/`connect`
  and the raw, timer, event, signal and readiness descriptors, `poll`, `select`, `epoll_wait`,
  `kevent`, the sleeps, `flock` and `F_SETLKW`/`F_OFD_SETLKW` on a `VirtualFs` file, `pause`,
  `sigsuspend`, `sigwaitinfo`, `sigtimedwait`, a `close` lingering under `SO_LINGER`, a blocking
  `read`, `readv`, `write` or `writev` of a pipe the sim made, the waits for a child's end
  (`wait`, `waitpid`, `wait4`, `waitid`), `sem_wait`, and on Linux `sem_timedwait` and
  `sem_clockwait`. A call that blocks in the OS otherwise (a read of another real descriptor, a
  wait for a child's stop or continue, a mutex or condition variable, which never fail with `EINTR`
  anyway) is not interrupted: the handler runs at the thread's next hooked call, as if the call had
  restarted. A semaphore wait outside a deterministic schedule stays a native wait that the signal
  kicks: on Linux snare waits on the semaphore's futex word as glibc's `sem_wait` does, which
  holds for glibc's LP64 layout alone; on macOS it ends the wait with `thread_abort_safely`. A
  blocking pipe write longer than `PIPE_BUF` goes to the OS `PIPE_BUF` bytes at a time, each once
  the pipe has room, so another writer's bytes may come between them (POSIX allows that past
  `PIPE_BUF`), and on macOS the pipe does not grow past 16 KiB for it as it does for one large
  write, so a write a handler cuts short reports fewer bytes than the host's would. A wait for any
  child or a process group watches the children the process has as it starts and those the sim
  spawns meanwhile; one made otherwise meanwhile (`vfork`, `clone`) counts only once the wait looks
  again, and where the OS does not list a process's children (a Linux kernel built without
  `CONFIG_PROC_CHILDREN`) the wait is the OS's, uninterrupted. A signal sent to the sim's process
  from outside it (`Sim::raise_signal` from another thread, a forwarded real signal, `SIGCHLD`)
  runs, when a thread of the sim lets it through and none is blocked where it would interrupt it,
  on a thread of the sim's own standing in for that thread, not on the thread itself, and a blocked
  worker the host would never pick anyway is not interrupted. Masks: `sigsuspend` lets only a
  signal of the sim's end it, whatever real signals its mask lets in; a `sigwait`, `sigwaitinfo`,
  `sigtimedwait` or `signalfd` whose set mixes the sim's signals with others waits for the sim's
  alone; a handler's `sa_mask` blocks only the sim's signals of it; a handler that changes its mask
  has it put back as it returns, but a signal that arrives during it and that the mask from before
  `sigsuspend` blocks is still delivered under `sigsuspend`'s. On macOS a pending signal is taken
  lowest number first from the thread's and the process's together; XNU keeps a signal sent to the
  process with a thread it picked, so `sigpending` on another thread does not show it there. A
  child process gets the real mask, without the sim's blocked signals.
- **Hooks reached from inside an allocator:** a C allocator installed as the global allocator
  (jemalloc, mimalloc) calls the hooked pthread, clock and thread functions from inside its own
  critical sections, where a hook that allocates or waits on a lock whose holder allocates can
  deadlock the allocator. Setting up a default mutex or condition variable records nothing, the
  nested-wait record is fixed-size, and the census keeps room for 64 watched mutexes. A thread
  holding a pthread mutex (just taken, about to be let go, or won after a contended wait) records
  it, and its wait's end, for the census and for a deterministic schedule without allocating or
  waiting for either lock: a record that finds its lock taken is queued for the holder. A
  deterministic schedule allocates nothing under its lock or as a thread waits or wakes in it, as
  each thread's share is made when it joins and the schedule's tables grow with the lock let go,
  and the lists of waiters a wake from another sim reaches have fixed room (`alloc_jemalloc.rs`,
  `alloc_mimalloc.rs`). What remains: outside a deterministic schedule, a thread that waits for one
  of the allocator's locks while it holds another (allocators nest theirs) takes the census lock to
  count its wait, whose holder may be allocating as it adds a thread's row or records a wake, and a
  condition-variable wait takes it with its mutex held again, and, while other sims run, theirs. A time skip or a caught clock spin's
  step allocates in the clock layer's timer bookkeeping, and a caught spin outside a deterministic
  schedule takes the census and readiness locks. Under a deterministic schedule, a wait on more than
  eight readiness keys frees its key list under the schedule's lock as it ends, and Windows shared
  (SRW) locks record their holders, allocating, under it. The executive's arm callback runs
  on the thread that has just won a contended mutex, which may be one of the allocator's.
- **Long clock-reading loops:** a loop that reads the clock with no other hooked call between
  reads is a clock spin whether it waits on time or works (README, "Clock spins"). Its first
  65,536 reads cost 1 µs each, as calls that do not block do; past those its steps grow toward
  one second, so a computation reading the clock that many times between hooked calls (an
  allocator under sustained churn, a per-item timestamp over hundreds of thousands of items)
  sees time run ahead of its work. Holding `busy()` across such a loop keeps the clock still,
  and any hooked call in it other than a clock read or a yield starts the count again.
- **Pure atomic spins** (`while !flag { spin_loop() }`) bypass function hooks and can prevent a
  virtual sleeper from waking. Block or yield cooperatively. A `busy()` lease around the spin
  does not solve that dependency and suppresses watchdog detection.
- **Readiness adapters without source identities:** adapters that supply no socket/descriptor
  identity use broad subscriptions in native and deterministic modes. These fallback waits can
  recheck after unrelated traffic; source-aware subscriptions filter unrelated notifications.
- **SimHost hardware timestamps:** the default represents an ideal NIC with no independent
  hardware/software timestamp-point latency. It cannot validate physical NIC latency compensation.
  UDP filters are a synthetic protocol classifier, not a specific driver's hardware parser.
  One-step TX modes suppress hardware error-queue reports for classified one-step UDP Sync
  and Pdelay_Resp messages, but still lack packet timestamp insertion, correction-field updates,
  and corresponding checksum changes. Those require modeled egress and ingress timestamp
  relationships, not just a capability bitmap. Receive-filter ioctl results can be captured with
  `Nic::hwtstamp_rx_mapping`; profiles without mappings retain the inferred widening rule and
  cannot claim exact driver configuration parity.
- **macOS interface binding:** `IP_BOUND_IF` receive filtering is approximated as strict interface
  selection. [XNU's `_inp_restricted_recv`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/in_pcb.c)
  permits an otherwise unrestricted ingress interface without `IFEF_RESTRICTED_RECV`; restricted
  interfaces also have receive-any-interface, management entitlement and bound-interface checks.
  NECP and cellular/expensive/constrained/AWDL restrictions apply separately. The matrix is
  source-reviewed, unmeasured on the host. Windows `IP_UNICAST_IF` selects outgoing traffic only.
- **Fragment charging:** IPv6 fragment charging is unmeasured and allocator-dependent. Incorrect
  charging changes receive-buffer admission and drop counts; it is validation debt.
- **Hardware profiles:** driver-info register/EEPROM/private-flag lengths can be configured, but
  register dumps, EEPROM contents and private-flag operations are not modelled. Initial carrier
  can be configured independently with `Nic::carrier`, including unknown-but-up interfaces.
  Allocated TX queues can be configured separately, but deriving them from channel maxima is
  not reliable for every driver. PTP request checks model core rules rather than all driver
  flags, and `gettimex64` support cannot be inferred from `PTP_CLOCK_GETCAPS`. These require
  measured profile data, not a claim of general hardware parity.
- **Timestamp generation lifecycle:** Linux's initial software RX activation window is
  configured with `SimBuilder::rx_timestamp_startup_delay`; zero starts warm, while a nonzero
  delay starts once on the first successful generation request. The sim stays warm afterward.
  Host-global static-key reference counts, later deactivation and reactivation cycles, and
  kernel workqueue scheduling are not represented by this initial startup profile.
- **macOS ICMP:** the host suppresses repeated unreachables; the sim re-arms per datagram. A local
  burst probe produced errors for 3 of 40 sends. The suppression policy has not been reproduced.
- **Watchdog:** `stuck_after` aborts the whole test process, because a stuck thread can't be
  unwound. This contains a busy stall, not every deadlock, and kills other sims in the same process.
  A participant blocked in a call snare does not hook uses no CPU time, so it is reported only
  after ten times the threshold (at least 5 s).
  Choose the threshold to allow legitimate work. Leases suppress detection. Use child-process
  isolation where failure containment matters. Diagnostics have a bounded, best-effort reporting window.
