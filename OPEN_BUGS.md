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

- **Host name** (`simhost_uname.rs`): `uname` reports `HostProfile::nodename`, but `gethostname`
  is not modelled and still returns the real name (glibc builds it from the `uname` syscall
  inside libc, macOS from `sysctl` `kern.hostname`), and neither are the macOS `kern.ostype`,
  `kern.osrelease`, `kern.version` and `kern.hostname` sysctls.

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

- `recvmmsg` (Linux) receives each message through the backend's `recvmsg`. An error after the
  first message ends the batch and is dropped, where the kernel keeps it as the socket's pending
  error for the next call (`do_recvmmsg`, net/socket.c).
- On a plain sim (no `SimHost`), `sendmsg` with any control message fails with `EOPNOTSUPP`:
  `IP_PKTINFO`, `IP_TOS`, `SCM_TXTIME` and the rest are modelled only for a `SimHost`'s sockets.
- Linux `getsockopt(SO_TYPE)` on an `AF_PACKET` socket reads `SOCK_STREAM` (1) where the kernel
  reports the type it was opened with (`SOCK_RAW` 3 or `SOCK_DGRAM` 2).
- A `SimHost`'s netlink sockets answer only the socket-level options of `limits::sockopt`
  (buffers, priority, busy polling, `SO_DOMAIN`/`SO_PROTOCOL`, ...); any other `getsockopt` or
  `setsockopt` on them, `SO_TYPE` and `SO_ERROR` included, reaches the real OS on the reserved
  descriptor and fails with `ENOTSOCK`.

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
- Unsupported socket `fcntl` commands return `EINVAL`. This avoids reporting false success,
  but valid host commands beyond the modelled descriptor/status flags and duplication still
  need implementations and host comparisons. `strict_sockopts` does not validate these commands.

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
  host comparisons. Granted realtime-class thread/background behavior has a priority-range
  mismatch described below; earlier requests reported `HIGH_PRIORITY_CLASS` instead.
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
  `SimBuilder::threads_per_core`, all in NUMA node 0 and last-level cache 0 with no flags
  (`Parked`, `Allocated`, `RealTime`) and efficiency class 0, so hybrid machines with cores of
  different sizes or classes, several caches or nodes are not represented; its `Process` and
  `Flags` arguments are ignored. Selected CPU sets do not interact with `SetThreadAffinityMask` as
  they do on Windows.
- Timers created through `CreateWaitableTimerW/A` and `CreateWaitableTimerExW/A` support unnamed
  relative/absolute deadlines, periodic auto/manual-reset signals, same-process handle aliases,
  cancellation,
  `SetWaitableTimerEx` without a reason context, and non-alertable single/timer-only multiple
  waits. Native comparisons cover signal state, atomic wait-all consumption, alias access rights
  and cleanup after a run. Named/security attributes, APC callbacks, resume requests, reason
  contexts, cross-process aliases, alertable timer waits and blocking mixed-object waits return
  `ERROR_NOT_SUPPORTED` (50). Tolerable-delay requests use the exact deadline
  rather than modelling the host's coalescing policy.
- A timed `WaitOnAddress` outlasts a spurious return (`TRUE` with the comparand still in place)
  only when no `WakeByAddress*` reached its address meanwhile, tracked in a fixed table of 4096
  hashed counters. A wake of another address sharing the slot lets the spurious return through, and
  std's `park_timeout` then returns before its virtual timeout.
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

Missing Windows features: overlapped and event-notified I/O, TCP urgent data,
keepalive-driven dead-peer detection, and control messages other than timestamps. Non-timestamp
outbound control messages fail with `WSAEOPNOTSUPP`; source/interface selection through those
messages needs an implementation and native comparisons.

Shared/exclusive SRW locks, critical sections and raw condition-variable waits have hooks and
native comparisons. Application objects initialized before entering the simulation are outside the
usage contract. Process-runtime synchronization can still lack owner metadata. Windows filesystem and environment
APIs also reach real process state;
the corresponding isolation guarantees require additional hooks and parity tests.

## File plane

Regular virtual files support positional IO, truncate and sync without reaching the backing
`/dev/null`; proc/sysfs text snapshots support positional reads and handle write, truncate and sync
errors directly. Read-only proc/sysfs descriptor comparisons run against Linux. Remaining differences
are real model gaps:

- VirtualFs models directory descriptors, raw directory records, `fdopendir`, filesystem
  statistics, sparse pages with configured storage limits, hard links, working-directory-relative
  paths, and symbolic links within one plane. Native comparisons cover `chdir`/`fchdir`/`getcwd`,
  renamed and unlinked directory identity, relative/absolute link targets, `readlink`, final-link
  flags, loops and traversal limits, directory-relative calls, and pathname mutations. Permissions
  still use fixed modes rather than ownership, ACLs, caller credentials or umask. Symlink targets
  outside the owned namespace or into passthrough are rejected with `EXDEV`; cross-plane symlink
  traversal and interior parent traversal into another plane are not supported. Paths from an
  unlinked directory retain `.` identity, but parent/child traversal still requires a namespace
  path. Linux `O_PATH | O_NOFOLLOW` and macOS `O_SYMLINK` handles are rejected with `EOPNOTSUPP`.
  Full pathname length limits and mount semantics remain unmodeled.
- SimHost rejects positional writes to virtual device nodes with `EOPNOTSUPP`;
  device-specific parity is unmeasured.
- Mutable file flags cover append/nonblocking, not every host `fcntl` operation.

## Ignored validation

Hardware and privileged tests remain opt-in when they require an adapter, PTP clock, peer
reflector, npcap, a private network namespace, or permission to change device settings. Their
guards do not establish that the model passes those comparisons. Windows adapter-row comparisons
now capture the measured physical medium; the UDP-statistics comparison runs by default without
adapter prerequisites.

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
  explicit application workaround; it does not make this unchanged regression pass.
- **Windows realtime thread priority:**
  `win_host_os_truth::current_process_background_and_priority_classes_match_the_host` reports
  a mismatch when this VM grants `REALTIME_PRIORITY_CLASS`: native `SetThreadPriority(-14)`
  succeeds and reads back `-8`, while the model rejects it with `ERROR_INVALID_PARAMETER` (87).
  The earlier host comparison downgraded realtime requests to `HIGH_PRIORITY_CLASS` and did
  not exercise this case. The accepted range and background-mode interactions need a native
  calibration under an actually granted realtime class.

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
  Under `deterministic()` such a wait then passes the baton, so the run's order depends on how
  long the outside holder took (a holder descheduled on a loaded or single-CPU host exceeds the
  grace). macOS pthread mutexes name their owner and keep the baton for an outside holder.
  std's one-time Windows Winsock startup, which holds its `Once` far longer, is run outside every
  domain before the first one is installed. macOS std `RwLock` and `Once` can park on ownerless
  semaphores. An external holder's `sim.busy()` lease prevents the incorrect skip; an
  owner-aware wrapper is another path.
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
  OS descheduling can also produce a period without observed progress; choose the threshold to
  allow it and legitimate work. Leases suppress detection. Use child-process isolation where
  failure containment matters. Diagnostics have a bounded, best-effort reporting window.
