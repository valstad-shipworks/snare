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

- **Local time** (`local_time.rs`, `local_time_os_truth.rs`): a sim that decides its zone serves
  `localtime_r`, `localtime`, `mktime`, `timelocal`, `ctime_r`, `ctime` and macOS's
  `CFTimeZoneCopySystem`/`CopyDefault`, but the `tzname`, `timezone` and `daylight` globals that
  `tzset` fills stay the process's, and libc functions that convert inside themselves (`strftime`
  with a `struct tm` lacking `tm_zone`, `getdate`, glibc's `__localtime64_r` aliases) see the
  machine's zone. `CFTimeZoneSetDefault` is process-wide; a sim that decides its zone answers
  `CFTimeZoneCopyDefault` with its own regardless. Leap-second records of `right/` zones are not
  applied. With a negative `tm_isdst`, `mktime` of a local time that occurs twice takes the
  earlier instant; glibc's choice depends on the offset left by the process's previous `mktime`
  call and tzcode's on its binary search, so the host can pick the later one. On Windows the
  UCRT's local time (`_localtime64_s`, `_mktime64`, `_tzset`) and `GetTimeZoneInformation` read
  the machine's zone.

- **CPU count** (`simhost_cpus.rs`): `sysconf`, Linux `sched_getaffinity` and macOS's `hw.*`
  counts follow `HostProfile::cpus`, but per-CPU listings do not: Linux `/proc/stat` and
  `/proc/cpuinfo` and macOS `host_processor_info` (what sysinfo's CPU list reads) report the
  machine's CPUs, and a `WinHost`'s `GetSystemInfo`, `GetActiveProcessorCount` and
  `GetLogicalProcessorInformation(Ex)` the real ones.

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

- On a plain sim (no `SimHost`), `sendmsg` with any control message fails with `EOPNOTSUPP`:
  `IP_PKTINFO`, `IP_TOS`, `SCM_TXTIME` and the rest are modelled only for a `SimHost`'s sockets.

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
- A `WaitOnAddress`, timed or not, outlasts a spurious return (`TRUE` with the comparand still in
  place) only when no `WakeByAddress*` reached its address meanwhile, tracked in a fixed table of
  65 536 hashed counters. A wake of another address sharing the slot lets the spurious return
  through: std's `park_timeout` then returns before its virtual timeout, and a condition variable
  wait returns with no notify.
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
- Advisory locks on a `VirtualFs` file keep Linux's separation of `flock` locks from record
  locks; on macOS the two share one lock list and conflict (even a description's own `flock`
  against its OFD lock), which the model does not reproduce. A blocked `F_SETLKW`/`flock` is not
  interrupted by a signal (`EINTR`), `F_SETLKWTIMEOUT`/`F_OFD_SETLKWTIMEOUT` (macOS) are not
  modelled, and a directory stream's descriptor (`opendir`) cannot be locked (`EINVAL`).
  `SimHost` files (`/dev`, `/proc`, `/sys`) take no locks: lock commands fail with `EINVAL` and
  `flock` reaches the `/dev/null` placeholder.
- `mmap` of a virtual file maps its `/dev/null` placeholder, so SQLite's WAL index (`-shm`) cannot
  be mapped: `PRAGMA journal_mode=WAL` succeeds, the first write in WAL mode fails with
  `SQLITE_IOERR_SHMMAP`.
- A file another sim's plane opened is served by that plane for I/O and descriptor calls from any
  thread, but the working directory stays per sim: `fchdir` through such a directory descriptor
  reaches its `/dev/null` placeholder and fails with `ENOTDIR`.
- File timestamps follow the sim's clock (README, "File timestamps"), with these limits:
  - `chmod`, `chown` and their relatives are not modelled on a `VirtualFs` (modes are fixed), so
    they never stamp a change time there.
  - On real files the sim records only what it does through the hooked calls. Path `truncate(2)`,
    `fallocate`, `copy_file_range`, `sendfile`, writes through a mapping, writes through a descriptor
    opened before the sim or duplicated outside the hooks, `chmod`, and another process's changes
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
  Under `deterministic()` such a wait keeps the baton for 50 ms of real time before it passes it,
  after which the run's order depends on how long the outside holder took; std's thread-start lock,
  which parallel tests' spawning threads hold, otherwise broke replay under load
  (`edge_scale_testers`). A holder inside the domain costs a deterministic wait those 50 ms. macOS pthread mutexes name their owner; a
  deterministic wait on one held outside the schedule keeps the baton for the same 50 ms, then waits
  in the schedule for the unlock, so its order too depends on how long the holder took.
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
  run the other's tasks. `cargo snare test --parallel <smol|async-std|rayon|all>` (or
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
  real time with no thread coming to rest, 1 s for one that has never blocked, 5 s in all, for its
  leftovers to park), or one polling
  an atomic. A yield gives nothing to tell which running sim, if any, posted the work it finds. Only
  participants are listed as waiters, so background, helper and driver leftovers never move. A
  futex word does not say whether it is a lock or a condition: on Linux a leftover parked on a
  std `Mutex` that a running sim's thread unlocks follows that sim as well. A follower that reaches
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
- **Real pipes in a sim poll:** `pipe`/`pipe2` stay real, so a `poll` over a pipe and sim
  sockets cannot block on the pipe; a loop waiting on both spins until `stuck_after` reports it.
  `socketpair(AF_UNIX)` is simulated and works as a wake-up channel.
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
  condition-variable wait takes it with its mutex held again. A time skip or a caught clock spin's
  step allocates in the clock layer's timer bookkeeping, a caught spin outside a deterministic
  schedule takes the census and readiness locks, and a condition-variable wait records its signal
  count, allocating, under a lock its signal takes.
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
  OS descheduling can also produce a period without observed progress; choose the threshold to
  allow it and legitimate work. Leases suppress detection. Use child-process isolation where
  failure containment matters. Diagnostics have a bounded, best-effort reporting window.
