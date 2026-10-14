# Hot-path benchmarks

Run `cargo bench -p snare --bench hooked_calls` on an otherwise idle host. The benchmark runs on Unix and Windows. Record the revision, Rust version, target, OS, CPU, and Docker or VM resource settings with each result. Run one measurement process at a time, without concurrent test suites or compilation.

## Timing and resources

Managed samples use `iter_custom` and read their elapsed time under `snare::real`. An `Instant` read by application code inside a simulation reads virtual time and cannot measure throughput. Each managed sample creates a fresh simulation. Simulation construction, entry, exit, and destruction are outside its stopwatch; the two lifecycle benchmarks measure construction/destruction and construction/run/destruction explicitly.

Application sockets, polling objects, mutexes, and testers are created inside `Sim.run`. Socket binding, connection establishment, and poll registration precede their hot-path stopwatches. The tester benchmark measures the client request/reply loop after its socket is bound, including any wait for tester startup and scheduling. It does not measure complete tester setup and teardown. Native oracle resources in any additional comparison must be created under `snare::real`; managed resources must remain inside the active simulation.

Every managed socket holds a real descriptor, and a sim inherits the process's descriptor limit, so the `in_sim` group first raises the soft `RLIMIT_NOFILE` toward the hard limit (to at most 100,000, which macOS's `kern.maxfilesperproc` allows). A host whose hard limit is below about 17,000 cannot run the largest workloads.

Criterion warms each benchmark for one second and measures for three seconds. Fresh simulation state does not imply a cold process: installed hooks, allocator state, worker initialization, and CPU caches can persist across samples and benchmark groups. The `passthrough` group installs hooks before measurement. Its results describe installed hooks with no active simulation, rather than a pristine unhooked native process. The lifecycle group also measures process-warm behavior. Measure initial hook installation and first-call costs separately in fresh processes.

## Workload interpretation

`in_sim/clock_gettime` retains its metric name but measures `Instant::now` plus one yield per 32 reads. Reads and yields increment the same clock-spin counter; yielding does not reset it. Managed samples therefore enter the caught-spin path after 64 combined events and include time advancement and scheduling checks. This workload measures sustained clock polling, rather than isolated ordinary clock reads. Use `passthrough/clock_gettime_with_yield_32_outside_a_sim` for the same operation mix outside a simulation. `passthrough/clock_gettime_outside_a_sim` measures reads without yields and cannot be subtracted directly from the composite managed figure. The OS API used by `Instant` depends on the platform.

`in_sim/mutex_2_threads_with_spawn_join` includes child creation and join, with exactly the requested number of lock operations split between parent and child. It does not guarantee contention: either thread can complete much of its work before the other runs. `deterministic/yield_2_threads_with_spawn_join` likewise includes creation/join and exactly the requested number of yields; its per-yield figure is not a measurement of a fixed number of baton transfers. The `handoff_condvar_ring/N` and `handoff_channel_ring/N` benchmarks isolate handoff instead: N persistent workers, spawned and released from a barrier before the stopwatch, pass a baton round a ring, each waiting on its own condition variable or channel for the previous worker to hand over. One iteration is one handoff; the final joins are inside the stopwatch. The rings run in the `passthrough` group (installed hooks, no sim, as a native control), in `in_sim` and in `deterministic`.

`channel_burst/64` measures one channel send and receive: a producer sends 64 values, then waits for the consumer to acknowledge them on a second channel. Its first value makes the consumer ready while the producer still runs, so it shows what a deterministic schedule pays when a woken thread is not handed the baton at once. It runs in the same three groups as the rings.

`tcp_bind_listen_close_beside_listeners/N` and `tcp_connect_accept_close_beside_listeners/N` measure one `TcpListener::bind` (socket, `SO_REUSEADDR`, bind, listen, close), or one connect, accept and close of both ends, in a sim already holding N TCP listeners on other ports. They take 10 samples each, since building 16,384 listeners takes seconds per sample where binds scan every socket.

`time_skip_1ms_sleep` measures the real cost of a virtual sleep. Native one-millisecond sleeps perform a different wall-clock workload, so their ratio is not hook overhead. The uncontended mutex workload can stay on the standard library's atomic fast path and does not isolate blocking synchronization hooks. Empty Mio polls cover 1, 64, and 1024 registered sockets; `mio_poll_wake_beside_idle`, `mio_poll_all_ready` and `poll_level_all_ready` cover a blocking wait beside idle registrations and ready-event delivery from every registration (see the ready-list section below). No workload registers and deregisters dynamically.

Criterion coverage includes plain Sim workloads, deterministic yield, sleep and handoff-ring workloads, and installed-hook passthrough clock/yield calls and handoff rings. It does not provide matched native socket baselines, SimHost workloads, capture-enabled workloads, or broad deterministic networking coverage.

## Comparing results

Compare matched workloads with the same operation counts, build profile, platform, and host configuration. Keep cold startup, process-warm lifecycle, and warmed throughput results separate. Repeat measurements in fresh processes and vary group order when investigating initialization or cache effects. Report estimates and their spread alongside the workload scope.

Historical figures need the original source and environment to remain comparable. The former two-thread labels `mutex_contended_2_threads` and `baton_handoff_yield` included spawn/join and performed one extra operation for odd iteration counts. Tester figures containing diagnostic atomic stores or a logging thread describe that additional work. Do not treat those results as directly interchangeable with the current workloads.

`tests/edge_scale_perf_guards.rs` supplies generous debug-time regression bounds, rather than precise comparative benchmarks. `tests/edge_scale_alloc.rs` counts warmed caller-thread Rust allocation calls; it excludes child-thread allocations, native allocations, allocation sizes, and retained memory. Its spawn/join budget measures allocation overhead after subtracting a native spawn/join baseline in the same test binary.

## macOS runtime optimization, 2026-10-04

The final comparison used macOS 26.6.2 / Darwin 25.6.0 on an Apple M5 Pro (18 logical CPUs), Rust 1.98.0, and release optimization with debug information (`CARGO_PROFILE_RELEASE_DEBUG=1`). Each of 78 configurations ran five times per executable in fresh processes, with shuffled configuration order and alternating randomized before/after order: 780 samples, zero errors. Tests and compilation finished before these measurements. The lighter-load rerun recorded one-minute load averages of 4.71 before and 8.02 after; CPU placement, frequency, and background OS activity remained uncontrolled. These are measured workload timings, with ranges, rather than universal throughput guarantees.

The table shows plain simulation medians, with minimum–maximum in parentheses. Bind and timer rows show the whole batch; poll rows show one call. Speedup divides the two medians; the raw summaries also include median paired speedups.

| Workload | Before | Final | Change |
| --- | --- | --- | --- |
| 1,600 ephemeral UDP binds (batch) | 479.437 (442.380–527.162) ms | 2.468 (2.053–2.765) ms | 194.3× |
| Empty Mio poll, 1,024 registrations | 1345.686 (1213.223–1850.215) µs | 204.814 (183.372–246.337) µs | 6.6× |
| Mio poll, 128 unread 8 KiB datagrams | 229.108 (195.118–304.593) µs | 21.817 (20.998–23.960) µs | 10.5× |
| Reverse cancellation, 8,000 distinct timers (batch) | 83.579 (76.914–91.970) ms | 0.949 (0.844–1.145) ms | 88.1× |
| Register 8,000 distinct timers (batch) | 1.165 (1.085–1.289) ms | 1.511 (1.281–1.637) ms | 30% slower |

The managed `host` probe on macOS uses Fabric for UDP and readiness, with the SimHost profile and clock layers present. It does not measure a separate SimHost UDP implementation. The matrix also covers deterministic simulation and matched controls for clock/yield, empty receive, UDP/TCP transfer, uncontended mutex, virtual sleep, explicit bind, and spawn/join. Small changes in these controls remain sensitive to scheduling; the clock/yield case includes caught-spin behavior as described above.

The allocator now indexes occupied dynamic ports by IP and address family, tracks scoped-address and family sharing, and caches the lowest nonfull word. Bitmaps grow only through the highest occupied word, up to 2 KiB of bits per indexed IP or family, plus sparse reference maps. Lowest-free, wildcard, alias, replacement, wraparound, and exhaustion behavior remain covered by tests. In this run, median time per ephemeral bind stayed near 1.4–1.7 µs from 100 through 1,600 sockets; the earlier allocator rose from 3.2 to 299.6 µs. This removes repeated candidate-by-binding scans from the allocation path.

The kqueue path validates only descriptors named in changes, reads datagram metadata without cloning payloads, and sorts firing registrations. Exact zero-timeout calls avoid wait subscription and interest construction while retaining the final readiness check and one charged call latency. Large blocking-interest sets use indexed membership after 64 keys, preserving insertion order and the allocation-free small-set representation. Readiness notifications reject unrelated domains before checking keys, with domain-zero behavior unchanged. Polling still scans registrations; a ready-event queue would be a separate architectural change.

Timer cancellation now resolves a wake ID to its deadline under the existing table lock. Fired Native holds, foreign and deterministic delivery, pruning, tied swap-removal order, and destruction outside locks retain their behavior. This adds one reverse-map entry per registered asynchronous wake. The measured 8,000-timer registration cost increased from 145.6 to 188.8 ns per timer, while cancellation fell from 10,447 to 119 ns. Wakes sharing one deadline are found through a recorded slot since the 2026-10-12 pass below. Native synchronous sleeps do not use this reverse index.

The ready-datagram probe leaves packets unread and measures repeated edge-triggered polls, including the initial event batches. It is not a drain-and-receive throughput benchmark. Bind timing includes backing descriptor and socket creation but excludes teardown. Timer registration includes future creation and first poll; reverse cancellation times dropping those futures. Startup is reported separately. All managed application resources are created inside `Sim.run`; real-time stopwatches are harness operations.

Validation: the macOS workspace library/integration suite passed 1,291 tests with no failures and two existing hardware-dependent ignores. The final bitmap storage refinement then passed both allocator unit tests and both full-range/exhaustion regressions. Strict workspace/all-target Clippy, formatting, and the Criterion benchmark smoke run passed. Linux and Windows performance optimization and validation are deferred.

Raw samples, summaries, executable hashes, ranges, CSV, and environment metadata are saved locally in `target/performance/macos-quiet/`. The loaded-host comparison remains in `target/performance/`; its optimized executable predates the bitmap storage refinement. These ignored target artifacts are local records, not repository fixtures.

To repeat a comparison, preserve the pre-change executable before editing, rebuild with the same profile, then run from the repository root:

```sh
mkdir -p target/performance
CARGO_PROFILE_RELEASE_DEBUG=1 cargo build -p snare --example performance_probe --release
cp target/release/examples/performance_probe target/performance/performance_probe-before
```

After implementing the change, rebuild and compare:

```sh
CARGO_PROFILE_RELEASE_DEBUG=1 cargo build -p snare --example performance_probe --release
python3 scripts/measure-runtime.py --before target/performance/performance_probe-before --output target/performance/comparison
```

For a single workload, use `target/release/examples/performance_probe plain poll 1024 300`. The CLI is `MODE CASE SIZE ITERATIONS`; modes are `native`, `passthrough`, `plain`, `det`, and Unix `host`. Native and passthrough comparisons are oracle/harness workloads; timer cases require a managed mode. The [comparison harness](../../../scripts/measure-runtime.py) currently targets macOS and runs every process serially. The [probe](../examples/performance_probe.rs) uses the existing dependencies.

## macOS send/receive optimization, 2026-10-04

The send/receive comparison uses the same machine and release profile as the runtime comparison above. It compares against the executable saved after those runtime optimizations, before this send/receive pass. Each configuration runs in five fresh processes per executable, with shuffled configuration order and randomized paired executable order. Application sockets and buffers are created inside `Sim.run`; socket setup and connection establishment precede the real-time stopwatch. One operation is a local send/receive or write/read pair, without a peer reply. Capture and timestamp socket options are disabled. The final probe includes a receive-mode selector absent from this first baseline, so these timings describe complete workloads rather than isolated syscall costs.

The final transfer matrix has 66 configurations and 660 samples, with no errors. It covers plain, deterministic, and macOS host-profile simulations, connected and unconnected UDP, 2/64/1,024 UDP sockets, three payload sizes per protocol, and empty nonblocking receive. The one-minute load average was 4.18 before and 4.13 after on 18 logical CPUs. No agent benchmarks, test suites, or compilation ran concurrently. CPU placement, frequency, and unrelated OS activity remained uncontrolled.

Plain simulation medians follow, with minimum–maximum in parentheses. Times are per transfer pair, except the empty receive row, which is per call.

| Workload | Before | Final | Speedup |
| --- | --- | --- | --- |
| TCP, 64 bytes | 617 (613–620) ns | 458 (449–459) ns | 1.35× |
| TCP, 1 KiB | 2.766 (2.739–2.800) µs | 0.471 (0.467–0.484) µs | 5.87× |
| TCP, 8 KiB | 18.869 (18.800–18.981) µs | 0.650 (0.635–0.659) µs | 29.02× |
| UDP, 4 bytes, 2 sockets | 678 (665–772) ns | 643 (632–736) ns | 1.05× |
| UDP, 8 KiB, 2 sockets | 982 (947–984) ns | 849 (844–862) ns | 1.16× |
| UDP, 4 bytes, 1,024 sockets | 3.223 (3.131–3.283) µs | 0.653 (0.625–0.663) µs | 4.94× |
| UDP, 8 KiB, 1,024 sockets | 3.886 (3.765–4.065) µs | 0.852 (0.833–0.866) µs | 4.56× |
| Empty nonblocking UDP receive | 169 (165–175) ns | 133 (132–137) ns | 1.27× |

All 66 configuration medians improved in this run. Small-packet UDP ranges overlap, so a single process may not reproduce its modest median gain. The first index candidate slowed tiny UDP transfers slightly; the final index stores queue references directly in each port bucket, avoiding a second address-map lookup. The saved intermediate samples remain available separately.

TCP read and peek copy from the deque's two contiguous slices. Reads then drain exactly the copied prefix, with chunk accounting, receive memory, timestamps, EOF, shutdown, and readiness notifications preserved. Main-thread stack samples of the earlier 8-KiB TCP workload were dominated by its byte-by-byte read loop. The profiles identify where time was spent; they are not hardware CPU-counter measurements.

UDP destination candidates are indexed by port, and tester station addresses have IP reference counts. Replacements update both the canonical binding map and indexed queue references; alias close removes a binding only after its last descriptor closes. This adds one indexed queue reference per binding and port-bucket metadata. Single-address buckets keep their first binding inline. Candidate enumeration remains linear in the number of bindings sharing a destination port. TCP tester-listener station lookup is indexed by IP since the 2026-10-12 pass below.

UDP send borrows the caller payload during the call. Every queued delivery, duplicate, delayed packet, capture, or error report that retains payload bytes still owns them before the call returns. The warmed caller-thread allocation fixture reports 12 allocations per UDP send/receive pair, down from 13, and zero for TCP write/read. Only the measured macOS UDP allocation budget was tightened; Linux's existing budget remains pending validation. Receive timeout lookup uses the already captured socket record, and nonblocking datagram receives skip timeout construction. Blocking calls still capture one timeout budget before the receive loop.

Single-iovec TCP `recvmsg` reads into the caller buffer directly, avoiding the staging allocation and extra copy. Multiple iovecs retain staging. macOS datagram `recvmsg` creates Mach timestamp payloads only when requested and moves the payload when just one Mach option is enabled. Realtime `timeval` serialization writes fields into zero-filled native-layout bytes so control-message padding is deterministic. Timestamp message ordering and native option behavior are covered by regression tests. Short `MSG_PEEK | MSG_WAITALL` reads return at EOF or a pending error without consuming queued bytes or the error; the wait predicate accounts for bytes still in flight before FIN.

The separate `recvmsg` comparison has 36 configurations and 360 samples, with no errors. Its baseline already includes the initial UDP indexes, borrowed UDP sends, and bulk TCP reads. The final executable additionally includes direct indexed queue references, receive timeout lookup changes, lazy macOS timestamp payloads, and direct single-buffer TCP receive. Its probe code is identical between executables. It therefore measures the remaining combined improvements rather than isolating any one change. The one-minute load average was 4.18 before and 4.25 after.

| Plain simulation workload | Before | Final | Speedup |
| --- | --- | --- | --- |
| UDP send + single-iovec `recvmsg`, 4 bytes | 776 (767–952) ns | 720 (704–793) ns | 1.08× |
| TCP write + single-iovec `recvmsg`, 1 KiB | 609 (597–610) ns | 545 (534–547) ns | 1.12× |
| TCP write + single-iovec `recvmsg`, 8 KiB | 887 (881–901) ns | 721 (700–727) ns | 1.23× |
| TCP write + two-iovec `recvmsg`, 8 KiB | 902 (866–1,072) ns | 865 (861–874) ns | 1.04× |

Validation: the workspace library/integration suite passed 1,303 tests with no failures and two existing hardware-dependent ignores. After the final index and timeout refinements, 107 focused unit/integration tests passed, including binding replacement identity, multicast, ICMP, 10,000-socket delivery, timeout behavior, and allocation budgets. Strict workspace/all-target Clippy, formatting, and diff checks passed on the final sources. All application resources in the new network tests are created under snare. Windows performance testing remains deferred; the 2026-10-12 pass below adds Linux Criterion results.

Final raw samples, summaries, CSV files, executable/source hashes, environment records, and validation logs are local artifacts under `target/performance/send-recv/`. Use `transfers-final/` and `recvmsg-final/` for the final measurements; other directories preserve intermediate candidates. These target artifacts are not repository fixtures.

The comparison harness accepts `--suite send-recv` and `--suite recvmsg` in addition to its default runtime matrix:

```sh
python3 scripts/measure-runtime.py --suite send-recv --before target/performance/send-recv/before --output target/performance/send-recv/repeated-transfers
python3 scripts/measure-runtime.py --suite recvmsg --before target/performance/send-recv/recvmsg-before --output target/performance/send-recv/repeated-recvmsg
```

Single workloads include `performance_probe plain udp_connected_8192 1024 50000`, `performance_probe det tcp_1024 2 20000`, and `performance_probe plain tcp_recvmsg_vectored_8192 2 50000`. UDP `SIZE` counts the sender, receiver, and unrelated bound sockets. On macOS, `host` networking continues to use Fabric with the host-profile clock layers; these results do not establish separate SimHost UDP performance, capture-enabled throughput, large multicast fan-out, or multi-threaded contention.

### 128-byte payloads

The small-payload follow-up used the same saved executables with 128-byte application payloads, excluding packet headers. Ten paired repetitions covered plain, deterministic, and host-profile modes: 480 send/receive samples and 240 `recvmsg` samples, with zero errors. The application resource and timing rules above remain unchanged. Only the comparison harness and these notes changed; no Rust rebuild was needed.

Plain simulation medians follow, with minimum–maximum in parentheses. Each row measures one send/receive or write/read pair. Speedup divides the medians.

| 128-byte workload | Before | Final | Speedup |
| --- | --- | --- | --- |
| TCP write/read | 910 (839–969) ns | 529 (471–582) ns | 1.72× |
| UDP, 2 sockets | 750 (699–857) ns | 688 (645–818) ns | 1.09× |
| Connected UDP, 2 sockets | 821 (710–970) ns | 770 (642–804) ns | 1.07× |
| UDP, 64 sockets | 944 (847–1,078) ns | 751 (674–909) ns | 1.26× |
| UDP, 1,024 sockets | 3.649 (3.362–4.030) µs | 0.790 (0.660–0.830) µs | 4.62× |
| TCP single-iovec `recvmsg`, incremental baseline | 587 (571–601) ns | 533 (522–538) ns | 1.10× |

The `recvmsg` baseline already includes bulk TCP reads and initial UDP indexing, as described above. Two-iovec TCP `recvmsg` improved by 1.06× in plain simulation; UDP single/two-iovec `recvmsg` improved by 1.09×/1.08×. These incremental ratios cannot be multiplied by the write/read ratios: the API workloads and baselines differ.

Background compilation was active during the transfer run. Its one-minute load average rose from 7.19 to 8.05; the `recvmsg` run recorded 9.57 to 9.60. Small UDP ranges overlap substantially. Across the three modes, the median paired speedup for two-socket UDP was 1.055–1.059×, while ratios of independent medians ranged from 0.997–1.090×. Treat this as a modest, noisy gain. TCP paired speedups were 1.62–1.74×, and 1,024-socket UDP paired speedups were 4.95–5.00×.

Raw samples, summaries, ranges, CSV, hashes, and environment records are in `target/performance/send-recv/128-transfers/` and `128-recvmsg/`; `128-validation.json` records the checks. Repeat with a custom payload override:

```sh
python3 scripts/measure-runtime.py --suite send-recv --payloads 128 --repeats 10 --before target/performance/send-recv/before --after target/performance/send-recv/after --output target/performance/send-recv/repeated-128-transfers
python3 scripts/measure-runtime.py --suite recvmsg --payloads 128 --repeats 10 --before target/performance/send-recv/recvmsg-before --after target/performance/send-recv/after --output target/performance/send-recv/repeated-128-recvmsg
```


## macOS 32-socket UDP optimization, 2026-10-04

This comparison starts after the earlier send/receive optimizations above. Both saved executables contain the same workload code and were built with `cargo build --release`, `CARGO_PROFILE_RELEASE_DEBUG=1`, and `CARGO_INCREMENTAL=0`. Debug information supports stack profiling; the release optimizer remains enabled. Allocation measurements also use `cargo test --release`. Debug correctness test timings are excluded from benchmark results.

The final matrix has 21 configurations across plain, deterministic, and host-profile modes, with ten randomized paired repetitions: 420 samples, zero errors. Application sockets, buffers, synchronization objects and workers are created inside `Sim.run`. Binding, connection and thread creation precede the real-time stopwatch. Default routing and socket options are used, with capture and ancillary timestamps disabled. Tests and compilation finished before measurements, and each probe ran serially.

`udp_mesh_128` rotates through all 32 senders, receiving immediately on each sender's paired socket. Its connected variant uses the same pairing. `udp_burst_128` sends from every socket before receiving on every socket. Mesh samples contain 300,000 transfers; burst samples contain 320,000. `udp_threaded_128` gives each connected socket its own worker, measuring barrier release, 1,000 send/receive iterations per worker and all joins: 32,000 aggregate transfers. One transfer counts one send and one receive. The two legacy UDP controls retain 32 bound sockets but use only two active sockets.

Plain simulation medians follow, with minimum–maximum in parentheses. These are nanoseconds per aggregate transfer, including the threaded row.

| 128-byte workload | Before | Final | Speedup |
| --- | --- | --- | --- |
| 32 active sockets, rotating pairs | 717 (682–753) ns | 463 (439–546) ns | 1.55× |
| 32 active connected sockets, rotating pairs | 710 (696–825) ns | 462 (445–505) ns | 1.54× |
| 32 active connected sockets, send-all/receive-all | 719 (693–746) ns | 452 (434–481) ns | 1.59× |
| 32 connected sockets and 32 workers | 4743 (4604–5055) ns | 3583 (3416–3751) ns | 1.32× |

Across modes, active mesh/burst median paired speedups are 1.53–1.60×. Plain and host-profile threaded paired speedups are 1.33× and 1.34×. Deterministic threaded results are less stable: the final run's paired median is 1.06×, with broad overlapping ranges; earlier comparisons were essentially flat. This does not establish a substantial deterministic scheduling improvement. The final one-minute load average rose from 7.40 to 9.29 on the same 18-CPU Apple M5 Pro. Background OS activity, CPU placement and frequency remain uncontrolled.

UDP send and receive now capture their endpoint state in one socket-table lookup. Description storage uses recyclable slots after the fd map, removing a second hash lookup while preserving unique description identities, shared alias state and final-close retirement. Single-binding destination ports deliver without temporary candidate/output vectors; shared-port routing retains its sorted general path. Interface names are shared internally, per-socket NIC strings retain capacity, and the four maximum compounded duplication delays fit inline. Directed hold checks share one policy lock. Fault draw order, counters and recipient filtering are covered by parity regressions.

Datagrams up to 128 bytes own their payload inline before send returns; larger payloads retain owned heap storage. Peek, delayed duplicates, truncation, maximum UDP payloads and Unix datagram pairs are covered. The release allocation regression measures exactly zero warmed caller-thread Rust allocations across 32 active sockets for addressed and connected 128-byte sends, in plain and deterministic modes. The string-address fixture falls from 12 allocations per transfer to one; its macOS budget is tightened, while Linux's budget remains unchanged. These counts exclude native allocator activity and do not establish allocation-free blocked worker scheduling or optional capture/error-report paths.

The inline payload representation is 136 bytes, versus a 24-byte Vec, and a queued datagram is 272 bytes on this macOS build. Larger payloads still allocate their bytes and carry the expanded representation. Virtual receive-buffer accounting continues to use the native model's charges. The description arena and free list retain peak capacity; fd entries gain slot/generation metadata. Storage is a throughput tradeoff, not a universal memory reduction.

A separate ten-pair boundary matrix compared the intermediate candidate before inline storage/singleton routing with the next candidate: 360 samples, no errors, for 0/127/128/129/1,024/8,192-byte UDP transfers with 32 bound sockets. Every configuration improved in that comparison. A further 360-sample comparison of the final arena/notification refinement measured connected mesh paired gains of 6–8%, TCP control gains of 3–6%, and mostly flat larger-UDP/empty-receive controls. Threaded incremental changes were modest and noisy. These different baselines must not be combined by multiplying absolute medians.

Readiness broadcasts update generations and stale counts under the board lock, retain notifications inline through 32 subscriptions, then notify after releasing the lock. Inactive subscriptions still receive generation updates but need no Condvar notification. Full `SimShared::kick` skips ClockLayer's duplicate publication while preserving custom layer callbacks and deterministic timer/scheduler releases. Keyed kicks retain their ordinary timer publication. A notified waiter remains stale until it rechecks; the Executive's quiescence transaction remains locked. A final release stack profile still shows native mutex and Condvar waits. Samples include blocked time and are not CPU percentages. The threaded probe does not attach an Executive, so these numbers do not establish Sham/Theater's idle-check or wake-to-run improvement.

Validation: the final macOS workspace library/integration suite passed 1,320 tests, zero failures and two existing hardware-dependent ignores. All 48 library tests and both allocation tests also passed in release mode. Strict workspace/all-target Clippy, formatting and diff checks passed. Tests cover alias replacement/reuse, multicast and routing, fault ordering, readiness spill/reuse, rejected time skips, foreign-controller reactions and neighboring-simulation isolation. No application passthrough was introduced. Linux and Windows runtime/performance validation remains deferred.

Raw executables, hashes, samples, ranges, CSV summaries, independent audits, profiles and validation logs are local artifacts in `target/performance/udp32/`. `final/` is the baseline-to-final comparison; `incremental/` and `boundaries/` use the intermediate baselines described above. `readiness-review.md` records the remaining lock and causality constraints for an attached-Executive investigation. These target artifacts are local records, not repository fixtures.

```sh
CARGO_PROFILE_RELEASE_DEBUG=1 CARGO_INCREMENTAL=0 cargo build --release -p snare --example performance_probe
python3 scripts/measure-runtime.py --suite udp32 --repeats 10 --before target/performance/udp32/before --after target/release/examples/performance_probe --output target/performance/udp32/repeated-final
CARGO_PROFILE_RELEASE_DEBUG=1 CARGO_INCREMENTAL=0 cargo test --release -p snare --test edge_scale_alloc -- --nocapture
```

## Deterministic handoff, tied timers, station lookup and Linux futex probes, 2026-10-12

This pass adds handoff benchmarks, then removes the costs they and the earlier notes exposed. It is the first pass with Linux numbers.

Linux results come from Criterion on a dedicated benchmark host, svc01: AMD Ryzen 9 5950X, Linux 6.8.0-139-generic, Rust 1.99.0, the default bench profile, pinned to CCD0 (CPUs 0–7 and 16–23) with the `performance` governor and boost on, and serialized against CI jobs. The before tree is revision 50edd64 exported with `git archive`, with this pass's `benches/hooked_calls.rs` and probe copied in and the same `Cargo.lock`, so both trees run identical workloads; the after tree is the changed working tree. Three before/after pairs ran in alternating order, with one-minute load averages between 1.35 and 5.60 on the 32-thread host. Each cell is the median of the three Criterion point estimates, with their minimum–maximum. The filter excludes `in_sim/mio_poll_zero_timeout/1024`, which fails on Linux before and after: the sim inherits the host's 1,024-descriptor soft limit, and 1,024 sockets plus the poll exceed it.

macOS results come from `scripts/measure-runtime.py --suite handoff --repeats 9` on the Apple M5 Pro (macOS 26.6.2, Rust 1.99.0), with probes built by `CARGO_PROFILE_RELEASE_DEBUG=1 CARGO_INCREMENTAL=0 cargo build --release`: 468 fresh-process samples in randomized paired order, zero errors. Unrelated sessions loaded the host heavily: the one-minute load average was 43.1 before and 33.8 after on 18 logical CPUs, and reached 77 during earlier runs that day. Only large effects are meaningful there; native controls in the same run moved by paired factors of 0.94–1.11. Docker on this Mac served for Linux profiles and tests only, since its handoff timings spread from 3.5 to 42 µs.

Application threads, mutexes, condition variables, channels, sockets and timers are created inside `Sim.run`; the passthrough rings run outside any sim with hooks installed. Ring workers are spawned and pass a start barrier before the stopwatch.

Linux, Criterion, per handoff, transfer pair or cancel:

| Workload | Before | After | Speedup |
| --- | --- | --- | --- |
| `deterministic/handoff_condvar_ring/2` | 5.417 (5.358–5.419) µs | 1.318 (1.296–1.370) µs | 4.11× |
| `deterministic/handoff_channel_ring/2` | 5.581 (5.581–5.612) µs | 1.572 (1.528–1.597) µs | 3.55× |
| `deterministic/handoff_condvar_ring/3` | 5.440 (5.406–5.459) µs | 4.491 (4.464–4.618) µs | 1.21× |
| `deterministic/handoff_condvar_ring/8` | 5.549 (5.531–5.596) µs | 4.583 (4.567–4.724) µs | 1.21× |
| `deterministic/handoff_channel_ring/8` | 5.822 (5.790–5.848) µs | 4.824 (4.782–4.965) µs | 1.21× |
| `deterministic/yield_2_threads_with_spawn_join` | 3.635 (3.580–3.655) µs | 0.808 (0.807–0.829) µs | 4.50× |
| `deterministic/time_skip_1ms_sleep` | 1.236 (1.216–1.266) µs | 0.945 (0.933–0.947) µs | 1.31× |
| `in_sim/handoff_condvar_ring/2` | 2.439 (2.431–2.484) µs | 1.147 (1.139–1.182) µs | 2.13× |
| `in_sim/handoff_channel_ring/2` | 989.9 (987.1–1001.4) ns | 634.3 (625.1–689.1) ns | 1.56× |
| `in_sim/handoff_condvar_ring/8` | 4.147 (4.068–4.151) µs | 3.416 (3.414–3.515) µs | 1.21× |
| `in_sim/handoff_channel_ring/8` | 4.322 (4.295–4.366) µs | 3.525 (3.515–3.639) µs | 1.23× |
| `passthrough/handoff_condvar_ring/2` (native control) | 3.107 (3.067–3.126) µs | 3.140 (3.089–3.159) µs | 0.99× |
| `passthrough/handoff_condvar_ring/8` (native control) | 3.102 (3.096–3.123) µs | 3.102 (3.095–3.103) µs | 1.00× |
| `in_sim/timer_cancel_1000_tied` (1,000 cancels) | 153.040 (150.290–162.700) µs | 40.925 (36.305–42.241) µs | 3.74× |
| `in_sim/udp_send_recv_beside_256_tcp_listeners` | 802.5 (782.3–809.5) ns | 512.1 (510.4–519.5) ns | 1.57× |
| `in_sim/udp_send_recv_loopback` | 491.9 (491.1–501.2) ns | 515.7 (514.4–544.6) ns | 0.95× |
| `in_sim/mutex_2_threads_with_spawn_join` | 5.9 (5.8–5.9) ns | 8.9 (8.7–9.0) ns | 0.66× |

The three-worker rows not shown improved by 1.19–1.21×. The other 18 Criterion workloads, including `thread_spawn_join`, `time_skip_1ms_sleep`, the testers round trip and the remaining passthrough rings, stayed within 0.96–1.02×.

macOS, measure-runtime, per handoff or cancel, nanoseconds:

| Workload | Before | After | Speedup | Paired |
| --- | --- | --- | --- | --- |
| det condvar ring, 2 workers | 3,804 (1,986–20,730) | 1,150 (790–4,639) | 3.31× | 2.75× |
| det channel ring, 2 workers | 3,828 (2,665–14,955) | 1,769 (1,559–13,316) | 2.16× | 2.06× |
| det condvar ring, 3 workers | 3,875 (1,979–13,347) | 3,792 (1,869–23,518) | 1.02× | 1.02× |
| det condvar ring, 8 workers | 3,653 (1,964–16,222) | 3,548 (1,942–51,622) | 1.03× | 0.97× |
| det channel ring, 8 workers | 4,481 (2,131–27,942) | 4,112 (2,615–36,220) | 1.09× | 0.83× |
| plain, 1,000 tied timer cancels | 189.1 (177.4–214.2) | 46.8 (45.2–381.3) | 4.04× | 4.07× |
| plain, 4,000 tied timer cancels | 599.6 (546.4–1,047.9) | 44.5 (40.5–52.8) | 13.48× | 13.26× |
| det, 4,000 tied timer cancels | 679.3 (549.0–1,177.5) | 51.4 (42.4–62.4) | 13.22× | 13.63× |
| plain UDP, 1,024 TCP listeners | 1,189 (1,074–1,884) | 461 (415–608) | 2.58× | 2.71× |
| det UDP, 1,024 TCP listeners | 1,406 (1,104–1,961) | 478 (440–643) | 2.94× | 2.64× |
| plain UDP, 1 TCP listener | 450 (410–605) | 471 (424–702) | 0.96× | 0.99× |

The ranges of the three- and eight-worker deterministic rings overlap almost entirely; this run does not separate them from the native controls' noise. Plain rings, whose macOS paths did not change, moved by paired factors of 0.89–1.03.

### Profiles

A macOS `sample` of the deterministic two-worker condvar ring spent 82% of each worker's samples in `__psynch_cvwait` and 10% in `__psynch_cvsignal`, called from the scheduler's parker grant; scheduler bookkeeping, hooks and locks made up the remaining 7%. Handoff cost was the kernel wake of the next thread, not lock contention, allocation or scans. A Linux `perf record` in Docker of the same ring, with the next thread caught spinning, put about 35% of non-spinning samples in the futex wait hook's readability check: `getpid` plus `process_vm_readv`, whose kernel side looks up the VMA, pins the page and copies four bytes. In the same VM, a C microbenchmark measured 317–369 ns for that pair of calls and 128–142 ns for one `FUTEX_CMP_REQUEUE` probe. A plain-mode Linux profile of the eight-worker ring spent 6% in std's `Mutex::lock_contended` on the census lock: the woken waiter's `unpark_inner` waits while the waker issues the real `FUTEX_WAKE` under that lock, which keeps the wake and its census record atomic.

### What changed

A parked deterministic thread now spins on an atomic flag for up to 512 checks (about 5 µs on the M5 Pro) before sleeping on its condition variable, but only when the handoff that parked it went to the thread it had the baton from. The scheduler tells that from the previous two holders. Two threads passing the baton back and forth therefore find it while still spinning, and no kernel wake is needed; a ring of three or more never spins. A grant signals the condition variable only when the thread sleeps, after letting go of the parker's lock. A spin that ends in sleep makes the thread skip spinning on its next one and then three handbacks, so a slow peer or a loaded host costs little CPU. Unconditional spinning was measured first: on svc01 it made three-worker rings 12–16% faster and left eight-worker rings unchanged, but on the loaded Mac its three- and eight-worker medians were 10–57% slower, so spinning was limited to handbacks. Who runs next, and so deterministic replay order, is unchanged; only how a parked thread waits for its grant changed.

On Linux, the futex hooks probe a word's readability with one `FUTEX_CMP_REQUEUE` that wakes and requeues nothing, instead of `getpid` and `process_vm_readv`. The kernel reads the word as for any futex call and answers 0 or `EAGAIN` if it could and `EFAULT` if not; the word is then read atomically. Any other error, such as a seccomp filter refusing the call, falls back to the copy and its `/proc/self/maps` fallback. `EFAULT` behavior for unreadable and `PROT_NONE` words is unchanged, and the restricted-seccomp tests still pass. The three- and eight-worker Linux rings, which never spin, owe their 1.2× mainly to this probe; macOS, which has no such probe, shows no comparable change.

Each registered timer wake records its slot (pending waker index or delivered-and-held index) beside its deadline. Cancellation swap-removes at that slot and updates the moved entry's slot, so wakes tied on one deadline cancel in constant time with the same swap-removal order as before. Delivering held wakes now writes their new slot, one map update per wake.

The listener registry keeps a count of tester listeners per IP, maintained on insert, replacement and removal, so `station_at` no longer scans every listener. Every UDP send asks it, so code-under-test TCP listeners previously slowed UDP linearly.

`in_sim/mutex_2_threads_with_spawn_join` slowed from 5.9 to 8.9 ns per lock. In Docker, restoring the old probe only in the wait paths restored the old 14 ns there, and adding three `getpid` calls to the new probe made it 12.2–12.6 ns. A faster contended wait path lets the waiter reach the real futex sleep before the holder unlocks, which costs a wake; the benchmark's race rewards a slower wait path rather than measuring per-call cost. In isolated svc01 reruns, `in_sim/udp_send_recv_loopback` measured 495–501 ns before, 504–518 ns after, and 503–508 ns with the listener registry change reverted; its 0.95× row is within run-to-run spread and not attributable to that change.

### Validation

The macOS workspace suite passed 1,516 tests with no failures and three ignores (two hardware-dependent tests and one doctest). The Linux workspace suite in Docker (`rust:latest`, aarch64, 18 CPUs) passed 1,916 tests with no failures and 24 ignores. New unit tests cover tester-listener counts through replacement and removal, and cancellation of tied wakes moved by earlier cancels, pending and delivered. `deterministic.rs`, `parallel_mio_determinism.rs` and `executive_det.rs` passed three further times on Linux. The deterministic two-, three- and eight-worker rings ran 120 times on each OS without a hang. Strict workspace/all-target Clippy passed on macOS and Linux, and formatting passed.

### What remains

Deterministic handoff among three or more threads still costs one kernel wake per handoff: 4.5–4.8 µs on svc01 against a 3.1 µs native ring. Waking the next thread before the current one parks, or keeping exactly the next runnable thread spinning, would need the scheduler to predict the next holder before the running thread blocks. The two-thread deterministic handback still spends about 1.3 µs per handoff on Linux in hook and scheduler work. Plain-mode Linux waits contend on the census lock as profiled above. Polling still scans registrations, and a ready-event queue would be a separate architectural change. TCP binds and connects still collect every socket of the fabric to check port conflicts. Windows still scans its UDP bindings and listeners for stations, and Windows performance testing remains deferred. The second pass below takes up the binds, connects, polls and rings of this list; its own list supersedes this one.

Artifacts are local, in `target/performance/handoff/`: `svc01-pairs/` holds the final Criterion logs, `svc01-varA/` the isolated reruns, `svc01-spin512.log`, `svc01-adapt6.log` and `svc01-adapt2.log` the spin variants, `macos/` the measure-runtime samples and summary, and `profiles/` the macOS samples. They are not repository fixtures.

```sh
cargo bench -p snare --bench hooked_calls -- '^(passthrough|in_sim/(clock|sched|udp|tcp|thread|time|mutex|handoff|mio_poll_zero_timeout/(1|64)$)|lifecycle|deterministic|testers)'
CARGO_PROFILE_RELEASE_DEBUG=1 CARGO_INCREMENTAL=0 cargo build --release -p snare --example performance_probe
python3 scripts/measure-runtime.py --suite handoff --repeats 9 --before target/performance/handoff/performance_probe-before --output target/performance/handoff/macos
```

Single workloads include `performance_probe det handoff_condvar 2 20000`, `performance_probe plain timer_cancel_tied 4000 1` and `performance_probe plain udp_beside_listeners 1024 20000`; `SIZE` is the worker count, the number of tied timers, or the number of TCP listeners.

## Port index, cheaper polls and nudged handoffs, 2026-10-12

A second pass the same day takes up the list above: binds and connects among many sockets, polls with many registrations, the Linux 1,024-registration poll, and deterministic rings of three or more threads.

Linux results come from Criterion on svc01 as above. The before tree is the first 2026-10-12 pass, with this pass's `benches/hooked_calls.rs` and probe copied in and the same `Cargo.lock`; the after tree is the changed working tree. Three before/after pairs ran over the whole suite in the order before, after, after, before, before, after. A late change to the nudge below touched only deterministic waits, so the `deterministic` and `testers` groups ran again as three more pairs (after, before, before, after, after, before), and their rows come from that run. One-minute load averages were between 1.49 and 6.17 on the 32-thread host. Each cell is the median of the three Criterion point estimates, with their minimum–maximum. The TCP scale workloads take 10 samples each (see above).

macOS results come from `scripts/measure-runtime.py --suite scale --repeats 5` and `--suite handoff --repeats 7` on the Apple M5 Pro, with probes built by `CARGO_PROFILE_RELEASE_DEBUG=1 CARGO_INCREMENTAL=0 cargo build --release`: 200 and 406 fresh-process samples in randomized paired order, zero errors. Unrelated sessions loaded the host: one-minute load averages were 12.0 before and 9.6 after the scale suite and 16.3 before and 12.8 after the handoff suite, on 18 logical CPUs, after reaching 30 earlier in the session. Native controls in the handoff run moved by paired factors of 0.96–1.03.

Linux, Criterion, per call, handoff, message, bind or connect:

| Workload | Before | After | Speedup |
| --- | --- | --- | --- |
| `in_sim/mio_poll_zero_timeout/1` | 1.602 (1.571–1.624) µs | 226.5 (224.8–234.7) ns | 7.07× |
| `in_sim/mio_poll_zero_timeout/64` | 50.523 (49.510–51.235) µs | 3.906 (3.898–3.965) µs | 12.93× |
| `in_sim/mio_poll_zero_timeout/1024` | 923.900 (892.450–930.650) µs | 81.109 (80.903–81.977) µs | 11.39× |
| `in_sim/tcp_bind_listen_close_beside_listeners/1024` | 29.741 (29.654–30.039) µs | 3.218 (3.204–3.272) µs | 9.24× |
| `in_sim/tcp_bind_listen_close_beside_listeners/16384` | 652.910 (627.590–661.060) µs | 3.161 (3.007–3.234) µs | 206.55× |
| `in_sim/tcp_connect_accept_close_beside_listeners/1024` | 33.731 (33.608–33.874) µs | 6.583 (6.386–6.796) µs | 5.12× |
| `in_sim/tcp_connect_accept_close_beside_listeners/16384` | 470.540 (463.230–475.480) µs | 6.228 (6.221–6.495) µs | 75.56× |
| `deterministic/handoff_condvar_ring/3` | 4.475 (4.461–4.489) µs | 3.719 (3.716–3.758) µs | 1.20× |
| `deterministic/handoff_channel_ring/3` | 4.715 (4.696–4.719) µs | 3.856 (3.853–3.885) µs | 1.22× |
| `deterministic/handoff_condvar_ring/8` | 4.604 (4.582–4.631) µs | 3.792 (3.789–3.817) µs | 1.21× |
| `deterministic/handoff_channel_ring/8` | 4.836 (4.817–4.838) µs | 3.932 (3.917–3.940) µs | 1.23× |
| `deterministic/handoff_condvar_ring/2` | 1.320 (1.289–1.334) µs | 1.353 (1.339–1.381) µs | 0.98× |
| `deterministic/yield_2_threads_with_spawn_join` | 789.8 (788.4–790.3) ns | 811.5 (810.0–812.2) ns | 0.97× |
| `deterministic/channel_burst/64` | 65.8 (65.6–66.5) ns | 67.5 (65.0–68.4) ns | 0.97× |
| `passthrough/handoff_condvar_ring/8` (native control) | 3.114 (3.107–3.116) µs | 3.113 (3.106–3.114) µs | 1.00× |
| `passthrough/channel_burst/64` (native control) | 115.4 (113.6–116.6) ns | 114.6 (112.2–115.8) ns | 1.01× |

`in_sim/mio_poll_zero_timeout/1024` failed before the benchmark raised its descriptor limit; both trees ran it here. The other 30 workloads, including the plain and native rings, the UDP and TCP transfers and the remaining deterministic rings, stayed within 0.96–1.04×, except `in_sim/timer_cancel_1000_tied` at 1.17× and `in_sim/channel_burst/64` at 1.12×, whose before runs spread over 34.2–40.9 µs and 85.8–90.4 ns and which this pass did not change. The two-worker deterministic rings, deterministic yields and bursts are 1–3% slower, beyond before-run spreads of under 1%. The nudge adds a check to every wake and a load to every nudge, and nothing else this pass changed lies on those paths on Linux.

On macOS, UDP send and receive gained about 1.27× from the mutex hooks' passthrough exit, the only change on that path; the deterministic rings did not move beyond the loaded host's noise.

macOS, measure-runtime, per call, bind, connect, handoff or message, nanoseconds:

| Workload | Before | After | Speedup | Paired |
| --- | --- | --- | --- | --- |
| plain poll, 1 registration | 623 (474–651) | 268 (204–281) | 2.32× | 2.33× |
| plain poll, 64 registrations | 12,300 (8,936–13,500) | 3,159 (2,277–3,363) | 3.88× | 3.92× |
| plain poll, 1,024 registrations | 250,700 (159,800–314,800) | 58,300 (37,800–74,600) | 4.30× | 4.29× |
| det poll, 1,024 registrations | 296,800 (159,100–337,100) | 75,400 (37,600–100,300) | 3.93× | 3.96× |
| plain poll, 128 registrations, 1 KiB datagram on each | 18,100 (17,200–31,600) | 5,165 (4,760–10,700) | 3.51× | 3.55× |
| plain bind beside 1,024 listeners | 28,700 (20,800–32,500) | 2,349 (1,641–2,678) | 12.23× | 12.23× |
| plain bind beside 16,384 listeners | 716,100 (585,700–836,200) | 2,208 (1,698–2,348) | 324.31× | 356.07× |
| plain connect beside 1,024 listeners | 31,600 (22,700–36,000) | 4,590 (3,486–4,692) | 6.89× | 6.89× |
| plain connect beside 16,384 listeners | 693,300 (461,800–792,400) | 4,797 (3,564–5,046) | 144.53× | 137.40× |
| plain UDP send/receive, 1 TCP listener | 437 (405–443) | 344 (313–345) | 1.27× | 1.28× |
| det condvar ring, 3 workers | 5,132 (2,523–5,898) | 4,960 (3,021–5,883) | 1.03× | 0.94× |
| det condvar ring, 8 workers | 4,651 (2,532–6,088) | 4,759 (3,175–6,169) | 0.98× | 0.97× |
| det channel ring, 8 workers | 5,061 (2,917–6,293) | 5,275 (3,229–6,236) | 0.96× | 0.99× |
| det channel burst, 64 | 117 (65–165) | 105 (73–138) | 1.12× | 1.07× |
| native condvar ring, 8 workers | 3,833 (1,627–4,766) | 3,839 (1,594–4,251) | 1.00× | 1.01× |

### Profiles

A Linux `perf record` in Docker of a zero-timeout `epoll_wait` over 1,024 idle UDP registrations put 81% of its time in `wait_until_dynamic`: a wait whose deadline had already passed still built its interests (a hash set of 1,024 wake keys, 40%), the earliest timerfd expiry (a hash set of every watched identity, 10%), and ran the readiness scan a second and third time as its predicate. The scan itself took four record locks and three queue locks per registration, computed every registration's arrival order whether or not it fired, and wrote every registration's edge state back through a hash lookup. Each `epoll_wait` and `kevent` also walked every socket of the fabric at least twice looking for connecting sockets. A macOS `sample` of the same poll spent 65% in snare's hooked `pthread_mutex_lock` and `pthread_mutex_unlock`, reached by the fabric's own `std` mutexes: a lock read thread-local state twice and an unlock four times, each time finding the caller under passthrough. A `sample` of a bind beside 4,096 listeners spent almost all its time in `tcp_bind_addr`, collecting every socket with a copy of its options.

Counters in a scratch build on svc01 showed that when a ring worker hands over, the thread it makes runnable is the only runnable one and is granted next in all but a few hundred of four million handoffs: the scheduler can name the next holder before the current one blocks, the condition the first pass named for waking it early.

### What changed

The fabric's socket table indexes descriptions by the port each holds against a new bind: a TCP socket's bound, listening or connected address, or a datagram socket's claim. The index is kept where a description is placed, replaced, retired, handed to another sim or bound in place, and a debug assertion checks every entry read. The listener registry keeps the addresses listened on at each port. A TCP bind, listen or implicit connect bind checks only the sockets and listeners on its port, with the same `tcp_bind_conflict` rule; an explicit UDP bind checks only the datagram sockets on its port. Ephemeral ports draw from the same counter in the same order. The table also counts connecting sockets, so polls skip their connect sweep when there are none.

A zero-timeout `epoll_wait` no longer enters the readiness wait. Its deadline has passed on entry, and a wait with a passed deadline checks readiness once more and returns without parking, in a deterministic schedule and outside one. What that check could add is a connect falling due, which still counts as a wake; in a deterministic schedule nothing else can change between the scan and the return, and outside one a change racing the call shows at the next. The kqueue path, which already skipped the wait, drops its second scan the same way. Readiness, edge, one-shot and level-triggered requeue rules are unchanged.

The scan reads a stream's or datagram socket's record once, under one lock, for its pending error, readable error-queue reports and error wakes, and a datagram socket's queue once for its readiness and landed count. A registration's arrival order is computed only when it fires, and its edge state is written back only when it changed. Lands and error-wake counts happen as before, grouped under fewer locks; in a deterministic schedule no other thread runs meanwhile, so the grouping cannot be seen.

On every Unix, the `pthread_mutex_lock` and `pthread_mutex_unlock` hooks forward straight to libc on a thread under passthrough, where every other step they took already did nothing. On macOS that covers snare's own `std` mutexes.

A deterministic thread made the only runnable one while another holds the baton is nudged: if it sleeps without a grant, its parker's condition variable is signalled so the kernel wakes it while the holder still runs, and when the holder lets go the grant usually finds it awake, needing no second kernel wake. A nudged thread that wakes before its grant spins for it for up to 10 µs of real time; a spin that ends in sleep makes the thread pass up its next one, then three, nudges, as handback spins do. A nudge the grant overtakes is dropped. Who runs next, and so replay order, is unchanged. A version that left a nudge set until the thread's next park made each worker spin from the park after its handoff, which is the spinning from every park the first pass rejected: it brought three-worker rings to 2.6 µs on svc01 by spinning about 5 µs per handoff, and was not kept.

The benchmark raises its own descriptor limit, so `in_sim/mio_poll_zero_timeout/1024` runs on Linux.

### Validation

The macOS workspace suite passed 1,541 tests with no failures and three ignores (two hardware-dependent tests and one doctest). The Linux workspace suite in Docker (`rust:latest`, aarch64, 18 CPUs) passed 1,940 with no failures and 24 ignores. A new test binds among ten thousand TCP and ten thousand UDP sockets, and debug builds check every port-index entry they read against the socket it names throughout both suites. `deterministic.rs`, `deterministic_processes.rs`, `parallel_mio_determinism.rs` and `executive_det.rs` passed three further times on each OS after the last change. The deterministic two-, three- and eight-worker condvar and channel rings and the 64-message burst ran 60 times on each OS after the last change, and 120 times each before it, without a hang. Strict workspace/all-target Clippy passed on macOS and Linux, as did Clippy of `snare` and `snare-interpose` for `x86_64-pc-windows-msvc`, and formatting passed.

### What remains

Polling still scans every registration, now at about 80 ns per idle UDP registration on svc01 and 40–60 ns on the M5 Pro. A ready list would need every change to a socket's readiness to reach the registrations watching it: datagram queues and their timed landings, stream pipes and their shutdown progress, listener queues, error queues with their visibility deadlines, eventfd and timerfd counters, and the records a `SimHost` serves. Blocking waits use wake keys for the same purpose but only to re-run the scan. Blocking `epoll_wait` and `kevent` calls still rebuild their wake keys over every registration each time they sleep. The ready-list pass below takes up this paragraph; its own list supersedes it.

Deterministic rings of three or more threads still cost 3.7–3.9 µs per handoff on svc01, against 3.1 µs native, and are unchanged on the M5 Pro. The two-thread handback costs about 1.3 µs.

Plain-mode Linux waits still contend on the census lock, which the waker holds across the real `FUTEX_WAKE` so that the woken waiter cannot leave its wait before the release is recorded. Recording it after the wake instead would need to tell which waiter the kernel woke: by then that waiter may have left and another enrolled on the same word, and `signal_futex` would release the wrong one, keeping the domain from ever looking quiescent. That has not been changed.

On macOS every lock of snare's own still passes through the hooks, now at the cost of one thread-local read. Windows still scans its UDP bindings and listeners for stations, and an explicit Windows UDP bind still checks every socket; Windows performance testing remains deferred.

Artifacts are local, in `target/performance/round2/`: `svc01/` holds the Criterion logs of the three full pairs and the three deterministic pairs, `nudge/` the nudge variant runs and counter logs, `profiles/` the macOS samples and Linux perf reports, and `macos-scale/` and `macos-handoff/` the measure-runtime samples and summaries. They are not repository fixtures.

```sh
cargo bench -p snare --bench hooked_calls
CARGO_PROFILE_RELEASE_DEBUG=1 CARGO_INCREMENTAL=0 cargo build --release -p snare --example performance_probe
python3 scripts/measure-runtime.py --suite scale --repeats 5 --before target/performance/round2/performance_probe-before --output target/performance/round2/macos-scale
python3 scripts/measure-runtime.py --suite handoff --repeats 7 --before target/performance/round2/performance_probe-before --output target/performance/round2/macos-handoff
```

Single workloads include `performance_probe plain poll 1024 300`, `performance_probe plain listen_beside_listeners 16384 2000`, `performance_probe plain connect_beside_listeners 16384 2000` and `performance_probe det channel_burst 64 64000`; for the last `SIZE` is the burst length.

## Windows baseline, timed waits and AFD polls, 2026-10-12

This pass makes the Criterion benchmark run on Windows, takes a first Windows baseline, and removes the three costs it exposed. All 39 workloads run there, including `in_sim/mio_poll_zero_timeout/1024`.

Windows results come from Criterion with the default bench profile, built for `aarch64-pc-windows-msvc` with `cargo xwin` (Rust 1.99.0) and run in a Parallels VM: Windows 11 ARM64 10.0.26300.9457, 4 virtual CPUs and 12 GB, on the Apple M5 Pro (18 CPUs). That host is no benchmark machine: unrelated sessions load it, and the VM's wakes ride on the host's scheduler. In three earlier rounds of alternating pairs, at one-minute load averages of 8 to 32, the native `passthrough` rings moved by up to 110× between runs of one binary (`passthrough/handoff_channel_ring/8` from 37 µs to 13 ms). The table is a fourth round, taken when the load average had fallen to 2–4: two before and two after runs in alternating order, each cell the mean of the two Criterion point estimates with both in parentheses. The before tree is this pass's starting point with this pass's `benches/hooked_calls.rs`; the after tree is the changed working tree, which also carries the `WaitOnAddress` wake tracking below.

Application threads, mutexes, condition variables, channels, sockets and timers are created inside `Sim.run`; the passthrough rings run outside any sim with hooks installed.

Windows, Criterion, per operation:

| Workload | Before | After | Speedup |
| --- | --- | --- | --- |
| `in_sim/mio_poll_zero_timeout/1024` | 657.5 (647.9, 667.2) µs | 25.1 (25.1, 25.1) µs | 26.19× |
| `in_sim/time_skip_1ms_sleep` | 515.8 (514.0, 517.7) µs | 35.7 (35.0, 36.4) µs | 14.44× |
| `in_sim/mio_poll_zero_timeout/64` | 3.299 (3.254, 3.343) µs | 2.465 (2.447, 2.484) µs | 1.34× |
| `in_sim/mio_poll_zero_timeout/1` | 1.116 (1.055, 1.177) µs | 1.060 (1.058, 1.063) µs | 1.05× |
| `deterministic/time_skip_1ms_sleep` | 28.5 (28.4, 28.7) µs | 28.4 (28.3, 28.4) µs | 1.01× |
| `in_sim/udp_send_recv_loopback` | 471.0 (469.3, 472.6) ns | 477.6 (466.4, 488.9) ns | 0.99× |
| `in_sim/handoff_condvar_ring/2` | 715.3 (656.0, 774.5) ns | 1430.4 (641.8, 2219.0) ns | 0.50× |
| `in_sim/handoff_condvar_ring/8` | 10.976 (10.972, 10.980) µs | 10.903 (10.894, 10.912) µs | 1.01× |
| `deterministic/handoff_condvar_ring/2` | 1.063 (1.056, 1.069) µs | 1.030 (1.028, 1.032) µs | 1.03× |
| `deterministic/handoff_condvar_ring/8` | 11.057 (11.031, 11.083) µs | 11.011 (10.999, 11.023) µs | 1.00× |
| `passthrough/handoff_condvar_ring/2` (native control) | 1.485 (1.399, 1.571) µs | 1.201 (0.753, 1.649) µs | 1.24× |
| `passthrough/handoff_condvar_ring/8` (native control) | 10.275 (10.273, 10.277) µs | 10.319 (10.311, 10.327) µs | 1.00× |
| `testers/udp_tester_round_trip` | 7.680 (7.614, 7.747) µs | 11.401 (8.292, 14.510) µs | 0.67× |

The other 26 workloads, including every other `passthrough` one, stayed within 0.89–1.03×. Two-thread handoffs are bimodal in this VM, native ones included: `passthrough/handoff_condvar_ring/2` ran at 0.75 and 1.65 µs in the two after runs. One after run of `in_sim/handoff_condvar_ring/2` matched the before runs (642 ns) and the other did not (2.2 µs), and the tester round trip, also two threads, split the same way; neither separates from that spread. Both louder rounds after the changes, the timer change then in an earlier form, agreed with this one on the two large rows. As a baseline, hooked calls on Windows in this VM cost about what they do elsewhere (`in_sim/udp_send_recv_loopback` 0.47 µs, `in_sim/mutex_uncontended` 6.7 ns, `in_sim/thread_spawn_join` 71 µs), while every handoff among three or more threads, native or simulated, plain or deterministic, costs 10–11 µs: the VM's wake latency, not snare's.

Single timed waits, measured with a throwaway probe (not kept): real time per call over 50 or 200 calls on the only participant of a fresh plain sim, release build, during the louder rounds, one or more runs per cell:

| Call | Platform | Before | After |
| --- | --- | --- | --- |
| `thread::park_timeout(1 ms)` | Windows VM | 16.3–29.0 ms | 0.75–9.2 µs |
| `Condvar::wait_timeout(1 ms)` | Windows VM | 17.9–29.9 ms | 0.79–3.9 µs |
| `thread::park_timeout(1 ms)` | macOS, M5 Pro | 2.519 ms | 683 ns |
| `Condvar::wait_timeout(1 ms)` | macOS, M5 Pro | 2.524 ms | 1.01 µs |
| `thread::park_timeout(1 ms)` | Linux, Docker aarch64 | 2.995 ms | 1.53 µs |

### Profiles

No sampling profiler ran in the VM; timing probes isolated the costs. A plain sim's one-millisecond virtual park or condition-variable timeout took 16–29 ms of real time on Windows and 2.5–3.0 ms on macOS and Linux, whatever the requested length (`park_timeout(1 s)` cost the same). That is one real slice of a timed native wait: up to 2 ms (`NATIVE_WAIT_SLICE`) everywhere, and on Windows a 2 ms `WaitOnAddress` timeout runs to the next tick of the default system timer. `thread::sleep` on Windows waits on a high-resolution waitable timer with an infinite timeout, which polled the handle in 2 ms real slices until the idle-skip worker moved time. `mio_poll_zero_timeout` grew 3× from 1 to 64 sockets and 199× from 64 to 1,024: every completion-port check scanned all sockets to find each pending AFD poll's record.

### What changed

A timed native wait whose participant leaves its domain quiescent time-skips before its first real slice instead of after it. If the skip reaches the wait's own deadline, it times out without touching the OS. This is shared code: futex, `WaitOnAddress`, `pthread_cond_timedwait` and semaphore timed waits on every platform take the same path. Who wakes and when, in virtual time, is unchanged; the skip that ended the first slice now ends no slice.

A waitable-timer wait with an infinite timeout, as `thread::sleep` makes, time-skips to the timer itself before each 2 ms real slice when its domain is quiescent and no executive is attached, rather than waiting for the idle-skip worker. It registers no second timer, so an executive's timer listing is unchanged.

Each modeled AFD poll request keeps the socket handle it polls and finds the socket by it, falling back to a scan only when the handle no longer holds that socket. Completion-port refreshes, interest collection and due checks are linear in pending polls.

`WaitOnAddress` tells a wake from a spurious return per address (an `AddressWatch` per wait, listed under a fixed table of 4,096 spin-locked lists), not per hashed counter. It costs one uncontended lock and unlock per real wait and per wake that finds waiters in its list.

### Validation

The macOS workspace suite passed 1,540 tests with no failures and three ignores, and the Linux workspace suite in Docker (`rust:latest`, aarch64) passed 1,939 with no failures and 24 ignores. In the Windows ARM64 VM, all 314 test and example binaries ran: 1,034 tests passed with no failures and six ignores, and the `performance_probe` example, run without its arguments, exits with its usage assertion as before. The executive suites caught a first form of the timer change that registered a second timer per sleep and so doubled the executive's timer listing; the form above registers none. `wait_on_address_win::a_spurious_return_outlasts_a_wake_of_an_address_sharing_its_slot` fails before the wake tracking change, in both its timed and untimed cases, and passes after. Strict workspace/all-target Clippy passed on macOS and Linux, Clippy for `snare` and `snare-interpose` passed for `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`, and formatting passed.

### What remains

`thread::sleep` on Windows still costs 28–36 µs of real time per virtual sleep, plain or deterministic, against about 1 µs on Linux: std creates, sets, waits on and closes a waitable timer for every sleep, and each step is modeled. Handoffs among three or more threads cost the VM's 10–11 µs wake, so only a quiet Windows host can show what snare adds there. Windows x86_64 is unmeasured, and the Windows numbers come from one shared host; a repeat on a dedicated Windows machine would replace them. Windows still scans its UDP bindings and listeners for stations. The Windows pass below takes up the sleep and station items; its own list supersedes them.

Artifacts are local, in `target/performance/windows/`: `r1-*` (wake tracking only), `r2-*` and `r3-*` (the louder rounds), `r4-*` (targeted reruns) and `r5-*` (the table) hold the Criterion logs, each run named for its tree. They are not repository fixtures.

```sh
cargo xwin bench -p snare --bench hooked_calls --no-run --target aarch64-pc-windows-msvc
# in the VM, from a scratch directory:
hooked_calls-<hash>.exe --bench --noplot
```

## Ready lists for epoll and kqueue, 2026-10-12

A third pass replaces the per-call scan of every registration in an epoll set or kqueue with change notices, so that a wait costs what changed rather than what is registered, and gives blocking waits on a set one wake key in place of one per registration.

Linux results come from Criterion on svc01 as above. The before tree is the second 2026-10-12 pass with the Windows baseline, with this pass's `benches/hooked_calls.rs` and the same `Cargo.lock`; the after tree is the changed working tree. Three before and three after runs of the poll and socket workloads ran in the order before, after, after, before, before, after, at one-minute load averages between 1.28 and 4.00. Each cell is the median of the three Criterion point estimates, with their minimum–maximum. The Mac was too loaded for timing and took no measurements in this pass.

Four workloads are new. `mio_poll_wake_beside_idle/N` is one round trip between a thread blocked in a Mio poll with N idle UDP sockets registered beside an active one and an echo thread: the poller sends, blocks until the reply makes its socket readable and reads it. `mio_poll_all_ready/1024` lands a datagram on each of 1,024 registered UDP sockets, polls until all 1,024 are reported and reads each, per round. `poll_level_all_ready/1024` (Linux and macOS) is one zero-timeout wait on a level-triggered epoll set or kqueue of 1,024 UDP sockets that each hold an unread datagram, so every wait reports all of them.

Linux, Criterion, per poll, round trip or round:

| Workload | Before | After | Speedup |
| --- | --- | --- | --- |
| `in_sim/mio_poll_zero_timeout/1` | 235.4 (229.7–236.9) ns | 136.7 (131.7–138.3) ns | 1.72× |
| `in_sim/mio_poll_zero_timeout/64` | 3.767 (3.755–3.920) µs | 135.0 (133.7–135.6) ns | 27.9× |
| `in_sim/mio_poll_zero_timeout/1024` | 80.137 (79.515–82.876) µs | 137.6 (136.7–138.2) ns | 582× |
| `in_sim/mio_poll_wake_beside_idle/1` | 9.663 (9.399–9.820) µs | 9.524 (9.412–9.556) µs | 1.01× |
| `in_sim/mio_poll_wake_beside_idle/1024` | 566.800 (554.980–571.410) µs | 9.546 (9.537–9.570) µs | 59.4× |
| `in_sim/poll_level_all_ready/1024` | 152.230 (147.720–153.370) µs | 88.221 (87.671–88.876) µs | 1.73× |
| `in_sim/mio_poll_all_ready/1024` | 843.410 (841.490–882.710) µs | 884.610 (884.390–886.570) µs | 0.95× |
| `in_sim/udp_send_recv_loopback` | 600.5 (587.5–620.7) ns | 598.1 (593.9–602.8) ns | 1.00× |
| `in_sim/tcp_write_read_1k_loopback` | 403.3 (393.6–404.3) ns | 390.4 (387.0–398.3) ns | 1.03× |

A zero-timeout poll no longer grows with the registrations it holds, and a thread blocked beside 1,024 idle registrations wakes as fast as one beside a single registration. `mio_poll_all_ready/1024` is 5% slower: each of its 1,024 sends per round now marks its socket on the set's list, about 40 ns a send, which the poll's cheaper scan does not repay when every socket changes every round. While no set holds a subscription, a bump pays one atomic load for them (`udp_send_recv_loopback`); otherwise each key it names costs a lookup in one board shard.

### Profiles

The second pass's profiles, above, located the costs: a zero-timeout `epoll_wait` over 1,024 idle registrations spent its time locking and reading each registration's socket, and a blocking wait rebuilt a hash set of 2,048 wake keys every time it slept, which every readiness bump in the process then searched. A first form of this pass that kept the due registrations in hash sets measured 244 µs for `poll_level_all_ready/1024` against 153 µs before (an extra four SipHash operations per registration); the registrations now live in slots and a scan reaches them by slot, which brought it to 88 µs.

### What changed

`crate::notices` keeps a process-wide board, sharded by key, of the poll sets subscribed to each readiness key, and each set has a list of the keys marked since it last looked. A registration is subscribed under the keys its sources bump: an open description's own key and its socket record's (`Descriptor` and `Socket`), or for a socket another backend of the sim serves its record's. Every keyed readiness bump, scheduled or not, first marks its keys on the lists subscribed in its domain, and when any list is reached the bump also names each such set's own key. A blocking `epoll_wait` or `kevent` therefore listens to its set's key, its descriptor's and its real-descriptor watch's, and nothing else: its key set no longer depends on what is registered, and is rebuilt in constant time. A bump that names no source (`Readiness::bump`, a kick) makes every set look at all of its registrations at its next scan.

An epoll set's registrations and a kqueue's `EVFILT_READ`/`EVFILT_WRITE` notes live in a `PollSet`, slots indexed by identity. A scan looks only at the registrations on its due list: those notices marked, those it found firing last time (level-triggered and ready, or an edge or one-shot not yet taken because `maxevents` ran out), those whose readiness moves with the clock alone (a connect under way, an armed timerfd, a socket record with a delayed arrival, error or report pending: the same test a blocking wait already used to decide whether clock moves concern it), registrations on real descriptors the fabric does not serve, and kqueue notes on a descriptor number that names nothing. Any other registration was neither ready nor waiting on the clock when last looked at, and nothing has told its sources apart from it since, so a scan would find it exactly as it left it. The scan itself, its edge, one-shot, `EV_CLEAR`, `EV_DISPATCH` and level-triggered requeue rules, and its sort by arrival order are unchanged; ties sort in slot order rather than hash order. A wait on a set is clock-sensitive while its last scan left a registration timed.

Changes that came with no bump, because only the calling thread could be waiting on them, now post a notice without waking anyone: a socket's state change in place (a connect settling or failing, a connect to itself, a listen), an error made pending or an ICMP report queued on a record, a `setsockopt`, and a descriptor about to stop naming its description (a close, a `dup2` over it, a stale mirror replaced), so that a kqueue note on that number looks at what it names next. An epoll set or kqueue handed to another sim makes all of its registrations due there. Bumps reach the board before `Readiness::state` is taken, and nothing is added under that lock beyond a scan's own list.

### Validation

The macOS workspace suite passed 1,568 tests with no failures and three ignores, and the Linux workspace suite in Docker (`rust:latest`, aarch64) passed 1,970 with no failures and 24 ignores. `deterministic.rs`, `deterministic_processes.rs`, `parallel_mio_determinism.rs`, `executive_det.rs`, `real_fds_in_waits.rs`, `tokio_runtime.rs` and the Mio, kqueue, timerfd and readiness suites passed three further times on each OS. New unit tests cover notices reaching only the registrations and domains they name, the key a reached bump adds, and registrations replaced during a scan staying due. `readiness_mutations::host_close_releases_the_model_poll_waiter` fails intermittently on Linux in both trees (15 of 60 runs before, 21 of 60 after, in Docker): its closed descriptor number is reused by a concurrent test in the same binary. Strict workspace/all-target Clippy passed on macOS and Linux, as did Clippy of `snare` and `snare-interpose` for `x86_64-pc-windows-msvc`, and formatting passed. No Windows code changed beyond a notice where a Windows ICMP error is queued, so the Windows suite was not rerun.

### What remains

`poll(2)` and `select` still look at every descriptor they are given, as the call hands them all over, and their blocking waits still rebuild one wake key per descriptor each time they sleep; caching those keys while the fabric's descriptor table is unchanged was not done. Windows AFD polls are still checked one by one at each completion-port refresh (linear in pending polls since the Windows pass), and could take the same notices, keyed by each request's socket record. Windows still scans its UDP bindings and listeners for stations, and an explicit Windows UDP bind still checks every socket. A list holds its marks in a hashed set; a send to a registered socket costs about 40 ns more than before, which shows when every registered socket changes between polls. Readiness changes that reach no bump and no notice would now go unseen by a scan until something else marks the registration; the changes known to come without a bump are listed above, and the suites found no other.

Contention on the process-wide `Readiness::state` lock and its condition-variable wakes, not scanning, dominates a sampled `theater` run (one executive, about 25 threads, about 24 sockets); this pass does not change it; the pass below takes it up.

Artifacts are local, in `target/performance/round3/`: `svc01/` holds the Criterion logs of the six runs, each named for its tree, and `notices-hashset-after.log` the hash-set form's run. They are not repository fixtures.

```sh
cargo bench -p snare --bench hooked_calls -- '^in_sim/(mio_poll|poll_level|udp_send_recv_loopback|tcp_write_read)'
```

## Executive wakes, clock-move wakes and checks outside the readiness lock, 2026-10-12

A fourth pass targets a sim shaped like `theater` under `sham`: one executive outside the sim that enters a timestamp every few milliseconds once the sim is quiescent, about 25 participant threads, a dozen TCP and a dozen UDP sockets carrying payloads under 1 KiB every 4–8 ms, and mio, `poll`, timed receives, sleeps and `snare::sched::park` as the waits. The metric is sim time per wall time with the clock as fast as possible. `benches/cell_workload.rs` reproduces that traffic (14 UDP and 15 TCP sockets, 2,400 timestamps per sim second): `cargo bench -p snare --bench cell_workload -- SIM_SECS` prints wall time per timestamp and how often the executive checked quiescence, waited for activity and jumped.

Linux results come from svc01 as above: `cell_workload` for 60 sim seconds, three runs of each tree in the order before, after, after, before, before, after, at one-minute load averages of 1.3 to 3.0. The before tree is the ready-list pass with this pass's `cell_workload.rs`; the after tree is the changed working tree. Each cell is the median of three runs with their minimum–maximum. CPU time and context switches are from `/usr/bin/time -v` on the same binaries, two runs each.

Linux, `cell_workload`, 60 sim seconds:

| Per timestamp | Before | After | Speedup |
| --- | --- | --- | --- |
| Wall time | 70.6 (70.4–72.8) µs | 43.3 (42.9–43.6) µs | 1.63× |
| Executive quiescence checks | 7.13 | 2.21 | |
| Executive activity waits | 6.13 | 1.21 | |
| CPU time (user + system) | 244 µs | 134 µs | 1.82× |
| Voluntary context switches | 37.0 | 15.9 | |

The steps, each measured once or twice on svc01 as it landed (wall µs per timestamp, run-to-run spread about 3%): before 67–68; epoch moves only where quiescence can change, and a lock-free answer for a busy sim, 64; clock moves waking only the waits they made due, 53; a parking participant leaving the epoch alone while a woken waiter has yet to re-check, 53 (executive waits 3.7 → 1.3 per timestamp); one readiness-lock acquisition to register and check, 52; checks outside the readiness lock with a per-waiter parker, 42–44; lock-free descriptor ownership and one table lock per `poll` key set, 41–42.

`theater` itself, built against each tree without changing theater (its sources copied beside links to their sibling repositories, `snare` and `snare-interpose` patched in with `--config 'patch.crates-io…'` and the copy's lock file updated), ran `run_headless "Floor 2.rtn" --pacing afap --max-sim-secs 60` on the M5 Pro: five pairs in the order before, after, each started once the one-minute load average was under 8 (it read 5.8 to 7.0; other sessions loaded the host throughout the day, to over 40). Wall time for 60 sim seconds was 6.93 (6.63–7.79) s before and 5.75 (5.62–6.23) s after, 1.20×, about 0.115 and 0.095 s per sim second. For reference, 3.2.0 took 9.7 s on a loaded host earlier the same day. Runs at load averages of 30 to 40 showed no difference between the trees (10–19 s each): there the host's CPU, not the sim's wakes, set the pace.

Per-call workloads (`hooked_calls`, two runs of each tree) moved within run-to-run spread except `in_sim/mio_poll_zero_timeout/1`, 137.8 → 112.8 ns (1.22×, the descriptor check below) and `in_sim/tcp_write_read_1k_loopback`, 391 → 370 ns (1.06×): `in_sim/udp_send_recv_loopback` 585 → 580 ns, `in_sim/clock_gettime` 135 → 133 ns, `in_sim/handoff_condvar_ring/2` 1.14 → 1.15 µs, `in_sim/mio_poll_wake_beside_idle/1` 9.58 → 9.48 µs, `testers/udp_tester_round_trip` 8.30 → 8.36 µs, `deterministic/handoff_condvar_ring/2` 1.34 → 1.35 µs. `in_sim/channel_burst/64` read 102 ns after against 69 and 100 ns in the two before runs; it is a race between a producer and a waking consumer (see Workload interpretation) and moves with wake timing.

### Profiles

A macOS `sample` of `theater` on 3.2.0 had its executive thread blocked 35% of the time on a mutex inside `Executive::quiescence` and 42% waiting for `arm_notify`, and most of the process's mutex waits on the process-wide `Readiness::state`: re-taking it after condition-variable wakes, in `wait_until_dynamic`, in bumps and in `Subscription::drop`. Off-CPU `perf` profiles of `cell_workload` in Docker (sched_switch with call graphs) and counters added to a scratch build located the causes:

- Clock moves woke waits they could not have made ready. A charged call's latency that reached any timer bumped every time-sensitive waiter, so 54% of `epoll_wait` sleeps and 54% of `thread::sleep` sleeps ended in a wake with nothing ready; a `park` with a token counted as time-sensitive too. 28 context switches per timestamp in Docker came down to 21 by this alone.
- The executive woke about six times per timestamp: every participant parking or waking moved the epoch, though only the last parking (or the first waking) can change quiescence. Of the wakes left, 52% found a woken waiter yet to re-check (`Settling`): a participant parked while another it had just woken had not yet run.
- `ready` closures ran holding `Readiness::state`: in Docker 37 ms of every 314 ms of wall time went to predicates under that lock, and a bump waited 1.6 µs on average to take it. A woken waiter re-took it from its condition variable before it could re-check, and a blocking call took it four or five times.
- Every hooked descriptor call (`Net::owns`) and each key a `poll` wait listens on took the fabric's descriptor-table lock; with predicates out of the readiness lock that became the next contention in `theater`'s `kevent` and `poll` waits.

A `theater` sample after the changes shows the process running about 0.4 CPUs on average: its time is wake latency along chains of threads handing work to each other, which macOS charges at tens of microseconds per wake on a loaded host, and its executive spends 86% of its time waiting for the sim. Spinning briefly before sleeping (20 and 50 µs, with and without backing off) and deferring wakes that would only wait at the timestamp gate were measured and gave no gain, and were not kept.

### What changed

The epoch (`Domain::epoch`, `Quiescence::epoch`, what `arm_notify` waits on) moves only for a change that can make the domain quiescent or end its quiescence: a participant parking that leaves every participant parked, or one waking from there, and as before leases, class changes, thread exits, a deterministic schedule (where every park still counts) and the last woken waiter re-checking and waiting on. A participant that parks while a waiter a bump woke has yet to re-check leaves the epoch alone (`snare_interpose::settling_gauge` counts those waiters per domain without the readiness lock), and that waiter, if its re-check leads it out of its wait, leaves without moving it (`try_leave_sim_wait_settled`): the domain was not quiescent before and is not after. Its documented contract, "moves whenever quiescence may have changed", is unchanged; executives such as sham's that arm after every non-quiescent read now wake about once per timestamp instead of six times. The stall watchdog, which used the epoch as its sign of progress, reads a separate count of every park and wake, and the audit's outside-wake check forgets its quiet mark where a wake moves no epoch.

`Executive::quiescence` answers without the readiness lock when a participant is running outside a deterministic schedule (`Domain::busy_quiescence`), the case where whether a waiter is still waking cannot matter; the answer, blocker included, is the one the locked path gives. `Executive::epoch` reads the epoch with no lock, and `Executive::timer_count` counts what `timers(usize::MAX)` lists without listing it.

A charged call's latency that reaches a timer wakes only the waits that move made due and those every clock move concerns (`Layer::wake_due`, `Readiness::bump_due`), as an executive's own clock moves already did. A deterministic schedule's waits are woken as before.

A blocking readiness wait registers and makes its first check under one acquisition of `Readiness::state`, computes its interests only from its checks, and unregisters on its way out holding the lock it leaves with. Each waiter sleeps on a parker of its own; a bump marks it stale, counts the bump on the parker and signals it, so a woken waiter re-checks before it takes the readiness lock. The stale mark keeps the domain settling meanwhile, so no time skip or executive step sees it parked while it runs its check, exactly as when it held the lock. A bump matching its registered interests during the check makes it check again; so does any bump at all while the check changed those interests (a delayed arrival making it time-sensitive, a new key), since such a bump may have gone by unmatched. A wait not yet counted parked also checks without the lock. A waiter woken any other way (its sleep timed out) checks holding the lock as before.

The fabric keeps a bit per descriptor number it serves, and per number that mirrors another sim's socketpair end, beside its descriptor table, so `Net::owns` and the `Fs::owns` of its bpf devices answer without the table's lock; a `poll` wait's keys take the table's lock once rather than three times per descriptor, and an epoll set's or kqueue's wait no longer looks up its own descriptor.

New APIs: `Executive::epoch`, `Executive::timer_count`, `Domain::busy_quiescence`, `snare_interpose::settling_gauge`, `snare_interpose::try_leave_sim_wait_settled`, `Layer::wake_due` (defaulting to `wake_waiters`).

### Validation

The macOS workspace suite passed 1,569 tests with no failures and three ignores, and the Linux workspace suite in Docker (`rust:latest`, aarch64) passed 1,971 with no failures and 24 ignores. In the Windows ARM64 VM, the executive, deterministic, quiescence, waitable-timer, IOCP, WSAPoll, `WaitOnAddress`, scheduling-primitive, stuck, virtual-time and library suites passed: 332 tests, no failures, one ignore. `deterministic.rs`, `deterministic_processes.rs`, `parallel_mio_determinism.rs`, `executive_det.rs`, `executive.rs`, `real_fds_in_waits.rs`, `tokio_runtime.rs`, `stuck.rs` and the readiness, Mio, kqueue and timerfd suites passed three further times on each OS. A new test holds a participant running while two others hand a value back and forth 500 times and checks that the epoch never moves and an armed callback never fires until the sim settles; others check `timer_count` against `timers`. A first form of the checks outside the lock missed a clock move that came while a check found its wait newly time-sensitive, which `tokio_runtime::runtimes_in_concurrent_sims` caught (two 50 ms sleeps took 10.1 s of sim time in about one run in six); making every bump reach a re-checking waiter fixed it but cost about 230,000 extra re-checks per minute of sim time in `theater`, and the interest comparison above replaced it (no failure in 30 further runs of that suite, nor in any later suite run). `readiness_mutations::host_close_releases_the_model_poll_waiter` still fails intermittently on Linux in both trees, as the ready-list pass recorded. Strict workspace/all-target Clippy passed on macOS and Linux, as did Clippy of `snare` and `snare-interpose` for `x86_64-pc-windows-msvc`, and formatting passed.

### What remains

The sim's critical path is now wake latency along chains of threads: each timestamp of `cell_workload` still takes about 16 context switches on svc01, nearly all of them the workload's own hand-offs. `Readiness::state` is still one process-wide lock for registering, bumping and quiescence checks, now held only briefly; a bump still scans every registered waiter in the process. `theater`'s executive jumps to every participant timer separately (about 26,600 jumps a minute of sim time), and each jump is a full quiescence cycle of wakes.

Changes on sham's side that would help, none of which this pass needed: count timers with `Executive::timer_count` in `build_sched`'s snapshot rather than `timers(usize::MAX).len()`, and take `participants()` and the audit only when a report needs them rather than every 5 ms of wall time; and, where a reaction is expected within microseconds, read `Executive::epoch` for a few microseconds before blocking in `arm_notify`'s channel (measured in `cell_workload` on the loaded Mac, with no clear gain there).

Artifacts are local, in `target/performance/round4/`: `svc01/` holds the `cell_workload` and `hooked_calls` logs of every run named for its step and tree, and `profiles/` the off-CPU summaries and the `theater` samples. They are not repository fixtures.

```sh
cargo bench -p snare --bench cell_workload -- 60
```

## Windows sleeps, AFD notices and station lookup, 2026-10-12

A Windows pass takes up the Windows items left above: `thread::sleep`, completion-port refreshes that looked at every pending AFD poll, and station lookup that scanned the UDP bindings and listeners.

Windows results come from Criterion built for `aarch64-pc-windows-msvc` with `cargo xwin` (Rust 1.99.0) and run in the Parallels VM of the Windows baseline above (Windows 11 ARM64, 4 virtual CPUs, 12 GB, on the Apple M5 Pro). For most of the pass unrelated sessions held the host at one-minute load averages of 25–52, at which loopback UDP took 4–7 µs instead of 0.6 µs; those rounds are kept but not tabled. The tables come from a window at load averages of 1.6–3.0. The before tree is the third pass's working tree with this pass's `benches/hooked_calls.rs` and `benches/cell_workload.rs`; the after tree is the changed working tree. Criterion rows are the mean of the Criterion point estimates, each in parentheses: two before and two after runs of the suite in the order before, after, after, before, and for the socket rows four of each against the final after tree, in the order before, after, after, before, twice. The `tcp_*_beside_listeners/16384` workloads were left out: building 16,384 listeners on Windows takes long enough that Criterion estimated 2.4 hours for one of them (see What remains). The timer table comes from a throwaway probe (not kept): six alternating runs per tree of 3,000 calls each in a fresh plain or `deterministic()` sim, medians with ranges.

Windows, Criterion, per operation:

| Workload | Before | After | Speedup |
| --- | --- | --- | --- |
| `in_sim/time_skip_1ms_sleep` | 34.840 (34.947, 34.732) µs | 4.622 (4.630, 4.614) µs | 7.54× |
| `deterministic/time_skip_1ms_sleep` | 28.421 (28.381, 28.460) µs | 4.557 (4.542, 4.572) µs | 6.24× |
| `in_sim/mio_poll_zero_timeout/1` | 1.117 (1.162, 1.086, 1.097, 1.125) µs | 1.102 (1.132, 1.168, 1.056, 1.054) µs | 1.01× |
| `in_sim/mio_poll_zero_timeout/64` | 2.449 (2.397, 2.453, 2.457, 2.489) µs | 1.047 (1.036, 1.034, 1.066, 1.053) µs | 2.34× |
| `in_sim/mio_poll_zero_timeout/1024` | 24.578 (24.472, 24.390, 24.792, 24.659) µs | 1.060 (1.071, 1.060, 1.060, 1.049) µs | 23.19× |
| `in_sim/mio_poll_wake_beside_idle/1` | 24.779 (26.047, 23.819, 24.471, 24.780) µs | 28.898 (28.516, 28.105, 29.709, 29.261) µs | 0.86× |
| `in_sim/mio_poll_wake_beside_idle/1024` | 327.668 (330.320, 334.440, 327.530, 318.380) µs | 29.790 (29.352, 29.687, 29.994, 30.125) µs | 11.00× |
| `in_sim/mio_poll_all_ready/1024` | 4.531 (4.509, 4.500, 4.538, 4.579) ms | 1.957 (1.952, 1.948, 1.969, 1.957) ms | 2.32× |
| `in_sim/udp_send_recv_beside_256_tcp_listeners` | 847.0 (838.0, 829.8, 856.4, 863.9) ns | 609.9 (630.3, 596.7, 597.0, 615.7) ns | 1.39× |
| `in_sim/tcp_connect_accept_close_beside_listeners/1024` | 4.209 (4.095, 4.243, 4.314, 4.183) µs | 3.328 (3.307, 3.392, 3.236, 3.378) µs | 1.26× |
| `in_sim/tcp_bind_listen_close_beside_listeners/1024` | 224.727 (232.260, 218.580, 228.870, 219.200) µs | 216.205 (227.460, 210.000, 214.970, 212.390) µs | 1.04× |
| `in_sim/udp_send_recv_loopback` | 582.4 (580.4, 594.1, 571.1, 583.9) ns | 602.6 (601.9, 606.1, 597.1, 605.2) ns | 0.97× |
| `in_sim/tcp_write_read_1k_loopback` | 307.4 (304.9, 305.9, 316.2, 302.8) ns | 305.0 (301.5, 307.4, 303.8, 307.2) ns | 1.01× |

The other 31 workloads stayed within 0.88–1.16×. The three- and eight-worker rings, native and simulated, moved by 0.99–1.01×; the two-thread rings, still bimodal in this VM, by 0.88–1.00×, with before and after runs each landing on both modes (`in_sim/handoff_condvar_ring/2` at 1.352 and 0.541 µs before, 0.543 and 1.610 µs after). `passthrough/sched_yield_outside_a_sim`, a native control, moved 1.16×. `mio_poll_wake_beside_idle/1` is 4 µs slower in all eight runs: a waiter is now woken through its port's key and takes one more look at the poll set per wake, on a round trip that is otherwise two VM wakes. `udp_send_recv_loopback` is 3% slower, about the 571–594 ns spread of its before runs.

Single waitable-timer calls, real time per call:

| Call | Before | After |
| --- | --- | --- |
| `thread::sleep(1 ms)`, plain | 29.96 (28.74–35.12) µs | 5.45 (5.41–14.51) µs |
| `thread::sleep(1 ms)`, `deterministic()` | 24.99 (24.65–32.51) µs | 5.05 (5.03–5.25) µs |
| create, set 1 ms, wait, close, plain | 30.22 (29.29–34.76) µs | 5.54 (5.22–6.07) µs |
| create, set 1 ms, wait, close, `deterministic()` | 25.43 (24.65–39.64) µs | 5.16 (5.02–5.20) µs |
| create, set 1 ms, close | 3.52 (3.46–3.82) µs | 2.65 (2.57–5.74) µs |
| create, close | 2.29 (2.25–2.53) µs | 2.33 (2.24–2.70) µs |
| `Sleep(1)`, no timer | 0.45 (0.45–0.48) µs | 0.45 (0.44–0.52) µs |

`cell_workload` now runs on Windows (below). Ten virtual seconds, four alternating runs per tree at load averages of 2.0–2.5, took 5.32–6.61 s of wall time before (mean 5.98 s) and 5.49–6.84 s after (mean 6.23 s): no change beyond the spread. Its 4,000 timestamps cost 1.3–1.7 ms of wall time each, which this pass does not address.

### Profiles

No profiler ships in the VM, so a throwaway one sampled the measuring thread from inside the probe process every 40 µs (`SuspendThread`, `GetThreadContext`, a walk of the ARM64 frame-pointer chain, `ResumeThread`), and `llvm-symbolizer` resolved the samples against the PDB on the Mac. Suspension slows the sampled thread severalfold, so the shares are of a distorted run, but they agreed with the call-by-call timings above. In a plain sim's `thread::sleep`, 31% of samples were in the clock's `WakeRunner::run`, handing the timer's waker to the `snare-timer-wakes` thread and waiting for it to come back, and 22% in `offer_idle_skip`, which found that waker pending and started a fresh `snare-idle-skip` worker thread for every sleep (`std::thread::Builder::spawn` alone 17%); the rest went to the timer's own system calls: creating and closing its event, resetting it on every set and probing it at every wait. A deterministic sleep spent 34% in the runner hand-off. Natively, an event's create and close cost 2.1–2.5 µs together and each other event call about 1 µs in this VM.

### What changed

A waitable timer's waker, registered with `Layer::register_owned_wake`, is marked as the interposer's own, and the clock runs a batch of such wakers on the thread that moved the clock instead of handing it to its runner thread. The waker signals the timer's event and takes the timer's and the census's locks, which no thread holds while it moves the clock; were one held, the runner would have waited on it too. While they run the thread counts as the clock's waker thread (`in_clock_wake`), so a periodic timer re-armed from its waker is listed without an owner, as before. A batch with any other waker goes to the runner as before.

A waitable-timer wait with an infinite timeout that runs its own time skip (a participant, no executive attached) no longer wakes the sim's waiters and offers its domain an idle skip as it parks (`native_wait_at_skipping`); its first skip that moves nothing does both (`notify_native_wait`). The skip that ends a lone sleep therefore starts no worker thread.

Each timer keeps whether its event may be signaled in an atomic word beside its state: set by every signal, cleared by a reset and by a wait seen to take the signal with nothing posted since, and set for good once one of its handles is closed. A wait skips its non-blocking probe of an event that cannot be signaled, and `SetWaitableTimer` skips `ResetEvent` when the event cannot be signaled and the handle was created with `TIMER_MODIFY_STATE`, the right the reset also checked. The word is read without the timer's lock: a probe runs under the census lock, and a signal takes the timer's lock before the census's.

On Windows, `crate::notices` now serves completion ports. A port's pending AFD polls live in a `PollSet` keyed by status block, each subscribed to its socket record's key. A refresh looks only at the polls notices marked, those on a socket that is new, connecting or holding a delayed arrival or error, and those whose socket is gone, and completes the ready ones in submission order, as the scan of every poll did. A blocking wait on a port listens to the port's key alone. Setting a socket's `SO_RCVBUF` or `SO_SNDBUF` posts a notice, as queuing an error on its record already did. The handle table counts its connecting sockets, so a refresh skips its connect sweep while there are none.

The Windows registry indexes its UDP bindings by port and counts the tester endpoints and tester listeners at each IP, so a datagram's candidate queues come from its port's bindings and station lookup is two hash lookups, as on Unix.

`mio_poll_wake_beside_idle` and `mio_poll_all_ready` drain each socket they read until it would block on Windows: Mio's Windows selector polls a socket again only then, so without it both hung there, before and after these changes. `cell_workload` runs on Windows, with `WSAPoll` for the device reactor and a connected UDP pair for the bus master's wake.

### Validation

The macOS workspace suite passed 1,580 tests with three ignores; `cmsg_os_truth`, which compares a foreign-source `IP_PKTINFO` send with the host's, failed once on the host's side and passed when rerun. The Linux workspace suite in Docker (`rust:latest`, aarch64) passed 1,982 with 24 ignores and one failure, `edge_scale_perf_guards::a_thousand_thread_spawns` (702 ms against its 520 ms debug-build bound, at a host load average near 40); no Linux code changed beyond the shared native-wait split. In the Windows ARM64 VM, all 297 test and example binaries of the final tree ran: 1,057 tests passed with no failures and six ignores. A new `windows_iocp` test polls 64 idle UDP sockets beside a listener in plain and deterministic sims, and checks that a zero-timeout poll reports nothing, that datagrams to two of them and a connection with its data are each reported, and that nothing else is. A first form of the signal tracking read the timer's state under its lock from inside a probe, which runs under the census lock, while a signal takes the two in the other order; `monotonic`'s clock-move hammers deadlocked on it in the VM, which the same sampler, pointed at the hung process, showed, and pass with the atomic word. Strict Clippy passed for the macOS workspace and for `snare` and `snare-interpose` on `aarch64-pc-windows-msvc` and `x86_64-pc-windows-msvc`, and formatting passed.

### What remains

A sleep still costs about 5 µs on Windows against 0.45 µs for `Sleep`: std creates and closes an event-backed timer for each, 2.3 µs of system calls in this VM, and the wait signals and takes that event, two more. Handing out events from a pool would save the create and close but would keep a closed handle open, so a double close, a wait or a duplicate on it would no longer fail as on Windows, and a pooled handle's protection and inheritance flags would carry over; it was not done.

Binds still scan on Windows: a TCP bind checks every socket and listener (`tcp_bind_addr`), an explicit UDP bind every datagram socket (`dgram_claims`), and an ephemeral UDP port every binding for each port it tries (`alloc_port`). A bind beside 1,024 listeners costs about 220 µs against 3 µs on Linux, and building 16,384 listeners makes `tcp_*_beside_listeners/16384` impractical to run there. The port index above could serve `alloc_port` and the bind checks; the binding code was left to the bind-semantics work under way.

`mio_poll_wake_beside_idle/1` is 4 µs (16%) slower, as above. Executive timestamps in `cell_workload` cost 1.3–1.7 ms of wall time on Windows. Windows x86_64 is unmeasured, and these numbers come from one shared host.

Artifacts are local, in `target/performance/win2/`: `r2/` holds the quiet round's probe, Criterion and `cell_workload` logs, `r3/` the socket rows' rounds, `r4/` wake round-trip probe runs, `r0/` and `r1/` the rounds under load, and the binaries they ran, each named for its tree. They are not repository fixtures.

```sh
cargo xwin bench -p snare --bench hooked_calls --bench cell_workload --no-run --target aarch64-pc-windows-msvc --cross-compiler clang
# in the VM, from a scratch directory:
hooked_calls-<hash>.exe --bench --noplot "^(passthrough|deterministic|lifecycle|testers)/|^in_sim/[^t]|^in_sim/t[^c]|^in_sim/tcp_[^bc]|beside_listeners/1024$"
cell_workload-<hash>.exe 10
```

## Windows completion-port wake, 2026-10-13

`mio_poll_wake_beside_idle/1` had become slower on Windows with the pass above. This pass finds where with an event trace and takes one system call off every round trip's critical path.

### Trace

A throwaway build (not kept) recorded each readiness bump, parker signal, park and wake, each check a woken waiter makes, the completion-port wait's loop, AFD poll submissions and completions, and the sim's `sendto`/`recvfrom`/`recv` calls into a fixed in-memory buffer, stamped with the ARM64 virtual counter (24 ticks/µs) and the thread id, and dumped after 8,000 round trips of the benchmark's workload (the second half traced). Each round has exactly one signal and one wake on each side: no extra or repeated wake. In medians, at host load averages of 8–20, a round splits into the echo thread's wake (12.9–14.5 µs from the poller's signal to its return from the parker), its work to its own signal (3.3 µs), the poller's wake (9.7 µs) and the poller's work from waking to its next send (5.5–6.1 µs). A signal (`Mutex` plus `WakeConditionVariable`) costs its sender 3.3–4.8 µs in this VM. Of the poller's work, 1.2–1.6 µs was its first check: it asked the real completion port (`GetQueuedCompletionStatusEx` with no wait) before looking at the sim's own state, and the port could not hold the completion yet, since the sim posts it only from the refresh that follows the check; that refresh then posts it and a second call takes it.

### What changed

A completion-port wait's checks look at the port's generation and at the AFD polls notices marked first, and ask the real port only when neither shows a change. Nothing else moved: a wait with nothing due still asks the port before it sleeps, and a zero-timeout wait never reaches these checks.

With the reordering the poller's median work after a wake fell from 5.4–6.1 to 4.4–4.7 µs in the trace, and traced rounds from 31.5–35.0 µs to 27.8–28.9 µs (means; the remaining time is the two VM wakes).

### Results

Criterion, run in the Windows 11 ARM64 VM of the passes above in alternating rounds at host load averages of 4.0–5.3 (the first two rounds; in a third, this tree's binaries ran 25–55% slower than in the first two and the window binaries did not, so it is left out of the table and kept in the logs). "Window before/after" are the previous pass's own before and after binaries; "this before" is this pass's tree without the change, "this after" with it.

| Workload | Window before | Window after | This before | This after |
| --- | --- | --- | --- | --- |
| `in_sim/mio_poll_wake_beside_idle/1` | 27.40 (27.76, 27.04) µs | 29.79 (29.70, 29.88) µs | 29.10 (29.15, 29.06) µs | 26.34 (26.17, 26.52) µs |
| `in_sim/mio_poll_wake_beside_idle/1024` | 330.7 (335.9, 325.4) µs | 30.32 (30.29, 30.36) µs | 30.26 (30.05, 30.47) µs | 26.62 (27.16, 26.08) µs |

The round trip is back below the window pass's before tree. `mio_poll_zero_timeout/1`, `/64` and `/1024` stayed at 1.08–1.18 µs in both trees but for one 1.36 µs round (two rounds at loads of 6–8). Windows x86_64 is unmeasured.

Artifacts are local, in `target/performance/a579/`: the four benchmark binaries, the logs of each round and the trace build's sources. They are not repository fixtures.
