# Hot-path benchmarks

Run `cargo bench -p snare --bench hooked_calls` on an otherwise idle host. The benchmark runs on Unix; its Windows entry point performs no measurements. Record the revision, Rust version, target, OS, CPU, and Docker or VM resource settings with each result. Run one measurement process at a time, without concurrent test suites or compilation.

## Timing and resources

Managed samples use `iter_custom` and read their elapsed time under `snare::real`. An `Instant` read by application code inside a simulation reads virtual time and cannot measure throughput. Each managed sample creates a fresh simulation. Simulation construction, entry, exit, and destruction are outside its stopwatch; the two lifecycle benchmarks measure construction/destruction and construction/run/destruction explicitly.

Application sockets, polling objects, mutexes, and testers are created inside `Sim.run`. Socket binding, connection establishment, and poll registration precede their hot-path stopwatches. The tester benchmark measures the client request/reply loop after its socket is bound, including any wait for tester startup and scheduling. It does not measure complete tester setup and teardown. Native oracle resources in any additional comparison must be created under `snare::real`; managed resources must remain inside the active simulation.

Criterion warms each benchmark for one second and measures for three seconds. Fresh simulation state does not imply a cold process: installed hooks, allocator state, worker initialization, and CPU caches can persist across samples and benchmark groups. The `passthrough` group installs hooks before measurement. Its results describe installed hooks with no active simulation, rather than a pristine unhooked native process. The lifecycle group also measures process-warm behavior. Measure initial hook installation and first-call costs separately in fresh processes.

## Workload interpretation

`in_sim/clock_gettime` retains its metric name but measures `Instant::now` plus one yield per 32 reads. Reads and yields increment the same clock-spin counter; yielding does not reset it. Managed samples therefore enter the caught-spin path after 64 combined events and include time advancement and scheduling checks. This workload measures sustained clock polling, rather than isolated ordinary clock reads. Use `passthrough/clock_gettime_with_yield_32_outside_a_sim` for the same operation mix outside a simulation. `passthrough/clock_gettime_outside_a_sim` measures reads without yields and cannot be subtracted directly from the composite managed figure. The OS API used by `Instant` depends on the platform.

`in_sim/mutex_2_threads_with_spawn_join` includes child creation and join, with exactly the requested number of lock operations split between parent and child. It does not guarantee contention: either thread can complete much of its work before the other runs. `deterministic/yield_2_threads_with_spawn_join` likewise includes creation/join and exactly the requested number of yields; its per-yield figure is not a measurement of a fixed number of baton transfers. A separate persistent-worker benchmark with an explicit barrier or handoff protocol is needed to isolate contention or scheduler handoff costs.

`time_skip_1ms_sleep` measures the real cost of a virtual sleep. Native one-millisecond sleeps perform a different wall-clock workload, so their ratio is not hook overhead. The uncontended mutex workload can stay on the standard library's atomic fast path and does not isolate blocking synchronization hooks. Empty Mio polls cover 1, 64, and 1024 registered sockets, without ready-event delivery or dynamic registration workloads.

Criterion coverage includes plain Sim workloads, two deterministic workloads, and installed-hook passthrough clock/yield calls. It does not provide matched native socket or synchronization baselines, SimHost workloads, capture-enabled workloads, Windows measurements, or broad deterministic networking coverage.

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

Timer cancellation now resolves a wake ID to its deadline under the existing table lock. Fired Native holds, foreign and deterministic delivery, pruning, tied swap-removal order, and destruction outside locks retain their behavior. This adds one reverse-map entry per registered asynchronous wake. The measured 8,000-timer registration cost increased from 145.6 to 188.8 ns per timer, while cancellation fell from 10,447 to 119 ns. Cancellation still scans wakers sharing one deadline; the distinct-deadline result does not establish performance for a large tied bucket. Native synchronous sleeps do not use this reverse index.

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

UDP destination candidates are indexed by port, and tester station addresses have IP reference counts. Replacements update both the canonical binding map and indexed queue references; alias close removes a binding only after its last descriptor closes. This adds one indexed queue reference per binding and port-bucket metadata. Single-address buckets keep their first binding inline. Candidate enumeration remains linear in the number of bindings sharing a destination port, and TCP tester/listener station lookup still scans listeners.

UDP send borrows the caller payload during the call. Every queued delivery, duplicate, delayed packet, capture, or error report that retains payload bytes still owns them before the call returns. The warmed caller-thread allocation fixture reports 12 allocations per UDP send/receive pair, down from 13, and zero for TCP write/read. Only the measured macOS UDP allocation budget was tightened; Linux's existing budget remains pending validation. Receive timeout lookup uses the already captured socket record, and nonblocking datagram receives skip timeout construction. Blocking calls still capture one timeout budget before the receive loop.

Single-iovec TCP `recvmsg` reads into the caller buffer directly, avoiding the staging allocation and extra copy. Multiple iovecs retain staging. macOS datagram `recvmsg` creates Mach timestamp payloads only when requested and moves the payload when just one Mach option is enabled. Realtime `timeval` serialization writes fields into zero-filled native-layout bytes so control-message padding is deterministic. Timestamp message ordering and native option behavior are covered by regression tests. Short `MSG_PEEK | MSG_WAITALL` reads return at EOF or a pending error without consuming queued bytes or the error; the wait predicate accounts for bytes still in flight before FIN.

The separate `recvmsg` comparison has 36 configurations and 360 samples, with no errors. Its baseline already includes the initial UDP indexes, borrowed UDP sends, and bulk TCP reads. The final executable additionally includes direct indexed queue references, receive timeout lookup changes, lazy macOS timestamp payloads, and direct single-buffer TCP receive. Its probe code is identical between executables. It therefore measures the remaining combined improvements rather than isolating any one change. The one-minute load average was 4.18 before and 4.25 after.

| Plain simulation workload | Before | Final | Speedup |
| --- | --- | --- | --- |
| UDP send + single-iovec `recvmsg`, 4 bytes | 776 (767–952) ns | 720 (704–793) ns | 1.08× |
| TCP write + single-iovec `recvmsg`, 1 KiB | 609 (597–610) ns | 545 (534–547) ns | 1.12× |
| TCP write + single-iovec `recvmsg`, 8 KiB | 887 (881–901) ns | 721 (700–727) ns | 1.23× |
| TCP write + two-iovec `recvmsg`, 8 KiB | 902 (866–1,072) ns | 865 (861–874) ns | 1.04× |

Validation: the workspace library/integration suite passed 1,303 tests with no failures and two existing hardware-dependent ignores. After the final index and timeout refinements, 107 focused unit/integration tests passed, including binding replacement identity, multicast, ICMP, 10,000-socket delivery, timeout behavior, and allocation budgets. Strict workspace/all-target Clippy, formatting, and diff checks passed on the final sources. All application resources in the new network tests are created under snare. Linux and Windows performance testing remains deferred.

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
