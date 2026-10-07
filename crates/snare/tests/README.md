# snare tests

How the integration tests of `crates/snare` (and the engine tests of `crates/snare-interpose`) are
organised, how to run them on each platform, which feature areas each platform covers, and what
a Windows run is expected to skip. For maintainers; the user-facing feature description is the
top-level `README.md`.

## Layout

Every `*.rs` here is its own test binary. Most run the code under test inside a `Sim` and assert
on what it observed; a test binary of its own is used whenever a test needs process-wide state to
itself (`dns_chains.rs`, `pcapng_env*.rs`, `signals_ctrlc*.rs`).

`support/` holds helpers pulled in with `#[path = "support/…"] mod …;`:

| Helper | For |
|---|---|
| `rawsock.rs` | Raw TCP calls one step at a time (`socket`, `setsockopt`, `bind`, `listen`) on unix and Winsock. |
| `netfault.rs` | Fault-test plumbing: `raw()` handles, host error codes (`code::*`), linger, buffers, a one-socket `poll`/`WSAPoll`, `IP_RECVERR`, `SIO_UDP_CONNRESET`. |
| `winsock.rs` | Windows only: `setsockopt`/`getsockopt` at any level, `ioctlsocket`, a synchronous `WSAIoctl`, `WSARecvMsg` (fetched through `SIO_GET_EXTENSION_FUNCTION_POINTER`), `WSASendMsg`, control-message building and walking, `QueryPerformanceCounter`. |
| `counters.rs` | The host's real protocol counters (`/proc/net/snmp`, `net.inet.udp.stats`, `GetUdpStatistics`/`GetTcpStatistics`). |
| `pcapng_reader.rs` | A minimal pcapng reader and TCP sequence checker for the capture tests. |
| `hw.rs` | The hardware tier's skip and environment helpers (see [Hardware tests](#hardware-tests)). |

## Naming

| Pattern | Meaning |
|---|---|
| `<area>.rs` | The feature on every platform the sim models it on; platform differences are small `#[cfg]` helpers or `cfg!` expectations inside the file. |
| `<area>_win.rs` | Windows only (`#![cfg(windows)]`): the Winsock/Win32 surface of a feature whose unix side lives in `<area>.rs`, or a Windows-only feature. |
| `demo_<area>_*.rs` | Walk-throughs of one API surface, usually one OS's (`demo_netlink_*`, `demo_sched_*` are Linux; `demo_macos_*` macOS). |
| `simhost_*.rs` | A `SimHost` (Linux, some macOS); there is no `SimHost` on Windows, whose host plane is `WinHost`. |
| `*_os_truth` (file or test) | The same calls on the real stack (`snare::real`) and in a sim, side by side, asserting equal outcomes. They need nothing but loopback and the current user's rights, so they mean the same on a VM and on real hardware, and pin the model to whatever OS runs them. |
| `*_on_windows`, `*_on_the_host` | Real-stack only: pins a measured host fact the sim is meant to reproduce (used where the sim side is not modelled yet). |
| `hw_*.rs` | The hardware tier: needs a NIC, a peer or privileges, and skips itself otherwise. |

Ignored tests always carry a reason. `"not modelled on Windows: …"` marks a sim gap a test already
describes; `"differs on purpose: …"` a deliberate divergence; `"needs …"` a real-OS check that
needs rights, hardware or environment the default run lacks.

Application coverage follows the usage invariant: every resource or object used by the code under
test is created under its active simulation, including dependency and worker initialization.
Passthrough is reserved for other-side emulation and the harness. Native comparison probes run
their own construction and operations in passthrough; their real objects are not handed to the
simulated application. Tests of pre-existing native objects or mixed native/model handles are
interposer robustness probes, rather than evidence of supported application behavior.

The outside-held std mutex fixture constructs its mutex inside `Sim::run` and lets a passthrough
harness thread hold it. Its Linux/Windows ownership gap remains distinct from objects constructed
outside the simulation.

## Running

All from the workspace root, with a private target directory when another build is running.

```console
# macOS (host)
cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets

# Linux, in OrbStack/Docker; the named volume keeps the Linux build apart from target/
docker run --rm -v "$PWD":/work:ro -w /work -v snare-lxtarget:/tmp/lxtarget \
    -e CARGO_TARGET_DIR=/tmp/lxtarget rust:latest cargo test --workspace --no-fail-fast

# Windows, cross-checked from macOS (no Windows machine needed)
cargo clippy -p snare -p snare-interpose --all-targets --target aarch64-pc-windows-msvc
cargo xwin test --no-run --no-fail-fast --target aarch64-pc-windows-msvc -p snare -p snare-interpose

# Windows, run in the Parallels VM "Windows 11" (SNARE_WINDOWS_VM overrides the name)
scripts/test-windows.sh aarch64-pc-windows-msvc
scripts/test-windows-host.sh            # just win_host.rs
```

The default Windows build excludes the Npcap cases in `pcap_raw_win` and `pcapng_npcap_win`.
Enable `hw-npcap` with the matching Npcap SDK and runtime installed to build and run them.
Npcap's installer does not complete on the ARM64 VM used here; those cases remain unverified.

The full Windows runner builds the workspace first, including the `interpose-probe` DLL required
by `windows_modules`. For a native Windows test run, build that fixture with
`cargo build -p interpose-probe` using the same target and profile before running the tests.

To see what a Windows run skips, run a binary with `--ignored`. Ignored tests include unsupported
paths and hardware fixtures; read their reasons before enabling a group.

## Parity matrix

✅ covered · ◐ partly (what is missing in the note) · ⛔ not modelled on that OS (tests ignored with
the reason, see [Windows gaps](#windows-gaps)) · — not applicable (no such OS surface) · ✗ modelled
but not covered by a test.

These marks describe test coverage, not execution evidence. Windows paths marked covered may
still be runtime-unverified; consult [Windows run triage](#windows-run-triage).

| Area | Test files | macOS | Linux | Windows | Notes |
|---|---|---|---|---|---|
| Virtual clock, time skip | `virtual_time`, `virtual_time_win`, `demo_clock_std_time`, `monotonic`, `time_rate`, `simhost_clock`, `demo_clock_*` | ✅ | ✅ | ✅ | QPC/`GetTickCount64`/`QueryUnbiasedInterruptTime`/file-time reads in `virtual_time_win`, `monotonic`, `win_host_os_truth`. |
| Clock spins | `clock_spin` | ✅ | ✅ | ✅ | |
| Tied timed waits | `timer_ties` | ✅ | ✅ | ✅ | Windows covers `WSAPoll` and the Mio IOCP pairing. |
| Native waits, quiescence | `native_waits`, `quiescence`, `quiescence_win`, `demo_tcp_quiescence`, `sem_waits` | ✅ | ✅ | ✅ | Scaled futex `WAIT_BITSET` (Linux) and `dispatch_semaphore` (macOS) only there; `sem_waits` covers Linux and Windows, not macOS named semaphores (✗). |
| Locks held outside the sim | `outside_locks`, `critical_sections_win`, `win_sync_shared` | ✅ | ✅ | ◐ | Windows shared/exclusive SRW locks and critical sections track known holders; raw condition-variable waits cover all three lock modes. A std `Mutex` held outside is only detectable on macOS (Linux/Windows words name no holder). |
| Windows waitable timers | `win_waitable_timers` | — | — | ✅ | Relative/absolute deadlines, periodic auto/manual signals, same-process aliases and access rights, extended sets, atomic timer-only any/all waits, concurrent clock moves and off-run cleanup. |
| Deterministic schedule | `deterministic` | ✅ | ✅ | ✅ | SimHost replay Linux only. |
| Stuck runs | `stuck` | ✅ | ✅ | ✅ | |
| Executive | `executive`, `executive_classes`, `executive_det`, `executive_simhost` | ✅ | ✅ | ✅ | `executive_simhost` Linux. |
| Thread classes, cooperative primitives | `thread_classes`, `sched_primitives` | ✅ | ✅ | ✅ | |
| Entropy, interposer engine | `snare-interpose/tests/{audit,clock,random}`, `variadic`, `windows_modules` | ✅ | ✅ | ✅ | `variadic` unix; `windows_modules` Windows. |
| TCP | `tcp`, `tcp_server`, `tcp_win`, `demo_tcp_testers`, `rcvtimeo` | ✅ | ✅ | ✅ | `SO_RCVTIMEO` gives `TimedOut` on Windows. |
| UDP | `udp_fabric`, `udp_win`, `udp_icmp`, `simhost_udp*` | ✅ | ✅ | ✅ | SimHost UDP Linux. |
| `MSG_PEEK` | `udp_fabric`, `tcp_win` | ✅ | ✅ | ✅ | |
| Truncated datagram | `udp_win` | ✗ | ✗ | ✅ | Windows `WSAEMSGSIZE`. |
| Testers | `testers`, `tester_chain`, `tester_conns`, `tester_framing`, `tester_arrivals` | ✅ | ✅ | ✅ | |
| Readiness syscalls | `kqueue_raw`, `mio_kqueue`, `mio_readiness`, `demo_tcp_mio`, `wsapoll_win`, `tcp_server` | ✅ | ✅ | ✅ | `WSAPoll`/`select` on Windows. |
| timerfd, raw descriptor syscalls | `timerfd` | — | ✅ | — | Expiry on the sim's clock bounds epoll and poll waits; `syscall(SYS_eventfd2)`/`SYS_epoll_*` reach the model; host-checked. |
| Process-wide reactors across sims | `async_io_reactor`, `process_local_fds` | ✅ | ✅ | ⛔ | Epoll sets, kqueues, eventfds and timerfds move to the next sim with the threads blocked on them; another sim's socket is `EBADF`. Tests sharing one take turns. |
| mio edge-triggered events | `mio_waker`, `backpressure`, `connect_faults`, `pcapng`, `windows_iocp` | ✅ | ✅ | ✅ | Windows supports Mio's single-socket, infinite, non-exclusive AFD poll profile; wakeups, edges, backpressure and connection errors run by default. |
| Socket faults, back-pressure | `faults`, `backpressure` | ✅ | ✅ | ✅ | |
| Connect faults | `connect_faults` | ✅ | ✅ | ✅ | |
| Socket table | `socket_table`, `socket_table_win` | ✅ | ✅ | ✅ | |
| Socket limits, buffers | `socket_limits`, `socket_limits_win`, `os_parity`, `tcp_buffers`, `tcp_buffers_os_truth` | ✅ | ✅ | ✅ | |
| Bind rules | `bind_os_truth` | ✅ | ✅ | ✅ | |
| Winsock call codes and options | `winsock_os_truth` | — | — | ✅ | Wrong-state codes, `SOL_SOCKET` and other-level defaults and round trips, unbound `getsockname`, `WSARecvMsg`/`WSASendMsg` on TCP. |
| Privileges | `privileges`, `os_parity` | ✅ | ✅ | — | No reserved ports or capabilities on Windows. |
| Process limits | `rlimits`, `nic_adapter_props_win`, `win_host_os_truth` | ✅ | ✅ | ✅ | Windows: working-set bounds and process-handle type/access checks. |
| Multicast | `multicast`, `multicast_os_truth` | ✅ | ✅ | ✅ | `IP_MULTICAST_ALL` Linux only. |
| Don't-fragment | `dontfrag`, `dontfrag_win` | ✅ | ✅ | ✅ | `IP_DONTFRAGMENT`, `IPV6_DONTFRAG`, `IP_MTU_DISCOVER`. |
| Packet timestamps | `timestamps`, `timestamp_startup`, `demo_udp_timestamping`, `simhost_*`, `timestamps_win` | ✅ | ✅ | ✅ | Linux configurable software RX startup, arrival-time eligibility and legacy datagram fallback; Windows `SIO_TIMESTAMPING`/`SO_TIMESTAMP`/`SIO_GET_TX_TIMESTAMP`, in the sim only; one real code pinned. |
| Unmodelled options, strict mode | `strict_sockopts` | ✅ | ✅ | ✅ | Real Winsock codes pinned by `unknown_option_codes_on_windows`. |
| Interfaces and routing | `nic_routing`, `nic_link`, `nic_policy`, `nic_bind_device`, `nic_os_truth` | ✅ | ✅ | ✅ | |
| Interface enumeration | `nic_enumeration`, `demo_nic_*`, `nic_iphlpapi_win`, `nic_os_truth` | ✅ | ✅ | ✅ | Windows `GetAdaptersAddresses` shape against the host in `nic_os_truth`. |
| NIC tuning | `simhost_ethtool`, `simhost_nic*`, `simhost_macos_sysctl`, `nic_adapter_props_win` | ◐ | ✅ | ✅ | macOS: `sysctl` only. |
| Netlink | `demo_netlink_*`, `simhost_netlink`, `simhost_genetlink` | — | ✅ | — | |
| Protocol counters | `proto_counters`, `proto_counters_os_truth` | ✅ | ✅ | ✅ | |
| Names | `dns`, `dns_chains`, `dns_win` | ✅ | ✅ | ✅ | |
| Signals, console control | `signals`, `signals_ctrlc*`, `signals_forward_real`, `signals_signal_hook`, `signals_win` | ✅ | ✅ | ✅ | `signal-hook` is unix only. |
| Recorded events | `recorded_events` | ✅ | ✅ | ✅ | |
| Packet capture | `pcapng`, `pcapng_env*`, `simhost_pcapng`, `pcapng_npcap_win` | ✅ | ✅ | ✅ | npcap capture needs `wpcap.lib`. |
| Raw L2 | `bpf_l2`, `demo_bpf_*`, `raw_l2`, `pcap_raw_win` | ✅ | ✅ | ◐ | npcap is structural; needs Npcap to link and run. |
| Host scheduling | `demo_sched_*`, `demo_macos_*`, `simhost_rt`, `simhost_macos_rt`, `win_host`, `win_host_os_truth` | ✅ | ✅ | ✅ | Windows priorities, affinity, duplicate/pseudo handle identity, a 119-call access/error matrix and isolated process/thread background transitions against Windows 11 build 26200.9457 in `win_host_os_truth`. Background comparisons include class changes, overlaps, inherited threads and priorities −16 through 16. |
| Timer resolution | `demo_clock_cpu_dma_latency`, `win_host_os_truth` | — | ✅ | ✅ | Period requests and unmatched releases compared with Windows. |
| `socketpair(AF_UNIX)` | `socketpair` | ✅ | ✅ | — | |
| Virtual files | `virtual_fs`, `demo_vfs_*`, `fs_descriptor_ops`, `fs_live_contents`, `fs_path_ops`, `fs_path_resolution` | ✅ | ✅ | ⛔ | Windows file APIs reach real process state. |
| Environment | `env_and_real`, `demo_env_*`, `demo_real_escape` | ✅ | ✅ | ⛔ | Windows environment APIs reach real process state. |
| `SimHost`, `HostProfile`, `EasyBuilder` | `simhost_*`, `easy_builder`, `demo_easy_presets`, `time_control` | ◐ | ✅ | — | `WinHost` instead. |
| Wall-clock controls | `time_rate`, `virtual_time_win` | ✅ | ✅ | ✅ | Plain wall clock uses real time and refuses controls; explicit rates provide a controllable clock. |

## Windows gaps

What the Windows backend does not model, each with the tests that describe it:

| Gap | Effect | Tests |
|---|---|---|
| Other IOCP/AFD variants | Multi-socket, finite and exclusive AFD polls, alertable modeled-port waits, modeled port/helper aliases and mixed native/modeled port traffic are explicitly unsupported. Mio's single-socket infinite non-exclusive profile and non-alertable completion waits are modeled. | `windows_iocp` covers native packet/status/byte-count comparisons, virtual deadlines, native passthrough and dynamic interests; `mio_waker`, `timer_ties`, `backpressure`, `connect_faults` run by default. |
| Overlapped and notified I/O on a sim socket | Overlapped `WSARecv`/`WSASend`/`WSARecvMsg`/`WSASendMsg`/`WSAIoctl`, `WSAEventSelect`, `WSAAsyncSelect`, `AcceptEx`, `TransmitFile`, `WSAJoinLeaf`, `WSAConnectByName`/`ByList`, and the `ConnectEx`/`AcceptEx`/`DisconnectEx`/`TransmitFile`/`TransmitPackets`/`GetAcceptExSockaddrs` extension pointers fail with `WSAEOPNOTSUPP`; `select`/`WSAPoll` over sim and real sockets together likewise. | none |
| Control messages other than timestamps | `IP_PKTINFO`/`IPV6_PKTINFO`, `IP_RECVTTL`, `IP_RECVTOS`, ... are kept and listed as unmodelled, but `WSARecvMsg` returns no such message. `WSASendMsg` rejects non-timestamp control messages with `WSAEOPNOTSUPP` before sending. | `timestamps_win::unsupported_outbound_control_messages_fail_without_sending` |
| Holder of a std `Mutex` | Its `WaitOnAddress` word names no holder (as the Linux futex), so a waiter on one held outside the sim counts parked. | `outside_locks::a_std_mutex_held_outside_the_sim_holds_time_still` (also ignored on Linux) |
| Foreign scheduling objects, actual realtime-class behavior | Foreign process/thread objects return `ERROR_NOT_SUPPORTED` (50). Tracked threads retain a native handle until `WinHost` drops. Actual realtime thread/background priority interactions remain unmeasured: the unelevated VM accepts the request but reports HIGH priority. | `win_host_os_truth` covers current-process aliases, access/error validation, background transitions and the explicit foreign-process boundary; elevated realtime-class parity tests needed. |
| Waitable timer variants | `CreateWaitableTimerW/A` and `CreateWaitableTimerExW/A` share the timer model; native comparisons cover all four creation APIs in manual/auto-reset modes and extended-API access rights. Named/security attributes, APC/resume/reason contexts, cross-process aliases, alertable timer waits and blocking mixed-object waits are explicitly unsupported. Relative/absolute periodic timers, local aliases and timer-only any/all waits have native comparisons. Tolerable-delay requests use exact deadlines rather than host coalescing. | `win_waitable_timers` |
| Files, environment | No Windows hooks; calls reach real process state. | No Windows API parity tests yet. |

## Windows run triage

The workspace builds for `aarch64-pc-windows-msvc`. The recorded full pass covered 272 default
test and benchmark binaries on Windows 11 ARM64 (10.0.26200.9457), with 844 tests passing, zero
failing and 7 ignored. The clock-spin suite includes regressions for
joining an already-finished thread after a caught yield spin, participant admission and pending
native timer wake receipts. Fresh-process repetitions passed 200 clock-spin suites and 100
TCP/UDP arrival suites with their exact virtual-time assertions unchanged.

Runtime coverage includes the socket, timer, scheduler, executive, signal, DNS, adapter,
packet-capture and native-wait branches enabled by the default build. These establish the
exercised cases on that VM; they do not certify every hook, hardware path or Windows version.
Npcap paths require a separate feature build with a matching SDK and installed runtime.

Ordinary Windows std sleeps use the OS 100 ns timer grid, and finite synchronization
timeouts use a millisecond wait argument. Overflowing Rust sleep durations retain their full
finite duration before clock saturation. Clock snapshots may retain finer internal precision.

**Expected ignored** — hardware fixtures requiring a NIC, PHC, peer or mutation opt-in; the
private Linux network-namespace probe and manual absent-neighbour calibration described below;
the Linux process-global `environ` pins; and the outside-held std mutex pin on Linux and Windows.
The real loopback-refusal calibration runs normally on all three platforms.

See `OPEN_BUGS.md` for measured gaps and model boundaries.

## Hardware tests

Three tiers check the model against reality:

| Tier | Runs | Compares the sim with |
|---|---|---|
| unit / sim | every `cargo test` | the behaviour the tests spell out |
| `*_os_truth` | every `cargo test` | the build host's own stack on loopback, with the current user's rights |
| hardware truth, `hw_*.rs` | host-only comparisons run normally; device and peer comparisons use `--include-ignored hw_` | a real NIC and its driver, a PHC, a second machine on the wire, real privileges, the host's kernel configuration |

Tests that require a NIC, PHC, peer or hardware mutation remain `#[ignore = "hardware: ..."]`.
Host-only Linux socket-buffer, transmit-time and scheduler comparisons and Windows UDP-statistics
error-code comparisons run in a plain `cargo test`. These compare the privileges and capabilities
the process actually has; they do not require successful privileged operations.
Run with `--include-ignored hw_`, a test that finds its hardware missing returns early through
`support/hw.rs`'s `require!`/`need!`, printing `skipped: needs X (set SNARE_HW_...)` and appending
the line to the `SNARE_HW_REPORT` file; libtest still shows it as `ok`, so the runners fold the
skips into their report. A hardware test builds its sim from what it reads off the real machine
(`hw::linux::nic_profile` turns the real `ethtool` answers into a `snare::Nic`; the Windows tests
build an `Adapter` and a `NicSpec` the same way), runs one probe under `snare::real` and in that
sim, and asserts equal answers. What the model cannot express is reported with `hw::note`, not
failed.

### Running

```console
# Linux, on the machine under test (builds as you; --sudo runs only the test binaries as root)
scripts/test-hardware.sh --dry-run                       # what it found, what it would touch
scripts/test-hardware.sh --iface enp3s0                   # read-only
scripts/test-hardware.sh --iface enp3s0 --peer 10.0.0.2 --mutate --sudo
# the second machine, for --peer
scripts/test-hardware.sh --reflector

# Windows (PowerShell; elevated for the tests that need administrator rights)
scripts\test-hardware.ps1 -Adapter "Ethernet 2" -Npcap
scripts\test-hardware.ps1 -Adapter "Ethernet 2" -Mutate
scripts\test-hardware.ps1 -Reflector
```

The runners print the machine's facts and exactly what will be changed, run the `hw_*` binaries
one test at a time (`--test-threads=1`), and write `target/hardware-report.txt` (passed, failed
with the assertion, skipped with the reason, notes) beside the full log, exiting non-zero on a
failure. By hand: `SNARE_HW_IFACE=enp3s0 cargo test -p snare --test 'hw_*' -- --include-ignored hw_ --test-threads=1`.

| Variable | Meaning | Default |
|---|---|---|
| `SNARE_HW_IFACE` | the Linux NIC under test | the first `/sys/class/net/*` with a `device` link, not wireless, carrier up first |
| `SNARE_HW_PTP` | its PTP clock | `/dev/ptp<phc_index>` from the NIC's `ETHTOOL_GET_TS_INFO` |
| `SNARE_HW_PEER` | `ip[:port]` of a second machine running the reflector | none: peer tests skip |
| `SNARE_HW_MUTATE` | `1` lets tests change settings, each restored afterwards | off: nothing is changed |
| `SNARE_HW_WIN_ADAPTER` | the Windows adapter's alias | the first Ethernet adapter that is up |
| `SNARE_HW_NPCAP` | `1` when npcap is installed | `%SystemRoot%\System32\Npcap\wpcap.dll` exists |
| `SNARE_HW_REPORT` | file the skips and notes are appended to | none (the runners set it) |
| `SNARE_HW_REFLECT`, `_PORT`, `_SECS` | run `hw_peer_reflector` on the peer, its port, its idle limit | off, 47000, 600 s |

Privileges: reading `ethtool`, `SIOCGHWTSTAMP` and the sysfs facts needs none; `/dev/ptp*` is
usually root-only; every change (`ETHTOOL_S*`, `SIOCSHWTSTAMP`, qdiscs) needs `CAP_NET_ADMIN`;
`hw_rt_truth` compares whatever the runner holds (`CAP_SYS_NICE`, `CAP_IPC_LOCK`, `RLIMIT_RTPRIO`,
`RLIMIT_MEMLOCK`), so run it once as root and once as the user the program runs as.
`hw_ethtool_setters_need_net_admin` runs only without `CAP_NET_ADMIN`. On Windows the adapter
write and restart need an elevated token.

### Network-namespace fixtures

`nic_os_truth::linux_netns_ground_truth` creates its own network namespace before adding a dummy
interface. It requires `CAP_SYS_ADMIN`, `CAP_NET_ADMIN` and `iproute2`, so it remains ignored by
the unprivileged default run. A disposable Docker container supplies these capabilities without
changing the host's interfaces or routes:

```console
docker build -t snare-netns - <<'DOCKERFILE'
FROM rust:1.98
RUN apt-get update && apt-get install -y --no-install-recommends iproute2
DOCKERFILE

docker run --rm --cap-add SYS_ADMIN --cap-add NET_ADMIN --security-opt seccomp=unconfined \
    -v "$PWD":/work:ro -w /work -v snare-lxtarget:/tmp/lxtarget \
    -e CARGO_TARGET_DIR=/tmp/lxtarget snare-netns \
    cargo test -p snare --test nic_os_truth linux_netns_ground_truth -- --ignored --exact --nocapture
```

`connect_faults::real_os_on_link_absent_calibration` needs an interface and an address known to
be absent on its subnet. The following fixture creates both inside another private namespace;
`test1` has no IP address, so no neighbour can answer for `10.77.0.233`. Loopback must be up for
the local failure indication to reach the connecting socket. The optional `TCP_SYNCNT` setting
bounds SYN retries. Build dependencies are downloaded before entering the namespace, which
has no external connectivity. This calibration prints the errno and elapsed time rather than
asserting a universal timeout:

```console
docker run --rm --cap-add SYS_ADMIN --cap-add NET_ADMIN --security-opt seccomp=unconfined \
    -v "$PWD":/work:ro -w /work -v snare-lxtarget:/tmp/lxtarget \
    -e CARGO_TARGET_DIR=/tmp/lxtarget snare-netns sh -eu -c '
        cargo test -p snare --test connect_faults --no-run
        unshare -n sh -eu << "NETNS"
        ip link set lo up
        ip link add test0 type veth peer name test1
        ip addr add 10.77.0.1/24 dev test0
        ip link set test0 up
        ip link set test1 up
        SNARE_ON_LINK_IF=test0 SNARE_ON_LINK_ADDR=10.77.0.233:80 SNARE_ON_LINK_SYN_RETRIES=2 \
            cargo test --offline -p snare --test connect_faults real_os_on_link_absent_calibration -- --ignored --exact --nocapture
NETNS
    '
```

Both fixtures have passed in this disposable setup; the absent-neighbour probe returned
`EHOSTUNREACH` after about 3.1 seconds. Neither requires a physical NIC or a free address on the
machine's real network. Hardware mutations require the explicit `--mutate`/`SNARE_HW_MUTATE=1`
opt-in above. They restart adapters or change timestamp settings and qdiscs, so use dedicated
test interfaces.

### What each file proves

| File | Needs | Proves |
|---|---|---|
| `hw_ethtool_truth` | NIC; `--mutate` + `CAP_NET_ADMIN` for the changes | Every read-only `SIOCETHTOOL` answer (`GDRVINFO`, `GLINK`, `GRINGPARAM`, `GCOALESCE`, `GCHANNELS`, `GPAUSEPARAM`, `GEEE`, `GFLAGS`, `GET_TS_INFO`, `GSSET_INFO`, `GSTRINGS`) is identical from the real driver and from a sim `Nic` built from it: layouts, derived fields (`eee_active`, link, `n_stats`) and `EOPNOTSUPP` for missing operations. Without the capability every setter is `EPERM`. With `--mutate`: ring resize and out-of-range `EINVAL`, unsupported coalescing field `EOPNOTSUPP` (the supported set comes from ethtool netlink `COALESCE_GET`), channel limits, pause/EEE round trips and refused EEE modes. |
| `hw_timestamping_truth` | NIC; peer; `--mutate` or ptp4l for hardware stamps | `SIOCGHWTSTAMP` result; `SIOCSHWTSTAMP` sequences (filter widening, `ERANGE`, bad flags) and read-back; `BIND_PHC` errors; datagrams through the NIC to the peer and back with software, then hardware, stamps: `POLLERR`, every error-queue entry's control messages, filled `scm_timestamping` slots, `sock_extended_err` (origin, info, `OPT_ID` key), `OPT_TSONLY`, and the echo's receive stamps. |
| `hw_ptp_truth` | readable `/dev/ptpN` | `PTP_SYS_OFFSET` (incl. 0 and past `PTP_MAX_SAMPLES`), `PTP_SYS_OFFSET_PRECISE`, `PTP_SYS_OFFSET_EXTENDED`, `PTP_CLOCK_GETCAPS` succeed or fail alike and fill the same slots in order; `clock_gettime`/`clock_getres` on the dynamic clock id (`FD_TO_CLOCKID`), on a closed fd, and opening a missing clock. The sim's clock takes the real one's `PTP_CLOCK_GETCAPS`. |
| `hw_txtime_truth` | any Linux for `SO_TXTIME`; NIC + `--mutate` + `CAP_NET_ADMIN` for `etf` | `SO_TXTIME` validation, privilege and read-back, `SCM_TXTIME` sends; `etf` parameter errors at the root, `mq`, offloaded `etf` per transmit queue (the sim is given the queues the driver accepted, so what is compared is every other step and each refused queue's errno), the qdisc table, and the default put back (`noqueue` on an `IFF_NO_QUEUE` device such as veth, which the sim's NIC is marked as when the real root starts as `noqueue`). |
| `hw_rt_truth` | any Linux; root on an RT host for the interesting gates | CPU sets, `/sys/kernel/realtime`, `nproc`, affinity and governor as the host renders them; the RT setup sequence (FIFO/RR priorities, `pthread_setschedparam`, pinning, `setpriority(-20)`, `mlockall`, `/dev/cpu_dma_latency`) run in a forked child vs a `SimHost` built from the host, and that the sim never touched the real scheduler. `sched_setattr` is not modelled and not called. |
| `hw_sockbuf_truth` | any Linux; peer for the wire tests | `SysLimits::from_real_host` against `SO_RCVBUF`/`SO_SNDBUF`/`*FORCE` rounding (notes where the host departs from the stock table); the receive-buffer charge of datagrams that came back through the NIC (driver buffers, IP fragments) and a flood's admitted count and `SO_RXQ_OVFL`. |
| `hw_peer_reflector` | `SNARE_HW_REFLECT=1` | The peer's UDP echo (IPv4, and IPv6 where it binds separately). |
| `hw_win_adapter_truth` | Windows adapter; elevation + `-Mutate` to write | The SetupAPI walk from alias to device node, `DriverVersion`, the standardized keywords' values and `Ndi\Params` maxima, write access, against an `Adapter` built from them; with `-Mutate` a property write, `CM_Disable/Enable_DevNode` codes, the link after the restart and the read-back (restored). |
| `hw_win_iphlp_truth` | Windows adapter | `GetAdaptersAddresses` sizing and the fields the model fills, `GetIfEntry2`/`GetIfTable2` rows, the unknown-LUID code, `GetUdpStatistics(Ex/Ex2)` codes per family. |
| `hw_win_npcap_truth` | npcap; `--features hw-npcap`; `-Mutate` to send | Opening `\Device\NPF_{GUID}` and a bogus device, `sendpacket` and send queues (`SendSync` off and on) and which frames loop back. The file is `#![cfg(all(windows, feature = "hw-npcap"))]`: the `pcap` crate links `wpcap.lib` from the npcap SDK, which a default Windows build does not have; the runner turns the feature on when `wpcap.dll` is present. |

Windows 11 ARM64 VM runs have exercised `hw_win_udp_statistics_codes_match`,
`hw_win_adapters_addresses_match`, `hw_win_if_rows_match` and
`hw_win_adapter_reads_match_the_model`. The wired-adapter guards remain because those fixtures
are not guaranteed on other machines. Adapter mutation and Npcap paths remain unverified on
that VM. Linux device comparisons have also run in Docker against a veth interface and a peer;
this does not establish physical NIC, driver or PHC parity.

### Known gaps (failing on purpose until modelled)

None at present against a veth pair and the OrbStack 7.0 kernel. The five found there (`SO_TXTIME`
and `SCM_TXTIME` validation, `POLLERR` for a `SimHost` socket's transmit stamp, `SIOCGHWTSTAMP` on
a NIC without hardware timestamping, `mq` going by the queues allocated rather than those in use,
and the receive-buffer charge of a datagram that arrived as IP fragments) are modelled, each pinned
by a sim-only test as well (`simhost_txtime`, `simhost_udp`, `simhost_hwtstamp`, `simhost_qdisc`).

Predicted from the model and not yet seen on hardware, so possibly divergent on a real NIC:

- `Nic::register_dump_len`, `eeprom_len` and `private_flags_count` configure driver-info metadata
  (zero by default); register/EEPROM contents and private-flag operations are not modelled.
  `Nic::carrier` represents an unknown-but-up interface, pinned across topology, sysfs,
  rtnetlink, `getifaddrs` and `GLINK` by `simhost_nic_topology`.
- The transmit queues a driver allocated are taken from `ETHTOOL_GCHANNELS`' maxima; a driver that
  allocates more (igb: `IGB_MAX_TX_QUEUES`) lists the same qdiscs but accepts a qdisc on a class
  past its channel maximum, which the sim refuses (`ENOENT`) unless the profile sets
  `Nic::tx_queues_allocated`.
- A datagram that arrived as fragments is charged the sum of its fragments' buffers, as veth
  measures; a driver whose receive buffers are page fragments may coalesce fragments on reassembly
  (`skb_try_coalesce`) and charge less, and IPv6 fragments are unmeasured.
- `SIOCSHWTSTAMP` profiles can reproduce measured driver results with `Nic::hwtstamp_rx_mapping`.
  Requests without an explicit mapping use inferred widening from `ETHTOOL_GET_TS_INFO`, which
  can differ from the driver. A NIC's hardware stamp is its PHC at the send or arrival, with none
  of a real one's latency. UDP PTP filters check version and event, Sync or Delay_Req fields in
  payloads of at least 34 bytes on port 319; NTP filtering uses port 123. This is a synthetic
  packet classification policy, rather than a copy of a NIC's parser. One-step modes suppress
  hardware error-queue reports for classified UDP Sync/Pdelay_Resp messages, but do not insert
  packet timestamps or update correction fields and checksums.
- `PTP_ENABLE_PPS` stands root in for `CAP_SYS_TIME`; `PTP_EXTTS_REQUEST`, `PTP_PEROUT_REQUEST`
  and the pin requests check only the core's rules and the channel count, not the driver's flags.
  `hw_ptp_truth` builds its sim from the real clock's `PTP_CLOCK_GETCAPS`; whether the driver has
  `gettimex64` (for `PTP_SYS_OFFSET_EXTENDED`) is assumed.

### First run on real hardware

1. Build and check discovery: `scripts/test-hardware.sh --dry-run`. Confirm the NIC, its driver,
   the PTP clock and the kernel (PREEMPT_RT?) are the intended ones; set `--iface`/`--ptp` if not.
2. Stop anything managing the NIC's timestamping (ptp4l, phc2sys) or note that
   `hw_hwtstamp_get_matches` will skip, and that the hardware exchange then uses its settings.
3. Read-only pass as the user: `scripts/test-hardware.sh --iface IF`. Expect `hw_ethtool_setters_need_net_admin` to run here.
4. Read-only pass as root: add `--sudo` (PTP, RT gates, `cpu_dma_latency`).
5. On the second machine: `scripts/test-hardware.sh --reflector` (open UDP 47000 in its
   firewall), then add `--peer <its address>` here.
6. Only on a machine whose link may drop briefly: add `--mutate`. Afterwards check `ethtool -g/-c/-l/-a`,
   `hwstamp_ctl -i IF` and `tc qdisc show dev IF` read as before the run (the report's log has the
   saved values).
7. Repeat on another driver family (e.g. igb, igc, e1000e, ixgbe, mlx5, stmmac): the model is
   checked per driver, and fast-talker must work across them.
8. Windows: `scripts\test-hardware.ps1 -Adapter ...` from an elevated shell, then with `-Npcap`
   on an x64 machine with Npcap, then `-Mutate`.
9. File each failure as a model gap with the report: the assertion names the call and both answers.

## Behaviour pins for the performance pass

Tests written ahead of the performance pass to pin exact results, so an optimisation cannot change
semantics unnoticed. Goldens live in `golden/` and are rewritten with `SNARE_BLESS=1` (see
`support/golden.rs`). Allocation budgets (`perf_budget_*`) and the coarse real-time guards run
in the default Unix suite. The guards retain their calibrated bounds and have passed the full
macOS and Linux suites at normal test concurrency. The benchmark baseline and how to compare
against it are in `../benches/README.md`.

| File | Pins |
|---|---|
| `edge_scale_sockets` | 10 000 UDP sockets: ids 1…10 000 in creation order, table order, closed-socket order, ids never reused, one datagram to each reaches only it (UDP counters exact); ephemeral UDP ports lowest-free from 49152, per address; 2 000 TCP connects queue unbounded and are accepted FIFO, client ports sequential, accepted ids after the clients. |
| `edge_scale_fd_limit` | Own binary: with `RLIMIT_NOFILE` 300 past what the process holds, exactly 300 sockets open, the next `socket` is `EMFILE` (UDP and TCP), failures take no id or table row, a close frees a slot. |
| `edge_scale_datagrams` | 10 000 × 100-byte datagrams at an unread socket: delivered/overflowed/drops exact per OS (Linux 221, macOS 4 099 admitted), the first sent kept in order, `UdpCounters` exact, the read time exact; with `enforce_rcvbuf` off all queue in order; a recording tester takes all 10 000 in order. |
| `edge_scale_tcp` | 16 MiB across a 1 ms link: FNV-1a intact, exact virtual time per OS, with exact segment counts under `deterministic()`; plain byte/time checks; a 64 KiB receive window's exact longer time; a 4 MiB two-way echo's exact time. |
| `edge_scale_readiness` | 2 000 sockets on one `mio::Poll`: each reported exactly once per edge, 32 full batches of 64, a new datagram is a new edge; Linux level-triggered epoll reports all 2 000 on every wait. |
| `edge_scale_timers` | 20 000 `sleep_until` futures over 200 tied instants: each fires 1 ns past its deadline, one poller wake per instant, ties in registration order (plain and `deterministic()`); a default-run 100 000-future stress pin over 1 000 tied instants; 1 000 sleeping threads wake 1 ns past their deadlines, deterministic order golden. |
| `edge_scale_threads` | 1 000 condvar waiters all wake from one `notify_all` with no virtual time passing, deterministic order golden and replayed; lineage ids of a 300-deep chain and a 10×10×10 tree distinct, schedule-independent, golden; the executive lists 1 000 blocked participants and one `jump_to` fires all 1 000. |
| `edge_scale_testers` | 200 UDP echo testers each answer once with one `Received`/`Sent` logged each, deterministic answer order and log golden; 100 TCP line-echo testers × 20 lines echoed in order with exact event counts. |
| `edge_scale_routes` | 250 interfaces indexed 2…251 with `sim0` last; 10 000 overlapping routes: 1 000 lookups match a longest-prefix/metric/age model and a golden; removing half moves exactly 595 lookups; a datagram leaves by the looked-up interface. |
| `edge_scale_golden` | A 16 000-step, 8-thread `deterministic()` run of yields, sleeps, locks, condvar handoffs and UDP: replays in-process, FNV-1a hash, final time and per-kind counts golden per OS. |
| `edge_scale_counts` | Counts, not wall time: N sleeps take exactly N executive jumps of one timer each, no outside wakes; 10 000 sleeps move the clock exactly 10 000 × (1 ms + 1 ns); at 100 000 calls an empty receive and `poll(0)` cost exactly 1 µs each, send+recv, locks and yields nothing. Linux checks zero readiness wakes from unrelated socket traffic and a separate idle-waiter context-switch budget. |
| `edge_scale_alloc` | Own binary with a counting global allocator: allocations per hooked call (clock read, yield, empty recv, `poll(0)`, UDP/TCP round trip, mutex, time skip, spawn+join) against budgets of today's value + 25 % + 1 (today: `poll(0)` 3, UDP send+recv 13, spawn+join overhead 2 after subtracting the native baseline, the rest 0). |
| `edge_scale_perf_guards` | Nine default-run Unix guards: real-time bounds of 10× the measured debug time for 100k yields/empty receives/clock reads, 20k UDP round trips, 10k time skips, 1k spawns, 10k explicit and 1k ephemeral binds, 100 sims. |
| `edge_net_tcp` | TCP edges (unix): zero-length send/recv, partial-write sizes past both buffers per OS rule, all 36 orders of `SHUT_WR`/`RD`/`RDWR` on either end (golden per OS), simultaneous close, read after EOF, linger 0, 600 small writes byte-exact across random reads, `MSG_DONTWAIT`, nonblocking connect `EINPROGRESS`→`SO_ERROR` at the SYN plan's end, bounded listener backlog and repeated listen capacity, fd reuse without stale options or record, `try_clone`/`F_DUPFD` (shared `O_NONBLOCK`, descriptor-local `FD_CLOEXEC`), exact `SO_RCVTIMEO`/`SO_SNDTIMEO` deadlines. |
| `macos_tcp_read_shutdown*` | Exact native/plain/deterministic comparisons for receive-buffer flushing, read-shut incoming-data resets, queued bytes before reset, `MSG_PEEK`/`SO_ERROR` consumption and kqueue EOF errors; Unix socket-pair control. Paused-clock tests pin local close at data arrival and peer reset after reverse latency, including pre-shutdown flights, late inspection, prior FIN and directed quiesce windows with shortened replacements. Outside-sim inspection uses the connection’s clock. A scaled-clock receive checks timer wake delivery; captures require the receiver's reset instead of an ACK at the original arrival stamp. Simulated application sockets are constructed inside their active simulation; passthrough is confined to native oracles and capture inspection. |
| `win_listener_backlog` | Native Winsock and plain/deterministic completed-queue capacities for backlogs 0–3; repeated listen preserves the first capacity. |
| `tcp_error_queue_segments` | Linux native/Fabric/SimHost IPv4 TX-report payload, byte key and receive-memory charge across four large writes and five locked receive-buffer sizes; pending final segments produce no report before reads, including sends before accept after delayed SYN retries. |
| `error_queue_limits` | Linux native report charges, capacity and release; ordinary UDP/TCP data shares the receive-memory budget with ICMP and timestamp reports, and a partial TCP read retains its segment's memory. |
| `edge_net_udp` | UDP edges (unix): zero-length datagrams, payloads to 65507, truncation (`MSG_TRUNC` in and out, scattered iovecs), peek then recv, connected filtering, one ICMP error per unreachable, 200 datagrams drained in order, overflow counts per OS against `SysLimits::host()`, `SO_RXQ_OVFL` and `SO_TIMESTAMP` control bytes exact, broadcast recipients, Linux `IP_MULTICAST_ALL`; Linux parity regressions cover quoted ICMP payload and mixed error-queue arrival ordering. |
| `edge_net_readiness` | Readiness (unix): epoll LT/ET/ONESHOT exact `(events, data)` over 11 steps (plain, `deterministic()`, real OS), eventfd rules, kqueue `EV_CLEAR`/`ONESHOT`/`DISPATCH`/`DISABLE`/`ENABLE` and `EVFILT_USER` sequences, mio `Waker` one event per five wakes, zero-timeout polls charging exactly 1 µs, timed-out waits 1 ns past, modelled `select`. |
| `readiness_mutations` | Parked waiters become runnable after SimHost close/descriptor replacement or kqueue registration/enable of an already readable socket. Linux native comparisons cover empty netlink polling, all three request APIs, retained descriptor aliases and new epoll edges while an older response remains unread. |
| `edge_net_policy` | Link policies (unix): seeded `UdpPolicy` and `NicPolicy` loss/dup/jitter sequences, arrival stamps and `Link` events golden and equal under `deterministic()`, accounting `delivered = sent − Lost + Duplicated`, policy MTU drops draw nothing, TCP jitter never reorders (read times golden per OS), link down mid-flight drops datagrams and stalls TCP to the exact instant it returns. |
| `edge_net_topology` | Routing ties (earliest, metric, bound address, connected subnet, /32, `Route::src`, IPv6) via `route_lookup` and real sends; carrier and admin flaps mid-stream with exact counters; bind-to-device per OS; strong/weak host; don't-fragment boundaries MTU−28/−27 (IPv4) and −48/−47 (IPv6) at four MTUs; raw frame MTU+14/+15; `nic_counters` after a fixed scenario. |
| `edge_net_testers` | Framing independent of read splits (seeded, 300 plans per framing: `Line`, `Bytes`, `Delimited` incl. a self-overlapping delimiter, `LengthPrefixed` at widths 1/2/4/8), through a TCP tester too; a UDP tester parses each datagram alone; per-connection state fresh per TCP connection, kept per UDP source, in arrival order; cyclic ticks at exact instants (1 ns past each timed one); a deterministic echo session's events and stamps golden (`edge_net_testers_events.txt`). |
| `edge_net_pcapng` | A deterministic eth0 scenario (datagrams, an ICMP unreachable, a three-segment TCP echo under latency, half-closes, a refused connect): every byte after the section header golden and identical on macOS and Linux (`edge_net_pcapng.txt`), same seed same file, capture changes nothing the run sees, MACs per frame. |
| `edge_net_counters` | `ProtoCounters` after each of 25 steps touching every UDP/TCP counter in both families, then `/proc/net/snmp(6)` or `net.inet.udp.stats` as read, golden per OS; counters per sim. |
| `edge_sync_dispatch` | Where a hooked call lands (unix): managed → sim; `real` (nested, after a panic inside it) → OS with the thread still in its sim; threads spawned under `real`, threads outside every sim, a layer's own callback (no reentry) and TLS destructors at thread exit → OS; `dlsym` hands out the hook outside passthrough (even off a sim) and the OS function under `real`; a cached OS pointer stays real in a sim, the hook pointer is simulated only for a managed caller; an import address taken on a managed thread is the hook; `fork` reaches the OS and is counted unmodelled once (not under `real`). |
| `edge_sync_threads` | Lineage ids exactly `mix(parent, birth order)` through a 1 000-thread storm (plain and `deterministic()`), grandchildren, scoped threads, `Builder`; later entries' roots `mix(ROOT_SALT, entry)`; each thread's seeded stream from its lineage alone; names per OS (Linux truncation to 15 bytes, unnamed children inherit the creator's name on Linux); joining an exited thread costs no time; a detached thread stays in its sim (dormant between runs, back in the next run, after the drop); panics poison, unwind to `join`/`run`, release quiescence and leave the sim reusable. |
| `edge_sync_primitives` | `deterministic()` traces of Mutex hand-off, RwLock order (writer preference on Linux only), Condvar `notify_one`/`notify_all` wake counts, Condvar timeouts, OnceLock/Once racers, Barrier leaders, rendezvous/timed channels, park/unpark and try_lock storms, replayed and golden per OS (`golden/edge_sync_primitives/`); plain-clock wake counts and timed-wait bounds; Once initialised by a managed thread with a passthrough waiter, the reverse, and mixed racers; a lock held by a thread the run left behind. |
| `edge_sync_raw` | Raw pthread mutex codes equal the host's (`EBUSY`, error-checking `EDEADLK`/`EPERM`) on the plain clock and under `deterministic()`; trylock storms; `pthread_cond_timedwait` ends exactly 1 ns past its absolute deadline under `deterministic()`; a lost signal and one wake with no spurious wakes; bare `pthread_create` children join the sim with the next lineage and `pthread_join(self)` is `EDEADLK`; Linux futex codes and wake counts, futex and `sem_timedwait` timeouts exact, semaphore codes equal the host's; macOS dispatch semaphore codes and timeout. |
| `edge_sync_lifecycle` | 1 000 sims built, run and dropped each start at virtual zero and the realtime epoch, end at the same instant and free their domain; runs of two sims nest on one thread and each restores the other's clock and id; a nested run of the same sim is a later entry; two sims in turn keep separate clocks; a sim built on one thread runs on another; testers, sockets/ports, DNS names and the topology stay in their sim and persist across its runs; a clock set and paused in one sim leaves another alone. |
| `edge_host_fs` | VirtualFs: empty/sparse/large files, stat fields and inodes, readdir order with `.`/`..`, unicode and byte-preserving non-UTF-8 names, resolved intermediate components and trailing slash, deny > passthrough > tree > owned, O_CREAT/O_TRUNC/O_EXCL/O_APPEND, live write visibility and directory-parent validation, declined calls reaching the OS or `/dev/null`, virtual fds across threads and `real`, tree sharing across runs and sims. |
| `fs_directory_ops` | Native/model directory-relative mutations, `rmdir` errors, `fdopendir`, packed directory records, descriptor aliases and rewind, close-on-exec flags, descriptor zero and large descriptors; Linux synthetic directory records, metadata and filesystem types. |
| `fs_sparse` | Native/model sparse 64 GiB growth and shrink; configured page quotas, partial writes, `statfs`/`fstatfs`, and storage retained until the final unlinked inode reference closes. |
| `fs_live_contents` | Native/model parity for writes and truncation through separate opens, shared live metadata, independent offsets, concurrent appenders and creation errors; independently built file planes remain isolated. |
| `fs_path_ops` | Native/model parity for absolute mkdir/rename/unlink, replacement and directory moves, hard links, stable inode identity and zero link counts on retained unlinked descriptors, byte-preserving names, plus path/type errors. |
| `fs_path_resolution` | Native/model parity for missing or non-directory components before `.`/`..`, including open/stat/mkdir/unlink/rename and directory/canonicalization APIs; valid traversal, declared mount roots and explicit passthrough/deny precedence. |
| `edge_host_env` | Isolated environment: empty vs unset, profile duplicates, case, non-UTF-8 values, stable `getenv` pointers, rejected invalid names, per-sim isolation and persistence, which threads see it, write-through when not isolated; Linux enumeration remains an ignored bug because it reads process-global `environ`. |
| `edge_host_dns` | Name table: ASCII case folding and one trailing dot, canonical name on the head node, many-address order per family vs the real resolver, `AI_NUMERICHOST`, replace/remove and reverse order, `localhost` override, `getnameinfo` buffer boundary and flags, exact virtual lookup latency, per-sim tables. |
| `edge_host_signals` | Signal table: handler and log order across `raise`/`kill`/`pthread_kill`/test raises, `raise_after` tie order, `SA_RESETHAND` remains, previous-disposition chain, process `SIG_IGN` snapshotted at build, per-sim isolation and `real`, other signals to the OS, ctrlc once per raise. |
| `edge_host_limits` | Exact errno sequences of rlimit/sched/nice/mlock edges on `SimHost` and plain sims; failing-call os_truth; `RLIM_INFINITY`; limits shared across a sim's threads and runs, never between sims; per-thread policy; `SCHED_IDLE` exit gate; macOS `mlockall` `ENOSYS` and per-sim wiring. |
| `edge_host_sysfs` | Byte-exact `/sys` and `/proc` rendering for an explicit profile and `EasyBuilder::realtime()` (golden per OS), listings, `threaded` write rules/persistence/snapshot; macOS sysctl `NET_RT_IFLIST2` and `net.inet.udp.stats` (golden); repeatable across threads and runs. |
| `edge_host_nic` | Linux golden transcripts of ethtool (four drivers/privilege sets), PTP ioctls (limits, fd modes, caps) and rtnetlink qdisc change/dump sequences; replay on a fresh sim; ethtool state per host and kept across runs. |
| `edge_host_random` | Seeded entropy byte-exact (golden per OS) and against the documented SplitMix64/lineage algorithm; root/child/grandchild and later-entry root lineages; a partial word is discarded; empty/oversized requests; `getrandom` flags and size; OS entropy for unmanaged threads and `real`; HashMap keys replay. |
| `edge_time_clock` | Discrete clock, exact ns (plain and `deterministic()`, replayed): sleeps and expired timed waits (condvar, channel, park, `sched::park`, `SO_RCVTIMEO`) land at deadline + 1 ns; tied and adjacent deadlines share one landing; a timer registered right after a skip coalesces with one already there; a wait ended early leaves no ghost deadline (a later deadlock gives up without moving time); `Duration::MAX` waits end on their event; deadlines near `u64::MAX`; zero timeouts never skip (plain clock charges 1 µs for a native zero wait, `deterministic()` nothing); 3 000 `sleep_until` timers each 1 ns past, at most one poll per distinct instant. |
| `windows_std_sleep` | Windows Rust sleep overflow boundaries and finite clock saturation in Plain/Det modes, nonzero start times, paused Executive deadlines, maximum finite native sleeps, and bounded fresh-process native `Sleep(INFINITE)` / non-alertable `SleepEx(INFINITE)` checks after advancing to the clock limit. |
| `edge_time_spin` | Clock spins: 63 reads in a row hold still, the 64th moves 1 µs, every later one `max(age/64, 1 µs)` capped at 1 s (3 000 reads exact against the model), a spin caught later steps from where it was caught; any other hooked call (or a charged call) ends it; a step lands 1 ns short of a timer then 1 ns past it, where its sleeper wakes; paused and executive-driven clocks never move under a spin; each call returning without blocking costs exactly 1 µs, clamped to a grant's horizon and back to normal after detach; two spinners stay monotonic and replay. |
| `edge_time_controls` | All 100 ordered pairs of `pause`/`resume`/`advance`/`advance(0)`/`set_value` (forward, same, back)/`set_rate` (0, ∞, finite) from 5 ms, plain and `deterministic()`: exact reading, pause state and rate after each, never back, refused controls (set back, finite rate under `deterministic()`) panic and change nothing; a waiter released by `advance`/`set_value` reads exactly the reading left, one released by `resume` wakes 1 ns past its deadline; controls from inside the run read back exactly. |
| `edge_time_executive` | `jump_to` lands exactly on the earliest timer at or before its target (or on the target, never back) and returns the timers released; sleepers read exactly their deadline; charges up to a frozen grant's horizon, `freeze`, a new horizon; an empty timestamp leaves blocked count, next deadline and (plain clock) the epoch unchanged; a timestamp behind the clock changes nothing the sim reads; a timer at the timestamp fires on leave, one 1 ns before refuses checked entry; busy and setup leases refuse jumps and checked entry; epoch only rises; census classes; `with_driver_time` refuses non-drivers. |
| `edge_time_quiescence` | Give-ups: never while a thread is starting, computing with no hooked call, or woken and not yet run; a timerless deadlock gives up `WouldBlock` without moving time, one behind a timer exactly 1 ns past it; a thread left over after its run sleeps exact landings no faster than real time; four concurrent sims (two deterministic) and a paused one keep exact independent clocks; `stuck_after(40 ms)` stays quiet through an hour of sleeps, a held lease and a paused clock. Wake economy by counts: a condvar waiter, a parked thread and a sleep future among 50 other sleepers wake exactly once per event; 50 empty timestamps wake none of 20 condvar waiters. |
| `edge_time_golden` | `deterministic()` seed-1 traces (`<virtual ns> <thread> <event>`, recorded under `real` so recording does not perturb the schedule), replayed and compared line by line with `golden/edge_time_<scenario>[.<os>].txt`: mutex contention, condvar ping-pong, many channel producers, tied sleeps, a spawn/join tree, TCP and UDP testers, UDP-with-jitter and TCP exchange, clock spins beside a yielder and a sleeper, a rayon pool, crossbeam `WaitGroup`/`Parker`/`Backoff`, seeded randomness. Scenarios without randomness trace the same under any seed; the seeded one differs between seeds 1 and 2. `SNARE_BLESS=1` rewrites the shared file, `SNARE_BLESS=os` this OS's override. |
