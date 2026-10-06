# snare

Deterministic, in-process simulation of the operating system for Rust tests — **without changing the
code under test.**

Your code keeps calling `std::net::TcpStream`, `std::fs::File`, `std::env::var`, `libc::sched_setscheduler`,
`clock_gettime`, raw `AF_PACKET`/`io_uring` — exactly as it does in production. snare interposes at the
OS-call boundary underneath it and serves those calls from an in-memory model: a virtual network, a
virtual filesystem, a simulated host, a virtual clock. The test drives the other side of the wire.

```rust
use snare::prelude::*;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

let sim = Sim::new();
sim.run(|| {
    // The "server" the code under test talks to — scripted by the test.
    let server = connect_tester::<Line>("127.0.0.2:9000")
        .then_action(|msg, _from| TesterAction::Send(Line(format!("echo:{}", msg.0))));

    // The code under test: a real TcpStream. Its socket calls are serviced from memory.
    let client = std::thread::spawn(|| {
        let mut s = TcpStream::connect("127.0.0.2:9000").unwrap();
        s.write_all(b"hello\n").unwrap();
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).unwrap();
        line
    });

    run_testers!(server);
    assert_eq!(client.join().unwrap(), "echo:hello\n");
});
```

No shim types, no dependency injection, no trait objects threaded through the code under test. It is a
plain `TcpStream`.

## The paradigm

snare 1.x required the code under test to import snare's shim types (`snare::net::TcpStream`
instead of `std::net::TcpStream`, and so on). That only tests code you could edit to use the shims, and
it never covers what a dependency does three crates down.

snare 2 removes that constraint. It patches the **import tables** of the loaded program (ELF GOT / Mach-O
`__got` / PE IAT) so that the libc and Win32 symbols a managed thread calls — `socket`, `open`, `getenv`,
`clock_gettime`, `ioctl`, `sched_setscheduler`, … — land in snare's hooks first. A hook offers the call
to the test's in-memory model; if the model declines, the call falls through to the real OS. Nothing the
code under test imports changes. This reaches straight through `std` and every dependency.

Every resource or object used by the code under test must be created under its active simulation.
Run initialization inside `Sim::run`, including constructors, dependency initialization, worker
pools and lazy initialization. Objects created before entering the simulation, or created with
interposition disabled and then handed to the code under test, violate this usage invariant.

Passthrough (`snare::real`) is reserved for other-side emulation and the test harness. The code under
test, including its dependencies and initialization, must remain under interposition. The harness
can configure the simulated world before the run and use independent real resources for its own
bookkeeping, fixtures and native comparisons.

Two needs, one library:

- **Deterministic unit tests** — write them in-crate or as integration tests, guarded by
  `#[cfg(snare)]`, and run them with `cargo snare test` (below).
- **One process, one API** — the test body, its scripted peers (testers) and any higher-level harness
  run in the same process as the code under test and drive the simulation through the same in-process
  API (`Sim`, testers, `set_udp_policy`, the time controls). There is no controller process and no
  cross-process protocol; when the harness or other-side emulator needs the real machine it says so
  with [`snare::real`](#reaching-the-real-machine-snarereal).

## How it works

```
        code under test (plain std / libc / raw syscalls)
                         │  its OS symbols are interposed
                         ▼
  snare-interpose:  import-table patch ──► per-thread hooks ──► Domain
                                                                 ├─ Layer stack   (clock, entropy, sleep)
                                                                 ├─ Net backend   (sockets, netlink, raw L2)
                                                                 ├─ Fs  backend   (files, /sys, /proc, /dev)
                                                                 ├─ Host backend  (scheduling, NIC tuning)
                                                                 └─ Env backend   (getenv/setenv)
                                                                 │ declined?
                                                                 ▼
                                                            the real OS
```

- **`snare-interpose`** is the engine: the import-table patchers, the per-thread hook functions, the
  `Domain` (a thread's simulated world), the `Layer`/`Net`/`Fs`/`Host`/`Env` backend traits, and the
  `real()` escape hatch. It has no opinion about *what* is simulated — that is a backend.
- **`snare`** is the ergonomic layer built on it: `Sim`/`SimBuilder`, `SimHost` (one backend that models
  a whole host), `HostProfile`/`EasyBuilder` to configure it, the `Fabric` (TCP/UDP/raw-L2 network),
  `VirtualFs`, and the `connect_tester`/`run_testers!` scripted-peer API.

A thread becomes *managed* while it is inside `Sim::run`, and every thread it spawns inherits the
simulation automatically. Only managed threads are interposed; the test's own bookkeeping is not.

## What is simulated

| Surface | Covered |
|---|---|
| **Time** | `clock_gettime` (`CLOCK_MONOTONIC`/`REALTIME`/`TAI`), `gettimeofday`, `QueryPerformanceCounter`, `GetTickCount64`, `mach_absolute_time` — a discrete-event virtual clock at a fixed epoch (the default, with or without a `SimHost`; `wall_clock()` opts out). Time jumps to the next pending sleep or timeout once every thread is blocked, and each call that returns without blocking costs a microsecond, so busy-polls still let time move. It can also run scaled to real time (`time_rate`), be set forward (`set_time_value`), and be paused, which holds every sleep and timed wait until time is moved from outside — see [Controlling time](#controlling-time). |
| **Entropy** | `getrandom`/`getentropy`/`arc4random`/`ProcessPrng` — seeded, so `HashMap` order etc. is repeatable. |
| **TCP** | `std::net::TcpStream`/`TcpListener` against scripted `connect_tester` peers, or against each other: the code under test can `bind`/`listen`/`accept` (`accept4` flags on Linux) and connect to its own listeners, with `shutdown(2)` (`SHUT_RD`/`SHUT_WR`/`SHUT_RDWR`) and bind conflicts (`EADDRINUSE`, `SO_REUSEADDR`) as the host OS has them. |
| **UDP** | `std::net::UdpSocket` serviced from memory on every platform: `bind`/`connect`/`sendto`/`recvfrom`/`sendmsg`/`recvmsg` (and Linux `sendmmsg`/`recvmmsg`), blocking cross-thread receive, broadcast (`SO_BROADCAST`), multicast (`IP_ADD_MEMBERSHIP`, Linux `IP_MULTICAST_ALL`), Linux `IP_RECVERR` ICMP reports on `MSG_ERRQUEUE`, and several addresses sharing a port. Under a `SimHost` it adds `SCM_TXTIME` launch deadlines, and its sockets work with `poll` and `epoll`. TCP and UDP run together in one `Sim`. |
| **Packet timestamps** | Kernel receive and transmit stamps from the sim's clock on the plain `Sim` and under a `SimHost`: Linux `SO_TIMESTAMP`/`SO_TIMESTAMPNS`/`SO_TIMESTAMPING` (`SCM_TIMESTAMP*`, UDP and TCP) and `MSG_ERRQUEUE` transmit stamps (`OPT_ID`, `OPT_TSONLY`, `TX_SCHED`/`TX_ACK`); macOS `SO_TIMESTAMP`/`SO_TIMESTAMP_MONOTONIC`/`SO_TIMESTAMP_CONTINUOUS`; Windows `SIO_TIMESTAMPING` on UDP (`WSARecvMsg`'s `SO_TIMESTAMP`, `SIO_GET_TX_TIMESTAMP` by `SO_TIMESTAMP_ID`). A packet is stamped when it reaches the socket, after its link delay. See [Packet timestamps](#packet-timestamps). |
| **Raw L2** | Linux `AF_PACKET`/`SOCK_RAW` + `bind(sockaddr_ll)`; macOS `/dev/bpf*` (`BIOCSETIF`/`bpf_hdr`). What EtherCAT masters (ethercrab) use. Interfaces come from the sim's topology (`add_nic`), and frames respect their link state and MTU. |
| **Interfaces and routing** | One topology per sim (`NicSpec`, `Route`, `add_nic`, `set_link`, `schedule_link`, `route_lookup`) that every backend routes real traffic through: longest-prefix routes, source selection, carrier and admin flaps that stall TCP and drop datagrams, per-interface latency/jitter/loss (`NicPolicy`) and counters, and bind-to-device (`SO_BINDTODEVICE`, `IP_BOUND_IF`, `IP_UNICAST_IF`, or `set_socket_device` from the test) with the host OS's errors. See [Interfaces and routing](#interfaces-and-routing). |
| **Interface enumeration** | `if_nametoindex`/`if_indextoname`/`if_nameindex`, `getifaddrs`, `SIOCGIF*`, SimHost sysfs, rtnetlink `RTM_GETLINK`/`GETADDR`/`GETROUTE`, macOS `NET_RT_IFLIST2`, and Windows IP Helper (`GetIfEntry2`, `GetAdaptersAddresses`, `ConvertInterface*`, `GetBestRoute2`) all read the topology. See [Enumerating interfaces](#enumerating-interfaces). |
| **Readiness** | `epoll` + `eventfd` (Linux) and `kqueue`/`kevent` (macOS, incl. `EVFILT_USER` wakers), so `mio`-based code works natively on both. Edge-triggered registrations (`EPOLLET`, `EV_CLEAR`) are reported once per event as the kernels do — data arriving, an eventfd write or a `NOTE_TRIGGER` is a new edge even on an fd already ready — so a fired `mio::Waker` or an idle writable socket does not wake every poll; `EPOLLONESHOT`, `EV_ONESHOT`, `EV_DISPATCH` and `EV_DISABLE`/`EV_ENABLE` are honoured. Terminal errors follow edge-triggered delivery; newly visible errors or timestamp reports produce new edges. Level-triggered waits repeat while ready. `poll(2)`, `WSAPoll` and Winsock `select` block and honour their timeouts. |
| **Socket faults and back-pressure** | Raised socket errors (`raise_socket_error`), ICMP port unreachables (injected, from a tester, and sent back automatically after the round trip for a datagram no socket takes), one-way link stalls that hold traffic in flight (`quiesce`), TCP send and receive buffers (`SO_SNDBUF`/`SO_RCVBUF`) and a receive window (`TcpPolicy::recv_window`) that block sends with `SO_SNDTIMEO` and host-OS writable thresholds, and `SO_LINGER` aborts and waiting closes — each with the host OS's codes and call order. See [Socket faults and back-pressure](#socket-faults-and-back-pressure). |
| **Connect faults** | A listening address refuses (`ListenerBehavior::Refusing`) or drops SYNs until an instant (`DelayingUntil`), and an address nobody answers at makes a connect wait out the host OS's SYN retransmission plan — Linux 131 s (`tcp_syn_retries`, `tcp_syn_linear_timeouts`, `TCP_SYNCNT`), macOS 75 s (`TCP_CONNECTIONTIMEOUT`), Windows 21 s (`TCP_MAXRT`) — in virtual time. Nonblocking connects report `EINPROGRESS`/`WSAEWOULDBLOCK`, then `poll`/`epoll`/`kqueue`/`select` and `SO_ERROR`, so `connect_timeout` and `mio` behave as on the real OS. See [Connect faults](#connect-faults). |
| **Protocol counters** | The host's UDP and TCP counters, driven by the sim's traffic: Linux `/proc/net/snmp` and `/proc/net/snmp6`, macOS `sysctl` `net.inet.udp.stats`, Windows `GetUdpStatistics(Ex/Ex2)` and `GetTcpStatistics(Ex/Ex2)`, and `proto_counters()` for the test. See [Protocol counters](#protocol-counters). |
| **Netlink** | `AF_NETLINK` rtnetlink `RTM_GETLINK`/`IFLA_STATS64` (a dump, or one link by index or name), genetlink `CTRL_CMD_GETFAMILY`, `RTM_GETQDISC`/ETF. |
| **Files** | `VirtualFs`: an in-memory tree behind open, sequential/positional IO, truncate, sync, stat and directory-stream calls, with glob passthrough to real paths. `SimHost` also renders `/sys`, `/proc`, `/dev/ptp*`, `/dev/cpu_dma_latency` (the request held open reads back through `SimHost::cpu_dma_latency`). Raw directory syscalls and path mutation are incomplete. |
| **Host tuning** | Scheduling (`sched_setscheduler`/affinity/priority, `mlock`/`mlockall`), resource limits (`RLIMIT_RTPRIO`/`NICE`/`MEMLOCK`), NIC config (`ethtool` rings/coalescing/channels/pause/EEE/flags/flow rules/stats, `SIOC[GS]HWTSTAMP`, qdiscs and ETF offload, threaded NAPI, queues/IRQs), PTP, capability gating — all modeled, never touching the real scheduler or NIC. |
| **Kernel identity** | Under a `SimHost`, `uname` (and Linux `SYS_uname`) reports the profile's `sysname`/`nodename`/`kernel_release`/`kernel_version`/`machine`: a fixed kernel by default, whose Linux version string carries `PREEMPT_RT` when the profile does, or the build machine's own with `real_uname()`. `gethostname` still reads the real name. |
| **Tester stages** | A tester's message chain: `then_test` / `then_stateful_test` drop or rewrite a message before later stages, `then_edit_state` updates state, `then_action` / `then_stateful_action` answer — run in the order added. |
| **Thread classes** | Every thread in a `Sim` is a participant unless marked (`snare::sched::mark_background`, `mark_helper`, `mark_driver_thread`, `spawn_as`): only participants hold up quiescence and the deterministic schedule. `busy()` / `setup_scope()` leases hold time still; thread names from `pthread_setname_np` / `SetThreadDescription` label each thread. `SimBuilder::stuck_after` fails a run a spinning participant has frozen. See [Stuck runs](#stuck-runs). |
| **Cooperative primitives** | `snare::sched::park` / `current_unparker`, `block_on` / `block_on_until` / `block_on_timeout`, the `Sleep` future (`sleep_until`), `WakerSet` and `is_driven`: in a sim they wait on its clock and schedule — counted toward quiescence, their deadlines virtual timers, their wakes held at an executive's gate — and off one on real time. See [Cooperative primitives](#cooperative-primitives). |
| **Executive** | An outside simulation owns a sim's clock in-process (`Sim::executive`, `snare::sched::attach`): it lets time flow in grants up to a horizon, jumps it timer group by timer group once the sim is quiescent, and acts at timestamps of its own whose effects reach the participants only when the timestamp ends — with a quiescence/participant/timer listing and an audit of what it cannot see. See [Executive](#executive). |
| **Socket table** | One record per open socket of the code under test on every backend (`socket_table()`, `socket_entry(id)`, `socket_id(&sock)`, `closed_sockets()`, `sockets_bound(addr)`): kind, local and peer address, the listener an accepted stream came from, multicast memberships, queued/delivered/sent counts, the pending `SO_ERROR` and when it opened and closed. See [Socket table](#socket-table). |
| **Socket limits and privileges** | `SO_RCVBUF`/`SO_SNDBUF` rounded as the host OS does, each datagram admitted against the receive buffer at its arrival (Linux `truesize`, macOS `sb_cc`/`sb_mbcnt`, Windows payload), `FIONREAD`/`SIOCINQ`/`SIOCOUTQ`, `SO_NREAD`, `SO_MEMINFO`, `SO_RXQ_OVFL`, `SO_COOKIE`; one `Privileges` per sim gating reserved-port binds, `SO_*BUFFORCE`, `SO_PRIORITY`/`SO_MARK`, interface rebinds, `AF_PACKET`, `/dev/bpf*` and a `SimHost`'s capabilities. See [Socket limits and privileges](#socket-limits-and-privileges). |
| **Names** | `getaddrinfo`/`freeaddrinfo`, `getnameinfo`, `gethostbyname` (and Winsock's `GetAddrInfoW`/`GetNameInfoW`) answered from a per-sim host table (`add_host`) plus a built-in `localhost` — unknown names fail with the host's own code (`EAI_NONAME`, `WSAHOST_NOT_FOUND`), never real DNS; numeric hosts and hints stay the real libc's. Per-name latency and seeded failures (`set_dns_policy`). See [Names](#names). |
| **Signals** | `sigaction`/`signal`/`raise`/`kill`/`pthread_kill` for `SIGINT`/`SIGTERM`/`SIGHUP` (Windows: `SetConsoleCtrlHandler`, `GenerateConsoleCtrlEvent`, the CRT's `signal`/`raise`) against per-sim dispositions; `Sim::raise_signal` delivers as the host OS would, so `ctrlc` and `signal-hook` run unchanged. The semaphores and socketpairs their threads block on (`sem_*`, `socketpair(AF_UNIX)`, Windows semaphores) are simulated too. See [Signals](#signals). |
| **Recorded events** | A sim-wide log (`recorded_events()`, `Sim::recorded_events`) of what crossed each tester's boundary, what link policies did to datagrams, policy changes, injected faults and delivered signals, stamped on the sim's clock. |
| **Packet capture** | `SimBuilder::pcapng(path)` (or `SNARE_PCAPNG_DIR` for every sim, `SNARE_PCAPNG_TESTS` for chosen tests) writes what crosses the sim's network to a pcapng file Wireshark opens: fabricated Ethernet/IP headers around each TCP connection (handshake, segments, ACKs at arrival, FINs, resets, SYN retransmissions), each datagram once at its sender, ICMP port unreachables and raw L2 frames verbatim, stamped on the sim's clock per interface, optionally commented with real wall time. See [Packet capture](#packet-capture). |
| **Environment** | `getenv`/`setenv`/`unsetenv` lookups and mutations are isolated (opt-in). macOS enumeration uses the simulated snapshot; Linux `vars`/`vars_os` still read the real process environment. |
| **Windows** | The thread-scheduling plane (`SetThreadPriority`/affinity/priority-class/`timeBeginPeriod`, MMCSS `AvSetMmThreadCharacteristicsW`/`AvSetMmThreadPriority`/`AvRevertMmThreadCharacteristics`, power throttling through `Set/GetProcessInformation` and `Set/GetThreadInformation`, CPU sets) runs against a `WinHost`, read back with `Sim::time_periods`, `mmcss_tasks`, `process_power_throttling`, `thread_power_throttling`, `process_default_cpu_sets` and `thread_selected_cpu_sets`, and `std::net::TcpStream`/`TcpListener`/`UdpSocket` are serviced from memory by a Winsock fabric (`socket`/`bind`/`listen`/`accept`/`connect`/`send`/`recv`/`sendto`/`recvfrom` with `MSG_PEEK`/`MSG_WAITALL` and `WSAEMSGSIZE` truncation, the synchronous `WSASend`/`WSARecv`/`WSASendTo`/`WSARecvFrom`/`WSASendMsg` and the `WSARecvMsg` extension, blocking recv/accept, UDP broadcast/multicast/multi-IP, don't-fragment, `WSAIoctl` including `SIO_CPU_AFFINITY`, read back with `Sim::socket_cpu_affinity`). `WSAPoll` and `select` readiness and `WSADuplicateSocket` (`try_clone`) are modelled, IOCP is planned; a sim socket never reaches Winsock — overlapped calls and event/window-message notification on one fail with `WSAEOPNOTSUPP`. A pcap/npcap interposer is in place structurally. |

Registered hooks record unsupported calls in `Domain::unmodelled()`. An empty report is a useful
check, but does not prove full simulation: unhooked functions, direct process-global reads and CPU
instructions are outside that accounting.

## Configuring the host: `SimHost`, `HostProfile`, `EasyBuilder`

For code that tunes the host (real-time schedulers, NIC configurators like `fast-talker`), attach a
`SimHost` describing the machine. The OS *personality* is fixed by `cfg!(target_os)` at compile time; what
you configure here are host *facts*.

```rust
use snare::{HostProfile, Nic, LinkStats, Sim, CAP_SYS_NICE};
use std::net::Ipv4Addr;

let host = HostProfile::new()
    .cpus(8)
    .isolated(2..8)                       // /sys/devices/system/cpu/isolated
    .governor("performance")
    .preempt_rt(true)                     // /sys/kernel/realtime
    .cap(CAP_SYS_NICE)                    // grant a capability; setters EPERM without it
    .nic(Nic::new("eth0", 2)
        .mtu(9000)
        .driver("igb", "5.6.0")
        .hardware_timestamping(true)
        .address(Ipv4Addr::new(10, 0, 0, 10))
        .queues(4, 4)
        .link_stats(LinkStats { rx_packets: 1000, ..Default::default() }))
    .env("RUNTIME_ENV", "sim")            // isolates + sets the environment
    .kernel_release("6.6.30-rt30")        // uname -r; also sysname, nodename, kernel_version, machine
    .build();

Sim::builder().host(host).build().run(|| {
    // sched_setscheduler(SCHED_FIFO), ethtool, /sys reads, SO_TIMESTAMPING, getenv — all served here.
});
```

`uname` reports a host named `snare` running a fixed kernel (Linux `6.12.0`, `#1 SMP PREEMPT_DYNAMIC`,
or `#1 SMP PREEMPT_RT` with `preempt_rt(true)`; macOS `Darwin` `25.0.0`) on the build target's machine
type. `HostProfile::real_uname()` copies all five fields from the machine running the test instead,
and works inside a sim.

`EasyBuilder` gives batteries-included presets when you just want a working machine:

```rust
use snare::{EasyBuilder, Sim};

let host = EasyBuilder::realtime().build();   // 8-CPU PREEMPT_RT, all caps, a hw-timestamping NIC
// also: EasyBuilder::server() / laptop() / unprivileged() / minimal(), each tweakable:
let host = EasyBuilder::laptop().cpus(2).privileged(false).build();

Sim::builder().host(host).build().run(|| { /* ... */ });
```

## Files: `VirtualFs`

```rust
use snare::{FsBuilder, Sim};

let fs = FsBuilder::new()
    .file("/etc/app.conf", "mode = fast\n")
    .dir("/var/run")
    .passthrough("/usr/share/**")   // globs that reach the real filesystem
    .deny("/secret/**")             // globs that always fail
    .build();

Sim::builder().fs(fs).build().run(|| {
    assert_eq!(std::fs::read_to_string("/etc/app.conf").unwrap(), "mode = fast\n");
});
```

Separate opens of a file share live contents; duplicated descriptors also share offsets and status
flags. Writes and truncation are visible immediately. Absolute `mkdir`, `unlink` and `rename`
operate on the virtual tree, preserve inode identity across moves, and keep unlinked files usable
through open descriptors. Creation requires a declared directory parent, and pathname traversal
checks intermediate components before resolving `.` and `..`. Relative path mutations,
`rmdir`, `getdents64`, `fdopendir`, permissions and sparse storage need additional modelling.
See [OPEN_BUGS.md](OPEN_BUGS.md) for the file-plane boundaries.

## Determinism and quiescence

Time is virtual, so a test that "waits a second" finishes instantly and every run sees the same
timestamps; randomness is seeded (`SimBuilder::seed`), per thread, so `HashMap` order, random ids and
link faults replay. When every thread is blocked with no timer left to fire, the run is deadlocked and
the blocked simulated wait gives up (`EAGAIN`) rather than hanging the test.
Timers due at one instant all fire there: a time skip lands 1 ns past the earliest deadline, and the
next skip waits until every timed wait it reached has returned, so a park, condvar or channel timeout —
which notices its deadline only between real-time slices of at most 2 ms — wakes at its deadline even
when a sleeper on another thread is due at the same instant and would otherwise skip straight on.
Likewise a thread woken from a native wait — a futex, condition variable or semaphore wake, or the
exit of the thread it joins — holds off every time skip until it has run.
A thread blocked on a lock that no thread of its sim holds — one held by another test running in
parallel, an unmanaged thread, or std's own process-wide locks such as the one every thread start
and exit takes — waits on the world outside, not on the sim, so it holds off time skips too until
it gets the lock. The pthread mutex hooks record which mutexes each of a sim's threads holds, so a
contended pthread mutex (std's `Mutex` on macOS) is judged exactly; a futex word names no holder, so
on Linux a lock wait on a word in static data (std's own statics) first waits up to 1 ms of real
time uncounted, which an outside holder in a short critical section lets go within, and a lock in
heap memory held outside the sim is still counted as a wait in it.

Thread *interleaving* is deterministic too with `Sim::builder().deterministic()`: one thread runs at a
time, and control passes only where a thread waits — a socket, sleep, mutex, condition variable,
channel, park, join or yield — to the next thread in a fixed order. Those waits are emulated rather than
handed to the kernel, so the waker always moves its waiters to the run queue itself and nothing is woken
behind the scheduler's back; locks shared with threads outside the simulation (another test running in
parallel) are waited out without letting their timing reorder this one. With the same seed, a run
replays exactly. What it cannot see it cannot order: a thread spinning on an atomic without ever
yielding keeps the baton, and a call that blocks in the OS outside snare's hooks blocks every thread.
A yield with no other thread able to run time-skips to the next pending timer, as a free-running
yield does once every other thread is parked, so a yield loop waiting on a sleeper (crossbeam's
`Backoff::snooze`, rayon's idle workers) gets there.

The sim's own code often runs on a participant from inside its hooked wait — the deterministic
schedule's dispatch and the time skips in it, or an idle skip as a native wait begins — where std may
already have parked the thread on its thread parker. std's parker tracks one park at a time, so a std
wait there that parks the same thread again (a channel; on macOS also a contended `OnceLock`, `Once`
or `RwLock`) would leave neither park able to be woken. snare's own process-wide singletons therefore
never wait to be initialised, and the parker's blocking calls (`dispatch_semaphore_wait`, Linux
`futex`, `WaitOnAddress`) treat a wait nested in another on the same object as a 1 ms real-time
slice that returns as a spurious wakeup, and wake the outer park to re-check, so a layer that blocks
in std there still makes progress.

### Clock spins

Reading the clock never moves a discrete clock, so a thread waiting on time by polling it —
`while Instant::now() < deadline {}`, with or without `yield_now`, spin_sleep's final spin, a loop
that checks an unhooked channel between reads — would wait forever. snare catches such a *clock
spin* and moves time for it:

- A participant's clock reads and `sched_yield`/`SwitchToThread` calls count toward a spin; any other
  hooked call (a socket call, a sleep, a wait, a thread spawn, a lock that contends, a signal) ends
  it — a wait as it begins, whether it then blocks or finds what it waits for already there, while
  one whose timeout is zero or already past is a poll and leaves the spin running — and so does each
  of the sim's own waits, such as a tester waiting for its next message or tick:
  the clock reads of a tester's loop and handlers never add up to a spin. After 64 in a row the spin is caught: isolated reads, a few back-to-back reads, or reads with
  other hooked calls between them never get there and keep holding still. A loop polling a socket
  is not a clock spin: each non-blocking call is charged its microsecond instead.
- Each read of a caught spin moves time one step: 1/64 of the virtual time since the spin was
  caught, at least 1 µs. The steps grow geometrically, so an hour-long spin takes about 1,100 reads
  and a spin overshoots its own deadline by at most 1/64 of its length (one more read before any
  other hooked call moves it one more step). A step never jumps a pending timer: one that would
  reach the earliest timer lands 1 ns short of it, so a spinner whose deadline comes first sees it
  first, and the next lands just past it, as a time skip does, waking its waiter.
- Time moves only while every other participant is parked or spinning itself, no woken waiter has
  yet to run and no lease is held, so other threads' work at the current instant comes first and
  timers fire in order. A free-running spin waits for a waiter its step reached to take its
  deadline (up to 5 ms of real time) before stepping on. Under `deterministic()` each step is a
  scheduling point: the spinner hands the baton to any runnable thread that is not spinning, and
  after a step lets the threads it released run before the next. Runs replay exactly.
- A yield loop that does not read the clock waits on another thread, not on a deadline of its own,
  and keeps the full time skip to the next timer; it gets none while a clock spinner is about,
  since that would jump past the spinner's deadline. A thread that read the clock since its last
  yield is polling, and its yields only hand others a turn.
- A paused clock, or one an executive drives, is never moved by a spin: the spinner keeps reading
  the held instant, yielding the CPU, until something outside the sim moves or resumes the clock;
  `stuck_after` reports it. A spin that moves time is progress to the watchdog. A scaled or
  as-fast-as-possible clock moves on its own and a `wall_clock()` sim reads real time, so neither is
  touched. Only participants' spins count; a background or driver thread spinning on the clock is
  left alone.

## Thread classes and leases

Every thread created inside `Sim::run` is simulated — its sockets, clock, files and environment are
the sim's — and by default it is a *participant*: time skips only once every participant is blocked, a
blocked wait gives up only when they all are, and `deterministic()` runs participants one at a time. A
thread the run should not wait on changes its class with `snare::sched`:

| Class | Set with | Effect |
|---|---|---|
| `Participant` | the default; `participate(name)` for a scope | Counts toward quiescence and runs in the deterministic schedule. |
| `Background` / `Helper` | `mark_background(label)` / `mark_helper()` | Still simulated, but never holds up quiescence or the schedule. Its sleeps and timeouts are satisfied as the clock passes them rather than steering a time skip, and its non-blocking calls cost no time. |
| `Driver` | `mark_driver_thread()` | As `Background`, and its clock reads, sleeps and timeouts (socket, poll and condition-variable timeouts alike) are real; `sched::now()` reads the sim's clock. |

`spawn_as(class, label)` makes the threads the caller creates while the guard lives start in `class`
(for a pool or library that spawns its own threads); later children, and a background thread's own
children, are participants again. Sim waits (a receive, a poll, an accept) still give up when every
participant is blocked with no participant timer left, however many background timers are pending.
Once no participant can give up — each is in a join, a lock, a condition variable or a channel
receive, waiting on what only a background thread can do, as when the test stops a sampler and joins
it — time skips to the background threads' timers instead, so the join returns. Under
`deterministic()` a thread that leaves the schedule (`mark_background` on a running participant, or a
`participate` guard dropping) hands the baton on as it goes, and a thread of another class runs
beside the schedule: whatever it wakes — a channel send, a condvar signal, a socket write — still
reaches the schedule, but when it runs relative to the participants depends on the OS, so its effects
on them only replay if they wait for it. The same holds for a background thread entering the schedule
through `participate`: the point where it joins depends on real time, so the run replays only if the
participants wait for it there (for a message it sends from inside the guard, say).

`busy(label)` (`Send`; also `Sim::busy`) and `setup_scope(label)` are leases: while one is held the sim
is never quiescent, so time does not skip and no blocked wait gives up, even on the discrete clock; a
deterministic schedule idles until the lease is dropped. Taking one waits out a time skip already in
flight, so from any thread, inside the sim or not, no skip lands once `busy` returns. A lease has a
kind: `busy` takes a `LeaseKind::Busy` one, for work the sim cannot see that lasts about as long as a
reaction, and `setup_scope` a `LeaseKind::Setup` one, which may last as long as setup takes without
anything being stuck. `held_leases()` lists them as `LeaseInfo { label, kind, holder }`, the holder
being the name of the thread that took it. Off a sim both return an inert lease (`is_held()` is
`false`) rather than panicking, so code shared with a real deployment can take them unconditionally;
`sched::in_sim()` says whether the calling thread runs in a sim at all, and `sched::current_sim()`
which one (a `SimId`, also `Sim::id`). A thread's name is whatever it set through `pthread_setname_np` or
`SetThreadDescription` (std's `Builder::name`), which go to the OS unchanged — a Linux name over 15
bytes still fails with `ERANGE` — or `thread-<lineage>` otherwise.

### Stuck runs

A participant that runs without making a hooked call — spinning on an atomic, or computing — keeps
the sim from going quiescent, so the discrete clock cannot move and every sleeper it may be waiting
for waits for good: the test hangs. `SimBuilder::stuck_after(d)` (off by default) turns that into a
failure. A watchdog thread outside the sim samples it every eighth of `d` (between 1 ms and 250 ms)
and fires once, for `d` of real time, a participant has been running while none of the sim's
progress has happened: no participant blocked or woke, no lease was taken or given back, virtual
time did not move (a time skip, a clock write, a scaled or granted clock flowing, the microsecond
each non-blocking call is charged, a [clock spin](#clock-spins)'s step), and under `deterministic()` no participant began a wait in the
schedule. It never fires while every participant is blocked — on a paused clock, on an executive, on
locks only a thread outside the sim can release — since the design waits for those, nor while a
lease is held or an executive's timestamp is open, nor on a `wall_clock()` sim, whose time moves on
its own. A participant that legitimately runs longer than
`d` with no hooked call (a long computation, a blocking call snare does not hook, work inside
`real`) holds `busy()` across it. Off by default because that work looks exactly like a spin.

A stuck thread cannot be made to panic from outside, and the test would never finish, so the
watchdog attempts its report on the process's stderr — past the test harness's output capture —
with a 100 ms reporting budget, then aborts the test process. Locked or blocked stderr may leave
the report incomplete, and OS scheduling may delay detection and termination. The report names
every participant: running (and, under `deterministic()`, which one holds the baton), or what it
waits in and until when, what it last
waited in, and the leases it holds.

The same listing explains a deterministic schedule that has idled for a second with every
participant blocked — on a held clock, on a lease, or on locks only something outside the sim can
release: that is waiting rather than stuck, so it is a one-time warning on stderr and the schedule
carries on.

## Sim lifecycle

A `Sim` is *running* while at least one thread is inside `Sim::run`, and *dormant* between runs and
after it is dropped. Threads spawned inside a run that are still alive when it returns — a
background loop the test never stopped, a pool's idle workers — stay in the sim: their clock,
sockets and files are still its own, and the sim's state lives as long as any of them does, even
past the `Sim`'s drop. But nothing waits on them any more, so while the sim is dormant:

- **Time moves for them at real time's pace.** A time skip lands no further past the reading the
  run ended at than real time has moved since, so a leftover thread sleeping in a loop sleeps in
  real time (a near-idle CPU) instead of racing the virtual clock ahead at full speed. An
  as-fast-as-possible clock holds still between such skips too. With no leftover thread waiting on
  a timer the clock does not move at all, so a sim without leftovers starts its next run where the
  last one ended. A paused clock, or one an executive still drives, stays held.
- **A wait with nothing left to wait for blocks** instead of giving up as a deadlock: a receive no
  thread will ever answer stays blocked (polling a few times a second) rather than failing with
  `EAGAIN`, so a leftover loop that retries on errors does not spin.
- **They no longer count anywhere else**: not toward another sim's quiescence (each sim's woken
  waiters are its own, however many sims run in parallel), not toward the `stuck_after` watchdog
  (a leftover thread spinning on an atomic is the test's own business once the run has ended), and
  a deterministic schedule has already let them go to run freely.
- **They can still be stopped and joined from outside**: set the flag they poll and join them;
  their sleeps end in real time.

The next `Sim::run` on the same sim takes its leftovers back: they are its participants again, and
time skips go back to virtual time at once (monotonic time never goes backwards across the switch).
A test that wants none of this stops its threads before the run returns.

## Controlling time

The clock every `Sim` runs on can be driven from the test, through `Sim` methods or a `TimeHandle`
(`sim.time()`, or `snare::time()` from any thread running inside the sim):

| Call | Effect |
|---|---|
| `set_time_rate(r)` / `SimBuilder::time_rate(r)` | `r` in (0, 1e6]: virtual time runs at `r` times real time (larger values clamp). `0.0` pauses. `f64::INFINITY` returns to virtual time — discrete-event, or as-fast-as-possible for a `SimHost` or Windows sim built with `wall_clock()` — keeping the reading. Negative or NaN panics. |
| `time_rate()` | `0.0` while paused, the rate while scaled, `f64::INFINITY` on virtual time. |
| `pause_time()` / `resume_time()` | Pausing holds the clock: reads return the same instant, and every sleep, socket timeout, poll timeout and condition-variable or futex timeout blocks until time moves, as `nanosleep(2)` and `Sleep` wait out their whole interval. Resuming restores the mode and rate in force before the pause. |
| `advance_time(d)` | Moves the clock forward by `d`, paused or not, waking what it reaches. |
| `set_time_value(v)` / `time_value()` | Sets sim time — how far the clock has moved since the sim was built — to `v`, `CLOCK_MONOTONIC` and the realtime clocks moving with it; forward only (setting it back panics and leaves the clock alone). `time_value()` reads without ticking. |

Monotonic time never goes backwards, whatever moves the clock: every monotonic source is
non-decreasing on each thread and across threads that synchronize, every mode switch re-anchors at
the last reading handed out, and a request to move the clock back is refused. Realtime starts at a
fixed epoch and moves with sim time; `CLOCK_MONOTONIC` (and `Instant`, `mach_absolute_time`,
`QueryPerformanceCounter`, `GetTickCount64`) starts at zero in every sim, so a replay reads the same
absolute values. The guarantee is per sim: an `Instant` taken outside the sim, or in an earlier sim
and kept in a static, is on a different timeline and may look ahead of one taken inside. A driver thread is the one
exception by design: it reads real time, and an executive's timestamp time while it acts at one.

A paused clock is moved by something outside the simulation — the test thread before or after `run`,
or a thread it starts under `snare::real` — so a sim where every thread waits on a paused clock is
waiting, not deadlocked; it says so on stderr after a second. Once resumed, a wait nothing can
satisfy gives up as before. On an as-fast-as-possible clock, a timed wait that is still held when
the clock resumes times out then, the clock jumping to its deadline as a sleep's does; one already
running when the clock is paused or scaled keeps the time it had left and holds with the clock. Under
`deterministic()` the clock can be paused, advanced and set; a write made while every simulated
thread is blocked on the paused clock releases the waiters in the schedule's fixed order, but one
made while a simulated thread runs lands wherever real time puts it in that thread's work, so the run
only replays if outside writes wait for the sim to block; an [Executive](#executive)'s `jump_to` and
`enter_timestamp_checked` act only while the schedule is idle, so they always do. A real-time rate is refused, since nothing
in a deterministic run may depend on real time. A plain unix `Sim` built with `wall_clock()` runs on the
real clock and has none of these controls; `time_rate(1.0)` gives a controllable clock that tracks
real time. With a `SimHost`, rate, value and pause apply to its timestamps, PHC samples and
`SO_TXTIME` alike. Scaled time follows real time, so it is not reproducible run to run.

On Windows, Rust sleep durations that exceed its signed 100 ns timer range reach the
simulated clock before conversion, including `std::thread::sleep(Duration::MAX)`. They
saturate at the clock's finite limit. Ordinary Rust sleeps retain the Windows timer grid;
native `Sleep(INFINITE)` and non-alertable `SleepEx(INFINITE)` still wait indefinitely.
This uses a typed hook on the linked Rust sleep implementation, following transparent entry
tail jumps. Entirely inlined implementations and separately linked std copies need their own
instrumentation. Hook installation errors are reported immediately.

## Executive

A simulation that drives the code under test from outside — sham inside theater — owns the sim's
clock through an `Executive`, in the same process: `sim.executive(ExecutiveConfig::default())` from any
thread, or `snare::sched::attach(cfg)` from a thread inside the run. Attaching fails with
`AlreadyAttached`, `NotInSim` (the free function off a sim's thread) or `WallClock` (a plain unix sim
on the real clock, which has no clock to own). From then until the executive drops, only it moves
time: there is no time skip on quiescence and no deadlock give-up — a wait nothing can satisfy waits
for the executive, and a deterministic schedule idles — and `pause_time`, `resume_time`,
`advance_time`, `set_time_rate`, `set_time_value` and their `TimeHandle` forms panic with "this
Sim's clock is owned by an Executive". The clock is frozen at its reading until the first grant.

| Call | Effect |
|---|---|
| `grant(Grant { anchor_v, anchor_wall, rate, horizon })` | Time runs from `anchor_v` at the real instant `anchor_wall`, `rate` virtual seconds per real second (in `[0, 1e6]`, NaN as 0), never past `horizon`. An anchor behind the clock anchors at the clock's reading, now. Timers the clock flows past fire as real time reaches them. |
| `freeze()` | Holds the clock where it is (horizon at the reading, rate 0). |
| `next_deadline()` | The earliest participant timer after the reading. Background timers are never jump targets; they fire as the clock passes them. |
| `jump_to(t)` | If the sim is quiescent — checked under the sim's locks in the same step as the move, so no participant starts running in between — moves the clock to `t` or to the earliest participant timer before it, exactly onto that deadline, and returns how many waits and events were due there; `Err(NotQuiescent)` changes nothing. The horizon rises to reach just past the landing — 1 ns, or one `QueryPerformanceCounter` tick on Windows — so a wait that recomputes a zero timeout at its deadline can creep over it on the latency its call is charged; the rate stays the grant's. Code that runs after the landing may therefore read up to that much past it. |
| `enter_timestamp(t)` / `leave_timestamp(t)` | The calling thread becomes the driver and acts at `t`: it reads exactly `t` from every clock and the code under test reads at least `t`, while the clock itself stands just before `t`, so timers at `t` are still pending. Participants released meanwhile — by what the driver sends, or by timers before `t` — wait at a gate, still counted blocked, until `leave_timestamp(t)` moves the clock to `t` (its horizon just past `t`, as for `jump_to`), fires what is due there (returning the count) and opens the gate. It wakes only waiters something reached: a timestamp at which nothing was sent and nothing came due leaves a quiescent sim quiescent. |
| `enter_timestamp_checked(t)` | As `enter_timestamp`, only if the sim is quiescent and no participant timer falls before `t`, checked in the same step; on `Err` nothing changes but the calling thread becoming the driver. |
| `with_driver_time(t, f)` | On a driver thread (a pool worker doing the executive's work), runs `f` reading `t` as the sim's time; its sends are held at the gate like the executive's own. |
| `quiescence()` | `quiescent`, the epoch, runnable/blocked participants, leases, `next_deadline`, and the first `blocker`: `Runnable` (a running participant, by name) > `Settling` (a woken waiter, a participant a futex, condition-variable, semaphore or `WaitOnAddress` wake released, one waiting for a pthread mutex that is now free, a joiner whose thread exited, or a participant the gate let go at the end of a timestamp, yet to run) > `Lease` (a busy lease) > `Setup` (only setup leases) > `Deferred` (held at the gate) > `TimerDue` (a timer at or before the reading its waiter has yet to take). |
| `arm_notify(epoch, f)` | Calls `f` once the epoch moves past `epoch` — a participant parking or waking, a lease taken or given back, a class change, a deterministic schedule going idle — on the thread that moved it, with no lock of the sim held. |
| `participants()` / `timers(n)` / `held_leases()` / `drain_hints()` | Every participant (lineage, name, running or blocked, for how long in sim and real time, what it waits in, its deadline, what it last waited in, the leases it holds) then one row per lease, with its `lease_kind`; the earliest timers, participants' before the others', with their owners' names; the leases with their kinds; the `hint_starving` hints since the last drain. |
| `outside_wakes()` | Unmatched returns from participants' native waits since the executive attached: nothing snare observed since quiescence explains the return. Always counted, with or without an audit. Spurious OS returns, such as those allowed by [WaitOnAddress](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitonaddress), can contribute; this is not proof that an unmanaged thread released the waiter. A run requiring every wake to be accounted for asserts it stays 0. |
| `audit()` | With `ExecutiveConfig { audit: true }` (or `SNARE_SCHED_AUDIT` set to anything but empty or `0`): background and helper threads' sim-visible effects (sends, connects, closes, futex/condvar/semaphore/address wakes, sleeps, `busy`), counted apart inside a `setup_scope`; the outside wakes; and every call the sim cannot model, as a violation. |
| `thread_census()` / `sim_id()` | Every OS thread of the process and whose it is (see [Thread census](#thread-census)); the sim's id. |

Dropping the executive (or `detach`) returns the clock to its base mode at its reading — never
backwards, and past an open timestamp's time — opens the gate, and time skips and deadlock give-ups
resume with the OS's own errors.

The gate holds participants leaving a sim wait (a socket, poll or sleep), a futex, a semaphore, a
`WaitOnAddress`, a condition variable or a join. A condition-variable wait woken inside a timestamp
lets go of its mutex while it waits at the gate and takes it back after, which the caller sees as an
ordinary wakeup. A contended mutex returns holding the code under test's lock, so it passes the gate
rather than risk blocking the executive's own threads on that lock. A participant already running when an unchecked `enter_timestamp` begins can see what the
driver does at `t` early, as can background threads, which the gate never holds. Under
`deterministic()` a timestamp also holds the schedule's baton: `enter_timestamp` waits for every
participant to block, `enter_timestamp_checked` takes it only if the schedule is idle, and
`leave_timestamp` hands it to the participants in the schedule's own order, whatever order the data
arrived in. A grant's rate runs as 0 there, with a one-time warning, so a deterministic run driven by
jumps and checked timestamps replays exactly; a flowing grant follows real time by design.

Outside `deterministic()`, a participant released by another thread's wake counts as `Settling` from
the wake until it runs: the futex, condition-variable, semaphore and `WaitOnAddress` hooks count,
before the OS wakes anyone, how many participants were parked on that address (up to the wake's
count), and an exit counts its joiners. A pthread mutex is judged by who holds it instead: the lock,
trylock and unlock hooks track the holder of every mutex a participant waits for, so a participant in
a contended lock is `Settling` only while that mutex is free or held outside the sim, and one woken
from a condition variable only while its mutex is free or its own. A holder that
re-takes the lock before the woken waiter runs, or that notifies and then sleeps holding the lock,
leaves the waiter blocked and the domain quiescent. A wake the OS hands to a thread that is not a
participant (a background thread waiting on the same address) leaves the parked participant counted
`Settling` until it next wakes, and a wake or unlock from a thread outside the sim is not seen at
all.

Whatever makes a participant runnable keeps the sim from being quiescent until that participant has
run: a datagram, bytes or a connection delivered to a socket it waits on (and any other readiness
change) marks every waiter woken as `Settling` until it has taken the lock again and re-checked — a
waiter that let go of the lock for a moment on its way back to sleep counts as asleep meanwhile, so a
wake landing then marks it too; an `Unparker::unpark` is such a readiness change; a futex,
condition-variable, semaphore or address wake counts as above; and a participant the gate held stays
counted until it has left its wait, so the next `enter_timestamp_checked` cannot slip in between the
gate opening and the participant running. A datagram still in flight is a timer at its arrival, not
a pending wake. A readiness change wakes only the waiters of the sim it belongs to (and threads
outside every sim): sims driven side by side by executives of their own never wake each other's
waiters, so none reads `Settling` because of a neighbour, and a jump made right after reading
quiescent goes through however busy the sims beside it are.

A driver time (`enter_timestamp`, `with_driver_time`) lapses on every thread when the executive is
dropped: the driver reads real time again.

Migrating sham and theater: sham and theater are the simulator and are never interposed. Theater
builds the `Sim` (seed from `SimBuilder::seed`) and hands it to sham's `SnareDomain::new(&sim, cfg)`,
which owns the clock through `sim.executive(cfg)` in place of the old `attach_driver`, before the code
under test starts. The code under test (conductor) runs inside `sim.run`; everything theater does
with sham, and every thread sham starts, runs under `snare::real`, so none of it joins the sim and
nothing marks thread classes or uses driver time. Theater talks to the code under test only through
the `Sim` API: its network (testers, or emulator threads woken from outside), faults and time.
There is no global slot or `register_test`, and no environment handshake; the thread census is
`sched::thread_census()` (below).

### Thread census

`sched::thread_census()` (also `Sim::thread_census`, `Executive::thread_census`) lists every OS
thread of the process — read from `/proc/self/task` on Linux, `task_threads` on macOS and a Toolhelp
thread snapshot on Windows — as a `CensusThread { os_id, name, owner }`, where `owner` is
`ThisSim(class)` for the calling thread's (or that) sim, `OtherSim(id, class)` for another sim's,
`Snare` for snare's own service threads (the link-delay and timer wakers, an executive's flow thread,
a stuck watchdog, the signal forwarder) and `Unmanaged` for everything else: the test harness, a
thread started outside every sim or under `snare::real`, one a runtime started for itself.
`ThreadCensus::unmanaged()`, `this_sim()` and `other_sims()` filter it. A thread counts as a sim's
from its own first line in the sim until it leaves, so one being created or exiting can read as
unmanaged for that moment; a run that fails on unknown threads should want one found unmanaged in
two censuses in a row, as theater's tracker did with snare v1.

## Cooperative primitives

`snare::sched` has the blocking and future primitives a simulation's own runtime (sham's
participants) is written against. In a sim they run on its clock and its schedule; off one, on real
time.

| Call | Effect |
|------|--------|
| `park(deadline)` / `current_unparker()` | Blocks until the thread's `Unparker` fires or the deadline passes (`ParkResult::Unparked` / `TimedOut`). An unpark that came first is consumed and returns at once. In a sim the park is a sim wait: it counts toward quiescence, its deadline (an `Instant`, read on the sim's clock) is a timer a time skip or an executive's jump lands on, a wake during an executive's timestamp is held at the gate, and under `deterministic()` it waits in the schedule. A participant parked with no deadline while nothing in the sim can move keeps waiting, as a join does. `Unparker::unpark` and `Unparker::waker()` work from any thread. |
| `block_on(f)` / `block_on_until(f, deadline)` / `block_on_timeout(f, d)` | Polls `f`, parking between polls with the thread's `Unparker` as the waker. Past the deadline `f` is polled once more, so an output ready at the deadline is not lost; a timeout past the end of the clock is no deadline. |
| `sleep_until(instant)` → `Sleep` | A future that completes when the clock reaches the instant: on its first pending poll its waker becomes a timer of the calling thread's class (a participant's steers time skips, a background thread's fires as the clock passes it or, once every participant waits on what only such a thread can do, steers them too), which the discrete time skip, `Executive::jump_to`, a flowing grant, a scaled clock reaching it (a real-time waker set for the real arrival) or a clock writer fires. Later polls replace the waker; dropping it, or completing, removes the timer. `is_elapsed()` checks the clock. On an as-fast-as-possible clock waiting on it jumps the clock to the instant, as a sleep does. Any waker works, not only `block_on`'s: a hand-rolled executor blocking in a channel receive or a condition variable between polls is woken at the instant, under `deterministic()` too. The clock runs the wakers it fires on a thread of its own, outside the sim. |
| `WakerSet` | The wakers of every task waiting on one piece of state: `register` before checking the state, `wake_all` after changing it. |
| `is_driven()` | The calling thread is a participant and the sim's clock is virtual (discrete, scaled, paused or owned by an executive). |

A driver thread outside an executive's timestamp reads real `Instant`s, so its `Sleep`s and park
deadlines are on real time; such threads should time their waits with real-time timers, or under
`with_driver_time`.

## Tester stages

Each message the code under test sends a tester runs through the tester's stages in the order they
were added:

| Stage | Effect |
|---|---|
| `then_test(\|msg, from\| Option<P>)` / `then_stateful_test` | `Some` passes that message — rewritten or not — to the stages after it; `None` drops it there. |
| `then_edit_state(\|state, from\| ..)` | Updates the tester's state, then passes the message on unchanged. |
| `then_action(\|msg, from\| TesterAction)` / `then_stateful_action` | Acts on the message at once; later stages still see it. |

A stage added before a dropping test has already run for that message. `recording()` keeps what the
code under test sent, before any stage sees it, and `on_connect` and cyclic actions do not go through
the chain. Stages added before `with_state` keep working without the state.

### Framing

A tester's message type says how the byte stream is cut into messages (`Packet::parse`). Besides
`Bytes` (whatever each read returns) and `Line` (`\n`-ended text), two framings cover most device
protocols without a hand-written `Packet`; both keep the raw frame (`frame()`) and send frames as
they are:

| Type | Frame |
|---|---|
| `Delimited<D>` | Up to and including the first `D::DELIMITER`: `Lf`, `Cr`, `CrLf`, or any byte string on a marker type implementing `Delimiter`. `Delimited::new(body)` appends the delimiter; `body()` / `text()` drop it. |
| `LengthPrefixed<L>` | `L::FIELD: LengthField { offset, width, endian, adjust }`: the unsigned `width`-byte (1, 2, 4, 8) field at `offset`, `Endian::Big` or `Little`, plus `adjust`, is the whole frame's length — `adjust` is the header and trailer size when the field counts the payload, 0 when it counts the whole frame. |

```rust
/// [0x02][type][len: u16 LE][payload][0x03]: the length counts the payload only.
struct Gcom;
impl FrameLength for Gcom {
    const FIELD: LengthField = LengthField { offset: 2, width: 2, endian: Endian::Little, adjust: 5 };
}
let tracker = connect_tester::<LengthPrefixed<Gcom>>("10.0.0.5:820");
let robot = connect_tester::<Delimited<CrLf>>("10.0.0.6:16001");
```

Over TCP a frame split across reads waits for the rest and several frames in one read come out one
by one. Over UDP each datagram is parsed on its own: it may carry several frames, a frame never
spans datagrams, and an incomplete tail is dropped with its datagram (with `Bytes`, one datagram is
one message). A `LengthPrefixed` field giving a frame shorter than the field's own end panics the
tester, which fails the test.

### Cyclic actions and phase

`with_cyclic_action(period, ..)` runs first one period into the run, then every period;
`with_cyclic_action_at(period, phase, ..)` runs at `phase`, `phase + period`, ... — so two emitters on
an 8 ms cycle with phases 4 ms and 8 ms tick exactly half a cycle apart. Every tester in one
`run_testers!` is phased from the same start, read on the sim's clock, and the next tick is always
the previous one plus a period, so ticks do not drift. `with_stateful_cyclic_action[_at]` adds the
tester's state.

### Per-connection state

`with_state(S)` is one value for the whole tester. `with_conn_state(|peer| C)` adds one value per
peer, made as it appears — per TCP connection accepted (a reconnect starts fresh), per UDP source
address — and the `conn` methods see it beside the tester's state:

| Method | Sees |
|---|---|
| `then_conn_action(\|conn, state, msg, from\| ..)` / `then_conn_test` | The sender's `C`; stages in the same chain as the others. |
| `on_conn_connect(\|conn, state, from\| ..)` | The new peer's `C`, just made. |
| `with_conn_cyclic_action[_at](period, [phase,] \|conn, state, peer\| ..)` | Each tick, once per live peer (open connections, every UDP source) in the order they appeared, with its `C`; a plain `Send` goes to that peer only. A plain cyclic action sees no `C` and sends to every peer. |
| `until_conns(\|state, conns\| bool)` / `inspect_conns(\|conns\| ..)` | Every peer's `(SocketAddr, C)` of the run, closed connections included, kept until the next run. |

`with_state` and `with_conn_state` go in either order, and stages added before either keep working
without it.

## Recorded events

Every `Sim` keeps one log of what happened at the edge of the code under test, readable with
`snare::recorded_events()` from any of its threads or `sim.recorded_events()` from anywhere, during
the run or after it. Each `RecordedEntry` has `at`, sim time (`time_value()`) without ticking the clock
(real time since the sim was built on a plain `wall_clock()` sim), a `seq` that only ever grows, and
the `RecordedEvent`:

| Event | Logged when |
|---|---|
| `Accepted` | a TCP tester accepts a connection, before `on_connect` runs. |
| `Received { transport, len }` | a tester parses a message; `len` is the bytes it was parsed from. |
| `Sent { transport, len }` | a tester's bytes go toward the code under test. |
| `Closed` / `Reset` | a tester closes or resets a connection, once, including the closes at the end of its run. |
| `PeerClosed` / `PeerReset` | the tester reads end-of-stream, or a reset it did not cause. |
| `Quiesced { span }` / `Suppressed { toward, len }` | a tester goes silent toward a peer, and each message it then drops in either direction. |
| `Link { from, to, len, fault }` | a `UdpPolicy` loses a datagram, drops it for its MTU (`TooBig`) or duplicates it. A perfect link logs nothing. |
| `UdpPolicyChanged` / `TcpPolicyChanged` | `set_udp_policy` / `set_tcp_policy`, with the policy now in force. |
| `Fault { addr, fault }` | an injected fault takes effect on the code under test: `Error { errno, call }` when a call reports a raised error, `IcmpPortUnreachable { from }` when a call reports an ICMP error, `Stalled { span, direction }` when `quiesce` holds a link, `Unreachable { errno }` when a send or connect finds no route or a connect finds no neighbour, `LinkDown { nic }` when a send leaves through an interface without carrier; `Fault::Dns { name, failure }` when a `DnsPolicy` fails a lookup; `ConnectRefused` (a `Refusing` listener), `ConnectTimedOut` and `ConnectDelayed { until }` when a connect that waited on its SYN ends. |
| `NicChanged { nic, admin_up, carrier }` | an interface is added, removed, or changes admin state or carrier (a scheduled change logs when it takes effect). |
| `Signal { signal, origin, delivery }` | a signal or console control event reaches the code under test, sent by the test (`Sim`), the code itself (`Process`) or forwarded from the real process (`Real`). |
| `UnmodelledOption { socket, local, option, refused }` | the code under test first uses, on that socket, a socket option or ioctl the sim does not model; `refused` under `strict_sockopts`. See [Unmodelled options](#unmodelled-options-and-strict_sockopts). |

`clear_recorded_events()` starts a fresh phase (sequence numbers carry on), and
`SimBuilder::record_events(false)` keeps nothing, for a long, chatty run. Recording never moves the
clock, yields or wakes a thread, so a `deterministic()` run logs the same entries, in the same order,
with the same stamps, every time, and logs or not without changing the run; on the free-running
virtual clock, events from different threads at the same instant may come out in either order.
Coming from the original snare: `UdpSendFromTest { dropped }` is a `Sent` followed by a
`Link { fault: Lost | TooBig }`.

## Packet capture

`Sim::builder().pcapng(path)` writes every frame that crosses the sim's network to a pcapng file,
created (or truncated) at `build` — which panics if it cannot be — and finished when the `Sim`
drops. `Sim::pcapng_path()` says where. With no explicit path, setting `SNARE_PCAPNG_DIR=<dir>`
captures each sim to `<dir>/<building thread's name>.pcapng` (`:` becomes `-`, other characters
outside `[A-Za-z0-9._-]` `_`, and a second sim built by the same thread gets `-2`, then `-3`); if
that file cannot be written the sim warns on stderr and runs without capture.

To capture chosen tests without touching their code, set `SNARE_PCAPNG_TESTS` to a comma-separated
list of test thread names — cargo names each test's thread after its path, `module::test` — and
only sims built on a listed thread are captured, to `SNARE_PCAPNG_DIR` if set and otherwise to
`snare-pcapng` in the temporary directory, each saying where on stderr. An entry matches the whole
name or its last `::` segments, so `my_test` lists `tests::my_test`; a blank list counts as unset.
An explicit `pcapng(path)` is captured either way.

```console
$ SNARE_PCAPNG_TESTS=my_test,other_mod::another_test cargo snare test
```

Stamps are always the sim's clock. `SimBuilder::pcapng_wall_comment(true)`, or
`SNARE_PCAPNG_WALL_COMMENT` set to anything but empty or `0`, also writes the real wall time each
frame was sent at as its EPB's `opt_comment` (draft-ietf-opsawg-pcapng §3.5), in UTC as
`wall 2026-10-02T09:15:42.123456789Z`, to line a capture up with logs kept on real time; a frame
due after it was sent (an ACK after latency, a planned retransmission) carries the real time it was
written, when the capture first saw the sim's clock reach it. Wireshark lists it as the packet's
comment. The comments make the file differ from run to run.

The sim has no real frames, so capture fabricates them, once per frame at its sender:

| Traffic | Frames |
|---|---|
| TCP connect | `SYN`, `SYN\|ACK`, `ACK` when it is accepted; `SYN` then `RST\|ACK` when refused; a connect that waits shows the host OS's SYN retransmissions at their plan points up to the answer, and nothing for a timeout. A refused connect still takes an ephemeral port. |
| TCP data | Each accepted write as MSS-sized `PSH\|ACK` segments (MSS = egress MTU − 40, − 60 for IPv6), and the receiver's `ACK` stamped when the bytes arrive (`TcpPolicy` latency, a stalled or down link). On macOS, data reaching a TCP endpoint after `SHUT_RD` gets a reset instead of an ACK. |
| TCP close | `FIN\|ACK` from `shutdown(SHUT_WR)`, the last close or a tester's close, once per end, with the peer's `ACK` when the last byte in flight arrives; `SHUT_RD` itself sends nothing. `RST\|ACK` from a tester's `Reset`, `SO_LINGER` 0, a closing listener's unaccepted connections or incoming TCP data after macOS read shutdown. |
| UDP | Each datagram at its sender — fabric, Winsock fabric, `SimHost` (stamped with its `SO_TIMESTAMPING` TX stamp) and tester endpoints — before any link policy, so loss and duplication never change the count and a frame lost on a down link is still there. A send refused (`EAGAIN`, `EACCES`, no route) writes nothing. |
| ICMP | A port unreachable (ICMPv6 type 1 code 4) from the unreachable address, stamped when the datagram got there; an injected one at once. |
| Raw L2 | `AF_PACKET` writes, `/dev/bpf*` writes and npcap sends, verbatim on their interface. |

Frames are Ethernet II with IPv4 (DF, a per-source ID, TTL 64, or 128 on Windows) or IPv6 (v4-mapped
addresses are written as IPv4), real IP/TCP/UDP/ICMP checksums, an MSS option on `SYN`s and a
window of 65535. Sequence numbers start from a per-connection ISN drawn from the sim's seed and the
connection's addresses. MACs are all zero on loopback, the group address for broadcast and
multicast, the owning interface's `NicSpec::mac` for the host's addresses, and a locally
administered hash of the address otherwise. Each interface a frame crosses gets an interface block,
named after it, the first time it is used; stamps are nanoseconds of the sim's `CLOCK_REALTIME`
(real time on a plain `wall_clock()` sim); `epb_flags` marks frames the code under test sent as
outbound and its testers' as inbound.

Frames due later (a retransmission, an ACK after latency) wait until the sim's time reaches them,
and the file is complete after each write. A waiting connect's planned retransmissions, and every
frame after them, stay unwritten until the connect has played those points of its plan, so a
nonblocking connect checked late still shows only the SYNs before its answer, and its handshake at
the plan point that answered it; a connect left waiting holds the rest of the capture until it is
answered, closed or the sim drops. Frames are written in time order: one stamped before a frame
already written (a sender that read its stamp just before another thread wrote) takes that frame's
stamp. On Windows, a refused connect keeps probing for the host's refusal window; the capture shows
each `SYN` with the `RST|ACK` answering it, and the handshake if a listener appears in time.

Capture only observes: it never moves the clock, yields, wakes a thread or draws from the seed, so a
run behaves the same with or without it, and under `deterministic()` the same seed writes the same
bytes (wall-time comments aside). Keep the file on a local disk — a slow write holds up the thread that sent the frame.

## Interfaces and routing

Every `Sim` has one topology of interfaces, addresses and routes, shared by the fabric, the Winsock
fabric and a `SimHost`'s UDP sockets. It holds host facts only; what the host does with them —
error codes, strong or weak host, what happens to a link that loses carrier — is the build host's.

```rust,no_run
use snare::{IpNet, NicPolicy, NicSpec, Route, Sim};
use std::time::Duration;

let sim = Sim::builder()
    .nic(
        NicSpec::new("eth0")
            .address("10.0.0.1/24".parse::<IpNet>().unwrap())
            .station("10.0.0.2".parse::<std::net::IpAddr>().unwrap())
            .policy(NicPolicy { latency: Duration::from_micros(80), ..Default::default() }),
    )
    .route(Route::new("192.168.0.0/16".parse::<IpNet>().unwrap(), "eth0").gateway([10, 0, 0, 254]))
    .build();
sim.run(|| {
    snare::schedule_link("eth0", Duration::from_secs(2), false).unwrap(); // the cable comes out
});
```

- **Default topology.** Loopback at index 1 (`lo` / `lo0` / `Loopback Pseudo-Interface 1`, with
  `127.0.0.0/8` and `::1`, MTU 65536 / 16384 / 4294967295) and `sim0` at the next free index with
  no addresses and the default routes (`0.0.0.0/0`, `::/0`, metric 100). A `SimHost` that declares
  interfaces registers them instead (`Nic::network`, `Nic::station`, `Nic::policy`, `link_stats`
  as the counters' start). Initial carrier follows `operstate == "up"` unless `Nic::carrier`
  overrides it; `.operstate("unknown").carrier(true)` represents an unknown-but-up interface.
  The default routes leave through its lowest one
  unless `HostProfile::route` declares its own.
- **Open, then routed.** Until an interface has an address, the sim is open: binding any address
  claims it for the host (on `sim0`), so tests that bind whatever they like keep working. Once one
  does, the code under test binds only the host's addresses (127/8 always), broadcast and multicast
  addresses, and the interfaces' `stations`; anything else is `EADDRNOTAVAIL` / `WSAEADDRNOTAVAIL`.
- **Who is where.** An address is the host's, a station's (a tester endpoint or listener bound there,
  or a `NicSpec::stations` address an in-process socket binds — on the segment, across the link,
  never reached through a host wildcard bind), or nobody's.
- **Routing.** Every send and connect resolves a path: a bound device first (Linux
  `SO_BINDTODEVICE`/`SO_BINDTOIFINDEX` use the device even with no route; macOS
  `IP_BOUND_IF`/`IPV6_BOUND_IF` use scoped routes only, `ENETUNREACH` on a miss, `ENETDOWN` when it
  is down; Windows `IP_UNICAST_IF`/`IPV6_UNICAST_IF` for unicast), then `IP_MULTICAST_IF` or the
  source's interface for multicast, local delivery through loopback for the host's own addresses,
  then the longest prefix through a live interface (ties: the bound address's interface, the lowest
  metric, the earliest route). Each interface address brings its connected subnet. No route is
  `ENETUNREACH` (macOS `sendto` from a specific address: `EHOSTUNREACH`; Windows `WSAENETUNREACH`) and logs
  `Fault::Unreachable`. A loopback source leaving the host is `EINVAL` on Linux and
  `EADDRNOTAVAIL` on macOS; Windows is a strong host, so a bound address only leaves through its own
  interface (`WSAENETUNREACH`, as measured) and only receives there.
- **Sources and delivery.** An unconnected wildcard or unbound UDP socket keeps its wildcard local
  address and each datagram carries the route's source; a TCP client's local address is the
  route's source. A UDP `connect` from the wildcard (or unbound) takes the route's source address,
  v4-mapped on an IPv6 socket, and the socket then receives only there, as every host does
  (`getsockname` reports it). Connecting again keeps that address on Linux; macOS and Windows
  dissolve the association first and pick anew. Dissolving it (`connect` to an `AF_UNSPEC`
  address; on Windows also the all-zero address) follows the host: Linux returns to the wildcard
  unless `bind` named an address and gives up the port unless `bind` named one (the next send or
  connect takes a new one); macOS returns to the wildcard, keeps the port and fails with
  `EAFNOSUPPORT` (`EINVAL` for an address shorter than the family's); Windows returns to what
  `bind` named, keeps the port, and refuses an address shorter than the family's with
  `WSAEFAULT`. `tests/udp_connect_source.rs` compares this with the real host. A datagram
  reaches the exact bind, else a wildcard bind only for the host's own addresses; a directed
  broadcast reaches its subnet's stations and the host's wildcard binds; a socket bound to a device
  only receives what arrives on it. Recipients are served in (port, address) order.
- **Multicast.** A group's datagram reaches, on its port, every socket that joined the group. On
  Linux a socket also receives the groups any socket of the host joined while `IP_MULTICAST_ALL`
  (`IPV6_MULTICAST_ALL`) is on, the default; turning it off leaves only its own joins. macOS and
  Windows deliver joined groups only. On Linux and macOS the socket must be bound to the wildcard or
  the group itself. `tests/multicast_os_truth.rs` compares this with the real host. Which interface
  a join named is not matched against the arriving one, `IP_DROP_MEMBERSHIP` is not modelled, and
  one exact address takes one socket (`SO_REUSEADDR`/`SO_REUSEPORT` sharing is not modelled).
- **Bind to device from the test.** `set_socket_device(id, Some(nic))` (or `None`; also
  `Sim::set_socket_device`) binds an open socket as the host's option would, with that option's
  error for an unknown name (`ENODEV`, `ENXIO`, `WSAEINVAL`) and no privilege check.
- **Link state.** `set_link`, `set_nic` and `schedule_link` (a deadline on the sim's clock, so a
  thread blocked on the link wakes when it changes, under every clock and `deterministic()`). With
  carrier down, Linux and macOS keep routes: sends succeed and the frame is dropped
  (`tx_dropped`, `tx_carrier_errors`, `Fault::LinkDown`), inbound is lost, and a datagram in flight
  across a flap is discarded. Windows media sense withdraws the interface's routes and addresses.
  Admin down withdraws routes (Linux keeps the addresses bindable, as measured; macOS answers
  `ENETDOWN` to sockets bound there). TCP over a dead link stalls: writes succeed, bytes wait in
  flight and arrive in order once the link returns (or the interface is removed); a blocked read
  with nothing scheduled gives up like any quiescent wait. Raw L2 frames do not cross a dead link,
  an oversized frame is `EMSGSIZE`, and Linux `AF_PACKET` on a down interface is `ENETDOWN`.
- **`NicPolicy`.** Latency, jitter, loss and duplication on traffic crossing the interface (host to
  station, station to station), never host-local traffic, drawn from the sim's seed in a fixed order
  (loss, duplication, jitter, then the address's `UdpPolicy`); delays add and losses compound. TCP
  takes the latency and jitter per write, in order, without loss. With no policy set, draws are
  exactly as before.
- **Counters.** `nic_counters(name)` counts frames with their headers (UDP +42 / +62 bytes, TCP
  segments of at most MTU-40 bytes +54 / +74); loopback traffic counts on loopback;
  `set_nic_counters` edits them.

`add_nic`, `remove_nic`, `set_nic`, `set_link`, `schedule_link`, `set_nic_policy`,
`set_nic_counters`, `nic`, `nics`, `nic_counters`, `add_route`, `remove_route`,
`set_default_route`, `routes` and `route_lookup` work from any thread of a sim, and as `Sim`
methods from anywhere. `tests/nic_os_truth.rs` compares the error codes against the real host.

### Enumerating interfaces

Every way the code under test can list interfaces reads the same topology, so `set_link`,
`set_nic` and the counters show up everywhere at once:

- **libc (Linux, macOS).** `if_nametoindex`, `if_indextoname`, `if_nameindex`/`if_freenameindex`,
  and `getifaddrs`/`freeifaddrs`: one `AF_PACKET` (Linux, `ifa_data` a `rtnl_link_stats`) or
  `AF_LINK` (macOS, an `if_data`) entry per interface, then one `AF_INET`/`AF_INET6` entry per host
  address with netmask and broadcast, in index order (glibc lists the link entries first). Stations
  are not listed. Flags follow the link: `IFF_UP` while admin up, `IFF_RUNNING` (and Linux
  `IFF_LOWER_UP`) with carrier. Unknown names fail as the host's libc does (`ENODEV` from glibc,
  `ENXIO` on macOS; pinned by `tests/nic_enumeration.rs` against the real call).
- **ioctls on any socket.** Linux `SIOCGIFINDEX`, `SIOCGIFMTU`, `SIOCGIFFLAGS`, `SIOCGIFHWADDR`;
  macOS `SIOCGIFFLAGS`, `SIOCGIFMTU`. An interface without a configured MAC has `02:00:<index>`.
- **`SimHost`.** `/sys/class/net/<if>/{mtu,ifindex,operstate,carrier,flags,address,statistics/*}`
  (reading `carrier` of an admin-down interface is `EINVAL`, as `carrier_show`), rtnetlink
  `RTM_GETLINK` (flags, `IFLA_OPERSTATE`, `IFLA_CARRIER`, `IFLA_MTU`, `IFLA_ADDRESS`,
  `IFLA_STATS64`), `RTM_GETADDR` and `RTM_GETROUTE` dumps, and macOS `sysctl` `NET_RT_IFLIST2` all
  render the topology, loopback included. `ethtool`, hardware timestamping, queues, IRQs and PTP
  stay the host profile's (see [NIC drivers](#nic-drivers-ethtool-qdiscs-threaded-napi)).
- **Windows IP Helper.** `if_nametoindex`/`if_indextoname` (NDIS names such as `ethernet_32772`,
  `loopback_0`), the `ConvertInterface*` alias/name/LUID/index conversions, `GetIfEntry2`,
  `GetIfTable2`, `GetUnicastIpAddressTable`, `FreeMibTable`, `GetAdaptersAddresses` (with the
  `ERROR_BUFFER_OVERFLOW` size handshake) and `GetBestRoute2`, rendered through the `windows-sys`
  types. `OperStatus`/`MediaConnectState` follow the link, octet and packet counters follow
  traffic, and addresses are listed only with carrier (media sense). Tables the sim hands out are
  freed by `FreeMibTable`; any other pointer goes to the real one.

### NIC drivers: `ethtool`, qdiscs, threaded NAPI

On Linux a `SimHost` interface has a driver, declared on its `Nic` the way old snare's `NicCaps`
and `DriverSeed` did, and `SIOCETHTOOL` runs against it as net/ethtool/ioctl.c `__dev_ethtool`
does (Linux 6.12): a command outside the kernel's read-only list needs `CAP_NET_ADMIN` (`EPERM`,
checked first), an operation the driver lacks is `EOPNOTSUPP`, and the core's own checks run
before the driver's. What the code under test sets persists; `SimHost::ethtool(nic)` returns it
all as a `NicEthtool`.

| Command | `Nic` builder | Rules |
|---|---|---|
| `GDRVINFO` | `driver`, `bus_info`, `firmware`, `expansion_rom`, `register_dump_len`, `eeprom_len`, `private_flags_count` | dump lengths and private-flag count default to zero; `n_stats` from driver statistics |
| `GLINK` | — | admin up with carrier, from the topology |
| `[GS]RINGPARAM` | `rings(Rings { .. })` | each size within its maximum (`EINVAL`); the `*_max` given are ignored |
| `[GS]COALESCE` | `coalesce(CoalesceParams, Coalesce)`, `coalesce_limits` | a non-zero field outside `supported_coalesce_params` is `EOPNOTSUPP`; above the driver's limits `EINVAL` |
| `[GS]CHANNELS` | `channels(Channels { .. })` | no change succeeds at once; counts within maxima, at least one RX and TX queue, not below a queue a flow rule uses (`EINVAL`); the queue count (`/sys/class/net/<if>/queues`) follows |
| `[GS]PAUSEPARAM`, `[GS]EEE` | `pause`, `eee` | an EEE mode outside `supported` is `EINVAL` |
| `[GS]FLAGS` | `ntuple(slots)` makes `ETH_FLAG_NTUPLE` settable | unknown flags `EINVAL`; a change outside `hw_features` `EOPNOTSUPP` |
| `GRXCLSRLCNT`/`GRXCLSRULE`/`GRXCLSRLALL`/`SRXCLSRLINS`/`SRXCLSRLDEL` | `ntuple(slots)` | as igb: a slot past the table, a missing queue or an empty slot `EINVAL`, a short `rule_locs` `EMSGSIZE` |
| `GSSET_INFO`/`GSTRINGS`/`GSTATS` | `driver_stats([(name, value)])`, `SimHost::set_driver_stat` | none declared: `EOPNOTSUPP`, as a driver without statistics |

rtnetlink `RTM_NEWQDISC`/`RTM_DELQDISC` change the qdiscs `RTM_GETQDISC` dumps (every interface, in
index order). Multiqueue goes by the transmit queues the driver allocated (`num_tx_queues`:
`Nic::tx_queues_allocated`, else the channel maxima), not those in use (`real_num_tx_queues`, the
`queues/` listing): a multi-queue interface starts with `mq` over one default qdisc per allocated
queue (`pfifo_fast` past the queues in use) and the dump lists the queues in use and any qdisc
created with a handle, as net/sched/sch_mq.c `mq_attach` hashes them; a single-queue one starts with
the default qdisc, and an `IFF_NO_QUEUE` one (`Nic::no_queue`, veth) with `noqueue`. Replacing the
root or an `mq` class's qdisc follows net/sched/sch_api.c `tc_modify_qdisc`
(`NLM_F_CREATE`/`NLM_F_REPLACE`/`NLM_F_EXCL`, automatic handles from `8001:`), `mq` needs more than
one allocated queue (`EOPNOTSUPP`), and `etf` checks its parameters as `etf_init` does
(`CLOCK_TAI` only, a dynamic clock `ENOTSUPP` (524)); `TC_ETF_OFFLOAD_ON` needs `Nic::etf_offload(queues)`
(`EOPNOTSUPP` without, `EINVAL` on another queue, as igb on an I210). Changes need `CAP_NET_ADMIN` and
are acked with `NLMSG_ERROR` when `NLM_F_ACK` asks. `/sys/class/net/<if>/threaded` reads and, for
root, writes the threaded-NAPI switch (`Nic::threaded_napi`): `EPERM` without `CAP_NET_ADMIN`,
`EOPNOTSUPP` for a value other than 0 or 1. `EasyBuilder` presets ship an I210-like driver with all
of the above. Tests: `tests/simhost_ethtool.rs`.

### Windows adapter properties and restarts

Windows tunes an adapter through its device node, not an ioctl: a program enumerates the network
class with `SetupDiGetClassDevsW`/`SetupDiEnumDeviceInfo`, opens the driver key with
`SetupDiOpenDevRegKey(DIREG_DRV)`, matches its `NetCfgInstanceId` to the interface GUID IP Helper
reports, writes standardized keywords (`*ReceiveBuffers`, `*InterruptModeration`, `*FlowControl`,
`*NumRssQueues`, `*RSS`, `*SoftwareTimestamp`, EEE names) as `REG_SZ` values, reads their limits
from `Ndi\Params\<keyword>\max`, and restarts the device with `CM_Disable_DevNode` +
`CM_Enable_DevNode` (fast-talker's `nic/windows.rs` does exactly this). Every one of those calls is
in-process, so the Windows `Sim` serves them: each non-loopback interface is a device node whose
two keys (`DIREG_DRV`, and `DIREG_DEV`'s `Device Parameters`, where the interrupt affinity policy
lives) are an in-memory registry that keeps what the code under test writes.

- **Describe it.** `SimBuilder::adapter(nic, Adapter::new().property("*ReceiveBuffers", "512",
  Some(4096)).without_property("*RSS").driver_version("..").restart_flap(d))`, or
  `Sim::set_adapter` later. The default `Adapter::new()` mirrors snare 1.x's `NicCaps`: rings 256
  of 4096, interrupt moderation on, flow control Rx & Tx, 4 of 8 RSS queues, RSS on, software
  timestamping off, no EEE keyword, 2 s flap.
- **Read it back.** `Sim::adapter_property(nic, keyword)`, `Sim::adapter_value(nic,
  AdapterKey::{Driver, Device}, path, name) -> Option<RegValue>`, `Sim::adapter_restarts(nic)`.
- **Restart flap.** `CM_Disable_DevNode` drops the interface's carrier; `CM_Enable_DevNode`
  schedules it back up `restart_flap` later on the sim's clock (`schedule_link`), so
  `GetIfEntry2`'s `OperStatus`, media sense and the sockets all see the outage, under the virtual
  clock and `deterministic()`. An interface that had no carrier stays down.
- **Elevation** is `Privileges::root`. A standard user may read the keys but gets
  `ERROR_ACCESS_DENIED` opening one for writing or creating a subkey, and `CR_ACCESS_DENIED` from
  the `CM_*` calls. A write through a handle opened `KEY_READ` is `ERROR_ACCESS_DENIED` for anyone.
- **Codes.** Missing value or key `ERROR_FILE_NOT_FOUND`, short buffer `ERROR_MORE_DATA` with the
  size, a buffer without a length `ERROR_INVALID_PARAMETER`, enumerating past the end
  `ERROR_NO_MORE_ITEMS`, a wrong `cbSize` `ERROR_INVALID_USER_BUFFER`, a bad key type
  `ERROR_INVALID_FLAGS`; `tests/nic_adapter_props_win.rs` (`registry_codes_os_truth`,
  `setupapi_codes_os_truth`) compares them with the real registry and SetupAPI.
- **Passthrough.** Only the sets, keys and device instances the sim minted (and the network-class
  enumeration that mints them) are simulated; every other registry key, device class or `DEVINST`
  goes to the real API. A sim handle passed to a SetupAPI call that is not hooked reaches the real
  one. `CreateFileW(\\.\{GUID})` for NDIS statistics is not modelled (it fails, as for a virtual
  adapter), so driver counters come from `GetIfEntry2` alone.

The `WinHost` also keeps the process's working set: `SetProcessWorkingSetSizeEx` /
`GetProcessWorkingSetSizeEx` (fast-talker's `reserve_working_set`) never touch the real process.
Measured on Windows 11: a new process has 204 800 / 1 413 120 bytes with both limits soft; bounds
round down to 4 KiB and the minimum is raised to 20 pages; min above max, or `ENABLE` and
`DISABLE` of one limit together, is `ERROR_INVALID_PARAMETER`; a minimum beyond the machine is
`ERROR_NO_SYSTEM_RESOURCES` (the sim has 16 GiB and refuses above 7/8 of it); flags 0 keep the
limits' state; both bounds `(SIZE_T)-1` trims and succeeds. Raising either bound needs
`SeIncreaseWorkingSetPrivilege`, whose stand-in is `ipc_lock` (`ERROR_PRIVILEGE_NOT_HELD`
without it). `Sim::working_set()` reads it back; `working_set_os_truth` compares with the real OS.

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
retires the description. Remaining descriptor boundaries are listed in [open bugs](OPEN_BUGS.md).
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
`WSAESHUTDOWN`; and a bind overlapping a wildcard or equal address follows each OS's `SO_REUSEADDR`
rule (`tests/bind_os_truth.rs` compares the sim against the host).

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
read back as well (with Windows' default until set, such as `IP_MULTICAST_LOOP` on and `IPV6_V6ONLY`
on), listed, and refused under `strict_sockopts()` with `WSAEINVAL` at `SOL_SOCKET` and
`WSAENOPROTOOPT` elsewhere, the codes Winsock gives an option it does not know (measured). An option
Winsock does not define fails with those codes with or without strict mode, as does an
`ioctlsocket` command other than `FIONBIO`, `FIONREAD` and `SIOCATMARK` (`WSAEOPNOTSUPP`, measured).
A `WSAIoctl` code the sim does not carry out cannot succeed without effect, since only the OS could
fill its output: it fails with `WSAEOPNOTSUPP` and is listed as refused. `SO_SNDLOWAT`,
`SO_RCVLOWAT` and `SO_USELOOPBACK` fail `WSAEINVAL`, as Microsoft documents. A level the socket does
not take fails first: `IPPROTO_IPV6` on an IPv4 socket (`WSAEINVAL`), `IPPROTO_TCP` on a datagram
socket and `IPPROTO_UDP` on a stream (`WSAENOPROTOOPT`); `SO_KEEPALIVE` is stream-only.

The harmless options are kept and read back but change nothing, because nothing a test can observe in
the sim depends on them: `SO_KEEPALIVE` and the TCP keepalive timers (no connection dies idle),
`TCP_NODELAY` and Linux `TCP_QUICKACK` (no Nagle or delayed ACKs), `SO_OOBINLINE` and `SO_DEBUG`, macOS
`SO_NOSIGPIPE` (the sim never raises `SIGPIPE`; std sets it on every socket), and `IP_TOS`, `IP_TTL`,
`IP_MULTICAST_TTL`, `IPV6_TCLASS`, `IPV6_UNICAST_HOPS`, `IPV6_MULTICAST_HOPS` (no QoS or hop count);
`FIOCLEX`/`FIONCLEX` for ioctls. Windows keeps the same, read back from Windows' defaults until set
(`IP_TTL` and `IPV6_UNICAST_HOPS` 128, the multicast hop limits 1, the TCP keepalive timers 2 hours,
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

Everything else the sim does not model — `SO_REUSEPORT`,
`IP_MULTICAST_LOOP`, `IP_DROP_MEMBERSHIP`, `IPV6_V6ONLY`, `SO_RCVLOWAT`, `SIOCGSTAMP` and the
rest — is unmodelled. A `SimHost` socket keeps its
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
for root, else 1000 on Linux, 501 on macOS) and renders `CapEff`/`CapPrm`/`CapBnd` in
`/proc/self/status`.

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

## Names

Inside a `Sim`, name resolution never leaves the process. `getaddrinfo`, `getnameinfo` and
`gethostbyname` — and on Windows `GetAddrInfoW`, `GetNameInfoW` — answer from the sim's host table
and a built-in `localhost` (`::1`, `127.0.0.1`; on Windows `""` too). Any other name fails as the
host OS fails an unknown name: `EAI_NONAME` (std's "failed to lookup address information"),
`HOST_NOT_FOUND`, `WSAHOST_NOT_FOUND` (11001), at once and without a packet.

```rust
let sim = Sim::builder().add_host("robot1.local", ["127.0.0.20".parse().unwrap()]).build();
sim.run(|| {
    let robot = connect_tester::<Line>("robot1.local:9000");   // testers and policies take names
    set_dns_policy("robot1.local", |p| p.latency = Duration::from_millis(30));
    // TcpStream::connect("ROBOT1.local.:9000") reaches the tester after 30 ms of virtual time
});
```

| Call | Effect |
|---|---|
| `add_host(name, addrs)` / `remove_host(name)` | Resolves `name` (case-insensitive, one trailing dot ignored) to `addrs` in table order. Also on `SimBuilder` and `Sim`. A name with no address of the asked family fails with `EAI_NONAME` (glibc, macOS) or `WSANO_DATA` (Windows). |
| `set_dns_policy(name, ..)` / `set_default_dns_policy(..)` | `DnsPolicy { latency, failure, failure_rate }`: the lookup waits `latency` on the sim's clock (virtual, so it time-skips and orders under `deterministic()`), then fails with `failure` — or, with a `failure_rate`, fails that often (`TryAgain` unless `failure` says otherwise), drawn from the sim's seed. Failures are logged as `Fault::Dns`. |
| `SimBuilder::resolve_real(name)` | Looks `name` up on the real resolver when the sim is built and keeps the answer; panics if it fails. |
| `SimBuilder::real_dns()` | Sends unknown names to the real resolver, counted as unmodelled calls. Panics in `build()` with `deterministic()`, since a real lookup blocks outside the schedule. |

Numeric hosts, a null node and service names go to the real libc / ws2_32, so hints semantics and
error precedence are the host's own; Windows reads a shorthand such as `127.1` as numeric only with
`AI_NUMERICHOST`, and otherwise as a name. A known name is answered by asking the OS for each of its
addresses as a numeric host with the caller's hints and joining the lists it returns; `freeaddrinfo`
takes such a list apart again on any thread, even after the sim is gone. `AI_ADDRCONFIG` is
ignored. `getnameinfo` reverses an address to the first table name holding it (and loopback to
`localhost` on Linux and macOS), otherwise numerically, or `EAI_NONAME` / `WSAHOST_NOT_FOUND` with
`NI_NAMEREQD`. The asynchronous resolvers (`getaddrinfo_a`, `GetAddrInfoEx`, `DNSServiceGetAddrInfo`,
`DnsQuery_W`, `res_query`) are not modelled and are reported as unmodelled calls.

## Signals

Each `Sim` keeps its own signal dispositions. The code under test installs its handlers with the
OS's own calls, so `ctrlc` and `signal-hook` run unchanged, and the real process's
handlers are never touched; two sims in one test binary each see only their own.

```rust
let sim = Sim::new();
let signals = sim.signals();                      // Clone + Send, usable from any thread
sim.run(|| {
    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || tx.send(()).unwrap()).unwrap();
    assert_eq!(signals.raise(Signal::Interrupt), SignalDelivery::Handled);
    rx.recv().unwrap();
    let pending = signals.raise_after(Signal::Terminate, Duration::from_secs(30)); // a virtual timer
    pending.wait();
});
```

| Platform | What is simulated |
|---|---|
| unix | `sigaction`, `signal` (BSD semantics), `raise`, `kill` of the own process (`getpid()`, 0, `-getpgrp()`; `kill(-1)` skips the caller, as on the host, so it goes to the OS) and `pthread_kill` for `SIGINT`, `SIGTERM`, `SIGHUP`. Every other signal, and other pids, go to the OS. A sim's table starts from the process's dispositions, so an inherited `SIG_IGN` reads back. Delivery is synchronous on the sending thread, as POSIX requires of a signal a process sends itself: `SA_SIGINFO` handlers get a `siginfo_t` with `si_code` `SI_USER` (Linux: `SI_TKILL` for `raise`/`pthread_kill`) and `si_pid` the parent for the test's signals; `SA_RESETHAND` and `SA_NODEFER` behave as on the host. `pthread_kill` to another thread of the sim runs the handler there at its next hooked call. |
| Windows | `SetConsoleCtrlHandler` (a list per sim, plus the ignore-CTRL+C flag), `GenerateConsoleCtrlEvent` for this process (group 0 or its own id; asynchronous, as on Windows; CTRL+C to a nonzero group succeeds and reaches no one, as Windows documents) and the CRT's `signal`/`raise` for `SIGINT`, `SIGBREAK`, `SIGTERM`. Each event is handled on a new thread, last registered handler first, until one returns `TRUE`. A close event's handlers get 5 s and a logoff or shutdown's 20 s of sim time before the delivery reports `HandledThenExit`. |
| both | `Sim::raise_signal` / `SignalHandle::raise` returns `Handled`, `HandledThenExit`, `DefaultAction` (never carried out), `Ignored`, or `Unavailable` for a signal the host OS lacks (`Break`/`Close`/`Logoff`/`Shutdown` on unix, `Terminate`/`Hangup` on Windows). From a thread outside the sim it is delivered on a new thread of the sim, joined before it returns; inside an executive's timestamp its effects wait for the timestamp to end like any other wake. |

The waits those libraries' threads block on are simulated: POSIX semaphores (`sem_wait`,
`sem_timedwait`, `sem_clockwait`, `sem_trywait`, `sem_post`; named semaphores on macOS), Windows
semaphore handles in `WaitForSingleObject` / `ReleaseSemaphore`, and `socketpair(AF_UNIX,
SOCK_STREAM | SOCK_DGRAM)`, served by the fabric like any socket (`poll`, `epoll`, `kqueue`, EOF,
`EPIPE`; an unnamed address as the host reports it). `pipe`/`pipe2` stay real. Under
`deterministic()`, once every root thread of a run has left and nothing can run, the schedule lets
leftover daemon threads (the `ctrlc` thread) go; they wait outside it until the sim runs again.

`SimBuilder::forward_real_signals()` opts a sim in to the real `SIGINT`/`SIGTERM`/`SIGHUP` (a console
control handler on Windows): while any sim forwards, a process-wide forwarder delivers each real
signal into every forwarding sim, and one that no sim handled or ignored is raised for real against
the process's own disposition. The last forwarding sim to drop restores the originals. Signal masks,
`sigwait`/`signalfd`, `EINTR` on blocked calls and `SIGALRM` are not modelled.

## Reaching the real machine: `snare::real`

The harness and other-side emulation sometimes need the *real* OS — to read a real fixture file,
or a real environment value — while the code under test stays simulated. Wrap those harness
operations in `real`:

```rust
let key = snare::real(|| std::env::var("HOME"));          // real environment
let fixture = snare::real(|| std::fs::read("tests/data/frame.bin")).unwrap();  // real file
```

`real(f)` runs `f` with interposition switched off on the calling thread only (it nests, and other
managed threads stay simulated). Threads spawned inside `real` also run outside the simulation.
Keep resource construction and execution of the code under test inside `Sim::run`, outside any
`real` closure. A native object created by the harness must not become a resource of the code
under test.

## The `cargo snare` harness

snare only compiles with `--cfg snare`; without it the build stops at a `compile_error!`. On Linux,
rustix and the raw-syscall crates reach the kernel with an inline `syscall` instruction unless they
are built for snare (below), and such calls would silently escape the simulation.

Set a package up once:

```console
$ cargo snare --init
```

It puts snare under a `cfg(snare)` target table (moving an existing snare dev-dependency there and
combining its platform `cfg`), and declares the cfg to the `unexpected_cfgs` lint (in
`[workspace.lints.rust]` when the package inherits its lints):

```toml
[target.'cfg(snare)'.dev-dependencies]
snare = "3"

[lints.rust]
unexpected_cfgs = { level = "warn", check-cfg = ['cfg(snare)'] }
```

Guard the tests with the same cfg — `#![cfg(snare)]` at the top of an integration test file,
`#[cfg(all(test, snare))]` on an in-crate test module:

```rust
#![cfg(snare)]

use snare::prelude::*;

#[test]
fn deterministic() {
    Sim::new().run(|| { /* ... */ });
}
```

```console
$ cargo snare test            # builds with --cfg snare, patches in the shims, runs the tests
```

`cargo snare` sets `--cfg snare` (and `--cfg rustix_use_libc`) and injects the drop-in shims via
`cargo --config patch.crates-io...`. Plain `cargo test` builds neither snare nor the
`#[cfg(snare)]` tests.

## Shims (`shims/`)

Some crates bypass libc in ways an import-table hook cannot see — raw `io_uring` rings in mmap'd memory,
`AF_XDP` UMEM. For those, snare provides drop-in replacement crates injected via `[patch.crates-io]`:

- **`io-uring`** — emulates the ring in-process, executing each SQE through libc `read`/`write` so the
  interposer sees ordinary I/O.
- **`xsk-rs`** (AF_XDP) — routes frame TX/RX through libc `send`/`recv`.
- **`sc`, `syscalls`** — route raw syscalls through libc so the `syscall` hook catches them.

The shims honor `snare::real`: each resource is tagged with the passthrough mode it was created in, and
using it in the other mode panics rather than silently mixing an emulated ring with real-OS I/O.

## Platform support

| | Linux (x86_64, aarch64) | macOS (aarch64, x86_64) | Windows (x86_64, aarch64) |
|---|---|---|---|
| Interposition | ELF GOT | Mach-O `__got` (+ variadic trampoline on arm64) | PE IAT |
| Time / entropy / sleep | ✅ | ✅ | ✅ |
| TCP | ✅ | ✅ | ✅ (Winsock) |
| UDP | ✅ | ✅ | ✅ (Winsock) |
| Readiness | ✅ (`epoll`, `poll`, `eventfd`) | ✅ (`kqueue`/`kevent`, `poll`) | ✅ (`WSAPoll`, `select`) |
| Raw L2 | `AF_PACKET` | `/dev/bpf` | pcap/npcap (structural) |
| Host scheduling | ✅ | ✅ (pthread/Mach) | ✅ (`WinHost`) |
| Interfaces and routing | ✅ (`getifaddrs`, `SIOCGIF*`, netlink) | ✅ (`getifaddrs`, `SIOCGIF*`, `sysctl`) | ✅ (IP Helper) |
| NIC tuning / PTP | ✅ (`ethtool`, qdiscs, sysfs) | partial (`sysctl`) | adapter properties + restart (SetupAPI/registry/`CM_*`) |
| Process limits | ✅ (`RLIMIT_RTPRIO`/`NICE`/`MEMLOCK`, `mlock`) | ✅ (`RLIMIT_MEMLOCK`, `mlock`) | priority class, working set (`WinHost`) |
| Names / signals | ✅ | ✅ | ✅ (`GetAddrInfoW`, console control events) |

Linux means glibc (`target_env = "gnu"`). Every other target — musl, 32-bit x86 and ARM, Android,
the BSDs, illumos, Redox — stops at a single `compile_error!` naming the supported targets. A crate
that also builds for those targets gates the dev-dependency:

```toml
[target.'cfg(all(snare, any(all(target_os = "linux", target_env = "gnu", any(target_arch = "x86_64", target_arch = "aarch64")), target_os = "macos", windows)))'.dev-dependencies]
snare = "3"
```

and puts its sim tests behind the same `cfg`.

The minimum supported Rust version is 1.88.

## Repository layout

```
crates/snare-interpose/   the engine: patchers, hooks, Domain, backend traits, real()
crates/snare/             Sim, SimHost, HostProfile, EasyBuilder, Fabric, VirtualFs, testers
crates/cargo-snare/       the `cargo snare` subcommand
shims/                    io-uring, xsk-rs, sc, syscalls drop-ins ([patch.crates-io])
```

## Running the tests

`.cargo/config.toml` builds this workspace with `--cfg snare`; a `RUSTFLAGS` set in the environment
replaces it, so include `--cfg snare` there too.

```console
cargo test                                  # macOS / Linux
cargo clippy --all-targets
cargo xwin build --workspace --target x86_64-pc-windows-msvc   # Windows cross-build (cargo-xwin)
```

Linux-only surfaces are exercised in a container (`docker run --rm -v "$PWD":/work -w /work rust:latest
cargo test`). `scripts/test-windows.sh` cross-builds the workspace and runs its Windows tests in a
Parallels VM; `scripts/test-windows-host.sh` runs only the scheduling-plane target.

The Windows module-loading test needs the `interpose-probe` DLL in the target's profile directory,
beside `deps`. The full Windows runner builds the workspace first to produce it; `cargo test
--no-run` alone does not. On a native Windows checkout, run `cargo build -p interpose-probe` before
`cargo test --workspace --all-targets`, using the same target and profile for both commands.

## A note on the source

Behaviour that mirrors a kernel interface is cited in the code to its authority — a man-page section
(`man 2 sched_setscheduler`), a kernel header (`<linux/if_link.h> struct rtnl_link_stats64`), or a
`Documentation/` path (`Documentation/networking/timestamping.rst`) — so the modeled struct layouts,
magic numbers, and errno conventions can be checked against the real thing.
