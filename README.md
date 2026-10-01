# snare2

Deterministic, in-process simulation of the operating system for Rust tests — **without changing the
code under test.**

Your code keeps calling `std::net::TcpStream`, `std::fs::File`, `std::env::var`, `libc::sched_setscheduler`,
`clock_gettime`, raw `AF_PACKET`/`io_uring` — exactly as it does in production. snare2 interposes at the
OS-call boundary underneath it and serves those calls from an in-memory model: a virtual network, a
virtual filesystem, a simulated host, a virtual clock. The test drives the other side of the wire.

```rust
use snare::{Sim, connect_tester, run_testers, Line, TesterAction};
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

The original `snare` required the code under test to import snare's shim types (`snare::net::TcpStream`
instead of `std::net::TcpStream`, and so on). That only tests code you could edit to use the shims, and
it never covers what a dependency does three crates down.

snare2 removes that constraint. It patches the **import tables** of the loaded program (ELF GOT / Mach-O
`__got` / PE IAT) so that the libc and Win32 symbols a managed thread calls — `socket`, `open`, `getenv`,
`clock_gettime`, `ioctl`, `sched_setscheduler`, … — land in snare's hooks first. A hook offers the call
to the test's in-memory model; if the model declines, the call falls through to the real OS. Nothing the
code under test imports changes. This reaches straight through `std` and every dependency.

Two needs, one library:

- **Deterministic unit tests** — write them in-crate guarded by `#[cfg(snare)]` and run them with
  `cargo snare` (below), or as ordinary integration tests that build a `Sim`.
- **A programmatic API** — drive the simulation directly (time acceleration, discrete events, scripted
  peers) for higher-level harnesses.

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
| **Time** | `clock_gettime` (`CLOCK_MONOTONIC`/`REALTIME`/`TAI`), `gettimeofday`, `QueryPerformanceCounter` — a virtual clock at a fixed epoch. Sleeps return instantly and advance virtual time (as-fast-as-possible). A `SimHost`'s clock takes `pause_time`/`advance_time`/`resume_time`; a plain `Sim` can opt into a deterministic discrete-event clock (`Sim::builder().virtual_clock()`) where a blocked sleep/wait skips straight to its deadline once the sim is quiescent. |
| **Entropy** | `getrandom`/`getentropy`/`arc4random`/`ProcessPrng` — seeded, so `HashMap` order etc. is repeatable. |
| **TCP** | `std::net::TcpStream`/`TcpListener` against scripted `connect_tester` peers. |
| **UDP** | `std::net::UdpSocket` serviced from memory on every platform: `bind`/`connect`/`sendto`/`recvfrom`, blocking cross-thread receive, broadcast (`SO_BROADCAST`), multicast (`IP_ADD_MEMBERSHIP`), and several addresses sharing a port. Under a `SimHost` it adds `SO_TIMESTAMPING` (`SCM_TIMESTAMPING`), `MSG_ERRQUEUE` tx timestamps and `SCM_TXTIME` launch deadlines. TCP and UDP run together in one `Sim`. |
| **Raw L2** | Linux `AF_PACKET`/`SOCK_RAW` + `bind(sockaddr_ll)`; macOS `/dev/bpf*` (`BIOCSETIF`/`bpf_hdr`). What EtherCAT masters (ethercrab) use. |
| **Readiness** | `epoll` + `eventfd` (Linux) and `kqueue`/`kevent` (macOS, incl. `EVFILT_USER` wakers), so `mio`-based code works natively on both. |
| **Netlink** | `AF_NETLINK` rtnetlink `RTM_GETLINK`/`IFLA_STATS64`, genetlink `CTRL_CMD_GETFAMILY`, `RTM_GETQDISC`/ETF. |
| **Files** | `VirtualFs`: an in-memory tree behind `open`/`read`/`write`/`stat`/`statx`/`getdents64`, with glob passthrough to real paths. `SimHost` also renders `/sys`, `/proc`, `/dev/ptp*`, `/dev/cpu_dma_latency`. |
| **Host tuning** | Scheduling (`sched_setscheduler`/affinity/priority, `mlockall`), NIC config (`ethtool`, `SIOC[GS]HWTSTAMP`, sysfs, queues/IRQs, `getifaddrs`), PTP, capability gating — all modeled, never touching the real scheduler or NIC. |
| **Environment** | `getenv`/`setenv`/`unsetenv` — an isolated, deterministic environment (opt-in). |
| **Windows** | The thread-scheduling plane (`SetThreadPriority`/affinity/priority-class/`timeBeginPeriod`) runs against a `WinHost`, and `std::net::TcpStream`/`TcpListener`/`UdpSocket` are serviced from memory by a Winsock fabric (`socket`/`bind`/`listen`/`accept`/`connect`/`send`/`recv`/`sendto`/`recvfrom`, blocking recv/accept, UDP broadcast/multicast/multi-IP). `WSAPoll`/IOCP readiness and `WSADuplicateSocket` (`try_clone`) are planned; a pcap/npcap interposer is in place structurally. |

Anything not modeled falls through to the real OS and is counted — `Domain::unmodelled()` reports every
such call, so a test that expects full simulation can assert it is empty.

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
    .build();

Sim::builder().host(host).build().run(|| {
    // sched_setscheduler(SCHED_FIFO), ethtool, /sys reads, SO_TIMESTAMPING, getenv — all served here.
});
```

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

## Determinism and quiescence

The clock is virtual and sleeps are as-fast-as-possible, so a test that "waits a second" finishes
instantly and every run produces identical timestamps. Full deterministic *scheduling* is out of reach
through hooks (inline futexes and atomics are invisible), so snare2 targets **quiescence** instead: when
every managed thread is blocked in a simulated wait with no possible progress, the run is deadlocked and
the wait gives up (returns `EAGAIN`) rather than hanging forever. Correct cross-thread progress is
unaffected.

## Reaching the real machine: `snare::real`

Tester code sometimes needs the *real* OS — to read a real fixture file, or a real environment value —
while the code under test stays simulated. Wrap it in `real`:

```rust
let key = snare::real(|| std::env::var("HOME"));          // real environment
let fixture = snare::real(|| std::fs::read("tests/data/frame.bin")).unwrap();  // real file
```

`real(f)` runs `f` with interposition switched off on the calling thread only (it nests, and other
managed threads stay simulated).

## The `cargo snare` harness

Write deterministic tests in the crate, guarded by `#[cfg(snare)]`, and run them under interposition:

```rust
#[cfg(snare)]
#[test]
fn deterministic() {
    snare::Sim::new().run(|| { /* ... */ });
}
```

```console
$ cargo snare test            # builds with --cfg snare, patches in the shims, runs the tests
```

`cargo snare` sets `--cfg snare` (and `--cfg rustix_use_libc`) and injects the drop-in shims via
`cargo --config patch.crates-io...` — no edits to your `Cargo.toml`. Plain `cargo test` leaves the
`#[cfg(snare)]` tests out.

## Shims (`shims/`)

Some crates bypass libc in ways an import-table hook cannot see — raw `io_uring` rings in mmap'd memory,
`AF_XDP` UMEM. For those, snare2 provides drop-in replacement crates injected via `[patch.crates-io]`:

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
| Readiness | ✅ (`epoll`, `poll`, `eventfd`) | ✅ (`kqueue`/`kevent`, `poll`) | — (planned) |
| Raw L2 | `AF_PACKET` | `/dev/bpf` | pcap/npcap (structural) |
| Host scheduling | ✅ | ✅ (pthread/Mach) | ✅ (`WinHost`) |
| NIC / netlink / PTP | ✅ | partial (`sysctl`) | — |

## Repository layout

```
crates/snare-interpose/   the engine: patchers, hooks, Domain, backend traits, real()
crates/snare/             Sim, SimHost, HostProfile, EasyBuilder, Fabric, VirtualFs, testers
crates/cargo-snare/       the `cargo snare` subcommand
shims/                    io-uring, xsk-rs, sc, syscalls drop-ins ([patch.crates-io])
```

## Running the tests

```console
cargo test                                  # macOS / Linux
cargo clippy --all-targets
cargo xwin build --target x86_64-pc-windows-msvc   # Windows cross-build (cargo-xwin)
```

Linux-only surfaces are exercised in a container (`docker run --rm -v "$PWD":/work -w /work rust:latest
cargo test`). The Windows scheduling plane is run in a Parallels VM via `scripts/test-windows-host.sh`.

## A note on the source

Behaviour that mirrors a kernel interface is cited in the code to its authority — a man-page section
(`man 2 sched_setscheduler`), a kernel header (`<linux/if_link.h> struct rtnl_link_stats64`), or a
`Documentation/` path (`Documentation/networking/timestamping.rst`) — so the modeled struct layouts,
magic numbers, and errno conventions can be checked against the real thing.
