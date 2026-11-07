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

snare patches the program's import tables so the libc and Win32 calls a managed thread makes
land in its hooks first; a hook serves the call from the model or lets it fall through to the real
OS. That reaches through `std` and every dependency. [How it works](docs/how-it-works.md) has the
detail and the rules a test follows.

## Quick start

```console
$ cargo snare --init          # snare under [target.'cfg(snare)'.dev-dependencies], cfg declared
$ cargo snare test            # builds with --cfg snare, patches in the shims, runs the tests
```

```rust
#![cfg(snare)]

use snare::prelude::*;

#[test]
fn deterministic() {
    Sim::new().run(|| { /* ... */ });
}
```

Plain `cargo test` builds neither snare nor the `#[cfg(snare)]` tests. See [The `cargo snare`
harness](docs/harness.md) for what it sets and why, the shims it patches in, and `snare::real`
for a harness that needs the real machine.

## What it simulates

- **Time and entropy**: a discrete-event virtual clock behind every clock call, seeded randomness,
  local time zones. [Time](docs/time-and-executive.md), [local time](docs/local-time.md).
- **Network**: TCP, UDP, raw L2 (`AF_PACKET`, `/dev/bpf`), readiness (`epoll`, `kqueue`, `poll`,
  `WSAPoll`), netlink, packet timestamps, faults and back-pressure, name resolution.
  [Sockets](docs/sockets.md), [interfaces and routing](docs/interfaces.md),
  [names and signals](docs/names-and-signals.md).
- **The host**: CPUs, scheduling and affinity, resource limits, NIC drivers over `ethtool`, qdiscs,
  PTP, the kernel's own threads, interrupt lines and NAPI, `uname`, capabilities.
  [The simulated host](docs/host.md).
- **Files**: an in-memory file system, synthesized `/sys`, `/proc`, `/dev` and a tracefs.
  [Files](docs/files.md).
- **Signals, the environment, Windows' scheduling plane and Winsock.**
  [Everything covered, surface by surface](docs/coverage.md).

The test drives the other side with scripted peers ([testers](docs/testers.md)), can capture what
crossed the network to pcapng ([packet capture](docs/packet-capture.md)), and controls the
schedule and the clock ([determinism and threads](docs/scheduling.md),
[the executive](docs/time-and-executive.md)).

## Platforms

Linux (glibc; x86_64, aarch64), macOS (aarch64, x86_64) and Windows (x86_64, aarch64); Rust 1.88 or
later. Every other target stops at a `compile_error!`. What each platform covers, the repository
layout and how to run snare's own tests are in [Platforms and development](docs/development.md).
Known gaps are in [OPEN_BUGS.md](OPEN_BUGS.md).

## Documentation

| | |
|---|---|
| [How it works](docs/how-it-works.md) | the interposition model and the rules a test follows |
| [What is simulated](docs/coverage.md) | every surface, in detail |
| [The simulated host](docs/host.md) | `SimHost`, `HostProfile`, `EasyBuilder`; kernel threads, interrupts and NAPI |
| [Files](docs/files.md) | `VirtualFs`, file timestamps, tracefs |
| [Local time](docs/local-time.md) | time zones on each platform |
| [Determinism, threads and the sim lifecycle](docs/scheduling.md) | quiescence, clock spins, thread classes, stuck runs |
| [Time, the executive and cooperative primitives](docs/time-and-executive.md) | controlling time, an outside simulation owning the clock |
| [Testers and recorded events](docs/testers.md) | scripted peers and the event log |
| [Packet capture](docs/packet-capture.md) | pcapng output |
| [Interfaces, routing and NIC drivers](docs/interfaces.md) | the topology, enumeration, `ethtool`, Windows adapters |
| [Sockets](docs/sockets.md) | faults, connect faults, the socket table, timestamps, options, limits, counters |
| [Names and signals](docs/names-and-signals.md) | `getaddrinfo` and friends, signal delivery |
| [The cargo snare harness](docs/harness.md) | `cargo snare`, `snare::real`, the shims |
| [Platforms and development](docs/development.md) | platform matrix, layout, running the tests, citations |

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
