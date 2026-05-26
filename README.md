# snare

A pseudo-integration testing library for code that talks over TCP, UDP, or
mio. Snare swaps out `std::net`, `std::thread`, and `mio` with drop-in
modules that, under tests, route every byte through an in-process mock —
and re-export the real types otherwise, so the same code runs against the
real network in production with zero overhead.

The point is to write tests that exercise actual `TcpStream::connect`,
`UdpSocket::send_to`, `Poll::poll`, etc. paths in your code without binding
to real ports, racing the OS scheduler, or pulling in a tokio runtime just
to drive a fake server.

## How it works

There are two pieces:

- **The shim.** `snare::net`, `snare::thread`, and `snare::mio` are
  drop-in replacements for the corresponding standard / `mio` modules. When
  the `shim` feature is on (which you only turn on for `[dev-dependencies]`)
  every socket call is intercepted and serviced from a per-test in-memory
  state slot. When `shim` is off, they're `pub use` re-exports — your
  release build sees zero indirection.

- **The tester.** A small builder API (`connect_tester`, `then_action`,
  `with_cyclic_action`, `until_condition`, ...) describes what the
  "other side of the wire" should do: respond to packets, fire cyclic
  sends, inject errors, close the connection after N messages, etc.
  `run_testers!` drives the loop until every tester's finish condition
  fires.

So in a typical test you write the SUT against `snare::net::TcpStream`,
spawn it on a `snare::thread::spawn`, and on the test thread build a
`NetTester` that plays the role of the peer.

## Setup

Use snare as a regular dep without `shim`, and as a dev-dep with `shim`
enabled. Cargo merges the two feature sets and only turns `shim` on under
the test profile:

```toml
[dependencies]
snare = "1"

[dev-dependencies]
snare = { version = "1", features = ["shim", "mio-compat"] }
```

`mio-compat` is only needed if your SUT uses `mio` directly. Drop it
otherwise.

In your code, replace these imports project-wide:

| Replace                                           | With            |
| ------------------------------------------------- | --------------- |
| `std::net::{TcpListener, TcpStream, UdpSocket}`   | `snare::net`    |
| `std::thread`                                     | `snare::thread` |
| `mio::{Poll, Waker, Token, Interest, event, net}` | `snare::mio`    |

The release build resolves these to the real things; tests resolve them
to the shim. No `#[cfg(test)]` toggling at the call site.

## Writing a test

Every test that touches the shim has to start with `register_test()` —
this is what carves out the per-test state slot. Threads the test or SUT
spawns need to be attached to that slot, which `snare::thread::spawn`
handles for you. If you reach for `std::thread::spawn`, chain
`.register_as_child()` on the join handle, or call
`register_thread_child_of(...)` from inside the spawned closure.

A minimal test where the SUT sends a UDP packet and the tester echoes one
byte back:

```rust,ignore
use std::{net::SocketAddr, time::Duration};
use snare::{
    Packetable, SocketType, TesterAction, TimerState, UdpSocket,
    connect_tester, register_test, run_testers,
};

#[derive(Clone, Debug)]
struct Bytes(Vec<u8>);

impl Packetable for Bytes {
    const CAN_BE_FLATTENED: bool = false;
    const SOCKET_TYPE: SocketType = SocketType::Udp;
    fn encode(&self) -> Vec<u8> { self.0.clone() }
    fn decode(data: &[u8]) -> Option<(Self, usize)> {
        (!data.is_empty()).then(|| (Bytes(data.to_vec()), data.len()))
    }
}

#[test]
fn echoes_first_byte() {
    register_test();

    let server_addr: SocketAddr = ([127, 0, 0, 1], 4000).into();
    let client_addr: SocketAddr = ([127, 0, 0, 1], 4001).into();

    let mut tester = connect_tester::<Bytes>(server_addr)
        .then_action(|pkt, src| TesterAction::Send(src, Bytes(vec![pkt.0[0]])))
        .until_stateful_condition::<TimerState>(|t| t.poll_elapsed() >= Duration::from_secs(1));

    // The SUT — a thread that sends and reads back.
    snare::thread::spawn(move || {
        let sock = UdpSocket::bind(client_addr).unwrap();
        sock.send_to(b"hi", server_addr).unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = sock.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"h");
    });

    run_testers!(tester);
}
```

The same shape works for TCP — set `SOCKET_TYPE = SocketType::Tcp`,
implement `decode` to handle partial reads (return `None` when the buffer
doesn't yet contain a complete frame; snare will keep calling you as more
bytes arrive), and use `snare::net::TcpStream` / `TcpListener` in the SUT.

## Tester API

`NetTester` is built up with chained `then_*` and `with_*` calls:

- `then_test` / `then_stateful_test` — packet handlers. Return
  `Some(pkt)` to forward to the next handler in the chain, `None` to drop.
- `then_action` / `then_stateful_action` — same shape, but return a
  `TesterAction` (send a reply, close the socket, inject an error, ...).
- `then_edit_state` — mutate state per packet without inspecting it.
- `with_cyclic_action` / `with_stateful_cyclic_action` — fire on a
  fixed interval, regardless of incoming traffic.
- `with_state` — eagerly initialize a state slot with a configured value.
- `until_condition` / `until_stateful_condition` — finish conditions.
  Any returning `true` ends the tester. With none configured, the tester
  ends once there are no pending packets.
- `peek_state` — borrow state after the run for assertions.

State is typed and stored in an `AnyMap` per tester, so handlers ask for
the type they need (`<MyCounter>`) and snare lazy-inits a `Default` if
absent.

`TesterAction` covers: `Send`, `RaiseSocketError`, `CloseSocket`,
`Multiple`, `Quiesce` / `QuiesceWithMode`, `ResetTcp`,
`SetListenerBehavior`, `SetTcpInboundLatency`, `SetTcpRecvWindow`,
`SetUdpPolicy`. The last few are how you mutate link policy mid-test from
inside a tester closure.

## Fault injection and link policy

The same primitives are available directly (not via a tester) for setup
that runs before `run_testers!`:

- **UDP:** `set_udp_policy(addr, |p| ...)` configures `loss_rate`,
  `duplicate_rate`, `reorder_jitter`, `inbound_latency`,
  `send_queue_depth`, and `mtu`. Use `seed_rng(...)` for deterministic
  loss/dup tests.
- **TCP:** `set_tcp_inbound_latency(addr, dur)` delays bytes inbound to
  `addr`; `set_tcp_recv_window(addr, Some(n))` caps the SUT's receive
  buffer so writes back-pressure.
- **Listeners:** `set_listener_behavior(addr, Refusing |
  DelayingUntil(t) | Accepting)` controls how connects resolve.
- **Connection lifecycle:** `reset_tcp(addr)` synthesizes a peer RST;
  `quiesce(addr, dur)` suppresses mio readiness in one or both
  directions for a window.
- **Recording log:** `recorded_events()` returns a timestamped log of
  every send/close/quiesce/reset/error that crossed the test boundary.
  Useful for "did we hit the retry path?" style assertions.
  `clear_recorded_events()` scopes the log to one phase.

## Thread tracking

Every shim call resolves a per-thread "which test owns me?" lookup. The
test thread itself is registered by `register_test()`; child threads must
opt in. The easy ways:

- `snare::thread::spawn(...)` and `snare::thread::Builder::spawn(...)` —
  same signatures as `std::thread`, but they register the child against
  the spawning thread's test before running the closure.
- `handle.register_as_child()` (extension trait on `JoinHandle`,
  `Thread`, and `ThreadId`) — for when you already have a
  `std::thread::spawn(...)` result.
- `register_thread_child_of(parent_id)` — for when the registration has
  to happen from inside the spawned closure (e.g. you only learn the
  parent id at runtime).

Unregistered threads that touch the shim hit a 2s grace-period poll
before panicking, so a late `.register_as_child()` still works under CI
contention. Don't rely on that for normal code paths.

## Features

- `shim` — turn on the in-process mock. Off by default so production
  builds re-export the real types.
- `mio-compat` — expose `snare::mio`. Required if your SUT uses `mio`
  directly; otherwise leave it off.

## pcapng capture

Snare can write every byte that crosses the shim to a `.pcapng` file you can
open in Wireshark. Off by default; opt in via env vars.

The shim has no real packets, so the writer fabricates Ethernet + IPv4/IPv6 +
TCP/UDP framing per flow — including a synthetic 3-way handshake and ACKs —
so the output renders as a normal conversation in Wireshark.

### Enable for a specific test

Call `snare::enable_pcapng()` after `register_test()`. Capture only happens
when `SNARE_PCAPNG_DIR` is set in the environment; otherwise it's a no-op,
so this line is safe to leave in committed test code.

```rust,ignore
#[test]
fn my_test() {
    snare::register_test();
    snare::enable_pcapng();
    // ... rest of the test
}
```

```bash
SNARE_PCAPNG_DIR=/tmp/snare-pcaps cargo test my_test
```

### Enable from outside the test

Set `SNARE_PCAPNG_TESTS` to a comma-separated list of test thread names
(for cargo this is the test function path) to force-enable capture without
touching the test code:

```bash
SNARE_PCAPNG_DIR=/tmp/snare-pcaps \
SNARE_PCAPNG_TESTS=my_test,other_mod::another_test \
  cargo test
```

### Output

One `<dir>/<test thread name>.pcapng` file per test. Cargo names test
threads after the test path, so they're filename-safe after a light
sanitization.

### Caveats

- TCP byte streams emit one PSH/ACK segment per `write` call (plus a peer
  ACK), so segmentation reflects when the SUT called `write`, not real
  TCP-stack chunking.
- UDP is captured at `send_to` time regardless of whether anything
  receives it — SUT↔SUT UDP delivery in the shim is framework-driven, but
  the tap fires unconditionally.
- IP/TCP/UDP checksums are written as zero (Wireshark reads these as
  "checksum offload"); MACs are deterministic from the socket addr.
