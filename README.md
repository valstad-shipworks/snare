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

`mio-compat` is only needed if your SUT uses `mio` directly, and
`ctrlc-compat` only if it uses `ctrlc`. Drop them otherwise.

In your code, replace these imports project-wide:

| Replace                                           | With            |
| ------------------------------------------------- | --------------- |
| `std::net::{TcpListener, TcpStream, UdpSocket}`   | `snare::net`    |
| `std::thread`                                     | `snare::thread` |
| `std::time::{Instant, SystemTime}`                | `snare::time`   |
| `mio::{Poll, Waker, Token, Interest, event, net}` | `snare::mio`    |
| `ctrlc::{set_handler, try_set_handler, Error}`    | `snare::ctrlc`  |
| `fast_talker::`                                   | `snare::fast_talker::` |

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
  loss/dup tests. Each `(source, destination)` flow draws from its own
  stream derived from the seed, and no draw is made for a probability of 0,
  so what happens on one flow never depends on traffic on another or on
  the order in which threads sending at the same instant run.
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

## Virtual clock

`snare::time` is a drop-in for `std::time`. Point your SUT at
`snare::time::Instant` / `snare::time::SystemTime` (`Duration` is untouched)
and, under the shim, both read from a per-test virtual clock instead of the OS.
Off the shim it re-exports `std::time`, so release builds see the real clock
with zero overhead.

The clock has two knobs:

- **`value`** — what the clock reads right now.
  `set_time_value(dur)` sets it (the elapsed reported by `Instant::now()` since
  the virtual epoch, and the offset into `SystemTime::now()`); `time_value()`
  reads it; `advance_time(dur)` jumps it forward, even while paused.
- **`rate`** — how fast `value` advances relative to real time.
  `set_time_rate(1.0)` tracks the real clock (the default), `0.0` pauses it so
  `now()` stops advancing, `>1.0` runs fast (capped at 1e6). `pause_time()`
  sets rate `0.0`; `resume_time()` restores the rate from before the pause and
  does nothing if the clock isn't paused. The rate can't go negative —
  `set_time_rate` panics on a negative or non-finite value, since a backwards
  clock would break the monotonicity of `Instant::now()`.

Reading the clock takes no lock: each thread caches its state slot's clock,
which is a seqlock over an anchored line in 32.32 fixed point.

```rust,ignore
snare::register_test();
snare::pause_time();                              // freeze time
let t0 = snare::time::Instant::now();
snare::advance_time(Duration::from_secs(30));     // 30s "passes" instantly
assert_eq!(t0.elapsed(), Duration::from_secs(30));

snare::set_time_rate(60.0);                        // now 1 real sec = 1 virtual min
```

The clock resolves through the same thread-chain hierarchy as the network
shims — every thread the test owns shares one clock — and collapses to a single
process-wide clock under `--cfg snare_global`, just like the rest of the shim
state.

`snare::thread::sleep` and `snare::thread::sleep_until` are tied to this clock
too: they block until virtual time reaches the deadline. So a paused clock parks
the sleeper until you `advance_time` (or `resume_time`) it from another thread,
and a fast clock wakes it after proportionally less real time. Deadlines live in
one timer heap per state slot, fired in `(deadline, seq)` order by a single
`snare-sched-timer` thread, so a thousand sleepers cost one thread, not a
thousand. When a test needs to wait in real wall-clock time regardless of the
rate — polling real I/O, an OS background thread — use
`snare::thread::real_sleep`, which is a straight alias for `std::thread::sleep`
(and is available off the shim too).

Network timing runs on the same clock: TCP and UDP latency releases, quiesce
windows, `DelayingUntil`, linger, read/write/poll timeouts, the tester's timers
and cycles, the `run_testers!` start-up delay, recorded event stamps and pcapng
timestamps are all virtual. A delayed datagram wakes its reader exactly at its
virtual release time. A timeout only fires when virtual time passes it, so a
paused clock holds every network timeout too.

## Scheduler: driving the clock from a simulation

`snare::sched` lets an outside simulation executive own the clock, so a whole
process (the SUT's threads, driver threads, emulated devices) runs on the
executive's virtual time and can skip idle stretches. sham's `SnareDomain` is
the reference user.

- **Driver.** `attach_driver(DriverConfig { seed, accounting, audit })` puts the
  slot's clock in *Driven* mode and returns the one `Driver`. It fails with
  `AlreadyAttached`, `NotGlobal` (needs `--cfg snare_global` or a registered
  test slot) or, without `shim`, `ShimDisabled`. Attaching seeds the RNG.
  While driven, `set_time_rate`, `pause_time`, `resume_time`,
  `set_time_value` and `advance_time` are ignored with a one-time warning per
  call site. Dropping the driver returns the clock to Scaled mode, frozen at
  its current value.
- **Grants.** `Driver::grant(Grant { anchor_v, anchor_wall, rate, horizon })`
  lets time flow along a line but never past `horizon`; `freeze()` holds it.
  `enter_timestamp(t)` holds everyone else at `t − 1 ns` while the calling
  thread reads exactly `t` and its wakes are deferred; `leave_timestamp(t)`
  delivers them and fires timers due at `t`. `with_driver_time(t, f)` gives
  worker threads the same view of `t`.
- **Participants and quiescence.** With `accounting` on, snare tracks which
  threads matter. A thread joins by spawn handoff (`snare::thread::spawn` and
  `Builder::spawn[_scoped]` register the child as running before it starts), by
  its first blocking snare call, by waking a participant, or explicitly with
  `participate(name)`. It counts as blocked only inside a snare wait: `park`,
  `block_on`, `Sleep`, `thread::sleep`, or a blocking socket call (labelled
  `"tcp read"`, `"tcp accept"`, `"udp read"`, `"mio poll"`, …). A waker moves
  its target back to running under the scheduler lock before the OS wake, so
  the count never reaches zero while a wake is in flight. `busy(label)` returns
  a `BusyLease` that keeps the domain busy while held. The domain is
  *quiescent* when nothing is running, no lease is held, no wake is deferred
  and no timer is due; `Driver::quiescence()` reports that, the next deadline,
  and what blocks it (`BlockerKind`). A thread already parked when the driver
  attaches is invisible to it, so attach first.
- **Jumps.** `Driver::jump_to(t)` re-checks quiescence under the lock and
  moves the clock to `min(t, next deadline)`, firing exactly one timer group,
  or returns `NotQuiescent`.
- **Observation.** `participants()`, `timers(n)`, `arm_notify(epoch, f)` (a
  one-shot callback on any change), `drain_hints()` (from
  `hint_starving(source, severity)`) and `audit()`.
- **Audit mode.** `DriverConfig.audit`, or `SNARE_SCHED_AUDIT` set to anything
  but `0` or empty, records a `QuiescenceViolation` whenever a blocked or
  unknown thread with no lease writes to a socket, connects, or wakes a
  participant.
- **Blocking primitives.** `park(deadline)`, `Unparker`/`current_unparker`,
  `block_on(future)` (the thread is blocked while the future is pending) and
  `sleep_until(t) -> Sleep` (a future; dropping it cancels the timer).
  `block_on_until(future, Option<Instant>)` and `block_on_timeout(future,
  Duration)` return `None` at the deadline, after polling the future one last
  time; under a driver the wait is visible and the deadline is virtual, so
  the driver can jump straight to it. An overflowing timeout means no
  deadline. `WakerSet` holds the wakers of every task waiting on one piece of
  state: register, then re-check, then return `Pending`; `wake_all` after the
  change.
- **Deciding how to wait.** `is_driven()` is true when an accounting driver
  owns the calling thread's clock and the thread is not background, helper or
  driver-class: its waits should be snare waits with virtual deadlines.
  `is_participant()` is true only for a thread that is already a registered
  participant, and never registers one.
- **Thread classes.** `thread_class()` reports `Participant`, `Background`,
  `Helper`, `Driver` or `Unclassified`. `mark_background(label)` (telemetry,
  logging, reports) and `mark_helper()` (compute-pool workers that run only
  while a participant waits on them) take a thread out of accounting for
  good: it is never registered by a first touch or as a stray, and it never
  holds up quiescence. Its snare effects (waking a participant, a snare
  wait, a socket send or receive, taking a lease) still happen, and each is
  recorded as a `ClassEffect` in `AuditReport::class_effects` (last 256) and
  `total_class_effects` whenever an accounting driver is attached.
  `setup_scope(label)` marks an unclassified thread background and holds a
  `setup:<label>` lease until dropped, so time cannot move while the
  simulation is wired up; its effects count into `total_setup_effects`
  instead.
- **Checked timestamps.** `Driver::enter_timestamp_checked(t)` does what
  `enter_timestamp` does only if the domain is quiescent and no timer is due
  before `t`, checked and applied under one lock, and otherwise returns
  `NotQuiescent`.
- **Attribution.** `ParticipantInfo` carries `last_wait` (the wait it last
  woke from) and `leases` (labels of the leases its thread holds).
  `Driver::held_leases()` and `held_leases()` list every lease with the name
  of the participant holding it, `None` for an orphan. `Driver::detach()`
  releases the clock like dropping the driver.
- **Test kit.** `sched::testkit::StrictClock` (doc-hidden, `shim` only)
  attaches an accounting driver, marks the calling thread background and
  moves time only by jumping to the next deadline once the domain is
  quiescent. It panics when a running participant with no lease keeps the
  domain busy for `StrictConfig::stuck_after` of wall time.

Without `shim`, `snare::sched` still compiles: `park`, `block_on`,
`block_on_until`, `block_on_timeout` and `Sleep` run on wall time,
`participate`, `busy`, `hint_starving` and `setup_scope` are no-ops,
`is_driven` and `is_participant` are false, and `attach_driver` returns
`ShimDisabled`. Code written against it builds for
production unchanged.

Every wait site registers with its resource's wait set before it checks
readiness, so a notification that lands in between is never lost; a mutation
wakes only the waiters of the resource it touched.

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

### Global mode: one shared network for the whole process

Per-test isolation is the right model for `#[test]`s, but it's the wrong
model for a long-running **single-process simulation** — e.g. driving real
device drivers against an in-process emulator, where conductor threads,
driver worker threads, and the emulator all need to see one shared virtual
network and there is no "test" to scope them to.

Build with `--cfg snare_global` and every thread in the process funnels to
one shared state slot instead of a per-test one. In this mode:

- `register_test()`, `register_child_thread()`, and
  `register_thread_child_of()` are optional no-ops.
- Plain `std::thread::spawn` works — no `.register_as_child()`, no grace
  poll, no "not a valid test thread" panic. Every thread shares the same
  sockets, listeners, valid-IP set, and RNG.
- The slot auto-vivifies on first access.

Set it for the whole build (it must compile `snare` once with the cfg), e.g.
in the sim binary's `.cargo/config.toml`:

```toml
[build]
rustflags = ["--cfg", "snare_global"]
```

or `RUSTFLAGS='--cfg snare_global' cargo build`. Leave it off for ordinary
test builds, which want isolation. The cfg only matters when `shim` is on.

## OS semantics

Sockets, errors and system calls differ between operating systems. snare
emulates one of them per state slot, chosen with `snare::OsSemantics`:

```rust,ignore
#[non_exhaustive]
pub enum OsSemantics { Linux, MacOs, Windows }
```

- `OsSemantics::host()` is the OS snare was built for (anything that is
  neither macOS nor Windows counts as Linux), and it is the default.
- `os_semantics()` reads the calling thread's slot. It exists without `shim`
  too, where it always returns the host.
- With `shim`, `set_os_semantics(os)` selects an OS for the slot and
  `os_semantics_explicit()` says whether one was selected. It applies to
  operations from then on, so call it before creating sockets; existing
  sockets keep what they decided at bind time, such as their ephemeral port.
  It also renames the loopback interface and, unless `set_sys_limits` was
  called, resets the socket limits to the new OS's defaults.
- `SNARE_OS=linux|macos|windows` (`darwin` also works, case does not
  matter) selects an OS for every slot in the process, which is the way to
  switch a whole harness such as theater. The value is parsed once; a bad
  one panics on the first snare call, before any lock is held.
- `OsSemantics` also answers questions directly: `errno`, `error_kind`,
  `sys_errno`, `sys_error_kind`, `ephemeral_ports` and `loopback_name`, plus
  `from_name` for parsing.

**Legacy and faithful mode.** A slot whose OS was never chosen is in
*legacy* mode: every result is exactly what snare gave before OS semantics
existed, even though `os_semantics()` reports the host. Choosing an OS,
through `set_os_semantics` or `SNARE_OS`, puts the slot in *faithful* mode,
which turns on the rows tagged *faithful* below. Behaviour that only new
APIs can reach (interfaces from `add_nic`, link down, injected ICMP,
privileges, `snare::fast_talker`) always follows the selected OS.

```rust,ignore
snare::register_test();
snare::set_os_semantics(OsSemantics::Windows);
let s = UdpSocket::bind("127.0.0.1:0").unwrap();
assert!(OsSemantics::Windows.ephemeral_ports().contains(&s.local_addr().unwrap().port()));
let err = UdpSocket::bind("10.9.9.9:5000").unwrap_err();   // no interface owns it
assert_eq!(snare::os_error_code(&err), Some(10049));        // WSAEADDRNOTAVAIL
assert_eq!(err.kind(), std::io::ErrorKind::AddrNotAvailable);
```

**Errors.** Two tables name the errors snare can produce: `Errno` for
socket errors (Winsock codes on Windows) and `SysErrno` for thread, process,
interface and privilege errors (Win32 codes on Windows, such as 1314
`ERROR_PRIVILEGE_NOT_HELD` for `Perm`). An error built for the host OS is a
plain `io::Error::from_raw_os_error`, so `raw_os_error()` and `kind()` match
the real thing exactly. An error built for another OS carries a
`SimOsError { os, code, name }` payload instead. `os_error_code(&e)` reads
the code either way, and is what tests should compare.

`kind()` follows std's mapping for the selected OS, with one difference.
std leaves some codes uncategorized (on macOS `EMSGSIZE`, `ENOBUFS`,
`ENOPROTOOPT` and `ENODEV`; on Windows `WSAEMSGSIZE` and `WSAENOBUFS`), and
code outside std cannot build an `Uncategorized` error. So on the host those
errors report `kind() == Uncategorized`, and emulated off the host they
report `Other`. Assert such errors with `os_error_code`, never `kind()`.

Every point where snare's behaviour depends on the OS:

| # | Area | Linux | macOS | Windows | Applies |
|---|---|---|---|---|---|
| 1 | Ephemeral ports (bind `:0`, connect) | 32768–60999 | 49152–65535 | 49152–65535 | faithful; legacy counts up from 40000 |
| 2 | Bind to an address no interface owns | `EADDRNOTAVAIL` | `EADDRNOTAVAIL` | `WSAEADDRNOTAVAIL` | faithful; legacy gives UDP `InvalidInput`, TCP `AddrNotAvailable` |
| 3 | Port conflict (same port and family, either side wildcard or equal addresses) | `EADDRINUSE` | `EADDRINUSE` | `WSAEADDRINUSE`, but a specific address over a wildcard succeeds | faithful; legacy keys ports by address, so `0.0.0.0:5000` and `10.0.0.2:5000` coexist |
| 4 | Port below 1024 without `net_bind_service` or `root` | `EACCES` | allowed | allowed | always (reachable only after revoking privileges) |
| 5 | Bindable loopback addresses | all of 127/8 | 127.0.0.1 only | all of 127/8 | faithful; legacy allows 127.0.0.1 |
| 6 | UDP broadcast without `SO_BROADCAST` | `EACCES` | `EACCES` | `WSAEACCES` | faithful |
| 7 | UDP datagram too large | over 65507 (v4) / 65527 (v6): `EMSGSIZE` | same, and over `udp_max_dgram` (9216) | `WSAEMSGSIZE` | faithful |
| 8 | Egress interface down (bound device, or strong host) | `ENETDOWN` | `ENETDOWN` | `WSAENETDOWN` | always |
| 9 | No route | `ENETUNREACH` | `ENETUNREACH` | `WSAENETUNREACH` | always |
| 10 | Strong or weak host model | weak | weak | strong: `WSAEHOSTUNREACH` | always |
| 11 | TCP connect to an owned address with no listener | `ECONNREFUSED` at once | at once | `WSAECONNREFUSED` after 2 s virtual | faithful; legacy refuses at once |
| 12 | TCP connect to a routable address nobody owns | `ETIMEDOUT` after 127 s virtual | after 75 s | after 21 s | faithful; legacy gives `AddrNotAvailable`. `connect_timeout` caps the wait |
| 13 | Blocking read timeout | `WouldBlock` (`EAGAIN`) | `WouldBlock` | `TimedOut` (`WSAETIMEDOUT`) | faithful; legacy `WouldBlock` |
| 14 | Non-blocking would-block code | `EAGAIN` (11) | 35 | `WSAEWOULDBLOCK` | faithful; `kind()` is `WouldBlock` everywhere, legacy keeps its old code |
| 15 | UDP receive into a short buffer | truncated, `Ok(len)` | truncated | prefix filled, datagram consumed, `WSAEMSGSIZE` | faithful |
| 16 | ICMP port unreachable, connected UDP socket | next receive or send `ECONNREFUSED` | same | `WSAECONNRESET` | always |
| 17 | ICMP port unreachable, unconnected UDP socket | ignored | ignored | next receive `WSAECONNRESET` | always |
| 18 | ICMP sources | `inject_icmp_port_unreachable(to, from)`, or `NicPolicy::icmp_port_unreachable` for addresses of `add_nic` interfaces (never `add_ip_addr` ones) | | | always |
| 19 | TCP write after the peer closed | first write `Ok` (the peer answers RST), then `EPIPE`; after a RST `ECONNRESET` | same | first write `Ok`, then `WSAECONNRESET` | faithful; legacy `BrokenPipe` |
| 20 | `set_linger(Some(0))` | accepted; drop resets the peer (`ECONNRESET` on its next read) | same | same (`WSAECONNRESET`) | faithful; legacy `InvalidInput` |
| 21 | Non-blocking connect in progress (mio) | `EINPROGRESS` | same | `WSAEWOULDBLOCK` | **not modelled** (below) |
| 22 | `IPV6_V6ONLY` default for `[::]` | off | off | on | faithful |
| 23 | UDP bind to a multicast group address | allowed | allowed | `WSAEADDRNOTAVAIL` | always |
| 24 | Delivery of groups the socket did not join (`IP_MULTICAST_ALL`) | yes unless `only_joined` | joined only | joined only | always |
| 25 | `SO_RCVBUF`/`SO_SNDBUF` | doubled, capped at `rmem_max`/`wmem_max`, with a minimum | `ENOBUFS` over `max_sockbuf` | as given | always (through `snare::fast_talker`) |
| 26 | Bind to device | `SO_BINDTODEVICE` (`net_raw` to rebind) | `IP_BOUND_IF` | `IP_UNICAST_IF`, sends only | always |
| 27 | Ctrl-C and signals | `SIGINT`, `SIGTERM`, `SIGHUP` | same | console events | always |
| 28 | Timestamp source and resolution | nanoseconds, hardware if capable | microseconds, transmit stamped in user space, no drop count | as fast-talker's Windows backend | always |
| 29 | `send_at` (timed send) | `SO_TXTIME` with ETF | `Unsupported` | `Unsupported` | always |
| 30 | fast-talker item availability | per fast-talker's own `cfg`s | | | always |
| 31 | Thread name length | 15 bytes | 63 bytes | unlimited | always |
| 32 | Protocol counter names | `/proc/net/snmp` | `udpstat` | IP Helper | always |
| 33 | Windows timer granularity | | | **not modelled** | |
| 34 | TCP retransmission timeout on a dead link | **not modelled**: bytes stall until the link returns | | | |
| 35 | Delivery to wildcard-bound sockets | exact bind first, then wildcard | same | same (with #22) | always for addresses of `add_nic` interfaces; faithful otherwise |
| 36 | Source address of wildcard sends and TCP clients | the route's `src`, else the egress interface's first address | same | same | as #35 |
| 37 | Loopback interface name | `lo` | `lo0` | `Loopback Pseudo-Interface 1` | always: only the selected OS's name resolves |
| 38 | Windows adapter restart after a ring, coalescing, pause, channel (or other adapter) change | | | link down for `NicCaps::win_restart_flap` (2 s virtual) | always |

What is not modelled:

- **#21.** Under the shim a mio `TcpStream::connect` is the blocking std
  connect, which snare cannot tell apart from a std one. It never reports
  `EINPROGRESS`: a refused or timed-out connect (#11, #12) waits its
  virtual time inside `connect` and returns the final error, where real
  mio returns at once and reports the result later. Test #11 and #12 under
  `sched::testkit::StrictClock` or a fast clock, never under `pause_time`,
  where the connect would never return.
- **#33.** Windows timer granularity (the 15.6 ms default tick) is not
  applied to sleeps or timeouts.
- **#34.** TCP has no retransmission timeout: bytes sent over a downed
  interface wait until it comes back, however long that is.

## Interfaces and routing

With `shim`, network interfaces are part of snare's network. Every state
slot starts with two:

- the loopback, index 1, named `lo`, `lo0` or `Loopback Pseudo-Interface 1`
  after the selected OS, with `127.0.0.1/8` and `::1/128`;
- `snare0`, index 2, with no addresses of its own. It carries the default
  routes (`0.0.0.0/0` and `::/0`, metric 100) and every address added with
  `add_ip_addr`.

`add_ip_addr(ip)` keeps working as before: it assigns `ip/32` (or `/128`) to
`snare0`, loopback addresses to the loopback, and does nothing for an
unspecified address or one an explicit interface already owns. Existing
tests are unaffected.

Tests define more interfaces with `add_nic(NicSpec)`:

- `NicSpec { name, kind, index, addresses: Vec<IpNet>, mac, mtu, link_up,
  speed_mbps, driver: DriverSeed, caps: NicCaps, policy: NicPolicy }`.
  `NicSpec::new(name)` is Ethernet, link up, MTU 1500, 1 Gb/s, with default
  capabilities and a perfect link; `.address(..)`, `.caps(..)` and
  `.policy(..)` build on it. Each address adds a connected route (metric 0).
- `NicCaps` holds what fast-talker can see and set: hardware and software
  timestamping and the PHC index, ring sizes and limits, channel counts,
  `coalesce_supported` (a `CoalesceSupport` bit set in Linux's
  `ETHTOOL_COALESCE_*` order) with its limits, pause, EEE, ntuple and flow
  rule slots, ETF offload, threaded NAPI, queue statistics, driver
  statistic names, and `win_restart_flap`.
- `DriverSeed` is what the driver reports (driver, version, firmware, bus,
  expansion ROM).
- `NicPolicy { latency, jitter, loss_rate, duplicate_rate,
  icmp_port_unreachable }` applies to traffic arriving on the interface.
  Datagrams get loss, duplication, latency and uniform jitter and can
  overtake each other; TCP gets latency and jitter but keeps its byte
  order, and no loss.

At run time: `set_nic(name, |spec| ..)`, `set_link(name, up)`,
`set_nic_policy(name, |p| ..)`, `set_nic_counters(name, |c| ..)` and
`remove_nic(name)`. Routes: `add_route(Route { dest, nic, gateway, src,
metric })`, `remove_route(dest)`, `set_default_route(Some(nic))` and
`routes()`. `route_lookup(src, dst)` answers which interface and source
address a packet would use. `nic(name)`, `nics()` and `nic_counters(name)`
return snapshots, with counters named after Linux's `rtnl_link_stats64`.

**Which interface traffic uses.** A send picks its egress interface from,
in order:

1. the socket's bound device (`SO_BINDTODEVICE`, `IP_BOUND_IF`,
   `IP_UNICAST_IF`, or `set_socket_device` from the test);
2. for a multicast destination, the multicast interface;
3. the loopback for 127/8 and `::1`;
4. the routing table: longest prefix, then the route through the
   interface owning the bound address, then metric, then insertion order.
   Only routes through an up interface count. Under Windows semantics a
   socket bound to a specific address may only leave through that
   address's interface (strong host).

Failures carry the selected OS's code: `ENETDOWN` for a downed bound
device, `ENETUNREACH` with no route, `EHOSTUNREACH` for Windows' strong
host. Datagrams whose receiving interface is down are lost silently; TCP
bytes over a downed interface wait and resume when `set_link(name, true)`
brings it back.

**Interfaces are shared segments.** Two sockets whose addresses sit on the
same interface talk through that interface, not the loopback, so its
policy applies to traffic between a driver and an emulated device in the
same process. The receiving interface is the one owning the destination
address, else the egress interface.

**Modern delivery and source selection.** Two rows change what existing
tests see, so they are scoped: a datagram to a wildcard-bound socket (#35)
and the source address of a wildcard send or TCP client (#36). They apply
in faithful mode, or when the address involved belongs to an interface
added with `add_nic` (an *explicit* interface). Otherwise delivery is as
before: traffic among `add_ip_addr` addresses reaches exactly-bound
sockets and then the virtual testers (`from_local`). In modern delivery a
destination prefers the newest exactly-bound socket, then a wildcard
socket when the host owns the address. The source of a wildcard send is
the destination itself when the host owns it (Linux's local route), else
the route's `src`, else the egress interface's first address of the same
family. `SocketEntry::nic` stays `None` for wildcard sockets;
`last_tx_nic` and `last_rx_nic` show what they used.

**`NicPolicy` and `UdpPolicy`.** `NicPolicy` is the link model for
socket-to-socket traffic. `UdpPolicy` (`set_udp_policy`) still applies
only to traffic from virtual testers and `inject_udp_from_test`, as
before.

**Socket buffers and drops.** A receive buffer set through
`snare::fast_talker` is enforced when a datagram reaches the socket
(Linux charges each datagram `per_datagram_overhead` bytes on top of its
payload). Buffers that were never set are unlimited unless
`SysLimits::enforce_default_rcvbuf` is on. `SysLimits::drop_accounting`
decides what counts as a socket drop: `PolicyAndOverflow` (the default)
counts wire loss and overflow, `OverflowOnly` counts overflow only, as a
real kernel does.

**Sockets have identity.** Every UDP socket, TCP stream and TCP listener
gets a `SocketId` when it is created, never reused; read it with
`socket_id(&sock)` (the sealed `SimSocket` trait covers snare's
`UdpSocket`, `TcpStream` and `TcpListener`). Queries return `SocketEntry`
values (kind, local and peer address, the listener of an accepted stream,
owning interface, bound device, multicast interface and memberships, last
interfaces used, buffer sizes, queue depth, delivered, overflowed,
wire-lost and dropped counts, a pending ICMP error, and when it was created
and closed):

- `socket_entry(id)`: live or closed;
- `sockets_bound(addr)`: every live socket on an address (a listener and
  all its accepted streams, say);
- `socket_table()`: every live socket;
- `closed_sockets()`: the closed ones.

`set_socket_device(id, Some(nic))` binds a socket to an interface from the
test, and `inject_socket_drops(id, n)` adds to its drop count.

A UDP socket closes when its last handle (including `try_clone` copies)
drops, freeing its port.

**Privileges and system limits.** `set_privileges(|p| ..)` controls what
the simulated process may do: `root`, `net_admin`, `net_raw`,
`net_bind_service`, `sys_nice`, `ipc_lock`, `rtprio_limit` (99),
`nice_limit` (-20) and `memlock_limit` (unlimited). Everything is granted
by default; revoke a privilege to make a privileged call fail as it would.
Several checks accept `root` in place of a capability, as a real root
process has them all, so revoke both. `set_sys_limits`
sets `rmem_default`, `rmem_max`, `wmem_default`, `wmem_max`,
`max_sockbuf`, `udp_max_dgram`, `enforce_default_rcvbuf`,
`per_datagram_overhead` and `drop_accounting`. Their defaults follow the
selected OS: 212992 for every Linux buffer value; 786896 and 9216 with an
8 MiB maximum and a 9216-byte datagram limit on macOS; 65536 and no
maximum on Windows.

**Reordering.** Datagrams in flight are kept in delivery order, so
`UdpPolicy::reorder_jitter` (and `NicPolicy::jitter`) reorders datagrams
instead of holding later ones behind an earlier, slower one.

A worked example:

```rust,ignore
use std::time::Duration;
use snare::net::UdpSocket;
use snare::{IpNet, NicPolicy, NicSpec, OsSemantics, Route};

snare::register_test();
snare::set_os_semantics(OsSemantics::Linux);

snare::add_nic(NicSpec::new("eth0").address("10.0.0.1/24".parse::<IpNet>().unwrap())).unwrap();
snare::add_nic(
    NicSpec::new("eth1")
        .address("192.168.1.10/24".parse::<IpNet>().unwrap())
        .address("192.168.1.20/24".parse::<IpNet>().unwrap())
        .policy(NicPolicy { latency: Duration::from_micros(200), ..Default::default() }),
)
.unwrap();
snare::add_route(Route::new("172.16.0.0/16".parse().unwrap(), "eth1")).unwrap();
assert_eq!(
    snare::route_lookup(None, "172.16.4.2".parse().unwrap()).unwrap(),
    ("eth1".to_string(), Some("192.168.1.10".parse().unwrap()))
);

// The emulated device and the driver share eth1.
let device = UdpSocket::bind("192.168.1.20:3956").unwrap();
let host = UdpSocket::bind("0.0.0.0:0").unwrap();
host.send_to(b"discover", "192.168.1.20:3956").unwrap();
let mut buf = [0u8; 64];
let (n, _from) = device.recv_from(&mut buf).unwrap();
assert_eq!(&buf[..n], b"discover");

let entry = snare::socket_entry(snare::socket_id(&host)).unwrap();
assert_eq!(entry.last_tx_nic.as_deref(), Some("eth1"));
assert_eq!(snare::nic_counters("eth1").unwrap().rx_packets, 1);

snare::set_socket_device(snare::socket_id(&host), Some("eth1")).unwrap();
snare::set_link("eth1", false).unwrap();
let err = host.send_to(b"again", "192.168.1.20:3956").unwrap_err();
assert_eq!(snare::os_error_code(&err), Some(100)); // ENETDOWN
```

**Migrating a harness (theater).** Nothing changes until a harness opts in.
Addresses added with `add_ip_addr` sit on `snare0` and keep legacy
delivery, so virtual testers keep reading traffic for them from
`from_local`. Set `SNARE_OS=linux` once no tester depends on `from_local`
for traffic to an address the host owns and a wildcard socket listens on:
from then on such traffic reaches the socket. ICMP port unreachable is only
ever generated for addresses of `add_nic` interfaces with
`NicPolicy::icmp_port_unreachable` on, so testers behind `add_ip_addr`
addresses never trigger it.

## Features

- `shim` — turn on the in-process mock. Off by default so production
  builds re-export the real types.
- `mio-compat` — expose `snare::mio`. Required if your SUT uses `mio`
  directly; otherwise leave it off.
- `ctrlc-compat` — expose `snare::ctrlc`. Required if your SUT uses
  `ctrlc`; otherwise leave it off. `ctrlc-termination` also turns on
  `ctrlc`'s `termination` feature (SIGTERM and SIGHUP).
- `fast-talker-core`, `fast-talker-compat` and the other `fast-talker-*`
  features — expose `snare::fast_talker` (see [fast-talker](#fast-talker)).

### Ctrl-C

With `shim` on, `snare::ctrlc::set_handler` registers one handler per state
slot (a second call returns `Error::MultipleHandlers`, as does
`try_set_handler`). The handler runs once per Ctrl-C on a dedicated `ctrl-c`
thread spawned through `snare::thread`: under an accounting driver it is a
participant that is blocked (wait `"ctrlc"`) while idle, and it reads virtual
time. `snare::ctrlc::raise()` delivers a virtual Ctrl-C to the calling
thread's slot and returns whether a handler was set. The handler thread is
made runnable before the wake, a raise inside `enter_timestamp` is deferred
until `leave_timestamp`, and a raise from a background thread is recorded as
a class effect rather than a stray. The first virtual handler also installs
the real `ctrlc` handler, so a real Ctrl-C is forwarded to every slot's
handler from `ctrlc`'s own thread, which is marked background. Without `shim`,
`snare::ctrlc` is `ctrlc` and has no `raise`.

`snare::ctrlc::raise_signal(VirtualSignal) -> SignalDelivery` delivers any
signal the selected OS has, as that OS and `ctrlc` would:

- Unix semantics have `Interrupt` (`SIGINT`), `Terminate` (`SIGTERM`) and
  `Hangup` (`SIGHUP`). `Interrupt` always reaches the handler (`Handled`);
  `Terminate` and `Hangup` reach it only with `ctrlc-termination`, and
  otherwise report `DefaultAction`.
- Windows semantics have `Interrupt` (`CTRL_C_EVENT`), `Break`, `Close`,
  `Logoff` and `Shutdown`. `ctrlc`'s console handler receives all of them
  with or without `termination`. `Interrupt` and `Break` are `Handled`;
  `Close`, `Logoff` and `Shutdown` are `HandledThenExit`, because the real
  OS ends the process once the handler returns. snare never exits; it
  reports this so a harness can act on it.
- A signal the OS does not have is `Unavailable`, and any signal with no
  handler set is `DefaultAction`.

`snare::time` and its clock controls (`set_time_rate`, `pause_time`, ...) also
live behind `shim` — off the feature, `snare::time` is a plain `std::time`
re-export and the controls aren't compiled. `snare::sched` and
`snare::thread::sleep_until` exist in both builds.

## fast-talker

`snare::fast_talker` is a drop-in for the [`fast-talker`] crate (timestamped
sockets, NIC tuning, IRQs, real-time threads, system checks, counters and
the monitor). A crate switches by writing `snare::fast_talker::` where it
wrote `fast_talker::`. Without `shim` the module is `pub use
::fast_talker::*`, so real hardware behaves exactly as before. With `shim`,
everything that touches the OS works on snare's interfaces, threads and
virtual clock instead, and the test can seed and query all of it.

[`fast-talker`]: https://github.com/valstad-shipworks/fast-talker

### Features

| Feature | fast-talker features |
|---|---|
| `fast-talker-core` | none (sockets, timestamps, `nic`, `irq`, `rt`, `multicast`, `counters`) |
| `fast-talker-plan` | `plan` |
| `fast-talker-options` | `options` |
| `fast-talker-sys-check` | `sys-check` |
| `fast-talker-monitor` | `monitor` (with `plan` and `options`) |
| `fast-talker-serde` | `serde` |
| `fast-talker-pyo3` | `pyo3` (with `options`); `snare::fast_talker::py` is fast-talker's |
| `fast-talker-compat` | fast-talker's default features: what a plain `fast-talker = "0.1"` gives |

`mio-compat` also turns on `fast-talker/mio`, so `Timestamped` and
`TimestampedStream` over snare's mio sockets are mio sources. `shim`, when
fast-talker is enabled at all, turns on fast-talker's hidden `sim` feature
and every fast-talker feature snare hooks (`plan`, `options`, `sys-check`,
`monitor`), so the whole surface is simulated whatever another crate in the
build enables. The `fast-talker-*` sub-features only shape the non-shim
build.

```toml
[dependencies]
snare = { version = "1", features = ["fast-talker-compat"] }

[dev-dependencies]
snare = { version = "1", features = ["shim", "fast-talker-compat", "mio-compat"] }
```

### What stays fast-talker's, and what snare owns

Under `shim`, fast-talker's data types are re-exported, so they are the
same types (same `TypeId`) as in a non-shim build, and config files, serde
and pyo3 conversions keep working:

- the root types `Config`, `Source`, `Timestamp`, `TxTimestamp`, `Sent`,
  `Received`, `Hardware`, `TxTime`, `TxTimeError`, `TxTimeErrorKind`;
- all of `latency`, `counters`, `plan`, `options` (including
  `SocketOption`), `sys_check` and `sockets` (including `SocketOptions`,
  `SocketMemory` and `incoming_cpu`);
- all of `monitor`: `Monitor`, `Config`, `WatchedSocket`, `Sample` and the
  rest;
- `tcp::{Stage, TxEvent, TcpInfo}`, the `nic` value types (`DriverInfo`,
  `LinkStats`, `Rings`, `Coalesce`, `Pause`, `Channels`, the flow rule
  types) and `rt::{Scheduler, ThreadPriority, ProcessPriority, QosClass}`.

snare owns every item that holds an OS handle or reads OS state:
`Socket`, `Timestamped`, `tcp::{Stream, TimestampedStream}`,
`nic::{Nic, DriverStats, Napi}`, all of `irq` and `multicast`, and
`rt::{Thread, CpuDmaLatency, TimerResolution, Mmcss}` with the process
functions (`lock_memory`, `isolated_cpus`, `prefault_stack`, …). They keep
fast-talker's signatures, but every item exists on every host; whether it
works is decided by `os_semantics()` at run time and fails with
`Unsupported` (`"… is not supported on <os> (snare simulated)"`) otherwise.
Two host-shaped details remain:

- `rt::Thread::pin` takes a `Scheduler` off Windows hosts and a
  `ThreadPriority` on Windows hosts, as fast-talker's does;
  `pin_scheduler` and `pin_priority` exist everywhere.
- Where the host's fast-talker lacks a `nic` value type (`Eee` off Linux
  and Windows, `Rss` off Windows, `Etf`, `Qdisc`, `ClockOffset`,
  `QueueStats`, `OffsetMethod` and `QueueKind` off Linux), snare defines a
  copy with the same fields, methods and serde attributes, so a macOS host
  can simulate Linux. `monitor::InterfaceSample::{queue_delta, clock}`
  exist only on Linux hosts, so they are only filled there.

`Timestamped`, `TimestampedStream`, `multicast` and `Nic::napi_for_socket`
take snare sockets through the sealed `SimSocket` trait. fast-talker's
`Socket` trait is open, but under the shim a crate cannot put `Timestamped`
over its own socket wrapper; wrap the `Timestamped` instead.

### fast-talker's hidden `sim` feature

snare needs a small, additive feature in fast-talker, `sim`, which is off
by default, hidden from its docs and changes nothing when off:

- constructors for its `#[non_exhaustive]` result types, so snare can build
  real `Sent`, `Received`, `Sample`, `Finding` and similar values;
- `AsHandle` widening: `SocketOptions::apply`, `SocketOption::apply_all`,
  `SocketMemory::of`, `sockets::incoming_cpu` and `WatchedSocket::new` take
  `&impl AsHandle` instead of `&impl AsFd` (`AsSocket` on Windows). Every
  `AsFd` type is `AsHandle`, so existing callers compile unchanged, and
  snare's sockets hand fast-talker a simulated handle that goes to snare,
  never to a syscall;
- guards on raw handles below zero: raw-fd paths (`multicast::*`,
  `TcpInfo::of`, the raw socket-option and memory paths) given a snare
  socket, whose raw fd is -1, fail with `Unsupported` ("no OS socket (snare
  shim): use snare::fast_talker") before any syscall;
- a backend hook at the top of fast-talker's own entry points
  (`Plan::apply`/`check`, thread and process options, `sys_check`,
  `Check::recommended`/`privileges`, `Counters::read`, `sockets::udp`/`tcp`,
  `Monitor::start`, `Timestamp::elapsed`, `RoundTrips::sent`, and the
  platform choice in `options::Target::here`). The hooks answer only on a
  thread that belongs to a snare state slot; on any other thread fast-talker
  does exactly what it always did, so enabling `shim` in a test binary never
  changes real fast-talker calls elsewhere.

snare installs its backend on its first call in the process (any state
access, `register_test`, a socket constructor). A harness that may call
fast-talker before touching snare calls `snare::fast_talker::sim::install()`
first. Under `--cfg snare_global`, make one snare call (such as
`snare::os_semantics()`) before the code under test starts.

### `compat`

`snare::fast_talker::compat` has helpers spelled the same with and without
`shim`:

- `now() -> std::time::SystemTime`: snare's virtual wall clock under the
  shim, `SystemTime::now()` otherwise;
- `tcp_info(&stream)`: `TcpInfo::of`, which cannot take a snare stream;
- `apply_thread_options_to(thread, &options, &rules)`:
  `ThreadOption::apply_all_to` for an `rt::Thread`, which is snare's type
  under the shim.

Two fast-talker calls still compile with a snare socket, because snare
sockets implement `AsRawFd` (returning -1), and fail at run time with the
`Unsupported` guard: `TcpInfo::of(&snare_stream)` (use `compat::tcp_info`)
and `fast_talker::multicast::*` on a snare socket (use
`snare::fast_talker::multicast`).

### Time and timestamps

- A receive stamp is the virtual instant the datagram reached the socket,
  not when it was read, so a slow reader sees the true queueing delay.
  Hardware stamps sit `StackDelay::hw_rx_before_kernel` earlier and carry
  `hardware_raw` with the interface's PTP offset (`sim::set_ptp`).
- A transmit stamp is the send instant, or the launch instant of a timed
  send. `Received::drops` is the socket's drop count when the datagram was
  queued, which reflects `NicPolicy` loss, `UdpPolicy` loss and receive
  buffer overflow (see `DropAccounting`).
- Sources follow the emulated OS: on Linux, kernel stamps, or hardware ones
  when the interface has `NicCaps::hw_rx_timestamp`, the process has
  `net_admin` and the PTP clock is within tolerance; on macOS, microsecond
  kernel stamps, transmit stamps in user space and no drop count; on
  Windows, as fast-talker's Windows backend.
- `Timestamp::elapsed` and `RoundTrips::sent` read the virtual clock on a
  snare thread.
- Code that passes its own time, `send_at(at)`, `send_to_at` or
  `RoundTrips::poll(now, ..)`, must take it from `compat::now()` or
  `snare::time::SystemTime::now().into()`. `std::time::SystemTime::now()`
  does not follow snare's clock, so it gives wrong launch times, round
  trips and loss figures.
- `send_at` needs Linux semantics. With an ETF qdisc on the outgoing
  interface (`Nic::set_etf`, or `sim::set_etf` from the test) the datagram
  is held until its launch instant, and late or mismatched launch times are
  reported as `TxTimeError`s (`sim::inject_txtime_missed` forces misses).
  Without ETF it is sent at once and logs `FtEvent::TxTimeWithoutEtf`.
- A ready transmit stamp or timed-send error makes the socket poll as
  errored, level-triggered, as with a real error queue.

### The test context: `snare::fast_talker::sim`

Seeds that are not fast-talker-specific live in snare's root (interfaces,
capabilities, policies, counters, routes, privileges, limits, drops, OS
semantics). `sim` adds the rest:

- seeds: `set_cpus(CpuTopology)`, `set_sys_facts(|f| ..)` (`SysFacts::tuned()`
  is the default, `stock()` a fresh install), `set_ptp`, `set_tai_offset`,
  `set_stack_delay`, `set_etf`, `set_driver_stats`, `bump_driver_stat`,
  `set_queue_stats`, `set_irq`, `set_protocol_counters`,
  `inject_txtime_missed`, `mutate_interface`;
- queries: `threads`, `thread_named`, `thread_of(ThreadId)`,
  `thread_by_tid` (`ThreadSnapshot`: scheduler, nice, affinity, QoS,
  time constraint, Windows priority, MMCSS, prefaulted stack, the live
  snare thread class and a log of every setting applied or refused);
  `process` (memory lock, CPU DMA latency requests, timer resolution,
  priority class); `socket`/`sockets` (`FtSocketSnapshot`: the `SocketEntry`,
  timestamping config and source, `SocketOptions` asked for and
  `SockOptsSnapshot` in force, memberships, pending stamps);
  `interface`/`interfaces` (rings, coalescing, pause, channels, EEE,
  threaded NAPI, queues, flow rules, qdiscs and ETF, timestamping mode,
  apply log); `irq`/`irqs`; `incoming_cpu`; `plans_applied`, `sys_checks`,
  `monitors` (each monitor's whole config, thread, sample count, last
  sample and errors); `events`/`clear_events`.

```rust,ignore
use snare::fast_talker::rt::{self, Scheduler};
use snare::fast_talker::{sim, sockets::SocketOptions};
use snare::{OsSemantics, net::UdpSocket};

snare::register_test();
snare::set_os_semantics(OsSemantics::Linux);
snare::set_privileges(|p| {
    p.root = false;
    p.net_admin = false;
});

let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
let id = snare::socket_id(&sock);
let _sock = snare::thread::Builder::new()
    .name("rx-loop".into())
    .spawn(move || {
        rt::Thread::current().pin_scheduler(&[2], Scheduler::Fifo(80)).unwrap();
        SocketOptions { recv_buffer: Some(4 << 20), ..Default::default() }
            .apply(&sock)
            .unwrap();
        sock
    })
    .unwrap()
    .join()
    .unwrap();

let t = sim::thread_named("rx-loop").unwrap();
assert_eq!(t.scheduler, Some(Scheduler::Fifo(80)));
assert_eq!(t.affinity, Some(vec![2]));

let s = sim::socket(id).unwrap();
assert_eq!(s.options.recv_buffer, Some(4 << 20));           // asked for
assert_eq!(s.sockopts.recv_buffer, Some(2 * 212_992));      // no CAP_NET_ADMIN: capped, doubled
```

### Scheduling

The shim follows `snare::sched`'s rules, so it works under an accounting
driver:

- Nothing in the shim moves time. Stamps are read from the virtual clock;
  future effects (a delayed datagram, a timed send, a stamp, the end of a
  Windows adapter restart) are scheduled for their instant and woken then.
- Blocking calls are snare waits with virtual deadlines; `drain` never
  blocks.
- The monitor runs on a background thread, `fast-talker-mon`, that is never
  a participant. It parks until the next interval of virtual time; each
  sample holds a `busy` lease from before it is read until the callback
  returns, so under a driver time stands still while a sample is handled.
  A lease keeps the domain busy even while its holder waits, so **the
  callback must not block on a snare wait**. Stopping or dropping the
  monitor wakes it at once and joins it (it detaches when called with
  driver time).
- Real-time settings are recorded only; they never change how snare
  schedules a thread.

### The `SO_RCVBUF … not applied: Bad file descriptor` warning

A snare socket has no OS socket, and its raw fd is deliberately -1. Crate
code that sets options through the raw fd, such as

```rust,ignore
libc::setsockopt(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, ..)
```

gets `EBADF` under the shim (and logs the warning). snare cannot intercept
libc. The fix is in the crate: set the option through fast-talker, which
works on a real socket (`AsFd`) and a snare socket alike:

```rust,ignore
use snare::fast_talker::sockets::SocketOptions;

SocketOptions { recv_buffer: Some(n), ..Default::default() }.apply(&sock)?;
```

or `snare::fast_talker::options::SocketOption::RecvBuffer(n)` with
`SocketOption::apply_all`. The same applies to raw `recvmsg` and error-queue
code: use `Timestamped` and `TimestampedStream`.

### Lints for `sim_time_lint`

Patterns a crate's simulation lint should flag, because they bypass snare
or read the wrong clock:

- `.as_raw_fd()` / `.as_raw_socket()` on a snare socket;
- `libc::setsockopt`, `libc::getsockopt`, `libc::recvmsg`, `libc::sendmsg`
  (and `MSG_ERRQUEUE` reads) on a socket;
- `TcpInfo::of` (use `compat::tcp_info`);
- `fast_talker::multicast::*` with a snare socket (use
  `snare::fast_talker::multicast`), and any remaining `fast_talker::` path
  that should be `snare::fast_talker::`;
- `std::time::SystemTime::now()` passed to `send_at`, `send_to_at` or
  `RoundTrips::poll` (use `compat::now()`);
- `Timestamp::elapsed` in code that may run on a thread outside snare,
  where it reads the real clock against virtual stamps.

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
- Packet timestamps are the virtual `SystemTime`. Set
  `SNARE_PCAPNG_WALL_COMMENT` to add each packet's wall time as a packet
  comment.
- IP/TCP/UDP checksums are written as zero (Wireshark reads these as
  "checksum offload"); MACs are deterministic from the socket addr.
