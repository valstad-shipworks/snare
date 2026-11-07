# Testers and recorded events

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
| `UnmodelledOption { socket, local, option, refused }` | the code under test first uses, on that socket, a socket option or ioctl the sim does not model; `refused` under `strict_sockopts`. See [Unmodelled options](sockets.md#unmodelled-options-and-strict_sockopts). |

`clear_recorded_events()` starts a fresh phase (sequence numbers carry on), and
`SimBuilder::record_events(false)` keeps nothing, for a long, chatty run. Recording never moves the
clock, yields or wakes a thread, so a `deterministic()` run logs the same entries, in the same order,
with the same stamps, every time, and logs or not without changing the run; on the free-running
virtual clock, events from different threads at the same instant may come out in either order.
Coming from the original snare: `UdpSendFromTest { dropped }` is a `Sent` followed by a
`Link { fault: Lost | TooBig }`.
