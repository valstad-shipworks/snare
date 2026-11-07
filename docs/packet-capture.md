# Packet capture

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
