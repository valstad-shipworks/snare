# snare syscall shims

Drop-in `[patch.crates-io]` replacements for the crates that reach the Linux kernel with an
inline `syscall`/`svc` instruction instead of going through libc. Under an import-table interposer
(snare) an inline instruction is invisible; routing the same calls through libc's `syscall` symbol
(and the ordinary socket/file functions) makes them observable, and for modelled calls,
redirectable.

The snare test harness applies these together with `--cfg rustix_use_libc` (which moves rustix's
own backend onto libc). With that flag plus these patches, the raw-syscall sources found across the
top networking crates are covered.

| shim | replaces | how |
|------|----------|-----|
| `sc/`       | `sc` 0.2        | `syscallN` and the `syscall!` macro forward to `libc::syscall`; `nr` tables vendored |
| `syscalls/` | `syscalls` 0.8  | vendored crate; only the raw `syscall/mod.rs` layer is rerouted to `libc::syscall` |
| `io-uring/` | `io-uring` 0.7  | vendored crate; the ring is emulated in-process and each SQE is executed via libc |
| `xsk-rs/`   | `xsk-rs` 0.8    | rewritten drop-in; the AF_XDP UMEM and its four rings are emulated in-process and every frame crosses a real fd via libc `send`/`recv` |

`cargo snare test` patches them in from this repository at its release tag. To apply them by hand
in a consumer manifest:

```toml
[patch.crates-io]
sc        = { git = "https://github.com/valstad-shipworks/snare", tag = "v2.0.0" }
syscalls  = { git = "https://github.com/valstad-shipworks/snare", tag = "v2.0.0" }
io-uring  = { git = "https://github.com/valstad-shipworks/snare", tag = "v2.0.0" }
xsk-rs    = { git = "https://github.com/valstad-shipworks/snare", tag = "v2.0.0" }
```

These are for **test/simulation builds only**, never release. Each `syscallN` returns the kernel's
own value (a negative errno on failure), so callers that decode the raw result behave unchanged.

## io_uring emulation scope

The ring's submission/completion queues and opcode builders are the real crate's; only
`io_uring_setup`, the ring `mmap`, and `io_uring_enter` are replaced. Submission is **synchronous**:
each `submit`/`submit_and_wait` runs the queued SQEs immediately via libc and posts completions.

Covered opcodes: `Nop`, `Read`/`Write` (with offset), `Readv`/`Writev`, `Fsync`, `Send`/`Recv`,
`SendMsg`/`RecvMsg`, `Accept`, `Connect`, `Close`, `Shutdown`, `PollAdd` (blocking readiness),
`Timeout`. Anything else completes with `-EINVAL`.

Not emulated (registration returns `-ENOSYS`): SQPOLL, IOPOLL, registered buffers/files (Fixed),
multishot, linked SQEs, provided-buffer rings.

## AF_XDP (xsk-rs) emulation scope

Real AF_XDP moves frames through an `mmap`'d UMEM shared with the kernel, so no per-frame syscall
ever crosses the interposer. The shim replaces the kernel entirely: the UMEM is one heap
allocation divided into frames, the fill/completion/TX/RX rings are in-process `VecDeque`s, and the
socket is a `socketpair`. `tx_q.produce`/`produce_one` enqueue descriptors; `tx_q.wakeup` is the
seam where each frame leaves the process via libc `send`. `rx_q.poll_and_consume` pulls frames in
via libc `recv` into a buffer drawn from the fill queue. `needs_wakeup` reports whether TX frames
are still queued. An interposer that hooks `send`/`recv` sees these frames exactly as it does
`AF_PACKET` ones.

Faithful: the descriptor lifecycle (write UMEM → TX → completion; fill → RX), the
`needs_wakeup`/`wakeup` flush contract, and frame byte contents. Not emulated: any kernel/XDP
behaviour, zero-copy, shared-UMEM binds (`Socket::new` always returns the fill/comp pair as
`Some`), the interface name and `queue_id` (accepted and ignored), and all flags beyond
`XDP_USE_NEED_WAKEUP`'s wakeup semantics. With no interposer present the backing `socketpair` loops
TX straight back to RX, which is what the crate's round-trip test exercises.
