# snare shims

Drop-in `[patch.crates-io]` replacements for crates whose behaviour an import-table interposer
(snare) cannot see or cannot replay. Shimming is the last resort: each one here exists because no
hook reaches what the crate does. Every shim is a vendored copy of the named upstream release with
the smallest change that fixes it; outside every sim, and in a build without `--cfg snare`, each
behaves as upstream.

## Default shims

`cargo snare test` patches these whenever their crate (in the listed release line) is in the
dependency graph, because without them the crate escapes the sim or replays differently.

| shim | replaces | what changed, and why |
|------|----------|-----------------------|
| `sc/`       | `sc` 0.2        | `syscallN` and the `syscall!` macro forward to `libc::syscall`; `nr` tables vendored. Inline `syscall`/`svc` instructions are invisible to the interposer |
| `syscalls/` | `syscalls` 0.8  | only the raw `syscall/mod.rs` layer is rerouted to `libc::syscall`, for the same reason |
| `io-uring/` | `io-uring` 0.7  | the ring is emulated in-process and each SQE is executed via libc: a real ring moves I/O through shared memory, with no call per operation |
| `xsk-rs/`   | `xsk-rs` 0.8    | rewritten drop-in; the AF_XDP UMEM and its four rings are emulated in-process and every frame crosses a real fd via libc `send`/`recv` |
| `quanta-0.12/`, `quanta-0.13/` | `quanta` 0.12, 0.13 | under `cfg(snare)`, `Clock::new` never picks the counter source (`rdtsc` on x86_64, `cntvct_el0` on aarch64), so every clock reads `clock_gettime`/`QueryPerformanceCounter`. Counter reads are instructions the interposer cannot see, and the ~200 ms calibration against the OS clock would run on, and spend, the virtual time of whichever sim made the first clock |
| `minstant/`, `fastant/` | `minstant` 0.1, `fastant` 0.1 | under `cfg(snare)`, the load-time constructor skips TSC detection (it reads the real `/sys/devices/system/clocksource/.../available_clocksource`), so `Instant` comes from the OS clock instead of `rdtsc` on x86 Linux |
| `fastrand/` | `fastrand` 2 | under `cfg(snare)`, a thread-local generator seeded outside the sim the thread now runs in is reseeded on its first use there, and inside a sim the seed hashes the sim's clock and a count of generators the sim has seeded instead of the thread id. A `ThreadId` is a process-wide counter that no OS call produces, so a deterministic sim's draws (tempfile names, async-executor's steal order) depended on how many threads the process had made before it. A seed set with `fastrand::seed` is kept |
| `rayon-core/` | `rayon-core` 1 | inside a sim, each worker's steal-victim generator is seeded by its index in its pool instead of a process-wide counter of every worker ever started, so a pool built in a deterministic sim steals in the same order on every run. Its per-sim global pool is parallel-only (below) |

The harness applies them together with `--cfg rustix_use_libc`, which moves rustix's own backend
onto libc. With that flag plus these patches, the raw-syscall sources found across the top
networking crates are covered.

## Parallel-only shims

These crates already reach the OS through libc, but keep a reactor, an executor or a thread pool in
process-wide statics, which one sim would otherwise create and every later sim inherit. Sims still
work without these shims, taking turns on the shared state; two running at once would share
threads that poll one sim's tasks and fire another's wakers, which neither sim's quiescence can
account for. Each shim keeps one per sim instead (a `snare_interpose::sim_local`), shut down as the
sim drops.

| shim | replaces | what changed |
|------|----------|--------------|
| `async-io/` | `async-io` 2.6  | one reactor and "async-io" thread per sim; the process-wide one only outside every sim |
| `async-global-executor/` | `async-global-executor` 2.4 | async-std's global executor and its worker threads, one set per sim |
| `blocking/` | `blocking` 1.7 | the `unblock` thread pool, one per sim |
| `smol/` | `smol` 2.0 | `smol::spawn`'s global executor and its "smol-N" threads, one set per sim; the threads exit, and the executor's unfinished tasks are dropped, when the sim ends |
| `rayon-core/` with `--cfg snare_parallel_rayon` | `rayon-core` 1 | the global pool (`rayon::join`, `par_iter` outside `install`, `rayon::spawn`, `build_global`) is the sim's own; its workers exit when the sim ends |

They are opt-in, since most suites need few or none of them:

```console
$ cargo snare test --parallel smol             # async-io, blocking, smol
$ cargo snare test --parallel async-std,rayon  # async-io, async-global-executor, blocking; rayon's per-sim pool
$ cargo snare test --parallel all
```

`--parallel` takes runtime names (`async-std`, `smol`, `rayon`), crate names (`async-io`,
`async-global-executor`, `blocking`, `rayon-core`), `all` and `none`, comma-separated or repeated.
To keep the selection with the code, put it in the manifest; `cargo snare test` reads the union of
the workspace's and every member's list, and a `--parallel` on the command line replaces it:

```toml
[package.metadata.snare]        # or [workspace.metadata.snare]
parallel = ["smol", "rayon"]
```

A parallel shim is still only patched when its crate is in the dependency graph, and
`--parallel rayon` adds `--cfg snare_parallel_rayon` to `RUSTFLAGS` (which rebuilds every crate
once when it changes). `cargo snare test --dry-run` prints the shims patched and the active
selection. `--all-shims` patches every default shim, and every parallel shim the selection names,
whether or not the graph has its crate; it never selects a parallel shim by itself.

## Patching by hand

`cargo snare test` patches the shims in from this repository at its release tag. To apply them by
hand in a consumer manifest (a crate with a shim per release line takes a patch key per line, with
`package` and `version` to pick the shim):

```toml
[patch.crates-io]
sc          = { git = "https://github.com/valstad-shipworks/snare", tag = "v3.1.0" }
syscalls    = { git = "https://github.com/valstad-shipworks/snare", tag = "v3.1.0" }
io-uring    = { git = "https://github.com/valstad-shipworks/snare", tag = "v3.1.0" }
xsk-rs      = { git = "https://github.com/valstad-shipworks/snare", tag = "v3.1.0" }
quanta_0_12 = { git = "https://github.com/valstad-shipworks/snare", tag = "v3.1.0", package = "quanta", version = "0.12" }
quanta_0_13 = { git = "https://github.com/valstad-shipworks/snare", tag = "v3.1.0", package = "quanta", version = "0.13" }
minstant    = { git = "https://github.com/valstad-shipworks/snare", tag = "v3.1.0" }
fastant     = { git = "https://github.com/valstad-shipworks/snare", tag = "v3.1.0" }
fastrand    = { git = "https://github.com/valstad-shipworks/snare", tag = "v3.1.0" }
rayon-core  = { git = "https://github.com/valstad-shipworks/snare", tag = "v3.1.0" }
# parallel-only, as needed:
async-io    = { git = "https://github.com/valstad-shipworks/snare", tag = "v3.1.0" }
async-global-executor = { git = "https://github.com/valstad-shipworks/snare", tag = "v3.1.0" }
blocking    = { git = "https://github.com/valstad-shipworks/snare", tag = "v3.1.0" }
smol        = { git = "https://github.com/valstad-shipworks/snare", tag = "v3.1.0" }
```

Patch only the crates the graph has (cargo warns about an unused patch), build with `--cfg snare`,
and add `--cfg snare_parallel_rayon` for rayon's per-sim pool.

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
