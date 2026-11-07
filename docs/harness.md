# The cargo snare harness, snare::real and the shims

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
snare = "^3"

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
`cargo --config patch.crates-io...`, from the snare release the lock file resolved (tag `vX` for
a crates.io snare `X`, with `snare` and `snare-interpose` patched from it so one interposer is
linked), or from the checkout or git reference a path or git snare comes from. Plain `cargo test`
builds neither snare nor the `#[cfg(snare)]` tests.

The cfgs go in through `RUSTFLAGS` (appended to any already set), and cargo then ignores
`build.rustflags` and `target.*.rustflags` from `.cargo/config.toml`. A crate that relies on cfgs
from its own config file must put them in `RUSTFLAGS` as well; a `CARGO_ENCODED_RUSTFLAGS` in the
environment overrides both and drops the snare cfgs. `cargo snare test --dry-run` prints the
shims patched, the crates given per-sim state by `--parallel` (see [Shims](#shims-shims)), and the
assembled command.

## Shims (`shims/`)

Some crates bypass libc in ways an import-table hook cannot see — raw `io_uring` rings in mmap'd memory,
`AF_XDP` UMEM, CPU counter reads — or seed from process-wide state a sim cannot replay. For those,
snare provides drop-in replacement crates injected via `[patch.crates-io]`. `cargo snare test`
patches these whenever their crate is in the dependency graph:

- **`io-uring`** — emulates the ring in-process, executing each SQE through libc `read`/`write` so the
  interposer sees ordinary I/O.
- **`xsk-rs`** (AF_XDP) — routes frame TX/RX through libc `send`/`recv`.
- **`sc`, `syscalls`** — route raw syscalls through libc so the `syscall` hook catches them.
- **`quanta`** (0.12 and 0.13), **`minstant`**, **`fastant`** — never read the TSC or the aarch64
  system counter, so their clocks are the sim's; quanta also skips its ~200 ms calibration spin.
- **`fastrand`** — seeds each thread's generator inside a sim from the sim instead of the
  process-wide thread id, so deterministic sims replay whatever ran before them.
- **`rayon-core`** — seeds each worker's steal order by its index in its pool, so pools built in a
  deterministic sim replay.

Others only let concurrent sims each keep their own copy of a runtime's process-wide state; sims
work without them by taking turns, so they are opt-in with `--parallel` (or `parallel = [...]`
under `[package.metadata.snare]` / `[workspace.metadata.snare]`):

- **`async-io`** — one reactor and "async-io" thread per sim instead of per process, shut down
  when the sim drops.
- **`async-global-executor`, `blocking`** — async-std's global executor and the `unblock` thread pool,
  one per sim, so async-std tasks and blocking jobs of one sim never run on another's threads.
- **`smol`** — `smol::spawn`'s global executor and "smol-N" threads, one set per sim.
- **`rayon-core`** with `--cfg snare_parallel_rayon` — rayon's global pool, one per sim.
- **`futures-timer`** — the "futures-timer" thread every `Delay` is timed on, one per sim, shut
  down when the sim drops.

```console
$ cargo snare test --parallel smol        # async-io + blocking + smol
$ cargo snare test --parallel async-std   # async-io + async-global-executor + blocking
$ cargo snare test --parallel rayon       # adds --cfg snare_parallel_rayon
$ cargo snare test --parallel all --dry-run
```

`shims/README.md` lists each shim's change and how to patch them by hand.

The shims honor `snare::real`: each resource is tagged with the passthrough mode it was created in, and
using it in the other mode panics rather than silently mixing an emulated ring with real-OS I/O.
