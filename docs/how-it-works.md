# How snare works

## The paradigm

snare 1.x required the code under test to import snare's shim types (`snare::net::TcpStream`
instead of `std::net::TcpStream`, and so on). That only tests code you could edit to use the shims, and
it never covers what a dependency does three crates down.

snare 2 removes that constraint. It patches the **import tables** of the loaded program (ELF GOT / Mach-O
`__got` / PE IAT) so that the libc and Win32 symbols a managed thread calls — `socket`, `open`, `getenv`,
`clock_gettime`, `ioctl`, `sched_setscheduler`, … — land in snare's hooks first. A hook offers the call
to the test's in-memory model; if the model declines, the call falls through to the real OS. Nothing the
code under test imports changes. This reaches straight through `std` and every dependency.

A function's address stored in data is redirected too: C dispatch tables such as SQLite's
`aSyscall[]` (`{ "fstat", fstat }`, …) and Rust statics like
`static F: unsafe extern "C" fn(..) = libc::fstat` are filled by the loader from data
relocations (ELF `R_X86_64_64`/`R_AARCH64_ABS64`, Mach-O binds in `__const`/`__data`), and
snare rewrites those words alongside the import slots. A pointer taken in code, one read from data
and one returned by `dlsym` (or `GetProcAddress`) therefore all name the hook, and compare equal.
On Windows such a pointer is the address of the linker's import thunk, which jumps through the
patched IAT. A copy the program makes at run time before the first `Sim` is built (into the heap or
a lazily initialized static) keeps the real address.

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
  with [`snare::real`](harness.md#reaching-the-real-machine-snarereal).

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
