# Platforms and development

## Platform support

| | Linux (x86_64, aarch64) | macOS (aarch64, x86_64) | Windows (x86_64, aarch64) |
|---|---|---|---|
| Interposition | ELF GOT + data relocations | Mach-O `__got` + data binds (+ variadic trampoline on arm64) | PE IAT |
| Time / entropy / sleep | ✅ | ✅ | ✅ |
| TCP | ✅ | ✅ | ✅ (Winsock) |
| UDP | ✅ | ✅ | ✅ (Winsock) |
| Readiness | ✅ (`epoll`, `poll`, `eventfd`) | ✅ (`kqueue`/`kevent`, `poll`) | ✅ (`WSAPoll`, `select`, IOCP for Mio) |
| Raw L2 | `AF_PACKET` | `/dev/bpf` | pcap/npcap (structural) |
| Host scheduling | ✅ | ✅ (pthread/Mach) | ✅ (`WinHost`) |
| Interfaces and routing | ✅ (`getifaddrs`, `SIOCGIF*`, netlink) | ✅ (`getifaddrs`, `SIOCGIF*`, `sysctl`) | ✅ (IP Helper) |
| NIC tuning / PTP | ✅ (`ethtool`, qdiscs, sysfs) | partial (`sysctl`) | adapter properties + restart (SetupAPI/registry/`CM_*`) |
| Process limits | ✅ (`RLIMIT_RTPRIO`/`NICE`/`MEMLOCK`, `mlock`) | ✅ (`RLIMIT_MEMLOCK`, `mlock`) | priority class, working set (`WinHost`) |
| Names / signals | ✅ | ✅ | ✅ (`GetAddrInfoW`, console control events) |
| Environment (opt-in) | lookups and changes; enumeration reads the real `environ` | ✅ (enumeration through `_NSGetEnviron`) | ✅ (Win32 and UCRT calls, children) |

Linux means glibc (`target_env = "gnu"`). Every other target — musl, 32-bit x86 and ARM, Android,
the BSDs, illumos, Redox — stops at a single `compile_error!` naming the supported targets. A crate
that also builds for those targets needs no gate beyond `cfg(snare)`: only `cargo snare test` sets
it, on the machine running the tests, so a build for any other target never pulls snare in.

```toml
[target.'cfg(snare)'.dev-dependencies]
snare = "^3"
```

The minimum supported Rust version is 1.88.

## Repository layout

```
crates/snare-interpose/   the engine: patchers, hooks, Domain, backend traits, real()
crates/snare/             Sim, SimHost, HostProfile, EasyBuilder, Fabric, VirtualFs, testers
crates/cargo-snare/       the `cargo snare` subcommand
probes/interpose-probe/   test-fixture DLL for the Windows module-loading test (unpublished)
shims/                    drop-in [patch.crates-io] crates: io-uring, xsk-rs, sc, syscalls, quanta, minstant,
                          fastant, fastrand, rayon-core; with --parallel: async-io, async-global-executor,
                          blocking, smol, futures-timer
scripts/                  Windows VM and hardware test runners, socket-buffer and runtime measurements
```

## Running the tests

`.cargo/config.toml` builds this workspace with `--cfg snare`; a `RUSTFLAGS` set in the environment
replaces it, so include `--cfg snare` there too.

```console
cargo test                                  # macOS / Linux
cargo clippy --all-targets
cargo xwin build --cross-compiler clang --workspace --target x86_64-pc-windows-msvc   # Windows (cargo-xwin)
```

Linux-only surfaces are exercised in a container (`docker run --rm -v "$PWD":/work -w /work rust:latest
cargo test`). `scripts/test-windows.sh` cross-builds the workspace and runs its Windows tests in a
Parallels VM; `scripts/test-windows-host.sh` runs only the scheduling-plane target.

The Windows module-loading test needs the `interpose-probe` DLL in the target's profile directory,
beside `deps`. The full Windows runner builds the workspace first to produce it; `cargo test
--no-run` alone does not. On a native Windows checkout, run `cargo build -p interpose-probe` before
`cargo test --workspace --all-targets`, using the same target and profile for both commands.

## A note on the source

Behaviour that mirrors a kernel interface is cited in the code to its authority — a man-page section
(`man 2 sched_setscheduler`), a kernel header (`<linux/if_link.h> struct rtnl_link_stats64`), or a
`Documentation/` path (`Documentation/networking/timestamping.rst`) — so the modeled struct layouts,
magic numbers, and errno conventions can be checked against the real thing.
