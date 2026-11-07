# Files

## Files: `VirtualFs`

```rust
use snare::{FsBuilder, Sim};

let fs = FsBuilder::new()
    .file("/etc/app.conf", "mode = fast\n")
    .dir("/var/run")
    .passthrough("/usr/share/**")   // globs that reach the real filesystem
    .deny("/secret/**")             // globs that always fail
    .build();

Sim::builder().fs(fs).build().run(|| {
    assert_eq!(std::fs::read_to_string("/etc/app.conf").unwrap(), "mode = fast\n");
});
```

Separate opens of a file share live contents; duplicated descriptors also share offsets and status
flags. Writes and truncation are visible immediately. Absolute `mkdir`, `unlink` and `rename`
operate on the virtual tree, preserve inode identity across moves, and keep unlinked files usable
through open descriptors. Creation requires a declared directory parent, and pathname traversal
checks intermediate components before resolving `.` and `..`.

Nodes carry permission bits, an owner and a group: `FsBuilder::mode` and `FsBuilder::owner` set a
declared node's, which otherwise is `0644` (a file) or `0755` (a directory) and belongs to the user
the code under test runs as. That user is the sim's: what `geteuid` and `getegid` report in it (a
`SimHost`'s root or stock user, otherwise the real process's ids and groups), with
`Privileges::root` granting what root may do. Opening, creating, removing, renaming, listing and
searching, `access`/`faccessat`, `chdir`/`fchdir`, the `utimensat` family,
`chmod`/`fchmod`/`fchmodat`/`lchmod` and `chown`/`fchown`/`lchown`/`fchownat` check them as the host
does, with the sticky bit, set-group-ID directories, and the set-user-ID and set-group-ID bits a
write or a `chown` clears; where Linux and macOS differ (`chown` rules, the group and mode bits a new
node gets, a symlink's own mode) each side takes its host's (`fs_permissions` compares the two as
root and as an ordinary user). Each sim keeps its own `umask`, 022 to start with, which masks the
mode of what it creates; setting it changes neither the process's nor another sim's.

An open file belongs to the process, as a descriptor does in a real one: a file opened in one sim
and kept past its run (a log file behind a global `tracing` subscriber) is the same open file when
another sim's thread, or a thread outside every sim, writes to it, and the bytes land in the file
system that opened it. Paths stay per sim. Once that sim is gone, calls through the descriptor fail
with `EBADF`, and its number stays reserved until the holder closes it, so it never reaches a file
the OS opened in the meantime. With a `SimHost` as well, the host serves the paths it models
(`/sys`, `/proc`, `/dev`) first, the `VirtualFs` the rest.

Virtual files take advisory locks: `fcntl` record locks (`F_GETLK`, `F_SETLK`, `F_SETLKW` and the
`F_OFD_*` forms on Linux and macOS, and macOS `F_SETLKWTIMEOUT`/`F_OFD_SETLKWTIMEOUT`) and
`flock`. Every thread is in the one process, so process record locks never conflict with each
other and go when any descriptor of the file closes, as POSIX has it; open-file-description and
`flock` locks conflict between separate opens and go with the description's last descriptor. As on
the host, `flock` locks are independent of record locks on Linux and share one lock list with them
on macOS, where they conflict even with the same description's OFD locks. A blocked `F_SETLKW`,
`F_OFD_SETLKW` or `flock` waits like any other blocked call in the sim, so it lets virtual time
move and keeps a deterministic schedule, and a timed wait gives up on the sim's clock. A
`SimHost`'s `/proc`, `/sys` and `/dev` files take the same locks, one inode per path, as Linux
locks those files like any other.

`mmap` maps a virtual file with the host's semantics: its first mapping moves the file's bytes into
a real shared memory object the harness owns (a `memfd` on Linux, an unlinked temporary file on
macOS), which every later mapping and the file's own reads, writes and truncation then use, so
shared mappings stay coherent with each other and with I/O, a private mapping copies on write,
touching a page past the end raises `SIGBUS`, and `mmap`/`mprotect` fail with the host's errnos.
SQLite's default VFS locks a database on a `VirtualFs` as it would on disk, and runs in WAL mode
with its wal-index mapped. Each `VirtualFs` reports a device number of its own in `st_dev`, so
files of two sims never share the (`st_dev`, `st_ino`) identity SQLite keys its locks by.
See [OPEN_BUGS.md](../OPEN_BUGS.md) for the file-plane boundaries.

### File timestamps

File times follow the sim's `CLOCK_REALTIME`, so code that compares a file's age with
`SystemTime::now()` (age-based log rotation, config reloads, pruning by creation time) sees a
consistent world:

- **`VirtualFs`**: every node keeps access, modification, change and birth times in nanoseconds.
  Declared nodes start at the instant the sim is built (`FsBuilder::times` with `NodeTimes`
  overrides any of them). Creation stamps all four and the parent's modification and change
  times; `write`, `pwrite`, `ftruncate` and `O_TRUNC` stamp modification and change; `link`,
  `unlink` and `rename` stamp the inode's change time and the parents'; `chmod` and `chown` and
  their relatives stamp the change time (on macOS a `chown` naming no id leaves it); reads and directory
  listings stamp the access time under Linux's `relatime` rule (only when it is not after the
  modification or change time, or is a day old). `utimensat`, `futimens`, `utimes`, `futimes` and
  macOS `setattrlist`/`fsetattrlist` (std's `File::set_times`, including macOS `set_created`) set
  what they name. `stat`, `fstat`, `fstatat` and macOS `st_birthtime`, and Linux `statx`
  (`STATX_ATIME`/`MTIME`/`CTIME`/`BTIME`), report them. Where Linux and macOS differ, the model
  takes the host's side: a read at end of file marks the access only on Linux; setting only the
  access time marks the change time only on Linux; on macOS a modification time set before the
  birth time moves the birth time back (`fs_times` compares each step with the host).
- **Real files in a sim on a virtual clock**: what the sim creates or changes on the real file
  system is recorded per (device, inode) at the sim's time, by the same rules (writes through
  descriptors the sim opened for writing, `O_CREAT`/`O_TRUNC`, `mkdir`, `symlink`, `link`,
  `unlink`, `rename`, the `utimensat`, `chmod` and `chown` families), and `stat` reports it; the real file keeps real
  times. A change the sim cannot see (another process's write, a write through a descriptor opened
  before the sim) shows at the sim's time of the first `stat` that notices it. A real file the sim
  never touched shows its host times shifted by one constant, the host clock minus the sim's when
  the sim was built: it keeps its age relative to the sim's start and its order among real files,
  instead of sitting years after a 2023 sim clock. A sim on the real clock (`wall_clock`) reports
  host times unchanged. A real file a sim opened for writing goes back to the OS when the sim
  drops, so a log file kept past the run stays writable.
- **`SimHost` files** under `/proc`, `/sys` and `/dev` carry the sim's boot instant; like procfs
  and sysfs, the `/proc` and `/sys` ones report no birth time.

### tracefs

A `HostProfile` with `.tracefs(Some(Tracefs::full()))` (the `realtime` and `server` presets have
it) serves `/sys/kernel/tracing` as a Linux kernel with hist triggers, synthetic events and the
`osnoise` and `timerlat` tracers does, on every platform the sim runs on. It is for code that
drives the real thing: the numbers it reports are made up, the rules are the kernel's, so a
program that writes a trigger the kernel would refuse, removes a synthetic event a trigger still
uses, truncates a `trigger` file by opening it with `O_TRUNC`, forgets a trigger before `rmdir`,
or stops the timerlat tracer while a thread still waits in `timerlat_fd` gets the errno the
kernel gives, or, for the last, a [`TracefsFault`] in the recorded events instead of the
`SIGKILL` the kernel sends.

```rust,ignore
let host = EasyBuilder::realtime().profile().root(true).build();
let tracefs = host.tracefs().unwrap();
Sim::builder().host(host).build().run(|| {
    // The code under test makes an instance, registers triggers, opens timerlat_fd ...
    tracefs.inject("irq/irq_handler_exit", &[("cpu", "1"), ("irq", "133"), ("irqlat", "4096")]);
    tracefs.set_timerlat(3, 1_500, 9_000, 12_000);
    // ... and reads its hist files and trace pipes.
});
assert!(tracefs.faults().is_empty());
```

What it has: `instances/<name>` by `mkdir`/`rmdir` (`EBUSY` while triggers or an open `trace_pipe`
remain); the per-instance `current_tracer`, `tracing_on`, `trace_clock`, `tracing_cpumask`,
`buffer_size_kb`, `trace`, `snapshot`, `set_event` and `events/`; the `irq`, `sched` and `timer`
tracepoints with their fields, `events/<sys>/<event>/{enable,filter,trigger,hist,format,id}`;
`synthetic_events`; `osnoise/` (global, as in the kernel: `options`, `cpus`, the periods and
thresholds, `per_cpu/cpuN/timerlat_fd`); and `trace_pipe` and `per_cpu/cpuN/trace_pipe` as pipes
the sim made, so `poll` on them waits on the sim's clock. `hist:` commands are checked as
`trace_events_hist.c` checks them: fields and modifiers, variables and `$var` references
(including the one-definition-per-instance rule), `onmatch(...).trace(...)` parameter counts and
types against the synthetic event, `onmax($v).snapshot()`/`.save()`, the `if` filter. A refused
write is `EINVAL` with the reason in `error_log`.

What a test drives: [`TracefsSim::inject`] records one tracepoint hit on every instance, into the
ring buffer and pipes of those that enable it and through every hist trigger on it, whose
`onmatch` actions record the synthetic event in turn, so a hist file reads back as the kernel
would print it; an `onmax` past its maximum snapshots the ring. [`TracefsSim::set_timerlat`] and
[`TracefsSim::set_osnoise`] set what the tracers report. A thread reading `timerlat_fd` (pinned
to that CPU, once the tracer runs with `NO_OSNOISE_WORKLOAD`, as the kernel requires) sleeps one
period on the sim's clock per `read` and that period's samples land on the instance's pipes; the
osnoise tracer and timerlat with the kernel workload write one sample per period of virtual
time, caught up whenever a pipe is read. `stop_tracing_total_us` and `print_stack` stop the
instance and dump a stack as the tracer does. [`TracefsSim`] also lists the instances, triggers,
synthetic events and readers for assertions on what the code under test left behind.

Not modelled: tracers other than `nop`, `function`, `osnoise` and `timerlat`; events outside the
three systems; kprobes, uprobes and `dynamic_events`; `trace_marker`; `set_ftrace_*`; the
`hist` value and sort details beyond `hitcount`.
