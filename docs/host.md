# The simulated host

## Configuring the host: `SimHost`, `HostProfile`, `EasyBuilder`

For code that tunes the host (real-time schedulers, NIC configurators like `fast-talker`), attach a
`SimHost` describing the machine. The OS *personality* is fixed by `cfg!(target_os)` at compile time; what
you configure here are host *facts*.

```rust
use snare::{HostProfile, Nic, LinkStats, Sim, CAP_SYS_NICE};
use std::net::Ipv4Addr;

let host = HostProfile::new()
    .cpus(8)
    .isolated(2..8)                       // /sys/devices/system/cpu/isolated
    .governor("performance")
    .preempt_rt(true)                     // /sys/kernel/realtime
    .cap(CAP_SYS_NICE)                    // grant a capability; setters EPERM without it
    .nic(Nic::new("eth0", 2)
        .mac([0x50, 0x7c, 0x6f, 0x93, 0xa6, 0x55])   // getifaddrs AF_PACKET, SIOCGIFHWADDR
        .mtu(9000)
        .driver("igb", "5.6.0")
        .hardware_timestamping(true)
        .address(Ipv4Addr::new(10, 0, 0, 10))
        .queues(4, 4)
        .link_stats(LinkStats { rx_packets: 1000, ..Default::default() }))
    .env("RUNTIME_ENV", "sim")            // isolates + sets the environment
    .kernel_release("6.6.30-rt30")        // uname -r; also sysname, nodename, kernel_version, machine
    .build();

Sim::builder().host(host).build().run(|| {
    // sched_setscheduler(SCHED_FIFO), ethtool, /sys reads, SO_TIMESTAMPING, getenv — all served here.
});
```

The profile's CPUs are what the code under test counts: `sysconf(_SC_NPROCESSORS_CONF)` is
`cpus`, `_SC_NPROCESSORS_ONLN` the `online` ones, Linux `sched_getaffinity` the online set, and
macOS's `hw.ncpu`, `hw.activecpu`, `hw.logicalcpu`, `hw.physicalcpu` (and their `_max` forms) and,
on arm64, one performance level `hw.perflevel0.*` follow it. So `num_cpus` and
`std::thread::available_parallelism` report it on both. The per-CPU listings follow it too: Linux
`/proc/stat` and `/proc/cpuinfo` list the online CPUs (each `cpuinfo` entry is the machine's
first processor's, renumbered), and macOS `host_processor_info` returns one record per CPU, so
sysinfo's CPU list is the profile's. The host runs no load: every online CPU counts idle time for
the whole of the sim clock's uptime. A Windows sim counts its own processors too; see
[CPU count on Windows](interfaces.md#cpu-count-on-windows).

`uname` reports a host named `snare` running a fixed kernel (Linux `6.12.0`, `#1 SMP PREEMPT_DYNAMIC`,
or `#1 SMP PREEMPT_RT` with `preempt_rt(true)`; macOS `Darwin` `25.0.0`) on the build target's machine
type. `HostProfile::real_uname()` copies all five fields from the machine running the test instead,
and works inside a sim. `gethostname` returns the profile's `nodename`, truncating a short buffer as
each libc does (glibc's `ENAMETOOLONG`, macOS's NUL-ended prefix), and so do Linux
`/proc/sys/kernel/hostname` and macOS `kern.hostname`. `sethostname` renames the sim's host when
the macOS sim runs as root; on Linux it needs `CAP_SYS_ADMIN`, which `Privileges` does not model, so
it fails with `EPERM` as it does for an unprivileged process.

`EasyBuilder` gives batteries-included presets when you just want a working machine:

```rust
use snare::{EasyBuilder, Sim};

let host = EasyBuilder::realtime().build();   // 8-CPU PREEMPT_RT, all caps, a hw-timestamping NIC
// also: EasyBuilder::server() / laptop() / unprivileged() / minimal(), each tweakable:
let host = EasyBuilder::laptop().cpus(2).privileged(false).build();

Sim::builder().host(host).build().run(|| { /* ... */ });
```

## Kernel command line and sysctls

`/proc/cmdline` is `HostProfile::kernel_cmdline`, or without one a boot image and root device
followed by `isolcpus=` and `nohz_full=` for the profile's `isolated` and `nohz_full` CPUs.
`HostProfile::sysctl(key, value)` adds a sysctl under `/proc/sys` by its dotted key;
`kernel.sched_rt_runtime_us` (950000), `kernel.sched_rt_period_us` (1000000) and
`kernel.timer_migration` (1) are served at the kernel's defaults without one. Root may write them:
a numeric sysctl takes an integer, `sched_rt_runtime_us` -1 or at most the period, and
`timer_migration` 0 or 1, each `EINVAL` otherwise. A sysctl outside the table and the modelled
network ones is the real machine's. Tests: `tests/host_cmdline_sysctl.rs`.

## Kernel threads, interrupts and NAPI

On Linux a `SimHost` boots a kernel of its own before the code under test runs, so code that tunes
the kernel's threads and interrupts (`chrt`/`taskset` done by hand, fast-talker's `irq` and `nic`
modules) finds them and is held to the kernel's rules. Nothing reaches the real machine's threads
or `/proc/irq`.

**Kernel threads.** They are processes of the simulated host, each with a pid below the simulated
tids, listed in `/proc` with its full name in `/proc/<pid>/comm`, and scheduled through the same
`sched_*` model as the code under test's threads (`CAP_SYS_NICE` gates a real-time policy):

| Thread | Exists | Starts at | Affinity |
|---|---|---|---|
| `ksoftirqd/N` | every kernel, per online CPU | `SCHED_OTHER` | bound to CPU N |
| `ktimers/N`, `rcuc/N`, `irq_work/N` | `preempt_rt(true)`, per online CPU | `SCHED_FIFO` 1 | bound to CPU N |
| `irq/<n>-<name>` | `preempt_rt(true)`, per interrupt line (forced threading) | `SCHED_FIFO` 50 | the line's effective CPU, following it when the line moves |
| `napi/<if>-<id>` | per NAPI instance while `/sys/class/net/<if>/threaded` is 1 | `SCHED_OTHER` | every online CPU |

A bound thread refuses `sched_setaffinity` with `EINVAL` (`PF_NO_SETAFFINITY`). Kernel threads are
not the caller's tasks: `/proc/self/task` lists only the code under test's threads.

**Interrupt lines.** `/proc/irq/<n>/{smp_affinity,smp_affinity_list,effective_affinity,
effective_affinity_list,node}`, `/proc/irq/default_smp_affinity`, `/sys/kernel/irq/<n>/actions`
and `/proc/interrupts` (every count 0) list:

- each NIC's MSI vectors (`Nic::msi_irqs`), as igb requests them: the first, for link and other
  causes, named after the interface, then one `<if>-TxRx-<n>` per queue vector in use (the combined
  channels, else one per remaining vector); a lone vector is named after the interface;
- `HostProfile::irq(n, name)`, a line that moves like any other;
- `HostProfile::managed_irq(n, name, cpus)`, a kernel-managed queue vector (NVMe's) spread onto
  `cpus`.

Writes follow kernel/irq/proc.c: only root may open them for writing (`EACCES`); a managed line
refuses with `EIO`; a cpulist (`a-b`, `a-b:used/group`) or hex mask the kernel's parsers reject is
`EINVAL`, or `ERANGE`/`EOVERFLOW` past the CPU count; a line told only offline CPUs goes back to the
default affinity and the write succeeds; a default naming no online CPU is `EINVAL`. The effective
affinity is the first online CPU of a line's affinity, and for a managed line the first CPU not
`isolated`, falling back to the first.

**NAPI.** Each queue vector registers a NAPI instance with an id from 8193 (`MIN_NAPI_ID` with
`NR_CPUS` 8192). The `netdev` generic-netlink family's `NETDEV_CMD_NAPI_GET` dumps them, all or one
interface's (`NETDEV_A_NAPI_IFINDEX`): ifindex, id, interrupt, and the thread's pid while NAPI runs
in threads.

**Queue tuning.** Under `/sys/class/net/<if>/`: `napi_defer_hard_irqs` and `gro_flush_timeout`
(`CAP_NET_ADMIN`, `kstrtoul` text, a deferral above `S32_MAX` is `ERANGE`),
`queues/rx-<n>/rps_cpus` (`CAP_NET_ADMIN`, a hex mask with isolated CPUs dropped, `EINVAL` if that
empties it), `queues/tx-<n>/xps_cpus` (`CAP_NET_ADMIN`, a hex mask) and
`queues/tx-<n>/byte_queue_limits/limit_max` (at most `DQL_MAX_LIMIT`, 1879048192, which is also
where it starts), for each queue in use.

**Queue count changes.** An `ETHTOOL_SCHANNELS` that changes the count rebuilds the interface's
interrupt scheme as igb `igb_reinit_queues` does: every vector is requested anew on the default
affinity with a new handler thread, and every NAPI instance is registered again with a new id and,
when threaded, a new `SCHED_OTHER` thread. Whatever placed the old ones has to place them again.

Tests: `tests/host_kernel_threads.rs`, `tests/host_proc_irq.rs`, `tests/host_proc_tasks.rs`.
