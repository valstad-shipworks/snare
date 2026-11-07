# Interfaces, routing and NIC drivers

## Interfaces and routing

Every `Sim` has one topology of interfaces, addresses and routes, shared by the fabric, the Winsock
fabric and a `SimHost`'s UDP sockets. It holds host facts only; what the host does with them —
error codes, strong or weak host, what happens to a link that loses carrier — is the build host's.

```rust,no_run
use snare::{IpNet, NicPolicy, NicSpec, Route, Sim};
use std::time::Duration;

let sim = Sim::builder()
    .nic(
        NicSpec::new("eth0")
            .address("10.0.0.1/24".parse::<IpNet>().unwrap())
            .station("10.0.0.2".parse::<std::net::IpAddr>().unwrap())
            .policy(NicPolicy { latency: Duration::from_micros(80), ..Default::default() }),
    )
    .route(Route::new("192.168.0.0/16".parse::<IpNet>().unwrap(), "eth0").gateway([10, 0, 0, 254]))
    .build();
sim.run(|| {
    snare::schedule_link("eth0", Duration::from_secs(2), false).unwrap(); // the cable comes out
});
```

- **Default topology.** Loopback at index 1 (`lo` / `lo0` / `Loopback Pseudo-Interface 1`, with
  `127.0.0.0/8` and `::1`, MTU 65536 / 16384 / 4294967295) and `sim0` at the next free index with
  no addresses and the default routes (`0.0.0.0/0`, `::/0`, metric 100). A `SimHost` that declares
  interfaces registers them instead (`Nic::network`, `Nic::station`, `Nic::policy`, `link_stats`
  as the counters' start). Initial carrier follows `operstate == "up"` unless `Nic::carrier`
  overrides it; `.operstate("unknown").carrier(true)` represents an unknown-but-up interface.
  The default routes leave through its lowest one
  unless `HostProfile::route` declares its own.
- **Open, then routed.** Until an interface has an address, the sim is open: binding any address
  claims it for the host (on `sim0`), so tests that bind whatever they like keep working. Once one
  does, the code under test binds only the host's addresses (127/8 always), broadcast and multicast
  addresses, and the interfaces' `stations`; anything else is `EADDRNOTAVAIL` / `WSAEADDRNOTAVAIL`.
- **Who is where.** An address is the host's, a station's (a tester endpoint or listener bound there,
  or a `NicSpec::stations` address an in-process socket binds — on the segment, across the link,
  never reached through a host wildcard bind), or nobody's.
- **Routing.** Every send and connect resolves a path: a bound device first (Linux
  `SO_BINDTODEVICE`/`SO_BINDTOIFINDEX` use the device even with no route; macOS
  `IP_BOUND_IF`/`IPV6_BOUND_IF` use scoped routes only, `ENETUNREACH` on a miss, `ENETDOWN` when it
  is down; Windows `IP_UNICAST_IF`/`IPV6_UNICAST_IF` for unicast), then `IP_MULTICAST_IF` or the
  source's interface for multicast, local delivery through loopback for the host's own addresses,
  then the longest prefix through a live interface (ties: the bound address's interface, the lowest
  metric, the earliest route). Each interface address brings its connected subnet. No route is
  `ENETUNREACH` (macOS `sendto` from a specific address: `EHOSTUNREACH`; Windows `WSAENETUNREACH`) and logs
  `Fault::Unreachable`. A loopback source leaving the host is `EINVAL` on Linux and
  `EADDRNOTAVAIL` on macOS; Windows is a strong host, so a bound address only leaves through its own
  interface (`WSAENETUNREACH`, as measured) and only receives there.
- **Sources and delivery.** An unconnected wildcard or unbound UDP socket keeps its wildcard local
  address and each datagram carries the route's source; a TCP client's local address is the
  route's source. A UDP `connect` from the wildcard (or unbound) takes the route's source address,
  v4-mapped on an IPv6 socket, and the socket then receives only there, as every host does
  (`getsockname` reports it). Connecting again keeps that address on Linux; macOS and Windows
  dissolve the association first and pick anew. Dissolving it (`connect` to an `AF_UNSPEC`
  address; on Windows also the all-zero address) follows the host: Linux returns to the wildcard
  unless `bind` named an address and gives up the port unless `bind` named one (the next send or
  connect takes a new one); macOS returns to the wildcard, keeps the port and fails with
  `EAFNOSUPPORT` (`EINVAL` for an address shorter than the family's); Windows returns to what
  `bind` named, keeps the port, and refuses an address shorter than the family's with
  `WSAEFAULT`. `tests/udp_connect_source.rs` compares this with the real host. A datagram
  reaches the exact bind, else a wildcard bind only for the host's own addresses; a directed
  broadcast reaches its subnet's stations and the host's wildcard binds; a socket bound to a device
  only receives what arrives on it. Recipients are served in (port, address) order.
- **Dual-stack IPv6.** An IPv6 socket without `IPV6_V6ONLY` bound to `::` (RFC 3493 §3.7) takes
  IPv4 datagrams and connections as one at `0.0.0.0` would, after any IPv4 socket at the IPv4
  wildcard of the port, and reports them v4-mapped (`recvfrom`, `accept`, `getpeername`,
  `getsockname`; macOS gives `0.0.0.0` as `::`, and a socket bound or connected to an IPv4 address
  its senders as `sockaddr_in`). A v4-mapped address is the IPv4 one on the wire: binding it binds
  the IPv4 address, and sending or connecting to it reaches IPv4 sockets. `IPV6_V6ONLY` reads and
  sets as each host has it: off by default on Linux (`net.ipv6.bindv6only`) and macOS, on by default
  on Windows (`SysLimits::bindv6only`), taken only before the socket is bound, with each host's size
  rules and errors; Linux turns it on when a socket binds a specific IPv6 address. The crossings a
  host refuses fail as it fails them: IPv4 from an IPv6-only socket or one bound to an IPv6 address,
  IPv6 from one bound to a v4-mapped address, and a `sockaddr_in` given an IPv6 socket (only Linux
  lets one send to it) or a `sockaddr_in6` an IPv4 one. A dual-stack socket holds its port in both
  families: TCP and UDP binds collide across them as on the host, under each host's
  `SO_REUSEADDR` and `SO_REUSEPORT` rules (see **Port sharing** below), and a dual-stack
  socket's ephemeral port is free in both. A `SimHost`'s Linux datagram sockets are dual-stack
  too. An IPv4 datagram an IPv6 socket sends
  carries the IPv4 `IP_TTL`/`IP_TOS` on Linux and its `IPV6_UNICAST_HOPS` as the TTL on macOS, and one it receives reports the control messages each
  host gives it (see [Control messages](sockets.md#control-messages)). `tests/dual_stack_os_truth.rs`
  compares all of it with the real host on Linux, macOS and Windows.
- **Multicast.** A group's datagram reaches, on its port, every socket that joined the group. On
  Linux a socket also receives the groups any socket of the host joined while `IP_MULTICAST_ALL`
  (`IPV6_MULTICAST_ALL`) is on, the default; turning it off leaves only its own joins. macOS and
  Windows deliver joined groups only. On Linux and macOS the socket must be bound to the wildcard or
  the group itself. `tests/multicast_os_truth.rs` compares this with the real host. Which interface
  a join named is not matched against the arriving one and `IP_DROP_MEMBERSHIP` is not modelled.
  Receivers that share a group's port set `SO_REUSEADDR` (Linux, Windows) or `SO_REUSEPORT`
  (macOS; `SO_REUSEADDR` too when they bind the group itself), as on the host.
- **Port sharing.** `SO_REUSEADDR`, `SO_REUSEPORT` (Linux, macOS) and Windows'
  `SO_EXCLUSIVEADDRUSE` decide which binds of one port succeed, for TCP and UDP alike, as each
  host decides: Linux lets an overlapping bind through when both sockets set `SO_REUSEADDR` (and
  the held one is not listening) or both set `SO_REUSEPORT`, and checks again at `listen`; macOS
  lets an equal address through only when both set `SO_REUSEPORT`, and a wildcard overlap when
  the new socket sets either; Windows lets anything through to a socket that set `SO_REUSEADDR`
  but one that set `SO_EXCLUSIVEADDRUSE`, and keeps a wildcard and a specific address apart. Of
  several sockets sharing an address, a unicast datagram or a connection reaches one: the one
  connected to its sender, else on Linux the most recently bound, or a member of its
  `SO_REUSEPORT` group chosen by a hash of the flow keyed with the sim's seed (each flow keeps to
  one member; the same seed replays the same spread); on macOS the most recently bound at a
  specific address and the earliest bound at the wildcard; on Windows always the earliest bound.
  Broadcast and multicast datagrams reach every one. `tests/reuseport_os_truth.rs` compares it
  with the real host on Linux, macOS and Windows; a socket at a station address stands for
  another host and shares nothing with the host's.
- **Bind to device from the test.** `set_socket_device(id, Some(nic))` (or `None`; also
  `Sim::set_socket_device`) binds an open socket as the host's option would, with that option's
  error for an unknown name (`ENODEV`, `ENXIO`, `WSAEINVAL`) and no privilege check.
- **Link state.** `set_link`, `set_nic` and `schedule_link` (a deadline on the sim's clock, so a
  thread blocked on the link wakes when it changes, under every clock and `deterministic()`). With
  carrier down, Linux and macOS keep routes: sends succeed and the frame is dropped
  (`tx_dropped`, `tx_carrier_errors`, `Fault::LinkDown`), inbound is lost, and a datagram in flight
  across a flap is discarded. Windows media sense withdraws the interface's routes and addresses.
  Admin down withdraws routes (Linux keeps the addresses bindable, as measured; macOS answers
  `ENETDOWN` to sockets bound there). TCP over a dead link stalls: writes succeed, bytes wait in
  flight and arrive in order once the link returns (or the interface is removed); a blocked read
  with nothing scheduled gives up like any quiescent wait. Raw L2 frames do not cross a dead link,
  an oversized frame is `EMSGSIZE`, and Linux `AF_PACKET` on a down interface is `ENETDOWN`.
- **`NicPolicy`.** Latency, jitter, loss and duplication on traffic crossing the interface (host to
  station, station to station), never host-local traffic, drawn from the sim's seed in a fixed order
  (loss, duplication, jitter, then the address's `UdpPolicy`); delays add and losses compound. TCP
  takes the latency and jitter per write, in order, without loss. With no policy set, draws are
  exactly as before.
- **Counters.** `nic_counters(name)` counts frames with their headers (UDP +42 / +62 bytes, TCP
  segments of at most MTU-40 bytes +54 / +74); loopback traffic counts on loopback;
  `set_nic_counters` edits them.

`add_nic`, `remove_nic`, `set_nic`, `set_link`, `schedule_link`, `set_nic_policy`,
`set_nic_counters`, `nic`, `nics`, `nic_counters`, `add_route`, `remove_route`,
`set_default_route`, `routes` and `route_lookup` work from any thread of a sim, and as `Sim`
methods from anywhere. `tests/nic_os_truth.rs` compares the error codes against the real host.

### Enumerating interfaces

Every way the code under test can list interfaces reads the same topology, so `set_link`,
`set_nic` and the counters show up everywhere at once:

- **libc (Linux, macOS).** `if_nametoindex`, `if_indextoname`, `if_nameindex`/`if_freenameindex`,
  and `getifaddrs`/`freeifaddrs`: one `AF_PACKET` (Linux, `ifa_data` a `rtnl_link_stats`) or
  `AF_LINK` (macOS, an `if_data`) entry per interface, then one `AF_INET`/`AF_INET6` entry per host
  address with netmask and broadcast, in index order (glibc lists the link entries first). Stations
  are not listed. Flags follow the link: `IFF_UP` while admin up, `IFF_RUNNING` (and Linux
  `IFF_LOWER_UP`) with carrier. Unknown names fail as the host's libc does (`ENODEV` from glibc,
  `ENXIO` on macOS; pinned by `tests/nic_enumeration.rs` against the real call).
- **ioctls on any socket.** Linux `SIOCGIFINDEX`, `SIOCGIFMTU`, `SIOCGIFFLAGS`, `SIOCGIFHWADDR`;
  macOS `SIOCGIFFLAGS`, `SIOCGIFMTU`. An interface without a configured MAC has `02:00:<index>`.
- **`SimHost`.** `/sys/class/net/<if>/{mtu,ifindex,operstate,carrier,flags,address,statistics/*}`
  (reading `carrier` of an admin-down interface is `EINVAL`, as `carrier_show`), rtnetlink
  `RTM_GETLINK` (flags, `IFLA_OPERSTATE`, `IFLA_CARRIER`, `IFLA_MTU`, `IFLA_ADDRESS`,
  `IFLA_STATS64`), `RTM_GETADDR` and `RTM_GETROUTE` dumps, and macOS `sysctl` `NET_RT_IFLIST2` all
  render the topology, loopback included. `ethtool`, hardware timestamping, queues, IRQs and PTP
  stay the host profile's (see [NIC drivers](#nic-drivers-ethtool-qdiscs-threaded-napi)).
- **Windows IP Helper.** `if_nametoindex`/`if_indextoname` (NDIS names such as `ethernet_32772`,
  `loopback_0`), the `ConvertInterface*` alias/name/LUID/index conversions, `GetIfEntry2`,
  `GetIfTable2`, `GetUnicastIpAddressTable`, `FreeMibTable`, `GetAdaptersAddresses` (with the
  `ERROR_BUFFER_OVERFLOW` size handshake) and `GetBestRoute2`, rendered through the `windows-sys`
  types. `OperStatus`/`MediaConnectState` follow the link, octet and packet counters follow
  traffic, and addresses are listed only with carrier (media sense). Tables the sim hands out are
  freed by `FreeMibTable`; any other pointer goes to the real one.

### NIC drivers: `ethtool`, qdiscs, threaded NAPI

On Linux a `SimHost` interface has a driver, declared on its `Nic` the way old snare's `NicCaps`
and `DriverSeed` did, and `SIOCETHTOOL` runs against it as net/ethtool/ioctl.c `__dev_ethtool`
does (Linux 6.12): a command outside the kernel's read-only list needs `CAP_NET_ADMIN` (`EPERM`,
checked first), an operation the driver lacks is `EOPNOTSUPP`, and the core's own checks run
before the driver's. What the code under test sets persists; `SimHost::ethtool(nic)` returns it
all as a `NicEthtool`.

| Command | `Nic` builder | Rules |
|---|---|---|
| `GDRVINFO` | `driver`, `bus_info`, `firmware`, `expansion_rom`, `register_dump_len`, `eeprom_len`, `private_flags_count`, `self_test_count` | dump lengths, private-flag and self-test counts default to zero; `n_stats` from driver statistics |
| `GLINK` | — | admin up with carrier, from the topology |
| `[GS]RINGPARAM` | `rings(Rings { .. })` | each size within its maximum (`EINVAL`); the `*_max` given are ignored |
| `[GS]COALESCE` | `coalesce(CoalesceParams, Coalesce)`, `coalesce_limits` | a non-zero field outside `supported_coalesce_params` is `EOPNOTSUPP`; above the driver's limits `EINVAL` |
| `[GS]CHANNELS` | `channels(Channels { .. })` | no change succeeds at once; counts within maxima, at least one RX and TX queue, not below a queue a flow rule uses (`EINVAL`); the queue count (`/sys/class/net/<if>/queues`) follows |
| `[GS]PAUSEPARAM`, `[GS]EEE` | `pause`, `eee` | an EEE mode outside `supported` is `EINVAL` |
| `[GS]FLAGS` | `ntuple(slots)` makes `ETH_FLAG_NTUPLE` settable | unknown flags `EINVAL`; a change outside `hw_features` `EOPNOTSUPP` |
| `GRXCLSRLCNT`/`GRXCLSRULE`/`GRXCLSRLALL`/`SRXCLSRLINS`/`SRXCLSRLDEL` | `ntuple(slots)` | as igb: a slot past the table, a missing queue or an empty slot `EINVAL`, a short `rule_locs` `EMSGSIZE` |
| `GSSET_INFO`/`GSTRINGS`/`GSTATS` | `driver_stats([(name, value)])`, `SimHost::set_driver_stat` | none declared: `EOPNOTSUPP`, as a driver without statistics |

rtnetlink `RTM_NEWQDISC`/`RTM_DELQDISC` change the qdiscs `RTM_GETQDISC` dumps (every interface, in
index order). Multiqueue goes by the transmit queues the driver allocated (`num_tx_queues`:
`Nic::tx_queues_allocated`, else the channel maxima), not those in use (`real_num_tx_queues`, the
`queues/` listing): a multi-queue interface starts with `mq` over one default qdisc per allocated
queue (`pfifo_fast` past the queues in use) and the dump lists the queues in use and any qdisc
created with a handle, as net/sched/sch_mq.c `mq_attach` hashes them; a single-queue one starts with
the default qdisc, and an `IFF_NO_QUEUE` one (`Nic::no_queue`, veth) with `noqueue`. Replacing the
root or an `mq` class's qdisc follows net/sched/sch_api.c `tc_modify_qdisc`
(`NLM_F_CREATE`/`NLM_F_REPLACE`/`NLM_F_EXCL`, automatic handles from `8001:`), `mq` needs more than
one allocated queue (`EOPNOTSUPP`), and `etf` checks its parameters as `etf_init` does
(`CLOCK_TAI` only, a dynamic clock `ENOTSUPP` (524)); `TC_ETF_OFFLOAD_ON` needs `Nic::etf_offload(queues)`
(`EOPNOTSUPP` without, `EINVAL` on another queue, as igb on an I210). Changes need `CAP_NET_ADMIN` and
are acked with `NLMSG_ERROR` when `NLM_F_ACK` asks. `/sys/class/net/<if>/threaded` reads and, for
root, writes the threaded-NAPI switch (`Nic::threaded_napi`): `EPERM` without `CAP_NET_ADMIN`,
`EOPNOTSUPP` for a value other than 0 or 1, and starts or stops the interface's `napi/<if>-<id>`
threads. The interface's interrupt lines, NAPI instances, per-queue tuning files and what a queue
count change does to them are in [Kernel threads, interrupts and
NAPI](host.md#kernel-threads-interrupts-and-napi). `EasyBuilder` presets ship an I210-like driver
with all of the above. Tests: `tests/simhost_ethtool.rs`.

### Windows adapter properties and restarts

Windows tunes an adapter through its device node, not an ioctl: a program enumerates the network
class with `SetupDiGetClassDevsW`/`SetupDiEnumDeviceInfo`, opens the driver key with
`SetupDiOpenDevRegKey(DIREG_DRV)`, matches its `NetCfgInstanceId` to the interface GUID IP Helper
reports, writes standardized keywords (`*ReceiveBuffers`, `*InterruptModeration`, `*FlowControl`,
`*NumRssQueues`, `*RSS`, `*SoftwareTimestamp`, EEE names) as `REG_SZ` values, reads their limits
from `Ndi\Params\<keyword>\max`, and restarts the device with `CM_Disable_DevNode` +
`CM_Enable_DevNode` (fast-talker's `nic/windows.rs` does exactly this). Every one of those calls is
in-process, so the Windows `Sim` serves them: each non-loopback interface is a device node whose
two keys (`DIREG_DRV`, and `DIREG_DEV`'s `Device Parameters`, where the interrupt affinity policy
lives) are an in-memory registry that keeps what the code under test writes.

- **Describe it.** `SimBuilder::adapter(nic, Adapter::new().property("*ReceiveBuffers", "512",
  Some(4096)).without_property("*RSS").driver_version("..").restart_flap(d))`, or
  `Sim::set_adapter` later. The default `Adapter::new()` mirrors snare 1.x's `NicCaps`: rings 256
  of 4096, interrupt moderation on, flow control Rx & Tx, 4 of 8 RSS queues, RSS on, software
  timestamping off, no EEE keyword, 2 s flap.
- **Read it back.** `Sim::adapter_property(nic, keyword)`, `Sim::adapter_value(nic,
  AdapterKey::{Driver, Device}, path, name) -> Option<RegValue>`, `Sim::adapter_restarts(nic)`.
- **Restart flap.** `CM_Disable_DevNode` drops the interface's carrier; `CM_Enable_DevNode`
  schedules it back up `restart_flap` later on the sim's clock (`schedule_link`), so
  `GetIfEntry2`'s `OperStatus`, media sense and the sockets all see the outage, under the virtual
  clock and `deterministic()`. An interface that had no carrier stays down.
- **Elevation** is `Privileges::root`. A standard user may read the keys but gets
  `ERROR_ACCESS_DENIED` opening one for writing or creating a subkey, and `CR_ACCESS_DENIED` from
  the `CM_*` calls. A write through a handle opened `KEY_READ` is `ERROR_ACCESS_DENIED` for anyone.
- **Codes.** Missing value or key `ERROR_FILE_NOT_FOUND`, short buffer `ERROR_MORE_DATA` with the
  size, a buffer without a length `ERROR_INVALID_PARAMETER`, enumerating past the end
  `ERROR_NO_MORE_ITEMS`, a wrong `cbSize` `ERROR_INVALID_USER_BUFFER`, a bad key type
  `ERROR_INVALID_FLAGS`; `tests/nic_adapter_props_win.rs` (`registry_codes_os_truth`,
  `setupapi_codes_os_truth`) compares them with the real registry and SetupAPI.
- **Passthrough.** Only the sets, keys and device instances the sim minted (and the network-class
  enumeration that mints them) are simulated; every other registry key, device class or `DEVINST`
  goes to the real API. A sim handle passed to a SetupAPI call that is not hooked reaches the real
  one. `CreateFileW(\\.\{GUID})` for NDIS statistics is not modelled (it fails, as for a virtual
  adapter), so driver counters come from `GetIfEntry2` alone.

The `WinHost` also keeps the process's working set: `SetProcessWorkingSetSizeEx` /
`GetProcessWorkingSetSizeEx` (fast-talker's `reserve_working_set`) never touch the real process.
Measured on Windows 11: a new process has 204 800 / 1 413 120 bytes with both limits soft; bounds
round down to 4 KiB and the minimum is raised to 20 pages; min above max, or `ENABLE` and
`DISABLE` of one limit together, is `ERROR_INVALID_PARAMETER`; a minimum beyond the machine is
`ERROR_NO_SYSTEM_RESOURCES` (the sim has 16 GiB and refuses above 7/8 of it); flags 0 keep the
limits' state; both bounds `(SIZE_T)-1` trims and succeeds. Raising either bound needs
`SeIncreaseWorkingSetPrivilege`, whose stand-in is `ipc_lock` (`ERROR_PRIVILEGE_NOT_HELD`
without it). `Sim::working_set()` reads it back; `working_set_os_truth` compares with the real OS.

### CPU count on Windows

A Windows sim's machine has `SimBuilder::cpus` logical processors (default 8) in one processor
group, one package and NUMA node 0, grouped into cores of `threads_per_core`. The code under test
counts them: `GetSystemInfo`/`GetNativeSystemInfo` (`dwNumberOfProcessors`,
`dwActiveProcessorMask`; the other fields are the machine's), `GetActiveProcessorCount` and
`GetMaximumProcessorCount` (group 0 or `ALL_PROCESSOR_GROUPS`; any other group is
`ERROR_INVALID_PARAMETER`), `GetActiveProcessorGroupCount`/`GetMaximumProcessorGroupCount`,
`GetLogicalProcessorInformation(Ex)` for every relationship, `GetProcessAffinityMask`/
`SetProcessAffinityMask`, `GetNumaHighestNodeNumber`, `GetNumaNodeProcessorMask(Ex/2)` and
`CallNtPowerInformation(ProcessorInformation)`. So `std::thread::available_parallelism`,
`num_cpus::get` and `get_physical`, and sysinfo's CPU list and physical core count are the
profile's, and tokio's and rayon's default worker counts follow it. The default stays 8 rather
than the machine's count so that masks, CPU set ids and worker counts are the same on every
machine; pass `.cpus(std::thread::available_parallelism()?.get())` for the machine's.

The topology records copy the machine's caches: those of the core running logical processor 0
are repeated for each simulated core, and those it shares with other cores stand once for the
package; each core is also one module, and `GetSystemCpuSetInformation`'s `LastLevelCacheIndex`
follows the last-level cache. `CallNtPowerInformation` repeats the machine's per-processor
records, renumbered. Layouts, record order, the last errors (the count functions leave
`ERROR_INSUFFICIENT_BUFFER` even when they succeed) and the short-buffer conventions —
`ERROR_INSUFFICIENT_BUFFER` with the length needed, whole records written by
`GetLogicalProcessorInformation` but none by its `Ex` form, `ERROR_NOACCESS` for a null buffer
with a length, `ERROR_GEN_FAILURE` for an unknown relationship — were measured on Windows 11 and
are compared with the machine by `win_cpus_os_truth`. `SetProcessAffinityMask` takes a nonzero
subset of the processors and moves every thread onto it; `SetThreadAffinityMask` is held to it.
