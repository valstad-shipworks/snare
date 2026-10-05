//! Socket buffer limits and process privileges: what the host OS lets a socket buffer and who may
//! do what. One [`Privileges`] and one [`SysLimits`] per sim gate every privileged socket call and
//! size every receive queue, with or without a `SimHost`.
//!
//! The two live in [`SysConfig`] behind their own mutexes, each taken only inside
//! [`snare_interpose::real`] and never while the other is held, so reading them from a socket
//! call that already holds a socket's state lock cannot deadlock. A datagram socket's receive
//! accounting ([`SockBuf`], [`RxAccount`]) lives in its [`SockRec`]'s state and changes under
//! that lock; [`RxQueue`] belongs to the backend and calls into the record, so it must not be
//! used with the record's state lock held.

use std::collections::VecDeque;
use std::ffi::c_int;
use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;

use crate::readiness::Deadline;
use crate::scope;
use crate::sockets::{SockRec, SocketKind};

// Capability numbers from include/uapi/linux/capability.h.
pub(crate) const CAP_NET_BIND_SERVICE: c_int = 10;
pub(crate) const CAP_NET_ADMIN: c_int = 12;
pub(crate) const CAP_NET_RAW: c_int = 13;
pub(crate) const CAP_IPC_LOCK: c_int = 14;
pub(crate) const CAP_SYS_NICE: c_int = 23;
pub(crate) const CAP_SYS_RESOURCE: c_int = 24;

/// A resource limit as `getrlimit(2)` reports it: the soft limit the kernel enforces (`rlim_cur`)
/// and the ceiling an unprivileged process may raise it to (`rlim_max`), in the resource's unit.
/// Either may be [`Rlimit::INFINITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rlimit {
    /// The soft limit, `rlim_cur`.
    pub cur: u64,
    /// The hard limit, `rlim_max`.
    pub max: u64,
}

impl Rlimit {
    /// No limit. Linux's `RLIM_INFINITY` is `~0UL` (include/uapi/asm-generic/resource.h), macOS's
    /// `(1 << 63) - 1` (<sys/resource.h>); the hooks translate between this value and the host's.
    pub const INFINITY: u64 = u64::MAX;

    /// Soft and hard limit both `limit`.
    pub const fn new(limit: u64) -> Self {
        Rlimit {
            cur: limit,
            max: limit,
        }
    }

    /// Soft and hard limit both [`INFINITY`](Self::INFINITY).
    pub const fn unlimited() -> Self {
        Self::new(Self::INFINITY)
    }
}

/// What the code under test is allowed to do: whether it runs as root, the Linux capabilities
/// (capabilities(7)) it holds and the process resource limits (man 2 getrlimit) that let an
/// unprivileged process do some of the same. macOS gates on `root` and `RLIMIT_MEMLOCK` alone,
/// Windows gates no socket call.
///
/// The limits are what `getrlimit`/`prlimit` report inside the sim, and `setrlimit` by the code
/// under test changes them here (never the real process's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Privileges {
    /// Effective uid 0: what macOS checks for reserved ports and BPF devices.
    pub root: bool,
    /// `CAP_NET_ADMIN`: interface configuration, `SO_RCVBUFFORCE`/`SO_SNDBUFFORCE`, `SO_MARK`,
    /// `SO_PRIORITY` above 6 (man 7 socket).
    pub net_admin: bool,
    /// `CAP_NET_RAW`: `AF_PACKET` and raw sockets (man 7 packet), and also `SO_MARK` and a high
    /// `SO_PRIORITY` (net/core/sock.c `sk_setsockopt`).
    pub net_raw: bool,
    /// `CAP_NET_BIND_SERVICE`: binding a port below `ip_unprivileged_port_start`.
    pub net_bind_service: bool,
    /// `CAP_SYS_NICE`: real-time scheduling policies and raising priority (man 7 sched).
    pub sys_nice: bool,
    /// `CAP_IPC_LOCK`: `mlock` beyond `RLIMIT_MEMLOCK` (man 2 mlock).
    pub ipc_lock: bool,
    /// `CAP_SYS_RESOURCE`: raising a hard resource limit (man 2 setrlimit). macOS checks `root`
    /// instead.
    pub sys_resource: bool,
    /// `RLIMIT_RTPRIO`: the highest real-time priority an unprivileged thread may take, 0 for
    /// none (man 2 getrlimit, man 7 sched). Linux only.
    pub rtprio_limit: Rlimit,
    /// `RLIMIT_NICE`: the lowest nice value an unprivileged thread may take, as `20 - limit`, so
    /// 40 allows -20 and 0 allows no lowering at all (man 2 getrlimit). Linux only.
    pub nice_limit: Rlimit,
    /// `RLIMIT_MEMLOCK`: the bytes `mlock` may lock without `CAP_IPC_LOCK` (man 2 mlock); on
    /// macOS the bytes `mlock` may wire, privileged or not.
    pub memlock_limit: Rlimit,
}

/// The stock `RLIMIT_MEMLOCK`: 8 MiB on Linux (`MLOCK_LIMIT` in include/uapi/linux/resource.h,
/// the init task's value in include/asm-generic/resource.h `INIT_RLIMITS`, since Linux 5.16;
/// 64 KiB before), unlimited on macOS (measured on macOS 26 for an ordinary user; tests/rlimits.rs
/// `memlock_os_truth` compares the rest of the macOS behaviour).
const STOCK_MEMLOCK: u64 = if cfg!(target_os = "linux") {
    8 * 1024 * 1024
} else {
    Rlimit::INFINITY
};

impl Privileges {
    /// Root with every capability modelled, `RLIMIT_RTPRIO` 99, `RLIMIT_NICE` 40 and an unlimited
    /// `RLIMIT_MEMLOCK`: what a plain sim grants, so even with a capability revoked the limits
    /// still allow what it gated (snare 1.x's defaults).
    pub const fn all() -> Self {
        Privileges {
            root: true,
            net_admin: true,
            net_raw: true,
            net_bind_service: true,
            sys_nice: true,
            ipc_lock: true,
            sys_resource: true,
            rtprio_limit: Rlimit::new(99),
            nice_limit: Rlimit::new(40),
            memlock_limit: Rlimit::unlimited(),
        }
    }

    /// An unprivileged user with no capabilities and the kernel's stock limits: `RLIMIT_RTPRIO`
    /// and `RLIMIT_NICE` 0 (include/asm-generic/resource.h `INIT_RLIMITS`), so no real-time
    /// policy and no lowering of the nice value, and the stock `RLIMIT_MEMLOCK`.
    pub const fn none() -> Self {
        Privileges {
            root: false,
            net_admin: false,
            net_raw: false,
            net_bind_service: false,
            sys_nice: false,
            ipc_lock: false,
            sys_resource: false,
            rtprio_limit: Rlimit::new(0),
            nice_limit: Rlimit::new(0),
            memlock_limit: Rlimit::new(STOCK_MEMLOCK),
        }
    }

    /// The privileges of the real process running the tests: its effective uid, its effective
    /// capabilities (the `CapEff:` line of `/proc/self/status`, man 5 proc_pid_status; on macOS
    /// root holds them all) and its `RLIMIT_RTPRIO`, `RLIMIT_NICE` and `RLIMIT_MEMLOCK`. Reads
    /// bypass the sim, so it works inside one.
    #[cfg(unix)]
    pub fn from_real_process() -> io::Result<Self> {
        snare_interpose::real(|| {
            let root = unsafe { libc::geteuid() } == 0;
            let mut p = if cfg!(target_os = "linux") {
                let status = std::fs::read_to_string("/proc/self/status")?;
                let caps = status
                    .lines()
                    .find_map(|l| l.strip_prefix("CapEff:"))
                    .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
                    .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
                Self::from_caps(caps, root)
            } else if root {
                Self::all()
            } else {
                Self::none()
            };
            #[cfg(target_os = "linux")]
            {
                p.rtprio_limit = crate::proclimits::real_rlimit(libc::RLIMIT_RTPRIO as c_int)?;
                p.nice_limit = crate::proclimits::real_rlimit(libc::RLIMIT_NICE as c_int)?;
            }
            p.memlock_limit = crate::proclimits::real_rlimit(libc::RLIMIT_MEMLOCK as c_int)?;
            Ok(p)
        })
    }

    /// Whether the capability numbered `cap` (`CAP_NET_ADMIN` and friends) is held; a capability
    /// snare does not model is never held.
    pub fn has_cap(&self, cap: c_int) -> bool {
        match cap {
            CAP_NET_BIND_SERVICE => self.net_bind_service,
            CAP_NET_ADMIN => self.net_admin,
            CAP_NET_RAW => self.net_raw,
            CAP_IPC_LOCK => self.ipc_lock,
            CAP_SYS_NICE => self.sys_nice,
            CAP_SYS_RESOURCE => self.sys_resource,
            _ => false,
        }
    }

    /// The privileges of a capability bitmask, bit `n` for capability `n` as `capget(2)` and the
    /// `CapEff:` line of `/proc/<pid>/status` lay it out (man 5 proc_pid_status), with the stock
    /// limits of [`none`](Self::none): the kernel gives root the same `INIT_RLIMITS` as anyone.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn from_caps(caps: u64, root: bool) -> Self {
        let has = |cap: c_int| caps & (1u64 << cap) != 0;
        Privileges {
            root,
            net_admin: has(CAP_NET_ADMIN),
            net_raw: has(CAP_NET_RAW),
            net_bind_service: has(CAP_NET_BIND_SERVICE),
            sys_nice: has(CAP_SYS_NICE),
            ipc_lock: has(CAP_IPC_LOCK),
            sys_resource: has(CAP_SYS_RESOURCE),
            ..Self::none()
        }
    }

    /// The capability bitmask, as `/proc/<pid>/status` prints it (man 5 proc_pid_status,
    /// `CapEff`): only the modelled capabilities' bits can be set.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn cap_mask(&self) -> u64 {
        [
            CAP_NET_BIND_SERVICE,
            CAP_NET_ADMIN,
            CAP_NET_RAW,
            CAP_IPC_LOCK,
            CAP_SYS_NICE,
            CAP_SYS_RESOURCE,
        ]
        .into_iter()
        .filter(|&cap| self.has_cap(cap))
        .fold(0, |mask, cap| mask | 1u64 << cap)
    }
}

/// The host's socket-buffer sysctls: the defaults a new socket gets, the most `SO_RCVBUF` /
/// `SO_SNDBUF` may ask for, and the lowest port an unprivileged process may bind. A change applies
/// to sockets created after it. The Linux knobs are documented in
/// Documentation/admin-guide/sysctl/net.rst (`net.core.*`) and
/// Documentation/networking/ip-sysctl.rst (`net.ipv4.*`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysLimits {
    /// The receive buffer of a new datagram socket (`net.core.rmem_default`,
    /// `net.inet.udp.recvspace`).
    pub rmem_default: usize,
    /// The largest `SO_RCVBUF` (`net.core.rmem_max`, `kern.ipc.maxsockbuf`). On macOS it also
    /// caps the mbuf allowance of a receive buffer.
    pub rmem_max: usize,
    /// The send buffer of a new datagram socket (`net.core.wmem_default`,
    /// `net.inet.udp.maxdgram`).
    pub wmem_default: usize,
    /// The largest `SO_SNDBUF` (`net.core.wmem_max`, `kern.ipc.maxsockbuf`).
    pub wmem_max: usize,
    /// The receive and send buffers of a new TCP socket (`net.ipv4.tcp_rmem`/`tcp_wmem`,
    /// `net.inet.tcp.recvspace`/`sendspace`).
    pub tcp_rmem_default: usize,
    /// See `tcp_rmem_default`.
    pub tcp_wmem_default: usize,
    /// macOS: a buffer size at or above this fails with `ENOBUFS` outright. A snare knob with no
    /// xnu counterpart, off (`usize::MAX`) by default. Below it, a request above
    /// `rmem_max`/`wmem_max` clamps to the maximum, or fails with `ENOBUFS` when the buffer is
    /// already at the maximum, as xnu bsd/kern/uipc_socket2.c `sbreserve` does.
    pub sockbuf_reject_at: usize,
    /// Binding a port below this needs `CAP_NET_BIND_SERVICE` on Linux
    /// (`net.ipv4.ip_unprivileged_port_start`) or root on macOS.
    pub unprivileged_port_start: u16,
    /// Whether a full receive buffer drops what arrives, as the kernel does. A snare knob, on by
    /// default; off lets datagram data and Linux error reports queue without limit.
    pub enforce_rcvbuf: bool,
    /// How often Linux retransmits a connect's SYN before giving up
    /// (`net.ipv4.tcp_syn_retries`, default 6, at most 127:
    /// Documentation/networking/ip-sysctl.rst); a socket's `TCP_SYNCNT` overrides it. Linux 6.5
    /// and later add `tcp_syn_linear_timeouts` retransmissions. Unused elsewhere.
    pub tcp_syn_retries: u8,
    /// Linux SYN retransmissions using the initial timeout before exponential backoff.
    /// `net.ipv4.tcp_syn_linear_timeouts` defaults to 4 on Linux 6.5 and later; 0 selects the
    /// older schedule. Unused elsewhere.
    pub tcp_syn_linear_timeouts: u8,
    /// Maximum `listen` backlog (`net.core.somaxconn` on Linux, `kern.ipc.somaxconn` on macOS).
    pub listen_backlog_max: usize,
    /// Linux's maximum GSO skb size before protocol headers. Zero disables aggregation;
    /// the default is the legacy 65536-byte netdevice limit. Device-specific limits require
    /// a measured profile value; `from_real_host` does not read this driver setting.
    pub tcp_gso_max_size: usize,
    /// Linux: whether a datagram is admitted whenever the queue's charge does not already exceed
    /// `SO_RCVBUF`, so the queue can overshoot the buffer by one datagram, as kernels before 6.18
    /// do (net/ipv4/udp.c `__udp_enqueue_schedule_skb`: v6.12 drops only when `rmem > rcvbuf`;
    /// v6.15 adds the `rmem + size > rcvbuf` test but still lets a datagram in while
    /// `rmem <= rcvbuf`). Off is the v6.18 rule: admitted when its charge fits, or into an empty
    /// queue. [`host`](Self::host) assumes a current kernel; [`from_real_host`](Self::from_real_host)
    /// picks the rule from the running kernel's release. Unused off Linux.
    pub udp_rcvbuf_overshoot: bool,
    /// Linux: the `skb->truesize` of a received datagram whose head fits the kernel's small-head
    /// cache (net/core/skbuff.c `SKB_SMALL_HEAD_CACHE_SIZE`, sized from `MAX_TCP_HEADER`, plus
    /// the `sk_buff`), which also is what a datagram too large for a 16 KiB head adds to its
    /// length. It depends on the kernel's configuration, not its architecture: measured 960 on
    /// Debian's stock 6.12 kernels for both x86_64 and arm64, 1152 on OrbStack's arm64
    /// 7.0.14-orbstack (scripts/measure-sockbuf.sh). See [`linux_truesize`]. Unused off Linux.
    pub skb_small_truesize: usize,
    /// Linux: the bytes of a datagram's kmalloc'd head that an IPv4 UDP payload cannot use: the
    /// headroom, the IP and UDP headers and the trailing `struct skb_shared_info`
    /// (include/linux/skbuff.h `SKB_DATA_ALIGN`, `SKB_HEAD_ALIGN`). A payload of `len` bytes
    /// takes the smallest power-of-two kmalloc class of at least `len` plus this. Measured 378 on
    /// Debian's stock 6.12 kernels (x86_64 and arm64), 442 on OrbStack's 7.0.14-orbstack, whose
    /// `skb_shared_info` is 64 bytes larger (its `SK_RMEM_DEFAULT` is 229376 rather than 212992).
    /// Unused off Linux.
    pub skb_head_overhead: usize,
}

impl Default for SysLimits {
    fn default() -> Self {
        Self::host()
    }
}

impl SysLimits {
    /// A stock install of the build host's OS on its architecture. Measured: macOS 26 arm64
    /// (sysctl), Debian's stock Linux 6.12 and 7.2 kernels on x86_64 and arm64 (/proc/sys, and
    /// `SO_MEMINFO` for the `skb_*` fields: scripts/measure-sockbuf.sh), Windows 11.
    /// tests/os_parity.rs compares a sim built from [`from_real_host`](Self::from_real_host)
    /// with the machine it runs on.
    ///
    /// - macOS: `kern.ipc.maxsockbuf` 8 MiB is `SB_MAX` (xnu bsd/sys/socketvar.h);
    ///   `net.inet.udp.maxdgram` 9216 is `udp_sendspace` (bsd/netinet/udp_usrreq.c);
    ///   `net.inet.udp.recvspace` 786896 is what `udp_init` there sets once the mbuf cluster pool
    ///   is at least 96 MiB, replacing the compile-time `187 * (1024 + sizeof(struct
    ///   sockaddr_in6))`; `net.inet.tcp.recvspace`/`sendspace` 131072 are `tcp_recvspace` and
    ///   `tcp_sendspace`, `128 * 1024` (bsd/netinet/tcp_usrreq.c). Ports below `IPPORT_RESERVED`
    ///   1024 (`<netinet/in.h>`) are reserved.
    /// - Linux, as of 6.18: `rmem_default`/`wmem_default` are `SK_RMEM_DEFAULT`,
    ///   `SKB_TRUESIZE(256) * 256` (include/net/sock.h), which depends on the kernel's `sk_buff`
    ///   and `skb_shared_info` sizes: 212992 on Debian's x86_64 and arm64 kernels alike, 229376
    ///   on OrbStack's. Since 6.18 `rmem_max`/`wmem_max` default to 4 MiB (net/core/sock.c
    ///   `sysctl_rmem_max = 4 << 20`; measured on Debian 7.2.8); earlier kernels default them to
    ///   `SK_RMEM_DEFAULT` too (measured on Debian 6.12.111), which, like the admission rule and
    ///   the `skb_*` sizes, [`from_real_host`](Self::from_real_host) picks up. `tcp_rmem` 131072
    ///   and `tcp_wmem` 16384 (the middle values), `ip_unprivileged_port_start` 1024 and
    ///   `tcp_syn_retries` 6 are the documented defaults (Documentation/networking/ip-sysctl.rst).
    /// - Windows: 65536 for every new socket's `SO_RCVBUF`/`SO_SNDBUF`, and Winsock takes any
    ///   size as given; neither is documented, and tests/os_parity.rs
    ///   `sockbuf_semantics_match_real_os` compares both with the real OS. No port is reserved.
    pub fn host() -> Self {
        if cfg!(target_os = "macos") {
            SysLimits {
                rmem_default: 786_896,
                rmem_max: 8_388_608,
                wmem_default: 9216,
                wmem_max: 8_388_608,
                tcp_rmem_default: 131_072,
                tcp_wmem_default: 131_072,
                sockbuf_reject_at: usize::MAX,
                unprivileged_port_start: 1024,
                enforce_rcvbuf: true,
                tcp_syn_retries: 6,
                tcp_syn_linear_timeouts: 0,
                listen_backlog_max: 128,
                tcp_gso_max_size: 0,
                udp_rcvbuf_overshoot: false,
                skb_small_truesize: 960,
                skb_head_overhead: 378,
            }
        } else if cfg!(target_os = "linux") {
            SysLimits {
                rmem_default: 212_992,
                rmem_max: 4 << 20,
                wmem_default: 212_992,
                wmem_max: 4 << 20,
                tcp_rmem_default: 131_072,
                tcp_wmem_default: 16_384,
                sockbuf_reject_at: usize::MAX,
                unprivileged_port_start: 1024,
                enforce_rcvbuf: true,
                tcp_syn_retries: 6,
                tcp_syn_linear_timeouts: 4,
                listen_backlog_max: 4096,
                tcp_gso_max_size: 65536,
                udp_rcvbuf_overshoot: false,
                skb_small_truesize: 960,
                skb_head_overhead: 378,
            }
        } else {
            SysLimits {
                rmem_default: 65_536,
                rmem_max: usize::MAX,
                wmem_default: 65_536,
                wmem_max: usize::MAX,
                tcp_rmem_default: 65_536,
                tcp_wmem_default: 65_536,
                sockbuf_reject_at: usize::MAX,
                unprivileged_port_start: 0,
                enforce_rcvbuf: true,
                tcp_syn_retries: 6,
                tcp_syn_linear_timeouts: 0,
                listen_backlog_max: 200,
                tcp_gso_max_size: 0,
                udp_rcvbuf_overshoot: false,
                skb_small_truesize: 960,
                skb_head_overhead: 378,
            }
        }
    }

    /// The machine this runs on, read from `/proc/sys` (Linux) or `sysctl` (macOS); Windows has no
    /// such knobs and gets [`host`](Self::host). Fields with no sysctl behind them keep their
    /// [`host`](Self::host) values. Reads bypass the sim, so it works inside one.
    pub fn from_real_host() -> io::Result<Self> {
        snare_interpose::real(Self::read_real)
    }

    /// Reads the `net.core` and `net.ipv4` sysctls from `/proc/sys`; the `tcp_rmem`/`tcp_wmem`
    /// vectors are `min default max` and their middle value is the default (ip-sysctl.rst).
    #[cfg(target_os = "linux")]
    fn read_real() -> io::Result<Self> {
        let read = |path: &str| -> io::Result<Vec<usize>> {
            let text = std::fs::read_to_string(path)?;
            text.split_whitespace()
                .map(|v| {
                    v.parse()
                        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
                })
                .collect()
        };
        let one = |path: &str| -> io::Result<usize> {
            read(path)?
                .first()
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
        };
        let middle = |path: &str| -> io::Result<usize> {
            read(path)?
                .get(1)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
        };
        let stock = Self::host();
        let (skb_small_truesize, skb_head_overhead) =
            probe_truesize().unwrap_or((stock.skb_small_truesize, stock.skb_head_overhead));
        Ok(SysLimits {
            rmem_default: one("/proc/sys/net/core/rmem_default")?,
            rmem_max: one("/proc/sys/net/core/rmem_max")?,
            wmem_default: one("/proc/sys/net/core/wmem_default")?,
            wmem_max: one("/proc/sys/net/core/wmem_max")?,
            tcp_rmem_default: middle("/proc/sys/net/ipv4/tcp_rmem")?,
            tcp_wmem_default: middle("/proc/sys/net/ipv4/tcp_wmem")?,
            sockbuf_reject_at: usize::MAX,
            unprivileged_port_start: one("/proc/sys/net/ipv4/ip_unprivileged_port_start")?
                .min(u16::MAX as usize) as u16,
            enforce_rcvbuf: true,
            tcp_syn_retries: one("/proc/sys/net/ipv4/tcp_syn_retries")?.min(u8::MAX as usize) as u8,
            tcp_syn_linear_timeouts: match one("/proc/sys/net/ipv4/tcp_syn_linear_timeouts") {
                Ok(value) => value.min(u8::MAX as usize) as u8,
                Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
                Err(error) => return Err(error),
            },
            listen_backlog_max: one("/proc/sys/net/core/somaxconn")?,
            tcp_gso_max_size: stock.tcp_gso_max_size,
            udp_rcvbuf_overshoot: kernel_before(
                &std::fs::read_to_string("/proc/sys/kernel/osrelease")?,
                (6, 18),
            ),
            skb_small_truesize,
            skb_head_overhead,
        })
    }

    /// Reads the socket-buffer sysctls with `sysctlbyname(3)`; `kern.ipc.maxsockbuf` is the
    /// maximum for both directions (xnu `sb_max`).
    #[cfg(target_os = "macos")]
    fn read_real() -> io::Result<Self> {
        /// One integer sysctl, which macOS stores as a 4-byte `int` or an 8-byte quad.
        fn sysctl(name: &std::ffi::CStr) -> io::Result<usize> {
            let mut value = [0u8; 8];
            let mut len = value.len();
            let rc = unsafe {
                libc::sysctlbyname(
                    name.as_ptr(),
                    value.as_mut_ptr().cast(),
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(match len {
                4 => u32::from_ne_bytes(value[..4].try_into().unwrap()) as usize,
                _ => u64::from_ne_bytes(value) as usize,
            })
        }
        let max = sysctl(c"kern.ipc.maxsockbuf")?;
        Ok(SysLimits {
            rmem_default: sysctl(c"net.inet.udp.recvspace")?,
            rmem_max: max,
            wmem_default: sysctl(c"net.inet.udp.maxdgram")?,
            wmem_max: max,
            tcp_rmem_default: sysctl(c"net.inet.tcp.recvspace")?,
            tcp_wmem_default: sysctl(c"net.inet.tcp.sendspace")?,
            listen_backlog_max: sysctl(c"kern.ipc.somaxconn")?,
            ..Self::host()
        })
    }

    /// Windows has no socket-buffer sysctls: the stock values.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn read_real() -> io::Result<Self> {
        Ok(Self::host())
    }
}

/// One sim's privileges and limits.
pub(crate) struct SysConfig {
    privileges: Mutex<Privileges>,
    limits: Mutex<SysLimits>,
    /// The memory the code under test has locked, charged against `RLIMIT_MEMLOCK`.
    #[cfg(unix)]
    wired: Mutex<crate::proclimits::Wired>,
}

impl SysConfig {
    /// Every privilege and the host's stock limits.
    pub(crate) fn new() -> Self {
        SysConfig {
            privileges: Mutex::new(Privileges::all()),
            limits: Mutex::new(SysLimits::host()),
            #[cfg(unix)]
            wired: Mutex::new(crate::proclimits::Wired::default()),
        }
    }

    /// The locked-memory table, locked. Taken with no other snare lock held.
    #[cfg(unix)]
    pub(crate) fn wired(&self) -> std::sync::MutexGuard<'_, crate::proclimits::Wired> {
        snare_interpose::real(|| self.wired.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// A copy of the privileges now.
    pub(crate) fn privileges(&self) -> Privileges {
        snare_interpose::real(|| self.privileges.lock().unwrap().clone())
    }

    /// Applies `change` under the lock.
    pub(crate) fn set_privileges(&self, change: impl FnOnce(&mut Privileges)) {
        snare_interpose::real(|| change(&mut self.privileges.lock().unwrap()));
    }

    /// Whether capability `cap` is held now.
    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) fn has_cap(&self, cap: c_int) -> bool {
        self.privileges().has_cap(cap)
    }

    /// A copy of the limits now.
    pub(crate) fn limits(&self) -> SysLimits {
        snare_interpose::real(|| self.limits.lock().unwrap().clone())
    }

    /// Applies `change` under the lock; sockets already open keep their buffers.
    pub(crate) fn set_limits(&self, change: impl FnOnce(&mut SysLimits)) {
        snare_interpose::real(|| change(&mut self.limits.lock().unwrap()));
    }

    /// The errno a bind to `addr` fails with for want of privilege: below the unprivileged port
    /// start without `CAP_NET_BIND_SERVICE` on Linux (net/ipv4/af_inet.c `__inet_bind`,
    /// `inet_port_requires_bind_service`); below it on a specific address without root on macOS
    /// (a wildcard bind is allowed there: xnu bsd/netinet/in_pcb.c `in_pcbbind` checks
    /// `PRIV_NETINET_RESERVEDPORT` only when `sin_addr.s_addr != 0`). Both fail with `EACCES`
    /// (man 2 bind). Port 0 asks for an ephemeral port and is never denied. Pinned on the host by
    /// tests/os_parity.rs `privileged_port_matches_real_os`.
    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) fn bind_denied(&self, addr: SocketAddr) -> Option<c_int> {
        let port = addr.port();
        if port == 0 || port >= self.limits().unprivileged_port_start {
            return None;
        }
        let privileges = self.privileges();
        let allowed = if cfg!(target_os = "linux") {
            privileges.net_bind_service
        } else if cfg!(target_os = "macos") {
            privileges.root || addr.ip().is_unspecified()
        } else {
            true
        };
        (!allowed).then_some(crate::netif::code::EACCES)
    }
}

/// The privileges of the calling thread's sim. Panics off a sim.
#[track_caller]
pub fn privileges() -> Privileges {
    scope::here().sys.privileges()
}

/// Changes the privileges of the calling thread's sim, from then on. Panics off a sim.
#[track_caller]
pub fn set_privileges(change: impl FnOnce(&mut Privileges)) {
    scope::here().sys.set_privileges(change);
}

/// The socket limits of the calling thread's sim. Panics off a sim.
#[track_caller]
pub fn sys_limits() -> SysLimits {
    scope::here().sys.limits()
}

/// Changes the socket limits of the calling thread's sim for sockets created from then on. Panics
/// off a sim.
#[track_caller]
pub fn set_sys_limits(change: impl FnOnce(&mut SysLimits)) {
    scope::here().sys.set_limits(change);
}

/// A datagram's share of its socket's receive buffer, given back when it is read.
#[derive(Clone, Copy, Default)]
pub(crate) struct Charge {
    /// What it adds to [`RxAccount::rmem_alloc`].
    mem: usize,
    /// What it adds to [`RxAccount::cc`] (macOS only; 0 elsewhere).
    cc: usize,
}

/// What a socket's receive queue holds against its buffer: the kernel's memory charge
/// (`sk_rmem_alloc` on Linux, `sb_mbcnt` on macOS, payload bytes on Windows), and on macOS the
/// byte count `sb_cc` that `FIONREAD` reports.
#[derive(Clone, Copy, Default)]
pub(crate) struct RxAccount {
    /// The memory charge of what is queued.
    pub(crate) rmem_alloc: usize,
    /// Datagrams queued.
    pub(crate) queued: usize,
    /// Payload bytes queued.
    pub(crate) queued_bytes: usize,
    /// macOS `sb_cc`: the bytes of the queued records, addresses and control included.
    pub(crate) cc: usize,
    /// Whether the socket has received anything before.
    seen: bool,
}

impl RxAccount {
    /// What a `len`-byte datagram (over IPv6 when `v6`) that crossed a path of MTU `mtu` costs
    /// this queue now. On macOS the cost depends on whether the socket has received before (see
    /// `mac::record`); the path matters only on Linux, which charges a datagram that arrived as
    /// fragments per fragment ([`linux_truesize_fragmented`]).
    fn charge(&self, len: usize, v6: bool, skb: (usize, usize), mtu: Option<u32>) -> Charge {
        if cfg!(target_os = "linux") {
            Charge {
                mem: linux_truesize_fragmented(len, v6, skb, mtu),
                cc: 0,
            }
        } else if cfg!(target_os = "macos") {
            Charge {
                mem: mac::mbufs(len),
                cc: mac::record(len, self.seen),
            }
        } else {
            Charge { mem: len, cc: 0 }
        }
    }

    /// Whether a datagram costing `charge` fits a buffer of `rcvbuf` (as getsockopt reports it).
    /// `sb_max` bounds macOS's mbuf allowance.
    ///
    /// - Linux admits into an empty queue whatever its size, else while the charge still fits
    ///   (net/ipv4/udp.c `__udp_enqueue_schedule_skb` since v6.18: drop when `rmem + size >
    ///   rcvbuf` and `rmem` is not 0); with `overshoot` (older kernels, see
    ///   [`SysLimits::udp_rcvbuf_overshoot`]) while the queue's charge is at most `rcvbuf`.
    /// - macOS needs room for the record's bytes under `sb_hiwat` and for its mbufs under
    ///   `sb_mbmax` (xnu bsd/kern/uipc_socket2.c `sbspace`), with the slack the calibration
    ///   found (`mac`).
    /// - Windows admits while the queued payload is below `SO_RCVBUF`. Winsock does not document
    ///   the rule; tests/os_parity.rs `overflow_counts_match_real_os` compares it with the real OS
    ///   and tests/socket_limits_win.rs `overflow_admits_while_below_rcvbuf` pins it in the sim.
    fn fits(&self, rcvbuf: i32, sb_max: usize, overshoot: bool, charge: Charge) -> bool {
        let rcvbuf = rcvbuf.max(0) as usize;
        if cfg!(target_os = "linux") {
            if overshoot {
                self.rmem_alloc <= rcvbuf
            } else {
                self.rmem_alloc == 0 || self.rmem_alloc + charge.mem <= rcvbuf
            }
        } else if cfg!(target_os = "macos") {
            let mbmax = rcvbuf.saturating_mul(mac::SB_EFFICIENCY).min(sb_max);
            charge.cc <= rcvbuf.saturating_sub(self.cc)
                && self.rmem_alloc < mbmax.saturating_add(mac::MBUF_SLACK)
        } else {
            self.queued_bytes < rcvbuf
        }
    }

    /// Charges an admitted `len`-byte datagram.
    fn take(&mut self, len: usize, charge: Charge) {
        self.rmem_alloc += charge.mem;
        self.cc += charge.cc;
        self.queued += 1;
        self.queued_bytes += len;
        self.seen = true;
    }

    /// Returns the charge of a datagram that was read. Saturates, so a socket whose limits changed
    /// in between cannot underflow.
    fn give_back(&mut self, len: usize, charge: Charge) {
        self.rmem_alloc = self.rmem_alloc.saturating_sub(charge.mem);
        self.cc = self.cc.saturating_sub(charge.cc);
        self.queued = self.queued.saturating_sub(1);
        self.queued_bytes = self.queued_bytes.saturating_sub(len);
    }
}

/// Whether the Linux release string `release` (`/proc/sys/kernel/osrelease`, `uname -r`, e.g.
/// `6.12.111+deb13-amd64`) is older than `major.minor`. A release that does not parse counts as
/// current.
#[cfg(target_os = "linux")]
fn kernel_before(release: &str, (major, minor): (u32, u32)) -> bool {
    let mut parts = release
        .trim()
        .split(|c: char| !c.is_ascii_digit())
        .map(str::parse::<u32>);
    match (parts.next(), parts.next()) {
        (Some(Ok(a)), Some(Ok(b))) => (a, b) < (major, minor),
        _ => false,
    }
}

/// `SKB_DATA_ALIGN(sizeof(struct sk_buff))` on a 64-bit kernel (include/linux/skbuff.h
/// `SKB_TRUESIZE`): what every head adds to the slab object it lands in. Measured as the step
/// from a 1024-byte head to `truesize` 1280 on every kernel scripts/measure-sockbuf.sh booted.
const SK_BUFF_SIZE: usize = 256;

/// The `skb->truesize` Linux charges a `len`-byte UDP datagram received over loopback, given the
/// kernel's `(skb_small_truesize, skb_head_overhead)` ([`SysLimits`]): the small-head cache
/// object while the payload fits it, else the power-of-two kmalloc class (1 KiB to 16 KiB) the
/// payload plus the overhead fits, plus the `sk_buff` (include/linux/skbuff.h `SKB_TRUESIZE`;
/// net/core/skbuff.c `kmalloc_reserve`); a larger datagram costs its length plus the small
/// truesize. IPv6 costs 13 bytes more than IPv4 at every step below that. Measured byte by byte with
/// `SO_MEMINFO` from 0 to 17000 bytes over IPv4 and IPv6 by scripts/sockbuf-probe.c on Debian
/// 6.12.111 x86_64 and arm64 (identical), Debian 7.2.8 x86_64 and arm64, and OrbStack's
/// 7.0.14-orbstack arm64; tests/socket_limits.rs `truesize_os_truth` compares it with the kernel
/// it runs on.
pub(crate) fn linux_truesize(len: usize, v6: bool, (small, overhead): (usize, usize)) -> usize {
    let need = len + if v6 { 13 } else { 0 } + overhead;
    if need < small - SK_BUFF_SIZE {
        return small;
    }
    match [1024, 2048, 4096, 8192]
        .into_iter()
        .find(|&class| need < class)
    {
        Some(class) => class + SK_BUFF_SIZE,
        None if need < 16384 - 1 => 16384 + SK_BUFF_SIZE,
        None => len + small,
    }
}

/// The `skb->truesize` Linux charges a `len`-byte UDP datagram (over IPv6 when `v6`) that crossed
/// a path whose smallest MTU is `mtu`. One that fits a packet is [`linux_truesize`]'s single
/// buffer. A longer one left the sender as IP fragments (net/ipv4/ip_output.c `ip_fragment`,
/// net/ipv6/ip6_output.c `ip6_fragment`, Linux 7.0): every fragment but the last carries the
/// largest multiple of 8 bytes of the UDP header and payload that fits the MTU after the IPv4
/// header (20 bytes) or the IPv6 header and its fragment header (40 + 8). Each fragment is
/// received into a buffer of its own, and reassembly chains them on the first one's
/// `frag_list`, adding each one's truesize to the head's (net/ipv4/inet_fragment.c
/// `inet_frag_reasm_finish`: `head->truesize += fp->truesize`, reached from net/ipv4/
/// ip_fragment.c `ip_frag_reasm` and net/ipv6/reassembly.c `ip6_frag_reasm`), so the datagram
/// costs the sum. A fragment is charged as the unfragmented datagram whose packet is as long:
/// IPv4 fragment payload `p` as a `p - 8`-byte datagram, IPv6 as a `p`-byte one.
///
/// Reassembly may instead coalesce a fragment into the head (`skb_try_coalesce`), which charges
/// only its data; that needs a head the fragment's page can join, which loopback and veth
/// buffers (kmalloc'd heads) do not offer. Measured through veth with 1500-byte MTUs on Linux
/// 7.0.14-orbstack by tests/hw_sockbuf_truth.rs `hw_sockbuf_peer_truesize_matches` (IPv4: 1473
/// bytes as 2304 + 1152, 3000 as 2 × 2304 + 1152, 9000 as 6 × 2304 + 1152); a driver building
/// page-fragment receive buffers may coalesce and charge less, and IPv6 is unmeasured.
pub(crate) fn linux_truesize_fragmented(
    len: usize,
    v6: bool,
    skb: (usize, usize),
    mtu: Option<u32>,
) -> usize {
    const UDP_HEADER: usize = 8;
    let ip_header = if v6 { 40 + 8 } else { 20 };
    let unfragmented = if v6 { 40 } else { 20 } + UDP_HEADER + len;
    let Some(mtu) = mtu
        .map(|m| m as usize)
        .filter(|&m| unfragmented > m && m > ip_header + 8)
    else {
        return linux_truesize(len, v6, skb);
    };
    let max_fragment = (mtu - ip_header) & !7;
    let mut rest = UDP_HEADER + len;
    let mut total = 0;
    while rest > 0 {
        let fragment = rest.min(max_fragment);
        rest -= fragment;
        let as_datagram = if v6 {
            fragment
        } else {
            fragment.saturating_sub(UDP_HEADER)
        };
        total += linux_truesize(as_datagram, v6, skb);
    }
    total
}

/// Measures the running kernel's `(skb_small_truesize, skb_head_overhead)` with `SO_MEMINFO`
/// (man 7 socket): the truesize of an empty datagram, and the smallest payload whose head needs a
/// 2 KiB kmalloc class, found by bisection over loopback. `None` if loopback or `SO_MEMINFO` is
/// unavailable. Called under [`snare_interpose::real`].
#[cfg(target_os = "linux")]
fn probe_truesize() -> Option<(usize, usize)> {
    use std::os::fd::AsRawFd;
    /// `SO_MEMINFO` (include/uapi/asm-generic/socket.h); `SK_MEMINFO_RMEM_ALLOC` is word 0 of
    /// what it returns (include/uapi/linux/sock_diag.h).
    const SO_MEMINFO: c_int = 55;
    let rx = std::net::UdpSocket::bind("127.0.0.1:0").ok()?;
    let tx = std::net::UdpSocket::bind("127.0.0.1:0").ok()?;
    rx.set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .ok()?;
    let to = rx.local_addr().ok()?;
    let buf = [0u8; 1024];
    let truesize = |len: usize| -> Option<usize> {
        tx.send_to(&buf[..len], to).ok()?;
        let mut peek = [0u8; 1];
        rx.peek(&mut peek).ok()?;
        let mut words = [0u32; 9];
        let mut optlen = std::mem::size_of_val(&words) as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                rx.as_raw_fd(),
                libc::SOL_SOCKET,
                SO_MEMINFO,
                words.as_mut_ptr().cast(),
                &mut optlen,
            )
        };
        let mut sink = [0u8; 2048];
        rx.recv(&mut sink).ok()?;
        (rc == 0).then_some(words[0] as usize)
    };
    let small = truesize(0)?;
    let (mut lo, mut hi) = (0, 1024);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if truesize(mid)? >= 2048 + SK_BUFF_SIZE {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    (lo > 0 && lo < 1024).then_some((small, 1024 - lo))
}

/// macOS's receive-buffer charge for UDP, calibrated against xnu 25 (macOS 26) arm64 by counting
/// the datagrams a loopback socket admits across buffer sizes; tests/os_parity.rs
/// `overflow_counts_match_real_os` pins it. Every number here is from that calibration except
/// `SB_EFFICIENCY`.
mod mac {
    /// `sb_mbmax` is `sb_hiwat` times this (xnu bsd/kern/uipc_socket2.c `sb_efficiency` and
    /// `sbreserve`); the cap at `kern.ipc.maxsockbuf` is what the calibration found.
    pub(super) const SB_EFFICIENCY: usize = 8;
    /// The mbuf allowance a datagram still gets once `sb_mbcnt` reaches `sb_mbmax`. Calibrated.
    pub(super) const MBUF_SLACK: usize = 448;

    /// The bytes a record adds to `sb_cc`: the 16-byte source address (`sizeof(struct
    /// sockaddr_in)`, prepended by `sbappendaddr`), the payload and, on every datagram but the
    /// socket's first, a 16-byte control mbuf. The control mbuf is calibrated.
    pub(super) fn record(len: usize, seen: bool) -> usize {
        len + 16 + if seen { 16 } else { 0 }
    }

    /// The mbuf memory a datagram's record takes (`sb_mbcnt`): three mbufs, plus a cluster once
    /// the payload no longer fits them. The 200-byte threshold and both sizes are calibrated.
    pub(super) fn mbufs(len: usize) -> usize {
        if len <= 200 { 1536 } else { 3584 }
    }
}

/// A datagram a receive queue can hold.
pub(crate) trait Arrival {
    /// Where it came from.
    fn src(&self) -> SocketAddr;
    /// Its payload length in bytes.
    fn payload(&self) -> usize;
    /// When it arrives; `None` arrived on sending.
    fn arrives(&self) -> Option<Deadline>;
    /// Whether the link it crossed went down before it arrived.
    fn lost(&self) -> bool;
    /// The smallest MTU on the path it crossed, `None` when it crossed no interface the sim
    /// knows the MTU of: what decides whether it arrived as IP fragments.
    fn path_mtu(&self) -> Option<u32> {
        None
    }
}

/// A landed datagram with what it was charged and the socket's drop count when it landed.
struct Queued<D> {
    dg: D,
    charge: Charge,
    /// The `SO_RXQ_OVFL` value to report with it; 0 while that option is off.
    drops: u32,
}

/// A datagram socket's receive path: what is still in flight, and what has landed in the receive
/// buffer. Datagrams land at their arrival, oldest first, each admitted against the buffer then;
/// whatever does not fit is dropped as the kernel drops it.
pub(crate) struct RxQueue<D> {
    /// Datagrams not yet arrived, each with the sequence number it was pushed with.
    in_flight: Vec<(u64, D)>,
    /// Datagrams landed in the receive buffer, oldest first.
    rx: VecDeque<Queued<D>>,
    /// Push counter: datagrams arriving at the same instant land in the order they were sent.
    seq: u64,
    /// Datagrams admitted to the receive buffer so far. Each wakes the socket on Linux
    /// (net/core/sock.c `sock_def_readable` from `__udp_enqueue_schedule_skb`) and XNU
    /// (bsd/kern/uipc_socket2.c `sorwakeup`), which is a new edge for edge-triggered readiness.
    landed: u64,
}

impl<D> Default for RxQueue<D> {
    fn default() -> Self {
        RxQueue {
            in_flight: Vec::new(),
            rx: VecDeque::new(),
            seq: 0,
            landed: 0,
        }
    }
}

impl<D: Arrival> RxQueue<D> {
    pub(crate) fn pending_time(&self) -> bool {
        !self.in_flight.is_empty()
    }

    /// Takes in a datagram from the wire for socket `rec` (`None` for a tester's endpoint, which
    /// has no buffer limit). One that arrives at once lands after everything already due, so
    /// arrival order holds.
    pub(crate) fn push(&mut self, dg: D, rec: Option<&SockRec>) {
        self.seq += 1;
        if let Some(arrives) = dg.arrives() {
            self.in_flight.push((self.seq, dg));
            #[cfg(target_os = "linux")]
            if let Some(rec) = rec {
                rec.note_data_arrival(arrives);
            }
            #[cfg(not(target_os = "linux"))]
            let _ = arrives;
            return;
        }
        self.land(rec);
        self.enqueue(dg, rec);
    }

    /// Moves every datagram that has arrived by now into the receive buffer, in arrival order,
    /// discarding those whose link went down on the way. Each is admitted against the buffer
    /// as it stands when it lands.
    pub(crate) fn land(&mut self, rec: Option<&SockRec>) {
        self.land_when(rec, |dg| dg.arrives().is_none_or(|d| d.passed()));
    }

    #[cfg(windows)]
    fn land_at(&mut self, rec: Option<&SockRec>, cutoff: std::time::Duration) {
        self.land_when(rec, |dg| dg.arrives().is_none_or(|d| d.at() <= cutoff));
    }

    fn land_when(&mut self, rec: Option<&SockRec>, arrived: impl Fn(&D) -> bool) {
        if self.in_flight.is_empty() {
            return;
        }
        let (mut due, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.in_flight)
            .into_iter()
            .partition(|(_, dg)| arrived(dg));
        self.in_flight = rest;
        due.retain(|(_, dg)| !dg.lost());
        due.sort_by_key(|(seq, dg)| (dg.arrives().map(|d| d.instant()), *seq));
        for (_, dg) in due {
            self.enqueue(dg, rec);
        }
        #[cfg(target_os = "linux")]
        self.track_arrival(rec);
    }

    #[cfg(target_os = "linux")]
    fn track_arrival(&self, rec: Option<&SockRec>) {
        if let Some(rec) = rec {
            let arrives = self
                .in_flight
                .iter()
                .filter_map(|(_, d)| d.arrives())
                .min_by_key(|d| d.at());
            rec.set_data_arrival(arrives);
        }
    }

    /// Lands `dg` if `rec`'s buffer admits it; an overflow is counted on the record and dropped.
    fn enqueue(&mut self, dg: D, rec: Option<&SockRec>) {
        let admitted = match rec {
            Some(rec) => rec.admit(dg.payload(), dg.src(), dg.path_mtu(), dg.arrives()),
            None => Some((Charge::default(), 0)),
        };
        if let Some((charge, drops)) = admitted {
            self.rx.push_back(Queued { dg, charge, drops });
            self.landed += 1;
        }
    }

    /// The oldest landed datagram whose source passes `accept`, with the socket's drop count
    /// when it was queued (`SO_RXQ_OVFL`).
    pub(crate) fn pop(
        &mut self,
        accept: impl Fn(SocketAddr) -> bool,
        rec: Option<&SockRec>,
    ) -> Option<(D, u32)> {
        self.land(rec);
        self.pop_landed(accept, rec)
    }

    pub(crate) fn pop_landed(
        &mut self,
        accept: impl Fn(SocketAddr) -> bool,
        rec: Option<&SockRec>,
    ) -> Option<(D, u32)> {
        let idx = self.rx.iter().position(|q| accept(q.dg.src()))?;
        let q = self.rx.remove(idx)?;
        if let Some(rec) = rec {
            rec.consumed(q.dg.payload(), q.charge, q.dg.src());
        }
        Some((q.dg, q.drops))
    }

    /// A copy of the datagram [`pop`](Self::pop) would take, left in the buffer and still
    /// charged against it (man 2 recv: `MSG_PEEK` "returns data from the beginning of the receive
    /// queue without removing that data from the queue").
    #[cfg(not(windows))]
    pub(crate) fn peek(
        &mut self,
        accept: impl Fn(SocketAddr) -> bool,
        rec: Option<&SockRec>,
    ) -> Option<(D, u32)>
    where
        D: Clone,
    {
        self.land(rec);
        self.peek_landed(accept)
    }

    #[cfg(not(windows))]
    pub(crate) fn first_matching(
        &mut self,
        accept: impl Fn(SocketAddr) -> bool,
        rec: Option<&SockRec>,
    ) -> Option<(&D, u32)> {
        self.land(rec);
        let q = self.rx.iter().find(|q| accept(q.dg.src()))?;
        Some((&q.dg, q.drops))
    }

    pub(crate) fn peek_landed(&self, accept: impl Fn(SocketAddr) -> bool) -> Option<(D, u32)>
    where
        D: Clone,
    {
        let q = self.rx.iter().find(|q| accept(q.dg.src()))?;
        Some((q.dg.clone(), q.drops))
    }

    /// Whether a landed datagram's source passes `accept`.
    pub(crate) fn has(
        &mut self,
        accept: impl Fn(SocketAddr) -> bool,
        rec: Option<&SockRec>,
    ) -> bool {
        self.land(rec);
        self.rx.iter().any(|q| accept(q.dg.src()))
    }

    #[cfg(windows)]
    pub(crate) fn first_matching_at(
        &mut self,
        accept: impl Fn(SocketAddr) -> bool,
        rec: Option<&SockRec>,
        cutoff: std::time::Duration,
    ) -> Option<&D> {
        self.land_at(rec, cutoff);
        self.rx
            .iter()
            .find(|queued| accept(queued.dg.src()))
            .map(|queued| &queued.dg)
    }

    /// The payload length of the next datagram a read returns.
    pub(crate) fn next_len(&mut self, rec: Option<&SockRec>) -> Option<usize> {
        self.land(rec);
        self.rx.front().map(|q| q.dg.payload())
    }

    /// How many datagrams have landed in the receive buffer so far, landing what has arrived.
    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) fn landed(&mut self, rec: Option<&SockRec>) -> u64 {
        self.land(rec);
        self.landed
    }

    /// Datagrams and payload bytes landed and waiting to be read.
    pub(crate) fn queued(&self) -> (usize, usize) {
        self.rx
            .iter()
            .fold((0, 0), |(n, bytes), q| (n + 1, bytes + q.dg.payload()))
    }
}

/// The per-socket buffer state: the sizes getsockopt reports and what fills them.
#[derive(Clone, Copy)]
pub(crate) struct SockBuf {
    /// `SO_RCVBUF` as getsockopt reports it (Linux: already doubled).
    pub(crate) rcvbuf: i32,
    /// `SO_SNDBUF` as getsockopt reports it.
    pub(crate) sndbuf: i32,
    #[cfg(target_os = "linux")]
    pub(crate) rcv_locked: bool,
    /// Whether arrivals are admitted against `rcvbuf`: datagram sockets only, while
    /// [`SysLimits::enforce_rcvbuf`] was on at creation.
    enforce: bool,
    #[cfg(target_os = "linux")]
    enforce_error: bool,
    #[cfg(target_os = "linux")]
    /// Error reports share `sk_rmem_alloc` but do not reserve `sk_forward_alloc` pages.
    pub(crate) error_mem: usize,
    /// `rmem_max` at creation: macOS's `sb_max`.
    sb_max: usize,
    /// [`SysLimits::udp_rcvbuf_overshoot`] at creation.
    overshoot: bool,
    /// [`SysLimits::skb_small_truesize`] and [`SysLimits::skb_head_overhead`] at creation.
    skb: (usize, usize),
    pub(crate) rx: RxAccount,
    /// Datagrams dropped because the buffer was full.
    pub(crate) overflowed: u64,
    /// Datagrams the link lost before they reached the socket.
    pub(crate) wire_lost: u64,
    /// The kernel's `sk_drops`: overflows plus injected drops, wrapping as the kernel's `u32`
    /// counter does.
    pub(crate) drops: u32,
    /// Whether `SO_RXQ_OVFL` is on.
    pub(crate) rxq_ovfl: bool,
}

/// `v` as an `int` socket option value, saturating at `i32::MAX`.
fn as_opt(v: usize) -> i32 {
    v.min(i32::MAX as usize) as i32
}

impl SockBuf {
    /// The buffers of a new socket of `kind`: the TCP defaults for a stream or listener, the
    /// core defaults for anything else.
    pub(crate) fn new(kind: SocketKind, limits: &SysLimits) -> Self {
        let tcp = matches!(kind, SocketKind::TcpStream | SocketKind::TcpListener);
        let (rcvbuf, sndbuf) = if tcp {
            (limits.tcp_rmem_default, limits.tcp_wmem_default)
        } else {
            (limits.rmem_default, limits.wmem_default)
        };
        SockBuf {
            rcvbuf: as_opt(rcvbuf),
            sndbuf: as_opt(sndbuf),
            #[cfg(target_os = "linux")]
            rcv_locked: false,
            enforce: limits.enforce_rcvbuf && kind == SocketKind::Udp,
            #[cfg(target_os = "linux")]
            enforce_error: limits.enforce_rcvbuf,
            #[cfg(target_os = "linux")]
            error_mem: 0,
            sb_max: limits.rmem_max,
            overshoot: limits.udp_rcvbuf_overshoot,
            skb: (limits.skb_small_truesize, limits.skb_head_overhead),
            rx: RxAccount::default(),
            overflowed: 0,
            wire_lost: 0,
            drops: 0,
            rxq_ovfl: false,
        }
    }

    /// Stores `value` as the buffer option sets it.
    pub(crate) fn set(&mut self, which: Buf, value: i32) {
        match which {
            Buf::Rcv => {
                self.rcvbuf = value;
                #[cfg(target_os = "linux")]
                {
                    self.rcv_locked = true;
                }
            }
            Buf::Snd => self.sndbuf = value,
        }
    }

    /// Takes a listening socket's sizes, for a stream accepted from it.
    pub(crate) fn inherit(&mut self, listener: &SockBuf) {
        self.rcvbuf = listener.rcvbuf;
        self.sndbuf = listener.sndbuf;
        #[cfg(target_os = "linux")]
        {
            self.rcv_locked = listener.rcv_locked;
        }
    }

    /// What a TCP socket may hold written and not yet acknowledged, its send buffer: the
    /// reported `SO_SNDBUF`. Measured over loopback against a reader that never reads, with both
    /// buffers set, the bytes a nonblocking writer gets in before `EAGAIN` come to this plus
    /// [`tcp_recv_space`](Self::tcp_recv_space) within 40% on Linux (the smallest buffers deviate
    /// most) and exactly on Windows (tests/tcp_buffers_os_truth.rs). Two host behaviours are not
    /// modelled, so the sim usually back-pressures sooner: Linux grows a send buffer whose
    /// `SO_SNDBUF` was never set toward `tcp_wmem`'s maximum as the connection's window opens
    /// (net/ipv4/tcp_input.c `tcp_sndbuf_expand`; measured 2.6 MB in flight on a loopback stream
    /// nobody reads), and macOS rounds TCP buffers up to whole segments and grows a loopback
    /// receive buffer past `SO_RCVBUF` by an amount that varies from run to run (measured:
    /// `SO_SNDBUF` 4096 reads back 65328, four 16332-byte segments).
    pub(crate) fn tcp_send_space(&self) -> usize {
        self.sndbuf.max(0) as usize
    }

    /// What a TCP socket may hold received and not yet read, which bounds the window it
    /// advertises: the reported `SO_RCVBUF` on Linux (already doubled, of which
    /// `tcp_adv_win_scale` nominally reserves half for overhead, Documentation/networking/
    /// ip-sysctl.rst; the measured totals match the whole value better) and macOS, and twice the
    /// value given on Windows, as measured (see [`tcp_send_space`](Self::tcp_send_space)).
    pub(crate) fn tcp_recv_space(&self) -> usize {
        let rcvbuf = self.rcvbuf.max(0) as usize;
        if cfg!(windows) {
            rcvbuf.saturating_mul(2)
        } else {
            rcvbuf
        }
    }

    /// Admits a `len`-byte datagram that crossed a path of MTU `mtu`, or counts it as an
    /// overflow drop. On admission returns its charge and the drop count to report with it
    /// (`SO_RXQ_OVFL`, man 7 socket).
    pub(crate) fn admit(
        &mut self,
        len: usize,
        v6: bool,
        mtu: Option<u32>,
    ) -> Option<(Charge, u32)> {
        let charge = self.rx.charge(len, v6, self.skb, mtu);
        if self.enforce
            && !self
                .rx
                .fits(self.rcvbuf, self.sb_max, self.overshoot, charge)
        {
            self.overflowed += 1;
            self.drops = self.drops.wrapping_add(1);
            return None;
        }
        self.rx.take(len, charge);
        Some((charge, if self.rxq_ovfl { self.drops } else { 0 }))
    }

    /// Returns a read datagram's charge.
    pub(crate) fn consumed(&mut self, len: usize, charge: Charge) {
        self.rx.give_back(len, charge);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn error_charge(&self, len: usize, v6: bool) -> usize {
        linux_truesize(len, v6, self.skb)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn take_tcp(&mut self, len: usize) -> usize {
        let charge = self.skb.0.saturating_add(len);
        self.rx.rmem_alloc = self.rx.rmem_alloc.saturating_add(charge);
        charge
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn consume_tcp(&mut self, charge: usize) {
        self.rx.rmem_alloc = self.rx.rmem_alloc.saturating_sub(charge);
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn admit_error(&mut self, charge: usize) -> bool {
        if self.enforce_error
            && self.rx.rmem_alloc.saturating_add(charge) >= self.rcvbuf.max(0) as usize
        {
            return false;
        }
        self.rx.rmem_alloc += charge;
        self.error_mem += charge;
        true
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn consume_error(&mut self, charge: usize) {
        self.rx.rmem_alloc = self.rx.rmem_alloc.saturating_sub(charge);
        self.error_mem = self.error_mem.saturating_sub(charge);
    }
}

/// Which buffer an option sizes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Buf {
    /// `SO_RCVBUF`.
    Rcv,
    /// `SO_SNDBUF`.
    Snd,
}

/// The value `SO_RCVBUF`/`SO_SNDBUF` (or, `forced`, `SO_RCVBUFFORCE`/`SO_SNDBUFFORCE`) set to `val`
/// on a buffer now `current` stores, as the host OS rounds it, or the errno it fails with.
/// tests/os_parity.rs `sockbuf_semantics_match_real_os` compares these rules with the real OS
/// on every host.
///
/// - Linux: see the comment in the body (man 7 socket, `SO_RCVBUF`, `SO_RCVBUFFORCE`).
/// - macOS: a value below 1 fails with `EINVAL` (xnu bsd/kern/uipc_socket.c `sosetoptlock`); a
///   value above the maximum clamps to it unless the buffer is already there, when `sbreserve`
///   fails and the call returns `ENOBUFS` (bsd/kern/uipc_socket2.c `sbreserve`).
/// - Windows: stored as given, negative values and 0 included. [Microsoft Learn:
///   setsockopt](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-setsockopt)
///   does not say so; the parity test above and tests/socket_limits_win.rs `sockbuf_as_given`
///   pin it.
#[allow(unused_variables)]
pub(crate) fn sockbuf_value(
    limits: &SysLimits,
    buf: Buf,
    val: c_int,
    current: i32,
    forced: bool,
) -> Result<i32, c_int> {
    #[cfg(target_os = "linux")]
    {
        // net/core/sock.c: the request is capped at rmem_max/wmem_max (read as unsigned, so -1
        // asks for the cap) unless forced, then doubled for bookkeeping overhead, with a floor of
        // SOCK_MIN_RCVBUF / SOCK_MIN_SNDBUF.
        // include/net/sock.h: TCP_SKB_MIN_TRUESIZE (2048 + aligned sizeof(struct sk_buff)), and
        // twice that for send, as a 64-bit kernel computes them.
        const SOCK_MIN_RCVBUF: i64 = 2304;
        const SOCK_MIN_SNDBUF: i64 = 4608;
        let (max, floor) = match buf {
            Buf::Rcv => (limits.rmem_max, SOCK_MIN_RCVBUF),
            Buf::Snd => (limits.wmem_max, SOCK_MIN_SNDBUF),
        };
        let v = if forced {
            val.max(0) as u32
        } else {
            (val as u32).min(max.min(u32::MAX as usize) as u32)
        };
        let v = (v as i64).min(i32::MAX as i64 / 2);
        Ok((v * 2).max(floor) as i32)
    }
    #[cfg(target_os = "macos")]
    {
        if val <= 0 {
            return Err(libc::EINVAL);
        }
        if val as usize >= limits.sockbuf_reject_at {
            return Err(libc::ENOBUFS);
        }
        let max = match buf {
            Buf::Rcv => limits.rmem_max,
            Buf::Snd => limits.wmem_max,
        };
        // bsd/kern/uipc_socket2.c sbreserve: a request above sb_max clamps to it, unless the
        // buffer is already that large, when sbreserve refuses it.
        if val as usize > max && current as usize >= max {
            return Err(libc::ENOBUFS);
        }
        Ok(as_opt((val as usize).min(max)))
    }
    #[cfg(windows)]
    Ok(val)
}

/// `SO_RXQ_OVFL` (include/uapi/asm-generic/socket.h): report the drop count with each datagram
/// (man 7 socket). macOS has no such option; the sim lets only Linux turn it on.
#[cfg(target_os = "linux")]
pub(crate) const SO_RXQ_OVFL: c_int = 40;

/// The buffer, priority and introspection socket options, as the host OS answers them for a
/// socket of the code under test on any unix backend. Each is answered from the record and never
/// reaches the OS. The Linux numbers are those of include/uapi/asm-generic/socket.h, which every
/// architecture snare targets uses.
#[cfg(unix)]
pub(crate) mod sockopt {
    use std::ffi::c_int;

    use super::{Buf, CAP_NET_ADMIN, CAP_NET_RAW, sockbuf_value};
    use crate::scope::SimShared;
    use crate::sockets::SockRec;

    #[cfg(target_os = "linux")]
    mod name {
        use std::ffi::c_int;
        pub(super) const SO_SNDBUFFORCE: c_int = 32;
        pub(super) const SO_RCVBUFFORCE: c_int = 33;
        pub(super) const SO_PRIORITY: c_int = 12;
        pub(super) const SO_MARK: c_int = 36;
        pub(super) const SO_MEMINFO: c_int = 55;
        pub(super) const SO_COOKIE: c_int = 57;
    }

    /// The `int` an option value holds; `EINVAL` when it is shorter than an `int`, as Linux
    /// net/core/sock.c `sk_setsockopt` and xnu bsd/kern/uipc_socket.c `sooptcopyin` answer. A
    /// null pointer gets `EINVAL` too, where the kernels answer `EFAULT`.
    fn read_int(val: *const u8, len: u32) -> Result<c_int, c_int> {
        if val.is_null() || (len as usize) < size_of::<c_int>() {
            return Err(libc::EINVAL);
        }
        Ok(unsafe { val.cast::<c_int>().read_unaligned() })
    }

    /// Handles one of these options; `None` when `(level, name)` is not one. Takes the record's
    /// state lock and reads the sim's limits and privileges, whose locks are leaves.
    ///
    /// # Safety
    /// `val` points to `len` readable bytes.
    pub(crate) unsafe fn set(
        shared: &SimShared,
        rec: &SockRec,
        level: c_int,
        name: c_int,
        val: *const u8,
        len: u32,
    ) -> Option<Result<(), c_int>> {
        if level != libc::SOL_SOCKET {
            return None;
        }
        let buf = match name {
            libc::SO_RCVBUF => Some((Buf::Rcv, false)),
            libc::SO_SNDBUF => Some((Buf::Snd, false)),
            #[cfg(target_os = "linux")]
            name::SO_RCVBUFFORCE => Some((Buf::Rcv, true)),
            #[cfg(target_os = "linux")]
            name::SO_SNDBUFFORCE => Some((Buf::Snd, true)),
            _ => None,
        };
        if let Some((which, forced)) = buf {
            return Some((|| {
                let v = read_int(val, len)?;
                // net/core/sock.c: the forcing variants are for CAP_NET_ADMIN alone.
                if forced && !shared.sys.has_cap(CAP_NET_ADMIN) {
                    return Err(libc::EPERM);
                }
                let mut state = rec.state();
                let current = match which {
                    Buf::Rcv => state.buf.rcvbuf,
                    Buf::Snd => state.buf.sndbuf,
                };
                let stored = sockbuf_value(&shared.sys.limits(), which, v, current, forced)?;
                state.buf.set(which, stored);
                Ok(())
            })());
        }
        #[cfg(target_os = "linux")]
        {
            let raw_or_admin =
                || shared.sys.has_cap(CAP_NET_RAW) || shared.sys.has_cap(CAP_NET_ADMIN);
            match name {
                // socket(7): priorities outside 0..=6 need CAP_NET_ADMIN; net/core/sock.c
                // sk_set_prio_allowed also accepts CAP_NET_RAW.
                name::SO_PRIORITY => {
                    return Some(read_int(val, len).and_then(|v| {
                        if !(0..=6).contains(&v) && !raw_or_admin() {
                            return Err(libc::EPERM);
                        }
                        rec.state().opts.priority = v;
                        Ok(())
                    }));
                }
                name::SO_MARK => {
                    return Some(read_int(val, len).and_then(|v| {
                        if !raw_or_admin() {
                            return Err(libc::EPERM);
                        }
                        rec.state().opts.mark = v as u32;
                        Ok(())
                    }));
                }
                super::SO_RXQ_OVFL => {
                    return Some(read_int(val, len).map(|v| rec.state().buf.rxq_ovfl = v != 0));
                }
                _ => {}
            }
        }
        let _ = (CAP_NET_RAW, shared);
        None
    }

    /// Copies `bytes` to the caller's getsockopt buffer, truncated to `*len` and writing back the
    /// length copied, as Linux net/core/sock.c `sk_getsockopt` does (`if (len > lv) len = lv`);
    /// `EFAULT` for a null pointer.
    ///
    /// # Safety
    /// `val` points to `*len` writable bytes and `len` is valid, or either is null.
    unsafe fn write_bytes(bytes: &[u8], val: *mut u8, len: *mut u32) -> Result<(), c_int> {
        if val.is_null() || len.is_null() {
            return Err(libc::EFAULT);
        }
        let n = (unsafe { *len } as usize).min(bytes.len());
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), val, n);
            *len = n as u32;
        }
        Ok(())
    }

    /// Reads one of these options back; `None` when `(level, name)` is not one. Lands what has
    /// arrived first, so call it with no backend lock held.
    ///
    /// # Safety
    /// `val`/`len` are the caller's getsockopt buffer.
    pub(crate) unsafe fn get(
        rec: &SockRec,
        level: c_int,
        name: c_int,
        val: *mut u8,
        len: *mut u32,
    ) -> Option<Result<(), c_int>> {
        if level != libc::SOL_SOCKET {
            return None;
        }
        let int = |v: c_int| unsafe { write_bytes(&v.to_ne_bytes(), val, len) };
        match name {
            libc::SO_RCVBUF => return Some(int(rec.state().buf.rcvbuf)),
            libc::SO_SNDBUF => return Some(int(rec.state().buf.sndbuf)),
            _ => {}
        }
        #[cfg(target_os = "linux")]
        match name {
            name::SO_PRIORITY => return Some(int(rec.state().opts.priority)),
            name::SO_MARK => return Some(int(rec.state().opts.mark as c_int)),
            super::SO_RXQ_OVFL => return Some(int(rec.state().buf.rxq_ovfl as c_int)),
            // The record's socket id serves as the cookie: unique and never reused within a sim,
            // as sock_gen_cookie's is within a boot. A buffer shorter than a u64 fails with
            // EINVAL (sk_getsockopt).
            name::SO_COOKIE => {
                if len.is_null() || (unsafe { *len } as usize) < size_of::<u64>() {
                    return Some(Err(libc::EINVAL));
                }
                return Some(unsafe { write_bytes(&rec.id.get().to_ne_bytes(), val, len) });
            }
            // sk_get_meminfo's array (net/core/sock.c), truncated to the caller's length by
            // sk_getsockopt, in its order: rmem_alloc, rcvbuf, wmem_alloc, sndbuf, fwd_alloc,
            // wmem_queued, optmem, backlog, drops (include/uapi/linux/sock_diag.h SK_MEMINFO_*).
            // fwd_alloc is approximated as what rounds rmem_alloc up to whole 4 KiB pages, since
            // net/core/sock.c __sk_mem_schedule reserves memory in pages (sk_mem_pages);
            // nothing is sent or backlogged in the sim, so those words are 0.
            name::SO_MEMINFO => {
                rec.land();
                let buf = rec.state().buf;
                let rmem = buf.rx.rmem_alloc as u32;
                let ordinary = rmem.saturating_sub(buf.error_mem as u32);
                let words = [
                    rmem,
                    buf.rcvbuf as u32,
                    0,
                    buf.sndbuf as u32,
                    (4096 - ordinary % 4096) % 4096,
                    0,
                    0,
                    0,
                    buf.drops,
                ];
                let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
                return Some(unsafe { write_bytes(&bytes, val, len) });
            }
            _ => {}
        }
        // xnu bsd/kern/uipc_socket.c sogetoptlock: SO_NREAD is the first datagram's or the
        // stream's unread byte count; SO_NWRITE is the send buffer's sb_cc, always 0 here as the
        // sim keeps no send-buffer occupancy.
        #[cfg(target_os = "macos")]
        match name {
            libc::SO_NREAD => return Some(int(rec.nread())),
            libc::SO_NWRITE => return Some(int(0)),
            _ => {}
        }
        None
    }
}
