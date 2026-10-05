//! The host's protocol counters: the UDP and TCP MIBs a real kernel keeps, driven by the sim's
//! own traffic, and their renderings for the code under test — Linux `/proc/net/snmp` and
//! `/proc/net/snmp6`, macOS `sysctl` `net.inet.udp.stats` (`struct udpstat`), Windows
//! `GetUdpStatistics`/`GetTcpStatistics` and their `Ex`/`Ex2` forms.
//!
//! What is counted is OS-neutral ([`UdpMib`], [`TcpMib`]); each OS's rendering maps it onto its
//! own counter names. Only traffic of the code under test's sockets counts, as only that crosses
//! the simulated host's stack: a tester is another machine. The counters are atomics, so they
//! are leaves in every lock order and may be bumped under any lock.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::scope::{self, SimShared};
use crate::sockets::SocketKind;

/// The UDP counters of one address family.
#[derive(Default)]
pub(crate) struct UdpMib {
    /// Datagrams sent.
    pub(crate) out: AtomicU64,
    /// Datagrams taken into a socket's receive buffer.
    pub(crate) received: AtomicU64,
    /// Datagrams the code under test read.
    pub(crate) read: AtomicU64,
    /// Datagrams dropped on arrival for a full receive buffer.
    pub(crate) rcvbuf_errors: AtomicU64,
    /// Unicast datagrams to one of the host's addresses on a port no socket holds.
    pub(crate) no_ports: AtomicU64,
    /// Broadcast or multicast datagrams the host took in that no socket received.
    pub(crate) ignored_multi: AtomicU64,
}

/// The TCP counters of one address family.
#[derive(Default)]
pub(crate) struct TcpMib {
    /// Connects that sent a SYN.
    pub(crate) active_opens: AtomicU64,
    /// Connections a listener of the code under test took.
    pub(crate) passive_opens: AtomicU64,
    /// Connects that failed after sending their SYN.
    pub(crate) attempt_fails: AtomicU64,
    /// Established connections of the code under test ended by a reset.
    pub(crate) estab_resets: AtomicU64,
    /// Data segments received.
    pub(crate) in_segs: AtomicU64,
    /// Data segments sent.
    pub(crate) out_segs: AtomicU64,
    /// Resets the host sent.
    pub(crate) out_rsts: AtomicU64,
}

/// Every protocol counter of one sim.
#[derive(Default)]
pub(crate) struct ProtoStats {
    udp4: UdpMib,
    udp6: UdpMib,
    tcp4: TcpMib,
    tcp6: TcpMib,
}

/// Whether traffic for `ip` is IPv6 on the wire: an IPv4-mapped address travels as IPv4.
fn is_v6(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => false,
        IpAddr::V6(v6) => v6.to_ipv4_mapped().is_none(),
    }
}

impl ProtoStats {
    /// The UDP counters of `ip`'s family.
    pub(crate) fn udp(&self, ip: IpAddr) -> &UdpMib {
        if is_v6(ip) { &self.udp6 } else { &self.udp4 }
    }

    /// The TCP counters of `ip`'s family.
    pub(crate) fn tcp(&self, ip: IpAddr) -> &TcpMib {
        if is_v6(ip) { &self.tcp6 } else { &self.tcp4 }
    }
}

/// Adds one to `counter`.
pub(crate) fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// A snapshot of one family's UDP counters (see [`proto_counters`]).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpCounters {
    /// Datagrams the code under test sent.
    pub sent: u64,
    /// Datagrams taken into one of its sockets' receive buffers.
    pub received: u64,
    /// Datagrams it read.
    pub read: u64,
    /// Datagrams dropped on arrival because the receiving socket's buffer was full.
    pub rcvbuf_errors: u64,
    /// Unicast datagrams to the host on a port no socket holds.
    pub no_ports: u64,
    /// Broadcast or multicast datagrams the host took in that no socket received.
    pub ignored_multi: u64,
    /// UDP sockets of this family open now.
    pub sockets: u64,
}

/// A snapshot of one family's TCP counters (see [`proto_counters`]).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpCounters {
    /// Connects that sent a SYN.
    pub active_opens: u64,
    /// Connections a listener of the code under test took.
    pub passive_opens: u64,
    /// Connects that failed after sending their SYN.
    pub attempt_fails: u64,
    /// Established connections ended by a reset.
    pub estab_resets: u64,
    /// Connected streams open now.
    pub curr_estab: u64,
    /// Data segments received (MSS-sized pieces of each write; handshake, ACK and FIN segments
    /// are not counted).
    pub in_segs: u64,
    /// Data segments sent, counted as `in_segs`.
    pub out_segs: u64,
    /// Resets the host sent.
    pub out_rsts: u64,
}

/// The host's protocol counters, per address family, as the sim's traffic drove them.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProtoCounters {
    pub udp4: UdpCounters,
    pub udp6: UdpCounters,
    pub tcp4: TcpCounters,
    pub tcp6: TcpCounters,
}

/// The protocol counters of the calling thread's sim: the same numbers the code under test reads
/// from `/proc/net/snmp`, `net.inet.udp.stats` or `GetUdpStatistics`. Panics off a sim.
#[track_caller]
pub fn proto_counters() -> ProtoCounters {
    scope::here().proto_counters()
}

impl SimShared {
    /// Counts a connection in `ip`'s family reset: a reset the host sent when `sent_by_host`, and
    /// one ended established connection per end of the code under test in `ends`.
    pub(crate) fn count_reset(&self, ip: IpAddr, sent_by_host: bool, ends: [bool; 2]) {
        let tcp = self.stats.tcp(ip);
        if sent_by_host {
            bump(&tcp.out_rsts);
        }
        for _ in ends.into_iter().filter(|cut| *cut) {
            bump(&tcp.estab_resets);
        }
    }

    /// See [`proto_counters`].
    pub(crate) fn proto_counters(&self) -> ProtoCounters {
        let (mut udp, mut estab) = ([0u64; 2], [0u64; 2]);
        snare_interpose::real(|| {
            for rec in self.sockets.live_recs() {
                rec.land();
                let state = rec.state();
                let Some(local) = state.local else {
                    continue;
                };
                let family = is_v6(local.ip()) as usize;
                match state.kind {
                    SocketKind::Udp => udp[family] += 1,
                    SocketKind::TcpStream if state.tcp_established => estab[family] += 1,
                    _ => {}
                }
            }
        });
        let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let udp_of = |m: &UdpMib, sockets: u64| UdpCounters {
            sent: load(&m.out),
            received: load(&m.received),
            read: load(&m.read),
            rcvbuf_errors: load(&m.rcvbuf_errors),
            no_ports: load(&m.no_ports),
            ignored_multi: load(&m.ignored_multi),
            sockets,
        };
        let tcp_of = |m: &TcpMib, curr_estab: u64| TcpCounters {
            active_opens: load(&m.active_opens),
            passive_opens: load(&m.passive_opens),
            attempt_fails: load(&m.attempt_fails),
            estab_resets: load(&m.estab_resets),
            curr_estab,
            in_segs: load(&m.in_segs),
            out_segs: load(&m.out_segs),
            out_rsts: load(&m.out_rsts),
        };
        ProtoCounters {
            udp4: udp_of(&self.stats.udp4, udp[0]),
            udp6: udp_of(&self.stats.udp6, udp[1]),
            tcp4: tcp_of(&self.stats.tcp4, estab[0]),
            tcp6: tcp_of(&self.stats.tcp6, estab[1]),
        }
    }
}

impl UdpCounters {
    /// Every datagram that reached the host for a socket, delivered or not.
    #[cfg_attr(windows, allow(dead_code))]
    fn arrived(&self) -> u64 {
        self.received + self.rcvbuf_errors + self.no_ports + self.ignored_multi
    }
}

/// Linux `/proc/net/snmp` and `/proc/net/snmp6`, as net/ipv4/proc.c (`snmp_seq_show_ipstats`,
/// `icmp_put`, `snmp_seq_show_tcp_udp`) and net/ipv6/proc.c (`snmp6_seq_show`) print them: the
/// field lists are `snmp4_ipstats_list`, `snmp4_tcp_list`, `snmp4_udp_list`,
/// `snmp6_ipstats_list` and `snmp6_udp6_list` there, in a 6.x/7.x kernel's order, which
/// tests/proto_counters_os_truth.rs compares with the machine's own file. The `IcmpMsg` lines
/// only appear for message types with a count, so none is printed.
///
/// Values: `Forwarding` 2 is "not forwarding" (RFC 1213 `ipForwarding`), the default with
/// `net.ipv4.ip_forward` 0; `DefaultTTL` 64 is `IPDEFTTL` (include/uapi/linux/ip.h); TCP's
/// `RtoAlgorithm` 1 is "other", `RtoMin` 200 and `RtoMax` 120000 are `TCP_RTO_MIN`/`TCP_RTO_MAX`
/// in milliseconds (include/net/tcp.h) and `MaxConn` -1 is "dynamic" (RFC 4022 `tcpMaxConn`),
/// printed signed as `snmp_seq_show_tcp_udp` does. The UDP counters follow net/ipv4/udp.c:
/// `InDatagrams` counts a datagram when `udp_recvmsg` hands it to the reader, `InErrors` and
/// `RcvbufErrors` a receive-buffer overflow (`__udp_queue_rcv_skb`), `NoPorts` a unicast
/// datagram with no socket (`__udp4_lib_rcv`, which sends the port unreachable counted under
/// `OutDestUnreachs`), `IgnoredMulti` a broadcast or multicast one no socket took
/// (`__udp4_lib_mcast_deliver`). TCP's lines sum both families, as the kernel keeps one TCP MIB
/// per namespace. The IP lines count the UDP datagrams and TCP data segments above; ICMP errors
/// received, `SndbufErrors`, `MemErrors`, checksum errors and retransmissions are never counted.
#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use super::{ProtoCounters, TcpCounters, UdpCounters};
    use std::fmt::Write;

    const IP: &str = "Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams \
        InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout \
        ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates OutTransmits";
    const ICMP: &str = "InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs \
        InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks \
        InAddrMaskReps OutMsgs OutErrors OutRateLimitGlobal OutRateLimitHost OutDestUnreachs \
        OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps \
        OutTimestampReps OutAddrMasks OutAddrMaskReps";
    const TCP: &str = "RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails \
        EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors";
    const UDP: &str = "InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors \
        InCsumErrors IgnoredMulti MemErrors";
    const IP6: &[&str] = &[
        "InReceives",
        "InHdrErrors",
        "InTooBigErrors",
        "InNoRoutes",
        "InAddrErrors",
        "InUnknownProtos",
        "InTruncatedPkts",
        "InDiscards",
        "InDelivers",
        "OutForwDatagrams",
        "OutRequests",
        "OutDiscards",
        "OutNoRoutes",
        "ReasmTimeout",
        "ReasmReqds",
        "ReasmOKs",
        "ReasmFails",
        "FragOKs",
        "FragFails",
        "FragCreates",
        "InMcastPkts",
        "OutMcastPkts",
        "InOctets",
        "OutOctets",
        "InMcastOctets",
        "OutMcastOctets",
        "InBcastOctets",
        "OutBcastOctets",
        "InNoECTPkts",
        "InECT1Pkts",
        "InECT0Pkts",
        "InCEPkts",
        "OutTransmits",
    ];
    const ICMP6: &[&str] = &[
        "InMsgs",
        "InErrors",
        "OutMsgs",
        "OutErrors",
        "InCsumErrors",
        "OutRateLimitHost",
        "InDestUnreachs",
        "InPktTooBigs",
        "InTimeExcds",
        "InParmProblems",
        "InEchos",
        "InEchoReplies",
        "InGroupMembQueries",
        "InGroupMembResponses",
        "InGroupMembReductions",
        "InRouterSolicits",
        "InRouterAdvertisements",
        "InNeighborSolicits",
        "InNeighborAdvertisements",
        "InRedirects",
        "InMLDv2Reports",
        "OutDestUnreachs",
        "OutPktTooBigs",
        "OutTimeExcds",
        "OutParmProblems",
        "OutEchos",
        "OutEchoReplies",
        "OutGroupMembQueries",
        "OutGroupMembResponses",
        "OutGroupMembReductions",
        "OutRouterSolicits",
        "OutRouterAdvertisements",
        "OutNeighborSolicits",
        "OutNeighborAdvertisements",
        "OutRedirects",
        "OutMLDv2Reports",
    ];

    /// One header line and its value line, `Name: f1 f2 ..` then `Name: v1 v2 ..`.
    fn pair(out: &mut String, name: &str, fields: &str, values: &[i64]) {
        let header: Vec<&str> = fields.split_whitespace().collect();
        let _ = writeln!(out, "{name}: {}", header.join(" "));
        let values: Vec<String> = values.iter().map(i64::to_string).collect();
        let _ = writeln!(out, "{name}: {}", values.join(" "));
    }

    /// The value of `name` in a field list, the rest 0.
    fn values(fields: &str, set: &[(&str, u64)]) -> Vec<i64> {
        fields
            .split_whitespace()
            .map(|f| {
                set.iter()
                    .find(|(n, _)| *n == f)
                    .map_or(0, |(_, v)| *v as i64)
            })
            .collect()
    }

    /// The UDP line's values.
    fn udp_values(u: &UdpCounters) -> Vec<i64> {
        values(
            UDP,
            &[
                ("InDatagrams", u.read),
                ("NoPorts", u.no_ports),
                ("InErrors", u.rcvbuf_errors),
                ("OutDatagrams", u.sent),
                ("RcvbufErrors", u.rcvbuf_errors),
                ("IgnoredMulti", u.ignored_multi),
            ],
        )
    }

    /// `/proc/net/snmp`.
    pub(crate) fn snmp(c: &ProtoCounters) -> Vec<u8> {
        let mut out = String::new();
        let (u, t4, t6) = (&c.udp4, &c.tcp4, &c.tcp6);
        let tin = u.arrived() + t4.in_segs;
        let tout = u.sent + t4.out_segs;
        let mut ip = values(
            IP,
            &[
                ("InReceives", tin),
                ("InDelivers", tin),
                ("OutRequests", tout),
                ("OutTransmits", tout),
            ],
        );
        ip[0] = 2;
        ip[1] = 64;
        pair(&mut out, "Ip", IP, &ip);
        pair(
            &mut out,
            "Icmp",
            ICMP,
            &values(
                ICMP,
                &[("OutMsgs", u.no_ports), ("OutDestUnreachs", u.no_ports)],
            ),
        );
        let sum = |f: fn(&TcpCounters) -> u64| f(t4) + f(t6);
        let mut tcp = values(
            TCP,
            &[
                ("ActiveOpens", sum(|t| t.active_opens)),
                ("PassiveOpens", sum(|t| t.passive_opens)),
                ("AttemptFails", sum(|t| t.attempt_fails)),
                ("EstabResets", sum(|t| t.estab_resets)),
                ("CurrEstab", sum(|t| t.curr_estab)),
                ("InSegs", sum(|t| t.in_segs)),
                ("OutSegs", sum(|t| t.out_segs)),
                ("OutRsts", sum(|t| t.out_rsts)),
            ],
        );
        tcp[..4].copy_from_slice(&[1, 200, 120_000, -1]);
        pair(&mut out, "Tcp", TCP, &tcp);
        pair(&mut out, "Udp", UDP, &udp_values(u));
        pair(&mut out, "UdpLite", UDP, &values(UDP, &[]));
        out.into_bytes()
    }

    /// `/proc/net/snmp6`: one `%-32s\t%lu` line per counter (net/ipv6/proc.c
    /// `snmp6_seq_show_item`). `snmp6_udplite6_list` has no `IgnoredMulti`.
    pub(crate) fn snmp6(c: &ProtoCounters) -> Vec<u8> {
        let mut out = String::new();
        let mut line = |name: String, v: u64| {
            let _ = writeln!(out, "{name:<32}\t{v}");
        };
        let (u, t) = (&c.udp6, &c.tcp6);
        let tin = u.arrived() + t.in_segs;
        let tout = u.sent + t.out_segs;
        for f in IP6 {
            let v = match *f {
                "InReceives" | "InDelivers" => tin,
                "OutRequests" | "OutTransmits" => tout,
                _ => 0,
            };
            line(format!("Ip6{f}"), v);
        }
        for f in ICMP6 {
            let v = match *f {
                "OutMsgs" | "OutDestUnreachs" => u.no_ports,
                _ => 0,
            };
            line(format!("Icmp6{f}"), v);
        }
        let udp = udp_values(u);
        for (f, v) in UDP.split_whitespace().zip(&udp) {
            line(format!("Udp6{f}"), *v as u64);
        }
        for f in UDP.split_whitespace().filter(|f| *f != "IgnoredMulti") {
            line(format!("UdpLite6{f}"), 0);
        }
        out.into_bytes()
    }
}

/// macOS `net.inet.udp.stats`: a `struct udpstat` (xnu bsd/netinet/udp_var.h), 23 `u_int32_t`
/// counters in the public source, followed by three more words macOS 26 has and the source does
/// not show, which read 0 here: the sysctl answers 104 bytes, measured and pinned by
/// tests/proto_counters_os_truth.rs. Counters follow bsd/netinet/udp_usrreq.c `udp_input`:
/// `udps_ipackets` counts every datagram arriving for the host, `udps_noport` a unicast one with
/// no socket, `udps_noportbcast` a broadcast or multicast one no socket took, `udps_fullsock`
/// one a full socket dropped, and `udp_output` counts `udps_opackets`. The IPv6 input path
/// (bsd/netinet6/udp6_usrreq.c) counts into the same struct, so both families are summed. Words
/// the sim never moves stay 0.
#[cfg(target_os = "macos")]
pub(crate) mod macos {
    use std::sync::Arc;

    use snare_interpose::{Host, NetResult as HostResult};

    use super::ProtoCounters;
    use crate::scope::SimShared;

    /// The size of `struct udpstat` on macOS 26, measured.
    const UDPSTAT_LEN: usize = 104;
    /// `net.inet.udp.stats` as a MIB: `CTL_NET`, `PF_INET`, `IPPROTO_UDP`, `UDPCTL_STATS`
    /// (`<sys/sysctl.h>`, `<sys/socket.h>`, `<netinet/in.h>`, bsd/netinet/udp_var.h).
    const UDP_STATS_MIB: [i32; 4] = [4, 2, 17, 2];
    /// The sysctl's name.
    const UDP_STATS_NAME: &str = "net.inet.udp.stats";

    /// Answers a read of the node `mib` names from `shared`'s counters; `None` for any other
    /// node. Behaves as the real one, measured: a null `oldp` reports the size, a short buffer
    /// gets what fits and success (bsd/netinet/udp_usrreq.c `udp_getstat` copies
    /// `MIN(sizeof(udpstat), oldlen)`), and a write is `EPERM` (the node is `CTLFLAG_RD`).
    ///
    /// # Safety
    /// `oldp` is null or writable for `*oldlenp` bytes; `oldlenp` is null or valid.
    pub(crate) unsafe fn read(
        shared: &SimShared,
        mib: &[i32],
        oldp: *mut u8,
        oldlenp: *mut usize,
        newp: *const u8,
    ) -> Option<HostResult> {
        if mib != UDP_STATS_MIB {
            return None;
        }
        if !newp.is_null() {
            return Some(HostResult::Err(libc::EPERM));
        }
        if oldlenp.is_null() {
            return Some(HostResult::Err(libc::EINVAL));
        }
        let bytes = udpstat(&shared.proto_counters());
        unsafe {
            if oldp.is_null() {
                *oldlenp = bytes.len();
            } else {
                let n = (*oldlenp).min(bytes.len());
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), oldp, n);
                *oldlenp = n;
            }
        }
        Some(HostResult::Ok(0))
    }

    /// The MIB of a node name this module serves.
    pub(crate) fn mib_of(name: &str) -> Option<[i32; 4]> {
        (name == UDP_STATS_NAME).then_some(UDP_STATS_MIB)
    }

    /// `sysctlnametomib` for a name [`mib_of`] knows: the MIB into `mib`, its length into
    /// `*sizep`, `ENOMEM` when `*sizep` is too short (man 3 sysctlnametomib).
    ///
    /// # Safety
    /// `mib` is writable for `*sizep` ints; `sizep` is valid.
    pub(crate) unsafe fn name_to_mib(
        name: &str,
        mib: *mut i32,
        sizep: *mut usize,
    ) -> Option<HostResult> {
        let words = mib_of(name)?;
        if mib.is_null() || sizep.is_null() {
            return Some(HostResult::Err(libc::EINVAL));
        }
        unsafe {
            if *sizep < words.len() {
                return Some(HostResult::Err(libc::ENOMEM));
            }
            std::ptr::copy_nonoverlapping(words.as_ptr(), mib, words.len());
            *sizep = words.len();
        }
        Some(HostResult::Ok(0))
    }

    /// The name a `sysctlbyname`/`sysctlnametomib` caller passed, if it is UTF-8.
    ///
    /// # Safety
    /// `name` is null or a C string.
    pub(crate) unsafe fn name_str<'a>(name: *const std::ffi::c_char) -> Option<&'a str> {
        if name.is_null() {
            return None;
        }
        unsafe { std::ffi::CStr::from_ptr(name) }.to_str().ok()
    }

    /// A plain sim's host on macOS: it serves the protocol-counter sysctls and declines every
    /// other host call. A `SimHost` serves them itself.
    pub(crate) struct StatsHost(pub(crate) Arc<SimShared>);

    impl Host for StatsHost {
        unsafe fn sysctl(
            &self,
            name: *const i32,
            namelen: u32,
            oldp: *mut u8,
            oldlenp: *mut usize,
            newp: *const u8,
            _newlen: usize,
        ) -> Option<HostResult> {
            if name.is_null() {
                return None;
            }
            let mib = unsafe { std::slice::from_raw_parts(name, namelen as usize) };
            unsafe { read(&self.0, mib, oldp, oldlenp, newp) }
        }

        unsafe fn sysctlbyname(
            &self,
            name: *const std::ffi::c_char,
            oldp: *mut u8,
            oldlenp: *mut usize,
            newp: *const u8,
            _newlen: usize,
        ) -> Option<HostResult> {
            let mib = mib_of(unsafe { name_str(name) }?)?;
            unsafe { read(&self.0, &mib, oldp, oldlenp, newp) }
        }

        unsafe fn sysctlnametomib(
            &self,
            name: *const std::ffi::c_char,
            mib: *mut i32,
            sizep: *mut usize,
        ) -> Option<HostResult> {
            unsafe { name_to_mib(name_str(name)?, mib, sizep) }
        }
    }

    /// The struct's bytes.
    fn udpstat(c: &ProtoCounters) -> Vec<u8> {
        let (a, b) = (&c.udp4, &c.udp6);
        let mut words = [0u32; UDPSTAT_LEN / 4];
        let w = |v: u64| v as u32;
        words[0] = w(a.arrived() + b.arrived());
        words[4] = w(a.no_ports + b.no_ports);
        words[5] = w(a.ignored_multi + b.ignored_multi);
        words[6] = w(a.rcvbuf_errors + b.rcvbuf_errors);
        words[9] = w(a.sent + b.sent);
        words.iter().flat_map(|v| v.to_ne_bytes()).collect()
    }
}

/// Windows `MIB_UDPSTATS`/`MIB_UDPSTATS2` and `MIB_TCPSTATS_LH`/`MIB_TCPSTATS2` (udpmib.h,
/// tcpmib.h; [Microsoft Learn:
/// MIB_UDPSTATS](https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udpstats),
/// [MIB_TCPSTATS_LH](https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcpstats_lh)),
/// written through the `windows-sys` types. Measured on Windows 11 and pinned by
/// tests/proto_counters_os_truth.rs: `dwInDatagrams` counts a datagram when it arrives at a socket,
/// before it is read; `RtoAlgorithm` is `MIB_TCP_RTO_VANJ` (4), `dwRtoMin` 5, and `dwRtoMax` and
/// `dwMaxConn` are `0xFFFFFFFF`. `dwInErrors` counts receive-buffer overflows, a snare choice the
/// documentation does not settle. `dwNumAddrs` and `dwNumConns` are the sim's open UDP sockets
/// and connected streams of the family.
#[cfg(windows)]
pub(crate) mod windows {
    use super::{TcpCounters, UdpCounters};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_TCPSTATS_LH, MIB_TCPSTATS2, MIB_UDPSTATS, MIB_UDPSTATS2,
    };

    /// `MIB_UDPSTATS`.
    pub(crate) fn udp(u: &UdpCounters) -> MIB_UDPSTATS {
        MIB_UDPSTATS {
            dwInDatagrams: u.received as u32,
            dwNoPorts: u.no_ports as u32,
            dwInErrors: u.rcvbuf_errors as u32,
            dwOutDatagrams: u.sent as u32,
            dwNumAddrs: u.sockets as u32,
        }
    }

    /// `MIB_UDPSTATS2`.
    pub(crate) fn udp2(u: &UdpCounters) -> MIB_UDPSTATS2 {
        MIB_UDPSTATS2 {
            dw64InDatagrams: u.received,
            dwNoPorts: u.no_ports as u32,
            dwInErrors: u.rcvbuf_errors as u32,
            dw64OutDatagrams: u.sent,
            dwNumAddrs: u.sockets as u32,
        }
    }

    /// `MIB_TCP_RTO_VANJ`.
    const RTO_VANJ: i32 = 4;

    /// `MIB_TCPSTATS_LH`.
    pub(crate) fn tcp(t: &TcpCounters) -> MIB_TCPSTATS_LH {
        let mut s: MIB_TCPSTATS_LH = unsafe { std::mem::zeroed() };
        s.Anonymous.RtoAlgorithm = RTO_VANJ;
        s.dwRtoMin = 5;
        s.dwRtoMax = u32::MAX;
        s.dwMaxConn = u32::MAX;
        s.dwActiveOpens = t.active_opens as u32;
        s.dwPassiveOpens = t.passive_opens as u32;
        s.dwAttemptFails = t.attempt_fails as u32;
        s.dwEstabResets = t.estab_resets as u32;
        s.dwCurrEstab = t.curr_estab as u32;
        s.dwInSegs = t.in_segs as u32;
        s.dwOutSegs = t.out_segs as u32;
        s.dwOutRsts = t.out_rsts as u32;
        s.dwNumConns = t.curr_estab as u32;
        s
    }

    /// `MIB_TCPSTATS2`.
    pub(crate) fn tcp2(t: &TcpCounters) -> MIB_TCPSTATS2 {
        let mut s: MIB_TCPSTATS2 = unsafe { std::mem::zeroed() };
        s.RtoAlgorithm = RTO_VANJ;
        s.dwRtoMin = 5;
        s.dwRtoMax = u32::MAX;
        s.dwMaxConn = u32::MAX;
        s.dwActiveOpens = t.active_opens as u32;
        s.dwPassiveOpens = t.passive_opens as u32;
        s.dwAttemptFails = t.attempt_fails as u32;
        s.dwEstabResets = t.estab_resets as u32;
        s.dwCurrEstab = t.curr_estab as u32;
        s.dw64InSegs = t.in_segs;
        s.dw64OutSegs = t.out_segs;
        s.dwOutRsts = t.out_rsts as u32;
        s.dwNumConns = t.curr_estab as u32;
        s
    }
}
