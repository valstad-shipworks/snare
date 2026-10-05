//! `Counters::read` under the shim: the simulated kernel's protocol
//! counters, with the key set of the emulated OS, built from the traffic
//! snare carried plus [`sim::set_protocol_counters`](super::sim::set_protocol_counters).

use std::collections::BTreeMap;
use std::io;

use ::fast_talker::counters::Counters;

use super::platform::{Item, require};
use crate::netif::UdpStats;
use crate::os::OsSemantics;

const UDP_FIELDS: [&str; 9] = [
    "InDatagrams",
    "NoPorts",
    "InErrors",
    "OutDatagrams",
    "RcvbufErrors",
    "SndbufErrors",
    "InCsumErrors",
    "IgnoredMulti",
    "MemErrors",
];

const TCP_FIXED: [(&str, u64); 4] = [
    ("TcpRtoAlgorithm", 1),
    ("TcpRtoMin", 200),
    ("TcpRtoMax", 120_000),
    ("TcpMaxConn", u64::MAX),
];

const TCP_ZEROED: [&str; 13] = [
    "TcpActiveOpens",
    "TcpPassiveOpens",
    "TcpAttemptFails",
    "TcpEstabResets",
    "TcpCurrEstab",
    "TcpInSegs",
    "TcpOutSegs",
    "TcpRetransSegs",
    "TcpInErrs",
    "TcpOutRsts",
    "TcpInCsumErrors",
    "TcpExtListenOverflows",
    "TcpExtListenDrops",
];

pub(crate) fn read() -> io::Result<Counters> {
    require(Item::Counters)?;
    let os = crate::os_semantics();
    let stats = crate::netif::udp_stats();
    let injected = crate::state::ft_slot()
        .inner
        .lock()
        .protocol_counter_injections
        .clone();
    let mut values = base(os, stats);
    for (name, v) in injected {
        let slot = values.entry(name).or_default();
        *slot = slot.wrapping_add(v);
    }
    Ok(values.into_iter().collect())
}

/// Every counter `os` reports, from snare's UDP counters (IPv4, IPv6).
fn base(os: OsSemantics, [v4, v6]: [UdpStats; 2]) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    let mut put = |name: String, v: u64| {
        out.insert(name, v);
    };
    match os {
        OsSemantics::Linux => {
            for (prefix, s) in [("Udp", Some(v4)), ("Udp6", Some(v6)), ("UdpLite", None)] {
                let s = s.unwrap_or_default();
                for field in UDP_FIELDS {
                    let v = match field {
                        "InDatagrams" => s.read,
                        "NoPorts" => s.no_ports,
                        "InErrors" => s.in_errors,
                        "OutDatagrams" => s.out,
                        "RcvbufErrors" => s.rcvbuf_errors,
                        _ => 0,
                    };
                    put(format!("{prefix}{field}"), v);
                }
            }
            put("IpForwarding".into(), 2);
            put("IpDefaultTTL".into(), 64);
            for (name, v) in TCP_FIXED {
                put(name.into(), v);
            }
            for name in TCP_ZEROED {
                put(name.into(), 0);
            }
        }
        OsSemantics::MacOs => {
            let sum = |f: fn(&UdpStats) -> u64| f(&v4) + f(&v6);
            put("UdpInDatagrams".into(), sum(|s| s.queued));
            put("UdpNoPorts".into(), sum(|s| s.no_ports));
            put("UdpInErrors".into(), sum(|s| s.in_errors));
            put("UdpOutDatagrams".into(), sum(|s| s.out));
            put("UdpRcvbufErrors".into(), sum(|s| s.rcvbuf_errors));
            put("UdpInCsumErrors".into(), 0);
            put("UdpIgnoredMulti".into(), 0);
        }
        OsSemantics::Windows => {
            for (prefix, s) in [("Udp", v4), ("Udp6", v6)] {
                put(format!("{prefix}InDatagrams"), s.queued);
                put(format!("{prefix}NoPorts"), s.no_ports);
                put(format!("{prefix}InErrors"), s.in_errors);
                put(format!("{prefix}OutDatagrams"), s.out);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(queued: u64, read: u64) -> UdpStats {
        UdpStats {
            queued,
            read,
            no_ports: 1,
            out: 7,
            rcvbuf_errors: 2,
            in_errors: 2,
        }
    }

    #[test]
    fn key_sets_follow_the_os() {
        let s = [stats(5, 3), stats(1, 1)];
        let linux = base(OsSemantics::Linux, s);
        assert_eq!(linux["UdpInDatagrams"], 3);
        assert_eq!(linux["Udp6InDatagrams"], 1);
        assert_eq!(linux["UdpRcvbufErrors"], 2);
        assert_eq!(linux["TcpMaxConn"], u64::MAX);
        assert!(linux.contains_key("UdpLiteInDatagrams"));

        let macos = base(OsSemantics::MacOs, s);
        assert_eq!(macos["UdpInDatagrams"], 6);
        assert_eq!(macos["UdpOutDatagrams"], 14);
        assert_eq!(macos.len(), 7);
        assert!(!macos.keys().any(|k| k.starts_with("Udp6")));

        let windows = base(OsSemantics::Windows, s);
        assert_eq!(windows.len(), 8);
        assert_eq!(windows["UdpInErrors"], 2);
        assert!(!windows.contains_key("UdpRcvbufErrors"));
    }
}
