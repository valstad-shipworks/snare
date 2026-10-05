//! The protocol counters against the machine the tests run on: the layout the code under test
//! reads (`/proc/net/snmp` field names, `struct udpstat`'s size, the IP Helper constants) and
//! which counter a datagram to a closed port and an unread datagram move, real and simulated
//! side by side. The real host's counters move with other traffic too, so real deltas are only
//! checked to be at least what this test caused.

#[path = "support/counters.rs"]
mod counters;

use std::net::UdpSocket;
use std::time::Duration;

use snare::Sim;

/// Sends one datagram to a closed loopback port and one to a socket that does not read it, and
/// returns the UDP counters before and after.
fn closed_port_and_unread() -> ([u64; 4], [u64; 4]) {
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let before = counters::udp();
    tx.send_to(b"x", "127.0.0.1:9").unwrap();
    tx.send_to(b"y", rx.local_addr().unwrap()).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    (before, counters::udp())
}

#[test]
fn closed_port_and_unread_datagram_move_the_same_counters() {
    let (rb, ra) = closed_port_and_unread();
    let (sb, sa) = Sim::new().run(closed_port_and_unread);
    let delta = |b: [u64; 4], a: [u64; 4]| [a[0] - b[0], a[1] - b[1], a[2] - b[2], a[3] - b[3]];
    let (real, sim) = (delta(rb, ra), delta(sb, sa));
    let received = if cfg!(target_os = "linux") {
        0
    } else if cfg!(target_os = "macos") {
        2
    } else {
        1
    };
    assert_eq!(sim, [received, 1, 0, 2]);
    for i in 0..4 {
        assert!(real[i] >= sim[i], "counter {i}: real {real:?}, sim {sim:?}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn proc_net_snmp_field_names_match_real_os() {
    let names = |text: &str| -> Vec<String> {
        text.lines()
            .step_by(2)
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let snmp6_names = |text: &str| -> Vec<String> {
        text.lines()
            .map(|l| l.split_whitespace().next().unwrap().to_string())
            .filter(|n| !n.starts_with("Icmp6InType") && !n.starts_with("Icmp6OutType"))
            .collect()
    };
    let real = std::fs::read_to_string("/proc/net/snmp").unwrap();
    let real: Vec<String> = names(&real)
        .into_iter()
        .filter(|l| !l.starts_with("IcmpMsg:"))
        .collect();
    let real6 = snmp6_names(&std::fs::read_to_string("/proc/net/snmp6").unwrap());
    let (sim, sim6) = Sim::new().run(|| {
        (
            names(&std::fs::read_to_string("/proc/net/snmp").unwrap()),
            snmp6_names(&std::fs::read_to_string("/proc/net/snmp6").unwrap()),
        )
    });
    assert_eq!(sim, real);
    assert_eq!(sim6, real6);
}

#[cfg(target_os = "macos")]
#[test]
fn udpstat_size_matches_real_os() {
    let real = counters::udpstat().len();
    let sim = Sim::new().run(|| counters::udpstat().len());
    assert_eq!(sim, real);
}

#[cfg(windows)]
#[test]
fn tcp_constants_match_real_os() {
    let pick = |family| {
        let t = counters::tcpstats(family);
        (
            unsafe { t.Anonymous.dwRtoAlgorithm },
            t.dwRtoMin,
            t.dwRtoMax,
            t.dwMaxConn,
        )
    };
    for family in [2, 23] {
        let real = pick(family);
        let sim = Sim::new().run(move || pick(family));
        assert_eq!(sim, real);
    }
}
