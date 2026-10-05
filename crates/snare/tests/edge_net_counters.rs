#![cfg(unix)]
//! Behaviour pins for the protocol counters ahead of a performance pass: a fixed scenario moves
//! every UDP and TCP counter of both families one step at a time (reads, no-ports, broadcast and
//! multicast nobody took, a zero-length datagram, a flooded buffer, opens, refusals, a write
//! longer than loopback's segment size, a linger-0 abort, a tester's connection), and the
//! snapshot after each step — so a counter batched or bumped late shows — plus what the code
//! under test then reads through its OS's own interface (`/proc/net/snmp` and `/proc/net/snmp6`
//! on Linux, `net.inet.udp.stats` on macOS) match the golden `edge_net_counters_<os>.txt`.

#[path = "support/golden.rs"]
mod golden;
#[path = "support/netfault.rs"]
mod netfault;

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream, UdpSocket};
use std::time::Duration;

use snare::{Bytes, Sim, connect_tester, proto_counters};

/// Appends `label` and the counters that differ from the previous step's.
fn step(out: &mut String, last: &mut snare::ProtoCounters, label: &str) {
    let now = proto_counters();
    writeln!(out, "{label}").unwrap();
    if now.udp4 != last.udp4 {
        writeln!(out, "  udp4 {:?}", now.udp4).unwrap();
    }
    if now.udp6 != last.udp6 {
        writeln!(out, "  udp6 {:?}", now.udp6).unwrap();
    }
    if now.tcp4 != last.tcp4 {
        writeln!(out, "  tcp4 {:?}", now.tcp4).unwrap();
    }
    if now.tcp6 != last.tcp6 {
        writeln!(out, "  tcp6 {:?}", now.tcp6).unwrap();
    }
    *last = now;
}

fn scenario() -> String {
    let mut out = String::new();
    let mut last = proto_counters();
    step(&mut out, &mut last, "start");

    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    step(&mut out, &mut last, "two udp4 sockets");
    for _ in 0..5 {
        tx.send_to(b"hello", rx.local_addr().unwrap()).unwrap();
    }
    step(&mut out, &mut last, "five datagrams queued");
    let mut buf = [0u8; 2048];
    for _ in 0..3 {
        rx.recv_from(&mut buf).unwrap();
    }
    step(&mut out, &mut last, "three read");
    tx.send_to(b"", rx.local_addr().unwrap()).unwrap();
    step(&mut out, &mut last, "a zero-length datagram");
    tx.send_to(b"x", "127.0.0.1:9").unwrap();
    step(&mut out, &mut last, "to a closed port");

    tx.set_broadcast(true).unwrap();
    tx.send_to(b"b", (Ipv4Addr::BROADCAST, 9)).unwrap();
    step(&mut out, &mut last, "a broadcast nobody takes");
    let group = Ipv4Addr::new(239, 7, 7, 7);
    let member = UdpSocket::bind("0.0.0.0:0").unwrap();
    member
        .join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)
        .unwrap();
    let other_port = member.local_addr().unwrap().port() + 1;
    tx.send_to(b"m", (group, other_port)).unwrap();
    step(&mut out, &mut last, "a joined group on a port nobody holds");
    tx.send_to(b"n", (Ipv4Addr::new(239, 8, 8, 8), other_port))
        .unwrap();
    step(&mut out, &mut last, "a group nobody joined");
    tx.send_to(b"g", (group, member.local_addr().unwrap().port()))
        .unwrap();
    step(&mut out, &mut last, "a joined group's member takes it");

    let small = UdpSocket::bind("127.0.0.1:0").unwrap();
    netfault::set_buf(netfault::raw(&small), true, 1);
    for _ in 0..20 {
        tx.send_to(&[0u8; 1000], small.local_addr().unwrap())
            .unwrap();
    }
    let entry = snare::socket_entry(snare::socket_id(&small).unwrap()).unwrap();
    writeln!(
        out,
        "flood: delivered {} overflowed {} drops {}",
        entry.delivered, entry.overflowed, entry.drops
    )
    .unwrap();
    step(&mut out, &mut last, "twenty into a minimal buffer");
    drop(small);
    step(&mut out, &mut last, "its socket closed");

    let rx6 = UdpSocket::bind("[::1]:0").unwrap();
    let tx6 = UdpSocket::bind("[::1]:0").unwrap();
    tx6.send_to(b"six", rx6.local_addr().unwrap()).unwrap();
    rx6.recv_from(&mut buf).unwrap();
    tx6.send_to(b"six", "[::1]:9").unwrap();
    step(&mut out, &mut last, "udp6: one read, one to a closed port");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    step(&mut out, &mut last, "connected, not yet accepted");
    let (mut server, _) = listener.accept().unwrap();
    step(&mut out, &mut last, "accepted");
    client.write_all(&[1u8; 100]).unwrap();
    client.write_all(&[2u8; 20_000]).unwrap();
    step(&mut out, &mut last, "100 then 20000 bytes written");
    let mut got = vec![0u8; 20_100];
    server.read_exact(&mut got).unwrap();
    server.write_all(b"").unwrap();
    step(&mut out, &mut last, "read; an empty write");
    let refused = TcpStream::connect("127.0.0.1:9").unwrap_err();
    assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
    step(&mut out, &mut last, "refused");
    client.shutdown(Shutdown::Write).unwrap();
    step(&mut out, &mut last, "client half-closed");
    netfault::set_linger(netfault::raw(&server), 0);
    drop(server);
    step(&mut out, &mut last, "server aborts with linger 0");
    drop(client);
    step(&mut out, &mut last, "client closed");

    let listener6 = TcpListener::bind("[::1]:0").unwrap();
    let c6 = TcpStream::connect(listener6.local_addr().unwrap()).unwrap();
    let (s6, _) = listener6.accept().unwrap();
    (&c6).write_all(b"v6").unwrap();
    step(&mut out, &mut last, "tcp6 connection, one write");
    drop((c6, s6));
    step(&mut out, &mut last, "tcp6 closed");

    let _tester = connect_tester::<Bytes>("127.0.0.2:7000");
    let mut to_tester = TcpStream::connect("127.0.0.2:7000").unwrap();
    to_tester.write_all(&[0u8; 3000]).unwrap();
    step(&mut out, &mut last, "a tester's connection, one write");
    drop(to_tester);
    step(&mut out, &mut last, "closed toward the tester");

    out.push_str(&os_view());
    out
}

#[cfg(target_os = "linux")]
fn os_view() -> String {
    let snmp = std::fs::read_to_string("/proc/net/snmp").unwrap();
    let snmp6 = std::fs::read_to_string("/proc/net/snmp6").unwrap();
    format!("/proc/net/snmp\n{snmp}/proc/net/snmp6\n{snmp6}")
}

#[cfg(target_os = "macos")]
fn os_view() -> String {
    let mut buf = [0u8; 256];
    let mut len = buf.len();
    let rc = unsafe {
        libc::sysctlbyname(
            c"net.inet.udp.stats".as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(rc, 0);
    let words: Vec<String> = buf[..len]
        .chunks(4)
        .map(|c| u32::from_ne_bytes(c.try_into().unwrap()).to_string())
        .collect();
    format!("net.inet.udp.stats ({len} bytes)\n{}\n", words.join(" "))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn os_view() -> String {
    String::new()
}

#[test]
fn a_fixed_scenario_moves_the_counters_exactly() {
    let first = Sim::builder().deterministic().build().run(scenario);
    let plain = Sim::new().run(scenario);
    assert_eq!(first, plain, "the plain clock counts the same");
    golden::check_text(
        &format!("edge_net_counters_{}.txt", std::env::consts::OS),
        &first,
    );
}

#[test]
fn counters_are_per_sim_and_start_at_zero() {
    let a = Sim::new();
    let b = Sim::new();
    a.run(|| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.send_to(b"x", "127.0.0.1:9").unwrap();
    });
    assert_eq!(a.proto_counters().udp4.no_ports, 1);
    assert_eq!(a.proto_counters().udp4.sent, 1);
    assert_eq!(a.proto_counters().udp4.sockets, 0, "closed again");
    assert_eq!(b.proto_counters(), snare::ProtoCounters::default());
    b.run(|| assert_eq!(proto_counters(), snare::ProtoCounters::default()));
}

/// udp(7) counts a datagram into `InDatagrams`/`RcvbufErrors` when it reaches the socket, so a
/// reader of `/proc/net/snmp` sees it the moment its link delay has passed.
#[test]
fn a_datagram_in_flight_counts_as_received_once_it_lands() {
    Sim::new().run(|| {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = rx.local_addr().unwrap();
        snare::set_udp_policy(to, |p| p.latency = Duration::from_millis(5));
        tx.send_to(b"late", to).unwrap();
        let c = proto_counters().udp4;
        assert_eq!((c.sent, c.received, c.read), (1, 0, 0));
        std::thread::sleep(Duration::from_millis(6));
        let c = proto_counters().udp4;
        assert_eq!((c.sent, c.received, c.read), (1, 1, 0));
    });
}

#[test]
fn an_in_flight_datagram_is_counted_once_its_socket_is_looked_at() {
    Sim::new().run(|| {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = rx.local_addr().unwrap();
        snare::set_udp_policy(to, |p| p.latency = Duration::from_millis(5));
        tx.send_to(b"late", to).unwrap();
        std::thread::sleep(Duration::from_millis(6));
        assert_eq!(proto_counters().udp4.received, 1);
        let entry = snare::socket_entry(snare::socket_id(&rx).unwrap()).unwrap();
        assert_eq!((entry.queued, entry.delivered), (1, 1));
        let c = proto_counters().udp4;
        assert_eq!((c.sent, c.received, c.read), (1, 1, 0));
        let mut buf = [0u8; 8];
        rx.recv_from(&mut buf).unwrap();
        assert_eq!(proto_counters().udp4.read, 1);
    });
}

/// The `Tcp:` line's opens, failures, resets and `CurrEstab` as deltas from `before`.
#[cfg(target_os = "linux")]
fn tcp_line(before: &std::collections::HashMap<String, u64>) -> [i64; 6] {
    let now = proc_tcp();
    let d = |k: &str| now[k] as i64 - before[k] as i64;
    [
        d("ActiveOpens"),
        d("PassiveOpens"),
        d("AttemptFails"),
        d("EstabResets"),
        d("OutRsts"),
        d("CurrEstab"),
    ]
}

#[cfg(target_os = "linux")]
fn proc_tcp() -> std::collections::HashMap<String, u64> {
    let text = std::fs::read_to_string("/proc/net/snmp").unwrap();
    let mut lines = text.lines().filter(|l| l.starts_with("Tcp: "));
    let (names, values) = (lines.next().unwrap(), lines.next().unwrap());
    names[5..]
        .split(' ')
        .zip(values[5..].split(' '))
        .map(|(k, v)| (k.to_string(), v.parse::<i64>().unwrap() as u64))
        .collect()
}

/// A loopback connection's life — connected and accepted, a refused connect, a half-close the
/// server reads, an abort with linger 0 from the side in `CLOSE_WAIT`, then the other side's
/// close — as `Tcp:` deltas after each step.
#[cfg(target_os = "linux")]
fn tcp_lifecycle() -> Vec<[i64; 6]> {
    let settle = || std::thread::sleep(Duration::from_millis(50));
    let before = proc_tcp();
    let mut steps = Vec::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    settle();
    steps.push(tcp_line(&before));
    TcpStream::connect("127.0.0.1:9").unwrap_err();
    settle();
    steps.push(tcp_line(&before));
    client.write_all(b"x").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut got = Vec::new();
    server.read_to_end(&mut got).unwrap();
    settle();
    steps.push(tcp_line(&before));
    netfault::set_linger(netfault::raw(&server), 0);
    drop(server);
    settle();
    steps.push(tcp_line(&before));
    drop(client);
    settle();
    steps.push(tcp_line(&before));
    steps
}

/// Linux counts `OutRsts` for the reset its own closed port answers a SYN with, `EstabResets`
/// only for a socket leaving `ESTABLISHED` or `CLOSE_WAIT` by a reset, and `CurrEstab` over
/// those two states only (net/ipv4/tcp.c `tcp_set_state`).
#[cfg(target_os = "linux")]
#[test]
fn tcp_lifecycle_counters_os_truth() {
    let real = tcp_lifecycle();
    let sim = Sim::new().run(tcp_lifecycle);
    assert_eq!(sim, real);
}
