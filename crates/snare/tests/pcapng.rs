//! pcapng capture of what crosses the sim's network: TCP handshakes, data, ACKs, FINs and resets
//! with consistent sequence numbers, datagrams once at their sender, ICMP port unreachables and
//! raw frames, stamped on the sim's clock and attributed to the interface they cross.

#[path = "support/netfault.rs"]
mod netfault;
#[path = "support/pcapng_reader.rs"]
mod reader;

use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use reader::{ACK, EPOCH_NS, FIN, Frame, L4, PSH, RST, SYN};
use snare::sched::{self, ExecutiveConfig};
use snare::{
    Bytes, IpNet, ListenerBehavior, NicSpec, Sim, TesterAction, connect_tester, run_testers,
    set_listener_behavior, set_tcp_policy, set_udp_policy, udp_tester,
};

const MS: Duration = Duration::from_millis(1);

fn scratch(name: &str) -> PathBuf {
    snare::real(|| {
        let dir = std::env::temp_dir().join(format!("snare-pcapng-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(format!("{name}.pcapng"))
    })
}

fn captured(name: &str, run: impl FnOnce()) -> reader::File {
    captured_with(name, Sim::builder(), run)
}

fn captured_with(name: &str, builder: snare::SimBuilder, run: impl FnOnce()) -> reader::File {
    let path = scratch(name);
    let sim = builder.pcapng(&path).build();
    assert_eq!(sim.pcapng_path(), Some(path.as_path()));
    sim.run(run);
    drop(sim);
    reader::read(&path)
}

fn frames(file: &reader::File) -> Vec<Frame> {
    file.packets
        .iter()
        .map(|p| reader::decode(&p.data))
        .collect()
}

fn tcp(file: &reader::File) -> Vec<(Frame, bool, u64)> {
    file.packets
        .iter()
        .map(|p| (reader::decode(&p.data), p.inbound, p.ns))
        .filter(|(f, _, _)| f.tcp_flags().is_some())
        .collect()
}

fn flags(frames: &[(Frame, bool, u64)]) -> Vec<(u8, bool)> {
    frames
        .iter()
        .map(|(f, inbound, _)| (f.tcp_flags().unwrap(), *inbound))
        .collect()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// The points after a connect starts at which the host retransmits its SYN.
fn syn_plan() -> Vec<u64> {
    if cfg!(unix) {
        vec![1, 2, 3, 4, 5, 7, 11, 19, 35, 67]
    } else {
        vec![3, 9]
    }
}

#[test]
fn tcp_echo_with_connect_tester() {
    let file = captured("tcp_echo", || {
        let server = connect_tester::<Bytes>("127.0.0.2:9500")
            .then_action(|msg, _| TesterAction::Send(msg))
            .until_after(50 * MS);
        let client = thread::spawn(|| {
            let mut s = TcpStream::connect("127.0.0.2:9500").unwrap();
            s.write_all(b"hello").unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).unwrap();
            buf
        });
        run_testers!(server);
        assert_eq!(&client.join().unwrap(), b"hello");
    });
    let segs = tcp(&file);
    let seen = flags(&segs);
    assert_eq!(
        &seen[..7],
        &[
            (SYN, false),
            (SYN | ACK, true),
            (ACK, false),
            (PSH | ACK, false),
            (ACK, true),
            (PSH | ACK, true),
            (ACK, false),
        ]
    );
    assert!(seen.contains(&(FIN | ACK, false)), "{seen:?}");
    assert!(seen.contains(&(FIN | ACK, true)), "{seen:?}");
    assert_eq!(segs[3].0.payload, b"hello");
    assert_eq!(segs[5].0.payload, b"hello");
    let (syn, synack) = (&segs[0].0, &segs[1].0);
    assert_eq!((syn.dst, syn.dport), (ip("127.0.0.2"), 9500));
    assert!(matches!(syn.l4, L4::Tcp { mss: Some(_), .. }));
    assert!(matches!(synack.l4, L4::Tcp { mss: Some(_), .. }));
    assert_eq!(syn.dst_mac, [0; 6], "loopback frames carry zero MACs");
    let ttl = if cfg!(windows) { 128 } else { 64 };
    assert!(segs.iter().all(|(f, _, _)| f.ttl == ttl));
    reader::check_tcp_sequences(&frames(&file));
    assert!(file.appl.starts_with("snare "));
    assert_eq!(file.os, std::env::consts::OS);
}

#[test]
fn connect_refused_emits_syn_then_rst_ack() {
    let file = captured("refused", || {
        let e = TcpStream::connect("127.0.0.1:9").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::ConnectionRefused);
    });
    let seen = flags(&tcp(&file));
    assert_eq!(seen.first(), Some(&(SYN, false)));
    assert_eq!(seen.last(), Some(&(RST | ACK, true)));
    assert!(
        seen.iter()
            .all(|f| *f == (SYN, false) || *f == (RST | ACK, true)),
        "{seen:?}"
    );
    assert_eq!(seen.len(), if cfg!(windows) { 10 } else { 2 });
    if cfg!(windows) {
        let segs = tcp(&file);
        for (index, pair) in segs.as_chunks::<2>().0.iter().enumerate() {
            assert_eq!(pair[0].2 - segs[0].2, index as u64 * 500_000_000);
            assert_eq!(pair[0].2, pair[1].2);
        }
    }
    let segs = tcp(&file);
    let (syn, rst) = (&segs[0].0, &segs.last().unwrap().0);
    assert_eq!(rst.seq_ack().1, syn.seq_ack().0.wrapping_add(1));
    assert!(
        (49152..=65535).contains(&syn.sport),
        "a refused connect still takes an ephemeral port: {}",
        syn.sport
    );
}

#[test]
fn syn_retransmits_follow_the_os_plan_and_stop_at_resolution() {
    let until = 5;
    let file = captured("syn_plan", || {
        let tester = connect_tester::<Bytes>("127.0.0.2:9501").until_after(MS);
        set_listener_behavior(
            "127.0.0.2:9501",
            ListenerBehavior::DelayingUntil(Instant::now() + Duration::from_secs(until)),
        );
        drop(TcpStream::connect("127.0.0.2:9501").unwrap());
        drop(tester);
    });
    let segs = tcp(&file);
    let syns: Vec<u64> = segs
        .iter()
        .filter(|(f, _, _)| f.tcp_flags() == Some(SYN))
        .map(|(_, _, ns)| *ns)
        .collect();
    let t0 = syns[0];
    let rel: Vec<u64> = syns.iter().map(|ns| (ns - t0) / 1_000_000_000).collect();
    let mut expected = vec![0];
    let resolved = *syn_plan().iter().find(|&&t| t >= until).unwrap();
    expected.extend(syn_plan().into_iter().take_while(|&t| t <= resolved));
    assert_eq!(rel, expected);
    let synack = segs
        .iter()
        .find(|(f, _, _)| f.tcp_flags() == Some(SYN | ACK))
        .expect("SYN|ACK");
    assert!(
        synack.2 - syns.last().unwrap() < 1_000_000,
        "answered at the last retransmission"
    );
    reader::check_tcp_sequences(&frames(&file));

    let nic = NicSpec::new("eth0").address("192.168.60.2/24".parse::<IpNet>().unwrap());
    let path = scratch("syn_plan_absent");
    let sim = Sim::builder().nic(nic).pcapng(&path).build();
    let failed_at = sim.run(|| {
        TcpStream::connect("192.168.60.77:80").unwrap_err();
        snare::time().value()
    });
    drop(sim);
    let file = reader::read(&path);
    let segs = tcp(&file);
    assert!(!segs.is_empty());
    assert!(segs.iter().all(|(f, _, _)| f.tcp_flags() == Some(SYN)));
    let t0 = segs[0].2;
    for (_, _, ns) in &segs {
        let rel = ns - t0;
        assert!(
            rel == 0 || syn_plan().contains(&(rel / 1_000_000_000)),
            "{rel}"
        );
        assert!(
            *ns <= EPOCH_NS + failed_at.as_nanos() as u64,
            "no SYN after giving up"
        );
    }
}

#[cfg(windows)]
#[test]
fn extended_maxrt_captures_retries_at_the_capped_timeout() {
    use std::mem::size_of;
    use windows_sys::Win32::Networking::WinSock as ws;
    for timeout in [240i32, -1] {
        let file = captured(&format!("extended_maxrt_{timeout}"), || {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let at = listener.local_addr().unwrap();
            set_listener_behavior(
                at,
                ListenerBehavior::DelayingUntil(Instant::now() + Duration::from_secs(200)),
            );
            unsafe {
                let fd = ws::socket(ws::AF_INET as i32, ws::SOCK_STREAM, 0);
                assert_ne!(fd, ws::INVALID_SOCKET);
                assert_eq!(
                    ws::setsockopt(
                        fd,
                        ws::IPPROTO_TCP,
                        5,
                        (&raw const timeout).cast(),
                        size_of::<i32>() as i32
                    ),
                    0
                );
                let mut address: ws::SOCKADDR_IN = std::mem::zeroed();
                address.sin_family = ws::AF_INET;
                address.sin_port = at.port().to_be();
                address.sin_addr.S_un.S_addr = u32::from_ne_bytes([127, 0, 0, 1]);
                assert_eq!(
                    ws::connect(
                        fd,
                        (&raw const address).cast(),
                        size_of::<ws::SOCKADDR_IN>() as i32
                    ),
                    0
                );
                ws::closesocket(fd);
            }
        });
        let syns: Vec<_> = tcp(&file)
            .into_iter()
            .filter(|(frame, _, _)| frame.tcp_flags() == Some(SYN))
            .map(|(_, _, at)| at)
            .collect();
        let first = syns[0];
        assert_eq!(
            syns.into_iter()
                .map(|at| (at - first) / 1_000_000_000)
                .collect::<Vec<_>>(),
            [0, 3, 9, 21, 45, 93, 153, 213]
        );
        reader::check_tcp_sequences(&frames(&file));
    }
}

#[test]
#[cfg(windows)]
fn listener_inside_the_refusal_window_is_captured() {
    let file = captured("refusal_window", || {
        let client = thread::spawn(|| {
            let mut s = TcpStream::connect("127.0.0.2:9504").unwrap();
            s.write_all(b"hello").unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).unwrap();
        });
        thread::sleep(Duration::from_millis(750));
        let server = connect_tester::<Bytes>("127.0.0.2:9504")
            .then_action(|msg, _| TesterAction::Send(msg))
            .until_after(Duration::from_secs(3));
        run_testers!(server);
        client.join().unwrap();
    });
    let segs = tcp(&file);
    let seen = flags(&segs);
    assert_eq!(
        &seen[..7],
        &[
            (SYN, false),
            (RST | ACK, true),
            (SYN, false),
            (RST | ACK, true),
            (SYN, false),
            (SYN | ACK, true),
            (ACK, false),
        ]
    );
    assert!(seen.contains(&(PSH | ACK, false)), "{seen:?}");
    assert!(seen.contains(&(PSH | ACK, true)), "{seen:?}");
    assert_eq!(
        segs[4].2 - segs[0].2,
        1_000_000_000,
        "the retry after the listener starts"
    );
    reader::check_tcp_sequences(&frames(&file));
}

#[test]
fn lazily_polled_connect_keeps_only_the_syns_before_its_answer() {
    let file = captured("lazy_connect", || {
        let tester = connect_tester::<Bytes>("127.0.0.2:9503").until_after(MS);
        set_listener_behavior(
            "127.0.0.2:9503",
            ListenerBehavior::DelayingUntil(Instant::now() + Duration::from_millis(1500)),
        );
        let s = mio::net::TcpStream::connect("127.0.0.2:9503".parse().unwrap()).unwrap();
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..10 {
            thread::sleep(Duration::from_secs(1));
            u.send_to(b"x", "127.0.0.1:9").unwrap();
        }
        netfault::poll(netfault::raw(&s), false, true, 0);
        assert!(s.take_error().unwrap().is_none());
        drop(s);
        drop(tester);
    });
    let stamps: Vec<u64> = file.packets.iter().map(|p| p.ns).collect();
    assert!(stamps.is_sorted(), "{stamps:?}");
    let segs = tcp(&file);
    let synack = segs
        .iter()
        .find(|(f, _, _)| f.tcp_flags() == Some(SYN | ACK))
        .expect("SYN|ACK")
        .2;
    let syns: Vec<u64> = segs
        .iter()
        .filter(|(f, _, _)| f.tcp_flags() == Some(SYN))
        .map(|(_, _, ns)| *ns)
        .collect();
    assert!(syns.iter().all(|&ns| ns <= synack), "{syns:?} vs {synack}");
    assert!(
        synack - syns[0] < 10_000_000_000,
        "answered at a plan point: {syns:?} {synack}"
    );
    reader::check_tcp_sequences(&frames(&file));
}

#[test]
fn tester_reset_emits_rst() {
    let file = captured("tester_reset", || {
        let server = connect_tester::<Bytes>("127.0.0.2:9502")
            .then_action(|_, _| TesterAction::Reset)
            .until_after(50 * MS);
        let client = thread::spawn(|| {
            let mut s = TcpStream::connect("127.0.0.2:9502").unwrap();
            s.write_all(b"x").unwrap();
            let mut buf = [0u8; 1];
            let _ = s.read(&mut buf);
        });
        run_testers!(server);
        client.join().unwrap();
    });
    let seen = flags(&tcp(&file));
    assert_eq!(
        seen.iter().filter(|f| **f == (RST | ACK, true)).count(),
        1,
        "{seen:?}"
    );
    assert!(!seen.iter().any(|(f, _)| f & FIN != 0), "{seen:?}");
    reader::check_tcp_sequences(&frames(&file));
}

#[test]
fn linger_zero_emits_rst() {
    let file = captured("linger_zero", || {
        let server = connect_tester::<Bytes>("127.0.0.2:9503").until_after(50 * MS);
        let client = thread::spawn(|| {
            let s = TcpStream::connect("127.0.0.2:9503").unwrap();
            netfault::set_linger(netfault::raw(&s), 0);
            drop(s);
        });
        run_testers!(server);
        client.join().unwrap();
    });
    let seen = flags(&tcp(&file));
    assert_eq!(
        seen.iter().filter(|f| **f == (RST | ACK, false)).count(),
        1,
        "{seen:?}"
    );
    assert!(
        !seen.iter().any(|(f, out)| f & FIN != 0 && !out),
        "{seen:?}"
    );
}

#[test]
fn shutdown_write_then_close_emits_one_fin() {
    let file = captured("shutdown_write", || {
        let server = connect_tester::<Bytes>("127.0.0.2:9504").until_after(50 * MS);
        let client = thread::spawn(|| {
            let s = TcpStream::connect("127.0.0.2:9504").unwrap();
            s.shutdown(Shutdown::Write).unwrap();
            drop(s);
        });
        run_testers!(server);
        client.join().unwrap();
    });
    let seen = flags(&tcp(&file));
    assert_eq!(
        seen.iter().filter(|f| **f == (FIN | ACK, false)).count(),
        1,
        "{seen:?}"
    );
    reader::check_tcp_sequences(&frames(&file));
}

#[test]
fn shutdown_read_emits_no_fin() {
    let file = captured("shutdown_read", || {
        let server = connect_tester::<Bytes>("127.0.0.2:9505").until_after(50 * MS);
        let client = thread::spawn(|| {
            let s = TcpStream::connect("127.0.0.2:9505").unwrap();
            s.shutdown(Shutdown::Read).unwrap();
            thread::sleep(10 * MS);
            std::mem::forget(s);
        });
        run_testers!(server);
        client.join().unwrap();
    });
    let seen = flags(&tcp(&file));
    assert!(
        !seen.iter().any(|(f, out)| f & FIN != 0 && !out),
        "{seen:?}"
    );
}

#[test]
fn udp_both_directions_with_udp_tester() {
    let file = captured("udp_both", || {
        let tester = udp_tester::<Bytes>("127.0.0.2:9600")
            .then_action(|msg, _| TesterAction::Send(msg))
            .until_after(50 * MS);
        let client = thread::spawn(|| {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.send_to(b"ping", "127.0.0.2:9600").unwrap();
            let mut buf = [0u8; 8];
            let (n, from) = s.recv_from(&mut buf).unwrap();
            (buf[..n].to_vec(), from)
        });
        run_testers!(tester);
        let (got, from) = client.join().unwrap();
        assert_eq!(got, b"ping");
        assert_eq!(from, "127.0.0.2:9600".parse::<SocketAddr>().unwrap());
    });
    let pkts: Vec<(Frame, bool)> = file
        .packets
        .iter()
        .map(|p| (reader::decode(&p.data), p.inbound))
        .collect();
    assert_eq!(pkts.len(), 2);
    let (out, inb) = (&pkts[0], &pkts[1]);
    assert!(!out.1 && inb.1);
    assert_eq!(out.0.l4, L4::Udp);
    assert_eq!((out.0.dst, out.0.dport), (ip("127.0.0.2"), 9600));
    assert_eq!((inb.0.src, inb.0.sport), (ip("127.0.0.2"), 9600));
    assert_eq!((inb.0.dst, inb.0.dport), (out.0.src, out.0.sport));
    assert_eq!(out.0.payload, b"ping");
    assert_eq!(inb.0.payload, b"ping");
}

#[test]
fn udp_loss_and_duplication_capture_once() {
    let file = captured_with("udp_loss", Sim::builder().seed(3), || {
        let rx = UdpSocket::bind("127.0.0.1:9601").unwrap();
        set_udp_policy("127.0.0.1:9601", |p| {
            p.loss_rate = 0.4;
            p.duplicate_rate = 0.4;
        });
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        for i in 0..20u8 {
            tx.send_to(&[i], "127.0.0.1:9601").unwrap();
        }
        drop(rx);
    });
    let pkts = frames(&file);
    assert_eq!(pkts.len(), 20);
    let payloads: Vec<u8> = pkts.iter().map(|f| f.payload[0]).collect();
    assert_eq!(payloads, (0..20).collect::<Vec<u8>>());
    let ids: Vec<u16> = pkts.iter().map(|f| f.ip_id).collect();
    assert!(
        ids.windows(2).all(|w| w[1] == w[0].wrapping_add(1)),
        "{ids:?}"
    );
}

#[test]
fn udp_stalled_send_not_captured() {
    let file = captured("udp_stalled", || {
        let tx = UdpSocket::bind("127.0.0.1:9602").unwrap();
        set_udp_policy("127.0.0.1:9602", |p| p.send_queue_depth = Some(0));
        tx.set_nonblocking(true).unwrap();
        let e = tx.send_to(b"x", "127.0.0.1:9603").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock);
    });
    assert!(file.packets.is_empty());
}

#[test]
fn icmp_port_unreachable_is_captured() {
    let file = captured("icmp", || {
        set_udp_policy("127.0.0.1:9", |p| p.latency = 10 * MS);
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        a.connect("127.0.0.1:9").unwrap();
        a.send(b"anyone?").unwrap();
        let mut buf = [0u8; 4];
        a.recv(&mut buf).unwrap_err();
    });
    let pkts: Vec<(Frame, bool, u64)> = file
        .packets
        .iter()
        .map(|p| (reader::decode(&p.data), p.inbound, p.ns))
        .collect();
    assert_eq!(pkts.len(), 2);
    let (udp, icmp) = (&pkts[0], &pkts[1]);
    assert_eq!(udp.0.l4, L4::Udp);
    let L4::Icmp { kind, code, quoted } = &icmp.0.l4 else {
        panic!("{:?}", icmp.0);
    };
    assert_eq!((*kind, *code), (3, 3));
    assert!(icmp.1, "from the network");
    assert_eq!((icmp.0.src, icmp.0.dst), (udp.0.dst, udp.0.src));
    assert_eq!(&quoted[12..20], &[127, 0, 0, 1, 127, 0, 0, 1]);
    assert_eq!(&quoted[22..24], &9u16.to_be_bytes());
    assert_eq!(&quoted[28..], b"anyone?");
    assert_eq!(
        icmp.2 - udp.2,
        10_000_000,
        "sent when the datagram arrived there"
    );
}

#[test]
fn broadcast_and_multicast_dst_macs() {
    let nic = NicSpec::new("eth0")
        .address("10.9.0.1/24".parse::<IpNet>().unwrap())
        .mac([0x02, 0xaa, 0, 0, 0, 1]);
    let file = captured_with("bcast", Sim::builder().nic(nic), || {
        let s = UdpSocket::bind("10.9.0.1:0").unwrap();
        s.set_broadcast(true).unwrap();
        s.send_to(b"a", "10.9.0.255:9700").unwrap();
        s.send_to(b"b", "255.255.255.255:9700").unwrap();
        s.send_to(b"c", "239.1.2.3:9700").unwrap();
        s.send_to(b"d", "10.9.0.20:9700").unwrap();
    });
    let pkts = frames(&file);
    let dst: Vec<[u8; 6]> = pkts.iter().map(|f| f.dst_mac).collect();
    assert_eq!(dst[0], [0xff; 6]);
    assert_eq!(dst[1], [0xff; 6]);
    assert_eq!(dst[2], [0x01, 0x00, 0x5e, 0x01, 0x02, 0x03]);
    assert_eq!(dst[3][0], 0x02);
    assert!(pkts.iter().all(|f| f.src_mac == [0x02, 0xaa, 0, 0, 0, 1]));
}

#[test]
fn per_nic_idbs_follow_routing() {
    let a = NicSpec::new("snA").address("10.21.0.1/24".parse::<IpNet>().unwrap());
    let b = NicSpec::new("snB").address("10.22.0.1/24".parse::<IpNet>().unwrap());
    let file = captured_with("per_nic", Sim::builder().nic(a).nic(b), || {
        let s = UdpSocket::bind("0.0.0.0:0").unwrap();
        s.send_to(b"b", "10.22.0.9:9701").unwrap();
        s.send_to(b"a", "10.21.0.9:9701").unwrap();
        s.send_to(b"b", "10.22.0.9:9701").unwrap();
    });
    assert_eq!(file.ifaces, ["snB", "snA"], "interfaces in first-use order");
    let on: Vec<(&str, IpAddr)> = file
        .packets
        .iter()
        .map(|p| (p.iface.as_str(), reader::decode(&p.data).src))
        .collect();
    assert_eq!(
        on,
        [
            ("snB", ip("10.22.0.1")),
            ("snA", ip("10.21.0.1")),
            ("snB", ip("10.22.0.1"))
        ]
    );
}

#[test]
fn stamps_follow_virtual_clock() {
    let file = captured("stamps", || {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        thread::sleep(Duration::from_secs(2));
        s.send_to(b"x", "127.0.0.1:9702").unwrap();
    });
    let ns = file.packets[0].ns;
    assert!(ns >= EPOCH_NS + 2_000_000_000, "{ns}");
    assert!(ns < EPOCH_NS + 2_001_000_000, "{ns}");
}

/// The Unix nanoseconds of a `wall YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ` comment, by the days-from-civil
/// count of Howard Hinnant's "chrono-Compatible Low-Level Date Algorithms".
fn wall_ns(comment: &str) -> u64 {
    let t = comment.strip_prefix("wall ").expect(comment);
    assert_eq!(t.len(), 30, "{t}");
    assert!(t.ends_with('Z') && &t[10..11] == "T", "{t}");
    let num = |r: std::ops::Range<usize>| t[r].parse::<u64>().unwrap();
    let (y, m, d) = (num(0..4), num(5..7), num(8..10));
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + num(11..13) * 3600 + num(14..16) * 60 + num(17..19);
    secs * 1_000_000_000 + num(20..29)
}

fn real_unix_ns() -> u64 {
    snare::real(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    })
}

#[test]
fn wall_comment_carries_real_time_while_stamps_stay_virtual() {
    let before = real_unix_ns();
    let builder = Sim::builder().pcapng_wall_comment(true);
    let file = captured_with("wall_comment", builder, || {
        set_tcp_policy("127.0.0.2:9507", |p| p.latency = 50 * MS);
        let server = connect_tester::<Bytes>("127.0.0.2:9507").until_after(200 * MS);
        let client = thread::spawn(|| {
            let mut s = TcpStream::connect("127.0.0.2:9507").unwrap();
            s.write_all(b"late").unwrap();
            thread::sleep(Duration::from_secs(5));
        });
        run_testers!(server);
        client.join().unwrap();
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.send_to(b"x", "127.0.0.1:9703").unwrap();
    });
    let after = real_unix_ns();
    assert!(file.packets.len() > 4, "{}", file.packets.len());
    for p in &file.packets {
        let comment = p
            .comment
            .as_deref()
            .expect("every frame has a wall comment");
        let wall = wall_ns(comment);
        assert!(
            (before..=after).contains(&wall),
            "{comment} outside the run"
        );
        assert!(
            p.ns >= EPOCH_NS && p.ns < EPOCH_NS + 10_000_000_000,
            "{}",
            p.ns
        );
    }
    let last = file.packets.last().unwrap();
    assert!(
        last.ns >= EPOCH_NS + 5_000_000_000,
        "virtual stamp {}",
        last.ns
    );
    assert!(
        wall_ns(last.comment.as_deref().unwrap()) - before < 5_000_000_000,
        "wall time follows real time, not the sim's"
    );
    let plain = captured("wall_comment_off", || {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.send_to(b"x", "127.0.0.1:9704").unwrap();
    });
    assert!(!plain.packets.is_empty());
    assert!(plain.packets.iter().all(|p| p.comment.is_none()));
}

#[test]
fn tcp_latency_ack_stamped_at_arrival() {
    let file = captured("tcp_latency", || {
        set_tcp_policy("127.0.0.2:9506", |p| p.latency = 50 * MS);
        let server = connect_tester::<Bytes>("127.0.0.2:9506").until_after(200 * MS);
        let client = thread::spawn(|| {
            let mut s = TcpStream::connect("127.0.0.2:9506").unwrap();
            s.write_all(b"slow").unwrap();
            thread::sleep(100 * MS);
        });
        run_testers!(server);
        client.join().unwrap();
    });
    let segs = tcp(&file);
    let data = segs
        .iter()
        .position(|(f, _, _)| f.payload == b"slow")
        .unwrap();
    let ack = segs[data + 1..]
        .iter()
        .find(|(f, inbound, _)| *inbound && f.tcp_flags() == Some(ACK))
        .unwrap();
    assert_eq!(ack.2 - segs[data].2, 50_000_000);
    let stamps: Vec<u64> = file.packets.iter().map(|p| p.ns).collect();
    assert!(stamps.windows(2).all(|w| w[0] <= w[1]), "{stamps:?}");
}

/// A run with jittery, lossy links whose outcome depends on every draw and wake.
fn busy_run() -> Vec<String> {
    set_udp_policy("127.0.0.1:9800", |p| {
        p.jitter = 3 * MS;
        p.loss_rate = 0.2;
        p.duplicate_rate = 0.2;
    });
    set_tcp_policy("127.0.0.2:9801", |p| p.jitter = 2 * MS);
    let server = connect_tester::<Bytes>("127.0.0.2:9801")
        .then_action(|msg, _| TesterAction::Send(msg))
        .until_after(100 * MS);
    let rx = UdpSocket::bind("127.0.0.1:9800").unwrap();
    rx.set_read_timeout(Some(20 * MS)).unwrap();
    let tx = thread::spawn(|| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        for i in 0..10u8 {
            s.send_to(&[i], "127.0.0.1:9800").unwrap();
            thread::sleep(MS);
        }
    });
    let tcp = thread::spawn(|| {
        let mut s = TcpStream::connect("127.0.0.2:9801").unwrap();
        let mut out = Vec::new();
        for i in 0..5u8 {
            s.write_all(&[i; 3]).unwrap();
            let mut buf = [0u8; 3];
            s.read_exact(&mut buf).unwrap();
            out.push(format!("{buf:?}@{:?}", sched::now()));
        }
        out
    });
    let mut log = Vec::new();
    let mut buf = [0u8; 4];
    while let Ok((n, _)) = rx.recv_from(&mut buf) {
        log.push(format!("{:?}@{:?}", &buf[..n], sched::now()));
    }
    run_testers!(server);
    tx.join().unwrap();
    log.extend(tcp.join().unwrap());
    log.push(format!("end@{:?}", sched::now()));
    log
}

fn det(seed: u64) -> snare::SimBuilder {
    Sim::builder().deterministic().seed(seed)
}

#[test]
fn capture_does_not_perturb_the_run() {
    let plain = det(5).build();
    let without = plain.run(busy_run);
    let events_without = plain.recorded_events();
    drop(plain);
    let path = scratch("perturb");
    let sim = det(5).pcapng(&path).build();
    let with = sim.run(busy_run);
    assert_eq!(with, without);
    assert_eq!(sim.recorded_events(), events_without);
    drop(sim);
    assert!(!reader::read(&path).packets.is_empty());
}

fn masked(file: &reader::File) -> Vec<Vec<u8>> {
    file.packets
        .iter()
        .map(|p| {
            let mut data = p.data.clone();
            if reader::decode(&data).tcp_flags().is_some() {
                let l4 = 14 + 20;
                data[l4 + 4..l4 + 12].fill(0);
                data[l4 + 16..l4 + 18].fill(0);
            }
            data
        })
        .collect()
}

#[test]
fn deterministic_capture_is_byte_identical() {
    let run = |seed: u64, name: &str| {
        let path = scratch(name);
        det(seed).pcapng(&path).build().run(busy_run);
        snare::real(|| std::fs::read(&path)).unwrap()
    };
    let a = run(7, "det_a");
    let b = run(7, "det_b");
    assert!(a == b, "seed 7 twice writes the same bytes");
    let c = reader::parse(&run(8, "det_c"));
    let a = reader::parse(&a);
    let (ma, mc) = (masked(&a), masked(&c));
    let tcp_a: Vec<_> = ma
        .iter()
        .zip(&a.packets)
        .filter(|(_, p)| reader::decode(&p.data).tcp_flags().is_some())
        .map(|(m, _)| m)
        .collect();
    let tcp_c: Vec<_> = mc
        .iter()
        .zip(&c.packets)
        .filter(|(_, p)| reader::decode(&p.data).tcp_flags().is_some())
        .map(|(m, _)| m)
        .collect();
    assert_eq!(
        tcp_a, tcp_c,
        "another seed changes only the ISNs of the TCP frames"
    );
    let isn = |f: &reader::File| {
        f.packets
            .iter()
            .map(|p| reader::decode(&p.data))
            .find(|f| f.tcp_flags() == Some(SYN))
            .unwrap()
            .seq_ack()
            .0
    };
    assert_ne!(isn(&a), isn(&c));
}

#[test]
fn parallel_sims_get_independent_ports_and_files() {
    let ports: Vec<(u16, PathBuf)> = (0..2)
        .map(|i| {
            thread::spawn(move || {
                let path = scratch(&format!("parallel_{i}"));
                let sim = Sim::builder().pcapng(&path).build();
                sim.run(|| {
                    let server = connect_tester::<Bytes>("127.0.0.2:9507").until_after(10 * MS);
                    let client = thread::spawn(|| {
                        TcpStream::connect("127.0.0.2:9507")
                            .unwrap()
                            .local_addr()
                            .unwrap()
                    });
                    run_testers!(server);
                    client.join().unwrap();
                });
                drop(sim);
                let file = reader::read(&path);
                (reader::decode(&file.packets[0].data).sport, path)
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    assert_eq!(ports[0].0, 49152);
    assert_eq!(ports[1].0, 49152);
    assert_ne!(ports[0].1, ports[1].1);
}

#[test]
fn no_capture_by_default() {
    let sim = Sim::new();
    assert_eq!(sim.pcapng_path(), None);
}

#[test]
fn file_is_complete_after_sim_drop_even_with_leaked_threads() {
    let path = scratch("leaked");
    let sim = Sim::builder().pcapng(&path).build();
    sim.run(|| {
        set_tcp_policy("127.0.0.2:9508", |p| p.latency = Duration::from_secs(10));
        let server = connect_tester::<Bytes>("127.0.0.2:9508").until_after(MS);
        let client = thread::spawn(|| {
            let mut s = TcpStream::connect("127.0.0.2:9508").unwrap();
            s.write_all(b"late").unwrap();
            std::mem::forget(s);
        });
        client.join().unwrap();
        std::mem::forget(server);
    });
    drop(sim);
    let file = reader::read(&path);
    let segs = tcp(&file);
    let last = segs.last().unwrap();
    assert!(
        last.1 && last.0.tcp_flags() == Some(ACK),
        "the ACK due later is written"
    );
    let data = segs.iter().find(|(f, _, _)| f.payload == b"late").unwrap();
    assert_eq!(last.2 - data.2, 10_000_000_000);
}

#[test]
fn sut_listener_and_sut_client_both_outbound() {
    let file = captured("sut_both", || {
        let listener = TcpListener::bind("127.0.0.1:9509").unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 2];
            s.read_exact(&mut buf).unwrap();
            s.write_all(&buf).unwrap();
        });
        let mut c = TcpStream::connect("127.0.0.1:9509").unwrap();
        c.write_all(b"hi").unwrap();
        let mut buf = [0u8; 2];
        c.read_exact(&mut buf).unwrap();
        server.join().unwrap();
    });
    let segs = tcp(&file);
    assert!(segs.len() >= 7);
    assert!(segs.iter().all(|(_, inbound, _)| !inbound));
    reader::check_tcp_sequences(&frames(&file));
}

#[test]
fn executive_driven_stamps_follow_jumps() {
    let path = scratch("executive");
    let sim = Sim::builder().pcapng(&path).build();
    sim.run(|| {
        let exec = sched::attach(ExecutiveConfig::default()).unwrap();
        sched::mark_driver_thread();
        let sender = thread::spawn(|| {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            thread::sleep(5 * MS);
            s.send_to(b"a", "127.0.0.1:9703").unwrap();
        });
        loop {
            let q = exec.quiescence();
            if q.quiescent && q.next_deadline == Some(5 * MS) && exec.jump_to(20 * MS).is_ok() {
                break;
            }
            snare::real(|| thread::sleep(Duration::from_micros(200)));
        }
        loop {
            let q = exec.quiescence();
            if q.quiescent && exec.enter_timestamp_checked(30 * MS).is_ok() {
                break;
            }
            snare::real(|| thread::sleep(Duration::from_micros(200)));
        }
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.send_to(b"b", "127.0.0.1:9703").unwrap();
        exec.leave_timestamp(30 * MS);
        sender.join().unwrap();
    });
    drop(sim);
    let file = reader::read(&path);
    let stamps: Vec<u64> = file
        .packets
        .iter()
        .filter(|p| reader::decode(&p.data).l4 == L4::Udp)
        .map(|p| p.ns - EPOCH_NS)
        .collect();
    assert_eq!(stamps, [5_000_000, 30_000_000]);
}

#[test]
#[cfg(target_os = "linux")]
fn af_packet_frame_written_verbatim_on_named_iface() {
    let file = captured("af_packet", || {
        snare::add_nic(NicSpec::new("sneth9").index(9).mtu(1500)).unwrap();
        let fd = unsafe {
            let fd = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                i32::from(0x88A4u16.to_be()),
            );
            let mut sll: libc::sockaddr_ll = std::mem::zeroed();
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_protocol = 0x88A4u16.to_be();
            sll.sll_ifindex = 9;
            let rc = libc::bind(
                fd,
                (&sll as *const libc::sockaddr_ll).cast(),
                size_of::<libc::sockaddr_ll>() as u32,
            );
            assert_eq!(rc, 0);
            fd
        };
        let frame: Vec<u8> = (0..60).map(|i| i as u8).collect();
        let n = unsafe { libc::write(fd, frame.as_ptr().cast(), frame.len()) };
        assert_eq!(n, 60);
        unsafe { libc::close(fd) };
    });
    assert_eq!(file.ifaces, ["sneth9"]);
    assert_eq!(
        file.packets[0].data,
        (0..60).map(|i| i as u8).collect::<Vec<u8>>()
    );
    assert!(!file.packets[0].inbound);
}

#[test]
#[cfg(target_os = "macos")]
fn bpf_frame_written_verbatim_on_biocsetif_iface() {
    const BIOCSETIF: libc::c_ulong = 0x8020_426c;
    let file = captured("bpf", || {
        snare::add_nic(NicSpec::new("en7").index(7).mtu(1500)).unwrap();
        let path = std::ffi::CString::new("/dev/bpf0").unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
        assert!(fd >= 0);
        let mut ifr = [0u8; 32];
        ifr[..3].copy_from_slice(b"en7");
        assert_eq!(unsafe { libc::ioctl(fd, BIOCSETIF, ifr.as_mut_ptr()) }, 0);
        let frame: Vec<u8> = (0..60).map(|i| i as u8).collect();
        let n = unsafe { libc::write(fd, frame.as_ptr().cast(), frame.len()) };
        assert_eq!(n, 60);
        unsafe { libc::close(fd) };
    });
    assert_eq!(file.ifaces, ["en7"]);
    assert_eq!(
        file.packets[0].data,
        (0..60).map(|i| i as u8).collect::<Vec<u8>>()
    );
}
