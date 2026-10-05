#![cfg(unix)]
//! Behaviour pins for packet capture ahead of a performance pass: one fixed, deterministic scenario
//! on an Ethernet interface — a datagram to a tester and one to a port nobody holds (its ICMP port
//! unreachable), a TCP echo of a write three segments long under link latency, a half-close from
//! each side, a refused connect — writes, after the section header, exactly the bytes of the
//! golden `edge_net_pcapng.txt` (a per-packet summary, then every byte in hex), the same on every
//! host. The same seed writes the same file twice, and capturing changes nothing the run sees.

#[path = "support/golden.rs"]
mod golden;
#[path = "support/pcapng_reader.rs"]
mod reader;

use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::time::Duration;

use snare::{
    Bytes, IpNet, NicSpec, RecordedEntry, Sim, TcpPolicy, TesterAction, UdpPolicy, connect_tester,
    run_testers, set_tcp_policy, set_udp_policy, udp_tester,
};

const MS: Duration = Duration::from_millis(1);

fn scratch(name: &str) -> PathBuf {
    snare::real(|| {
        let dir = std::env::temp_dir().join(format!("snare-edge-pcapng-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(format!("{name}.pcapng"))
    })
}

fn sim(capture: Option<&PathBuf>) -> Sim {
    let mut builder = Sim::builder().deterministic().seed(0xC0FFEE).nic(
        NicSpec::new("eth0")
            .address("10.9.0.1/24".parse::<IpNet>().unwrap())
            .mtu(1500)
            .mac([0x02, 0, 0, 0, 0, 0x01]),
    );
    if let Some(path) = capture {
        builder = builder.pcapng(path);
    }
    builder.build()
}

/// What the code under test saw: the echo, the refused connect's error kind and the ICMP error the
/// second datagram drew.
fn scenario() -> (Vec<u8>, std::io::ErrorKind, Option<i32>) {
    set_tcp_policy("10.9.0.2:5000", |p: &mut TcpPolicy| p.latency = MS);
    set_udp_policy("10.9.0.2:6000", |p: &mut UdpPolicy| p.latency = 2 * MS);
    let echo = connect_tester::<Bytes>("10.9.0.2:5000")
        .then_action(|msg, _| TesterAction::Send(msg))
        .until_after(40 * MS);
    let sink = udp_tester::<Bytes>("10.9.0.2:6000").until_after(40 * MS);
    let client = std::thread::spawn(|| {
        let u = UdpSocket::bind("10.9.0.1:0").unwrap();
        u.connect("10.9.0.2:6000").unwrap();
        u.send(&[0xAB; 100]).unwrap();
        let v = UdpSocket::bind("10.9.0.1:0").unwrap();
        v.connect("10.9.0.2:6001").unwrap();
        v.send(b"nobody").unwrap();
        std::thread::sleep(MS);
        let icmp = v.send(b"again").err().and_then(|e| e.raw_os_error());
        let payload: Vec<u8> = (0..3000u32).map(|i| (i * 7 % 251) as u8).collect();
        let mut s = TcpStream::connect("10.9.0.2:5000").unwrap();
        s.write_all(&payload).unwrap();
        let mut back = vec![0u8; payload.len()];
        s.read_exact(&mut back).unwrap();
        s.shutdown(Shutdown::Write).unwrap();
        let mut rest = Vec::new();
        s.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
        let refused = TcpStream::connect("10.9.0.2:5001").unwrap_err().kind();
        (back, refused, icmp)
    });
    run_testers!(echo, sink);
    client.join().unwrap()
}

fn captured(name: &str) -> (Vec<u8>, Vec<RecordedEntry>) {
    let path = scratch(name);
    let sim = sim(Some(&path));
    sim.run(scenario);
    let events = sim.recorded_events();
    drop(sim);
    (snare::real(|| std::fs::read(&path)).unwrap(), events)
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn flag_names(flags: u8) -> String {
    [
        (reader::SYN, "S"),
        (reader::FIN, "F"),
        (reader::RST, "R"),
        (reader::PSH, "P"),
        (reader::ACK, "."),
    ]
    .iter()
    .filter(|(bit, _)| flags & bit != 0)
    .map(|(_, name)| *name)
    .collect()
}

fn summary(file: &reader::File) -> String {
    let mut out = String::new();
    let start = file.packets.first().map_or(0, |p| p.ns);
    for p in &file.packets {
        let f = reader::decode(&p.data);
        let what = match &f.l4 {
            reader::L4::Tcp {
                seq,
                ack,
                flags,
                mss,
            } => format!(
                "tcp [{}] seq {seq} ack {ack} mss {mss:?}",
                flag_names(*flags)
            ),
            reader::L4::Udp => "udp".to_string(),
            reader::L4::Icmp { kind, code, .. } => format!("icmp {kind}/{code}"),
            reader::L4::Other(n) => format!("proto {n}"),
        };
        out.push_str(&format!(
            "+{:>9}ns {} {} {}:{} > {}:{} id {} ttl {} {} len {}\n",
            p.ns - start,
            p.iface,
            if p.inbound { "in " } else { "out" },
            f.src,
            f.sport,
            f.dst,
            f.dport,
            f.ip_id,
            f.ttl,
            what,
            f.payload.len()
        ));
    }
    out
}

#[test]
fn a_fixed_scenario_writes_the_golden_capture() {
    let (bytes, _) = captured("golden");
    let (again, _) = captured("golden-again");
    assert_eq!(bytes, again, "the same seed writes the same bytes");

    let shb_len = le32(&bytes, 4) as usize;
    assert_eq!(le32(&bytes, 0), 0x0A0D_0D0A);
    assert_eq!(le32(&bytes, shb_len - 4) as usize, shb_len);
    let file = reader::parse(&bytes);
    assert_eq!(file.os, std::env::consts::OS);
    assert_eq!(file.appl, concat!("snare ", env!("CARGO_PKG_VERSION")));
    assert_eq!(file.ifaces, ["eth0"]);
    assert!(file.packets.iter().all(|p| p.comment.is_none()));
    reader::check_tcp_sequences(
        &file
            .packets
            .iter()
            .map(|p| reader::decode(&p.data))
            .collect::<Vec<_>>(),
    );
    let first_ns = file.packets.first().map(|p| p.ns);
    let text = format!(
        "first stamp {first_ns:?}\n{}\n{}",
        summary(&file),
        golden::hex(&bytes[shb_len..])
    );
    golden::check_text("edge_net_pcapng.txt", &text);
}

#[test]
fn capturing_changes_nothing_the_run_sees() {
    let plain = sim(None);
    let seen = plain.run(scenario);
    let plain_events = plain.recorded_events();
    drop(plain);
    let path = scratch("observer");
    let capturing = sim(Some(&path));
    let seen_capturing = capturing.run(scenario);
    assert_eq!(seen, seen_capturing);
    assert_eq!(plain_events, capturing.recorded_events());
    assert_eq!(seen.1, std::io::ErrorKind::ConnectionRefused);
    assert_eq!(seen.2, Some(libc::ECONNREFUSED));
    assert_eq!(seen.0.len(), 3000);
}

#[test]
fn every_frame_on_the_interface_carries_its_macs() {
    let (bytes, _) = captured("macs");
    let file = reader::parse(&bytes);
    let host: IpAddr = "10.9.0.1".parse().unwrap();
    for p in &file.packets {
        let f = reader::decode(&p.data);
        let (ours, theirs) = if f.src == host {
            (f.src_mac, f.dst_mac)
        } else {
            (f.dst_mac, f.src_mac)
        };
        assert_eq!(ours, [0x02, 0, 0, 0, 0, 0x01], "{f:?}");
        assert_eq!(
            theirs[0] & 0x03,
            0x02,
            "locally administered unicast: {f:?}"
        );
    }
}
