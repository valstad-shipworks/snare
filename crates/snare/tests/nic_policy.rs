//! An interface's link policy: latency, jitter, loss and duplication on the traffic that crosses
//! it, never on host-local traffic, drawn from the sim's seed.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use snare::{IpNet, NicPolicy, NicSpec, Sim, set_udp_policy};

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn sim(policy: NicPolicy, seed: u64) -> Sim {
    Sim::builder()
        .seed(seed)
        .nic(
            NicSpec::new("eth0")
                .index(4)
                .address(net("10.0.0.1/24"))
                .station(ip("10.0.0.2"))
                .policy(policy),
        )
        .build()
}

fn drain(sock: &UdpSocket) -> Vec<u8> {
    sock.set_nonblocking(true).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 8];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock => return out,
            Err(e) => panic!("recv failed: {e}"),
        }
    }
}

#[test]
fn latency_applies_to_station_traffic_only() {
    let latency = Duration::from_millis(5);
    let policy = NicPolicy {
        latency,
        ..NicPolicy::default()
    };
    sim(policy, 0).run(|| {
        let host = UdpSocket::bind("10.0.0.1:7000").unwrap();
        let station = UdpSocket::bind("10.0.0.2:7000").unwrap();
        let local = UdpSocket::bind("127.0.0.1:0").unwrap();
        local.send_to(b"l", "10.0.0.1:7000").unwrap();
        assert_eq!(drain(&host), b"l", "host-local traffic never crosses eth0");
        host.send_to(b"s", "10.0.0.2:7000").unwrap();
        assert!(drain(&station).is_empty(), "still in flight");
        station.set_nonblocking(false).unwrap();
        let t0 = Instant::now();
        let mut buf = [0u8; 4];
        station.recv_from(&mut buf).unwrap();
        assert!(t0.elapsed() >= latency - Duration::from_micros(50));
        station.send_to(b"h", "10.0.0.1:7000").unwrap();
        assert!(drain(&host).is_empty(), "inbound takes the latency too");
        std::thread::sleep(latency);
        assert_eq!(drain(&host), b"h");
    });
}

#[test]
fn jitter_reorders_datagrams_but_not_tcp() {
    let policy = NicPolicy {
        jitter: Duration::from_millis(10),
        ..NicPolicy::default()
    };
    sim(policy, 7).run(|| {
        let station = UdpSocket::bind("10.0.0.2:7100").unwrap();
        let host = UdpSocket::bind("10.0.0.1:0").unwrap();
        for i in 0..32u8 {
            host.send_to(&[i], "10.0.0.2:7100").unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
        let got = drain(&station);
        let mut sorted = got.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            (0..32).collect::<Vec<u8>>(),
            "every datagram arrives"
        );
        assert_ne!(got, sorted, "jitter reorders datagrams");

        let listener = TcpListener::bind("10.0.0.2:7101").unwrap();
        let mut client = TcpStream::connect("10.0.0.2:7101").unwrap();
        let (mut server, _) = listener.accept().unwrap();
        for i in 0..32u8 {
            client.write_all(&[i]).unwrap();
        }
        let mut buf = [0u8; 32];
        server.read_exact(&mut buf).unwrap();
        assert_eq!(
            buf.to_vec(),
            (0..32).collect::<Vec<u8>>(),
            "TCP stays in order"
        );
    });
}

fn lossy_run(seed: u64) -> Vec<u8> {
    let policy = NicPolicy {
        loss_rate: 0.3,
        duplicate_rate: 0.3,
        ..NicPolicy::default()
    };
    sim(policy, seed).run(|| {
        let station = UdpSocket::bind("10.0.0.2:7200").unwrap();
        let host = UdpSocket::bind("10.0.0.1:0").unwrap();
        for i in 0..64u8 {
            host.send_to(&[i], "10.0.0.2:7200").unwrap();
        }
        drain(&station)
    })
}

#[test]
fn loss_and_duplicate_rates_replay_with_seed() {
    let first = lossy_run(11);
    assert_eq!(first, lossy_run(11), "the same seed replays");
    assert_ne!(first, lossy_run(12), "another seed explores another run");
    let lost = (0..64u8).filter(|i| !first.contains(i)).count();
    let doubled = (0..64u8)
        .filter(|i| first.iter().filter(|b| *b == i).count() == 2)
        .count();
    assert!(lost > 5 && doubled > 5, "lost {lost}, doubled {doubled}");
}

#[test]
fn interface_and_address_duplication_deliver_all_four_copies() {
    for deterministic in [false, true] {
        let mut builder = Sim::builder().seed(7).nic(
            NicSpec::new("eth0")
                .index(4)
                .address(net("10.0.0.1/24"))
                .station(ip("10.0.0.2"))
                .policy(NicPolicy {
                    latency: Duration::from_millis(1),
                    duplicate_rate: 1.0,
                    ..NicPolicy::default()
                }),
        );
        if deterministic {
            builder = builder.deterministic();
        }
        builder.build().run(|| {
            let station = UdpSocket::bind("10.0.0.2:7201").unwrap();
            let host = UdpSocket::bind("10.0.0.1:0").unwrap();
            set_udp_policy(station.local_addr().unwrap(), |policy| {
                policy.latency = Duration::from_millis(1);
                policy.duplicate_rate = 1.0;
            });
            host.send_to(b"x", station.local_addr().unwrap()).unwrap();
            assert!(drain(&station).is_empty());
            std::thread::sleep(Duration::from_millis(3));
            assert_eq!(drain(&station), b"xxxx");
        });
    }
}

#[test]
fn tcp_takes_nic_latency_in_order() {
    let latency = Duration::from_millis(20);
    let policy = NicPolicy {
        latency,
        ..NicPolicy::default()
    };
    sim(policy, 0).run(|| {
        let listener = TcpListener::bind("10.0.0.2:7300").unwrap();
        let mut client = TcpStream::connect("10.0.0.2:7300").unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let t0 = Instant::now();
        client.write_all(b"one").unwrap();
        client.write_all(b"two").unwrap();
        let mut buf = [0u8; 6];
        server.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"onetwo");
        assert!(t0.elapsed() >= latency);
    });
}

fn loopback_losses(extra_nic: bool) -> Vec<u8> {
    let mut builder = Sim::builder().seed(5);
    if extra_nic {
        builder = builder.nic(NicSpec::new("eth9").index(9));
    }
    builder.build().run(|| {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        set_udp_policy(rx.local_addr().unwrap(), |p| {
            p.loss_rate = 0.5;
            p.jitter = Duration::from_micros(300);
        });
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        for i in 0..48u8 {
            tx.send_to(&[i], rx.local_addr().unwrap()).unwrap();
        }
        std::thread::sleep(Duration::from_millis(1));
        drain(&rx)
    })
}

#[test]
fn no_nic_policy_keeps_existing_draw_order() {
    let plain = loopback_losses(false);
    assert_eq!(plain, loopback_losses(true));
    assert!(!plain.is_empty() && plain.len() < 48);
}
