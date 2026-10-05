#![cfg(unix)]

use std::io::ErrorKind;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use snare::Sim;

fn receive(socket: &UdpSocket, expected: &[u8]) {
    let mut data = [0u8; 16];
    assert_eq!(socket.recv(&mut data).unwrap(), expected.len());
    assert_eq!(&data[..expected.len()], expected);
}

fn empty(socket: &UdpSocket) {
    assert_eq!(
        socket.recv(&mut [0u8; 16]).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
}

#[test]
fn shared_port_delivery_preserves_exact_wildcard_and_family_selection() {
    for deterministic in [false, true] {
        let builder = Sim::builder();
        let sim = if deterministic {
            builder.deterministic()
        } else {
            builder
        }
        .build();
        sim.run(|| {
            let unrelated: Vec<_> = (20_000..20_128)
                .map(|port| UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap())
                .collect();
            let wildcard = UdpSocket::bind("0.0.0.0:9400").unwrap();
            let exact = UdpSocket::bind("127.0.0.1:9400").unwrap();
            let other = UdpSocket::bind("127.0.0.2:9400").unwrap();
            let ipv6 = UdpSocket::bind("[::1]:9400").unwrap();
            let other_port = UdpSocket::bind("0.0.0.0:9401").unwrap();
            let sender = UdpSocket::bind("127.0.0.1:9500").unwrap();
            for socket in [&wildcard, &exact, &other, &ipv6, &other_port]
                .into_iter()
                .chain(unrelated.iter())
            {
                socket.set_nonblocking(true).unwrap();
            }
            sender.send_to(b"exact", "127.0.0.1:9400").unwrap();
            receive(&exact, b"exact");
            empty(&wildcard);
            empty(&other);
            empty(&ipv6);
            sender.set_broadcast(true).unwrap();
            sender.send_to(b"all", "255.255.255.255:9400").unwrap();
            for socket in [&wildcard, &exact, &other] {
                receive(socket, b"all");
            }
            empty(&ipv6);
            empty(&other_port);
            drop(wildcard);
            let alias = exact.try_clone().unwrap();
            drop(exact);
            sender.send_to(b"alias", "127.0.0.1:9400").unwrap();
            receive(&alias, b"alias");
            drop(alias);
            let replacement = UdpSocket::bind("127.0.0.1:9400").unwrap();
            sender.send_to(b"rebound", "127.0.0.1:9400").unwrap();
            receive(&replacement, b"rebound");
            for socket in unrelated {
                empty(&socket);
            }
        });
    }
}

fn delivery_run(
    shared_port: bool,
    wildcard: bool,
    deterministic: bool,
    faults: bool,
) -> (Vec<u8>, snare::NicCounters) {
    let mut builder = Sim::builder().seed(19);
    if deterministic {
        builder = builder.deterministic();
    }
    builder.build().run(|| {
        let bound = if wildcard {
            "0.0.0.0:9600"
        } else {
            "127.0.0.1:9600"
        };
        let receiver = UdpSocket::bind(bound).unwrap();
        let extra = shared_port.then(|| UdpSocket::bind("127.0.0.2:9600").unwrap());
        let sender = UdpSocket::bind("127.0.0.1:9601").unwrap();
        receiver.set_nonblocking(true).unwrap();
        if faults {
            snare::set_udp_policy(receiver.local_addr().unwrap(), |policy| {
                policy.loss_rate = 0.2;
                policy.duplicate_rate = 0.4;
                policy.latency = Duration::from_millis(1);
                policy.jitter = Duration::from_millis(2);
            });
            snare::quiesce(
                sender.local_addr().unwrap(),
                Duration::from_millis(4),
                snare::Direction::Send,
            );
            snare::quiesce(
                "127.0.0.1:9600",
                Duration::from_millis(7),
                snare::Direction::Receive,
            );
            snare::quiesce(bound, Duration::from_millis(5), snare::Direction::Receive);
        }
        for value in 0..48u8 {
            sender.send_to(&[value], "127.0.0.1:9600").unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
        let mut received = Vec::new();
        loop {
            let mut data = [0u8; 1];
            match receiver.recv(&mut data) {
                Ok(1) => received.push(data[0]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                result => panic!("unexpected receive {result:?}"),
            }
        }
        if let Some(extra) = extra {
            extra.set_nonblocking(true).unwrap();
            empty(&extra);
        }
        let loopback = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let counters = snare::nic_counters(loopback).unwrap();
        assert_eq!(counters.tx_packets, 48);
        assert_eq!(counters.rx_packets, received.len() as u64);
        (received, counters)
    })
}

#[test]
fn singleton_and_shared_port_routes_preserve_fault_draws_holds_and_counters() {
    for deterministic in [false, true] {
        for wildcard in [false, true] {
            for faults in [false, true] {
                let single = delivery_run(false, wildcard, deterministic, faults);
                assert_eq!(single, delivery_run(true, wildcard, deterministic, faults));
                assert!(!single.0.is_empty());
                if !faults {
                    assert_eq!(single.0, (0..48u8).collect::<Vec<_>>());
                }
            }
        }
    }
}
