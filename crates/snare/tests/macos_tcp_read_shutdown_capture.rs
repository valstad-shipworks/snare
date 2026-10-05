#![cfg(target_os = "macos")]

#[path = "support/pcapng_reader.rs"]
mod reader;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

use reader::{ACK, FIN, PSH, RST, SYN};
use snare::{NicSpec, Sim, set_tcp_policy};

#[test]
fn incoming_data_after_read_shutdown_captures_a_reset_without_an_ack() {
    for deterministic in [false, true] {
        for both in [false, true] {
            for in_flight in [false, true] {
                let path = snare::real(|| {
                    std::env::temp_dir().join(format!(
                        "snare-read-shutdown-{}-{deterministic}-{both}-{in_flight}.pcapng",
                        std::process::id()
                    ))
                });
                let builder = Sim::builder().pcapng(&path);
                let sim = if deterministic {
                    builder.deterministic().build()
                } else {
                    builder.build()
                };
                sim.run(|| {
                    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                    let address = listener.local_addr().unwrap();
                    set_tcp_policy(address, |policy| {
                        policy.latency = Duration::from_millis(10);
                    });
                    let mut client = TcpStream::connect(address).unwrap();
                    let (mut server, _) = listener.accept().unwrap();
                    if both {
                        client.shutdown(Shutdown::Read).unwrap();
                    }
                    if in_flight {
                        client.write_all(b"discarded").unwrap();
                        server.shutdown(Shutdown::Read).unwrap();
                    } else {
                        server.shutdown(Shutdown::Read).unwrap();
                        client.write_all(b"discarded").unwrap();
                    }
                    std::thread::sleep(Duration::from_millis(100));
                    if in_flight {
                        let unrelated = UdpSocket::bind("127.0.0.1:0").unwrap();
                        unrelated
                            .send_to(b"other", unrelated.local_addr().unwrap())
                            .unwrap();
                    }
                    assert_eq!(
                        server.write(b"reply").unwrap_err().raw_os_error(),
                        Some(libc::EPIPE)
                    );
                    let mut bytes = [0; 16];
                    assert_eq!(
                        client.read(&mut bytes).unwrap_err().raw_os_error(),
                        Some(libc::ECONNRESET)
                    );
                    assert_eq!(client.read(&mut bytes).unwrap(), 0);
                    assert_eq!(server.read(&mut bytes).unwrap(), 0);
                });
                drop(sim);
                let capture = snare::real(|| reader::read(&path));
                let frames: Vec<_> = capture
                    .packets
                    .iter()
                    .map(|packet| (reader::decode(&packet.data), packet.ns))
                    .filter(|(frame, _)| frame.tcp_flags().is_some())
                    .collect();
                assert_eq!(
                    frames
                        .iter()
                        .map(|(frame, _)| frame.tcp_flags().unwrap())
                        .collect::<Vec<_>>(),
                    [SYN, SYN | ACK, ACK, PSH | ACK, RST | ACK]
                );
                let (data, sent_at) = &frames[3];
                let (reset, reset_at) = &frames[4];
                assert_eq!(data.payload, b"discarded");
                assert_eq!((reset.src, reset.sport), (data.dst, data.dport));
                assert_eq!((reset.dst, reset.dport), (data.src, data.sport));
                assert_eq!(reset_at - sent_at, 10_000_000);
                assert!(
                    frames
                        .iter()
                        .all(|(frame, _)| frame.tcp_flags().unwrap() & FIN == 0)
                );
                reader::check_tcp_sequences(
                    &frames
                        .iter()
                        .map(|(frame, _)| frame.clone())
                        .collect::<Vec<_>>(),
                );
                snare::real(|| std::fs::remove_file(path)).unwrap();
            }
        }
    }
}

#[test]
fn frames_sent_before_the_peer_receives_a_reset_remain_in_the_capture() {
    for deterministic in [false, true] {
        let path = snare::real(|| {
            std::env::temp_dir().join(format!(
                "snare-read-shutdown-phases-{}-{deterministic}.pcapng",
                std::process::id()
            ))
        });
        let builder = Sim::builder().pcapng(&path);
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        sim.run(|| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            set_tcp_policy(address, |policy| policy.latency = Duration::from_millis(10));
            let mut client = TcpStream::connect(address).unwrap();
            let (mut server, _) = listener.accept().unwrap();
            client.write_all(b"a").unwrap();
            server.shutdown(Shutdown::Read).unwrap();
            std::thread::sleep(Duration::from_millis(5));
            server.write_all(b"b").unwrap();
            std::thread::sleep(Duration::from_millis(10));
            let mut byte = [0];
            client.read_exact(&mut byte).unwrap();
            assert_eq!(byte, *b"b");
            client.write_all(b"late").unwrap();
            std::thread::sleep(Duration::from_millis(10));
            assert_eq!(
                client.read(&mut byte).unwrap_err().raw_os_error(),
                Some(libc::ECONNRESET)
            );
            assert_eq!(
                server.write(b"closed").unwrap_err().raw_os_error(),
                Some(libc::EPIPE)
            );
        });
        drop(sim);
        let capture = snare::real(|| reader::read(&path));
        let frames: Vec<_> = capture
            .packets
            .iter()
            .map(|packet| (reader::decode(&packet.data), packet.ns))
            .collect();
        assert_eq!(
            frames
                .iter()
                .map(|(frame, _)| frame.tcp_flags().unwrap())
                .collect::<Vec<_>>(),
            [
                SYN,
                SYN | ACK,
                ACK,
                PSH | ACK,
                PSH | ACK,
                RST | ACK,
                ACK,
                PSH | ACK
            ]
        );
        let (a, a_at) = &frames[3];
        let (b, b_at) = &frames[4];
        let (reset, reset_at) = &frames[5];
        let (ack, ack_at) = &frames[6];
        let (late, late_at) = &frames[7];
        assert_eq!(
            (&a.payload[..], &b.payload[..], &late.payload[..]),
            (&b"a"[..], &b"b"[..], &b"late"[..])
        );
        assert_eq!((reset.src, reset.sport), (a.dst, a.dport));
        assert_eq!((ack.src, ack.sport), (b.dst, b.dport));
        assert_eq!(reset_at - a_at, 10_000_000);
        assert_eq!(ack_at - b_at, 10_000_000);
        assert!(*ack_at > *reset_at && *ack_at < *reset_at + 10_000_000);
        assert!(*late_at > *reset_at && *late_at < *reset_at + 10_000_000);
        reader::check_tcp_sequences(
            &frames
                .iter()
                .map(|(frame, _)| frame.clone())
                .collect::<Vec<_>>(),
        );
        snare::real(|| std::fs::remove_file(path)).unwrap();
    }
}

#[test]
fn finishing_an_uninspected_connection_resolves_its_due_reset_reservation() {
    for deterministic in [false, true] {
        for held in [FinishHold::None, FinishHold::Receive, FinishHold::Carrier] {
            finish_uninspected(deterministic, held);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FinishHold {
    None,
    Receive,
    Carrier,
}

fn finish_uninspected(deterministic: bool, held: FinishHold) {
    let path = snare::real(|| {
        std::env::temp_dir().join(format!(
            "snare-read-shutdown-finish-{}-{deterministic}-{held:?}.pcapng",
            std::process::id()
        ))
    });
    let mut builder = Sim::builder().pcapng(&path);
    if held == FinishHold::Carrier {
        builder = builder.nic(
            NicSpec::new("eth0")
                .index(4)
                .address("10.0.0.1/24".parse::<snare::IpNet>().unwrap())
                .station("10.0.0.2".parse::<std::net::IpAddr>().unwrap()),
        );
    }
    let sim = if deterministic {
        builder.deterministic().build()
    } else {
        builder.build()
    };
    let descriptors = sim.run(|| {
        let listener = TcpListener::bind(if held == FinishHold::Carrier {
            "10.0.0.2:9400"
        } else {
            "127.0.0.1:0"
        })
        .unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        let (server, _) = listener.accept().unwrap();
        set_tcp_policy(address, |policy| policy.latency = Duration::from_millis(10));
        if held != FinishHold::None {
            sim.pause_time();
        }
        client.write_all(b"uninspected").unwrap();
        server.shutdown(Shutdown::Read).unwrap();
        if held == FinishHold::Carrier {
            snare::schedule_link("eth0", Duration::from_millis(5), false).unwrap();
            snare::schedule_link("eth0", Duration::from_millis(30), true).unwrap();
            sim.advance_time(Duration::from_millis(5));
        } else if held == FinishHold::Receive {
            sim.advance_time(Duration::from_millis(5));
            sim.quiesce(
                address,
                Duration::from_millis(25),
                snare::Direction::Receive,
            );
        }
        let descriptors = [client.as_raw_fd(), server.as_raw_fd()];
        std::mem::forget(client);
        std::mem::forget(server);
        if held != FinishHold::None {
            sim.advance_time(Duration::from_millis(95));
        } else {
            std::thread::sleep(Duration::from_millis(100));
        }
        let unrelated = UdpSocket::bind("127.0.0.1:0").unwrap();
        unrelated
            .send_to(b"other", unrelated.local_addr().unwrap())
            .unwrap();
        descriptors
    });
    drop(sim);
    snare::real(|| {
        for descriptor in descriptors {
            assert_eq!(unsafe { libc::close(descriptor) }, 0);
        }
    });
    let capture = snare::real(|| reader::read(&path));
    let frames: Vec<_> = capture
        .packets
        .iter()
        .map(|packet| (reader::decode(&packet.data), packet.ns))
        .collect();
    assert_eq!(
        frames
            .iter()
            .map(|(frame, _)| frame.tcp_flags().unwrap_or(0))
            .collect::<Vec<_>>(),
        [SYN, SYN | ACK, ACK, PSH | ACK, RST | ACK, 0]
    );
    assert_eq!(
        frames[4].1 - frames[3].1,
        if held == FinishHold::None {
            10_000_000
        } else {
            30_000_000
        }
    );
    assert!(frames[5].1 > frames[4].1);
    assert_eq!(
        (frames[4].0.src, frames[4].0.sport),
        (frames[3].0.dst, frames[3].0.dport)
    );
    assert_eq!(frames[3].0.payload, b"uninspected");
    assert_eq!(frames[5].0.payload, b"other");
    reader::check_tcp_sequences(
        &frames
            .iter()
            .map(|(frame, _)| frame.clone())
            .collect::<Vec<_>>(),
    );
    snare::real(|| std::fs::remove_file(path)).unwrap();
}

#[test]
fn receive_holds_preserve_reset_timestamps_and_frames_before_peer_close() {
    for deterministic in [false, true] {
        for hold_receiver in [false, true] {
            let path = snare::real(|| {
                std::env::temp_dir().join(format!(
                    "snare-read-shutdown-hold-{}-{deterministic}-{hold_receiver}.pcapng",
                    std::process::id()
                ))
            });
            let builder = Sim::builder().pcapng(&path);
            let sim = if deterministic {
                builder.deterministic().build()
            } else {
                builder.build()
            };
            sim.run(|| {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let address = listener.local_addr().unwrap();
                set_tcp_policy(address, |policy| {
                    policy.latency = Duration::from_millis(10);
                });
                let mut client = TcpStream::connect(address).unwrap();
                let (mut server, _) = listener.accept().unwrap();
                sim.pause_time();
                client.write_all(b"held").unwrap();
                server.shutdown(Shutdown::Read).unwrap();
                sim.advance_time(Duration::from_millis(5));
                let (held_address, span) = if hold_receiver {
                    (address, Duration::from_millis(25))
                } else {
                    (client.local_addr().unwrap(), Duration::from_millis(45))
                };
                sim.quiesce(held_address, span, snare::Direction::Receive);
                sim.advance_time(Duration::from_millis(15));
                if hold_receiver {
                    server.write_all(b"before-close").unwrap();
                } else {
                    assert_eq!(
                        server.write(b"closed").unwrap_err().raw_os_error(),
                        Some(libc::EPIPE)
                    );
                }
                sim.advance_time(Duration::from_millis(15));
                client.write_all(b"before-reset-receipt").unwrap();
                sim.advance_time(Duration::from_millis(65));
                let unrelated = UdpSocket::bind("127.0.0.1:0").unwrap();
                unrelated
                    .send_to(b"after-close", unrelated.local_addr().unwrap())
                    .unwrap();
                let mut bytes = [0; 32];
                if hold_receiver {
                    client.read_exact(&mut bytes[..12]).unwrap();
                    assert_eq!(&bytes[..12], b"before-close");
                }
                assert_eq!(
                    client.read(&mut bytes).unwrap_err().raw_os_error(),
                    Some(libc::ECONNRESET)
                );
                assert_eq!(client.read(&mut bytes).unwrap(), 0);
                assert_eq!(
                    server.write(b"closed").unwrap_err().raw_os_error(),
                    Some(libc::EPIPE)
                );
            });
            drop(sim);
            let capture = snare::real(|| reader::read(&path));
            let frames: Vec<_> = capture
                .packets
                .iter()
                .map(|packet| (reader::decode(&packet.data), packet.ns))
                .collect();
            let (held, held_at) = frames
                .iter()
                .find(|(frame, _)| frame.payload == b"held")
                .unwrap();
            let resets: Vec<_> = frames
                .iter()
                .filter(|(frame, _)| frame.tcp_flags() == Some(RST | ACK))
                .collect();
            assert_eq!(resets.len(), 1);
            let (reset, reset_at) = resets[0];
            assert_eq!((reset.src, reset.sport), (held.dst, held.dport));
            assert_eq!(
                reset_at - held_at,
                if hold_receiver {
                    30_000_000
                } else {
                    10_000_000
                }
            );
            let (_, late_at) = frames
                .iter()
                .find(|(frame, _)| frame.payload == b"before-reset-receipt")
                .unwrap();
            assert_eq!(late_at - held_at, 35_000_000);
            assert!(late_at > reset_at);
            let (_, unrelated_at) = frames
                .iter()
                .find(|(frame, _)| frame.payload == b"after-close")
                .unwrap();
            assert!(unrelated_at > late_at);
            if hold_receiver {
                let (reply, reply_at) = frames
                    .iter()
                    .find(|(frame, _)| frame.payload == b"before-close")
                    .unwrap();
                assert_eq!(reply_at - held_at, 20_000_000);
                let (_, ack_at) = frames
                    .iter()
                    .find(|(frame, at)| {
                        frame.tcp_flags() == Some(ACK)
                            && (frame.src, frame.sport) == (reply.dst, reply.dport)
                            && at > reply_at
                    })
                    .unwrap();
                assert_eq!(ack_at - reply_at, 10_000_000);
            }
            assert!(
                frames
                    .iter()
                    .all(|(frame, _)| { frame.tcp_flags().is_none_or(|flags| flags & FIN == 0) })
            );
            reader::check_tcp_sequences(
                &frames
                    .iter()
                    .filter(|(frame, _)| frame.tcp_flags().is_some())
                    .map(|(frame, _)| frame.clone())
                    .collect::<Vec<_>>(),
            );
            snare::real(|| std::fs::remove_file(path)).unwrap();
        }
    }
}
