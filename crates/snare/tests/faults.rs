//! Faults a test can inject — a reset connection, a peer that goes silent, a lossy, duplicating,
//! size-limited or stalled UDP link — and seeded randomness that makes a run replay exactly.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

use snare::{
    Bytes, Line, Sim, TesterAction, connect_tester, run_testers, set_tcp_policy, set_udp_policy,
    udp_tester,
};

#[test]
fn a_reset_connection_fails_the_next_read() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.6:7100")
            .then_action(|_, _| TesterAction::Reset)
            .until_after(Duration::from_secs(1));

        let client = std::thread::spawn(|| {
            let mut stream = TcpStream::connect("127.0.0.6:7100").unwrap();
            stream.write_all(b"hello\n").unwrap();
            let mut buf = [0u8; 8];
            stream.read(&mut buf).unwrap_err().kind()
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), std::io::ErrorKind::ConnectionReset);
    });
}

#[test]
fn a_quiesced_peer_ignores_requests_until_it_wakes() {
    Sim::new().run(|| {
        let mut first = true;
        let server = connect_tester::<Line>("127.0.0.6:7200")
            .then_action(move |msg, _| {
                if std::mem::take(&mut first) {
                    // Hang for 50ms without answering the first request.
                    TesterAction::Quiesce(Duration::from_millis(50))
                } else {
                    TesterAction::Send(Line(format!("echo:{}", msg.0)))
                }
            })
            .until_after(Duration::from_secs(1));

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.6:7200").unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            let mut line = String::new();
            writeln!(w, "1").unwrap();
            assert!(r.read_line(&mut line).is_err(), "no answer while hung");
            writeln!(w, "2").unwrap(); // dropped: still silent
            std::thread::sleep(Duration::from_millis(60));
            writeln!(w, "3").unwrap();
            r.get_ref().set_read_timeout(None).unwrap();
            r.read_line(&mut line).unwrap();
            line
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), "echo:3\n");
    });
}

fn recv_all(sock: &UdpSocket) -> Vec<Vec<u8>> {
    sock.set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 2048];
    while let Ok((n, _)) = sock.recv_from(&mut buf) {
        got.push(buf[..n].to_vec());
    }
    got
}

#[test]
fn a_lossy_link_drops_everything_at_full_loss() {
    Sim::new().run(|| {
        let rx = UdpSocket::bind("127.0.0.6:7300").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        set_udp_policy("127.0.0.6:7300", |p| p.loss_rate = 1.0);
        for _ in 0..5 {
            tx.send_to(b"x", "127.0.0.6:7300").unwrap();
        }
        assert!(recv_all(&rx).is_empty());
        set_udp_policy("127.0.0.6:7300", |p| p.loss_rate = 0.0);
        tx.send_to(b"y", "127.0.0.6:7300").unwrap();
        assert_eq!(recv_all(&rx), [b"y".to_vec()]);
    });
}

#[test]
fn a_duplicating_link_delivers_twice_and_an_mtu_drops_big_datagrams() {
    Sim::new().run(|| {
        let rx = UdpSocket::bind("127.0.0.6:7400").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        set_udp_policy("127.0.0.6:7400", |p| {
            p.duplicate_rate = 1.0;
            p.mtu = Some(100);
        });
        tx.send_to(b"small", "127.0.0.6:7400").unwrap();
        tx.send_to(&[0u8; 500], "127.0.0.6:7400").unwrap();
        assert_eq!(recv_all(&rx), [b"small".to_vec(), b"small".to_vec()]);
    });
}

#[test]
fn a_stalled_sender_would_block_until_the_link_frees() {
    Sim::new().run(|| {
        let rx = UdpSocket::bind("127.0.0.6:7500").unwrap();
        let tx = UdpSocket::bind("127.0.0.6:7501").unwrap();
        tx.set_nonblocking(true).unwrap();
        set_udp_policy("127.0.0.6:7501", |p| p.send_queue_depth = Some(0));
        let err = tx.send_to(b"x", "127.0.0.6:7500").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        set_udp_policy("127.0.0.6:7501", |p| p.send_queue_depth = None);
        tx.send_to(b"y", "127.0.0.6:7500").unwrap();
        assert_eq!(recv_all(&rx), [b"y".to_vec()]);
    });
}

#[test]
fn a_tester_on_a_lossy_link_sees_only_what_got_through() {
    Sim::builder().seed(3).build().run(|| {
        let sink = udp_tester::<Bytes>("127.0.0.6:7600")
            .recording()
            .until_after(Duration::from_millis(20));
        set_udp_policy("127.0.0.6:7600", |p| p.loss_rate = 0.5);
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        for n in 0..200u8 {
            tx.send_to(&[n], "127.0.0.6:7600").unwrap();
        }
        run_testers!(sink);
        let got = sink.recorded().len();
        assert!(
            (60..=140).contains(&got),
            "about half of 200 got through: {got}"
        );
    });
}

/// The first hash a freshly spawned thread computes: std seeds a thread's `RandomState` keys from
/// the OS on first use, so this reads the sim's randomness.
fn first_hash_on_a_new_thread(seed: u64) -> u64 {
    Sim::builder().seed(seed).build().run(|| {
        std::thread::spawn(|| RandomState::new().hash_one(42u64))
            .join()
            .unwrap()
    })
}

#[test]
fn the_same_seed_replays_the_same_randomness() {
    assert_eq!(first_hash_on_a_new_thread(7), first_hash_on_a_new_thread(7));
    assert_ne!(first_hash_on_a_new_thread(7), first_hash_on_a_new_thread(8));
}

#[test]
fn the_same_seed_replays_the_same_losses() {
    let delivered = |seed| {
        Sim::builder().seed(seed).build().run(|| {
            let rx = UdpSocket::bind("127.0.0.6:7700").unwrap();
            let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
            set_udp_policy("127.0.0.6:7700", |p| p.loss_rate = 0.5);
            for n in 0..32u8 {
                tx.send_to(&[n], "127.0.0.6:7700").unwrap();
            }
            recv_all(&rx)
        })
    };
    assert_eq!(delivered(11), delivered(11));
    assert_ne!(delivered(11), delivered(12));
}

#[test]
fn latency_holds_a_datagram_in_flight_on_the_virtual_clock() {
    let real = std::time::Instant::now();
    Sim::new().run(|| {
        let rx = UdpSocket::bind("127.0.0.6:7800").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        set_udp_policy("127.0.0.6:7800", |p| p.latency = Duration::from_secs(2));
        let start = std::time::Instant::now();
        tx.send_to(b"late", "127.0.0.6:7800").unwrap();

        rx.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 8];
        let early = rx.recv_from(&mut buf).unwrap_err();
        assert_eq!(
            early.kind(),
            std::io::ErrorKind::WouldBlock,
            "still in flight"
        );

        rx.set_nonblocking(false).unwrap();
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"late");
        let waited = start.elapsed();
        assert!(
            (Duration::from_secs(2)..Duration::from_millis(2010)).contains(&waited),
            "arrived after the 2s link latency, got {waited:?}"
        );
    });
    assert!(
        real.elapsed() < Duration::from_secs(2),
        "the latency passed in virtual time"
    );
}

/// The order 20 datagrams sent back-to-back arrive in over a jittery link.
fn arrival_order(seed: u64) -> Vec<u8> {
    Sim::builder().seed(seed).build().run(|| {
        let rx = UdpSocket::bind("127.0.0.6:7900").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        set_udp_policy("127.0.0.6:7900", |p| {
            p.latency = Duration::from_millis(10);
            p.jitter = Duration::from_millis(10);
        });
        for n in 0..20u8 {
            tx.send_to(&[n], "127.0.0.6:7900").unwrap();
        }
        let mut buf = [0u8; 4];
        (0..20)
            .map(|_| {
                rx.recv_from(&mut buf).unwrap();
                buf[0]
            })
            .collect()
    })
}

#[test]
fn jitter_reorders_datagrams_and_the_seed_replays_the_order() {
    let order = arrival_order(5);
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        (0..20).collect::<Vec<u8>>(),
        "nothing lost or duplicated"
    );
    assert_ne!(
        order, sorted,
        "jitter let later datagrams overtake earlier ones"
    );
    assert_eq!(
        order,
        arrival_order(5),
        "the same seed replays the same order"
    );
    assert_ne!(order, arrival_order(6), "another seed, another order");
}

#[test]
fn latency_on_the_wall_clock_takes_real_time() {
    Sim::builder().wall_clock().build().run(|| {
        let rx = UdpSocket::bind("127.0.0.6:8000").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        set_udp_policy("127.0.0.6:8000", |p| p.latency = Duration::from_millis(40));
        // Measured on the real clock: off the virtual clock the latency is real time, but the
        // sim's own clock (Windows' tick clock) need not be.
        let start = snare::real(std::time::Instant::now);
        tx.send_to(b"x", "127.0.0.6:8000").unwrap();
        let mut buf = [0u8; 4];
        rx.recv_from(&mut buf).unwrap();
        let waited = snare::real(|| start.elapsed());
        assert!(
            (Duration::from_millis(35)..Duration::from_millis(190)).contains(&waited),
            "woke at the arrival, not the 200ms deadlock poll: {waited:?}"
        );
    });
}

#[test]
fn tcp_latency_applies_in_each_direction() {
    let real = std::time::Instant::now();
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.6:8100")
            .then_action(|msg, _| TesterAction::Send(msg))
            .until_after(Duration::from_secs(5));
        set_tcp_policy("127.0.0.6:8100", |p| p.latency = Duration::from_millis(100));

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.6:8100").unwrap();
            let start = std::time::Instant::now();
            (&stream).write_all(b"ping\n").unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            (line, start.elapsed())
        });

        run_testers!(server);
        let (line, round_trip) = client.join().unwrap();
        assert_eq!(line, "ping\n");
        assert!(
            (Duration::from_millis(200)..Duration::from_millis(210)).contains(&round_trip),
            "100ms out and 100ms back, got {round_trip:?}"
        );
    });
    assert!(
        real.elapsed() < Duration::from_secs(5),
        "the latency passed in virtual time"
    );
}

#[test]
fn tcp_jitter_never_reorders_bytes() {
    Sim::builder().seed(9).build().run(|| {
        let sink = connect_tester::<Line>("127.0.0.6:8200")
            .recording()
            .until_after(Duration::from_millis(200));
        set_tcp_policy("127.0.0.6:8200", |p| {
            p.latency = Duration::from_millis(1);
            p.jitter = Duration::from_millis(5);
        });
        let stream = TcpStream::connect("127.0.0.6:8200").unwrap();
        for n in 0..30 {
            writeln!(&stream, "{n}").unwrap();
        }
        run_testers!(sink);
        let got: Vec<String> = sink.recorded().into_iter().map(|(_, l)| l.0).collect();
        let sent: Vec<String> = (0..30).map(|n| n.to_string()).collect();
        assert_eq!(got, sent);
    });
}

#[test]
fn a_close_lands_after_the_data_sent_before_it() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.6:8300")
            .on_connect(|_, _| {
                TesterAction::Multiple(vec![
                    TesterAction::Send(Line("bye".into())),
                    TesterAction::Close,
                ])
            })
            .until_after(Duration::from_millis(500));
        set_tcp_policy("127.0.0.6:8300", |p| p.latency = Duration::from_millis(50));

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.6:8300").unwrap();
            let mut all = String::new();
            BufReader::new(stream).read_to_string(&mut all).unwrap();
            all
        });

        run_testers!(server);
        assert_eq!(
            client.join().unwrap(),
            "bye\n",
            "the data, then end-of-stream"
        );
    });
}

#[path = "support/netfault.rs"]
mod netfault;

mod injected {
    use std::io::{ErrorKind, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::time::{Duration, Instant};

    use snare::{
        Direction, Fault, Line, RecordedEvent, Sim, TesterAction, connect_tester, quiesce,
        raise_socket_error, recorded_events, run_testers, set_tcp_policy,
    };

    use super::netfault::{self, code, errno};

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    fn udp_pair() -> (UdpSocket, UdpSocket) {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        (a, b)
    }

    #[test]
    fn raise_socket_error_fails_next_call_and_clears() {
        Sim::new().run(|| {
            let (mut client, _server) = pair();
            let local = client.local_addr().unwrap();
            raise_socket_error(local, ErrorKind::ConnectionReset.into());
            assert_eq!(errno(client.write(b"x").unwrap_err()), code::ECONNRESET);
            assert_eq!(
                client.write(b"x").unwrap(),
                1,
                "reporting cleared the error"
            );
        });
    }

    #[test]
    fn raised_error_on_tcp_returns_buffered_data_first() {
        Sim::new().run(|| {
            let (mut client, mut server) = pair();
            server.write_all(b"hi").unwrap();
            raise_socket_error(
                client.local_addr().unwrap(),
                ErrorKind::ConnectionAborted.into(),
            );
            let mut buf = [0u8; 8];
            if cfg!(windows) {
                assert_eq!(
                    errno(client.read(&mut buf).unwrap_err()),
                    code::ECONNABORTED
                );
                assert_eq!(client.read(&mut buf).unwrap(), 2);
            } else {
                assert_eq!(client.read(&mut buf).unwrap(), 2);
                assert_eq!(
                    errno(client.read(&mut buf).unwrap_err()),
                    code::ECONNABORTED
                );
            }
        });
    }

    #[test]
    fn raised_error_on_udp_ordering() {
        Sim::new().run(|| {
            let (a, b) = udp_pair();
            a.send_to(b"d", b.local_addr().unwrap()).unwrap();
            raise_socket_error(b.local_addr().unwrap(), ErrorKind::HostUnreachable.into());
            let mut buf = [0u8; 8];
            if cfg!(target_os = "macos") {
                assert_eq!(b.recv(&mut buf).unwrap(), 1);
                assert_eq!(errno(b.recv(&mut buf).unwrap_err()), code::EHOSTUNREACH);
            } else {
                assert_eq!(errno(b.recv(&mut buf).unwrap_err()), code::EHOSTUNREACH);
                assert_eq!(b.recv(&mut buf).unwrap(), 1);
            }
        });
    }

    #[test]
    fn so_error_reports_and_clears() {
        Sim::new().run(|| {
            let (a, _b) = udp_pair();
            raise_socket_error(a.local_addr().unwrap(), ErrorKind::NetworkDown.into());
            let e = a.take_error().unwrap().expect("pending error");
            assert_eq!(e.raw_os_error(), Some(code::ENETDOWN));
            assert!(a.take_error().unwrap().is_none());
            a.send_to(b"ok", a.local_addr().unwrap()).unwrap();
        });
    }

    #[test]
    fn raised_error_wakes_poll() {
        Sim::new().run(|| {
            let (a, _b) = udp_pair();
            let addr = a.local_addr().unwrap();
            let raw = netfault::raw(&a);
            assert!(!netfault::poll(raw, true, false, 0).readable);
            let blocked = std::thread::spawn(move || {
                let mut buf = [0u8; 8];
                errno(a.recv(&mut buf).unwrap_err())
            });
            std::thread::sleep(Duration::from_millis(10));
            raise_socket_error(addr, ErrorKind::ConnectionRefused.into());
            assert_eq!(blocked.join().unwrap(), code::ECONNREFUSED);

            let (c, _d) = udp_pair();
            let raw = netfault::raw(&c);
            let caddr = c.local_addr().unwrap();
            let raiser = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                raise_socket_error(caddr, ErrorKind::ConnectionRefused.into());
            });
            let ready = netfault::poll(raw, true, false, -1);
            assert!(
                ready.readable || ready.error,
                "poll reports the pending error"
            );
            raiser.join().unwrap();
            drop(c);
        });
    }

    #[test]
    fn raise_socket_error_maps_kinds_to_host_codes() {
        let table = [
            (ErrorKind::ConnectionReset, code::ECONNRESET),
            (ErrorKind::ConnectionAborted, code::ECONNABORTED),
            (ErrorKind::ConnectionRefused, code::ECONNREFUSED),
            (ErrorKind::TimedOut, code::ETIMEDOUT),
            (ErrorKind::BrokenPipe, code::EPIPE),
            (ErrorKind::NotConnected, code::ENOTCONN),
            (ErrorKind::NetworkUnreachable, code::ENETUNREACH),
            (ErrorKind::HostUnreachable, code::EHOSTUNREACH),
            (ErrorKind::NetworkDown, code::ENETDOWN),
            (ErrorKind::AddrNotAvailable, code::EADDRNOTAVAIL),
        ];
        Sim::new().run(|| {
            let (a, _b) = udp_pair();
            let addr = a.local_addr().unwrap();
            for (kind, want) in table {
                raise_socket_error(addr, kind.into());
                assert_eq!(
                    a.take_error().unwrap().unwrap().raw_os_error(),
                    Some(want),
                    "{kind:?}"
                );
            }
            raise_socket_error(addr, std::io::Error::from_raw_os_error(code::ETIMEDOUT));
            let e = a.take_error().unwrap().unwrap();
            assert_eq!(
                e.raw_os_error(),
                Some(code::ETIMEDOUT),
                "a raw code passes as given"
            );
        });
        let caught = std::panic::catch_unwind(|| {
            Sim::new().run(|| raise_socket_error("127.0.0.1:1", ErrorKind::Other.into()))
        });
        assert!(caught.is_err(), "an error kind with no socket code panics");
    }

    #[test]
    fn tester_action_raise_socket_error() {
        Sim::new().run(|| {
            let server = connect_tester::<Line>("127.0.0.6:7400")
                .then_action(|_, _| {
                    TesterAction::RaiseSocketError(ErrorKind::ConnectionReset.into())
                })
                .until_after(Duration::from_secs(1));
            let client = std::thread::spawn(|| {
                let mut stream = TcpStream::connect("127.0.0.6:7400").unwrap();
                stream.write_all(b"go\n").unwrap();
                let mut buf = [0u8; 8];
                errno(stream.read(&mut buf).unwrap_err())
            });
            run_testers!(server);
            assert_eq!(client.join().unwrap(), code::ECONNRESET);
        });
    }

    #[test]
    fn sim_methods_work_outside_run() {
        let sim = Sim::new();
        let a: SocketAddr = "127.0.0.1:7501".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:7502".parse().unwrap();
        sim.set_udp_policy(b, |p| p.latency = Duration::from_millis(30));
        sim.set_tcp_policy("127.0.0.1:7503", |p| p.latency = Duration::from_millis(5));
        sim.quiesce(a, Duration::from_millis(100), Direction::Receive);
        sim.raise_socket_error(a, ErrorKind::ConnectionReset.into());
        sim.inject_icmp_port_unreachable(a, b);
        let (to_b, to_a) = sim.run(|| {
            let sa = UdpSocket::bind(a).unwrap();
            let sb = UdpSocket::bind(b).unwrap();
            let mut buf = [0u8; 8];
            let start = Instant::now();
            sa.send_to(b"1", b).unwrap();
            sb.recv(&mut buf).unwrap();
            let to_b = start.elapsed();
            let start = Instant::now();
            sb.send_to(b"2", a).unwrap();
            sa.recv(&mut buf).unwrap();
            (to_b, start.elapsed())
        });
        assert!(
            to_b >= Duration::from_millis(30),
            "policy set before the run: {to_b:?}"
        );
        assert!(
            to_a >= Duration::from_millis(70),
            "stall set before the run: {to_a:?}"
        );
        let tcp = sim.run(|| {
            let listener = TcpListener::bind("127.0.0.1:7503").unwrap();
            let mut client = TcpStream::connect("127.0.0.1:7503").unwrap();
            let (mut server, _) = listener.accept().unwrap();
            let start = Instant::now();
            client.write_all(b"x").unwrap();
            let mut buf = [0u8; 1];
            server.read_exact(&mut buf).unwrap();
            let took = start.elapsed();
            sim.raise_socket_error(
                client.local_addr().unwrap(),
                ErrorKind::ConnectionReset.into(),
            );
            let failed = client.write(b"y").map_err(errno);
            (took, failed)
        });
        assert!(tcp.0 >= Duration::from_millis(5));
        assert_eq!(tcp.1, Err(code::ECONNRESET));
    }

    fn linger_pair(secs: u16) -> (TcpStream, TcpStream) {
        let (client, server) = pair();
        #[allow(clippy::unnecessary_cast)]
        netfault::set_linger(netfault::raw(&client), secs as _);
        (client, server)
    }

    #[test]
    fn linger_zero_drop_resets_peer() {
        Sim::new().run(|| {
            let (client, mut server) = linger_pair(0);
            drop(client);
            let mut buf = [0u8; 4];
            assert_eq!(
                server.read(&mut buf).unwrap_err().kind(),
                ErrorKind::ConnectionReset
            );

            let tester =
                connect_tester::<Line>("127.0.0.6:7600").until_after(Duration::from_millis(50));
            let client = std::thread::spawn(|| {
                let stream = TcpStream::connect("127.0.0.6:7600").unwrap();
                #[allow(clippy::unnecessary_cast)]
                netfault::set_linger(netfault::raw(&stream), 0 as _);
                drop(stream);
            });
            run_testers!(tester);
            client.join().unwrap();
            let reset = recorded_events()
                .into_iter()
                .any(|e| matches!(e.event, RecordedEvent::PeerReset { .. }));
            assert!(reset, "the tester saw the reset");
        });
    }

    #[test]
    fn linger_nonzero_close_waits_for_in_flight() {
        Sim::new().run(|| {
            let listener = TcpListener::bind("127.0.0.1:7700").unwrap();
            set_tcp_policy("127.0.0.1:7700", |p| p.latency = Duration::from_millis(100));
            let mut client = TcpStream::connect("127.0.0.1:7700").unwrap();
            let (mut server, _) = listener.accept().unwrap();
            #[allow(clippy::unnecessary_cast)]
            netfault::set_linger(netfault::raw(&client), 5 as _);
            client.write_all(b"bye").unwrap();
            let start = Instant::now();
            drop(client);
            let took = start.elapsed();
            assert!(took >= Duration::from_millis(100), "{took:?}");
            assert!(took < Duration::from_secs(5), "{took:?}");
            let mut got = Vec::new();
            server.read_to_end(&mut got).unwrap();
            assert_eq!(got, b"bye");
        });
    }

    #[test]
    fn quiesce_receive_holds_inbound_then_releases_in_order() {
        Sim::new().run(|| {
            let (mut client, mut server) = pair();
            let at = server.local_addr().unwrap();
            quiesce(at, Duration::from_millis(100), Direction::Receive);
            let start = Instant::now();
            client.write_all(b"abc").unwrap();
            client.write_all(b"def").unwrap();
            server.write_all(b"out").unwrap();
            let mut back = [0u8; 3];
            client.read_exact(&mut back).unwrap();
            assert!(
                start.elapsed() < Duration::from_millis(100),
                "outbound is not held"
            );
            let mut got = [0u8; 6];
            server.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"abcdef");
            assert!(start.elapsed() >= Duration::from_millis(100));
        });
    }

    #[test]
    fn quiesce_send_holds_outbound_only() {
        Sim::new().run(|| {
            let (mut client, mut server) = pair();
            quiesce(
                client.local_addr().unwrap(),
                Duration::from_millis(100),
                Direction::Send,
            );
            let start = Instant::now();
            server.write_all(b"in").unwrap();
            let mut buf = [0u8; 2];
            client.read_exact(&mut buf).unwrap();
            assert!(
                start.elapsed() < Duration::from_millis(100),
                "inbound is not held"
            );
            client.write_all(b"out").unwrap();
            let mut got = [0u8; 3];
            server.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"out");
            assert!(start.elapsed() >= Duration::from_millis(100));
        });
    }

    #[test]
    fn quiesce_udp_holds_datagrams_one_way() {
        Sim::new().run(|| {
            let (a, b) = udp_pair();
            quiesce(
                b.local_addr().unwrap(),
                Duration::from_millis(100),
                Direction::Receive,
            );
            let start = Instant::now();
            a.send_to(b"1", b.local_addr().unwrap()).unwrap();
            a.send_to(b"2", b.local_addr().unwrap()).unwrap();
            b.send_to(b"r", a.local_addr().unwrap()).unwrap();
            let mut buf = [0u8; 4];
            a.recv(&mut buf).unwrap();
            assert!(start.elapsed() < Duration::from_millis(100));
            b.recv(&mut buf).unwrap();
            assert_eq!(buf[0], b'1');
            b.recv(&mut buf).unwrap();
            assert_eq!(buf[0], b'2');
            assert!(start.elapsed() >= Duration::from_millis(100));
        });
    }

    #[test]
    fn tester_action_quiesce_link() {
        Sim::new().run(|| {
            let server = connect_tester::<Line>("127.0.0.6:7800")
                .then_action(|msg, _| {
                    TesterAction::Multiple(vec![
                        TesterAction::QuiesceLink(Duration::from_millis(100), Direction::Receive),
                        TesterAction::Send(msg),
                    ])
                })
                .until_after(Duration::from_secs(1));
            let client = std::thread::spawn(|| {
                let mut stream = TcpStream::connect("127.0.0.6:7800").unwrap();
                let start = Instant::now();
                stream.write_all(b"ping\n").unwrap();
                let mut buf = [0u8; 5];
                stream.read_exact(&mut buf).unwrap();
                start.elapsed()
            });
            run_testers!(server);
            assert!(client.join().unwrap() >= Duration::from_millis(100));
        });
    }

    #[test]
    fn faults_are_recorded() {
        Sim::new().run(|| {
            let (a, b) = udp_pair();
            let addr = a.local_addr().unwrap();
            raise_socket_error(addr, ErrorKind::ConnectionReset.into());
            assert!(a.send_to(b"x", b.local_addr().unwrap()).is_err());
            quiesce(addr, Duration::from_millis(10), Direction::Both);
            a.connect(b.local_addr().unwrap()).unwrap();
            snare::inject_icmp_port_unreachable(addr, b.local_addr().unwrap());
            let mut buf = [0u8; 4];
            assert_eq!(errno(a.recv(&mut buf).unwrap_err()), code::ICMP);
            let faults: Vec<Fault> = recorded_events()
                .into_iter()
                .filter_map(|e| match e.event {
                    RecordedEvent::Fault {
                        addr: Some(at),
                        fault,
                    } if at == addr => Some(fault),
                    _ => None,
                })
                .collect();
            assert_eq!(
                faults,
                [
                    Fault::Error {
                        errno: code::ECONNRESET,
                        call: "send"
                    },
                    Fault::Stalled {
                        span: Duration::from_millis(10),
                        direction: Direction::Both
                    },
                    Fault::IcmpPortUnreachable {
                        from: b.local_addr().unwrap()
                    },
                ]
            );
        });
    }
}
