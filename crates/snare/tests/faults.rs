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
            stream.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
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
    sock.set_read_timeout(Some(Duration::from_millis(10))).unwrap();
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
        assert!((60..=140).contains(&got), "about half of 200 got through: {got}");
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
        assert_eq!(early.kind(), std::io::ErrorKind::WouldBlock, "still in flight");

        rx.set_nonblocking(false).unwrap();
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"late");
        let waited = start.elapsed();
        assert!(
            (Duration::from_secs(2)..Duration::from_millis(2010)).contains(&waited),
            "arrived after the 2s link latency, got {waited:?}"
        );
    });
    assert!(real.elapsed() < Duration::from_secs(2), "the latency passed in virtual time");
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
    assert_eq!(sorted, (0..20).collect::<Vec<u8>>(), "nothing lost or duplicated");
    assert_ne!(order, sorted, "jitter let later datagrams overtake earlier ones");
    assert_eq!(order, arrival_order(5), "the same seed replays the same order");
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
    assert!(real.elapsed() < Duration::from_secs(5), "the latency passed in virtual time");
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
                TesterAction::Multiple(vec![TesterAction::Send(Line("bye".into())), TesterAction::Close])
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
        assert_eq!(client.join().unwrap(), "bye\n", "the data, then end-of-stream");
    });
}
