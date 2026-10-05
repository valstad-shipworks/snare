//! Cyclic actions phased into their cycle, and per-connection tester state alongside the tester's
//! own: per TCP connection and per UDP source, in message handlers, connect hooks, per-peer cyclic
//! actions, finish conditions and inspection — under the default sim and a deterministic one.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use snare::{Bytes, Line, Sim, TesterAction, connect_tester, run_testers, udp_tester};

/// The default sim and a deterministic one; every test runs under both.
fn sims() -> [Sim; 2] {
    [Sim::new(), Sim::builder().deterministic().build()]
}

const CYCLE: Duration = Duration::from_millis(8);

#[test]
fn overdue_cyclic_actions_run_through_the_finish_deadline() {
    for sim in sims() {
        sim.run(|| {
            let ticker = udp_tester::<Bytes>("127.0.0.61:16109")
                .with_state(0usize)
                .with_stateful_cyclic_action_at(
                    Duration::from_millis(200),
                    Duration::ZERO,
                    |ticks| {
                        *ticks += 1;
                        if *ticks == 1 {
                            snare::time().advance(Duration::from_millis(1900));
                        }
                        TesterAction::Nothing
                    },
                )
                .until_after(Duration::from_millis(1050));
            run_testers!(ticker);
            assert_eq!(ticker.inspect(|ticks| *ticks), 6);
        });
    }
}

#[test]
fn an_arbitrary_finish_condition_stops_overdue_cyclic_actions() {
    for sim in sims() {
        for condition in 0..3 {
            sim.run(|| {
                let ticker = udp_tester::<Bytes>("127.0.0.61:16109")
                    .with_state(0usize)
                    .with_stateful_cyclic_action_at(
                        Duration::from_millis(200),
                        Duration::ZERO,
                        |ticks| {
                            *ticks += 1;
                            if *ticks == 1 {
                                snare::time().advance(Duration::from_millis(1900));
                            }
                            TesterAction::Nothing
                        },
                    )
                    .until_after(Duration::from_millis(1050));
                let ticker = match condition {
                    0 => ticker.until_state(|ticks| *ticks >= 1),
                    1 => ticker.until_conns(|ticks, _| *ticks >= 1),
                    _ => ticker.until(|elapsed| elapsed >= Duration::from_millis(200)),
                };
                run_testers!(ticker);
                assert_eq!(ticker.inspect(|ticks| *ticks), 1, "condition {condition}");
            });
        }
    }
}

#[test]
fn two_controllers_tick_half_a_cycle_apart() {
    for sim in sims() {
        sim.run(|| {
            let host: SocketAddr = "127.0.0.1:16100".parse().unwrap();
            let controller = |addr: &str, phase: Duration| {
                udp_tester::<Bytes>(addr)
                    .with_state(Vec::<Instant>::new())
                    .with_stateful_cyclic_action_at(CYCLE, phase, move |ticks| {
                        ticks.push(Instant::now());
                        TesterAction::SendTo(host, Bytes(vec![ticks.len() as u8]))
                    })
                    .until_after(Duration::from_millis(30))
            };
            let early = controller("127.0.0.61:16101", CYCLE / 2);
            let late = udp_tester::<Bytes>("127.0.0.61:16102")
                .with_state(Vec::<Instant>::new())
                .with_stateful_cyclic_action(CYCLE, move |ticks| {
                    ticks.push(Instant::now());
                    TesterAction::SendTo(host, Bytes(vec![ticks.len() as u8]))
                })
                .until_after(Duration::from_millis(30));
            let at_start = controller("127.0.0.61:16103", Duration::ZERO);
            let _host = UdpSocket::bind(host).unwrap();

            run_testers!(early, late, at_start);
            let ticks = |t: &snare::Tester<Bytes, Vec<Instant>>| t.inspect(Vec::clone);
            let (early, late, at_start) = (ticks(&early), ticks(&late), ticks(&at_start));
            assert_eq!((early.len(), late.len(), at_start.len()), (4, 3, 4));
            for ticks in [&early, &late, &at_start] {
                for pair in ticks[1..].windows(2) {
                    assert_eq!(
                        pair[1] - pair[0],
                        CYCLE,
                        "no drift from one tick to the next"
                    );
                }
            }
            for k in 0..3 {
                assert_eq!(late[k] - early[k], CYCLE / 2, "exactly half a cycle apart");
                assert_eq!(
                    at_start[k + 1],
                    late[k],
                    "phase zero and one period share a lattice"
                );
            }
            // The first tick of a zero phase runs as the run starts; later ticks come from timed
            // wakes, which land as the sim's own sleeps do.
            let first = early[0] - at_start[0];
            assert!(
                first >= CYCLE / 2 && first < CYCLE / 2 + Duration::from_micros(1),
                "{first:?}"
            );
        });
    }
}

/// A client's session on the device: what it has sent on this connection.
#[derive(Default)]
struct Session {
    commands: Vec<String>,
}

#[test]
fn each_connection_keeps_its_own_session_beside_the_shared_state() {
    for sim in sims() {
        sim.run(|| {
            let device = connect_tester::<Line>("127.0.0.61:16110")
                .with_state(0usize)
                .with_conn_state(|_| Session::default())
                .then_conn_action(|session, total, msg, _| {
                    session.commands.push(msg.0.clone());
                    *total += 1;
                    TesterAction::Send(Line(format!("{} of {}", session.commands.len(), total)))
                })
                .until_conns(|total, conns| *total == 5 && conns.len() == 2)
                .until_after(Duration::from_secs(1));

            let client = |commands: &'static [&'static str]| {
                std::thread::spawn(move || {
                    let stream = TcpStream::connect("127.0.0.61:16110").unwrap();
                    let me = stream.local_addr().unwrap();
                    let mut w = stream.try_clone().unwrap();
                    let mut r = BufReader::new(stream);
                    let mut replies = Vec::new();
                    for cmd in commands {
                        writeln!(w, "{cmd}").unwrap();
                        let mut line = String::new();
                        r.read_line(&mut line).unwrap();
                        replies.push(line.trim_end().split(' ').next().unwrap().to_owned());
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    (me, replies)
                })
            };
            let a = client(&["a1", "a2", "a3"]);
            let b = client(&["b1", "b2"]);

            run_testers!(device);
            let (a_addr, a_replies) = a.join().unwrap();
            let (b_addr, b_replies) = b.join().unwrap();
            assert_eq!(a_replies, ["1", "2", "3"], "a's own count");
            assert_eq!(b_replies, ["1", "2"], "b's own count");
            device.inspect(|total| assert_eq!(*total, 5));
            device.inspect_conns(|conns| {
                assert_eq!(conns.len(), 2);
                for (peer, session) in conns {
                    let expected: &[&str] = if *peer == a_addr {
                        &["a1", "a2", "a3"]
                    } else {
                        assert_eq!(*peer, b_addr);
                        &["b1", "b2"]
                    };
                    assert_eq!(session.commands, expected);
                }
            });
        });
    }
}

#[test]
fn a_per_connection_cyclic_streams_each_peer_its_own_sequence() {
    for sim in sims() {
        sim.run(|| {
            let streamer = connect_tester::<Line>("127.0.0.61:16120")
                .with_conn_state(|peer| (peer, 0u32))
                .on_conn_connect(|(peer, _), _, from| {
                    assert_eq!(*peer, from);
                    TesterAction::Send(Line("hello".into()))
                })
                .with_conn_cyclic_action_at(
                    Duration::from_millis(10),
                    Duration::from_millis(5),
                    |(peer, seq), _, from| {
                        assert_eq!(*peer, from, "a peer's tick sees its own state");
                        *seq += 1;
                        TesterAction::Send(Line(format!("{} {seq}", from.port())))
                    },
                )
                .until_after(Duration::from_millis(40));

            let client = || {
                std::thread::spawn(|| {
                    let mut stream = TcpStream::connect("127.0.0.61:16120").unwrap();
                    let me = stream.local_addr().unwrap().port();
                    let mut all = String::new();
                    stream.read_to_string(&mut all).unwrap();
                    (me, all)
                })
            };
            let (a, b) = (client(), client());

            run_testers!(streamer);
            for (me, all) in [a.join().unwrap(), b.join().unwrap()] {
                let expected: String = std::iter::once("hello\n".to_owned())
                    .chain((1..=4).map(|seq| format!("{me} {seq}\n")))
                    .collect();
                assert_eq!(all, expected, "only its own ticks, at 5, 15, 25 and 35 ms");
            }
            streamer.inspect_conns(|conns| {
                assert_eq!(conns.len(), 2);
                assert!(conns.iter().all(|(_, (_, seq))| *seq == 4));
            });
        });
    }
}

#[test]
fn udp_sources_each_get_a_session_and_closed_connections_get_no_ticks() {
    for sim in sims() {
        sim.run(|| {
            let device = udp_tester::<Bytes>("127.0.0.61:16130")
                .with_conn_state(|_| 0u8)
                .then_conn_action(|count, _: &mut (), _, _| {
                    *count += 1;
                    TesterAction::Send(Bytes(vec![*count]))
                })
                .until_conns(|_, conns| conns.iter().map(|(_, n)| *n as usize).sum::<usize>() == 3)
                .until_after(Duration::from_secs(1));

            let client = std::thread::spawn(|| {
                let a = UdpSocket::bind("127.0.0.1:0").unwrap();
                let b = UdpSocket::bind("127.0.0.1:0").unwrap();
                let mut got = Vec::new();
                for sock in [&a, &b, &a] {
                    sock.send_to(b"x", "127.0.0.61:16130").unwrap();
                    let mut buf = [0u8; 4];
                    let n = sock.recv(&mut buf).unwrap();
                    got.push(buf[..n].to_vec());
                }
                got
            });

            run_testers!(device);
            assert_eq!(client.join().unwrap(), [vec![1], vec![1], vec![2]]);
            device.inspect_conns(|conns| {
                assert_eq!(conns.iter().map(|(_, n)| *n).collect::<Vec<_>>(), [2, 1]);
            });

            let ticker = connect_tester::<Line>("127.0.0.61:16131")
                .with_conn_state(|_| 0u32)
                .with_conn_cyclic_action(Duration::from_millis(5), |ticks, _, _| {
                    *ticks += 1;
                    TesterAction::Nothing
                })
                .then_conn_action(|_, _, _, _| TesterAction::Close)
                .until_after(Duration::from_millis(23));
            let client = std::thread::spawn(|| {
                let mut stream = TcpStream::connect("127.0.0.61:16131").unwrap();
                std::thread::sleep(Duration::from_millis(7));
                stream.write_all(b"bye\n").unwrap();
                let mut rest = Vec::new();
                stream.read_to_end(&mut rest).unwrap();
            });
            run_testers!(ticker);
            client.join().unwrap();
            ticker.inspect_conns(|conns| {
                assert_eq!(conns.len(), 1);
                assert_eq!(
                    conns[0].1, 1,
                    "ticked at 5 ms, closed at 7 ms, then never again"
                );
            });
        });
    }
}

#[test]
fn state_layers_compose_in_either_order() {
    for sim in sims() {
        sim.run(|| {
            let tester = connect_tester::<Line>("127.0.0.61:16140")
                .then_action(|_, _| TesterAction::Send(Line("plain".into())))
                .with_conn_state(|_| 10u32)
                .then_conn_action(|conn, _, _, _| {
                    *conn += 1;
                    TesterAction::Send(Line(format!("conn {conn}")))
                })
                .with_state(String::from("shared"))
                .then_conn_action(|conn, shared, _, _| {
                    TesterAction::Send(Line(format!("{shared} {conn}")))
                })
                .until_after(Duration::from_millis(20));

            let client = std::thread::spawn(|| {
                let mut stream = TcpStream::connect("127.0.0.61:16140").unwrap();
                stream.write_all(b"go\n").unwrap();
                let mut all = String::new();
                stream.read_to_string(&mut all).unwrap();
                all
            });

            run_testers!(tester);
            assert_eq!(client.join().unwrap(), "plain\nconn 11\nshared 11\n");
            tester.inspect(|shared| assert_eq!(shared, "shared"));
            tester.inspect_conns(|conns| assert_eq!(conns[0].1, 11));
        });
    }
}
