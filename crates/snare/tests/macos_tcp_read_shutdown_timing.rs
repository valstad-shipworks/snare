#![cfg(target_os = "macos")]

use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use snare::{NicSpec, Sim};

const DELAY: Duration = Duration::from_millis(10);

fn run_both(f: impl Fn(&Sim, TcpStream, TcpStream)) {
    for deterministic in [false, true] {
        let sim = if deterministic {
            Sim::builder().deterministic().build()
        } else {
            Sim::new()
        };
        with_connection(&sim, |client, server| f(&sim, client, server));
    }
}

fn with_connection(sim: &Sim, f: impl FnOnce(TcpStream, TcpStream)) {
    sim.run(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        for stream in [&client, &server] {
            let value: libc::c_int = 1;
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        stream.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_NOSIGPIPE,
                        (&value as *const libc::c_int).cast(),
                        size_of_val(&value) as libc::socklen_t,
                    )
                },
                0
            );
        }
        sim.set_tcp_policy(addr, |policy| policy.latency = DELAY);
        f(client, server);
    });
}

fn send(stream: &TcpStream, bytes: &[u8]) -> Result<usize, i32> {
    let result = unsafe { libc::send(stream.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), 0) };
    if result < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        Ok(result as usize)
    }
}

fn recv(stream: &TcpStream, flags: libc::c_int) -> Result<Vec<u8>, i32> {
    let mut bytes = [0; 8];
    let result = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            flags,
        )
    };
    if result < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        Ok(bytes[..result as usize].to_vec())
    }
}

fn so_error(stream: &TcpStream) -> i32 {
    let mut value: libc::c_int = 0;
    let mut length = size_of_val(&value) as libc::socklen_t;
    assert_eq!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut value as *mut libc::c_int).cast(),
                &mut length,
            )
        },
        0
    );
    value
}

#[test]
fn incoming_data_closes_the_receiver_before_the_peer_gets_its_reset() {
    run_both(|sim, client, server| {
        sim.pause_time();
        server.shutdown(Shutdown::Read).unwrap();
        assert_eq!(recv(&server, libc::MSG_DONTWAIT), Ok(Vec::new()));
        assert_eq!(send(&client, b"a"), Ok(1));
        sim.advance_time(DELAY / 2);
        assert_eq!(send(&server, b"b"), Ok(1));
        sim.advance_time(DELAY / 2);
        assert_eq!(send(&server, b"c"), Err(libc::EPIPE));
        let counters = snare::proto_counters().tcp4;
        assert_eq!(counters.out_rsts, 1);
        assert_eq!(counters.estab_resets, 1);
        assert_eq!(so_error(&server), 0);
        assert_eq!(so_error(&client), 0);
        assert_eq!(recv(&client, libc::MSG_DONTWAIT), Err(libc::EAGAIN));
        sim.advance_time(DELAY / 2);
        assert_eq!(recv(&client, libc::MSG_DONTWAIT), Ok(b"b".to_vec()));
        sim.advance_time(DELAY / 2);
        assert_eq!(send(&client, b"d"), Err(libc::EPIPE));
        let counters = snare::proto_counters().tcp4;
        assert_eq!(counters.out_rsts, 1);
        assert_eq!(counters.estab_resets, 2);
        assert_eq!(so_error(&client), libc::ECONNRESET);
        assert_eq!(so_error(&client), 0);
        assert_eq!(recv(&client, libc::MSG_DONTWAIT), Ok(Vec::new()));
    });
}

#[test]
fn shutdown_keeps_the_original_arrival_time_of_data_already_in_flight() {
    run_both(|sim, client, server| {
        sim.pause_time();
        assert_eq!(send(&client, b"a"), Ok(1));
        sim.advance_time(DELAY / 2);
        server.shutdown(Shutdown::Read).unwrap();
        sim.advance_time(DELAY / 2);
        assert_eq!(send(&server, b"b"), Err(libc::EPIPE));
        assert_eq!(so_error(&client), 0);
        sim.advance_time(DELAY);
        assert_eq!(recv(&client, libc::MSG_PEEK), Err(libc::ECONNRESET));
        assert_eq!(recv(&client, 0), Err(libc::ECONNRESET));
        assert_eq!(recv(&client, 0), Ok(Vec::new()));
    });
}

#[test]
fn shutting_read_after_delivery_discards_data_without_resetting_the_peer() {
    run_both(|sim, client, server| {
        sim.pause_time();
        assert_eq!(send(&client, b"a"), Ok(1));
        sim.advance_time(DELAY);
        server.shutdown(Shutdown::Read).unwrap();
        assert_eq!(recv(&server, libc::MSG_DONTWAIT), Ok(Vec::new()));
        assert_eq!(send(&server, b"b"), Ok(1));
        sim.advance_time(DELAY);
        assert_eq!(recv(&client, 0), Ok(b"b".to_vec()));
        assert_eq!(so_error(&client), 0);
        assert_eq!(so_error(&server), 0);
    });
}

#[test]
fn a_blocking_peer_waits_through_incoming_data_and_the_returning_reset() {
    run_both(|_, client, server| {
        server.shutdown(Shutdown::Read).unwrap();
        let start = Instant::now();
        assert_eq!(send(&client, b"a"), Ok(1));
        assert_eq!(recv(&client, 0), Err(libc::ECONNRESET));
        assert!((DELAY * 2..DELAY * 2 + Duration::from_millis(1)).contains(&start.elapsed()));
        assert_eq!(recv(&client, 0), Ok(Vec::new()));
    });
}

#[test]
fn a_late_query_preserves_data_sent_before_the_local_close() {
    run_both(|sim, client, server| {
        sim.pause_time();
        server.shutdown(Shutdown::Read).unwrap();
        assert_eq!(send(&client, b"a"), Ok(1));
        sim.advance_time(DELAY / 2);
        assert_eq!(send(&server, b"b"), Ok(1));
        sim.advance_time(DELAY * 2);
        assert_eq!(recv(&client, 0), Ok(b"b".to_vec()));
        assert_eq!(recv(&client, 0), Err(libc::ECONNRESET));
        assert_eq!(recv(&client, 0), Ok(Vec::new()));
    });
}

#[test]
fn a_fin_does_not_deliver_the_later_incoming_data_reset_synchronously() {
    run_both(|sim, client, server| {
        sim.pause_time();
        server.shutdown(Shutdown::Both).unwrap();
        sim.advance_time(DELAY / 2);
        assert_eq!(send(&client, b"a"), Ok(1));
        assert_eq!(so_error(&client), 0);
        sim.advance_time(DELAY);
        assert_eq!(send(&client, b"b"), Ok(1));
        assert_eq!(so_error(&client), 0);
        assert_eq!(recv(&client, libc::MSG_DONTWAIT), Ok(Vec::new()));
        sim.advance_time(DELAY - Duration::from_nanos(1));
        assert_eq!(send(&client, b"c"), Ok(1));
        assert_eq!(so_error(&client), 0);
        sim.advance_time(Duration::from_nanos(1));
        assert_eq!(send(&client, b"d"), Err(libc::EPIPE));
        assert_eq!(so_error(&client), libc::ECONNRESET);
        assert_eq!(recv(&client, 0), Ok(Vec::new()));
    });
}

#[test]
fn a_scaled_clock_wakes_a_blocked_peer_for_the_returning_reset() {
    let sim = Sim::new();
    with_connection(&sim, |client, server| {
        sim.set_time_rate(10.0);
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        server.shutdown(Shutdown::Read).unwrap();
        let start = Instant::now();
        assert_eq!(send(&client, b"a"), Ok(1));
        assert_eq!(recv(&client, 0), Err(libc::ECONNRESET));
        assert!(start.elapsed() >= DELAY * 2);
        assert_eq!(so_error(&client), 0);
        assert_eq!(recv(&client, 0), Ok(Vec::new()));
    });
}

#[test]
fn data_arriving_after_the_reset_is_discarded() {
    for lazy in [false, true] {
        run_both(|sim, client, server| {
            sim.pause_time();
            server.shutdown(Shutdown::Read).unwrap();
            assert_eq!(send(&client, b"a"), Ok(1));
            sim.advance_time(DELAY / 2);
            sim.set_tcp_policy(server.local_addr().unwrap(), |policy| {
                policy.latency = DELAY * 3;
            });
            assert_eq!(send(&server, b"late"), Ok(4));
            sim.advance_time(if lazy { DELAY * 7 / 2 } else { DELAY * 3 / 2 });
            assert_eq!(recv(&client, libc::MSG_DONTWAIT), Err(libc::ECONNRESET));
            assert_eq!(recv(&client, libc::MSG_DONTWAIT), Ok(Vec::new()));
            sim.advance_time(DELAY * 2);
            assert_eq!(recv(&client, libc::MSG_DONTWAIT), Ok(Vec::new()));
        });
    }
}

fn receive_stall(sim: &Sim, late: bool) {
    with_connection(sim, |client, server| {
        sim.pause_time();
        server.shutdown(Shutdown::Read).unwrap();
        assert_eq!(send(&client, b"a"), Ok(1));
        sim.advance_time(DELAY / 2);
        sim.quiesce(
            server.local_addr().unwrap(),
            DELAY * 5 / 2,
            snare::Direction::Receive,
        );
        sim.advance_time(DELAY / 2);
        if !late {
            assert_eq!(so_error(&client), 0);
            assert_eq!(snare::proto_counters().tcp4.estab_resets, 0);
        }
        sim.advance_time(DELAY * 2);
        if late {
            sim.advance_time(DELAY / 2);
        }
        assert_eq!(send(&server, b"b"), Err(libc::EPIPE));
        assert_eq!(so_error(&client), 0);
        assert_eq!(snare::proto_counters().tcp4.estab_resets, 1);
        let remaining = if late { DELAY / 2 } else { DELAY };
        sim.advance_time(remaining - Duration::from_nanos(1));
        assert_eq!(so_error(&client), 0);
        sim.advance_time(Duration::from_nanos(1));
        assert_eq!(so_error(&client), libc::ECONNRESET);
        assert_eq!(snare::proto_counters().tcp4.estab_resets, 2);
    });
}

#[test]
fn receive_quiescence_delays_local_close_and_then_the_reverse_reset() {
    receive_stall(&Sim::new(), false);
}

#[test]
fn deterministic_receive_quiescence_delays_local_close_and_then_the_reverse_reset() {
    receive_stall(&Sim::builder().deterministic().build(), false);
}

#[test]
fn a_late_query_uses_the_receive_hold_end_as_the_local_close_time() {
    for sim in [Sim::new(), Sim::builder().deterministic().build()] {
        receive_stall(&sim, true);
    }
}

#[test]
fn receive_quiescence_on_the_sender_holds_only_the_returning_reset() {
    run_both(|sim, client, server| {
        sim.pause_time();
        server.shutdown(Shutdown::Read).unwrap();
        assert_eq!(send(&client, b"a"), Ok(1));
        sim.advance_time(DELAY / 2);
        sim.quiesce(
            client.local_addr().unwrap(),
            DELAY * 5 / 2,
            snare::Direction::Receive,
        );
        sim.advance_time(DELAY / 2);
        assert_eq!(send(&server, b"b"), Err(libc::EPIPE));
        assert_eq!(so_error(&client), 0);
        assert_eq!(snare::proto_counters().tcp4.estab_resets, 1);
        sim.advance_time(DELAY * 2 - Duration::from_nanos(1));
        assert_eq!(so_error(&client), 0);
        sim.advance_time(Duration::from_nanos(1));
        assert_eq!(so_error(&client), libc::ECONNRESET);
        assert_eq!(snare::proto_counters().tcp4.estab_resets, 2);
    });
}

#[test]
fn replacing_a_receive_hold_preserves_the_shortened_release_time_on_a_late_query() {
    run_both(|sim, client, server| {
        sim.pause_time();
        server.shutdown(Shutdown::Read).unwrap();
        assert_eq!(send(&client, b"a"), Ok(1));
        sim.advance_time(DELAY / 2);
        let addr = server.local_addr().unwrap();
        sim.quiesce(addr, DELAY * 9 / 2, snare::Direction::Receive);
        sim.advance_time(DELAY * 3 / 2);
        sim.quiesce(addr, DELAY, snare::Direction::Receive);
        sim.advance_time(DELAY * 3 / 2);
        assert_eq!(send(&server, b"b"), Err(libc::EPIPE));
        assert_eq!(so_error(&client), 0);
        sim.advance_time(DELAY / 2 - Duration::from_nanos(1));
        assert_eq!(so_error(&client), 0);
        sim.advance_time(Duration::from_nanos(1));
        assert_eq!(so_error(&client), libc::ECONNRESET);
    });
}

#[test]
fn adjacent_receive_holds_extend_the_arrival_before_the_reverse_trip() {
    run_both(|sim, client, server| {
        sim.pause_time();
        server.shutdown(Shutdown::Read).unwrap();
        assert_eq!(send(&client, b"a"), Ok(1));
        sim.advance_time(DELAY / 2);
        let addr = server.local_addr().unwrap();
        sim.quiesce(addr, DELAY * 3 / 2, snare::Direction::Receive);
        sim.advance_time(DELAY * 3 / 2);
        sim.quiesce(addr, DELAY, snare::Direction::Receive);
        sim.advance_time(DELAY * 3 / 2);
        assert_eq!(send(&server, b"b"), Err(libc::EPIPE));
        assert_eq!(so_error(&client), 0);
        sim.advance_time(DELAY / 2);
        assert_eq!(so_error(&client), libc::ECONNRESET);
    });
}

#[test]
fn replacing_a_hold_that_precedes_the_write_keeps_the_nominal_packet_deadline() {
    run_both(|sim, client, server| {
        sim.pause_time();
        server.shutdown(Shutdown::Read).unwrap();
        let addr = server.local_addr().unwrap();
        sim.quiesce(addr, DELAY * 5, snare::Direction::Receive);
        assert_eq!(send(&client, b"a"), Ok(1));
        sim.advance_time(DELAY * 2);
        sim.quiesce(addr, DELAY / 2, snare::Direction::Receive);
        sim.advance_time(DELAY);
        assert_eq!(send(&server, b"b"), Err(libc::EPIPE));
        assert_eq!(so_error(&client), 0);
        sim.advance_time(DELAY / 2);
        assert_eq!(so_error(&client), libc::ECONNRESET);
    });
}

fn with_link_connection(deterministic: bool, f: impl FnOnce(&Sim, TcpStream, TcpStream)) {
    let nic = NicSpec::new("eth0")
        .index(4)
        .address("10.0.0.1/24".parse::<snare::IpNet>().unwrap())
        .station("10.0.0.2".parse::<std::net::IpAddr>().unwrap());
    let mut builder = Sim::builder().nic(nic);
    if deterministic {
        builder = builder.deterministic();
    }
    let sim = builder.build();
    sim.run(|| {
        let addr = "10.0.0.2:9400";
        let listener = TcpListener::bind(addr).unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        for stream in [&client, &server] {
            let value: libc::c_int = 1;
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        stream.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_NOSIGPIPE,
                        (&value as *const libc::c_int).cast(),
                        size_of_val(&value) as libc::socklen_t,
                    )
                },
                0
            );
        }
        sim.set_tcp_policy(server.local_addr().unwrap(), |policy| {
            policy.latency = DELAY
        });
        f(&sim, client, server);
    });
}

#[test]
fn a_carrier_flap_dates_local_close_at_link_release_before_the_reverse_trip() {
    for deterministic in [false, true] {
        with_link_connection(deterministic, |sim, client, server| {
            sim.pause_time();
            server.shutdown(Shutdown::Read).unwrap();
            assert_eq!(send(&client, b"a"), Ok(1));
            snare::schedule_link("eth0", DELAY / 2, false).unwrap();
            snare::schedule_link("eth0", DELAY * 3, true).unwrap();
            sim.advance_time(DELAY * 7 / 2);
            assert_eq!(send(&server, b"b"), Err(libc::EPIPE));
            assert_eq!(so_error(&client), 0, "deterministic={deterministic}");
            sim.advance_time(DELAY / 2 - Duration::from_nanos(1));
            assert_eq!(so_error(&client), 0);
            sim.advance_time(Duration::from_nanos(1));
            assert_eq!(so_error(&client), libc::ECONNRESET);
        });
    }
}

#[test]
fn a_carrier_flap_during_the_reverse_trip_holds_only_the_reset_delivery() {
    for deterministic in [false, true] {
        with_link_connection(deterministic, |sim, client, server| {
            sim.pause_time();
            server.shutdown(Shutdown::Read).unwrap();
            assert_eq!(send(&client, b"a"), Ok(1));
            snare::schedule_link("eth0", DELAY * 3 / 2, false).unwrap();
            snare::schedule_link("eth0", DELAY * 3, true).unwrap();
            sim.advance_time(DELAY);
            assert_eq!(send(&server, b"b"), Err(libc::EPIPE));
            assert_eq!(so_error(&client), 0);
            sim.advance_time(DELAY * 2 - Duration::from_nanos(1));
            assert_eq!(so_error(&client), 0);
            sim.advance_time(Duration::from_nanos(1));
            assert_eq!(so_error(&client), libc::ECONNRESET);
        });
    }
}

#[test]
fn directed_and_carrier_holds_extend_each_other_before_the_reverse_trip() {
    for deterministic in [false, true] {
        with_link_connection(deterministic, |sim, client, server| {
            sim.pause_time();
            server.shutdown(Shutdown::Read).unwrap();
            assert_eq!(send(&client, b"a"), Ok(1));
            snare::schedule_link("eth0", DELAY * 9 / 5, false).unwrap();
            snare::schedule_link("eth0", DELAY * 3, true).unwrap();
            let addr = server.local_addr().unwrap();
            sim.advance_time(DELAY / 2);
            sim.quiesce(addr, DELAY * 3 / 2, snare::Direction::Receive);
            sim.advance_time(DELAY * 2);
            sim.quiesce(addr, DELAY, snare::Direction::Receive);
            sim.advance_time(DELAY * 3 / 2);
            assert_eq!(send(&server, b"b"), Err(libc::EPIPE));
            assert_eq!(so_error(&client), 0);
            sim.advance_time(DELAY / 2 - Duration::from_nanos(1));
            assert_eq!(so_error(&client), 0);
            sim.advance_time(Duration::from_nanos(1));
            assert_eq!(so_error(&client), libc::ECONNRESET);
        });
    }
}

#[test]
fn removing_a_down_interface_releases_the_packet_before_the_reverse_trip() {
    for deterministic in [false, true] {
        with_link_connection(deterministic, |sim, client, server| {
            sim.pause_time();
            server.shutdown(Shutdown::Read).unwrap();
            assert_eq!(send(&client, b"a"), Ok(1));
            sim.advance_time(DELAY / 2);
            snare::set_link("eth0", false).unwrap();
            sim.advance_time(DELAY * 5 / 2);
            snare::remove_nic("eth0").unwrap();
            sim.advance_time(DELAY / 2);
            assert_eq!(send(&server, b"b"), Err(libc::EPIPE));
            assert_eq!(so_error(&client), 0);
            sim.advance_time(DELAY / 2);
            assert_eq!(so_error(&client), libc::ECONNRESET);
        });
    }
}
