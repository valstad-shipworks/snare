#![cfg(target_os = "macos")]

use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Duration;

use snare::{Sim, SocketEntry, SocketId};

const LATENCY: Duration = Duration::from_millis(10);

fn entries(sim: &Sim, client: SocketId, server: SocketId) -> (SocketEntry, SocketEntry) {
    let table = sim.socket_table();
    assert_eq!(table.len(), 2);
    let client = table
        .iter()
        .find(|entry| entry.id == client)
        .unwrap()
        .clone();
    let server = table
        .iter()
        .find(|entry| entry.id == server)
        .unwrap()
        .clone();
    assert_eq!(client.closed_at, None);
    assert_eq!(server.closed_at, None);
    (client, server)
}

#[test]
fn inspection_outside_the_sim_uses_the_connections_clock() {
    for deterministic in [false, true] {
        let sim = if deterministic {
            Sim::builder().deterministic().build()
        } else {
            Sim::new()
        };
        sim.pause_time();
        let (client, server, client_id, server_id) = sim.run(|| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let mut client = TcpStream::connect(address).unwrap();
            let (server, _) = listener.accept().unwrap();
            sim.set_tcp_policy(address, |policy| policy.latency = LATENCY);
            let client_id = snare::socket_id(&client).unwrap();
            let server_id = snare::socket_id(&server).unwrap();
            server.shutdown(Shutdown::Read).unwrap();
            client.write_all(b"discarded").unwrap();
            (client, server, client_id, server_id)
        });

        assert_eq!(sim.time_value(), Duration::ZERO);
        for _ in 0..2 {
            let (client, server) = entries(&sim, client_id, server_id);
            assert_eq!((client.pending_error, server.pending_error), (None, None));
            assert_eq!((client.queued_bytes, server.queued_bytes), (0, 0));
            let counters = sim.proto_counters().tcp4;
            assert_eq!((counters.out_rsts, counters.estab_resets), (0, 0));
            assert_eq!(counters.curr_estab, 2);
        }

        sim.advance_time(LATENCY);
        for _ in 0..2 {
            let (client, server) = entries(&sim, client_id, server_id);
            assert_eq!((client.pending_error, server.pending_error), (None, None));
            assert_eq!((client.queued_bytes, server.queued_bytes), (0, 0));
            let counters = sim.proto_counters().tcp4;
            assert_eq!((counters.out_rsts, counters.estab_resets), (1, 1));
            assert_eq!(counters.curr_estab, 1);
        }

        sim.advance_time(LATENCY);
        for _ in 0..2 {
            let (client, server) = entries(&sim, client_id, server_id);
            assert_eq!(client.pending_error, Some(libc::ECONNRESET));
            assert_eq!(server.pending_error, None);
            assert_eq!((client.queued_bytes, server.queued_bytes), (0, 0));
            let counters = sim.proto_counters().tcp4;
            assert_eq!((counters.out_rsts, counters.estab_resets), (1, 2));
            assert_eq!(counters.curr_estab, 0);
        }
        assert_eq!(sim.time_value(), LATENCY * 2);
        sim.run(|| drop((client, server)));
    }
}
