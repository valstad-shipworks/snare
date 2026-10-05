//! TCP send and receive buffers bound what a stream holds written and not yet read: a writer
//! whose peer does not read fills the peer's receive buffer and its own send buffer, then
//! back-pressures, with each host's partial-write rule.

#[path = "support/netfault.rs"]
mod netfault;

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use snare::{Sim, TcpPolicy, set_tcp_policy};

/// A connection to a listener at `at` whose listener asked for `rcv` and client for `snd`.
fn pair(at: &str, snd: i32, rcv: i32) -> (TcpStream, TcpStream, TcpListener) {
    let listener = TcpListener::bind(at).unwrap();
    netfault::set_buf(netfault::raw(&listener), true, rcv);
    let client = TcpStream::connect(at).unwrap();
    netfault::set_buf(netfault::raw(&client), false, snd);
    let (server, _) = listener.accept().unwrap();
    (client, server, listener)
}

/// The receive room a reader whose `SO_RCVBUF` reads `rcvbuf` gives: twice it on Windows.
fn recv_space(rcvbuf: usize) -> usize {
    if cfg!(windows) { rcvbuf * 2 } else { rcvbuf }
}

/// Writes `chunk`-byte pieces without blocking until the stream refuses one.
fn fill(client: &mut TcpStream, chunk: usize) -> usize {
    client.set_nonblocking(true).unwrap();
    let data = vec![7u8; chunk];
    let mut total = 0;
    loop {
        match client.write(&data) {
            Ok(n) => total += n,
            Err(e) if e.kind() == ErrorKind::WouldBlock => return total,
            Err(e) => panic!("{e}"),
        }
    }
}

#[test]
fn unread_stream_holds_both_buffers() {
    Sim::new().run(|| {
        let (mut client, server, _l) = pair("127.0.0.1:9100", 16384, 16384);
        let cap = netfault::sndbuf(netfault::raw(&client))
            + recv_space(netfault::rcvbuf(netfault::raw(&server)));
        assert_eq!(fill(&mut client, 1024), cap);
        assert!(!netfault::poll(netfault::raw(&client), false, true, 0).writable);
    });
}

#[test]
fn accepted_stream_inherits_listener_buffers() {
    Sim::new().run(|| {
        let (_client, server, listener) = pair("127.0.0.1:9101", 8192, 24576);
        assert_eq!(
            netfault::rcvbuf(netfault::raw(&server)),
            netfault::rcvbuf(netfault::raw(&listener))
        );
    });
}

#[test]
fn reading_frees_room_for_the_writer() {
    Sim::new().run(|| {
        let (mut client, mut server, _l) = pair("127.0.0.1:9102", 8192, 8192);
        let first = fill(&mut client, 512);
        let mut buf = vec![0u8; first];
        server.read_exact(&mut buf).unwrap();
        assert!(netfault::poll(netfault::raw(&client), false, true, 1000).writable);
        assert_eq!(fill(&mut client, 512), first);
    });
}

#[test]
fn large_nonblocking_write_follows_the_host() {
    Sim::new().run(|| {
        let (mut client, server, _l) = pair("127.0.0.1:9103", 16384, 16384);
        let cap = netfault::sndbuf(netfault::raw(&client))
            + recv_space(netfault::rcvbuf(netfault::raw(&server)));
        client.set_nonblocking(true).unwrap();
        let data = vec![1u8; 100_000];
        let n = client.write(&data).unwrap();
        if cfg!(windows) {
            assert_eq!(n, data.len(), "Windows takes the whole send");
            assert_eq!(
                client.write(&data).unwrap_err().kind(),
                ErrorKind::WouldBlock
            );
        } else {
            assert_eq!(n, cap, "a partial write fills the buffers");
        }
    });
}

#[cfg(target_os = "macos")]
#[test]
fn macos_waits_for_the_low_water_mark() {
    Sim::new().run(|| {
        let (mut client, mut server, _l) = pair("127.0.0.1:9104", 8192, 8192);
        let full = fill(&mut client, 1000);
        let mut buf = vec![0u8; 1500];
        server.read_exact(&mut buf).unwrap();
        client.set_nonblocking(true).unwrap();
        let big = vec![0u8; 4096];
        assert_eq!(
            client.write(&big).unwrap_err().kind(),
            ErrorKind::WouldBlock,
            "1500 free is under SO_SNDLOWAT"
        );
        assert_eq!(
            client.write(&big[..1000]).unwrap(),
            1000,
            "a write that fits goes in"
        );
        let mut more = vec![0u8; 2048];
        server.read_exact(&mut more).unwrap();
        assert!(client.write(&big).unwrap() >= 2048, "{full}");
    });
}

#[test]
fn blocking_write_waits_for_the_reader() {
    Sim::new().run(|| {
        let (mut client, mut server, _l) = pair("127.0.0.1:9105", 4096, 4096);
        let total = 256 * 1024;
        let writer = std::thread::spawn(move || {
            client.write_all(&vec![3u8; total]).unwrap();
        });
        std::thread::sleep(Duration::from_millis(10));
        let mut got = 0;
        let mut buf = [0u8; 1000];
        while got < total {
            got += server.read(&mut buf).unwrap();
        }
        writer.join().unwrap();
        assert_eq!(got, total);
    });
}

#[test]
fn recv_window_policy_caps_below_the_buffer() {
    Sim::new().run(|| {
        let (mut client, server, _l) = pair("127.0.0.1:9106", 4096, 65536);
        set_tcp_policy("127.0.0.1:9106", |p: &mut TcpPolicy| {
            p.recv_window = Some(1000)
        });
        let rcv = recv_space(netfault::rcvbuf(netfault::raw(&server)));
        let snd = netfault::sndbuf(netfault::raw(&client));
        assert!(1000 < rcv);
        assert_eq!(fill(&mut client, 8), 1000 + snd);
    });
}

#[test]
fn deterministic_runs_fill_the_same() {
    let run = || {
        let sim = Sim::builder().deterministic().build();
        sim.run(|| {
            let (mut client, mut server, _l) = pair("127.0.0.1:9107", 4096, 4096);
            let writer = std::thread::spawn(move || {
                let mut sizes = Vec::new();
                for i in 1..40 {
                    sizes.push(client.write(&vec![0u8; i * 300]).unwrap());
                }
                sizes
            });
            let mut buf = [0u8; 700];
            let mut reads = Vec::new();
            loop {
                let n = server.read(&mut buf).unwrap();
                reads.push(n);
                if reads.iter().sum::<usize>() >= (1..40).map(|i| i * 300).sum::<usize>() {
                    break;
                }
            }
            (writer.join().unwrap(), reads)
        })
    };
    let first = run();
    for _ in 0..4 {
        assert_eq!(run(), first);
    }
}
