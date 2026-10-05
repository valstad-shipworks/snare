//! TCP receive-window back-pressure: a reader's window bounds what a writer can put in flight, so
//! sends block (or come back short, or with `EAGAIN`/`WSAEWOULDBLOCK`) until the reader frees
//! room, `SO_SNDTIMEO` bounds a blocked send, and poll reports a bounded stream writable only past
//! the host's threshold.

#[path = "support/netfault.rs"]
mod netfault;

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use snare::{
    Bytes, Direction, Sim, TesterAction, connect_tester, quiesce, run_testers, set_tcp_policy,
    sockets_bound,
};

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

/// Writes `data` in 4 KiB sends, each blocking until the stream takes it whole. Windows takes a
/// whole send while its buffer has any room, so one large send would not show the window.
fn write_chunked(stream: &mut TcpStream, data: &[u8]) {
    for chunk in data.chunks(4096) {
        stream.write_all(chunk).unwrap();
    }
}

/// A connection to a listener at `at` whose receive window is `window`.
fn windowed(at: &str, window: usize) -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(at).unwrap();
    set_tcp_policy(at, |p| p.recv_window = Some(window));
    let client = TcpStream::connect(at).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

#[test]
fn recv_window_with_stall_blocks_writer() {
    Sim::new().run(|| {
        let (mut client, mut server) = windowed("127.0.0.1:8100", 64 * 1024);
        quiesce(
            "127.0.0.1:8100",
            Duration::from_millis(200),
            Direction::Receive,
        );
        let data = pattern(1 << 20);
        let sent = data.clone();
        let start = Instant::now();
        let writer = std::thread::spawn(move || {
            write_chunked(&mut client, &sent);
            start.elapsed()
        });
        let mut got = Vec::new();
        let mut buf = [0u8; 8192];
        while got.len() < data.len() {
            let n = server.read(&mut buf).unwrap();
            got.extend_from_slice(&buf[..n]);
        }
        let wrote_in = writer.join().unwrap();
        assert!(got == data, "1 MB arrived in order");
        assert!(wrote_in >= Duration::from_millis(200), "{wrote_in:?}");
    });
}

#[test]
fn nonblocking_write_partial_then_wouldblock_then_writable() {
    Sim::new().run(|| {
        let (mut client, mut server) = windowed("127.0.0.1:8200", 64 * 1024);
        client.set_nonblocking(true).unwrap();
        let data = pattern(1 << 20);
        let first = client.write(&data).unwrap();
        if cfg!(windows) {
            assert_eq!(first, data.len(), "Windows takes the whole send");
        } else {
            assert!(first > 0 && first < data.len(), "{first}");
        }
        assert_eq!(
            client.write(&data[..1024]).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        let raw = netfault::raw(&client);
        assert!(!netfault::poll(raw, false, true, 0).writable);
        let mut buf = vec![0u8; first];
        server.read_exact(&mut buf).unwrap();
        assert_eq!(buf, data[..first]);
        assert!(netfault::poll(raw, false, true, 1000).writable);
        assert!(client.write(&data[..1024]).unwrap() > 0);
    });
}

#[test]
fn mio_reports_writable_once_the_reader_frees_room() {
    use mio::{Events, Interest, Poll, Token};
    Sim::new().run(|| {
        let (client, mut server) = windowed("127.0.0.1:8250", 64 * 1024);
        client.set_nonblocking(true).unwrap();
        let mut client = mio::net::TcpStream::from_std(client);
        let mut poll = Poll::new().unwrap();
        let mut events = Events::with_capacity(4);
        poll.registry()
            .register(&mut client, Token(1), Interest::WRITABLE)
            .unwrap();
        poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
        let data = pattern(1 << 20);
        let mut sent = 0;
        loop {
            match client.write(&data) {
                Ok(n) => sent += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => panic!("{e}"),
            }
        }
        poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert!(events.is_empty(), "a full window is not writable");
        let reader = std::thread::spawn(move || {
            let mut buf = vec![0u8; sent];
            server.read_exact(&mut buf).unwrap();
            server
        });
        poll.poll(&mut events, Some(Duration::from_secs(5)))
            .unwrap();
        assert!(events.iter().any(|e| e.is_writable()));
        drop(reader.join().unwrap());
    });
}

#[test]
fn so_sndtimeo_bounds_blocked_write() {
    Sim::new().run(|| {
        let (mut client, _server) = windowed("127.0.0.1:8300", 16 * 1024);
        client
            .set_write_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        client.set_nonblocking(true).unwrap();
        while client.write(&[0u8; 1024]).is_ok() {}
        client.set_nonblocking(false).unwrap();
        let start = Instant::now();
        let e = client.write(&pattern(4096)).unwrap_err();
        let took = start.elapsed();
        if cfg!(windows) {
            assert_eq!(e.kind(), ErrorKind::TimedOut);
        } else {
            assert_eq!(e.kind(), ErrorKind::WouldBlock);
        }
        assert!(took >= Duration::from_millis(100), "{took:?}");
        assert!(took < Duration::from_secs(1), "{took:?}");
    });
}

#[test]
fn latency_window_gives_bandwidth_delay_backpressure() {
    Sim::new().run(|| {
        let window = 32 * 1024;
        let (mut client, mut server) = windowed("127.0.0.1:8400", window);
        set_tcp_policy("127.0.0.1:8400", |p| p.latency = Duration::from_millis(50));
        netfault::set_buf(netfault::raw(&client), false, 16 * 1024);
        let cap = window + netfault::sndbuf(netfault::raw(&client));
        let total = cap * 6;
        let data = pattern(total);
        let start = Instant::now();
        let writer = std::thread::spawn(move || write_chunked(&mut client, &data));
        let mut got = 0;
        let mut buf = vec![0u8; 64 * 1024];
        while got < total {
            got += server.read(&mut buf).unwrap();
        }
        writer.join().unwrap();
        let took = start.elapsed();
        assert!(
            took >= Duration::from_millis(50 * 5),
            "six windows' worth needs at least five more round trips: {took:?}"
        );
    });
}

#[test]
fn sut_recv_window_caps_tester_sends() {
    Sim::new().run(|| {
        let total = 64 * 1024;
        let tester = connect_tester::<Bytes>("127.0.0.8:8500")
            .then_action(move |_, _| TesterAction::Send(Bytes(pattern(total))))
            .until_after(Duration::from_millis(500));
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect("127.0.0.8:8500").unwrap();
            let local = stream.local_addr().unwrap();
            set_tcp_policy(local, |p| p.recv_window = Some(4096));
            stream.write_all(b"go").unwrap();
            std::thread::sleep(Duration::from_millis(50));
            let queued = sockets_bound(local)[0].queued_bytes;
            let mut got = vec![0u8; total];
            stream.read_exact(&mut got).unwrap();
            (queued, got)
        });
        run_testers!(tester);
        let (queued, got) = client.join().unwrap();
        assert!(queued > 0 && queued <= 4096, "{queued}");
        assert!(got == pattern(total));
    });
}

#[test]
fn tester_action_set_recv_window() {
    Sim::new().run(|| {
        let total = 64 * 1024;
        let tester = connect_tester::<Bytes>("127.0.0.8:8600")
            .on_connect(move |_, _| {
                TesterAction::Multiple(vec![
                    TesterAction::SetRecvWindow(Some(2048)),
                    TesterAction::Send(Bytes(pattern(total))),
                ])
            })
            .until_after(Duration::from_millis(500));
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect("127.0.0.8:8600").unwrap();
            let local = stream.local_addr().unwrap();
            std::thread::sleep(Duration::from_millis(50));
            let queued = sockets_bound(local)[0].queued_bytes;
            let mut got = vec![0u8; total];
            stream.read_exact(&mut got).unwrap();
            (queued, got)
        });
        run_testers!(tester);
        let (queued, got) = client.join().unwrap();
        assert!(queued > 0 && queued <= 2048, "{queued}");
        assert!(got == pattern(total));
    });
}
