use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Duration;

use snare::sched::{self, Driver, DriverConfig, PState, attach_driver};
use snare::{OsSemantics, TcpListener, TcpStream, register_test, set_tcp_recv_window};

static SERIAL: Mutex<()> = Mutex::new(());

fn setup() -> (MutexGuard<'static, ()>, Driver) {
    let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    register_test();
    sched::mark_driver_thread();
    let driver = attach_driver(DriverConfig {
        seed: 7,
        accounting: true,
        audit: false,
    })
    .unwrap();
    (guard, driver)
}

fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

fn wait_real(cond: impl Fn() -> bool) -> bool {
    let start = std::time::Instant::now();
    while !cond() {
        if start.elapsed() > Duration::from_secs(5) {
            return false;
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    true
}

fn state_of(driver: &Driver, name: &str) -> Option<PState> {
    driver
        .participants()
        .into_iter()
        .find(|p| &*p.name == name)
        .map(|p| p.state)
}

/// Spawns a thread that writes `len` bytes counting up from 0 into `client`
/// with `write_all`, returning the result.
fn blocked_writer(
    driver: &Driver,
    client: TcpStream,
    len: usize,
) -> JoinHandle<std::io::Result<()>> {
    let writer = snare::thread::Builder::new()
        .name("writer".to_string())
        .spawn(move || {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            (&client).write_all(&data)
        })
        .unwrap();
    assert!(
        wait_real(|| state_of(driver, "writer") == Some(PState::Blocked)),
        "the writer never parked on the full window"
    );
    writer
}

fn read_n(stream: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).unwrap();
    buf
}

#[test]
fn a_blocking_write_into_a_full_window_parks_until_the_peer_reads() {
    let (_s, driver) = setup();
    let (client, mut server) = pair();
    set_tcp_recv_window(server.local_addr().unwrap(), Some(4));
    let writer = blocked_writer(&driver, client, 10);
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(state_of(&driver, "writer"), Some(PState::Blocked));
    assert!(!writer.is_finished());

    let mut got = read_n(&mut server, 4);
    assert_eq!(got, [0, 1, 2, 3]);
    got.extend(read_n(&mut server, 4));
    got.extend(read_n(&mut server, 2));
    writer.join().unwrap().unwrap();
    assert_eq!(got, (0..10).collect::<Vec<u8>>());
}

#[test]
fn a_write_takes_what_the_window_has_room_for() {
    let (_s, _driver) = setup();
    let (mut client, mut server) = pair();
    set_tcp_recv_window(server.local_addr().unwrap(), Some(4));
    client.set_nonblocking(true).unwrap();
    assert_eq!(client.write(b"abcdef").unwrap(), 4);
    assert_eq!(
        client.write(b"ef").unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    assert_eq!(read_n(&mut server, 1), b"a");
    assert_eq!(client.write(b"ef").unwrap(), 1);
    assert_eq!(read_n(&mut server, 4), b"bcde");
}

#[test]
fn growing_the_window_wakes_a_blocked_writer() {
    let (_s, driver) = setup();
    let (client, mut server) = pair();
    let server_addr = server.local_addr().unwrap();
    set_tcp_recv_window(server_addr, Some(4));
    let writer = blocked_writer(&driver, client, 12);
    set_tcp_recv_window(server_addr, Some(12));
    writer.join().unwrap().unwrap();
    assert_eq!(read_n(&mut server, 12), (0..12).collect::<Vec<u8>>());
}

#[test]
fn removing_the_window_wakes_a_blocked_writer() {
    let (_s, driver) = setup();
    let (client, mut server) = pair();
    let server_addr = server.local_addr().unwrap();
    set_tcp_recv_window(server_addr, Some(4));
    let writer = blocked_writer(&driver, client, 64);
    set_tcp_recv_window(server_addr, None);
    writer.join().unwrap().unwrap();
    assert_eq!(read_n(&mut server, 64), (0..64).collect::<Vec<u8>>());
}

#[test]
fn a_peer_close_fails_a_blocked_writer_as_a_fresh_write_fails() {
    let (_s, driver) = setup();
    let (client, server) = pair();
    set_tcp_recv_window(server.local_addr().unwrap(), Some(4));
    let probe = client.try_clone().unwrap();
    let writer = blocked_writer(&driver, client, 8);
    drop(server);
    let err = writer.join().unwrap().unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NotConnected);
    assert_eq!(
        (&probe).write(b"x").unwrap_err().kind(),
        ErrorKind::NotConnected
    );
}

#[test]
fn an_abortive_peer_close_resets_a_blocked_writer() {
    let (_s, driver) = setup();
    snare::set_os_semantics(OsSemantics::Linux);
    let (client, server) = pair();
    set_tcp_recv_window(server.local_addr().unwrap(), Some(4));
    let probe = client.try_clone().unwrap();
    let writer = blocked_writer(&driver, client, 8);
    server.set_linger(Some(Duration::ZERO)).unwrap();
    drop(server);
    let err = writer.join().unwrap().unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ConnectionReset);
    assert_eq!(
        (&probe).write(b"x").unwrap_err().kind(),
        ErrorKind::BrokenPipe
    );
}

#[test]
fn a_graceful_peer_close_under_faithful_semantics_ends_a_blocked_writer() {
    let (_s, driver) = setup();
    snare::set_os_semantics(OsSemantics::Linux);
    let (client, server) = pair();
    set_tcp_recv_window(server.local_addr().unwrap(), Some(4));
    let probe = client.try_clone().unwrap();
    let writer = blocked_writer(&driver, client, 8);
    drop(server);
    writer.join().unwrap().unwrap();
    assert_eq!(
        (&probe).write(b"x").unwrap_err().kind(),
        ErrorKind::BrokenPipe
    );
}

#[cfg(feature = "mio-compat")]
#[test]
fn mio_writability_waits_for_room_in_the_peers_window() {
    use snare::mio::{Events, Interest, Poll, Token, net::TcpStream as MioTcpStream};

    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    register_test();
    let (client, server) = pair();
    set_tcp_recv_window(server.local_addr().unwrap(), Some(4));
    let mut stream = MioTcpStream::from_std(client);
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(4);
    poll.registry()
        .register(&mut stream, Token(1), Interest::WRITABLE)
        .unwrap();
    let writable = |events: &Events| events.iter().any(|e| e.is_writable());

    poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
    assert!(writable(&events));
    assert_eq!(stream.write(b"abcdef").unwrap(), 4);
    for _ in 0..3 {
        assert_eq!(
            stream.write(b"x").unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        poll.poll(&mut events, Some(Duration::from_millis(10)))
            .unwrap();
        assert!(events.is_empty(), "a full window reported writable");
    }

    let reader = snare::thread::Builder::new()
        .name("reader".to_string())
        .spawn(move || {
            let mut server = server;
            snare::thread::sleep(Duration::from_millis(50));
            let mut buf = [0u8; 2];
            server.read_exact(&mut buf).unwrap();
            (server, buf)
        })
        .unwrap();
    let before = snare::time::Instant::now();
    poll.poll(&mut events, None).unwrap();
    assert!(writable(&events));
    assert!(snare::time::Instant::now() - before >= Duration::from_millis(50));
    let (mut server, buf) = reader.join().unwrap();
    assert_eq!(&buf, b"ab");

    poll.poll(&mut events, Some(Duration::from_millis(10)))
        .unwrap();
    assert!(events.is_empty(), "writability was reported twice");
    assert_eq!(stream.write(b"xyz").unwrap(), 2);
    assert_eq!(read_n(&mut server, 4), b"cdxy");
}
