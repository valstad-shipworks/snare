//! Runtime behaviour `snare::mio::net` must share with real mio. Built
//! without `shim` it runs against mio itself, with `shim` against snare's.

use std::io::{self, ErrorKind, Read};
use std::net::SocketAddr;
use std::sync::mpsc;
use std::time::Duration;

use snare::mio::net::{TcpListener, TcpStream, UdpSocket};
use snare::mio::{Events, Interest, Poll, Token};

fn setup() {
    #[cfg(feature = "shim")]
    snare::register_test();
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// Runs `f` on another thread and fails the test if it has not returned
/// within five seconds of wall time, instead of hanging.
fn within_deadline<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    let _worker = snare::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("the operation blocked; a mio socket must return WouldBlock")
}

fn poll_until(poll: &mut Poll, token: Token, want: impl Fn(&snare::mio::event::Event) -> bool) {
    let mut events = Events::with_capacity(8);
    for _ in 0..500 {
        poll.poll(&mut events, Some(Duration::from_millis(10)))
            .unwrap();
        if events.iter().any(|e| e.token() == token && want(e)) {
            return;
        }
    }
    panic!("no event for {token:?}");
}

#[test]
fn udp_recv_from_before_register_would_block() {
    setup();
    let err = within_deadline(|| {
        let socket = UdpSocket::bind(loopback()).unwrap();
        let mut buf = [0u8; 8];
        socket.recv_from(&mut buf).unwrap_err().kind()
    });
    assert_eq!(err, ErrorKind::WouldBlock);
}

/// Real mio leaves `from_std` sockets as they are and expects them to be
/// nonblocking already; the shim switches them, so both hold after it.
#[cfg(feature = "shim")]
#[test]
fn udp_from_std_is_nonblocking() {
    setup();
    let err = within_deadline(|| {
        let std_socket = snare::net::UdpSocket::bind(loopback()).unwrap();
        let socket = UdpSocket::from_std(std_socket);
        let mut buf = [0u8; 8];
        socket.recv_from(&mut buf).unwrap_err().kind()
    });
    assert_eq!(err, ErrorKind::WouldBlock);
}

#[test]
fn listener_accept_would_block_unregistered() {
    setup();
    let err = within_deadline(|| {
        let listener = TcpListener::bind(loopback()).unwrap();
        listener.accept().map(|(_, a)| a).unwrap_err().kind()
    });
    assert_eq!(err, ErrorKind::WouldBlock);
}

#[test]
fn listener_accept_would_block_registered() {
    setup();
    let err = within_deadline(|| {
        let mut listener = TcpListener::bind(loopback()).unwrap();
        let poll = Poll::new().unwrap();
        poll.registry()
            .register(&mut listener, Token(0), Interest::READABLE)
            .unwrap();
        listener.accept().map(|(_, a)| a).unwrap_err().kind()
    });
    assert_eq!(err, ErrorKind::WouldBlock);
}

#[test]
fn accepted_stream_is_nonblocking() {
    setup();
    let err = within_deadline(|| {
        let mut listener = TcpListener::bind(loopback()).unwrap();
        let addr = listener.local_addr().unwrap();
        let mut poll = Poll::new().unwrap();
        poll.registry()
            .register(&mut listener, Token(0), Interest::READABLE)
            .unwrap();
        let _client = TcpStream::connect(addr).unwrap();
        poll_until(&mut poll, Token(0), |e| e.is_readable());
        let (mut server, _) = listener.accept().unwrap();
        let mut buf = [0u8; 8];
        server.read(&mut buf).unwrap_err().kind()
    });
    assert_eq!(err, ErrorKind::WouldBlock);
}

#[test]
fn connect_to_closed_port_reports_refused() {
    setup();
    let probe = TcpListener::bind(loopback()).unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let refused = within_deadline(move || match TcpStream::connect(addr) {
        Err(e) => e.kind(),
        Ok(mut stream) => {
            let mut poll = Poll::new().unwrap();
            poll.registry()
                .register(&mut stream, Token(1), Interest::WRITABLE)
                .unwrap();
            poll_until(&mut poll, Token(1), |e| e.is_writable() || e.is_error());
            match stream.take_error() {
                Ok(Some(e)) => e.kind(),
                Ok(None) => stream.peer_addr().unwrap_err().kind(),
                Err(e) => e.kind(),
            }
        }
    });
    assert!(
        matches!(
            refused,
            ErrorKind::ConnectionRefused | ErrorKind::NotConnected
        ),
        "{refused:?}"
    );
}

#[test]
fn listener_ttl_round_trips() {
    setup();
    let listener = TcpListener::bind(loopback()).unwrap();
    listener.set_ttl(42).unwrap();
    assert_eq!(listener.ttl().unwrap(), 42);
}

#[test]
fn try_io_runs_the_closure() {
    setup();
    let socket = UdpSocket::bind(loopback()).unwrap();
    let got = socket.try_io(|| Ok::<_, io::Error>(7)).unwrap();
    assert_eq!(got, 7);
    let listener = TcpListener::bind(loopback()).unwrap();
    let addr = listener.local_addr().unwrap();
    let stream = within_deadline(move || {
        let s = TcpStream::connect(addr).unwrap();
        drop(listener);
        s
    });
    let err = stream
        .try_io(|| Err::<(), _>(io::Error::from(ErrorKind::WouldBlock)))
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
}

#[test]
fn only_v6_is_off_on_a_dual_stack_v6_socket() {
    setup();
    #[cfg(feature = "shim")]
    snare::set_os_semantics(snare::OsSemantics::host());
    let socket = UdpSocket::bind("[::1]:0".parse::<SocketAddr>().unwrap()).unwrap();
    assert_eq!(socket.only_v6().unwrap(), cfg!(windows));
}
