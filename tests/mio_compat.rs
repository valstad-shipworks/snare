use std::{
    io::{ErrorKind, Write},
    net::SocketAddr,
    time::{Duration, Instant},
};

use snare::{
    TcpListener, TcpStream, register_test,
    mio::{Interest, Poll, Token, Waker, event::Events},
};

fn accept_with_timeout(listener: &TcpListener, timeout: Duration) -> TcpStream {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    panic!("accept timeout");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(err) => panic!("accept failed: {err}"),
        }
    }
}

#[test]
fn waker_emits_event() {
    register_test();
    let mut poll = Poll::new().unwrap();
    let waker = Waker::new(poll.registry(), Token(7)).unwrap();
    let mut events = Events::with_capacity(4);

    waker.wake().unwrap();
    poll.poll(&mut events, Some(Duration::from_millis(10))).unwrap();

    assert!(
        events.iter().any(|evt| evt.token() == Token(7) && evt.is_readable() && evt.is_writable())
    );
}

#[test]
fn listener_readable_on_connect() {
    register_test();
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(4);
    let mut listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let addr = listener.local_addr().unwrap();
    poll.registry()
        .register(&mut listener, Token(1), Interest::READABLE)
        .unwrap();

    let _client = TcpStream::connect(addr).unwrap();
    poll.poll(&mut events, Some(Duration::from_secs(1))).unwrap();
    assert!(events.iter().any(|evt| evt.token() == Token(1) && evt.is_readable()));

    listener.set_nonblocking(true).unwrap();
    let _ = accept_with_timeout(&listener, Duration::from_secs(1));
}

#[test]
fn stream_readable_after_peer_write() {
    register_test();
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(4);
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client_stream = TcpStream::connect(addr).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut server_stream = accept_with_timeout(&listener, Duration::from_secs(1));
    poll.registry()
        .register(&mut server_stream, Token(2), Interest::READABLE)
        .unwrap();

    client_stream.write_all(b"ping").unwrap();
    poll.poll(&mut events, Some(Duration::from_secs(1))).unwrap();
    assert!(events.iter().any(|evt| evt.token() == Token(2) && evt.is_readable()));
}
