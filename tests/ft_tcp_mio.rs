//! fast-talker's `TimestampedStream` as a source on snare's mio shim.

use std::io::Write;
use std::net::SocketAddr;
use std::time::Duration;

use snare::fast_talker::tcp::{Stage, TimestampedStream};
use snare::fast_talker::{Config, Hardware, compat};
use snare::mio::event::Events;
use snare::mio::net::{TcpListener, TcpStream};
use snare::mio::{Interest, Poll, Token};
use snare::sched::testkit::{StrictClock, StrictConfig};
use snare::{
    IpNet, NicSpec, OsSemantics, add_nic, advance_time, pause_time, register_test, set_nic_policy,
    set_os_semantics,
};

const SERVER: &str = "10.0.0.1:7000";
const LATENCY: Duration = Duration::from_millis(5);
const CLIENT: Token = Token(1);
const PEER: Token = Token(2);

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn pair(os: OsSemantics) -> (TcpStream, TcpStream) {
    register_test();
    set_os_semantics(os);
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/24"))).unwrap();
    set_nic_policy("eth0", |p| p.latency = LATENCY).unwrap();
    let server: SocketAddr = SERVER.parse().unwrap();
    let listener = TcpListener::bind(server).unwrap();
    let client = TcpStream::connect(server).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

fn config(transmit: bool) -> Config {
    Config {
        hardware: Hardware::Off,
        transmit,
        ..Config::default()
    }
}

/// The events one zero-timeout poll reports, as `(token, readable, error)`.
fn poll_now(poll: &mut Poll) -> Vec<(Token, bool, bool)> {
    let mut events = Events::with_capacity(8);
    poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
    events
        .iter()
        .map(|e| (e.token(), e.is_readable(), e.is_error()))
        .collect()
}

#[test]
fn a_timestamped_stream_drains_in_a_poll_loop() {
    let (mut client, server) = pair(OsSemantics::Linux);
    pause_time();
    let mut server = TimestampedStream::with_config(server, config(false));
    let mut poll = Poll::new().unwrap();
    poll.registry()
        .register(&mut server, PEER, Interest::READABLE)
        .unwrap();
    assert!(poll_now(&mut poll).is_empty());

    let mut sent = Vec::new();
    for chunk in [b"ab", b"cd"] {
        sent.push(compat::now() + LATENCY);
        client.write_all(chunk).unwrap();
        advance_time(Duration::from_millis(1));
    }
    assert!(poll_now(&mut poll).is_empty(), "still on the wire");
    advance_time(LATENCY);
    let mut got = Vec::new();
    let mut buf = [0u8; 2];
    for _ in 0..3 {
        for (token, readable, _) in poll_now(&mut poll) {
            assert_eq!(token, PEER);
            assert!(readable);
            server
                .drain(&mut buf, |p, t| got.push((p.to_vec(), t.time)))
                .unwrap();
        }
    }
    assert_eq!(got, [(b"ab".to_vec(), sent[0]), (b"cd".to_vec(), sent[1])]);
    assert!(poll_now(&mut poll).is_empty());
    poll.registry().deregister(&mut server).unwrap();
}

#[test]
fn ready_send_stages_are_an_error_until_read() {
    let (client, _server) = pair(OsSemantics::Linux);
    pause_time();
    let mut client = TimestampedStream::with_config(client, config(true));
    let mut poll = Poll::new().unwrap();
    poll.registry()
        .register(&mut client, CLIENT, Interest::READABLE)
        .unwrap();
    assert!(poll_now(&mut poll).is_empty());
    client.send(b"x").unwrap();
    assert_eq!(poll_now(&mut poll), [(CLIENT, false, true)]);
    assert_eq!(
        poll_now(&mut poll),
        [(CLIENT, false, true)],
        "level-triggered"
    );
    let mut events = Vec::new();
    assert_eq!(client.tx_events(&mut events).unwrap(), 2);
    assert!(
        poll_now(&mut poll).is_empty(),
        "the ack is still on its way"
    );
    advance_time(LATENCY * 2);
    assert_eq!(poll_now(&mut poll), [(CLIENT, false, true)]);
    events.clear();
    assert_eq!(client.tx_events(&mut events).unwrap(), 1);
    assert_eq!(events[0].stage, Stage::Acked);
    assert!(poll_now(&mut poll).is_empty());
}

#[test]
fn user_space_stages_are_never_an_error() {
    for os in [OsSemantics::MacOs, OsSemantics::Windows] {
        let (client, _server) = pair(os);
        pause_time();
        let mut client = TimestampedStream::with_config(client, config(true));
        let mut poll = Poll::new().unwrap();
        poll.registry()
            .register(&mut client, CLIENT, Interest::READABLE)
            .unwrap();
        client.send(b"x").unwrap();
        assert!(poll_now(&mut poll).is_empty(), "{os}");
        let mut events = Vec::new();
        assert_eq!(client.tx_events(&mut events).unwrap(), 1, "{os}");
    }
}

#[test]
fn a_blocked_poller_wakes_when_the_ack_arrives() {
    let (client, _server) = pair(OsSemantics::Linux);
    let mut client = TimestampedStream::with_config(client, config(true));
    let mut poll = Poll::new().unwrap();
    poll.registry()
        .register(&mut client, CLIENT, Interest::READABLE)
        .unwrap();
    let _clock = StrictClock::start(StrictConfig::default()).unwrap();
    let (sent, woke, acked) = snare::thread::spawn(move || {
        let sent = compat::now();
        client.send(b"x").unwrap();
        let mut stages = Vec::new();
        client.tx_events(&mut stages).unwrap();
        let mut events = Events::with_capacity(8);
        poll.poll(&mut events, None).unwrap();
        let woke = compat::now();
        stages.clear();
        client.tx_events(&mut stages).unwrap();
        (sent, woke, stages[0].timestamp.time)
    })
    .join()
    .unwrap();
    assert_eq!(woke, sent + LATENCY * 2);
    assert_eq!(acked, woke);
}
