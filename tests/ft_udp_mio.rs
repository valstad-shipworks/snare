//! fast-talker's `Timestamped` as a source on snare's mio shim.

use std::net::SocketAddr;
use std::time::Duration;

use snare::fast_talker::nic::Etf;
use snare::fast_talker::sim;
use snare::fast_talker::{Config, Hardware, Timestamped, TxTime, compat};
use snare::mio::event::Events;
use snare::mio::net::UdpSocket;
use snare::mio::{Interest, Poll, Token};
use snare::sched::testkit::{StrictClock, StrictConfig};
use snare::{
    IpNet, NicSpec, OsSemantics, add_nic, advance_time, pause_time, register_test, set_os_semantics,
};

const RX: &str = "10.0.0.2:7000";
const TX: Token = Token(1);
const RXT: Token = Token(2);

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn setup() -> (UdpSocket, UdpSocket) {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    pause_time();
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/24"))).unwrap();
    add_nic(NicSpec::new("eth1").address(net("10.0.0.2/24"))).unwrap();
    (
        UdpSocket::bind(addr("10.0.0.1:7001")).unwrap(),
        UdpSocket::bind(addr(RX)).unwrap(),
    )
}

fn config(transmit: bool, txtime: Option<TxTime>) -> Config {
    Config {
        hardware: Hardware::Off,
        transmit,
        txtime,
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
fn a_timestamped_socket_registers_and_drains_on_readable() {
    let (tx, rx) = setup();
    let mut rx = Timestamped::with_config(rx, config(false, None));
    let mut poll = Poll::new().unwrap();
    poll.registry()
        .register(&mut rx, RXT, Interest::READABLE)
        .unwrap();
    assert!(poll_now(&mut poll).is_empty());
    let sent = compat::now();
    for i in 0..3u8 {
        tx.send_to(&[i], addr(RX)).unwrap();
    }
    assert_eq!(poll_now(&mut poll), [(RXT, true, false)]);
    let mut buf = [0u8; 16];
    let mut got = Vec::new();
    let n = rx
        .drain(&mut buf, |p, r| got.push((p[0], r.timestamp.time)))
        .unwrap();
    assert_eq!(n, 3);
    assert_eq!(got, [(0, sent), (1, sent), (2, sent)]);
    assert!(poll_now(&mut poll).is_empty());
    poll.registry().deregister(&mut rx).unwrap();
}

#[test]
fn a_pending_transmit_stamp_is_an_error_until_drained() {
    let (tx, _rx) = setup();
    let mut tx = Timestamped::with_config(tx, config(true, None));
    let mut poll = Poll::new().unwrap();
    poll.registry()
        .register(&mut tx, TX, Interest::READABLE)
        .unwrap();
    assert!(poll_now(&mut poll).is_empty());
    tx.send_to(b"x", addr(RX)).unwrap();
    assert_eq!(poll_now(&mut poll), [(TX, false, true)]);
    assert_eq!(poll_now(&mut poll), [(TX, false, true)], "level-triggered");
    let mut stamps = Vec::new();
    assert_eq!(tx.tx_timestamps(&mut stamps).unwrap(), 1);
    assert!(poll_now(&mut poll).is_empty());
}

#[test]
fn a_timed_sends_stamp_is_signalled_only_after_launch() {
    let (tx, _rx) = setup();
    sim::set_etf("eth0", None, Some(Etf::default())).unwrap();
    let mut tx = Timestamped::with_config(tx, config(true, Some(TxTime::Launch)));
    let mut poll = Poll::new().unwrap();
    poll.registry()
        .register(&mut tx, TX, Interest::READABLE)
        .unwrap();
    let launch = compat::now() + Duration::from_millis(10);
    tx.send_to_at(b"x", addr(RX), launch).unwrap();
    assert!(poll_now(&mut poll).is_empty());
    let mut stamps = Vec::new();
    assert_eq!(tx.tx_timestamps(&mut stamps).unwrap(), 0);

    let poller = snare::thread::spawn(move || {
        let mut events = Events::with_capacity(8);
        poll.poll(&mut events, None).unwrap();
        let seen: Vec<_> = events.iter().map(|e| (e.token(), e.is_error())).collect();
        (seen, compat::now())
    });
    advance_time(Duration::from_millis(4));
    advance_time(Duration::from_millis(6));
    let (seen, woke) = poller.join().unwrap();
    assert_eq!(seen, [(TX, true)]);
    assert_eq!(woke, launch);
    assert_eq!(tx.tx_timestamps(&mut stamps).unwrap(), 1);
    assert_eq!(stamps[0].timestamp.time, launch);
}

#[test]
fn a_blocked_poller_wakes_for_a_timed_sends_stamp_at_its_launch() {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/24"))).unwrap();
    add_nic(NicSpec::new("eth1").address(net("10.0.0.2/24"))).unwrap();
    sim::set_etf("eth0", None, Some(Etf::default())).unwrap();
    let tx = UdpSocket::bind(addr("10.0.0.1:7001")).unwrap();
    let mut tx = Timestamped::with_config(tx, config(true, Some(TxTime::Launch)));
    let mut poll = Poll::new().unwrap();
    poll.registry()
        .register(&mut tx, TX, Interest::READABLE)
        .unwrap();
    let _clock = StrictClock::start(StrictConfig::default()).unwrap();
    let (launch, woke, seen) = snare::thread::spawn(move || {
        let launch = compat::now() + Duration::from_millis(10);
        tx.send_to_at(b"x", addr(RX), launch).unwrap();
        let mut events = Events::with_capacity(8);
        poll.poll(&mut events, None).unwrap();
        let seen: Vec<_> = events.iter().map(|e| (e.token(), e.is_error())).collect();
        (launch, compat::now(), seen)
    })
    .join()
    .unwrap();
    assert_eq!(seen, [(TX, true)]);
    assert_eq!(woke, launch);
}
