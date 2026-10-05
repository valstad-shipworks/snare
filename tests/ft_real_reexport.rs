//! Without `shim`, `snare::fast_talker` is fast-talker itself.
#![cfg(not(feature = "shim"))]

use std::any::TypeId;
use std::time::{Duration, SystemTime};

fn same<A: 'static, B: 'static>() -> bool {
    TypeId::of::<A>() == TypeId::of::<B>()
}

#[test]
fn os_items_are_fast_talkers_own() {
    use snare::fast_talker as ft;
    assert!(same::<ft::nic::Nic, ::fast_talker::nic::Nic>());
    assert!(same::<
        ft::Timestamped<std::net::UdpSocket>,
        ::fast_talker::Timestamped<std::net::UdpSocket>,
    >());
    assert!(same::<
        ft::tcp::TimestampedStream<std::net::TcpStream>,
        ::fast_talker::tcp::TimestampedStream<std::net::TcpStream>,
    >());
    assert!(same::<ft::rt::Thread, ::fast_talker::rt::Thread>());
    assert!(same::<ft::monitor::Monitor, ::fast_talker::monitor::Monitor>());
    assert!(same::<
        ft::options::ThreadOption,
        ::fast_talker::options::ThreadOption,
    >());
    assert!(same::<
        ft::counters::Counters,
        ::fast_talker::counters::Counters,
    >());
}

#[test]
fn compat_uses_the_real_clock_and_sockets() {
    let before = SystemTime::now();
    let now = snare::fast_talker::compat::now();
    assert!(now >= before && now < before + Duration::from_secs(5));

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    snare::fast_talker::compat::tcp_info(&client).unwrap();
    let report = snare::fast_talker::compat::apply_thread_options_to(
        snare::fast_talker::rt::Thread::current(),
        &[],
        &Default::default(),
    )
    .unwrap();
    assert!(report.applied.is_empty());
}
