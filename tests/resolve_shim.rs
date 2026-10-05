//! Name resolution and address families on the shim's sockets.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use snare::sched::{DriverConfig, attach_driver};
use snare::{OsSemantics, TcpListener, TcpStream, UdpSocket, add_host, os_error_code};

/// The audit switches are process-wide, so tests that turn one on run
/// alone.
fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

struct Env(&'static str);

impl Env {
    fn set(key: &'static str, value: &str) -> Env {
        // SAFETY: every test that reads or writes the environment holds
        // `serial()`.
        unsafe { std::env::set_var(key, value) };
        Env(key)
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        // SAFETY: as in `Env::set`.
        unsafe { std::env::remove_var(self.0) };
    }
}

#[test]
fn localhost_resolves_to_both_loopbacks_without_the_host() {
    let _s = serial();
    snare::register_test();
    let _audit = Env::set("SNARE_SCHED_AUDIT", "1");
    let udp = UdpSocket::bind("localhost:0").unwrap();
    assert_eq!(
        udp.local_addr().unwrap().ip(),
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    );
    let listener = TcpListener::bind(("LocalHost.", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stream = TcpStream::connect(("localhost", port)).unwrap();
    assert_eq!(stream.peer_addr().unwrap().port(), port);
}

#[test]
fn add_host_names_resolve_inside_the_sim() {
    let _s = serial();
    snare::register_test();
    let _audit = Env::set("SNARE_SCHED_AUDIT", "1");
    add_host("robot1.local", IpAddr::V4(Ipv4Addr::LOCALHOST));
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = rx.local_addr().unwrap().port();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    tx.send_to(b"hi", format!("ROBOT1.local.:{port}")).unwrap();
    let mut buf = [0u8; 4];
    let (n, from) = rx.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"hi");
    assert_eq!(from, tx.local_addr().unwrap());
    tx.connect(("robot1.local", port)).unwrap();
    assert_eq!(tx.peer_addr().unwrap(), rx.local_addr().unwrap());
}

#[test]
fn audit_mode_refuses_names_the_sim_cannot_resolve() {
    let _s = serial();
    snare::register_test();
    let _audit = Env::set("SNARE_SCHED_AUDIT", "1");
    let t = Instant::now();
    assert!(UdpSocket::bind("robot9.local:0").is_err());
    assert!(TcpListener::bind(("robot9.local", 0)).is_err());
    assert!(TcpStream::connect("robot9.local:18735").is_err());
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert!(udp.send_to(b"x", "robot9.local:9").is_err());
    assert!(udp.connect(("robot9.local".to_string(), 9)).is_err());
    assert!(t.elapsed().as_millis() < 500, "{:?}", t.elapsed());
}

#[test]
fn an_auditing_driver_records_the_lookup_as_fatal() {
    let _s = serial();
    snare::register_test();
    let driver = attach_driver(DriverConfig {
        seed: 1,
        accounting: false,
        audit: true,
    })
    .unwrap();
    let err = TcpStream::connect("robot9.local:18735").unwrap_err();
    assert!(err.to_string().contains("robot9.local"), "{err}");
    let audit = driver.audit();
    assert_eq!(audit.total_violations, 1, "{audit:?}");
    let v = &audit.violations[0];
    assert!(v.fatal && v.op == "host dns lookup", "{v:?}");
}

#[test]
fn numeric_addresses_never_reach_the_resolver() {
    let _s = serial();
    snare::register_test();
    let _audit = Env::set("SNARE_SCHED_AUDIT", "1");
    let addrs = [SocketAddr::from(([127, 0, 0, 1], 0))];
    UdpSocket::bind(&addrs[..]).unwrap();
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    UdpSocket::bind("[::1]:0".to_string()).unwrap();
    let err = UdpSocket::bind("127.0.0.1").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    let err = UdpSocket::bind("localhost:port").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
}

fn v4_to_v6(os: OsSemantics, bind: &str) -> (Option<i32>, Option<i32>) {
    snare::register_test();
    snare::set_os_semantics(os);
    let udp = UdpSocket::bind(bind).unwrap();
    let send = udp.send_to(b"x", "[::1]:9").unwrap_err();
    let connect = udp.connect("[::ffff:127.0.0.1]:9").unwrap_err();
    assert!(udp.peer_addr().is_err());
    (os_error_code(&send), os_error_code(&connect))
}

#[test]
fn a_v4_udp_socket_cannot_address_v6() {
    assert_eq!(
        v4_to_v6(OsSemantics::Linux, "127.0.0.1:0"),
        (Some(97), Some(97))
    );
    assert_eq!(
        v4_to_v6(OsSemantics::MacOs, "127.0.0.1:0"),
        (Some(65), Some(22))
    );
    assert_eq!(
        v4_to_v6(OsSemantics::MacOs, "0.0.0.0:0"),
        (Some(22), Some(22))
    );
    assert_eq!(
        v4_to_v6(OsSemantics::Windows, "127.0.0.1:0"),
        (Some(10047), Some(10047))
    );
}
