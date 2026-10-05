//! The fast-talker shim's foundation: type identity with fast-talker, the
//! clock and platform hooks, sockets that never reach a syscall, and the
//! per-slot fast-talker state.

use std::any::TypeId;
use std::io;
use std::time::{Duration, SystemTime};

use ::fast_talker::__sim::ctor;
use snare::fast_talker::nic::Nic;
use snare::fast_talker::options::{Rules, ThreadOption};
use snare::fast_talker::sim::{self, FtEvent};
use snare::fast_talker::sockets::SocketOptions;
use snare::fast_talker::sys_check::{Check, Status, sys_check};
use snare::fast_talker::{Source, compat, rt};
use snare::net::{TcpListener, TcpStream, UdpSocket};
use snare::{OsSemantics, advance_time, pause_time, register_test, set_os_semantics};

fn same<A: 'static, B: 'static>() -> bool {
    TypeId::of::<A>() == TypeId::of::<B>()
}

fn host_recommended() -> Check {
    if cfg!(windows) {
        Check::WinHighPerformancePower
    } else if cfg!(target_os = "macos") {
        Check::MacOsLowPowerModeOff
    } else {
        Check::PreemptRt
    }
}

#[test]
fn pure_types_are_fast_talkers_own() {
    use snare::fast_talker as shim;
    assert!(same::<shim::Config, ::fast_talker::Config>());
    assert!(same::<shim::Received, ::fast_talker::Received>());
    assert!(same::<shim::Timestamp, ::fast_talker::Timestamp>());
    assert!(same::<shim::plan::Plan, ::fast_talker::plan::Plan>());
    assert!(same::<
        shim::options::ThreadOption,
        ::fast_talker::options::ThreadOption,
    >());
    assert!(same::<
        shim::options::SocketOption,
        ::fast_talker::options::SocketOption,
    >());
    assert!(same::<
        shim::sockets::SocketOptions,
        ::fast_talker::sockets::SocketOptions,
    >());
    assert!(same::<shim::monitor::Config, ::fast_talker::monitor::Config>());
    assert!(same::<
        shim::sys_check::Check,
        ::fast_talker::sys_check::Check,
    >());
    assert!(same::<shim::nic::Rings, ::fast_talker::nic::Rings>());
    assert!(same::<shim::rt::Scheduler, ::fast_talker::rt::Scheduler>());
    assert!(same::<shim::tcp::TcpInfo, ::fast_talker::tcp::TcpInfo>());
    assert!(!same::<shim::rt::Thread, ::fast_talker::rt::Thread>());
    assert!(!same::<shim::nic::Nic, ::fast_talker::nic::Nic>());
}

#[test]
fn stamps_age_on_the_virtual_clock() {
    register_test();
    pause_time();
    let stamp = ctor::timestamp(compat::now(), Source::Kernel, None);
    assert_eq!(stamp.elapsed(), Duration::ZERO);
    advance_time(Duration::from_millis(5));
    assert_eq!(stamp.elapsed(), Duration::from_millis(5));
    let snare_now: SystemTime = snare::time::SystemTime::now().into();
    assert_eq!(snare_now, compat::now());
}

#[test]
fn recommended_checks_follow_the_emulated_os() {
    register_test();
    let first = match snare::os_semantics() {
        OsSemantics::Windows => Check::WinHighPerformancePower,
        OsSemantics::MacOs => Check::MacOsLowPowerModeOff,
        _ => Check::PreemptRt,
    };
    assert_eq!(Check::recommended(&[3])[0], first);
    set_os_semantics(OsSemantics::Windows);
    assert_eq!(
        Check::recommended(&[3]),
        [
            Check::WinHighPerformancePower,
            Check::WinCoreParkingDisabled
        ]
    );
    assert_eq!(Check::privileges(80).len(), 4);
    set_os_semantics(OsSemantics::MacOs);
    assert_eq!(Check::recommended(&[3]), [Check::MacOsLowPowerModeOff]);
    set_os_semantics(OsSemantics::Linux);
    assert_eq!(Check::recommended(&[3])[0], Check::PreemptRt);
    assert_eq!(Check::privileges(80).len(), 5);
}

#[test]
fn threads_outside_snare_keep_real_behaviour() {
    register_test();
    set_os_semantics(if cfg!(windows) {
        OsSemantics::Linux
    } else {
        OsSemantics::Windows
    });
    pause_time();
    std::thread::spawn(|| {
        let old = ctor::timestamp(
            SystemTime::now() - Duration::from_secs(2),
            Source::UserSpace,
            None,
        );
        assert!(old.elapsed() >= Duration::from_secs(2));
        assert_eq!(Check::recommended(&[3])[0], host_recommended());
        let counters = ::fast_talker::counters::Counters::read().unwrap();
        assert!(counters.get("UdpInDatagrams").is_some());
    })
    .join()
    .unwrap();
}

#[test]
fn snare_threads_never_reach_the_hosts_settings() {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    let rules = Rules::default();
    ThreadOption::apply_all(&[ThreadOption::CpuAffinity(vec![7])], &rules).unwrap();
    let me = sim::thread_of(std::thread::current().id()).unwrap();
    assert_eq!(
        me.affinity,
        Some(vec![7]),
        "recorded by snare, not the host"
    );
    sim::set_sys_facts(|f| f.smt_enabled = true);
    let findings = sys_check(&[Check::SmtDisabled]);
    assert!(matches!(findings[0].status, Status::Fail { .. }));
    sim::set_protocol_counters(|c| {
        c.insert("SnareOnly".into(), 7);
    });
    let counters = ::fast_talker::counters::Counters::read().unwrap();
    assert_eq!(counters.get("SnareOnly"), Some(7));
}

#[test]
fn snare_sockets_never_reach_a_syscall() {
    register_test();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    SocketOptions {
        recv_buffer: Some(1 << 16),
        ..SocketOptions::default()
    }
    .apply(&udp)
    .expect("answered by snare, never setsockopt(-1)");
    assert_eq!(
        snare::socket_entry(snare::socket_id(&udp)).unwrap().rcvbuf,
        Some(
            snare::fast_talker::sockets::SocketMemory::of(&udp)
                .unwrap()
                .rcvbuf as usize
        )
    );

    #[cfg(unix)]
    {
        let e = ::fast_talker::multicast::join(&udp, "239.1.2.3".parse().unwrap(), "").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        assert!(e.to_string().contains("no OS socket (snare shim)"), "{e}");
        let e = ::fast_talker::tcp::TcpInfo::of(&udp).unwrap_err();
        assert_eq!(e.raw_os_error(), None);
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let watched =
        snare::fast_talker::monitor::WatchedSocket::new("ctl", &client).expect("snare stream");
    let (label, handle, stream) = ::fast_talker::__sim::watched(&watched);
    assert_eq!(label, "ctl");
    assert_eq!(handle.map(|h| h.0), Some(snare::socket_id(&client).get()));
    assert!(stream);
    let watched = snare::fast_talker::monitor::WatchedSocket::new("rx", &udp).unwrap();
    assert!(!::fast_talker::__sim::watched(&watched).2);
    assert!(snare::fast_talker::compat::tcp_info(&client).is_ok());
}

#[test]
fn ft_state_follows_snare_threads() {
    register_test();
    let worker = snare::thread::Builder::new()
        .name("ft-worker".into())
        .spawn(|| {
            rt::prefault_stack(64 * 1024);
            let me = rt::Thread::current();
            assert_eq!(me.name().unwrap(), "ft-worker");
            assert_eq!(rt::Thread::from(::fast_talker::rt::Thread::current()), me);
            (me.id(), ::fast_talker::rt::Thread::current().id())
        })
        .unwrap();
    let (tid, host) = worker.join().unwrap();
    let t = sim::thread_named("ft-worker").expect("registered");
    assert_eq!(t.tid, tid);
    assert_eq!(t.host_tid, Some(host));
    assert_eq!(t.prefault_bytes, 64 * 1024);
    assert!(sim::thread_of(std::thread::current().id()).is_none());
    rt::Thread::current();
    assert!(sim::thread_of(std::thread::current().id()).is_some());
}

#[test]
fn nics_are_snares_and_availability_follows_the_os() {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    let nic = Nic::open("snare0").unwrap();
    assert!(nic.link_up().unwrap());
    assert_eq!(nic.driver().unwrap().driver, "snare");
    assert_eq!(
        Nic::open("eth9").unwrap_err().kind(),
        io::ErrorKind::NotFound
    );

    set_os_semantics(OsSemantics::MacOs);
    sim::clear_events();
    let e = nic.driver().unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    assert_eq!(
        e.to_string(),
        "NIC driver information is not supported on macos (snare simulated)"
    );
    assert!(sim::events().iter().any(|e| matches!(
        e.event,
        FtEvent::Unsupported {
            os: OsSemantics::MacOs,
            ..
        }
    )));
}
