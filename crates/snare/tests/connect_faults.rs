//! Connects that do not complete at once: a listener that refuses or holds SYNs, an address
//! nobody answers at, and the host OS's SYN retransmission plan a connect waits out — in virtual
//! time, so a two-minute give-up costs nothing — with nonblocking connects, poll, select and
//! `SO_ERROR` reporting how it ended.

use std::io::{self, BufRead, BufReader, ErrorKind, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use snare::{
    Fault, IpNet, Line, ListenerBehavior, NicSpec, RecordedEvent, Sim, TesterAction,
    connect_tester, recorded_events, run_testers, set_listener_behavior,
};

const SECOND: Duration = Duration::from_secs(1);

/// When a connect that nothing answers gives up: Linux at 131 s with four linear timeouts, macOS at
/// `keepinit` (75 s), Windows after 2 retransmissions (21 s).
const GIVE_UP: Duration = Duration::from_secs(if cfg!(target_os = "linux") {
    131
} else if cfg!(target_os = "macos") {
    75
} else {
    21
});

/// When Windows reports a refused connect: it retries the SYN on a reset first.
const REFUSED_AFTER: Duration = if cfg!(windows) {
    Duration::from_secs(2)
} else {
    Duration::ZERO
};

#[cfg(unix)]
const ETIMEDOUT: i32 = libc::ETIMEDOUT;
#[cfg(windows)]
const ETIMEDOUT: i32 = 10060;
#[cfg(unix)]
const ECONNREFUSED: i32 = libc::ECONNREFUSED;
#[cfg(windows)]
const ECONNREFUSED: i32 = 10061;

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// Whether `elapsed` is `expected`, give or take the sim's per-call latencies.
fn about(elapsed: Duration, expected: Duration) -> bool {
    elapsed >= expected && elapsed < expected + Duration::from_millis(50)
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let out = f();
    (out, start.elapsed())
}

#[test]
fn refusing_listener_refuses_then_accepting_accepts() {
    Sim::new().run(|| {
        let at = addr("127.0.0.7:7300");
        let listener = TcpListener::bind(at).unwrap();
        set_listener_behavior(at, ListenerBehavior::Refusing);
        let (refused, elapsed) = timed(|| TcpStream::connect(at));
        let refused = refused.unwrap_err();
        assert_eq!(refused.kind(), ErrorKind::ConnectionRefused);
        assert_eq!(refused.raw_os_error(), Some(ECONNREFUSED));
        assert!(about(elapsed, REFUSED_AFTER), "refused after {elapsed:?}");

        set_listener_behavior(at, ListenerBehavior::Accepting);
        let (stream, elapsed) = timed(|| TcpStream::connect(at));
        stream.unwrap();
        assert!(
            elapsed < Duration::from_millis(1),
            "accepted at once: {elapsed:?}"
        );
        listener.accept().unwrap();
    });
}

#[test]
fn listener_behavior_set_before_tester_exists_applies() {
    Sim::new().run(|| {
        set_listener_behavior("127.0.0.7:7310", ListenerBehavior::Refusing);
        let server = connect_tester::<Line>("127.0.0.7:7310")
            .then_action(|_, _| TesterAction::Nothing)
            .until_after(Duration::from_secs(5));
        let client = std::thread::spawn(|| TcpStream::connect("127.0.0.7:7310").map(drop));
        run_testers!(server);
        let refused = client.join().unwrap().unwrap_err();
        assert_eq!(refused.kind(), ErrorKind::ConnectionRefused);
    });
}

#[test]
fn delaying_listener_connects_at_next_syn_retransmit() {
    let expected = Duration::from_secs(if cfg!(windows) { 3 } else { 2 });
    Sim::new().run(|| {
        let at = addr("127.0.0.7:7320");
        let listener = TcpListener::bind(at).unwrap();
        let until = Instant::now() + Duration::from_millis(1500);
        set_listener_behavior(at, ListenerBehavior::DelayingUntil(until));
        let (stream, elapsed) = timed(|| TcpStream::connect(at));
        stream.unwrap();
        assert!(about(elapsed, expected), "connected after {elapsed:?}");
        listener.accept().unwrap();
    });
}

#[test]
fn delaying_listener_past_give_up_times_out() {
    Sim::new().run(|| {
        let at = addr("127.0.0.7:7330");
        let _listener = TcpListener::bind(at).unwrap();
        let until = Instant::now() + Duration::from_secs(1000);
        set_listener_behavior(at, ListenerBehavior::DelayingUntil(until));
        let (err, elapsed) = timed(|| TcpStream::connect(at).unwrap_err());
        assert_eq!(err.kind(), ErrorKind::TimedOut);
        assert_eq!(err.raw_os_error(), Some(ETIMEDOUT));
        assert!(about(elapsed, GIVE_UP), "gave up after {elapsed:?}");
    });
}

#[test]
fn connect_to_absent_off_link_address_times_out_after_syn_span() {
    Sim::new().run(|| {
        let (err, elapsed) = timed(|| TcpStream::connect("10.255.0.1:80").unwrap_err());
        assert_eq!(err.raw_os_error(), Some(ETIMEDOUT), "{err}");
        assert!(about(elapsed, GIVE_UP), "gave up after {elapsed:?}");
    });
}

#[test]
fn connect_to_absent_on_link_station_host_unreachable() {
    // Measured by `real_os_on_link_absent_calibration`: Linux EHOSTUNREACH after 3 neighbour
    // solicitations; macOS and Windows follow their SYN plans.
    #[cfg(target_os = "linux")]
    let (errno, after) = (libc::EHOSTUNREACH, Duration::from_secs(3));
    #[cfg(not(target_os = "linux"))]
    let (errno, after) = (ETIMEDOUT, GIVE_UP);
    let net: IpNet = "192.168.77.1/24".parse().unwrap();
    let sim = Sim::builder()
        .nic(NicSpec::new("eth0").address(net))
        .build();
    sim.run(|| {
        let (err, elapsed) = timed(|| TcpStream::connect("192.168.77.40:80").unwrap_err());
        assert_eq!(err.raw_os_error(), Some(errno), "{err}");
        assert!(about(elapsed, after), "failed after {elapsed:?}");
    });
}

#[test]
fn connect_timeout_caps_the_syn_wait() {
    Sim::new().run(|| {
        let (err, elapsed) =
            timed(|| TcpStream::connect_timeout(&addr("10.255.0.1:80"), 5 * SECOND).unwrap_err());
        assert_eq!(err.kind(), ErrorKind::TimedOut);
        assert!(about(elapsed, 5 * SECOND), "timed out after {elapsed:?}");
    });
}

#[test]
fn connect_timeout_reports_a_refusal() {
    Sim::new().run(|| {
        let at = addr("127.0.0.7:7340");
        let _listener = TcpListener::bind(at).unwrap();
        set_listener_behavior(at, ListenerBehavior::Refusing);
        let (err, elapsed) = timed(|| TcpStream::connect_timeout(&at, 5 * SECOND).unwrap_err());
        assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
        assert!(about(elapsed, REFUSED_AFTER), "refused after {elapsed:?}");
    });
}

#[test]
fn listener_appearing_mid_connect_is_reached_at_next_retransmit() {
    // Retransmissions at 3 s: Linux 1, 3; macOS 1, 2, 3; Windows 3.
    Sim::new().run(|| {
        let late = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(2500));
            let listener = TcpListener::bind("10.20.0.5:9000").unwrap();
            listener.accept().unwrap().1
        });
        let (stream, elapsed) = timed(|| TcpStream::connect("10.20.0.5:9000"));
        let stream = stream.unwrap();
        assert!(about(elapsed, 3 * SECOND), "connected after {elapsed:?}");
        assert_eq!(late.join().unwrap(), stream.local_addr().unwrap());
    });
}

#[cfg(unix)]
fn connect_with_option(dest: SocketAddr, level: i32, name: i32, value: i32) -> io::Result<()> {
    let SocketAddr::V4(dest) = dest else {
        unreachable!()
    };
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        assert!(fd >= 0);
        let rc = libc::setsockopt(
            fd,
            level,
            name,
            (&value as *const i32).cast(),
            size_of::<i32>() as libc::socklen_t,
        );
        assert_eq!(rc, 0, "setsockopt: {}", io::Error::last_os_error());
        let mut got = 0i32;
        let mut len = size_of::<i32>() as libc::socklen_t;
        libc::getsockopt(fd, level, name, (&mut got as *mut i32).cast(), &mut len);
        assert_eq!(got, value);
        let mut sin: libc::sockaddr_in = std::mem::zeroed();
        sin.sin_family = libc::AF_INET as _;
        sin.sin_port = dest.port().to_be();
        sin.sin_addr.s_addr = u32::from(*dest.ip()).to_be();
        let rc = libc::connect(
            fd,
            (&sin as *const libc::sockaddr_in).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        let result = if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        };
        libc::close(fd);
        result
    }
}

#[cfg(windows)]
fn connect_with_option(dest: SocketAddr, level: i32, name: i32, value: i32) -> io::Result<()> {
    use windows_sys::Win32::Networking::WinSock as ws;
    let SocketAddr::V4(dest) = dest else {
        unreachable!()
    };
    std::net::UdpSocket::bind("127.0.0.1:0").ok();
    unsafe {
        let s = ws::socket(ws::AF_INET as i32, ws::SOCK_STREAM, 0);
        assert_ne!(s, ws::INVALID_SOCKET);
        let rc = ws::setsockopt(
            s,
            level,
            name,
            (&value as *const i32).cast(),
            size_of::<i32>() as i32,
        );
        assert_eq!(rc, 0, "setsockopt: {}", ws::WSAGetLastError());
        let mut sin: ws::SOCKADDR_IN = std::mem::zeroed();
        sin.sin_family = ws::AF_INET;
        sin.sin_port = dest.port().to_be();
        sin.sin_addr.S_un.S_addr = u32::from(*dest.ip()).to_be();
        let rc = ws::connect(
            s,
            (&sin as *const ws::SOCKADDR_IN).cast(),
            size_of::<ws::SOCKADDR_IN>() as i32,
        );
        let result = if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(ws::WSAGetLastError()))
        };
        ws::closesocket(s);
        result
    }
}

#[test]
fn per_socket_syn_option_shortens_span() {
    #[cfg(target_os = "linux")]
    let (name, value, after) = (libc::TCP_SYNCNT, 2, 7 * SECOND);
    #[cfg(target_os = "macos")]
    let (name, value, after) = (0x20, 10, 10 * SECOND);
    #[cfg(windows)]
    let (name, value, after) = (5, 5, 5 * SECOND);
    Sim::new().run(|| {
        let (result, elapsed) =
            timed(|| connect_with_option(addr("10.255.0.1:80"), 6, name, value));
        assert_eq!(result.unwrap_err().raw_os_error(), Some(ETIMEDOUT));
        assert!(about(elapsed, after), "gave up after {elapsed:?}");
    });
}

#[cfg(windows)]
#[test]
fn extended_and_indefinite_maxrt_retry_until_a_listener_answers() {
    for timeout in [240, -1] {
        for deterministic in [false, true] {
            let sim = if deterministic {
                Sim::builder().deterministic().seed(7).build()
            } else {
                Sim::new()
            };
            sim.run(|| {
                let at = addr("127.0.0.7:7420");
                let _listener = TcpListener::bind(at).unwrap();
                set_listener_behavior(
                    at,
                    ListenerBehavior::DelayingUntil(Instant::now() + 200 * SECOND),
                );
                let (result, elapsed) = timed(|| connect_with_option(at, 6, 5, timeout));
                result.unwrap();
                assert!(
                    about(elapsed, 213 * SECOND),
                    "timeout={timeout}, elapsed={elapsed:?}"
                );
            });
        }
    }
}

#[test]
fn mio_nonblocking_connect_reports_error_event() {
    use mio::{Events, Interest, Poll, Token};
    Sim::new().run(|| {
        let mut poll = Poll::new().unwrap();
        let mut stream = mio::net::TcpStream::connect(addr("10.255.0.1:80")).unwrap();
        poll.registry()
            .register(
                &mut stream,
                Token(1),
                Interest::READABLE | Interest::WRITABLE,
            )
            .unwrap();
        let mut events = Events::with_capacity(4);
        let start = Instant::now();
        let error = loop {
            poll.poll(&mut events, None).unwrap();
            if let Some(event) = events.iter().find(|e| e.token() == Token(1)) {
                assert!(event.is_error() || event.is_write_closed(), "{event:?}");
                break stream.take_error().unwrap().expect("SO_ERROR set");
            }
        };
        assert_eq!(error.raw_os_error(), Some(ETIMEDOUT));
        assert!(about(start.elapsed(), GIVE_UP), "{:?}", start.elapsed());
        assert!(
            stream.take_error().unwrap().is_none(),
            "SO_ERROR clears once read"
        );
    });
}

#[cfg(unix)]
#[test]
fn nonblocking_connect_in_progress_then_already_then_isconn() {
    use std::os::fd::AsRawFd;
    Sim::new().run(|| {
        let at = addr("127.0.0.7:7350");
        let listener = TcpListener::bind(at).unwrap();
        let until = Instant::now() + Duration::from_millis(500);
        set_listener_behavior(at, ListenerBehavior::DelayingUntil(until));
        let stream = mio::net::TcpStream::connect(at).unwrap();
        let fd = stream.as_raw_fd();
        let connect = || unsafe {
            let SocketAddr::V4(v4) = at else {
                unreachable!()
            };
            let mut sin: libc::sockaddr_in = std::mem::zeroed();
            sin.sin_family = libc::AF_INET as _;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
            let rc = libc::connect(
                fd,
                (&sin as *const libc::sockaddr_in).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            (rc == 0)
                .then_some(0)
                .ok_or_else(|| io::Error::last_os_error().raw_os_error())
        };
        assert_eq!(connect(), Err(Some(libc::EALREADY)));
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pfd, 1, -1) };
        assert_eq!(ready, 1);
        assert_eq!(pfd.revents, libc::POLLOUT);
        assert!(stream.take_error().unwrap().is_none());
        assert_eq!(connect(), Err(Some(libc::EISCONN)));
        listener.accept().unwrap();
    });
}

#[cfg(windows)]
#[test]
fn nonblocking_connect_wouldblock_then_wsapoll_err() {
    use windows_sys::Win32::Networking::WinSock as ws;
    Sim::new().run(|| {
        let at = addr("127.0.0.7:7360");
        let _listener = TcpListener::bind(at).unwrap();
        set_listener_behavior(at, ListenerBehavior::Refusing);
        let SocketAddr::V4(v4) = at else {
            unreachable!()
        };
        unsafe {
            let s = ws::socket(ws::AF_INET as i32, ws::SOCK_STREAM, 0);
            let mut on: u32 = 1;
            assert_eq!(ws::ioctlsocket(s, ws::FIONBIO, &mut on), 0);
            let mut sin: ws::SOCKADDR_IN = std::mem::zeroed();
            sin.sin_family = ws::AF_INET;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.S_un.S_addr = u32::from(*v4.ip()).to_be();
            let rc = ws::connect(
                s,
                (&sin as *const ws::SOCKADDR_IN).cast(),
                size_of::<ws::SOCKADDR_IN>() as i32,
            );
            assert_eq!(rc, ws::SOCKET_ERROR);
            assert_eq!(ws::WSAGetLastError(), ws::WSAEWOULDBLOCK);
            let mut pfd = ws::WSAPOLLFD {
                fd: s,
                events: ws::POLLWRNORM,
                revents: 0,
            };
            let start = Instant::now();
            assert_eq!(ws::WSAPoll(&mut pfd, 1, -1), 1);
            assert!(
                about(start.elapsed(), REFUSED_AFTER),
                "{:?}",
                start.elapsed()
            );
            assert_eq!(pfd.revents, ws::POLLERR | ws::POLLHUP);
            let mut code = 0i32;
            let mut len = size_of::<i32>() as i32;
            ws::getsockopt(
                s,
                ws::SOL_SOCKET,
                ws::SO_ERROR,
                (&mut code as *mut i32).cast(),
                &mut len,
            );
            assert_eq!(code, ECONNREFUSED);
            ws::closesocket(s);
        }
    });
}

#[test]
fn connect_timeout_under_wall_clock_times_out_in_real_time() {
    Sim::builder().wall_clock().build().run(|| {
        let start = snare::real(Instant::now);
        let err = TcpStream::connect_timeout(&addr("10.255.0.1:80"), Duration::from_millis(300))
            .unwrap_err();
        let elapsed = snare::real(|| start.elapsed());
        assert_eq!(err.kind(), ErrorKind::TimedOut);
        // The sim's clock charges each call that does not block, so it may run a little ahead.
        assert!(elapsed >= Duration::from_millis(250), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    });
}

#[test]
fn tester_action_set_listener_behavior() {
    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.7:7370")
            .then_action(|msg, _| match msg.0.as_str() {
                "refuse" => TesterAction::Multiple(vec![
                    TesterAction::SetListenerBehavior(ListenerBehavior::Refusing),
                    TesterAction::Send(Line("ok".into())),
                ]),
                _ => TesterAction::Nothing,
            })
            .until_after(Duration::from_secs(10));
        let client = std::thread::spawn(|| {
            let mut stream = TcpStream::connect("127.0.0.7:7370").unwrap();
            stream.write_all(b"refuse\n").unwrap();
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            assert_eq!(line, "ok\n");
            TcpStream::connect("127.0.0.7:7370").map(drop)
        });
        run_testers!(server);
        let refused = client.join().unwrap().unwrap_err();
        assert_eq!(refused.kind(), ErrorKind::ConnectionRefused);
    });
}

#[test]
fn sim_method_works_outside_run() {
    let sim = Sim::new();
    sim.set_listener_behavior("127.0.0.7:7380", ListenerBehavior::Refusing);
    let delay = Instant::now() + Duration::from_millis(1500);
    sim.set_listener_behavior("127.0.0.7:7381", ListenerBehavior::DelayingUntil(delay));
    let expected = Duration::from_secs(if cfg!(windows) { 3 } else { 2 });
    sim.run(|| {
        let _refusing = TcpListener::bind("127.0.0.7:7380").unwrap();
        let _delaying = TcpListener::bind("127.0.0.7:7381").unwrap();
        let (stream, elapsed) = timed(|| TcpStream::connect("127.0.0.7:7381"));
        stream.unwrap();
        assert!(about(elapsed, expected), "connected after {elapsed:?}");
        let refused = TcpStream::connect("127.0.0.7:7380").unwrap_err();
        assert_eq!(refused.kind(), ErrorKind::ConnectionRefused);
    });
}

#[test]
fn connect_faults_are_recorded() {
    let sim = Sim::new();
    sim.run(|| {
        let refusing = addr("127.0.0.7:7390");
        let delaying = addr("127.0.0.7:7391");
        let _l1 = TcpListener::bind(refusing).unwrap();
        let _l2 = TcpListener::bind(delaying).unwrap();
        set_listener_behavior(refusing, ListenerBehavior::Refusing);
        TcpStream::connect(refusing).unwrap_err();
        let until = Instant::now() + Duration::from_millis(500);
        set_listener_behavior(delaying, ListenerBehavior::DelayingUntil(until));
        TcpStream::connect(delaying).unwrap();
        TcpStream::connect("10.255.0.1:80").unwrap_err();
        let faults: Vec<(Option<SocketAddr>, Fault)> = recorded_events()
            .into_iter()
            .filter_map(|e| match e.event {
                RecordedEvent::Fault { addr, fault } => Some((addr, fault)),
                _ => None,
            })
            .collect();
        assert_eq!(faults.len(), 3, "{faults:?}");
        assert_eq!(faults[0], (Some(refusing), Fault::ConnectRefused));
        assert!(
            matches!(faults[1], (Some(a), Fault::ConnectDelayed { .. }) if a == delaying),
            "{faults:?}"
        );
        assert_eq!(
            faults[2],
            (Some(addr("10.255.0.1:80")), Fault::ConnectTimedOut)
        );
    });
}

#[test]
fn existing_refused_connect_tests_stay_green() {
    let net: IpNet = "192.168.78.1/24".parse().unwrap();
    let sim = Sim::builder()
        .nic(
            NicSpec::new("eth0")
                .address(net)
                .station(addr("192.168.78.9:0").ip()),
        )
        .build();
    sim.run(|| {
        for dest in ["127.0.0.1:1", "192.168.78.1:2", "192.168.78.9:3"] {
            let (err, elapsed) = timed(|| TcpStream::connect(dest).unwrap_err());
            assert_eq!(err.kind(), ErrorKind::ConnectionRefused, "{dest}");
            assert!(
                about(elapsed, REFUSED_AFTER),
                "{dest} refused after {elapsed:?}"
            );
        }
    });
}

/// Calibrates the constants above against the real OS: a connect to a closed loopback port is
/// refused at once on unix and after about 2 s on Windows.
#[test]
fn real_os_refusal_timing_calibration() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let (err, elapsed) = timed(|| TcpStream::connect(("127.0.0.1", port)).unwrap_err());
    assert_eq!(err.raw_os_error(), Some(ECONNREFUSED));
    eprintln!("refused after {elapsed:?}");
    if cfg!(windows) {
        assert!(elapsed > Duration::from_millis(1500) && elapsed < Duration::from_millis(3000));
    } else {
        assert!(elapsed < Duration::from_millis(100));
    }
}

/// Connects to an unused address on the primary NIC's subnet, bound to that NIC so no VPN route
/// answers instead, and prints how the real OS fails. Pass the interface and the absent address
/// in `SNARE_ON_LINK_IF` and `SNARE_ON_LINK_ADDR` (e.g. `en0` and `192.168.0.233:80`). Linux
/// accepts `SNARE_ON_LINK_SYN_RETRIES` to bound the SYN retry budget for calibration.
#[cfg(unix)]
#[test]
#[ignore = "needs SNARE_ON_LINK_IF and SNARE_ON_LINK_ADDR naming a real NIC and an absent on-link address"]
fn real_os_on_link_absent_calibration() {
    let ifname = std::env::var("SNARE_ON_LINK_IF").expect("SNARE_ON_LINK_IF");
    let dest: std::net::SocketAddrV4 = std::env::var("SNARE_ON_LINK_ADDR")
        .expect("SNARE_ON_LINK_ADDR")
        .parse()
        .unwrap();
    let cname = std::ffi::CString::new(ifname).unwrap();
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0, "{}", io::Error::last_os_error());
    #[cfg(target_os = "macos")]
    let rc = {
        let index = unsafe { libc::if_nametoindex(cname.as_ptr()) } as libc::c_int;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_BOUND_IF,
                (&index as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        }
    };
    #[cfg(target_os = "linux")]
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            cname.as_ptr().cast(),
            cname.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "{}", io::Error::last_os_error());
    #[cfg(target_os = "linux")]
    if let Ok(value) = std::env::var("SNARE_ON_LINK_SYN_RETRIES") {
        let retries: libc::c_int = value.parse().unwrap();
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_SYNCNT,
                    std::ptr::from_ref(&retries).cast(),
                    size_of::<libc::c_int>() as libc::socklen_t,
                )
            },
            0,
            "{}",
            io::Error::last_os_error()
        );
    }
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "macos")]
    {
        sin.sin_len = size_of::<libc::sockaddr_in>() as u8;
    }
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_port = dest.port().to_be();
    sin.sin_addr.s_addr = u32::from(*dest.ip()).to_be();
    let (err, elapsed) = timed(|| {
        let rc = unsafe {
            libc::connect(
                fd,
                (&sin as *const libc::sockaddr_in).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        assert_ne!(rc, 0, "connected to {dest}");
        io::Error::last_os_error()
    });
    unsafe { libc::close(fd) };
    eprintln!("on-link absent {dest}: {err} after {elapsed:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn simhost_tcp_syn_retries_sets_the_span() {
    for (linear, expected) in [(0, 15), (4, 19)] {
        let mut limits = snare::SysLimits::host();
        limits.tcp_syn_retries = 3;
        limits.tcp_syn_linear_timeouts = linear;
        let host = snare::HostProfile::new().build();
        Sim::builder()
            .host(host)
            .sys_limits(limits)
            .build()
            .run(|| {
                let shown = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_syn_retries").unwrap();
                assert_eq!(shown, "3\n");
                let shown =
                    std::fs::read_to_string("/proc/sys/net/ipv4/tcp_syn_linear_timeouts").unwrap();
                assert_eq!(shown, format!("{linear}\n"));
                let (err, elapsed) = timed(|| TcpStream::connect("10.255.0.1:80").unwrap_err());
                assert_eq!(err.raw_os_error(), Some(ETIMEDOUT));
                assert!(
                    about(elapsed, expected * SECOND),
                    "gave up after {elapsed:?}"
                );
            });
    }
}

#[test]
fn closing_a_connecting_socket_calls_off_its_syn_timers() {
    Sim::new().run(|| {
        let err = TcpStream::connect_timeout(&addr("10.255.0.1:80"), Duration::from_millis(100))
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::TimedOut);
        let socket = std::net::UdpSocket::bind("127.0.0.7:7410").unwrap();
        let (received, elapsed) = timed(|| socket.recv(&mut [0u8; 8]));
        assert!(received.is_err(), "nothing ever sends here");
        assert!(
            elapsed < SECOND,
            "time skipped to a stale SYN timer: {elapsed:?}"
        );
    });
}
