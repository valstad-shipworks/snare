#![cfg(unix)]

//! Hermetic name resolution: `getaddrinfo`, `getnameinfo` and `gethostbyname` answered from the
//! sim's host table and a built-in localhost, with the host's own error codes, and numeric hosts
//! and hints left to the real libc. The oracle tests compare against the real resolver through
//! `snare::real`.

use std::collections::BTreeSet;
use std::ffi::{CStr, CString, c_char, c_int};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{mem, ptr};

use snare::{
    Bytes, DnsFailure, Fault, Line, RecordedEvent, Sim, TesterAction, add_host, connect_tester,
    run_testers, set_dns_policy, set_udp_policy, udp_tester,
};

unsafe extern "C" {
    fn gethostbyname(name: *const c_char) -> *mut libc::hostent;
}

#[cfg(target_os = "linux")]
fn h_errno() -> c_int {
    unsafe extern "C" {
        fn __h_errno_location() -> *mut c_int;
    }
    unsafe { *__h_errno_location() }
}

#[cfg(target_os = "macos")]
fn h_errno() -> c_int {
    unsafe extern "C" {
        static h_errno: c_int;
    }
    unsafe { h_errno }
}

const HOST_NOT_FOUND: c_int = 1;
const NO_DATA: c_int = 4;

fn v4(text: &str) -> IpAddr {
    IpAddr::V4(text.parse::<Ipv4Addr>().unwrap())
}

fn v6(text: &str) -> IpAddr {
    IpAddr::V6(text.parse::<Ipv6Addr>().unwrap())
}

/// One `addrinfo` node, as compared between the sim and the real resolver.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Node {
    family: c_int,
    socktype: c_int,
    protocol: c_int,
    addr: String,
    canon: Option<String>,
}

fn sockaddr_text(addr: *const libc::sockaddr, len: libc::socklen_t) -> String {
    let mut host = [0 as c_char; 128];
    let mut serv = [0 as c_char; 32];
    let rc = unsafe {
        libc::getnameinfo(
            addr,
            len,
            host.as_mut_ptr(),
            host.len() as _,
            serv.as_mut_ptr(),
            serv.len() as _,
            libc::NI_NUMERICHOST | libc::NI_NUMERICSERV,
        )
    };
    assert_eq!(rc, 0);
    let host = unsafe { CStr::from_ptr(host.as_ptr()) }.to_string_lossy();
    let serv = unsafe { CStr::from_ptr(serv.as_ptr()) }.to_string_lossy();
    format!("{host} {serv}")
}

/// `getaddrinfo` with the given hints, as nodes or the return code.
fn gai(
    node: Option<&str>,
    service: Option<&str>,
    family: c_int,
    socktype: c_int,
    flags: c_int,
) -> Result<Vec<Node>, c_int> {
    let node = node.map(|n| CString::new(n).unwrap());
    let service = service.map(|s| CString::new(s).unwrap());
    let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_flags = flags;
    let mut list = ptr::null_mut();
    let rc = unsafe {
        libc::getaddrinfo(
            node.as_ref().map_or(ptr::null(), |n| n.as_ptr()),
            service.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            &hints,
            &mut list,
        )
    };
    if rc != 0 {
        return Err(rc);
    }
    let mut nodes = Vec::new();
    let mut at = list;
    while !at.is_null() {
        let n = unsafe { &*at };
        nodes.push(Node {
            family: n.ai_family,
            socktype: n.ai_socktype,
            protocol: n.ai_protocol,
            addr: sockaddr_text(n.ai_addr, n.ai_addrlen),
            canon: (!n.ai_canonname.is_null()).then(|| {
                unsafe { CStr::from_ptr(n.ai_canonname) }
                    .to_string_lossy()
                    .into_owned()
            }),
        });
        at = n.ai_next;
    }
    unsafe { libc::freeaddrinfo(list) };
    Ok(nodes)
}

fn addrs(name: &str) -> BTreeSet<IpAddr> {
    (name, 0)
        .to_socket_addrs()
        .unwrap()
        .map(|a| a.ip())
        .collect()
}

#[test]
fn localhost_matches_host_resolver() {
    let real = snare::real(|| addrs("localhost"));
    let sim = Sim::new().run(|| addrs("localhost"));
    assert_eq!(sim, real);
    assert_eq!(sim, BTreeSet::from([v6("::1"), v4("127.0.0.1")]));
}

#[test]
fn add_host_resolves_names() {
    let sim = Sim::builder()
        .add_host("robot1.local", [v4("127.0.0.20")])
        .build();
    sim.run(|| {
        add_host("cam.local", [v4("127.0.0.21")]);
        let robot = connect_tester::<Line>("robot1.local:9000")
            .then_action(|msg, _| TesterAction::Send(Line(format!("ok:{}", msg.0))))
            .until_after(Duration::from_millis(200));
        let cam = udp_tester::<Bytes>("cam.local:9001")
            .then_action(|msg, _| TesterAction::Send(msg))
            .until_after(Duration::from_millis(200));
        let client = std::thread::spawn(|| {
            let mut tcp = TcpStream::connect("ROBOT1.local.:9000").unwrap();
            assert_eq!(tcp.peer_addr().unwrap(), "127.0.0.20:9000".parse().unwrap());
            tcp.write_all(b"go\n").unwrap();
            let mut line = String::new();
            BufReader::new(tcp).read_line(&mut line).unwrap();
            let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            udp.send_to(b"ping", "cam.local:9001").unwrap();
            let mut buf = [0u8; 16];
            let (n, from) = udp.recv_from(&mut buf).unwrap();
            assert_eq!(from, "127.0.0.21:9001".parse().unwrap());
            (line, buf[..n].to_vec())
        });
        run_testers!(robot, cam);
        let (line, echo) = client.join().unwrap();
        assert_eq!(line, "ok:go\n");
        assert_eq!(echo, b"ping");
    });
}

#[test]
fn multi_address_fallthrough() {
    Sim::new().run(|| {
        add_host("multi.local", [v4("127.0.0.30"), v4("127.0.0.31")]);
        let server = connect_tester::<Line>("127.0.0.31:9000")
            .then_action(|_, _| TesterAction::Send(Line("hi".into())))
            .until_after(Duration::from_millis(200));
        let client = std::thread::spawn(|| {
            let mut tcp = TcpStream::connect("multi.local:9000").unwrap();
            let peer = tcp.peer_addr().unwrap();
            tcp.write_all(b"x\n").unwrap();
            let mut line = String::new();
            BufReader::new(tcp).read_line(&mut line).unwrap();
            peer
        });
        run_testers!(server);
        assert_eq!(client.join().unwrap(), "127.0.0.31:9000".parse().unwrap());
    });
}

#[test]
fn unknown_name_is_eai_noname() {
    let expected = snare::real(|| unsafe { CStr::from_ptr(libc::gai_strerror(libc::EAI_NONAME)) })
        .to_string_lossy()
        .into_owned();
    Sim::new().run(|| {
        let start = snare::real(Instant::now);
        let err = ("robot9.invalid", 80).to_socket_addrs().unwrap_err();
        assert!(err.to_string().contains(&expected), "{err}");
        assert_eq!(
            gai(Some("robot9.invalid"), Some("80"), 0, libc::SOCK_STREAM, 0),
            Err(libc::EAI_NONAME)
        );
        assert!(snare::real(|| start.elapsed()) < Duration::from_millis(500));
    });
}

#[test]
fn numeric_passthrough_matches_os() {
    let scoped = if cfg!(target_os = "macos") {
        "fe80::1%lo0"
    } else {
        "fe80::1%lo"
    };
    let cases: Vec<(Option<&str>, Option<&str>, c_int, c_int)> = vec![
        (Some("127.1"), Some("80"), libc::AF_UNSPEC, 0),
        (Some("::1"), Some("80"), libc::AF_INET, 0),
        (Some("::1"), Some("80"), libc::AF_INET, libc::AI_NUMERICHOST),
        (Some(scoped), Some("80"), libc::AF_UNSPEC, 0),
        (None, Some("80"), libc::AF_UNSPEC, libc::AI_PASSIVE),
        (None, Some("80"), libc::AF_INET6, 0),
        (
            Some("10.1.2.3"),
            Some("http"),
            libc::AF_INET6,
            libc::AI_V4MAPPED,
        ),
        (
            Some("localhost"),
            Some("80"),
            libc::AF_UNSPEC,
            libc::AI_NUMERICHOST,
        ),
        (Some("1.2.3.4"), Some("no-such-service"), libc::AF_UNSPEC, 0),
    ];
    for (node, service, family, flags) in cases {
        for socktype in [0, libc::SOCK_STREAM, libc::SOCK_DGRAM] {
            let real = snare::real(|| gai(node, service, family, socktype, flags));
            let sim = Sim::new().run(|| gai(node, service, family, socktype, flags));
            assert_eq!(
                sim, real,
                "{node:?} {service:?} {family} {socktype} {flags:#x}"
            );
        }
    }
    let real: Vec<SocketAddr> = snare::real(|| "[::1]:0".to_socket_addrs().unwrap().collect());
    let sim: Vec<SocketAddr> = Sim::new().run(|| "[::1]:0".to_socket_addrs().unwrap().collect());
    assert_eq!(sim, real);
}

/// A table name holding exactly localhost's addresses answers every hint combination as the real
/// resolver answers localhost, order and repeats aside: the real one sorts per RFC 6724, and
/// glibc's files backend also answers an AF_INET query with 127.0.0.1 for its `::1` line.
#[test]
fn hints_follow_os_semantics() {
    let sim = Sim::builder()
        .add_host("twin.local", [v6("::1"), v4("127.0.0.1")])
        .build();
    let mut flagsets = vec![0, libc::AI_PASSIVE, libc::AI_NUMERICSERV, libc::AI_V4MAPPED];
    if cfg!(target_os = "macos") {
        flagsets.push(libc::AI_ALL);
    }
    for family in [libc::AF_UNSPEC, libc::AF_INET, libc::AF_INET6] {
        for socktype in [0, libc::SOCK_STREAM, libc::SOCK_DGRAM] {
            for &flags in &flagsets {
                for service in [None, Some("80"), Some("http")] {
                    let sorted = |r: Result<Vec<Node>, c_int>| {
                        r.map(|mut v| {
                            v.sort();
                            v.dedup();
                            v
                        })
                    };
                    let real = sorted(snare::real(|| {
                        gai(Some("localhost"), service, family, socktype, flags)
                    }));
                    let got = sorted(
                        sim.run(|| gai(Some("twin.local"), service, family, socktype, flags)),
                    );
                    assert_eq!(got, real, "{family} {socktype} {flags:#x} {service:?}");
                }
            }
        }
    }
}

#[test]
fn v4mapped_rules() {
    let sim = Sim::builder()
        .add_host("dual.local", [v4("127.0.0.40"), v6("fd00::40")])
        .add_host("four.local", [v4("127.0.0.41")])
        .build();
    sim.run(|| {
        let addrs = |name, flags| {
            gai(
                Some(name),
                Some("80"),
                libc::AF_INET6,
                libc::SOCK_STREAM,
                flags,
            )
            .map(|v| v.into_iter().map(|n| n.addr).collect::<Vec<_>>())
        };
        assert_eq!(
            addrs("four.local", libc::AI_V4MAPPED),
            Ok(vec!["::ffff:127.0.0.41 80".to_string()])
        );
        assert_eq!(
            addrs("dual.local", libc::AI_V4MAPPED),
            Ok(vec!["fd00::40 80".to_string()])
        );
        assert_eq!(
            addrs("dual.local", libc::AI_V4MAPPED | libc::AI_ALL),
            Ok(vec![
                "fd00::40 80".to_string(),
                "::ffff:127.0.0.41 80".replace("41", "40")
            ])
        );
        let unmapped = addrs("four.local", 0);
        if cfg!(target_os = "macos") {
            assert_eq!(unmapped, Ok(vec!["::ffff:127.0.0.41 80".to_string()]));
        } else {
            assert_eq!(unmapped, Err(libc::EAI_NONAME));
        }
        let real = snare::real(|| {
            gai(
                Some("127.0.0.41"),
                Some("80"),
                libc::AF_INET,
                0,
                libc::AI_V4MAPPED,
            )
        });
        assert_eq!(
            gai(
                Some("four.local"),
                Some("80"),
                libc::AF_INET,
                0,
                libc::AI_V4MAPPED
            ),
            real
        );
    });
}

#[test]
fn family_mismatch_is_eai_noname() {
    let real = if cfg!(target_os = "macos") {
        snare::real(|| {
            gai(
                Some("broadcasthost"),
                Some("80"),
                libc::AF_INET6,
                0,
                libc::AI_ADDRCONFIG,
            )
        })
    } else {
        snare::real(|| gai(Some("ip6-allnodes"), Some("80"), libc::AF_INET, 0, 0))
    };
    assert_eq!(real, Err(libc::EAI_NONAME));
    let sim = Sim::builder()
        .add_host("six.local", [v6("fd00::6")])
        .build();
    sim.run(|| {
        assert_eq!(
            gai(Some("six.local"), Some("80"), libc::AF_INET, 0, 0),
            Err(libc::EAI_NONAME)
        );
        add_host("none.local", []);
        assert_eq!(
            gai(Some("none.local"), Some("80"), libc::AF_UNSPEC, 0, 0),
            Err(libc::EAI_NONAME)
        );
    });
}

fn name_info(addr: SocketAddr, host_len: usize, flags: c_int) -> Result<(String, String), c_int> {
    let (storage, len) = match addr {
        SocketAddr::V4(a) => {
            let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
            sin.sin_family = libc::AF_INET as _;
            sin.sin_port = a.port().to_be();
            sin.sin_addr.s_addr = u32::from(*a.ip()).to_be();
            #[cfg(target_os = "macos")]
            {
                sin.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
            }
            let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
            unsafe { ptr::write((&raw mut storage).cast(), sin) };
            (storage, mem::size_of::<libc::sockaddr_in>())
        }
        SocketAddr::V6(a) => {
            let mut sin6: libc::sockaddr_in6 = unsafe { mem::zeroed() };
            sin6.sin6_family = libc::AF_INET6 as _;
            sin6.sin6_port = a.port().to_be();
            sin6.sin6_addr.s6_addr = a.ip().octets();
            #[cfg(target_os = "macos")]
            {
                sin6.sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
            }
            let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
            unsafe { ptr::write((&raw mut storage).cast(), sin6) };
            (storage, mem::size_of::<libc::sockaddr_in6>())
        }
    };
    let mut host = vec![0 as c_char; host_len];
    let mut serv = [0 as c_char; 32];
    let rc = unsafe {
        libc::getnameinfo(
            (&raw const storage).cast(),
            len as _,
            host.as_mut_ptr(),
            host_len as _,
            serv.as_mut_ptr(),
            serv.len() as _,
            flags,
        )
    };
    if rc != 0 {
        return Err(rc);
    }
    let text = |p: *const c_char| unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    Ok((text(host.as_ptr()), text(serv.as_ptr())))
}

#[test]
fn getnameinfo_reverse() {
    let sim = Sim::builder()
        .add_host("robot1.local", [v4("127.0.0.20")])
        .build();
    let real_http = snare::real(|| name_info("127.0.0.1:80".parse().unwrap(), 64, 0))
        .unwrap()
        .1;
    sim.run(|| {
        assert_eq!(
            name_info("127.0.0.20:80".parse().unwrap(), 64, 0),
            Ok(("robot1.local".into(), real_http.clone()))
        );
        assert_eq!(
            name_info(
                "[::ffff:127.0.0.20]:80".parse().unwrap(),
                64,
                libc::NI_NUMERICSERV
            ),
            Ok(("robot1.local".into(), "80".into()))
        );
        assert_eq!(
            name_info("127.0.0.20:80".parse().unwrap(), 5, 0),
            Err(libc::EAI_OVERFLOW)
        );
        assert_eq!(
            name_info("127.0.0.20:80".parse().unwrap(), 64, libc::NI_NUMERICHOST),
            Ok(("127.0.0.20".into(), real_http.clone()))
        );
        assert_eq!(
            name_info("127.0.0.99:80".parse().unwrap(), 64, 0),
            Ok(("127.0.0.99".into(), real_http.clone()))
        );
        assert_eq!(
            name_info("127.0.0.99:80".parse().unwrap(), 64, libc::NI_NAMEREQD),
            Err(libc::EAI_NONAME)
        );
        assert_eq!(
            name_info("127.0.0.1:80".parse().unwrap(), 64, libc::NI_NUMERICSERV),
            Ok(("localhost".into(), "80".into()))
        );
        assert_eq!(
            name_info("[::1]:80".parse().unwrap(), 64, libc::NI_NUMERICSERV),
            Ok(("localhost".into(), "80".into()))
        );
    });
    let real = snare::real(|| name_info("127.0.0.1:80".parse().unwrap(), 64, libc::NI_NUMERICSERV));
    assert_eq!(real, Ok(("localhost".into(), "80".into())));
}

fn host_by_name(name: &str) -> Result<(String, Vec<Ipv4Addr>), c_int> {
    let name = CString::new(name).unwrap();
    let entry = unsafe { gethostbyname(name.as_ptr()) };
    if entry.is_null() {
        return Err(h_errno());
    }
    let entry = unsafe { &*entry };
    assert_eq!(entry.h_addrtype, libc::AF_INET);
    assert_eq!(entry.h_length, 4);
    let mut addrs = Vec::new();
    let mut at = entry.h_addr_list;
    unsafe {
        while !at.read_unaligned().is_null() {
            let mut octets = [0u8; 4];
            ptr::copy_nonoverlapping(at.read_unaligned().cast::<u8>(), octets.as_mut_ptr(), 4);
            addrs.push(Ipv4Addr::from(octets));
            at = at.add(1);
        }
    }
    let name = unsafe { CStr::from_ptr(entry.h_name) }
        .to_string_lossy()
        .into_owned();
    Ok((name, addrs))
}

#[test]
fn gethostbyname_sim() {
    let sim = Sim::builder()
        .add_host(
            "Robot1.local",
            [v6("fd00::1"), v4("127.0.0.20"), v4("127.0.0.21")],
        )
        .add_host("six.local", [v6("fd00::6")])
        .build();
    sim.run(|| {
        assert_eq!(
            host_by_name("robot1.LOCAL"),
            Ok((
                "Robot1.local".into(),
                vec![Ipv4Addr::new(127, 0, 0, 20), Ipv4Addr::new(127, 0, 0, 21)]
            ))
        );
        assert_eq!(host_by_name("six.local"), Err(NO_DATA));
        assert_eq!(host_by_name("robot9.invalid"), Err(HOST_NOT_FOUND));
        let numeric = host_by_name("127.0.0.5").unwrap();
        assert_eq!(numeric.1, vec![Ipv4Addr::new(127, 0, 0, 5)]);
        set_dns_policy("robot1.local", |p| p.failure = Some(DnsFailure::TryAgain));
        assert_eq!(host_by_name("robot1.local"), Err(2));
    });
}

#[test]
fn dns_latency_is_virtual() {
    Sim::new().run(|| {
        add_host("slow.local", [v4("127.0.0.60")]);
        set_dns_policy("slow.local", |p| p.latency = Duration::from_secs(5));
        let real = snare::real(Instant::now);
        let start = Instant::now();
        let found = addrs("slow.local");
        assert_eq!(found, BTreeSet::from([v4("127.0.0.60")]));
        let virtual_elapsed = start.elapsed();
        assert!(
            virtual_elapsed >= Duration::from_secs(5),
            "{virtual_elapsed:?}"
        );
        assert!(
            virtual_elapsed < Duration::from_secs(6),
            "{virtual_elapsed:?}"
        );
        assert!(snare::real(|| real.elapsed()) < Duration::from_secs(1));
    });
}

fn latency_trace(seed: u64) -> Vec<(usize, Duration, bool)> {
    let sim = Sim::builder().deterministic().seed(seed).build();
    sim.run(|| {
        for (i, ms) in [7u64, 3, 5].into_iter().enumerate() {
            let name = format!("node{i}.local");
            add_host(&name, [v4(&format!("127.0.0.{}", 70 + i))]);
            set_dns_policy(&name, |p| {
                p.latency = Duration::from_millis(ms);
                p.failure_rate = 0.3;
            });
        }
        let log = Arc::new(Mutex::new(Vec::new()));
        let start = Instant::now();
        let workers: Vec<_> = (0..3)
            .map(|i| {
                let log = log.clone();
                std::thread::spawn(move || {
                    for _ in 0..4 {
                        let ok = (format!("node{i}.local"), 0).to_socket_addrs().is_ok();
                        log.lock().unwrap().push((i, start.elapsed(), ok));
                    }
                })
            })
            .collect();
        for w in workers {
            w.join().unwrap();
        }
        Arc::try_unwrap(log).unwrap().into_inner().unwrap()
    })
}

#[test]
fn dns_latency_deterministic() {
    let first = latency_trace(11);
    assert_eq!(first.len(), 12);
    assert_eq!(first, latency_trace(11));
    let at =
        |i: usize| -> Vec<Duration> { first.iter().filter(|e| e.0 == i).map(|e| e.1).collect() };
    let rounded = |d: Duration| d.as_millis() as u64;
    assert_eq!(
        at(1).into_iter().map(rounded).collect::<Vec<_>>(),
        [3, 6, 9, 12]
    );
    assert_eq!(
        at(0).into_iter().map(rounded).collect::<Vec<_>>(),
        [7, 14, 21, 28]
    );
}

fn failure_trace(seed: u64) -> (Vec<Result<usize, c_int>>, usize) {
    let sim = Sim::builder()
        .seed(seed)
        .add_host("flaky.local", [v4("127.0.0.80")])
        .build();
    let results = sim.run(|| {
        set_dns_policy("flaky.local", |p| p.failure_rate = 0.5);
        (0..40)
            .map(|_| gai(Some("flaky.local"), None, 0, libc::SOCK_STREAM, 0).map(|v| v.len()))
            .collect::<Vec<_>>()
    });
    let faults = sim
        .recorded_events()
        .iter()
        .filter(|e| {
            matches!(
                &e.event,
                RecordedEvent::Fault {
                    fault: Fault::Dns { name, failure: DnsFailure::TryAgain },
                    ..
                } if name == "flaky.local"
            )
        })
        .count();
    (results, faults)
}

#[test]
fn dns_failures() {
    Sim::new().run(|| {
        add_host("a.local", [v4("127.0.0.81")]);
        for (failure, code) in [
            (DnsFailure::NotFound, libc::EAI_NONAME),
            (DnsFailure::TryAgain, libc::EAI_AGAIN),
            (DnsFailure::Fail, libc::EAI_FAIL),
        ] {
            set_dns_policy("a.local", |p| p.failure = Some(failure));
            assert_eq!(gai(Some("a.local"), None, 0, 0, 0), Err(code));
        }
        set_dns_policy("a.local", |p| *p = Default::default());
        assert!(gai(Some("a.local"), None, 0, 0, 0).is_ok());
        snare::set_default_dns_policy(|p| p.failure = Some(DnsFailure::Fail));
        assert_eq!(gai(Some("a.local"), None, 0, 0, 0), Err(libc::EAI_FAIL));
        assert_eq!(
            gai(Some("127.0.0.81"), None, 0, libc::SOCK_STREAM, 0).map(|v| v.len()),
            Ok(1)
        );
    });
    let (results, faults) = failure_trace(5);
    let failed = results.iter().filter(|r| r.is_err()).count();
    assert!(failed > 5 && failed < 35, "{failed} of 40 failed");
    assert!(
        results
            .iter()
            .all(|r| matches!(r, Ok(1) | Err(libc::EAI_AGAIN)))
    );
    assert_eq!(faults, failed);
    assert_eq!(failure_trace(5), (results.clone(), faults));
    assert_ne!(failure_trace(6).0, results);
}

#[test]
fn testers_and_policies_accept_names() {
    let sim = Sim::new();
    sim.add_host("cam.local", [v4("127.0.0.90")]);
    sim.run(|| {
        set_udp_policy("cam.local:9001", |p| p.loss_rate = 1.0);
        let cam = udp_tester::<Bytes>("cam.local:9001")
            .recording()
            .until_after(Duration::from_millis(100));
        let client = std::thread::spawn(|| {
            let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            udp.send_to(b"lost", "cam.local:9001").unwrap();
        });
        run_testers!(cam);
        client.join().unwrap();
        assert!(cam.recorded().is_empty());
    });
}

#[test]
fn outside_sim_untouched() {
    let sim = Sim::builder()
        .add_host("snare-outside.invalid", [v4("127.0.0.95")])
        .build();
    assert!(sim.run(|| ("snare-outside.invalid", 0).to_socket_addrs().is_ok()));
    assert!(("snare-outside.invalid", 0).to_socket_addrs().is_err());
    assert!(addrs("localhost").contains(&v4("127.0.0.1")));
}

#[test]
fn resolve_real_snapshot() {
    let name = if cfg!(target_os = "macos") {
        "broadcasthost"
    } else {
        "ip6-allnodes"
    };
    let real = snare::real(|| addrs(name));
    let sim = Sim::builder().resolve_real(name).build();
    assert_eq!(sim.run(|| addrs(name)), real);
}

#[test]
#[should_panic(expected = "resolve_real")]
fn resolve_real_failure_panics() {
    Sim::builder().resolve_real("snare-missing.invalid").build();
}

#[test]
fn real_dns_opt_in() {
    let name = if cfg!(target_os = "macos") {
        "broadcasthost"
    } else {
        "ip6-localhost"
    };
    assert!(Sim::new().run(|| (name, 0).to_socket_addrs().is_err()));
    let real = snare::real(|| addrs(name));
    assert_eq!(Sim::builder().real_dns().build().run(|| addrs(name)), real);
}

#[test]
#[should_panic(expected = "real_dns cannot be combined with deterministic")]
fn real_dns_with_deterministic_panics() {
    Sim::builder().deterministic().real_dns().build();
}

#[cfg(target_os = "linux")]
#[test]
fn simhost_coexistence() {
    let sim = Sim::builder()
        .host(snare::HostProfile::new().build())
        .add_host("plc.local", [v4("127.0.0.96")])
        .build();
    sim.run(|| {
        let plc = connect_tester::<Line>("plc.local:9800")
            .then_action(|msg, _| TesterAction::Send(Line(format!("ok:{}", msg.0))))
            .until_after(Duration::from_millis(200));
        let client = std::thread::spawn(|| {
            let mut tcp = TcpStream::connect("plc.local:9800").unwrap();
            tcp.write_all(b"go\n").unwrap();
            let mut line = String::new();
            BufReader::new(tcp).read_line(&mut line).unwrap();
            line
        });
        run_testers!(plc);
        assert_eq!(client.join().unwrap(), "ok:go\n");
        assert_eq!(
            addrs("localhost"),
            BTreeSet::from([v6("::1"), v4("127.0.0.1")])
        );
        assert!(("robot9.invalid", 0).to_socket_addrs().is_err());
    });
}

/// Resolver families and socket-type expansion against an address from the host's files backend.
#[cfg(target_os = "linux")]
#[test]
fn hosts_file_oracle() {
    let hosts = std::fs::read_to_string("/etc/hosts").unwrap();
    let mut names = std::collections::BTreeMap::<String, BTreeSet<IpAddr>>::new();
    for line in hosts.lines() {
        let mut fields = line.split('#').next().unwrap().split_whitespace();
        let Some(ip) = fields.next().and_then(|text| text.parse::<IpAddr>().ok()) else {
            continue;
        };
        for name in fields {
            names.entry(name.to_owned()).or_default().insert(ip);
        }
    }
    let candidate = names
        .iter()
        .filter(|(name, _)| !name.contains("localhost"))
        .min_by_key(|(_, addresses)| (addresses.iter().any(IpAddr::is_ipv4), addresses.len()))
        .or_else(|| names.get_key_value("localhost"));
    let (name, _) = candidate.expect("/etc/hosts contains a resolvable host name");
    let real = snare::real(|| {
        gai(
            Some(name),
            Some("80"),
            libc::AF_UNSPEC,
            libc::SOCK_STREAM,
            0,
        )
    })
    .unwrap();
    let addresses: Vec<IpAddr> = real
        .iter()
        .map(|node| node.addr.split_once(' ').unwrap().0.parse().unwrap())
        .collect();
    let sim = Sim::builder()
        .add_host("files-oracle.invalid", addresses.clone())
        .build();
    for family in [libc::AF_UNSPEC, libc::AF_INET, libc::AF_INET6] {
        let real = snare::real(|| gai(Some(name), Some("80"), family, 0, 0));
        // NSS can answer localhost differently for each requested family.
        let family_sim = (name == "localhost").then(|| {
            let addresses =
                snare::real(|| gai(Some(name), Some("80"), family, libc::SOCK_STREAM, 0))
                    .map(|nodes| {
                        nodes
                            .into_iter()
                            .map(|node| {
                                node.addr
                                    .split_once(' ')
                                    .unwrap()
                                    .0
                                    .parse::<IpAddr>()
                                    .unwrap()
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_else(|_| addresses.clone());
            Sim::builder()
                .add_host("files-oracle.invalid", addresses)
                .build()
        });
        let got = family_sim
            .as_ref()
            .unwrap_or(&sim)
            .run(|| gai(Some("files-oracle.invalid"), Some("80"), family, 0, 0));
        assert_eq!(
            got.map(|mut nodes| {
                nodes.sort();
                nodes
            }),
            real.map(|mut nodes| {
                nodes.sort();
                nodes
            }),
            "{name}, family={family}"
        );
    }
}
