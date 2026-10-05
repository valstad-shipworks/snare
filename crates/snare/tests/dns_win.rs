#![cfg(windows)]

//! Hermetic name resolution on Winsock: `getaddrinfo`, `GetAddrInfoW`, `getnameinfo`,
//! `GetNameInfoW` and `gethostbyname` answered from the sim's host table and a built-in
//! localhost, failing with the WSA codes Winsock uses, and numeric hosts and hints left to the
//! real ws2_32. The oracle tests compare against the real resolver through `snare::real`.

use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{mem, ptr};

use snare::{
    Bytes, DnsFailure, Fault, Line, RecordedEvent, Sim, TesterAction, add_host, connect_tester,
    run_testers, set_dns_policy, set_udp_policy, udp_tester,
};
use windows_sys::Win32::Networking::WinSock::{
    ADDRINFOA, ADDRINFOW, AF_INET, AF_INET6, AF_UNSPEC, AI_ALL, AI_CANONNAME, AI_NUMERICHOST,
    AI_PASSIVE, AI_V4MAPPED, FreeAddrInfoW, GetAddrInfoW, GetNameInfoW, NI_NAMEREQD,
    NI_NUMERICHOST, NI_NUMERICSERV, SOCK_DGRAM, SOCK_STREAM, SOCKADDR, SOCKADDR_STORAGE, WSAEFAULT,
    WSAGetLastError, WSAHOST_NOT_FOUND, WSANO_DATA, WSANO_RECOVERY, WSATRY_AGAIN, freeaddrinfo,
    getaddrinfo, gethostbyname, getnameinfo,
};

fn v4(text: &str) -> IpAddr {
    IpAddr::V4(text.parse::<Ipv4Addr>().unwrap())
}

fn v6(text: &str) -> IpAddr {
    IpAddr::V6(text.parse::<Ipv6Addr>().unwrap())
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

fn ensure_winsock() {
    let _ = std::net::UdpSocket::bind("127.0.0.1:0");
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Node {
    family: i32,
    socktype: i32,
    protocol: i32,
    addr: String,
    canon: Option<String>,
}

fn sockaddr_text(addr: *const SOCKADDR, len: usize) -> String {
    let mut host = [0u8; 128];
    let mut serv = [0u8; 32];
    let rc = unsafe {
        getnameinfo(
            addr,
            len as i32,
            host.as_mut_ptr(),
            host.len() as u32,
            serv.as_mut_ptr(),
            serv.len() as u32,
            (NI_NUMERICHOST | NI_NUMERICSERV) as i32,
        )
    };
    assert_eq!(rc, 0);
    let text = |b: &[u8]| {
        CStr::from_bytes_until_nul(b)
            .unwrap()
            .to_string_lossy()
            .into_owned()
    };
    format!("{} {}", text(&host), text(&serv))
}

fn gai(
    node: Option<&str>,
    service: Option<&str>,
    family: i32,
    socktype: i32,
    flags: i32,
) -> Result<Vec<Node>, i32> {
    ensure_winsock();
    let node = node.map(|n| CString::new(n).unwrap());
    let service = service.map(|s| CString::new(s).unwrap());
    let mut hints: ADDRINFOA = unsafe { mem::zeroed() };
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_flags = flags;
    let mut list = ptr::null_mut();
    let rc = unsafe {
        getaddrinfo(
            node.as_ref().map_or(ptr::null(), |n| n.as_ptr().cast()),
            service.as_ref().map_or(ptr::null(), |s| s.as_ptr().cast()),
            &hints,
            &mut list,
        )
    };
    if rc != 0 {
        assert_eq!(unsafe { WSAGetLastError() }, rc);
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
                unsafe { CStr::from_ptr(n.ai_canonname.cast()) }
                    .to_string_lossy()
                    .into_owned()
            }),
        });
        at = n.ai_next;
    }
    unsafe { freeaddrinfo(list) };
    Ok(nodes)
}

fn gai_w(node: &str, flags: i32) -> Result<(usize, Option<String>), i32> {
    ensure_winsock();
    let node = wide(node);
    let mut hints: ADDRINFOW = unsafe { mem::zeroed() };
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = flags;
    let mut list = ptr::null_mut();
    let rc = unsafe { GetAddrInfoW(node.as_ptr(), ptr::null(), &hints, &mut list) };
    if rc != 0 {
        assert_eq!(unsafe { WSAGetLastError() }, rc);
        return Err(rc);
    }
    let canon = unsafe {
        let p = (*list).ai_canonname;
        (!p.is_null()).then(|| {
            let mut len = 0;
            while *p.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        })
    };
    let mut count = 0;
    let mut at = list;
    while !at.is_null() {
        count += 1;
        at = unsafe { (*at).ai_next };
    }
    unsafe { FreeAddrInfoW(list) };
    Ok((count, canon))
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
            .until_after(Duration::from_secs(5));
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
fn unknown_name_is_wsahost_not_found() {
    Sim::new().run(|| {
        let start = snare::real(Instant::now);
        let err = ("robot9.invalid", 80).to_socket_addrs().unwrap_err();
        assert_eq!(err.raw_os_error(), Some(11001));
        assert_eq!(
            gai(Some("robot9.invalid"), None, 0, 0, 0),
            Err(WSAHOST_NOT_FOUND)
        );
        assert_eq!(gai_w("robot9.invalid", 0), Err(11001));
        assert!(snare::real(|| start.elapsed()) < Duration::from_millis(500));
    });
}

#[test]
fn numeric_passthrough_matches_os() {
    let cases: Vec<(Option<&str>, Option<&str>, i32, i32)> = vec![
        (Some("127.1"), Some("80"), AF_UNSPEC as i32, 0),
        (Some("::1"), Some("80"), AF_INET as i32, 0),
        (
            Some("::1"),
            Some("80"),
            AF_INET as i32,
            AI_NUMERICHOST as i32,
        ),
        (Some("fe80::1%1"), Some("80"), AF_UNSPEC as i32, 0),
        (None, Some("80"), AF_UNSPEC as i32, AI_PASSIVE as i32),
        (None, Some("80"), AF_INET6 as i32, AI_PASSIVE as i32),
        (
            Some("10.1.2.3"),
            Some("80"),
            AF_INET6 as i32,
            AI_V4MAPPED as i32,
        ),
        (
            Some("localhost"),
            Some("80"),
            AF_UNSPEC as i32,
            AI_NUMERICHOST as i32,
        ),
    ];
    for (node, service, family, flags) in cases {
        for socktype in [0, SOCK_STREAM, SOCK_DGRAM] {
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

#[test]
fn hints_follow_os_semantics() {
    let sim = Sim::builder()
        .add_host("twin.local", [v6("::1"), v4("127.0.0.1")])
        .build();
    for family in [AF_UNSPEC, AF_INET, AF_INET6] {
        for socktype in [0, SOCK_STREAM, SOCK_DGRAM] {
            for flags in [0, AI_PASSIVE, AI_V4MAPPED] {
                for service in [None, Some("80"), Some("http")] {
                    let sorted = |r: Result<Vec<Node>, i32>| {
                        r.map(|mut v| {
                            v.sort();
                            v.dedup();
                            v
                        })
                    };
                    let (family, flags) = (family as i32, flags as i32);
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
        .add_host("six.local", [v6("fd00::6")])
        .build();
    sim.run(|| {
        let addrs = |name, flags: u32| {
            gai(
                Some(name),
                Some("80"),
                AF_INET6 as i32,
                SOCK_STREAM,
                flags as i32,
            )
            .map(|v| v.into_iter().map(|n| n.addr).collect::<Vec<_>>())
        };
        let mapped = snare::real(|| addrs("127.0.0.41", AI_V4MAPPED));
        assert_eq!(addrs("four.local", AI_V4MAPPED), mapped);
        assert_eq!(
            addrs("dual.local", AI_V4MAPPED),
            Ok(vec!["fd00::40 80".to_string()])
        );
        assert_eq!(
            addrs("dual.local", AI_V4MAPPED | AI_ALL).map(|v| v.len()),
            Ok(2)
        );
        assert_eq!(
            gai(Some("six.local"), Some("80"), AF_INET as i32, 0, 0),
            Err(WSANO_DATA)
        );
    });
}

fn lookup_raw(name: &str) -> usize {
    let name = CString::new(name).unwrap();
    let mut hints: ADDRINFOA = unsafe { mem::zeroed() };
    hints.ai_flags = AI_CANONNAME as i32;
    let mut list = ptr::null_mut();
    assert_eq!(
        unsafe { getaddrinfo(name.as_ptr().cast(), ptr::null(), &hints, &mut list) },
        0
    );
    let canon = unsafe { CStr::from_ptr((*list).ai_canonname.cast()) };
    assert_eq!(canon.to_str().unwrap(), "Multi.local");
    list as usize
}

fn free_raw(list: usize) {
    unsafe { freeaddrinfo(list as *const ADDRINFOA) };
}

#[test]
fn freeaddrinfo_releases_chains() {
    ensure_winsock();
    let sim = Sim::builder()
        .add_host(
            "Multi.local",
            [v4("127.0.0.50"), v6("fd00::50"), v4("127.0.0.51")],
        )
        .build();
    let leftover = sim.run(|| {
        for _ in 0..10_000 {
            free_raw(lookup_raw("multi.local"));
        }
        for _ in 0..1000 {
            assert_eq!(
                gai_w("multi.local", AI_CANONNAME as i32),
                Ok((3, Some("Multi.local".into())))
            );
        }
        let lists: Vec<usize> = (0..1000).map(|_| lookup_raw("multi.local")).collect();
        std::thread::spawn(move || lists.into_iter().for_each(free_raw))
            .join()
            .unwrap();
        let real = snare::real(|| {
            let mut list = ptr::null_mut();
            let rc = unsafe {
                getaddrinfo(
                    c"127.0.0.1".as_ptr().cast(),
                    ptr::null(),
                    ptr::null(),
                    &mut list,
                )
            };
            assert_eq!(rc, 0);
            list as usize
        });
        free_raw(real);
        (0..1000)
            .map(|_| lookup_raw("multi.local"))
            .collect::<Vec<_>>()
    });
    drop(sim);
    std::thread::spawn(move || leftover.into_iter().for_each(free_raw))
        .join()
        .unwrap();
}

fn sockaddr(addr: SocketAddr) -> (SOCKADDR_STORAGE, i32) {
    let mut storage: SOCKADDR_STORAGE = unsafe { mem::zeroed() };
    let bytes = (&raw mut storage).cast::<u8>();
    unsafe {
        match addr {
            SocketAddr::V4(a) => {
                *bytes.cast::<u16>() = AF_INET;
                *bytes.add(2).cast::<[u8; 2]>() = a.port().to_be_bytes();
                *bytes.add(4).cast::<[u8; 4]>() = a.ip().octets();
                (storage, 16)
            }
            SocketAddr::V6(a) => {
                *bytes.cast::<u16>() = AF_INET6;
                *bytes.add(2).cast::<[u8; 2]>() = a.port().to_be_bytes();
                *bytes.add(8).cast::<[u8; 16]>() = a.ip().octets();
                (storage, 28)
            }
        }
    }
}

fn name_info(addr: SocketAddr, host_len: usize, flags: u32) -> Result<(String, String), i32> {
    ensure_winsock();
    let (storage, len) = sockaddr(addr);
    let mut host = vec![0u8; host_len];
    let mut serv = [0u8; 32];
    let rc = unsafe {
        getnameinfo(
            (&raw const storage).cast(),
            len,
            host.as_mut_ptr(),
            host_len as u32,
            serv.as_mut_ptr(),
            serv.len() as u32,
            flags as i32,
        )
    };
    if rc != 0 {
        return Err(rc);
    }
    let text = |b: &[u8]| {
        CStr::from_bytes_until_nul(b)
            .unwrap()
            .to_string_lossy()
            .into_owned()
    };
    Ok((text(&host), text(&serv)))
}

fn name_info_w(addr: SocketAddr, host_len: usize, flags: u32) -> Result<String, i32> {
    let (storage, len) = sockaddr(addr);
    let mut host = vec![0u16; host_len];
    let rc = unsafe {
        GetNameInfoW(
            (&raw const storage).cast(),
            len,
            host.as_mut_ptr(),
            host_len as u32,
            ptr::null_mut(),
            0,
            flags as i32,
        )
    };
    if rc != 0 {
        return Err(rc);
    }
    let end = host.iter().position(|&c| c == 0).unwrap();
    Ok(String::from_utf16_lossy(&host[..end]))
}

#[test]
fn getnameinfo_reverse() {
    let sim = Sim::builder()
        .add_host("robot1.local", [v4("127.0.0.20")])
        .build();
    sim.run(|| {
        assert_eq!(
            name_info("127.0.0.20:80".parse().unwrap(), 64, NI_NUMERICSERV),
            Ok(("robot1.local".into(), "80".into()))
        );
        assert_eq!(
            name_info(
                "[::ffff:127.0.0.20]:80".parse().unwrap(),
                64,
                NI_NUMERICSERV
            ),
            Ok(("robot1.local".into(), "80".into()))
        );
        assert_eq!(
            name_info_w("127.0.0.20:80".parse().unwrap(), 64, 0),
            Ok("robot1.local".into())
        );
        assert_eq!(
            name_info("127.0.0.20:80".parse().unwrap(), 5, 0),
            Err(WSAEFAULT)
        );
        assert_eq!(
            name_info_w("127.0.0.20:80".parse().unwrap(), 5, 0),
            Err(WSAEFAULT)
        );
        assert_eq!(
            name_info("127.0.0.99:80".parse().unwrap(), 64, NI_NUMERICSERV),
            Ok(("127.0.0.99".into(), "80".into()))
        );
        assert_eq!(
            name_info("127.0.0.99:80".parse().unwrap(), 64, NI_NAMEREQD),
            Err(WSAHOST_NOT_FOUND)
        );
    });
}

fn host_by_name(name: &str) -> Result<(String, Vec<Ipv4Addr>), i32> {
    ensure_winsock();
    let name = CString::new(name).unwrap();
    let entry = unsafe { gethostbyname(name.as_ptr().cast()) };
    if entry.is_null() {
        return Err(unsafe { WSAGetLastError() });
    }
    let entry = unsafe { &*entry };
    assert_eq!(entry.h_addrtype, AF_INET as i16);
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
    let name = unsafe { CStr::from_ptr(entry.h_name.cast()) }
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
        assert_eq!(host_by_name("six.local"), Err(WSANO_DATA));
        assert_eq!(host_by_name("robot9.invalid"), Err(WSAHOST_NOT_FOUND));
        assert_eq!(
            host_by_name("127.0.0.5"),
            Ok(("127.0.0.5".into(), vec![Ipv4Addr::new(127, 0, 0, 5)]))
        );
        set_dns_policy("robot1.local", |p| p.failure = Some(DnsFailure::TryAgain));
        assert_eq!(host_by_name("robot1.local"), Err(WSATRY_AGAIN));
    });
}

#[test]
fn gethostbyname_non_names_match_os() {
    let inputs = ["", "::1", "fe80::1%1", "127.1", "1.2.3.256", "10.0.0.7"];
    let real: Vec<_> = inputs.iter().map(|name| host_by_name(name)).collect();
    let simmed: Vec<_> = Sim::new().run(|| inputs.iter().map(|name| host_by_name(name)).collect());
    assert_eq!(simmed, real);
    assert_eq!(
        simmed[1],
        Err(WSAHOST_NOT_FOUND),
        "an IPv6 string is refused, not looked up"
    );
}

#[test]
fn dns_latency_is_virtual() {
    Sim::new().run(|| {
        add_host("slow.local", [v4("127.0.0.60")]);
        set_dns_policy("slow.local", |p| p.latency = Duration::from_secs(5));
        let real = snare::real(Instant::now);
        let start = Instant::now();
        assert_eq!(addrs("slow.local"), BTreeSet::from([v4("127.0.0.60")]));
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_secs(5) && elapsed < Duration::from_secs(6),
            "{elapsed:?}"
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
    let at = |i: usize| -> Vec<u64> {
        first
            .iter()
            .filter(|e| e.0 == i)
            .map(|e| e.1.as_millis() as u64)
            .collect()
    };
    assert_eq!(at(1), [3, 6, 9, 12]);
    assert_eq!(at(0), [7, 14, 21, 28]);
}

fn failure_trace(seed: u64) -> (Vec<Result<usize, i32>>, usize) {
    let sim = Sim::builder()
        .seed(seed)
        .add_host("flaky.local", [v4("127.0.0.80")])
        .build();
    let results = sim.run(|| {
        set_dns_policy("flaky.local", |p| p.failure_rate = 0.5);
        (0..40)
            .map(|_| gai(Some("flaky.local"), None, 0, SOCK_STREAM, 0).map(|v| v.len()))
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
            (DnsFailure::NotFound, WSAHOST_NOT_FOUND),
            (DnsFailure::TryAgain, WSATRY_AGAIN),
            (DnsFailure::Fail, WSANO_RECOVERY),
        ] {
            set_dns_policy("a.local", |p| p.failure = Some(failure));
            assert_eq!(gai(Some("a.local"), None, 0, 0, 0), Err(code));
            assert_eq!(gai_w("a.local", 0), Err(code));
        }
    });
    let (results, faults) = failure_trace(5);
    let failed = results.iter().filter(|r| r.is_err()).count();
    assert!(failed > 5 && failed < 35, "{failed} of 40 failed");
    assert_eq!(faults, failed);
    assert_eq!(failure_trace(5), (results.clone(), faults));
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
    let real = snare::real(|| addrs("localhost"));
    let sim = Sim::builder().resolve_real("localhost").build();
    sim.run(|| add_host("other.local", [v4("127.0.0.97")]));
    assert_eq!(sim.run(|| addrs("localhost")), real);
}

#[test]
#[should_panic(expected = "real_dns cannot be combined with deterministic")]
fn real_dns_with_deterministic_panics() {
    Sim::builder().deterministic().real_dns().build();
}

#[test]
fn empty_node_is_local_host() {
    Sim::new().run(|| {
        let found = gai(Some(""), Some("80"), AF_UNSPEC as i32, SOCK_STREAM, 0)
            .unwrap()
            .into_iter()
            .map(|n| n.addr)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            found,
            BTreeSet::from(["127.0.0.1 80".to_string(), "::1 80".to_string()])
        );
    });
}
