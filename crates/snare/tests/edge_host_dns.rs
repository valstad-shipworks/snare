#![cfg(unix)]
//! Edge cases of the sim's name table, pinned exactly ahead of a performance pass: ASCII-only
//! case folding and the single trailing dot, `ai_canonname` on the head node only, many addresses
//! in table order per family (against the real resolver's numeric answers joined the same way),
//! `AI_NUMERICHOST` on a table name, replacing and removing entries and what reverse lookups then
//! answer, overriding the built-in `localhost`, the `getnameinfo` buffer boundary and flags, the
//! virtual time a lookup with latency takes, and which threads and sims see a table.

use std::ffi::{CStr, CString, c_char, c_int};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};
use std::{mem, ptr};

use snare::{Sim, add_host, remove_host, set_dns_policy};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Node {
    family: c_int,
    socktype: c_int,
    protocol: c_int,
    addr: String,
    canon: Option<String>,
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
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

fn gai(
    node: &str,
    service: Option<&str>,
    family: c_int,
    socktype: c_int,
    flags: c_int,
) -> Result<Vec<Node>, c_int> {
    let node = CString::new(node).unwrap();
    let service = service.map(|s| CString::new(s).unwrap());
    let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_flags = flags;
    let mut list = ptr::null_mut();
    let rc = unsafe {
        libc::getaddrinfo(
            node.as_ptr(),
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

fn addrs_of(name: &str) -> Result<Vec<String>, c_int> {
    gai(name, Some("80"), libc::AF_UNSPEC, libc::SOCK_STREAM, 0)
        .map(|v| v.into_iter().map(|n| n.addr).collect())
}

fn name_info(addr: SocketAddr, host_len: usize, flags: c_int) -> Result<String, c_int> {
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
    let rc = unsafe {
        libc::getnameinfo(
            (&raw const storage).cast(),
            len as _,
            host.as_mut_ptr(),
            host_len as _,
            ptr::null_mut(),
            0,
            flags,
        )
    };
    if rc != 0 {
        return Err(rc);
    }
    Ok(unsafe { CStr::from_ptr(host.as_ptr()) }
        .to_string_lossy()
        .into_owned())
}

fn reverse(addr: &str) -> Result<String, c_int> {
    name_info(SocketAddr::new(ip(addr), 80), 128, 0)
}

#[test]
fn names_fold_ascii_case_and_drop_one_trailing_dot() {
    let sim = Sim::builder()
        .add_host("Robot.Local.", [ip("127.0.0.20")])
        .build();
    sim.run(|| {
        for name in ["robot.local", "ROBOT.LOCAL", "rObOt.lOcAl.", "Robot.Local."] {
            assert_eq!(addrs_of(name), Ok(vec!["127.0.0.20 80".into()]), "{name}");
        }
        for name in [
            "robot.local..",
            ".robot.local",
            "robot",
            "robot.local.local",
        ] {
            assert_eq!(addrs_of(name), Err(libc::EAI_NONAME), "{name}");
        }
        add_host("R\u{f6}bot.local", [ip("127.0.0.21")]);
        assert_eq!(
            addrs_of("r\u{f6}BOT.local"),
            Ok(vec!["127.0.0.21 80".into()])
        );
        assert_eq!(
            addrs_of("R\u{d6}BOT.local"),
            Err(libc::EAI_NONAME),
            "non-ASCII letters keep their case"
        );
    });
}

#[test]
fn the_canonical_name_rides_on_the_head_node_only() {
    let sim = Sim::builder()
        .add_host(
            "Multi.Local.",
            [ip("127.0.0.30"), ip("127.0.0.31"), ip("fd00::32")],
        )
        .build();
    sim.run(|| {
        let nodes = gai(
            "multi.local",
            Some("80"),
            libc::AF_UNSPEC,
            libc::SOCK_STREAM,
            libc::AI_CANONNAME,
        )
        .unwrap();
        let canon: Vec<Option<&str>> = nodes.iter().map(|n| n.canon.as_deref()).collect();
        assert_eq!(canon, [Some("Multi.Local"), None, None]);
        let plain = gai(
            "multi.local",
            Some("80"),
            libc::AF_UNSPEC,
            libc::SOCK_STREAM,
            0,
        )
        .unwrap();
        assert!(plain.iter().all(|n| n.canon.is_none()));
        let one = gai(
            "multi.local",
            Some("80"),
            libc::AF_INET6,
            libc::SOCK_STREAM,
            libc::AI_CANONNAME,
        )
        .unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].canon.as_deref(), Some("Multi.Local"));
        add_host("MULTI.local", [ip("127.0.0.33")]);
        let renamed = gai(
            "multi.local",
            Some("80"),
            libc::AF_INET,
            libc::SOCK_STREAM,
            libc::AI_CANONNAME,
        )
        .unwrap();
        assert_eq!(
            renamed[0].canon.as_deref(),
            Some("MULTI.local"),
            "a replacement respells it"
        );
    });
}

/// What the sim builds for `addrs`: the real resolver's numeric answer for each address with the
/// same hints, IPv6 first and IPv4 only when no IPv6 address fits for `AF_INET6`.
fn joined_real(addrs: &[IpAddr], family: c_int, socktype: c_int) -> Result<Vec<Node>, c_int> {
    let ask = |a: &IpAddr| {
        gai(
            &a.to_string(),
            Some("80"),
            family,
            socktype,
            libc::AI_NUMERICHOST,
        )
        .unwrap_or_default()
    };
    let nodes: Vec<Node> = if family == libc::AF_INET6 {
        let six: Vec<Node> = addrs.iter().filter(|a| a.is_ipv6()).flat_map(ask).collect();
        if six.is_empty() {
            addrs.iter().filter(|a| a.is_ipv4()).flat_map(ask).collect()
        } else {
            six
        }
    } else {
        addrs.iter().flat_map(ask).collect()
    };
    if nodes.is_empty() {
        Err(libc::EAI_NONAME)
    } else {
        Ok(nodes)
    }
}

#[test]
fn many_addresses_come_back_in_table_order_os_truth() {
    let table: Vec<IpAddr> = [
        "127.0.0.9",
        "fd00::3",
        "127.0.0.1",
        "10.9.8.7",
        "fd00::1",
        "192.168.0.255",
        "::1",
        "127.0.0.2",
        "fe80::1",
        "172.16.0.1",
        "fd00::2",
        "8.8.8.8",
        "127.0.0.3",
        "2001:db8::1",
        "127.0.0.4",
        "127.0.0.5",
    ]
    .into_iter()
    .map(ip)
    .collect();
    let only_v4: Vec<IpAddr> = table.iter().copied().filter(IpAddr::is_ipv4).collect();
    let sim = Sim::builder()
        .add_host("many.local", table.clone())
        .add_host("four.local", only_v4.clone())
        .build();
    for family in [libc::AF_UNSPEC, libc::AF_INET, libc::AF_INET6] {
        for socktype in [0, libc::SOCK_STREAM, libc::SOCK_DGRAM] {
            let real = snare::real(|| joined_real(&table, family, socktype));
            let got = sim.run(|| gai("many.local", Some("80"), family, socktype, 0));
            assert_eq!(got, real, "family {family} socktype {socktype}");
            let real = snare::real(|| joined_real(&only_v4, family, socktype));
            let got = sim.run(|| gai("four.local", Some("80"), family, socktype, 0));
            if family == libc::AF_INET6 && cfg!(target_os = "linux") {
                assert_eq!(
                    got,
                    Err(libc::EAI_NONAME),
                    "Linux maps no IPv4 address without AI_V4MAPPED"
                );
            } else if family == libc::AF_INET6 {
                let mapped: Vec<IpAddr> = only_v4
                    .iter()
                    .map(|a| match a {
                        IpAddr::V4(v4) => IpAddr::V6(v4.to_ipv6_mapped()),
                        other => *other,
                    })
                    .collect();
                let real = snare::real(|| joined_real(&mapped, family, socktype));
                assert_eq!(got, real, "macOS maps IPv4 addresses for AF_INET6 unasked");
            } else {
                assert_eq!(got, real, "v4 only: family {family} socktype {socktype}");
            }
        }
    }
    let std_order: Vec<IpAddr> = sim.run(|| {
        ("many.local", 1)
            .to_socket_addrs()
            .unwrap()
            .map(|a| a.ip())
            .collect()
    });
    assert_eq!(
        std_order, table,
        "std sees the table order, one entry per address"
    );
}

#[test]
fn numeric_host_on_a_table_name_matches_the_real_resolver_os_truth() {
    let real = snare::real(|| {
        gai(
            "robot.local",
            Some("80"),
            libc::AF_UNSPEC,
            0,
            libc::AI_NUMERICHOST,
        )
    });
    assert_eq!(real, Err(libc::EAI_NONAME));
    let sim = Sim::builder()
        .add_host("robot.local", [ip("127.0.0.20")])
        .build();
    assert_eq!(
        sim.run(|| gai(
            "robot.local",
            Some("80"),
            libc::AF_UNSPEC,
            0,
            libc::AI_NUMERICHOST
        )),
        real
    );
}

#[test]
fn replacing_and_removing_entries_steer_reverse_lookups() {
    let sim = Sim::new();
    sim.run(|| {
        add_host("a.local", [ip("127.0.0.50")]);
        add_host("b.local", [ip("127.0.0.50"), ip("127.0.0.51")]);
        assert_eq!(
            reverse("127.0.0.50").as_deref(),
            Ok("a.local"),
            "the first entry holding it"
        );
        add_host("A.LOCAL", [ip("127.0.0.52"), ip("127.0.0.50")]);
        assert_eq!(
            reverse("127.0.0.50").as_deref(),
            Ok("A.LOCAL"),
            "a replacement keeps its place"
        );
        assert_eq!(
            addrs_of("a.local"),
            Ok(vec!["127.0.0.52 80".into(), "127.0.0.50 80".into()])
        );
        remove_host("a.local.");
        assert_eq!(reverse("127.0.0.50").as_deref(), Ok("b.local"));
        assert_eq!(addrs_of("a.local"), Err(libc::EAI_NONAME));
        add_host("a.local", [ip("127.0.0.50")]);
        assert_eq!(
            reverse("127.0.0.50").as_deref(),
            Ok("b.local"),
            "re-added at the end"
        );
        remove_host("never.local");
        add_host("none.local", []);
        assert_eq!(addrs_of("none.local"), Err(libc::EAI_NONAME));
        assert_eq!(reverse("127.0.0.99").as_deref(), Ok("127.0.0.99"));
        assert_eq!(
            name_info(
                SocketAddr::new(ip("127.0.0.99"), 80),
                128,
                libc::NI_NAMEREQD
            ),
            Err(libc::EAI_NONAME)
        );
        assert_eq!(
            name_info(
                SocketAddr::new(ip("127.0.0.51"), 80),
                128,
                libc::NI_NAMEREQD
            )
            .as_deref(),
            Ok("b.local")
        );
        let both = libc::NI_NUMERICHOST | libc::NI_NAMEREQD;
        assert_eq!(
            name_info(SocketAddr::new(ip("127.0.0.51"), 80), 128, both),
            Err(libc::EAI_NONAME)
        );
        add_host("six.local", [ip("fd00::77")]);
        assert_eq!(reverse("fd00::77").as_deref(), Ok("six.local"));
        assert_eq!(
            reverse("::ffff:127.0.0.51").as_deref(),
            Ok("b.local"),
            "a mapped address reverses as IPv4"
        );
    });
}

#[test]
fn numeric_host_with_name_required_os_truth() {
    let both = libc::NI_NUMERICHOST | libc::NI_NAMEREQD;
    let at = SocketAddr::new(ip("127.0.0.99"), 80);
    let real = snare::real(|| name_info(at, 128, both));
    assert_eq!(Sim::new().run(|| name_info(at, 128, both)), real);
    let real = snare::real(|| name_info(at, 128, libc::NI_NUMERICHOST));
    assert_eq!(
        Sim::new().run(|| name_info(at, 128, libc::NI_NUMERICHOST)),
        real
    );
}

#[test]
fn the_getnameinfo_buffer_boundary() {
    let sim = Sim::builder()
        .add_host("abcd.local", [ip("127.0.0.60")])
        .build();
    sim.run(|| {
        let at = SocketAddr::new(ip("127.0.0.60"), 80);
        assert_eq!(name_info(at, 11, 0).as_deref(), Ok("abcd.local"));
        assert_eq!(name_info(at, 10, 0), Err(libc::EAI_OVERFLOW));
        assert_eq!(name_info(at, 1, 0), Err(libc::EAI_OVERFLOW));
    });
}

#[test]
fn a_table_entry_overrides_the_builtin_localhost() {
    let sim = Sim::new();
    sim.run(|| {
        let builtin = addrs_of("localhost").unwrap();
        add_host("LocalHost", [ip("127.0.0.77")]);
        assert_eq!(addrs_of("LOCALHOST"), Ok(vec!["127.0.0.77 80".into()]));
        let canon = gai(
            "localhost",
            Some("80"),
            libc::AF_INET,
            libc::SOCK_STREAM,
            libc::AI_CANONNAME,
        )
        .unwrap();
        assert_eq!(canon[0].canon.as_deref(), Some("LocalHost"));
        assert_eq!(reverse("127.0.0.77").as_deref(), Ok("LocalHost"));
        assert_eq!(
            reverse("127.0.0.1").as_deref(),
            Ok("localhost"),
            "the loopbacks still name localhost"
        );
        let real = snare::real(|| addrs_of("localhost").unwrap());
        assert_ne!(real, ["127.0.0.77 80"], "real escapes the table");
        let unmanaged = snare::real(|| std::thread::spawn(|| addrs_of("localhost").unwrap()))
            .join()
            .unwrap();
        assert_eq!(unmanaged, real);
        let spawned = std::thread::spawn(|| addrs_of("localhost").unwrap())
            .join()
            .unwrap();
        assert_eq!(spawned, ["127.0.0.77 80"]);
        remove_host("localhost");
        assert_eq!(addrs_of("localhost").unwrap(), builtin);
    });
}

#[test]
fn tables_are_per_sim_and_persist_across_runs() {
    let a = Sim::builder()
        .add_host("a-only.local", [ip("127.0.0.80")])
        .build();
    let b = Sim::new();
    std::thread::scope(|scope| {
        scope.spawn(|| a.run(|| add_host("late-a.local", [ip("127.0.0.81")])));
        scope.spawn(|| b.run(|| add_host("late-b.local", [ip("127.0.0.82")])));
    });
    a.run(|| {
        assert_eq!(addrs_of("late-a.local"), Ok(vec!["127.0.0.81 80".into()]));
        assert_eq!(addrs_of("late-b.local"), Err(libc::EAI_NONAME));
    });
    b.run(|| {
        assert_eq!(addrs_of("a-only.local"), Err(libc::EAI_NONAME));
        assert_eq!(addrs_of("late-b.local"), Ok(vec!["127.0.0.82 80".into()]));
    });
    a.remove_host("a-only.local");
    b.add_host("outside.local", [ip("127.0.0.83")]);
    assert_eq!(a.run(|| addrs_of("a-only.local")), Err(libc::EAI_NONAME));
    assert_eq!(
        b.run(|| addrs_of("outside.local")),
        Ok(vec!["127.0.0.83 80".into()])
    );
    assert_eq!(
        Sim::new().run(|| addrs_of("late-a.local")),
        Err(libc::EAI_NONAME)
    );
}

fn timed_lookups(sim: &Sim) -> Vec<(Duration, Result<usize, c_int>)> {
    sim.run(|| {
        add_host("slow.local", [ip("127.0.0.90"), ip("127.0.0.91")]);
        add_host("fast.local", [ip("127.0.0.92")]);
        set_dns_policy("slow.local", |p| p.latency = Duration::from_millis(30));
        let start = Instant::now();
        let mut out = Vec::new();
        for name in [
            "slow.local",
            "fast.local",
            "SLOW.local.",
            "missing.local",
            "fast.local",
        ] {
            let got = gai(name, Some("80"), libc::AF_INET, libc::SOCK_STREAM, 0).map(|v| v.len());
            out.push((start.elapsed(), got));
        }
        out
    })
}

#[test]
fn lookups_take_their_latency_in_virtual_time() {
    for sim in [Sim::new(), Sim::builder().deterministic().build()] {
        let got = timed_lookups(&sim);
        let results: Vec<_> = got.iter().map(|(_, r)| *r).collect();
        assert_eq!(results, [Ok(2), Ok(1), Ok(2), Err(libc::EAI_NONAME), Ok(1)]);
        let ms = |d: Duration| d.as_millis();
        let at: Vec<u128> = got.iter().map(|(t, _)| ms(*t)).collect();
        assert_eq!(at, [30, 30, 60, 60, 60], "{got:?}");
        for pair in got.windows(2) {
            assert!(pair[1].0 > pair[0].0, "each lookup costs time: {got:?}");
        }
    }
}
