//! The host's protocol counters follow the sim's traffic, and the code under test reads the same
//! numbers through its OS's own interface: `/proc/net/snmp`, `net.inet.udp.stats` or
//! `GetUdpStatisticsEx`.

#[path = "support/counters.rs"]
mod counters;
#[path = "support/netfault.rs"]
mod netfault;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};

use std::time::Duration;

use snare::{
    Bytes, RecordedEvent, Sim, TesterAction, connect_tester, proto_counters, recorded_events,
    run_testers, udp_tester,
};

/// Sends three datagrams to a socket that reads two, one to a port nobody holds, and floods a
/// one-datagram buffer, then checks both the snapshot and the OS's view.
fn udp_traffic() {
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let to = rx.local_addr().unwrap();
    for _ in 0..3 {
        tx.send_to(b"hello", to).unwrap();
    }
    let mut buf = [0u8; 16];
    rx.recv_from(&mut buf).unwrap();
    rx.recv_from(&mut buf).unwrap();
    tx.send_to(b"nobody", "127.0.0.1:9").unwrap();

    let c = proto_counters().udp4;
    assert_eq!(
        (c.sent, c.received, c.read, c.no_ports, c.rcvbuf_errors),
        (4, 3, 2, 1, 0)
    );
    assert_eq!(c.sockets, 2);

    let small = UdpSocket::bind("127.0.0.1:0").unwrap();
    netfault::set_buf(netfault::raw(&small), true, 1);
    for _ in 0..20 {
        tx.send_to(&[0u8; 1000], small.local_addr().unwrap())
            .unwrap();
    }
    let entry = snare::socket_entry(snare::socket_id(&small).unwrap()).unwrap();
    let c = proto_counters().udp4;
    assert!(entry.overflowed > 0);
    assert_eq!(c.rcvbuf_errors, entry.overflowed);
    assert_eq!(c.received, 3 + entry.delivered);

    let [received, no_ports, rcvbuf_errors, sent] = counters::udp();
    let expect_received = if cfg!(target_os = "linux") {
        c.read
    } else if cfg!(target_os = "macos") {
        c.received + c.rcvbuf_errors + c.no_ports
    } else {
        c.received
    };
    assert_eq!(
        (received, no_ports, rcvbuf_errors, sent),
        (expect_received, 1, c.rcvbuf_errors, 24)
    );
}

#[test]
fn udp_counters_follow_traffic() {
    Sim::new().run(udp_traffic);
}

#[cfg(target_os = "linux")]
#[test]
fn udp_counters_follow_simhost_traffic() {
    Sim::builder()
        .host(snare::HostProfile::new().build())
        .build()
        .run(udp_traffic);
}

#[test]
fn ipv6_counts_apart() {
    Sim::new().run(|| {
        let rx = UdpSocket::bind("[::1]:0").unwrap();
        let tx = UdpSocket::bind("[::1]:0").unwrap();
        tx.send_to(b"six", rx.local_addr().unwrap()).unwrap();
        let c = proto_counters();
        assert_eq!((c.udp6.sent, c.udp6.received), (1, 1));
        assert_eq!((c.udp4.sent, c.udp4.received), (0, 0));
    });
}

#[test]
fn tester_datagram_to_a_closed_port_counts() {
    Sim::new().run(|| {
        let _keep = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        let peer = udp_tester::<Bytes>("127.0.0.2:4000")
            .with_cyclic_action(Duration::from_millis(100), move || {
                TesterAction::SendTo(to, Bytes(b"x".to_vec()))
            })
            .until_after(Duration::from_millis(250));
        run_testers!(peer);
        let sent = recorded_events()
            .iter()
            .filter(|e| matches!(e.event, RecordedEvent::Sent { .. }))
            .count() as u64;
        assert!(sent > 0);
        assert_eq!(proto_counters().udp4.no_ports, sent);
    });
}

#[test]
fn tcp_counters_follow_connections() {
    Sim::new().run(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(&[1u8; 100]).unwrap();
        let mut buf = [0u8; 100];
        server.read_exact(&mut buf).unwrap();
        let refused = TcpStream::connect("127.0.0.1:9").unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
        let c = proto_counters().tcp4;
        assert_eq!(
            (
                c.active_opens,
                c.passive_opens,
                c.attempt_fails,
                c.curr_estab
            ),
            (2, 1, 1, 2)
        );
        assert_eq!((c.out_segs, c.in_segs), (1, 1));
        netfault::set_linger(netfault::raw(&client), 0);
        drop(client);
        let c = proto_counters().tcp4;
        assert_eq!(
            (c.out_rsts, c.estab_resets, c.curr_estab),
            (if cfg!(windows) { 6 } else { 2 }, 2, 0)
        );
        drop(server);
    });
}

#[cfg(windows)]
#[test]
/// [Native TCP statistics](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-gettcpstatisticsex)
/// cover the whole computer, so the host delta may include unrelated traffic.
fn refused_loopback_reset_counter_and_host_calibration() {
    fn resets() -> u32 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let before = counters::tcpstats(2).dwOutRsts;
        let refused = TcpStream::connect(addr).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::ConnectionRefused);
        counters::tcpstats(2).dwOutRsts.wrapping_sub(before)
    }
    let real = resets();
    let model = Sim::new().run(resets);
    assert_eq!(model, 5, "simulated loopback refusal RST segments");
    eprintln!("loopback refusal: model RST count={model}; host-wide RST delta={real}");
}

#[test]
fn tester_connections_count_one_end() {
    Sim::new().run(|| {
        let _tester = connect_tester::<Bytes>("127.0.0.2:7000");
        let mut stream = TcpStream::connect("127.0.0.2:7000").unwrap();
        stream.write_all(&[0u8; 3000]).unwrap();
        let c = proto_counters().tcp4;
        assert_eq!((c.active_opens, c.passive_opens), (1, 0));
        assert_eq!(c.out_segs, 1, "one loopback segment");
        assert_eq!(c.in_segs, 0);
    });
}

#[cfg(target_os = "linux")]
#[test]
fn proc_net_snmp_renders_every_line() {
    Sim::new().run(|| {
        let text = std::fs::read_to_string("/proc/net/snmp").unwrap();
        let names: Vec<&str> = text.lines().map(|l| l.split(':').next().unwrap()).collect();
        assert_eq!(
            names,
            [
                "Ip", "Ip", "Icmp", "Icmp", "Tcp", "Tcp", "Udp", "Udp", "UdpLite", "UdpLite"
            ]
        );
        let tcp = counters::proc_line("/proc/net/snmp", "Tcp");
        assert_eq!(tcp["MaxConn"], u64::MAX, "printed as -1");
        assert_eq!(tcp["RtoMin"], 200);
        let ip = counters::proc_line("/proc/net/snmp", "Ip");
        assert_eq!((ip["Forwarding"], ip["DefaultTTL"]), (2, 64));
        let six = std::fs::read_to_string("/proc/net/snmp6").unwrap();
        assert!(six.lines().any(|l| l.starts_with("Udp6InDatagrams ")));
        let meta = std::fs::metadata("/proc/net/snmp").unwrap();
        assert!(meta.is_file());
    });
}

#[cfg(target_os = "linux")]
#[test]
fn proc_net_snmp_snapshots_at_first_read_until_rewound() {
    use std::io::{Seek, SeekFrom};
    Sim::new().run(|| {
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut f = std::fs::File::open("/proc/net/snmp").unwrap();
        tx.send_to(b"x", "127.0.0.1:9").unwrap();
        let mut head = [0u8; 16];
        f.read_exact(&mut head).unwrap();
        tx.send_to(b"y", "127.0.0.1:9").unwrap();
        let mut rest = String::new();
        f.read_to_string(&mut rest).unwrap();
        assert!(
            rest.contains("\nUdp: 0 1 0 1 "),
            "the first read's snapshot: {rest}"
        );
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut fresh = String::new();
        f.read_to_string(&mut fresh).unwrap();
        assert!(fresh.contains("\nUdp: 0 2 0 2 "), "{fresh}");
    });
}

#[cfg(target_os = "macos")]
#[test]
fn macos_udpstat_follows_sysctl_rules() {
    Sim::new().run(|| {
        let mut len = 0usize;
        let rc = unsafe {
            libc::sysctlbyname(
                c"net.inet.udp.stats".as_ptr(),
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        assert_eq!((rc, len), (0, 104));
        let mut mib = [0i32; 4];
        let mut n = 4usize;
        let name = c"net.inet.udp.stats";
        let rc = unsafe { libc::sysctlnametomib(name.as_ptr(), mib.as_mut_ptr(), &mut n) };
        assert_eq!((rc, mib), (0, [4, 2, 17, 2]));
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(b"x", "127.0.0.1:9").unwrap();
        let mut words = [0u32; 26];
        let mut len = 104usize;
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                4,
                words.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!((words[0], words[4], words[9]), (1, 1, 1));
        let mut short = [0u8; 8];
        let mut len = 8usize;
        let v = 0u32;
        let rc = unsafe {
            libc::sysctlbyname(
                c"net.inet.udp.stats".as_ptr(),
                short.as_mut_ptr().cast(),
                &mut len,
                (&v as *const u32) as *mut _,
                4,
            )
        };
        assert_eq!(rc, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
    });
}

#[cfg(windows)]
#[test]
fn windows_statistics_report_constants_and_families() {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetTcpStatisticsEx2, GetUdpStatisticsEx, MIB_TCPSTATS2, MIB_UDPSTATS,
    };
    Sim::new().run(|| {
        let listener = TcpListener::bind("[::1]:0").unwrap();
        let _c = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _s = listener.accept().unwrap();
        let t = counters::tcpstats(23);
        assert_eq!(unsafe { t.Anonymous.dwRtoAlgorithm }, 4);
        assert_eq!(
            (t.dwRtoMin, t.dwRtoMax, t.dwMaxConn),
            (5, u32::MAX, u32::MAX)
        );
        assert_eq!(
            (t.dwActiveOpens, t.dwPassiveOpens, t.dwCurrEstab),
            (1, 1, 2)
        );
        assert_eq!(counters::tcpstats(2).dwActiveOpens, 0);
        let mut t2: MIB_TCPSTATS2 = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { GetTcpStatisticsEx2(&mut t2, 23) }, 0);
        assert_eq!(t2.dwPassiveOpens, 1);
        let mut u: MIB_UDPSTATS = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { GetUdpStatisticsEx(&mut u, 7) }, 50);
    });
}
