//! fast-talker's `sys_check` and `Counters::read` under the shim: answered
//! from the simulated host, with the emulated OS's checks, texts and
//! counter names.

use std::net::SocketAddr;
use std::time::Duration;

use snare::fast_talker::counters::Counters;
use snare::fast_talker::sim::{self, CpuTopology, FtEvent, PtpSeed, SysFacts};
use snare::fast_talker::sys_check::{Check, Finding, Status, sys_check};
use snare::net::UdpSocket;
use snare::{
    IpNet, NicCaps, NicSpec, OsSemantics, add_nic, register_test, set_nic_policy, set_os_semantics,
    set_privileges, set_sys_limits, socket_entry, socket_id,
};

const ALL: [OsSemantics; 3] = [OsSemantics::Linux, OsSemantics::MacOs, OsSemantics::Windows];

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn status(findings: &[Finding], check: &Check) -> Status {
    findings
        .iter()
        .find(|f| &f.check == check)
        .unwrap()
        .status
        .clone()
}

fn fail(expected: &str, actual: &str) -> Status {
    Status::Fail {
        expected: expected.into(),
        actual: actual.into(),
    }
}

#[test]
fn tuned_hosts_pass_and_stock_hosts_fail_with_fast_talkers_texts() {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    sim::set_cpus(CpuTopology {
        count: 4,
        isolated: vec![2, 3],
        nohz_full: vec![2, 3],
        ..CpuTopology::default()
    });
    let checks = Check::recommended(&[2, 3]);
    assert_eq!(checks.len(), 9);
    let findings = sys_check(&checks);
    assert!(findings.iter().all(Finding::is_pass), "{findings:?}");

    sim::set_sys_facts(|f| *f = SysFacts::stock());
    sim::set_cpus(CpuTopology {
        count: 4,
        isolated: vec![3],
        ..CpuTopology::default()
    });
    let findings = sys_check(&checks);
    assert!(!findings.iter().any(Finding::is_pass), "{findings:?}");
    assert_eq!(
        status(&findings, &Check::PreemptRt),
        fail(
            "a PREEMPT_RT kernel",
            "6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC"
        )
    );
    assert_eq!(
        status(&findings, &Check::Isolated(vec![2, 3])),
        fail("isolated to include 2-3", "isolated = \"3\", missing 2")
    );
    assert_eq!(
        status(&findings, &Check::IrqbalanceStopped),
        fail("irqbalance not running", "running as pid 812")
    );
    assert_eq!(
        status(&findings, &Check::RtThrottlingDisabled),
        fail(
            "kernel.sched_rt_runtime_us = -1",
            "kernel.sched_rt_runtime_us = 950000"
        )
    );
    assert_eq!(
        status(
            &findings,
            &Check::Governor {
                cpus: vec![2, 3],
                governor: "performance".into()
            }
        ),
        fail("governor performance", "cpu2=schedutil, cpu3=schedutil")
    );
    assert_eq!(
        status(
            &findings,
            &Check::IdleLatency {
                cpus: vec![2, 3],
                max_us: 10
            }
        ),
        fail(
            "no enabled idle state slower than 10 µs",
            "cpu2 C6 (133 µs), cpu3 C6 (133 µs)"
        )
    );
    assert_eq!(
        status(&findings, &Check::TransparentHugepages("never".into())),
        fail("never", "madvise")
    );

    let extra = sys_check(&[
        Check::KernelArg("isolcpus".into()),
        Check::KernelArg("quiet".into()),
        Check::Sysctl {
            key: "net.core.rmem_max".into(),
            value: "212992".into(),
        },
        Check::Sysctl {
            key: "net.no.such".into(),
            value: "1".into(),
        },
        Check::SmtDisabled,
        Check::WinCoreParkingDisabled,
    ]);
    assert!(extra[0].is_pass() && extra[1].is_pass() && extra[2].is_pass());
    assert!(matches!(extra[3].status, Status::Error(_)));
    assert_eq!(extra[4].status, fail("SMT off", "on"));
    assert_eq!(
        extra[5].status,
        Status::Unsupported("not available on linux".into())
    );

    let records = sim::sys_checks();
    assert_eq!(records.len(), 3);
    assert_eq!(records[1].checks, checks);
    assert_eq!(records[1].findings, findings);
    assert!(sim::events().iter().any(|e| matches!(
        e.event,
        FtEvent::SysCheck {
            checks: 9,
            passed: 0
        }
    )));
}

#[test]
fn phc_synced_reads_the_interfaces_ptp_clock() {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    add_nic(
        NicSpec::new("eth0")
            .address(net("10.0.0.1/24"))
            .caps(NicCaps {
                hw_rx_timestamp: true,
                phc_index: Some(2),
                ..NicCaps::default()
            }),
    )
    .unwrap();
    let check = |iface: &str| Check::PhcSynced {
        interface: iface.into(),
        max_offset: Duration::from_micros(1),
    };
    let run = |iface: &str| sys_check(&[check(iface)]).remove(0).status;

    assert_eq!(run("eth0"), Status::Pass);
    sim::set_ptp(
        "eth0",
        PtpSeed {
            clock: 2,
            offset_nanos: 500,
            uncertainty: Duration::from_nanos(200),
            tai: true,
        },
    )
    .unwrap();
    assert_eq!(run("eth0"), Status::Pass);
    for (offset, text) in [(5_000, "5µs"), (-5_000, "-5µs")] {
        sim::set_ptp(
            "eth0",
            PtpSeed {
                clock: 2,
                offset_nanos: offset,
                uncertainty: Duration::from_nanos(200),
                tai: false,
            },
        )
        .unwrap();
        assert_eq!(
            run("eth0"),
            fail(
                "eth0 clock within 1µs of the system clock",
                &format!("{text} off (± 200ns) on /dev/ptp2")
            )
        );
    }
    assert_eq!(
        run("snare0"),
        Status::Unsupported("snare0 has no PTP hardware clock".into())
    );
    assert!(matches!(run("eth9"), Status::Error(_)));
    set_privileges(|p| p.root = false);
    assert!(matches!(run("eth0"), Status::Error(_)));
    set_os_semantics(OsSemantics::Windows);
    assert_eq!(
        run("eth0"),
        Status::Unsupported("not available on windows".into())
    );
}

#[test]
fn recommended_checks_follow_the_emulated_os() {
    for os in ALL {
        register_test();
        set_os_semantics(os);
        sim::set_cpus(CpuTopology {
            isolated: vec![1],
            nohz_full: vec![1],
            ..CpuTopology::default()
        });
        let checks = Check::recommended(&[1]);
        let expected: &[Check] = match os {
            OsSemantics::Linux => &[Check::PreemptRt],
            OsSemantics::MacOs => &[Check::MacOsLowPowerModeOff],
            _ => &[
                Check::WinHighPerformancePower,
                Check::WinCoreParkingDisabled,
            ],
        };
        assert!(checks.starts_with(expected), "{os}: {checks:?}");
        if os != OsSemantics::Linux {
            assert_eq!(checks, expected);
        }
        assert!(sys_check(&checks).iter().all(Finding::is_pass), "{os}");

        sim::set_sys_facts(|f| {
            *f = SysFacts::stock();
            f.macos_low_power_mode = true;
        });
        sim::set_cpus(CpuTopology::default());
        let findings = sys_check(&checks);
        assert!(!findings.iter().any(Finding::is_pass), "{os}: {findings:?}");
        match os {
            OsSemantics::MacOs => assert_eq!(findings[0].status, fail("Low Power Mode off", "on")),
            OsSemantics::Windows => {
                assert_eq!(
                    findings[0].status,
                    fail(
                        "High performance or Ultimate Performance power plan",
                        "Balanced"
                    )
                );
                assert_eq!(
                    findings[1].status,
                    fail(
                        "100% of cores unparked",
                        "class 0 keeps 10% of cores unparked"
                    )
                );
            }
            _ => {}
        }

        let privileges = Check::privileges(80);
        assert_eq!(
            privileges.len(),
            match os {
                OsSemantics::Linux => 5,
                OsSemantics::MacOs => 1,
                _ => 4,
            }
        );
        assert!(sys_check(&privileges).iter().all(Finding::is_pass), "{os}");
        set_privileges(|p| {
            *p = snare::Privileges {
                root: false,
                net_admin: false,
                net_raw: false,
                net_bind_service: false,
                sys_nice: false,
                ipc_lock: false,
                rtprio_limit: 0,
                nice_limit: 0,
                memlock_limit: Some(65536),
            }
        });
        let denied = sys_check(&privileges);
        let passes = denied.iter().filter(|f| f.is_pass()).count();
        assert_eq!(
            passes,
            usize::from(os == OsSemantics::MacOs),
            "{os}: {denied:?}"
        );
        match os {
            OsSemantics::Linux => assert_eq!(
                denied[1].status,
                fail(
                    "CAP_SYS_NICE or RLIMIT_RTPRIO >= 80",
                    "no CAP_SYS_NICE, RLIMIT_RTPRIO = 0"
                )
            ),
            OsSemantics::Windows => assert_eq!(
                denied[1].status,
                fail(
                    "SeIncreaseBasePriorityPrivilege",
                    "not held by this process"
                )
            ),
            _ => {}
        }

        let foreign = match os {
            OsSemantics::Linux => Check::MacOsLowPowerModeOff,
            _ => Check::PreemptRt,
        };
        assert_eq!(
            sys_check(&[foreign]).remove(0).status,
            Status::Unsupported(format!("not available on {os}"))
        );
    }
}

/// A slot on `os` with `eth0` answering closed ports with ICMP, receive
/// buffers enforced at a small default, and a sender and receiver on it.
fn udp_host(os: OsSemantics) -> (UdpSocket, UdpSocket) {
    register_test();
    set_os_semantics(os);
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/24"))).unwrap();
    set_nic_policy("eth0", |p| p.icmp_port_unreachable = true).unwrap();
    set_sys_limits(|l| {
        l.enforce_default_rcvbuf = true;
        l.rmem_default = 1000;
    });
    let tx = UdpSocket::bind("10.0.0.1:7001").unwrap();
    let rx = UdpSocket::bind("10.0.0.1:7000").unwrap();
    rx.set_nonblocking(true).unwrap();
    (tx, rx)
}

#[test]
fn counters_reflect_traffic_and_overflows_per_os() {
    for os in ALL {
        let (tx, rx) = udp_host(os);
        let before = Counters::read().unwrap();
        for _ in 0..20 {
            tx.send_to(&[0u8; 100], addr("10.0.0.1:7000")).unwrap();
        }
        tx.send_to(b"x", addr("10.0.0.1:9")).unwrap();
        let mut buf = [0u8; 256];
        rx.recv_from(&mut buf).unwrap();
        rx.recv_from(&mut buf).unwrap();

        let entry = socket_entry(socket_id(&rx)).unwrap();
        let overflowed = entry.overflowed;
        assert!(overflowed > 0 && overflowed < 20, "{os}: {overflowed}");
        let after = Counters::read().unwrap();
        let d = after.since(&before).udp();
        assert_eq!(d.out_datagrams, 21, "{os}");
        assert_eq!(d.no_ports, 1, "{os}");
        assert_eq!(d.in_errors, overflowed, "{os}");
        match os {
            OsSemantics::Linux => {
                assert_eq!(d.in_datagrams, 2);
                assert_eq!(d.rcvbuf_errors, overflowed);
                assert!(after.get("Udp6InDatagrams").is_some());
                assert!(after.get("TcpExtListenDrops").is_some());
            }
            OsSemantics::MacOs => {
                assert_eq!(d.in_datagrams, 20 - overflowed);
                assert_eq!(d.rcvbuf_errors, overflowed);
                assert_eq!(after.get("Udp6InDatagrams"), None);
                assert_eq!(after.iter().count(), 7);
            }
            _ => {
                assert_eq!(d.in_datagrams, 20 - overflowed);
                assert_eq!(after.get("UdpRcvbufErrors"), None);
                assert!(after.get("Udp6NoPorts").is_some());
                assert_eq!(after.iter().count(), 8);
            }
        }
        assert_eq!(after.udp6(), Counters::default().udp6(), "{os}");
    }
}

#[test]
fn injected_protocol_counters_add_to_the_traffic() {
    let (tx, _rx) = udp_host(OsSemantics::Linux);
    tx.send_to(b"x", addr("10.0.0.1:9")).unwrap();
    sim::set_protocol_counters(|c| {
        c.insert("UdpNoPorts".into(), 5);
        c.insert("TcpExtTCPTimeouts".into(), 3);
    });
    let c = Counters::read().unwrap();
    assert_eq!(c.udp().no_ports, 6);
    assert_eq!(c.get("TcpExtTCPTimeouts"), Some(3));
    sim::set_protocol_counters(|c| {
        c.insert("UdpNoPorts".into(), 0);
    });
    assert_eq!(Counters::read().unwrap().udp().no_ports, 1);
}

#[test]
fn threads_without_a_slot_read_the_hosts_counters() {
    let _ = udp_host(OsSemantics::Linux);
    sim::set_protocol_counters(|c| {
        c.insert("SnareOnly".into(), 1);
    });
    assert_eq!(Counters::read().unwrap().get("SnareOnly"), Some(1));
    let real = std::thread::spawn(Counters::read).join().unwrap().unwrap();
    assert!(real.get("UdpInDatagrams").is_some());
    assert_eq!(real.get("SnareOnly"), None);
}
