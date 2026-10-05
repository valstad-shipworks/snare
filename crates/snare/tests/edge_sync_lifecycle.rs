//! A `Sim`'s lifecycle, pinned for the performance pass: a thousand sims built, run and dropped
//! one after another each start at virtual zero, end at the same instant and free their domain;
//! runs of two sims nest on one thread and each restores the one outside it; a sim built on one
//! thread runs on another; and nothing a sim was given or the code under test changed — testers,
//! sockets, names, the topology, the clock — is seen by another sim, while the same sim keeps it
//! from one run to the next.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use snare::{Line, NicSpec, Sim, TesterAction, connect_tester};
use snare_interpose::Domain;

/// The sim's realtime epoch, in Unix seconds.
const SIM_EPOCH: u64 = 1_700_000_000;

fn realtime() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

#[test]
fn a_thousand_sims_each_start_at_zero_end_alike_and_free_their_domain() {
    let mut ends = Vec::new();
    for i in 0..1000u64 {
        let sim = Sim::builder().seed(i).build();
        assert_eq!(sim.time_value(), Duration::ZERO, "sim {i} starts at zero");
        let (weak, started) = sim.run(|| {
            let started = realtime();
            std::thread::spawn(|| std::thread::sleep(Duration::from_millis(1)))
                .join()
                .unwrap();
            (Domain::current().unwrap().downgrade(), started)
        });
        assert_eq!(started, Duration::from_secs(SIM_EPOCH), "sim {i}");
        ends.push(sim.time_value());
        drop(sim);
        assert!(weak.upgrade().is_none(), "sim {i}'s domain outlived it");
    }
    assert!(ends.windows(2).all(|w| w[0] == w[1]), "{:?}", &ends[..4]);
    assert!(ends[0] >= Duration::from_millis(1));
}

#[test]
fn runs_of_two_sims_nest_on_one_thread() {
    let outer = Sim::new();
    let inner = Sim::new();
    let (outer_id, inner_id) = (outer.id(), inner.id());
    let seen = outer.run(|| {
        std::thread::sleep(Duration::from_secs(10));
        let before = (snare::sched::current_sim() == Some(outer_id), realtime());
        let nested = inner.run(|| {
            let at = realtime();
            std::thread::sleep(Duration::from_secs(1));
            (
                snare::sched::current_sim() == Some(inner_id),
                at,
                realtime(),
            )
        });
        let after = (snare::sched::current_sim() == Some(outer_id), realtime());
        (before, nested, after)
    });
    let epoch = Duration::from_secs(SIM_EPOCH);
    assert!(seen.0.0);
    assert!(seen.0.1 >= epoch + Duration::from_secs(10));
    assert!(seen.1.0, "the inner run is the inner sim's");
    assert_eq!(
        seen.1.1, epoch,
        "the inner sim's clock starts at its own zero"
    );
    assert!(seen.1.2 >= epoch + Duration::from_secs(1));
    assert!(seen.2.0, "the outer sim is restored");
    assert!(seen.2.1 >= seen.0.1 && seen.2.1 < seen.0.1 + Duration::from_secs(1));
    assert!(inner.time_value() >= Duration::from_secs(1));
    assert!(outer.time_value() < Duration::from_secs(11));
}

#[test]
fn a_run_nested_in_a_run_of_the_same_sim_is_a_later_entry() {
    let sim = Sim::new();
    let seen = sim.run(|| {
        let outer = snare_interpose::thread_lineage();
        let inner = sim.run(snare_interpose::thread_lineage);
        (
            outer,
            inner,
            snare_interpose::thread_lineage(),
            snare::sched::in_sim(),
        )
    });
    assert_eq!(seen.0, 0);
    assert_ne!(seen.1, 0, "the nested entry gets a root lineage of its own");
    assert_eq!(seen.2, 0, "the outer lineage is restored");
    assert!(seen.3);
    assert!(!snare::sched::in_sim());
}

#[test]
fn two_sims_in_turn_on_one_thread_keep_separate_clocks() {
    let first = Sim::new();
    first.run(|| std::thread::sleep(Duration::from_secs(3600)));
    let second = Sim::new();
    let at = second.run(realtime);
    assert_eq!(at, Duration::from_secs(SIM_EPOCH));
    assert!(first.time_value() >= Duration::from_secs(3600));
    assert!(second.time_value() < Duration::from_millis(1));
    let resumed = first.run(realtime);
    assert!(resumed >= Duration::from_secs(SIM_EPOCH + 3600));
}

#[test]
fn a_sim_built_on_one_thread_runs_on_another() {
    fn send<T: Send>(_: &T) {}
    let sim = Sim::new();
    send(&sim);
    let id = sim.id();
    let sim = std::thread::spawn(move || {
        let seen = sim.run(|| {
            std::thread::sleep(Duration::from_secs(2));
            (snare::sched::current_sim() == Some(id), realtime())
        });
        assert!(seen.0);
        assert!(seen.1 >= Duration::from_secs(SIM_EPOCH + 2));
        sim
    })
    .join()
    .unwrap();
    let again = sim.run(realtime);
    assert!(again >= Duration::from_secs(SIM_EPOCH + 2));
}

#[test]
fn a_tester_belongs_to_its_sim_alone() {
    let with_tester = Sim::new();
    let without = Sim::new();
    let refused = with_tester.run(|| {
        let _server =
            connect_tester::<Line>("127.0.0.31:9031").then_action(|msg, _| TesterAction::Send(msg));
        without.run(|| {
            TcpStream::connect("127.0.0.31:9031")
                .map(|_| ())
                .map_err(|e| e.kind())
        })
    });
    assert_eq!(refused, Err(std::io::ErrorKind::ConnectionRefused));
}

#[test]
fn sockets_and_ports_are_per_sim() {
    let a = Sim::new();
    let b = Sim::new();
    let (la, lb) = a.run(|| {
        let la = TcpListener::bind("127.0.0.1:7100").unwrap();
        let lb = b.run(|| TcpListener::bind("127.0.0.1:7100").unwrap());
        (la, lb)
    });
    assert_eq!(a.socket_table().len(), 1);
    assert_eq!(b.socket_table().len(), 1);
    let echoed = b.run(|| {
        let mut client = TcpStream::connect("127.0.0.1:7100").unwrap();
        let (mut server, _) = lb.accept().unwrap();
        client.write_all(b"b").unwrap();
        let mut got = [0u8; 1];
        server.read_exact(&mut got).unwrap();
        got
    });
    assert_eq!(&echoed, b"b");
    assert_eq!(
        a.socket_table().len(),
        1,
        "b's connection is not in a's table"
    );
    drop(la);
    let real = snare::real(|| {
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    });
    assert!(real.port() != 0);
}

#[test]
fn names_are_per_sim_and_kept_across_runs() {
    let a = Sim::builder()
        .add_host("edge-a.test", [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 41))])
        .build();
    let b = Sim::new();
    let lookup = || {
        ("edge-a.test", 80)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|a| a.ip()).collect::<Vec<_>>())
            .map_err(|_| ())
    };
    assert_eq!(
        a.run(lookup),
        Ok(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 41))])
    );
    assert_eq!(b.run(lookup), Err(()));
    a.run(|| snare::add_host("edge-late.test", [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 42))]));
    let late = || {
        ("edge-late.test", 80)
            .to_socket_addrs()
            .map(|_| ())
            .map_err(|_| ())
    };
    assert_eq!(a.run(late), Ok(()), "kept for the next run");
    assert_eq!(b.run(late), Err(()));
    assert_eq!(Sim::new().run(late), Err(()));
}

#[test]
fn the_topology_is_per_sim_and_kept_across_runs() {
    let a = Sim::new();
    let b = Sim::new();
    let baseline: Vec<String> = Sim::new().nics().into_iter().map(|n| n.spec.name).collect();
    a.run(|| {
        snare::add_nic(NicSpec::new("edge0").address(snare::IpNet::new(
            IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1)),
            24,
        )))
        .unwrap();
    });
    let names = |sim: &Sim| {
        sim.nics()
            .into_iter()
            .map(|n| n.spec.name)
            .collect::<Vec<_>>()
    };
    assert!(names(&a).contains(&"edge0".to_string()));
    assert_eq!(names(&b), baseline);
    assert!(
        a.run(|| snare::nic("edge0").is_some()),
        "kept for the next run"
    );
    assert!(b.run(|| snare::nic("edge0").is_none()));
}

#[test]
fn a_clock_moved_in_one_sim_leaves_another_alone() {
    let a = Sim::new();
    let b = Sim::new();
    a.set_time_value(Duration::from_secs(86_400));
    a.pause_time();
    let start = Instant::now();
    let in_b = b.run(|| {
        std::thread::sleep(Duration::from_millis(5));
        realtime()
    });
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(in_b < Duration::from_secs(SIM_EPOCH + 1));
    assert_eq!(a.time_value(), Duration::from_secs(86_400));
    assert_eq!(a.run(realtime), Duration::from_secs(SIM_EPOCH + 86_400));
}
